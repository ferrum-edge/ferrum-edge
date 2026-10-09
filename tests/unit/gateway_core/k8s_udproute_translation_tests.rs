//! Gateway API `UDPRoute` translation, admission, and status coverage (#3275).
//!
//! A `UDPRoute` carries no request-level predicate, so the Gateway listener
//! port is the entire match and the rule's `backendRefs` **set** is the
//! datagram peer set. These tests pin the strict admission boundaries
//! (backendRef port, backend kind, ReferenceGrant, namespace, listener
//! protocol/kind), the weighted multi-backend semantics required by pinned
//! Gateway API v1.5.1, the declared-parent fail-closed invariant shared with
//! `TCPRoute`/`TLSRoute`, and the reload/delete behavior — not only
//! first-start construction.

use ferrum_edge::_test_support::merge_k8s_translation;
use ferrum_edge::config::types::{
    BackendScheme, GatewayConfig, LoadBalancerAlgorithm, Proxy, Upstream,
};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    translate_k8s_objects_collecting_skips,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, GatewayApiStatusUpdate, plan_gateway_api_status_updates,
};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};

const GATEWAY_API_SRC: &str = include_str!("../../../src/config_sources/k8s/gateway_api.rs");
const WATCHER_SRC: &str = include_str!("../../../src/k8s_controller/watcher.rs");
const STATUS_SRC: &str = include_str!("../../../src/k8s_controller/status.rs");

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn multi_namespace_options() -> K8sTranslationOptions {
    let namespaces = vec!["default".to_string(), "backends".to_string()];
    options().with_source_namespaces(namespaces)
}

fn object_in(kind: &str, version: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: version.to_string(),
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

fn udp_route(name: &str, spec: Value) -> K8sObject {
    let version = "gateway.networking.k8s.io/v1alpha2";
    object_in("UDPRoute", version, "default", name, spec)
}

fn udp_route_at(name: &str, created_at: &str, spec: Value) -> K8sObject {
    let mut route = udp_route(name, spec);
    route.metadata.creation_timestamp = Some(created_at.to_string());
    route
}

fn udp_route_in(namespace: &str, name: &str, created_at: &str, spec: Value) -> K8sObject {
    let version = "gateway.networking.k8s.io/v1alpha2";
    let mut route = object_in("UDPRoute", version, namespace, name, spec);
    route.metadata.creation_timestamp = Some(created_at.to_string());
    route
}

fn gateway_class() -> K8sObject {
    let spec = json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME});
    let version = "gateway.networking.k8s.io/v1";
    object_in("GatewayClass", version, "", "ferrum", spec)
}

/// A Ferrum-managed Gateway with one UDP listener on `port`.
fn udp_gateway(name: &str, listener: &str, port: u16) -> K8sObject {
    let spec = json!({
        "gatewayClassName": "ferrum",
        "listeners": [{
            "name": listener,
            "port": port,
            "protocol": "UDP",
            "allowedRoutes": {
                "kinds": [{"kind": "UDPRoute"}],
                "namespaces": {"from": "Same"}
            }
        }]
    });
    let version = "gateway.networking.k8s.io/v1";
    object_in("Gateway", version, "default", name, spec)
}

fn gateway_object(name: &str, spec: Value) -> K8sObject {
    let version = "gateway.networking.k8s.io/v1";
    object_in("Gateway", version, "default", name, spec)
}

fn l4_route(kind: &str, name: &str, spec: Value) -> K8sObject {
    let version = "gateway.networking.k8s.io/v1alpha2";
    object_in(kind, version, "default", name, spec)
}

/// The standard single-UDP-listener lab: GatewayClass, a Ferrum Gateway with
/// listener `dns` on 15353, and one `UDPRoute` named `dns` carrying `spec`.
fn udp_lab(spec: Value) -> [K8sObject; 3] {
    [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns", spec),
    ]
}

fn service(namespace: &str, name: &str, port: u16) -> K8sObject {
    let spec = json!({
        "selector": {"app": name},
        "ports": [{"name": "udp", "protocol": "UDP", "port": port, "targetPort": port}]
    });
    object_in("Service", "v1", namespace, name, spec)
}

fn simple_rule(backend: &str, port: u16) -> Value {
    json!({"rules": [{"backendRefs": [{"name": backend, "port": port}]}]})
}

fn attached_rule(parent: &str, section: &str, backend: &str, port: u16) -> Value {
    json!({
        "parentRefs": [{"name": parent, "sectionName": section}],
        "rules": [{"backendRefs": [{"name": backend, "port": port}]}]
    })
}

fn cross_namespace_rule(backend: &str, namespace: &str, port: u16) -> Value {
    json!({
        "rules": [{"backendRefs": [{
            "name": backend,
            "namespace": namespace,
            "port": port
        }]}]
    })
}

fn reference_grant(name: &str, from_kind: &str) -> K8sObject {
    let spec = json!({
        "from": [{
            "group": "gateway.networking.k8s.io",
            "kind": from_kind,
            "namespace": "default"
        }],
        "to": [{"group": "", "kind": "Service", "name": "coredns"}]
    });
    let version = "gateway.networking.k8s.io/v1beta1";
    object_in("ReferenceGrant", version, "backends", name, spec)
}

fn route_condition_field(
    updates: &[GatewayApiStatusUpdate],
    name: &str,
    condition: &str,
    field: &str,
) -> Option<String> {
    let update = updates
        .iter()
        .find(|update| update.kind == "UDPRoute" && update.name == name)?;
    update
        .status
        .get("parents")?
        .as_array()?
        .iter()
        .filter_map(|parent| parent.get("conditions")?.as_array())
        .flatten()
        .find(|entry| entry.get("type").and_then(Value::as_str) == Some(condition))
        .and_then(|entry| entry.get(field).and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

fn route_condition(
    updates: &[GatewayApiStatusUpdate],
    name: &str,
    condition: &str,
) -> Option<String> {
    route_condition_field(updates, name, condition, "status")
}

fn route_condition_reason(
    updates: &[GatewayApiStatusUpdate],
    name: &str,
    condition: &str,
) -> Option<String> {
    route_condition_field(updates, name, condition, "reason")
}

fn gateway_listener_attached_routes(
    updates: &[GatewayApiStatusUpdate],
    gateway_name: &str,
    listener_name: &str,
) -> Option<u64> {
    let update = updates
        .iter()
        .find(|update| update.kind == "Gateway" && update.name == gateway_name)?;
    update
        .status
        .get("listeners")?
        .as_array()?
        .iter()
        .find(|listener| listener.get("name").and_then(Value::as_str) == Some(listener_name))
        .and_then(|listener| listener.get("attachedRoutes").and_then(Value::as_u64))
}

#[test]
fn udp_route_materializes_udp_stream_proxy_on_listener_port() {
    let route = udp_route("dns", attached_rule("edge", "dns", "coredns", 5353));
    let objects = [gateway_class(), udp_gateway("edge", "dns", 15353), route];

    let translated = translate_k8s_objects(&objects, options());
    let result = translated.expect("translation succeeds");

    assert_eq!(result.config.proxies.len(), 1);
    let proxy = &result.config.proxies[0];
    assert_eq!(proxy.backend_scheme, Some(BackendScheme::Udp));
    assert_eq!(proxy.listen_port, Some(15353));
    assert_eq!(proxy.backend_port, 5353);
    assert_eq!(proxy.backend_host, "coredns.default.svc.cluster.local");
    // Datagram semantics: no listen path, no host predicate, per-session idle.
    assert_eq!(proxy.listen_path, None);
    assert!(proxy.hosts.is_empty());
    assert!(proxy.udp_idle_timeout_seconds > 0);
    assert_eq!(
        proxy.udp_max_response_amplification_factor,
        Some(8.0),
        "ordinary UDPRoute translation must project the finite controller default"
    );
}

#[test]
fn udp_route_without_materialized_listener_opens_no_listener() {
    let objects = [udp_route("dns", simple_rule("coredns", 5353))];

    let translated = translate_k8s_objects(&objects, options());
    let result = translated.expect("translation succeeds");

    assert!(result.config.proxies.is_empty());
    assert!(result.warnings.iter().any(|warning| {
        warning.contains(r#"UDPRoute "default"/"dns" has no valid attached Gateway listener"#)
    }));
}

#[test]
fn udp_route_backend_port_is_required() {
    let spec = json!({"rules": [{"backendRefs": [{"name": "coredns"}]}]});
    let objects = [udp_route("dns", spec)];

    let translated = translate_k8s_objects(&objects, options());
    let err = translated.expect_err("a portless backendRef fails closed");

    assert!(err.to_string().contains("UDPRoute backendRefs[].port"));
    assert!(err.to_string().contains("is required"));
}

#[test]
fn udp_route_backend_port_zero_fails_closed() {
    let objects = [udp_route("dns", simple_rule("coredns", 0))];

    let translated = translate_k8s_objects(&objects, options());
    let err = translated.expect_err("port 0 fails closed");

    assert!(err.to_string().contains("UDPRoute backendRefs[].port"));
}

#[test]
fn udp_route_backend_port_above_kubernetes_range_fails_closed() {
    let spec = json!({"rules": [{"backendRefs": [{"name": "dns", "port": 70000}]}]});
    let objects = [udp_route("dns", spec)];

    let translated = translate_k8s_objects(&objects, options());
    let err = translated.expect_err("port 70000 fails closed");

    assert!(err.to_string().contains("UDPRoute backendRefs[].port"));
    assert!(err.to_string().contains("70000"));
}

#[test]
fn udp_route_rejects_non_service_backend_kind() {
    let spec = json!({
        "rules": [{"backendRefs": [{
            "group": "example.com",
            "kind": "DatagramSink",
            "name": "sink",
            "port": 5353
        }]}]
    });
    let objects = [udp_route("dns", spec)];

    let translated = translate_k8s_objects(&objects, options());
    let err = translated.expect_err("unsupported backendRef target kind fails closed");

    let message = err.to_string();
    assert!(
        message
            .contains(r#"unsupported backendRef target group "example.com" kind "DatagramSink""#)
    );
    assert!(message.contains("UDPRoute only supports core Service backendRefs"));
}

#[test]
fn udp_route_hostnames_are_rejected_fail_closed() {
    // Gateway API defines no `hostnames` on UDPRoute, and a datagram carries no
    // name to match on. Accepting one would materialize an inert selector.
    let spec = json!({
        "hostnames": ["dns.example.com"],
        "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
    });
    let objects = [udp_route("dns", spec)];

    let translated = translate_k8s_objects(&objects, options());
    let err = translated.expect_err("UDPRoute hostnames fail closed");

    assert!(err.to_string().contains("UDPRoute spec.hostnames"));
}

#[test]
fn udp_route_rejects_any_present_hostnames_shape() {
    for hostnames in [json!([]), Value::Null, json!("dns.example.com"), json!(42)] {
        let spec = json!({
            "hostnames": hostnames,
            "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
        });
        let objects = [udp_route("dns", spec)];

        let translated = translate_k8s_objects(&objects, options());
        let err = translated.expect_err("every present UDPRoute hostnames shape fails closed");

        assert!(err.to_string().contains("UDPRoute spec.hostnames"));
    }
}

#[test]
fn udp_route_cross_namespace_backend_ref_requires_reference_grant() {
    let spec = cross_namespace_rule("coredns", "backends", 5353);
    let ungranted = [udp_route("dns", spec.clone())];

    let translated = translate_k8s_objects(&ungranted, multi_namespace_options());
    let err = translated.expect_err("an ungranted cross-namespace ref fails");

    assert!(
        err.to_string()
            .contains("requires a matching ReferenceGrant")
    );

    // A matching grant authorizes the backendRef, but UDPRoute still requires a
    // valid attached Gateway listener before any proxy is materialized.
    let grant = reference_grant("allow-udproute", "UDPRoute");
    let attached_cross_namespace = json!({
        "parentRefs": [{"name": "edge", "sectionName": "dns"}],
        "rules": [{"backendRefs": [{
            "name": "coredns",
            "namespace": "backends",
            "port": 5353
        }]}]
    });
    let granted = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns", attached_cross_namespace),
        grant,
    ];

    let translated = translate_k8s_objects(&granted, multi_namespace_options());
    let result = translated.expect("a matching grant authorizes the ref");

    assert_eq!(
        result.config.proxies[0].backend_host,
        "coredns.backends.svc.cluster.local"
    );
}

#[test]
fn udp_route_reference_grant_for_another_kind_does_not_authorize() {
    let spec = cross_namespace_rule("coredns", "backends", 5353);
    let grant = reference_grant("allow-tcproute-only", "TCPRoute");
    let objects = [udp_route("dns", spec), grant];

    let translated = translate_k8s_objects(&objects, multi_namespace_options());
    let err = translated.expect_err("a TCPRoute grant is not a UDPRoute grant");

    assert!(
        err.to_string()
            .contains("requires a matching ReferenceGrant")
    );
}

#[test]
fn udp_route_rejects_cross_namespace_parent_ref() {
    let mut gateway = udp_gateway("edge", "dns", 15353);
    gateway.metadata.namespace = "backends".to_string();
    gateway.spec["listeners"][0]["allowedRoutes"]["namespaces"]["from"] = json!("All");
    let spec = json!({
        "parentRefs": [{"name": "edge", "namespace": "backends"}],
        "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
    });
    let objects = [gateway_class(), gateway, udp_route("dns", spec)];

    let translated = translate_k8s_objects(&objects, multi_namespace_options());
    let err = translated.expect_err("cross-namespace L4 parents fail closed");

    let message = err.to_string();
    assert!(message.contains("UDPRoute cross-namespace parentRefs"));
}

#[test]
fn udp_route_does_not_attach_to_a_tcp_listener() {
    let spec = json!({
        "gatewayClassName": "ferrum",
        "listeners": [{
            "name": "stream",
            "port": 15353,
            "protocol": "TCP",
            "allowedRoutes": {"kinds": [{"kind": "TCPRoute"}]}
        }]
    });
    let version = "gateway.networking.k8s.io/v1";
    let gateway = object_in("Gateway", version, "default", "edge", spec);
    let route = udp_route("dns", attached_rule("edge", "stream", "coredns", 5353));
    let objects = [gateway_class(), gateway, route];

    let translated = translate_k8s_objects(&objects, options());
    let err = translated.expect_err("a UDP route needs a UDP listener");

    assert!(err.to_string().contains("UDPRoute"));
}

#[test]
fn udp_route_rule_with_only_zero_weight_backends_materializes_nothing() {
    let spec = json!({
        "rules": [{"backendRefs": [{
            "name": "coredns",
            "port": 5353,
            "weight": 0
        }]}]
    });
    let objects = [udp_route("dns", spec)];

    let translated = translate_k8s_objects(&objects, options());
    let result = translated.expect("a zero-weight-only rule is accepted");

    assert!(result.config.proxies.is_empty());
    let warned = result
        .warnings
        .iter()
        .any(|warning| warning.contains("UDPRoute") && warning.contains("zero-weight"));
    assert!(warned, "expected a warning, got {:?}", result.warnings);
}

#[test]
fn udp_route_update_and_delete_regenerate_live_config() {
    let gateway = udp_gateway("edge", "dns", 15353);
    let route = udp_route("dns", attached_rule("edge", "dns", "coredns-b", 5353));
    let updated_objects = [gateway_class(), gateway.clone(), route];

    let translated = translate_k8s_objects(&updated_objects, options());
    let updated = translated.expect("translation succeeds");

    assert_eq!(
        updated.config.proxies[0].backend_host,
        "coredns-b.default.svc.cluster.local"
    );

    // Deletion is modeled by the route leaving the snapshot: the listener must
    // not survive as an orphaned UDP proxy.
    let deleted_objects = [gateway_class(), gateway];
    let translated = translate_k8s_objects(&deleted_objects, options());
    let deleted = translated.expect("translation succeeds without the route");

    assert!(deleted.config.proxies.is_empty());
}

#[test]
fn udp_route_status_reports_accepted_resolved_and_programmed() {
    let route = udp_route("dns", attached_rule("edge", "dns", "coredns", 5353));
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        service("default", "coredns", 5353),
        route,
    ];

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);

    assert_eq!(
        route_condition(&updates, "dns", "Accepted").as_deref(),
        Some("True")
    );
    assert_eq!(
        route_condition(&updates, "dns", "ResolvedRefs").as_deref(),
        Some("True")
    );
    assert_eq!(
        route_condition(&updates, "dns", "Programmed").as_deref(),
        Some("True")
    );

    let gateway_update = updates
        .iter()
        .find(|update| update.kind == "Gateway")
        .expect("Gateway status update");
    let supported: Vec<&str> = gateway_update.status["listeners"][0]["supportedKinds"]
        .as_array()
        .expect("supportedKinds")
        .iter()
        .filter_map(|kind| kind.get("kind").and_then(Value::as_str))
        .collect();
    assert_eq!(supported, vec!["UDPRoute"]);
}

#[test]
fn udp_route_status_reports_unresolved_missing_backend() {
    let route = udp_route("dns", attached_rule("edge", "dns", "absent", 5353));
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        service("default", "coredns", 5353),
        route,
    ];

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);

    assert_eq!(
        route_condition(&updates, "dns", "ResolvedRefs").as_deref(),
        Some("False")
    );
}

#[test]
fn udp_route_rejects_present_service_import_with_invalid_kind_status_parity() {
    // A fully present TCP ServiceImport is still InvalidKind on UDPRoute:
    // translation refuses non-Service backends and ResolvedRefs must not claim
    // the inventory resolved (#3270 status/traffic parity).
    let import = object_in(
        "ServiceImport",
        "multicluster.x-k8s.io/v1alpha1",
        "default",
        "dns-import",
        json!({
            "type": "ClusterSetIP",
            "ports": [{ "port": 5353, "protocol": "TCP" }]
        }),
    );
    let route = udp_route(
        "dns",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "dns"}],
            "rules": [{
                "backendRefs": [{
                    "group": "multicluster.x-k8s.io",
                    "kind": "ServiceImport",
                    "name": "dns-import",
                    "port": 5353
                }]
            }]
        }),
    );
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        import,
        route,
    ];

    let err = translate_k8s_objects(&objects, options())
        .expect_err("UDPRoute must reject ServiceImport backends");
    let message = err.to_string();
    assert!(message.contains(
        r#"unsupported backendRef target group "multicluster.x-k8s.io" kind "ServiceImport""#
    ));
    assert!(message.contains("UDPRoute only supports core Service backendRefs"));

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    assert_eq!(
        route_condition(&updates, "dns", "ResolvedRefs").as_deref(),
        Some("False")
    );
    assert_eq!(
        route_condition_reason(&updates, "dns", "ResolvedRefs").as_deref(),
        Some("InvalidKind")
    );
}

#[test]
fn udp_route_service_import_reference_grant_cannot_override_invalid_kind() {
    // Fail-closed ordering: capability classification precedes ReferenceGrant.
    // A grant for ServiceImport must not authorize a kind UDPRoute cannot
    // materialize, and status must stay InvalidKind (not RefNotPermitted or
    // ResolvedRefs=True).
    let import = object_in(
        "ServiceImport",
        "multicluster.x-k8s.io/v1alpha1",
        "backends",
        "dns-import",
        json!({
            "type": "ClusterSetIP",
            "ports": [{ "port": 5353, "protocol": "TCP" }]
        }),
    );
    let grant = object_in(
        "ReferenceGrant",
        "gateway.networking.k8s.io/v1beta1",
        "backends",
        "allow-import",
        json!({
            "from": [{
                "group": "gateway.networking.k8s.io",
                "kind": "UDPRoute",
                "namespace": "default"
            }],
            "to": [{
                "group": "multicluster.x-k8s.io",
                "kind": "ServiceImport"
            }]
        }),
    );
    let route = udp_route(
        "dns",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "dns"}],
            "rules": [{
                "backendRefs": [{
                    "group": "multicluster.x-k8s.io",
                    "kind": "ServiceImport",
                    "name": "dns-import",
                    "namespace": "backends",
                    "port": 5353
                }]
            }]
        }),
    );
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        import,
        grant,
        route,
    ];

    let err = translate_k8s_objects(&objects, multi_namespace_options())
        .expect_err("a ServiceImport grant must not authorize UDPRoute");
    let message = err.to_string();
    assert!(message.contains(
        r#"unsupported backendRef target group "multicluster.x-k8s.io" kind "ServiceImport""#
    ));
    assert!(!message.contains("ReferenceGrant"));

    let updates = plan_gateway_api_status_updates(&objects, multi_namespace_options(), &[]);
    assert_eq!(
        route_condition(&updates, "dns", "ResolvedRefs").as_deref(),
        Some("False")
    );
    assert_eq!(
        route_condition_reason(&updates, "dns", "ResolvedRefs").as_deref(),
        Some("InvalidKind")
    );
}

// ---------------------------------------------------------------------------
// Declared-parent fail-closed invariant (shared with TCPRoute / TLSRoute)
// ---------------------------------------------------------------------------

/// A route that declares Gateway `parentRefs` but resolves no materializable
/// listener must open **nothing**. The backend-port fallback exists only for
/// the parentless legacy shape; letting a declared-but-unmatched parent reach
/// it would bind an unintended OS listener on the backend port while status
/// reports `NoMatchingParent`.
fn assert_no_listener_for_declared_parent(objects: &[K8sObject], backend_port: u16) {
    let result = translate_k8s_objects(objects, options()).expect("translation succeeds");

    assert!(
        result.config.proxies.is_empty(),
        "a declared-but-unmatched parent must not materialize a proxy, got {:?}",
        result
            .config
            .proxies
            .iter()
            .map(|proxy| (proxy.id.clone(), proxy.listen_port))
            .collect::<Vec<_>>()
    );
    assert!(
        !result
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.listen_port == Some(backend_port)),
        "the backend port must never become a listen port here"
    );
    assert!(result.config.upstreams.is_empty());
}

/// The route is rejected outright: assert the *snapshot* still opens no
/// listener on the backend port rather than only that the error exists.
fn assert_rejected_route_opens_no_listener(objects: &[K8sObject], backend_port: u16) {
    let (translation, skipped) = translate_k8s_objects_collecting_skips(objects, options())
        .expect("translation converges after skipping the rejected route");

    assert!(
        !skipped.is_empty(),
        "the route was expected to be rejected, but nothing was skipped"
    );
    assert!(
        !translation
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.listen_port == Some(backend_port)),
        "a rejected route must not leave a backend-port listener, got {:?}",
        translation
            .config
            .proxies
            .iter()
            .map(|proxy| (proxy.id.clone(), proxy.listen_port))
            .collect::<Vec<_>>()
    );
}

#[test]
fn udp_route_with_unknown_gateway_parent_opens_no_listener() {
    let spec = json!({
        "parentRefs": [{"name": "absent"}],
        "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
    });
    let objects = [gateway_class(), udp_route("dns", spec)];

    assert_no_listener_for_declared_parent(&objects, 5353);
}

#[test]
fn udp_route_parented_to_a_foreign_controller_gateway_opens_no_listener() {
    // A Gateway owned by another controller contributes no listener policy, so
    // a UDPRoute naming it has nothing to attach to.
    let spec = json!({
        "gatewayClassName": "not-ferrum",
        "listeners": [{"name": "dns", "port": 15353, "protocol": "UDP"}]
    });
    let foreign = gateway_object("edge", spec);
    let route_spec = json!({
        "parentRefs": [{"name": "edge"}],
        "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
    });
    let objects = [gateway_class(), foreign, udp_route("dns", route_spec)];

    assert_no_listener_for_declared_parent(&objects, 5353);
}

#[test]
fn tcp_route_with_unknown_gateway_parent_opens_no_listener() {
    // The fail-closed listener gate is shared L4 code; TCPRoute must not keep
    // the old fail-open backend-port fallback for a declared parent either.
    let spec = json!({
        "parentRefs": [{"name": "absent"}],
        "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
    });
    let route = l4_route("TCPRoute", "db", spec);
    let objects = [gateway_class(), route];

    assert_no_listener_for_declared_parent(&objects, 5432);
}

#[test]
fn tls_route_with_unknown_gateway_parent_opens_no_listener() {
    let spec = json!({
        "parentRefs": [{"name": "absent"}],
        "hostnames": ["db.example.com"],
        "rules": [{"backendRefs": [{"name": "db", "port": 15443}]}]
    });
    let route = l4_route("TLSRoute", "db", spec);
    let objects = [gateway_class(), route];

    assert_no_listener_for_declared_parent(&objects, 15443);
}

#[test]
fn parentless_l4_routes_keep_the_backend_port_fallback() {
    // UDPRoute is Gateway API-only: a parentless shape opens no listener.
    // Parentless TCPRoute/TLSRoute keep the legacy backend-port fallback.
    let udp_objects = [udp_route("dns", simple_rule("coredns", 5353))];
    let udp = translate_k8s_objects(&udp_objects, options()).expect("translation succeeds");
    assert!(udp.config.proxies.is_empty());
    assert!(udp.warnings.iter().any(|warning| {
        warning.contains(r#"UDPRoute "default"/"dns" has no valid attached Gateway listener"#)
    }));

    let tcp_route = l4_route(
        "TCPRoute",
        "db",
        json!({"rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]}),
    );
    let tcp = translate_k8s_objects(&[tcp_route], options()).expect("translation succeeds");
    assert_eq!(tcp.config.proxies[0].listen_port, Some(5432));

    let tls_route = l4_route(
        "TLSRoute",
        "db",
        json!({
            "hostnames": ["db.example.com"],
            "rules": [{"backendRefs": [{"name": "db", "port": 15443}]}]
        }),
    );
    let tls = translate_k8s_objects(&[tls_route], options()).expect("translation succeeds");
    assert_eq!(tls.config.proxies[0].listen_port, Some(15443));
}

#[test]
fn udp_route_with_only_non_gateway_parents_opens_no_listener() {
    // Ferrum implements no non-Gateway parent for UDPRoute, and such a route is
    // not a status candidate either (it names no managed Gateway). Falling back
    // to the backend port would bind an unannounced north-south UDP relay, so a
    // declared parent Ferrum cannot resolve must open nothing.
    let gamma = json!({
        "parentRefs": [{"group": "", "kind": "Service", "name": "coredns"}],
        "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
    });
    let gamma_objects = [gateway_class(), udp_route("gamma", gamma)];
    assert_no_listener_for_declared_parent(&gamma_objects, 5353);

    // A mistyped parent kind must fail the same way rather than silently
    // downgrading to the parentless fallback.
    let mistyped = json!({
        "parentRefs": [{"kind": "gateway", "name": "edge"}],
        "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
    });
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("typo", mistyped),
    ];
    assert_no_listener_for_declared_parent(&objects, 5353);

    // Kubernetes CRD admission rejects these shapes, but a config-source
    // boundary must not reinterpret present-but-invalid parentRefs as absent
    // and thereby open the legacy fallback listener.
    for parent_refs in [json!([]), json!({"name": "edge"})] {
        let invalid = json!({
            "parentRefs": parent_refs,
            "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
        });
        let invalid_objects = [gateway_class(), udp_route("invalid-parent-refs", invalid)];
        assert_no_listener_for_declared_parent(&invalid_objects, 5353);
    }
}

#[test]
fn udp_route_with_unmatched_section_name_opens_no_listener() {
    let route = udp_route(
        "dns",
        attached_rule("edge", "absent-listener", "coredns", 5353),
    );
    let objects = [gateway_class(), udp_gateway("edge", "dns", 15353), route];

    assert_rejected_route_opens_no_listener(&objects, 5353);
}

#[test]
fn udp_route_on_a_tcp_listener_opens_no_listener() {
    let spec = json!({
        "gatewayClassName": "ferrum",
        "listeners": [{
            "name": "stream",
            "port": 15353,
            "protocol": "TCP",
            "allowedRoutes": {"kinds": [{"kind": "TCPRoute"}]}
        }]
    });
    let gateway = gateway_object("edge", spec);
    let route = udp_route("dns", attached_rule("edge", "stream", "coredns", 5353));
    let objects = [gateway_class(), gateway, route];

    assert_rejected_route_opens_no_listener(&objects, 5353);
}

#[test]
fn udp_route_disallowed_by_listener_namespace_selector_opens_no_listener() {
    let spec = json!({
        "gatewayClassName": "ferrum",
        "listeners": [{
            "name": "dns",
            "port": 15353,
            "protocol": "UDP",
            "allowedRoutes": {
                "kinds": [{"kind": "UDPRoute"}],
                "namespaces": {
                    "from": "Selector",
                    "selector": {"matchLabels": {"gateway-access": "true"}}
                }
            }
        }]
    });
    let gateway = gateway_object("edge", spec);
    let route = udp_route("dns", attached_rule("edge", "dns", "coredns", 5353));
    let objects = [gateway_class(), gateway, route];

    assert_rejected_route_opens_no_listener(&objects, 5353);
}

// ---------------------------------------------------------------------------
// backendRefs is a weighted set (pinned Gateway API v1.5.1)
// ---------------------------------------------------------------------------

fn weighted_rule(legs: Value) -> Value {
    json!({
        "parentRefs": [{"name": "edge", "sectionName": "dns"}],
        "rules": [{"backendRefs": legs}]
    })
}

fn sole_proxy_and_upstream(
    result: &ferrum_edge::config_sources::k8s::K8sTranslation,
) -> (&Proxy, &Upstream) {
    assert_eq!(result.config.proxies.len(), 1);
    assert_eq!(result.config.upstreams.len(), 1);
    let proxy = &result.config.proxies[0];
    let upstream = &result.config.upstreams[0];
    assert_eq!(proxy.upstream_id.as_deref(), Some(upstream.id.as_str()));
    assert_eq!(upstream.namespace, proxy.namespace);
    (proxy, upstream)
}

fn target_weights(upstream: &Upstream) -> Vec<(String, u16, u32)> {
    upstream
        .targets
        .iter()
        .map(|target| (target.host.clone(), target.port, target.weight))
        .collect()
}

#[test]
fn udp_route_two_weighted_backends_materialize_one_weighted_upstream() {
    let spec = weighted_rule(json!([
        {"name": "coredns-a", "port": 5353, "weight": 3},
        {"name": "coredns-b", "port": 5354, "weight": 1}
    ]));
    let objects = udp_lab(spec);

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    let (proxy, upstream) = sole_proxy_and_upstream(&result);

    assert_eq!(proxy.listen_port, Some(15353));
    assert_eq!(proxy.backend_scheme, Some(BackendScheme::Udp));
    // The upstream is authoritative for a multi-leg rule; the direct backend
    // fields must not carry a second, contradictory destination.
    assert!(proxy.backend_host.is_empty());
    assert_eq!(proxy.backend_port, 0);
    assert_eq!(
        target_weights(upstream),
        vec![
            ("coredns-a.default.svc.cluster.local".to_string(), 5353, 3),
            ("coredns-b.default.svc.cluster.local".to_string(), 5354, 1),
        ]
    );
    assert_eq!(
        upstream.algorithm,
        LoadBalancerAlgorithm::WeightedRoundRobin
    );
}

#[test]
fn udp_route_omitted_weights_default_to_equal_shares() {
    let spec = weighted_rule(json!([
        {"name": "coredns-a", "port": 5353},
        {"name": "coredns-b", "port": 5353}
    ]));
    let objects = udp_lab(spec);

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    let (_, upstream) = sole_proxy_and_upstream(&result);

    assert!(upstream.targets.iter().all(|target| target.weight == 1));
    assert_eq!(upstream.algorithm, LoadBalancerAlgorithm::RoundRobin);
}

#[test]
fn udp_route_zero_weight_legs_are_filtered_from_the_upstream() {
    let spec = weighted_rule(json!([
        {"name": "coredns-a", "port": 5353, "weight": 2},
        {"name": "dark", "port": 5353, "weight": 0},
        {"name": "coredns-b", "port": 5353, "weight": 1}
    ]));
    let objects = udp_lab(spec);

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    let (_, upstream) = sole_proxy_and_upstream(&result);

    assert_eq!(upstream.targets.len(), 2);
    assert!(
        !upstream
            .targets
            .iter()
            .any(|target| target.host.starts_with("dark."))
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("UDPRoute skipped 1 zero-weight"))
    );
}

#[test]
fn udp_route_single_serviceable_leg_stays_a_direct_backend() {
    // A one-leg rule must not gain an upstream indirection.
    let spec = weighted_rule(json!([{"name": "coredns", "port": 5353, "weight": 7}]));
    let objects = udp_lab(spec);

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert_eq!(result.config.proxies.len(), 1);
    assert!(result.config.upstreams.is_empty());
    assert_eq!(
        result.config.proxies[0].backend_host,
        "coredns.default.svc.cluster.local"
    );
    assert_eq!(result.config.proxies[0].backend_port, 5353);
    assert!(result.config.proxies[0].upstream_id.is_none());
}

#[test]
fn udp_route_unresolved_leg_keeps_its_weight_as_a_blackhole_target() {
    // Pinned v1.5.1 UDPRoute: "if an invalid backend is requested to have 80%
    // of the packets, then 80% of packets must be dropped instead". The
    // unresolved leg keeps weight 3 pointed at an unresolvable host; the valid
    // leg keeps weight 1 and is NOT renormalized up to the whole rule.
    let spec = weighted_rule(json!([
        {"name": "coredns", "port": 5353, "weight": 1},
        {"name": "absent", "port": 5353, "weight": 3}
    ]));
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        service("default", "coredns", 5353),
        udp_route("dns", spec),
    ];

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    let (_, upstream) = sole_proxy_and_upstream(&result);

    assert_eq!(
        target_weights(upstream),
        vec![
            ("coredns.default.svc.cluster.local".to_string(), 5353, 1),
            ("ferrum-zero-weight.invalid.".to_string(), 65535, 3),
        ]
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("not redistributed"))
    );
}

#[test]
fn udp_route_leg_whose_service_lacks_the_port_is_a_blackhole_target() {
    let spec = weighted_rule(json!([
        {"name": "coredns", "port": 5353, "weight": 1},
        {"name": "coredns", "port": 9999, "weight": 1}
    ]));
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        service("default", "coredns", 5353),
        udp_route("dns", spec),
    ];

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    let (_, upstream) = sole_proxy_and_upstream(&result);

    assert_eq!(
        target_weights(upstream),
        vec![
            ("coredns.default.svc.cluster.local".to_string(), 5353, 1),
            ("ferrum-zero-weight.invalid.".to_string(), 65535, 1),
        ]
    );
}

#[test]
fn udp_route_status_reports_unresolved_refs_for_a_mixed_rule() {
    let spec = weighted_rule(json!([
        {"name": "coredns", "port": 5353, "weight": 1},
        {"name": "absent", "port": 5353, "weight": 3}
    ]));
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        service("default", "coredns", 5353),
        udp_route("dns", spec),
    ];

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);

    assert_eq!(
        route_condition(&updates, "dns", "ResolvedRefs").as_deref(),
        Some("False")
    );
    // The rule still attaches; only the reference resolution is negative.
    assert_eq!(
        route_condition(&updates, "dns", "Accepted").as_deref(),
        Some("True")
    );
}

#[test]
fn udp_route_denied_cross_namespace_leg_fails_the_whole_rule_closed() {
    // No ReferenceGrant: the rule is unrepresentable as a weighted set that
    // still honors the denial, so the entire route fails closed instead of
    // silently serving only the permitted leg.
    let spec = json!({
        "parentRefs": [{"name": "edge", "sectionName": "dns"}],
        "rules": [{"backendRefs": [
            {"name": "coredns", "port": 5353, "weight": 1},
            {"name": "coredns", "namespace": "backends", "port": 5353, "weight": 1}
        ]}]
    });
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns", spec),
    ];

    let err = translate_k8s_objects(&objects, multi_namespace_options())
        .expect_err("an ungranted leg fails the rule closed");

    assert!(
        err.to_string()
            .contains("requires a matching ReferenceGrant")
    );
}

#[test]
fn udp_route_unsupported_backend_kind_in_a_set_fails_the_whole_rule_closed() {
    let spec = weighted_rule(json!([
        {"name": "coredns", "port": 5353, "weight": 1},
        {"group": "example.com", "kind": "DatagramSink", "name": "sink", "port": 5353}
    ]));
    let objects = udp_lab(spec);

    let err = translate_k8s_objects(&objects, options())
        .expect_err("an unsupported kind fails the rule closed");

    let message = err.to_string();
    assert!(
        message
            .contains(r#"unsupported backendRef target group "example.com" kind "DatagramSink""#)
    );
    assert!(message.contains("UDPRoute only supports core Service backendRefs"));
}

#[test]
fn udp_route_zero_weight_leg_still_has_its_port_validated() {
    // A malformed port is a spec error regardless of the weight that would
    // have selected the leg.
    for port in [json!(0), json!(70000)] {
        let spec = weighted_rule(json!([
            {"name": "coredns", "port": 5353, "weight": 1},
            {"name": "dark", "port": port, "weight": 0}
        ]));
        let objects = udp_lab(spec);

        let err = translate_k8s_objects(&objects, options())
            .expect_err("a malformed port fails closed at any weight");

        assert!(err.to_string().contains("UDPRoute backendRefs[].port"));
    }
}

#[test]
fn udp_route_zero_weight_leg_still_has_its_target_kind_validated() {
    let spec = weighted_rule(json!([
        {"name": "coredns", "port": 5353, "weight": 1},
        {
            "group": "example.com",
            "kind": "DatagramSink",
            "name": "dark",
            "port": 5353,
            "weight": 0
        }
    ]));
    let objects = udp_lab(spec);

    let err = translate_k8s_objects(&objects, options())
        .expect_err("an unsupported zero-weight target kind fails closed");

    let message = err.to_string();
    assert!(
        message
            .contains(r#"unsupported backendRef target group "example.com" kind "DatagramSink""#)
    );
    assert!(message.contains("UDPRoute only supports core Service backendRefs"));
}

#[test]
fn udp_route_zero_weight_cross_namespace_leg_still_requires_reference_grant() {
    let spec = weighted_rule(json!([
        {"name": "coredns", "port": 5353, "weight": 1},
        {
            "name": "coredns",
            "namespace": "backends",
            "port": 5353,
            "weight": 0
        }
    ]));
    let objects = udp_lab(spec);

    let err = translate_k8s_objects(&objects, multi_namespace_options())
        .expect_err("an ungranted zero-weight cross-namespace ref fails closed");

    assert!(
        err.to_string()
            .contains("requires a matching ReferenceGrant")
    );
}

#[test]
fn udp_route_hostile_weight_shapes_fail_closed() {
    for weight in [json!(1_000_001), json!(-1), json!("high"), json!(1.5)] {
        let spec = weighted_rule(json!([
            {"name": "coredns-a", "port": 5353, "weight": 1},
            {"name": "coredns-b", "port": 5353, "weight": weight}
        ]));
        let objects = udp_lab(spec);

        let err = translate_k8s_objects(&objects, options())
            .expect_err("an out-of-range or non-integer weight fails closed");

        assert!(err.to_string().contains("weight must be between 0 and"));
    }
}

#[test]
fn udp_route_accepts_and_normalizes_gateway_api_max_weight() {
    let spec = weighted_rule(json!([
        {"name": "coredns-a", "port": 5353, "weight": 1},
        {"name": "coredns-b", "port": 5353, "weight": 1_000_000}
    ]));
    let objects = udp_lab(spec);

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    let (_, upstream) = sole_proxy_and_upstream(&result);
    let weights: Vec<u32> = upstream
        .targets
        .iter()
        .map(|target| target.weight)
        .collect();

    assert_eq!(weights, vec![1, 65_535]);
}

#[test]
fn udp_route_backend_ref_fan_out_is_bounded() {
    // Gateway API bounds UDPRouteRule.backendRefs at 16; a non-CRD-validated
    // config source must not be able to expand an unbounded target set.
    let legs: Vec<Value> = (0..17)
        .map(|index| json!({"name": format!("coredns-{index}"), "port": 5353}))
        .collect();
    let spec = weighted_rule(Value::Array(legs));
    let objects = udp_lab(spec);

    let err =
        translate_k8s_objects(&objects, options()).expect_err("a 17-entry fan-out fails closed");

    assert!(err.to_string().contains("at most 16 entries"));
}

/// Two matchless rules on one listener, each with its own backend.
///
/// The pinned Gateway API v1.5.1 CRD accepts `1..=16` `UDPRouteSpec.rules`, so
/// this object is **valid upstream**.
fn multi_rule_spec() -> Value {
    json!({
        "parentRefs": [{"name": "edge", "sectionName": "dns"}],
        "rules": [
            {"backendRefs": [{"name": "coredns-a", "port": 5353}]},
            {"backendRefs": [{"name": "coredns-b", "port": 5354}]}
        ]
    })
}

/// `UDPRouteRule` carries only `name` and `backendRefs` — no match predicate —
/// so N rules are N indistinguishable matches on one port with no
/// standards-defined precedence, and their per-rule weights are not comparable
/// across rules. Ferrum declines to invent an aggregate and rejects fail closed
/// with a `spec.rules`-specific diagnostic that states the upstream bound and
/// Ferrum's own.
#[test]
fn udp_route_multiple_matchless_rules_fail_closed() {
    let objects = udp_lab(multi_rule_spec());

    let err = translate_k8s_objects(&objects, options()).expect_err("competing rules fail closed");

    let message = err.to_string();
    assert!(message.contains("UDPRoute spec.rules"), "{message}");
    // The diagnostic must name the exact upstream bound it is declining, not
    // imply the object is malformed.
    assert!(message.contains("permits 1..=16 rules"), "{message}");
    assert!(message.contains("not implemented by Ferrum"), "{message}");
    assert!(message.contains("no match predicate"), "{message}");
}

/// The whole point of the previous test's marker: an upstream-valid object
/// Ferrum declines must report `Accepted=False` with the upstream
/// `UnsupportedValue` reason, never the generic `Invalid` (which claims the
/// object is malformed). Backend resolution is reported on its own terms.
#[test]
fn udp_route_multiple_rules_report_unsupported_value_not_invalid() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        service("default", "coredns-a", 5353),
        service("default", "coredns-b", 5354),
        udp_route("dns", multi_rule_spec()),
    ];

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);

    assert_eq!(
        route_condition(&updates, "dns", "Accepted").as_deref(),
        Some("False")
    );
    assert_eq!(
        route_condition_reason(&updates, "dns", "Accepted").as_deref(),
        Some("UnsupportedValue")
    );
    assert_eq!(
        route_condition(&updates, "dns", "Programmed").as_deref(),
        Some("False")
    );
    assert_eq!(
        route_condition(&updates, "dns", "ResolvedRefs").as_deref(),
        Some("True")
    );
}

/// A shape the CRD itself forbids stays `Invalid`: the marker must not widen
/// into "every rejection is merely unsupported".
#[test]
fn udp_route_malformed_shape_still_reports_invalid() {
    let spec = json!({
        "parentRefs": [{"name": "edge", "sectionName": "dns"}],
        "hostnames": ["dns.example.com"],
        "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
    });
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        service("default", "coredns", 5353),
        udp_route("dns", spec),
    ];

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);

    assert_eq!(
        route_condition_reason(&updates, "dns", "Accepted").as_deref(),
        Some("Invalid")
    );
}

#[test]
fn udp_route_missing_rules_rejects_invalid() {
    let spec = json!({
        "parentRefs": [{"name": "edge", "sectionName": "dns"}]
    });
    let objects = udp_lab(spec);

    let err = translate_k8s_objects(&objects, options()).expect_err("missing rules fail closed");
    let message = err.to_string();
    assert!(message.contains("UDPRoute spec.rules"), "{message}");
    assert!(message.contains("required"), "{message}");

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    assert_eq!(
        route_condition_reason(&updates, "dns", "Accepted").as_deref(),
        Some("Invalid")
    );
}

#[test]
fn udp_route_non_array_rules_rejects_invalid() {
    let spec = json!({
        "parentRefs": [{"name": "edge", "sectionName": "dns"}],
        "rules": {"backendRefs": [{"name": "coredns", "port": 5353}]}
    });
    let objects = udp_lab(spec);

    let err = translate_k8s_objects(&objects, options()).expect_err("non-array rules fail closed");
    assert!(
        err.to_string()
            .contains("UDPRoute spec.rules must be an array")
    );

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    assert_eq!(
        route_condition_reason(&updates, "dns", "Accepted").as_deref(),
        Some("Invalid")
    );
}

#[test]
fn udp_route_empty_rules_rejects_invalid() {
    let spec = json!({
        "parentRefs": [{"name": "edge", "sectionName": "dns"}],
        "rules": []
    });
    let objects = udp_lab(spec);

    let err = translate_k8s_objects(&objects, options()).expect_err("empty rules fail closed");
    assert!(
        err.to_string()
            .contains("UDPRoute spec.rules must contain at least 1")
    );

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    assert_eq!(
        route_condition_reason(&updates, "dns", "Accepted").as_deref(),
        Some("Invalid")
    );
}

#[test]
fn udp_route_missing_backend_refs_rejects_invalid() {
    let spec = json!({
        "parentRefs": [{"name": "edge", "sectionName": "dns"}],
        "rules": [{}]
    });
    let objects = udp_lab(spec);

    let err =
        translate_k8s_objects(&objects, options()).expect_err("missing backendRefs fail closed");
    assert!(err.to_string().contains("UDPRoute backendRefs is required"));

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    assert_eq!(
        route_condition_reason(&updates, "dns", "Accepted").as_deref(),
        Some("Invalid")
    );
}

#[test]
fn udp_route_non_array_backend_refs_rejects_invalid() {
    let spec = json!({
        "parentRefs": [{"name": "edge", "sectionName": "dns"}],
        "rules": [{"backendRefs": {"name": "coredns", "port": 5353}}]
    });
    let objects = udp_lab(spec);

    let err =
        translate_k8s_objects(&objects, options()).expect_err("non-array backendRefs fail closed");
    assert!(
        err.to_string()
            .contains("UDPRoute backendRefs must be an array")
    );

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    assert_eq!(
        route_condition_reason(&updates, "dns", "Accepted").as_deref(),
        Some("Invalid")
    );
}

#[test]
fn udp_route_empty_backend_refs_rejects_invalid() {
    let spec = json!({
        "parentRefs": [{"name": "edge", "sectionName": "dns"}],
        "rules": [{"backendRefs": []}]
    });
    let objects = udp_lab(spec);

    let err =
        translate_k8s_objects(&objects, options()).expect_err("empty backendRefs fail closed");
    assert!(
        err.to_string()
            .contains("UDPRoute backendRefs must contain at least 1")
    );

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    assert_eq!(
        route_condition_reason(&updates, "dns", "Accepted").as_deref(),
        Some("Invalid")
    );
}

#[test]
fn udp_routes_on_the_same_listener_arbitrate_oldest_wins() {
    let winner = udp_route_at(
        "dns-old",
        "2024-01-01T00:00:00Z",
        attached_rule("edge", "dns", "coredns-a", 5353),
    );
    let mut loser = udp_route_at(
        "dns-new",
        "2024-01-02T00:00:00Z",
        attached_rule("edge", "dns", "coredns-b", 5354),
    );
    // Weighted loser would otherwise generate an upstream; conflict must
    // suppress that orphan as well as the listen-port proxy.
    loser.spec = json!({
        "parentRefs": [{"name": "edge", "sectionName": "dns"}],
        "rules": [{"backendRefs": [
            {"name": "coredns-b", "port": 5354, "weight": 1},
            {"name": "coredns-c", "port": 5355, "weight": 1}
        ]}]
    });
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        winner,
        loser,
    ];

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert_eq!(result.config.proxies.len(), 1, "exactly one listener owner");
    assert_eq!(result.config.proxies[0].listen_port, Some(15353));
    assert_eq!(
        result.config.proxies[0].backend_host,
        "coredns-a.default.svc.cluster.local"
    );
    assert!(
        result.config.upstreams.is_empty(),
        "weighted conflict loser must not leave an orphan upstream: {:?}",
        result
            .config
            .upstreams
            .iter()
            .map(|upstream| upstream.id.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        result
            .route_conflicts
            .iter()
            .any(|conflict| conflict.loser.name == "dns-new" && conflict.winner.name == "dns-old"),
        "expected conflict evidence, got {:?}",
        result.route_conflicts
    );

    let updates = plan_gateway_api_status_updates(&objects, options(), &result.route_conflicts);
    // Official Gateway API UDPRoute multiple-route attachment: both routes
    // report Accepted=True; only the oldest is Programmed/effective. Listener
    // attachedRoutes counts every accepted attached route, including the
    // non-effective newer one — not materialized-only.
    assert_eq!(
        route_condition(&updates, "dns-old", "Accepted").as_deref(),
        Some("True")
    );
    assert_eq!(
        route_condition_reason(&updates, "dns-old", "Accepted").as_deref(),
        Some("Accepted")
    );
    assert_eq!(
        route_condition(&updates, "dns-old", "Programmed").as_deref(),
        Some("True")
    );
    assert_eq!(
        route_condition(&updates, "dns-old", "Conflicted").as_deref(),
        Some("False")
    );
    assert_eq!(
        route_condition(&updates, "dns-new", "Accepted").as_deref(),
        Some("True"),
        "fully shadowed newer UDPRoute must stay Accepted=True"
    );
    assert_eq!(
        route_condition_reason(&updates, "dns-new", "Accepted").as_deref(),
        Some("Accepted"),
        "conflict must not flip Accepted reason to Conflicted"
    );
    assert_eq!(
        route_condition(&updates, "dns-new", "Programmed").as_deref(),
        Some("False")
    );
    assert_eq!(
        route_condition_reason(&updates, "dns-new", "Programmed").as_deref(),
        Some("Conflicted")
    );
    assert_eq!(
        route_condition(&updates, "dns-new", "Conflicted").as_deref(),
        Some("True")
    );
    assert_eq!(
        gateway_listener_attached_routes(&updates, "edge", "dns"),
        Some(2),
        "attachedRoutes must count accepted attached UDPRoutes including the non-effective newer route"
    );
}

#[test]
fn udp_routes_on_distinct_listeners_remain_independent() {
    let gateway = gateway_object(
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {
                    "name": "dns",
                    "port": 15353,
                    "protocol": "UDP",
                    "allowedRoutes": {"kinds": [{"kind": "UDPRoute"}]}
                },
                {
                    "name": "metrics",
                    "port": 15354,
                    "protocol": "UDP",
                    "allowedRoutes": {"kinds": [{"kind": "UDPRoute"}]}
                }
            ]
        }),
    );
    let objects = [
        gateway_class(),
        gateway,
        udp_route("dns", attached_rule("edge", "dns", "coredns-a", 5353)),
        udp_route(
            "metrics",
            attached_rule("edge", "metrics", "coredns-b", 5354),
        ),
    ];

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert!(
        result.route_conflicts.is_empty(),
        "{:?}",
        result.route_conflicts
    );
    let mut ports: Vec<Option<u16>> = result
        .config
        .proxies
        .iter()
        .map(|proxy| proxy.listen_port)
        .collect();
    ports.sort();
    assert_eq!(ports, vec![Some(15353), Some(15354)]);
}

#[test]
fn udp_route_selector_aliases_to_the_same_listener_conflict() {
    // Wildcard parentRef and sectionName both resolve to listener `dns`.
    let winner = udp_route_at(
        "wildcard",
        "2024-01-01T00:00:00Z",
        json!({
            "parentRefs": [{"name": "edge"}],
            "rules": [{"backendRefs": [{"name": "coredns-a", "port": 5353}]}]
        }),
    );
    let loser = udp_route_at(
        "section",
        "2024-01-02T00:00:00Z",
        attached_rule("edge", "dns", "coredns-b", 5354),
    );
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        winner,
        loser,
    ];

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert_eq!(result.config.proxies.len(), 1);
    assert_eq!(
        result.config.proxies[0].backend_host,
        "coredns-a.default.svc.cluster.local"
    );
    assert!(
        result
            .route_conflicts
            .iter()
            .any(|conflict| conflict.loser.name == "section" && conflict.winner.name == "wildcard"),
        "{:?}",
        result.route_conflicts
    );
}

#[test]
fn udp_route_equal_timestamp_tie_breaks_by_namespace_name() {
    let older_name = udp_route_in(
        "default",
        "a-route",
        "2024-01-01T00:00:00Z",
        attached_rule("edge", "dns", "coredns-a", 5353),
    );
    let newer_name = udp_route_in(
        "default",
        "b-route",
        "2024-01-01T00:00:00Z",
        attached_rule("edge", "dns", "coredns-b", 5354),
    );
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        newer_name,
        older_name,
    ];

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert_eq!(result.config.proxies.len(), 1);
    assert_eq!(
        result.config.proxies[0].backend_host,
        "coredns-a.default.svc.cluster.local"
    );
    assert!(
        result
            .route_conflicts
            .iter()
            .any(|conflict| conflict.winner.name == "a-route" && conflict.loser.name == "b-route"),
        "{:?}",
        result.route_conflicts
    );
}

#[test]
fn udp_route_partial_listener_conflict_keeps_the_non_colliding_listener() {
    let gateway = gateway_object(
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {
                    "name": "dns",
                    "port": 15353,
                    "protocol": "UDP",
                    "allowedRoutes": {"kinds": [{"kind": "UDPRoute"}]}
                },
                {
                    "name": "metrics",
                    "port": 15354,
                    "protocol": "UDP",
                    "allowedRoutes": {"kinds": [{"kind": "UDPRoute"}]}
                }
            ]
        }),
    );
    let exclusive = udp_route_at(
        "dns-only",
        "2024-01-01T00:00:00Z",
        attached_rule("edge", "dns", "coredns-a", 5353),
    );
    let shared = udp_route_at(
        "both",
        "2024-01-02T00:00:00Z",
        json!({
            "parentRefs": [{"name": "edge"}],
            "rules": [{"backendRefs": [{"name": "coredns-b", "port": 5354}]}]
        }),
    );
    let objects = [gateway_class(), gateway, exclusive, shared];

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    let mut ports: Vec<Option<u16>> = result
        .config
        .proxies
        .iter()
        .map(|proxy| proxy.listen_port)
        .collect();
    ports.sort();
    // dns-only owns 15353; both keeps only the non-colliding metrics listener.
    assert_eq!(ports, vec![Some(15353), Some(15354)]);
    let metrics_owner = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_port == Some(15354))
        .expect("metrics listener remains");
    assert!(metrics_owner.id.contains("both"));
    assert!(
        result
            .route_conflicts
            .iter()
            .any(|conflict| conflict.loser.name == "both" && conflict.winner.name == "dns-only"),
        "{:?}",
        result.route_conflicts
    );

    let updates = plan_gateway_api_status_updates(&objects, options(), &result.route_conflicts);
    // Partial loss on one concrete listener: the multi-listener route stays
    // Accepted and Programmed (retains metrics), with supplementary Conflicted.
    assert_eq!(
        route_condition(&updates, "both", "Accepted").as_deref(),
        Some("True")
    );
    assert_eq!(
        route_condition_reason(&updates, "both", "Accepted").as_deref(),
        Some("Accepted")
    );
    assert_eq!(
        route_condition(&updates, "both", "Programmed").as_deref(),
        Some("True")
    );
    assert_eq!(
        route_condition(&updates, "both", "Conflicted").as_deref(),
        Some("True")
    );
    assert_eq!(
        route_condition(&updates, "dns-only", "Accepted").as_deref(),
        Some("True")
    );
    assert_eq!(
        route_condition(&updates, "dns-only", "Programmed").as_deref(),
        Some("True")
    );
    assert_eq!(
        gateway_listener_attached_routes(&updates, "edge", "dns"),
        Some(2),
        "dns listener attachedRoutes includes both the exclusive winner and the partially conflicted multi-listener route"
    );
    assert_eq!(
        gateway_listener_attached_routes(&updates, "edge", "metrics"),
        Some(1)
    );
}

#[test]
fn udp_route_conflict_loser_promotes_after_winner_delete() {
    let gateway = udp_gateway("edge", "dns", 15353);
    let winner = udp_route_at(
        "dns-old",
        "2024-01-01T00:00:00Z",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "dns"}],
            "rules": [{"backendRefs": [
                {"name": "coredns-a", "port": 5353, "weight": 1},
                {"name": "coredns-b", "port": 5354, "weight": 1}
            ]}]
        }),
    );
    let loser = udp_route_at(
        "dns-new",
        "2024-01-02T00:00:00Z",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "dns"}],
            "rules": [{"backendRefs": [
                {"name": "coredns-c", "port": 5355, "weight": 1},
                {"name": "coredns-d", "port": 5356, "weight": 1}
            ]}]
        }),
    );

    let contested = translate_k8s_objects(
        &[
            gateway_class(),
            gateway.clone(),
            winner.clone(),
            loser.clone(),
        ],
        options(),
    )
    .expect("translation succeeds");
    assert_eq!(contested.config.proxies.len(), 1);
    assert_eq!(contested.config.upstreams.len(), 1);
    assert!(contested.config.upstreams[0].id.contains("dns-old"));

    let after_delete = translate_k8s_objects(&[gateway_class(), gateway, loser], options())
        .expect("translation succeeds");
    assert_eq!(after_delete.config.proxies.len(), 1);
    assert_eq!(after_delete.config.upstreams.len(), 1);
    assert!(after_delete.config.upstreams[0].id.contains("dns-new"));
    assert!(after_delete.route_conflicts.is_empty());
}

#[test]
fn udp_route_weight_only_update_replaces_the_upstream_targets() {
    let gateway = udp_gateway("edge", "dns", 15353);
    let before = weighted_rule(json!([
        {"name": "coredns-a", "port": 5353, "weight": 1},
        {"name": "coredns-b", "port": 5353, "weight": 1}
    ]));
    let after = weighted_rule(json!([
        {"name": "coredns-a", "port": 5353, "weight": 9},
        {"name": "coredns-b", "port": 5353, "weight": 1}
    ]));

    let first = translate_k8s_objects(
        &[gateway_class(), gateway.clone(), udp_route("dns", before)],
        options(),
    )
    .expect("translation succeeds");
    let (_, first_upstream) = sole_proxy_and_upstream(&first);
    let upstream_id = first_upstream.id.clone();
    assert_eq!(first_upstream.algorithm, LoadBalancerAlgorithm::RoundRobin);

    let second = translate_k8s_objects(
        &[gateway_class(), gateway, udp_route("dns", after)],
        options(),
    )
    .expect("translation succeeds");
    let (_, second_upstream) = sole_proxy_and_upstream(&second);

    // Same deterministic id, replaced targets — no stale sibling upstream.
    assert_eq!(second_upstream.id, upstream_id);
    assert_eq!(
        second_upstream
            .targets
            .iter()
            .map(|target| target.weight)
            .collect::<Vec<_>>(),
        vec![9, 1]
    );
    assert_eq!(
        second_upstream.algorithm,
        LoadBalancerAlgorithm::WeightedRoundRobin
    );
}

#[test]
fn udp_route_shrinking_to_one_leg_drops_the_upstream() {
    let gateway = udp_gateway("edge", "dns", 15353);
    let two_legs = weighted_rule(json!([
        {"name": "coredns-a", "port": 5353, "weight": 1},
        {"name": "coredns-b", "port": 5353, "weight": 1}
    ]));
    let one_leg = weighted_rule(json!([{"name": "coredns-a", "port": 5353, "weight": 1}]));

    let before = translate_k8s_objects(
        &[gateway_class(), gateway.clone(), udp_route("dns", two_legs)],
        options(),
    )
    .expect("translation succeeds");
    assert_eq!(before.config.upstreams.len(), 1);

    let after = translate_k8s_objects(
        &[gateway_class(), gateway, udp_route("dns", one_leg)],
        options(),
    )
    .expect("translation succeeds");

    assert!(
        after.config.upstreams.is_empty(),
        "the replaced snapshot must not retain a stale upstream"
    );
    assert_eq!(
        after.config.proxies[0].backend_host,
        "coredns-a.default.svc.cluster.local"
    );
    assert!(after.config.proxies[0].upstream_id.is_none());
}

#[test]
fn udp_route_deletion_removes_both_proxy_and_upstream() {
    let gateway = udp_gateway("edge", "dns", 15353);
    let spec = weighted_rule(json!([
        {"name": "coredns-a", "port": 5353, "weight": 1},
        {"name": "coredns-b", "port": 5353, "weight": 1}
    ]));

    let live = translate_k8s_objects(
        &[gateway_class(), gateway.clone(), udp_route("dns", spec)],
        options(),
    )
    .expect("translation succeeds");
    assert_eq!(live.config.proxies.len(), 1);
    assert_eq!(live.config.upstreams.len(), 1);

    let deleted = translate_k8s_objects(&[gateway_class(), gateway], options())
        .expect("translation succeeds without the route");

    assert!(deleted.config.proxies.is_empty());
    assert!(deleted.config.upstreams.is_empty());
}

#[test]
fn udp_route_on_two_listeners_shares_one_upstream_across_distinct_proxies() {
    let spec = json!({
        "gatewayClassName": "ferrum",
        "listeners": [
            {
                "name": "dns",
                "port": 15353,
                "protocol": "UDP",
                "allowedRoutes": {"kinds": [{"kind": "UDPRoute"}]}
            },
            {
                "name": "dns-alt",
                "port": 15354,
                "protocol": "UDP",
                "allowedRoutes": {"kinds": [{"kind": "UDPRoute"}]}
            }
        ]
    });
    let gateway = gateway_object("edge", spec);
    let route_spec = json!({
        "parentRefs": [{"name": "edge"}],
        "rules": [{"backendRefs": [
            {"name": "coredns-a", "port": 5353, "weight": 1},
            {"name": "coredns-b", "port": 5353, "weight": 1}
        ]}]
    });
    let objects = [gateway_class(), gateway, udp_route("dns", route_spec)];

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert_eq!(result.config.upstreams.len(), 1);
    let mut ports: Vec<Option<u16>> = result
        .config
        .proxies
        .iter()
        .map(|proxy| proxy.listen_port)
        .collect();
    ports.sort();
    assert_eq!(ports, vec![Some(15353), Some(15354)]);

    let ids: Vec<&str> = result
        .config
        .proxies
        .iter()
        .map(|proxy| proxy.id.as_str())
        .collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1], "each listener needs its own proxy id");
    let upstream_id = result.config.upstreams[0].id.as_str();
    assert!(
        result
            .config
            .proxies
            .iter()
            .all(|proxy| proxy.upstream_id.as_deref() == Some(upstream_id))
    );
}

#[test]
fn udp_route_proxy_ids_do_not_collide_with_a_same_named_tcp_route() {
    // The historical L4 proxy id encodes only (namespace, name, rule index).
    // Attach a real UDP Gateway so the UDPRoute materializes; parentless
    // TCPRoute keeps the legacy backend-port fallback.
    let tcp = l4_route(
        "TCPRoute",
        "dns",
        json!({"rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]}),
    );
    let udp = udp_route("dns", attached_rule("edge", "dns", "coredns", 5353));
    let objects = [gateway_class(), udp_gateway("edge", "dns", 15353), tcp, udp];

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert_eq!(
        result.config.proxies.len(),
        2,
        "a UDPRoute must not upsert over a same-named TCPRoute, got {:?}",
        result
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.id.clone())
            .collect::<Vec<_>>()
    );
    let udp_proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.backend_scheme == Some(BackendScheme::Udp))
        .expect("the UDP proxy survives");
    assert!(udp_proxy.id.contains("udproute"));
}

#[test]
fn deleting_a_weighted_udp_route_prunes_its_generated_upstream_from_live_config() {
    // Translation alone regenerates from the snapshot, but the live gateway
    // config is a *merge* of the K8s translation onto whatever another source
    // owns. If `gwapi-l4-upstream-` is missing from the reconciler's managed
    // prefix list, the deleted route's upstream survives the merge forever.
    let gateway = udp_gateway("edge", "dns", 15353);
    let spec = weighted_rule(json!([
        {"name": "coredns-a", "port": 5353, "weight": 1},
        {"name": "coredns-b", "port": 5353, "weight": 1}
    ]));
    let live = translate_k8s_objects(
        &[gateway_class(), gateway.clone(), udp_route("dns", spec)],
        options(),
    )
    .expect("translation succeeds");
    let managed: BTreeSet<String> = ["default".to_string()].into_iter().collect();

    let active = merge_k8s_translation(&GatewayConfig::default(), &live.config, &managed);
    assert_eq!(active.upstreams.len(), 1);
    assert!(active.upstreams[0].id.starts_with("gwapi-l4-upstream-"));

    let deleted = translate_k8s_objects(&[gateway_class(), gateway], options())
        .expect("translation succeeds without the route");
    let after = merge_k8s_translation(&active, &deleted.config, &managed);

    assert!(
        after.upstreams.is_empty(),
        "the generated L4 upstream must be pruned with its route, got {:?}",
        after
            .upstreams
            .iter()
            .map(|upstream| upstream.id.clone())
            .collect::<Vec<_>>()
    );
    assert!(after.proxies.is_empty());
}

#[test]
fn udproute_is_wired_through_watch_translation_and_status() {
    // The three surfaces a route kind needs; a partial wiring silently drops
    // UDPRoute back to "watched but inert".
    assert!(WATCHER_SRC.contains("plural: \"udproutes\""));
    assert!(GATEWAY_API_SRC.contains("\"UDPRoute\" => {"));
    assert!(GATEWAY_API_SRC.contains("\"UDP\" => vec![\"UDPRoute\"]"));
    assert!(STATUS_SRC.contains("(\"UDPRoute\", \"v1alpha2\") => \"udproutes\""));
}

#[test]
fn udp_route_ids_follow_the_shared_l4_id_rule() {
    // UDPRoute has no id exemption: like TCPRoute/TLSRoute it keeps the
    // readable id in its own namespace and would get a source-bound id when
    // materialized in a parent Gateway's namespace.
    let udp_exemption = "scheme.is_udp() || config_namespace == object.metadata.namespace";
    assert!(
        !GATEWAY_API_SRC.contains(udp_exemption),
        "UDPRoute proxy ids must not bypass the source-bound id rule"
    );

    let gateway_in = |namespace: &str, port: u16| {
        let mut gateway = udp_gateway("edge", "dns", port);
        gateway.metadata.namespace = namespace.to_string();
        gateway
    };
    // `shop`/`checkout-api` and `shop-checkout`/`api` dash-join to the same
    // readable id; each must still keep its own proxy.
    let objects = [
        gateway_class(),
        gateway_in("shop", 15353),
        gateway_in("shop-checkout", 15354),
        udp_route_in(
            "shop",
            "checkout-api",
            "2024-01-01T00:00:00Z",
            attached_rule("edge", "dns", "coredns", 5353),
        ),
        udp_route_in(
            "shop-checkout",
            "api",
            "2024-01-01T00:00:00Z",
            attached_rule("edge", "dns", "coredns", 5353),
        ),
    ];
    let namespaces = vec!["shop".to_string(), "shop-checkout".to_string()];
    let options = options().with_source_namespaces(namespaces);

    let result = translate_k8s_objects(&objects, options).expect("translation succeeds");

    let keys: BTreeSet<(String, String)> = result
        .config
        .proxies
        .iter()
        .map(|proxy| (proxy.namespace.clone(), proxy.id.clone()))
        .collect();
    assert_eq!(keys.len(), 2, "each UDPRoute keeps its own proxy: {keys:?}");
    let listen_ports: BTreeSet<Option<u16>> = result
        .config
        .proxies
        .iter()
        .map(|proxy| proxy.listen_port)
        .collect();
    assert_eq!(
        listen_ports,
        BTreeSet::from([Some(15353), Some(15354)]),
        "neither route may replace the other's listener"
    );
    for proxy in &result.config.proxies {
        assert!(
            !proxy.id.contains("__"),
            "an own-namespace UDPRoute keeps the readable id: {}",
            proxy.id
        );
    }
}
