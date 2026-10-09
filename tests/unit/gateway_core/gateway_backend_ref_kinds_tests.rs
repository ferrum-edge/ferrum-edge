//! Gateway API non-Service `backendRef` kinds (issue #3270).
//!
//! Covers the shared typed backend-kind adapter for MCS `ServiceImport`
//! (GEP-1748): same-namespace materialization, cross-namespace ReferenceGrant,
//! unknown-kind rejection, missing-target fail-closed, update/withdrawal, and
//! status/`ResolvedRefs` parity with translation.

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslation, K8sTranslationOptions, translate_k8s_objects,
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
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, name: &str, namespace: &str, api_version: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{namespace}-{name}"),
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

fn http_route(name: &str, namespace: &str, backend_refs: Value) -> K8sObject {
    object(
        "HTTPRoute",
        name,
        namespace,
        "gateway.networking.k8s.io/v1",
        json!({
            "rules": [{ "backendRefs": backend_refs }]
        }),
    )
}

fn http_route_with_parent(name: &str, namespace: &str, backend_refs: Value) -> K8sObject {
    object(
        "HTTPRoute",
        name,
        namespace,
        "gateway.networking.k8s.io/v1",
        json!({
            "parentRefs": [{"name": "edge"}],
            "rules": [{ "backendRefs": backend_refs }]
        }),
    )
}

fn service_import(name: &str, namespace: &str, port: u16) -> K8sObject {
    service_import_with_ports(
        name,
        namespace,
        "multicluster.x-k8s.io/v1alpha1",
        json!([{ "port": port, "protocol": "TCP" }]),
    )
}

fn service_import_with_ports(
    name: &str,
    namespace: &str,
    api_version: &str,
    ports: Value,
) -> K8sObject {
    object(
        "ServiceImport",
        name,
        namespace,
        api_version,
        json!({
            "type": "ClusterSetIP",
            "ports": ports
        }),
    )
}

/// A `managed-by` value naming an MCS controller rather than one of
/// Kubernetes' own EndpointSlice controllers.
const MCS_CONTROLLER: &str = "mcs-controller.example.io";

/// Mark `slice` the way KEP-1645 has the MCS controller mark the imported
/// slices it manages (issue #6123).
fn mark_mcs_managed(slice: &mut K8sObject) {
    slice.metadata.labels.insert(
        "endpointslice.kubernetes.io/managed-by".to_string(),
        MCS_CONTROLLER.to_string(),
    );
}

/// An MCS-managed EndpointSlice of the `default/store` import.
fn mcs_slice(endpoints: Value) -> K8sObject {
    let mut slice = object(
        "EndpointSlice",
        "store-mcs",
        "default",
        "discovery.k8s.io/v1",
        json!({ "ports": [{ "port": 8080 }], "endpoints": endpoints }),
    );
    slice.metadata.labels.insert(
        "multicluster.kubernetes.io/service-name".to_string(),
        "store".to_string(),
    );
    mark_mcs_managed(&mut slice);
    slice
}

fn ready_endpoint(address: &str) -> Value {
    json!({ "addresses": [address], "conditions": { "ready": true } })
}

/// An HTTPRoute in `default` to the `default/store` import on port 8080.
fn store_import_route() -> K8sObject {
    http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    )
}

/// Every host the translated config can dial.
fn dial_hosts(translation: &K8sTranslation) -> Vec<&str> {
    let config = &translation.config;
    let mut hosts: Vec<&str> = config
        .proxies
        .iter()
        .map(|proxy| proxy.backend_host.as_str())
        .collect();
    for upstream in &config.upstreams {
        hosts.extend(upstream.targets.iter().map(|target| target.host.as_str()));
    }
    hosts
}

fn assert_warned(translation: &K8sTranslation, fragment: &str) {
    assert!(
        translation
            .warnings
            .iter()
            .any(|warning| warning.contains(fragment)),
        "expected a warning containing {fragment:?}: {:?}",
        translation.warnings
    );
}

fn tcp_route(name: &str, namespace: &str, backend_refs: Value) -> K8sObject {
    object(
        "TCPRoute",
        name,
        namespace,
        "gateway.networking.k8s.io/v1alpha2",
        json!({
            "rules": [{ "backendRefs": backend_refs }]
        }),
    )
}

fn grpc_route(name: &str, namespace: &str, backend_refs: Value) -> K8sObject {
    object(
        "GRPCRoute",
        name,
        namespace,
        "gateway.networking.k8s.io/v1",
        json!({
            "rules": [{ "backendRefs": backend_refs }]
        }),
    )
}

fn tls_route(name: &str, namespace: &str, backend_refs: Value) -> K8sObject {
    object(
        "TLSRoute",
        name,
        namespace,
        "gateway.networking.k8s.io/v1alpha2",
        json!({
            "rules": [{ "backendRefs": backend_refs }]
        }),
    )
}

fn ferrum_gateway_class() -> K8sObject {
    object(
        "GatewayClass",
        "ferrum",
        "",
        "gateway.networking.k8s.io/v1",
        json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
    )
}

fn ferrum_gateway() -> K8sObject {
    object(
        "Gateway",
        "edge",
        "default",
        "gateway.networking.k8s.io/v1",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": { "namespaces": { "from": "All" } }
            }]
        }),
    )
}

fn find_condition<'a>(conditions: &'a [Value], type_name: &str) -> &'a Value {
    conditions
        .iter()
        .find(|condition| condition["type"] == type_name)
        .unwrap_or_else(|| panic!("missing condition {type_name}"))
}

fn assert_fault_route(translation: &ferrum_edge::config_sources::k8s::K8sTranslation) {
    assert_eq!(
        translation.config.proxies.len(),
        1,
        "expected a single fail-closed route proxy"
    );
    let plugin = translation
        .config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .expect("invalid backend route should carry mesh_route_dispatch");
    let abort = &plugin.config["rules"][0]["fault"]["abort"];
    assert_eq!(abort["status_code"], 500);
    assert_eq!(abort["percentage"], 100.0);
}

#[test]
fn service_import_same_namespace_materializes_clusterset_dns() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    let import = service_import("store", "default", 8080);

    let translation = translate_k8s_objects(&[route, import], options())
        .expect("ServiceImport backendRef should translate");

    assert_eq!(
        translation.config.proxies[0].backend_host,
        "store.default.svc.clusterset.local"
    );
    assert_eq!(translation.config.proxies[0].backend_port, 8080);
}

#[test]
fn service_import_missing_target_fail_closed() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "missing",
            "port": 8080
        }]),
    );

    let translation = translate_k8s_objects(&[route], options())
        .expect("missing ServiceImport should translate fail-closed");
    assert_fault_route(&translation);
}

#[test]
fn service_import_wrong_port_fail_closed() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 9090
        }]),
    );
    let import = service_import("store", "default", 8080);

    let translation = translate_k8s_objects(&[route, import], options())
        .expect("wrong ServiceImport port should translate fail-closed");
    assert_fault_route(&translation);
}

#[test]
fn unknown_backend_kind_still_fail_closed() {
    let route = http_route(
        "api",
        "default",
        json!([{
            "group": "example.com",
            "kind": "Backend",
            "name": "api",
            "port": 8080
        }]),
    );

    let translation = translate_k8s_objects(&[route], options())
        .expect("unknown backend kind should translate fail-closed");
    assert_fault_route(&translation);
}

#[test]
fn service_import_cross_namespace_requires_reference_grant() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "namespace": "backend",
            "port": 8080
        }]),
    );
    let import = service_import("store", "backend", 8080);
    let opts = options().with_source_namespaces(vec!["default".to_string(), "backend".to_string()]);

    let denied = translate_k8s_objects(&[route.clone(), import.clone()], opts.clone())
        .expect("unauthorized ServiceImport should translate fail-closed");
    assert_fault_route(&denied);

    let grant = object(
        "ReferenceGrant",
        "allow-store",
        "backend",
        "gateway.networking.k8s.io/v1",
        json!({
            "from": [{
                "group": "gateway.networking.k8s.io",
                "kind": "HTTPRoute",
                "namespace": "default"
            }],
            "to": [{
                "group": "multicluster.x-k8s.io",
                "kind": "ServiceImport"
            }]
        }),
    );

    let allowed = translate_k8s_objects(&[route, import, grant], opts)
        .expect("ReferenceGrant should authorize ServiceImport backendRef");
    assert_eq!(
        allowed.config.proxies[0].backend_host,
        "store.backend.svc.clusterset.local"
    );
}

#[test]
fn service_import_withdrawal_removes_materialized_backend() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    let import = service_import("store", "default", 8080);

    let with_import = translate_k8s_objects(&[route.clone(), import], options())
        .expect("initial ServiceImport load");
    assert_eq!(
        with_import.config.proxies[0].backend_host,
        "store.default.svc.clusterset.local"
    );

    let after_delete = translate_k8s_objects(&[route], options())
        .expect("ServiceImport deletion should withdraw to fail-closed");
    assert_fault_route(&after_delete);
}

#[test]
fn service_import_update_changes_port_materialization() {
    let route_v1 = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    let import = service_import("store", "default", 8080);
    let first = translate_k8s_objects(&[route_v1, import.clone()], options()).unwrap();
    assert_eq!(first.config.proxies[0].backend_port, 8080);

    let route_v2 = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    // Import gains a second published port; route still selects 8080.
    let import_updated = object(
        "ServiceImport",
        "store",
        "default",
        "multicluster.x-k8s.io/v1alpha1",
        json!({
            "type": "ClusterSetIP",
            "ports": [
                { "port": 8080, "protocol": "TCP" },
                { "port": 8443, "protocol": "TCP" }
            ]
        }),
    );
    let second = translate_k8s_objects(&[route_v2, import_updated], options()).unwrap();
    assert_eq!(
        second.config.proxies[0].backend_host,
        first.config.proxies[0].backend_host
    );
    assert_eq!(second.config.proxies[0].backend_port, 8080);
}

#[test]
fn status_and_translation_agree_on_service_import_resolved_refs() {
    let route = http_route_with_parent(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    let import = service_import("store", "default", 8080);
    let objects = vec![
        ferrum_gateway_class(),
        ferrum_gateway(),
        route.clone(),
        import.clone(),
    ];

    let translation = translate_k8s_objects(&objects, options()).unwrap();
    assert_eq!(
        translation.config.proxies[0].backend_host,
        "store.default.svc.clusterset.local"
    );

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    let route_update = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "store")
        .expect("HTTPRoute status update");
    let conditions = route_update.status["parents"][0]["conditions"]
        .as_array()
        .unwrap();
    assert_eq!(find_condition(conditions, "ResolvedRefs")["status"], "True");

    let missing = vec![ferrum_gateway_class(), ferrum_gateway(), route];
    let unresolved = plan_gateway_api_status_updates(&missing, options(), &[]);
    let route_update = unresolved
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "store")
        .expect("HTTPRoute status update");
    let conditions = route_update.status["parents"][0]["conditions"]
        .as_array()
        .unwrap();
    assert_eq!(
        find_condition(conditions, "ResolvedRefs")["status"],
        "False"
    );
    assert_eq!(
        find_condition(conditions, "ResolvedRefs")["reason"],
        "BackendNotFound"
    );
}

#[test]
fn service_import_endpoint_slice_expansion_when_pod_discovery_enabled() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    let import = service_import("store", "default", 8080);
    let mut slice = object(
        "EndpointSlice",
        "store-mcs",
        "default",
        "discovery.k8s.io/v1",
        json!({
            "ports": [{ "port": 8080 }],
            "endpoints": [{
                "addresses": ["10.0.0.10"],
                "conditions": { "ready": true }
            }]
        }),
    );
    slice.metadata.labels.insert(
        "multicluster.kubernetes.io/service-name".to_string(),
        "store".to_string(),
    );
    mark_mcs_managed(&mut slice);

    let opts = options().with_pod_discovery_enabled(true);

    let translation = translate_k8s_objects(&[route, import, slice], opts)
        .expect("ServiceImport EndpointSlice expansion should translate");
    assert_eq!(translation.config.proxies[0].backend_host, "10.0.0.10");
    assert_eq!(translation.config.proxies[0].backend_port, 8080);
}

#[test]
fn named_service_import_port_expands_onto_the_slice_container_port() {
    // A `ServiceImport` carries no `targetPort`, so the ClusterSet port number
    // is NOT the pod port: MCS-derived EndpointSlices mirror the exporting
    // cluster's slices, whose `ports[].port` is the backing container port and
    // whose `ports[].name` is the ClusterSet port's name. Resolving by number
    // (or falling back to the ClusterSet number) would dial 10.0.0.10:80 for a
    // `80 -> http -> 8080` import.
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 80
        }]),
    );
    let import = service_import_with_ports(
        "store",
        "default",
        "multicluster.x-k8s.io/v1alpha1",
        json!([{ "name": "http", "port": 80, "protocol": "TCP" }]),
    );
    let mut slice = object(
        "EndpointSlice",
        "store-mcs",
        "default",
        "discovery.k8s.io/v1",
        json!({
            "ports": [{ "name": "http", "port": 8080 }],
            "endpoints": [{
                "addresses": ["10.0.0.10"],
                "conditions": { "ready": true }
            }]
        }),
    );
    slice.metadata.labels.insert(
        "multicluster.kubernetes.io/service-name".to_string(),
        "store".to_string(),
    );
    mark_mcs_managed(&mut slice);

    let translation = translate_k8s_objects(
        &[route, import, slice],
        options().with_pod_discovery_enabled(true),
    )
    .expect("named ServiceImport port should resolve through the slice port name");
    assert_eq!(translation.config.proxies[0].backend_host, "10.0.0.10");
    assert_eq!(translation.config.proxies[0].backend_port, 8080);
}

#[test]
fn unmappable_service_import_slice_falls_back_to_clusterset_dns() {
    // No slice port carries the ClusterSet port's name, so there is no honest
    // container-port mapping. Skip the slice and keep the stable ClusterSet DNS
    // target (which the MCS data plane resolves correctly) rather than guessing
    // a pod port that may serve something else entirely.
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 80
        }]),
    );
    let import = service_import_with_ports(
        "store",
        "default",
        "multicluster.x-k8s.io/v1alpha1",
        json!([
            { "name": "http", "port": 80, "protocol": "TCP" },
            { "name": "admin", "port": 9090, "protocol": "TCP" }
        ]),
    );
    let mut slice = object(
        "EndpointSlice",
        "store-mcs",
        "default",
        "discovery.k8s.io/v1",
        json!({
            "ports": [{ "name": "admin", "port": 9091 }],
            "endpoints": [{
                "addresses": ["10.0.0.10"],
                "conditions": { "ready": true }
            }]
        }),
    );
    slice.metadata.labels.insert(
        "multicluster.kubernetes.io/service-name".to_string(),
        "store".to_string(),
    );
    mark_mcs_managed(&mut slice);

    let translation = translate_k8s_objects(
        &[route, import, slice],
        options().with_pod_discovery_enabled(true),
    )
    .expect("an unmappable MCS slice should still translate");
    assert_eq!(
        translation.config.proxies[0].backend_host,
        "store.default.svc.clusterset.local"
    );
    assert_eq!(translation.config.proxies[0].backend_port, 80);
}

#[test]
fn service_import_protocol_admission_is_fail_closed_with_status_parity() {
    for protocol in [json!("UDP"), json!("SCTP"), json!(7)] {
        let route = http_route_with_parent(
            "store",
            "default",
            json!([{
                "group": "multicluster.x-k8s.io",
                "kind": "ServiceImport",
                "name": "store",
                "port": 8080
            }]),
        );
        let import = service_import_with_ports(
            "store",
            "default",
            "multicluster.x-k8s.io/v1alpha1",
            json!([{ "port": 8080, "protocol": protocol }]),
        );
        let objects = vec![ferrum_gateway_class(), ferrum_gateway(), route, import];

        let translation = translate_k8s_objects(&objects, options())
            .expect("unsupported transport should become a fail-closed HTTP route");
        assert_fault_route(&translation);

        let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
        let route_update = updates
            .iter()
            .find(|update| update.kind == "HTTPRoute" && update.name == "store")
            .expect("HTTPRoute status update");
        let conditions = route_update.status["parents"][0]["conditions"]
            .as_array()
            .expect("route conditions");
        let resolved = find_condition(conditions, "ResolvedRefs");
        assert_eq!(resolved["status"], "False");
        assert_eq!(resolved["reason"], "UnsupportedProtocol");
    }
}

#[test]
fn omitted_service_import_port_derives_only_one_tcp_candidate() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store"
        }]),
    );
    let one_tcp = service_import_with_ports(
        "store",
        "default",
        "multicluster.x-k8s.io/v1alpha1",
        json!([
            { "port": 8080 },
            { "port": 5353, "protocol": "UDP" }
        ]),
    );
    let derived = translate_k8s_objects(&[route.clone(), one_tcp], options())
        .expect("one default-TCP port should derive");
    assert_eq!(derived.config.proxies[0].backend_port, 8080);

    let ambiguous = service_import_with_ports(
        "store",
        "default",
        "multicluster.x-k8s.io/v1alpha1",
        json!([
            { "port": 8080, "protocol": "TCP" },
            { "port": 8443, "protocol": "TCP" }
        ]),
    );
    let rejected = translate_k8s_objects(&[route, ambiguous], options())
        .expect("ambiguous custom-backend port should fail closed");
    assert_fault_route(&rejected);

    let core_service = http_route("core", "default", json!([{ "name": "api" }]));
    let historical = translate_k8s_objects(&[core_service], options())
        .expect("core Service defaults are unchanged");
    assert_eq!(historical.config.proxies[0].backend_port, 80);
}

#[test]
fn wrong_api_group_service_import_never_satisfies_backend_ref() {
    let route = http_route_with_parent(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    let impostor = service_import_with_ports(
        "store",
        "default",
        "example.test/v1alpha1",
        json!([{ "port": 8080, "protocol": "TCP" }]),
    );

    let objects = vec![ferrum_gateway_class(), ferrum_gateway(), route, impostor];
    let translation = translate_k8s_objects(&objects, options())
        .expect("wrong-group object should not satisfy the typed ref");
    assert_fault_route(&translation);

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    let route_update = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "store")
        .expect("HTTPRoute status update");
    let conditions = route_update.status["parents"][0]["conditions"]
        .as_array()
        .expect("route conditions");
    let resolved = find_condition(conditions, "ResolvedRefs");
    assert_eq!(resolved["status"], "False");
    assert_eq!(resolved["reason"], "BackendNotFound");
}

#[test]
fn stream_service_import_uses_stable_dns_and_derives_single_port() {
    let route = tcp_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store"
        }]),
    );
    let import = service_import("store", "default", 8080);
    let mut slice = object(
        "EndpointSlice",
        "store-mcs",
        "default",
        "discovery.k8s.io/v1",
        json!({
            "ports": [{ "port": 8080 }],
            "endpoints": [
                { "addresses": ["10.0.0.10"], "conditions": { "ready": true } },
                { "addresses": ["10.0.0.11"], "conditions": { "ready": true } }
            ]
        }),
    );
    slice.metadata.labels.insert(
        "multicluster.kubernetes.io/service-name".to_string(),
        "store".to_string(),
    );

    let translation = translate_k8s_objects(
        &[route, import, slice],
        options().with_pod_discovery_enabled(true),
    )
    .expect("stream ServiceImport should use a stable ClusterSet target");
    assert_eq!(translation.config.proxies.len(), 1);
    assert_eq!(
        translation.config.proxies[0].backend_host,
        "store.default.svc.clusterset.local"
    );
    assert_eq!(translation.config.proxies[0].backend_port, 8080);
}

#[test]
fn supported_route_families_retain_service_import_materialization() {
    // HTTP is covered elsewhere; pin GRPC/TCP/TLS positive admission so the
    // route-kind capability gate cannot accidentally drop Extended support.
    let backend_refs = json!([{
        "group": "multicluster.x-k8s.io",
        "kind": "ServiceImport",
        "name": "store",
        "port": 8080
    }]);
    let import = service_import("store", "default", 8080);

    for route in [
        grpc_route("store", "default", backend_refs.clone()),
        tcp_route("store", "default", backend_refs.clone()),
        tls_route("store", "default", backend_refs),
    ] {
        let kind = route.kind.clone();
        let translation = translate_k8s_objects(&[route, import.clone()], options())
            .unwrap_or_else(|error| panic!("{kind} ServiceImport should translate: {error}"));
        assert_eq!(
            translation.config.proxies[0].backend_host, "store.default.svc.clusterset.local",
            "{kind} should keep ClusterSet DNS"
        );
        assert_eq!(translation.config.proxies[0].backend_port, 8080);
    }
}

#[test]
fn service_import_slice_without_an_mcs_managed_by_label_is_not_expanded() {
    // KEP-1645 has the MCS controller mark every imported slice it manages. A
    // slice without that mark, or one naming Kubernetes' own EndpointSlice
    // controllers, is ignored and the backend keeps ClusterSet DNS (issue
    // #6123).
    for manager in [
        None,
        Some(""),
        Some("endpointslice-controller.k8s.io"),
        Some("endpointslicemirroring-controller.k8s.io"),
    ] {
        let mut slice = mcs_slice(json!([ready_endpoint("10.0.0.10")]));
        match manager {
            Some(manager) => {
                slice.metadata.labels.insert(
                    "endpointslice.kubernetes.io/managed-by".to_string(),
                    manager.to_string(),
                );
            }
            None => {
                slice
                    .metadata
                    .labels
                    .remove("endpointslice.kubernetes.io/managed-by");
            }
        }

        let translation = translate_k8s_objects(
            &[
                store_import_route(),
                service_import("store", "default", 8080),
                slice,
            ],
            options().with_pod_discovery_enabled(true),
        )
        .expect("an unmanaged MCS slice should still translate");

        assert_eq!(
            dial_hosts(&translation),
            vec!["store.default.svc.clusterset.local"],
            "{manager:?}"
        );
        assert_warned(&translation, "is ignored");
    }
}

#[test]
fn service_import_slice_refuses_addresses_that_can_never_be_a_backend() {
    let refused = [
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254",
        "100.100.100.200",
        "64:ff9b::a9fe:a9fe",
        "metadata.google.internal",
    ];
    let mut endpoints = vec![ready_endpoint("10.0.0.10")];
    endpoints.extend(refused.into_iter().map(ready_endpoint));

    let translation = translate_k8s_objects(
        &[
            store_import_route(),
            service_import("store", "default", 8080),
            mcs_slice(Value::Array(endpoints)),
        ],
        options().with_pod_discovery_enabled(true),
    )
    .expect("an MCS slice with special addresses should translate");

    let hosts = dial_hosts(&translation);
    assert_eq!(hosts, vec!["10.0.0.10"]);
    assert_warned(&translation, "6 endpoint address(es) refused");
}

#[test]
fn service_import_slice_refuses_this_clusters_infrastructure_outside_its_namespace() {
    // Remote endpoints cannot be checked against local Pods, but an address
    // this cluster owns can: only a Pod of the import's own namespace is
    // admitted among them.
    let mut own_pod = object("Pod", "store-0", "default", "v1", json!({}));
    own_pod.status = json!({ "phase": "Running", "podIP": "10.244.3.7" });
    let mut other_pod = object("Pod", "ledger-0", "payments", "v1", json!({}));
    other_pod.status = json!({ "phase": "Running", "podIP": "10.244.3.20" });
    let other_service = object(
        "Service",
        "payroll",
        "payments",
        "v1",
        json!({
            "clusterIP": "10.96.0.50",
            "selector": { "app": "payroll" },
            "ports": [{ "name": "http", "port": 8080 }]
        }),
    );
    let mut node = object(
        "Node",
        "worker-1",
        "",
        "v1",
        json!({ "podCIDRs": ["10.244.3.0/24"] }),
    );
    node.status = json!({ "addresses": [{ "type": "InternalIP", "address": "192.168.10.5" }] });
    let slice = mcs_slice(json!([
        ready_endpoint("10.0.0.10"),
        ready_endpoint("10.244.3.7"),
        ready_endpoint("10.244.3.20"),
        ready_endpoint("10.96.0.50"),
        ready_endpoint("192.168.10.5"),
        ready_endpoint("10.244.3.99"),
        {
            "addresses": ["10.0.0.11"],
            "conditions": { "ready": true },
            "targetRef": { "kind": "Pod", "namespace": "payments", "name": "ledger-0" }
        }
    ]));

    let translation = translate_k8s_objects(
        &[
            store_import_route(),
            service_import("store", "default", 8080),
            slice,
            own_pod,
            other_pod,
            other_service,
            node,
        ],
        options()
            .with_source_namespaces(Vec::new())
            .with_pod_discovery_enabled(true),
    )
    .expect("an MCS slice naming local infrastructure should translate");

    let hosts = dial_hosts(&translation);
    for admitted in ["10.0.0.10", "10.244.3.7"] {
        assert!(
            hosts.contains(&admitted),
            "{admitted} missing from {hosts:?}"
        );
    }
    for refused in [
        "10.244.3.20",
        "10.96.0.50",
        "192.168.10.5",
        "10.244.3.99",
        "10.0.0.11",
    ] {
        assert!(!hosts.contains(&refused), "{refused} admitted: {hosts:?}");
    }
    assert_warned(&translation, "5 endpoint address(es) refused");
}
