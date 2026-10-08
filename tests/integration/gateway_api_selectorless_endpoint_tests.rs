//! Gateway API backendRefs to selector-less Services stay inside the Service's
//! namespace (issue #6108).
//!
//! Kubernetes never manages the EndpointSlices of a Service without a
//! `spec.selector`, so whoever can write EndpointSlices in that namespace
//! decides which addresses the Service publishes. Pointing one at another
//! namespace's Pods would reach them without a ReferenceGrant, the same bypass
//! an `ExternalName` alias gives (#6094). A backendRef to a selector-less
//! Service is admitted only when every endpoint is a Pod of the Service's
//! namespace, judged by the Pod IPs pod discovery observes. The slice's own
//! `targetRef` can refuse an endpoint but never vouch for one.

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, plan_gateway_api_status_updates,
};
use serde_json::{Value, json};
use std::collections::HashMap;

const REFUSAL: &str = "backendRef to selector-less Service";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_source_namespaces(Vec::new())
    .with_pod_discovery_enabled(true)
}

fn opted_in_options() -> K8sTranslationOptions {
    options().with_selectorless_external_endpoints_allowed(true)
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

fn gateway_class() -> K8sObject {
    object(
        "GatewayClass",
        "ferrum",
        "",
        "gateway.networking.k8s.io/v1",
        json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
    )
}

fn gateway() -> K8sObject {
    object(
        "Gateway",
        "shared",
        "tenant-a",
        "gateway.networking.k8s.io/v1",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]
        }),
    )
}

fn http_route(backend_ref: Value) -> K8sObject {
    object(
        "HTTPRoute",
        "store",
        "tenant-a",
        "gateway.networking.k8s.io/v1",
        json!({
            "parentRefs": [{ "name": "shared" }],
            "hostnames": ["store.example.com"],
            "rules": [{
                "matches": [{ "path": { "type": "PathPrefix", "value": "/" } }],
                "backendRefs": [backend_ref]
            }]
        }),
    )
}

/// A selector-less ClusterIP Service: its EndpointSlices are hand-written.
fn selectorless_service(namespace: &str) -> K8sObject {
    object(
        "Service",
        "payroll",
        namespace,
        "v1",
        json!({
            "clusterIP": "10.96.0.50",
            "ports": [{ "name": "http", "port": 8080, "targetPort": 8080 }]
        }),
    )
}

fn endpoint_slice(namespace: &str, endpoints: Value) -> K8sObject {
    let mut slice = object(
        "EndpointSlice",
        "payroll-manual",
        namespace,
        "discovery.k8s.io/v1",
        json!({
            "addressType": "IPv4",
            "ports": [{ "name": "http", "port": 8080 }],
            "endpoints": endpoints
        }),
    );
    slice.metadata.labels.insert(
        "kubernetes.io/service-name".to_string(),
        "payroll".to_string(),
    );
    slice
}

fn endpoint(address: &str) -> Value {
    json!({ "addresses": [address], "conditions": { "ready": true } })
}

fn endpoint_with_target(address: &str, pod_namespace: &str, pod_name: &str) -> Value {
    json!({
        "addresses": [address],
        "conditions": { "ready": true },
        "targetRef": { "kind": "Pod", "namespace": pod_namespace, "name": pod_name }
    })
}

fn pod(namespace: &str, name: &str, ip: &str) -> K8sObject {
    let mut pod = object("Pod", name, namespace, "v1", json!({}));
    pod.status = json!({ "phase": "Running", "podIP": ip });
    pod
}

/// A same-namespace HTTPRoute to `tenant-a/payroll` whose one manual slice
/// carries `endpoints`, plus `pods`.
fn same_namespace_fixture(endpoints: Value, pods: Vec<K8sObject>) -> Vec<K8sObject> {
    let mut objects = vec![
        gateway_class(),
        gateway(),
        http_route(json!({ "name": "payroll", "port": 8080 })),
        selectorless_service("tenant-a"),
        endpoint_slice("tenant-a", endpoints),
    ];
    objects.extend(pods);
    objects
}

/// Every host the translated config can dial.
fn dial_hosts(config: &GatewayConfig) -> Vec<&str> {
    let mut hosts = Vec::new();
    for proxy in &config.proxies {
        hosts.push(proxy.backend_host.as_str());
    }
    for upstream in &config.upstreams {
        hosts.extend(upstream.targets.iter().map(|target| target.host.as_str()));
    }
    hosts
}

/// `(status, reason)` of `condition_type` on a route's first parent status.
fn route_condition(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    kind: &str,
    name: &str,
    condition_type: &str,
) -> (String, Option<String>) {
    let updates = plan_gateway_api_status_updates(objects, options, &[]);
    let route = updates
        .iter()
        .find(|update| update.kind == kind && update.name == name)
        .unwrap_or_else(|| panic!("{kind} {name} status"));
    let condition = route.status["parents"][0]["conditions"]
        .as_array()
        .expect("route parent conditions")
        .iter()
        .find(|condition| condition["type"] == condition_type)
        .unwrap_or_else(|| panic!("{condition_type} condition"));
    (
        condition["status"].as_str().unwrap_or_default().to_string(),
        condition["reason"].as_str().map(ToOwned::to_owned),
    )
}

fn resolved_refs(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
) -> (String, Option<String>) {
    route_condition(objects, options, "HTTPRoute", "store", "ResolvedRefs")
}

/// The HTTPRoute translates (the refused backend fails its rule closed), never
/// dials `address`, warns, and reports `ResolvedRefs=False/RefNotPermitted`.
fn assert_refused(objects: &[K8sObject], options: K8sTranslationOptions, address: &str) {
    let translation =
        translate_k8s_objects(objects, options.clone()).expect("translation succeeds");
    assert!(
        !dial_hosts(&translation.config).contains(&address),
        "refused endpoint {address} must never become a dial target"
    );
    assert!(
        translation
            .warnings
            .iter()
            .any(|warning| warning.contains(REFUSAL)),
        "refusal must be warned about: {:?}",
        translation.warnings
    );
    let (status, reason) = resolved_refs(objects, options);
    assert_eq!(status, "False", "endpoint {address}");
    assert_eq!(
        reason.as_deref(),
        Some("RefNotPermitted"),
        "endpoint {address}"
    );
}

fn assert_admitted(objects: &[K8sObject], options: K8sTranslationOptions, address: &str) {
    let translation =
        translate_k8s_objects(objects, options.clone()).expect("translation succeeds");
    assert!(
        dial_hosts(&translation.config).contains(&address),
        "admitted endpoint {address} must be dialed: {:?}",
        dial_hosts(&translation.config)
    );
    assert!(
        translation
            .warnings
            .iter()
            .all(|warning| !warning.contains(REFUSAL)),
        "{:?}",
        translation.warnings
    );
    assert_eq!(resolved_refs(objects, options).0, "True");
}

#[test]
fn endpoint_that_is_a_pod_of_the_service_namespace_is_admitted() {
    // Address-only, exactly as Gateway API conformance writes manual slices
    // for its `HTTPRouteServiceTypes` test.
    let objects = same_namespace_fixture(
        json!([endpoint("10.1.0.10")]),
        vec![pod("tenant-a", "payroll-0", "10.1.0.10")],
    );
    assert_admitted(&objects, options(), "10.1.0.10");
}

#[test]
fn endpoint_whose_target_ref_names_another_namespace_is_refused() {
    let objects = same_namespace_fixture(
        json!([endpoint_with_target("10.2.0.20", "hr", "payroll-db-0")]),
        vec![pod("hr", "payroll-db-0", "10.2.0.20")],
    );
    assert_refused(&objects, options(), "10.2.0.20");
}

#[test]
fn address_only_endpoint_carrying_another_namespaces_pod_ip_is_refused() {
    let objects = same_namespace_fixture(
        json!([endpoint("10.2.0.20")]),
        vec![pod("hr", "payroll-db-0", "10.2.0.20")],
    );
    assert_refused(&objects, options(), "10.2.0.20");
    // The operator opt-in admits unattributed IPs, never another namespace's Pod.
    assert_refused(&objects, opted_in_options(), "10.2.0.20");
}

#[test]
fn target_ref_cannot_vouch_for_another_namespaces_pod_ip() {
    let objects = same_namespace_fixture(
        json!([endpoint_with_target("10.2.0.20", "tenant-a", "payroll-0")]),
        vec![
            pod("tenant-a", "payroll-0", "10.1.0.10"),
            pod("hr", "payroll-db-0", "10.2.0.20"),
        ],
    );
    assert_refused(&objects, options(), "10.2.0.20");
}

#[test]
fn one_foreign_endpoint_refuses_the_whole_backend() {
    let objects = same_namespace_fixture(
        json!([endpoint("10.1.0.10"), endpoint("10.2.0.20")]),
        vec![
            pod("tenant-a", "payroll-0", "10.1.0.10"),
            pod("hr", "payroll-db-0", "10.2.0.20"),
        ],
    );
    assert_refused(&objects, options(), "10.2.0.20");
    assert_refused(&objects, options(), "10.1.0.10");
}

#[test]
fn ip_claimed_by_pods_in_two_namespaces_is_refused() {
    let objects = same_namespace_fixture(
        json!([endpoint("10.1.0.10")]),
        vec![
            pod("tenant-a", "payroll-0", "10.1.0.10"),
            pod("hr", "payroll-db-0", "10.1.0.10"),
        ],
    );
    assert_refused(&objects, options(), "10.1.0.10");
}

#[test]
fn host_network_and_terminal_pods_do_not_attribute_an_ip() {
    // A host-network Pod reports its node's IP; a Succeeded Pod has released
    // its IP for reuse. Neither makes the address a Pod of the namespace.
    let mut host_network = pod("tenant-a", "node-agent", "10.0.0.5");
    host_network.spec = json!({ "hostNetwork": true });
    let mut completed = pod("tenant-a", "job-0", "10.1.0.30");
    completed.status["phase"] = json!("Succeeded");
    for (address, owner) in [("10.0.0.5", host_network), ("10.1.0.30", completed)] {
        let objects = same_namespace_fixture(json!([endpoint(address)]), vec![owner]);
        assert_refused(&objects, options(), address);
    }
}

#[test]
fn unattributed_endpoint_ip_is_refused_unless_the_operator_opts_in() {
    let objects = same_namespace_fixture(json!([endpoint("203.0.113.10")]), Vec::new());
    assert_refused(&objects, options(), "203.0.113.10");
    assert_admitted(&objects, opted_in_options(), "203.0.113.10");
}

#[test]
fn special_and_fqdn_endpoints_are_refused_even_when_opted_in() {
    for address in [
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "payroll.hr.svc.cluster.local",
    ] {
        let objects = same_namespace_fixture(json!([endpoint(address)]), Vec::new());
        assert_refused(&objects, opted_in_options(), address);
    }
}

fn cross_namespace_fixture(endpoints: Value, pods: Vec<K8sObject>) -> Vec<K8sObject> {
    let mut objects = vec![
        gateway_class(),
        gateway(),
        http_route(json!({ "name": "payroll", "namespace": "tenant-b", "port": 8080 })),
        object(
            "ReferenceGrant",
            "allow-tenant-a",
            "tenant-b",
            "gateway.networking.k8s.io/v1beta1",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "tenant-a"
                }],
                "to": [{ "group": "", "kind": "Service" }]
            }),
        ),
        selectorless_service("tenant-b"),
        endpoint_slice("tenant-b", endpoints),
    ];
    objects.extend(pods);
    objects
}

#[test]
fn granted_reference_reaches_only_pods_of_the_granting_namespace() {
    let own_pods = cross_namespace_fixture(
        json!([endpoint("10.3.0.30")]),
        vec![pod("tenant-b", "payroll-0", "10.3.0.30")],
    );
    assert_admitted(&own_pods, options(), "10.3.0.30");

    // The route's own namespace is still "another namespace" for tenant-b's
    // Service: the grant authorizes tenant-b's backends, not a detour home.
    let route_namespace_pods = cross_namespace_fixture(
        json!([endpoint("10.1.0.10")]),
        vec![pod("tenant-a", "store-0", "10.1.0.10")],
    );
    assert_refused(&route_namespace_pods, options(), "10.1.0.10");

    // The opt-in is for same-namespace routes only; a grant never widens it.
    let unattributed = cross_namespace_fixture(json!([endpoint("203.0.113.10")]), Vec::new());
    assert_refused(&unattributed, opted_in_options(), "203.0.113.10");
}

#[test]
fn selectorless_endpoint_refusal_refuses_an_l4_route() {
    let objects = vec![
        gateway_class(),
        object(
            "Gateway",
            "shared",
            "tenant-a",
            "gateway.networking.k8s.io/v1",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "postgres",
                    "port": 5432,
                    "protocol": "TCP",
                    "allowedRoutes": {
                        "namespaces": { "from": "Same" },
                        "kinds": [{ "kind": "TCPRoute" }]
                    }
                }]
            }),
        ),
        object(
            "TCPRoute",
            "db",
            "tenant-a",
            "gateway.networking.k8s.io/v1alpha2",
            json!({
                "parentRefs": [{ "name": "shared", "sectionName": "postgres" }],
                "rules": [{ "backendRefs": [{ "name": "payroll", "port": 8080 }] }]
            }),
        ),
        selectorless_service("tenant-a"),
        endpoint_slice("tenant-a", json!([endpoint("10.2.0.20")])),
        pod("hr", "payroll-db-0", "10.2.0.20"),
    ];

    let error = translate_k8s_objects(&objects, options())
        .expect_err("an L4 route to a cross-namespace selector-less endpoint");
    assert!(
        error.to_string().contains(REFUSAL),
        "unexpected refusal: {error}"
    );
    let (status, reason) = route_condition(&objects, options(), "TCPRoute", "db", "ResolvedRefs");
    assert_eq!(status, "False");
    assert_eq!(reason.as_deref(), Some("RefNotPermitted"));
}

#[test]
fn without_pod_discovery_the_backend_is_admitted_with_a_warning() {
    // No Pod or EndpointSlice inventory: the controller cannot attribute the
    // endpoints, so it keeps routing through Service DNS and says so.
    let objects = same_namespace_fixture(
        json!([endpoint("10.2.0.20")]),
        vec![pod("hr", "payroll-db-0", "10.2.0.20")],
    );
    let options = options().with_pod_discovery_enabled(false);
    let translation =
        translate_k8s_objects(&objects, options.clone()).expect("translation succeeds");
    assert!(
        dial_hosts(&translation.config).contains(&"payroll.tenant-a.svc.cluster.local"),
        "{:?}",
        dial_hosts(&translation.config)
    );
    assert!(
        translation
            .warnings
            .iter()
            .any(|warning| warning.contains("admitted unverified")),
        "{:?}",
        translation.warnings
    );
    assert_eq!(resolved_refs(&objects, options).0, "True");
}

#[test]
fn selector_backed_service_is_not_subject_to_the_guard() {
    let mut objects = same_namespace_fixture(json!([endpoint("10.1.0.10")]), Vec::new());
    let service = objects
        .iter_mut()
        .find(|object| object.kind == "Service")
        .expect("Service");
    service.spec["selector"] = json!({ "app": "payroll" });
    let translation = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    assert!(
        translation
            .warnings
            .iter()
            .all(|warning| !warning.contains(REFUSAL)),
        "{:?}",
        translation.warnings
    );
    assert_eq!(resolved_refs(&objects, options()).0, "True");
}
