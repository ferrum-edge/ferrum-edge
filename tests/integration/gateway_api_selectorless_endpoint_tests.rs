//! Gateway API backendRefs to core Services stay inside the Service's
//! namespace, judged by EndpointSlice attribution (issue #6108).
//!
//! Kubernetes never manages the EndpointSlices of a Service without a
//! `spec.selector`, and anyone who can write EndpointSlices can attach an extra
//! slice to a selector-backed Service by its `kubernetes.io/service-name`
//! label; kube-proxy and CoreDNS honour both. Pointing such a slice at another
//! namespace's Pods would reach them without a ReferenceGrant, the same bypass
//! an `ExternalName` alias gives (#6094). A backendRef to a Service is
//! admitted only when every endpoint is a Pod of the Service's namespace,
//! judged by the Pod IPs pod discovery observes (and, for a grace window,
//! recently observed). The slice's own `targetRef` can refuse an endpoint but
//! never vouch for one, except that it can name a selector-backed Service's
//! same-namespace host-network Pod.

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, PodClaimInventory, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, plan_gateway_api_status_updates,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Duration;

const REFUSAL: &str = "is not permitted by EndpointSlice attribution";
const UNVERIFIED: &str = "is admitted without EndpointSlice attribution";
const OPT_IN_INACTIVE: &str = "FERRUM_K8S_ALLOW_SELECTORLESS_EXTERNAL_ENDPOINTS=true is inactive";
const SERVICE_DNS: &str = "payroll.tenant-a.svc.cluster.local";

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

fn discovery_off_options() -> K8sTranslationOptions {
    options().with_pod_discovery_enabled(false)
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

fn payroll_service(namespace: &str, spec: Value) -> K8sObject {
    object("Service", "payroll", namespace, "v1", spec)
}

/// A selector-less ClusterIP Service: its EndpointSlices are hand-written.
fn selectorless_service(namespace: &str) -> K8sObject {
    payroll_service(
        namespace,
        json!({
            "clusterIP": "10.96.0.50",
            "ports": [{ "name": "http", "port": 8080, "targetPort": 8080 }]
        }),
    )
}

/// A selector-backed Service; `cluster_ip` is `"None"` for a headless one.
fn selector_service(cluster_ip: &str) -> K8sObject {
    payroll_service(
        "tenant-a",
        json!({
            "clusterIP": cluster_ip,
            "selector": { "app": "payroll" },
            "ports": [{ "name": "http", "port": 8080, "targetPort": 8080 }]
        }),
    )
}

fn named_endpoint_slice(namespace: &str, name: &str, endpoints: Value) -> K8sObject {
    let mut slice = object(
        "EndpointSlice",
        name,
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

fn endpoint_slice(namespace: &str, endpoints: Value) -> K8sObject {
    named_endpoint_slice(namespace, "payroll-manual", endpoints)
}

/// The slice the EndpointSlice controller writes for a selector-backed
/// Service.
fn controller_slice(endpoints: Value) -> K8sObject {
    let mut slice = named_endpoint_slice("tenant-a", "payroll-abcde", endpoints);
    slice.metadata.labels.insert(
        "endpointslice.kubernetes.io/managed-by".to_string(),
        "endpointslice-controller.k8s.io".to_string(),
    );
    slice
}

/// An extra slice attached to the Service by label alone; the EndpointSlice
/// controller leaves it untouched and kube-proxy still uses it.
fn extra_slice(endpoints: Value) -> K8sObject {
    let mut slice = named_endpoint_slice("tenant-a", "payroll-extra", endpoints);
    slice.metadata.labels.insert(
        "endpointslice.kubernetes.io/managed-by".to_string(),
        "someone-else".to_string(),
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

/// A host-network Pod: it reports its Node's IP.
fn host_network_pod(namespace: &str, name: &str, node_ip: &str) -> K8sObject {
    let mut pod = pod(namespace, name, node_ip);
    pod.spec = json!({ "hostNetwork": true });
    pod
}

fn node(name: &str, address: &str, pod_cidr: &str) -> K8sObject {
    node_with_spec(name, address, json!({ "podCIDRs": [pod_cidr] }))
}

fn node_with_spec(name: &str, address: &str, spec: Value) -> K8sObject {
    let mut node = object("Node", name, "", "v1", spec);
    node.status = json!({ "addresses": [{ "type": "InternalIP", "address": address }] });
    node
}

/// An observed Node, which the external-endpoint opt-in needs to be active.
fn worker() -> K8sObject {
    node("worker-1", "192.168.10.5", "10.244.3.0/24")
}

/// A same-namespace HTTPRoute to `tenant-a/payroll`, the Service and its
/// slices, plus `extra` objects.
fn route_fixture(service: K8sObject, extra: Vec<K8sObject>) -> Vec<K8sObject> {
    let mut objects = vec![
        gateway_class(),
        gateway(),
        http_route(json!({ "name": "payroll", "port": 8080 })),
        service,
    ];
    objects.extend(extra);
    objects
}

/// A same-namespace HTTPRoute to the selector-less `tenant-a/payroll` whose
/// one manual slice carries `endpoints`, plus `pods`.
fn same_namespace_fixture(endpoints: Value, pods: Vec<K8sObject>) -> Vec<K8sObject> {
    let mut extra = vec![endpoint_slice("tenant-a", endpoints)];
    extra.extend(pods);
    route_fixture(selectorless_service("tenant-a"), extra)
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
/// dials `address` or the Service, warns, and reports
/// `ResolvedRefs=False/RefNotPermitted`. Returns the refusal warnings.
fn assert_refused(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    address: &str,
) -> Vec<String> {
    let translation =
        translate_k8s_objects(objects, options.clone()).expect("translation succeeds");
    let hosts = dial_hosts(&translation.config);
    assert!(
        !hosts.contains(&address),
        "refused endpoint {address:?} must never become a dial target: {hosts:?}"
    );
    assert!(
        hosts.iter().all(|host| !host.starts_with("payroll.")),
        "a refused Service must not be dialed through its DNS name either: {hosts:?}"
    );
    let refusals: Vec<String> = translation
        .warnings
        .iter()
        .filter(|warning| warning.contains(REFUSAL))
        .cloned()
        .collect();
    assert!(
        !refusals.is_empty(),
        "refusal of {address:?} must be warned about: {:?}",
        translation.warnings
    );
    let (status, reason) = resolved_refs(objects, options);
    assert_eq!(status, "False", "endpoint {address:?}");
    assert_eq!(
        reason.as_deref(),
        Some("RefNotPermitted"),
        "endpoint {address:?}"
    );
    refusals
}

fn assert_admitted(objects: &[K8sObject], options: K8sTranslationOptions, dial_host: &str) {
    let translation =
        translate_k8s_objects(objects, options.clone()).expect("translation succeeds");
    assert!(
        dial_hosts(&translation.config).contains(&dial_host),
        "admitted backend {dial_host:?} must be dialed: {:?}",
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
fn not_ready_and_terminating_foreign_endpoints_are_still_refused() {
    // Readiness flips without the slice's author doing anything, and
    // kube-proxy falls back to serving terminating endpoints (reading an
    // omitted `serving` as true). Only an explicit `ready: false` and
    // `serving: false` takes an endpoint out of every consumer's reach.
    for conditions in [
        json!({ "ready": false }),
        json!({ "ready": false, "terminating": true }),
        json!({ "ready": false, "serving": true, "terminating": true }),
        json!({ "serving": false }),
    ] {
        let objects = same_namespace_fixture(
            json!([
                endpoint("10.1.0.10"),
                { "addresses": ["10.2.0.20"], "conditions": conditions }
            ]),
            vec![
                pod("tenant-a", "payroll-0", "10.1.0.10"),
                pod("hr", "payroll-db-0", "10.2.0.20"),
            ],
        );
        assert_refused(&objects, options(), "10.2.0.20");
    }
}

#[test]
fn foreign_endpoint_that_is_neither_ready_nor_serving_does_not_refuse_the_backend() {
    // Nothing dials it: Ferrum and CoreDNS need `ready`, and kube-proxy's
    // terminating fallback needs `serving`.
    for conditions in [
        json!({ "ready": false, "serving": false }),
        json!({ "ready": false, "serving": false, "terminating": true }),
    ] {
        let objects = same_namespace_fixture(
            json!([
                endpoint("10.1.0.10"),
                { "addresses": ["10.2.0.20"], "conditions": conditions }
            ]),
            vec![
                pod("tenant-a", "payroll-0", "10.1.0.10"),
                pod("hr", "payroll-db-0", "10.2.0.20"),
            ],
        );
        assert_admitted(&objects, options(), "10.1.0.10");
    }
}

/// The controller-managed slice of a selector-backed `tenant-a/payroll` naming
/// `payroll-0` (ready) and `payroll-1` with `payroll_1` conditions.
fn payroll_slice(payroll_1: Value) -> K8sObject {
    controller_slice(json!([
        endpoint_with_target("10.1.0.10", "tenant-a", "payroll-0"),
        {
            "addresses": ["10.1.0.11"],
            "conditions": payroll_1,
            "targetRef": { "kind": "Pod", "namespace": "tenant-a", "name": "payroll-1" }
        }
    ]))
}

/// A selector-backed `tenant-a/payroll` with both Pods observed, then with
/// `payroll-1` gone and its terminating endpoint still in the slice.
fn grace_window_fixtures() -> (Vec<K8sObject>, Vec<K8sObject>) {
    let before = route_fixture(
        selector_service("10.96.0.60"),
        vec![
            payroll_slice(json!({ "ready": true })),
            pod("tenant-a", "payroll-0", "10.1.0.10"),
            pod("tenant-a", "payroll-1", "10.1.0.11"),
        ],
    );
    let after = route_fixture(
        selector_service("10.96.0.60"),
        vec![
            payroll_slice(json!({ "ready": false, "serving": true, "terminating": true })),
            pod("tenant-a", "payroll-0", "10.1.0.10"),
        ],
    );
    (before, after)
}

#[test]
fn deleted_pods_lingering_terminating_endpoint_is_attributed_within_the_grace_window() {
    // A Pod leaves the Pod store before the EndpointSlice controller drops
    // its terminating endpoint. Within the grace window the endpoint still
    // belongs to the Pod's namespace; after it, it is unattributed.
    let (before, after) = grace_window_fixtures();

    // A controller that never saw payroll-1 cannot attribute its address.
    assert_refused(&after, options(), "10.1.0.11");

    let remembering = options().with_pod_claim_inventory(PodClaimInventory::new());
    assert_admitted(&before, remembering.clone(), SERVICE_DNS);
    assert_admitted(&after, remembering, SERVICE_DNS);

    let expired = PodClaimInventory::with_grace_window(Duration::ZERO);
    let forgetting = options().with_pod_claim_inventory(expired);
    assert_admitted(&before, forgetting.clone(), SERVICE_DNS);
    assert_refused(&after, forgetting, "10.1.0.11");
}

#[test]
fn grace_window_counts_from_when_the_pod_leaves_the_inventory() {
    // The last reconcile that saw payroll-1 ran longer than the window
    // before the one that finds it gone: the window starts at that later
    // reconcile, and later reconciles do not restart it. The window is long
    // enough that a stalled runner cannot expire it between the first
    // "after" reconcile and the admissions that follow it.
    let grace = Duration::from_secs(5);
    let (before, after) = grace_window_fixtures();
    let inventory = PodClaimInventory::with_grace_window(grace);
    let remembering = options().with_pod_claim_inventory(inventory);

    assert_admitted(&before, remembering.clone(), SERVICE_DNS);
    std::thread::sleep(grace + grace / 2);
    assert_admitted(&after, remembering.clone(), SERVICE_DNS);
    assert_admitted(&after, remembering.clone(), SERVICE_DNS);
    std::thread::sleep(grace + grace / 2);
    assert_refused(&after, remembering, "10.1.0.11");
}

#[test]
fn a_restricted_pod_watch_scope_remembers_claims_only_for_terminating_endpoints() {
    // Outside the scope a Pod could reuse the departed Pod's IP unobserved.
    // The EndpointSlice controller marks a deleted Pod's endpoint terminating
    // before the Pod leaves the API, so with a restricted scope a remembered
    // claim still vouches for that lingering endpoint, but never for a ready
    // endpoint naming the same IP.
    let (before, after) = grace_window_fixtures();
    let ready_after = route_fixture(
        selector_service("10.96.0.60"),
        vec![
            payroll_slice(json!({ "ready": true })),
            pod("tenant-a", "payroll-0", "10.1.0.10"),
        ],
    );
    // kube-proxy and CoreDNS serve an endpoint whose `ready` is true whatever
    // `terminating` says, so a forged `ready: true, terminating: true` is
    // not vouched for either.
    let forged_after = route_fixture(
        selector_service("10.96.0.60"),
        vec![
            payroll_slice(json!({ "ready": true, "terminating": true })),
            pod("tenant-a", "payroll-0", "10.1.0.10"),
        ],
    );
    let restricted = options()
        .with_pod_source_namespaces(vec!["tenant-a".to_string()])
        .with_pod_claim_inventory(PodClaimInventory::new());
    assert_admitted(&before, restricted.clone(), SERVICE_DNS);
    assert_admitted(&after, restricted.clone(), SERVICE_DNS);
    assert_refused(&ready_after, restricted.clone(), "10.1.0.11");
    assert_refused(&forged_after, restricted.clone(), "10.1.0.11");
    // The refusal did not consume the claim: the terminating endpoint is
    // still within its window.
    assert_admitted(&after, restricted, SERVICE_DNS);
}

#[test]
fn a_recent_claim_never_outvotes_an_observed_pod_of_another_namespace() {
    // payroll-1's IP was reused by another namespace's Pod: the Pod observed
    // now decides, so the lingering endpoint is foreign even within the
    // grace window.
    let before = same_namespace_fixture(
        json!([endpoint("10.1.0.11")]),
        vec![pod("tenant-a", "payroll-1", "10.1.0.11")],
    );
    let after = same_namespace_fixture(
        json!([endpoint("10.1.0.11")]),
        vec![pod("hr", "payroll-db-0", "10.1.0.11")],
    );
    let remembering = options().with_pod_claim_inventory(PodClaimInventory::new());
    assert_admitted(&before, remembering.clone(), "10.1.0.11");
    assert_refused(&after, remembering, "10.1.0.11");
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
fn every_ip_a_dual_stack_pod_reports_is_attributed() {
    let mut dual_stack = pod("tenant-a", "payroll-0", "10.1.0.10");
    dual_stack.status["podIPs"] = json!([{ "ip": "10.1.0.10" }, { "ip": "fd00:10::a" }]);
    let mut slice = endpoint_slice("tenant-a", json!([endpoint("fd00:10::a")]));
    slice.spec["addressType"] = json!("IPv6");
    let objects = route_fixture(selectorless_service("tenant-a"), vec![slice, dual_stack]);

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

#[test]
fn host_network_and_terminal_pods_do_not_attribute_an_ip() {
    // A host-network Pod reports its node's IP; a Succeeded Pod has released
    // its IP for reuse. Neither makes the address a Pod of the namespace.
    let host_network = host_network_pod("tenant-a", "node-agent", "10.0.0.5");
    let mut completed = pod("tenant-a", "job-0", "10.1.0.30");
    completed.status["phase"] = json!("Succeeded");
    for (address, owner) in [("10.0.0.5", host_network), ("10.1.0.30", completed)] {
        let objects = same_namespace_fixture(json!([endpoint(address)]), vec![owner]);
        assert_refused(&objects, options(), address);
    }

    // A selector-less Service's slice cannot vouch for a host-network Pod by
    // `targetRef` either; only a selector-backed Service's can.
    let objects = same_namespace_fixture(
        json!([endpoint_with_target("10.0.0.5", "tenant-a", "node-agent")]),
        vec![host_network_pod("tenant-a", "node-agent", "10.0.0.5")],
    );
    assert_refused(&objects, options(), "10.0.0.5");
}

#[test]
fn unattributed_endpoint_ip_is_refused_unless_the_operator_opts_in() {
    let objects = same_namespace_fixture(json!([endpoint("203.0.113.10")]), vec![worker()]);
    assert_refused(&objects, options(), "203.0.113.10");
    assert_admitted(&objects, opted_in_options(), "203.0.113.10");
}

#[test]
fn opt_in_is_inactive_until_the_controller_observes_a_node() {
    // Without the Node watch, a Node address or an unwatched Pod's IP looks
    // external, so the opt-in keeps refusing and the translation says why.
    let unobserved = same_namespace_fixture(json!([endpoint("203.0.113.10")]), Vec::new());
    assert_refused(&unobserved, opted_in_options(), "203.0.113.10");
    let translation =
        translate_k8s_objects(&unobserved, opted_in_options()).expect("translation succeeds");
    let inactive = translation
        .warnings
        .iter()
        .filter(|warning| warning.contains(OPT_IN_INACTIVE))
        .count();
    assert_eq!(inactive, 1, "{:?}", translation.warnings);

    let observed = same_namespace_fixture(json!([endpoint("203.0.113.10")]), vec![worker()]);
    assert_admitted(&observed, opted_in_options(), "203.0.113.10");
    let translation =
        translate_k8s_objects(&observed, opted_in_options()).expect("translation succeeds");
    assert!(
        translation
            .warnings
            .iter()
            .all(|warning| !warning.contains(OPT_IN_INACTIVE)),
        "{:?}",
        translation.warnings
    );
}

#[test]
fn special_malformed_and_fqdn_endpoints_are_refused_even_when_opted_in() {
    for address in [
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "0.1.2.3",
        "224.0.0.1",
        "255.255.255.255",
        "100.100.100.200",
        "168.63.129.16",
        "::1",
        "::",
        "fe80::1",
        "ff02::1",
        "fd00:ec2::254",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        // NAT64 and deprecated IPv4-compatible spellings of special addresses.
        "64:ff9b::7f00:1",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b::6464:64c8",
        "::127.0.0.1",
        "::169.254.169.254",
        // Not IP addresses at all: an FQDN, a zone id, leading zeros, and
        // surrounding whitespace.
        "payroll.hr.svc.cluster.local",
        "fe80::1%eth0",
        "010.0.0.1",
        " 203.0.113.10",
        "203.0.113.10 ",
    ] {
        let objects = same_namespace_fixture(json!([endpoint(address)]), vec![worker()]);
        assert_refused(&objects, opted_in_options(), address);
    }
}

#[test]
fn a_pod_reporting_a_special_address_does_not_make_it_a_backend() {
    // Only someone able to patch `pods/status` can make a non-host-network Pod
    // report these; the deny list is checked before any Pod claim.
    for address in ["127.0.0.1", "169.254.169.254", "::1", "fd00:ec2::254"] {
        let objects = same_namespace_fixture(
            json!([endpoint(address)]),
            vec![pod("tenant-a", "payroll-0", address), worker()],
        );
        assert_refused(&objects, opted_in_options(), address);
    }
}

#[test]
fn nat64_endpoint_follows_its_embedded_ipv4() {
    // 64:ff9b::cb00:710a embeds the external 203.0.113.10 (opt-in admits it);
    // 64:ff9b::a02:14 embeds another namespace's Pod (always refused).
    let external = same_namespace_fixture(json!([endpoint("64:ff9b::cb00:710a")]), vec![worker()]);
    assert_refused(&external, options(), "64:ff9b::cb00:710a");
    assert_admitted(&external, opted_in_options(), "64:ff9b::cb00:710a");

    let foreign = same_namespace_fixture(
        json!([endpoint("64:ff9b::a02:14")]),
        vec![pod("hr", "payroll-db-0", "10.2.0.20"), worker()],
    );
    assert_refused(&foreign, opted_in_options(), "64:ff9b::a02:14");
}

#[test]
fn opt_in_never_admits_cluster_infrastructure() {
    // Another Service's ClusterIP (kube-proxy forwards it to that Service's
    // Pods), a Node address (the kubelet and every NodePort), and an IP in a
    // Node's Pod CIDR (a Pod outside the watch scope) are never "external".
    let ledger = object(
        "Service",
        "ledger",
        "hr",
        "v1",
        json!({
            "clusterIP": "10.96.7.7",
            "selector": { "app": "ledger" },
            "ports": [{ "name": "http", "port": 8080 }]
        }),
    );
    for address in ["10.96.7.7", "10.96.0.50", "192.168.10.5", "10.244.3.17"] {
        let objects =
            same_namespace_fixture(json!([endpoint(address)]), vec![ledger.clone(), worker()]);
        assert_refused(&objects, opted_in_options(), address);
    }

    // A genuinely external IP is still admitted beside that inventory.
    let objects = same_namespace_fixture(json!([endpoint("203.0.113.10")]), vec![ledger, worker()]);
    assert_admitted(&objects, opted_in_options(), "203.0.113.10");
}

#[test]
fn opt_in_never_admits_an_ip_inside_any_nodes_pod_cidr() {
    // Every Node's CIDRs count, in both families and whatever their prefix
    // length, including the single-family `spec.podCIDR` fallback.
    let dual_stack = node_with_spec(
        "worker-2",
        "192.168.10.6",
        json!({ "podCIDRs": ["10.244.4.0/24", "fd00:10:244:4::/64"] }),
    );
    let legacy = node_with_spec(
        "worker-3",
        "192.168.10.7",
        json!({ "podCIDR": "10.245.0.0/16" }),
    );
    let nodes = vec![worker(), dual_stack, legacy];

    for address in ["10.244.4.200", "fd00:10:244:4::17", "10.245.200.1"] {
        let mut slice = endpoint_slice("tenant-a", json!([endpoint(address)]));
        if address.contains(':') {
            slice.spec["addressType"] = json!("IPv6");
        }
        let mut objects = route_fixture(selectorless_service("tenant-a"), vec![slice]);
        objects.extend(nodes.clone());
        assert_refused(&objects, opted_in_options(), address);
    }

    // Just outside every CIDR is external.
    for address in ["10.244.5.1", "10.246.0.1"] {
        let mut objects = same_namespace_fixture(json!([endpoint(address)]), Vec::new());
        objects.extend(nodes.clone());
        assert_admitted(&objects, opted_in_options(), address);
    }
}

#[test]
fn slice_labelled_for_both_a_service_and_a_service_import_is_still_checked() {
    // kube-proxy and CoreDNS map a slice to a Service by
    // `kubernetes.io/service-name` alone; the MCS label must not hide it.
    let mut slice = endpoint_slice("tenant-a", json!([endpoint("10.2.0.20")]));
    slice.metadata.labels.insert(
        "multicluster.kubernetes.io/service-name".to_string(),
        "payroll".to_string(),
    );
    let objects = route_fixture(
        selectorless_service("tenant-a"),
        vec![slice, pod("hr", "payroll-db-0", "10.2.0.20")],
    );
    assert_refused(&objects, options(), "10.2.0.20");
}

#[test]
fn controller_managed_slices_of_a_selector_service_are_admitted() {
    let endpoints = Value::Array(vec![
        endpoint_with_target("10.1.0.10", "tenant-a", "payroll-0"),
        endpoint_with_target("10.1.0.11", "tenant-a", "payroll-1"),
    ]);
    let pods = vec![
        pod("tenant-a", "payroll-0", "10.1.0.10"),
        pod("tenant-a", "payroll-1", "10.1.0.11"),
    ];

    let mut headless = vec![controller_slice(endpoints.clone())];
    headless.extend(pods.clone());
    let headless = route_fixture(selector_service("None"), headless);
    assert_admitted(&headless, options(), "10.1.0.10");

    let mut cluster_ip = vec![controller_slice(endpoints)];
    cluster_ip.extend(pods);
    let cluster_ip = route_fixture(selector_service("10.96.0.60"), cluster_ip);
    assert_admitted(&cluster_ip, options(), SERVICE_DNS);
}

#[test]
fn extra_slice_on_a_selector_service_is_refused() {
    // Ferrum dials a headless Service's endpoints itself, and kube-proxy
    // load-balances a ClusterIP Service onto the extra slice: either way the
    // label-attached slice reaches another namespace's Pod.
    let named = json!([endpoint_with_target("10.1.0.10", "tenant-a", "payroll-0")]);
    for cluster_ip in ["None", "10.96.0.60"] {
        let objects = route_fixture(
            selector_service(cluster_ip),
            vec![
                controller_slice(named.clone()),
                extra_slice(json!([endpoint("10.2.0.20")])),
                pod("tenant-a", "payroll-0", "10.1.0.10"),
                pod("hr", "payroll-db-0", "10.2.0.20"),
            ],
        );
        assert_refused(&objects, options(), "10.2.0.20");
    }
}

#[test]
fn opt_in_does_not_admit_an_unattributed_endpoint_of_a_selector_service() {
    let objects = route_fixture(
        selector_service("10.96.0.60"),
        vec![extra_slice(json!([endpoint("203.0.113.10")])), worker()],
    );
    assert_refused(&objects, opted_in_options(), "203.0.113.10");
}

#[test]
fn selector_service_reaches_its_host_network_daemonset_pods() {
    // A host-network Pod reports its Node's IP, which no other Pod claims;
    // the controller-managed endpoint names it by `targetRef`.
    let daemonset_pod = host_network_pod("tenant-a", "payroll-node-a", "192.168.10.5");
    let worker = worker();
    let named = json!([endpoint_with_target(
        "192.168.10.5",
        "tenant-a",
        "payroll-node-a"
    )]);
    for (cluster_ip, dial_host) in [("None", "192.168.10.5"), ("10.96.0.60", SERVICE_DNS)] {
        let objects = route_fixture(
            selector_service(cluster_ip),
            vec![
                controller_slice(named.clone()),
                daemonset_pod.clone(),
                worker.clone(),
            ],
        );
        assert_admitted(&objects, options(), dial_host);
    }

    // Without the `targetRef`, or naming a Pod that reports another address,
    // the Node address is refused.
    let unnamed = route_fixture(
        selector_service("None"),
        vec![
            controller_slice(json!([endpoint("192.168.10.5")])),
            daemonset_pod.clone(),
            worker.clone(),
        ],
    );
    assert_refused(&unnamed, options(), "192.168.10.5");
    let mismatched = route_fixture(
        selector_service("None"),
        vec![
            controller_slice(named),
            host_network_pod("tenant-a", "payroll-node-a", "192.168.10.6"),
            worker,
        ],
    );
    assert_refused(&mismatched, options(), "192.168.10.5");
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
    let unattributed = cross_namespace_fixture(json!([endpoint("203.0.113.10")]), vec![worker()]);
    assert_refused(&unattributed, opted_in_options(), "203.0.113.10");
}

#[test]
fn endpoint_slice_refusal_refuses_a_grpc_route_backend() {
    let mut objects = same_namespace_fixture(
        json!([endpoint("10.2.0.20")]),
        vec![pod("hr", "payroll-db-0", "10.2.0.20")],
    );
    objects.retain(|object| object.kind != "HTTPRoute");
    objects.push(object(
        "GRPCRoute",
        "rpc",
        "tenant-a",
        "gateway.networking.k8s.io/v1",
        json!({
            "parentRefs": [{ "name": "shared" }],
            "hostnames": ["rpc.example.com"],
            "rules": [{ "backendRefs": [{ "name": "payroll", "port": 8080 }] }]
        }),
    ));

    let translation = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    assert!(!dial_hosts(&translation.config).contains(&"10.2.0.20"));
    assert!(
        translation
            .warnings
            .iter()
            .any(|warning| warning.contains(REFUSAL)),
        "{:?}",
        translation.warnings
    );
    let (status, reason) = route_condition(&objects, options(), "GRPCRoute", "rpc", "ResolvedRefs");
    assert_eq!(status, "False");
    assert_eq!(reason.as_deref(), Some("RefNotPermitted"));
}

fn l4_fixture(listener: Value, route: K8sObject) -> Vec<K8sObject> {
    vec![
        gateway_class(),
        object(
            "Gateway",
            "shared",
            "tenant-a",
            "gateway.networking.k8s.io/v1",
            json!({ "gatewayClassName": "ferrum", "listeners": [listener] }),
        ),
        route,
        selectorless_service("tenant-a"),
        endpoint_slice("tenant-a", json!([endpoint("10.2.0.20")])),
        pod("hr", "payroll-db-0", "10.2.0.20"),
    ]
}

#[test]
fn endpoint_slice_refusal_refuses_l4_routes() {
    let tcp = l4_fixture(
        json!({
            "name": "postgres",
            "port": 5432,
            "protocol": "TCP",
            "allowedRoutes": {
                "namespaces": { "from": "Same" },
                "kinds": [{ "kind": "TCPRoute" }]
            }
        }),
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
    );
    let udp = l4_fixture(
        json!({
            "name": "dns",
            "port": 5353,
            "protocol": "UDP",
            "allowedRoutes": {
                "namespaces": { "from": "Same" },
                "kinds": [{ "kind": "UDPRoute" }]
            }
        }),
        object(
            "UDPRoute",
            "db",
            "tenant-a",
            "gateway.networking.k8s.io/v1alpha2",
            json!({
                "parentRefs": [{ "name": "shared", "sectionName": "dns" }],
                "rules": [{ "backendRefs": [{ "name": "payroll", "port": 8080 }] }]
            }),
        ),
    );

    for (kind, objects) in [("TCPRoute", tcp), ("UDPRoute", udp)] {
        let error = translate_k8s_objects(&objects, options())
            .expect_err("an L4 route to a cross-namespace endpoint is rejected");
        assert!(
            error.to_string().contains(REFUSAL),
            "{kind}: unexpected refusal: {error}"
        );
        let (status, reason) = route_condition(&objects, options(), kind, "db", "ResolvedRefs");
        assert_eq!(status, "False", "{kind}");
        assert_eq!(reason.as_deref(), Some("RefNotPermitted"), "{kind}");
    }
}

#[test]
fn without_pod_discovery_a_selectorless_service_is_refused_as_unverifiable() {
    // No Pod or EndpointSlice inventory: nothing manages the slices and
    // nothing here can tell where they point, so the backend fails closed.
    // The opt-in promises that other namespaces' Pods stay refused, which an
    // unchecked slice cannot keep, so it does not admit it either.
    let objects = same_namespace_fixture(
        json!([endpoint("10.2.0.20")]),
        vec![pod("hr", "payroll-db-0", "10.2.0.20")],
    );
    for options in [
        discovery_off_options(),
        discovery_off_options().with_selectorless_external_endpoints_allowed(true),
    ] {
        let refusals = assert_refused(&objects, options, SERVICE_DNS);
        assert!(
            refusals
                .iter()
                .any(|warning| warning.contains("cannot be checked")),
            "{refusals:?}"
        );
    }
}

#[test]
fn outside_the_pod_watch_scope_a_selectorless_service_is_refused_as_unverifiable() {
    let objects = same_namespace_fixture(
        json!([endpoint("10.1.0.10")]),
        vec![pod("tenant-a", "payroll-0", "10.1.0.10")],
    );
    let options = options().with_pod_source_namespaces(vec!["tenant-b".to_string()]);
    let refusals = assert_refused(&objects, options, "10.1.0.10");
    assert!(
        refusals
            .iter()
            .any(|warning| warning.contains("cannot be checked")),
        "{refusals:?}"
    );
}

#[test]
fn without_pod_discovery_a_selector_service_is_admitted_with_a_warning() {
    // Kubernetes manages a selector-backed Service's slices, so it keeps
    // routing through Service DNS; an extra slice cannot be checked, and the
    // translation says so once per Service.
    let mut objects = route_fixture(
        selector_service("10.96.0.60"),
        vec![extra_slice(json!([endpoint("10.2.0.20")]))],
    );
    objects.push(object(
        "HTTPRoute",
        "store-v2",
        "tenant-a",
        "gateway.networking.k8s.io/v1",
        json!({
            "parentRefs": [{ "name": "shared" }],
            "hostnames": ["store-v2.example.com"],
            "rules": [{ "backendRefs": [{ "name": "payroll", "port": 8080 }] }]
        }),
    ));
    let translation =
        translate_k8s_objects(&objects, discovery_off_options()).expect("translation succeeds");
    assert!(
        dial_hosts(&translation.config).contains(&SERVICE_DNS),
        "{:?}",
        dial_hosts(&translation.config)
    );
    let unverified = translation
        .warnings
        .iter()
        .filter(|warning| warning.contains(UNVERIFIED))
        .count();
    assert_eq!(unverified, 1, "{:?}", translation.warnings);
    assert_eq!(resolved_refs(&objects, discovery_off_options()).0, "True");
}
