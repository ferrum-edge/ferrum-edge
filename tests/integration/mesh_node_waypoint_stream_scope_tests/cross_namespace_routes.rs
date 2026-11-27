//! Cross-namespace VirtualService `http[]` destinations (issue #7499).
//!
//! A carried route in namespace `default` naming Service `other/ratings` is
//! served only when every gate holds: the translator admitted it
//! (ReferenceGrant, Service, EndpointSlice; see
//! `tests/unit/config/istio_virtual_service_cross_namespace_tests.rs`), the
//! control plane carried an `authorized_cross_namespace_targets` entry for the
//! route (inside its namespace scope, the bearer `ns` claim, and the
//! subscriber's Service visibility), and the data plane is a Sidecar. The data
//! plane dials it through a route-namespace clone of the destination Service's
//! upstream (`__mesh-out-vs-xns-upstream-*`), so
//! `GatewayConfig::validate_upstream_references` stays namespace-local. These
//! tests drive the production halves: K8s translation, CP filtering and slice
//! projection, both wires, and data-plane slice preparation.

use std::collections::HashSet;

use ferrum_edge::_test_support::{
    filter_config_to_mesh_request_for_test, mesh_mtls_dispatch_authority_for_test,
    try_acquire_destination_active_request_for_test,
    validate_mesh_route_dispatch_upstream_references_for_test,
};
use ferrum_edge::backend_active_request_limit::BackendActiveRequestLimiter;
use ferrum_edge::config::types::{
    AdmissionUpstreamRef, GatewayConfig, LoadBalancerAlgorithm, Proxy, Upstream,
};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::grpc::cp_server::CpScope;
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshVirtualServiceHttpRoutes, MeshWaypointServiceRef,
};
use ferrum_edge::modes::mesh::slice::{MeshHttpRouteCrossNamespaceTarget, MeshSlice};
use ferrum_edge::modes::mesh::{
    MeshRuntimeConfig, MeshTopology, prepare_gateway_config_from_mesh_slice,
};
use ferrum_edge::xds::carrier::{MeshSliceCarrier, build_slice_carriers};
use serde_json::{Value, json};

use super::super::mesh_test_support::{
    DEFAULT_NAMESPACE, runtime_for_topology, service_for, workload_for,
};

const OTHER: &str = "other";
const RATINGS_OTHER: &str = "ratings.other.svc.cluster.local";
const RATINGS_OTHER_UPSTREAM: &str = "__mesh-out-upstream-other-ratings-8080";
const CLONE_PREFIX: &str = "__mesh-out-vs-xns-upstream-";

fn k8s(api_version: &str, kind: &str, name: &str, namespace: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: None,
            labels: Default::default(),
            annotations: Default::default(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn k8s_service(name: &str, namespace: &str) -> K8sObject {
    k8s(
        "v1",
        "Service",
        name,
        namespace,
        json!({
            "selector": {"app": name},
            "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]
        }),
    )
}

fn grant() -> K8sObject {
    k8s(
        "gateway.networking.k8s.io/v1beta1",
        "ReferenceGrant",
        "allow-default-virtual-services",
        OTHER,
        json!({
            "from": [{"group": "networking.istio.io", "kind": "VirtualService", "namespace": DEFAULT_NAMESPACE}],
            "to": [{"group": "", "kind": "Service", "name": "ratings"}]
        }),
    )
}

/// The default namespace's Sidecar egress scope imports `other/*`.
fn importing_sidecar() -> K8sObject {
    k8s(
        "networking.istio.io/v1",
        "Sidecar",
        "default",
        DEFAULT_NAMESPACE,
        json!({"egress": [{"hosts": ["./*", "other/*"]}]}),
    )
}

fn virtual_service(name: &str, spec: Value) -> K8sObject {
    k8s(
        "networking.istio.io/v1",
        "VirtualService",
        name,
        DEFAULT_NAMESPACE,
        spec,
    )
}

fn destination_rule(name: &str, namespace: &str, host: &str, traffic_policy: Value) -> K8sObject {
    k8s(
        "networking.istio.io/v1",
        "DestinationRule",
        name,
        namespace,
        json!({"host": host, "trafficPolicy": traffic_policy}),
    )
}

fn direct_spec(host: &str) -> Value {
    json!({
        "hosts": ["reviews.default.svc.cluster.local"],
        "http": [{"route": [{"destination": {"host": host, "port": {"number": 8080}}}]}]
    })
}

fn branch_spec() -> Value {
    json!({
        "hosts": ["reviews.default.svc.cluster.local"],
        "http": [
            {
                "match": [{"uri": {"prefix": "/"}, "headers": {"x-version": {"exact": "v2"}}}],
                "route": [{"destination": {"host": RATINGS_OTHER, "port": {"number": 8080}}}]
            },
            {"route": [{"destination": {"host": "reviews.default.svc.cluster.local", "port": {"number": 8080}}}]}
        ]
    })
}

fn ninety_ten_spec() -> Value {
    json!({
        "hosts": ["reviews.default.svc.cluster.local"],
        "http": [{"route": [
            {"destination": {"host": "reviews.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 90},
            {"destination": {"host": RATINGS_OTHER, "port": {"number": 8080}}, "weight": 10}
        ]}]
    })
}

/// Translate `objects` (with the `other/ratings` Service, its grant and the
/// importing Sidecar), then add the mesh inventory both namespaces hold.
fn translated(objects: Vec<K8sObject>) -> GatewayConfig {
    let mut all = vec![
        k8s_service("reviews", DEFAULT_NAMESPACE),
        k8s_service("ratings", OTHER),
        grant(),
        importing_sidecar(),
    ];
    all.extend(objects);
    let translated = translate_k8s_objects(
        &all,
        K8sTranslationOptions::new(
            DEFAULT_NAMESPACE.to_string(),
            TrustDomain::new("cluster.local").expect("trust domain"),
        )
        .with_source_namespaces(Vec::new()),
    )
    .expect("resources translate");
    let mut config = translated.config;
    let reviews = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.0.0.11"],
    );
    let ratings = workload_for("ratings", OTHER, [("app", "ratings")], ["10.0.1.12"]);
    let mesh = config.mesh.get_or_insert_with(Box::default);
    mesh.services = vec![
        service_for("reviews", DEFAULT_NAMESPACE, &[&reviews]),
        service_for("ratings", OTHER, &[&ratings]),
    ];
    mesh.workloads = vec![reviews, ratings];
    config.normalize_fields();
    config.normalize_mesh_fields();
    config
}

fn sidecar_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        sidecar_enforced: true,
        ..runtime_for_topology(MeshTopology::Sidecar)
    }
}

fn node_waypoint_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        sidecar_enforced: true,
        ..runtime_for_topology(MeshTopology::NodeWaypoint)
    }
}

fn slice_for(config: &GatewayConfig, runtime: &MeshRuntimeConfig) -> MeshSlice {
    MeshSlice::from_gateway_config(config, runtime.mesh_slice_request())
}

fn carried_routes(prepared: &GatewayConfig) -> Vec<&Proxy> {
    prepared
        .proxies
        .iter()
        .filter(|proxy| proxy.id.starts_with("istio-vs-") && !proxy.id.starts_with("istio-vs-l4_"))
        .collect()
}

fn upstream<'a>(prepared: &'a GatewayConfig, id: &str) -> &'a Upstream {
    prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == id)
        .unwrap_or_else(|| panic!("upstream {id} is materialized"))
}

fn assert_references_resolve(prepared: &GatewayConfig) {
    prepared
        .validate_upstream_references()
        .expect("every proxy upstream reference resolves in its own namespace");
    validate_mesh_route_dispatch_upstream_references_for_test(prepared)
        .expect("every dispatch upstream reference resolves in its own namespace");
}

fn route_ids(slice: &MeshSlice) -> Vec<String> {
    slice
        .http_routes
        .proxies
        .iter()
        .filter_map(|proxy| proxy.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

/// The clone a route-namespace reference to `other/ratings:8080` dials.
fn assert_ratings_clone(prepared: &GatewayConfig, clone_id: &str) {
    assert!(clone_id.starts_with(CLONE_PREFIX), "{clone_id}");
    let clone = upstream(prepared, clone_id);
    assert_eq!(
        clone.namespace, DEFAULT_NAMESPACE,
        "the clone lives in the route namespace"
    );
    assert_eq!(
        clone.admission_upstream_id,
        Some(AdmissionUpstreamRef {
            namespace: OTHER.to_string(),
            id: RATINGS_OTHER_UPSTREAM.to_string(),
        }),
        "the clone is admitted as the destination Service upstream"
    );
    let hosts: Vec<&str> = clone
        .targets
        .iter()
        .map(|target| target.host.as_str())
        .collect();
    assert_eq!(
        hosts,
        vec!["10.0.1.12"],
        "the clone dials the destination workloads"
    );
    for target in &clone.targets {
        assert_eq!(
            target.tags.get("mesh.mtls").map(String::as_str),
            Some("true"),
            "over the Sidecar SVID-mTLS transport"
        );
        assert_eq!(
            target.tags.get("mesh.spiffe_id").map(String::as_str),
            Some("spiffe://cluster.local/ns/other/sa/ratings"),
            "pinned to the destination workload identity"
        );
        assert_eq!(
            mesh_mtls_dispatch_authority_for_test(
                target,
                false,
                Some("reviews.default.svc.cluster.local")
            ),
            "ratings.other.svc:8080",
            "the destination Sidecar is sent its own Service authority"
        );
    }
}

#[test]
fn the_control_plane_carries_an_authorized_target_only_to_a_sidecar_that_sees_it() {
    let config = translated(vec![virtual_service("direct", direct_spec(RATINGS_OTHER))]);
    let binding = config
        .mesh
        .as_ref()
        .and_then(|mesh| mesh.virtual_service_http_routes.first())
        .expect("mesh binding");
    assert_eq!(
        binding.authorized_cross_namespace_targets,
        vec![MeshWaypointServiceRef {
            namespace: OTHER.to_string(),
            name: "ratings".to_string(),
        }]
    );

    let slice = slice_for(&config, &sidecar_runtime());
    let routes = route_ids(&slice);
    assert_eq!(routes.len(), 1, "the Sidecar slice carries the route");
    assert_eq!(
        slice.http_routes.authorized_cross_namespace_targets,
        vec![MeshHttpRouteCrossNamespaceTarget {
            proxy_id: routes[0].clone(),
            namespace: OTHER.to_string(),
            name: "ratings".to_string(),
        }]
    );
    assert!(
        slice
            .workloads
            .iter()
            .any(|workload| workload.namespace == OTHER && workload.service_name == "ratings"),
        "the authorized destination's own workloads ride the Sidecar slice"
    );

    // Both wires keep the authorization.
    let native: MeshSlice =
        serde_json::from_value(serde_json::to_value(&slice).expect("serialize"))
            .expect("native slice JSON decodes");
    assert!(native.content_eq(&slice));
    let carrier = build_slice_carriers(&slice)
        .into_iter()
        .find(|carrier| matches!(carrier, MeshSliceCarrier::HttpRoutes(_)))
        .expect("HTTP route carrier");
    let bytes = carrier.encode_value().expect("encode");
    assert_eq!(
        MeshSliceCarrier::decode(carrier.type_url(), &bytes)
            .expect("decode")
            .expect("recognized carrier"),
        MeshSliceCarrier::HttpRoutes(slice.http_routes.clone())
    );
    let mut withdrawn = slice.clone();
    withdrawn
        .http_routes
        .authorized_cross_namespace_targets
        .clear();
    assert!(
        !withdrawn.content_eq(&slice),
        "withdrawing an authorization re-applies the slice"
    );

    // A NodeWaypoint does not route cross-namespace destinations: the route is
    // withheld rather than carried.
    let node_waypoint = slice_for(&config, &node_waypoint_runtime());
    assert!(node_waypoint.http_routes.proxies.is_empty());
    assert!(
        node_waypoint
            .http_routes
            .authorized_cross_namespace_targets
            .is_empty()
    );

    // Without the egress import the subscriber does not see `other/ratings`.
    let mut unimported = config.clone();
    if let Some(mesh) = unimported.mesh.as_mut() {
        mesh.sidecars.clear();
    }
    let hidden = slice_for(&unimported, &sidecar_runtime());
    assert!(hidden.http_routes.proxies.is_empty());
    assert!(
        !hidden
            .workloads
            .iter()
            .any(|workload| workload.namespace == OTHER),
        "no workload of another namespace leaks into the slice"
    );

    // A binding that does not authorize the Service carries nothing.
    let mut unauthorized = config.clone();
    if let Some(mesh) = unauthorized.mesh.as_mut() {
        for binding in &mut mesh.virtual_service_http_routes {
            binding.authorized_cross_namespace_targets.clear();
        }
    }
    let withheld = slice_for(&unauthorized, &sidecar_runtime());
    assert!(withheld.http_routes.proxies.is_empty());
    assert!(
        !withheld
            .workloads
            .iter()
            .any(|workload| workload.namespace == OTHER)
    );
}

#[test]
fn control_plane_scope_and_bearer_claims_are_ceilings_on_authorized_targets() {
    let config = translated(vec![virtual_service("direct", direct_spec(RATINGS_OTHER))]);
    let runtime = sidecar_runtime();
    let request = runtime.mesh_slice_request();
    let carried = |scope: CpScope, bearer: Option<HashSet<String>>| -> MeshSlice {
        let filtered =
            filter_config_to_mesh_request_for_test(&config, &request, &scope, bearer.as_ref());
        MeshSlice::from_gateway_config(&filtered, request.clone())
    };
    let both: HashSet<String> = [DEFAULT_NAMESPACE.to_string(), OTHER.to_string()].into();

    let served = carried(CpScope::Set(both.clone()), None);
    assert_eq!(
        served.http_routes.authorized_cross_namespace_targets.len(),
        1
    );
    assert_eq!(
        carried(CpScope::All, Some(both.clone()))
            .http_routes
            .authorized_cross_namespace_targets
            .len(),
        1
    );

    // A CP scope that does not serve `other`, a single-namespace CP, and a
    // bearer claim without `other` all withhold the route.
    for (case, slice) in [
        (
            "set without other",
            carried(CpScope::Set([DEFAULT_NAMESPACE.to_string()].into()), None),
        ),
        (
            "single namespace",
            carried(CpScope::Single(DEFAULT_NAMESPACE.to_string()), None),
        ),
        (
            "bearer without other",
            carried(CpScope::All, Some([DEFAULT_NAMESPACE.to_string()].into())),
        ),
    ] {
        assert!(
            slice
                .http_routes
                .authorized_cross_namespace_targets
                .is_empty(),
            "{case}"
        );
        assert!(slice.http_routes.proxies.is_empty(), "{case}");
    }
}

#[test]
fn sidecar_routes_an_authorized_cross_namespace_direct_destination() {
    let config = translated(vec![virtual_service("direct", direct_spec(RATINGS_OTHER))]);
    let runtime = sidecar_runtime();
    let prepared = prepare_gateway_config_from_mesh_slice(&slice_for(&config, &runtime), &runtime)
        .expect("slice materializes");
    assert_references_resolve(&prepared);
    let routes = carried_routes(&prepared);
    assert_eq!(routes.len(), 1, "the VirtualService route is served");
    let clone_id = routes[0].upstream_id.clone().expect("bound upstream");
    assert_ratings_clone(&prepared, &clone_id);
    // The destination Service's own upstream is untouched.
    let source = upstream(&prepared, RATINGS_OTHER_UPSTREAM);
    assert_eq!(source.namespace, OTHER);
    assert!(
        source
            .targets
            .iter()
            .all(|target| !target.tags.contains_key("mesh.mtls_authority_host")),
        "the shared Service upstream is never stamped"
    );
}

#[test]
fn sidecar_routes_an_authorized_cross_namespace_dispatch_branch() {
    let config = translated(vec![virtual_service("branch", branch_spec())]);
    let runtime = sidecar_runtime();
    let prepared = prepare_gateway_config_from_mesh_slice(&slice_for(&config, &runtime), &runtime)
        .expect("slice materializes");
    assert_references_resolve(&prepared);
    let routes = carried_routes(&prepared);
    assert_eq!(routes.len(), 1, "the merged route is served");
    let dispatch = prepared
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.proxy_id.as_deref() == Some(routes[0].id.as_str())
        })
        .expect("the branch rides a dispatch rule");
    let rule_destinations: Vec<&str> = dispatch.config["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .filter_map(|rule| rule["destination"]["upstream_id"].as_str())
        .collect();
    let clone_id = rule_destinations
        .iter()
        .find(|id| id.starts_with(CLONE_PREFIX))
        .expect("the cross-namespace branch dials the route-namespace clone");
    assert_ratings_clone(&prepared, clone_id);
}

#[test]
fn sidecar_dispatches_a_destination_rule_governed_ninety_ten_split_with_the_destination_rule() {
    let config = translated(vec![
        virtual_service("split", ninety_ten_spec()),
        destination_rule(
            "ratings-dr",
            OTHER,
            RATINGS_OTHER,
            json!({"loadBalancer": {"simple": "RANDOM"}}),
        ),
    ]);
    let runtime = sidecar_runtime();
    let slice = slice_for(&config, &runtime);
    assert!(
        slice
            .destination_rules
            .iter()
            .any(|rule| rule.namespace == OTHER && rule.name == "ratings-dr"),
        "the destination namespace's exported rule is visible to the subscriber"
    );
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    assert_references_resolve(&prepared);
    let routes = carried_routes(&prepared);
    assert_eq!(routes.len(), 1, "the split route is served");
    let dispatch = prepared
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.proxy_id.as_deref() == Some(routes[0].id.as_str())
        })
        .expect("the split is dispatched leg by leg");
    let legs: Vec<(String, u64)> = dispatch.config["weighted_splits"][0]["legs"]
        .as_array()
        .expect("legs")
        .iter()
        .map(|leg| {
            (
                leg["upstream_id"].as_str().expect("leg id").to_string(),
                leg["weight"].as_u64().expect("leg weight"),
            )
        })
        .collect();
    assert_eq!(legs.len(), 2, "{legs:?}");
    assert_eq!(legs[0].1, 90);
    assert_eq!(legs[1].1, 10);
    assert!(legs[0].0.contains("reviews"), "{legs:?}");
    assert_ratings_clone(&prepared, &legs[1].0);
    assert_eq!(
        upstream(&prepared, &legs[1].0).algorithm,
        LoadBalancerAlgorithm::Random,
        "the destination namespace's DestinationRule governs the cross-namespace leg"
    );
    assert_eq!(
        upstream(&prepared, RATINGS_OTHER_UPSTREAM).algorithm,
        LoadBalancerAlgorithm::Random,
        "the clone copies the post-DestinationRule Service upstream"
    );
}

#[test]
fn a_cross_namespace_clone_shares_the_destination_active_request_lane() {
    let config = translated(vec![
        virtual_service("direct", direct_spec(RATINGS_OTHER)),
        destination_rule(
            "ratings-cap",
            OTHER,
            RATINGS_OTHER,
            json!({"connectionPool": {"http": {"http2MaxRequests": 1}}}),
        ),
    ]);
    let runtime = sidecar_runtime();
    let mut prepared =
        prepare_gateway_config_from_mesh_slice(&slice_for(&config, &runtime), &runtime)
            .expect("slice materializes");
    // Publication normalizes the prepared generation (`update_config`).
    prepared.normalize_fields();
    let carried = carried_routes(&prepared)[0].clone();
    let plain = prepared
        .proxies
        .iter()
        .find(|proxy| proxy.upstream_id.as_deref() == Some(RATINGS_OTHER_UPSTREAM))
        .expect("the other/ratings Service route")
        .clone();
    assert_eq!(plain.namespace, OTHER);

    let limiter = BackendActiveRequestLimiter::new();
    let held = try_acquire_destination_active_request_for_test(&limiter, &plain, 8080)
        .expect("the first request is admitted")
        .expect("the DestinationRule cap applies to the Service route");
    try_acquire_destination_active_request_for_test(&limiter, &carried, 8080)
        .expect_err("the cross-namespace route shares the destination's held lane");
    drop(held);
    let permit = try_acquire_destination_active_request_for_test(&limiter, &carried, 8080)
        .expect("the lane is free again")
        .expect("the DestinationRule cap applies to the cross-namespace route");
    try_acquire_destination_active_request_for_test(&limiter, &plain, 8080)
        .expect_err("a cross-namespace request holds the Service route's lane too");
    drop(permit);
}

/// The data-plane half of the acceptance criterion: a cross-namespace
/// destination whose route arrives without an authorization entry (a wire
/// the control plane did not verify) is refused, and the rest of the slice
/// keeps serving.
#[test]
fn unverified_cross_namespace_targets_on_the_wire_are_refused_without_rejecting_the_slice() {
    let runtime = sidecar_runtime();
    for (name, spec) in [
        ("direct", direct_spec(RATINGS_OTHER)),
        ("branch", branch_spec()),
        ("split", ninety_ten_spec()),
    ] {
        let config = translated(vec![virtual_service(name, spec)]);
        let mut slice = slice_for(&config, &runtime);
        assert!(!slice.http_routes.proxies.is_empty(), "{name}: carried");
        slice.http_routes.authorized_cross_namespace_targets.clear();
        let prepared = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
            .unwrap_or_else(|error| panic!("{name}: the slice still materializes: {error}"));
        assert_references_resolve(&prepared);
        assert!(
            carried_routes(&prepared).is_empty(),
            "{name}: route refused"
        );
        assert!(
            !prepared
                .upstreams
                .iter()
                .any(|upstream| upstream.id.starts_with(CLONE_PREFIX)),
            "{name}: no clone survives a refused route"
        );
        assert!(
            prepared
                .proxies
                .iter()
                .any(|proxy| proxy.id == "__mesh-outbound-default-reviews-8080"),
            "{name}: the host keeps its Service route"
        );
    }

    // An entry naming another Service authorizes nothing here.
    let config = translated(vec![virtual_service("direct", direct_spec(RATINGS_OTHER))]);
    let mut slice = slice_for(&config, &runtime);
    for target in &mut slice.http_routes.authorized_cross_namespace_targets {
        target.name = "details".to_string();
    }
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("the slice still materializes");
    assert!(
        carried_routes(&prepared).is_empty(),
        "an authorization names one Service"
    );
}

#[test]
fn a_node_waypoint_refuses_cross_namespace_destinations_even_when_the_wire_authorizes_them() {
    let config = translated(vec![virtual_service("direct", direct_spec(RATINGS_OTHER))]);
    let sidecar_slice = slice_for(&config, &sidecar_runtime());
    let runtime = node_waypoint_runtime();
    let mut slice = slice_for(&config, &runtime);
    // Simulate a producer that carried the route and its authorization, and
    // the destination's workloads, to a NodeWaypoint.
    slice.http_routes = sidecar_slice.http_routes.clone();
    for service in &sidecar_slice.services {
        if service.namespace == OTHER
            && !slice
                .services
                .iter()
                .any(|known| known.namespace == service.namespace && known.name == service.name)
        {
            slice.services.push(service.clone());
        }
    }
    for workload in &sidecar_slice.workloads {
        if workload.namespace == OTHER && !slice.workloads.contains(workload) {
            slice.workloads.push(workload.clone());
        }
    }
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    assert_references_resolve(&prepared);
    assert!(carried_routes(&prepared).is_empty());
    assert!(
        !prepared
            .upstreams
            .iter()
            .any(|upstream| upstream.id.starts_with(CLONE_PREFIX))
    );
}

#[test]
fn malformed_cross_namespace_targets_reject_the_slice() {
    let config = translated(vec![virtual_service("direct", direct_spec(RATINGS_OTHER))]);
    let runtime = sidecar_runtime();
    let slice = slice_for(&config, &runtime);
    let entry = slice.http_routes.authorized_cross_namespace_targets[0].clone();
    let malformed = [
        (
            "own namespace",
            MeshHttpRouteCrossNamespaceTarget {
                namespace: DEFAULT_NAMESPACE.to_string(),
                ..entry.clone()
            },
        ),
        (
            "uncarried route",
            MeshHttpRouteCrossNamespaceTarget {
                proxy_id: "istio-vs-default-missing-0".to_string(),
                ..entry.clone()
            },
        ),
        (
            "empty name",
            MeshHttpRouteCrossNamespaceTarget {
                name: String::new(),
                ..entry.clone()
            },
        ),
        (
            "padded namespace",
            MeshHttpRouteCrossNamespaceTarget {
                namespace: " other".to_string(),
                ..entry.clone()
            },
        ),
        ("duplicate", entry.clone()),
    ];
    for (case, target) in malformed {
        let mut broken = slice.clone();
        broken
            .http_routes
            .authorized_cross_namespace_targets
            .push(target);
        assert!(
            prepare_gateway_config_from_mesh_slice(&broken, &runtime).is_err(),
            "{case}: a malformed authorization rejects the slice"
        );
    }

    // Unknown fields are refused at decode on both wires.
    let mut value = serde_json::to_value(&slice).expect("serialize");
    value["http_routes"]["authorized_cross_namespace_targets"][0]["port"] = json!(8080);
    assert!(serde_json::from_value::<MeshSlice>(value).is_err());
}

#[test]
fn upstream_references_stay_namespace_local() {
    let config = translated(vec![virtual_service("direct", direct_spec(RATINGS_OTHER))]);
    let runtime = sidecar_runtime();
    let mut prepared =
        prepare_gateway_config_from_mesh_slice(&slice_for(&config, &runtime), &runtime)
            .expect("slice materializes");
    let route = prepared
        .proxies
        .iter_mut()
        .find(|proxy| proxy.id.starts_with("istio-vs-"))
        .expect("carried route");
    // Pointing the route straight at the other namespace's upstream id is a
    // dangling reference: references never resolve across namespaces.
    route.upstream_id = Some(RATINGS_OTHER_UPSTREAM.to_string());
    assert!(prepared.validate_upstream_references().is_err());
}

#[test]
fn mesh_config_validation_bounds_authorized_targets() {
    let binding = |targets: Vec<MeshWaypointServiceRef>| MeshConfig {
        virtual_service_http_routes: vec![MeshVirtualServiceHttpRoutes {
            name: "direct".to_string(),
            namespace: DEFAULT_NAMESPACE.to_string(),
            export_to: vec!["*".to_string()],
            proxy_ids: vec!["istio-vs-default-direct-0".to_string()],
            authorized_cross_namespace_targets: targets,
        }],
        ..MeshConfig::default()
    };
    let target = |namespace: &str, name: &str| MeshWaypointServiceRef {
        namespace: namespace.to_string(),
        name: name.to_string(),
    };
    assert!(
        !binding(vec![target(OTHER, "ratings")])
            .validate()
            .iter()
            .any(|error| error.contains("authorized_cross_namespace_targets")),
        "a well-formed authorization is admitted"
    );
    for (case, targets) in [
        ("own namespace", vec![target(DEFAULT_NAMESPACE, "ratings")]),
        ("empty namespace", vec![target("", "ratings")]),
        ("padded name", vec![target(OTHER, "ratings ")]),
        (
            "duplicate",
            vec![target(OTHER, "ratings"), target(OTHER, "ratings")],
        ),
        (
            "too many",
            (0..=64)
                .map(|index| target(OTHER, &format!("svc-{index}")))
                .collect(),
        ),
    ] {
        let errors = binding(targets).validate();
        assert!(
            errors
                .iter()
                .any(|error| error.contains("authorized_cross_namespace_targets")),
            "{case}: {errors:?}"
        );
        assert!(
            errors.iter().all(|error| !error.contains("ratings ")),
            "{case}: diagnostics never echo a supplied value"
        );
    }
}

/// Review F2: a workload of a THIRD namespace attached to the authorized
/// target Service (a cross-namespace `WorkloadEntry`) never reaches the
/// subscriber, neither as a workload nor as a Service workload reference,
/// even when the subscriber's view imports that namespace and its bearer
/// claim does not.
#[test]
fn a_third_namespace_workload_attached_to_the_target_never_reaches_the_slice() {
    use ferrum_edge::modes::mesh::config::WorkloadRef;

    let mut config = translated(vec![virtual_service("direct", direct_spec(RATINGS_OTHER))]);
    let mut attached = workload_for("vm", "gamma", [("app", "vm")], ["10.0.2.50"]);
    attached.service_name = "ratings".to_string();
    attached.service_namespace = Some(OTHER.to_string());
    let attached_identity = attached.spiffe_id.clone();
    let mesh = config.mesh.as_mut().expect("mesh block");
    mesh.services
        .iter_mut()
        .find(|service| service.namespace == OTHER && service.name == "ratings")
        .expect("other/ratings")
        .workloads
        .push(WorkloadRef {
            spiffe_id: attached_identity.clone(),
        });
    mesh.workloads.push(attached);
    for sidecar in &mut mesh.sidecars {
        for egress in &mut sidecar.egress {
            egress.hosts.push("gamma/*".to_string());
        }
    }

    let runtime = sidecar_runtime();
    let request = runtime.mesh_slice_request();
    let all: HashSet<String> = [DEFAULT_NAMESPACE, OTHER, "gamma"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let bearer: HashSet<String> = [DEFAULT_NAMESPACE, OTHER]
        .into_iter()
        .map(str::to_string)
        .collect();
    let filtered = filter_config_to_mesh_request_for_test(
        &config,
        &request,
        &CpScope::Set(all),
        Some(&bearer),
    );
    for (case, slice) in [
        (
            "scoped control plane",
            MeshSlice::from_gateway_config(&filtered, request.clone()),
        ),
        ("unfiltered", slice_for(&config, &runtime)),
    ] {
        assert_eq!(
            slice.http_routes.authorized_cross_namespace_targets.len(),
            1,
            "{case}: the route rides"
        );
        assert!(
            !slice
                .workloads
                .iter()
                .any(|workload| workload.spiffe_id == attached_identity),
            "{case}: the third-namespace workload is not serialized"
        );
        let target = slice
            .services
            .iter()
            .find(|service| service.namespace == OTHER && service.name == "ratings")
            .expect("the target Service rides");
        assert!(
            !target
                .workloads
                .iter()
                .any(|reference| reference.spiffe_id == attached_identity),
            "{case}: the target Service does not reference it either"
        );
        let prepared =
            prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
        let clone_id = carried_routes(&prepared)[0]
            .upstream_id
            .clone()
            .expect("bound upstream");
        assert_ratings_clone(&prepared, &clone_id);
    }
}

/// Review F3: the projection never emits more authorizations than a data
/// plane accepts. A route that would overflow the budget is withheld (route
/// order), and the rest of the set still applies.
#[test]
fn the_projection_withholds_routes_beyond_the_authorization_budget() {
    use ferrum_edge::modes::mesh::slice::MAX_HTTP_ROUTE_CROSS_NAMESPACE_TARGETS as BUDGET;

    let mut config = translated(vec![virtual_service("direct", direct_spec(RATINGS_OTHER))]);
    let route = config
        .proxies
        .iter()
        .find(|proxy| proxy.id.starts_with("istio-vs-"))
        .expect("carried route")
        .clone();
    let mut extra_ids = Vec::with_capacity(BUDGET);
    for index in 0..BUDGET {
        let mut copy = route.clone();
        copy.id = format!("{}-x{index}", route.id);
        copy.listen_path = Some(format!("/r{index}"));
        extra_ids.push(copy.id.clone());
        config.proxies.push(copy);
    }
    let last = extra_ids.last().cloned().expect("ids");
    config
        .mesh
        .as_mut()
        .expect("mesh block")
        .virtual_service_http_routes[0]
        .proxy_ids
        .extend(extra_ids);

    let runtime = sidecar_runtime();
    let slice = slice_for(&config, &runtime);
    assert_eq!(
        slice.http_routes.authorized_cross_namespace_targets.len(),
        BUDGET
    );
    let carried = route_ids(&slice);
    assert_eq!(carried.len(), BUDGET, "exactly one route is withheld");
    assert!(
        !carried.contains(&last),
        "the last route in order is the one withheld"
    );
    prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("a set at the budget materializes");
}

/// Review F4: DestinationRules naming the destination workloads' own
/// addresses never match the route-namespace clone (it takes its policy from
/// the Service upstream it copies), so they cannot reject the slice before
/// the clone is refreshed.
#[test]
fn endpoint_host_destination_rules_do_not_reject_a_slice_with_a_clone() {
    use ferrum_edge::modes::mesh::config::WorkloadRef;

    let mut config = translated(vec![
        virtual_service("direct", direct_spec(RATINGS_OTHER)),
        destination_rule(
            "vm-a",
            DEFAULT_NAMESPACE,
            "vm-a.example.com",
            json!({"loadBalancer": {"simple": "RANDOM"}}),
        ),
        destination_rule(
            "vm-b",
            DEFAULT_NAMESPACE,
            "vm-b.example.com",
            json!({"loadBalancer": {"simple": "ROUND_ROBIN"}}),
        ),
    ]);
    let vm_a = workload_for("ratings", OTHER, [("app", "ratings")], ["vm-a.example.com"]);
    let mut vm_b = workload_for(
        "ratings-b",
        OTHER,
        [("app", "ratings")],
        ["vm-b.example.com"],
    );
    vm_b.service_name = "ratings".to_string();
    let mesh = config.mesh.as_mut().expect("mesh block");
    mesh.workloads
        .retain(|workload| !(workload.namespace == OTHER && workload.service_name == "ratings"));
    let ratings = mesh
        .services
        .iter_mut()
        .find(|service| service.namespace == OTHER && service.name == "ratings")
        .expect("other/ratings");
    ratings.workloads = vec![
        WorkloadRef {
            spiffe_id: vm_a.spiffe_id.clone(),
        },
        WorkloadRef {
            spiffe_id: vm_b.spiffe_id.clone(),
        },
    ];
    mesh.workloads.push(vm_a);
    mesh.workloads.push(vm_b);
    let rules = mesh.destination_rules.clone();

    let runtime = sidecar_runtime();
    let mut slice = slice_for(&config, &runtime);
    // Both endpoint-host rules are visible to the subscriber.
    for rule in rules {
        if !slice
            .destination_rules
            .iter()
            .any(|known| known.namespace == rule.namespace && known.name == rule.name)
        {
            slice.destination_rules.push(rule);
        }
    }
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("endpoint-host rules do not reject the slice");
    let routes = carried_routes(&prepared);
    assert_eq!(routes.len(), 1, "the route is served");
    let clone = upstream(&prepared, routes[0].upstream_id.as_deref().expect("bound"));
    let mut hosts: Vec<&str> = clone
        .targets
        .iter()
        .map(|target| target.host.as_str())
        .collect();
    hosts.sort_unstable();
    assert_eq!(hosts, vec!["vm-a.example.com", "vm-b.example.com"]);
    assert_eq!(
        clone.algorithm,
        upstream(&prepared, RATINGS_OTHER_UPSTREAM).algorithm,
        "the clone carries the Service upstream's policy, not an endpoint rule's"
    );
}
