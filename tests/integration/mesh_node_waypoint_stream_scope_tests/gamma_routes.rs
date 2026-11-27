//! Gateway API GAMMA routes (`HTTPRoute` / `GRPCRoute` with `Service`
//! parentRefs) carried on Sidecar and NodeWaypoint mesh slices (issue #7538).
//!
//! The production halves end to end: the K8s translator writes the GAMMA mesh
//! route set and binding, `MeshSlice::from_gateway_config` projects it as a
//! control plane does, the slice crosses the native (JSON) and xDS
//! (`HttpRoutesCarrier`) wires unchanged, and
//! `prepare_gateway_config_from_mesh_slice` decodes and materializes it on the
//! data plane through the same checks VirtualService routes pass.

use ferrum_edge::RouterCache;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::modes::mesh::{
    MeshRuntimeConfig, MeshTopology, MeshTrafficDirection, prepare_gateway_config_from_mesh_slice,
};
use ferrum_edge::router_cache::{MeshRouteScope, MeshScopedResolution};
use ferrum_edge::xds::carrier::{MeshSliceCarrier, build_slice_carriers};
use serde_json::{Value, json};

use super::super::mesh_test_support::{
    DEFAULT_NAMESPACE, runtime_for_topology, service_for, workload_for,
};

const HOST: &str = "reviews.default.svc.cluster.local";

fn object(kind: &str, api_version: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{namespace}-{name}"),
            namespace: namespace.to_string(),
            generation: Some(1),
            labels: Default::default(),
            annotations: Default::default(),
            creation_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn k8s_service(namespace: &str, name: &str) -> K8sObject {
    object(
        "Service",
        "v1",
        namespace,
        name,
        json!({
            "selector": {"app": name},
            "clusterIP": "10.96.0.20",
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}]
        }),
    )
}

/// A producer HTTPRoute on `default/reviews`: `/api` with `x-version: v2`
/// splits 50/50 between `reviews` and `ratings` and sets a request header.
fn gamma_route(namespace: &str, parent_namespace: &str, backend_namespace: &str) -> K8sObject {
    object(
        "HTTPRoute",
        "gateway.networking.k8s.io/v1",
        namespace,
        "reviews-route",
        json!({
            "parentRefs": [{
                "group": "",
                "kind": "Service",
                "name": "reviews",
                "namespace": parent_namespace,
                "port": 8080
            }],
            "rules": [{
                "matches": [{
                    "path": {"type": "PathPrefix", "value": "/api"},
                    "headers": [{"name": "x-version", "value": "v2"}]
                }],
                "filters": [{
                    "type": "RequestHeaderModifier",
                    "requestHeaderModifier": {"set": [{"name": "x-routed-by", "value": "gamma"}]}
                }],
                "timeouts": {"request": "2s"},
                "backendRefs": [
                    {"name": "reviews", "namespace": backend_namespace, "port": 8080, "weight": 50},
                    {"name": "ratings", "namespace": backend_namespace, "port": 8080, "weight": 50}
                ]
            }]
        }),
    )
}

/// Translate `objects` and add the mesh inventory the routes reach.
fn translated_config(objects: &[K8sObject]) -> GatewayConfig {
    let translated = translate_k8s_objects(
        objects,
        K8sTranslationOptions::new(
            DEFAULT_NAMESPACE.to_string(),
            TrustDomain::new("cluster.local").expect("trust domain"),
        )
        .with_source_namespaces(vec![DEFAULT_NAMESPACE.to_string(), "clients".to_string()]),
    )
    .expect("snapshot translates");
    let mut config = translated.config;
    let reviews = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.0.0.11"],
    );
    let ratings = workload_for(
        "ratings",
        DEFAULT_NAMESPACE,
        [("app", "ratings")],
        ["10.0.0.12"],
    );
    let mesh = config.mesh.get_or_insert_with(Box::default);
    mesh.services = vec![
        service_for("reviews", DEFAULT_NAMESPACE, &[&reviews]),
        service_for("ratings", DEFAULT_NAMESPACE, &[&ratings]),
    ];
    mesh.workloads = vec![reviews, ratings];
    config.normalize_fields();
    config.normalize_mesh_fields();
    config
}

fn producer_config() -> GatewayConfig {
    translated_config(&[
        k8s_service(DEFAULT_NAMESPACE, "reviews"),
        k8s_service(DEFAULT_NAMESPACE, "ratings"),
        gamma_route(DEFAULT_NAMESPACE, DEFAULT_NAMESPACE, DEFAULT_NAMESPACE),
    ])
}

fn slice_for(config: &GatewayConfig, runtime: &MeshRuntimeConfig) -> MeshSlice {
    MeshSlice::from_gateway_config(config, runtime.mesh_slice_request())
}

fn carried_ids(values: &[Value]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| value.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn routed_proxy_id(
    prepared: &GatewayConfig,
    path: &str,
    direction: Option<MeshTrafficDirection>,
) -> Option<String> {
    let cache = RouterCache::new(prepared, 1024);
    match cache.resolve_mesh_scoped_route_for_test(
        Some(HOST),
        path,
        None,
        false,
        MeshRouteScope {
            direction,
            authority_port: Some(8080),
            ..MeshRouteScope::default()
        },
    ) {
        MeshScopedResolution::Routed(route) => Some(route.route_match().proxy.id.clone()),
        MeshScopedResolution::NotFound | MeshScopedResolution::Refused => None,
    }
}

#[test]
fn gamma_routes_ride_the_sidecar_and_node_waypoint_slices_only() {
    let config = producer_config();
    let node_waypoint = slice_for(&config, &runtime_for_topology(MeshTopology::NodeWaypoint));
    let proxy_ids = carried_ids(&node_waypoint.http_routes.proxies);
    assert_eq!(
        proxy_ids.len(),
        1,
        "one route for the Service: {proxy_ids:?}"
    );
    assert!(proxy_ids[0].starts_with("istio-vs-gamma_service-"));
    let upstream_ids = carried_ids(&node_waypoint.http_routes.upstreams);
    assert_eq!(upstream_ids.len(), 1, "the weighted split upstream rides");
    assert!(upstream_ids[0].starts_with("istio-vs-upstream-gamma_httproute-"));
    for plugin in &node_waypoint.http_routes.plugin_configs {
        let owner = plugin
            .get("proxy_id")
            .and_then(Value::as_str)
            .expect("route plugins are proxy-scoped");
        assert!(proxy_ids.iter().any(|id| id == owner));
    }

    let sidecar = slice_for(&config, &runtime_for_topology(MeshTopology::Sidecar));
    assert_eq!(
        sidecar.http_routes, node_waypoint.http_routes,
        "one projection for both topologies"
    );

    for topology in [MeshTopology::Ambient, MeshTopology::ServiceWaypoint] {
        assert!(
            slice_for(&config, &runtime_for_topology(topology))
                .http_routes
                .is_empty(),
            "{topology:?} is not served GAMMA routes in this release"
        );
    }
}

/// F1: the same snapshot handed to a gateway (non-mesh) data plane, or seen on
/// an inbound mesh listener, serves nothing for a GAMMA route.
#[test]
fn a_gateway_listener_never_serves_a_gamma_route() {
    let config = producer_config();
    for path in ["/api/items", "/other"] {
        let routed = routed_proxy_id(&config, path, None);
        assert!(
            routed
                .as_deref()
                .is_none_or(|id| !id.starts_with("istio-vs-gamma_")),
            "a gateway listener given the translated snapshot must not route {path} to the \
             GAMMA proxy, got {routed:?}"
        );
        let inbound = routed_proxy_id(&config, path, Some(MeshTrafficDirection::Inbound));
        assert!(
            inbound
                .as_deref()
                .is_none_or(|id| !id.starts_with("istio-vs-gamma_")),
            "an inbound mesh listener never serves a GAMMA route, got {inbound:?}"
        );
    }
    assert!(
        routed_proxy_id(&config, "/api/items", Some(MeshTrafficDirection::Outbound))
            .is_some_and(|id| id.starts_with("istio-vs-gamma_")),
        "the outbound mesh listener does"
    );
}

/// A consumer route whose backend is in another namespace is never carried in
/// this release, to any namespace.
#[test]
fn a_cross_namespace_consumer_route_is_carried_nowhere() {
    let config = translated_config(&[
        k8s_service(DEFAULT_NAMESPACE, "reviews"),
        k8s_service(DEFAULT_NAMESPACE, "ratings"),
        gamma_route("clients", DEFAULT_NAMESPACE, DEFAULT_NAMESPACE),
    ]);
    let node_waypoint = runtime_for_topology(MeshTopology::NodeWaypoint);
    for namespace in [DEFAULT_NAMESPACE, "clients", "other"] {
        let request = MeshSliceRequest {
            namespace: namespace.to_string(),
            ..node_waypoint.mesh_slice_request()
        };
        assert!(
            MeshSlice::from_gateway_config(&config, request)
                .http_routes
                .is_empty(),
            "{namespace}: a consumer route never affects another namespace's traffic"
        );
    }
}

#[test]
fn a_consumer_route_rides_only_its_own_namespace() {
    let config = translated_config(&[
        k8s_service(DEFAULT_NAMESPACE, "reviews"),
        k8s_service(DEFAULT_NAMESPACE, "ratings"),
        k8s_service("clients", "reviews"),
        k8s_service("clients", "ratings"),
        // A consumer route in `clients` for `default/reviews`, routing to the
        // `clients` namespace's own Services.
        gamma_route("clients", DEFAULT_NAMESPACE, "clients"),
    ]);
    let mesh = config.mesh.as_ref().expect("mesh block");
    let binding = mesh
        .virtual_service_http_routes
        .iter()
        .find(|binding| binding.name == "gamma_default_reviews")
        .expect("consumer binding");
    assert_eq!(binding.namespace, "clients");
    assert!(binding.export_to.is_empty(), "namespace-local");

    let node_waypoint = runtime_for_topology(MeshTopology::NodeWaypoint);
    assert!(
        slice_for(&config, &node_waypoint).http_routes.is_empty(),
        "a consumer route never reaches the Service namespace's clients"
    );
    let clients = MeshSliceRequest {
        namespace: "clients".to_string(),
        ..node_waypoint.mesh_slice_request()
    };
    assert!(
        !MeshSlice::from_gateway_config(&config, clients)
            .http_routes
            .is_empty(),
        "it rides to clients in its own namespace"
    );
}

#[test]
fn gamma_routes_round_trip_over_native_json_and_the_xds_carrier() {
    let config = producer_config();
    let slice = slice_for(&config, &runtime_for_topology(MeshTopology::Sidecar));
    assert!(!slice.http_routes.is_empty());
    let native: MeshSlice =
        serde_json::from_value(serde_json::to_value(&slice).expect("serialize"))
            .expect("native slice JSON decodes");
    assert!(native.content_eq(&slice));
    let carrier = build_slice_carriers(&slice)
        .into_iter()
        .find(|carrier| matches!(carrier, MeshSliceCarrier::HttpRoutes(_)))
        .expect("the existing HTTP route carrier carries GAMMA routes");
    let bytes = carrier.encode_value().expect("encode");
    assert_eq!(
        MeshSliceCarrier::decode(carrier.type_url(), &bytes)
            .expect("decode")
            .expect("recognized carrier"),
        MeshSliceCarrier::HttpRoutes(slice.http_routes.clone())
    );
}

#[test]
fn node_waypoint_data_plane_materializes_gamma_routes() {
    let config = producer_config();
    let runtime = runtime_for_topology(MeshTopology::NodeWaypoint);
    let slice = slice_for(&config, &runtime);
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("the data plane accepts the GAMMA route set");
    for id in carried_ids(&slice.http_routes.proxies) {
        assert!(
            prepared.proxies.iter().any(|proxy| proxy.id == id),
            "{id} materializes (the data-plane binding did not refuse it)"
        );
    }
    let dispatch_count = prepared
        .plugin_configs
        .iter()
        .filter(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin
                    .proxy_id
                    .as_deref()
                    .is_some_and(|id| id.starts_with("istio-vs-gamma_"))
        })
        .count();
    assert_eq!(dispatch_count, 1, "the Service's one dispatch instance");
}

#[test]
fn sidecar_serves_gamma_routes_on_outbound_capture_only() {
    let config = producer_config();
    let runtime = runtime_for_topology(MeshTopology::Sidecar);
    let slice = slice_for(&config, &runtime);
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("the data plane accepts the GAMMA route set");
    let gamma_id = carried_ids(&slice.http_routes.proxies).remove(0);
    assert!(
        prepared.proxies.iter().any(|proxy| proxy.id == gamma_id),
        "the Sidecar binding keeps the GAMMA route"
    );

    // Every path of the Service host reaches the GAMMA route on outbound
    // capture: its dispatch instance serves the matching rule or rejects the
    // request, so no path falls through to the plain Service route.
    for path in ["/api/items", "/other"] {
        assert_eq!(
            routed_proxy_id(&prepared, path, Some(MeshTrafficDirection::Outbound)),
            Some(gamma_id.clone()),
            "{path}"
        );
        assert!(
            routed_proxy_id(&prepared, path, Some(MeshTrafficDirection::Inbound))
                .is_none_or(|id| !id.starts_with("istio-vs-")),
            "an inbound mesh listener never serves a carried GAMMA route ({path})"
        );
    }
}
