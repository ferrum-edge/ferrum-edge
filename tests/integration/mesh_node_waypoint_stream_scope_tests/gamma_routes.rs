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

#[test]
fn restrictive_sidecar_egress_keeps_gamma_route_despite_no_forward_placeholder() {
    let mut config = producer_config();
    let mesh = config.mesh.as_mut().expect("mesh");
    mesh.sidecars
        .push(ferrum_edge::modes::mesh::config::MeshSidecar {
            name: "strict".to_string(),
            namespace: DEFAULT_NAMESPACE.to_string(),
            workload_selector: None,
            egress: vec![ferrum_edge::modes::mesh::config::MeshSidecarEgress {
                hosts: vec![
                    "./reviews.default.svc.cluster.local".to_string(),
                    "./ratings.default.svc.cluster.local".to_string(),
                ],
                port: None,
            }],
            ingress: Vec::new(),
            ingress_declared: false,
            outbound_traffic_policy: None,
            egress_inherits_defaults: false,
        });
    let runtime = MeshRuntimeConfig {
        sidecar_enforced: true,
        ..runtime_for_topology(MeshTopology::Sidecar)
    };
    let slice = slice_for(&config, &runtime);
    assert_eq!(
        carried_ids(&slice.http_routes.proxies).len(),
        1,
        "strict Sidecar importing parent and backends keeps the GAMMA route"
    );
}

#[test]
fn unavailable_canary_backend_fails_only_its_rule_and_keeps_gamma_dispatch() {
    let route = object(
        "HTTPRoute",
        "gateway.networking.k8s.io/v1",
        DEFAULT_NAMESPACE,
        "reviews-canary",
        json!({
            "parentRefs": [{"group": "", "kind": "Service", "name": "reviews", "port": 8080}],
            "rules": [
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": "/canary"}}],
                    "backendRefs": [{"name": "ratings", "port": 8080}]
                },
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": "/stable"}}],
                    "backendRefs": [{"name": "reviews", "port": 8080}]
                }
            ]
        }),
    );
    let mut config = translated_config(&[
        k8s_service(DEFAULT_NAMESPACE, "reviews"),
        k8s_service(DEFAULT_NAMESPACE, "ratings"),
        route,
    ]);
    // Scale `ratings` to zero endpoints while `reviews` remains healthy.
    let mesh = config.mesh.as_mut().expect("mesh");
    mesh.workloads.retain(|w| w.service_name != "ratings");
    for svc in &mut mesh.services {
        if svc.name == "ratings" {
            svc.workloads.clear();
        }
    }
    let runtime = runtime_for_topology(MeshTopology::NodeWaypoint);
    let slice = slice_for(&config, &runtime);
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("GAMMA slice materializes with scaled-to-zero canary backend");
    let gamma_id = carried_ids(&slice.http_routes.proxies).remove(0);
    assert!(
        prepared.proxies.iter().any(|proxy| proxy.id == gamma_id),
        "GAMMA proxy remains materialized when one rule backend has zero endpoints"
    );
    let dispatch = prepared
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.proxy_id.as_deref() == Some(gamma_id.as_str())
        })
        .expect("GAMMA dispatch plugin");
    assert_eq!(
        dispatch.config["reject_unmatched"],
        json!(true),
        "unmatched paths still return 404 rather than falling through to plain Service"
    );
    let rules = dispatch.config["rules"].as_array().expect("rules array");
    let canary = rules
        .iter()
        .find(|rule| rule["match"]["uri"]["regex"] == json!("/canary(/.*)?"))
        .expect("canary rule preserved");
    assert_eq!(
        canary["fault"]["abort"]["status_code"],
        json!(503),
        "unavailable canary rule fails closed with 503"
    );
    assert!(
        canary["destination"].get("upstream_id").is_none(),
        "unavailable canary rule has no dangling upstream_id"
    );
    let stable = rules
        .iter()
        .find(|rule| rule["match"]["uri"]["regex"] == json!("/stable(/.*)?"))
        .expect("stable rule preserved");
    assert_eq!(
        stable["destination"]["upstream_id"],
        json!("__mesh-out-upstream-default-reviews-8080"),
        "healthy rule keeps routing to its mesh Service upstream"
    );
    assert!(
        stable.get("fault").is_none(),
        "healthy rule has no abort fault"
    );
}

#[test]
fn weighted_split_with_scaled_to_zero_backend_fails_proportionally_with_503() {
    let route = object(
        "HTTPRoute",
        "gateway.networking.k8s.io/v1",
        DEFAULT_NAMESPACE,
        "reviews-weighted-canary",
        json!({
            "parentRefs": [{"group": "", "kind": "Service", "name": "reviews", "port": 8080}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                "backendRefs": [
                    {"name": "reviews", "port": 8080, "weight": 90},
                    {"name": "ratings", "port": 8080, "weight": 10}
                ]
            }]
        }),
    );
    let mut config = translated_config(&[
        k8s_service(DEFAULT_NAMESPACE, "reviews"),
        k8s_service(DEFAULT_NAMESPACE, "ratings"),
        route,
    ]);
    // Scale only the 10% canary backend (`ratings`) to zero endpoints.
    let mesh = config.mesh.as_mut().expect("mesh");
    mesh.workloads.retain(|w| w.service_name != "ratings");
    for svc in &mut mesh.services {
        if svc.name == "ratings" {
            svc.workloads.clear();
        }
    }
    let runtime = runtime_for_topology(MeshTopology::NodeWaypoint);
    let slice = slice_for(&config, &runtime);
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("weighted GAMMA split materializes when one leg has zero endpoints");
    let gamma_id = carried_ids(&slice.http_routes.proxies).remove(0);
    assert!(
        prepared.proxies.iter().any(|proxy| proxy.id == gamma_id),
        "GAMMA proxy remains materialized"
    );
    let dispatch = prepared
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.proxy_id.as_deref() == Some(gamma_id.as_str())
        })
        .expect("GAMMA dispatch plugin");
    let rules = dispatch.config["rules"].as_array().expect("rules array");
    let rule = &rules[0];
    let split_upstream_id = rule["destination"]["upstream_id"]
        .as_str()
        .expect("healthy share keeps routing through the rebound split upstream");
    let split_upstream = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == split_upstream_id)
        .expect("rebound split upstream exists");
    assert!(
        !split_upstream.targets.is_empty(),
        "rebound split upstream keeps healthy targets"
    );
    assert!(
        split_upstream.targets.iter().all(|target| {
            target.tags.get("mesh_service_name").map(String::as_str) == Some("reviews")
        }),
        "surviving split targets must point only to healthy reviews, got {:?}",
        split_upstream.targets
    );
    assert_eq!(rule["fault"]["abort"]["status_code"], json!(503));
    let pct = rule["fault"]["abort"]["percentage"]
        .as_f64()
        .expect("proportional 503 percentage");
    assert!(
        (pct - 10.0).abs() < 1e-6,
        "10% unavailable weight produces 10% 503 abort, got {pct}"
    );
}

#[test]
fn weighted_split_preserves_distinct_500_invalid_and_503_unavailable_shares() {
    let route = object(
        "HTTPRoute",
        "gateway.networking.k8s.io/v1",
        DEFAULT_NAMESPACE,
        "reviews-mixed-invalid-and-scaled-zero",
        json!({
            "parentRefs": [{"group": "", "kind": "Service", "name": "reviews", "port": 8080}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/mix"}}],
                "backendRefs": [
                    {"name": "reviews", "port": 8080, "weight": 80},
                    {"name": "ratings", "port": 8080, "weight": 10},
                    {"name": "missing-svc", "port": 8080, "weight": 10}
                ]
            }]
        }),
    );
    let mut config = translated_config(&[
        k8s_service(DEFAULT_NAMESPACE, "reviews"),
        k8s_service(DEFAULT_NAMESPACE, "ratings"),
        route,
    ]);
    // Scale only the 10% valid canary (`ratings`) to zero endpoints; the 10%
    // invalid `missing-svc` backendRef already carries a 10% 500 abort.
    let mesh = config.mesh.as_mut().expect("mesh");
    mesh.workloads.retain(|w| w.service_name != "ratings");
    for svc in &mut mesh.services {
        if svc.name == "ratings" {
            svc.workloads.clear();
        }
    }
    let runtime = runtime_for_topology(MeshTopology::NodeWaypoint);
    let slice = slice_for(&config, &runtime);
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("mixed 500 + 503 GAMMA split materializes");
    let gamma_id = carried_ids(&slice.http_routes.proxies).remove(0);
    let dispatch = prepared
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.proxy_id.as_deref() == Some(gamma_id.as_str())
        })
        .expect("GAMMA dispatch plugin");
    ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatchConfig::from_value_normalized(
        &dispatch.config,
    )
    .expect("emitted secondary_abort dispatch config passes validation");
    let rule = &dispatch.config["rules"].as_array().expect("rules array")[0];
    let split_upstream_id = rule["destination"]["upstream_id"]
        .as_str()
        .expect("healthy 80% share routes through rebound split upstream");
    let split_upstream = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == split_upstream_id)
        .expect("rebound split upstream");
    assert!(
        !split_upstream.targets.is_empty()
            && split_upstream.targets.iter().all(|target| {
                target.tags.get("mesh_service_name").map(String::as_str) == Some("reviews")
            }),
        "surviving targets must belong only to healthy reviews, got {:?}",
        split_upstream.targets
    );
    assert_eq!(rule["fault"]["abort"]["status_code"], json!(500));
    let pct_500 = rule["fault"]["abort"]["percentage"]
        .as_f64()
        .expect("500 pct");
    assert!(
        (pct_500 - 10.0).abs() < 1e-6,
        "invalid backendRef keeps 10% 500 share, got {pct_500}"
    );
    assert_eq!(rule["fault"]["secondary_abort"]["status_code"], json!(503));
    let pct_503_cond = rule["fault"]["secondary_abort"]["percentage"]
        .as_f64()
        .expect("conditional 503 pct");
    let expected_cond = 10.0 / 90.0 * 100.0;
    assert!(
        (pct_503_cond - expected_cond).abs() < 1e-6,
        "10% unavailable share of 90% valid share = {expected_cond}%, got {pct_503_cond}"
    );

    // When ALL valid legs scale to zero, 10% still returns 500 and the remaining
    // 90% returns 503 (secondary_abort 100%) without overwriting the 500 share.
    let mesh = config.mesh.as_mut().expect("mesh");
    mesh.workloads.retain(|w| w.service_name != "reviews");
    for svc in &mut mesh.services {
        if svc.name == "reviews" {
            svc.workloads.clear();
        }
    }
    let slice_all_zero = slice_for(&config, &runtime);
    let prepared_all_zero = prepare_gateway_config_from_mesh_slice(&slice_all_zero, &runtime)
        .expect("all-valid-zero + invalid split materializes");
    let dispatch_all_zero = prepared_all_zero
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.proxy_id.as_deref() == Some(gamma_id.as_str())
        })
        .expect("GAMMA dispatch plugin");
    ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatchConfig::from_value_normalized(
        &dispatch_all_zero.config,
    )
    .expect("emitted all-zero secondary_abort config passes validation");
    let rule_all_zero = &dispatch_all_zero.config["rules"]
        .as_array()
        .expect("rules array")[0];
    assert_eq!(rule_all_zero["fault"]["abort"]["status_code"], json!(500));
    assert!(
        (rule_all_zero["fault"]["abort"]["percentage"]
            .as_f64()
            .unwrap()
            - 10.0)
            .abs()
            < 1e-6
    );
    assert_eq!(
        rule_all_zero["fault"]["secondary_abort"]["status_code"],
        json!(503)
    );
    assert_eq!(
        rule_all_zero["fault"]["secondary_abort"]["percentage"],
        json!(100.0)
    );
}

#[test]
fn wildcard_destination_rule_does_not_drop_gamma_dispatch() {
    let route = object(
        "HTTPRoute",
        "gateway.networking.k8s.io/v1",
        DEFAULT_NAMESPACE,
        "reviews-with-terminal-rule",
        json!({
            "parentRefs": [{"group": "", "kind": "Service", "name": "reviews", "port": 8080}],
            "rules": [
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": "/broken"}}],
                    "backendRefs": [{"name": "missing-svc", "port": 8080}]
                },
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": "/ok"}}],
                    "backendRefs": [{"name": "reviews", "port": 8080}]
                }
            ]
        }),
    );
    let mut config = translated_config(&[k8s_service(DEFAULT_NAMESPACE, "reviews"), route]);
    let mesh = config.mesh.as_mut().expect("mesh");
    mesh.destination_rules
        .push(ferrum_edge::modes::mesh::config::MeshDestinationRule {
            name: "mesh-wide-wildcard".to_string(),
            namespace: DEFAULT_NAMESPACE.to_string(),
            host: "*".to_string(),
            export_to: vec!["*".to_string()],
            traffic_policy: None,
            port_level_settings: std::collections::HashMap::new(),
            subsets: Vec::new(),
        });
    let runtime = runtime_for_topology(MeshTopology::NodeWaypoint);
    let slice = slice_for(&config, &runtime);
    assert!(
        slice
            .destination_rules
            .iter()
            .any(|dr| dr.name == "mesh-wide-wildcard" && dr.host == "*"),
        "wildcard DestinationRule must survive slice projection"
    );
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("GAMMA slice materializes under wildcard DestinationRule");
    let gamma_id = carried_ids(&slice.http_routes.proxies).remove(0);
    assert!(
        prepared.proxies.iter().any(|proxy| proxy.id == gamma_id),
        "visible wildcard DestinationRule must not drop GAMMA dispatch proxy or its 100%-abort rule"
    );
}
