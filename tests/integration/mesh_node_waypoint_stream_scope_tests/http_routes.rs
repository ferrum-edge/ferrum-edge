//! VirtualService HTTP routes carried on a NodeWaypoint mesh slice (issue #7233).
//!
//! A mesh data plane is built from a `MeshSlice`, never from a whole
//! `GatewayConfig`. These tests drive the production halves: the K8s
//! translator writes the mesh binding, `MeshSlice::from_gateway_config`
//! projects the routes a NodeWaypoint serves (as a control plane does), the
//! slice crosses the native (JSON) and xDS (ECDS carrier) wire, and
//! `prepare_gateway_config_from_mesh_slice` materializes it on the data plane.

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::_test_support::{
    install_plugin_finalizers_for_test, mesh_mtls_dispatch_authority_for_test,
    run_before_proxy_hooks_for_test, try_acquire_destination_active_request_for_test,
    validate_mesh_route_dispatch_upstream_references_for_test,
};
use ferrum_edge::RouterCache;
use ferrum_edge::backend_active_request_limit::BackendActiveRequestLimiter;
use ferrum_edge::config::db_backend::namespaced_runtime_key;
use ferrum_edge::config::types::{GatewayConfig, UPSTREAM_TARGET_SERVICE_NAME_TAG};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, PolicyScope, ServicePort, WorkloadPort, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::modes::mesh::{
    MESH_AUTHZ_PLUGIN_ID, MeshRuntimeConfig, MeshTopology, MeshTrafficDirection,
    prepare_gateway_config_from_mesh_slice,
};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, create_plugin};
use ferrum_edge::router_cache::{MeshRouteScope, MeshScopedResolution};
use ferrum_edge::xds::carrier::{MeshSliceCarrier, build_slice_carriers};
use serde_json::json;

use super::super::mesh_test_support::{
    DEFAULT_NAMESPACE, policy_allow_principal, runtime_for_topology, service_for, workload_for,
};

const TRUSTED: &str = "spiffe://cluster.local/ns/default/sa/trusted";
const UNTRUSTED: &str = "spiffe://cluster.local/ns/default/sa/untrusted";

fn virtual_service(name: &str, spec: serde_json::Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "VirtualService".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: DEFAULT_NAMESPACE.to_string(),
            generation: None,
            labels: Default::default(),
            annotations: Default::default(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// A weighted split between `reviews` and `ratings`, which the translator
/// materializes as an `istio-vs-upstream-*` upstream behind a
/// `mesh_route_dispatch` route.
fn split_spec(extra: serde_json::Value) -> serde_json::Value {
    let mut spec = json!({
        "hosts": ["reviews.default.svc.cluster.local"],
        "http": [{
            "route": [
                {
                    "destination": {
                        "host": "reviews.default.svc.cluster.local",
                        "port": {"number": 8080}
                    },
                    "weight": 50
                },
                {
                    "destination": {
                        "host": "ratings.default.svc.cluster.local",
                        "port": {"number": 8080}
                    },
                    "weight": 50
                }
            ]
        }]
    });
    if let (Some(spec), Some(extra)) = (spec.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            spec.insert(key.clone(), value.clone());
        }
    }
    spec
}

/// [`split_spec`] guarded by a header match, which the translator captures as
/// `mesh_route_dispatch` rules on the route (an unguarded route has none).
fn guarded_split_spec() -> serde_json::Value {
    let mut spec = split_spec(json!({}));
    spec["http"][0]["match"] = json!([{
        "uri": {"prefix": "/api"},
        "headers": {"x-version": {"exact": "v2"}}
    }]);
    spec
}

/// Translate `objects`, then add the mesh inventory the routes reach and a
/// destination policy that admits only `TRUSTED` to `app=reviews`.
fn translated_config(objects: &[K8sObject]) -> GatewayConfig {
    let translated = translate_k8s_objects(
        objects,
        K8sTranslationOptions::new(
            DEFAULT_NAMESPACE.to_string(),
            TrustDomain::new("cluster.local").expect("trust domain"),
        ),
    )
    .expect("VirtualService translates");
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
    let details = workload_for(
        "details",
        DEFAULT_NAMESPACE,
        [("app", "details")],
        ["10.0.0.13"],
    );
    let mesh = config.mesh.get_or_insert_with(Box::default);
    mesh.services = vec![
        service_for("reviews", DEFAULT_NAMESPACE, &[&reviews]),
        service_for("ratings", DEFAULT_NAMESPACE, &[&ratings]),
        service_for("details", DEFAULT_NAMESPACE, &[&details]),
    ];
    mesh.workloads = vec![reviews, ratings, details];
    mesh.mesh_policies = vec![policy_allow_principal(
        "reviews-trusted-only",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
                namespace: None,
            },
        },
        TRUSTED,
    )];
    config.normalize_fields();
    config.normalize_mesh_fields();
    config
}

fn node_waypoint_runtime() -> MeshRuntimeConfig {
    runtime_for_topology(MeshTopology::NodeWaypoint)
}

fn node_waypoint_slice(config: &GatewayConfig, runtime: &MeshRuntimeConfig) -> MeshSlice {
    MeshSlice::from_gateway_config(config, runtime.mesh_slice_request())
}

fn carried_ids(values: &[serde_json::Value]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| value.get("id").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect()
}

#[test]
fn translator_binds_mesh_virtual_service_http_routes_with_export_to() {
    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);
    let mesh = config.mesh.as_ref().expect("mesh block");
    assert_eq!(mesh.virtual_service_http_routes.len(), 1);
    let binding = &mesh.virtual_service_http_routes[0];
    assert_eq!(binding.name, "split");
    assert_eq!(binding.namespace, DEFAULT_NAMESPACE);
    assert_eq!(binding.export_to, vec!["*".to_string()]);
    assert!(!binding.proxy_ids.is_empty());
    for id in &binding.proxy_ids {
        assert!(
            config.proxies.iter().any(|proxy| &proxy.id == id),
            "every bound id names a translated proxy"
        );
    }
}

#[test]
fn translator_does_not_bind_an_ingress_only_virtual_service() {
    let config = translated_config(&[virtual_service(
        "ingress-only",
        split_spec(json!({"gateways": ["istio-system/public"]})),
    )]);
    assert!(
        !config.proxies.is_empty(),
        "gateway routes still translate for gateway data planes"
    );
    let mesh = config.mesh.as_ref().expect("mesh block");
    assert!(mesh.virtual_service_http_routes.is_empty());
}

#[test]
fn node_waypoint_slice_carries_bound_routes_their_plugins_and_upstreams() {
    let config = translated_config(&[virtual_service("split", guarded_split_spec())]);
    let slice = node_waypoint_slice(&config, &node_waypoint_runtime());
    let routes = &slice.http_routes;
    assert!(!routes.proxies.is_empty(), "NodeWaypoint gets the routes");
    let proxy_ids = carried_ids(&routes.proxies);
    assert!(proxy_ids.iter().all(|id| id.starts_with("istio-vs-")));
    let upstream_ids = carried_ids(&routes.upstreams);
    assert_eq!(
        upstream_ids.len(),
        1,
        "the weighted split upstream rides along"
    );
    assert!(upstream_ids[0].starts_with("istio-vs-upstream-"));
    assert!(
        routes.plugin_configs.iter().any(|plugin| {
            plugin
                .get("plugin_name")
                .and_then(serde_json::Value::as_str)
                == Some("mesh_route_dispatch")
        }),
        "the route's mesh_route_dispatch rules ride along"
    );
    for plugin in &routes.plugin_configs {
        let owner = plugin
            .get("proxy_id")
            .and_then(serde_json::Value::as_str)
            .expect("route plugins are proxy-scoped");
        assert!(proxy_ids.iter().any(|id| id == owner));
    }
}

#[test]
fn http_routes_are_not_carried_to_other_topologies_or_namespaces() {
    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);

    // Issue #7423: Sidecar slices carry the routes too (see the Sidecar
    // section below); Ambient (the L4 data plane) and ServiceWaypoint do not.
    for topology in [MeshTopology::Ambient, MeshTopology::ServiceWaypoint] {
        let runtime = runtime_for_topology(topology);
        let slice = MeshSlice::from_gateway_config(&config, runtime.mesh_slice_request());
        assert!(
            slice.http_routes.is_empty(),
            "{topology:?} is not served HTTP routes"
        );
    }

    let other_namespace = MeshSliceRequest {
        namespace: "other".to_string(),
        node_waypoint_capture_scoping: true,
        sidecar_http_routes: false,
        ..node_waypoint_runtime().mesh_slice_request()
    };
    let slice = MeshSlice::from_gateway_config(&config, other_namespace);
    assert!(
        slice.http_routes.is_empty(),
        "routes outside the subscription namespace are not visible"
    );
}

#[test]
fn http_routes_honour_virtual_service_export_to() {
    let config = translated_config(&[virtual_service(
        "split",
        split_spec(json!({"exportTo": ["other"]})),
    )]);
    let slice = node_waypoint_slice(&config, &node_waypoint_runtime());
    assert!(
        slice.http_routes.is_empty(),
        "a VirtualService not exported to its own namespace is not served there"
    );
}

#[test]
fn a_route_with_a_missing_plugin_config_is_not_carried() {
    let mut config = translated_config(&[virtual_service("split", guarded_split_spec())]);
    config
        .plugin_configs
        .retain(|plugin| plugin.plugin_name != "mesh_route_dispatch");
    let slice = node_waypoint_slice(&config, &node_waypoint_runtime());
    assert!(
        slice.http_routes.proxies.is_empty(),
        "a route whose association cannot resolve is dropped fail-closed"
    );
}

#[test]
fn content_eq_tracks_http_route_changes() {
    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);
    let slice = node_waypoint_slice(&config, &node_waypoint_runtime());
    assert!(slice.content_eq(&slice.clone()));

    let mut withdrawn = slice.clone();
    withdrawn.http_routes = Default::default();
    assert!(
        !slice.content_eq(&withdrawn),
        "a withdrawn route must re-apply"
    );

    let mut reweighted = slice.clone();
    reweighted.http_routes.upstreams[0]["targets"][0]["weight"] = json!(1);
    assert!(
        !slice.content_eq(&reweighted),
        "a route upstream edit must re-apply"
    );

    let rebuilt = node_waypoint_slice(&config, &node_waypoint_runtime());
    assert!(
        slice.content_eq(&rebuilt),
        "an unchanged projection is a no-op"
    );
}

#[test]
fn http_routes_round_trip_over_native_json_and_the_xds_carrier() {
    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);
    let slice = node_waypoint_slice(&config, &node_waypoint_runtime());
    assert!(!slice.http_routes.is_empty());

    let native: MeshSlice =
        serde_json::from_value(serde_json::to_value(&slice).expect("serialize"))
            .expect("native slice JSON decodes");
    assert!(native.content_eq(&slice));

    let carriers = build_slice_carriers(&slice);
    let carrier = carriers
        .iter()
        .find(|carrier| matches!(carrier, MeshSliceCarrier::HttpRoutes(_)))
        .expect("xDS emits the HTTP route carrier");
    let bytes = carrier.encode_value().expect("encode");
    let decoded = MeshSliceCarrier::decode(carrier.type_url(), &bytes)
        .expect("decode")
        .expect("recognized carrier");
    assert_eq!(
        decoded,
        MeshSliceCarrier::HttpRoutes(slice.http_routes.clone())
    );

    let empty = MeshSlice::default();
    assert!(
        !build_slice_carriers(&empty)
            .iter()
            .any(|carrier| matches!(carrier, MeshSliceCarrier::HttpRoutes(_))),
        "no carrier for an empty route set"
    );
}

#[test]
fn data_plane_materializes_carried_routes_and_exposes_route_upstreams_to_authz() {
    let config = translated_config(&[virtual_service("split", guarded_split_spec())]);
    let runtime = node_waypoint_runtime();
    let slice = node_waypoint_slice(&config, &runtime);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");

    let route_upstream = carried_ids(&slice.http_routes.upstreams).remove(0);
    assert!(
        prepared
            .upstreams
            .iter()
            .any(|upstream| upstream.id == route_upstream)
    );
    for id in carried_ids(&slice.http_routes.proxies) {
        assert!(prepared.proxies.iter().any(|proxy| proxy.id == id));
    }
    assert!(
        prepared
            .plugin_configs
            .iter()
            .any(|plugin| plugin.plugin_name == "mesh_route_dispatch")
    );

    let authz = prepared
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz injected");
    let route_upstreams = authz.config["node_waypoint_route_upstreams"]
        .as_array()
        .expect("route upstream list");
    assert!(
        route_upstreams
            .iter()
            .any(|entry| entry["id"] == json!(route_upstream)),
        "the slice-built config feeds the NodeWaypoint destination index"
    );
    assert!(
        authz.config["mesh_slice"].get("http_routes").is_none(),
        "route plugin configs are not copied into mesh_authz"
    );
}

#[test]
fn data_plane_refuses_http_routes_outside_node_waypoint_and_sidecar() {
    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);
    let slice = node_waypoint_slice(&config, &node_waypoint_runtime());
    for topology in [MeshTopology::Ambient, MeshTopology::ServiceWaypoint] {
        prepare_gateway_config_from_mesh_slice(&slice, &runtime_for_topology(topology))
            .expect_err("only a NodeWaypoint or a Sidecar serves carried HTTP routes");
    }
}

#[test]
fn data_plane_refuses_a_route_set_with_a_dangling_upstream() {
    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);
    let runtime = node_waypoint_runtime();
    let mut slice = node_waypoint_slice(&config, &runtime);
    slice.http_routes.upstreams.clear();
    prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect_err("a route naming an uncarried upstream refuses the slice");
}

fn node_waypoint_request(
    proxy: Arc<ferrum_edge::config::types::Proxy>,
    source: &str,
) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    let identity = SpiffeId::new(source).expect("spiffe");
    ctx.peer_spiffe_id = Some(identity.clone());
    ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        identity,
        DEFAULT_NAMESPACE,
        HashMap::from([("app".to_string(), "client".to_string())]),
    )));
    ctx.matched_proxy = Some(proxy);
    ctx
}

/// End to end: a destination policy on `app=reviews` applies on the
/// VirtualService route that reaches `reviews` and not on a route that does
/// not, on a NodeWaypoint built from its slice.
#[tokio::test]
async fn route_scoped_destination_policy_applies_only_to_its_route_on_node_waypoint() {
    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);
    let runtime = node_waypoint_runtime();
    let slice = node_waypoint_slice(&config, &runtime);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    let authz_config = &prepared
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz injected")
        .config;
    let authz = MeshAuthz::new(authz_config).expect("mesh_authz builds");

    let route_upstream = carried_ids(&slice.http_routes.upstreams).remove(0);
    let split_route = Arc::new(
        prepared
            .proxies
            .iter()
            .find(|proxy| proxy.upstream_id.as_deref() == Some(route_upstream.as_str()))
            .expect("the split route is served")
            .clone(),
    );
    let details_route = Arc::new(
        prepared
            .proxies
            .iter()
            .find(|proxy| {
                proxy.namespace == DEFAULT_NAMESPACE
                    && proxy
                        .upstream_id
                        .as_deref()
                        .is_some_and(|id| id.contains("details"))
            })
            .expect("the details Service route is materialized")
            .clone(),
    );

    let mut trusted = node_waypoint_request(Arc::clone(&split_route), TRUSTED);
    let result = authz.authorize(&mut trusted).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "the route's upstream resolves to its destinations, got {result:?}"
    );
    assert_eq!(
        trusted
            .metadata
            .get("mesh_authz.node_waypoint_authorized_upstream_id")
            .map(String::as_str),
        Some(route_upstream.as_str())
    );

    let mut untrusted = node_waypoint_request(Arc::clone(&split_route), UNTRUSTED);
    match authz.authorize(&mut untrusted).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("the reviews policy applies on its route, got {other:?}"),
    }

    let mut other_route = node_waypoint_request(details_route, UNTRUSTED);
    let result = authz.authorize(&mut other_route).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "the reviews policy does not apply on an unrelated route, got {result:?}"
    );
}

#[test]
fn mesh_config_binding_rejects_a_non_route_proxy_id() {
    let config = MeshConfig {
        virtual_service_http_routes: vec![
            ferrum_edge::modes::mesh::config::MeshVirtualServiceHttpRoutes {
                name: "split".to_string(),
                namespace: DEFAULT_NAMESPACE.to_string(),
                export_to: vec!["*".to_string()],
                proxy_ids: vec!["operator-route".to_string()],
            },
        ],
        ..MeshConfig::default()
    };
    assert!(
        config
            .validate()
            .iter()
            .any(|error| error.contains("virtual_service_http_routes[0]")),
        "a binding may only name VirtualService HTTP route proxies"
    );
}

fn destination_rule(name: &str, host: &str, simple_lb: &str) -> K8sObject {
    let mut object = virtual_service(
        name,
        json!({
            "host": host,
            "trafficPolicy": {"loadBalancer": {"simple": simple_lb}}
        }),
    );
    object.kind = "DestinationRule".to_string();
    object
}

fn carried_route_proxies(config: &GatewayConfig) -> Vec<&ferrum_edge::config::types::Proxy> {
    config
        .proxies
        .iter()
        .filter(|proxy| proxy.id.starts_with("istio-vs-") && !proxy.id.starts_with("istio-vs-l4_"))
        .collect()
}

/// Review finding sol F1: a carried split must dial the destination workloads
/// over the NodeWaypoint mesh transport, like the materialized Service route it
/// shadows, never the Service DNS name over plain HTTP.
#[test]
fn carried_split_dials_the_service_workloads_not_the_service_dns_name() {
    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);
    let runtime = node_waypoint_runtime();
    let slice = node_waypoint_slice(&config, &runtime);
    let split_id = carried_ids(&slice.http_routes.upstreams).remove(0);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    let split = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == split_id)
        .expect("split upstream served");
    let mut hosts: Vec<&str> = split
        .targets
        .iter()
        .map(|target| target.host.as_str())
        .collect();
    hosts.sort_unstable();
    assert_eq!(hosts, vec!["10.0.0.11", "10.0.0.12"]);
    for target in &split.targets {
        assert!(
            target
                .tags
                .contains_key(ferrum_edge::config::types::UPSTREAM_TARGET_SERVICE_NAME_TAG),
            "each rebound target keeps its Service attribution"
        );
        assert_eq!(target.service_port_policy_key, Some(8080));
    }
}

/// Review finding sol F1: a single-destination route uses the Service port's
/// materialized upstream.
#[test]
fn carried_direct_route_uses_the_materialized_service_upstream() {
    let config = translated_config(&[virtual_service(
        "direct",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "route": [{
                    "destination": {
                        "host": "reviews.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }
                }]
            }]
        }),
    )]);
    let runtime = node_waypoint_runtime();
    let slice = node_waypoint_slice(&config, &runtime);
    assert!(!slice.http_routes.proxies.is_empty());
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    let routes = carried_route_proxies(&prepared);
    assert!(!routes.is_empty(), "the VirtualService route is served");
    for route in routes {
        let upstream_id = route
            .upstream_id
            .as_deref()
            .expect("the route is bound to an upstream");
        assert!(upstream_id.starts_with("__mesh-out"), "got {upstream_id:?}");
        assert!(upstream_id.contains("reviews"));
    }
}

/// Review finding sol F1 / dsf F3: a destination the waypoint cannot reach
/// over its mesh transport refuses the route instead of dialing it in the
/// clear, and the Service keeps its materialized route.
#[test]
fn a_route_to_an_unmodeled_cluster_service_is_refused() {
    let config = translated_config(&[virtual_service(
        "missing",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "route": [{
                    "destination": {
                        "host": "missing.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }
                }]
            }]
        }),
    )]);
    let runtime = node_waypoint_runtime();
    let slice = node_waypoint_slice(&config, &runtime);
    assert!(!slice.http_routes.proxies.is_empty());
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    assert!(carried_route_proxies(&prepared).is_empty());
    assert!(
        prepared.proxies.iter().any(|proxy| {
            proxy
                .upstream_id
                .as_deref()
                .is_some_and(|id| id.starts_with("__mesh-out") && id.contains("reviews"))
        }),
        "the Service route is materialized again"
    );
}

/// Review findings dsf F2 (round 1) and sol F2 (round 2), resolved by issue
/// #7387: a split across Services that DestinationRules govern is served,
/// and each leg is dispatched through its own Service's upstream (which
/// carries its rule) instead of the split's workload targets. See
/// `weighted_split_legs` for the per-leg policy, ratio and authorization
/// coverage.
#[test]
fn a_split_across_destination_rule_governed_services_is_dispatched_leg_by_leg() {
    let config = translated_config(&[
        virtual_service("split", split_spec(json!({}))),
        destination_rule("reviews-dr", "reviews.default.svc.cluster.local", "RANDOM"),
        destination_rule(
            "ratings-dr",
            "ratings.default.svc.cluster.local",
            "ROUND_ROBIN",
        ),
    ]);
    let runtime = node_waypoint_runtime();
    let slice = node_waypoint_slice(&config, &runtime);
    assert_eq!(slice.destination_rules.len(), 2);
    let split_id = carried_ids(&slice.http_routes.upstreams).remove(0);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    let routes = carried_route_proxies(&prepared);
    assert_eq!(routes.len(), 1, "the split route is served");
    assert_eq!(routes[0].upstream_id.as_deref(), Some(split_id.as_str()));
    let legs: Vec<&str> = prepared
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .filter_map(|plugin| plugin.config.get("weighted_splits"))
        .flat_map(|splits| splits.as_array().into_iter().flatten())
        .filter(|split| split["upstream_id"] == json!(split_id))
        .flat_map(|split| split["legs"].as_array().into_iter().flatten())
        .filter_map(|leg| leg["upstream_id"].as_str())
        .collect();
    assert_eq!(
        legs,
        vec![
            "__mesh-out-upstream-default-reviews-8080",
            "__mesh-out-upstream-default-ratings-8080"
        ]
    );
}

fn add_reviews_replica(config: &mut GatewayConfig, address: &'static str) {
    let replica = workload_for(
        "reviews-replica",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        [address],
    );
    let mesh = config.mesh.as_mut().expect("mesh block");
    let reviews = mesh
        .services
        .iter_mut()
        .find(|service| service.name == "reviews")
        .expect("reviews service");
    reviews.workloads.push(WorkloadRef {
        spiffe_id: replica.spiffe_id.clone(),
    });
    mesh.workloads.push(replica);
}

fn split_target_weights(prepared: &GatewayConfig, split_id: &str) -> HashMap<String, u32> {
    prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == split_id)
        .expect("split served")
        .targets
        .iter()
        .map(|target| (target.host.clone(), target.weight))
        .collect()
}

/// Review findings sol F3 / dsf F2 (round 2): unequal leg weights keep their
/// ratio across one common scale, and a leg's share is divided across its
/// workloads.
#[test]
fn split_weights_keep_the_configured_ratio_across_legs_and_workloads() {
    let mut spec = split_spec(json!({}));
    spec["http"][0]["route"][0]["weight"] = json!(90);
    spec["http"][0]["route"][1]["weight"] = json!(10);
    let mut config = translated_config(&[virtual_service("split", spec)]);
    add_reviews_replica(&mut config, "10.0.0.21");
    let runtime = node_waypoint_runtime();
    let slice = node_waypoint_slice(&config, &runtime);
    let split_id = carried_ids(&slice.http_routes.upstreams).remove(0);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    let weights = split_target_weights(&prepared, &split_id);
    let reviews = f64::from(weights["10.0.0.11"]) + f64::from(weights["10.0.0.21"]);
    let ratings = f64::from(weights["10.0.0.12"]);
    assert_eq!(
        weights["10.0.0.11"], weights["10.0.0.21"],
        "a leg's share is split evenly across its workloads"
    );
    let ratio = reviews / ratings;
    assert!(
        (ratio - 9.0).abs() < 0.01,
        "90/10 must stay 9:1 across the legs, got {ratio}"
    );
}

/// Review findings sol F3 / dsf F2 (round 2): an external leg is scaled with
/// the in-mesh legs, so a 50/50 split stays 50/50.
#[test]
fn a_mixed_internal_and_external_split_keeps_its_ratio() {
    let mut spec = split_spec(json!({}));
    spec["http"][0]["route"][1]["destination"] = json!({
        "host": "api.example.com",
        "port": {"number": 443}
    });
    let config = translated_config(&[virtual_service("split", spec)]);
    let runtime = node_waypoint_runtime();
    let slice = node_waypoint_slice(&config, &runtime);
    let split_id = carried_ids(&slice.http_routes.upstreams).remove(0);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    let weights = split_target_weights(&prepared, &split_id);
    assert_eq!(weights.len(), 2, "one workload and one external target");
    assert_eq!(
        weights["10.0.0.11"], weights["api.example.com"],
        "50/50 between a Service and an external host stays 50/50"
    );
}

/// Review findings sol F4 / dsf F3 (round 2): a split with an unreachable leg
/// is refused and its upstream pruned, so the Services' distinct
/// DestinationRules cannot refuse the whole slice through the leftover.
#[test]
fn an_unreachable_split_leg_refuses_the_route_and_prunes_the_split() {
    let mut config = translated_config(&[
        virtual_service("split", split_spec(json!({}))),
        destination_rule("reviews-dr", "reviews.default.svc.cluster.local", "RANDOM"),
        destination_rule(
            "ratings-dr",
            "ratings.default.svc.cluster.local",
            "ROUND_ROBIN",
        ),
    ]);
    let mesh = config.mesh.as_mut().expect("mesh block");
    for workload in &mut mesh.workloads {
        if workload.service_name == "ratings" {
            workload.addresses.clear();
        }
    }
    let runtime = node_waypoint_runtime();
    let slice = node_waypoint_slice(&config, &runtime);
    let split_id = carried_ids(&slice.http_routes.upstreams).remove(0);
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("the slice materializes without the refused split");
    assert!(carried_route_proxies(&prepared).is_empty());
    assert!(
        !prepared
            .upstreams
            .iter()
            .any(|upstream| upstream.id == split_id)
    );
}

/// Review finding sol F1 (round 2): a two-label `<svc>.<ns>` alias of a Service
/// the slice does not model is refused, never dialed as an external host.
#[test]
fn a_two_label_alias_of_an_unmodeled_service_is_refused() {
    for host in ["missing.default", "ratings.other"] {
        let config = translated_config(&[virtual_service(
            "alias",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [{
                    "route": [{
                        "destination": {"host": host, "port": {"number": 8080}}
                    }]
                }]
            }),
        )]);
        let runtime = node_waypoint_runtime();
        let slice = node_waypoint_slice(&config, &runtime);
        assert!(!slice.http_routes.proxies.is_empty(), "{host}");
        let prepared =
            prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
        assert!(carried_route_proxies(&prepared).is_empty(), "{host}");
    }
}

fn direct_route(hosts: serde_json::Value) -> serde_json::Value {
    json!({
        "hosts": hosts,
        "http": [{
            "route": [{
                "destination": {
                    "host": "reviews.default.svc.cluster.local",
                    "port": {"number": 8080}
                }
            }]
        }]
    })
}

/// Review finding dsf F1 (round 2): a carried route declaring a Service by
/// short name or by FQDN answers every spelling of that Service's host, like
/// the Service route it shadows.
#[test]
fn a_carried_route_answers_every_spelling_of_its_service_host() {
    for declared in ["reviews", "reviews.default.svc.cluster.local"] {
        let config =
            translated_config(&[virtual_service("direct", direct_route(json!([declared])))]);
        let runtime = node_waypoint_runtime();
        let slice = node_waypoint_slice(&config, &runtime);
        let prepared =
            prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
        let routes = carried_route_proxies(&prepared);
        assert!(!routes.is_empty(), "{declared}");
        for route in routes {
            for spelling in [
                "reviews",
                "reviews.default",
                "reviews.default.svc",
                "reviews.default.svc.cluster.local",
            ] {
                assert!(
                    route.hosts.iter().any(|host| host == spelling),
                    "declared {declared:?}: missing {spelling:?} in {:?}",
                    route.hosts
                );
            }
        }
    }
}

/// Review finding dsf F4 (round 2): a malformed or empty `spec.gateways` never
/// falls back to the `mesh` default.
#[test]
fn a_malformed_gateways_field_does_not_bind_the_mesh() {
    for gateways in [json!([]), json!("istio-system/public"), json!([7])] {
        let config = translated_config(&[virtual_service(
            "split",
            split_spec(json!({"gateways": gateways.clone()})),
        )]);
        let mesh = config.mesh.as_ref().expect("mesh block");
        assert!(
            mesh.virtual_service_http_routes.is_empty(),
            "gateways {gateways} must not bind the mesh"
        );
    }
}

// ---------------------------------------------------------------------------
// Sidecar projection (issue #7423). The Sidecar reuses the NodeWaypoint route
// machinery; only the transport (per-workload SVID-mTLS) and the listener the
// routes are served on (outbound capture only) differ.
// ---------------------------------------------------------------------------

fn sidecar_runtime() -> MeshRuntimeConfig {
    runtime_for_topology(MeshTopology::Sidecar)
}

fn sidecar_slice(config: &GatewayConfig, runtime: &MeshRuntimeConfig) -> MeshSlice {
    MeshSlice::from_gateway_config(config, runtime.mesh_slice_request())
}

/// A Sidecar whose own workload is the `workload` fixture (`app=<workload>`).
fn sidecar_runtime_for(workload: &str) -> MeshRuntimeConfig {
    let mut runtime = sidecar_runtime();
    runtime.workload_spiffe_id = Some(format!("spiffe://cluster.local/ns/default/sa/{workload}"));
    runtime.workload_labels = HashMap::from([("app".to_string(), workload.to_string())]);
    runtime
}

fn prepared_sidecar(config: &GatewayConfig, runtime: &MeshRuntimeConfig) -> GatewayConfig {
    prepare_gateway_config_from_mesh_slice(&sidecar_slice(config, runtime), runtime)
        .expect("slice materializes")
}

/// The proxy a request for `authority` (`host[:port]`) + `path` resolves to
/// on a listener of `direction`, the way the request frontends resolve it.
fn routed_proxy_id(
    prepared: &GatewayConfig,
    authority: &str,
    path: &str,
    direction: Option<MeshTrafficDirection>,
) -> Option<String> {
    let (host, authority_port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port.parse::<u16>().expect("authority port"))),
        None => (authority, None),
    };
    let cache = RouterCache::new(prepared, 1024);
    match cache.resolve_mesh_scoped_route_for_test(
        Some(host),
        path,
        None,
        false,
        MeshRouteScope {
            direction,
            authority_port,
            ..MeshRouteScope::default()
        },
    ) {
        MeshScopedResolution::Routed(route) => Some(route.route_match().proxy.id.clone()),
        MeshScopedResolution::NotFound | MeshScopedResolution::Refused => None,
    }
}

fn ninety_ten_split_spec() -> serde_json::Value {
    let mut spec = split_spec(json!({}));
    spec["http"][0]["route"][0]["weight"] = json!(90);
    spec["http"][0]["route"][1]["weight"] = json!(10);
    spec
}

#[test]
fn sidecar_requests_and_receives_bound_routes_their_plugins_and_upstreams() {
    let runtime = sidecar_runtime();
    let request = runtime.mesh_slice_request();
    assert!(request.sidecar_http_routes, "a Sidecar asks for the routes");
    assert!(!request.node_waypoint_capture_scoping);

    let config = translated_config(&[virtual_service("split", guarded_split_spec())]);
    let slice = sidecar_slice(&config, &runtime);
    let proxy_ids = carried_ids(&slice.http_routes.proxies);
    assert!(
        !proxy_ids.is_empty(),
        "the Sidecar slice carries the routes"
    );
    assert!(proxy_ids.iter().all(|id| id.starts_with("istio-vs-")));
    let upstream_ids = carried_ids(&slice.http_routes.upstreams);
    assert_eq!(
        upstream_ids.len(),
        1,
        "the weighted split upstream rides along"
    );
    assert!(
        slice.http_routes.plugin_configs.iter().any(|plugin| {
            plugin
                .get("plugin_name")
                .and_then(serde_json::Value::as_str)
                == Some("mesh_route_dispatch")
        }),
        "the route's match dispatch rules ride along"
    );

    // The same projection a NodeWaypoint gets: one implementation.
    let node_waypoint = node_waypoint_slice(&config, &node_waypoint_runtime());
    assert_eq!(slice.http_routes, node_waypoint.http_routes);

    // A request without the flag (Ambient-shaped) gets nothing.
    let unflagged = MeshSliceRequest {
        sidecar_http_routes: false,
        ..runtime.mesh_slice_request()
    };
    assert!(
        MeshSlice::from_gateway_config(&config, unflagged)
            .http_routes
            .is_empty()
    );
}

#[test]
fn sidecar_routes_honour_export_to_and_round_trip_both_wires() {
    let hidden = translated_config(&[virtual_service(
        "split",
        split_spec(json!({"exportTo": ["other"]})),
    )]);
    assert!(
        sidecar_slice(&hidden, &sidecar_runtime())
            .http_routes
            .is_empty(),
        "a VirtualService not exported to the Sidecar's namespace is not served"
    );

    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);
    let slice = sidecar_slice(&config, &sidecar_runtime());
    let native: MeshSlice =
        serde_json::from_value(serde_json::to_value(&slice).expect("serialize"))
            .expect("native slice JSON decodes");
    assert!(native.content_eq(&slice));
    let carrier = build_slice_carriers(&slice)
        .into_iter()
        .find(|carrier| matches!(carrier, MeshSliceCarrier::HttpRoutes(_)))
        .expect("xDS emits the HTTP route carrier for a Sidecar slice");
    let bytes = carrier.encode_value().expect("encode");
    assert_eq!(
        MeshSliceCarrier::decode(carrier.type_url(), &bytes)
            .expect("decode")
            .expect("recognized carrier"),
        MeshSliceCarrier::HttpRoutes(slice.http_routes.clone())
    );
}

/// The Sidecar rebinds a carried split onto its own mesh transport: each leg
/// becomes the destination Service's workloads over pinned SVID-mTLS, never
/// the Service DNS name over plain HTTP, and the shadowed Service keeps its
/// materialized upstream while its route yields to the VirtualService route.
#[test]
fn sidecar_split_dials_the_service_workloads_over_svid_mtls() {
    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);
    let runtime = sidecar_runtime();
    let slice = sidecar_slice(&config, &runtime);
    let split_id = carried_ids(&slice.http_routes.upstreams).remove(0);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");

    let routes = carried_route_proxies(&prepared);
    assert_eq!(routes.len(), 1, "the VirtualService route is served");
    assert_eq!(routes[0].upstream_id.as_deref(), Some(split_id.as_str()));
    let split = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == split_id)
        .expect("split upstream served");
    let mut hosts: Vec<&str> = split
        .targets
        .iter()
        .map(|target| target.host.as_str())
        .collect();
    hosts.sort_unstable();
    assert_eq!(hosts, vec!["10.0.0.11", "10.0.0.12"]);
    for target in &split.targets {
        assert_eq!(
            target
                .tags
                .get(ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG)
                .map(String::as_str),
            Some("true"),
            "every leg rides the Sidecar SVID-mTLS transport"
        );
        assert!(
            target.tags.contains_key("mesh.spiffe_id"),
            "every leg pins the destination workload identity"
        );
        assert_eq!(target.service_port_policy_key, Some(8080));
    }

    assert!(
        prepared
            .upstreams
            .iter()
            .any(|upstream| upstream.id == "__mesh-out-upstream-default-reviews-8080"),
        "the shadowed Service keeps its materialized upstream"
    );
    assert!(
        !prepared
            .proxies
            .iter()
            .any(|proxy| proxy.id == "__mesh-outbound-default-reviews-8080"),
        "the Service route yields to the VirtualService route on the same host and path"
    );
    assert!(
        prepared
            .proxies
            .iter()
            .any(|proxy| proxy.id == "__mesh-outbound-default-ratings-8080"),
        "a Service no route shadows keeps its own route"
    );
    prepared
        .validate_unique_listen_paths()
        .expect("carried and materialized routes do not collide");

    // Review finding sol F2 / dsf F1: each leg presents its own destination
    // Service as the `:authority` (never the pod address, never the
    // VirtualService host), and the destination Sidecar routes it to that
    // Service's inbound route.
    for target in &split.targets {
        let service = target
            .tags
            .get(UPSTREAM_TARGET_SERVICE_NAME_TAG)
            .expect("each leg names its Service")
            .clone();
        let authority = mesh_mtls_dispatch_authority_for_test(
            target,
            routes[0].preserve_host_header,
            Some("reviews.default.svc.cluster.local"),
        );
        assert_eq!(
            authority,
            format!("{service}.default.svc:8080"),
            "leg {service} presents its own Service host and port"
        );
        let destination = prepared_sidecar(&config, &sidecar_runtime_for(&service));
        assert_eq!(
            routed_proxy_id(
                &destination,
                &authority,
                "/",
                Some(MeshTrafficDirection::Inbound)
            )
            .as_deref(),
            Some(format!("__mesh-inbound-default-{service}-8080").as_str()),
            "the {service} Sidecar serves what the client leg sends"
        );
    }
}

/// Review findings sol F2 / dsf F1 (rounds 1 and 2): a direct route to
/// another Service dials a route-scoped clone of that Service's upstream,
/// whose targets present that Service's host and port. The shared Service
/// upstream is untouched, so plain Service traffic keeps the client `Host`
/// and port exactly as before.
#[test]
fn sidecar_direct_route_presents_the_destination_service_authority() {
    let config = translated_config(&[virtual_service(
        "direct",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "route": [{
                    "destination": {
                        "host": "ratings.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }
                }]
            }]
        }),
    )]);
    let prepared = prepared_sidecar(&config, &sidecar_runtime());
    let routes = carried_route_proxies(&prepared);
    assert_eq!(routes.len(), 1, "the VirtualService route is served");
    let upstream_id = routes[0]
        .upstream_id
        .as_deref()
        .expect("the route is bound to an upstream");
    assert_eq!(upstream_id, "__mesh-out-vs-upstream-default-ratings-8080");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == upstream_id)
        .expect("the route-scoped ratings upstream is materialized");
    assert!(!upstream.targets.is_empty());
    for target in &upstream.targets {
        let authority = mesh_mtls_dispatch_authority_for_test(
            target,
            routes[0].preserve_host_header,
            Some("reviews.default.svc.cluster.local"),
        );
        assert_eq!(authority, "ratings.default.svc:8080");
    }

    // Plain Service traffic to the same destination keeps the client Host.
    let service_route = prepared
        .proxies
        .iter()
        .find(|proxy| proxy.id == "__mesh-outbound-default-ratings-8080")
        .expect("the ratings Service route is served");
    assert_eq!(
        service_route.upstream_id.as_deref(),
        Some("__mesh-out-upstream-default-ratings-8080")
    );
    let shared = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == "__mesh-out-upstream-default-ratings-8080")
        .expect("the shared ratings upstream is materialized");
    for target in &shared.targets {
        assert!(
            !target.tags.contains_key("mesh.mtls_authority_host"),
            "the shared Service upstream is never stamped"
        );
        assert_eq!(
            mesh_mtls_dispatch_authority_for_test(
                target,
                service_route.preserve_host_header,
                Some("ratings.default.svc.cluster.local:8080"),
            ),
            "ratings.default.svc.cluster.local:8080",
            "plain Service traffic keeps the client Host and port"
        );
    }
}

/// Review finding sol F2 (round 2): the source's egress view can import one
/// port of a destination that serves several. The carried route still
/// presents the selected Service port, so the destination Sidecar, which
/// sees every port, routes it to that port's inbound route.
#[test]
fn sidecar_carried_route_presents_the_service_port_of_a_narrowed_multi_port_destination() {
    let mut config = translated_config(&[virtual_service(
        "direct",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "route": [{
                    "destination": {
                        "host": "ratings.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }
                }]
            }]
        }),
    )]);
    let mesh = config.mesh.as_mut().expect("mesh block");
    let ratings = mesh
        .services
        .iter_mut()
        .find(|service| service.name == "ratings")
        .expect("ratings service");
    ratings.ports.push(ServicePort {
        port: 9090,
        protocol: AppProtocol::Http,
        name: Some("http-alt".to_string()),
        target_port: None,
    });
    mesh.workloads
        .iter_mut()
        .find(|workload| workload.service_name == "ratings")
        .expect("ratings workload")
        .ports
        .push(WorkloadPort {
            port: 9090,
            protocol: AppProtocol::Http,
            name: Some("http-alt".to_string()),
        });

    // The client's egress scope imports ratings:8080 only.
    let runtime = sidecar_runtime();
    let mut slice = sidecar_slice(&config, &runtime);
    slice
        .services
        .iter_mut()
        .find(|service| service.name == "ratings")
        .expect("ratings imported")
        .ports
        .retain(|port| port.port == 8080);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    let routes = carried_route_proxies(&prepared);
    assert_eq!(routes.len(), 1, "the VirtualService route is served");
    let upstream_id = routes[0].upstream_id.as_deref().expect("bound upstream");
    let target = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == upstream_id)
        .and_then(|upstream| upstream.targets.first())
        .expect("a ratings target");
    let authority = mesh_mtls_dispatch_authority_for_test(
        target,
        routes[0].preserve_host_header,
        Some("reviews.default.svc.cluster.local"),
    );
    assert_eq!(authority, "ratings.default.svc:8080");

    let destination = prepared_sidecar(&config, &sidecar_runtime_for("ratings"));
    assert_eq!(
        routed_proxy_id(
            &destination,
            &authority,
            "/",
            Some(MeshTrafficDirection::Inbound)
        )
        .as_deref(),
        Some("__mesh-inbound-default-ratings-8080"),
        "the two-port destination routes the presented port"
    );
    assert_eq!(
        routed_proxy_id(
            &destination,
            "ratings.default.svc",
            "/",
            Some(MeshTrafficDirection::Inbound)
        ),
        None,
        "without the port the two-port destination cannot pick a route"
    );
}

fn authority_rewrite_spec(authority: &str) -> serde_json::Value {
    json!({
        "hosts": ["reviews.default.svc.cluster.local"],
        "http": [{
            "match": [{"uri": {"prefix": "/api"}}],
            "rewrite": {"authority": authority},
            "route": [{
                "destination": {
                    "host": "ratings.default.svc.cluster.local",
                    "port": {"number": 8080}
                }
            }]
        }]
    })
}

/// Review finding sol F3 (round 2): an explicit `rewrite.authority` that
/// names the selected destination reaches dispatch unchanged (the destination
/// stamp does not override it); one the destination cannot route refuses the
/// route instead of being silently mis-sent.
#[tokio::test]
async fn sidecar_authority_rewrite_reaches_dispatch_unchanged() {
    const REWRITTEN: &str = "ratings.default.svc.cluster.local:8080";
    let config = translated_config(&[virtual_service("api", authority_rewrite_spec(REWRITTEN))]);
    let prepared = prepared_sidecar(&config, &sidecar_runtime_for("details"));
    let routes = carried_route_proxies(&prepared);
    assert_eq!(routes.len(), 1, "an admitted authority rewrite is served");
    let route = routes[0].clone();
    let dispatch = prepared
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.proxy_id.as_deref() == Some(route.id.as_str())
        })
        .expect("the rewrite rides a dispatch rule");
    let mut plugins = vec![
        create_plugin("mesh_route_dispatch", &dispatch.config)
            .expect("dispatch config constructs")
            .expect("built-in plugin"),
    ];
    install_plugin_finalizers_for_test(&mut plugins).expect("chain assembles");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/users".to_string(),
    );
    ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
    ctx.matched_proxy = Some(Arc::new(route.clone()));
    let mut headers = HashMap::from([(
        "host".to_string(),
        "reviews.default.svc.cluster.local".to_string(),
    )]);
    ctx.headers = headers.clone();
    let result = run_before_proxy_hooks_for_test(&plugins, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let selected = ctx
        .route_override_upstream_id
        .clone()
        .expect("the rule selects its destination");
    assert_eq!(selected, "__mesh-out-vs-rw-upstream-default-ratings-8080");
    let target = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == selected)
        .and_then(|upstream| upstream.targets.first())
        .expect("a ratings target");
    // The rewrite flips host preservation on the effective proxy.
    let preserve = route.preserve_host_header || ctx.route_override_authority.is_some();
    assert_eq!(
        mesh_mtls_dispatch_authority_for_test(
            target,
            preserve,
            headers.get("host").map(String::as_str)
        ),
        REWRITTEN
    );

    let foreign = translated_config(&[virtual_service(
        "api",
        authority_rewrite_spec("api.example.com"),
    )]);
    let prepared = prepared_sidecar(&foreign, &sidecar_runtime_for("details"));
    assert!(
        carried_route_proxies(&prepared).is_empty(),
        "a rewritten authority the destination cannot route refuses the route"
    );
}

/// Run the carried `/api` route's dispatch chain for `/api/users` with no peer
/// certificate (outbound capture) and return the `:authority` Sidecar mTLS
/// dispatch presents for the selected destination, with the selected upstream.
async fn rewritten_dispatch_authority(prepared: &GatewayConfig) -> (String, String) {
    let route = carried_route_proxies(prepared)
        .into_iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some("/api"))
        .expect("the /api route is served")
        .clone();
    let dispatch = prepared
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.proxy_id.as_deref() == Some(route.id.as_str())
        })
        .expect("the rewrite rides a dispatch rule");
    let mut plugins = vec![
        create_plugin("mesh_route_dispatch", &dispatch.config)
            .expect("dispatch config constructs")
            .expect("built-in plugin"),
    ];
    install_plugin_finalizers_for_test(&mut plugins).expect("chain assembles");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/users".to_string(),
    );
    ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
    ctx.matched_proxy = Some(Arc::new(route.clone()));
    let mut headers = HashMap::from([(
        "host".to_string(),
        "reviews.default.svc.cluster.local".to_string(),
    )]);
    ctx.headers = headers.clone();
    let result = run_before_proxy_hooks_for_test(&plugins, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let selected = ctx
        .route_override_upstream_id
        .clone()
        .expect("the rule selects its destination");
    let target = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == selected)
        .and_then(|upstream| upstream.targets.first())
        .expect("a destination target");
    // The rewrite flips host preservation on the effective proxy.
    let preserve = route.preserve_host_header || ctx.route_override_authority.is_some();
    let authority = mesh_mtls_dispatch_authority_for_test(
        target,
        preserve,
        headers.get("host").map(String::as_str),
    );
    (authority, selected)
}

fn add_second_ratings_port(config: &mut GatewayConfig) {
    let mesh = config.mesh.as_mut().expect("mesh block");
    mesh.services
        .iter_mut()
        .find(|service| service.name == "ratings")
        .expect("ratings service")
        .ports
        .push(ServicePort {
            port: 9090,
            protocol: AppProtocol::Http,
            name: Some("http-alt".to_string()),
            target_port: None,
        });
    mesh.workloads
        .iter_mut()
        .find(|workload| workload.service_name == "ratings")
        .expect("ratings workload")
        .ports
        .push(WorkloadPort {
            port: 9090,
            protocol: AppProtocol::Http,
            name: Some("http-alt".to_string()),
        });
}

/// Review finding dsf F2 (round 3): a port-less `rewrite.authority` is
/// forwarded verbatim (no Service port appended) and the single-port
/// destination routes it. On a multi-port destination a port-less authority
/// could not pick a port, so the route is withheld instead of altered.
#[tokio::test]
async fn sidecar_portless_authority_rewrite_is_forwarded_verbatim() {
    const REWRITTEN: &str = "ratings.default.svc.cluster.local";
    let config = translated_config(&[virtual_service("api", authority_rewrite_spec(REWRITTEN))]);
    let prepared = prepared_sidecar(&config, &sidecar_runtime_for("details"));
    let (authority, selected) = rewritten_dispatch_authority(&prepared).await;
    assert_eq!(selected, "__mesh-out-vs-rw-upstream-default-ratings-8080");
    assert_eq!(
        authority, REWRITTEN,
        "the rewrite reaches dispatch unchanged"
    );
    let destination = prepared_sidecar(&config, &sidecar_runtime_for("ratings"));
    assert_eq!(
        routed_proxy_id(
            &destination,
            &authority,
            "/",
            Some(MeshTrafficDirection::Inbound)
        )
        .as_deref(),
        Some("__mesh-inbound-default-ratings-8080"),
        "the single-port destination routes the port-less authority"
    );

    // The same rewrite to a two-port destination cannot be routed without a
    // port, even when the client's egress view imports only one port.
    let mut multi_port = config.clone();
    add_second_ratings_port(&mut multi_port);
    let runtime = sidecar_runtime_for("details");
    let mut slice = sidecar_slice(&multi_port, &runtime);
    assert!(
        slice.http_routes.proxies.is_empty(),
        "the control plane withholds a port-less rewrite to a multi-port Service"
    );
    for service in &mut slice.services {
        if service.name == "ratings" {
            service.ports.retain(|port| port.port == 8080);
        }
    }
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    assert!(carried_route_proxies(&prepared).is_empty());
}

/// Review findings sol F1 / dsf F1 (round 3): the route-scoped clones share
/// the destination's `http2MaxRequests` lane with the Service route. With a
/// cap of 1, a request held on the plain Service route refuses both carried
/// variants (the stamped clone and the authority-rewrite clone), and releasing
/// it admits them again.
#[test]
fn sidecar_carried_route_clones_share_the_destination_active_request_lane() {
    let mut cap = virtual_service(
        "ratings-cap",
        json!({
            "host": "ratings.default.svc.cluster.local",
            "trafficPolicy": {"connectionPool": {"http": {"http2MaxRequests": 1}}}
        }),
    );
    cap.kind = "DestinationRule".to_string();
    let mut spec = authority_rewrite_spec("ratings.default.svc.cluster.local:8080");
    spec["http"].as_array_mut().expect("http").push(json!({
        "route": [{
            "destination": {
                "host": "ratings.default.svc.cluster.local",
                "port": {"number": 8080}
            }
        }]
    }));
    let config = translated_config(&[virtual_service("api", spec), cap]);
    let mut prepared = prepared_sidecar(&config, &sidecar_runtime_for("details"));
    // Publication normalizes the prepared generation (`update_config`).
    prepared.normalize_fields();

    let plain = prepared
        .proxies
        .iter()
        .find(|proxy| proxy.id == "__mesh-outbound-default-ratings-8080")
        .expect("the ratings Service route")
        .clone();
    let carried = carried_route_proxies(&prepared)
        .into_iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some("/"))
        .expect("the carried / route")
        .clone();
    assert_eq!(
        carried.upstream_id.as_deref(),
        Some("__mesh-out-vs-upstream-default-ratings-8080")
    );
    let api = carried_route_proxies(&prepared)
        .into_iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some("/api"))
        .expect("the carried /api route")
        .clone();
    let upstreams: HashMap<String, Arc<ferrum_edge::config::types::Upstream>> = prepared
        .upstreams
        .iter()
        .map(|upstream| {
            (
                namespaced_runtime_key(&upstream.namespace, &upstream.id),
                Arc::new(upstream.clone()),
            )
        })
        .collect();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/users".to_string(),
    );
    ctx.route_override_upstream_id =
        Some("__mesh-out-vs-rw-upstream-default-ratings-8080".to_string());
    let rewritten = ctx.apply_route_overrides_with_upstreams(Arc::new(api), &upstreams);
    assert_eq!(
        rewritten.upstream_id.as_deref(),
        Some("__mesh-out-vs-rw-upstream-default-ratings-8080")
    );

    let limiter = BackendActiveRequestLimiter::new();
    let held = try_acquire_destination_active_request_for_test(&limiter, &plain, 8080)
        .expect("the first request is admitted")
        .expect("the DestinationRule cap applies to the Service route");
    try_acquire_destination_active_request_for_test(&limiter, &carried, 8080)
        .expect_err("the carried route shares the held lane");
    try_acquire_destination_active_request_for_test(&limiter, &rewritten, 8080)
        .expect_err("the authority-rewrite branch shares the held lane");
    drop(held);
    let carried_permit = try_acquire_destination_active_request_for_test(&limiter, &carried, 8080)
        .expect("the lane is free again")
        .expect("the DestinationRule cap applies to the carried route");
    try_acquire_destination_active_request_for_test(&limiter, &plain, 8080)
        .expect_err("a carried request holds the Service route's lane too");
    drop(carried_permit);
}

/// Add `other/ratings` to a Sidecar slice, as an egress scope importing it
/// would.
fn import_other_namespace_ratings(slice: &mut MeshSlice) {
    let workload = workload_for("ratings", "other", [("app", "ratings")], ["10.0.1.12"]);
    slice
        .services
        .push(service_for("ratings", "other", &[&workload]));
    slice.workloads.push(workload);
}

fn assert_references_resolve(prepared: &GatewayConfig) {
    prepared
        .validate_upstream_references()
        .expect("every proxy upstream reference resolves");
    validate_mesh_route_dispatch_upstream_references_for_test(prepared)
        .expect("every dispatch upstream reference resolves");
}

/// Review finding sol F1 (round 2): a carried route whose destination (direct
/// or a dispatch branch) is a Service in another namespace is refused, so no
/// dangling upstream reference reaches the generation and the rest of the
/// slice keeps serving.
#[test]
fn sidecar_refuses_cross_namespace_carried_destinations() {
    let runtime = sidecar_runtime();
    for (name, spec) in [
        (
            "direct",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [{
                    "route": [{
                        "destination": {
                            "host": "ratings.other.svc.cluster.local",
                            "port": {"number": 8080}
                        }
                    }]
                }]
            }),
        ),
        (
            "branch",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [
                    {
                        "match": [{
                            "uri": {"prefix": "/"},
                            "headers": {"x-version": {"exact": "v2"}}
                        }],
                        "route": [{
                            "destination": {
                                "host": "ratings.other.svc.cluster.local",
                                "port": {"number": 8080}
                            }
                        }]
                    },
                    {
                        "route": [{
                            "destination": {
                                "host": "details.default.svc.cluster.local",
                                "port": {"number": 8080}
                            }
                        }]
                    }
                ]
            }),
        ),
    ] {
        let config = translated_config(&[virtual_service(name, spec)]);
        let mut slice = sidecar_slice(&config, &runtime);
        assert!(!slice.http_routes.proxies.is_empty(), "{name}: carried");
        import_other_namespace_ratings(&mut slice);
        let prepared = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
            .expect("the slice still materializes");
        assert_references_resolve(&prepared);
        for route in carried_route_proxies(&prepared) {
            assert!(
                !route.backend_host.contains(".other."),
                "{name}: no surviving carried route dials another namespace"
            );
            assert!(
                route
                    .upstream_id
                    .as_deref()
                    .is_none_or(|id| !id.contains("-other-")),
                "{name}: no surviving carried route names another namespace's upstream"
            );
        }
        for plugin in prepared
            .plugin_configs
            .iter()
            .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        {
            assert!(
                !plugin.config.to_string().contains("ratings.other")
                    && !plugin.config.to_string().contains("-other-ratings-"),
                "{name}: no surviving dispatch rule names another namespace"
            );
        }
        assert!(
            prepared
                .proxies
                .iter()
                .any(|proxy| proxy.id == "__mesh-outbound-default-reviews-8080"),
            "{name}: the host keeps its Service route"
        );
    }
}

/// Issue #7499 (1.0 refusal): a weighted split with a leg in another
/// namespace and NO DestinationRule used to install that Service's workloads
/// in the route's own split upstream and serve them. Every cross-namespace
/// leg now refuses its split (and the routes naming it) before either
/// rebinding path is chosen, on Sidecar and NodeWaypoint, in either leg
/// order; the host keeps its Service route and the rest of the slice applies.
#[test]
fn a_split_with_a_leg_in_another_namespace_is_refused_without_a_destination_rule() {
    let foreign_leg = json!({
        "destination": {"host": "ratings.other.svc.cluster.local", "port": {"number": 8080}},
        "weight": 10
    });
    let local_leg = json!({
        "destination": {"host": "reviews.default.svc.cluster.local", "port": {"number": 8080}},
        "weight": 90
    });
    for (order, legs) in [
        (
            "local first",
            json!([local_leg.clone(), foreign_leg.clone()]),
        ),
        (
            "foreign first",
            json!([foreign_leg.clone(), local_leg.clone()]),
        ),
    ] {
        let config = translated_config(&[virtual_service(
            "split",
            json!({"hosts": ["reviews.default.svc.cluster.local"], "http": [{"route": legs}]}),
        )]);
        for (topology, runtime) in [
            ("Sidecar", sidecar_runtime()),
            ("NodeWaypoint", node_waypoint_runtime()),
        ] {
            let mut slice = MeshSlice::from_gateway_config(&config, runtime.mesh_slice_request());
            assert!(
                slice.destination_rules.is_empty(),
                "{order}/{topology}: no DestinationRule governs either leg"
            );
            assert!(
                !slice.http_routes.proxies.is_empty(),
                "{order}/{topology}: carried"
            );
            import_other_namespace_ratings(&mut slice);
            let prepared =
                prepare_gateway_config_from_mesh_slice(&slice, &runtime).unwrap_or_else(|error| {
                    panic!("{order}/{topology}: the slice still materializes: {error}")
                });
            assert_references_resolve(&prepared);
            assert!(
                carried_route_proxies(&prepared).is_empty(),
                "{order}/{topology}: the split route is refused"
            );
            assert!(
                !prepared.upstreams.iter().any(|upstream| {
                    upstream.id.starts_with("istio-vs-upstream-")
                        || (upstream.namespace == DEFAULT_NAMESPACE
                            && upstream
                                .targets
                                .iter()
                                .any(|target| target.host == "10.0.1.12"))
                }),
                "{order}/{topology}: no route-namespace upstream dials the other namespace"
            );
            assert!(
                prepared.proxies.iter().any(|proxy| {
                    proxy.namespace == DEFAULT_NAMESPACE
                        && proxy.upstream_id.as_deref().is_some_and(|id| {
                            id.starts_with("__mesh-out") && id.contains("reviews")
                        })
                }),
                "{order}/{topology}: the host keeps its Service route"
            );
        }
    }
}

/// Issue #7499 (1.0 refusal): a direct destination in another namespace is
/// refused on NodeWaypoint as on Sidecar (see
/// `sidecar_refuses_cross_namespace_carried_destinations`).
#[test]
fn node_waypoint_refuses_a_direct_destination_in_another_namespace() {
    let config = translated_config(&[virtual_service(
        "direct",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{"route": [{"destination": {
                "host": "ratings.other.svc.cluster.local",
                "port": {"number": 8080}
            }}]}]
        }),
    )]);
    let runtime = node_waypoint_runtime();
    let mut slice = node_waypoint_slice(&config, &runtime);
    assert!(!slice.http_routes.proxies.is_empty(), "carried");
    import_other_namespace_ratings(&mut slice);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    assert_references_resolve(&prepared);
    assert!(carried_route_proxies(&prepared).is_empty());
}

/// Issue #7423 acceptance: a 90/10 VirtualService split on a Sidecar sends
/// 90% of N requests to one leg and 10% to the other, through the production
/// load balancer over the prepared Sidecar config.
#[test]
fn sidecar_ninety_ten_split_dispatches_ninety_ten_over_n_requests() {
    let config = translated_config(&[virtual_service("split", ninety_ten_split_spec())]);
    let runtime = sidecar_runtime();
    let slice = sidecar_slice(&config, &runtime);
    let split_id = carried_ids(&slice.http_routes.upstreams).remove(0);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");

    let cache = ferrum_edge::LoadBalancerCache::new(&prepared);
    let snapshot = cache.load();
    const REQUESTS: usize = 1000;
    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..REQUESTS {
        let selection = ferrum_edge::LoadBalancerCache::select_target_from(
            &snapshot,
            DEFAULT_NAMESPACE,
            &split_id,
            "",
            None,
        )
        .expect("the split upstream selects a target");
        let service = selection
            .target
            .tags
            .get(ferrum_edge::config::types::UPSTREAM_TARGET_SERVICE_NAME_TAG)
            .cloned()
            .expect("each rebound target names its Service");
        *counts.entry(service).or_default() += 1;
    }
    let reviews = counts.get("reviews").copied().unwrap_or_default();
    let ratings = counts.get("ratings").copied().unwrap_or_default();
    assert_eq!(reviews + ratings, REQUESTS, "only the two legs are dialed");
    let reviews_share = reviews as f64 / REQUESTS as f64;
    assert!(
        (reviews_share - 0.9).abs() <= 0.02,
        "90/10 split sent {reviews}/{ratings} of {REQUESTS} requests"
    );
}

/// A split across DestinationRule-governed Services is dispatched leg by leg
/// on a Sidecar too (issue #7387 machinery), each leg the Service port's own
/// rule-bearing Sidecar upstream, with the configured 90/10 weights.
#[test]
fn sidecar_split_across_destination_rule_governed_services_is_dispatched_leg_by_leg() {
    let config = translated_config(&[
        virtual_service("split", ninety_ten_split_spec()),
        destination_rule("reviews-dr", "reviews.default.svc.cluster.local", "RANDOM"),
        destination_rule(
            "ratings-dr",
            "ratings.default.svc.cluster.local",
            "ROUND_ROBIN",
        ),
    ]);
    let runtime = sidecar_runtime();
    let slice = sidecar_slice(&config, &runtime);
    let split_id = carried_ids(&slice.http_routes.upstreams).remove(0);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    let legs: Vec<(String, u64)> = prepared
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .filter_map(|plugin| plugin.config.get("weighted_splits"))
        .flat_map(|splits| splits.as_array().into_iter().flatten())
        .filter(|split| split["upstream_id"] == json!(split_id))
        .flat_map(|split| split["legs"].as_array().into_iter().flatten())
        .filter_map(|leg| {
            Some((
                leg["upstream_id"].as_str()?.to_string(),
                leg["weight"].as_u64()?,
            ))
        })
        .collect();
    assert_eq!(
        legs,
        vec![
            (
                "__mesh-out-vs-upstream-default-reviews-8080".to_string(),
                90
            ),
            (
                "__mesh-out-vs-upstream-default-ratings-8080".to_string(),
                10
            ),
        ]
    );
    for (leg, _) in &legs {
        let upstream = prepared
            .upstreams
            .iter()
            .find(|upstream| &upstream.id == leg)
            .expect("each leg is a materialized Sidecar upstream");
        assert!(upstream.targets.iter().all(|target| {
            target
                .tags
                .get(ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG)
                .is_some_and(|value| value == "true")
        }));
    }
}

/// A Sidecar refuses a route that names an in-cluster Service its slice does
/// not model, exactly like a NodeWaypoint: it never dials a Service DNS name
/// in plaintext, and the Service keeps its materialized route.
#[test]
fn sidecar_refuses_a_route_to_an_unmodeled_cluster_service() {
    let config = translated_config(&[virtual_service(
        "missing",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "route": [{
                    "destination": {
                        "host": "missing.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }
                }]
            }]
        }),
    )]);
    let runtime = sidecar_runtime();
    let slice = sidecar_slice(&config, &runtime);
    assert!(!slice.http_routes.proxies.is_empty());
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    assert!(carried_route_proxies(&prepared).is_empty());
    assert!(
        prepared
            .proxies
            .iter()
            .any(|proxy| proxy.id == "__mesh-outbound-default-reviews-8080"),
        "the Service route is materialized again"
    );
}

/// Carried routes are client-side: served on the Sidecar's outbound capture
/// listener and on non-mesh listeners (gateway parity), never on an inbound
/// mesh listener, where a peer could otherwise name a routed host and have
/// this Sidecar dial it onward with its own identity.
#[test]
fn sidecar_carried_routes_are_never_served_on_the_inbound_listener() {
    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);
    let runtime = sidecar_runtime();
    let slice = sidecar_slice(&config, &runtime);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    let cache = RouterCache::new(&prepared, 1024);
    let host = Some("reviews.default.svc.cluster.local");
    let routed_id = |direction: Option<MeshTrafficDirection>| match cache
        .resolve_mesh_scoped_route_for_test(
            host,
            "/",
            None,
            false,
            MeshRouteScope {
                direction,
                ..MeshRouteScope::default()
            },
        ) {
        MeshScopedResolution::Routed(route) => Some(route.route_match().proxy.id.clone()),
        MeshScopedResolution::NotFound | MeshScopedResolution::Refused => None,
    };

    let outbound = routed_id(Some(MeshTrafficDirection::Outbound)).expect("outbound routes");
    assert!(
        outbound.starts_with("istio-vs-"),
        "the outbound capture leg applies the VirtualService route, got {outbound:?}"
    );
    let non_mesh = routed_id(None).expect("non-mesh listeners keep VirtualService routes");
    assert!(non_mesh.starts_with("istio-vs-"));
    assert!(
        routed_id(Some(MeshTrafficDirection::Inbound))
            .is_none_or(|id| !id.starts_with("istio-vs-")),
        "an inbound mesh listener must never serve a carried VirtualService route"
    );
}

/// A carried route claiming the local workload's own inbound route slot (same
/// namespace, path and host) is refused on a Sidecar: the local inbound route
/// keeps the slot and the slice still applies, instead of the listen-path
/// conflict refusing the whole generation.
#[test]
fn sidecar_refuses_a_carried_route_that_claims_the_local_inbound_route() {
    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);
    let mut runtime = sidecar_runtime();
    runtime.workload_spiffe_id = Some("spiffe://cluster.local/ns/default/sa/reviews".to_string());
    runtime.workload_labels = HashMap::from([("app".to_string(), "reviews".to_string())]);
    let slice = sidecar_slice(&config, &runtime);
    assert!(!slice.http_routes.proxies.is_empty());
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    assert!(
        prepared
            .proxies
            .iter()
            .any(|proxy| proxy.id == "__mesh-inbound-default-reviews-8080"),
        "the local reviews inbound route is served"
    );
    assert!(
        carried_route_proxies(&prepared).is_empty(),
        "the carried route claiming the local service's slot is refused"
    );
    prepared
        .validate_unique_listen_paths()
        .expect("no listen-path conflict reaches the generation");
    // Review finding sol F1: inbound serving still works.
    assert_eq!(
        routed_proxy_id(
            &prepared,
            "reviews.default.svc.cluster.local",
            "/",
            Some(MeshTrafficDirection::Inbound)
        )
        .as_deref(),
        Some("__mesh-inbound-default-reviews-8080")
    );
}

/// Review finding sol F3: a carried route on a longer prefix of the local
/// Service's host coexists with the local inbound `/` route. Refused on the
/// inbound listener, it must not hide that route: inbound requests under the
/// prefix still reach the local application, while the outbound leg applies
/// the VirtualService route.
#[test]
fn sidecar_inbound_falls_back_to_the_local_route_beneath_a_carried_prefix() {
    let config = translated_config(&[virtual_service(
        "api",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "match": [{"uri": {"prefix": "/api"}}],
                "route": [{
                    "destination": {
                        "host": "ratings.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }
                }]
            }]
        }),
    )]);
    let prepared = prepared_sidecar(&config, &sidecar_runtime_for("reviews"));
    let routes = carried_route_proxies(&prepared);
    assert_eq!(
        routes.len(),
        1,
        "the /api route coexists with the inbound /"
    );
    let carried = routes[0].id.clone();
    assert_eq!(
        routed_proxy_id(
            &prepared,
            "reviews.default.svc.cluster.local",
            "/api/users",
            Some(MeshTrafficDirection::Inbound)
        )
        .as_deref(),
        Some("__mesh-inbound-default-reviews-8080"),
        "inbound requests under the carried prefix reach the local route"
    );
    assert_eq!(
        routed_proxy_id(
            &prepared,
            "reviews.default.svc.cluster.local",
            "/api/users",
            Some(MeshTrafficDirection::Outbound)
        ),
        Some(carried),
        "the outbound leg applies the VirtualService route"
    );
}

/// Review finding sol F4: a split served on a Sidecar whose own workload backs
/// one of the legs keeps that leg. The local Service's route yields to its
/// inbound route, but its secured upstream stays for the carried split.
#[test]
fn sidecar_split_keeps_every_leg_whichever_destination_workload_calls() {
    let mut spec = ninety_ten_split_spec();
    spec["hosts"] = json!(["details.default.svc.cluster.local"]);
    let config = translated_config(&[virtual_service("split", spec)]);
    for client in ["reviews", "ratings"] {
        let runtime = sidecar_runtime_for(client);
        let slice = sidecar_slice(&config, &runtime);
        let split_id = carried_ids(&slice.http_routes.upstreams).remove(0);
        let prepared =
            prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
        assert!(
            prepared
                .proxies
                .iter()
                .any(|proxy| proxy.id == format!("__mesh-inbound-default-{client}-8080")),
            "{client}: the local inbound route is served"
        );
        let routes = carried_route_proxies(&prepared);
        assert_eq!(routes.len(), 1, "{client}: the split route is served");
        let weights = split_target_weights(&prepared, &split_id);
        let reviews = weights.get("10.0.0.11").copied().unwrap_or_default();
        let ratings = weights.get("10.0.0.12").copied().unwrap_or_default();
        assert!(
            reviews > 0 && ratings > 0,
            "{client}: both legs are dialed, got {weights:?}"
        );
        // One common scale keeps the configured ratio (not the raw weights).
        let ratio = f64::from(reviews) / f64::from(ratings);
        assert!(
            (ratio - 9.0).abs() < 0.01,
            "{client}: 90/10 must stay 9:1 across the legs, got {weights:?}"
        );
    }
}

fn source_namespace_spec(source_namespace: &str) -> serde_json::Value {
    json!({
        "hosts": ["reviews.default.svc.cluster.local"],
        "http": [{
            "match": [{"uri": {"prefix": "/api"}, "sourceNamespace": source_namespace}],
            "route": [{
                "destination": {
                    "host": "ratings.default.svc.cluster.local",
                    "port": {"number": 8080}
                }
            }]
        }]
    })
}

/// Review finding sol F5: a Sidecar's outbound capture leg carries no peer
/// SVID, so `sourceNamespace` is decided from the trusted local workload. A
/// rule naming the local namespace matches a request with no peer
/// certificate; a route whose rules name only other namespaces is refused.
#[tokio::test]
async fn sidecar_source_namespace_is_decided_from_the_local_workload() {
    let config = translated_config(&[virtual_service("api", source_namespace_spec("default"))]);
    let prepared = prepared_sidecar(&config, &sidecar_runtime_for("details"));
    let routes = carried_route_proxies(&prepared);
    assert_eq!(routes.len(), 1, "the local-namespace route is served");
    let route = routes[0].clone();
    let dispatch = prepared
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.proxy_id.as_deref() == Some(route.id.as_str())
        })
        .expect("the route keeps its dispatch instance");
    let rules = dispatch.config["rules"].as_array().expect("rules");
    assert!(!rules.is_empty(), "the local-namespace rule is kept");
    assert!(
        rules
            .iter()
            .all(|rule| rule["match"].get("source_namespace").is_none()),
        "the sourceNamespace predicate is resolved before serving: {rules:?}"
    );

    let mut plugins = vec![
        create_plugin("mesh_route_dispatch", &dispatch.config)
            .expect("dispatch config constructs")
            .expect("built-in plugin"),
    ];
    install_plugin_finalizers_for_test(&mut plugins).expect("chain assembles");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/users".to_string(),
    );
    ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
    ctx.matched_proxy = Some(Arc::new(route));
    assert!(
        ctx.peer_spiffe_id.is_none(),
        "outbound capture has no peer SVID"
    );
    let mut headers = HashMap::from([(
        "host".to_string(),
        "reviews.default.svc.cluster.local".to_string(),
    )]);
    ctx.headers = headers.clone();
    let result = run_before_proxy_hooks_for_test(&plugins, &mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "the matched rule dispatches"
    );
    assert_eq!(
        ctx.route_override_upstream_id.as_deref(),
        Some("__mesh-out-vs-upstream-default-ratings-8080")
    );

    let foreign = translated_config(&[virtual_service("api", source_namespace_spec("prod"))]);
    let prepared = prepared_sidecar(&foreign, &sidecar_runtime_for("details"));
    assert!(
        carried_route_proxies(&prepared).is_empty(),
        "a route that applies only to another source namespace is refused"
    );
    assert!(
        prepared
            .proxies
            .iter()
            .any(|proxy| proxy.id == "__mesh-outbound-default-reviews-8080"),
        "the host keeps its Service route"
    );
}

/// The upstream a carried route on `listen_path` dispatches a request for
/// `path` with `headers` to on a Sidecar's outbound capture leg (no peer
/// certificate): its `mesh_route_dispatch` instances run through the
/// production `before_proxy` chain, and a request no rule claims keeps the
/// route's own destination. `None` when the chain refuses the request.
async fn sidecar_dispatched_upstream(
    prepared: &GatewayConfig,
    listen_path: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Option<String> {
    sidecar_dispatch(prepared, listen_path, path, headers)
        .await
        .ok()
}

/// [`sidecar_dispatched_upstream`] with the refusal status: `Err(status)` when
/// the chain answers the request itself.
async fn sidecar_dispatch(
    prepared: &GatewayConfig,
    listen_path: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<String, u16> {
    let route = carried_route_proxies(prepared)
        .into_iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some(listen_path))
        .unwrap_or_else(|| panic!("the carried {listen_path} route is served"))
        .clone();
    let mut plugins: Vec<Arc<dyn Plugin>> = route
        .plugins
        .iter()
        .filter_map(|association| {
            prepared.plugin_configs.iter().find(|plugin| {
                plugin.namespace == route.namespace
                    && plugin.id == association.plugin_config_id
                    && plugin.plugin_name == "mesh_route_dispatch"
            })
        })
        .map(|plugin| {
            create_plugin("mesh_route_dispatch", &plugin.config)
                .expect("dispatch config constructs")
                .expect("built-in plugin")
        })
        .collect();
    install_plugin_finalizers_for_test(&mut plugins).expect("chain assembles");
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), path.to_string());
    ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
    ctx.matched_proxy = Some(Arc::new(route.clone()));
    let mut request_headers: HashMap<String, String> = headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    request_headers.insert(
        "host".to_string(),
        "reviews.default.svc.cluster.local".to_string(),
    );
    ctx.headers = request_headers.clone();
    match run_before_proxy_hooks_for_test(&plugins, &mut ctx, &mut request_headers).await {
        PluginResult::Continue => Ok(ctx
            .route_override_upstream_id
            .clone()
            .or_else(|| route.upstream_id.clone())
            .expect("the route has a destination")),
        PluginResult::Reject { status_code, .. }
        | PluginResult::RejectBinary { status_code, .. } => Err(status_code),
    }
}

fn route_to(host: &str) -> serde_json::Value {
    json!([{
        "destination": {
            "host": format!("{host}.default.svc.cluster.local"),
            "port": {"number": 8080}
        }
    }])
}

const SIDECAR_REVIEWS: &str = "__mesh-out-vs-upstream-default-reviews-8080";
const SIDECAR_RATINGS: &str = "__mesh-out-vs-upstream-default-ratings-8080";
const SIDECAR_DETAILS: &str = "__mesh-out-vs-upstream-default-details-8080";

/// Issue #7440: a `sourceNamespace` rule naming another namespace is removed
/// on a Sidecar, but the route keeps its unconditional fallback `http[]`
/// entry: requests reach the fallback destination, not the plain Service
/// route. A rule naming the Sidecar's own namespace matches every request.
#[tokio::test]
async fn sidecar_source_namespace_keeps_the_fallback_route() {
    for (source_namespace, expected) in
        [("other-ns", SIDECAR_REVIEWS), ("default", SIDECAR_RATINGS)]
    {
        let config = translated_config(&[virtual_service(
            "fallback",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [
                    {"match": [{"sourceNamespace": source_namespace}], "route": route_to("ratings")},
                    {"route": route_to("reviews")}
                ]
            }),
        )]);
        let prepared = prepared_sidecar(&config, &sidecar_runtime_for("details"));
        assert_eq!(
            sidecar_dispatched_upstream(&prepared, "/", "/anything", &[])
                .await
                .as_deref(),
            Some(expected),
            "sourceNamespace {source_namespace}"
        );
        assert!(
            !prepared
                .proxies
                .iter()
                .any(|proxy| proxy.id == "__mesh-outbound-default-reviews-8080"),
            "sourceNamespace {source_namespace}: the VirtualService still owns the host"
        );
    }
}

/// Issue #7440: ORed `match[]` entries are independent conditions. Removing
/// the foreign-namespace one keeps its URI-only sibling, so the route still
/// serves `/api`.
#[tokio::test]
async fn sidecar_source_namespace_keeps_a_uri_only_or_sibling() {
    let config = translated_config(&[virtual_service(
        "or",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "match": [
                    {"uri": {"prefix": "/api"}, "sourceNamespace": "other-ns"},
                    {"uri": {"prefix": "/api"}}
                ],
                "route": route_to("ratings")
            }]
        }),
    )]);
    let prepared = prepared_sidecar(&config, &sidecar_runtime_for("details"));
    assert_eq!(
        sidecar_dispatched_upstream(&prepared, "/api", "/api/users", &[])
            .await
            .as_deref(),
        Some(SIDECAR_RATINGS),
        "the URI-only sibling still routes /api"
    );
    prepared
        .validate_unique_listen_paths()
        .expect("the generation stays valid");
}

/// Issue #7440: a rule whose every ORed condition names another namespace is
/// removed whole, and the later fallback still serves; a removed condition
/// never widens into a match.
#[tokio::test]
async fn sidecar_source_namespace_rule_with_only_foreign_conditions_falls_back() {
    let config = translated_config(&[virtual_service(
        "foreign",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [
                {
                    "match": [{"sourceNamespace": "team-a"}, {"sourceNamespace": "team-b"}],
                    "route": route_to("ratings")
                },
                {"route": route_to("reviews")}
            ]
        }),
    )]);
    let prepared = prepared_sidecar(&config, &sidecar_runtime_for("details"));
    for path in ["/", "/api/users"] {
        assert_eq!(
            sidecar_dispatched_upstream(&prepared, "/", path, &[])
                .await
                .as_deref(),
            Some(SIDECAR_REVIEWS),
            "{path}: only the fallback applies"
        );
    }
}

/// Issue #7440: removing a foreign-namespace rule keeps the rules after it
/// and the fallback, in order.
#[tokio::test]
async fn sidecar_source_namespace_keeps_later_rules_and_the_fallback() {
    let config = translated_config(&[virtual_service(
        "ordered",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [
                {"match": [{"sourceNamespace": "other-ns"}], "route": route_to("ratings")},
                {
                    "match": [{"headers": {"x-version": {"exact": "v2"}}}],
                    "route": route_to("details")
                },
                {"route": route_to("reviews")}
            ]
        }),
    )]);
    let prepared = prepared_sidecar(&config, &sidecar_runtime_for("details"));
    assert_eq!(
        sidecar_dispatched_upstream(&prepared, "/", "/", &[("x-version", "v2")])
            .await
            .as_deref(),
        Some(SIDECAR_DETAILS),
        "the later header rule still matches"
    );
    assert_eq!(
        sidecar_dispatched_upstream(&prepared, "/", "/", &[])
            .await
            .as_deref(),
        Some(SIDECAR_REVIEWS),
        "an unmatched request takes the fallback, never the removed rule"
    );
}

/// Review finding neon F1 (#7443): `reject_unmatched` on a carried dispatch
/// instance is untrusted slice input. A present non-boolean value fails
/// closed: the instance is malformed, so the whole slice update is rejected
/// (sol F1, #7447) instead of the instance being detached to serve the
/// fallback.
#[test]
fn sidecar_source_namespace_fails_closed_on_a_malformed_reject_unmatched() {
    let config = translated_config(&[virtual_service(
        "or",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "match": [
                    {"uri": {"prefix": "/api"}, "sourceNamespace": "other-ns"},
                    {"uri": {"prefix": "/api"}}
                ],
                "route": route_to("ratings")
            }]
        }),
    )]);
    let runtime = sidecar_runtime_for("details");
    for (value, served) in [
        (json!(false), Some(true)),
        (json!("true"), None),
        (json!(1), None),
        (serde_json::Value::Null, None),
    ] {
        let mut slice = sidecar_slice(&config, &runtime);
        let mut patched = 0;
        for plugin in &mut slice.http_routes.plugin_configs {
            if plugin["plugin_name"] == json!("mesh_route_dispatch") {
                plugin["config"]["reject_unmatched"] = value.clone();
                patched += 1;
            }
        }
        assert_eq!(patched, 1, "the route carries one dispatch instance");
        // `None`: the slice update is rejected and the last generation serves.
        let api_served = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
            .ok()
            .map(|prepared| {
                carried_route_proxies(&prepared)
                    .iter()
                    .any(|proxy| proxy.listen_path.as_deref() == Some("/api"))
            });
        assert_eq!(api_served, served, "reject_unmatched = {value}");
    }
}

/// Review finding sol F2 (#7443 round 2): the miss policy of an emptied
/// dispatch instance is read with the plugin's own parser. A valid object that
/// omits `reject_unmatched` keeps its default and the route serves its
/// fallback; an unknown key such as `rejectUnmatched` (which the plugin would
/// refuse to construct) rejects the slice update instead of detaching the
/// instance.
#[test]
fn sidecar_source_namespace_parses_the_dispatch_miss_policy() {
    let config = translated_config(&[virtual_service(
        "or",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "match": [
                    {"uri": {"prefix": "/api"}, "sourceNamespace": "other-ns"},
                    {"uri": {"prefix": "/api"}}
                ],
                "route": route_to("ratings")
            }]
        }),
    )]);
    let runtime = sidecar_runtime_for("details");
    for (name, served) in [("omitted", Some(true)), ("unknown key", None)] {
        let mut slice = sidecar_slice(&config, &runtime);
        let mut patched = 0;
        for plugin in &mut slice.http_routes.plugin_configs {
            if plugin["plugin_name"] == json!("mesh_route_dispatch") {
                let object = plugin["config"]
                    .as_object_mut()
                    .expect("dispatch config object");
                object.remove("reject_unmatched");
                if name == "unknown key" {
                    object.insert("rejectUnmatched".to_string(), json!(false));
                }
                patched += 1;
            }
        }
        assert_eq!(patched, 1, "the route carries one dispatch instance");
        // `None`: the slice update is rejected and the last generation serves.
        let api_served = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
            .ok()
            .map(|prepared| {
                carried_route_proxies(&prepared)
                    .iter()
                    .any(|proxy| proxy.listen_path.as_deref() == Some("/api"))
            });
        assert_eq!(api_served, served, "{name}");
    }
}

/// Review finding sol F1 (#7443 round 2): plugin config ids are namespaced
/// resource ids, so a carried set in which two routes own records with one id
/// is refused at decode, before any Sidecar filtering could detach both.
#[test]
fn data_plane_refuses_a_route_set_reusing_a_plugin_config_id_across_owners() {
    let config = translated_config(&[virtual_service(
        "two",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [
                {
                    "match": [{
                        "uri": {"prefix": "/a"},
                        "headers": {"x-version": {"exact": "v2"}}
                    }],
                    "route": route_to("ratings")
                },
                {
                    "match": [{
                        "uri": {"prefix": "/b"},
                        "headers": {"x-version": {"exact": "v2"}}
                    }],
                    "route": route_to("details")
                }
            ]
        }),
    )]);
    let runtime = sidecar_runtime_for("details");
    let slice = sidecar_slice(&config, &runtime);
    let proxy_ids = carried_ids(&slice.http_routes.proxies);
    assert_eq!(proxy_ids.len(), 2, "two carried routes");
    prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("the unmodified route set materializes");

    let mut tampered = slice.clone();
    let first = tampered
        .http_routes
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin["plugin_name"] == json!("mesh_route_dispatch")
                && plugin["proxy_id"] == json!(proxy_ids[0])
        })
        .expect("the first route's dispatch instance")
        .clone();
    let mut second_owner = first;
    second_owner["proxy_id"] = json!(proxy_ids[1]);
    tampered.http_routes.plugin_configs.push(second_owner);
    let error = prepare_gateway_config_from_mesh_slice(&tampered, &runtime)
        .expect_err("a plugin config id owned by two routes refuses the slice");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("reuses the id of an earlier plugin config"),
        "{rendered}"
    );
}

/// Review finding neon F1 (#7447): proxy and upstream ids are namespaced
/// resource ids too. A carried route set that reuses one for two records is
/// refused at decode, like a reused plugin config id, before any binding or
/// filtering could act on the wrong record or on both.
#[test]
fn data_plane_refuses_a_route_set_reusing_a_proxy_or_upstream_id() {
    let runtime = sidecar_runtime_for("details");

    let config = translated_config(&[virtual_service("split", split_spec(json!({})))]);
    let slice = sidecar_slice(&config, &runtime);
    assert_eq!(slice.http_routes.upstreams.len(), 1, "one carried split");
    let mut tampered = slice.clone();
    let mut duplicate = tampered.http_routes.upstreams[0].clone();
    duplicate["targets"][0]["host"] = json!("secret.other.svc.cluster.local");
    tampered.http_routes.upstreams.push(duplicate);
    let error = prepare_gateway_config_from_mesh_slice(&tampered, &runtime)
        .expect_err("a reused upstream id refuses the slice");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("reuses the id of an earlier upstream"),
        "{rendered}"
    );

    let config = translated_config(&[virtual_service("split", guarded_split_spec())]);
    let slice = sidecar_slice(&config, &runtime);
    prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("the unmodified route set materializes");
    let mut tampered = slice.clone();
    let mut duplicate = tampered.http_routes.proxies[0].clone();
    duplicate["listen_path"] = json!("/elsewhere");
    tampered.http_routes.proxies.push(duplicate);
    let error = prepare_gateway_config_from_mesh_slice(&tampered, &runtime)
        .expect_err("a reused proxy id refuses the slice");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("reuses the id of an earlier proxy"),
        "{rendered}"
    );
}

/// Review findings neon F2 / sol F1 (#7447): an instance with a
/// `sourceNamespace` condition is validated with the plugin's own constructor
/// before any rule is removed. A config the plugin would refuse rejects the
/// slice update (sol F1, #7447), whether filtering would have emptied it (zero
/// port, empty `sourceNamespace`) or left a valid-looking sibling behind.
#[test]
fn sidecar_source_namespace_validates_the_dispatch_config_before_filtering() {
    let runtime = sidecar_runtime_for("details");
    let served = |config: &GatewayConfig, patch: &dyn Fn(&mut serde_json::Value)| {
        let mut slice = sidecar_slice(config, &runtime);
        let mut patched = 0;
        for plugin in &mut slice.http_routes.plugin_configs {
            if plugin["plugin_name"] == json!("mesh_route_dispatch") {
                patch(&mut plugin["config"]);
                patched += 1;
            }
        }
        assert_eq!(patched, 1, "the route carries one dispatch instance");
        // `None`: the slice update is rejected and the last generation serves.
        prepare_gateway_config_from_mesh_slice(&slice, &runtime)
            .ok()
            .map(|prepared| {
                carried_route_proxies(&prepared)
                    .iter()
                    .any(|proxy| proxy.listen_path.as_deref() == Some("/api"))
            })
    };
    let foreign_rule = |config: &mut serde_json::Value| -> usize {
        config["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .position(|rule| rule["match"].get("source_namespace").is_some())
            .expect("the sourceNamespace rule")
    };

    // An instance filtering would empty (the route has a URI-only sibling).
    let fallback = translated_config(&[virtual_service(
        "or",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "match": [
                    {"uri": {"prefix": "/api"}, "sourceNamespace": "other-ns"},
                    {"uri": {"prefix": "/api"}}
                ],
                "route": route_to("ratings")
            }]
        }),
    )]);
    assert_eq!(
        served(&fallback, &|_| {}),
        Some(true),
        "a valid instance is detached"
    );
    assert_eq!(
        served(&fallback, &|config| {
            let index = foreign_rule(config);
            config["rules"][index]["match"]["port"] = json!(0);
        }),
        None,
        "a zero port the plugin refuses rejects the slice"
    );
    assert_eq!(
        served(&fallback, &|config| {
            let index = foreign_rule(config);
            config["rules"][index]["match"]["source_namespace"] = json!("");
        }),
        None,
        "an empty sourceNamespace the plugin refuses rejects the slice"
    );

    // An instance filtering would leave with a valid sibling rule.
    let guarded = translated_config(&[virtual_service(
        "guarded",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "match": [
                    {"uri": {"prefix": "/api"}, "sourceNamespace": "other-ns"},
                    {"uri": {"prefix": "/api"}, "headers": {"x-version": {"exact": "v2"}}}
                ],
                "route": route_to("ratings")
            }]
        }),
    )]);
    assert_eq!(
        served(&guarded, &|_| {}),
        Some(true),
        "the valid header sibling keeps it"
    );
    assert_eq!(
        served(&guarded, &|config| {
            let index = foreign_rule(config);
            config["rules"][index]["match"]["port"] = json!(0);
        }),
        None,
        "removing the invalid rule must not heal the config"
    );
}

fn header_gated_spec() -> serde_json::Value {
    json!({
        "hosts": ["reviews.default.svc.cluster.local"],
        "http": [{
            "match": [{"uri": {"prefix": "/api"}, "headers": {"x-version": {"exact": "v2"}}}],
            "route": route_to("ratings")
        }]
    })
}

/// Review findings sol F1 / neon F1 (#7449): every carried dispatch instance
/// is validated by the plugin constructor at decode, on Sidecar and
/// NodeWaypoint alike, whether or not it has a `sourceNamespace` condition.
/// A malformed one rejects the slice update instead of being dropped with a
/// route the binding refuses or healed by the binding's destination rewrite.
///
/// Review finding dsf F1 (#7449 round 2) and dsf F1 / neon F1 (#7451): the
/// record around a valid config must have exactly the shape the translator
/// emits. A record the plugin cache would never build (disabled, not
/// proxy-scoped, not listed in its route's `plugins`), or one that could skip
/// or reorder the instance (an execution trigger, valid or malformed, or a
/// priority override), or one with any other field the translator never sets
/// (labels, an API spec id) rejects the slice. Otherwise the route would keep
/// serving without its 404 match gate. The translator's own record is the
/// positive case.
///
/// Review findings sol F1 / dsf F1 and the id-rule test gap (#7452): the
/// allowlist covers every carried record, whatever its `plugin_name`. These
/// also reject the slice:
/// * a record keeping the reserved dispatch id under another plugin type;
/// * a dispatch record under a non-canonical `istio-vs-` id, still listed by
///   its route;
/// * a dispatch id naming another route than its `proxy_id`;
/// * an extra, associated record of a kind the translator never attaches.
#[test]
fn every_malformed_carried_dispatch_instance_rejects_the_slice() {
    let config = translated_config(&[virtual_service("gated", header_gated_spec())]);
    type DispatchPatch = (&'static str, fn(&mut serde_json::Value));
    let patches: [DispatchPatch; 3] = [
        ("zero port", |config| {
            config["rules"][0]["match"]["port"] = json!(0);
        }),
        ("destination without a port", |config| {
            config["rules"][0]["destination"]
                .as_object_mut()
                .expect("rule destination")
                .remove("backend_port");
        }),
        ("unknown miss-policy key", |config| {
            config["rejectUnmatched"] = json!(true);
        }),
    ];
    for runtime in [sidecar_runtime_for("details"), node_waypoint_runtime()] {
        let topology = runtime.topology;
        let slice = MeshSlice::from_gateway_config(&config, runtime.mesh_slice_request());
        // Positive case: the translator's own record, carried as emitted,
        // sets only allowlisted record fields and decodes.
        let translated_dispatch: Vec<_> = slice
            .http_routes
            .plugin_configs
            .iter()
            .filter(|plugin| plugin["plugin_name"] == json!("mesh_route_dispatch"))
            .collect();
        assert_eq!(
            translated_dispatch.len(),
            1,
            "{topology:?}: one dispatch instance"
        );
        let record = translated_dispatch[0]
            .as_object()
            .expect("dispatch record object");
        for key in record.keys() {
            assert!(
                [
                    "id",
                    "plugin_name",
                    "namespace",
                    "config",
                    "scope",
                    "proxy_id",
                    "enabled",
                    "created_at",
                    "updated_at",
                ]
                .contains(&key.as_str()),
                "{topology:?}: the translator sets record field {key}"
            );
        }
        assert_eq!(record["enabled"], json!(true), "{topology:?}");
        assert_eq!(record["scope"], json!("proxy"), "{topology:?}");
        prepare_gateway_config_from_mesh_slice(&slice, &runtime)
            .unwrap_or_else(|error| panic!("{topology:?}: the valid slice applies: {error:#}"));
        for (name, patch) in patches {
            let mut tampered = slice.clone();
            let mut patched = 0;
            for plugin in &mut tampered.http_routes.plugin_configs {
                if plugin["plugin_name"] == json!("mesh_route_dispatch") {
                    patch(&mut plugin["config"]);
                    patched += 1;
                }
            }
            assert_eq!(patched, 1, "{topology:?} {name}: one dispatch instance");
            let error = prepare_gateway_config_from_mesh_slice(&tampered, &runtime)
                .expect_err("a malformed dispatch instance rejects the slice update");
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("is not a valid `mesh_route_dispatch` configuration"),
                "{topology:?} {name}: {rendered}"
            );
        }
        for name in [
            "disabled",
            "global scope",
            "unassociated",
            "trigger",
            "malformed trigger",
            "priority override",
            "labels",
            "api spec id",
            "reserved id on another plugin type",
            "non-canonical id",
            "id names another route",
            "foreign plugin kind",
        ] {
            let mut tampered = slice.clone();
            let mut dispatch_ids = Vec::new();
            let mut renamed: Option<(serde_json::Value, serde_json::Value)> = None;
            let mut extra: Option<serde_json::Value> = None;
            for plugin in &mut tampered.http_routes.plugin_configs {
                if plugin["plugin_name"] == json!("mesh_route_dispatch") {
                    match name {
                        "disabled" => plugin["enabled"] = json!(false),
                        "global scope" => plugin["scope"] = json!("global"),
                        "trigger" => {
                            plugin["trigger"] =
                                json!({"when": {"match": {"path": {"prefix": ["/never"]}}}});
                        }
                        "malformed trigger" => {
                            plugin["trigger"] = json!({"when": {"all": []}});
                        }
                        "priority override" => plugin["priority_override"] = json!(1),
                        "labels" => plugin["labels"] = json!({"team": "mesh"}),
                        "api spec id" => plugin["api_spec_id"] = json!("spec"),
                        "reserved id on another plugin type" => {
                            plugin["plugin_name"] = json!("cors");
                            plugin["config"] = json!({"allowed_origins": ["https://a.example"]});
                        }
                        "non-canonical id" | "id names another route" => {
                            let proxy_id = plugin["proxy_id"]
                                .as_str()
                                .expect("dispatch proxy_id")
                                .to_string();
                            let id = if name == "non-canonical id" {
                                format!("istio-vs-dispatch-{proxy_id}")
                            } else {
                                "istio-vs-mrd-istio-vs-elsewhere".to_string()
                            };
                            renamed = Some((plugin["id"].clone(), json!(id)));
                            plugin["id"] = json!(id);
                        }
                        "foreign plugin kind" => {
                            let proxy_id = plugin["proxy_id"]
                                .as_str()
                                .expect("dispatch proxy_id")
                                .to_string();
                            let mut record = plugin.clone();
                            record["id"] = json!(format!("istio-vs-extra-{proxy_id}"));
                            record["plugin_name"] = json!("request_size_limiting");
                            record["config"] = json!({"max_bytes": 1024});
                            extra = Some(record);
                        }
                        _ => {}
                    }
                    dispatch_ids.push(plugin["id"].clone());
                }
            }
            if let Some(record) = extra.take() {
                let mut linked = 0;
                for proxy in &mut tampered.http_routes.proxies {
                    if proxy["id"] == record["proxy_id"] {
                        proxy["plugins"]
                            .as_array_mut()
                            .expect("route plugin associations")
                            .push(json!({"plugin_config_id": record["id"].clone()}));
                        linked += 1;
                    }
                }
                assert_eq!(linked, 1, "{topology:?}: the extra record is associated");
                tampered.http_routes.plugin_configs.push(record);
            }
            if let Some((old, new)) = renamed.take() {
                let mut relinked = 0;
                for proxy in &mut tampered.http_routes.proxies {
                    if let Some(associations) = proxy["plugins"].as_array_mut() {
                        for association in associations {
                            if association["plugin_config_id"] == old {
                                association["plugin_config_id"] = new.clone();
                                relinked += 1;
                            }
                        }
                    }
                }
                assert_eq!(
                    relinked, 1,
                    "{topology:?} {name}: the route still lists the renamed record"
                );
            }
            assert_eq!(
                dispatch_ids.len(),
                1,
                "{topology:?} {name}: one dispatch instance"
            );
            if name == "unassociated" {
                let mut unlinked = 0;
                for proxy in &mut tampered.http_routes.proxies {
                    if let Some(associations) = proxy["plugins"].as_array_mut() {
                        let before = associations.len();
                        associations.retain(|association| {
                            association["plugin_config_id"] != dispatch_ids[0]
                        });
                        unlinked += before - associations.len();
                    }
                }
                assert_eq!(
                    unlinked, 1,
                    "{topology:?}: the route listed its dispatch instance"
                );
            }
            let error = prepare_gateway_config_from_mesh_slice(&tampered, &runtime)
                .expect_err("a dispatch record the translator does not emit rejects the slice");
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("record the translator does not emit"),
                "{topology:?} {name}: {rendered}"
            );
        }
    }
}

/// A VirtualService whose carried routes use every plugin kind the translator
/// attaches. The `/api` route has a header gate, request and response header
/// transforms, a loopback mirror and a CORS policy: dispatch, both
/// transformers, `request_mirror` and `cors`. The `/legacy` route has a match
/// predicate the translator cannot represent, so it gets the unconditional
/// `request_termination`.
fn every_route_plugin_kind_config() -> GatewayConfig {
    let mut spec = header_gated_spec();
    spec["http"][0]["headers"] = json!({
        "request": {"set": {"x-request-tag": "mesh"}},
        "response": {"set": {"x-response-tag": "mesh"}}
    });
    spec["http"][0]["corsPolicy"] = json!({
        "allowOrigins": [{"exact": "https://app.example"}, {"exact": "https://admin.example"}],
        "allowMethods": ["GET"],
        "maxAge": "600s",
        "allowCredentials": true
    });
    spec["http"][0]["mirror"] = json!({"host": "127.0.0.1", "port": {"number": 9000}});
    spec["http"]
        .as_array_mut()
        .expect("http routes")
        .push(json!({
            "match": [{"uri": {"prefix": "/legacy"}, "withoutHeaders": {}}],
            "route": route_to("details")
        }));
    translated_config(&[virtual_service("decorated", spec)])
}

/// Review follow-ups (#7452, #7453): the record and body allowlists cover
/// every carried plugin kind, so the translator's own records of all six
/// kinds must still decode, on Sidecar and NodeWaypoint.
#[test]
fn translator_route_plugin_kinds_decode_on_both_topologies() {
    let config = every_route_plugin_kind_config();
    for runtime in [sidecar_runtime_for("details"), node_waypoint_runtime()] {
        let topology = runtime.topology;
        let slice = MeshSlice::from_gateway_config(&config, runtime.mesh_slice_request());
        let kinds: std::collections::BTreeSet<&str> = slice
            .http_routes
            .plugin_configs
            .iter()
            .filter_map(|plugin| plugin["plugin_name"].as_str())
            .collect();
        for kind in [
            "mesh_route_dispatch",
            "request_transformer",
            "response_transformer",
            "request_termination",
            "request_mirror",
            "cors",
        ] {
            assert!(
                kinds.contains(kind),
                "{topology:?}: the routes carry {kind}: {kinds:?}"
            );
        }
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).unwrap_or_else(|error| {
            panic!("{topology:?}: the translator's route plugins decode: {error:#}")
        });
    }
}

/// The largest CORS `max_age` the translator can project: `u64::MAX`
/// milliseconds rounded up to seconds (`ISTIO_DURATION_SECS_MAX`).
const CORS_MAX_AGE_SECS_MAX: u64 = u64::MAX.div_ceil(1000);

/// Review findings sol F1 / F2 (#7453): the config body of every non-dispatch
/// kind is pinned at decode to the shape its translator builder emits, and
/// any deviation rejects the slice on Sidecar and NodeWaypoint. A mirror may
/// not leave loopback (another host, a cleartext opt-in or a protocol switch).
/// A termination may not become conditional (a plugin-local trigger) or stop
/// refusing (another status). A transformer may not carry static rules, and
/// CORS may not grow a key the translator never sets.
///
/// Review findings (#7455):
/// * The termination trigger case uses a trigger the plugin itself accepts,
///   so only the body pin can refuse it.
/// * CORS value pins are covered: a credentialed exact `*`, which the
///   translator defers and the plugin would silently strip; `max_age` one
///   past the largest projected value, with the largest value itself
///   accepted; an unsupported preflight mode; a multi-operator origin; a
///   non-string method.
/// * The mirror port and percentage bounds are covered.
/// * Review finding sol F1 (#7456): an origin list over the plugin's matcher
///   count, or a matcher over its byte bound, is refused before any regex is
///   compiled.
#[test]
fn every_non_translator_route_plugin_body_rejects_the_slice() {
    let config = every_route_plugin_kind_config();
    type BodyPatch = (&'static str, &'static str, fn(&mut serde_json::Value));
    let patches: &[BodyPatch] = &[
        ("request_mirror", "non-loopback host", |body| {
            body["mirror_host"] = json!("10.0.0.5");
        }),
        ("request_mirror", "cleartext opt-in", |body| {
            body["mirror_host"] = json!("10.0.0.5");
            body["allow_plaintext"] = json!(true);
        }),
        ("request_mirror", "protocol switch", |body| {
            body["mirror_protocol"] = json!("https");
        }),
        ("request_mirror", "port zero", |body| {
            body["mirror_port"] = json!(0);
        }),
        ("request_mirror", "port above range", |body| {
            body["mirror_port"] = json!(65536);
        }),
        ("request_mirror", "zero percentage", |body| {
            body["percentage"] = json!(0);
        }),
        ("request_mirror", "percentage above 100", |body| {
            body["percentage"] = json!(100.5);
        }),
        ("request_termination", "conditional trigger", |body| {
            body["trigger"] = json!({"path_prefix": "/never"});
        }),
        ("request_termination", "non-refusing status", |body| {
            body["status_code"] = json!(200);
        }),
        ("request_transformer", "static rules", |body| {
            body["rules"] =
                json!([{"operation": "add", "target": "header", "key": "x-a", "value": "1"}]);
        }),
        ("response_transformer", "route overrides off", |body| {
            body["apply_route_overrides"] = json!(false);
        }),
        ("cors", "unknown key", |body| {
            body["allow_private_network"] = json!(true);
        }),
        ("cors", "credentialed wildcard", |body| {
            body["allowed_origins"] = json!([{"exact": "*"}]);
            body["allow_credentials"] = json!(true);
        }),
        ("cors", "max_age above the projected range", |body| {
            body["max_age"] = json!(CORS_MAX_AGE_SECS_MAX + 1);
        }),
        ("cors", "unsupported preflight mode", |body| {
            body["unmatched_preflights"] = json!("reject");
        }),
        ("cors", "multi-operator origin", |body| {
            body["allowed_origins"] =
                json!([{"exact": "https://app.example", "prefix": "https://app.example"}]);
        }),
        ("cors", "non-string method", |body| {
            body["allowed_methods"] = json!([1]);
        }),
        // One past the plugin's 64-matcher bound, credentialed with regex
        // matchers, so the count bound must refuse it before the credential
        // check would compile each regex (#7456 sol F1).
        ("cors", "too many origin matchers", |body| {
            body["allowed_origins"] = serde_json::Value::Array(
                (0..65)
                    .map(|index| json!({"regex": format!("https://app{index}\\.example")}))
                    .collect(),
            );
            body["allow_credentials"] = json!(true);
        }),
        // One matcher over the plugin's 512-byte bound.
        ("cors", "oversized origin matcher", |body| {
            body["allowed_origins"] =
                json!([{"exact": format!("https://{}.example", "a".repeat(512))}]);
        }),
    ];
    for runtime in [sidecar_runtime_for("details"), node_waypoint_runtime()] {
        let topology = runtime.topology;
        let slice = MeshSlice::from_gateway_config(&config, runtime.mesh_slice_request());
        prepare_gateway_config_from_mesh_slice(&slice, &runtime)
            .unwrap_or_else(|error| panic!("{topology:?}: the valid slice applies: {error:#}"));
        // The largest `max_age` the translator can project is accepted.
        let mut at_bound = slice.clone();
        for plugin in &mut at_bound.http_routes.plugin_configs {
            if plugin["plugin_name"] == json!("cors") {
                plugin["config"]["max_age"] = json!(CORS_MAX_AGE_SECS_MAX);
            }
        }
        prepare_gateway_config_from_mesh_slice(&at_bound, &runtime).unwrap_or_else(|error| {
            panic!("{topology:?}: the largest projected max_age applies: {error:#}")
        });
        for &(kind, name, patch) in patches {
            let mut tampered = slice.clone();
            let mut patched = 0;
            for plugin in &mut tampered.http_routes.plugin_configs {
                if plugin["plugin_name"] == json!(kind) {
                    patch(&mut plugin["config"]);
                    patched += 1;
                }
            }
            assert_eq!(patched, 1, "{topology:?} {kind} {name}: one record");
            let error = prepare_gateway_config_from_mesh_slice(&tampered, &runtime)
                .expect_err("a body the translator does not emit rejects the slice");
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("carries a config body the translator does not emit"),
                "{topology:?} {kind} {name}: {rendered}"
            );
        }
    }
}

/// Review finding neon F2 (#7449): a `source_namespace` of `null` is an absent
/// predicate (the plugin reads it as `None`), so a Sidecar keeps the rule and
/// its header gate instead of deleting it as a foreign-namespace condition.
#[tokio::test]
async fn sidecar_source_namespace_null_is_an_absent_predicate() {
    let config = translated_config(&[virtual_service("gated", header_gated_spec())]);
    let runtime = sidecar_runtime_for("details");
    let mut slice = sidecar_slice(&config, &runtime);
    for plugin in &mut slice.http_routes.plugin_configs {
        if plugin["plugin_name"] == json!("mesh_route_dispatch") {
            plugin["config"]["rules"][0]["match"]["source_namespace"] = serde_json::Value::Null;
        }
    }
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    assert_eq!(
        sidecar_dispatch(&prepared, "/api", "/api/users", &[("x-version", "v2")]).await,
        Ok(SIDECAR_RATINGS.to_string()),
        "the header rule still dispatches"
    );
    assert_eq!(
        sidecar_dispatch(&prepared, "/api", "/api/users", &[]).await,
        Err(404),
        "the header gate still refuses a miss"
    );
}
