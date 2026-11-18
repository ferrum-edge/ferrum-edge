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

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{MeshConfig, PolicyScope, WorkloadRef, WorkloadSelector};
use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::modes::mesh::{
    MESH_AUTHZ_PLUGIN_ID, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_from_mesh_slice,
};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
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
            ("__mesh-out-upstream-default-reviews-8080".to_string(), 90),
            ("__mesh-out-upstream-default-ratings-8080".to_string(), 10),
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
    use ferrum_edge::RouterCache;
    use ferrum_edge::modes::mesh::MeshTrafficDirection;
    use ferrum_edge::router_cache::{MeshRouteScope, MeshScopedResolution};

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
}
