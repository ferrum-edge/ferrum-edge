//! ServiceWaypoint VirtualService `http[]` routes (issue #7500): control-plane
//! projection, wire contract, and data-plane materialization.
//!
//! These tests drive the production halves end to end: the Kubernetes
//! translator writes each VirtualService's routes and its mesh binding, the
//! control plane filters its configuration for the subscription
//! (`cp_filter_config_to_mesh_request_for_test`, the input of both the native
//! `MeshSubscribe` and the xDS ADS streams) and projects the slice
//! (`MeshSlice::from_gateway_config`), the slice crosses the native JSON and
//! xDS wire, and `prepare_gateway_config_from_mesh_slice` materializes it on a
//! ServiceWaypoint data plane.

use std::net::IpAddr;

use ferrum_edge::_test_support::{
    cp_filter_config_to_mesh_request_for_test, xds_config_fingerprints_equal_for_test,
};
use ferrum_edge::RouterCache;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{MeshWaypointBinding, MeshWaypointServiceRef, Workload};
use ferrum_edge::modes::mesh::config_consumer::xds_client::{
    XdsClientConfig, reverse_translate_xds_snapshot,
};
use ferrum_edge::modes::mesh::service_waypoint_l7::{
    ServiceWaypointConnectMode, ServiceWaypointL7Binding, ServiceWaypointL7Target,
    ServiceWaypointL7TargetIndex, is_service_waypoint_l7_route_id, service_waypoint_l7_route_id,
    service_waypoint_l7_upstream_id,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::modes::mesh::{
    MeshRuntimeConfig, MeshTopology, MeshTrafficDirection, prepare_gateway_config_from_mesh_slice,
};
use ferrum_edge::router_cache::{MeshRouteScope, MeshScopedResolution};
use ferrum_edge::xds::carrier::{
    MeshSliceCarrier, XdsNodeScoping, build_slice_carriers, decode_node_metadata,
    encode_node_metadata_with_scoping,
};
use ferrum_edge::xds::translate_mesh_slice_to_snapshot;
use serde_json::json;

use super::mesh_test_support::{runtime_for_topology, service_for, workload_for};

/// The waypoint's own namespace (the subscription namespace).
const WAYPOINT_NAMESPACE: &str = "default";
const WAYPOINT_NAME: &str = "waypoint";
/// A tenant whose Service is bound to the waypoint through
/// `istio.io/use-waypoint-namespace`.
const TENANT_NAMESPACE: &str = "tenant";
/// An unrelated third namespace.
const EVIL_NAMESPACE: &str = "evil";
/// A namespace with a Service that is NOT bound to the waypoint.
const PAYMENTS_NAMESPACE: &str = "payments";

const REVIEWS_IP: &str = "10.0.0.11";
const RATINGS_IP: &str = "10.0.0.12";
const DETAILS_IP: &str = "10.0.0.13";
const ORDERS_IP: &str = "10.0.1.21";
const BILLING_IP: &str = "10.0.9.9";

fn host(service: &str, namespace: &str) -> String {
    format!("{service}.{namespace}.svc.cluster.local")
}

fn virtual_service(name: &str, namespace: &str, spec: serde_json::Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "VirtualService".to_string(),
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
        status: serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// A weighted split on `route_host` between two destinations.
fn split_spec(
    route_host: &str,
    first: (&str, u32),
    second: (&str, u32),
    export_to: Option<&[&str]>,
) -> serde_json::Value {
    let mut spec = json!({
        "hosts": [route_host],
        "http": [{
            "route": [
                {"destination": {"host": first.0, "port": {"number": 8080}}, "weight": first.1},
                {"destination": {"host": second.0, "port": {"number": 8080}}, "weight": second.1}
            ]
        }]
    });
    if let Some(export_to) = export_to {
        spec["exportTo"] = json!(export_to);
    }
    spec
}

/// A single-destination route on `route_host`.
fn direct_spec(
    route_host: &str,
    destination: &str,
    export_to: Option<&[&str]>,
) -> serde_json::Value {
    let mut spec = json!({
        "hosts": [route_host],
        "http": [{
            "match": [{"uri": {"prefix": "/api"}}],
            "route": [{"destination": {"host": destination, "port": {"number": 8080}}}]
        }]
    });
    if let Some(export_to) = export_to {
        spec["exportTo"] = json!(export_to);
    }
    spec
}

/// Translate one namespace's VirtualServices into `config` (proxies,
/// upstreams, route plugins, and the mesh route bindings).
fn translate_into(config: &mut GatewayConfig, namespace: &str, objects: &[K8sObject]) {
    let translated = translate_k8s_objects(
        objects,
        K8sTranslationOptions::new(
            namespace.to_string(),
            TrustDomain::new("cluster.local").expect("trust domain"),
        ),
    )
    .expect("VirtualService translates");
    let translated = translated.config;
    config.proxies.extend(translated.proxies);
    config.upstreams.extend(translated.upstreams);
    config.plugin_configs.extend(translated.plugin_configs);
    if let Some(mesh) = translated.mesh {
        config
            .mesh
            .get_or_insert_with(Box::default)
            .virtual_service_http_routes
            .extend(mesh.virtual_service_http_routes);
    }
}

fn workloads() -> Vec<Workload> {
    vec![
        workload_for(
            "reviews",
            WAYPOINT_NAMESPACE,
            [("app", "reviews")],
            [REVIEWS_IP],
        ),
        workload_for(
            "ratings",
            WAYPOINT_NAMESPACE,
            [("app", "ratings")],
            [RATINGS_IP],
        ),
        workload_for(
            "details",
            WAYPOINT_NAMESPACE,
            [("app", "details")],
            [DETAILS_IP],
        ),
        workload_for("orders", TENANT_NAMESPACE, [("app", "orders")], [ORDERS_IP]),
        workload_for(
            "billing",
            PAYMENTS_NAMESPACE,
            [("app", "billing")],
            [BILLING_IP],
        ),
    ]
}

/// The binding of `WAYPOINT_NAME`: `reviews` and `ratings` in the waypoint
/// namespace plus `orders` from the tenant namespace. `details` and
/// `billing` are NOT bound.
fn binding(waypoint_for: &str) -> MeshWaypointBinding {
    MeshWaypointBinding {
        name: WAYPOINT_NAME.to_string(),
        namespace: WAYPOINT_NAMESPACE.to_string(),
        waypoint_for: waypoint_for.to_string(),
        gateway_class_name: Some("istio-waypoint".to_string()),
        services: vec![
            MeshWaypointServiceRef {
                namespace: WAYPOINT_NAMESPACE.to_string(),
                name: "reviews".to_string(),
            },
            MeshWaypointServiceRef {
                namespace: WAYPOINT_NAMESPACE.to_string(),
                name: "ratings".to_string(),
            },
            MeshWaypointServiceRef {
                namespace: TENANT_NAMESPACE.to_string(),
                name: "orders".to_string(),
            },
        ],
    }
}

/// The control plane's authoritative configuration: the inventory, the
/// waypoint binding, and the VirtualServices `per_namespace` holds.
fn cp_config(
    waypoint_binding: Option<MeshWaypointBinding>,
    per_namespace: &[(&str, Vec<K8sObject>)],
) -> GatewayConfig {
    let mut config = GatewayConfig::default();
    for (namespace, objects) in per_namespace {
        translate_into(&mut config, namespace, objects);
    }
    let workloads = workloads();
    let by_name = |name: &str| {
        workloads
            .iter()
            .find(|workload| workload.service_name == name)
            .expect("fixture workload")
            .clone()
    };
    let mesh = config.mesh.get_or_insert_with(Box::default);
    mesh.services = vec![
        service_for("reviews", WAYPOINT_NAMESPACE, &[&by_name("reviews")]),
        service_for("ratings", WAYPOINT_NAMESPACE, &[&by_name("ratings")]),
        service_for("details", WAYPOINT_NAMESPACE, &[&by_name("details")]),
        service_for("orders", TENANT_NAMESPACE, &[&by_name("orders")]),
        service_for("billing", PAYMENTS_NAMESPACE, &[&by_name("billing")]),
    ];
    mesh.workloads = workloads;
    mesh.waypoint_bindings = waypoint_binding.into_iter().collect();
    config.normalize_fields();
    config.normalize_mesh_fields();
    config
}

fn service_waypoint_runtime() -> MeshRuntimeConfig {
    let mut runtime = runtime_for_topology(MeshTopology::ServiceWaypoint);
    runtime.namespace = WAYPOINT_NAMESPACE.to_string();
    runtime.waypoint_name = Some(WAYPOINT_NAME.to_string());
    runtime
}

/// Project the slice the way a control plane serves it: filter for the
/// subscription, then build the slice.
fn served_slice(config: &GatewayConfig, request: &MeshSliceRequest) -> MeshSlice {
    let filtered = cp_filter_config_to_mesh_request_for_test(config, request);
    MeshSlice::from_gateway_config(&filtered, request.clone())
}

fn carried_route_ids(slice: &MeshSlice) -> Vec<String> {
    slice
        .http_routes
        .proxies
        .iter()
        .filter_map(|proxy| proxy.get("id").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect()
}

fn carried_route_namespaces(slice: &MeshSlice) -> Vec<String> {
    slice
        .http_routes
        .proxies
        .iter()
        .filter_map(|proxy| proxy.get("namespace").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect()
}

/// The default set of VirtualServices: a 90/10 split on `reviews` between the
/// two bound Services in the waypoint namespace, and the tenant's own route on
/// its bound `orders` Service.
fn default_virtual_services() -> Vec<(&'static str, Vec<K8sObject>)> {
    vec![
        (
            WAYPOINT_NAMESPACE,
            vec![virtual_service(
                "reviews-split",
                WAYPOINT_NAMESPACE,
                split_spec(
                    &host("reviews", WAYPOINT_NAMESPACE),
                    (&host("reviews", WAYPOINT_NAMESPACE), 90),
                    (&host("ratings", WAYPOINT_NAMESPACE), 10),
                    None,
                ),
            )],
        ),
        (
            TENANT_NAMESPACE,
            vec![virtual_service(
                "orders-api",
                TENANT_NAMESPACE,
                direct_spec(
                    &host("orders", TENANT_NAMESPACE),
                    &host("orders", TENANT_NAMESPACE),
                    None,
                ),
            )],
        ),
    ]
}

// ── Wire contract ──────────────────────────────────────────────────────────

#[test]
fn service_waypoint_requests_http_routes_on_its_own_flag() {
    let request = service_waypoint_runtime().mesh_slice_request();
    assert!(request.service_waypoint_http_routes);
    assert!(!request.sidecar_http_routes);
    assert!(!request.node_waypoint_capture_scoping);
    assert_eq!(request.waypoint_name.as_deref(), Some(WAYPOINT_NAME));

    for topology in [
        MeshTopology::Sidecar,
        MeshTopology::Ambient,
        MeshTopology::NodeWaypoint,
    ] {
        assert!(
            !runtime_for_topology(topology)
                .mesh_slice_request()
                .service_waypoint_http_routes,
            "{topology:?} never asks for ServiceWaypoint routes"
        );
    }
}

#[test]
fn xds_node_metadata_carries_the_service_waypoint_flag() {
    let scoping = XdsNodeScoping {
        service_waypoint_http_routes: true,
        ..XdsNodeScoping::default()
    };
    assert!(!scoping.is_default());
    let bytes = encode_node_metadata_with_scoping(None, Some(WAYPOINT_NAME), scoping);
    let metadata = decode_node_metadata(&bytes);
    assert!(metadata.service_waypoint_http_routes);
    assert!(!metadata.sidecar_http_routes);
    assert_eq!(XdsNodeScoping::from(&metadata), scoping);

    // The flag alone (no identity, no waypoint name) still rides the wire.
    let bare = encode_node_metadata_with_scoping(None, None, scoping);
    assert!(!bare.is_empty());
    assert!(decode_node_metadata(&bare).service_waypoint_http_routes);

    // An older DP that never sets it encodes nothing for it.
    let none = encode_node_metadata_with_scoping(None, None, XdsNodeScoping::default());
    assert!(none.is_empty());
    assert!(!decode_node_metadata(&none).service_waypoint_http_routes);
}

#[test]
fn native_and_xds_round_trips_give_identical_service_waypoint_slices() {
    let config = cp_config(Some(binding("service")), &default_virtual_services());
    let runtime = service_waypoint_runtime();
    let slice = served_slice(&config, &runtime.mesh_slice_request());
    assert!(!slice.http_routes.is_empty(), "the routes are projected");
    assert!(!slice.service_waypoint_bound_services.is_empty());

    // Native MeshSubscribe: the slice crosses the wire as JSON.
    let native: MeshSlice =
        serde_json::from_value(serde_json::to_value(&slice).expect("serialize"))
            .expect("native slice JSON decodes");
    assert!(native.content_eq(&slice));
    assert_eq!(native.http_routes, slice.http_routes);

    // xDS ADS: the CP's snapshot rebuilt through the DP's production path.
    let carriers = build_slice_carriers(&slice);
    assert!(
        carriers
            .iter()
            .any(|carrier| matches!(carrier, MeshSliceCarrier::HttpRoutes(_))),
        "xDS emits the HTTP route carrier for a ServiceWaypoint"
    );
    let dp_config = XdsClientConfig {
        cp_urls: Vec::new(),
        node_id: slice.node_id.clone(),
        cluster: String::new(),
        namespace: slice.namespace.clone(),
        workload_spiffe_id: slice.workload_spiffe_id.clone(),
        waypoint_name: slice.waypoint_name.clone(),
        ambient_udp_source_scoping: true,
        node_waypoint_capture_scoping: false,
        sidecar_http_routes: false,
        service_waypoint_http_routes: true,
        stream_channel_capacity: 1,
        primary_retry_secs: 0,
        connect_timeout_seconds: 0,
        labels: slice.labels.clone(),
    };
    let xds = reverse_translate_xds_snapshot(&translate_mesh_slice_to_snapshot(&slice), &dp_config)
        .expect("the DP rebuilds the xDS-carried slice");
    assert_eq!(xds.http_routes, native.http_routes);
    assert_eq!(
        xds.service_waypoint_bound_services,
        native.service_waypoint_bound_services
    );
    assert!(
        xds.content_eq(&native),
        "the xDS-built ServiceWaypoint slice is the native one"
    );

    // Both materialize the same data plane.
    let from_native =
        prepare_gateway_config_from_mesh_slice(&native, &runtime).expect("native materializes");
    let from_xds =
        prepare_gateway_config_from_mesh_slice(&xds, &runtime).expect("xDS materializes");
    let ids = |config: &GatewayConfig| {
        let mut ids: Vec<String> = config
            .proxies
            .iter()
            .map(|proxy| proxy.id.clone())
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(ids(&from_native), ids(&from_xds));
}

#[test]
fn content_eq_and_xds_fingerprint_cover_service_waypoint_http_routes() {
    let config = cp_config(Some(binding("service")), &default_virtual_services());
    let request = service_waypoint_runtime().mesh_slice_request();
    let slice = served_slice(&config, &request);
    assert!(slice.content_eq(&slice.clone()));

    let mut withdrawn = slice.clone();
    withdrawn.http_routes = Default::default();
    assert!(
        !slice.content_eq(&withdrawn),
        "a withdrawn route re-applies"
    );

    let mut reweighted = slice.clone();
    let split = reweighted
        .http_routes
        .upstreams
        .first_mut()
        .expect("the split upstream rides along");
    split["targets"][0]["weight"] = json!(1);
    assert!(!slice.content_eq(&reweighted), "a route edit re-applies");

    // The xDS stream cache: the request flag changes the filtered config the
    // stream fingerprints (the tenant's bound-Service routes ride only with
    // it), and so does a route edit.
    let flagged = cp_filter_config_to_mesh_request_for_test(&config, &request);
    let unflagged = cp_filter_config_to_mesh_request_for_test(
        &config,
        &MeshSliceRequest {
            service_waypoint_http_routes: false,
            ..request.clone()
        },
    );
    assert!(
        !xds_config_fingerprints_equal_for_test(&flagged, &unflagged),
        "`service_waypoint_http_routes` is part of the xDS fingerprint input"
    );
    assert!(xds_config_fingerprints_equal_for_test(
        &flagged,
        &cp_filter_config_to_mesh_request_for_test(&config, &request)
    ));
    let mut edited_config = config.clone();
    for upstream in &mut edited_config.upstreams {
        for target in &mut upstream.targets {
            target.weight = target.weight.saturating_add(1);
        }
    }
    let edited = cp_filter_config_to_mesh_request_for_test(&edited_config, &request);
    assert!(
        !xds_config_fingerprints_equal_for_test(&flagged, &edited),
        "an `http_routes` edit moves the xDS fingerprint"
    );
}

// ── Control-plane projection ──────────────────────────────────────────────

#[test]
fn service_waypoint_slice_carries_its_bound_services_routes() {
    let config = cp_config(Some(binding("service")), &default_virtual_services());
    let slice = served_slice(&config, &service_waypoint_runtime().mesh_slice_request());
    let ids = carried_route_ids(&slice);
    assert!(
        ids.iter().any(|id| id.contains("reviews-split")),
        "the waypoint namespace's route on its bound Service rides: {ids:?}"
    );
    assert!(
        ids.iter().any(|id| id.contains("orders-api")),
        "the bound tenant Service's own route rides: {ids:?}"
    );
    assert!(ids.iter().all(|id| id.starts_with("istio-vs-")));
    let namespaces = carried_route_namespaces(&slice);
    assert!(namespaces.contains(&TENANT_NAMESPACE.to_string()));
    for plugin in &slice.http_routes.plugin_configs {
        let owner = plugin
            .get("proxy_id")
            .and_then(serde_json::Value::as_str)
            .expect("route plugins are proxy-scoped");
        assert!(ids.iter().any(|id| id == owner));
    }
}

#[test]
fn missing_binding_and_non_service_waypoint_for_project_no_http_routes() {
    let request = service_waypoint_runtime().mesh_slice_request();

    // No Gateway binding at all: `services` fail-opens for the rollout
    // window, the routes do not.
    let unbound = served_slice(&cp_config(None, &default_virtual_services()), &request);
    assert!(
        !unbound.services.is_empty(),
        "the routing view still fail-opens during a rollout"
    );
    assert!(unbound.service_waypoint_bound_services.is_empty());
    assert!(
        unbound.http_routes.is_empty(),
        "a missing Gateway binding projects no http_routes"
    );

    for waypoint_for in ["none", "workload", "", "future-mode"] {
        let slice = served_slice(
            &cp_config(Some(binding(waypoint_for)), &default_virtual_services()),
            &request,
        );
        assert!(
            slice.service_waypoint_bound_services.is_empty(),
            "waypoint_for {waypoint_for:?} claims no service traffic"
        );
        assert!(
            slice.http_routes.is_empty(),
            "waypoint_for {waypoint_for:?} projects no http_routes"
        );
    }

    // `all` claims service traffic like `service`.
    let all = served_slice(
        &cp_config(Some(binding("all")), &default_virtual_services()),
        &request,
    );
    assert!(!all.http_routes.is_empty());

    // A binding for another waypoint name is not this waypoint's evidence.
    let mut other = binding("service");
    other.name = "other-waypoint".to_string();
    let slice = served_slice(
        &cp_config(Some(other), &default_virtual_services()),
        &request,
    );
    assert!(slice.http_routes.is_empty());

    // Without the request flag (an older DP) nothing is carried either.
    let unflagged = served_slice(
        &cp_config(Some(binding("service")), &default_virtual_services()),
        &MeshSliceRequest {
            service_waypoint_http_routes: false,
            ..request.clone()
        },
    );
    assert!(unflagged.http_routes.is_empty());
}

#[test]
fn third_namespace_virtual_service_exported_everywhere_is_excluded() {
    let mut namespaces = default_virtual_services();
    namespaces.push((
        EVIL_NAMESPACE,
        vec![virtual_service(
            "hijack",
            EVIL_NAMESPACE,
            direct_spec(
                &host("orders", TENANT_NAMESPACE),
                "attacker.example.com",
                Some(&["*"]),
            ),
        )],
    ));
    let config = cp_config(Some(binding("service")), &namespaces);
    let request = service_waypoint_runtime().mesh_slice_request();

    for slice in [
        served_slice(&config, &request),
        // The anti-hijack rule is the projection's own, not only the CP
        // filter's: an unfiltered inventory is refused the same way.
        MeshSlice::from_gateway_config(&config, request.clone()),
    ] {
        let ids = carried_route_ids(&slice);
        assert!(
            !ids.iter().any(|id| id.contains("hijack")),
            "a VirtualService in an unrelated namespace never rides another tenant's \
             ServiceWaypoint: {ids:?}"
        );
        assert!(
            !carried_route_namespaces(&slice).contains(&EVIL_NAMESPACE.to_string()),
            "nothing from the third namespace is carried"
        );
        assert!(
            ids.iter().any(|id| id.contains("orders-api")),
            "the Service owner's own route still rides"
        );
    }
}

#[test]
fn waypoint_namespace_route_on_a_tenant_service_needs_export_to_that_tenant() {
    let route = |export_to: &[&str]| {
        vec![(
            WAYPOINT_NAMESPACE,
            vec![virtual_service(
                "orders-from-waypoint",
                WAYPOINT_NAMESPACE,
                direct_spec(
                    &host("orders", TENANT_NAMESPACE),
                    &host("orders", TENANT_NAMESPACE),
                    Some(export_to),
                ),
            )],
        )]
    };
    let request = service_waypoint_runtime().mesh_slice_request();

    let local = served_slice(
        &cp_config(Some(binding("service")), &route(&["."])),
        &request,
    );
    assert!(
        !carried_route_ids(&local)
            .iter()
            .any(|id| id.contains("orders-from-waypoint")),
        "a waypoint-namespace route not exported to the Service's namespace is refused"
    );

    let exported = served_slice(
        &cp_config(Some(binding("service")), &route(&[".", TENANT_NAMESPACE])),
        &request,
    );
    assert!(
        carried_route_ids(&exported)
            .iter()
            .any(|id| id.contains("orders-from-waypoint")),
        "istio.io/use-waypoint-namespace: the waypoint namespace may route its bound \
         tenant Service when it exports the route to that tenant"
    );
}

#[test]
fn routes_on_unbound_hosts_or_to_unbound_services_are_not_carried() {
    let namespaces = vec![(
        WAYPOINT_NAMESPACE,
        vec![
            // A route on a Service this waypoint is not bound to.
            virtual_service(
                "details-route",
                WAYPOINT_NAMESPACE,
                direct_spec(
                    &host("details", WAYPOINT_NAMESPACE),
                    &host("details", WAYPOINT_NAMESPACE),
                    None,
                ),
            ),
            // A route on a bound Service that splits onto an unbound one.
            virtual_service(
                "reviews-to-details",
                WAYPOINT_NAMESPACE,
                split_spec(
                    &host("reviews", WAYPOINT_NAMESPACE),
                    (&host("reviews", WAYPOINT_NAMESPACE), 50),
                    (&host("details", WAYPOINT_NAMESPACE), 50),
                    None,
                ),
            ),
            // A route on a bound Service with a leg in another namespace.
            virtual_service(
                "ratings-to-billing",
                WAYPOINT_NAMESPACE,
                split_spec(
                    &host("ratings", WAYPOINT_NAMESPACE),
                    (&host("ratings", WAYPOINT_NAMESPACE), 90),
                    (&host("billing", PAYMENTS_NAMESPACE), 10),
                    None,
                ),
            ),
        ],
    )];
    let slice = served_slice(
        &cp_config(Some(binding("service")), &namespaces),
        &service_waypoint_runtime().mesh_slice_request(),
    );
    assert!(
        slice.http_routes.is_empty(),
        "no route reaches a Service this waypoint is not bound to: {:?}",
        carried_route_ids(&slice)
    );
}

// ── Relay inventory and bound-Service evidence never widen ────────────────

fn backing_addresses(config: &GatewayConfig) -> Vec<String> {
    let mesh = config.mesh.as_deref().expect("mesh block");
    let mut addresses: Vec<String> = mesh
        .inbound_relay_destinations
        .iter()
        .map(|destination| format!("{:?}", destination.host))
        .collect();
    addresses.sort();
    addresses
}

#[test]
fn inbound_relay_destinations_never_widen_to_cross_namespace_split_legs() {
    let runtime = service_waypoint_runtime();
    let request = runtime.mesh_slice_request();
    let baseline_config = cp_config(Some(binding("service")), &default_virtual_services());
    let baseline = served_slice(&baseline_config, &request);
    let baseline_prepared =
        prepare_gateway_config_from_mesh_slice(&baseline, &runtime).expect("baseline");
    let baseline_relay = backing_addresses(&baseline_prepared);
    assert!(!baseline_relay.is_empty(), "the bound backing pods relay");

    // A route on a bound Service with a cross-namespace leg: the projection
    // refuses it, and neither the bound-Service evidence nor the workloads
    // the slice carries grow.
    let mut namespaces = default_virtual_services();
    namespaces[0].1.push(virtual_service(
        "ratings-to-billing",
        WAYPOINT_NAMESPACE,
        split_spec(
            &host("ratings", WAYPOINT_NAMESPACE),
            (&host("ratings", WAYPOINT_NAMESPACE), 90),
            (&host("billing", PAYMENTS_NAMESPACE), 10),
            None,
        ),
    ));
    let config = cp_config(Some(binding("service")), &namespaces);
    let slice = served_slice(&config, &request);
    assert_eq!(
        slice.service_waypoint_bound_services,
        baseline.service_waypoint_bound_services
    );
    assert!(
        !slice.workloads.iter().any(|workload| workload
            .addresses
            .iter()
            .any(|address| address == BILLING_IP)),
        "the cross-namespace leg's workloads are not carried"
    );

    // Even a producer that DID carry such a route (here, the NodeWaypoint
    // projection of the same namespace, which applies no binding gate)
    // cannot widen the data plane: the leg is refused and the relay
    // inventory stays the bound backing pods.
    let node_waypoint_request =
        runtime_for_topology(MeshTopology::NodeWaypoint).mesh_slice_request();
    let node_waypoint = MeshSlice::from_gateway_config(&config, node_waypoint_request);
    assert!(
        carried_route_ids(&node_waypoint)
            .iter()
            .any(|id| id.contains("ratings-to-billing")),
        "fixture: the unbounded projection carries the cross-namespace leg"
    );
    let mut forged = slice.clone();
    forged.http_routes = node_waypoint.http_routes.clone();
    let prepared = prepare_gateway_config_from_mesh_slice(&forged, &runtime)
        .expect("the data plane refuses the route, not the slice");
    assert_eq!(
        backing_addresses(&prepared),
        baseline_relay,
        "inbound_relay_destinations never widens to a split leg"
    );
    assert!(
        !backing_addresses(&prepared)
            .iter()
            .any(|address| address.contains(BILLING_IP))
    );
    assert!(
        !prepared
            .proxies
            .iter()
            .any(|proxy| proxy.id.contains("ratings-to-billing")),
        "the cross-namespace route is refused on the ServiceWaypoint"
    );
    let mesh = prepared.mesh.as_deref().expect("mesh block");
    assert!(
        mesh.service_waypoint_l7_bindings
            .iter()
            .all(|binding| binding.target.namespace != PAYMENTS_NAMESPACE),
        "the L7 target set is the bound Services only"
    );
}

// ── Data-plane materialization ─────────────────────────────────────────────

fn prepared_service_waypoint(runtime: &MeshRuntimeConfig) -> (MeshSlice, GatewayConfig) {
    let config = cp_config(Some(binding("service")), &default_virtual_services());
    let slice = served_slice(&config, &runtime.mesh_slice_request());
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, runtime).expect("slice materializes");
    (slice, prepared)
}

#[test]
fn data_plane_materializes_bound_service_l7_upstreams_and_default_routes() {
    let runtime = service_waypoint_runtime();
    let (slice, prepared) = prepared_service_waypoint(&runtime);

    for (namespace, service, address) in [
        (WAYPOINT_NAMESPACE, "reviews", REVIEWS_IP),
        (WAYPOINT_NAMESPACE, "ratings", RATINGS_IP),
        (TENANT_NAMESPACE, "orders", ORDERS_IP),
    ] {
        let upstream_id = service_waypoint_l7_upstream_id(namespace, service, 8080);
        let upstream = prepared
            .upstreams
            .iter()
            .find(|upstream| upstream.namespace == namespace && upstream.id == upstream_id)
            .unwrap_or_else(|| panic!("{upstream_id} materializes"));
        assert_eq!(upstream.targets.len(), 1);
        assert_eq!(upstream.targets[0].host, address);
        assert_eq!(upstream.targets[0].port, 8080);
        assert_eq!(
            upstream.name.as_deref(),
            Some(host(service, namespace).as_str()),
            "named by the Service FQDN so DestinationRules apply"
        );
        let route_id = service_waypoint_l7_route_id(namespace, service, 8080);
        let route = prepared
            .proxies
            .iter()
            .find(|proxy| proxy.namespace == namespace && proxy.id == route_id)
            .unwrap_or_else(|| panic!("{route_id} materializes"));
        assert_eq!(route.upstream_id.as_deref(), Some(upstream_id.as_str()));
        assert!(route.hosts.contains(&host(service, namespace)));
        assert!(is_service_waypoint_l7_route_id(&route.id));
    }
    // An unbound Service gets nothing.
    assert!(
        !prepared
            .proxies
            .iter()
            .any(|proxy| proxy.id
                == service_waypoint_l7_route_id(WAYPOINT_NAMESPACE, "details", 8080))
    );

    // The carried routes survive and their split is rebound onto the bound
    // Services' workloads, never their DNS names.
    for id in carried_route_ids(&slice) {
        assert!(
            prepared.proxies.iter().any(|proxy| proxy.id == id),
            "carried route {id} materializes"
        );
    }
    let split = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id.starts_with("istio-vs-upstream-"))
        .expect("the split upstream materializes");
    let mut split_hosts: Vec<&str> = split
        .targets
        .iter()
        .map(|target| target.host.as_str())
        .collect();
    split_hosts.sort_unstable();
    assert_eq!(split_hosts, vec![REVIEWS_IP, RATINGS_IP]);

    // No identity source: the explicit development posture keeps the
    // plaintext target shape (no mesh transport tag).
    let reviews = prepared
        .upstreams
        .iter()
        .find(|upstream| {
            upstream.id == service_waypoint_l7_upstream_id(WAYPOINT_NAMESPACE, "reviews", 8080)
        })
        .expect("reviews upstream");
    assert!(!reviews.targets[0].tags.contains_key("mesh.hbone"));
}

#[test]
fn identity_backed_service_waypoint_dials_backing_workloads_over_hbone() {
    let mut runtime = service_waypoint_runtime();
    runtime.workload_svid_cert_path = Some("/var/run/ferrum/svid.pem".to_string());
    runtime.workload_svid_key_path = Some("/var/run/ferrum/svid-key.pem".to_string());
    runtime.workload_svid_trust_bundle_path = Some("/var/run/ferrum/bundle.pem".to_string());
    let (_, prepared) = prepared_service_waypoint(&runtime);
    let reviews = prepared
        .upstreams
        .iter()
        .find(|upstream| {
            upstream.id == service_waypoint_l7_upstream_id(WAYPOINT_NAMESPACE, "reviews", 8080)
        })
        .expect("reviews upstream");
    let target = &reviews.targets[0];
    assert_eq!(
        target.tags.get("mesh.hbone").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        target.tags.get("mesh.spiffe_id").map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/reviews"),
        "the backing workload identity is pinned"
    );
    assert_eq!(target.service_port_policy_key, Some(8080));
}

#[test]
fn router_builds_the_target_index_and_per_bound_service_partitions() {
    let runtime = service_waypoint_runtime();
    let (slice, prepared) = prepared_service_waypoint(&runtime);
    let router = RouterCache::new(&prepared, 1024);
    let routes = router.service_waypoint_l7_routes();
    let reviews = ServiceWaypointL7Target {
        namespace: WAYPOINT_NAMESPACE.to_string(),
        service: "reviews".to_string(),
        service_port: 8080,
    };
    let orders = ServiceWaypointL7Target {
        namespace: TENANT_NAMESPACE.to_string(),
        service: "orders".to_string(),
        service_port: 8080,
    };

    let index = routes.index();
    assert!(index.contains(&reviews));
    assert!(index.contains(&orders));
    assert_eq!(
        index.classify_authority(&host("reviews", WAYPOINT_NAMESPACE), 8080),
        ServiceWaypointConnectMode::TerminateL7(reviews.clone())
    );
    assert_eq!(
        index.classify_authority("Reviews.Default.svc.cluster.local.", 8080),
        ServiceWaypointConnectMode::TerminateL7(reviews.clone()),
        "Service hosts compare case-insensitively without a trailing dot"
    );
    assert_eq!(
        index.classify_authority(REVIEWS_IP, 8080),
        ServiceWaypointConnectMode::TerminateL7(reviews.clone()),
        "a backing pod authority maps to its bound Service"
    );
    assert_eq!(
        index.classify_authority(REVIEWS_IP, 9090),
        ServiceWaypointConnectMode::NotL7Target
    );
    for unbound in [
        host("details", WAYPOINT_NAMESPACE),
        DETAILS_IP.to_string(),
        BILLING_IP.to_string(),
        "127.0.0.1".to_string(),
    ] {
        assert_eq!(
            index.classify_authority(&unbound, 8080),
            ServiceWaypointConnectMode::NotL7Target,
            "{unbound} is not an L7 target of this waypoint"
        );
    }

    let partition = routes.partition(&reviews).expect("reviews partition");
    assert_eq!(
        partition.default_route.id,
        service_waypoint_l7_route_id(WAYPOINT_NAMESPACE, "reviews", 8080)
    );
    let carried: Vec<&str> = partition
        .carried_routes
        .iter()
        .map(|route| route.id.as_str())
        .collect();
    assert!(
        carried.iter().all(|id| carried_route_ids(&slice)
            .iter()
            .any(|carried_id| carried_id.as_str() == *id)),
        "only carried routes are in the partition"
    );
    assert!(
        carried.iter().any(|id| id.contains("reviews-split")),
        "the split route on reviews is bound to reviews: {carried:?}"
    );
    assert!(partition.admits_host("reviews"));
    assert!(partition.admits_host(&host("reviews", WAYPOINT_NAMESPACE)));
    assert!(
        !partition.admits_host(&host("ratings", WAYPOINT_NAMESPACE)),
        "another bound Service's host is a mismatch, never a route to it"
    );
    assert!(!partition.admits_host("attacker.example.com"));

    let orders_partition = routes.partition(&orders).expect("orders partition");
    assert!(
        orders_partition
            .carried_routes
            .iter()
            .any(|route| route.id.contains("orders-api"))
    );
    assert!(
        orders_partition
            .carried_routes
            .iter()
            .all(|route| route.namespace == TENANT_NAMESPACE),
        "a partition holds only routes of its Service's own namespace"
    );

    let summary = routes.service_summary(WAYPOINT_NAMESPACE, "reviews");
    assert_eq!(summary.l7_http_ports, vec![8080]);
    assert_eq!(
        summary.virtual_service_route_count,
        partition.carried_routes.len()
    );
    let unbound = routes.service_summary(WAYPOINT_NAMESPACE, "details");
    assert!(unbound.l7_http_ports.is_empty());
    assert_eq!(unbound.virtual_service_route_count, 0);
}

#[test]
fn target_index_refuses_an_ambiguous_backing_endpoint() {
    let address: IpAddr = "10.0.0.50".parse().expect("ip");
    let binding_for = |service: &str| ServiceWaypointL7Binding {
        target: ServiceWaypointL7Target {
            namespace: WAYPOINT_NAMESPACE.to_string(),
            service: service.to_string(),
            service_port: 8080,
        },
        route_id: service_waypoint_l7_route_id(WAYPOINT_NAMESPACE, service, 8080),
        upstream_id: service_waypoint_l7_upstream_id(WAYPOINT_NAMESPACE, service, 8080),
        hosts: vec![host(service, WAYPOINT_NAMESPACE)],
        service_addresses: Vec::new(),
        backing_endpoints: vec![(address, 8080)],
    };
    let index = ServiceWaypointL7TargetIndex::from_bindings(&[
        binding_for("frontend"),
        binding_for("backend"),
    ]);
    assert_eq!(
        index.classify_authority("10.0.0.50", 8080),
        ServiceWaypointConnectMode::Ambiguous,
        "one pod address:port owned by two bound Services is never guessed"
    );
    assert_eq!(
        index.classify_authority("[::ffff:10.0.0.50]", 8080),
        ServiceWaypointConnectMode::Ambiguous,
        "mapped IPv6 canonicalizes to the same endpoint"
    );
    assert_eq!(
        index.classify_authority(&host("frontend", WAYPOINT_NAMESPACE), 8080),
        ServiceWaypointConnectMode::TerminateL7(ServiceWaypointL7Target {
            namespace: WAYPOINT_NAMESPACE.to_string(),
            service: "frontend".to_string(),
            service_port: 8080,
        }),
        "the Service host still names exactly one Service"
    );
}

#[test]
fn data_plane_refuses_routes_without_this_waypoints_binding_evidence() {
    let runtime = service_waypoint_runtime();
    let (slice, _) = prepared_service_waypoint(&runtime);

    let mut no_evidence = slice.clone();
    no_evidence.service_waypoint_bound_services.clear();
    prepare_gateway_config_from_mesh_slice(&no_evidence, &runtime)
        .expect_err("carried routes without bound-Service evidence refuse the slice");

    let mut other_waypoint = runtime.clone();
    other_waypoint.waypoint_name = Some("other-waypoint".to_string());
    prepare_gateway_config_from_mesh_slice(&slice, &other_waypoint)
        .expect_err("routes built for another waypoint identity refuse the slice");

    // A carried route in a namespace that is neither the waypoint's nor a
    // bound Service's is refused.
    let mut foreign = slice.clone();
    let route = foreign
        .http_routes
        .proxies
        .first_mut()
        .expect("a carried route");
    route["namespace"] = json!(EVIL_NAMESPACE);
    prepare_gateway_config_from_mesh_slice(&foreign, &runtime)
        .expect_err("a carried route outside the bound namespaces refuses the slice");

    // Without routes, the same runtime materializes the L7 surface only.
    let mut routeless = slice;
    routeless.http_routes = Default::default();
    let prepared = prepare_gateway_config_from_mesh_slice(&routeless, &runtime)
        .expect("a routeless slice materializes");
    assert!(
        prepared
            .proxies
            .iter()
            .any(|proxy| is_service_waypoint_l7_route_id(&proxy.id))
    );
}

// ── `mesh_route_admitted_for_direction` on every direct inbound listener ──

fn routed_proxy_id(
    prepared: &GatewayConfig,
    host: &str,
    path: &str,
    direction: Option<MeshTrafficDirection>,
) -> Option<String> {
    let cache = RouterCache::new(prepared, 1024);
    match cache.resolve_mesh_scoped_route_for_test(
        Some(host),
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
fn carried_and_default_l7_routes_are_never_served_on_a_direct_inbound_listener() {
    let runtime = service_waypoint_runtime();
    let (_, prepared) = prepared_service_waypoint(&runtime);
    assert!(
        prepared
            .proxies
            .iter()
            .any(|proxy| proxy.id.starts_with("istio-vs-")),
        "fixture: the ServiceWaypoint holds carried routes"
    );
    for (route_host, path) in [
        (host("reviews", WAYPOINT_NAMESPACE), "/"),
        (host("reviews", WAYPOINT_NAMESPACE), "/api"),
        ("reviews".to_string(), "/"),
        (host("orders", TENANT_NAMESPACE), "/api/orders"),
    ] {
        assert_eq!(
            routed_proxy_id(
                &prepared,
                &route_host,
                path,
                Some(MeshTrafficDirection::Inbound)
            ),
            None,
            "a direct request on the ServiceWaypoint :15008 listener for {route_host}{path} \
             reaches neither a carried istio-vs route nor a default L7 route"
        );
        // The default L7 routes are not in the shared tiers on any listener.
        let unscoped = routed_proxy_id(&prepared, &route_host, path, None);
        assert!(
            unscoped
                .as_deref()
                .is_none_or(|id| !is_service_waypoint_l7_route_id(id)),
            "the default L7 route is reachable only through its partition: {unscoped:?}"
        );
    }

    // The NodeWaypoint and Sidecar inbound listeners keep refusing carried
    // routes too.
    let config = cp_config(Some(binding("service")), &default_virtual_services());
    for topology in [MeshTopology::NodeWaypoint, MeshTopology::Sidecar] {
        let runtime = runtime_for_topology(topology);
        let slice = MeshSlice::from_gateway_config(&config, runtime.mesh_slice_request());
        let prepared =
            prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
        let routed = routed_proxy_id(
            &prepared,
            &host("reviews", WAYPOINT_NAMESPACE),
            "/",
            Some(MeshTrafficDirection::Inbound),
        );
        assert!(
            routed
                .as_deref()
                .is_none_or(|id| !id.starts_with("istio-vs-")),
            "{topology:?} inbound serves no carried route: {routed:?}"
        );
    }
}

#[test]
fn service_waypoint_carries_no_node_waypoint_capture_inventory() {
    let request = service_waypoint_runtime().mesh_slice_request();
    let slice = served_slice(
        &cp_config(Some(binding("service")), &default_virtual_services()),
        &request,
    );
    assert!(slice.node_waypoint_capture_destinations.is_empty());
    assert!(!slice.http_routes.is_empty());
}

// ── `GET /service-waypoint/services` ───────────────────────────────────────

mod admin_endpoint {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use ferrum_edge::admin::{
        AdminState,
        jwt_auth::{JwtConfig, JwtManager},
        serve_admin_on_listener,
    };
    use ferrum_edge::config::{EnvConfig, OperatingMode};
    use ferrum_edge::dns::{DnsCache, DnsConfig};
    use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
    use ferrum_edge::modes::mesh::service_waypoint_l7::is_service_waypoint_l7_route_id;
    use ferrum_edge::proxy::ProxyState;
    use ferrum_edge::time_compat::UtcTimestamp;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::{Value, json};

    use crate::scaffolding::port_registry::TestSocket;

    use super::{
        TENANT_NAMESPACE, WAYPOINT_NAMESPACE, prepared_service_waypoint, service_waypoint_runtime,
    };

    const ADMIN_JWT_SECRET: &str = "service-waypoint-l7-admin-test-secret-32b";
    const ADMIN_JWT_ISSUER: &str = "ferrum-edge-test";

    fn mint_admin_token() -> String {
        let now = UtcTimestamp::now();
        let claims = json!({
            "iss": ADMIN_JWT_ISSUER,
            "sub": "service-waypoint-operator",
            "iat": now.unix_timestamp(),
            "nbf": now.unix_timestamp(),
            "exp": (now.checked_add(::time::SignedDuration::seconds(1800)).unwrap()).unix_timestamp(),
            "jti": uuid::Uuid::new_v4().to_string(),
            "role": "admin",
        });
        encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(ADMIN_JWT_SECRET.as_bytes()).unwrap(),
        )
        .expect("encode admin JWT")
    }

    fn admin_state(proxy_state: ProxyState, mesh_runtime_state: MeshRuntimeState) -> AdminState {
        AdminState {
            db: None,
            jwt_manager: JwtManager::new(JwtConfig {
                secret: ADMIN_JWT_SECRET.to_string(),
                issuer: ADMIN_JWT_ISSUER.to_string(),
                audience: None,
                max_ttl_seconds: 3600,
                algorithm: jsonwebtoken::Algorithm::HS256,
            }),
            metrics_auth: Default::default(),
            cached_config: None,
            proxy_state: Some(proxy_state),
            mode: "mesh".to_string(),
            read_only: true,
            admin_audit_enabled: false,
            admin_audit_fallback_dir: None,
            admin_require_namespace_claim: false,
            startup_ready: None,
            serving_degraded: None,
            serving_listener_failures: None,
            gateway_listener_status: None,
            gateway_listener_failure_fails_readiness: false,
            db_available: None,
            config_rejected: None,
            admin_restore_max_body_size_mib: 100,
            admin_spec_max_body_size_mib: 25,
            reserved_ports: std::collections::HashSet::new(),
            stream_proxy_bind_address: "0.0.0.0".to_string(),
            admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
            cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
            db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
            dp_registry: None,
            mesh_registry: None,
            cp_connection_state: None,
            admin_http_header_read_timeout_seconds: 10,
            mesh_runtime_state: Some(mesh_runtime_state),
            admin_tls_handshake_timeout_seconds: 10,
            admin_request_limits: Default::default(),
            backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
            external_ref_policy: Arc::new(
                ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
            ),
            external_ref_loader: Arc::new(
                ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
            ),
            runtime_config_apply: None,
        }
    }

    async fn start_admin(state: AdminState) -> (u16, tokio::sync::watch::Sender<bool>) {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let listener = tokio::net::TcpListener::bind_test(addr).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = serve_admin_on_listener(
                listener,
                state,
                shutdown_rx,
                None,
                ferrum_edge::admin::AdminConnLimiter::unlimited(),
            )
            .await;
        });
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        (port, shutdown_tx)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_waypoint_services_reports_l7_ports_and_route_counts() {
        let runtime = service_waypoint_runtime();
        let (slice, prepared) = prepared_service_waypoint(&runtime);
        let env_config = EnvConfig {
            mode: OperatingMode::Mesh,
            log_level: "error".to_string(),
            proxy_http_port: 0,
            proxy_https_port: 0,
            admin_http_port: 0,
            admin_https_port: 0,
            shutdown_drain_seconds: 0,
            max_connections: 0,
            namespace: runtime.namespace.clone(),
            ..EnvConfig::default()
        };
        let (proxy_state, _handles) = ProxyState::new(
            prepared,
            DnsCache::new(DnsConfig::default()),
            env_config,
            None,
            None,
        )
        .expect("the ServiceWaypoint generation is accepted by the proxy runtime");
        let live = proxy_state.router_cache.service_waypoint_l7_routes();
        assert!(
            live.partitions()
                .all(|partition| is_service_waypoint_l7_route_id(&partition.default_route.id)),
            "the serving generation carries the partitions"
        );
        assert!(!live.is_empty());

        let mesh_runtime_state = MeshRuntimeState::new();
        {
            let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
            mesh_runtime_state.install_slice(slice.clone());
            let token = mesh_runtime_state.begin_revision_apply(&slice);
            assert!(mesh_runtime_state.record_applied_slice_with_token(&slice, token));
        }
        let (port, _shutdown) = start_admin(admin_state(proxy_state, mesh_runtime_state)).await;

        let response = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{port}/service-waypoint/services"))
            .header("Authorization", format!("Bearer {}", mint_admin_token()))
            .send()
            .await
            .expect("GET /service-waypoint/services");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body: Value = response.json().await.expect("JSON body");
        let services = body["services"].as_array().expect("services array");
        let entry = |namespace: &str, name: &str| {
            services
                .iter()
                .find(|service| service["namespace"] == namespace && service["name"] == name)
                .unwrap_or_else(|| panic!("{namespace}/{name} is listed"))
                .clone()
        };
        let reviews = entry(WAYPOINT_NAMESPACE, "reviews");
        assert_eq!(reviews["l7_http_ports"], json!([8080]));
        assert!(
            reviews["virtual_service_route_count"]
                .as_u64()
                .is_some_and(|count| count >= 1),
            "the split route on reviews attaches to reviews"
        );
        let ratings = entry(WAYPOINT_NAMESPACE, "ratings");
        assert_eq!(ratings["l7_http_ports"], json!([8080]));
        assert_eq!(
            ratings["virtual_service_route_count"],
            json!(0),
            "a split leg does not attach the route to its destination Service"
        );
        let orders = entry(TENANT_NAMESPACE, "orders");
        assert_eq!(orders["l7_http_ports"], json!([8080]));
        assert!(
            orders["virtual_service_route_count"]
                .as_u64()
                .is_some_and(|count| count >= 1),
            "the tenant's own route attaches to orders"
        );
        for service in services {
            let fields: Vec<&str> = service
                .as_object()
                .expect("service entry object")
                .keys()
                .map(String::as_str)
                .collect();
            let mut fields = fields;
            fields.sort_unstable();
            assert_eq!(
                fields,
                vec![
                    "l7_http_ports",
                    "name",
                    "namespace",
                    "ports",
                    "virtual_service_route_count",
                    "workload_count",
                ],
                "the entry matches the closed openapi schema and exposes no route rules"
            );
        }
    }
}
