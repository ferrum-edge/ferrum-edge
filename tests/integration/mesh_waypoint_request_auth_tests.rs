//! RequestAuthentication on shared waypoints follows the destination workload
//! (issue #6670).
//!
//! A NodeWaypoint or ServiceWaypoint terminates requests for OTHER workloads,
//! so a RequestAuthentication selecting a destination (`app=api`) must be
//! carried to the waypoint and enforced for requests to that destination —
//! and only that destination — rather than being matched against the
//! waypoint's own identity.
//!
//! Coverage:
//!   - Publication: a waypoint slice carries destination-selecting resources;
//!     a Sidecar slice for an unrelated workload does not.
//!   - NodeWaypoint Service routes: the route to the selected destination gets
//!     a proxy-group `jwks_auth` instance with exactly that destination's
//!     providers; the route to an unrelated destination does not.
//!   - A refused destination resource refuses the route to that destination
//!     and leaves the unrelated route alone.
//!   - The waypoint's own set still governs routes whose destination set
//!     equals it, and Sidecar materialization is unchanged.

use std::collections::BTreeMap;

use ferrum_edge::config::types::{GatewayConfig, PluginScope, Proxy};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::config::{
    MeshJwtRule, MeshRequestAuthentication, NodeWaypointEndpoint, PolicyScope, Workload,
    WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::modes::mesh::{
    MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX, MESH_REQUEST_AUTH_PLUGIN_ID,
    MESH_REQUEST_AUTH_REFUSED_PLUGIN_ID, MeshRuntimeConfig, MeshTopology,
    prepare_gateway_config_from_mesh_slice,
};
use ferrum_edge::plugins::ProxyProtocol;
use ferrum_edge::proxy::ProxyState;

use super::mesh_test_support::{
    DEFAULT_NAMESPACE, gateway_config_with_mesh, mesh_config_with, mesh_slice_with,
    runtime_for_topology, service_for, workload_for,
};

fn request_auth(name: &str, scope: PolicyScope) -> MeshRequestAuthentication {
    MeshRequestAuthentication {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope,
        jwt_rules: vec![MeshJwtRule {
            issuer: format!("https://{name}.example.com"),
            audiences: Vec::new(),
            jwks_uri: None,
            jwks: Some(r#"{"keys":[]}"#.to_string()),
            from_headers: Vec::new(),
            from_params: Vec::new(),
            forward_original_token: false,
            output_claim_to_headers: Vec::new(),
        }],
        refused: false,
    }
}

fn refused_request_auth(name: &str, scope: PolicyScope) -> MeshRequestAuthentication {
    MeshRequestAuthentication {
        jwt_rules: Vec::new(),
        refused: true,
        ..request_auth(name, scope)
    }
}

fn selector(app: &str) -> PolicyScope {
    PolicyScope::WorkloadSelector {
        selector: WorkloadSelector {
            labels: [("app".to_string(), app.to_string())].into_iter().collect(),
            namespace: Some(DEFAULT_NAMESPACE.to_string()),
        },
    }
}

fn api_and_web() -> (Workload, Workload) {
    (
        workload_for("api", DEFAULT_NAMESPACE, [("app", "api")], ["10.0.0.11"]),
        workload_for("web", DEFAULT_NAMESPACE, [("app", "web")], ["10.0.0.12"]),
    )
}

fn node_waypoint_runtime() -> MeshRuntimeConfig {
    let mut runtime = runtime_for_topology(MeshTopology::NodeWaypoint);
    runtime.workload_spiffe_id =
        Some("spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint".to_string());
    runtime
}

fn prepare_node_waypoint(request_authentications: Vec<MeshRequestAuthentication>) -> GatewayConfig {
    let runtime = node_waypoint_runtime();
    let (api, web) = api_and_web();
    let services = vec![
        service_for("api", DEFAULT_NAMESPACE, &[&api]),
        service_for("web", DEFAULT_NAMESPACE, &[&web]),
    ];
    let slice = MeshSlice {
        request_authentications,
        ..mesh_slice_with(&runtime, vec![api, web], services, Vec::new())
    };
    prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("NodeWaypoint slice preparation must succeed")
}

/// The materialized NodeWaypoint Service route whose upstream reaches `service`.
fn service_route<'a>(config: &'a GatewayConfig, service: &str) -> &'a Proxy {
    let upstream = format!("__mesh-out-upstream-{DEFAULT_NAMESPACE}-{service}-8080");
    config
        .proxies
        .iter()
        .find(|proxy| proxy.upstream_id.as_deref() == Some(upstream.as_str()))
        .unwrap_or_else(|| {
            panic!(
                "no route to {service}; proxies: {:?}",
                config
                    .proxies
                    .iter()
                    .map(|proxy| (&proxy.id, &proxy.upstream_id))
                    .collect::<Vec<_>>()
            )
        })
}

/// Issuers of the destination `jwks_auth` instance attached to `route`, if any.
fn destination_issuers(config: &GatewayConfig, route: &Proxy) -> Option<Vec<String>> {
    let association = route.plugins.iter().find(|association| {
        association
            .plugin_config_id
            .starts_with(MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX)
    })?;
    let plugin = config
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.id == association.plugin_config_id && plugin.namespace == route.namespace
        })
        .expect("associated destination instance exists");
    assert_eq!(plugin.plugin_name, "jwks_auth");
    assert_eq!(plugin.scope, PluginScope::ProxyGroup);
    assert_eq!(plugin.config["allow_missing_token"], true);
    let mut issuers: Vec<String> = plugin.config["providers"]
        .as_array()
        .expect("providers")
        .iter()
        .map(|provider| provider["issuer"].as_str().expect("issuer").to_string())
        .collect();
    issuers.sort();
    Some(issuers)
}

fn global_request_auth_issuers(config: &GatewayConfig) -> Option<Vec<String>> {
    let plugin = config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)?;
    Some(
        plugin.config["providers"]
            .as_array()
            .expect("providers")
            .iter()
            .map(|provider| provider["issuer"].as_str().expect("issuer").to_string())
            .collect(),
    )
}

#[test]
fn node_waypoint_applies_destination_selector_only_to_that_destination() {
    let config = prepare_node_waypoint(vec![request_auth("api-jwt", selector("api"))]);

    assert_eq!(
        global_request_auth_issuers(&config),
        None,
        "the selector does not select the waypoint itself"
    );
    assert_eq!(
        destination_issuers(&config, service_route(&config, "api")),
        Some(vec!["https://api-jwt.example.com".to_string()]),
        "the route to app=api must validate app=api's tokens"
    );
    assert_eq!(
        destination_issuers(&config, service_route(&config, "web")),
        None,
        "the route to app=web must not carry app=api's providers"
    );
}

#[test]
fn node_waypoint_destination_instance_unions_namespace_and_selector_resources() {
    let namespace_wide = request_auth(
        "ns-jwt",
        PolicyScope::Namespace {
            namespace: DEFAULT_NAMESPACE.to_string(),
        },
    );
    let config = prepare_node_waypoint(vec![
        namespace_wide,
        request_auth("api-jwt", selector("api")),
    ]);

    // The waypoint's subscription namespace is `default`, so the
    // namespace-wide resource is its own set and stays global.
    assert_eq!(
        global_request_auth_issuers(&config),
        Some(vec!["https://ns-jwt.example.com".to_string()])
    );
    assert_eq!(
        destination_issuers(&config, service_route(&config, "api")),
        Some(vec![
            "https://api-jwt.example.com".to_string(),
            "https://ns-jwt.example.com".to_string(),
        ]),
        "app=api's route replaces the global set with its full destination set"
    );
    assert_eq!(
        destination_issuers(&config, service_route(&config, "web")),
        None,
        "app=web's destination set equals the global set, so it keeps the global instance"
    );
}

#[test]
fn node_waypoint_refused_destination_resource_refuses_only_that_route() {
    let config = prepare_node_waypoint(vec![refused_request_auth("api-jwt", selector("api"))]);

    let api_route = service_route(&config, "api");
    let web_route = service_route(&config, "web");
    assert_eq!(destination_issuers(&config, api_route), None);

    let refusal = config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == MESH_REQUEST_AUTH_REFUSED_PLUGIN_ID)
        .expect("a refused destination resource installs the refusal");
    assert_eq!(refusal.plugin_name, "request_termination");
    assert_eq!(refusal.config["status_code"], 503);
    let trigger = serde_json::to_value(
        refusal
            .trigger
            .as_ref()
            .expect("the refusal is scoped to the refused destination's routes"),
    )
    .expect("trigger serializes");
    let rendered = trigger.to_string();
    assert!(
        rendered.contains(&api_route.id),
        "refusal trigger must name the app=api route: {rendered}"
    );
    assert!(
        !rendered.contains(&web_route.id),
        "refusal trigger must not name the app=web route: {rendered}"
    );
}

/// The published chain replaces the global instance on the destination route
/// instead of running both: two `jwks_auth` instances would each reject the
/// other's issuer.
#[tokio::test]
async fn node_waypoint_destination_instance_replaces_the_global_instance_in_the_chain() {
    let namespace_wide = request_auth(
        "ns-jwt",
        PolicyScope::Namespace {
            namespace: DEFAULT_NAMESPACE.to_string(),
        },
    );
    let prepared = prepare_node_waypoint(vec![
        namespace_wide,
        request_auth("api-jwt", selector("api")),
    ]);
    let api_route = service_route(&prepared, "api").clone();
    let web_route = service_route(&prepared, "web").clone();
    let env_config = EnvConfig {
        mode: OperatingMode::Mesh,
        log_level: "error".to_string(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        namespace: DEFAULT_NAMESPACE.to_string(),
        ..EnvConfig::default()
    };
    let (state, _tasks) = ProxyState::new(
        prepared,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("the prepared NodeWaypoint config publishes");

    for route in [&api_route, &web_route] {
        let chain = state
            .plugin_cache
            .request_view(&route.namespace, &route.id, ProxyProtocol::Http)
            .plugins();
        let jwks_instances = chain
            .iter()
            .filter(|plugin| plugin.name() == "jwks_auth")
            .count();
        assert_eq!(
            jwks_instances, 1,
            "route {} must run exactly one RequestAuthentication instance",
            route.id
        );
    }
}

/// The waypoint's own providers must not govern a destination no resource
/// selects: they would reject that destination's tokens and mint principals
/// for it. The global instance is gated off that route.
#[test]
fn node_waypoint_global_instance_is_gated_off_destinations_without_resources() {
    let runtime = node_waypoint_runtime();
    let api = workload_for("api", DEFAULT_NAMESPACE, [("app", "api")], ["10.0.0.11"]);
    let web = workload_for("web", "other", [("app", "web")], ["10.0.0.12"]);
    let services = vec![
        service_for("api", DEFAULT_NAMESPACE, &[&api]),
        service_for("web", "other", &[&web]),
    ];
    let slice = MeshSlice {
        request_authentications: vec![request_auth(
            "ns-jwt",
            PolicyScope::Namespace {
                namespace: DEFAULT_NAMESPACE.to_string(),
            },
        )],
        ..mesh_slice_with(&runtime, vec![api, web], services, Vec::new())
    };
    let config = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("NodeWaypoint slice preparation must succeed");

    let web_upstream = "__mesh-out-upstream-other-web-8080";
    let web_route = config
        .proxies
        .iter()
        .find(|proxy| proxy.upstream_id.as_deref() == Some(web_upstream))
        .expect("route to other/web");
    let api_route = service_route(&config, "api");
    assert_eq!(destination_issuers(&config, web_route), None);
    let global = config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
        .expect("the namespace-wide resource selects the waypoint's own namespace");
    let trigger = serde_json::to_value(
        global
            .trigger
            .as_ref()
            .expect("the global instance is gated off other/web"),
    )
    .expect("trigger serializes")
    .to_string();
    assert!(trigger.contains("\"not\""), "{trigger}");
    assert!(trigger.contains(&web_route.id), "{trigger}");
    assert!(
        !trigger.contains(&api_route.id),
        "default/api is governed by the namespace-wide resource: {trigger}"
    );
}

/// Workloads behind one Service with different RequestAuthentication sets
/// cannot share one instance: the backend is chosen after authentication.
#[test]
fn node_waypoint_refuses_route_whose_workloads_disagree() {
    let runtime = node_waypoint_runtime();
    let v1 = workload_for(
        "api-v1",
        DEFAULT_NAMESPACE,
        [("app", "api"), ("version", "v1")],
        ["10.0.0.21"],
    );
    let v2 = workload_for(
        "api-v2",
        DEFAULT_NAMESPACE,
        [("app", "api"), ("version", "v2")],
        ["10.0.0.22"],
    );
    let (_, web) = api_and_web();
    let services = vec![
        service_for("api", DEFAULT_NAMESPACE, &[&v1, &v2]),
        service_for("web", DEFAULT_NAMESPACE, &[&web]),
    ];
    let v2_only = PolicyScope::WorkloadSelector {
        selector: WorkloadSelector {
            labels: [("version".to_string(), "v2".to_string())]
                .into_iter()
                .collect(),
            namespace: Some(DEFAULT_NAMESPACE.to_string()),
        },
    };
    let slice = MeshSlice {
        request_authentications: vec![request_auth("v2-jwt", v2_only)],
        ..mesh_slice_with(&runtime, vec![v1, v2, web], services, Vec::new())
    };
    let config = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("NodeWaypoint slice preparation must succeed");

    let api_route = service_route(&config, "api");
    let web_route = service_route(&config, "web");
    assert_eq!(
        destination_issuers(&config, api_route),
        None,
        "no union instance may be installed for workloads that disagree"
    );
    let refusal = config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == MESH_REQUEST_AUTH_REFUSED_PLUGIN_ID)
        .expect("the disagreeing route is refused");
    let trigger = serde_json::to_value(refusal.trigger.as_ref().expect("scoped refusal"))
        .expect("trigger serializes")
        .to_string();
    assert!(trigger.contains(&api_route.id), "{trigger}");
    assert!(!trigger.contains(&web_route.id), "{trigger}");
}

/// A destination whose providers one `jwks_auth` instance cannot verify (here
/// nine sharing one issuer, over the per-issuer candidate bound) refuses its
/// routes instead of vetoing the whole generation.
#[test]
fn node_waypoint_refuses_destination_over_the_provider_bound() {
    let mut over_bound = request_auth("api-jwt", selector("api"));
    let rule = over_bound.jwt_rules[0].clone();
    over_bound.jwt_rules = (0..9)
        .map(|index| MeshJwtRule {
            audiences: vec![format!("aud-{index}")],
            ..rule.clone()
        })
        .collect();
    let config = prepare_node_waypoint(vec![over_bound]);

    let api_route = service_route(&config, "api");
    let web_route = service_route(&config, "web");
    assert_eq!(destination_issuers(&config, api_route), None);
    let refusal = config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == MESH_REQUEST_AUTH_REFUSED_PLUGIN_ID)
        .expect("the over-bound destination is refused");
    let trigger = serde_json::to_value(refusal.trigger.as_ref().expect("scoped refusal"))
        .expect("trigger serializes")
        .to_string();
    assert!(trigger.contains(&api_route.id), "{trigger}");
    assert!(!trigger.contains(&web_route.id), "{trigger}");
}

/// A secured NodeWaypoint never dials a Service workload without NodeWaypoint
/// metadata, so that workload's (empty) set does not make the route disagree.
#[test]
fn node_waypoint_secured_transport_ignores_unreachable_workloads() {
    let mut runtime = node_waypoint_runtime();
    runtime.workload_svid_cert_path = Some("/var/run/secrets/svid.pem".to_string());
    runtime.workload_svid_key_path = Some("/var/run/secrets/svid.key".to_string());
    runtime.workload_svid_trust_bundle_path = Some("/var/run/secrets/bundle.pem".to_string());
    let mut enrolled = workload_for(
        "api-v1",
        DEFAULT_NAMESPACE,
        [("app", "api"), ("version", "v1")],
        ["10.0.0.21"],
    );
    enrolled.node_waypoint = Some(NodeWaypointEndpoint {
        address: "192.0.2.10".to_string(),
        hbone_port: 15008,
        spiffe_id: enrolled.spiffe_id.clone(),
        node_name: None,
        node_uid: None,
        network: None,
        cluster: None,
    });
    let unenrolled = workload_for(
        "api-v2",
        DEFAULT_NAMESPACE,
        [("app", "api"), ("version", "v2")],
        ["10.0.0.22"],
    );
    let services = vec![service_for(
        "api",
        DEFAULT_NAMESPACE,
        &[&enrolled, &unenrolled],
    )];
    let v1_only = PolicyScope::WorkloadSelector {
        selector: WorkloadSelector {
            labels: [("version".to_string(), "v1".to_string())]
                .into_iter()
                .collect(),
            namespace: Some(DEFAULT_NAMESPACE.to_string()),
        },
    };
    let slice = MeshSlice {
        request_authentications: vec![request_auth("v1-jwt", v1_only)],
        ..mesh_slice_with(&runtime, vec![enrolled, unenrolled], services, Vec::new())
    };
    let config = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("NodeWaypoint slice preparation must succeed");

    assert_eq!(
        destination_issuers(&config, service_route(&config, "api")),
        Some(vec!["https://v1-jwt.example.com".to_string()]),
        "only the enrolled workload is reachable, so its set governs the route"
    );
    assert!(
        config
            .plugin_configs
            .iter()
            .all(|plugin| plugin.id != MESH_REQUEST_AUTH_REFUSED_PLUGIN_ID),
        "the route must not be refused for an unreachable workload"
    );
}

#[test]
fn sidecar_materialization_ignores_destination_resources() {
    let runtime = runtime_for_topology(MeshTopology::Sidecar);
    let (api, web) = api_and_web();
    let services = vec![
        service_for("api", DEFAULT_NAMESPACE, &[&api]),
        service_for("web", DEFAULT_NAMESPACE, &[&web]),
    ];
    let slice = MeshSlice {
        request_authentications: vec![request_auth("api-jwt", selector("api"))],
        ..mesh_slice_with(&runtime, vec![api, web], services, Vec::new())
    };
    let config = prepare_gateway_config_from_mesh_slice(&slice, &runtime)
        .expect("Sidecar slice preparation must succeed");

    assert!(
        config.plugin_configs.iter().all(|plugin| !plugin
            .id
            .starts_with(MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX)),
        "a Sidecar enforces only its own resources"
    );
    assert!(
        config
            .proxies
            .iter()
            .flat_map(|proxy| proxy.plugins.iter())
            .all(|association| !association
                .plugin_config_id
                .starts_with(MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX))
    );
}

fn slice_request(namespace: &str) -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: "node".to_string(),
        namespace: namespace.to_string(),
        cluster_domain: "cluster.local".to_string(),
        ..MeshSliceRequest::default()
    }
}

fn published_request_auth_names(
    request: MeshSliceRequest,
    resources: Vec<MeshRequestAuthentication>,
) -> Vec<String> {
    let (api, web) = api_and_web();
    let mesh = ferrum_edge::modes::mesh::config::MeshConfig {
        request_authentications: resources,
        ..mesh_config_with(
            vec![api.clone(), web.clone()],
            vec![
                service_for("api", DEFAULT_NAMESPACE, &[&api]),
                service_for("web", DEFAULT_NAMESPACE, &[&web]),
            ],
            Vec::new(),
        )
    };
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let mut names: Vec<String> = MeshSlice::from_gateway_config(&config, request)
        .request_authentications
        .into_iter()
        .map(|resource| resource.name)
        .collect();
    names.sort();
    names
}

#[test]
fn waypoint_slices_carry_destination_request_authentications() {
    let resources = || {
        vec![
            request_auth("api-jwt", selector("api")),
            request_auth("unmatched-jwt", selector("nothing")),
        ]
    };

    let node_waypoint = slice_request(DEFAULT_NAMESPACE).with_node_waypoint_capture_scoping(true);
    assert_eq!(
        published_request_auth_names(node_waypoint, resources()),
        vec!["api-jwt".to_string()],
        "a NodeWaypoint slice carries resources selecting the workloads it fronts, and no others"
    );

    let service_waypoint = MeshSliceRequest {
        waypoint_name: Some("waypoint".to_string()),
        ..slice_request(DEFAULT_NAMESPACE)
    };
    assert_eq!(
        published_request_auth_names(service_waypoint, resources()),
        vec!["api-jwt".to_string()]
    );

    let web_sidecar = MeshSliceRequest {
        workload_spiffe_id: Some("spiffe://cluster.local/ns/default/sa/web".to_string()),
        labels: BTreeMap::from([("app".to_string(), "web".to_string())]),
        ..slice_request(DEFAULT_NAMESPACE)
    };
    assert!(
        published_request_auth_names(web_sidecar, resources()).is_empty(),
        "a Sidecar slice carries only the resources selecting its own workload"
    );
}
