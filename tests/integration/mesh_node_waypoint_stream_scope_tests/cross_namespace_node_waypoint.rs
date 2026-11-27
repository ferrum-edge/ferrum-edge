//! Cross-namespace VirtualService `http[]` destinations on a NodeWaypoint
//! (issue #7499).
//!
//! A NodeWaypoint judges a carried route's destination policy itself, so an
//! authorized destination Service in another namespace rides its slice with
//! that namespace's AuthorizationPolicy and RequestAuthentication resources
//! selecting the destination workloads, and the route is authorized against
//! them: per route destination, per dispatch branch and per weighted-split
//! leg. These tests drive the production halves: K8s translation (with the
//! ReferenceGrant), CP filtering and slice projection, data-plane slice
//! preparation, the `mesh_authz` plugin built from that config, and the
//! production `before_proxy` chain.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ferrum_edge::_test_support::{
    filter_config_to_mesh_request_for_test, install_plugin_finalizers_for_test,
    run_before_proxy_hooks_for_test,
};
use ferrum_edge::config::types::{GatewayConfig, LoadBalancerAlgorithm, PluginScope, Proxy};
use ferrum_edge::grpc::cp_server::CpScope;
use ferrum_edge::identity::spiffe::SpiffeId;
use ferrum_edge::modes::mesh::config::{
    MeshJwtRule, MeshPolicy, MeshRequestAuthentication, PolicyScope, WorkloadSelector,
};
use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::modes::mesh::{
    MESH_AUTHZ_PLUGIN_ID, MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX,
    prepare_gateway_config_from_mesh_slice,
};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, create_plugin};
use serde_json::{Value, json};

use super::super::mesh_test_support::{DEFAULT_NAMESPACE, policy_allow_principal};
use super::cross_namespace_routes::{
    CLONE_PREFIX, OTHER, RATINGS_OTHER, assert_references_resolve, branch_spec, carried_routes,
    destination_rule, direct_spec, ninety_ten_spec, node_waypoint_runtime, ratings_source,
    route_ids, sidecar_runtime, slice_for, translated, upstream, virtual_service,
};

const TRUSTED: &str = "spiffe://cluster.local/ns/default/sa/trusted";
const UNTRUSTED: &str = "spiffe://cluster.local/ns/default/sa/untrusted";
const DENIED_BODY: &str = r#"{"error":"Mesh authorization denied"}"#;

fn selector(app: &str) -> PolicyScope {
    PolicyScope::WorkloadSelector {
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), app.to_string())]),
            namespace: None,
        },
    }
}

/// `other`'s own policy: only `TRUSTED` reaches `app=ratings`.
fn ratings_trusted_only() -> MeshPolicy {
    policy_allow_principal("ratings-trusted-only", OTHER, selector("ratings"), TRUSTED)
}

fn request_auth(name: &str, namespace: &str, app: &str) -> MeshRequestAuthentication {
    MeshRequestAuthentication {
        name: name.to_string(),
        namespace: namespace.to_string(),
        scope: selector(app),
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

/// The translated VirtualService (granted, `other/ratings` imported) with
/// `policies` and `request_authentications` in the mesh inventory.
fn config_with(
    spec: Value,
    extra: Vec<ferrum_edge::config_sources::k8s::K8sObject>,
    policies: Vec<MeshPolicy>,
    request_authentications: Vec<MeshRequestAuthentication>,
) -> GatewayConfig {
    let mut objects = vec![virtual_service("route", spec)];
    objects.extend(extra);
    let mut config = translated(objects);
    let mesh = config.mesh.as_mut().expect("mesh block");
    mesh.mesh_policies = policies;
    mesh.request_authentications = request_authentications;
    config
}

fn prepare(slice: &MeshSlice) -> GatewayConfig {
    let prepared = prepare_gateway_config_from_mesh_slice(slice, &node_waypoint_runtime())
        .expect("slice materializes");
    assert_references_resolve(&prepared);
    prepared
}

fn authz(prepared: &GatewayConfig) -> MeshAuthz {
    let config = prepared
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz injected")
        .config
        .clone();
    MeshAuthz::new(&config).expect("mesh_authz builds")
}

/// The production chain of `route`'s dispatch instance plus the cache-installed
/// dispatch finalizer.
fn route_dispatch(prepared: &GatewayConfig, route: &Proxy) -> Vec<Arc<dyn Plugin>> {
    let config = prepared
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.namespace == route.namespace
                && route
                    .plugins
                    .iter()
                    .any(|association| association.plugin_config_id == plugin.id)
        })
        .expect("the carried route keeps its dispatch rules");
    let mut plugins = vec![
        create_plugin("mesh_route_dispatch", &config.config)
            .expect("dispatch config constructs")
            .expect("built-in plugin"),
    ];
    install_plugin_finalizers_for_test(&mut plugins).expect("dispatch chain assembles");
    plugins
}

/// One request from `source` (a pod of `default`) on `route`, through
/// `mesh_authz` and then `plugins`' `before_proxy` chain.
async fn serve(
    authz: &MeshAuthz,
    plugins: &[Arc<dyn Plugin>],
    route: &Proxy,
    source: &str,
    v2: bool,
) -> (PluginResult, Option<PluginResult>, RequestContext) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    let identity = SpiffeId::new(source).expect("spiffe");
    ctx.peer_spiffe_id = Some(identity.clone());
    ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        identity,
        DEFAULT_NAMESPACE,
        HashMap::from([("app".to_string(), "client".to_string())]),
    )));
    ctx.matched_proxy = Some(Arc::new(route.clone()));
    let mut headers = HashMap::from([(
        "host".to_string(),
        "reviews.default.svc.cluster.local".to_string(),
    )]);
    if v2 {
        headers.insert("x-version".to_string(), "v2".to_string());
    }
    ctx.headers = headers.clone();
    let authorized = authz.authorize(&mut ctx).await;
    if !matches!(authorized, PluginResult::Continue) {
        return (authorized, None, ctx);
    }
    let dispatched = run_before_proxy_hooks_for_test(plugins, &mut ctx, &mut headers).await;
    (authorized, Some(dispatched), ctx)
}

fn assert_denied(result: &PluginResult, what: &str) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(*status_code, 403, "{what}");
            assert_eq!(body, DENIED_BODY, "{what}");
        }
        other => panic!("{what}: expected a 403 refusal, got {other:?}"),
    }
}

fn policy_names(slice: &MeshSlice) -> HashSet<(String, String)> {
    slice
        .mesh_policies
        .iter()
        .map(|policy| (policy.namespace.clone(), policy.name.clone()))
        .collect()
}

/// The CP filter and the slice builder carry the destination namespace's
/// AuthorizationPolicy and RequestAuthentication resources that select the
/// authorized destination's workloads to a NodeWaypoint, and nothing else of
/// that namespace or of any other; a Sidecar (which judges no destination
/// policy) gets none of them.
#[test]
fn a_node_waypoint_slice_carries_the_destination_namespace_policies() {
    let unrelated = policy_allow_principal("unrelated", OTHER, selector("unrelated"), TRUSTED);
    let third = policy_allow_principal("third", "gamma", selector("ratings"), TRUSTED);
    let config = config_with(
        direct_spec(RATINGS_OTHER),
        Vec::new(),
        vec![ratings_trusted_only(), unrelated, third],
        vec![
            request_auth("ratings-jwt", OTHER, "ratings"),
            request_auth("unrelated-jwt", OTHER, "unrelated"),
        ],
    );
    let runtime = node_waypoint_runtime();
    let request = runtime.mesh_slice_request();
    let scope = CpScope::Set(
        [DEFAULT_NAMESPACE, OTHER, "gamma"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    );
    let filtered = filter_config_to_mesh_request_for_test(&config, &request, &scope, None);
    for (case, slice) in [
        (
            "scoped control plane",
            MeshSlice::from_gateway_config(&filtered, request.clone()),
        ),
        ("unfiltered", slice_for(&config, &runtime)),
    ] {
        assert_eq!(route_ids(&slice).len(), 1, "{case}: the route rides");
        assert_eq!(
            slice.http_routes.authorized_cross_namespace_targets.len(),
            1,
            "{case}"
        );
        assert!(
            slice
                .workloads
                .iter()
                .any(|workload| workload.namespace == OTHER && workload.service_name == "ratings"),
            "{case}: the destination workloads ride"
        );
        let policies = policy_names(&slice);
        assert!(
            policies.contains(&(OTHER.to_string(), "ratings-trusted-only".to_string())),
            "{case}: the destination's own policy rides: {policies:?}"
        );
        assert!(
            !policies.contains(&(OTHER.to_string(), "unrelated".to_string()))
                && !policies.contains(&("gamma".to_string(), "third".to_string())),
            "{case}: nothing selecting no destination workload rides: {policies:?}"
        );
        let request_auths: Vec<&str> = slice
            .request_authentications
            .iter()
            .map(|resource| resource.name.as_str())
            .collect();
        assert_eq!(request_auths, vec!["ratings-jwt"], "{case}");
    }

    let sidecar = slice_for(&config, &sidecar_runtime());
    assert!(
        sidecar
            .mesh_policies
            .iter()
            .all(|policy| policy.namespace != OTHER),
        "a Sidecar judges no destination policy"
    );
    assert!(sidecar.request_authentications.is_empty());
}

/// Acceptance: an authorized cross-namespace direct destination routes
/// cleanly on a NodeWaypoint and is authorized against the destination
/// namespace's AuthorizationPolicy.
#[tokio::test]
async fn node_waypoint_routes_a_direct_destination_under_its_namespace_policy() {
    let config = config_with(
        direct_spec(RATINGS_OTHER),
        Vec::new(),
        vec![ratings_trusted_only()],
        Vec::new(),
    );
    let prepared = prepare(&slice_for(&config, &node_waypoint_runtime()));
    let routes = carried_routes(&prepared);
    assert_eq!(routes.len(), 1, "the route is served");
    let route = routes[0].clone();
    let clone_id = route.upstream_id.clone().expect("bound upstream");
    assert!(clone_id.starts_with(CLONE_PREFIX), "{clone_id}");
    let clone = upstream(&prepared, &clone_id);
    assert_eq!(clone.namespace, DEFAULT_NAMESPACE);
    let hosts: Vec<&str> = clone
        .targets
        .iter()
        .map(|target| target.host.as_str())
        .collect();
    assert_eq!(hosts, vec!["10.0.1.12"], "the destination workloads");
    for target in &clone.targets {
        assert_eq!(
            target
                .tags
                .get(ferrum_edge::config::types::UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG)
                .map(String::as_str),
            Some(OTHER),
            "the target names the destination Service's namespace"
        );
    }

    let authz = authz(&prepared);
    let (authorized, _, _) = serve(&authz, &[], &route, TRUSTED, false).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "the destination namespace's policy admits TRUSTED: {authorized:?}"
    );
    let (authorized, _, _) = serve(&authz, &[], &route, UNTRUSTED, false).await;
    assert_denied(&authorized, "the destination namespace's policy refuses");
}

/// Acceptance: a `mesh_route_dispatch` branch to an authorized
/// cross-namespace destination is authorized against that destination's
/// namespace policy, not the route's own destination's.
#[tokio::test]
async fn node_waypoint_authorizes_a_dispatch_branch_against_its_namespace_policy() {
    let config = config_with(
        branch_spec(),
        Vec::new(),
        vec![ratings_trusted_only()],
        Vec::new(),
    );
    let prepared = prepare(&slice_for(&config, &node_waypoint_runtime()));
    let routes = carried_routes(&prepared);
    assert_eq!(routes.len(), 1, "the merged route is served");
    let route = routes[0].clone();
    let authz = authz(&prepared);
    let dispatch = route_dispatch(&prepared, &route);

    let (authorized, dispatched, ctx) = serve(&authz, &dispatch, &route, TRUSTED, true).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "{authorized:?}"
    );
    assert!(
        matches!(dispatched, Some(PluginResult::Continue)),
        "the ratings branch admits TRUSTED: {dispatched:?}"
    );
    let selected = ctx
        .route_override_upstream_id
        .clone()
        .expect("the branch overrides the destination");
    assert!(selected.starts_with(CLONE_PREFIX), "{selected}");

    let (authorized, dispatched, _) = serve(&authz, &dispatch, &route, UNTRUSTED, true).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "the route's own destination (reviews) admits UNTRUSTED: {authorized:?}"
    );
    assert_denied(
        &dispatched.expect("dispatch ran"),
        "the cross-namespace branch keeps its namespace's policy",
    );

    // Without `x-version: v2` the request stays on reviews, which has no
    // policy.
    let (_, dispatched, _) = serve(&authz, &dispatch, &route, UNTRUSTED, false).await;
    assert!(matches!(dispatched, Some(PluginResult::Continue)));
}

/// Acceptance: a DestinationRule-governed 90/10 split with an authorized
/// cross-namespace leg is dispatched leg by leg on a NodeWaypoint, the leg
/// carries the destination namespace's DestinationRule, and authorization
/// lists the leg as its own candidate.
#[test]
fn node_waypoint_dispatches_a_destination_rule_governed_split() {
    let config = config_with(
        ninety_ten_spec(),
        vec![destination_rule(
            "ratings-dr",
            OTHER,
            RATINGS_OTHER,
            json!({"loadBalancer": {"simple": "RANDOM"}}),
        )],
        vec![ratings_trusted_only()],
        Vec::new(),
    );
    let prepared = prepare(&slice_for(&config, &node_waypoint_runtime()));
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
    assert_eq!((legs[0].1, legs[1].1), (90, 10));
    assert!(legs[0].0.contains("reviews"), "{legs:?}");
    assert!(legs[1].0.starts_with(CLONE_PREFIX), "{legs:?}");
    assert_eq!(
        upstream(&prepared, &legs[1].0).algorithm,
        LoadBalancerAlgorithm::Random,
        "the destination namespace's DestinationRule governs the leg"
    );
    assert_eq!(
        ratings_source(&prepared).algorithm,
        LoadBalancerAlgorithm::Random
    );
    let authz_config = &prepared
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz injected")
        .config;
    let destinations: Vec<&str> = authz_config["node_waypoint_route_branches"][0]["destinations"]
        .as_array()
        .expect("the legs are authorization candidates")
        .iter()
        .filter_map(|destination| destination["upstream_id"].as_str())
        .collect();
    assert!(
        destinations.contains(&legs[1].0.as_str()),
        "the cross-namespace leg is judged on its own: {destinations:?}"
    );
    assert!(
        authz_config["node_waypoint_route_upstreams"]
            .as_array()
            .expect("route upstreams")
            .iter()
            .any(|entry| entry["id"].as_str() == Some(legs[1].0.as_str())),
        "the leg resolves to the destination's workloads"
    );
}

/// Acceptance: RequestAuthentication on a NodeWaypoint route reaching an
/// authorized cross-namespace destination is the destination namespace's
/// resource selecting that destination.
#[test]
fn node_waypoint_scopes_request_authentication_to_the_destination_namespace() {
    let config = config_with(
        direct_spec(RATINGS_OTHER),
        Vec::new(),
        Vec::new(),
        vec![request_auth("ratings-jwt", OTHER, "ratings")],
    );
    let prepared = prepare(&slice_for(&config, &node_waypoint_runtime()));
    let route = carried_routes(&prepared)[0].clone();
    let association = route
        .plugins
        .iter()
        .find(|association| {
            association
                .plugin_config_id
                .starts_with(MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX)
        })
        .expect("the route gets its destination's RequestAuthentication");
    let plugin = prepared
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == association.plugin_config_id)
        .expect("destination instance exists");
    assert_eq!(plugin.plugin_name, "jwks_auth");
    assert_eq!(plugin.scope, PluginScope::ProxyGroup);
    assert_eq!(
        plugin.config["providers"][0]["issuer"],
        json!("https://ratings-jwt.example.com")
    );
}
