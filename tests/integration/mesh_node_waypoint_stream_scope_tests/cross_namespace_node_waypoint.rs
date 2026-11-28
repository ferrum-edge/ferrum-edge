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

// ---------------------------------------------------------------------------
// Two NodeWaypoints, cross-namespace (issue #7499).
//
// The source pods (`default/client`, `default/intruder`, `gamma/client`) are
// enrolled on NodeWaypoint A; the destination `other/ratings` on NodeWaypoint
// B, on another node. A applies the carried route and dials B over HBONE,
// pinned to B's identity, asserting the source pod's principal in baggage. B
// relays to `ratings` and authorizes the relay against `other`'s policy for
// the destination workload, with the asserted principal when it trusts A to
// assert it (its slice's assertor inventory, derived from the workloads A
// fronts). The destination namespace's policy is therefore evaluated twice,
// once on each waypoint, and these tests prove the two decisions agree for
// ALLOW and DENY by source principal and by source namespace.

const WAYPOINT_A: &str = "spiffe://cluster.local/ns/ferrum/sa/node-waypoint-a";
const WAYPOINT_B: &str = "spiffe://cluster.local/ns/ferrum/sa/node-waypoint-b";
const WAYPOINT_C: &str = "spiffe://cluster.local/ns/ferrum/sa/node-waypoint-c";
const CLIENT: &str = "spiffe://cluster.local/ns/default/sa/client";
const INTRUDER: &str = "spiffe://cluster.local/ns/default/sa/intruder";
const GAMMA_CLIENT: &str = "spiffe://cluster.local/ns/gamma/sa/client";
const RATINGS_ADDRESS: &str = "10.0.1.12";

fn node_waypoint_endpoint(
    spiffe: &str,
    address: &str,
    node: &str,
) -> ferrum_edge::modes::mesh::config::NodeWaypointEndpoint {
    ferrum_edge::modes::mesh::config::NodeWaypointEndpoint {
        address: address.to_string(),
        hbone_port: 15008,
        spiffe_id: SpiffeId::new(spiffe).expect("node waypoint SPIFFE ID"),
        node_name: Some(node.to_string()),
        node_uid: Some(format!("{node}-uid")),
        network: None,
        cluster: None,
    }
}

/// A rule matching one source principal or one source namespace.
fn source_rule(
    principal: Option<&str>,
    namespace: Option<&str>,
    action: ferrum_edge::modes::mesh::config::PolicyAction,
) -> ferrum_edge::modes::mesh::config::MeshRule {
    use ferrum_edge::identity::spiffe::TrustDomain;
    use ferrum_edge::modes::mesh::config::{MeshRule, PrincipalMatch};
    MeshRule {
        from: vec![PrincipalMatch {
            spiffe_id_pattern: principal.map(str::to_string),
            namespace_pattern: namespace.map(str::to_string),
            trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
            trust_domain_pattern: None,
        }],
        to: Vec::new(),
        when: Vec::new(),
        request_principals: Vec::new(),
        not_request_principals: Vec::new(),
        source_negation: Default::default(),
        never_matches: false,
        action,
    }
}

fn ratings_policy(
    name: &str,
    rules: Vec<ferrum_edge::modes::mesh::config::MeshRule>,
) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: OTHER.to_string(),
        scope: selector("ratings"),
        rules,
    }
}

/// `other`'s policy by namespace and principal: ALLOW sources from
/// `default`, DENY `default/intruder`.
fn allow_namespace_deny_principal() -> Vec<MeshPolicy> {
    use ferrum_edge::modes::mesh::config::PolicyAction;
    vec![
        ratings_policy(
            "allow-default",
            vec![source_rule(None, Some("default"), PolicyAction::Allow)],
        ),
        ratings_policy(
            "deny-intruder",
            vec![source_rule(Some(INTRUDER), None, PolicyAction::Deny)],
        ),
    ]
}

/// `other`'s policy by principal and namespace: ALLOW `default/client` and
/// `gamma/client`, DENY every source from `gamma`.
fn allow_principal_deny_namespace() -> Vec<MeshPolicy> {
    use ferrum_edge::modes::mesh::config::PolicyAction;
    vec![
        ratings_policy(
            "allow-clients",
            vec![
                source_rule(Some(CLIENT), None, PolicyAction::Allow),
                source_rule(Some(GAMMA_CLIENT), None, PolicyAction::Allow),
            ],
        ),
        ratings_policy(
            "deny-gamma",
            vec![source_rule(None, Some("gamma"), PolicyAction::Deny)],
        ),
    ]
}

/// The granted direct route to `other/ratings`, `ratings` enrolled on B and
/// the three sources enrolled on A.
fn two_waypoint_config(policies: Vec<MeshPolicy>) -> GatewayConfig {
    use super::super::mesh_test_support::workload_for;

    let mut config = config_with(direct_spec(RATINGS_OTHER), Vec::new(), policies, Vec::new());
    let mesh = config.mesh.as_mut().expect("mesh block");
    for workload in &mut mesh.workloads {
        if workload.namespace == OTHER && workload.service_name == "ratings" {
            workload.node_waypoint =
                Some(node_waypoint_endpoint(WAYPOINT_B, "10.9.0.2", "worker-b"));
        }
    }
    for (name, namespace, address) in [
        ("client", DEFAULT_NAMESPACE, "10.0.0.21"),
        ("intruder", DEFAULT_NAMESPACE, "10.0.0.22"),
        ("client", "gamma", "10.0.3.21"),
    ] {
        let mut source = workload_for(name, namespace, [("app", "client")], [address]);
        source.node_waypoint = Some(node_waypoint_endpoint(WAYPOINT_A, "10.9.0.1", "worker-a"));
        mesh.workloads.push(source);
    }
    config
}

/// An identity-backed NodeWaypoint (secured HBONE transport) subscribing in
/// `namespace` as `identity`.
fn identity_backed_node_waypoint(
    identity: &str,
    namespace: &str,
) -> ferrum_edge::modes::mesh::MeshRuntimeConfig {
    ferrum_edge::modes::mesh::MeshRuntimeConfig {
        namespace: namespace.to_string(),
        workload_spiffe_id: Some(identity.to_string()),
        workload_svid_cert_path: Some("/var/run/ferrum/svid.pem".to_string()),
        workload_svid_key_path: Some("/var/run/ferrum/svid.key".to_string()),
        workload_svid_trust_bundle_path: Some("/var/run/ferrum/bundle.pem".to_string()),
        ..node_waypoint_runtime()
    }
}

fn scope(namespaces: &[&str]) -> CpScope {
    CpScope::Set(
        namespaces
            .iter()
            .map(|namespace| namespace.to_string())
            .collect(),
    )
}

/// Waypoint A's prepared config, from its control-plane-filtered slice.
fn prepare_source_waypoint(config: &GatewayConfig) -> GatewayConfig {
    let runtime = identity_backed_node_waypoint(WAYPOINT_A, DEFAULT_NAMESPACE);
    let request = runtime.mesh_slice_request();
    let filtered = filter_config_to_mesh_request_for_test(
        config,
        &request,
        &scope(&[DEFAULT_NAMESPACE, OTHER, "gamma", "ferrum"]),
        None,
    );
    let slice = MeshSlice::from_gateway_config(&filtered, request);
    let prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("waypoint A materializes");
    assert_references_resolve(&prepared);
    prepared
}

/// Waypoint B's prepared config, from its control-plane-filtered slice under
/// `cp_scope`.
fn prepare_destination_waypoint(config: &GatewayConfig, cp_scope: &CpScope) -> GatewayConfig {
    let runtime = identity_backed_node_waypoint(WAYPOINT_B, "ferrum");
    let request = runtime.mesh_slice_request();
    let filtered = filter_config_to_mesh_request_for_test(config, &request, cp_scope, None);
    let slice = MeshSlice::from_gateway_config(&filtered, request);
    assert!(
        slice
            .node_waypoint_capture_destinations
            .iter()
            .any(|workload| workload.namespace == OTHER && workload.service_name == "ratings"),
        "B terminates capture for ratings"
    );
    prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("waypoint B materializes")
}

/// A's decision for a `GET` from `source` on its carried route to
/// `other/ratings`.
async fn source_waypoint_allows(authz: &MeshAuthz, route: &Proxy, source: &str) -> PluginResult {
    source_waypoint_allows_method(authz, route, source, "GET").await
}

/// A's decision for a `method` request from `source` on its carried route to
/// `other/ratings`.
async fn source_waypoint_allows_method(
    authz: &MeshAuthz,
    route: &Proxy,
    source: &str,
    method: &str,
) -> PluginResult {
    let identity = SpiffeId::new(source).expect("spiffe");
    let namespace = identity.namespace().expect("namespaced source").to_string();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        "/api".to_string(),
    );
    ctx.peer_spiffe_id = Some(identity.clone());
    ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        identity,
        &namespace,
        HashMap::from([("app".to_string(), "client".to_string())]),
    )));
    ctx.matched_proxy = Some(Arc::new(route.clone()));
    ctx.headers = HashMap::from([(
        "host".to_string(),
        "reviews.default.svc.cluster.local".to_string(),
    )]);
    authz.authorize(&mut ctx).await
}

/// B's decision for an HBONE relay from `peer` asserting `asserted`, to
/// `ratings`, in the production relay context: an opaque CONNECT tunnel
/// (`mark_hbone_connect_relay`, as `hbone_proxy` tags it), never judged on
/// the CONNECT's own method or path. Returns the result and the recorded deny
/// policy.
async fn destination_waypoint_relays(
    authz: &MeshAuthz,
    peer: &str,
    asserted: &str,
) -> (PluginResult, Option<String>) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "CONNECT".to_string(),
        "/".to_string(),
    );
    ctx.peer_spiffe_id = Some(SpiffeId::new(peer).expect("spiffe"));
    ctx.mesh_direction = Some(ferrum_edge::modes::mesh::MeshTrafficDirection::Inbound);
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    ctx.mark_hbone_connect_relay();
    ctx.headers.insert(
        "baggage".to_string(),
        ferrum_edge::modes::mesh::hbone::baggage_header_for_source(
            &SpiffeId::new(asserted).expect("spiffe"),
        ),
    );
    ctx.matched_proxy = Some(Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "__mesh-inbound-hbone-relay",
            "namespace": "ferrum",
            "hosts": [],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": RATINGS_ADDRESS,
            "backend_port": 8080
        }))
        .expect("relay proxy"),
    ));
    let result = authz.authorize(&mut ctx).await;
    let deny_policy = ctx.metadata.get("mesh_authz.deny_policy").cloned();
    (result, deny_policy)
}

fn allowed(result: &PluginResult) -> bool {
    match result {
        PluginResult::Continue => true,
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(*status_code, 403, "a refusal is a 403: {result:?}");
            false
        }
        other => panic!("unexpected authorization outcome {other:?}"),
    }
}

/// Acceptance (cross-node NodeWaypoint trust): A dials B over HBONE pinned to
/// B, B trusts A's assertion of each source A fronts, and both waypoints
/// reach the same decision under the destination namespace's policy, for
/// ALLOW and DENY by source principal and by source namespace.
#[tokio::test]
async fn two_node_waypoints_agree_on_the_destination_namespace_policy() {
    for (case, policies, expectations) in [
        (
            "ALLOW by namespace, DENY by principal",
            allow_namespace_deny_principal(),
            [
                (CLIENT, true, None),
                (INTRUDER, false, Some("deny-intruder")),
                (GAMMA_CLIENT, false, None),
            ],
        ),
        (
            "ALLOW by principal, DENY by namespace",
            allow_principal_deny_namespace(),
            [
                (CLIENT, true, None),
                (GAMMA_CLIENT, false, Some("deny-gamma")),
                (INTRUDER, false, None),
            ],
        ),
    ] {
        let config = two_waypoint_config(policies);

        // Waypoint A: the carried route dials B over HBONE, pinned to B.
        let source = prepare_source_waypoint(&config);
        let routes = carried_routes(&source);
        assert_eq!(routes.len(), 1, "{case}: A serves the route");
        let route = routes[0].clone();
        let clone = upstream(&source, route.upstream_id.as_deref().expect("bound"));
        assert!(clone.id.starts_with(CLONE_PREFIX), "{case}");
        for target in &clone.targets {
            assert_eq!(target.host, RATINGS_ADDRESS, "{case}: inner authority");
            assert_eq!(
                target.tags.get("mesh.hbone").map(String::as_str),
                Some("true"),
                "{case}: over HBONE"
            );
            assert_eq!(
                target.tags.get("mesh.hbone_dial_host").map(String::as_str),
                Some("10.9.0.2"),
                "{case}: to B's node"
            );
            assert_eq!(
                target
                    .tags
                    .get("mesh.hbone_peer_spiffe_id")
                    .map(String::as_str),
                Some(WAYPOINT_B),
                "{case}: pinned to B"
            );
        }
        let source_authz = authz(&source);

        // Waypoint B trusts A to assert exactly the sources A fronts.
        let destination = prepare_destination_waypoint(
            &config,
            &scope(&[DEFAULT_NAMESPACE, OTHER, "gamma", "ferrum"]),
        );
        let destination_authz_config = &destination
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
            .expect("mesh_authz injected")
            .config;
        let assertors = destination_authz_config["trusted_hbone_assertors"]
            .as_array()
            .expect("an exact assertor inventory");
        let waypoint_a = assertors
            .iter()
            .find(|entry| entry["assertor"].as_str() == Some(WAYPOINT_A))
            .expect("B trusts A");
        let asserts: HashSet<&str> = waypoint_a["asserts"]
            .as_array()
            .expect("asserts")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            [CLIENT, INTRUDER, GAMMA_CLIENT]
                .iter()
                .all(|source| asserts.contains(source)),
            "{case}: A may assert every source it fronts, across namespaces: {asserts:?}"
        );
        let destination_authz = authz(&destination);

        for (principal, expected, deny_policy) in expectations {
            let at_source =
                allowed(&source_waypoint_allows(&source_authz, &route, principal).await);
            let (relayed, recorded) =
                destination_waypoint_relays(&destination_authz, WAYPOINT_A, principal).await;
            let at_destination = allowed(&relayed);
            assert_eq!(at_source, expected, "{case}: A decides {principal}");
            assert_eq!(at_destination, expected, "{case}: B decides {principal}");
            if let Some(deny_policy) = deny_policy {
                assert_eq!(
                    recorded.as_deref(),
                    Some(deny_policy),
                    "{case}: B's refusal of {principal} is the destination namespace's DENY"
                );
            }
        }

        // A waypoint that fronts none of these sources cannot assert one: B
        // judges the relay on that waypoint's own identity and refuses it.
        let (relayed, _) =
            destination_waypoint_relays(&destination_authz, WAYPOINT_C, CLIENT).await;
        assert!(
            !allowed(&relayed),
            "{case}: an unproven assertion is refused"
        );
    }
}

/// A destination NodeWaypoint trusts an assertion only for source namespaces
/// its own control-plane scope (and bearer `ns` claim) covers: outside them
/// the assertion is ignored and the relay is refused, never admitted on the
/// source waypoint's say-so.
#[tokio::test]
async fn a_destination_node_waypoint_ignores_assertions_outside_its_scope() {
    let config = two_waypoint_config(allow_namespace_deny_principal());
    let destination = prepare_destination_waypoint(&config, &scope(&[OTHER, "ferrum"]));
    let destination_authz = authz(&destination);
    let (relayed, _) = destination_waypoint_relays(&destination_authz, WAYPOINT_A, CLIENT).await;
    assert!(
        !allowed(&relayed),
        "B does not trust A to assert a `default` source it may not see"
    );
}

/// `other`'s method-scoped policy: ALLOW `GET` for `default/client`, DENY
/// `DELETE` for everyone.
fn method_scoped_policies() -> Vec<MeshPolicy> {
    use ferrum_edge::modes::mesh::config::{PolicyAction, RequestMatch};
    let mut allow_get = source_rule(Some(CLIENT), None, PolicyAction::Allow);
    allow_get.to = vec![RequestMatch {
        methods: vec!["GET".to_string()],
        ..RequestMatch::default()
    }];
    let deny_delete = ferrum_edge::modes::mesh::config::MeshRule {
        from: Vec::new(),
        to: vec![RequestMatch {
            methods: vec!["DELETE".to_string()],
            ..RequestMatch::default()
        }],
        ..source_rule(None, None, PolicyAction::Deny)
    };
    vec![
        ratings_policy("allow-client-get", vec![allow_get]),
        ratings_policy("deny-delete", vec![deny_delete]),
    ]
}

/// Review F2 (round 5): a method-scoped destination policy is enforced by the
/// source NodeWaypoint at Layer 7, and the destination NodeWaypoint admits
/// the opaque relay that waypoint forwards for a source it fronts: the relay's
/// HTTP-only predicates were decided upstream, its identity predicates are
/// still judged here. A relay from a waypoint that fronts nothing gets no such
/// standing and is judged as a Layer-4 session on its own identity.
#[tokio::test]
async fn a_destination_node_waypoint_admits_what_the_source_waypoint_authorized_at_layer_7() {
    let config = two_waypoint_config(method_scoped_policies());
    let source = prepare_source_waypoint(&config);
    let route = carried_routes(&source)[0].clone();
    let source_authz = authz(&source);
    let destination = prepare_destination_waypoint(
        &config,
        &scope(&[DEFAULT_NAMESPACE, OTHER, "gamma", "ferrum"]),
    );
    let destination_authz = authz(&destination);

    // Waypoint A judges the HTTP request against `other`'s policy.
    assert!(
        allowed(&source_waypoint_allows_method(&source_authz, &route, CLIENT, "GET").await),
        "A allows the client's GET"
    );
    assert!(
        !allowed(&source_waypoint_allows_method(&source_authz, &route, CLIENT, "POST").await),
        "A refuses a method the ALLOW does not name"
    );
    assert!(
        !allowed(&source_waypoint_allows_method(&source_authz, &route, CLIENT, "DELETE").await),
        "A applies the method-scoped DENY"
    );
    assert!(
        !allowed(&source_waypoint_allows_method(&source_authz, &route, INTRUDER, "GET").await),
        "A refuses a principal the ALLOW does not name"
    );

    // Waypoint B admits the relay A forwards for the client: its HTTP-only
    // predicates were A's to decide.
    let (relayed, recorded) =
        destination_waypoint_relays(&destination_authz, WAYPOINT_A, CLIENT).await;
    assert!(
        allowed(&relayed),
        "B admits A's relay of the client's authorized request: {recorded:?}"
    );
    // The identity half of the ALLOW is still judged at B.
    let (relayed, _) = destination_waypoint_relays(&destination_authz, WAYPOINT_A, INTRUDER).await;
    assert!(
        !allowed(&relayed),
        "B refuses a relayed principal no ALLOW names"
    );
    // A relay from a waypoint that fronts none of these sources is judged as
    // a Layer-4 session on that waypoint's own identity, where an ALLOW
    // reading a method never matches.
    let (relayed, _) = destination_waypoint_relays(&destination_authz, WAYPOINT_C, CLIENT).await;
    assert!(!allowed(&relayed), "an unproven assertion is refused");
}

/// Review F6 (round 5): on a NodeWaypoint, a route to the absolute two-label
/// DNS name `ratings.other.` is an external route and never inherits the
/// destination policy of the modeled Service `other/ratings`, which an
/// authorized route of the same slice reaches under that policy.
#[tokio::test]
async fn an_absolute_two_label_route_never_inherits_the_service_policy() {
    let mut config = config_with(
        direct_spec(RATINGS_OTHER),
        vec![virtual_service(
            "external",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [{
                    "match": [{"uri": {"prefix": "/external"}}],
                    "route": [{"destination": {"host": "ratings.other.", "port": {"number": 8080}}}]
                }]
            }),
        )],
        vec![ratings_trusted_only()],
        Vec::new(),
    );
    // Keep the importing Sidecar so `other/ratings` stays visible to `default`,
    // and add `*/*` so the external host `ratings.other.` is not narrowed out.
    config
        .mesh
        .as_mut()
        .expect("mesh block")
        .sidecars
        .first_mut()
        .expect("importing sidecar")
        .egress
        .first_mut()
        .expect("egress listener")
        .hosts
        .push("*/*".to_string());
    let prepared = prepare(&slice_for(&config, &node_waypoint_runtime()));
    let routes = carried_routes(&prepared);
    let external = routes
        .iter()
        .find(|route| route.backend_host == "ratings.other.")
        .map(|route| (*route).clone())
        .expect("the external route is served");
    assert_eq!(external.upstream_id, None, "a direct external backend");
    let authorized = routes
        .iter()
        .find(|route| {
            route
                .upstream_id
                .as_deref()
                .is_some_and(|id| id.starts_with(CLONE_PREFIX))
        })
        .map(|route| (*route).clone())
        .expect("the authorized route is served");

    let authz = authz(&prepared);
    let (result, _, _) = serve(&authz, &[], &authorized, UNTRUSTED, false).await;
    assert_denied(&result, "the Service route keeps its destination policy");
    let (result, _, _) = serve(&authz, &[], &external, UNTRUSTED, false).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "the external DNS route is not the Service: {result:?}"
    );
}
