//! Per-destination authorization for `mesh_route_dispatch` branches of a
//! carried VirtualService route on a NodeWaypoint (issue #7383).
//!
//! The translator merges a header-matched route to `ratings` into the
//! fallback route to `reviews`, so one carried proxy has the static
//! destination `reviews` and a dispatch rule to `ratings`. Authorization runs
//! before dispatch, so each candidate's own destination policy must decide the
//! requests that reach it. These tests drive the production halves: the K8s
//! translator, the control plane's slice projection, the data plane's slice
//! materialization (which threads the candidates to `mesh_authz`), the
//! `mesh_authz` plugin built from that config, and the production
//! `before_proxy` chain (route dispatch plus proxy core's final check).

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::_test_support::run_before_proxy_hooks_for_test;
use ferrum_edge::config::types::{GatewayConfig, PluginScope, Proxy};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MeshJwtRule, MeshPolicy, MeshRequestAuthentication, PolicyScope, WorkloadSelector,
};
use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::modes::mesh::{
    MESH_AUTHZ_PLUGIN_ID, MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX,
    MESH_REQUEST_AUTH_REFUSED_PLUGIN_ID, MeshRuntimeConfig, MeshTopology,
    prepare_gateway_config_from_mesh_slice,
};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::mesh_route_dispatch::RULE_INDEX_METADATA_KEY;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, create_plugin};
use serde_json::json;

use super::super::mesh_test_support::{
    DEFAULT_NAMESPACE, policy_allow_principal, runtime_for_topology, service_for, workload_for,
};

const TRUSTED: &str = "spiffe://cluster.local/ns/default/sa/trusted";
const UNTRUSTED: &str = "spiffe://cluster.local/ns/default/sa/untrusted";
const REVIEWS_UPSTREAM: &str = "__mesh-out-upstream-default-reviews-8080";
const RATINGS_UPSTREAM: &str = "__mesh-out-upstream-default-ratings-8080";
const DENIED_BODY: &str = r#"{"error":"Mesh authorization denied"}"#;

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

/// `x-version: v2` goes to `ratings`; everything else to `reviews`. The
/// translator merges the guarded route into the fallback route's proxy.
fn branch_spec() -> serde_json::Value {
    json!({
        "hosts": ["reviews.default.svc.cluster.local"],
        "http": [
            {
                "match": [{"headers": {"x-version": {"exact": "v2"}}}],
                "route": [{
                    "destination": {
                        "host": "ratings.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }
                }]
            },
            {
                "route": [{
                    "destination": {
                        "host": "reviews.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }
                }]
            }
        ]
    })
}

fn selector(app: &str) -> PolicyScope {
    PolicyScope::WorkloadSelector {
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), app.to_string())]),
            namespace: None,
        },
    }
}

/// Destination policy admitting only `TRUSTED` to `app=reviews`.
fn reviews_trusted_only() -> MeshPolicy {
    policy_allow_principal(
        "reviews-trusted-only",
        DEFAULT_NAMESPACE,
        selector("reviews"),
        TRUSTED,
    )
}

/// Destination policy admitting only `UNTRUSTED` to `app=ratings`.
fn ratings_untrusted_only() -> MeshPolicy {
    policy_allow_principal(
        "ratings-untrusted-only",
        DEFAULT_NAMESPACE,
        selector("ratings"),
        UNTRUSTED,
    )
}

/// Translate the branching VirtualService and add the mesh inventory it
/// reaches. Both workloads also carry `tier=backend`.
fn translated_config(policies: Vec<MeshPolicy>) -> GatewayConfig {
    let translated = translate_k8s_objects(
        &[virtual_service("branches", branch_spec())],
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
        [("app", "reviews"), ("tier", "backend")],
        ["10.0.0.11"],
    );
    let ratings = workload_for(
        "ratings",
        DEFAULT_NAMESPACE,
        [("app", "ratings"), ("tier", "backend")],
        ["10.0.0.12"],
    );
    let mesh = config.mesh.get_or_insert_with(Box::default);
    mesh.services = vec![
        service_for("reviews", DEFAULT_NAMESPACE, &[&reviews]),
        service_for("ratings", DEFAULT_NAMESPACE, &[&ratings]),
    ];
    mesh.workloads = vec![reviews, ratings];
    mesh.mesh_policies = policies;
    config.normalize_fields();
    config.normalize_mesh_fields();
    config
}

fn node_waypoint_runtime() -> MeshRuntimeConfig {
    runtime_for_topology(MeshTopology::NodeWaypoint)
}

fn node_waypoint_slice(policies: Vec<MeshPolicy>) -> MeshSlice {
    let config = translated_config(policies);
    MeshSlice::from_gateway_config(&config, node_waypoint_runtime().mesh_slice_request())
}

fn prepare(slice: &MeshSlice) -> GatewayConfig {
    prepare_gateway_config_from_mesh_slice(slice, &node_waypoint_runtime())
        .expect("slice materializes")
}

/// The one carried route the merged VirtualService produces.
fn carried_route(prepared: &GatewayConfig) -> Proxy {
    let routes: Vec<&Proxy> = prepared
        .proxies
        .iter()
        .filter(|proxy| proxy.id.starts_with("istio-vs-") && !proxy.id.starts_with("istio-vs-l4_"))
        .collect();
    assert_eq!(
        routes.len(),
        1,
        "the guarded route is merged into the fallback route: {:?}",
        routes.iter().map(|proxy| &proxy.id).collect::<Vec<_>>()
    );
    routes[0].clone()
}

/// The materialized Service route that reaches `upstream_id` (not a carried
/// VirtualService route).
fn service_route(prepared: &GatewayConfig, upstream_id: &str) -> Proxy {
    prepared
        .proxies
        .iter()
        .find(|proxy| {
            !proxy.id.starts_with("istio-vs-") && proxy.upstream_id.as_deref() == Some(upstream_id)
        })
        .unwrap_or_else(|| panic!("no Service route to {upstream_id}"))
        .clone()
}

/// `mesh_authz` built without per-destination verdicts: it decides the
/// carried route on its own destination alone, as before issue #7383.
fn single_destination_authz(prepared: &GatewayConfig) -> MeshAuthz {
    let mut config = authz_config(prepared);
    config
        .as_object_mut()
        .expect("object config")
        .remove("node_waypoint_route_branches");
    MeshAuthz::new(&config).expect("mesh_authz builds")
}

fn authz_config(prepared: &GatewayConfig) -> serde_json::Value {
    prepared
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz injected")
        .config
        .clone()
}

/// The production `mesh_route_dispatch` instance of `route`.
fn route_dispatch(prepared: &GatewayConfig, route: &Proxy) -> Arc<dyn Plugin> {
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
    create_plugin("mesh_route_dispatch", &config.config)
        .expect("dispatch config constructs")
        .expect("built-in plugin")
}

fn node_waypoint_request(route: &Proxy, source: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    let identity = SpiffeId::new(source).expect("spiffe");
    ctx.peer_spiffe_id = Some(identity.clone());
    ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        identity,
        DEFAULT_NAMESPACE,
        HashMap::from([("app".to_string(), "client".to_string())]),
    )));
    ctx.matched_proxy = Some(Arc::new(route.clone()));
    ctx
}

fn branch_headers(v2: bool) -> HashMap<String, String> {
    let mut headers = HashMap::from([(
        "host".to_string(),
        "reviews.default.svc.cluster.local".to_string(),
    )]);
    if v2 {
        headers.insert("x-version".to_string(), "v2".to_string());
    }
    headers
}

/// One request through `mesh_authz` and then the production `before_proxy`
/// chain holding `plugins`.
async fn serve(
    authz: &MeshAuthz,
    plugins: &[Arc<dyn Plugin>],
    route: &Proxy,
    source: &str,
    v2: bool,
) -> (PluginResult, Option<PluginResult>, RequestContext) {
    let mut ctx = node_waypoint_request(route, source);
    let mut headers = branch_headers(v2);
    ctx.headers = headers.clone();
    let authorized = authz.authorize(&mut ctx).await;
    if !matches!(authorized, PluginResult::Continue) {
        return (authorized, None, ctx);
    }
    let dispatched = run_before_proxy_hooks_for_test(plugins, &mut ctx, &mut headers).await;
    (authorized, Some(dispatched), ctx)
}

fn assert_denied(result: &PluginResult, body: &str, what: &str) {
    match result {
        PluginResult::Reject {
            status_code,
            body: rejected,
            ..
        } => {
            assert_eq!(*status_code, 403, "{what}");
            assert_eq!(rejected, body, "{what}");
        }
        other => panic!("{what}: expected a 403 refusal, got {other:?}"),
    }
}

/// The deny policy a destination's own route records for `source`.
async fn own_route_deny_policy(authz: &MeshAuthz, route: &Proxy, source: &str) -> String {
    let mut ctx = node_waypoint_request(route, source);
    let result = authz.authorize(&mut ctx).await;
    assert_denied(&result, DENIED_BODY, "the destination's own route refuses");
    ctx.metadata
        .get("mesh_authz.deny_policy")
        .cloned()
        .expect("deny policy recorded")
}

#[test]
fn slice_preparation_threads_each_candidate_destination_to_mesh_authz() {
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    assert_eq!(route.upstream_id.as_deref(), Some(REVIEWS_UPSTREAM));
    let branches = authz_config(&prepared)["node_waypoint_route_branches"].clone();
    assert_eq!(
        branches,
        json!([{
            "namespace": DEFAULT_NAMESPACE,
            "proxy_id": route.id,
            "destinations": [
                {"upstream_id": REVIEWS_UPSTREAM},
                {"upstream_id": RATINGS_UPSTREAM}
            ]
        }]),
        "the route's own destination first, then the rebound rule destination"
    );
}

#[test]
fn a_route_without_another_candidate_is_not_threaded() {
    let translated = translate_k8s_objects(
        &[virtual_service(
            "direct",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [{
                    "match": [{"headers": {"x-version": {"exact": "v2"}}}],
                    "route": [{
                        "destination": {
                            "host": "reviews.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }
                    }]
                }]
            }),
        )],
        K8sTranslationOptions::new(
            DEFAULT_NAMESPACE.to_string(),
            TrustDomain::new("cluster.local").expect("trust domain"),
        ),
    )
    .expect("VirtualService translates");
    let mut config = translated.config;
    let base = translated_config(vec![reviews_trusted_only()]);
    config.mesh = base.mesh;
    config.normalize_fields();
    config.normalize_mesh_fields();
    let slice =
        MeshSlice::from_gateway_config(&config, node_waypoint_runtime().mesh_slice_request());
    let prepared = prepare(&slice);
    assert!(
        authz_config(&prepared)
            .get("node_waypoint_route_branches")
            .is_none(),
        "a route whose rules all keep its own destination keeps the single-destination decision"
    );
}

/// Issue #7383: an alternative branch whose destination policy admits the
/// request passes, although the route's own destination would refuse it.
#[tokio::test]
async fn an_allowed_alternative_branch_passes() {
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = MeshAuthz::new(&authz_config(&prepared)).expect("mesh_authz builds");
    let dispatch = route_dispatch(&prepared, &route);

    let (authorized, dispatched, ctx) = serve(&authz, &[dispatch], &route, UNTRUSTED, true).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "ratings admits the request, so authorization defers to dispatch: {authorized:?}"
    );
    assert!(
        matches!(dispatched, Some(PluginResult::Continue)),
        "the ratings branch is admitted: {dispatched:?}"
    );
    assert_eq!(
        ctx.route_override_upstream_id.as_deref(),
        Some(RATINGS_UPSTREAM)
    );
    assert!(!ctx.metadata.contains_key("mesh_authz.deny_policy"));
}

/// Issue #7383: an alternative branch is refused by its own destination's
/// policy even when the route's own destination admits the request, with the
/// same denial that destination's own route produces.
#[tokio::test]
async fn a_denied_alternative_branch_is_refused_even_when_the_static_destination_allows() {
    let slice = node_waypoint_slice(vec![reviews_trusted_only(), ratings_untrusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = MeshAuthz::new(&authz_config(&prepared)).expect("mesh_authz builds");
    let dispatch = route_dispatch(&prepared, &route);

    let (authorized, dispatched, ctx) = serve(&authz, &[dispatch], &route, TRUSTED, true).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "reviews admits TRUSTED: {authorized:?}"
    );
    let dispatched = dispatched.expect("dispatch ran");
    assert_denied(&dispatched, DENIED_BODY, "the ratings branch is refused");
    assert_eq!(ctx.route_override_upstream_id, None);
    assert!(
        !ctx.metadata.contains_key(RULE_INDEX_METADATA_KEY),
        "the refused rule served nothing"
    );
    let expected =
        own_route_deny_policy(&authz, &service_route(&prepared, RATINGS_UPSTREAM), TRUSTED).await;
    assert_eq!(
        ctx.metadata.get("mesh_authz.deny_policy"),
        Some(&expected),
        "the branch denial carries the ratings policy's own deny policy"
    );
}

/// Issue #7383: the route's own branch still answers to the route's own
/// destination policy, in both directions.
#[tokio::test]
async fn the_static_branch_still_uses_its_own_policy() {
    let slice = node_waypoint_slice(vec![reviews_trusted_only(), ratings_untrusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = MeshAuthz::new(&authz_config(&prepared)).expect("mesh_authz builds");
    let dispatch = route_dispatch(&prepared, &route);

    // UNTRUSTED: ratings would admit it, so authorization defers, but the
    // request reaches reviews, whose policy refuses it.
    let (authorized, dispatched, ctx) =
        serve(&authz, &[Arc::clone(&dispatch)], &route, UNTRUSTED, false).await;
    assert!(matches!(authorized, PluginResult::Continue));
    assert_denied(
        &dispatched.expect("dispatch ran"),
        DENIED_BODY,
        "the static branch keeps the reviews policy",
    );
    let expected =
        own_route_deny_policy(&single_destination_authz(&prepared), &route, UNTRUSTED).await;
    assert_eq!(ctx.metadata.get("mesh_authz.deny_policy"), Some(&expected));

    // TRUSTED reaches reviews and is admitted.
    let (_, dispatched, ctx) = serve(&authz, &[dispatch], &route, TRUSTED, false).await;
    assert!(matches!(dispatched, Some(PluginResult::Continue)));
    assert!(
        ctx.route_override_upstream_id.is_none()
            || ctx.route_override_upstream_id.as_deref() == Some(REVIEWS_UPSTREAM)
    );
    assert!(!ctx.metadata.contains_key("mesh_authz.deny_policy"));
}

/// Issue #7383: proxy core re-checks the destination the request finally
/// reaches, so a request whose own destination refused it is refused even
/// when route dispatch never runs (stood down, or not in the chain).
#[tokio::test]
async fn the_reached_destination_is_checked_without_route_dispatch() {
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = MeshAuthz::new(&authz_config(&prepared)).expect("mesh_authz builds");

    let (authorized, dispatched, _) = serve(&authz, &[], &route, UNTRUSTED, true).await;
    assert!(matches!(authorized, PluginResult::Continue));
    assert_denied(
        &dispatched.expect("before_proxy ran"),
        DENIED_BODY,
        "without dispatch the request reaches reviews, which refuses it",
    );

    let (_, dispatched, _) = serve(&authz, &[], &route, TRUSTED, true).await;
    assert!(matches!(dispatched, Some(PluginResult::Continue)));
}

/// Issue #7383: a destination the verdict table does not name has no verdict
/// and is refused (fail closed), even though its policy would admit it.
#[tokio::test]
async fn a_destination_without_a_verdict_is_refused() {
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let mut config = authz_config(&prepared);
    config["node_waypoint_route_branches"][0]["destinations"] =
        json!([{"upstream_id": REVIEWS_UPSTREAM}]);
    let authz = MeshAuthz::new(&config).expect("mesh_authz builds");
    let dispatch = route_dispatch(&prepared, &route);

    let (authorized, dispatched, ctx) = serve(&authz, &[dispatch], &route, TRUSTED, true).await;
    assert!(matches!(authorized, PluginResult::Continue));
    assert_denied(
        &dispatched.expect("dispatch ran"),
        DENIED_BODY,
        "ratings is not a candidate, so it has no verdict",
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("route_branch_unauthorized")
    );
}

/// Without per-destination verdicts (an operator `mesh_authz` replaced the
/// managed instance, or the candidates were not threaded) the blanket
/// override refusal still applies.
#[tokio::test]
async fn without_verdicts_the_blanket_override_refusal_stays() {
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = single_destination_authz(&prepared);
    let dispatch = route_dispatch(&prepared, &route);

    let (authorized, dispatched, _) = serve(&authz, &[dispatch], &route, TRUSTED, true).await;
    assert!(matches!(authorized, PluginResult::Continue));
    match dispatched.expect("dispatch ran") {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert!(body.contains("unauthorized destination"), "{body}");
        }
        other => panic!("expected the blanket refusal, got {other:?}"),
    }

    let (authorized, _, _) = serve(&authz, &[], &route, UNTRUSTED, true).await;
    assert_denied(
        &authorized,
        DENIED_BODY,
        "the static destination decides at authorization",
    );
}

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

fn prepare_with_request_auth(request_auth: MeshRequestAuthentication) -> (GatewayConfig, Proxy) {
    let mut slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    slice.request_authentications = vec![request_auth];
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    (prepared, route)
}

/// RequestAuthentication destination scoping (#6670) holds per branch: a
/// resource selecting both destinations governs the merged route, and one
/// selecting only the alternative destination refuses the route, because
/// the backend is chosen after authentication.
#[test]
fn request_authentication_holds_for_every_branch() {
    let both = PolicyScope::WorkloadSelector {
        selector: WorkloadSelector {
            labels: HashMap::from([("tier".to_string(), "backend".to_string())]),
            namespace: None,
        },
    };
    let (prepared, route) = prepare_with_request_auth(request_auth("backend-jwt", both));
    let association = route
        .plugins
        .iter()
        .find(|association| {
            association
                .plugin_config_id
                .starts_with(MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX)
        })
        .expect("the merged route gets the resource both branches share");
    let plugin = prepared
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == association.plugin_config_id)
        .expect("destination instance exists");
    assert_eq!(plugin.plugin_name, "jwks_auth");
    assert_eq!(plugin.scope, PluginScope::ProxyGroup);
    assert_eq!(
        plugin.config["providers"][0]["issuer"],
        json!("https://backend-jwt.example.com")
    );
    assert!(
        prepared
            .plugin_configs
            .iter()
            .all(|plugin| plugin.id != MESH_REQUEST_AUTH_REFUSED_PLUGIN_ID),
        "no branch disagrees"
    );

    let (prepared, route) =
        prepare_with_request_auth(request_auth("ratings-jwt", selector("ratings")));
    assert!(
        route.plugins.iter().all(|association| !association
            .plugin_config_id
            .starts_with(MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX)),
        "no union instance for branches that disagree"
    );
    let refusal = prepared
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == MESH_REQUEST_AUTH_REFUSED_PLUGIN_ID)
        .expect("a route whose branches disagree is refused");
    let trigger = serde_json::to_value(refusal.trigger.as_ref().expect("scoped refusal"))
        .expect("trigger serializes")
        .to_string();
    assert!(trigger.contains(&route.id), "{trigger}");
}
