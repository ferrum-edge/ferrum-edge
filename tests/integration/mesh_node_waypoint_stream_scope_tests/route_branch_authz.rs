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
    MeshExtAuthzProvider, MeshJwtRule, MeshPolicy, MeshRequestAuthentication, MeshRule,
    PolicyAction, PolicyScope, WorkloadSelector,
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
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext, create_plugin};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::scaffolding::port_registry::TestSocket;

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

/// On `/api`, `x-version: v2` goes to `ratings` and everything else to
/// `reviews`. The guarded route shares the fallback route's path, so the
/// translator merges it into the fallback route's proxy as a dispatch rule.
fn branch_spec() -> serde_json::Value {
    json!({
        "hosts": ["reviews.default.svc.cluster.local"],
        "http": [
            {
                "match": [{
                    "uri": {"prefix": "/api"},
                    "headers": {"x-version": {"exact": "v2"}}
                }],
                "route": [{
                    "destination": {
                        "host": "ratings.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }
                }]
            },
            {
                "match": [{"uri": {"prefix": "/api"}}],
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

/// Destination policy admitting only `TRUSTED` to `app=ratings`.
fn ratings_trusted_only() -> MeshPolicy {
    policy_allow_principal(
        "ratings-trusted-only",
        DEFAULT_NAMESPACE,
        selector("ratings"),
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
    let (authorized, dispatched, ctx, _) = serve_capture(authz, plugins, route, source, v2).await;
    (authorized, dispatched, ctx)
}

/// [`serve`], also returning the backend-bound request headers.
async fn serve_capture(
    authz: &MeshAuthz,
    plugins: &[Arc<dyn Plugin>],
    route: &Proxy,
    source: &str,
    v2: bool,
) -> (
    PluginResult,
    Option<PluginResult>,
    RequestContext,
    HashMap<String, String>,
) {
    let mut ctx = node_waypoint_request(route, source);
    let mut headers = branch_headers(v2);
    headers.insert(
        "authorization".to_string(),
        "Bearer client-token".to_string(),
    );
    ctx.headers = headers.clone();
    let authorized = authz.authorize(&mut ctx).await;
    if !matches!(authorized, PluginResult::Continue) {
        return (authorized, None, ctx, headers);
    }
    let dispatched = run_before_proxy_hooks_for_test(plugins, &mut ctx, &mut headers).await;
    (authorized, Some(dispatched), ctx, headers)
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
    // The inventory and policy of the branching fixture, under this
    // VirtualService's own mesh binding.
    let base = translated_config(vec![reviews_trusted_only()]);
    let base_mesh = *base.mesh.expect("fixture mesh block");
    let mesh = config.mesh.get_or_insert_with(Box::default);
    mesh.services = base_mesh.services;
    mesh.workloads = base_mesh.workloads;
    mesh.mesh_policies = base_mesh.mesh_policies;
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

/// Issue #7383 review (dsf F2): when the route's own destination cannot be
/// resolved but another candidate is allowed, the request continues, the
/// alternative is admitted, and the own branch is refused as
/// `destination_scope_missing`.
#[tokio::test]
async fn an_unresolvable_own_destination_defers_to_an_allowed_alternative() {
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let mut config = authz_config(&prepared);
    // The destination index no longer resolves `reviews`, while its upstream
    // still names a modeled mesh destination.
    for field in ["services", "workloads"] {
        if let Some(entries) = config["mesh_slice"][field].as_array_mut() {
            entries.retain(|entry| {
                entry["name"] != json!("reviews") && entry["service_name"] != json!("reviews")
            });
        }
    }
    let authz = MeshAuthz::new(&config).expect("mesh_authz builds");
    let dispatch = route_dispatch(&prepared, &route);

    let (authorized, dispatched, ctx) =
        serve(&authz, &[Arc::clone(&dispatch)], &route, TRUSTED, true).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "ratings is allowed, so authorization defers: {authorized:?}"
    );
    assert!(matches!(dispatched, Some(PluginResult::Continue)));
    assert_eq!(
        ctx.route_override_upstream_id.as_deref(),
        Some(RATINGS_UPSTREAM)
    );

    let (authorized, dispatched, ctx) = serve(&authz, &[dispatch], &route, TRUSTED, false).await;
    assert!(matches!(authorized, PluginResult::Continue));
    assert_denied(
        &dispatched.expect("dispatch ran"),
        r#"{"error":"Mesh authorization denied: missing destination policy scope"}"#,
        "the own branch has no resolvable destination scope",
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("destination_scope_missing")
    );
}

/// Issue #7383 review (dsf F2): when every candidate refuses the request, the
/// route's own destination refuses it at authorization, with its own deny
/// policy, exactly as a route without other candidates would.
#[tokio::test]
async fn when_every_candidate_refuses_the_own_refusal_stands_at_authorization() {
    let slice = node_waypoint_slice(vec![reviews_trusted_only(), ratings_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = MeshAuthz::new(&authz_config(&prepared)).expect("mesh_authz builds");
    let dispatch = route_dispatch(&prepared, &route);

    let (authorized, dispatched, ctx) = serve(&authz, &[dispatch], &route, UNTRUSTED, true).await;
    assert_denied(
        &authorized,
        DENIED_BODY,
        "no candidate admits UNTRUSTED, so authorization refuses",
    );
    assert!(dispatched.is_none(), "dispatch never runs");
    let expected =
        own_route_deny_policy(&single_destination_authz(&prepared), &route, UNTRUSTED).await;
    assert_eq!(ctx.metadata.get("mesh_authz.deny_policy"), Some(&expected));
}

const PROVIDER_ALLOW_WITH_TOKEN: &str = "HTTP/1.1 200 OK\r\n\
authorization: Bearer provider-minted-token\r\n\
content-length: 0\r\n\r\n";

const PROVIDER_DENY: &str = "HTTP/1.1 403 Forbidden\r\n\
www-authenticate: Bearer realm=\"mesh\"\r\n\
content-length: 0\r\n\r\n";

/// A local stub authorizer answering every check with `response`, counting
/// the checks it receives.
async fn start_provider(response: &'static str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("stub authorizer binds");
    let port = listener.local_addr().expect("stub local addr").port();
    let calls = Arc::new(AtomicUsize::new(0));
    let task_calls = Arc::clone(&calls);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            task_calls.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                let _ = stream.read(&mut buffer).await;
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    (port, calls)
}

fn custom_policy(name: &str, app: &str) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: selector(app),
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Custom {
                provider: "branch-ext-authz".to_string(),
            },
        }],
    }
}

/// `mesh_authz` from the prepared config plus a CUSTOM policy selecting one
/// destination, bound to a stub provider that owns `authorization` upstream.
fn authz_with_custom(prepared: &GatewayConfig, policy: MeshPolicy, port: u16) -> MeshAuthz {
    let mut config = authz_config(prepared);
    let slice = config["mesh_slice"]
        .as_object_mut()
        .expect("embedded mesh slice");
    slice
        .entry("mesh_policies")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("policy list")
        .push(serde_json::to_value(policy).expect("policy serializes"));
    let provider = MeshExtAuthzProvider {
        name: "branch-ext-authz".to_string(),
        service: "127.0.0.1".to_string(),
        port,
        tls: false,
        path_prefix: Some("/check".to_string()),
        timeout_ms: 500,
        fail_open: false,
        status_on_error: 403,
        include_request_headers_in_check: Vec::new(),
        include_additional_headers_in_check: Vec::new(),
        include_request_body_in_check: None,
        headers_to_upstream_on_allow: vec!["authorization".to_string()],
        headers_to_downstream_on_deny: vec!["www-authenticate".to_string()],
        headers_to_downstream_on_allow: Vec::new(),
    };
    slice.insert(
        "ext_authz_providers".to_string(),
        json!([serde_json::to_value(provider).expect("provider serializes")]),
    );
    MeshAuthz::new_with_http_client(&config, Some(PluginHttpClient::default()))
        .expect("mesh_authz builds with the provider")
}

/// Issue #7383 review (sol F1): a credential the own destination's provider
/// mints is never forwarded to an alternative branch without a CUSTOM policy
/// of its own, and the provider is not even asked about such a request.
#[tokio::test]
async fn a_provider_credential_does_not_follow_the_request_to_another_branch() {
    let (port, calls) = start_provider(PROVIDER_ALLOW_WITH_TOKEN).await;
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = authz_with_custom(&prepared, custom_policy("reviews-ext", "reviews"), port);
    let dispatch = route_dispatch(&prepared, &route);

    let (authorized, dispatched, ctx, headers) =
        serve_capture(&authz, &[Arc::clone(&dispatch)], &route, TRUSTED, true).await;
    assert!(matches!(authorized, PluginResult::Continue));
    assert!(
        matches!(dispatched, Some(PluginResult::Continue)),
        "ratings has no CUSTOM policy and admits the request: {dispatched:?}"
    );
    assert_eq!(
        ctx.route_override_upstream_id.as_deref(),
        Some(RATINGS_UPSTREAM)
    );
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer client-token"),
        "the reviews provider's credential must not reach ratings"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no check runs for a destination the request does not reach"
    );

    // The request that does reach reviews runs reviews' check and carries
    // its provider's credential.
    let (_, dispatched, _, headers) =
        serve_capture(&authz, &[dispatch], &route, TRUSTED, false).await;
    assert!(matches!(dispatched, Some(PluginResult::Continue)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer provider-minted-token")
    );
}

/// Issue #7383 review (sol F2): an alternative destination's own CUSTOM
/// check runs when dispatch selects it, and its allow admits the request.
#[tokio::test]
async fn an_alternative_branch_runs_its_own_custom_check() {
    let (port, calls) = start_provider(PROVIDER_ALLOW_WITH_TOKEN).await;
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = authz_with_custom(&prepared, custom_policy("ratings-ext", "ratings"), port);
    let dispatch = route_dispatch(&prepared, &route);

    let (authorized, dispatched, ctx, headers) =
        serve_capture(&authz, &[Arc::clone(&dispatch)], &route, TRUSTED, true).await;
    assert!(matches!(authorized, PluginResult::Continue));
    assert!(
        matches!(dispatched, Some(PluginResult::Continue)),
        "the ratings provider allows: {dispatched:?}"
    );
    assert_eq!(
        ctx.route_override_upstream_id.as_deref(),
        Some(RATINGS_UPSTREAM)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer provider-minted-token")
    );

    // The own branch has no CUSTOM policy: no check, no provider header.
    let (_, dispatched, _, headers) =
        serve_capture(&authz, &[dispatch], &route, TRUSTED, false).await;
    assert!(matches!(dispatched, Some(PluginResult::Continue)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer client-token")
    );
}

/// Issue #7383 review (sol F2): the own destination's CUSTOM refusal applies
/// only to requests that reach it; a request routed to an alternative without
/// a CUSTOM policy passes, and the provider is not consulted for it.
#[tokio::test]
async fn an_own_destination_custom_refusal_applies_only_to_its_own_branch() {
    let (port, calls) = start_provider(PROVIDER_DENY).await;
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = authz_with_custom(&prepared, custom_policy("reviews-ext", "reviews"), port);
    let dispatch = route_dispatch(&prepared, &route);

    let (authorized, dispatched, _) =
        serve(&authz, &[Arc::clone(&dispatch)], &route, TRUSTED, true).await;
    assert!(matches!(authorized, PluginResult::Continue));
    assert!(matches!(dispatched, Some(PluginResult::Continue)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (_, dispatched, ctx) = serve(&authz, &[dispatch], &route, TRUSTED, false).await;
    match dispatched.expect("dispatch ran") {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 403);
            assert!(
                headers.contains_key("www-authenticate"),
                "the provider's own denial is kept: {headers:?}"
            );
        }
        other => panic!("the reviews provider refuses its own branch, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("custom:reviews-ext")
    );
}

/// A destination that still owes its CUSTOM check when the `before_proxy`
/// pass ends (route dispatch did not run) is refused, never admitted
/// unchecked, and no provider is called after the request transformers.
#[tokio::test]
async fn a_destination_owing_a_custom_check_without_dispatch_is_refused() {
    let (port, calls) = start_provider(PROVIDER_ALLOW_WITH_TOKEN).await;
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = authz_with_custom(&prepared, custom_policy("reviews-ext", "reviews"), port);

    let (authorized, dispatched, ctx) = serve(&authz, &[], &route, TRUSTED, false).await;
    assert!(matches!(authorized, PluginResult::Continue));
    assert_denied(
        &dispatched.expect("before_proxy ran"),
        DENIED_BODY,
        "the reviews check never ran",
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("custom:reviews-ext")
    );
}
