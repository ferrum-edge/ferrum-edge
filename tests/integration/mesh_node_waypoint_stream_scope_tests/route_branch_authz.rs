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

use async_trait::async_trait;
use ferrum_edge::_test_support::{
    early_route_total_ms_for_test, install_plugin_finalizers_for_test,
    run_after_proxy_hooks_for_test, run_before_proxy_hooks_for_test,
};
use ferrum_edge::config::types::{GatewayConfig, PluginScope, Proxy};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    ConditionMatch, MeshExtAuthzProvider, MeshJwtRule, MeshPolicy, MeshRequestAuthentication,
    MeshRule, PolicyAction, PolicyScope, RequestMatch, WorkloadSelector,
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
/// `ratings` is reached on `ratings_port`.
fn branch_spec_with_ratings_port(ratings_port: u16) -> serde_json::Value {
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
                        "port": {"number": ratings_port}
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
    translated_config_with_ratings_port(policies, 8080)
}

/// [`translated_config`] with the `ratings` Service, its workload and the
/// VirtualService branch on `ratings_port`.
fn translated_config_with_ratings_port(
    policies: Vec<MeshPolicy>,
    ratings_port: u16,
) -> GatewayConfig {
    let translated = translate_k8s_objects(
        &[virtual_service(
            "branches",
            branch_spec_with_ratings_port(ratings_port),
        )],
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
    let mut ratings = workload_for(
        "ratings",
        DEFAULT_NAMESPACE,
        [("app", "ratings"), ("tier", "backend")],
        ["10.0.0.12"],
    );
    ratings.ports[0].port = ratings_port;
    let mut ratings_service = service_for("ratings", DEFAULT_NAMESPACE, &[&ratings]);
    ratings_service.ports[0].port = ratings_port;
    let mesh = config.mesh.get_or_insert_with(Box::default);
    mesh.services = vec![
        service_for("reviews", DEFAULT_NAMESPACE, &[&reviews]),
        ratings_service,
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

/// The production `mesh_route_dispatch` instance of `route`, as the plugin
/// cache assembles it: followed by the cache-installed dispatch finalizer,
/// which admits the destination the dispatch group selected.
fn route_dispatch(prepared: &GatewayConfig, route: &Proxy) -> Vec<Arc<dyn Plugin>> {
    dispatch_chain(vec![route_dispatch_instance(prepared, route)])
}

/// The production chain of a carried route with `authz` in it: `mesh_authz`'s
/// own `before_proxy` hook, the route's dispatch instance, and the finalizer.
fn authz_dispatch_chain(
    authz: &Arc<MeshAuthz>,
    prepared: &GatewayConfig,
    route: &Proxy,
) -> Vec<Arc<dyn Plugin>> {
    dispatch_chain(vec![
        Arc::clone(authz) as Arc<dyn Plugin>,
        route_dispatch_instance(prepared, route),
    ])
}

/// `plugins` with the cache-internal finalizers installed.
fn dispatch_chain(mut plugins: Vec<Arc<dyn Plugin>>) -> Vec<Arc<dyn Plugin>> {
    install_plugin_finalizers_for_test(&mut plugins).expect("dispatch chain assembles");
    plugins
}

fn route_dispatch_instance(prepared: &GatewayConfig, route: &Proxy) -> Arc<dyn Plugin> {
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

fn branch_headers(version: Option<&str>) -> HashMap<String, String> {
    let mut headers = HashMap::from([(
        "host".to_string(),
        "reviews.default.svc.cluster.local".to_string(),
    )]);
    if let Some(version) = version {
        headers.insert("x-version".to_string(), version.to_string());
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
    let version = v2.then_some("v2");
    let (authorized, dispatched, ctx, _) =
        serve_version(authz, plugins, route, source, version).await;
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
    serve_version(authz, plugins, route, source, v2.then_some("v2")).await
}

/// One request carrying `x-version: <version>` (when set), returning the
/// backend-bound request headers too.
async fn serve_version(
    authz: &MeshAuthz,
    plugins: &[Arc<dyn Plugin>],
    route: &Proxy,
    source: &str,
    version: Option<&str>,
) -> (
    PluginResult,
    Option<PluginResult>,
    RequestContext,
    HashMap<String, String>,
) {
    let mut ctx = node_waypoint_request(route, source);
    let mut headers = branch_headers(version);
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

    let (authorized, dispatched, ctx) = serve(&authz, &dispatch, &route, UNTRUSTED, true).await;
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

    let (authorized, dispatched, ctx) = serve(&authz, &dispatch, &route, TRUSTED, true).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "reviews admits TRUSTED: {authorized:?}"
    );
    let dispatched = dispatched.expect("dispatch ran");
    assert_denied(&dispatched, DENIED_BODY, "the ratings branch is refused");
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
    let (authorized, dispatched, ctx) = serve(&authz, &dispatch, &route, UNTRUSTED, false).await;
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
    let (_, dispatched, ctx) = serve(&authz, &dispatch, &route, TRUSTED, false).await;
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

    let (authorized, dispatched, ctx) = serve(&authz, &dispatch, &route, TRUSTED, true).await;
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

    let (authorized, dispatched, _) = serve(&authz, &dispatch, &route, TRUSTED, true).await;
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

    let (authorized, dispatched, ctx) = serve(&authz, &dispatch, &route, TRUSTED, true).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "ratings is allowed, so authorization defers: {authorized:?}"
    );
    assert!(matches!(dispatched, Some(PluginResult::Continue)));
    assert_eq!(
        ctx.route_override_upstream_id.as_deref(),
        Some(RATINGS_UPSTREAM)
    );

    let (authorized, dispatched, ctx) = serve(&authz, &dispatch, &route, TRUSTED, false).await;
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

    let (authorized, dispatched, ctx) = serve(&authz, &dispatch, &route, UNTRUSTED, true).await;
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
    authz_with_custom_policies(prepared, vec![policy], port, Vec::new())
}

/// [`authz_with_custom`] with several added policies and the provider's
/// `headersToDownstreamOnAllow` list.
fn authz_with_custom_policies(
    prepared: &GatewayConfig,
    policies: Vec<MeshPolicy>,
    port: u16,
    downstream_on_allow: Vec<String>,
) -> MeshAuthz {
    let mut provider = stub_provider("branch-ext-authz", port, &["authorization"]);
    provider.headers_to_downstream_on_allow = downstream_on_allow;
    authz_with_providers(prepared, policies, vec![provider])
}

/// A stub provider named `name` on `port` that owns `upstream_owned`.
fn stub_provider(name: &str, port: u16, upstream_owned: &[&str]) -> MeshExtAuthzProvider {
    MeshExtAuthzProvider {
        name: name.to_string(),
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
        headers_to_upstream_on_allow: upstream_owned.iter().map(ToString::to_string).collect(),
        headers_to_downstream_on_deny: vec!["www-authenticate".to_string()],
        headers_to_downstream_on_allow: Vec::new(),
    }
}

/// `mesh_authz` from the prepared config plus `policies` and `providers`.
fn authz_with_providers(
    prepared: &GatewayConfig,
    policies: Vec<MeshPolicy>,
    providers: Vec<MeshExtAuthzProvider>,
) -> MeshAuthz {
    let mut config = authz_config(prepared);
    let slice = config["mesh_slice"]
        .as_object_mut()
        .expect("embedded mesh slice");
    slice
        .entry("mesh_policies")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("policy list")
        .extend(
            policies
                .into_iter()
                .map(|policy| serde_json::to_value(policy).expect("policy serializes")),
        );
    slice.insert(
        "ext_authz_providers".to_string(),
        serde_json::to_value(providers).expect("providers serialize"),
    );
    MeshAuthz::new_with_http_client(&config, Some(PluginHttpClient::default()))
        .expect("mesh_authz builds with the providers")
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
    let authz = Arc::new(authz_with_custom(
        &prepared,
        custom_policy("reviews-ext", "reviews"),
        port,
    ));
    // The production chain: `mesh_authz`'s own hook, dispatch, finalizer.
    let dispatch = authz_dispatch_chain(&authz, &prepared, &route);

    let (authorized, dispatched, ctx, headers) =
        serve_capture(&authz, &dispatch, &route, TRUSTED, true).await;
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
        serve_capture(&authz, &dispatch, &route, TRUSTED, false).await;
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
    let authz = Arc::new(authz_with_custom(
        &prepared,
        custom_policy("ratings-ext", "ratings"),
        port,
    ));
    // The production chain: `mesh_authz`'s own hook, dispatch, finalizer.
    let dispatch = authz_dispatch_chain(&authz, &prepared, &route);

    let (authorized, dispatched, ctx, headers) =
        serve_capture(&authz, &dispatch, &route, TRUSTED, true).await;
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
        serve_capture(&authz, &dispatch, &route, TRUSTED, false).await;
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

    let (authorized, dispatched, _) = serve(&authz, &dispatch, &route, TRUSTED, true).await;
    assert!(matches!(authorized, PluginResult::Continue));
    assert!(matches!(dispatched, Some(PluginResult::Continue)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (_, dispatched, ctx) = serve(&authz, &dispatch, &route, TRUSTED, false).await;
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

const PROVIDER_DENY_401: &str = "HTTP/1.1 401 Unauthorized\r\n\
www-authenticate: Bearer realm=\"mesh\"\r\n\
content-length: 0\r\n\r\n";

const PROVIDER_ALLOW_WITH_COOKIE: &str = "HTTP/1.1 200 OK\r\n\
authorization: Bearer provider-minted-token\r\n\
set-cookie: session=refreshed; Path=/\r\n\
content-length: 0\r\n\r\n";

/// Two contiguous dispatch instances on the carried route, both soft
/// fallbacks (`reject_unmatched: false`): the first routes `x-version: v1`
/// to the route's own destination (reviews), the second `x-version: v2` to
/// ratings. The cache installs one finalizer after the second.
fn two_dispatch_chain() -> Vec<Arc<dyn Plugin>> {
    let instance = |version: &str, upstream: &str| {
        create_plugin(
            "mesh_route_dispatch",
            &json!({
                "rules": [{
                    "match": {"headers": {"x-version": version}},
                    "destination": {"upstream_id": upstream}
                }]
            }),
        )
        .expect("dispatch config constructs")
        .expect("built-in plugin")
    };
    dispatch_chain(vec![
        instance("v1", REVIEWS_UPSTREAM),
        instance("v2", RATINGS_UPSTREAM),
    ])
}

/// Issue #7383 review (round 2, sol F1): with several dispatch instances, an
/// earlier instance that does not match must not judge the destination the
/// request has at that point. Only the destination the whole group selects
/// is admitted, so a request the own destination would refuse reaches the
/// alternative a later instance selects.
#[tokio::test]
async fn two_dispatch_instances_judge_only_the_final_destination() {
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = MeshAuthz::new(&authz_config(&prepared)).expect("mesh_authz builds");
    let chain = two_dispatch_chain();

    let (authorized, dispatched, ctx, _) =
        serve_version(&authz, &chain, &route, UNTRUSTED, Some("v2")).await;
    assert!(matches!(authorized, PluginResult::Continue));
    assert!(
        matches!(dispatched, Some(PluginResult::Continue)),
        "the first instance's miss must not refuse for reviews: {dispatched:?}"
    );
    assert_eq!(
        ctx.route_override_upstream_id.as_deref(),
        Some(RATINGS_UPSTREAM)
    );

    // A request the first instance routes to reviews is still judged by
    // reviews' own policy.
    let (_, dispatched, _, _) = serve_version(&authz, &chain, &route, UNTRUSTED, Some("v1")).await;
    assert_denied(
        &dispatched.expect("dispatch ran"),
        DENIED_BODY,
        "reviews refuses UNTRUSTED",
    );
}

/// Issue #7383 review (round 2, sol F1): with several dispatch instances, the
/// own destination's CUSTOM check runs only for a request the group finally
/// sends there; an allow binds nothing for a request a later instance sends
/// elsewhere.
#[tokio::test]
async fn two_dispatch_instances_run_custom_only_for_the_final_destination_allow() {
    let (port, calls) = start_provider(PROVIDER_ALLOW_WITH_TOKEN).await;
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = authz_with_custom(&prepared, custom_policy("reviews-ext", "reviews"), port);
    let chain = two_dispatch_chain();

    let (_, dispatched, ctx, headers) =
        serve_version(&authz, &chain, &route, TRUSTED, Some("v2")).await;
    assert!(
        matches!(dispatched, Some(PluginResult::Continue)),
        "ratings is reached and admitted: {dispatched:?}"
    );
    assert_eq!(
        ctx.route_override_upstream_id.as_deref(),
        Some(RATINGS_UPSTREAM)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer client-token")
    );

    let (_, dispatched, _, headers) =
        serve_version(&authz, &chain, &route, TRUSTED, Some("v1")).await;
    assert!(matches!(dispatched, Some(PluginResult::Continue)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer provider-minted-token")
    );
}

/// Issue #7383 review (round 2, sol F1): an own-destination CUSTOM refusal
/// never refuses a request a later dispatch instance sends elsewhere.
#[tokio::test]
async fn two_dispatch_instances_run_custom_only_for_the_final_destination_deny() {
    let (port, calls) = start_provider(PROVIDER_DENY).await;
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = authz_with_custom(&prepared, custom_policy("reviews-ext", "reviews"), port);
    let chain = two_dispatch_chain();

    let (_, dispatched, _, _) = serve_version(&authz, &chain, &route, TRUSTED, Some("v2")).await;
    assert!(matches!(dispatched, Some(PluginResult::Continue)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (_, dispatched, ctx, _) = serve_version(&authz, &chain, &route, TRUSTED, Some("v1")).await;
    match dispatched.expect("dispatch ran") {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
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

/// Issue #7383 review (round 2, sol F2): a reached branch whose destination
/// has both a CUSTOM policy and a refusing local policy runs its provider
/// first, as a direct request to that destination does. A provider refusal
/// keeps the provider's own status and allowlisted header.
#[tokio::test]
async fn a_reached_branch_runs_custom_before_its_local_denial_provider_refuses() {
    let (port, calls) = start_provider(PROVIDER_DENY_401).await;
    let slice = node_waypoint_slice(vec![reviews_trusted_only(), ratings_untrusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = authz_with_custom(&prepared, custom_policy("ratings-ext", "ratings"), port);
    let dispatch = route_dispatch(&prepared, &route);

    let (authorized, dispatched, ctx) = serve(&authz, &dispatch, &route, TRUSTED, true).await;
    assert!(matches!(authorized, PluginResult::Continue));
    match dispatched.expect("dispatch ran") {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 401, "the provider's own status is kept");
            assert!(
                headers.contains_key("www-authenticate"),
                "the provider's allowlisted challenge is kept: {headers:?}"
            );
        }
        other => panic!("the ratings provider refuses, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the provider decides first"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("custom:ratings-ext")
    );
    assert!(ctx.metadata.contains_key("mesh_authz.ext_authz_outcome"));
}

/// Issue #7383 review (round 2, sol F2): when the provider allows, the
/// branch's stored local denial still applies, and none of the provider's
/// mutations reach the request.
#[tokio::test]
async fn a_reached_branch_runs_custom_before_its_local_denial_provider_allows() {
    let (port, calls) = start_provider(PROVIDER_ALLOW_WITH_TOKEN).await;
    let slice = node_waypoint_slice(vec![reviews_trusted_only(), ratings_untrusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = authz_with_custom(&prepared, custom_policy("ratings-ext", "ratings"), port);
    let dispatch = route_dispatch(&prepared, &route);

    let (_, dispatched, ctx, headers) =
        serve_capture(&authz, &dispatch, &route, TRUSTED, true).await;
    assert_denied(
        &dispatched.expect("dispatch ran"),
        DENIED_BODY,
        "ratings' local policy refuses TRUSTED after the provider allowed",
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // A request straight to ratings is decided the same way: its provider
    // allows, then its local policy refuses.
    let expected =
        own_route_deny_policy(&authz, &service_route(&prepared, RATINGS_UPSTREAM), TRUSTED).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(ctx.metadata.get("mesh_authz.deny_policy"), Some(&expected));
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer client-token"),
        "a refused branch gets none of the provider's headers"
    );
}

/// Records whether a provider-owned name is visible to a policy plugin
/// running between `mesh_authz` and route dispatch.
struct OwnedHeaderProbe {
    saw_authorization: Arc<std::sync::Mutex<Option<bool>>>,
}

#[async_trait]
impl Plugin for OwnedHeaderProbe {
    fn name(&self) -> &str {
        "test_owned_header_probe"
    }

    fn priority(&self) -> u16 {
        2900
    }

    async fn before_proxy(
        &self,
        _ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let seen = headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("authorization"));
        if let Ok(mut slot) = self.saw_authorization.lock() {
            *slot = Some(seen);
        }
        PluginResult::Continue
    }
}

/// Issue #7383 review (round 2 dsf F1, round 3 dsf F1): on a route with
/// per-destination verdicts, `mesh_authz`'s own `before_proxy` removes the
/// client's copies of every candidate provider's owned names, so no policy
/// plugin before dispatch sees them, and installs nothing. When the selected
/// destination owes no CUSTOM check, the client's own values are given back
/// unchanged.
#[tokio::test]
async fn client_copies_of_provider_owned_headers_are_hidden_then_restored() {
    let (port, calls) = start_provider(PROVIDER_ALLOW_WITH_TOKEN).await;
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz: Arc<dyn Plugin> = Arc::new(authz_with_custom(
        &prepared,
        custom_policy("reviews-ext", "reviews"),
        port,
    ));
    let saw_authorization = Arc::new(std::sync::Mutex::new(None));
    let probe: Arc<dyn Plugin> = Arc::new(OwnedHeaderProbe {
        saw_authorization: Arc::clone(&saw_authorization),
    });

    let mut ctx = node_waypoint_request(&route, TRUSTED);
    let mut headers = branch_headers(Some("v2"));
    headers.insert(
        "authorization".to_string(),
        "Bearer client-token".to_string(),
    );
    headers.insert("X_Authorization".to_string(), "unrelated".to_string());
    ctx.headers = headers.clone();
    assert!(matches!(
        authz.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
    let chain = dispatch_chain(vec![
        Arc::clone(&authz),
        probe,
        route_dispatch_instance(&prepared, &route),
    ]);
    let result = run_before_proxy_hooks_for_test(&chain, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue), "{result:?}");
    assert_eq!(
        ctx.route_override_upstream_id.as_deref(),
        Some(RATINGS_UPSTREAM)
    );
    assert_eq!(
        *saw_authorization.lock().expect("probe slot"),
        Some(false),
        "a policy plugin between mesh_authz and dispatch never sees the client's copy"
    );
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer client-token"),
        "ratings owes no CUSTOM check, so the client's own value is restored: {headers:?}"
    );
    assert_eq!(
        headers.get("X_Authorization").map(String::as_str),
        Some("unrelated"),
        "an unrelated header is untouched"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no check runs for ratings");
}

/// Issue #7383 review (round 2, dsf F3): the reached destination's provider
/// `headersToDownstreamOnAllow` result lands on that request's response only.
#[tokio::test]
async fn downstream_provider_headers_land_only_for_the_reached_branch() {
    let (port, calls) = start_provider(PROVIDER_ALLOW_WITH_COOKIE).await;
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = Arc::new(authz_with_custom_policies(
        &prepared,
        vec![custom_policy("reviews-ext", "reviews")],
        port,
        vec!["set-cookie".to_string()],
    ));
    let chain = dispatch_chain(vec![
        Arc::clone(&authz) as Arc<dyn Plugin>,
        route_dispatch_instance(&prepared, &route),
    ]);

    for (v2, expect_cookie) in [(false, true), (true, false)] {
        let (authorized, dispatched, mut ctx, _) =
            serve_capture(&authz, &chain, &route, TRUSTED, v2).await;
        assert!(matches!(authorized, PluginResult::Continue));
        assert!(
            matches!(dispatched, Some(PluginResult::Continue)),
            "v2={v2}: {dispatched:?}"
        );
        let mut response_headers = HashMap::new();
        run_after_proxy_hooks_for_test(&chain, &mut ctx, 200, &mut response_headers).await;
        assert_eq!(
            response_headers.contains_key("set-cookie"),
            expect_cookie,
            "v2={v2}: {response_headers:?}"
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "only the reviews branch is checked"
    );
}

/// Issue #7383 review (round 2, dsf F3): a second `mesh_authz` instance folds
/// its verdicts in conjunctively; tables that cannot be aligned refuse every
/// destination.
#[tokio::test]
async fn a_second_mesh_authz_instance_merges_conjunctively() {
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let config = authz_config(&prepared);
    let first = MeshAuthz::new(&config).expect("mesh_authz builds");
    let aligned = MeshAuthz::new(&config).expect("mesh_authz builds");
    let mut misaligned_config = config.clone();
    misaligned_config["node_waypoint_route_branches"][0]["destinations"]
        .as_array_mut()
        .expect("destinations")
        .push(json!({"backend_host": "api.example.com", "backend_port": 443}));
    let misaligned = MeshAuthz::new(&misaligned_config).expect("mesh_authz builds");
    let dispatch = route_dispatch(&prepared, &route);

    for (second, admitted) in [(&aligned, true), (&misaligned, false)] {
        let mut ctx = node_waypoint_request(&route, TRUSTED);
        let mut headers = branch_headers(Some("v2"));
        ctx.headers = headers.clone();
        assert!(matches!(
            first.authorize(&mut ctx).await,
            PluginResult::Continue
        ));
        assert!(matches!(
            second.authorize(&mut ctx).await,
            PluginResult::Continue
        ));
        let result = run_before_proxy_hooks_for_test(&dispatch, &mut ctx, &mut headers).await;
        if admitted {
            assert!(
                matches!(result, PluginResult::Continue),
                "aligned verdicts keep ratings allowed: {result:?}"
            );
        } else {
            assert_denied(
                &result,
                DENIED_BODY,
                "misaligned tables refuse every destination",
            );
            assert_eq!(
                ctx.metadata
                    .get("mesh_authz.deny_policy")
                    .map(String::as_str),
                Some("route_branch_unauthorized")
            );
        }
    }
}

const RATINGS_8081_UPSTREAM: &str = "__mesh-out-upstream-default-ratings-8081";

/// A selector-scoped `ratings` rule limited to `ports`.
fn ratings_rule_on_ports(name: &str, ports: &[u16], action: PolicyAction) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: selector("ratings"),
        rules: vec![MeshRule {
            from: Vec::new(),
            to: vec![RequestMatch {
                ports: ports.to_vec(),
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action,
        }],
    }
}

/// The ratings-on-8081 fixture: `reviews` on 8080 is the route's own
/// destination, `x-version: v2` goes to `ratings` on 8081.
fn ratings_on_8081(policies: Vec<MeshPolicy>) -> (GatewayConfig, Proxy) {
    let config = translated_config_with_ratings_port(policies, 8081);
    let slice =
        MeshSlice::from_gateway_config(&config, node_waypoint_runtime().mesh_slice_request());
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    (prepared, route)
}

/// A captured NodeWaypoint request that arrived on port 8080 (reviews' port).
async fn serve_captured_on_8080(
    authz: &MeshAuthz,
    plugins: &[Arc<dyn Plugin>],
    route: &Proxy,
    version: Option<&str>,
) -> (PluginResult, Option<PluginResult>, RequestContext) {
    let mut ctx = node_waypoint_request(route, TRUSTED);
    ctx.mesh_direction = Some(ferrum_edge::modes::mesh::MeshTrafficDirection::Outbound);
    ctx.orig_dst = Some("10.96.0.20:8080".parse().expect("orig dst"));
    let mut headers = branch_headers(version);
    ctx.headers = headers.clone();
    let authorized = authz.authorize(&mut ctx).await;
    if !matches!(authorized, PluginResult::Continue) {
        return (authorized, None, ctx);
    }
    let dispatched = run_before_proxy_hooks_for_test(plugins, &mut ctx, &mut headers).await;
    (authorized, Some(dispatched), ctx)
}

/// Issue #7383 review (round 3, sol F1): an alternative destination on a
/// different port is judged on ITS port. A DENY scoped to ratings' port
/// refuses the ratings branch although the request arrived on reviews' port,
/// and a DENY scoped to the arrival port does not leak onto ratings.
#[tokio::test]
async fn an_alternative_on_another_port_is_judged_on_its_own_port() {
    let (prepared, route) = ratings_on_8081(vec![reviews_trusted_only()]);
    let branches = authz_config(&prepared)["node_waypoint_route_branches"].clone();
    assert_eq!(
        branches[0]["destinations"][1],
        json!({"upstream_id": RATINGS_8081_UPSTREAM}),
        "the branch is threaded on ratings' own Service port"
    );
    let dispatch = route_dispatch(&prepared, &route);

    for (deny_port, refused) in [(8081u16, true), (8080u16, false)] {
        let mut config = authz_config(&prepared);
        config["mesh_slice"]["mesh_policies"]
            .as_array_mut()
            .expect("policy list")
            .push(
                serde_json::to_value(ratings_rule_on_ports(
                    "ratings-port-deny",
                    &[deny_port],
                    PolicyAction::Deny,
                ))
                .expect("policy serializes"),
            );
        let authz = MeshAuthz::new(&config).expect("mesh_authz builds");
        let (authorized, dispatched, ctx) =
            serve_captured_on_8080(&authz, &dispatch, &route, Some("v2")).await;
        assert!(
            matches!(authorized, PluginResult::Continue),
            "deny on {deny_port}: {authorized:?}"
        );
        let dispatched = dispatched.expect("dispatch ran");
        if refused {
            assert_denied(&dispatched, DENIED_BODY, "a DENY on ratings' port applies");
            assert!(
                ctx.metadata
                    .get("mesh_authz.deny_policy")
                    .is_some_and(|policy| policy.contains("ratings-port-deny")),
                "{:?}",
                ctx.metadata.get("mesh_authz.deny_policy")
            );
        } else {
            assert!(
                matches!(dispatched, PluginResult::Continue),
                "a DENY on the arrival port must not apply to ratings: {dispatched:?}"
            );
            assert_eq!(
                ctx.route_override_upstream_id.as_deref(),
                Some(RATINGS_8081_UPSTREAM)
            );
        }
    }
}

/// Issue #7383 review (round 3, sol F1): a CUSTOM rule limited to the
/// alternative's own port is found for that branch and its provider decides.
#[tokio::test]
async fn an_alternative_port_scoped_custom_rule_runs_on_its_own_port() {
    let (port, calls) = start_provider(PROVIDER_DENY).await;
    let (prepared, route) = ratings_on_8081(vec![reviews_trusted_only()]);
    let authz = authz_with_custom(
        &prepared,
        ratings_rule_on_ports(
            "ratings-port-ext",
            &[8081],
            PolicyAction::Custom {
                provider: "branch-ext-authz".to_string(),
            },
        ),
        port,
    );
    let dispatch = route_dispatch(&prepared, &route);

    let (authorized, dispatched, ctx) =
        serve_captured_on_8080(&authz, &dispatch, &route, Some("v2")).await;
    assert!(matches!(authorized, PluginResult::Continue));
    match dispatched.expect("dispatch ran") {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("the ratings provider refuses, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the port-scoped CUSTOM rule matched ratings' port"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("custom:ratings-port-ext")
    );
}

/// Issue #7383 review (round 3, sol F2): the early route-total preview follows
/// the dispatch group like execution does. An intermediate rule whose
/// destination the request may not reach is replaced by a later instance's
/// allowed, timed destination, so the preview arms that destination's total.
#[tokio::test]
async fn the_route_total_preview_follows_the_dispatch_group() {
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let authz = MeshAuthz::new(&authz_config(&prepared)).expect("mesh_authz builds");
    let instance = |upstream: &str, timeout_ms: u64| {
        create_plugin(
            "mesh_route_dispatch",
            &json!({
                "rules": [{
                    "match": {"headers": {"x-version": "v2"}},
                    "destination": {"upstream_id": upstream},
                    "request_timeout_ms": timeout_ms
                }]
            }),
        )
        .expect("dispatch config constructs")
        .expect("built-in plugin")
    };
    // Both instances match; the first selects reviews (which refuses
    // UNTRUSTED), the second replaces it with ratings and a 100 ms total.
    let chain = dispatch_chain(vec![
        instance(REVIEWS_UPSTREAM, 5000),
        instance(RATINGS_UPSTREAM, 100),
    ]);

    let mut ctx = node_waypoint_request(&route, UNTRUSTED);
    let mut headers = branch_headers(Some("v2"));
    ctx.headers = headers.clone();
    assert!(matches!(
        authz.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
    assert_eq!(
        early_route_total_ms_for_test(&chain, &ctx, true),
        Some(100),
        "the preview arms the final destination's total"
    );
    let result = run_before_proxy_hooks_for_test(&chain, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue), "{result:?}");
    assert_eq!(
        ctx.route_override_upstream_id.as_deref(),
        Some(RATINGS_UPSTREAM)
    );
    assert_eq!(ctx.route_override_request_timeout_ms, Some(100));
}

/// A selector-scoped `ratings` rule with one `when:` condition on
/// `destination.port`.
fn ratings_rule_on_destination_port(
    name: &str,
    values: &[&str],
    not_values: &[&str],
    action: PolicyAction,
) -> MeshPolicy {
    let mut policy = ratings_rule_on_ports(name, &[], action);
    policy.rules[0].to = Vec::new();
    policy.rules[0].when = vec![ConditionMatch {
        key: "destination.port".to_string(),
        values: values.iter().map(ToString::to_string).collect(),
        not_values: not_values.iter().map(ToString::to_string).collect(),
    }];
    policy
}

fn authz_with_policy(prepared: &GatewayConfig, policy: MeshPolicy) -> MeshAuthz {
    authz_with_policies(prepared, vec![policy])
}

/// `mesh_authz` from the prepared config plus `policies` (no provider).
fn authz_with_policies(prepared: &GatewayConfig, policies: Vec<MeshPolicy>) -> MeshAuthz {
    let mut config = authz_config(prepared);
    config["mesh_slice"]
        .as_object_mut()
        .expect("embedded mesh slice")
        .entry("mesh_policies")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("policy list")
        .extend(
            policies
                .into_iter()
                .map(|policy| serde_json::to_value(policy).expect("policy serializes")),
        );
    MeshAuthz::new(&config).expect("mesh_authz builds")
}

/// Issue #7383 review (round 4, sol F1): a request that arrives with no
/// destination port (no captured original destination) still has the branch
/// port as BOTH the typed port and the `destination.port` attribute, so a
/// positive `destination.port` DENY on the alternative applies.
#[tokio::test]
async fn a_portless_arrival_still_applies_a_destination_port_deny_on_the_branch() {
    let (prepared, route) = ratings_on_8081(vec![reviews_trusted_only()]);
    let dispatch = route_dispatch(&prepared, &route);
    let authz = authz_with_policy(
        &prepared,
        ratings_rule_on_destination_port("ratings-dport-deny", &["8081"], &[], PolicyAction::Deny),
    );
    let (authorized, dispatched, ctx) = serve(&authz, &dispatch, &route, TRUSTED, true).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "{authorized:?}"
    );
    assert_denied(
        &dispatched.expect("dispatch ran"),
        DENIED_BODY,
        "the destination.port DENY on ratings applies",
    );
    assert!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .is_some_and(|policy| policy.contains("ratings-dport-deny")),
        "{:?}",
        ctx.metadata.get("mesh_authz.deny_policy")
    );
}

/// Issue #7383 review (round 4, sol F1): from a portless arrival, a
/// negative-only `destination.port` ALLOW on the alternative does not grant a
/// request reaching the excluded port.
#[tokio::test]
async fn a_portless_arrival_does_not_let_a_negative_destination_port_allow_grant() {
    let (prepared, route) = ratings_on_8081(vec![reviews_trusted_only()]);
    let dispatch = route_dispatch(&prepared, &route);
    let authz = authz_with_policy(
        &prepared,
        ratings_rule_on_destination_port("ratings-not-8081", &[], &["8081"], PolicyAction::Allow),
    );
    let (authorized, dispatched, _) = serve(&authz, &dispatch, &route, TRUSTED, true).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "{authorized:?}"
    );
    assert_denied(
        &dispatched.expect("dispatch ran"),
        DENIED_BODY,
        "an ALLOW excluding 8081 must not admit ratings:8081",
    );
}

/// Issue #7383 review (round 4, sol F1): from a portless arrival, a CUSTOM
/// rule conditioned on the alternative's `destination.port` runs.
#[tokio::test]
async fn a_portless_arrival_runs_a_destination_port_custom_rule_on_the_branch() {
    let (port, calls) = start_provider(PROVIDER_DENY).await;
    let (prepared, route) = ratings_on_8081(vec![reviews_trusted_only()]);
    let dispatch = route_dispatch(&prepared, &route);
    let authz = authz_with_custom(
        &prepared,
        ratings_rule_on_destination_port(
            "ratings-dport-ext",
            &["8081"],
            &[],
            PolicyAction::Custom {
                provider: "branch-ext-authz".to_string(),
            },
        ),
        port,
    );
    let (authorized, dispatched, ctx) = serve(&authz, &dispatch, &route, TRUSTED, true).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "{authorized:?}"
    );
    match dispatched.expect("dispatch ran") {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("the ratings provider refuses, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("custom:ratings-dport-ext")
    );
}

/// Issue #7383 review (round 4, sol F1): from a request that arrived on 8080,
/// `destination.port` on the alternative names 8081: a DENY on 8081 applies,
/// a DENY on the arrival port does not.
#[tokio::test]
async fn a_destination_port_condition_on_the_branch_names_its_own_port() {
    let (prepared, route) = ratings_on_8081(vec![reviews_trusted_only()]);
    let dispatch = route_dispatch(&prepared, &route);
    for (deny_port, refused) in [("8081", true), ("8080", false)] {
        let authz = authz_with_policy(
            &prepared,
            ratings_rule_on_destination_port(
                "ratings-dport-deny",
                &[deny_port],
                &[],
                PolicyAction::Deny,
            ),
        );
        let (authorized, dispatched, _) =
            serve_captured_on_8080(&authz, &dispatch, &route, Some("v2")).await;
        assert!(
            matches!(authorized, PluginResult::Continue),
            "{authorized:?}"
        );
        let dispatched = dispatched.expect("dispatch ran");
        if refused {
            assert_denied(&dispatched, DENIED_BODY, "destination.port 8081 applies");
        } else {
            assert!(
                matches!(dispatched, PluginResult::Continue),
                "destination.port 8080 must not apply to ratings: {dispatched:?}"
            );
        }
    }
}

const PROVIDER_ALLOW_WITH_VERIFIED_USER: &str = "HTTP/1.1 200 OK\r\n\
x-verified-user: alice\r\n\
content-length: 0\r\n\r\n";

/// Issue #7383 review (round 4, sol F2 / dsf F1): two destination-specific
/// providers with disjoint owned headers. The reached destination's provider
/// decides only its own names; the client's copy of a name only the OTHER
/// destination's provider owns goes through unchanged.
#[tokio::test]
async fn disjoint_providers_decide_only_their_own_headers() {
    let (reviews_port, reviews_calls) = start_provider(PROVIDER_ALLOW_WITH_TOKEN).await;
    let (ratings_port, ratings_calls) = start_provider(PROVIDER_ALLOW_WITH_VERIFIED_USER).await;
    let slice = node_waypoint_slice(vec![reviews_trusted_only()]);
    let prepared = prepare(&slice);
    let route = carried_route(&prepared);
    let mut reviews_ext = custom_policy("reviews-ext", "reviews");
    reviews_ext.rules[0].action = PolicyAction::Custom {
        provider: "reviews-ext-authz".to_string(),
    };
    let mut ratings_ext = custom_policy("ratings-ext", "ratings");
    ratings_ext.rules[0].action = PolicyAction::Custom {
        provider: "ratings-ext-authz".to_string(),
    };
    let authz = Arc::new(authz_with_providers(
        &prepared,
        vec![reviews_ext, ratings_ext],
        vec![
            stub_provider("reviews-ext-authz", reviews_port, &["authorization"]),
            stub_provider("ratings-ext-authz", ratings_port, &["x-verified-user"]),
        ],
    ));
    let chain = authz_dispatch_chain(&authz, &prepared, &route);

    let serve_forged = |v2: bool| {
        let authz = Arc::clone(&authz);
        let chain = chain.clone();
        let route = route.clone();
        async move {
            let mut ctx = node_waypoint_request(&route, TRUSTED);
            let mut headers = branch_headers(v2.then_some("v2"));
            headers.insert(
                "authorization".to_string(),
                "Bearer client-token".to_string(),
            );
            headers.insert("x-verified-user".to_string(), "mallory".to_string());
            ctx.headers = headers.clone();
            assert!(matches!(
                authz.authorize(&mut ctx).await,
                PluginResult::Continue
            ));
            let result = run_before_proxy_hooks_for_test(&chain, &mut ctx, &mut headers).await;
            (result, headers)
        }
    };

    // ratings: its provider sets x-verified-user; the client's bearer token
    // (owned only by reviews' provider) reaches ratings unchanged.
    let (result, headers) = serve_forged(true).await;
    assert!(matches!(result, PluginResult::Continue), "{result:?}");
    assert_eq!(
        headers.get("x-verified-user").map(String::as_str),
        Some("alice")
    );
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer client-token")
    );
    assert_eq!(ratings_calls.load(Ordering::SeqCst), 1);
    assert_eq!(reviews_calls.load(Ordering::SeqCst), 0);

    // reviews: its provider sets authorization; the client's x-verified-user
    // (owned only by ratings' provider, which was not consulted) is the
    // client's own value, as on a route with no other candidate.
    let (result, headers) = serve_forged(false).await;
    assert!(matches!(result, PluginResult::Continue), "{result:?}");
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer provider-minted-token")
    );
    assert_eq!(
        headers.get("x-verified-user").map(String::as_str),
        Some("mallory")
    );
    assert_eq!(reviews_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ratings_calls.load(Ordering::SeqCst), 1);
}

/// A rule on `app` (or mesh-wide when `app` is `None`) with one `when:`
/// condition.
fn rule_with_condition(
    name: &str,
    app: Option<&str>,
    key: &str,
    values: &[&str],
    action: PolicyAction,
) -> MeshPolicy {
    let mut policy = ratings_rule_on_ports(name, &[], action);
    policy.scope = app.map_or(PolicyScope::MeshWide, selector);
    policy.rules[0].to = Vec::new();
    policy.rules[0].when = vec![ConditionMatch {
        key: key.to_string(),
        values: values.iter().map(ToString::to_string).collect(),
        not_values: Vec::new(),
    }];
    policy
}

/// Issue #7383 review (round 5, sol F1): with only a MESH-WIDE policy loaded
/// (no selector-scoped one), candidates are still evaluated on their own
/// port: a mesh-wide DENY on 8081 refuses the ratings:8081 branch of a
/// request that arrived on 8080, and leaves the own branch alone.
#[tokio::test]
async fn a_mesh_wide_port_deny_applies_to_the_branch_it_names() {
    let (prepared, route) = ratings_on_8081(Vec::new());
    let dispatch = route_dispatch(&prepared, &route);
    let mut deny = ratings_rule_on_ports("mesh-deny-8081", &[8081], PolicyAction::Deny);
    deny.scope = PolicyScope::MeshWide;
    let authz = authz_with_policy(&prepared, deny);

    let (authorized, dispatched, ctx) =
        serve_captured_on_8080(&authz, &dispatch, &route, Some("v2")).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "{authorized:?}"
    );
    assert_denied(
        &dispatched.expect("dispatch ran"),
        DENIED_BODY,
        "the mesh-wide DENY on 8081 applies to ratings:8081",
    );
    assert!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .is_some_and(|policy| policy.contains("mesh-deny-8081")),
        "{:?}",
        ctx.metadata.get("mesh_authz.deny_policy")
    );

    let (_, dispatched, _) = serve_captured_on_8080(&authz, &dispatch, &route, None).await;
    assert!(
        matches!(dispatched, Some(PluginResult::Continue)),
        "reviews:8080 is not named by the DENY: {dispatched:?}"
    );
}

/// Issue #7383 review (round 5, sol F1): a mesh-wide CUSTOM rule limited to
/// 8081 runs for the ratings:8081 branch with no selector-scoped policy
/// loaded, and not for the own branch on 8080.
#[tokio::test]
async fn a_mesh_wide_port_custom_rule_runs_for_the_branch_it_names() {
    let (port, calls) = start_provider(PROVIDER_DENY).await;
    let (prepared, route) = ratings_on_8081(Vec::new());
    let dispatch = route_dispatch(&prepared, &route);
    let mut custom = ratings_rule_on_ports(
        "mesh-ext-8081",
        &[8081],
        PolicyAction::Custom {
            provider: "branch-ext-authz".to_string(),
        },
    );
    custom.scope = PolicyScope::MeshWide;
    let authz = authz_with_custom(&prepared, custom, port);

    let (authorized, dispatched, ctx) =
        serve_captured_on_8080(&authz, &dispatch, &route, Some("v2")).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "{authorized:?}"
    );
    match dispatched.expect("dispatch ran") {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("the provider refuses the ratings branch, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("custom:mesh-ext-8081")
    );

    let (_, dispatched, _) = serve_captured_on_8080(&authz, &dispatch, &route, None).await;
    assert!(matches!(dispatched, Some(PluginResult::Continue)));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "no check for reviews:8080");
}

/// Issue #7383 review (round 5, dsf F1): the arrival destination address is
/// not an alternative's, so `destination.ip` is unsourceable there and fails
/// closed: a DENY on another address still refuses the branch.
#[tokio::test]
async fn a_destination_ip_deny_on_the_branch_fails_closed() {
    let (prepared, route) = ratings_on_8081(vec![reviews_trusted_only()]);
    let dispatch = route_dispatch(&prepared, &route);
    let authz = authz_with_policy(
        &prepared,
        rule_with_condition(
            "ratings-dip-deny",
            Some("ratings"),
            "destination.ip",
            &["10.96.0.99/32"],
            PolicyAction::Deny,
        ),
    );
    let (authorized, dispatched, _) =
        serve_captured_on_8080(&authz, &dispatch, &route, Some("v2")).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "{authorized:?}"
    );
    assert_denied(
        &dispatched.expect("dispatch ran"),
        DENIED_BODY,
        "an unsourceable destination.ip makes the ratings DENY match",
    );
}

/// Issue #7383 review (round 5, dsf F1): an ALLOW on the arrival address
/// admits the own branch (whose address it is) but never the alternative.
#[tokio::test]
async fn a_destination_ip_allow_on_the_arrival_address_admits_only_the_own_branch() {
    let (prepared, route) = ratings_on_8081(Vec::new());
    let dispatch = route_dispatch(&prepared, &route);
    let authz = authz_with_policies(
        &prepared,
        vec![
            rule_with_condition(
                "reviews-arrival-ip",
                Some("reviews"),
                "destination.ip",
                &["10.96.0.20/32"],
                PolicyAction::Allow,
            ),
            rule_with_condition(
                "ratings-arrival-ip",
                Some("ratings"),
                "destination.ip",
                &["10.96.0.20/32"],
                PolicyAction::Allow,
            ),
        ],
    );

    let (_, dispatched, _) = serve_captured_on_8080(&authz, &dispatch, &route, None).await;
    assert!(
        matches!(dispatched, Some(PluginResult::Continue)),
        "the own branch matches on its arrival address: {dispatched:?}"
    );

    let (authorized, dispatched, _) =
        serve_captured_on_8080(&authz, &dispatch, &route, Some("v2")).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "{authorized:?}"
    );
    assert_denied(
        &dispatched.expect("dispatch ran"),
        DENIED_BODY,
        "the arrival address is not ratings', so its ALLOW never matches",
    );
}
