//! Weighted VirtualService splits dispatched leg by leg on a NodeWaypoint
//! (issue #7387).
//!
//! A split naming a Service that a DestinationRule governs is no longer
//! refused: slice preparation gives the route's `mesh_route_dispatch`
//! instance the split's legs (`weighted_splits`), each the Service port's own
//! materialized upstream (which carries the DestinationRule) or a residual
//! upstream per external host. The dispatch finalizer picks a leg once
//! routing is final and publishes it as the route override, so dispatch uses
//! that leg's own policy, and per-destination authorization judges the leg.
//! These tests drive the production halves: the K8s translator, the control
//! plane's slice projection, the data plane's slice preparation, `mesh_authz`
//! built from the prepared config, and the production `before_proxy` chain
//! (dispatch instance, cache-installed finalizer, proxy core's final check).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ferrum_edge::_test_support::{
    collect_rejecting_runtime_config_errors_for_test, install_plugin_finalizers_for_test,
    run_before_proxy_hooks_for_test,
};
use ferrum_edge::config::db_backend::namespaced_runtime_key;
use ferrum_edge::config::types::{GatewayConfig, Proxy, Upstream};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MeshExtAuthzProvider, MeshPolicy, MeshRule, PolicyAction, PolicyScope, WorkloadSelector,
};
use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::modes::mesh::{
    MESH_AUTHZ_PLUGIN_ID, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_from_mesh_slice,
};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext, create_plugin};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::scaffolding::port_registry::TestSocket;

use super::super::mesh_test_support::{
    DEFAULT_NAMESPACE, policy_allow_principal, policy_deny_principal, runtime_for_topology,
    service_for, workload_for,
};

const TRUSTED: &str = "spiffe://cluster.local/ns/default/sa/trusted";
const UNTRUSTED: &str = "spiffe://cluster.local/ns/default/sa/untrusted";
const REVIEWS_UPSTREAM: &str = "__mesh-out-upstream-default-reviews-8080";
const RATINGS_UPSTREAM: &str = "__mesh-out-upstream-default-ratings-8080";
const DETAILS_UPSTREAM: &str = "__mesh-out-upstream-default-details-8080";
const DENIED_BODY: &str = r#"{"error":"Mesh authorization denied"}"#;

fn k8s_object(kind: &str, name: &str, spec: serde_json::Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: kind.to_string(),
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

/// A VirtualService on the `reviews` host whose only route splits across
/// `legs` (`(destination host, port, weight)`).
fn split_virtual_service(name: &str, host: &str, legs: &[(&str, u16, u32)]) -> K8sObject {
    let route: Vec<serde_json::Value> = legs
        .iter()
        .map(|(destination, port, weight)| {
            json!({
                "destination": {"host": destination, "port": {"number": port}},
                "weight": weight
            })
        })
        .collect();
    k8s_object(
        "VirtualService",
        name,
        json!({"hosts": [host], "http": [{"route": route}]}),
    )
}

fn reviews_ratings_split(reviews_weight: u32, ratings_weight: u32) -> K8sObject {
    split_virtual_service(
        "split",
        "reviews.default.svc.cluster.local",
        &[
            ("reviews.default.svc.cluster.local", 8080, reviews_weight),
            ("ratings.default.svc.cluster.local", 8080, ratings_weight),
        ],
    )
}

/// A DestinationRule whose connection pool gives the Service's traffic a
/// distinct connection limit and connect timeout.
fn pool_destination_rule(
    name: &str,
    host: &str,
    max_connections: u32,
    connect_timeout: &str,
) -> K8sObject {
    k8s_object(
        "DestinationRule",
        name,
        json!({
            "host": host,
            "trafficPolicy": {
                "connectionPool": {
                    "tcp": {
                        "maxConnections": max_connections,
                        "connectTimeout": connect_timeout
                    }
                }
            }
        }),
    )
}

/// `reviews` (3 connections, 1s) and `ratings` (7 connections, 2s).
fn reviews_and_ratings_rules() -> Vec<K8sObject> {
    vec![
        pool_destination_rule("reviews-dr", "reviews.default.svc.cluster.local", 3, "1s"),
        pool_destination_rule("ratings-dr", "ratings.default.svc.cluster.local", 7, "2s"),
    ]
}

fn selector(app: &str) -> PolicyScope {
    PolicyScope::WorkloadSelector {
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), app.to_string())]),
            namespace: None,
        },
    }
}

/// Translate `objects` and add the mesh inventory: `reviews`, `ratings` and
/// `details`, each one workload on port 8080.
fn translated_config(objects: &[K8sObject], policies: Vec<MeshPolicy>) -> GatewayConfig {
    let translated = translate_k8s_objects(
        objects,
        K8sTranslationOptions::new(
            DEFAULT_NAMESPACE.to_string(),
            TrustDomain::new("cluster.local").expect("trust domain"),
        ),
    )
    .expect("resources translate");
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
    mesh.mesh_policies = policies;
    config.normalize_fields();
    config.normalize_mesh_fields();
    config
}

fn node_waypoint_runtime() -> MeshRuntimeConfig {
    runtime_for_topology(MeshTopology::NodeWaypoint)
}

fn slice_for(config: &GatewayConfig) -> MeshSlice {
    MeshSlice::from_gateway_config(config, node_waypoint_runtime().mesh_slice_request())
}

fn prepare(objects: &[K8sObject], policies: Vec<MeshPolicy>) -> (MeshSlice, GatewayConfig) {
    let slice = slice_for(&translated_config(objects, policies));
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &node_waypoint_runtime())
        .expect("slice materializes");
    (slice, prepared)
}

/// The carried VirtualService routes of a prepared config.
fn carried_routes(prepared: &GatewayConfig) -> Vec<&Proxy> {
    prepared
        .proxies
        .iter()
        .filter(|proxy| proxy.id.starts_with("istio-vs-") && !proxy.id.starts_with("istio-vs-l4_"))
        .collect()
}

/// The one carried route, which keeps the split as its own destination.
fn carried_split_route(prepared: &GatewayConfig) -> Proxy {
    let routes = carried_routes(prepared);
    assert_eq!(routes.len(), 1, "the split route is served");
    let route = routes[0].clone();
    assert!(
        route
            .upstream_id
            .as_deref()
            .is_some_and(|id| id.starts_with("istio-vs-upstream-")),
        "the route's own destination stays the split: {:?}",
        route.upstream_id
    );
    route
}

/// The route's `mesh_route_dispatch` config.
fn route_dispatch_config(prepared: &GatewayConfig, route: &Proxy) -> serde_json::Value {
    prepared
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
        .expect("the route has a mesh_route_dispatch instance")
        .config
        .clone()
}

/// The legs the route's dispatch instance resolves `split_id` to.
fn split_legs(prepared: &GatewayConfig, route: &Proxy, split_id: &str) -> Vec<(String, u64)> {
    let config = route_dispatch_config(prepared, route);
    let split = config["weighted_splits"]
        .as_array()
        .expect("weighted splits written")
        .iter()
        .find(|split| split["upstream_id"] == json!(split_id))
        .expect("the split is resolved leg by leg")
        .clone();
    split["legs"]
        .as_array()
        .expect("legs")
        .iter()
        .map(|leg| {
            (
                leg["upstream_id"].as_str().expect("leg id").to_string(),
                leg["weight"].as_u64().expect("leg weight"),
            )
        })
        .collect()
}

/// The production chain: `plugins` with the cache-installed finalizers.
fn chain(mut plugins: Vec<Arc<dyn Plugin>>) -> Vec<Arc<dyn Plugin>> {
    install_plugin_finalizers_for_test(&mut plugins).expect("chain assembles");
    plugins
}

fn route_dispatch_instance(prepared: &GatewayConfig, route: &Proxy) -> Arc<dyn Plugin> {
    create_plugin(
        "mesh_route_dispatch",
        &route_dispatch_config(prepared, route),
    )
    .expect("dispatch config constructs")
    .expect("built-in plugin")
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

fn route_branches(prepared: &GatewayConfig, route: &Proxy) -> serde_json::Value {
    authz_config(prepared)["node_waypoint_route_branches"]
        .as_array()
        .expect("candidate tables threaded")
        .iter()
        .find(|entry| entry["proxy_id"] == json!(route.id))
        .expect("the split route has a candidate table")
        .clone()
}

fn request(route: &Proxy, source: &str) -> RequestContext {
    request_at(route, source, "/")
}

fn request_at(route: &Proxy, source: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), path.to_string());
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

fn request_headers() -> HashMap<String, String> {
    HashMap::from([
        (
            "host".to_string(),
            "reviews.default.svc.cluster.local".to_string(),
        ),
        (
            "authorization".to_string(),
            "Bearer client-token".to_string(),
        ),
    ])
}

/// One request through the `before_proxy` chain only (no authorization).
async fn dispatch(plugins: &[Arc<dyn Plugin>], route: &Proxy) -> (PluginResult, RequestContext) {
    let mut ctx = request(route, TRUSTED);
    let mut headers = request_headers();
    ctx.headers = headers.clone();
    let result = run_before_proxy_hooks_for_test(plugins, &mut ctx, &mut headers).await;
    (result, ctx)
}

/// One request through `authz.authorize` and then the `before_proxy` chain.
async fn serve(
    authz: &MeshAuthz,
    plugins: &[Arc<dyn Plugin>],
    route: &Proxy,
    source: &str,
) -> (PluginResult, RequestContext, HashMap<String, String>) {
    let mut ctx = request(route, source);
    let mut headers = request_headers();
    ctx.headers = headers.clone();
    let authorized = authz.authorize(&mut ctx).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "a weighted-split route always continues to leg selection: {authorized:?}"
    );
    let result = run_before_proxy_hooks_for_test(plugins, &mut ctx, &mut headers).await;
    (result, ctx, headers)
}

fn selected_leg(ctx: &RequestContext) -> String {
    ctx.route_override_upstream_id
        .clone()
        .expect("a leg is published as the route override")
}

fn upstream_map(prepared: &GatewayConfig) -> HashMap<String, Arc<Upstream>> {
    prepared
        .upstreams
        .iter()
        .map(|upstream| {
            (
                namespaced_runtime_key(&upstream.namespace, &upstream.id),
                Arc::new(upstream.clone()),
            )
        })
        .collect()
}

/// `(max_connections, connect_timeout_ms)` the leg's dispatch resolves.
fn effective_leg_policy(
    ctx: &RequestContext,
    route: &Proxy,
    upstreams: &HashMap<String, Arc<Upstream>>,
) -> (Option<u32>, Option<u64>) {
    let effective = ctx.apply_route_overrides_with_upstreams(Arc::new(route.clone()), upstreams);
    let overrides = effective
        .dispatch_port_overrides
        .as_ref()
        .expect("the leg's DestinationRule projection is resolved");
    let port = overrides.get(&8080).expect("the leg's Service port policy");
    (port.max_connections, port.connect_timeout_ms)
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

/// The split is served, keeps its id as the route's own destination, and its
/// legs are each Service's own materialized upstream with the configured
/// weight; authorization lists the legs, never the split, as candidates.
#[test]
fn a_destination_rule_governed_split_is_dispatched_leg_by_leg() {
    let mut objects = vec![reviews_ratings_split(90, 10)];
    objects.extend(reviews_and_ratings_rules());
    let (slice, prepared) = prepare(&objects, Vec::new());
    assert_eq!(slice.destination_rules.len(), 2);
    let route = carried_split_route(&prepared);
    let split_id = route.upstream_id.clone().expect("split id");
    assert_eq!(
        split_legs(&prepared, &route, &split_id),
        vec![
            (REVIEWS_UPSTREAM.to_string(), 90),
            (RATINGS_UPSTREAM.to_string(), 10)
        ]
    );
    let branches = route_branches(&prepared, &route);
    assert_eq!(
        branches["destinations"],
        json!([
            {"upstream_id": split_id},
            {"upstream_id": REVIEWS_UPSTREAM},
            {"upstream_id": RATINGS_UPSTREAM}
        ])
    );
    assert_eq!(branches["own_is_weighted_split"], json!(true));
    assert_eq!(branches["weighted_split"], json!(true));
}

/// Each leg is dispatched through its own Service's upstream, so only that
/// Service's DestinationRule (connection limit and connect timeout) applies
/// to it, and the configured ratio holds exactly over every cycle,
/// interleaved rather than in runs.
#[tokio::test]
async fn each_leg_carries_only_its_own_destination_rule_and_the_ratio_holds() {
    let mut objects = vec![reviews_ratings_split(90, 10)];
    objects.extend(reviews_and_ratings_rules());
    let (_, prepared) = prepare(&objects, Vec::new());
    let route = carried_split_route(&prepared);
    let plugins = chain(vec![route_dispatch_instance(&prepared, &route)]);
    let upstreams = upstream_map(&prepared);

    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut first_ratings = None;
    for turn in 0..200 {
        let (result, ctx) = dispatch(&plugins, &route).await;
        assert!(matches!(result, PluginResult::Continue), "{result:?}");
        let leg = selected_leg(&ctx);
        let policy = effective_leg_policy(&ctx, &route, &upstreams);
        match leg.as_str() {
            REVIEWS_UPSTREAM => assert_eq!(policy, (Some(3), Some(1000)), "reviews' own rule"),
            RATINGS_UPSTREAM => {
                assert_eq!(policy, (Some(7), Some(2000)), "ratings' own rule");
                first_ratings = first_ratings.or(Some(turn));
            }
            other => panic!("no other destination is dispatched: {other}"),
        }
        *counts.entry(leg).or_default() += 1;
    }
    assert_eq!(counts[REVIEWS_UPSTREAM], 180, "90/10 holds exactly");
    assert_eq!(counts[RATINGS_UPSTREAM], 20, "90/10 holds exactly");
    assert!(
        first_ratings.is_some_and(|turn| turn < 50),
        "legs are interleaved, not served in runs: first ratings at {first_ratings:?}"
    );
}

/// Three legs keep 50/30/20 exactly per 100 requests.
#[tokio::test]
async fn a_three_leg_split_keeps_every_ratio() {
    let mut objects = vec![split_virtual_service(
        "split",
        "reviews.default.svc.cluster.local",
        &[
            ("reviews.default.svc.cluster.local", 8080, 50),
            ("ratings.default.svc.cluster.local", 8080, 30),
            ("details.default.svc.cluster.local", 8080, 20),
        ],
    )];
    objects.extend(reviews_and_ratings_rules());
    let (_, prepared) = prepare(&objects, Vec::new());
    let route = carried_split_route(&prepared);
    let plugins = chain(vec![route_dispatch_instance(&prepared, &route)]);
    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..100 {
        let (_, ctx) = dispatch(&plugins, &route).await;
        *counts.entry(selected_leg(&ctx)).or_default() += 1;
    }
    assert_eq!(counts[REVIEWS_UPSTREAM], 50);
    assert_eq!(counts[RATINGS_UPSTREAM], 30);
    assert_eq!(counts[DETAILS_UPSTREAM], 20);
}

/// A DENY policy on one leg's workloads refuses exactly the requests that
/// leg receives, answering as that destination's own policy would; the
/// other leg serves the same caller.
#[tokio::test]
async fn a_leg_deny_policy_applies_only_to_that_leg() {
    let mut objects = vec![reviews_ratings_split(90, 10)];
    objects.extend(reviews_and_ratings_rules());
    let deny = policy_deny_principal(
        "ratings-deny-untrusted",
        DEFAULT_NAMESPACE,
        selector("ratings"),
        UNTRUSTED,
    );
    let (_, prepared) = prepare(&objects, vec![deny]);
    let route = carried_split_route(&prepared);
    let authz = Arc::new(MeshAuthz::new(&authz_config(&prepared)).expect("mesh_authz builds"));
    let plugins = chain(vec![
        Arc::clone(&authz) as Arc<dyn Plugin>,
        route_dispatch_instance(&prepared, &route),
    ]);

    let (mut served, mut refused) = (0, 0);
    for _ in 0..100 {
        let (result, ctx, _) = serve(&authz, &plugins, &route, UNTRUSTED).await;
        match selected_leg(&ctx).as_str() {
            REVIEWS_UPSTREAM => {
                assert!(matches!(result, PluginResult::Continue), "{result:?}");
                served += 1;
            }
            RATINGS_UPSTREAM => {
                assert_denied(&result, "the ratings leg's own DENY refuses it");
                assert!(
                    ctx.metadata
                        .get("mesh_authz.deny_policy")
                        .is_some_and(|policy| policy.contains("ratings-deny-untrusted")),
                    "the refusal names the ratings policy: {:?}",
                    ctx.metadata.get("mesh_authz.deny_policy")
                );
                refused += 1;
            }
            other => panic!("unexpected leg {other}"),
        }
    }
    assert_eq!((served, refused), (90, 10));

    // A caller the policy does not name is served on both legs.
    for _ in 0..10 {
        let (result, _, _) = serve(&authz, &plugins, &route, TRUSTED).await;
        assert!(matches!(result, PluginResult::Continue), "{result:?}");
    }
}

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
                provider: "leg-ext-authz".to_string(),
            },
        }],
    }
}

/// `mesh_authz` from the prepared config plus `policy`, bound to a stub
/// provider on `port`.
fn authz_with_custom(prepared: &GatewayConfig, policy: MeshPolicy, port: u16) -> MeshAuthz {
    let provider = MeshExtAuthzProvider {
        name: "leg-ext-authz".to_string(),
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
    slice.insert(
        "ext_authz_providers".to_string(),
        serde_json::to_value(vec![provider]).expect("provider serializes"),
    );
    MeshAuthz::new_with_http_client(&config, Some(PluginHttpClient::default()))
        .expect("mesh_authz builds with the provider")
}

/// A CUSTOM policy on one leg's workloads runs its provider only for the
/// requests that leg receives, with the provider's own refusal; the other
/// leg is served without the provider being asked, and the client's own
/// header for a provider-owned name reaches it unchanged.
#[tokio::test]
async fn a_leg_custom_check_runs_only_for_that_leg() {
    let (port, calls) = start_provider(PROVIDER_DENY).await;
    let mut objects = vec![reviews_ratings_split(50, 50)];
    objects.extend(reviews_and_ratings_rules());
    let (_, prepared) = prepare(&objects, Vec::new());
    let route = carried_split_route(&prepared);
    let authz = Arc::new(authz_with_custom(
        &prepared,
        custom_policy("reviews-ext", "reviews"),
        port,
    ));
    let plugins = chain(vec![
        Arc::clone(&authz) as Arc<dyn Plugin>,
        route_dispatch_instance(&prepared, &route),
    ]);

    let (mut reviews, mut ratings) = (0, 0);
    for _ in 0..20 {
        let (result, ctx, headers) = serve(&authz, &plugins, &route, TRUSTED).await;
        match selected_leg(&ctx).as_str() {
            REVIEWS_UPSTREAM => {
                reviews += 1;
                match result {
                    PluginResult::Reject {
                        status_code,
                        headers,
                        ..
                    } => {
                        assert_eq!(status_code, 403);
                        assert!(
                            headers.contains_key("www-authenticate"),
                            "the provider's own refusal is kept: {headers:?}"
                        );
                    }
                    other => panic!("the reviews provider refuses its leg, got {other:?}"),
                }
                assert_eq!(
                    ctx.metadata
                        .get("mesh_authz.deny_policy")
                        .map(String::as_str),
                    Some("custom:reviews-ext")
                );
            }
            RATINGS_UPSTREAM => {
                ratings += 1;
                assert!(matches!(result, PluginResult::Continue), "{result:?}");
                assert_eq!(
                    headers.get("authorization").map(String::as_str),
                    Some("Bearer client-token"),
                    "the ratings leg owes no check and keeps the client's header"
                );
            }
            other => panic!("unexpected leg {other}"),
        }
    }
    assert_eq!((reviews, ratings), (10, 10), "50/50 holds");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        reviews,
        "the provider is asked only about requests that reach the reviews leg"
    );
}

/// A split mixing a DestinationRule-governed Service with an external host
/// dispatches the external host through a residual upstream holding only
/// that host, keeps 50/50, and authorizes the external leg on its own port
/// (it is not refused for an unresolved port) while the Service leg keeps
/// its own policy.
#[tokio::test]
async fn a_split_mixing_a_destination_rule_leg_and_an_external_leg_is_served() {
    let objects = vec![
        split_virtual_service(
            "split",
            "reviews.default.svc.cluster.local",
            &[
                ("reviews.default.svc.cluster.local", 8080, 50),
                ("api.example.com", 443, 50),
            ],
        ),
        pool_destination_rule("reviews-dr", "reviews.default.svc.cluster.local", 3, "1s"),
    ];
    let reviews_trusted_only = policy_allow_principal(
        "reviews-trusted-only",
        DEFAULT_NAMESPACE,
        selector("reviews"),
        TRUSTED,
    );
    let (_, prepared) = prepare(&objects, vec![reviews_trusted_only]);
    let route = carried_split_route(&prepared);
    let split_id = route.upstream_id.clone().expect("split id");
    let external_leg = format!("{split_id}-external-0");
    assert_eq!(
        split_legs(&prepared, &route, &split_id),
        vec![
            (REVIEWS_UPSTREAM.to_string(), 50),
            (external_leg.clone(), 50)
        ]
    );
    let residual = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == external_leg)
        .expect("the residual external upstream is materialized");
    assert_eq!(residual.targets.len(), 1);
    assert_eq!(residual.targets[0].host, "api.example.com");
    assert_eq!(residual.targets[0].port, 443);
    assert!(
        authz_config(&prepared)["node_waypoint_route_upstreams"]
            .as_array()
            .expect("route upstream index")
            .iter()
            .any(|entry| entry["id"] == json!(external_leg)),
        "the residual leg is indexed like every route upstream"
    );

    let authz = Arc::new(MeshAuthz::new(&authz_config(&prepared)).expect("mesh_authz builds"));
    let plugins = chain(vec![
        Arc::clone(&authz) as Arc<dyn Plugin>,
        route_dispatch_instance(&prepared, &route),
    ]);
    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..100 {
        let (result, ctx, _) = serve(&authz, &plugins, &route, TRUSTED).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "both legs serve a trusted caller: {result:?} ({:?})",
            ctx.metadata.get("mesh_authz.deny_policy")
        );
        *counts.entry(selected_leg(&ctx)).or_default() += 1;
    }
    assert_eq!(counts[REVIEWS_UPSTREAM], 50);
    assert_eq!(counts[&external_leg], 50);

    // The reviews policy still decides the reviews leg, and only it.
    let (mut refused, mut served) = (0, 0);
    for _ in 0..20 {
        let (result, ctx, _) = serve(&authz, &plugins, &route, UNTRUSTED).await;
        if selected_leg(&ctx) == REVIEWS_UPSTREAM {
            assert_denied(
                &result,
                "the reviews leg's ALLOW does not admit an untrusted caller",
            );
            refused += 1;
        } else {
            assert!(matches!(result, PluginResult::Continue), "{result:?}");
            served += 1;
        }
    }
    assert!(
        refused > 0 && served > 0,
        "both legs were reached: {refused} refused, {served} served"
    );
}

/// A request whose split was never resolved to a leg (route dispatch did not
/// run) is refused by proxy core's final check, even with no
/// AuthorizationPolicy loaded: the split itself is never a dispatch
/// destination.
#[tokio::test]
async fn an_unselected_split_is_refused_by_proxy_core() {
    let mut objects = vec![reviews_ratings_split(90, 10)];
    objects.extend(reviews_and_ratings_rules());
    let (_, prepared) = prepare(&objects, Vec::new());
    let route = carried_split_route(&prepared);
    let authz = Arc::new(MeshAuthz::new(&authz_config(&prepared)).expect("mesh_authz builds"));
    // `mesh_authz` alone: nothing picks a leg.
    let plugins = chain(vec![Arc::clone(&authz) as Arc<dyn Plugin>]);
    let (result, ctx, _) = serve(&authz, &plugins, &route, TRUSTED).await;
    assert!(ctx.route_override_upstream_id.is_none());
    assert_denied(&result, "the unselected split is refused");
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("route_branch_unauthorized")
    );
}

/// Without per-destination verdicts (an operator `mesh_authz` replaced the
/// managed instance), a selected leg is held to the single-destination guard
/// a matched rule is: with scoped policy active the route's authorized
/// destination is the split, so a leg is refused rather than reached with
/// policy that was never evaluated for it.
#[tokio::test]
async fn without_verdicts_a_selected_leg_is_held_to_the_single_destination_guard() {
    let mut objects = vec![reviews_ratings_split(90, 10)];
    objects.extend(reviews_and_ratings_rules());
    let reviews_trusted_only = policy_allow_principal(
        "reviews-trusted-only",
        DEFAULT_NAMESPACE,
        selector("reviews"),
        TRUSTED,
    );
    let (_, prepared) = prepare(&objects, vec![reviews_trusted_only]);
    let route = carried_split_route(&prepared);
    let mut config = authz_config(&prepared);
    config
        .as_object_mut()
        .expect("object config")
        .remove("node_waypoint_route_branches");
    let authz = MeshAuthz::new(&config).expect("mesh_authz builds");
    let plugins = chain(vec![route_dispatch_instance(&prepared, &route)]);

    let mut ctx = request(&route, TRUSTED);
    let mut headers = request_headers();
    ctx.headers = headers.clone();
    let authorized = authz.authorize(&mut ctx).await;
    assert!(
        matches!(authorized, PluginResult::Continue),
        "{authorized:?}"
    );
    let result = run_before_proxy_hooks_for_test(&plugins, &mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("a leg the guard did not authorize is refused, got {other:?}"),
    }
}

/// Refusals that remain: a DestinationRule split with an in-cluster leg the
/// waypoint does not model is refused (the host keeps its Service route).
#[test]
fn a_destination_rule_split_with_an_unmodeled_leg_is_refused() {
    let objects = vec![
        split_virtual_service(
            "split",
            "reviews.default.svc.cluster.local",
            &[
                ("reviews.default.svc.cluster.local", 8080, 50),
                ("missing.default.svc.cluster.local", 8080, 50),
            ],
        ),
        pool_destination_rule("reviews-dr", "reviews.default.svc.cluster.local", 3, "1s"),
    ];
    let (_, prepared) = prepare(&objects, Vec::new());
    assert!(carried_routes(&prepared).is_empty());
    assert!(
        prepared
            .proxies
            .iter()
            .any(|proxy| proxy.upstream_id.as_deref() == Some(REVIEWS_UPSTREAM)),
        "reviews keeps its Service route"
    );
}

/// Refusals that remain: a leg in another namespace cannot be dispatched by
/// a namespace-local route override, so the split is refused.
#[test]
fn a_destination_rule_split_with_a_leg_in_another_namespace_is_refused() {
    let objects = vec![
        split_virtual_service(
            "split",
            "reviews.default.svc.cluster.local",
            &[
                ("reviews.default.svc.cluster.local", 8080, 50),
                ("ratings.other.svc.cluster.local", 8080, 50),
            ],
        ),
        pool_destination_rule("reviews-dr", "reviews.default.svc.cluster.local", 3, "1s"),
    ];
    let mut config = translated_config(&objects, Vec::new());
    let foreign = workload_for("ratings", "other", [("app", "ratings")], ["10.0.1.12"]);
    let mesh = config.mesh.as_mut().expect("mesh block");
    mesh.services
        .push(service_for("ratings", "other", &[&foreign]));
    mesh.workloads.push(foreign);
    let slice = slice_for(&config);
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &node_waypoint_runtime())
        .expect("the slice materializes without the refused split");
    assert!(carried_routes(&prepared).is_empty());
}

/// Refusals that remain: a split with more legs than leg selection tracks is
/// refused.
#[test]
fn a_destination_rule_split_with_too_many_legs_is_refused() {
    let names: Vec<&'static str> = (0..33)
        .map(|index| -> &'static str { Box::leak(format!("svc-{index}").into_boxed_str()) })
        .collect();
    let hosts: Vec<String> = names
        .iter()
        .map(|name| format!("{name}.default.svc.cluster.local"))
        .collect();
    let legs: Vec<(&str, u16, u32)> = hosts.iter().map(|host| (host.as_str(), 8080, 1)).collect();
    let objects = vec![
        split_virtual_service("split", "reviews.default.svc.cluster.local", &legs),
        pool_destination_rule("svc-0-dr", "svc-0.default.svc.cluster.local", 3, "1s"),
    ];
    let mut config = translated_config(&objects, Vec::new());
    let mesh = config.mesh.as_mut().expect("mesh block");
    for (index, name) in names.iter().enumerate() {
        let address: &'static str = Box::leak(format!("10.0.2.{}", index + 1).into_boxed_str());
        let workload = workload_for(name, DEFAULT_NAMESPACE, [("app", *name)], [address]);
        mesh.services
            .push(service_for(name, DEFAULT_NAMESPACE, &[&workload]));
        mesh.workloads.push(workload);
    }
    let slice = slice_for(&config);
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &node_waypoint_runtime())
        .expect("the slice materializes without the refused split");
    assert!(carried_routes(&prepared).is_empty());
}

/// Refusals that remain: a residual external leg whose id another
/// VirtualService's split already owns refuses the route that needs it, and
/// only that route.
#[test]
fn a_residual_leg_id_already_in_use_refuses_the_route() {
    let objects = vec![
        split_virtual_service(
            "split",
            "reviews.default.svc.cluster.local",
            &[
                ("reviews.default.svc.cluster.local", 8080, 50),
                ("api.example.com", 443, 50),
            ],
        ),
        // Translates to the upstream id `<split>-external-0` would take.
        split_virtual_service(
            "split-0-external",
            "details.default.svc.cluster.local",
            &[
                ("details.default.svc.cluster.local", 8080, 50),
                ("ratings.default.svc.cluster.local", 8080, 50),
            ],
        ),
        pool_destination_rule("reviews-dr", "reviews.default.svc.cluster.local", 3, "1s"),
    ];
    let (_, prepared) = prepare(&objects, Vec::new());
    let routes = carried_routes(&prepared);
    assert_eq!(routes.len(), 1, "only the other VirtualService is served");
    assert!(
        routes[0]
            .hosts
            .iter()
            .any(|host| host.starts_with("details"))
    );
}

/// Leg-by-leg dispatch is decided by the data plane from its own slice view:
/// a carried route that already carries `weighted_splits` refuses the slice.
#[test]
fn a_carried_route_with_weighted_splits_refuses_the_slice() {
    let mut objects = vec![k8s_object(
        "VirtualService",
        "guarded",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "match": [{"uri": {"prefix": "/api"}, "headers": {"x-version": {"exact": "v2"}}}],
                "route": [
                    {"destination": {"host": "reviews.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 50},
                    {"destination": {"host": "ratings.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 50}
                ]
            }]
        }),
    )];
    objects.extend(reviews_and_ratings_rules());
    let mut slice = slice_for(&translated_config(&objects, Vec::new()));
    let dispatch = slice
        .http_routes
        .plugin_configs
        .iter_mut()
        .find(|plugin| plugin["plugin_name"] == json!("mesh_route_dispatch"))
        .expect("the guarded route carries its dispatch rules");
    dispatch["config"]["weighted_splits"] = json!([{
        "upstream_id": "istio-vs-upstream-default-guarded-0",
        "legs": [{"upstream_id": REVIEWS_UPSTREAM, "weight": 1}]
    }]);
    prepare_gateway_config_from_mesh_slice(&slice, &node_waypoint_runtime())
        .expect_err("carried weighted_splits are refused");
}

/// The existing workload rebinding keeps every split without a
/// DestinationRule unchanged: it dials workloads through the split upstream
/// and carries no `weighted_splits`.
#[test]
fn a_split_without_destination_rules_keeps_workload_rebinding() {
    let (_, prepared) = prepare(&[reviews_ratings_split(90, 10)], Vec::new());
    let route = carried_split_route(&prepared);
    assert!(
        prepared
            .plugin_configs
            .iter()
            .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .all(|plugin| plugin.config.get("weighted_splits").is_none()),
        "no split is dispatched leg by leg"
    );
    let split = prepared
        .upstreams
        .iter()
        .find(|upstream| route.upstream_id.as_deref() == Some(upstream.id.as_str()))
        .expect("split served");
    let mut hosts: Vec<&str> = split
        .targets
        .iter()
        .map(|target| target.host.as_str())
        .collect();
    hosts.sort_unstable();
    assert_eq!(hosts, vec!["10.0.0.11", "10.0.0.12"]);
}

/// A DestinationRule whose `trafficPolicy.connectionPool.tcp` is `tcp`.
fn tcp_destination_rule(name: &str, host: &str, tcp: serde_json::Value) -> K8sObject {
    k8s_object(
        "DestinationRule",
        name,
        json!({"host": host, "trafficPolicy": {"connectionPool": {"tcp": tcp}}}),
    )
}

/// The index of the route's `mesh_route_dispatch` config in `config`.
fn route_dispatch_index(config: &GatewayConfig, route: &Proxy) -> usize {
    config
        .plugin_configs
        .iter()
        .position(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.namespace == route.namespace
                && route
                    .plugins
                    .iter()
                    .any(|association| association.plugin_config_id == plugin.id)
        })
        .expect("the route has a mesh_route_dispatch instance")
}

/// Issue #7387 review (sol F1 = dsf F1): a weighted-split leg is validated
/// like a rule's `upstream_id`. A leg naming no upstream, or one that exists
/// only in another namespace, refuses the configuration instead of falling
/// back to the route's direct backend at dispatch.
#[test]
fn a_weighted_leg_must_name_an_upstream_in_the_route_namespace() {
    let mut objects = vec![reviews_ratings_split(90, 10)];
    objects.extend(reviews_and_ratings_rules());
    let (_, prepared) = prepare(&objects, Vec::new());
    let route = carried_split_route(&prepared);
    let dispatch = route_dispatch_index(&prepared, &route);
    let leg_errors = |config: &GatewayConfig| -> Vec<String> {
        collect_rejecting_runtime_config_errors_for_test(config)
            .into_iter()
            .filter(|error| error.contains("weighted_splits"))
            .collect()
    };
    assert_eq!(
        leg_errors(&prepared),
        Vec::<String>::new(),
        "generated legs resolve"
    );

    let mut typo = prepared.clone();
    typo.plugin_configs[dispatch].config["weighted_splits"][0]["legs"][0]["upstream_id"] =
        json!("typo");
    assert!(
        leg_errors(&typo)
            .iter()
            .any(|error| error.contains("weighted_splits[0].legs[0]")),
        "a missing leg refuses the config: {:?}",
        leg_errors(&typo)
    );

    let mut foreign = prepared.clone();
    let mut elsewhere = foreign
        .upstreams
        .iter()
        .find(|upstream| upstream.id == REVIEWS_UPSTREAM)
        .expect("reviews upstream")
        .clone();
    elsewhere.namespace = "other".to_string();
    elsewhere.id = "elsewhere".to_string();
    elsewhere.name = Some("elsewhere".to_string());
    foreign.upstreams.push(elsewhere);
    foreign.plugin_configs[dispatch].config["weighted_splits"][0]["legs"][1]["upstream_id"] =
        json!("elsewhere");
    assert!(
        leg_errors(&foreign)
            .iter()
            .any(|error| error.contains("weighted_splits[0].legs[1]")),
        "a leg in another namespace refuses the config: {:?}",
        leg_errors(&foreign)
    );
}

/// A slice carrying one header-guarded split route, plus `extra` more
/// header-guarded rules on the same route, each to its own split between
/// `reviews` and `ratings`. `reviews` is DestinationRule-governed.
fn slice_with_guarded_splits(extra: usize) -> MeshSlice {
    let mut objects = vec![k8s_object(
        "VirtualService",
        "guarded",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{
                "match": [{"uri": {"prefix": "/api"}, "headers": {"x-version": {"exact": "v2"}}}],
                "route": [
                    {"destination": {"host": "reviews.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 50},
                    {"destination": {"host": "ratings.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 50}
                ]
            }]
        }),
    )];
    objects.extend(reviews_and_ratings_rules());
    let mut slice = slice_for(&translated_config(&objects, Vec::new()));
    let base = slice.http_routes.upstreams[0].clone();
    let base_id = base["id"].as_str().expect("split id").to_string();
    let ids: Vec<String> = (0..extra).map(|n| format!("{base_id}-x{n}")).collect();
    for id in &ids {
        let mut upstream = base.clone();
        upstream["id"] = json!(id);
        upstream["name"] = json!(id);
        slice.http_routes.upstreams.push(upstream);
    }
    let dispatch = slice
        .http_routes
        .plugin_configs
        .iter_mut()
        .find(|plugin| plugin["plugin_name"] == json!("mesh_route_dispatch"))
        .expect("the guarded route carries its dispatch rules");
    let rules = dispatch["config"]["rules"]
        .as_array_mut()
        .expect("dispatch rules");
    for (n, id) in ids.iter().enumerate() {
        rules.push(json!({
            "match": {"headers": {"x-split": {"exact": n.to_string()}}},
            "destination": {"upstream_id": id}
        }));
    }
    slice
}

/// Issue #7387 review (sol F3): one route may name at most as many
/// leg-dispatched splits as one `mesh_route_dispatch` instance accepts. At
/// the limit the route is served and its instance constructs; past it the
/// route is refused (the host keeps its Service route) instead of the
/// generated instance failing construction for the whole generation.
#[test]
fn a_route_with_more_splits_than_one_dispatch_instance_accepts_is_refused() {
    let at_limit = slice_with_guarded_splits(63);
    let prepared = prepare_gateway_config_from_mesh_slice(&at_limit, &node_waypoint_runtime())
        .expect("slice materializes");
    let routes = carried_routes(&prepared);
    assert_eq!(routes.len(), 1, "64 splits fit one instance");
    let route = routes[0].clone();
    let splits = route_dispatch_config(&prepared, &route)["weighted_splits"]
        .as_array()
        .expect("weighted splits")
        .len();
    assert_eq!(splits, 64);
    let _ = route_dispatch_instance(&prepared, &route);

    let past_limit = slice_with_guarded_splits(64);
    let prepared = prepare_gateway_config_from_mesh_slice(&past_limit, &node_waypoint_runtime())
        .expect("the slice materializes without the refused route");
    assert!(carried_routes(&prepared).is_empty());
    assert!(
        prepared
            .proxies
            .iter()
            .any(|proxy| proxy.upstream_id.as_deref() == Some(REVIEWS_UPSTREAM)),
        "reviews keeps its Service route"
    );
}

/// Issue #7387 review (sol F4): with two same-tier DestinationRules on one
/// leg's Service, the leg's projected connect timeout is the last rule's,
/// exactly what the Service's own route uses, not the first rule's.
#[test]
fn a_leg_connect_timeout_follows_the_last_matching_rule() {
    let objects = vec![
        split_virtual_service(
            "split",
            "details.default.svc.cluster.local",
            &[
                ("reviews.default.svc.cluster.local", 8080, 50),
                ("ratings.default.svc.cluster.local", 8080, 50),
            ],
        ),
        tcp_destination_rule(
            "a-reviews",
            "reviews.default.svc.cluster.local",
            json!({"connectTimeout": "1s"}),
        ),
        tcp_destination_rule(
            "z-reviews",
            "reviews.default.svc.cluster.local",
            json!({"connectTimeout": "2s"}),
        ),
    ];
    let (_, prepared) = prepare(&objects, Vec::new());
    let _ = carried_split_route(&prepared);
    let reviews = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == REVIEWS_UPSTREAM)
        .expect("reviews upstream");
    let seeded = reviews
        .port_overrides
        .get(&8080)
        .and_then(|slot| slot.connect_timeout_ms);
    assert_eq!(seeded, Some(2000), "the last rule's timeout is projected");
    let service_route = prepared
        .proxies
        .iter()
        .find(|proxy| {
            !proxy.id.starts_with("istio-vs-")
                && proxy.upstream_id.as_deref() == Some(REVIEWS_UPSTREAM)
        })
        .expect("reviews keeps its Service route");
    assert_eq!(
        Some(service_route.backend_connect_timeout_ms),
        seeded,
        "the leg and the Service's own route use the same timeout"
    );
}

/// Issue #7387 review (sol F5): on a merged route whose own destination's
/// DestinationRule sets a connect timeout, a weighted-split leg whose own
/// rule sets none uses the route's own timeout, never the other Service's;
/// the own destination keeps its rule through its upstream's port slots.
#[tokio::test]
async fn a_leg_without_its_own_timeout_does_not_inherit_another_services_rule() {
    let objects = vec![
        k8s_object(
            "VirtualService",
            "merged",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [
                    {
                        "match": [{"uri": {"prefix": "/api"}, "headers": {"x-version": {"exact": "v2"}}}],
                        "route": [
                            {"destination": {"host": "ratings.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 50},
                            {"destination": {"host": "details.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 50}
                        ]
                    },
                    {
                        "match": [{"uri": {"prefix": "/api"}}],
                        "route": [{"destination": {"host": "reviews.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }
                ]
            }),
        ),
        tcp_destination_rule(
            "reviews-dr",
            "reviews.default.svc.cluster.local",
            json!({"connectTimeout": "1s"}),
        ),
        tcp_destination_rule(
            "ratings-dr",
            "ratings.default.svc.cluster.local",
            json!({"maxConnections": 3}),
        ),
        tcp_destination_rule(
            "details-dr",
            "details.default.svc.cluster.local",
            json!({"connectTimeout": "2s"}),
        ),
    ];
    let (_, prepared) = prepare(&objects, Vec::new());
    let routes = carried_routes(&prepared);
    assert_eq!(
        routes.len(),
        1,
        "the guarded split is merged into the fallback"
    );
    let route = routes[0].clone();
    assert_eq!(route.upstream_id.as_deref(), Some(REVIEWS_UPSTREAM));
    assert_ne!(
        route.backend_connect_timeout_ms, 1000,
        "the route keeps its own timeout; reviews' rule rides its upstream"
    );
    let reviews_slot = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == REVIEWS_UPSTREAM)
        .and_then(|upstream| upstream.port_overrides.get(&8080))
        .and_then(|slot| slot.connect_timeout_ms);
    assert_eq!(
        reviews_slot,
        Some(1000),
        "the own destination keeps its rule"
    );

    let plugins = chain(vec![route_dispatch_instance(&prepared, &route)]);
    let upstreams = upstream_map(&prepared);
    let mut seen = HashMap::new();
    for _ in 0..10 {
        let mut ctx = request_at(&route, TRUSTED, "/api");
        let mut headers = request_headers();
        headers.insert("x-version".to_string(), "v2".to_string());
        ctx.headers = headers.clone();
        let result = run_before_proxy_hooks_for_test(&plugins, &mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue), "{result:?}");
        let leg = selected_leg(&ctx);
        let effective =
            ctx.apply_route_overrides_with_upstreams(Arc::new(route.clone()), &upstreams);
        let slot = effective
            .dispatch_port_overrides
            .as_ref()
            .and_then(|overrides| overrides.get(&8080));
        match leg.as_str() {
            RATINGS_UPSTREAM => {
                assert_eq!(slot.and_then(|slot| slot.max_connections), Some(3));
                assert_eq!(
                    slot.and_then(|slot| slot.connect_timeout_ms),
                    None,
                    "ratings' rule sets no timeout"
                );
                assert_eq!(
                    effective.backend_connect_timeout_ms, route.backend_connect_timeout_ms,
                    "ratings uses the route's own timeout, not reviews' rule"
                );
            }
            DETAILS_UPSTREAM => {
                assert_eq!(slot.and_then(|slot| slot.connect_timeout_ms), Some(2000));
            }
            other => panic!("the guarded rule reaches only the split's legs: {other}"),
        }
        *seen.entry(leg).or_insert(0) += 1;
    }
    assert_eq!(seen.len(), 2, "both legs were reached: {seen:?}");
}

/// Issue #7387 review round 2 (sol F1): a leg-dispatched split keeps only its
/// Service legs' workloads, so two external legs whose hosts have different
/// DestinationRules no longer make DestinationRule application refuse the
/// whole slice; each residual external leg carries its own host's rule.
#[test]
fn external_legs_with_different_destination_rules_each_keep_their_own() {
    let objects = vec![
        split_virtual_service(
            "split",
            "reviews.default.svc.cluster.local",
            &[
                ("reviews.default.svc.cluster.local", 8080, 34),
                ("api.one.example", 443, 33),
                ("api.two.example", 443, 33),
            ],
        ),
        pool_destination_rule("reviews-dr", "reviews.default.svc.cluster.local", 3, "1s"),
        tcp_destination_rule(
            "api-one-dr",
            "api.one.example",
            json!({"connectTimeout": "1s"}),
        ),
        tcp_destination_rule(
            "api-two-dr",
            "api.two.example",
            json!({"connectTimeout": "2s"}),
        ),
    ];
    let slice = slice_for(&translated_config(&objects, Vec::new()));
    assert_eq!(
        slice.destination_rules.len(),
        3,
        "every rule reaches the waypoint"
    );
    let prepared = prepare_gateway_config_from_mesh_slice(&slice, &node_waypoint_runtime())
        .expect("distinct external rules no longer refuse the slice");
    let route = carried_split_route(&prepared);
    let split_id = route.upstream_id.clone().expect("split id");
    let split = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == split_id)
        .expect("the split stays the route's own destination");
    assert!(
        split
            .targets
            .iter()
            .all(|target| !target.host.contains("example")),
        "the never-dialed split keeps no external host: {:?}",
        split
            .targets
            .iter()
            .map(|target| &target.host)
            .collect::<Vec<_>>()
    );
    for (index, host, timeout) in [(0, "api.one.example", 1000), (1, "api.two.example", 2000)] {
        let residual = prepared
            .upstreams
            .iter()
            .find(|upstream| upstream.id == format!("{split_id}-external-{index}"))
            .expect("residual external leg");
        assert_eq!(residual.targets.len(), 1);
        assert_eq!(residual.targets[0].host, host);
        assert_eq!(
            residual
                .port_overrides
                .get(&443)
                .and_then(|slot| slot.connect_timeout_ms),
            Some(timeout),
            "{host} carries its own rule"
        );
    }
}

/// Issue #7387 review round 2 (sol F2): a dispatch instance its execution
/// trigger skipped selects no weighted-split leg; the same instance selects
/// one when its trigger matches. Built through the production plugin cache.
#[tokio::test]
async fn a_trigger_skipped_instance_selects_no_leg() {
    let upstream = |id: &str| -> Upstream {
        serde_json::from_value(json!({
            "id": id,
            "name": id,
            "targets": [{"host": "127.0.0.1", "port": 8080, "weight": 1}],
            "algorithm": "round_robin"
        }))
        .expect("upstream")
    };
    let mut config = GatewayConfig {
        proxies: vec![
            serde_json::from_value(json!({
                "id": "p1",
                "listen_path": "/",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": 8080,
                "upstream_id": "split",
                "plugins": [{"plugin_config_id": "mrd"}]
            }))
            .expect("proxy"),
        ],
        upstreams: vec![upstream("split"), upstream("leg-a"), upstream("leg-b")],
        plugin_configs: vec![
            serde_json::from_value(json!({
                "id": "mrd",
                "plugin_name": "mesh_route_dispatch",
                "scope": "proxy",
                "proxy_id": "p1",
                "enabled": true,
                "config": {
                    "weighted_splits": [{
                        "upstream_id": "split",
                        "legs": [
                            {"upstream_id": "leg-a", "weight": 1},
                            {"upstream_id": "leg-b", "weight": 1}
                        ]
                    }]
                },
                "trigger": {"when": {"match": {"path": {"prefix": ["/canary"]}}}}
            }))
            .expect("plugin config"),
        ],
        ..Default::default()
    };
    config.normalize_fields();
    let cache = ferrum_edge::PluginCache::new(&config).expect("cache builds");
    let proxy = config.proxies[0].clone();
    let plugins = ferrum_edge::_test_support::plugins_for_protocol_for_test(
        &cache,
        &proxy.namespace,
        &proxy.id,
        ferrum_edge::plugins::ProxyProtocol::Http,
    );

    for path in ["/ordinary", "/canary/x"] {
        let mut ctx =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), path.to_string());
        ctx.matched_proxy = Some(Arc::new(proxy.clone()));
        let mut headers = HashMap::from([("host".to_string(), "example.test".to_string())]);
        ctx.headers = headers.clone();
        let result = run_before_proxy_hooks_for_test(&plugins, &mut ctx, &mut headers).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{path}: {result:?}"
        );
        if path == "/ordinary" {
            assert_eq!(
                ctx.route_override_upstream_id, None,
                "a skipped instance selects nothing"
            );
        } else {
            assert!(
                matches!(
                    ctx.route_override_upstream_id.as_deref(),
                    Some("leg-a" | "leg-b")
                ),
                "the instance that ran selects a leg: {:?}",
                ctx.route_override_upstream_id
            );
        }
    }
}

/// Issue #7387 review round 2 (dsf F2): a global `mesh_route_dispatch`
/// instance makes a route reach other destinations just like a proxy-scoped
/// one, so the route keeps its own connect timeout and its own destination's
/// DestinationRule timeout rides that upstream instead.
#[test]
fn a_global_dispatch_instance_keeps_route_owned_connect_timeouts() {
    let objects = vec![
        k8s_object(
            "VirtualService",
            "direct",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [{
                    "route": [{"destination": {"host": "reviews.default.svc.cluster.local", "port": {"number": 8080}}}]
                }]
            }),
        ),
        tcp_destination_rule(
            "reviews-dr",
            "reviews.default.svc.cluster.local",
            json!({"connectTimeout": "1s"}),
        ),
    ];
    let mut config = translated_config(&objects, Vec::new());
    config.plugin_configs.push(
        serde_json::from_value(json!({
            "id": "operator-dispatch",
            "namespace": DEFAULT_NAMESPACE,
            "plugin_name": "mesh_route_dispatch",
            "scope": "global",
            "enabled": true,
            "config": {
                "rules": [{
                    "match": {"headers": {"x-ratings": {"exact": "1"}}},
                    "destination": {"upstream_id": RATINGS_UPSTREAM}
                }]
            }
        }))
        .expect("global dispatch config"),
    );
    let prepared = ferrum_edge::modes::mesh::prepare_gateway_config_via_mesh_slice_with_fixtures(
        config,
        &node_waypoint_runtime(),
    )
    .expect("slice materializes");
    let route = carried_routes(&prepared)
        .into_iter()
        .find(|route| route.upstream_id.as_deref() == Some(REVIEWS_UPSTREAM))
        .expect("the direct route is served")
        .clone();
    assert_ne!(
        route.backend_connect_timeout_ms, 1000,
        "the route keeps its own timeout"
    );
    let reviews_slot = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == REVIEWS_UPSTREAM)
        .and_then(|upstream| upstream.port_overrides.get(&8080))
        .and_then(|slot| slot.connect_timeout_ms);
    assert_eq!(reviews_slot, Some(1000), "reviews' rule rides its upstream");
}
