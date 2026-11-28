//! The ReferenceGrant invariant of cross-namespace VirtualService
//! destinations (issue #7499, review round 5): **adding or removing a
//! ReferenceGrant changes only the routes that name the granted target.**
//!
//! Each test computes the complete data-plane config of one fixture twice,
//! with and without the `other/ratings` grant, through the production halves
//! (K8s translation, slice projection, data-plane slice preparation with the
//! poller-discovered multicluster endpoints merged in exactly as slice apply
//! merges them), and asserts that the two configs differ only in the routes of
//! the VirtualService that names `other/ratings` and the objects those routes
//! alone reach: their proxies, route plugin configs, split and clone
//! upstreams, the destination source upstream, and the authorization
//! metadata that scopes them. Every other proxy, upstream and plugin config,
//! the routing workload set, and every authorization decision on every other
//! route, must be identical.
//!
//! The fixture covers both topologies that apply VirtualService routes
//! (Sidecar and NodeWaypoint), a DestinationRule-governed split, a
//! subscriber-namespace `WorkloadEntry` attached to the target Service (a
//! mixed-backend ordinary route) or none (a remote-only ordinary route),
//! remote-cluster endpoints of the target Service that share the destination
//! workloads' identity, and policy scoping: a destination-namespace
//! AuthorizationPolicy and RequestAuthentication selecting the destination,
//! and a mesh-wide policy only (so the missing-scope census would flip if a
//! grant-only policy joined it).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use ferrum_edge::config::types::{GatewayConfig, Proxy};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    EastWestGateway, MultiClusterConfig, PolicyScope, RemoteCluster, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::multicluster::{
    RemoteClusterEndpoints, RemoteClusterEntry, RemoteEndpointSnapshot,
};
use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;
use ferrum_edge::modes::mesh::{
    MESH_AUTHZ_PLUGIN_ID, MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX,
    MESH_REQUEST_AUTH_REFUSED_PARTITION_ID_PREFIX, MESH_REQUEST_AUTH_REFUSED_PLUGIN_ID,
    MeshRuntimeConfig, prepare_gateway_config_from_mesh_slice_with_remote_endpoints_for_test,
};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::{Value, json};

use super::super::mesh_test_support::{
    DEFAULT_NAMESPACE, policy_allow_principal, policy_deny_principal, service_for, workload_for,
};
use super::cross_namespace_routes::{
    OTHER, RATINGS_OTHER, SOURCE_PREFIX, destination_rule, k8s_service, node_waypoint_runtime,
    sidecar_runtime, slice_for, translated_with_grant, virtual_service,
};

/// The VirtualService whose routes name the granted target.
const GRANTED_ROUTE_MARKER: &str = "-default-granted-";
const TRUSTED: &str = "spiffe://cluster.local/ns/default/sa/trusted";
const UNTRUSTED: &str = "spiffe://cluster.local/ns/default/sa/untrusted";
const BANNED: &str = "spiffe://cluster.local/ns/default/sa/banned";
const REMOTE_CLUSTER: &str = "west";
const REMOTE_CONTROL_PLANE: &str = "https://cp.remote.example:15010";

fn selector(namespace: &str, app: &str) -> PolicyScope {
    PolicyScope::WorkloadSelector {
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), app.to_string())]),
            namespace: Some(namespace.to_string()),
        },
    }
}

fn request_auth(
    name: &str,
    namespace: &str,
    app: &str,
) -> ferrum_edge::modes::mesh::config::MeshRequestAuthentication {
    use ferrum_edge::modes::mesh::config::{MeshJwtRule, MeshRequestAuthentication};
    MeshRequestAuthentication {
        name: name.to_string(),
        namespace: namespace.to_string(),
        scope: selector(namespace, app),
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

/// The fixture, with or without the grant, with or without a
/// subscriber-namespace `WorkloadEntry` backing `other/ratings`.
fn fixture(with_grant: bool, with_entry: bool) -> GatewayConfig {
    let mut config = translated_with_grant(
        vec![
            k8s_service("details", DEFAULT_NAMESPACE),
            // Names the granted target: a DestinationRule-governed 90/10
            // split with a leg to `other/ratings`, plus a direct granted route
            // (so destination RequestAuthentication attaches cleanly without
            // diverging across legs), both on their own paths so they shadow
            // no route the fixture serves without the grant.
            virtual_service(
                "granted",
                json!({
                    "hosts": ["reviews.default.svc.cluster.local"],
                    "http": [
                        {
                            "match": [{"uri": {"prefix": "/granted-direct"}}],
                            "route": [{"destination": {
                                "host": RATINGS_OTHER,
                                "port": {"number": 8080}
                            }}]
                        },
                        {
                            "match": [{"uri": {"prefix": "/granted"}}],
                            "route": [
                                {"destination": {
                                    "host": "reviews.default.svc.cluster.local",
                                    "port": {"number": 8080}
                                }, "weight": 90},
                                {"destination": {
                                    "host": RATINGS_OTHER,
                                    "port": {"number": 8080}
                                }, "weight": 10}
                            ]
                        }
                    ]
                }),
            ),
            // Names only `default/reviews`.
            virtual_service(
                "local",
                json!({
                    "hosts": ["reviews.default.svc.cluster.local"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/local"}}],
                        "route": [{"destination": {
                            "host": "reviews.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}]
                    }]
                }),
            ),
            // Unrelated combined mixed split (local Service + external host,
            // no governing DestinationRule so it stays a single combined
            // upstream): a grant-only RequestAuthentication must never turn
            // this route into a 503 refusal.
            virtual_service(
                "mixed",
                json!({
                    "hosts": ["details.default.svc.cluster.local"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/mixed"}}],
                        "route": [
                            {"destination": {
                                "host": "details.default.svc.cluster.local",
                                "port": {"number": 8080}
                            }, "weight": 50},
                            {"destination": {
                                "host": "partner.example.com",
                                "port": {"number": 8080}
                            }, "weight": 50}
                        ]
                    }]
                }),
            ),
            destination_rule(
                "ratings-dr",
                OTHER,
                RATINGS_OTHER,
                json!({"loadBalancer": {"simple": "RANDOM"}}),
            ),
            destination_rule(
                "reviews-dr",
                DEFAULT_NAMESPACE,
                "reviews.default.svc.cluster.local",
                // A load-balancer rule: a top-level `connectTimeout` would
                // move from the route proxies onto the upstream's port slots
                // once ANY route leg-dispatches through it (issue #7387), an
                // equivalent representation this byte comparison would flag.
                json!({"loadBalancer": {"simple": "RANDOM"}}),
            ),
        ],
        with_grant,
    );
    let mesh = config.mesh.as_mut().expect("mesh block");
    let details = workload_for(
        "details",
        DEFAULT_NAMESPACE,
        [("app", "details")],
        ["10.0.0.19"],
    );
    mesh.services
        .push(service_for("details", DEFAULT_NAMESPACE, &[&details]));
    mesh.workloads.push(details);
    if with_entry {
        let mut entry = workload_for("vm", DEFAULT_NAMESPACE, [("app", "vm")], ["10.0.0.50"]);
        entry.service_name = "ratings".to_string();
        entry.service_namespace = Some(OTHER.to_string());
        mesh.services
            .iter_mut()
            .find(|service| service.namespace == OTHER && service.name == "ratings")
            .expect("other/ratings")
            .workloads
            .push(WorkloadRef {
                spiffe_id: entry.spiffe_id.clone(),
            });
        mesh.workloads.push(entry);
    }
    mesh.mesh_policies = vec![
        // The destination namespace's own policy, selecting the destination.
        policy_allow_principal(
            "ratings-trusted-only",
            OTHER,
            selector(OTHER, "ratings"),
            TRUSTED,
        ),
        // Mesh-wide only on this side, so the missing-scope census is false
        // without the grant.
        policy_deny_principal("deny-banned", "istio-system", PolicyScope::MeshWide, BANNED),
    ];
    mesh.request_authentications = vec![request_auth("ratings-jwt", OTHER, "ratings")];
    config
}

/// The remote cluster's endpoints of `other/ratings`: a remote replica with
/// the destination workloads' own identity.
fn remote_endpoints() -> RemoteEndpointSnapshot {
    let mut replica = workload_for("ratings", OTHER, [("app", "ratings")], ["10.2.0.12"]);
    replica.network = Some("net2".to_string());
    replica.cluster = Some(REMOTE_CLUSTER.to_string());
    replica.remote_provenance = true;
    let service = ferrum_edge::modes::mesh::config::MeshService {
        cluster_ips: Vec::new(),
        name: "ratings".to_string(),
        namespace: OTHER.to_string(),
        ports: vec![ferrum_edge::modes::mesh::config::ServicePort {
            port: 8080,
            protocol: ferrum_edge::modes::mesh::config::AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: replica.spiffe_id.clone(),
        }],
        protocol_overrides: HashMap::new(),
        uid: None,
        allow_path_parameters: false,
    };
    RemoteEndpointSnapshot {
        clusters: HashMap::from([(
            REMOTE_CLUSTER.to_string(),
            Arc::new(RemoteClusterEntry::new(
                REMOTE_CLUSTER.to_string(),
                TrustDomain::new("cluster.local").expect("trust domain"),
                Some("net2".to_string()),
                Some(REMOTE_CONTROL_PLANE.to_string()),
                None,
                RemoteClusterEndpoints {
                    workloads: vec![replica],
                    services: vec![service],
                },
                1,
            )),
        )]),
    }
}

/// The multicluster topology the slice declares: the remote cluster above,
/// fronted by an east-west gateway claiming `other/ratings`.
fn multi_cluster() -> MultiClusterConfig {
    MultiClusterConfig {
        local_cluster: Some("east".to_string()),
        federation_endpoint: None,
        remote_clusters: vec![RemoteCluster {
            name: REMOTE_CLUSTER.to_string(),
            trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
            network: Some("net2".to_string()),
            control_plane_url: Some(REMOTE_CONTROL_PLANE.to_string()),
            federation_endpoint: None,
            discovery_credential_ref: None,
        }],
        east_west_gateways: vec![EastWestGateway {
            name: "west-gateway".to_string(),
            namespace: "istio-system".to_string(),
            host: "203.0.113.10".to_string(),
            port: 15443,
            sni_hosts: vec![RATINGS_OTHER.to_string()],
            trust_domain: None,
            network: Some("net2".to_string()),
        }],
    }
}

/// The complete data-plane config of `config` on `runtime`, with the remote
/// endpoints merged in.
fn data_plane(config: &GatewayConfig, runtime: &MeshRuntimeConfig) -> GatewayConfig {
    let mut slice = slice_for(config, runtime);
    slice.multi_cluster = Some(multi_cluster());
    prepare_gateway_config_from_mesh_slice_with_remote_endpoints_for_test(
        &slice,
        runtime,
        &remote_endpoints(),
    )
    .unwrap_or_else(|error| panic!("{:?}: slice materializes: {error}", runtime.topology))
}

fn names_granted_route(id: &str) -> bool {
    id.contains(GRANTED_ROUTE_MARKER)
}

/// Every string value in `value` (the upstream ids a dispatch config names).
fn strings_in(value: &Value, into: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            into.insert(text.clone());
        }
        Value::Array(items) => items.iter().for_each(|item| strings_in(item, into)),
        Value::Object(map) => map.values().for_each(|item| strings_in(item, into)),
        _ => {}
    }
}

/// `__mesh_authz` with the metadata that scopes only the granted routes'
/// destinations removed: the grant-only destination workloads and policies,
/// and the route upstream / branch entries of granted routes and of upstreams
/// only those routes reach.
fn normalize_authz(config: &mut Value, kept_upstreams: &BTreeSet<String>) {
    let Some(object) = config.as_object_mut() else {
        return;
    };
    object.remove("node_waypoint_route_destination_workloads");
    let grant_only_policies: HashSet<(String, String)> = object
        .remove("node_waypoint_route_destination_policies")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .map(|policy| {
            (
                policy["namespace"].as_str().unwrap_or_default().to_string(),
                policy["name"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    if let Some(Value::Array(entries)) = object.get_mut("node_waypoint_route_upstreams") {
        entries.retain(|entry| {
            entry["id"]
                .as_str()
                .is_some_and(|id| kept_upstreams.contains(id))
        });
    }
    if let Some(Value::Array(entries)) = object.get_mut("node_waypoint_route_branches") {
        entries.retain(|entry| !entry["proxy_id"].as_str().is_some_and(names_granted_route));
    }
    let grant_only = |policy: &Value| {
        grant_only_policies.contains(&(
            policy["namespace"].as_str().unwrap_or_default().to_string(),
            policy["name"].as_str().unwrap_or_default().to_string(),
        ))
    };
    if let Some(Value::Array(policies)) = object.get_mut("mesh_policies") {
        policies.retain(|policy| !grant_only(policy));
    }
    if let Some(slice) = object.get_mut("mesh_slice").and_then(Value::as_object_mut) {
        slice.remove("version");
        if let Some(Value::Array(policies)) = slice.get_mut("mesh_policies") {
            policies.retain(|policy| !grant_only(policy));
        }
        // The destination namespace's RequestAuthentication rides only for the
        // granted destination and is applied only to the routes reaching it
        // (asserted on the proxies' plugin associations below).
        if let Some(Value::Array(resources)) = slice.get_mut("request_authentications") {
            resources.retain(|resource| resource["namespace"].as_str() != Some(OTHER));
        }
    }
}

/// Remove wall-clock timestamps (`created_at`, `updated_at`) before comparing
/// two independent `data_plane` preparations of the fixture.
fn strip_timestamps(value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        object.remove("created_at");
        object.remove("updated_at");
    }
}

/// Remove only `granted_proxies` from a `__mesh_request_auth_refused*`
/// plugin's `proxy_id` trigger leaves. Returns `false` when the refusal was
/// explicitly scoped to `proxy_id` leaves and only named granted routes (so
/// the refusal never affects any retained route). Any unscoped refusal or any
/// refusal naming a retained route stays in the compared view.
fn retain_refusal_for_ungranted_routes(value: &mut Value, granted_proxies: &HashSet<&str>) -> bool {
    fn strip_leaf(leaf: &mut Value, granted_proxies: &HashSet<&str>) -> Option<bool> {
        let ids = leaf
            .get_mut("match")
            .and_then(Value::as_object_mut)?
            .get_mut("proxy_id")
            .and_then(Value::as_array_mut)?;
        ids.retain(|id| !id.as_str().is_some_and(|id| granted_proxies.contains(id)));
        Some(!ids.is_empty())
    }
    let Some(when) = value
        .get_mut("trigger")
        .and_then(Value::as_object_mut)
        .and_then(|trigger| trigger.get_mut("when"))
    else {
        return true;
    };
    if let Some(any) = when.get_mut("any").and_then(Value::as_array_mut) {
        let mut kept = Vec::new();
        for mut leaf in std::mem::take(any) {
            match strip_leaf(&mut leaf, granted_proxies) {
                Some(false) => {}
                Some(true) | None => kept.push(leaf),
            }
        }
        if kept.is_empty() {
            return false;
        }
        *any = kept;
        return true;
    }
    match strip_leaf(when, granted_proxies) {
        Some(false) => false,
        Some(true) | None => true,
    }
}

/// The parts of `config` the grant must not change, keyed for a readable
/// diff: every proxy, upstream and plugin config that is not one of the
/// granted routes' own objects, and the routing workload set.
fn ungranted_view(config: &GatewayConfig) -> BTreeMap<String, Value> {
    let granted_proxies: HashSet<&str> = config
        .proxies
        .iter()
        .filter(|proxy| names_granted_route(&proxy.id))
        .map(|proxy| proxy.id.as_str())
        .collect();
    let kept_proxies: Vec<&Proxy> = config
        .proxies
        .iter()
        .filter(|proxy| !granted_proxies.contains(proxy.id.as_str()))
        .collect();
    let route_plugin = |plugin: &&ferrum_edge::config::types::PluginConfig| {
        plugin
            .proxy_id
            .as_deref()
            .is_some_and(|id| granted_proxies.contains(id))
    };
    // Upstreams referenced by the granted routes and by everything else.
    let mut granted_refs = BTreeSet::new();
    let mut kept_refs = BTreeSet::new();
    for proxy in &config.proxies {
        let refs = if granted_proxies.contains(proxy.id.as_str()) {
            &mut granted_refs
        } else {
            &mut kept_refs
        };
        refs.extend(proxy.upstream_id.clone());
    }
    for plugin in config
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
    {
        if route_plugin(&plugin) {
            strings_in(&plugin.config, &mut granted_refs);
        } else {
            strings_in(&plugin.config, &mut kept_refs);
        }
    }
    let kept_upstream_ids: BTreeSet<String> = config
        .upstreams
        .iter()
        .filter(|upstream| {
            !upstream.id.starts_with(SOURCE_PREFIX)
                && (kept_refs.contains(&upstream.id) || !granted_refs.contains(&upstream.id))
        })
        .map(|upstream| upstream.id.clone())
        .collect();
    // A destination RequestAuthentication instance only the granted routes
    // associate with is theirs.
    let kept_associations: HashSet<&str> = kept_proxies
        .iter()
        .flat_map(|proxy| proxy.plugins.iter())
        .map(|association| association.plugin_config_id.as_str())
        .collect();

    let mut view = BTreeMap::new();
    for proxy in &kept_proxies {
        let mut value = serde_json::to_value(proxy).expect("proxy serializes");
        strip_timestamps(&mut value);
        view.insert(format!("proxy {}/{}", proxy.namespace, proxy.id), value);
    }
    for upstream in config
        .upstreams
        .iter()
        .filter(|upstream| kept_upstream_ids.contains(&upstream.id))
    {
        let mut value = serde_json::to_value(upstream).expect("upstream serializes");
        strip_timestamps(&mut value);
        view.insert(
            format!("upstream {}/{}", upstream.namespace, upstream.id),
            value,
        );
    }
    for plugin in &config.plugin_configs {
        if route_plugin(&plugin)
            || (plugin
                .id
                .starts_with(MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX)
                && !kept_associations.contains(plugin.id.as_str()))
        {
            continue;
        }
        let mut value = serde_json::to_value(plugin).expect("plugin serializes");
        strip_timestamps(&mut value);
        if (plugin.id == MESH_REQUEST_AUTH_REFUSED_PLUGIN_ID
            || plugin
                .id
                .starts_with(MESH_REQUEST_AUTH_REFUSED_PARTITION_ID_PREFIX))
            && !retain_refusal_for_ungranted_routes(&mut value, &granted_proxies)
        {
            continue;
        }
        if plugin.id == MESH_AUTHZ_PLUGIN_ID {
            normalize_authz(&mut value["config"], &kept_upstream_ids);
        }
        view.insert(format!("plugin {}/{}", plugin.namespace, plugin.id), value);
    }
    let mut workloads: Vec<String> = config
        .mesh
        .as_ref()
        .map(|mesh| {
            mesh.workloads
                .iter()
                .map(|workload| serde_json::to_string(workload).expect("workload serializes"))
                .collect()
        })
        .unwrap_or_default();
    workloads.sort_unstable();
    view.insert("mesh workloads".to_string(), json!(workloads));
    view
}

/// `mesh_authz`'s decision for a request on `route`, from `source` with its
/// resolved pod scope, or with no resolved scope at all.
async fn decide(authz: &MeshAuthz, route: &Proxy, source: Option<&str>) -> String {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    if let Some(source) = source {
        let identity = SpiffeId::new(source).expect("spiffe");
        ctx.peer_spiffe_id = Some(identity.clone());
        ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
            identity,
            DEFAULT_NAMESPACE,
            HashMap::from([("app".to_string(), "client".to_string())]),
        )));
    }
    ctx.matched_proxy = Some(Arc::new(route.clone()));
    ctx.headers = HashMap::from([("host".to_string(), route.backend_host.clone())]);
    let result = authz.authorize(&mut ctx).await;
    let verdict = match result {
        PluginResult::Continue => "allow".to_string(),
        PluginResult::Reject { status_code, .. } => format!("reject {status_code}"),
        other => format!("{other:?}"),
    };
    format!(
        "{verdict} deny_policy={:?} scope_missing={:?}",
        ctx.metadata.get("mesh_authz.deny_policy"),
        ctx.metadata.get("mesh_authz.scope_missing")
    )
}

fn authz(config: &GatewayConfig) -> MeshAuthz {
    let plugin = config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz injected");
    MeshAuthz::new(&plugin.config).expect("mesh_authz builds")
}

/// The invariant, for one fixture on one topology.
async fn assert_grant_changes_only_its_routes(runtime: MeshRuntimeConfig, with_entry: bool) {
    let topology = runtime.topology;
    let granted = data_plane(&fixture(true, with_entry), &runtime);
    let ungranted = data_plane(&fixture(false, with_entry), &runtime);
    let case = format!("{topology:?} entry={with_entry}");

    // The fixture exercises what it claims: the grant serves its route, and
    // the ordinary route of the target Service exists in both.
    assert!(
        granted
            .proxies
            .iter()
            .any(|proxy| names_granted_route(&proxy.id)),
        "{case}: the granted route is served"
    );
    assert!(
        !ungranted
            .proxies
            .iter()
            .any(|proxy| names_granted_route(&proxy.id)),
        "{case}: without the grant the route is refused"
    );
    assert!(
        granted
            .upstreams
            .iter()
            .any(|upstream| upstream.id.starts_with(SOURCE_PREFIX)),
        "{case}: the granted route reaches a destination source"
    );
    assert!(
        granted
            .proxies
            .iter()
            .any(|proxy| proxy.id.contains("-default-mixed-"))
            && ungranted
                .proxies
                .iter()
                .any(|proxy| proxy.id.contains("-default-mixed-")),
        "{case}: the unrelated mixed split is materialized in both configs"
    );
    if topology == ferrum_edge::modes::mesh::MeshTopology::NodeWaypoint {
        let direct_granted = granted
            .proxies
            .iter()
            .find(|proxy| names_granted_route(&proxy.id) && proxy.listen_path == "/granted-direct")
            .unwrap_or_else(|| panic!("{case}: direct granted route materialized"));
        let refusal_targets_direct = granted.plugin_configs.iter().any(|plugin| {
            (plugin.id == MESH_REQUEST_AUTH_REFUSED_PLUGIN_ID
                || plugin
                    .id
                    .starts_with(MESH_REQUEST_AUTH_REFUSED_PARTITION_ID_PREFIX))
                && serde_json::to_string(&plugin.trigger)
                    .unwrap_or_default()
                    .contains(&direct_granted.id)
        });
        if with_entry {
            // With `default/vm` attached to `other/ratings`, the Service's
            // workloads have divergent RequestAuthentication sets (`ratings`
            // selects `ratings-jwt`, `vm` selects none), so the direct route
            // fails closed under `__mesh_request_auth_refused`.
            assert!(
                refusal_targets_direct,
                "{case}: heterogeneous Service workloads refuse the direct granted route"
            );
        } else {
            assert!(
                direct_granted.plugins.iter().any(|association| {
                    association
                        .plugin_config_id
                        .starts_with(MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX)
                }),
                "{case}: homogeneous direct granted route carries destination RequestAuthentication"
            );
            assert!(
                !refusal_targets_direct,
                "{case}: homogeneous direct granted route serves traffic rather than 503 refusal"
            );
        }
    }

    let with = ungranted_view(&granted);
    let without = ungranted_view(&ungranted);
    let keys: BTreeSet<&String> = with.keys().chain(without.keys()).collect();
    let differences: Vec<String> = keys
        .into_iter()
        .filter(|key| with.get(*key) != without.get(*key))
        .map(|key| {
            format!(
                "{key}:\n  with grant:    {}\n  without grant: {}",
                with.get(key)
                    .map_or("<absent>".to_string(), Value::to_string),
                without
                    .get(key)
                    .map_or("<absent>".to_string(), Value::to_string),
            )
        })
        .collect();
    assert!(
        differences.is_empty(),
        "{case}: the grant changed objects outside its routes:\n{}",
        differences.join("\n")
    );

    // Every authorization decision on every other route is identical,
    // including with no resolved source scope (the missing-scope census).
    let granted_authz = authz(&granted);
    let ungranted_authz = authz(&ungranted);
    for route in ungranted.proxies.iter().filter(|proxy| {
        !proxy
            .backend_scheme
            .is_some_and(|scheme| scheme.is_stream())
    }) {
        let counterpart = granted
            .proxies
            .iter()
            .find(|proxy| proxy.namespace == route.namespace && proxy.id == route.id)
            .unwrap_or_else(|| panic!("{case}: {} is kept", route.id));
        for source in [Some(TRUSTED), Some(UNTRUSTED), Some(BANNED), None] {
            assert_eq!(
                decide(&granted_authz, counterpart, source).await,
                decide(&ungranted_authz, route, source).await,
                "{case}: {} decides {source:?} the same with and without the grant",
                route.id
            );
        }
    }
}

/// Sidecar: an ordinary route to `other/ratings` with a subscriber-namespace
/// `WorkloadEntry` and remote-cluster failover, and a remote-only one.
#[tokio::test]
async fn a_grant_changes_only_the_routes_naming_its_target_on_a_sidecar() {
    for with_entry in [true, false] {
        assert_grant_changes_only_its_routes(sidecar_runtime(), with_entry).await;
    }
}

/// NodeWaypoint: the same, with the destination namespace's policy and
/// RequestAuthentication scoped to the granted destination alone.
#[tokio::test]
async fn a_grant_changes_only_the_routes_naming_its_target_on_a_node_waypoint() {
    for with_entry in [true, false] {
        assert_grant_changes_only_its_routes(node_waypoint_runtime(), with_entry).await;
    }
}

/// Review F3 (round 5): the remote-cluster endpoints of the target Service,
/// which share the destination workloads' identity, keep backing its ordinary
/// Sidecar route through the east-west gateway when a grant adds the local
/// destination workloads for the authorized route.
#[test]
fn a_grant_keeps_the_remote_endpoints_of_the_ordinary_route() {
    for with_entry in [true, false] {
        let granted = data_plane(&fixture(true, with_entry), &sidecar_runtime());
        let ordinary = granted
            .upstreams
            .iter()
            .find(|upstream| upstream.id == "__mesh-out-upstream-other-ratings-8080")
            .expect("the ordinary Service upstream");
        assert!(
            ordinary
                .targets
                .iter()
                .any(|target| target.host == "203.0.113.10"),
            "entry={with_entry}: the remote failover target stays: {:?}",
            ordinary.targets
        );
        assert!(
            !ordinary
                .targets
                .iter()
                .any(|target| target.host == "10.0.1.12"),
            "entry={with_entry}: the grant-only destination workload never backs it"
        );
    }
}

/// A grant-only RequestAuthentication that collides in `(namespace, name)`
/// with an ordinary waypoint-selecting RequestAuthentication must remain
/// tracked per-record so adding the grant never turns an unrelated mixed route
/// into a 503 refusal, while both records stay enforced on their targets.
#[test]
fn a_colliding_grant_only_request_auth_does_not_refuse_unrelated_routes() {
    use ferrum_edge::modes::mesh::config::{MeshJwtRule, MeshRequestAuthentication};

    let make_ra = |scope: PolicyScope, issuer: &str| MeshRequestAuthentication {
        name: "shared-ra".to_string(),
        namespace: "istio-system".to_string(),
        scope,
        jwt_rules: vec![MeshJwtRule {
            issuer: issuer.to_string(),
            audiences: Vec::new(),
            jwks_uri: None,
            jwks: Some(r#"{"keys":[]}"#.to_string()),
            from_headers: Vec::new(),
            from_params: Vec::new(),
            forward_original_token: false,
            output_claim_to_headers: Vec::new(),
        }],
        refused: false,
    };

    let build = |with_grant: bool| {
        let mut cfg = fixture(with_grant, false);
        let mesh = cfg.mesh.as_mut().expect("mesh block");
        mesh.request_authentications = vec![
            // Ordinary record selecting the waypoint itself.
            make_ra(PolicyScope::MeshWide, "https://ordinary.example.com"),
            // Distinct record with the SAME `(namespace, name)` selecting ONLY
            // the cross-namespace destination `other/ratings`.
            make_ra(selector(OTHER, "ratings"), "https://dest-only.example.com"),
        ];
        data_plane(&cfg, &node_waypoint_runtime())
    };

    let ungranted = build(false);
    let granted = build(true);

    for (label, cfg) in [("ungranted", &ungranted), ("granted", &granted)] {
        let mixed = cfg
            .proxies
            .iter()
            .find(|proxy| proxy.listen_path == "/mixed")
            .unwrap_or_else(|| panic!("{label}: /mixed route present"));
        assert!(
            !mixed.plugins.iter().any(|assoc| {
                assoc.plugin_config_id == MESH_REQUEST_AUTH_REFUSED_PLUGIN_ID
                    || assoc
                        .plugin_config_id
                        .starts_with(MESH_REQUEST_AUTH_REFUSED_PARTITION_ID_PREFIX)
            }),
            "{label}: colliding grant-only RA must not attach 503 refusal to /mixed: {:?}",
            mixed.plugins
        );
    }

    // The granted route still enforces the destination-only RA's issuer.
    let granted_route = granted
        .proxies
        .iter()
        .find(|proxy| proxy.id.contains(GRANTED_ROUTE_MARKER))
        .expect("granted route");
    let dest_jwks_ids: Vec<&str> = granted_route
        .plugins
        .iter()
        .map(|assoc| assoc.plugin_config_id.as_str())
        .filter(|id| id.starts_with(MESH_REQUEST_AUTH_DESTINATION_PLUGIN_ID_PREFIX))
        .collect();
    assert!(
        dest_jwks_ids.iter().any(|id| {
            granted.plugin_configs.iter().any(|plugin| {
                plugin.id == *id
                    && plugin.config["providers"]
                        .as_array()
                        .is_some_and(|providers| {
                            providers
                                .iter()
                                .any(|p| p["issuer"] == "https://dest-only.example.com")
                        })
            })
        }),
        "granted route must still enforce the colliding destination-only RequestAuthentication"
    );
}
