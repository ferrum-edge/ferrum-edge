//! Gateway API routes on a shared Gateway stay isolated per source object.
//!
//! Cross-namespace HTTPRoutes are materialized in their parent Gateway's
//! namespace, so routes owned by different tenants share one proxy, upstream,
//! and plugin keyspace there. Their ids must stay distinct even when the
//! route namespace and name dash-join to the same string. Backend references
//! must also stay inside the ReferenceGrant boundary, which an `ExternalName`
//! Service (a DNS alias to any host) would otherwise bypass.

use ferrum_edge::config::types::{GatewayConfig, Proxy};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, plan_gateway_api_status_updates,
};
use serde_json::{Value, json};
use std::collections::HashMap;

const VICTIM_HOST: &str = "checkout.apps.example.com";
const OTHER_HOST: &str = "other.apps.example.com";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_source_namespaces(Vec::new())
}

fn object(kind: &str, name: &str, namespace: &str, api_version: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{namespace}-{name}"),
            namespace: namespace.to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn gateway_class() -> K8sObject {
    object(
        "GatewayClass",
        "ferrum",
        "",
        "gateway.networking.k8s.io/v1",
        json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
    )
}

fn shared_gateway(namespace: &str, from: &str) -> K8sObject {
    object(
        "Gateway",
        "shared",
        namespace,
        "gateway.networking.k8s.io/v1",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": { "namespaces": { "from": from } }
            }]
        }),
    )
}

/// A route whose rule emits a dispatch plugin (method match + header filter)
/// and an upstream (two weighted backends).
fn tenant_route(namespace: &str, name: &str, host: &str, backend: &str) -> K8sObject {
    object(
        "HTTPRoute",
        name,
        namespace,
        "gateway.networking.k8s.io/v1",
        json!({
            "parentRefs": [{ "name": "shared", "namespace": "infra" }],
            "hostnames": [host],
            "rules": [{
                "matches": [{
                    "path": { "type": "PathPrefix", "value": "/" },
                    "method": "GET"
                }],
                "filters": [{
                    "type": "RequestHeaderModifier",
                    "requestHeaderModifier": {
                        "set": [{ "name": "X-Tenant", "value": namespace }]
                    }
                }],
                "backendRefs": [
                    { "name": backend, "port": 8080, "weight": 1 },
                    { "name": format!("{backend}-canary"), "port": 8080, "weight": 1 }
                ]
            }]
        }),
    )
}

fn proxy_for<'a>(config: &'a GatewayConfig, host: &str) -> &'a Proxy {
    config
        .proxies
        .iter()
        .find(|proxy| proxy.namespace == "infra" && proxy.hosts.iter().any(|h| h == host))
        .unwrap_or_else(|| panic!("proxy for {host} in the Gateway namespace"))
}

#[test]
fn dash_joined_cross_namespace_routes_keep_distinct_proxies_upstreams_and_plugins() {
    // `shop/checkout-api` and `shop-checkout/api` dash-join to the same
    // readable id; both are materialized in the Gateway's `infra` namespace.
    let objects = vec![
        gateway_class(),
        shared_gateway("infra", "All"),
        tenant_route("shop", "checkout-api", VICTIM_HOST, "checkout"),
        tenant_route("shop-checkout", "api", OTHER_HOST, "storefront"),
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translation");
    let config = &translation.config;

    config
        .validate_unique_resource_ids()
        .expect("every materialized resource keeps a unique (namespace, id)");

    let victim = proxy_for(config, VICTIM_HOST);
    let other = proxy_for(config, OTHER_HOST);
    assert_ne!(
        victim.id, other.id,
        "the two tenants must not share a proxy id"
    );

    let victim_upstream_id = victim.upstream_id.as_deref().expect("victim upstream");
    let other_upstream_id = other.upstream_id.as_deref().expect("other upstream");
    assert_ne!(
        victim_upstream_id, other_upstream_id,
        "the two tenants must not share an upstream id"
    );
    let victim_upstream = config
        .upstreams
        .iter()
        .find(|upstream| upstream.namespace == "infra" && upstream.id == victim_upstream_id)
        .expect("victim upstream materialized");
    assert!(
        victim_upstream
            .targets
            .iter()
            .all(|target| target.host.ends_with(".shop.svc.cluster.local")),
        "the victim's upstream must reach only its own backends: {:?}",
        victim_upstream.targets
    );

    // Every plugin attached to the victim's proxy is the victim's own: exactly
    // one dispatch plugin, and none that routes to the other tenant.
    let victim_plugins: Vec<_> = config
        .plugin_configs
        .iter()
        .filter(|plugin| {
            plugin.namespace == "infra" && plugin.proxy_id.as_deref() == Some(victim.id.as_str())
        })
        .collect();
    let dispatch_plugins = victim_plugins
        .iter()
        .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .count();
    assert_eq!(
        dispatch_plugins, 1,
        "the victim proxy must carry exactly its own dispatch plugin"
    );
    for plugin in &victim_plugins {
        let rendered = plugin.config.to_string();
        assert!(
            !rendered.contains(other_upstream_id) && !rendered.contains("\"shop-checkout\""),
            "a plugin on the victim proxy must not route to the other tenant: {rendered}"
        );
    }
}

fn external_name_fixture(service_spec: Value) -> Vec<K8sObject> {
    vec![
        gateway_class(),
        shared_gateway("tenant-a", "Same"),
        object(
            "HTTPRoute",
            "store",
            "tenant-a",
            "gateway.networking.k8s.io/v1",
            json!({
                "parentRefs": [{ "name": "shared" }],
                "hostnames": ["store.example.com"],
                "rules": [{
                    "matches": [{ "path": { "type": "PathPrefix", "value": "/" } }],
                    "backendRefs": [{ "name": "payroll", "port": 8080 }]
                }]
            }),
        ),
        object("Service", "payroll", "tenant-a", "v1", service_spec),
    ]
}

fn resolved_refs(objects: &[K8sObject]) -> (String, Option<String>) {
    let updates = plan_gateway_api_status_updates(objects, options(), &[]);
    let route = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "store")
        .expect("HTTPRoute status");
    let condition = route.status["parents"][0]["conditions"]
        .as_array()
        .expect("route parent conditions")
        .iter()
        .find(|condition| condition["type"] == "ResolvedRefs")
        .expect("ResolvedRefs condition");
    (
        condition["status"].as_str().unwrap_or_default().to_string(),
        condition["reason"].as_str().map(ToOwned::to_owned),
    )
}

#[test]
fn external_name_service_backend_is_refused_and_reported() {
    // Same-namespace backendRef, so no ReferenceGrant is consulted — but the
    // ExternalName alias points into another namespace.
    let objects = external_name_fixture(json!({
        "type": "ExternalName",
        "externalName": "payroll.hr.svc.cluster.local",
        "ports": [{ "name": "http", "port": 8080 }]
    }));
    let translation = translate_k8s_objects(&objects, options()).expect("translation");
    let alias = "payroll.tenant-a.svc.cluster.local";
    assert!(
        translation
            .config
            .proxies
            .iter()
            .all(|proxy| proxy.backend_host != alias),
        "an ExternalName Service must never become a dial target"
    );
    assert!(
        translation
            .config
            .upstreams
            .iter()
            .flat_map(|upstream| upstream.targets.iter())
            .all(|target| target.host != alias),
        "an ExternalName Service must never become an upstream target"
    );
    let (status, reason) = resolved_refs(&objects);
    assert_eq!(status, "False");
    assert_eq!(reason.as_deref(), Some("UnsupportedProtocol"));
}

#[test]
fn cluster_ip_service_backend_still_resolves() {
    let objects = external_name_fixture(json!({
        "type": "ClusterIP",
        "clusterIP": "10.96.0.10",
        "ports": [{ "name": "http", "port": 8080 }]
    }));
    let translation = translate_k8s_objects(&objects, options()).expect("translation");
    assert!(
        translation
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_host == "payroll.tenant-a.svc.cluster.local"),
        "a ClusterIP Service keeps resolving through Service DNS"
    );
    assert_eq!(resolved_refs(&objects).0, "True");
}
