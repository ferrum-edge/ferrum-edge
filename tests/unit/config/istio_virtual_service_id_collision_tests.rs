//! GHSA-qw5p-g8jx-pmv8: two VirtualServices in one namespace whose names
//! differ only in a character the lossy `resource_id` join folds (`my.app` and
//! `my-app`) derive the same route proxy id. The second proxy is refused by
//! `K8sAccumulator::upsert_proxy`; its proxy-scoped plugins (whose ids are
//! derived from the proxy id) must be refused with it. Otherwise the
//! translation carries two plugin configs with one `(namespace, id)`, and the
//! controller's publish-time duplicate-id check rejects every later
//! Kubernetes reconcile for the whole cluster.

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn virtual_service_with_cors(name: &str, host: &str, origin: &str) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "VirtualService".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            namespace: "default".to_string(),
            ..K8sMetadata::default()
        },
        spec: json!({
            "hosts": [host],
            "http": [{
                "route": [{"destination": {
                    "host": "echo.default.svc.cluster.local",
                    "port": {"number": 8080}
                }}],
                "corsPolicy": {
                    "allowOrigins": [{"exact": origin}],
                    "allowMethods": ["GET"]
                }
            }]
        }),
        status: Value::Object(serde_json::Map::new()),
    }
}

#[test]
fn colliding_virtual_service_proxy_ids_do_not_publish_duplicate_plugin_ids() {
    let result = translate_k8s_objects(
        &[
            virtual_service_with_cors("my.app", "a.example.com", "https://a.example.com"),
            virtual_service_with_cors("my-app", "b.example.com", "https://b.example.com"),
        ],
        options(),
    )
    .expect("translation succeeds");
    let config = result.config;

    // Precondition: the two VirtualServices really do derive one proxy id.
    let route_proxies: Vec<_> = config
        .proxies
        .iter()
        .filter(|proxy| proxy.id.starts_with("istio-vs-default-my-app"))
        .collect();
    assert_eq!(
        route_proxies.len(),
        1,
        "the colliding route proxy must be materialized once: {:?}",
        config.proxies.iter().map(|p| &p.id).collect::<Vec<_>>()
    );
    let proxy_id = route_proxies[0].id.clone();

    let cors_plugins: Vec<_> = config
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.plugin_name == "cors")
        .collect();
    assert_eq!(
        cors_plugins.len(),
        1,
        "only the surviving proxy's cors plugin may be published: {:?}",
        cors_plugins.iter().map(|p| &p.id).collect::<Vec<_>>()
    );
    assert_eq!(cors_plugins[0].proxy_id.as_deref(), Some(proxy_id.as_str()));

    config
        .validate_unique_resource_ids()
        .expect("a colliding VirtualService pair must not yield duplicate resource ids");
}

#[test]
fn distinct_virtual_service_proxy_ids_keep_both_plugins() {
    let result = translate_k8s_objects(
        &[
            virtual_service_with_cors("app-a", "a.example.com", "https://a.example.com"),
            virtual_service_with_cors("app-b", "b.example.com", "https://b.example.com"),
        ],
        options(),
    )
    .expect("translation succeeds");
    let config = result.config;
    for vs_name in ["app-a", "app-b"] {
        let prefix = format!("istio-vs-default-{vs_name}");
        assert!(
            config.plugin_configs.iter().any(|plugin| {
                plugin.plugin_name == "cors"
                    && plugin
                        .proxy_id
                        .as_deref()
                        .is_some_and(|id| id.starts_with(&prefix))
            }),
            "VirtualService {vs_name} must keep its cors plugin"
        );
    }
    config
        .validate_unique_resource_ids()
        .expect("distinct VirtualServices have distinct resource ids");
}
