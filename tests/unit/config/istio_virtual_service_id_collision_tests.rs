//! GHSA-qw5p-g8jx-pmv8: two VirtualServices in one namespace whose names
//! differ only in a character the lossy `resource_id` join folds (`my.app` and
//! `my-app`) derive the same route proxy or route upstream id.
//!
//! Every derived id is claimed by the VirtualService that derived it first.
//! A later VirtualService deriving an owned id is refused as a whole with an
//! `InvalidResource` error, so the status writer reports it
//! `FerrumAccepted=False` instead of silently shadowing its route or letting
//! its upstream overwrite the owner's backends. The surviving translation has
//! no duplicate `(namespace, id)`, so the controller's publish-time
//! duplicate-id check never rejects the reconcile.

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sResourceKey, K8sTranslateError, K8sTranslationOptions,
    translate_k8s_objects, translate_k8s_objects_collecting_skips,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn virtual_service(name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "VirtualService".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            namespace: "default".to_string(),
            ..K8sMetadata::default()
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn virtual_service_with_cors(name: &str, host: &str, origin: &str) -> K8sObject {
    virtual_service(
        name,
        json!({
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
    )
}

fn refused_key(name: &str) -> K8sResourceKey {
    K8sResourceKey {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "VirtualService".to_string(),
        namespace: "default".to_string(),
        name: name.to_string(),
    }
}

fn assert_refused_for_owned_id(
    skipped: &std::collections::HashMap<K8sResourceKey, K8sTranslateError>,
    refused: &str,
    owner: &str,
    id_kind: &str,
) {
    let error = skipped
        .get(&refused_key(refused))
        .unwrap_or_else(|| panic!("VirtualService {refused} must be refused: {skipped:?}"));
    let K8sTranslateError::InvalidResource { message, .. } = error else {
        panic!("VirtualService {refused} must be refused as an invalid resource: {error:?}");
    };
    assert!(
        message.contains(&format!("route {id_kind} id"))
            && message.contains("already derived by VirtualService")
            && message.contains(&format!("{owner:?}")),
        "refusal must name the owning VirtualService: {message}"
    );
    assert_eq!(skipped.len(), 1, "only the later VirtualService is refused");
}

#[test]
fn later_virtual_service_deriving_an_owned_proxy_id_is_refused() {
    // Both orders: whichever VirtualService is translated first keeps the id.
    for (first, second) in [("my.app", "my-app"), ("my-app", "my.app")] {
        let (translation, skipped) = translate_k8s_objects_collecting_skips(
            &[
                virtual_service_with_cors(first, "a.example.com", "https://a.example.com"),
                virtual_service_with_cors(second, "b.example.com", "https://b.example.com"),
            ],
            options(),
        )
        .expect("translation converges with the colliding VirtualService skipped");
        assert_refused_for_owned_id(&skipped, second, first, "proxy");

        let config = translation.config;
        let route_proxies: Vec<_> = config
            .proxies
            .iter()
            .filter(|proxy| proxy.id.starts_with("istio-vs-default-my-app"))
            .collect();
        assert!(
            !route_proxies.is_empty(),
            "the owner's route proxy must be materialized: {:?}",
            config.proxies.iter().map(|p| &p.id).collect::<Vec<_>>()
        );
        for proxy in &route_proxies {
            assert!(
                !proxy.hosts.iter().any(|host| host == "b.example.com"),
                "the refused VirtualService's host must not be served: {:?}",
                proxy.hosts
            );
        }

        let cors_plugins: Vec<_> = config
            .plugin_configs
            .iter()
            .filter(|plugin| plugin.plugin_name == "cors")
            .collect();
        assert_eq!(
            cors_plugins.len(),
            1,
            "only the owner's cors plugin may be published: {:?}",
            cors_plugins.iter().map(|p| &p.id).collect::<Vec<_>>()
        );

        config
            .validate_unique_resource_ids()
            .expect("a colliding VirtualService pair must not yield duplicate resource ids");
    }
}

#[test]
fn later_virtual_service_deriving_an_owned_upstream_id_is_refused() {
    // `my.app` has two matches on http[0], so its proxies are `…-my-app-0-0`
    // and `…-my-app-0-1`, while `my-app`'s single-match proxy is
    // `…-my-app-0`: the proxy ids differ, but both weighted routes derive the
    // upstream id `istio-vs-upstream-default-my-app-0`.
    let owner = virtual_service(
        "my.app",
        json!({
            "hosts": ["a.example.com"],
            "http": [{
                "match": [{"uri": {"prefix": "/a"}}, {"uri": {"prefix": "/b"}}],
                "route": [
                    {"destination": {"host": "svc-one-v1.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 50},
                    {"destination": {"host": "svc-one-v2.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 50}
                ]
            }]
        }),
    );
    let later = virtual_service(
        "my-app",
        json!({
            "hosts": ["b.example.com"],
            "http": [{
                "match": [{"uri": {"prefix": "/c"}}],
                "route": [
                    {"destination": {"host": "svc-two-v1.default.svc.cluster.local", "port": {"number": 9090}}, "weight": 50},
                    {"destination": {"host": "svc-two-v2.default.svc.cluster.local", "port": {"number": 9090}}, "weight": 50}
                ]
            }]
        }),
    );

    let (translation, skipped) = translate_k8s_objects_collecting_skips(&[owner, later], options())
        .expect("translation converges with the colliding VirtualService skipped");
    assert_refused_for_owned_id(&skipped, "my-app", "my.app", "upstream");

    let config = translation.config;
    let upstream = config
        .upstreams
        .iter()
        .find(|upstream| upstream.id == "istio-vs-upstream-default-my-app-0")
        .expect("the owner's upstream must be materialized");
    assert!(
        upstream
            .targets
            .iter()
            .all(|target| target.host.contains("svc-one")),
        "the refused VirtualService must not overwrite the owner's backends: {:?}",
        upstream
            .targets
            .iter()
            .map(|target| &target.host)
            .collect::<Vec<_>>()
    );
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
