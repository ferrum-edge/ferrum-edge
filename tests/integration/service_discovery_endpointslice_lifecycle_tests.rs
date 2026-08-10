//! Integration coverage for Kubernetes EndpointSlice lifecycle publication (#3716).
//!
//! Verifies that an endpoint transitioning from active to terminating is removed
//! from the live LoadBalancerCache while a healthy peer remains selectable.

use ferrum_edge::config::types::{
    GatewayConfig, KubernetesConfig, LoadBalancerAlgorithm, SdProvider, ServiceDiscoveryConfig,
    Upstream, UpstreamTarget, default_namespace,
};
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::service_discovery::ServiceDiscoverer;
use ferrum_edge::service_discovery::kubernetes::KubernetesDiscoverer;
use std::collections::HashMap;
use std::sync::Arc;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_upstream(id: &str) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: default_namespace(),
        name: None,
        targets: Vec::new(),
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: Some(ServiceDiscoveryConfig {
            provider: SdProvider::Kubernetes,
            dns_sd: None,
            kubernetes: Some(KubernetesConfig {
                namespace: "default".to_string(),
                service_name: "users-api".to_string(),
                port_name: Some("http".to_string()),
                label_selector: None,
                poll_interval_seconds: 30,
            }),
            consul: None,
            mesh: None,
            default_weight: 1,
        }),
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        source_labels: Default::default(),
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn endpointslice_items(endpoints: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "items": [{
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
            "endpoints": endpoints
        }]
    })
}

async fn publish_discovered(
    cache: &LoadBalancerCache,
    discoverer: &KubernetesDiscoverer,
    upstream_id: &str,
) -> Vec<UpstreamTarget> {
    let discovered = discoverer
        .discover()
        .await
        .expect("kubernetes discovery must succeed");
    cache.update_targets(
        "ferrum",
        upstream_id,
        discovered.clone(),
        LoadBalancerAlgorithm::RoundRobin,
        None,
    );
    discovered
}

#[tokio::test]
async fn kubernetes_endpointslice_active_to_terminating_removes_endpoint_from_lb_cache() {
    let mock_server = MockServer::start().await;

    let active_slice = endpointslice_items(serde_json::json!([
        {
            "addresses": ["10.244.0.10"],
            "conditions": {"ready": true, "serving": true, "terminating": false}
        },
        {
            "addresses": ["10.244.0.11"],
            "conditions": {"ready": true, "serving": true, "terminating": false}
        }
    ]));

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&active_slice))
        .mount(&mock_server)
        .await;

    let config = GatewayConfig {
        upstreams: vec![make_upstream("users")],
        ..Default::default()
    };
    let cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "users-api".to_string(),
        Some("http".to_string()),
        None,
        1,
    )
    .with_api_url(mock_server.uri());

    let first = publish_discovered(&cache, &discoverer, "users").await;
    assert_eq!(first.len(), 2);
    let live = cache
        .get_upstream("ferrum", "users")
        .expect("upstream live");
    let mut hosts: Vec<&str> = live.targets.iter().map(|t| t.host.as_str()).collect();
    hosts.sort_unstable();
    assert_eq!(hosts, vec!["10.244.0.10", "10.244.0.11"]);

    mock_server.reset().await;

    let terminating_peer = endpointslice_items(serde_json::json!([
        {
            "addresses": ["10.244.0.10"],
            "conditions": {
                "ready": true,
                "serving": true,
                "terminating": true
            }
        },
        {
            "addresses": ["10.244.0.11"],
            "conditions": {"ready": true, "serving": true, "terminating": false}
        }
    ]));

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&terminating_peer))
        .mount(&mock_server)
        .await;

    let second = publish_discovered(&cache, &discoverer, "users").await;
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].host, "10.244.0.11");

    let live = cache
        .get_upstream("ferrum", "users")
        .expect("upstream still live");
    assert_eq!(live.targets.len(), 1);
    assert_eq!(live.targets[0].host, "10.244.0.11");

    let selected = cache
        .select_target("ferrum", "users", "sticky", None)
        .expect("healthy peer must remain selectable");
    assert_eq!(selected.target.host, "10.244.0.11");
}
