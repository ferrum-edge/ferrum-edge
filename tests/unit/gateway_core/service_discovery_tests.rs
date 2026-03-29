//! Unit tests for the service discovery module.

use ferrum_gateway::config::types::*;
use ferrum_gateway::load_balancer::LoadBalancerCache;
use ferrum_gateway::service_discovery::consul::ConsulDiscoverer;
use ferrum_gateway::service_discovery::kubernetes::KubernetesDiscoverer;
use ferrum_gateway::service_discovery::{ServiceDiscoverer, ServiceDiscoveryManager};
use std::collections::HashMap;
use std::sync::Arc;

// ── Helper: build a minimal GatewayConfig with upstreams ──────────────

fn make_config_with_upstreams(upstreams: Vec<Upstream>) -> GatewayConfig {
    GatewayConfig {
        upstreams,
        ..Default::default()
    }
}

fn make_upstream(
    id: &str,
    targets: Vec<UpstreamTarget>,
    sd: Option<ServiceDiscoveryConfig>,
) -> Upstream {
    Upstream {
        id: id.to_string(),
        name: None,
        targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        health_checks: None,
        service_discovery: sd,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn make_target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        weight: 1,
        tags: HashMap::new(),
        path: None,
    }
}

// ── ServiceDiscoveryConfig serialization ──────────────────────────────

#[test]
fn test_sd_config_deserialize_dns_sd() {
    let json = r#"{
        "provider": "dns_sd",
        "dns_sd": {
            "service_name": "_http._tcp.my-service.consul",
            "poll_interval_seconds": 15
        },
        "default_weight": 5
    }"#;

    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.provider, SdProvider::DnsSd);
    assert_eq!(config.default_weight, 5);
    let dns = config.dns_sd.unwrap();
    assert_eq!(dns.service_name, "_http._tcp.my-service.consul");
    assert_eq!(dns.poll_interval_seconds, 15);
    assert!(config.kubernetes.is_none());
    assert!(config.consul.is_none());
}

#[test]
fn test_sd_config_deserialize_kubernetes() {
    let json = r#"{
        "provider": "kubernetes",
        "kubernetes": {
            "namespace": "production",
            "service_name": "my-api",
            "port_name": "http",
            "label_selector": "app=my-api"
        }
    }"#;

    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.provider, SdProvider::Kubernetes);
    assert_eq!(config.default_weight, 1); // default
    let k8s = config.kubernetes.unwrap();
    assert_eq!(k8s.namespace, "production");
    assert_eq!(k8s.service_name, "my-api");
    assert_eq!(k8s.port_name.unwrap(), "http");
    assert_eq!(k8s.label_selector.unwrap(), "app=my-api");
    assert_eq!(k8s.poll_interval_seconds, 30); // default
}

#[test]
fn test_sd_config_deserialize_consul() {
    let json = r#"{
        "provider": "consul",
        "consul": {
            "address": "http://consul:8500",
            "service_name": "my-api",
            "datacenter": "dc1",
            "tag": "production",
            "healthy_only": false,
            "token": "my-acl-token",
            "poll_interval_seconds": 10
        }
    }"#;

    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.provider, SdProvider::Consul);
    let consul = config.consul.unwrap();
    assert_eq!(consul.address, "http://consul:8500");
    assert_eq!(consul.service_name, "my-api");
    assert_eq!(consul.datacenter.unwrap(), "dc1");
    assert_eq!(consul.tag.unwrap(), "production");
    assert!(!consul.healthy_only);
    assert_eq!(consul.token.unwrap(), "my-acl-token");
    assert_eq!(consul.poll_interval_seconds, 10);
}

#[test]
fn test_sd_config_defaults() {
    let json = r#"{
        "provider": "consul",
        "consul": {
            "address": "http://consul:8500",
            "service_name": "my-api"
        }
    }"#;

    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    let consul = config.consul.unwrap();
    assert!(consul.healthy_only); // default true
    assert_eq!(consul.poll_interval_seconds, 30); // default
    assert!(consul.datacenter.is_none());
    assert!(consul.tag.is_none());
    assert!(consul.token.is_none());
    assert_eq!(config.default_weight, 1); // default
}

#[test]
fn test_sd_config_roundtrip_json() {
    let config = ServiceDiscoveryConfig {
        provider: SdProvider::DnsSd,
        dns_sd: Some(DnsSdConfig {
            service_name: "_http._tcp.api.example.com".to_string(),
            poll_interval_seconds: 20,
        }),
        kubernetes: None,
        consul: None,
        default_weight: 3,
    };

    let json = serde_json::to_string(&config).unwrap();
    let deserialized: ServiceDiscoveryConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.provider, SdProvider::DnsSd);
    assert_eq!(deserialized.default_weight, 3);
    assert_eq!(
        deserialized.dns_sd.unwrap().service_name,
        "_http._tcp.api.example.com"
    );
}

#[test]
fn test_upstream_with_service_discovery() {
    let json = r#"{
        "id": "my-upstream",
        "targets": [
            {"host": "static-1.example.com", "port": 8080}
        ],
        "algorithm": "round_robin",
        "service_discovery": {
            "provider": "dns_sd",
            "dns_sd": {
                "service_name": "_http._tcp.my-service.consul"
            }
        }
    }"#;

    let upstream: Upstream = serde_json::from_str(json).unwrap();
    assert_eq!(upstream.id, "my-upstream");
    assert_eq!(upstream.targets.len(), 1);
    assert!(upstream.service_discovery.is_some());
    let sd = upstream.service_discovery.unwrap();
    assert_eq!(sd.provider, SdProvider::DnsSd);
}

#[test]
fn test_upstream_without_service_discovery() {
    let json = r#"{
        "id": "basic-upstream",
        "targets": [
            {"host": "backend.example.com", "port": 8080}
        ]
    }"#;

    let upstream: Upstream = serde_json::from_str(json).unwrap();
    assert!(upstream.service_discovery.is_none());
}

// ── LoadBalancerCache::update_targets ─────────────────────────────────

#[test]
fn test_load_balancer_cache_update_targets() {
    let config = make_config_with_upstreams(vec![
        make_upstream(
            "upstream-1",
            vec![make_target("host-a", 8080), make_target("host-b", 8080)],
            None,
        ),
        make_upstream("upstream-2", vec![make_target("host-c", 9090)], None),
    ]);

    let cache = LoadBalancerCache::new(&config);

    // Verify initial state
    let u1 = cache.get_upstream("upstream-1").unwrap();
    assert_eq!(u1.targets.len(), 2);

    // Update targets for upstream-1
    let new_targets = vec![
        make_target("host-a", 8080),
        make_target("host-b", 8080),
        make_target("host-d", 8080), // new discovered target
    ];
    cache.update_targets(
        "upstream-1",
        new_targets,
        LoadBalancerAlgorithm::RoundRobin,
        None,
    );

    // Verify updated state
    let u1 = cache.get_upstream("upstream-1").unwrap();
    assert_eq!(u1.targets.len(), 3);
    assert_eq!(u1.targets[2].host, "host-d");

    // Verify upstream-2 is untouched
    let u2 = cache.get_upstream("upstream-2").unwrap();
    assert_eq!(u2.targets.len(), 1);
    assert_eq!(u2.targets[0].host, "host-c");
}

#[test]
fn test_load_balancer_cache_update_targets_selection_works() {
    let config = make_config_with_upstreams(vec![make_upstream(
        "up",
        vec![make_target("old-host", 8080)],
        None,
    )]);

    let cache = LoadBalancerCache::new(&config);

    // Select from old targets
    let sel = cache.select_target("up", "key", None).unwrap();
    assert_eq!(sel.target.host, "old-host");

    // Update to new targets
    cache.update_targets(
        "up",
        vec![make_target("new-host", 9090)],
        LoadBalancerAlgorithm::RoundRobin,
        None,
    );

    // Select from new targets
    let sel = cache.select_target("up", "key", None).unwrap();
    assert_eq!(sel.target.host, "new-host");
    assert_eq!(sel.target.port, 9090);
}

// ── merge_targets ─────────────────────────────────────────────────────

#[test]
fn test_merge_targets_no_overlap() {
    let static_targets = vec![make_target("static-1", 8080)];
    let discovered = vec![make_target("discovered-1", 9090)];

    let merged = ferrum_gateway::service_discovery::merge_targets(&static_targets, &discovered);
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].host, "static-1");
    assert_eq!(merged[1].host, "discovered-1");
}

#[test]
fn test_merge_targets_overlap_keeps_static() {
    let mut static_targets = vec![make_target("shared-host", 8080)];
    static_targets[0].weight = 10; // static has custom weight

    let mut discovered = vec![make_target("shared-host", 8080)];
    discovered[0].weight = 1; // discovered has default weight

    let merged = ferrum_gateway::service_discovery::merge_targets(&static_targets, &discovered);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].weight, 10); // static weight preserved
}

#[test]
fn test_merge_targets_empty_discovered() {
    let static_targets = vec![make_target("static-1", 8080)];
    let discovered: Vec<UpstreamTarget> = vec![];

    let merged = ferrum_gateway::service_discovery::merge_targets(&static_targets, &discovered);
    assert_eq!(merged.len(), 1);
}

#[test]
fn test_merge_targets_empty_static() {
    let static_targets: Vec<UpstreamTarget> = vec![];
    let discovered = vec![make_target("discovered-1", 9090)];

    let merged = ferrum_gateway::service_discovery::merge_targets(&static_targets, &discovered);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].host, "discovered-1");
}

// ── targets_equal ─────────────────────────────────────────────────────

#[test]
fn test_targets_equal_same_order() {
    let a = vec![make_target("h1", 80), make_target("h2", 90)];
    let b = vec![make_target("h1", 80), make_target("h2", 90)];
    assert!(ferrum_gateway::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_different_order() {
    let a = vec![make_target("h2", 90), make_target("h1", 80)];
    let b = vec![make_target("h1", 80), make_target("h2", 90)];
    assert!(ferrum_gateway::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_different_length() {
    let a = vec![make_target("h1", 80)];
    let b = vec![make_target("h1", 80), make_target("h2", 90)];
    assert!(!ferrum_gateway::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_different_content() {
    let a = vec![make_target("h1", 80)];
    let b = vec![make_target("h2", 80)];
    assert!(!ferrum_gateway::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_empty() {
    let a: Vec<UpstreamTarget> = vec![];
    let b: Vec<UpstreamTarget> = vec![];
    assert!(ferrum_gateway::service_discovery::targets_equal(&a, &b));
}

// ── SdProvider::as_str ────────────────────────────────────────────────

#[test]
fn test_sd_provider_as_str() {
    assert_eq!(SdProvider::DnsSd.as_str(), "dns_sd");
    assert_eq!(SdProvider::Kubernetes.as_str(), "kubernetes");
    assert_eq!(SdProvider::Consul.as_str(), "consul");
}

// ── ServiceDiscoveryManager lifecycle ─────────────────────────────────

#[tokio::test]
async fn test_manager_start_with_no_sd_upstreams() {
    let config = make_config_with_upstreams(vec![make_upstream(
        "up-1",
        vec![make_target("h1", 80)],
        None,
    )]);

    let cache = Arc::new(LoadBalancerCache::new(&config));
    let dns_cache = ferrum_gateway::dns::DnsCache::new(Default::default());
    let manager = ServiceDiscoveryManager::new(
        cache,
        dns_cache,
        Arc::new(ferrum_gateway::health_check::HealthChecker::new()),
        ferrum_gateway::plugins::PluginHttpClient::default(),
    );

    // No SD config → no tasks started
    manager.start(&config, None);
    // Manager should have no tasks (we can't directly inspect, but it shouldn't panic)
    manager.stop();
}

#[tokio::test]
async fn test_manager_stop_is_idempotent() {
    let config = make_config_with_upstreams(vec![]);
    let cache = Arc::new(LoadBalancerCache::new(&config));
    let dns_cache = ferrum_gateway::dns::DnsCache::new(Default::default());
    let manager = ServiceDiscoveryManager::new(
        cache,
        dns_cache,
        Arc::new(ferrum_gateway::health_check::HealthChecker::new()),
        ferrum_gateway::plugins::PluginHttpClient::default(),
    );

    manager.stop();
    manager.stop(); // Should not panic
}

// ── Consul discoverer: URL building ───────────────────────────────────

#[test]
fn test_consul_discoverer_provider_name() {
    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        "http://consul:8500".to_string(),
        "my-service".to_string(),
        None,
        None,
        true,
        None,
        1,
    );
    assert_eq!(discoverer.provider_name(), "consul");
}

// ── Kubernetes discoverer: provider name ──────────────────────────────

#[test]
fn test_kubernetes_discoverer_provider_name() {
    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "my-service".to_string(),
        None,
        None,
        1,
    );
    assert_eq!(discoverer.provider_name(), "kubernetes");
}

// ── Consul response parsing (mock HTTP) ──────────────────────────────

#[tokio::test]
async fn test_consul_discover_parses_response() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let consul_response = serde_json::json!([
        {
            "Node": {"Address": "10.0.0.1"},
            "Service": {
                "Address": "10.0.0.1",
                "Port": 8080,
                "Tags": ["production", "v2"],
                "Weights": {"Passing": 5, "Warning": 1}
            }
        },
        {
            "Node": {"Address": "10.0.0.2"},
            "Service": {
                "Address": "",
                "Port": 8080,
                "Tags": []
            }
        },
        {
            "Node": {"Address": "10.0.0.3"},
            "Service": {
                "Address": "10.0.0.3",
                "Port": 0,
                "Tags": []
            }
        }
    ]);

    Mock::given(method("GET"))
        .and(path("/v1/health/service/my-api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&consul_response)
                .insert_header("X-Consul-Index", "42"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "my-api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );

    let targets = discoverer.discover().await.unwrap();

    // Should have 2 targets: port=0 and empty address are filtered out
    assert_eq!(targets.len(), 2);

    // First target: has Service.Address and Weights.Passing
    assert_eq!(targets[0].host, "10.0.0.1");
    assert_eq!(targets[0].port, 8080);
    assert_eq!(targets[0].weight, 5); // from Weights.Passing

    // Second target: falls back to Node.Address since Service.Address is empty
    assert_eq!(targets[1].host, "10.0.0.2");
    assert_eq!(targets[1].port, 8080);
    assert_eq!(targets[1].weight, 1); // default_weight
}

#[tokio::test]
async fn test_consul_discover_with_token() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/secure-api"))
        .and(header("X-Consul-Token", "secret-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "secure-api".to_string(),
        None,
        None,
        false,
        Some("secret-token".to_string()),
        1,
    );

    let targets = discoverer.discover().await.unwrap();
    assert!(targets.is_empty());
}

#[tokio::test]
async fn test_consul_discover_error_response() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/bad-api"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "bad-api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );

    let result = discoverer.discover().await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("500"));
}

// ── Kubernetes EndpointSlice parsing ──────────────────────────────────

#[tokio::test]
async fn test_kubernetes_discover_parses_endpointslice() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let endpoint_slice_response = serde_json::json!({
        "items": [
            {
                "ports": [
                    {"name": "http", "port": 8080, "protocol": "TCP"},
                    {"name": "grpc", "port": 9090, "protocol": "TCP"}
                ],
                "endpoints": [
                    {
                        "addresses": ["10.244.0.5", "10.244.0.6"],
                        "conditions": {"ready": true}
                    },
                    {
                        "addresses": ["10.244.0.7"],
                        "conditions": {"ready": false}
                    }
                ]
            }
        ]
    });

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&endpoint_slice_response))
        .mount(&mock_server)
        .await;

    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "my-service".to_string(),
        Some("http".to_string()), // select by port name
        None,
        1,
    )
    .with_api_url(mock_server.uri());

    let targets = discoverer.discover().await.unwrap();

    // Should have 2 ready endpoints (10.244.0.7 is not ready)
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].host, "10.244.0.5");
    assert_eq!(targets[0].port, 8080); // matched "http" port
    assert_eq!(targets[1].host, "10.244.0.6");
    assert_eq!(targets[1].port, 8080);
}

// ── YAML config with service discovery ────────────────────────────────

#[test]
fn test_yaml_config_with_service_discovery() {
    let yaml = r#"
proxies: []
consumers: []
plugin_configs: []
upstreams:
  - id: my-upstream
    targets:
      - host: static-host
        port: 8080
    algorithm: round_robin
    service_discovery:
      provider: consul
      consul:
        address: http://consul:8500
        service_name: my-api
        healthy_only: true
      default_weight: 2
"#;

    let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.upstreams.len(), 1);
    let upstream = &config.upstreams[0];
    assert!(upstream.service_discovery.is_some());
    let sd = upstream.service_discovery.as_ref().unwrap();
    assert_eq!(sd.provider, SdProvider::Consul);
    assert_eq!(sd.default_weight, 2);
    let consul = sd.consul.as_ref().unwrap();
    assert_eq!(consul.address, "http://consul:8500");
    assert!(consul.healthy_only);
}
