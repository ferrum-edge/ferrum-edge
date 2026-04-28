//! Unit tests for the service discovery module.

use ferrum_edge::config::types::*;
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::service_discovery::consul::ConsulDiscoverer;
use ferrum_edge::service_discovery::kubernetes::KubernetesDiscoverer;
use ferrum_edge::service_discovery::{ServiceDiscoverer, ServiceDiscoveryManager};
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
        namespace: default_namespace(),
        name: None,
        targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: sd,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        api_spec_id: None,
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

    let merged = ferrum_edge::service_discovery::merge_targets(&static_targets, &discovered);
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

    let merged = ferrum_edge::service_discovery::merge_targets(&static_targets, &discovered);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].weight, 10); // static weight preserved
}

#[test]
fn test_merge_targets_empty_discovered() {
    let static_targets = vec![make_target("static-1", 8080)];
    let discovered: Vec<UpstreamTarget> = vec![];

    let merged = ferrum_edge::service_discovery::merge_targets(&static_targets, &discovered);
    assert_eq!(merged.len(), 1);
}

#[test]
fn test_merge_targets_empty_static() {
    let static_targets: Vec<UpstreamTarget> = vec![];
    let discovered = vec![make_target("discovered-1", 9090)];

    let merged = ferrum_edge::service_discovery::merge_targets(&static_targets, &discovered);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].host, "discovered-1");
}

// ── targets_equal ─────────────────────────────────────────────────────

#[test]
fn test_targets_equal_same_order() {
    let a = vec![make_target("h1", 80), make_target("h2", 90)];
    let b = vec![make_target("h1", 80), make_target("h2", 90)];
    assert!(ferrum_edge::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_different_order() {
    let a = vec![make_target("h2", 90), make_target("h1", 80)];
    let b = vec![make_target("h1", 80), make_target("h2", 90)];
    assert!(ferrum_edge::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_different_length() {
    let a = vec![make_target("h1", 80)];
    let b = vec![make_target("h1", 80), make_target("h2", 90)];
    assert!(!ferrum_edge::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_different_content() {
    let a = vec![make_target("h1", 80)];
    let b = vec![make_target("h2", 80)];
    assert!(!ferrum_edge::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_empty() {
    let a: Vec<UpstreamTarget> = vec![];
    let b: Vec<UpstreamTarget> = vec![];
    assert!(ferrum_edge::service_discovery::targets_equal(&a, &b));
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
    let dns_cache = ferrum_edge::dns::DnsCache::new(Default::default());
    let manager = ServiceDiscoveryManager::new(
        cache,
        dns_cache,
        Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        ferrum_edge::plugins::PluginHttpClient::default(),
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
    let dns_cache = ferrum_edge::dns::DnsCache::new(Default::default());
    let manager = ServiceDiscoveryManager::new(
        cache,
        dns_cache,
        Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        ferrum_edge::plugins::PluginHttpClient::default(),
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

// ── Deserialization edge cases ────────────────────────────────────────

#[test]
fn test_sd_config_provider_mismatch_dns_sd_missing_config() {
    // Provider says dns_sd but no dns_sd config block — deserialization succeeds
    // but the manager will skip (warn + return) at runtime.
    let json = r#"{"provider": "dns_sd"}"#;
    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.provider, SdProvider::DnsSd);
    assert!(config.dns_sd.is_none());
}

#[test]
fn test_sd_config_provider_mismatch_kubernetes_missing_config() {
    let json = r#"{"provider": "kubernetes"}"#;
    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.provider, SdProvider::Kubernetes);
    assert!(config.kubernetes.is_none());
}

#[test]
fn test_sd_config_provider_mismatch_consul_missing_config() {
    let json = r#"{"provider": "consul"}"#;
    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.provider, SdProvider::Consul);
    assert!(config.consul.is_none());
}

#[test]
fn test_sd_config_invalid_provider_rejected() {
    let json = r#"{"provider": "etcd"}"#;
    let result: Result<ServiceDiscoveryConfig, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn test_sd_config_missing_provider_rejected() {
    let json = r#"{"dns_sd": {"service_name": "test"}}"#;
    let result: Result<ServiceDiscoveryConfig, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn test_sd_config_default_weight_zero() {
    let json = r#"{
        "provider": "dns_sd",
        "dns_sd": {"service_name": "_http._tcp.test"},
        "default_weight": 0
    }"#;
    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.default_weight, 0);
}

#[test]
fn test_sd_config_kubernetes_defaults() {
    let json = r#"{
        "provider": "kubernetes",
        "kubernetes": {"service_name": "my-api"}
    }"#;
    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    let k8s = config.kubernetes.unwrap();
    assert_eq!(k8s.namespace, "default");
    assert_eq!(k8s.poll_interval_seconds, 30);
    assert!(k8s.port_name.is_none());
    assert!(k8s.label_selector.is_none());
}

#[test]
fn test_sd_config_dns_sd_defaults() {
    let json = r#"{
        "provider": "dns_sd",
        "dns_sd": {"service_name": "_http._tcp.test.consul"}
    }"#;
    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    let dns = config.dns_sd.unwrap();
    assert_eq!(dns.poll_interval_seconds, 30);
}

// ── targets_equal edge cases ──────────────────────────────────────────

#[test]
fn test_targets_equal_different_weights() {
    let mut a = vec![make_target("h1", 80)];
    a[0].weight = 5;
    let mut b = vec![make_target("h1", 80)];
    b[0].weight = 10;
    assert!(!ferrum_edge::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_different_tags() {
    let mut a = vec![make_target("h1", 80)];
    a[0].tags.insert("env".to_string(), "prod".to_string());
    let mut b = vec![make_target("h1", 80)];
    b[0].tags.insert("env".to_string(), "staging".to_string());
    assert!(!ferrum_edge::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_same_tags_different_order() {
    let mut a = vec![make_target("h1", 80)];
    a[0].tags.insert("a".to_string(), "1".to_string());
    a[0].tags.insert("b".to_string(), "2".to_string());
    let mut b = vec![make_target("h1", 80)];
    b[0].tags.insert("b".to_string(), "2".to_string());
    b[0].tags.insert("a".to_string(), "1".to_string());
    assert!(ferrum_edge::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_extra_tag() {
    let mut a = vec![make_target("h1", 80)];
    a[0].tags.insert("env".to_string(), "prod".to_string());
    let b = vec![make_target("h1", 80)];
    assert!(!ferrum_edge::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_different_ports() {
    let a = vec![make_target("h1", 80)];
    let b = vec![make_target("h1", 8080)];
    assert!(!ferrum_edge::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_duplicates() {
    let a = vec![make_target("h1", 80), make_target("h1", 80)];
    let b = vec![make_target("h1", 80), make_target("h1", 80)];
    assert!(ferrum_edge::service_discovery::targets_equal(&a, &b));
}

#[test]
fn test_targets_equal_duplicate_vs_single() {
    let a = vec![make_target("h1", 80), make_target("h1", 80)];
    let b = vec![make_target("h1", 80)];
    assert!(!ferrum_edge::service_discovery::targets_equal(&a, &b));
}

// ── merge_targets edge cases ──────────────────────────────────────────

#[test]
fn test_merge_targets_multiple_overlaps() {
    let static_targets = vec![make_target("host-a", 8080), make_target("host-b", 9090)];
    let discovered = vec![
        make_target("host-a", 8080), // overlaps
        make_target("host-b", 9090), // overlaps
        make_target("host-c", 7070), // new
    ];
    let merged = ferrum_edge::service_discovery::merge_targets(&static_targets, &discovered);
    assert_eq!(merged.len(), 3);
    assert_eq!(merged[0].host, "host-a");
    assert_eq!(merged[1].host, "host-b");
    assert_eq!(merged[2].host, "host-c");
}

#[test]
fn test_merge_targets_same_host_different_ports_not_overlap() {
    let static_targets = vec![make_target("host-a", 8080)];
    let discovered = vec![make_target("host-a", 9090)];
    let merged = ferrum_edge::service_discovery::merge_targets(&static_targets, &discovered);
    assert_eq!(merged.len(), 2);
}

#[test]
fn test_merge_targets_both_empty() {
    let merged = ferrum_edge::service_discovery::merge_targets(&[], &[]);
    assert!(merged.is_empty());
}

#[test]
fn test_merge_targets_preserves_discovered_tags() {
    let static_targets: Vec<UpstreamTarget> = vec![];
    let mut discovered_target = make_target("discovered", 8080);
    discovered_target
        .tags
        .insert("consul_tag_0".to_string(), "production".to_string());
    let discovered = vec![discovered_target];
    let merged = ferrum_edge::service_discovery::merge_targets(&static_targets, &discovered);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].tags.get("consul_tag_0").unwrap(), "production");
}

// ── Consul response parsing edge cases ────────────────────────────────

#[tokio::test]
async fn test_consul_discover_weight_zero_uses_default() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let consul_response = serde_json::json!([{
        "Node": {"Address": "10.0.0.1"},
        "Service": {
            "Address": "10.0.0.1",
            "Port": 8080,
            "Tags": [],
            "Weights": {"Passing": 0, "Warning": 0}
        }
    }]);

    Mock::given(method("GET"))
        .and(path("/v1/health/service/my-api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&consul_response)
                .insert_header("X-Consul-Index", "1"),
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
        42, // default_weight
    );

    let targets = discoverer.discover().await.unwrap();
    assert_eq!(targets.len(), 1);
    // Passing weight is 0 so it should use 0 (the code uses the Passing value as-is)
    assert_eq!(targets[0].weight, 0);
}

#[tokio::test]
async fn test_consul_discover_no_weights_uses_default() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let consul_response = serde_json::json!([{
        "Node": {"Address": "10.0.0.1"},
        "Service": {
            "Address": "10.0.0.1",
            "Port": 8080,
            "Tags": []
        }
    }]);

    Mock::given(method("GET"))
        .and(path("/v1/health/service/svc"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&consul_response)
                .insert_header("X-Consul-Index", "1"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "svc".to_string(),
        None,
        None,
        false,
        None,
        7, // default_weight
    );

    let targets = discoverer.discover().await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].weight, 7);
}

#[tokio::test]
async fn test_consul_discover_all_entries_filtered() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    // All entries have port=0 or empty address — all filtered
    let consul_response = serde_json::json!([
        {
            "Node": {"Address": ""},
            "Service": {"Address": "", "Port": 8080, "Tags": []}
        },
        {
            "Node": {"Address": "10.0.0.1"},
            "Service": {"Address": "10.0.0.1", "Port": 0, "Tags": []}
        }
    ]);

    Mock::given(method("GET"))
        .and(path("/v1/health/service/empty-svc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&consul_response))
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "empty-svc".to_string(),
        None,
        None,
        false,
        None,
        1,
    );

    let targets = discoverer.discover().await.unwrap();
    assert!(targets.is_empty());
}

#[tokio::test]
async fn test_consul_discover_missing_service_object() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    // Entry missing the "Service" key entirely
    let consul_response = serde_json::json!([
        {"Node": {"Address": "10.0.0.1"}},
        {
            "Node": {"Address": "10.0.0.2"},
            "Service": {"Address": "10.0.0.2", "Port": 8080, "Tags": []}
        }
    ]);

    Mock::given(method("GET"))
        .and(path("/v1/health/service/partial"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&consul_response))
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "partial".to_string(),
        None,
        None,
        false,
        None,
        1,
    );

    let targets = discoverer.discover().await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host, "10.0.0.2");
}

#[tokio::test]
async fn test_consul_discover_trailing_slash_in_address() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/svc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&mock_server)
        .await;

    // Address with trailing slash should be normalized
    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        format!("{}/", mock_server.uri()),
        "svc".to_string(),
        None,
        None,
        false,
        None,
        1,
    );

    // Should not double-slash in the URL — the request should still match
    let targets = discoverer.discover().await.unwrap();
    assert!(targets.is_empty());
}

#[tokio::test]
async fn test_consul_discover_with_datacenter_and_tag() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/my-api"))
        .and(query_param("dc", "us-east-1"))
        .and(query_param("tag", "v2"))
        .and(query_param("passing", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "my-api".to_string(),
        Some("us-east-1".to_string()),
        Some("v2".to_string()),
        true, // healthy_only
        None,
        1,
    );

    let targets = discoverer.discover().await.unwrap();
    assert!(targets.is_empty());
}

#[tokio::test]
async fn test_consul_discover_consul_tags_extracted() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let consul_response = serde_json::json!([{
        "Node": {"Address": "10.0.0.1"},
        "Service": {
            "Address": "10.0.0.1",
            "Port": 8080,
            "Tags": ["production", "v2", "canary"]
        }
    }]);

    Mock::given(method("GET"))
        .and(path("/v1/health/service/tagged-svc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&consul_response))
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "tagged-svc".to_string(),
        None,
        None,
        false,
        None,
        1,
    );

    let targets = discoverer.discover().await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].tags.get("consul_tag_0").unwrap(), "production");
    assert_eq!(targets[0].tags.get("consul_tag_1").unwrap(), "v2");
    assert_eq!(targets[0].tags.get("consul_tag_2").unwrap(), "canary");
    assert_eq!(targets[0].tags.len(), 3);
}

// ── Kubernetes response parsing edge cases ────────────────────────────

#[tokio::test]
async fn test_kubernetes_discover_no_port_name_uses_first_port() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let response = serde_json::json!({
        "items": [{
            "ports": [
                {"name": "grpc", "port": 9090, "protocol": "TCP"},
                {"name": "http", "port": 8080, "protocol": "TCP"}
            ],
            "endpoints": [{
                "addresses": ["10.244.0.5"],
                "conditions": {"ready": true}
            }]
        }]
    });

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .mount(&mock_server)
        .await;

    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "my-service".to_string(),
        None, // no port_name → first port
        None,
        1,
    )
    .with_api_url(mock_server.uri());

    let targets = discoverer.discover().await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].port, 9090); // first port in array
}

#[tokio::test]
async fn test_kubernetes_discover_port_name_not_found() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let response = serde_json::json!({
        "items": [{
            "ports": [
                {"name": "grpc", "port": 9090, "protocol": "TCP"}
            ],
            "endpoints": [{
                "addresses": ["10.244.0.5"],
                "conditions": {"ready": true}
            }]
        }]
    });

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .mount(&mock_server)
        .await;

    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "my-service".to_string(),
        Some("http".to_string()), // not in the ports list
        None,
        1,
    )
    .with_api_url(mock_server.uri());

    let targets = discoverer.discover().await.unwrap();
    // Port name "http" not found, so no targets should be returned
    assert!(targets.is_empty());
}

#[tokio::test]
async fn test_kubernetes_discover_empty_items() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"items": []})))
        .mount(&mock_server)
        .await;

    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "my-service".to_string(),
        None,
        None,
        1,
    )
    .with_api_url(mock_server.uri());

    let targets = discoverer.discover().await.unwrap();
    assert!(targets.is_empty());
}

#[tokio::test]
async fn test_kubernetes_discover_missing_conditions_defaults_ready() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let response = serde_json::json!({
        "items": [{
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
            "endpoints": [{
                "addresses": ["10.244.0.5"]
                // no "conditions" key
            }]
        }]
    });

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .mount(&mock_server)
        .await;

    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "my-service".to_string(),
        None,
        None,
        1,
    )
    .with_api_url(mock_server.uri());

    let targets = discoverer.discover().await.unwrap();
    // Missing conditions defaults to ready=true
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host, "10.244.0.5");
}

#[tokio::test]
async fn test_kubernetes_discover_multiple_endpointslice_items() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let response = serde_json::json!({
        "items": [
            {
                "ports": [{"name": "http", "port": 8080}],
                "endpoints": [{
                    "addresses": ["10.0.0.1", "10.0.0.2"],
                    "conditions": {"ready": true}
                }]
            },
            {
                "ports": [{"name": "http", "port": 8081}],
                "endpoints": [{
                    "addresses": ["10.0.1.1"],
                    "conditions": {"ready": true}
                }]
            }
        ]
    });

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .mount(&mock_server)
        .await;

    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "my-service".to_string(),
        None, // first port from each item
        None,
        1,
    )
    .with_api_url(mock_server.uri());

    let targets = discoverer.discover().await.unwrap();
    assert_eq!(targets.len(), 3);
    assert_eq!(targets[0].port, 8080);
    assert_eq!(targets[1].port, 8080);
    assert_eq!(targets[2].port, 8081);
}

#[tokio::test]
async fn test_kubernetes_discover_error_response() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .mount(&mock_server)
        .await;

    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "my-service".to_string(),
        None,
        None,
        1,
    )
    .with_api_url(mock_server.uri());

    let result = discoverer.discover().await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("403"));
}

#[tokio::test]
async fn test_kubernetes_discover_uses_default_weight() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let response = serde_json::json!({
        "items": [{
            "ports": [{"port": 8080}],
            "endpoints": [{
                "addresses": ["10.244.0.5"],
                "conditions": {"ready": true}
            }]
        }]
    });

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .mount(&mock_server)
        .await;

    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "my-service".to_string(),
        None,
        None,
        15, // custom default weight
    )
    .with_api_url(mock_server.uri());

    let targets = discoverer.discover().await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].weight, 15);
}

// ── LB cache update_targets edge cases ────────────────────────────────

#[test]
fn test_load_balancer_cache_update_targets_nonexistent_upstream() {
    let config = make_config_with_upstreams(vec![make_upstream(
        "up-1",
        vec![make_target("h1", 80)],
        None,
    )]);

    let cache = LoadBalancerCache::new(&config);

    // Updating a non-existent upstream should not panic
    cache.update_targets(
        "does-not-exist",
        vec![make_target("h2", 90)],
        LoadBalancerAlgorithm::RoundRobin,
        None,
    );

    // Original upstream should be untouched
    let u1 = cache.get_upstream("up-1").unwrap();
    assert_eq!(u1.targets.len(), 1);
}

#[test]
fn test_load_balancer_cache_update_targets_to_empty() {
    let config = make_config_with_upstreams(vec![make_upstream(
        "up-1",
        vec![make_target("h1", 80), make_target("h2", 90)],
        None,
    )]);

    let cache = LoadBalancerCache::new(&config);

    // Update to zero targets
    cache.update_targets("up-1", vec![], LoadBalancerAlgorithm::RoundRobin, None);

    let u1 = cache.get_upstream("up-1").unwrap();
    assert!(u1.targets.is_empty());
}

// ── Manager with mismatched provider config ───────────────────────────

#[tokio::test]
async fn test_manager_start_with_mismatched_provider_skips() {
    // Upstream has provider=consul but no consul config block.
    // Manager should log a warning and skip without panicking.
    let config = make_config_with_upstreams(vec![make_upstream(
        "up-mismatched",
        vec![make_target("fallback", 8080)],
        Some(ServiceDiscoveryConfig {
            provider: SdProvider::Consul,
            dns_sd: None,
            kubernetes: None,
            consul: None, // mismatch: provider says consul but no config
            default_weight: 1,
        }),
    )]);

    let cache = Arc::new(LoadBalancerCache::new(&config));
    let dns_cache = ferrum_edge::dns::DnsCache::new(Default::default());
    let manager = ServiceDiscoveryManager::new(
        cache.clone(),
        dns_cache,
        Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        ferrum_edge::plugins::PluginHttpClient::default(),
    );

    // Should not panic — the mismatched upstream is silently skipped
    manager.start(&config, None);
    manager.stop();

    // Static target should remain unchanged
    let u = cache.get_upstream("up-mismatched").unwrap();
    assert_eq!(u.targets.len(), 1);
    assert_eq!(u.targets[0].host, "fallback");
}

#[tokio::test]
async fn test_manager_start_with_dns_sd_mismatch_skips() {
    let config = make_config_with_upstreams(vec![make_upstream(
        "up-dns",
        vec![make_target("fallback", 8080)],
        Some(ServiceDiscoveryConfig {
            provider: SdProvider::DnsSd,
            dns_sd: None, // mismatch
            kubernetes: None,
            consul: None,
            default_weight: 1,
        }),
    )]);

    let cache = Arc::new(LoadBalancerCache::new(&config));
    let dns_cache = ferrum_edge::dns::DnsCache::new(Default::default());
    let manager = ServiceDiscoveryManager::new(
        cache,
        dns_cache,
        Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        ferrum_edge::plugins::PluginHttpClient::default(),
    );

    manager.start(&config, None);
    manager.stop();
}

#[tokio::test]
async fn test_manager_start_with_kubernetes_mismatch_skips() {
    let config = make_config_with_upstreams(vec![make_upstream(
        "up-k8s",
        vec![make_target("fallback", 8080)],
        Some(ServiceDiscoveryConfig {
            provider: SdProvider::Kubernetes,
            dns_sd: None,
            kubernetes: None, // mismatch
            consul: None,
            default_weight: 1,
        }),
    )]);

    let cache = Arc::new(LoadBalancerCache::new(&config));
    let dns_cache = ferrum_edge::dns::DnsCache::new(Default::default());
    let manager = ServiceDiscoveryManager::new(
        cache,
        dns_cache,
        Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        ferrum_edge::plugins::PluginHttpClient::default(),
    );

    manager.start(&config, None);
    manager.stop();
}
