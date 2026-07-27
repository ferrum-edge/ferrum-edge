//! Unit tests for the service discovery module.

use ferrum_edge::config::types::*;
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::modes::mesh::config::{
    AppProtocol, EastWestGateway, MeshConfig, MeshService, MultiClusterConfig, ServicePort,
    Workload, WorkloadPort, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::request_epoch::RequestEpochStore;
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
        subsets: None,
        port_overrides: std::collections::HashMap::new(),
        source_locality: None,
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

fn make_target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
    }
}

fn mesh_spiffe(raw: &str) -> SpiffeId {
    SpiffeId::new(raw.to_string()).expect("test SPIFFE ID")
}

fn mesh_workload(id: &str, service_name: &str, address: &str, port: u16) -> Workload {
    Workload {
        spiffe_id: mesh_spiffe(id),
        selector: WorkloadSelector::default(),
        service_name: service_name.to_string(),
        addresses: vec![address.to_string()],
        ports: vec![WorkloadPort {
            port,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
        namespace: default_namespace(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: None,
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    }
}

fn mesh_service(name: &str, spiffe_id: &str, port: u16) -> MeshService {
    MeshService {
        cluster_ips: Vec::new(),
        name: name.to_string(),
        namespace: default_namespace(),
        ports: vec![ServicePort {
            port,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: mesh_spiffe(spiffe_id),
        }],
        protocol_overrides: HashMap::new(),
    }
}

fn request_epoch_store(config: GatewayConfig) -> Arc<RequestEpochStore> {
    let plugin_cache = PluginCache::new(&config).expect("plugin cache");
    let consumer_index = ConsumerIndex::new(&config.consumers);
    let load_balancer_cache = LoadBalancerCache::new(&config);
    Arc::new(RequestEpochStore::from_runtime_parts(
        config,
        &plugin_cache,
        &consumer_index,
        &load_balancer_cache,
    ))
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
fn test_sd_config_deserialize_mesh() {
    let json = r#"{
        "provider": "mesh",
        "mesh": {
            "service_name": "payments",
            "namespace": "backend",
            "port": 8080,
            "poll_interval_seconds": 5
        },
        "default_weight": 9
    }"#;

    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.provider, SdProvider::Mesh);
    assert_eq!(config.default_weight, 9);
    let mesh = config.mesh.unwrap();
    assert_eq!(mesh.service_name, "payments");
    assert_eq!(mesh.namespace.as_deref(), Some("backend"));
    assert_eq!(mesh.port, Some(8080));
    assert_eq!(mesh.poll_interval_seconds, 5);
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
        mesh: None,
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
    let u1 = cache.get_upstream("ferrum", "upstream-1").unwrap();
    assert_eq!(u1.targets.len(), 2);

    // Update targets for upstream-1
    let new_targets = vec![
        make_target("host-a", 8080),
        make_target("host-b", 8080),
        make_target("host-d", 8080), // new discovered target
    ];
    cache.update_targets(
        "ferrum",
        "upstream-1",
        new_targets,
        LoadBalancerAlgorithm::RoundRobin,
        None,
    );

    // Verify updated state
    let u1 = cache.get_upstream("ferrum", "upstream-1").unwrap();
    assert_eq!(u1.targets.len(), 3);
    assert_eq!(u1.targets[2].host, "host-d");

    // Verify upstream-2 is untouched
    let u2 = cache.get_upstream("ferrum", "upstream-2").unwrap();
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
    let sel = cache.select_target("ferrum", "up", "key", None).unwrap();
    assert_eq!(sel.target.host, "old-host");

    // Update to new targets
    cache.update_targets(
        "ferrum",
        "up",
        vec![make_target("new-host", 9090)],
        LoadBalancerAlgorithm::RoundRobin,
        None,
    );

    // Select from new targets
    let sel = cache.select_target("ferrum", "up", "key", None).unwrap();
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

#[test]
fn filter_discovered_targets_keeps_valid_cross_cluster_hbone_synthetic_host() {
    let mut target = make_target("mesh-xc-hbone|west-gw.example.com|15443|10.9.0.1", 8080);
    target.service_port_policy_key = Some(8080);
    target.tags = HashMap::from([
        (
            ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG.to_string(),
            "true".to_string(),
        ),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG.to_string(),
            "true".to_string(),
        ),
        (
            ferrum_edge::proxy::hbone_pool::HBONE_DIAL_HOST_TAG.to_string(),
            "west-gw.example.com".to_string(),
        ),
        (
            ferrum_edge::proxy::hbone_pool::HBONE_AUTHORITY_HOST_TAG.to_string(),
            "10.9.0.1".to_string(),
        ),
        (
            ferrum_edge::proxy::hbone_pool::HBONE_PORT_TAG.to_string(),
            "15443".to_string(),
        ),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_EASTWEST_SNI_TAG.to_string(),
            "api.ferrum.svc.cluster.local".to_string(),
        ),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG.to_string(),
            "west.local".to_string(),
        ),
    ]);

    let filtered = ferrum_edge::service_discovery::filter_discovered_targets(
        "up-mesh",
        "mesh",
        vec![target],
        ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    );

    assert_eq!(
        filtered.len(),
        1,
        "synthetic cross-cluster HBONE targets must survive production SD filtering"
    );
    assert_eq!(
        filtered[0].host,
        "mesh-xc-hbone|west-gw.example.com|15443|10.9.0.1"
    );
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
fn test_targets_equal_different_policy_port() {
    let mut a = vec![make_target("h1", 8080)];
    a[0].service_port_policy_key = Some(80);
    let b = vec![make_target("h1", 8080)];
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
    assert_eq!(SdProvider::Mesh.as_str(), "mesh");
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
        None,
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
        None,
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
version: "1"
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
fn test_sd_config_provider_mismatch_mesh_missing_config() {
    let json = r#"{"provider": "mesh"}"#;
    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.provider, SdProvider::Mesh);
    assert!(config.mesh.is_none());
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

#[test]
fn test_sd_config_mesh_defaults() {
    let json = r#"{
        "provider": "mesh",
        "mesh": {"service_name": "payments"}
    }"#;
    let config: ServiceDiscoveryConfig = serde_json::from_str(json).unwrap();
    let mesh = config.mesh.unwrap();
    assert_eq!(mesh.service_name, "payments");
    assert!(mesh.namespace.is_none());
    assert!(mesh.port.is_none());
    assert_eq!(mesh.poll_interval_seconds, 30);
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
        "ferrum",
        "does-not-exist",
        vec![make_target("h2", 90)],
        LoadBalancerAlgorithm::RoundRobin,
        None,
    );

    // Original upstream should be untouched
    let u1 = cache.get_upstream("ferrum", "up-1").unwrap();
    assert_eq!(u1.targets.len(), 1);

    // A stale service-discovery update must not create a selectable phantom
    // balancer after the upstream has been removed from config.
    assert!(cache.get_upstream("ferrum", "does-not-exist").is_none());
    assert!(
        cache
            .select_target("ferrum", "does-not-exist", "key", None)
            .is_none()
    );
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
    cache.update_targets(
        "ferrum",
        "up-1",
        vec![],
        LoadBalancerAlgorithm::RoundRobin,
        None,
    );

    let u1 = cache.get_upstream("ferrum", "up-1").unwrap();
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
            mesh: None,
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
        None,
    );

    // Should not panic — the mismatched upstream is silently skipped
    manager.start(&config, None);
    manager.stop();

    // Static target should remain unchanged
    let u = cache.get_upstream("ferrum", "up-mismatched").unwrap();
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
            mesh: None,
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
        None,
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
            mesh: None,
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
        None,
    );

    manager.start(&config, None);
    manager.stop();
}

#[tokio::test]
async fn test_manager_start_with_mesh_missing_epoch_skips() {
    let config = make_config_with_upstreams(vec![make_upstream(
        "up-mesh",
        vec![make_target("fallback", 8080)],
        Some(ServiceDiscoveryConfig {
            provider: SdProvider::Mesh,
            dns_sd: None,
            kubernetes: None,
            consul: None,
            mesh: Some(MeshSdConfig {
                service_name: "api".to_string(),
                namespace: None,
                port: None,
                poll_interval_seconds: 30,
                topology: Default::default(),
            }),
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
        None,
    );

    manager.start(&config, None);
    manager.stop();

    let u = cache.get_upstream("ferrum", "up-mesh").unwrap();
    assert_eq!(u.targets.len(), 1);
    assert_eq!(u.targets[0].host, "fallback");
}

#[tokio::test]
async fn test_manager_mesh_discovery_populates_load_balancer() {
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let mut config = make_config_with_upstreams(vec![make_upstream(
        "up-mesh",
        Vec::new(),
        Some(ServiceDiscoveryConfig {
            provider: SdProvider::Mesh,
            dns_sd: None,
            kubernetes: None,
            consul: None,
            mesh: Some(MeshSdConfig {
                service_name: "api".to_string(),
                namespace: None,
                port: Some(8080),
                poll_interval_seconds: 30,
                topology: Default::default(),
            }),
            default_weight: 4,
        }),
    )]);
    config.mesh = Some(Box::new(MeshConfig {
        services: vec![mesh_service("api", api_id, 8080)],
        workloads: vec![mesh_workload(api_id, "api", "10.0.0.9", 8080)],
        ..MeshConfig::default()
    }));

    let cache = Arc::new(LoadBalancerCache::new(&config));
    let dns_cache = ferrum_edge::dns::DnsCache::new(Default::default());
    let manager = ServiceDiscoveryManager::new(
        cache.clone(),
        dns_cache,
        Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        ferrum_edge::plugins::PluginHttpClient::default(),
        Some(request_epoch_store(config.clone())),
    );

    manager.start(&config, None);

    let mut discovered = Vec::new();
    for _ in 0..50 {
        discovered = cache
            .get_upstream("ferrum", "up-mesh")
            .map(|upstream| upstream.targets.clone())
            .unwrap_or_default();
        if !discovered.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    manager.stop();

    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].host, "10.0.0.9");
    assert_eq!(discovered[0].port, 8080);
    assert_eq!(discovered[0].weight, 4);
    assert_eq!(
        discovered[0].tags.get("mesh.spiffe_id").map(String::as_str),
        Some(api_id)
    );
}

// ── Mesh SD destination-topology transport tags (gateway-to-mesh bridge) ──
//
// Mesh transports are per-topology: Sidecar peers serve SVID-mTLS HTTP/2 on
// :15006 (no HBONE listener), Ambient peers serve HBONE on :15008. The
// discoverer must stamp the transport the configured destination topology
// actually serves, plus — for Sidecar — the `:authority` routing metadata the
// peer's materialized inbound routes match on.

fn mesh_sd_discoverer(
    mesh: MeshConfig,
    port: Option<u16>,
    topology: MeshSdTopology,
) -> ferrum_edge::service_discovery::mesh::MeshServiceDiscoverer {
    let config = GatewayConfig {
        version: "1".to_string(),
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    ferrum_edge::service_discovery::mesh::MeshServiceDiscoverer::new(
        request_epoch_store(config),
        "api".to_string(),
        default_namespace(),
        port,
        1,
        topology,
    )
}

fn mesh_service_with_ports(spiffe_id: &str, ports: Vec<ServicePort>) -> MeshService {
    MeshService {
        cluster_ips: Vec::new(),
        name: "api".to_string(),
        namespace: default_namespace(),
        ports,
        workloads: vec![WorkloadRef {
            spiffe_id: mesh_spiffe(spiffe_id),
        }],
        protocol_overrides: HashMap::new(),
    }
}

fn http_service_port(port: u16, name: &str) -> ServicePort {
    ServicePort {
        port,
        protocol: AppProtocol::Http,
        name: Some(name.to_string()),
        target_port: None,
    }
}

fn mesh_workload_with_ports(spiffe_id: &str, address: &str, ports: Vec<u16>) -> Workload {
    let mut workload = mesh_workload(spiffe_id, "api", address, 0);
    workload.ports = ports
        .into_iter()
        .map(|port| WorkloadPort {
            port,
            protocol: AppProtocol::Http,
            name: Some(format!("p{port}")),
        })
        .collect();
    workload
}

#[tokio::test]
async fn mesh_sd_sidecar_topology_emits_mtls_tags_not_hbone() {
    // A sidecar peer has NO HBONE listener — sidecar-topology discovery must
    // stamp `mesh.mtls` (never `mesh.hbone`) plus the destination service
    // authority host the peer's inbound routes match; a single-HTTP-port
    // service must NOT carry the `:authority` rewrite port.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let mesh = MeshConfig {
        services: vec![mesh_service("api", api_id, 8080)],
        workloads: vec![mesh_workload(api_id, "api", "10.0.0.1", 8080)],
        ..MeshConfig::default()
    };

    let targets = mesh_sd_discoverer(mesh, None, MeshSdTopology::Sidecar)
        .discover()
        .await
        .expect("discover succeeds");

    assert_eq!(targets.len(), 1);
    let tags = &targets[0].tags;
    assert_eq!(tags.get("mesh.mtls").map(String::as_str), Some("true"));
    assert!(
        !tags.contains_key("mesh.hbone"),
        "a sidecar destination must never carry the HBONE transport tag"
    );
    assert_eq!(
        tags.get("mesh.spiffe_id").map(String::as_str),
        Some(api_id),
        "peer identity pinning metadata must be preserved on the mTLS transport"
    );
    assert_eq!(
        tags.get(ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_AUTHORITY_HOST_TAG)
            .map(String::as_str),
        Some("api.ferrum.svc"),
        "sidecar SD targets carry the destination service authority host — the \
         gateway's client Host is not a mesh service host the peer routes"
    );
    assert!(
        !tags.contains_key(ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_AUTHORITY_PORT_TAG),
        "single-port services must not stamp the :authority rewrite port"
    );
}

#[tokio::test]
async fn mesh_sd_sidecar_topology_multi_port_service_stamps_authority_port() {
    // A multi-HTTP-port sidecar destination disambiguates its per-port inbound
    // siblings by the request `:authority` port, so each discovered target
    // must carry the owning SERVICE port — mirroring the mesh-mode
    // materializer's contract.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let mesh = MeshConfig {
        services: vec![mesh_service_with_ports(
            api_id,
            vec![
                http_service_port(80, "http"),
                http_service_port(81, "admin"),
            ],
        )],
        workloads: vec![mesh_workload_with_ports(api_id, "10.0.0.1", vec![80, 81])],
        ..MeshConfig::default()
    };

    let targets = mesh_sd_discoverer(mesh, Some(81), MeshSdTopology::Sidecar)
        .discover()
        .await
        .expect("discover succeeds");

    assert_eq!(targets.len(), 1);
    let tags = &targets[0].tags;
    assert_eq!(
        tags.get(ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_AUTHORITY_PORT_TAG)
            .map(String::as_str),
        Some("81"),
        "multi-port sidecar destinations carry the owning service port for :authority rewrite"
    );
    assert_eq!(
        tags.get(ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_AUTHORITY_HOST_TAG)
            .map(String::as_str),
        Some("api.ferrum.svc")
    );
    assert_eq!(tags.get("mesh.mtls").map(String::as_str), Some("true"));
}

#[tokio::test]
async fn mesh_sd_sidecar_topology_counts_http_ports_via_protocol_overrides() {
    // `protocol_overrides` can promote a raw-protocol declared port to
    // HTTP-family. The multi-port trigger must count EFFECTIVE protocols (the
    // shared `service_http_family_ports` predicate the materializer uses), so
    // an override-promoted second HTTP port still stamps the authority port.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let mut svc = mesh_service_with_ports(
        api_id,
        vec![
            http_service_port(80, "http"),
            ServicePort {
                port: 81,
                protocol: AppProtocol::Tcp,
                name: Some("admin".to_string()),
                target_port: None,
            },
        ],
    );
    svc.protocol_overrides.insert(81, AppProtocol::Http);
    let mesh = MeshConfig {
        services: vec![svc],
        workloads: vec![mesh_workload_with_ports(api_id, "10.0.0.1", vec![80, 81])],
        ..MeshConfig::default()
    };

    let targets = mesh_sd_discoverer(mesh, Some(80), MeshSdTopology::Sidecar)
        .discover()
        .await
        .expect("discover succeeds");

    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0]
            .tags
            .get(ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_AUTHORITY_PORT_TAG)
            .map(String::as_str),
        Some("80"),
        "an override-promoted second HTTP port makes the service multi-port; \
         counting raw declared protocols would silently skip the authority port"
    );
}

#[tokio::test]
async fn mesh_sd_ambient_topology_never_stamps_mtls_authority_tags() {
    // The authority host/port rewrite tags are a Sidecar mesh-mTLS contract;
    // HBONE carries the app addr:port in the CONNECT authority already.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let mesh = MeshConfig {
        services: vec![mesh_service_with_ports(
            api_id,
            vec![
                http_service_port(80, "http"),
                http_service_port(81, "admin"),
            ],
        )],
        workloads: vec![mesh_workload_with_ports(api_id, "10.0.0.1", vec![80, 81])],
        ..MeshConfig::default()
    };

    let targets = mesh_sd_discoverer(mesh, Some(81), MeshSdTopology::Ambient)
        .discover()
        .await
        .expect("discover succeeds");

    assert_eq!(targets.len(), 1);
    let tags = &targets[0].tags;
    assert_eq!(tags.get("mesh.hbone").map(String::as_str), Some("true"));
    assert!(
        !tags.contains_key(ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_AUTHORITY_PORT_TAG),
        "HBONE targets must not carry the sidecar :authority rewrite port tag"
    );
    assert!(
        !tags.contains_key(ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_AUTHORITY_HOST_TAG),
        "HBONE targets must not carry the sidecar :authority host tag"
    );
}

/// Remote-provenance workload in the `west-network` / `west.local` remote
/// cluster, ref'd by the service alongside the local workload.
fn mesh_remote_west_workload(remote_id: &str, port: u16) -> Workload {
    let mut remote = mesh_workload(remote_id, "api", "10.9.0.1", port);
    remote.remote_provenance = true;
    remote.network = Some("west-network".to_string());
    remote.trust_domain = TrustDomain::new("west.local").expect("trust domain");
    remote.locality = Some("west-region/west-zone".to_string());
    remote
}

/// `MultiClusterConfig` whose east-west gateway fronts `west-network` for the
/// `west.local` trust domain and claims the `api` service FQDN.
fn mesh_west_multi_cluster() -> MultiClusterConfig {
    MultiClusterConfig {
        east_west_gateways: vec![EastWestGateway {
            name: "west-ew".to_string(),
            namespace: "istio-system".to_string(),
            host: "west-gw.example.com".to_string(),
            port: 15443,
            sni_hosts: vec!["api.ferrum.svc.cluster.local".to_string()],
            trust_domain: Some(TrustDomain::new("west.local").expect("trust domain")),
            network: Some("west-network".to_string()),
        }],
        ..MultiClusterConfig::default()
    }
}

#[tokio::test]
async fn mesh_sd_sidecar_topology_bridges_remote_workloads_via_east_west_gateway() {
    // Sidecar remote workloads must NEVER be published as direct
    // `remote-pod:15006` dials (unreachable in a multi-network mesh). With
    // `mesh.multi_cluster` carrying a matching east-west gateway, the SD
    // bridge emits ONE gateway failover target per (network, trust_domain)
    // group — the same shape mesh-mode egress materializes via the shared
    // `append_cross_cluster_mesh_targets` core — appended after the locals.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let remote_id = "spiffe://west.local/ns/ferrum/sa/api";
    let mut svc = mesh_service("api", api_id, 8080);
    svc.workloads.push(WorkloadRef {
        spiffe_id: mesh_spiffe(remote_id),
    });
    let mesh = MeshConfig {
        services: vec![svc],
        workloads: vec![
            mesh_workload(api_id, "api", "10.0.0.1", 8080),
            mesh_remote_west_workload(remote_id, 8080),
        ],
        multi_cluster: Some(mesh_west_multi_cluster()),
        ..MeshConfig::default()
    };

    let targets = mesh_sd_discoverer(mesh, None, MeshSdTopology::Sidecar)
        .discover()
        .await
        .expect("discover succeeds");

    assert_eq!(
        targets.len(),
        2,
        "one local target plus ONE east-west gateway target (never a direct remote-pod dial)"
    );

    // Local target first (unchanged by the bridge): direct pod dial with the
    // pinned pod SPIFFE.
    assert_eq!(targets[0].host, "10.0.0.1");
    assert_eq!(targets[0].port, 8080);
    assert_eq!(
        targets[0].tags.get("mesh.spiffe_id").map(String::as_str),
        Some(api_id)
    );
    assert!(!targets[0].tags.contains_key("mesh.cross_cluster"));
    assert!(!targets[0].tags.contains_key("mesh.remote"));

    // Gateway failover target: identity = the gateway DIAL endpoint.
    let gateway = &targets[1];
    assert_eq!(gateway.host, "west-gw.example.com");
    assert_eq!(gateway.port, 15443);
    assert_eq!(
        gateway.service_port_policy_key,
        Some(8080),
        "DR policy stays keyed by the declared SERVICE port, not the gateway port"
    );
    assert_eq!(
        gateway.locality.as_deref(),
        Some("west-region/west-zone"),
        "remote-tier locality so locality-LB ranks the gateway after locals"
    );
    let tags = &gateway.tags;
    assert_eq!(
        tags.get("mesh.cross_cluster").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        tags.get("mesh.eastwest_sni").map(String::as_str),
        Some("api.ferrum.svc.cluster.local"),
        "SNI the remote east-west gateway passthrough routes on"
    );
    assert_eq!(
        tags.get("mesh.mtls_port").map(String::as_str),
        Some("15443"),
        "dial port is the east-west gateway port, not :15006"
    );
    assert_eq!(tags.get("mesh.mtls").map(String::as_str), Some("true"));
    assert_eq!(
        tags.get("mesh.remote").map(String::as_str),
        Some("true"),
        "gateway targets are remote provenance for strict local-first LB"
    );
    assert!(
        !tags.contains_key("mesh.spiffe_id"),
        "no pod pinning across the SNI-passthrough gateway (trust-domain-only verification)"
    );
    assert_eq!(
        tags.get("mesh.trust_domain").map(String::as_str),
        Some("west.local"),
        "verification is scoped to the REMOTE trust domain"
    );
    assert_eq!(
        tags.get(ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_AUTHORITY_HOST_TAG)
            .map(String::as_str),
        Some("api.ferrum.svc"),
        "SD-bridge gateway targets carry the destination service authority host — the \
         gateway's client Host is a public hostname the destination sidecar would 404"
    );
    assert!(
        !tags.contains_key(ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_AUTHORITY_PORT_TAG),
        "cross-cluster never stamps the :authority rewrite port (destination \
         disambiguates captured traffic by orig-dst)"
    );
}

#[tokio::test]
async fn mesh_sd_sidecar_bridges_service_name_matched_remote_workloads_without_refs() {
    // A MeshService with NO `workloads` refs matches workloads by
    // `workload.service_name` (the supported mesh-SD shape pinned by the
    // inline `service_without_workload_refs_matches_service_name` test). The
    // east-west bridge must honor those SAME matching semantics: a
    // remote-provenance sidecar workload matched only by service_name still
    // yields the gateway failover target. (Codex round 1: the bridge
    // previously re-matched through the materializer's ref-only matcher,
    // which sees an empty ref list and silently bridged nothing.)
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let remote_id = "spiffe://west.local/ns/ferrum/sa/api";
    let mut svc = mesh_service("api", api_id, 8080);
    svc.workloads.clear(); // no refs — service_name fallback matching only
    let mesh = MeshConfig {
        services: vec![svc],
        workloads: vec![
            mesh_workload(api_id, "api", "10.0.0.1", 8080),
            mesh_remote_west_workload(remote_id, 8080),
        ],
        multi_cluster: Some(mesh_west_multi_cluster()),
        ..MeshConfig::default()
    };

    let targets = mesh_sd_discoverer(mesh, None, MeshSdTopology::Sidecar)
        .discover()
        .await
        .expect("discover succeeds");

    assert_eq!(
        targets.len(),
        2,
        "service_name-matched shape bridges like the ref'd shape: one local \
         target plus ONE east-west gateway target"
    );

    // Local half of the no-refs shape is unchanged by the bridge.
    assert_eq!(targets[0].host, "10.0.0.1");
    assert_eq!(targets[0].port, 8080);
    assert!(!targets[0].tags.contains_key("mesh.cross_cluster"));
    assert!(!targets[0].tags.contains_key("mesh.remote"));

    // Gateway failover target — same shape the ref-based bridge test pins.
    let gateway = &targets[1];
    assert_eq!(gateway.host, "west-gw.example.com");
    assert_eq!(gateway.port, 15443);
    assert_eq!(gateway.service_port_policy_key, Some(8080));
    let tags = &gateway.tags;
    assert_eq!(
        tags.get("mesh.cross_cluster").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        tags.get("mesh.eastwest_sni").map(String::as_str),
        Some("api.ferrum.svc.cluster.local")
    );
    assert_eq!(
        tags.get("mesh.mtls_port").map(String::as_str),
        Some("15443")
    );
    assert_eq!(tags.get("mesh.mtls").map(String::as_str), Some("true"));
    assert_eq!(tags.get("mesh.remote").map(String::as_str), Some("true"));
    assert!(
        !tags.contains_key("mesh.spiffe_id"),
        "no pod pinning across the SNI-passthrough gateway"
    );
    assert_eq!(
        tags.get("mesh.trust_domain").map(String::as_str),
        Some("west.local")
    );
    assert_eq!(
        tags.get(ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_AUTHORITY_HOST_TAG)
            .map(String::as_str),
        Some("api.ferrum.svc")
    );
}

#[tokio::test]
async fn mesh_sd_sidecar_remote_workloads_without_matching_gateway_skip_fail_closed() {
    // A remote group whose network has no east-west gateway (and no catch-all)
    // must be skipped fail-closed by the shared core: never a direct
    // remote-pod dial, never a dial to an unresolved gateway address.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let remote_id = "spiffe://west.local/ns/ferrum/sa/api";
    let mut svc = mesh_service("api", api_id, 8080);
    svc.workloads.push(WorkloadRef {
        spiffe_id: mesh_spiffe(remote_id),
    });
    let mut multi_cluster = mesh_west_multi_cluster();
    // The only gateway fronts a DIFFERENT network; per the shared core's
    // fail-closed selection there is no catch-all fall-through.
    multi_cluster.east_west_gateways[0].network = Some("east-network".to_string());
    let mesh = MeshConfig {
        services: vec![svc],
        workloads: vec![
            mesh_workload(api_id, "api", "10.0.0.1", 8080),
            mesh_remote_west_workload(remote_id, 8080),
        ],
        multi_cluster: Some(multi_cluster),
        ..MeshConfig::default()
    };

    let targets = mesh_sd_discoverer(mesh, None, MeshSdTopology::Sidecar)
        .discover()
        .await
        .expect("discover succeeds");

    assert_eq!(
        targets.len(),
        1,
        "no gateway target without a matching east-west gateway (fail closed)"
    );
    assert_eq!(targets[0].host, "10.0.0.1");
}

#[tokio::test]
async fn mesh_sd_sidecar_remote_workloads_on_non_first_port_bridge_with_alias() {
    // MULTI-PORT east-west (issue #2010 phase 3): the SD bridge now bridges a
    // NON-first HTTP-family selected port too. The destination gateway
    // auto-materializes a per-port passthrough proxy on the `p<port>.<fqdn>` SNI
    // alias, so a remote workload selected on port 81 is bridged with
    // `mesh.eastwest_sni = p81.api.ferrum.svc.cluster.local`.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let remote_id = "spiffe://west.local/ns/ferrum/sa/api";
    let mut svc = mesh_service_with_ports(
        api_id,
        vec![
            http_service_port(80, "http"),
            http_service_port(81, "admin"),
        ],
    );
    svc.workloads.push(WorkloadRef {
        spiffe_id: mesh_spiffe(remote_id),
    });
    let mut remote = mesh_remote_west_workload(remote_id, 80);
    remote.ports = vec![
        WorkloadPort {
            port: 80,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        },
        WorkloadPort {
            port: 81,
            protocol: AppProtocol::Http,
            name: Some("admin".to_string()),
        },
    ];
    let mut multi_cluster = mesh_west_multi_cluster();
    multi_cluster.east_west_gateways[0].sni_hosts.clear(); // wildcard gateway
    let mesh = MeshConfig {
        services: vec![svc],
        workloads: vec![
            mesh_workload_with_ports(api_id, "10.0.0.1", vec![80, 81]),
            remote,
        ],
        multi_cluster: Some(multi_cluster),
        ..MeshConfig::default()
    };

    let targets = mesh_sd_discoverer(mesh, Some(81), MeshSdTopology::Sidecar)
        .discover()
        .await
        .expect("discover succeeds");

    // Local target (10.0.0.1:81) + one east-west gateway target for the remote.
    assert_eq!(
        targets.len(),
        2,
        "a non-first HTTP port now bridges the remote workload east-west, got {:?}",
        targets
            .iter()
            .map(|t| (&t.host, t.port))
            .collect::<Vec<_>>()
    );
    let cross = targets
        .iter()
        .find(|t| t.tags.contains_key("mesh.cross_cluster"))
        .expect("a cross-cluster gateway target must be emitted for the non-first port");
    assert_eq!(
        cross.tags.get("mesh.eastwest_sni").map(String::as_str),
        Some("p81.api.ferrum.svc.cluster.local"),
        "the non-first port routes on the p<port> SNI alias"
    );
    assert!(
        targets.iter().any(|t| t.host == "10.0.0.1" && t.port == 81),
        "the local workload target is still present"
    );
}

#[tokio::test]
async fn mesh_sd_ambient_topology_keeps_direct_remote_fallback_without_gateway() {
    // Flat-network compatibility for Ambient SD: when no east-west gateway is
    // declared, remote workloads stay discoverable as direct pod-IP HBONE
    // targets, marked with `mesh.remote` so strict local-first LB can key on
    // provenance.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let remote_id = "spiffe://cluster.local/ns/ferrum/sa/api-remote";
    let mut remote = mesh_workload(remote_id, "api", "10.9.0.1", 8080);
    remote.remote_provenance = true;
    let mut svc = mesh_service("api", api_id, 8080);
    svc.workloads.push(WorkloadRef {
        spiffe_id: mesh_spiffe(remote_id),
    });
    let mesh = MeshConfig {
        services: vec![svc],
        workloads: vec![mesh_workload(api_id, "api", "10.0.0.1", 8080), remote],
        ..MeshConfig::default()
    };

    let mut targets = mesh_sd_discoverer(mesh, None, MeshSdTopology::Ambient)
        .discover()
        .await
        .expect("discover succeeds");
    targets.sort_by(|a, b| a.host.cmp(&b.host));

    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].host, "10.0.0.1");
    assert!(!targets[0].tags.contains_key("mesh.remote"));
    assert_eq!(targets[1].host, "10.9.0.1");
    assert_eq!(
        targets[1].tags.get("mesh.remote").map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn mesh_sd_ambient_keeps_direct_remote_fallback_when_catch_all_gateway_cannot_route() {
    // A network catch-all gateway only suppresses direct remote fallback when it
    // is an actual candidate for this service/trust-domain. A catch-all that
    // claims a different SNI would be rejected by the shared selector, so
    // retaining direct fallback preserves the flat-network compatibility valve.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let remote_id = "spiffe://west.local/ns/ferrum/sa/api";
    let mut svc = mesh_service("api", api_id, 8080);
    svc.workloads.push(WorkloadRef {
        spiffe_id: mesh_spiffe(remote_id),
    });
    let mut multi_cluster = mesh_west_multi_cluster();
    multi_cluster.east_west_gateways[0].network = None;
    multi_cluster.east_west_gateways[0].sni_hosts =
        vec!["other.ferrum.svc.cluster.local".to_string()];
    let mesh = MeshConfig {
        services: vec![svc],
        workloads: vec![
            mesh_workload(api_id, "api", "10.0.0.1", 8080),
            mesh_remote_west_workload(remote_id, 8080),
        ],
        multi_cluster: Some(multi_cluster),
        ..MeshConfig::default()
    };

    let mut targets = mesh_sd_discoverer(mesh, None, MeshSdTopology::Ambient)
        .discover()
        .await
        .expect("discover succeeds");
    targets.sort_by(|a, b| a.host.cmp(&b.host));

    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].host, "10.0.0.1");
    assert!(!targets[0].tags.contains_key("mesh.remote"));
    assert_eq!(targets[1].host, "10.9.0.1");
    assert_eq!(
        targets[1].tags.get("mesh.remote").map(String::as_str),
        Some("true")
    );
    assert!(
        !targets[1].tags.contains_key("mesh.cross_cluster"),
        "non-candidate catch-all must not force the gateway-routed shape"
    );
}

#[tokio::test]
async fn mesh_sd_ambient_keeps_unknown_network_direct_fallback_when_catch_all_cannot_route() {
    // `network: None` east-west gateways are catch-alls, not exact declarations
    // for workloads missing a network label. If the catch-all is not a candidate
    // for this service/trust-domain, it must not suppress the flat-network
    // direct fallback for an unknown-network remote workload.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let remote_id = "spiffe://west.local/ns/ferrum/sa/api";
    let mut svc = mesh_service("api", api_id, 8080);
    svc.workloads.push(WorkloadRef {
        spiffe_id: mesh_spiffe(remote_id),
    });
    let mut remote = mesh_remote_west_workload(remote_id, 8080);
    remote.network = None;
    let mut multi_cluster = mesh_west_multi_cluster();
    multi_cluster.east_west_gateways[0].network = None;
    multi_cluster.east_west_gateways[0].sni_hosts =
        vec!["other.ferrum.svc.cluster.local".to_string()];
    let mesh = MeshConfig {
        services: vec![svc],
        workloads: vec![mesh_workload(api_id, "api", "10.0.0.1", 8080), remote],
        multi_cluster: Some(multi_cluster),
        ..MeshConfig::default()
    };

    let mut targets = mesh_sd_discoverer(mesh, None, MeshSdTopology::Ambient)
        .discover()
        .await
        .expect("discover succeeds");
    targets.sort_by(|a, b| a.host.cmp(&b.host));

    assert_eq!(
        targets.len(),
        2,
        "non-candidate catch-all gateway must not suppress unknown-network direct fallback"
    );
    assert_eq!(targets[0].host, "10.0.0.1");
    assert!(!targets[0].tags.contains_key("mesh.remote"));
    assert_eq!(targets[1].host, "10.9.0.1");
    assert_eq!(
        targets[1].tags.get("mesh.remote").map(String::as_str),
        Some("true")
    );
    assert!(
        !targets[1].tags.contains_key("mesh.cross_cluster"),
        "unknown-network direct fallback must not be rewritten into a non-candidate gateway target"
    );
}

#[tokio::test]
async fn mesh_sd_ambient_exact_network_gateway_without_candidate_skips_remote_fail_closed() {
    // An exact-network gateway declaration is authoritative for that remote
    // network. If it cannot route this service/trust-domain, Ambient SD must
    // fail closed rather than re-enable the direct pod-IP compatibility path.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let remote_id = "spiffe://west.local/ns/ferrum/sa/api";
    let mut svc = mesh_service("api", api_id, 8080);
    svc.workloads.push(WorkloadRef {
        spiffe_id: mesh_spiffe(remote_id),
    });
    let mut multi_cluster = mesh_west_multi_cluster();
    multi_cluster.east_west_gateways[0].sni_hosts =
        vec!["other.ferrum.svc.cluster.local".to_string()];
    let mesh = MeshConfig {
        services: vec![svc],
        workloads: vec![
            mesh_workload(api_id, "api", "10.0.0.1", 8080),
            mesh_remote_west_workload(remote_id, 8080),
        ],
        multi_cluster: Some(multi_cluster),
        ..MeshConfig::default()
    };

    let targets = mesh_sd_discoverer(mesh, None, MeshSdTopology::Ambient)
        .discover()
        .await
        .expect("discover succeeds");

    assert_eq!(
        targets.len(),
        1,
        "exact-network non-candidate gateway must suppress direct remote fallback"
    );
    assert_eq!(targets[0].host, "10.0.0.1");
    assert!(!targets[0].tags.contains_key("mesh.remote"));
    assert!(
        !targets.iter().any(|target| target.host == "10.9.0.1"),
        "remote pod IP must not be emitted when its network has a declared gateway"
    );
}

#[tokio::test]
async fn mesh_sd_ambient_topology_bridges_remote_workloads_via_east_west_gateway() {
    // When an east-west gateway is declared for the remote workload's network,
    // Ambient SD must use the mesh-mode Ambient shape: one per-pod synthetic
    // target whose dial override is the gateway, while the real pod address is
    // preserved as the inner HBONE CONNECT authority. It must not also emit the
    // old direct remote-pod target.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let remote_id = "spiffe://west.local/ns/ferrum/sa/api";
    let mut svc = mesh_service("api", api_id, 8080);
    svc.workloads.push(WorkloadRef {
        spiffe_id: mesh_spiffe(remote_id),
    });
    let mesh = MeshConfig {
        services: vec![svc],
        workloads: vec![
            mesh_workload(api_id, "api", "10.0.0.1", 8080),
            mesh_remote_west_workload(remote_id, 8080),
        ],
        multi_cluster: Some(mesh_west_multi_cluster()),
        ..MeshConfig::default()
    };

    let targets = mesh_sd_discoverer(mesh, None, MeshSdTopology::Ambient)
        .discover()
        .await
        .expect("discover succeeds");

    assert_eq!(
        targets.len(),
        2,
        "one local target plus one gateway-routed Ambient target"
    );

    assert_eq!(targets[0].host, "10.0.0.1");
    assert_eq!(targets[0].port, 8080);
    assert_eq!(
        targets[0].tags.get("mesh.spiffe_id").map(String::as_str),
        Some(api_id)
    );
    assert!(!targets[0].tags.contains_key("mesh.cross_cluster"));
    assert!(!targets[0].tags.contains_key("mesh.remote"));

    let gateway = &targets[1];
    assert_ne!(
        gateway.host, "10.9.0.1",
        "remote pod IP must not be emitted as the dial identity when a gateway exists"
    );
    assert!(
        gateway.host.contains("west-gw.example.com") && gateway.host.contains("10.9.0.1"),
        "Ambient gateway target identity scopes the real pod by gateway endpoint, got {:?}",
        gateway.host
    );
    assert_eq!(gateway.port, 8080, "target port remains the app port");
    assert_eq!(gateway.service_port_policy_key, Some(8080));
    assert_eq!(
        gateway.locality.as_deref(),
        Some("west-region/west-zone"),
        "remote-tier locality is preserved"
    );

    let tags = &gateway.tags;
    assert_eq!(tags.get("mesh.hbone").map(String::as_str), Some("true"));
    assert_eq!(
        tags.get("mesh.hbone_dial_host").map(String::as_str),
        Some("west-gw.example.com"),
        "dispatch dials the east-west gateway"
    );
    assert_eq!(
        tags.get("mesh.hbone_port").map(String::as_str),
        Some("15443"),
        "dial port is the east-west gateway port"
    );
    assert_eq!(
        tags.get("mesh.hbone_authority_host").map(String::as_str),
        Some("10.9.0.1"),
        "inner CONNECT authority keeps the real pod address"
    );
    assert_eq!(
        tags.get("mesh.eastwest_sni").map(String::as_str),
        Some("api.ferrum.svc.cluster.local")
    );
    assert_eq!(
        tags.get("mesh.cross_cluster").map(String::as_str),
        Some("true")
    );
    assert_eq!(tags.get("mesh.remote").map(String::as_str), Some("true"));
    assert_eq!(
        tags.get("mesh.trust_domain").map(String::as_str),
        Some("west.local")
    );
    assert!(
        !tags.contains_key("mesh.spiffe_id"),
        "gateway-routed Ambient targets verify by remote trust domain, not a pinned pod SVID"
    );
}

#[tokio::test]
async fn mesh_sd_ambient_mixed_networks_bridge_gatewayed_and_keep_gatewayless_direct() {
    // The exact mixed-network scenario from issue #2011, in ONE snapshot: a
    // gateway is declared for network A (west) while network B (east) has no
    // gateway and no catch-all applies. The west workload must bridge through
    // its east-west gateway (synthetic identity + dial override) while the
    // east workload keeps the direct pod-IP flat-network fallback — gateway
    // authority is judged PER WORKLOAD NETWORK, never snapshot-wide.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let west_id = "spiffe://west.local/ns/ferrum/sa/api";
    let east_id = "spiffe://east.local/ns/ferrum/sa/api";
    let mut svc = mesh_service("api", api_id, 8080);
    svc.workloads.push(WorkloadRef {
        spiffe_id: mesh_spiffe(west_id),
    });
    svc.workloads.push(WorkloadRef {
        spiffe_id: mesh_spiffe(east_id),
    });
    let mut east_remote = mesh_workload(east_id, "api", "10.8.0.1", 8080);
    east_remote.remote_provenance = true;
    east_remote.network = Some("east-network".to_string());
    east_remote.trust_domain = TrustDomain::new("east.local").expect("trust domain");
    let mesh = MeshConfig {
        services: vec![svc],
        workloads: vec![
            mesh_workload(api_id, "api", "10.0.0.1", 8080),
            mesh_remote_west_workload(west_id, 8080),
            east_remote,
        ],
        // Gateway declared for west-network ONLY: no east-network entry and no
        // catch-all, so east keeps the flat-network compatibility valve.
        multi_cluster: Some(mesh_west_multi_cluster()),
        ..MeshConfig::default()
    };

    let mut targets = mesh_sd_discoverer(mesh, None, MeshSdTopology::Ambient)
        .discover()
        .await
        .expect("discover succeeds");
    targets.sort_by(|a, b| a.host.cmp(&b.host));

    assert_eq!(
        targets.len(),
        3,
        "one local target, one direct east fallback, one west gateway bridge"
    );

    // Local workload is unchanged.
    assert_eq!(targets[0].host, "10.0.0.1");
    assert!(!targets[0].tags.contains_key("mesh.remote"));
    assert!(!targets[0].tags.contains_key("mesh.cross_cluster"));

    // Gatewayless east-network workload keeps the direct pod-IP HBONE target.
    let east = &targets[1];
    assert_eq!(east.host, "10.8.0.1");
    assert_eq!(
        east.tags.get("mesh.remote").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        east.tags.get("mesh.hbone").map(String::as_str),
        Some("true")
    );
    assert!(
        !east.tags.contains_key("mesh.cross_cluster"),
        "no gateway is declared for east-network: the direct fallback must not \
         be forced into the gateway-routed shape"
    );
    assert!(
        !east.tags.contains_key("mesh.hbone_dial_host"),
        "the direct fallback dials the pod address itself, never a gateway"
    );

    // West-network workload bridges through its declared east-west gateway.
    let west = &targets[2];
    assert!(
        west.host.contains("west-gw.example.com") && west.host.contains("10.9.0.1"),
        "west target must carry the gateway-scoped synthetic identity, got {:?}",
        west.host
    );
    assert_eq!(
        west.tags.get("mesh.hbone_dial_host").map(String::as_str),
        Some("west-gw.example.com")
    );
    assert_eq!(
        west.tags
            .get("mesh.hbone_authority_host")
            .map(String::as_str),
        Some("10.9.0.1")
    );
    assert_eq!(
        west.tags.get("mesh.cross_cluster").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        west.tags.get("mesh.remote").map(String::as_str),
        Some("true")
    );
    assert!(
        !targets.iter().any(|target| target.host == "10.9.0.1"),
        "the gateway-declared west workload must not also emit a direct pod-IP target"
    );
}

#[tokio::test]
async fn mesh_sd_ambient_gateway_declared_non_first_port_bridges_with_alias() {
    // MULTI-PORT east-west (issue #2010 phase 3): a gateway-declared Ambient
    // remote workload selected on a NON-first HTTP-family port is now bridged to a
    // per-pod HBONE east-west target on the `p<port>.<fqdn>` SNI alias — NOT a
    // direct remote pod dial.
    let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
    let remote_id = "spiffe://west.local/ns/ferrum/sa/api";
    let mut svc = mesh_service_with_ports(
        api_id,
        vec![
            http_service_port(80, "http"),
            http_service_port(81, "admin"),
        ],
    );
    svc.workloads.push(WorkloadRef {
        spiffe_id: mesh_spiffe(remote_id),
    });
    let mut remote = mesh_remote_west_workload(remote_id, 80);
    remote.ports = vec![
        WorkloadPort {
            port: 80,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        },
        WorkloadPort {
            port: 81,
            protocol: AppProtocol::Http,
            name: Some("admin".to_string()),
        },
    ];
    let mut multi_cluster = mesh_west_multi_cluster();
    multi_cluster.east_west_gateways[0].sni_hosts.clear(); // wildcard gateway
    let mesh = MeshConfig {
        services: vec![svc],
        workloads: vec![
            mesh_workload_with_ports(api_id, "10.0.0.1", vec![80, 81]),
            remote,
        ],
        multi_cluster: Some(multi_cluster),
        ..MeshConfig::default()
    };

    let targets = mesh_sd_discoverer(mesh, Some(81), MeshSdTopology::Ambient)
        .discover()
        .await
        .expect("discover succeeds");

    // Local target (10.0.0.1:81) + one per-pod east-west HBONE target (synthetic
    // host) for the remote, on the p81 alias.
    assert_eq!(
        targets.len(),
        2,
        "a non-first HTTP port now bridges the remote workload east-west, got {:?}",
        targets
            .iter()
            .map(|t| (&t.host, t.port))
            .collect::<Vec<_>>()
    );
    let cross = targets
        .iter()
        .find(|t| t.tags.contains_key("mesh.cross_cluster"))
        .expect("a per-pod cross-cluster HBONE target must be emitted for the non-first port");
    assert_eq!(
        cross.tags.get("mesh.eastwest_sni").map(String::as_str),
        Some("p81.api.ferrum.svc.cluster.local"),
        "the non-first port routes on the p<port> SNI alias"
    );
    assert_eq!(
        cross.tags.get("mesh.remote").map(String::as_str),
        Some("true")
    );
    assert!(
        !targets.iter().any(|t| t.host == "10.9.0.1"),
        "the remote pod must be reached via the east-west gateway, never a direct pod dial"
    );
}
