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
use ferrum_edge::service_discovery::{
    ServiceDiscoverer, ServiceDiscoveryManager, SnapshotAdmission, SnapshotAdmissionPolicy,
    admit_discovered_snapshot,
};
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
        service_namespace: None,
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
async fn test_kubernetes_discover_rejects_terminating_and_non_serving_endpoints() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let response = serde_json::json!({
        "items": [{
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
            "endpoints": [
                {
                    "addresses": ["10.244.0.1"],
                    "conditions": {"ready": true, "serving": true, "terminating": false}
                },
                {
                    "addresses": ["10.244.0.2"],
                    "conditions": {"ready": true, "serving": false}
                },
                {
                    "addresses": ["10.244.0.3"],
                    "conditions": {"ready": true, "terminating": true}
                },
                {
                    "addresses": ["10.244.0.4"],
                    "conditions": {"serving": false}
                },
                {
                    "addresses": ["10.244.0.5"],
                    "conditions": {"terminating": false}
                },
                {
                    "addresses": ["10.244.0.6"],
                    "conditions": {"ready": true, "serving": true, "terminating": true}
                },
                {
                    "addresses": ["10.244.0.7"]
                }
            ]
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
    let hosts: Vec<&str> = targets.iter().map(|t| t.host.as_str()).collect();
    assert_eq!(
        hosts,
        vec!["10.244.0.1", "10.244.0.5", "10.244.0.7"],
        "only lifecycle-eligible EndpointSlice endpoints must be published"
    );
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

    let snapshot = mesh_sd_discoverer(mesh, None, MeshSdTopology::Ambient)
        .discover()
        .await
        .expect("discover succeeds");
    let mut targets = snapshot.targets().to_vec();
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

    let snapshot = mesh_sd_discoverer(mesh, None, MeshSdTopology::Ambient)
        .discover()
        .await
        .expect("discover succeeds");
    let mut targets = snapshot.targets().to_vec();
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

    let snapshot = mesh_sd_discoverer(mesh, None, MeshSdTopology::Ambient)
        .discover()
        .await
        .expect("discover succeeds");
    let mut targets = snapshot.targets().to_vec();
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

    let snapshot = mesh_sd_discoverer(mesh, None, MeshSdTopology::Ambient)
        .discover()
        .await
        .expect("discover succeeds");
    let mut targets = snapshot.targets().to_vec();
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

// ── Consul blocking-query cursor admission (issue #3719) ──────────────
//
// These tests drive discover() through the exact production
// admit → publish → cursor-commit pipeline (`apply_service_discovery_snapshot_for_test`),
// observing LoadBalancerCache state and subsequent Consul request query params.
// They intentionally do not call a public early-commit helper.

fn consul_health_instance(host: &str, port: u16) -> serde_json::Value {
    serde_json::json!([{
        "Node": {"Address": host},
        "Service": {
            "Address": host,
            "Port": port,
            "Tags": [],
            "Weights": {"Passing": 1, "Warning": 1}
        }
    }])
}

fn consul_invalid_entries() -> serde_json::Value {
    serde_json::json!([
        {"Node": {"Address": "10.0.0.1"}},
        {
            "Node": {"Address": ""},
            "Service": {"Address": "", "Port": 0, "Tags": [], "Weights": {"Passing": 1}}
        }
    ])
}

fn consul_mixed_entries() -> serde_json::Value {
    serde_json::json!([
        {
            "Node": {"Address": ""},
            "Service": {"Address": "", "Port": 0, "Tags": [], "Weights": {"Passing": 1}}
        },
        {
            "Node": {"Address": "10.0.0.2"},
            "Service": {
                "Address": "10.0.0.2",
                "Port": 8080,
                "Tags": [],
                "Weights": {"Passing": 1, "Warning": 1}
            }
        }
    ])
}

fn cursor_index(d: &ConsulDiscoverer) -> u64 {
    ferrum_edge::_test_support::consul_blocking_query_index_for_test(d)
}

struct ConsulPipelineHarness {
    upstream_id: String,
    lb_cache: Arc<LoadBalancerCache>,
    dns_cache: ferrum_edge::dns::DnsCache,
    health_checker: Arc<ferrum_edge::health_check::HealthChecker>,
    request_epoch: Option<Arc<RequestEpochStore>>,
    static_targets: Vec<UpstreamTarget>,
    // Kept so the cancel watch sender outlives pipeline cancel checks.
    #[allow(dead_code)]
    cancel_tx: tokio::sync::watch::Sender<bool>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
    state: ferrum_edge::_test_support::DiscoveryLoopStateForTest,
}

impl ConsulPipelineHarness {
    fn new(upstream_id: &str, seed_targets: Vec<UpstreamTarget>) -> Self {
        Self::with_dns_policy(
            upstream_id,
            seed_targets,
            ferrum_edge::config::BackendEgressPolicy::unrestricted(),
            None,
        )
    }

    fn with_dns_policy(
        upstream_id: &str,
        seed_targets: Vec<UpstreamTarget>,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy,
        request_epoch: Option<Arc<RequestEpochStore>>,
    ) -> Self {
        let config = make_config_with_upstreams(vec![make_upstream(
            upstream_id,
            seed_targets.clone(),
            None,
        )]);
        let lb_cache = Arc::new(LoadBalancerCache::new(&config));
        if !seed_targets.is_empty() {
            // Simulate prior-task dynamic targets already installed in the cache.
            lb_cache.update_targets(
                "ferrum",
                upstream_id,
                seed_targets,
                LoadBalancerAlgorithm::RoundRobin,
                None,
            );
        }
        let dns_config = ferrum_edge::dns::DnsConfig {
            backend_allow_ips,
            ..Default::default()
        };
        let dns_cache = ferrum_edge::dns::DnsCache::new(dns_config);
        // Keep the cancel sender alive so `borrow()` stays meaningful for the
        // production cancel checks inside the apply pipeline.
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        Self {
            upstream_id: upstream_id.to_string(),
            lb_cache,
            dns_cache,
            health_checker: Arc::new(ferrum_edge::health_check::HealthChecker::new()),
            request_epoch,
            static_targets: Vec::new(),
            cancel_tx,
            cancel_rx,
            state: ferrum_edge::_test_support::DiscoveryLoopStateForTest::new(),
        }
    }

    fn lb_hosts(&self) -> Vec<String> {
        self.lb_cache
            .get_upstream("ferrum", &self.upstream_id)
            .map(|u| u.targets.iter().map(|t| t.host.clone()).collect())
            .unwrap_or_default()
    }

    async fn apply_snapshot(
        &mut self,
        snapshot: ferrum_edge::service_discovery::DiscoverySnapshot,
    ) -> ferrum_edge::_test_support::DiscoveryApplyControlForTest {
        ferrum_edge::_test_support::apply_service_discovery_snapshot_for_test(
            "ferrum",
            &self.upstream_id,
            "consul",
            snapshot,
            &mut self.state,
            &self.lb_cache,
            &self.request_epoch,
            &self.static_targets,
            LoadBalancerAlgorithm::RoundRobin,
            &None,
            &self.cancel_rx,
            &None,
            &self.dns_cache,
            &self.health_checker,
        )
        .await
    }

    async fn discover_and_apply(
        &mut self,
        discoverer: &ConsulDiscoverer,
    ) -> Result<ferrum_edge::_test_support::DiscoveryApplyControlForTest, anyhow::Error> {
        let snapshot = discoverer.discover().await?;
        Ok(self.apply_snapshot(snapshot).await)
    }
}

#[tokio::test]
async fn consul_higher_index_http_500_does_not_advance_cursor() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.1", 8080))
                .insert_header("X-Consul-Index", "10"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "10"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string("Internal Server Error")
                .insert_header("X-Consul-Index", "99"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let mut harness = ConsulPipelineHarness::new("up-consul", Vec::new());

    harness
        .discover_and_apply(&discoverer)
        .await
        .expect("first poll admitted");
    assert_eq!(cursor_index(&discoverer), 10);
    assert_eq!(harness.lb_hosts(), vec!["10.0.0.1".to_string()]);

    let err = harness
        .discover_and_apply(&discoverer)
        .await
        .expect_err("500 must fail before admission");
    assert!(err.to_string().contains("status 500"));
    assert!(
        !err.to_string().contains("Internal Server Error"),
        "error path must not leak Consul response bodies"
    );
    assert_eq!(cursor_index(&discoverer), 10);
    assert_eq!(harness.lb_hosts(), vec!["10.0.0.1".to_string()]);
}

#[tokio::test]
async fn consul_higher_index_malformed_json_does_not_advance_cursor() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.1", 8080))
                .insert_header("X-Consul-Index", "10"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "10"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{not-json")
                .insert_header("X-Consul-Index", "99"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let mut harness = ConsulPipelineHarness::new("up-consul", Vec::new());

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 10);

    let err = harness
        .discover_and_apply(&discoverer)
        .await
        .expect_err("malformed JSON must fail");
    assert!(err.to_string().contains("malformed JSON"));
    assert!(
        !err.to_string().contains("{not-json"),
        "error path must not leak Consul response bodies"
    );
    assert_eq!(cursor_index(&discoverer), 10);
    assert_eq!(harness.lb_hosts(), vec!["10.0.0.1".to_string()]);
}

#[tokio::test]
async fn consul_shared_admission_rejection_retains_targets_and_cursor() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("8.8.8.8", 8080))
                .insert_header("X-Consul-Index", "10"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "10"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.9", 8080))
                .insert_header("X-Consul-Index", "99"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let public_only = ferrum_edge::config::BackendEgressPolicy::from_allow_ips(
        ferrum_edge::config::BackendAllowIps::Public,
    );
    let mut harness =
        ConsulPipelineHarness::with_dns_policy("up-consul", Vec::new(), public_only, None);

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 10);
    assert_eq!(harness.lb_hosts(), vec!["8.8.8.8".to_string()]);

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(
        cursor_index(&discoverer),
        10,
        "shared-admission rejection must retain the prior cursor"
    );
    assert_eq!(
        harness.lb_hosts(),
        vec!["8.8.8.8".to_string()],
        "shared-admission rejection must retain installed targets"
    );
}

#[tokio::test]
async fn consul_rejected_same_index_then_valid_same_index_is_admitted_and_published() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("8.8.8.8", 8080))
                .insert_header("X-Consul-Index", "50"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "50"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.9", 8080))
                .insert_header("X-Consul-Index", "50"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "50"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("backend.example.com", 8080))
                .insert_header("X-Consul-Index", "50"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let public_only = ferrum_edge::config::BackendEgressPolicy::from_allow_ips(
        ferrum_edge::config::BackendAllowIps::Public,
    );
    let mut harness =
        ConsulPipelineHarness::with_dns_policy("up-consul", Vec::new(), public_only, None);

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 50);

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 50);
    assert_eq!(harness.lb_hosts(), vec!["8.8.8.8".to_string()]);

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 50);
    assert_eq!(harness.lb_hosts(), vec!["backend.example.com".to_string()]);
}

#[tokio::test]
async fn consul_successful_higher_index_publishes_then_commits() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.1", 8080))
                .insert_header("X-Consul-Index", "42"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let mut harness = ConsulPipelineHarness::new("up-consul", Vec::new());

    assert_eq!(cursor_index(&discoverer), 0);
    let snapshot = discoverer.discover().await.unwrap();
    assert_eq!(
        cursor_index(&discoverer),
        0,
        "discover must not commit early"
    );
    assert_eq!(snapshot.pending_cursor_index(), Some(42));
    harness.apply_snapshot(snapshot).await;
    assert_eq!(cursor_index(&discoverer), 42);
    assert_eq!(harness.lb_hosts(), vec!["10.0.0.1".to_string()]);
    assert!(harness.state.snapshot_installed());
}

#[tokio::test]
async fn consul_successful_lower_index_rollback_publishes_then_commits() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.1", 8080))
                .insert_header("X-Consul-Index", "100"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "100"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.2", 8080))
                .insert_header("X-Consul-Index", "7"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let mut harness = ConsulPipelineHarness::new("up-consul", Vec::new());

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 100);

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 7);
    assert_eq!(harness.lb_hosts(), vec!["10.0.0.2".to_string()]);
}

#[tokio::test]
async fn consul_publication_failure_does_not_commit_cursor() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.1", 8080))
                .insert_header("X-Consul-Index", "42"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );

    let config = make_config_with_upstreams(vec![make_upstream("up-consul", Vec::new(), None)]);
    let base_epoch = request_epoch_store(config);
    let failing_epoch = Arc::new(
        ferrum_edge::_test_support::request_epoch_store_with_lb_generation_for_test(
            &base_epoch,
            u64::MAX,
        ),
    );
    let mut harness = ConsulPipelineHarness::with_dns_policy(
        "up-consul",
        Vec::new(),
        ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        Some(failing_epoch),
    );

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(
        cursor_index(&discoverer),
        0,
        "publication failure must not commit the Consul cursor"
    );
    assert!(!harness.state.snapshot_installed());
    assert!(harness.lb_hosts().is_empty());
}

#[tokio::test]
async fn consul_legitimate_empty_first_response_clears_prior_targets_then_commits() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([]))
                .insert_header("X-Consul-Index", "12"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    // Seed the LB with stale dynamic targets while also configuring a static
    // target that must survive the first empty publication/clear path.
    let prior_dynamic = vec![make_target("10.0.0.55", 8080)];
    let static_targets = vec![make_target("static-keep.example", 8080)];
    let mut harness = ConsulPipelineHarness::new("up-consul", prior_dynamic);
    harness.static_targets = static_targets;
    assert_eq!(harness.lb_hosts(), vec!["10.0.0.55".to_string()]);
    assert!(!harness.state.snapshot_installed());

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(
        harness.lb_hosts(),
        vec!["static-keep.example".to_string()],
        "first empty admitted snapshot must clear prior dynamic targets while retaining static targets"
    );
    assert_eq!(cursor_index(&discoverer), 12);
    assert!(harness.state.snapshot_installed());
}

#[tokio::test]
async fn consul_unchanged_snapshot_commits_cursor_only_after_prior_install() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.1", 8080))
                .insert_header("X-Consul-Index", "20"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Same targets, higher index — publication may be skipped after install,
    // but the cursor must still advance.
    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "20"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.1", 8080))
                .insert_header("X-Consul-Index", "21"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let mut harness = ConsulPipelineHarness::new("up-consul", Vec::new());

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 20);
    assert!(harness.state.snapshot_installed());

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(
        cursor_index(&discoverer),
        21,
        "admitted unchanged snapshot may commit only after a prior install"
    );
    assert_eq!(harness.lb_hosts(), vec!["10.0.0.1".to_string()]);
}

#[tokio::test]
async fn consul_all_provider_entries_rejected_retains_targets_and_cursor() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.1", 8080))
                .insert_header("X-Consul-Index", "10"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "10"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_invalid_entries())
                .insert_header("X-Consul-Index", "99"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let mut harness = ConsulPipelineHarness::new("up-consul", Vec::new());

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 10);

    let snapshot = discoverer.discover().await.unwrap();
    assert!(snapshot.targets().is_empty());
    assert_eq!(
        snapshot.admission_policy(),
        SnapshotAdmissionPolicy::AtomicCursor {
            provider_item_count: 2
        }
    );
    harness.apply_snapshot(snapshot).await;
    assert_eq!(cursor_index(&discoverer), 10);
    assert_eq!(harness.lb_hosts(), vec!["10.0.0.1".to_string()]);
}

#[tokio::test]
async fn consul_mixed_provider_entries_publish_valid_subset_and_commit() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_mixed_entries())
                .insert_header("X-Consul-Index", "33"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let mut harness = ConsulPipelineHarness::new("up-consul", Vec::new());

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 33);
    assert_eq!(harness.lb_hosts(), vec!["10.0.0.2".to_string()]);
}

#[tokio::test]
async fn consul_legitimate_empty_json_array_is_admissible() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([]))
                .insert_header("X-Consul-Index", "5"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let snapshot = discoverer.discover().await.unwrap();
    assert_eq!(
        snapshot.admission_policy(),
        SnapshotAdmissionPolicy::AtomicCursor {
            provider_item_count: 0
        }
    );
    match admit_discovered_snapshot(
        "up-consul",
        "consul",
        snapshot,
        ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    ) {
        SnapshotAdmission::Accepted { targets, cursor } => {
            assert!(targets.is_empty());
            // Cursor remains uncommitted here; only the manager/pipeline commits.
            assert!(cursor.is_some());
            drop(cursor);
        }
        SnapshotAdmission::Rejected { reason, .. } => {
            panic!("legitimate [] must be accepted, got {reason}")
        }
    }
    assert_eq!(cursor_index(&discoverer), 0);
}

#[test]
fn non_consul_accept_filtered_empty_policy_preserves_pre_pr_semantics() {
    // DNS-SD / Kubernetes / mesh snapshots use AcceptFilteredEmpty: even when
    // every normalized target is removed by shared admission, the empty set is
    // accepted (no atomic cursor rejection).
    let snapshot =
        ferrum_edge::service_discovery::DiscoverySnapshot::from_targets(vec![make_target(
            "10.0.0.1", 8080,
        )]);
    assert_eq!(
        snapshot.admission_policy(),
        SnapshotAdmissionPolicy::AcceptFilteredEmpty
    );
    match admit_discovered_snapshot(
        "up-dns",
        "dns_sd",
        snapshot,
        ferrum_edge::config::BackendEgressPolicy::from_allow_ips(
            ferrum_edge::config::BackendAllowIps::Public,
        ),
    ) {
        SnapshotAdmission::Accepted { targets, cursor } => {
            assert!(targets.is_empty());
            assert!(cursor.is_none());
        }
        SnapshotAdmission::Rejected { reason, .. } => {
            panic!("non-Consul providers must accept filtered-empty, got {reason}")
        }
    }
}

#[tokio::test]
async fn consul_manager_loop_empty_first_response_clears_cache_and_uses_index_query() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([]))
                .insert_header("X-Consul-Index", "12"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // After the empty snapshot commits index=12, the manager's next poll must
    // use a blocking query with that cursor.
    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "12"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.7", 8080))
                .insert_header("X-Consul-Index", "13"),
        )
        .mount(&mock_server)
        .await;

    let upstream_id = "up-consul-mgr";
    let config = make_config_with_upstreams(vec![make_upstream(
        upstream_id,
        Vec::new(),
        Some(ServiceDiscoveryConfig {
            provider: SdProvider::Consul,
            dns_sd: None,
            kubernetes: None,
            consul: Some(ConsulConfig {
                address: mock_server.uri(),
                service_name: "api".to_string(),
                datacenter: None,
                tag: None,
                healthy_only: false,
                token: None,
                poll_interval_seconds: 1,
            }),
            mesh: None,
            default_weight: 1,
        }),
    )]);
    let cache = Arc::new(LoadBalancerCache::new(&config));
    cache.update_targets(
        "ferrum",
        upstream_id,
        vec![make_target("10.0.0.55", 8080)],
        LoadBalancerAlgorithm::RoundRobin,
        None,
    );
    assert_eq!(
        cache
            .get_upstream("ferrum", upstream_id)
            .unwrap()
            .targets
            .iter()
            .map(|t| t.host.as_str())
            .collect::<Vec<_>>(),
        vec!["10.0.0.55"]
    );

    let dns_cache = ferrum_edge::dns::DnsCache::new(Default::default());
    let manager = ServiceDiscoveryManager::new(
        cache.clone(),
        dns_cache,
        Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        ferrum_edge::plugins::PluginHttpClient::default(),
        None,
    );
    manager.start(&config, None);

    // Wait until the empty snapshot publishes (clearing prior targets) and the
    // follow-up blocking query with index=12 installs the next target.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut saw_cleared = false;
    loop {
        let hosts: Vec<String> = cache
            .get_upstream("ferrum", upstream_id)
            .map(|u| u.targets.iter().map(|t| t.host.clone()).collect())
            .unwrap_or_default();
        if hosts.is_empty() {
            saw_cleared = true;
        }
        if hosts == vec!["10.0.0.7".to_string()] {
            assert!(
                saw_cleared,
                "follow-up publish must be preceded by clearing prior dynamic targets"
            );
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            manager.stop();
            panic!(
                "manager did not clear prior targets then publish via index=12 query; hosts={hosts:?}, saw_cleared={saw_cleared}"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    manager.stop();
}

#[test]
fn parse_consul_index_header_accepts_decimal_u64() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("X-Consul-Index", "42".parse().unwrap());
    assert_eq!(
        ferrum_edge::_test_support::parse_consul_index_header_for_test(&headers),
        Some(42)
    );
}

#[test]
fn parse_consul_index_header_rejects_oversized_or_non_digit() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "X-Consul-Index",
        "18446744073709551616".parse().unwrap(), // 2^64, 20 digits but overflows u64
    );
    assert_eq!(
        ferrum_edge::_test_support::parse_consul_index_header_for_test(&headers),
        None
    );

    headers.clear();
    headers.insert("X-Consul-Index", "12abc".parse().unwrap());
    assert_eq!(
        ferrum_edge::_test_support::parse_consul_index_header_for_test(&headers),
        None
    );

    headers.clear();
    headers.insert(
        "X-Consul-Index",
        "000000000000000000000".parse().unwrap(), // 21 digits
    );
    assert_eq!(
        ferrum_edge::_test_support::parse_consul_index_header_for_test(&headers),
        None
    );
}

#[tokio::test]
async fn consul_401_acl_denied_does_not_advance_cursor_or_leak_body() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.1", 8080))
                .insert_header("X-Consul-Index", "10"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "10"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string("ACL not found: secret-token-value")
                .insert_header("X-Consul-Index", "99"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        Some("secret-token-value".to_string()),
        1,
    );
    let mut harness = ConsulPipelineHarness::new("up-consul", Vec::new());

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 10);

    let err = harness
        .discover_and_apply(&discoverer)
        .await
        .expect_err("401 must fail closed");
    let msg = err.to_string();
    assert!(msg.contains("status 401"), "got: {msg}");
    assert!(
        msg.contains("ACL token policy"),
        "401 must carry a fixed ACL remediation hint: {msg}"
    );
    assert!(
        !msg.contains("secret-token-value"),
        "401 path must not leak token or body: {msg}"
    );
    assert_eq!(cursor_index(&discoverer), 10);
    assert_eq!(harness.lb_hosts(), vec!["10.0.0.1".to_string()]);
}

#[tokio::test]
async fn consul_403_acl_denied_does_not_advance_cursor_or_leak_body() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.1", 8080))
                .insert_header("X-Consul-Index", "10"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "10"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_string("Permission denied for token abc")
                .insert_header("X-Consul-Index", "99"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let mut harness = ConsulPipelineHarness::new("up-consul", Vec::new());

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 10);

    let err = harness
        .discover_and_apply(&discoverer)
        .await
        .expect_err("403 must fail closed");
    let msg = err.to_string();
    assert!(msg.contains("status 403"), "got: {msg}");
    assert!(
        msg.contains("ACL token policy"),
        "403 must carry a fixed ACL remediation hint: {msg}"
    );
    assert!(
        !msg.contains("Permission denied"),
        "403 must not leak body: {msg}"
    );
    assert_eq!(cursor_index(&discoverer), 10);
}

#[tokio::test]
async fn consul_repeated_all_rejected_retains_cursor_and_increments_rejection_metric() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.1", 8080))
                .insert_header("X-Consul-Index", "10"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Same candidate index, sustained all-rejected catalog.
    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "10"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_invalid_entries())
                .insert_header("X-Consul-Index", "99"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let mut harness = ConsulPipelineHarness::new("up-consul", Vec::new());
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let before = registry.service_discovery_provider_normalization_rejected_total();

    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 10);

    harness.discover_and_apply(&discoverer).await.unwrap();
    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(
        cursor_index(&discoverer),
        10,
        "repeated all-rejected polls must not advance the cursor"
    );
    assert_eq!(harness.lb_hosts(), vec!["10.0.0.1".to_string()]);
    let after = registry.service_discovery_provider_normalization_rejected_total();
    assert!(
        after >= before + 2,
        "each rejected poll must increment the bounded rejection counter (before={before}, after={after})"
    );
}

#[tokio::test]
async fn consul_cursor_advance_and_rollback_emit_bounded_metrics() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.1", 8080))
                .insert_header("X-Consul-Index", "40"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "40"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.2", 8080))
                .insert_header("X-Consul-Index", "50"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "50"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.3", 8080))
                .insert_header("X-Consul-Index", "7"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let mut harness = ConsulPipelineHarness::new("up-consul", Vec::new());
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let advance_before = registry.service_discovery_cursor_advance_total();
    let rollback_before = registry.service_discovery_cursor_rollback_total();

    harness.discover_and_apply(&discoverer).await.unwrap(); // 0 -> 40
    harness.discover_and_apply(&discoverer).await.unwrap(); // 40 -> 50
    harness.discover_and_apply(&discoverer).await.unwrap(); // 50 -> 7
    assert_eq!(cursor_index(&discoverer), 7);

    let advance_after = registry.service_discovery_cursor_advance_total();
    let rollback_after = registry.service_discovery_cursor_rollback_total();
    assert!(
        advance_after >= advance_before + 2,
        "higher-index commits must increment advance (before={advance_before}, after={advance_after})"
    );
    assert!(
        rollback_after > rollback_before,
        "lower-index commit must increment rollback (before={rollback_before}, after={rollback_after})"
    );
}

#[tokio::test]
async fn consul_shared_admission_rejection_increments_bounded_metric() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("8.8.8.8", 8080))
                .insert_header("X-Consul-Index", "10"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .and(query_param("index", "10"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(consul_health_instance("10.0.0.9", 8080))
                .insert_header("X-Consul-Index", "99"),
        )
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let public_only = ferrum_edge::config::BackendEgressPolicy::from_allow_ips(
        ferrum_edge::config::BackendAllowIps::Public,
    );
    let mut harness =
        ConsulPipelineHarness::with_dns_policy("up-consul", Vec::new(), public_only, None);
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let before = registry.service_discovery_shared_admission_rejected_total();

    harness.discover_and_apply(&discoverer).await.unwrap();
    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 10);

    let after = registry.service_discovery_shared_admission_rejected_total();
    assert!(
        after > before,
        "shared-admission rejection must increment bounded counter (before={before}, after={after})"
    );
}

// ── Discovery body ceilings + Kubernetes envelope integrity (#3718/#3720) ──

fn discovery_body_test_lock() -> &'static tokio::sync::Mutex<()> {
    use std::sync::OnceLock;
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Serializes discovery-body tests that compare process counters or publish the
/// production install seam. Custom limits and their budget counters are scoped
/// to the calling test thread, so unrelated parallel discovery tests keep the
/// installed/default production limits.
struct DiscoveryBodyLimitsGuard {
    _lock: tokio::sync::MutexGuard<'static, ()>,
    clear_override: bool,
}

impl DiscoveryBodyLimitsGuard {
    /// Exclusive ownership for collector / budget observation without changing
    /// effective ceilings.
    async fn serialize() -> Self {
        Self {
            _lock: discovery_body_test_lock().lock().await,
            clear_override: false,
        }
    }

    async fn install(max_response: usize, max_error: usize, budget: usize) -> Self {
        let lock = discovery_body_test_lock().lock().await;
        ferrum_edge::_test_support::override_discovery_body_limits_for_test(
            ferrum_edge::config::env_config::DiscoveryBodyLimits {
                max_response_bytes: max_response,
                max_error_bytes: max_error,
                body_budget_bytes: budget,
            },
        )
        .expect("test discovery body limits");
        Self {
            _lock: lock,
            clear_override: true,
        }
    }
}

impl Drop for DiscoveryBodyLimitsGuard {
    fn drop(&mut self) {
        if self.clear_override {
            ferrum_edge::_test_support::clear_discovery_body_limits_override_for_test();
        }
    }
}

async fn serve_raw_http_once(status_line: &str, headers: &[(&str, &str)], body: &[u8]) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind raw discovery fixture");
    let addr = listener.local_addr().expect("local addr");
    let status = status_line.to_string();
    let header_lines: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    let body = body.to_vec();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await;
        let mut response = format!("{status}\r\n");
        for (k, v) in &header_lines {
            response.push_str(&format!("{k}: {v}\r\n"));
        }
        response.push_str("Connection: close\r\n\r\n");
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.write_all(&body).await;
        let _ = socket.shutdown().await;
    });
    format!("http://{addr}")
}

fn chunked_body(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // Emit one chunk for the whole payload so the collector still streams
    // through reqwest's chunk API without a Content-Length.
    out.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n0\r\n\r\n");
    out
}

#[test]
fn discovery_body_limits_parse_rejects_zero_and_inconsistent_relationships() {
    use ferrum_edge::config::env_config::{
        DEFAULT_SERVICE_DISCOVERY_BODY_BUDGET_BYTES,
        DEFAULT_SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES,
        DEFAULT_SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES,
        HARD_MAX_SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES, parse_discovery_body_limits,
    };

    let defaults = parse_discovery_body_limits(None, None, None).unwrap();
    assert_eq!(
        defaults.max_response_bytes,
        DEFAULT_SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES
    );
    assert_eq!(
        defaults.max_error_bytes,
        DEFAULT_SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES
    );
    assert_eq!(
        defaults.body_budget_bytes,
        DEFAULT_SERVICE_DISCOVERY_BODY_BUDGET_BYTES
    );

    assert!(
        parse_discovery_body_limits(Some("0"), None, None)
            .unwrap_err()
            .contains("0 is not unlimited")
    );
    assert!(
        parse_discovery_body_limits(None, Some("0"), None)
            .unwrap_err()
            .contains("0 is not unlimited")
    );
    assert!(
        parse_discovery_body_limits(None, None, Some("0"))
            .unwrap_err()
            .contains("0 is not unlimited")
    );
    assert!(
        parse_discovery_body_limits(Some("1024"), Some("2048"), Some("4096"))
            .unwrap_err()
            .contains("must be <=")
    );
    assert!(
        parse_discovery_body_limits(Some("8192"), Some("1024"), Some("4096"))
            .unwrap_err()
            .contains("must be >=")
    );
    let clamped =
        parse_discovery_body_limits(Some("999999999"), Some("1024"), Some("999999999")).unwrap();
    assert_eq!(
        clamped.max_response_bytes,
        HARD_MAX_SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES
    );
}

#[test]
fn discovery_body_limits_parsing_is_pure_across_repeated_snapshots() {
    use ferrum_edge::config::env_config::parse_discovery_body_limits;

    let first = parse_discovery_body_limits(Some("1024"), Some("512"), Some("2048")).unwrap();
    let second = parse_discovery_body_limits(Some("4096"), Some("1024"), Some("8192")).unwrap();
    let first_again = parse_discovery_body_limits(Some("1024"), Some("512"), Some("2048")).unwrap();
    assert_eq!(first, first_again);
    assert_ne!(first.max_response_bytes, second.max_response_bytes);
    assert_eq!(second.max_response_bytes, 4096);
}

#[test]
fn discovery_body_limits_envconfig_parse_does_not_pin_process_install() {
    use crate::unit::env_lock::EnvGuard;
    use ferrum_edge::config::env_config::{
        DEFAULT_SERVICE_DISCOVERY_BODY_BUDGET_BYTES,
        DEFAULT_SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES,
        DEFAULT_SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES, SERVICE_DISCOVERY_BODY_BUDGET_BYTES_KEY,
        SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES_KEY, SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES_KEY,
    };

    let env = EnvGuard::new(&[
        "FERRUM_MODE",
        "FERRUM_FILE_CONFIG_PATH",
        SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES_KEY,
        SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES_KEY,
        SERVICE_DISCOVERY_BODY_BUDGET_BYTES_KEY,
    ]);
    env.set("FERRUM_MODE", "file");
    env.set(
        "FERRUM_FILE_CONFIG_PATH",
        "/tmp/ferrum-discovery-body-cap.yaml",
    );
    env.set(SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES_KEY, "2048");
    env.set(SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES_KEY, "512");
    env.set(SERVICE_DISCOVERY_BODY_BUDGET_BYTES_KEY, "4096");
    let first = ferrum_edge::config::EnvConfig::from_env().expect("first snapshot");
    assert_eq!(first.service_discovery_max_response_body_bytes, 2048);
    assert_eq!(first.service_discovery_max_error_body_bytes, 512);
    assert_eq!(first.service_discovery_body_budget_bytes, 4096);

    // A later, different but valid snapshot must still parse: from_env must not
    // have installed the process OnceLock on the first call.
    env.set(SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES_KEY, "8192");
    env.set(SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES_KEY, "1024");
    env.set(SERVICE_DISCOVERY_BODY_BUDGET_BYTES_KEY, "16384");
    let second = ferrum_edge::config::EnvConfig::from_env().expect("second snapshot");
    assert_eq!(second.service_discovery_max_response_body_bytes, 8192);
    assert_eq!(second.service_discovery_max_error_body_bytes, 1024);
    assert_eq!(second.service_discovery_body_budget_bytes, 16384);

    // Clearing the keys restores documented defaults without OnceLock poisoning.
    env.unset(SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES_KEY);
    env.unset(SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES_KEY);
    env.unset(SERVICE_DISCOVERY_BODY_BUDGET_BYTES_KEY);
    let defaults = ferrum_edge::config::EnvConfig::from_env().expect("default snapshot");
    assert_eq!(
        defaults.service_discovery_max_response_body_bytes,
        DEFAULT_SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES
    );
    assert_eq!(
        defaults.service_discovery_max_error_body_bytes,
        DEFAULT_SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES
    );
    assert_eq!(
        defaults.service_discovery_body_budget_bytes,
        DEFAULT_SERVICE_DISCOVERY_BODY_BUDGET_BYTES
    );
}

#[tokio::test]
async fn discovery_body_limits_install_accepts_identical_and_rejects_mismatch() {
    use ferrum_edge::config::env_config::{
        DEFAULT_SERVICE_DISCOVERY_BODY_BUDGET_BYTES,
        DEFAULT_SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES,
        DEFAULT_SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES, DiscoveryBodyLimits,
    };
    use ferrum_edge::service_discovery::http_body::install_discovery_body_limits;

    // Installing limits updates the same process-wide budget ceiling used by
    // collector tests. Hold their lifetime lock so this deterministic install
    // cannot race a test-owned override or a live budget permit.
    let _guard = DiscoveryBodyLimitsGuard::serialize().await;

    let defaults = DiscoveryBodyLimits {
        max_response_bytes: DEFAULT_SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES,
        max_error_bytes: DEFAULT_SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES,
        body_budget_bytes: DEFAULT_SERVICE_DISCOVERY_BODY_BUDGET_BYTES,
    };
    // Prefer documented defaults so this stays coherent if another suite already
    // published the production install seam in-process.
    install_discovery_body_limits(defaults).expect("default install");
    install_discovery_body_limits(defaults).expect("identical reinstall");

    let mismatch = install_discovery_body_limits(DiscoveryBodyLimits {
        max_response_bytes: 1024,
        max_error_bytes: 512,
        body_budget_bytes: 2048,
    })
    .expect_err("mismatching install must fail closed");
    assert!(
        mismatch.contains("already installed with a different value"),
        "{mismatch}"
    );
    assert!(
        !mismatch.contains("1024") && !mismatch.contains("4194304"),
        "mismatch diagnostic must not echo numeric ceilings: {mismatch}"
    );

    let zero = install_discovery_body_limits(DiscoveryBodyLimits {
        max_response_bytes: 0,
        max_error_bytes: 0,
        body_budget_bytes: 0,
    })
    .expect_err("install must not accept 0");
    assert!(
        zero.contains("0 is not unlimited") || zero.contains("must be >= 1"),
        "{zero}"
    );
}

#[tokio::test]
async fn discovery_body_test_override_does_not_leak_to_parallel_threads() {
    use ferrum_edge::config::env_config::{
        DEFAULT_SERVICE_DISCOVERY_BODY_BUDGET_BYTES,
        DEFAULT_SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES,
        DEFAULT_SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES,
    };

    let _guard = DiscoveryBodyLimitsGuard::install(64, 32, 256).await;
    assert_eq!(
        ferrum_edge::service_discovery::http_body::effective_discovery_body_limits()
            .max_response_bytes,
        64
    );
    assert_eq!(
        ferrum_edge::_test_support::discovery_body_budget_max_for_test(),
        256
    );

    let (parallel_limits, parallel_budget) = std::thread::spawn(|| {
        (
            ferrum_edge::service_discovery::http_body::effective_discovery_body_limits(),
            ferrum_edge::_test_support::discovery_body_budget_max_for_test(),
        )
    })
    .join()
    .expect("parallel discovery test thread");
    assert_eq!(
        parallel_limits.max_response_bytes,
        DEFAULT_SERVICE_DISCOVERY_MAX_RESPONSE_BODY_BYTES
    );
    assert_eq!(
        parallel_limits.max_error_bytes,
        DEFAULT_SERVICE_DISCOVERY_MAX_ERROR_BODY_BYTES
    );
    assert_eq!(parallel_budget, DEFAULT_SERVICE_DISCOVERY_BODY_BUDGET_BYTES);
}

#[test]
fn discovery_body_limits_production_publish_seam_lives_in_main() {
    let main_src = include_str!("../../../src/main.rs");
    let env_src = include_str!("../../../src/config/env_config.rs");
    assert!(
        main_src.contains("install_discovery_body_limits"),
        "production startup must publish discovery body ceilings after EnvConfig is accepted"
    );
    assert!(
        !env_src.contains("install_discovery_body_limits("),
        "EnvConfig parsing must remain pure and must not install the process OnceLock"
    );
}

#[tokio::test]
async fn discovery_collector_rejects_oversized_content_length_before_body() {
    let _guard = DiscoveryBodyLimitsGuard::install(64, 32, 256).await;
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let before = registry.service_discovery_response_oversized_total();

    let base = serve_raw_http_once(
        "HTTP/1.1 200 OK",
        &[
            ("Content-Type", "application/json"),
            ("Content-Length", "1000000"),
        ],
        b"{}",
    )
    .await;
    let response = reqwest::Client::new()
        .get(format!("{base}/v1"))
        .send()
        .await
        .expect("send");
    let err = ferrum_edge::_test_support::collect_discovery_response_body_for_test(response, true)
        .await
        .expect_err("oversized CL must fail");
    assert_eq!(err, "response_oversized");
    assert!(registry.service_discovery_response_oversized_total() > before);
    assert_eq!(
        ferrum_edge::_test_support::discovery_body_budget_used_for_test(),
        0,
        "oversized CL must not charge the shared budget"
    );
}

#[tokio::test]
async fn discovery_collector_rejects_disagreeing_repeated_content_length() {
    let _guard = DiscoveryBodyLimitsGuard::install(64, 32, 256).await;
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let before = registry.service_discovery_response_oversized_total();

    // Two field lines that disagree: the HTTP client may reject before the
    // collector, or the collector must fail closed on ambiguity. Either
    // boundary preserves the early oversized-declaration contract.
    let base = serve_raw_http_once(
        "HTTP/1.1 200 OK",
        &[
            ("Content-Type", "application/json"),
            ("Content-Length", "32"),
            ("Content-Length", "48"),
        ],
        &[b'x'; 32],
    )
    .await;
    let client_result = reqwest::Client::new()
        .get(format!("{base}/dup"))
        .send()
        .await;
    match client_result {
        Err(_) => {
            // Client rejected conflicting Content-Length before collection.
        }
        Ok(response) => {
            let err = ferrum_edge::_test_support::collect_discovery_response_body_for_test(
                response, true,
            )
            .await
            .expect_err("disagreeing CL must fail closed");
            assert_eq!(err, "ambiguous_content_length");
            assert!(registry.service_discovery_response_oversized_total() > before);
        }
    }
    assert_eq!(
        ferrum_edge::_test_support::discovery_body_budget_used_for_test(),
        0
    );
}

#[tokio::test]
async fn discovery_collector_accepts_agreeing_repeated_content_length() {
    let _guard = DiscoveryBodyLimitsGuard::install(64, 32, 256).await;
    let body = vec![b'y'; 16];
    let base = serve_raw_http_once(
        "HTTP/1.1 200 OK",
        &[
            ("Content-Type", "application/json"),
            ("Content-Length", "16"),
            ("Content-Length", "16"),
        ],
        &body,
    )
    .await;
    let client_result = reqwest::Client::new()
        .get(format!("{base}/ok"))
        .send()
        .await;
    match client_result {
        Err(_) => {
            // Some HTTP stacks reject even agreeing repeats; that still keeps
            // the collector boundary fail-closed for malformed framing.
        }
        Ok(response) => {
            let accepted = ferrum_edge::_test_support::collect_discovery_response_body_for_test(
                response, true,
            )
            .await
            .expect("agreeing repeated CL must be accepted when the client delivers it");
            assert_eq!(accepted, 16);
        }
    }
}

#[tokio::test]
async fn discovery_collector_does_not_preallocate_uncharged_content_length() {
    let collector_src = include_str!("../../../src/service_discovery/http_body.rs");
    assert!(
        !collector_src.contains("Vec::with_capacity") && !collector_src.contains("buf.reserve"),
        "the collector must not preallocate from untrusted Content-Length"
    );

    // A large-but-under-ceiling Content-Length must not allocate that capacity
    // outside the shared budget. Stall after headers so only the declaration is
    // visible; budget usage must stay zero until retained bytes are charged.
    let _guard = DiscoveryBodyLimitsGuard::install(1024, 32, 2048).await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled fixture");
    let addr = listener.local_addr().expect("addr");
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await;
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 512\r\nConnection: close\r\n\r\n";
        let _ = socket.write_all(headers.as_bytes()).await;
        let _ = release_rx.await;
        let _ = socket.write_all(&[b'z'; 512]).await;
        let _ = socket.shutdown().await;
    });

    let response = reqwest::Client::new()
        .get(format!("http://{addr}/stall"))
        .send()
        .await
        .expect("headers");
    assert_eq!(
        ferrum_edge::_test_support::discovery_body_budget_used_for_test(),
        0,
        "headers alone must not charge or pre-reserve against the shared budget"
    );

    let collect = tokio::spawn(async move {
        ferrum_edge::_test_support::collect_discovery_response_body_for_test(response, true).await
    });
    // Give the collector a chance to observe Content-Length and (incorrectly)
    // reserve before any body bytes arrive.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        ferrum_edge::_test_support::discovery_body_budget_used_for_test(),
        0,
        "stalled body must not charge budget before retained bytes exist"
    );
    let _ = release_tx.send(());
    let accepted = collect.await.expect("join").expect("collect");
    assert_eq!(accepted, 512);
    assert_eq!(
        ferrum_edge::_test_support::discovery_body_budget_used_for_test(),
        0,
        "permit must release after the collected body drops"
    );
}

#[tokio::test]
async fn discovery_collector_accepts_exact_limit_and_rejects_limit_plus_one_chunked() {
    let _guard = DiscoveryBodyLimitsGuard::install(64, 32, 256).await;
    let exact = vec![b'a'; 64];
    let over = vec![b'b'; 65];

    let base_ok = serve_raw_http_once(
        "HTTP/1.1 200 OK",
        &[
            ("Content-Type", "application/json"),
            ("Transfer-Encoding", "chunked"),
        ],
        &chunked_body(&exact),
    )
    .await;
    let ok = reqwest::Client::new()
        .get(format!("{base_ok}/ok"))
        .send()
        .await
        .expect("send exact");
    let accepted = ferrum_edge::_test_support::collect_discovery_response_body_for_test(ok, true)
        .await
        .expect("exact limit must be accepted");
    assert_eq!(accepted, 64);
    assert_eq!(
        ferrum_edge::_test_support::discovery_body_budget_used_for_test(),
        0,
        "permit must release after collector result drops"
    );

    let base_over = serve_raw_http_once(
        "HTTP/1.1 200 OK",
        &[
            ("Content-Type", "application/json"),
            ("Transfer-Encoding", "chunked"),
        ],
        &chunked_body(&over),
    )
    .await;
    let bad = reqwest::Client::new()
        .get(format!("{base_over}/over"))
        .send()
        .await
        .expect("send over");
    let err = ferrum_edge::_test_support::collect_discovery_response_body_for_test(bad, true)
        .await
        .expect_err("limit+1 must fail");
    assert_eq!(err, "response_oversized");
    assert_eq!(
        ferrum_edge::_test_support::discovery_body_budget_used_for_test(),
        0
    );
}

#[tokio::test]
async fn discovery_collector_bounds_error_bodies_independently() {
    let _guard = DiscoveryBodyLimitsGuard::install(256, 16, 1024).await;
    let body = vec![b'x'; 64];
    let base = serve_raw_http_once(
        "HTTP/1.1 500 Internal Server Error",
        &[
            ("Content-Type", "text/plain"),
            ("Transfer-Encoding", "chunked"),
        ],
        &chunked_body(&body),
    )
    .await;
    let response = reqwest::Client::new()
        .get(format!("{base}/err"))
        .send()
        .await
        .expect("send");
    let err = ferrum_edge::_test_support::collect_discovery_response_body_for_test(response, false)
        .await
        .expect_err("error body must use tighter ceiling");
    assert_eq!(err, "response_oversized");
}

#[tokio::test]
async fn discovery_body_budget_rejects_concurrent_pollers_and_releases_on_cancel() {
    let _guard = DiscoveryBodyLimitsGuard::install(64, 16, 96).await;
    let payload = vec![b'z'; 64];

    async fn one_collect(base: String) -> Result<usize, &'static str> {
        let response = reqwest::Client::new()
            .get(format!("{base}/body"))
            .send()
            .await
            .map_err(|_| "body_read_failed")?;
        ferrum_edge::_test_support::collect_discovery_response_body_for_test(response, true).await
    }

    // Hold one successful body (and its permit) while other pollers compete.
    let hold_base = serve_raw_http_once(
        "HTTP/1.1 200 OK",
        &[
            ("Content-Type", "application/json"),
            ("Transfer-Encoding", "chunked"),
        ],
        &chunked_body(&payload),
    )
    .await;
    let held_response = reqwest::Client::new()
        .get(format!("{hold_base}/hold"))
        .send()
        .await
        .expect("hold send");
    let held = {
        use ferrum_edge::service_discovery::http_body::{
            DiscoveryBodyRole, collect_discovery_response_body,
        };
        collect_discovery_response_body(held_response, DiscoveryBodyRole::Success)
            .await
            .expect("first body admitted")
    };
    assert_eq!(held.as_slice().len(), 64);
    assert_eq!(
        ferrum_edge::_test_support::discovery_body_budget_used_for_test(),
        64
    );

    let mut rejected = 0usize;
    for _ in 0..4 {
        let base = serve_raw_http_once(
            "HTTP/1.1 200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Transfer-Encoding", "chunked"),
            ],
            &chunked_body(&payload),
        )
        .await;
        match one_collect(base).await {
            Ok(_) => {}
            Err("body_budget_rejected") => rejected += 1,
            Err(other) => panic!("unexpected collector failure: {other}"),
        }
    }
    assert!(
        rejected >= 1,
        "shared budget must reject at least one concurrent poller"
    );

    // Cancellation: drop an in-flight charged body and confirm budget releases.
    drop(held);
    assert_eq!(
        ferrum_edge::_test_support::discovery_body_budget_used_for_test(),
        0
    );
}

#[tokio::test]
async fn kubernetes_malformed_envelopes_fail_closed_valid_empty_withdraws() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _guard = DiscoveryBodyLimitsGuard::serialize().await;
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let before = registry.service_discovery_malformed_envelope_total();

    for malformed in [
        serde_json::json!({}),
        serde_json::json!({"items": null}),
        serde_json::json!({"items": {}}),
        serde_json::json!({"items": "nope"}),
        serde_json::json!([1, 2, 3]),
    ] {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&malformed))
            .mount(&mock_server)
            .await;
        let discoverer = KubernetesDiscoverer::new(
            reqwest::Client::new(),
            "default".to_string(),
            "svc".to_string(),
            None,
            None,
            1,
        )
        .with_api_url(mock_server.uri());
        let err = discoverer.discover().await.expect_err("malformed envelope");
        assert!(
            err.to_string().contains("malformed EndpointSliceList"),
            "unexpected error: {err}"
        );
    }
    assert!(registry.service_discovery_malformed_envelope_total() > before);

    // Invalid JSON
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
        .mount(&mock_server)
        .await;
    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "svc".to_string(),
        None,
        None,
        1,
    )
    .with_api_url(mock_server.uri());
    assert!(discoverer.discover().await.is_err());

    // Authoritative empty withdrawal
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"items": []})))
        .mount(&mock_server)
        .await;
    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "svc".to_string(),
        None,
        None,
        1,
    )
    .with_api_url(mock_server.uri());
    let empty = discoverer.discover().await.expect("valid empty");
    assert!(empty.targets().is_empty());
}

#[tokio::test]
async fn kubernetes_normal_endpointslicelist_still_parses() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _guard = DiscoveryBodyLimitsGuard::serialize().await;
    let mock_server = MockServer::start().await;
    let response = serde_json::json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSliceList",
        "items": [{
            "ports": [{"name": "http", "port": 8080}],
            "endpoints": [{
                "addresses": ["10.244.0.9"],
                "conditions": {"ready": true, "serving": true}
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
        "svc".to_string(),
        None,
        None,
        1,
    )
    .with_api_url(mock_server.uri());
    let targets = discoverer.discover().await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host, "10.244.0.9");
    assert_eq!(targets[0].port, 8080);
}

#[tokio::test]
async fn kubernetes_error_response_does_not_surface_body_bytes() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _guard = DiscoveryBodyLimitsGuard::serialize().await;
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(403).set_body_string("secret-token=abc&registry-credential=xyz"),
        )
        .mount(&mock_server)
        .await;
    let discoverer = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "svc".to_string(),
        None,
        None,
        1,
    )
    .with_api_url(mock_server.uri());
    let err = discoverer.discover().await.unwrap_err().to_string();
    assert!(err.contains("403"));
    assert!(!err.contains("secret-token"));
    assert!(!err.contains("registry-credential"));
}

#[tokio::test]
async fn production_discovery_loop_retains_targets_and_cursor_on_oversized_or_malformed() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Keep the success ceiling well above valid Consul/Kubernetes fixtures
    // (~100-150B compact JSON) while the oversized probe stays clearly over it.
    let _guard = DiscoveryBodyLimitsGuard::install(1024, 64, 4096).await;

    // Seed Consul with a healthy snapshot + cursor, then serve oversized and
    // confirm prior LB targets + cursor remain.
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Consul-Index", "77")
                .set_body_json(consul_health_instance("10.0.0.40", 8080)),
        )
        .up_to_n_times(1)
        .expect(1)
        .mount(&mock_server)
        .await;

    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let mut harness = ConsulPipelineHarness::new("up-body-cap", Vec::new());
    harness.discover_and_apply(&discoverer).await.unwrap();
    assert_eq!(cursor_index(&discoverer), 77);
    let installed = harness
        .lb_cache
        .get_upstream("ferrum", "up-body-cap")
        .expect("upstream installed");
    assert!(
        installed
            .targets
            .iter()
            .any(|t| t.host == "10.0.0.40" && t.port == 8080)
    );

    // Oversized success body must retain targets + cursor (streamed limit).
    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Consul-Index", "99")
                .set_body_string("x".repeat(4096)),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    let err = discoverer.discover().await.expect_err("oversized");
    assert!(err.to_string().contains("byte limit"));
    assert_eq!(cursor_index(&discoverer), 77);
    let still = harness
        .lb_cache
        .get_upstream("ferrum", "up-body-cap")
        .expect("upstream retained");
    assert!(still.targets.iter().any(|t| t.host == "10.0.0.40"));

    // Kubernetes malformed envelope through the production apply pipeline.
    let k8s_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [{
                "ports": [{"port": 8080}],
                "endpoints": [{
                    "addresses": ["10.244.1.1"],
                    "conditions": {"ready": true}
                }]
            }]
        })))
        .up_to_n_times(1)
        .mount(&k8s_server)
        .await;
    let k8s = KubernetesDiscoverer::new(
        reqwest::Client::new(),
        "default".to_string(),
        "svc".to_string(),
        None,
        None,
        1,
    )
    .with_api_url(k8s_server.uri());
    let mut k8s_harness = ConsulPipelineHarness::new("up-k8s-envelope", Vec::new());
    let good = k8s.discover().await.unwrap();
    let _ = ferrum_edge::_test_support::apply_service_discovery_snapshot_for_test(
        "ferrum",
        "up-k8s-envelope",
        "kubernetes",
        good,
        &mut k8s_harness.state,
        &k8s_harness.lb_cache,
        &k8s_harness.request_epoch,
        &k8s_harness.static_targets,
        LoadBalancerAlgorithm::RoundRobin,
        &None,
        &k8s_harness.cancel_rx,
        &None,
        &k8s_harness.dns_cache,
        &k8s_harness.health_checker,
    )
    .await;
    assert!(
        k8s_harness
            .lb_cache
            .get_upstream("ferrum", "up-k8s-envelope")
            .unwrap()
            .targets
            .iter()
            .any(|t| t.host == "10.244.1.1")
    );

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&k8s_server)
        .await;
    assert!(k8s.discover().await.is_err());
    assert!(
        k8s_harness
            .lb_cache
            .get_upstream("ferrum", "up-k8s-envelope")
            .unwrap()
            .targets
            .iter()
            .any(|t| t.host == "10.244.1.1"),
        "malformed envelope must retain last admitted Kubernetes targets"
    );
}

#[tokio::test]
async fn consul_normal_parsing_still_works_under_bounded_collector() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/health/service/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Consul-Index", "5")
                .set_body_json(consul_health_instance("10.0.0.50", 9090)),
        )
        .mount(&mock_server)
        .await;
    let discoverer = ConsulDiscoverer::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "api".to_string(),
        None,
        None,
        false,
        None,
        1,
    );
    let snapshot = discoverer.discover().await.unwrap();
    assert_eq!(snapshot.targets().len(), 1);
    assert_eq!(snapshot.pending_cursor_index(), Some(5));
}
