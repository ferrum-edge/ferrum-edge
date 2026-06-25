//! Integration coverage for Tier 3b cross-cluster endpoint discovery.
//!
//! Verifies the load-bearing behavior: remote-cluster endpoints discovered from
//! `RemoteCluster.control_plane_url` are aggregated into the local mesh registry
//! (tagged with remote locality), the `MeshServiceDiscoverer` resolves both
//! local and remote endpoints for a service, and the locality-aware priority
//! load balancer fails over local → remote at the endpoint level when the local
//! endpoints become unhealthy.
//!
//! The remote source is a mock (`RemoteServiceSource`) so the full
//! discovery → aggregation → failover path is exercised without a live remote
//! control plane.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use dashmap::DashMap;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, Upstream, UpstreamLocalityLbSetting, UpstreamTarget,
};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::load_balancer::{HealthContext, LoadBalancerCache};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshService, MultiClusterConfig, RemoteCluster, ServicePort, Workload,
    WorkloadPort, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::multicluster::{
    RemoteClusterEndpoints, RemoteClusterEntry, RemoteEndpointSnapshot,
    merge_remote_endpoints_into_mesh,
};
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::request_epoch::RequestEpochStore;
use ferrum_edge::service_discovery::ServiceDiscoverer;
use ferrum_edge::service_discovery::mesh::MeshServiceDiscoverer;

fn td(raw: &str) -> TrustDomain {
    TrustDomain::new(raw).expect("trust domain")
}

fn spiffe(raw: &str) -> SpiffeId {
    SpiffeId::new(raw.to_string()).expect("spiffe id")
}

fn workload(spiffe_id: &str, service: &str, addr: &str, locality: Option<&str>) -> Workload {
    Workload {
        spiffe_id: spiffe(spiffe_id),
        selector: WorkloadSelector::default(),
        service_name: service.to_string(),
        addresses: vec![addr.to_string()],
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain: td("cluster.local"),
        namespace: "default".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: locality.map(str::to_string),
        service_account: None,
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    }
}

fn service(name: &str, refs: &[&str]) -> MeshService {
    MeshService {
        cluster_ips: Vec::new(),
        name: name.to_string(),
        namespace: "default".to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: refs
            .iter()
            .map(|r| WorkloadRef {
                spiffe_id: spiffe(r),
            })
            .collect(),
        protocol_overrides: HashMap::new(),
    }
}

fn remote_snapshot(endpoints: RemoteClusterEndpoints) -> RemoteEndpointSnapshot {
    let mut clusters = HashMap::new();
    clusters.insert(
        "west".to_string(),
        RemoteClusterEntry::new(
            "west".to_string(),
            td("remote.local"),
            Some("net2".to_string()),
            // Matches `admitting_candidate`'s declared (normalized) URL so the
            // full-poll-identity merge filter admits these endpoints.
            Some("https://cp.remote.example:15010".to_string()),
            None,
            endpoints,
            1,
        ),
    );
    RemoteEndpointSnapshot { clusters }
}

/// Candidate `MultiClusterConfig` that admits the `remote_snapshot` cluster
/// identity (`west` / `remote.local` / `net2`) so the same-generation merge
/// filter passes — the slice-apply path always merges against the candidate
/// slice's `multi_cluster`.
fn admitting_candidate() -> MultiClusterConfig {
    MultiClusterConfig {
        remote_clusters: vec![RemoteCluster {
            name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: Some("net2".to_string()),
            control_plane_url: Some("https://cp.remote.example:15010".to_string()),
            federation_endpoint: None,
            discovery_credential_ref: None,
        }],
        ..MultiClusterConfig::default()
    }
}

fn epoch_store(mesh: MeshConfig) -> Arc<RequestEpochStore> {
    let config = GatewayConfig {
        version: "1".to_string(),
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
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

/// The discoverer resolves BOTH local and remote workloads for a service, and
/// the remote target carries its (remote) locality so it tiers below local.
#[tokio::test]
async fn mesh_multicluster_discoverer_resolves_local_and_remote_targets() {
    let local_id = "spiffe://cluster.local/ns/default/sa/local";
    let remote_id = "spiffe://remote.local/ns/default/sa/remote";

    // Local slice: one local workload of `reviews`.
    let local_workloads = vec![workload(
        local_id,
        "reviews",
        "10.1.0.1",
        Some("us-east-1/zone-a"),
    )];
    let local_services = vec![service("reviews", &[local_id])];

    // Remote cluster contributes another `reviews` endpoint, already tagged
    // with a remote locality (as the discovery poller would).
    let remote = RemoteClusterEndpoints {
        workloads: vec![workload(
            remote_id,
            "reviews",
            "10.2.0.1",
            Some("remote-west/net2"),
        )],
        services: vec![service("reviews", &[remote_id])],
    };
    let snapshot = remote_snapshot(remote);

    // Merge (as the slice-apply path does) then run the discoverer.
    let (workloads, services) = merge_remote_endpoints_into_mesh(
        &local_workloads,
        &local_services,
        &snapshot,
        Some(&admitting_candidate()),
    );
    let mesh = MeshConfig {
        workloads,
        services,
        ..MeshConfig::default()
    };
    let discoverer = MeshServiceDiscoverer::new(
        epoch_store(mesh),
        "reviews".to_string(),
        "default".to_string(),
        None,
        1,
    );

    let targets = discoverer.discover().await.expect("discover succeeds");
    assert_eq!(targets.len(), 2, "both local and remote endpoints resolved");

    let local_target = targets
        .iter()
        .find(|t| t.host == "10.1.0.1")
        .expect("local target");
    assert_eq!(local_target.locality.as_deref(), Some("us-east-1/zone-a"));

    let remote_target = targets
        .iter()
        .find(|t| t.host == "10.2.0.1")
        .expect("remote target");
    assert_eq!(
        remote_target.locality.as_deref(),
        Some("remote-west/net2"),
        "remote endpoint carries remote locality so it tiers below local"
    );
}

/// End-to-end failover: with local + remote endpoints in one upstream and a
/// source locality matching the local region, the LB sends traffic ONLY to the
/// local endpoint while it is healthy, and fails over to the remote endpoint
/// once the local endpoint is ejected.
#[tokio::test]
async fn mesh_multicluster_load_balancer_fails_over_local_to_remote() {
    let upstream_id = "reviews-mc";
    let now = Utc::now();

    // Two targets: local (us-east-1) and remote (remote-west). Source locality
    // is us-east-1, so the local target is the preferred (same-region) tier and
    // the remote target is the fallback tier.
    let upstream = Upstream {
        id: upstream_id.to_string(),
        name: None,
        namespace: "default".to_string(),
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        targets: vec![
            UpstreamTarget {
                host: "10.1.0.1".to_string(),
                port: 8080,
                service_port_policy_key: None,
                weight: 1,
                tags: HashMap::new(),
                locality: Some("us-east-1/zone-a".to_string()),
                path: None,
            },
            UpstreamTarget {
                host: "10.2.0.1".to_string(),
                port: 8080,
                service_port_policy_key: None,
                weight: 1,
                tags: HashMap::new(),
                locality: Some("remote-west/net2".to_string()),
                path: None,
            },
        ],
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: Some("us-east-1/zone-a".to_string()),
        locality_lb_strict: false,
        locality_lb_setting: Some(UpstreamLocalityLbSetting::default()),
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    };

    let config = GatewayConfig {
        version: "1".to_string(),
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let lb = LoadBalancerCache::new(&config);

    // All healthy: every selection lands on the local (same-region) endpoint.
    for i in 0..20 {
        let selection = lb
            .select_target(upstream_id, &i.to_string(), None)
            .expect("target");
        assert_eq!(
            selection.target.host, "10.1.0.1",
            "healthy local endpoint must win the same-region tier"
        );
    }

    // Eject the local endpoint (active unhealthy, keyed `upstream_id::host:port`).
    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    active_unhealthy.insert(format!("{upstream_id}::10.1.0.1:8080"), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    // Failover: with the local endpoint ejected, the LB falls through to the
    // remote endpoint tier.
    for i in 0..20 {
        let selection = lb
            .select_target(upstream_id, &i.to_string(), Some(&health))
            .expect("failover target");
        assert_eq!(
            selection.target.host, "10.2.0.1",
            "remote endpoint must receive traffic once local is unhealthy"
        );
    }
}
