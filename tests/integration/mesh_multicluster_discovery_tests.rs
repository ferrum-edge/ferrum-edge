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
    GatewayConfig, LoadBalancerAlgorithm, MeshSdTopology, Upstream, UpstreamLocalityLbSetting,
    UpstreamTarget,
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
        true,
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
        MeshSdTopology::Ambient,
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

// ── Remote-discovery JWT audience binding (issue #2475) ─────────────────────
//
// Clusters B and C deliberately share the SAME JWT secret and the SAME issuer:
// the deprecated-but-supported `FERRUM_CP_DP_GRPC_JWT_SECRET` fallback posture.
// Signature + issuer + expiry alone therefore cannot tell B's discovery token
// apart from a token minted for C, which is exactly the cross-cluster
// acceptance the `aud` binding exists to close. Every test below stands up the
// REAL `MeshGrpcServer` verifier on loopback and drives it with the REAL
// production dialer (`NativeRemoteSource`) or a hand-minted token, so the
// assertions cover the wire path rather than a helper in isolation.

mod audience_binding {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use ferrum_edge::config::types::GatewayConfig;
    use ferrum_edge::grpc::auth::remote_discovery_audience;
    use ferrum_edge::grpc::dp_client::{GrpcJwtSecret, generate_dp_jwt_full};
    use ferrum_edge::grpc::mesh_server::MeshGrpcServer;
    use ferrum_edge::grpc::proto::MeshSubscribeRequest;
    use ferrum_edge::grpc::proto::mesh_config_sync_client::MeshConfigSyncClient;
    use ferrum_edge::identity::spiffe::TrustDomain;
    use ferrum_edge::modes::mesh::multicluster::{
        NativeRemoteSource, RemoteClusterPollContext, RemoteDiscoveryConfig,
        RemoteDiscoveryTlsConfig, RemoteServiceSource,
    };
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::{Channel, Server};

    /// Shared across BOTH clusters on purpose — this is the posture the
    /// audience binding has to defend.
    const SHARED_SECRET: &str = "shared-cross-cluster-secret-000000";
    const SHARED_ISSUER: &str = "ferrum-edge-cp-dp";
    const NAMESPACE: &str = "ferrum";
    const NODE_ID: &str = "dp-poller";
    const CLUSTER_B: &str = "cluster-b";
    const CLUSTER_C: &str = "cluster-c";

    struct ClusterCp {
        url: String,
        shutdown_tx: Option<oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    }

    impl ClusterCp {
        async fn shutdown(mut self) {
            if let Some(tx) = self.shutdown_tx.take() {
                let _ = tx.send(());
            }
            let _ = self.task.await;
        }
    }

    /// Stand up a real `MeshGrpcServer` on loopback for `cluster_audience`.
    /// `None` models a control plane with no `FERRUM_MESH_CLUSTER_AUDIENCE`.
    async fn start_cluster_cp(cluster_audience: Option<&str>) -> ClusterCp {
        let config = Arc::new(ArcSwap::new(Arc::new(GatewayConfig::default())));
        let (server, _tx) = MeshGrpcServer::builder(config, SHARED_SECRET.to_string())
            .expected_issuer(SHARED_ISSUER.to_string())
            .namespace(NAMESPACE.to_string())
            .cluster_audience(cluster_audience.map(str::to_string))
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind CP");
        let addr = listener.local_addr().expect("CP addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let incoming = TcpListenerStream::new(listener);
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        ClusterCp {
            url: format!("http://{addr}"),
            shutdown_tx: Some(shutdown_tx),
            task,
        }
    }

    /// A poll context declaring `cluster_name` (the target-cluster identifier)
    /// against `url`. The minted audience is derived from `cluster_name`, NOT
    /// from the URL — pointing a B-declared poll at C's endpoint is exactly the
    /// misrouted/replayed-token scenario.
    fn poll_ctx(cluster_name: &str, url: &str) -> RemoteClusterPollContext {
        RemoteClusterPollContext {
            cluster_name: cluster_name.to_string(),
            trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
            network: None,
            control_plane_url: url.to_string(),
            credential_ref: None,
            config: RemoteDiscoveryConfig {
                poll_interval: Duration::from_millis(50),
                request_timeout: Duration::from_secs(5),
                max_stale_age: None,
                production_mode: false,
                jwt_secret: Some(shared_secret()),
                node_id: NODE_ID.to_string(),
                namespace: NAMESPACE.to_string(),
                tls_config: RemoteDiscoveryTlsConfig::default(),
            },
        }
    }

    fn shared_secret() -> GrpcJwtSecret {
        GrpcJwtSecret::with_issuer(SHARED_SECRET.to_string(), SHARED_ISSUER.to_string())
    }

    /// Drive `MeshSubscribe` with a caller-supplied bearer token, bypassing the
    /// production dialer so missing / wrong / malformed audiences can be put on
    /// the wire directly.
    async fn subscribe_with_token(
        url: &str,
        token: &str,
        remote_discovery: bool,
    ) -> Result<(), tonic::Status> {
        let channel = Channel::from_shared(url.to_string())
            .expect("channel")
            .connect()
            .await
            .expect("connect to CP");
        let bearer: tonic::metadata::MetadataValue<_> =
            format!("Bearer {token}").parse().expect("bearer metadata");
        #[allow(clippy::result_large_err)]
        let mut client =
            MeshConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
                req.metadata_mut().insert("authorization", bearer.clone());
                Ok(req)
            });
        let request = MeshSubscribeRequest {
            node_id: NODE_ID.to_string(),
            ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
            namespace: NAMESPACE.to_string(),
            workload_spiffe_id: String::new(),
            labels: HashMap::new(),
            waypoint_name: String::new(),
            ambient_udp_source_scoping: false,
            remote_discovery,
        };
        client.mesh_subscribe(tonic::Request::new(request)).await?;
        Ok(())
    }

    /// Mint a discovery-shaped token with an arbitrary `aud`. Signed with the
    /// shared secret and shared issuer, so ONLY the audience distinguishes it.
    fn token_with_audience(audience: Option<&str>) -> String {
        generate_dp_jwt_full(
            SHARED_SECRET,
            NODE_ID,
            SHARED_ISSUER,
            Some(NAMESPACE),
            audience,
        )
        .expect("mint token")
    }

    /// Mint a token whose `aud` claim is an arbitrary JSON value, so malformed
    /// and multi-valued shapes can be exercised.
    fn token_with_raw_audience(audience: serde_json::Value) -> String {
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": NODE_ID,
            "iat": now,
            "exp": now + 600,
            "iss": SHARED_ISSUER,
            "role": "data_plane",
            "ns": NAMESPACE,
            "aud": audience,
        });
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(SHARED_SECRET.as_bytes()),
        )
        .expect("mint raw-audience token")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cluster_b_accepts_its_own_token_and_cluster_c_rejects_it() {
        let cp_b = start_cluster_cp(Some(CLUSTER_B)).await;
        let cp_c = start_cluster_cp(Some(CLUSTER_C)).await;

        // B's own discovery poll succeeds end to end through the production
        // dialer: the minted `aud` names B (derived from RemoteCluster.name,
        // not the endpoint URL) and B expects exactly that.
        let ctx_b = poll_ctx(CLUSTER_B, &cp_b.url);
        NativeRemoteSource::new(&ctx_b, shared_secret())
            .fetch()
            .await
            .expect("cluster B accepts a token minted for cluster B");

        // The SAME credential misrouted to C: same secret, same issuer, same
        // node/namespace — only the audience differs. C must refuse it.
        let ctx_b_at_c = poll_ctx(CLUSTER_B, &cp_c.url);
        let err = NativeRemoteSource::new(&ctx_b_at_c, shared_secret())
            .fetch()
            .await
            .expect_err("cluster C must refuse a token minted for cluster B");
        assert!(
            err.contains("MeshSubscribe failed"),
            "the poll must fail at subscribe time, before any endpoint import: {err}"
        );

        // Control: C accepts a poll actually declared for C, proving the
        // rejection above is the audience and not the shared harness.
        let ctx_c = poll_ctx(CLUSTER_C, &cp_c.url);
        NativeRemoteSource::new(&ctx_c, shared_secret())
            .fetch()
            .await
            .expect("cluster C accepts a token minted for cluster C");

        cp_b.shutdown().await;
        cp_c.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn both_clusters_reject_missing_wrong_and_malformed_audiences() {
        let cp_b = start_cluster_cp(Some(CLUSTER_B)).await;
        let cp_c = start_cluster_cp(Some(CLUSTER_C)).await;

        let b_audience = remote_discovery_audience(CLUSTER_B);
        let c_audience = remote_discovery_audience(CLUSTER_C);

        // Cases that are wrong for BOTH clusters, so every CP must refuse them.
        // The wrong-cluster case is deliberately NOT here: each cluster ACCEPTS
        // its own audience (that is what
        // `cluster_b_accepts_its_own_token_and_cluster_c_rejects_it` asserts),
        // so it has to be paired with the peer that did not mint it.
        let cases: Vec<(&str, String)> = vec![
            // Missing: an ordinary CP↔DP-shaped token carries no `aud` at all.
            ("missing", token_with_audience(None)),
            // Unprefixed bare cluster name: not this surface's audience.
            ("unprefixed", token_with_audience(Some(CLUSTER_B))),
        ];
        let raw_cases: Vec<(&str, String)> = vec![
            (
                "empty string",
                token_with_raw_audience(serde_json::json!("")),
            ),
            (
                "empty array",
                token_with_raw_audience(serde_json::json!([])),
            ),
            ("non-string", token_with_raw_audience(serde_json::json!(42))),
            (
                "non-string array",
                token_with_raw_audience(serde_json::json!([1, 2])),
            ),
            (
                "object",
                token_with_raw_audience(serde_json::json!({"cluster": CLUSTER_B})),
            ),
            // Ambiguous: naming both clusters must not be honored by either.
            (
                "ambiguous",
                token_with_raw_audience(serde_json::json!([b_audience, c_audience])),
            ),
        ];

        // Each cluster is additionally presented with the OTHER cluster's
        // audience — the misrouted/replayed token, in both directions.
        for (cp, wrong_label, wrong_audience) in [
            (&cp_b, "wrong (c at b)", c_audience.as_str()),
            (&cp_c, "wrong (b at c)", b_audience.as_str()),
        ] {
            let mut cp_cases = cases.clone();
            cp_cases.extend_from_slice(&raw_cases);
            cp_cases.push((wrong_label, token_with_audience(Some(wrong_audience))));
            for (label, token) in &cp_cases {
                let status = subscribe_with_token(&cp.url, token, true)
                    .await
                    .expect_err(&format!("{label} audience must be refused"));
                assert_eq!(
                    status.code(),
                    tonic::Code::Unauthenticated,
                    "{label} audience must fail authentication, not fall through"
                );
                assert!(
                    !status.message().contains(token.as_str()),
                    "{label}: the rejection must never echo the presented token"
                );
            }
        }

        cp_b.shutdown().await;
        cp_c.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unconfigured_control_plane_refuses_remote_discovery_but_serves_local() {
        // No FERRUM_MESH_CLUSTER_AUDIENCE: the CP cannot state which cluster it
        // is, so it must refuse every cross-cluster subscription rather than
        // accept an unbound one.
        let cp = start_cluster_cp(None).await;

        let status = subscribe_with_token(
            &cp.url,
            &token_with_audience(Some(&remote_discovery_audience(CLUSTER_B))),
            true,
        )
        .await
        .expect_err("an unconfigured CP must refuse cross-cluster discovery");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);

        // Even a token with no audience at all is refused on this class.
        let status = subscribe_with_token(&cp.url, &token_with_audience(None), true)
            .await
            .expect_err("an unconfigured CP refuses discovery regardless of the token");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);

        // Ordinary local mesh subscriptions are unaffected: unchanged token
        // shape, unchanged acceptance.
        subscribe_with_token(&cp.url, &token_with_audience(None), false)
            .await
            .expect("ordinary local mesh subscriptions keep working unchanged");

        cp.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discovery_token_cannot_be_downgraded_into_a_local_subscription() {
        // The `remote_discovery` flag is caller-supplied. Clearing it must not
        // launder a discovery token minted for B into a local subscription at
        // C (or anywhere else): the local branch refuses the reserved prefix.
        let cp_c = start_cluster_cp(Some(CLUSTER_C)).await;
        let b_token = token_with_audience(Some(&remote_discovery_audience(CLUSTER_B)));

        let status = subscribe_with_token(&cp_c.url, &b_token, false)
            .await
            .expect_err("a reserved discovery audience must not be honored as a local token");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);

        // C's own discovery audience is likewise not a local-subscription
        // credential — the two purposes are separated, not merely scoped.
        let c_token = token_with_audience(Some(&remote_discovery_audience(CLUSTER_C)));
        let status = subscribe_with_token(&cp_c.url, &c_token, false)
            .await
            .expect_err("even this cluster's discovery audience is not a local token");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);

        cp_c.shutdown().await;
    }
}
