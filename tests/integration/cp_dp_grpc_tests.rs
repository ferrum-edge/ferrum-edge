//! Tests for Control Plane / Data Plane gRPC communication.
//!
//! These tests verify that the DP client connects to the CP server,
//! receives initial config snapshots, and processes streaming config updates.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use tokio::time::timeout;
use tonic::transport::server::ServerTlsConfig;
use tonic::transport::{Certificate, Identity, Server};

use ferrum_edge::config::db_loader::IncrementalResult;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, DispatchKind, GatewayConfig, LoadBalancerAlgorithm, Proxy,
    Upstream, UpstreamTarget,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::grpc::cp_server::CpGrpcServer;
use ferrum_edge::grpc::dp_client::{self, DpGrpcTlsConfig, GrpcJwtSecret};
use ferrum_edge::grpc::mesh_server::MeshGrpcServer;
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshService, MeshWaypointBinding, MeshWaypointServiceRef, ServicePort,
    TrustBundle, TrustBundleSet, Workload, WorkloadPort, WorkloadSelector,
};
use ferrum_edge::modes::mesh::config_consumer::native_client::{
    NativeMeshClientConfig, start_native_mesh_client_with_shutdown,
};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::proxy::ProxyState;
use ferrum_edge::xds::{LDS_TYPE_URL, XdsAdsServer};

const TEST_JWT_SECRET: &str = "test-grpc-secret-key";

/// Wrap the test secret in `GrpcJwtSecret` for type-safe calls.
fn test_secret() -> GrpcJwtSecret {
    GrpcJwtSecret::new(TEST_JWT_SECRET.to_string())
}

/// Create a test Proxy entry.
fn create_test_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("Test Proxy {}", id)),
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".to_string(),
        backend_port: 3000,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],

        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Create a GatewayConfig with the given number of test proxies.
fn create_test_config(proxy_count: usize) -> GatewayConfig {
    let proxies: Vec<Proxy> = (0..proxy_count)
        .map(|i| create_test_proxy(&format!("proxy-{}", i), &format!("/api-{}", i)))
        .collect();
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

fn create_test_trust_bundles() -> TrustBundleSet {
    TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new("cluster.local").unwrap(),
            x509_authorities: vec!["AQIDBA==".to_string()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: Some(300),
        },
        federated: vec![TrustBundle {
            trust_domain: TrustDomain::new("remote.local").unwrap(),
            x509_authorities: vec!["BQYH".to_string()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        }],
    }
}

fn create_test_mesh_config() -> GatewayConfig {
    let trust_domain = TrustDomain::new("cluster.local").unwrap();
    let mut config = GatewayConfig {
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    config.mesh = Some(Box::new(MeshConfig {
        workloads: vec![Workload {
            spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/ferrum/sa/api").unwrap(),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "api".to_string())]),
                namespace: Some("ferrum".to_string()),
            },
            service_name: "api".to_string(),
            addresses: Vec::new(),
            ports: vec![WorkloadPort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain,
            namespace: "ferrum".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: "api".to_string(),
            namespace: "ferrum".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        }],
        ..MeshConfig::default()
    }));
    config
}

/// Create a minimal EnvConfig for testing (file mode with dummy path).
fn create_test_env_config() -> ferrum_edge::config::EnvConfig {
    ferrum_edge::config::EnvConfig {
        mode: ferrum_edge::config::env_config::OperatingMode::File,
        log_level: "info".into(),
        enable_streaming_latency_tracking: false,
        proxy_http_port: 8000,
        proxy_https_port: 8443,
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        proxy_bind_address: "0.0.0.0".into(),
        admin_http_port: 9000,
        admin_https_port: 9443,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_bind_address: "0.0.0.0".into(),
        allow_insecure_admin_http: false,
        admin_jwt_secret: None,
        db_type: None,
        db_url: None,
        db_poll_interval: 30,
        db_rejected_delta_backoff_initial_seconds: 1,
        db_rejected_delta_backoff_max_seconds: 30,
        db_rejected_delta_full_reload_threshold: 3,
        db_tls_mode: None,
        db_tls_ca_cert_path: None,
        db_tls_client_cert_path: None,
        db_tls_client_key_path: None,
        file_config_path: Some("/tmp/test-config.json".into()),
        db_config_backup_path: None,
        db_failover_urls: Vec::new(),
        db_read_replica_url: None,
        cp_grpc_listen_addr: None,
        cp_dp_grpc_jwt_secret: None,
        dp_cp_grpc_urls: Vec::new(),
        dp_cp_failover_primary_retry_secs: 300,
        cp_grpc_tls_cert_path: None,
        cp_grpc_tls_key_path: None,
        cp_grpc_tls_client_ca_path: None,
        dp_grpc_tls_ca_cert_path: None,
        dp_grpc_tls_client_cert_path: None,
        dp_grpc_tls_client_key_path: None,
        dp_grpc_tls_no_verify: false,
        max_header_size_bytes: 32768,
        max_single_header_size_bytes: 16384,
        max_request_body_size_bytes: 10_485_760,
        max_response_body_size_bytes: 10_485_760,
        response_buffer_cutoff_bytes: 65_536,
        h2_coalesce_target_bytes: 131_072,
        dns_ttl_override: None,
        dns_overrides: HashMap::new(),
        dns_resolver_address: None,
        dns_resolver_hosts_file: None,
        dns_order: None,
        dns_min_ttl: 5,
        dns_stale_ttl: 3600,
        dns_error_ttl: 1,
        dns_failed_retry_interval: 10,
        dns_warmup_concurrency: 500,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        tls_ca_bundle_path: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        frontend_tls_client_ca_bundle_path: None,
        admin_tls_client_ca_bundle_path: None,
        tls_no_verify: false,
        admin_read_only: false,
        admin_tls_no_verify: false,
        enable_http3: false,
        http3_idle_timeout: 30,
        http3_max_streams: 1000,
        http3_stream_receive_window: 8_388_608,
        http3_receive_window: 33_554_432,
        http3_send_window: 8_388_608,
        http3_connections_per_backend: 4,
        http3_pool_idle_timeout_seconds: 120,
        grpc_pool_ready_wait_ms: 1,
        pool_cleanup_interval_seconds: 30,
        tcp_idle_timeout_seconds: 300,
        udp_max_sessions: 10_000,
        udp_cleanup_interval_seconds: 10,
        tls_min_version: "1.2".into(),
        tls_max_version: "1.3".into(),
        tls_cipher_suites: None,
        tls_prefer_server_cipher_order: true,
        tls_curves: None,
        tls_session_cache_size: 4096,
        stream_proxy_bind_address: "0.0.0.0".into(),
        admin_allowed_cidrs: String::new(),
        trusted_proxies: String::new(),
        dns_cache_max_size: 10_000,
        dns_slow_threshold_ms: None,
        real_ip_header: None,
        dtls_cert_path: None,
        dtls_key_path: None,
        dtls_client_ca_cert_path: None,
        plugin_http_slow_threshold_ms: 1000,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        migrate_action: "up".into(),
        migrate_dry_run: false,
        worker_threads: None,
        blocking_threads: None,
        max_connections: 0,
        tcp_listen_backlog: 2048,
        server_http2_max_concurrent_streams: 250,
        ..Default::default()
    }
}

/// Create a ProxyState with empty config for DP testing.
fn create_test_proxy_state() -> ProxyState {
    let dns_cache = DnsCache::new(DnsConfig {
        global_overrides: HashMap::new(),
        resolver_addresses: None,
        hosts_file_path: None,
        dns_order: None,
        ttl_override_seconds: None,
        min_ttl_seconds: 5,
        stale_ttl_seconds: 3600,
        error_ttl_seconds: 1,
        max_cache_size: 10_000,
        warmup_concurrency: 500,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        slow_threshold_ms: None,
        refresh_threshold_percent: 90,
        failed_retry_interval_seconds: 10,
        try_tcp_on_error: true,
        num_concurrent_reqs: 3,
        max_active_requests: 512,
        max_concurrent_refreshes: 64,
        shard_amount: 0,
    });
    let env_config = create_test_env_config();
    let (state, _health_check_handles) =
        ProxyState::new(GatewayConfig::default(), dns_cache, env_config, None, None).unwrap();
    state
}

/// Start a CP gRPC server on a random port and return the address and broadcast sender.
async fn start_test_cp_server(
    config: GatewayConfig,
) -> (
    SocketAddr,
    tokio::sync::broadcast::Sender<ferrum_edge::grpc::proto::ConfigUpdate>,
    tokio::task::JoinHandle<()>,
) {
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let (server, update_tx) = CpGrpcServer::new(config_arc.clone(), TEST_JWT_SECRET.to_string());
    let (mesh_server, _mesh_update_tx) =
        MeshGrpcServer::new(config_arc, TEST_JWT_SECRET.to_string());

    // Bind to port 0 to get a random available port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .add_service(mesh_server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("gRPC server failed");
    });

    // Give the server a moment to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, update_tx, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_receives_initial_config_from_cp() {
    // Start CP server with 2 proxies
    let cp_config = create_test_config(2);
    let (addr, _update_tx, _server_handle) = start_test_cp_server(cp_config.clone()).await;

    // Create DP proxy state (starts empty)
    let proxy_state = create_test_proxy_state();
    assert_eq!(proxy_state.config.load().proxies.len(), 0);

    // Connect to CP and receive initial config (DP generates JWT from shared secret).
    //
    // `connect_and_subscribe` is a long-lived streaming subscription — it
    // only returns when the stream ends or errors. The previous
    // `timeout(5s, connect_and_subscribe(...))` therefore *always* burned
    // the full 5 s timeout window: the stream stays open, the timeout
    // fires, the test treats `Err(_)` as "success after we already saw
    // the config." Switching to spawn-and-poll drops this test from
    // ~5 s to under 100 ms.
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let node_id = "test-node-1";

    let ps = proxy_state.clone();
    let cp_url_clone = cp_url.clone();
    let secret = test_secret();
    let node_id_owned = node_id.to_string();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url_clone,
            &secret,
            &node_id_owned,
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "DP did not receive initial config within 5s"
    );

    let current_config = proxy_state.config.load();
    assert_eq!(
        current_config.proxies.len(),
        2,
        "DP should have received 2 proxies from CP"
    );
    assert_eq!(current_config.proxies[0].id, "proxy-0");
    assert_eq!(current_config.proxies[1].id, "proxy-1");

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_stores_gateway_trust_bundles_from_initial_snapshot() {
    let mut cp_config = create_test_config(1);
    cp_config.trust_bundles = Some(Box::new(create_test_trust_bundles()));
    let (addr, _update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "trust-bundle-node-1",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.gateway_trust_bundles.load().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "DP should store CP-delivered gateway trust bundles"
    );

    let loaded = proxy_state.gateway_trust_bundles.load_full();
    let trust_bundles = loaded.as_ref().as_ref().expect("trust bundles stored");
    assert_eq!(trust_bundles.local.trust_domain.as_str(), "cluster.local");
    assert_eq!(trust_bundles.local.x509_authorities, vec![vec![1, 2, 3, 4]]);
    assert_eq!(trust_bundles.federated.len(), 1);
    assert!(
        proxy_state.config.load().trust_bundles.is_none(),
        "DP-facing GatewayConfig JSON should not carry trust bundles"
    );
    assert!(proxy_state.gateway_svid_bundle.load().is_none());

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_stores_gateway_trust_bundles_from_delta_side_channel() {
    let cp_config = create_test_config(1);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "trust-bundle-node-2",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    let received_initial = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received_initial.is_ok(), "DP should receive initial config");

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    let trust_bundles = create_test_trust_bundles();
    CpGrpcServer::broadcast_delta_with_trust_bundles(
        &update_tx,
        &delta,
        "trust-bundles-v2",
        Some(&trust_bundles),
    );

    let received_trust = timeout(Duration::from_secs(5), async {
        loop {
            let loaded = proxy_state.gateway_trust_bundles.load();
            if loaded
                .as_ref()
                .as_ref()
                .is_some_and(|tb| tb.local.x509_authorities == vec![vec![1, 2, 3, 4]])
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_trust.is_ok(),
        "DP should apply gateway trust bundles from delta side-channel"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_gateway_trust_bundles_from_rejected_delta() {
    let cp_config = create_test_config(1);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "trust-bundle-rejected-delta-node",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    let received_initial = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received_initial.is_ok(), "DP should receive initial config");

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![create_test_proxy("proxy-conflict", "/api-0")],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    let trust_bundles = create_test_trust_bundles();
    CpGrpcServer::broadcast_delta_with_trust_bundles(
        &update_tx,
        &delta,
        "trust-bundles-rejected-delta",
        Some(&trust_bundles),
    );

    let received_trust = timeout(Duration::from_secs(5), async {
        loop {
            let loaded = proxy_state.gateway_trust_bundles.load();
            if loaded
                .as_ref()
                .as_ref()
                .is_some_and(|tb| tb.local.x509_authorities == vec![vec![1, 2, 3, 4]])
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_trust.is_ok(),
        "DP should apply valid gateway trust bundles even when resource delta is rejected"
    );
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        1,
        "Rejected resource delta must not mutate the gateway config"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_clears_gateway_trust_bundles_from_explicit_side_channel_null() {
    let mut cp_config = create_test_config(1);
    cp_config.trust_bundles = Some(Box::new(create_test_trust_bundles()));
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "trust-bundle-node-3",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    let received_initial = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.gateway_trust_bundles.load().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_initial.is_ok(),
        "DP should receive initial gateway trust bundles"
    );

    let cleared_config = create_test_config(1);
    CpGrpcServer::broadcast_update(&update_tx, &cleared_config);

    let cleared = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.gateway_trust_bundles.load().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        cleared.is_ok(),
        "DP should clear CP-delivered trust bundles when CP sends side-channel null"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mesh_subscribe_receives_initial_mesh_slice() {
    let cp_config = create_test_mesh_config();
    let (addr, _update_tx, _server_handle) = start_test_cp_server(cp_config).await;
    let token = dp_client::generate_dp_jwt(TEST_JWT_SECRET, "mesh-node").unwrap();
    let auth_header = format!("Bearer {token}");
    let channel =
        tonic::transport::Channel::from_shared(format!("http://127.0.0.1:{}", addr.port()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client =
        ferrum_edge::grpc::proto::mesh_config_sync_client::MeshConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut().insert(
                    "authorization",
                    tonic::metadata::MetadataValue::try_from(auth_header.as_str()).unwrap(),
                );
                Ok(req)
            },
        );

    let request = tonic::Request::new(ferrum_edge::grpc::proto::MeshSubscribeRequest {
        node_id: "mesh-node".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
        workload_spiffe_id: "spiffe://cluster.local/ns/ferrum/sa/api".to_string(),
        labels: HashMap::from([("app".to_string(), "api".to_string())]),
        waypoint_name: String::new(),
    });
    let mut stream = client.mesh_subscribe(request).await.unwrap().into_inner();
    let update = stream.message().await.unwrap().unwrap();
    let slice: ferrum_edge::modes::mesh::slice::MeshSlice =
        serde_json::from_str(&update.mesh_slice_json).unwrap();

    assert_eq!(slice.node_id, "mesh-node");
    assert_eq!(slice.services.len(), 1);
    assert_eq!(slice.services[0].name, "api");
    assert_eq!(slice.workloads.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mesh_subscribe_waypoint_name_narrows_initial_slice() {
    let mut cp_config = GatewayConfig {
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    cp_config.mesh = Some(Box::new(MeshConfig {
        services: vec![
            MeshService {
                cluster_ips: Vec::new(),
                name: "api".to_string(),
                namespace: "ferrum".to_string(),
                ports: vec![ServicePort {
                    port: 8080,
                    protocol: AppProtocol::Http,
                    name: Some("http".to_string()),
                    target_port: None,
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            },
            MeshService {
                cluster_ips: Vec::new(),
                name: "billing".to_string(),
                namespace: "ferrum".to_string(),
                ports: vec![ServicePort {
                    port: 9090,
                    protocol: AppProtocol::Http,
                    name: Some("http".to_string()),
                    target_port: None,
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            },
        ],
        waypoint_bindings: vec![MeshWaypointBinding {
            name: "api-waypoint".to_string(),
            namespace: "ferrum".to_string(),
            waypoint_for: "service".to_string(),
            services: vec![MeshWaypointServiceRef {
                namespace: "ferrum".to_string(),
                name: "api".to_string(),
            }],
        }],
        ..MeshConfig::default()
    }));

    let (addr, _update_tx, _server_handle) = start_test_cp_server(cp_config).await;
    let token = dp_client::generate_dp_jwt(TEST_JWT_SECRET, "mesh-node").unwrap();
    let auth_header = format!("Bearer {token}");
    let channel =
        tonic::transport::Channel::from_shared(format!("http://127.0.0.1:{}", addr.port()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client =
        ferrum_edge::grpc::proto::mesh_config_sync_client::MeshConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut().insert(
                    "authorization",
                    tonic::metadata::MetadataValue::try_from(auth_header.as_str()).unwrap(),
                );
                Ok(req)
            },
        );

    let request = tonic::Request::new(ferrum_edge::grpc::proto::MeshSubscribeRequest {
        node_id: "mesh-node".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
        workload_spiffe_id: String::new(),
        labels: HashMap::new(),
        waypoint_name: "api-waypoint".to_string(),
    });
    let mut stream = client.mesh_subscribe(request).await.unwrap().into_inner();
    let update = stream.message().await.unwrap().unwrap();
    let slice: ferrum_edge::modes::mesh::slice::MeshSlice =
        serde_json::from_str(&update.mesh_slice_json).unwrap();

    assert_eq!(slice.waypoint_name.as_deref(), Some("api-waypoint"));
    assert_eq!(slice.services.len(), 1);
    assert_eq!(slice.services[0].name, "api");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_native_mesh_client_installs_mesh_slice_from_cp() {
    let cp_config = create_test_mesh_config();
    let (addr, _update_tx, _server_handle) = start_test_cp_server(cp_config).await;
    let state = MeshRuntimeState::new();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let client_config = NativeMeshClientConfig {
        node_id: "mesh-node".to_string(),
        namespace: "ferrum".to_string(),
        workload_spiffe_id: Some("spiffe://cluster.local/ns/ferrum/sa/api".to_string()),
        waypoint_name: None,
        labels: HashMap::from([("app".to_string(), "api".to_string())]),
        primary_retry_secs: 0,
    };
    let handle = tokio::spawn(start_native_mesh_client_with_shutdown(
        vec![format!("http://127.0.0.1:{}", addr.port())],
        test_secret(),
        client_config,
        state.clone(),
        shutdown_rx,
        None,
        None,
    ));

    timeout(Duration::from_secs(5), state.wait_for_first_slice())
        .await
        .expect("native mesh client should install first slice");
    let snapshot = state.snapshot();
    let slice = snapshot.as_ref().as_ref().expect("slice installed");
    assert_eq!(slice.node_id, "mesh-node");
    assert_eq!(slice.services.len(), 1);
    assert_eq!(slice.workloads.len(), 1);

    shutdown_tx.send(true).expect("shutdown signal sent");
    timeout(Duration::from_secs(2), handle)
        .await
        .expect("native mesh client should exit on shutdown")
        .expect("native mesh client task should not panic");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_xds_ads_stream_returns_lds_snapshot() {
    let config_arc = Arc::new(ArcSwap::new(Arc::new(create_test_mesh_config())));
    let (_cp_server, update_tx) =
        CpGrpcServer::new(config_arc.clone(), TEST_JWT_SECRET.to_string());
    let xds_server = XdsAdsServer::new(
        config_arc,
        update_tx,
        TEST_JWT_SECRET.to_string(),
        ferrum_edge::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER.to_string(),
        "ferrum".to_string(),
        32,
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let _server_handle = tokio::spawn(async move {
        Server::builder()
            .add_service(xds_server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("xDS server failed");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let channel =
        tonic::transport::Channel::from_shared(format!("http://127.0.0.1:{}", addr.port()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client =
        ferrum_edge::xds::proto::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient::new(
            channel,
        );
    let token = dp_client::generate_dp_jwt(TEST_JWT_SECRET, "xds-node").unwrap();
    let requests = tokio_stream::iter(vec![ferrum_edge::xds::proto::DiscoveryRequest {
        version_info: String::new(),
        node: Some(ferrum_edge::xds::proto::Node {
            id: "xds-node".to_string(),
            cluster: String::new(),
            metadata: Vec::new(),
        }),
        resource_names: vec!["*".to_string()],
        type_url: LDS_TYPE_URL.to_string(),
        response_nonce: String::new(),
        error_detail: None,
    }]);
    let mut request = tonic::Request::new(requests);
    request.metadata_mut().insert(
        "authorization",
        tonic::metadata::MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );

    let mut stream = client
        .stream_aggregated_resources(request)
        .await
        .unwrap()
        .into_inner();
    let response = stream.message().await.unwrap().unwrap();

    assert_eq!(response.type_url, LDS_TYPE_URL);
    assert_eq!(response.resources.len(), 1);
    assert!(!response.version_info.is_empty());
    assert!(!response.nonce.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_xds_ads_per_node_stream_cap_rejects_excess_streams() {
    use ferrum_edge::xds::proto::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
    use ferrum_edge::xds::proto::{DiscoveryRequest, Node};

    let config_arc = Arc::new(ArcSwap::new(Arc::new(create_test_mesh_config())));
    let (_cp_server, update_tx) =
        CpGrpcServer::new(config_arc.clone(), TEST_JWT_SECRET.to_string());
    // Cap concurrent ADS streams per node id at 1.
    let xds_server = XdsAdsServer::new(
        config_arc,
        update_tx,
        TEST_JWT_SECRET.to_string(),
        ferrum_edge::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER.to_string(),
        "ferrum".to_string(),
        32,
    )
    .with_max_streams_per_node(1);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let _server_handle = tokio::spawn(async move {
        Server::builder()
            .add_service(xds_server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("xDS server failed");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("http://127.0.0.1:{}", addr.port());
    let token = dp_client::generate_dp_jwt(TEST_JWT_SECRET, "capped-node").unwrap();
    let bearer =
        move || tonic::metadata::MetadataValue::try_from(format!("Bearer {token}")).unwrap();
    let lds_request = || DiscoveryRequest {
        version_info: String::new(),
        node: Some(Node {
            id: "capped-node".to_string(),
            cluster: String::new(),
            metadata: Vec::new(),
        }),
        resource_names: vec!["*".to_string()],
        type_url: LDS_TYPE_URL.to_string(),
        response_nonce: String::new(),
        error_detail: None,
    };

    // First stream: keep the request sender alive so the stream stays open.
    let channel_one = tonic::transport::Channel::from_shared(url.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client_one = AggregatedDiscoveryServiceClient::new(channel_one);
    let (req_tx_one, req_rx_one) = tokio::sync::mpsc::channel::<DiscoveryRequest>(4);
    req_tx_one.send(lds_request()).await.unwrap();
    let mut request_one =
        tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(req_rx_one));
    request_one.metadata_mut().insert("authorization", bearer());
    let mut stream_one = client_one
        .stream_aggregated_resources(request_one)
        .await
        .unwrap()
        .into_inner();
    // Drain the first response so the server has registered the node stream.
    let first = stream_one.message().await.unwrap().unwrap();
    assert_eq!(first.type_url, LDS_TYPE_URL);

    // Second concurrent stream for the SAME node id must be rejected once its
    // first request resolves the node id and trips the per-node ceiling.
    let channel_two = tonic::transport::Channel::from_shared(url)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client_two = AggregatedDiscoveryServiceClient::new(channel_two);
    let (req_tx_two, req_rx_two) = tokio::sync::mpsc::channel::<DiscoveryRequest>(4);
    req_tx_two.send(lds_request()).await.unwrap();
    let mut request_two =
        tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(req_rx_two));
    request_two.metadata_mut().insert("authorization", bearer());
    let mut stream_two = client_two
        .stream_aggregated_resources(request_two)
        .await
        .unwrap()
        .into_inner();
    let rejection = timeout(Duration::from_secs(5), stream_two.message())
        .await
        .expect("second stream resolves quickly")
        .expect_err("second concurrent stream for the node must be rejected");
    assert_eq!(rejection.code(), tonic::Code::ResourceExhausted);
    assert!(
        rejection
            .message()
            .contains("per-node concurrent stream limit"),
        "unexpected rejection message: {}",
        rejection.message()
    );

    // Keep the first stream's sender alive until the assertion completes so the
    // ceiling is genuinely exercised against a live concurrent stream.
    drop(req_tx_one);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_receives_config_updates() {
    // Start CP server with initial config of 1 proxy
    let cp_config = create_test_config(1);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    // Create DP proxy state (starts empty)
    let proxy_state = create_test_proxy_state();

    // Spawn the DP client in the background (DP generates JWT from shared secret)
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "test-node-2",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    // Wait for initial config to arrive
    let received_initial = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_initial.is_ok(),
        "DP should have received initial config with 1 proxy"
    );

    // Now broadcast an updated config with 3 proxies
    let updated_config = create_test_config(3);
    CpGrpcServer::broadcast_update(&update_tx, &updated_config);

    // Wait for the update to arrive
    let received_update = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_update.is_ok(),
        "DP should have received updated config with 3 proxies"
    );

    let current_config = proxy_state.config.load();
    assert_eq!(current_config.proxies.len(), 3);
    assert_eq!(current_config.proxies[2].id, "proxy-2");

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_rejects_invalid_token() {
    // Start CP server
    let cp_config = create_test_config(1);
    let (addr, _update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    // DP uses a WRONG secret — the JWT it generates won't verify on the CP
    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let result = timeout(
        Duration::from_secs(5),
        dp_client::connect_and_subscribe(
            &cp_url,
            &GrpcJwtSecret::new("wrong-secret-key".to_string()),
            "bad-node",
            &proxy_state,
            None,
            "ferrum",
        ),
    )
    .await;

    match result {
        Ok(Err(e)) => {
            // Should get an authentication error
            let err_msg = format!("{}", e);
            assert!(
                err_msg.contains("Unauthenticated")
                    || err_msg.contains("unauthenticated")
                    || err_msg.contains("token"),
                "Expected authentication error, got: {}",
                err_msg
            );
        }
        Ok(Ok(())) => panic!("Should have rejected invalid token"),
        Err(_) => panic!("Should have responded before timeout"),
    }

    // Verify proxy state was NOT updated
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        0,
        "Config should remain empty after auth failure"
    );
}

/// Verify that the CP rejects correctly-signed JWTs that are missing required claims.
///
/// This uses a raw tonic client (bypassing `dp_client::connect_and_subscribe`) to
/// craft a token with the correct secret but missing `sub` and `iat` claims.
/// This exercises the CP's `verify_jwt_metadata()` defense-in-depth validation.
#[tokio::test(flavor = "multi_thread")]
async fn test_cp_rejects_token_missing_required_claims() {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::json;

    let cp_config = create_test_config(1);
    let (addr, _update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    // Create a token signed with the correct secret but missing required claims (no sub, no iat)
    let now = chrono::Utc::now().timestamp();
    let minimal_claims = json!({"exp": now + 3600, "role": "data_plane"});
    let token_no_sub = encode(
        &Header::new(Algorithm::HS256),
        &minimal_claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .unwrap();

    // Connect directly via tonic (bypassing dp_client which always generates valid tokens)
    let channel =
        tonic::transport::Channel::from_shared(format!("http://127.0.0.1:{}", addr.port()))
            .unwrap()
            .connect()
            .await
            .unwrap();

    let token_meta: tonic::metadata::MetadataValue<_> =
        format!("Bearer {}", token_no_sub).parse().unwrap();
    let mut client =
        ferrum_edge::grpc::proto::config_sync_client::ConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        );

    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "missing-claims-node".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
    });

    let result = client.subscribe(request).await;
    assert!(
        result.is_err(),
        "CP should reject token missing required claims"
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Expected Unauthenticated error, got: {}",
        status
    );
}

/// Helper: connect a tonic channel + interceptor that attaches `token` as the
/// bearer credential, and yield a `ConfigSyncClient` ready to issue calls. A
/// macro (rather than a fn returning `impl Future<Output = ConfigSyncClient<…>>`)
/// keeps the concrete client type local to each test, so clippy's
/// `type_complexity` rule does not fire on the function signature.
macro_rules! connect_client_with_token {
    ($bound_addr:expr, $token:expr) => {{
        let channel = tonic::transport::Channel::from_shared(format!(
            "http://127.0.0.1:{}",
            $bound_addr.port()
        ))
        .unwrap()
        .connect()
        .await
        .unwrap();
        let token_meta: tonic::metadata::MetadataValue<_> =
            format!("Bearer {}", $token).parse().unwrap();
        ferrum_edge::grpc::proto::config_sync_client::ConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        )
    }};
}

macro_rules! connect_mesh_client_with_token {
    ($bound_addr:expr, $token:expr) => {{
        let channel = tonic::transport::Channel::from_shared(format!(
            "http://127.0.0.1:{}",
            $bound_addr.port()
        ))
        .unwrap()
        .connect()
        .await
        .unwrap();
        let token_meta: tonic::metadata::MetadataValue<_> =
            format!("Bearer {}", $token).parse().unwrap();
        ferrum_edge::grpc::proto::mesh_config_sync_client::MeshConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        )
    }};
}

/// Default issuer used by `start_test_cp_server`'s `CpGrpcServer::new()` path.
const TEST_DEFAULT_ISSUER: &str = "ferrum-edge-cp-dp";

/// Verify that the CP accepts a DP token whose `iss` claim matches the
/// configured expected issuer. Sanity check that the new issuer enforcement
/// does not break the happy path.
#[tokio::test(flavor = "multi_thread")]
async fn test_cp_accepts_token_with_matching_issuer() {
    let cp_config = create_test_config(1);
    let (addr, _update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    // Mint a token with the default issuer that the test CP expects.
    let token =
        dp_client::generate_dp_jwt_with_issuer(TEST_JWT_SECRET, "iss-good", TEST_DEFAULT_ISSUER)
            .unwrap();
    let mut client = connect_client_with_token!(addr, token);

    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "iss-good".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
    });

    let result = client.subscribe(request).await;
    assert!(
        result.is_ok(),
        "CP should accept token with matching issuer, got: {:?}",
        result.err()
    );
}

/// Verify that the CP rejects a DP token whose `iss` claim does not match
/// the configured expected issuer. This is the core security fix: a token
/// signed with the same shared secret but bearing a different `iss` (e.g.
/// from a sibling service that reused the secret) must NOT authenticate.
#[tokio::test(flavor = "multi_thread")]
async fn test_cp_rejects_token_with_wrong_issuer() {
    let cp_config = create_test_config(1);
    let (addr, _update_tx, server_handle) = start_test_cp_server(cp_config).await;

    // Mint a token signed with the correct secret but bearing a foreign issuer.
    let token =
        dp_client::generate_dp_jwt_with_issuer(TEST_JWT_SECRET, "iss-bad", "some-other-service")
            .unwrap();
    let mut client = connect_client_with_token!(addr, token);

    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "iss-bad".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
    });

    let result = client.subscribe(request).await;
    assert!(
        result.is_err(),
        "CP should reject token with wrong issuer (cross-service replay)"
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Expected Unauthenticated, got: {}",
        status
    );

    server_handle.abort();
}

/// `MeshSubscribe` shares the same CP/DP JWT security boundary as the
/// classic DP Subscribe stream. Cover it explicitly so mesh config cannot
/// accidentally drift into a weaker auth path.
#[tokio::test(flavor = "multi_thread")]
async fn test_mesh_subscribe_rejects_token_with_wrong_issuer() {
    let cp_config = create_test_mesh_config();
    let (addr, _update_tx, server_handle) = start_test_cp_server(cp_config).await;

    let token = dp_client::generate_dp_jwt_with_issuer(
        TEST_JWT_SECRET,
        "mesh-iss-bad",
        "some-other-service",
    )
    .unwrap();
    let mut client = connect_mesh_client_with_token!(addr, token);

    let request = tonic::Request::new(ferrum_edge::grpc::proto::MeshSubscribeRequest {
        node_id: "mesh-iss-bad".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
        workload_spiffe_id: "spiffe://cluster.local/ns/ferrum/sa/api".to_string(),
        labels: HashMap::from([("app".to_string(), "api".to_string())]),
        waypoint_name: String::new(),
    });

    let result = client.mesh_subscribe(request).await;
    assert!(
        result.is_err(),
        "CP should reject MeshSubscribe token with wrong issuer"
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Expected Unauthenticated, got: {}",
        status
    );

    server_handle.abort();
}

/// Verify that the CP rejects a DP token that has no `iss` claim at all.
/// Pre-fix DPs (or any third-party token) without `iss` would have passed
/// the old `exp/iat/sub` check; now they must be rejected.
#[tokio::test(flavor = "multi_thread")]
async fn test_cp_rejects_token_with_no_issuer_claim() {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::json;

    let cp_config = create_test_config(1);
    let (addr, _update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    // Hand-craft a token that has all OLD required claims (exp/iat/sub) but
    // no `iss` claim, signed with the correct shared secret.
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "sub": "iss-missing",
        "iat": now,
        "exp": now + 3600,
        "role": "data_plane",
    });
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .unwrap();

    let mut client = connect_client_with_token!(addr, token);

    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "iss-missing".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
    });

    let result = client.subscribe(request).await;
    assert!(
        result.is_err(),
        "CP should reject token missing the `iss` claim"
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Expected Unauthenticated, got: {}",
        status
    );
}

/// Verify that issuer enforcement does not weaken the existing wrong-secret
/// rejection: a token signed with the WRONG secret must still be rejected
/// even if it carries a correct `iss`. Regression-protects against an
/// implementation that, for example, validated `iss` first and ignored the
/// signature check on issuer mismatch.
#[tokio::test(flavor = "multi_thread")]
async fn test_cp_still_rejects_token_signed_with_wrong_secret() {
    let cp_config = create_test_config(1);
    let (addr, _update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    // Token bearing the correct issuer but signed with a different secret.
    let token = dp_client::generate_dp_jwt_with_issuer(
        "totally-different-secret",
        "iss-wrong-key",
        TEST_DEFAULT_ISSUER,
    )
    .unwrap();
    let mut client = connect_client_with_token!(addr, token);

    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "iss-wrong-key".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
    });

    let result = client.subscribe(request).await;
    assert!(
        result.is_err(),
        "CP must still reject tokens signed with the wrong secret"
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Expected Unauthenticated, got: {}",
        status
    );
}

/// Verify that a CP configured with a non-default expected issuer accepts
/// tokens with the matching custom issuer and rejects tokens with the
/// default issuer. This exercises the
/// `with_channel_capacity_registry_and_issuer` constructor that production
/// uses to thread `FERRUM_CP_DP_GRPC_JWT_ISSUER` through.
#[tokio::test(flavor = "multi_thread")]
async fn test_cp_with_custom_issuer_accepts_only_matching_tokens() {
    use ferrum_edge::grpc::cp_server::{CpGrpcServer, DpNodeRegistry};

    const CUSTOM_ISSUER: &str = "my-fleet.cp-dp";

    let config = create_test_config(1);
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let (server, _update_tx) = CpGrpcServer::with_channel_capacity_registry_and_issuer(
        config_arc,
        TEST_JWT_SECRET.to_string(),
        128,
        Arc::new(DpNodeRegistry::new()),
        CUSTOM_ISSUER.to_string(),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound_addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Token with the custom issuer the CP expects: accepted.
    let good_token =
        dp_client::generate_dp_jwt_with_issuer(TEST_JWT_SECRET, "custom-good", CUSTOM_ISSUER)
            .unwrap();
    let mut good_client = connect_client_with_token!(bound_addr, good_token);
    let good_req = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "custom-good".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
    });
    assert!(
        good_client.subscribe(good_req).await.is_ok(),
        "CP with custom issuer should accept matching token"
    );

    // Token with the *default* issuer must now be rejected — this proves the
    // expected-issuer string was actually plumbed through the constructor.
    let stale_token =
        dp_client::generate_dp_jwt_with_issuer(TEST_JWT_SECRET, "custom-bad", TEST_DEFAULT_ISSUER)
            .unwrap();
    let mut stale_client = connect_client_with_token!(bound_addr, stale_token);
    let stale_req = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "custom-bad".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
    });
    let stale_result = stale_client.subscribe(stale_req).await;
    assert!(
        stale_result.is_err(),
        "CP with custom issuer must reject default-issuer tokens"
    );
    assert_eq!(
        stale_result.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );

    server_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_handles_malformed_config() {
    // Start CP server with valid initial config
    let cp_config = create_test_config(1);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    // Spawn DP client (DP generates JWT from shared secret)
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "test-node-malformed",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    // Wait for initial config
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received.is_ok(), "Should receive initial config");

    // Send a malformed config update (invalid JSON that can't deserialize to GatewayConfig)
    let malformed_update = ferrum_edge::grpc::proto::ConfigUpdate {
        update_type: 0,
        config_json: "{invalid json!!!}".to_string(),
        version: "bad".to_string(),
        timestamp: chrono::Utc::now().timestamp(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        trust_bundles_json: String::new(),
    };
    let _ = update_tx.send(malformed_update);

    // Wait a bit then verify the config wasn't corrupted
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Config should still have the valid initial config (1 proxy)
    let current_config = proxy_state.config.load();
    assert_eq!(
        current_config.proxies.len(),
        1,
        "Config should remain unchanged after malformed update"
    );

    // Now send a valid update to prove the client is still alive
    let valid_config = create_test_config(2);
    CpGrpcServer::broadcast_update(&update_tx, &valid_config);

    let recovered = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "Client should recover and process valid updates after malformed one"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_rejects_snapshot_with_invalid_proxy_hosts() {
    let cp_config = create_test_config(1);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "test-node-invalid-host",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received.is_ok(), "Should receive initial config");
    assert_eq!(proxy_state.config.load().proxies[0].id, "proxy-0");

    let mut invalid_config = create_test_config(1);
    invalid_config.proxies[0].id = "bad-host".to_string();
    invalid_config.proxies[0].hosts = vec!["api..example.com".to_string()];
    CpGrpcServer::broadcast_update(&update_tx, &invalid_config);

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        proxy_state.config.load().proxies[0].id,
        "proxy-0",
        "DP must keep the last valid config after an invalid host snapshot"
    );

    let valid_config = create_test_config(2);
    CpGrpcServer::broadcast_update(&update_tx, &valid_config);
    let recovered = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "Client should continue processing valid updates after rejecting invalid hosts"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_preserves_config_after_cp_shutdown() {
    // This test verifies that when the CP goes down, the DP preserves its cached config
    // and the start_dp_client_with_shutdown loop keeps running (doesn't crash).

    // Start CP server with initial config
    let cp_config = create_test_config(2);
    let (addr, _update_tx, server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    // Use the DP client loop with auto-reconnect logic.
    let ps = proxy_state.clone();
    let url_clone = cp_url.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            vec![url_clone],
            test_secret(),
            ps,
            None,
            None,
            None,
            None,
            "ferrum".to_string(),
            0,
            None,
            None,
        )
        .await;
    });

    // Wait for initial config
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "Should receive initial config with 2 proxies"
    );

    // Shut down CP server
    server_handle.abort();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify cached config is preserved (the key behavior)
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        2,
        "Cached config should be preserved after CP shutdown"
    );
    assert_eq!(proxy_state.config.load().proxies[0].id, "proxy-0");
    assert_eq!(proxy_state.config.load().proxies[1].id, "proxy-1");

    // Verify the client task is still alive (not crashed) — it should be retrying
    assert!(
        !client_handle.is_finished(),
        "DP client should still be running (retrying connection)"
    );

    client_handle.abort();
}

// ── TLS / mTLS tests ─────────────────────────────────────────────────────────

/// Generate a self-signed CA + leaf certificate for testing.
/// Returns (ca_cert_pem, server_cert_pem, server_key_pem).
fn generate_test_ca_and_server_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Generate CA key pair and self-signed CA cert
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec!["Ferrum Test CA".to_string()]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();
    let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

    // Generate server key pair and cert signed by the CA
    let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut server_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));
    let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

    (
        ca_pem.into_bytes(),
        server_cert.pem().into_bytes(),
        server_key.serialize_pem().into_bytes(),
    )
}

/// Start a CP gRPC server with TLS on a random port.
async fn start_test_cp_server_with_tls(
    config: GatewayConfig,
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    client_ca_pem: Option<&[u8]>,
) -> (
    SocketAddr,
    tokio::sync::broadcast::Sender<ferrum_edge::grpc::proto::ConfigUpdate>,
    tokio::task::JoinHandle<()>,
) {
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let (server, update_tx) = CpGrpcServer::new(config_arc, TEST_JWT_SECRET.to_string());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut tls_config =
        ServerTlsConfig::new().identity(Identity::from_pem(server_cert_pem, server_key_pem));
    if let Some(ca_pem) = client_ca_pem {
        tls_config = tls_config.client_ca_root(Certificate::from_pem(ca_pem));
    }

    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let handle = tokio::spawn(async move {
        Server::builder()
            .tls_config(tls_config)
            .expect("Failed to configure TLS")
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("gRPC TLS server failed");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, update_tx, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_connects_to_cp_with_tls() {
    // Generate CA + server cert
    let (ca_pem, server_cert_pem, server_key_pem) = generate_test_ca_and_server_cert();

    // Start CP server with TLS
    let cp_config = create_test_config(2);
    let (addr, _update_tx, _server_handle) =
        start_test_cp_server_with_tls(cp_config.clone(), &server_cert_pem, &server_key_pem, None)
            .await;

    // Create DP with TLS config (CA cert to verify server)
    let proxy_state = create_test_proxy_state();
    let cp_url = format!("https://127.0.0.1:{}", addr.port());

    let tls_config = DpGrpcTlsConfig {
        ca_cert_pem: Some(ca_pem),
        client_cert_pem: None,
        client_key_pem: None,
    };

    // See `test_dp_receives_initial_config_from_cp` for why this is
    // spawn-and-poll rather than `timeout(secs(5), connect_and_subscribe)`.
    let ps = proxy_state.clone();
    let cp_url_clone = cp_url.clone();
    let secret = test_secret();
    let tls = tls_config.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url_clone,
            &secret,
            "tls-node-1",
            &ps,
            Some(&tls),
            "ferrum",
        )
        .await
    });

    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "DP did not receive initial config over TLS within 5s"
    );

    let current_config = proxy_state.config.load();
    assert_eq!(
        current_config.proxies.len(),
        2,
        "DP should have received 2 proxies from CP over TLS"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_connects_to_cp_with_mtls() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Generate CA for both server and client certs
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec!["Ferrum Test CA".to_string()]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem().into_bytes();
    let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

    // Generate server cert signed by CA
    let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut server_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));
    let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();
    let server_cert_pem = server_cert.pem().into_bytes();
    let server_key_pem = server_key.serialize_pem().into_bytes();

    // Generate client cert signed by the same CA
    let client_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let client_params = rcgen::CertificateParams::new(vec!["dp-client".to_string()]).unwrap();
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();
    let client_cert_pem = client_cert.pem().into_bytes();
    let client_key_pem = client_key.serialize_pem().into_bytes();

    // Start CP with mTLS (requires client certs verified against the CA)
    let cp_config = create_test_config(3);
    let (addr, _update_tx, _server_handle) = start_test_cp_server_with_tls(
        cp_config.clone(),
        &server_cert_pem,
        &server_key_pem,
        Some(&ca_pem),
    )
    .await;

    // Create DP with mTLS config (CA cert + client cert/key)
    let proxy_state = create_test_proxy_state();
    let cp_url = format!("https://127.0.0.1:{}", addr.port());

    let tls_config = DpGrpcTlsConfig {
        ca_cert_pem: Some(ca_pem),
        client_cert_pem: Some(client_cert_pem),
        client_key_pem: Some(client_key_pem),
    };

    // See `test_dp_receives_initial_config_from_cp` for why this is
    // spawn-and-poll rather than `timeout(secs(5), connect_and_subscribe)`.
    let ps = proxy_state.clone();
    let cp_url_clone = cp_url.clone();
    let secret = test_secret();
    let tls = tls_config.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url_clone,
            &secret,
            "mtls-node-1",
            &ps,
            Some(&tls),
            "ferrum",
        )
        .await
    });

    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "DP did not receive initial config over mTLS within 5s"
    );

    let current_config = proxy_state.config.load();
    assert_eq!(
        current_config.proxies.len(),
        3,
        "DP should have received 3 proxies from CP over mTLS"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_rejects_untrusted_cp_server_cert() {
    // Generate one CA for the server and a DIFFERENT CA for the client trust store
    let (_, server_cert_pem, server_key_pem) = generate_test_ca_and_server_cert();

    // Generate a different CA that the DP will trust (server cert NOT signed by this)
    let different_ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut different_ca_params =
        rcgen::CertificateParams::new(vec!["Different CA".to_string()]).unwrap();
    different_ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let different_ca_cert = different_ca_params.self_signed(&different_ca_key).unwrap();
    let different_ca_pem = different_ca_cert.pem().into_bytes();

    // Start CP server with its own cert
    let cp_config = create_test_config(1);
    let (addr, _update_tx, _server_handle) =
        start_test_cp_server_with_tls(cp_config, &server_cert_pem, &server_key_pem, None).await;

    // DP trusts the WRONG CA — should fail to connect
    let proxy_state = create_test_proxy_state();
    let cp_url = format!("https://127.0.0.1:{}", addr.port());

    let tls_config = DpGrpcTlsConfig {
        ca_cert_pem: Some(different_ca_pem),
        client_cert_pem: None,
        client_key_pem: None,
    };

    let result = timeout(
        Duration::from_secs(5),
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "untrusted-node",
            &proxy_state,
            Some(&tls_config),
            "ferrum",
        ),
    )
    .await;

    // Connection should fail due to certificate verification
    match result {
        Ok(Err(_)) => {} // Expected: TLS handshake failure
        Ok(Ok(())) => panic!("Should have failed with untrusted CA"),
        Err(_) => panic!("Should have failed fast, not timed out"),
    }

    // Config should remain empty
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        0,
        "Config should remain empty when TLS verification fails"
    );
}

// ── Delta / Incremental update tests ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_update_adding_proxy() {
    // Start CP with initial config of 1 proxy
    let cp_config = create_test_config(1);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    // Spawn DP client (DP generates JWT from shared secret)
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "delta-node-1",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    // Wait for initial full snapshot
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "Should receive initial config with 1 proxy"
    );

    // Now send a DELTA update that adds a new proxy
    let new_proxy = create_test_proxy("proxy-new", "/api-new");
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![new_proxy],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    // Wait for the delta to be applied
    let received_delta = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_delta.is_ok(),
        "DP should have applied delta adding a proxy (expected 2 proxies)"
    );

    let config = proxy_state.config.load();
    assert_eq!(config.proxies.len(), 2);
    // Both original and new proxy should be present
    let ids: Vec<&str> = config.proxies.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains(&"proxy-0"));
    assert!(ids.contains(&"proxy-new"));

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_update_removing_proxy() {
    // Start CP with initial config of 3 proxies
    let cp_config = create_test_config(3);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "delta-node-2",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    // Wait for initial snapshot
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "Should receive initial config with 3 proxies"
    );

    // Send a DELTA that removes proxy-1
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec!["proxy-1".to_string()],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    // Wait for delta to be applied
    let received_delta = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_delta.is_ok(),
        "DP should have applied delta removing proxy-1 (expected 2 proxies)"
    );

    let config = proxy_state.config.load();
    assert_eq!(config.proxies.len(), 2);
    let ids: Vec<&str> = config.proxies.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains(&"proxy-0"));
    assert!(!ids.contains(&"proxy-1")); // removed
    assert!(ids.contains(&"proxy-2"));

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_then_full_snapshot() {
    // Verify that a full snapshot after deltas produces the correct final state.
    let cp_config = create_test_config(2);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "delta-node-3",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    // Wait for initial snapshot (2 proxies)
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received.is_ok());

    // Send a delta that adds proxy-extra
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![create_test_proxy("proxy-extra", "/api-extra")],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    // Wait for delta
    let received_delta = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received_delta.is_ok(), "Should have 3 proxies after delta");

    // Now send a full snapshot with only 1 proxy — should replace everything
    let final_config = create_test_config(1);
    CpGrpcServer::broadcast_update(&update_tx, &final_config);

    let received_full = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_full.is_ok(),
        "Full snapshot should override to 1 proxy"
    );

    let config = proxy_state.config.load();
    assert_eq!(config.proxies.len(), 1);
    assert_eq!(config.proxies[0].id, "proxy-0");

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_ignores_malformed_delta() {
    // Verify that a malformed delta doesn't corrupt existing config.
    let cp_config = create_test_config(2);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "delta-node-4",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    // Wait for initial snapshot
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received.is_ok());

    // Send malformed delta (invalid JSON for update_type=1)
    let malformed = ferrum_edge::grpc::proto::ConfigUpdate {
        update_type: 1, // DELTA
        config_json: "{not valid delta json!!!}".to_string(),
        version: "bad".to_string(),
        timestamp: Utc::now().timestamp(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        trust_bundles_json: String::new(),
    };
    let _ = update_tx.send(malformed);

    // Wait a bit, then verify config is unchanged
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        2,
        "Config should remain unchanged after malformed delta"
    );

    // Send a valid delta to prove client is still alive
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![create_test_proxy("proxy-after", "/api-after")],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v3");

    let recovered = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "Client should recover and apply valid delta after malformed one"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_incremental_result_serde_roundtrip() {
    // Verify IncrementalResult survives JSON serialization/deserialization
    // (this is the wire format for DELTA updates).
    let original = IncrementalResult {
        added_or_modified_proxies: vec![
            create_test_proxy("proxy-a", "/api-a"),
            create_test_proxy("proxy-b", "/api-b"),
        ],
        removed_proxy_ids: vec!["proxy-old".to_string()],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec!["consumer-gone".to_string()],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec!["upstream-x".to_string()],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };

    let json = serde_json::to_string(&original).expect("Failed to serialize IncrementalResult");
    let deserialized: IncrementalResult =
        serde_json::from_str(&json).expect("Failed to deserialize IncrementalResult");

    assert_eq!(deserialized.added_or_modified_proxies.len(), 2);
    assert_eq!(deserialized.added_or_modified_proxies[0].id, "proxy-a");
    assert_eq!(deserialized.added_or_modified_proxies[1].id, "proxy-b");
    assert_eq!(deserialized.removed_proxy_ids, vec!["proxy-old"]);
    assert_eq!(deserialized.removed_consumer_ids, vec!["consumer-gone"]);
    assert_eq!(deserialized.removed_upstream_ids, vec!["upstream-x"]);
    assert!(deserialized.added_or_modified_consumers.is_empty());
    assert!(deserialized.added_or_modified_plugin_configs.is_empty());
    assert!(deserialized.added_or_modified_upstreams.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_modifying_proxy() {
    // Verify that a delta with a modified proxy (same ID, different fields)
    // correctly updates the existing proxy in-place.
    let cp_config = create_test_config(2);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "delta-mod-node",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    // Wait for initial snapshot (2 proxies)
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received.is_ok());

    // Verify initial backend port
    assert_eq!(proxy_state.config.load().proxies[0].backend_port, 3000);

    // Send delta that modifies proxy-0 (change backend_port)
    let mut modified_proxy = create_test_proxy("proxy-0", "/api-0");
    modified_proxy.backend_port = 9999;
    modified_proxy.updated_at = Utc::now(); // newer timestamp

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![modified_proxy],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    // Wait for delta — proxy count stays 2 but backend_port changes
    let received_delta = timeout(Duration::from_secs(5), async {
        loop {
            let config = proxy_state.config.load();
            if let Some(p) = config.proxies.iter().find(|p| p.id == "proxy-0")
                && p.backend_port == 9999
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_delta.is_ok(),
        "DP should have applied delta modifying proxy-0 backend_port to 9999"
    );

    // Verify total proxy count unchanged
    let config = proxy_state.config.load();
    assert_eq!(config.proxies.len(), 2);
    // Verify the modification stuck
    let proxy_0 = config.proxies.iter().find(|p| p.id == "proxy-0").unwrap();
    assert_eq!(proxy_0.backend_port, 9999);
    // Verify proxy-1 is untouched
    let proxy_1 = config.proxies.iter().find(|p| p.id == "proxy-1").unwrap();
    assert_eq!(proxy_1.backend_port, 3000);

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_with_mixed_operations() {
    // A single delta that simultaneously adds, modifies, and removes proxies.
    let cp_config = create_test_config(3); // proxy-0, proxy-1, proxy-2
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "delta-mixed-node",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    // Wait for initial snapshot (3 proxies)
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received.is_ok());

    // Send a single delta that:
    // - Removes proxy-1
    // - Modifies proxy-0 (change backend_port)
    // - Adds proxy-new
    let mut modified = create_test_proxy("proxy-0", "/api-0");
    modified.backend_port = 5555;
    modified.updated_at = Utc::now();

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![modified, create_test_proxy("proxy-new", "/api-new")],
        removed_proxy_ids: vec!["proxy-1".to_string()],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    // Wait for delta — should go from 3 to 3 (remove 1, add 1, modify 1)
    let received_delta = timeout(Duration::from_secs(5), async {
        loop {
            let config = proxy_state.config.load();
            let ids: Vec<&str> = config.proxies.iter().map(|p| p.id.as_str()).collect();
            if ids.contains(&"proxy-new") && !ids.contains(&"proxy-1") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_delta.is_ok(),
        "DP should have applied mixed delta (add + modify + remove)"
    );

    let config = proxy_state.config.load();
    assert_eq!(config.proxies.len(), 3); // -1 removed, +1 added = net 3

    let ids: Vec<&str> = config.proxies.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains(&"proxy-0"));
    assert!(!ids.contains(&"proxy-1")); // removed
    assert!(ids.contains(&"proxy-2"));
    assert!(ids.contains(&"proxy-new")); // added

    // Verify modification
    let proxy_0 = config.proxies.iter().find(|p| p.id == "proxy-0").unwrap();
    assert_eq!(proxy_0.backend_port, 5555);

    client_handle.abort();
}

/// Test that the CP rejects a DP with a mismatched minor version.
#[allow(clippy::result_large_err)]
#[tokio::test]
async fn test_cp_rejects_dp_with_version_mismatch() {
    let config = create_test_config(1);
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));

    let (server, _update_tx) = CpGrpcServer::new(config_arc, TEST_JWT_SECRET.to_string());

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let bound_addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    // Give the server a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    let generated_token = dp_client::generate_dp_jwt(TEST_JWT_SECRET, "test-dp").unwrap();
    let token_meta: tonic::metadata::MetadataValue<_> =
        format!("Bearer {}", generated_token).parse().unwrap();
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", bound_addr))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client =
        ferrum_edge::grpc::proto::config_sync_client::ConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        );

    // Send a Subscribe with a fake incompatible version (different minor)
    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "test-dp".to_string(),
        ferrum_version: "99.99.0".to_string(),
        namespace: "ferrum".to_string(),
    });

    let result = client.subscribe(request).await;
    assert!(result.is_err(), "CP should reject mismatched DP version");
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(
        status.message().contains("Version mismatch"),
        "Error should mention version mismatch, got: {}",
        status.message()
    );

    // Also test GetFullConfig with mismatched version
    let request = tonic::Request::new(ferrum_edge::grpc::proto::FullConfigRequest {
        node_id: "test-dp".to_string(),
        ferrum_version: "99.99.0".to_string(),
        namespace: "ferrum".to_string(),
    });

    let result = client.get_full_config(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);

    // Verify that a matching version succeeds
    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "test-dp-good".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
    });

    let result = client.subscribe(request).await;
    assert!(result.is_ok(), "CP should accept DP with matching version");

    server_handle.abort();
}

/// Test that the CP rejects a DP that sends an empty version (pre-v0.9.0 DP).
#[allow(clippy::result_large_err)]
#[tokio::test]
async fn test_cp_rejects_dp_with_empty_version() {
    let config = create_test_config(1);
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));

    let (server, _update_tx) = CpGrpcServer::new(config_arc, TEST_JWT_SECRET.to_string());

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let bound_addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let generated_token = dp_client::generate_dp_jwt(TEST_JWT_SECRET, "test-dp").unwrap();
    let token_meta: tonic::metadata::MetadataValue<_> =
        format!("Bearer {}", generated_token).parse().unwrap();
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", bound_addr))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client =
        ferrum_edge::grpc::proto::config_sync_client::ConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        );

    // Empty version simulates a pre-v0.9.0 DP that doesn't set the field
    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "old-dp".to_string(),
        ferrum_version: String::new(),
        namespace: "ferrum".to_string(),
    });

    let result = client.subscribe(request).await;
    assert!(result.is_err(), "CP should reject DP with empty version");
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(
        status.message().contains("did not report its version"),
        "Error should mention missing version, got: {}",
        status.message()
    );

    server_handle.abort();
}

// ─── Upstream delta tests ────────────────────────────────────────────────────

fn create_test_upstream(id: &str, hosts: &[(&str, u16)]) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("upstream-{}", id)),
        targets: hosts
            .iter()
            .map(|(h, p)| UpstreamTarget {
                host: h.to_string(),
                port: *p,
                service_port_policy_key: None,
                weight: 100,
                tags: HashMap::new(),
                locality: None,
                path: None,
            })
            .collect(),
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn create_test_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_adding_upstream() {
    let initial = GatewayConfig::default();
    let (addr, update_tx, _server_handle) = start_test_cp_server(initial).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "upstream-add-node",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![create_test_upstream(
            "u1",
            &[("backend1.local", 8080), ("backend2.local", 8081)],
        )],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    let applied = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().upstreams.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(applied.is_ok(), "DP should apply upstream delta within 5s");

    let cfg = proxy_state.config.load();
    assert_eq!(cfg.upstreams[0].id, "u1");
    assert_eq!(cfg.upstreams[0].targets.len(), 2);

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_removing_upstream() {
    let initial = GatewayConfig {
        upstreams: vec![create_test_upstream("u1", &[("host1", 80)])],
        ..Default::default()
    };
    let (addr, update_tx, _server_handle) = start_test_cp_server(initial).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "upstream-rm-node",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    let applied = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().upstreams.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        applied.is_ok(),
        "DP should receive initial config with 1 upstream"
    );

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec!["u1".to_string()],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v3");

    let applied = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().upstreams.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(applied.is_ok(), "DP should remove upstream via delta");

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_modifying_upstream_targets() {
    let initial = GatewayConfig {
        upstreams: vec![create_test_upstream("u1", &[("old-host", 80)])],
        ..Default::default()
    };
    let (addr, update_tx, _server_handle) = start_test_cp_server(initial).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "upstream-mod-node",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    let applied = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().upstreams.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(applied.is_ok());

    let mut modified_upstream =
        create_test_upstream("u1", &[("new-host-a", 9090), ("new-host-b", 9091)]);
    modified_upstream.updated_at = Utc::now() + chrono::Duration::seconds(10);

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![modified_upstream],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v3");

    let applied = timeout(Duration::from_secs(5), async {
        loop {
            let cfg = proxy_state.config.load();
            if !cfg.upstreams.is_empty() && cfg.upstreams[0].targets.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(applied.is_ok(), "DP should apply modified upstream targets");

    let cfg = proxy_state.config.load();
    assert_eq!(cfg.upstreams[0].targets[0].host, "new-host-a");
    assert_eq!(cfg.upstreams[0].targets[1].host, "new-host-b");

    client_handle.abort();
}

// ─── Consumer delta tests ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_adding_consumer() {
    let initial = GatewayConfig::default();
    let (addr, update_tx, _server_handle) = start_test_cp_server(initial).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "consumer-add-node",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![
            create_test_consumer("c1", "alice"),
            create_test_consumer("c2", "bob"),
        ],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    let applied = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().consumers.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(applied.is_ok(), "DP should apply consumer delta");

    let cfg = proxy_state.config.load();
    assert_eq!(cfg.consumers[0].username, "alice");
    assert_eq!(cfg.consumers[1].username, "bob");

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_removing_consumer() {
    let initial = GatewayConfig {
        consumers: vec![
            create_test_consumer("c1", "alice"),
            create_test_consumer("c2", "bob"),
        ],
        ..Default::default()
    };
    let (addr, update_tx, _server_handle) = start_test_cp_server(initial).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "consumer-rm-node",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    let applied = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().consumers.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(applied.is_ok());

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec!["c1".to_string()],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v3");

    let applied = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().consumers.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(applied.is_ok(), "DP should remove consumer via delta");

    let cfg = proxy_state.config.load();
    assert_eq!(cfg.consumers[0].username, "bob");

    client_handle.abort();
}

// ─── Multi-DP broadcast test ─────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_cp_broadcasts_delta_to_multiple_dps() {
    let initial = create_test_config(1);
    let (addr, update_tx, _server_handle) = start_test_cp_server(initial).await;

    let proxy_state_1 = create_test_proxy_state();
    let proxy_state_2 = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps1 = proxy_state_1.clone();
    let url1 = cp_url.clone();

    let dp_handle_1 = tokio::spawn(async move {
        dp_client::connect_and_subscribe(&url1, &test_secret(), "multi-dp-1", &ps1, None, "ferrum")
            .await
    });

    let ps2 = proxy_state_2.clone();
    let url2 = cp_url.clone();

    let dp_handle_2 = tokio::spawn(async move {
        dp_client::connect_and_subscribe(&url2, &test_secret(), "multi-dp-2", &ps2, None, "ferrum")
            .await
    });

    // Wait for both DPs to receive initial config
    let both_ready = timeout(Duration::from_secs(5), async {
        loop {
            let c1 = proxy_state_1.config.load().proxies.len();
            let c2 = proxy_state_2.config.load().proxies.len();
            if c1 == 1 && c2 == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(both_ready.is_ok(), "Both DPs should receive initial config");

    // Broadcast delta adding a new proxy
    let new_proxy = create_test_proxy("proxy-new", "/new-route");
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![new_proxy],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    // Both DPs should receive and apply the delta
    let both_applied = timeout(Duration::from_secs(5), async {
        loop {
            let c1 = proxy_state_1.config.load().proxies.len();
            let c2 = proxy_state_2.config.load().proxies.len();
            if c1 == 2 && c2 == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        both_applied.is_ok(),
        "Both DPs should apply the delta (DP1: {}, DP2: {})",
        proxy_state_1.config.load().proxies.len(),
        proxy_state_2.config.load().proxies.len()
    );

    let cfg1 = proxy_state_1.config.load();
    let cfg2 = proxy_state_2.config.load();
    assert_eq!(cfg1.proxies.len(), cfg2.proxies.len());

    dp_handle_1.abort();
    dp_handle_2.abort();
}

// ─── Mixed entity delta test ─────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_with_all_entity_types() {
    let initial = GatewayConfig {
        proxies: vec![create_test_proxy("p1", "/api")],
        consumers: vec![create_test_consumer("c1", "alice")],
        upstreams: vec![create_test_upstream("u1", &[("host1", 80)])],
        ..Default::default()
    };
    let (addr, update_tx, _server_handle) = start_test_cp_server(initial).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "mixed-delta-node",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    let ready = timeout(Duration::from_secs(5), async {
        loop {
            let cfg = proxy_state.config.load();
            if cfg.proxies.len() == 1 && cfg.consumers.len() == 1 && cfg.upstreams.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(ready.is_ok());

    // Send a mixed delta: add proxy, remove consumer, modify upstream
    let mut modified_upstream = create_test_upstream("u1", &[("new-host", 9090)]);
    modified_upstream.updated_at = Utc::now() + chrono::Duration::seconds(10);

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![create_test_proxy("p2", "/new")],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec!["c1".to_string()],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![modified_upstream],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v3");

    let applied = timeout(Duration::from_secs(5), async {
        loop {
            let cfg = proxy_state.config.load();
            if cfg.proxies.len() == 2
                && cfg.consumers.is_empty()
                && cfg.upstreams.len() == 1
                && cfg.upstreams[0].targets[0].host == "new-host"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        applied.is_ok(),
        "DP should apply mixed delta across all entity types"
    );

    client_handle.abort();
}

/// Start a CP gRPC server with a custom broadcast channel capacity.
/// Returns the config ArcSwap so the caller can update the config that
/// the lag-recovery snapshot reads from.
async fn start_test_cp_server_with_capacity(
    config: GatewayConfig,
    channel_capacity: usize,
) -> (
    SocketAddr,
    tokio::sync::broadcast::Sender<ferrum_edge::grpc::proto::ConfigUpdate>,
    Arc<ArcSwap<GatewayConfig>>,
    tokio::task::JoinHandle<()>,
) {
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let (server, update_tx) = CpGrpcServer::with_channel_capacity(
        config_arc.clone(),
        TEST_JWT_SECRET.to_string(),
        channel_capacity,
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("gRPC server failed");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, update_tx, config_arc, handle)
}

/// Verify that when a DP lags behind the broadcast channel capacity, it
/// receives a full snapshot recovery instead of the missed deltas.
#[tokio::test(flavor = "multi_thread")]
async fn test_dp_recovers_from_broadcast_channel_overflow() {
    // Start CP with a very small channel capacity (2) so it's easy to overflow
    let initial_config = create_test_config(1);
    let (addr, update_tx, config_arc, _server_handle) =
        start_test_cp_server_with_capacity(initial_config, 2).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    // Connect DP and wait for initial config
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "overflow-test-node",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    let received_initial = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_initial.is_ok(),
        "DP should receive initial config with 1 proxy"
    );

    // Update the CP's config to the final state (5 proxies).
    // When the DP's lag recovery triggers, it reads the *current* config
    // from this ArcSwap, so it should get 5 proxies.
    let final_config = create_test_config(5);
    config_arc.store(Arc::new(final_config.clone()));

    // Flood the broadcast channel with more updates than its capacity (2).
    // The DP won't be able to keep up, triggering a BroadcastStream::Lagged error
    // which causes the CP to send a full snapshot recovery.
    // All flood messages use the same config so the final state is deterministic.
    for _ in 0..10 {
        CpGrpcServer::broadcast_update(&update_tx, &final_config);
    }

    // Wait for the DP to settle — it should have 5 proxies regardless of
    // whether it got the recovery snapshot or a non-dropped broadcast (both
    // carry the same 5-proxy config). The key behavior: the DP doesn't crash
    // and ends up with the correct state.
    let recovered = timeout(Duration::from_secs(10), async {
        loop {
            let cfg = proxy_state.config.load();
            if cfg.proxies.len() == 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "DP should recover to 5 proxies after broadcast channel overflow. Current: {}",
        proxy_state.config.load().proxies.len()
    );

    // Verify the DP can still process normal updates after recovery
    let post_recovery_config = create_test_config(7);
    config_arc.store(Arc::new(post_recovery_config.clone()));
    CpGrpcServer::broadcast_update(&update_tx, &post_recovery_config);

    let post_recovery = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 7 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        post_recovery.is_ok(),
        "DP should process updates normally after overflow recovery"
    );

    client_handle.abort();
}

// ─── Cross-namespace rejection tests ─────────────────────────────────────────
//
// These tests cover the multi-tenant security gap where a DP started with
// `FERRUM_NAMESPACE=staging` against a CP serving `FERRUM_NAMESPACE=production`
// would silently inherit production config. The CP-side fix is explicit
// rejection with `failed_precondition`; the DP-side defense-in-depth filter
// strips cross-namespace resources from any snapshot/delta that slips
// through.

/// Start a CP gRPC server bound to a specific CP namespace.
async fn start_test_cp_server_with_namespace(
    config: GatewayConfig,
    cp_namespace: &str,
) -> (
    SocketAddr,
    tokio::sync::broadcast::Sender<ferrum_edge::grpc::proto::ConfigUpdate>,
    tokio::task::JoinHandle<()>,
) {
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let registry = Arc::new(ferrum_edge::grpc::cp_server::DpNodeRegistry::new());
    let (server, update_tx) = CpGrpcServer::with_channel_capacity_registry_and_namespace(
        config_arc.clone(),
        TEST_JWT_SECRET.to_string(),
        128,
        registry,
        cp_namespace.to_string(),
    );
    let (mesh_server, _mesh_update_tx) =
        MeshGrpcServer::with_channel_capacity_registry_issuer_and_namespace(
            config_arc,
            TEST_JWT_SECRET.to_string(),
            128,
            Arc::new(ferrum_edge::grpc::mesh_registry::MeshNodeRegistry::new()),
            TEST_DEFAULT_ISSUER.to_string(),
            cp_namespace.to_string(),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .add_service(mesh_server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("gRPC server failed");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, update_tx, handle)
}

/// CP serves `production`, DP requests `staging` → CP returns
/// `failed_precondition` and the error message includes both namespaces.
#[tokio::test(flavor = "multi_thread")]
async fn test_cp_rejects_dp_with_mismatched_namespace_subscribe() {
    let cp_config = create_test_config(2);
    let (addr, _update_tx, server_handle) =
        start_test_cp_server_with_namespace(cp_config, "production").await;

    let generated_token = dp_client::generate_dp_jwt(TEST_JWT_SECRET, "test-dp").unwrap();
    let token_meta: tonic::metadata::MetadataValue<_> =
        format!("Bearer {}", generated_token).parse().unwrap();
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client =
        ferrum_edge::grpc::proto::config_sync_client::ConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        );

    // DP advertises a different namespace than the CP serves.
    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "test-dp".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "staging".to_string(),
    });

    let result = client.subscribe(request).await;
    assert!(
        result.is_err(),
        "CP should reject DP with mismatched namespace"
    );
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(
        status.message().contains("staging"),
        "Error should mention DP namespace 'staging', got: {}",
        status.message()
    );
    assert!(
        status.message().contains("production"),
        "Error should mention CP namespace 'production', got: {}",
        status.message()
    );

    server_handle.abort();
}

/// `MeshSubscribe` enforces the same namespace boundary as classic Subscribe:
/// a mesh node in `staging` must not receive a CP's `production` mesh slice.
#[tokio::test(flavor = "multi_thread")]
async fn test_cp_rejects_mesh_subscribe_with_mismatched_namespace() {
    let cp_config = create_test_mesh_config();
    let (addr, _update_tx, server_handle) =
        start_test_cp_server_with_namespace(cp_config, "production").await;

    let generated_token = dp_client::generate_dp_jwt(TEST_JWT_SECRET, "test-mesh-dp").unwrap();
    let mut client = connect_mesh_client_with_token!(addr, generated_token);

    let request = tonic::Request::new(ferrum_edge::grpc::proto::MeshSubscribeRequest {
        node_id: "test-mesh-dp".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "staging".to_string(),
        workload_spiffe_id: "spiffe://cluster.local/ns/staging/sa/api".to_string(),
        labels: HashMap::from([("app".to_string(), "api".to_string())]),
        waypoint_name: String::new(),
    });

    let result = client.mesh_subscribe(request).await;
    assert!(
        result.is_err(),
        "CP should reject MeshSubscribe with mismatched namespace"
    );
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(
        status.message().contains("staging"),
        "Error should mention mesh node namespace 'staging', got: {}",
        status.message()
    );
    assert!(
        status.message().contains("production"),
        "Error should mention CP namespace 'production', got: {}",
        status.message()
    );

    server_handle.abort();
}

/// `GetFullConfig` enforces the same namespace check as `Subscribe`.
#[tokio::test(flavor = "multi_thread")]
async fn test_cp_rejects_dp_with_mismatched_namespace_get_full_config() {
    let cp_config = create_test_config(1);
    let (addr, _update_tx, server_handle) =
        start_test_cp_server_with_namespace(cp_config, "production").await;

    let generated_token = dp_client::generate_dp_jwt(TEST_JWT_SECRET, "test-dp").unwrap();
    let token_meta: tonic::metadata::MetadataValue<_> =
        format!("Bearer {}", generated_token).parse().unwrap();
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client =
        ferrum_edge::grpc::proto::config_sync_client::ConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        );

    let request = tonic::Request::new(ferrum_edge::grpc::proto::FullConfigRequest {
        node_id: "test-dp".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "staging".to_string(),
    });

    let result = client.get_full_config(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(
        status.message().contains("staging") && status.message().contains("production"),
        "Error should mention both DP and CP namespaces, got: {}",
        status.message()
    );

    server_handle.abort();
}

/// `GetFullConfig` returns the same gateway trust-bundle side channel as the
/// Subscribe full snapshot while keeping trust material out of `config_json`.
#[tokio::test(flavor = "multi_thread")]
async fn test_get_full_config_returns_gateway_trust_bundles_side_channel() {
    let mut cp_config = create_test_config(1);
    cp_config.trust_bundles = Some(Box::new(create_test_trust_bundles()));
    let (addr, _update_tx, server_handle) =
        start_test_cp_server_with_namespace(cp_config, "ferrum").await;

    let generated_token = dp_client::generate_dp_jwt(TEST_JWT_SECRET, "test-dp").unwrap();
    let token_meta: tonic::metadata::MetadataValue<_> =
        format!("Bearer {}", generated_token).parse().unwrap();
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client =
        ferrum_edge::grpc::proto::config_sync_client::ConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        );

    let request = tonic::Request::new(ferrum_edge::grpc::proto::FullConfigRequest {
        node_id: "test-dp".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
    });

    let response = client
        .get_full_config(request)
        .await
        .expect("GetFullConfig should succeed")
        .into_inner();

    let config_json: serde_json::Value =
        serde_json::from_str(&response.config_json).expect("config JSON should parse");
    assert!(config_json.get("trust_bundles").is_none());
    assert_ne!(response.trust_bundles_json, "null");
    assert!(response.trust_bundles_json.contains("cluster.local"));

    server_handle.abort();
}

/// DP advertises the same namespace the CP serves → subscribe succeeds and
/// the DP receives the initial config snapshot.
#[tokio::test(flavor = "multi_thread")]
async fn test_cp_accepts_dp_with_matching_namespace() {
    let mut cp_config = create_test_config(2);
    // T2-A: CP-side per-namespace partitioning filters the snapshot to the
    // requested namespace. Tag the test proxies so they land in the
    // CP/DP's "production" namespace, not the default "ferrum".
    for proxy in cp_config.proxies.iter_mut() {
        proxy.namespace = "production".to_string();
    }
    let (addr, _update_tx, server_handle) =
        start_test_cp_server_with_namespace(cp_config, "production").await;

    let generated_token = dp_client::generate_dp_jwt(TEST_JWT_SECRET, "test-dp").unwrap();
    let token_meta: tonic::metadata::MetadataValue<_> =
        format!("Bearer {}", generated_token).parse().unwrap();
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client =
        ferrum_edge::grpc::proto::config_sync_client::ConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        );

    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "test-dp-good".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "production".to_string(),
    });

    let mut stream = client
        .subscribe(request)
        .await
        .expect("CP should accept matching namespace")
        .into_inner();

    // Pull the first message — the initial FULL_SNAPSHOT.
    let first = timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("stream should yield within 5s")
        .expect("stream message should not error")
        .expect("stream should yield a snapshot");
    assert_eq!(
        first.update_type, 0,
        "first message should be FULL_SNAPSHOT"
    );

    let cfg: GatewayConfig =
        serde_json::from_str(&first.config_json).expect("snapshot config should deserialize");
    assert_eq!(cfg.proxies.len(), 2);

    server_handle.abort();
}

/// DP-side defense in depth: when the CP somehow regresses and ships a
/// snapshot containing resources from another namespace, the DP filters
/// them out before applying so the local `GatewayConfig` stays
/// single-namespace.
#[tokio::test(flavor = "multi_thread")]
async fn test_dp_filters_cross_namespace_resources_from_snapshot() {
    // Build a config that intentionally mixes two namespaces. We can't
    // get the CP to ship this in production (its `check_namespace` guard
    // would fire first), but the helper is designed precisely for this
    // kind of regression simulation — we connect with the same namespace
    // the CP advertises (so `Subscribe` succeeds) and then verify that
    // the DP-side filter still strips the cross-namespace pollution if
    // the CP-side filter were ever bypassed.
    //
    // The mechanic we're verifying lives in
    // `filter_config_to_namespace`. We exercise it via the real
    // `connect_and_subscribe` path so the integration is realistic.
    let mut mixed = create_test_config(0);
    // 2 proxies in `production` (this DP's namespace).
    let mut p_prod_a = create_test_proxy("prod-a", "/prod-a");
    p_prod_a.namespace = "production".to_string();
    let mut p_prod_b = create_test_proxy("prod-b", "/prod-b");
    p_prod_b.namespace = "production".to_string();
    // 1 proxy from another namespace that should be filtered out.
    let mut p_staging = create_test_proxy("staging-a", "/staging-a");
    p_staging.namespace = "staging".to_string();
    mixed.proxies.push(p_prod_a);
    mixed.proxies.push(p_prod_b);
    mixed.proxies.push(p_staging);

    // 1 upstream in production and 1 in staging — verify upstreams are
    // filtered too.
    let mut up_prod = create_test_upstream("up-prod", &[("prod.example.com", 443)]);
    up_prod.namespace = "production".to_string();
    let mut up_staging = create_test_upstream("up-staging", &[("staging.example.com", 443)]);
    up_staging.namespace = "staging".to_string();
    mixed.upstreams.push(up_prod);
    mixed.upstreams.push(up_staging);

    // Start the CP server in the `production` namespace so the DP's
    // `Subscribe` is accepted; the snapshot itself contains
    // cross-namespace pollution that the DP's filter must strip.
    let (addr, _update_tx, server_handle) =
        start_test_cp_server_with_namespace(mixed, "production").await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let _ = timeout(
        Duration::from_secs(5),
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "test-dp",
            &proxy_state,
            None,
            "production",
        ),
    )
    .await;

    // Give the snapshot a moment to apply.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let cfg = proxy_state.config.load();
    assert_eq!(
        cfg.proxies.len(),
        2,
        "DP should retain only the 2 production proxies, not the 1 staging proxy"
    );
    for p in cfg.proxies.iter() {
        assert_eq!(
            p.namespace, "production",
            "every retained proxy should be in the production namespace"
        );
    }
    assert_eq!(
        cfg.upstreams.len(),
        1,
        "DP should retain only the 1 production upstream, not the 1 staging upstream"
    );
    assert_eq!(cfg.upstreams[0].namespace, "production");

    server_handle.abort();
}
