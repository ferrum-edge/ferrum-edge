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

use ferrum_edge::config::db_loader::{IncrementalResult, NamespacedResourceId};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, DispatchKind, GatewayConfig, LoadBalancerAlgorithm,
    PluginConfig, PluginScope, Proxy, Upstream, UpstreamTarget,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::grpc::cp_server::CpGrpcServer;
use ferrum_edge::grpc::dp_client::{self, DpCpConnectionState, DpGrpcTlsConfig, GrpcJwtSecret};
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

/// Build a TCP stream proxy (`dispatch_kind.is_stream()`) bound to `listen_port`.
/// Used to drive `StreamListenerManager::wait_until_started` timeout coverage.
fn create_test_tcp_stream_proxy(id: &str, listen_port: u16) -> Proxy {
    let mut proxy = create_test_proxy(id, "/unused");
    proxy.backend_scheme = Some(BackendScheme::Tcp);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Tcp);
    proxy.listen_path = None;
    proxy.listen_port = Some(listen_port);
    proxy.hosts = vec![];
    proxy
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

/// Start a CP with the supplied correlation/client-attribution ownership value.
async fn start_test_cp_server_with_real_ip_header(
    config: GatewayConfig,
    real_ip_header: &str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let (server, _update_tx) = CpGrpcServer::builder(config_arc, TEST_JWT_SECRET.to_string())
        .real_ip_header(Some(real_ip_header.to_string()))
        .build();
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
    (addr, handle)
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
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta_with_trust_bundles(
        &update_tx,
        &delta,
        &version,
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
async fn test_dp_rejects_gateway_trust_bundles_from_rejected_delta() {
    let cp_config = create_test_config(1);
    let (addr, update_tx, config_arc, _server_handle) =
        start_test_cp_server_with_capacity(cp_config, 16).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let connection_state = Arc::new(ArcSwap::new(Arc::new(
        DpCpConnectionState::new_disconnected(&cp_url),
    )));
    let client_connection_state = connection_state.clone();
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            vec![cp_url],
            test_secret(),
            ps,
            None,
            None,
            None,
            None,
            "ferrum".to_string(),
            0,
            Some(client_connection_state),
            None,
        )
        .await;
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
        added_or_modified_proxies: vec![
            create_test_proxy("proxy-missed", "/api-missed"),
            create_test_proxy("proxy-conflict", "/api-0"),
        ],
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
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta_with_trust_bundles(
        &update_tx,
        &delta,
        &version,
        Some(&trust_bundles),
    );

    // The CP fixes only the bad member in a later delta. Because the original
    // mixed batch was rejected atomically, the DP must not keep consuming that
    // stream and apply this partial fix against the wrong base. Its reconnect
    // must instead recover all three resources from the authoritative snapshot.
    let mut authoritative = create_test_config(1);
    authoritative
        .proxies
        .push(create_test_proxy("proxy-missed", "/api-missed"));
    authoritative
        .proxies
        .push(create_test_proxy("proxy-conflict", "/api-fixed"));
    authoritative.loaded_at = Utc::now();
    config_arc.store(Arc::new(authoritative));
    let partial_fix = IncrementalResult {
        added_or_modified_proxies: vec![create_test_proxy("proxy-conflict", "/api-fixed")],
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
    let partial_version = partial_fix.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &partial_fix, &partial_version);

    let resubscribed = timeout(Duration::from_secs(5), async {
        loop {
            let state = connection_state.load();
            if state.config_divergence_recoveries_total >= 1
                && !state.config_diverged
                && proxy_state.config.load().proxies.len() == 3
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        resubscribed.is_ok(),
        "DP should terminate the rejected-delta stream and resubscribe"
    );
    assert!(
        proxy_state.gateway_trust_bundles.load().is_none(),
        "Trust side-channel from a rejected resource batch must not apply"
    );
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        3,
        "Full-snapshot recovery must restore both members of the rejected mixed batch"
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
        ambient_udp_source_scoping: false,
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
        ambient_udp_source_scoping: false,
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
        ambient_udp_source_scoping: false,
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
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
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
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });

    let result = client.subscribe(request).await;
    assert!(
        result.is_ok(),
        "CP should accept token with matching issuer, got: {:?}",
        result.err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cp_enforces_real_ip_header_ownership_contract_before_distribution() {
    let (addr, server_handle) =
        start_test_cp_server_with_real_ip_header(create_test_config(1), "cf-connecting-ip").await;
    let token = dp_client::generate_dp_jwt_with_issuer(
        TEST_JWT_SECRET,
        "real-ip-owner",
        TEST_DEFAULT_ISSUER,
    )
    .unwrap();
    let mut client = connect_client_with_token!(addr, token);

    for (advertised, expected_message) in [
        (None, "did not advertise"),
        (Some("x-real-ip"), "does not match"),
    ] {
        let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
            node_id: "real-ip-owner".to_string(),
            ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
            namespace: "ferrum".to_string(),
            real_ip_header: advertised.map(str::to_string),
            supports_heartbeat: true,
        });
        let status = client.subscribe(request).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status.message().contains(expected_message), "got: {status}");
    }

    let full_config_status = client
        .get_full_config(tonic::Request::new(
            ferrum_edge::grpc::proto::FullConfigRequest {
                node_id: "real-ip-owner".to_string(),
                ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
                namespace: "ferrum".to_string(),
                real_ip_header: Some("x-real-ip".to_string()),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(full_config_status.code(), tonic::Code::FailedPrecondition);
    assert!(full_config_status.message().contains("does not match"));

    let accepted = client
        .subscribe(tonic::Request::new(
            ferrum_edge::grpc::proto::SubscribeRequest {
                node_id: "real-ip-owner".to_string(),
                ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
                namespace: "ferrum".to_string(),
                real_ip_header: Some("CF-CONNECTING-IP".to_string()),
                supports_heartbeat: true,
            },
        ))
        .await;
    assert!(
        accepted.is_ok(),
        "case-insensitively matching DP ownership must be admitted: {:?}",
        accepted.err()
    );

    server_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cp_treats_explicitly_empty_real_ip_header_as_unset() {
    let (addr, server_handle) =
        start_test_cp_server_with_real_ip_header(create_test_config(1), "").await;
    let token = dp_client::generate_dp_jwt_with_issuer(
        TEST_JWT_SECRET,
        "real-ip-unset",
        TEST_DEFAULT_ISSUER,
    )
    .unwrap();
    let mut client = connect_client_with_token!(addr, token);

    let missing_status = client
        .subscribe(tonic::Request::new(
            ferrum_edge::grpc::proto::SubscribeRequest {
                node_id: "real-ip-unset".to_string(),
                ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
                namespace: "ferrum".to_string(),
                real_ip_header: None,
                supports_heartbeat: true,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(missing_status.code(), tonic::Code::FailedPrecondition);
    assert!(missing_status.message().contains("did not advertise"));

    let subscribed = client
        .subscribe(tonic::Request::new(
            ferrum_edge::grpc::proto::SubscribeRequest {
                node_id: "real-ip-unset".to_string(),
                ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
                namespace: "ferrum".to_string(),
                real_ip_header: Some(String::new()),
                supports_heartbeat: true,
            },
        ))
        .await;
    assert!(
        subscribed.is_ok(),
        "explicitly empty CP and DP ownership must both mean unset: {:?}",
        subscribed.err()
    );

    let full_config = client
        .get_full_config(tonic::Request::new(
            ferrum_edge::grpc::proto::FullConfigRequest {
                node_id: "real-ip-unset".to_string(),
                ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
                namespace: "ferrum".to_string(),
                real_ip_header: Some(String::new()),
            },
        ))
        .await;
    assert!(
        full_config.is_ok(),
        "unary config fetch must apply the same empty ownership normalization: {:?}",
        full_config.err()
    );

    server_handle.abort();
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
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
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
        ambient_udp_source_scoping: false,
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
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
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
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
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
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
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
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
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
    let (addr, update_tx, config_arc, _server_handle) =
        start_test_cp_server_with_capacity(cp_config, 16).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    // Spawn the production reconnect loop (DP generates JWT from shared secret).
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            vec![cp_url],
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
        heartbeat: false,
        heartbeat_negotiated: false,
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

    // Make the CP's authoritative snapshot valid before the DP reconnects.
    // Recovery must come from that new subscription base, not from continuing
    // to consume the rejected stream.
    let valid_config = create_test_config(2);
    config_arc.store(Arc::new(valid_config));

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
        "Client should reconnect and recover from the authoritative full snapshot"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_rejects_snapshot_with_invalid_proxy_hosts() {
    let cp_config = create_test_config(1);
    let (addr, update_tx, config_arc, _server_handle) =
        start_test_cp_server_with_capacity(cp_config, 16).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            vec![cp_url],
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
    config_arc.store(Arc::new(valid_config));
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
        "Client should reconnect and recover from a valid authoritative snapshot"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_keeps_last_good_snapshot_after_case_ambiguous_mtls_dns_update() {
    let cp_config = create_test_config(1);
    let (addr, update_tx, config_arc, _server_handle) =
        start_test_cp_server_with_capacity(cp_config, 16).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            vec![cp_url],
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

    timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("DP should receive the initial snapshot");

    let mut upper = Consumer {
        id: "upper".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "alice".to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    upper.credentials.insert(
        "mtls_auth".to_string(),
        serde_json::json!([{"identity": "API.Example.COM"}]),
    );
    let mut lower = upper.clone();
    lower.id = "lower".to_string();
    lower.username = "bob".to_string();
    lower.credentials.insert(
        "mtls_auth".to_string(),
        serde_json::json!([{"identity": "api.example.com"}]),
    );
    let mut invalid_config = create_test_config(2);
    invalid_config.consumers = vec![upper, lower];
    invalid_config.plugin_configs = vec![PluginConfig {
        id: "dns-mtls".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "mtls_auth".to_string(),
        config: serde_json::json!({"cert_field": "san_dns"}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }];
    CpGrpcServer::broadcast_update(&update_tx, &invalid_config);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let retained = proxy_state.config.load();
    assert_eq!(retained.proxies.len(), 1);
    assert!(
        retained.consumers.is_empty(),
        "DP must not publish an ambiguous case-folded ConsumerIndex"
    );
    drop(retained);

    let valid_config = create_test_config(2);
    config_arc.store(Arc::new(valid_config));
    timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("DP should reconnect and recover after rejecting the ambiguous update");

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
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);

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
        removed_proxy_ids: vec![NamespacedResourceId::new("ferrum", "proxy-1")],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);

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
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);

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
async fn test_dp_keeps_last_good_config_after_unparseable_delta_shape() {
    // Verify that an unclassifiable delta body doesn't corrupt existing config.
    //
    // Note this is deliberately NOT the legacy bare-ID removal shape: that one
    // is a supported same-major.minor rolling-upgrade encoding and is applied
    // (see `dp_applies_legacy_bare_id_removal_delta_in_its_own_namespace`). Only
    // a removal entry that is neither a bare ID nor a namespace-qualified key is
    // unclassifiable, and it must fail closed.
    let cp_config = create_test_config(2);
    let (addr, update_tx, config_arc, _server_handle) =
        start_test_cp_server_with_capacity(cp_config, 16).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            vec![cp_url],
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

    // A removal entry that is neither a bare ID string nor a namespace-qualified
    // key is unclassifiable. It is valid JSON, so it must be rejected by the
    // delta schema and fail closed rather than partially applying.
    let mut legacy_delta = serde_json::to_value(IncrementalResult {
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
    })
    .unwrap();
    legacy_delta["removed_consumer_ids"] = serde_json::json!([{"unexpected_key": 1}]);
    let malformed = ferrum_edge::grpc::proto::ConfigUpdate {
        update_type: 1, // DELTA
        config_json: serde_json::to_string(&legacy_delta).unwrap(),
        version: "bad".to_string(),
        timestamp: Utc::now().timestamp(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        trust_bundles_json: String::new(),
        heartbeat: false,
        heartbeat_negotiated: false,
    };
    let _ = update_tx.send(malformed);

    // Wait a bit, then verify config is unchanged
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        2,
        "Config should remain unchanged after an unclassifiable delta"
    );

    // A later partial CP update would omit resources that were part of the
    // rejected batch, so recovery must instead re-establish an authoritative
    // full-snapshot base containing the complete current state.
    let mut recovered_config = create_test_config(2);
    recovered_config
        .proxies
        .push(create_test_proxy("proxy-after", "/api-after"));
    recovered_config.loaded_at = Utc::now();
    config_arc.store(Arc::new(recovered_config));

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
        "Client should reconnect and recover from the authoritative full snapshot"
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
        removed_proxy_ids: vec![NamespacedResourceId::new("ferrum", "proxy-old")],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![NamespacedResourceId::new("ferrum", "consumer-gone")],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![NamespacedResourceId::new("ferrum", "upstream-x")],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };

    let json = serde_json::to_string(&original).expect("Failed to serialize IncrementalResult");
    let deserialized: IncrementalResult =
        serde_json::from_str(&json).expect("Failed to deserialize IncrementalResult");

    assert_eq!(deserialized.added_or_modified_proxies.len(), 2);
    assert_eq!(deserialized.added_or_modified_proxies[0].id, "proxy-a");
    assert_eq!(deserialized.added_or_modified_proxies[1].id, "proxy-b");
    assert_eq!(
        deserialized.removed_proxy_ids,
        vec![NamespacedResourceId::new("ferrum", "proxy-old")]
    );
    assert_eq!(
        deserialized.removed_consumer_ids,
        vec![NamespacedResourceId::new("ferrum", "consumer-gone")]
    );
    assert_eq!(
        deserialized.removed_upstream_ids,
        vec![NamespacedResourceId::new("ferrum", "upstream-x")]
    );
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
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);

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
        removed_proxy_ids: vec![NamespacedResourceId::new("ferrum", "proxy-1")],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);

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
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
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
        real_ip_header: Some(String::new()),
    });

    let result = client.get_full_config(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);

    // Verify that a matching version succeeds
    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "test-dp-good".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
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
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
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
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);

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
        removed_upstream_ids: vec![NamespacedResourceId::new("ferrum", "u1")],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);

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
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);

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
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);

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
        removed_consumer_ids: vec![NamespacedResourceId::new("ferrum", "c1")],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);

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
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);

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
        removed_consumer_ids: vec![NamespacedResourceId::new("ferrum", "c1")],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![modified_upstream],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);

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
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
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
        ambient_udp_source_scoping: false,
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
        real_ip_header: Some(String::new()),
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
        real_ip_header: Some(String::new()),
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
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
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

#[tokio::test(flavor = "multi_thread")]
async fn wait_until_started_times_out_when_stream_listener_never_binds() {
    // #2971 production seam the DP relies on: after the first CP snapshot the DP
    // calls `stream_listener_manager.wait_until_started(...)` and only WARNS
    // (non-fatal in DP mode) when it times out. Place a stream proxy in the shared
    // config ArcSwap WITHOUT starting/reconciling any listener, so the desired
    // listener can never report started and the wait must return Err — the exact
    // timeout branch the DP snapshot path treats as a non-fatal warning.
    let proxy_state = create_test_proxy_state();
    let mut config = GatewayConfig::default();
    config
        .proxies
        .push(create_test_tcp_stream_proxy("tcp-1", 19071));
    proxy_state.config.store(Arc::new(config));

    let result = proxy_state
        .stream_listener_manager
        .wait_until_started(Duration::from_millis(50))
        .await;

    assert!(
        result.is_err(),
        "wait_until_started must time out when the stream listener never binds"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_consumes_heartbeat_without_applying_or_tearing_down_stream() {
    // ConfigSync heartbeats keep an otherwise-silent stream alive without being
    // treated as config. Prove both properties on a single subscription: a
    // heartbeat whose payload is a 5-proxy FULL_SNAPSHOT must NOT be applied
    // (config stays at 1), and the stream must survive it so a subsequent real
    // config still applies over the same stream.
    let cp_config = create_test_config(1);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(&cp_url, &test_secret(), "hb-node", &ps, None, "ferrum")
            .await
    });

    // Wait for the initial snapshot (1 proxy).
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
        "DP should receive the initial snapshot"
    );

    // A heartbeat carrying a would-be 5-proxy FULL_SNAPSHOT payload. If heartbeat
    // handling were broken, this would parse and apply to 5 proxies.
    let heartbeat_payload = serde_json::to_string(&create_test_config(5)).unwrap();
    let heartbeat = ferrum_edge::grpc::proto::ConfigUpdate {
        update_type: 0,
        config_json: heartbeat_payload,
        version: String::new(),
        timestamp: Utc::now().timestamp(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        trust_bundles_json: String::new(),
        heartbeat: true,
        heartbeat_negotiated: true,
    };
    update_tx
        .send(heartbeat)
        .expect("heartbeat should broadcast");

    // Give the DP time to consume the heartbeat; config must remain at 1 proxy.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        1,
        "a heartbeat must not be applied as config"
    );

    // The stream must have survived the heartbeat: a real update still applies.
    CpGrpcServer::broadcast_update(&update_tx, &create_test_config(3));
    let applied = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        applied.is_ok(),
        "the stream must survive the heartbeat and apply the subsequent config"
    );

    client_handle.abort();
}

// ---------------------------------------------------------------------------
// ConfigSync lifecycle regressions driven through the real production entry
// points (issues #2967, #2969, #2970, #2971, #2972 and the #2395 mixed-version
// compatibility cases).
// ---------------------------------------------------------------------------

/// Copy one direction of a relayed TCP connection until the blackhole flips.
///
/// While blackholed the task holds both socket halves open and forwards
/// nothing, so the peer sees a healthy-looking but permanently silent
/// connection — the "CP host power loss / NAT idle timeout / partition without
/// RST" shape from issue #2967.
async fn relay_pipe(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    blackhole: Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 16 * 1024];
    loop {
        if blackhole.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(25)).await;
            continue;
        }
        // `read` is cancel-safe on a TcpStream, so the periodic tick can poll
        // the blackhole flag without losing buffered bytes.
        let read = tokio::select! {
            result = from.read(&mut buf) => result,
            _ = tokio::time::sleep(Duration::from_millis(25)) => continue,
        };
        match read {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if to.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// A TCP relay in front of a CP that can be flipped into a silent partition.
///
/// Established connections stay open but stop forwarding; new connections are
/// accepted and immediately dropped so a reconnect against the partitioned CP
/// fails fast instead of stalling the test on the connect timeout.
async fn spawn_blackhole_relay(
    upstream: SocketAddr,
) -> (
    SocketAddr,
    Arc<std::sync::atomic::AtomicBool>,
    tokio::task::JoinHandle<()>,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::TcpStream;

    let blackhole = Arc::new(AtomicBool::new(false));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let flag = blackhole.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((inbound, _)) = listener.accept().await else {
                return;
            };
            if flag.load(Ordering::Relaxed) {
                drop(inbound);
                continue;
            }
            let Ok(outbound) = TcpStream::connect(upstream).await else {
                continue;
            };
            let (client_read, client_write) = inbound.into_split();
            let (server_read, server_write) = outbound.into_split();
            tokio::spawn(relay_pipe(client_read, server_write, flag.clone()));
            tokio::spawn(relay_pipe(server_read, client_write, flag.clone()));
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, blackhole, handle)
}

/// Wait until the DP's applied config holds exactly `count` proxies.
async fn wait_for_proxy_count(state: &ProxyState, count: usize, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if state.config.load().proxies.len() == count {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Wait until a proxy with `id` is present in the DP's applied config.
async fn wait_for_proxy_id(state: &ProxyState, id: &str, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if state.config.load().proxies.iter().any(|p| p.id == id) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Wait until the DP's applied config holds `proxies` proxies and no upstreams.
async fn wait_for_proxy_count_without_upstreams(
    state: &ProxyState,
    proxies: usize,
    budget: Duration,
) -> bool {
    let deadline = std::time::Instant::now() + budget;
    loop {
        let config = state.config.load();
        if config.proxies.len() == proxies && config.upstreams.is_empty() {
            return true;
        }
        drop(config);
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Wait until an atomic readiness flag reads true.
async fn wait_for_flag(flag: &std::sync::atomic::AtomicBool, budget: Duration) -> bool {
    use std::sync::atomic::Ordering;

    let deadline = std::time::Instant::now() + budget;
    loop {
        if flag.load(Ordering::Acquire) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Build a DELTA envelope carrying `body` as its config JSON.
///
/// `version` must be the RFC3339 encoding of the body's `poll_timestamp`
/// (same instant the production CP puts on the wire). A second `Utc::now()`
/// here fails `reconcile_snapshot_version` and the DP refuses the delta.
fn delta_update(body: String, version: &str) -> ferrum_edge::grpc::proto::ConfigUpdate {
    ferrum_edge::grpc::proto::ConfigUpdate {
        update_type: 1,
        config_json: body,
        version: version.to_string(),
        timestamp: Utc::now().timestamp(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        trust_bundles_json: String::new(),
        heartbeat: false,
        heartbeat_negotiated: false,
    }
}

/// A delta that only adds `proxy`.
fn add_proxy_delta(proxy: Proxy) -> IncrementalResult {
    IncrementalResult {
        added_or_modified_proxies: vec![proxy],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 1,
        poll_timestamp: Utc::now(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dp_blackholed_configsync_stream_fails_over_to_fallback_cp() {
    // Issue #2967 acceptance: an established ConfigSync transport that becomes
    // silently blackholed must be detected, torn down, and replaced by a
    // fallback CP within a bounded interval — not left pending forever on
    // `message().await` while `/cluster` keeps reporting "online".
    //
    // The production silence bound is 150s, so this drives the real DP entry
    // point with a compressed per-invocation `ConfigSyncStreamTimings`. That
    // policy is a plain stack argument with no global/env override, so the test
    // value cannot leak into a production DP.
    use std::sync::atomic::Ordering;

    let primary_config = create_test_config(1);
    let (primary_addr, _primary_tx, _primary_handle) = start_test_cp_server(primary_config).await;

    let mut fallback_config = create_test_config(3);
    fallback_config.loaded_at = Utc::now();
    let (fallback_addr, _fallback_tx, _fallback_handle) =
        start_test_cp_server(fallback_config).await;

    let (relay_addr, blackhole, relay_handle) = spawn_blackhole_relay(primary_addr).await;

    let primary_url = format!("http://{}", relay_addr);
    let fallback_url = format!("http://{}", fallback_addr);
    let proxy_state = create_test_proxy_state();
    let connection_state = Arc::new(ArcSwap::new(Arc::new(
        DpCpConnectionState::new_disconnected(&primary_url),
    )));

    let ps = proxy_state.clone();
    let cs = connection_state.clone();
    let urls = vec![primary_url.clone(), fallback_url.clone()];
    let timings = ferrum_edge::grpc::configsync_lifecycle::ConfigSyncStreamTimings {
        max_silence: Duration::from_secs(2),
    };
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_stream_timings(
            urls,
            test_secret(),
            ps,
            None,
            None,
            None,
            None,
            "ferrum".to_string(),
            0,
            Some(cs),
            None,
            timings,
        )
        .await;
    });

    assert!(
        wait_for_proxy_count(&proxy_state, 1, Duration::from_secs(10)).await,
        "DP should apply the primary CP's snapshot first"
    );
    assert!(
        connection_state.load().connected,
        "DP should report connected to the primary CP"
    );

    // Silently partition the established stream: sockets stay open, bytes stop.
    blackhole.store(true, Ordering::Relaxed);

    assert!(
        wait_for_proxy_count(&proxy_state, 3, Duration::from_secs(45)).await,
        "DP must detect the silent partition and reach the fallback CP"
    );
    let state = connection_state.load();
    assert_eq!(
        state.cp_url, fallback_url,
        "DP must be attached to the fallback CP after the partition"
    );
    assert!(
        !state.is_primary,
        "the fallback CP must not be reported as primary"
    );

    client_handle.abort();
    relay_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn dp_snapshot_apply_is_never_detached_by_a_lifecycle_select_arm() {
    // Issue #2969 acceptance: a slow/in-flight FULL_SNAPSHOT apply must not be
    // detachable by a lifecycle select! arm. `update_config_off_thread` is a
    // `spawn_blocking`, so cancelling the await would leave the swap running
    // detached and able to land after the DP has moved on — silently
    // overwriting a newer snapshot with an older one.
    //
    // Deterministic proof: race a large snapshot apply against the shutdown arm,
    // then assert the config observed when the DP client returns never changes
    // afterwards. A detached apply would land after that return.
    let (addr, update_tx, _server_handle) = start_test_cp_server(create_test_config(1)).await;

    let proxy_state = create_test_proxy_state();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let ps = proxy_state.clone();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            vec![cp_url],
            test_secret(),
            ps,
            Some(shutdown_rx),
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

    assert!(
        wait_for_proxy_count(&proxy_state, 1, Duration::from_secs(10)).await,
        "DP should apply the initial snapshot"
    );

    // A deliberately large snapshot so the apply has real work to do, pushed
    // immediately before shutdown so both land in the same select! iteration.
    let mut large = create_test_config(400);
    large.loaded_at = Utc::now();
    CpGrpcServer::broadcast_update(&update_tx, &large);
    let _ = shutdown_tx.send(true);

    let returned = timeout(Duration::from_secs(20), client_handle).await;
    assert!(
        returned.is_ok(),
        "DP client must observe shutdown and return"
    );

    // Whatever was committed must be a complete snapshot, never a torn mix.
    let at_return = proxy_state.config.load().proxies.len();
    assert!(
        at_return == 1 || at_return == 400,
        "config must only ever be a complete snapshot, saw {at_return} proxies"
    );

    // The decisive assertion: no apply may still be in flight once the client
    // has returned. A detached `spawn_blocking` would mutate the config here.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        at_return,
        "no config apply may land after the DP client returned"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dp_failover_refuses_older_snapshot_and_preserves_newer_config() {
    // Issue #2970 acceptance: two CP sources, newer then older. On failover the
    // DP must refuse the older body, terminate that source's stream (so the
    // stale CP's next delta can never apply against newer config), and keep
    // serving the newer active config.
    let mut newer = create_test_config(3);
    newer.loaded_at = Utc::now();
    let (newer_addr, _newer_tx, newer_handle) = start_test_cp_server(newer).await;

    let mut older = create_test_config(1);
    older.loaded_at = Utc::now() - chrono::Duration::hours(6);
    let (older_addr, older_tx, _older_handle) = start_test_cp_server(older).await;

    let proxy_state = create_test_proxy_state();
    let newer_url = format!("http://127.0.0.1:{}", newer_addr.port());
    let older_url = format!("http://127.0.0.1:{}", older_addr.port());
    let connection_state = Arc::new(ArcSwap::new(Arc::new(
        DpCpConnectionState::new_disconnected(&newer_url),
    )));

    let ps = proxy_state.clone();
    let cs = connection_state.clone();
    let urls = vec![newer_url, older_url];
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            urls,
            test_secret(),
            ps,
            None,
            None,
            None,
            None,
            "ferrum".to_string(),
            0,
            Some(cs),
            None,
        )
        .await;
    });

    assert!(
        wait_for_proxy_count(&proxy_state, 3, Duration::from_secs(10)).await,
        "DP should apply the newer CP's snapshot"
    );
    let accepted_at = connection_state.load().last_config_received_at;

    // Take the newer CP away so the DP fails over to the stale one.
    newer_handle.abort();

    // Give the DP several failover cycles against the stale CP.
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        3,
        "a stale fallback snapshot must never roll the applied config back"
    );
    assert_eq!(
        connection_state.load().last_config_received_at,
        accepted_at,
        "a fenced snapshot must not advance last_config_received_at"
    );

    // The fenced stream must be terminated, not merely skipped: a delta pushed
    // by the stale CP must never reach the DP's applied config.
    let stale_delta = add_proxy_delta(create_test_proxy("stale-injected", "/stale"));
    let version = stale_delta.poll_timestamp.to_rfc3339();
    let body = serde_json::to_string(&stale_delta).unwrap();
    let _ = older_tx.send(delta_update(body, &version));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let injected = proxy_state
        .config
        .load()
        .proxies
        .iter()
        .any(|proxy| proxy.id == "stale-injected");
    assert!(
        !injected,
        "a delta from the fenced stale CP must never apply against newer config"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn older_cross_source_payload_comparison_canonicalizes_the_candidate() {
    // The older-cross-source identical-payload exception compares a raw
    // CP-delivered snapshot against the DP's *applied* config. `update_config`
    // canonicalizes a snapshot before storing it (normalize, resolve upstream
    // TLS, quarantine invalid HMAC credentials, inject gateway
    // workload-metrics identity), so comparing the raw candidate reports a
    // spurious mismatch and fences an equivalent failover snapshot that should
    // have established a safe delta base.
    //
    // Hostname normalization is the cheapest deterministic proof of that skew:
    // the applied config holds the lowercased host, the raw candidate does not.
    use ferrum_edge::grpc::configsync_lifecycle::gateway_config_content_matches;

    let state = create_test_proxy_state();

    let mut raw = create_test_config(1);
    raw.proxies[0].backend_host = "UPPER.Example.Test".to_string();

    let outcome = state.update_config(raw.clone());
    assert_eq!(outcome, ferrum_edge::proxy::ConfigApplyOutcome::Applied);

    let applied = state.current_config();
    assert_eq!(
        applied.proxies[0].backend_host, "upper.example.test",
        "update_config must store the canonicalized snapshot"
    );

    assert!(
        !gateway_config_content_matches(applied.as_ref(), &raw),
        "raw candidate must not match the applied config; this is the skew being guarded"
    );

    let comparable = state.canonicalize_snapshot_for_comparison(&raw);
    assert!(
        gateway_config_content_matches(applied.as_ref(), &comparable),
        "canonicalized candidate must match the applied config so the \
         identical-payload exception is not silently inert"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dp_becomes_ready_and_applies_delta_despite_unbindable_stream_port() {
    // Issue #2971 acceptance: a CP snapshot containing a stream proxy whose port
    // never binds on this node must still make the DP ready, must not tear down
    // the healthy ConfigSync stream (bind failures are non-fatal in DP mode),
    // and a subsequent delta must still apply on that same stream.
    let mut cp_config = create_test_config(1);
    let stream_proxy = create_test_tcp_stream_proxy("tcp-unbindable", 19087);
    cp_config.proxies.push(stream_proxy);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let startup_ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let connection_state = Arc::new(ArcSwap::new(Arc::new(
        DpCpConnectionState::new_disconnected(&cp_url),
    )));

    let ps = proxy_state.clone();
    let ready = startup_ready.clone();
    let cs = connection_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            vec![cp_url],
            test_secret(),
            ps,
            None,
            None,
            None,
            Some(ready),
            "ferrum".to_string(),
            0,
            Some(cs),
            None,
        )
        .await;
    });

    // The DP snapshot path waits up to 10s for stream listeners to start; the
    // unbindable one never will, and that must only produce a warning.
    assert!(
        wait_for_flag(&startup_ready, Duration::from_secs(40)).await,
        "one unbindable stream port must not block DP readiness"
    );
    assert!(
        connection_state.load().connected,
        "the ConfigSync stream must stay connected through a local bind failure"
    );

    // The same stream must still carry deltas.
    let delta = add_proxy_delta(create_test_proxy("after-bind-failure", "/after"));
    let version = delta.poll_timestamp.to_rfc3339();
    let body = serde_json::to_string(&delta).unwrap();
    let _ = update_tx.send(delta_update(body, &version));

    assert!(
        wait_for_proxy_id(&proxy_state, "after-bind-failure", Duration::from_secs(10)).await,
        "a delta after a local stream bind failure must still apply"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn dp_returns_promptly_on_shutdown_of_a_healthy_idle_stream() {
    // Issue #2972 acceptance: a DP parked on a healthy, idle ConfigSync stream
    // must observe shutdown and return promptly instead of burning the outer
    // five-second background drain in data_plane.rs.
    let (addr, _update_tx, _server_handle) = start_test_cp_server(create_test_config(2)).await;

    let proxy_state = create_test_proxy_state();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let ps = proxy_state.clone();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            vec![cp_url],
            test_secret(),
            ps,
            Some(shutdown_rx),
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

    assert!(
        wait_for_proxy_count(&proxy_state, 2, Duration::from_secs(10)).await,
        "DP should apply the initial snapshot"
    );
    // The stream is now healthy and idle — exactly the state that used to park
    // the DP in `message().await` until the drain timeout expired.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let started = std::time::Instant::now();
    let _ = shutdown_tx.send(true);
    let returned = timeout(Duration::from_secs(3), client_handle).await;
    assert!(
        returned.is_ok(),
        "DP client must return on shutdown of an idle healthy stream"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "shutdown must not consume the outer 5s drain budget, took {:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cp_only_negotiates_heartbeats_with_subscribers_that_advertise_support() {
    // Issue #2395 mixed-version, new CP → legacy DP: heartbeats are a negotiated
    // capability. A subscriber that does not advertise support must never be
    // told heartbeats are on, and therefore never receives an empty heartbeat
    // envelope it would treat as an unusable FULL_SNAPSHOT and churn on.
    let (addr, _update_tx, _server_handle) = start_test_cp_server(create_test_config(1)).await;

    for advertises in [false, true] {
        let token =
            dp_client::generate_dp_jwt_with_issuer(TEST_JWT_SECRET, "hb-neg", TEST_DEFAULT_ISSUER)
                .unwrap();
        let mut client = connect_client_with_token!(addr, token);
        let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
            node_id: "hb-neg".to_string(),
            ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
            namespace: "ferrum".to_string(),
            real_ip_header: Some(String::new()),
            supports_heartbeat: advertises,
        });
        let mut stream = client.subscribe(request).await.unwrap().into_inner();
        let initial = timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("initial update should arrive")
            .expect("stream ok")
            .expect("initial update present");

        assert!(
            !initial.heartbeat,
            "the initial update is a real FULL_SNAPSHOT, never a heartbeat"
        );
        assert_eq!(
            initial.heartbeat_negotiated, advertises,
            "CP must confirm heartbeats only to subscribers that advertised them"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dp_applies_legacy_bare_id_removal_delta_in_its_own_namespace() {
    // Issue #2395 mixed-version, new DP ← legacy CP: a CP at an older patch
    // sends removal keys as bare ID strings. The DP must accept that body and
    // scope the removals to its already-authorized subscription namespace
    // instead of rejecting the delta and churning through resync reconnects.
    let mut cp_config = create_test_config(2);
    let upstream = create_test_upstream("upstream-legacy", &[("backend", 8080)]);
    cp_config.upstreams.push(upstream);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(
            &cp_url,
            &test_secret(),
            "legacy-delta-node",
            &ps,
            None,
            "ferrum",
        )
        .await
    });

    assert!(
        wait_for_proxy_count(&proxy_state, 2, Duration::from_secs(10)).await,
        "DP should apply the initial snapshot"
    );

    // Exactly the body an older same-major.minor CP emits: bare-ID removal
    // arrays and no additive `removed_*_keys`. Envelope version must still
    // match the body's poll_timestamp instant (production CP contract).
    let poll_timestamp = Utc::now();
    let version = poll_timestamp.to_rfc3339();
    let legacy_body = serde_json::json!({
        "added_or_modified_proxies": [],
        "removed_proxy_ids": ["proxy-1"],
        "added_or_modified_consumers": [],
        "removed_consumer_ids": [],
        "added_or_modified_plugin_configs": [],
        "removed_plugin_config_ids": [],
        "added_or_modified_upstreams": [],
        "removed_upstream_ids": ["upstream-legacy"],
        "poll_timestamp": version,
    });
    let body = serde_json::to_string(&legacy_body).unwrap();
    let _ = update_tx.send(delta_update(body, &version));

    assert!(
        wait_for_proxy_count_without_upstreams(&proxy_state, 1, Duration::from_secs(10)).await,
        "a legacy bare-ID removal delta must apply in the subscription namespace"
    );
    assert_eq!(proxy_state.config.load().proxies[0].id, "proxy-0");

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn delta_broadcast_body_stays_parseable_by_a_legacy_removal_id_shape() {
    // Issue #2395 mixed-version, new CP → legacy DP: the DELTA body the CP puts
    // on the wire must still deserialize under the pre-qualified-removals
    // schema, i.e. `removed_*_ids` are bare strings and the namespace-qualified
    // keys ride in additive arrays a legacy DP ignores.
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![create_test_proxy("proxy-new", "/new")],
        removed_proxy_ids: vec![NamespacedResourceId::new("ferrum", "proxy-gone")],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![NamespacedResourceId::new("ferrum", "consumer-gone")],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![NamespacedResourceId::new("ferrum", "plugin-gone")],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![NamespacedResourceId::new("ferrum", "upstream-gone")],
        sequence_cursor: 3,
        poll_timestamp: Utc::now(),
    };
    let (_addr, update_tx, _server_handle) = start_test_cp_server(create_test_config(1)).await;
    let mut receiver = update_tx.subscribe();
    let version = delta.poll_timestamp.to_rfc3339();
    CpGrpcServer::broadcast_delta(&update_tx, &delta, &version);
    let broadcast = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("delta should broadcast")
        .expect("broadcast payload");

    let body: serde_json::Value = serde_json::from_str(&broadcast.config_json).unwrap();
    assert_eq!(body["removed_proxy_ids"], serde_json::json!(["proxy-gone"]));
    assert_eq!(
        body["removed_plugin_config_ids"],
        serde_json::json!(["plugin-gone"])
    );
    assert_eq!(
        body["removed_upstream_ids"],
        serde_json::json!(["upstream-gone"])
    );
    assert_eq!(body["removed_proxy_keys"][0]["namespace"], "ferrum");
    assert_eq!(body["removed_consumer_ids"][0]["namespace"], "ferrum");
    assert!(
        !broadcast.heartbeat,
        "a resource delta must never be flagged as a heartbeat"
    );
}
