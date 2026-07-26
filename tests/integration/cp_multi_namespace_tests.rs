//! Multi-namespace control plane integration tests (MESH-T2-A).
//!
//! Verifies the per-namespace broadcast partitioning, CP scope authorisation,
//! and JWT `ns` tenancy claim enforcement. Companion to
//! `cp_dp_grpc_tests.rs` (which covers the single-namespace back-compat
//! path) — the back-compat path is intentionally re-exercised here under
//! the new scope abstraction to prove the byte-identical guarantee.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use tokio::time::timeout;
use tonic::transport::Server;

use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::grpc::cp_server::{CpGrpcServer, CpScope, DpNodeRegistry};
use ferrum_edge::grpc::mesh_registry::MeshNodeRegistry;
use ferrum_edge::grpc::mesh_server::MeshGrpcServer;
use ferrum_edge::identity::TrustDomain;
use ferrum_edge::modes::mesh::config::{MeshConfig, MeshService, TrustBundle, TrustBundleSet};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::xds::{LDS_TYPE_URL, XdsAdsServer};

const TEST_JWT_SECRET: &str = "test-grpc-secret-multi-ns-2026-jeremyjpj";
const TEST_ISSUER: &str = "ferrum-edge-cp-dp";

/// Mint a JWT with an optional `ns` claim (string or array). When `ns` is
/// `None`, the token carries no `ns` claim — exercises the back-compat
/// fall-through path.
fn mint_token_with_ns(node_id: &str, ns: Option<serde_json::Value>) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "sub": node_id,
        "iat": now,
        "exp": now + 600,
        "iss": TEST_ISSUER,
        "role": "data_plane",
    });
    if let Some(ns_value) = ns {
        claims["ns"] = ns_value;
    }
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("test JWT must encode")
}

/// Create a minimal Proxy entry in `namespace`. Uses serde to avoid copying
/// the giant Proxy fixture from cp_dp_grpc_tests.rs.
fn proxy_in(id: &str, namespace: &str) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: namespace.to_string(),
        name: Some(id.to_string()),
        hosts: vec![],
        listen_path: Some(format!("/{id}")),
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

fn test_trust_bundles() -> TrustBundleSet {
    TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new("cluster.local").expect("valid trust domain"),
            x509_authorities: vec!["AQIDBA==".to_string()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    }
}

fn mesh_service(name: &str, namespace: &str) -> MeshService {
    MeshService {
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: Vec::new(),
        workloads: Vec::new(),
        protocol_overrides: HashMap::new(),
        cluster_ips: Vec::new(),
    }
}

fn multi_tenant_mesh_config() -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        mesh: Some(Box::new(MeshConfig {
            services: vec![
                mesh_service("svc-tenant-a", "tenant-a"),
                mesh_service("svc-tenant-b", "tenant-b"),
            ],
            trust_bundles: Some(test_trust_bundles()),
            ..MeshConfig::default()
        })),
        ..Default::default()
    }
}

/// Boot a CP gRPC server with an explicit `CpScope` and the
/// `cp_require_namespace_claim` knob.
async fn start_cp_with_scope(
    config: GatewayConfig,
    scope: CpScope,
    require_ns_claim: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let registry = Arc::new(DpNodeRegistry::new());
    let (server, _tx) = CpGrpcServer::builder(cfg_arc, TEST_JWT_SECRET.to_string())
        .channel_capacity(64)
        .registry(registry)
        .expected_issuer(TEST_ISSUER.to_string())
        .scope(scope)
        .require_ns_claim(require_ns_claim)
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

/// Macro: connect a raw `ConfigSyncClient` carrying `token` in the
/// `authorization` metadata header. Using a macro rather than an `async fn`
/// avoids leaking a complex `impl FnMut(...)` closure type through the
/// helper's return signature.
macro_rules! connect_with_token {
    ($addr:expr, $token:expr) => {{
        let token_meta: tonic::metadata::MetadataValue<_> =
            format!("Bearer {}", $token).parse().unwrap();
        let channel = tonic::transport::Channel::from_shared(format!("http://{}", $addr))
            .unwrap()
            .connect()
            .await
            .unwrap();
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

macro_rules! connect_mesh_with_token {
    ($addr:expr, $token:expr) => {{
        let token_meta: tonic::metadata::MetadataValue<_> =
            format!("Bearer {}", $token).parse().unwrap();
        let channel = tonic::transport::Channel::from_shared(format!("http://{}", $addr))
            .unwrap()
            .connect()
            .await
            .unwrap();
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

async fn start_mesh_with_scope(
    config: GatewayConfig,
    scope: CpScope,
    require_ns_claim: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let (server, _tx) = MeshGrpcServer::builder(cfg_arc, TEST_JWT_SECRET.to_string())
        .channel_capacity(64)
        .registry(Arc::new(MeshNodeRegistry::new()))
        .expected_issuer(TEST_ISSUER.to_string())
        .namespace("tenant-a".to_string())
        .scope(scope)
        .require_ns_claim(require_ns_claim)
        .build();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("mesh gRPC server failed");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, handle)
}

async fn start_xds_with_scope(
    config: GatewayConfig,
    scope: CpScope,
    require_ns_claim: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let (_cp, update_tx) = CpGrpcServer::builder(cfg_arc.clone(), TEST_JWT_SECRET.to_string())
        .channel_capacity(64)
        .scope(scope.clone())
        .require_ns_claim(require_ns_claim)
        .build();
    let server = XdsAdsServer::new(
        cfg_arc,
        update_tx,
        TEST_JWT_SECRET.to_string(),
        TEST_ISSUER.to_string(),
        "tenant-a".to_string(),
        32,
    )
    .with_scope(scope)
    .with_require_namespace_claim(require_ns_claim);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("xDS server failed");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, handle)
}

// ── Back-compat: single-namespace CP behaves identically ──────────────────

/// `CpScope::Single("ferrum")` + no `ns` claim + `require_claim=false` is
/// the back-compat default. A DP in the same namespace must succeed and
/// receive the initial snapshot.
#[tokio::test(flavor = "multi_thread")]
async fn back_compat_single_scope_accepts_matching_namespace() {
    let mut cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        ..Default::default()
    };
    cfg.proxies.push(proxy_in("p-1", "ferrum"));
    cfg.proxies.push(proxy_in("p-2", "ferrum"));

    let (addr, handle) =
        start_cp_with_scope(cfg, CpScope::Single("ferrum".to_string()), false).await;

    let token = mint_token_with_ns("dp-a", None);
    let mut client = connect_with_token!(addr, token);

    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-a".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    let mut stream = client
        .subscribe(request)
        .await
        .expect("subscribe must succeed on matching namespace")
        .into_inner();
    let first = timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("stream message within 5s")
        .expect("stream message ok")
        .expect("first message present");
    assert_eq!(first.update_type, 0);
    let cfg: GatewayConfig =
        serde_json::from_str(&first.config_json).expect("initial snapshot parses");
    assert_eq!(cfg.proxies.len(), 2, "DP must see all 2 ferrum proxies");

    handle.abort();
}

/// `CpScope::Single("production")` rejects a DP requesting `staging`. The
/// rejection must mention both namespaces so operators can debug fast.
#[tokio::test(flavor = "multi_thread")]
async fn back_compat_single_scope_rejects_mismatched_namespace() {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        ..Default::default()
    };
    let (addr, handle) =
        start_cp_with_scope(cfg, CpScope::Single("production".to_string()), false).await;

    let token = mint_token_with_ns("dp-b", None);
    let mut client = connect_with_token!(addr, token);

    let request = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-b".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "staging".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    let err = client
        .subscribe(request)
        .await
        .expect_err("CP must reject mismatched namespace");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    let msg = err.message();
    assert!(
        msg.contains("staging") && msg.contains("production"),
        "error must reference both namespaces, got: {msg}"
    );

    handle.abort();
}

// ── Multi-tenant: per-namespace broadcast partitioning ────────────────────

/// `CpScope::Set({prod,staging})` accepts claimed subscribers in either namespace,
/// rejects subscribers in unlisted namespaces, AND a delta written into one
/// namespace is invisible to subscribers in the other namespace.
#[tokio::test(flavor = "multi_thread")]
async fn multi_ns_set_scope_partitions_broadcasts_per_namespace() {
    let mut cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        ..Default::default()
    };
    cfg.proxies.push(proxy_in("p-prod-1", "prod"));
    cfg.proxies.push(proxy_in("p-prod-2", "prod"));
    cfg.proxies.push(proxy_in("p-staging-1", "staging"));

    let mut set = HashSet::new();
    set.insert("prod".to_string());
    set.insert("staging".to_string());
    let (addr, handle) = start_cp_with_scope(cfg, CpScope::Set(set), false).await;

    // Subscribe DP in prod.
    let prod_token = mint_token_with_ns("dp-prod", Some(json!("prod")));
    let mut prod_client = connect_with_token!(addr, prod_token);
    let prod_req = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-prod".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "prod".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    let mut prod_stream = prod_client.subscribe(prod_req).await.unwrap().into_inner();
    let prod_first = timeout(Duration::from_secs(5), prod_stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let prod_cfg: GatewayConfig = serde_json::from_str(&prod_first.config_json).unwrap();
    assert_eq!(
        prod_cfg.proxies.len(),
        2,
        "prod DP must only see prod proxies"
    );
    for p in &prod_cfg.proxies {
        assert_eq!(p.namespace, "prod");
    }

    // Subscribe DP in staging.
    let staging_token = mint_token_with_ns("dp-staging", Some(json!("staging")));
    let mut staging_client = connect_with_token!(addr, staging_token);
    let staging_req = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-staging".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "staging".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    let mut staging_stream = staging_client
        .subscribe(staging_req)
        .await
        .unwrap()
        .into_inner();
    let staging_first = timeout(Duration::from_secs(5), staging_stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let staging_cfg: GatewayConfig = serde_json::from_str(&staging_first.config_json).unwrap();
    assert_eq!(
        staging_cfg.proxies.len(),
        1,
        "staging DP must only see staging proxies"
    );
    assert_eq!(staging_cfg.proxies[0].namespace, "staging");

    // Subscribe DP in a namespace NOT in the CP scope — must be rejected.
    let dev_token = mint_token_with_ns("dp-dev", Some(json!("dev")));
    let mut dev_client = connect_with_token!(addr, dev_token);
    let dev_req = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-dev".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "dev".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    let err = dev_client.subscribe(dev_req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    handle.abort();
}

/// `CpScope::All` accepts subscribers in any namespace; the initial
/// snapshot is filtered to that DP's namespace.
#[tokio::test(flavor = "multi_thread")]
async fn multi_ns_all_scope_filters_initial_snapshot_per_subscriber() {
    let mut cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        ..Default::default()
    };
    cfg.proxies.push(proxy_in("p-a", "ns-a"));
    cfg.proxies.push(proxy_in("p-b", "ns-b"));
    cfg.proxies.push(proxy_in("p-c", "ns-c"));

    let (addr, handle) = start_cp_with_scope(cfg, CpScope::All, false).await;

    for (node_id, ns, expected_proxy) in [
        ("dp-a", "ns-a", "p-a"),
        ("dp-b", "ns-b", "p-b"),
        ("dp-c", "ns-c", "p-c"),
    ] {
        let token = mint_token_with_ns(node_id, Some(json!(ns)));
        let mut client = connect_with_token!(addr, token);
        let req = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
            node_id: node_id.to_string(),
            ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
            namespace: ns.to_string(),
            real_ip_header: Some(String::new()),
            supports_heartbeat: true,
        });
        let mut stream = client.subscribe(req).await.unwrap().into_inner();
        let first = timeout(Duration::from_secs(5), stream.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let snap: GatewayConfig = serde_json::from_str(&first.config_json).unwrap();
        assert_eq!(
            snap.proxies.len(),
            1,
            "{} must see only its namespace",
            node_id
        );
        assert_eq!(snap.proxies[0].id, expected_proxy);
        assert_eq!(snap.proxies[0].namespace, ns);
    }

    handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_ns_set_scope_rejects_token_without_ns_by_default() {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        ..Default::default()
    };
    let mut set = HashSet::new();
    set.insert("prod".to_string());
    set.insert("staging".to_string());
    let (addr, handle) = start_cp_with_scope(cfg, CpScope::Set(set), false).await;

    let token = mint_token_with_ns("dp-no-claim", None);
    let mut client = connect_with_token!(addr, token);
    let req = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-no-claim".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "prod".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    let err = client.subscribe(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(err.message().contains("Multi-namespace"));
    handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_ns_rejects_malformed_ns_claim_before_snapshot() {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        proxies: vec![proxy_in("p-prod", "prod")],
        ..Default::default()
    };
    let (addr, handle) = start_cp_with_scope(cfg, CpScope::All, false).await;

    let token = mint_token_with_ns("dp-bad-claim", Some(json!(42)));
    let mut client = connect_with_token!(addr, token);
    let req = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-bad-claim".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "prod".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    let err = client.subscribe(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert!(err.message().contains("ns"));
    handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_ns_trust_bundles_are_not_sent_to_tenant_side_channel() {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        proxies: vec![proxy_in("p-prod", "prod")],
        trust_bundles: Some(Box::new(test_trust_bundles())),
        ..Default::default()
    };
    let mut set = HashSet::new();
    set.insert("prod".to_string());
    set.insert("staging".to_string());
    let (addr, handle) = start_cp_with_scope(cfg, CpScope::Set(set), false).await;

    let token = mint_token_with_ns("dp-prod", Some(json!("prod")));
    let mut client = connect_with_token!(addr, token);
    let req = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-prod".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "prod".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    let mut stream = client.subscribe(req).await.unwrap().into_inner();
    let first = timeout(Duration::from_secs(5), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.trust_bundles_json, "null");
    let snap: GatewayConfig = serde_json::from_str(&first.config_json).unwrap();
    assert!(snap.trust_bundles.is_none());
    handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn native_mesh_subscribe_filters_tenant_slice_and_trust_material() {
    let mut set = HashSet::new();
    set.insert("tenant-a".to_string());
    set.insert("tenant-b".to_string());
    let (addr, handle) =
        start_mesh_with_scope(multi_tenant_mesh_config(), CpScope::Set(set), false).await;

    let token = mint_token_with_ns("mesh-tenant-a", Some(json!("tenant-a")));
    let mut client = connect_mesh_with_token!(addr, token);
    let req = tonic::Request::new(ferrum_edge::grpc::proto::MeshSubscribeRequest {
        node_id: "mesh-tenant-a".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "tenant-a".to_string(),
        workload_spiffe_id: String::new(),
        labels: HashMap::new(),
        waypoint_name: String::new(),
        ambient_udp_source_scoping: false,
    });
    let mut stream = client.mesh_subscribe(req).await.unwrap().into_inner();
    let first = timeout(Duration::from_secs(5), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let slice: MeshSlice = serde_json::from_str(&first.mesh_slice_json).unwrap();
    assert_eq!(slice.namespace, "tenant-a");
    assert_eq!(slice.services.len(), 1);
    assert_eq!(slice.services[0].name, "svc-tenant-a");
    assert!(slice.trust_bundles.is_none());

    handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn native_mesh_subscribe_rejects_missing_claim_in_multi_scope() {
    let mut set = HashSet::new();
    set.insert("tenant-a".to_string());
    set.insert("tenant-b".to_string());
    let (addr, handle) =
        start_mesh_with_scope(multi_tenant_mesh_config(), CpScope::Set(set), false).await;

    let token = mint_token_with_ns("mesh-no-claim", None);
    let mut client = connect_mesh_with_token!(addr, token);
    let req = tonic::Request::new(ferrum_edge::grpc::proto::MeshSubscribeRequest {
        node_id: "mesh-no-claim".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "tenant-a".to_string(),
        workload_spiffe_id: String::new(),
        labels: HashMap::new(),
        waypoint_name: String::new(),
        ambient_udp_source_scoping: false,
    });
    let err = client.mesh_subscribe(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn xds_rejects_missing_and_ambiguous_namespace_claims_in_multi_scope() {
    let mut set = HashSet::new();
    set.insert("tenant-a".to_string());
    set.insert("tenant-b".to_string());
    let (addr, handle) =
        start_xds_with_scope(multi_tenant_mesh_config(), CpScope::Set(set), false).await;

    for (node_id, token) in [
        ("xds-no-claim", mint_token_with_ns("xds-no-claim", None)),
        (
            "xds-ambiguous",
            mint_token_with_ns("xds-ambiguous", Some(json!(["tenant-a", "tenant-b"]))),
        ),
    ] {
        let channel = tonic::transport::Channel::from_shared(format!("http://{}", addr))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client =
            ferrum_edge::xds::proto::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient::new(
                channel,
            );
        let requests = tokio_stream::iter(vec![ferrum_edge::xds::proto::DiscoveryRequest {
            version_info: String::new(),
            node: Some(ferrum_edge::xds::proto::Node {
                id: node_id.to_string(),
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
        let err = client
            .stream_aggregated_resources(request)
            .await
            .expect_err("xDS must reject before opening stream");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    handle.abort();
}

// ── JWT `ns` claim enforcement ────────────────────────────────────────────

/// `require_claim=true` rejects a DP whose JWT carries no `ns` claim, even
/// when the CP scope and DP namespace would otherwise match.
#[tokio::test(flavor = "multi_thread")]
async fn require_claim_rejects_token_without_ns() {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        ..Default::default()
    };
    let (addr, handle) = start_cp_with_scope(cfg, CpScope::Single("prod".to_string()), true).await;

    let token = mint_token_with_ns("dp-no-claim", None);
    let mut client = connect_with_token!(addr, token);
    let req = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-no-claim".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "prod".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    let err = client.subscribe(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(
        err.message().contains("FERRUM_CP_REQUIRE_NAMESPACE_CLAIM"),
        "error must explain the require-claim policy, got: {}",
        err.message()
    );
    handle.abort();
}

/// `require_claim=true` accepts a DP whose `ns` claim matches the requested
/// namespace.
#[tokio::test(flavor = "multi_thread")]
async fn require_claim_accepts_matching_string_claim() {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        ..Default::default()
    };
    let (addr, handle) = start_cp_with_scope(cfg, CpScope::Single("prod".to_string()), true).await;

    let token = mint_token_with_ns("dp-claim-prod", Some(json!("prod")));
    let mut client = connect_with_token!(addr, token);
    let req = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-claim-prod".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "prod".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    let mut stream = client
        .subscribe(req)
        .await
        .expect("CP must accept matching claim")
        .into_inner();
    let first = timeout(Duration::from_secs(5), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.update_type, 0);
    handle.abort();
}

/// Multi-value claim authorises every listed namespace. Same bearer can
/// connect for `prod` AND `staging`, but not for `dev`.
#[tokio::test(flavor = "multi_thread")]
async fn array_claim_authorises_multiple_namespaces() {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        ..Default::default()
    };
    let mut set = HashSet::new();
    set.insert("prod".to_string());
    set.insert("staging".to_string());
    set.insert("dev".to_string());
    let (addr, handle) = start_cp_with_scope(cfg, CpScope::Set(set), true).await;

    let token = mint_token_with_ns("dp-multi", Some(json!(["prod", "staging"])));

    // Connect for `prod` — must succeed.
    let mut client_prod = connect_with_token!(addr, token.clone());
    let req_prod = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-multi".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "prod".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    assert!(
        client_prod.subscribe(req_prod).await.is_ok(),
        "claim ['prod','staging'] must allow prod"
    );

    // Connect for `dev` — must be rejected even though CP scope includes it.
    let mut client_dev = connect_with_token!(addr, token);
    let req_dev = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-multi".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "dev".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    let err = client_dev.subscribe(req_dev).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    handle.abort();
}

/// Claim that does NOT include the requested namespace rejects even when
/// the CP scope would otherwise allow it. The CP must consult the JWT
/// claim BEFORE the scope check — otherwise the CP scope becomes
/// effectively the only authorisation gate, which defeats the purpose of
/// per-token tenancy.
#[tokio::test(flavor = "multi_thread")]
async fn claim_overrides_cp_scope_when_more_restrictive() {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        ..Default::default()
    };
    let mut set = HashSet::new();
    set.insert("prod".to_string());
    set.insert("staging".to_string());
    let (addr, handle) = start_cp_with_scope(cfg, CpScope::Set(set), false).await;

    // Claim only authorises `staging`; bearer asks for `prod` — denied.
    let token = mint_token_with_ns("dp-restricted", Some(json!(["staging"])));
    let mut client = connect_with_token!(addr, token);
    let req = tonic::Request::new(ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: "dp-restricted".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "prod".to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    });
    let err = client.subscribe(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    handle.abort();
}

/// `GetFullConfig` honours the same JWT + scope checks as `Subscribe`.
#[tokio::test(flavor = "multi_thread")]
async fn get_full_config_filters_to_dp_namespace() {
    let mut cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        ..Default::default()
    };
    cfg.proxies.push(proxy_in("p-prod", "prod"));
    cfg.proxies.push(proxy_in("p-staging", "staging"));

    let mut set = HashSet::new();
    set.insert("prod".to_string());
    set.insert("staging".to_string());
    let (addr, handle) = start_cp_with_scope(cfg, CpScope::Set(set), false).await;

    let token = mint_token_with_ns("dp-prod", Some(json!("prod")));
    let mut client = connect_with_token!(addr, token);

    let req = tonic::Request::new(ferrum_edge::grpc::proto::FullConfigRequest {
        node_id: "dp-prod".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "prod".to_string(),
        real_ip_header: Some(String::new()),
    });
    let resp = client
        .get_full_config(req)
        .await
        .expect("GetFullConfig must succeed for prod")
        .into_inner();
    let snap: GatewayConfig = serde_json::from_str(&resp.config_json).expect("snapshot must parse");
    assert_eq!(snap.proxies.len(), 1);
    assert_eq!(snap.proxies[0].namespace, "prod");

    handle.abort();
}
