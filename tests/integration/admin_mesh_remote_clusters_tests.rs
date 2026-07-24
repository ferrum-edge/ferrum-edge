//! Integration coverage for `GET /mesh/remote-clusters` (F7.2).
//!
//! Exercises the parts of the admin surface that genuinely need a live gateway:
//! JWT gating, the not-in-mesh-mode `404`, the empty-before-discovery shape, and
//! the accepted-slice → `configured` view contract (including that an accepted
//! `MultiClusterConfig` with no successfully-polled cluster yields an empty
//! `discovered` list — the discovery store is reconciled from the *accepted*
//! slice and is intentionally NOT mutable through any production API). The pure
//! response-builder logic — discovered counts/age, sorting, counts-only payload,
//! and the accepted-slice scoping that filters any cluster absent from the
//! accepted config out of `discovered` — is covered by the unit suite in
//! `tests/unit/admin/mesh_remote_clusters_tests.rs`, which can stage a
//! `RemoteEndpointSnapshot` directly without a runtime store seeder.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::env_config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::TrustDomain;
use ferrum_edge::modes::mesh::config::{MeshConfig, MultiClusterConfig, RemoteCluster};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::proxy::ProxyState;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-mesh-remote-clusters-32".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
        }
    }
}

fn create_test_jwt_manager(config: &TestConfig) -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        audience: None,
        max_ttl_seconds: config.max_ttl,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn generate_test_token(config: &TestConfig) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": "test-user",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

/// Build an `AdminState` in mesh mode. `discovery_poll_interval` > 0 flips the
/// `discovery_enabled` flag the handler reads from env config.
fn build_admin_state(
    jwt: JwtManager,
    mesh_runtime_state: Option<MeshRuntimeState>,
    discovery_poll_interval: u64,
) -> AdminState {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        mesh: Some(Box::new(MeshConfig::default())),
        ..GatewayConfig::default()
    };
    let env_config = EnvConfig {
        namespace: "alpha".to_string(),
        mesh_config_protocol: "native".to_string(),
        mesh_remote_discovery_poll_interval_seconds: discovery_poll_interval,
        ..EnvConfig::default()
    };
    let (proxy_state, _handles) = ProxyState::new(
        cfg,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("proxy state");

    AdminState {
        db: None,
        jwt_manager: jwt,
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: Some(proxy_state),
        mode: "mesh".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    }
}

async fn start_test_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual_addr).await.is_ok() {
            return (format!("http://{}", actual_addr), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {} never became ready", actual_addr);
}

fn td(raw: &str) -> TrustDomain {
    TrustDomain::new(raw).expect("trust domain")
}

/// Install an accepted slice carrying a `MultiClusterConfig` declaring two
/// remote clusters (one discoverable, one federation-only).
fn install_accepted_slice_with_config(runtime: &MeshRuntimeState) {
    let slice = MeshSlice {
        namespace: "alpha".to_string(),
        version: "v-rc-1".to_string(),
        multi_cluster: Some(MultiClusterConfig {
            local_cluster: Some("local".to_string()),
            federation_endpoint: None,
            remote_clusters: vec![
                RemoteCluster {
                    name: "remote-east".to_string(),
                    trust_domain: td("east.example.com"),
                    network: Some("net2".to_string()),
                    control_plane_url: Some("grpcs://cp.east.example.com:50051".to_string()),
                    federation_endpoint: Some("https://spire.east.example.com/bundle".to_string()),
                    discovery_credential_ref: None,
                },
                RemoteCluster {
                    name: "remote-west".to_string(),
                    trust_domain: td("west.example.com"),
                    network: None,
                    // Federation-only: no control plane, never discoverable.
                    control_plane_url: None,
                    federation_endpoint: Some("https://spire.west.example.com/bundle".to_string()),
                    discovery_credential_ref: None,
                },
            ],
            east_west_gateways: Vec::new(),
        }),
        ..MeshSlice::default()
    };
    runtime.install_slice(slice.clone());
    runtime.record_applied_slice(&slice);
}

#[tokio::test]
async fn remote_clusters_endpoint_requires_jwt() {
    let tc = TestConfig::default();
    let state = build_admin_state(
        create_test_jwt_manager(&tc),
        Some(MeshRuntimeState::new()),
        60,
    );
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/remote-clusters"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn remote_clusters_endpoint_returns_404_outside_mesh_mode() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    // No mesh_runtime_state wired in — mirrors the other `/mesh/*` endpoints'
    // wrong-mode branch.
    let state = build_admin_state(create_test_jwt_manager(&tc), None, 60);
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/remote-clusters"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn remote_clusters_endpoint_returns_200_empty_before_discovery() {
    // Mesh runtime wired but nothing discovered and no slice accepted — the DP
    // is in mesh mode but hasn't converged. Both lists must be present (and
    // empty) so dashboards can poll continuously across boot. Discovery is
    // disabled here (poll interval 0).
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let state = build_admin_state(
        create_test_jwt_manager(&tc),
        Some(MeshRuntimeState::new()),
        0,
    );
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/remote-clusters"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();

    assert_eq!(body["discovery_enabled"], false);
    assert_eq!(
        body["discovered"].as_array().map(Vec::len),
        Some(0),
        "discovered must be an empty array, not null"
    );
    assert_eq!(
        body["configured"].as_array().map(Vec::len),
        Some(0),
        "configured must be an empty array, not null"
    );
}

#[tokio::test]
async fn remote_clusters_endpoint_reflects_accepted_config_with_empty_discovered() {
    // An accepted slice declares two remote clusters but nothing has been
    // successfully polled yet (the discovery store is only populated by the live
    // poller, never by the admin/test surface). The end-to-end contract: the
    // `configured` view reflects the accepted slice, every entry reports
    // `discovered: false`, the `discovered` list is empty, and the
    // control-plane / federation URLs never appear in the payload.
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let runtime = MeshRuntimeState::new();
    install_accepted_slice_with_config(&runtime);

    let state = build_admin_state(create_test_jwt_manager(&tc), Some(runtime), 60);
    let (base_url, _shutdown) = start_test_admin(state).await;

    let body: Value = reqwest::Client::new()
        .get(format!("{base_url}/mesh/remote-clusters"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(body["discovery_enabled"], true);

    // Nothing polled → discovered is empty (and scoped to the accepted slice).
    let discovered = body["discovered"].as_array().expect("discovered array");
    assert!(
        discovered.is_empty(),
        "no cluster has been polled; discovered must be empty: {discovered:?}"
    );

    // ── configured view ──────────────────────────────────────────────────
    let configured = body["configured"].as_array().expect("configured array");
    assert_eq!(configured.len(), 2);
    // Sorted by cluster_name: remote-east before remote-west.
    let cfg_east = &configured[0];
    assert_eq!(cfg_east["cluster_name"], "remote-east");
    assert_eq!(cfg_east["trust_domain"], "east.example.com");
    assert_eq!(cfg_east["network"], "net2");
    assert_eq!(cfg_east["control_plane_configured"], true);
    assert_eq!(cfg_east["federation_endpoint_configured"], true);
    assert_eq!(
        cfg_east["discovered"], false,
        "remote-east is configured but nothing has been polled yet"
    );

    let cfg_west = &configured[1];
    assert_eq!(cfg_west["cluster_name"], "remote-west");
    assert_eq!(
        cfg_west["control_plane_configured"], false,
        "remote-west is federation-only"
    );
    assert_eq!(cfg_west["federation_endpoint_configured"], true);
    assert_eq!(cfg_west["discovered"], false);

    // Control-plane / federation URLs must never appear in the payload.
    let body_str = serde_json::to_string(&body).unwrap();
    assert!(
        !body_str.contains("grpcs://") && !body_str.contains("https://spire"),
        "configured entries must not expose control-plane / federation URLs: {body_str}"
    );
}
