//! Admin API — Node-Waypoint Identities Endpoint
//!
//! Verifies that `GET /node-waypoint/identities` is JWT-gated, returns 404
//! when node-waypoint topology is not enabled, and surfaces the resolver's
//! enrolled-identity snapshot when it is. This is the operator-facing
//! introspection surface for GAP-2M's identity resolver — it lets
//! `kubectl`-style debugging answer "which pods is this waypoint serving?"
//! without scraping eBPF maps.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_ebpf_common::OrigDst4;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::SpiffeId;
use ferrum_edge::modes::mesh::node_waypoint::{
    NodeWaypointIdentity, NodeWaypointIdentityResolver, parse_pod_uid,
};
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
            jwt_secret: "test-secret-key-for-admin-api-32chars".to_string(),
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

fn make_admin_state(jwt: JwtManager, with_resolver: bool) -> AdminState {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let env_config = ferrum_edge::config::env_config::EnvConfig::default();
    let dns_cache = DnsCache::new(DnsConfig::default());
    let (mut proxy_state, _health_check_handles) =
        ProxyState::new(cfg, dns_cache, env_config, None, None).expect("proxy state");

    if with_resolver {
        let resolver = Arc::new(NodeWaypointIdentityResolver::new(0));
        // Two pods with distinct identities and a single cookie each.
        let pod_a = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let pod_b = parse_pod_uid("22222222-2222-2222-2222-222222222222").unwrap();
        let id_a = NodeWaypointIdentity::new(
            pod_a,
            SpiffeId::new("spiffe://cluster.local/ns/default/sa/api").unwrap(),
        );
        let id_b = NodeWaypointIdentity::new(
            pod_b,
            SpiffeId::new("spiffe://cluster.local/ns/default/sa/billing").unwrap(),
        );
        let hash_a = id_a.workload_spiffe_hash;
        let hash_b = id_b.workload_spiffe_hash;
        resolver.upsert_identity(id_a);
        resolver.upsert_identity(id_b);
        resolver.record_orig_dst4(
            101,
            OrigDst4 {
                addr: 0x0a000001,
                port: 8080,
                pod_uid: pod_a,
                workload_spiffe_hash: hash_a,
            },
        );
        resolver.record_orig_dst4(
            102,
            OrigDst4 {
                addr: 0x0a000002,
                port: 8081,
                pod_uid: pod_b,
                workload_spiffe_hash: hash_b,
            },
        );
        proxy_state = proxy_state.with_node_waypoint_identity_resolver(resolver);
    }

    AdminState {
        db: None,
        jwt_manager: jwt,
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: Some(proxy_state),
        mode: "test".to_string(),
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
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    }
}

async fn start_test_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    let state_clone = state.clone();
    let shutdown_rx_clone = shutdown_rx.clone();
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            state_clone,
            shutdown_rx_clone,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    (format!("http://{}", actual_addr), shutdown_tx)
}

async fn get_with_token(base_url: &str, path: &str, token: &str) -> (reqwest::StatusCode, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}{}", base_url, path))
        .header("authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    (status, body)
}

async fn get_unauth(base_url: &str, path: &str) -> reqwest::StatusCode {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}{}", base_url, path))
        .send()
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn node_waypoint_identities_requires_jwt() {
    let tc = TestConfig::default();
    let state = make_admin_state(create_test_jwt_manager(&tc), true);
    let (base_url, _shutdown) = start_test_admin(state).await;

    let status = get_unauth(&base_url, "/node-waypoint/identities").await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn node_waypoint_identities_returns_404_when_resolver_absent() {
    let tc = TestConfig::default();
    let state = make_admin_state(create_test_jwt_manager(&tc), false);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body) = get_with_token(&base_url, "/node-waypoint/identities", &token).await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("node-waypoint"),
        "expected an explanatory 'not enabled' error, got {body}"
    );
}

#[tokio::test]
async fn node_waypoint_identities_returns_enrolled_pods() {
    let tc = TestConfig::default();
    let state = make_admin_state(create_test_jwt_manager(&tc), true);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body) = get_with_token(&base_url, "/node-waypoint/identities", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["identity_count"], 2);
    assert_eq!(body["cookies"]["orig_dst4"], 2);
    assert_eq!(body["cookies"]["orig_dst6"], 0);

    let identities = body["identities"].as_array().unwrap();
    assert_eq!(identities.len(), 2);
    // Sorted by pod UID — pod_a (11..) before pod_b (22..).
    assert_eq!(
        identities[0]["pod_uid"],
        "11111111-1111-1111-1111-111111111111"
    );
    assert_eq!(
        identities[0]["spiffe_id"],
        "spiffe://cluster.local/ns/default/sa/api"
    );
    assert_eq!(identities[0]["orig_dst4_cookies"], 1);
    assert_eq!(identities[0]["orig_dst6_cookies"], 0);
    assert_eq!(identities[0]["has_policy_scope"], false);
    assert!(identities[0]["workload_spiffe_hash"].is_number());

    assert_eq!(
        identities[1]["pod_uid"],
        "22222222-2222-2222-2222-222222222222"
    );
    assert_eq!(
        identities[1]["spiffe_id"],
        "spiffe://cluster.local/ns/default/sa/billing"
    );
}
