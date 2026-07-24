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
use ferrum_edge::modes::mesh::config::{AppProtocol, MeshConfig, MeshService, ServicePort};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::{
    MeshEgressScopeResource, MeshEgressScopeSnapshot, MeshSlice,
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
            jwt_secret: "test-secret-key-for-mesh-egress-32chars".to_string(),
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

fn mesh_service(name: &str) -> MeshService {
    MeshService {
        cluster_ips: Vec::new(),
        name: name.to_string(),
        namespace: "alpha".to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: None,
            target_port: None,
        }],
        workloads: Vec::new(),
        protocol_overrides: std::collections::HashMap::new(),
    }
}

fn build_admin_state(jwt: JwtManager, mesh_runtime_state: Option<MeshRuntimeState>) -> AdminState {
    let mesh = MeshConfig {
        services: vec![mesh_service("reviews")],
        ..MeshConfig::default()
    };
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let env_config = EnvConfig {
        namespace: "alpha".to_string(),
        mesh_sidecar_enforced: false,
        mesh_sidecar_enforced_dry_run: true,
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

fn install_default_egress_slice(runtime: &MeshRuntimeState) {
    let slice = MeshSlice {
        namespace: "alpha".to_string(),
        sidecar_egress_scope: Some(MeshEgressScopeSnapshot {
            sidecar_enforced: false,
            dry_run: true,
            sidecar_applied: false,
            sidecar_admitted_services: 1,
            sidecar_denied_services: 1,
            services: vec![MeshEgressScopeResource {
                namespace: "alpha".to_string(),
                name: "reviews".to_string(),
                hosts: vec!["reviews.alpha.svc.cluster.local".to_string()],
                ports: vec![8080],
            }],
            known_destinations: vec!["reviews.alpha.svc.cluster.local:8080".to_string()],
            ..MeshEgressScopeSnapshot::default()
        }),
        ..MeshSlice::default()
    };
    runtime.install_slice(slice.clone());
    runtime.record_applied_slice(&slice);
}

fn admin_state(jwt: JwtManager) -> AdminState {
    let mesh_runtime = MeshRuntimeState::new();
    install_default_egress_slice(&mesh_runtime);
    build_admin_state(jwt, Some(mesh_runtime))
}

fn admin_state_without_mesh_runtime(jwt: JwtManager) -> AdminState {
    build_admin_state(jwt, None)
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

#[tokio::test]
async fn mesh_egress_scope_endpoint_returns_expected_json() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let state = admin_state(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response: Value = reqwest::Client::new()
        .get(format!("{base_url}/mesh/egress-scope"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(response["namespace"], "alpha");
    assert_eq!(response["scope"]["dry_run"], true);
    assert_eq!(response["health"]["sidecar_admitted_services"], 1);
    assert_eq!(response["health"]["sidecar_denied_services"], 1);
    assert_eq!(response["scope"]["services"][0]["name"], "reviews");
}

#[tokio::test]
async fn mesh_egress_scope_test_endpoint_admits_and_denies_candidates() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let state = admin_state(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let client = reqwest::Client::new();

    let admitted: Value = client
        .post(format!("{base_url}/mesh/egress-scope/test"))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({"host": "reviews.alpha.svc.cluster.local", "port": 8080}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(admitted["allowed"], true);

    let denied: Value = client
        .post(format!("{base_url}/mesh/egress-scope/test"))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({"host": "ratings.alpha.svc.cluster.local", "port": 8080}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(denied["allowed"], false);
    assert_eq!(denied["decision"], "deny");
}

#[tokio::test]
async fn mesh_egress_scope_endpoint_requires_jwt() {
    let tc = TestConfig::default();
    let state = admin_state(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{base_url}/mesh/egress-scope"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);

    let response = client
        .post(format!("{base_url}/mesh/egress-scope/test"))
        .json(&json!({"host": "reviews.alpha.svc.cluster.local"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn mesh_egress_scope_returns_404_without_accepted_slice() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    // No MeshRuntimeState is wired into AdminState — handler should report
    // "no active scope" instead of synthesising counts from raw config.
    let state = admin_state_without_mesh_runtime(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{base_url}/mesh/egress-scope"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);

    let response = client
        .post(format!("{base_url}/mesh/egress-scope/test"))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({"host": "reviews.alpha.svc.cluster.local"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn mesh_egress_scope_ignores_received_but_unaccepted_slice() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let runtime = MeshRuntimeState::new();
    install_default_egress_slice(&runtime);
    runtime.install_slice(MeshSlice {
        namespace: "alpha".to_string(),
        sidecar_egress_scope: Some(MeshEgressScopeSnapshot {
            sidecar_admitted_services: 9,
            sidecar_denied_services: 9,
            known_destinations: vec!["rejected.alpha.svc.cluster.local:8080".to_string()],
            ..MeshEgressScopeSnapshot::default()
        }),
        ..MeshSlice::default()
    });
    let state = build_admin_state(create_test_jwt_manager(&tc), Some(runtime));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let client = reqwest::Client::new();

    let response: Value = client
        .get(format!("{base_url}/mesh/egress-scope"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["health"]["sidecar_admitted_services"], 1);
    assert_eq!(response["health"]["sidecar_denied_services"], 1);

    let dry_run: Value = client
        .post(format!("{base_url}/mesh/egress-scope/test"))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({"host": "rejected.alpha.svc.cluster.local", "port": 8080}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(dry_run["allowed"], false);
}

#[tokio::test]
async fn mesh_egress_scope_test_endpoint_rejects_bad_request_bodies() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let state = admin_state(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let client = reqwest::Client::new();

    // Non-JSON body.
    let response = client
        .post(format!("{base_url}/mesh/egress-scope/test"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body("not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);

    // Missing host.
    let response = client
        .post(format!("{base_url}/mesh/egress-scope/test"))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({"port": 8080}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);

    // Empty host.
    let response = client
        .post(format!("{base_url}/mesh/egress-scope/test"))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({"host": ""}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);

    // Port 0.
    let response = client
        .post(format!("{base_url}/mesh/egress-scope/test"))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({"host": "reviews.alpha.svc.cluster.local", "port": 0}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
}
