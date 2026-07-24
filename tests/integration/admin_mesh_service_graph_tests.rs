use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::plugins::TransactionSummary;
use ferrum_edge::plugins::mesh::prometheus_helpers::mesh_request_key;
use ferrum_edge::plugins::mesh::service_graph::record_transaction_with_mesh_key;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
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
            jwt_secret: "test-secret-key-for-mesh-service-graph-32chars".to_string(),
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

fn admin_state(jwt: JwtManager) -> AdminState {
    admin_state_with_mesh_runtime(jwt, None)
}

fn admin_state_with_mesh_runtime(
    jwt: JwtManager,
    mesh_runtime_state: Option<MeshRuntimeState>,
) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt,
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
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
        reserved_ports: HashSet::new(),
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

fn active_mesh_runtime() -> MeshRuntimeState {
    let runtime = MeshRuntimeState::new();
    runtime.install_slice(MeshSlice {
        node_id: "test-node".to_string(),
        namespace: "default".to_string(),
        version: "test".to_string(),
        ..MeshSlice::default()
    });
    runtime
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

fn seed_service_graph_edge(source_principal: &str, destination_principal: &str) {
    let metadata = HashMap::from([
        (
            "mesh.source.principal".to_string(),
            source_principal.to_string(),
        ),
        (
            "mesh.destination.principal".to_string(),
            destination_principal.to_string(),
        ),
        ("mesh.source.workload".to_string(), "frontend".to_string()),
        ("mesh.source.namespace".to_string(), "default".to_string()),
        ("mesh.source.app".to_string(), "frontend".to_string()),
        ("mesh.source.service".to_string(), "frontend".to_string()),
        (
            "mesh.destination.workload".to_string(),
            "reviews".to_string(),
        ),
        (
            "mesh.destination.namespace".to_string(),
            "default".to_string(),
        ),
        ("mesh.destination.app".to_string(), "reviews".to_string()),
        (
            "mesh.destination.service".to_string(),
            "reviews".to_string(),
        ),
        ("mesh.request_protocol".to_string(), "http".to_string()),
        (
            "mesh.connection_security_policy".to_string(),
            "mutual_tls".to_string(),
        ),
    ]);

    let summary = TransactionSummary {
        namespace: "default".to_string(),
        proxy_id: Some("reviews".to_string()),
        proxy_name: Some("reviews".to_string()),
        response_status_code: 503,
        latency_total_ms: 7.5,
        metadata,
        ..TransactionSummary::default()
    };
    let mesh_key = mesh_request_key(&summary);
    record_transaction_with_mesh_key(&summary, mesh_key.as_ref());
}

async fn fetch_service_graph(base_url: &str, token: &str) -> (reqwest::StatusCode, Value) {
    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/service-graph"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.json().await.unwrap();
    (status, body)
}

#[tokio::test]
async fn mesh_service_graph_endpoint_requires_jwt() {
    let tc = TestConfig::default();
    let state = admin_state(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/service-graph"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn mesh_service_graph_endpoint_returns_seeded_topology_json() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let state =
        admin_state_with_mesh_runtime(create_test_jwt_manager(&tc), Some(active_mesh_runtime()));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let edge_id = uuid::Uuid::new_v4();
    let source_principal = format!("spiffe://cluster.local/ns/default/sa/frontend-{edge_id}");
    let destination_principal = format!("spiffe://cluster.local/ns/default/sa/reviews-{edge_id}");

    let mut body = Value::Null;
    for attempt in 0..3 {
        seed_service_graph_edge(&source_principal, &destination_principal);
        let (status, current_body) = fetch_service_graph(&base_url, &token).await;
        assert_eq!(status, reqwest::StatusCode::OK, "body: {current_body}");
        body = current_body;
        if body["edges"].as_array().is_some_and(|edges| {
            edges.iter().any(|edge| {
                edge["source_principal"] == source_principal
                    && edge["destination_principal"] == destination_principal
            })
        }) {
            break;
        }
        if attempt < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        }
    }

    assert!(
        body["edge_count"].as_u64().unwrap_or(0) >= 1,
        "missing graph edge count: {body}"
    );
    let edge = body["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|edge| {
            edge["source_principal"] == source_principal
                && edge["destination_principal"] == destination_principal
        })
        .unwrap_or_else(|| panic!("seeded edge missing from service graph: {body}"));
    assert_eq!(edge["source_workload"], "frontend");
    assert_eq!(edge["destination_service"], "reviews");
    assert_eq!(edge["request_protocol"], "http");
    assert_eq!(edge["connection_security_policy"], "mutual_tls");
    assert!(edge["requests_total"].as_u64().unwrap_or(0) >= 1);
    assert!(edge["errors_total"].as_u64().unwrap_or(0) >= 1);
    assert!(edge["duration_ms_total"].as_f64().unwrap_or(0.0) >= 7.5);
    assert!(edge["last_seen"].as_str().is_some());
}

#[tokio::test]
async fn mesh_service_graph_endpoint_requires_active_mesh_runtime() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let state = admin_state(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let (status, body) = fetch_service_graph(&base_url, &token).await;

    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "No active mesh service graph");
}
