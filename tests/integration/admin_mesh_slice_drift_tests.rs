//! Integration coverage for CP `GET /mesh/slice-drift` and
//! `ReportMeshSliceStatus` (issue #3265).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::auth::MESH_LOCAL_SUBSCRIBE_AUDIENCE;
use ferrum_edge::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER;
use ferrum_edge::grpc::dp_client;
use ferrum_edge::grpc::mesh_registry::MeshNodeRegistry;
use ferrum_edge::grpc::mesh_server::MeshGrpcServer;
use ferrum_edge::grpc::mesh_slice_drift::{MeshSliceConvergenceState, MeshSliceDriftRegistry};
use ferrum_edge::grpc::proto::mesh_config_sync_client::MeshConfigSyncClient;
use ferrum_edge::grpc::proto::mesh_config_sync_server::MeshConfigSyncServer;
use ferrum_edge::grpc::proto::{MeshSliceStatusReport, MeshSubscribeRequest};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

const ADMIN_JWT_SECRET: &str = "test-secret-key-for-mesh-slice-drift-32";
const ADMIN_JWT_ISSUER: &str = "test-ferrum-edge";
const GRPC_JWT_SECRET: &str = "test-cp-dp-grpc-jwt-secret-at-least-32";

fn admin_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": ADMIN_JWT_ISSUER,
        "sub": "test-user",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(ADMIN_JWT_SECRET.as_bytes()),
    )
    .expect("admin jwt")
}

fn mesh_jwt(node_id: &str) -> String {
    dp_client::generate_dp_jwt_full(
        GRPC_JWT_SECRET,
        node_id,
        DEFAULT_CP_DP_JWT_ISSUER,
        None,
        Some(MESH_LOCAL_SUBSCRIBE_AUDIENCE),
    )
    .expect("mesh jwt")
}

fn cp_admin_state(drift: Arc<MeshSliceDriftRegistry>) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: JwtManager::new(JwtConfig {
            secret: ADMIN_JWT_SECRET.to_string(),
            issuer: ADMIN_JWT_ISSUER.to_string(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        }),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "cp".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::common::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
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
        mesh_registry: Some(Arc::new(MeshNodeRegistry::new().with_drift(drift))),
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
    }
}

async fn start_test_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = TcpListener::bind(addr).await.unwrap();
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
            return (format!("http://{actual_addr}"), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener did not become ready");
}

async fn start_mesh_cp() -> (
    SocketAddr,
    Arc<MeshSliceDriftRegistry>,
    tokio::task::JoinHandle<()>,
) {
    start_mesh_cp_with_drift(Arc::new(MeshSliceDriftRegistry::new())).await
}

async fn start_mesh_cp_with_drift(
    drift: Arc<MeshSliceDriftRegistry>,
) -> (
    SocketAddr,
    Arc<MeshSliceDriftRegistry>,
    tokio::task::JoinHandle<()>,
) {
    let config = Arc::new(ArcSwap::from_pointee(GatewayConfig::default()));
    let registry = Arc::new(MeshNodeRegistry::new().with_drift(drift.clone()));
    let (server, _tx) = MeshGrpcServer::builder(config, GRPC_JWT_SECRET.to_string())
        .registry(registry)
        .drift(drift.clone())
        .expected_issuer(DEFAULT_CP_DP_JWT_ISSUER.to_string())
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let incoming = TcpListenerStream::new(listener);
    let handle = tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(MeshConfigSyncServer::new(server))
            .serve_with_incoming(incoming)
            .await;
    });
    (addr, drift, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn slice_drift_admin_auth_and_ack_nack_convergence() {
    let (grpc_addr, drift, _grpc_handle) = start_mesh_cp().await;
    let (admin_base, _shutdown) = start_test_admin(cp_admin_state(drift.clone())).await;

    let unauth = reqwest::Client::new()
        .get(format!("{admin_base}/mesh/slice-drift"))
        .send()
        .await
        .expect("unauth");
    assert_eq!(unauth.status(), reqwest::StatusCode::UNAUTHORIZED);

    let token = mesh_jwt("mesh-dp-a");
    let auth_header = format!("Bearer {token}");
    let channel = tonic::transport::Channel::from_shared(format!("http://{grpc_addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client =
        MeshConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert(
                "authorization",
                tonic::metadata::MetadataValue::try_from(auth_header.as_str()).unwrap(),
            );
            Ok(req)
        });

    let forged = MeshSubscribeRequest {
        node_id: "forged-id".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
        workload_spiffe_id: String::new(),
        labels: HashMap::new(),
        waypoint_name: String::new(),
        ambient_udp_source_scoping: false,
        remote_discovery: false,
        node_waypoint_capture_scoping: false,
    };
    assert!(
        client
            .mesh_subscribe(tonic::Request::new(forged))
            .await
            .is_err(),
        "JWT sub / node_id mismatch must fail closed"
    );

    let subscribe = MeshSubscribeRequest {
        node_id: "mesh-dp-a".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
        workload_spiffe_id: String::new(),
        labels: HashMap::new(),
        waypoint_name: String::new(),
        ambient_udp_source_scoping: false,
        remote_discovery: false,
        node_waypoint_capture_scoping: false,
    };
    let mut stream = client
        .mesh_subscribe(tonic::Request::new(subscribe.clone()))
        .await
        .unwrap()
        .into_inner();
    let update = stream.message().await.unwrap().unwrap();
    assert!(!update.heartbeat);
    assert!(!update.session_token.is_empty());

    client
        .report_mesh_slice_status(MeshSliceStatusReport {
            version: update.version.clone(),
            error_message: "slice_json_invalid".to_string(),
            session_token: update.session_token.clone(),
        })
        .await
        .expect("nack");
    assert_eq!(
        drift.snapshot().data_planes[0].convergence,
        MeshSliceConvergenceState::Rejecting
    );

    client
        .report_mesh_slice_status(MeshSliceStatusReport {
            version: update.version.clone(),
            error_message: String::new(),
            session_token: update.session_token.clone(),
        })
        .await
        .expect("ack");

    // A replacement stream can send the same version. The prior stream's
    // delayed ACK must still be refused by its opaque generation token.
    let mut replacement = client
        .mesh_subscribe(tonic::Request::new(subscribe))
        .await
        .unwrap()
        .into_inner();
    let replacement_update = replacement.message().await.unwrap().unwrap();
    assert_eq!(replacement_update.version, update.version);
    assert_ne!(replacement_update.session_token, update.session_token);
    assert!(
        client
            .report_mesh_slice_status(MeshSliceStatusReport {
                version: update.version.clone(),
                error_message: String::new(),
                session_token: update.session_token.clone(),
            })
            .await
            .is_err(),
        "stale same-version session ACK must fail closed"
    );
    client
        .report_mesh_slice_status(MeshSliceStatusReport {
            version: replacement_update.version.clone(),
            error_message: String::new(),
            session_token: replacement_update.session_token.clone(),
        })
        .await
        .expect("replacement ack");

    let body: Value = reqwest::Client::new()
        .get(format!("{admin_base}/mesh/slice-drift"))
        .bearer_auth(admin_token())
        .send()
        .await
        .expect("admin get")
        .error_for_status()
        .expect("200")
        .json()
        .await
        .expect("json");
    assert_eq!(body["mode"], "cp");
    assert_eq!(body["summary"]["tracked"], 1);
    assert_eq!(body["data_planes"][0]["node_id"], "mesh-dp-a");
    assert_eq!(body["data_planes"][0]["convergence"], "converged");
    assert_eq!(
        body["data_planes"][0]["acknowledged"]["version"],
        update.version
    );
}

/// Drift tracking is observability. A registry that refuses to admit this DP
/// (cardinality cap) must degrade the subscription to "untracked", never deny
/// mesh configuration delivery.
#[tokio::test(flavor = "multi_thread")]
async fn drift_registry_refusal_still_delivers_mesh_config_untracked() {
    let drift = Arc::new(MeshSliceDriftRegistry::with_max_entries(1));
    // Occupy the only slot with a connected row so it cannot be evicted.
    let occupant = drift
        .open_session("mesh-dp-occupant", "ferrum", Utc::now(), Some("v1"))
        .expect("occupant admitted");
    assert!(!occupant.is_empty());

    let (grpc_addr, drift, _grpc_handle) = start_mesh_cp_with_drift(drift).await;

    let token = mesh_jwt("mesh-dp-refused");
    let auth_header = format!("Bearer {token}");
    let channel = tonic::transport::Channel::from_shared(format!("http://{grpc_addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client =
        MeshConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert(
                "authorization",
                tonic::metadata::MetadataValue::try_from(auth_header.as_str()).unwrap(),
            );
            Ok(req)
        });

    let subscribe = MeshSubscribeRequest {
        node_id: "mesh-dp-refused".to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".to_string(),
        workload_spiffe_id: String::new(),
        labels: HashMap::new(),
        waypoint_name: String::new(),
        ambient_udp_source_scoping: false,
        remote_discovery: false,
        node_waypoint_capture_scoping: false,
    };
    let mut stream = client
        .mesh_subscribe(tonic::Request::new(subscribe))
        .await
        .expect("a full drift registry must not refuse mesh config delivery")
        .into_inner();
    let update = stream.message().await.unwrap().unwrap();
    assert!(!update.heartbeat);
    assert!(
        !update.mesh_slice_json.is_empty(),
        "the refused DP still receives its mesh slice"
    );
    assert!(
        update.session_token.is_empty(),
        "an untracked subscription must not carry a drift session token"
    );

    let snapshot = drift.snapshot();
    assert_eq!(snapshot.summary.tracked, 1);
    assert_eq!(snapshot.data_planes[0].node_id, "mesh-dp-occupant");
}

#[tokio::test(flavor = "multi_thread")]
async fn slice_drift_admin_404_outside_cp_mode() {
    let drift = Arc::new(MeshSliceDriftRegistry::new());
    let mut state = cp_admin_state(drift);
    state.mode = "mesh".to_string();
    state.mesh_registry = None;
    let (admin_base, _shutdown) = start_test_admin(state).await;
    let resp = reqwest::Client::new()
        .get(format!("{admin_base}/mesh/slice-drift"))
        .bearer_auth(admin_token())
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}
