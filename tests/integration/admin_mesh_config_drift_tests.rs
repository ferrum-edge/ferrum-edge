//! Integration coverage for `GET /mesh/config-drift` (MESH-T6-C).
//!
//! Exercises the end-to-end admin surface: AdminState is built with a
//! `MeshRuntimeState`, slices are installed and marked accepted, and the
//! handler must reflect resource counts, fingerprints, age, and overlay
//! summary. The pure response-builder logic is covered by inline unit
//! tests in `src/admin/mesh_config_drift.rs`; this leg validates JWT
//! gating, the not-in-mesh-mode case, and the slice → admin response
//! contract.

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
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshPolicy, MeshRuntimeOverlay, PolicyScope, RuntimeValue,
};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::proxy::ProxyState;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::HashMap;
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
            jwt_secret: "test-secret-key-for-mesh-config-drift-32".to_string(),
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

fn build_admin_state(jwt: JwtManager, mesh_runtime_state: Option<MeshRuntimeState>) -> AdminState {
    let mesh = MeshConfig::default();
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    // Mirror the runtime-overlay test setup: a populated `mesh_config_protocol`
    // and `dp_cp_grpc_urls` so the response surfaces realistic values for the
    // `source_protocol` / `source_cp_url` fields.
    let env_config = EnvConfig {
        namespace: "alpha".to_string(),
        mesh_config_protocol: "native".to_string(),
        dp_cp_grpc_urls: vec!["grpcs://cp-primary.mesh.svc:50051".to_string()],
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

fn populated_slice(namespace: &str, version: &str) -> MeshSlice {
    let mut overlay_fields = HashMap::new();
    overlay_fields.insert(
        "ferrum.log.level".to_string(),
        RuntimeValue::String("debug".to_string()),
    );
    MeshSlice {
        namespace: namespace.to_string(),
        version: version.to_string(),
        mesh_policies: vec![
            MeshPolicy {
                name: "deny-all".to_string(),
                namespace: namespace.to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![],
            },
            MeshPolicy {
                name: "allow-frontend".to_string(),
                namespace: namespace.to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![],
            },
        ],
        runtime_overlay: MeshRuntimeOverlay {
            fields: overlay_fields,
        },
        ..MeshSlice::default()
    }
}

fn install_accepted_slice(runtime: &MeshRuntimeState, slice: MeshSlice) {
    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    runtime.install_slice(slice.clone());
    runtime.record_applied_slice(&slice);
}

#[tokio::test]
async fn config_drift_endpoint_requires_jwt() {
    let tc = TestConfig::default();
    let state = build_admin_state(create_test_jwt_manager(&tc), Some(MeshRuntimeState::new()));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/config-drift"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn config_drift_endpoint_returns_404_outside_mesh_mode() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    // No mesh_runtime_state wired in — mirrors `/mesh/runtime-overlay`'s
    // "wrong-mode" branch so operator tooling can tell mesh-mode-without-
    // accepted-slice (200, last_received_at: null) from not-in-mesh-mode (404).
    let state = build_admin_state(create_test_jwt_manager(&tc), None);
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/config-drift"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn config_drift_endpoint_returns_200_with_nulls_before_first_slice() {
    // Mesh runtime wired but no slice accepted yet — the DP is in mesh
    // mode but the CP hasn't converged. The shape must remain stable so
    // dashboards can poll `/mesh/config-drift` continuously across boot.
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let state = build_admin_state(create_test_jwt_manager(&tc), Some(MeshRuntimeState::new()));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/config-drift"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();

    // No slice → `last_received_at`, `age_seconds`, `version`, `namespace`,
    // and `fingerprint` are elided by `skip_serializing_if`. Counts default
    // to all zeros, the protocol/CP source surface still populates from
    // env.
    assert!(body["slice"].get("last_received_at").is_none());
    assert!(body["slice"].get("age_seconds").is_none());
    assert!(body["slice"].get("version").is_none());
    assert!(body["slice"].get("namespace").is_none());
    assert!(body["slice"].get("fingerprint").is_none());
    assert_eq!(body["slice"]["resources"]["mesh_policies"], 0);
    assert_eq!(body["slice"]["resources"]["services"], 0);
    assert_eq!(body["slice"]["source_protocol"], "native");
    assert_eq!(
        body["slice"]["source_cp_url"],
        "grpcs://cp-primary.mesh.svc:50051"
    );
    // No slice means no overlay surface either — even with the default
    // `include_overlay=true` the block is absent.
    assert!(
        body.get("runtime_overlay").is_none(),
        "runtime_overlay block must be absent when no slice has been accepted"
    );
}

#[tokio::test]
async fn config_drift_endpoint_reflects_accepted_slice() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let runtime = MeshRuntimeState::new();
    install_accepted_slice(&runtime, populated_slice("alpha", "v-drift-1"));
    // Sleep so `age_seconds > 0` is observable on fast hardware — the
    // assertion is `> 0` rather than equality because the response builder
    // reads `chrono::Utc::now()` inside the handler.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let state = build_admin_state(create_test_jwt_manager(&tc), Some(runtime));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let body: Value = reqwest::Client::new()
        .get(format!("{base_url}/mesh/config-drift"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(body["slice"]["namespace"], "alpha");
    assert_eq!(body["slice"]["version"], "v-drift-1");
    assert_eq!(body["slice"]["resources"]["mesh_policies"], 2);
    let fingerprint = body["slice"]["fingerprint"]
        .as_str()
        .expect("fingerprint is a string");
    assert!(
        fingerprint.starts_with("sha256-"),
        "fingerprint must use sha256- prefix: got {fingerprint}"
    );
    assert_eq!(fingerprint.len(), "sha256-".len() + 64);
    let age = body["slice"]["age_seconds"]
        .as_u64()
        .expect("age_seconds is a u64");
    assert!(
        age >= 1,
        "age_seconds should be at least 1 after a 1.1s sleep, got {age}"
    );

    // Overlay block is present by default and lists the single key the
    // test slice installs.
    let overlay = body
        .get("runtime_overlay")
        .expect("runtime_overlay default-on");
    assert_eq!(overlay["key_count"], 1);
    assert_eq!(overlay["keys"][0], "ferrum.log.level");
    assert!(
        overlay["fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256-"))
    );
}

#[tokio::test]
async fn config_drift_endpoint_omits_overlay_block_when_disabled() {
    // `?include_overlay=false` opts the operator out of the overlay
    // surface — useful for high-frequency drift polling that only needs
    // the slice fingerprint.
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let runtime = MeshRuntimeState::new();
    install_accepted_slice(&runtime, populated_slice("alpha", "v-drift-2"));

    let state = build_admin_state(create_test_jwt_manager(&tc), Some(runtime));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let body: Value = reqwest::Client::new()
        .get(format!(
            "{base_url}/mesh/config-drift?include_overlay=false"
        ))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(body["slice"]["version"], "v-drift-2");
    assert!(
        body.get("runtime_overlay").is_none(),
        "include_overlay=false must omit the runtime_overlay block"
    );
}

#[tokio::test]
async fn config_drift_endpoint_fingerprint_changes_on_resource_drift() {
    // Two slices with the same version string but different mesh policies
    // must produce different fingerprints — operators rely on this to spot
    // a CP that re-stamps version strings on unchanged content vs a real
    // resource change.
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);

    let runtime_a = MeshRuntimeState::new();
    install_accepted_slice(&runtime_a, populated_slice("alpha", "v"));
    let state_a = build_admin_state(create_test_jwt_manager(&tc), Some(runtime_a));
    let (url_a, _shutdown_a) = start_test_admin(state_a).await;

    let runtime_b = MeshRuntimeState::new();
    let mut slice_b = populated_slice("alpha", "v");
    slice_b.mesh_policies.pop(); // one policy short
    install_accepted_slice(&runtime_b, slice_b);
    let state_b = build_admin_state(create_test_jwt_manager(&tc), Some(runtime_b));
    let (url_b, _shutdown_b) = start_test_admin(state_b).await;

    let fp_a = reqwest::Client::new()
        .get(format!("{url_a}/mesh/config-drift"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["slice"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();

    let fp_b = reqwest::Client::new()
        .get(format!("{url_b}/mesh/config-drift"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["slice"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();

    assert_ne!(
        fp_a, fp_b,
        "fingerprints must diverge when slice content diverges (version held constant)"
    );
}

#[tokio::test]
async fn config_drift_endpoint_fingerprint_ignores_version_restamp() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);

    let runtime_a = MeshRuntimeState::new();
    install_accepted_slice(&runtime_a, populated_slice("alpha", "v1"));
    let state_a = build_admin_state(create_test_jwt_manager(&tc), Some(runtime_a));
    let (url_a, _shutdown_a) = start_test_admin(state_a).await;

    let runtime_b = MeshRuntimeState::new();
    install_accepted_slice(&runtime_b, populated_slice("alpha", "v2"));
    let state_b = build_admin_state(create_test_jwt_manager(&tc), Some(runtime_b));
    let (url_b, _shutdown_b) = start_test_admin(state_b).await;

    let fp_a = reqwest::Client::new()
        .get(format!("{url_a}/mesh/config-drift"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["slice"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();

    let fp_b = reqwest::Client::new()
        .get(format!("{url_b}/mesh/config-drift"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["slice"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();

    assert_eq!(fp_a, fp_b);
}
