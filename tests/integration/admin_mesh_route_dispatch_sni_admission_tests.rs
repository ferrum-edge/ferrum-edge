//! Admin plugin-write admission for `mesh_route_dispatch` route overrides that
//! land on plain-HTTPS backend-TLS-SNI destinations.
//!
//! A candidate write must evaluate SNI / direct-H2 conflicts against the exact
//! post-write plugin-config view (DB-loaded, candidate replaced/added). Passing
//! an empty plugin list would miss an already-effective associated
//! request-body-buffering plugin and admit a route that 502s at runtime.

use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
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
            jwt_secret: "test-secret-key-for-mrd-sni-admission".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
        }
    }
}

fn make_jwt_manager(config: &TestConfig) -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        audience: None,
        max_ttl_seconds: config.max_ttl,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn make_token(config: &TestConfig) -> String {
    let now = chrono::Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": "test-user",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .unwrap()
}

async fn build_admin_state(tc: &TestConfig) -> (AdminState, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = tmp.path().join("mrd_sni_admission.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("DB connect must succeed");

    // Intentionally leave `cached_config` empty: plugin-write SNI admission must
    // load plugin configs from the DB rather than trusting a GatewayConfig cache
    // (or silently treating a missing cache as an empty plugin list).
    let state = AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: make_jwt_manager(tc),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: None,
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
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
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
    };
    (state, tmp)
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual = listener.local_addr().unwrap();
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
        if tokio::net::TcpStream::connect(actual).await.is_ok() {
            return (format!("http://{}", actual), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin server at {} never became ready", actual);
}

async fn admin_post(base_url: &str, path: &str, token: &str, body: &Value) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}{}", base_url, path))
        .header("authorization", format!("Bearer {}", token))
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(json!({}));
    (status, body)
}

fn err_string(body: &Value) -> String {
    body.get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn plain_upstream(id: &str) -> Value {
    json!({
        "id": id,
        "name": id,
        "targets": [{"host": "127.0.0.1", "port": 8080, "weight": 100}],
        "algorithm": "round_robin",
    })
}

fn sni_upstream(id: &str) -> Value {
    json!({
        "id": id,
        "name": id,
        "targets": [{"host": "backend.mesh.internal", "port": 443, "weight": 100}],
        "algorithm": "round_robin",
        "backend_tls_sni": "backend.mesh.internal",
    })
}

fn https_proxy_with_plugins(id: &str, upstream_id: &str, plugin_ids: &[&str]) -> Value {
    json!({
        "id": id,
        "listen_path": "/api",
        "backend_scheme": "https",
        "backend_host": "127.0.0.1",
        "backend_port": 8443,
        "strip_listen_path": true,
        "upstream_id": upstream_id,
        "plugins": plugin_ids
            .iter()
            .map(|plugin_id| json!({ "plugin_config_id": plugin_id }))
            .collect::<Vec<_>>(),
    })
}

fn global_mesh_route_dispatch(id: &str, destination_upstream: &str) -> Value {
    json!({
        "id": id,
        "plugin_name": "mesh_route_dispatch",
        "scope": "global",
        "enabled": true,
        "config": {
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": destination_upstream},
            }],
        },
    })
}

async fn seed_plain_and_sni_upstreams(base_url: &str, token: &str) {
    let (status, body) =
        admin_post(base_url, "/upstreams", token, &plain_upstream("plain-up")).await;
    assert_eq!(status, 201, "plain upstream seed failed: {body:?}");
    let (status, body) = admin_post(base_url, "/upstreams", token, &sni_upstream("sni-up")).await;
    assert_eq!(status, 201, "SNI upstream seed failed: {body:?}");
}

#[tokio::test]
async fn mesh_route_dispatch_plugin_write_rejects_sni_override_with_associated_buffering_plugin() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_and_sni_upstreams(&base_url, &token).await;

    // Proxy associates an effective request-body-buffering plugin. The
    // mesh_route_dispatch write below must see that association via the
    // DB-backed candidate plugin view (not an empty list / stale cache).
    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &["grpc-web-1"])
        ],
        "plugin_configs": [{
            "id": "grpc-web-1",
            "plugin_name": "grpc_web",
            "scope": "proxy",
            "proxy_id": "p-sni",
            "enabled": true,
            "config": {},
        }],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 201,
        "proxy + buffering plugin seed failed: {body:?}"
    );

    let (status, body) = admin_post(
        &base_url,
        "/plugins/config",
        &token,
        &global_mesh_route_dispatch("mrd-sni", "sni-up"),
    )
    .await;
    assert_eq!(
        status, 400,
        "SNI route override with associated buffering plugin must reject: {body:?}"
    );
    let err = err_string(&body);
    assert!(
        err.contains("request-body-buffering")
            && err.contains("backend TLS SNI")
            && err.contains("grpc-web-1")
            && err.contains("attaches"),
        "rejection must name the associated buffering plugin; got: {err}"
    );
}

#[tokio::test]
async fn mesh_route_dispatch_plugin_write_admits_sni_override_when_local_non_buffering_shadows_global()
 {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_and_sni_upstreams(&base_url, &token).await;

    // Global compression would force request-body buffering, but an enabled
    // local same-named instance that does not buffer shadows it (PluginCache
    // merge semantics). Admission must not false-reject the SNI override.
    let (status, body) = admin_post(
        &base_url,
        "/plugins/config",
        &token,
        &json!({
            "id": "global-compression",
            "plugin_name": "compression",
            "scope": "global",
            "enabled": true,
            "config": {
                "decompress_request": true,
                "max_decompressed_request_size": 1024,
            },
        }),
    )
    .await;
    assert_eq!(
        status, 201,
        "global buffering compression seed failed: {body:?}"
    );

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &["local-compression"])
        ],
        "plugin_configs": [{
            "id": "local-compression",
            "plugin_name": "compression",
            "scope": "proxy",
            "proxy_id": "p-sni",
            "enabled": true,
            "config": {},
        }],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 201,
        "proxy + local non-buffering compression seed failed: {body:?}"
    );

    let (status, body) = admin_post(
        &base_url,
        "/plugins/config",
        &token,
        &global_mesh_route_dispatch("mrd-sni", "sni-up"),
    )
    .await;
    assert_eq!(
        status, 201,
        "local non-buffering shadow must not false-reject SNI route override: {body:?}"
    );
}

#[tokio::test]
async fn batch_import_rejects_sni_route_override_with_associated_buffering_plugin() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    // Single batch creates the whole conflicting graph: plain default upstream,
    // SNI override destination, buffering association, and global route override.
    let batch = json!({
        "upstreams": [
            plain_upstream("plain-up"),
            sni_upstream("sni-up"),
        ],
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &["grpc-web-1"])
        ],
        "plugin_configs": [
            {
                "id": "grpc-web-1",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "p-sni",
                "enabled": true,
                "config": {},
            },
            global_mesh_route_dispatch("mrd-sni", "sni-up"),
        ],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 400,
        "batch must fail closed on SNI route override + buffering: {body:?}"
    );
    let errors = body
        .get("validation_errors")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let joined = errors
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    let err = if joined.is_empty() {
        err_string(&body)
    } else {
        joined
    };
    assert!(
        err.contains("request-body-buffering")
            && err.contains("backend TLS SNI")
            && err.contains("grpc-web-1"),
        "batch rejection must name the buffering plugin; got: {err}"
    );
}

#[tokio::test]
async fn upstream_reverse_write_rejects_sni_when_reached_only_via_route_override() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, body) =
        admin_post(&base_url, "/upstreams", &token, &plain_upstream("plain-up")).await;
    assert_eq!(status, 201, "plain default upstream seed failed: {body:?}");
    let (status, body) =
        admin_post(&base_url, "/upstreams", &token, &plain_upstream("override-up")).await;
    assert_eq!(status, 201, "plain override upstream seed failed: {body:?}");

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &["grpc-web-1"])
        ],
        "plugin_configs": [{
            "id": "grpc-web-1",
            "plugin_name": "grpc_web",
            "scope": "proxy",
            "proxy_id": "p-sni",
            "enabled": true,
            "config": {},
        }],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(status, 201, "proxy + buffering seed failed: {body:?}");

    let (status, body) = admin_post(
        &base_url,
        "/plugins/config",
        &token,
        &global_mesh_route_dispatch("mrd-override", "override-up"),
    )
    .await;
    assert_eq!(
        status, 201,
        "route override onto plain upstream must admit: {body:?}"
    );

    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{}/upstreams/override-up", base_url))
        .header("authorization", format!("Bearer {}", token))
        .json(&sni_upstream("override-up"))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(json!({}));
    assert_eq!(
        status, 400,
        "Upstream reverse-write must reject SNI when only a route override reaches it: {body:?}"
    );
    let err = err_string(&body);
    assert!(
        err.contains("request-body-buffering")
            && err.contains("backend TLS SNI")
            && err.contains("grpc-web-1"),
        "upstream reverse-write rejection must name the buffering plugin; got: {err}"
    );
}
