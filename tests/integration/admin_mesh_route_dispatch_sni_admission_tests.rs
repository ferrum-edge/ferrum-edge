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
use ferrum_edge::config::types::{PluginAssociation, PluginConfig, PluginScope, Proxy};
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

async fn build_admin_state(tc: &TestConfig) -> (AdminState, DatabaseStore, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = tmp.path().join("mrd_sni_admission.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store =
        DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
            .await
            .expect("DB connect must succeed");

    // Intentionally leave `cached_config` empty: plugin-write SNI admission must
    // load plugin configs from the DB rather than trusting a GatewayConfig cache
    // (or silently treating a missing cache as an empty plugin list).
    let state = AdminState {
        db: Some(Arc::new(store.clone())),
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
    (state, store, tmp)
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

async fn admin_put(base_url: &str, path: &str, token: &str, body: &Value) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{}{}", base_url, path))
        .header("authorization", format!("Bearer {}", token))
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(json!({}));
    (status, body)
}

async fn admin_delete(base_url: &str, path: &str, token: &str) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("{}{}", base_url, path))
        .header("authorization", format!("Bearer {}", token))
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

fn batch_err_string(body: &Value) -> String {
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
    if joined.is_empty() {
        err_string(body)
    } else {
        joined
    }
}

fn assert_sni_buffering_rejection(status: u16, body: &Value, plugin_id: &str) {
    assert_eq!(
        status, 400,
        "SNI + effective buffering must reject: {body:?}"
    );
    let err = err_string(body);
    assert!(
        err.contains("request-body-buffering")
            && err.contains("backend TLS SNI")
            && err.contains(plugin_id),
        "rejection must name the buffering plugin; got: {err}"
    );
}

fn assert_api_spec_sni_buffering_rejection(status: u16, body: &Value, plugin_id: &str) {
    assert_eq!(
        status, 422,
        "API-spec SNI + effective buffering must reject: {body:?}"
    );
    let joined = body
        .get("failures")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|failure| failure.get("errors"))
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        joined.contains("request-body-buffering")
            && joined.contains("backend TLS SNI")
            && joined.contains(plugin_id),
        "API-spec rejection must name the buffering plugin; got: {joined} / {body:?}"
    );
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

fn proxy_mesh_route_dispatch(id: &str, proxy_id: &str, destination_upstream: &str) -> Value {
    json!({
        "id": id,
        "plugin_name": "mesh_route_dispatch",
        "scope": "proxy",
        "proxy_id": proxy_id,
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
    let (state, _store, _tmp) = build_admin_state(&tc).await;
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
    let (state, _store, _tmp) = build_admin_state(&tc).await;
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
    let (state, _store, _tmp) = build_admin_state(&tc).await;
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
    let err = batch_err_string(&body);
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
    let (state, _store, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, body) =
        admin_post(&base_url, "/upstreams", &token, &plain_upstream("plain-up")).await;
    assert_eq!(status, 201, "plain default upstream seed failed: {body:?}");
    let (status, body) = admin_post(
        &base_url,
        "/upstreams",
        &token,
        &plain_upstream("override-up"),
    )
    .await;
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

#[tokio::test]
async fn mesh_route_dispatch_scope_change_to_global_rejects_sni_with_buffering() {
    // Finding 1: changing an attached local mesh_route_dispatch to Global must
    // compute shadowing from the post-write candidate set. Consulting the stale
    // pre-write DB row would skip the attached proxy and admit an outage.
    let tc = TestConfig::default();
    let (state, _store, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_and_sni_upstreams(&base_url, &token).await;

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &["grpc-web-1", "mrd-local"])
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
            // Same-upstream override: no SNI conflict while local.
            proxy_mesh_route_dispatch("mrd-local", "p-sni", "plain-up"),
        ],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(status, 201, "proxy + local MRD seed failed: {body:?}");

    let (status, body) = admin_put(
        &base_url,
        "/plugins/config/mrd-local",
        &token,
        &global_mesh_route_dispatch("mrd-local", "sni-up"),
    )
    .await;
    assert_sni_buffering_rejection(status, &body, "grpc-web-1");
}

#[tokio::test]
async fn batch_disable_local_mrd_rejects_unshadowed_global_sni_override() {
    // Finding 2: disabling an attached local mesh_route_dispatch unshadows a
    // global SNI override; batch must screen even when batch_introduces_mrd
    // would be false.
    let tc = TestConfig::default();
    let (state, _store, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_and_sni_upstreams(&base_url, &token).await;

    let (status, body) = admin_post(
        &base_url,
        "/plugins/config",
        &token,
        &global_mesh_route_dispatch("mrd-global", "sni-up"),
    )
    .await;
    assert_eq!(
        status, 201,
        "global SNI override with no proxies yet must admit: {body:?}"
    );

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &["grpc-web-1", "mrd-local"])
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
            // Local same-name shadow keeps the global SNI override inert.
            proxy_mesh_route_dispatch("mrd-local", "p-sni", "plain-up"),
        ],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 201,
        "local MRD shadow must admit under buffering: {body:?}"
    );

    let disable = json!({
        "plugin_configs": [{
            "id": "mrd-local",
            "plugin_name": "mesh_route_dispatch",
            "scope": "proxy",
            "proxy_id": "p-sni",
            "enabled": false,
            "config": {
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "plain-up"},
                }],
            },
        }],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &disable).await;
    assert_eq!(
        status, 400,
        "batch disable that unshadows global SNI+buffering must reject: {body:?}"
    );
    let err = batch_err_string(&body);
    assert!(
        err.contains("request-body-buffering")
            && err.contains("backend TLS SNI")
            && err.contains("grpc-web-1"),
        "batch unshadow rejection must name buffering plugin; got: {err}"
    );
}

#[tokio::test]
async fn batch_buffering_mutation_rejects_existing_sni_route_override() {
    // Finding 2: updating an effective buffering plugin can make an existing
    // SNI route override undispatchable even when no MRD is in the batch.
    let tc = TestConfig::default();
    let (state, _store, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_and_sni_upstreams(&base_url, &token).await;

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &["local-compression"])
        ],
        "plugin_configs": [
            {
                "id": "local-compression",
                "plugin_name": "compression",
                "scope": "proxy",
                "proxy_id": "p-sni",
                "enabled": true,
                // Non-buffering initially.
                "config": {},
            },
            global_mesh_route_dispatch("mrd-sni", "sni-up"),
        ],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 201,
        "SNI override with non-buffering compression must admit: {body:?}"
    );

    let enable_buffering = json!({
        "plugin_configs": [{
            "id": "local-compression",
            "plugin_name": "compression",
            "scope": "proxy",
            "proxy_id": "p-sni",
            "enabled": true,
            "config": {
                "decompress_request": true,
                "max_decompressed_request_size": 1024,
            },
        }],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &enable_buffering).await;
    assert_eq!(
        status, 400,
        "batch buffering mutation against SNI route override must reject: {body:?}"
    );
    let err = batch_err_string(&body);
    assert!(
        err.contains("request-body-buffering")
            && err.contains("backend TLS SNI")
            && err.contains("local-compression"),
        "batch buffering mutation rejection must name plugin; got: {err}"
    );
}

#[tokio::test]
async fn plugin_delete_local_mrd_rejects_unshadowed_global_sni_override() {
    // Finding 3: PluginConfig DELETE of an attached local mesh_route_dispatch
    // must fail closed when it would unshadow a conflicting global override.
    let tc = TestConfig::default();
    let (state, _store, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_and_sni_upstreams(&base_url, &token).await;

    let (status, body) = admin_post(
        &base_url,
        "/plugins/config",
        &token,
        &global_mesh_route_dispatch("mrd-global", "sni-up"),
    )
    .await;
    assert_eq!(status, 201, "global SNI override seed failed: {body:?}");

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &["grpc-web-1", "mrd-local"])
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
            proxy_mesh_route_dispatch("mrd-local", "p-sni", "plain-up"),
        ],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(status, 201, "local shadow seed failed: {body:?}");

    let (status, body) = admin_delete(&base_url, "/plugins/config/mrd-local", &token).await;
    assert_sni_buffering_rejection(status, &body, "grpc-web-1");
}

#[tokio::test]
async fn non_mrd_buffering_plugin_write_rejects_default_upstream_sni() {
    // Finding 4: a non-MRD buffering plugin write must screen the proxy's
    // default upstream SNI against the post-write plugin chain.
    let tc = TestConfig::default();
    let (state, _store, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, body) = admin_post(&base_url, "/upstreams", &token, &sni_upstream("sni-up")).await;
    assert_eq!(status, 201, "SNI upstream seed failed: {body:?}");

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "sni-up", &[])
        ],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 201,
        "SNI default-upstream proxy seed failed: {body:?}"
    );

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
    assert_sni_buffering_rejection(status, &body, "global-compression");
}

#[tokio::test]
async fn non_mrd_buffering_plugin_write_rejects_existing_sni_route_override() {
    // Finding 4: a non-MRD buffering plugin update must screen existing
    // local/global route overrides against the post-write plugin chain.
    let tc = TestConfig::default();
    let (state, _store, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_and_sni_upstreams(&base_url, &token).await;

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &["mrd-local", "local-compression"])
        ],
        "plugin_configs": [
            proxy_mesh_route_dispatch("mrd-local", "p-sni", "sni-up"),
            {
                "id": "local-compression",
                "plugin_name": "compression",
                "scope": "proxy",
                "proxy_id": "p-sni",
                "enabled": true,
                "config": {},
            },
        ],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 201,
        "local SNI override with non-buffering compression must admit: {body:?}"
    );

    let (status, body) = admin_put(
        &base_url,
        "/plugins/config/local-compression",
        &token,
        &json!({
            "id": "local-compression",
            "plugin_name": "compression",
            "scope": "proxy",
            "proxy_id": "p-sni",
            "enabled": true,
            "config": {
                "decompress_request": true,
                "max_decompressed_request_size": 1024,
            },
        }),
    )
    .await;
    assert_sni_buffering_rejection(status, &body, "local-compression");
}

#[tokio::test]
async fn global_buffering_plugin_write_rejects_existing_sni_route_override() {
    // Finding 4: global non-MRD buffering must not early-return; screen
    // existing route overrides under the post-write chain.
    let tc = TestConfig::default();
    let (state, _store, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_and_sni_upstreams(&base_url, &token).await;

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &[])
        ],
        "plugin_configs": [
            global_mesh_route_dispatch("mrd-sni", "sni-up"),
        ],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 201,
        "global SNI override without buffering must admit: {body:?}"
    );

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
    assert_sni_buffering_rejection(status, &body, "global-compression");
}

#[tokio::test]
async fn invalid_local_buffering_config_does_not_shadow_global_candidate() {
    // A persisted local that fails construction remains absent from
    // PluginCache, so it cannot shadow a same-named global. Admission must not
    // skip this proxy merely because the broken row is enabled and attached.
    let tc = TestConfig::default();
    let (state, _store, _tmp) = build_admin_state(&tc).await;
    let db = state.db.as_ref().expect("test database").clone();
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_and_sni_upstreams(&base_url, &token).await;
    let (status, body) = admin_post(
        &base_url,
        "/plugins/config",
        &token,
        &global_mesh_route_dispatch("mrd-sni", "sni-up"),
    )
    .await;
    assert_eq!(status, 201, "global SNI override seed failed: {body:?}");

    // Respect plugin_configs.proxy_id FK: create the proxy first without the
    // invalid association, persist the broken local, then attach it.
    let proxy: Proxy = serde_json::from_value(https_proxy_with_plugins(
        "p-sni",
        "plain-up",
        &[],
    ))
    .expect("deserialize persisted proxy fixture");
    db.create_proxy(&proxy)
        .await
        .expect("persist proxy before invalid local compression");

    let now = chrono::Utc::now();
    db.create_plugin_config(&PluginConfig {
        id: "invalid-local-compression".to_string(),
        plugin_name: "compression".to_string(),
        namespace: "ferrum".to_string(),
        config: json!({"unknown_field": true}),
        scope: PluginScope::Proxy,
        proxy_id: Some("p-sni".to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    })
    .await
    .expect("persist invalid local compression fixture");
    let mut attached = db
        .get_proxy("ferrum", "p-sni")
        .await
        .expect("load proxy")
        .expect("proxy must exist");
    attached.plugins.push(PluginAssociation {
        plugin_config_id: "invalid-local-compression".to_string(),
    });
    assert!(
        db.update_proxy(&attached)
            .await
            .expect("attach invalid local compression"),
        "proxy must still exist after attach"
    );

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
    assert_sni_buffering_rejection(status, &body, "global-compression");
}

#[tokio::test]
async fn invalid_local_route_dispatch_does_not_shadow_valid_global_route() {
    // MeshRouteDispatch::new rejects an empty rule set. Such a persisted local
    // is not in the runtime chain and must not suppress the valid global route
    // override during SNI admission.
    let tc = TestConfig::default();
    let (state, _store, _tmp) = build_admin_state(&tc).await;
    let db = state.db.as_ref().expect("test database").clone();
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_and_sni_upstreams(&base_url, &token).await;
    let (status, body) = admin_post(
        &base_url,
        "/plugins/config",
        &token,
        &global_mesh_route_dispatch("mrd-sni", "sni-up"),
    )
    .await;
    assert_eq!(status, 201, "global SNI override seed failed: {body:?}");

    // Respect plugin_configs.proxy_id FK: create the proxy first without the
    // invalid association, persist the broken local, then attach it.
    let proxy: Proxy = serde_json::from_value(https_proxy_with_plugins(
        "p-sni",
        "plain-up",
        &[],
    ))
    .expect("deserialize persisted proxy fixture");
    db.create_proxy(&proxy)
        .await
        .expect("persist proxy before invalid local route dispatcher");

    let now = chrono::Utc::now();
    db.create_plugin_config(&PluginConfig {
        id: "invalid-local-mrd".to_string(),
        plugin_name: "mesh_route_dispatch".to_string(),
        namespace: "ferrum".to_string(),
        config: json!({}),
        scope: PluginScope::Proxy,
        proxy_id: Some("p-sni".to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    })
    .await
    .expect("persist invalid local route-dispatch fixture");
    let mut attached = db
        .get_proxy("ferrum", "p-sni")
        .await
        .expect("load proxy")
        .expect("proxy must exist");
    attached.plugins.push(PluginAssociation {
        plugin_config_id: "invalid-local-mrd".to_string(),
    });
    assert!(
        db.update_proxy(&attached)
            .await
            .expect("attach invalid local route dispatcher"),
        "proxy must still exist after attach"
    );

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
    assert_sni_buffering_rejection(status, &body, "global-compression");
}

#[tokio::test]
async fn api_spec_import_rejects_sni_route_override_with_buffering_plugin() {
    // Finding 5: API-spec import must fail closed on route-override SNI +
    // buffering (no redundant fixture bulk — one POST).
    let tc = TestConfig::default();
    let (state, _store, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, body) = admin_post(&base_url, "/upstreams", &token, &sni_upstream("sni-up")).await;
    assert_eq!(
        status, 201,
        "hand-managed SNI upstream seed failed: {body:?}"
    );

    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "SNI route override admission", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": "p-sni",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": 8443,
            "strip_listen_path": true,
            "upstream_id": "plain-up",
            "plugins": [
                {"plugin_config_id": "grpc-web-1"},
                {"plugin_config_id": "mrd-sni"},
            ],
        },
        "x-ferrum-upstream": {
            "id": "plain-up",
            "name": "plain-up",
            "targets": [{"host": "127.0.0.1", "port": 8080, "weight": 100}],
            "algorithm": "round_robin",
        },
        "x-ferrum-plugins": [
            {
                "id": "grpc-web-1",
                "plugin_name": "grpc_web",
                "config": {},
            },
            {
                "id": "mrd-sni",
                "plugin_name": "mesh_route_dispatch",
                "config": {
                    "rules": [{
                        "match": {"methods": ["GET"]},
                        "destination": {"upstream_id": "sni-up"},
                    }],
                },
            },
        ],
    });
    let (status, body) = admin_post(&base_url, "/api-specs", &token, &spec).await;
    assert_api_spec_sni_buffering_rejection(status, &body, "grpc-web-1");
}

#[tokio::test]
async fn api_spec_put_screens_the_exact_post_replacement_plugin_set() {
    // Simulate a legacy persisted conflict that predates this admission gate:
    // the spec owns an attached buffering plugin plus an MRD route to an SNI
    // upstream. A PUT that omits the old owned buffering plugin must evaluate
    // the actual replacement state and repair the object, while a later PUT
    // that reintroduces the same conflict must still fail closed.
    let tc = TestConfig::default();
    let (state, store, _tmp) = build_admin_state(&tc).await;
    let db = state.db.as_ref().expect("test database").clone();
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, body) = admin_post(&base_url, "/upstreams", &token, &sni_upstream("sni-up")).await;
    assert_eq!(
        status, 201,
        "hand-managed SNI upstream seed failed: {body:?}"
    );

    let seed = json!({
        "openapi": "3.1.0",
        "info": {"title": "Exact SNI replacement", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": "p-sni",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": 8443,
            "strip_listen_path": true,
            "upstream_id": "plain-up",
            "plugins": [{"plugin_config_id": "mrd-sni"}],
        },
        "x-ferrum-upstream": {
            "id": "plain-up",
            "name": "plain-up",
            "targets": [{"host": "127.0.0.1", "port": 8080, "weight": 100}],
            "algorithm": "round_robin",
        },
        "x-ferrum-plugins": [{
            "id": "mrd-sni",
            "plugin_name": "mesh_route_dispatch",
            "config": {
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "sni-up"},
                }],
            },
        }],
    });
    let (status, body) = admin_post(&base_url, "/api-specs", &token, &seed).await;
    assert_eq!(status, 201, "non-buffering API spec seed failed: {body:?}");
    let spec_id = body["id"]
        .as_str()
        .expect("API-spec response id")
        .to_string();

    // Direct admin create_plugin_config never stamps api_spec_id (forged
    // ownership is forbidden). Tag the legacy conflict as spec-owned via SQL
    // so replace deletion can see it — matching other API-spec drift fixtures.
    let now = chrono::Utc::now();
    db.create_plugin_config(&PluginConfig {
        id: "grpc-web-1".to_string(),
        plugin_name: "grpc_web".to_string(),
        namespace: "ferrum".to_string(),
        config: json!({}),
        scope: PluginScope::Proxy,
        proxy_id: Some("p-sni".to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    })
    .await
    .expect("persist legacy buffering fixture row");
    sqlx::query("UPDATE plugin_configs SET api_spec_id = ? WHERE namespace = ? AND id = ?")
        .bind(&spec_id)
        .bind("ferrum")
        .bind("grpc-web-1")
        .execute(&store.pool())
        .await
        .expect("tag legacy buffering fixture as spec-owned");
    let owned = db
        .list_spec_owned_plugin_configs("ferrum", &spec_id)
        .await
        .expect("list spec-owned plugins");
    assert!(
        owned.iter().any(|plugin| plugin.id == "grpc-web-1"),
        "test precondition: injected buffering plugin must be spec-owned"
    );
    let mut persisted_proxy = db
        .get_proxy("ferrum", "p-sni")
        .await
        .expect("load API-spec proxy")
        .expect("API-spec proxy must exist");
    persisted_proxy.plugins.push(PluginAssociation {
        plugin_config_id: "grpc-web-1".to_string(),
    });
    assert!(
        db.update_proxy(&persisted_proxy)
            .await
            .expect("attach legacy buffering fixture"),
        "API-spec proxy must still exist"
    );

    // Materially change the extracted resource graph so this PUT cannot take
    // the matching-resource-hash metadata-only no-op; SNI + MRD stay intact.
    let mut replacement = seed.clone();
    replacement["x-ferrum-proxy"]["listen_path"] = json!("/api-repaired");
    let path = format!("/api-specs/{spec_id}");
    let (status, body) = admin_put(&base_url, &path, &token, &replacement).await;
    assert_eq!(
        status, 200,
        "PUT removing the old owned conflict must use the post-replacement state: {body:?}"
    );
    assert!(
        db.get_plugin_config("ferrum", "grpc-web-1")
            .await
            .expect("load removed plugin")
            .is_none(),
        "omitted spec-owned buffering plugin must be deleted"
    );
    let repaired_proxy = db
        .get_proxy("ferrum", "p-sni")
        .await
        .expect("load repaired proxy")
        .expect("repaired proxy must exist");
    assert_eq!(
        repaired_proxy.listen_path, "/api-repaired",
        "replacement must rewrite the proxy listen_path"
    );
    assert!(
        repaired_proxy
            .plugins
            .iter()
            .all(|association| association.plugin_config_id != "grpc-web-1"),
        "omitted spec-owned plugin association must be deleted"
    );

    let mut conflicting = replacement.clone();
    conflicting["x-ferrum-proxy"]["plugins"] = json!([
        {"plugin_config_id": "grpc-web-1"},
        {"plugin_config_id": "mrd-sni"},
    ]);
    conflicting["x-ferrum-plugins"]
        .as_array_mut()
        .expect("plugin array")
        .insert(
            0,
            json!({
                "id": "grpc-web-1",
                "plugin_name": "grpc_web",
                "config": {},
            }),
        );
    let (status, body) = admin_put(&base_url, &path, &token, &conflicting).await;
    assert_api_spec_sni_buffering_rejection(status, &body, "grpc-web-1");
}

#[tokio::test]
async fn proxy_reverse_write_rejects_buffering_attach_with_sni_route_override() {
    // Finding 5: Proxy reverse-write must reject attaching a buffering plugin
    // when an applicable route override already lands on SNI.
    let tc = TestConfig::default();
    let (state, _store, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_and_sni_upstreams(&base_url, &token).await;

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &[])
        ],
        "plugin_configs": [
            global_mesh_route_dispatch("mrd-sni", "sni-up"),
            {
                "id": "grpc-web-1",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "p-sni",
                "enabled": true,
                "config": {},
            },
        ],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 201,
        "SNI override with staged (unattached) buffering must admit: {body:?}"
    );

    let (status, body) = admin_put(
        &base_url,
        "/proxies/p-sni",
        &token,
        &https_proxy_with_plugins("p-sni", "plain-up", &["grpc-web-1"]),
    )
    .await;
    assert_sni_buffering_rejection(status, &body, "grpc-web-1");
}
