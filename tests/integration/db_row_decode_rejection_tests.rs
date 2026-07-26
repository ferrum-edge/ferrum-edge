//! SQLite poll/admin repair regression for undecodable SQL rows (issue #2997).
//!
//! A reachable database that returns an undecodable row must NOT flip
//! `db_available=false`. Last-known-good runtime config keeps serving, and
//! admin writes stay open so the offending row can be repaired in-band —
//! matching the #2158 validation-rejection contract for decode failures.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::_test_support::{
    is_poll_validation_rejection, is_row_decode_rejection, record_config_validation_rejection,
};
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_loader::{DatabaseBackend, DatabaseStore, DbPoolConfig};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, DispatchKind, Proxy, default_namespace,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tempfile::TempDir;

async fn sqlite_store() -> (Arc<DatabaseStore>, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("row_decode_rejection.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store creation must succeed");
    (Arc::new(store), temp_dir)
}

fn test_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: default_namespace(),
        name: Some(format!("proxy-{id}")),
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port: 8080,
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

fn test_consumer(id: &str) -> Consumer {
    Consumer {
        id: id.to_string(),
        namespace: default_namespace(),
        username: format!("user-{id}"),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: vec![],
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: "test-secret-key-for-admin-api".to_string(),
        issuer: "test-ferrum-edge".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn admin_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": "test-ferrum-edge",
        "sub": "test-user",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string()
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"test-secret-key-for-admin-api"),
    )
    .unwrap()
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
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
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    (format!("http://{addr}"), shutdown_tx)
}

async fn admin_post(base_url: &str, path: &str, token: &str, body: &Value) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("{base_url}{path}"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn admin_delete(base_url: &str, path: &str, token: &str) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .delete(format!("{base_url}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn admin_put(base_url: &str, path: &str, token: &str, body: &Value) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .put(format!("{base_url}{path}"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn admin_get(base_url: &str, path: &str, token: &str) -> (reqwest::StatusCode, Value) {
    let resp = reqwest::Client::new()
        .get(format!("{base_url}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.json().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

#[tokio::test(flavor = "multi_thread")]
async fn undecodable_consumer_row_keeps_admin_writable_for_in_band_repair() {
    let (store, _tmp) = sqlite_store().await;
    let ns = default_namespace();

    // Seed a valid runtime snapshot (proxy + consumer).
    store
        .create_proxy(&test_proxy("p-good", "/good"))
        .await
        .expect("create proxy");
    store
        .create_consumer(&test_consumer("c-bad"))
        .await
        .expect("create consumer");

    let good = store
        .load_full_config(&ns)
        .await
        .expect("initial full load must succeed");
    assert_eq!(good.proxies.len(), 1);
    assert_eq!(good.consumers.len(), 1);

    // Out-of-band corruption: credentials column is no longer JSON.
    sqlx::query("UPDATE consumers SET credentials = '{not json' WHERE id = ? AND namespace = ?")
        .bind("c-bad")
        .bind(&ns)
        .execute(&store.pool())
        .await
        .expect("corrupt credentials");

    // Point-load and full-load both surface a typed row-decode rejection.
    let point_err = store
        .get_consumer(&ns, "c-bad")
        .await
        .expect_err("point-load must reject undecodable credentials");
    assert!(
        is_row_decode_rejection(&point_err),
        "point-load must attach RowDecodeRejection: {point_err:#}"
    );
    assert!(
        is_poll_validation_rejection(&point_err),
        "point-load decode must classify for the poll loop: {point_err:#}"
    );

    let load_err = store
        .load_full_config(&ns)
        .await
        .expect_err("full load must reject the undecodable consumer row");
    assert!(
        is_row_decode_rejection(&load_err),
        "full load must attach RowDecodeRejection: {load_err:#}"
    );
    assert!(
        is_poll_validation_rejection(&load_err),
        "full load decode must classify for the poll loop: {load_err:#}"
    );

    // Simulate one poll tick: reachable-decode rejection keeps writes open.
    let db_available = Arc::new(AtomicBool::new(true));
    let config_rejected = Arc::new(AtomicBool::new(false));
    let db_backend: Arc<dyn DatabaseBackend> = store.clone();
    record_config_validation_rejection(
        &db_backend,
        &db_available,
        &config_rejected,
        &load_err,
        "row-decode rejection regression",
    )
    .await;
    assert!(
        db_available.load(Ordering::Relaxed),
        "reachable row-decode rejection must keep db_available=true"
    );
    assert!(
        config_rejected.load(Ordering::Relaxed),
        "row-decode rejection must raise config_rejected"
    );

    // Last-known-good config remains served from the admin cache.
    let cached = Arc::new(ArcSwap::new(Arc::new(good)));
    let state = AdminState {
        db: Some(store.clone()),
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: Some(cached),
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_available),
        config_rejected: Some(config_rejected),
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
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    };
    let (base_url, _shutdown) = start_admin(state).await;
    let token = admin_token();

    let (status, health) = admin_get(&base_url, "/health", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(health["config_rejected"], true);
    assert_eq!(health["admin_writes_enabled"], true);

    // Cached last-known-good proxy is still visible.
    let (status, body) = admin_get(&base_url, "/proxies/p-good", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "cached proxy must remain: {body}"
    );
    assert_eq!(body["id"], "p-good");

    // POST with the same id must be 409 (row still occupies the id), not 503.
    let (conflict_status, conflict_body) = admin_post(
        &base_url,
        "/consumers",
        &token,
        &json!({
            "id": "c-bad",
            "username": "user-c-bad-retry",
            "credentials": {},
            "acl_groups": [],
        }),
    )
    .await;
    assert_eq!(
        conflict_status, 409,
        "POST same id must conflict on undecodable row (got {conflict_status}): {conflict_body:?}"
    );

    // In-band repair: DELETE the undecodable consumer (must not be 503).
    let (del_status, del_body) = admin_delete(&base_url, "/consumers/c-bad", &token).await;
    assert!(
        (200..300).contains(&del_status),
        "DELETE must succeed for in-band repair (got {del_status}): {del_body:?}"
    );

    // POST must also stay non-503 while the rejection is standing.
    let (post_status, post_body) = admin_post(
        &base_url,
        "/proxies",
        &token,
        &json!({
            "listen_path": "/repair-2997",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
        }),
    )
    .await;
    assert!(
        (200..300).contains(&post_status),
        "POST must stay writable during row-decode rejection (got {post_status}): {post_body:?}"
    );

    // After repair, a full load succeeds again.
    let repaired = store
        .load_full_config(&ns)
        .await
        .expect("full load must succeed after deleting the undecodable consumer");
    assert!(
        repaired.consumers.iter().all(|c| c.id != "c-bad"),
        "corrupted consumer must be gone after DELETE"
    );
}

/// A corrupt *proxy* row is read back by the pre-delete mTLS-DNS ambiguity
/// baseline (`mtls_dns_identity_conflicts_tx` loads every proxy and plugin
/// config unconditionally, before the row is removed). That baseline read must
/// not turn the in-band DELETE repair into a 5xx — issue #2997.
#[tokio::test(flavor = "multi_thread")]
async fn undecodable_proxy_row_allows_delete_repair() {
    let (store, _tmp) = sqlite_store().await;
    let ns = default_namespace();

    store
        .create_proxy(&test_proxy("p-keep", "/keep"))
        .await
        .expect("create surviving proxy");
    store
        .create_proxy(&test_proxy("p-bad", "/bad"))
        .await
        .expect("create proxy to corrupt");
    let good = store
        .load_full_config(&ns)
        .await
        .expect("initial full load must succeed");

    // Out-of-band corruption: the hosts column is no longer JSON.
    sqlx::query("UPDATE proxies SET hosts = '{not json' WHERE id = ? AND namespace = ?")
        .bind("p-bad")
        .bind(&ns)
        .execute(&store.pool())
        .await
        .expect("corrupt hosts");

    let load_err = store
        .load_full_config(&ns)
        .await
        .expect_err("full load must reject the undecodable proxy row");
    assert!(
        is_row_decode_rejection(&load_err),
        "full load must attach RowDecodeRejection: {load_err:#}"
    );

    let db_available = Arc::new(AtomicBool::new(true));
    let config_rejected = Arc::new(AtomicBool::new(false));
    let db_backend: Arc<dyn DatabaseBackend> = store.clone();
    record_config_validation_rejection(
        &db_backend,
        &db_available,
        &config_rejected,
        &load_err,
        "row-decode proxy delete repair",
    )
    .await;
    assert!(
        db_available.load(Ordering::Relaxed),
        "reachable row-decode rejection must keep db_available=true"
    );

    let cached = Arc::new(ArcSwap::new(Arc::new(good)));
    let state = AdminState {
        db: Some(store.clone()),
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: Some(cached),
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_available),
        config_rejected: Some(config_rejected),
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
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    };
    let (base_url, _shutdown) = start_admin(state).await;
    let token = admin_token();

    let (del_status, del_body) = admin_delete(&base_url, "/proxies/p-bad", &token).await;
    assert!(
        (200..300).contains(&del_status),
        "DELETE must repair an undecodable proxy row (got {del_status}): {del_body:?}"
    );

    let repaired = store
        .load_full_config(&ns)
        .await
        .expect("full load must succeed after deleting the undecodable proxy");
    assert!(
        repaired.proxies.iter().all(|p| p.id != "p-bad"),
        "corrupted proxy must be gone after DELETE"
    );
    assert!(
        repaired.proxies.iter().any(|p| p.id == "p-keep"),
        "unrelated proxy must survive the repair delete"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn undecodable_consumer_row_allows_put_overwrite_repair() {
    let (store, _tmp) = sqlite_store().await;
    let ns = default_namespace();

    store
        .create_consumer(&test_consumer("c-put"))
        .await
        .expect("create consumer");
    let good = store
        .load_full_config(&ns)
        .await
        .expect("initial full load must succeed");

    sqlx::query("UPDATE consumers SET credentials = '{not json' WHERE id = ? AND namespace = ?")
        .bind("c-put")
        .bind(&ns)
        .execute(&store.pool())
        .await
        .expect("corrupt credentials");

    let load_err = store
        .load_full_config(&ns)
        .await
        .expect_err("full load must reject undecodable consumer");
    assert!(is_row_decode_rejection(&load_err));

    let db_available = Arc::new(AtomicBool::new(true));
    let config_rejected = Arc::new(AtomicBool::new(false));
    let db_backend: Arc<dyn DatabaseBackend> = store.clone();
    record_config_validation_rejection(
        &db_backend,
        &db_available,
        &config_rejected,
        &load_err,
        "row-decode put repair",
    )
    .await;

    let cached = Arc::new(ArcSwap::new(Arc::new(good)));
    let state = AdminState {
        db: Some(store.clone()),
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: Some(cached),
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_available),
        config_rejected: Some(config_rejected),
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
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    };
    let (base_url, _shutdown) = start_admin(state).await;
    let token = admin_token();

    // In-band repair: PUT overwrite must stay non-503 and restore decodability.
    let (put_status, put_body) = admin_put(
        &base_url,
        "/consumers/c-put",
        &token,
        &json!({
            "username": "user-c-put-repaired",
            "credentials": {},
            "acl_groups": [],
        }),
    )
    .await;
    assert!(
        (200..300).contains(&put_status),
        "PUT overwrite must repair undecodable row (got {put_status}): {put_body:?}"
    );

    let repaired = store
        .load_full_config(&ns)
        .await
        .expect("full load must succeed after PUT overwrite repair");
    let consumer = repaired
        .consumers
        .iter()
        .find(|c| c.id == "c-put")
        .expect("repaired consumer must remain");
    assert_eq!(consumer.username, "user-c-put-repaired");
}
