//! Integration coverage for GET /backup security audit (#2422).

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::audit::{self, list_local_fallback_events};
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, DispatchKind, GatewayConfig, Proxy,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tracing_subscriber::fmt::MakeWriter;

const JWT_SECRET: &str = "test-secret-key-for-backup-audit-32chars!!";
const JWT_ISSUER: &str = "test-ferrum-edge";
const JWT_CANARY: &str = "backup-jwt-canary-secret-value-32chars";
const COOKIE_CANARY: &str = "session=backup-cookie-canary-never-in-logs";
const RESOURCES_CANARY: &str = "canary-secret-token-never-in-audit-or-logs";
const PAYLOAD_FRAGMENT_CANARY: &str = "secret-user";

/// In-memory tracing sink mirroring the admin SharedAdminLogWriter pattern so
/// backup-path diagnostics can be asserted without production test helpers.
#[derive(Clone, Default)]
struct SharedBackupAuditLogWriter(Arc<Mutex<Vec<u8>>>);

impl SharedBackupAuditLogWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap_or_default()
    }
}

impl Write for SharedBackupAuditLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBackupAuditLogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture_backup_audit_logs() -> (
    SharedBackupAuditLogWriter,
    tracing::subscriber::DefaultGuard,
) {
    let writer = SharedBackupAuditLogWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    (writer, tracing::subscriber::set_default(subscriber))
}

fn assert_logs_omit_hostile_canaries(logs: &str, extra: &[&str]) {
    let mut canaries = vec![
        JWT_CANARY,
        COOKIE_CANARY,
        RESOURCES_CANARY,
        PAYLOAD_FRAGMENT_CANARY,
        "Bearer ",
        "Cookie:",
        "eyJhbGciOi",
    ];
    canaries.extend_from_slice(extra);
    for canary in canaries {
        assert!(
            !logs.contains(canary),
            "backup audit path leaked canary {canary:?} into tracing output:\n{logs}"
        );
    }
}

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn token(subject: &str, role: Option<&str>) -> String {
    let now = Utc::now();
    let mut claims = json!({
        "iss": JWT_ISSUER,
        "sub": subject,
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(role) = role {
        claims["role"] = json!(role);
    }
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

/// Mint an admin token carrying an `ns` claim so the namespace-claim gate can
/// be exercised without touching process-global environment state.
fn token_with_ns(subject: &str, ns: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": subject,
        "role": "admin",
        "ns": ns,
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

fn test_pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 2,
        min_connections: 0,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 300,
        connect_timeout_seconds: 5,
        statement_timeout_seconds: 0,
    }
}

async fn make_store(dir: &TempDir) -> DatabaseStore {
    let db_path = dir
        .path()
        .join(format!("backup-audit-{}.db", uuid::Uuid::new_v4()));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, test_pool_config())
        .await
        .expect("connect sqlite store")
}

fn base_admin_state() -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        // Mutation audit remains off by default; backup security auditing is
        // unconditional and must still admit records in this configuration.
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::common::isolated_audit_fallback_dir()),
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

fn admin_state(db: DatabaseStore) -> AdminState {
    let mut state = base_admin_state();
    state.db = Some(Arc::new(db));
    state
}

fn create_test_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("Test Proxy {id}")),
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
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

fn sample_cached_config() -> GatewayConfig {
    let mut credentials = HashMap::new();
    credentials.insert("jwt".to_string(), json!([{ "secret": JWT_CANARY }]));
    GatewayConfig {
        version: "1".to_string(),
        proxies: vec![create_test_proxy("p1", "/cached")],
        consumers: vec![Consumer {
            id: "c1".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            username: "secret-user".to_string(),
            custom_id: None,
            credentials,
            acl_groups: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

fn cached_only_state(config: GatewayConfig) -> AdminState {
    let mut state = base_admin_state();
    state.mode = "file".to_string();
    state.read_only = true;
    state.cached_config = Some(Arc::new(ArcSwap::new(Arc::new(config))));
    state
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual = listener.local_addr().unwrap();
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
        if tokio::net::TcpStream::connect(actual).await.is_ok() {
            return (format!("http://{}", actual), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {} never became ready", actual);
}

async fn get_backup(
    base: &str,
    path: &str,
    bearer: &str,
    request_id: Option<&str>,
) -> (u16, Value, Option<String>) {
    get_backup_with_cookie(base, path, bearer, request_id, None).await
}

async fn get_backup_with_cookie(
    base: &str,
    path: &str,
    bearer: &str,
    request_id: Option<&str>,
    cookie: Option<&str>,
) -> (u16, Value, Option<String>) {
    get_backup_with_headers(base, path, bearer, request_id, cookie, None).await
}

async fn get_backup_with_headers(
    base: &str,
    path: &str,
    bearer: &str,
    request_id: Option<&str>,
    cookie: Option<&str>,
    namespace: Option<&str>,
) -> (u16, Value, Option<String>) {
    let mut req = reqwest::Client::new()
        .get(format!("{base}{path}"))
        .bearer_auth(bearer);
    if let Some(request_id) = request_id {
        req = req.header("X-Request-Id", request_id);
    }
    if let Some(cookie) = cookie {
        req = req.header("Cookie", cookie);
    }
    if let Some(namespace) = namespace {
        req = req.header("X-Ferrum-Namespace", namespace);
    }
    let response = req.send().await.expect("GET backup");
    let status = response.status().as_u16();
    let data_source = response
        .headers()
        .get("x-data-source")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body, data_source)
}

async fn get_audit(base: &str, bearer: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .get(format!("{base}/audit?action=backup&limit=20"))
        .bearer_auth(bearer)
        .send()
        .await
        .expect("GET audit");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

fn assert_no_secret_canaries(value: &Value) {
    let rendered = serde_json::to_string(value).expect("serialize");
    assert!(
        !rendered.contains(JWT_CANARY),
        "jwt secret leaked into audit surface: {rendered}"
    );
    assert!(!rendered.contains("Bearer "));
    assert!(!rendered.contains("Cookie:"));
    assert!(!rendered.contains("eyJhbGciOi"));
}

#[tokio::test]
async fn backup_success_writes_audit_with_counts_bytes_and_request_id() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("backup-admin", Some("admin"));

    let (status, body, source) =
        get_backup(&base, "/backup", &admin, Some("req-backup-success-1")).await;
    assert_eq!(status, 200, "backup body: {body:?}");
    assert_eq!(source.as_deref(), Some("database"));

    let (audit_status, audit_body) = get_audit(&base, &admin).await;
    assert_eq!(audit_status, 200, "audit body: {audit_body:?}");
    assert_eq!(audit_body["total"], 1);
    let event = &audit_body["items"][0];
    assert_eq!(event["actor"], "backup-admin");
    assert_eq!(event["action"], "backup");
    assert_eq!(event["outcome"], "success");
    assert_eq!(event["request_id"], "req-backup-success-1");
    assert_eq!(event["source_address"], "127.0.0.1");
    assert_eq!(event["diff"]["data_source"], "database");
    assert_eq!(event["diff"]["resources"], "all");
    assert!(event["diff"]["bytes"].as_u64().unwrap_or(0) > 0);
    assert_eq!(event["diff"]["counts"]["proxies"], 0);
    assert_no_secret_canaries(&audit_body);
}

#[tokio::test]
async fn backup_validation_failure_is_audited_without_export_body() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("backup-admin", Some("admin"));

    let (status, body, _) = get_backup(&base, "/backup?resources=api_specs", &admin, None).await;
    assert_eq!(status, 400, "validation body: {body:?}");
    assert!(body.get("proxies").is_none());

    let (audit_status, audit_body) = get_audit(&base, &admin).await;
    assert_eq!(audit_status, 200);
    assert_eq!(audit_body["total"], 1);
    let event = &audit_body["items"][0];
    assert_eq!(event["outcome"], "validation_failed");
    assert_eq!(event["diff"]["failure_category"], "validation_failed");
    assert_eq!(event["diff"]["resources"], json!(["api_specs"]));
    assert_no_secret_canaries(&audit_body);
}

#[tokio::test]
async fn backup_role_denial_is_audited() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let operator = token("ops-user", Some("operator"));
    let admin = token("backup-admin", Some("admin"));

    let (status, body, _) = get_backup(&base, "/backup", &operator, Some("deny-1")).await;
    assert_eq!(status, 403, "denied body: {body:?}");

    let (audit_status, audit_body) = get_audit(&base, &admin).await;
    assert_eq!(audit_status, 200);
    assert_eq!(audit_body["total"], 1);
    let event = &audit_body["items"][0];
    assert_eq!(event["actor"], "ops-user");
    assert_eq!(event["outcome"], "denied");
    assert_eq!(event["diff"]["failure_category"], "forbidden");
    assert_eq!(event["request_id"], "deny-1");
    assert_no_secret_canaries(&audit_body);
}

#[tokio::test]
async fn backup_unknown_resources_token_is_rejected_without_persisting_canary() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("backup-admin", Some("admin"));
    let canary = "canary-secret-token-never-in-audit-or-logs";

    let (status, body, _) = get_backup(
        &base,
        &format!("/backup?resources=proxies,{canary}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, 400, "unknown resources body: {body:?}");
    assert_eq!(body["error"], "Unsupported backup resource filter");
    assert!(!body.to_string().contains(canary));

    let (audit_status, audit_body) = get_audit(&base, &admin).await;
    assert_eq!(audit_status, 200);
    assert_eq!(audit_body["total"], 1);
    let event = &audit_body["items"][0];
    assert_eq!(event["outcome"], "validation_failed");
    assert_eq!(event["diff"]["failure_category"], "validation_failed");
    assert_eq!(event["diff"]["resources"], "invalid");
    let rendered = serde_json::to_string(&audit_body).unwrap();
    assert!(!rendered.contains(canary));
    assert_no_secret_canaries(&audit_body);
}

#[tokio::test]
async fn backup_key_only_resources_is_rejected_without_widening() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("backup-admin", Some("admin"));

    let (status, body, _) = get_backup(&base, "/backup?resources", &admin, None).await;
    assert_eq!(status, 400, "key-only resources body: {body:?}");
    assert_eq!(body["error"], "Unsupported backup resource filter");
    assert!(body.get("proxies").is_none(), "must not emit a full export");

    let (audit_status, audit_body) = get_audit(&base, &admin).await;
    assert_eq!(audit_status, 200);
    assert_eq!(audit_body["total"], 1);
    let event = &audit_body["items"][0];
    assert_eq!(event["outcome"], "validation_failed");
    assert_eq!(event["diff"]["failure_category"], "validation_failed");
    assert_eq!(event["diff"]["resources"], "invalid");
    assert_no_secret_canaries(&audit_body);
}

#[tokio::test]
async fn backup_duplicate_resources_is_rejected_without_persisting_tokens() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("backup-admin", Some("admin"));
    let canary = "canary-secret-token-never-in-audit-or-logs";

    let (status, body, _) = get_backup(
        &base,
        &format!("/backup?resources=proxies&resources={canary}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, 400, "duplicate resources body: {body:?}");
    assert_eq!(body["error"], "Unsupported backup resource filter");
    assert!(!body.to_string().contains(canary));
    assert!(body.get("proxies").is_none());

    let (audit_status, audit_body) = get_audit(&base, &admin).await;
    assert_eq!(audit_status, 200);
    assert_eq!(audit_body["total"], 1);
    let event = &audit_body["items"][0];
    assert_eq!(event["outcome"], "validation_failed");
    assert_eq!(event["diff"]["resources"], "invalid");
    let rendered = serde_json::to_string(&audit_body).unwrap();
    assert!(!rendered.contains(canary));
    assert_no_secret_canaries(&audit_body);
}

#[tokio::test]
async fn backup_allowlisted_resources_filter_still_exports() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("backup-admin", Some("admin"));

    let (status, body, _) =
        get_backup(&base, "/backup?resources=proxies,consumers", &admin, None).await;
    assert_eq!(status, 200, "allow-listed filter body: {body:?}");
    assert!(body.get("proxies").is_some());
    assert!(body.get("consumers").is_some());
    assert!(body.get("upstreams").is_none() || body["upstreams"].as_array().unwrap().is_empty());

    let (audit_status, audit_body) = get_audit(&base, &admin).await;
    assert_eq!(audit_status, 200);
    assert_eq!(audit_body["total"], 1);
    let event = &audit_body["items"][0];
    assert_eq!(event["outcome"], "success");
    assert_eq!(event["diff"]["resources"], json!(["consumers", "proxies"]));
    assert_no_secret_canaries(&audit_body);
}

#[tokio::test(flavor = "current_thread")]
async fn backup_invalid_namespace_is_audited_in_default_namespace_without_echoing() {
    let (logs, _guard) = capture_backup_audit_logs();
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("backup-admin", Some("admin"));
    let hostile_ns = "hostile-ns/../canary-secret-namespace-never-persist!!";

    let (status, body, _) = get_backup_with_headers(
        &base,
        "/backup",
        &admin,
        Some("ns-invalid-1"),
        Some(COOKIE_CANARY),
        Some(hostile_ns),
    )
    .await;
    assert_eq!(status, 400, "invalid namespace body: {body:?}");
    assert!(body.get("proxies").is_none());
    // Preserve the existing HTTP rejection shape (may mention validation detail).
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("Invalid X-Ferrum-Namespace"),
        "unexpected rejection body: {body:?}"
    );

    let (audit_status, audit_body) = get_audit(&base, &admin).await;
    assert_eq!(audit_status, 200);
    assert_eq!(audit_body["total"], 1);
    let event = &audit_body["items"][0];
    assert_eq!(
        event["namespace"],
        ferrum_edge::config::types::DEFAULT_NAMESPACE
    );
    assert_eq!(
        event["resource_id"],
        ferrum_edge::config::types::DEFAULT_NAMESPACE
    );
    assert_eq!(event["outcome"], "validation_failed");
    assert_eq!(event["diff"]["failure_category"], "validation_failed");
    assert_eq!(event["diff"]["namespace_status"], "invalid");
    assert_eq!(event["diff"]["resources"], "all");
    assert_eq!(event["request_id"], "ns-invalid-1");
    let rendered = serde_json::to_string(&audit_body).unwrap();
    assert!(
        !rendered.contains(hostile_ns),
        "raw invalid namespace leaked into audit: {rendered}"
    );
    assert_no_secret_canaries(&audit_body);

    let captured = logs.contents();
    assert_logs_omit_hostile_canaries(&captured, &[hostile_ns, &admin]);
}

/// A namespace-claim denial must audit the real `GET /backup` attempt, and must
/// not fabricate a `backup` security record for a method that has no backup
/// route — otherwise any authenticated caller could inflate the audit trail
/// with records describing exports that were never reachable.
#[tokio::test]
#[serial_test::serial(admin_audit_local_fallback_lock)]
async fn namespace_claim_denial_audits_get_backup_only() {
    let fallback = TempDir::new().unwrap();
    let mut state = cached_only_state(sample_cached_config());
    state.admin_require_namespace_claim = true;
    state.admin_audit_fallback_dir = Some(fallback.path().to_path_buf());

    let (base, _shutdown) = start_admin(state).await;
    let scoped = token_with_ns("ns-scoped-admin", "other-ns");

    let post = reqwest::Client::new()
        .post(format!("{base}/backup"))
        .bearer_auth(&scoped)
        .header("X-Ferrum-Namespace", "ferrum")
        .send()
        .await
        .expect("POST backup");
    assert_eq!(post.status().as_u16(), 403);
    assert!(
        list_local_fallback_events(fallback.path())
            .expect("list fallback")
            .is_empty(),
        "non-GET /backup must not record a backup security event"
    );

    let (status, _body, _) = get_backup_with_headers(
        &base,
        "/backup",
        &scoped,
        Some("ns-denied-1"),
        None,
        Some("ferrum"),
    )
    .await;
    assert_eq!(status, 403);

    let events = list_local_fallback_events(fallback.path()).expect("list fallback");
    assert_eq!(events.len(), 1, "GET /backup denial must be audited");
    assert_eq!(events[0].action, "backup");
    assert_eq!(events[0].outcome, audit::outcome::DENIED.as_str());
    assert_eq!(events[0].request_id, "ns-denied-1");
    assert_eq!(events[0].diff["failure_category"], "namespace_denied");
}

#[tokio::test]
#[serial_test::serial(admin_audit_local_fallback_lock)]
async fn cached_backup_without_db_uses_local_fallback_audit_sink() {
    let fallback = TempDir::new().unwrap();
    let mut state = cached_only_state(sample_cached_config());
    // Inject an isolated fallback path through AdminState — never mutate
    // process-global environment (which races parallel tests / panics).
    state.admin_audit_fallback_dir = Some(fallback.path().to_path_buf());

    let (base, _shutdown) = start_admin(state).await;
    let admin = token("backup-admin", Some("admin"));

    let (status, body, source) =
        get_backup(&base, "/backup", &admin, Some("cached-backup-1")).await;
    assert_eq!(status, 200, "cached backup body: {body:?}");
    assert_eq!(source.as_deref(), Some("cached"));
    assert!(
        body.to_string().contains(JWT_CANARY),
        "backup payload itself remains unredacted"
    );

    let events = list_local_fallback_events(fallback.path()).expect("list fallback");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, audit::outcome::SUCCESS.as_str());
    assert_eq!(events[0].request_id, "cached-backup-1");
    assert_eq!(events[0].diff["data_source"], "cached");
    assert!(events[0].diff["bytes"].as_u64().unwrap() > 0);
    let rendered = serde_json::to_string(&events[0]).unwrap();
    assert!(!rendered.contains(JWT_CANARY));
}

/// Issue #2422: credentials/tokens/cookies/payload fragments must never appear
/// in tracing output for backup success, authenticated denial, validation
/// failure, or audit-sink failure. Uses current_thread so the capturing
/// subscriber sees handler-emitted logs from the in-process admin server.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(admin_audit_local_fallback_lock)]
async fn backup_paths_omit_hostile_canaries_from_tracing_output() {
    let (logs, _guard) = capture_backup_audit_logs();

    // --- success (cached unredacted payload) ---
    let success_fallback = TempDir::new().unwrap();
    let mut success_state = cached_only_state(sample_cached_config());
    success_state.admin_audit_fallback_dir = Some(success_fallback.path().to_path_buf());
    let (success_base, _success_shutdown) = start_admin(success_state).await;
    let admin = token("backup-admin", Some("admin"));
    let admin_jwt = admin.clone();

    let (status, body, source) = get_backup_with_cookie(
        &success_base,
        "/backup",
        &admin,
        Some("req-log-success-1"),
        Some(COOKIE_CANARY),
    )
    .await;
    assert_eq!(status, 200, "success body: {body:?}");
    assert_eq!(source.as_deref(), Some("cached"));
    assert!(
        body.to_string().contains(JWT_CANARY),
        "export body still carries the credential canary"
    );
    assert!(
        body.to_string().contains(PAYLOAD_FRAGMENT_CANARY),
        "export body still carries the payload-fragment canary"
    );

    // --- authenticated denial ---
    let deny_tmp = TempDir::new().unwrap();
    let (deny_base, _deny_shutdown) = start_admin(admin_state(make_store(&deny_tmp).await)).await;
    let operator = token("ops-user", Some("operator"));
    let (deny_status, deny_body, _) = get_backup_with_cookie(
        &deny_base,
        "/backup",
        &operator,
        Some("req-log-deny-1"),
        Some(COOKIE_CANARY),
    )
    .await;
    assert_eq!(deny_status, 403, "denied body: {deny_body:?}");

    // --- validation failure with hostile resources token ---
    let validation_tmp = TempDir::new().unwrap();
    let (validation_base, _validation_shutdown) =
        start_admin(admin_state(make_store(&validation_tmp).await)).await;
    let (validation_status, validation_body, _) = get_backup_with_cookie(
        &validation_base,
        &format!("/backup?resources=proxies,{RESOURCES_CANARY}"),
        &admin,
        Some("req-log-validation-1"),
        Some(COOKIE_CANARY),
    )
    .await;
    assert_eq!(
        validation_status, 400,
        "validation body: {validation_body:?}"
    );
    assert!(!validation_body.to_string().contains(RESOURCES_CANARY));

    // --- audit-sink failure (no DB + symlink fallback) before releasing body ---
    #[cfg(unix)]
    {
        let parent = TempDir::new().unwrap();
        let real = parent.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut fail_state = cached_only_state(sample_cached_config());
        fail_state.admin_audit_fallback_dir = Some(link);
        let (fail_base, _fail_shutdown) = start_admin(fail_state).await;
        let (fail_status, fail_body, _) = get_backup_with_cookie(
            &fail_base,
            "/backup",
            &admin,
            Some("req-log-admit-fail-1"),
            Some(COOKIE_CANARY),
        )
        .await;
        assert_eq!(fail_status, 503, "admit-fail body: {fail_body:?}");
        assert!(!fail_body.to_string().contains(JWT_CANARY));
        assert!(!fail_body.to_string().contains(PAYLOAD_FRAGMENT_CANARY));
        assert_eq!(
            fail_body["error"],
            "Backup aborted: security audit record could not be admitted"
        );
    }

    let captured = logs.contents();
    assert_logs_omit_hostile_canaries(&captured, &[&admin_jwt, &operator]);
    // Stable sanitized success marker — counts/bytes only, never payload.
    assert!(
        captured.contains("Backup:") && captured.contains("bytes)"),
        "expected sanitized backup success log, got:\n{captured}"
    );
    #[cfg(unix)]
    {
        assert!(
            captured.contains("audit_security_admit_local_fallback")
                || captured
                    .contains("Failed to admit security-sensitive audit event to local fallback"),
            "expected audit-sink failure surface in logs:\n{captured}"
        );
        assert!(
            captured.contains("detail_withheld"),
            "audit-sink failure must withhold detail:\n{captured}"
        );
    }
}
