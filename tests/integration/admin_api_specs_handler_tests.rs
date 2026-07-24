//! Integration tests for the `/api-specs` admin API endpoints (Wave 3).
//!
//! All tests run against an in-process admin listener backed by a SQLite
//! temp-file database so they are self-contained with no external services.
//!
//! The test harness pattern is identical to `admin_backend_capabilities_tests.rs`:
//!   1. Create a fresh SQLite store.
//!   2. Build an `AdminState` wired to that store.
//!   3. Spawn the admin listener on a random port.
//!   4. Make HTTP requests using `reqwest`.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::{
    admin::{
        AdminState,
        jwt_auth::{JwtConfig, JwtManager},
        serve_admin_on_listener,
    },
    config::{
        db_loader::{DatabaseStore, DbPoolConfig},
        types::{Consumer, PluginAssociation, PluginConfig, PluginScope, Proxy, Upstream},
    },
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::{Arc, atomic::AtomicU64, atomic::Ordering};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Counters and helpers
// ---------------------------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(1);

fn uid(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{n}")
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

const JWT_SECRET: &str = "test-secret-key-for-api-specs-32chars";
const JWT_ISSUER: &str = "test-ferrum-edge";

fn make_jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn make_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "test-user",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let key = EncodingKey::from_secret(JWT_SECRET.as_bytes());
    encode(&Header::new(jsonwebtoken::Algorithm::HS256), &claims, &key).unwrap()
}

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

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
    let db_path = dir.path().join(format!("test-{}.db", uid("db")));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, test_pool_config())
        .await
        .expect("connect_with_pool_config failed")
}

// ---------------------------------------------------------------------------
// AdminState builder
// ---------------------------------------------------------------------------

fn make_admin_state(db: DatabaseStore, max_spec_mib: usize) -> AdminState {
    AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: make_jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: max_spec_mib,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 30,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    }
}

// ---------------------------------------------------------------------------
// Listener bootstrap
// ---------------------------------------------------------------------------

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual = listener.local_addr().unwrap();
    let state_clone = state.clone();
    let rx_clone = rx.clone();
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            state_clone,
            rx_clone,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await;
    });
    // Wait until the listener is ready
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    (format!("http://{}", actual), tx)
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

struct AdminClient {
    base: String,
    token: String,
    client: reqwest::Client,
}

impl AdminClient {
    fn new(base: String) -> Self {
        Self {
            base,
            token: make_token(),
            client: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn post_json(&self, path: &str, body: &Value) -> (reqwest::StatusCode, Value) {
        let resp = self
            .client
            .post(self.url(path))
            .header("authorization", format!("Bearer {}", self.token))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(body).unwrap())
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let val: Value = resp.json().await.unwrap_or(json!(null));
        (status, val)
    }

    async fn post_json_in_namespace(
        &self,
        path: &str,
        namespace: &str,
        body: &Value,
    ) -> (reqwest::StatusCode, Value) {
        let resp = self
            .client
            .post(self.url(path))
            .header("authorization", format!("Bearer {}", self.token))
            .header("content-type", "application/json")
            .header("x-ferrum-namespace", namespace)
            .body(serde_json::to_vec(body).unwrap())
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let val: Value = resp.json().await.unwrap_or(json!(null));
        (status, val)
    }

    async fn post_yaml(&self, path: &str, body: &str) -> (reqwest::StatusCode, Value) {
        let resp = self
            .client
            .post(self.url(path))
            .header("authorization", format!("Bearer {}", self.token))
            .header("content-type", "application/yaml")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let val: Value = resp.json().await.unwrap_or(json!(null));
        (status, val)
    }

    async fn post_raw(
        &self,
        path: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> (reqwest::StatusCode, Value) {
        let resp = self
            .client
            .post(self.url(path))
            .header("authorization", format!("Bearer {}", self.token))
            .header("content-type", content_type)
            .body(body)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let val: Value = resp.json().await.unwrap_or(json!(null));
        (status, val)
    }

    async fn put_json(&self, path: &str, body: &Value) -> (reqwest::StatusCode, Value) {
        let resp = self
            .client
            .put(self.url(path))
            .header("authorization", format!("Bearer {}", self.token))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(body).unwrap())
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let val: Value = resp.json().await.unwrap_or(json!(null));
        (status, val)
    }

    /// GET that returns the raw bytes + status (for content negotiation tests).
    async fn get_raw(
        &self,
        path: &str,
        accept: Option<&str>,
        if_none_match: Option<&str>,
    ) -> (reqwest::StatusCode, Vec<u8>, reqwest::header::HeaderMap) {
        let mut req = self
            .client
            .get(self.url(path))
            .header("authorization", format!("Bearer {}", self.token));
        if let Some(a) = accept {
            req = req.header("accept", a);
        }
        if let Some(inm) = if_none_match {
            req = req.header("if-none-match", inm);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.bytes().await.unwrap().to_vec();
        (status, bytes, headers)
    }

    async fn get_json(&self, path: &str) -> (reqwest::StatusCode, Value) {
        let resp = self
            .client
            .get(self.url(path))
            .header("authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let val: Value = resp.json().await.unwrap_or(json!(null));
        (status, val)
    }

    async fn delete(&self, path: &str) -> reqwest::StatusCode {
        self.delete_json(path).await.0
    }

    async fn delete_json(&self, path: &str) -> (reqwest::StatusCode, Value) {
        let resp = self
            .client
            .delete(self.url(path))
            .header("authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let val: Value = resp.json().await.unwrap_or(json!(null));
        (status, val)
    }
}

// ---------------------------------------------------------------------------
// Minimal spec builders
// ---------------------------------------------------------------------------

/// Build a minimal `Proxy` suitable for inserting directly into the DB.
fn make_proxy_for_db(id: &str, namespace: &str, listen_path: &str) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "backend_host": "backend.example.com",
        "backend_port": 443,
        "listen_path": listen_path
    }))
    .expect("proxy deserialization failed")
}

/// Minimal valid JSON spec with a unique proxy id.
fn minimal_json_spec(proxy_id: &str) -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        }
    })
}

fn json_spec_with_plugin(
    proxy_id: &str,
    backend_host: &str,
    plugin_id: &str,
    plugin_name: &str,
    plugin_config: Value,
) -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {"title": "HMAC replacement candidate", "version": "2.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": backend_host,
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        },
        "x-ferrum-plugins": [{
            "id": plugin_id,
            "plugin_name": plugin_name,
            "config": plugin_config
        }]
    })
}

fn hmac_plugin_config() -> Value {
    json!({"clock_skew_seconds": 300})
}

fn request_body_transformer_config() -> Value {
    json!({
        "rules": [{
            "operation": "add",
            "target": "body",
            "key": "gateway",
            "value": "ferrum"
        }]
    })
}

fn manual_proxy_plugin(
    plugin_id: &str,
    proxy_id: &str,
    plugin_name: &str,
    config: Value,
) -> PluginConfig {
    PluginConfig {
        id: plugin_id.to_string(),
        namespace: "ferrum".to_string(),
        plugin_name: plugin_name.to_string(),
        config,
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

async fn convert_spec_owned_plugin_to_global(
    store: &DatabaseStore,
    proxy_id: &str,
    plugin_id: &str,
) {
    let mut proxy = store
        .get_proxy("ferrum", proxy_id)
        .await
        .expect("get spec proxy")
        .expect("spec proxy must exist");
    proxy
        .plugins
        .retain(|association| association.plugin_config_id != plugin_id);
    assert!(
        store
            .update_proxy(&proxy)
            .await
            .expect("remove association"),
        "spec proxy must exist while removing the global association"
    );

    let mut plugin = store
        .get_plugin_config("ferrum", plugin_id)
        .await
        .expect("get spec-owned plugin")
        .expect("spec-owned plugin must exist");
    assert!(
        plugin.api_spec_id.is_some(),
        "seed plugin must retain spec ownership"
    );
    plugin.scope = PluginScope::Global;
    plugin.proxy_id = None;
    assert!(
        store
            .update_plugin_config(&plugin)
            .await
            .expect("promote spec-owned plugin to global"),
        "spec-owned plugin must exist while promoting it to global"
    );
}

async fn attach_manual_proxy_plugin(store: &DatabaseStore, proxy_id: &str, plugin: &PluginConfig) {
    store
        .create_plugin_config(plugin)
        .await
        .expect("create manual plugin");
    let mut proxy = store
        .get_proxy("ferrum", proxy_id)
        .await
        .expect("get proxy for manual association")
        .expect("proxy must exist for manual association");
    proxy.plugins.push(PluginAssociation {
        plugin_config_id: plugin.id.clone(),
    });
    assert!(
        store
            .update_proxy(&proxy)
            .await
            .expect("attach manual plugin"),
        "proxy must exist while attaching manual plugin"
    );
}

async fn assert_put_replaces_removed_spec_owned_global(
    old_plugin_name: &str,
    old_plugin_config: Value,
    incoming_plugin_name: &str,
    incoming_plugin_config: Value,
) {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("replace-global-proxy");
    let old_plugin_id = uid("old-spec-global");
    let incoming_plugin_id = uid("incoming-spec-plugin");
    let initial_spec = json_spec_with_plugin(
        &proxy_id,
        "old-backend.internal",
        &old_plugin_id,
        old_plugin_name,
        old_plugin_config,
    );
    let (post_status, post_body) = client.post_json("/api-specs", &initial_spec).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "initial API spec failed: {post_body}"
    );
    let spec_id = post_body["id"]
        .as_str()
        .expect("POST response must include spec id")
        .to_string();
    convert_spec_owned_plugin_to_global(&store, &proxy_id, &old_plugin_id).await;

    let replacement_spec = json_spec_with_plugin(
        &proxy_id,
        "replacement-backend.internal",
        &incoming_plugin_id,
        incoming_plugin_name,
        incoming_plugin_config,
    );
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &replacement_spec)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::OK,
        "removed spec-owned global polluted replacement validation: {put_body}"
    );
    assert!(
        store
            .get_plugin_config("ferrum", &old_plugin_id)
            .await
            .expect("read removed spec-owned global")
            .is_none(),
        "removed spec-owned global must be deleted by replacement"
    );
    assert!(
        store
            .get_plugin_config("ferrum", &incoming_plugin_id)
            .await
            .expect("read incoming spec plugin")
            .is_some(),
        "incoming spec plugin must be persisted"
    );
    let runtime_config = store
        .load_full_config("ferrum")
        .await
        .expect("successful replacement must remain runtime-loadable");
    assert!(
        runtime_config
            .plugin_configs
            .iter()
            .all(|plugin| plugin.id != old_plugin_id),
        "removed spec-owned global leaked into runtime config"
    );
    assert!(
        runtime_config
            .plugin_configs
            .iter()
            .any(|plugin| plugin.id == incoming_plugin_id),
        "incoming spec plugin missing from runtime config"
    );
}

async fn assert_put_rejects_preserved_manual_association(
    manual_plugin_name: &str,
    manual_plugin_config: Value,
    incoming_plugin_name: &str,
    incoming_plugin_config: Value,
) {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("preserved-manual-proxy");
    let manual_plugin_id = uid("manual-plugin");
    let incoming_plugin_id = uid("incoming-spec-plugin");
    let (post_status, post_body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "initial API spec failed: {post_body}"
    );
    let spec_id = post_body["id"]
        .as_str()
        .expect("POST response must include spec id")
        .to_string();
    let manual_plugin = manual_proxy_plugin(
        &manual_plugin_id,
        &proxy_id,
        manual_plugin_name,
        manual_plugin_config,
    );
    attach_manual_proxy_plugin(&store, &proxy_id, &manual_plugin).await;

    let spec_before = store
        .get_api_spec("ferrum", &spec_id)
        .await
        .expect("read API spec before rejected PUT")
        .expect("API spec must exist before rejected PUT");
    let proxy_before = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("read proxy before rejected PUT")
        .expect("proxy must exist before rejected PUT");
    let replacement_spec = json_spec_with_plugin(
        &proxy_id,
        "replacement-backend.internal",
        &incoming_plugin_id,
        incoming_plugin_name,
        incoming_plugin_config,
    );
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &replacement_spec)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "PUT reported success despite an invalid preserved manual association: {put_body}"
    );
    assert!(
        put_body
            .to_string()
            .contains("hmac_auth cannot be combined with request-body transformer"),
        "missing HMAC composition rejection: {put_body}"
    );

    let spec_after = store
        .get_api_spec("ferrum", &spec_id)
        .await
        .expect("read API spec after rejected PUT")
        .expect("API spec must survive rejected PUT");
    assert_eq!(spec_after.content_hash, spec_before.content_hash);
    assert_eq!(spec_after.resource_hash, spec_before.resource_hash);
    assert_eq!(spec_after.updated_at, spec_before.updated_at);
    let proxy_after = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("read proxy after rejected PUT")
        .expect("proxy must survive rejected PUT");
    assert_eq!(proxy_after.backend_host, proxy_before.backend_host);
    assert_eq!(proxy_after.updated_at, proxy_before.updated_at);
    let associations_after: Vec<&str> = proxy_after
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .collect();
    assert!(
        associations_after.contains(&manual_plugin_id.as_str()),
        "rejected PUT removed the preserved manual association: {associations_after:?}"
    );
    assert!(
        store
            .get_plugin_config("ferrum", &incoming_plugin_id)
            .await
            .expect("read rejected incoming plugin")
            .is_none(),
        "rejected incoming spec plugin must not be persisted"
    );
    let runtime_config = store
        .load_full_config("ferrum")
        .await
        .expect("rejected replacement must leave the prior runtime config loadable");
    assert!(
        runtime_config
            .proxies
            .iter()
            .find(|proxy| proxy.id == proxy_id)
            .is_some_and(|proxy| {
                proxy
                    .plugins
                    .iter()
                    .any(|association| association.plugin_config_id == manual_plugin_id)
            }),
        "prior runtime config lost the preserved manual association"
    );
}

/// Minimal valid YAML spec string.
fn minimal_yaml_spec(proxy_id: &str) -> String {
    format!(
        r#"openapi: "3.1.0"
info:
  title: YAML Test API
  version: "1.0.0"
x-ferrum-proxy:
  id: {proxy_id}
  backend_host: backend.internal
  backend_port: 443
  listen_path: /{proxy_id}
"#
    )
}

// ============================================================================
// POST /api-specs — happy path
// ============================================================================

#[tokio::test]
async fn post_happy_path_returns_201_with_id() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let (status, body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;

    assert_eq!(status, reqwest::StatusCode::CREATED, "body: {body}");
    assert!(body["id"].is_string(), "expected id in response: {body}");
    assert_eq!(body["proxy_id"].as_str().unwrap(), proxy_id);
    assert!(body["content_hash"].is_string());
    assert!(body["spec_version"].is_string());
}

#[tokio::test]
async fn post_returns_id_that_can_be_fetched() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let (post_status, post_body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED);

    let spec_id = post_body["id"].as_str().unwrap();
    let (get_status, get_bytes, _) = client
        .get_raw(
            &format!("/api-specs/{spec_id}"),
            Some("application/json"),
            None,
        )
        .await;
    assert_eq!(
        get_status,
        reqwest::StatusCode::OK,
        "GET after POST should return 200"
    );
    // The bytes should parse as valid JSON
    let parsed: Value = serde_json::from_slice(&get_bytes).unwrap();
    assert!(parsed.get("openapi").is_some() || parsed.get("swagger").is_some());
}

// ============================================================================
// POST — error paths
// ============================================================================

#[tokio::test]
async fn post_malformed_body_returns_400() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base.clone());

    let (status, body) = client
        .post_raw(
            "/api-specs",
            b"not valid json or yaml at all !!!".to_vec(),
            "application/json",
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "body: {body}");
    assert!(body["code"].is_string(), "expected error code: {body}");
}

#[tokio::test]
async fn post_with_x_ferrum_consumers_returns_400_with_code() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let spec = json!({
        "swagger": "2.0",
        "info": {"title": "T", "version": "1"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "b.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        },
        "x-ferrum-consumers": [{"username": "alice"}]
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    // ConsumerExtensionNotAllowed is a semantic violation → 422 (L5 fix).
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "body: {body}"
    );
    assert_eq!(
        body["code"].as_str().unwrap_or(""),
        "ConsumerExtensionNotAllowed"
    );
    // Body shape must be consistent with other extract errors.
    assert!(body["error"].is_string(), "body must have 'error' field");
    assert!(
        body["details"].is_string(),
        "body must have 'details' field"
    );
}

#[tokio::test]
async fn post_with_plugin_scope_global_returns_400() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let spec = json!({
        "swagger": "2.0",
        "info": {"title": "T", "version": "1"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "b.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        },
        "x-ferrum-plugins": [{
            "id": "bad-plugin",
            "plugin_name": "rate_limiting",
            "scope": "global",
            "config": {}
        }]
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    // PluginInvalidScope is a semantic violation → 422 (L5 fix).
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "body: {body}"
    );
    assert_eq!(body["code"].as_str().unwrap_or(""), "PluginInvalidScope");
}

#[tokio::test]
async fn post_with_invalid_proxy_field_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    // listen_port on an HTTP proxy is invalid
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "version": "1"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "b.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "listen_port": 9090
        }
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "body: {body}"
    );
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "Spec validation failed"
    );
    assert!(body["failures"].is_array());
}

#[tokio::test]
async fn api_spec_post_and_put_reject_client_supplied_ownership_tags() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    let rejected_proxy_id = uid("ownership-tagged-post");
    let rejected_upstream_id = uid("ownership-tagged-upstream");
    let rejected_plugin_id = uid("ownership-tagged-plugin");
    let copied_owner = uid("copied-api-spec-owner");
    let tagged_spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Copied API", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": rejected_proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{rejected_proxy_id}"),
            "api_spec_id": copied_owner
        },
        "x-ferrum-upstream": {
            "id": rejected_upstream_id,
            "targets": [{"host": "target.internal", "port": 443}],
            "api_spec_id": copied_owner
        },
        "x-ferrum-plugins": [{
            "id": rejected_plugin_id,
            "plugin_name": "rate_limiting",
            "config": {"limits": [{"scope": "default", "requests_per_minute": 100}]},
            "api_spec_id": copied_owner
        }]
    });

    let (post_status, post_body) = client.post_json("/api-specs", &tagged_spec).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "client-supplied ownership tags must be a validation error: {post_body}"
    );
    let post_failures = post_body["failures"]
        .as_array()
        .expect("422 response must include validation failures");
    for resource_type in ["proxy", "upstream", "plugin"] {
        assert!(
            post_failures.iter().any(|failure| {
                failure["resource_type"] == resource_type
                    && failure["errors"].as_array().is_some_and(|errors| {
                        errors.iter().any(|error| {
                            error
                                .as_str()
                                .is_some_and(|message| message.contains("server-managed"))
                        })
                    })
            }),
            "missing {resource_type} ownership-tag rejection: {post_body}"
        );
    }
    assert!(
        store
            .get_proxy("ferrum", &rejected_proxy_id)
            .await
            .unwrap()
            .is_none(),
        "rejected POST must not persist its proxy"
    );

    let existing_proxy_id = uid("ownership-tagged-put");
    let (setup_status, setup_body) = client
        .post_json("/api-specs", &minimal_json_spec(&existing_proxy_id))
        .await;
    assert_eq!(setup_status, reqwest::StatusCode::CREATED, "{setup_body}");
    let spec_id = setup_body["id"]
        .as_str()
        .expect("POST response must include spec id");
    let mut tagged_put = minimal_json_spec(&existing_proxy_id);
    tagged_put["x-ferrum-proxy"]["api_spec_id"] = json!(copied_owner);
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &tagged_put)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "PUT must reject copied ownership tags before persistence: {put_body}"
    );
    assert!(put_body.to_string().contains("server-managed"));
    assert!(
        store
            .get_api_spec("ferrum", spec_id)
            .await
            .unwrap()
            .is_some(),
        "rejected PUT must preserve the existing API spec"
    );
}

#[tokio::test]
async fn post_same_proxy_id_twice_returns_conflict_or_validation_error() {
    // When the same spec (same proxy_id + listen_path) is submitted twice,
    // the second attempt fails because the listen_path uniqueness check at
    // validation time detects the conflict.  The response is either:
    //   422 Unprocessable Entity — detected during validation (listen_path conflict)
    //   409 Conflict             — detected during DB insert (UNIQUE constraint)
    // Both are correct rejections; this test asserts one of the two.
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let spec = minimal_json_spec(&proxy_id);

    let (s1, _) = client.post_json("/api-specs", &spec).await;
    assert_eq!(s1, reqwest::StatusCode::CREATED);

    let (s2, body2) = client.post_json("/api-specs", &spec).await;
    assert!(
        s2 == reqwest::StatusCode::CONFLICT || s2 == reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 409 or 422 on duplicate submit, got {s2}; body: {body2}"
    );
}

/// P1 regression: 409 Conflict responses must NOT expose raw DB error strings
/// (constraint names, table names, schema internals) to the caller.
///
/// The handler logs the raw detail at WARN but returns only a generic message.
#[tokio::test]
async fn conflict_error_does_not_leak_raw_db_message() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let spec = minimal_json_spec(&proxy_id);

    // First submit succeeds.
    let (s1, _) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        s1,
        reqwest::StatusCode::CREATED,
        "first submit must succeed"
    );

    // Second submit of the same spec must fail with 409 or 422.
    let (s2, body2) = client.post_json("/api-specs", &spec).await;
    assert!(
        s2 == reqwest::StatusCode::CONFLICT || s2 == reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 409 or 422 on duplicate submit, got {s2}; body: {body2}"
    );

    if s2 == reqwest::StatusCode::CONFLICT {
        // If the DB constraint fired, the error body must NOT contain raw DB internals.
        let error_str = body2["error"].as_str().unwrap_or("");
        let body_str = body2.to_string();

        // Must NOT contain SQL/Mongo constraint identifiers.
        assert!(
            !body_str.to_lowercase().contains("unique"),
            "conflict response must not expose 'UNIQUE' constraint name; body: {body2}"
        );
        assert!(
            !body_str.to_lowercase().contains("constraint"),
            "conflict response must not expose 'constraint'; body: {body2}"
        );
        assert!(
            !body_str.to_lowercase().contains("duplicate key"),
            "conflict response must not expose 'duplicate key'; body: {body2}"
        );
        assert!(
            !body_str.contains("proxies"),
            "conflict response must not expose table name 'proxies'; body: {body2}"
        );
        assert!(
            !body_str.contains("api_specs"),
            "conflict response must not expose table name 'api_specs'; body: {body2}"
        );

        // The error message should be the generic one.
        assert!(
            error_str.contains("conflict") || error_str.contains("Conflict"),
            "conflict response must contain a generic conflict message; got: {error_str}"
        );
    }
}

#[tokio::test]
async fn post_body_exceeding_limit_returns_413() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    // Set cap to 1 byte effectively (1 MiB to avoid needing huge payloads, but
    // we send 2 MiB worth)
    let (base, _shutdown) = start_admin(make_admin_state(store, 1)).await;
    let client = AdminClient::new(base);

    // 2 MiB body — exceeds the 1 MiB cap
    let big_body = vec![b'x'; 2 * 1024 * 1024];
    let (status, body) = client
        .post_raw("/api-specs", big_body, "application/json")
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "body: {body}"
    );
}

#[tokio::test]
async fn post_body_exceeding_limit_with_raised_cap_succeeds() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    // Raise cap to 50 MiB; send a 2 MiB valid spec
    let (base, _shutdown) = start_admin(make_admin_state(store, 50)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let spec = minimal_json_spec(&proxy_id);
    let body_bytes = serde_json::to_vec(&spec).unwrap();

    // Under the cap → should succeed
    let (status, resp_body) = client
        .post_raw("/api-specs", body_bytes, "application/json")
        .await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "body: {resp_body}");
}

// ============================================================================
// GET /api-specs/{id}
// ============================================================================

#[tokio::test]
async fn get_unknown_id_returns_404() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let (status, _, _) = client.get_raw("/api-specs/doesnotexist", None, None).await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_roundtrip_yaml_submit_accept_json() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let yaml_spec = minimal_yaml_spec(&proxy_id);

    // Submit as YAML
    let (post_status, post_body) = client.post_yaml("/api-specs", &yaml_spec).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "body: {post_body}"
    );

    let spec_id = post_body["id"].as_str().unwrap();

    // Retrieve with Accept: application/json — should get valid JSON
    let (get_status, get_bytes, get_headers) = client
        .get_raw(
            &format!("/api-specs/{spec_id}"),
            Some("application/json"),
            None,
        )
        .await;
    assert_eq!(get_status, reqwest::StatusCode::OK);
    // Must parse as JSON
    let parsed: Value = serde_json::from_slice(&get_bytes)
        .expect("GET response should be valid JSON when Accept: application/json");
    assert_eq!(parsed["openapi"].as_str(), Some("3.1.0"));
    // Content-Type must be application/json
    let ct = get_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("application/json"),
        "expected JSON content-type, got: {ct}"
    );
}

#[tokio::test]
async fn get_with_matching_if_none_match_returns_304() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let (post_status, post_body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED);

    let spec_id = post_body["id"].as_str().unwrap();

    // First GET to grab the ETag
    let (_, _, headers) = client
        .get_raw(&format!("/api-specs/{spec_id}"), None, None)
        .await;
    let etag = headers
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("ETag header must be present")
        .to_string();

    // Conditional GET with If-None-Match matching the ETag
    let (status, _, _) = client
        .get_raw(&format!("/api-specs/{spec_id}"), None, Some(&etag))
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::NOT_MODIFIED,
        "matching ETag should return 304"
    );
}

// ============================================================================
// GET /api-specs/by-proxy/{proxy_id}
// ============================================================================

#[tokio::test]
async fn get_by_proxy_returns_spec_content() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let (post_status, _) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED);

    let (status, bytes, _) = client
        .get_raw(
            &format!("/api-specs/by-proxy/{proxy_id}"),
            Some("application/json"),
            None,
        )
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "by-proxy should return 200"
    );
    let parsed: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(parsed.get("openapi").is_some());
}

#[tokio::test]
async fn get_by_proxy_unknown_returns_404() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let (status, _, _) = client
        .get_raw("/api-specs/by-proxy/no-such-proxy", None, None)
        .await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
}

// ============================================================================
// PUT /api-specs/{id}
// ============================================================================

#[tokio::test]
async fn put_replaces_spec_content() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");

    // Initial POST
    let (post_status, post_body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED);
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    // Replace with updated version
    let updated_spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Updated API", "version": "2.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "new-backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        }
    });

    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &updated_spec)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::OK,
        "PUT should return 200; body: {put_body}"
    );
    assert_eq!(put_body["id"].as_str().unwrap(), spec_id);

    // Verify content changed
    let (get_status, get_bytes, _) = client
        .get_raw(
            &format!("/api-specs/{spec_id}"),
            Some("application/json"),
            None,
        )
        .await;
    assert_eq!(get_status, reqwest::StatusCode::OK);
    let parsed: Value = serde_json::from_slice(&get_bytes).unwrap();
    assert_eq!(parsed["info"]["title"].as_str(), Some("Updated API"));
}

#[tokio::test]
async fn put_unknown_id_returns_404() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let (status, body) = client
        .put_json("/api-specs/no-such-id", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND, "body: {body}");
}

// ============================================================================
// DELETE /api-specs/{id}
// ============================================================================

#[tokio::test]
async fn delete_removes_spec_and_proxy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let (post_status, post_body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED);
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    // Delete
    let del_status = client.delete(&format!("/api-specs/{spec_id}")).await;
    assert_eq!(del_status, reqwest::StatusCode::NO_CONTENT);

    // Spec is gone
    let (get_status, _, _) = client
        .get_raw(&format!("/api-specs/{spec_id}"), None, None)
        .await;
    assert_eq!(get_status, reqwest::StatusCode::NOT_FOUND);

    // Proxy is gone too (via DB cascade)
    let proxy_row = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get_proxy failed");
    assert!(
        proxy_row.is_none(),
        "proxy should be deleted after spec delete"
    );
}

#[tokio::test]
async fn delete_unknown_id_returns_404() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let status = client.delete("/api-specs/no-such-id").await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_rejects_removing_last_global_tcp_throttle_target_with_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_port = bound.local_addr().unwrap().port();
    drop(bound);

    let tcp_proxy_id = uid("spec-tcp-delete-guard");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "TCP delete guard", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": tcp_proxy_id,
            "backend_scheme": "tcp",
            "backend_host": "127.0.0.1",
            "backend_port": 9000,
            "listen_port": listen_port
        }
    });
    let (post_status, post_body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "TCP API-spec setup failed: {post_body}"
    );
    let spec_id = post_body["id"]
        .as_str()
        .expect("POST response must include spec id")
        .to_string();

    let http_proxy_id = uid("http-only");
    store
        .create_proxy(&make_proxy_for_db(
            &http_proxy_id,
            "ferrum",
            &format!("/{http_proxy_id}"),
        ))
        .await
        .expect("create unsupported global target");
    let throttle_id = uid("global-tcp-throttle");
    let now = Utc::now();
    store
        .create_plugin_config(&PluginConfig {
            id: throttle_id,
            namespace: "ferrum".to_string(),
            plugin_name: "tcp_connection_throttle".to_string(),
            config: json!({"max_connections_per_key": 1}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("mixed global throttle graph must be valid");

    let (delete_status, delete_body) = client.delete_json(&format!("/api-specs/{spec_id}")).await;
    assert_eq!(
        delete_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "invalid API-spec cascade did not return 422: {delete_body}"
    );
    assert!(
        delete_body["failures"].as_array().is_some_and(|failures| {
            failures
                .iter()
                .any(|failure| failure["resource_type"] == "plugin_composition")
        }),
        "422 response omitted the plugin-composition failure: {delete_body}"
    );
    assert!(
        store
            .get_api_spec("ferrum", &spec_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get_proxy("ferrum", &tcp_proxy_id)
            .await
            .unwrap()
            .is_some()
    );
}

// ============================================================================
// GET /api-specs (list)
// ============================================================================

#[tokio::test]
async fn list_returns_namespace_scoped_items() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // Submit two specs
    let p1 = uid("proxy");
    let p2 = uid("proxy");
    let (s1, _) = client
        .post_json("/api-specs", &minimal_json_spec(&p1))
        .await;
    let (s2, _) = client
        .post_json("/api-specs", &minimal_json_spec(&p2))
        .await;
    assert_eq!(s1, reqwest::StatusCode::CREATED);
    assert_eq!(s2, reqwest::StatusCode::CREATED);

    let (list_status, list_body) = client.get_json("/api-specs").await;
    assert_eq!(list_status, reqwest::StatusCode::OK);
    let items = list_body["items"].as_array().expect("items must be array");
    assert!(
        items.len() >= 2,
        "expected at least 2 items, got {}",
        items.len()
    );
}

#[tokio::test]
async fn list_does_not_include_spec_content() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let (s, _) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(s, reqwest::StatusCode::CREATED);

    let (_, list_body) = client.get_json("/api-specs").await;
    let items = list_body["items"].as_array().expect("items must be array");
    assert!(!items.is_empty());

    for item in items {
        assert!(
            item.get("spec_content").is_none(),
            "spec_content must NOT be in list response; item: {item}"
        );
    }
}

#[tokio::test]
async fn list_pagination_with_next_offset() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // Submit 3 specs
    for _ in 0..3 {
        let p = uid("proxy");
        let (s, _) = client.post_json("/api-specs", &minimal_json_spec(&p)).await;
        assert_eq!(s, reqwest::StatusCode::CREATED);
    }

    // Request first 2
    let (status, body) = client.get_json("/api-specs?limit=2&offset=0").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["limit"].as_u64().unwrap(), 2);
    assert_eq!(body["offset"].as_u64().unwrap(), 0);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);

    // `total` must be an integer equal to the total number of inserted specs.
    assert!(
        body["total"].is_number(),
        "list response must include a `total` integer field; body: {body}"
    );
    assert_eq!(
        body["total"].as_i64().unwrap(),
        3,
        "`total` must reflect the count of all matching specs, not just this page"
    );

    // When limit exactly equals count, next_offset should be set
    if body["next_offset"].is_number() {
        assert_eq!(body["next_offset"].as_u64().unwrap(), 2);
    }
    // next request with offset=2
    let (status2, body2) = client.get_json("/api-specs?limit=2&offset=2").await;
    assert_eq!(status2, reqwest::StatusCode::OK);
    // Should have the remaining item(s)
    assert!(!body2["items"].as_array().unwrap().is_empty());
    // total must also be present on subsequent pages and remain consistent.
    assert_eq!(
        body2["total"].as_i64().unwrap(),
        3,
        "`total` must be consistent across pages"
    );
}

// ============================================================================
// Auth guard
// ============================================================================

#[tokio::test]
async fn unauthenticated_post_returns_401() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;

    let client = reqwest::Client::new();
    let status = client
        .post(format!("{}/api-specs", base))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unauthenticated_get_returns_401() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;

    let client = reqwest::Client::new();
    let status = client
        .get(format!("{}/api-specs/some-id", base))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
}

// ============================================================================
// Gap #2: Plugin validation against a real failing plugin config
// ============================================================================

/// `rate_limiting` with an empty config fails `validate_plugin_config` because
/// no rate-limit windows are specified.  The handler must return 422 with a
/// `failures` entry whose `resource_type` is "plugin" and `id` matches the
/// plugin id from the spec.
#[tokio::test]
async fn post_with_failing_plugin_config_returns_422_via_real_validator() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        },
        "x-ferrum-plugins": [{
            "id": "bad-rl",
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "config": {}
        }]
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 422 for failing plugin config; body: {body}"
    );
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "Spec validation failed",
        "body: {body}"
    );
    let failures = body["failures"].as_array().expect("failures must be array");
    let plugin_failure = failures
        .iter()
        .find(|f| f["resource_type"].as_str() == Some("plugin"))
        .unwrap_or_else(|| panic!("expected a plugin failure entry; body: {body}"));
    assert_eq!(
        plugin_failure["id"].as_str().unwrap_or(""),
        "bad-rl",
        "plugin failure id must match the submitted plugin id"
    );
}

#[tokio::test]
async fn api_spec_post_and_exact_put_validate_against_prospective_schema_graph() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let schema_name = uid("api-spec-schema");
    let schema_plugin = PluginConfig {
        id: uid("schema-plugin"),
        namespace: "ferrum".to_string(),
        plugin_name: "transaction_log_schema".to_string(),
        config: json!({"schemas": {(schema_name.clone()): {}}}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    store
        .create_plugin_config(&schema_plugin)
        .await
        .expect("persist prospective schema without publishing the live registry");

    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("schema-api-spec-proxy");
    let plugin_id = uid("schema-api-spec-logger");
    let mut spec = json_spec_with_plugin(
        &proxy_id,
        "backend.internal",
        &plugin_id,
        "stdout_logging",
        json!({"schema_ref": schema_name}),
    );

    let (post_status, post_body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "POST must use the authoritative prospective graph: {post_body}"
    );
    let spec_id = post_body["id"]
        .as_str()
        .expect("created API spec returns id");

    spec["info"]["version"] = json!("2.0.0");
    spec["x-ferrum-plugins"][0]["config"]["filter"] = json!({"status_code_min": 500});
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::OK,
        "exact PUT must remove old spec-owned plugins and overlay replacements before graph validation: {put_body}"
    );
}

#[tokio::test]
async fn api_spec_writes_ignore_an_unchanged_invalid_persisted_schema_graph() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("unrelated-schema-graph-proxy");
    let mut spec = minimal_json_spec(&proxy_id);

    let (post_status, post_body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
    let spec_id = post_body["id"]
        .as_str()
        .expect("created API spec returns id");

    store
        .create_plugin_config(&PluginConfig {
            id: uid("preexisting-dangling-logger"),
            namespace: "ferrum".to_string(),
            plugin_name: "stdout_logging".to_string(),
            config: json!({"schema_ref": "missing"}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .await
        .expect("persist pre-existing invalid graph participant");

    let unrelated_proxy_id = uid("second-unrelated-schema-graph-proxy");
    let (unrelated_status, unrelated_body) = client
        .post_json("/api-specs", &minimal_json_spec(&unrelated_proxy_id))
        .await;
    assert_eq!(
        unrelated_status,
        reqwest::StatusCode::CREATED,
        "unrelated POST must not repair the persisted graph: {unrelated_body}"
    );

    spec["info"]["version"] = json!("2.0.0");
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::OK,
        "unrelated PUT must not repair the persisted graph: {put_body}"
    );
}

#[tokio::test]
async fn api_spec_put_and_delete_validate_removed_spec_owned_schema_definitions() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("removed-schema-definition-proxy");
    let mut spec = minimal_json_spec(&proxy_id);

    let (post_status, post_body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
    let spec_id = post_body["id"]
        .as_str()
        .expect("created API spec returns id")
        .to_string();
    let schema_name = uid("spec-owned-schema");
    let schema_id = uid("spec-owned-schema-plugin");
    store
        .create_plugin_config(&PluginConfig {
            id: schema_id.clone(),
            namespace: "ferrum".to_string(),
            plugin_name: "transaction_log_schema".to_string(),
            config: json!({"schemas": {(schema_name.clone()): {}}}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .await
        .expect("persist spec-owned schema definition");
    sqlx::query("UPDATE plugin_configs SET api_spec_id = ? WHERE namespace = ? AND id = ?")
        .bind(&spec_id)
        .bind("ferrum")
        .bind(&schema_id)
        .execute(&store.pool())
        .await
        .expect("tag schema definition with API-spec ownership");
    let owned_plugins = store
        .list_spec_owned_plugin_configs("ferrum", &spec_id)
        .await
        .expect("list spec-owned plugins before replacement");
    assert!(
        owned_plugins.iter().any(|plugin| plugin.id == schema_id),
        "test precondition: the removed definition must be spec-owned"
    );
    store
        .create_plugin_config(&PluginConfig {
            id: uid("manual-schema-referrer"),
            namespace: "ferrum".to_string(),
            plugin_name: "stdout_logging".to_string(),
            config: json!({"schema_ref": schema_name}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .await
        .expect("persist manual schema referrer");

    spec["info"]["version"] = json!("2.0.0");
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "removing the spec-owned definition must validate retained referrers: {put_body}"
    );
    assert!(
        put_body.to_string().contains("unknown schema"),
        "{put_body}"
    );
    let owned_plugins = store
        .list_spec_owned_plugin_configs("ferrum", &spec_id)
        .await
        .expect("list spec-owned plugins after rejected PUT");
    assert!(
        owned_plugins.iter().any(|plugin| plugin.id == schema_id),
        "rejected PUT must preserve the spec-owned schema definition"
    );

    let delete_status = client.delete(&format!("/api-specs/{spec_id}")).await;
    assert_eq!(
        delete_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "deleting a spec-owned definition must validate retained referrers"
    );
    let owned_plugins = store
        .list_spec_owned_plugin_configs("ferrum", &spec_id)
        .await
        .expect("list spec-owned plugins after rejected DELETE");
    assert!(
        owned_plugins.iter().any(|plugin| plugin.id == schema_id),
        "rejected DELETE must preserve the spec-owned schema definition"
    );
}

#[tokio::test]
async fn api_spec_delete_models_proxy_and_orphaned_group_plugin_cascades() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("schema-cascade-proxy");
    let spec = minimal_json_spec(&proxy_id);

    let (post_status, post_body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
    let spec_id = post_body["id"]
        .as_str()
        .expect("created API spec returns id")
        .to_string();
    let schema_name = uid("cascade-schema");
    let schema_id = uid("cascade-schema-owner");
    store
        .create_plugin_config(&PluginConfig {
            id: schema_id.clone(),
            namespace: "ferrum".to_string(),
            plugin_name: "transaction_log_schema".to_string(),
            config: json!({"schemas": {(schema_name.clone()): {}}}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .await
        .expect("persist schema definition");
    sqlx::query("UPDATE plugin_configs SET api_spec_id = ? WHERE namespace = ? AND id = ?")
        .bind(&spec_id)
        .bind("ferrum")
        .bind(&schema_id)
        .execute(&store.pool())
        .await
        .expect("tag schema definition with API-spec ownership");

    let proxy_logger_id = uid("cascade-proxy-logger");
    let proxy_logger = manual_proxy_plugin(
        &proxy_logger_id,
        &proxy_id,
        "stdout_logging",
        json!({"schema_ref": schema_name}),
    );
    attach_manual_proxy_plugin(&store, &proxy_id, &proxy_logger).await;

    let group_logger_id = uid("cascade-group-logger");
    let group_logger = PluginConfig {
        id: group_logger_id.clone(),
        namespace: "ferrum".to_string(),
        plugin_name: "stdout_logging".to_string(),
        config: json!({"schema_ref": schema_name}),
        scope: PluginScope::ProxyGroup,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    attach_manual_proxy_plugin(&store, &proxy_id, &group_logger).await;

    let delete_status = client.delete(&format!("/api-specs/{spec_id}")).await;
    assert_eq!(
        delete_status,
        reqwest::StatusCode::NO_CONTENT,
        "referrers removed by the same proxy cascade must not block deletion"
    );
    for plugin_id in [&schema_id, &proxy_logger_id, &group_logger_id] {
        assert!(
            store
                .get_plugin_config("ferrum", plugin_id)
                .await
                .expect("read cascade-deleted plugin")
                .is_none(),
            "API-spec deletion must remove cascaded plugin {plugin_id}"
        );
    }
}

#[tokio::test]
async fn api_spec_delete_accepts_unattached_proxy_scoped_cascade_plugin() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("unattached-cascade-proxy");
    let spec = minimal_json_spec(&proxy_id);

    let (post_status, post_body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
    let spec_id = post_body["id"]
        .as_str()
        .expect("created API spec returns id")
        .to_string();
    let plugin_id = uid("unattached-cascade-plugin");
    store
        .create_plugin_config(&manual_proxy_plugin(
            &plugin_id,
            &proxy_id,
            "stdout_logging",
            json!({}),
        ))
        .await
        .expect("create unattached proxy-scoped plugin");

    let proxy = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get API-spec proxy")
        .expect("API-spec proxy missing");
    assert!(
        proxy
            .plugins
            .iter()
            .all(|association| association.plugin_config_id != plugin_id),
        "test plugin must remain unattached"
    );

    let delete_status = client.delete(&format!("/api-specs/{spec_id}")).await;
    assert_eq!(
        delete_status,
        reqwest::StatusCode::NO_CONTENT,
        "valid unattached proxy-scoped config must not block API-spec deletion"
    );
    assert!(
        store
            .get_plugin_config("ferrum", &plugin_id)
            .await
            .expect("read cascade-deleted unattached plugin")
            .is_none(),
        "proxy deletion must cascade the unattached proxy-scoped config"
    );
}

#[tokio::test]
async fn api_spec_delete_rejects_cascade_plugins_that_atomic_restore_cannot_recreate() {
    for (scope, expected_error) in [
        ("global", "is global and cannot be associated"),
        ("proxy_group", "proxy-group plugin"),
    ] {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir).await;
        let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
        let client = AdminClient::new(base);
        let proxy_id = uid("malformed-cascade-proxy");
        let spec = minimal_json_spec(&proxy_id);

        let (post_status, post_body) = client.post_json("/api-specs", &spec).await;
        assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
        let spec_id = post_body["id"]
            .as_str()
            .expect("created API spec returns id")
            .to_string();
        let plugin_id = uid("malformed-cascade-plugin");
        store
            .create_plugin_config(&manual_proxy_plugin(
                &plugin_id,
                &proxy_id,
                "stdout_logging",
                json!({}),
            ))
            .await
            .expect("create hand-owned proxy plugin");
        sqlx::query("UPDATE plugin_configs SET scope = ? WHERE namespace = ? AND id = ?")
            .bind(scope)
            .bind("ferrum")
            .bind(&plugin_id)
            .execute(&store.pool())
            .await
            .expect("inject malformed cascade scope");

        let (delete_status, delete_body) =
            client.delete_json(&format!("/api-specs/{spec_id}")).await;
        assert_eq!(
            delete_status,
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            "{scope} plugin with proxy_id must fail closed: {delete_body}"
        );
        assert_eq!(delete_body["error"], "Spec validation failed");
        assert_eq!(
            delete_body["failures"][0]["resource_type"],
            "restore_snapshot"
        );
        assert!(
            delete_body["failures"][0]["errors"][0]
                .as_str()
                .is_some_and(|error| error.contains(expected_error)),
            "unexpected restore-snapshot failure: {delete_body}"
        );
        assert!(
            store
                .get_api_spec("ferrum", &spec_id)
                .await
                .expect("read preserved API spec")
                .is_some(),
            "rejected delete must preserve the API spec"
        );
        assert!(
            store
                .get_proxy("ferrum", &proxy_id)
                .await
                .expect("read preserved proxy")
                .is_some(),
            "rejected delete must preserve the proxy"
        );
        assert!(
            store
                .get_plugin_config("ferrum", &plugin_id)
                .await
                .expect("read preserved malformed plugin")
                .is_some(),
            "rejected delete must preserve the malformed plugin for repair"
        );
    }
}

#[tokio::test]
async fn api_spec_delete_rejects_unrestorable_hand_owned_associations_before_persistence() {
    for (case, expected_error) in [
        ("global", "is global and cannot be associated"),
        ("other_proxy", "not restored proxy"),
    ] {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir).await;
        let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
        let client = AdminClient::new(base);
        let proxy_id = uid("unrestorable-association-proxy");
        let spec = minimal_json_spec(&proxy_id);

        let (post_status, post_body) = client.post_json("/api-specs", &spec).await;
        assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
        let spec_id = post_body["id"]
            .as_str()
            .expect("created API spec returns id")
            .to_string();
        let plugin_id = uid("unrestorable-association-plugin");
        let plugin = manual_proxy_plugin(&plugin_id, &proxy_id, "stdout_logging", json!({}));
        attach_manual_proxy_plugin(&store, &proxy_id, &plugin).await;

        match case {
            "global" => {
                sqlx::query(
                    "UPDATE plugin_configs SET scope = 'global', proxy_id = NULL \
                     WHERE namespace = ? AND id = ?",
                )
                .bind("ferrum")
                .bind(&plugin_id)
                .execute(&store.pool())
                .await
                .expect("inject associated global plugin");
            }
            "other_proxy" => {
                let other_proxy_id = uid("unrestorable-association-other-proxy");
                store
                    .create_proxy(&make_proxy_for_db(
                        &other_proxy_id,
                        "ferrum",
                        &format!("/{other_proxy_id}"),
                    ))
                    .await
                    .expect("create the plugin's foreign target proxy");
                sqlx::query(
                    "UPDATE plugin_configs SET proxy_id = ? WHERE namespace = ? AND id = ?",
                )
                .bind(&other_proxy_id)
                .bind("ferrum")
                .bind(&plugin_id)
                .execute(&store.pool())
                .await
                .expect("retarget associated plugin to another proxy");
            }
            _ => unreachable!("fixed test case"),
        }

        let (delete_status, delete_body) =
            client.delete_json(&format!("/api-specs/{spec_id}")).await;
        assert_eq!(
            delete_status,
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            "unrestorable {case} association must fail before delete: {delete_body}"
        );
        assert_eq!(delete_body["error"], "Spec validation failed");
        assert_eq!(
            delete_body["failures"][0]["resource_type"],
            "restore_snapshot"
        );
        assert_eq!(delete_body["failures"][0]["id"], plugin_id);
        let error = delete_body["failures"][0]["errors"][0]
            .as_str()
            .expect("structured restore-snapshot error");
        assert!(
            error.contains(expected_error),
            "unexpected failure: {delete_body}"
        );
        assert!(
            error.contains(&proxy_id),
            "proxy evidence missing: {delete_body}"
        );
        assert!(
            store
                .get_api_spec("ferrum", &spec_id)
                .await
                .unwrap()
                .is_some(),
            "pre-delete rejection must preserve the API spec"
        );
        let proxy_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM proxies WHERE namespace = ? AND id = ?")
                .bind("ferrum")
                .bind(&proxy_id)
                .fetch_one(&store.pool())
                .await
                .expect("inspect preserved invalid proxy row");
        assert_eq!(
            proxy_count, 1,
            "pre-delete rejection must preserve the proxy"
        );
    }
}

#[tokio::test]
async fn api_spec_delete_rejects_cascade_plugin_referenced_by_another_proxy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("cross-proxy-cascade-owner");
    let other_proxy_id = uid("cross-proxy-cascade-referrer");
    let plugin_id = uid("cross-proxy-cascade-plugin");

    let (post_status, post_body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
    let spec_id = post_body["id"]
        .as_str()
        .expect("created API spec returns id")
        .to_string();
    let plugin = manual_proxy_plugin(&plugin_id, &proxy_id, "stdout_logging", json!({}));
    attach_manual_proxy_plugin(&store, &proxy_id, &plugin).await;
    store
        .create_proxy(&make_proxy_for_db(
            &other_proxy_id,
            "ferrum",
            &format!("/{other_proxy_id}"),
        ))
        .await
        .expect("create foreign referrer proxy");
    sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)")
        .bind(&other_proxy_id)
        .bind(&plugin_id)
        .execute(&store.pool())
        .await
        .expect("inject cross-proxy plugin association");

    let (delete_status, delete_body) = client.delete_json(&format!("/api-specs/{spec_id}")).await;
    assert_eq!(
        delete_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "cross-proxy cascade association must fail before delete: {delete_body}"
    );
    assert_eq!(delete_body["error"], "Spec validation failed");
    assert_eq!(
        delete_body["failures"][0]["resource_type"],
        "restore_snapshot"
    );
    assert_eq!(delete_body["failures"][0]["id"], plugin_id);
    let error = delete_body["failures"][0]["errors"][0]
        .as_str()
        .expect("structured restore-snapshot error");
    assert!(
        error.contains(&spec_id),
        "spec evidence missing: {delete_body}"
    );
    assert!(
        error.contains(&proxy_id),
        "owner evidence missing: {delete_body}"
    );
    assert!(
        error.contains(&other_proxy_id),
        "foreign referrer evidence missing: {delete_body}"
    );
    let association_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM proxy_plugins WHERE plugin_config_id = ?")
            .bind(&plugin_id)
            .fetch_one(&store.pool())
            .await
            .expect("inspect preserved cross-proxy associations");
    assert_eq!(
        association_count, 2,
        "pre-delete rejection must preserve both associations"
    );
}

#[tokio::test]
async fn api_spec_delete_rejects_owned_global_with_proxy_id_before_persistence() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("malformed-owned-global-proxy");
    let plugin_id = uid("malformed-owned-global-plugin");
    let spec = json_spec_with_plugin(
        &proxy_id,
        "backend.internal",
        &plugin_id,
        "request_transformer",
        request_body_transformer_config(),
    );

    let (post_status, post_body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
    let spec_id = post_body["id"]
        .as_str()
        .expect("created API spec returns id")
        .to_string();
    convert_spec_owned_plugin_to_global(&store, &proxy_id, &plugin_id).await;
    sqlx::query("UPDATE plugin_configs SET proxy_id = ? WHERE namespace = ? AND id = ?")
        .bind(&proxy_id)
        .bind("ferrum")
        .bind(&plugin_id)
        .execute(&store.pool())
        .await
        .expect("inject proxy_id on spec-owned global plugin");

    let (delete_status, delete_body) = client.delete_json(&format!("/api-specs/{spec_id}")).await;
    assert_eq!(
        delete_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "malformed owned global must fail before delete: {delete_body}"
    );
    assert_eq!(delete_body["error"], "Spec validation failed");
    assert_eq!(
        delete_body["failures"][0]["resource_type"],
        "restore_snapshot"
    );
    let error = delete_body["failures"][0]["errors"][0]
        .as_str()
        .expect("structured restore-snapshot error");
    assert!(
        error.contains(&plugin_id),
        "plugin evidence missing: {delete_body}"
    );
    assert!(
        error.contains(&proxy_id),
        "proxy evidence missing: {delete_body}"
    );
    assert!(
        error.contains("global plugin") && error.contains("proxy_id"),
        "malformed scope evidence missing: {delete_body}"
    );
    let plugin_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM plugin_configs WHERE namespace = ? AND id = ? AND api_spec_id = ?",
    )
    .bind("ferrum")
    .bind(&plugin_id)
    .bind(&spec_id)
    .fetch_one(&store.pool())
    .await
    .expect("inspect preserved spec-owned global plugin");
    assert_eq!(
        plugin_count, 1,
        "pre-delete rejection must preserve the malformed owned global"
    );
}

#[test]
fn api_spec_delete_maps_missing_embedded_plugin_association_to_422() {
    let source = include_str!("../../src/admin/api_specs/handlers.rs");
    let association_check = source
        .find("for association in &existing_proxy.plugins {")
        .expect("API-spec delete must inspect embedded proxy associations");
    let restore_snapshot = source[association_check..]
        .find("let previous_bundle = ExtractedBundle")
        .map(|offset| association_check + offset)
        .expect("association validation must precede the restore snapshot");
    let association_check = &source[association_check..restore_snapshot];

    assert!(association_check.contains("Ok(None) =>"));
    assert!(association_check.contains("ApiSpecError::ValidationFailures"));
    assert!(association_check.contains("resource_type: \"plugin_graph\""));
    assert!(association_check.contains("proxy association references missing plugin"));
    assert!(
        !association_check.contains("delete snapshot lost associated plugin"),
        "persistent Mongo embedded-reference corruption must not be reported as a race"
    );
}

#[tokio::test]
async fn api_spec_delete_rejects_foreign_owned_cascade_plugin_without_retagging() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("foreign-owned-cascade-proxy");
    let spec = minimal_json_spec(&proxy_id);

    let (post_status, post_body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
    let spec_id = post_body["id"]
        .as_str()
        .expect("created API spec returns id")
        .to_string();
    let plugin_id = uid("foreign-owned-cascade-plugin");
    let plugin = manual_proxy_plugin(&plugin_id, &proxy_id, "stdout_logging", json!({}));
    attach_manual_proxy_plugin(&store, &proxy_id, &plugin).await;

    let foreign_spec_id = uid("foreign-api-spec-owner");
    sqlx::query("UPDATE plugin_configs SET api_spec_id = ? WHERE namespace = ? AND id = ?")
        .bind(&foreign_spec_id)
        .bind("ferrum")
        .bind(&plugin_id)
        .execute(&store.pool())
        .await
        .expect("inject foreign API-spec ownership");

    let (delete_status, delete_body) = client.delete_json(&format!("/api-specs/{spec_id}")).await;
    assert_eq!(
        delete_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "foreign-owned cascade plugin must block API-spec deletion: {delete_body}"
    );
    assert_eq!(delete_body["error"], "Spec validation failed");
    assert_eq!(
        delete_body["failures"][0]["resource_type"],
        "restore_snapshot"
    );
    assert_eq!(delete_body["failures"][0]["id"], plugin_id);
    let ownership_error = delete_body["failures"][0]["errors"][0]
        .as_str()
        .expect("structured ownership failure");
    assert!(ownership_error.contains(&spec_id));
    assert!(ownership_error.contains(&foreign_spec_id));
    assert!(ownership_error.contains(&plugin_id));
    assert!(
        store
            .get_api_spec("ferrum", &spec_id)
            .await
            .unwrap()
            .is_some(),
        "rejected delete must preserve the API spec"
    );
    assert!(
        store
            .get_proxy("ferrum", &proxy_id)
            .await
            .unwrap()
            .is_some(),
        "rejected delete must preserve the proxy"
    );
    let preserved_plugin = store
        .get_plugin_config("ferrum", &plugin_id)
        .await
        .unwrap()
        .expect("rejected delete must preserve the plugin");
    assert_eq!(
        preserved_plugin.api_spec_id.as_deref(),
        Some(foreign_spec_id.as_str()),
        "rejected delete must not retag foreign ownership"
    );
}

#[tokio::test]
async fn direct_proxy_delete_rejects_foreign_owned_cascade_plugin_without_retagging() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("direct-foreign-plugin-proxy");

    let (post_status, post_body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
    let spec_id = post_body["id"]
        .as_str()
        .expect("created API spec returns id")
        .to_string();
    let plugin_id = uid("direct-foreign-plugin");
    let plugin = manual_proxy_plugin(&plugin_id, &proxy_id, "stdout_logging", json!({}));
    attach_manual_proxy_plugin(&store, &proxy_id, &plugin).await;

    let foreign_spec_id = uid("direct-foreign-plugin-owner");
    sqlx::query("UPDATE plugin_configs SET api_spec_id = ? WHERE namespace = ? AND id = ?")
        .bind(&foreign_spec_id)
        .bind("ferrum")
        .bind(&plugin_id)
        .execute(&store.pool())
        .await
        .expect("inject foreign API-spec ownership");

    let (delete_status, delete_body) = client.delete_json(&format!("/proxies/{proxy_id}")).await;
    assert_eq!(
        delete_status,
        reqwest::StatusCode::BAD_REQUEST,
        "foreign-owned cascade plugin must block direct proxy deletion: {delete_body}"
    );
    let error = delete_body["error"]
        .as_str()
        .expect("direct delete ownership error");
    assert!(error.contains(&proxy_id));
    assert!(error.contains(&plugin_id));
    assert!(error.contains(&spec_id));
    assert!(error.contains(&foreign_spec_id));
    assert!(
        store
            .get_api_spec("ferrum", &spec_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get_proxy("ferrum", &proxy_id)
            .await
            .unwrap()
            .is_some()
    );
    let preserved_plugin = store
        .get_plugin_config("ferrum", &plugin_id)
        .await
        .unwrap()
        .expect("rejected direct delete must preserve plugin");
    assert_eq!(
        preserved_plugin.api_spec_id.as_deref(),
        Some(foreign_spec_id.as_str())
    );
}

#[tokio::test]
async fn direct_proxy_delete_rejects_foreign_upstream_then_allows_hand_owned_graph() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("direct-foreign-upstream-proxy");

    let (post_status, post_body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
    let spec_id = post_body["id"]
        .as_str()
        .expect("created API spec returns id")
        .to_string();

    let upstream_id = uid("direct-hand-upstream");
    let upstream: Upstream = serde_json::from_value(json!({
        "id": upstream_id,
        "namespace": "ferrum",
        "targets": [{"host": "manual.internal", "port": 443}]
    }))
    .expect("hand-owned upstream");
    store
        .create_upstream(&upstream)
        .await
        .expect("create hand-owned upstream");
    let mut drifted_proxy = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get spec proxy")
        .expect("spec proxy exists");
    drifted_proxy.upstream_id = Some(upstream_id.clone());
    store
        .update_proxy(&drifted_proxy)
        .await
        .expect("point proxy at hand-owned upstream");

    let plugin_id = uid("direct-hand-plugin");
    let plugin = manual_proxy_plugin(&plugin_id, &proxy_id, "stdout_logging", json!({}));
    attach_manual_proxy_plugin(&store, &proxy_id, &plugin).await;

    let foreign_spec_id = uid("direct-foreign-upstream-owner");
    sqlx::query("UPDATE upstreams SET api_spec_id = ? WHERE namespace = ? AND id = ?")
        .bind(&foreign_spec_id)
        .bind("ferrum")
        .bind(&upstream_id)
        .execute(&store.pool())
        .await
        .expect("inject foreign upstream ownership");

    let (rejected_status, rejected_body) =
        client.delete_json(&format!("/proxies/{proxy_id}")).await;
    assert_eq!(
        rejected_status,
        reqwest::StatusCode::BAD_REQUEST,
        "foreign-owned upstream must block direct proxy deletion: {rejected_body}"
    );
    let error = rejected_body["error"]
        .as_str()
        .expect("direct delete upstream ownership error");
    assert!(error.contains(&proxy_id));
    assert!(error.contains(&upstream_id));
    assert!(error.contains(&spec_id));
    assert!(error.contains(&foreign_spec_id));
    assert!(
        store
            .get_api_spec("ferrum", &spec_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get_proxy("ferrum", &proxy_id)
            .await
            .unwrap()
            .is_some()
    );

    sqlx::query("UPDATE upstreams SET api_spec_id = NULL WHERE namespace = ? AND id = ?")
        .bind("ferrum")
        .bind(&upstream_id)
        .execute(&store.pool())
        .await
        .expect("restore hand-owned upstream shape");

    let (delete_status, delete_body) = client.delete_json(&format!("/proxies/{proxy_id}")).await;
    assert_eq!(
        delete_status,
        reqwest::StatusCode::NO_CONTENT,
        "legitimate hand-owned upstream and plugin must pass direct delete preflight: {delete_body}"
    );
    assert!(
        store
            .get_api_spec("ferrum", &spec_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_proxy("ferrum", &proxy_id)
            .await
            .unwrap()
            .is_none()
    );
    let preserved_upstream = store
        .get_upstream("ferrum", &upstream_id)
        .await
        .unwrap()
        .expect("hand-owned upstream must survive proxy deletion");
    assert!(preserved_upstream.api_spec_id.is_none());
}

#[tokio::test]
async fn post_rejects_hmac_request_body_transformer_composition() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("hmac-transform-proxy");
    let hmac_id = uid("hmac-plugin");
    let transformer_id = uid("body-transformer");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "HMAC composition", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        },
        "x-ferrum-plugins": [
            {
                "id": hmac_id,
                "plugin_name": "hmac_auth",
                "config": {"clock_skew_seconds": 300}
            },
            {
                "id": transformer_id,
                "plugin_name": "request_transformer",
                "config": {"rules": [{
                    "operation": "add",
                    "target": "body",
                    "key": "gateway",
                    "value": "ferrum"
                }]}
            }
        ]
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;

    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "unsafe API-spec plugin bundle was admitted: {body}"
    );
    let composition_failure = body["failures"]
        .as_array()
        .and_then(|failures| {
            failures
                .iter()
                .find(|failure| failure["resource_type"] == "plugin_composition")
        })
        .unwrap_or_else(|| panic!("missing plugin composition failure: {body}"));
    assert!(
        composition_failure["errors"]
            .to_string()
            .contains("hmac_auth cannot be combined with request-body transformer"),
        "unexpected composition failure: {composition_failure}"
    );
}

#[tokio::test]
async fn post_mtls_dns_policy_conflict_returns_409() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let mut upper = Consumer {
        id: uid("mtls-upper"),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: uid("mtls-upper-user"),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    upper.credentials.insert(
        "mtls_auth".to_string(),
        json!([{"identity": "API.Example.COM"}]),
    );
    let mut lower = upper.clone();
    lower.id = uid("mtls-lower");
    lower.username = uid("mtls-lower-user");
    lower.credentials.insert(
        "mtls_auth".to_string(),
        json!([{"identity": "api.example.com"}]),
    );
    store
        .create_consumer(&upper)
        .await
        .expect("create exact-case upper identity");
    store
        .create_consumer(&lower)
        .await
        .expect("create exact-case lower identity before DNS policy activation");

    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("mtls-dns-conflict-proxy");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "mTLS DNS conflict", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        },
        "x-ferrum-plugins": [{
            "id": uid("mtls-dns-policy"),
            "plugin_name": "mtls_auth",
            "config": {"cert_field": "san_dns"}
        }]
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::CONFLICT,
        "mTLS DNS candidate conflict must use the documented 409 response: {body}"
    );
}

#[tokio::test]
async fn put_excludes_removed_spec_owned_global_hmac_before_adding_body_transformer() {
    assert_put_replaces_removed_spec_owned_global(
        "hmac_auth",
        hmac_plugin_config(),
        "request_transformer",
        request_body_transformer_config(),
    )
    .await;
}

#[tokio::test]
async fn put_excludes_removed_spec_owned_global_body_transformer_before_adding_hmac() {
    assert_put_replaces_removed_spec_owned_global(
        "request_transformer",
        request_body_transformer_config(),
        "hmac_auth",
        hmac_plugin_config(),
    )
    .await;
}

#[tokio::test]
async fn put_rejects_body_transformer_beside_preserved_manual_hmac_association() {
    assert_put_rejects_preserved_manual_association(
        "hmac_auth",
        hmac_plugin_config(),
        "request_transformer",
        request_body_transformer_config(),
    )
    .await;
}

#[tokio::test]
async fn put_rejects_hmac_beside_preserved_manual_body_transformer_association() {
    assert_put_rejects_preserved_manual_association(
        "request_transformer",
        request_body_transformer_config(),
        "hmac_auth",
        hmac_plugin_config(),
    )
    .await;
}

#[tokio::test]
async fn put_rejects_same_id_overlay_of_manual_hmac_plugin_without_mutation() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);
    let proxy_id = uid("same-id-manual-proxy");
    let manual_plugin_id = uid("same-id-manual-hmac");
    let (post_status, post_body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "initial API spec failed: {post_body}"
    );
    let spec_id = post_body["id"]
        .as_str()
        .expect("POST response must include spec id")
        .to_string();
    let manual_plugin = manual_proxy_plugin(
        &manual_plugin_id,
        &proxy_id,
        "hmac_auth",
        hmac_plugin_config(),
    );
    attach_manual_proxy_plugin(&store, &proxy_id, &manual_plugin).await;

    let spec_before = store
        .get_api_spec("ferrum", &spec_id)
        .await
        .expect("read API spec before rejected PUT")
        .expect("API spec must exist before rejected PUT");
    let proxy_before = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("read proxy before rejected PUT")
        .expect("proxy must exist before rejected PUT");
    let replacement_spec = json_spec_with_plugin(
        &proxy_id,
        "replacement-backend.internal",
        &manual_plugin_id,
        "request_transformer",
        request_body_transformer_config(),
    );
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &replacement_spec)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "same-ID manual plugin overlay was not rejected during validation: {put_body}"
    );
    assert!(
        put_body
            .to_string()
            .contains("replacement cannot take ownership"),
        "same-ID rejection must identify the ownership conflict: {put_body}"
    );

    let spec_after = store
        .get_api_spec("ferrum", &spec_id)
        .await
        .expect("read API spec after rejected PUT")
        .expect("API spec must survive rejected PUT");
    assert_eq!(spec_after.content_hash, spec_before.content_hash);
    assert_eq!(spec_after.resource_hash, spec_before.resource_hash);
    assert_eq!(spec_after.updated_at, spec_before.updated_at);
    let proxy_after = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("read proxy after rejected PUT")
        .expect("proxy must survive rejected PUT");
    assert_eq!(proxy_after.backend_host, proxy_before.backend_host);
    assert_eq!(proxy_after.updated_at, proxy_before.updated_at);
    assert!(
        proxy_after
            .plugins
            .iter()
            .any(|association| association.plugin_config_id == manual_plugin_id),
        "rejected PUT must retain the manual plugin association"
    );
    let manual_after = store
        .get_plugin_config("ferrum", &manual_plugin_id)
        .await
        .expect("read manual plugin after rejected PUT")
        .expect("manual plugin must survive rejected PUT");
    assert_eq!(manual_after.plugin_name, "hmac_auth");
    assert_eq!(manual_after.config, manual_plugin.config);
    assert!(manual_after.api_spec_id.is_none());

    let runtime_config = store
        .load_full_config("ferrum")
        .await
        .expect("rejected replacement must leave the prior runtime config loadable");
    assert!(
        runtime_config
            .plugin_configs
            .iter()
            .any(|plugin| plugin.id == manual_plugin_id && plugin.plugin_name == "hmac_auth"),
        "prior runtime config lost or replaced the manual HMAC plugin"
    );
}

#[tokio::test]
async fn disabled_basic_auth_spec_can_be_staged_before_plugin_construction() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let mut spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Disabled Basic auth staging", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        },
        "x-ferrum-plugins": [{
            "id": uid("basic-auth"),
            "plugin_name": "basic_auth",
            "enabled": false,
            // This unsupported field makes construction fail independently of
            // the process environment, so successful staging proves that the
            // disabled import path did not construct the plugin.
            "config": {"realm": "staged-but-unused"}
        }]
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "disabled Basic auth config should be stageable: {body}"
    );

    let spec_id = body["id"].as_str().expect("created spec id");
    spec["x-ferrum-plugins"][0]["enabled"] = json!(true);
    let (status, body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec)
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "enabling must perform plugin construction and fail closed: {body}"
    );
    assert!(body["failures"].as_array().is_some_and(|failures| {
        failures
            .iter()
            .any(|failure| failure["resource_type"] == "plugin")
    }));
}

// ============================================================================
// Gap #3: Multiple validation failures aggregated in one 422
// ============================================================================

/// A spec with both an invalid proxy field AND a failing plugin config must
/// return a single 422 whose `failures` array has at least two entries: one
/// with `resource_type: "proxy"` and one with `resource_type: "plugin"`.
#[tokio::test]
async fn post_with_multiple_validation_errors_returns_all_failures() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    // Invalid proxy: `listen_port` on an HTTP proxy is rejected.
    // Invalid plugin: `rate_limiting` with empty config.
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "listen_port": 9090
        },
        "x-ferrum-plugins": [{
            "id": "bad-rl",
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "config": {}
        }]
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 422 for multiple validation errors; body: {body}"
    );

    let failures = body["failures"].as_array().expect("failures must be array");
    assert!(
        failures.len() >= 2,
        "expected at least 2 failures (proxy + plugin), got {}; body: {body}",
        failures.len()
    );

    let has_proxy_failure = failures
        .iter()
        .any(|f| f["resource_type"].as_str() == Some("proxy"));
    assert!(has_proxy_failure, "must have a proxy failure; body: {body}");

    let has_plugin_failure = failures
        .iter()
        .any(|f| f["resource_type"].as_str() == Some("plugin"));
    assert!(
        has_plugin_failure,
        "must have a plugin failure; body: {body}"
    );
}

// ============================================================================
// Gap #5: PUT preserves created_at, advances updated_at
// ============================================================================

/// After a PUT, the spec's `created_at` must be unchanged while `updated_at`
/// must be strictly later than `created_at` (or at least as late, accounting
/// for sub-millisecond clocks on fast machines).
///
/// The list endpoint returns both timestamps; we compare them there.
#[tokio::test]
async fn put_preserves_created_at_advances_updated_at() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");

    // POST the initial spec.
    let (post_status, post_body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    // Capture created_at from the list endpoint.
    let (list_status, list_body) = client.get_json("/api-specs").await;
    assert_eq!(list_status, reqwest::StatusCode::OK);
    let items = list_body["items"].as_array().unwrap();
    let item = items
        .iter()
        .find(|i| i["id"].as_str() == Some(&spec_id))
        .expect("spec must appear in list");
    let created_at_str = item["created_at"]
        .as_str()
        .expect("created_at must be a string");
    let created_at: chrono::DateTime<chrono::Utc> = created_at_str
        .parse()
        .expect("created_at must parse as RFC3339");

    // Sleep a little to ensure the clock advances.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // PUT a replacement spec.
    let updated_spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Updated API", "version": "2.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "new-backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        }
    });
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &updated_spec)
        .await;
    assert_eq!(put_status, reqwest::StatusCode::OK, "{put_body}");

    // Re-fetch from list and compare timestamps.
    let (list2_status, list2_body) = client.get_json("/api-specs").await;
    assert_eq!(list2_status, reqwest::StatusCode::OK);
    let items2 = list2_body["items"].as_array().unwrap();
    let item2 = items2
        .iter()
        .find(|i| i["id"].as_str() == Some(&spec_id))
        .expect("spec must still appear in list after PUT");

    let created_at_after_str = item2["created_at"]
        .as_str()
        .expect("created_at must still be a string after PUT");
    let updated_at_str = item2["updated_at"]
        .as_str()
        .expect("updated_at must be a string after PUT");
    let updated_at: chrono::DateTime<chrono::Utc> = updated_at_str
        .parse()
        .expect("updated_at must parse as RFC3339");

    // created_at must be identical (as a string, before any timezone
    // normalization differences, compare the parsed timestamps).
    let created_at_after: chrono::DateTime<chrono::Utc> = created_at_after_str
        .parse()
        .expect("created_at after PUT must parse as RFC3339");
    assert_eq!(
        created_at, created_at_after,
        "created_at must be unchanged after PUT"
    );

    // updated_at must be >= created_at (on a fast machine they could be equal
    // if the DB clock has coarse granularity, but it must not go backward).
    assert!(
        updated_at >= created_at,
        "updated_at ({updated_at}) must be >= created_at ({created_at}) after PUT"
    );
}

// ============================================================================
// Gap #6: File-mode write rejection (read_only = true)
// ============================================================================

/// When `AdminState.read_only = true` (file mode), POST/PUT/DELETE must return
/// 403 with `{"error": "Admin API is in read-only mode"}`.
#[tokio::test]
async fn post_in_read_only_mode_returns_403() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    // Build read-only state (mirroring file mode).
    let mut state = make_admin_state(store, 25);
    state.read_only = true;

    let (base, _shutdown) = start_admin(state).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let (status, body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;

    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "POST in read-only mode must return 403; body: {body}"
    );
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "Admin API is in read-only mode",
        "error message must match; body: {body}"
    );
}

#[tokio::test]
async fn put_in_read_only_mode_returns_403() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let mut state = make_admin_state(store, 25);
    state.read_only = true;

    let (base, _shutdown) = start_admin(state).await;
    let client = AdminClient::new(base);

    let (status, body) = client
        .put_json("/api-specs/any-id", &minimal_json_spec("some-proxy"))
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "PUT in read-only mode must return 403; body: {body}"
    );
}

#[tokio::test]
async fn delete_in_read_only_mode_returns_403() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let mut state = make_admin_state(store, 25);
    state.read_only = true;

    let (base, _shutdown) = start_admin(state).await;
    let client = AdminClient::new(base);

    let status = client.delete("/api-specs/any-id").await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "DELETE in read-only mode must return 403"
    );
}

// ============================================================================
// Gap #7: PUT/DELETE without JWT returns 401
// ============================================================================

#[tokio::test]
async fn unauthenticated_put_returns_401() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;

    let client = reqwest::Client::new();
    let status = client
        .put(format!("{}/api-specs/some-id", base))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unauthenticated_delete_returns_401() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;

    let client = reqwest::Client::new();
    let status = client
        .delete(format!("{}/api-specs/some-id", base))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
}

// ============================================================================
// Gap #8: POST spec conflicts with a hand-created proxy
// ============================================================================

/// When a proxy is created directly in the DB with the same listen_path as the
/// spec being submitted, the validation step (`check_listen_path_unique`) detects
/// the conflict and returns 422 (or the DB INSERT returns 409 if the proxy_id
/// also matches).  Either rejection is acceptable.
#[tokio::test]
async fn post_spec_conflicts_with_hand_created_proxy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    // Insert a proxy directly — same listen_path as the spec we'll submit.
    let conflict_id = uid("conflict-proxy");
    let hand_proxy = make_proxy_for_db(&conflict_id, "ferrum", &format!("/{conflict_id}"));
    store
        .create_proxy(&hand_proxy)
        .await
        .expect("hand-create proxy failed");

    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // Submit a spec that uses the same listen_path → conflict.
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": uid("new-proxy"),
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{conflict_id}")
        }
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert!(
        status == reqwest::StatusCode::CONFLICT
            || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 409 or 422 when listen_path conflicts with hand-created proxy; \
         got {status}; body: {body}"
    );
}

// ============================================================================
// Gap #9: DELETE-then-POST same proxy_id succeeds
// ============================================================================

/// Deleting a spec and then re-submitting a spec for the same proxy_id must
/// succeed (201).  The proxy uniqueness constraint applies to live rows only.
#[tokio::test]
async fn delete_then_post_same_proxy_id_succeeds() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("reuse-proxy");
    let spec = minimal_json_spec(&proxy_id);

    // First POST.
    let (s1, b1) = client.post_json("/api-specs", &spec).await;
    assert_eq!(s1, reqwest::StatusCode::CREATED, "first POST failed: {b1}");
    let spec_id = b1["id"].as_str().unwrap().to_string();

    // DELETE.
    let del_status = client.delete(&format!("/api-specs/{spec_id}")).await;
    assert_eq!(del_status, reqwest::StatusCode::NO_CONTENT);

    // Second POST with the same proxy_id — must succeed.
    let (s2, b2) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        s2,
        reqwest::StatusCode::CREATED,
        "second POST after delete must succeed (201); body: {b2}"
    );
}

// ============================================================================
// Gap #10: Pathological inputs handled gracefully
// ============================================================================

/// Three sub-cases: empty body, missing version field, deeply nested YAML.
/// None of them should return 500 or crash the server.
#[tokio::test]
async fn post_pathological_inputs_handled_gracefully() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // Sub-case 1: completely empty body.
    let (status_empty, _) = client
        .post_raw("/api-specs", vec![], "application/json")
        .await;
    assert_ne!(
        status_empty,
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "empty body must not cause 500"
    );
    assert!(
        status_empty.is_client_error(),
        "empty body must return a 4xx error, got {status_empty}"
    );

    // Sub-case 2: body that parses but has no version field.
    // The extractor looks for "openapi" / "swagger" keys to determine the version.
    let no_version = serde_json::json!({
        "info": {"title": "No Version", "version": "1.0"},
        "x-ferrum-proxy": {
            "id": "no-version-proxy",
            "backend_host": "b.internal",
            "backend_port": 443,
            "listen_path": "/no-version"
        }
    });
    let (status_no_ver, body_no_ver) = client
        .post_raw(
            "/api-specs",
            serde_json::to_vec(&no_version).unwrap(),
            "application/json",
        )
        .await;
    assert_ne!(
        status_no_ver,
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "missing version field must not cause 500; body: {body_no_ver}"
    );
    // The extractor should return UnknownVersion → 400.
    assert_eq!(
        status_no_ver,
        reqwest::StatusCode::BAD_REQUEST,
        "missing openapi/swagger field must return 400; body: {body_no_ver}"
    );

    // Sub-case 3: deeply nested YAML (200 levels) — must not crash.
    let deep_yaml = {
        let mut s = String::from("a:\n");
        for _ in 0..200 {
            s.push_str("  a:\n");
        }
        s
    };
    // Wrap it as a spec-shaped document to give the parser something to work
    // with.  Even if serde_yaml parses it, the extractor will reject it for
    // missing fields.
    let (status_deep, _) = client.post_yaml("/api-specs", &deep_yaml).await;
    assert_ne!(
        status_deep,
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "deeply nested YAML must not cause 500 (no panic / DoS)"
    );
}

// ============================================================================
// Wave 5 — list filters, sort, metadata in summary, idempotent PUT
// ============================================================================

/// Minimal spec builder with all Tier 1 metadata fields populated.
fn full_spec_json(proxy_id: &str, title: &str, tag: &str, spec_version: &str) -> Value {
    json!({
        "openapi": spec_version,
        "info": {
            "title": title,
            "version": "1.0.0",
            "description": format!("Description for {title}"),
            "contact": { "name": "Bob", "email": "bob@example.com" },
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" }
        },
        "tags": [{"name": tag}],
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/items": { "get": {}, "post": {} }
        },
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        }
    })
}

/// `GET /api-specs` with ?proxy_id, ?spec_version, and ?sort_by filters works.
#[tokio::test]
async fn list_endpoint_accepts_query_filters() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // POST three specs: two 3.1.x, one 3.0.x.
    let proxy_a = uid("proxy-a");
    let proxy_b = uid("proxy-b");
    let proxy_c = uid("proxy-c");

    client
        .post_json(
            "/api-specs",
            &full_spec_json(&proxy_a, "Alpha", "v3", "3.1.0"),
        )
        .await;
    client
        .post_json(
            "/api-specs",
            &full_spec_json(&proxy_b, "Beta", "v3", "3.1.0"),
        )
        .await;
    client
        .post_json(
            "/api-specs",
            &full_spec_json(&proxy_c, "Gamma", "v3", "3.0.3"),
        )
        .await;

    // Filter by proxy_id.
    let (status, body) = client
        .get_json(&format!("/api-specs?proxy_id={proxy_a}"))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "proxy_id filter: {body}");
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "proxy_id filter must return 1 item");
    assert_eq!(items[0]["proxy_id"].as_str().unwrap(), proxy_a);

    // Filter by spec_version prefix.
    let (status2, body2) = client.get_json("/api-specs?spec_version=3.1").await;
    assert_eq!(
        status2,
        reqwest::StatusCode::OK,
        "spec_version filter: {body2}"
    );
    let items2 = body2["items"].as_array().unwrap();
    assert_eq!(items2.len(), 2, "spec_version=3.1 must return 2 items");

    // Sort by title asc.
    let (status3, body3) = client.get_json("/api-specs?sort_by=title&order=asc").await;
    assert_eq!(status3, reqwest::StatusCode::OK, "sort: {body3}");
    let items3 = body3["items"].as_array().unwrap();
    // Alpha < Beta < Gamma
    if items3.len() >= 2 {
        let titles: Vec<_> = items3.iter().filter_map(|i| i["title"].as_str()).collect();
        assert!(
            titles.windows(2).all(|w| w[0] <= w[1]),
            "titles must be ascending: {titles:?}"
        );
    }
}

/// `?sort_by=DROP_TABLE` returns 400.
#[tokio::test]
async fn list_endpoint_invalid_sort_by_returns_400() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let (status, body) = client.get_json("/api-specs?sort_by=DROP_TABLE").await;
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "invalid sort_by must return 400: {body}"
    );
}

/// `?order=INVALID` returns 400.
#[tokio::test]
async fn list_endpoint_invalid_order_returns_400() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let (status, body) = client.get_json("/api-specs?order=INVALID").await;
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "invalid order must return 400: {body}"
    );
}

/// Malformed `limit`/`offset` return 400 rather than being silently coerced to
/// the endpoint default. `/api-specs` keeps its own stricter bounds (default
/// 50, max 200) but shares the rejection contract of every other list endpoint.
#[tokio::test]
async fn list_endpoint_malformed_pagination_returns_400() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    for (query, expected_message) in [
        (
            "/api-specs?limit=abc",
            "limit must be a non-negative integer",
        ),
        (
            "/api-specs?limit=-1",
            "limit must be a non-negative integer",
        ),
        (
            "/api-specs?limit=1.5",
            "limit must be a non-negative integer",
        ),
        (
            "/api-specs?offset=abc",
            "offset must be a non-negative integer",
        ),
        (
            "/api-specs?offset=-1",
            "offset must be a non-negative integer",
        ),
        // Above u32::MAX: this endpoint's offset is a 32-bit value.
        (
            "/api-specs?offset=4294967296",
            "offset exceeds the maximum supported value",
        ),
        // Percent-encoding the key must not bypass the same narrower ceiling.
        (
            "/api-specs?%6fffset=4294967296",
            "offset exceeds the maximum supported value",
        ),
        // One past u64::MAX cannot be represented by the coercion parser.
        (
            "/api-specs?limit=18446744073709551616",
            "limit exceeds the maximum supported value",
        ),
    ] {
        let (status, body) = client.get_json(query).await;
        assert_eq!(
            status,
            reqwest::StatusCode::BAD_REQUEST,
            "{query} must be rejected with 400, not coerced: {body}"
        );
        assert_eq!(body["error"], expected_message, "wrong error for {query}");
    }
}

/// Unknown query parameters stay ignored even when their *name* or their
/// *value* cannot be percent-decoded to valid UTF-8. An undecodable name cannot
/// alias any recognized ASCII filter, so it is unknown; and because the name is
/// matched before the value is decoded, an ignored parameter's value is never
/// decoded at all. Neither may fail an otherwise valid request — clients
/// routinely append unrelated parameters. Recognized filters stay strict.
#[tokio::test]
async fn list_endpoint_ignores_undecodable_unknown_query_keys() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // %80 is a bare UTF-8 continuation byte: an undecodable, unrecognized name.
    let (status, body) = client.get_json("/api-specs?%80=1").await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "undecodable unknown key must be ignored, not rejected: {body}"
    );
    assert_eq!(body["limit"], 50, "endpoint default still applies: {body}");

    // An ignored key must not disturb the recognized parameters beside it.
    let (status, body) = client.get_json("/api-specs?%80=1&limit=7").await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");
    assert_eq!(body["limit"], 7, "sibling recognized key still parsed");

    // The *value* of an ignored key is never decoded, so an undecodable value
    // on an ignored name cannot fail the request either. Both orderings are
    // asserted: whether the ignored pair precedes or follows a recognized one
    // must not change the outcome.
    for query in [
        // Undecodable name AND undecodable value.
        "/api-specs?%80=%80",
        // Decodable but unrecognized name with an undecodable value — clients
        // routinely append third-party parameters carrying arbitrary bytes.
        "/api-specs?tracking_id=%80",
        "/api-specs?%80=%80&limit=7",
        "/api-specs?limit=7&%80=%80",
        "/api-specs?limit=7&tracking_id=%80",
    ] {
        let (status, body) = client.get_json(query).await;
        assert_eq!(
            status,
            reqwest::StatusCode::OK,
            "{query}: an ignored key must never be rejected on its value: {body}"
        );
    }

    // ...and the recognized sibling is still applied in either order.
    for query in ["/api-specs?%80=%80&limit=7", "/api-specs?limit=7&%80=%80"] {
        let (_, body) = client.get_json(query).await;
        assert_eq!(body["limit"], 7, "{query}: recognized sibling still parsed");
    }

    // Every recognized name stays strict on an undecodable value; ignoring a
    // value must never extend to a filter that is actually consumed.
    for query in [
        "/api-specs?offset=%80",
        "/api-specs?proxy_id=%80",
        "/api-specs?spec_version=%80",
        "/api-specs?title_contains=%80",
        "/api-specs?updated_since=%80",
        "/api-specs?has_tag=%80",
        "/api-specs?sort_by=%80",
        "/api-specs?order=%80",
    ] {
        let (status, body) = client.get_json(query).await;
        assert_eq!(
            status,
            reqwest::StatusCode::BAD_REQUEST,
            "{query}: recognized keys keep strict value decoding: {body}"
        );
    }

    // Recognized keys stay strict: a malformed *value* is still a 400, and an
    // encoded name that DOES decode to a recognized key is still bound-checked
    // (the `%6fffset` alias asserted in the 400 test above).
    let (status, body) = client.get_json("/api-specs?limit=%80").await;
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "recognized key with undecodable value must still be rejected: {body}"
    );
}

/// `limit=0` means the endpoint default (50) and an over-max limit caps at 200,
/// mirroring the shared parser's semantics at this endpoint's own bounds.
#[tokio::test]
async fn list_endpoint_limit_zero_and_over_max_are_bounded() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let (status, body) = client.get_json("/api-specs?limit=0").await;
    assert_eq!(status, reqwest::StatusCode::OK, "limit=0 body: {body}");
    assert_eq!(body["limit"], 50, "limit=0 means the server default");

    let (status, body) = client.get_json("/api-specs?limit=100000").await;
    assert_eq!(status, reqwest::StatusCode::OK, "over-max body: {body}");
    assert_eq!(body["limit"], 200, "over-max limit caps at 200");

    let (status, body) = client
        .get_json("/api-specs?limit=9223372036854775808")
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "u64 limit body: {body}");
    assert_eq!(body["limit"], 200, "any representable over-max limit caps");
}

/// The list summary includes Tier 1 metadata fields but excludes resource_hash.
#[tokio::test]
async fn list_summary_includes_tier1_metadata_excludes_resource_hash() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let (status, post_body) = client
        .post_json(
            "/api-specs",
            &full_spec_json(&proxy_id, "Products API", "products", "3.1.0"),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "POST: {post_body}");

    let (list_status, list_body) = client.get_json("/api-specs").await;
    assert_eq!(list_status, reqwest::StatusCode::OK, "list: {list_body}");

    let items = list_body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "list must have at least one item");
    let item = &items[0];

    // Must have Tier 1 fields.
    assert!(
        item.get("description").is_some(),
        "description must be present"
    );
    assert!(
        item.get("contact_name").is_some(),
        "contact_name must be present"
    );
    assert!(
        item.get("contact_email").is_some(),
        "contact_email must be present"
    );
    assert!(
        item.get("license_name").is_some(),
        "license_name must be present"
    );
    assert!(
        item.get("license_identifier").is_some(),
        "license_identifier must be present"
    );
    assert!(item.get("tags").is_some(), "tags must be present");
    assert!(
        item.get("server_urls").is_some(),
        "server_urls must be present"
    );
    assert!(
        item.get("operation_count").is_some(),
        "operation_count must be present"
    );

    // operation_count: /items has get+post = 2.
    assert_eq!(item["operation_count"].as_u64().unwrap_or(0), 2);

    // Must NOT expose resource_hash (internal implementation detail).
    assert!(
        item.get("resource_hash").is_none(),
        "resource_hash must NOT appear in list summary"
    );
}

/// PUT with the same proxy bundle does not bump proxy.updated_at (handler-level smoke test).
#[tokio::test]
async fn put_with_unchanged_resources_does_not_bump_proxy_updated_at() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let db_arc = std::sync::Arc::new(store.clone());

    // We need direct DB access to check proxy.updated_at, so we hold onto the store.
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let spec_body = full_spec_json(&proxy_id, "Stable API", "stable", "3.1.0");

    // POST → get the spec id.
    let (post_status, post_resp) = client.post_json("/api-specs", &spec_body).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "POST: {post_resp}"
    );
    let spec_id = post_resp["id"].as_str().expect("id").to_string();

    // Read proxy.updated_at before PUT.
    let proxy_before = db_arc
        .get_proxy("ferrum", &proxy_id)
        .await
        .unwrap()
        .unwrap();
    let before_ts = proxy_before.updated_at;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // PUT with exactly the same body (same bundle → same resource_hash).
    let (put_status, put_resp) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_body)
        .await;
    assert_eq!(put_status, reqwest::StatusCode::OK, "PUT: {put_resp}");

    // proxy.updated_at must NOT have advanced.
    let proxy_after = db_arc
        .get_proxy("ferrum", &proxy_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        proxy_after.updated_at.timestamp(),
        before_ts.timestamp(),
        "proxy.updated_at must not advance when bundle is unchanged (idempotent PUT)"
    );
}

// ============================================================================
// Fix 4 — ID validation / UUID generation (PR review)
// ============================================================================

/// A spec submitted with `"id": ""` on x-ferrum-proxy must succeed (201) and
/// the handler assigns a valid UUID for the proxy_id.
#[tokio::test]
async fn post_with_empty_proxy_id_assigns_uuid() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let spec = serde_json::json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": "",
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": "/empty-id-path"
        }
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "body: {body}");

    // The returned proxy_id must be a valid non-empty UUID.
    let proxy_id = body["proxy_id"]
        .as_str()
        .expect("proxy_id must be a string");
    assert!(!proxy_id.is_empty(), "proxy_id must be non-empty");
    assert!(
        uuid::Uuid::parse_str(proxy_id).is_ok(),
        "proxy_id must be a valid UUID when spec omits id; got: {proxy_id}"
    );
}

/// A spec with an invalid plugin id (contains spaces and special chars) must
/// return 400 with a MalformedExtension error code.
///
/// Note: ID validation was moved into the extractor (Fix 1) so that UUIDs are
/// generated before auto-linking. Invalid IDs now surface as
/// ExtractError::MalformedExtension → 400 "Spec parse failed", which is a
/// more appropriate status than 422 (the resource is malformed, not unprocessable).
#[tokio::test]
async fn post_with_invalid_plugin_id_returns_400() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let spec = serde_json::json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        },
        "x-ferrum-plugins": [{
            "id": "has spaces and !@#",
            "plugin_name": "cors",
            "scope": "proxy",
            "config": {"allowed_origins": ["*"]}
        }]
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "invalid plugin id must return 400 (MalformedExtension from extractor); body: {body}"
    );
    assert_eq!(
        body["code"].as_str(),
        Some("MalformedExtension"),
        "error code must be MalformedExtension; body: {body}"
    );
}

// ============================================================================
// Fix 6 — PUT enforces same proxy_id rule (PR review)
// ============================================================================

/// PUT with a spec whose x-ferrum-proxy.id differs from the existing spec's
/// proxy_id must return 422 with a proxy failure entry.
#[tokio::test]
async fn put_with_different_proxy_id_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // POST a spec for proxy A.
    let proxy_a = uid("proxy-a");
    let (post_status, post_body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_a))
        .await;
    assert_eq!(post_status, reqwest::StatusCode::CREATED, "{post_body}");
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    // PUT with x-ferrum-proxy.id = proxy B (different from proxy A).
    let proxy_b = uid("proxy-b");
    let (put_status, put_body) = client
        .put_json(
            &format!("/api-specs/{spec_id}"),
            &minimal_json_spec(&proxy_b),
        )
        .await;

    assert_eq!(
        put_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "PUT with different proxy_id must return 422; body: {put_body}"
    );
    let failures = put_body["failures"].as_array().expect("failures array");
    let proxy_failure = failures
        .iter()
        .find(|f| f["resource_type"].as_str() == Some("proxy"))
        .unwrap_or_else(|| panic!("expected a proxy failure; body: {put_body}"));
    assert!(
        proxy_failure["errors"]
            .as_array()
            .map(|e| !e.is_empty())
            .unwrap_or(false),
        "proxy failure must have error messages; body: {put_body}"
    );
}

// ============================================================================
// Fix 7 — Upstream name uniqueness check uses name not id (PR review)
// ============================================================================

/// Two specs with upstreams that share the same NAME but have different IDs
/// must trigger a conflict on the second submit.
#[tokio::test]
async fn post_two_specs_with_same_upstream_name_different_ids_returns_conflict() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let shared_name = format!("shared-upstream-{}", uid("name"));

    // First spec: upstream with shared_name.
    let proxy_a = uid("proxy-a");
    let upstream_a = uid("upstream-a");
    let spec_a = serde_json::json!({
        "openapi": "3.1.0",
        "info": {"title": "Spec A", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_a,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_a}")
        },
        "x-ferrum-upstream": {
            "id": upstream_a,
            "name": shared_name,
            "targets": [{"host": "target.internal", "port": 443}]
        }
    });
    let (s1, b1) = client.post_json("/api-specs", &spec_a).await;
    assert_eq!(
        s1,
        reqwest::StatusCode::CREATED,
        "first spec must succeed; body: {b1}"
    );

    // Second spec: different upstream id but same name → conflict.
    let proxy_b = uid("proxy-b");
    let upstream_b = uid("upstream-b");
    let spec_b = serde_json::json!({
        "openapi": "3.1.0",
        "info": {"title": "Spec B", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_b,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_b}")
        },
        "x-ferrum-upstream": {
            "id": upstream_b,
            "name": shared_name,
            "targets": [{"host": "target.internal", "port": 443}]
        }
    });
    let (s2, b2) = client.post_json("/api-specs", &spec_b).await;
    assert!(
        s2 == reqwest::StatusCode::CONFLICT || s2 == reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "second spec with duplicate upstream name must return 409 or 422; got {s2}; body: {b2}"
    );
}

// ---------------------------------------------------------------------------
// Fix 4: PUT with same upstream name must not self-collide (409)
// ---------------------------------------------------------------------------

/// POST a spec that includes an upstream named "my-upstream". Then PUT the
/// same spec (same proxy_id, same upstream name). Without Fix 4, the
/// check_upstream_name_unique call on the PUT path returns false (the spec
/// collides with its own existing upstream row), producing a 422/409. With
/// the fix, the existing upstream_id is excluded from the uniqueness check
/// and the PUT returns 200.
#[tokio::test]
async fn put_keeps_same_upstream_name_succeeds() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let state = make_admin_state(store, 10);
    let (base, _shutdown) = start_admin(state).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let upstream_id = uid("upstream");
    let shared_upstream_name = uid("shared-upstream");
    let listen_path = format!("/{proxy_id}");

    // POST: initial spec with an upstream.
    let spec_v1 = json!({
        "openapi": "3.1.0",
        "info": {"title": "PUT same upstream test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-upstream": {
            "id": upstream_id,
            "name": shared_upstream_name,
            "targets": [{"host": "target.internal", "port": 443}]
        }
    });

    let (s1, b1) = client.post_json("/api-specs", &spec_v1).await;
    assert_eq!(
        s1,
        reqwest::StatusCode::CREATED,
        "POST must succeed; body: {b1}"
    );
    let spec_id = b1["id"]
        .as_str()
        .expect("response must include id")
        .to_string();

    // PUT: same proxy + same upstream name (same upstream_id).
    // This is the normal "re-submit without changing anything meaningful" case.
    let spec_v2 = json!({
        "openapi": "3.1.0",
        "info": {"title": "PUT same upstream test v2", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-upstream": {
            "id": upstream_id,
            "name": shared_upstream_name,
            "targets": [{"host": "target-v2.internal", "port": 443}]
        }
    });

    let (s2, b2) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_v2)
        .await;
    assert_eq!(
        s2,
        reqwest::StatusCode::OK,
        "PUT with same upstream name must succeed (not 409/422); body: {b2}"
    );
}

#[tokio::test]
async fn put_idless_upstream_reuses_spec_owned_upstream_after_proxy_drift() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let state = make_admin_state(store.clone(), 10);
    let (base, _shutdown) = start_admin(state).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let spec_upstream_id = uid("spec-upstream");
    let hand_upstream_id = uid("hand-upstream");
    let shared_name = uid("shared-name");
    let listen_path = format!("/{proxy_id}");

    let spec_v1 = json!({
        "openapi": "3.1.0",
        "info": {"title": "PUT idless drift", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-upstream": {
            "id": spec_upstream_id,
            "name": shared_name,
            "targets": [{"host": "target.internal", "port": 443}]
        }
    });
    let (s1, b1) = client.post_json("/api-specs", &spec_v1).await;
    assert_eq!(s1, reqwest::StatusCode::CREATED, "POST: {b1}");
    let spec_id = b1["id"].as_str().unwrap().to_string();

    // Drift the proxy through the direct DB/admin path to a hand-created
    // upstream. The later id-less PUT must still reuse the upstream tagged
    // with api_spec_id, not this mutable proxy pointer.
    let hand_upstream: Upstream = serde_json::from_value(json!({
        "id": hand_upstream_id,
        "namespace": "ferrum",
        "name": uid("manual-name"),
        "targets": [{"host": "manual.internal", "port": 443}]
    }))
    .expect("hand upstream");
    store
        .create_upstream(&hand_upstream)
        .await
        .expect("create hand upstream");
    let mut drifted_proxy = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get proxy")
        .expect("proxy exists");
    drifted_proxy.upstream_id = Some(hand_upstream.id.clone());
    store
        .update_proxy(&drifted_proxy)
        .await
        .expect("drift proxy upstream_id");

    let spec_v2 = json!({
        "openapi": "3.1.0",
        "info": {"title": "PUT idless drift", "version": "1.0.1"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-upstream": {
            "id": "",
            "name": shared_name,
            "targets": [{"host": "target-v2.internal", "port": 443}]
        }
    });

    let (s2, b2) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_v2)
        .await;
    assert_eq!(
        s2,
        reqwest::StatusCode::OK,
        "id-less PUT must reuse the spec-owned upstream, not the drifted proxy pointer; body: {b2}"
    );

    let proxy_after = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get proxy after PUT")
        .expect("proxy after PUT");
    assert_eq!(
        proxy_after.upstream_id.as_deref(),
        Some(spec_upstream_id.as_str()),
        "PUT must restore the proxy to the original spec-owned upstream id"
    );
}

/// PUT changes the upstream `id` but keeps the same upstream `name`.
///
/// The `check_upstream_name_unique` exclusion must be the *stored*
/// upstream_id from the existing proxy in the DB, not the bundle's
/// post-assign_ids_for_put upstream.id. If the exclusion uses the bundle's
/// (new) id, the stored row (with the same name, old id) is still seen
/// and reported as a duplicate, falsely rejecting the change.
#[tokio::test]
async fn put_with_changed_upstream_id_same_name_succeeds() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let state = make_admin_state(store, 10);
    let (base, _shutdown) = start_admin(state).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let upstream_v1_id = uid("upstream-v1");
    let upstream_v2_id = uid("upstream-v2");
    let shared_name = uid("shared-name");
    let listen_path = format!("/{proxy_id}");

    let spec_v1 = json!({
        "openapi": "3.1.0",
        "info": {"title": "PUT changed upstream id", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-upstream": {
            "id": upstream_v1_id,
            "name": shared_name,
            "targets": [{"host": "target.internal", "port": 443}]
        }
    });
    let (s1, b1) = client.post_json("/api-specs", &spec_v1).await;
    assert_eq!(s1, reqwest::StatusCode::CREATED, "POST: {b1}");
    let spec_id = b1["id"].as_str().unwrap().to_string();

    // PUT: change the upstream id, keep the upstream name.
    let spec_v2 = json!({
        "openapi": "3.1.0",
        "info": {"title": "PUT changed upstream id", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-upstream": {
            "id": upstream_v2_id,
            "name": shared_name,
            "targets": [{"host": "target-v2.internal", "port": 443}]
        }
    });
    let (s2, b2) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_v2)
        .await;
    assert_eq!(
        s2,
        reqwest::StatusCode::OK,
        "PUT with changed upstream id (same name) must succeed; body: {b2}"
    );
}

// ============================================================================
// Fix 1 — PUT idempotency: reuse existing IDs for empty-id re-submissions
// ============================================================================

/// POST a spec with empty proxy.id (extractor leaves it empty; handler mints UUID).
/// PUT the same spec (still empty proxy.id) → handler must reuse the stored proxy
/// id, not mint a new one, so the immutability check does NOT fire.
#[tokio::test]
async fn put_with_empty_ids_reuses_existing_proxy_id() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    let listen_path = format!("/{}", uid("path"));

    // POST with empty proxy.id — handler mints a UUID.
    let spec_body = json!({
        "openapi": "3.1.0",
        "info": {"title": "Idempotent PUT test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": "",
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        }
    });

    let (post_status, post_body) = client.post_json("/api-specs", &spec_body).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "POST: {post_body}"
    );
    let spec_id = post_body["id"].as_str().unwrap().to_string();
    let stored_proxy_id = post_body["proxy_id"].as_str().unwrap().to_string();
    assert!(
        !stored_proxy_id.is_empty(),
        "stored proxy_id must be a UUID"
    );

    // PUT the same spec (still empty proxy.id).
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_body)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::OK,
        "PUT with empty proxy.id must succeed (reuse stored proxy_id); body: {put_body}"
    );

    // The proxy_id in the response must be the same as from POST.
    assert_eq!(
        put_body["proxy_id"].as_str().unwrap(),
        stored_proxy_id,
        "PUT must preserve the stored proxy_id"
    );

    // The proxy must still exist in the DB under the original id.
    let proxy = store
        .get_proxy("ferrum", &stored_proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must still exist after idempotent PUT");
    assert_eq!(proxy.id, stored_proxy_id);
}

/// POST a spec with two plugins (empty IDs). The extractor leaves IDs empty; POST
/// handler mints UUIDs. PUT the same spec (still empty plugin IDs) → handler must
/// reuse the existing IDs by plugin_name, and the resource hash short-circuit must
/// fire (proxy.updated_at does NOT advance).
#[tokio::test]
async fn put_with_empty_plugin_ids_reuses_by_name() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let listen_path = format!("/{proxy_id}");

    let spec_body = json!({
        "openapi": "3.1.0",
        "info": {"title": "Plugin ID reuse test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [
            {"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["*"]}},
            {"id": "", "plugin_name": "correlation_id", "config": {}}
        ]
    });

    let (post_status, post_body) = client.post_json("/api-specs", &spec_body).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "POST: {post_body}"
    );
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    // Capture proxy.updated_at before the PUT.
    let proxy_before = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must exist after POST");
    let updated_before = proxy_before.updated_at;

    // Sleep to ensure any write would advance the timestamp.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // PUT the same spec — handler must reuse plugin IDs by name.
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_body)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::OK,
        "PUT with same spec must succeed; body: {put_body}"
    );

    // Resource hash short-circuit: proxy.updated_at must NOT advance.
    let proxy_after = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must still exist after PUT");
    assert_eq!(
        proxy_after.updated_at.timestamp(),
        updated_before.timestamp(),
        "proxy.updated_at must be unchanged when resource hash matches (short-circuit)"
    );
}

/// POST a spec with plugin_name "cors". PUT replacing it with plugin_name
/// "ai_rate_limiter" → new plugin id must be minted (no name match), old
/// plugin removed, replace path runs (updated_at advances).
#[tokio::test]
async fn put_with_renamed_plugin_gets_new_id() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let listen_path = format!("/{proxy_id}");

    // POST with "cors" plugin.
    let spec_v1 = json!({
        "openapi": "3.1.0",
        "info": {"title": "Renamed plugin test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [{"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["*"]}}]
    });
    let (post_status, post_body) = client.post_json("/api-specs", &spec_v1).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "POST: {post_body}"
    );
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    // Sleep so updated_at difference is detectable.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // PUT with "correlation_id" instead of "cors" (different plugin_name).
    let spec_v2 = json!({
        "openapi": "3.1.0",
        "info": {"title": "Renamed plugin test v2", "version": "2.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [{"id": "", "plugin_name": "correlation_id", "config": {}}]
    });
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_v2)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::OK,
        "PUT with renamed plugin must succeed; body: {put_body}"
    );

    // Proxy must still exist and its id must be unchanged.
    let proxy_after = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must still exist");
    assert_eq!(proxy_after.id, proxy_id);

    // The replace path ran (different resource hash — correlation_id ≠ cors).
    // updated_at must be >= created_at (the server-side stamp from Fix 1 ensures
    // this is always true; a stale embedded timestamp would make it go backward).
    assert!(
        proxy_after.updated_at >= proxy_after.created_at,
        "proxy.updated_at ({}) must be >= created_at ({}) after replace",
        proxy_after.updated_at,
        proxy_after.created_at
    );
}

/// POST a spec with plugin_name "cors" (empty id → gets UUID "pl_x"). PUT with
/// same plugin_name but explicit id "pl_explicit" → uses "pl_explicit", replacing
/// "pl_x". The resource hash changes and the replace path runs.
#[tokio::test]
async fn put_with_explicit_plugin_id_overrides_match() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let listen_path = format!("/{proxy_id}");

    // POST with empty plugin id.
    let spec_v1 = json!({
        "openapi": "3.1.0",
        "info": {"title": "Explicit ID override test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [{"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["*"]}}]
    });
    let (post_status, post_body) = client.post_json("/api-specs", &spec_v1).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "POST: {post_body}"
    );
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    // PUT with explicit id "pl-explicit".
    let explicit_id = uid("pl-explicit");
    let spec_v2 = json!({
        "openapi": "3.1.0",
        "info": {"title": "Explicit ID override test v2", "version": "2.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [{"id": explicit_id, "plugin_name": "cors", "config": {"allowed_origins": ["*"]}}]
    });
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_v2)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::OK,
        "PUT with explicit plugin id must succeed; body: {put_body}"
    );

    // The plugin with explicit_id must now exist.
    let plugin = store
        .get_plugin_config("ferrum", &explicit_id)
        .await
        .expect("get_plugin_config failed")
        .expect("explicit plugin must exist after PUT");
    assert_eq!(plugin.id, explicit_id);
    assert_eq!(plugin.plugin_name, "cors");
}

/// PUT can create duplicate final plugin IDs when one empty-id plugin reuses an
/// existing spec-owned ID and another plugin explicitly names that same ID.
/// This must be rejected before persistence rather than falling through to a
/// database uniqueness error.
#[tokio::test]
async fn put_with_empty_plugin_reuse_and_explicit_duplicate_id_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let listen_path = format!("/{proxy_id}");

    let spec_v1 = json!({
        "openapi": "3.1.0",
        "info": {"title": "Final duplicate plugin ID test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [{"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["*"]}}]
    });

    let (post_status, post_body) = client.post_json("/api-specs", &spec_v1).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "POST: {post_body}"
    );
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    let plugins = store
        .list_spec_owned_plugin_configs("ferrum", &spec_id)
        .await
        .expect("list_spec_owned_plugin_configs");
    assert_eq!(plugins.len(), 1, "POST should create one spec-owned plugin");
    let reused_plugin_id = plugins[0].id.clone();

    let spec_v2 = json!({
        "openapi": "3.1.0",
        "info": {"title": "Final duplicate plugin ID test v2", "version": "2.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [
            {"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["*"]}},
            {"id": reused_plugin_id, "plugin_name": "correlation_id", "config": {}}
        ]
    });

    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_v2)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "PUT with duplicate final plugin IDs must return 422; body: {put_body}"
    );
    let failures = put_body["failures"].as_array().expect("failures array");
    let plugin_failure = failures
        .iter()
        .find(|f| f["resource_type"].as_str() == Some("plugin"))
        .unwrap_or_else(|| panic!("expected plugin failure; body: {put_body}"));
    let errors = plugin_failure["errors"].as_array().expect("errors array");
    assert!(
        errors.iter().any(|e| e
            .as_str()
            .is_some_and(|msg| msg.contains("duplicate plugin id"))),
        "error must mention duplicate plugin id; body: {put_body}"
    );

    let plugins_after = store
        .list_spec_owned_plugin_configs("ferrum", &spec_id)
        .await
        .expect("list_spec_owned_plugin_configs after failed PUT");
    assert_eq!(
        plugins_after.len(),
        1,
        "failed PUT must not replace the original plugin set"
    );
    assert_eq!(plugins_after[0].id, reused_plugin_id);
}

// ============================================================================
// Fix 2 — Validate proxy.plugins associations
// ============================================================================

/// POST a spec with an association to a plugin_config_id that doesn't exist in
/// the DB → must return 422 with resource_type "proxy_plugin_association".
#[tokio::test]
async fn post_proxy_plugin_association_to_unknown_plugin_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let bogus_plugin_id = uid("bogus-plugin");

    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Bad association test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "plugins": [{"plugin_config_id": bogus_plugin_id}]
        }
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "association to non-existent plugin must return 422; body: {body}"
    );
    let failures = body["failures"].as_array().expect("failures array");
    let assoc_failure = failures
        .iter()
        .find(|f| f["resource_type"].as_str() == Some("proxy_plugin_association"))
        .unwrap_or_else(|| panic!("expected proxy_plugin_association failure; body: {body}"));
    assert!(!assoc_failure["errors"].as_array().unwrap().is_empty());
}

/// POST a spec where x-ferrum-proxy.plugins references a plugin owned by a
/// DIFFERENT proxy → 422.
#[tokio::test]
async fn post_proxy_plugin_association_to_other_proxy_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    // Create a different proxy + proxy-scoped plugin directly in the DB.
    let other_proxy_id = uid("other-proxy");
    let other_proxy = make_proxy_for_db(&other_proxy_id, "ferrum", &format!("/{other_proxy_id}"));
    store
        .create_proxy(&other_proxy)
        .await
        .expect("create other proxy");

    let other_plugin_id = uid("other-plugin");
    let other_plugin: ferrum_edge::config::types::PluginConfig =
        serde_json::from_value(serde_json::json!({
            "id": other_plugin_id,
            "namespace": "ferrum",
            "plugin_name": "cors",
            "scope": "proxy",
            "proxy_id": other_proxy_id,
            "config": {"allowed_origins": ["*"]},
            "enabled": true
        }))
        .expect("other plugin deserialization");
    store
        .create_plugin_config(&other_plugin)
        .await
        .expect("create other plugin");

    let proxy_id = uid("proxy");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Other proxy plugin test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "plugins": [{"plugin_config_id": other_plugin_id}]
        }
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "association to other proxy's plugin must return 422; body: {body}"
    );
    let failures = body["failures"].as_array().expect("failures array");
    assert!(
        failures
            .iter()
            .any(|f| f["resource_type"].as_str() == Some("proxy_plugin_association")),
        "must have a proxy_plugin_association failure; body: {body}"
    );
}

/// POST a spec where x-ferrum-proxy.plugins references a plugin from another
/// namespace -> 422.
#[tokio::test]
async fn post_proxy_plugin_association_to_other_namespace_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    let other_namespace = "other-namespace";
    let shared_plugin_id = uid("shared-plugin");
    let shared_plugin: ferrum_edge::config::types::PluginConfig =
        serde_json::from_value(serde_json::json!({
            "id": shared_plugin_id,
            "namespace": other_namespace,
            "plugin_name": "cors",
            "scope": "proxy_group",
            "config": {"allowed_origins": ["*"]},
            "enabled": true
        }))
        .expect("shared plugin deserialization");
    store
        .create_plugin_config(&shared_plugin)
        .await
        .expect("create other-namespace plugin");

    let proxy_id = uid("proxy");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Cross namespace plugin test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "plugins": [{"plugin_config_id": shared_plugin_id}]
        }
    });

    let (status, body) = client
        .post_json_in_namespace("/api-specs", "ferrum", &spec)
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "association to another namespace's plugin must return 422; body: {body}"
    );
    let failures = body["failures"].as_array().expect("failures array");
    // Plugin-config reads are namespace-predicated (issue #2122 DB-M1): the
    // other-namespace plugin reports as missing in the spec's namespace, so
    // the rejection no longer discloses which namespace owns it.
    assert!(
        failures
            .iter()
            .any(|f| f["resource_type"] == "proxy_plugin_association"
                && f["errors"].as_array().is_some_and(|a| a.iter().any(|e| e
                    .as_str()
                    .is_some_and(
                        |s| s.contains(&shared_plugin_id) && s.contains("does not exist")
                    )))),
        "must include the cross-namespace association rejection in failures: {body}"
    );
}

/// POST a spec where x-ferrum-proxy.plugins references a GLOBAL plugin → 422.
///
/// Mirrors the system-wide invariant enforced by
/// `GatewayConfig::validate_plugin_references` and SQL
/// `validate_proxy_plugin_associations`: proxy associations may only
/// reference proxy-scoped or proxy_group-scoped configs. Global plugins
/// apply implicitly to all proxies via `plugin_cache` and must remain
/// unassociated.
#[tokio::test]
async fn post_proxy_plugin_association_to_global_plugin_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    // Create a global plugin in the DB.
    let global_plugin_id = uid("global-plugin");
    let global_plugin: ferrum_edge::config::types::PluginConfig =
        serde_json::from_value(serde_json::json!({
            "id": global_plugin_id,
            "namespace": "ferrum",
            "plugin_name": "cors",
            "scope": "global",
            "config": {"allowed_origins": ["*"]},
            "enabled": true
        }))
        .expect("global plugin deserialization");
    store
        .create_plugin_config(&global_plugin)
        .await
        .expect("create global plugin");

    let proxy_id = uid("proxy");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Global plugin association test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "plugins": [{"plugin_config_id": global_plugin_id}]
        }
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "association to global plugin must be rejected; body: {body}"
    );
    let failures = body["failures"].as_array().expect("failures array");
    assert!(
        failures
            .iter()
            .any(|f| f["resource_type"] == "proxy_plugin_association"
                && f["errors"]
                    .as_array()
                    .and_then(|a| a.iter().find(|e| e
                        .as_str()
                        .map(|s| s.contains("scope=global"))
                        .unwrap_or(false)))
                    .is_some()),
        "must include the scope=global rejection in failures: {body}"
    );
}

/// POST a spec where x-ferrum-proxy.plugins references one of the spec's own
/// x-ferrum-plugins (auto-added by the extractor). The validator must NOT reject
/// this as "non-existent" — about-to-insert plugins are always valid.
#[tokio::test]
async fn post_proxy_plugin_association_to_about_to_insert_plugin_succeeds() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let plugin_id = uid("spec-plugin");

    // The association in proxy.plugins points to the same plugin in x-ferrum-plugins.
    // This is the normal auto-extracted case after Round 2 — the extractor adds the
    // association automatically. This test verifies the validator does not double-reject it.
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "About-to-insert plugin test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "plugins": [{"plugin_config_id": plugin_id}]
        },
        "x-ferrum-plugins": [{
            "id": plugin_id,
            "plugin_name": "cors",
            "config": {"allowed_origins": ["*"]}
        }]
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "association to about-to-insert spec plugin must succeed; body: {body}"
    );
}

// ============================================================================
// Fix 3 (SQL parity) — PUT keeps manual proxy plugin associations
// ============================================================================
/// See admin_db_api_specs_tests.rs for the full DB-layer test. This handler-
/// level test verifies the end-to-end invariant: after a PUT that replaces the
/// spec-owned plugin, a manually-added association (proxy-group plugin) still
/// causes the proxy to run that plugin at runtime.
///
/// The proxy.updated_at behaviour is tested at the DB layer. Here we verify
/// the proxy still exists and the proxy-group plugin association is visible via
/// `get_proxy`.
#[tokio::test]
async fn put_keeps_manually_added_proxy_group_plugin_association() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let listen_path = format!("/{proxy_id}");

    // POST the initial spec (with one spec-owned plugin).
    let spec_v1 = json!({
        "openapi": "3.1.0",
        "info": {"title": "Manual assoc test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [{"id": uid("spec-plugin-v1"), "plugin_name": "cors", "config": {"allowed_origins": ["*"]}}]
    });
    let (post_status, post_body) = client.post_json("/api-specs", &spec_v1).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "POST: {post_body}"
    );
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    // Manually create a proxy-group plugin and add it to the proxy (simulates
    // an operator associating a shared rate-limit plugin after spec creation).
    let manual_plugin_id = uid("proxy-group");
    let manual_plugin: ferrum_edge::config::types::PluginConfig =
        serde_json::from_value(serde_json::json!({
            "id": manual_plugin_id,
            "namespace": "ferrum",
            "plugin_name": "cors",
            "scope": "proxy_group",
            "config": {"allowed_origins": ["*"]},
            "enabled": true
        }))
        .expect("proxy-group plugin deserialization");
    store
        .create_plugin_config(&manual_plugin)
        .await
        .expect("create proxy-group plugin");

    // Insert the proxy-plugin junction row manually.
    use ferrum_edge::config::types::PluginAssociation;
    let proxy_with_manual_assoc = {
        let mut p = store
            .get_proxy("ferrum", &proxy_id)
            .await
            .expect("get_proxy")
            .expect("proxy exists");
        p.plugins.push(PluginAssociation {
            plugin_config_id: manual_plugin_id.clone(),
        });
        p
    };
    store
        .update_proxy(&proxy_with_manual_assoc)
        .await
        .expect("update proxy");

    // PUT the spec with a different spec-owned plugin (forces a non-short-circuit replace).
    let new_spec_plugin_id = uid("spec-plugin-v2");
    let spec_v2 = json!({
        "openapi": "3.1.0",
        "info": {"title": "Manual assoc test v2", "version": "2.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "new-backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [{
            "id": new_spec_plugin_id,
            "plugin_name": "correlation_id",
            "config": {}
        }]
    });
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_v2)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::OK,
        "PUT must succeed; body: {put_body}"
    );

    // The proxy-group plugin must still be associated with the proxy.
    let proxy_after = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get_proxy after PUT")
        .expect("proxy must still exist");
    let plugin_ids: Vec<&str> = proxy_after
        .plugins
        .iter()
        .map(|a| a.plugin_config_id.as_str())
        .collect();
    assert!(
        plugin_ids.contains(&manual_plugin_id.as_str()),
        "proxy-group plugin association must be preserved after PUT; found: {:?}",
        plugin_ids
    );
}

// ============================================================================
// Fix 2 — Stream proxy port validation
// ============================================================================

/// POST a spec with a TCP proxy whose listen_port collides with an already-stored
/// stream proxy → must return 422 with a "port" error.
#[tokio::test]
async fn post_spec_with_stream_proxy_port_collision_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    // Pre-create a stream proxy on port 7777 directly in the DB.
    let existing_tcp_proxy: Proxy = serde_json::from_value(json!({
        "id": uid("existing-tcp"),
        "namespace": "ferrum",
        "backend_host": "tcp-backend.internal",
        "backend_port": 9001,
        "backend_scheme": "tcp",
        "listen_port": 7777
    }))
    .expect("stream proxy deserialization");
    store
        .create_proxy(&existing_tcp_proxy)
        .await
        .expect("create existing tcp proxy");

    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // Submit a spec with a different TCP proxy that wants the same port 7777.
    let proxy_id = uid("tcp-proxy");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Stream port collision test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "other-tcp.internal",
            "backend_port": 9002,
            "backend_scheme": "tcp",
            "listen_port": 7777
        }
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 422 on stream port collision; body: {body}"
    );
    let failures = body["failures"].as_array().expect("failures array");
    assert!(
        failures
            .iter()
            .any(|f| f["resource_type"].as_str() == Some("proxy")
                && f["errors"]
                    .as_array()
                    .map(|errs| errs
                        .iter()
                        .any(|e| e.as_str().unwrap_or("").contains("7777")))
                    .unwrap_or(false)),
        "expected port-collision error in failures; body: {body}"
    );
}

/// POST a spec with a TCP proxy on a reserved gateway port → must return 422.
#[tokio::test]
async fn post_spec_with_reserved_gateway_port_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let mut state = make_admin_state(store, 25);
    // Mark port 9000 as a reserved gateway port (mirrors the admin HTTP port default).
    state.reserved_ports = std::collections::HashSet::from([9000u16]);

    let (base, _shutdown) = start_admin(state).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("tcp-reserved");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Reserved port test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "tcp-backend.internal",
            "backend_port": 9001,
            "backend_scheme": "tcp",
            "listen_port": 9000
        }
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 422 for reserved port; body: {body}"
    );
    let failures = body["failures"].as_array().expect("failures array");
    assert!(
        failures
            .iter()
            .any(|f| f["resource_type"].as_str() == Some("proxy")),
        "expected proxy failure for reserved port; body: {body}"
    );
}

// ============================================================================
// Fix 2b — OS-level port availability probe on spec import
// ============================================================================

/// POST a spec with a TCP proxy on a port that is already bound by another
/// process → must return 422 (or 409 as direct admin does). The port is held
/// for the entire test by a TcpListener guard.
#[tokio::test]
async fn post_spec_with_unbindable_stream_port_returns_422_or_equivalent() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    // Bind a TCP listener on an ephemeral port and hold it for the duration
    // of the test so the gateway's OS-level probe fails.
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied_port = bound.local_addr().unwrap().port();

    let mut state = make_admin_state(store, 25);
    // Point the stream bind address to 127.0.0.1 so the probe targets the
    // same interface as our held listener.
    state.stream_proxy_bind_address = "127.0.0.1".to_string();

    let (base, _shutdown) = start_admin(state).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("tcp-occupied");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Port unavailable test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "tcp-backend.internal",
            "backend_port": 9001,
            "backend_scheme": "tcp",
            "listen_port": occupied_port
        }
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    // Direct admin returns 409 CONFLICT for port probe failures; spec validation
    // surfaces the same error via the 422 ValidationFailures path since we
    // accumulate all errors before returning.
    assert!(
        status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
            || status == reqwest::StatusCode::CONFLICT,
        "expected 422 or 409 for unavailable port; got {status}; body: {body}"
    );

    // Keep the listener alive until after the request to ensure the port stays
    // occupied during the probe.
    drop(bound);
}

/// POST a spec with a CP-mode state → port probe must NOT fire.
/// Verified by binding a port, submitting a spec targeting that port via a
/// CP-mode AdminState, and expecting success (201) since CP skips the probe.
/// The DB uniqueness check must still pass (no prior stream proxy on the port).
#[tokio::test]
async fn post_spec_stream_port_cp_mode_skips_os_probe() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    // Bind a port to make it appear occupied.
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied_port = bound.local_addr().unwrap().port();

    let mut state = make_admin_state(store, 25);
    state.mode = "cp".to_string();
    state.stream_proxy_bind_address = "127.0.0.1".to_string();

    let (base, _shutdown) = start_admin(state).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("tcp-cp-probe");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "CP port probe skip test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "tcp-backend.internal",
            "backend_port": 9001,
            "backend_scheme": "tcp",
            "listen_port": occupied_port
        }
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    // CP mode skips the OS probe (matches Proxy::after_validate guard), so the
    // spec must be accepted even though the port is currently occupied locally.
    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "CP mode must skip port probe and accept spec; body: {body}"
    );

    drop(bound);
}

// ============================================================================
// Fix 1 — upstream_id existence validation on spec import
// ============================================================================

/// POST a spec that sets proxy.upstream_id to a non-existent upstream and
/// includes no x-ferrum-upstream → must return 422 with upstream_id error.
#[tokio::test]
async fn post_spec_with_dangling_upstream_id_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy-dangling");
    let dangling_uid = uid("non-existent-upstream");

    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Dangling upstream_id test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "upstream_id": dangling_uid
        }
        // Intentionally no x-ferrum-upstream
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 422 for dangling upstream_id; body: {body}"
    );
    let failures = body["failures"].as_array().expect("failures array");
    assert!(
        failures.iter().any(|f| {
            f["resource_type"].as_str() == Some("proxy")
                && f["errors"]
                    .as_array()
                    .map(|errs| {
                        errs.iter()
                            .any(|e| e.as_str().unwrap_or("").contains("upstream_id"))
                    })
                    .unwrap_or(false)
        }),
        "expected upstream_id error in failures; body: {body}"
    );
}

/// POST a spec where proxy.upstream_id matches the bundled x-ferrum-upstream
/// id → must succeed (201).  The bundled upstream is not yet in the DB but
/// is about to be inserted together with the proxy.
#[tokio::test]
async fn post_spec_with_upstream_id_referencing_bundled_upstream_succeeds() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy-bundled-up");
    let upstream_id = uid("bundled-upstream");

    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Bundled upstream test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "upstream_id": upstream_id
        },
        "x-ferrum-upstream": {
            "id": upstream_id,
            "targets": [{"host": "target.internal", "port": 443}]
        }
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "spec with upstream_id matching bundled upstream must succeed; body: {body}"
    );
}

/// POST a spec where proxy.upstream_id references an upstream that was already
/// created in the DB via direct admin → must succeed (201).
#[tokio::test]
async fn post_spec_with_upstream_id_referencing_existing_db_upstream_succeeds() {
    use ferrum_edge::config::types::Upstream;

    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    // Pre-create an upstream directly in the DB.
    let pre_upstream_id = uid("pre-upstream");
    let pre_upstream: Upstream = serde_json::from_value(json!({
        "id": pre_upstream_id,
        "namespace": "ferrum",
        "targets": [{"host": "target.internal", "port": 443}]
    }))
    .expect("upstream deserialization");
    store
        .create_upstream(&pre_upstream)
        .await
        .expect("create pre-upstream");

    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy-pre-upstream");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Pre-existing upstream test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "upstream_id": pre_upstream_id
        }
        // No x-ferrum-upstream: the proxy references the pre-existing one.
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "spec with upstream_id referencing existing DB upstream must succeed; body: {body}"
    );
}

// ============================================================================
// Fix 3 — Generic PluginConfig field validation
// ============================================================================

/// POST a spec with a plugin whose priority_override exceeds the allowed maximum
/// (10000) → must return 422 with the priority-override error.
#[tokio::test]
async fn post_spec_with_plugin_priority_override_too_high_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Priority override test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        },
        "x-ferrum-plugins": [{
            "id": uid("plugin"),
            "plugin_name": "cors",
            "priority_override": 10001,
            "config": {"allowed_origins": ["*"]}
        }]
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 422 for priority_override > 10000; body: {body}"
    );
    let failures = body["failures"].as_array().expect("failures array");
    assert!(
        failures.iter().any(|f| {
            f["resource_type"].as_str() == Some("plugin")
                && f["errors"]
                    .as_array()
                    .map(|errs| {
                        errs.iter().any(|e| {
                            let s = e.as_str().unwrap_or("");
                            s.contains("priority_override") || s.contains("10000")
                        })
                    })
                    .unwrap_or(false)
        }),
        "expected priority_override error in plugin failures; body: {body}"
    );
}

// ============================================================================
// Fix 4 — Reject duplicate proxy plugin associations
// ============================================================================

/// POST a spec where the operator writes the same plugin_config_id twice in
/// x-ferrum-proxy.plugins → must return 422.
#[tokio::test]
async fn post_spec_with_duplicate_proxy_plugin_association_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    // Create a pre-existing proxy-scoped plugin in the DB to reference.
    let proxy_id = uid("proxy");
    // First create the proxy so the plugin FK is valid.
    let proxy: Proxy = serde_json::from_value(json!({
        "id": proxy_id,
        "namespace": "ferrum",
        "backend_host": "backend.internal",
        "backend_port": 443,
        "listen_path": format!("/{proxy_id}")
    }))
    .expect("proxy deserialization");
    store.create_proxy(&proxy).await.expect("create proxy");

    use ferrum_edge::config::types::PluginConfig;
    let shared_plugin_id = uid("shared-plugin");
    let shared_plugin: PluginConfig = serde_json::from_value(json!({
        "id": shared_plugin_id,
        "namespace": "ferrum",
        "plugin_name": "cors",
        "scope": "proxy_group",
        "config": {"allowed_origins": ["*"]}
    }))
    .expect("plugin deserialization");
    store
        .create_plugin_config(&shared_plugin)
        .await
        .expect("create shared plugin");

    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // Spec references shared_plugin_id twice in x-ferrum-proxy.plugins.
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Duplicate assoc test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "plugins": [
                {"plugin_config_id": shared_plugin_id},
                {"plugin_config_id": shared_plugin_id}
            ]
        }
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 422 for duplicate plugin association; body: {body}"
    );
    let failures = body["failures"].as_array().expect("failures array");
    assert!(
        failures
            .iter()
            .any(|f| f["resource_type"].as_str() == Some("proxy_plugin_association")),
        "expected proxy_plugin_association failure; body: {body}"
    );
}

// ============================================================================
// Fix 5 — Canonical plugin matching on PUT
// ============================================================================

/// PUT with two id-less plugins of the same plugin_name and IDENTICAL configs →
/// existing IDs are reused in deterministic FIFO order; the resource hash does
/// not change between identical re-submissions (idempotent).
#[tokio::test]
async fn put_with_two_id_less_same_name_plugins_identical_configs_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let listen_path = format!("/{proxy_id}");

    // Both plugins have the same plugin_name AND identical config — the
    // extractor allows multiple proxy-scoped instances of the same plugin.
    let two_cors_plugins = json!([
        {"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["*"]}},
        {"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["*"]}}
    ]);

    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Two identical plugins", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": two_cors_plugins
    });

    // POST — initial create.
    let (post_status, post_body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "POST: {post_body}"
    );
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    // Fetch the resource_hash from the spec row via the list endpoint.
    let (_, list_body) = client.get_json("/api-specs").await;
    // (resource_hash is intentionally omitted from the list response per spec;
    //  we verify idempotency via the proxy's updated_at staying the same.)

    // Sleep to make timestamp differences detectable.
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;

    let proxy_before = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must exist");
    let updated_at_before = proxy_before.updated_at;

    // PUT with the same spec (identical content → same resource hash → short-circuit).
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::OK,
        "PUT identical spec must succeed; body: {put_body}"
    );

    let proxy_after = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get_proxy after PUT")
        .expect("proxy must still exist");

    // Short-circuit: no DB write happened, updated_at must not have advanced.
    assert_eq!(
        proxy_after.updated_at, updated_at_before,
        "proxy.updated_at must not advance on idempotent PUT (resource hash unchanged)"
    );

    // Suppress the unused-variable warning from the list body (used for context).
    let _ = list_body;
}

/// PUT with two id-less plugins of the same plugin_name but DIFFERENT configs →
/// must return 422 requiring explicit IDs.
#[tokio::test]
async fn put_with_two_id_less_same_name_plugins_different_configs_returns_422() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let listen_path = format!("/{proxy_id}");

    // Initial POST with one cors plugin.
    let spec_v1 = json!({
        "openapi": "3.1.0",
        "info": {"title": "Ambiguous PUT test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [{"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["*"]}}]
    });
    let (post_status, post_body) = client.post_json("/api-specs", &spec_v1).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "POST: {post_body}"
    );
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    // PUT with two cors plugins that have DIFFERENT configs and both have empty IDs.
    let spec_v2 = json!({
        "openapi": "3.1.0",
        "info": {"title": "Ambiguous PUT test v2", "version": "2.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [
            {"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["https://a.example"]}},
            {"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["https://b.example"]}}
        ]
    });
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_v2)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 422 for ambiguous same-name different-config plugins; body: {put_body}"
    );
    // spec_version must be populated — previously this was String::new() (M2 fix).
    let sv = put_body["spec_version"].as_str().unwrap_or("");
    assert!(
        sv.starts_with("3."),
        "spec_version must be non-empty and start with '3.' (got '{sv}'); body: {put_body}"
    );
    let failures = put_body["failures"].as_array().expect("failures array");
    assert!(
        failures.iter().any(|f| {
            f["resource_type"].as_str() == Some("plugin")
                && f["errors"]
                    .as_array()
                    .map(|errs| {
                        errs.iter().any(|e| {
                            let s = e.as_str().unwrap_or("");
                            s.contains("explicit") || s.contains("disambiguate")
                        })
                    })
                    .unwrap_or(false)
        }),
        "expected 'explicit ids' error; body: {put_body}"
    );
}

/// PUT with two id-less plugins sharing a `plugin_name`, where ONE matches the
/// existing stored config canonically and the OTHER is a brand-new instance:
/// the matched one reuses the stored id, the new one mints a UUID, and the
/// PUT succeeds. Round-5 Fix 5 incorrectly rejected this as ambiguous; the
/// reviewer flagged it as P1 at HEAD cf7ebc9.
#[tokio::test]
async fn put_adds_second_same_name_plugin_when_one_matches_canonically() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let listen_path = format!("/{proxy_id}");

    // POST with a single cors plugin (config A).
    let spec_v1 = json!({
        "openapi": "3.1.0",
        "info": {"title": "Append duplicate test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [
            {"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["https://a.example"]}}
        ]
    });
    let (s1, b1) = client.post_json("/api-specs", &spec_v1).await;
    assert_eq!(s1, reqwest::StatusCode::CREATED, "POST: {b1}");
    let spec_id = b1["id"].as_str().unwrap().to_string();

    // PUT with two cors plugins: one identical to existing (canonical match),
    // one new (unmatched). The new fix must mint a UUID for the unmatched one
    // rather than rejecting both because of the name duplicate.
    let spec_v2 = json!({
        "openapi": "3.1.0",
        "info": {"title": "Append duplicate test v2", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        },
        "x-ferrum-plugins": [
            {"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["https://a.example"]}},
            {"id": "", "plugin_name": "cors", "config": {"allowed_origins": ["https://b.example"]}}
        ]
    });
    let (s2, b2) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_v2)
        .await;
    assert_eq!(
        s2,
        reqwest::StatusCode::OK,
        "PUT must succeed: one duplicate matched, one new — unambiguous; body: {b2}"
    );
}

// ============================================================================
// Fix 1 — Timestamp stamping (server-side overrides operator-supplied values)
// ============================================================================

// ============================================================================
// Item 8 — title_contains wildcard rejection (handler-level round-trip)
// ============================================================================

#[tokio::test]
async fn list_with_title_contains_wildcard_returns_400() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // `%` is a SQL LIKE wildcard — must be rejected with 400.
    let (status, body) = client.get_json("/api-specs?title_contains=foo%25bar").await;
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "percent in title_contains must return 400; body: {body}"
    );

    // `_` is also a SQL single-char wildcard — must be rejected.
    let (status2, body2) = client.get_json("/api-specs?title_contains=foo_bar").await;
    assert_eq!(
        status2,
        reqwest::StatusCode::BAD_REQUEST,
        "underscore in title_contains must return 400; body: {body2}"
    );

    // Plain text must be accepted (returns 200 with empty list).
    let (status3, _body3) = client.get_json("/api-specs?title_contains=MyAPI").await;
    assert_eq!(
        status3,
        reqwest::StatusCode::OK,
        "plain text in title_contains must return 200"
    );
}

// ============================================================================
// Item 10 — percent_decode: invalid UTF-8 sequence returns 400
// ============================================================================

#[tokio::test]
async fn list_with_invalid_percent_encoding_returns_400() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // %80 is an invalid UTF-8 continuation byte without a start byte.
    let (status, body) = client
        .get_json("/api-specs?title_contains=%80invalid")
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "invalid percent-encoding must return 400; body: {body}"
    );
}

/// `?has_tag=` accepts arbitrary input AT QUERY TIME — and the SQL `has_tag`
/// filter embeds it directly into a `LIKE '%"<input>"%'` pattern with no
/// `ESCAPE` clause. SQL `LIKE` treats `%` as a multi-char wildcard and `_`
/// as a single-char wildcard, so a client sending `?has_tag=%25` (URL-decoded
/// `%`) or `?has_tag=_` would inject wildcards and turn the advertised
/// exact-membership filter into a multi-row pattern match.
///
/// We reject the same character set we reject at ingest (`"`, `%`, `_`, `\`)
/// in the query parser, returning 400 with a clear message.
#[tokio::test]
async fn list_with_has_tag_wildcard_returns_400() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // Each forbidden char must be rejected. Percent-encoded forms decode
    // BEFORE the reject check (validated by `percent_decode` running first).
    for (label, query) in [
        ("percent literal", "/api-specs?has_tag=%25"), // %25 → '%'
        ("underscore", "/api-specs?has_tag=api_v1"),
        ("quote literal", "/api-specs?has_tag=foo%22bar"), // %22 → '"'
        ("backslash literal", "/api-specs?has_tag=foo%5Cbar"), // %5C → '\'
    ] {
        let (status, body) = client.get_json(query).await;
        assert_eq!(
            status,
            reqwest::StatusCode::BAD_REQUEST,
            "{label} ({query}) must return 400; body: {body}"
        );
        let err = body["error"].as_str().unwrap_or("");
        assert!(
            err.contains("forbidden character") && err.contains("has_tag"),
            "{label}: error must cite the rejection rule; got: {err}"
        );
    }
}

// ============================================================================
// Test coverage gap — concurrent POST with same proxy_id
// ============================================================================

/// Two concurrent POST requests referencing the same proxy_id race the unique
/// constraint check.  Exactly one must succeed (201) and the other must be
/// rejected (409 Conflict or 422 from listen_path uniqueness).
#[tokio::test]
async fn concurrent_handler_post_same_proxy_id_one_succeeds_one_409() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;

    let proxy_id = uid("proxy");
    let spec = minimal_json_spec(&proxy_id);

    // Spawn two concurrent POST requests; both claim the same proxy_id / listen_path.
    let client_a = AdminClient::new(base.clone());
    let client_b = AdminClient::new(base.clone());
    let spec_a = spec.clone();
    let spec_b = spec.clone();

    let (ra, rb) = tokio::join!(
        client_a.post_json("/api-specs", &spec_a),
        client_b.post_json("/api-specs", &spec_b),
    );

    let (status_a, body_a) = ra;
    let (status_b, body_b) = rb;

    let statuses = [status_a, status_b];
    let bodies = [&body_a, &body_b];

    // Exactly one must be 201 and the other a conflict/uniqueness error.
    let created_count = statuses
        .iter()
        .filter(|&&s| s == reqwest::StatusCode::CREATED)
        .count();
    let conflict_count = statuses
        .iter()
        .filter(|&&s| {
            s == reqwest::StatusCode::CONFLICT || s == reqwest::StatusCode::UNPROCESSABLE_ENTITY
        })
        .count();

    assert_eq!(
        created_count, 1,
        "exactly one POST must return 201; statuses: {:?}, bodies: {:?}",
        statuses, bodies
    );
    assert_eq!(
        conflict_count, 1,
        "exactly one POST must return 409 or 422; statuses: {:?}, bodies: {:?}",
        statuses, bodies
    );
}

// ============================================================================
// Test coverage gap — YAML body with JSON Content-Type → 400
// ============================================================================

/// Sending a YAML body with `Content-Type: application/json` must be rejected
/// with 400 because the explicit Content-Type forces JSON parsing, which fails
/// on a YAML document.
#[tokio::test]
async fn post_yaml_body_with_json_content_type_returns_400() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    // Valid YAML but invalid JSON body.
    let yaml_body = minimal_yaml_spec(&proxy_id);

    let (status, body) = client
        .post_raw("/api-specs", yaml_body.into_bytes(), "application/json")
        .await;

    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "YAML body with JSON Content-Type must return 400; body: {body}"
    );
    // The error code must identify the JSON parse failure.
    assert_eq!(
        body["code"].as_str(),
        Some("InvalidJson"),
        "error code must be InvalidJson; body: {body}"
    );
}

// ============================================================================
// Test coverage gap — Unicode/emoji metadata round-trip
// ============================================================================

/// Submit a spec whose `info.title`, `info.description`, and `x-ferrum-proxy.name`
/// contain multi-byte UTF-8 characters (including emoji).  The metadata must
/// survive the round-trip (POST → GET list) byte-for-byte.
#[tokio::test]
async fn post_unicode_in_metadata_round_trips() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    // Emoji in title; multi-byte chars in description.
    let spec = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "API 🚀 Unicode Test Ünïcödé",
            "version": "1.0.0",
            "description": "描述 — description with CJK and accents: café, naïve, résumé"
        },
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        }
    });

    let (post_status, post_body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "POST must succeed; body: {post_body}"
    );
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    // Retrieve via list and check that the title and description round-tripped.
    let (list_status, list_body) = client.get_json("/api-specs").await;
    assert_eq!(list_status, reqwest::StatusCode::OK);

    let items = list_body["items"].as_array().expect("items must be array");
    let found = items
        .iter()
        .find(|item| item["id"].as_str() == Some(&spec_id));
    let found = found.expect("submitted spec must appear in list");

    assert_eq!(
        found["title"].as_str(),
        Some("API 🚀 Unicode Test Ünïcödé"),
        "title must round-trip with emoji intact; got: {}",
        found["title"]
    );
    assert_eq!(
        found["description"].as_str(),
        Some("描述 — description with CJK and accents: café, naïve, résumé"),
        "description must round-trip with CJK chars intact; got: {}",
        found["description"]
    );
}

// ============================================================================
// Decompression bomb defence — end-to-end
// ============================================================================

/// A corrupted or adversarially-tampered DB row whose `spec_content` is a
/// "gzip bomb" (small compressed bytes that decompress to many MiB) must NOT
/// crash the admin server or exhaust memory on GET.
///
/// `decompress_gzip_capped` enforces a `2 * admin_spec_max_body_size_mib * MiB`
/// cap; the GET handler surfaces overflow as a 500 with a generic
/// "spec content corrupt or oversized" message.
#[tokio::test]
async fn get_with_bomb_ratio_spec_content_returns_500() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    // admin_spec_max_body_size_mib = 1 → decompress cap = 2 MiB.
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 1)).await;
    let client = AdminClient::new(base);

    // POST a normal spec to create a row we can tamper with.
    let proxy_id = uid("proxy");
    let listen_path = format!("/{proxy_id}");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "bomb test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": listen_path
        }
    });
    let (s1, b1) = client.post_json("/api-specs", &spec).await;
    assert_eq!(s1, reqwest::StatusCode::CREATED, "POST: {b1}");
    let spec_id = b1["id"].as_str().unwrap().to_string();

    // Build a bomb: gzip-compress 8 MiB of zeros.  The compressed output is
    // ~8 KiB; decompressed it's 8 MiB, which exceeds the 2 MiB cap.
    let zeros = vec![0u8; 8 * 1024 * 1024];
    let bomb = ferrum_edge::admin::spec_codec::compress_gzip(&zeros).expect("gzip ok");
    assert!(
        bomb.len() < 100 * 1024,
        "bomb must compress to <100 KiB to actually be a bomb (got {} bytes)",
        bomb.len()
    );

    // Overwrite the stored spec_content via a raw SQL UPDATE.  This simulates
    // a corrupted DB row or an attacker who somehow modified storage.
    sqlx::query("UPDATE api_specs SET spec_content = ? WHERE id = ?")
        .bind(bomb.as_slice())
        .bind(&spec_id)
        .execute(&store.pool())
        .await
        .expect("update bomb spec_content");

    // GET — must NOT OOM the server.  Returns a 500 with a generic error body
    // (the redacted message; raw decompression error is logged at error level).
    let (status, body) = client.get_json(&format!("/api-specs/{spec_id}")).await;
    assert_eq!(
        status,
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "GET on a bomb-ratio row must return 500; body: {body}"
    );

    // Sanity: server is still alive (subsequent request returns normally).
    let (status_after, _body) = client.get_json("/api-specs").await;
    assert_eq!(
        status_after,
        reqwest::StatusCode::OK,
        "server must remain responsive after rejecting the bomb"
    );
}

// ============================================================================
// Fix 1 — Timestamp stamping (server-side overrides operator-supplied values)
// ============================================================================

/// POST a spec, then PUT with an artificially-old updated_at embedded in the
/// x-ferrum-proxy extension.  The server must overwrite it with a fresh
/// server-side timestamp, so the incremental polling delta path can see the
/// change.
#[tokio::test]
async fn put_overwrites_imported_updated_at_so_polling_picks_change() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");

    // POST the initial spec.
    let (post_status, post_body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(
        post_status,
        reqwest::StatusCode::CREATED,
        "POST: {post_body}"
    );
    let spec_id = post_body["id"].as_str().unwrap().to_string();

    let proxy_after_post = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get_proxy")
        .expect("proxy must exist after POST");
    let post_updated_at = proxy_after_post.updated_at;

    // Sleep to ensure the wall clock advances.
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;

    // PUT with an explicitly-old updated_at embedded in the spec document.
    // If the server-side stamp does NOT fire, the stored updated_at would be
    // 1970-01-01 and polling would never pick up the change.
    let spec_with_old_ts = json!({
        "openapi": "3.1.0",
        "info": {"title": "Timestamp overwrite test", "version": "2.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "new-backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "updated_at": "1970-01-01T00:00:00Z"
        },
        "x-ferrum-plugins": [{
            "id": uid("plugin"),
            "plugin_name": "cors",
            "config": {"allowed_origins": ["*"]},
            "updated_at": "1970-01-01T00:00:00Z"
        }]
    });
    let (put_status, put_body) = client
        .put_json(&format!("/api-specs/{spec_id}"), &spec_with_old_ts)
        .await;
    assert_eq!(
        put_status,
        reqwest::StatusCode::OK,
        "PUT must succeed; body: {put_body}"
    );

    let proxy_after_put = store
        .get_proxy("ferrum", &proxy_id)
        .await
        .expect("get_proxy after PUT")
        .expect("proxy must still exist");

    // The server-side stamp must have overwritten the embedded 1970 timestamp.
    assert!(
        proxy_after_put.updated_at > post_updated_at,
        "proxy.updated_at ({}) must be NEWER than the initial POST timestamp ({}) \
         — server-side stamping must override the 1970-01-01 embedded in the spec",
        proxy_after_put.updated_at,
        post_updated_at
    );

    // Also verify for the plugin.
    let plugins = store
        .list_spec_owned_plugin_configs("ferrum", &spec_id)
        .await
        .expect("list_spec_owned_plugin_configs");
    if let Some(plugin) = plugins.first() {
        let epoch = chrono::DateTime::parse_from_rfc3339("1970-01-01T00:00:00Z")
            .unwrap()
            .to_utc();
        assert!(
            plugin.updated_at > epoch,
            "plugin.updated_at must be overwritten by server-side stamp; got {}",
            plugin.updated_at
        );
    }
}

// ============================================================================
// Test coverage gap — DP mode returns 403 on writes
// ============================================================================

/// DP mode sets `read_only = true` and `mode = "dp"`.  All write endpoints
/// must return 403.  GET endpoints must still work.
#[tokio::test]
async fn dp_mode_blocks_spec_writes_allows_reads() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let mut state = make_admin_state(store, 25);
    state.read_only = true;
    state.mode = "dp".to_string();

    let (base, _shutdown) = start_admin(state).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let (status, _) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "POST must be 403 in DP mode"
    );

    let (status, _) = client
        .put_json("/api-specs/any-id", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "PUT must be 403 in DP mode"
    );

    let status = client.delete("/api-specs/any-id").await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "DELETE must be 403 in DP mode"
    );

    // GETs should still work (404 because nothing exists, not 403).
    let (status, _) = client.get_json("/api-specs").await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "GET list must succeed in DP mode"
    );

    let (status, _) = client.get_json("/api-specs/nonexistent").await;
    assert_eq!(
        status,
        reqwest::StatusCode::NOT_FOUND,
        "GET by id must return 404, not 403"
    );
}

// ============================================================================
// Test coverage gap — concurrent POST with overlapping listen_path
// ============================================================================

/// Sequential POSTs with different proxy IDs but the same listen_path:
/// the first must succeed, the second must be rejected by the listen_path
/// uniqueness check.
#[tokio::test]
async fn post_overlapping_listen_path_second_rejected() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let listen_path = format!("/{}", uid("shared-path"));
    let spec_a = json!({
        "openapi": "3.1.0",
        "info": {"title": "A", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": uid("proxy-a"),
            "backend_host": "a.internal",
            "backend_port": 443,
            "listen_path": &listen_path
        }
    });
    let spec_b = json!({
        "openapi": "3.1.0",
        "info": {"title": "B", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": uid("proxy-b"),
            "backend_host": "b.internal",
            "backend_port": 443,
            "listen_path": &listen_path
        }
    });

    let (status_a, _) = client.post_json("/api-specs", &spec_a).await;
    assert_eq!(
        status_a,
        reqwest::StatusCode::CREATED,
        "first POST must succeed"
    );

    let (status_b, _) = client.post_json("/api-specs", &spec_b).await;
    assert!(
        status_b == reqwest::StatusCode::CONFLICT
            || status_b == reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "second POST with same listen_path must be rejected; got {status_b}"
    );
}

// ============================================================================
// Test coverage gap — Accept: application/yaml GET
// ============================================================================

/// GET with `Accept: application/yaml` must return YAML content, not JSON.
#[tokio::test]
async fn get_with_accept_yaml_returns_yaml() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let (status, body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(status, reqwest::StatusCode::CREATED);
    let spec_id = body["id"].as_str().expect("spec id must be present");

    // GET with Accept: application/yaml
    let (status, bytes, headers) = client
        .get_raw(
            &format!("/api-specs/{spec_id}"),
            Some("application/yaml"),
            None,
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);

    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("yaml"),
        "Content-Type must be YAML when Accept: application/yaml; got: {ct}"
    );

    // Body must parse as YAML.
    let yaml_str = String::from_utf8(bytes).expect("response must be valid UTF-8");
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(&yaml_str).expect("response must be valid YAML");
    assert!(!parsed.is_null(), "parsed YAML must be non-null");
}

// ============================================================================
// Test coverage gap — CP→DP distribution excludes api_specs
// ============================================================================

/// The hot-path isolation invariant: a GatewayConfig loaded from the DB must
/// NOT contain api_specs data, and api_spec_id must be stripped from all
/// resources.  This verifies the contract that CP→DP gRPC distribution
/// (which serializes GatewayConfig) never leaks spec metadata to DPs.
#[tokio::test]
async fn loaded_gateway_config_excludes_api_specs_after_submission() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store.clone(), 25)).await;
    let client = AdminClient::new(base);

    // Submit a spec with proxy + upstream + plugin.
    let proxy_id = uid("proxy");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Distribution Test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": &proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        },
        "x-ferrum-upstream": {
            "id": uid("upstream"),
            "targets": [{"host": "10.0.0.1", "port": 8080}]
        },
        "x-ferrum-plugins": [{
            "id": uid("plugin"),
            "plugin_name": "cors",
            "config": {"allowed_origins": ["*"]}
        }]
    });

    let (status, _) = client.post_json("/api-specs", &spec).await;
    assert_eq!(status, reqwest::StatusCode::CREATED);

    // Load the full GatewayConfig as the runtime/gRPC path would.
    let config = store
        .load_full_config("ferrum")
        .await
        .expect("load_full_config must succeed");

    // The config must contain the proxy (it's a real resource).
    assert!(
        config.proxies.iter().any(|p| p.id == proxy_id),
        "proxy must appear in loaded config"
    );

    // But api_spec_id must be stripped from every resource.
    for p in &config.proxies {
        assert!(
            p.api_spec_id.is_none(),
            "proxy {}: api_spec_id must be None in GatewayConfig; got {:?}",
            p.id,
            p.api_spec_id
        );
    }
    for u in &config.upstreams {
        assert!(
            u.api_spec_id.is_none(),
            "upstream {}: api_spec_id must be None in GatewayConfig; got {:?}",
            u.id,
            u.api_spec_id
        );
    }
    for pc in &config.plugin_configs {
        assert!(
            pc.api_spec_id.is_none(),
            "plugin_config {}: api_spec_id must be None in GatewayConfig; got {:?}",
            pc.id,
            pc.api_spec_id
        );
    }

    // Serialize config to JSON and verify no "api_specs" key appears.
    let config_json = serde_json::to_value(&config).expect("config serialization");
    assert!(
        config_json.get("api_specs").is_none(),
        "GatewayConfig JSON must not contain an api_specs key — this would leak to DPs via gRPC"
    );
}

// ============================================================================
// Follow-up coverage from PR #526 review
// ============================================================================

/// Empty body (0 bytes) must return a parse error, not panic.
#[tokio::test]
async fn post_empty_body_returns_400() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let (status, body) = client
        .post_raw("/api-specs", vec![], "application/json")
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "empty body must be rejected as a parse error; body: {body}"
    );
}

/// Irrelevant Accept header (text/html) must still return a response
/// (RFC 7231 permits serving any representation when no Accept rules match
/// our supported formats).
#[tokio::test]
async fn get_with_irrelevant_accept_returns_stored_format() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let (status, body) = client
        .post_json("/api-specs", &minimal_json_spec(&proxy_id))
        .await;
    assert_eq!(status, reqwest::StatusCode::CREATED);
    let spec_id = body["id"].as_str().unwrap();

    // text/html is not a known format — server should default to stored.
    let (status, _bytes, headers) = client
        .get_raw(&format!("/api-specs/{spec_id}"), Some("text/html"), None)
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "unsupported Accept must not return 406; server should default to stored format"
    );
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("json"),
        "stored format is JSON, so Content-Type must be JSON; got: {ct}"
    );
}

/// YAML with anchor/alias syntax must be rejected at parse time.
#[tokio::test]
async fn post_yaml_with_anchor_alias_returns_400() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let yaml_with_anchor = r#"openapi: "3.1.0"
info:
  title: &title Bomb Test
  version: "1.0.0"
x-ferrum-proxy:
  id: anchor-test
  backend_host: backend.internal
  backend_port: 443
  listen_path: /anchor-test
alias_ref: *title
"#;

    let (status, body) = client.post_yaml("/api-specs", yaml_with_anchor).await;
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "YAML with anchor/alias must be rejected; body: {body}"
    );
    let details = body["details"].as_str().unwrap_or("");
    assert!(
        details.contains("anchor") || details.contains("alias"),
        "error must mention anchor/alias; got: {details}"
    );
}

/// Combined list filters must work together (regression for multi-clause SQL).
#[tokio::test]
async fn list_with_combined_filters() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    // Submit two specs with different titles and tags.
    let proxy_id_a = uid("proxy");
    let spec_a = json!({
        "openapi": "3.1.0",
        "info": {"title": "Orders Service", "version": "1.0.0"},
        "tags": [{"name": "public"}],
        "x-ferrum-proxy": {
            "id": &proxy_id_a,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id_a}")
        }
    });
    let (s1, _) = client.post_json("/api-specs", &spec_a).await;
    assert_eq!(s1, reqwest::StatusCode::CREATED);

    let proxy_id_b = uid("proxy");
    let spec_b = json!({
        "openapi": "3.0.3",
        "info": {"title": "Users Service", "version": "2.0.0"},
        "tags": [{"name": "internal"}],
        "x-ferrum-proxy": {
            "id": &proxy_id_b,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id_b}")
        }
    });
    let (s2, _) = client.post_json("/api-specs", &spec_b).await;
    assert_eq!(s2, reqwest::StatusCode::CREATED);

    // Combined: title_contains=Orders AND spec_version=3.1 → only spec_a
    let (status, body) = client
        .get_json("/api-specs?title_contains=Orders&spec_version=3.1")
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let items = body["items"].as_array().expect("items must be array");
    assert_eq!(
        items.len(),
        1,
        "combined filter must return exactly one match; got: {items:?}"
    );
    assert_eq!(items[0]["title"].as_str(), Some("Orders Service"));
}

/// Case-insensitive Content-Type must work end-to-end.
#[tokio::test]
async fn post_with_uppercase_content_type_succeeds() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let spec = minimal_json_spec(&proxy_id);
    let body_bytes = serde_json::to_vec(&spec).unwrap();

    // Send with mixed-case Content-Type.
    let (status, _body) = client
        .post_raw("/api-specs", body_bytes, "Application/JSON")
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "mixed-case Content-Type must be accepted per RFC 7231"
    );
}

/// Duplicate plugin IDs in a spec must be rejected at extraction time.
#[tokio::test]
async fn post_with_duplicate_plugin_ids_returns_error() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(make_admin_state(store, 25)).await;
    let client = AdminClient::new(base);

    let proxy_id = uid("proxy");
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "Dup Plugin Test", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": &proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        },
        "x-ferrum-plugins": [
            {
                "id": "same-id",
                "plugin_name": "cors",
                "config": {"allowed_origins": ["*"]}
            },
            {
                "id": "same-id",
                "plugin_name": "compression",
                "config": {}
            }
        ]
    });

    let (status, body) = client.post_json("/api-specs", &spec).await;
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "duplicate plugin IDs must be rejected as malformed extension; body: {body}"
    );
    let details = body["details"].as_str().unwrap_or("");
    assert!(
        details.contains("duplicate plugin id"),
        "error must mention duplicate plugin id; got: {details}"
    );
}
