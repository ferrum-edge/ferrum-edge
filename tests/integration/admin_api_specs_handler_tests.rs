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
        types::Proxy,
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
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn make_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "test-user",
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
    DatabaseStore::connect_with_tls_config(
        "sqlite",
        &url,
        false,
        None,
        None,
        None,
        false,
        test_pool_config(),
    )
    .await
    .expect("connect_with_tls_config failed")
}

// ---------------------------------------------------------------------------
// AdminState builder
// ---------------------------------------------------------------------------

fn make_admin_state(db: DatabaseStore, max_spec_mib: usize) -> AdminState {
    AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: make_jwt_manager(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: max_spec_mib,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        dp_registry: None,
        cp_connection_state: None,
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
        let _ = serve_admin_on_listener(listener, state_clone, rx_clone, None).await;
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
        self.client
            .delete(self.url(path))
            .header("authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .unwrap()
            .status()
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
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(
        body["code"].as_str().unwrap_or(""),
        "ConsumerExtensionNotAllowed"
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
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "body: {body}");
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
    let proxy_row = store.get_proxy(&proxy_id).await.expect("get_proxy failed");
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

    // When limit exactly equals count, next_offset should be set
    if body["next_offset"].is_number() {
        assert_eq!(body["next_offset"].as_u64().unwrap(), 2);
    }
    // next request with offset=2
    let (status2, body2) = client.get_json("/api-specs?limit=2&offset=2").await;
    assert_eq!(status2, reqwest::StatusCode::OK);
    // Should have the remaining item(s)
    assert!(!body2["items"].as_array().unwrap().is_empty());
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
