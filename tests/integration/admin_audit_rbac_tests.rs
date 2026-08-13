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
        types::{PluginConfig, PluginScope},
    },
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "test-secret-key-for-admin-audit-rbac-32chars";
const JWT_ISSUER: &str = "test-ferrum-edge";

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
        .join(format!("audit-{}.db", uuid::Uuid::new_v4()));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, test_pool_config())
        .await
        .expect("connect sqlite store")
}

fn admin_state_with_audit(db: DatabaseStore, admin_audit_enabled: bool) -> AdminState {
    AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled,
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
    admin_state_with_audit(db, true)
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

fn upstream_payload(id: &str) -> Value {
    json!({
        "id": id,
        "name": format!("upstream-{id}"),
        "targets": [
            {"host": "10.0.0.10", "port": 8080, "weight": 100}
        ],
        "algorithm": "round_robin"
    })
}

async fn post_json(base: &str, path: &str, bearer: &str, body: &Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(bearer)
        .json(body)
        .send()
        .await
        .expect("POST request");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn post_raw(base: &str, path: &str, bearer: &str, body: Vec<u8>) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(bearer)
        .body(body)
        .send()
        .await
        .expect("POST request");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn get_json(base: &str, path: &str, bearer: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .get(format!("{base}{path}"))
        .bearer_auth(bearer)
        .send()
        .await
        .expect("GET request");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn wait_for_audit_total(base: &str, path: &str, bearer: &str, expected: u64) -> Value {
    let mut last_body = json!({});
    let mut last_status = 0;
    for _ in 0..100 {
        let (status, body) = get_json(base, path, bearer).await;
        last_status = status;
        last_body = body;
        if status == 200 && last_body["total"].as_u64() == Some(expected) {
            return last_body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!(
        "audit list did not reach total={expected}; last status={last_status}, body={last_body:?}"
    );
}

#[tokio::test]
async fn viewer_role_is_rejected_on_admin_mutation() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;

    let viewer = token("view-only", Some("viewer"));
    let (status, body) =
        post_json(&base, "/upstreams", &viewer, &upstream_payload("rbac-u1")).await;

    assert_eq!(status, 403, "viewer mutation body: {body:?}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("required role is 'operator'"),
        "unexpected RBAC error body: {body:?}"
    );
}

#[tokio::test]
async fn token_without_role_claim_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;

    let no_role = token("legacy-token", None);
    let (status, body) = get_json(&base, "/upstreams", &no_role).await;

    assert_eq!(status, 401, "missing-role token body: {body:?}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Missing admin role claim"),
        "unexpected missing-role error body: {body:?}"
    );
}

#[tokio::test]
async fn non_admin_cannot_read_backup_unredacted_credentials() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;

    let viewer = token("view-only", Some("viewer"));
    let (status, body) = get_json(&base, "/backup", &viewer).await;
    assert_eq!(status, 403, "viewer backup body: {body:?}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("required role is 'admin'"),
        "unexpected RBAC error body: {body:?}"
    );

    let operator = token("op-user", Some("operator"));
    let (status, body) = get_json(&base, "/backup", &operator).await;
    assert_eq!(status, 403, "operator backup body: {body:?}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("required role is 'admin'"),
        "unexpected RBAC error body: {body:?}"
    );

    let admin = token("security-admin", Some("admin"));
    let (status, _body) = get_json(&base, "/backup", &admin).await;
    assert_eq!(status, 200, "admin backup must succeed");
}

#[tokio::test]
async fn audit_rbac_precedes_route_local_pagination_validation() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;

    let viewer = token("view-only", Some("viewer"));
    let (status, body) = get_json(&base, "/audit?limit=abc", &viewer).await;
    assert_eq!(status, 403, "audit RBAC must precede pagination: {body:?}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("required role is 'admin'"),
        "unexpected RBAC error body: {body:?}"
    );
}

#[tokio::test]
async fn viewer_restore_is_rejected_before_large_body_buffering() {
    let tmp = TempDir::new().unwrap();
    let mut state = admin_state(make_store(&tmp).await);
    state.admin_restore_max_body_size_mib = 0;
    let (base, _shutdown) = start_admin(state).await;

    let viewer = token("view-only", Some("viewer"));
    let (status, body) = post_raw(
        &base,
        "/restore?confirm=true",
        &viewer,
        br#"{"version":"1","proxies":[]}"#.to_vec(),
    )
    .await;

    assert_eq!(status, 403, "viewer restore body: {body:?}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("required role is 'admin'"),
        "unexpected RBAC error body: {body:?}"
    );
}

/// `/batch` and `/restore` are the two bulk-write routes whose handlers carry no
/// role check of their own, so their `admin` requirement has to hold from the
/// route arm as well as from the pre-body admission gate. An `operator` may
/// create a proxy or an upstream one at a time; neither of these is a permitted
/// escalation of that.
#[tokio::test]
async fn operator_cannot_bulk_write_through_batch_or_restore() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;

    let operator = token("op-user", Some("operator"));
    for path in ["/batch", "/restore?confirm=true"] {
        let (status, body) = post_raw(
            &base,
            path,
            &operator,
            br#"{"version":"1","proxies":[]}"#.to_vec(),
        )
        .await;
        assert_eq!(status, 403, "operator {path} body: {body:?}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("required role is 'admin'"),
            "unexpected RBAC error body for {path}: {body:?}"
        );
    }
}

#[tokio::test]
async fn upstream_mutation_writes_queryable_audit_event() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let operator = token("mesh-operator", Some("operator"));
    let admin = token("security-admin", Some("admin"));

    let (status, body) = post_json(
        &base,
        "/upstreams",
        &operator,
        &upstream_payload("audit-u1"),
    )
    .await;
    assert_eq!(status, 201, "upstream create failed: {body:?}");

    let audit_body = wait_for_audit_total(&base, "/audit?resource_type=upstream", &admin, 1).await;
    assert_eq!(audit_body["total"], 1);

    let items = audit_body["items"].as_array().expect("audit items");
    let event = &items[0];
    assert_eq!(event["actor"], "mesh-operator");
    assert_eq!(event["action"], "create");
    assert_eq!(event["resource_type"], "upstream");
    assert_eq!(event["resource_id"], "audit-u1");
    assert_eq!(event["namespace"], "ferrum");
    assert_eq!(event["diff"]["after"]["id"], "audit-u1");
}

#[tokio::test]
async fn disabled_admin_audit_skips_mutation_events() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state_with_audit(make_store(&tmp).await, false);
    let (base, _shutdown) = start_admin(state).await;
    let operator = token("mesh-operator", Some("operator"));
    let admin = token("security-admin", Some("admin"));

    let (status, body) = post_json(
        &base,
        "/upstreams",
        &operator,
        &upstream_payload("audit-disabled-u1"),
    )
    .await;
    assert_eq!(status, 201, "upstream create failed: {body:?}");

    let (status, audit_body) = get_json(&base, "/audit?resource_type=upstream", &admin).await;
    assert_eq!(status, 200, "audit list failed: {audit_body:?}");
    assert_eq!(audit_body["total"], 0);
}

#[tokio::test]
async fn plugin_config_audit_diff_redacts_sensitive_config_fields() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));

    let secret_key = "super-secret-load-test-key-0123456789!";
    let plugin = json!({
        "id": "audit-plugin-secret",
        "plugin_name": "load_testing",
        "scope": "global",
        "config": {
            "key": secret_key,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "ramp": true
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(status, 201, "plugin create failed: {body:?}");
    assert_eq!(body["config"]["key"], secret_key);

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=plugin_config&resource_id=audit-plugin-secret",
        &admin,
        1,
    )
    .await;
    let event = &audit_body["items"].as_array().expect("audit items")[0];
    assert_eq!(event["diff"]["after"]["config"]["key"], "[REDACTED]");
    assert_eq!(event["diff"]["after"]["config"]["ramp"], true);
    assert_eq!(event["diff"]["after"]["config"]["concurrent_clients"], 1);
    assert_eq!(event["diff"]["after"]["config"]["duration_seconds"], 1);
    let serialized = event["diff"].to_string();
    assert!(
        !serialized.contains(secret_key),
        "secret key leaked: {event:?}"
    );
}

#[tokio::test]
async fn non_admin_plugin_config_reads_redact_sensitive_fields() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));
    let operator = token("mesh-operator", Some("operator"));

    let secret_key = "read-secret-load-test-key-0123456789!";
    let plugin = json!({
        "id": "read-plugin-secret",
        "plugin_name": "load_testing",
        "scope": "global",
        "config": {
            "key": secret_key,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "ramp": true
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(status, 201, "plugin create failed: {body:?}");

    let (status, viewer_body) =
        get_json(&base, "/plugins/config/read-plugin-secret", &viewer).await;
    assert_eq!(status, 200, "viewer plugin get failed: {viewer_body:?}");
    assert_eq!(viewer_body["config"]["key"], "[REDACTED]");
    assert_eq!(viewer_body["config"]["ramp"], true);
    assert_eq!(viewer_body["config"]["concurrent_clients"], 1);
    assert!(
        !viewer_body.to_string().contains(secret_key),
        "viewer response leaked plugin secret: {viewer_body:?}"
    );

    let (status, operator_body) =
        get_json(&base, "/plugins/config/read-plugin-secret", &operator).await;
    assert_eq!(status, 200, "operator plugin get failed: {operator_body:?}");
    assert_eq!(operator_body["config"]["key"], "[REDACTED]");
    assert_eq!(operator_body["config"]["ramp"], true);

    let (status, admin_body) = get_json(&base, "/plugins/config/read-plugin-secret", &admin).await;
    assert_eq!(status, 200, "admin plugin get failed: {admin_body:?}");
    assert_eq!(admin_body["config"]["key"], secret_key);
    assert_eq!(admin_body["config"]["ramp"], true);

    let (status, list_body) = get_json(&base, "/plugins/config", &viewer).await;
    assert_eq!(status, 200, "viewer plugin list failed: {list_body:?}");
    assert_eq!(list_body["data"][0]["config"]["key"], "[REDACTED]");
    assert_eq!(list_body["data"][0]["config"]["ramp"], true);
}

/// `ai_semantic_cache` in Redis mode carries two distinct secrets that a
/// Viewer/Operator read and every audit diff must not disclose:
///
/// * `redis_integrity_key` — the HMAC-SHA256 secret that authenticates Redis
///   cache envelopes. Disclosure lets any reader forge an envelope that the
///   gateway will replay as a cache hit, so it is redacted wholesale.
/// * `redis_url` credentials — Redis ACL credentials are documented as
///   encodable in the URL (`redis://user:pass@host`). Userinfo is replaced and
///   query/fragment data is removed; scheme/host/port/database stay visible as
///   bounded diagnostics.
///
/// Full-Admin reads stay raw so rotation via read-modify-write keeps working.
#[tokio::test]
async fn redis_backed_plugin_secrets_are_redacted_for_non_admins_and_audit() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));
    let operator = token("mesh-operator", Some("operator"));

    let integrity_key = "redis-integrity-secret-0123456789abcdef";
    let redis_password = "redis-acl-password-0123456789";
    let redis_query_secret = "query-secret-0123456789";
    let redis_fragment_secret = "fragment-secret-0123456789";
    let redis_url = format!(
        "redis://cacheuser:{redis_password}@cache.internal:6379/3?token={redis_query_secret}#{redis_fragment_secret}"
    );
    let plugin = json!({
        "id": "redis-cache-secret",
        "plugin_name": "ai_semantic_cache",
        "scope": "global",
        "config": {
            "sync_mode": "redis",
            "redis_url": &redis_url,
            "redis_integrity_key": integrity_key,
            "ttl_seconds": 60
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(status, 201, "plugin create failed: {body:?}");

    let expected_url = "redis://redacted@cache.internal:6379/3";

    for (role, actor) in [("viewer", &viewer), ("operator", &operator)] {
        let (status, projected) =
            get_json(&base, "/plugins/config/redis-cache-secret", actor).await;
        assert_eq!(status, 200, "{role} plugin get failed: {projected:?}");
        assert_eq!(
            projected["config"]["redis_integrity_key"], "[REDACTED]",
            "{role} read exposed the Redis integrity key: {projected:?}"
        );
        assert_eq!(
            projected["config"]["redis_url"], expected_url,
            "{role} read did not strip Redis URL userinfo: {projected:?}"
        );
        // Non-secret diagnostics survive the projection.
        assert_eq!(projected["config"]["ttl_seconds"], 60);
        assert_eq!(projected["config"]["sync_mode"], "redis");
        let serialized = projected.to_string();
        assert!(
            !serialized.contains(integrity_key)
                && !serialized.contains(redis_password)
                && !serialized.contains(redis_query_secret)
                && !serialized.contains(redis_fragment_secret),
            "{role} response leaked Redis secret material: {projected:?}"
        );
    }

    let (status, list_body) = get_json(&base, "/plugins/config", &viewer).await;
    assert_eq!(status, 200, "viewer plugin list failed: {list_body:?}");
    let serialized = list_body.to_string();
    assert!(
        !serialized.contains(integrity_key)
            && !serialized.contains(redis_password)
            && !serialized.contains(redis_query_secret)
            && !serialized.contains(redis_fragment_secret),
        "viewer list leaked Redis secret material: {list_body:?}"
    );
    assert_eq!(list_body["data"][0]["config"]["redis_url"], expected_url);
    assert_eq!(
        list_body["data"][0]["config"]["redis_integrity_key"],
        "[REDACTED]"
    );

    // Full Admin still sees the raw values so rotation by read-modify-write works.
    let (status, admin_body) = get_json(&base, "/plugins/config/redis-cache-secret", &admin).await;
    assert_eq!(status, 200, "admin plugin get failed: {admin_body:?}");
    assert_eq!(admin_body["config"]["redis_integrity_key"], integrity_key);
    assert_eq!(admin_body["config"]["redis_url"], redis_url);

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=plugin_config&resource_id=redis-cache-secret",
        &admin,
        1,
    )
    .await;
    let event = &audit_body["items"].as_array().expect("audit items")[0];
    assert_eq!(
        event["diff"]["after"]["config"]["redis_integrity_key"],
        "[REDACTED]"
    );
    assert_eq!(event["diff"]["after"]["config"]["redis_url"], expected_url);
    let serialized = event["diff"].to_string();
    assert!(
        !serialized.contains(integrity_key)
            && !serialized.contains(redis_password)
            && !serialized.contains(redis_query_secret)
            && !serialized.contains(redis_fragment_secret),
        "audit diff leaked Redis secret material: {event:?}"
    );
}

#[tokio::test]
async fn nested_provider_credentials_are_recursively_redacted() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));

    let provider_api_key = "nested-provider-api-key-canary";
    let plugin = json!({
        "id": "nested-provider-redaction",
        "plugin_name": "ai_federation",
        "scope": "global",
        "config": {
            "providers": [{
                "name": "redaction-provider",
                "provider_type": "openai",
                "api_key": provider_api_key,
                "model_patterns": ["gpt-*"]
            }]
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(status, 201, "plugin create failed: {body:?}");
    assert_eq!(body["config"]["providers"][0]["api_key"], provider_api_key);

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=plugin_config&resource_id=nested-provider-redaction",
        &admin,
        1,
    )
    .await;
    let audit_config =
        &audit_body["items"].as_array().expect("audit items")[0]["diff"]["after"]["config"];
    assert_eq!(audit_config["providers"][0]["api_key"], "[REDACTED]");
    assert_eq!(audit_config["providers"][0]["name"], "redaction-provider");
    assert_eq!(audit_config["providers"][0]["model_patterns"][0], "gpt-*");

    let (status, viewer_body) =
        get_json(&base, "/plugins/config/nested-provider-redaction", &viewer).await;
    assert_eq!(status, 200, "viewer plugin get failed: {viewer_body:?}");
    assert_eq!(
        viewer_body["config"]["providers"][0]["api_key"],
        "[REDACTED]"
    );
    assert_eq!(
        viewer_body["config"]["providers"][0]["name"],
        "redaction-provider"
    );

    let (status, admin_body) =
        get_json(&base, "/plugins/config/nested-provider-redaction", &admin).await;
    assert_eq!(status, 200, "admin plugin get failed: {admin_body:?}");
    assert_eq!(
        admin_body["config"]["providers"][0]["api_key"],
        provider_api_key
    );

    let projected = format!("{audit_config:?}{viewer_body:?}");
    assert!(
        !projected.contains(provider_api_key),
        "nested provider credential leaked: {projected}"
    );
}

#[tokio::test]
async fn serverless_config_audit_and_non_admin_reads_redact_url_credentials() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));
    let trigger_secret = "signed-trigger-secret";
    let function_key = "azure-function-key-secret";
    let plugin = json!({
        "id": "serverless-redaction",
        "plugin_name": "serverless_function",
        "scope": "global",
        "config": {
            "provider": "azure_functions",
            "function_url": format!(
                "https://functions.example/private/{trigger_secret}?code={trigger_secret}"
            ),
            "azure_function_key": function_key
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(status, 201, "plugin create failed: {body:?}");

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=plugin_config&resource_id=serverless-redaction",
        &admin,
        1,
    )
    .await;
    let event = &audit_body["items"].as_array().expect("audit items")[0];
    assert_eq!(
        event["diff"]["after"]["config"]["function_url"],
        "https://functions.example/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(
        event["diff"]["after"]["config"]["azure_function_key"],
        "[REDACTED]"
    );

    let (status, viewer_body) =
        get_json(&base, "/plugins/config/serverless-redaction", &viewer).await;
    assert_eq!(status, 200, "viewer plugin get failed: {viewer_body:?}");
    assert_eq!(
        viewer_body["config"]["function_url"],
        "https://functions.example/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(viewer_body["config"]["azure_function_key"], "[REDACTED]");
    let serialized = format!("{event:?}{viewer_body:?}");
    assert!(!serialized.contains(trigger_secret));
    assert!(!serialized.contains(function_key));
}

#[tokio::test]
async fn malformed_persisted_serverless_url_is_wholly_redacted_from_views_and_audit() {
    let tmp = TempDir::new().unwrap();
    let store = make_store(&tmp).await;
    let nested_secret = "nested-signed-trigger-secret";
    let plugin_id = "malformed-serverless-redaction";
    store
        .create_plugin_config(&PluginConfig {
            id: plugin_id.to_string(),
            plugin_name: "serverless_function".to_string(),
            namespace: "ferrum".to_string(),
            config: json!({
                "provider": "azure_functions",
                "function_url": [
                    null,
                    {"nested": format!("https://functions.example/run?code={nested_secret}")}
                ]
            }),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .await
        .expect("persist malformed legacy plugin config");

    let state = admin_state(store);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));

    let (status, viewer_body) =
        get_json(&base, &format!("/plugins/config/{plugin_id}"), &viewer).await;
    assert_eq!(status, 200, "viewer plugin get failed: {viewer_body:?}");
    assert_eq!(viewer_body["config"]["function_url"], "[REDACTED]");
    assert!(!viewer_body.to_string().contains(nested_secret));

    let response = reqwest::Client::new()
        .delete(format!("{base}/plugins/config/{plugin_id}"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("delete malformed persisted plugin config");
    assert_eq!(response.status().as_u16(), 204);

    let audit_body = wait_for_audit_total(
        &base,
        &format!("/audit?resource_type=plugin_config&resource_id={plugin_id}"),
        &admin,
        1,
    )
    .await;
    let event = &audit_body["items"].as_array().expect("audit items")[0];
    assert_eq!(
        event["diff"]["before"]["config"]["function_url"],
        "[REDACTED]"
    );
    assert!(
        !event["diff"].to_string().contains(nested_secret),
        "malformed nested function URL leaked into audit: {event:?}"
    );
}

#[tokio::test]
async fn loki_config_projection_redacts_endpoint_and_all_header_credentials() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));
    let operator = token("mesh-operator", Some("operator"));

    let path_secret = "loki-private-path-canary";
    let query_secret = "loki-query-canary";
    let auth_secret = "loki-auth-canary";
    let tenant_secret = "loki-tenant-canary";
    let arbitrary_header_secret = "loki-arbitrary-header-canary";
    let endpoint = format!(
        "https://logs.example.com/{path_secret}/loki/api/v1/push?tenant_key={query_secret}"
    );
    let plugin = json!({
        "id": "loki-redaction-config",
        "plugin_name": "loki_logging",
        "scope": "global",
        "config": {
            "endpoint_url": endpoint,
            "authorization_header": format!("Bearer {auth_secret}"),
            "custom_headers": {
                "X-Scope-OrgID": tenant_secret,
                "X-Arbitrary": arbitrary_header_secret
            }
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(status, 201, "Loki plugin create failed: {body:?}");
    assert_eq!(body["config"]["endpoint_url"], endpoint);
    assert_eq!(
        body["config"]["authorization_header"],
        format!("Bearer {auth_secret}")
    );

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=plugin_config&resource_id=loki-redaction-config",
        &admin,
        1,
    )
    .await;
    let audit_config =
        &audit_body["items"].as_array().expect("audit items")[0]["diff"]["after"]["config"];
    assert_loki_config_projection_redacted(audit_config);

    for bearer in [&viewer, &operator] {
        let (status, projected) =
            get_json(&base, "/plugins/config/loki-redaction-config", bearer).await;
        assert_eq!(
            status, 200,
            "projected Loki config read failed: {projected:?}"
        );
        assert_loki_config_projection_redacted(&projected["config"]);
    }

    let (status, list) = get_json(&base, "/plugins/config", &viewer).await;
    assert_eq!(status, 200, "viewer Loki config list failed: {list:?}");
    let listed = list["data"]
        .as_array()
        .expect("plugin list data")
        .iter()
        .find(|item| item["id"] == "loki-redaction-config")
        .expect("listed Loki config");
    assert_loki_config_projection_redacted(&listed["config"]);

    let (status, raw) = get_json(&base, "/plugins/config/loki-redaction-config", &admin).await;
    assert_eq!(status, 200, "admin Loki config read failed: {raw:?}");
    assert_eq!(raw["config"]["endpoint_url"], endpoint);
    assert_eq!(
        raw["config"]["custom_headers"]["X-Scope-OrgID"],
        tenant_secret
    );

    for projection in [audit_config, &listed["config"]] {
        let serialized = projection.to_string();
        for secret in [
            path_secret,
            query_secret,
            auth_secret,
            tenant_secret,
            arbitrary_header_secret,
        ] {
            assert!(
                !serialized.contains(secret),
                "Loki config projection leaked {secret}: {serialized}"
            );
        }
    }
}

fn assert_loki_config_projection_redacted(config: &Value) {
    assert_eq!(
        config["endpoint_url"],
        "https://logs.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(config["authorization_header"], "[REDACTED]");
    assert_eq!(config["custom_headers"]["X-Scope-OrgID"], "[REDACTED]");
    assert_eq!(config["custom_headers"]["X-Arbitrary"], "[REDACTED]");
}

#[tokio::test]
async fn otel_tracing_config_projections_redact_endpoint_auth_and_headers() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));

    let path_secret = "otel-path-canary";
    let query_secret = "otel-query-canary";
    let auth_secret = "otel-auth-canary";
    let header_secret = "otel-header-canary";
    let endpoint =
        format!("https://collector.example.com/{path_secret}/v1/traces?api_key={query_secret}");
    let plugin = json!({
        "id": "otel-redaction-config",
        "plugin_name": "otel_tracing",
        "scope": "global",
        "config": {
            "endpoint": endpoint,
            "authorization": format!("Bearer {auth_secret}"),
            "headers": {
                "x-honeycomb-team": header_secret
            }
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(status, 201, "otel plugin create failed: {body:?}");
    assert_eq!(body["config"]["endpoint"], endpoint);

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=plugin_config&resource_id=otel-redaction-config",
        &admin,
        1,
    )
    .await;
    let audit_config =
        &audit_body["items"].as_array().expect("audit items")[0]["diff"]["after"]["config"];
    assert_otel_config_projection_redacted(audit_config);

    let (status, projected) =
        get_json(&base, "/plugins/config/otel-redaction-config", &viewer).await;
    assert_eq!(status, 200, "viewer otel config read failed: {projected:?}");
    assert_otel_config_projection_redacted(&projected["config"]);

    let (status, list) = get_json(&base, "/plugins/config", &viewer).await;
    assert_eq!(status, 200, "viewer otel config list failed: {list:?}");
    let listed = list["data"]
        .as_array()
        .expect("plugin list data")
        .iter()
        .find(|item| item["id"] == "otel-redaction-config")
        .expect("listed otel config");
    assert_otel_config_projection_redacted(&listed["config"]);

    let (status, raw) = get_json(&base, "/plugins/config/otel-redaction-config", &admin).await;
    assert_eq!(status, 200, "admin otel config read failed: {raw:?}");
    assert_eq!(raw["config"]["endpoint"], endpoint);
    assert_eq!(
        raw["config"]["authorization"],
        format!("Bearer {auth_secret}")
    );
    assert_eq!(raw["config"]["headers"]["x-honeycomb-team"], header_secret);

    for projection in [audit_config, &projected["config"], &listed["config"]] {
        let serialized = projection.to_string();
        for secret in [path_secret, query_secret, auth_secret, header_secret] {
            assert!(
                !serialized.contains(secret),
                "otel config projection leaked {secret}: {serialized}"
            );
        }
    }
}

fn assert_otel_config_projection_redacted(config: &Value) {
    assert_eq!(
        config["endpoint"],
        "https://collector.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(config["authorization"], "[REDACTED]");
    assert_eq!(config["headers"]["x-honeycomb-team"], "[REDACTED]");
}

#[tokio::test]
async fn disabled_non_object_loki_configs_are_fully_redacted_across_projections() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));
    let operator = token("mesh-operator", Some("operator"));

    // A `null` config carries nothing to disclose and projects as `null`; every
    // other non-object shape is replaced wholesale because its interior cannot
    // be classified against the plugin schema. This is now uniform across all
    // plugins rather than a loki-only special case.
    for (shape, raw_config, expected) in [
        (
            "scalar",
            json!("loki-disabled-scalar-secret-canary"),
            json!("[REDACTED]"),
        ),
        (
            "array",
            json!(["loki-disabled-array-secret-canary", {"nested": "credential"}]),
            json!("[REDACTED]"),
        ),
        ("null", Value::Null, Value::Null),
    ] {
        let id = format!("loki-disabled-{shape}");
        let plugin = json!({
            "id": id,
            "plugin_name": "loki_logging",
            "scope": "global",
            "enabled": false,
            "config": raw_config
        });

        let (status, created) = post_json(&base, "/plugins/config", &admin, &plugin).await;
        assert_eq!(
            status, 201,
            "disabled {shape} Loki config create failed: {created:?}"
        );
        assert_eq!(created["config"], raw_config);

        let audit_body = wait_for_audit_total(
            &base,
            &format!("/audit?resource_type=plugin_config&resource_id={id}"),
            &admin,
            1,
        )
        .await;
        let audit_config =
            &audit_body["items"].as_array().expect("audit items")[0]["diff"]["after"]["config"];
        assert_eq!(audit_config, &expected);

        for bearer in [&viewer, &operator] {
            let (status, projected) =
                get_json(&base, &format!("/plugins/config/{id}"), bearer).await;
            assert_eq!(
                status, 200,
                "projected disabled {shape} Loki config read failed: {projected:?}"
            );
            assert_eq!(projected["config"], expected);
        }

        let (status, raw) = get_json(&base, &format!("/plugins/config/{id}"), &admin).await;
        assert_eq!(
            status, 200,
            "admin disabled {shape} Loki config read failed: {raw:?}"
        );
        assert_eq!(raw["config"], raw_config);
    }
}

#[tokio::test]
async fn consumer_keyauth_audit_diff_redacts_plaintext_key() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));

    let consumer = json!({
        "id": "audit-keyauth-consumer",
        "username": "audit-keyauth-user",
        "credentials": {}
    });
    let (status, body) = post_json(&base, "/consumers", &admin, &consumer).await;
    assert_eq!(status, 201, "consumer create failed: {body:?}");
    // Audit persistence is asynchronous. Observe the consumer event before
    // starting another write so the two-connection SQLite pool does not race.
    wait_for_audit_total(
        &base,
        "/audit?resource_type=consumer&resource_id=audit-keyauth-consumer",
        &admin,
        1,
    )
    .await;

    let plaintext_key = "super-secret-keyauth-api-key-do-not-leak";
    let cred = json!([{ "key": plaintext_key }]);
    let response = reqwest::Client::new()
        .put(format!(
            "{base}/consumers/audit-keyauth-consumer/credentials/keyauth"
        ))
        .bearer_auth(&admin)
        .json(&cred)
        .send()
        .await
        .expect("PUT credentials");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    assert_eq!(status, 200, "PUT keyauth failed: {body:?}");

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=consumer_credentials&resource_id=audit-keyauth-consumer",
        &admin,
        1,
    )
    .await;
    let event = &audit_body["items"].as_array().expect("audit items")[0];
    assert_eq!(
        event["diff"]["after"]["credentials"]["keyauth"][0]["key"], "[REDACTED]",
        "keyauth key not redacted in audit diff: {event:?}"
    );
    let serialized = event["diff"].to_string();
    assert!(
        !serialized.contains(plaintext_key),
        "plaintext keyauth key leaked into audit diff: {event:?}"
    );
}

#[tokio::test]
async fn basic_credential_mutations_emit_shape_independent_audit_markers() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));

    let consumer = json!({
        "id": "audit-basic-consumer",
        "username": "audit-basic-user",
        "credentials": {}
    });
    let (status, body) = post_json(&base, "/consumers", &admin, &consumer).await;
    assert_eq!(status, 201, "consumer create failed: {body:?}");
    // Audit persistence is asynchronous. Observe each event before the next
    // mutation so the test's two-connection SQLite pool does not race writers.
    wait_for_audit_total(
        &base,
        "/audit?resource_type=consumer&resource_id=audit-basic-consumer",
        &admin,
        1,
    )
    .await;

    let old_hash = format!("hmac_sha256:{}", "a".repeat(64));
    let new_hash = format!("hmac_sha256:{}", "b".repeat(64));
    let client = reqwest::Client::new();
    let credential_audit_path =
        "/audit?resource_type=consumer_credentials&resource_id=audit-basic-consumer";

    let response = client
        .put(format!(
            "{base}/consumers/audit-basic-consumer/credentials/basicauth"
        ))
        .bearer_auth(&admin)
        .json(&json!([{"password_hash": old_hash.clone()}]))
        .send()
        .await
        .expect("PUT Basic credentials");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    assert_eq!(status, 200, "PUT Basic credentials failed: {body:?}");
    assert!(body["credentials"].get("basicauth").is_none());
    wait_for_audit_total(&base, credential_audit_path, &admin, 1).await;

    let response = client
        .post(format!(
            "{base}/consumers/audit-basic-consumer/credentials/basicauth"
        ))
        .bearer_auth(&admin)
        .json(&json!({"password_hash": new_hash.clone()}))
        .send()
        .await
        .expect("POST Basic credential");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    assert_eq!(status, 200, "POST Basic credential failed: {body:?}");
    assert!(body["credentials"].get("basicauth").is_none());
    wait_for_audit_total(&base, credential_audit_path, &admin, 2).await;

    let response = client
        .delete(format!(
            "{base}/consumers/audit-basic-consumer/credentials/basicauth/0"
        ))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("DELETE Basic credential by index");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    assert_eq!(status, 200, "DELETE Basic credential failed: {body:?}");
    assert!(body["credentials"].get("basicauth").is_none());
    wait_for_audit_total(&base, credential_audit_path, &admin, 3).await;

    let response = client
        .delete(format!(
            "{base}/consumers/audit-basic-consumer/credentials/basicauth"
        ))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("DELETE all Basic credentials");
    assert_eq!(response.status().as_u16(), 204);

    let audit_body = wait_for_audit_total(&base, credential_audit_path, &admin, 4).await;
    let items = audit_body["items"].as_array().expect("audit items");
    let actions: std::collections::HashSet<&str> = items
        .iter()
        .filter_map(|event| event["action"].as_str())
        .collect();
    assert_eq!(
        actions,
        std::collections::HashSet::from([
            "update_credentials",
            "append_credential",
            "delete_credential",
            "delete_credentials",
        ])
    );

    for event in items {
        assert_eq!(event["diff"]["credential_type"], "basicauth");
        assert_eq!(event["diff"]["credential_change"], "[REDACTED]");
        for side in ["before", "after"] {
            if let Some(marker) = event["diff"][side]["credentials"].get("basicauth") {
                assert_eq!(marker, "[REDACTED]");
            }
        }
        let serialized = event["diff"].to_string();
        assert!(!serialized.contains(&old_hash));
        assert!(!serialized.contains(&new_hash));
        assert!(!serialized.contains("password_hash"));
    }
}

#[tokio::test]
async fn upstream_consul_token_redacted_in_audit_diff() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));

    let consul_token = "super-secret-consul-acl-token-do-not-leak";
    let upstream = json!({
        "id": "audit-consul-upstream",
        "name": "upstream-consul",
        "targets": [
            {"host": "10.0.0.10", "port": 8080, "weight": 100}
        ],
        "algorithm": "round_robin",
        "service_discovery": {
            "provider": "consul",
            "consul": {
                "address": "http://consul.local:8500",
                "service_name": "my-service",
                "token": consul_token
            }
        }
    });

    let (status, body) = post_json(&base, "/upstreams", &admin, &upstream).await;
    assert_eq!(status, 201, "upstream create failed: {body:?}");

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=upstream&resource_id=audit-consul-upstream",
        &admin,
        1,
    )
    .await;
    let event = &audit_body["items"].as_array().expect("audit items")[0];
    assert_eq!(
        event["diff"]["after"]["service_discovery"]["consul"]["token"], "[REDACTED]",
        "consul ACL token not redacted in audit diff: {event:?}"
    );
    let serialized = event["diff"].to_string();
    assert!(
        !serialized.contains(consul_token),
        "plaintext consul token leaked into audit diff: {event:?}"
    );
}

#[tokio::test]
async fn non_admin_upstream_reads_redact_consul_token() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));
    let operator = token("mesh-operator", Some("operator"));

    let consul_token = "read-secret-consul-acl-token";
    let upstream = json!({
        "id": "read-consul-upstream",
        "name": "read-upstream-consul",
        "targets": [
            {"host": "10.0.0.10", "port": 8080, "weight": 100}
        ],
        "algorithm": "round_robin",
        "service_discovery": {
            "provider": "consul",
            "consul": {
                "address": "http://consul.local:8500",
                "service_name": "my-service",
                "token": consul_token
            }
        }
    });

    let (status, body) = post_json(&base, "/upstreams", &admin, &upstream).await;
    assert_eq!(status, 201, "upstream create failed: {body:?}");

    let (status, viewer_body) = get_json(&base, "/upstreams/read-consul-upstream", &viewer).await;
    assert_eq!(status, 200, "viewer upstream get failed: {viewer_body:?}");
    assert_eq!(
        viewer_body["service_discovery"]["consul"]["token"],
        "[REDACTED]"
    );
    assert!(
        !viewer_body.to_string().contains(consul_token),
        "viewer response leaked consul token: {viewer_body:?}"
    );

    let (status, operator_body) =
        get_json(&base, "/upstreams/read-consul-upstream", &operator).await;
    assert_eq!(
        status, 200,
        "operator upstream get failed: {operator_body:?}"
    );
    assert_eq!(
        operator_body["service_discovery"]["consul"]["token"],
        "[REDACTED]"
    );

    let (status, admin_body) = get_json(&base, "/upstreams/read-consul-upstream", &admin).await;
    assert_eq!(status, 200, "admin upstream get failed: {admin_body:?}");
    assert_eq!(
        admin_body["service_discovery"]["consul"]["token"],
        consul_token
    );
}

#[tokio::test]
async fn audit_list_rejects_offset_above_backend_range() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));

    let (status, body) = get_json(&base, "/audit?offset=4294967296", &admin).await;

    assert_eq!(status, 400, "oversized offset body: {body:?}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("offset"),
        "unexpected audit offset error body: {body:?}"
    );
}

#[tokio::test]
async fn audit_list_coerces_zero_limit_to_server_default() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));

    let (status, body) = get_json(&base, "/audit?limit=0", &admin).await;

    assert_eq!(status, 200, "zero limit body: {body:?}");
    // `/audit` shares the canonical pagination parser, so `limit=0` means the
    // documented server default (100) here exactly as it does on every other
    // list endpoint — it is no longer re-parsed into a 1-item clamp.
    assert_eq!(body["limit"], 100);
}

#[tokio::test]
async fn rejected_batch_mutation_writes_no_audit_event() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));

    let (status, body) = post_json(
        &base,
        "/upstreams",
        &admin,
        &upstream_payload("batch-duplicate-u1"),
    )
    .await;
    assert_eq!(status, 201, "upstream seed failed: {body:?}");

    // `POST /batch` is all-or-nothing (issue #2401): the duplicate upstream
    // rejects the whole graph, so the consumer ahead of it is never committed
    // and there is no mutation to attribute in the audit log. This used to be a
    // `207 Multi-Status` with the consumer durable.
    let batch = json!({
        "consumers": [{
            "id": "partial-batch-c1",
            "username": "partial-batch-user"
        }],
        "upstreams": [upstream_payload("batch-duplicate-u1")]
    });
    let (status, body) = post_json(&base, "/batch", &admin, &batch).await;
    assert_eq!(status, 409, "rejected batch body: {body:?}");
    assert!(
        body.get("created").is_none(),
        "a rejected atomic batch must not report created counts: {body:?}"
    );

    let (status, consumer) = get_json(&base, "/consumers/partial-batch-c1", &admin).await;
    assert_eq!(
        status, 404,
        "the consumer ahead of the duplicate must not survive: {consumer:?}"
    );

    let (status, audit_body) = get_json(
        &base,
        "/audit?resource_type=gateway_config&action=batch_create",
        &admin,
    )
    .await;
    assert_eq!(status, 200, "audit read failed: {audit_body:?}");
    assert_eq!(
        audit_body["total"], 0,
        "a fully rejected batch must not write a batch_create audit event: {audit_body:?}"
    );
}

/// GHSA-4988-2wph-67g2: an HTTP log sink's endpoint may carry collector
/// credentials in its path/query (documented in `docs/plugins.md`), and its
/// `custom_headers` map accepts arbitrary vendor authentication header names
/// that match no substring pattern. Neither may reach a non-admin read, an
/// audit diff, or a list projection.
#[tokio::test]
async fn http_logging_endpoint_and_custom_header_credentials_are_projected() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));
    let operator = token("mesh-operator", Some("operator"));

    let path_secret = "httplog-path-canary";
    let query_secret = "httplog-query-canary";
    let vendor_secret = "httplog-honeycomb-canary";
    let tenant_secret = "httplog-tenant-canary";
    let endpoint =
        format!("https://collector.example.com/{path_secret}/ingest?api_key={query_secret}");
    let plugin = json!({
        "id": "http-logging-redaction",
        "plugin_name": "http_logging",
        "scope": "global",
        "config": {
            "endpoint_url": endpoint,
            "custom_headers": {
                "x-honeycomb-team": vendor_secret,
                "X-Tenant": tenant_secret
            },
            "batch_size": 50
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(status, 201, "http_logging create failed: {body:?}");

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=plugin_config&resource_id=http-logging-redaction",
        &admin,
        1,
    )
    .await;
    let audit_config =
        &audit_body["items"].as_array().expect("audit items")[0]["diff"]["after"]["config"];
    assert_http_logging_projection_redacted(audit_config);

    let mut projections = vec![audit_config.clone()];
    for bearer in [&viewer, &operator] {
        let (status, projected) =
            get_json(&base, "/plugins/config/http-logging-redaction", bearer).await;
        assert_eq!(status, 200, "projected read failed: {projected:?}");
        assert_http_logging_projection_redacted(&projected["config"]);
        projections.push(projected["config"].clone());

        let (status, list) = get_json(&base, "/plugins/config", bearer).await;
        assert_eq!(status, 200, "projected list failed: {list:?}");
        let listed = list["data"]
            .as_array()
            .expect("plugin list data")
            .iter()
            .find(|item| item["id"] == "http-logging-redaction")
            .expect("listed http_logging config")
            .clone();
        assert_http_logging_projection_redacted(&listed["config"]);
        projections.push(listed["config"].clone());
    }

    // Admin reads stay raw so rotation by read-modify-write keeps working.
    let (status, raw) = get_json(&base, "/plugins/config/http-logging-redaction", &admin).await;
    assert_eq!(status, 200, "admin read failed: {raw:?}");
    assert_eq!(raw["config"]["endpoint_url"], endpoint);
    assert_eq!(
        raw["config"]["custom_headers"]["x-honeycomb-team"],
        vendor_secret
    );

    for projection in &projections {
        let serialized = projection.to_string();
        for secret in [path_secret, query_secret, vendor_secret, tenant_secret] {
            assert!(
                !serialized.contains(secret),
                "http_logging projection leaked {secret}: {serialized}"
            );
        }
    }
}

fn assert_http_logging_projection_redacted(config: &Value) {
    assert_eq!(
        config["endpoint_url"],
        "https://collector.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(config["custom_headers"]["x-honeycomb-team"], "[REDACTED]");
    assert_eq!(config["custom_headers"]["X-Tenant"], "[REDACTED]");
    // Safe-value control: non-credential tuning stays readable for operators.
    assert_eq!(config["batch_size"], 50);
    // Header names remain visible; only the values are secret.
    assert!(
        config["custom_headers"]
            .as_object()
            .expect("custom_headers object")
            .contains_key("x-honeycomb-team")
    );
}

/// GHSA-4988-2wph-67g2: `proxy_alerts` generic webhook channels take a
/// credential-bearing `url` (a key with no sensitive substring), arbitrary
/// vendor header names, and an operator-authored `body_template` that is the
/// documented place to inline a routing key.
#[tokio::test]
async fn proxy_alerts_generic_webhook_credentials_are_projected() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));
    let operator = token("mesh-operator", Some("operator"));

    let url_path_secret = "alerts-url-path-canary";
    let url_query_secret = "alerts-url-query-canary";
    let header_secret = "alerts-header-canary";
    let template_secret = "alerts-template-canary";
    let slack_secret = "alerts-slack-canary";
    let webhook_url =
        format!("https://hooks.example.com/{url_path_secret}?routing_key={url_query_secret}");
    let plugin = json!({
        "id": "proxy-alerts-redaction",
        "plugin_name": "proxy_alerts",
        "scope": "global",
        // Stored without plugin construction so the projection contract is
        // exercised independently of channel-dispatch prerequisites.
        "enabled": false,
        "config": {
            "channels": {
                "generic": {
                    "type": "webhook",
                    "url": webhook_url,
                    "method": "POST",
                    "headers": {"x-routing-key": header_secret},
                    "body_template": format!("{{\"key\":\"{template_secret}\"}}")
                },
                "ops-slack": {
                    "type": "slack",
                    "webhook_url": format!("https://hooks.slack.com/services/T0/B0/{slack_secret}")
                }
            }
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(status, 201, "proxy_alerts create failed: {body:?}");

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=plugin_config&resource_id=proxy-alerts-redaction",
        &admin,
        1,
    )
    .await;
    let audit_config =
        &audit_body["items"].as_array().expect("audit items")[0]["diff"]["after"]["config"];
    assert_proxy_alerts_projection_redacted(audit_config);

    let mut projections = vec![audit_config.clone()];
    for bearer in [&viewer, &operator] {
        let (status, projected) =
            get_json(&base, "/plugins/config/proxy-alerts-redaction", bearer).await;
        assert_eq!(status, 200, "projected read failed: {projected:?}");
        assert_proxy_alerts_projection_redacted(&projected["config"]);
        projections.push(projected["config"].clone());
    }

    let (status, raw) = get_json(&base, "/plugins/config/proxy-alerts-redaction", &admin).await;
    assert_eq!(status, 200, "admin read failed: {raw:?}");
    assert_eq!(raw["config"]["channels"]["generic"]["url"], webhook_url);

    for projection in &projections {
        let serialized = projection.to_string();
        for secret in [
            url_path_secret,
            url_query_secret,
            header_secret,
            template_secret,
            slack_secret,
        ] {
            assert!(
                !serialized.contains(secret),
                "proxy_alerts projection leaked {secret}: {serialized}"
            );
        }
    }
}

fn assert_proxy_alerts_projection_redacted(config: &Value) {
    let generic = &config["channels"]["generic"];
    assert_eq!(
        generic["url"],
        "https://hooks.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(generic["headers"]["x-routing-key"], "[REDACTED]");
    assert_eq!(generic["body_template"], "[REDACTED]");
    // Safe-value controls: channel wiring stays legible.
    assert_eq!(generic["type"], "webhook");
    assert_eq!(generic["method"], "POST");
    // `webhook_url` is caught wholesale by the name heuristic; the schema must
    // not weaken that to a structural projection.
    assert_eq!(config["channels"]["ops-slack"]["webhook_url"], "[REDACTED]");
}

/// GHSA-4988-2wph-67g2: `kafka_logging.producer_config` is an arbitrary
/// librdkafka property map. Everything outside the safe-tuning allow-list is
/// redacted, so a newly sensitive upstream property is covered by default.
#[tokio::test]
async fn kafka_producer_config_properties_are_projected_by_allow_list() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));
    let operator = token("mesh-operator", Some("operator"));

    let keypw_secret = "kafka-keypw-canary";
    let oauth_secret = "kafka-keytab-canary";
    let plugin = json!({
        "id": "kafka-producer-redaction",
        "plugin_name": "kafka_logging",
        "scope": "global",
        // Stored without producer construction; the projection is what is under
        // test here, and inline PEM rejection is covered by the plugin's own
        // admission tests.
        "enabled": false,
        "config": {
            "broker_list": "broker.example.com:9093",
            "topic": "ferrum-logs",
            "security_protocol": "sasl_ssl",
            "producer_config": {
                "ssl.key.password": keypw_secret,
                "sasl.kerberos.keytab": oauth_secret,
                "linger.ms": "20",
                "compression.type": "lz4"
            }
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(status, 201, "kafka_logging create failed: {body:?}");

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=plugin_config&resource_id=kafka-producer-redaction",
        &admin,
        1,
    )
    .await;
    let audit_config =
        &audit_body["items"].as_array().expect("audit items")[0]["diff"]["after"]["config"];
    assert_kafka_projection_redacted(audit_config);

    let mut projections = vec![audit_config.clone()];
    for bearer in [&viewer, &operator] {
        let (status, projected) =
            get_json(&base, "/plugins/config/kafka-producer-redaction", bearer).await;
        assert_eq!(status, 200, "projected read failed: {projected:?}");
        assert_kafka_projection_redacted(&projected["config"]);
        projections.push(projected["config"].clone());
    }

    let (status, raw) = get_json(&base, "/plugins/config/kafka-producer-redaction", &admin).await;
    assert_eq!(status, 200, "admin read failed: {raw:?}");
    assert_eq!(
        raw["config"]["producer_config"]["sasl.kerberos.keytab"],
        oauth_secret
    );

    for projection in &projections {
        let serialized = projection.to_string();
        for secret in [keypw_secret, oauth_secret] {
            assert!(
                !serialized.contains(secret),
                "kafka projection leaked {secret}: {serialized}"
            );
        }
    }
}

fn assert_kafka_projection_redacted(config: &Value) {
    let props = &config["producer_config"];
    assert_eq!(props["ssl.key.password"], "[REDACTED]");
    // No name heuristic matches this property; only the allow-list saves it.
    assert_eq!(props["sasl.kerberos.keytab"], "[REDACTED]");
    // Safe-value controls: allow-listed tuning knobs stay visible.
    assert_eq!(props["linger.ms"], "20");
    assert_eq!(props["compression.type"], "lz4");
    assert_eq!(config["topic"], "ferrum-logs");
}

/// `GET /backup` intentionally exports raw configuration so backups stay
/// restorable, which is only safe while it remains Admin-only. Pin that gate
/// alongside the projection tests so a future role change cannot quietly turn
/// the backup route into the disclosure path the projection closes.
#[tokio::test]
async fn backup_export_is_admin_only_and_stays_raw_for_admin() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));
    let operator = token("mesh-operator", Some("operator"));

    let vendor_secret = "backup-honeycomb-canary";
    let plugin = json!({
        "id": "backup-projection-probe",
        "plugin_name": "otel_tracing",
        "scope": "global",
        "config": {
            "endpoint": "https://collector.example.com/v1/traces",
            "headers": {"x-honeycomb-team": vendor_secret}
        }
    });
    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(status, 201, "otel plugin create failed: {body:?}");

    for (role, bearer) in [("viewer", &viewer), ("operator", &operator)] {
        let (status, denied) = get_json(&base, "/backup", bearer).await;
        assert_eq!(status, 403, "{role} must not reach /backup: {denied:?}");
        assert!(
            !denied.to_string().contains(vendor_secret),
            "{role} backup denial leaked config: {denied:?}"
        );
    }

    let (status, backup) = get_json(&base, "/backup", &admin).await;
    assert_eq!(status, 200, "admin backup failed: {backup:?}");
    let stored = backup["plugin_configs"]
        .as_array()
        .expect("backup plugin_configs")
        .iter()
        .find(|item| item["id"] == "backup-projection-probe")
        .expect("backed-up plugin config");
    assert_eq!(
        stored["config"]["headers"]["x-honeycomb-team"], vendor_secret,
        "admin backups must stay restorable"
    );
}

// ---------------------------------------------------------------------------
// Remaining observability sinks — advisory GHSA-8594-2xhc-8g38
//
// `http_logging`, `ai_transcript_audit`, and `api_chargeback_sink` accept
// endpoints whose path/query can carry a reusable credential. Non-admin reads
// and every audit projection must render only the structurally redacted form.
// These vendor-shaped cases now route through the one schema-aware projection
// (GHSA-4988-2wph-67g2), so they assert its structural markers rather than the
// per-plugin `/redacted` rendering they were written against.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_logging_vendor_collector_endpoint_credentials_are_projected() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));
    let operator = token("mesh-operator", Some("operator"));

    let path_secret = "http-logging-sumo-path-canary";
    let query_secret = "http-logging-mezmo-query-canary";
    let header_secret = "http-logging-header-canary";
    let endpoint = format!(
        "https://endpoint1.collection.us1.sumologic.com/receiver/v1/http/{path_secret}?apikey={query_secret}"
    );
    let plugin = json!({
        "id": "http-logging-redaction-config",
        "plugin_name": "http_logging",
        "scope": "global",
        "config": {
            "endpoint_url": endpoint,
            "custom_headers": { "X-Sumo-Category": header_secret }
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(status, 201, "http_logging plugin create failed: {body:?}");
    assert_eq!(body["config"]["endpoint_url"], endpoint);

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=plugin_config&resource_id=http-logging-redaction-config",
        &admin,
        1,
    )
    .await;
    let audit_config =
        &audit_body["items"].as_array().expect("audit items")[0]["diff"]["after"]["config"];
    assert_vendor_http_logging_projection_redacted(audit_config);

    let mut projections = vec![audit_config.clone()];
    for bearer in [&viewer, &operator] {
        let (status, projected) = get_json(
            &base,
            "/plugins/config/http-logging-redaction-config",
            bearer,
        )
        .await;
        assert_eq!(status, 200, "projected read failed: {projected:?}");
        assert_vendor_http_logging_projection_redacted(&projected["config"]);
        projections.push(projected["config"].clone());
    }

    // The admin (raw) read is deliberately unredacted — an operator with the
    // admin role must still be able to read back what they configured.
    let (status, raw) = get_json(
        &base,
        "/plugins/config/http-logging-redaction-config",
        &admin,
    )
    .await;
    assert_eq!(status, 200, "admin raw read failed: {raw:?}");
    assert_eq!(raw["config"]["endpoint_url"], endpoint);

    for projection in &projections {
        let serialized = projection.to_string();
        for secret in [path_secret, query_secret, header_secret] {
            assert!(
                !serialized.contains(secret),
                "http_logging projection leaked {secret}: {serialized}"
            );
        }
    }
}

fn assert_vendor_http_logging_projection_redacted(config: &Value) {
    assert_eq!(
        config["endpoint_url"],
        "https://endpoint1.collection.us1.sumologic.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(config["custom_headers"]["X-Sumo-Category"], "[REDACTED]");
}

#[tokio::test]
async fn ai_transcript_audit_config_projections_redact_sink_endpoint_and_headers() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));

    let path_secret = "transcript-path-canary";
    let query_secret = "transcript-query-canary";
    let header_secret = "transcript-header-canary";
    let endpoint = format!("https://audit.example.com/ingest/{path_secret}?apikey={query_secret}");
    let plugin = json!({
        "id": "transcript-redaction-config",
        "plugin_name": "ai_transcript_audit",
        "scope": "global",
        "config": {
            "sink": {
                "type": "http",
                "endpoint_url": endpoint,
                "custom_headers": { "X-Audit-Token": header_secret }
            }
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(
        status, 201,
        "ai_transcript_audit plugin create failed: {body:?}"
    );
    assert_eq!(body["config"]["sink"]["endpoint_url"], endpoint);

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=plugin_config&resource_id=transcript-redaction-config",
        &admin,
        1,
    )
    .await;
    let audit_config =
        &audit_body["items"].as_array().expect("audit items")[0]["diff"]["after"]["config"];
    assert_transcript_projection_redacted(audit_config);

    let (status, projected) = get_json(
        &base,
        "/plugins/config/transcript-redaction-config",
        &viewer,
    )
    .await;
    assert_eq!(status, 200, "viewer read failed: {projected:?}");
    assert_transcript_projection_redacted(&projected["config"]);

    for projection in [audit_config, &projected["config"]] {
        let serialized = projection.to_string();
        for secret in [path_secret, query_secret, header_secret] {
            assert!(
                !serialized.contains(secret),
                "ai_transcript_audit projection leaked {secret}: {serialized}"
            );
        }
    }
}

fn assert_transcript_projection_redacted(config: &Value) {
    assert_eq!(
        config["sink"]["endpoint_url"],
        "https://audit.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(
        config["sink"]["custom_headers"]["X-Audit-Token"],
        "[REDACTED]"
    );
}

#[tokio::test]
async fn api_chargeback_sink_config_projections_redact_clickhouse_endpoint_and_params() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));
    let viewer = token("view-only", Some("viewer"));

    let path_secret = "chargeback-path-canary";
    let param_secret = "chargeback-param-value-canary";
    let spool_dir = tmp.path().join("chargeback-spool");
    std::fs::create_dir_all(&spool_dir).unwrap();
    let clickhouse_url = format!("https://clickhouse.example.com:8443/{path_secret}");
    let plugin = json!({
        "id": "chargeback-redaction-config",
        "plugin_name": "api_chargeback_sink",
        "scope": "global",
        "config": {
            "mode": "per_event",
            "clickhouse": {
                "url": clickhouse_url,
                "database": "ferrum",
                "table": "charges_raw",
                "timeout_ms": 1000,
                "insert_query_params": { "async_insert": param_secret }
            },
            "batch": {"size": 2, "flush_interval_ms": 60000, "buffer_capacity": 10},
            "retry": {"max_attempts": 1, "initial_delay_ms": 1, "max_delay_ms": 1, "jitter": false},
            "spool": {
                "enabled": true,
                "dir": spool_dir.to_string_lossy(),
                "max_bytes": 1048576,
                "replay_interval_secs": 3600,
                "compression": "none"
            },
            "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
            "bandwidth_pricing": {"price_per_byte_sent": 0.000001, "price_per_byte_received": 0.000002},
            "stream_connection_pricing": {"price_per_connection": 0.1},
            "pricing_version": "test-v1",
            "currency": "USD"
        }
    });

    let (status, body) = post_json(&base, "/plugins/config", &admin, &plugin).await;
    assert_eq!(
        status, 201,
        "api_chargeback_sink plugin create failed: {body:?}"
    );
    assert_eq!(body["config"]["clickhouse"]["url"], clickhouse_url);

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=plugin_config&resource_id=chargeback-redaction-config",
        &admin,
        1,
    )
    .await;
    let audit_config =
        &audit_body["items"].as_array().expect("audit items")[0]["diff"]["after"]["config"];
    assert_chargeback_projection_redacted(audit_config);

    let (status, projected) = get_json(
        &base,
        "/plugins/config/chargeback-redaction-config",
        &viewer,
    )
    .await;
    assert_eq!(status, 200, "viewer read failed: {projected:?}");
    assert_chargeback_projection_redacted(&projected["config"]);

    for projection in [audit_config, &projected["config"]] {
        let serialized = projection.to_string();
        for secret in [path_secret, param_secret] {
            assert!(
                !serialized.contains(secret),
                "api_chargeback_sink projection leaked {secret}: {serialized}"
            );
        }
    }
}

fn assert_chargeback_projection_redacted(config: &Value) {
    assert_eq!(
        config["clickhouse"]["url"],
        "https://clickhouse.example.com:8443/[REDACTED_PATH]"
    );
    assert_eq!(
        config["clickhouse"]["insert_query_params"]["async_insert"],
        "[REDACTED]"
    );
}
