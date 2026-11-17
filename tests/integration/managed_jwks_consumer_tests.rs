//! Admin-managed JWKS records consumed by `jwks_auth` (issue #7277).
//!
//! Drives the real admin listener: a JWKS document uploaded through
//! `POST /admin/tls/jwks` verifies tokens for a `jwks_auth` provider whose
//! `jwks_source` names it, a `PUT` rotates the key set (the added `kid` is
//! accepted and the removed one refused as soon as the write returns), a
//! referenced record cannot be deleted, and deleting an unreferenced record
//! withdraws every key so tokens are refused.

use std::sync::Arc;

use arc_swap::ArcSwap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::plugins::utils::jwks_cache::cached_store;
use ferrum_edge::plugins::utils::jwks_store::JwksTrustState;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, jwks_auth::JwksAuth};
use ferrum_edge::proxy::client_ip::TrustedProxies;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::scaffolding::port_registry::TestSocket;

const ADMIN_SECRET: &str = "managed-jwks-admin-secret-0123456789abcdef";
const ADMIN_ISSUER: &str = "managed-jwks-test";
const TOKEN_ISSUER: &str = "https://managed-jwks.idp.example";

fn admin_token() -> String {
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": ADMIN_ISSUER,
        "sub": "tls-admin",
        "role": "admin",
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(ADMIN_SECRET.as_bytes()).unwrap(),
    )
    .expect("admin token")
}

fn admin_state(cached_config: Arc<ArcSwap<GatewayConfig>>) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: JwtManager::new(JwtConfig {
            secret: ADMIN_SECRET.to_string(),
            issuer: ADMIN_ISSUER.to_string(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: Algorithm::HS256,
        }),
        metrics_auth: Default::default(),
        proxy_state: None,
        cached_config: Some(cached_config),
        mode: "test".to_string(),
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
        reserved_ports: Default::default(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        mesh_runtime_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
        runtime_config_apply: None,
    }
}

struct AdminHarness {
    base: String,
    client: reqwest::Client,
    token: String,
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl AdminHarness {
    async fn start(state: AdminState) -> Self {
        let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind admin");
        let addr = listener.local_addr().expect("admin addr");
        let (shutdown, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            serve_admin_on_listener(
                listener,
                state,
                rx,
                None,
                ferrum_edge::admin::AdminConnLimiter::unlimited(),
            )
            .await
            .expect("admin serve");
        });
        Self {
            base: format!("http://{addr}"),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("client"),
            token: admin_token(),
            shutdown,
            task,
        }
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.send_in(method, path, body, None).await
    }

    async fn send_ns(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        namespace: &str,
    ) -> (StatusCode, Value) {
        self.send_in(method, path, body, Some(namespace)).await
    }

    async fn send_in(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        namespace: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.token);
        if let Some(namespace) = namespace {
            request = request.header("X-Ferrum-Namespace", namespace);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("admin request");
        let status = response.status();
        let body = response.json().await.unwrap_or(Value::Null);
        (status, body)
    }
}

impl Drop for AdminHarness {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.task.abort();
    }
}

struct SigningKey {
    kid: String,
    jwk: Value,
    encoding: EncodingKey,
}

fn signing_key(kid: &str) -> SigningKey {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256 key");
    let point = key_pair.public_key_raw();
    SigningKey {
        kid: kid.to_string(),
        jwk: json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": kid,
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..]),
        }),
        encoding: EncodingKey::from_ec_pem(key_pair.serialize_pem().as_bytes())
            .expect("EC encoding key"),
    }
}

fn jwks_json(keys: &[&SigningKey]) -> String {
    let keys: Vec<Value> = keys.iter().map(|key| key.jwk.clone()).collect();
    json!({ "keys": keys }).to_string()
}

fn bearer(key: &SigningKey) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key.kid.clone());
    let claims = json!({
        "iss": TOKEN_ISSUER,
        "sub": "managed-user",
        "exp": Utc::now().timestamp() + 3600,
    });
    encode(&header, &claims, &key.encoding).expect("sign token")
}

async fn authenticate(plugin: &JwksAuth, key: &SigningKey) -> PluginResult {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/orders".to_string(),
    );
    ctx.headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", bearer(key)),
    );
    plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await
}

fn accepted(result: &PluginResult) -> bool {
    matches!(result, PluginResult::Continue)
}

fn refused(result: &PluginResult) -> bool {
    matches!(
        result,
        PluginResult::Reject {
            status_code: 401,
            ..
        }
    )
}

fn jwks_auth_plugin_config(id: &str, source: &str) -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "jwks_auth".to_string(),
        config: json!({ "providers": [{ "issuer": TOKEN_ISSUER, "jwks_source": source }] }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_managed_jwks_drives_jwks_auth_verification_rotation_and_withdrawal() {
    let record_id = format!("idp-{}", uuid::Uuid::new_v4().simple());
    let source = format!("managed://jwks/{record_id}#jwks");
    let plugin_config = jwks_auth_plugin_config("managed-jwks-auth", &source);

    let cached_config = Arc::new(ArcSwap::from_pointee(GatewayConfig {
        plugin_configs: vec![plugin_config.clone()],
        ..Default::default()
    }));
    let admin = AdminHarness::start(admin_state(Arc::clone(&cached_config))).await;

    // A document without a usable signing key is refused at admission.
    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/admin/tls/jwks",
            Some(json!({
                "id": record_id,
                "name": "symmetric only",
                "jwks_json": json!({"keys": [{"kty": "oct", "k": "dGVzdA", "kid": "sym"}]}).to_string(),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("no usable signing key")),
        "{body}"
    );

    // Before the record exists, the presence check refuses the reference.
    let errors = ferrum_edge::plugins::jwks_auth::managed_jwks_source_errors(&plugin_config.config);
    assert!(
        errors.len() == 1 && errors[0].contains("does not exist"),
        "{errors:?}"
    );

    // Upload the first key set.
    let first = signing_key("first");
    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/admin/tls/jwks",
            Some(json!({ "id": record_id, "name": "IdP keys", "jwks_json": jwks_json(&[&first]) })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["source_uri"], format!("managed://jwks/{record_id}"));
    assert!(
        ferrum_edge::plugins::jwks_auth::managed_jwks_source_errors(&plugin_config.config)
            .is_empty()
    );

    // A running jwks_auth reading the record through the shared JWKS cache.
    let plugin = JwksAuth::new_with_config_id(
        &plugin_config.config,
        ferrum_edge::plugins::PluginHttpClient::default(),
        Some(&plugin_config.id),
    )
    .expect("managed jwks_auth");
    plugin
        .start_background_tasks()
        .expect("runtime starts the managed store");
    plugin.commit_background_tasks();
    plugin.warmup_jwks().await;
    assert!(accepted(&authenticate(&plugin, &first).await));
    let shared = cached_store(&source).expect("managed store is shared");
    assert_eq!(shared.health_snapshot().trust_state, JwksTrustState::Fresh);

    // The inventory reports the plugin reference.
    let (status, inventory) = admin
        .send(reqwest::Method::GET, "/admin/tls/inventory", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{inventory}");
    let entries = inventory["data"].as_array().cloned().unwrap_or_default();
    assert!(
        entries.iter().any(|entry| {
            entry["material_kind"] == "jwks"
                && entry["source"]["identifier"] == source
                && entry["used_by"].as_array().is_some_and(|used_by| {
                    used_by.iter().any(|usage| {
                        usage["surface"] == "jwks_auth"
                            && usage["resource_id"] == "managed-jwks-auth#provider[0]"
                    })
                })
        }),
        "inventory must list the managed JWKS reference: {inventory}"
    );

    // Rotate: replace the key set. The `PUT` re-reads every managed store on
    // this node before it returns, so the new `kid` is accepted and the
    // removed one refused immediately, with no wait.
    let second = signing_key("second");
    let (status, body) = admin
        .send(
            reqwest::Method::PUT,
            &format!("/admin/tls/jwks/{record_id}"),
            Some(json!({ "jwks_json": jwks_json(&[&second]) })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(accepted(&authenticate(&plugin, &second).await));
    assert!(refused(&authenticate(&plugin, &first).await));

    // A referenced record cannot be deleted.
    let (status, body) = admin
        .send(
            reqwest::Method::DELETE,
            &format!("/admin/tls/jwks/{record_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(accepted(&authenticate(&plugin, &second).await));

    // Once no config references it, the delete lands and withdraws every key:
    // the still-running consumer refuses tokens, like an expired remote set.
    cached_config.store(Arc::new(GatewayConfig::default()));
    let (status, body) = admin
        .send(
            reqwest::Method::DELETE,
            &format!("/admin/tls/jwks/{record_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(refused(&authenticate(&plugin, &second).await));
    assert_eq!(
        shared.health_snapshot().trust_state,
        JwksTrustState::Expired
    );

    // Re-creating the record restores verification as soon as it is written.
    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/admin/tls/jwks",
            Some(
                json!({ "id": record_id, "name": "IdP keys", "jwks_json": jwks_json(&[&second]) }),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(accepted(&authenticate(&plugin, &second).await));

    drop(plugin);
    let _ = admin
        .send(
            reqwest::Method::DELETE,
            &format!("/admin/tls/jwks/{record_id}"),
            None,
        )
        .await;
}

async fn sqlite_store(dir: &tempfile::TempDir) -> ferrum_edge::config::db_loader::DatabaseStore {
    let db_path = dir
        .path()
        .join(format!("managed-jwks-{}.db", uuid::Uuid::new_v4().simple()));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    ferrum_edge::config::db_loader::DatabaseStore::connect_with_pool_config(
        "sqlite",
        &url,
        ferrum_edge::config::db_loader::DbPoolConfig {
            max_connections: 4,
            min_connections: 0,
            acquire_timeout_seconds: 5,
            idle_timeout_seconds: 60,
            max_lifetime_seconds: 300,
            connect_timeout_seconds: 5,
            statement_timeout_seconds: 0,
        },
    )
    .await
    .expect("connect sqlite store")
}

fn jwks_auth_plugin_body(id: &str, source: &str, enabled: bool) -> Value {
    json!({
        "id": id,
        "plugin_name": "jwks_auth",
        "scope": "global",
        "enabled": enabled,
        "config": { "providers": [{ "issuer": TOKEN_ISSUER, "jwks_source": source }] },
    })
}

fn jwks_auth_spec(proxy_id: &str, plugin_id: &str, source: &str) -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {"title": "Managed JWKS API", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": proxy_id,
            "backend_host": "backend.internal",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}")
        },
        "x-ferrum-plugins": [{
            "id": plugin_id,
            "plugin_name": "jwks_auth",
            "config": { "providers": [{ "issuer": TOKEN_ISSUER, "jwks_source": source }] }
        }]
    })
}

/// Every admin write path that persists an enabled `jwks_auth` /
/// `oidc_relying_party` refuses a `jwks_source` naming a managed JWKS record
/// this node does not hold: `POST /plugins/config`, `POST /batch`, and API
/// spec create and replace (issue #7277; dsf F2/F3 and sol F2 on #7373). A
/// disabled plugin is staged without the check, and every path admits the
/// reference once the record exists.
#[tokio::test(flavor = "multi_thread")]
async fn admin_writes_refuse_a_managed_jwks_source_without_a_usable_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut state = admin_state(Arc::new(ArcSwap::from_pointee(GatewayConfig::default())));
    state.db = Some(Arc::new(sqlite_store(&dir).await));
    state.cached_config = None;
    state.mode = "database".to_string();
    let admin = AdminHarness::start(state).await;

    let record_id = format!("idp-{}", uuid::Uuid::new_v4().simple());
    let source = format!("managed://jwks/{record_id}#jwks");
    let missing_id = format!("missing-{}", uuid::Uuid::new_v4().simple());
    let missing = format!("managed://jwks/{missing_id}#jwks");

    let refused_naming = |status: StatusCode, body: &Value, expected: StatusCode, id: &str| {
        assert_eq!(status, expected, "{body}");
        let rendered = body.to_string();
        assert!(
            rendered.contains(id) && rendered.contains("does not exist"),
            "the refusal must name the missing record: {body}"
        );
    };

    // Single plugin write.
    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/plugins/config",
            Some(jwks_auth_plugin_body("managed-single", &source, true)),
        )
        .await;
    refused_naming(status, &body, StatusCode::BAD_REQUEST, &record_id);

    // A disabled plugin is staged: the presence check gates enabled writes.
    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/plugins/config",
            Some(jwks_auth_plugin_body("managed-disabled", &missing, false)),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // Batch write.
    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/batch",
            Some(json!({
                "plugin_configs": [jwks_auth_plugin_body("managed-batch", &source, true)],
            })),
        )
        .await;
    refused_naming(status, &body, StatusCode::BAD_REQUEST, &record_id);

    // API spec create: the extracted plugin goes through the same check.
    let proxy_id = format!("managed-spec-{}", uuid::Uuid::new_v4().simple());
    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/api-specs",
            Some(jwks_auth_spec(&proxy_id, "managed-spec-plugin", &source)),
        )
        .await;
    refused_naming(status, &body, StatusCode::UNPROCESSABLE_ENTITY, &record_id);

    // Create the record; every path now admits the reference.
    let key = signing_key("admission");
    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/admin/tls/jwks",
            Some(json!({ "id": record_id, "name": "IdP keys", "jwks_json": jwks_json(&[&key]) })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/plugins/config",
            Some(jwks_auth_plugin_body("managed-single", &source, true)),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/api-specs",
            Some(jwks_auth_spec(&proxy_id, "managed-spec-plugin", &source)),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let spec_id = body["id"].as_str().expect("created spec id").to_string();

    // API spec replace: a reference to a missing record is refused and the
    // stored spec keeps serving the admitted one.
    let (status, body) = admin
        .send(
            reqwest::Method::PUT,
            &format!("/api-specs/{spec_id}"),
            Some(jwks_auth_spec(&proxy_id, "managed-spec-plugin", &missing)),
        )
        .await;
    refused_naming(status, &body, StatusCode::UNPROCESSABLE_ENTITY, &missing_id);
    let (status, body) = admin
        .send(
            reqwest::Method::GET,
            "/plugins/config/managed-spec-plugin",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["config"]["providers"][0]["jwks_source"], source,
        "a refused replacement must not be persisted: {body}"
    );
}

/// A database-mode node serves one namespace, but its Admin API writes any
/// namespace and every gateway sharing the managed store reads the record. A
/// JWKS record that an enabled `jwks_auth` in another namespace references
/// must not be deleted from a node whose served configuration has no
/// reference (issue #7394): the guard scans every namespace in the store.
#[tokio::test(flavor = "multi_thread")]
async fn delete_refuses_a_managed_jwks_record_referenced_from_another_namespace() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The served configuration (namespace `ferrum`) holds no reference.
    let mut state = admin_state(Arc::new(ArcSwap::from_pointee(GatewayConfig::default())));
    state.db = Some(Arc::new(sqlite_store(&dir).await));
    state.mode = "database".to_string();
    let admin = AdminHarness::start(state).await;

    let record_id = format!("idp-{}", uuid::Uuid::new_v4().simple());
    let source = format!("managed://jwks/{record_id}#jwks");
    let key = signing_key("cross-namespace");
    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/admin/tls/jwks",
            Some(json!({ "id": record_id, "name": "IdP keys", "jwks_json": jwks_json(&[&key]) })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let tenant = "tenant-b";
    let (status, body) = admin
        .send_ns(
            reqwest::Method::POST,
            "/plugins/config",
            Some(jwks_auth_plugin_body("tenant-b-auth", &source, true)),
            tenant,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let delete_path = format!("/admin/tls/jwks/{record_id}");
    let (status, body) = admin
        .send(reqwest::Method::DELETE, &delete_path, None)
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a record another namespace references must not be deleted: {body}"
    );
    assert!(
        body["used_by"].as_array().is_some_and(|used_by| {
            used_by.iter().any(|usage| {
                usage["namespace"] == tenant
                    && usage["resource_type"] == "plugin_config"
                    && usage["resource_id"] == "tenant-b-auth#provider[0]"
            })
        }),
        "the refusal names the referencing namespace and plugin: {body}"
    );
    let (status, body) = admin.send(reqwest::Method::GET, &delete_path, None).await;
    assert_eq!(status, StatusCode::OK, "the record survives: {body}");

    // A disabled consumer reads nothing, so it no longer holds the record.
    let (status, body) = admin
        .send_ns(
            reqwest::Method::PUT,
            "/plugins/config/tenant-b-auth?expected_proxy_ids=",
            Some(jwks_auth_plugin_body("tenant-b-auth", &source, false)),
            tenant,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = admin
        .send(reqwest::Method::DELETE, &delete_path, None)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unreferenced record deletes: {body}"
    );
}

use ferrum_edge::admin::TlsReferenceScanHookAction;

type ScanHookFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = TlsReferenceScanHookAction> + Send>>;
type ScanHook = Arc<dyn Fn() -> ScanHookFuture + Send + Sync>;

/// Removes this test's scan hook (keyed by its own record id) even when the
/// test panics. Other tests' hooks are untouched.
struct ScanHookGuard(String);

impl Drop for ScanHookGuard {
    fn drop(&mut self) {
        ferrum_edge::admin::set_tls_reference_scan_hook_for_tests(&self.0, None);
    }
}

/// Bounded wait, so a hook that never fires fails the test instead of hanging.
async fn within<T>(what: &str, future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(30), future)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

/// Pause the first delete of `record_id` between its reference scan and its
/// namespace re-check, then answer `action`.
fn pause_first_scan_of(
    record_id: &str,
    action: TlsReferenceScanHookAction,
) -> (
    ScanHookGuard,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
) {
    let scanned = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (hook_scanned, hook_release) = (scanned.clone(), release.clone());
    let hook: ScanHook = Arc::new(move || -> ScanHookFuture {
        let pause = !paused.swap(true, std::sync::atomic::Ordering::SeqCst);
        let (scanned, release) = (hook_scanned.clone(), hook_release.clone());
        Box::pin(async move {
            if pause {
                scanned.notify_one();
                release.notified().await;
                action
            } else {
                TlsReferenceScanHookAction::Continue
            }
        })
    });
    ferrum_edge::admin::set_tls_reference_scan_hook_for_tests(record_id, Some(hook));
    (ScanHookGuard(record_id.to_string()), scanned, release)
}

async fn database_admin(
    dir: &tempfile::TempDir,
) -> (
    Arc<AdminHarness>,
    Arc<ferrum_edge::config::db_loader::DatabaseStore>,
) {
    let mut state = admin_state(Arc::new(ArcSwap::from_pointee(GatewayConfig::default())));
    let store = Arc::new(sqlite_store(dir).await);
    state.db = Some(store.clone());
    state.mode = "database".to_string();
    (Arc::new(AdminHarness::start(state).await), store)
}

async fn database_admin_with_record(
    dir: &tempfile::TempDir,
) -> (
    Arc<AdminHarness>,
    String,
    String,
    Arc<ferrum_edge::config::db_loader::DatabaseStore>,
) {
    let (admin, store) = database_admin(dir).await;
    let record_id = format!("idp-{}", uuid::Uuid::new_v4().simple());
    let source = format!("managed://jwks/{record_id}#jwks");
    let key = signing_key("fenced");
    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/admin/tls/jwks",
            Some(json!({ "id": record_id, "name": "IdP keys", "jwks_json": jwks_json(&[&key]) })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (admin, record_id, source, store)
}

/// Review sol F1 on #7412: a reference committed in an already-scanned
/// namespace while the delete is between its scan and the store delete must
/// not leave a stored reference to a deleted record. The delete holds every
/// scanned namespace's admission lease until the record is gone, so the
/// plugin write waits, then fails admission because the record no longer
/// exists. Both requests never succeed together.
#[tokio::test(flavor = "multi_thread")]
async fn delete_fences_reference_writes_into_scanned_namespaces() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (admin, record_id, source, _store) = database_admin_with_record(&dir).await;
    let tenant = "tenant-b";
    // tenant-b exists before the delete starts, so the scan fences it.
    let (status, body) = admin
        .send_ns(
            reqwest::Method::POST,
            "/consumers",
            Some(json!({"id": "tenant-b-consumer", "username": "tenant-b-consumer"})),
            tenant,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (_hook, scanned, release) =
        pause_first_scan_of(&record_id, TlsReferenceScanHookAction::Continue);
    let delete_path = format!("/admin/tls/jwks/{record_id}");
    let deleting = {
        let admin = admin.clone();
        let path = delete_path.clone();
        tokio::spawn(async move { admin.send(reqwest::Method::DELETE, &path, None).await })
    };
    within("the reference scan", scanned.notified()).await;

    // The scan found no reference. A reference write into tenant-b now.
    let mut writing = {
        let admin = admin.clone();
        let source = source.clone();
        tokio::spawn(async move {
            admin
                .send_ns(
                    reqwest::Method::POST,
                    "/plugins/config",
                    Some(jwks_auth_plugin_body("late-auth", &source, true)),
                    tenant,
                )
                .await
        })
    };
    // It cannot commit while the delete holds tenant-b's admission lease.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), &mut writing)
            .await
            .is_err(),
        "a reference write into a fenced namespace must wait for the delete"
    );
    release.notify_one();

    let (delete_status, delete_body) = within("the delete", deleting).await.expect("delete task");
    let (write_status, write_body) = within("the write", writing).await.expect("write task");
    assert_eq!(delete_status, StatusCode::OK, "{delete_body}");
    assert_eq!(
        write_status,
        StatusCode::BAD_REQUEST,
        "the late reference must fail admission: {write_body}"
    );
    let (status, body) = admin
        .send_ns(
            reqwest::Method::GET,
            "/plugins/config/late-auth",
            None,
            tenant,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no stored reference: {body}");
}

/// The same race into a namespace that had no rows when the scan started:
/// its lease is not held, so the write may commit during the pause. The
/// namespace re-check then sees it and rescans, so the delete answers `409`;
/// or the write was held by a shared process lock and fails admission after
/// the delete. Either way the two never both succeed.
#[tokio::test(flavor = "multi_thread")]
async fn delete_rescans_a_namespace_created_during_the_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (admin, record_id, source, _store) = database_admin_with_record(&dir).await;
    let tenant = "tenant-new";

    let (_hook, scanned, release) =
        pause_first_scan_of(&record_id, TlsReferenceScanHookAction::Continue);
    let delete_path = format!("/admin/tls/jwks/{record_id}");
    let deleting = {
        let admin = admin.clone();
        let path = delete_path.clone();
        tokio::spawn(async move { admin.send(reqwest::Method::DELETE, &path, None).await })
    };
    within("the reference scan", scanned.notified()).await;

    let mut writing = {
        let admin = admin.clone();
        let source = source.clone();
        tokio::spawn(async move {
            admin
                .send_ns(
                    reqwest::Method::POST,
                    "/plugins/config",
                    Some(jwks_auth_plugin_body("new-tenant-auth", &source, true)),
                    tenant,
                )
                .await
        })
    };
    // Let the write commit if nothing holds it; a held write resolves later.
    let early = tokio::time::timeout(std::time::Duration::from_secs(5), &mut writing).await;
    release.notify_one();
    let (delete_status, delete_body) = within("the delete", deleting).await.expect("delete task");
    let (write_status, write_body) = match early {
        Ok(joined) => joined.expect("write task"),
        Err(_) => within("the write", writing).await.expect("write task"),
    };

    match write_status {
        StatusCode::CREATED => {
            assert_eq!(
                delete_status,
                StatusCode::CONFLICT,
                "a committed reference must refuse the delete: {delete_body}"
            );
            assert!(
                delete_body["used_by"]
                    .as_array()
                    .is_some_and(|used_by| used_by
                        .iter()
                        .any(|usage| usage["namespace"] == tenant)),
                "the rescan names the new namespace: {delete_body}"
            );
        }
        StatusCode::BAD_REQUEST => {
            assert_eq!(delete_status, StatusCode::OK, "{delete_body}");
        }
        other => panic!("unexpected write status {other}: {write_body}"),
    }
}

/// An ACME certificate record for `domain`, self-signed and imported through
/// the Admin API.
async fn create_acme_certificate(admin: &AdminHarness, id: &str, domain: &str) {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256 key");
    let params = rcgen::CertificateParams::new(vec![domain.to_string()]).expect("params");
    let cert = params
        .self_signed(&key_pair)
        .expect("self-signed certificate");
    let (status, body) = admin
        .send(
            reqwest::Method::POST,
            "/admin/tls/acme/certificates",
            Some(json!({
                "id": id,
                "domains": [domain],
                "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
                "cert_pem": cert.pem(),
                "key_pem": key_pair.serialize_pem(),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

/// Review dsf F3 on #7412: the ACME delete runs the same cross-namespace
/// guard. A proxy in another namespace that names the certificate refuses the
/// delete with `409` naming that namespace.
#[tokio::test(flavor = "multi_thread")]
async fn acme_delete_refuses_a_certificate_referenced_from_another_namespace() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (admin, _store) = database_admin(&dir).await;
    let id = format!("acme-{}", uuid::Uuid::new_v4().simple());
    create_acme_certificate(&admin, &id, "acme-fence.example.com").await;
    let tenant = "tenant-b";
    let (status, body) = admin
        .send_ns(
            reqwest::Method::POST,
            "/proxies",
            Some(json!({
                "id": "acme-proxy",
                "listen_path": "/acme-proxy",
                "backend_scheme": "https",
                "backend_host": "backend.internal",
                "backend_port": 443,
                "backend_tls_client_cert_path": format!("acme://certificates/{id}#cert"),
                "backend_tls_client_key_path": format!("acme://certificates/{id}#key"),
            })),
            tenant,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let path = format!("/admin/tls/acme/certificates/{id}");
    let (status, body) = admin.send(reqwest::Method::DELETE, &path, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["used_by"].as_array().is_some_and(|used_by| used_by
            .iter()
            .any(|usage| { usage["namespace"] == tenant && usage["resource_id"] == "acme-proxy" })),
        "the refusal names the referencing namespace and proxy: {body}"
    );
    let (status, body) = admin.send(reqwest::Method::GET, &path, None).await;
    assert_eq!(status, StatusCode::OK, "the certificate survives: {body}");
}

/// Review sol F2 / dsf F3 on #7412: the TLS store re-validates the fence
/// under its own lock right before removing the record. Leases that lapse
/// after the scan refuse the delete with `503` and leave the record in place.
#[tokio::test(flavor = "multi_thread")]
async fn acme_delete_refuses_when_the_fence_lapses_after_the_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (admin, _store) = database_admin(&dir).await;
    let id = format!("acme-{}", uuid::Uuid::new_v4().simple());
    create_acme_certificate(&admin, &id, "acme-lapse.example.com").await;

    let (_hook, scanned, release) = pause_first_scan_of(&id, TlsReferenceScanHookAction::LoseFence);
    let path = format!("/admin/tls/acme/certificates/{id}");
    let deleting = {
        let admin = admin.clone();
        let path = path.clone();
        tokio::spawn(async move { admin.send(reqwest::Method::DELETE, &path, None).await })
    };
    within("the reference scan", scanned.notified()).await;
    release.notify_one();
    let (status, body) = within("the delete", deleting).await.expect("delete task");
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a lapsed fence must refuse the delete: {body}"
    );
    let (status, body) = admin.send(reqwest::Method::GET, &path, None).await;
    assert_eq!(status, StatusCode::OK, "the certificate survives: {body}");
}

/// Review sol F3 on #7412: the fence pins the config store topology, so a
/// reconnect cannot move the scan or the leases to another database while a
/// delete is between its scan and the store delete.
#[tokio::test(flavor = "multi_thread")]
async fn reconnect_waits_for_the_delete_fence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (admin, record_id, _source, store) = database_admin_with_record(&dir).await;
    let (_hook, scanned, release) =
        pause_first_scan_of(&record_id, TlsReferenceScanHookAction::Continue);
    let path = format!("/admin/tls/jwks/{record_id}");
    let deleting = {
        let admin = admin.clone();
        let path = path.clone();
        tokio::spawn(async move { admin.send(reqwest::Method::DELETE, &path, None).await })
    };
    within("the reference scan", scanned.notified()).await;

    let other = dir.path().join(format!(
        "managed-jwks-other-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let other_url = format!("sqlite:{}?mode=rwc", other.to_string_lossy());
    let mut reconnecting = {
        let store = store.clone();
        tokio::spawn(async move { store.reconnect(&other_url).await })
    };
    match tokio::time::timeout(std::time::Duration::from_millis(500), &mut reconnecting).await {
        Err(_) => {}
        Ok(joined) => assert!(
            joined.expect("reconnect task").is_err(),
            "a reconnect must not publish while the delete fence pins the topology"
        ),
    }
    release.notify_one();
    let (status, body) = within("the delete", deleting).await.expect("delete task");
    assert_eq!(status, StatusCode::OK, "{body}");
    reconnecting.abort();
}

/// Review round 3 (sol F1 / dsf F1) on #7412: the store checks the fence
/// again after it has persisted the removal. A fence that lapsed while the
/// write was being persisted restores the record before the store lock is
/// released, and the delete answers `503`, never `200`.
#[tokio::test(flavor = "multi_thread")]
async fn delete_restores_the_record_when_the_fence_lapses_during_persistence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (admin, record_id, _source, _store) = database_admin_with_record(&dir).await;
    let (_hook, scanned, release) = pause_first_scan_of(
        &record_id,
        TlsReferenceScanHookAction::LoseFenceAfterPersist,
    );
    let path = format!("/admin/tls/jwks/{record_id}");
    let deleting = {
        let admin = admin.clone();
        let path = path.clone();
        tokio::spawn(async move { admin.send(reqwest::Method::DELETE, &path, None).await })
    };
    within("the reference scan", scanned.notified()).await;
    release.notify_one();
    let (status, body) = within("the delete", deleting).await.expect("delete task");
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a fence lost during persistence must not report a delete: {body}"
    );
    let (status, body) = admin.send(reqwest::Method::GET, &path, None).await;
    assert_eq!(status, StatusCode::OK, "the record was restored: {body}");
}

/// Removes this test's store-delete hook even when the test panics.
struct StoreDeleteHookGuard(String);

impl Drop for StoreDeleteHookGuard {
    fn drop(&mut self) {
        ferrum_edge::admin::set_tls_store_delete_hook_for_tests(&self.0, None);
    }
}

/// Review round 3 (dsf F3) on #7412, the round-2 sol F1 fix: the fence moves
/// into the blocking store delete. Cancelling the request (an HTTP/2 stream
/// reset) while that delete is held must not release the namespace leases: a
/// reference write into a scanned namespace still waits, and once the delete
/// completes it fails admission because the record is gone.
#[tokio::test(flavor = "multi_thread")]
async fn cancelled_delete_keeps_the_fence_until_the_store_delete_ends() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (admin, record_id, source, _store) = database_admin_with_record(&dir).await;
    let tenant = "tenant-b";
    let (status, body) = admin
        .send_ns(
            reqwest::Method::POST,
            "/consumers",
            Some(json!({"id": "tenant-b-consumer", "username": "tenant-b-consumer"})),
            tenant,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // Hold the blocking store delete, with the fence already moved into it.
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let entered_tx = std::sync::Mutex::new(Some(entered_tx));
    let release_rx = std::sync::Mutex::new(release_rx);
    ferrum_edge::admin::set_tls_store_delete_hook_for_tests(
        &record_id,
        Some(Arc::new(move || {
            if let Some(tx) = entered_tx.lock().expect("entered lock").take() {
                let _ = tx.send(());
            }
            let _ = release_rx
                .lock()
                .expect("release lock")
                .recv_timeout(std::time::Duration::from_secs(60));
        })),
    );
    let _store_hook = StoreDeleteHookGuard(record_id.clone());

    // An HTTP/2 client, so aborting the request resets its stream and the
    // server drops the handler future.
    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .expect("h2 client");
    let deleting = {
        let url = format!("{}/admin/tls/jwks/{record_id}", admin.base);
        let token = admin.token.clone();
        tokio::spawn(async move { h2.delete(url).bearer_auth(token).send().await })
    };
    within("the store delete", entered_rx)
        .await
        .expect("store delete hook");
    deleting.abort();
    let _ = deleting.await;

    let mut writing = {
        let admin = admin.clone();
        let source = source.clone();
        tokio::spawn(async move {
            admin
                .send_ns(
                    reqwest::Method::POST,
                    "/plugins/config",
                    Some(jwks_auth_plugin_body("cancelled-race-auth", &source, true)),
                    tenant,
                )
                .await
        })
    };
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), &mut writing)
            .await
            .is_err(),
        "the cancelled delete's fence must still hold tenant-b's lease"
    );
    release_tx.send(()).expect("release the store delete");

    let (status, body) = within("the write", writing).await.expect("write task");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the late reference fails admission once the record is gone: {body}"
    );
    let path = format!("/admin/tls/jwks/{record_id}");
    let (status, body) = admin.send(reqwest::Method::GET, &path, None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the delete completed: {body}"
    );
}
