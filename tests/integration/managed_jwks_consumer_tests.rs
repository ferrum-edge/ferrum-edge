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
        &EncodingKey::from_secret(ADMIN_SECRET.as_bytes()),
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
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.token);
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
