//! `GET /config/export` and the `FERRUM_ADMIN_JWT_VIEWER_SECRET` role ceiling
//! over a real admin listener (issue #5904).
//!
//! A read-only credential must be able to take a fingerprinted configuration
//! snapshot for drift detection, and must not be able to reach `GET /backup`
//! or any operator/admin route, whatever role its token claims.
//!
//! The `FERRUM_ADMIN_JWT_VIEWER_NAMESPACES` namespace ceiling for the same
//! credential (issue #5929) is covered at the bottom of this file.

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use ferrum_edge::admin::{
    AdminState, MetricsAuthPolicy,
    jwt_auth::{JwtConfig, JwtManager, ViewerNamespaceCeiling},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::types::{Consumer, GatewayConfig};
use ferrum_edge::proxy::client_ip::TrustedProxies;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;

const PRIMARY_SECRET: &str = "config-export-primary-secret-0123456789ab";
const VIEWER_SECRET: &str = "config-export-viewer-secret-0123456789abc";
const ISSUER: &str = "ferrum-edge-config-export-test";
const EXPORT: &str = "/config/export";
const CREDENTIAL_PATH: &str = "/consumers/consumer-staging/credentials/keyauth";
const METRICS_TOKEN: &str = "config-export-metrics-bearer-token-0123456789";

const STAGING_KEY: &str = "staging-api-key-must-not-leak";
const PROD_KEY: &str = "prod-api-key-must-not-leak";
const CONSUL_TOKEN: &str = "consul-token-must-not-leak";
const CONSUL_PASSWORD: &str = "consul-address-password-must-not-leak";
const LABEL_PASSWORD: &str = "proxy-label-password-must-not-leak";

/// Fixed timestamps, so rebuilding the fixture yields the same configuration.
const STAMP: &str = "2026-01-02T03:04:05Z";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: PRIMARY_SECRET.to_string(),
        issuer: ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    })
    .with_viewer_secret(VIEWER_SECRET.to_string())
    .expect("distinct viewer secret")
}

fn token(secret: &str, algorithm: Algorithm, role: &str, ns: Option<Value>) -> String {
    let now = chrono::Utc::now();
    let mut claims = json!({
        "iss": ISSUER,
        "sub": "drift-monitor",
        "role": role,
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(ns) = ns {
        claims["ns"] = ns;
    }
    encode(
        &Header::new(algorithm),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn two_tenant_config(staging_key: &str) -> GatewayConfig {
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [
            {
                "id": "proxy-staging",
                "namespace": "staging",
                "labels": {
                    "runbook": format!("https://ops:{LABEL_PASSWORD}@wiki.internal/runbook"),
                    "repo": "ssh://git@github.com/org/repo"
                },
                "listen_path": "/api",
                "backend_host": "staging.internal",
                "backend_port": 8080,
                "backend_scheme": "http",
                "created_at": STAMP,
                "updated_at": STAMP
            },
            {
                "id": "proxy-prod",
                "namespace": "prod",
                "listen_path": "/api",
                "backend_host": "prod.internal",
                "backend_port": 8080,
                "backend_scheme": "http",
                "created_at": STAMP,
                "updated_at": STAMP
            }
        ],
        "consumers": [
            {
                "id": "consumer-staging",
                "namespace": "staging",
                "username": "alice",
                "credentials": {"keyauth": [{"key": staging_key}]},
                "created_at": STAMP,
                "updated_at": STAMP
            },
            {
                "id": "consumer-prod",
                "namespace": "prod",
                "username": "bob",
                "credentials": {"keyauth": [{"key": PROD_KEY}]},
                "created_at": STAMP,
                "updated_at": STAMP
            }
        ],
        "plugin_configs": [],
        "upstreams": [{
            "id": "upstream-staging",
            "namespace": "staging",
            "name": "orders",
            "targets": [],
            "service_discovery": {
                "provider": "consul",
                "consul": {
                    "address": format!("http://acl:{CONSUL_PASSWORD}@consul.internal:8500"),
                    "service_name": "orders",
                    "token": CONSUL_TOKEN
                }
            },
            "created_at": STAMP,
            "updated_at": STAMP
        }]
    }))
    .expect("fixture deserializes")
}

fn admin_state(cached: Arc<ArcSwap<GatewayConfig>>, require_namespace_claim: bool) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt_manager(),
        metrics_auth: Arc::new(MetricsAuthPolicy {
            allowed_cidrs: TrustedProxies::none(),
            bearer_token: Some(METRICS_TOKEN.to_string()),
        }),
        proxy_state: None,
        cached_config: Some(cached),
        mode: "file".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::common::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: require_namespace_claim,
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
        admin_allowed_cidrs: Arc::new(TrustedProxies::none()),
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
        runtime_config_apply: None,
    }
}

fn cached(config: GatewayConfig) -> Arc<ArcSwap<GatewayConfig>> {
    Arc::new(ArcSwap::new(Arc::new(config)))
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind_test(addr).await.unwrap();
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
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    (format!("http://{actual}"), shutdown_tx)
}

struct Reply {
    status: u16,
    data_source: Option<String>,
    body: Value,
    text: String,
}

async fn get(base: &str, path: &str, bearer: Option<&str>, namespace: Option<&str>) -> Reply {
    send(reqwest::Method::GET, base, path, bearer, namespace, None).await
}

async fn send(
    method: reqwest::Method,
    base: &str,
    path: &str,
    bearer: Option<&str>,
    namespace: Option<&str>,
    body: Option<&Value>,
) -> Reply {
    let mut req = reqwest::Client::new().request(method, format!("{base}{path}"));
    if let Some(body) = body {
        req = req.json(body);
    }
    if let Some(bearer) = bearer {
        req = req.bearer_auth(bearer);
    }
    if let Some(ns) = namespace {
        req = req.header("X-Ferrum-Namespace", ns);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let data_source = resp
        .headers()
        .get("x-data-source")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let text = resp.text().await.unwrap_or_default();
    let body = serde_json::from_str(&text).unwrap_or(Value::Null);
    Reply {
        status,
        data_source,
        body,
        text,
    }
}

fn is_fingerprint(value: &Value) -> bool {
    value
        .as_str()
        .and_then(|text| text.strip_prefix("hmac-sha256:"))
        .is_some_and(|hex| hex.len() == 64)
}

fn keyauth_fingerprint(export: &Value) -> Value {
    export
        .pointer("/consumers/0/credentials/keyauth/0/key")
        .cloned()
        .unwrap_or(Value::Null)
}

#[tokio::test]
async fn viewer_can_export_fingerprints_but_not_backup() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(admin_state(config, false)).await;
    let viewer = token(PRIMARY_SECRET, Algorithm::HS256, "viewer", None);

    let export = get(&base, EXPORT, Some(&viewer), Some("staging")).await;
    assert_eq!(
        export.status, 200,
        "viewer must be able to export: {}",
        export.text
    );
    assert_eq!(export.data_source.as_deref(), Some("cached"));
    assert_eq!(export.body["source"], "cached");
    assert_eq!(export.body["namespace"], "staging");
    for secret in [
        STAGING_KEY,
        PROD_KEY,
        CONSUL_TOKEN,
        CONSUL_PASSWORD,
        LABEL_PASSWORD,
        PRIMARY_SECRET,
        VIEWER_SECRET,
    ] {
        assert!(
            !export.text.contains(secret),
            "the export disclosed secret material: {secret}"
        );
    }
    assert!(is_fingerprint(&keyauth_fingerprint(&export.body)));
    let consul_token = export
        .body
        .pointer("/upstreams/0/service_discovery/consul/token")
        .cloned()
        .unwrap_or(Value::Null);
    assert!(is_fingerprint(&consul_token));
    let proxy = &export.body["proxies"][0];
    assert_eq!(proxy["backend_host"], "staging.internal");

    let backup = get(&base, "/backup", Some(&viewer), Some("staging")).await;
    assert_eq!(backup.status, 403, "viewer must not reach the raw backup");
    assert!(!backup.text.contains(STAGING_KEY));
}

#[tokio::test]
async fn viewer_secret_token_is_capped_at_viewer_even_when_it_claims_admin() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(admin_state(config, false)).await;
    let capped_admin = token(VIEWER_SECRET, Algorithm::HS256, "admin", None);

    let export = get(&base, EXPORT, Some(&capped_admin), Some("staging")).await;
    assert_eq!(export.status, 200, "{}", export.text);

    for path in ["/backup", "/audit", "/gateway-trust-bundles"] {
        let reply = get(&base, path, Some(&capped_admin), Some("staging")).await;
        assert_eq!(
            reply.status, 403,
            "a viewer-secret token claiming admin must be refused on {path}: {}",
            reply.text
        );
        assert!(
            reply.text.contains("'viewer'"),
            "the refusal must name the capped role on {path}: {}",
            reply.text
        );
    }

    // Control: the same claims under the primary secret really are admin, so
    // the refusals above come from the ceiling and not from the route.
    let real_admin = token(PRIMARY_SECRET, Algorithm::HS256, "admin", None);
    let path = "/gateway-trust-bundles";
    let reply = get(&base, path, Some(&real_admin), Some("staging")).await;
    assert_ne!(reply.status, 403, "{}", reply.text);
    assert_ne!(reply.status, 401, "{}", reply.text);
}

#[tokio::test]
async fn algorithm_confusion_and_non_admin_credentials_are_rejected() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(admin_state(config, false)).await;

    for algorithm in [Algorithm::HS384, Algorithm::HS512] {
        let confused = token(VIEWER_SECRET, algorithm, "admin", None);
        let reply = get(&base, EXPORT, Some(&confused), None).await;
        assert_eq!(reply.status, 401, "{algorithm:?}: {}", reply.text);
    }

    // Observability tiering: no credential and the metrics bearer token do
    // not reach configuration.
    let anonymous = get(&base, EXPORT, None, None).await;
    assert_eq!(anonymous.status, 401);
    let metrics = get(&base, EXPORT, Some(METRICS_TOKEN), None).await;
    assert_eq!(metrics.status, 401);
    assert!(!metrics.text.contains(STAGING_KEY));
}

#[tokio::test]
async fn fingerprints_are_stable_and_change_when_the_credential_changes() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(admin_state(config.clone(), false)).await;
    let viewer = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);

    let first = get(&base, EXPORT, Some(&viewer), Some("staging")).await;
    let second = get(&base, EXPORT, Some(&viewer), Some("staging")).await;
    assert_eq!(first.status, 200);
    assert_eq!(
        first.text, second.text,
        "exports of unchanged configuration must be byte-identical"
    );

    // Republishing an identical snapshot changes nothing either.
    config.store(Arc::new(two_tenant_config(STAGING_KEY)));
    let republished = get(&base, EXPORT, Some(&viewer), Some("staging")).await;
    assert_eq!(first.text, republished.text);

    config.store(Arc::new(two_tenant_config("rotated-staging-api-key")));
    let rotated = get(&base, EXPORT, Some(&viewer), Some("staging")).await;
    assert_eq!(rotated.status, 200);
    let before = keyauth_fingerprint(&first.body);
    let after = keyauth_fingerprint(&rotated.body);
    assert!(is_fingerprint(&after));
    assert_ne!(before, after, "a rotated key must fingerprint differently");
    assert_eq!(first.body["upstreams"], rotated.body["upstreams"]);
}

#[tokio::test]
async fn export_is_namespace_scoped_and_honours_ns_claims() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(admin_state(config, false)).await;

    // A present `ns` claim is honoured even with enforcement off.
    let staging_claim = Some(json!("staging"));
    let staging_only = token(VIEWER_SECRET, Algorithm::HS256, "viewer", staging_claim);
    let own = get(&base, EXPORT, Some(&staging_only), Some("staging")).await;
    assert_eq!(own.status, 200, "{}", own.text);
    assert_eq!(own.body["counts"]["consumers"], 1);
    assert_eq!(own.body["consumers"][0]["username"], "alice");
    assert!(!own.text.contains("consumer-prod"));
    let other = get(&base, EXPORT, Some(&staging_only), Some("prod")).await;
    assert_eq!(other.status, 403, "{}", other.text);
    assert!(!other.text.contains("consumer-prod"));

    // With no claim and enforcement off, the header is a selector only.
    let unscoped = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);
    let prod = get(&base, EXPORT, Some(&unscoped), Some("prod")).await;
    assert_eq!(prod.status, 200);
    assert_eq!(prod.body["consumers"][0]["username"], "bob");
    assert_eq!(prod.body["counts"]["upstreams"], 0);
}

#[tokio::test]
async fn export_requires_an_ns_claim_when_enforcement_is_on() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(admin_state(config, true)).await;

    let unscoped = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);
    let refused = get(&base, EXPORT, Some(&unscoped), Some("staging")).await;
    assert_eq!(refused.status, 403, "{}", refused.text);

    let staging_claim = Some(json!(["staging"]));
    let scoped = token(VIEWER_SECRET, Algorithm::HS256, "viewer", staging_claim);
    let allowed = get(&base, EXPORT, Some(&scoped), Some("staging")).await;
    assert_eq!(allowed.status, 200, "{}", allowed.text);
}

#[tokio::test]
async fn viewer_secret_token_is_refused_on_write_and_operator_routes() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(admin_state(config, false)).await;
    let capped_admin = token(VIEWER_SECRET, Algorithm::HS256, "admin", None);
    let proxy = json!({
        "id": "proxy-new",
        "listen_path": "/new",
        "backend_host": "new.internal",
        "backend_port": 8080,
        "backend_scheme": "http"
    });
    let consumer = json!({"id": "consumer-new", "username": "mallory"});
    let plugin = json!({"plugin_name": "cors", "scope": "global", "config": {}});
    let upstream = json!({"name": "new", "targets": [{"host": "new.internal", "port": 80}]});
    let credential = json!({"key": "mallory-key-0123456789"});
    let empty = json!({});

    use reqwest::Method;
    let writes: Vec<(Method, &str, Option<&Value>)> = vec![
        (Method::POST, "/proxies", Some(&proxy)),
        (Method::PUT, "/proxies/proxy-staging", Some(&proxy)),
        (Method::DELETE, "/proxies/proxy-staging", None),
        (Method::POST, "/consumers", Some(&consumer)),
        (Method::PUT, "/consumers/consumer-staging", Some(&consumer)),
        (Method::DELETE, "/consumers/consumer-staging", None),
        (Method::PUT, CREDENTIAL_PATH, Some(&credential)),
        (Method::POST, CREDENTIAL_PATH, Some(&credential)),
        (Method::DELETE, CREDENTIAL_PATH, None),
        (Method::POST, "/plugins/config", Some(&plugin)),
        (Method::PUT, "/plugins/config/plugin-x", Some(&plugin)),
        (Method::DELETE, "/plugins/config/plugin-x", None),
        (Method::POST, "/upstreams", Some(&upstream)),
        (Method::PUT, "/upstreams/upstream-staging", Some(&upstream)),
        (Method::DELETE, "/upstreams/upstream-staging", None),
        (Method::POST, "/batch", Some(&empty)),
        (Method::POST, "/restore?confirm=true", Some(&empty)),
        (Method::POST, "/namespaces", Some(&empty)),
        (Method::POST, "/admin/tls/certificates", Some(&empty)),
        (Method::DELETE, "/admin/tls/acme/certificates/cert-x", None),
        (
            Method::POST,
            "/mesh/config-revision/reset?confirm=true",
            None,
        ),
        (Method::POST, "/backend-capabilities/refresh", None),
    ];
    for (method, path, body) in writes {
        let label = format!("{method} {path}");
        let reply = send(method, &base, path, Some(&capped_admin), None, body).await;
        assert_eq!(reply.status, 403, "{label}: {}", reply.text);
        assert!(
            reply.text.contains("'viewer'"),
            "{label} must be refused by the viewer ceiling: {}",
            reply.text
        );
    }

    // The resources are untouched.
    let viewer = token(PRIMARY_SECRET, Algorithm::HS256, "viewer", None);
    let export = get(&base, EXPORT, Some(&viewer), Some("staging")).await;
    assert_eq!(export.body["counts"]["proxies"], 1);
    assert_eq!(export.body["counts"]["consumers"], 1);
}

#[tokio::test]
async fn viewer_secret_scope_claims_do_not_reach_diagnostic_lookups() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(admin_state(config, false)).await;
    let path = "/diagnostics/v1/refs/fd1_00000000000000000000000000000000";

    let capped = scoped_token(VIEWER_SECRET);
    let refused = get(&base, path, Some(&capped), None).await;
    assert_eq!(refused.status, 403, "{}", refused.text);
    assert!(
        refused.text.contains("diagnostics:read"),
        "{}",
        refused.text
    );

    // Control: the same claims under the primary key pass the scope check and
    // reach the (empty) reference store.
    let primary = scoped_token(PRIMARY_SECRET);
    let reached = get(&base, path, Some(&primary), None).await;
    assert_eq!(reached.status, 404, "{}", reached.text);
}

/// A token carrying `scope: diagnostics:read` and an `ns` claim.
fn scoped_token(secret: &str) -> String {
    let now = chrono::Utc::now();
    let claims = json!({
        "iss": ISSUER,
        "sub": "diagnostics-reader",
        "role": "admin",
        "scope": "diagnostics:read",
        "ns": ["ferrum", "staging"],
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

#[tokio::test]
async fn viewer_reads_and_the_export_mask_url_userinfo() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(admin_state(config, false)).await;
    let viewer = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);

    let path = "/upstreams/upstream-staging";
    let read = get(&base, path, Some(&viewer), Some("staging")).await;
    assert_eq!(read.status, 200, "{}", read.text);
    assert!(!read.text.contains(CONSUL_PASSWORD), "{}", read.text);
    let address = &read.body["service_discovery"]["consul"]["address"];
    assert_eq!(address, "http://redacted@consul.internal:8500/");

    let export = get(&base, EXPORT, Some(&viewer), Some("staging")).await;
    assert!(!export.text.contains(CONSUL_PASSWORD));
    let exported = export
        .body
        .pointer("/upstreams/0/service_discovery/consul/address")
        .cloned()
        .unwrap_or(Value::Null);
    assert!(is_fingerprint(&exported), "{exported}");
}

async fn sqlite_store(dir: &tempfile::TempDir) -> DatabaseStore {
    let path = dir.path().join("config-export.db");
    let url = format!("sqlite:{}?mode=rwc", path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, DbPoolConfig::default())
        .await
        .expect("connect sqlite store")
}

fn consumer_with_key(id: &str, username: &str, key: &str) -> Consumer {
    serde_json::from_value(json!({
        "id": id,
        "username": username,
        "credentials": {"keyauth": [{"key": key}]},
        "created_at": STAMP,
        "updated_at": STAMP
    }))
    .expect("consumer fixture deserializes")
}

#[tokio::test]
async fn database_export_is_labelled_and_falls_back_to_cached_on_database_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = sqlite_store(&dir).await;
    let database_key = "database-api-key-must-not-leak";
    db.create_consumer(&consumer_with_key("db-consumer", "dora", database_key))
        .await
        .expect("seed consumer");
    let pool = db.pool();

    let mut cached_config = GatewayConfig::default();
    let cached_key = "cached-api-key-must-not-leak";
    cached_config.consumers = vec![consumer_with_key("cached-consumer", "carol", cached_key)];
    let mut state = admin_state(cached(cached_config), false);
    state.db = Some(Arc::new(db));
    state.mode = "database".to_string();
    let (base, _sd) = start_admin(state).await;
    let viewer = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);

    let live = get(&base, EXPORT, Some(&viewer), None).await;
    assert_eq!(live.status, 200, "{}", live.text);
    assert_eq!(live.data_source.as_deref(), Some("database"));
    assert_eq!(live.body["source"], "database");
    assert_eq!(live.body["consumers"][0]["username"], "dora");
    assert!(is_fingerprint(&keyauth_fingerprint(&live.body)));
    assert!(!live.text.contains(database_key));

    // A database outage falls back to the labelled cached snapshot.
    pool.close().await;
    let fallback = get(&base, EXPORT, Some(&viewer), None).await;
    assert_eq!(fallback.status, 200, "{}", fallback.text);
    assert_eq!(fallback.data_source.as_deref(), Some("cached"));
    assert_eq!(fallback.body["source"], "cached");
    assert_eq!(fallback.body["consumers"][0]["username"], "carol");
    assert!(!fallback.text.contains(cached_key));
}

/// Userinfo is stripped only for `viewer` reads. `operator` and `admin` write
/// proxies and upstreams, so their reads must round-trip through `PUT`
/// unchanged, including username-only URLs such as `ssh://git@host`.
#[tokio::test]
async fn only_viewer_reads_strip_url_userinfo() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(admin_state(config, false)).await;
    let proxy_path = "/proxies/proxy-staging";
    let upstream_path = "/upstreams/upstream-staging";
    let stored_runbook = format!("https://ops:{LABEL_PASSWORD}@wiki.internal/runbook");
    let stored_address = format!("http://acl:{CONSUL_PASSWORD}@consul.internal:8500");

    for role in ["admin", "operator"] {
        let writer = token(PRIMARY_SECRET, Algorithm::HS256, role, None);
        let proxy = get(&base, proxy_path, Some(&writer), Some("staging")).await;
        assert_eq!(proxy.status, 200, "{role}: {}", proxy.text);
        let labels = &proxy.body["labels"];
        assert_eq!(labels["runbook"], stored_runbook.as_str(), "{role}");
        assert_eq!(labels["repo"], "ssh://git@github.com/org/repo", "{role}");

        let upstream = get(&base, upstream_path, Some(&writer), Some("staging")).await;
        assert_eq!(upstream.status, 200, "{role}: {}", upstream.text);
        let consul = &upstream.body["service_discovery"]["consul"];
        assert_eq!(consul["address"], stored_address.as_str(), "{role}");
    }

    // The Consul token stays withheld from operators, as before.
    let operator = token(PRIMARY_SECRET, Algorithm::HS256, "operator", None);
    let upstream = get(&base, upstream_path, Some(&operator), Some("staging")).await;
    assert!(!upstream.text.contains(CONSUL_TOKEN));

    let viewer = token(PRIMARY_SECRET, Algorithm::HS256, "viewer", None);
    let proxy = get(&base, proxy_path, Some(&viewer), Some("staging")).await;
    assert_eq!(proxy.status, 200, "{}", proxy.text);
    assert!(!proxy.text.contains(LABEL_PASSWORD));
    let labels = &proxy.body["labels"];
    assert_eq!(labels["runbook"], "https://redacted@wiki.internal/runbook");
    assert_eq!(labels["repo"], "ssh://redacted@github.com/org/repo");
}

// ── FERRUM_ADMIN_JWT_VIEWER_NAMESPACES (issue #5929) ────────────────────
//
// The namespace ceiling for viewer-key tokens is enforced by the admin
// dispatcher, so every route family is exercised here over a real listener.

const CEILING_REFUSAL: &str = "FERRUM_ADMIN_JWT_VIEWER_NAMESPACES";

/// Reads a viewer may make, one per namespace-scoped route family.
const NAMESPACE_SCOPED_READS: &[&str] = &[
    "/proxies",
    "/proxies/proxy-prod",
    "/consumers",
    "/consumers/consumer-prod",
    "/upstreams",
    "/upstreams/upstream-prod",
    "/plugins/config",
    "/plugins/config/plugin-prod",
    "/api-specs",
    "/api-specs/00000000-0000-0000-0000-000000000000",
    EXPORT,
    "/gateway-trust-bundles",
    "/gateway-trust-bundles/00000000-0000-0000-0000-000000000000",
    "/gateway-trust/status",
    "/backup",
    "/audit",
];

const NAMESPACE_SCOPED_POSTS: &[&str] = &["/batch", "/restore?confirm=true"];

fn ceiling_admin_state(
    cached: Arc<ArcSwap<GatewayConfig>>,
    require_namespace_claim: bool,
    ceiling: &str,
) -> AdminState {
    let mut state = admin_state(cached, require_namespace_claim);
    let ceiling = ViewerNamespaceCeiling::parse(ceiling).expect("valid ceiling");
    state.jwt_manager = jwt_manager().with_viewer_namespace_ceiling(ceiling);
    state
}

/// The two-tenant fixture with the namespace list file mode records at load.
fn registry_config() -> GatewayConfig {
    let mut config = two_tenant_config(STAGING_KEY);
    config.known_namespaces = vec![
        "ferrum".to_string(),
        "prod".to_string(),
        "staging".to_string(),
    ];
    config
}

fn listed_names(reply: &Reply) -> Vec<String> {
    let items = reply.body["data"].as_array().cloned().unwrap_or_default();
    let mut names: Vec<String> = items
        .iter()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect();
    names.sort();
    names
}

fn assert_ceiling_refusal(reply: &Reply, label: &str) {
    assert_eq!(reply.status, 403, "{label}: {}", reply.text);
    assert!(
        reply.text.contains(CEILING_REFUSAL),
        "{label} must be refused by the namespace ceiling: {}",
        reply.text
    );
    for leaked in ["consumer-prod", "bob", "prod.internal", PROD_KEY] {
        assert!(
            !reply.text.contains(leaked),
            "{label} disclosed {leaked}: {}",
            reply.text
        );
    }
}

#[tokio::test]
async fn viewer_key_token_is_refused_outside_the_namespace_ceiling_on_every_route_family() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(ceiling_admin_state(config, false, "staging")).await;

    // The holder chooses its claims: none, one outside the ceiling, or one
    // that lists both. None of them reaches `prod`.
    let claim_less = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);
    let prod_claim = Some(json!("prod"));
    let outside = token(VIEWER_SECRET, Algorithm::HS256, "viewer", prod_claim);
    let both_claim = Some(json!(["staging", "prod"]));
    let wide_admin = token(VIEWER_SECRET, Algorithm::HS256, "admin", both_claim);
    let tokens = [
        ("no ns claim", claim_less),
        ("ns=prod", outside),
        ("ns=[staging,prod] claiming admin", wide_admin),
    ];
    for (label, bearer) in &tokens {
        for path in NAMESPACE_SCOPED_READS {
            let reply = get(&base, path, Some(bearer), Some("prod")).await;
            assert_ceiling_refusal(&reply, &format!("{label} GET {path} (prod)"));
        }
        // Omitting the header selects `ferrum`, also outside the ceiling.
        let reply = get(&base, EXPORT, Some(bearer), None).await;
        assert_ceiling_refusal(&reply, &format!("{label} GET {EXPORT} (default namespace)"));
    }

    // Writes are refused too, before the role check or any body handling.
    let viewer = &tokens[0].1;
    let proxy = json!({"id": "proxy-new", "listen_path": "/new", "backend_host": "h"});
    let reply = send(
        reqwest::Method::POST,
        &base,
        "/proxies",
        Some(viewer),
        Some("prod"),
        Some(&proxy),
    )
    .await;
    assert_ceiling_refusal(&reply, "POST /proxies (prod)");
}

#[tokio::test]
async fn ceiling_bound_viewers_are_denied_global_routes_except_the_explicit_allowlist() {
    let config = cached(registry_config());
    let (base, _sd) = start_admin(ceiling_admin_state(config, false, "staging")).await;
    let ceiling_viewer = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);

    for path in [
        "/charges",
        "/metrics",
        "/admin/metrics",
        "/metrics/runtime",
        "/cluster",
        "/backend-capabilities",
    ] {
        let reply = get(&base, path, Some(&ceiling_viewer), None).await;
        assert_ceiling_refusal(&reply, &format!("GET {path}"));
    }

    for path in [
        "/namespaces",
        "/namespaces/staging",
        "/plugins",
        "/health",
        "/live",
        "/status",
    ] {
        let reply = get(&base, path, Some(&ceiling_viewer), None).await;
        assert_eq!(reply.status, 200, "GET {path}: {}", reply.text);
        if path == "/health" || path == "/status" {
            assert_eq!(reply.body.as_object().map(|body| body.len()), Some(2));
            assert!(reply.body.get("status").is_some(), "{}", reply.text);
            assert!(reply.body.get("ready").is_some(), "{}", reply.text);
        }
    }
    let overload = get(&base, "/overload", Some(&ceiling_viewer), None).await;
    assert_eq!(overload.status, 200, "{}", overload.text);
    assert_eq!(overload.body, json!({"level": "normal"}));

    let unbounded_config = cached(registry_config());
    let (unbounded_base, _sd) = start_admin(admin_state(unbounded_config, false)).await;
    let unbounded_viewer = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);
    for path in ["/health", "/status"] {
        let reply = get(&unbounded_base, path, Some(&unbounded_viewer), None).await;
        assert_eq!(reply.status, 200, "GET {path}: {}", reply.text);
        for detail in ["timestamp", "mode", "admin_writes_enabled", "fips"] {
            assert!(
                reply.body.get(detail).is_some(),
                "GET {path}: {}",
                reply.text
            );
        }
    }

    // A viewer-key token without a configured ceiling keeps the existing
    // global read behavior.
    let config = cached(registry_config());
    let (base, _sd) = start_admin(admin_state(config, false)).await;
    let fleet_viewer = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);
    for path in [
        "/charges",
        "/metrics",
        "/admin/metrics",
        "/metrics/runtime",
        "/cluster",
        "/backend-capabilities",
    ] {
        let reply = get(&base, path, Some(&fleet_viewer), None).await;
        assert_ne!(reply.status, 403, "GET {path}: {}", reply.text);
    }
}

#[tokio::test]
async fn ceiling_bound_viewers_cannot_post_batch_or_restore_outside_the_ceiling() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(ceiling_admin_state(config, false, "staging")).await;
    let viewer = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);

    for path in NAMESPACE_SCOPED_POSTS {
        let reply = send(
            reqwest::Method::POST,
            &base,
            path,
            Some(&viewer),
            Some("prod"),
            Some(&json!({})),
        )
        .await;
        assert_ceiling_refusal(&reply, &format!("POST {path}"));
    }
}

#[tokio::test]
async fn viewer_key_token_reads_normally_inside_the_namespace_ceiling() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(ceiling_admin_state(config, false, "staging,analytics")).await;

    let claim_less = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);
    let wide_claim = Some(json!(["staging", "prod"]));
    let wide = token(VIEWER_SECRET, Algorithm::HS256, "viewer", wide_claim);
    for bearer in [&claim_less, &wide] {
        let export = get(&base, EXPORT, Some(bearer), Some("staging")).await;
        assert_eq!(export.status, 200, "{}", export.text);
        assert_eq!(export.body["namespace"], "staging");
        assert_eq!(export.body["consumers"][0]["username"], "alice");

        for path in [
            "/proxies",
            "/proxies/proxy-staging",
            "/consumers",
            "/consumers/consumer-staging",
            "/upstreams",
            "/upstreams/upstream-staging",
            "/plugins/config",
        ] {
            let reply = get(&base, path, Some(bearer), Some("staging")).await;
            assert_eq!(reply.status, 200, "GET {path}: {}", reply.text);
            assert!(!reply.text.contains(CEILING_REFUSAL), "{path}");
        }

        // Inside the ceiling the ordinary role ceiling still applies.
        let backup = get(&base, "/backup", Some(bearer), Some("staging")).await;
        assert_eq!(backup.status, 403, "{}", backup.text);
        assert!(backup.text.contains("'viewer'"), "{}", backup.text);
        assert!(!backup.text.contains(CEILING_REFUSAL), "{}", backup.text);
    }

    // A missing resource inside the ceiling is an ordinary 404, not a 403.
    let missing = get(&base, "/proxies/nope", Some(&claim_less), Some("staging")).await;
    assert_eq!(missing.status, 404, "{}", missing.text);
    // An empty namespace inside the ceiling is readable (and empty).
    let empty = get(&base, "/proxies", Some(&claim_less), Some("analytics")).await;
    assert_eq!(empty.status, 200, "{}", empty.text);
}

#[tokio::test]
async fn primary_key_tokens_ignore_the_viewer_namespace_ceiling() {
    let config = cached(registry_config());
    let (base, _sd) = start_admin(ceiling_admin_state(config, false, "staging")).await;

    for role in ["viewer", "admin"] {
        let primary = token(PRIMARY_SECRET, Algorithm::HS256, role, None);
        let export = get(&base, EXPORT, Some(&primary), Some("prod")).await;
        assert_eq!(export.status, 200, "{role}: {}", export.text);
        assert_eq!(export.body["consumers"][0]["username"], "bob");
        let proxy = get(&base, "/proxies/proxy-prod", Some(&primary), Some("prod")).await;
        assert_eq!(proxy.status, 200, "{role}: {}", proxy.text);
        let list = get(&base, "/namespaces", Some(&primary), None).await;
        assert_eq!(list.status, 200, "{role}: {}", list.text);
        let names = listed_names(&list);
        assert_eq!(names, ["ferrum", "prod", "staging"], "{role}");
        let detail = get(&base, "/namespaces/prod", Some(&primary), None).await;
        assert_eq!(detail.status, 200, "{role}: {}", detail.text);
    }
}

#[tokio::test]
async fn unset_viewer_namespace_ceiling_keeps_viewer_key_tokens_fleet_wide() {
    let config = cached(registry_config());
    let (base, _sd) = start_admin(admin_state(config, false)).await;
    let viewer = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);

    let proxy = get(&base, "/proxies/proxy-prod", Some(&viewer), Some("prod")).await;
    assert_eq!(proxy.status, 200, "{}", proxy.text);
    let export = get(&base, EXPORT, Some(&viewer), Some("prod")).await;
    assert_eq!(export.status, 200, "{}", export.text);
    let list = get(&base, "/namespaces", Some(&viewer), None).await;
    assert_eq!(listed_names(&list), ["ferrum", "prod", "staging"]);
    let detail = get(&base, "/namespaces/prod", Some(&viewer), None).await;
    assert_eq!(detail.status, 200, "{}", detail.text);
}

#[tokio::test]
async fn namespace_registry_is_filtered_to_the_viewer_namespace_ceiling() {
    let config = cached(registry_config());
    let (base, _sd) = start_admin(ceiling_admin_state(config, false, "staging")).await;

    let claim_less = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);
    let wide_claim = Some(json!(["staging", "prod", "ferrum"]));
    let wide = token(VIEWER_SECRET, Algorithm::HS256, "viewer", wide_claim);
    for bearer in [&claim_less, &wide] {
        let list = get(&base, "/namespaces", Some(bearer), None).await;
        assert_eq!(list.status, 200, "{}", list.text);
        assert_eq!(listed_names(&list), ["staging"], "{}", list.text);

        let inside = get(&base, "/namespaces/staging", Some(bearer), None).await;
        assert_eq!(inside.status, 200, "{}", inside.text);
        for name in ["prod", "ferrum", "never-created"] {
            let path = format!("/namespaces/{name}");
            let outside = get(&base, &path, Some(bearer), None).await;
            // The same answer whether or not the namespace exists.
            assert_ceiling_refusal(&outside, &format!("GET {path}"));
        }
    }
}

#[tokio::test]
async fn database_namespace_registry_is_filtered_to_the_viewer_namespace_ceiling() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = sqlite_store(&dir).await;
    for (id, namespace) in [("c-staging", "staging"), ("c-prod", "prod")] {
        let consumer: Consumer = serde_json::from_value(json!({
            "id": id,
            "namespace": namespace,
            "username": id,
            "credentials": {},
            "created_at": STAMP,
            "updated_at": STAMP
        }))
        .expect("consumer fixture deserializes");
        db.create_consumer(&consumer).await.expect("seed consumer");
    }
    let mut state = ceiling_admin_state(cached(GatewayConfig::default()), false, "staging");
    state.db = Some(Arc::new(db));
    state.mode = "database".to_string();
    let (base, _sd) = start_admin(state).await;

    let viewer = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);
    let list = get(&base, "/namespaces", Some(&viewer), None).await;
    assert_eq!(list.status, 200, "{}", list.text);
    let names = listed_names(&list);
    assert_eq!(names, ["staging"], "{}", list.text);

    let primary = token(
        PRIMARY_SECRET,
        Algorithm::HS256,
        "viewer",
        Some(json!(["prod", "staging"])),
    );
    let list = get(&base, "/namespaces", Some(&primary), None).await;
    let names = listed_names(&list);
    assert!(names.iter().any(|name| name == "prod"), "{}", list.text);
    assert!(names.iter().any(|name| name == "staging"), "{}", list.text);

    let export = get(&base, EXPORT, Some(&viewer), Some("prod")).await;
    assert_ceiling_refusal(&export, "database-mode export (prod)");
    let export = get(&base, EXPORT, Some(&viewer), Some("staging")).await;
    assert_eq!(export.status, 200, "{}", export.text);
    assert_eq!(export.data_source.as_deref(), Some("database"));
}

#[tokio::test]
async fn viewer_namespace_ceiling_composes_with_namespace_claim_enforcement() {
    let config = cached(registry_config());
    let (base, _sd) = start_admin(ceiling_admin_state(config, true, "staging,prod")).await;

    let staging_claim = Some(json!(["staging", "ferrum"]));
    let scoped = token(VIEWER_SECRET, Algorithm::HS256, "viewer", staging_claim);
    let allowed = get(&base, EXPORT, Some(&scoped), Some("staging")).await;
    assert_eq!(allowed.status, 200, "{}", allowed.text);

    // Inside the ceiling but outside the claim: the claim gate refuses.
    let prod_claim = Some(json!(["prod"]));
    let prod_only = token(VIEWER_SECRET, Algorithm::HS256, "viewer", prod_claim);
    let refused = get(&base, EXPORT, Some(&prod_only), Some("staging")).await;
    assert_eq!(refused.status, 403, "{}", refused.text);
    assert!(!refused.text.contains(CEILING_REFUSAL), "{}", refused.text);
    // Inside the claim but outside the ceiling: the ceiling refuses.
    let refused = get(&base, "/proxies", Some(&prod_only), Some("prod")).await;
    assert_ceiling_refusal(&refused, "GET /proxies (prod) with ns=prod");

    // Claim enforcement still requires an explicit claim inside the ceiling.
    let claim_less = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);
    let refused = get(&base, "/proxies", Some(&claim_less), Some("staging")).await;
    assert_eq!(refused.status, 403, "{}", refused.text);
    assert!(refused.text.contains("`ns` claim"), "{}", refused.text);

    // Listing is filtered by both.
    let list = get(&base, "/namespaces", Some(&scoped), None).await;
    assert_eq!(list.status, 200, "{}", list.text);
    assert_eq!(listed_names(&list), ["staging"], "{}", list.text);
}

#[tokio::test]
async fn ceiling_refused_backup_is_recorded_with_namespace_ceiling_decision() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(sqlite_store(&dir).await);
    let mut state = ceiling_admin_state(cached(two_tenant_config(STAGING_KEY)), false, "staging");
    state.db = Some(db.clone());
    state.mode = "database".to_string();
    let (base, _sd) = start_admin(state).await;
    let viewer = token(VIEWER_SECRET, Algorithm::HS256, "viewer", None);

    let reply = get(&base, "/backup", Some(&viewer), Some("prod")).await;
    assert_ceiling_refusal(&reply, "GET /backup (prod)");

    let rows = db
        .list_audit_events(
            "ferrum",
            &ferrum_edge::admin::audit::AuditListFilter {
                action: Some("backup".to_string()),
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("list backup security audit rows");
    let event = rows
        .items
        .iter()
        .find(|event| event.outcome == "denied")
        .expect("ceiling refusal is durably audited");
    assert_eq!(event.diff["namespace_ceiling"], "outside");
}

#[tokio::test]
async fn viewer_key_diagnostic_lookups_stay_refused_under_the_namespace_ceiling() {
    let config = cached(two_tenant_config(STAGING_KEY));
    let (base, _sd) = start_admin(ceiling_admin_state(config, false, "prod")).await;
    let path = "/diagnostics/v1/refs/fd1_00000000000000000000000000000000";

    // `scoped_token` carries `ns: [ferrum, staging]`, both outside `prod`.
    let capped = scoped_token(VIEWER_SECRET);
    let refused = get(&base, path, Some(&capped), None).await;
    assert_eq!(refused.status, 403, "{}", refused.text);

    // Primary-key lookups are unaffected by the viewer ceiling.
    let primary = scoped_token(PRIMARY_SECRET);
    let reached = get(&base, path, Some(&primary), None).await;
    assert_eq!(reached.status, 404, "{}", reached.text);
}
