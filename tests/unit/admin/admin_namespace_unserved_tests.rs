//! Admin writes to a namespace the local data plane does not route (issue #5447).
//!
//! The Admin API is deliberately multi-namespace: a control plane stores every
//! tenant's configuration and each data plane subscribes to its own. A
//! single-process gateway is different — it projects every snapshot down to
//! `FERRUM_NAMESPACE` before serving it, so a resource written under any other
//! `X-Ferrum-Namespace` is committed, stays Admin-visible, and is never matched
//! by the local router. These tests pin the two signals that make that
//! observable instead of silent:
//!
//!   1. `X-Ferrum-Namespace-Unserved: true` on the accepted mutation response.
//!   2. One bounded `WARN` per `(namespace, resource kind)`.
//!
//! Plus the discovery surface: the `namespace` object on the authenticated
//! `/health` + `/status` detail (`active`, `serving_scope`,
//! `data_plane_single_namespace`).
//!
//! Routing is deliberately untouched, so there is nothing here asserting a
//! changed status code — every mutation below still succeeds exactly as before.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState, NAMESPACE_UNSERVED_HEADER,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_backend::DatabaseBackend;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::env_config::OperatingMode;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::ProxyState;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "unserved-namespace-test-secret-key-000000";
const JWT_ISSUER: &str = "ferrum-edge-unserved-ns-test";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn admin_token() -> String {
    token_with_role("admin")
}

fn token_with_role(role: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "unserved-ns-test",
        "role": role,
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

async fn sqlite_store(temp_dir: &TempDir, file: &str) -> Arc<dyn DatabaseBackend> {
    let db_path = temp_dir.path().join(file);
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store connects and migrates");
    Arc::new(store)
}

/// A data plane pinned to `namespace`, exactly as a serving mode builds it.
fn proxy_state_for(namespace: &str) -> ProxyState {
    let mut config = GatewayConfig::default();
    config.normalize_fields();
    let env_config = ferrum_edge::config::EnvConfig {
        mode: OperatingMode::Database,
        namespace: namespace.to_string(),
        ..Default::default()
    };
    let (state, _health_check_handles) = ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("ProxyState::new");
    state
}

/// `database`-mode admin state: the only shipped mode that is both a writable
/// Admin API and a single-namespace data plane, which is what makes the
/// issue #5447 condition reachable at all.
fn database_state(db: Arc<dyn DatabaseBackend>, active_namespace: &str) -> AdminState {
    let proxy_state = proxy_state_for(active_namespace);
    let cached = Some(proxy_state.config.clone());
    admin_state("database", Some(proxy_state), Some(db), cached)
}

/// Control-plane admin state: writable Admin, no local data plane.
fn control_plane_state(db: Arc<dyn DatabaseBackend>) -> AdminState {
    admin_state("cp", None, Some(db), None)
}

fn admin_state(
    mode: &str,
    proxy_state: Option<ProxyState>,
    db: Option<Arc<dyn DatabaseBackend>>,
    cached_config: Option<Arc<ArcSwap<GatewayConfig>>>,
) -> AdminState {
    AdminState {
        db,
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config,
        proxy_state,
        mode: mode.to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::isolated_audit_fallback_dir()),
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
        // No poll-loop coordinator: the mutation returns its synchronous
        // success status straight after the durable commit, which is also what
        // happens in production for a namespace this process does not serve.
        runtime_config_apply: None,
    }
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

/// `(status, unserved header value, body)` for one admin request.
async fn request(
    method: reqwest::Method,
    base: &str,
    path: &str,
    namespace: Option<&str>,
    body: Option<&Value>,
) -> (u16, Option<String>, Value) {
    let mut req = reqwest::Client::new()
        .request(method, format!("{base}{path}"))
        .bearer_auth(admin_token());
    if let Some(namespace) = namespace {
        req = req.header("X-Ferrum-Namespace", namespace);
    }
    if let Some(body) = body {
        req = req.json(body);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    // Read the documented (mixed-case) spelling: HTTP field names are
    // case-insensitive, so this also proves the wire form matches the spec name.
    let unserved = resp
        .headers()
        .get(NAMESPACE_UNSERVED_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = resp.json().await.unwrap_or(Value::Null);
    (status, unserved, body)
}

fn proxy_payload(id: &str, listen_path: &str) -> Value {
    json!({
        "id": id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
        "strip_listen_path": true,
    })
}

fn upstream_payload(id: &str, name: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "targets": [{"host": "127.0.0.1", "port": 8080, "weight": 100}],
        "algorithm": "round_robin",
    })
}

// The tests below observe the process-global issue #5447 warning bookkeeping;
// `serial_test::serial(admin_unserved_namespace_observability_lock)` serializes
// them for parallel `cargo test` runs.

/// The issue #5447 repro: a process serving `ferrum` accepts a proxy under
/// another namespace. The write still succeeds (routing is unchanged), but the
/// response now says the data plane will never route it, and the gateway logs
/// exactly once for the `(namespace, resource kind)` pair.
#[tokio::test]
#[serial_test::serial(admin_unserved_namespace_observability_lock)]
async fn accepted_write_to_an_unserved_namespace_is_marked_and_warned_once() {
    ferrum_edge::admin::reset_unserved_namespace_observability_for_test();
    let temp_dir = TempDir::new().unwrap();
    let db = sqlite_store(&temp_dir, "unserved_marked.db").await;
    let (base, _sd) = start_admin(database_state(db, "ferrum")).await;

    let (status, unserved, body) = request(
        reqwest::Method::POST,
        &base,
        "/proxies",
        Some("nexusiso"),
        Some(&proxy_payload("p-one", "/one")),
    )
    .await;
    assert_eq!(status, 201, "the write must still be accepted: {body}");
    assert_eq!(
        unserved.as_deref(),
        Some("true"),
        "an accepted write outside the served namespace must be marked"
    );

    // A second resource of the same kind in the same namespace: still marked on
    // the wire (the client needs it per response), but deduplicated in the log.
    let (status, unserved, body) = request(
        reqwest::Method::POST,
        &base,
        "/proxies",
        Some("nexusiso"),
        Some(&proxy_payload("p-two", "/two")),
    )
    .await;
    assert_eq!(status, 201, "second write must also be accepted: {body}");
    assert_eq!(unserved.as_deref(), Some("true"));

    // A different resource kind in the same namespace is a distinct dedup key.
    let (status, unserved, body) = request(
        reqwest::Method::POST,
        &base,
        "/upstreams",
        Some("nexusiso"),
        Some(&upstream_payload("u-one", "payments")),
    )
    .await;
    assert_eq!(status, 201, "upstream write must be accepted: {body}");
    assert_eq!(unserved.as_deref(), Some("true"));

    assert_eq!(
        ferrum_edge::admin::unserved_namespace_mutation_count_for_test(),
        3,
        "every accepted unserved mutation must be counted"
    );
    assert_eq!(
        ferrum_edge::admin::unserved_namespace_warn_emitted_count_for_test(),
        2,
        "one WARN per (namespace, resource kind), not per resource"
    );
}

/// A write into the served namespace must be indistinguishable from before:
/// no marker, no warning, no counter movement.
#[tokio::test]
#[serial_test::serial(admin_unserved_namespace_observability_lock)]
async fn write_to_the_served_namespace_is_not_marked() {
    ferrum_edge::admin::reset_unserved_namespace_observability_for_test();
    let temp_dir = TempDir::new().unwrap();
    let db = sqlite_store(&temp_dir, "served_unmarked.db").await;
    let (base, _sd) = start_admin(database_state(db, "ferrum")).await;

    // Explicit header naming the served namespace.
    let (status, unserved, body) = request(
        reqwest::Method::POST,
        &base,
        "/proxies",
        Some("ferrum"),
        Some(&proxy_payload("p-explicit", "/explicit")),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(unserved, None, "the served namespace must never be marked");

    // Absent header — the default namespace, which is also the served one here.
    let (status, unserved, body) = request(
        reqwest::Method::POST,
        &base,
        "/proxies",
        None,
        Some(&proxy_payload("p-default", "/default")),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(unserved, None);

    assert_eq!(
        ferrum_edge::admin::unserved_namespace_mutation_count_for_test(),
        0
    );
    assert_eq!(
        ferrum_edge::admin::unserved_namespace_warn_emitted_count_for_test(),
        0
    );
}

/// The marker follows `FERRUM_NAMESPACE`, not the `ferrum` default: a process
/// configured for `tenant-a` marks a write to `ferrum` and not the reverse.
/// This is the deployment shape from the issue report, inverted.
#[tokio::test]
#[serial_test::serial(admin_unserved_namespace_observability_lock)]
async fn the_marker_follows_the_configured_active_namespace() {
    ferrum_edge::admin::reset_unserved_namespace_observability_for_test();
    let temp_dir = TempDir::new().unwrap();
    let db = sqlite_store(&temp_dir, "configured_active.db").await;
    let (base, _sd) = start_admin(database_state(db, "tenant-a")).await;

    let (status, unserved, body) = request(
        reqwest::Method::POST,
        &base,
        "/proxies",
        Some("tenant-a"),
        Some(&proxy_payload("p-served", "/served")),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        unserved, None,
        "the configured namespace is the served one and must not be marked"
    );

    // The default namespace is now the unserved one.
    let (status, unserved, body) = request(
        reqwest::Method::POST,
        &base,
        "/proxies",
        None,
        Some(&proxy_payload("p-default", "/default")),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(unserved.as_deref(), Some("true"));
}

/// Multi-namespace writes are the point of a control plane: it stores every
/// namespace in its scope and each data plane subscribes to its own. A CP must
/// never mark or warn.
#[tokio::test]
#[serial_test::serial(admin_unserved_namespace_observability_lock)]
async fn control_plane_writes_are_never_marked() {
    ferrum_edge::admin::reset_unserved_namespace_observability_for_test();
    let temp_dir = TempDir::new().unwrap();
    let db = sqlite_store(&temp_dir, "control_plane.db").await;
    let (base, _sd) = start_admin(control_plane_state(db)).await;

    for namespace in ["prod", "staging", "ferrum"] {
        let (status, unserved, body) = request(
            reqwest::Method::POST,
            &base,
            "/proxies",
            Some(namespace),
            Some(&proxy_payload(
                &format!("p-{namespace}"),
                &format!("/{namespace}"),
            )),
        )
        .await;
        assert_eq!(status, 201, "CP write for {namespace} failed: {body}");
        assert_eq!(
            unserved, None,
            "a CP serves no traffic itself, so nothing is unserved there"
        );
    }

    assert_eq!(
        ferrum_edge::admin::unserved_namespace_warn_emitted_count_for_test(),
        0,
        "multi-namespace CP writes must not produce a misconfiguration warning"
    );
}

/// Reads, rejected writes, and global admin surfaces are all outside the
/// marker's scope.
#[tokio::test]
#[serial_test::serial(admin_unserved_namespace_observability_lock)]
async fn reads_rejections_and_global_routes_are_not_marked() {
    ferrum_edge::admin::reset_unserved_namespace_observability_for_test();
    let temp_dir = TempDir::new().unwrap();
    let db = sqlite_store(&temp_dir, "out_of_scope.db").await;
    let (base, _sd) = start_admin(database_state(db, "ferrum")).await;

    // A read of an unserved namespace: `GET /status` is the discovery surface,
    // so the per-request marker deliberately stays off reads.
    let (status, unserved, _) = request(
        reqwest::Method::GET,
        &base,
        "/proxies",
        Some("foreign-tenant"),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(unserved, None, "reads are not marked");

    // A rejected mutation never reached the store, so it is not the
    // silent-success condition issue #5447 is about. A `viewer` token is
    // refused by the route's role gate before any handler runs.
    let resp = reqwest::Client::new()
        .post(format!("{base}/proxies"))
        .bearer_auth(token_with_role("viewer"))
        .header("X-Ferrum-Namespace", "foreign-tenant")
        .json(&proxy_payload("p-denied", "/denied"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "a viewer token must not create a proxy"
    );
    assert!(
        resp.headers().get(NAMESPACE_UNSERVED_HEADER).is_none(),
        "a non-2xx response must not be marked"
    );

    // `/namespaces` is a global registry surface; `X-Ferrum-Namespace` does not
    // select a tenant there.
    let (status, unserved, body) = request(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        Some("foreign-tenant"),
        Some(&json!({"name": "brand-new"})),
    )
    .await;
    assert_eq!(status, 201, "namespace registry create failed: {body}");
    assert_eq!(
        unserved, None,
        "a global admin surface is never namespace-unserved"
    );

    assert_eq!(
        ferrum_edge::admin::unserved_namespace_warn_emitted_count_for_test(),
        0
    );
}

/// The discovery surface: authenticated `/status` and `/health` publish the one
/// namespace this process routes plus its closed-set serving scope, and the
/// unauthenticated tier keeps carrying neither.
#[tokio::test]
async fn status_publishes_the_active_namespace_and_serving_scope() {
    let temp_dir = TempDir::new().unwrap();
    let db = sqlite_store(&temp_dir, "status_namespace.db").await;
    let (base, _sd) = start_admin(database_state(db, "tenant-a")).await;

    // The readiness verdict is deliberately not asserted: it aggregates
    // process-global signals (JWKS trust, service discovery, replay authority)
    // that other tests in this binary can move. The detailed body shape is the
    // same for `200` and `503`, and it is the contract under test here.
    for path in ["/status", "/health"] {
        let (_, _, body) = request(reqwest::Method::GET, &base, path, None, None).await;
        assert_eq!(
            body["namespace"]["active"],
            json!("tenant-a"),
            "{path} must name the served namespace"
        );
        assert_eq!(
            body["namespace"]["serving_scope"],
            json!("single-namespace-data-plane"),
            "{path} must label a serving process as single-namespace"
        );
        assert_eq!(
            body["namespace"]["data_plane_single_namespace"],
            json!(true),
            "{path} must say everything outside `active` is unrouted here"
        );
    }

    // Unauthenticated probes keep the coarse `status` + `ready` contract.
    let resp = reqwest::Client::new()
        .get(format!("{base}/status"))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.get("namespace").is_none(),
        "the namespace block is authenticated detail only: {body}"
    );
}

/// A control plane routes nothing, so it reports no active namespace rather
/// than advertising its own `FERRUM_NAMESPACE` as a serving target.
#[tokio::test]
async fn control_plane_status_reports_no_active_namespace() {
    let temp_dir = TempDir::new().unwrap();
    let db = sqlite_store(&temp_dir, "status_cp.db").await;
    let (base, _sd) = start_admin(control_plane_state(db)).await;

    // Readiness is not asserted here either; see the note above.
    let (_, _, body) = request(reqwest::Method::GET, &base, "/status", None, None).await;
    assert_eq!(
        body["namespace"]["active"],
        Value::Null,
        "a CP has no data-plane namespace"
    );
    assert_eq!(body["namespace"]["serving_scope"], json!("control-plane"));
    assert_eq!(
        body["namespace"]["data_plane_single_namespace"],
        json!(false),
        "a CP must not claim that other namespaces are unrouted"
    );
}
