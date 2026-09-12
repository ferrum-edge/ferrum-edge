//! Namespace registry CRUD composed with the database-mode read-your-write
//! live-apply coordinator (issue #3955 x #3926).
//!
//! A registry mutation only changes what this process serves when it moves
//! resource rows into or out of the served namespace. Those mutations must not
//! answer 2xx before the poll loop accepts a covering `config_changes`
//! generation, and must fail closed with #3926's redacted reason taxonomy when
//! it cannot. Tests that park a mutation on poll acceptance poll for the
//! covering watermark to be written before asserting the response is still
//! withheld, so the commit precondition is observed rather than assumed from a
//! fixed sleep. The mutations that write no change record at all — a
//! registry-only `POST`, a description-only `PUT`, an unconfirmed `DELETE` —
//! must never wait, because `latest_change_sequence` is a namespace-wide `MAX`
//! and waiting on it would block them behind an unrelated concurrent writer.

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_backend::DatabaseBackend;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::runtime_config_apply::RuntimeConfigApply;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

const JWT_SECRET: &str = "test-secret-key-for-namespace-live-apply";
const JWT_ISSUER: &str = "test-ferrum-edge";

/// A live-apply budget chosen so it can never fire in these tests.
///
/// Three of these tests park a request on the poll-acceptance wait, assert it
/// is still parked, and then drive the coordinator to the outcome under test.
/// The budget is scaffolding there, not the property — only
/// `rename_into_served_namespace_times_out_closed` exercises the timeout path,
/// and it sets its own 200ms budget explicitly.
///
/// It used to be 30s, which a heavily loaded runner can beat: the task can be
/// starved between observing the parked mutation and the call that drives the
/// outcome, and the request then answers `reload_timeout` instead of the expected
/// reason.
/// Observed on PR #4121 (`Integration Tests (admin-platform)`), where the job
/// recorded 30.42s for `rename_into_served_namespace_fails_closed_on_rejection`
/// and got `reload_timeout` where `config_rejected` was required — on a PR that
/// touches no live-apply code. Five minutes is far outside any plausible
/// scheduling stall while still bounding a genuinely wedged coordinator.
const NEVER_FIRES: Duration = Duration::from_secs(300);

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
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "namespace-live-apply",
        "role": "admin",
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
    .expect("token encodes")
}

fn test_pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 4,
        min_connections: 0,
        acquire_timeout_seconds: 10,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 300,
        connect_timeout_seconds: 5,
        statement_timeout_seconds: 0,
    }
}

/// A poll-loop coordinator that serves `namespace` and has accepted nothing.
/// A poll-loop coordinator pinned to the store's CURRENT topology epoch.
///
/// `RuntimeConfigApply::with_timeout` pins epoch 0, but `DatabaseStore`
/// initialises `topology_epoch` to 1. `prepare_live_apply_after_commit`
/// captures the covering cursor at `db.config_topology_epoch()`, while
/// `record_accepted` / `record_rejected` stamp the coordinator's own epoch —
/// so an epoch-0 coordinator can never satisfy a waiter parked at epoch 1, and
/// every outcome-recording test fell through to its own timeout instead.
fn coordinator(namespace: &str, epoch: u64, timeout: Duration) -> Arc<RuntimeConfigApply> {
    Arc::new(RuntimeConfigApply::with_timeout_at_epoch(
        namespace, epoch, 0, timeout,
    ))
}

async fn make_store(dir: &TempDir) -> DatabaseStore {
    let db_path = dir
        .path()
        .join(format!("ns-live-{}.db", uuid::Uuid::new_v4()));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, test_pool_config())
        .await
        .expect("connect sqlite store")
}

fn namespace_admin_state(
    db: Arc<dyn DatabaseBackend>,
    apply: Option<Arc<RuntimeConfigApply>>,
) -> AdminState {
    AdminState {
        db: Some(db),
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
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
        runtime_config_apply: apply,
    }
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("loopback addr parses");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind_test(addr)
        .await
        .expect("bind");
    let actual = listener.local_addr().expect("local addr");
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
            return (format!("http://{actual}"), shutdown_tx);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("admin listener at {actual} never became ready");
}

async fn send(
    method: reqwest::Method,
    base: &str,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut request = reqwest::Client::new()
        .request(method, format!("{base}{path}"))
        .bearer_auth(admin_token());
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.expect("request succeeds");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

fn spawn_send(
    method: reqwest::Method,
    base: &str,
    path: &str,
    body: Option<Value>,
) -> tokio::task::JoinHandle<(u16, Value)> {
    let base = base.to_string();
    let path = path.to_string();
    tokio::spawn(async move { send(method, &base, &path, body).await })
}

async fn seed_upstream(store: &DatabaseStore, namespace: &str, id: &str) {
    sqlx::query("INSERT INTO upstreams (id, namespace, name, targets) VALUES (?, ?, ?, '[]')")
        .bind(id)
        .bind(namespace)
        .bind(format!("{id}-name"))
        .execute(&store.pool())
        .await
        .expect("seed upstream");
}

/// A store whose derived tenant `tenant-a` holds one upstream, wired to a
/// coordinator that serves `served` and has accepted nothing yet.
struct RenameFixture {
    store: DatabaseStore,
    apply: Arc<RuntimeConfigApply>,
    base: String,
    /// Held only so the admin listener outlives the test body.
    _shutdown: tokio::sync::watch::Sender<bool>,
}

async fn rename_fixture(dir: &TempDir, served: &str, timeout: Duration) -> RenameFixture {
    let store = make_store(dir).await;
    seed_upstream(&store, "tenant-a", "u-rename").await;
    let apply = coordinator(served, store.config_topology_epoch(), timeout);
    let db: Arc<dyn DatabaseBackend> = Arc::new(store.clone());
    let (base, shutdown) = start_admin(namespace_admin_state(db, Some(apply.clone()))).await;
    RenameFixture {
        store,
        apply,
        base,
        _shutdown: shutdown,
    }
}

#[tokio::test]
async fn rename_into_served_namespace_waits_for_poll_acceptance() {
    let dir = TempDir::new().expect("temp dir");
    let fx = rename_fixture(&dir, "served", NEVER_FIRES).await;

    let handle = spawn_send(
        reqwest::Method::PUT,
        &fx.base,
        "/namespaces/tenant-a",
        Some(json!({"name": "served"})),
    );
    // The rename committed even though the response is withheld: the covering
    // watermark is readable and the resources already moved.
    let covering = covering_watermark(&fx.store, "served").await;
    assert!(
        !handle.is_finished(),
        "a rename into the served namespace must not answer before the poll loop accepts it"
    );
    assert!(covering >= 1, "rename must write upsert tombstones");

    fx.apply.record_accepted(covering);
    let (status, body) = handle.await.expect("rename task");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["name"], "served");
}

#[tokio::test]
async fn rename_into_served_namespace_fails_closed_on_rejection() {
    let dir = TempDir::new().expect("temp dir");
    let fx = rename_fixture(&dir, "served", NEVER_FIRES).await;

    let handle = spawn_send(
        reqwest::Method::PUT,
        &fx.base,
        "/namespaces/tenant-a",
        Some(json!({"name": "served"})),
    );
    let covering = covering_watermark(&fx.store, "served").await;
    assert!(!handle.is_finished(), "rename must still be waiting");
    fx.apply.record_rejected(covering);

    let (status, body) = handle.await.expect("rename task");
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["applied"], false);
    assert_eq!(body["reason"], "config_rejected");
    // Fail-closed here means "durable but not live", NOT "nothing applied":
    // the retryable-contention 503 shape must not be reused.
    assert!(body.get("rollback").is_none(), "{body}");
}

#[tokio::test]
async fn rename_into_served_namespace_times_out_closed() {
    let dir = TempDir::new().expect("temp dir");
    let fx = rename_fixture(&dir, "served", Duration::from_millis(200)).await;

    let (status, body) = send(
        reqwest::Method::PUT,
        &fx.base,
        "/namespaces/tenant-a",
        Some(json!({"name": "served"})),
    )
    .await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["applied"], false);
    assert_eq!(body["reason"], "reload_timeout");
}

#[tokio::test]
async fn waiting_rename_releases_the_registry_admission_lease() {
    let dir = TempDir::new().expect("temp dir");
    let fx = rename_fixture(&dir, "served", NEVER_FIRES).await;

    let rename = spawn_send(
        reqwest::Method::PUT,
        &fx.base,
        "/namespaces/tenant-a",
        Some(json!({"name": "served"})),
    );

    // Establish the precondition before probing: the rename has committed (its
    // covering record is readable) and is therefore parked on poll acceptance.
    // Probing first would race the rename's own lease acquisition and could
    // succeed for the wrong reason.
    let covering = covering_watermark(&fx.store, "served").await;
    assert!(!rename.is_finished(), "rename must be parked on the wait");

    // Every registry mutation takes the SAME global admission lease first. A
    // create that completes proves the waiting rename is not holding it — the
    // pins are dropped before the poll-acceptance wait, not across it. Were the
    // lease held across the wait, this probe would block until the timeout.
    let (status, body) = tokio::time::timeout(
        Duration::from_secs(10),
        send(
            reqwest::Method::POST,
            &fx.base,
            "/namespaces",
            Some(json!({"name": "probe"})),
        ),
    )
    .await
    .expect("a concurrent create must not block behind the parked rename");
    assert_eq!(status, 201, "{body}");

    fx.apply.record_accepted(covering);
    let (status, body) = rename.await.expect("rename task");
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn registry_only_create_does_not_wait_for_runtime_apply() {
    let dir = TempDir::new().expect("temp dir");
    let store = make_store(&dir).await;
    // A pending, unaccepted change record in the served namespace: a create
    // that waited on the namespace-wide MAX would block on this unrelated row.
    seed_config_change(&store, "served").await;
    let apply = coordinator(
        "served",
        store.config_topology_epoch(),
        Duration::from_millis(200),
    );
    let db: Arc<dyn DatabaseBackend> = Arc::new(store.clone());
    let (base, _shutdown) = start_admin(namespace_admin_state(db, Some(apply.clone()))).await;

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        Some(json!({"name": "served", "description": "empty tenant"})),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(apply.accepted_sequence(), 0, "no generation was accepted");
}

#[tokio::test]
async fn description_only_update_does_not_wait_for_runtime_apply() {
    let dir = TempDir::new().expect("temp dir");
    let store = make_store(&dir).await;
    seed_upstream(&store, "served", "u-desc").await;
    seed_config_change(&store, "served").await;
    let apply = coordinator(
        "served",
        store.config_topology_epoch(),
        Duration::from_millis(200),
    );
    let db: Arc<dyn DatabaseBackend> = Arc::new(store.clone());
    let (base, _shutdown) = start_admin(namespace_admin_state(db, Some(apply))).await;

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/served",
        Some(json!({"description": "renamed nothing"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["description"], "renamed nothing");
}

#[tokio::test]
async fn unconfirmed_delete_of_an_empty_served_tenant_does_not_wait() {
    let dir = TempDir::new().expect("temp dir");
    let store = make_store(&dir).await;
    let apply = coordinator(
        "served",
        store.config_topology_epoch(),
        Duration::from_millis(200),
    );
    let db: Arc<dyn DatabaseBackend> = Arc::new(store.clone());
    let (base, _shutdown) = start_admin(namespace_admin_state(db, Some(apply))).await;

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        Some(json!({"name": "served"})),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    // Only now, so the create above cannot be the thing that would have waited.
    seed_config_change(&store, "served").await;

    let (status, body) = send(reqwest::Method::DELETE, &base, "/namespaces/served", None).await;
    assert_eq!(status, 204, "{body}");
}

#[tokio::test]
async fn confirmed_cascade_delete_of_the_served_namespace_waits() {
    let dir = TempDir::new().expect("temp dir");
    let mut store = make_store(&dir).await;
    // The served namespace is normally protected from DELETE. Configure this
    // process to protect a different name so the coordination path itself is
    // exercised rather than short-circuited by the 409.
    store.set_protected_namespaces(&["ferrum".to_string()]);
    seed_upstream(&store, "served", "u-cascade").await;
    let apply = coordinator("served", store.config_topology_epoch(), NEVER_FIRES);
    let db: Arc<dyn DatabaseBackend> = Arc::new(store.clone());
    let (base, _shutdown) = start_admin(namespace_admin_state(db, Some(apply.clone()))).await;

    let handle = spawn_send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/served?confirm=true",
        None,
    );
    let covering = covering_watermark(&store, "served").await;
    assert!(
        !handle.is_finished(),
        "a confirmed cascade of the served namespace must wait for poll acceptance"
    );
    apply.record_accepted(covering);
    let (status, body) = handle.await.expect("delete task");
    assert_eq!(status, 204, "{body}");
}

#[tokio::test]
async fn rename_between_unserved_namespaces_does_not_wait() {
    let dir = TempDir::new().expect("temp dir");
    let store = make_store(&dir).await;
    seed_upstream(&store, "tenant-a", "u-unserved").await;
    // The coordinator serves a namespace neither side of this rename touches.
    let apply = coordinator(
        "served",
        store.config_topology_epoch(),
        Duration::from_millis(200),
    );
    let db: Arc<dyn DatabaseBackend> = Arc::new(store.clone());
    let (base, _shutdown) = start_admin(namespace_admin_state(db, Some(apply))).await;

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-a",
        Some(json!({"name": "tenant-b"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["name"], "tenant-b");
}

#[tokio::test]
async fn a_mode_without_a_live_apply_coordinator_never_waits() {
    let dir = TempDir::new().expect("temp dir");
    let store = make_store(&dir).await;
    seed_upstream(&store, "tenant-a", "u-none").await;
    // CP / DP / file mode and every test harness set `runtime_config_apply:
    // None`; a rename there must stay non-blocking.
    let db: Arc<dyn DatabaseBackend> = Arc::new(store.clone());
    let (base, _shutdown) = start_admin(namespace_admin_state(db, None)).await;

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-a",
        Some(json!({"name": "ferrum-moved"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

/// A durable `config_changes` row so the namespace-wide covering watermark is
/// strictly above the coordinator's accepted sequence.
///
/// Written directly: the point is an unaccepted watermark, not a real resource,
/// and a mutation that wrongly waited on the namespace-wide `MAX` would park on
/// exactly this row.
async fn seed_config_change(store: &DatabaseStore, namespace: &str) {
    sqlx::query(
        "INSERT INTO config_changes (namespace, resource_type, resource_id, operation, created_at) \
         VALUES (?, 'upstream', 'seed-watermark', 'upsert', ?)",
    )
    .bind(namespace)
    .bind(Utc::now().to_rfc3339())
    .execute(&store.pool())
    .await
    .expect("seed config change");
}

/// Waits until the parked mutation has durably written a covering change
/// record, then returns that watermark.
///
/// `!handle.is_finished()` alone cannot distinguish "committed and parked on
/// poll acceptance" from "has not committed yet" — a loaded runner can leave
/// the request short of the commit for longer than any fixed sleep. Polling
/// for the watermark makes that precondition observable instead of assumed.
///
/// The deadline is generous enough that it can never fire on a merely-slow
/// runner (same reasoning as [`NEVER_FIRES`]): a genuinely wedged coordinator
/// that never commits must still fail, and fail legibly. Sixty seconds is far
/// outside any plausible commit stall while still bounding a wedged writer.
async fn covering_watermark(store: &DatabaseStore, namespace: &str) -> u64 {
    const POLL: Duration = Duration::from_millis(10);
    const DEADLINE: Duration = Duration::from_secs(60);
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let sequence = store
            .latest_change_sequence(namespace)
            .await
            .expect("latest_change_sequence");
        if sequence >= 1 {
            return sequence;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "namespace {namespace}: covering config_changes record was never written \
                 within {DEADLINE:?}"
            );
        }
        tokio::time::sleep(POLL).await;
    }
}
