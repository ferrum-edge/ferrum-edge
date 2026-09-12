//! Database-mode admin mutations wait for the poll-loop generation (issue #3926).
//!
//! Successful POST/PUT/DELETE must not return 2xx until `ProxyState` is serving
//! a generation covering the captured `config_changes` watermark. Tests spawn a
//! small replica of the authoritative incremental poll path — they do not invent
//! a second apply implementation.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::config_change_watch::wait_for_config_poll_wake;
use ferrum_edge::config::db_backend::DatabaseBackend;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::env_config::OperatingMode;
use ferrum_edge::config::runtime_config_apply::{LiveApplyCursor, RuntimeConfigApply};
use ferrum_edge::config::types::{GatewayConfig, default_namespace};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::watch;

const JWT_SECRET: &str = "test-secret-key-for-admin-api";

async fn sqlite_store() -> (Arc<DatabaseStore>, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("admin_live_apply.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store");
    (Arc::new(store), temp_dir)
}

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
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
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

fn proxy_payload(listen_path: &str) -> Value {
    json!({
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
        "strip_listen_path": true
    })
}

fn proxy_state() -> ProxyState {
    let mut config = GatewayConfig::default();
    config.normalize_fields();
    let env_config = ferrum_edge::config::EnvConfig {
        mode: OperatingMode::Database,
        ..Default::default()
    };
    let (state, _handles) = ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("ProxyState::new");
    state
}

fn live_admin_state(
    store: Arc<DatabaseStore>,
    proxy_state: ProxyState,
    apply: Arc<RuntimeConfigApply>,
) -> AdminState {
    AdminState {
        db: Some(store),
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: Some(proxy_state.config.clone()),
        proxy_state: Some(proxy_state),
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
        runtime_config_apply: Some(apply),
    }
}

async fn start_admin(state: AdminState) -> (String, watch::Sender<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
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
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (format!("http://{addr}"), shutdown_tx)
}

async fn admin_json(
    method: reqwest::Method,
    base_url: &str,
    path: &str,
    token: &str,
    body: Option<&Value>,
) -> (u16, Value) {
    let mut req = reqwest::Client::new()
        .request(method, format!("{base_url}{path}"))
        .bearer_auth(token);
    if let Some(body) = body {
        req = req.json(body);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

// Mirrors the database-mode poll loop's own parameter set: store, namespace,
// runtime state, apply coordinator, shutdown, and the three per-test knobs.
// A params struct here would only rename the same eight values.
#[allow(clippy::too_many_arguments)]
fn spawn_authoritative_poller(
    store: Arc<DatabaseStore>,
    namespace: String,
    proxy_state: ProxyState,
    apply: Arc<RuntimeConfigApply>,
    mut shutdown: watch::Receiver<bool>,
    poll_delay: Duration,
    polls_completed: Arc<AtomicU64>,
    reject: bool,
) {
    let wake = apply.wake_signal();
    tokio::spawn(async move {
        let db: Arc<dyn DatabaseBackend> = store;
        let initial_permit = db.acquire_write_topology_permit().await;
        let initial_epoch = initial_permit.topology_epoch();
        let initial_sequence = db.latest_change_sequence(&namespace).await.unwrap_or(0);
        let mut last_cursor = LiveApplyCursor::new(initial_epoch, initial_sequence);
        apply.record_accepted_cursor(last_cursor);
        drop(initial_permit);
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = wait_for_config_poll_wake(
                    &mut interval,
                    Some(&wake),
                    Duration::ZERO,
                    None,
                ) => {
                    if !poll_delay.is_zero() {
                        tokio::time::sleep(poll_delay).await;
                    }
                    if reject {
                        let permit = db.acquire_write_topology_permit().await;
                        let topology_epoch = permit.topology_epoch();
                        if let Ok(sequence) = db.latest_change_sequence(&namespace).await {
                            apply.record_rejected_cursor(LiveApplyCursor::new(
                                topology_epoch,
                                sequence,
                            ));
                        }
                        drop(permit);
                        polls_completed.fetch_add(1, Ordering::Relaxed);
                        apply.nudge_if_waiters_pending();
                        continue;
                    }
                    let load_permit = db.acquire_write_topology_permit().await;
                    let load_epoch = load_permit.topology_epoch();
                    if load_epoch != last_cursor.topology_epoch {
                        apply.observe_topology(load_epoch);
                        last_cursor = LiveApplyCursor::new(load_epoch, 0);
                        drop(load_permit);
                    } else if let Ok(result) = db
                        .load_incremental_config(&namespace, last_cursor.sequence)
                        .await
                    {
                        let next = LiveApplyCursor::new(load_epoch, result.sequence_cursor);
                        drop(load_permit);
                        match proxy_state.apply_incremental(result).await {
                            ConfigApplyOutcome::Applied | ConfigApplyOutcome::Unchanged => {
                                let final_permit = db.acquire_write_topology_permit().await;
                                if final_permit.topology_epoch() == load_epoch {
                                    last_cursor = next;
                                    apply.record_accepted_cursor(next);
                                } else {
                                    apply.observe_topology(final_permit.topology_epoch());
                                }
                            }
                            ConfigApplyOutcome::Rejected { .. } => {
                                let final_permit = db.acquire_write_topology_permit().await;
                                if final_permit.topology_epoch() == load_epoch {
                                    apply.record_rejected_cursor(next);
                                } else {
                                    apply.observe_topology(final_permit.topology_epoch());
                                }
                            }
                        }
                    } else {
                        drop(load_permit);
                    }
                    polls_completed.fetch_add(1, Ordering::Relaxed);
                    apply.nudge_if_waiters_pending();
                }
                _ = shutdown.changed() => return,
            }
        }
    });
}

fn runtime_has_listen_path(proxy_state: &ProxyState, listen_path: &str) -> bool {
    proxy_state
        .current_config()
        .proxies
        .iter()
        .any(|proxy| proxy.listen_path.as_deref() == Some(listen_path))
}

#[tokio::test]
async fn create_update_delete_are_live_on_success() {
    let (store, _tmp) = sqlite_store().await;
    let ns = default_namespace();
    let proxy_state = proxy_state();
    let seq = store.latest_change_sequence(&ns).await.unwrap_or(0);
    let apply = Arc::new(RuntimeConfigApply::at_epoch(
        ns.clone(),
        store.config_topology_epoch(),
        seq,
    ));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_authoritative_poller(
        store.clone(),
        ns,
        proxy_state.clone(),
        apply.clone(),
        shutdown_rx,
        Duration::ZERO,
        Arc::new(AtomicU64::new(0)),
        false,
    );
    let state = live_admin_state(store, proxy_state.clone(), apply);
    let (base, _admin_shutdown) = start_admin(state).await;
    let token = admin_token();

    let (status, body) = tokio::time::timeout(
        Duration::from_secs(5),
        admin_json(
            reqwest::Method::POST,
            &base,
            "/proxies",
            &token,
            Some(&proxy_payload("/live-create")),
        ),
    )
    .await
    .expect("create must not wait for the poll interval");
    assert_eq!(status, 201, "create: {body}");
    assert!(
        runtime_has_listen_path(&proxy_state, "/live-create"),
        "201 must mean the proxy is in the live snapshot"
    );
    let id = body["id"].as_str().expect("created id").to_string();

    let update = proxy_payload("/live-update");
    let (status, body) = tokio::time::timeout(
        Duration::from_secs(5),
        admin_json(
            reqwest::Method::PUT,
            &base,
            &format!("/proxies/{id}"),
            &token,
            Some(&update),
        ),
    )
    .await
    .expect("update must not wait for the poll interval");
    assert_eq!(status, 200, "update: {body}");
    assert!(runtime_has_listen_path(&proxy_state, "/live-update"));
    assert!(!runtime_has_listen_path(&proxy_state, "/live-create"));

    let (status, body) = tokio::time::timeout(
        Duration::from_secs(5),
        admin_json(
            reqwest::Method::DELETE,
            &base,
            &format!("/proxies/{id}"),
            &token,
            None,
        ),
    )
    .await
    .expect("delete must not wait for the poll interval");
    assert_eq!(status, 204, "delete: {body}");
    assert!(!runtime_has_listen_path(&proxy_state, "/live-update"));
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn concurrent_writes_coalesce_and_both_become_live() {
    let (store, _tmp) = sqlite_store().await;
    let ns = default_namespace();
    let proxy_state = proxy_state();
    let seq = store.latest_change_sequence(&ns).await.unwrap_or(0);
    let apply = Arc::new(RuntimeConfigApply::at_epoch(
        ns.clone(),
        store.config_topology_epoch(),
        seq,
    ));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_authoritative_poller(
        store.clone(),
        ns,
        proxy_state.clone(),
        apply.clone(),
        shutdown_rx,
        Duration::from_millis(50),
        Arc::new(AtomicU64::new(0)),
        false,
    );
    let state = live_admin_state(store, proxy_state.clone(), apply);
    let (base, _admin_shutdown) = start_admin(state).await;
    let token = admin_token();

    // Bind both payloads: `admin_json` borrows them, and the futures are not
    // awaited until the `tokio::join!` below, which outlives a temporary.
    let payload_a = proxy_payload("/coalesce-a");
    let payload_b = proxy_payload("/coalesce-b");
    let post_a = admin_json(
        reqwest::Method::POST,
        &base,
        "/proxies",
        &token,
        Some(&payload_a),
    );
    let post_b = admin_json(
        reqwest::Method::POST,
        &base,
        "/proxies",
        &token,
        Some(&payload_b),
    );
    let ((status_a, body_a), (status_b, body_b)) =
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(post_a, post_b)
        })
        .await
        .expect("concurrent creates must coalesce onto one reload");
    assert_eq!(status_a, 201, "a: {body_a}");
    assert_eq!(status_b, 201, "b: {body_b}");
    assert!(runtime_has_listen_path(&proxy_state, "/coalesce-a"));
    assert!(runtime_has_listen_path(&proxy_state, "/coalesce-b"));
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn reload_failure_after_commit_returns_503_applied_false() {
    let (store, _tmp) = sqlite_store().await;
    let ns = default_namespace();
    let proxy_state = proxy_state();
    let seq = store.latest_change_sequence(&ns).await.unwrap_or(0);
    let apply = Arc::new(RuntimeConfigApply::at_epoch(
        ns.clone(),
        store.config_topology_epoch(),
        seq,
    ));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_authoritative_poller(
        store.clone(),
        ns,
        proxy_state.clone(),
        apply.clone(),
        shutdown_rx,
        Duration::ZERO,
        Arc::new(AtomicU64::new(0)),
        true,
    );
    let state = live_admin_state(store, proxy_state.clone(), apply);
    let (base, _admin_shutdown) = start_admin(state).await;
    let token = admin_token();

    let (status, body) = tokio::time::timeout(
        Duration::from_secs(5),
        admin_json(
            reqwest::Method::POST,
            &base,
            "/proxies",
            &token,
            Some(&proxy_payload("/rejected-live")),
        ),
    )
    .await
    .expect("rejected apply must fail closed without the 30s budget");
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["applied"], false);
    assert_eq!(body["reason"], "config_rejected");
    assert!(
        !runtime_has_listen_path(&proxy_state, "/rejected-live"),
        "rejected generation must not be served"
    );
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn write_during_in_flight_poll_and_after_empty_poll_still_becomes_live() {
    let (store, _tmp) = sqlite_store().await;
    let ns = default_namespace();
    let proxy_state = proxy_state();
    let seq = store.latest_change_sequence(&ns).await.unwrap_or(0);
    let apply = Arc::new(RuntimeConfigApply::at_epoch(
        ns.clone(),
        store.config_topology_epoch(),
        seq,
    ));
    let polls = Arc::new(AtomicU64::new(0));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_authoritative_poller(
        store.clone(),
        ns,
        proxy_state.clone(),
        apply.clone(),
        shutdown_rx,
        Duration::from_millis(80),
        polls.clone(),
        false,
    );
    apply.wake_signal().signal_immediate();
    let started = std::time::Instant::now();
    while polls.load(Ordering::Relaxed) == 0 {
        if started.elapsed() > Duration::from_secs(5) {
            panic!("empty poll never completed");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let state = live_admin_state(store, proxy_state.clone(), apply.clone());
    let (base, _admin_shutdown) = start_admin(state).await;
    let token = admin_token();

    apply.wake_signal().signal_immediate();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (status, body) = tokio::time::timeout(
        Duration::from_secs(5),
        admin_json(
            reqwest::Method::POST,
            &base,
            "/proxies",
            &token,
            Some(&proxy_payload("/after-empty-poll")),
        ),
    )
    .await
    .expect("write during/after a poll must re-arm or join the in-flight reload");
    assert_eq!(status, 201, "{body}");
    assert!(runtime_has_listen_path(&proxy_state, "/after-empty-poll"));
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn tests_without_a_poll_loop_do_not_wait() {
    let (store, _tmp) = sqlite_store().await;
    let proxy_state = proxy_state();
    let mut state = live_admin_state(
        store,
        proxy_state.clone(),
        Arc::new(RuntimeConfigApply::new(default_namespace(), 0)),
    );
    state.runtime_config_apply = None;
    let (base, _shutdown) = start_admin(state).await;
    let token = admin_token();
    let (status, body) = tokio::time::timeout(
        Duration::from_secs(2),
        admin_json(
            reqwest::Method::POST,
            &base,
            "/proxies",
            &token,
            Some(&proxy_payload("/no-coordinator")),
        ),
    )
    .await
    .expect("None coordinator must not block");
    assert_eq!(status, 201, "{body}");
    assert!(
        !runtime_has_listen_path(&proxy_state, "/no-coordinator"),
        "without a poll loop the runtime snapshot stays unchanged"
    );
}

// ---------------------------------------------------------------------------
// Issue #4139 — deferred apply (`?apply=async`) + `GET /config/apply-status`.
// ---------------------------------------------------------------------------

async fn admin_request(
    method: reqwest::Method,
    base_url: &str,
    path: &str,
    token: &str,
    body: Option<&Value>,
) -> (u16, reqwest::header::HeaderMap, Value) {
    let mut req = reqwest::Client::new()
        .request(method, format!("{base_url}{path}"))
        .bearer_auth(token);
    if let Some(body) = body {
        req = req.json(body);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.json().await.unwrap_or_else(|_| json!({}));
    (status, headers, body)
}

/// Parse `X-Ferrum-Config-Cursor: {epoch}:{sequence}`.
fn cursor_from_headers(headers: &reqwest::header::HeaderMap) -> (u64, u64) {
    let raw = headers
        .get("x-ferrum-config-cursor")
        .expect("mutation response must carry the covering cursor header")
        .to_str()
        .expect("cursor header is ascii");
    let (epoch, sequence) = raw.split_once(':').expect("cursor is epoch:sequence");
    (
        epoch.parse().expect("epoch u64"),
        sequence.parse().expect("sequence u64"),
    )
}

struct DeferredHarness {
    proxy_state: ProxyState,
    base: String,
    token: String,
    shutdown_tx: watch::Sender<bool>,
    _admin_shutdown: watch::Sender<bool>,
    _tmp: TempDir,
}

/// Poller-backed admin server for the deferred-apply tests. `poll_delay` and
/// `reject` mirror `spawn_authoritative_poller`'s knobs.
async fn deferred_harness(poll_delay: Duration, reject: bool) -> DeferredHarness {
    let (store, tmp) = sqlite_store().await;
    let ns = default_namespace();
    let proxy_state = proxy_state();
    let seq = store.latest_change_sequence(&ns).await.unwrap_or(0);
    let apply = Arc::new(RuntimeConfigApply::at_epoch(
        ns.clone(),
        store.config_topology_epoch(),
        seq,
    ));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_authoritative_poller(
        store.clone(),
        ns,
        proxy_state.clone(),
        apply.clone(),
        shutdown_rx,
        poll_delay,
        Arc::new(AtomicU64::new(0)),
        reject,
    );
    let state = live_admin_state(store, proxy_state.clone(), apply);
    let (base, admin_shutdown) = start_admin(state).await;
    DeferredHarness {
        proxy_state,
        base,
        token: admin_token(),
        shutdown_tx,
        _admin_shutdown: admin_shutdown,
        _tmp: tmp,
    }
}

#[tokio::test]
async fn deferred_create_returns_202_with_cursor_and_apply_status_converges() {
    let h = deferred_harness(Duration::from_millis(50), false).await;

    let (status, headers, body) = tokio::time::timeout(
        Duration::from_secs(5),
        admin_request(
            reqwest::Method::POST,
            &h.base,
            "/proxies?apply=async",
            &h.token,
            Some(&proxy_payload("/deferred-create")),
        ),
    )
    .await
    .expect("deferred create must not wait on the reload");
    assert_eq!(status, 202, "deferred create is accepted, not live: {body}");
    assert!(
        body["id"].as_str().is_some(),
        "202 keeps the created-resource body: {body}"
    );
    let (epoch, sequence) = cursor_from_headers(&headers);

    let (status, _headers, status_body) = tokio::time::timeout(
        Duration::from_secs(10),
        admin_request(
            reqwest::Method::GET,
            &h.base,
            &format!("/config/apply-status?epoch={epoch}&sequence={sequence}&wait_ms=5000"),
            &h.token,
            None,
        ),
    )
    .await
    .expect("blocking apply-status must nudge the poll, not sit on the interval");
    assert_eq!(status, 200, "{status_body}");
    assert_eq!(status_body["state"], "applied", "{status_body}");
    assert!(
        runtime_has_listen_path(&h.proxy_state, "/deferred-create"),
        "applied means the runtime snapshot serves the write"
    );
    let _ = h.shutdown_tx.send(true);
}

#[tokio::test]
async fn deferred_writes_converge_with_one_final_wait() {
    let h = deferred_harness(Duration::from_millis(30), false).await;

    let mut last_cursor = (0u64, 0u64);
    for path in ["/bulk-a", "/bulk-b", "/bulk-c"] {
        let (status, headers, body) = tokio::time::timeout(
            Duration::from_secs(5),
            admin_request(
                reqwest::Method::POST,
                &h.base,
                "/proxies?apply=async",
                &h.token,
                Some(&proxy_payload(path)),
            ),
        )
        .await
        .expect("deferred writes must pipeline without per-write reloads");
        assert_eq!(status, 202, "{path}: {body}");
        let cursor = cursor_from_headers(&headers);
        assert!(
            cursor >= last_cursor,
            "cursors are monotone per topology: {cursor:?} < {last_cursor:?}"
        );
        last_cursor = cursor;
    }

    // ONE wait on the LAST cursor covers every prior deferred write — this is
    // the bulk-provisioning recipe from issue #4139.
    let (status, _headers, body) = tokio::time::timeout(
        Duration::from_secs(10),
        admin_request(
            reqwest::Method::GET,
            &h.base,
            &format!(
                "/config/apply-status?epoch={}&sequence={}&wait_ms=5000",
                last_cursor.0, last_cursor.1
            ),
            &h.token,
            None,
        ),
    )
    .await
    .expect("single final wait");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "applied", "{body}");
    for path in ["/bulk-a", "/bulk-b", "/bulk-c"] {
        assert!(
            runtime_has_listen_path(&h.proxy_state, path),
            "{path} must be live once the covering cursor is applied"
        );
    }
    let _ = h.shutdown_tx.send(true);
}

#[tokio::test]
async fn deferred_write_rejected_candidate_is_reported_by_apply_status() {
    let h = deferred_harness(Duration::ZERO, true).await;

    let (status, headers, body) = tokio::time::timeout(
        Duration::from_secs(5),
        admin_request(
            reqwest::Method::POST,
            &h.base,
            "/proxies?apply=async",
            &h.token,
            Some(&proxy_payload("/deferred-rejected")),
        ),
    )
    .await
    .expect("deferred write returns before the poll rejects");
    assert_eq!(status, 202, "{body}");
    let (epoch, sequence) = cursor_from_headers(&headers);

    let (status, _headers, body) = tokio::time::timeout(
        Duration::from_secs(10),
        admin_request(
            reqwest::Method::GET,
            &h.base,
            &format!("/config/apply-status?epoch={epoch}&sequence={sequence}&wait_ms=5000"),
            &h.token,
            None,
        ),
    )
    .await
    .expect("apply-status resolves the rejection fail-closed");
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["state"], "rejected",
        "a rejected generation must not read as pending or applied: {body}"
    );
    assert!(
        !runtime_has_listen_path(&h.proxy_state, "/deferred-rejected"),
        "rejected generation must not be served"
    );
    let _ = h.shutdown_tx.send(true);
}

#[tokio::test]
async fn sync_mutations_carry_the_covering_cursor_header() {
    let h = deferred_harness(Duration::ZERO, false).await;

    let (status, headers, body) = tokio::time::timeout(
        Duration::from_secs(5),
        admin_request(
            reqwest::Method::POST,
            &h.base,
            "/proxies",
            &h.token,
            Some(&proxy_payload("/sync-cursor")),
        ),
    )
    .await
    .expect("sync create");
    assert_eq!(status, 201, "{body}");
    let (epoch, sequence) = cursor_from_headers(&headers);

    // The sync path already proved liveness; the header names the same cursor
    // apply-status classifies as applied without waiting.
    let (status, _headers, body) = admin_request(
        reqwest::Method::GET,
        &h.base,
        &format!("/config/apply-status?epoch={epoch}&sequence={sequence}"),
        &h.token,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "applied", "{body}");
    let _ = h.shutdown_tx.send(true);
}

#[tokio::test]
async fn apply_status_and_apply_mode_inputs_are_strictly_validated() {
    let h = deferred_harness(Duration::ZERO, false).await;

    for (path, expect) in [
        ("/config/apply-status", "epoch and sequence are required"),
        (
            "/config/apply-status?epoch=1",
            "epoch and sequence are required",
        ),
        (
            "/config/apply-status?epoch=1&sequence=x",
            "sequence must be an unsigned integer",
        ),
        (
            "/config/apply-status?epoch=1&epoch=2&sequence=3",
            "epoch must not be supplied more than once",
        ),
        (
            "/config/apply-status?epoch=1&sequence=2&wait_ms=999999",
            "wait_ms must be at most 30000",
        ),
    ] {
        let (status, _headers, body) =
            admin_request(reqwest::Method::GET, &h.base, path, &h.token, None).await;
        assert_eq!(status, 400, "{path}: {body}");
        assert_eq!(body["error"].as_str(), Some(expect), "{path}");
    }

    for path in ["/proxies?apply=deferred", "/proxies?apply=async&apply=sync"] {
        let (status, _headers, body) = admin_request(
            reqwest::Method::POST,
            &h.base,
            path,
            &h.token,
            Some(&proxy_payload("/never-created")),
        )
        .await;
        assert_eq!(status, 400, "{path}: {body}");
    }
    assert!(!runtime_has_listen_path(&h.proxy_state, "/never-created"));
    let _ = h.shutdown_tx.send(true);
}

#[tokio::test]
async fn apply_status_is_unverifiable_for_a_foreign_topology_epoch() {
    let h = deferred_harness(Duration::ZERO, false).await;

    let (status, headers, _body) = admin_request(
        reqwest::Method::POST,
        &h.base,
        "/proxies",
        &h.token,
        Some(&proxy_payload("/epoch-probe")),
    )
    .await;
    assert_eq!(status, 201);
    let (epoch, sequence) = cursor_from_headers(&headers);

    // A cursor from a replaced (or never-issued) topology cannot be proven
    // live by this process — truthfully unverifiable, never a false applied.
    let (status, _headers, body) = admin_request(
        reqwest::Method::GET,
        &h.base,
        &format!(
            "/config/apply-status?epoch={}&sequence={sequence}",
            epoch + 1
        ),
        &h.token,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "unverifiable", "{body}");
    let _ = h.shutdown_tx.send(true);
}

#[tokio::test]
async fn apply_status_does_not_wait_on_an_unissued_future_cursor() {
    let h = deferred_harness(Duration::ZERO, false).await;

    let (status, headers, _body) = admin_request(
        reqwest::Method::POST,
        &h.base,
        "/proxies",
        &h.token,
        Some(&proxy_payload("/issued-cursor-bound")),
    )
    .await;
    assert_eq!(status, 201);
    let (epoch, _sequence) = cursor_from_headers(&headers);

    let (status, _headers, body) = tokio::time::timeout(
        Duration::from_millis(500),
        admin_request(
            reqwest::Method::GET,
            &h.base,
            &format!(
                "/config/apply-status?epoch={epoch}&sequence={}&wait_ms=30000",
                u64::MAX
            ),
            &h.token,
            None,
        ),
    )
    .await
    .expect("an unissued future cursor must not register a blocking waiter");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "unverifiable", "{body}");
    let _ = h.shutdown_tx.send(true);
}

#[tokio::test]
async fn deferred_without_poll_loop_stays_plain_success_and_status_is_absent() {
    let (store, _tmp) = sqlite_store().await;
    let proxy_state = proxy_state();
    let mut state = live_admin_state(
        store,
        proxy_state.clone(),
        Arc::new(RuntimeConfigApply::new(default_namespace(), 0)),
    );
    state.runtime_config_apply = None;
    let (base, _shutdown) = start_admin(state).await;
    let token = admin_token();

    // No coordinator → nothing to defer: the write stays a plain 201 with no
    // cursor header, exactly like the sync no-coordinator contract.
    let (status, headers, body) = tokio::time::timeout(
        Duration::from_secs(2),
        admin_request(
            reqwest::Method::POST,
            &base,
            "/proxies?apply=async",
            &token,
            Some(&proxy_payload("/deferred-no-coordinator")),
        ),
    )
    .await
    .expect("None coordinator must not block");
    assert_eq!(status, 201, "{body}");
    assert!(headers.get("x-ferrum-config-cursor").is_none());

    let (status, _headers, body) = admin_request(
        reqwest::Method::GET,
        &base,
        "/config/apply-status?epoch=0&sequence=0",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test]
async fn deferred_batch_returns_202_with_cursor_and_converges() {
    // The exact shape the 30k scaling harness relies on (issues #4136/#4139):
    // POST /batch?apply=async answers 202 + cursor for an all-or-nothing
    // graph, and one blocking apply-status wait proves it live.
    let h = deferred_harness(Duration::from_millis(30), false).await;

    let batch = json!({
        "proxies": [
            proxy_payload("/batch-deferred-a"),
            proxy_payload("/batch-deferred-b"),
        ]
    });
    let (status, headers, body) = tokio::time::timeout(
        Duration::from_secs(5),
        admin_request(
            reqwest::Method::POST,
            &h.base,
            "/batch?apply=async",
            &h.token,
            Some(&batch),
        ),
    )
    .await
    .expect("deferred batch must not wait on the reload");
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["created"]["proxies"], 2, "{body}");
    let (epoch, sequence) = cursor_from_headers(&headers);

    let (status, _headers, body) = tokio::time::timeout(
        Duration::from_secs(10),
        admin_request(
            reqwest::Method::GET,
            &h.base,
            &format!("/config/apply-status?epoch={epoch}&sequence={sequence}&wait_ms=5000"),
            &h.token,
            None,
        ),
    )
    .await
    .expect("blocking apply-status");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "applied", "{body}");
    for path in ["/batch-deferred-a", "/batch-deferred-b"] {
        assert!(runtime_has_listen_path(&h.proxy_state, path));
    }
    let _ = h.shutdown_tx.send(true);
}
