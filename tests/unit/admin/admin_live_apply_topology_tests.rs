//! Issue #3926 — live-apply sequence capture must stay on the pinned topology.
//!
//! `latest_change_sequence` is a covering watermark (`MAX(sequence)`), not the
//! mutation's exact assigned row. Capture it under the write-topology pin;
//! never re-query it after release. A reconnect that publishes a stale pool
//! must not turn that stale watermark into a false 2xx.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::_test_support::{
    DbPoolConfig, SqlReconnectTopology, SqlReconnectTransitionTestHooks,
    database_store_reconnect_as_failover_for_test,
    database_store_set_latest_change_sequence_fault_for_test,
    database_store_set_reconnect_transition_hooks_for_test,
};
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
};
use ferrum_edge::config::db_backend::DatabaseBackend;
use ferrum_edge::config::db_loader::DatabaseStore;
use ferrum_edge::config::runtime_config_apply::{
    LiveApplyFailure, LiveApplyMode, RuntimeConfigApply,
};
use ferrum_edge::config::types::{Proxy, default_namespace};
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode};
use serde_json::{Value, json};
use tokio::sync::oneshot;

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: "test-secret-key-for-admin-api".to_string(),
        issuer: "test-ferrum-edge".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn live_apply_state(
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
        admin_audit_fallback_dir: Some(crate::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
        db_available: Some(Arc::new(AtomicBool::new(true))),
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
        runtime_config_apply: apply,
    }
}

fn make_http_proxy(id: &str) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "namespace": "ferrum",
        "hosts": [format!("{id}.test")],
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080
    }))
    .unwrap()
}

fn ok_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from("{}")))
        .unwrap()
}

async fn response_json(response: Response<Full<Bytes>>) -> (u16, Value) {
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
    (status, value)
}

async fn sqlite_pair() -> (DatabaseStore, String, String, tempfile::TempDir) {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let primary_url = format!("sqlite:{}?mode=rwc", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());
    let store =
        DatabaseStore::connect_with_pool_config("sqlite", &primary_url, DbPoolConfig::default())
            .await
            .unwrap();
    // Migrate the failover file so a topology switch exposes an empty (stale)
    // `config_changes` table instead of a missing-schema query failure.
    DatabaseStore::connect_with_pool_config("sqlite", &failover_url, DbPoolConfig::default())
        .await
        .unwrap();
    (store, primary_url, failover_url, temp_dir)
}

#[tokio::test]
async fn prepare_is_noop_without_coordinator_or_served_namespace() {
    let (store, _primary, _failover, _tmp) = sqlite_pair().await;
    store
        .create_proxy(&make_http_proxy("p-noop"))
        .await
        .unwrap();
    database_store_set_latest_change_sequence_fault_for_test(&store, true);
    let db: Arc<dyn DatabaseBackend> = Arc::new(store);

    let none_state = live_apply_state(db.clone(), None);
    let prepared = none_state
        .prepare_live_apply_after_commit(&default_namespace(), 0)
        .await
        .expect("no coordinator must skip the sequence read");
    assert!(prepared.is_noop());

    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let served = live_apply_state(db, Some(apply));
    let other = served
        .prepare_live_apply_after_commit("other", 0)
        .await
        .expect("unserved namespace must skip the sequence read");
    assert!(other.is_noop());
}

#[tokio::test]
async fn covering_watermark_is_max_sequence_not_an_exact_row() {
    let (store, _primary, _failover, _tmp) = sqlite_pair().await;
    store.create_proxy(&make_http_proxy("p-a")).await.unwrap();
    store.create_proxy(&make_http_proxy("p-b")).await.unwrap();
    let covering = store
        .latest_change_sequence(&default_namespace())
        .await
        .unwrap();
    assert!(
        covering >= 2,
        "two durable writes must produce a covering watermark of at least 2, got {covering}"
    );

    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let topology_epoch = store.config_topology_epoch();
    let db: Arc<dyn DatabaseBackend> = Arc::new(store);
    let state = live_apply_state(db, Some(apply));
    let prepared = state
        .prepare_live_apply_after_commit(&default_namespace(), topology_epoch)
        .await
        .expect("sequence read on the pinned store");
    assert_eq!(prepared.covering_sequence(), Some(covering));
}

#[tokio::test]
async fn sequence_unavailable_returns_applied_false() {
    let (store, _primary, _failover, _tmp) = sqlite_pair().await;
    store
        .create_proxy(&make_http_proxy("p-seq-unavail"))
        .await
        .unwrap();
    database_store_set_latest_change_sequence_fault_for_test(&store, true);
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let db: Arc<dyn DatabaseBackend> = Arc::new(store.clone());
    let state = live_apply_state(db, Some(apply));

    let permit = state.admit_write().await.expect("admit on primary");
    let (status, body) = response_json(
        state
            .complete_live_config_mutation_after_commit(
                &default_namespace(),
                permit,
                ok_response(),
                LiveApplyMode::Sync,
            )
            .await,
    )
    .await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["applied"], false);
    assert_eq!(body["reason"], "sequence_unavailable");
}

#[tokio::test]
async fn active_coordinator_without_database_store_fails_closed() {
    let (store, _primary, _failover, _tmp) = sqlite_pair().await;
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let db: Arc<dyn DatabaseBackend> = Arc::new(store);
    let state = AdminState {
        db: None,
        ..live_apply_state(db, Some(apply))
    };

    let failure = state
        .prepare_live_apply_after_commit(&default_namespace(), 0)
        .await
        .expect_err("an active live-apply coordinator requires its database store");
    let (status, body) = response_json(failure).await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["applied"], false);
    assert_eq!(body["reason"], "sequence_unavailable");
}

#[tokio::test]
async fn captured_sequence_fails_closed_after_pinned_topology_is_replaced() {
    let (store, _primary, failover_url, _tmp) = sqlite_pair().await;
    store
        .create_proxy(&make_http_proxy("p-pinned"))
        .await
        .unwrap();
    let ns = default_namespace();
    let primary_covering = store.latest_change_sequence(&ns).await.unwrap();
    assert!(primary_covering >= 1);

    let primary_epoch = store.config_topology_epoch();
    let apply = Arc::new(RuntimeConfigApply::at_epoch(
        "ferrum",
        primary_epoch,
        primary_covering,
    ));
    let db: Arc<dyn DatabaseBackend> = Arc::new(store.clone());
    let state = live_apply_state(db, Some(apply.clone()));

    let permit = state.admit_write().await.expect("admit on primary");
    assert!(permit.is_pinned());
    assert_eq!(permit.topology_epoch(), primary_epoch);

    let (before_lock_tx, before_lock_rx) = oneshot::channel::<()>();
    let holding = Arc::new(AtomicBool::new(false));
    let before_lock_tx = Arc::new(StdMutex::new(Some(before_lock_tx)));
    database_store_set_reconnect_transition_hooks_for_test(
        &store,
        Some(SqlReconnectTransitionTestHooks {
            before_lock: Some(Arc::new({
                let before_lock_tx = Arc::clone(&before_lock_tx);
                move |topology| {
                    let before_lock_tx = Arc::clone(&before_lock_tx);
                    Box::pin(async move {
                        if topology != SqlReconnectTopology::Failover {
                            return;
                        }
                        if let Some(tx) = before_lock_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    })
                }
            })),
            while_holding: Some(Arc::new({
                let holding = Arc::clone(&holding);
                move |topology| {
                    let holding = Arc::clone(&holding);
                    Box::pin(async move {
                        if topology == SqlReconnectTopology::Failover {
                            holding.store(true, Ordering::SeqCst);
                        }
                    })
                }
            })),
        }),
    );

    let failover_store = store.clone();
    let failover_url_task = failover_url.clone();
    let failover_task = tokio::spawn(async move {
        database_store_reconnect_as_failover_for_test(&failover_store, &failover_url_task).await
    });
    before_lock_rx
        .await
        .expect("failover must reach write lock while admit pin is held");
    assert!(
        !holding.load(Ordering::SeqCst),
        "reconnect must wait while the topology pin is held"
    );

    let prepared = state
        .prepare_live_apply_after_commit(&ns, primary_epoch)
        .await
        .expect("sequence query while pin is held");
    assert_eq!(
        prepared.covering_sequence(),
        Some(primary_covering),
        "covering watermark must come from the pinned primary, not a stale failover pool"
    );
    assert!(
        !holding.load(Ordering::SeqCst),
        "sequence capture must complete while reconnect is still blocked"
    );

    drop(permit);
    failover_task
        .await
        .expect("join failover")
        .expect("failover reconnect after pin release");
    database_store_set_reconnect_transition_hooks_for_test(&store, None);
    assert!(!store.failover_topology_status().primary_active);
    let failover_epoch = store.config_topology_epoch();
    assert!(failover_epoch > primary_epoch);
    let stale = store.latest_change_sequence(&ns).await.unwrap();
    assert!(
        stale < primary_covering,
        "failover pool must expose a stale watermark ({stale} < {primary_covering})"
    );

    database_store_set_latest_change_sequence_fault_for_test(&store, true);
    apply.observe_topology(failover_epoch);
    let cursor = prepared.covering_cursor().expect("captured cursor");
    assert_eq!(
        apply.await_committed_cursor(cursor).await,
        Err(LiveApplyFailure::SequenceUnavailable),
        "an accepted watermark from the old topology must never cover failover data"
    );

    let (status, body) = response_json(
        state
            .finish_prepared_live_apply(prepared, ok_response())
            .await,
    )
    .await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["reason"], "sequence_unavailable");
}

#[tokio::test]
async fn complete_releases_pin_and_fails_when_reconnect_replaces_topology() {
    let (store, _primary, failover_url, _tmp) = sqlite_pair().await;
    store
        .create_proxy(&make_http_proxy("p-complete"))
        .await
        .unwrap();
    let ns = default_namespace();
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let db: Arc<dyn DatabaseBackend> = Arc::new(store.clone());
    let state = live_apply_state(db, Some(apply.clone()));

    let permit = state.admit_write().await.expect("admit on primary");
    let (before_lock_tx, before_lock_rx) = oneshot::channel::<()>();
    let before_lock_tx = Arc::new(StdMutex::new(Some(before_lock_tx)));
    database_store_set_reconnect_transition_hooks_for_test(
        &store,
        Some(SqlReconnectTransitionTestHooks {
            before_lock: Some(Arc::new({
                let before_lock_tx = Arc::clone(&before_lock_tx);
                move |topology| {
                    let before_lock_tx = Arc::clone(&before_lock_tx);
                    Box::pin(async move {
                        if topology != SqlReconnectTopology::Failover {
                            return;
                        }
                        if let Some(tx) = before_lock_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    })
                }
            })),
            while_holding: None,
        }),
    );

    let failover_store = store.clone();
    let failover_url_task = failover_url.clone();
    let failover_task = tokio::spawn(async move {
        database_store_reconnect_as_failover_for_test(&failover_store, &failover_url_task).await
    });
    before_lock_rx
        .await
        .expect("failover must reach write lock while admit pin is held");

    let complete_state = state.clone();
    let complete_ns = ns.clone();
    let complete_handle = tokio::spawn(async move {
        complete_state
            .complete_live_config_mutation_after_commit(
                &complete_ns,
                permit,
                ok_response(),
                LiveApplyMode::Sync,
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(5), failover_task)
        .await
        .expect("pin must be released before the live-apply wait")
        .expect("join failover")
        .expect("failover reconnect");
    database_store_set_reconnect_transition_hooks_for_test(&store, None);
    apply.observe_topology(store.config_topology_epoch());
    let response = tokio::time::timeout(Duration::from_secs(5), complete_handle)
        .await
        .expect("completion must fail promptly once topology changes")
        .expect("complete task");
    let (status, body) = response_json(response).await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["reason"], "sequence_unavailable");
}

/// Count `proxies` rows with `id` in one SQLite file, bypassing the store.
async fn sqlite_proxy_count(db_url: &str, id: &str) -> i64 {
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(db_url)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM proxies WHERE id = ?")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    pool.close().await;
    count
}

/// Issue #7033: a primary failback whose deferred migrations fail must not
/// leave the primary pool live behind failover topology. An opt-in Admin write
/// admitted afterwards must land on the failover database it is recorded
/// against, so the fence it raises protects writes that really are on the
/// failover side.
#[tokio::test]
async fn failed_failback_migration_keeps_admin_writes_on_failover_pool() {
    use ferrum_edge::_test_support::database_store_set_migrations_pending_for_test;
    use ferrum_edge::config::db_backend::primary_failback_fenced;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let primary_rw_url = format!("sqlite:{}?mode=rw", primary_path.to_string_lossy());
    let primary_create_url = format!("sqlite:{}?mode=rwc", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());

    let mut store = DatabaseStore::connect_with_failover(
        "sqlite",
        &primary_rw_url,
        std::slice::from_ref(&failover_url),
        DbPoolConfig::default(),
    )
    .await
    .unwrap();
    store.set_failover_allow_writes(true);
    assert!(!store.failover_topology_status().primary_active);

    // Migrate the primary file, then corrupt its core history so the deferred
    // migrations fail on failback.
    DatabaseStore::connect_with_pool_config("sqlite", &primary_create_url, DbPoolConfig::default())
        .await
        .unwrap();
    {
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect(&primary_create_url)
            .await
            .unwrap();
        sqlx::query("UPDATE _ferrum_migrations SET checksum = 'tampered-7033' WHERE version = 1")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }
    database_store_set_migrations_pending_for_test(&store, true);

    let error = store
        .reconnect(&primary_rw_url)
        .await
        .expect_err("failback must fail when the deferred migrations fail");
    assert!(!primary_failback_fenced(&error), "{error:#}");
    assert!(
        !store.failover_topology_status().primary_active,
        "a failed failback must leave topology on failover"
    );

    let db: Arc<dyn DatabaseBackend> = Arc::new(store.clone());
    let state = live_apply_state(db, None);
    let permit = state
        .admit_write()
        .await
        .expect("opt-in failover writes are admitted");
    store
        .create_proxy(&make_http_proxy("p-after-failed-failback"))
        .await
        .unwrap();
    drop(permit);

    let status = store.failover_topology_status();
    assert!(!status.primary_active);
    assert!(
        status.primary_failback_fenced,
        "the admitted failover write must fence failback"
    );
    assert_eq!(
        sqlite_proxy_count(&failover_url, "p-after-failed-failback").await,
        1,
        "the admitted write must land on the failover database"
    );
    assert_eq!(
        sqlite_proxy_count(&primary_create_url, "p-after-failed-failback").await,
        0,
        "the admitted write must not land on the primary behind failover topology"
    );

    // The fence now correctly protects a write that is on the failover side.
    let error = store
        .reconnect(&primary_rw_url)
        .await
        .expect_err("failback must stay fenced after the admitted failover write");
    assert!(primary_failback_fenced(&error), "{error:#}");
    assert!(!store.failover_topology_status().primary_active);
}
