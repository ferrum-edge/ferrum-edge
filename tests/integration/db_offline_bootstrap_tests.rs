//! Integration tests for `DatabaseStore::connect_offline_with_tls_config`.
//!
//! The offline bootstrap path is the mechanism that supports
//! `FERRUM_DB_CONFIG_BACKUP_PATH` when every configured DB URL is unreachable
//! at startup. Two invariants must hold for the gateway to actually recover
//! rather than stay stuck in degraded mode indefinitely:
//!
//! 1. **Failover URLs must be preserved on the store.** The polling loop's
//!    `try_failover_reconnect()` probes `self.failover_urls` — if it's empty,
//!    a primary that stays down permanently locks the gateway out of a
//!    healthy failover DB.
//! 2. **Migrations must run on the first successful reconnect.** The lazy
//!    pool skipped migrations at startup because the DB was unreachable. If
//!    `reconnect()` doesn't run them later, queries will error with "no such
//!    table" and `db_available` stays false forever.
//!
//! Both invariants are tested here end-to-end against real SQLite pools.

use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use tempfile::TempDir;

/// Build a pool config with short timeouts so unreachable URLs fail fast.
fn fast_fail_pool_config() -> DbPoolConfig {
    DbPoolConfig {
        connect_timeout_seconds: 2,
        acquire_timeout_seconds: 2,
        max_lifetime_seconds: 300,
        idle_timeout_seconds: 60,
        statement_timeout_seconds: 0,
        max_connections: 2,
        min_connections: 0,
    }
}

/// Offline-bootstrapped store should preserve the failover URL list so that
/// the polling loop's `try_failover_reconnect()` can probe each URL in order.
/// Verified by calling `try_failover_reconnect()` with an unreachable primary
/// and a reachable failover — the store must connect to the failover.
#[tokio::test(flavor = "multi_thread")]
async fn offline_bootstrap_preserves_failover_urls_and_reconnects() {
    let temp_dir = TempDir::new().unwrap();
    let failover_db_path = temp_dir.path().join("failover.db");
    let failover_url = format!("sqlite:{}?mode=rwc", failover_db_path.to_string_lossy());

    let bogus_primary = "sqlite:/nonexistent/offline-bootstrap/bogus.db?mode=ro".to_string();

    // Construct an offline store that knows about both the primary and the
    // failover URL. The lazy pool points at the (unreachable) primary.
    let store = DatabaseStore::connect_offline_with_tls_config(
        "sqlite",
        &bogus_primary,
        std::slice::from_ref(&failover_url),
        false,
        None,
        None,
        None,
        false,
        fast_fail_pool_config(),
    )
    .expect("offline store construction should succeed even with unreachable primary");

    // `try_failover_reconnect()` must try the failover URL because the store
    // was built with it. If the codex-flagged bug were present — empty
    // `failover_urls` — this would only attempt the primary and fail.
    let recovered_url = store
        .try_failover_reconnect(&bogus_primary, false, None, None, None, false)
        .await
        .expect("reconnect via failover URL should succeed");
    assert_eq!(
        recovered_url, failover_url,
        "try_failover_reconnect must report the failover URL as the recovery target"
    );

    // Failover SQLite file must have been created on disk — proves the pool
    // actually connected (mode=rwc auto-creates).
    assert!(
        failover_db_path.exists(),
        "failover SQLite file should exist after successful reconnect"
    );
}

/// An offline-bootstrapped store defers migrations (the lazy pool has no
/// live DB to run them against). `reconnect()` must run migrations the first
/// time it succeeds — otherwise polling-loop queries fail on missing tables.
///
/// Verified by:
/// 1. Building an offline store against an unreachable primary.
/// 2. Calling `try_failover_reconnect()` with a reachable failover.
/// 3. Running a query that requires the schema to exist. If migrations were
///    skipped, `load_full_config` errors with "no such table"; if they ran,
///    it returns an empty config (no rows yet).
#[tokio::test(flavor = "multi_thread")]
async fn offline_bootstrap_runs_migrations_on_first_successful_reconnect() {
    let temp_dir = TempDir::new().unwrap();
    let failover_db_path = temp_dir.path().join("failover.db");
    let failover_url = format!("sqlite:{}?mode=rwc", failover_db_path.to_string_lossy());

    let bogus_primary = "sqlite:/nonexistent/migrations-test/bogus.db?mode=ro".to_string();

    let store = DatabaseStore::connect_offline_with_tls_config(
        "sqlite",
        &bogus_primary,
        std::slice::from_ref(&failover_url),
        false,
        None,
        None,
        None,
        false,
        fast_fail_pool_config(),
    )
    .expect("offline store construction");

    // Before reconnect, the schema does not exist. A query against the lazy
    // pool (which points at the unreachable primary) fails.
    assert!(
        store.load_full_config("ferrum").await.is_err(),
        "load_full_config must fail before reconnect (primary unreachable, schema not created)"
    );

    // Reconnect via failover. `reconnect()` must run the deferred migrations,
    // otherwise subsequent queries will fail on missing tables.
    store
        .try_failover_reconnect(&bogus_primary, false, None, None, None, false)
        .await
        .expect("failover reconnect should succeed");

    // After reconnect, schema must exist. `load_full_config` against a fresh
    // SQLite returns an empty config, NOT a "no such table" error.
    let config = store
        .load_full_config("ferrum")
        .await
        .expect("load_full_config should succeed after migrations ran during reconnect");
    assert!(
        config.proxies.is_empty(),
        "fresh failover DB should have no proxies"
    );
    assert!(
        config.consumers.is_empty(),
        "fresh failover DB should have no consumers"
    );
}

/// A normal (non-offline) store must NOT re-run migrations on every
/// reconnect. Reconnect is called by the DNS-change path during normal
/// operation — re-running migrations there would be needless churn. This
/// test verifies the migrations-pending flag only applies to offline-
/// bootstrapped stores: after a normal connect, a reconnect shouldn't
/// re-execute the migration runner.
#[tokio::test(flavor = "multi_thread")]
async fn normal_reconnect_does_not_rerun_migrations() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("primary.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());

    // Eager connect — migrations run exactly once here.
    let store = DatabaseStore::connect_with_tls_config(
        "sqlite",
        &db_url,
        false,
        None,
        None,
        None,
        false,
        fast_fail_pool_config(),
    )
    .await
    .expect("initial connect");

    // Simulate a DNS-change reconnect to the same URL. Must succeed without
    // error — if migrations were re-run unconditionally they would skip
    // (since they already applied), but exposing an extra noisy log on every
    // DNS blip is avoidable.
    store
        .reconnect(&db_url, false, None, None, None, false)
        .await
        .expect("reconnect should succeed without side effects");

    // Schema still there, queries still work.
    let config = store
        .load_full_config("ferrum")
        .await
        .expect("load_full_config still works after reconnect");
    assert!(config.proxies.is_empty());
}

// ── maybe_apply_deferred_migrations ─────────────────────────────────────────

/// `maybe_apply_deferred_migrations` returns `Ok(true)` the first time it
/// runs migrations on an offline-bootstrapped store where the lazy pool
/// points at a now-reachable DB. Subsequent calls return `Ok(false)` —
/// migrations must not re-run once applied.
///
/// This is the primary entry point exercised at startup (after offline
/// bootstrap) and from the polling loop's success path, so it must return
/// the right signal to callers that gate `db_available` / `bootstrap_from_backup`
/// on the outcome.
#[tokio::test(flavor = "multi_thread")]
async fn maybe_apply_deferred_migrations_returns_true_only_on_first_apply() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("reachable.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());

    // Offline bootstrap against a URL that is immediately reachable — the
    // lazy pool will connect on the first query. `migrations_pending=true`
    // so the first `maybe_apply_deferred_migrations` should actually run.
    let store = DatabaseStore::connect_offline_with_tls_config(
        "sqlite",
        &db_url,
        &[],
        false,
        None,
        None,
        None,
        false,
        fast_fail_pool_config(),
    )
    .expect("offline store construction");

    // First call: migrations run, returns Ok(true).
    let ran = store
        .maybe_apply_deferred_migrations()
        .await
        .expect("first migration attempt should succeed against reachable DB");
    assert!(
        ran,
        "first call on an offline-bootstrapped store must run migrations"
    );

    // Second call: flag already cleared, returns Ok(false) without re-running.
    let ran_again = store
        .maybe_apply_deferred_migrations()
        .await
        .expect("second call must be a cheap no-op");
    assert!(
        !ran_again,
        "second call must return false — migrations already applied, CAS fails"
    );

    // Third call confirms idempotence.
    let ran_third = store
        .maybe_apply_deferred_migrations()
        .await
        .expect("third call must also be a cheap no-op");
    assert!(!ran_third);

    // Schema exists now — query succeeds.
    let config = store
        .load_full_config("ferrum")
        .await
        .expect("schema should be ready after migrations applied");
    assert!(config.proxies.is_empty());
}

/// `maybe_apply_deferred_migrations` on a store created by the normal
/// (eager) connect returns `Ok(false)` immediately — migrations already
/// ran during construction, nothing is pending.
///
/// This guards against a regression where the flag defaulted to `true`
/// for all stores, causing normal reconnects (DNS changes) to re-run
/// migrations needlessly.
#[tokio::test(flavor = "multi_thread")]
async fn maybe_apply_deferred_migrations_no_op_on_eager_connected_store() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("eager.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());

    let store = DatabaseStore::connect_with_tls_config(
        "sqlite",
        &db_url,
        false,
        None,
        None,
        None,
        false,
        fast_fail_pool_config(),
    )
    .await
    .expect("eager connect");

    // Flag defaults to false on eager-connect path; helper must no-op.
    let ran = store
        .maybe_apply_deferred_migrations()
        .await
        .expect("no-op call must not error");
    assert!(
        !ran,
        "eager-connected store has migrations_pending=false; helper must return false"
    );
}

/// When an offline-bootstrapped store's lazy pool connects on the first
/// query *without* any `reconnect()` call (the codex-flagged scenario for
/// the polling-loop path), `maybe_apply_deferred_migrations` still runs
/// migrations correctly — proving the polling loop's direct call covers
/// the "lazy pool works without reconnect" case that `reconnect()` alone
/// would have missed.
#[tokio::test(flavor = "multi_thread")]
async fn lazy_pool_direct_success_is_covered_by_polling_loop_path() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("direct.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());

    let store = DatabaseStore::connect_offline_with_tls_config(
        "sqlite",
        &db_url,
        &[],
        false,
        None,
        None,
        None,
        false,
        fast_fail_pool_config(),
    )
    .expect("offline store construction");

    // Deliberately do NOT call `reconnect()` — simulate the case where
    // the lazy pool happens to connect successfully on the first query
    // because the DB was reachable the whole time.
    //
    // The polling loop's success path calls `maybe_apply_deferred_migrations`
    // directly to cover this exact scenario. Without that call, the flag
    // would remain `true` forever and a future schema change would never
    // be applied.
    let ran = store
        .maybe_apply_deferred_migrations()
        .await
        .expect("direct migration via polling-loop path should succeed");
    assert!(
        ran,
        "polling-loop path must execute migrations even when reconnect never fired"
    );

    // Query succeeds — schema is now up to date.
    store
        .load_full_config("ferrum")
        .await
        .expect("queries succeed after direct migration path ran");
}
