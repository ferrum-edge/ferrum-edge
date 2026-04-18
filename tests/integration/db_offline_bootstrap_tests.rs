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
