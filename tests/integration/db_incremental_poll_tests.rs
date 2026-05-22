//! Integration tests for the incremental DB poll boundary condition.
//!
//! Verifies that `load_incremental_config` uses `>=` (inclusive) on the
//! `updated_at` comparison so that a row written at exactly the safety-margin
//! boundary is never missed.

use chrono::{Duration, Utc};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use std::collections::HashSet;
use tempfile::TempDir;

/// Helper: create a SQLite-backed `DatabaseStore` with migrations applied.
async fn sqlite_store() -> (DatabaseStore, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("incremental_poll_test.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store creation must succeed");
    (store, temp_dir)
}

/// A row whose `updated_at` equals `since_safe` (the 1-second-adjusted
/// boundary) must be included in the incremental result.
///
/// Before the fix, `WHERE updated_at > ?` excluded this row. After the fix
/// (`>=`), it is correctly returned. Duplicates are harmless because the
/// incremental merge is ID-keyed.
#[tokio::test(flavor = "multi_thread")]
async fn incremental_poll_includes_row_at_exact_boundary() {
    let (store, _temp_dir) = sqlite_store().await;

    // Pick a deterministic boundary timestamp.
    // `load_incremental_config(since)` subtracts 1 second internally
    // (`since_safe = since - 1s`), then queries `WHERE updated_at >= since_safe`.
    // We set the row's `updated_at` to `since - 1s` (i.e. exactly `since_safe`).
    let since = Utc::now();
    let boundary_ts = (since - Duration::seconds(1)).to_rfc3339();

    // Insert a minimal upstream row with `updated_at` at the exact boundary.
    let pool = store.pool();
    sqlx::query(
        "INSERT INTO upstreams (id, namespace, name, targets, algorithm, created_at, updated_at) \
         VALUES ('boundary-upstream', 'ferrum', 'boundary', '[{\"host\":\"127.0.0.1\",\"port\":8080}]', 'round_robin', ?, ?)",
    )
    .bind(&boundary_ts)
    .bind(&boundary_ts)
    .fetch_all(&pool)
    .await
    .expect("INSERT must succeed");

    // No known IDs — simulates a fresh incremental poll where we have no prior
    // state (the ID set is empty, so nothing counts as "previously seen").
    let empty: HashSet<String> = HashSet::new();

    let result = store
        .load_incremental_config("ferrum", since, &empty, &empty, &empty, &empty)
        .await
        .expect("incremental poll must succeed");

    // The upstream at the boundary timestamp must be included.
    assert_eq!(
        result.added_or_modified_upstreams.len(),
        1,
        "upstream at exact boundary timestamp must be returned by >= comparison"
    );
    assert_eq!(
        result.added_or_modified_upstreams[0].id,
        "boundary-upstream"
    );
}

/// A row whose `updated_at` is strictly before `since_safe` must NOT be
/// returned — the inclusive `>=` should not pull in arbitrarily old rows.
#[tokio::test(flavor = "multi_thread")]
async fn incremental_poll_excludes_row_before_boundary() {
    let (store, _temp_dir) = sqlite_store().await;

    let since = Utc::now();
    // Place the row 5 seconds before `since_safe` (i.e. 6 seconds before `since`).
    let old_ts = (since - Duration::seconds(6)).to_rfc3339();

    let pool = store.pool();
    sqlx::query(
        "INSERT INTO upstreams (id, namespace, name, targets, algorithm, created_at, updated_at) \
         VALUES ('old-upstream', 'ferrum', 'old', '[{\"host\":\"127.0.0.1\",\"port\":8080}]', 'round_robin', ?, ?)",
    )
    .bind(&old_ts)
    .bind(&old_ts)
    .fetch_all(&pool)
    .await
    .expect("INSERT must succeed");

    let empty: HashSet<String> = HashSet::new();

    let result = store
        .load_incremental_config("ferrum", since, &empty, &empty, &empty, &empty)
        .await
        .expect("incremental poll must succeed");

    // The old upstream must not appear.
    assert!(
        result.added_or_modified_upstreams.is_empty(),
        "upstream well before the boundary must not be returned"
    );
}

/// All four table queries (`proxies`, `consumers`, `plugin_configs`,
/// `upstreams`) must use inclusive comparison. Insert one row per table
/// at exactly the boundary and verify all are returned.
#[tokio::test(flavor = "multi_thread")]
async fn incremental_poll_boundary_all_four_tables() {
    let (store, _temp_dir) = sqlite_store().await;

    let since = Utc::now();
    let boundary_ts = (since - Duration::seconds(1)).to_rfc3339();

    let pool = store.pool();

    // Upstream
    sqlx::query(
        "INSERT INTO upstreams (id, namespace, name, targets, algorithm, created_at, updated_at) \
         VALUES ('u1', 'ferrum', 'u1', '[{\"host\":\"127.0.0.1\",\"port\":8080}]', 'round_robin', ?, ?)",
    )
    .bind(&boundary_ts)
    .bind(&boundary_ts)
    .fetch_all(&pool)
    .await
    .unwrap();

    // Proxy (requires an upstream FK or NULL upstream_id)
    sqlx::query(
        "INSERT INTO proxies (id, namespace, name, hosts, listen_path, backend_scheme, backend_host, backend_port, created_at, updated_at) \
         VALUES ('p1', 'ferrum', 'p1', '[]', '/test', 'https', '127.0.0.1', 8080, ?, ?)",
    )
    .bind(&boundary_ts)
    .bind(&boundary_ts)
    .fetch_all(&pool)
    .await
    .unwrap();

    // Consumer
    sqlx::query(
        "INSERT INTO consumers (id, namespace, username, credentials, created_at, updated_at) \
         VALUES ('c1', 'ferrum', 'testuser', '{}', ?, ?)",
    )
    .bind(&boundary_ts)
    .bind(&boundary_ts)
    .fetch_all(&pool)
    .await
    .unwrap();

    // Plugin config
    sqlx::query(
        "INSERT INTO plugin_configs (id, namespace, plugin_name, config, enabled, created_at, updated_at) \
         VALUES ('pc1', 'ferrum', 'rate_limiting', '{\"limits\":[{\"scope\":\"default\",\"requests_per_minute\":100}]}', 1, ?, ?)",
    )
    .bind(&boundary_ts)
    .bind(&boundary_ts)
    .fetch_all(&pool)
    .await
    .unwrap();

    let empty: HashSet<String> = HashSet::new();

    let result = store
        .load_incremental_config("ferrum", since, &empty, &empty, &empty, &empty)
        .await
        .expect("incremental poll must succeed");

    assert_eq!(
        result.added_or_modified_upstreams.len(),
        1,
        "upstream at boundary must be included"
    );
    assert_eq!(
        result.added_or_modified_proxies.len(),
        1,
        "proxy at boundary must be included"
    );
    assert_eq!(
        result.added_or_modified_consumers.len(),
        1,
        "consumer at boundary must be included"
    );
    assert_eq!(
        result.added_or_modified_plugin_configs.len(),
        1,
        "plugin_config at boundary must be included"
    );
}
