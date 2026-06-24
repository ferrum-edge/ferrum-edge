//! Regression coverage for SQL full runtime config loads.
//!
//! Full loads must read every runtime table from one transaction-scoped view
//! and page by stable IDs rather than mutable offsets.

use ferrum_edge::config::db_loader::{DatabaseBackend, DatabaseStore, DbPoolConfig};
use tempfile::TempDir;

async fn sqlite_store() -> (DatabaseStore, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("full_load_snapshot_test.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store creation must succeed");
    (store, temp_dir)
}

async fn seed_runtime_row_set(store: &DatabaseStore, idx: usize) {
    let ts = chrono::Utc::now().to_rfc3339();
    let pool = store.pool();
    let suffix = format!("{idx:02}");

    sqlx::query(
        "INSERT INTO upstreams (id, namespace, name, targets, algorithm, created_at, updated_at) \
         VALUES (?, 'ferrum', ?, ?, 'round_robin', ?, ?)",
    )
    .bind(format!("u-{suffix}"))
    .bind(format!("upstream-{suffix}"))
    .bind(format!(r#"[{{"host":"127.0.0.1","port":{}}}]"#, 8100 + idx))
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("upstream insert must succeed");

    sqlx::query(
        "INSERT INTO proxies \
         (id, namespace, name, hosts, listen_path, backend_scheme, backend_host, backend_port, upstream_id, created_at, updated_at) \
         VALUES (?, 'ferrum', ?, '[]', ?, 'http', '127.0.0.1', ?, ?, ?, ?)",
    )
    .bind(format!("p-{suffix}"))
    .bind(format!("proxy-{suffix}"))
    .bind(format!("/p-{suffix}"))
    .bind(8100 + idx as i64)
    .bind(format!("u-{suffix}"))
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("proxy insert must succeed");

    sqlx::query(
        "INSERT INTO consumers (id, namespace, username, credentials, created_at, updated_at) \
         VALUES (?, 'ferrum', ?, '{}', ?, ?)",
    )
    .bind(format!("c-{suffix}"))
    .bind(format!("consumer-{suffix}"))
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("consumer insert must succeed");

    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, enabled, created_at, updated_at) \
         VALUES (?, 'ferrum', 'key_auth', ?, 1, ?, ?)",
    )
    .bind(format!("pc-{suffix}"))
    .bind(r#"{"key_location":"header:X-API-Key"}"#)
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("plugin config insert must succeed");
}

#[tokio::test(flavor = "multi_thread")]
async fn full_load_keyset_pagination_returns_all_runtime_rows_at_page_boundaries() {
    let (mut store, _temp_dir) = sqlite_store().await;
    store.set_full_load_page_size(2);

    for idx in 0..4 {
        seed_runtime_row_set(&store, idx).await;
    }

    let config = store
        .load_full_config("ferrum")
        .await
        .expect("full load must succeed");

    assert_eq!(config.proxies.len(), 4);
    assert_eq!(config.consumers.len(), 4);
    assert_eq!(config.plugin_configs.len(), 4);
    assert_eq!(config.upstreams.len(), 4);
    assert_eq!(config.proxies[0].id, "p-00");
    assert_eq!(config.proxies[3].id, "p-03");
}

#[tokio::test(flavor = "multi_thread")]
async fn full_load_keyset_pagination_handles_final_partial_page() {
    let (mut store, _temp_dir) = sqlite_store().await;
    store.set_full_load_page_size(2);

    for idx in 0..5 {
        seed_runtime_row_set(&store, idx).await;
    }

    let config = store
        .load_full_config("ferrum")
        .await
        .expect("full load must succeed");

    assert_eq!(config.proxies.len(), 5);
    assert_eq!(config.consumers.len(), 5);
    assert_eq!(config.plugin_configs.len(), 5);
    assert_eq!(config.upstreams.len(), 5);
    assert_eq!(config.upstreams[4].id, "u-04");
}

#[tokio::test(flavor = "multi_thread")]
async fn full_load_late_query_failure_rejects_candidate() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_runtime_row_set(&store, 0).await;

    let mut conn = store
        .pool()
        .acquire()
        .await
        .expect("SQLite connection acquisition must succeed");
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .expect("disabling SQLite foreign key checks must succeed");
    sqlx::query("DROP TABLE upstreams")
        .execute(&mut *conn)
        .await
        .expect("dropping upstreams table must succeed");
    drop(conn);

    let error = match store.load_full_config("ferrum").await {
        Ok(_) => panic!("late table failure must reject the full-load candidate"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("upstreams"),
        "error should identify the failed late table query: {error}"
    );
}
