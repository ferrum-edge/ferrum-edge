//! Regression tests for SQL proxy/plugin association loading.
//!
//! Proxy/plugin associations carry security and policy plugins. SQL loaders
//! must fail closed when the junction-table query or row decoding fails, and
//! admin reads must not serialize incomplete association graphs.

use chrono::{Duration, Utc};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use std::collections::HashSet;
use tempfile::TempDir;

async fn sqlite_store() -> (DatabaseStore, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("proxy_plugin_assoc_test.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store creation must succeed");
    (store, temp_dir)
}

async fn seed_proxy_with_plugin(store: &DatabaseStore) {
    let pool = store.pool();
    let ts = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO proxies \
         (id, namespace, name, hosts, listen_path, backend_scheme, backend_host, backend_port, created_at, updated_at) \
         VALUES (?, 'ferrum', 'edge', '[\"example.com\"]', '/', 'http', '127.0.0.1', 8080, ?, ?)",
    )
    .bind("proxy-1")
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("proxy insert must succeed");

    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'ferrum', 'key_auth', ?, 'proxy', ?, 1, ?, ?)",
    )
    .bind("plugin-1")
    .bind(r#"{"key_location":"header:X-API-Key"}"#)
    .bind("proxy-1")
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("plugin insert must succeed");

    sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)")
        .bind("proxy-1")
        .bind("plugin-1")
        .execute(&pool)
        .await
        .expect("association insert must succeed");
}

async fn drop_proxy_plugins_table(store: &DatabaseStore) {
    sqlx::query("DROP TABLE proxy_plugins")
        .execute(&store.pool())
        .await
        .expect("drop proxy_plugins must succeed");
}

fn error_text<T>(result: Result<T, anyhow::Error>) -> String {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(err) => err.to_string(),
    }
}

fn assert_association_error_context(message: &str, operation: &str) {
    assert!(
        message.contains(&format!("operation={operation}")),
        "error should include operation context, got: {message}"
    );
    assert!(
        message.contains("resource=proxy_plugins"),
        "error should identify proxy_plugins, got: {message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn successful_association_loading_remains_unchanged() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let full = store
        .load_full_config("ferrum")
        .await
        .expect("full load must succeed");
    let proxy = full
        .proxies
        .iter()
        .find(|proxy| proxy.id == "proxy-1")
        .expect("proxy must be present");
    assert_eq!(proxy.plugins.len(), 1);
    assert_eq!(proxy.plugins[0].plugin_config_id, "plugin-1");

    let empty = HashSet::new();
    let incremental = store
        .load_incremental_config(
            "ferrum",
            Utc::now() - Duration::days(1),
            &empty,
            &empty,
            &empty,
            &empty,
        )
        .await
        .expect("incremental load must succeed");
    let incremental_proxy = incremental
        .added_or_modified_proxies
        .iter()
        .find(|proxy| proxy.id == "proxy-1")
        .expect("incremental proxy must be present");
    assert_eq!(incremental_proxy.plugins.len(), 1);
    assert_eq!(incremental_proxy.plugins[0].plugin_config_id, "plugin-1");

    let admin_proxy = store
        .get_proxy("proxy-1")
        .await
        .expect("admin get_proxy must succeed")
        .expect("proxy must exist");
    assert_eq!(admin_proxy.plugins.len(), 1);
    assert_eq!(admin_proxy.plugins[0].plugin_config_id, "plugin-1");

    let page = store
        .list_proxies_paginated("ferrum", 25, 0)
        .await
        .expect("admin list_proxies must succeed");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].plugins.len(), 1);
    assert_eq!(page.items[0].plugins[0].plugin_config_id, "plugin-1");
}

#[tokio::test(flavor = "multi_thread")]
async fn full_load_association_query_failure_rejects_candidate() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;
    drop_proxy_plugins_table(&store).await;

    let message = error_text(store.load_full_config("ferrum").await);
    assert_association_error_context(&message, "load_full_config");
    assert!(
        !message.contains("X-API-Key"),
        "association errors must not include plugin credential material: {message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn incremental_association_query_failure_rejects_delta() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let baseline = store
        .load_full_config("ferrum")
        .await
        .expect("baseline full load must succeed");
    let known_proxy_ids: HashSet<String> = baseline.proxies.iter().map(|p| p.id.clone()).collect();
    let known_consumer_ids: HashSet<String> =
        baseline.consumers.iter().map(|c| c.id.clone()).collect();
    let known_plugin_config_ids: HashSet<String> = baseline
        .plugin_configs
        .iter()
        .map(|pc| pc.id.clone())
        .collect();
    let known_upstream_ids: HashSet<String> =
        baseline.upstreams.iter().map(|u| u.id.clone()).collect();

    drop_proxy_plugins_table(&store).await;

    let message = error_text(
        store
            .load_incremental_config(
                "ferrum",
                Utc::now() - Duration::days(1),
                &known_proxy_ids,
                &known_consumer_ids,
                &known_plugin_config_ids,
                &known_upstream_ids,
            )
            .await,
    );
    assert_association_error_context(&message, "load_incremental_config");
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_association_row_rejects_candidate_instead_of_being_skipped() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let mut conn = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, X'FF')")
        .bind("proxy-1")
        .execute(&mut *conn)
        .await
        .unwrap();

    let message = error_text(store.load_full_config("ferrum").await);
    assert_association_error_context(&message, "load_full_config");
    assert!(
        message.contains("proxy_id=proxy-1") && message.contains("column=plugin_config_id"),
        "decode error should include safe row context, got: {message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_invalid_association_rejects_the_full_snapshot() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;
    store
        .load_full_config("ferrum")
        .await
        .expect("valid baseline must load before injecting invalid association");

    let ts = Utc::now().to_rfc3339();
    let pool = store.pool();
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'other', 'key_auth', ?, 'proxy', ?, 1, ?, ?)",
    )
    .bind("plugin-other")
    .bind(r#"{"key_location":"header:X-Secret-Key"}"#)
    .bind("proxy-1")
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("cross-namespace plugin insert must succeed");

    sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)")
        .bind("proxy-1")
        .bind("plugin-other")
        .execute(&pool)
        .await
        .expect("cross-namespace association insert must succeed");

    let message = error_text(store.load_full_config("ferrum").await);
    assert_association_error_context(&message, "load_full_config");
    assert!(
        message.contains("plugin-other"),
        "invalid association should identify the safe plugin id, got: {message}"
    );
    assert!(
        !message.contains("X-Secret-Key"),
        "invalid association error must not expose plugin config values: {message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_proxy_reads_fail_closed_on_association_query_failure() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;
    drop_proxy_plugins_table(&store).await;

    let get_message = error_text(store.get_proxy("proxy-1").await);
    assert_association_error_context(&get_message, "get_proxy");

    let list_message = error_text(store.list_proxies_paginated("ferrum", 25, 0).await);
    assert_association_error_context(&list_message, "list_proxies_paginated");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_proxy_reads_reject_incomplete_cross_namespace_associations() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let ts = Utc::now().to_rfc3339();
    let pool = store.pool();
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'other', 'key_auth', ?, 'proxy', ?, 1, ?, ?)",
    )
    .bind("plugin-other")
    .bind(r#"{"key_location":"header:X-Secret-Key"}"#)
    .bind("proxy-1")
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("cross-namespace plugin insert must succeed");
    sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)")
        .bind("proxy-1")
        .bind("plugin-other")
        .execute(&pool)
        .await
        .expect("cross-namespace association insert must succeed");

    let get_message = error_text(store.get_proxy("proxy-1").await);
    assert_association_error_context(&get_message, "get_proxy");
    assert!(get_message.contains("plugin-other"));
    assert!(!get_message.contains("X-Secret-Key"));

    let list_message = error_text(store.list_proxies_paginated("ferrum", 25, 0).await);
    assert_association_error_context(&list_message, "list_proxies_paginated");
    assert!(list_message.contains("plugin-other"));
    assert!(!list_message.contains("X-Secret-Key"));
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_proxy_reads_reject_global_plugin_associations() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let ts = Utc::now().to_rfc3339();
    let pool = store.pool();
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'ferrum', 'key_auth', ?, 'global', ?, 1, ?, ?)",
    )
    .bind("plugin-global")
    .bind(r#"{"key_location":"header:X-Global-Key"}"#)
    .bind(Option::<String>::None)
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("global plugin insert must succeed");
    sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)")
        .bind("proxy-1")
        .bind("plugin-global")
        .execute(&pool)
        .await
        .expect("global association insert must succeed");

    let get_message = error_text(store.get_proxy("proxy-1").await);
    assert_association_error_context(&get_message, "get_proxy");
    assert!(get_message.contains("plugin-global"));
    assert!(!get_message.contains("X-Global-Key"));

    let list_message = error_text(store.list_proxies_paginated("ferrum", 25, 0).await);
    assert_association_error_context(&list_message, "list_proxies_paginated");
    assert!(list_message.contains("plugin-global"));
    assert!(!list_message.contains("X-Global-Key"));
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_proxy_reads_reject_proxy_group_plugin_with_proxy_id() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let ts = Utc::now().to_rfc3339();
    let pool = store.pool();
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'ferrum', 'key_auth', ?, 'proxy_group', ?, 1, ?, ?)",
    )
    .bind("plugin-group-corrupt")
    .bind(r#"{"key_location":"header:X-Group-Key"}"#)
    .bind("proxy-1")
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("proxy-group plugin insert must succeed");
    sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)")
        .bind("proxy-1")
        .bind("plugin-group-corrupt")
        .execute(&pool)
        .await
        .expect("proxy-group association insert must succeed");

    let get_message = error_text(store.get_proxy("proxy-1").await);
    assert_association_error_context(&get_message, "get_proxy");
    assert!(get_message.contains("plugin-group-corrupt"));
    assert!(!get_message.contains("X-Group-Key"));

    let list_message = error_text(store.list_proxies_paginated("ferrum", 25, 0).await);
    assert_association_error_context(&list_message, "list_proxies_paginated");
    assert!(list_message.contains("plugin-group-corrupt"));
    assert!(!list_message.contains("X-Group-Key"));
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_write_precheck_can_repair_invalid_associations() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let ts = Utc::now().to_rfc3339();
    let pool = store.pool();
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'ferrum', 'key_auth', ?, 'global', ?, 1, ?, ?)",
    )
    .bind("plugin-global")
    .bind(r#"{"key_location":"header:X-Global-Key"}"#)
    .bind(Option::<String>::None)
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("global plugin insert must succeed");
    sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)")
        .bind("proxy-1")
        .bind("plugin-global")
        .execute(&pool)
        .await
        .expect("global association insert must succeed");

    let read_message = error_text(store.get_proxy("proxy-1").await);
    assert_association_error_context(&read_message, "get_proxy");
    assert!(read_message.contains("plugin-global"));

    let mut repair_proxy = store
        .get_proxy_for_write("proxy-1")
        .await
        .expect("write precheck get must succeed")
        .expect("proxy must exist");
    repair_proxy
        .plugins
        .retain(|assoc| assoc.plugin_config_id != "plugin-global");
    store
        .update_proxy(&repair_proxy)
        .await
        .expect("update should repair proxy_plugins rows");

    let repaired = store
        .get_proxy("proxy-1")
        .await
        .expect("repaired proxy read must succeed")
        .expect("proxy must still exist");
    assert_eq!(repaired.plugins.len(), 1);
    assert_eq!(repaired.plugins[0].plugin_config_id, "plugin-1");
}
