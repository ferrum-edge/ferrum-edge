//! Regression tests for fail-closed SQL row decoding during config mutations.
//!
//! Destructive admin mutations must abort and roll back when a selected row
//! required for follow-on invalidation/cleanup cannot be decoded. Silently
//! skipping malformed rows would commit a partial mutation (issues #3209 and
//! #3221). Coverage uses SQLite type drift (`X'FF'` blobs) against the shared
//! `AnyRow`/`try_get::<String>` path used by PostgreSQL, MySQL, and SQLite.

use chrono::Utc;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use sqlx::Row;
use tempfile::TempDir;

async fn sqlite_store() -> (DatabaseStore, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("mutation_decode_fail_closed.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store creation must succeed");
    (store, temp_dir)
}

async fn insert_proxy(store: &DatabaseStore, id: &str, updated_at: &str) {
    sqlx::query(
        "INSERT INTO proxies \
         (id, namespace, name, hosts, listen_path, backend_scheme, backend_host, backend_port, created_at, updated_at) \
         VALUES (?, 'ferrum', ?, '[\"example.com\"]', '/', 'http', '127.0.0.1', 8080, ?, ?)",
    )
    .bind(id)
    .bind(format!("proxy-{id}"))
    .bind(updated_at)
    .bind(updated_at)
    .execute(&store.pool())
    .await
    .expect("proxy insert must succeed");
}

async fn insert_plugin(
    store: &DatabaseStore,
    id: &str,
    scope: &str,
    proxy_id: Option<&str>,
    config: &str,
    ts: &str,
) {
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'ferrum', 'key_auth', ?, ?, ?, 1, ?, ?)",
    )
    .bind(id)
    .bind(config)
    .bind(scope)
    .bind(proxy_id)
    .bind(ts)
    .bind(ts)
    .execute(&store.pool())
    .await
    .expect("plugin insert must succeed");
}

async fn insert_association(store: &DatabaseStore, proxy_id: &str, plugin_config_id: &str) {
    sqlx::query(
        "INSERT INTO proxy_plugins (namespace, proxy_id, plugin_config_id) VALUES ('ferrum', ?, ?)",
    )
    .bind(proxy_id)
    .bind(plugin_config_id)
    .execute(&store.pool())
    .await
    .expect("association insert must succeed");
}

async fn seed_change(
    store: &DatabaseStore,
    resource_type: &str,
    resource_id: &str,
    operation: &str,
    ts: &str,
) {
    sqlx::query(
        "INSERT INTO config_changes \
         (namespace, resource_type, resource_id, operation, created_at) \
         VALUES ('ferrum', ?, ?, ?, ?)",
    )
    .bind(resource_type)
    .bind(resource_id)
    .bind(operation)
    .bind(ts)
    .execute(&store.pool())
    .await
    .expect("config_changes seed must succeed");
}

async fn proxy_updated_at(store: &DatabaseStore, id: &str) -> String {
    sqlx::query_scalar("SELECT updated_at FROM proxies WHERE id = ? AND namespace = 'ferrum'")
        .bind(id)
        .fetch_one(&store.pool())
        .await
        .expect("proxy updated_at must be readable")
}

async fn count_plugins(store: &DatabaseStore, id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM plugin_configs WHERE id = ? AND namespace = 'ferrum'")
        .bind(id)
        .fetch_one(&store.pool())
        .await
        .expect("plugin count must succeed")
}

async fn count_associations(store: &DatabaseStore, plugin_config_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM proxy_plugins WHERE namespace = 'ferrum' AND plugin_config_id = ?",
    )
    .bind(plugin_config_id)
    .fetch_one(&store.pool())
    .await
    .expect("association count must succeed")
}

async fn count_proxies(store: &DatabaseStore, id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM proxies WHERE id = ? AND namespace = 'ferrum'")
        .bind(id)
        .fetch_one(&store.pool())
        .await
        .expect("proxy count must succeed")
}

async fn count_blob_scoped_plugins(store: &DatabaseStore) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM plugin_configs \
         WHERE namespace = 'ferrum' AND scope = 'proxy_group' AND typeof(id) = 'blob'",
    )
    .fetch_one(&store.pool())
    .await
    .expect("blob plugin count must succeed")
}

async fn change_log_snapshot(store: &DatabaseStore) -> Vec<(i64, String, String, String)> {
    let rows = sqlx::query(
        "SELECT sequence, resource_type, resource_id, operation \
         FROM config_changes WHERE namespace = 'ferrum' ORDER BY sequence",
    )
    .fetch_all(&store.pool())
    .await
    .expect("config_changes snapshot must succeed");
    rows.into_iter()
        .map(|row| {
            (
                row.get::<i64, _>("sequence"),
                row.get::<String, _>("resource_type"),
                row.get::<String, _>("resource_id"),
                row.get::<String, _>("operation"),
            )
        })
        .collect()
}

fn assert_safe_decode_error(message: &str, operation: &str, column: &str) {
    assert!(
        message.contains(&format!("operation={operation}")),
        "error should include operation context, got: {message}"
    );
    assert!(
        message.contains(&format!("column={column}")),
        "error should identify the failing column, got: {message}"
    );
    assert!(
        !message.contains("X-API-Key") && !message.contains("X-Orphan-Key"),
        "decode errors must not expose plugin credential material: {message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_plugin_config_rolls_back_when_association_proxy_id_fails_to_decode() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    insert_proxy(&store, "proxy-1", &ts).await;
    insert_plugin(
        &store,
        "plugin-1",
        "proxy",
        Some("proxy-1"),
        r#"{"key_location":"header:X-API-Key"}"#,
        &ts,
    )
    .await;
    insert_association(&store, "proxy-1", "plugin-1").await;
    seed_change(&store, "plugin_config", "plugin-1", "upsert", &ts).await;
    seed_change(&store, "proxy", "proxy-1", "upsert", &ts).await;

    let updated_before = proxy_updated_at(&store, "proxy-1").await;
    let changes_before = change_log_snapshot(&store).await;
    assert_eq!(count_plugins(&store, "plugin-1").await, 1);
    assert_eq!(count_associations(&store, "plugin-1").await, 1);

    let mut conn = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE proxy_plugins SET proxy_id = X'FF' \
         WHERE namespace = 'ferrum' AND plugin_config_id = ?",
    )
    .bind("plugin-1")
    .execute(&mut *conn)
    .await
    .expect("injecting undecodable proxy_id must succeed");
    drop(conn);

    let err = store
        .delete_plugin_config("ferrum", "plugin-1")
        .await
        .expect_err("malformed association proxy_id must abort plugin deletion");
    let message = err.to_string();
    // `delete_plugin_config` reads the junction twice inside its transaction:
    // first the mTLS DNS-identity baseline (which, since `proxy_plugins` is
    // keyed on `(namespace, proxy_id, plugin_config_id)`, reads the namespace's
    // rows directly rather than joining `proxies`), then its own invalidation
    // read. Whichever decodes the poisoned row first fails the whole delete
    // closed with the same safe context.
    assert!(
        message.contains("operation=delete_plugin_config")
            || message.contains("operation=mtls_dns_repair_delete_baseline"),
        "error should include the delete path's operation context, got: {message}"
    );
    assert_safe_decode_error(
        &message,
        if message.contains("operation=delete_plugin_config") {
            "delete_plugin_config"
        } else {
            "mtls_dns_repair_delete_baseline"
        },
        "proxy_id",
    );
    assert!(
        message.contains("resource=proxy_plugins"),
        "error should identify proxy_plugins, got: {message}"
    );

    assert_eq!(
        count_plugins(&store, "plugin-1").await,
        1,
        "plugin_configs row must remain after rollback"
    );
    assert_eq!(
        count_associations(&store, "plugin-1").await,
        1,
        "proxy_plugins junction row must remain after rollback"
    );
    assert_eq!(
        proxy_updated_at(&store, "proxy-1").await,
        updated_before,
        "proxies.updated_at must be unchanged when invalidation decode fails"
    );
    assert_eq!(
        change_log_snapshot(&store).await,
        changes_before,
        "config_changes must be unchanged when plugin deletion rolls back"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_proxy_rolls_back_when_orphaned_proxy_group_metadata_fails_to_decode() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    insert_proxy(&store, "proxy-1", &ts).await;
    seed_change(&store, "proxy", "proxy-1", "upsert", &ts).await;

    // Pre-existing orphaned proxy_group plugin whose id cannot decode as String.
    // Parent proxy deletion invokes cleanup and must fail closed rather than
    // silently retaining the orphan while reporting success (issue #3221).
    let mut conn = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (X'FF', 'ferrum', 'key_auth', ?, 'proxy_group', NULL, 1, ?, ?)",
    )
    .bind(r#"{"key_location":"header:X-Orphan-Key"}"#)
    .bind(&ts)
    .bind(&ts)
    .execute(&mut *conn)
    .await
    .expect("injecting undecodable orphan plugin id must succeed");
    drop(conn);

    let changes_before = change_log_snapshot(&store).await;
    assert_eq!(count_blob_scoped_plugins(&store).await, 1);
    assert_eq!(count_proxies(&store, "proxy-1").await, 1);

    let err = store
        .delete_proxy("ferrum", "proxy-1")
        .await
        .expect_err("malformed orphan metadata must abort the parent proxy deletion");
    let message = err.to_string();
    assert_safe_decode_error(&message, "cleanup_orphaned_proxy_group_plugins", "id");
    assert!(
        message.contains("resource=plugin_configs"),
        "error should identify plugin_configs, got: {message}"
    );

    assert_eq!(
        count_proxies(&store, "proxy-1").await,
        1,
        "parent proxy deletion must roll back when orphan decode fails"
    );
    assert_eq!(
        count_blob_scoped_plugins(&store).await,
        1,
        "undecodable orphan must remain untouched after rollback"
    );
    assert_eq!(
        change_log_snapshot(&store).await,
        changes_before,
        "config_changes must be unchanged when orphan cleanup aborts the parent mutation"
    );
}

// ---------------------------------------------------------------------------
// Issue #4526 — plugin construction is the real schema gate, and the two
// consumers of a stored `plugin_configs` row must take OPPOSITE branches:
//
// * A serving-mode (`Runtime`) full load QUARANTINES an unconstructible
//   OptionalFailOpen row so `database` mode still reaches its admin listener
//   and the row stays deletable in-band. FailClosed and KeepLastKnownGood rows
//   continue to reject publication.
// * A `ControlPlane` load REJECTS the snapshot, so the CP can never broadcast a
//   row that would freeze every DP on last-known-good with no ConfigSync
//   acknowledgement to show it.
// ---------------------------------------------------------------------------

async fn insert_named_plugin(
    store: &DatabaseStore,
    id: &str,
    plugin_name: &str,
    config: &str,
    ts: &str,
) {
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'ferrum', ?, ?, 'global', NULL, 1, ?, ?)",
    )
    .bind(id)
    .bind(plugin_name)
    .bind(config)
    .bind(ts)
    .bind(ts)
    .execute(&store.pool())
    .await
    .expect("plugin insert must succeed");
}

#[tokio::test(flavor = "multi_thread")]
async fn serving_load_quarantines_unconstructible_plugin_row_while_cp_load_rejects_it() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    // Admin write-time validation rejects new rows like this; this direct
    // insert stands in for a row written before the constructor was tightened.
    insert_named_plugin(
        &store,
        "debugger-typo",
        "transaction_debugger",
        r#"{"filtr":{}}"#,
        &ts,
    )
    .await;
    insert_named_plugin(&store, "stdout-ok", "stdout_logging", r#"{}"#, &ts).await;

    // Serving mode: the load SUCCEEDS with the bad row quarantined, so startup
    // continues to the admin listener instead of exiting.
    let runtime_config = store
        .load_full_config("ferrum")
        .await
        .expect("a serving-mode full load must not fail on an unconstructible plugin row");
    let surviving: Vec<&str> = runtime_config
        .plugin_configs
        .iter()
        .map(|pc| pc.id.as_str())
        .collect();
    assert_eq!(
        surviving,
        vec!["stdout-ok"],
        "only the unconstructible row is dropped from the served snapshot"
    );
    assert_eq!(
        runtime_config.quarantined_plugin_configs.len(),
        1,
        "the quarantine must be reported so database mode raises config_rejected"
    );
    assert!(
        runtime_config.quarantined_plugin_configs[0].contains("debugger-typo")
            && runtime_config.quarantined_plugin_configs[0].contains("transaction_debugger"),
        "the quarantine message names the plugin and its config id: {:?}",
        runtime_config.quarantined_plugin_configs
    );

    // Control plane: an unconstructible row whose plugin is NOT OptionalFailOpen
    // is refused outright, so it is never broadcast to the data-plane fleet.
    // (The `transaction_debugger` typo above is exempt in both modes — a serving mode
    // quarantines it and the CP omits it with a warning — so the CP half of
    // this contract needs a FailClosed row: the exact reproduction from issue
    // #4526, a closed config object with a typo'd key.)
    insert_named_plugin(
        &store,
        "rsl-typo",
        "request_size_limiting",
        r#"{"max_bytes":1024,"max_bytez":1}"#,
        &ts,
    )
    .await;
    let cp_error = store
        .load_full_config_for_purpose(
            "ferrum",
            ferrum_edge::config::db_backend::FullConfigLoadPurpose::ControlPlane,
        )
        .await
        .expect_err("CP admission must refuse an unconstructible plugin config");
    // The typed marker keeps the CP poll loop's admin API writable for in-band
    // repair; its Display carries the rejecting-error count, and the individual
    // messages (which name the plugin and its config id) are logged.
    let rendered = format!("{cp_error:#}");
    assert!(
        rendered.contains("configuration validation failed")
            && rendered.contains("1 rejecting error(s)"),
        "CP admission must return the typed validation rejection for the unconstructible \
         FailClosed plugin row (the OptionalFailOpen typo is exempt): {rendered}"
    );

    // And the serving-mode load now fails closed too: a FailClosed row is never
    // quarantined, so the same store no longer starts a `database` gateway.
    let runtime_error = store
        .load_full_config("ferrum")
        .await
        .expect_err("a serving-mode full load must refuse an unconstructible FailClosed plugin");
    let rendered = format!("{runtime_error:#}");
    assert!(
        rendered.contains("configuration validation failed")
            && rendered.contains("1 rejecting error(s)"),
        "runtime admission must fail closed on a FailClosed row instead of quarantining it: {rendered}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn serving_load_does_not_quarantine_retired_fail_closed_auth_plugin() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    insert_named_plugin(&store, "retired-auth", "oauth2_auth", r#"{}"#, &ts).await;

    let error = store
        .load_full_config("ferrum")
        .await
        .expect_err("a retired FailClosed auth plugin must reject runtime publication");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("configuration validation failed")
            && rendered.contains("1 rejecting error(s)"),
        "runtime admission must fail closed instead of serving without authentication: {rendered}"
    );
}

/// Issue #4624 — the reload chokepoint, in-process.
///
/// A serving-mode full load never produces a candidate with an unconstructible
/// `FailClosed` row stripped out (the test above proves the load itself fails
/// closed). This pins the second half of the contract: even if such a candidate
/// reached [`ProxyState::update_config`], the apply is REJECTED and the entire
/// prior runtime generation is preserved — `update_config` is not a place where
/// a security plugin can quietly disappear.
///
/// The `OptionalFailOpen` half of the same fixture pins the contrast: that row
/// is omitted, the apply succeeds, and the fail-closed plugin is untouched.
#[tokio::test(flavor = "multi_thread")]
async fn full_reload_candidate_with_unconstructible_fail_closed_plugin_keeps_prior_generation() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    insert_proxy(&store, "proxy-1", &ts).await;
    insert_plugin(
        &store,
        "plugin-1",
        "proxy",
        Some("proxy-1"),
        r#"{"key_location":"header:X-API-Key"}"#,
        &ts,
    )
    .await;
    insert_association(&store, "proxy-1", "plugin-1").await;
    // `transaction_debugger` is `OptionalFailOpen`; `stdout_logging` is
    // `KeepLastKnownGood` and would reject the optional candidate below.
    insert_named_plugin(&store, "optional-ok", "transaction_debugger", r#"{}"#, &ts).await;

    let good = store
        .load_full_config("ferrum")
        .await
        .expect("the healthy generation must load");
    assert!(
        good.quarantined_plugin_configs.is_empty(),
        "the healthy generation quarantines nothing"
    );

    let (proxy_state, _health_check_handles) = ferrum_edge::proxy::ProxyState::new(
        good.clone(),
        ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default()),
        ferrum_edge::config::env_config::EnvConfig::default(),
        None,
        None,
    )
    .expect("proxy state from the healthy generation");

    // A real authoritative full load carries a newer `updated_at` on the row
    // that changed; without it the apply short-circuits as `Unchanged` before
    // the plugin cache is ever rebuilt, which is not the path under test.
    let later = Utc::now() + chrono::Duration::seconds(5);
    let mut fail_closed_candidate = good.clone();
    for plugin_config in &mut fail_closed_candidate.plugin_configs {
        if plugin_config.id == "plugin-1" {
            plugin_config.config =
                serde_json::json!({"key_location": "header:X-API-Key", "typo": true});
            plugin_config.updated_at = later;
        }
    }
    match proxy_state.update_config(fail_closed_candidate) {
        ferrum_edge::proxy::ConfigApplyOutcome::Rejected { errors } => assert!(
            errors.iter().any(|error| error.contains("key_auth")),
            "the rejection must name the unconstructible plugin: {errors:?}"
        ),
        other => panic!("an unconstructible key_auth row must not be applied, got: {other:?}"),
    }
    let live = proxy_state.config.load_full();
    assert!(
        live.plugin_configs
            .iter()
            .any(|plugin_config| plugin_config.id == "plugin-1"),
        "the fail-closed plugin must still be in the serving generation"
    );
    assert_eq!(
        live.plugin_configs.len(),
        good.plugin_configs.len(),
        "the ENTIRE prior generation is preserved, not a partially applied candidate"
    );

    // Contrast: an unconstructible OptionalFailOpen row is omitted, the apply
    // succeeds, and the fail-closed plugin is untouched.
    let mut optional_candidate = good.clone();
    for plugin_config in &mut optional_candidate.plugin_configs {
        if plugin_config.id == "optional-ok" {
            plugin_config.config = serde_json::json!({"filtr": {}});
            plugin_config.updated_at = later;
        }
    }
    assert!(
        matches!(
            proxy_state.update_config(optional_candidate),
            ferrum_edge::proxy::ConfigApplyOutcome::Applied
        ),
        "an unconstructible optional plugin must not reject the generation"
    );
    let live = proxy_state.config.load_full();
    assert!(
        live.plugin_configs
            .iter()
            .any(|plugin_config| plugin_config.id == "plugin-1"),
        "quarantining an optional plugin must never drop the fail-closed one"
    );
}
