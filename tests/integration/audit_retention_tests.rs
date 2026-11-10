//! Integration tests for namespace-scoped audit-event retention (#2996).
//!
//! Exercises the SQLite SQL path because `DatabaseStore` is shared by all SQL
//! backends behind dialect-specific DELETE rendering. Mongo parity for the
//! shared contract is locked in `tests/unit/config/audit_retention_tests.rs`.

use chrono::{Duration, Utc};
use ferrum_edge::admin::audit::{AuditEvent, AuditListFilter, AuditRetentionPolicy};
use ferrum_edge::config::db_backend::DatabaseBackend;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use serde_json::json;
use tempfile::TempDir;

fn disabled_retention() -> AuditRetentionPolicy {
    AuditRetentionPolicy {
        retention_days: None,
        max_rows_per_namespace: None,
    }
}

async fn sqlite_store_with_retention(policy: AuditRetentionPolicy) -> (DatabaseStore, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("audit_retention_test.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let mut store =
        DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
            .await
            .expect("SQLite store creation must succeed");
    store.set_audit_retention_policy(policy);
    (store, temp_dir)
}

fn event_at(namespace: &str, id: &str, days_ago: i64, id_suffix: &str) -> AuditEvent {
    AuditEvent {
        id: format!("{id}-{id_suffix}"),
        ts: Utc::now() - Duration::days(days_ago),
        actor: "tester".to_string(),
        action: "update".to_string(),
        resource_type: "proxy".to_string(),
        resource_id: id.to_string(),
        namespace: namespace.to_string(),
        namespace_at_event: namespace.to_string(),
        source_address: String::new(),
        request_id: String::new(),
        outcome: String::new(),
        diff: json!({ "after": { "id": id } }),
    }
}

fn event_ordered(namespace: &str, id: &str, minutes_ago: i64) -> AuditEvent {
    AuditEvent {
        id: id.to_string(),
        ts: Utc::now() - Duration::minutes(minutes_ago),
        actor: "tester".to_string(),
        action: "update".to_string(),
        resource_type: "proxy".to_string(),
        resource_id: id.to_string(),
        namespace: namespace.to_string(),
        namespace_at_event: namespace.to_string(),
        source_address: String::new(),
        request_id: String::new(),
        outcome: String::new(),
        diff: json!({ "after": { "id": id } }),
    }
}

#[tokio::test]
async fn age_prune_is_namespace_isolated_and_respects_cutoff() {
    let (mut store, _tmp) = sqlite_store_with_retention(AuditRetentionPolicy {
        retention_days: Some(7),
        max_rows_per_namespace: None,
    })
    .await;

    // Insert without piggyback prune so we can assert an explicit prune call.
    // Disable retention, insert, then re-enable and prune.
    store.set_audit_retention_policy(disabled_retention());
    store
        .insert_audit_event(&event_at("ns-a", "old-a", 10, "1"))
        .await
        .unwrap();
    store
        .insert_audit_event(&event_at("ns-a", "new-a", 1, "1"))
        .await
        .unwrap();
    store
        .insert_audit_event(&event_at("ns-b", "old-b", 10, "1"))
        .await
        .unwrap();
    store
        .insert_audit_event(&event_at("ns-b", "new-b", 1, "1"))
        .await
        .unwrap();

    store.set_audit_retention_policy(AuditRetentionPolicy {
        retention_days: Some(7),
        max_rows_per_namespace: None,
    });
    let deleted = store.prune_audit_events("ns-a").await.unwrap();
    assert!(
        deleted >= 1,
        "ns-a should prune at least the 10-day-old row"
    );

    let ns_a = store
        .list_audit_events(
            "ns-a",
            &AuditListFilter {
                limit: 50,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(ns_a.total, 1);
    assert_eq!(ns_a.items[0].resource_id, "new-a");

    let ns_b = store
        .list_audit_events(
            "ns-b",
            &AuditListFilter {
                limit: 50,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(ns_b.total, 2, "pruning ns-a must not delete ns-b rows");
}

#[tokio::test]
async fn max_rows_cap_keeps_newest_by_ts_id_and_preserves_other_namespace() {
    let (mut store, _tmp) = sqlite_store_with_retention(disabled_retention()).await;

    for minutes in [5, 4, 3, 2, 1] {
        store
            .insert_audit_event(&event_ordered("cap-a", &format!("a-{minutes}"), minutes))
            .await
            .unwrap();
        store
            .insert_audit_event(&event_ordered("cap-b", &format!("b-{minutes}"), minutes))
            .await
            .unwrap();
    }

    store.set_audit_retention_policy(AuditRetentionPolicy {
        retention_days: None,
        max_rows_per_namespace: Some(3),
    });
    let deleted = store.prune_audit_events("cap-a").await.unwrap();
    assert_eq!(deleted, 2);

    let ns_a = store
        .list_audit_events(
            "cap-a",
            &AuditListFilter {
                limit: 50,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(ns_a.total, 3);
    let ids: Vec<_> = ns_a.items.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids, vec!["a-1", "a-2", "a-3"]);

    let ns_b = store
        .list_audit_events(
            "cap-b",
            &AuditListFilter {
                limit: 50,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(ns_b.total, 5, "cap prune must stay namespace-scoped");
}

#[tokio::test]
async fn pagination_remains_correct_across_prune_boundary() {
    let (mut store, _tmp) = sqlite_store_with_retention(disabled_retention()).await;

    for minutes in (1..=6).rev() {
        store
            .insert_audit_event(&event_ordered("page-ns", &format!("p-{minutes}"), minutes))
            .await
            .unwrap();
    }

    store.set_audit_retention_policy(AuditRetentionPolicy {
        retention_days: None,
        max_rows_per_namespace: Some(4),
    });
    store.prune_audit_events("page-ns").await.unwrap();

    let page1 = store
        .list_audit_events(
            "page-ns",
            &AuditListFilter {
                limit: 2,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let page2 = store
        .list_audit_events(
            "page-ns",
            &AuditListFilter {
                limit: 2,
                offset: 2,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(page1.total, 4);
    assert_eq!(page2.total, 4);
    assert_eq!(page1.items.len(), 2);
    assert_eq!(page2.items.len(), 2);
    assert_eq!(page1.items[0].id, "p-1");
    assert_eq!(page1.items[1].id, "p-2");
    assert_eq!(page2.items[0].id, "p-3");
    assert_eq!(page2.items[1].id, "p-4");

    let all_ids: Vec<_> = page1
        .items
        .iter()
        .chain(page2.items.iter())
        .map(|e| e.id.as_str())
        .collect();
    assert_eq!(all_ids, vec!["p-1", "p-2", "p-3", "p-4"]);
}

#[tokio::test]
async fn insert_piggyback_applies_soft_max_rows_without_failing_insert() {
    let max_rows = 2u64;
    let interval = ferrum_edge::admin::audit::audit_retention_max_rows_check_interval(max_rows);
    let (store, _tmp) = sqlite_store_with_retention(AuditRetentionPolicy {
        retention_days: None,
        max_rows_per_namespace: Some(max_rows),
    })
    .await;

    // Soft cap: after a verified under-cap check, up to `interval` further
    // inserts may land before the next boundary scan. Insert enough that the
    // piggyback path must scan while over the configured target.
    let total_inserts = 1 + interval;
    for minutes in (1..=total_inserts).rev() {
        store
            .insert_audit_event(&event_ordered(
                "piggy",
                &format!("g-{minutes}"),
                minutes as i64,
            ))
            .await
            .unwrap();
    }

    let listed = store
        .list_audit_events(
            "piggy",
            &AuditListFilter {
                limit: 50,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(listed.total, max_rows as i64);
    assert_eq!(listed.items[0].id, "g-1");
    assert_eq!(listed.items[1].id, "g-2");
}

#[tokio::test]
async fn first_insert_prunes_backlog_that_predates_retention_gate() {
    let max_rows = 2u64;
    let (mut store, _tmp) = sqlite_store_with_retention(disabled_retention()).await;

    for minutes in (1..=4).rev() {
        store
            .insert_audit_event(&event_ordered(
                "existing-backlog",
                &format!("old-{minutes}"),
                minutes,
            ))
            .await
            .unwrap();
    }

    store.set_audit_retention_policy(AuditRetentionPolicy {
        retention_days: None,
        max_rows_per_namespace: Some(max_rows),
    });
    store
        .insert_audit_event(&event_ordered("existing-backlog", "new", 0))
        .await
        .unwrap();

    let listed = store
        .list_audit_events(
            "existing-backlog",
            &AuditListFilter {
                limit: 50,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(listed.total, max_rows as i64);
    assert_eq!(listed.items[0].id, "new");
    assert_eq!(listed.items[1].id, "old-1");
}

async fn audit_total(store: &dyn DatabaseBackend, namespace: &str) -> i64 {
    store
        .list_audit_events(
            namespace,
            &AuditListFilter {
                limit: 50,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .total
}

/// Seed rows with retention disabled so no insert-path prune runs: the
/// namespaces are idle from the store's point of view.
async fn seed_idle_namespaces(store: &DatabaseStore) {
    for event in [
        event_at("idle-a", "old-a", 10, "1"),
        event_at("idle-a", "new-a", 1, "1"),
        event_at("idle-b", "old-b", 10, "1"),
        event_at("idle-b", "older-b", 20, "1"),
        event_at("idle-c", "new-c", 1, "1"),
        event_at("idle-c", "new-c", 2, "2"),
        event_at("idle-c", "new-c", 3, "3"),
    ] {
        store.insert_audit_event(&event).await.unwrap();
    }
}

/// `FERRUM_AUDIT_RETENTION_DAYS` promises age pruning per namespace, but
/// insert-path pruning only reaches a namespace that receives a new event. The
/// sweep must age out every namespace holding rows, and only by age: the row
/// cap is left to inserts because an idle namespace cannot grow.
#[tokio::test]
async fn expired_sweep_ages_out_every_namespace_without_inserts() {
    let (mut store, _tmp) = sqlite_store_with_retention(disabled_retention()).await;
    seed_idle_namespaces(&store).await;

    assert_eq!(
        store.prune_expired_audit_events().await.unwrap(),
        0,
        "the sweep is a no-op without age retention"
    );

    store.set_audit_retention_policy(AuditRetentionPolicy {
        retention_days: Some(7),
        max_rows_per_namespace: Some(1),
    });
    assert_eq!(store.prune_expired_audit_events().await.unwrap(), 3);
    assert_eq!(audit_total(&store, "idle-a").await, 1);
    assert_eq!(audit_total(&store, "idle-b").await, 0);
    assert_eq!(
        audit_total(&store, "idle-c").await,
        3,
        "the sweep must not apply the row cap"
    );
    assert_eq!(
        store.prune_expired_audit_events().await.unwrap(),
        0,
        "a second sweep finds nothing left to age out"
    );
}

/// The background task runs the sweep on its own, with no audit insert, and
/// exits promptly on shutdown.
#[tokio::test]
async fn retention_sweep_task_prunes_idle_namespaces_and_stops_on_shutdown() {
    use ferrum_edge::admin::audit::{spawn_retention_sweep, start_retention_sweep};
    use std::sync::Arc;

    let (mut store, _tmp) = sqlite_store_with_retention(disabled_retention()).await;
    seed_idle_namespaces(&store).await;
    store.set_audit_retention_policy(AuditRetentionPolicy {
        retention_days: Some(7),
        max_rows_per_namespace: None,
    });
    let db: Arc<dyn DatabaseBackend> = Arc::new(store);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    assert!(
        start_retention_sweep(None, Arc::clone(&db), shutdown_rx.clone()).is_none(),
        "no task without age retention"
    );

    // A zero interval still sleeps the 100 ms jitter floor between sweeps.
    let handle = spawn_retention_sweep(Arc::clone(&db), std::time::Duration::ZERO, shutdown_rx);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while audit_total(db.as_ref(), "idle-a").await != 1
            || audit_total(db.as_ref(), "idle-b").await != 0
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the sweep task must prune idle namespaces without any insert");
    assert_eq!(audit_total(db.as_ref(), "idle-c").await, 3);

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), handle)
        .await
        .expect("the sweep task must stop on shutdown")
        .expect("the sweep task must not panic");
}
