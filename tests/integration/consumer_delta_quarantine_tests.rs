//! Consumer changes ride the incremental delta unless load-time quarantine
//! could change their outcome (issue #6060).
//!
//! A full load quarantines colliding consumer identities and weak or duplicate
//! `hmac_auth` credentials, first-loaded consumer wins. A delta patched onto
//! that sanitized snapshot is only equivalent to a fresh full load when nothing
//! is quarantined, so loaders escalate consumer changes to a full reload while
//! anything is quarantined (or the state is unknown) and whenever a changed
//! consumer carries `hmac_auth`. The shared contract below runs on SQLite here
//! and on PostgreSQL, MySQL, and a MongoDB replica set in the live-store lane.

use ferrum_edge::config::db_backend::{
    BatchConfigWriteMode, DatabaseBackend, IncrementalResult, is_incremental_full_reload_required,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::types::Consumer;
use serde_json::{Value, json};
use std::future::Future;

const SHARED_SECRET: &str = "shared-hmac-secret-0123456789-abcdefghij";
const OTHER_SECRET: &str = "other-hmac-secret-0123456789-abcdefghijk";

fn consumer(namespace: &str, id: &str, credentials: Value) -> Consumer {
    serde_json::from_value(json!({
        "id": id,
        "username": format!("user-{id}"),
        "namespace": namespace,
        "credentials": credentials,
    }))
    .expect("consumer fixture")
}

fn keyauth(key: &str) -> Value {
    json!({"keyauth": [{"key": key}]})
}

fn hmac(secret: &str) -> Value {
    json!({"hmac_auth": [{"secret": secret}]})
}

async fn expect_escalation(db: &dyn DatabaseBackend, namespace: &str, after: u64, why: &str) {
    match db.load_incremental_config(namespace, after).await {
        Ok(_) => panic!("{why}: consumer change must escalate to a full reload"),
        Err(error) => assert!(
            is_incremental_full_reload_required(&error),
            "{why}: expected the consumer-change escalation, got {error}"
        ),
    }
}

async fn expect_delta(
    db: &dyn DatabaseBackend,
    namespace: &str,
    after: u64,
    why: &str,
) -> IncrementalResult {
    match db.load_incremental_config(namespace, after).await {
        Ok(delta) => delta,
        Err(error) => panic!("{why}: consumer change must ride the delta, got {error}"),
    }
}

fn hmac_of<'a>(
    config: &'a ferrum_edge::config::types::GatewayConfig,
    id: &str,
) -> Option<&'a Value> {
    config
        .consumers
        .iter()
        .find(|consumer| consumer.id == id)
        .expect("consumer present")
        .credentials
        .get("hmac_auth")
}

/// The consumer-delta quarantine contract every backend must keep.
/// `corrupt_hmac_secret(namespace, consumer_id, secret)` must overwrite the
/// stored `hmac_auth` secret out of band: bypassing credential uniqueness and
/// without a `config_changes` record, as a pre-existing row or direct DB edit
/// would.
pub(crate) async fn assert_consumer_delta_quarantine_contract<F, Fut>(
    db: &dyn DatabaseBackend,
    corrupt_hmac_secret: F,
) where
    F: Fn(String, String, String) -> Fut,
    Fut: Future<Output = ()>,
{
    let ns = format!("consumer-delta-{}", uuid::Uuid::new_v4().simple());
    let ns = ns.as_str();

    // No full load has recorded this namespace yet: escalate.
    db.create_consumer(&consumer(ns, "c-a", keyauth("key-a")))
        .await
        .unwrap();
    let after = db.latest_change_sequence(ns).await.unwrap();
    db.create_consumer(&consumer(ns, "c-b", keyauth("key-b")))
        .await
        .unwrap();
    expect_escalation(db, ns, after, "unknown quarantine state").await;

    // A full load that quarantined nothing lets creates, updates, and deletes
    // ride the delta.
    db.load_full_config(ns).await.unwrap();
    let after = db.latest_change_sequence(ns).await.unwrap();
    db.create_consumer(&consumer(ns, "c-c", keyauth("key-c")))
        .await
        .unwrap();
    assert!(
        db.update_consumer(
            &consumer(ns, "c-a", keyauth("key-a2")),
            &BatchConfigWriteMode::Admission
        )
        .await
        .unwrap()
    );
    assert!(db.delete_consumer(ns, "c-b").await.unwrap());
    let delta = expect_delta(db, ns, after, "clean namespace").await;
    let mut upserted: Vec<&str> = delta
        .added_or_modified_consumers
        .iter()
        .map(|consumer| consumer.id.as_str())
        .collect();
    upserted.sort_unstable();
    assert_eq!(upserted, ["c-a", "c-c"]);
    assert_eq!(
        delta
            .removed_consumer_ids
            .iter()
            .map(|id| id.id.as_str())
            .collect::<Vec<_>>(),
        ["c-b"]
    );
    assert!(delta.sequence_cursor > after);

    // An hmac_auth upsert escalates even in a clean namespace: which consumer
    // keeps a shared secret depends on full-load order.
    let after = db.latest_change_sequence(ns).await.unwrap();
    db.create_consumer(&consumer(ns, "c-h", hmac(SHARED_SECRET)))
        .await
        .unwrap();
    expect_escalation(db, ns, after, "hmac_auth upsert").await;

    // A stored duplicate secret is quarantined at full load: the later id
    // loses its credential, and every consumer change now escalates.
    db.create_consumer(&consumer(ns, "c-z", hmac(OTHER_SECRET)))
        .await
        .unwrap();
    corrupt_hmac_secret(ns.to_string(), "c-z".to_string(), SHARED_SECRET.to_string()).await;
    let full = db.load_full_config(ns).await.unwrap();
    assert_eq!(
        hmac_of(&full, "c-h"),
        Some(&json!([{"secret": SHARED_SECRET}]))
    );
    assert_eq!(
        hmac_of(&full, "c-z"),
        None,
        "the duplicate secret must be stripped from the later consumer"
    );
    let after = db.latest_change_sequence(ns).await.unwrap();
    db.create_consumer(&consumer(ns, "c-k", keyauth("key-k")))
        .await
        .unwrap();
    expect_escalation(db, ns, after, "keyauth create while quarantine is active").await;

    // Deleting the conflicting consumer escalates, and the full reload
    // rehydrates the stripped credential from storage.
    let after = db.latest_change_sequence(ns).await.unwrap();
    assert!(db.delete_consumer(ns, "c-h").await.unwrap());
    expect_escalation(db, ns, after, "delete of the conflicting consumer").await;
    let full = db.load_full_config(ns).await.unwrap();
    assert_eq!(
        hmac_of(&full, "c-z"),
        Some(&json!([{"secret": SHARED_SECRET}])),
        "the full reload must restore the previously stripped credential"
    );

    // That reload quarantined nothing, so consumer changes ride the delta again.
    let after = db.latest_change_sequence(ns).await.unwrap();
    assert!(
        db.update_consumer(
            &consumer(ns, "c-k", keyauth("key-k2")),
            &BatchConfigWriteMode::Admission
        )
        .await
        .unwrap()
    );
    let delta = expect_delta(db, ns, after, "clean after rehydration").await;
    assert_eq!(delta.added_or_modified_consumers.len(), 1);

    // A snapshot that was loaded but not published is forgotten: escalate.
    db.forget_consumer_quarantine_state(ns);
    let after = db.latest_change_sequence(ns).await.unwrap();
    assert!(
        db.update_consumer(
            &consumer(ns, "c-k", keyauth("key-k3")),
            &BatchConfigWriteMode::Admission
        )
        .await
        .unwrap()
    );
    expect_escalation(db, ns, after, "forgotten quarantine state").await;
}

/// Overwrite a stored SQL consumer's `hmac_auth` secret without a change-log
/// record or the credential-uniqueness index.
pub(crate) async fn corrupt_sql_hmac_secret(
    store: &DatabaseStore,
    namespace: &str,
    id: &str,
    secret: &str,
) {
    let credentials = hmac(secret).to_string();
    let sql = if store.db_type_str() == "postgres" {
        "UPDATE consumers SET credentials = $1 WHERE namespace = $2 AND id = $3"
    } else {
        "UPDATE consumers SET credentials = ? WHERE namespace = ? AND id = ?"
    };
    let result = sqlx::query(sql)
        .bind(credentials)
        .bind(namespace)
        .bind(id)
        .execute(&store.pool())
        .await
        .expect("out-of-band consumer update");
    assert_eq!(result.rows_affected(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consumer_delta_quarantine_contract() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("consumer-delta-quarantine.db");
    let url = format!("sqlite:{}?mode=rwc", path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &url, DbPoolConfig::default())
        .await
        .unwrap();
    assert_consumer_delta_quarantine_contract(&store, |namespace, id, secret| {
        let store = store.clone();
        async move { corrupt_sql_hmac_secret(&store, &namespace, &id, &secret).await }
    })
    .await;
}
