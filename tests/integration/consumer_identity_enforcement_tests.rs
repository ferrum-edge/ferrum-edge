//! Persistence-level consumer identity enforcement (issue #2121) and
//! phantom-update semantics (issue #2122 DB-M4) on the SQL backend.
//!
//! Consumer id, username, and custom_id share one identity keyspace per
//! namespace, enforced by the `consumer_identity_index` table written in the
//! same transaction as the consumer row — the admin precheck
//! (`check_consumer_identity_unique`) is raceable, so the constraint is the
//! authoritative backstop. Consumer ids are per-namespace: the same id may
//! exist in two namespaces (SQL PK is `(namespace, id)`).
//!
//! Exercises the SQLite path; the same `DatabaseStore` implementation backs
//! PostgreSQL/MySQL behind dialect-specific SQL rendering.

use chrono::Utc;
use ferrum_edge::config::db_backend::{BatchConfigWriteMode, DatabaseBackend};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::types::Consumer;
use std::collections::HashMap;
use tempfile::TempDir;

async fn sqlite_store() -> (DatabaseStore, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("consumer_identity_test.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store creation must succeed");
    store
        .run_migrations()
        .await
        .expect("migrations must succeed");
    (store, temp_dir)
}

fn consumer_in(namespace: &str, id: &str, username: &str, custom_id: Option<&str>) -> Consumer {
    Consumer {
        id: id.to_string(),
        namespace: namespace.to_string(),
        username: username.to_string(),
        custom_id: custom_id.map(str::to_string),
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn assert_unique_violation(err: &anyhow::Error) {
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("unique constraint")
            || msg.contains("duplicate key")
            || msg.contains("duplicate entry"),
        "expected a unique-constraint violation, got: {msg}"
    );
}

#[tokio::test]
async fn cross_field_collision_username_vs_custom_id_rejected_at_persistence() {
    let (store, _tmp) = sqlite_store().await;

    store
        .create_consumer(&consumer_in("ferrum", "c1", "alice", Some("alice-ext")))
        .await
        .expect("first consumer must persist");

    // c2's username collides with c1's custom_id — rejected by the
    // consumer_identity_index PK even though the (namespace, username)
    // unique index alone would allow it.
    let err = store
        .create_consumer(&consumer_in("ferrum", "c2", "alice-ext", None))
        .await
        .expect_err("cross-field collision must be rejected");
    assert_unique_violation(&err);

    // And c3's custom_id colliding with c1's id.
    let err = store
        .create_consumer(&consumer_in("ferrum", "c3", "carol", Some("c1")))
        .await
        .expect_err("custom_id colliding with an existing id must be rejected");
    assert_unique_violation(&err);
}

#[tokio::test]
async fn self_collision_within_one_consumer_is_allowed() {
    let (store, _tmp) = sqlite_store().await;

    // A consumer whose own custom_id equals its own username is valid — the
    // identity values are deduped before hitting the identity index.
    store
        .create_consumer(&consumer_in("ferrum", "c1", "alice", Some("alice")))
        .await
        .expect("self-collision must be allowed");

    let loaded = store
        .get_consumer("ferrum", "c1")
        .await
        .expect("get must succeed")
        .expect("consumer must exist");
    assert_eq!(loaded.custom_id.as_deref(), Some("alice"));
}

#[tokio::test]
async fn update_introducing_cross_field_collision_is_rejected() {
    let (store, _tmp) = sqlite_store().await;

    store
        .create_consumer(&consumer_in("ferrum", "c1", "alice", None))
        .await
        .expect("c1 must persist");
    store
        .create_consumer(&consumer_in("ferrum", "c2", "bob", None))
        .await
        .expect("c2 must persist");

    let err = store
        .update_consumer(
            &consumer_in("ferrum", "c2", "bob", Some("alice")),
            &BatchConfigWriteMode::Admission,
        )
        .await
        .expect_err("update stealing c1's username as custom_id must be rejected");
    assert_unique_violation(&err);

    // The failed update must not have corrupted c2 or leaked identity rows:
    // c2 can still be updated to a non-colliding shape.
    let updated = store
        .update_consumer(
            &consumer_in("ferrum", "c2", "bob", Some("bob-ext")),
            &BatchConfigWriteMode::Admission,
        )
        .await
        .expect("non-colliding update must succeed");
    assert!(updated);
}

#[tokio::test]
async fn consumer_ids_are_per_namespace() {
    let (store, _tmp) = sqlite_store().await;

    // The same consumer id in two namespaces must be accepted (issue #2121:
    // application-level uniqueness was always per-namespace; the PK now
    // matches it).
    store
        .create_consumer(&consumer_in("tenant-a", "shared-id", "alice", None))
        .await
        .expect("tenant-a consumer must persist");
    store
        .create_consumer(&consumer_in("tenant-b", "shared-id", "bob", None))
        .await
        .expect("tenant-b consumer with the same id must persist");

    // Reads are namespace-predicated.
    let a = store
        .get_consumer("tenant-a", "shared-id")
        .await
        .unwrap()
        .expect("tenant-a consumer must be readable");
    assert_eq!(a.username, "alice");
    let b = store
        .get_consumer("tenant-b", "shared-id")
        .await
        .unwrap()
        .expect("tenant-b consumer must be readable");
    assert_eq!(b.username, "bob");
    assert!(
        store
            .get_consumer("tenant-c", "shared-id")
            .await
            .unwrap()
            .is_none(),
        "unrelated namespace must not see the consumer"
    );

    // Deletes are namespace-predicated too: removing tenant-a's row leaves
    // tenant-b's untouched.
    assert!(
        store
            .delete_consumer("tenant-a", "shared-id")
            .await
            .unwrap()
    );
    assert!(
        store
            .get_consumer("tenant-b", "shared-id")
            .await
            .unwrap()
            .is_some()
    );

    // Duplicate id within one namespace is still rejected.
    let err = store
        .create_consumer(&consumer_in("tenant-b", "shared-id", "carol", None))
        .await
        .expect_err("duplicate id within a namespace must be rejected");
    assert_unique_violation(&err);
}

#[tokio::test]
async fn deleted_consumer_frees_its_identity_values() {
    let (store, _tmp) = sqlite_store().await;

    store
        .create_consumer(&consumer_in("ferrum", "c1", "alice", Some("alice-ext")))
        .await
        .expect("c1 must persist");
    assert!(store.delete_consumer("ferrum", "c1").await.unwrap());

    // All three identity values are reusable after the delete.
    store
        .create_consumer(&consumer_in("ferrum", "c1", "alice", Some("alice-ext")))
        .await
        .expect("identity values must be freed by the delete");
}

/// SQLite (BINARY) must keep NFC and NFD forms of the same grapheme as
/// distinct consumer identities — the same byte-exact contract PostgreSQL
/// `texteq` and MySQL `utf8mb4_0900_bin` provide (#2994).
#[tokio::test]
async fn nfc_and_nfd_usernames_are_distinct_byte_exact_identities() {
    let (store, _tmp) = sqlite_store().await;

    // U+00E9 (é) vs e + U+0301 combining acute — canonically equivalent under
    // UCA, distinct as UTF-8 bytes.
    let nfc_username = "caf\u{00e9}";
    let nfd_username = "cafe\u{0301}";
    assert_ne!(
        nfc_username.as_bytes(),
        nfd_username.as_bytes(),
        "fixture usernames must differ by bytes"
    );

    store
        .create_consumer(&consumer_in("ferrum", "nfc-consumer", nfc_username, None))
        .await
        .expect("NFC username must insert");
    store
        .create_consumer(&consumer_in("ferrum", "nfd-consumer", nfd_username, None))
        .await
        .expect("NFD username must insert as a distinct identity");

    assert!(
        store
            .check_consumer_identity_unique("ferrum", "other", nfc_username, None, None)
            .await
            .expect("NFC identity probe")
            .is_some(),
        "NFC username must collide with the NFC consumer only"
    );
    assert!(
        store
            .check_consumer_identity_unique("ferrum", "other", nfd_username, None, None)
            .await
            .expect("NFD identity probe")
            .is_some(),
        "NFD username must collide with the NFD consumer only"
    );

    let loaded_nfc = store
        .get_consumer("ferrum", "nfc-consumer")
        .await
        .expect("load NFC consumer")
        .expect("NFC consumer present");
    let loaded_nfd = store
        .get_consumer("ferrum", "nfd-consumer")
        .await
        .expect("load NFD consumer")
        .expect("NFD consumer present");
    assert_eq!(loaded_nfc.username.as_bytes(), nfc_username.as_bytes());
    assert_eq!(loaded_nfd.username.as_bytes(), nfd_username.as_bytes());
}

#[tokio::test]
async fn trailing_space_usernames_are_distinct_byte_exact_identities() {
    let (store, _tmp) = sqlite_store().await;

    store
        .create_consumer(&consumer_in("ferrum", "plain-consumer", "alice", None))
        .await
        .expect("plain username must insert");
    store
        .create_consumer(&consumer_in("ferrum", "space-consumer", "alice ", None))
        .await
        .expect("trailing-space username must insert as a distinct identity");

    let loaded = store
        .get_consumer("ferrum", "space-consumer")
        .await
        .expect("load trailing-space consumer")
        .expect("trailing-space consumer present");
    assert_eq!(loaded.username.as_bytes(), b"alice ");
}

#[tokio::test]
async fn phantom_update_returns_false_and_records_no_change() {
    let (store, _tmp) = sqlite_store().await;

    let seeded = store.latest_change_sequence("ferrum").await.unwrap();

    // Updating a consumer that never existed must report not-found rather
    // than fabricating an upsert change record (issue #2122 DB-M4).
    let updated = store
        .update_consumer(
            &consumer_in("ferrum", "ghost", "casper", None),
            &BatchConfigWriteMode::Admission,
        )
        .await
        .expect("phantom update must not error");
    assert!(!updated, "phantom update must report no match");

    let after = store.latest_change_sequence("ferrum").await.unwrap();
    assert_eq!(
        seeded, after,
        "a phantom update must not emit a config-change record"
    );
}
