//! Tests for ConsumerIndex — credential-indexed consumer lookup

use chrono::Utc;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::db_backend::NamespacedResourceId;
use ferrum_edge::config::types::Consumer;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedLogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn make_consumer(
    id: &str,
    username: &str,
    api_key: Option<&str>,
    custom_id: Option<&str>,
) -> Consumer {
    let mut credentials = HashMap::new();

    if let Some(key) = api_key {
        let mut keyauth_creds = Map::new();
        keyauth_creds.insert("key".to_string(), Value::String(key.to_string()));
        credentials.insert(
            "keyauth".to_string(),
            Value::Array(vec![Value::Object(keyauth_creds)]),
        );
    }

    let mut basicauth_creds = Map::new();
    basicauth_creds.insert(
        "password_hash".to_string(),
        Value::String("hmac_sha256:placeholder".to_string()),
    );
    credentials.insert(
        "basicauth".to_string(),
        Value::Array(vec![Value::Object(basicauth_creds)]),
    );

    Consumer {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: custom_id.map(|s| s.to_string()),
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// ---- Index correctness ----

#[test]
fn test_find_by_api_key_returns_correct_consumer() {
    let consumer = make_consumer("c1", "alice", Some("key-alice"), None);
    let index = ConsumerIndex::new(&[consumer]);

    let found = index.find_by_api_key("key-alice");
    assert!(found.is_some());
    assert_eq!(found.unwrap().username, "alice");
}

#[test]
fn test_find_by_api_key_missing_returns_none() {
    let consumer = make_consumer("c1", "alice", Some("key-alice"), None);
    let index = ConsumerIndex::new(&[consumer]);

    assert!(index.find_by_api_key("nonexistent-key").is_none());
}

#[test]
fn test_find_by_username_returns_correct_consumer() {
    let consumer = make_consumer("c1", "bob", Some("key-bob"), None);
    let index = ConsumerIndex::new(&[consumer]);

    let found = index.find_by_username("bob");
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, "c1");
}

/// Runtime identity indexes are byte-keyed HashMaps. NFC and NFD forms of the
/// same grapheme must remain distinct so DB uniqueness (MySQL
/// `utf8mb4_0900_bin`,
/// PostgreSQL `texteq`, SQLite BINARY) and runtime lookup stay aligned (#2994).
#[test]
fn test_nfc_and_nfd_usernames_are_distinct_runtime_identities() {
    let nfc_username = "caf\u{00e9}";
    let nfd_username = "cafe\u{0301}";
    assert_ne!(nfc_username.as_bytes(), nfd_username.as_bytes());

    let nfc = make_consumer("nfc", nfc_username, None, None);
    let nfd = make_consumer("nfd", nfd_username, None, None);
    let index = ConsumerIndex::new(&[nfc, nfd]);

    assert_eq!(
        index.find_by_username(nfc_username).map(|c| c.id.clone()),
        Some("nfc".to_string())
    );
    assert_eq!(
        index.find_by_username(nfd_username).map(|c| c.id.clone()),
        Some("nfd".to_string())
    );
    assert_eq!(
        index.find_by_identity(nfc_username).map(|c| c.id.clone()),
        Some("nfc".to_string())
    );
    assert_eq!(
        index.find_by_identity(nfd_username).map(|c| c.id.clone()),
        Some("nfd".to_string())
    );
}

#[test]
fn test_trailing_space_usernames_are_distinct_runtime_identities() {
    let plain = make_consumer("plain", "alice", None, None);
    let spaced = make_consumer("spaced", "alice ", None, None);
    let index = ConsumerIndex::new(&[plain, spaced]);

    assert_eq!(
        index.find_by_username("alice").map(|c| c.id.clone()),
        Some("plain".to_string())
    );
    assert_eq!(
        index.find_by_username("alice ").map(|c| c.id.clone()),
        Some("spaced".to_string())
    );
    assert_eq!(
        index.find_by_identity("alice ").map(|c| c.id.clone()),
        Some("spaced".to_string())
    );
}

#[test]
fn test_find_by_username_missing_returns_none() {
    let consumer = make_consumer("c1", "bob", Some("key-bob"), None);
    let index = ConsumerIndex::new(&[consumer]);

    assert!(index.find_by_username("nobody").is_none());
}

#[test]
fn test_find_by_identity_username() {
    let consumer = make_consumer("c1", "carol", None, None);
    let index = ConsumerIndex::new(&[consumer]);

    let found = index.find_by_identity("carol");
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, "c1");
}

#[test]
fn test_find_by_identity_id() {
    let consumer = make_consumer("c1", "carol", None, None);
    let index = ConsumerIndex::new(&[consumer]);

    let found = index.find_by_identity("c1");
    assert!(found.is_some());
    assert_eq!(found.unwrap().username, "carol");
}

#[test]
fn test_find_by_identity_custom_id() {
    let consumer = make_consumer("c1", "carol", None, Some("custom-carol"));
    let index = ConsumerIndex::new(&[consumer]);

    let found = index.find_by_identity("custom-carol");
    assert!(found.is_some());
    assert_eq!(found.unwrap().username, "carol");
}

#[test]
fn test_multiple_consumers_different_credentials() {
    let c1 = make_consumer("c1", "alice", Some("key-a"), None);
    let c2 = make_consumer("c2", "bob", Some("key-b"), None);
    let c3 = make_consumer("c3", "carol", None, Some("custom-c"));
    let index = ConsumerIndex::new(&[c1, c2, c3]);

    assert_eq!(index.find_by_api_key("key-a").unwrap().username, "alice");
    assert_eq!(index.find_by_api_key("key-b").unwrap().username, "bob");
    assert!(index.find_by_api_key("key-c").is_none());
    assert_eq!(index.find_by_username("carol").unwrap().id, "c3");
    assert_eq!(
        index.find_by_identity("custom-c").unwrap().username,
        "carol"
    );
    assert_eq!(index.consumer_count(), 3);
}

#[test]
fn test_consumers_returns_full_list() {
    let c1 = make_consumer("c1", "alice", Some("key-a"), None);
    let c2 = make_consumer("c2", "bob", Some("key-b"), None);
    let index = ConsumerIndex::new(&[c1, c2]);

    let all = index.consumers();
    assert_eq!(all.len(), 2);
}

#[test]
fn test_rebuild_reflects_new_consumers() {
    let c1 = make_consumer("c1", "alice", Some("key-a"), None);
    let index = ConsumerIndex::new(&[c1]);

    assert!(index.find_by_api_key("key-a").is_some());
    assert!(index.find_by_api_key("key-b").is_none());

    // Rebuild with different consumer
    let c2 = make_consumer("c2", "bob", Some("key-b"), None);
    index.rebuild(&[c2]);

    assert!(index.find_by_api_key("key-a").is_none()); // Old consumer gone
    assert!(index.find_by_api_key("key-b").is_some()); // New consumer present
    assert_eq!(index.consumer_count(), 1);
}

// ---- Edge cases ----

#[test]
fn test_empty_consumer_list() {
    let index = ConsumerIndex::new(&[]);

    assert!(index.find_by_api_key("any").is_none());
    assert!(index.find_by_username("any").is_none());
    assert!(index.find_by_identity("any").is_none());
    assert_eq!(index.consumer_count(), 0);
    assert_eq!(index.consumers().len(), 0);
}

#[test]
fn test_consumer_with_no_keyauth_credentials() {
    let mut credentials = HashMap::new();
    let mut basicauth_creds = Map::new();
    basicauth_creds.insert(
        "password_hash".to_string(),
        Value::String("hash".to_string()),
    );
    credentials.insert(
        "basicauth".to_string(),
        Value::Array(vec![Value::Object(basicauth_creds)]),
    );

    let consumer = Consumer {
        id: "c1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "nokey".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let index = ConsumerIndex::new(&[consumer]);

    // No API key credential, so find_by_api_key should return None
    assert!(index.find_by_api_key("anything").is_none());
    // But username lookup still works
    assert!(index.find_by_username("nokey").is_some());
    assert!(index.find_by_identity("nokey").is_some());
}

#[test]
fn test_index_len_counts_all_entries() {
    // One consumer with API key, username, and ID creates multiple index entries
    let consumer = make_consumer("c1", "alice", Some("key-a"), Some("custom-a"));
    let index = ConsumerIndex::new(&[consumer]);

    // Expected entries: keyauth:key-a, basic:alice, identity:alice, identity:c1, identity:custom-a
    assert_eq!(index.index_len(), 5);
}

#[test]
fn test_index_len_includes_mtls_entries() {
    let consumer = make_consumer_with_array_mtls("c1", "alice", &["CN=old", "CN=new"]);
    let index = ConsumerIndex::new(&[consumer]);

    // Expected entries: mtls:CN=old, mtls:CN=new, identity:alice, identity:c1
    assert_eq!(index.index_len(), 4);
}

// ---- apply_delta correctness ----

#[test]
fn test_apply_delta_add_consumer() {
    let c1 = make_consumer("c1", "alice", Some("key-a"), None);
    let index = ConsumerIndex::new(&[c1]);

    let c2 = make_consumer("c2", "bob", Some("key-b"), None);
    index.apply_delta(&[c2], &[], &[]);

    assert_eq!(index.consumer_count(), 2);
    assert!(index.find_by_api_key("key-a").is_some());
    assert!(index.find_by_api_key("key-b").is_some());
    assert!(index.find_by_username("bob").is_some());
    assert!(index.find_by_identity("c2").is_some());
}

#[test]
fn test_apply_delta_remove_consumer() {
    let c1 = make_consumer("c1", "alice", Some("key-a"), None);
    let c2 = make_consumer("c2", "bob", Some("key-b"), None);
    let index = ConsumerIndex::new(&[c1, c2]);

    index.apply_delta(&[], &[NamespacedResourceId::new("ferrum", "c1")], &[]);

    assert_eq!(index.consumer_count(), 1);
    assert!(index.find_by_api_key("key-a").is_none());
    assert!(index.find_by_username("alice").is_none());
    assert!(index.find_by_api_key("key-b").is_some());
}

#[test]
fn test_apply_delta_modify_consumer_credentials() {
    let c1 = make_consumer("c1", "alice", Some("key-old"), None);
    let index = ConsumerIndex::new(&[c1]);

    // Modify: change API key
    let c1_modified = make_consumer("c1", "alice", Some("key-new"), None);
    index.apply_delta(&[], &[], &[c1_modified]);

    assert_eq!(index.consumer_count(), 1);
    assert!(
        index.find_by_api_key("key-old").is_none(),
        "Old API key should be removed after modify"
    );
    assert!(
        index.find_by_api_key("key-new").is_some(),
        "New API key should be present after modify"
    );
    assert!(index.find_by_username("alice").is_some());
}

#[test]
fn test_apply_delta_simultaneous_add_remove_modify() {
    let c1 = make_consumer("c1", "alice", Some("key-a"), None);
    let c2 = make_consumer("c2", "bob", Some("key-b"), None);
    let c3 = make_consumer("c3", "carol", Some("key-c"), None);
    let index = ConsumerIndex::new(&[c1, c2, c3]);

    let c4 = make_consumer("c4", "dave", Some("key-d"), None);
    let c2_modified = make_consumer("c2", "bob", Some("key-b-new"), None);

    index.apply_delta(
        &[c4],
        &[NamespacedResourceId::new("ferrum", "c1")],
        &[c2_modified],
    );

    assert_eq!(index.consumer_count(), 3); // c2, c3, c4
    assert!(index.find_by_api_key("key-a").is_none()); // removed
    assert!(index.find_by_api_key("key-b").is_none()); // old key replaced
    assert!(index.find_by_api_key("key-b-new").is_some()); // modified
    assert!(index.find_by_api_key("key-c").is_some()); // unchanged
    assert!(index.find_by_api_key("key-d").is_some()); // added
}

// ---- Multi-credential (array format) tests ----

fn make_consumer_with_array_keys(id: &str, username: &str, keys: &[&str]) -> Consumer {
    let mut credentials = HashMap::new();
    let arr: Vec<Value> = keys
        .iter()
        .map(|k| {
            let mut m = Map::new();
            m.insert("key".to_string(), Value::String(k.to_string()));
            Value::Object(m)
        })
        .collect();
    credentials.insert("keyauth".to_string(), Value::Array(arr));

    Consumer {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_find_by_api_key_with_array_credentials() {
    let c = make_consumer_with_array_keys("c1", "alice", &["key-old", "key-new"]);
    let index = ConsumerIndex::new(&[c]);

    // Both keys should resolve to the same consumer
    let found_old = index.find_by_api_key("key-old").unwrap();
    let found_new = index.find_by_api_key("key-new").unwrap();
    assert_eq!(found_old.id, "c1");
    assert_eq!(found_new.id, "c1");
    // Non-existent key
    assert!(index.find_by_api_key("key-other").is_none());
}

#[test]
fn test_apply_delta_with_array_credentials() {
    let c1 = make_consumer_with_array_keys("c1", "alice", &["key-a1", "key-a2"]);
    let c2 = make_consumer("c2", "bob", Some("key-b"), None);
    let index = ConsumerIndex::new(&[c1, c2]);

    // Modify c1: rotate keys (remove key-a1, keep key-a2, add key-a3)
    let c1_modified = make_consumer_with_array_keys("c1", "alice", &["key-a2", "key-a3"]);
    index.apply_delta(&[], &[], &[c1_modified]);

    assert!(index.find_by_api_key("key-a1").is_none()); // old key removed
    assert!(index.find_by_api_key("key-a2").is_some()); // kept
    assert!(index.find_by_api_key("key-a3").is_some()); // new key
    assert!(index.find_by_api_key("key-b").is_some()); // other consumer unaffected
}

#[test]
fn test_apply_delta_remove_consumer_with_array_credentials() {
    let c1 = make_consumer_with_array_keys("c1", "alice", &["key-a1", "key-a2"]);
    let index = ConsumerIndex::new(&[c1]);

    index.apply_delta(&[], &[NamespacedResourceId::new("ferrum", "c1")], &[]);

    assert!(index.find_by_api_key("key-a1").is_none());
    assert!(index.find_by_api_key("key-a2").is_none());
    assert_eq!(index.consumer_count(), 0);
}

#[test]
fn test_multiple_array_credentials() {
    let c1 = make_consumer_with_array_keys("c1", "alice", &["key-a1", "key-a2"]);
    let c2 = make_consumer("c2", "bob", Some("key-b"), None);
    let index = ConsumerIndex::new(&[c1, c2]);

    assert_eq!(index.find_by_api_key("key-a1").unwrap().id, "c1");
    assert_eq!(index.find_by_api_key("key-a2").unwrap().id, "c1");
    assert_eq!(index.find_by_api_key("key-b").unwrap().id, "c2");
}

fn make_consumer_with_array_mtls(id: &str, username: &str, identities: &[&str]) -> Consumer {
    let mut credentials = HashMap::new();
    let arr: Vec<Value> = identities
        .iter()
        .map(|i| {
            let mut m = Map::new();
            m.insert("identity".to_string(), Value::String(i.to_string()));
            Value::Object(m)
        })
        .collect();
    credentials.insert("mtls_auth".to_string(), Value::Array(arr));

    Consumer {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_consumer_with_colliding_credentials(
    id: &str,
    username: &str,
    api_key: &str,
    custom_id: &str,
    mtls_identity: &str,
) -> Consumer {
    let mut consumer = make_consumer(id, username, Some(api_key), Some(custom_id));
    consumer.credentials.insert(
        "mtls_auth".to_string(),
        Value::Array(vec![serde_json::json!({ "identity": mtls_identity })]),
    );
    consumer
}

#[test]
fn test_find_by_mtls_identity_with_array_credentials() {
    let c = make_consumer_with_array_mtls("c1", "alice", &["CN=old", "CN=new"]);
    let index = ConsumerIndex::new(&[c]);

    assert_eq!(index.find_by_mtls_identity("CN=old").unwrap().id, "c1");
    assert_eq!(index.find_by_mtls_identity("CN=new").unwrap().id, "c1");
    assert!(index.find_by_mtls_identity("CN=other").is_none());
}

// ---- auth_type_counts / credential metrics ----

fn make_consumer_with_jwt(id: &str, username: &str) -> Consumer {
    let mut credentials = HashMap::new();
    let mut jwt_creds = Map::new();
    jwt_creds.insert(
        "secret".to_string(),
        Value::String("my-jwt-secret".to_string()),
    );
    credentials.insert(
        "jwt".to_string(),
        Value::Array(vec![Value::Object(jwt_creds)]),
    );

    Consumer {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_consumer_with_hmac(id: &str, username: &str) -> Consumer {
    let mut credentials = HashMap::new();
    let mut hmac_creds = Map::new();
    hmac_creds.insert(
        "secret".to_string(),
        Value::String("hmac-secret".to_string()),
    );
    credentials.insert(
        "hmac_auth".to_string(),
        Value::Array(vec![Value::Object(hmac_creds)]),
    );

    Consumer {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_hmac_identity_lookup_is_namespace_scoped_across_rebuild_and_delta() {
    let mut tenant_a = make_consumer_with_hmac("tenant-a-consumer", "shared-user");
    tenant_a.namespace = "tenant-a".to_string();
    let mut tenant_b = make_consumer_with_hmac("tenant-b-consumer", "shared-user");
    tenant_b.namespace = "tenant-b".to_string();
    let index = ConsumerIndex::new(&[tenant_a, tenant_b.clone()]);

    assert_eq!(
        index
            .find_hmac_by_identity("tenant-a", "shared-user")
            .unwrap()
            .id,
        "tenant-a-consumer"
    );
    assert_eq!(
        index
            .find_hmac_by_identity("tenant-b", "shared-user")
            .unwrap()
            .id,
        "tenant-b-consumer"
    );
    assert!(
        index
            .find_hmac_by_identity("tenant-c", "shared-user")
            .is_none()
    );

    tenant_b.username = "rotated-user".to_string();
    index.apply_delta(&[], &[], &[tenant_b]);
    assert!(
        index
            .find_hmac_by_identity("tenant-b", "shared-user")
            .is_none()
    );
    assert_eq!(
        index
            .find_hmac_by_identity("tenant-b", "rotated-user")
            .unwrap()
            .id,
        "tenant-b-consumer"
    );
    assert_eq!(
        index
            .find_hmac_by_identity("tenant-a", "shared-user")
            .unwrap()
            .id,
        "tenant-a-consumer"
    );
}

#[test]
fn test_auth_type_counts_empty() {
    let index = ConsumerIndex::new(&[]);
    let (keyauth, basic, mtls, jwt, hmac, identity, total) = index.auth_type_counts();
    assert_eq!(keyauth, 0);
    assert_eq!(basic, 0);
    assert_eq!(mtls, 0);
    assert_eq!(jwt, 0);
    assert_eq!(hmac, 0);
    assert_eq!(identity, 0);
    assert_eq!(total, 0);
}

#[test]
fn test_auth_type_counts_with_keyauth_and_basic() {
    let c = make_consumer("c1", "alice", Some("key-1"), None);
    let index = ConsumerIndex::new(&[c]);
    let (keyauth, basic, _mtls, _jwt, _hmac, _identity, total) = index.auth_type_counts();
    assert_eq!(keyauth, 1); // one API key
    assert_eq!(basic, 1); // make_consumer adds basicauth by default
    assert_eq!(total, 1);
}

#[test]
fn test_auth_type_counts_jwt_credentials() {
    let c = make_consumer_with_jwt("c1", "alice");
    let index = ConsumerIndex::new(&[c]);
    let (_keyauth, _basic, _mtls, jwt, _hmac, _identity, total) = index.auth_type_counts();
    assert_eq!(jwt, 1);
    assert_eq!(total, 1);
}

#[test]
fn test_auth_type_counts_hmac_credentials() {
    let c = make_consumer_with_hmac("c1", "alice");
    let index = ConsumerIndex::new(&[c]);
    let (_keyauth, _basic, _mtls, _jwt, hmac, _identity, total) = index.auth_type_counts();
    assert_eq!(hmac, 1);
    assert_eq!(total, 1);
}

#[test]
fn test_auth_type_counts_multiple_jwt_array_credentials() {
    let mut credentials = HashMap::new();
    // JWT with array of 2 credential entries (rotation scenario)
    credentials.insert(
        "jwt".to_string(),
        Value::Array(vec![
            serde_json::json!({"secret": "old-secret"}),
            serde_json::json!({"secret": "new-secret"}),
        ]),
    );
    let c = Consumer {
        id: "c1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "alice".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let index = ConsumerIndex::new(&[c]);
    let (_keyauth, _basic, _mtls, jwt, _hmac, _identity, _total) = index.auth_type_counts();
    assert_eq!(jwt, 2); // 2 credential entries in the array
}

#[test]
fn test_auth_type_counts_mixed_consumers() {
    let c1 = make_consumer("c1", "alice", Some("key-1"), None);
    let c2 = make_consumer_with_jwt("c2", "bob");
    let c3 = make_consumer_with_hmac("c3", "charlie");
    let index = ConsumerIndex::new(&[c1, c2, c3]);
    let (keyauth, basic, _mtls, jwt, hmac, _identity, total) = index.auth_type_counts();
    assert_eq!(keyauth, 1);
    assert_eq!(basic, 1); // only c1 has basicauth
    assert_eq!(jwt, 1);
    assert_eq!(hmac, 1);
    assert_eq!(total, 3);
}

#[test]
fn test_auth_type_counts_identity_index_entries() {
    // Identity index stores username, id, and custom_id for each consumer
    let c = make_consumer("c1", "alice", None, Some("alice-custom"));
    let index = ConsumerIndex::new(&[c]);
    let (_keyauth, _basic, _mtls, _jwt, _hmac, identity, _total) = index.auth_type_counts();
    // Identity index should have: username="alice", id="c1", custom_id="alice-custom"
    assert_eq!(identity, 3);
}

// ---- build_index: single credential type tests ----

#[test]
fn test_build_index_single_consumer_basicauth_only() {
    // Consumer with basicauth but no keyauth — only basic + identity indexes populated
    let mut credentials = HashMap::new();
    let mut basic_creds = Map::new();
    basic_creds.insert(
        "password_hash".to_string(),
        Value::String("hmac_sha256:hash".to_string()),
    );
    credentials.insert(
        "basicauth".to_string(),
        Value::Array(vec![Value::Object(basic_creds)]),
    );
    let c = Consumer {
        id: "c1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "alice".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let index = ConsumerIndex::new(&[c]);

    assert!(index.find_by_username("alice").is_some());
    assert!(index.find_by_identity("alice").is_some());
    assert!(index.find_by_identity("c1").is_some());
    assert!(index.find_by_api_key("anything").is_none());
    assert!(index.find_by_mtls_identity("anything").is_none());
    let (keyauth, basic, mtls, _jwt, _hmac, identity, total) = index.auth_type_counts();
    assert_eq!(keyauth, 0);
    assert_eq!(basic, 1);
    assert_eq!(mtls, 0);
    assert_eq!(identity, 2); // username + id
    assert_eq!(total, 1);
}

#[test]
fn test_build_index_single_consumer_jwt_only() {
    let c = make_consumer_with_jwt("c1", "jwt-user");
    let index = ConsumerIndex::new(&[c]);

    // JWT consumers are found via identity index, not keyauth or basic
    assert!(index.find_by_identity("jwt-user").is_some());
    assert!(index.find_by_identity("c1").is_some());
    assert!(index.find_by_api_key("anything").is_none());
    assert!(index.find_by_username("jwt-user").is_none()); // no basicauth
    let (keyauth, basic, _mtls, jwt, _hmac, _identity, total) = index.auth_type_counts();
    assert_eq!(keyauth, 0);
    assert_eq!(basic, 0);
    assert_eq!(jwt, 1);
    assert_eq!(total, 1);
}

#[test]
fn test_build_index_single_consumer_mtls_only() {
    let c = make_consumer_with_array_mtls("c1", "mtls-user", &["CN=service-a"]);
    let index = ConsumerIndex::new(&[c]);

    assert_eq!(
        index.find_by_mtls_identity("CN=service-a").unwrap().id,
        "c1"
    );
    assert!(index.find_by_mtls_identity("CN=unknown").is_none());
    assert!(index.find_by_api_key("anything").is_none());
    // identity index still populated with username + id
    assert!(index.find_by_identity("mtls-user").is_some());
    assert!(index.find_by_identity("c1").is_some());
    let (_keyauth, _basic, mtls, _jwt, _hmac, _identity, total) = index.auth_type_counts();
    assert_eq!(mtls, 1);
    assert_eq!(total, 1);
}

#[test]
fn test_build_index_consumer_with_all_credential_types() {
    // A consumer that has keyauth + basicauth + mtls + jwt + hmac all at once
    let mut credentials = HashMap::new();

    // keyauth
    let mut key_creds = Map::new();
    key_creds.insert("key".to_string(), Value::String("api-key-1".to_string()));
    credentials.insert(
        "keyauth".to_string(),
        Value::Array(vec![Value::Object(key_creds)]),
    );

    // basicauth
    let mut basic_creds = Map::new();
    basic_creds.insert(
        "password_hash".to_string(),
        Value::String("hmac_sha256:hash".to_string()),
    );
    credentials.insert(
        "basicauth".to_string(),
        Value::Array(vec![Value::Object(basic_creds)]),
    );

    // mtls_auth
    let mut mtls_creds = Map::new();
    mtls_creds.insert(
        "identity".to_string(),
        Value::String("CN=all-creds".to_string()),
    );
    credentials.insert(
        "mtls_auth".to_string(),
        Value::Array(vec![Value::Object(mtls_creds)]),
    );

    // jwt
    let mut jwt_creds = Map::new();
    jwt_creds.insert(
        "secret".to_string(),
        Value::String("jwt-secret-1".to_string()),
    );
    credentials.insert(
        "jwt".to_string(),
        Value::Array(vec![Value::Object(jwt_creds)]),
    );

    // hmac_auth
    let mut hmac_creds = Map::new();
    hmac_creds.insert(
        "secret".to_string(),
        Value::String("hmac-secret-1".to_string()),
    );
    credentials.insert(
        "hmac_auth".to_string(),
        Value::Array(vec![Value::Object(hmac_creds)]),
    );

    let c = Consumer {
        id: "c-all".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "multi-cred-user".to_string(),
        custom_id: Some("custom-all".to_string()),
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let index = ConsumerIndex::new(&[c]);

    assert_eq!(index.find_by_api_key("api-key-1").unwrap().id, "c-all");
    assert_eq!(
        index.find_by_username("multi-cred-user").unwrap().id,
        "c-all"
    );
    assert_eq!(
        index.find_by_mtls_identity("CN=all-creds").unwrap().id,
        "c-all"
    );
    assert_eq!(index.find_by_identity("custom-all").unwrap().id, "c-all");

    let (keyauth, basic, mtls, jwt, hmac, identity, total) = index.auth_type_counts();
    assert_eq!(keyauth, 1);
    assert_eq!(basic, 1);
    assert_eq!(mtls, 1);
    assert_eq!(jwt, 1);
    assert_eq!(hmac, 1);
    assert_eq!(identity, 3); // username + id + custom_id
    assert_eq!(total, 1);
}

// ---- Credential collision tests ----

#[test]
fn test_keyauth_collision_last_consumer_wins() {
    // Two consumers with the same API key — second overwrites first in HashMap
    let c1 = make_consumer("c1", "alice", Some("shared-key"), None);
    let c2 = make_consumer("c2", "bob", Some("shared-key"), None);
    let writer = SharedLogWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(writer.clone())
        .finish();
    let index = tracing::subscriber::with_default(subscriber, || ConsumerIndex::new(&[c1, c2]));

    let found = index.find_by_api_key("shared-key").unwrap();
    assert_eq!(found.id, "c2", "Last consumer with colliding key wins");
    assert_eq!(index.consumer_count(), 2);
    // Both consumers still present in the full list
    let all = index.consumers();
    assert_eq!(all.len(), 2);

    let logs = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("consumer 'c2' overwrites consumer 'c1'"));
    assert!(
        !logs.contains("shared-key"),
        "credential collision log leaked the reusable API key: {logs}"
    );
}

#[test]
fn test_basicauth_collision_last_consumer_wins() {
    // Two consumers with the same username and basicauth — collision on basic index
    let c1 = make_consumer("c1", "shared-user", Some("key-a"), None);
    let c2 = make_consumer("c2", "shared-user", Some("key-b"), None);
    let index = ConsumerIndex::new(&[c1, c2]);

    let found = index.find_by_username("shared-user").unwrap();
    assert_eq!(
        found.id, "c2",
        "Last consumer with colliding username wins in basic index"
    );
    // But separate keyauth keys still resolve correctly
    assert_eq!(index.find_by_api_key("key-a").unwrap().id, "c1");
    assert_eq!(index.find_by_api_key("key-b").unwrap().id, "c2");
}

#[test]
fn test_identity_collision_same_username() {
    // Two consumers with the same username — collision on identity index
    let c1 = make_consumer_with_jwt("c1", "shared-name");
    let c2 = make_consumer_with_jwt("c2", "shared-name");
    let index = ConsumerIndex::new(&[c1, c2]);

    let found = index.find_by_identity("shared-name").unwrap();
    assert_eq!(
        found.id, "c2",
        "Last consumer with colliding username wins in identity index"
    );
    // Each consumer's id is still unique in the identity index
    assert_eq!(index.find_by_identity("c1").unwrap().id, "c1");
    assert_eq!(index.find_by_identity("c2").unwrap().id, "c2");
}

#[test]
fn test_custom_id_collision_across_consumers() {
    // Two consumers with the same custom_id — identity collision (error-level log)
    let c1 = make_consumer("c1", "alice", Some("key-a"), Some("shared-custom"));
    let c2 = make_consumer("c2", "bob", Some("key-b"), Some("shared-custom"));
    let index = ConsumerIndex::new(&[c1, c2]);

    let found = index.find_by_identity("shared-custom").unwrap();
    assert_eq!(
        found.id, "c2",
        "Last consumer with colliding custom_id wins"
    );
    // Original consumers still accessible by their unique IDs
    assert_eq!(index.find_by_identity("c1").unwrap().id, "c1");
    assert_eq!(index.find_by_identity("c2").unwrap().id, "c2");
}

#[test]
fn test_mtls_collision_last_consumer_wins() {
    // Two consumers with the same mTLS identity
    let c1 = make_consumer_with_array_mtls("c1", "alice", &["CN=shared-cert"]);
    let c2 = make_consumer_with_array_mtls("c2", "bob", &["CN=shared-cert"]);
    let index = ConsumerIndex::new(&[c1, c2]);

    let found = index.find_by_mtls_identity("CN=shared-cert").unwrap();
    assert_eq!(
        found.id, "c2",
        "Last consumer with colliding mTLS identity wins"
    );
}

#[test]
fn test_apply_delta_remove_collision_winner_restores_shadowed_consumer() {
    let c1 = make_consumer_with_colliding_credentials(
        "c1",
        "shared-user",
        "shared-key",
        "shared-custom",
        "CN=shared",
    );
    let c2 = make_consumer_with_colliding_credentials(
        "c2",
        "shared-user",
        "shared-key",
        "shared-custom",
        "CN=shared",
    );
    let index = ConsumerIndex::new(&[c1, c2]);

    assert_eq!(index.find_by_api_key("shared-key").unwrap().id, "c2");
    assert_eq!(index.find_by_username("shared-user").unwrap().id, "c2");
    assert_eq!(index.find_by_identity("shared-custom").unwrap().id, "c2");
    assert_eq!(index.find_by_mtls_identity("CN=shared").unwrap().id, "c2");

    index.apply_delta(&[], &[NamespacedResourceId::new("ferrum", "c2")], &[]);

    assert_eq!(index.consumer_count(), 1);
    assert_eq!(index.find_by_api_key("shared-key").unwrap().id, "c1");
    assert_eq!(index.find_by_username("shared-user").unwrap().id, "c1");
    assert_eq!(index.find_by_identity("shared-custom").unwrap().id, "c1");
    assert_eq!(index.find_by_mtls_identity("CN=shared").unwrap().id, "c1");
    assert!(index.find_by_identity("c2").is_none());
}

#[test]
fn test_apply_delta_modify_collision_winner_restores_shadowed_consumer() {
    let c1 = make_consumer_with_colliding_credentials(
        "c1",
        "shared-user",
        "shared-key",
        "shared-custom",
        "CN=shared",
    );
    let c2 = make_consumer_with_colliding_credentials(
        "c2",
        "shared-user",
        "shared-key",
        "shared-custom",
        "CN=shared",
    );
    let index = ConsumerIndex::new(&[c1, c2]);

    let c2_modified = make_consumer_with_colliding_credentials(
        "c2",
        "unique-user",
        "unique-key",
        "unique-custom",
        "CN=unique",
    );
    index.apply_delta(&[], &[], &[c2_modified]);

    assert_eq!(index.consumer_count(), 2);
    assert_eq!(index.find_by_api_key("shared-key").unwrap().id, "c1");
    assert_eq!(index.find_by_username("shared-user").unwrap().id, "c1");
    assert_eq!(index.find_by_identity("shared-custom").unwrap().id, "c1");
    assert_eq!(index.find_by_mtls_identity("CN=shared").unwrap().id, "c1");
    assert_eq!(index.find_by_api_key("unique-key").unwrap().id, "c2");
    assert_eq!(index.find_by_username("unique-user").unwrap().id, "c2");
    assert_eq!(index.find_by_identity("unique-custom").unwrap().id, "c2");
    assert_eq!(index.find_by_mtls_identity("CN=unique").unwrap().id, "c2");
}

#[test]
fn test_custom_id_same_as_own_id_no_false_collision() {
    // A consumer's custom_id matches its own id — should not trigger identity collision
    let c = make_consumer("my-id", "alice", Some("key-a"), Some("my-id"));
    let index = ConsumerIndex::new(&[c]);

    let found = index.find_by_identity("my-id").unwrap();
    assert_eq!(found.username, "alice");
}

// ---- Multi-credential array format tests ----

#[test]
fn test_multi_keyauth_array_all_indexed() {
    // Consumer with 3 keyauth keys — all should be findable
    let c = make_consumer_with_array_keys("c1", "alice", &["key-1", "key-2", "key-3"]);
    let index = ConsumerIndex::new(&[c]);

    assert_eq!(index.find_by_api_key("key-1").unwrap().id, "c1");
    assert_eq!(index.find_by_api_key("key-2").unwrap().id, "c1");
    assert_eq!(index.find_by_api_key("key-3").unwrap().id, "c1");
    let (keyauth, _basic, _mtls, _jwt, _hmac, _identity, _total) = index.auth_type_counts();
    assert_eq!(keyauth, 3);
}

#[test]
fn test_multi_mtls_array_all_indexed() {
    // Consumer with multiple mTLS identities — all should be findable
    let c =
        make_consumer_with_array_mtls("c1", "svc", &["CN=old-cert", "CN=new-cert", "CN=staging"]);
    let index = ConsumerIndex::new(&[c]);

    assert_eq!(index.find_by_mtls_identity("CN=old-cert").unwrap().id, "c1");
    assert_eq!(index.find_by_mtls_identity("CN=new-cert").unwrap().id, "c1");
    assert_eq!(index.find_by_mtls_identity("CN=staging").unwrap().id, "c1");
    let (_keyauth, _basic, mtls, _jwt, _hmac, _identity, _total) = index.auth_type_counts();
    assert_eq!(mtls, 3);
}

#[test]
fn test_multi_jwt_array_credential_count() {
    // Consumer with multiple JWT secrets (rotation) — count reflects all entries
    let mut credentials = HashMap::new();
    credentials.insert(
        "jwt".to_string(),
        Value::Array(vec![
            serde_json::json!({"secret": "old-secret"}),
            serde_json::json!({"secret": "mid-secret"}),
            serde_json::json!({"secret": "new-secret"}),
        ]),
    );
    let c = Consumer {
        id: "c1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "jwt-rotator".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let index = ConsumerIndex::new(&[c]);

    let (_keyauth, _basic, _mtls, jwt, _hmac, _identity, _total) = index.auth_type_counts();
    assert_eq!(jwt, 3);
}

// ---- apply_delta: edge cases ----

#[test]
fn test_apply_delta_empty_is_noop() {
    let c1 = make_consumer("c1", "alice", Some("key-a"), None);
    let index = ConsumerIndex::new(&[c1]);

    // Empty delta should not change anything
    index.apply_delta(&[], &[], &[]);

    assert_eq!(index.consumer_count(), 1);
    assert!(index.find_by_api_key("key-a").is_some());
    assert!(index.find_by_username("alice").is_some());
}

#[test]
fn test_apply_delta_remove_nonexistent_consumer() {
    // Removing an ID that doesn't exist should be harmless
    let c1 = make_consumer("c1", "alice", Some("key-a"), None);
    let index = ConsumerIndex::new(&[c1]);

    index.apply_delta(
        &[],
        &[NamespacedResourceId::new("ferrum", "nonexistent-id")],
        &[],
    );

    assert_eq!(index.consumer_count(), 1);
    assert!(index.find_by_api_key("key-a").is_some());
}

#[test]
fn test_apply_delta_modify_single_to_array_credentials() {
    // Start with single keyauth, upgrade to array
    let c1 = make_consumer("c1", "alice", Some("key-single"), None);
    let index = ConsumerIndex::new(&[c1]);

    assert!(index.find_by_api_key("key-single").is_some());

    let c1_modified = make_consumer_with_array_keys("c1", "alice", &["key-new-1", "key-new-2"]);
    index.apply_delta(&[], &[], &[c1_modified]);

    assert!(
        index.find_by_api_key("key-single").is_none(),
        "Old single key removed"
    );
    assert!(index.find_by_api_key("key-new-1").is_some());
    assert!(index.find_by_api_key("key-new-2").is_some());
    assert_eq!(index.consumer_count(), 1);
}

#[test]
fn test_apply_delta_modify_mtls_credentials() {
    let c1 = make_consumer_with_array_mtls("c1", "alice", &["CN=old-cert"]);
    let index = ConsumerIndex::new(&[c1]);

    assert!(index.find_by_mtls_identity("CN=old-cert").is_some());

    let c1_modified = make_consumer_with_array_mtls("c1", "alice", &["CN=new-cert"]);
    index.apply_delta(&[], &[], &[c1_modified]);

    assert!(
        index.find_by_mtls_identity("CN=old-cert").is_none(),
        "Old mTLS identity removed"
    );
    assert!(index.find_by_mtls_identity("CN=new-cert").is_some());
}

#[test]
fn test_apply_delta_modify_custom_id() {
    let c1 = make_consumer("c1", "alice", Some("key-a"), Some("old-custom"));
    let index = ConsumerIndex::new(&[c1]);

    assert!(index.find_by_identity("old-custom").is_some());

    let c1_modified = make_consumer("c1", "alice", Some("key-a"), Some("new-custom"));
    index.apply_delta(&[], &[], &[c1_modified]);

    assert!(
        index.find_by_identity("old-custom").is_none(),
        "Old custom_id removed from identity index"
    );
    assert!(index.find_by_identity("new-custom").is_some());
    // id and username still findable
    assert!(index.find_by_identity("c1").is_some());
    assert!(index.find_by_identity("alice").is_some());
}

#[test]
fn test_apply_delta_add_collision_with_existing() {
    // Existing consumer has key-a; adding a new consumer with the same key
    let c1 = make_consumer("c1", "alice", Some("key-shared"), None);
    let index = ConsumerIndex::new(&[c1]);

    let c2 = make_consumer("c2", "bob", Some("key-shared"), None);
    index.apply_delta(&[c2], &[], &[]);

    // Both consumers exist in the full list
    assert_eq!(index.consumer_count(), 2);
    // The keyauth index stores last-write — c2 overwrites c1 for the shared key
    let found = index.find_by_api_key("key-shared").unwrap();
    assert_eq!(found.id, "c2");
}

#[test]
fn test_apply_delta_remove_all_consumers() {
    let c1 = make_consumer("c1", "alice", Some("key-a"), Some("custom-a"));
    let c2 = make_consumer("c2", "bob", Some("key-b"), None);
    let index = ConsumerIndex::new(&[c1, c2]);

    index.apply_delta(
        &[],
        &[
            NamespacedResourceId::new("ferrum", "c1"),
            NamespacedResourceId::new("ferrum", "c2"),
        ],
        &[],
    );

    assert_eq!(index.consumer_count(), 0);
    assert!(index.find_by_api_key("key-a").is_none());
    assert!(index.find_by_api_key("key-b").is_none());
    assert!(index.find_by_username("alice").is_none());
    assert!(index.find_by_identity("custom-a").is_none());
    assert!(index.consumers().is_empty());
}

#[test]
fn test_apply_delta_remove_consumer_with_mtls_cleans_mtls_index() {
    let c1 = make_consumer_with_array_mtls("c1", "alice", &["CN=cert-a", "CN=cert-b"]);
    let index = ConsumerIndex::new(&[c1]);

    assert!(index.find_by_mtls_identity("CN=cert-a").is_some());
    assert!(index.find_by_mtls_identity("CN=cert-b").is_some());

    index.apply_delta(&[], &[NamespacedResourceId::new("ferrum", "c1")], &[]);

    assert!(index.find_by_mtls_identity("CN=cert-a").is_none());
    assert!(index.find_by_mtls_identity("CN=cert-b").is_none());
    assert_eq!(index.consumer_count(), 0);
}

// ---- apply_delta: jwt/hmac count tracking ----

#[test]
fn test_apply_delta_add_jwt_consumer_updates_count() {
    let c1 = make_consumer("c1", "alice", Some("key-a"), None);
    let index = ConsumerIndex::new(&[c1]);

    let (_, _, _, jwt_before, _, _, _) = index.auth_type_counts();
    assert_eq!(jwt_before, 0);

    let c2 = make_consumer_with_jwt("c2", "bob");
    index.apply_delta(&[c2], &[], &[]);

    let (_, _, _, jwt_after, _, _, _) = index.auth_type_counts();
    assert_eq!(jwt_after, 1);
}

#[test]
fn test_apply_delta_remove_jwt_consumer_updates_count() {
    let c1 = make_consumer_with_jwt("c1", "alice");
    let c2 = make_consumer_with_jwt("c2", "bob");
    let index = ConsumerIndex::new(&[c1, c2]);

    let (_, _, _, jwt_before, _, _, _) = index.auth_type_counts();
    assert_eq!(jwt_before, 2);

    index.apply_delta(&[], &[NamespacedResourceId::new("ferrum", "c1")], &[]);

    let (_, _, _, jwt_after, _, _, _) = index.auth_type_counts();
    assert_eq!(jwt_after, 1);
}

#[test]
fn test_apply_delta_modify_hmac_consumer_updates_count() {
    // Start with hmac consumer, modify to add a second hmac entry
    let c1 = make_consumer_with_hmac("c1", "alice");
    let index = ConsumerIndex::new(&[c1]);

    let (_, _, _, _, hmac_before, _, _) = index.auth_type_counts();
    assert_eq!(hmac_before, 1);

    // Modify consumer to have 2 hmac entries
    let mut credentials = HashMap::new();
    credentials.insert(
        "hmac_auth".to_string(),
        Value::Array(vec![
            serde_json::json!({"secret": "old-hmac"}),
            serde_json::json!({"secret": "new-hmac"}),
        ]),
    );
    let c1_modified = Consumer {
        id: "c1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "alice".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    index.apply_delta(&[], &[], &[c1_modified]);

    let (_, _, _, _, hmac_after, _, _) = index.auth_type_counts();
    assert_eq!(hmac_after, 2);
}

// ---- Lookup after delta: comprehensive checks ----

#[test]
fn test_lookups_return_none_after_delta_remove() {
    let c1 = make_consumer("c1", "alice", Some("key-a"), Some("custom-a"));
    let index = ConsumerIndex::new(&[c1]);

    // Verify all lookups succeed before removal
    assert!(index.find_by_api_key("key-a").is_some());
    assert!(index.find_by_username("alice").is_some());
    assert!(index.find_by_identity("alice").is_some());
    assert!(index.find_by_identity("c1").is_some());
    assert!(index.find_by_identity("custom-a").is_some());

    index.apply_delta(&[], &[NamespacedResourceId::new("ferrum", "c1")], &[]);

    // All lookups must return None after removal
    assert!(index.find_by_api_key("key-a").is_none());
    assert!(index.find_by_username("alice").is_none());
    assert!(index.find_by_identity("alice").is_none());
    assert!(index.find_by_identity("c1").is_none());
    assert!(index.find_by_identity("custom-a").is_none());
}

#[test]
fn test_find_by_mtls_identity_returns_none_for_unknown() {
    let c = make_consumer_with_array_mtls("c1", "alice", &["CN=known"]);
    let index = ConsumerIndex::new(&[c]);

    assert!(index.find_by_mtls_identity("CN=unknown").is_none());
}

// ---- Consumer with no credentials at all ----

#[test]
fn test_consumer_with_empty_credentials() {
    let c = Consumer {
        id: "c1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "bare-user".to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let index = ConsumerIndex::new(&[c]);

    // No credential lookups work
    assert!(index.find_by_api_key("anything").is_none());
    assert!(index.find_by_username("bare-user").is_none()); // no basicauth
    assert!(index.find_by_mtls_identity("anything").is_none());
    // But identity index is still populated
    assert!(index.find_by_identity("bare-user").is_some());
    assert!(index.find_by_identity("c1").is_some());
    assert_eq!(index.consumer_count(), 1);
}

// ---- rebuild clears all indexes ----

#[test]
fn test_rebuild_clears_mtls_and_all_indexes() {
    let c1 = make_consumer_with_array_mtls("c1", "alice", &["CN=old"]);
    let index = ConsumerIndex::new(&[c1]);

    assert!(index.find_by_mtls_identity("CN=old").is_some());

    // Rebuild with completely different consumer
    let c2 = make_consumer("c2", "bob", Some("key-b"), None);
    index.rebuild(&[c2]);

    assert!(index.find_by_mtls_identity("CN=old").is_none());
    assert!(index.find_by_identity("alice").is_none());
    assert!(index.find_by_api_key("key-b").is_some());
    assert_eq!(index.consumer_count(), 1);
}

#[test]
fn test_rebuild_to_empty_clears_everything() {
    let c1 = make_consumer("c1", "alice", Some("key-a"), Some("custom-a"));
    let c2 = make_consumer_with_array_mtls("c2", "bob", &["CN=bob"]);
    let index = ConsumerIndex::new(&[c1, c2]);

    assert_eq!(index.consumer_count(), 2);

    index.rebuild(&[]);

    assert_eq!(index.consumer_count(), 0);
    assert_eq!(index.index_len(), 0);
    assert!(index.consumers().is_empty());
    let (keyauth, basic, mtls, jwt, hmac, identity, total) = index.auth_type_counts();
    assert_eq!(keyauth, 0);
    assert_eq!(basic, 0);
    assert_eq!(mtls, 0);
    assert_eq!(jwt, 0);
    assert_eq!(hmac, 0);
    assert_eq!(identity, 0);
    assert_eq!(total, 0);
}

// ---- Credential with non-object array elements (filtered out) ----

#[test]
fn test_non_object_array_elements_filtered_out() {
    // credential_entries filters non-object elements; keyauth with mixed types
    let mut credentials = HashMap::new();
    credentials.insert(
        "keyauth".to_string(),
        Value::Array(vec![
            serde_json::json!({"key": "valid-key"}),
            Value::String("not-an-object".to_string()), // filtered out
            Value::Null,                                // filtered out
        ]),
    );
    let c = Consumer {
        id: "c1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "alice".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let index = ConsumerIndex::new(&[c]);

    assert!(index.find_by_api_key("valid-key").is_some());
    let (keyauth, _, _, _, _, _, _) = index.auth_type_counts();
    assert_eq!(keyauth, 1); // only the valid object entry
}

// ---- Sequential delta operations ----

#[test]
fn test_sequential_deltas_accumulate() {
    let index = ConsumerIndex::new(&[]);

    // First delta: add c1
    let c1 = make_consumer("c1", "alice", Some("key-a"), None);
    index.apply_delta(&[c1], &[], &[]);
    assert_eq!(index.consumer_count(), 1);

    // Second delta: add c2
    let c2 = make_consumer("c2", "bob", Some("key-b"), None);
    index.apply_delta(&[c2], &[], &[]);
    assert_eq!(index.consumer_count(), 2);

    // Third delta: modify c1, remove c2
    let c1_modified = make_consumer("c1", "alice", Some("key-a-new"), None);
    index.apply_delta(
        &[],
        &[NamespacedResourceId::new("ferrum", "c2")],
        &[c1_modified],
    );
    assert_eq!(index.consumer_count(), 1);
    assert!(index.find_by_api_key("key-a").is_none());
    assert!(index.find_by_api_key("key-a-new").is_some());
    assert!(index.find_by_api_key("key-b").is_none());
}

// ---- Keyauth entry with missing "key" field ----

#[test]
fn test_keyauth_entry_missing_key_field_not_indexed() {
    let mut credentials = HashMap::new();
    // keyauth entry without "key" field — should be silently ignored
    let mut creds = Map::new();
    creds.insert(
        "description".to_string(),
        Value::String("no key here".to_string()),
    );
    credentials.insert(
        "keyauth".to_string(),
        Value::Array(vec![Value::Object(creds)]),
    );
    let c = Consumer {
        id: "c1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "alice".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let index = ConsumerIndex::new(&[c]);

    let (keyauth, _, _, _, _, _, _) = index.auth_type_counts();
    assert_eq!(
        keyauth, 0,
        "Entry without 'key' field should not be indexed"
    );
    assert_eq!(index.consumer_count(), 1);
}

#[test]
fn test_mtls_entry_missing_identity_field_not_indexed() {
    let mut credentials = HashMap::new();
    // mtls_auth entry without "identity" field — should be silently ignored
    let mut creds = Map::new();
    creds.insert(
        "description".to_string(),
        Value::String("no identity".to_string()),
    );
    credentials.insert(
        "mtls_auth".to_string(),
        Value::Array(vec![Value::Object(creds)]),
    );
    let c = Consumer {
        id: "c1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "alice".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let index = ConsumerIndex::new(&[c]);

    let (_, _, mtls, _, _, _, _) = index.auth_type_counts();
    assert_eq!(
        mtls, 0,
        "Entry without 'identity' field should not be in mtls index"
    );
}
