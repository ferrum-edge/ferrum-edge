//! Tests for ConsumerIndex — credential-indexed consumer lookup

use chrono::Utc;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::Consumer;
use serde_json::{Map, Value};
use std::collections::HashMap;

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
        credentials.insert("keyauth".to_string(), Value::Object(keyauth_creds));
    }

    let mut basicauth_creds = Map::new();
    basicauth_creds.insert(
        "password_hash".to_string(),
        Value::String("$2b$12$placeholder".to_string()),
    );
    credentials.insert("basicauth".to_string(), Value::Object(basicauth_creds));

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
    credentials.insert("basicauth".to_string(), Value::Object(basicauth_creds));

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

    index.apply_delta(&[], &["c1".to_string()], &[]);

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

    index.apply_delta(&[c4], &["c1".to_string()], &[c2_modified]);

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

    index.apply_delta(&[], &["c1".to_string()], &[]);

    assert!(index.find_by_api_key("key-a1").is_none());
    assert!(index.find_by_api_key("key-a2").is_none());
    assert_eq!(index.consumer_count(), 0);
}

#[test]
fn test_mixed_single_and_array_credentials() {
    // c1 uses array format, c2 uses single-object format
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
    credentials.insert("jwt".to_string(), Value::Object(jwt_creds));

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
    credentials.insert("hmac_auth".to_string(), Value::Object(hmac_creds));

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
