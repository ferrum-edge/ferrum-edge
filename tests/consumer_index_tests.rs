//! Tests for ConsumerIndex — credential-indexed consumer lookup

use chrono::Utc;
use ferrum_gateway::config::types::Consumer;
use ferrum_gateway::ConsumerIndex;
use serde_json::{Map, Value};
use std::collections::HashMap;

fn make_consumer(id: &str, username: &str, api_key: Option<&str>, custom_id: Option<&str>) -> Consumer {
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
        username: username.to_string(),
        custom_id: custom_id.map(|s| s.to_string()),
        credentials,
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
    assert_eq!(index.find_by_identity("custom-c").unwrap().username, "carol");
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
        username: "nokey".to_string(),
        custom_id: None,
        credentials,
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
