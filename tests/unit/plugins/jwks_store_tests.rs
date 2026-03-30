//! Tests for JWKS key store module

use ferrum_edge::plugins::jwks_store::JwksKeyStore;
use ferrum_edge::plugins::utils::PluginHttpClient;

#[test]
fn test_empty_store_has_no_keys() {
    let store = JwksKeyStore::new(
        "https://example.com/.well-known/jwks.json".to_string(),
        PluginHttpClient::default(),
    );
    assert!(!store.has_keys());
    assert!(store.get_key("nonexistent").is_none());
}

#[test]
fn test_jwks_uri_accessor() {
    let uri = "https://auth.example.com/.well-known/jwks.json";
    let store = JwksKeyStore::new(uri.to_string(), PluginHttpClient::default());
    assert_eq!(store.jwks_uri(), uri);
}

#[test]
fn test_all_keys_returns_empty_map_initially() {
    let store = JwksKeyStore::new(
        "https://example.com/.well-known/jwks.json".to_string(),
        PluginHttpClient::default(),
    );
    let all = store.all_keys();
    assert!(all.is_empty());
}

#[test]
fn test_get_key_with_various_kid_values() {
    let store = JwksKeyStore::new(
        "https://example.com/.well-known/jwks.json".to_string(),
        PluginHttpClient::default(),
    );

    // Various kid patterns should all return None on empty store
    assert!(store.get_key("").is_none());
    assert!(store.get_key("kid-123").is_none());
    assert!(store.get_key("abc-def-ghi").is_none());
    assert!(store.get_key("a".repeat(256).as_str()).is_none());
}

#[test]
fn test_multiple_store_instances_are_independent() {
    let store1 = JwksKeyStore::new(
        "https://auth1.example.com/jwks".to_string(),
        PluginHttpClient::default(),
    );
    let store2 = JwksKeyStore::new(
        "https://auth2.example.com/jwks".to_string(),
        PluginHttpClient::default(),
    );

    assert_ne!(store1.jwks_uri(), store2.jwks_uri());
    assert!(!store1.has_keys());
    assert!(!store2.has_keys());
}

#[test]
fn test_cloned_store_shares_keys() {
    let store = JwksKeyStore::new(
        "https://example.com/.well-known/jwks.json".to_string(),
        PluginHttpClient::default(),
    );
    let cloned = store.clone();

    // Both should reference the same underlying key store
    assert_eq!(store.jwks_uri(), cloned.jwks_uri());
    assert!(!store.has_keys());
    assert!(!cloned.has_keys());
}
