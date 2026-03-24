//! Tests for JWKS key store module

use ferrum_gateway::plugins::jwks_store::JwksKeyStore;
use ferrum_gateway::plugins::utils::PluginHttpClient;

#[test]
fn test_empty_store_has_no_keys() {
    let store = JwksKeyStore::new(
        "https://example.com/.well-known/jwks.json".to_string(),
        PluginHttpClient::default(),
    );
    assert!(!store.has_keys());
    assert!(store.get_key("nonexistent").is_none());
}
