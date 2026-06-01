//! Tests for JWKS key store module

use ferrum_edge::plugins::utils::PluginHttpClient;
use ferrum_edge::plugins::utils::jwks_store::JwksKeyStore;
use serde_json::json;

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

/// A minimal but well-formed RSA JWKS with one signing key.
///
/// `DecodingKey::from_rsa_raw_components` stores the components without
/// validating the modulus, so any valid base64url `n`/`e` yields a cached key —
/// sufficient to populate the store for cache-retention assertions.
fn populated_rsa_jwks() -> serde_json::Value {
    json!({
        "keys": [{
            "kty": "RSA",
            "kid": "k1",
            "use": "sig",
            "alg": "RS256",
            "n": "AQAB",
            "e": "AQAB"
        }]
    })
}

/// An authoritative successful JWKS fetch that returns zero keys must clear a
/// previously-populated cache. Operators and IdPs can intentionally publish an
/// empty JWKS to revoke all signing keys after compromise; retaining old keys
/// would keep revoked tokens or keys trusted until process restart.
#[tokio::test]
async fn test_empty_fetch_clears_last_known_good_keys() {
    let server = wiremock::MockServer::start().await;

    // Priority 1 (highest), exhausted after a single hit: serves the populated
    // JWKS for the first fetch only.
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(populated_rsa_jwks()))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;

    // Priority 2 fallback: every subsequent fetch returns an empty key set.
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({ "keys": [] })))
        .with_priority(2)
        .mount(&server)
        .await;

    let store = JwksKeyStore::new(
        format!("{}/jwks", server.uri()),
        PluginHttpClient::default(),
    );

    // First fetch populates the cache.
    let count = store
        .fetch_keys()
        .await
        .expect("first fetch should succeed");
    assert_eq!(count, 1);
    assert!(store.has_keys());
    assert!(store.get_key("k1").is_some());

    // Second fetch returns zero keys; the cache must be cleared so revoked
    // signing keys are no longer accepted.
    let count = store
        .fetch_keys()
        .await
        .expect("empty fetch should succeed without error");
    assert_eq!(count, 0, "empty fetch must report the new empty key count");
    assert!(
        !store.has_keys(),
        "an authoritative empty 200 must discard last-known-good keys"
    );
    assert!(
        store.get_key("k1").is_none(),
        "the previously cached key must no longer be present"
    );
}

/// An initially-empty store that receives an empty fetch stays empty and does
/// not error — initial population is still allowed to observe a legitimately
/// empty JWKS.
#[tokio::test]
async fn test_empty_fetch_on_empty_store_stays_empty() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({ "keys": [] })))
        .mount(&server)
        .await;

    let store = JwksKeyStore::new(
        format!("{}/jwks", server.uri()),
        PluginHttpClient::default(),
    );

    let count = store
        .fetch_keys()
        .await
        .expect("empty fetch should succeed");
    assert_eq!(count, 0);
    assert!(!store.has_keys());
}
