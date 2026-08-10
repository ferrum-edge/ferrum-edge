//! Tests for JWKS key store module

use ferrum_edge::plugins::utils::PluginHttpClient;
use ferrum_edge::plugins::utils::jwks_store::{
    JwksFailureClass, JwksKeyStore, JwksTrustState, redacted_jwks_uri,
};
use serde_json::json;
use std::time::Duration;

fn has_trusted_key(store: &JwksKeyStore, kid: &str) -> bool {
    store
        .trusted_keys()
        .is_some_and(|keys| keys.contains_key(kid))
}

#[test]
fn test_empty_store_has_no_keys() {
    let store = JwksKeyStore::new(
        "https://example.com/.well-known/jwks.json".to_string(),
        PluginHttpClient::default(),
    );
    assert!(!store.has_keys());
    assert!(!has_trusted_key(&store, "nonexistent"));
}

#[test]
fn test_jwks_uri_accessor() {
    let uri = "https://auth.example.com/.well-known/jwks.json";
    let store = JwksKeyStore::new(uri.to_string(), PluginHttpClient::default());
    assert_eq!(store.jwks_uri(), uri);
}

#[test]
fn test_trusted_keys_returns_none_initially() {
    let store = JwksKeyStore::new(
        "https://example.com/.well-known/jwks.json".to_string(),
        PluginHttpClient::default(),
    );
    let all = store.trusted_keys();
    assert!(all.is_none());
}

#[test]
fn test_trusted_keys_rejects_various_kid_values_in_empty_store() {
    let store = JwksKeyStore::new(
        "https://example.com/.well-known/jwks.json".to_string(),
        PluginHttpClient::default(),
    );

    // Various kid patterns should all return None on empty store
    assert!(!has_trusted_key(&store, ""));
    assert!(!has_trusted_key(&store, "kid-123"));
    assert!(!has_trusted_key(&store, "abc-def-ghi"));
    assert!(!has_trusted_key(&store, "a".repeat(256).as_str()));
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

#[test]
fn jwks_uri_redaction_removes_credentials_query_and_path() {
    let redacted = redacted_jwks_uri(
        "https://alice:super-secret@keys.example.com/private/jwks?signature=credential#fragment",
    );
    assert_eq!(redacted, "https://keys.example.com/");
    for secret in [
        "alice",
        "super-secret",
        "private",
        "signature",
        "credential",
    ] {
        assert!(!redacted.contains(secret));
    }
}

#[test]
fn jwk_key_ops_must_authorize_signature_verification() {
    let jwks = |key_use: Option<&str>, key_ops: Option<serde_json::Value>| {
        let mut key = json!({
            "kty": "RSA",
            "kid": "k1",
            "alg": "RS256",
            "n": "AQAB",
            "e": "AQAB"
        });
        if let Some(key_use) = key_use {
            key["use"] = json!(key_use);
        }
        if let Some(key_ops) = key_ops {
            key["key_ops"] = key_ops;
        }
        json!({"keys": [key]}).to_string()
    };

    for accepted in [
        jwks(None, None),
        jwks(None, Some(json!(["verify"]))),
        jwks(Some("sig"), None),
        jwks(Some("sig"), Some(json!(["verify"]))),
    ] {
        let store = JwksKeyStore::from_inline_jwks(&accepted)
            .expect("verification-capable key should be accepted");
        assert!(has_trusted_key(&store, "k1"));
    }

    for rejected in [
        jwks(None, Some(json!([]))),
        jwks(None, Some(json!(["encrypt"]))),
        jwks(Some("enc"), None),
        jwks(Some("enc"), Some(json!(["verify"]))),
        jwks(Some("sig"), Some(json!(["verify", "encrypt"]))),
    ] {
        assert!(
            JwksKeyStore::from_inline_jwks(&rejected).is_err(),
            "non-verification or contradictory key_ops must fail closed"
        );
    }
}

#[test]
fn oversized_jwk_component_is_rejected() {
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "k1",
            "use": "sig",
            "alg": "RS256",
            "n": "A".repeat(16 * 1024 + 1),
            "e": "AQAB"
        }]
    })
    .to_string();

    assert!(JwksKeyStore::from_inline_jwks(&jwks).is_err());
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

/// An empty 200 retains diagnostic/recovery keys only inside the configured
/// grace window, then fails closed without deleting them. A later valid set
/// atomically restores trust without a restart.
#[tokio::test]
async fn empty_fetch_expires_bounded_trust_and_valid_recovery_restores_it() {
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
    store.configure_trust_policy(Duration::from_millis(100), Duration::from_secs(1));

    // First fetch populates the cache.
    let count = store
        .fetch_keys()
        .await
        .expect("first fetch should succeed");
    assert_eq!(count, 1);
    assert!(store.has_keys());
    assert!(has_trusted_key(&store, "k1"));

    // Second fetch returns zero keys. It is a failed refresh and cannot move
    // the trust deadline, while the retained key remains usable during grace.
    let error = store
        .fetch_keys()
        .await
        .expect_err("empty fetch must be a failed trust refresh");
    assert!(error.contains("empty"));
    assert_eq!(store.health_snapshot().trust_state, JwksTrustState::Grace);
    assert!(
        store.has_keys(),
        "an empty 200 must not delete diagnostic/recovery state"
    );
    assert!(
        has_trusted_key(&store, "k1"),
        "the previously cached key remains trusted only during grace"
    );
    assert!(
        store.fetch_keys().await.is_err(),
        "a repeated empty 200 must remain a failed refresh"
    );

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let expired = store.health_snapshot();
    assert_eq!(expired.trust_state, JwksTrustState::Expired);
    assert_eq!(expired.last_failure, Some(JwksFailureClass::Empty));
    assert_eq!(expired.consecutive_failures, 2);
    assert!(
        store.has_keys(),
        "expiry must preserve retained recovery state"
    );
    assert!(
        !has_trusted_key(&store, "k1"),
        "expired keys must not verify"
    );

    server.reset().await;
    let recovered = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "k2",
            "use": "sig",
            "alg": "RS256",
            "n": "AQAB",
            "e": "AQAB"
        }]
    });
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(recovered))
        .mount(&server)
        .await;
    assert_eq!(store.fetch_keys().await.expect("valid recovery fetch"), 1);
    assert_eq!(store.health_snapshot().trust_state, JwksTrustState::Fresh);
    assert!(!has_trusted_key(&store, "k1"));
    assert!(has_trusted_key(&store, "k2"));
}

/// An initially-empty store treats an empty 200 as a failed refresh so the
/// background worker uses accelerated bounded retry.
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

    let error = store
        .fetch_keys()
        .await
        .expect_err("empty fetch must not count as a key-trust success");
    assert!(error.contains("empty"));
    assert!(!store.has_keys());
    assert_eq!(store.health_snapshot().trust_state, JwksTrustState::Expired);
}

#[tokio::test]
async fn test_oversized_jwks_response_is_rejected_without_populating_store() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_bytes(vec![b' '; 1024 * 1024 + 1]),
        )
        .mount(&server)
        .await;
    let store = JwksKeyStore::new(
        format!("{}/jwks", server.uri()),
        PluginHttpClient::default(),
    );

    let error = store
        .fetch_keys()
        .await
        .expect_err("oversized JWKS must be rejected");
    assert!(error.contains("oversized"));
    assert!(!store.has_keys());
    assert_eq!(
        store.health_snapshot().last_failure,
        Some(JwksFailureClass::Oversized)
    );
}

#[tokio::test]
async fn non_success_and_malformed_responses_record_bounded_failure_classes() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let store = JwksKeyStore::new(
        format!("{}/jwks", server.uri()),
        PluginHttpClient::default(),
    );

    assert!(store.fetch_keys().await.is_err());
    assert_eq!(
        store.health_snapshot().last_failure,
        Some(JwksFailureClass::HttpStatus)
    );

    server.reset().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;
    assert!(store.fetch_keys().await.is_err());
    let health = store.health_snapshot();
    assert_eq!(health.last_failure, Some(JwksFailureClass::Malformed));
    assert_eq!(health.consecutive_failures, 2);
}

#[tokio::test]
async fn test_oversized_refresh_retains_last_known_good_keys() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(populated_rsa_jwks()))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_bytes(vec![b' '; 1024 * 1024 + 1]),
        )
        .with_priority(2)
        .mount(&server)
        .await;
    let store = JwksKeyStore::new(
        format!("{}/jwks", server.uri()),
        PluginHttpClient::default(),
    );

    assert_eq!(store.fetch_keys().await.expect("initial fetch"), 1);
    assert!(store.fetch_keys().await.is_err());
    assert!(has_trusted_key(&store, "k1"));
}
