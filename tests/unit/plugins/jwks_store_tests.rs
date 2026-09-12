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
        // Start from the 2048-bit fixture so the modulus floor is not what
        // decides these cases; `use` is re-applied per case below.
        let mut fixture = rsa_jwks_with_kid(
            include_bytes!("../../../tests/fixtures/test_rsa_public.pem"),
            "k1",
        );
        let mut key = fixture["keys"][0].take();
        key.as_object_mut().expect("JWK object").remove("use");
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

#[test]
fn jwks_requires_unique_non_empty_key_identifiers() {
    let key = |kid: Option<&str>| {
        let mut key = json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": "AQAB",
            "e": "AQAB"
        });
        if let Some(kid) = kid {
            key["kid"] = json!(kid);
        }
        key
    };

    for rejected in [
        json!({"keys": [key(None)]}),
        json!({"keys": [key(Some(""))]}),
        json!({"keys": [key(Some("duplicate")), key(Some("duplicate"))]}),
    ] {
        assert!(
            JwksKeyStore::from_inline_jwks(&rejected.to_string()).is_err(),
            "unaddressable or ambiguous signing keys must fail closed"
        );
    }
}

/// A minimal but well-formed RSA JWKS with one signing key.
///
/// A JWKS carrying the 2048-bit fixture key under `kid` `k1`: the store now
/// applies the RSA modulus floor at load time, so a placeholder modulus would
/// be discarded as unusable instead of populating the cache.
fn populated_rsa_jwks() -> serde_json::Value {
    rsa_jwks_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public.pem"),
        "k1",
    )
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
    let recovered = rsa_jwks_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public_other.pem"),
        "k2",
    );
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

// ─── Unknown-`kid` on-demand refetch (issue #4508) ──────────────────────────

fn rsa_jwks_with_kid(public_key_pem: &[u8], kid: &str) -> serde_json::Value {
    super::jwks_auth_support::build_rsa_jwks_from_pem_with_kid(public_key_pem, kid)
}

/// Serve `first` once, then `second` for every later fetch.
async fn rotating_jwks_server(
    first: serde_json::Value,
    second: serde_json::Value,
) -> wiremock::MockServer {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(first))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(second))
        .with_priority(2)
        .mount(&server)
        .await;
    server
}

async fn received_requests(server: &wiremock::MockServer) -> usize {
    server
        .received_requests()
        .await
        .map(|requests| requests.len())
        .unwrap_or(0)
}

/// The background refresh task selects on the unknown-`kid` trigger, so a
/// rotated signing key becomes trusted without waiting out the refresh
/// interval. The interval here is an hour: only the on-demand path can
/// produce the second fetch.
#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn unknown_kid_trigger_refetches_before_the_refresh_interval_elapses() {
    let v1 = rsa_jwks_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public.pem"),
        "key-v1",
    );
    let v2 = rsa_jwks_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public_other.pem"),
        "key-v2",
    );
    let server = rotating_jwks_server(v1, v2).await;

    let store = JwksKeyStore::new(
        format!("{}/jwks", server.uri()),
        PluginHttpClient::default(),
    );
    let interval = Duration::from_secs(3_600);
    store.configure_trust_policy(interval, Duration::from_secs(3_600));
    store.configure_kid_miss_cooldown(Duration::from_secs(30));
    let refresh = store.start_background_refresh(interval);

    // The task's own first pass publishes v1.
    while !has_trusted_key(&store, "key-v1") {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!has_trusted_key(&store, "key-v2"));

    let before = store.refresh_completions();
    store.request_refresh_on_kid_miss();
    assert_eq!(store.kid_miss_refresh_requests(), 1);
    store.wait_for_refresh_completion_after(before).await;

    assert!(
        has_trusted_key(&store, "key-v2"),
        "the rotated key must be trusted without advancing the refresh interval"
    );
    refresh.abort();
}

/// A flood of tokens naming random unknown identifiers is bounded to one
/// upstream fetch per cooldown window.
#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn unknown_kid_triggers_are_bounded_to_one_fetch_per_cooldown_window() {
    let v1 = rsa_jwks_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public.pem"),
        "key-v1",
    );
    let v2 = rsa_jwks_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public_other.pem"),
        "key-v2",
    );
    let server = rotating_jwks_server(v1, v2).await;

    let store = JwksKeyStore::new(
        format!("{}/jwks", server.uri()),
        PluginHttpClient::default(),
    );
    let interval = Duration::from_secs(3_600);
    store.configure_trust_policy(interval, Duration::from_secs(3_600));
    store.configure_kid_miss_cooldown(Duration::from_secs(600));
    let refresh = store.start_background_refresh(interval);

    while !has_trusted_key(&store, "key-v1") {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let after_startup = received_requests(&server).await;

    let before = store.refresh_completions();
    for _ in 0..64 {
        store.request_refresh_on_kid_miss();
    }
    assert_eq!(
        store.kid_miss_refresh_requests(),
        1,
        "the cooldown must admit exactly one trigger per window"
    );
    store.wait_for_refresh_completion_after(before).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        received_requests(&server).await,
        after_startup + 1,
        "64 unknown identifiers inside one cooldown window must cost one fetch"
    );
    refresh.abort();
}

/// A zero cooldown disables the on-demand refetch entirely.
#[tokio::test]
async fn zero_cooldown_disables_the_unknown_kid_refetch() {
    let store = JwksKeyStore::new(
        "https://idp.example.com/jwks".to_string(),
        PluginHttpClient::default(),
    );
    store.configure_kid_miss_cooldown(Duration::ZERO);
    for _ in 0..8 {
        store.request_refresh_on_kid_miss();
    }
    assert_eq!(store.kid_miss_refresh_requests(), 0);
}

/// An inline store has nothing to refetch; the trigger is inert.
#[tokio::test]
async fn inline_store_never_admits_an_unknown_kid_refetch() {
    let jwks = rsa_jwks_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public.pem"),
        "key-v1",
    );
    let store = JwksKeyStore::from_inline_jwks(&jwks.to_string()).expect("inline JWKS");
    store.request_refresh_on_kid_miss();
    assert_eq!(store.kid_miss_refresh_requests(), 0);
    assert_eq!(store.kid_miss_cooldown(), Duration::ZERO);
}

/// An on-demand fetch is out of band: it never pulls the periodic refresh
/// into a tighter loop.
#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn an_on_demand_fetch_does_not_shorten_the_periodic_schedule() {
    let jwks = rsa_jwks_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public.pem"),
        "key-v1",
    );
    let server = rotating_jwks_server(jwks.clone(), jwks).await;
    let store = JwksKeyStore::new(
        format!("{}/jwks", server.uri()),
        PluginHttpClient::default(),
    );
    let interval = Duration::from_secs(3_600);
    store.configure_trust_policy(interval, Duration::from_secs(3_600));
    store.configure_kid_miss_cooldown(Duration::from_millis(1));
    let refresh = store.start_background_refresh(interval);

    while !has_trusted_key(&store, "key-v1") {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let after_startup = received_requests(&server).await;

    let before = store.refresh_completions();
    store.request_refresh_on_kid_miss();
    store.wait_for_refresh_completion_after(before).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        received_requests(&server).await,
        after_startup + 1,
        "the periodic deadline must survive an out-of-band fetch unchanged"
    );
    refresh.abort();
}

// ─── JWK `alg` is honoured per RFC 7517 §4.4 ────────────────────────────────

/// Before this, every unrecognized `alg` fell back to `Algorithm::RS256`, so a
/// key an issuer published for RSA-OAEP / RSA1_5 encryption — or for RSASSA-PSS
/// — became a PKCS#1 v1.5 signature-verification key. `use`/`key_ops` did not
/// catch it: a JWK may omit both.
#[test]
fn rsa_jwk_alg_must_name_a_supported_signature_algorithm() {
    let jwks = |alg: Option<&str>| {
        let mut fixture = rsa_jwks_with_kid(
            include_bytes!("../../../tests/fixtures/test_rsa_public.pem"),
            "k1",
        );
        let mut key = fixture["keys"][0].take();
        key.as_object_mut().expect("JWK object").remove("alg");
        if let Some(alg) = alg {
            key["alg"] = json!(alg);
        }
        json!({"keys": [key]}).to_string()
    };

    for accepted in [
        jwks(None),
        jwks(Some("RS256")),
        jwks(Some("RS384")),
        jwks(Some("RS512")),
    ] {
        let store = JwksKeyStore::from_inline_jwks(&accepted)
            .expect("absent or RSA signature alg should be accepted");
        assert!(has_trusted_key(&store, "k1"));
    }

    for rejected in [
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA1_5",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "HS256",
        "none",
        "not-an-algorithm",
    ] {
        assert!(
            JwksKeyStore::from_inline_jwks(&jwks(Some(rejected))).is_err(),
            "JWK alg {rejected} must not become an RS256 verification key"
        );
    }
}

/// The EC path ignored an `alg` it did not recognize and kept the curve-derived
/// algorithm, so a key published for key agreement (`ECDH-ES`) or one whose
/// `alg` contradicted its `crv` was still admitted for signature verification.
#[test]
fn ec_jwk_alg_must_agree_with_the_curve_and_name_a_signature_algorithm() {
    let jwks = |crv: &str, alg: Option<&str>, coordinate_len: usize| {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let coordinate = URL_SAFE_NO_PAD.encode(vec![7u8; coordinate_len]);
        let mut key = json!({
            "kty": "EC",
            "kid": "k1",
            "crv": crv,
            "x": coordinate,
            "y": coordinate
        });
        if let Some(alg) = alg {
            key["alg"] = json!(alg);
        }
        json!({"keys": [key]}).to_string()
    };

    for (crv, alg, len) in [
        ("P-256", None, 32),
        ("P-256", Some("ES256"), 32),
        ("P-384", None, 48),
        ("P-384", Some("ES384"), 48),
    ] {
        let store = JwksKeyStore::from_inline_jwks(&jwks(crv, alg, len))
            .expect("an alg that agrees with the curve should be accepted");
        assert!(has_trusted_key(&store, "k1"));
    }

    for (crv, alg, len) in [
        ("P-256", Some("ES384"), 32),
        ("P-384", Some("ES256"), 48),
        ("P-256", Some("ECDH-ES"), 32),
        ("P-256", Some("RS256"), 32),
        ("P-256", Some("ES512"), 32),
    ] {
        assert!(
            JwksKeyStore::from_inline_jwks(&jwks(crv, alg, len)).is_err(),
            "EC JWK alg {alg:?} on {crv} must not become a verification key"
        );
    }
}
