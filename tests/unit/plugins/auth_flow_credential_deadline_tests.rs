//! Infallible JSON-`exp` credential deadlines (issue #5420).
//!
//! `credential_deadline_from_unix_seconds` used to fold BOTH
//! `CredentialDeadline::Unbounded` and `::Invalid` onto `now`, so an `exp`
//! further out than this platform's monotonic `Instant` can express arrived at
//! `observe_credential_deadline` as a credential that had already expired —
//! even though the JWT layer had just validated it as live. It now mirrors the
//! certificate contract issue #5396 established: unbounded publishes NO
//! deadline, an unusable interval still fails closed.
//!
//! Where the monotonic clock runs out is platform dependent by construction, so
//! the boundary cases are driven through the `_test_support` conversion hooks
//! with an injected `now_mono` anchored at the platform maximum — that is the
//! only way to reach the unbounded branch deterministically on a
//! `timespec`-backed `Instant`, which holds `i64` seconds and therefore
//! represents even an `i64::MAX` expiry.
//!
//! The two claim-driven plugins are then exercised end to end against the
//! property that actually matters and holds on either clock: the far-future
//! credential is ADMITTED, with either no deadline or one far beyond any real
//! session, never one that already elapsed.

use ferrum_edge::_test_support::{
    credential_deadline_from_claims_at_for_test, credential_deadline_from_unix_seconds_at_for_test,
    request_credential_deadline_at,
};
use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, RequestContext, jwks_auth::JwksAuth, jwt_auth::JwtAuth};
use serde_json::json;
use std::time::Duration;

use super::jwks_auth_support::{build_rsa_jwks_from_pem, create_rs256_token_exact, default_client};
use super::plugin_utils::{
    assert_continue, assert_no_effective_credential_deadline, create_test_consumer,
};

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn create_hs256_token(claims: &serde_json::Value, secret: &str) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

/// The largest monotonic instant reachable from `now` by adding whole seconds.
///
/// `std` exposes no `Instant::MAX` and the maximum is platform dependent, so it
/// is found by a bounded binary search rather than hard-coded. Mirrors the
/// helper in `mtls_auth_certificate_lifetime_tests`, which compiles into the
/// other plugin test target.
fn largest_representable_instant(now: tokio::time::Instant) -> tokio::time::Instant {
    let (mut lo, mut hi) = (0_u64, u64::MAX);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if now.checked_add(Duration::from_secs(mid)).is_some() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    now.checked_add(Duration::from_secs(lo))
        .expect("the search settles on a representable offset")
}

#[test]
fn a_representable_expiry_keeps_its_exact_bound() {
    let now = tokio::time::Instant::now();
    assert_eq!(
        credential_deadline_from_unix_seconds_at_for_test(1_060, 0, 1_000, now),
        Some(now + Duration::from_secs(60))
    );
    assert_eq!(
        credential_deadline_from_unix_seconds_at_for_test(1_000, 60, 1_000, now),
        Some(now + Duration::from_secs(60)),
        "the validation leeway is part of the validated expiry, as before"
    );
    assert_eq!(
        credential_deadline_from_unix_seconds_at_for_test(1_000, 0, 1_000, now),
        Some(now),
        "a zero-remaining window is still a bound at the anchor, not an absent one"
    );
}

#[test]
fn an_expiry_beyond_the_representable_range_publishes_no_deadline() {
    // Issue #5420: this is the case that used to arrive as `now`, i.e. as an
    // already-expired credential the JWT layer had just validated as live.
    //
    // WHICH far-future expiry outruns the clock is platform dependent, so the
    // two reasons are separated. `exp + leeway` overflowing is pure `i64`
    // arithmetic and holds everywhere; the monotonic range running out is
    // anchored at the platform maximum so it holds everywhere too, rather than
    // only on a clock narrow enough to saturate on its own.
    let now = tokio::time::Instant::now();
    assert_eq!(
        credential_deadline_from_unix_seconds_at_for_test(i64::MAX, 1, 1_000, now),
        None,
        "an overflowing expiry+leeway is far future, not an unusable interval"
    );

    let anchored = largest_representable_instant(now);
    assert_eq!(
        credential_deadline_from_unix_seconds_at_for_test(i64::MAX, 0, 1_000, anchored),
        None,
        "an expiry that outruns the monotonic clock is a long-lived credential, \
         not an expired one"
    );
}

#[test]
fn a_now_mono_at_the_platform_maximum_publishes_no_deadline() {
    // Anchored where no further second is representable, so the outcome does
    // not depend on how far out this platform's monotonic clock reaches.
    let now_mono = largest_representable_instant(tokio::time::Instant::now());
    assert_eq!(
        credential_deadline_from_unix_seconds_at_for_test(1_000, 0, 999, now_mono),
        None,
        "a one-second window the clock cannot express is still a live credential"
    );
    assert_eq!(
        credential_deadline_from_unix_seconds_at_for_test(1_000, 0, 1_000, now_mono),
        Some(now_mono),
        "a representable deadline keeps its exact behaviour from the same anchor"
    );
}

#[test]
fn an_unusable_interval_still_fails_closed() {
    let now = tokio::time::Instant::now();
    assert_eq!(
        credential_deadline_from_unix_seconds_at_for_test(-1, 0, 100, now),
        Some(now),
        "an expiry before the Unix epoch can never bound a live credential"
    );
    assert_eq!(
        credential_deadline_from_unix_seconds_at_for_test(0, u64::MAX, 0, now),
        Some(now),
        "a leeway too wide to be a signed offset is a malformed validation \
         parameter, not a far-future expiry"
    );
}

#[test]
fn a_claims_expiry_beyond_the_representable_range_publishes_no_deadline() {
    let now = tokio::time::Instant::now();
    let anchored = largest_representable_instant(now);

    // Same split as the seconds-taking conversion above: the `i64` overflow is
    // platform independent, the exhausted monotonic range is anchored.
    let far_future = json!({"sub": "alice", "exp": i64::MAX});
    assert_eq!(
        credential_deadline_from_claims_at_for_test(&far_future, 1, 1_000, now),
        None,
        "the claim-driven conversion must admit without a bound too"
    );
    assert_eq!(
        credential_deadline_from_claims_at_for_test(&far_future, 0, 1_000, anchored),
        None,
        "a claim expiry that outruns the monotonic clock publishes no bound"
    );

    let representable = json!({"sub": "alice", "exp": 1_060});
    assert_eq!(
        credential_deadline_from_claims_at_for_test(&representable, 0, 1_000, now),
        Some(now + Duration::from_secs(60))
    );
    assert_eq!(
        credential_deadline_from_claims_at_for_test(&representable, 0, 1_000, anchored),
        None,
        "an ordinary claim expiry the clock cannot express publishes no bound either"
    );
}

#[test]
fn claims_without_a_usable_numeric_expiry_publish_no_deadline() {
    // Unchanged behaviour, asserted here because it is now the SAME answer as
    // the far-future case: neither is a bound, and neither is an expiry.
    let now = tokio::time::Instant::now();
    for claims in [
        json!({"sub": "alice"}),
        json!({"sub": "alice", "exp": "1060"}),
        json!({"sub": "alice", "exp": u64::MAX}),
    ] {
        assert_eq!(
            credential_deadline_from_claims_at_for_test(&claims, 0, 1_000, now),
            None,
            "no authoritative numeric expiry: {claims}"
        );
    }
}

#[tokio::test]
async fn jwt_auth_admits_a_far_future_exp_without_an_effective_deadline() {
    let plugin = JwtAuth::new(&json!({})).expect("default jwt_auth config");
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_hs256_token(
        &json!({"sub": "testuser", "exp": i64::MAX}),
        "test-jwt-secret",
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some() || ctx.authenticated_identity.is_some());
    assert_no_effective_credential_deadline(&ctx);
}

#[tokio::test]
async fn jwt_auth_still_publishes_a_representable_exp_as_a_deadline() {
    let plugin = JwtAuth::new(&json!({})).expect("default jwt_auth config");
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_hs256_token(
        &json!({"sub": "testuser", "exp": 9_999_999_999u64}),
        "test-jwt-secret",
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(
        request_credential_deadline_at(&ctx).is_some(),
        "an ordinary expiry must still bound the authenticated stream"
    );
}

#[tokio::test]
async fn jwks_auth_admits_a_far_future_exp_without_an_effective_deadline() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let inline_jwks = build_rsa_jwks_from_pem(public_key_pem).to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks
            }]
        }),
        default_client(),
    )
    .expect("inline JWKS provider");
    plugin.warmup_jwks().await;

    let token = create_rs256_token_exact(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "far-future-user",
            "exp": i64::MAX
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("far-future-user")
    );
    assert_no_effective_credential_deadline(&ctx);
}

#[tokio::test]
async fn jwks_auth_still_publishes_a_representable_exp_as_a_deadline() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let inline_jwks = build_rsa_jwks_from_pem(public_key_pem).to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks
            }]
        }),
        default_client(),
    )
    .expect("inline JWKS provider");
    plugin.warmup_jwks().await;

    let token = create_rs256_token_exact(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "bounded-user",
            "exp": 9_999_999_999u64
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert!(
        request_credential_deadline_at(&ctx).is_some(),
        "an ordinary expiry must still bound the authenticated stream"
    );
}
