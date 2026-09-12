//! Client-certificate authorization lifetime for `mtls_auth` (issue #3816).
//!
//! Covers the unconditional leaf-validity check in the DEFAULT configuration
//! (no issuer constraints), exact `notBefore` / `notAfter` boundaries, fail-closed
//! handling of unusable validity intervals, the authoritative credential
//! deadline published on the shared contract, and — critically — that the
//! per-connection evaluation cache used by HTTP/3 still re-decides validity on
//! every request while performing the expensive parse exactly once.

use ferrum_edge::_test_support::{
    mtls_cert_validity_unix_bounds_from_der_for_test, mtls_client_cert_is_valid_at_unix_for_test,
    request_credential_deadline_at, request_credential_deadline_remaining,
    try_credential_deadline_from_unix_seconds_at_for_test,
};
use ferrum_edge::config::types::Consumer;
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::mtls_auth::{MtlsAuth, MtlsAuthConnectionCache};
use ferrum_edge::plugins::utils::auth_flow::CredentialDeadline;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, StreamConnectionContext};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::assert_continue;

/// Self-signed client certificate with an explicit validity interval, in
/// seconds relative to now. rcgen takes `time::OffsetDateTime`.
fn cert_with_validity(
    cn: &str,
    not_before_offset_secs: i64,
    not_after_offset_secs: i64,
) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    params.distinguished_name = dn;

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now + time::Duration::seconds(not_before_offset_secs);
    params.not_after = now + time::Duration::seconds(not_after_offset_secs);

    params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap()
        .der()
        .to_vec()
}

/// Self-signed client certificate with absolute Unix-second validity bounds.
/// Used so boundary proofs evaluate those encoded instants instead of `now`.
fn cert_with_unix_validity(cn: &str, not_before_unix: i64, not_after_unix: i64) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    params.distinguished_name = dn;

    params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before_unix).unwrap();
    params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after_unix).unwrap();

    params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap()
        .der()
        .to_vec()
}

fn mtls_consumer(username: &str, identity: &str) -> Consumer {
    let mut credentials = HashMap::new();
    let mut mtls_creds = Map::new();
    mtls_creds.insert("identity".to_string(), Value::String(identity.to_string()));
    credentials.insert(
        "mtls_auth".to_string(),
        Value::Array(vec![Value::Object(mtls_creds)]),
    );

    Consumer {
        id: username.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn ctx_with_cert(cert_der: Vec<u8>) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));
    ctx
}

/// Default configuration: `cert_field` only, no issuer or CA-fingerprint
/// constraints. This is the shape the audit found unprotected.
fn default_plugin() -> MtlsAuth {
    MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap()
}

fn assert_fixed_401(result: PluginResult) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 401);
            assert_eq!(
                body,
                r#"{"error":"Client certificate is not currently valid"}"#
            );
        }
        other => panic!("expected a fixed 401 rejection, got {other:?}"),
    }
}

// --- Unconditional leaf validity, default configuration --------------------

#[tokio::test]
async fn default_configuration_rejects_an_expired_leaf() {
    let cert = cert_with_validity("client.example.com", -3_600, -60);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let mut ctx = ctx_with_cert(cert);

    assert_fixed_401(default_plugin().authenticate(&mut ctx, &index).await);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn default_configuration_rejects_a_not_yet_valid_leaf() {
    let cert = cert_with_validity("client.example.com", 3_600, 7_200);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let mut ctx = ctx_with_cert(cert);

    assert_fixed_401(default_plugin().authenticate(&mut ctx, &index).await);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn default_configuration_accepts_a_currently_valid_leaf() {
    let cert = cert_with_validity("client.example.com", -60, 3_600);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let mut ctx = ctx_with_cert(cert);

    assert_continue(default_plugin().authenticate(&mut ctx, &index).await);
    assert_eq!(
        ctx.identified_consumer
            .as_ref()
            .map(|c| c.username.as_str()),
        Some("alice")
    );
}

// --- Exact boundaries ------------------------------------------------------

#[test]
fn the_not_before_and_not_after_instants_are_themselves_inside_the_window() {
    // Evaluated at an explicit Unix instant so async setup cannot roll the
    // wall clock past a zero-width `[T, T]` window (issue #4359). RFC 5280
    // "valid at" semantics make both endpoints inclusive.
    const T: i64 = 1_700_000_000;
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(T, T, T),
        Some(true),
        "a zero-width window must admit its single enclosed second"
    );
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(T, T, T - 1),
        Some(false),
        "the second before notBefore is outside the window"
    );
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(T, T, T + 1),
        Some(false),
        "the second after notAfter is outside the window"
    );

    const NOT_BEFORE: i64 = 1_700_000_000;
    const NOT_AFTER: i64 = 1_700_000_010;
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(NOT_BEFORE, NOT_AFTER, NOT_BEFORE),
        Some(true)
    );
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(NOT_BEFORE, NOT_AFTER, NOT_AFTER),
        Some(true)
    );
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(NOT_BEFORE, NOT_AFTER, NOT_BEFORE + 5),
        Some(true)
    );
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(NOT_BEFORE, NOT_AFTER, NOT_BEFORE - 1),
        Some(false)
    );
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(NOT_BEFORE, NOT_AFTER, NOT_AFTER + 1),
        Some(false)
    );
}

#[test]
fn an_inverted_unix_interval_is_unusable_rather_than_evaluated() {
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(1_700_000_010, 1_700_000_000, 1_700_000_005),
        None,
        "an inverted interval must fail closed before any instant is compared"
    );
}

#[test]
fn parsed_leaf_bounds_are_inclusive_at_the_encoded_unix_instants() {
    // Mint a leaf at absolute Unix bounds so the production parser's timestamps
    // — not a separately sampled wall clock — are the instants under test.
    const NOT_BEFORE: i64 = 1_700_000_000;
    const NOT_AFTER: i64 = 1_700_000_010;
    let cert = cert_with_unix_validity("client.example.com", NOT_BEFORE, NOT_AFTER);
    let (parsed_not_before, parsed_not_after) =
        mtls_cert_validity_unix_bounds_from_der_for_test(&cert)
            .expect("a coherent leaf must yield a usable validity window");
    assert_eq!(parsed_not_before, NOT_BEFORE);
    assert_eq!(parsed_not_after, NOT_AFTER);
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(
            parsed_not_before,
            parsed_not_after,
            parsed_not_before,
        ),
        Some(true)
    );
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(
            parsed_not_before,
            parsed_not_after,
            parsed_not_after,
        ),
        Some(true)
    );
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(
            parsed_not_before,
            parsed_not_after,
            parsed_not_before - 1,
        ),
        Some(false)
    );
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(
            parsed_not_before,
            parsed_not_after,
            parsed_not_after + 1,
        ),
        Some(false)
    );
}

#[test]
fn the_per_request_validity_check_uses_the_inclusive_unix_predicate() {
    let source = include_str!("../../../src/plugins/mtls_auth.rs");
    let outcome = source
        .split("fn evaluation_outcome(")
        .nth(1)
        .expect("evaluation_outcome")
        .split("\n    fn verify_client_cert(")
        .next()
        .expect("bounded evaluation_outcome");
    assert!(
        outcome.contains("let now_unix = x509_parser::time::ASN1Time::now().timestamp();"),
        "the per-request check must sample wall-clock Unix time"
    );
    assert!(
        outcome.contains("if !validity.contains(now_unix)"),
        "the per-request check must use the inclusive CertValidityWindow predicate"
    );
}

#[test]
fn one_second_past_not_after_is_outside_the_window() {
    assert_eq!(
        mtls_client_cert_is_valid_at_unix_for_test(100, 200, 201),
        Some(false)
    );
}

#[tokio::test]
async fn an_inverted_validity_interval_fails_closed_as_an_invalid_certificate() {
    // `notAfter` before `notBefore` can never be valid. It must be refused
    // outright rather than admitted by whichever bound is compared first.
    let cert = cert_with_validity("client.example.com", 600, -600);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let mut ctx = ctx_with_cert(cert);

    match default_plugin().authenticate(&mut ctx, &index).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 401);
            assert_eq!(body, r#"{"error":"Invalid client certificate"}"#);
        }
        other => panic!("expected a fixed 401 rejection, got {other:?}"),
    }
    assert!(ctx.identified_consumer.is_none());
}

// --- The authoritative credential deadline ---------------------------------

#[tokio::test]
async fn a_successful_verification_publishes_the_certificate_deadline() {
    let cert = cert_with_validity("client.example.com", -60, 120);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let mut ctx = ctx_with_cert(cert);

    assert_continue(default_plugin().authenticate(&mut ctx, &index).await);

    let remaining = request_credential_deadline_remaining(&ctx)
        .expect("mtls_auth must publish the leaf notAfter as the credential deadline");
    // Derived from `notAfter`, converted once to a monotonic instant. Allow a
    // couple of seconds of slack for the second-granularity ASN.1 time and test
    // scheduling; the point is that it is finite and close to 120s.
    assert!(
        remaining <= std::time::Duration::from_secs(122),
        "deadline should track notAfter, got {remaining:?}"
    );
    assert!(
        remaining >= std::time::Duration::from_secs(110),
        "deadline should track notAfter, got {remaining:?}"
    );
}

#[tokio::test]
async fn a_rejected_certificate_publishes_no_credential_deadline() {
    let cert = cert_with_validity("client.example.com", -3_600, -60);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let mut ctx = ctx_with_cert(cert);

    assert_fixed_401(default_plugin().authenticate(&mut ctx, &index).await);
    assert!(request_credential_deadline_remaining(&ctx).is_none());
}

// --- The HTTP/3 connection cache -------------------------------------------

#[tokio::test]
async fn the_connection_cache_reevaluates_validity_without_reparsing_the_certificate() {
    // One transport connection, two multiplexed request streams. The expensive
    // parse/path/identity work happens once; the temporal decision does not.
    let valid = cert_with_validity("client.example.com", -60, 3_600);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let plugin = default_plugin();
    let cache = Arc::new(MtlsAuthConnectionCache::new());

    for _ in 0..3 {
        let mut ctx = ctx_with_cert(valid.clone());
        ctx.mtls_auth_connection_cache = Some(Arc::clone(&cache));
        assert_continue(plugin.authenticate(&mut ctx, &index).await);
        // Re-decided per request against the captured monotonic Instant.
        assert!(request_credential_deadline_at(&ctx).is_some());
    }

    assert_eq!(
        cache.evaluation_count(),
        1,
        "the certificate parse, path verification, and identity extraction must \
         stay memoized per plugin instance and connection"
    );
}

#[tokio::test]
async fn a_cached_success_becomes_a_fixed_401_once_the_certificate_expires() {
    // A certificate that is valid when the connection is admitted and expired
    // by the time a later stream on the SAME connection arrives. Because the
    // cache stores the validity WINDOW rather than "this was valid", the second
    // request is refused without a new TLS handshake.
    let expiring = cert_with_validity("client.example.com", -60, 1);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let plugin = default_plugin();
    let cache = Arc::new(MtlsAuthConnectionCache::new());

    let mut first = ctx_with_cert(expiring.clone());
    first.mtls_auth_connection_cache = Some(Arc::clone(&cache));
    assert_continue(plugin.authenticate(&mut first, &index).await);

    // ASN.1 times are second-granular; sleep past `notAfter`.
    tokio::time::sleep(std::time::Duration::from_millis(2_500)).await;

    let mut second = ctx_with_cert(expiring);
    second.mtls_auth_connection_cache = Some(Arc::clone(&cache));
    assert_fixed_401(plugin.authenticate(&mut second, &index).await);
    assert!(second.identified_consumer.is_none());

    assert_eq!(
        cache.evaluation_count(),
        1,
        "expiry must be decided from the cached window, not by re-parsing"
    );
}

#[tokio::test]
async fn a_cache_hit_returns_the_identical_monotonic_deadline_captured_at_first_success() {
    // The expensive evaluation runs once. Every later request on that cached
    // evaluation must return the SAME Instant — not a freshly converted one
    // that would land later after monotonic time (or wall-clock rollback)
    // advanced. Sleeping between the two authentications would make a
    // re-derived Instant strictly later if the Unix remaining seconds have
    // not yet ticked down.
    let valid = cert_with_validity("client.example.com", -60, 3_600);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let plugin = default_plugin();
    let cache = Arc::new(MtlsAuthConnectionCache::new());

    let mut first = ctx_with_cert(valid.clone());
    first.mtls_auth_connection_cache = Some(Arc::clone(&cache));
    assert_continue(plugin.authenticate(&mut first, &index).await);
    let first_deadline = request_credential_deadline_at(&first)
        .expect("first successful evaluation must capture the monotonic notAfter");

    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    let mut second = ctx_with_cert(valid);
    second.mtls_auth_connection_cache = Some(Arc::clone(&cache));
    assert_continue(plugin.authenticate(&mut second, &index).await);
    let second_deadline = request_credential_deadline_at(&second)
        .expect("cache hit must republish the captured monotonic deadline");

    assert_eq!(
        first_deadline, second_deadline,
        "cache-hit rollback/time-passage must not extend admission: the returned \
         credential deadline is the cached monotonic identity"
    );
    assert_eq!(cache.evaluation_count(), 1);
}

#[test]
fn a_fresh_unix_conversion_after_wall_clock_rollback_would_extend_the_instant() {
    // Evidence that converting `notAfter` again from a rolled-back wall clock
    // produces a LATER Instant — which is why the connection cache must retain
    // the first successful conversion instead of calling this on every request.
    let now = tokio::time::Instant::now();
    let original =
        try_credential_deadline_from_unix_seconds_at_for_test(2_000_000, 0, 2_000_000 - 120, now)
            .bounded()
            .expect("representable original conversion");
    let after_rollback =
        try_credential_deadline_from_unix_seconds_at_for_test(2_000_000, 0, 2_000_000 - 3_600, now)
            .bounded()
            .expect("representable rolled-back conversion");
    assert!(
        after_rollback > original,
        "a fresh conversion after wall-clock rollback must land later; the cache \
         path is what prevents that extension"
    );
}

#[test]
fn an_unusable_unix_to_monotonic_conversion_fails_closed() {
    let now = tokio::time::Instant::now();
    assert_eq!(
        try_credential_deadline_from_unix_seconds_at_for_test(-1, 0, 100, now),
        CredentialDeadline::Invalid,
        "an expiry before the Unix epoch can never bound a live credential"
    );
    assert_eq!(
        try_credential_deadline_from_unix_seconds_at_for_test(0, u64::MAX, 0, now),
        CredentialDeadline::Invalid,
        "a leeway too wide to be a signed offset is a malformed validation \
         parameter, not a far-future expiry"
    );
}

/// The largest monotonic instant reachable from `now` by adding whole seconds.
///
/// `std` exposes no `Instant::MAX`, and where the maximum sits is platform
/// dependent — a nanosecond-based clock saturates centuries before a
/// `timespec`-based one — so it is found by a bounded binary search instead of
/// hard-coded. Only used to place `now_mono` where the next second is
/// unrepresentable.
fn largest_representable_instant(now: tokio::time::Instant) -> tokio::time::Instant {
    let (mut lo, mut hi) = (0_u64, u64::MAX);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        let step = std::time::Duration::from_secs(mid);
        if now.checked_add(step).is_some() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    now.checked_add(std::time::Duration::from_secs(lo))
        .expect("the search settles on a representable offset")
}

#[test]
fn an_expiry_beyond_the_representable_range_admits_with_no_bound() {
    // Issue #5396: `None` used to mean BOTH "this interval can never be valid"
    // and "this expiry is further out than an Instant can hold". The second is
    // a perfectly valid long-lived certificate and must not fail closed.
    let now = tokio::time::Instant::now();
    assert_eq!(
        try_credential_deadline_from_unix_seconds_at_for_test(i64::MAX, 0, 0, now),
        CredentialDeadline::Unbounded,
        "an `i64::MAX` notAfter outruns the monotonic clock, it is not invalid"
    );
    assert_eq!(
        try_credential_deadline_from_unix_seconds_at_for_test(i64::MAX, 1, 0, now),
        CredentialDeadline::Unbounded,
        "an overflowing expiry+leeway is far future, not an unusable interval"
    );
}

#[test]
fn a_now_mono_at_the_platform_maximum_admits_with_no_bound() {
    // Anchored where no further second is representable, so the outcome does
    // not depend on how far out this platform's monotonic clock reaches.
    let now_mono = largest_representable_instant(tokio::time::Instant::now());
    assert_eq!(
        try_credential_deadline_from_unix_seconds_at_for_test(1_000, 0, 999, now_mono),
        CredentialDeadline::Unbounded,
        "a one-second window the clock cannot express is still a live credential"
    );
    // Representable deadlines keep their exact behaviour from the same anchor:
    // an already-elapsed window converts to the anchor itself, which the
    // callers then compare against `now` as before.
    assert_eq!(
        try_credential_deadline_from_unix_seconds_at_for_test(1_000, 0, 1_000, now_mono),
        CredentialDeadline::Bounded(now_mono),
        "a zero-remaining window is exactly the anchor, not unbounded"
    );
}

/// ~7,900 years out: the "no well-defined expiration" shape RFC 5280 spells
/// `99991231235959Z`, expressed as an offset the certificate helper accepts and
/// `time::OffsetDateTime` can still represent.
const NO_EXPIRATION_OFFSET_SECS: i64 = 250_000_000_000;

#[tokio::test]
async fn a_leaf_with_no_well_defined_expiration_still_authenticates() {
    // A valid long-lived certificate must authenticate on every platform
    // (issue #5396). Whether its `notAfter` is representable as a monotonic
    // deadline is a property of the host clock, never of the credential.
    let cert = cert_with_validity("client.example.com", -60, NO_EXPIRATION_OFFSET_SECS);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let mut ctx = ctx_with_cert(cert);

    assert_continue(default_plugin().authenticate(&mut ctx, &index).await);
    let consumer = ctx.identified_consumer.clone().expect("mapped consumer");
    assert_eq!(consumer.username, "alice");
    // Where the expiry IS representable it is published unchanged; where it is
    // not, the credential carries no bound of its own and the finite
    // authenticated-stream maximum is what limits the session.
    if let Some(remaining) = request_credential_deadline_remaining(&ctx) {
        assert!(
            remaining > std::time::Duration::from_secs(100 * 365 * 24 * 3_600),
            "a representable no-expiration bound must stay centuries out"
        );
    }
}

#[tokio::test]
async fn a_stream_connection_with_no_well_defined_expiration_is_admitted() {
    let cert = cert_with_validity("client.example.com", -60, NO_EXPIRATION_OFFSET_SECS);
    let index = Arc::new(ConsumerIndex::new(&[mtls_consumer(
        "alice",
        "client.example.com",
    )]));
    let mut ctx = stream_ctx_with_cert(cert, index);

    assert_continue(default_plugin().on_stream_connect(&mut ctx).await);
    assert!(ctx.is_authenticated());
}

#[test]
fn the_evaluation_admits_an_unrepresentable_expiry_instead_of_rejecting_it() {
    // Shape contract for the branch a Linux CI clock cannot reach: the
    // far-future arm must publish no bound, and only the unusable-interval arm
    // may return an invalid-certificate rejection (issue #5396).
    let source = include_str!("../../../src/plugins/mtls_auth.rs");
    let outcome = source
        .split("fn evaluation_outcome(")
        .nth(1)
        .expect("evaluation_outcome")
        .split("\n    fn verify_client_cert(")
        .next()
        .expect("bounded evaluation_outcome");
    let unbounded_arm = outcome
        .split("CredentialDeadline::Unbounded =>")
        .nth(1)
        .expect("the far-future arm must be handled explicitly")
        .split("CredentialDeadline::Invalid =>")
        .next()
        .expect("bounded far-future arm");
    assert!(
        !unbounded_arm.contains("return VerifyOutcome::"),
        "an expiry beyond the representable monotonic range must admit the \
         certificate, not reject it"
    );
    assert!(
        outcome.contains("CredentialDeadline::Invalid =>"),
        "an unusable validity interval must still fail closed"
    );
}

#[test]
fn the_cached_identity_retains_a_monotonic_expiry_converted_once() {
    let source = include_str!("../../../src/plugins/mtls_auth.rs");
    assert!(
        source.contains("monotonic_expiry: OnceLock<tokio::time::Instant>"),
        "the connection-cached identity must retain the first successful monotonic expiry"
    );
    let outcome = source
        .split("fn evaluation_outcome(")
        .nth(1)
        .expect("evaluation_outcome")
        .split("\n    fn verify_client_cert(")
        .next()
        .expect("bounded evaluation_outcome");
    assert!(
        !outcome.contains("auth_flow::credential_deadline_from_unix_seconds("),
        "cache hits must not derive a fresh Instant from Unix notAfter"
    );
    assert!(
        outcome.contains("auth_flow::try_credential_deadline_from_unix_seconds("),
        "the first successful evaluation must fail closed on an unrepresentable conversion"
    );
    assert!(
        outcome.contains("monotonic_expiry.get()"),
        "later requests must admit against the retained Instant"
    );
}

#[tokio::test]
async fn consumer_index_lookup_stays_per_request_behind_the_cache() {
    // Removing the consumer must take effect on the very next request over the
    // same connection, exactly as before this change.
    let cert = cert_with_validity("client.example.com", -60, 3_600);
    let plugin = default_plugin();
    let cache = Arc::new(MtlsAuthConnectionCache::new());

    let populated = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let mut first = ctx_with_cert(cert.clone());
    first.mtls_auth_connection_cache = Some(Arc::clone(&cache));
    assert_continue(plugin.authenticate(&mut first, &populated).await);

    let emptied = ConsumerIndex::new(&[]);
    let mut second = ctx_with_cert(cert);
    second.mtls_auth_connection_cache = Some(Arc::clone(&cache));
    match plugin.authenticate(&mut second, &emptied).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 401),
        other => panic!("expected a rejection after the consumer was removed, got {other:?}"),
    }
}

// --- Stream sessions -------------------------------------------------------

fn stream_ctx_with_cert(cert_der: Vec<u8>, index: Arc<ConsumerIndex>) -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "tcp-proxy".to_string(),
        Some("TCP Proxy".to_string()),
        5432,
        ferrum_edge::config::types::BackendScheme::Tcps,
        index,
    );
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));
    ctx
}

#[tokio::test]
async fn a_stream_connection_carries_the_certificate_deadline() {
    let cert = cert_with_validity("client.example.com", -60, 300);
    let index = Arc::new(ConsumerIndex::new(&[mtls_consumer(
        "alice",
        "client.example.com",
    )]));
    let mut ctx = stream_ctx_with_cert(cert, index);

    assert_continue(default_plugin().on_stream_connect(&mut ctx).await);
    assert!(ctx.is_authenticated());
    let deadline = ctx
        .credential_deadline_at()
        .expect("on_stream_connect must carry the certificate deadline into the session");
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    assert!(remaining <= std::time::Duration::from_secs(302));
    assert!(remaining >= std::time::Duration::from_secs(290));
}

#[tokio::test]
async fn a_stream_connection_with_an_expired_certificate_is_refused() {
    let cert = cert_with_validity("client.example.com", -3_600, -60);
    let index = Arc::new(ConsumerIndex::new(&[mtls_consumer(
        "alice",
        "client.example.com",
    )]));
    let mut ctx = stream_ctx_with_cert(cert, index);

    match default_plugin().on_stream_connect(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 401),
        other => panic!("expected the stream connection to be refused, got {other:?}"),
    }
    assert!(ctx.credential_deadline_at().is_none());
}

#[tokio::test]
async fn observing_a_later_deadline_never_lengthens_an_established_bound() {
    let cert = cert_with_validity("client.example.com", -60, 300);
    let index = Arc::new(ConsumerIndex::new(&[mtls_consumer(
        "alice",
        "client.example.com",
    )]));
    let mut ctx = stream_ctx_with_cert(cert, index);
    assert_continue(default_plugin().on_stream_connect(&mut ctx).await);

    let established = ctx.credential_deadline_at().expect("deadline");
    ctx.observe_credential_deadline(Some(established + std::time::Duration::from_secs(3_600)));
    assert_eq!(ctx.credential_deadline_at(), Some(established));

    // A `None` contribution is a no-op, never a reset.
    ctx.observe_credential_deadline(None);
    assert_eq!(ctx.credential_deadline_at(), Some(established));

    // An earlier contribution tightens it.
    let earlier = established - std::time::Duration::from_secs(60);
    ctx.observe_credential_deadline(Some(earlier));
    assert_eq!(ctx.credential_deadline_at(), Some(earlier));
}

// --- Redaction -------------------------------------------------------------

#[tokio::test]
async fn a_validity_rejection_never_echoes_certificate_or_time_material() {
    let cert = cert_with_validity("secret-client.internal.example.com", -3_600, -60);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let mut ctx = ctx_with_cert(cert);

    match default_plugin().authenticate(&mut ctx, &index).await {
        PluginResult::Reject { body, headers, .. } => {
            assert!(!body.contains("secret-client"));
            assert!(!body.contains("notAfter"));
            assert!(!body.contains("notBefore"));
            assert!(!body.chars().any(|c| c.is_ascii_digit()));
            for value in headers.values() {
                assert!(!value.contains("secret-client"));
            }
        }
        other => panic!("expected a rejection, got {other:?}"),
    }
}

/// Drift guard for the kTLS handoff decision (issue #3816).
///
/// `Plugin::admits_authenticated_stream_principal` defaults to `false`, and the
/// TCP/TLS listener uses it to decide — before the frontend handshake — whether
/// the socket may be handed to kernel TLS. A plugin that admits a stream
/// principal without overriding it would be relayed by `splice(2)` with no
/// enforceable authorization deadline, so the built-in inventory of such
/// plugins is pinned here: any new `on_stream_connect` hook that populates
/// `identified_consumer`, `authenticated_identity`, a certificate-derived
/// SPIFFE principal, or a credential deadline must both override the
/// declaration and be listed below.
#[test]
fn the_stream_principal_admitting_plugin_inventory_is_pinned() {
    use std::path::Path;

    const DECLARED: &[&str] = &["mtls_auth", "spiffe_identity"];

    fn scan(dir: &Path, found: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("readable plugin directory") {
            let entry = entry.expect("readable directory entry");
            let path = entry.path();
            if path.is_dir() {
                scan(&path, found);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // `src/plugins/mod.rs` holds the trait DEFINITION (and this
            // declaration's own doc comment), not a plugin implementation.
            if path == dir.join("mod.rs") && dir.ends_with("plugins") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("readable plugin source");
            let Some(hook_start) = source.find("fn on_stream_connect(") else {
                continue;
            };
            // Bound the scan to the hook body: other phases legitimately assign
            // request-scoped identity and are irrelevant to a stream session.
            // Comment lines are stripped so prose about the contract cannot be
            // mistaken for an implementation of it.
            let body: String = source[hook_start..]
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let assigns_identity = body.contains("ctx.identified_consumer = Some")
                || body.contains("ctx.authenticated_identity = Some")
                || body.contains("observe_credential_deadline")
                || body.contains("admit_certificate_spiffe_principal");
            if assigns_identity {
                found.push(
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or_default()
                        .to_string(),
                );
            }
        }
    }

    let mut found = Vec::new();
    scan(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/plugins"),
        &mut found,
    );
    found.sort();
    found.dedup();

    assert_eq!(
        found, DECLARED,
        "a plugin whose on_stream_connect admits an authenticated principal must override \
         Plugin::admits_authenticated_stream_principal and be listed here; otherwise a \
         TLS-terminating TCP listener carrying it can still take the kTLS splice path, where \
         the session's authorization deadline cannot be enforced"
    );
}

#[test]
fn mtls_auth_keeps_a_tcp_tls_listener_on_the_deadline_aware_userspace_relay() {
    let plugin: std::sync::Arc<dyn Plugin> = std::sync::Arc::new(default_plugin());
    assert!(plugin.admits_authenticated_stream_principal());
    assert!(!ferrum_edge::_test_support::ktls_handoff_eligible_for_test(
        true,
        false,
        false,
        &[plugin]
    ));
}

// --- Issuer-path lifetime (GHSA-jw5x-439c-78v3) ----------------------------
//
// The connection cache retains the issuer/fingerprint decision, but the
// configured pin and the presented issuing CAs are themselves valid only for a
// finite time. An issuer that expires before the leaf must end the cached
// decision — and the stream-admission deadline derived from it — at its own
// `notAfter`, not the leaf's.

/// Certificate parameters carrying an explicit validity window, in seconds
/// relative to now. `not_before` is always in the recent past.
fn params_with_validity(cn: &str, not_after_secs: i64) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    params.distinguished_name = dn;

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::seconds(60);
    params.not_after = now + time::Duration::seconds(not_after_secs);
    params
}

fn ca_params_with_validity(cn: &str, not_after_secs: i64) -> rcgen::CertificateParams {
    let mut params = params_with_validity(cn, not_after_secs);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    params
}

/// Root CA plus a client certificate it signed directly.
/// Returns `(ca_pem, client_der)`.
fn ca_signed_cert(
    ca_cn: &str,
    ca_secs: i64,
    client_cn: &str,
    client_secs: i64,
) -> (String, Vec<u8>) {
    let ca_params = ca_params_with_validity(ca_cn, ca_secs);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
    let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

    let client_params = params_with_validity(client_cn, client_secs);
    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_der = client_params
        .signed_by(&client_key, &ca_issuer)
        .unwrap()
        .der()
        .to_vec();

    (ca_pem, client_der)
}

/// Root CA -> intermediate -> client, each with its own validity window.
/// Returns `(root_pem, intermediate_der, client_der)`.
fn intermediate_signed_cert(
    root_secs: i64,
    intermediate_secs: i64,
    client_secs: i64,
) -> (String, Vec<u8>, Vec<u8>) {
    let root_params = ca_params_with_validity("Bounded Root CA", root_secs);
    let root_key = rcgen::KeyPair::generate().unwrap();
    let root_pem = root_params.self_signed(&root_key).unwrap().pem();
    let root_issuer = rcgen::Issuer::new(root_params, root_key);

    let intermediate_params = ca_params_with_validity("Bounded Intermediate CA", intermediate_secs);
    let intermediate_key = rcgen::KeyPair::generate().unwrap();
    let intermediate_der = intermediate_params
        .signed_by(&intermediate_key, &root_issuer)
        .unwrap()
        .der()
        .to_vec();
    let intermediate_issuer = rcgen::Issuer::new(intermediate_params, intermediate_key);

    let client_params = params_with_validity("client.example.com", client_secs);
    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_der = client_params
        .signed_by(&client_key, &intermediate_issuer)
        .unwrap()
        .der()
        .to_vec();

    (root_pem, intermediate_der, client_der)
}

/// One intermediate key cross-signed by two roots with different lifetimes, so
/// the leaf has two independently valid paths.
/// Returns `(short_root_pem, long_root_pem, chain_ders, client_der)`.
fn cross_signed_chain(short_secs: i64, long_secs: i64) -> (String, String, Vec<Vec<u8>>, Vec<u8>) {
    let short_params = ca_params_with_validity("Short Root CA", short_secs);
    let short_key = rcgen::KeyPair::generate().unwrap();
    let short_pem = short_params.self_signed(&short_key).unwrap().pem();
    let short_issuer = rcgen::Issuer::new(short_params, short_key);

    let long_params = ca_params_with_validity("Long Root CA", long_secs);
    let long_key = rcgen::KeyPair::generate().unwrap();
    let long_pem = long_params.self_signed(&long_key).unwrap().pem();
    let long_issuer = rcgen::Issuer::new(long_params, long_key);

    let intermediate_params = ca_params_with_validity("Cross-Signed Intermediate CA", 7_200);
    let intermediate_key = rcgen::KeyPair::generate().unwrap();
    let via_short = intermediate_params
        .signed_by(&intermediate_key, &short_issuer)
        .unwrap()
        .der()
        .to_vec();
    let via_long = intermediate_params
        .signed_by(&intermediate_key, &long_issuer)
        .unwrap()
        .der()
        .to_vec();
    let intermediate_issuer = rcgen::Issuer::new(intermediate_params, intermediate_key);

    let client_params = params_with_validity("client.example.com", 7_200);
    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_der = client_params
        .signed_by(&client_key, &intermediate_issuer)
        .unwrap()
        .der()
        .to_vec();

    (short_pem, long_pem, vec![via_short, via_long], client_der)
}

fn pinned_plugin(filters: Vec<Value>) -> MtlsAuth {
    MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": filters,
    }))
    .unwrap()
}

fn issuer_filter(cn: &str, pem: &str) -> Value {
    json!({ "cn": cn, "ca_certificate_pem": pem })
}

fn ctx_with_chain(cert_der: Vec<u8>, chain: Vec<Vec<u8>>) -> RequestContext {
    let mut ctx = ctx_with_cert(cert_der);
    ctx.tls_client_cert_chain_der = Some(Arc::new(chain));
    ctx
}

fn assert_remaining_near(ctx: &RequestContext, expected_secs: u64) {
    let remaining = request_credential_deadline_remaining(ctx)
        .expect("a successful verification must publish a credential deadline");
    let low = std::time::Duration::from_secs(expected_secs.saturating_sub(10));
    let high = std::time::Duration::from_secs(expected_secs + 2);
    assert!(
        remaining >= low && remaining <= high,
        "expected roughly {expected_secs}s of authorized lifetime, got {remaining:?}"
    );
}

#[tokio::test]
async fn a_pinned_issuer_expiring_before_the_leaf_bounds_the_credential_deadline() {
    let (ca_pem, client) = ca_signed_cert("Bounded Issuer CA", 300, "client.example.com", 7_200);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let plugin = pinned_plugin(vec![issuer_filter("Bounded Issuer CA", &ca_pem)]);
    let mut ctx = ctx_with_cert(client);

    assert_continue(plugin.authenticate(&mut ctx, &index).await);
    assert_remaining_near(&ctx, 300);
}

#[tokio::test]
async fn a_longer_lived_pinned_issuer_never_lengthens_the_leaf_bound() {
    let (ca_pem, client) = ca_signed_cert("Bounded Issuer CA", 7_200, "client.example.com", 300);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let plugin = pinned_plugin(vec![issuer_filter("Bounded Issuer CA", &ca_pem)]);
    let mut ctx = ctx_with_cert(client);

    assert_continue(plugin.authenticate(&mut ctx, &index).await);
    assert_remaining_near(&ctx, 300);
}

#[tokio::test]
async fn the_earliest_notafter_on_the_accepted_path_wins_not_just_the_pinned_ca() {
    // Pinned root outlives the leaf; the presented intermediate does not.
    let (root_pem, intermediate, client) = intermediate_signed_cert(7_200, 300, 7_200);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let plugin = pinned_plugin(vec![issuer_filter("Bounded Root CA", &root_pem)]);
    let mut ctx = ctx_with_chain(client, vec![intermediate]);

    assert_continue(plugin.authenticate(&mut ctx, &index).await);
    assert_remaining_near(&ctx, 300);
}

#[tokio::test]
async fn an_alternative_longer_lived_verified_path_keeps_the_longer_bound() {
    // Two cryptographically valid paths exist. Filters are alternatives, so the
    // longer-lived one is the operator's authorization; tightening to the other
    // would shorten a session the configuration allows.
    let (short_pem, long_pem, chain, client) = cross_signed_chain(300, 3_600);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let filters = vec![
        issuer_filter("Short Root CA", &short_pem),
        issuer_filter("Long Root CA", &long_pem),
    ];
    let plugin = pinned_plugin(filters);
    let mut ctx = ctx_with_chain(client, chain);

    assert_continue(plugin.authenticate(&mut ctx, &index).await);
    assert_remaining_near(&ctx, 3_600);
}

#[tokio::test]
async fn an_expired_presented_intermediate_leaves_no_verified_path() {
    let (root_pem, intermediate, client) = intermediate_signed_cert(7_200, -60, 7_200);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let plugin = pinned_plugin(vec![issuer_filter("Bounded Root CA", &root_pem)]);
    let mut ctx = ctx_with_chain(client, vec![intermediate]);

    match plugin.authenticate(&mut ctx, &index).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected the constraint to refuse the certificate, got {other:?}"),
    }
    assert!(request_credential_deadline_at(&ctx).is_none());
}

#[tokio::test]
async fn a_cached_evaluation_keeps_returning_the_issuer_bounded_deadline() {
    let (ca_pem, client) = ca_signed_cert("Bounded Issuer CA", 300, "client.example.com", 7_200);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let plugin = pinned_plugin(vec![issuer_filter("Bounded Issuer CA", &ca_pem)]);
    let cache = Arc::new(MtlsAuthConnectionCache::new());

    let mut first = ctx_with_cert(client.clone());
    first.mtls_auth_connection_cache = Some(Arc::clone(&cache));
    assert_continue(plugin.authenticate(&mut first, &index).await);
    let captured = request_credential_deadline_at(&first).expect("deadline");

    let mut second = ctx_with_cert(client);
    second.mtls_auth_connection_cache = Some(Arc::clone(&cache));
    assert_continue(plugin.authenticate(&mut second, &index).await);
    assert_eq!(request_credential_deadline_at(&second), Some(captured));
    assert_eq!(cache.evaluation_count(), 1);
    assert_remaining_near(&second, 300);
}

#[tokio::test]
async fn a_stream_connection_carries_the_issuer_bounded_deadline() {
    let (ca_pem, client) = ca_signed_cert("Bounded Issuer CA", 300, "client.example.com", 7_200);
    let index = Arc::new(ConsumerIndex::new(&[mtls_consumer(
        "alice",
        "client.example.com",
    )]));
    let plugin = pinned_plugin(vec![issuer_filter("Bounded Issuer CA", &ca_pem)]);
    let mut ctx = stream_ctx_with_cert(client, index);

    assert_continue(plugin.on_stream_connect(&mut ctx).await);
    let deadline = ctx.credential_deadline_at().expect("stream deadline");
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    assert!(remaining <= std::time::Duration::from_secs(302));
    assert!(remaining >= std::time::Duration::from_secs(290));
}
