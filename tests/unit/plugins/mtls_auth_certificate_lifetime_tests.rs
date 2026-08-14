//! Client-certificate authorization lifetime for `mtls_auth` (issue #3816).
//!
//! Covers the unconditional leaf-validity check in the DEFAULT configuration
//! (no issuer constraints), exact `notBefore` / `notAfter` boundaries, fail-closed
//! handling of unusable validity intervals, the authoritative credential
//! deadline published on the shared contract, and — critically — that the
//! per-connection evaluation cache used by HTTP/3 still re-decides validity on
//! every request while performing the expensive parse exactly once.

use ferrum_edge::_test_support::{
    request_credential_deadline_at, request_credential_deadline_remaining,
    try_credential_deadline_from_unix_seconds_at_for_test,
};
use ferrum_edge::config::types::Consumer;
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::mtls_auth::{MtlsAuth, MtlsAuthConnectionCache};
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

#[tokio::test]
async fn the_not_before_and_not_after_instants_are_themselves_inside_the_window() {
    // A certificate whose window is [now, now] — both boundaries collapse onto
    // the current second. RFC 5280 "valid at" semantics make this valid.
    let cert = cert_with_validity("client.example.com", 0, 0);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let mut ctx = ctx_with_cert(cert);

    assert_continue(default_plugin().authenticate(&mut ctx, &index).await);
}

#[tokio::test]
async fn one_second_past_not_after_is_outside_the_window() {
    let cert = cert_with_validity("client.example.com", -600, -1);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let mut ctx = ctx_with_cert(cert);

    assert_fixed_401(default_plugin().authenticate(&mut ctx, &index).await);
}

#[tokio::test]
async fn one_second_before_not_before_is_outside_the_window() {
    let cert = cert_with_validity("client.example.com", 1, 600);
    let index = ConsumerIndex::new(&[mtls_consumer("alice", "client.example.com")]);
    let mut ctx = ctx_with_cert(cert);

    assert_fixed_401(default_plugin().authenticate(&mut ctx, &index).await);
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
            .expect("representable original conversion");
    let after_rollback =
        try_credential_deadline_from_unix_seconds_at_for_test(2_000_000, 0, 2_000_000 - 3_600, now)
            .expect("representable rolled-back conversion");
    assert!(
        after_rollback > original,
        "a fresh conversion after wall-clock rollback must land later; the cache \
         path is what prevents that extension"
    );
}

#[test]
fn an_unrepresentable_unix_to_monotonic_conversion_fails_closed() {
    let now = tokio::time::Instant::now();
    assert!(
        try_credential_deadline_from_unix_seconds_at_for_test(-1, 0, 100, now).is_none(),
        "a negative expiry is not a monotonic deadline"
    );
    assert!(
        try_credential_deadline_from_unix_seconds_at_for_test(i64::MAX, 1, 0, now).is_none(),
        "an overflowing expiry+leeway must fail closed, not saturate into now"
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
/// `identified_consumer`, `authenticated_identity`, or a credential deadline
/// must both override the declaration and be listed below.
#[test]
fn the_stream_principal_admitting_plugin_inventory_is_pinned() {
    use std::path::Path;

    const DECLARED: &[&str] = &["mtls_auth"];

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
                || body.contains("observe_credential_deadline");
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
