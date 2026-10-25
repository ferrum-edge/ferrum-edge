use ferrum_edge::_test_support::{
    has_verified_peer_spiffe_identity_for_test, request_credential_deadline_at,
    request_credential_deadline_remaining,
};
use ferrum_edge::config::types::{BackendScheme, Consumer};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::identity::spiffe::{SpiffeId, spiffe_id_to_san};
use ferrum_edge::plugins::mesh::spiffe_identity::{SpiffeIdentity, SpiffeIdentityConnectionCache};
use ferrum_edge::plugins::{
    HTTP_FAMILY_AND_STREAM_PROTOCOLS, Plugin, PluginResult, RequestContext,
    StreamConnectionContext, priority,
};
use ferrum_edge::proxy::auth_lifetime::{
    StreamAuthTermination, effective_request_auth_deadline, request_is_authenticated,
};
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, KeyPair, SanType};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

fn build_cert(spiffe_uri: Option<&str>, dns: Option<&str>) -> Vec<u8> {
    let mut params = CertificateParams::default();
    if let Some(uri) = spiffe_uri {
        let id = SpiffeId::new(uri).unwrap();
        params
            .subject_alt_names
            .push(spiffe_id_to_san(&id).unwrap());
    }
    if let Some(dns_name) = dns {
        params.subject_alt_names.push(SanType::DnsName(
            rcgen::string::Ia5String::try_from(dns_name.to_string()).unwrap(),
        ));
    }
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.der().to_vec()
}

fn build_cert_with_uri_sans(uris: &[&str]) -> Vec<u8> {
    let mut params = CertificateParams::default();
    for uri in uris {
        params.subject_alt_names.push(SanType::URI(
            Ia5String::try_from((*uri).to_string()).unwrap(),
        ));
    }
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.der().to_vec()
}

fn empty_stream_ctx(cert_der: Option<Vec<u8>>) -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "tcp-proxy".to_string(),
        Some("tcp".to_string()),
        5432,
        BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&[] as &[Consumer])),
    );
    ctx.tls_client_cert_der = cert_der.map(Arc::new);
    ctx
}

#[test]
fn test_spiffe_identity_trait_contract() {
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "spiffe_identity");
    assert_eq!(plugin.priority(), priority::SPIFFE_IDENTITY);
    assert_eq!(
        plugin.supported_protocols(),
        HTTP_FAMILY_AND_STREAM_PROTOCOLS
    );
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
}

#[test]
fn test_spiffe_identity_rejects_config_fields() {
    let err = SpiffeIdentity::new(&json!({"unexpected_canary_key": true}))
        .err()
        .expect("unknown config must be rejected");
    assert!(err.contains("unsupported configuration field"), "{err}");
    assert!(
        !err.contains("unexpected_canary_key"),
        "the rejected key must not be echoed: {err}"
    );
}

#[tokio::test]
async fn test_http_request_extracts_spiffe_id() {
    let cert_der = build_cert(Some("spiffe://prod.example.com/ns/api/sa/default"), None);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    plugin.on_request_received(&mut ctx).await;

    assert_eq!(
        ctx.peer_spiffe_id.as_ref().map(SpiffeId::as_str),
        Some("spiffe://prod.example.com/ns/api/sa/default")
    );
}

#[tokio::test]
async fn test_http_request_ignores_non_spiffe_cert() {
    let cert_der = build_cert(None, Some("client.example.com"));
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    plugin.on_request_received(&mut ctx).await;

    assert!(ctx.peer_spiffe_id.is_none());
}

#[tokio::test]
async fn test_http_request_ignores_invalid_der() {
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(vec![0, 1, 2, 3]));

    plugin.on_request_received(&mut ctx).await;

    assert!(ctx.peer_spiffe_id.is_none());
}

#[tokio::test]
async fn test_http_request_rejects_duplicate_spiffe_uri_sans() {
    let cert_der = build_cert_with_uri_sans(&[
        "spiffe://prod.example.com/ns/api/sa/default",
        "spiffe://prod.example.com/ns/admin/sa/default",
    ]);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    let result = plugin.on_request_received(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
                "invalid SPIFFE identity certificate"
            );
        }
        other => panic!("expected duplicate SPIFFE URI SANs to reject, got {other:?}"),
    }
    assert!(ctx.peer_spiffe_id.is_none());
}

#[tokio::test]
async fn test_http_request_preserves_existing_spiffe_id() {
    let cert_der = build_cert(Some("spiffe://prod.example.com/ns/new/sa/default"), None);
    let existing = SpiffeId::new("spiffe://prod.example.com/ns/existing/sa/default").unwrap();
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.peer_spiffe_id = Some(existing);
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    plugin.on_request_received(&mut ctx).await;

    assert_eq!(
        ctx.peer_spiffe_id.as_ref().map(SpiffeId::as_str),
        Some("spiffe://prod.example.com/ns/existing/sa/default")
    );
}

/// Build a fresh per-request context sharing one connection's cert and
/// SPIFFE extraction cache, the way multiplexed HTTP/2 or HTTP/3 requests on
/// a single mTLS connection do.
fn ctx_on_connection(
    cert_der: &Arc<Vec<u8>>,
    cache: &Arc<SpiffeIdentityConnectionCache>,
) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::clone(cert_der));
    ctx.peer_spiffe_extraction_cache = Some(Arc::clone(cache));
    ctx
}

#[tokio::test]
async fn test_connection_cache_extracts_once_across_multiplexed_requests() {
    let cert_der = Arc::new(build_cert(
        Some("spiffe://prod.example.com/ns/api/sa/default"),
        None,
    ));
    let cache = Arc::new(SpiffeIdentityConnectionCache::new());
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();

    for _ in 0..3 {
        let mut ctx = ctx_on_connection(&cert_der, &cache);
        let result = plugin.on_request_received(&mut ctx).await;
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.peer_spiffe_id.as_ref().map(SpiffeId::as_str),
            Some("spiffe://prod.example.com/ns/api/sa/default")
        );
    }

    assert_eq!(
        cache.extraction_count(),
        1,
        "peer cert must be parsed once per connection, not once per request"
    );
}

#[tokio::test]
async fn test_connection_cache_rejects_duplicate_uri_sans_on_every_request() {
    let cert_der = Arc::new(build_cert_with_uri_sans(&[
        "spiffe://prod.example.com/ns/api/sa/default",
        "spiffe://prod.example.com/ns/admin/sa/default",
    ]));
    let cache = Arc::new(SpiffeIdentityConnectionCache::new());
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();

    for _ in 0..3 {
        let mut ctx = ctx_on_connection(&cert_der, &cache);
        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 403);
                assert!(body.contains("invalid SPIFFE identity"));
            }
            other => panic!("cached invalid-SVID outcome must reject every request, got {other:?}"),
        }
        assert!(ctx.peer_spiffe_id.is_none());
    }

    assert_eq!(cache.extraction_count(), 1);
}

#[tokio::test]
async fn test_connection_cache_non_spiffe_cert_is_noop_on_every_request() {
    let cert_der = Arc::new(build_cert(None, Some("client.example.com")));
    let cache = Arc::new(SpiffeIdentityConnectionCache::new());
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();

    for _ in 0..3 {
        let mut ctx = ctx_on_connection(&cert_der, &cache);
        let result = plugin.on_request_received(&mut ctx).await;
        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.peer_spiffe_id.is_none());
    }

    assert_eq!(cache.extraction_count(), 1);
}

#[tokio::test]
async fn test_connection_cache_unparsable_der_is_noop_on_every_request() {
    let cert_der = Arc::new(vec![0u8, 1, 2, 3]);
    let cache = Arc::new(SpiffeIdentityConnectionCache::new());
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();

    for _ in 0..3 {
        let mut ctx = ctx_on_connection(&cert_der, &cache);
        let result = plugin.on_request_received(&mut ctx).await;
        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.peer_spiffe_id.is_none());
    }

    assert_eq!(cache.extraction_count(), 1);
}

#[tokio::test]
async fn test_connection_cache_not_consulted_when_peer_spiffe_id_preset() {
    // A pre-stamped identity (e.g. node-waypoint eBPF attestation) must keep
    // precedence over peer-cert derivation, and the cache must stay untouched.
    let cert_der = Arc::new(build_cert(
        Some("spiffe://prod.example.com/ns/new/sa/default"),
        None,
    ));
    let cache = Arc::new(SpiffeIdentityConnectionCache::new());
    let existing = SpiffeId::new("spiffe://prod.example.com/ns/existing/sa/default").unwrap();
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();

    let mut ctx = ctx_on_connection(&cert_der, &cache);
    ctx.peer_spiffe_id = Some(existing);
    plugin.on_request_received(&mut ctx).await;

    assert_eq!(
        ctx.peer_spiffe_id.as_ref().map(SpiffeId::as_str),
        Some("spiffe://prod.example.com/ns/existing/sa/default")
    );
    assert_eq!(cache.extraction_count(), 0);
}

#[tokio::test]
async fn test_stream_connect_extracts_spiffe_metadata() {
    let cert_der = build_cert(Some("spiffe://prod.example.com/ns/tcp/sa/default"), None);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = empty_stream_ctx(Some(cert_der));

    plugin.on_stream_connect(&mut ctx).await;

    assert_eq!(
        ctx.metadata
            .as_ref()
            .and_then(|metadata| metadata.get("peer_spiffe_id"))
            .map(String::as_str),
        Some("spiffe://prod.example.com/ns/tcp/sa/default")
    );
}

#[tokio::test]
async fn test_stream_connect_rejects_duplicate_spiffe_uri_sans() {
    let cert_der = build_cert_with_uri_sans(&[
        "spiffe://prod.example.com/ns/tcp/sa/default",
        "spiffe://prod.example.com/ns/admin/sa/default",
    ]);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = empty_stream_ctx(Some(cert_der));

    let result = plugin.on_stream_connect(&mut ctx).await;

    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert!(ctx.metadata.is_none());
}

#[tokio::test]
async fn test_stream_connect_without_cert_is_noop() {
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = empty_stream_ctx(None);

    plugin.on_stream_connect(&mut ctx).await;

    assert!(ctx.metadata.is_none());
}

// ── SPIFFE trust-domain grammar (issue #5052) ─────────────────────────────

/// A trust domain whose first byte is `_` is legal under SPIFFE-ID §2.1 — the
/// spec constrains the character set, not the boundaries — and used to be
/// refused with 403 by Ferrum's own extra rule.
const BOUNDARY_PUNCTUATION_SVID: &str = "spiffe://_audit.example/ns/test/sa/client";

/// `spiffe://` + a 241-byte trust domain, above Ferrum's old 240-byte cap and
/// inside the spec's 255-byte limit.
fn long_trust_domain_svid() -> String {
    format!("spiffe://{}/workload", "a".repeat(241))
}

#[tokio::test]
async fn test_http_request_accepts_spec_legal_boundary_trust_domain() {
    let cert_der = build_cert(Some(BOUNDARY_PUNCTUATION_SVID), None);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    let result = plugin.on_request_received(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.peer_spiffe_id.as_ref().map(SpiffeId::as_str),
        Some(BOUNDARY_PUNCTUATION_SVID)
    );
}

#[tokio::test]
async fn test_http_request_accepts_a_241_byte_trust_domain() {
    let uri = long_trust_domain_svid();
    let cert_der = build_cert(Some(uri.as_str()), None);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    let result = plugin.on_request_received(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.peer_spiffe_id.as_ref().map(SpiffeId::as_str),
        Some(uri.as_str())
    );
}

#[tokio::test]
async fn test_stream_connect_accepts_spec_legal_boundary_trust_domain() {
    let cert_der = build_cert(Some(BOUNDARY_PUNCTUATION_SVID), None);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = empty_stream_ctx(Some(cert_der));

    let result = plugin.on_stream_connect(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .as_ref()
            .and_then(|metadata| metadata.get("peer_spiffe_id"))
            .map(String::as_str),
        Some(BOUNDARY_PUNCTUATION_SVID)
    );
}

// ── Certificate lifetime (GHSA-qqg9-3r2g-fh44) ────────────────────────────

/// Peer SVID with an explicit validity interval, in seconds relative to now.
fn svid_with_validity(uri: &str, not_before_secs: i64, not_after_secs: i64) -> Vec<u8> {
    let san = spiffe_id_to_san(&SpiffeId::new(uri).unwrap()).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![san];

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now + time::Duration::seconds(not_before_secs);
    params.not_after = now + time::Duration::seconds(not_after_secs);

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    params.self_signed(&key_pair).unwrap().der().to_vec()
}

fn assert_invalid_svid_reject(result: PluginResult) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
                "invalid SPIFFE identity certificate"
            );
            // The client learns nothing about the window it fell outside.
            assert!(!body.contains("notAfter"));
            assert!(!body.contains("notBefore"));
        }
        other => panic!("expected a fixed 403 rejection, got {other:?}"),
    }
}

const LIFETIME_SVID: &str = "spiffe://prod.example.com/ns/api/sa/default";

#[tokio::test]
async fn test_http_request_admits_the_svid_deadline_as_an_authenticated_principal() {
    let cert_der = svid_with_validity(LIFETIME_SVID, -60, 300);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.peer_spiffe_id.as_ref().map(SpiffeId::as_str),
        Some(LIFETIME_SVID)
    );
    assert!(ctx.has_certificate_spiffe_principal());

    // The SPIFFE-only chain (no Consumer, no mtls_auth) is what the shared
    // lifetime machinery must now recognize.
    assert!(request_is_authenticated(&ctx));
    let remaining =
        request_credential_deadline_remaining(&ctx).expect("the leaf notAfter must be published");
    assert!(remaining <= std::time::Duration::from_secs(302));
    assert!(remaining >= std::time::Duration::from_secs(290));

    let plan = effective_request_auth_deadline(&ctx, 3_600)
        .expect("an admitted SPIFFE principal must have an authorization deadline");
    assert_eq!(plan.termination, StreamAuthTermination::CredentialExpired);
}

#[tokio::test]
async fn test_http_request_rejects_an_expired_svid() {
    let cert_der = svid_with_validity(LIFETIME_SVID, -3_600, -60);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    assert_invalid_svid_reject(plugin.on_request_received(&mut ctx).await);
    assert!(ctx.peer_spiffe_id.is_none());
    assert!(!request_is_authenticated(&ctx));
    assert!(request_credential_deadline_at(&ctx).is_none());
}

#[tokio::test]
async fn test_http_request_rejects_a_not_yet_valid_svid() {
    let cert_der = svid_with_validity(LIFETIME_SVID, 3_600, 7_200);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    assert_invalid_svid_reject(plugin.on_request_received(&mut ctx).await);
    assert!(ctx.peer_spiffe_id.is_none());
}

#[tokio::test]
async fn test_connection_cache_reevaluates_svid_validity_on_every_request() {
    // The expensive DER parse is memoized per connection, but "is this SVID
    // valid right now" is time-dependent and must never be cached.
    let cert_der = Arc::new(svid_with_validity(LIFETIME_SVID, -3_600, -60));
    let cache = Arc::new(SpiffeIdentityConnectionCache::new());
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();

    for _ in 0..3 {
        let mut ctx = ctx_on_connection(&cert_der, &cache);
        assert_invalid_svid_reject(plugin.on_request_received(&mut ctx).await);
        assert!(ctx.peer_spiffe_id.is_none());
    }

    assert_eq!(cache.extraction_count(), 1);
}

#[tokio::test]
async fn test_connection_cache_returns_the_identical_captured_deadline() {
    let cert_der = Arc::new(svid_with_validity(LIFETIME_SVID, -60, 300));
    let cache = Arc::new(SpiffeIdentityConnectionCache::new());
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();

    let mut first = ctx_on_connection(&cert_der, &cache);
    plugin.on_request_received(&mut first).await;
    let captured = request_credential_deadline_at(&first).expect("first admission publishes one");

    let mut second = ctx_on_connection(&cert_der, &cache);
    plugin.on_request_received(&mut second).await;
    assert_eq!(
        request_credential_deadline_at(&second),
        Some(captured),
        "a cache hit must admit against the Instant captured at first success, never a fresh \
         conversion that a wall-clock rollback could push later"
    );
    assert_eq!(cache.extraction_count(), 1);
}

#[tokio::test]
async fn test_a_pre_stamped_identity_is_never_certificate_bounded() {
    // A node-waypoint eBPF-attested or HBONE-asserted principal carries no leaf
    // validity window, so it must not be treated as certificate-bounded.
    let cert_der = svid_with_validity(LIFETIME_SVID, -60, 300);
    let existing = SpiffeId::new("spiffe://prod.example.com/ns/existing/sa/default").unwrap();
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.peer_spiffe_id = Some(existing);
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    plugin.on_request_received(&mut ctx).await;

    assert!(!ctx.has_certificate_spiffe_principal());
    assert!(!request_is_authenticated(&ctx));
    assert!(request_credential_deadline_at(&ctx).is_none());
}

#[tokio::test]
async fn test_stream_connect_carries_the_svid_deadline() {
    let cert_der = svid_with_validity(LIFETIME_SVID, -60, 300);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = empty_stream_ctx(Some(cert_der));

    assert!(matches!(
        plugin.on_stream_connect(&mut ctx).await,
        PluginResult::Continue
    ));
    assert!(ctx.has_certificate_spiffe_principal());
    assert!(ctx.is_authenticated());
    let deadline = ctx
        .credential_deadline_at()
        .expect("on_stream_connect must carry the SVID deadline into the session");
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    assert!(remaining <= std::time::Duration::from_secs(302));
    assert!(remaining >= std::time::Duration::from_secs(290));
}

#[tokio::test]
async fn test_stream_connect_rejects_an_expired_svid() {
    let cert_der = svid_with_validity(LIFETIME_SVID, -3_600, -60);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = empty_stream_ctx(Some(cert_der));

    assert_invalid_svid_reject(plugin.on_stream_connect(&mut ctx).await);
    assert!(ctx.credential_deadline_at().is_none());
    assert!(!ctx.is_authenticated());
}

#[tokio::test]
async fn test_stream_pre_stamped_identity_is_never_certificate_bounded() {
    let cert_der = svid_with_validity(LIFETIME_SVID, -60, 300);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = empty_stream_ctx(Some(cert_der));
    ctx.insert_metadata(
        "peer_spiffe_id".to_string(),
        "spiffe://prod.example.com/ns/attested/sa/default".to_string(),
    );

    plugin.on_stream_connect(&mut ctx).await;

    assert!(!ctx.has_certificate_spiffe_principal());
    assert!(!ctx.is_authenticated());
    assert!(ctx.credential_deadline_at().is_none());
}

/// ~7,900 years out: the "no well-defined expiration" shape RFC 5280 spells
/// `99991231235959Z`, expressed as an offset `time::OffsetDateTime` can still
/// represent. Whether it converts to a monotonic `Instant` depends on the host
/// clock, which is exactly the platform split issue #5396 is about.
const NO_EXPIRATION_OFFSET_SECS: i64 = 250_000_000_000;

#[tokio::test]
async fn test_http_request_admits_an_svid_with_no_well_defined_expiration() {
    // A valid long-lived SVID must admit its principal on every platform: an
    // expiry the monotonic clock cannot express is not an invalid credential
    // and must not become the fixed 403 (issue #5396).
    let cert_der = svid_with_validity(LIFETIME_SVID, -60, NO_EXPIRATION_OFFSET_SECS);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.peer_spiffe_id.as_ref().map(SpiffeId::as_str),
        Some(LIFETIME_SVID)
    );
    assert!(ctx.has_certificate_spiffe_principal());
    assert!(request_is_authenticated(&ctx));

    // Where the expiry IS representable the leaf's own bound wins; where it is
    // not, the credential carries none and the finite authenticated-stream
    // maximum bounds the request instead. Either way an admitted principal is
    // still bounded.
    let plan = effective_request_auth_deadline(&ctx, 3_600)
        .expect("an admitted SPIFFE principal must have an authorization deadline");
    if request_credential_deadline_at(&ctx).is_none() {
        assert_eq!(
            plan.termination,
            StreamAuthTermination::AuthenticatedStreamMaxLifetime
        );
    }
}

#[tokio::test]
async fn test_stream_connect_admits_an_svid_with_no_well_defined_expiration() {
    let cert_der = svid_with_validity(LIFETIME_SVID, -60, NO_EXPIRATION_OFFSET_SECS);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = empty_stream_ctx(Some(cert_der));

    assert!(matches!(
        plugin.on_stream_connect(&mut ctx).await,
        PluginResult::Continue
    ));
    assert!(ctx.has_certificate_spiffe_principal());
    assert!(ctx.is_authenticated());
}

#[test]
fn test_admission_admits_an_unrepresentable_expiry_instead_of_refusing_it() {
    // Shape contract for the branch a Linux CI clock cannot reach: the
    // far-future arm publishes no bound, and only the unusable-interval arm
    // reaches the fixed 403 (issue #5396).
    let source = include_str!("../../../src/plugins/mesh/spiffe_identity.rs");
    for hook in ["fn on_request_received(", "fn on_stream_connect("] {
        let body = source
            .split(hook)
            .nth(1)
            .expect("the hook must exist")
            .split("CredentialDeadline::Unbounded =>")
            .nth(1)
            .expect("the far-future arm must be handled explicitly")
            .split("CredentialDeadline::Invalid =>")
            .next()
            .expect("bounded far-future arm");
        assert!(
            !body.contains("invalid_svid_reject"),
            "an expiry beyond the representable monotonic range must admit the \
             SVID, not refuse it"
        );
    }
    assert!(
        source.contains("CredentialDeadline::Invalid =>"),
        "an unusable validity interval must still refuse the SVID"
    );
}

#[test]
fn test_spiffe_identity_keeps_a_tcp_tls_listener_off_the_ktls_handoff() {
    // A kTLS leg is relayed by splice(2), where the session's authorization
    // deadline cannot be enforced.
    let plugin: Arc<dyn Plugin> = Arc::new(SpiffeIdentity::new(&json!({})).unwrap());
    assert!(plugin.admits_authenticated_stream_principal());
    assert!(!ferrum_edge::_test_support::ktls_handoff_eligible_for_test(
        true,
        false,
        false,
        &[plugin]
    ));
}

// ── Material-free invalid-SVID diagnostics (spiffe_identity-SOL-1) ─────────

const QUERY_CANARY: &str = "REVIEW_CANARY_SECRET_9f3c";
const USERINFO_CANARY: &str = "CANARY_PASSWORD_77";

/// URI SANs that are CA-signable X.509 URIs but invalid SPIFFE IDs, each
/// carrying a credential the diagnostic must never repeat.
fn credential_bearing_uri_sans() -> [String; 3] {
    [
        format!("spiffe://corp.example/ns/payments/sa/client?token={QUERY_CANARY}"),
        format!("spiffe://alice:{USERINFO_CANARY}@corp.example/ns/payments/sa/client"),
        format!("spiffe://corp.example/ns/payments/sa/client#{QUERY_CANARY}"),
    ]
}

fn assert_diagnostics_are_material_free(logs: &str, uri: &str) {
    assert!(
        logs.contains("rejecting peer cert with invalid SPIFFE URI SAN"),
        "the rejection must still be diagnosed at debug: {logs:?}"
    );
    super::plugin_utils::assert_no_secrets(
        logs,
        "invalid SPIFFE URI SAN rejection",
        &[QUERY_CANARY, USERINFO_CANARY, uri, "corp.example"],
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_http_invalid_spiffe_uri_san_diagnostic_never_echoes_the_uri() {
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    for uri in credential_bearing_uri_sans() {
        let cert_der = Arc::new(build_cert_with_uri_sans(&[uri.as_str()]));
        let cache = Arc::new(SpiffeIdentityConnectionCache::new());

        let (logs, guard) = super::plugin_utils::capture_debug_logs();
        // Repeated requests share the connection cache: the cached outcome
        // must be as material-free as the first derivation.
        for _ in 0..2 {
            let mut ctx = ctx_on_connection(&cert_der, &cache);
            assert_invalid_svid_reject(plugin.on_request_received(&mut ctx).await);
            assert!(ctx.peer_spiffe_id.is_none());
        }
        let mut uncached =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
        uncached.tls_client_cert_der = Some(Arc::clone(&cert_der));
        assert_invalid_svid_reject(plugin.on_request_received(&mut uncached).await);
        drop(guard);

        assert_diagnostics_are_material_free(&logs.contents(), &uri);
        let cached = format!("{cache:?}");
        assert!(
            !cached.contains(QUERY_CANARY) && !cached.contains(USERINFO_CANARY),
            "the connection cache must not retain the rejected URI: {cached}"
        );
        assert_eq!(cache.extraction_count(), 1);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_stream_invalid_spiffe_uri_san_diagnostic_never_echoes_the_uri() {
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    for uri in credential_bearing_uri_sans() {
        let mut ctx = empty_stream_ctx(Some(build_cert_with_uri_sans(&[uri.as_str()])));

        let (logs, guard) = super::plugin_utils::capture_debug_logs();
        assert_invalid_svid_reject(plugin.on_stream_connect(&mut ctx).await);
        drop(guard);

        assert!(ctx.metadata.is_none());
        assert_diagnostics_are_material_free(&logs.contents(), &uri);
    }
}

// ── Peerless classifier agrees with admission (spiffe_identity-MUSE-3) ─────

#[tokio::test(start_paused = true)]
async fn test_verified_peer_helper_refuses_once_the_captured_deadline_elapses() {
    let cert_der = Arc::new(svid_with_validity(LIFETIME_SVID, -60, 300));
    let cache = Arc::new(SpiffeIdentityConnectionCache::new());
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();

    let mut first = ctx_on_connection(&cert_der, &cache);
    assert!(matches!(
        plugin.on_request_received(&mut first).await,
        PluginResult::Continue
    ));
    assert!(has_verified_peer_spiffe_identity_for_test(
        &ctx_on_connection(&cert_der, &cache)
    ));

    // The paused tokio clock moves the monotonic deadline captured at first
    // admission into the past while the wall clock still reads inside the
    // leaf's window — exactly a wall-clock rollback.
    tokio::time::advance(Duration::from_secs(600)).await;

    let mut second = ctx_on_connection(&cert_der, &cache);
    assert_invalid_svid_reject(plugin.on_request_received(&mut second).await);
    assert!(
        !has_verified_peer_spiffe_identity_for_test(&ctx_on_connection(&cert_der, &cache)),
        "the peerless classifier must refuse exactly what admission refuses"
    );
}

#[tokio::test(start_paused = true)]
async fn test_verified_peer_helper_admits_before_any_deadline_is_captured() {
    // No admission yet on this connection: the slot is empty, so only the
    // wall-clock window decides — the two functions agree trivially.
    let cert_der = Arc::new(svid_with_validity(LIFETIME_SVID, -60, 300));
    let cache = Arc::new(SpiffeIdentityConnectionCache::new());
    tokio::time::advance(Duration::from_secs(600)).await;
    assert!(has_verified_peer_spiffe_identity_for_test(
        &ctx_on_connection(&cert_der, &cache)
    ));
}

// ── Opt-in admission policy (spiffe_identity-MUSE-4) ───────────────────────

fn assert_fixed_reject(result: PluginResult, expected_error: &str) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                json!({ "error": expected_error })
            );
            assert!(!body.contains("spiffe://"), "no identity is echoed: {body}");
        }
        other => panic!("expected a fixed 403 {expected_error:?}, got {other:?}"),
    }
}

const IDENTITY_REQUIRED: &str = "SPIFFE identity required";
const TRUST_DOMAIN_NOT_ALLOWED: &str = "SPIFFE trust domain not allowed";

#[test]
fn test_admission_policy_config_is_validated_without_echoing_values() {
    let too_many: Vec<String> = (0..65).map(|i| format!("td{i}.example")).collect();
    for (config, needle) in [
        (
            json!({"require_identity": "yes"}),
            "`require_identity` must be a boolean",
        ),
        (
            json!({"allowed_trust_domains": "prod.example.com"}),
            "must be an array",
        ),
        (
            json!({"allowed_trust_domains": []}),
            "at least one trust domain",
        ),
        (
            json!({"allowed_trust_domains": [7]}),
            "`allowed_trust_domains[0]` must be a string",
        ),
        (
            json!({"allowed_trust_domains": ["prod.example.com", "prod.example.com"]}),
            "`allowed_trust_domains[1]` duplicates",
        ),
        (
            json!({"allowed_trust_domains": ["spiffe://CANARY.example"]}),
            "`allowed_trust_domains[0]` is not a valid SPIFFE trust domain",
        ),
        (
            json!({ "allowed_trust_domains": too_many }),
            "at most 64 entries",
        ),
    ] {
        let err = SpiffeIdentity::new(&config)
            .err()
            .unwrap_or_else(|| panic!("{config} must be rejected"));
        assert!(err.contains(needle), "{config}: {err}");
        assert!(
            !err.contains("CANARY"),
            "the rejected value must not be echoed: {err}"
        );
    }

    for valid in [
        json!(null),
        json!({}),
        json!({"require_identity": false}),
        json!({"require_identity": true}),
        json!({"allowed_trust_domains": ["prod.example.com", "_audit.example"]}),
        json!({"forward_header": "x-spiffe-id"}),
    ] {
        assert!(
            SpiffeIdentity::new(&valid).is_ok(),
            "{valid} must be accepted"
        );
    }
}

#[tokio::test]
async fn test_require_identity_refuses_every_identity_absence_on_http() {
    let plugin = SpiffeIdentity::new(&json!({"require_identity": true})).unwrap();
    for cert in [
        None,
        Some(build_cert(None, Some("client.example.com"))),
        Some(vec![0u8, 1, 2, 3]),
    ] {
        let mut ctx =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
        ctx.tls_client_cert_der = cert.map(Arc::new);
        assert_fixed_reject(
            plugin.on_request_received(&mut ctx).await,
            IDENTITY_REQUIRED,
        );
        assert!(ctx.peer_spiffe_id.is_none());
    }

    let mut admitted =
        RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    admitted.tls_client_cert_der = Some(Arc::new(build_cert(Some(LIFETIME_SVID), None)));
    assert!(matches!(
        plugin.on_request_received(&mut admitted).await,
        PluginResult::Continue
    ));
    assert_eq!(
        admitted.peer_spiffe_id.as_ref().map(SpiffeId::as_str),
        Some(LIFETIME_SVID)
    );

    // A pre-stamped identity counts as present.
    let mut pre_stamped =
        RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    pre_stamped.peer_spiffe_id = Some(SpiffeId::new(LIFETIME_SVID).unwrap());
    assert!(matches!(
        plugin.on_request_received(&mut pre_stamped).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_require_identity_refuses_every_identity_absence_on_streams() {
    let plugin = SpiffeIdentity::new(&json!({"require_identity": true})).unwrap();
    for cert in [
        None,
        Some(build_cert(None, Some("client.example.com"))),
        Some(vec![0u8, 1, 2, 3]),
    ] {
        let mut ctx = empty_stream_ctx(cert);
        assert_fixed_reject(plugin.on_stream_connect(&mut ctx).await, IDENTITY_REQUIRED);
        assert!(!ctx.is_authenticated());
    }

    let mut admitted = empty_stream_ctx(Some(build_cert(Some(LIFETIME_SVID), None)));
    assert!(matches!(
        plugin.on_stream_connect(&mut admitted).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_default_config_still_admits_identity_absence() {
    // Defaults are byte-identical to the extraction-only behavior.
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
    let mut stream = empty_stream_ctx(None);
    assert!(matches!(
        plugin.on_stream_connect(&mut stream).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_allowed_trust_domains_gate_certificate_identities_on_http() {
    let plugin =
        SpiffeIdentity::new(&json!({"allowed_trust_domains": ["prod.example.com"]})).unwrap();

    let mut listed =
        RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    listed.tls_client_cert_der = Some(Arc::new(build_cert(Some(LIFETIME_SVID), None)));
    assert!(matches!(
        plugin.on_request_received(&mut listed).await,
        PluginResult::Continue
    ));
    assert!(listed.has_certificate_spiffe_principal());

    let cert_der = Arc::new(build_cert(
        Some("spiffe://other.example.com/ns/api/sa/default"),
        None,
    ));
    let cache = Arc::new(SpiffeIdentityConnectionCache::new());
    for _ in 0..2 {
        let mut unlisted = ctx_on_connection(&cert_der, &cache);
        assert_fixed_reject(
            plugin.on_request_received(&mut unlisted).await,
            TRUST_DOMAIN_NOT_ALLOWED,
        );
        assert!(unlisted.peer_spiffe_id.is_none());
        assert!(!request_is_authenticated(&unlisted));
    }

    // The policy applies to a pre-stamped identity too.
    let mut pre_stamped =
        RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    pre_stamped.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://other.example.com/ns/api/sa/default").unwrap());
    assert_fixed_reject(
        plugin.on_request_received(&mut pre_stamped).await,
        TRUST_DOMAIN_NOT_ALLOWED,
    );

    // No identity at all is not a trust-domain question: it passes unless
    // `require_identity` is also set.
    let mut anonymous =
        RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    assert!(matches!(
        plugin.on_request_received(&mut anonymous).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_allowed_trust_domains_gate_stream_identities() {
    let plugin =
        SpiffeIdentity::new(&json!({"allowed_trust_domains": ["prod.example.com"]})).unwrap();

    let mut listed = empty_stream_ctx(Some(build_cert(Some(LIFETIME_SVID), None)));
    assert!(matches!(
        plugin.on_stream_connect(&mut listed).await,
        PluginResult::Continue
    ));
    assert!(listed.has_certificate_spiffe_principal());

    let mut unlisted = empty_stream_ctx(Some(build_cert(
        Some("spiffe://other.example.com/ns/tcp/sa/default"),
        None,
    )));
    assert_fixed_reject(
        plugin.on_stream_connect(&mut unlisted).await,
        TRUST_DOMAIN_NOT_ALLOWED,
    );
    assert!(unlisted.metadata.is_none());
    assert!(!unlisted.is_authenticated());

    for (pre_stamped, admitted) in [
        ("spiffe://prod.example.com/ns/attested/sa/default", true),
        ("spiffe://other.example.com/ns/attested/sa/default", false),
        ("not a spiffe id", false),
    ] {
        let mut ctx = empty_stream_ctx(None);
        ctx.insert_metadata("peer_spiffe_id".to_string(), pre_stamped.to_string());
        let result = plugin.on_stream_connect(&mut ctx).await;
        if admitted {
            assert!(matches!(result, PluginResult::Continue), "{pre_stamped}");
        } else {
            assert_fixed_reject(result, TRUST_DOMAIN_NOT_ALLOWED);
        }
    }
}

#[test]
fn test_admission_policy_withdraws_hbone_inner_reuse() {
    for (config, reusable) in [
        (json!({}), true),
        (json!({"forward_header": "x-spiffe-id"}), true),
        (json!({"require_identity": false}), true),
        (json!({"require_identity": true}), false),
        (
            json!({"allowed_trust_domains": ["prod.example.com"]}),
            false,
        ),
    ] {
        let plugin = SpiffeIdentity::new(&config).unwrap();
        assert_eq!(plugin.allows_hbone_inner_reuse(), reusable, "{config}");
    }
}

// ── Backend identity propagation (spiffe_identity-MUSE-5) ──────────────────

#[tokio::test]
async fn test_forward_header_replaces_every_client_copy_with_the_admitted_identity() {
    let plugin = SpiffeIdentity::new(&json!({"forward_header": "X-Spiffe-Id"})).unwrap();
    assert!(plugin.modifies_request_headers());

    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(build_cert(Some(LIFETIME_SVID), None)));
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));

    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert(
        "x-spiffe-id".to_string(),
        "spiffe://attacker.example/ns/forged/sa/x".to_string(),
    );
    headers.insert("X_Spiffe_Id".to_string(), "forged".to_string());
    headers.insert("accept".to_string(), "*/*".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    assert_eq!(
        headers.get("x-spiffe-id").map(String::as_str),
        Some(LIFETIME_SVID)
    );
    assert!(!headers.contains_key("X_Spiffe_Id"));
    assert_eq!(headers.get("accept").map(String::as_str), Some("*/*"));
    assert_eq!(headers.len(), 2);
}

#[tokio::test]
async fn test_forward_header_strips_client_copies_without_an_identity() {
    let plugin = SpiffeIdentity::new(&json!({"forward_header": "x-spiffe-id"})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));

    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert(
        "X-SPIFFE-ID".to_string(),
        "spiffe://attacker.example/ns/forged/sa/x".to_string(),
    );
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        headers.is_empty(),
        "a client-chosen identity must never reach the backend: {headers:?}"
    );
}

#[tokio::test]
async fn test_default_config_forwards_nothing() {
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(build_cert(Some(LIFETIME_SVID), None)));
    plugin.on_request_received(&mut ctx).await;

    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-spiffe-id".to_string(), "client-value".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        headers.get("x-spiffe-id").map(String::as_str),
        Some("client-value"),
        "without forward_header the plugin must not touch backend headers"
    );
}

#[test]
fn test_forward_header_refuses_gateway_owned_and_invalid_names() {
    for name in [
        "authorization",
        "Proxy-Authorization",
        "cookie",
        "host",
        "connection",
        "forwarded",
        "x-real-ip",
        "X-Forwarded-Client-Cert",
        "x_forwarded_for",
        "x-consumer-username",
        "X_Consumer_Id",
        "x-ferrum-hops",
        "X_Path_Param_Id",
        "X-Geo-Country",
    ] {
        let err = SpiffeIdentity::new(&json!({ "forward_header": name }))
            .err()
            .unwrap_or_else(|| panic!("{name} must be refused"));
        assert!(err.contains("gateway-owned"), "{name}: {err}");
    }
    for invalid in [
        json!(""),
        json!("bad header"),
        json!(":authority"),
        json!(7),
    ] {
        assert!(
            SpiffeIdentity::new(&json!({ "forward_header": invalid })).is_err(),
            "{invalid} must be refused"
        );
    }
}
