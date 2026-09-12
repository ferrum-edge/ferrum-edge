use ferrum_edge::_test_support::{
    request_credential_deadline_at, request_credential_deadline_remaining,
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
use std::sync::Arc;

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
    let err = SpiffeIdentity::new(&json!({"unexpected": true}))
        .err()
        .expect("unknown config must be rejected");
    assert!(err.contains("no configuration fields are supported"));
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
