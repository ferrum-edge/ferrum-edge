//! Adversarial-parser entry points for the `fuzz/` cargo-fuzz workspace.
//!
//! This module is intentionally narrow: it exposes pure decode/validate helpers
//! with explicit input, recursion, allocation, and iteration budgets so the
//! fuzz lane can exercise hostile inputs without widening the production API.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::{Bytes, BytesMut};
use serde_json::Value;

use crate::config::BackendEgressPolicy;
use crate::config::file_loader::decode_and_validate_config_document;
use crate::config_sources::k8s::{K8sObject, K8sTranslationOptions, translate_k8s_objects};
use crate::identity::ca::PublishedJwtAuthority;
use crate::identity::jwt_svid::{
    authorities_from_jwks, decoding_key_for_authority, jwks_document, parse_strict_json_object,
    validate_jwt_svid, validate_published_authorities,
};
use crate::identity::spiffe::TrustDomain;
use crate::plugins::otel_tracing::{OtelTracing, build_traceparent};
use crate::plugins::validate_plugin_config;
use crate::proxy::mesh_udp_frame::{MAX_FRAME_PAYLOAD, encode_datagram, pop_framed_datagram};
use crate::proxy::proxy_protocol::parse_proxy_protocol_header_bytes;
use crate::tls::crl_policy::{classify_crl_window, crl_next_update_unix};
use crate::tls::ocsp::{MAX_OCSP_RESPONSE_BYTES, OcspCryptoPolicy, validate_structure_with_policy};
use crate::tls::{
    MAX_PEM_CERTIFICATE_RECORDS, parse_pem_certificate_bundle, parse_pem_private_key,
};
use rustls::pki_types::CertificateRevocationListDer;
use rustls::pki_types::pem::PemObject;

/// Hard cap on arbitrary fuzz input bytes passed into a single target invocation.
pub const MAX_FUZZ_INPUT_BYTES: usize = 64 * 1024;

/// Maximum JSON/YAML nesting depth accepted before decode is rejected fail-closed.
pub const MAX_JSON_DEPTH: usize = 64;

/// Maximum number of Kubernetes objects deserialized from one fuzz input.
pub const MAX_K8S_OBJECTS: usize = 32;

/// Maximum framed datagrams drained from one fuzz input stream.
pub const MAX_MESH_UDP_FRAMES: usize = 256;

/// Plugin names exercised by the structured plugin-config fuzz target.
pub const FUZZ_PLUGIN_NAMES: &[&str] = &[
    "cors",
    "rate_limiting",
    "correlation_id",
    "otel_tracing",
    "security_headers",
    "ip_restriction",
    "request_size_limiting",
    "body_validator",
];

/// Trust domain of the fixed JWT-SVID bundle the `jwt_svid` target validates
/// against.
pub const FUZZ_JWT_SVID_TRUST_DOMAIN: &str = "fuzz.example";

/// Key id of the single authority in that bundle.
pub const FUZZ_JWT_SVID_KEY_ID: &str = "fuzz-rsa-1";

/// Audience every `jwt_svid` token is validated for.
pub const FUZZ_JWT_SVID_AUDIENCE: &str = "ferrum-fuzz";

/// Input modes of the `jwt_svid` target, selected by the first byte modulo
/// this count: `0` strict-JSON object parse, `1` a raw compact token, `2` a
/// header and claims JSON pair (split at the first NUL) wrapped into a token
/// with a fixed bogus signature, `3` authority public-key PEM admission, `4`
/// an externally supplied JWKS bundle (`authorities_from_jwks`).
pub const FUZZ_JWT_SVID_MODES: u8 = 5;

/// Input modes of the `tls_material` target, selected by the first byte modulo
/// this count: `0` PEM certificate bundle admission, `1` PEM private-key
/// admission, `2` a PEM CRL bundle with each record's validity window
/// classified, `3` one DER CRL's validity window.
pub const FUZZ_TLS_MATERIAL_MODES: u8 = 4;

/// The fixed "now" CRL windows are classified against (2027-01-15), so the
/// target is deterministic.
pub const FUZZ_CRL_NOW_UNIX: i64 = 1_800_000_000;

/// CRL records classified from one PEM input.
pub const MAX_FUZZ_CRL_RECORDS: usize = 64;

/// Public half of the repository's synthetic RSA test key pair
/// (`tests/fixtures/`). It is test material, never production key material.
const FUZZ_JWT_SVID_PUBLIC_KEY_PEM: &str = include_str!("../tests/fixtures/test_rsa_public.pem");

/// Private half of the same synthetic pair. Used only by [`smoke_invariants`]
/// to prove the fixed bundle is admitted, so the fuzz target reaches signature
/// verification rather than failing every input at authority admission.
const FUZZ_JWT_SVID_PRIVATE_KEY_PEM: &str = include_str!("../tests/fixtures/test_rsa_private.pem");

/// Reject inputs that exceed the global fuzz byte budget.
pub fn enforce_input_budget(data: &[u8]) -> Result<&[u8], ()> {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return Err(());
    }
    Ok(data)
}

/// Measure structural depth of a parsed JSON value.
pub fn json_value_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(json_value_depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(json_value_depth).max().unwrap_or(0),
        _ => 1,
    }
}

/// Fail closed when nesting exceeds [`MAX_JSON_DEPTH`].
pub fn reject_excessive_json_depth(value: &Value) -> Result<(), ()> {
    if json_value_depth(value) > MAX_JSON_DEPTH {
        return Err(());
    }
    Ok(())
}

/// Parse a W3C `traceparent` header. Invalid input returns `None` (fail closed).
pub fn parse_traceparent_header(value: &str) -> Option<()> {
    OtelTracing::parse_traceparent(value).map(|_| ())
}

/// Round-trip invariant: a header accepted by the parser must re-encode to an
/// equivalent accepted header when sampled flags are preserved.
pub fn traceparent_round_trip_invariant(value: &str) -> bool {
    let Some(parsed) = OtelTracing::parse_traceparent(value) else {
        return true;
    };
    let rebuilt = build_traceparent("00", parsed.trace_id, parsed.parent_span_id, parsed.flags);
    OtelTracing::parse_traceparent(&rebuilt).is_some()
}

/// Decode and validate a config document from UTF-8 bytes. Errors are expected
/// for hostile input; panics are not.
pub fn fuzz_decode_config_document(content: &str) -> Result<(), String> {
    decode_and_validate_config_document(content, 30, &BackendEgressPolicy::unrestricted())
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Parse a complete PROXY protocol header from bytes.
pub fn fuzz_parse_proxy_protocol(data: &[u8]) -> Result<(), String> {
    parse_proxy_protocol_header_bytes(data)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Parse a datagram PROXY v2 DGRAM header, walk its auth/freshness TLV region,
/// and decode any freshness record it carries.
///
/// Bounded, allocation-free, and fail-closed. The `Result` carries only a
/// fixed-cardinality reason — never payload bytes, tag bytes, secret material,
/// sequence values, or addresses asserted inside the envelope.
pub fn fuzz_parse_datagram_header(data: &[u8]) -> Result<(), String> {
    crate::proxy::datagram_client_address::parse_datagram_header(data)
        .map_err(|error| error.reason().to_string())
}

/// Drain length-prefixed mesh UDP frames from a byte stream with a hard frame cap.
pub fn fuzz_drain_mesh_udp_frames(data: &[u8]) -> Result<Vec<Bytes>, String> {
    let mut buf = BytesMut::from(data);
    let mut frames = Vec::new();
    while let Some(frame) = pop_framed_datagram(&mut buf) {
        if frames.len() >= MAX_MESH_UDP_FRAMES {
            return Err("mesh UDP frame iteration budget exceeded".to_string());
        }
        frames.push(frame);
    }
    Ok(frames)
}

/// Encode then decode round-trip for a single payload (deterministic invariant).
pub fn mesh_udp_frame_round_trip(payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Ok(());
    }
    let mut wire = BytesMut::new();
    encode_datagram(&mut wire, payload).map_err(|error| error.to_string())?;
    let mut buf = wire;
    let decoded =
        pop_framed_datagram(&mut buf).ok_or_else(|| "round-trip frame missing".to_string())?;
    if decoded.as_ref() != payload {
        return Err("round-trip payload mismatch".to_string());
    }
    if pop_framed_datagram(&mut buf).is_some() {
        return Err("round-trip produced trailing frame".to_string());
    }
    Ok(())
}

/// Deserialize and translate Kubernetes objects from JSON bytes.
pub fn fuzz_translate_k8s_json(data: &[u8]) -> Result<(), String> {
    let value: Value = serde_json::from_slice(data).map_err(|error| error.to_string())?;
    reject_excessive_json_depth(&value).map_err(|()| "json depth budget exceeded".to_string())?;
    if value
        .as_array()
        .is_some_and(|objects| objects.len() > MAX_K8S_OBJECTS)
    {
        return Err("k8s object count budget exceeded".to_string());
    }
    let objects: Vec<K8sObject> = if value.is_array() {
        serde_json::from_value(value).map_err(|error| error.to_string())?
    } else {
        vec![serde_json::from_value(value).map_err(|error| error.to_string())?]
    };
    let options = K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").map_err(|error| error.to_string())?,
    );
    translate_k8s_objects(&objects, options)
        .map(|_| ())
        .map_err(|error| format!("{error:?}"))
}

/// Validate a plugin configuration JSON blob against a representative plugin set.
pub fn fuzz_validate_plugin_config(data: &[u8]) -> Result<(), String> {
    let Some((&selector, payload)) = data.split_first() else {
        return Ok(());
    };
    if payload.is_empty() {
        return Ok(());
    }
    let value: Value = serde_json::from_slice(payload).map_err(|error| error.to_string())?;
    reject_excessive_json_depth(&value).map_err(|()| "json depth budget exceeded".to_string())?;
    let plugin_idx = selector as usize % FUZZ_PLUGIN_NAMES.len();
    let plugin_name = FUZZ_PLUGIN_NAMES[plugin_idx];
    validate_plugin_config(plugin_name, &value)
}

/// Structural OCSP response validation under both cryptographic profiles
/// (issue #6584). Returns `false` only when an invariant is violated:
///
/// - an accepted response's reported length is the input length, it holds
///   between one and sixty-four `SingleResponse` entries, and it fits
///   [`MAX_OCSP_RESPONSE_BYTES`];
/// - the FIPS-enforced profile only narrows the interoperable one, so it never
///   accepts what the interoperable profile refuses, and when both accept they
///   report the same structure.
pub fn ocsp_structure_invariant(data: &[u8]) -> bool {
    let interoperable = validate_structure_with_policy(data, OcspCryptoPolicy::Interoperable);
    let fips = validate_structure_with_policy(data, OcspCryptoPolicy::FipsEnforced);
    if let Ok(structure) = &interoperable
        && (structure.der_len != data.len()
            || structure.single_responses == 0
            || structure.single_responses > 64
            || data.len() > MAX_OCSP_RESPONSE_BYTES)
    {
        return false;
    }
    match (&interoperable, &fips) {
        (Err(_), Ok(_)) => false,
        (Ok(interoperable), Ok(fips)) => interoperable == fips,
        _ => true,
    }
}

/// Number of `SingleResponse` entries in an accepted OCSP response, or the
/// interoperable profile's refusal.
pub fn fuzz_validate_ocsp_structure(data: &[u8]) -> Result<usize, String> {
    validate_structure_with_policy(data, OcspCryptoPolicy::Interoperable)
        .map(|structure| structure.single_responses)
}

fn fuzz_jwt_trust_domain() -> Option<TrustDomain> {
    TrustDomain::new(FUZZ_JWT_SVID_TRUST_DOMAIN).ok()
}

fn fuzz_jwt_bundle() -> Option<&'static BTreeMap<TrustDomain, Vec<PublishedJwtAuthority>>> {
    static BUNDLE: OnceLock<Option<BTreeMap<TrustDomain, Vec<PublishedJwtAuthority>>>> =
        OnceLock::new();
    BUNDLE
        .get_or_init(|| {
            let trust_domain = fuzz_jwt_trust_domain()?;
            let authority = PublishedJwtAuthority::new(
                trust_domain.clone(),
                FUZZ_JWT_SVID_KEY_ID,
                FUZZ_JWT_SVID_PUBLIC_KEY_PEM,
            );
            Some(BTreeMap::from([(trust_domain, vec![authority])]))
        })
        .as_ref()
}

/// Whether `token` validates against the fixed fuzz bundle.
pub fn fuzz_jwt_svid_validates(token: &str) -> bool {
    fuzz_jwt_bundle()
        .is_some_and(|bundle| validate_jwt_svid(token, FUZZ_JWT_SVID_AUDIENCE, bundle).is_ok())
}

/// Hand-rolled JWT-SVID parsing and validation (issue #6584): the strict
/// duplicate-key-refusing JSON object parser, the compact-token validator up to
/// and including signature verification, and authority PEM admission. See
/// [`FUZZ_JWT_SVID_MODES`] for the input layout.
///
/// Returns `false` only when an invariant is violated: a token-mode input
/// validated. No fuzz input can carry the fixed authority's RSA signature over
/// fresh claims, so an accepted token means signature verification was
/// bypassed.
pub fn fuzz_jwt_svid_invariant(data: &[u8]) -> bool {
    let Some((&selector, payload)) = data.split_first() else {
        return true;
    };
    match selector % FUZZ_JWT_SVID_MODES {
        0 => {
            let _ = parse_strict_json_object(payload);
            true
        }
        1 => match std::str::from_utf8(payload) {
            Ok(token) => !fuzz_jwt_svid_validates(token),
            Err(_) => true,
        },
        2 => {
            let (header, claims) = match payload.iter().position(|byte| *byte == 0) {
                Some(split) => (&payload[..split], &payload[split + 1..]),
                None => (payload, &[][..]),
            };
            let token = format!(
                "{}.{}.c2lnbmF0dXJl",
                URL_SAFE_NO_PAD.encode(header),
                URL_SAFE_NO_PAD.encode(claims)
            );
            !fuzz_jwt_svid_validates(&token)
        }
        3 => {
            if let (Ok(pem), Some(trust_domain)) =
                (std::str::from_utf8(payload), fuzz_jwt_trust_domain())
            {
                let authority =
                    PublishedJwtAuthority::new(trust_domain.clone(), FUZZ_JWT_SVID_KEY_ID, pem);
                let _ = validate_published_authorities(&trust_domain, &[authority]);
            }
            true
        }
        _ => jwks_round_trip_invariant(payload),
    }
}

/// An externally supplied JWKS the bundle consumer accepts must survive
/// publication and re-consumption unchanged: same key ids, public keys, and
/// effective verification algorithms. The declared `alg` itself may change —
/// publication states the algorithm an undeclared key is already limited to —
/// so the comparison is on what `decoding_key_for_authority` would allow.
/// Anything else means the hand-written JWK/SPKI conversions disagree.
fn jwks_round_trip_invariant(document: &[u8]) -> bool {
    let Some(trust_domain) = fuzz_jwt_trust_domain() else {
        return true;
    };
    let Ok(accepted) = authorities_from_jwks(&trust_domain, document) else {
        return true;
    };
    let Ok(published) = jwks_document(&accepted) else {
        return false;
    };
    let Ok(reconsumed) = authorities_from_jwks(&trust_domain, &published) else {
        return false;
    };
    let allowed = |authority: &PublishedJwtAuthority| {
        decoding_key_for_authority(authority).map(|(_, algorithms)| algorithms)
    };
    accepted.len() == reconsumed.len()
        && accepted.iter().zip(&reconsumed).all(|(first, second)| {
            first.key_id == second.key_id
                && first.public_key_pem == second.public_key_pem
                && matches!(
                    (allowed(first), allowed(second)),
                    (Ok(a), Ok(b)) if a == b
                )
        })
}

/// TLS material admission (issue #6584): Ferrum's own record limits, trailing
/// material handling, and CRL window rules on top of the `rustls-pki-types`
/// and `x509-parser` decoders. See [`FUZZ_TLS_MATERIAL_MODES`] for the input
/// layout.
///
/// Returns `false` only when an invariant is violated: an accepted certificate
/// bundle is empty or over the record limit, or a CRL admitted at
/// [`FUZZ_CRL_NOW_UNIX`] does not report a `nextUpdate` after it.
pub fn fuzz_tls_material_invariant(data: &[u8]) -> bool {
    let Some((&selector, payload)) = data.split_first() else {
        return true;
    };
    match selector % FUZZ_TLS_MATERIAL_MODES {
        0 => match parse_pem_certificate_bundle(payload, "fuzz", "fuzz") {
            Ok(certificates) => {
                !certificates.is_empty() && certificates.len() <= MAX_PEM_CERTIFICATE_RECORDS
            }
            Err(_) => true,
        },
        1 => {
            let _ = parse_pem_private_key(payload, "fuzz", "fuzz");
            true
        }
        2 => CertificateRevocationListDer::pem_slice_iter(payload)
            .take(MAX_FUZZ_CRL_RECORDS)
            .filter_map(Result::ok)
            .all(|crl| crl_window_invariant(&crl)),
        _ => crl_window_invariant(&CertificateRevocationListDer::from(payload)),
    }
}

/// Whether a JWKS bundle is accepted for the fixed fuzz trust domain. Used by
/// the seed tests to prove the valid seeds reach the round trip.
pub fn fuzz_jwks_accepts(document: &[u8]) -> bool {
    fuzz_jwt_trust_domain()
        .is_some_and(|trust_domain| authorities_from_jwks(&trust_domain, document).is_ok())
}

/// Whether one DER CRL is inside its validity window at [`FUZZ_CRL_NOW_UNIX`].
pub fn fuzz_crl_window_accepts(der: &[u8]) -> bool {
    classify_crl_window(&CertificateRevocationListDer::from(der), FUZZ_CRL_NOW_UNIX).is_ok()
}

fn crl_window_invariant(crl: &CertificateRevocationListDer<'_>) -> bool {
    match classify_crl_window(crl, FUZZ_CRL_NOW_UNIX) {
        Ok(()) => crl_next_update_unix(crl).is_some_and(|next| next > FUZZ_CRL_NOW_UNIX),
        Err(_) => true,
    }
}

/// A JWT-SVID for the fixed fuzz bundle, signed with the synthetic test key and
/// valid for five minutes. Smoke-only: see [`smoke_invariants`].
fn signed_fuzz_jwt_svid() -> Result<String, String> {
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(FUZZ_JWT_SVID_PRIVATE_KEY_PEM.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(FUZZ_JWT_SVID_KEY_ID.to_string());
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "sub": format!("spiffe://{FUZZ_JWT_SVID_TRUST_DOMAIN}/workload"),
        "aud": [FUZZ_JWT_SVID_AUDIENCE],
        "iat": now,
        "exp": now + 300,
    });
    jsonwebtoken::encode(&header, &claims, &key).map_err(|error| error.to_string())
}

/// Deterministic smoke helper used by hosted CI property checks.
pub fn smoke_invariants() -> Result<(), String> {
    let valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    if parse_traceparent_header(valid).is_none() {
        return Err("valid traceparent rejected".to_string());
    }
    if !traceparent_round_trip_invariant(valid) {
        return Err("traceparent round-trip failed".to_string());
    }
    mesh_udp_frame_round_trip(b"smoke")?;
    let proxy_v1 = b"PROXY TCP4 127.0.0.1 10.0.0.1 12345 443\r\n";
    fuzz_parse_proxy_protocol(proxy_v1)?;
    let mut datagram = Vec::from(*b"\r\n\r\n\x00\r\nQUIT\n");
    datagram.extend_from_slice(&[0x21, 0x12, 0x00, 0x0c]);
    datagram.extend_from_slice(&[203, 0, 113, 9, 10, 0, 0, 5]);
    datagram.extend_from_slice(&41234u16.to_be_bytes());
    datagram.extend_from_slice(&5353u16.to_be_bytes());
    datagram.extend_from_slice(b"q");
    fuzz_parse_datagram_header(&datagram)?;
    // The authenticated shape: a freshness TLV (0xE1, 29-byte value) followed by
    // the tag TLV (0xE0, 32 bytes). The parser must walk both and decode the
    // freshness value without needing the secret.
    let mut authenticated = Vec::from(*b"\r\n\r\n\x00\r\nQUIT\n");
    authenticated.extend_from_slice(&[0x21, 0x12]);
    authenticated.extend_from_slice(&79u16.to_be_bytes());
    authenticated.extend_from_slice(&[203, 0, 113, 9, 10, 0, 0, 5]);
    authenticated.extend_from_slice(&41234u16.to_be_bytes());
    authenticated.extend_from_slice(&5353u16.to_be_bytes());
    authenticated.extend_from_slice(&[0xE1, 0x00, 0x1D, 0x01]);
    authenticated.extend_from_slice(&1u32.to_be_bytes());
    authenticated.extend_from_slice(&1u64.to_be_bytes());
    authenticated.extend_from_slice(&0u64.to_be_bytes());
    authenticated.extend_from_slice(&1_760_000_000_000u64.to_be_bytes());
    authenticated.extend_from_slice(&[0xE0, 0x00, 0x20]);
    authenticated.extend_from_slice(&[0xAA; 32]);
    authenticated.extend_from_slice(b"q");
    fuzz_parse_datagram_header(&authenticated)?;
    let config =
        r#"{"version":"1","proxies":[],"consumers":[],"plugin_configs":[],"upstreams":[]}"#;
    fuzz_decode_config_document(config)?;
    fuzz_validate_plugin_config(b"0{\"allowed_origins\":[\"*\"]}")?;
    // The fixed JWT-SVID bundle must be admitted and must verify a genuinely
    // signed token; otherwise every `jwt_svid` input would stop at authority
    // admission and the target would fuzz nothing past it. The same token in
    // token mode must trip the forgery invariant, proving it can fire.
    let signed = signed_fuzz_jwt_svid()?;
    if !fuzz_jwt_svid_validates(&signed) {
        return Err("fixed fuzz JWT-SVID bundle rejected a correctly signed token".to_string());
    }
    let mut token_mode = vec![1_u8];
    token_mode.extend_from_slice(signed.as_bytes());
    if fuzz_jwt_svid_invariant(&token_mode) {
        return Err("JWT-SVID forgery invariant did not fire for an accepted token".to_string());
    }
    // Flip a byte of the decoded signature and re-encode it canonically, so
    // the token is refused by RSA verification rather than by the strict
    // base64url decoder (editing only the last character can change nothing
    // but unused trailing bits).
    let (signing_input, signature) = signed
        .rsplit_once('.')
        .ok_or_else(|| "signed JWT-SVID has no signature segment".to_string())?;
    let mut signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|error| error.to_string())?;
    let Some(first) = signature.first_mut() else {
        return Err("signed JWT-SVID has an empty signature".to_string());
    };
    *first ^= 0x01;
    let tampered = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(&signature));
    let mut tampered_mode = vec![1_u8];
    tampered_mode.extend_from_slice(tampered.as_bytes());
    if !fuzz_jwt_svid_invariant(&tampered_mode) {
        return Err("a tampered JWT-SVID signature validated".to_string());
    }
    if !ocsp_structure_invariant(b"\x30\x03\x0a\x01\x01") {
        return Err("OCSP invariant failed on an unsuccessful envelope".to_string());
    }
    Ok(())
}
