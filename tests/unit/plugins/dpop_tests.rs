//! Tests for the shared DPoP proof verifier in
//! `ferrum_edge::plugins::utils::dpop`.
//!
//! Covers two RFC 9449 §4.3 hardening fixes on the resource-server `verify()`
//! path:
//!   * finding #26 — the access-token hash claim `ath` is mandatory: a proof
//!     that omits `ath` (or carries the wrong one) is rejected, so a proof is
//!     bound to the specific presented token, not just the key.
//!   * finding #79 — the proof's `htu` is normalized (scheme/host case, default
//!     :80/:443 ports, query/fragment) before comparison, so a conformant
//!     client whose `htu` differs only cosmetically is still accepted.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ferrum_edge::plugins::utils::dpop::{
    self, DPOP_MARKER_RETENTION_SECONDS, DPOP_REPLAY_PROFILE, DpopVerifyInput,
    MAX_DPOP_CLOCK_SKEW_SECS, canonical_htu, canonical_htu_from_url, jwk_thumbprint_sha256,
};
use ferrum_edge::plugins::utils::replay_authority::ReplayDomain;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const RSA_PRIVATE_PEM: &[u8] = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
const RSA_PUBLIC_PEM: &[u8] = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

/// Build the RSA JWK (kty/n/e) for the test public key, matching the
/// representation `dpop::jwk_thumbprint_sha256` hashes over.
fn rsa_jwk() -> Jwk {
    let pem_str = std::str::from_utf8(RSA_PUBLIC_PEM).expect("utf8 pem");
    let der = der_from_pem(pem_str);
    let (n, e) = parse_rsa_public_key_der(&der);
    serde_json::from_value(json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": URL_SAFE_NO_PAD.encode(&n),
        "e": URL_SAFE_NO_PAD.encode(&e),
    }))
    .expect("rsa jwk should parse")
}

/// SHA-256(access_token), base64url no-pad — the expected `ath` value.
fn access_token_hash(access_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Sign a DPoP proof JWT (typ `dpop+jwt`, RS256, embedded `jwk`) over the given
/// claims using the test RSA private key.
fn sign_proof(claims: &Value, jwk: &Jwk) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(jwk.clone());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM).expect("encoding key"),
    )
    .expect("sign proof")
}

/// Access-token claims carrying the `cnf.jkt` thumbprint binding for the JWK.
fn token_claims_for(jkt: &str) -> Value {
    json!({ "iss": "issuer", "sub": "user", "cnf": { "jkt": jkt } })
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Base proof claims for a `GET https://api.example.com/resource` request.
/// Caller mutates `htu`/`ath` per test.
fn base_proof_claims() -> Value {
    json!({
        "htm": "GET",
        "htu": "https://api.example.com/resource",
        "iat": now(),
        "exp": now() + 120,
        "jti": format!("jti-{}", uuid_like()),
    })
}

/// Cheap unique-ish jti so independent verify() calls stay distinguishable.
fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

struct Harness {
    jwk: Jwk,
    jkt: String,
    domain: ReplayDomain,
}

impl Harness {
    fn new() -> Self {
        Self::with_domain(ReplayDomain::new(
            DPOP_REPLAY_PROFILE,
            "ferrum",
            "jwks_auth",
            "dpop-tests",
            "0",
        ))
    }

    fn with_domain(domain: ReplayDomain) -> Self {
        let jwk = rsa_jwk();
        let jkt = jwk_thumbprint_sha256(&jwk).expect("thumbprint");
        Self { jwk, jkt, domain }
    }

    /// Verify a proof carrying `claims`, signed with the harness key, against
    /// the given canonical server reference `htu` and presented `access_token`.
    ///
    /// `verify()` no longer owns replay state: it validates and returns the
    /// marker the caller must claim. The tests below therefore compare either
    /// the error, or the marker digest, rather than a unit success.
    fn verify(
        &self,
        claims: &Value,
        htu: &str,
        access_token: &str,
    ) -> Result<[u8; 32], &'static str> {
        let proof = sign_proof(claims, &self.jwk);
        let token_claims = token_claims_for(&self.jkt);
        dpop::verify(DpopVerifyInput {
            proof: &proof,
            access_token,
            access_token_claims: &token_claims,
            token_principal: &[b"issuer".as_slice(), b"user".as_slice()],
            method: "GET",
            htu,
            clock_skew: Duration::from_secs(30),
            domain: &self.domain,
        })
        .map(|marker| marker.digest())
    }

    fn verify_ok(&self, claims: &Value, htu: &str, access_token: &str) -> [u8; 32] {
        self.verify(claims, htu, access_token)
            .expect("proof should validate")
    }
}

// ── finding #26: `ath` is mandatory and must match the presented token ──────

#[test]
fn proof_without_ath_is_rejected() {
    let h = Harness::new();
    let token = "access-token-abc";
    let claims = base_proof_claims(); // no `ath`
    let result = h.verify(&claims, "https://api.example.com/resource", token);
    assert_eq!(
        result,
        Err("DPoP proof missing ath"),
        "a proof omitting `ath` must be rejected (RFC 9449 §4.3)"
    );
}

#[test]
fn proof_with_correct_ath_is_accepted() {
    let h = Harness::new();
    let token = "access-token-abc";
    let mut claims = base_proof_claims();
    claims["ath"] = json!(access_token_hash(token));
    assert!(
        h.verify(&claims, "https://api.example.com/resource", token)
            .is_ok(),
        "a proof with the correct `ath` for the presented token must be accepted"
    );
}

#[test]
fn proof_with_wrong_ath_is_rejected() {
    let h = Harness::new();
    let token = "access-token-abc";
    let mut claims = base_proof_claims();
    // `ath` bound to a *different* token than the one presented.
    claims["ath"] = json!(access_token_hash("some-other-token"));
    let result = h.verify(&claims, "https://api.example.com/resource", token);
    assert_eq!(
        result,
        Err("DPoP access token hash mismatch"),
        "a proof whose `ath` does not match the presented token must be rejected"
    );
}

// ── finding #79: proof `htu` is normalized before comparison ────────────────

/// All of these proof `htu` values are semantically equal to the canonical
/// server reference `https://api.example.com/resource` and must be accepted.
#[test]
fn proof_htu_variants_are_normalized_before_comparison() {
    let server_htu =
        canonical_htu("https", "api.example.com", "/resource").expect("canonical server htu");
    assert_eq!(server_htu, "https://api.example.com/resource");

    let token = "access-token-abc";
    for variant in [
        "https://api.example.com:443/resource", // explicit default port
        "https://API.EXAMPLE.COM/resource",     // mixed-case host
        "HTTPS://api.example.com/resource",     // mixed-case scheme
        "https://api.example.com/resource?foo=bar", // trailing query
        "https://api.example.com/resource#section", // fragment
        "https://API.example.com:443/resource?x=1#y", // all at once
    ] {
        let h = Harness::new();
        let mut claims = base_proof_claims();
        claims["htu"] = json!(variant);
        claims["ath"] = json!(access_token_hash(token));
        assert!(
            h.verify(&claims, &server_htu, token).is_ok(),
            "proof htu `{variant}` should normalize to the server reference and be accepted"
        );
    }
}

#[test]
fn proof_htu_with_different_host_is_still_rejected() {
    let h = Harness::new();
    let token = "access-token-abc";
    let mut claims = base_proof_claims();
    claims["htu"] = json!("https://evil.example.com/resource");
    claims["ath"] = json!(access_token_hash(token));
    let result = h.verify(&claims, "https://api.example.com/resource", token);
    assert_eq!(
        result,
        Err("DPoP URL mismatch"),
        "normalization must not accept a genuinely different host"
    );
}

#[test]
fn proof_htu_with_different_path_is_still_rejected() {
    let h = Harness::new();
    let token = "access-token-abc";
    let mut claims = base_proof_claims();
    claims["htu"] = json!("https://api.example.com/other");
    claims["ath"] = json!(access_token_hash(token));
    let result = h.verify(&claims, "https://api.example.com/resource", token);
    assert_eq!(
        result,
        Err("DPoP URL mismatch"),
        "normalization must not accept a genuinely different path"
    );
}

#[test]
fn unparseable_proof_htu_is_rejected() {
    let h = Harness::new();
    let token = "access-token-abc";
    let mut claims = base_proof_claims();
    claims["htu"] = json!("not a url");
    claims["ath"] = json!(access_token_hash(token));
    let result = h.verify(&claims, "https://api.example.com/resource", token);
    assert_eq!(
        result,
        Err("DPoP URL mismatch"),
        "a proof htu that cannot be parsed must be rejected"
    );
}

// ── direct coverage of the new `canonical_htu_from_url` helper ──────────────

#[test]
fn canonical_htu_from_url_matches_reference_normalizer() {
    let reference = canonical_htu("https", "example.com", "/resource");
    assert_eq!(reference.as_deref(), Some("https://example.com/resource"));

    for raw in [
        "https://example.com/resource",
        "https://example.com:443/resource",
        "https://Example.COM/resource",
        "HTTPS://example.com/resource",
        "https://example.com/resource?a=1&b=2",
        "https://example.com/resource#frag",
    ] {
        assert_eq!(
            canonical_htu_from_url(raw),
            reference,
            "`{raw}` should canonicalize to the reference htu"
        );
    }
}

#[test]
fn canonical_htu_from_url_strips_http_default_port() {
    assert_eq!(
        canonical_htu_from_url("http://example.com:80/x").as_deref(),
        Some("http://example.com/x")
    );
}

#[test]
fn canonical_htu_from_url_keeps_non_default_port() {
    assert_eq!(
        canonical_htu_from_url("https://example.com:8443/x").as_deref(),
        Some("https://example.com:8443/x")
    );
}

#[test]
fn canonical_htu_from_url_rejects_non_http_scheme() {
    assert_eq!(canonical_htu_from_url("ftp://example.com/x"), None);
    assert_eq!(canonical_htu_from_url("not a url"), None);
}

#[test]
fn canonical_htu_from_url_rejects_userinfo() {
    assert_eq!(
        canonical_htu_from_url("https://alice@example.com/resource"),
        None
    );
    assert_eq!(
        canonical_htu_from_url("https://alice:secret@example.com/resource"),
        None
    );
}

// ── issue #3834: the marker, not a local cache, is what `verify` produces ────

/// The same proof always produces the same marker inside one domain, which is
/// what makes a replay detectable across reload generations and replicas.
#[test]
fn identical_proof_produces_a_stable_marker_within_one_domain() {
    let h = Harness::new();
    let token = "access-token-abc";
    let mut claims = base_proof_claims();
    claims["ath"] = json!(access_token_hash(token));

    let first = h.verify_ok(&claims, "https://api.example.com/resource", token);
    let second = h.verify_ok(&claims, "https://api.example.com/resource", token);
    assert_eq!(
        first, second,
        "the same jkt/jti inside one protection domain must map to one marker"
    );
}

/// A different `jti` under the same key is a different proof and must not
/// collide with the first marker.
#[test]
fn distinct_jti_produces_a_distinct_marker() {
    let h = Harness::new();
    let token = "access-token-abc";
    let mut first_claims = base_proof_claims();
    first_claims["ath"] = json!(access_token_hash(token));
    let mut second_claims = base_proof_claims(); // fresh jti
    second_claims["ath"] = json!(access_token_hash(token));

    assert_ne!(
        h.verify_ok(&first_claims, "https://api.example.com/resource", token),
        h.verify_ok(&second_claims, "https://api.example.com/resource", token),
    );
}

/// Two equivalent replicas (same namespace, plugin-config id, provider index)
/// derive the same domain and therefore the same marker — that convergence is
/// what makes a shared claim meaningful. A different namespace, a different
/// plugin-config id, or a different provider index isolates.
#[test]
fn protection_domains_converge_for_replicas_and_isolate_across_policies() {
    let token = "access-token-abc";
    let mut claims = base_proof_claims();
    claims["ath"] = json!(access_token_hash(token));
    let htu = "https://api.example.com/resource";

    let replica_a = Harness::with_domain(ReplayDomain::new(
        DPOP_REPLAY_PROFILE,
        "ferrum",
        "jwks_auth",
        "policy-1",
        "0",
    ));
    let replica_b = Harness::with_domain(ReplayDomain::new(
        DPOP_REPLAY_PROFILE,
        "ferrum",
        "jwks_auth",
        "policy-1",
        "0",
    ));
    assert_eq!(
        replica_a.verify_ok(&claims, htu, token),
        replica_b.verify_ok(&claims, htu, token),
        "equivalent replicas must derive the same marker"
    );

    for isolated in [
        ReplayDomain::new(
            DPOP_REPLAY_PROFILE,
            "other-ns",
            "jwks_auth",
            "policy-1",
            "0",
        ),
        ReplayDomain::new(DPOP_REPLAY_PROFILE, "ferrum", "jwks_auth", "policy-2", "0"),
        ReplayDomain::new(DPOP_REPLAY_PROFILE, "ferrum", "jwks_auth", "policy-1", "1"),
        ReplayDomain::new(
            "ferrum-dpop-proof-v2",
            "ferrum",
            "jwks_auth",
            "policy-1",
            "0",
        ),
    ] {
        assert_ne!(
            replica_a.verify_ok(&claims, htu, token),
            Harness::with_domain(isolated).verify_ok(&claims, htu, token),
            "a distinct namespace/policy/provider/profile must not share a marker"
        );
    }
}

/// A domain component boundary cannot be forged by a `jti` containing a
/// delimiter: every field is length-framed.
#[test]
fn marker_fields_are_length_framed_against_delimiter_forgery() {
    let domain = ReplayDomain::new(DPOP_REPLAY_PROFILE, "ferrum", "jwks_auth", "policy-1", "0");
    assert_ne!(
        domain.marker(&[b"ab", b"c"]).digest(),
        domain.marker(&[b"a", b"bc"]).digest(),
        "a shifted field boundary must not produce the same marker"
    );
    assert_ne!(
        domain.marker(&[b"a|b", b""]).digest(),
        domain.marker(&[b"a", b"b"]).digest(),
        "an embedded delimiter must not impersonate a field boundary"
    );
}

/// The retention horizon is not configurable and must dominate the widest
/// acceptance window any admissible provider — or any later reload that widens
/// `dpop_clock_skew_secs` — can open for one unchanged proof.
#[test]
fn retention_horizon_dominates_the_widest_admissible_clock_skew() {
    const {
        assert!(
            DPOP_MARKER_RETENTION_SECONDS > 2 * MAX_DPOP_CLOCK_SKEW_SECS,
            "a proof stays acceptable across `iat ± skew`, so retention must exceed 2 * max skew"
        );
    }
    assert_eq!(MAX_DPOP_CLOCK_SKEW_SECS, 300);
    assert_eq!(DPOP_MARKER_RETENTION_SECONDS, 601);
}

// ── minimal RSA public-key DER parsing (SPKI) for building the test JWK ─────

fn der_from_pem(pem: &str) -> Vec<u8> {
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(b64).expect("base64 der")
}

/// Parse an RSA SubjectPublicKeyInfo DER into raw (n, e) big-endian bytes.
fn parse_rsa_public_key_der(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pos = 0;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_outer_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (algo_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed + algo_len;
    assert_eq!(der[pos], 0x03);
    pos += 1;
    let (_bs_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed + 1; // skip unused-bits byte
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_inner_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (n_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    let mut n = der[pos..pos + n_len].to_vec();
    pos += n_len;
    if !n.is_empty() && n[0] == 0 {
        n.remove(0);
    }
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (e_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    let e = der[pos..pos + e_len].to_vec();
    (n, e)
}

fn parse_asn1_length(data: &[u8]) -> (usize, usize) {
    if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        let mut length = 0usize;
        for &byte in &data[1..=num_bytes] {
            length = (length << 8) | byte as usize;
        }
        (length, 1 + num_bytes)
    }
}

// ── RSA proof keys must fit the JWT backend's 2048-8192-bit window ──────────

/// An RS256 DPoP proof whose `jwk` carries a synthetic modulus of `bits` bits.
/// The size check runs before the signature is verified, so the proof does
/// not need a real signature or a real key.
fn unsigned_rsa_proof(bits: usize) -> (String, Value) {
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "RSA",
        "n": URL_SAFE_NO_PAD.encode(vec![0xff_u8; bits / 8]),
        "e": "AQAB",
    }))
    .expect("rsa jwk should parse");
    let jkt = jwk_thumbprint_sha256(&jwk).expect("thumbprint");
    let header = json!({ "typ": "dpop+jwt", "alg": "RS256", "jwk": jwk });
    let proof = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(base_proof_claims().to_string()),
        URL_SAFE_NO_PAD.encode([0u8; 16]),
    );
    (proof, token_claims_for(&jkt))
}

#[test]
fn rsa_proof_keys_outside_the_jwt_backend_window_are_refused_by_size() {
    let domain = ReplayDomain::new(
        DPOP_REPLAY_PROFILE,
        "ferrum",
        "jwks_auth",
        "dpop-tests",
        "0",
    );
    for bits in [1024, 16384] {
        let (proof, token_claims) = unsigned_rsa_proof(bits);
        let result = dpop::verify(DpopVerifyInput {
            proof: &proof,
            access_token: "token",
            access_token_claims: &token_claims,
            token_principal: &[b"issuer".as_slice(), b"user".as_slice()],
            method: "GET",
            htu: "https://api.example.com/resource",
            clock_skew: Duration::from_secs(30),
            domain: &domain,
        });
        assert_eq!(
            result.map(|marker| marker.digest()),
            Err(dpop::DPOP_RSA_KEY_SIZE),
            "{bits}-bit RSA proof key"
        );
    }
    // A 2048-bit synthetic key passes the size check and then fails only on
    // its (absent) signature.
    let (proof, token_claims) = unsigned_rsa_proof(2048);
    let result = dpop::verify(DpopVerifyInput {
        proof: &proof,
        access_token: "token",
        access_token_claims: &token_claims,
        token_principal: &[b"issuer".as_slice(), b"user".as_slice()],
        method: "GET",
        htu: "https://api.example.com/resource",
        clock_skew: Duration::from_secs(30),
        domain: &domain,
    });
    assert!(
        matches!(result, Err(reason) if reason != dpop::DPOP_RSA_KEY_SIZE),
        "a 2048-bit key must not be refused for its size"
    );
}

// ── htu path canonicalization matches the frontend (jwks_auth-SOL-2) ────────

/// The frontend rewrites `RequestContext::path` to the canonical policy path
/// (`/v1/items/a%3Ab` becomes `/v1/items/a:b`) before any plugin runs, while
/// the `url` crate keeps a proof's escapes verbatim. A proof bound to the
/// exact URI the client sent must still match the canonical server reference.
#[test]
fn canonical_htu_from_url_canonicalizes_percent_encoded_paths_like_the_frontend() {
    for (raw, canonical_path) in [
        ("https://api.example.com/v1/items/a%3Ab", "/v1/items/a:b"),
        ("https://api.example.com/v1/items/a%3ab", "/v1/items/a:b"),
        ("https://api.example.com/res%6Furce", "/resource"),
        ("https://api.example.com/%61dmin/users", "/admin/users"),
    ] {
        assert_eq!(
            canonical_htu_from_url(raw),
            canonical_htu("https", "api.example.com", canonical_path),
            "`{raw}` must canonicalize to the frontend's policy path"
        );
    }
}

/// A proof path the frontend itself would refuse has no canonical form, so it
/// can never match a request the gateway admitted.
#[test]
fn canonical_htu_from_url_refuses_paths_the_frontend_refuses() {
    for raw in [
        "https://api.example.com/a%2Fb",
        "https://api.example.com/a%252Fb",
        "https://api.example.com/a%00b",
    ] {
        assert_eq!(
            canonical_htu_from_url(raw),
            None,
            "`{raw}` must not normalize"
        );
    }
}

#[test]
fn proof_bound_to_percent_encoded_target_matches_canonical_request_path() {
    let server_htu =
        canonical_htu("https", "api.example.com", "/v1/items/a:b").expect("canonical server htu");
    let token = "access-token-abc";

    let h = Harness::new();
    let mut claims = base_proof_claims();
    claims["htu"] = json!("https://api.example.com/v1/items/a%3Ab");
    claims["ath"] = json!(access_token_hash(token));
    assert!(
        h.verify(&claims, &server_htu, token).is_ok(),
        "a proof for the exact encoded target must match the canonical path"
    );

    let h = Harness::new();
    let mut claims = base_proof_claims();
    claims["htu"] = json!("https://api.example.com/v1/items/a%3Ac");
    claims["ath"] = json!(access_token_hash(token));
    assert_eq!(
        h.verify(&claims, &server_htu, token),
        Err("DPoP URL mismatch"),
        "canonicalization must not accept a genuinely different target"
    );
}

// ── proof algorithms beyond ES256/RS256 (jwks_auth-M3) ──────────────────────

/// Verify a pre-signed proof whose embedded key has thumbprint `jkt`.
fn verify_signed_proof(
    proof: &str,
    jkt: &str,
    access_token: &str,
) -> Result<[u8; 32], &'static str> {
    let token_claims = token_claims_for(jkt);
    let domain = ReplayDomain::new(
        DPOP_REPLAY_PROFILE,
        "ferrum",
        "jwks_auth",
        "dpop-tests",
        "0",
    );
    dpop::verify(DpopVerifyInput {
        proof,
        access_token,
        access_token_claims: &token_claims,
        token_principal: &[b"issuer".as_slice(), b"user".as_slice()],
        method: "GET",
        htu: "https://api.example.com/resource",
        clock_skew: Duration::from_secs(30),
        domain: &domain,
    })
    .map(|marker| marker.digest())
}

fn proof_claims_for(access_token: &str) -> Value {
    let mut claims = base_proof_claims();
    claims["ath"] = json!(access_token_hash(access_token));
    claims
}

fn sign_proof_with(alg: Algorithm, jwk: &Jwk, key: &EncodingKey, claims: &Value) -> String {
    let mut header = Header::new(alg);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(jwk.clone());
    encode(&header, claims, key).expect("sign proof")
}

fn rsa_jwk_without_alg() -> Jwk {
    let mut value = serde_json::to_value(rsa_jwk()).expect("jwk serializes");
    value.as_object_mut().expect("jwk object").remove("alg");
    serde_json::from_value(value).expect("rsa jwk should parse")
}

#[test]
fn rsassa_pss_proofs_are_accepted() {
    let token = "access-token-pss";
    let jwk = rsa_jwk_without_alg();
    let jkt = jwk_thumbprint_sha256(&jwk).expect("thumbprint");
    let key = EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM).expect("rsa key");
    for alg in [
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
        Algorithm::RS384,
        Algorithm::RS512,
    ] {
        let proof = sign_proof_with(alg, &jwk, &key, &proof_claims_for(token));
        assert!(
            verify_signed_proof(&proof, &jkt, token).is_ok(),
            "{alg:?} DPoP proof must verify"
        );
    }
}

#[test]
fn es384_proof_is_accepted() {
    let token = "access-token-es384";
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("P-384");
    let point = key_pair.public_key_raw();
    assert_eq!(point.len(), 97, "uncompressed P-384 point");
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "EC",
        "crv": "P-384",
        "x": URL_SAFE_NO_PAD.encode(&point[1..49]),
        "y": URL_SAFE_NO_PAD.encode(&point[49..]),
    }))
    .expect("ec jwk");
    let jkt = jwk_thumbprint_sha256(&jwk).expect("thumbprint");
    let key = EncodingKey::from_ec_pem(key_pair.serialize_pem().as_bytes()).expect("ec key");
    let proof = sign_proof_with(Algorithm::ES384, &jwk, &key, &proof_claims_for(token));
    assert!(verify_signed_proof(&proof, &jkt, token).is_ok());
}

fn ed25519_proof_key() -> (Jwk, EncodingKey) {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("Ed25519");
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(key_pair.public_key_raw()),
    }))
    .expect("okp jwk");
    let key = EncodingKey::from_ed_pem(key_pair.serialize_pem().as_bytes()).expect("ed key");
    (jwk, key)
}

#[test]
fn eddsa_proof_is_accepted_with_rfc8037_thumbprint() {
    let token = "access-token-eddsa";
    let (jwk, key) = ed25519_proof_key();
    let jkt = jwk_thumbprint_sha256(&jwk).expect("OKP thumbprint");

    // RFC 8037 §2 / RFC 7638: the thumbprint input is exactly crv, kty, x.
    let x = serde_json::to_value(&jwk).expect("jwk serializes")["x"]
        .as_str()
        .expect("x member")
        .to_string();
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(
        format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#).as_bytes(),
    ));
    assert_eq!(jkt, expected);

    let proof = sign_proof_with(Algorithm::EdDSA, &jwk, &key, &proof_claims_for(token));
    assert!(verify_signed_proof(&proof, &jkt, token).is_ok());
}

#[test]
fn eddsa_proof_signed_by_another_key_is_rejected() {
    let token = "access-token-eddsa";
    let (jwk, _) = ed25519_proof_key();
    let (_, other_key) = ed25519_proof_key();
    let jkt = jwk_thumbprint_sha256(&jwk).expect("OKP thumbprint");
    let proof = sign_proof_with(Algorithm::EdDSA, &jwk, &other_key, &proof_claims_for(token));
    assert_eq!(
        verify_signed_proof(&proof, &jkt, token),
        Err("Invalid DPoP proof")
    );
}

#[test]
fn symmetric_proof_algorithm_is_rejected() {
    let token = "access-token-hs256";
    let jwk = rsa_jwk_without_alg();
    let jkt = jwk_thumbprint_sha256(&jwk).expect("thumbprint");
    let proof = sign_proof_with(
        Algorithm::HS256,
        &jwk,
        &EncodingKey::from_secret(b"a-shared-secret-of-sufficient-length"),
        &proof_claims_for(token),
    );
    assert_eq!(
        verify_signed_proof(&proof, &jkt, token),
        Err(dpop::DPOP_UNSUPPORTED_ALGORITHM)
    );
}
