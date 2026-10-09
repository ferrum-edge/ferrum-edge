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
