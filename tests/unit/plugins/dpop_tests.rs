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

use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ferrum_edge::plugins::utils::dpop::{
    self, DpopJtiCache, DpopVerifyInput, canonical_htu, canonical_htu_from_url,
    jwk_thumbprint_sha256,
};
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
    json!({ "sub": "user", "cnf": { "jkt": jkt } })
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

/// Cheap unique-ish jti so independent verify() calls do not collide in the
/// shared replay cache.
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
    cache: DpopJtiCache,
}

impl Harness {
    fn new() -> Self {
        let jwk = rsa_jwk();
        let jkt = jwk_thumbprint_sha256(&jwk).expect("thumbprint");
        Self {
            jwk,
            jkt,
            cache: DpopJtiCache::new(64, Duration::from_secs(300), 4),
        }
    }

    /// Verify a proof carrying `claims`, signed with the harness key, against
    /// the given canonical server reference `htu` and presented `access_token`.
    fn verify(&self, claims: &Value, htu: &str, access_token: &str) -> Result<(), &'static str> {
        let proof = sign_proof(claims, &self.jwk);
        let token_claims = token_claims_for(&self.jkt);
        dpop::verify(DpopVerifyInput {
            proof: &proof,
            access_token,
            access_token_claims: &token_claims,
            method: "GET",
            htu,
            clock_skew: Duration::from_secs(30),
            cache: &self.cache,
        })
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
    let result = h.verify(&claims, "https://api.example.com/resource", token);
    assert_eq!(
        result,
        Ok(()),
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
        let result = h.verify(&claims, &server_htu, token);
        assert_eq!(
            result,
            Ok(()),
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

#[test]
fn concurrent_identical_jti_admits_exactly_one_request() {
    const WORKERS: usize = 32;
    let cache = Arc::new(DpopJtiCache::new(64, Duration::from_secs(300), 4));
    let barrier = Arc::new(Barrier::new(WORKERS));
    let now = Instant::now();

    let workers = (0..WORKERS)
        .map(|_| {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                cache.check_and_insert("same-jkt", "same-jti", now)
            })
        })
        .collect::<Vec<_>>();

    let admitted = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker should not panic"))
        .filter(|admitted| *admitted)
        .count();
    assert_eq!(admitted, 1);
}

#[test]
fn full_replay_cache_fails_closed_until_an_entry_expires() {
    let cache = DpopJtiCache::new(1, Duration::from_secs(60), 4);
    let now = Instant::now();
    assert!(cache.check_and_insert("jkt-a", "jti-a", now));
    assert!(
        !cache.check_and_insert("jkt-b", "jti-b", now),
        "a live replay marker must not be evicted to admit another proof"
    );
    assert!(cache.check_and_insert("jkt-b", "jti-b", now + Duration::from_secs(61)));
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
