//! JWKS conversion for SPIFFE JWT bundles.
//!
//! CA backends publish JWT authorities as
//! [`PublishedJwtAuthority`] — a key id plus an SPKI (`-----BEGIN PUBLIC
//! KEY-----`) PEM document. The SPIFFE Workload API instead speaks JWKS
//! (`FetchJWTBundles.bundles[trust_domain]` is a JWKS document), and
//! validation needs a `jsonwebtoken` [`DecodingKey`]. This module is the one
//! place both conversions live.
//!
//! ## Algorithm binding
//!
//! The allowed signature algorithms are derived from the **authority's own
//! public key**, never from the token header:
//!
//! | Key | Algorithms the key type can produce |
//! |---|---|
//! | EC P-256 (`prime256v1`) | `ES256` |
//! | EC P-384 (`secp384r1`) | `ES384` |
//! | RSA 2048–8192 bit | `RS256` `RS384` `RS512` `PS256` `PS384` `PS512` |
//!
//! Everything else — EC P-521 (no `jsonwebtoken` verifier), other curves,
//! Ed25519, DSA, GOST, unknown SPKI — is refused rather than guessed at, and
//! the HMAC family is never reachable, so `alg: HS256` signed with a public
//! key (the classic algorithm-confusion attack) cannot validate.
//!
//! That table is the **ceiling**, not the answer. An authority that *declares*
//! an `alg` is held to exactly that one
//! ([`PublishedJwtAuthority::declared_alg`]); a declaration the key type cannot
//! have produced is rejected rather than honoured. Where no declaration exists
//! the key type has to decide, and it only genuinely decides for EC — a curve
//! pins one algorithm. For RSA the conservative default is **`RS256` alone**:
//! RFC 7518 §3.1 lists `RS256` as the only Recommended RSASSA algorithm, so a
//! key that signs with anything else is expected to say so. Accepting all six
//! for an undeclared RSA key would silently broaden every consumed bundle.
//!
//! ## Externally supplied key policy
//!
//! [`authorities_from_jwks`] consumes a bundle Ferrum did not produce, so JWK
//! policy members are validated rather than skimmed: a present `use` must be a
//! string and must be `sig`; a present `key_ops` must be an array of strings
//! containing `verify`; the two must not contradict each other (RFC 7517 §4.3);
//! and a present `alg` must be a string naming an algorithm the key type can
//! produce. A **malformed** policy member is a rejection, never a fall-through
//! to "unspecified" — a bundle that says something Ferrum cannot parse must not
//! be trusted as if it had said nothing.
//!
//! ## Cryptographic admission
//!
//! Shape is not strength, and shape is not membership. Both are checked on
//! *every* path — externally supplied JWK, PEM/SPKI, and verification-key
//! construction — before an authority is published in `FetchJWTBundles` or used
//! to build a `DecodingKey`:
//!
//! - an **RSA modulus** is bounded by its *significant* bit length,
//!   `2048..=8192`, and must be **odd**. A byte-count floor is not the same
//!   test: 256 bytes with a small top byte is a 2041-bit key, and leading zero
//!   octets add nothing. Parity is not a size question at all: a modulus is a
//!   product of odd primes, so an even value — however well-sized and
//!   canonically encoded — is not an RSA modulus.
//! - an **RSA public exponent** must be odd and at least 3, within a bounded
//!   encoding. `0` and `1` are not exponents and an even value cannot be coprime
//!   with φ(n); real keys are 65537.
//! - externally supplied RSA `n` / `e` must additionally be **canonical**
//!   unsigned big-endian (RFC 7518 §6.3.1) — no leading zero octet. DER
//!   re-encoding would otherwise normalize a non-canonical member silently and
//!   let one key be published under two thumbprints.
//! - an **EC point** must actually lie on its named curve and not be the
//!   identity. An OID, an uncompressed marker, and correctly sized coordinates
//!   describe an off-curve point just as happily, and republishing one in
//!   `FetchJWTBundles` would hand every workload a bogus authority. Membership is
//!   proven with a bounded ephemeral ECDH agreement at the provider seam
//!   ([`crate::fips::ec_point_on_named_curve`]), so the arithmetic stays on the
//!   *selected* provider — `ring` on an ordinary build, the AWS-LC FIPS module on
//!   a `fips` build — rather than on a second, unrouted implementation.
//!
//! Every rejection is a fixed string; no key bytes ever reach an error.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::{Map, Value};
use x509_parser::asn1_rs::Tag;
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo};
use x509_parser::public_key::PublicKey;

use super::{
    JwtSvidError, MAX_JWKS_DOCUMENT_BYTES, MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN,
    MAX_JWT_KEY_ID_BYTES, MAX_JWT_PUBLIC_KEY_PEM_BYTES,
};
use crate::identity::ca::PublishedJwtAuthority;

const PEM_PUBLIC_KEY_BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const PEM_PUBLIC_KEY_END: &str = "-----END PUBLIC KEY-----";

/// Maximum accepted SPKI DER size. An SPKI for the key types we support is a
/// few hundred bytes; RSA-8192 is the practical ceiling.
const MAX_SPKI_DER_BYTES: usize = 4 * 1024;
/// Minimum accepted RSA modulus size, in **significant** bits.
///
/// Measured in bits rather than bytes on purpose. A byte-length floor of 256
/// admits a 2041-bit modulus whose top byte happens to be small, and leading
/// zero bytes never contribute strength at all — so the check is performed on
/// the significant bit length after stripping them.
const MIN_RSA_MODULUS_BITS: u32 = 2048;
/// Maximum accepted RSA modulus size, in significant bits. The module documents
/// RSA-8192 as its ceiling; without an explicit bound a bundle could publish an
/// arbitrarily large modulus and make every verification attempt expensive.
const MAX_RSA_MODULUS_BITS: u32 = 8192;
/// Maximum accepted RSA public exponent size. Real exponents are 3 bytes
/// (`65537`); a large one is a malformed or hostile JWK.
const MAX_RSA_EXPONENT_BYTES: usize = 8;
/// Smallest RSA public exponent that is not trivially broken. `0`/`1` are not
/// exponents at all and `2` is even (so not coprime with φ(n)); RFC 8017 and
/// SP 800-56B put the floor at 3, and every real key uses 65537.
const MIN_RSA_PUBLIC_EXPONENT: u64 = 3;

/// DER content bytes of the named-curve OIDs we accept.
/// `1.2.840.10045.3.1.7` — NIST P-256 / prime256v1.
const OID_BYTES_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `1.3.132.0.34` — NIST P-384 / secp384r1.
const OID_BYTES_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
/// `1.2.840.10045.2.1` — id-ecPublicKey.
const OID_BYTES_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `1.2.840.113549.1.1.1` — rsaEncryption.
const OID_BYTES_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// A public key decomposed into its JWK members.
struct JwkPublicKey {
    kty: &'static str,
    /// JWK members in RFC 7638 lexicographic order, excluding `kty` itself,
    /// which is inserted at its own lexicographic position by
    /// [`Self::thumbprint_input`].
    members: Vec<(&'static str, String)>,
    /// The `alg` advertised in the published JWK.
    preferred_alg: Algorithm,
    /// Every algorithm this key type may legitimately have signed with.
    allowed_algs: Vec<Algorithm>,
}

impl JwkPublicKey {
    /// RFC 7638 §3.2 canonical JWK: the required members only, lexicographic
    /// by member name, no whitespace.
    fn thumbprint_input(&self) -> String {
        // Sorted explicitly rather than via `serde_json::Map`: that type is a
        // `BTreeMap` only while the `preserve_order` feature is off, and any
        // crate in the graph can turn it on. A thumbprint that silently
        // changes with a transitive cargo feature would rotate every key id.
        let mut members: Vec<(&str, &str)> = self
            .members
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        members.push(("kty", self.kty));
        members.sort_unstable_by(|left, right| left.0.cmp(right.0));

        let mut out = String::from("{");
        for (index, (name, value)) in members.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&Value::String((*name).to_string()).to_string());
            out.push(':');
            out.push_str(&Value::String((*value).to_string()).to_string());
        }
        out.push('}');
        out
    }

    /// The published JWK for this key, including `kid`, `alg`, and `use`.
    ///
    /// `declared_alg` is republished verbatim when the authority carried one, so
    /// a consumed bundle's narrower declaration survives being re-served rather
    /// than being widened back to this key type's preferred algorithm.
    fn to_jwk(&self, key_id: &str, declared_alg: Option<Algorithm>) -> Value {
        let mut jwk = Map::new();
        jwk.insert("kty".to_string(), Value::String(self.kty.to_string()));
        for (name, value) in &self.members {
            jwk.insert((*name).to_string(), Value::String(value.clone()));
        }
        jwk.insert("kid".to_string(), Value::String(key_id.to_string()));
        jwk.insert(
            "alg".to_string(),
            Value::String(format!("{:?}", declared_alg.unwrap_or(self.preferred_alg))),
        );
        jwk.insert("use".to_string(), Value::String("sig".to_string()));
        Value::Object(jwk)
    }
}

/// Compute the RFC 7638 JWK thumbprint (base64url, unpadded SHA-256) of an
/// SPKI PEM public key. Used as the `kid` for Ferrum-minted JWT-SVIDs so the
/// key id is derived from the key itself rather than a counter that could
/// collide across restarts.
pub fn published_authority_key_id(public_key_pem: &str) -> Result<String, JwtSvidError> {
    let spki_der = spki_der_from_pem(public_key_pem)?;
    let key = jwk_public_key(&spki_der)?;
    let digest = crate::fips::backend::digest::digest(
        &crate::fips::backend::digest::SHA256,
        key.thumbprint_input().as_bytes(),
    );
    Ok(URL_SAFE_NO_PAD.encode(digest.as_ref()))
}

/// Validate one trust domain's **complete** authority set against every
/// documented bound, and return the serialized JWKS document.
///
/// This is the single gate both publication and validation go through, so
/// `ValidateJWTSVID` can never accept material `FetchJWTBundles` would have
/// refused. Checks, all before any authority is used for anything:
///
/// - the set is non-empty (an empty JWKS is not a conformant "no authorities"
///   signal — SPIFFE Workload API §6.2.2 requires at least the local
///   trust-domain bundle);
/// - the set is no larger than [`MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN`], so a
///   hostile or misconfigured bundle cannot drive an unbounded scan;
/// - every authority is stamped with `expected_trust_domain`, so a bundle keyed
///   under one domain can never carry another domain's key;
/// - every `key_id` is present, bounded, and control-character free;
/// - no two authorities share a `key_id` (an ambiguous `kid` must not silently
///   resolve to whichever entry came first);
/// - every authority's PEM/DER/key-type/key-size parses into a supported public
///   key;
/// - the serialized JWKS document itself is within
///   [`MAX_JWKS_DOCUMENT_BYTES`].
///
/// A malformed authority is never published or trusted alongside good ones —
/// the whole set is refused.
pub fn validate_published_authorities(
    expected_trust_domain: &crate::identity::spiffe::TrustDomain,
    authorities: &[PublishedJwtAuthority],
) -> Result<Vec<u8>, JwtSvidError> {
    if authorities.is_empty() {
        return Err(JwtSvidError::NoJwtAuthority(
            "this trust domain publishes no JWT authorities",
        ));
    }
    // Bound FIRST: every later check is per-authority work, so the cap has to
    // be enforced before the loop, not inside it.
    if authorities.len() > MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN {
        return Err(JwtSvidError::InvalidAuthority(
            "too many JWT authorities published for one trust domain",
        ));
    }

    let mut keys: Vec<Value> = Vec::with_capacity(authorities.len());
    let mut seen_key_ids: Vec<&str> = Vec::with_capacity(authorities.len());
    for authority in authorities {
        if authority.trust_domain != *expected_trust_domain {
            return Err(JwtSvidError::InvalidAuthority(
                "a published JWT authority does not belong to its bundle's trust domain",
            ));
        }
        validate_key_id(&authority.key_id)?;
        if seen_key_ids.contains(&authority.key_id.as_str()) {
            return Err(JwtSvidError::InvalidAuthority(
                "two JWT authorities share a key id",
            ));
        }
        seen_key_ids.push(authority.key_id.as_str());

        let spki_der = spki_der_from_pem(&authority.public_key_pem)?;
        let key = jwk_public_key(&spki_der)?;
        // A declaration the key type cannot have produced is refused here, at
        // the single admission gate, so neither publication nor validation can
        // act on it.
        if let Some(declared) = authority.declared_alg
            && !key.allowed_algs.contains(&declared)
        {
            return Err(JwtSvidError::InvalidAuthority(
                "a JWT authority declares a signature algorithm its key type cannot produce",
            ));
        }
        keys.push(key.to_jwk(&authority.key_id, authority.declared_alg));
    }

    let mut document = Map::new();
    document.insert("keys".to_string(), Value::Array(keys));
    let bytes = serde_json::to_vec(&Value::Object(document))
        .map_err(|e| JwtSvidError::Internal(format!("JWKS serialization failed: {e}")))?;
    if bytes.len() > MAX_JWKS_DOCUMENT_BYTES {
        return Err(JwtSvidError::InvalidAuthority("JWKS document is too large"));
    }
    Ok(bytes)
}

/// Build the JWKS document for one trust domain's published authorities.
///
/// Thin wrapper over [`validate_published_authorities`], which performs every
/// bound and binding check. The trust domain is taken from the first authority
/// and then required of all of them, so a mixed-domain set is refused here too.
pub fn jwks_document(authorities: &[PublishedJwtAuthority]) -> Result<Vec<u8>, JwtSvidError> {
    let Some(first) = authorities.first() else {
        return Err(JwtSvidError::NoJwtAuthority(
            "this trust domain publishes no JWT authorities",
        ));
    };
    validate_published_authorities(&first.trust_domain, authorities)
}

/// Parse an **externally supplied** JWKS document (a SPIRE agent's JWT bundle,
/// or a federated peer's) into published authorities.
///
/// This is the inverse of [`validate_published_authorities`] and is deliberately
/// as strict: the document is size-bounded before parsing, key entries are
/// bounded before conversion, every entry must be an asymmetric signing key of a
/// supported type/size, and the result is put back through
/// [`validate_published_authorities`] so an externally sourced bundle is held to
/// exactly the bounds a locally produced one is. `kid` is **required** — an
/// unnamed key in a multi-key bundle would be unselectable — and the recovered
/// `kid` is the peer's own, not recomputed, because that is what its tokens
/// carry.
///
/// Unknown JWK members are ignored (JWKS is an extensible document), but a
/// *known policy member* is never ignored, and a malformed one is never treated
/// as absent:
///
/// - `use`, if present, must be the string `sig`. A non-string `use` is a
///   rejection, not an unspecified key.
/// - `key_ops`, if present, must be an array whose entries are all strings and
///   which contains `verify`. A non-array `key_ops` (including a bare string)
///   is a rejection.
/// - `use` and `key_ops` together must be consistent (RFC 7517 §4.3): with
///   `use: "sig"` the only permitted operations are `sign` / `verify`, so a
///   bundle asserting both signature use and an encryption operation is
///   contradictory and refused.
/// - `alg`, if present, must be a string naming a supported algorithm, and is
///   carried onto [`PublishedJwtAuthority::declared_alg`] so validation is
///   restricted to that one algorithm rather than to everything the key type
///   could have produced.
pub fn authorities_from_jwks(
    trust_domain: &crate::identity::spiffe::TrustDomain,
    document: &[u8],
) -> Result<Vec<PublishedJwtAuthority>, JwtSvidError> {
    if document.is_empty() {
        return Err(JwtSvidError::InvalidAuthority("JWT bundle JWKS is empty"));
    }
    if document.len() > MAX_JWKS_DOCUMENT_BYTES {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS document is too large",
        ));
    }
    let parsed = super::parse_strict_json_object(document)
        .map_err(|_| JwtSvidError::InvalidAuthority("JWT bundle JWKS is not a JSON object"))?;
    let keys = match parsed.get("keys") {
        Some(Value::Array(keys)) => keys,
        _ => {
            return Err(JwtSvidError::InvalidAuthority(
                "JWT bundle JWKS has no 'keys' array",
            ));
        }
    };
    if keys.is_empty() {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS publishes no keys",
        ));
    }
    // Bound before the per-key work, so an oversized key list is refused rather
    // than scanned.
    if keys.len() > MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS publishes more keys than one trust domain may hold",
        ));
    }

    let mut authorities = Vec::with_capacity(keys.len());
    for key in keys {
        let Value::Object(jwk) = key else {
            return Err(JwtSvidError::InvalidAuthority(
                "JWT bundle JWKS key entry is not an object",
            ));
        };
        let key_id = match jwk.get("kid") {
            Some(Value::String(kid)) => kid.clone(),
            _ => {
                return Err(JwtSvidError::InvalidAuthority(
                    "JWT bundle JWKS key entry has no string 'kid'",
                ));
            }
        };
        validate_key_id(&key_id)?;
        check_jwk_key_policy(jwk)?;
        let declared_alg = jwk_declared_alg(jwk)?;
        let public_key_pem = spki_pem_from_jwk(jwk)?;
        authorities.push(PublishedJwtAuthority {
            trust_domain: trust_domain.clone(),
            key_id,
            public_key_pem,
            declared_alg,
        });
    }

    // Hold the external bundle to exactly the local bounds (duplicate `kid`,
    // trust-domain binding, total JWKS size).
    validate_published_authorities(trust_domain, &authorities)?;
    Ok(authorities)
}

/// Operations RFC 7517 §4.3 admits alongside `use: "sig"`. Anything else in
/// `key_ops` contradicts a signature key and is refused rather than reconciled.
const SIGNATURE_KEY_OPS: &[&str] = &["sign", "verify"];

/// Validate the `use` / `key_ops` policy members of an externally supplied JWK.
///
/// Each member is checked for **type** before value, so a hostile bundle cannot
/// evade the policy by supplying `"use": 1` or `"key_ops": "verify"` and having
/// the member skipped as "not the shape we look for". Absence is the only way to
/// be unspecified.
fn check_jwk_key_policy(jwk: &Map<String, Value>) -> Result<(), JwtSvidError> {
    let declared_use = match jwk.get("use") {
        None => None,
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => {
            return Err(JwtSvidError::InvalidAuthority(
                "JWT bundle JWKS key member 'use' is not a string",
            ));
        }
    };
    if let Some(value) = declared_use
        && value != "sig"
    {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS key is not declared for signature use",
        ));
    }

    let key_ops = match jwk.get("key_ops") {
        None => None,
        Some(Value::Array(ops)) => Some(ops),
        Some(_) => {
            return Err(JwtSvidError::InvalidAuthority(
                "JWT bundle JWKS key member 'key_ops' is not an array",
            ));
        }
    };
    let Some(ops) = key_ops else {
        return Ok(());
    };
    let mut permits_verify = false;
    for op in ops {
        let op = op.as_str().ok_or(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS key member 'key_ops' contains a non-string entry",
        ))?;
        if op == "verify" {
            permits_verify = true;
        }
        // Contradiction check, not merely a presence check: a key that says
        // `use: "sig"` while also claiming an encryption/derivation operation is
        // describing two different keys, and guessing which one it meant is
        // exactly what a fail-closed consumer must not do.
        if declared_use == Some("sig") && !SIGNATURE_KEY_OPS.contains(&op) {
            return Err(JwtSvidError::InvalidAuthority(
                "JWT bundle JWKS key declares signature use with a contradictory key operation",
            ));
        }
    }
    if !permits_verify {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS key does not permit signature verification",
        ));
    }
    Ok(())
}

/// Read a JWK's declared `alg`, if any.
///
/// A present member must be a string naming one of the algorithms Ferrum can
/// verify with. An unknown or symmetric name is refused rather than dropped:
/// dropping it would silently promote an `HS256`-declared key to the whole
/// asymmetric family its SPKI happens to support. Compatibility with the key's
/// actual type is enforced later, in [`validate_published_authorities`], which
/// is the single gate both publication and validation pass through.
fn jwk_declared_alg(jwk: &Map<String, Value>) -> Result<Option<Algorithm>, JwtSvidError> {
    let raw = match jwk.get("alg") {
        None => return Ok(None),
        Some(Value::String(value)) => value.as_str(),
        Some(_) => {
            return Err(JwtSvidError::InvalidAuthority(
                "JWT bundle JWKS key member 'alg' is not a string",
            ));
        }
    };
    let alg = match raw {
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        _ => {
            return Err(JwtSvidError::InvalidAuthority(
                "JWT bundle JWKS key declares an algorithm this validator does not support",
            ));
        }
    };
    Ok(Some(alg))
}

/// Re-encode a JWK public key as an SPKI `PUBLIC KEY` PEM.
///
/// Only the key types Ferrum can verify with are accepted (EC P-256 / P-384 and
/// RSA ≥ 2048 bit); everything else is refused rather than guessed at, matching
/// [`jwk_public_key`]'s allowed set exactly. The re-encoded SPKI is parsed back
/// through that same function, so a JWK that round-trips into something
/// unsupported cannot slip past.
fn spki_pem_from_jwk(jwk: &Map<String, Value>) -> Result<String, JwtSvidError> {
    let kty = jwk
        .get("kty")
        .and_then(Value::as_str)
        .ok_or(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS key entry has no 'kty'",
        ))?;
    let spki_der =
        match kty {
            "EC" => {
                let crv = jwk.get("crv").and_then(Value::as_str).ok_or(
                    JwtSvidError::InvalidAuthority("JWT bundle JWKS EC key names no curve"),
                )?;
                let (curve_oid, coordinate_bytes) = match crv {
                    "P-256" => (OID_BYTES_P256, 32usize),
                    "P-384" => (OID_BYTES_P384, 48usize),
                    _ => {
                        return Err(JwtSvidError::InvalidAuthority(
                            "unsupported JWT authority EC curve",
                        ));
                    }
                };
                let x = jwk_base64url_member(jwk, "x", coordinate_bytes)?;
                let y = jwk_base64url_member(jwk, "y", coordinate_bytes)?;
                let mut point = Vec::with_capacity(1 + 2 * coordinate_bytes);
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                let algorithm =
                    der_sequence(&[der_oid(OID_BYTES_EC_PUBLIC_KEY), der_oid(curve_oid)]);
                der_sequence(&[algorithm, der_bit_string(&point)])
            }
            "RSA" => {
                // `n` / `e` are unsigned big-endian **with no leading zero
                // octet** (RFC 7518 §6.3.1). Enforced rather than tolerated: DER
                // re-encoding strips leading zeros, so a non-canonical member
                // would be silently normalized and the same key could then be
                // published under two different thumbprints. Bounding the raw
                // members here also keeps an oversized one from being
                // DER-encoded at all; `jwk_public_key` re-checks the resulting
                // key after the round trip.
                let modulus = jwk_base64url_bounded(jwk, "n", (MAX_RSA_MODULUS_BITS / 8) as usize)?;
                let exponent = jwk_base64url_bounded(jwk, "e", MAX_RSA_EXPONENT_BYTES)?;
                if modulus.first() == Some(&0) || exponent.first() == Some(&0) {
                    return Err(JwtSvidError::InvalidAuthority(
                        "JWT bundle JWKS RSA member is not a canonical unsigned big-endian value",
                    ));
                }
                check_rsa_modulus(&modulus)?;
                check_rsa_exponent(&exponent)?;
                let rsa_public_key = der_sequence(&[
                    der_positive_integer(&modulus),
                    der_positive_integer(&exponent),
                ]);
                let algorithm = der_sequence(&[der_oid(OID_BYTES_RSA_ENCRYPTION), der_null()]);
                der_sequence(&[algorithm, der_bit_string(&rsa_public_key)])
            }
            _ => {
                return Err(JwtSvidError::InvalidAuthority(
                    "unsupported JWT authority key type",
                ));
            }
        };
    if spki_der.len() > MAX_SPKI_DER_BYTES {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key DER is empty or oversized",
        ));
    }
    // Re-parse what we just built: the PEM we hand on must be exactly as
    // acceptable as one that arrived as a PEM in the first place.
    jwk_public_key(&spki_der)?;
    Ok(spki_pem_from_der(&spki_der))
}

/// Decode a required base64url JWK member and require an exact byte length.
fn jwk_base64url_member(
    jwk: &Map<String, Value>,
    name: &str,
    expected_len: usize,
) -> Result<Vec<u8>, JwtSvidError> {
    let bytes = jwk_base64url_bounded(jwk, name, expected_len)?;
    if bytes.len() != expected_len {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority EC public key coordinate is not the named curve's size",
        ));
    }
    Ok(bytes)
}

/// Decode a required base64url JWK member, bounded before decoding.
fn jwk_base64url_bounded(
    jwk: &Map<String, Value>,
    name: &str,
    max_len: usize,
) -> Result<Vec<u8>, JwtSvidError> {
    let encoded = jwk
        .get(name)
        .and_then(Value::as_str)
        .ok_or(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS key entry is missing a required member",
        ))?;
    // 4 base64 characters carry 3 bytes; refuse before allocating.
    if encoded.len() / 4 * 3 > max_len {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS key member is too large",
        ));
    }
    let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| {
        JwtSvidError::InvalidAuthority("JWT bundle JWKS key member is not unpadded base64url")
    })?;
    if decoded.is_empty() || decoded.len() > max_len {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS key member is empty or too large",
        ));
    }
    Ok(decoded)
}

/// Wrap SPKI DER into a 64-column `PUBLIC KEY` PEM block.
fn spki_pem_from_der(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 64 + 64);
    out.push_str(PEM_PUBLIC_KEY_BEGIN);
    for (index, byte) in encoded.bytes().enumerate() {
        if index % 64 == 0 {
            out.push('\n');
        }
        out.push(byte as char);
    }
    out.push('\n');
    out.push_str(PEM_PUBLIC_KEY_END);
    out.push('\n');
    out
}

/// Minimal DER writers. Only the shapes an SPKI needs, and only for lengths a
/// bounded key can produce — every input here is already size-checked.
fn der_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len() + 5);
    out.push(tag);
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(contents);
    out
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut contents = Vec::new();
    for part in parts {
        contents.extend_from_slice(part);
    }
    der_tlv(0x30, &contents)
}

fn der_oid(content: &[u8]) -> Vec<u8> {
    der_tlv(0x06, content)
}

fn der_null() -> Vec<u8> {
    der_tlv(0x05, &[])
}

/// BIT STRING with a zero "unused bits" prefix octet.
fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(content.len() + 1);
    body.push(0x00);
    body.extend_from_slice(content);
    der_tlv(0x03, &body)
}

/// INTEGER from unsigned big-endian bytes. A leading `0x00` is prepended when
/// the high bit is set, so the value never round-trips as negative.
fn der_positive_integer(unsigned_be: &[u8]) -> Vec<u8> {
    let first_significant = unsigned_be
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(unsigned_be.len());
    let trimmed = &unsigned_be[first_significant..];
    if trimmed.is_empty() {
        return der_tlv(0x02, &[0x00]);
    }
    if trimmed[0] & 0x80 != 0 {
        let mut body = Vec::with_capacity(trimmed.len() + 1);
        body.push(0x00);
        body.extend_from_slice(trimmed);
        der_tlv(0x02, &body)
    } else {
        der_tlv(0x02, trimmed)
    }
}

/// Build a `jsonwebtoken` decoding key for a published authority, together
/// with the algorithms that authority is permitted to have signed with.
///
/// The permitted set is the **narrowest** of three things, in order:
///
/// 1. the authority's own [`PublishedJwtAuthority::declared_alg`], when it
///    declared one and the key type could have produced it (a declaration the
///    key type cannot produce is an error, never a widening);
/// 2. for an undeclared **RSA** key, `RS256` alone — RFC 7518 §3.1's only
///    Recommended RSASSA algorithm. Accepting the whole RS*/PS* family for a key
///    that said nothing would let a consumed bundle be verified under
///    algorithms its publisher never intended;
/// 3. otherwise the algorithms the key type can produce, which for the EC curves
///    Ferrum supports is exactly one anyway.
///
/// The token header's `alg` is never an input.
pub fn decoding_key_for_authority(
    authority: &PublishedJwtAuthority,
) -> Result<(DecodingKey, Vec<Algorithm>), JwtSvidError> {
    validate_key_id(&authority.key_id)?;
    let spki_der = spki_der_from_pem(&authority.public_key_pem)?;
    let key = jwk_public_key(&spki_der)?;
    let allowed_algs = match authority.declared_alg {
        Some(declared) => {
            if !key.allowed_algs.contains(&declared) {
                return Err(JwtSvidError::InvalidAuthority(
                    "a JWT authority declares a signature algorithm its key type cannot produce",
                ));
            }
            vec![declared]
        }
        None if key.kty == "RSA" => vec![Algorithm::RS256],
        None => key.allowed_algs.clone(),
    };
    let pem_bytes = authority.public_key_pem.as_bytes();
    let decoding = match key.kty {
        "EC" => DecodingKey::from_ec_pem(pem_bytes),
        "RSA" => DecodingKey::from_rsa_pem(pem_bytes),
        _ => {
            return Err(JwtSvidError::InvalidAuthority(
                "unsupported JWT authority key type",
            ));
        }
    }
    .map_err(|_| JwtSvidError::InvalidAuthority("JWT authority public key is unusable"))?;
    Ok((decoding, allowed_algs))
}

fn validate_key_id(key_id: &str) -> Result<(), JwtSvidError> {
    if key_id.is_empty() {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority key id must not be empty",
        ));
    }
    if key_id.len() > MAX_JWT_KEY_ID_BYTES {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority key id is too long",
        ));
    }
    if key_id.chars().any(|c| c.is_control()) {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority key id contains control characters",
        ));
    }
    Ok(())
}

/// Decode exactly one `PUBLIC KEY` PEM block into SPKI DER.
///
/// The document must contain **only** that block plus surrounding whitespace.
/// Rejected outright, rather than skipped over:
///
/// - anything but whitespace before `-----BEGIN PUBLIC KEY-----` or after
///   `-----END PUBLIC KEY-----`. Silently accepting arbitrary surrounding data
///   means the bytes an operator reviewed and the bytes Ferrum trusts are not
///   the same document — including a second, differently-labelled key envelope
///   that a reader would reasonably assume was in use;
/// - a second `PUBLIC KEY` block. An operator (or a federated peer)
///   concatenating several keys under one `kid` would otherwise silently have
///   only the first honoured.
fn spki_der_from_pem(pem: &str) -> Result<Vec<u8>, JwtSvidError> {
    if pem.is_empty() {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key PEM is empty",
        ));
    }
    if pem.len() > MAX_JWT_PUBLIC_KEY_PEM_BYTES {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key PEM is too large",
        ));
    }
    let begin = pem
        .find(PEM_PUBLIC_KEY_BEGIN)
        .ok_or(JwtSvidError::InvalidAuthority(
            "JWT authority public key is not a PUBLIC KEY PEM block",
        ))?;
    // Only whitespace may precede the envelope.
    if !pem[..begin].trim().is_empty() {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key PEM carries data before its PUBLIC KEY block",
        ));
    }
    let body_start = begin + PEM_PUBLIC_KEY_BEGIN.len();
    let rest = &pem[body_start..];
    let end = rest
        .find(PEM_PUBLIC_KEY_END)
        .ok_or(JwtSvidError::InvalidAuthority(
            "JWT authority public key PEM block is unterminated",
        ))?;
    let after_end = &rest[end + PEM_PUBLIC_KEY_END.len()..];
    if after_end.contains(PEM_PUBLIC_KEY_BEGIN) {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key PEM contains more than one block",
        ));
    }
    // ...and only whitespace may follow it. This subsumes the multi-block check
    // above for `PUBLIC KEY`, and additionally refuses a trailing envelope of
    // any other label (`CERTIFICATE`, `EC PRIVATE KEY`, …) rather than ignoring
    // material an operator would read as part of the document.
    if !after_end.trim().is_empty() {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key PEM carries data after its PUBLIC KEY block",
        ));
    }

    let base64_body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    let der = STANDARD.decode(base64_body.as_bytes()).map_err(|_| {
        JwtSvidError::InvalidAuthority("JWT authority public key PEM is not base64")
    })?;
    if der.is_empty() || der.len() > MAX_SPKI_DER_BYTES {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key DER is empty or oversized",
        ));
    }
    Ok(der)
}

/// Decompose an SPKI DER document into JWK members and the algorithms its key
/// type is allowed to have signed with.
fn jwk_public_key(spki_der: &[u8]) -> Result<JwkPublicKey, JwtSvidError> {
    let (rest, spki) = SubjectPublicKeyInfo::from_der(spki_der).map_err(|_| {
        JwtSvidError::InvalidAuthority("JWT authority public key is not a valid SPKI document")
    })?;
    if !rest.is_empty() {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key has trailing SPKI bytes",
        ));
    }
    let parsed = spki.parsed().map_err(|_| {
        JwtSvidError::InvalidAuthority("JWT authority public key could not be parsed")
    })?;

    match parsed {
        PublicKey::EC(_) => {
            let curve = ec_curve(&spki)?;
            // Read the point from the SPKI BIT STRING directly: `ECPoint` is
            // just a view over these bytes, and its accessor is tied to the
            // SPKI's own lifetime rather than the local binding's.
            let data: &[u8] = spki.subject_public_key.data.as_ref();
            let expected = 1 + 2 * curve.coordinate_bytes;
            if data.len() != expected || data[0] != 0x04 {
                return Err(JwtSvidError::InvalidAuthority(
                    "JWT authority EC public key is not an uncompressed point of the named curve",
                ));
            }
            // Shape is not membership: an OID, an uncompressed marker, and two
            // correctly sized coordinates describe a point that need not lie on
            // the curve at all. Prove it does before the key is published or
            // used to build a verifier.
            check_ec_point_on_curve(&curve, data)?;
            let (x, y) = data[1..].split_at(curve.coordinate_bytes);
            Ok(JwkPublicKey {
                kty: "EC",
                members: vec![
                    ("crv", curve.jwk_name.to_string()),
                    ("x", URL_SAFE_NO_PAD.encode(x)),
                    ("y", URL_SAFE_NO_PAD.encode(y)),
                ],
                preferred_alg: curve.alg,
                allowed_algs: vec![curve.alg],
            })
        }
        PublicKey::RSA(rsa) => {
            let modulus = strip_leading_zeros(rsa.modulus);
            let exponent = strip_leading_zeros(rsa.exponent);
            check_rsa_modulus(modulus)?;
            check_rsa_exponent(exponent)?;
            Ok(JwkPublicKey {
                kty: "RSA",
                members: vec![
                    ("e", URL_SAFE_NO_PAD.encode(exponent)),
                    ("n", URL_SAFE_NO_PAD.encode(modulus)),
                ],
                preferred_alg: Algorithm::RS256,
                allowed_algs: vec![
                    Algorithm::RS256,
                    Algorithm::RS384,
                    Algorithm::RS512,
                    Algorithm::PS256,
                    Algorithm::PS384,
                    Algorithm::PS512,
                ],
            })
        }
        _ => Err(JwtSvidError::InvalidAuthority(
            "unsupported JWT authority key type",
        )),
    }
}

/// Significant bit length of an unsigned big-endian integer, ignoring leading
/// zero bytes. `0` for a zero (or empty) value.
fn significant_bit_length(unsigned_be: &[u8]) -> u32 {
    let significant = strip_leading_zeros(unsigned_be);
    match significant.first() {
        None => 0,
        // `strip_leading_zeros` guarantees a nonzero first byte, so
        // `leading_zeros()` is at most 7 and the subtraction cannot underflow.
        Some(first) => (significant.len() as u32 - 1) * 8 + (8 - first.leading_zeros()),
    }
}

/// Admit an RSA modulus only when it is odd and inside the documented
/// `2048..=8192` significant-bit range.
///
/// A byte-length floor is not equivalent: 256 bytes whose top byte is `0x01`
/// carries 2041 significant bits, which is weaker than the module claims to
/// accept, and leading zero bytes contribute nothing at all. The upper bound is
/// enforced for the same reason it is documented — an unbounded modulus makes
/// every verification against that authority arbitrarily expensive.
///
/// Size is not the only structural fact available for free. An RSA modulus is a
/// product of odd primes, so it is **odd**; an even value is not an RSA modulus
/// at all, however well-sized and canonically encoded it is. Refusing it here
/// costs one bit test and keeps a malformed or hostile authority from being
/// republished in `FetchJWTBundles` or turned into a `DecodingKey`. The exponent
/// has always been parity-checked; the modulus not being was the asymmetry.
fn check_rsa_modulus(modulus: &[u8]) -> Result<(), JwtSvidError> {
    let bits = significant_bit_length(modulus);
    if bits < MIN_RSA_MODULUS_BITS {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority RSA public key is smaller than 2048 significant bits",
        ));
    }
    if bits > MAX_RSA_MODULUS_BITS {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority RSA public key is larger than the 8192-bit ceiling",
        ));
    }
    // The bit-length floor above guarantees a nonempty significant slice, so a
    // missing least-significant byte cannot silently pass as odd.
    if strip_leading_zeros(modulus)
        .last()
        .is_none_or(|byte| byte % 2 == 0)
    {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority RSA public key modulus is even; a modulus is a product of odd primes",
        ));
    }
    Ok(())
}

/// Admit an RSA public exponent only when it is odd and at least 3.
///
/// `0`, `1`, and `2` are not usable RSA exponents (`1` is the identity and an
/// even exponent cannot be coprime with φ(n)), and an even exponent generally is
/// a malformed or hostile JWK rather than an unusual key. The size bound is
/// applied by the caller before this runs, which is what makes the `u64`
/// conversion below total.
fn check_rsa_exponent(exponent: &[u8]) -> Result<(), JwtSvidError> {
    let significant = strip_leading_zeros(exponent);
    if significant.is_empty() || significant.len() > MAX_RSA_EXPONENT_BYTES {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority RSA public exponent is empty or oversized",
        ));
    }
    let mut value: u64 = 0;
    for byte in significant {
        value = (value << 8) | u64::from(*byte);
    }
    if value < MIN_RSA_PUBLIC_EXPONENT || value.is_multiple_of(2) {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority RSA public exponent must be an odd value of at least 3",
        ));
    }
    Ok(())
}

/// Prove an uncompressed SEC1 point really lies on its named curve, and is not
/// the identity.
///
/// Delegated to [`crate::fips::ec_point_on_named_curve`], the provider seam: a
/// bounded ephemeral ECDH agreement whose shared secret is discarded, because
/// both backends validate the peer public key (SEC1 §3.2.2) as part of accepting
/// it and neither exposes that validation on its own. Routing it through the
/// seam keeps the arithmetic on the *selected* provider — `ring` on an ordinary
/// build, the AWS-LC FIPS module on a `fips` build — instead of adding a second,
/// unrouted elliptic implementation on a trust-admission path.
///
/// An **unavailable** check is a failure, never an acceptance, and no error
/// carries any key bytes.
fn check_ec_point_on_curve(curve: &EcCurve, point: &[u8]) -> Result<(), JwtSvidError> {
    use crate::fips::{EcPointCheck, backend::agreement, ec_point_on_named_curve};

    let algorithm = match curve.jwk_name {
        "P-256" => &agreement::ECDH_P256,
        "P-384" => &agreement::ECDH_P384,
        _ => {
            return Err(JwtSvidError::InvalidAuthority(
                "unsupported JWT authority EC curve",
            ));
        }
    };
    match ec_point_on_named_curve(algorithm, point) {
        EcPointCheck::OnCurve => Ok(()),
        EcPointCheck::Invalid => Err(JwtSvidError::InvalidAuthority(
            "JWT authority EC public key is not a valid point on its named curve",
        )),
        EcPointCheck::Unavailable => Err(JwtSvidError::Internal(
            "EC public-key validation could not be performed".to_string(),
        )),
    }
}

struct EcCurve {
    jwk_name: &'static str,
    coordinate_bytes: usize,
    alg: Algorithm,
}

/// Resolve the named curve from the SPKI algorithm parameters.
///
/// The curve is taken from the OID, not inferred from the coordinate length:
/// brainpoolP256r1 has the same 32-byte coordinates as P-256 and must not be
/// silently verified as `ES256`.
fn ec_curve(spki: &SubjectPublicKeyInfo<'_>) -> Result<EcCurve, JwtSvidError> {
    let parameters = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or(JwtSvidError::InvalidAuthority(
            "JWT authority EC public key names no curve",
        ))?;
    if parameters.tag() != Tag::Oid {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority EC curve parameter is not an OID",
        ));
    }
    let oid = parameters.as_bytes();
    if oid == OID_BYTES_P256 {
        Ok(EcCurve {
            jwk_name: "P-256",
            coordinate_bytes: 32,
            alg: Algorithm::ES256,
        })
    } else if oid == OID_BYTES_P384 {
        Ok(EcCurve {
            jwk_name: "P-384",
            coordinate_bytes: 48,
            alg: Algorithm::ES384,
        })
    } else {
        Err(JwtSvidError::InvalidAuthority(
            "unsupported JWT authority EC curve",
        ))
    }
}

/// DER INTEGERs carry a leading `0x00` when the high bit is set; JWK `n` / `e`
/// are unsigned big-endian with no such padding (RFC 7518 §6.3.1).
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[first_significant..]
}
