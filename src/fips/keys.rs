//! Approved key strengths and forms for operator-controlled key material.
//!
//! # Why this exists separately from the provider
//!
//! Selecting the AWS-LC FIPS module decides *which implementation* computes a
//! signature. It does not, on its own, decide which **keys** Ferrum will agree
//! to serve with. Those are two different gates, and only one of them is the
//! provider's:
//!
//! - The rustls FIPS provider does reject a non-approved *algorithm* — it will
//!   not negotiate a suite, group, or signature scheme outside the approved
//!   set, and `fips::policy::check_tls_policy` re-asserts that over the
//!   constructed policy.
//! - It does **not** uniformly reject an approved algorithm used with an
//!   under-strength key. An RSA-1024 leaf certificate is `rsaEncryption` with
//!   `rsa_pkcs1_sha256`, both nominally approved; SP 800-131A Rev. 2 disallows
//!   the 1024-bit *key*, not the scheme. Depending on the construction path
//!   that key can reach a handshake, or it can fail later with an opaque
//!   provider error that names nothing the operator can act on.
//!
//! So this module is the Ferrum-enforced half, applied at admission: at the
//! single PEM certificate-loading boundary
//! ([`crate::tls::parse_pem_certificate_bundle`]) and at the JWKS key-admission
//! boundary. Both are construction/reload paths, never the request hot path.
//!
//! # What is checked, and on what material
//!
//! Only **public** key material is inspected: the `SubjectPublicKeyInfo` of a
//! certificate, or the public components of a JWK. Private keys keep flowing
//! through the existing secure loading boundary
//! ([`crate::tls::parse_pem_private_key`]) untouched — this module never parses,
//! copies, or logs private-key bytes. That is deliberate: a private key's
//! strength is pinned by the certificate it is paired with, so the public side
//! is both sufficient and the safe place to look.
//!
//! # Diagnostics
//!
//! Every diagnostic names the fixed Ferrum surface label, the key algorithm
//! family, and the observed strength in bits. It never interpolates a file
//! path, a URL, a subject name, or any key bytes. The surface label is bounded
//! to [`MAX_SURFACE_LABEL_CHARS`] because a few callers derive it from a
//! configuration-supplied source kind.

use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

/// Minimum approved RSA modulus size, in bits.
///
/// SP 800-131A Rev. 2 disallows RSA below 2048 bits for signature generation
/// and key transport. 1024-bit RSA has been disallowed since 2013.
pub const MIN_RSA_MODULUS_BITS: usize = 2048;

/// Largest RSA modulus Ferrum will admit, in bits.
///
/// Not a security floor — a bound. A certificate carrying a 64 Kib modulus is
/// a denial-of-service vector against every handshake that uses it, and no
/// approved profile needs one.
pub const MAX_RSA_MODULUS_BITS: usize = 8192;

/// Approved elliptic-curve field sizes, in bits: P-256, P-384, P-521.
///
/// These are the NIST prime curves of FIPS 186-5 / SP 800-186. Curve25519 and
/// Curve448 are absent: they are not approved for the ECDSA/ECDH schemes in
/// SP 800-56A, which is also why `fips::policy::FIPS_DEFAULT_KX_GROUPS` omits
/// X25519.
///
/// P-521 is admitted for *certificates* even though `ES512` is refused for
/// JWS. That is not an inconsistency: the JWS exclusion is about the
/// `jsonwebtoken` backend's implementation contract, while a P-521 certificate
/// is handled by the rustls provider, which classifies `secp521r1` itself.
pub const APPROVED_EC_FIELD_BITS: &[usize] = &[256, 384, 521];

/// Upper bound on how much of a surface label a diagnostic reproduces.
pub const MAX_SURFACE_LABEL_CHARS: usize = 64;

/// Truncate a caller-supplied surface label to a bounded, single-line form.
fn bounded_label(label: &str) -> String {
    let sanitized: String = label
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_SURFACE_LABEL_CHARS)
        .collect();
    if sanitized.is_empty() {
        "configured key material".to_string()
    } else {
        sanitized
    }
}

/// Admit one certificate's public key, when FIPS mode is enforced.
///
/// `surface_label` is the fixed Ferrum vocabulary label the caller already uses
/// for this material ("frontend TLS certificate", "backend CA bundle", …).
pub fn check_certificate_public_key(der: &[u8], surface_label: &str) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_certificate_public_key_enforced(der, surface_label)
}

/// The enforced half of [`check_certificate_public_key`].
///
/// Split out so the policy is directly testable on an ordinary build, where
/// enforcement can never be established at runtime — the same split
/// `fips::policy` uses.
pub fn check_certificate_public_key_enforced(
    der: &[u8],
    surface_label: &str,
) -> Result<(), String> {
    let label = bounded_label(surface_label);

    // PEM framing alone does not prove that the decoded record is valid X.509
    // DER. Fail here before serving: an unparseable record has no classifiable
    // key form, and several trust-bundle consumers would otherwise silently
    // skip it rather than produce an actionable admission error.
    let (remaining, certificate) = X509Certificate::from_der(der).map_err(|_| {
        format!(
            "{label}: the certificate DER could not be parsed and its public-key form cannot be \
             classified, so it is refused while FIPS mode is enforced."
        )
    })?;
    if !remaining.is_empty() {
        return Err(format!(
            "{label}: the certificate DER contains trailing data and its public-key form cannot \
             be classified unambiguously, so it is refused while FIPS mode is enforced."
        ));
    }

    let spki = certificate.public_key();
    let Ok(parsed) = spki.parsed() else {
        return Err(format!(
            "{label}: the certificate's public key could not be classified against the approved \
             key set, so it is refused while FIPS mode is enforced. Approved: RSA \
             {MIN_RSA_MODULUS_BITS}-{MAX_RSA_MODULUS_BITS} bits, or ECDSA over P-256/P-384/P-521."
        ));
    };

    match parsed {
        PublicKey::RSA(rsa) => {
            check_rsa_modulus_bits(unsigned_be_bit_length(rsa.modulus), &label)?;
            check_rsa_public_exponent_enforced(rsa.exponent, &label)
        }
        PublicKey::EC(point) => {
            let curve_oid = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.as_oid().ok())
                .ok_or_else(|| {
                    format!(
                        "{label}: the certificate's elliptic-curve parameters do not name a \
                         curve, so the key is refused while FIPS mode is enforced. Approved \
                         curves: P-256, P-384, P-521."
                    )
                })?;
            check_ec_curve_oid_and_point_enforced(&curve_oid.to_string(), point.data(), &label)
        }
        // Everything else is a definite "no", not an unclassified maybe. DSA is
        // withdrawn for signature generation by FIPS 186-5; the GOST curves are
        // not in any approved set; `Unknown` covers Ed25519/Ed448/X25519 and
        // any future algorithm this build has not classified.
        PublicKey::DSA(_) => Err(format!(
            "{label}: the certificate carries a DSA public key. FIPS 186-5 withdrew DSA for \
             signature generation, so it is refused while FIPS mode is enforced. Use RSA \
             (>= {MIN_RSA_MODULUS_BITS} bits) or ECDSA over P-256/P-384/P-521."
        )),
        PublicKey::GostR3410(_) | PublicKey::GostR3410_2012(_) => Err(format!(
            "{label}: the certificate carries a GOST R 34.10 public key, which is not in an \
             approved algorithm set and is refused while FIPS mode is enforced."
        )),
        PublicKey::Unknown(_) => Err(format!(
            "{label}: the certificate's public-key algorithm is not one Ferrum routes through the \
             selected cryptographic module (this includes Ed25519, Ed448, and X25519 keys), so it \
             is refused while FIPS mode is enforced. Use RSA (>= {MIN_RSA_MODULUS_BITS} bits) or \
             ECDSA over P-256/P-384/P-521."
        )),
    }
}

/// Exact bit length of an unsigned big-endian integer.
///
/// Certificate RSA moduli may carry DER sign padding and JWK issuers sometimes
/// add non-canonical leading zeroes. Neither may be credited as key strength.
fn unsigned_be_bit_length(bytes: &[u8]) -> usize {
    let significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map(|start| &bytes[start..])
        .unwrap_or(&[]);
    let Some(first) = significant.first() else {
        return 0;
    };
    (significant.len() - 1)
        .saturating_mul(8)
        .saturating_add(8usize.saturating_sub(first.leading_zeros() as usize))
}

/// Admit an EC named-curve OID and its SEC1 point encoding.
///
/// Curve identity comes from the RFC 5480 AlgorithmIdentifier parameters, not
/// from point length: secp256k1 and P-256 have identically sized points, while
/// P-521 coordinates occupy 66 octets and therefore look like 528 bits when
/// rounded to bytes. `curve_oid` is a public registry identifier and is never
/// reproduced in diagnostics.
#[doc(hidden)]
pub fn check_ec_curve_oid_and_point_enforced(
    curve_oid: &str,
    point: &[u8],
    surface_label: &str,
) -> Result<(), String> {
    let label = bounded_label(surface_label);
    let (curve_name, coordinate_bytes) = match curve_oid {
        "1.2.840.10045.3.1.7" => ("P-256", 32usize),
        "1.3.132.0.34" => ("P-384", 48usize),
        "1.3.132.0.35" => ("P-521", 66usize),
        _ => {
            return Err(format!(
                "{label}: the certificate names an elliptic curve outside the approved set and \
                 is refused while FIPS mode is enforced. Approved curves: P-256, P-384, P-521."
            ));
        }
    };
    let valid_length = match point.first().copied() {
        Some(0x04) => point.len() == 1 + 2 * coordinate_bytes,
        Some(0x02 | 0x03) => point.len() == 1 + coordinate_bytes,
        _ => false,
    };
    if !valid_length {
        return Err(format!(
            "{label}: the certificate carries a malformed {curve_name} public-point encoding and \
             is refused while FIPS mode is enforced."
        ));
    }
    Ok(())
}

/// Shared RSA strength rule for certificates and JWKs.
///
/// Public and ungated: it is a pure predicate over an already-measured bit
/// count, so it is the unit both admission paths agree on and the one a test
/// can exercise without minting an under-strength key. The mode gate lives on
/// the callers above.
pub fn check_rsa_modulus_bits(bits: usize, label: &str) -> Result<(), String> {
    if bits == 0 {
        return Err(format!(
            "{label}: the RSA public key's modulus could not be measured, so its strength cannot \
             be established and it is refused while FIPS mode is enforced."
        ));
    }
    if bits < MIN_RSA_MODULUS_BITS {
        return Err(format!(
            "{label}: the RSA public key is {bits} bits. FIPS mode requires at least \
             {MIN_RSA_MODULUS_BITS} bits (SP 800-131A Rev. 2 disallows shorter RSA keys for \
             signature generation and key transport)."
        ));
    }
    if bits > MAX_RSA_MODULUS_BITS {
        return Err(format!(
            "{label}: the RSA public key is {bits} bits, above the {MAX_RSA_MODULUS_BITS}-bit \
             admission ceiling. An oversized modulus is a handshake denial-of-service vector and \
             no approved profile requires one."
        ));
    }
    Ok(())
}

/// Admit an RSA modulus for JWT signature verification, on every profile.
///
/// jsonwebtoken's `aws_lc_rs` backend (the only one Ferrum compiles) verifies
/// RS*/PS* only with RSA keys of [`MIN_RSA_MODULUS_BITS`]–[`MAX_RSA_MODULUS_BITS`]
/// bits. A key outside that window still decodes, but every token signed with
/// it would then fail verification as if it were forged. Admission points call
/// this so such a key is refused up front, with its size named. Not gated on
/// FIPS mode: the limit is the backend's, so it applies to both profiles.
pub fn check_jwt_rsa_verification_modulus(
    modulus: &[u8],
    surface_label: &str,
) -> Result<(), String> {
    let bits = unsigned_be_bit_length(modulus);
    if (MIN_RSA_MODULUS_BITS..=MAX_RSA_MODULUS_BITS).contains(&bits) {
        return Ok(());
    }
    let label = bounded_label(surface_label);
    Err(format!(
        "{label}: the RSA public key is {bits} bits. JWT signatures are verified with AWS-LC, \
         which accepts only RSA keys of {MIN_RSA_MODULUS_BITS}-{MAX_RSA_MODULUS_BITS} bits, so \
         every token signed with this key would fail verification."
    ))
}

/// [`check_jwt_rsa_verification_modulus`] over a PKCS#1 `RSAPublicKey` DER,
/// the form jsonwebtoken stores for an RSA PEM public key (it unwraps an SPKI
/// `PUBLIC KEY` to this).
pub fn check_jwt_rsa_verification_pkcs1_der(der: &[u8], surface_label: &str) -> Result<(), String> {
    let parsed = x509_parser::public_key::RSAPublicKey::from_der(der);
    match parsed {
        Ok((remaining, key)) if remaining.is_empty() => {
            check_jwt_rsa_verification_modulus(key.modulus, surface_label)
        }
        _ => Err(format!(
            "{}: the RSA public key could not be parsed, so its size cannot be checked.",
            bounded_label(surface_label)
        )),
    }
}

/// Admit a JWK RSA modulus, when FIPS mode is enforced.
///
/// `modulus` is the decoded, unsigned big-endian `n` member of an RFC 7518 RSA
/// JWK — public material only. JWKs are fetched from an operator-configured
/// issuer, so a weak signing key admitted here would let that issuer's
/// compromise become Ferrum's authentication failure.
pub fn check_jwk_rsa_modulus(modulus: &[u8]) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_jwk_rsa_modulus_enforced(modulus)
}

/// The enforced half of [`check_jwk_rsa_modulus`].
pub fn check_jwk_rsa_modulus_enforced(modulus: &[u8]) -> Result<(), String> {
    check_rsa_modulus_bits(unsigned_be_bit_length(modulus), "JWKS RSA signing key")
}

/// Admit all security-relevant RSA JWK public components.
pub fn check_jwk_rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_jwk_rsa_public_key_enforced(modulus, exponent)
}

/// The enforced half of [`check_jwk_rsa_public_key`].
pub fn check_jwk_rsa_public_key_enforced(modulus: &[u8], exponent: &[u8]) -> Result<(), String> {
    check_jwk_rsa_modulus_enforced(modulus)?;
    check_rsa_public_exponent_enforced(exponent, "JWKS RSA signing key")
}

fn check_rsa_public_exponent_enforced(exponent: &[u8], surface_label: &str) -> Result<(), String> {
    let significant = exponent
        .iter()
        .position(|byte| *byte != 0)
        .map(|start| &exponent[start..])
        .unwrap_or(&[]);
    let greater_than_65536 = significant.len() > 3
        || (significant.len() == 3 && significant > [0x01, 0x00, 0x00].as_slice());
    if significant.is_empty()
        || significant.len() > 32
        || !greater_than_65536
        || !significant.last().is_some_and(|byte| byte & 1 == 1)
    {
        return Err(format!(
            "{surface_label} has an RSA public exponent outside the admitted FIPS 186-5 form \
             (odd, greater than 65536, and at most 256 bits)."
        ));
    }
    Ok(())
}

/// Approved JWK elliptic curves, as spelled in the RFC 7518 `crv` member.
///
/// P-521 is absent because its only JWS use is `ES512`, which
/// [`super::policy::APPROVED_JWT_ALGORITHMS`] refuses — see that constant for
/// why. Admitting the curve while refusing every algorithm that can use it
/// would just move the failure later.
pub const APPROVED_JWK_EC_CURVES: &[&str] = &["P-256", "P-384"];

/// Admit a JWK elliptic curve, when FIPS mode is enforced.
pub fn check_jwk_ec_curve(curve: &str) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_jwk_ec_curve_enforced(curve)
}

/// The enforced half of [`check_jwk_ec_curve`].
pub fn check_jwk_ec_curve_enforced(curve: &str) -> Result<(), String> {
    // RFC 7518 registry values are case-sensitive. Requiring the exact token
    // keeps this admission decision identical to the downstream algorithm
    // dispatch in `JwksKeyStore`; a normalized alias must not pass policy and
    // then select a different/default algorithm later.
    if APPROVED_JWK_EC_CURVES.contains(&curve) {
        return Ok(());
    }
    // `crv` is a fixed RFC 7518 registry vocabulary, so naming the observed
    // value is actionable and discloses nothing.
    let observed = bounded_label(curve);
    Err(format!(
        "JWKS EC signing key names curve `{observed}`, which is not admitted while FIPS mode is \
         enforced. Approved: {}.",
        APPROVED_JWK_EC_CURVES.join(", ")
    ))
}

/// Admit the complete public portion of an EC JWK.
pub fn check_jwk_ec_public_key(curve: Option<&str>, x: &[u8], y: &[u8]) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_jwk_ec_public_key_enforced(curve, x, y)
}

/// The enforced half of [`check_jwk_ec_public_key`].
pub fn check_jwk_ec_public_key_enforced(
    curve: Option<&str>,
    x: &[u8],
    y: &[u8],
) -> Result<(), String> {
    let curve = curve.ok_or_else(|| {
        "JWKS EC signing key omits `crv`, so its approved curve cannot be established while FIPS \
         mode is enforced."
            .to_string()
    })?;
    check_jwk_ec_curve_enforced(curve)?;
    let expected = match curve {
        "P-256" => 32,
        "P-384" => 48,
        _ => return Err("JWKS EC signing key names an unsupported curve.".to_string()),
    };
    if x.len() != expected || y.len() != expected {
        return Err(format!(
            "JWKS EC signing key has malformed public coordinates for {}; each coordinate must \
             be exactly {expected} bytes while FIPS mode is enforced.",
            curve
        ));
    }
    Ok(())
}
