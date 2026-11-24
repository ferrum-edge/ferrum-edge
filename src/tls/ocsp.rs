//! Certificate-bound validation of stapled OCSP responses (issue #4300).
//!
//! Ferrum used to accept any non-empty byte string as a stapled OCSP response
//! and attach it to the served `CertifiedKey`. Strict TLS clients abort the
//! handshake when the staple is malformed, expired, not yet valid, signed by an
//! unauthorized responder, or bound to a different certificate, so a config
//! reload or an admin mutation could turn a "loaded successfully" log line into
//! a protocol-wide outage. This module is the single validation path shared by
//! every source (file, inline, provider URI, Kubernetes Secret, managed store)
//! and by both the single-certificate and multi-certificate frontends.
//!
//! # What is enforced
//!
//! 1. **Bounded size.** The DER is rejected before any parsing when it exceeds
//!    [`MAX_OCSP_RESPONSE_BYTES`]. A stapled response is a small object; the
//!    generic TLS material cap ([`crate::tls::source`]) is sized for
//!    certificate bundles and is far too permissive to be the only bound in
//!    front of an ASN.1 parser.
//! 2. **A successful envelope.** `OCSPResponse.responseStatus` must be
//!    `successful(0)` and `responseBytes.responseType` must be
//!    `id-pkix-ocsp-basic`, carrying a `BasicOCSPResponse` (RFC 6960 §4.2.1).
//! 3. **A fully consumed grammar.** `ResponseData` and each `SingleResponse`
//!    are parsed to their last byte. Every optional field must appear at most
//!    once, in its defined position; unknown, duplicate, misordered, or
//!    trailing elements are refused rather than skipped, because a field this
//!    parser ignores is still inside the bytes the responder signed. Every
//!    `GeneralizedTime` is restricted to DER's `YYYYMMDDHHMMSSZ` profile and
//!    decoded, not merely tagged. An `Extensions` container is parsed
//!    structurally and must not repeat an extension OID, and because Ferrum
//!    implements no OCSP response extension, a *critical* one is refused (RFC
//!    6960 §4.4); a non-critical one is ignored after that strict parse.
//! 4. **A strict DER encoding, not merely a plausible one.** Every field
//!    boundary checks the ASN.1 *class* and the primitive/constructed bit as
//!    well as the tag number, so a context-specific element that reuses a
//!    universal tag number, a primitive "SEQUENCE", or a constructed OCTET
//!    STRING is refused instead of being decoded as the field it imitates.
//!    `Any::from_der` enforces definite lengths but not their minimal DER
//!    encoding, so every TLV this grammar walks is also checked for the shortest
//!    possible length octets. Each primitive is then checked against its
//!    type-specific DER rules:
//!    OBJECT IDENTIFIER content must be a complete canonical encoding
//!    (nonempty, terminated base-128 subidentifiers, no redundant leading
//!    `0x80` group); INTEGER and ENUMERATED content must be nonempty and
//!    minimal (one sign-protection `0x00` only when the next byte has its high
//!    bit set); a CertID serial must additionally be nonnegative; `successful(0)`
//!    and every `revocationReason` use that one canonical ENUMERATED encoding;
//!    the `BasicOCSPResponse` signature BIT STRING must be octet-aligned
//!    (`unused_bits == 0`) and nonempty, because the verifier hashes only the
//!    payload bytes and would otherwise accept a second encoding of the same
//!    signature; and `AlgorithmIdentifier` parameters follow a field- and
//!    algorithm-specific profile rather than one absent-or-NULL rule for every
//!    OID. `CertID.hashAlgorithm` accepts the two standards-compatible forms
//!    for digest identifiers — absent or canonical NULL — including unknown
//!    hash OIDs at the certificate-independent admin boundary (full validation
//!    still refuses an unsupported hash). `BasicOCSPResponse.signatureAlgorithm`
//!    applies the verifier-supported family: `ecdsa-with-SHA256` /
//!    `ecdsa-with-SHA384` and Ed25519 require absent parameters (RFC 5758 /
//!    RFC 8410), so a NULL that `x509_parser::verify_signature` would ignore is
//!    refused; RSA PKCS#1 (`sha*WithRSAEncryption`) requires the canonical
//!    NULL RFC 3279 and RFC 5754 specify when generating, so this
//!    strict-stapling policy rejects an omitted NULL; `rsassa-pss` requires
//!    present parameters parseable on the verification path, with no trailing
//!    or DEFAULT-encoded fields that parser would otherwise ignore. An unknown
//!    signature OID is refused at this grammar so it cannot be stored or
//!    served. `ResponseData.version` must be absent:
//!    DER omits a `DEFAULT` value, so an explicit `[0] INTEGER 0` would be a
//!    second encoding of one signed object, and any other version is
//!    unsupported. Every certificate carried in `certs` must parse as one
//!    complete X.509 `Certificate` with nothing left over — a malformed entry
//!    is refused even when a *different* carried certificate would have
//!    authorized the response.
//! 5. **A proven issuer.** The issuer is the chain member whose key actually
//!    signed the leaf, not merely one whose subject name matches the leaf's
//!    issuer name; same-name candidates are scanned until one verifies, and a
//!    self-issued leaf must be genuinely self-signed. This is what makes RFC
//!    6960's "CA that issued the certificate" explicit, and it is the same key
//!    a delegated responder must chain to.
//! 6. **`CertID` binding.** The single response for the configured leaf must
//!    match the leaf serial number and the `issuerNameHash` / `issuerKeyHash`
//!    of the configured issuer, recomputed under the `CertID` hash algorithm.
//!    A response that carries only *other* certificates' entries is rejected as
//!    wrong-certificate data rather than stapled, and a response carrying more
//!    than one entry for that certificate is rejected as ambiguous: a strict
//!    client re-derives the `CertID` itself and might select the other one.
//! 7. **Signature and responder authorization.** The `tbsResponseData`
//!    signature is verified against a responder that is either the issuer
//!    itself or a certificate carried in the response that is signed by the
//!    issuer, currently time-valid, carries the `id-kp-OCSPSigning` extended
//!    key usage (RFC 6960 §4.2.2.2), and — when it carries a `KeyUsage` at all
//!    — permits `digitalSignature`. Delegation to anything else is refused.
//! 8. **Time bounds.** `thisUpdate` must not be in the future and `nextUpdate`
//!    must not be in the past, each widened by [`OCSP_CLOCK_SKEW_SECONDS`]. A
//!    response without `nextUpdate` has no defined validity window and is refused: RFC
//!    6960 §2.4 makes an absent `nextUpdate` mean "newer information is
//!    available at all times", which is precisely the property a *stapled*
//!    (cached, re-served) response cannot have.
//! 9. **Status.** Only `good` is stapled. `revoked` and `unknown` fail closed:
//!    serving them is strictly worse than serving no staple at all, because a
//!    client that honours the staple will refuse the connection, and a reload
//!    must not be able to publish that state silently.
//!
//! # FIPS admission on this path
//!
//! Every signature this module verifies — the leaf-to-issuer proof, the
//! delegate-to-issuer proof, and the `BasicOCSPResponse` signature — goes
//! through `x509_parser::verify::verify_signature`. That API's supported set is
//! wider than Ferrum's FIPS contract: it selects
//! `RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY` for `sha1WithRSAEncryption`
//! (both registered OIDs) and `ED25519` for `id-Ed25519`, while `docs/fips.md`
//! records SHA-1 as disallowed for signature verification (SP 800-131A Rev. 2)
//! and Ed25519 as outside the algorithm set Ferrum routes through the selected
//! module. The SHA-1 arm is doubly wrong here: it also drops the RSA modulus
//! floor from 2048 bits to 1024.
//!
//! [`OcspCryptoPolicy`] is the seam that closes that gap. Under
//! [`OcspCryptoPolicy::FipsEnforced`] this module admits exactly
//! `sha256/384/512WithRSAEncryption`, `rsassa-pss` (already constrained to
//! SHA-2 by the parameter profile above), `ecdsa-with-SHA256`, and
//! `ecdsa-with-SHA384` — the verifier-supported set minus the two SHA-1 RSA
//! OIDs and Ed25519 — for the `BasicOCSPResponse` signature, for the served
//! leaf's own signature, and for every certificate carried in `certs`.
//!
//! Certificates carried in `certs` never pass through
//! [`crate::tls::parse_pem_certificate_bundle`], which is where Ferrum's
//! certificate key-form and key-strength admission normally runs, so an
//! embedded delegate could otherwise present an Ed25519 or RSA-1024 key to a
//! FIPS deployment. Each carried certificate is therefore admitted directly
//! through [`crate::fips::keys::check_certificate_public_key_enforced`], and so
//! is the issuer selected out of the served chain, so this module's guarantee
//! does not depend on what its callers already checked.
//!
//! Refusal is at the *grammar*, not only at serving time, so a non-approved
//! response cannot be stored by the admin boundary either. Outside enforcement
//! the profile is [`OcspCryptoPolicy::Interoperable`] and nothing here changes,
//! so ordinary deployments keep interoperating with responders that still sign
//! with SHA-1.
//!
//! ## What is *not* reclassified
//!
//! Two SHA-1 uses on this path are **key identifiers, not digital signatures**,
//! and both remain admitted under enforcement:
//!
//! - `CertID.issuerNameHash` / `CertID.issuerKeyHash`. RFC 6960 §4.1.1 defines
//!   `CertID` over a caller-chosen digest and real responders overwhelmingly
//!   use SHA-1; a client re-derives the same value to select an entry. Ferrum
//!   recomputes the hash and compares it, so it is a lookup key. The
//!   authenticity of the entry comes from the responder signature and from the
//!   **byte-exact** `serialNumber` comparison, neither of which is a digest.
//! - `ResponderID.byKey`, which RFC 6960 §4.2.1 defines as the SHA-1 hash of
//!   the responder's public-key BIT STRING contents. It selects which carried
//!   certificate to test; that certificate then has to be issuer-signed,
//!   OCSP-signing, time-valid, and produce a verifying signature.
//!
//! Neither digest carries a key, protects a secret, or decides admission on its
//! own, so neither is a security service in the SP 800-131A sense. Both are
//! computed through the selected provider ([`crate::fips::backend::digest`]),
//! not a second implementation. `src/fips/inventory.rs` records them under that
//! classification; do not conflate them with SHA-1 *signature* verification,
//! which this module refuses outright under enforcement.
//!
//! # Clock-skew policy
//!
//! Both time bounds are widened by [`OCSP_CLOCK_SKEW_SECONDS`] (5 minutes) in the
//! permissive direction only. The window Ferrum accepts is therefore
//! `thisUpdate - skew <= now <= nextUpdate + skew`. The skew is deliberately
//! not configurable: it exists to absorb ordinary NTP drift between the
//! responder and the gateway, not to let an operator extend the life of a stale
//! staple, which is what a large configurable value would really be for.
//!
//! # Diagnostics
//!
//! Every error is a short, structural description. No certificate bytes, no
//! response bytes, no key material, and no source URI are interpolated into the
//! message: callers add the already-redacted source identifier themselves.

use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::CertificateDer;
use x509_parser::asn1_rs::{Any, BitString, Class, FromDer, GeneralizedTime, Oid, Tag};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{
    OID_HASH_SHA1, OID_NIST_HASH_SHA256, OID_NIST_HASH_SHA384, OID_NIST_HASH_SHA512,
    OID_PKCS1_RSASSAPSS, OID_PKCS1_SHA1WITHRSA, OID_PKCS1_SHA256WITHRSA, OID_PKCS1_SHA384WITHRSA,
    OID_PKCS1_SHA512WITHRSA, OID_SHA1_WITH_RSA, OID_SIG_ECDSA_WITH_SHA256,
    OID_SIG_ECDSA_WITH_SHA384, OID_SIG_ED25519,
};
use x509_parser::signature_algorithm::RsaSsaPssParams;
use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use crate::fips::backend::digest;

/// Which `AlgorithmIdentifier` is being parsed, so parameter rules can follow
/// the field and the algorithm instead of one blanket absent-or-NULL profile.
#[derive(Debug, Clone, Copy)]
enum AlgorithmParameterProfile {
    /// `CertID.hashAlgorithm` and nested digest identifiers inside PSS.
    Digest,
    /// `BasicOCSPResponse.signatureAlgorithm`.
    Signature,
}

/// Cryptographic admission profile applied to the OCSP binding path.
///
/// This is the smallest seam that makes the FIPS half of this module testable.
/// [`crate::fips::is_enforcing`] is process-wide state that an ordinary
/// (`crypto-ring`) build can never establish at runtime — enforcement fails
/// closed at bootstrap on such a build — so a policy that only read that state
/// would be unreachable from any test the repository actually runs. Passing the
/// profile explicitly is the same split `fips::keys` and `fips::policy` use for
/// their `*_enforced` halves, expressed once as a value instead of once per
/// predicate, so the enforced path can be exercised end to end rather than one
/// isolated predicate at a time.
///
/// Production callers never construct a variant: they go through
/// [`validate_structure`] / [`validate_stapled_response`], which resolve it with
/// [`OcspCryptoPolicy::current`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspCryptoPolicy {
    /// Ordinary deployments: every algorithm the verification path supports.
    Interoperable,
    /// `FERRUM_FIPS_MODE=enforce`: only Ferrum's FIPS-approved algorithms and
    /// certificate key forms are admitted, at the grammar and at serving time.
    FipsEnforced,
}

impl OcspCryptoPolicy {
    /// Resolve the profile from this process's FIPS posture.
    pub fn current() -> Self {
        if crate::fips::is_enforcing() {
            Self::FipsEnforced
        } else {
            Self::Interoperable
        }
    }

    fn fips_enforced(self) -> bool {
        matches!(self, Self::FipsEnforced)
    }
}

/// Admit one signature `AlgorithmIdentifier` OID against the FIPS profile.
///
/// The admitted set is exactly what `x509_parser::verify::verify_signature`
/// supports, minus the two `sha1WithRSAEncryption` OIDs and `id-Ed25519`. Every
/// admitted RSA arm additionally carries ring/aws-lc's own 2048–8192-bit
/// modulus floor, which matches [`crate::fips::keys::MIN_RSA_MODULUS_BITS`] and
/// [`crate::fips::keys::MAX_RSA_MODULUS_BITS`]; the refused SHA-1 arm is the one
/// that would have accepted a 1024-bit modulus.
///
/// This is an allow-list, not a deny-list: an OID this build has not classified
/// is refused rather than passed to the verifier to be classified there.
fn check_signature_algorithm(
    oid: &Oid<'_>,
    field: &str,
    policy: OcspCryptoPolicy,
) -> Result<(), String> {
    if !policy.fips_enforced() {
        return Ok(());
    }
    if *oid == OID_PKCS1_SHA256WITHRSA
        || *oid == OID_PKCS1_SHA384WITHRSA
        || *oid == OID_PKCS1_SHA512WITHRSA
        || *oid == OID_PKCS1_RSASSAPSS
        || *oid == OID_SIG_ECDSA_WITH_SHA256
        || *oid == OID_SIG_ECDSA_WITH_SHA384
    {
        return Ok(());
    }
    Err(format!(
        "OCSP {field} names a signature algorithm outside Ferrum's FIPS-approved set, so it is \
         refused while FIPS mode is enforced. SHA-1 signatures are disallowed (SP 800-131A \
         Rev. 2) and Ed25519 is not in the algorithm set Ferrum routes through the selected \
         module. Approved: sha256/384/512WithRSAEncryption, rsassa-pss with SHA-256/384/512, \
         ecdsa-with-SHA256, ecdsa-with-SHA384."
    ))
}

/// Admit a certificate that is about to be used on this path — either because
/// its key verifies a signature, or because it is carried inside the response.
///
/// Delegates to the single Ferrum certificate key-form/key-strength gate so the
/// rule cannot drift from the one `parse_pem_certificate_bundle` applies.
fn check_certificate_key_form(
    der: &[u8],
    surface_label: &str,
    policy: OcspCryptoPolicy,
) -> Result<(), String> {
    if !policy.fips_enforced() {
        return Ok(());
    }
    crate::fips::keys::check_certificate_public_key_enforced(der, surface_label)
}

/// Maximum accepted size of a stapled OCSP response, in bytes.
///
/// Enforced *before* DER parsing. Real responses are a few hundred bytes to a
/// couple of kilobytes even when they embed a delegated responder certificate;
/// 64 KiB leaves generous headroom while keeping an unbounded ASN.1 walk off
/// the reload path.
pub const MAX_OCSP_RESPONSE_BYTES: usize = 64 * 1024;

/// Clock skew allowed on `thisUpdate` and `nextUpdate`, in seconds.
///
/// See the module documentation: permissive in both directions, fixed, and
/// deliberately not operator-tunable.
pub const OCSP_CLOCK_SKEW_SECONDS: i64 = 300;

/// DER content bytes of `id-pkix-ocsp-basic` (1.3.6.1.5.5.7.48.1.1).
const OID_PKIX_OCSP_BASIC_BYTES: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

/// DER content bytes of `id-mgf1` (1.2.840.113549.1.1.8).
const OID_MGF1_BYTES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];

/// Outcome of the certificate-independent structural pass.
///
/// This is what the admin boundary can prove about a stored OCSP record before
/// anyone has said which certificate it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcspStructure {
    /// Length of the validated DER, in bytes.
    pub der_len: usize,
    /// Number of `SingleResponse` entries in the `BasicOCSPResponse`.
    pub single_responses: usize,
    /// Soonest `nextUpdate` across the `SingleResponse` entries, as a Unix
    /// timestamp, or `None` when no entry declares one (issue #4505).
    ///
    /// Certificate-independent, so this is a lead-time signal only: the
    /// deadline that binds a served staple is the matched response's, which
    /// [`validate_stapled_response`] returns as
    /// [`OcspAcceptance::next_update`]. The two agree for the single-response
    /// staples an operator actually configures.
    pub earliest_next_update: Option<i64>,
}

/// Outcome of full, certificate-bound validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcspAcceptance {
    /// Length of the validated DER, in bytes.
    pub der_len: usize,
    /// `thisUpdate` of the matched `SingleResponse`, as a Unix timestamp.
    pub this_update: i64,
    /// `nextUpdate` of the matched `SingleResponse`, as a Unix timestamp.
    pub next_update: i64,
    /// `true` when the response was signed by a delegated responder rather than
    /// by the issuing CA directly.
    pub delegated_responder: bool,
}

/// Current wall-clock time as a Unix timestamp, saturating at the epoch.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Reject an over-large response before it reaches the DER parser.
fn enforce_size_bound(der: &[u8]) -> Result<(), String> {
    if der.is_empty() {
        return Err("OCSP response is empty".to_string());
    }
    if der.len() > MAX_OCSP_RESPONSE_BYTES {
        return Err(format!(
            "OCSP response is {} bytes, which exceeds the {MAX_OCSP_RESPONSE_BYTES}-byte maximum",
            der.len()
        ));
    }
    Ok(())
}

/// Parse exactly one DER TLV, returning the object, its complete encoding, and
/// the remaining input.
///
/// `asn1-rs` enforces definite lengths but does not enforce DER's minimal
/// length-octet encoding. Recompute the shortest length field for the decoded
/// content here so every grammar boundary inherits the missing constraint.
fn take_tlv(input: &[u8]) -> Result<(Any<'_>, &[u8], &[u8]), String> {
    let (rest, any) = Any::from_der(input).map_err(|error| format!("malformed DER: {error}"))?;
    let consumed = input.len() - rest.len();
    let first_identifier = input
        .first()
        .copied()
        .ok_or_else(|| "malformed DER: missing identifier octet".to_string())?;
    let identifier_octets = if first_identifier & 0x1f == 0x1f {
        input
            .get(1..)
            .ok_or_else(|| "malformed DER: missing identifier continuation".to_string())?
            .iter()
            .position(|octet| *octet & 0x80 == 0)
            .map(|position| position + 2)
            .ok_or_else(|| "malformed DER: unterminated identifier octets".to_string())?
    } else {
        1
    };
    let mut content_len = any.data.len();
    let mut minimal_length_octets = 1;
    if content_len >= 0x80 {
        while content_len != 0 {
            minimal_length_octets += 1;
            content_len >>= 8;
        }
    }
    let actual_header_len = consumed
        .checked_sub(any.data.len())
        .ok_or_else(|| "malformed DER: invalid header length".to_string())?;
    if actual_header_len > identifier_octets + minimal_length_octets {
        return Err("malformed DER: non-minimal length encoding".to_string());
    }
    Ok((any, &input[..consumed], rest))
}

/// The context-specific tag number of `any`, or `None` when it is not a
/// context-specific element.
fn context_tag(any: &Any<'_>) -> Option<u32> {
    if any.class() == Class::ContextSpecific {
        Some(any.tag().0)
    } else {
        None
    }
}

/// Parse a context-specific `[n] EXPLICIT` wrapper and return its content.
fn explicit_context<'a>(any: &Any<'a>, tag: u32, field: &str) -> Result<&'a [u8], String> {
    if any.class() != Class::ContextSpecific || any.tag() != Tag(tag) || !any.header.constructed() {
        return Err(format!("OCSP {field} is not a constructed [{tag}] element"));
    }
    Ok(any.data)
}

/// Require a universal, constructed SEQUENCE and return its content bytes.
///
/// `Any` keeps the tag *number* separate from the class and the
/// primitive/constructed bit, so comparing `tag()` alone would admit a
/// context-specific element that happens to reuse tag number 16 as well as a
/// primitive "SEQUENCE" that DER does not allow at all. Every SEQUENCE
/// boundary in this module goes through this helper so the audit is complete
/// by construction rather than by inspection.
fn expect_sequence<'a>(any: &Any<'a>, field: &str) -> Result<&'a [u8], String> {
    if any.class() != Class::Universal || any.tag() != Tag::Sequence || !any.header.constructed() {
        return Err(format!("OCSP {field} is not a SEQUENCE"));
    }
    Ok(any.data)
}

/// Name of a universal tag, for diagnostics only.
fn tag_name(tag: Tag) -> &'static str {
    if tag == Tag::Boolean {
        "BOOLEAN"
    } else if tag == Tag::Integer {
        "INTEGER"
    } else if tag == Tag::BitString {
        "BIT STRING"
    } else if tag == Tag::OctetString {
        "OCTET STRING"
    } else if tag == Tag::Oid {
        "OBJECT IDENTIFIER"
    } else if tag == Tag::Enumerated {
        "ENUMERATED"
    } else if tag == Tag::GeneralizedTime {
        "GeneralizedTime"
    } else {
        "element"
    }
}

/// Require a universal, primitive element carrying `tag` and return its content
/// bytes.
///
/// The counterpart of [`expect_sequence`] for the leaf types this grammar uses:
/// a constructed OCTET STRING, a context-specific element reusing a universal
/// tag number, or an INTEGER that is really a constructed impostor is refused
/// here rather than silently decoded.
fn expect_primitive<'a>(any: &Any<'a>, tag: Tag, field: &str) -> Result<&'a [u8], String> {
    if any.class() != Class::Universal || any.tag() != tag || any.header.constructed() {
        return Err(format!("OCSP {field} is not a primitive {}", tag_name(tag)));
    }
    Ok(any.data)
}

/// Require a universal, primitive OBJECT IDENTIFIER whose content is a
/// complete canonical DER encoding.
fn expect_oid<'a>(any: &Any<'a>, field: &str) -> Result<Oid<'a>, String> {
    let content = expect_primitive(any, Tag::Oid, field)?;
    validate_oid_content(content, field)?;
    Ok(Oid::new(std::borrow::Cow::Borrowed(content)))
}

/// X.690 §8.19: one or more base-128 subidentifiers, each terminated by an
/// octet with bit 8 clear, and no group using a redundant leading `0x80`.
fn validate_oid_content(content: &[u8], field: &str) -> Result<(), String> {
    let Some(&last) = content.last() else {
        return Err(format!("OCSP {field} OBJECT IDENTIFIER is empty"));
    };
    if last & 0x80 != 0 {
        return Err(format!(
            "OCSP {field} OBJECT IDENTIFIER is not a terminated base-128 encoding"
        ));
    }
    let mut index = 0usize;
    while index < content.len() {
        if content[index] == 0x80 {
            return Err(format!(
                "OCSP {field} OBJECT IDENTIFIER uses a redundant leading 0x80 continuation group"
            ));
        }
        loop {
            let byte = content[index];
            index += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    Ok(())
}

/// Require a universal, primitive INTEGER with canonical DER content.
///
/// A DER INTEGER is nonempty. The only legal leading `0x00` is the one-byte
/// sign-protection prefix used when the next byte has its high bit set; a
/// leading `0xFF` is likewise only legal when the next byte has its high bit
/// clear. `nonnegative` additionally refuses a high bit on the first content
/// byte, which is the rule for `CertificateSerialNumber` and the ENUMERATED
/// values this grammar uses.
fn expect_der_integer<'a>(
    any: &Any<'a>,
    field: &str,
    nonnegative: bool,
) -> Result<&'a [u8], String> {
    let content = expect_primitive(any, Tag::Integer, field)?;
    validate_der_integer_content(content, field, nonnegative)?;
    Ok(content)
}

fn validate_der_integer_content(
    content: &[u8],
    field: &str,
    nonnegative: bool,
) -> Result<(), String> {
    if content.is_empty() {
        return Err(format!("OCSP {field} is empty"));
    }
    if content.len() >= 2 {
        if content[0] == 0x00 && content[1] < 0x80 {
            return Err(format!("OCSP {field} is not a minimal DER encoding"));
        }
        if content[0] == 0xff && content[1] >= 0x80 {
            return Err(format!("OCSP {field} is not a minimal DER encoding"));
        }
    }
    if nonnegative && content[0] & 0x80 != 0 {
        return Err(format!("OCSP {field} is negative"));
    }
    Ok(())
}

fn decode_nonnegative_integer(content: &[u8], field: &str) -> Result<u32, String> {
    if content.len() > 4 {
        return Err(format!("OCSP {field} does not fit in a u32"));
    }
    let mut value = 0u32;
    for &byte in content {
        value = (value << 8) | u32::from(byte);
    }
    Ok(value)
}

/// Require a universal, primitive ENUMERATED with the same canonical content
/// encoding DER uses for INTEGER, then decode it as a nonnegative value.
fn expect_enumerated(any: &Any<'_>, field: &str) -> Result<u32, String> {
    let content = expect_primitive(any, Tag::Enumerated, field)?;
    validate_der_integer_content(content, field, true)?;
    decode_nonnegative_integer(content, field)
}

/// Require a universal, primitive BIT STRING that is octet-aligned and
/// nonempty.
///
/// `BitString::try_from` accepts any `unused_bits` byte, and
/// `x509_parser::verify::verify_signature` hashes only `signature.data`. A
/// responder could keep the exact valid signature bytes, set a nonzero unused
/// count, and still verify here while a strict client refused the staple.
fn expect_octet_aligned_bit_string<'a>(
    any: &Any<'a>,
    field: &str,
) -> Result<BitString<'a>, String> {
    let content = expect_primitive(any, Tag::BitString, field)?;
    if content.is_empty() {
        return Err(format!("OCSP {field} BIT STRING is empty"));
    }
    let unused_bits = content[0];
    let data = &content[1..];
    if unused_bits != 0 {
        return Err(format!(
            "OCSP {field} BIT STRING is not octet-aligned (unused_bits={unused_bits})"
        ));
    }
    if data.is_empty() {
        return Err(format!("OCSP {field} BIT STRING carries no bits"));
    }
    Ok(BitString::new(0, data))
}

fn is_canonical_null(any: &Any<'_>) -> bool {
    any.class() == Class::Universal
        && any.tag() == Tag::Null
        && !any.header.constructed()
        && any.data.is_empty()
}

/// Parse one `AlgorithmIdentifier`, validating the OID encoding and applying
/// the field- and algorithm-specific parameter profile.
fn parse_algorithm_identifier<'a>(
    input: &'a [u8],
    field: &str,
    profile: AlgorithmParameterProfile,
) -> Result<(AlgorithmIdentifier<'a>, &'a [u8]), String> {
    let (any, _, rest) = take_tlv(input)?;
    let content = expect_sequence(&any, field)?;
    Ok((
        parse_algorithm_identifier_content(content, field, profile)?,
        rest,
    ))
}

fn parse_algorithm_identifier_content<'a>(
    content: &'a [u8],
    field: &str,
    profile: AlgorithmParameterProfile,
) -> Result<AlgorithmIdentifier<'a>, String> {
    let (oid_any, _, rest) = take_tlv(content)?;
    let algorithm = expect_oid(&oid_any, field)?;
    let parameters = if rest.is_empty() {
        None
    } else {
        let (params_any, _, trailing) = take_tlv(rest)?;
        if !trailing.is_empty() {
            return Err(format!("OCSP {field} has trailing fields after parameters"));
        }
        Some(params_any)
    };
    validate_algorithm_parameters(&algorithm, parameters.as_ref(), field, profile)?;
    Ok(AlgorithmIdentifier::new(algorithm, parameters))
}

/// Apply the parameter profile for this field and OID.
///
/// Digest identifiers (CertID and nested PSS hashes) accept the two encodings
/// RFC 4055 / RFC 5754 require receivers to handle: absent, or canonical NULL.
/// Signature identifiers follow the verifier-supported family instead of that
/// digest rule, because `x509_parser::verify::verify_signature` selects ECDSA,
/// Ed25519, and RSA PKCS#1 by OID and ignores parameters on those paths.
fn validate_algorithm_parameters(
    oid: &Oid<'_>,
    params: Option<&Any<'_>>,
    field: &str,
    profile: AlgorithmParameterProfile,
) -> Result<(), String> {
    match profile {
        AlgorithmParameterProfile::Digest => validate_digest_parameters(params, field),
        AlgorithmParameterProfile::Signature => validate_signature_parameters(oid, params, field),
    }
}

fn validate_digest_parameters(params: Option<&Any<'_>>, field: &str) -> Result<(), String> {
    match params {
        None => Ok(()),
        Some(params) if is_canonical_null(params) => Ok(()),
        Some(_) => Err(format!("OCSP {field} parameters are not absent or NULL")),
    }
}

fn ecdsa_or_ed25519_signature_oid(oid: &Oid<'_>) -> bool {
    *oid == OID_SIG_ECDSA_WITH_SHA256
        || *oid == OID_SIG_ECDSA_WITH_SHA384
        || *oid == OID_SIG_ED25519
}

fn rsa_pkcs1_signature_oid(oid: &Oid<'_>) -> bool {
    *oid == OID_PKCS1_SHA1WITHRSA
        || *oid == OID_PKCS1_SHA256WITHRSA
        || *oid == OID_PKCS1_SHA384WITHRSA
        || *oid == OID_PKCS1_SHA512WITHRSA
        || *oid == OID_SHA1_WITH_RSA
}

fn validate_signature_parameters(
    oid: &Oid<'_>,
    params: Option<&Any<'_>>,
    field: &str,
) -> Result<(), String> {
    if ecdsa_or_ed25519_signature_oid(oid) {
        return match params {
            None => Ok(()),
            Some(_) => Err(format!("OCSP {field} parameters must be absent")),
        };
    }
    if rsa_pkcs1_signature_oid(oid) {
        // RFC 3279 §2.2.1 and RFC 5754 §2: when *generating* sha*WithRSAEncryption
        // the parameters MUST be NULL. Receivers must also accept an omitted
        // NULL, but this is a strict stapling gate: an encoding some clients
        // still reject is not served. Canonical NULL is what real responders
        // emit.
        return match params {
            Some(params) if is_canonical_null(params) => Ok(()),
            _ => Err(format!(
                "OCSP {field} parameters must be the canonical NULL"
            )),
        };
    }
    if *oid == OID_PKCS1_RSASSAPSS {
        let Some(params) = params else {
            return Err(format!("OCSP {field} rsassa-pss parameters are absent"));
        };
        return validate_rsassa_pss_parameters(params, field);
    }
    Err(format!(
        "OCSP {field} uses an algorithm whose parameters cannot be validated"
    ))
}

/// Parse one optional `[n] EXPLICIT` wrapper and return the inner object.
fn take_optional_explicit<'a>(
    input: &'a [u8],
    tag: u32,
    field: &str,
) -> Result<(Option<Any<'a>>, &'a [u8]), String> {
    if input.is_empty() {
        return Ok((None, input));
    }
    let (any, _, rest) = take_tlv(input)?;
    if context_tag(&any) != Some(tag) {
        return Ok((None, input));
    }
    let content = explicit_context(&any, tag, field)?;
    let (inner, _, trailing) = take_tlv(content)?;
    if !trailing.is_empty() {
        return Err(format!("OCSP {field} has trailing bytes"));
    }
    Ok((Some(inner), rest))
}

fn pss_hash_output_len(oid: &Oid<'_>) -> Option<u32> {
    if *oid == OID_NIST_HASH_SHA256 {
        Some(32)
    } else if *oid == OID_NIST_HASH_SHA384 {
        Some(48)
    } else if *oid == OID_NIST_HASH_SHA512 {
        Some(64)
    } else {
        None
    }
}

/// `rsassa-pss` parameters must be a SEQUENCE the verification path can parse,
/// without trailing or DEFAULT-encoded fields that `RsaSsaPssParams::try_from`
/// would otherwise ignore.
///
/// This is not a complete RFC 4055 strictness claim. It is the subset that
/// matches what `x509_parser::verify::verify_signature` actually uses (the hash
/// OID, mapped onto ring's MGF1-same-hash / salt-length-equals-hash PSS
/// algorithms) and that refuses a second encoding a strict client would reject.
fn validate_rsassa_pss_parameters(params: &Any<'_>, field: &str) -> Result<(), String> {
    let pss_field = format!("{field} rsassa-pss parameters");
    let content = expect_sequence(params, &pss_field)?;
    if RsaSsaPssParams::try_from(params).is_err() {
        return Err(format!("OCSP {pss_field} are not parseable"));
    }

    let hash_field = format!("{field} rsassa-pss hashAlgorithm");
    let (hash_any, rest) = take_optional_explicit(content, 0, &hash_field)?;
    let Some(hash_any) = hash_any else {
        return Err(format!("OCSP {hash_field} is absent"));
    };
    let hash_content = expect_sequence(&hash_any, &hash_field)?;
    let hash_alg = parse_algorithm_identifier_content(
        hash_content,
        &hash_field,
        AlgorithmParameterProfile::Digest,
    )?;
    let Some(hash_len) = pss_hash_output_len(&hash_alg.algorithm) else {
        return Err(format!(
            "OCSP {hash_field} is not SHA-256, SHA-384, or SHA-512"
        ));
    };

    let mgf_field = format!("{field} rsassa-pss maskGenAlgorithm");
    let (mgf_any, rest) = take_optional_explicit(rest, 1, &mgf_field)?;
    let Some(mgf_any) = mgf_any else {
        return Err(format!("OCSP {mgf_field} is absent"));
    };
    let mgf_content = expect_sequence(&mgf_any, &mgf_field)?;
    let (mgf_oid_any, _, mgf_rest) = take_tlv(mgf_content)?;
    let mgf_oid = expect_oid(&mgf_oid_any, &mgf_field)?;
    if mgf_oid.as_bytes() != OID_MGF1_BYTES {
        return Err(format!("OCSP {mgf_field} is not id-mgf1"));
    }
    if mgf_rest.is_empty() {
        return Err(format!("OCSP {mgf_field} parameters are absent"));
    }
    let (mgf_hash_any, _, mgf_trailing) = take_tlv(mgf_rest)?;
    if !mgf_trailing.is_empty() {
        return Err(format!(
            "OCSP {mgf_field} has trailing fields after parameters"
        ));
    }
    let mgf_hash_field = format!("{mgf_field} hashAlgorithm");
    let mgf_hash_content = expect_sequence(&mgf_hash_any, &mgf_hash_field)?;
    let mgf_hash = parse_algorithm_identifier_content(
        mgf_hash_content,
        &mgf_hash_field,
        AlgorithmParameterProfile::Digest,
    )?;
    if mgf_hash.algorithm != hash_alg.algorithm {
        return Err(format!(
            "OCSP {mgf_field} hash does not match hashAlgorithm"
        ));
    }

    let salt_field = format!("{field} rsassa-pss saltLength");
    let (salt_any, rest) = take_optional_explicit(rest, 2, &salt_field)?;
    let Some(salt_any) = salt_any else {
        return Err(format!("OCSP {salt_field} is absent"));
    };
    let salt_content = expect_der_integer(&salt_any, &salt_field, true)?;
    let salt = decode_nonnegative_integer(salt_content, &salt_field)?;
    if salt != hash_len {
        return Err(format!(
            "OCSP {salt_field} does not match the hash output length"
        ));
    }

    let trailer_field = format!("{field} rsassa-pss trailerField");
    let (trailer_any, rest) = take_optional_explicit(rest, 3, &trailer_field)?;
    if trailer_any.is_some() {
        return Err(format!(
            "OCSP {trailer_field} is encoded; DER omits a DEFAULT value"
        ));
    }
    if !rest.is_empty() {
        return Err(format!("OCSP {pss_field} have trailing fields"));
    }
    Ok(())
}

/// Require a universal, primitive DER `GeneralizedTime` and decode it.
///
/// DER permits exactly `YYYYMMDDHHMMSSZ` here: seconds and the trailing `Z` are
/// mandatory, while offsets, an absent timezone, and fractional seconds are
/// forbidden. Every instant is then decoded, even when the serving decision
/// does not read that particular field.
fn expect_generalized_time(any: &Any<'_>, raw: &[u8], field: &str) -> Result<i64, String> {
    if any.class() != Class::Universal
        || any.tag() != Tag::GeneralizedTime
        || any.header.constructed()
    {
        return Err(format!("OCSP {field} is not a GeneralizedTime"));
    }
    if any.data.len() != 15 || !any.data.ends_with(b"Z") {
        return Err(format!("OCSP {field} is not a DER GeneralizedTime"));
    }
    generalized_time_unix(raw, field)
}

/// A parsed `BasicOCSPResponse`, retaining the byte ranges signature
/// verification needs.
struct BasicResponse<'a> {
    /// Complete DER encoding of `tbsResponseData`, which is what is signed.
    tbs_raw: &'a [u8],
    /// Decoded `ResponseData`.
    response_data: ResponseData<'a>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: BitString<'a>,
    /// DER of each certificate carried in the optional `certs` field.
    certs: Vec<&'a [u8]>,
}

struct ResponseData<'a> {
    responder_id: ResponderId<'a>,
    single_responses: Vec<SingleResponse<'a>>,
}

enum ResponderId<'a> {
    /// Complete DER encoding of the responder's `Name`.
    ByName(&'a [u8]),
    /// SHA-1 hash of the responder's public-key BIT STRING contents.
    ByKey(&'a [u8]),
}

struct SingleResponse<'a> {
    cert_id: CertId<'a>,
    status: CertStatus,
    this_update: i64,
    next_update: Option<i64>,
}

struct CertId<'a> {
    hash_algorithm: Oid<'a>,
    issuer_name_hash: &'a [u8],
    issuer_key_hash: &'a [u8],
    /// Content bytes of the `serialNumber` INTEGER.
    serial_number: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertStatus {
    Good,
    Revoked,
    Unknown,
}

impl CertStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Revoked => "revoked",
            Self::Unknown => "unknown",
        }
    }
}

/// Unwrap `OCSPResponse` and return the `BasicOCSPResponse` DER.
fn basic_response_der(der: &[u8]) -> Result<&[u8], String> {
    let (outer, _, trailing) = take_tlv(der)?;
    if !trailing.is_empty() {
        return Err("OCSP response has trailing bytes after the outer SEQUENCE".to_string());
    }
    let outer_content = expect_sequence(&outer, "response")?;

    let (status_any, _, rest) = take_tlv(outer_content)?;
    let status = expect_enumerated(&status_any, "responseStatus")?;
    if status != 0 {
        return Err(format!(
            "OCSP responseStatus is {}, not successful(0)",
            response_status_name(status)
        ));
    }

    let (bytes_any, _, rest) = take_tlv(rest)
        .map_err(|_| "OCSP response is successful but carries no responseBytes".to_string())?;
    if !rest.is_empty() {
        return Err("OCSP response has trailing fields after responseBytes".to_string());
    }
    let response_bytes = explicit_context(&bytes_any, 0, "responseBytes")?;

    let (bytes_seq, _, trailing) = take_tlv(response_bytes)?;
    if !trailing.is_empty() {
        return Err("OCSP responseBytes has trailing bytes".to_string());
    }
    let bytes_seq_content = expect_sequence(&bytes_seq, "responseBytes")?;

    let (type_any, _, rest) = take_tlv(bytes_seq_content)?;
    let response_type = expect_oid(&type_any, "responseType")?;
    if response_type.as_bytes() != OID_PKIX_OCSP_BASIC_BYTES {
        return Err("OCSP responseType is not id-pkix-ocsp-basic".to_string());
    }

    let (response_any, _, rest) = take_tlv(rest)?;
    if !rest.is_empty() {
        return Err("OCSP responseBytes has trailing fields after response".to_string());
    }
    expect_primitive(&response_any, Tag::OctetString, "response field")
}

fn response_status_name(value: u32) -> &'static str {
    match value {
        1 => "malformedRequest(1)",
        2 => "internalError(2)",
        3 => "tryLater(3)",
        5 => "sigRequired(5)",
        6 => "unauthorized(6)",
        _ => "an unrecognized status",
    }
}

fn parse_basic_response(der: &[u8], policy: OcspCryptoPolicy) -> Result<BasicResponse<'_>, String> {
    let (basic, _, trailing) = take_tlv(der)?;
    if !trailing.is_empty() {
        return Err("BasicOCSPResponse has trailing bytes".to_string());
    }
    let basic_content = expect_sequence(&basic, "BasicOCSPResponse")?;

    let (tbs_any, tbs_raw, rest) = take_tlv(basic_content)?;
    let tbs_content = expect_sequence(&tbs_any, "tbsResponseData")?;
    let response_data = parse_response_data(tbs_content)?;

    let (signature_algorithm, rest) = parse_algorithm_identifier(
        rest,
        "signatureAlgorithm",
        AlgorithmParameterProfile::Signature,
    )?;
    // Refuse a non-approved responder signature algorithm at the grammar, so a
    // FIPS deployment cannot store one through the admin boundary either — not
    // merely decline to serve it later.
    check_signature_algorithm(
        &signature_algorithm.algorithm,
        "BasicOCSPResponse signatureAlgorithm",
        policy,
    )?;

    let (signature_any, _, rest) = take_tlv(rest)?;
    let signature = expect_octet_aligned_bit_string(&signature_any, "signature")?;

    let mut certs = Vec::new();
    if !rest.is_empty() {
        let (certs_any, _, trailing) = take_tlv(rest)?;
        if !trailing.is_empty() {
            return Err("BasicOCSPResponse has trailing fields after certs".to_string());
        }
        let certs_content = explicit_context(&certs_any, 0, "certs")?;
        let (certs_seq, _, trailing) = take_tlv(certs_content)?;
        if !trailing.is_empty() {
            return Err("OCSP certs has trailing bytes".to_string());
        }
        let certs_seq_content = expect_sequence(&certs_seq, "certs")?;
        let mut cursor = certs_seq_content;
        while !cursor.is_empty() {
            let (cert_any, raw, rest) = take_tlv(cursor)?;
            cursor = rest;
            if certs.len() == MAX_RESPONDER_CERTS {
                return Err(format!(
                    "OCSP response carries more than {MAX_RESPONDER_CERTS} responder certificates"
                ));
            }
            // `certs` is `SEQUENCE OF Certificate`, so structural admission has
            // to prove every carried entry really is one complete X.509
            // certificate. Recording an arbitrary TLV here and skipping the
            // unparseable ones at authorization time would fail open twice
            // over: a response whose bytes this parser cannot account for would
            // still be admitted by the admin boundary, and it could still be
            // authorized as long as some *other* carried certificate verified.
            expect_sequence(&cert_any, "certs entry")?;
            let (trailing, carried) = X509Certificate::from_der(raw).map_err(|_| {
                "OCSP certs carries an entry that is not a parseable X.509 certificate".to_string()
            })?;
            if !trailing.is_empty() {
                return Err(
                    "OCSP certs carries a certificate with trailing bytes after its encoding"
                        .to_string(),
                );
            }
            // A carried responder certificate never passes through
            // `parse_pem_certificate_bundle`, so this is the only place its key
            // form and the algorithm of the CA signature over it can be
            // admitted. It is applied to every carried entry, used or not, for
            // the same reason the parse above is: an entry this pass admits is
            // one a later loosening could reach.
            check_certificate_key_form(raw, "OCSP responder certificate", policy)?;
            check_signature_algorithm(
                &carried.signature_algorithm.algorithm,
                "responder certificate signature",
                policy,
            )?;
            certs.push(raw);
        }
    }

    Ok(BasicResponse {
        tbs_raw,
        response_data,
        signature_algorithm,
        signature,
        certs,
    })
}

/// Bound on the certificates a response may carry, and on the `SingleResponse`
/// entries it may contain. Both are walked linearly, so both need a ceiling
/// that does not depend on the (already bounded) byte length alone.
const MAX_RESPONDER_CERTS: usize = 16;
const MAX_SINGLE_RESPONSES: usize = 64;

fn parse_response_data(input: &[u8]) -> Result<ResponseData<'_>, String> {
    let (first, _, rest) = take_tlv(input)?;

    // version [0] EXPLICIT Version DEFAULT v1
    //
    // DER forbids encoding a DEFAULT value, so a conformant `ResponseData`
    // omits this field entirely: v1 must be absent, and every other version is
    // unsupported. Accepting an explicit `[0] INTEGER 0` would give one
    // response two valid-looking encodings under a single signature, which is
    // exactly the ambiguity a strict client would resolve differently.
    if context_tag(&first) == Some(0) {
        let version_content = explicit_context(&first, 0, "version")?;
        let (version_any, _, trailing) = take_tlv(version_content)?;
        if !trailing.is_empty() {
            return Err("OCSP version has trailing bytes".to_string());
        }
        let version_content = expect_der_integer(&version_any, "version", true)?;
        let version = decode_nonnegative_integer(version_content, "version")?;
        if version == 0 {
            return Err(
                "OCSP ResponseData encodes version v1 explicitly, but DER omits a DEFAULT value"
                    .to_string(),
            );
        }
        return Err(format!(
            "OCSP response declares unsupported version {version}"
        ));
    }
    let responder_any = first;

    let responder_id = match context_tag(&responder_any) {
        Some(1) => {
            let content = explicit_context(&responder_any, 1, "responderID")?;
            let (name_any, name_raw, trailing) = take_tlv(content)?;
            if !trailing.is_empty() {
                return Err("OCSP responderID byName has trailing bytes".to_string());
            }
            expect_sequence(&name_any, "responderID byName Name")?;
            ResponderId::ByName(name_raw)
        }
        Some(2) => {
            let content = explicit_context(&responder_any, 2, "responderID")?;
            let (hash_any, _, trailing) = take_tlv(content)?;
            if !trailing.is_empty() {
                return Err("OCSP responderID byKey has trailing bytes".to_string());
            }
            let hash = expect_primitive(&hash_any, Tag::OctetString, "responderID byKey")?;
            ResponderId::ByKey(hash)
        }
        _ => {
            return Err("OCSP responderID is neither byName [1] nor byKey [2]".to_string());
        }
    };

    // producedAt GeneralizedTime. The value is decoded, not merely tagged: an
    // unparseable instant is a malformed response even though the serving
    // decision itself is made from thisUpdate/nextUpdate.
    let (produced_any, produced_raw, rest) = take_tlv(rest)?;
    expect_generalized_time(&produced_any, produced_raw, "producedAt")?;

    let (responses_any, _, rest) = take_tlv(rest)?;
    let responses_content = expect_sequence(&responses_any, "responses")?;

    let mut single_responses = Vec::new();
    let mut cursor = responses_content;
    while !cursor.is_empty() {
        if single_responses.len() == MAX_SINGLE_RESPONSES {
            return Err(format!(
                "OCSP response carries more than {MAX_SINGLE_RESPONSES} SingleResponse entries"
            ));
        }
        let (single_any, _, next) = take_tlv(cursor)?;
        let single_content = expect_sequence(&single_any, "SingleResponse")?;
        single_responses.push(parse_single_response(single_content)?);
        cursor = next;
    }
    if single_responses.is_empty() {
        return Err("OCSP response carries no SingleResponse entries".to_string());
    }

    // responseExtensions [1] EXPLICIT Extensions OPTIONAL is the only field the
    // grammar allows after `responses`, at most once. Anything else — an
    // unknown context tag, a second [1], or a stray universal element — means
    // the encoder and this parser disagree about what was signed, so it is
    // refused rather than skipped.
    if !rest.is_empty() {
        let (extensions_any, _, trailing) = take_tlv(rest)?;
        if context_tag(&extensions_any) != Some(1) {
            return Err(
                "OCSP tbsResponseData carries an unexpected field after responses".to_string(),
            );
        }
        if !trailing.is_empty() {
            return Err(
                "OCSP tbsResponseData has trailing fields after responseExtensions".to_string(),
            );
        }
        let content = explicit_context(&extensions_any, 1, "responseExtensions")?;
        validate_extensions(content, "responseExtensions")?;
    }

    Ok(ResponseData {
        responder_id,
        single_responses,
    })
}

fn parse_single_response(input: &[u8]) -> Result<SingleResponse<'_>, String> {
    let (cert_id_any, _, rest) = take_tlv(input)?;
    let cert_id_content = expect_sequence(&cert_id_any, "CertID")?;
    let cert_id = parse_cert_id(cert_id_content)?;

    let (status_any, _, rest) = take_tlv(rest)?;
    let status = parse_cert_status(&status_any)?;

    let (this_update_any, this_update_raw, rest) = take_tlv(rest)?;
    let this_update = expect_generalized_time(&this_update_any, this_update_raw, "thisUpdate")?;

    // The remaining grammar is exactly `[0] nextUpdate OPTIONAL` followed by
    // `[1] singleExtensions OPTIONAL`, each at most once and in that order. A
    // permissive loop here would let a second `[0]` silently overwrite the
    // validity window the signature was meant to bind.
    let mut next_update = None;
    let mut cursor = rest;
    if !cursor.is_empty() {
        let (field, _, next) = take_tlv(cursor)?;
        if context_tag(&field) == Some(0) {
            let content = explicit_context(&field, 0, "nextUpdate")?;
            let (time_any, time_raw, trailing) = take_tlv(content)?;
            if !trailing.is_empty() {
                return Err("OCSP nextUpdate has trailing bytes".to_string());
            }
            next_update = Some(expect_generalized_time(&time_any, time_raw, "nextUpdate")?);
            cursor = next;
        }
    }
    if !cursor.is_empty() {
        let (field, _, next) = take_tlv(cursor)?;
        if context_tag(&field) != Some(1) {
            return Err(
                "OCSP SingleResponse carries an unexpected field after thisUpdate".to_string(),
            );
        }
        let content = explicit_context(&field, 1, "singleExtensions")?;
        validate_extensions(content, "singleExtensions")?;
        cursor = next;
    }
    if !cursor.is_empty() {
        return Err("OCSP SingleResponse has trailing fields after singleExtensions".to_string());
    }

    Ok(SingleResponse {
        cert_id,
        status,
        this_update,
        next_update,
    })
}

/// Validate the `CertStatus` CHOICE encoding, not merely its context tag.
///
/// ```text
/// CertStatus ::= CHOICE {
///     good    [0] IMPLICIT NULL,
///     revoked [1] IMPLICIT RevokedInfo,
///     unknown [2] IMPLICIT UnknownInfo }
/// ```
///
/// `UnknownInfo` is `NULL`, so both `good` and `unknown` are primitive and
/// empty. `revoked` is a constructed `RevokedInfo`. `revoked` and `unknown` are
/// refused later by serving policy, but a malformed encoding of either is a
/// structural failure that must be reported as such: a strict client parses the
/// same bytes, and Ferrum must not admit an entry it cannot fully account for.
fn parse_cert_status(any: &Any<'_>) -> Result<CertStatus, String> {
    let Some(tag) = context_tag(any) else {
        return Err("OCSP certStatus is not a context-specific CHOICE".to_string());
    };
    match tag {
        0 | 2 => {
            let (name, status) = if tag == 0 {
                ("good", CertStatus::Good)
            } else {
                ("unknown", CertStatus::Unknown)
            };
            if any.header.constructed() {
                return Err(format!(
                    "OCSP certStatus {name} is constructed, but it is an IMPLICIT NULL"
                ));
            }
            if !any.data.is_empty() {
                return Err(format!(
                    "OCSP certStatus {name} carries content, but it is an IMPLICIT NULL"
                ));
            }
            Ok(status)
        }
        1 => {
            if !any.header.constructed() {
                return Err("OCSP certStatus revoked is primitive, not a SEQUENCE".to_string());
            }
            parse_revoked_info(any.data)?;
            Ok(CertStatus::Revoked)
        }
        _ => Err("OCSP certStatus uses an unrecognized alternative".to_string()),
    }
}

/// Validate `RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime,
/// revocationReason [0] EXPLICIT CRLReason OPTIONAL }`.
fn parse_revoked_info(input: &[u8]) -> Result<(), String> {
    let (time_any, time_raw, rest) = take_tlv(input)?;
    expect_generalized_time(&time_any, time_raw, "revocationTime")?;

    if rest.is_empty() {
        return Ok(());
    }
    let (reason_any, _, trailing) = take_tlv(rest)?;
    if !trailing.is_empty() {
        return Err("OCSP RevokedInfo has trailing fields after revocationReason".to_string());
    }
    let content = explicit_context(&reason_any, 0, "revocationReason")?;
    let (value_any, _, trailing) = take_tlv(content)?;
    if !trailing.is_empty() {
        return Err("OCSP revocationReason has trailing bytes".to_string());
    }
    expect_enumerated(&value_any, "revocationReason")?;
    Ok(())
}

/// Bound on the entries one `Extensions` container may carry.
const MAX_EXTENSIONS: usize = 32;

/// Decode the `critical` flag of an `Extension`.
///
/// DER omits a `DEFAULT` value, so an encoded `FALSE` is not DER at all: it
/// would let the same extension be encoded two ways under one signature.
fn der_critical_flag(any: &Any<'_>, field: &str) -> Result<bool, String> {
    if any.header.constructed() || any.data.len() != 1 {
        return Err(format!("OCSP {field} critical flag is not a DER BOOLEAN"));
    }
    match any.data[0] {
        0xff => Ok(true),
        0x00 => Err(format!(
            "OCSP {field} encodes critical DEFAULT FALSE, which DER omits"
        )),
        _ => Err(format!("OCSP {field} critical flag is not a DER BOOLEAN")),
    }
}

/// Structurally validate an `Extensions` container and enforce RFC 6960 §4.4
/// criticality.
///
/// ```text
/// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
/// Extension  ::= SEQUENCE { extnID OBJECT IDENTIFIER,
///                           critical BOOLEAN DEFAULT FALSE,
///                           extnValue OCTET STRING }
/// ```
///
/// Ferrum implements no OCSP response extension, so a *critical* extension is
/// by definition one it cannot process and must not admit; a non-critical one
/// is ignored, but only after it has been parsed strictly enough to prove the
/// container really is an `Extensions` and nothing else is hiding inside the
/// signed bytes.
fn validate_extensions(content: &[u8], field: &str) -> Result<(), String> {
    let (container, _, trailing) = take_tlv(content)?;
    if !trailing.is_empty() {
        return Err(format!("OCSP {field} has trailing bytes"));
    }
    let container_content = expect_sequence(&container, field)?;
    if container_content.is_empty() {
        return Err(format!("OCSP {field} is an empty SEQUENCE"));
    }

    let mut cursor = container_content;
    let mut seen = 0usize;
    // X.509 forbids repeating one extension type inside an `Extensions`
    // container. Ferrum ignores supported non-critical extensions, so admitting
    // a duplicate would let the response mean one thing here and another to a
    // strict client that rejects the repetition or keeps the other copy. The
    // fixed-size table is bounded by `MAX_EXTENSIONS`, so the linear scan costs
    // at most a few hundred slice comparisons and cannot be driven quadratic.
    let mut seen_ids: [&[u8]; MAX_EXTENSIONS] = [&[]; MAX_EXTENSIONS];
    while !cursor.is_empty() {
        let (extension, _, next) = take_tlv(cursor)?;
        cursor = next;
        seen += 1;
        if seen > MAX_EXTENSIONS {
            return Err(format!(
                "OCSP {field} carries more than {MAX_EXTENSIONS} extensions"
            ));
        }
        if extension.class() != Class::Universal
            || extension.tag() != Tag::Sequence
            || !extension.header.constructed()
        {
            return Err(format!("OCSP {field} contains a non-SEQUENCE Extension"));
        }

        let (id_any, _, rest) = take_tlv(extension.data)?;
        expect_oid(&id_any, &format!("{field} extnID"))?;
        let id_bytes = id_any.data;
        if seen_ids[..seen - 1].contains(&id_bytes) {
            return Err(format!(
                "OCSP {field} repeats an extension OID, which X.509 Extensions must not do"
            ));
        }
        seen_ids[seen - 1] = id_bytes;

        let (second_any, _, tail) = take_tlv(rest)?;
        let mut critical = false;
        let mut value_any = second_any;
        let mut rest = tail;
        if value_any.tag() == Tag::Boolean && value_any.class() == Class::Universal {
            critical = der_critical_flag(&value_any, field)?;
            let (parsed, _, next) = take_tlv(rest)?;
            value_any = parsed;
            rest = next;
        }

        if !rest.is_empty() {
            return Err(format!("OCSP {field} Extension has trailing fields"));
        }
        if value_any.class() != Class::Universal
            || value_any.tag() != Tag::OctetString
            || value_any.header.constructed()
        {
            return Err(format!(
                "OCSP {field} extnValue is not a primitive OCTET STRING"
            ));
        }
        if critical {
            return Err(format!(
                "OCSP {field} contains a critical extension Ferrum does not implement"
            ));
        }
    }
    Ok(())
}

fn parse_cert_id(input: &[u8]) -> Result<CertId<'_>, String> {
    let (hash_algorithm, rest) = parse_algorithm_identifier(
        input,
        "CertID hashAlgorithm",
        AlgorithmParameterProfile::Digest,
    )?;

    let (name_hash_any, _, rest) = take_tlv(rest)?;
    let issuer_name_hash = expect_primitive(&name_hash_any, Tag::OctetString, "issuerNameHash")?;
    let (key_hash_any, _, rest) = take_tlv(rest)?;
    let issuer_key_hash = expect_primitive(&key_hash_any, Tag::OctetString, "issuerKeyHash")?;
    let (serial_any, _, trailing) = take_tlv(rest)?;
    let serial_number = expect_der_integer(&serial_any, "serialNumber", true)?;
    if !trailing.is_empty() {
        return Err("OCSP CertID has trailing fields".to_string());
    }

    Ok(CertId {
        hash_algorithm: hash_algorithm.algorithm,
        issuer_name_hash,
        issuer_key_hash,
        serial_number,
    })
}

fn generalized_time_unix(raw: &[u8], field: &str) -> Result<i64, String> {
    let (_, time) = GeneralizedTime::from_der(raw)
        .map_err(|_| format!("OCSP {field} is not a valid GeneralizedTime"))?;
    let datetime = time
        .utc_datetime()
        .map_err(|_| format!("OCSP {field} is not a representable instant"))?;
    Ok(datetime.unix_timestamp())
}

/// Bounded, certificate-independent structural validation.
///
/// This is what the admin boundary can prove about stored OCSP bytes before any
/// certificate context exists: the size bound, a successful basic envelope, and
/// a well-formed `BasicOCSPResponse` with at least one `SingleResponse`. It is
/// deliberately *not* sufficient to serve: activation always re-validates
/// through [`validate_stapled_response`] against the leaf and issuer actually
/// configured.
pub fn validate_structure(der: &[u8]) -> Result<OcspStructure, String> {
    validate_structure_with_policy(der, OcspCryptoPolicy::current())
}

/// [`validate_structure`] with an explicit cryptographic admission profile.
///
/// See [`OcspCryptoPolicy`] for why the profile is a parameter rather than a
/// read of process-wide FIPS state.
pub fn validate_structure_with_policy(
    der: &[u8],
    policy: OcspCryptoPolicy,
) -> Result<OcspStructure, String> {
    enforce_size_bound(der)?;
    let basic_der = basic_response_der(der)?;
    let basic = parse_basic_response(basic_der, policy)?;
    Ok(OcspStructure {
        der_len: der.len(),
        single_responses: basic.response_data.single_responses.len(),
        earliest_next_update: basic
            .response_data
            .single_responses
            .iter()
            .filter_map(|single| single.next_update)
            .min(),
    })
}

/// Full, certificate-bound validation against the chain that will be served.
///
/// `chain` is leaf-first, exactly as it is handed to rustls. The issuer is the
/// chain member whose key is proven to have signed the leaf; a self-signed leaf
/// is its own issuer. When neither holds, the response cannot be bound to anything
/// and is refused — an operator stapling a response must publish the issuer in
/// the served chain, which is what an OCSP-checking client needs anyway.
pub fn validate_stapled_response(
    der: &[u8],
    chain: &[CertificateDer<'_>],
) -> Result<OcspAcceptance, String> {
    validate_stapled_response_at(der, chain, now_unix())
}

/// [`validate_stapled_response`] with an explicit evaluation instant.
pub fn validate_stapled_response_at(
    der: &[u8],
    chain: &[CertificateDer<'_>],
    now: i64,
) -> Result<OcspAcceptance, String> {
    validate_stapled_response_at_with_policy(der, chain, now, OcspCryptoPolicy::current())
}

/// [`validate_stapled_response_at`] with an explicit cryptographic admission
/// profile.
///
/// See [`OcspCryptoPolicy`] for why the profile is a parameter rather than a
/// read of process-wide FIPS state.
pub fn validate_stapled_response_at_with_policy(
    der: &[u8],
    chain: &[CertificateDer<'_>],
    now: i64,
    policy: OcspCryptoPolicy,
) -> Result<OcspAcceptance, String> {
    enforce_size_bound(der)?;

    let leaf_der = chain
        .first()
        .ok_or_else(|| "cannot validate an OCSP response against an empty chain".to_string())?;
    let (leaf_trailing, leaf) = X509Certificate::from_der(leaf_der.as_ref())
        .map_err(|_| "server certificate is not parseable X.509 DER".to_string())?;
    if !leaf_trailing.is_empty() {
        return Err(
            "server certificate has trailing bytes after its X.509 DER encoding".to_string(),
        );
    }

    // `select_issuer_der` proves the binding by verifying the leaf's own
    // signature. Admit both the verification algorithm and the public key that
    // may become the self-signed issuer before that cryptographic operation is
    // performed; production callers already apply the same key gate while
    // loading the served bundle, but this validator's contract must stand on
    // its own.
    check_signature_algorithm(
        &leaf.signature_algorithm.algorithm,
        "served certificate signature",
        policy,
    )?;
    check_certificate_key_form(leaf_der.as_ref(), "served OCSP certificate", policy)?;

    let issuer_der = select_issuer_der(&leaf, chain, policy)?;
    let (issuer_trailing, issuer) = X509Certificate::from_der(issuer_der)
        .map_err(|_| "issuer certificate is not parseable X.509 DER".to_string())?;
    if !issuer_trailing.is_empty() {
        return Err(
            "issuer certificate has trailing bytes after its X.509 DER encoding".to_string(),
        );
    }
    // The issuer's key verifies the leaf, an undelegated response, and every
    // delegate. Callers reach this through `parse_pem_certificate_bundle`, but
    // re-admitting the *selected* issuer keeps that guarantee a property of
    // this module rather than of its call sites.
    check_certificate_key_form(issuer_der, "OCSP issuer certificate", policy)?;

    let basic_der = basic_response_der(der)?;
    let basic = parse_basic_response(basic_der, policy)?;

    let single = match_single_response(&basic, &leaf, &issuer)?;

    let delegated_responder = verify_signature_and_authorization(&basic, issuer_der, &issuer, now)?;

    match single.status {
        CertStatus::Good => {}
        status => {
            return Err(format!(
                "OCSP response reports certStatus {} for the configured certificate",
                status.as_str()
            ));
        }
    }

    let Some(next_update) = single.next_update else {
        let message = "OCSP response omits nextUpdate, so it has no validity window and cannot \
                       be stapled";
        return Err(message.to_string());
    };
    if next_update <= single.this_update {
        return Err("OCSP nextUpdate is not after thisUpdate".to_string());
    }
    if single.this_update > now.saturating_add(OCSP_CLOCK_SKEW_SECONDS) {
        return Err(format!(
            "OCSP thisUpdate is {} seconds in the future, beyond the {OCSP_CLOCK_SKEW_SECONDS}-second skew allowance",
            single.this_update.saturating_sub(now)
        ));
    }
    if next_update < now.saturating_sub(OCSP_CLOCK_SKEW_SECONDS) {
        return Err(format!(
            "OCSP nextUpdate expired {} seconds ago, beyond the {OCSP_CLOCK_SKEW_SECONDS}-second skew allowance",
            now.saturating_sub(next_update)
        ));
    }

    Ok(OcspAcceptance {
        der_len: der.len(),
        this_update: single.this_update,
        next_update,
        delegated_responder,
    })
}

/// Locate the issuer of `leaf` inside the served chain.
///
/// A matching subject name is *not* enough. RFC 6960 binds a `CertID` to "the
/// CA that issued the certificate", and the same binding is what authorizes a
/// delegated responder, so the selected certificate must be proven to hold the
/// key that actually signed the leaf. A name match alone would let any
/// same-named certificate in the served bundle — an old CA generation, a
/// cross-signed sibling, or an operator-supplied impostor — decide which
/// issuer key hash a `CertID` is compared against. Same-name candidates are
/// therefore scanned until one verifies, and a self-issued leaf is accepted as
/// its own issuer only when it is genuinely self-*signed*.
fn select_issuer_der<'a>(
    leaf: &X509Certificate<'_>,
    chain: &'a [CertificateDer<'_>],
    policy: OcspCryptoPolicy,
) -> Result<&'a [u8], String> {
    let leaf_issuer = leaf.issuer().as_raw();
    let mut saw_name_match = false;
    for candidate in chain.iter().skip(1) {
        let Ok((trailing, parsed)) = X509Certificate::from_der(candidate.as_ref()) else {
            continue;
        };
        if parsed.subject().as_raw() != leaf_issuer {
            continue;
        }
        saw_name_match = true;
        if !trailing.is_empty() {
            return Err(
                "the served certificate chain carries an issuer candidate with trailing bytes \
                 after its X.509 DER encoding"
                    .to_string(),
            );
        }
        // This key is about to verify the served leaf. Apply the FIPS key-form
        // gate before the proof rather than classifying it after an
        // unapproved key has already participated in a cryptographic operation.
        check_certificate_key_form(candidate.as_ref(), "OCSP issuer certificate", policy)?;
        if leaf.verify_signature(Some(parsed.public_key())).is_err() {
            continue;
        }
        return Ok(candidate.as_ref());
    }
    // A self-issued leaf is its own issuer; this is the ordinary shape for the
    // self-signed certificates used in tests and single-node deployments. It
    // still has to verify under its own key: self-issued is a name property,
    // self-signed is the key property the binding actually needs.
    if leaf.subject().as_raw() == leaf_issuer {
        saw_name_match = true;
        if leaf.verify_signature(None).is_ok() {
            return chain
                .first()
                .map(|certificate| certificate.as_ref())
                .ok_or_else(|| "cannot select an OCSP issuer from an empty chain".to_string());
        }
    }
    let message = if saw_name_match {
        "the served certificate chain carries the leaf's issuer name but no certificate whose key \
         signed the leaf, so a stapled OCSP response cannot be bound to it"
    } else {
        "the served certificate chain does not contain the leaf's issuer, so a stapled OCSP \
         response cannot be bound to it"
    };
    Err(message.to_string())
}

/// Find the one `SingleResponse` whose `CertID` names the configured leaf.
///
/// More than one match is an ambiguity, not a preference. A strict client
/// re-derives the `CertID` itself and may pick a different entry than Ferrum
/// did — including an entry that reuses another supported hash algorithm — so
/// admitting the first `good` while a second entry says `revoked` would staple
/// exactly the response that makes the handshake fail. The whole response is
/// refused instead.
fn match_single_response<'a, 'b>(
    basic: &'a BasicResponse<'b>,
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<&'a SingleResponse<'b>, String> {
    let leaf_serial = leaf.raw_serial();
    let issuer_name = issuer.subject().as_raw();
    let issuer_key = issuer.public_key().subject_public_key.data.as_ref();

    let mut serial_matched = false;
    let mut matched: Option<&'a SingleResponse<'b>> = None;
    for single in &basic.response_data.single_responses {
        if single.cert_id.serial_number != leaf_serial {
            continue;
        }
        serial_matched = true;
        // Unsupported CertID digests fail the whole response closed even when
        // another entry would match, rather than silently changing its meaning.
        let algorithm = cert_id_digest(&single.cert_id.hash_algorithm)?;
        if digest::digest(algorithm, issuer_name).as_ref() != single.cert_id.issuer_name_hash {
            continue;
        }
        if digest::digest(algorithm, issuer_key).as_ref() != single.cert_id.issuer_key_hash {
            continue;
        }
        if matched.is_some() {
            let message = "OCSP response carries more than one SingleResponse for the configured \
                           certificate, so the status a strict client would select is ambiguous";
            return Err(message.to_string());
        }
        matched = Some(single);
    }
    if let Some(single) = matched {
        return Ok(single);
    }

    let message = if serial_matched {
        "OCSP response CertID matches the certificate serial but not the configured issuer \
         name/key, so it was issued for a different certificate"
    } else {
        "OCSP response contains no entry for the configured certificate's serial number"
    };
    Err(message.to_string())
}

/// Resolve the `CertID` digest, including SHA-1.
///
/// SHA-1 stays admitted under FIPS enforcement, deliberately: RFC 6960 §4.1.1
/// makes `CertID` a caller-chosen digest over the issuer's *public* name and
/// *public* key, and real responders overwhelmingly emit SHA-1. Ferrum
/// recomputes it and compares, so it selects which `SingleResponse` to read —
/// it is a lookup key, not a digital signature and not a security service in
/// the SP 800-131A Rev. 2 sense. Authenticity comes from the responder
/// signature (allow-listed by `check_signature_algorithm`) and from the
/// byte-exact `serialNumber` comparison. The digest itself is computed by the
/// selected provider through `fips::backend`. See the module docs and
/// `src/fips/inventory.rs`.
fn cert_id_digest(oid: &Oid<'_>) -> Result<&'static digest::Algorithm, String> {
    if *oid == OID_HASH_SHA1 {
        Ok(&digest::SHA1_FOR_LEGACY_USE_ONLY)
    } else if *oid == OID_NIST_HASH_SHA256 {
        Ok(&digest::SHA256)
    } else if *oid == OID_NIST_HASH_SHA384 {
        Ok(&digest::SHA384)
    } else if *oid == OID_NIST_HASH_SHA512 {
        Ok(&digest::SHA512)
    } else {
        Err("OCSP CertID uses an unsupported hash algorithm".to_string())
    }
}

/// Verify the `BasicOCSPResponse` signature against an authorized responder.
///
/// Returns `true` when a delegated responder certificate was used.
fn verify_signature_and_authorization(
    basic: &BasicResponse<'_>,
    issuer_der: &[u8],
    issuer: &X509Certificate<'_>,
    now: i64,
) -> Result<bool, String> {
    let issuer_key = issuer.public_key();

    // The issuing CA signing its own responses is the common case, and is
    // authorized by construction.
    if responder_matches(&basic.response_data.responder_id, issuer)
        && verify_basic_signature(basic, issuer_key).is_ok()
    {
        return Ok(false);
    }

    let mut saw_named_delegate = false;
    for candidate_der in &basic.certs {
        // A carried copy of the issuer is not a delegation; it was already
        // tried above, and re-trying it here would report it as delegated.
        if *candidate_der == issuer_der {
            continue;
        }
        // Structural admission already proved every carried entry is one
        // complete X.509 certificate, so this cannot skip an entry: failing
        // closed here keeps that guarantee explicit rather than re-introducing
        // a silent skip if the admission pass ever loosens.
        let (_, candidate) = X509Certificate::from_der(candidate_der).map_err(|_| {
            "OCSP response carries an unparseable responder certificate".to_string()
        })?;
        if !responder_matches(&basic.response_data.responder_id, &candidate) {
            continue;
        }
        saw_named_delegate = true;

        // This byte-exact Name check is deliberately stricter than RFC 5280
        // name matching. `verify_signature` below is the cryptographic proof
        // that the configured issuer actually issued the delegate.
        if candidate.issuer().as_raw() != issuer.subject().as_raw() {
            continue;
        }
        // RFC 6960 §4.2.2.2: a delegated responder must be issued by the same
        // CA as the certificate being checked and must carry id-kp-OCSPSigning.
        let has_ocsp_signing = candidate
            .extended_key_usage()
            .ok()
            .flatten()
            .is_some_and(|eku| eku.value.ocsp_signing);
        if !has_ocsp_signing {
            continue;
        }
        // A responder that is allowed to sign OCSP responses still has to be
        // allowed to produce a digital signature at all. KeyUsage is optional,
        // but a present one that withholds digitalSignature contradicts the EKU
        // and fails closed; an unparseable KeyUsage is likewise not proof.
        match candidate.key_usage() {
            Ok(Some(key_usage)) if !key_usage.value.digital_signature() => continue,
            Ok(_) => {}
            Err(_) => continue,
        }
        if candidate.verify_signature(Some(issuer_key)).is_err() {
            continue;
        }
        let validity = candidate.validity();
        if now.saturating_add(OCSP_CLOCK_SKEW_SECONDS) < validity.not_before.timestamp()
            || now.saturating_sub(OCSP_CLOCK_SKEW_SECONDS) > validity.not_after.timestamp()
        {
            continue;
        }
        if verify_basic_signature(basic, candidate.public_key()).is_ok() {
            return Ok(true);
        }
    }

    let message = if saw_named_delegate {
        "OCSP response was signed by a responder that is not authorized for this issuer: it is \
         not the issuing CA and no carried certificate is an issuer-signed, currently valid \
         id-kp-OCSPSigning delegate permitting digitalSignature whose signature verifies"
    } else {
        "OCSP response signature could not be verified against the configured issuer and the \
         response carries no matching authorized responder certificate"
    };
    Err(message.to_string())
}

fn responder_matches(responder_id: &ResponderId<'_>, candidate: &X509Certificate<'_>) -> bool {
    match responder_id {
        ResponderId::ByName(name) => candidate.subject().as_raw() == *name,
        ResponderId::ByKey(key_hash) => {
            // RFC 6960 §4.2.1 fixes this identifier at SHA-1 over the public
            // key BIT STRING; it selects a candidate certificate and nothing
            // more. The selected candidate still has to be issuer-signed,
            // OCSP-signing, time-valid, and produce a verifying signature, so a
            // digest collision authorizes nothing. Admitted under FIPS
            // enforcement as a key identifier, not as a signature digest — see
            // the module docs.
            let key = candidate.public_key().subject_public_key.data.as_ref();
            let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, key);
            hash.as_ref() == *key_hash
        }
    }
}

fn verify_basic_signature(
    basic: &BasicResponse<'_>,
    public_key: &SubjectPublicKeyInfo<'_>,
) -> Result<(), String> {
    x509_parser::verify::verify_signature(
        public_key,
        &basic.signature_algorithm,
        &basic.signature,
        basic.tbs_raw,
    )
    .map_err(|error| format!("OCSP signature verification failed: {error}"))
}
