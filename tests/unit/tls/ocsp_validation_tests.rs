//! Certificate-bound OCSP staple validation (issue #4300).
//!
//! Ferrum used to accept any non-empty byte string as a stapled OCSP response.
//! These tests pin the replacement contract on real, deterministically
//! constructed fixtures: every positive case is a genuine `BasicOCSPResponse`
//! signed with a real ECDSA P-256 key over the exact `tbsResponseData` bytes
//! the validator hashes, and every negative case differs from that fixture in
//! exactly one respect.
//!
//! The builder below is a plain DER encoder rather than an OCSP responder
//! library on purpose: the point of a negative case is to emit the *malformed*
//! or *mis-bound* encoding a responder would never produce, which a responder
//! library will not let a test express.

use std::sync::{Arc, OnceLock};

use ferrum_edge::config::EnvConfig;
use ferrum_edge::tls::TlsPolicy;
use ferrum_edge::tls::multi_cert::{GatewayCertificateInput, load_gateway_multi_cert_tls_config};
use ferrum_edge::tls::ocsp::{
    MAX_OCSP_RESPONSE_BYTES, OCSP_CLOCK_SKEW_SECONDS, OcspCryptoPolicy,
    validate_stapled_response_at, validate_stapled_response_at_with_policy, validate_structure,
    validate_structure_with_policy,
};
use ferrum_edge::tls::{frontend_tls_slot_with, load_frontend_tls_candidate_from_paths};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use rustls::pki_types::CertificateDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

// ── DER encoding helpers ───────────────────────────────────────────────────

/// Encode one DER TLV. Lengths above 127 use the long form, which every
/// fixture here stays well inside for the header but not for the content.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
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
    out.extend_from_slice(content);
    out
}

fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn explicit(number: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | number, content)
}

fn octet_string(content: &[u8]) -> Vec<u8> {
    tlv(0x04, content)
}

fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

fn enumerated(value: u8) -> Vec<u8> {
    tlv(0x0a, &[value])
}

fn der_null() -> Vec<u8> {
    tlv(0x05, &[])
}

fn bit_string_with_unused(unused_bits: u8, content: &[u8]) -> Vec<u8> {
    let mut body = vec![unused_bits];
    body.extend_from_slice(content);
    tlv(0x03, &body)
}

fn generalized_time(unix: i64) -> Vec<u8> {
    let datetime =
        time::OffsetDateTime::from_unix_timestamp(unix).expect("representable GeneralizedTime");
    let rendered = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        datetime.year(),
        u8::from(datetime.month()),
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    );
    tlv(0x18, rendered.as_bytes())
}

/// Re-encode the outer TLV with one redundant long-form length octet while
/// preserving its tag and content exactly.
fn redundant_outer_length(mut der: Vec<u8>) -> Vec<u8> {
    assert_eq!(der.first(), Some(&0x30));
    if der[1] & 0x80 == 0 {
        der.insert(1, 0x81);
    } else {
        der[1] += 1;
        der.insert(2, 0x00);
    }
    der
}

const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// id-sha224 (2.16.840.1.101.3.4.2.4): a real digest OID Ferrum does not use
/// for CertID binding.
const OID_SHA224: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// sha256WithRSAEncryption (1.2.840.113549.1.1.11).
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
/// id-rsassa-pss (1.2.840.113549.1.1.10).
const OID_RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
/// id-mgf1 (1.2.840.113549.1.1.8).
const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
/// ecdsa-with-SHA512 (1.2.840.10045.4.3.4): same family as the supported ECDSA
/// OIDs, but not a verifier-supported signature algorithm.
const OID_ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const OID_OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// `id-pkix-ocsp-nonce` (1.3.6.1.5.5.7.48.1.2): a real OCSP extension Ferrum
/// does not implement, used here as the stand-in unknown extension.
const OID_OCSP_NONCE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];

/// One `Extension`. DER omits `critical` when it is FALSE.
fn extension(oid_bytes: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![oid(oid_bytes)];
    if critical {
        parts.push(tlv(0x01, &[0xff]));
    }
    parts.push(octet_string(value));
    sequence(&parts)
}

/// `[n] EXPLICIT Extensions`, the shape both `responseExtensions` and
/// `singleExtensions` use.
fn extensions_field(number: u8, entries: &[Vec<u8>]) -> Vec<u8> {
    explicit(number, &sequence(entries))
}

/// A `responseExtensions` / `singleExtensions` field holding one unimplemented
/// extension, critical or not.
fn one_extension_field(number: u8, critical: bool) -> Vec<u8> {
    extensions_field(number, &[extension(OID_OCSP_NONCE, critical, b"nonce")])
}

/// Minimal positive-INTEGER content bytes for a serial number.
fn serial_bytes(serial: u64) -> Vec<u8> {
    let mut bytes = serial.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    bytes
}

fn parse_certificate(der: &[u8]) -> X509Certificate<'_> {
    let (_, parsed) = X509Certificate::from_der(der).expect("parseable certificate");
    parsed
}

fn algorithm_identifier(oid_bytes: &[u8]) -> Vec<u8> {
    algorithm_identifier_with_params(oid_bytes, None)
}

fn algorithm_identifier_with_params(oid_bytes: &[u8], params: Option<&[u8]>) -> Vec<u8> {
    match params {
        Some(params) => sequence(&[oid(oid_bytes), params.to_vec()]),
        None => sequence(&[oid(oid_bytes)]),
    }
}

/// Canonical `rsassa-pss` parameters for SHA-256: present hash, MGF1 with the
/// same hash, saltLength 32, trailerField omitted.
fn rsassa_pss_sha256_parameters() -> Vec<u8> {
    let hash_alg = algorithm_identifier(OID_SHA256);
    let mgf1 = algorithm_identifier_with_params(OID_MGF1, Some(&hash_alg));
    sequence(&[
        explicit(0, &hash_alg),
        explicit(1, &mgf1),
        explicit(2, &tlv(0x02, &[32])),
    ])
}

fn sha1(data: &[u8]) -> Vec<u8> {
    let algorithm = &ring::digest::SHA1_FOR_LEGACY_USE_ONLY;
    ring::digest::digest(algorithm, data).as_ref().to_vec()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let algorithm = &ring::digest::SHA256;
    ring::digest::digest(algorithm, data).as_ref().to_vec()
}

// ── Test PKI ───────────────────────────────────────────────────────────────

fn ensure_crypto_provider() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// The PKCS#8 form of an rcgen key pair, retained so the same key that issued a
/// certificate can also sign raw `tbsResponseData` bytes.
///
/// `rcgen::Issuer::new` consumes its `KeyPair`, so the PKCS#8 bytes are taken
/// before the pair is moved and every OCSP signature is produced from them.
struct SigningKey {
    pkcs8: Vec<u8>,
}

impl SigningKey {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.pkcs8, &rng)
            .expect("ECDSA signing key");
        // Touch the public key so an accidental key/certificate mismatch in a
        // fixture surfaces here rather than as an opaque verification failure.
        assert!(!key.public_key().as_ref().is_empty());
        key.sign(&rng, message).expect("sign").as_ref().to_vec()
    }
}

/// A fresh P-256 key pair plus its PKCS#8 copy.
fn new_key() -> (rcgen::KeyPair, SigningKey) {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key pair");
    let pkcs8 = pair.serialize_der();
    (pair, SigningKey { pkcs8 })
}

const LEAF_SERIAL: u64 = 0x4300;
const OTHER_SERIAL: u64 = 0x4301;

struct TestPki {
    issuer_key: SigningKey,
    issuer_der: Vec<u8>,
    issuer_pem: String,
    leaf_der: Vec<u8>,
    leaf_pem: String,
    leaf_key_pem: String,
    /// A delegated OCSP responder: issued by the CA, carrying
    /// `id-kp-OCSPSigning`.
    delegate_key: SigningKey,
    delegate_der: Vec<u8>,
    /// A responder certificate with the OCSP-signing EKU that the CA never
    /// issued.
    rogue_key: SigningKey,
    rogue_der: Vec<u8>,
    /// A certificate issued by the CA that lacks `id-kp-OCSPSigning`.
    no_eku_key: SigningKey,
    no_eku_der: Vec<u8>,
    /// A certificate issued by the CA that carries only
    /// `anyExtendedKeyUsage`, not `id-kp-OCSPSigning`.
    any_eku_key: SigningKey,
    any_eku_der: Vec<u8>,
    /// Issuer-signed OCSP delegates outside their certificate validity window.
    expired_delegate_key: SigningKey,
    expired_delegate_der: Vec<u8>,
    future_delegate_key: SigningKey,
    future_delegate_der: Vec<u8>,
    /// A delegated responder carrying an explicit `KeyUsage` that includes
    /// `digitalSignature`.
    signing_ku_key: SigningKey,
    signing_ku_der: Vec<u8>,
    /// A delegated responder whose present `KeyUsage` withholds
    /// `digitalSignature`.
    no_digital_signature_key: SigningKey,
    no_digital_signature_der: Vec<u8>,
    /// A second, unrelated CA and a leaf beneath it.
    other_issuer_der: Vec<u8>,
    /// A certificate carrying the CA's exact subject name over a different key.
    /// It never signed the leaf.
    impostor_issuer_der: Vec<u8>,
    /// A certificate whose subject equals its issuer name but whose signature
    /// was made by a *different* key of that name: self-issued, not
    /// self-signed.
    self_issued_not_self_signed_der: Vec<u8>,
}

fn build_pki() -> TestPki {
    ensure_crypto_provider();

    let (issuer_pair, issuer_key) = new_key();
    let mut issuer_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    issuer_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum OCSP Test CA");
    issuer_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let issuer_cert = issuer_params
        .self_signed(&issuer_pair)
        .expect("self-signed CA");
    let issuer_der = issuer_cert.der().to_vec();
    let issuer_pem = issuer_cert.pem();
    let issuer_handle = rcgen::Issuer::new(issuer_params, issuer_pair);

    let (leaf_pair, _leaf_key) = new_key();
    let mut leaf_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ferrum-ocsp-leaf");
    leaf_params.serial_number = Some(rcgen::SerialNumber::from(LEAF_SERIAL));
    leaf_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let leaf_cert = leaf_params
        .signed_by(&leaf_pair, &issuer_handle)
        .expect("leaf cert");
    let leaf_key_pem = leaf_pair.serialize_pem();

    // A delegated responder: issued by the CA and carrying id-kp-OCSPSigning.
    let (delegate_pair, delegate_key) = new_key();
    let mut delegate_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("delegate params");
    delegate_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum OCSP Responder");
    delegate_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::OcspSigning);
    let delegate_cert = delegate_params
        .signed_by(&delegate_pair, &issuer_handle)
        .expect("delegate cert");

    // Issued by the same CA, but without the OCSP-signing EKU.
    let (no_eku_pair, no_eku_key) = new_key();
    let mut no_eku_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("no-eku params");
    no_eku_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Non-Responder");
    let no_eku_cert = no_eku_params
        .signed_by(&no_eku_pair, &issuer_handle)
        .expect("no-eku cert");

    // `anyExtendedKeyUsage` is not the explicit id-kp-OCSPSigning delegation
    // RFC 6960 requires.
    let (any_eku_pair, any_eku_key) = new_key();
    let mut any_eku_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("any-eku params");
    any_eku_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Any-EKU Responder");
    any_eku_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::Any);
    let any_eku_cert = any_eku_params
        .signed_by(&any_eku_pair, &issuer_handle)
        .expect("any-eku cert");

    let cert_now = time::OffsetDateTime::now_utc();
    let (expired_delegate_pair, expired_delegate_key) = new_key();
    let mut expired_delegate_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("expired delegate params");
    expired_delegate_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Expired OCSP Responder");
    expired_delegate_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::OcspSigning);
    expired_delegate_params.not_before = cert_now - time::Duration::days(2);
    expired_delegate_params.not_after = cert_now - time::Duration::days(1);
    let expired_delegate_cert = expired_delegate_params
        .signed_by(&expired_delegate_pair, &issuer_handle)
        .expect("expired delegate cert");

    let (future_delegate_pair, future_delegate_key) = new_key();
    let mut future_delegate_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("future delegate params");
    future_delegate_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Future OCSP Responder");
    future_delegate_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::OcspSigning);
    future_delegate_params.not_before = cert_now + time::Duration::days(1);
    future_delegate_params.not_after = cert_now + time::Duration::days(2);
    let future_delegate_cert = future_delegate_params
        .signed_by(&future_delegate_pair, &issuer_handle)
        .expect("future delegate cert");

    // Self-signed with the OCSP-signing EKU, but never issued by the CA.
    let (rogue_pair, rogue_key) = new_key();
    let mut rogue_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("rogue");
    rogue_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Rogue Responder");
    rogue_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::OcspSigning);
    let rogue_cert = rogue_params.self_signed(&rogue_pair).expect("rogue cert");

    // Issued by the CA with id-kp-OCSPSigning and a KeyUsage that permits a
    // digital signature.
    let (signing_ku_pair, signing_ku_key) = new_key();
    let mut signing_ku_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("signing-ku params");
    signing_ku_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum OCSP Responder KU");
    signing_ku_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::OcspSigning);
    signing_ku_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    let signing_ku_cert = signing_ku_params
        .signed_by(&signing_ku_pair, &issuer_handle)
        .expect("signing-ku cert");

    // Same, but the present KeyUsage withholds digitalSignature.
    let (no_ds_pair, no_digital_signature_key) = new_key();
    let mut no_ds_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("no-ds params");
    no_ds_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum OCSP Responder No DS");
    no_ds_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::OcspSigning);
    no_ds_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyEncipherment);
    let no_ds_cert = no_ds_params
        .signed_by(&no_ds_pair, &issuer_handle)
        .expect("no-ds cert");

    // The CA's exact subject name over a foreign key. Nothing it holds signed
    // the leaf, so it must never be selected as the issuer.
    let (impostor_pair, _impostor_key) = new_key();
    let mut impostor_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("impostor params");
    impostor_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    impostor_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum OCSP Test CA");
    impostor_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let impostor_cert = impostor_params
        .self_signed(&impostor_pair)
        .expect("impostor CA cert");

    // A CA named "Ferrum Self Issued" issuing a certificate that carries the
    // same subject name but its own, different key: subject == issuer, yet the
    // signature is not verifiable under the certificate's own key.
    let (masquerade_pair, _masquerade_key) = new_key();
    let mut masquerade_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("masquerade params");
    masquerade_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    masquerade_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Self Issued");
    masquerade_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let _masquerade_cert = masquerade_params
        .self_signed(&masquerade_pair)
        .expect("masquerade CA cert");
    let masquerade_handle = rcgen::Issuer::new(masquerade_params, masquerade_pair);

    let (self_issued_pair, _self_issued_key) = new_key();
    let mut self_issued_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("self-issued params");
    self_issued_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Self Issued");
    let self_issued_cert = self_issued_params
        .signed_by(&self_issued_pair, &masquerade_handle)
        .expect("self-issued cert");

    let (other_pair, _other_key) = new_key();
    let mut other_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("other CA");
    other_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    other_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Unrelated CA");
    let other_cert = other_params
        .self_signed(&other_pair)
        .expect("other CA cert");

    TestPki {
        issuer_key,
        issuer_der,
        issuer_pem,
        leaf_pem: leaf_cert.pem(),
        leaf_der: leaf_cert.der().to_vec(),
        leaf_key_pem,
        delegate_key,
        delegate_der: delegate_cert.der().to_vec(),
        rogue_key,
        rogue_der: rogue_cert.der().to_vec(),
        no_eku_key,
        no_eku_der: no_eku_cert.der().to_vec(),
        any_eku_key,
        any_eku_der: any_eku_cert.der().to_vec(),
        expired_delegate_key,
        expired_delegate_der: expired_delegate_cert.der().to_vec(),
        future_delegate_key,
        future_delegate_der: future_delegate_cert.der().to_vec(),
        signing_ku_key,
        signing_ku_der: signing_ku_cert.der().to_vec(),
        no_digital_signature_key,
        no_digital_signature_der: no_ds_cert.der().to_vec(),
        other_issuer_der: other_cert.der().to_vec(),
        impostor_issuer_der: impostor_cert.der().to_vec(),
        self_issued_not_self_signed_der: self_issued_cert.der().to_vec(),
    }
}

// ── OCSP response builder ──────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Good,
    Revoked,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponderIdKind {
    ByName,
    ByKey,
}

struct ResponseBuilder<'a> {
    /// Certificate whose subject/public key names the responder.
    responder_cert: &'a [u8],
    /// Key that actually signs `tbsResponseData`.
    signing_key: &'a SigningKey,
    responder_id: ResponderIdKind,
    /// Certificate whose subject name and public key the `CertID` hashes.
    cert_id_issuer: &'a [u8],
    serial: u64,
    hash_oid: &'static [u8],
    status: Status,
    this_update: i64,
    next_update: Option<i64>,
    embedded_certs: Vec<&'a [u8]>,
    corrupt_signature: bool,
    response_status: u8,
    response_type_oid: &'static [u8],
    /// Raw replacement for the `producedAt` element.
    produced_at: Option<Vec<u8>>,
    /// Raw elements appended to `ResponseData` after `responses`.
    response_data_tail: Vec<Vec<u8>>,
    /// Raw replacement for everything after `thisUpdate` in each
    /// `SingleResponse`. `None` emits the default optional `nextUpdate`.
    single_tail: Option<Vec<Vec<u8>>>,
    /// Raw replacement for the `certStatus` element.
    cert_status: Option<Vec<u8>>,
    /// Emit a second entry for the same serial under this `CertID` hash OID.
    duplicate_hash_oid: Option<&'static [u8]>,
    /// Emit a leading entry for an unrelated serial.
    leading_serial: Option<u64>,
    /// Emit additional entries for unrelated serials after the configured
    /// certificate's entry.
    additional_serials: Vec<u64>,
    /// Raw element prepended to `ResponseData`, for `version [0]` fixtures.
    version_field: Option<Vec<u8>>,
    /// Tag byte of the `CertID` `serialNumber`. `0x02` is the universal
    /// INTEGER; `0x82` reuses tag *number* 2 in the context-specific class.
    serial_tag: u8,
    /// Encode the `CertID` `issuerNameHash` as a constructed OCTET STRING
    /// (`0x24`) wrapping a primitive segment, which DER forbids.
    constructed_name_hash: bool,
    /// Tag byte of the `responses` container. `0x30` is the universal
    /// constructed SEQUENCE; `0x10` is the primitive form DER forbids.
    responses_tag: u8,
    /// Unused-bit count in the signature BIT STRING. Canonical DER uses 0.
    signature_unused_bits: u8,
    /// Raw INTEGER content for every `CertID` `serialNumber`. `None` uses the
    /// canonical encoding of `serial`.
    serial_content: Option<Vec<u8>>,
    /// Raw ENUMERATED content for `responseStatus`. `None` uses
    /// `response_status` as a single content octet.
    response_status_content: Option<Vec<u8>>,
    /// Raw `AlgorithmIdentifier` parameters TLV for each `CertID` hash
    /// algorithm. `None` omits parameters, the usual encoding.
    hash_algorithm_parameters: Option<Vec<u8>>,
    /// Raw `AlgorithmIdentifier` parameters TLV for `signatureAlgorithm`.
    signature_algorithm_parameters: Option<Vec<u8>>,
    /// OID content bytes for `signatureAlgorithm`. Defaults to
    /// `ecdsa-with-SHA256`, matching the P-256 test keys.
    signature_algorithm_oid: &'static [u8],
}

impl<'a> ResponseBuilder<'a> {
    fn new(pki: &'a TestPki, now: i64) -> Self {
        Self {
            responder_cert: pki.issuer_der.as_slice(),
            signing_key: &pki.issuer_key,
            responder_id: ResponderIdKind::ByName,
            cert_id_issuer: pki.issuer_der.as_slice(),
            serial: LEAF_SERIAL,
            hash_oid: OID_SHA1,
            status: Status::Good,
            this_update: now - 3_600,
            next_update: Some(now + 3_600),
            embedded_certs: Vec::new(),
            corrupt_signature: false,
            response_status: 0,
            response_type_oid: OID_OCSP_BASIC,
            produced_at: None,
            response_data_tail: Vec::new(),
            single_tail: None,
            cert_status: None,
            duplicate_hash_oid: None,
            leading_serial: None,
            additional_serials: Vec::new(),
            version_field: None,
            serial_tag: 0x02,
            constructed_name_hash: false,
            responses_tag: 0x30,
            signature_unused_bits: 0,
            serial_content: None,
            response_status_content: None,
            hash_algorithm_parameters: None,
            signature_algorithm_parameters: None,
            signature_algorithm_oid: OID_ECDSA_SHA256,
        }
    }

    /// One `SingleResponse` for `serial`, with the `CertID` hashed under
    /// `hash_oid`.
    fn single_response(&self, serial: u64, hash_oid: &[u8]) -> Vec<u8> {
        let cert_id_issuer = parse_certificate(self.cert_id_issuer);
        let hash = |data: &[u8]| -> Vec<u8> {
            if hash_oid == OID_SHA256 {
                sha256(data)
            } else {
                sha1(data)
            }
        };
        let name_hash = hash(cert_id_issuer.subject().as_raw());
        let key_hash = hash(cert_id_issuer.public_key().subject_public_key.data.as_ref());
        let encoded_name_hash = if self.constructed_name_hash {
            tlv(0x24, &octet_string(&name_hash))
        } else {
            octet_string(&name_hash)
        };
        let serial_content = self
            .serial_content
            .clone()
            .unwrap_or_else(|| serial_bytes(serial));
        let cert_id = sequence(&[
            algorithm_identifier_with_params(hash_oid, self.hash_algorithm_parameters.as_deref()),
            encoded_name_hash,
            octet_string(&key_hash),
            tlv(self.serial_tag, &serial_content),
        ]);

        let default_status = match self.status {
            // good [0] IMPLICIT NULL
            Status::Good => tlv(0x80, &[]),
            // revoked [1] IMPLICIT RevokedInfo { revocationTime GeneralizedTime }
            Status::Revoked => tlv(0xa1, &generalized_time(self.this_update)),
            // unknown [2] IMPLICIT UnknownInfo (NULL)
            Status::Unknown => tlv(0x82, &[]),
        };
        let cert_status = self.cert_status.clone().unwrap_or(default_status);

        let mut parts = vec![cert_id, cert_status, generalized_time(self.this_update)];
        match &self.single_tail {
            Some(tail) => parts.extend(tail.iter().cloned()),
            None => {
                if let Some(next_update) = self.next_update {
                    parts.push(explicit(0, &generalized_time(next_update)));
                }
            }
        }
        sequence(&parts)
    }

    fn build(&self) -> Vec<u8> {
        let responder = parse_certificate(self.responder_cert);
        let responder_id = match self.responder_id {
            ResponderIdKind::ByName => explicit(1, responder.subject().as_raw()),
            ResponderIdKind::ByKey => {
                let key = responder.public_key().subject_public_key.data.as_ref();
                explicit(2, &octet_string(&sha1(key)))
            }
        };

        let mut singles = Vec::new();
        if let Some(serial) = self.leading_serial {
            singles.push(self.single_response(serial, self.hash_oid));
        }
        singles.push(self.single_response(self.serial, self.hash_oid));
        if let Some(hash_oid) = self.duplicate_hash_oid {
            singles.push(self.single_response(self.serial, hash_oid));
        }
        singles.extend(
            self.additional_serials
                .iter()
                .map(|serial| self.single_response(*serial, self.hash_oid)),
        );

        let default_produced_at = generalized_time(self.this_update);
        let produced_at = self.produced_at.clone().unwrap_or(default_produced_at);

        let responses = tlv(self.responses_tag, &singles.concat());
        let mut response_data_parts = match &self.version_field {
            Some(version) => vec![version.clone(), responder_id, produced_at, responses],
            None => vec![responder_id, produced_at, responses],
        };
        response_data_parts.extend(self.response_data_tail.iter().cloned());
        let response_data = sequence(&response_data_parts);

        let mut signature = self.signing_key.sign(&response_data);
        if self.corrupt_signature {
            let last = signature.len() - 1;
            signature[last] ^= 0xff;
        }

        let mut basic_parts = vec![
            response_data,
            algorithm_identifier_with_params(
                self.signature_algorithm_oid,
                self.signature_algorithm_parameters.as_deref(),
            ),
            bit_string_with_unused(self.signature_unused_bits, &signature),
        ];
        if !self.embedded_certs.is_empty() {
            let certs: Vec<Vec<u8>> = self.embedded_certs.iter().map(|d| d.to_vec()).collect();
            basic_parts.push(explicit(0, &sequence(&certs)));
        }
        let basic = sequence(&basic_parts);

        let status_element = match &self.response_status_content {
            Some(content) => tlv(0x0a, content),
            None => enumerated(self.response_status),
        };
        if self.response_status != 0 {
            return sequence(&[status_element]);
        }

        sequence(&[
            status_element,
            explicit(
                0,
                &sequence(&[oid(self.response_type_oid), octet_string(&basic)]),
            ),
        ])
    }
}

fn chain(pki: &TestPki) -> Vec<CertificateDer<'static>> {
    vec![
        CertificateDer::from(pki.leaf_der.clone()),
        CertificateDer::from(pki.issuer_der.clone()),
    ]
}

/// Evaluation instant for every fixture.
///
/// Real wall-clock time, because the load-path tests go through the production
/// entry points, which take their own `SystemTime::now()`. Every fixture is
/// built relative to this value, so the behaviour under test stays
/// deterministic even though the instant does not.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

/// A complete, correctly signed OCSP response over a freshly built test PKI.
///
/// Shared with the managed-TLS admin tests so their fixture is a response that
/// actually satisfies the issue #4300 structural gate rather than a placeholder
/// byte string that only happened to be non-empty.
pub(crate) fn signed_ocsp_response_fixture() -> Vec<u8> {
    let pki = build_pki();
    ResponseBuilder::new(&pki, now()).build()
}

// ── Structural admission (the admin boundary) ──────────────────────────────

#[test]
fn structural_validation_accepts_a_well_formed_basic_response() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();

    let structure = validate_structure(&der).expect("structurally valid");
    assert_eq!(structure.der_len, der.len());
    assert_eq!(structure.single_responses, 1);
}

#[test]
fn a_redundant_long_form_length_is_rejected() {
    let pki = build_pki();
    let der = redundant_outer_length(ResponseBuilder::new(&pki, now()).build());

    let error = validate_structure(&der).expect_err("must reject non-minimal DER length");
    assert!(error.contains("non-minimal length"), "{error}");
}

#[test]
fn structural_validation_rejects_arbitrary_bytes() {
    // The exact fixture the pre-#4300 unit test called a valid OCSP response.
    let error = validate_structure(&[1, 2, 3]).expect_err("must reject");
    assert!(
        error.contains("malformed DER") || error.contains("SEQUENCE"),
        "{error}"
    );

    let empty = validate_structure(&[]).expect_err("empty response");
    assert!(empty.contains("empty"), "{empty}");
}

#[test]
fn structural_validation_rejects_an_unsuccessful_envelope() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_status = 3;
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("tryLater(3)"), "{error}");
}

#[test]
fn structural_validation_rejects_a_non_basic_response_type() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_type_oid = OID_SHA256;
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("id-pkix-ocsp-basic"), "{error}");
}

#[test]
fn size_bound_is_enforced_before_parsing() {
    let oversized = vec![0x30_u8; MAX_OCSP_RESPONSE_BYTES + 1];
    let error = validate_structure(&oversized).expect_err("must reject");
    assert!(error.contains("exceeds"), "{error}");

    let pki = build_pki();
    let error =
        validate_stapled_response_at(&oversized, &chain(&pki), now()).expect_err("must reject");
    assert!(error.contains("exceeds"), "{error}");
}

#[test]
fn responder_certificate_count_is_bounded_at_sixteen() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.embedded_certs = vec![pki.delegate_der.as_slice(); 16];
    validate_structure(&builder.build()).expect("sixteen responder certificates are allowed");

    builder.embedded_certs.push(pki.delegate_der.as_slice());
    let error = validate_structure(&builder.build()).expect_err("seventeen must be rejected");
    assert!(
        error.contains("more than 16 responder certificates"),
        "{error}"
    );
}

#[test]
fn single_response_count_is_bounded_at_sixty_four() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.additional_serials = (0_u64..63).map(|offset| 0x5000 + offset).collect();
    let structure =
        validate_structure(&builder.build()).expect("sixty-four SingleResponses are allowed");
    assert_eq!(structure.single_responses, 64);

    builder.additional_serials.push(0x6000);
    let error = validate_structure(&builder.build()).expect_err("sixty-five must be rejected");
    assert!(error.contains("more than 64 SingleResponse"), "{error}");
}

#[test]
fn extension_count_is_bounded_at_thirty_two() {
    let pki = build_pki();
    let mut entries: Vec<Vec<u8>> = (1_u8..=32)
        .map(|suffix| {
            let mut extension_oid = OID_OCSP_NONCE.to_vec();
            extension_oid.push(suffix);
            extension(&extension_oid, false, b"value")
        })
        .collect();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(1, &entries)];
    validate_structure(&builder.build()).expect("thirty-two extensions are allowed");

    let mut extension_oid = OID_OCSP_NONCE.to_vec();
    extension_oid.push(33);
    entries.push(extension(&extension_oid, false, b"value"));
    builder.response_data_tail = vec![extensions_field(1, &entries)];
    let error = validate_structure(&builder.build()).expect_err("thirty-three must be rejected");
    assert!(error.contains("more than 32 extensions"), "{error}");
}

// ── Certificate-bound validation ───────────────────────────────────────────

#[test]
fn a_fresh_issuer_signed_response_for_the_configured_leaf_is_accepted() {
    let pki = build_pki();
    let at = now();
    let der = ResponseBuilder::new(&pki, at).build();

    let acceptance = validate_stapled_response_at(&der, &chain(&pki), at).expect("accepted staple");
    assert_eq!(acceptance.der_len, der.len());
    assert_eq!(acceptance.this_update, at - 3_600);
    assert_eq!(acceptance.next_update, at + 3_600);
    assert!(!acceptance.delegated_responder);
}

#[test]
fn a_responder_id_by_key_hash_is_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_id = ResponderIdKind::ByKey;

    validate_stapled_response_at(&builder.build(), &chain(&pki), now()).expect("accepted staple");
}

#[test]
fn a_sha256_cert_id_is_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.hash_oid = OID_SHA256;

    validate_stapled_response_at(&builder.build(), &chain(&pki), now()).expect("accepted staple");
}

#[test]
fn a_corrupted_signature_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.corrupt_signature = true;

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("signature"), "{error}");
}

#[test]
fn a_response_signed_by_an_unrelated_key_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // Named as the issuer, signed by someone else entirely.
    builder.signing_key = &pki.rogue_key;

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(
        error.contains("signature") || error.contains("responder"),
        "{error}"
    );
}

#[test]
fn a_properly_delegated_responder_is_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.delegate_der.as_slice();
    builder.signing_key = &pki.delegate_key;
    builder.embedded_certs = vec![pki.delegate_der.as_slice()];

    let acceptance = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("accepted staple");
    assert!(acceptance.delegated_responder);
}

#[test]
fn a_delegated_responder_without_the_ocsp_signing_eku_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.no_eku_der.as_slice();
    builder.signing_key = &pki.no_eku_key;
    builder.embedded_certs = vec![pki.no_eku_der.as_slice()];

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("not authorized"), "{error}");
}

#[test]
fn any_extended_key_usage_does_not_authorize_a_delegated_responder() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.any_eku_der.as_slice();
    builder.signing_key = &pki.any_eku_key;
    builder.embedded_certs = vec![pki.any_eku_der.as_slice()];

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("anyExtendedKeyUsage must not authorize OCSP signing");
    assert!(error.contains("not authorized"), "{error}");
}

#[test]
fn an_expired_delegated_responder_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.expired_delegate_der.as_slice();
    builder.signing_key = &pki.expired_delegate_key;
    builder.embedded_certs = vec![pki.expired_delegate_der.as_slice()];

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("an expired OCSP delegate must be rejected");
    assert!(error.contains("not authorized"), "{error}");
}

#[test]
fn a_not_yet_valid_delegated_responder_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.future_delegate_der.as_slice();
    builder.signing_key = &pki.future_delegate_key;
    builder.embedded_certs = vec![pki.future_delegate_der.as_slice()];

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("a not-yet-valid OCSP delegate must be rejected");
    assert!(error.contains("not authorized"), "{error}");
}

#[test]
fn a_self_signed_responder_the_issuer_never_issued_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.rogue_der.as_slice();
    builder.signing_key = &pki.rogue_key;
    builder.embedded_certs = vec![pki.rogue_der.as_slice()];

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("not authorized"), "{error}");
}

#[test]
fn a_response_for_a_different_serial_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.serial = OTHER_SERIAL;

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(
        error.contains("no entry for the configured certificate"),
        "{error}"
    );
}

#[test]
fn a_response_bound_to_a_different_issuer_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_id_issuer = pki.other_issuer_der.as_slice();

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("not the configured issuer"), "{error}");
}

#[test]
fn a_revoked_status_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.status = Status::Revoked;

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("certStatus revoked"), "{error}");
}

#[test]
fn an_unknown_status_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.status = Status::Unknown;

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("certStatus unknown"), "{error}");
}

#[test]
fn an_expired_response_is_rejected_and_the_skew_window_is_bounded() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.this_update = now() - 7_200;
    builder.next_update = Some(now() - OCSP_CLOCK_SKEW_SECONDS - 60);

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("expired"), "{error}");

    // Just inside the skew allowance the same shape is still served.
    builder.next_update = Some(now() - OCSP_CLOCK_SKEW_SECONDS + 60);
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("within the documented skew allowance");
}

#[test]
fn a_future_response_is_rejected_and_the_skew_window_is_bounded() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.this_update = now() + OCSP_CLOCK_SKEW_SECONDS + 60;
    builder.next_update = Some(now() + 86_400);

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("future"), "{error}");

    builder.this_update = now() + OCSP_CLOCK_SKEW_SECONDS - 60;
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("within the documented skew allowance");
}

#[test]
fn a_response_without_next_update_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.next_update = None;

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("omits nextUpdate"), "{error}");
}

#[test]
fn a_chain_without_the_issuer_cannot_bind_a_staple() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();
    let leaf_only = vec![CertificateDer::from(pki.leaf_der.clone())];

    let error = validate_stapled_response_at(&der, &leaf_only, now()).expect_err("must reject");
    assert!(
        error.contains("does not contain the leaf's issuer"),
        "{error}"
    );
}

#[test]
fn a_leaf_with_trailing_der_bytes_cannot_bind_a_staple() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();
    let mut leaf = pki.leaf_der.clone();
    leaf.push(0);
    let malformed_chain = vec![
        CertificateDer::from(leaf),
        CertificateDer::from(pki.issuer_der.clone()),
    ];

    let error = validate_stapled_response_at(&der, &malformed_chain, now())
        .expect_err("trailing leaf bytes must be rejected");
    assert!(
        error.contains("server certificate has trailing bytes"),
        "{error}"
    );
}

#[test]
fn an_issuer_with_trailing_der_bytes_cannot_bind_a_staple() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();
    let mut issuer = pki.issuer_der.clone();
    issuer.push(0);
    let malformed_chain = vec![
        CertificateDer::from(pki.leaf_der.clone()),
        CertificateDer::from(issuer),
    ];

    let error = validate_stapled_response_at(&der, &malformed_chain, now())
        .expect_err("trailing issuer bytes must be rejected");
    assert!(
        error.contains("issuer candidate with trailing bytes"),
        "{error}"
    );
}

// ── ResponseData grammar ───────────────────────────────────────────────────

#[test]
fn a_malformed_produced_at_value_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // Correctly tagged GeneralizedTime, but the value is not a time.
    builder.produced_at = Some(tlv(0x18, b"not-a-timestamp"));

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("producedAt"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("producedAt"), "{error}");
}

#[test]
fn a_generalized_time_without_a_timezone_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.produced_at = Some(tlv(0x18, b"20260101000000"));

    let error = validate_structure(&builder.build()).expect_err("must reject missing timezone");
    assert!(error.contains("DER GeneralizedTime"), "{error}");
}

#[test]
fn a_generalized_time_with_an_explicit_offset_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.produced_at = Some(tlv(0x18, b"20260101000000+0000"));

    let error = validate_structure(&builder.build()).expect_err("must reject explicit offset");
    assert!(error.contains("DER GeneralizedTime"), "{error}");
}

#[test]
fn a_generalized_time_with_fractional_seconds_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.produced_at = Some(tlv(0x18, b"20260101000000.1Z"));

    let error = validate_structure(&builder.build()).expect_err("must reject fractional seconds");
    assert!(error.contains("DER GeneralizedTime"), "{error}");
}

#[test]
fn a_produced_at_with_the_wrong_tag_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.produced_at = Some(octet_string(b"20260101000000Z"));

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("producedAt is not a GeneralizedTime"),
        "{error}"
    );
}

#[test]
fn an_unknown_trailing_field_in_response_data_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // [3] is not a field of ResponseData at all.
    builder.response_data_tail = vec![explicit(3, &octet_string(b"surprise"))];

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("unexpected field after responses"),
        "{error}"
    );
}

#[test]
fn a_duplicate_response_extensions_field_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    let entry = one_extension_field(1, false);
    builder.response_data_tail = vec![entry.clone(), entry];

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("trailing fields after responseExtensions"),
        "{error}"
    );
}

#[test]
fn a_non_critical_response_extension_is_parsed_and_ignored() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![one_extension_field(1, false)];

    validate_structure(&builder.build()).expect("structurally valid");
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("a non-critical extension is ignored");
}

#[test]
fn a_critical_response_extension_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![one_extension_field(1, true)];

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("critical extension"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("critical extension"), "{error}");
}

#[test]
fn a_malformed_extensions_container_is_rejected() {
    let pki = build_pki();

    // Not a SEQUENCE OF Extension: an OCTET STRING where the container belongs.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![explicit(1, &octet_string(b"not-extensions"))];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("responseExtensions is not a SEQUENCE"),
        "{error}"
    );

    // An Extension whose extnValue is not an OCTET STRING.
    let mut builder = ResponseBuilder::new(&pki, now());
    let malformed = sequence(&[oid(OID_OCSP_NONCE), tlv(0x02, &[0x01])]);
    builder.response_data_tail = vec![extensions_field(1, &[malformed])];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("extnValue"), "{error}");

    // DER omits `critical` when FALSE, so an encoded FALSE is not DER.
    let mut builder = ResponseBuilder::new(&pki, now());
    let explicit_false = sequence(&[
        oid(OID_OCSP_NONCE),
        tlv(0x01, &[0x00]),
        octet_string(b"nonce"),
    ]);
    builder.response_data_tail = vec![extensions_field(1, &[explicit_false])];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("DEFAULT FALSE"), "{error}");

    // An empty Extensions container is not `SIZE (1..MAX)`.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(1, &[])];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("empty SEQUENCE"), "{error}");
}

// ── SingleResponse grammar ─────────────────────────────────────────────────

#[test]
fn a_duplicate_next_update_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // The second [0] used to silently overwrite the first, so a responder could
    // sign one window and have Ferrum enforce another.
    builder.single_tail = Some(vec![
        explicit(0, &generalized_time(now() + 3_600)),
        explicit(0, &generalized_time(now() + 86_400)),
    ]);

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("unexpected field after thisUpdate"),
        "{error}"
    );
}

#[test]
fn misordered_single_response_fields_are_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // singleExtensions [1] before nextUpdate [0].
    builder.single_tail = Some(vec![
        one_extension_field(1, false),
        explicit(0, &generalized_time(now() + 3_600)),
    ]);

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("trailing fields after singleExtensions"),
        "{error}"
    );
}

#[test]
fn an_unknown_trailing_field_in_a_single_response_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.single_tail = Some(vec![
        explicit(0, &generalized_time(now() + 3_600)),
        explicit(2, &octet_string(b"surprise")),
    ]);

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("unexpected field after thisUpdate"),
        "{error}"
    );
}

#[test]
fn single_extensions_follow_the_same_criticality_rule() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.single_tail = Some(vec![
        explicit(0, &generalized_time(now() + 3_600)),
        one_extension_field(1, false),
    ]);
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("a non-critical singleExtension is ignored");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.single_tail = Some(vec![
        explicit(0, &generalized_time(now() + 3_600)),
        one_extension_field(1, true),
    ]);
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("singleExtensions"), "{error}");
    assert!(error.contains("critical extension"), "{error}");
}

// ── CertStatus CHOICE encoding ─────────────────────────────────────────────

#[test]
fn a_constructed_or_non_empty_good_status_is_rejected() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    // Constructed [0] instead of the primitive IMPLICIT NULL.
    builder.cert_status = Some(tlv(0xa0, &[]));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("certStatus good"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    // Primitive, but carrying content an IMPLICIT NULL cannot have.
    builder.cert_status = Some(tlv(0x80, &[0x00]));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("certStatus good"), "{error}");
}

#[test]
fn a_malformed_unknown_status_is_rejected_structurally() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_status = Some(tlv(0x82, &[0x05, 0x00]));

    // Structurally malformed before serving policy ever sees `unknown`.
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("certStatus unknown"), "{error}");
    assert!(error.contains("IMPLICIT NULL"), "{error}");
}

#[test]
fn a_malformed_revoked_status_is_rejected_structurally() {
    let pki = build_pki();

    // revoked encoded as a primitive, but RevokedInfo is a SEQUENCE.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_status = Some(tlv(0x81, &generalized_time(now())));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("revoked is primitive"), "{error}");

    // Constructed, but revocationTime is missing its GeneralizedTime.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_status = Some(tlv(0xa1, &octet_string(b"20260101000000Z")));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("revocationTime"), "{error}");

    // A revocationReason that is not an ENUMERATED.
    let mut builder = ResponseBuilder::new(&pki, now());
    let mut revoked = generalized_time(now() - 60);
    revoked.extend_from_slice(&explicit(0, &octet_string(b"keyCompromise")));
    builder.cert_status = Some(tlv(0xa1, &revoked));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("revocationReason"), "{error}");

    // A well-formed RevokedInfo still fails closed on serving policy, and does
    // so with the status reason rather than a structural one.
    let mut builder = ResponseBuilder::new(&pki, now());
    let mut revoked = generalized_time(now() - 60);
    revoked.extend_from_slice(&explicit(0, &enumerated(1)));
    builder.cert_status = Some(tlv(0xa1, &revoked));
    validate_structure(&builder.build()).expect("structurally well formed");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("certStatus revoked"), "{error}");
}

#[test]
fn an_unrecognized_cert_status_alternative_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_status = Some(tlv(0x83, &[]));

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("unrecognized alternative"), "{error}");
}

// ── CertID ambiguity ───────────────────────────────────────────────────────

#[test]
fn duplicate_matching_cert_ids_are_rejected_as_ambiguous() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.duplicate_hash_oid = Some(OID_SHA1);

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("more than one SingleResponse"), "{error}");
}

#[test]
fn a_second_matching_cert_id_under_another_hash_algorithm_is_also_ambiguous() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // A strict client that derives SHA-256 CertIDs would select this second
    // entry, so Ferrum must not silently serve the first.
    builder.duplicate_hash_oid = Some(OID_SHA256);

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("more than one SingleResponse"), "{error}");
}

#[test]
fn a_leading_entry_for_another_certificate_still_resolves_the_configured_one() {
    let pki = build_pki();
    let at = now();
    let mut builder = ResponseBuilder::new(&pki, at);
    builder.leading_serial = Some(OTHER_SERIAL);

    let acceptance = validate_stapled_response_at(&builder.build(), &chain(&pki), at)
        .expect("one unambiguous match");
    assert_eq!(acceptance.next_update, at + 3_600);
}

// ── Issuer selection ───────────────────────────────────────────────────────

#[test]
fn a_same_subject_non_issuer_chain_candidate_cannot_stand_in_for_the_issuer() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();
    let impostor = vec![
        CertificateDer::from(pki.leaf_der.clone()),
        CertificateDer::from(pki.impostor_issuer_der.clone()),
    ];

    let error = validate_stapled_response_at(&der, &impostor, now()).expect_err("must reject");
    assert!(
        error.contains("no certificate whose key signed the leaf"),
        "{error}"
    );
}

#[test]
fn the_scan_continues_past_a_same_subject_impostor_to_the_real_issuer() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();
    let with_impostor = vec![
        CertificateDer::from(pki.leaf_der.clone()),
        CertificateDer::from(pki.impostor_issuer_der.clone()),
        CertificateDer::from(pki.issuer_der.clone()),
    ];

    validate_stapled_response_at(&der, &with_impostor, now())
        .expect("the real issuer is still found behind a same-name impostor");
}

#[test]
fn a_self_issued_leaf_that_is_not_self_signed_cannot_bind_a_staple() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();
    let masquerade = pki.self_issued_not_self_signed_der.clone();
    let self_issued = vec![CertificateDer::from(masquerade)];

    let error = validate_stapled_response_at(&der, &self_issued, now()).expect_err("must reject");
    assert!(
        error.contains("no certificate whose key signed the leaf"),
        "{error}"
    );
}

// ── Delegated responder key usage ──────────────────────────────────────────

#[test]
fn a_delegated_responder_with_digital_signature_key_usage_is_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.signing_ku_der.as_slice();
    builder.signing_key = &pki.signing_ku_key;
    builder.embedded_certs = vec![pki.signing_ku_der.as_slice()];

    let acceptance = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("accepted staple");
    assert!(acceptance.delegated_responder);
}

#[test]
fn a_delegated_responder_whose_key_usage_excludes_digital_signature_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.no_digital_signature_der.as_slice();
    builder.signing_key = &pki.no_digital_signature_key;
    builder.embedded_certs = vec![pki.no_digital_signature_der.as_slice()];

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("not authorized"), "{error}");
}

// ── DER class and primitive/constructed form ───────────────────────────────

#[test]
fn a_context_specific_element_reusing_a_universal_tag_number_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // `[2] IMPLICIT` primitive: the same tag *number* as a universal INTEGER,
    // and the same content bytes, in a different class. A parser that compares
    // only the tag number would decode it as the serial number and bind the
    // response to the configured certificate.
    builder.serial_tag = 0x82;

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("serialNumber"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("serialNumber"), "{error}");
}

#[test]
fn a_constructed_octet_string_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // A constructed OCTET STRING carrying one primitive segment holds the same
    // octets as the DER form, so a tag-number-only check would hash-compare it
    // against the issuer name and accept the binding.
    builder.constructed_name_hash = true;

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("issuerNameHash") || error.contains("malformed DER"),
        "{error}"
    );
}

#[test]
fn a_primitive_sequence_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // Universal tag number 16 in the primitive form. DER has no such encoding,
    // so `responses` must be refused rather than walked as a container.
    builder.responses_tag = 0x10;

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("responses is not a SEQUENCE") || error.contains("malformed DER"),
        "{error}"
    );
}

#[test]
fn an_explicitly_encoded_default_version_is_rejected() {
    let pki = build_pki();

    // DER omits a DEFAULT value, so `[0] EXPLICIT INTEGER 0` is a second
    // encoding of the same signed object: a strict client refuses it, and
    // Ferrum must not staple what a strict client refuses.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.version_field = Some(explicit(0, &tlv(0x02, &[0x00])));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("DEFAULT value"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("DEFAULT value"), "{error}");

    // A non-default version is unsupported, and still reported as such.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.version_field = Some(explicit(0, &tlv(0x02, &[0x01])));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("unsupported version 1"), "{error}");
}

// ── Primitive DER type constraints ─────────────────────────────────────────

#[test]
fn a_valid_signature_with_nonzero_unused_bits_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // Cryptographically valid payload bytes; only the unused-bit count differs
    // from the canonical octet-aligned BIT STRING. x509-parser's verifier
    // ignores unused_bits, so this is the encoding that would still verify.
    builder.signature_unused_bits = 1;

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("unused_bits=1"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("unused_bits=1"), "{error}");
}

#[test]
fn a_signature_bit_string_with_an_invalid_unused_bit_count_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_unused_bits = 8;

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("unused_bits=8"), "{error}");
}

#[test]
fn empty_nonminimal_and_negative_cert_id_serials_are_rejected() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.serial_content = Some(Vec::new());
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("serialNumber"), "{error}");
    assert!(error.contains("empty"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    let mut padded = vec![0x00];
    padded.extend_from_slice(&serial_bytes(LEAF_SERIAL));
    builder.serial_content = Some(padded);
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("serialNumber"), "{error}");
    assert!(error.contains("minimal"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("serialNumber"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.serial_content = Some(vec![0x80]);
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("serialNumber"), "{error}");
    assert!(error.contains("negative"), "{error}");
}

#[test]
fn malformed_and_noncanonical_extension_oids_are_rejected() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(1, &[extension(&[], false, b"nonce")])];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("extnID"), "{error}");
    assert!(error.contains("empty"), "{error}");

    let mut unterminated = OID_OCSP_NONCE.to_vec();
    let last = unterminated.len() - 1;
    unterminated[last] |= 0x80;
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(
        1,
        &[extension(&unterminated, false, b"nonce")],
    )];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("extnID"), "{error}");
    assert!(error.contains("terminated"), "{error}");

    let mut redundant = vec![OID_OCSP_NONCE[0], 0x80];
    redundant.extend_from_slice(&OID_OCSP_NONCE[1..]);
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(
        1,
        &[extension(&redundant, false, b"nonce")],
    )];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("extnID"), "{error}");
    assert!(error.contains("0x80"), "{error}");
}

#[test]
fn noncanonical_successful_response_status_encodings_are_rejected() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_status_content = Some(Vec::new());
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("responseStatus"), "{error}");
    assert!(error.contains("empty"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_status_content = Some(vec![0x00, 0x00]);
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("responseStatus"), "{error}");
    assert!(error.contains("minimal"), "{error}");
}

#[test]
fn noncanonical_revocation_reason_encodings_are_rejected() {
    let pki = build_pki();

    let mut revoked = generalized_time(now() - 60);
    revoked.extend_from_slice(&explicit(0, &tlv(0x0a, &[])));
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_status = Some(tlv(0xa1, &revoked));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("revocationReason"), "{error}");
    assert!(error.contains("empty"), "{error}");

    let mut revoked = generalized_time(now() - 60);
    revoked.extend_from_slice(&explicit(0, &tlv(0x0a, &[0x00, 0x01])));
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_status = Some(tlv(0xa1, &revoked));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("revocationReason"), "{error}");
    assert!(error.contains("minimal"), "{error}");
}

#[test]
fn a_cert_id_hash_algorithm_with_null_parameters_is_still_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.hash_algorithm_parameters = Some(der_null());

    validate_structure(&builder.build()).expect("structurally valid");
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("SHA-1 CertID hashAlgorithm with canonical NULL is accepted");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.hash_oid = OID_SHA256;
    builder.hash_algorithm_parameters = Some(der_null());
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("SHA-256 CertID hashAlgorithm with canonical NULL is accepted");
}

#[test]
fn an_ecdsa_signature_algorithm_with_null_parameters_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_parameters = Some(der_null());
    let der = builder.build();

    let error = validate_structure(&der).expect_err("must reject");
    assert!(error.contains("signatureAlgorithm"), "{error}");
    assert!(error.contains("absent"), "{error}");

    // The ECDSA signature bytes are cryptographically valid: signatureAlgorithm
    // sits outside tbsResponseData, and the verifier selects ECDSA by OID while
    // ignoring parameters. A strict client still refuses the NULL encoding.
    let error = validate_stapled_response_at(&der, &chain(&pki), now()).expect_err("must reject");
    assert!(error.contains("signatureAlgorithm"), "{error}");
    assert!(error.contains("absent"), "{error}");
}

#[test]
fn an_ed25519_signature_algorithm_with_null_parameters_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_ED25519;
    builder.signature_algorithm_parameters = Some(der_null());
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("signatureAlgorithm"), "{error}");
    assert!(error.contains("absent"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_ED25519;
    validate_structure(&builder.build()).expect("Ed25519 parameters are absent");
}

#[test]
fn rsa_pkcs1_signature_algorithm_requires_canonical_null_parameters() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_SHA256_RSA;
    builder.signature_algorithm_parameters = Some(der_null());
    validate_structure(&builder.build())
        .expect("sha256WithRSAEncryption with canonical NULL is structurally valid");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_SHA256_RSA;
    let error = validate_structure(&builder.build()).expect_err("must reject absent RSA NULL");
    assert!(error.contains("signatureAlgorithm"), "{error}");
    assert!(error.contains("NULL"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_SHA256_RSA;
    builder.signature_algorithm_parameters = Some(tlv(0x02, &[0x00]));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("signatureAlgorithm"), "{error}");
    assert!(error.contains("NULL"), "{error}");
}

#[test]
fn rsassa_pss_rejects_absent_null_and_malformed_parameters() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_RSASSA_PSS;
    let error = validate_structure(&builder.build()).expect_err("must reject absent PSS");
    assert!(error.contains("signatureAlgorithm"), "{error}");
    assert!(error.contains("rsassa-pss"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("absent PSS must not be served");
    assert!(error.contains("rsassa-pss"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_RSASSA_PSS;
    builder.signature_algorithm_parameters = Some(der_null());
    let error = validate_structure(&builder.build()).expect_err("must reject NULL PSS");
    assert!(error.contains("signatureAlgorithm"), "{error}");
    assert!(error.contains("SEQUENCE"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_RSASSA_PSS;
    builder.signature_algorithm_parameters = Some(tlv(0x30, &[]));
    let error = validate_structure(&builder.build()).expect_err("must reject empty PSS SEQUENCE");
    assert!(error.contains("rsassa-pss"), "{error}");
    assert!(error.contains("hashAlgorithm"), "{error}");

    let canonical = rsassa_pss_sha256_parameters();
    // Canonical PSS params use a short-form SEQUENCE; append an INTEGER inside
    // it so the verifier's parser would ignore the extra bytes.
    assert_eq!(canonical[0], 0x30);
    assert!(
        canonical[1] < 0x80,
        "canonical PSS params use a short length"
    );
    let mut inner = canonical[2..].to_vec();
    inner.extend_from_slice(&tlv(0x02, &[0x01]));
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_RSASSA_PSS;
    builder.signature_algorithm_parameters = Some(tlv(0x30, &inner));
    let error = validate_structure(&builder.build()).expect_err("must reject trailing PSS fields");
    assert!(error.contains("rsassa-pss"), "{error}");
    assert!(error.contains("trailing"), "{error}");
}

#[test]
fn rsassa_pss_canonical_parameters_are_structurally_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_RSASSA_PSS;
    builder.signature_algorithm_parameters = Some(rsassa_pss_sha256_parameters());

    validate_structure(&builder.build()).expect("canonical rsassa-pss parameters are structural");
    // The test PKI is ECDSA, so the staple cannot be served even though the
    // parameter encoding is the one the verification path can parse.
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("ECDSA key cannot verify rsassa-pss");
    assert!(
        error.contains("signature") || error.contains("responder"),
        "{error}"
    );
}

#[test]
fn an_unknown_signature_algorithm_is_rejected_regardless_of_parameters() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_ECDSA_SHA512;
    let error = validate_structure(&builder.build()).expect_err("must reject unknown signature");
    assert!(error.contains("signatureAlgorithm"), "{error}");
    assert!(error.contains("cannot be validated"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_ECDSA_SHA512;
    builder.signature_algorithm_parameters = Some(der_null());
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("signatureAlgorithm"), "{error}");
    assert!(error.contains("cannot be validated"), "{error}");
}

#[test]
fn an_unsupported_cert_id_hash_algorithm_is_structurally_parseable_but_not_served() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.hash_oid = OID_SHA224;
    builder.hash_algorithm_parameters = Some(der_null());

    validate_structure(&builder.build())
        .expect("unknown digest OIDs remain structurally parseable");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject unsupported CertID hash");
    assert!(error.contains("unsupported hash"), "{error}");
}

#[test]
fn algorithm_identifier_parameters_that_are_not_absent_or_null_are_rejected() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.hash_algorithm_parameters = Some(tlv(0x02, &[0x00]));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("hashAlgorithm"), "{error}");
    assert!(error.contains("parameters"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.hash_algorithm_parameters = Some(tlv(0x05, &[0x00]));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("hashAlgorithm"), "{error}");
    assert!(error.contains("parameters"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_parameters = Some(tlv(0x02, &[0x00]));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("signatureAlgorithm"), "{error}");
    assert!(error.contains("parameters"), "{error}");
}

// ── Embedded responder certificates ────────────────────────────────────────

#[test]
fn a_malformed_embedded_certificate_is_rejected() {
    let pki = build_pki();
    let malformed = sequence(&[octet_string(b"not a certificate")]);
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.embedded_certs = vec![malformed.as_slice()];

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("parseable X.509 certificate"), "{error}");
}

#[test]
fn a_malformed_unused_embedded_certificate_is_still_rejected() {
    let pki = build_pki();
    let malformed = sequence(&[octet_string(b"not a certificate")]);
    // The response is signed by the issuing CA itself, and the first carried
    // entry is a valid certificate, so the malformed one is never consulted
    // for authorization. Structural admission must still refuse the whole
    // response: bytes this parser cannot account for sit inside what the
    // responder signed.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.embedded_certs = vec![pki.signing_ku_der.as_slice(), malformed.as_slice()];

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("parseable X.509 certificate"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("parseable X.509 certificate"), "{error}");
}

#[test]
fn a_well_formed_embedded_certificate_is_still_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.embedded_certs = vec![pki.signing_ku_der.as_slice()];

    validate_structure(&builder.build()).expect("structurally valid");
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("an issuer-signed response is accepted alongside a carried certificate");
}

// ── Extension identity ─────────────────────────────────────────────────────

#[test]
fn duplicate_extension_oids_are_rejected() {
    let pki = build_pki();

    // X.509 forbids repeating one extension type. Ferrum ignores a supported
    // non-critical extension, so admitting the repetition would let Ferrum and
    // a strict client disagree about the same signed bytes.
    let repeated = [
        extension(OID_OCSP_NONCE, false, b"first"),
        extension(OID_OCSP_NONCE, false, b"second"),
    ];
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(1, &repeated)];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("repeats an extension OID"), "{error}");

    // The same rule applies inside a SingleResponse.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.single_tail = Some(vec![
        explicit(0, &generalized_time(now() + 3_600)),
        extensions_field(1, &repeated),
    ]);
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("repeats an extension OID"), "{error}");
}

#[test]
fn distinct_extension_oids_are_still_accepted() {
    let pki = build_pki();
    let distinct = [
        extension(OID_OCSP_NONCE, false, b"nonce"),
        extension(OID_SHA256, false, b"other"),
    ];
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(1, &distinct)];

    validate_structure(&builder.build()).expect("structurally valid");
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("distinct non-critical extensions are ignored");
}

// ── Load-path integration ──────────────────────────────────────────────────

fn tls_policy() -> TlsPolicy {
    ensure_crypto_provider();
    TlsPolicy::from_env_config(&EnvConfig::default()).expect("tls policy")
}

/// Materialize the served chain (leaf + issuer) and key as files, plus an OCSP
/// DER file, and return their paths.
fn write_material(dir: &std::path::Path, pki: &TestPki, ocsp: &[u8]) -> (String, String, String) {
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    let ocsp_path = dir.join("staple.der");
    std::fs::write(&cert_path, format!("{}{}", pki.leaf_pem, pki.issuer_pem)).expect("write cert");
    std::fs::write(&key_path, &pki.leaf_key_pem).expect("write key");
    std::fs::write(&ocsp_path, ocsp).expect("write ocsp");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
        ocsp_path.to_string_lossy().into_owned(),
    )
}

#[test]
fn the_single_certificate_loader_admits_a_valid_staple_and_refuses_an_invalid_one() {
    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    let valid = ResponseBuilder::new(&pki, now()).build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &valid);
    let policy = tls_policy();

    load_frontend_tls_candidate_from_paths(
        &cert_path,
        &key_path,
        None,
        Some(&ocsp_path),
        false,
        &policy,
        30,
        30,
        &[],
        None,
    )
    .expect("valid staple is admitted");

    // The pre-#4300 accepted-anything fixture must now fail the whole load.
    std::fs::write(&ocsp_path, [1_u8, 2, 3]).expect("rewrite ocsp");
    let error = match load_frontend_tls_candidate_from_paths(
        &cert_path,
        &key_path,
        None,
        Some(&ocsp_path),
        false,
        &policy,
        30,
        30,
        &[],
        None,
    ) {
        Err(error) => error,
        Ok(_) => panic!("garbage staple is refused"),
    };
    let rendered = format!("{error:#}");
    assert!(rendered.contains("was rejected"), "{rendered}");
    // Diagnostics stay redacted: no certificate or response bytes leak.
    assert!(!rendered.contains("BEGIN CERTIFICATE"), "{rendered}");
}

/// A reload that produces an invalid staple must never reach the published
/// slot: the candidate fails to build, so the atomic `ArcSwap` publication has
/// nothing to swap in and the last-known-good `ServerConfig` keeps serving.
#[test]
fn a_reload_with_a_bad_staple_leaves_the_last_known_good_material_in_service() {
    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    let valid = ResponseBuilder::new(&pki, now()).build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &valid);
    let policy = tls_policy();

    let rebuild = || {
        load_frontend_tls_candidate_from_paths(
            &cert_path,
            &key_path,
            None,
            Some(&ocsp_path),
            false,
            &policy,
            30,
            30,
            &[],
            None,
        )
    };

    let accepted = rebuild().expect("first load");
    let published = frontend_tls_slot_with(Arc::clone(&accepted.config));
    let before = published.load_full();

    // A revoked response is exactly the shape that used to be published
    // silently. Each of these rebuilds must fail, so the reload task has no
    // candidate to publish.
    for builder in [
        {
            let mut builder = ResponseBuilder::new(&pki, now());
            builder.status = Status::Revoked;
            builder
        },
        {
            let mut builder = ResponseBuilder::new(&pki, now());
            builder.next_update = Some(now() - OCSP_CLOCK_SKEW_SECONDS - 3_600);
            builder
        },
        {
            let mut builder = ResponseBuilder::new(&pki, now());
            builder.corrupt_signature = true;
            builder
        },
    ] {
        std::fs::write(&ocsp_path, builder.build()).expect("rewrite ocsp");
        let rebuilt = rebuild();
        assert!(
            rebuilt.is_err(),
            "an invalid staple must not produce a candidate"
        );
        if let Ok(candidate) = rebuilt {
            published.store(Arc::new(Some(candidate.config)));
        }
    }

    let after = published.load_full();
    assert!(
        Arc::ptr_eq(&before, &after),
        "a refused staple must leave the published ServerConfig untouched"
    );

    // The original, still-valid response reloads cleanly, so the refusal was
    // about the staple and not about the surrounding material.
    std::fs::write(&ocsp_path, &valid).expect("restore ocsp");
    rebuild().expect("the last-known-good staple still reloads");
}

#[test]
fn the_multi_certificate_loader_binds_the_staple_to_its_single_certificate() {
    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    let valid = ResponseBuilder::new(&pki, now()).build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &valid);
    let policy = tls_policy();

    let inputs = vec![GatewayCertificateInput {
        cert_source: cert_path.clone(),
        key_source: key_path.clone(),
        hostname: Some("localhost".to_string()),
        identity: "ns/gw/listener".to_string(),
        is_default: true,
    }];

    load_gateway_multi_cert_tls_config(&inputs, None, Some(&ocsp_path), &policy, 30, 0, &[])
        .expect("valid staple is admitted");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.serial = OTHER_SERIAL;
    std::fs::write(&ocsp_path, builder.build()).expect("rewrite ocsp");
    let error =
        load_gateway_multi_cert_tls_config(&inputs, None, Some(&ocsp_path), &policy, 30, 0, &[])
            .expect_err("wrong-certificate staple is refused");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("rejected"), "{rendered}");
}

// ── Serving-path proof (issue #4300) ───────────────────────────────────────
//
// The load-path tests above prove which responses are *accepted*. These prove
// that an accepted response is actually attached to the certificate the
// protocol stacks serve, for the single-certificate frontend and for the
// single-entry SNI frontend, and that it survives the shared H1/H2
// `rustls::ServerConfig`.
//
// The proof is a real in-memory TLS handshake — no sockets, no runtime, no
// timers — whose client certificate verifier records the `ocsp_response`
// rustls delivered alongside the certificate. That is what a client sees, as
// opposed to a field the test set itself. The HTTP/3 half of this contract is
// proven where the conversion lives, in `src/http3/server.rs`
// (`h3_ocsp_staple_tests`): `build_h3_rustls_server_config` is module-private,
// and the assertion there is that the converted config carries this same
// resolver and still serves these same bytes.

/// Records the staple rustls handed the client verifier.
#[derive(Debug)]
struct StapleRecordingVerifier {
    observed: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for StapleRecordingVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.observed.lock().expect("staple slot") = Some(ocsp_response.to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Complete an in-memory handshake against `server_config`, offering `alpn` and
/// the SNI name `server_name`, and return the staple the client observed. An
/// absent staple is an empty slice.
fn served_staple(
    server_config: Arc<rustls::ServerConfig>,
    server_name: &str,
    alpn: &[u8],
) -> Vec<u8> {
    ensure_crypto_provider();
    let observed = Arc::new(std::sync::Mutex::new(None));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(StapleRecordingVerifier {
            observed: Arc::clone(&observed),
            provider,
        }))
        .with_no_client_auth();
    client_config.alpn_protocols = vec![alpn.to_vec()];

    let name =
        rustls::pki_types::ServerName::try_from(server_name.to_string()).expect("test server name");
    let mut client =
        rustls::ClientConnection::new(Arc::new(client_config), name).expect("client connection");
    let mut server = rustls::ServerConnection::new(server_config).expect("server connection");

    for _ in 0..32 {
        let mut to_server = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut to_server).expect("client write");
        }
        let mut records = to_server.as_slice();
        while !records.is_empty() {
            let read = server.read_tls(&mut records).expect("server read");
            assert!(read > 0, "server TLS reader must make progress");
            server.process_new_packets().expect("server process");
        }

        let mut to_client = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut to_client).expect("server write");
        }
        let mut records = to_client.as_slice();
        while !records.is_empty() {
            let read = client.read_tls(&mut records).expect("client read");
            assert!(read > 0, "client TLS reader must make progress");
            client.process_new_packets().expect("client process");
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            return observed
                .lock()
                .expect("staple slot")
                .clone()
                .expect("the client verifier must have run");
        }
    }
    panic!("in-memory TLS handshake did not converge");
}

#[test]
fn the_single_certificate_frontend_serves_the_validated_staple_on_h1_and_h2() {
    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    let valid = ResponseBuilder::new(&pki, now()).build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &valid);
    let policy = tls_policy();

    let candidate = load_frontend_tls_candidate_from_paths(
        &cert_path,
        &key_path,
        None,
        Some(&ocsp_path),
        false,
        &policy,
        30,
        30,
        &[],
        None,
    )
    .expect("valid staple is admitted");

    // One `ServerConfig` backs both HTTP/1.1 and HTTP/2 on this listener, so
    // the staple has to reach a client under either negotiated protocol.
    for alpn in [&b"h2"[..], &b"http/1.1"[..]] {
        assert_eq!(
            served_staple(Arc::clone(&candidate.config), "localhost", alpn),
            valid,
            "the served certificate must carry the validated staple under ALPN {:?}",
            std::str::from_utf8(alpn).expect("ascii alpn")
        );
    }

    // The negative half: with no configured source the same material serves no
    // staple at all, so the assertion above cannot be met by a default.
    let unstapled = load_frontend_tls_candidate_from_paths(
        &cert_path,
        &key_path,
        None,
        None,
        false,
        &policy,
        30,
        30,
        &[],
        None,
    )
    .expect("load without a staple");
    assert!(
        served_staple(unstapled.config, "localhost", b"h2").is_empty(),
        "a certificate loaded without an OCSP source must serve no staple"
    );
}

#[test]
fn the_single_entry_sni_frontend_serves_the_validated_staple() {
    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    let valid = ResponseBuilder::new(&pki, now()).build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &valid);
    let policy = tls_policy();

    let inputs = vec![GatewayCertificateInput {
        cert_source: cert_path.clone(),
        key_source: key_path.clone(),
        hostname: Some("localhost".to_string()),
        identity: "ns/gw/listener".to_string(),
        is_default: true,
    }];

    let config =
        load_gateway_multi_cert_tls_config(&inputs, None, Some(&ocsp_path), &policy, 30, 0, &[])
            .expect("valid staple is admitted");
    assert_eq!(
        served_staple(config, "localhost", b"h2"),
        valid,
        "the SNI-selected certificate must carry the validated staple"
    );

    // A staple is bound to one certificate, so a data plane serving several
    // certificates staples it to none — and must not staple it to the entry
    // that happens to match the SNI name either.
    let multi = vec![
        inputs[0].clone(),
        pki_second_certificate(dir.path(), "other.localhost"),
    ];
    let multi_config =
        load_gateway_multi_cert_tls_config(&multi, None, Some(&ocsp_path), &policy, 30, 0, &[])
            .expect("a multi-certificate data plane still loads");
    assert!(
        served_staple(multi_config, "localhost", b"h2").is_empty(),
        "a multi-certificate data plane must staple the response to no certificate"
    );
}

/// A second, unrelated self-signed certificate/key pair on disk, as a Gateway
/// certificate input. Used to make the data plane multi-certificate.
fn pki_second_certificate(dir: &std::path::Path, hostname: &str) -> GatewayCertificateInput {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key pair");
    let params = rcgen::CertificateParams::new(vec![hostname.to_string()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-signed");
    let cert_path = dir.join(format!("{hostname}.crt"));
    let key_path = dir.join(format!("{hostname}.key"));
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    GatewayCertificateInput {
        cert_source: cert_path.to_string_lossy().into_owned(),
        key_source: key_path.to_string_lossy().into_owned(),
        hostname: Some(hostname.to_string()),
        identity: format!("ns/gw/{hostname}"),
        is_default: false,
    }
}

#[test]
fn a_refused_staple_never_reaches_a_serving_configuration() {
    // Fail-closed, stated as a serving property rather than a loader one: for
    // each rejected shape there is no `ServerConfig` at all, so there is
    // nothing that could serve those bytes.
    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    let valid = ResponseBuilder::new(&pki, now()).build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &valid);
    let policy = tls_policy();

    let mut revoked = ResponseBuilder::new(&pki, now());
    revoked.status = Status::Revoked;
    let mut wrong_certificate = ResponseBuilder::new(&pki, now());
    wrong_certificate.serial = OTHER_SERIAL;
    let mut corrupt = ResponseBuilder::new(&pki, now());
    corrupt.corrupt_signature = true;

    for rejected in [
        revoked.build(),
        wrong_certificate.build(),
        corrupt.build(),
        vec![1, 2, 3],
    ] {
        std::fs::write(&ocsp_path, &rejected).expect("rewrite ocsp");
        let rebuilt = load_frontend_tls_candidate_from_paths(
            &cert_path,
            &key_path,
            None,
            Some(&ocsp_path),
            false,
            &policy,
            30,
            30,
            &[],
            None,
        );
        assert!(
            rebuilt.is_err(),
            "a refused staple must not produce a servable configuration"
        );
    }
}

// ── FIPS admission on the OCSP binding path (issue #4300) ──────────────────
//
// `x509_parser::verify::verify_signature` — which verifies the leaf-to-issuer
// proof, the delegate-to-issuer proof, and the `BasicOCSPResponse` signature —
// supports `RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY` and Ed25519. Both are
// outside the contract in `docs/fips.md`, and the SHA-1 arm additionally drops
// the RSA modulus floor to 1024 bits. Certificates carried in `certs` are also
// never seen by `parse_pem_certificate_bundle`, where Ferrum's certificate
// key-form admission lives.
//
// `OcspCryptoPolicy` is the seam. These tests drive the enforced profile
// explicitly, because `fips::is_enforcing()` can never be true on the
// `crypto-ring` build the test suite runs (an enforce request fails closed at
// bootstrap on such a build), so a policy read from that global would be
// untestable here.

/// sha1WithRSAEncryption (1.2.840.113549.1.1.5).
const OID_SHA1_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];

/// Assert a diagnostic is the FIPS admission refusal rather than some later
/// failure that happens to also be an error.
fn assert_fips_refusal(error: &str) {
    assert!(
        error.contains("FIPS mode is enforced"),
        "expected a FIPS admission refusal, got: {error}"
    );
}

fn assert_not_a_fips_refusal(error: &str) {
    assert!(
        !error.contains("FIPS mode is enforced"),
        "the FIPS gate must not be what refused this: {error}"
    );
}

#[test]
fn an_ordinary_ecdsa_response_is_still_admitted_under_fips_enforcement() {
    // The interoperability half of the contract, and the one that pins the
    // identifier carve-out: the default fixture's `CertID` is hashed with
    // SHA-1, which RFC 6960 defines as a lookup key rather than a signature
    // digest and which enforcement therefore keeps admitting.
    let pki = build_pki();
    let response = ResponseBuilder::new(&pki, now()).build();
    validate_stapled_response_at_with_policy(
        &response,
        &chain(&pki),
        now(),
        OcspCryptoPolicy::FipsEnforced,
    )
    .expect("an ECDSA-P256/SHA-256 response with a SHA-1 CertID stays admitted under enforcement");
    validate_structure_with_policy(&response, OcspCryptoPolicy::FipsEnforced)
        .expect("and is admissible at the certificate-independent admin boundary");
}

#[test]
fn a_sha256_cert_id_is_also_admitted_under_fips_enforcement() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.hash_oid = OID_SHA256;
    let response = builder.build();
    validate_stapled_response_at_with_policy(
        &response,
        &chain(&pki),
        now(),
        OcspCryptoPolicy::FipsEnforced,
    )
    .expect("a SHA-256 CertID is admitted under enforcement");
}

#[test]
fn a_sha1_rsa_responder_signature_is_refused_under_fips_enforcement() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_SHA1_RSA;
    // RSA PKCS#1 requires the canonical NULL, so this fixture is structurally
    // valid and fails only on the algorithm itself.
    builder.signature_algorithm_parameters = Some(der_null());
    let response = builder.build();

    let error = validate_stapled_response_at_with_policy(
        &response,
        &chain(&pki),
        now(),
        OcspCryptoPolicy::FipsEnforced,
    )
    .expect_err("SHA-1 RSA signatures are refused while FIPS mode is enforced");
    assert_fips_refusal(&error);
    // The refusal is at the grammar, so the admin boundary cannot store it
    // either.
    let structural = validate_structure_with_policy(&response, OcspCryptoPolicy::FipsEnforced)
        .expect_err("a SHA-1 RSA response cannot be stored under enforcement");
    assert_fips_refusal(&structural);

    // Outside enforcement nothing changed: the same response reaches signature
    // verification, which fails for an unrelated reason (an RSA signature
    // algorithm over an EC key), and the structural pass still admits it.
    let interoperable = validate_stapled_response_at_with_policy(
        &response,
        &chain(&pki),
        now(),
        OcspCryptoPolicy::Interoperable,
    )
    .expect_err("the fixture is still not a verifiable signature");
    assert_not_a_fips_refusal(&interoperable);
    validate_structure_with_policy(&response, OcspCryptoPolicy::Interoperable)
        .expect("ordinary deployments keep admitting SHA-1 responder signatures structurally");
}

#[test]
fn an_ed25519_responder_signature_is_refused_under_fips_enforcement() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_ED25519;
    let response = builder.build();

    let error = validate_stapled_response_at_with_policy(
        &response,
        &chain(&pki),
        now(),
        OcspCryptoPolicy::FipsEnforced,
    )
    .expect_err("Ed25519 is refused while FIPS mode is enforced");
    assert_fips_refusal(&error);

    let interoperable = validate_stapled_response_at_with_policy(
        &response,
        &chain(&pki),
        now(),
        OcspCryptoPolicy::Interoperable,
    )
    .expect_err("the fixture is still not a verifiable Ed25519 signature");
    assert_not_a_fips_refusal(&interoperable);
}

#[test]
fn an_approved_rsa_signature_algorithm_is_not_what_the_fips_gate_refuses() {
    // The discriminator for the test above: the same fixture shape with
    // sha256WithRSAEncryption passes the algorithm gate and fails later, so the
    // SHA-1 refusal is about SHA-1 and not about "RSA over an EC key".
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_oid = OID_SHA256_RSA;
    builder.signature_algorithm_parameters = Some(der_null());
    let response = builder.build();

    let error = validate_stapled_response_at_with_policy(
        &response,
        &chain(&pki),
        now(),
        OcspCryptoPolicy::FipsEnforced,
    )
    .expect_err("the fixture is still not a verifiable signature");
    assert_not_a_fips_refusal(&error);
    validate_structure_with_policy(&response, OcspCryptoPolicy::FipsEnforced)
        .expect("sha256WithRSAEncryption is admitted by the algorithm gate");
}

/// A self-signed Ed25519 certificate: an approved-looking responder that
/// carries a key form `fips::keys` refuses, and that
/// `parse_pem_certificate_bundle` never sees because it arrives inside the OCSP
/// response rather than in the served chain.
fn ed25519_certificate() -> Vec<u8> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum OCSP Ed25519 Responder");
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::OcspSigning);
    let cert = params.self_signed(&key_pair).expect("self-signed");
    cert.der().to_vec()
}

#[test]
fn an_embedded_responder_certificate_with_a_non_approved_key_is_refused_under_fips_enforcement() {
    let pki = build_pki();
    let ed25519_der = ed25519_certificate();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.embedded_certs = vec![ed25519_der.as_slice()];
    let response = builder.build();

    // The response is signed by the issuing CA directly, so the carried
    // certificate is never *used*. It is still admitted or refused, because a
    // certificate this pass lets through is one a later loosening could reach.
    let error = validate_stapled_response_at_with_policy(
        &response,
        &chain(&pki),
        now(),
        OcspCryptoPolicy::FipsEnforced,
    )
    .expect_err("an embedded Ed25519 responder certificate is refused under enforcement");
    assert_fips_refusal(&error);
    assert!(
        error.contains("OCSP responder certificate"),
        "the diagnostic must name the surface it refused: {error}"
    );
    // No certificate bytes, subject names, or response bytes leak.
    assert!(!error.contains("BEGIN CERTIFICATE"), "{error}");
    assert!(!error.contains("Ferrum OCSP Ed25519 Responder"), "{error}");

    let structural = validate_structure_with_policy(&response, OcspCryptoPolicy::FipsEnforced)
        .expect_err("nor can it be stored through the admin boundary");
    assert_fips_refusal(&structural);

    // Outside enforcement the unused certificate is admitted exactly as before.
    validate_stapled_response_at_with_policy(
        &response,
        &chain(&pki),
        now(),
        OcspCryptoPolicy::Interoperable,
    )
    .expect("ordinary deployments keep accepting an unused carried certificate");
}

#[test]
fn an_approved_embedded_delegate_still_signs_under_fips_enforcement() {
    // The interoperability control for the test above: a P-256 delegate with
    // the OCSP-signing EKU passes both the key-form gate and the signature
    // algorithm gate, so enforcement does not break delegated responders.
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.delegate_der.as_slice();
    builder.signing_key = &pki.delegate_key;
    builder.embedded_certs = vec![pki.delegate_der.as_slice()];
    let response = builder.build();

    let acceptance = validate_stapled_response_at_with_policy(
        &response,
        &chain(&pki),
        now(),
        OcspCryptoPolicy::FipsEnforced,
    )
    .expect("an approved delegated responder is admitted under enforcement");
    assert!(acceptance.delegated_responder);
}

// ── Runtime staple re-check (issue #4505, item 4) ──────────────────────────

/// A staple that has reached its `nextUpdate` while the gateway runs is
/// retired by the periodic re-check, and the retirement reaches the wire.
///
/// Serving an expired response is strictly worse than serving none: a client
/// that enforces staple validity aborts the handshake on it, whereas an absent
/// staple falls back to that client's own revocation behaviour. Before this,
/// nothing revisited an accepted staple — without
/// `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` the same bytes were served
/// forever, and with live reload only a *source byte change* could replace
/// them.
#[test]
fn the_periodic_recheck_drops_a_staple_that_reached_next_update() {
    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    // A short-lived staple: valid now, expired one hour from now.
    let issued_at = now();
    let expires_at = issued_at + 3_600;
    let mut builder = ResponseBuilder::new(&pki, issued_at);
    builder.this_update = issued_at - 60;
    builder.next_update = Some(expires_at);
    let staple = builder.build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &staple);
    let policy = tls_policy();

    let candidate = load_frontend_tls_candidate_from_paths(
        &cert_path,
        &key_path,
        None,
        Some(&ocsp_path),
        false,
        &policy,
        30,
        // Warning window off, so this case is only about the drop.
        0,
        &[],
        None,
    )
    .expect("a staple inside its window is admitted");

    assert_eq!(
        served_staple(Arc::clone(&candidate.config), "localhost", b"h2"),
        staple,
        "the accepted staple must be served before nextUpdate"
    );

    // One second before the deadline nothing changes: a re-check must not
    // retire material that is still valid.
    let kept = ferrum_edge::tls::ocsp_recheck::run_recheck_at_scoped(
        expires_at - 1,
        Some(ocsp_path.as_str()),
    );
    assert_eq!(kept.dropped, 0, "a staple inside its window is kept");
    assert_eq!(kept.tracked, 1, "and stays tracked for the next pass");
    assert_eq!(
        served_staple(Arc::clone(&candidate.config), "localhost", b"h2"),
        staple,
        "a kept staple keeps reaching the wire"
    );

    // At the deadline it is retired, on the very `ServerConfig` the listener
    // already holds — no rebuild, so this works with live reload off.
    let dropped =
        ferrum_edge::tls::ocsp_recheck::run_recheck_at_scoped(expires_at, Some(ocsp_path.as_str()));
    assert_eq!(dropped.dropped, 1, "the expired staple is dropped");
    assert_eq!(
        dropped.tracked, 0,
        "and is no longer tracked: a refreshed response arrives as a new registration"
    );
    assert!(
        served_staple(Arc::clone(&candidate.config), "localhost", b"h2").is_empty(),
        "the served certificate must carry no staple after the re-check"
    );

    // Idempotent: a second pass has nothing left to do.
    let again = ferrum_edge::tls::ocsp_recheck::run_recheck_at_scoped(
        expires_at + 86_400,
        Some(ocsp_path.as_str()),
    );
    assert_eq!(again.dropped, 0);
}

/// The drop is a serving-state fact the TLS inventory has to report: the
/// operator's stale bytes are still on disk, so reading the source would keep
/// advertising a deadline for material nothing staples. Because the
/// `ferrum_tls_revocation_expiry_seconds{kind="ocsp"}` row is derived from
/// `TlsInventoryEntry::next_update`, clearing that field is also what makes the
/// row disappear.
#[test]
fn a_dropped_staple_is_reported_by_the_tls_inventory_without_a_deadline() {
    use ferrum_edge::tls::inventory::{InventoryScope, TlsInventory, TlsInventoryState};

    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    let issued_at = now();
    let expires_at = issued_at + 3_600;
    let mut builder = ResponseBuilder::new(&pki, issued_at);
    builder.this_update = issued_at - 60;
    builder.next_update = Some(expires_at);
    let staple = builder.build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &staple);
    let policy = tls_policy();

    let env_config = EnvConfig {
        frontend_tls_cert_path: Some(cert_path.clone()),
        frontend_tls_key_path: Some(key_path.clone()),
        frontend_tls_ocsp_response_source: Some(ocsp_path.clone()),
        ..EnvConfig::default()
    };

    let _candidate = load_frontend_tls_candidate_from_paths(
        &cert_path,
        &key_path,
        None,
        Some(&ocsp_path),
        false,
        &policy,
        30,
        0,
        &[],
        None,
    )
    .expect("a staple inside its window is admitted");

    let ocsp_entry = |inventory: &TlsInventory| {
        inventory
            .entries
            .iter()
            .find(|entry| entry.material_kind == "ocsp")
            .cloned()
            .expect("the configured OCSP source has an inventory entry")
    };

    let before = ocsp_entry(&TlsInventory::collect_with_scope(
        Some(&env_config),
        None,
        InventoryScope::Full,
    ));
    assert!(matches!(before.state, TlsInventoryState::Loaded));
    assert_eq!(
        before.next_update.map(|at| at.timestamp()),
        Some(expires_at),
        "a served staple reports its deadline"
    );

    assert_eq!(
        ferrum_edge::tls::ocsp_recheck::run_recheck_at_scoped(expires_at, Some(ocsp_path.as_str()))
            .dropped,
        1
    );

    let after = ocsp_entry(&TlsInventory::collect_with_scope(
        Some(&env_config),
        None,
        InventoryScope::Full,
    ));
    assert!(
        matches!(after.state, TlsInventoryState::Invalid),
        "a retired staple is not a healthy entry: {:?}",
        after.state
    );
    assert!(
        after
            .error
            .as_deref()
            .is_some_and(|error| error.contains("dropped at runtime")),
        "the entry must say why: {:?}",
        after.error
    );
    assert!(
        after.next_update.is_none() && after.days_until_next_update.is_none(),
        "no deadline may be reported for material that is no longer stapled"
    );
}

// ── Gateway multi-certificate enrolment (issue #4773) ──────────────────────

/// The Gateway-API multi-certificate frontend is enrolled in the same
/// re-check as the single-certificate one.
///
/// It validated a staple and recorded its `nextUpdate` but registered with
/// nothing, so no code path could retire the response: the listener kept
/// stapling a "good" assertion past the end of its validity window, for a
/// certificate that may since have been revoked. Clients that enforce staple
/// freshness abort such a handshake; clients that do not accept the stale
/// assertion. The single-certificate loader has been enrolled since issue
/// #4505 item 4 — this is that same contract on its sibling certificate
/// source (refs #4792).
#[test]
fn the_periodic_recheck_drops_a_gateway_multi_cert_staple_that_reached_next_update() {
    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    // One captured reference instant for the whole fixture. Reading the clock
    // again below would let a second boundary put the expected deadline one
    // second ahead of the staple's own embedded timestamp (PR #4875).
    let issued_at = now();
    let expires_at = issued_at + 3_600;
    let mut builder = ResponseBuilder::new(&pki, issued_at);
    builder.this_update = issued_at - 60;
    builder.next_update = Some(expires_at);
    let staple = builder.build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &staple);
    let policy = tls_policy();

    let inputs = vec![GatewayCertificateInput {
        cert_source: cert_path.clone(),
        key_source: key_path.clone(),
        hostname: Some("localhost".to_string()),
        identity: "ns/gw/listener".to_string(),
        is_default: true,
    }];

    let config = load_gateway_multi_cert_tls_config(
        &inputs,
        None,
        Some(&ocsp_path),
        &policy,
        30,
        // Warning window off, so this case is only about the drop.
        0,
        &[],
    )
    .expect("a staple inside its window is admitted");

    assert_eq!(
        served_staple(Arc::clone(&config), "localhost", b"h2"),
        staple,
        "the SNI-selected certificate must serve the staple before nextUpdate"
    );
    // The same credential is reachable through the fallback slot as well, so
    // an unindexed name observes the staple too.
    assert_eq!(
        served_staple(Arc::clone(&config), "unmatched.example.com", b"h2"),
        staple,
        "the fallback candidate must serve the staple before nextUpdate"
    );

    // Control: one second before the deadline the pass changes nothing.
    let kept = ferrum_edge::tls::ocsp_recheck::run_recheck_at_scoped(
        expires_at - 1,
        Some(ocsp_path.as_str()),
    );
    assert_eq!(kept.dropped, 0, "a staple inside its window is kept");
    assert_eq!(
        kept.tracked, 1,
        "the Gateway multi-certificate frontend must be tracked at all"
    );
    assert_eq!(
        served_staple(Arc::clone(&config), "localhost", b"h2"),
        staple,
        "a kept staple keeps reaching the wire"
    );
    assert!(
        ferrum_edge::tls::ocsp_recheck::dropped_staple_next_update(ocsp_path.as_str()).is_none(),
        "nothing may be reported retired while the staple is still served"
    );

    // At the deadline it is retired on the very `ServerConfig` the listener
    // already holds: a Gateway snapshot is not rebuilt without live reload, so
    // the retirement has to happen inside the resolver.
    let dropped =
        ferrum_edge::tls::ocsp_recheck::run_recheck_at_scoped(expires_at, Some(ocsp_path.as_str()));
    assert_eq!(dropped.dropped, 1, "the expired staple is dropped");
    assert_eq!(
        dropped.tracked, 0,
        "and is no longer tracked: a refreshed response arrives as a new registration"
    );
    assert!(
        served_staple(Arc::clone(&config), "localhost", b"h2").is_empty(),
        "the SNI-selected certificate must carry no staple after the re-check"
    );
    assert!(
        served_staple(Arc::clone(&config), "unmatched.example.com", b"h2").is_empty(),
        "the fallback candidate must be retired too, not only the indexed name"
    );
    assert_eq!(
        ferrum_edge::tls::ocsp_recheck::dropped_staple_next_update(ocsp_path.as_str()),
        Some(expires_at),
        "the retirement is reported so the TLS inventory stops advertising the deadline"
    );

    // Idempotent: a second pass has nothing left to do.
    let again = ferrum_edge::tls::ocsp_recheck::run_recheck_at_scoped(
        expires_at + 86_400,
        Some(ocsp_path.as_str()),
    );
    assert_eq!(again.dropped, 0);
}

/// A Gateway staple comfortably inside its window survives every re-check the
/// gateway performs while it stays valid, and keeps being served.
///
/// The control for the case above: the retirement must be driven by
/// `nextUpdate` and nothing else. A pass that dropped a healthy staple would
/// silently remove the freshness assertion stapling exists to provide.
#[test]
fn the_periodic_recheck_retains_a_fresh_gateway_multi_cert_staple() {
    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    let issued_at = now();
    let expires_at = issued_at + 30 * 86_400;
    let mut builder = ResponseBuilder::new(&pki, issued_at);
    builder.this_update = issued_at - 60;
    builder.next_update = Some(expires_at);
    let staple = builder.build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &staple);
    let policy = tls_policy();

    let inputs = vec![GatewayCertificateInput {
        cert_source: cert_path.clone(),
        key_source: key_path.clone(),
        hostname: Some("localhost".to_string()),
        identity: "ns/gw/listener".to_string(),
        is_default: true,
    }];

    let config =
        load_gateway_multi_cert_tls_config(&inputs, None, Some(&ocsp_path), &policy, 30, 0, &[])
            .expect("a fresh staple is admitted");

    for at in [issued_at, issued_at + 86_400, expires_at - 1] {
        let outcome =
            ferrum_edge::tls::ocsp_recheck::run_recheck_at_scoped(at, Some(ocsp_path.as_str()));
        assert_eq!(outcome.dropped, 0, "a fresh staple must not be retired");
        assert_eq!(
            outcome.tracked, 1,
            "and must stay tracked for the next pass"
        );
    }
    assert_eq!(
        served_staple(Arc::clone(&config), "localhost", b"h2"),
        staple,
        "a fresh staple keeps reaching the wire across re-check passes"
    );
    assert!(
        ferrum_edge::tls::ocsp_recheck::dropped_staple_next_update(ocsp_path.as_str()).is_none(),
        "a retained staple must not be reported as retired"
    );
}

/// Enrolment is a shared contract, not a per-loader habit.
///
/// Issue #4773 happened because acceptance was written twice and enrolment
/// once. Validation, the acceptance record, and registration now live in one
/// helper in `crate::tls::ocsp_recheck`, and `register_stapled_response` is
/// private to that module, so a third certificate source cannot validate a
/// staple and quietly skip the machinery that retires it (refs #4792).
#[test]
fn every_certificate_source_accepts_a_staple_through_the_shared_helper() {
    let recheck = include_str!("../../../src/tls/ocsp_recheck.rs");
    assert!(
        recheck.contains("\nfn register_stapled_response("),
        "registration must stay private to the re-check module so `enroll` is the only way in"
    );

    for (path, source) in [
        ("src/tls/mod.rs", include_str!("../../../src/tls/mod.rs")),
        (
            "src/tls/multi_cert.rs",
            include_str!("../../../src/tls/multi_cert.rs"),
        ),
    ] {
        assert!(
            source.contains("accept_stapled_response("),
            "{path} must accept a staple through the shared helper"
        );
        assert!(
            !source.contains("ocsp::validate_stapled_response("),
            "{path} must not validate a staple outside the shared helper: that is exactly how a \
             certificate source ends up serving one nothing can retire"
        );
        assert!(
            source.contains(".enroll(&"),
            "{path} must enrol the accepted staple with the resolver that serves it"
        );
    }
}
