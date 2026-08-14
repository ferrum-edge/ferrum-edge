//! Mutual TLS (mTLS) client certificate authentication plugin.
//!
//! Extracts the client certificate from the TLS handshake and matches a
//! configurable certificate field (Subject CN, OU, O, SAN DNS/Email,
//! fingerprint, or serial) against the consumer's `mtls_auth.identity`
//! credential for O(1) lookup.
//!
//! Optionally validates the certificate issuer against cryptographically pinned
//! per-proxy CA certificates (defense-in-depth on top of the TLS layer's CA
//! verification).

use crate::fips::approved::Sha256;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tracing::debug;
use x509_parser::prelude::*;

use crate::consumer_index::ConsumerIndex;

use super::utils::auth_flow::{self, AuthMechanism, ExtractedCredential, VerifyOutcome};
use super::{PluginResult, RequestContext, StreamConnectionContext};

/// Supported certificate fields for consumer identity matching.
#[derive(Debug, Clone, Copy)]
enum CertField {
    /// Subject Common Name (CN)
    SubjectCn,
    /// Subject Organizational Unit (OU)
    SubjectOu,
    /// Subject Organization (O)
    SubjectO,
    /// First DNS Subject Alternative Name
    SanDns,
    /// First Email Subject Alternative Name
    SanEmail,
    /// SHA-256 fingerprint of the DER-encoded certificate (lowercase hex)
    FingerprintSha256,
    /// Certificate serial number as lowercase hex of the DER integer value
    /// bytes, no separators, DER sign padding removed (i.e. the lowercase of
    /// `openssl x509 -serial` output).
    Serial,
}

static NEXT_MTLS_AUTH_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

/// Client-visible and log-safe reason when optional `allowed_issuers` filtering
/// rejects a peer certificate. Must never interpolate issuer DN/CN or other
/// certificate identity material (issue #3816).
const ALLOWED_ISSUER_MISMATCH: &str = "Certificate issuer does not match any allowed issuer";

/// Certificate-invariant temporal window retained beside a cached identity.
///
/// Only the two canonical Unix timestamps are kept. No DER, DN, SAN, serial, or
/// fingerprint reaches this type, and neither value is ever logged, exported as
/// a metric label, or echoed to a client.
#[derive(Debug, Clone, Copy)]
struct CertValidityWindow {
    not_before_unix: i64,
    not_after_unix: i64,
}

impl CertValidityWindow {
    /// Parse the leaf's validity interval, failing closed on anything that
    /// cannot be represented as a coherent window.
    ///
    /// `x509_parser` returns `i64` seconds, so an out-of-range or malformed
    /// ASN.1 time surfaces as a nonsensical value rather than a panic. An
    /// inverted interval (`not_after < not_before`) is rejected outright: such
    /// a certificate can never be valid, and admitting it would make the
    /// per-request check depend on which bound is compared first.
    fn from_certificate(cert: &X509Certificate<'_>) -> Option<Self> {
        let validity = cert.validity();
        let not_before_unix = validity.not_before.timestamp();
        let not_after_unix = validity.not_after.timestamp();
        if not_after_unix < not_before_unix {
            return None;
        }
        Some(Self {
            not_before_unix,
            not_after_unix,
        })
    }

    /// Whether `now_unix` lies inside the closed interval. Both boundaries are
    /// inclusive, matching RFC 5280's "valid at" semantics and
    /// `x509_parser`'s own `Validity::is_valid_at`.
    fn contains(&self, now_unix: i64) -> bool {
        now_unix >= self.not_before_unix && now_unix <= self.not_after_unix
    }
}

#[derive(Debug)]
enum CertificateEvaluation {
    /// Certificate-invariant result: the extracted identity plus the leaf's
    /// authoritative validity window, and — once the first successful
    /// evaluation converts `notAfter` — the monotonic expiry that every later
    /// cache hit must return unchanged (issue #3816). Deliberately does NOT
    /// record "was valid when evaluated": the Unix window is re-checked on
    /// every request, but the monotonic Instant is captured once so a
    /// wall-clock rollback cannot recreate a later deadline.
    Identity {
        identity: String,
        validity: CertValidityWindow,
        monotonic_expiry: OnceLock<tokio::time::Instant>,
    },
    InvalidCertificate,
    Forbidden(String),
}

/// Connection-local cache for mTLS certificate evaluation.
///
/// HTTP/2 and HTTP/3 create one cache per transport connection and share it
/// across multiplexed request contexts. Entries are keyed by the concrete
/// `mtls_auth` plugin instance so different per-proxy certificate policies do
/// not reuse each other's decision. The common path is one lock-free ArcSwap
/// load plus a HashMap lookup; `OnceLock` serializes only the first evaluation
/// for a plugin/connection pair.
pub struct MtlsAuthConnectionCache {
    evaluations: ArcSwap<HashMap<u64, Arc<OnceLock<CertificateEvaluation>>>>,
    evaluation_count: AtomicUsize,
}

impl std::fmt::Debug for MtlsAuthConnectionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtlsAuthConnectionCache")
            .field("entries", &self.evaluations.load().len())
            .field("evaluation_count", &self.evaluation_count())
            .finish()
    }
}

impl Default for MtlsAuthConnectionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl MtlsAuthConnectionCache {
    pub fn new() -> Self {
        Self {
            evaluations: ArcSwap::from_pointee(HashMap::new()),
            evaluation_count: AtomicUsize::new(0),
        }
    }

    /// Number of certificate evaluations performed by this connection cache.
    /// Exposed for instrumentation-backed regression tests.
    pub fn evaluation_count(&self) -> usize {
        self.evaluation_count.load(Ordering::Relaxed)
    }

    fn evaluation_slot(&self, instance_id: u64) -> Arc<OnceLock<CertificateEvaluation>> {
        let mut current = self.evaluations.load();
        loop {
            if let Some(slot) = current.get(&instance_id) {
                return Arc::clone(slot);
            }

            let slot = Arc::new(OnceLock::new());
            let mut updated = current.as_ref().clone();
            updated.insert(instance_id, Arc::clone(&slot));
            let previous = self
                .evaluations
                .compare_and_swap(&*current, Arc::new(updated));
            if Arc::ptr_eq(&*current, &*previous) {
                return slot;
            }
            current = previous;
        }
    }
}

impl CertField {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "subject_cn" => Some(Self::SubjectCn),
            "subject_ou" => Some(Self::SubjectOu),
            "subject_o" => Some(Self::SubjectO),
            "san_dns" => Some(Self::SanDns),
            "san_email" => Some(Self::SanEmail),
            "fingerprint_sha256" => Some(Self::FingerprintSha256),
            "serial" => Some(Self::Serial),
            _ => None,
        }
    }
}

fn canonical_serial_bytes(raw_serial: &[u8]) -> &[u8] {
    if raw_serial.len() > 1 && raw_serial[0] == 0 && (raw_serial[1] & 0x80) != 0 {
        &raw_serial[1..]
    } else {
        raw_serial
    }
}

/// Per-proxy issuer filter: binds descriptive CA subject fields to a pinned CA key.
///
/// All specified fields must match (AND logic within a single filter).
/// Multiple filters in `allowed_issuers` are OR'd — any one matching is sufficient.
#[derive(Debug, Clone)]
struct IssuerFilter {
    /// Issuer Common Name (CN)
    cn: Option<String>,
    /// Issuer Organization (O)
    o: Option<String>,
    /// Issuer Organizational Unit (OU)
    ou: Option<String>,
    /// DER certificate that cryptographically pins this issuer. Keeping the
    /// certificate (rather than only its subject DN) also permits verification
    /// when a root trust anchor was omitted from the client-presented chain.
    ca_cert_der: Vec<u8>,
}

impl IssuerFilter {
    fn from_json(val: &Value, context: &str) -> Result<Self, String> {
        let obj = val
            .as_object()
            .ok_or_else(|| format!("mtls_auth: '{context}' entries must be objects, got: {val}"))?;
        for key in obj.keys() {
            if !matches!(key.as_str(), "cn" | "o" | "ou" | "ca_certificate_pem") {
                return Err(format!(
                    "mtls_auth: '{context}' contains unsupported issuer field '{key}'"
                ));
            }
        }
        let ca_certificate_pem = string_field(obj, "ca_certificate_pem", context)?.ok_or_else(|| {
            format!(
                "mtls_auth: '{context}.ca_certificate_pem' is required to cryptographically pin the issuer"
            )
        })?;
        Self::from_fields(
            string_field(obj, "cn", context)?,
            string_field(obj, "o", context)?,
            string_field(obj, "ou", context)?,
            parse_ca_certificate_pem(&ca_certificate_pem, context)?,
            context,
        )
    }

    fn from_fields(
        cn: Option<String>,
        o: Option<String>,
        ou: Option<String>,
        ca_cert_der: Vec<u8>,
        context: &str,
    ) -> Result<Self, String> {
        if cn.is_none() && o.is_none() && ou.is_none() {
            return Err(format!(
                "mtls_auth: '{context}' issuer filter must specify at least one field"
            ));
        }
        let filter = Self {
            cn,
            o,
            ou,
            ca_cert_der,
        };
        let (_, ca_cert) = X509Certificate::from_der(&filter.ca_cert_der).map_err(|_| {
            format!("mtls_auth: '{context}.ca_certificate_pem' is not a valid X.509 certificate")
        })?;
        if !filter.matches_name(ca_cert.subject()) {
            return Err(format!(
                "mtls_auth: '{context}' DN fields do not match ca_certificate_pem subject"
            ));
        }
        Ok(filter)
    }

    fn matches_name(&self, name: &X509Name<'_>) -> bool {
        if let Some(expected_cn) = &self.cn {
            let actual = name
                .iter_common_name()
                .next()
                .and_then(|attr| attr.as_str().ok());
            if actual != Some(expected_cn.as_str()) {
                return false;
            }
        }

        if let Some(expected_o) = &self.o {
            let actual = name
                .iter_by_oid(&oid_registry::OID_X509_ORGANIZATION_NAME)
                .next()
                .and_then(|attr| attr.as_str().ok());
            if actual != Some(expected_o.as_str()) {
                return false;
            }
        }

        if let Some(expected_ou) = &self.ou {
            let actual = name
                .iter_by_oid(&oid_registry::OID_X509_ORGANIZATIONAL_UNIT)
                .next()
                .and_then(|attr| attr.as_str().ok());
            if actual != Some(expected_ou.as_str()) {
                return false;
            }
        }

        true
    }
}

fn parse_ca_certificate_pem(pem: &str, context: &str) -> Result<Vec<u8>, String> {
    let items = rustls_pemfile::read_all(&mut Cursor::new(pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| format!("mtls_auth: '{context}.ca_certificate_pem' contains malformed PEM"))?;
    let [rustls_pemfile::Item::X509Certificate(certificate)] = items.as_slice() else {
        return Err(format!(
            "mtls_auth: '{context}.ca_certificate_pem' must contain exactly one certificate and no other PEM items"
        ));
    };
    let der = certificate.as_ref().to_vec();
    let (_, parsed) = X509Certificate::from_der(&der).map_err(|_| {
        format!("mtls_auth: '{context}.ca_certificate_pem' is not a valid X.509 certificate")
    })?;
    if !parsed.is_ca() {
        return Err(format!(
            "mtls_auth: '{context}.ca_certificate_pem' must contain a CA certificate"
        ));
    }
    if !parsed.validity().is_valid() {
        return Err(format!(
            "mtls_auth: '{context}.ca_certificate_pem' must be currently valid"
        ));
    }
    if !parsed
        .key_usage()
        .ok()
        .flatten()
        .is_some_and(|usage| usage.value.key_cert_sign())
    {
        return Err(format!(
            "mtls_auth: '{context}.ca_certificate_pem' keyUsage must include keyCertSign"
        ));
    }
    Ok(der)
}

/// Return true only for a currently valid certificate that can issue another
/// certificate in the pinned path. Requiring both extensions also fails closed
/// on malformed or duplicate extension encodings reported by x509-parser.
fn is_valid_ca_issuer(cert: &X509Certificate<'_>) -> bool {
    cert.validity().is_valid()
        && cert
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|constraints| constraints.value.ca)
        && cert
            .key_usage()
            .ok()
            .flatten()
            .is_some_and(|usage| usage.value.key_cert_sign())
}

/// mTLS authentication plugin.
///
/// Authenticates consumers by matching a configurable field from the client's
/// TLS certificate against consumer credentials. This operates on top of the
/// server's CA chain verification — the TLS handshake already validates the
/// certificate chain. This plugin provides an additional consumer-scoped
/// identity check with optional per-proxy CA filtering.
///
/// # Plugin Configuration
///
/// ```json
/// {
///   "cert_field": "subject_cn",
///   "allowed_issuers": [
///     {
///       "cn": "Internal Services CA",
///       "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
///     }
///   ],
///   "allowed_ca_fingerprints_sha256": [
///     "a1b2c3d4e5f6..."
///   ]
/// }
/// ```
///
/// ## Issuer Filtering
///
/// When `allowed_issuers` is set, each filter's DN fields identify the pinned CA
/// subject and the plugin cryptographically verifies a peer path to that
/// filter's `ca_certificate_pem`. DN labels alone never authorize a CA.
///
/// When `allowed_ca_fingerprints_sha256` is set, the plugin verifies that at
/// least one certificate in the client's chain (intermediate/CA certs sent
/// during the TLS handshake) has a matching SHA-256 fingerprint. Note: root
/// CAs are typically not included in the client's chain — `allowed_issuers`
/// can verify against its configured CA even when that CA is omitted.
///
/// When both are configured, both constraints must pass (AND logic).
///
/// Supported `cert_field` values:
/// - `subject_cn` (default) — Subject Common Name
/// - `subject_ou` — Subject Organizational Unit
/// - `subject_o` — Subject Organization
/// - `san_dns` — First DNS Subject Alternative Name
/// - `san_email` — First email Subject Alternative Name
/// - `fingerprint_sha256` — SHA-256 fingerprint (lowercase hex)
/// - `serial` — Certificate serial number as lowercase hex of the DER integer
///   value bytes, no separators, DER sign padding removed. Store the lowercase
///   of `openssl x509 -serial` output (e.g. `0a1b2c`, or `ab…` for serials
///   whose high bit required a DER sign pad).
///
/// # Consumer Credentials
///
/// Consumers authenticate via their `mtls_auth` credential:
/// ```json
/// {
///   "mtls_auth": [{ "identity": "client.example.com" }]
/// }
/// ```
pub struct MtlsAuth {
    instance_id: u64,
    cert_field: CertField,
    /// Optional per-proxy issuer DN filters (OR across filters, AND within).
    allowed_issuers: Vec<IssuerFilter>,
    /// Optional SHA-256 fingerprints of allowed CA/intermediate certificates.
    allowed_ca_fingerprints_sha256: HashSet<[u8; 32]>,
}

impl MtlsAuth {
    pub fn new(config: &Value) -> Result<Self, String> {
        validate_top_level_keys(config)?;
        let cert_field = parse_cert_field(config)?;
        let allowed_issuers = parse_allowed_issuers(config)?;
        let allowed_ca_fingerprints_sha256 = parse_allowed_ca_fingerprints(config)?;

        Ok(Self {
            instance_id: NEXT_MTLS_AUTH_INSTANCE_ID.fetch_add(1, Ordering::Relaxed),
            cert_field,
            allowed_issuers,
            allowed_ca_fingerprints_sha256,
        })
    }

    /// Returns true if any issuer/CA filtering is configured.
    fn has_issuer_constraints(&self) -> bool {
        !self.allowed_issuers.is_empty() || !self.allowed_ca_fingerprints_sha256.is_empty()
    }

    /// Verify the certificate's issuer against configured constraints.
    ///
    /// Returns Ok(()) if no constraints are configured or all pass.
    /// Returns Err(reason) if a constraint fails.
    fn verify_issuer_constraints(
        &self,
        _peer_cert: &X509Certificate<'_>,
        peer_cert_der: &[u8],
        chain_der: Option<&[Vec<u8>]>,
    ) -> Result<(), String> {
        // Each filter's DN attributes were bound to the pinned certificate's
        // subject at construction. Runtime authorization therefore depends on a
        // cryptographically verified path to that pinned CA, which may be the
        // immediate issuer, an intermediate, or a root. DN labels alone are not
        // unique CA identities.
        if !self.allowed_issuers.is_empty() {
            let chain = chain_der.unwrap_or(&[]);
            let matched = self.allowed_issuers.iter().any(|filter| {
                self.chain_reaches_pinned_ca(peer_cert_der, chain, filter.ca_cert_der.as_slice())
            });
            if !matched {
                return Err(ALLOWED_ISSUER_MISMATCH.to_string());
            }
        }

        // Check allowed_ca_fingerprints_sha256 against the chain certs
        if !self.allowed_ca_fingerprints_sha256.is_empty() {
            let chain = chain_der.unwrap_or(&[]);
            let matched = self
                .validated_issuer_chain(peer_cert_der, chain)
                .into_iter()
                .any(|cert_der| {
                    let digest = Sha256::digest(cert_der);
                    let mut fingerprint = [0u8; 32];
                    fingerprint.copy_from_slice(&digest);
                    self.allowed_ca_fingerprints_sha256.contains(&fingerprint)
                });
            if !matched {
                return Err(
                    "No certificate in the chain matches any allowed CA fingerprint".to_string(),
                );
            }
        }

        Ok(())
    }

    fn chain_reaches_pinned_ca<'a>(
        &self,
        leaf_der: &'a [u8],
        chain: &'a [Vec<u8>],
        pinned_ca_der: &[u8],
    ) -> bool {
        let Ok((_, leaf)) = X509Certificate::from_der(leaf_der) else {
            return false;
        };
        let Ok((_, pinned_ca)) = X509Certificate::from_der(pinned_ca_der) else {
            return false;
        };
        if !leaf.validity().is_valid() {
            return false;
        }

        // 0 = unseen, 1 = reachable and pending, 2 = processed. Reusing one
        // state vector as the work queue keeps path search iterative and
        // bounded to O(n^2), including alternate and cyclic presented chains.
        let mut states = vec![0u8; chain.len()];
        let mut current = leaf;
        loop {
            if is_valid_ca_issuer(&pinned_ca)
                && current.issuer() == pinned_ca.subject()
                && current
                    .verify_signature(Some(pinned_ca.public_key()))
                    .is_ok()
            {
                return true;
            }

            for (idx, cert_der) in chain.iter().enumerate() {
                if states[idx] != 0 {
                    continue;
                }
                let Ok((_, candidate)) = X509Certificate::from_der(cert_der) else {
                    continue;
                };
                if is_valid_ca_issuer(&candidate)
                    && candidate.subject() == current.issuer()
                    && current
                        .verify_signature(Some(candidate.public_key()))
                        .is_ok()
                {
                    states[idx] = 1;
                }
            }

            let Some(next_idx) = states.iter().position(|state| *state == 1) else {
                return false;
            };
            states[next_idx] = 2;
            let Ok((_, parsed)) = X509Certificate::from_der(&chain[next_idx]) else {
                continue;
            };
            current = parsed;
        }
    }

    fn validated_issuer_chain<'a>(
        &self,
        leaf_der: &'a [u8],
        chain: &'a [Vec<u8>],
    ) -> Vec<&'a [u8]> {
        let mut verified_chain = Vec::new();
        let Ok((_, mut current)) = X509Certificate::from_der(leaf_der) else {
            return verified_chain;
        };
        if !current.validity().is_valid() {
            return verified_chain;
        }

        let mut used = vec![false; chain.len()];
        loop {
            let mut next_idx = None;
            for (idx, cert_der) in chain.iter().enumerate() {
                if used[idx] {
                    continue;
                }
                let Ok((_, candidate)) = X509Certificate::from_der(cert_der) else {
                    continue;
                };
                if !is_valid_ca_issuer(&candidate) || candidate.subject() != current.issuer() {
                    continue;
                }
                if current
                    .verify_signature(Some(candidate.public_key()))
                    .is_ok()
                {
                    next_idx = Some(idx);
                    break;
                }
            }

            let Some(idx) = next_idx else {
                break;
            };
            used[idx] = true;
            verified_chain.push(chain[idx].as_slice());
            if let Ok((_, parsed)) = X509Certificate::from_der(&chain[idx]) {
                current = parsed;
            } else {
                break;
            }
        }

        verified_chain
    }

    /// Extract the configured field value from a parsed X.509 certificate.
    fn extract_cert_identity(
        &self,
        cert: &X509Certificate<'_>,
        der_bytes: &[u8],
    ) -> Result<String, String> {
        match &self.cert_field {
            CertField::SubjectCn => {
                let cn = cert
                    .subject()
                    .iter_common_name()
                    .next()
                    .and_then(|attr| attr.as_str().ok())
                    .ok_or_else(|| "No CN found in certificate subject".to_string())?;
                Ok(cn.to_string())
            }
            CertField::SubjectOu => {
                let ou = cert
                    .subject()
                    .iter_by_oid(&oid_registry::OID_X509_ORGANIZATIONAL_UNIT)
                    .next()
                    .and_then(|attr| attr.as_str().ok())
                    .ok_or_else(|| "No OU found in certificate subject".to_string())?;
                Ok(ou.to_string())
            }
            CertField::SubjectO => {
                let o = cert
                    .subject()
                    .iter_by_oid(&oid_registry::OID_X509_ORGANIZATION_NAME)
                    .next()
                    .and_then(|attr| attr.as_str().ok())
                    .ok_or_else(|| "No O found in certificate subject".to_string())?;
                Ok(o.to_string())
            }
            CertField::SanDns => {
                let san = cert
                    .extensions()
                    .iter()
                    .find_map(|ext| {
                        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension()
                        {
                            san.general_names.iter().find_map(|name| {
                                if let GeneralName::DNSName(dns) = name {
                                    Some(dns.to_ascii_lowercase())
                                } else {
                                    None
                                }
                            })
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| "No DNS SAN found in certificate".to_string())?;
                Ok(san)
            }
            CertField::SanEmail => {
                let email = cert
                    .extensions()
                    .iter()
                    .find_map(|ext| {
                        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension()
                        {
                            san.general_names.iter().find_map(|name| {
                                if let GeneralName::RFC822Name(email) = name {
                                    Some(email.to_string())
                                } else {
                                    None
                                }
                            })
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| "No email SAN found in certificate".to_string())?;
                Ok(email)
            }
            CertField::FingerprintSha256 => {
                Ok(super::utils::cert_hash::sha256_hex_lower(der_bytes))
            }
            // Render the serial from its DER INTEGER value bytes as lowercase
            // hex with no separators. `BigUint::to_str_radix(16)` strips
            // meaningful leading zero nibbles and can produce an odd-length
            // string, while `raw_serial()` includes a DER-only `00` sign pad
            // for positive values whose high bit is set. OpenSSL's `-serial`
            // output uses the value bytes without that sign pad.
            CertField::Serial => Ok(hex::encode(canonical_serial_bytes(cert.raw_serial()))),
        }
    }

    fn evaluate_client_cert(
        &self,
        cert_der: &[u8],
        chain_der: Option<&[Vec<u8>]>,
    ) -> CertificateEvaluation {
        let (_, parsed_cert) = match X509Certificate::from_der(cert_der) {
            Ok(parsed) => parsed,
            Err(e) => {
                debug!("mtls_auth: failed to parse certificate: {}", e);
                return CertificateEvaluation::InvalidCertificate;
            }
        };

        // Retain the leaf's authoritative validity window UNCONDITIONALLY,
        // independently of whether optional issuer/CA constraints are
        // configured (issue #3816). The default configuration previously
        // reached identity extraction without ever consulting the leaf's
        // temporal bounds, so a certificate that crossed `notAfter` after its
        // TLS handshake kept authorizing requests on the same connection.
        //
        // A malformed or inverted interval is not representable as a window and
        // fails closed here, before any identity is extracted.
        let Some(validity) = CertValidityWindow::from_certificate(&parsed_cert) else {
            debug!("mtls_auth: certificate validity interval is not usable");
            return CertificateEvaluation::InvalidCertificate;
        };

        if self.has_issuer_constraints()
            && let Err(reason) = self.verify_issuer_constraints(&parsed_cert, cert_der, chain_der)
        {
            debug!("mtls_auth: allowed issuer constraint failed");
            return CertificateEvaluation::Forbidden(
                serde_json::json!({ "error": reason }).to_string(),
            );
        }

        let identity = match self.extract_cert_identity(&parsed_cert, cert_der) {
            Ok(id) => id,
            Err(e) => {
                debug!("mtls_auth: failed to extract identity: {}", e);
                return CertificateEvaluation::InvalidCertificate;
            }
        };

        CertificateEvaluation::Identity {
            identity,
            validity,
            monotonic_expiry: OnceLock::new(),
        }
    }

    fn evaluation_outcome(
        &self,
        evaluation: &CertificateEvaluation,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let (identity, validity, monotonic_expiry) = match evaluation {
            CertificateEvaluation::Identity {
                identity,
                validity,
                monotonic_expiry,
            } => (identity, validity, monotonic_expiry),
            CertificateEvaluation::InvalidCertificate => {
                return VerifyOutcome::Invalid(r#"{"error":"Invalid client certificate"}"#.into());
            }
            CertificateEvaluation::Forbidden(body) => {
                return VerifyOutcome::Forbidden(body.clone());
            }
        };

        // Cheap per-request temporal check (issue #3816). The expensive X.509
        // parse, path verification, and identity extraction stay memoized per
        // plugin instance and transport connection, but "is this certificate
        // valid RIGHT NOW" is time-dependent and must never be cached: an H2 or
        // H3 connection multiplexes new request streams for a long time without
        // repeating the TLS handshake, and an H1 connection is reused for
        // keep-alive requests. Two integer comparisons per request.
        //
        // X.509 validity is defined against wall-clock time, so the first
        // successful evaluation still rejects an invalid or not-yet-valid leaf
        // here. The monotonic Instant captured below is what later cache hits
        // admit against: a wall-clock rollback cannot recreate a later deadline
        // from the retained Unix `notAfter`.
        let now_unix = x509_parser::time::ASN1Time::now().timestamp();
        if !validity.contains(now_unix) {
            // Fixed body. `notBefore`, `notAfter`, the observed time, the
            // identity, and the certificate are all withheld from the client.
            debug!("mtls_auth: client certificate is outside its validity interval");
            return VerifyOutcome::Invalid(
                r#"{"error":"Client certificate is not currently valid"}"#.into(),
            );
        }

        let credential_deadline = if let Some(&deadline) = monotonic_expiry.get() {
            // Cache hit: admit against the Instant captured at first success.
            // An already-elapsed bound is a fixed 401 — never a fresh conversion
            // that could land later after wall-clock rollback.
            if tokio::time::Instant::now() >= deadline {
                debug!("mtls_auth: client certificate is outside its validity interval");
                return VerifyOutcome::Invalid(
                    r#"{"error":"Client certificate is not currently valid"}"#.into(),
                );
            }
            deadline
        } else {
            // First successful evaluation: convert `notAfter` once. An
            // unrepresentable conversion fails closed and does not populate the
            // slot, so a later request retries rather than caching a bogus Instant.
            let Some(converted) =
                auth_flow::try_credential_deadline_from_unix_seconds(validity.not_after_unix, 0)
            else {
                debug!(
                    "mtls_auth: certificate expiry is not representable as a monotonic deadline"
                );
                return VerifyOutcome::Invalid(r#"{"error":"Invalid client certificate"}"#.into());
            };
            match monotonic_expiry.set(converted) {
                Ok(()) => converted,
                Err(_) => monotonic_expiry.get().copied().unwrap_or(converted),
            }
        };

        let consumer = if matches!(self.cert_field, CertField::SanDns) {
            consumer_index.find_by_mtls_dns_identity(identity)
        } else {
            consumer_index.find_by_mtls_identity(identity)
        };
        match consumer {
            // The authoritative certificate bound published on the shared
            // protocol-neutral contract. Cache hits return the Instant captured
            // above, never a newly derived later value.
            Some(consumer) => VerifyOutcome::consumer(consumer)
                .with_credential_deadline(Some(credential_deadline)),
            None => VerifyOutcome::ConsumerNotFound(
                r#"{"error":"No consumer found for client certificate"}"#.into(),
            ),
        }
    }

    fn verify_client_cert(
        &self,
        cert_der: &[u8],
        chain_der: Option<&[Vec<u8>]>,
        connection_cache: Option<&MtlsAuthConnectionCache>,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        if let Some(cache) = connection_cache {
            let slot = cache.evaluation_slot(self.instance_id);
            let evaluation = slot.get_or_init(|| {
                cache.evaluation_count.fetch_add(1, Ordering::Relaxed);
                self.evaluate_client_cert(cert_der, chain_der)
            });
            self.evaluation_outcome(evaluation, consumer_index)
        } else {
            let evaluation = self.evaluate_client_cert(cert_der, chain_der);
            self.evaluation_outcome(&evaluation, consumer_index)
        }
    }
}

fn validate_top_level_keys(config: &Value) -> Result<(), String> {
    if config.is_null() {
        return Ok(());
    }
    let obj = config
        .as_object()
        .ok_or_else(|| "mtls_auth: config must be an object".to_string())?;
    for key in obj.keys() {
        if !matches!(
            key.as_str(),
            "cert_field" | "allowed_issuers" | "allowed_ca_fingerprints_sha256"
        ) {
            return Err(format!(
                "mtls_auth: config contains unsupported field '{key}'"
            ));
        }
    }
    Ok(())
}

fn string_field(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    context: &str,
) -> Result<Option<String>, String> {
    let Some(value) = obj.get(key) else {
        return Ok(None);
    };
    let raw = value
        .as_str()
        .ok_or_else(|| format!("mtls_auth: '{context}.{key}' must be a string, got: {value}"))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("mtls_auth: '{context}.{key}' must not be empty"));
    }
    Ok(Some(trimmed.to_string()))
}

fn parse_cert_field(config: &Value) -> Result<CertField, String> {
    match config.get("cert_field") {
        None => Ok(CertField::SubjectCn),
        Some(Value::String(value)) => CertField::from_str(value).ok_or_else(|| {
            format!("mtls_auth: 'cert_field' must be a supported certificate field, got: {value:?}")
        }),
        Some(other) => Err(format!(
            "mtls_auth: 'cert_field' must be a string, got: {other}"
        )),
    }
}

fn parse_allowed_issuers(config: &Value) -> Result<Vec<IssuerFilter>, String> {
    let mut filters = Vec::new();

    if let Some(value) = config.get("allowed_issuers") {
        if value.is_null() {
            return Err("mtls_auth: 'allowed_issuers' must be an array, got: null".to_string());
        }
        let arr = value.as_array().ok_or_else(|| {
            format!("mtls_auth: 'allowed_issuers' must be an array, got: {value}")
        })?;
        if arr.is_empty() {
            return Err(
                "mtls_auth: 'allowed_issuers' must not be empty; omit the field to disable issuer filtering"
                    .to_string(),
            );
        }
        filters.reserve(arr.len());
        for (idx, entry) in arr.iter().enumerate() {
            filters.push(IssuerFilter::from_json(
                entry,
                &format!("allowed_issuers[{idx}]"),
            )?);
        }
    }

    Ok(filters)
}

fn parse_allowed_ca_fingerprints(config: &Value) -> Result<HashSet<[u8; 32]>, String> {
    let Some(value) = config.get("allowed_ca_fingerprints_sha256") else {
        return Ok(HashSet::new());
    };
    if value.is_null() {
        return Err(
            "mtls_auth: 'allowed_ca_fingerprints_sha256' must be an array, got: null".to_string(),
        );
    }

    let arr = value.as_array().ok_or_else(|| {
        format!("mtls_auth: 'allowed_ca_fingerprints_sha256' must be an array, got: {value}")
    })?;
    if arr.is_empty() {
        return Err(
            "mtls_auth: 'allowed_ca_fingerprints_sha256' must not be empty; omit the field to disable CA fingerprint filtering"
                .to_string(),
        );
    }
    let mut fingerprints = HashSet::with_capacity(arr.len());
    for (idx, entry) in arr.iter().enumerate() {
        let raw = entry.as_str().ok_or_else(|| {
            format!(
                "mtls_auth: 'allowed_ca_fingerprints_sha256[{idx}]' must be a string, got: {entry}"
            )
        })?;
        let trimmed = raw.trim();
        let decoded = hex::decode(trimmed).map_err(|_| {
            format!("mtls_auth: 'allowed_ca_fingerprints_sha256[{idx}]' must be 64 hex characters")
        })?;
        if decoded.len() != 32 {
            return Err(format!(
                "mtls_auth: 'allowed_ca_fingerprints_sha256[{idx}]' must be 64 hex characters"
            ));
        }
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&decoded);
        fingerprints.insert(fingerprint);
    }
    Ok(fingerprints)
}

#[async_trait]
impl AuthMechanism for MtlsAuth {
    fn mechanism_name(&self) -> &'static str {
        "mtls_auth"
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        match &ctx.tls_client_cert_der {
            Some(der_bytes) => ExtractedCredential::MtlsCert {
                der_bytes: Arc::clone(der_bytes),
                chain_der: ctx.tls_client_cert_chain_der.clone(),
                connection_cache: ctx.mtls_auth_connection_cache.clone(),
            },
            None => ExtractedCredential::Missing,
        }
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let ExtractedCredential::MtlsCert {
            der_bytes,
            chain_der,
            connection_cache,
        } = credential
        else {
            return VerifyOutcome::NotApplicable;
        };

        self.verify_client_cert(
            der_bytes.as_slice(),
            chain_der.as_ref().map(|chain| chain.as_slice()),
            connection_cache.as_deref(),
            consumer_index,
        )
    }
}

auth_flow::impl_auth_plugin!(
    MtlsAuth,
    "mtls_auth",
    super::priority::MTLS_AUTH,
    crate::plugins::HTTP_FAMILY_AND_STREAM_PROTOCOLS,
    auth_flow::run_auth;
    /// `on_stream_connect` below maps a client certificate to a consumer and
    /// contributes the leaf's `notAfter` as the session authorization deadline,
    /// so a listener carrying this plugin can never be handed to kernel TLS:
    /// the `splice(2)` relay cannot be bounded by that deadline (issue #3816).
    fn admits_authenticated_stream_principal(&self) -> bool {
        true
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let cert_der = match &ctx.tls_client_cert_der {
            Some(der) => der,
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"No client certificate presented"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        match self.verify_client_cert(
            cert_der.as_slice(),
            ctx.tls_client_cert_chain_der.as_ref().map(|c| c.as_slice()),
            None,
            ctx.consumer_index.as_ref(),
        ) {
            VerifyOutcome::Success {
                consumer: Some(consumer),
                credential_deadline,
                ..
            } => {
                if ctx.identified_consumer.is_none() {
                    debug!(
                        "mtls_auth: identified stream consumer '{}'",
                        consumer.username
                    );
                    ctx.insert_metadata("consumer_username".to_string(), consumer.username.clone());
                    ctx.identified_consumer = Some(consumer);
                }
                if ctx.auth_method.is_none() {
                    ctx.auth_method = Some("mtls_auth");
                }
                // Carry the accepted certificate's authoritative monotonic
                // deadline into the stream session lifecycle (issue #3816).
                // `on_stream_connect` runs once at admission, so without this
                // the raw TCP/TLS and DTLS relays would have no bound at all.
                // Earliest wins across every admitting mechanism.
                ctx.observe_credential_deadline(credential_deadline);
                PluginResult::Continue
            }
            VerifyOutcome::NotApplicable => PluginResult::Continue,
            VerifyOutcome::Forbidden(body) => PluginResult::Reject {
                status_code: 403,
                body,
                headers: HashMap::new(),
            },
            VerifyOutcome::Internal(body) => PluginResult::Reject {
                status_code: 500,
                body,
                headers: HashMap::new(),
            },
            VerifyOutcome::Invalid(body)
            | VerifyOutcome::InvalidFormat(body)
            | VerifyOutcome::ConsumerNotFound(body)
            | VerifyOutcome::VerificationFailed(body) => PluginResult::Reject {
                status_code: 401,
                body,
                headers: HashMap::new(),
            },
            VerifyOutcome::Success { consumer: None, .. } => PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"No consumer found for client certificate"}"#.into(),
                headers: HashMap::new(),
            },
        }
    }
);
