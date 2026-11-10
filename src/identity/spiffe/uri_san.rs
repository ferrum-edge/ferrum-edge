//! Encode SPIFFE IDs as X.509 URI Subject Alternative Names, and extract them
//! from peer certificates.
//!
//! Per RFC 5280 §4.2.1.6 a `URI` GeneralName carries an IA5String (ASCII).
//! SPIFFE IDs are themselves ASCII (the parser rejects non-ASCII path
//! characters), so the conversion is byte-identical.
//!
//! On the **issue** side we hand the SPIFFE ID URI to `rcgen` as a
//! `SanType::URI`; rcgen handles the IA5String wrapping.
//!
//! On the **verify** side we parse the peer certificate with `x509-parser`
//! and walk the SAN extension's `general_names` looking for `URI` entries.
//! Per the SPIFFE X.509-SVID spec §4.1 an SVID has exactly one URI SAN and that
//! URI must contain the SPIFFE ID, so `extract_spiffe_id_from_parsed` itself
//! enforces that rule — it REJECTS a certificate carrying more than one URI SAN
//! rather than silently picking the first SPIFFE URI. No upstream layer does
//! this: the chain verifier (`tls/spiffe.rs`) is chain-only and neither rustls
//! nor x509-parser enforces the single-URI-SAN rule. A single `spiffe://` URI
//! alongside non-URI SANs (e.g. a DNS SAN) is accepted.

use rcgen::SanType;
use rcgen::string::Ia5String;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

use super::id::{SpiffeId, SpiffeIdError};

/// Errors raised when extracting a SPIFFE URI SAN from a peer certificate.
#[derive(Debug, thiserror::Error)]
pub enum UriSanError {
    #[error("certificate has no Subject Alternative Name extension")]
    NoSanExtension,
    #[error("certificate has no SPIFFE URI SAN")]
    NoSpiffeUri,
    #[error("certificate has {count} URI SANs; an X.509-SVID must have exactly one")]
    MultipleUriSans { count: usize },
    #[error("SPIFFE URI SAN '{uri}' is invalid: {source}")]
    InvalidSpiffeId {
        uri: String,
        #[source]
        source: SpiffeIdError,
    },
    #[error("failed to parse certificate DER: {0}")]
    ParseFailure(String),
}

/// Build a [`SanType::URI`] for use in an `rcgen::CertificateParams::subject_alt_names`
/// list.
pub fn spiffe_id_to_san(id: &SpiffeId) -> Result<SanType, UriSanError> {
    let ia5 = Ia5String::try_from(id.as_str().to_string()).map_err(|e| {
        UriSanError::ParseFailure(format!(
            "SPIFFE URI '{}' is not a valid IA5 string: {}",
            id, e
        ))
    })?;
    Ok(SanType::URI(ia5))
}

/// Extract the single SPIFFE URI SAN from a DER-encoded peer certificate
/// (a certificate carrying more than one URI SAN is rejected).
///
/// Returns the parsed [`SpiffeId`], or one of:
/// - [`UriSanError::ParseFailure`] if the DER does not parse as X.509.
/// - [`UriSanError::NoSanExtension`] if the cert lacks a SAN extension.
/// - [`UriSanError::NoSpiffeUri`] if the SAN list contains no `spiffe://` URI.
/// - [`UriSanError::InvalidSpiffeId`] if a `spiffe://` URI is present but
///   malformed (this is a strict-mode error — callers may choose to log and
///   continue if they prefer, but the default is to reject).
pub fn extract_spiffe_id_from_cert(cert_der: &[u8]) -> Result<SpiffeId, UriSanError> {
    let (_, parsed) = X509Certificate::from_der(cert_der)
        .map_err(|e| UriSanError::ParseFailure(e.to_string()))?;
    extract_spiffe_id_from_parsed(&parsed)
}

/// Like [`extract_spiffe_id_from_cert`] but takes an already-parsed
/// `X509Certificate`. Useful inside hot paths where the certificate has
/// already been parsed for other reasons (e.g. the `mtls_auth` plugin).
pub fn extract_spiffe_id_from_parsed(cert: &X509Certificate<'_>) -> Result<SpiffeId, UriSanError> {
    let mut saw_san = false;
    let mut first_spiffe_uri: Option<String> = None;
    let mut uri_san_count = 0usize;
    let mut spiffe_uri_count = 0usize;

    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            saw_san = true;
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    uri_san_count += 1;
                    if uri.starts_with("spiffe://") {
                        spiffe_uri_count += 1;
                        if first_spiffe_uri.is_none() {
                            first_spiffe_uri = Some((*uri).to_string());
                        }
                    }
                }
            }
        }
    }

    if !saw_san {
        return Err(UriSanError::NoSanExtension);
    }
    if spiffe_uri_count > 0 && uri_san_count > 1 {
        // SPIFFE X.509-SVID §4.1: an SVID carries exactly one URI SAN, and
        // that URI contains the SPIFFE ID. Reject rather than silently picking
        // the first SPIFFE URI, so a trusted-but-misconfigured leaf with a
        // second URI SAN cannot be attributed differently here than by a peer
        // mesh implementation.
        return Err(UriSanError::MultipleUriSans {
            count: uri_san_count,
        });
    }
    let uri = first_spiffe_uri.ok_or(UriSanError::NoSpiffeUri)?;
    SpiffeId::new(uri.clone()).map_err(|source| UriSanError::InvalidSpiffeId { uri, source })
}

/// Variant of [`extract_spiffe_id_from_cert`] returning `Option<SpiffeId>` —
/// `None` when the cert simply has no SPIFFE URI SAN (the common case for
/// non-mesh deployments).
///
/// Malformed `spiffe://` URIs are still treated as errors (returned via
/// `Err`); callers that want to silently ignore them can `.ok().flatten()`.
pub fn try_extract_spiffe_id(cert_der: &[u8]) -> Result<Option<SpiffeId>, UriSanError> {
    match extract_spiffe_id_from_cert(cert_der) {
        Ok(id) => Ok(Some(id)),
        Err(UriSanError::NoSanExtension) | Err(UriSanError::NoSpiffeUri) => Ok(None),
        Err(other) => Err(other),
    }
}

/// Parsed-cert variant of [`try_extract_spiffe_id`]: avoid double-parsing
/// when callers already have an `X509Certificate`.
pub fn try_extract_spiffe_id_from_parsed(
    cert: &X509Certificate<'_>,
) -> Result<Option<SpiffeId>, UriSanError> {
    match extract_spiffe_id_from_parsed(cert) {
        Ok(id) => Ok(Some(id)),
        Err(UriSanError::NoSanExtension) | Err(UriSanError::NoSpiffeUri) => Ok(None),
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::string::Ia5String;
    use rcgen::{CertificateParams, KeyPair, SanType};

    fn uri_san(uri: &str) -> SanType {
        SanType::URI(Ia5String::try_from(uri.to_string()).expect("ia5"))
    }

    fn cert_with_sans(sans: Vec<SanType>) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans;
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
        params
            .self_signed(&key_pair)
            .expect("self-signed cert")
            .der()
            .to_vec()
    }

    #[test]
    fn rejects_multiple_spiffe_uri_sans() {
        // A trusted-but-misconfigured CA leaf with two SPIFFE URIs must be
        // rejected, not silently resolved to whichever is encoded first.
        let der = cert_with_sans(vec![
            uri_san("spiffe://prod.example.com/ns/a/sa/legit"),
            uri_san("spiffe://prod.example.com/ns/kube-system/sa/admin"),
        ]);
        assert!(matches!(
            extract_spiffe_id_from_cert(&der),
            Err(UriSanError::MultipleUriSans { count: 2 })
        ));
    }

    #[test]
    fn rejects_spiffe_uri_alongside_other_uri_san() {
        let der = cert_with_sans(vec![
            uri_san("spiffe://prod.example.com/ns/a/sa/legit"),
            uri_san("https://svc.example.com/identity"),
        ]);
        assert!(matches!(
            extract_spiffe_id_from_cert(&der),
            Err(UriSanError::MultipleUriSans { count: 2 })
        ));
    }

    #[test]
    fn accepts_single_spiffe_uri_alongside_dns_san() {
        let der = cert_with_sans(vec![
            uri_san("spiffe://prod.example.com/ns/a/sa/legit"),
            SanType::DnsName(Ia5String::try_from("svc.example.com".to_string()).expect("ia5")),
        ]);
        let id = extract_spiffe_id_from_cert(&der).expect("single SPIFFE URI extracts");
        assert_eq!(id.as_str(), "spiffe://prod.example.com/ns/a/sa/legit");
    }

    #[test]
    fn no_spiffe_uri_reports_no_spiffe_uri() {
        let der = cert_with_sans(vec![SanType::DnsName(
            Ia5String::try_from("svc.example.com".to_string()).expect("ia5"),
        )]);
        assert!(matches!(
            extract_spiffe_id_from_cert(&der),
            Err(UriSanError::NoSpiffeUri)
        ));
    }
}
