//! File-based X.509-SVID loading for gateway identities.
//!
//! Mesh mode can obtain SVIDs from the Workload API / rotation machinery. Edge
//! gateway deployments often receive their SVID material as mounted files, so
//! this loader turns a leaf-first PEM chain, a PKCS#8 private key, and a PEM
//! trust bundle into the same [`SvidBundle`] shape used by SPIFFE TLS.

use std::path::Path;

use rcgen::PublicKeyData;
use x509_parser::prelude::*;

use crate::identity::spiffe::{SpiffeId, UriSanError, extract_spiffe_id_from_cert};
use crate::identity::{SvidBundle, TrustBundle, TrustBundleSet};
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use crate::tls::spiffe::SpiffeTlsError;

pub fn load_svid_bundle_from_files(
    cert_path: &Path,
    key_path: &Path,
    trust_bundle_path: &Path,
    explicit_spiffe_id: Option<&str>,
) -> Result<SvidBundle, SpiffeTlsError> {
    let cert_source = cert_path.to_string_lossy();
    let key_source = key_path.to_string_lossy();
    let trust_bundle_source = trust_bundle_path.to_string_lossy();
    load_svid_bundle_from_sources(
        cert_source.as_ref(),
        key_source.as_ref(),
        trust_bundle_source.as_ref(),
        explicit_spiffe_id,
    )
}

pub fn load_svid_bundle_from_sources(
    cert_source: &str,
    key_source: &str,
    trust_bundle_source: &str,
    explicit_spiffe_id: Option<&str>,
) -> Result<SvidBundle, SpiffeTlsError> {
    let cert_chain_der = read_cert_chain_source(
        cert_source,
        MaterialKind::Cert,
        "gateway SVID certificate chain",
    )?;
    let private_key_pkcs8_der = read_pkcs8_key_source(key_source)?;
    let x509_authorities = read_cert_chain_source(
        trust_bundle_source,
        MaterialKind::CaBundle,
        "gateway SVID trust bundle",
    )?;

    let leaf = cert_chain_der
        .first()
        .ok_or(SpiffeTlsError::NoLeafCert)?
        .as_slice();
    validate_cert_is_current(leaf, "gateway SVID leaf certificate")?;
    validate_leaf_is_not_ca(leaf)?;
    for (idx, intermediate) in cert_chain_der.iter().enumerate().skip(1) {
        validate_cert_is_current(
            intermediate,
            &format!("gateway SVID intermediate certificate #{idx}"),
        )?;
    }
    for (idx, ca) in x509_authorities.iter().enumerate() {
        validate_cert_is_current(ca, &format!("gateway SVID trust bundle cert #{}", idx + 1))?;
    }

    let spiffe_id = match extract_spiffe_id_from_cert(leaf) {
        Ok(id) => id,
        Err(UriSanError::NoSanExtension | UriSanError::NoSpiffeUri) => {
            let Some(explicit) = explicit_spiffe_id else {
                return Err(SpiffeTlsError::BadKeyMaterial(
                    "gateway SVID leaf certificate does not contain a SPIFFE URI SAN and FERRUM_GATEWAY_SPIFFE_ID is unset"
                        .to_string(),
                ));
            };
            SpiffeId::new(explicit.to_string()).map_err(|e| {
                SpiffeTlsError::BadKeyMaterial(format!(
                    "FERRUM_GATEWAY_SPIFFE_ID '{explicit}' is invalid: {e}"
                ))
            })?
        }
        Err(err) => {
            return Err(SpiffeTlsError::BadKeyMaterial(format!(
                "gateway SVID leaf certificate SPIFFE URI SAN is invalid: {err}"
            )));
        }
    };

    verify_leaf_key_match(leaf, &private_key_pkcs8_der)?;

    Ok(SvidBundle {
        trust_bundles: TrustBundleSet::local_only(TrustBundle {
            trust_domain: spiffe_id.trust_domain().clone(),
            x509_authorities,
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        }),
        spiffe_id,
        cert_chain_der,
        private_key_pkcs8_der: private_key_pkcs8_der.into(),
    })
}

fn read_cert_chain_source(
    source_value: &str,
    kind: MaterialKind,
    label: &str,
) -> Result<Vec<Vec<u8>>, SpiffeTlsError> {
    let source = CertSource::parse(source_value, kind);
    let material = load_material_blocking(&source, kind)
        .map_err(|e| SpiffeTlsError::BadKeyMaterial(format!("{label}: {e}")))?;
    let source_id = material.source_id.clone();
    let mut reader = material.bytes.expose_secret();
    let certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut reader)
        .map(|cert| {
            cert.map(|cert| cert.as_ref().to_vec()).map_err(|e| {
                SpiffeTlsError::BadKeyMaterial(format!(
                    "{label}: failed to parse PEM certificate in '{}': {e}",
                    source_id
                ))
            })
        })
        .collect::<Result<_, _>>()?;

    if certs.is_empty() {
        return Err(SpiffeTlsError::BadKeyMaterial(format!(
            "{label}: no CERTIFICATE blocks found in '{}'",
            source_id
        )));
    }
    Ok(certs)
}

fn read_pkcs8_key_source(source_value: &str) -> Result<Vec<u8>, SpiffeTlsError> {
    let source = CertSource::parse(source_value, MaterialKind::Key);
    let material = load_material_blocking(&source, MaterialKind::Key)
        .map_err(|e| SpiffeTlsError::BadKeyMaterial(format!("gateway SVID key: {e}")))?;
    let source_id = material.source_id.clone();
    let mut reader = material.bytes.expose_secret();
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader);
    let key = keys
        .next()
        .ok_or_else(|| {
            SpiffeTlsError::BadKeyMaterial(format!(
                "gateway SVID key: no PKCS#8 PRIVATE KEY block found in '{}'",
                source_id
            ))
        })?
        .map_err(|e| {
            SpiffeTlsError::BadKeyMaterial(format!(
                "gateway SVID key: failed to parse PKCS#8 key in '{}': {e}",
                source_id
            ))
        })?;

    if keys.next().is_some() {
        return Err(SpiffeTlsError::BadKeyMaterial(format!(
            "gateway SVID key: '{}' contains more than one PKCS#8 private key",
            source_id
        )));
    }

    Ok(key.secret_pkcs8_der().to_vec())
}

pub(crate) fn validate_cert_is_current(cert_der: &[u8], label: &str) -> Result<(), SpiffeTlsError> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        SpiffeTlsError::BadKeyMaterial(format!("{label}: failed to parse certificate DER: {e}"))
    })?;
    let validity = cert.validity();
    if validity.is_valid() {
        return Ok(());
    }

    let now_ts = x509_parser::time::ASN1Time::now().timestamp();
    if now_ts < validity.not_before.timestamp() {
        Err(SpiffeTlsError::BadKeyMaterial(format!(
            "{label}: certificate is not yet valid (notBefore: {})",
            validity.not_before
        )))
    } else {
        Err(SpiffeTlsError::BadKeyMaterial(format!(
            "{label}: certificate has expired (notAfter: {})",
            validity.not_after
        )))
    }
}

pub(crate) fn validate_leaf_is_not_ca(leaf_der: &[u8]) -> Result<(), SpiffeTlsError> {
    let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|e| {
        SpiffeTlsError::BadKeyMaterial(format!("gateway SVID leaf certificate parse failed: {e}"))
    })?;
    let basic_constraints = leaf.basic_constraints().map_err(|e| {
        SpiffeTlsError::BadKeyMaterial(format!(
            "gateway SVID leaf certificate basic constraints are invalid: {e}"
        ))
    })?;

    if basic_constraints.is_some_and(|ext| ext.value.ca) {
        return Err(SpiffeTlsError::BadKeyMaterial(
            "gateway SVID leaf certificate must not be a CA certificate".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_leaf_key_match(leaf_der: &[u8], key_der: &[u8]) -> Result<(), SpiffeTlsError> {
    let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|e| {
        SpiffeTlsError::BadKeyMaterial(format!("gateway SVID leaf certificate parse failed: {e}"))
    })?;
    let key_pair = rcgen::KeyPair::try_from(key_der).map_err(|e| {
        SpiffeTlsError::BadKeyMaterial(format!("gateway SVID private key is invalid: {e}"))
    })?;
    // Compare canonical DER SubjectPublicKeyInfo bytes. x509-parser preserves
    // the certificate SPKI DER and rcgen emits canonical SPKI DER for the key.
    let cert_spki = leaf.tbs_certificate.subject_pki.raw;
    let key_spki = key_pair.subject_public_key_info();
    if cert_spki != key_spki.as_slice() {
        return Err(SpiffeTlsError::BadKeyMaterial(
            "gateway SVID certificate public key does not match the supplied private key"
                .to_string(),
        ));
    }
    Ok(())
}
