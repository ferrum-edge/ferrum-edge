//! Ferrum's own internal certificate authority.
//!
//! Loads a root cert + key from disk (or via the existing `_VAULT` / `_AWS` /
//! `_AZURE` / `_GCP` / `_FILE` / `_ENV` secret-resolution suffixes — the
//! suffix machinery rewrites the named env var BEFORE we read it, so we
//! simply read whatever is present at startup) and signs SVIDs against it.
//!
//! ## Responsibilities
//!
//! - Mint X.509 SVIDs from CSRs or by generating fresh keys (the
//!   "Generate" form used by the workload-API server).
//! - Always rewrite the URI SAN with the caller-attested SPIFFE ID — never
//!   trust a SAN claim coming from a CSR.
//! - Publish the trust bundle (the root cert) for verifiers.
//!
//! ## Out of scope (deferred to later phases)
//!
//! - Intermediate CAs, key escrow, JWT-SVID minting (we expose the JWKS
//!   plumbing as an empty list for Phase A; later phases plug it in).
//! - CRL / OCSP publication.
//! - Cross-trust-domain federation (the upstream wrappers handle that).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SerialNumber, SigningKey,
};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info};

use super::{
    CaError, CertificateAuthority, IssuanceRequest, PublishedJwtAuthority, PublishedTrustBundle,
    SignedSvid,
};
use crate::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};

/// Default SVID lifetime when the issuance request does not specify one.
pub const DEFAULT_SVID_TTL_SECS: u64 = 3600; // 1h
/// Hard upper bound on SVID lifetime — internal CA refuses to mint long-lived SVIDs.
pub const MAX_SVID_TTL_SECS: u64 = 24 * 3600;

/// Configuration for the internal CA at construction time.
pub struct InternalCaConfig {
    /// PEM-encoded root certificate.
    pub root_cert_pem: String,
    /// PKCS#8 / PEM-encoded root private key. The CA never persists or logs
    /// this; the field name reflects the input format ("anything `KeyPair`
    /// accepts").
    pub root_key_pem: String,
    /// The trust domain this CA serves.
    pub trust_domain: TrustDomain,
    /// Optional refresh hint (seconds) shipped to clients that need to
    /// re-fetch the trust bundle. `None` ⇒ refresh on rotation only.
    pub bundle_refresh_hint_secs: Option<u64>,
    /// Default TTL applied when a request asks for `0` seconds.
    pub default_svid_ttl_secs: u64,
    /// Hard cap on per-SVID TTL — requests above are clamped.
    pub max_svid_ttl_secs: u64,
}

impl InternalCaConfig {
    /// Convenience: load PEM-encoded root cert + key from two file paths.
    pub fn from_paths(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        trust_domain: TrustDomain,
    ) -> Result<Self, CaError> {
        let root_cert_pem = std::fs::read_to_string(&cert_path).map_err(|e| {
            CaError::Config(format!(
                "failed to read root cert '{}': {}",
                cert_path.as_ref().display(),
                e
            ))
        })?;
        let root_key_pem = std::fs::read_to_string(&key_path).map_err(|e| {
            CaError::Config(format!(
                "failed to read root key '{}': {}",
                key_path.as_ref().display(),
                e
            ))
        })?;
        Ok(Self {
            root_cert_pem,
            root_key_pem,
            trust_domain,
            bundle_refresh_hint_secs: None,
            default_svid_ttl_secs: DEFAULT_SVID_TTL_SECS,
            max_svid_ttl_secs: MAX_SVID_TTL_SECS,
        })
    }
}

/// Internal CA implementing [`CertificateAuthority`].
///
/// Holds the parsed root key + cert in memory for the lifetime of the
/// process. Rotation of the root itself requires a restart.
pub struct InternalCa {
    trust_domain: TrustDomain,
    /// Root cert in DER form, exposed via the trust-bundle API.
    root_cert_der: Vec<u8>,
    /// rcgen issuer wrapping the root for signing operations.
    issuer: Issuer<'static, KeyPair>,
    bundle_refresh_hint_secs: Option<u64>,
    default_svid_ttl_secs: u64,
    max_svid_ttl_secs: u64,
}

impl InternalCa {
    /// Build the CA from a raw config. Validates that the PEM blobs parse and
    /// that the cert + key actually match (fail-fast at startup rather than
    /// at first issuance).
    pub fn new(config: InternalCaConfig) -> Result<Self, CaError> {
        let key_pair = KeyPair::from_pem(&config.root_key_pem)
            .map_err(|e| CaError::Config(format!("invalid root key PEM: {e}")))?;

        // Strip PEM envelope to get DER for the trust bundle response. The
        // `pem_to_der` helper also rejects multi-block PEMs (an operator who
        // concatenates a root + intermediate would otherwise silently use
        // only the first cert as the trust anchor).
        let root_cert_der = pem_to_der(&config.root_cert_pem)?;

        // Cert/key match self-test. `Issuer::from_ca_cert_pem` does not
        // verify that the key actually corresponds to the cert; without this
        // check, a misconfiguration surfaces only at first SVID issuance —
        // the gateway happily comes up and breaks under traffic. Compare the
        // SubjectPublicKeyInfo DER on both sides.
        verify_cert_key_match(&root_cert_der, &key_pair)?;

        // Parse the root cert and assemble a usable issuer. `from_ca_cert_pem`
        // requires the rcgen `pem` + `x509-parser` features (declared in
        // Cargo.toml) — the build will fail to compile otherwise.
        let issuer: Issuer<'static, KeyPair> =
            Issuer::from_ca_cert_pem(&config.root_cert_pem, key_pair)
                .map_err(|e| CaError::Config(format!("invalid root cert PEM: {e}")))?;

        info!(
            trust_domain = %config.trust_domain,
            "internal CA initialised"
        );
        crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health("internal", true);

        Ok(Self {
            trust_domain: config.trust_domain,
            root_cert_der,
            issuer,
            bundle_refresh_hint_secs: config.bundle_refresh_hint_secs,
            default_svid_ttl_secs: if config.default_svid_ttl_secs == 0 {
                DEFAULT_SVID_TTL_SECS
            } else {
                config.default_svid_ttl_secs
            },
            max_svid_ttl_secs: if config.max_svid_ttl_secs == 0 {
                MAX_SVID_TTL_SECS
            } else {
                config.max_svid_ttl_secs
            },
        })
    }

    /// The trust domain this CA serves.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    fn enforce_trust_domain(&self, id: &SpiffeId) -> Result<(), CaError> {
        if id.trust_domain() != &self.trust_domain {
            return Err(CaError::BadCsr(format!(
                "SPIFFE ID '{}' is not in this CA's trust domain '{}'",
                id, self.trust_domain
            )));
        }
        Ok(())
    }

    fn clamp_ttl(&self, requested: u64) -> u64 {
        let ttl = if requested == 0 {
            self.default_svid_ttl_secs
        } else {
            requested
        };
        ttl.min(self.max_svid_ttl_secs)
    }

    fn build_svid_params(
        &self,
        id: &SpiffeId,
        ttl_secs: u64,
    ) -> Result<CertificateParams, CaError> {
        let mut params = CertificateParams::default();
        // Subject: SPIFFE recommends an empty Subject (the URI SAN is the
        // identity), but we set CN to the SPIFFE ID for human-readable logs.
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, id.as_str());
        params.distinguished_name = dn;

        params.subject_alt_names.push(
            spiffe_id_to_san(id).map_err(|e| CaError::Internal(format!("URI SAN encode: {e}")))?,
        );

        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::seconds(ttl_secs as i64);

        // Random serial — 64 bits is sufficient for non-CA SVIDs and matches
        // SPIFFE conventions.
        let serial: u64 = rand_u64();
        params.serial_number = Some(SerialNumber::from_slice(&serial.to_be_bytes()));

        Ok(params)
    }

    fn sign_with_keypair(
        &self,
        id: &SpiffeId,
        ttl_secs: u64,
        signing_key: &impl SigningKey,
    ) -> Result<SignedSvid, CaError> {
        let params = self.build_svid_params(id, ttl_secs)?;
        let cert = params
            .signed_by(signing_key, &self.issuer)
            .map_err(|e| CaError::Internal(format!("rcgen sign failed: {e}")))?;

        let leaf_der = cert.der().to_vec();
        let not_after = issued_cert_not_after(&leaf_der)?;
        let chain = vec![leaf_der, self.root_cert_der.clone()];

        Ok(SignedSvid {
            spiffe_id: id.clone(),
            cert_chain_der: chain,
            // Filled in by callers that own the keypair (Csr path needs no
            // key; Generate path returns the freshly-generated PKCS#8 DER).
            private_key_pkcs8_der: Vec::new().into(),
            not_after,
        })
    }
}

#[async_trait]
impl CertificateAuthority for InternalCa {
    async fn issue_svid(&self, req: IssuanceRequest) -> Result<SignedSvid, CaError> {
        let result = (|| -> Result<SignedSvid, CaError> {
            match req {
                IssuanceRequest::Csr {
                    csr_der,
                    spiffe_id,
                    ttl_secs,
                } => {
                    self.enforce_trust_domain(&spiffe_id)?;
                    let ttl = self.clamp_ttl(ttl_secs);

                    // Re-derive the requester's public key from the CSR. We
                    // deliberately ignore any SAN already present in the CSR —
                    // the caller-attested `spiffe_id` is authoritative.
                    //
                    // SECURITY (TODO before non-UDS callers in Phase B+):
                    // `rcgen::CertificateSigningRequestParams::from_der` does NOT
                    // verify the CSR self-signature (proof-of-possession). For
                    // the local UDS Workload API server this is acceptable — the
                    // transport itself authenticates the calling workload via
                    // SO_PEERCRED-class attestation, and the SVID's URI SAN is
                    // determined by attestation, not by anything in the CSR.
                    //
                    // For ANY future caller that flows CSRs over a remote
                    // transport (Vault PKI bridge, cert-manager Issuer, federated
                    // SPIFFE bundle endpoint, mesh-expansion VM bootstrap), the
                    // PoP signature MUST be verified before we sign the public
                    // key — otherwise an attacker who intercepts a CSR can swap
                    // in their own public key and obtain a valid SVID for the
                    // victim's identity. Add a webpki / x509-parser-based PoP
                    // verification step at the start of this arm before wiring
                    // any non-UDS transport into `IssuanceRequest::Csr`.
                    let csr = rcgen::CertificateSigningRequestParams::from_der(&csr_der.into())
                        .map_err(|e| CaError::BadCsr(format!("CSR parse failed: {e}")))?;
                    let public_key = csr.public_key;
                    let params = self.build_svid_params(&spiffe_id, ttl)?;
                    let cert = params
                        .signed_by(&public_key, &self.issuer)
                        .map_err(|e| CaError::Internal(format!("rcgen sign(csr) failed: {e}")))?;

                    debug!(spiffe_id = %spiffe_id, ttl_secs = ttl, "internal CA: issued SVID from CSR");

                    let leaf_der = cert.der().to_vec();
                    let not_after = issued_cert_not_after(&leaf_der)?;
                    crate::plugins::mesh::prometheus_helpers::record_mesh_cert_expiry_at(
                        &spiffe_id, "internal", &not_after,
                    );
                    crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health("internal", true);
                    Ok(SignedSvid {
                        spiffe_id,
                        cert_chain_der: vec![leaf_der, self.root_cert_der.clone()],
                        private_key_pkcs8_der: Vec::new().into(),
                        not_after,
                    })
                }
                IssuanceRequest::Generate {
                    spiffe_id,
                    ttl_secs,
                } => {
                    self.enforce_trust_domain(&spiffe_id)?;
                    let ttl = self.clamp_ttl(ttl_secs);

                    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                        .map_err(|e| CaError::Internal(format!("keypair gen failed: {e}")))?;
                    let serialized_key = key_pair.serialize_der();

                    let mut svid = self.sign_with_keypair(&spiffe_id, ttl, &key_pair)?;
                    svid.private_key_pkcs8_der = serialized_key.into();
                    crate::plugins::mesh::prometheus_helpers::record_mesh_cert_expiry_at(
                        &svid.spiffe_id,
                        "internal",
                        &svid.not_after,
                    );
                    crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health("internal", true);

                    debug!(
                        spiffe_id = %spiffe_id,
                        ttl_secs = ttl,
                        "internal CA: issued SVID with generated key"
                    );
                    Ok(svid)
                }
            }
        })();
        if result.as_ref().is_err_and(ca_issue_error_marks_unhealthy) {
            crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health("internal", false);
        }
        result
    }

    async fn trust_bundle(&self, td: &TrustDomain) -> Result<PublishedTrustBundle, CaError> {
        if td != &self.trust_domain {
            return Err(CaError::UnknownTrustDomain(td.to_string()));
        }
        let bundle = PublishedTrustBundle {
            trust_domain: self.trust_domain.clone(),
            roots_der: vec![self.root_cert_der.clone()],
            refresh_hint_secs: self.bundle_refresh_hint_secs,
        };
        crate::plugins::mesh::prometheus_helpers::record_mesh_trust_bundle(&bundle, "internal");
        crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health("internal", true);
        Ok(bundle)
    }

    async fn jwt_authorities(
        &self,
        td: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
        if td != &self.trust_domain {
            return Err(CaError::UnknownTrustDomain(td.to_string()));
        }
        // Phase A: JWT-SVID minting is wired in but no signing keys are
        // published. Future phases plug a JwtAuthority registry here.
        Ok(Vec::new())
    }
}

/// Decode exactly one PEM CERTIFICATE block into raw DER. Rejects PEMs that
/// contain more than one block — concatenating root + intermediate would
/// otherwise silently use the first block as the trust anchor (and an
/// operator who put the intermediate first would issue with the intermediate
/// as "root", breaking chain validation in subtle ways).
fn pem_to_der(pem: &str) -> Result<Vec<u8>, CaError> {
    let mut reader = pem.as_bytes();
    let mut iter = rustls_pemfile::certs(&mut reader);
    let first = iter
        .next()
        .ok_or_else(|| CaError::Config("no CERTIFICATE block in root cert PEM".to_string()))?
        .map_err(|e| CaError::Config(format!("PEM parse failed: {e}")))?;
    if iter.next().is_some() {
        return Err(CaError::Config(
            "root cert PEM contains more than one CERTIFICATE block; the internal CA expects \
             a single self-signed root, not a chain. If you have intermediates, configure them \
             on the verifier side rather than embedding them in the root file."
                .to_string(),
        ));
    }
    Ok(first.as_ref().to_vec())
}

/// Compare the public key embedded in `root_cert_der` against the supplied
/// `KeyPair`. The two must encode to identical SubjectPublicKeyInfo DER, or
/// the cert was issued under a different key and signing operations will
/// produce certs that no peer can verify.
fn verify_cert_key_match(root_cert_der: &[u8], key_pair: &KeyPair) -> Result<(), CaError> {
    use rcgen::PublicKeyData;
    use x509_parser::prelude::*;
    let (_, parsed_root) = X509Certificate::from_der(root_cert_der)
        .map_err(|e| CaError::Config(format!("root cert parse failed: {e}")))?;
    let cert_spki_raw = parsed_root.tbs_certificate.subject_pki.raw;
    let key_spki_der = key_pair.subject_public_key_info();
    if cert_spki_raw != key_spki_der.as_slice() {
        return Err(CaError::Config(
            "internal CA: root certificate public key does not match the supplied private key \
             (cert/key mismatch); refusing to start"
                .to_string(),
        ));
    }
    Ok(())
}

fn ca_issue_error_marks_unhealthy(error: &CaError) -> bool {
    matches!(
        error,
        CaError::Config(_) | CaError::Upstream(_) | CaError::Internal(_) | CaError::Io(_)
    )
}

/// `rand` 0.10 is a dev dep but not a runtime dep here. We use the system
/// random source available via `ring` (already in our deps).
///
/// RFC 5280 §4.1.2.2 requires serial numbers to be positive ASN.1 INTEGERs.
/// The DER encoding of an INTEGER is sign-bit-sensitive: a high MSB makes
/// the value negative. We clear the high bit explicitly so the produced
/// serial round-trips as positive on every parser, regardless of whether
/// `rcgen` would otherwise add a sign-extension byte. We also avoid the
/// all-zero serial.
fn rand_u64() -> u64 {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut buf = [0u8; 8];
    if rng.fill(&mut buf).is_ok() {
        buf[0] &= 0x7f;
        if buf == [0u8; 8] {
            buf[7] = 1;
        }
        u64::from_be_bytes(buf)
    } else {
        // Fallback to a process-counter — astronomically unlikely to fire.
        // The counter starts at 1 so the all-zero case never appears.
        static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed) & 0x7fff_ffff_ffff_ffff
    }
}

/// Convenience wrapper that returns the internal CA as a [`SharedCa`].
pub fn shared_internal_ca(config: InternalCaConfig) -> Result<Arc<InternalCa>, CaError> {
    Ok(Arc::new(InternalCa::new(config)?))
}

fn issued_cert_not_after(leaf_der: &[u8]) -> Result<DateTime<Utc>, CaError> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, parsed) = X509Certificate::from_der(leaf_der)
        .map_err(|e| CaError::Internal(format!("issued SVID parse failed: {e}")))?;
    DateTime::<Utc>::from_timestamp(parsed.validity().not_after.timestamp(), 0).ok_or_else(|| {
        CaError::Internal("issued SVID notAfter is outside supported timestamp range".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_issue_health_only_tracks_backend_failures() {
        assert!(!ca_issue_error_marks_unhealthy(&CaError::BadCsr(
            "malformed csr".to_string()
        )));
        assert!(!ca_issue_error_marks_unhealthy(
            &CaError::UnknownTrustDomain("other.test".to_string())
        ));

        assert!(ca_issue_error_marks_unhealthy(&CaError::Config(
            "invalid backend configuration".to_string()
        )));
        assert!(ca_issue_error_marks_unhealthy(&CaError::Upstream(
            "upstream failed".to_string()
        )));
        assert!(ca_issue_error_marks_unhealthy(&CaError::Internal(
            "signing failed".to_string()
        )));
        assert!(ca_issue_error_marks_unhealthy(&CaError::Io(
            "disk read failed".to_string()
        )));
    }
}
