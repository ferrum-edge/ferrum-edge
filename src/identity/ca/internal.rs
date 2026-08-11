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
//! - Own a [`LocalJwtAuthority`] so the Workload API can mint and validate
//!   JWT-SVIDs for this trust domain, and publish that authority's public
//!   half as the trust domain's JWT bundle (issue #3617). The JWT signing key
//!   is **separately configured** material, never derived from the X.509 root:
//!   rotating one does not disturb the other, the root private key is never
//!   exposed to the JWT path, and a JWT verifier is never handed a key that
//!   also anchors certificate trust. See [`InternalCaConfig::jwt_signing_key_pem`].
//!
//! ## Out of scope (deferred to later phases)
//!
//! - Intermediate CAs and key escrow.
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
use crate::identity::jwt_svid::{
    DEFAULT_JWT_KEY_LIFETIME_SECS, JwtSvidSigner, LocalJwtAuthority, LocalJwtAuthorityConfig,
    SharedJwtSvidSigner,
};
use crate::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use zeroize::Zeroizing;

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
    /// Operator-configured ES256 (P-256) JWT signing key PEM for this trust
    /// domain.
    ///
    /// Deliberately **not** the X.509 root: a JWT bundle is published to every
    /// workload, so reusing the certificate root across protocols would put the
    /// CA's own key identity into a second, differently-scoped trust surface.
    /// Supplying the same value on every replica (and across restarts) is what
    /// keeps the trust domain's JWT authority continuous.
    pub jwt_signing_key_pem: Option<Zeroizing<String>>,
    /// JWT signing keys retained for **verification only**, newest first —
    /// normally the previous primary during a rotation.
    pub jwt_retired_key_pems: Vec<Zeroizing<String>>,
    /// How long an **ephemeral** JWT signing key stays active before the
    /// background rotation task replaces it. `0` disables time-based JWT key
    /// rotation, and is the default.
    ///
    /// Ignored (normalized to `0`) when [`Self::jwt_signing_key_pem`] is set:
    /// configured material is rotated externally, by rolling a new primary with
    /// the outgoing key in [`Self::jwt_retired_key_pems`]. See
    /// [`LocalJwtAuthority`].
    pub jwt_key_lifetime_secs: u64,
    /// Permit an ephemeral, process-local JWT signing key when none is
    /// configured. Dev/test only — it breaks restart and multi-replica
    /// continuity, so it is never a default.
    pub allow_ephemeral_jwt_key: bool,
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
            jwt_signing_key_pem: None,
            jwt_retired_key_pems: Vec::new(),
            jwt_key_lifetime_secs: DEFAULT_JWT_KEY_LIFETIME_SECS,
            allow_ephemeral_jwt_key: false,
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
    /// JWT signing authority for this trust domain, when one is configured.
    ///
    /// `None` when no JWT signing material is configured and the ephemeral dev
    /// opt-in is off: the JWT-SVID surface is then genuinely unavailable, so
    /// `jwt_signer()` returns `None` and `jwt_authorities()` is empty, and the
    /// Workload API answers the JWT RPCs `UNIMPLEMENTED` — fail-closed, rather
    /// than minting tokens signed by a key that vanishes on restart. Built at
    /// construction so no request path ever loads or generates a key.
    jwt_authority: Option<Arc<LocalJwtAuthority>>,
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

        // JWT signing authority for this trust domain, built eagerly so key
        // loading happens once at startup rather than on a mint RPC, and so
        // unusable material or an unprovable rotation cadence fails startup
        // closed instead of at first use. `JwtSvidError`'s message is a fixed
        // string that names no key material and no source.
        //
        // With NOTHING configured the authority is simply absent: this CA then
        // publishes no JWT trust and cannot mint JWT-SVIDs, which the Workload
        // API reports as `UNIMPLEMENTED`. That is the honest answer — silently
        // generating a process-local key would mint tokens that no restart and no
        // sibling replica can verify. The dev opt-in
        // (`allow_ephemeral_jwt_key`) is the only way to get one.
        let jwt_authority =
            if config.jwt_signing_key_pem.is_some() || config.allow_ephemeral_jwt_key {
                let mut jwt_config = LocalJwtAuthorityConfig::new(config.trust_domain.clone());
                jwt_config.signing_key_pem = config.jwt_signing_key_pem.clone();
                jwt_config.retired_key_pems = config.jwt_retired_key_pems.clone();
                jwt_config.key_lifetime_secs = config.jwt_key_lifetime_secs;
                jwt_config.allow_ephemeral_key = config.allow_ephemeral_jwt_key;
                Some(Arc::new(LocalJwtAuthority::new(jwt_config).map_err(
                    |e| CaError::Config(format!("JWT-SVID authority setup failed: {e}")),
                )?))
            } else {
                debug!(
                    trust_domain = %config.trust_domain,
                    "internal CA has no JWT signing material configured; JWT-SVID mint / bundles / \
                     validate stay UNIMPLEMENTED on this backend"
                );
                None
            };

        info!(
            trust_domain = %config.trust_domain,
            "internal CA initialised"
        );
        crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health("internal", true);

        Ok(Self {
            trust_domain: config.trust_domain,
            jwt_authority,
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

    /// The JWT signing authority backing this CA's JWT-SVID surface, when one is
    /// configured.
    ///
    /// Exposed so the background rotation task can drive
    /// [`LocalJwtAuthority::rotate_if_due`]; nothing on a request path needs it.
    pub fn jwt_authority(&self) -> Option<&Arc<LocalJwtAuthority>> {
        self.jwt_authority.as_ref()
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
                    // SECURITY — proof-of-possession (PoP) is enforced
                    // unconditionally here, before we sign the embedded public
                    // key. `rcgen::CertificateSigningRequestParams::from_der`
                    // does NOT check the PKCS#10 self-signature, so on its own
                    // it would let an attacker who intercepts a victim's CSR
                    // swap in their own public key and obtain a valid SVID for
                    // the victim's identity. We therefore verify the CSR
                    // self-signature with x509-parser first: a valid signature
                    // proves the requester holds the private key matching the
                    // public key we are about to certify.
                    //
                    // INVARIANT: this arm is safe for ANY transport — the local
                    // UDS Workload API server (SO_PEERCRED-class attested) today,
                    // and any future remote CSR bridge (Vault PKI, cert-manager
                    // Issuer, federated SPIFFE bundle endpoint, mesh-expansion VM
                    // bootstrap). Do NOT remove this PoP check when wiring a
                    // non-UDS caller; without it a remote transport would
                    // silently reintroduce the identity-spoofing vector.
                    {
                        use x509_parser::prelude::*;
                        let (_, parsed_csr) = X509CertificationRequest::from_der(&csr_der)
                            .map_err(|e| CaError::BadCsr(format!("CSR parse failed: {e}")))?;
                        parsed_csr.verify_signature().map_err(|e| {
                            CaError::BadCsr(format!(
                                "CSR proof-of-possession verification failed: {e}"
                            ))
                        })?;
                    }
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
        // The active signing key plus every retired key still inside its
        // rotation overlap, so a token minted just before a rotation stays
        // verifiable for its whole bounded lifetime. Empty when no JWT signing
        // material is configured — the Workload API turns that into
        // `UNIMPLEMENTED`, never into an empty (misleading) bundle map.
        Ok(self
            .jwt_authority
            .as_ref()
            .map(|authority| authority.authorities())
            .unwrap_or_default())
    }

    fn jwt_signer(&self) -> Option<SharedJwtSvidSigner> {
        self.jwt_authority
            .as_ref()
            .map(|authority| Arc::clone(authority) as SharedJwtSvidSigner)
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
    use crate::fips::backend::rand::SecureRandom;
    let rng = crate::fips::backend::rand::SystemRandom::new();
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
