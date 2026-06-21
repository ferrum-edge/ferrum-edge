//! Certificate Authority abstraction for the mesh identity subsystem.
//!
//! `CertificateAuthority` is the seam between an "identity issuer" (Ferrum's
//! own internal CA, a Vault PKI mount, cert-manager, or a SPIRE server) and
//! the rest of the codebase. The Workload API server uses one of these to
//! mint SVIDs in response to attested workloads; the rotation task uses the
//! same trait when refreshing Ferrum's own SVID.
//!
//! The trait is `async` because most real implementations talk to a remote
//! service (Vault, K8s certificates.k8s.io, SPIRE). The internal CA
//! ([`internal::InternalCa`]) is the synchronous reference implementation.

pub mod bootstrap;
pub mod internal;
pub mod spire;
pub mod upstream;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::fmt;
use std::sync::Arc;

use crate::identity::spiffe::{SpiffeId, TrustDomain};
use crate::identity::{RedactedPrivateKeyDer, SvidPrivateKeyDer};

/// A signed X.509 SVID, returned by [`CertificateAuthority::sign_workload_csr`].
#[derive(Clone)]
pub struct SignedSvid {
    /// The SPIFFE ID encoded into the URI SAN of `cert_chain[0]`.
    pub spiffe_id: SpiffeId,
    /// Leaf-first DER-encoded X.509 chain. Length ≥ 1.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// PKCS#8 DER-encoded private key for `cert_chain[0]`.
    pub private_key_pkcs8_der: SvidPrivateKeyDer,
    /// notAfter for the leaf certificate. Used by the rotation task.
    pub not_after: DateTime<Utc>,
}

impl fmt::Debug for SignedSvid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedSvid")
            .field("spiffe_id", &self.spiffe_id)
            .field("cert_chain_der", &self.cert_chain_der)
            .field("private_key_pkcs8_der", &RedactedPrivateKeyDer)
            .field("not_after", &self.not_after)
            .finish()
    }
}

/// A request to issue an SVID. Either a CSR (preferred — workload retains
/// its private key) or a key-included form (used by the streaming Workload
/// API where the agent generates the key on the workload's behalf).
#[derive(Debug, Clone)]
pub enum IssuanceRequest {
    /// Workload-supplied CSR. The CA parses, validates, and signs it.
    Csr {
        /// DER-encoded PKCS#10 CSR.
        csr_der: Vec<u8>,
        /// Caller-attested SPIFFE ID. The CA verifies the CSR public key
        /// matches and overwrites/inserts the URI SAN with this ID — never
        /// trusts a SAN claim coming from the CSR itself.
        spiffe_id: SpiffeId,
        /// Requested SVID lifetime. The CA may shorten this.
        ttl_secs: u64,
    },
    /// Workload API: the workload identifies itself via attestation only and
    /// asks the CA to generate both the key and the certificate. Used in
    /// SPIRE-style flows.
    Generate { spiffe_id: SpiffeId, ttl_secs: u64 },
}

/// A trust bundle entry as published by the CA.
#[derive(Debug, Clone)]
pub struct PublishedTrustBundle {
    pub trust_domain: TrustDomain,
    /// DER-encoded CA certificates that workloads should treat as roots when
    /// validating peer SVIDs in this trust domain.
    pub roots_der: Vec<Vec<u8>>,
    /// Suggested re-fetch interval. `None` ⇒ fetch on rotation only.
    pub refresh_hint_secs: Option<u64>,
}

/// A JWT signing authority published by the CA for JWT-SVID validation.
#[derive(Debug, Clone)]
pub struct PublishedJwtAuthority {
    pub trust_domain: TrustDomain,
    pub key_id: String,
    pub public_key_pem: String,
}

/// A certificate authority capable of issuing SVIDs and publishing trust
/// material.
///
/// Implementations are share-nothing — the Workload API server holds an
/// `Arc<dyn CertificateAuthority>` and clones it for each request.
#[async_trait]
pub trait CertificateAuthority: Send + Sync + 'static {
    /// Issue an SVID. The CA enforces all policy: it never trusts the
    /// SPIFFE ID claim from a CSR's existing SAN — the caller-passed
    /// [`IssuanceRequest::Csr::spiffe_id`] is authoritative because the
    /// caller has already attested the workload.
    async fn issue_svid(&self, req: IssuanceRequest) -> Result<SignedSvid, CaError>;

    /// Publish the trust bundle for a domain. For internal CAs this is the
    /// self-signed root; for SPIRE-backed CAs this is fetched from the SPIRE
    /// server.
    async fn trust_bundle(&self, td: &TrustDomain) -> Result<PublishedTrustBundle, CaError>;

    /// Publish JWKS authorities for JWT-SVID validation. May be empty when
    /// the CA does not mint JWT-SVIDs.
    async fn jwt_authorities(
        &self,
        td: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError>;
}

/// Errors raised by [`CertificateAuthority`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("CA configuration error: {0}")]
    Config(String),
    #[error("CSR rejected: {0}")]
    BadCsr(String),
    #[error("trust domain '{0}' is not served by this CA")]
    UnknownTrustDomain(String),
    #[error("upstream CA error: {0}")]
    Upstream(String),
    #[error("internal CA error: {0}")]
    Internal(String),
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for CaError {
    fn from(e: std::io::Error) -> Self {
        CaError::Io(e.to_string())
    }
}

/// Boxed trait object alias used by the workload-API server.
pub type SharedCa = Arc<dyn CertificateAuthority>;

/// Selects which CA backend to use at startup.
///
/// Parsed from `FERRUM_MESH_CA_BACKEND`. The default is `None` (no CA
/// configured — mesh identity features are disabled).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CaBackend {
    /// Ferrum's own internal CA (root cert + key on disk).
    Internal,
    /// Delegate to a SPIRE Agent over the Workload API UDS.
    SpireAgent,
    /// No CA — identity subsystem is inactive.
    #[default]
    None,
}

impl CaBackend {
    /// Parse from an env-var-style string. Case-insensitive. Returns
    /// `Err` for unrecognised values so the operator gets a clear error at
    /// startup.
    pub fn from_str_lossy(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "internal" => Ok(Self::Internal),
            "spire" | "spire_agent" | "spire-agent" => Ok(Self::SpireAgent),
            "none" | "" => Ok(Self::None),
            other => Err(format!(
                "unknown FERRUM_MESH_CA_BACKEND '{other}'; \
                 expected one of: internal, spire, none"
            )),
        }
    }
}

impl std::fmt::Display for CaBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => f.write_str("internal"),
            Self::SpireAgent => f.write_str("spire"),
            Self::None => f.write_str("none"),
        }
    }
}
