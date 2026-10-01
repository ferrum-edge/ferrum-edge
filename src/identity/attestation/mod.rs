//! Workload attestation — proving that the peer asking for an SVID is who
//! it says it is.
//!
//! Each attestor consumes some piece of identity material gathered from the
//! transport layer (Unix socket peer creds, mTLS peer certificate, projected
//! K8s SA token) and returns the SPIFFE ID the workload is allowed to claim.
//!
//! Attestors are layered so a workload-API server can run several in
//! parallel: K8s PSAT for K8s pods, Unix peer-creds for VM workloads, and a
//! cross-cluster federated JWT-SVID attestor for foreign trust domains.
//!
//! The trait is intentionally opaque on the input side — every attestor
//! consumes the same [`PeerInfo`] struct; the parts it cares about (PID,
//! peer cert, projected token) live as `Option`s so callers do not have to
//! teach the trait about every new transport.

pub mod k8s_psat;
pub mod spiffe_jwt_svid;
pub mod static_id;
pub mod unix;

use async_trait::async_trait;
use std::collections::HashMap;

use crate::identity::spiffe::SpiffeId;

/// Information the workload-API server has gathered about its peer at the
/// transport layer. Plumbed into every attestor.
#[derive(Debug, Default, Clone)]
pub struct PeerInfo {
    /// `SO_PEERCRED` PID, where supported.
    pub pid: Option<i32>,
    /// `SO_PEERCRED` UID, where supported.
    pub uid: Option<u32>,
    /// `SO_PEERCRED` GID, where supported.
    pub gid: Option<u32>,
    /// DER-encoded peer certificate (mTLS terminator paths).
    pub peer_cert_der: Option<Vec<u8>>,
    /// Caller-supplied bearer token (e.g. K8s projected SA token presented
    /// in a metadata field).
    pub bearer_token: Option<String>,
    /// Free-form metadata for transports that need to ship additional info
    /// (e.g. socket path, namespace hint).
    pub metadata: HashMap<String, String>,
}

/// Identity returned by a successful attestation.
#[derive(Debug, Clone)]
pub struct WorkloadIdentity {
    pub spiffe_id: SpiffeId,
    /// Free-form selectors (labels, tags) extracted by the attestor —
    /// useful for downstream policy evaluation.
    pub selectors: HashMap<String, String>,
    /// Human-readable summary of which attestor produced this identity.
    pub attestor_kind: String,
}

/// Errors raised by attestors.
#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("attestor not applicable to this peer")]
    NotApplicable,
    #[error("attestation failed: {0}")]
    Failed(String),
    #[error("attestor configuration invalid: {0}")]
    Config(String),
    #[error("attestor I/O error: {0}")]
    Io(String),
}

/// A workload attestor.
#[allow(clippy::double_must_use)] // async-trait adds a bare #[must_use]
#[async_trait]
pub trait Attestor: Send + Sync + 'static {
    /// Short kind identifier, e.g. "k8s_psat", "unix", "static".
    fn kind(&self) -> &'static str;

    /// Attest the peer. `Err(AttestError::NotApplicable)` signals that the
    /// caller should try the next attestor in its chain.
    async fn attest(&self, peer: &PeerInfo) -> Result<WorkloadIdentity, AttestError>;
}

/// Run a chain of attestors, returning the first successful identity. If every
/// attestor declines (`NotApplicable`), returns an aggregate failure.
///
/// Hard attestor failures are intentionally non-terminal: a K8s PSAT failure
/// records diagnostic context, but a later Unix peer-creds or static-dev
/// attestor may still succeed. This matches Ferrum's existing multi-auth
/// first-success-wins model and SPIRE-style selector composition. Operators
/// who need terminal rejection should configure mutually exclusive attestor
/// chains for that listener instead of mixing fallback identity sources.
pub async fn attest_chain(
    attestors: &[std::sync::Arc<dyn Attestor>],
    peer: &PeerInfo,
) -> Result<WorkloadIdentity, AttestError> {
    if attestors.is_empty() {
        return Err(AttestError::Config(
            "no attestors configured for the workload-API server".to_string(),
        ));
    }
    let mut last_failure: Option<AttestError> = None;
    for attestor in attestors {
        match attestor.attest(peer).await {
            Ok(id) => return Ok(id),
            Err(AttestError::NotApplicable) => continue,
            Err(other) => {
                last_failure = Some(other);
            }
        }
    }
    Err(last_failure.unwrap_or(AttestError::Failed("all attestors declined".to_string())))
}
