//! Mesh identity subsystem (Phase A — additive).
//!
//! The identity module is the SPIFFE-compatible foundation that every later
//! mesh layer composes against:
//!
//! - [`spiffe`] — SPIFFE primitives: trust domains, SPIFFE IDs, URI-SAN encoding.
//! - [`workload_api`] — gRPC client + server for the SPIFFE Workload API
//!   over Unix domain sockets.
//! - [`attestation`] — pluggable workload attestors (K8s PSAT, Unix peer
//!   creds, JWT-SVID federation, dev-only static identity).
//! - [`ca`] — `CertificateAuthority` trait + Ferrum's internal CA + wrappers
//!   for delegating to Vault PKI / cert-manager / SPIRE.
//! - [`rotation`] — background task that renews SVIDs and hot-swaps via
//!   `ArcSwap` for the lock-free TLS-resolver path.
//!
//! Phase A only **builds** these layers; nothing is wired into existing
//! listeners yet. The TLS builders [`crate::tls::build_spiffe_inbound_config`]
//! and [`crate::tls::build_spiffe_outbound_config`] expose ready-to-use APIs
//! for Phase C.

use std::collections::HashMap;
use std::sync::Arc;

pub mod attestation;
pub mod ca;
pub mod file_loader;
pub mod rotation;
pub mod spiffe;
pub mod workload_api;

#[allow(unused_imports)]
pub use attestation::{Attestor, PeerInfo, WorkloadIdentity};
#[allow(unused_imports)]
pub use ca::{CaBackend, CertificateAuthority, SharedCa};
#[allow(unused_imports)]
pub use spiffe::{SpiffeId, SpiffeIdError, TrustDomain, TrustDomainError};

/// Canonical read of the master mesh production guardrail
/// (`FERRUM_MESH_PRODUCTION_MODE`).
///
/// When `true`, identity-less / dev-only mesh postures are refused
/// unconditionally: the self-signed CA bootstrap ([`ca::bootstrap::bootstrap_dev_root`]),
/// the [`attestation::static_id::StaticAttestor`], and a `CaBackend::None` mesh
/// data plane (enforced in `EnvConfig` validation). Like the other identity
/// guardrails it is read directly from the environment — intentionally not
/// parsed into `EnvConfig` — so it stays readable before config load. The
/// per-posture dev opt-ins (`FERRUM_MESH_CA_BOOTSTRAP_DEV`,
/// `FERRUM_MESH_ALLOW_STATIC_ID`, `FERRUM_MESH_ALLOW_NO_CA`) stay separate and
/// must not be collapsed (see `.claude/rules/tls-security.md`).
pub fn production_mode() -> bool {
    std::env::var("FERRUM_MESH_PRODUCTION_MODE")
        .map(|v| {
            // Accept the same truthy spellings as `EnvConfig`'s bool parser
            // (`true` / `1`, case-insensitive) so a guardrail can't be bypassed
            // by a common boolean form.
            let v = v.trim();
            v.eq_ignore_ascii_case("true") || v == "1"
        })
        .unwrap_or(false)
}

/// A single fetched X.509-SVID with its surrounding trust material.
///
/// Hot-swapped by [`workload_api::fetch_loop`] / [`rotation`] via `ArcSwap`
/// so concurrent readers never observe a partial swap.
#[derive(Debug, Clone)]
pub struct SvidBundle {
    pub spiffe_id: SpiffeId,
    /// Leaf-first DER-encoded chain (length ≥ 1).
    pub cert_chain_der: Vec<Vec<u8>>,
    /// PKCS#8 / DER-encoded private key for `cert_chain_der[0]`.
    pub private_key_pkcs8_der: Vec<u8>,
    /// Local trust anchors for this SVID's trust domain plus any federated
    /// bundles relevant to peers we expect to communicate with.
    pub trust_bundles: TrustBundleSet,
}

impl SvidBundle {
    /// The trust domain this SVID belongs to.
    pub fn trust_domain(&self) -> &TrustDomain {
        self.spiffe_id.trust_domain()
    }
}

/// The complete set of trust bundles a workload trusts: a "local" bundle
/// for its own trust domain plus a map of federated bundles, keyed by
/// trust domain.
#[derive(Debug, Clone)]
pub struct TrustBundleSet {
    pub local: TrustBundle,
    pub federated: HashMap<TrustDomain, TrustBundle>,
}

impl Default for TrustBundleSet {
    fn default() -> Self {
        Self {
            local: TrustBundle {
                trust_domain: TrustDomain::new("ferrum.local")
                    .expect("ferrum.local is a valid trust domain"),
                x509_authorities: Vec::new(),
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: HashMap::new(),
        }
    }
}

impl TrustBundleSet {
    /// Convenience constructor that wraps a single trust bundle in a set.
    pub fn local_only(local: TrustBundle) -> Self {
        Self {
            local,
            federated: HashMap::new(),
        }
    }

    /// Look up a trust bundle by trust domain. Returns `Some(&self.local)`
    /// if `td` matches the local trust domain, otherwise consults the
    /// federated map.
    pub fn get(&self, td: &TrustDomain) -> Option<&TrustBundle> {
        if td == &self.local.trust_domain {
            Some(&self.local)
        } else {
            self.federated.get(td)
        }
    }
}

/// CA / verifier material for a trust domain.
///
/// `x509_authorities` is the set of DER-encoded root CA certs that anchor
/// SVID chains in this trust domain. `jwt_authorities` is the set of
/// public-key entries used to validate JWT-SVIDs.
#[derive(Debug, Clone)]
pub struct TrustBundle {
    pub trust_domain: TrustDomain,
    pub x509_authorities: Vec<Vec<u8>>,
    pub jwt_authorities: Vec<JwtAuthority>,
    pub refresh_hint_seconds: Option<u64>,
}

/// A JWKS-style entry used to validate JWT-SVIDs.
#[derive(Debug, Clone)]
pub struct JwtAuthority {
    pub key_id: String,
    pub public_key_pem: String,
}

/// Shared bundle slot type used by both fetch_loop and rotation.
pub type SharedSvidBundle = Arc<arc_swap::ArcSwap<Option<SvidBundle>>>;
