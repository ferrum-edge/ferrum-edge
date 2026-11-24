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
//! - [`ca`] — `CertificateAuthority` trait, Ferrum's internal CA, and the
//!   SPIRE agent adapter.
//! - [`jwt_svid`] — SPIFFE JWT-SVID mint / validate / JWKS bundles for the
//!   Workload API's three JWT RPCs.
//! - [`rotation`] — timing helpers for the internal mesh CA's SVID rotation
//!   loop (`src/modes/mesh/mod.rs`), which hot-swaps the gateway SVID slot via
//!   `ArcSwap` for the lock-free TLS-resolver path.
//! - [`svid_source_watch`] — polls the configured gateway SVID material
//!   sources (files and external providers) and republishes the bundle when
//!   material bytes or configured source identity change (provider version
//!   metadata alone does not).
//!
//! Mesh mode wires the Workload API / internal rotation pieces into the
//! gateway SVID slot when `FERRUM_MESH_CA_BACKEND` is enabled. The TLS builders
//! [`crate::tls::build_spiffe_inbound_config`] and
//! [`crate::tls::build_spiffe_outbound_config`] remain the shared lower-level
//! APIs for SPIFFE-aware listeners and clients.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use zeroize::Zeroizing;

pub mod attestation;
pub mod ca;
pub mod file_loader;
pub mod jwt_svid;
pub mod rotation;
pub mod spiffe;
pub mod svid_source_watch;
pub mod workload_api;

#[allow(unused_imports)]
pub use attestation::{Attestor, PeerInfo, WorkloadIdentity};
#[allow(unused_imports)]
pub use ca::{CaBackend, CertificateAuthority, SharedCa};
#[allow(unused_imports)]
pub use spiffe::{SpiffeId, SpiffeIdError, TrustDomain, TrustDomainError};

/// Every identity guardrail flag, all read only from the process environment.
/// [`validate_guardrail_env`] checks each one, so a value the strict parser
/// refuses fails startup instead of being read as a different posture.
pub const IDENTITY_GUARDRAIL_ENV_KEYS: [&str; 5] = [
    "FERRUM_MESH_PRODUCTION_MODE",
    "FERRUM_MESH_ALLOW_NO_CA",
    "FERRUM_MESH_ALLOW_STATIC_ID",
    "FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY",
    "FERRUM_MESH_CA_BOOTSTRAP_DEV",
];

/// The one truthy rule for the identity guardrail flags (issue #7237): the
/// repo-wide strict boolean parser (`true`/`false`/`1`/`0`, trimmed,
/// case-insensitive). Unset or blank is `None`. A non-UTF-8 value or any other
/// spelling is an error, never a silent `false`, because a typo in
/// `FERRUM_MESH_PRODUCTION_MODE` would otherwise switch production off.
///
/// Each caller passes its own `std::env::var(KEY)` read, so every flag keeps
/// exactly one literal reader.
pub fn parse_guardrail_flag(
    key: &str,
    read: Result<String, std::env::VarError>,
) -> Result<Option<bool>, String> {
    use crate::config::env_config::EnvValue;
    match read {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!(
            "Invalid {key} value: not valid UTF-8. Expected true, false, 1, or 0"
        )),
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        Ok(raw) => bool::parse_env(&raw, key).map(Some),
    }
}

/// Refuse any identity guardrail flag the strict parser rejects. Called from
/// `EnvConfig` validation, so `run` and `validate` fail before a typo can be
/// read as a different posture.
pub fn validate_guardrail_env() -> Result<(), String> {
    for key in IDENTITY_GUARDRAIL_ENV_KEYS {
        parse_guardrail_flag(key, std::env::var(key))?;
    }
    Ok(())
}

/// Read a dev opt-in: only an explicit truthy value opts in. An invalid value
/// (refused at startup by [`validate_guardrail_env`]) stays opted out.
pub(crate) fn guardrail_opt_in(key: &str, read: Result<String, std::env::VarError>) -> bool {
    matches!(parse_guardrail_flag(key, read), Ok(Some(true)))
}

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
///
/// Parsed with [`parse_guardrail_flag`]. An invalid value reads as `true`
/// (fail closed); `EnvConfig` validation refuses it before startup anyway.
pub fn production_mode() -> bool {
    match parse_guardrail_flag(
        "FERRUM_MESH_PRODUCTION_MODE",
        std::env::var("FERRUM_MESH_PRODUCTION_MODE"),
    ) {
        Ok(flag) => flag.unwrap_or(false),
        Err(_) => true,
    }
}

/// Canonical read of the `FERRUM_MESH_ALLOW_NO_CA` dev opt-in — the per-posture
/// sibling to `FERRUM_MESH_CA_BOOTSTRAP_DEV` / `FERRUM_MESH_ALLOW_STATIC_ID`.
///
/// When `true`, a `mesh` data plane with **no workload identity at all** (no
/// file-based gateway SVID material) is permitted to start with an insecure
/// plaintext inbound posture (dev/test only). This is consulted only by the
/// config-time no-identity gate in [`crate::config::EnvConfig`] validation — the
/// runtime inbound-TLS fail-closed enforcement in `src/modes/mesh` does **not**
/// read it: by the time that gate runs, a no-identity posture in dev has already
/// been acknowledged here, so the runtime gate keys purely on [`production_mode`]
/// (a configured-but-broken SVID, distinct from "no identity", is a hard error
/// there regardless of this opt-out).
///
/// Like [`production_mode`] it is read directly from the environment —
/// intentionally **not** parsed into `EnvConfig` — so a config-file-only value
/// can never re-open the posture. The config-time gate checks [`production_mode`]
/// first: this opt-out is ignored unconditionally under
/// `FERRUM_MESH_PRODUCTION_MODE=true` (see `.claude/rules/tls-security.md`; do not
/// collapse the per-posture opt-ins into one flag). Parsed with
/// [`parse_guardrail_flag`].
pub fn allow_no_ca() -> bool {
    guardrail_opt_in(
        "FERRUM_MESH_ALLOW_NO_CA",
        std::env::var("FERRUM_MESH_ALLOW_NO_CA"),
    )
}

/// Canonical read of the `FERRUM_MESH_ALLOW_STATIC_ID` dev opt-in.
///
/// This remains a direct environment-only guardrail and is always disabled in
/// production. Keeping the read here lets configuration validation and the
/// runtime [`attestation::static_id::StaticAttestor`] agree about whether the
/// fallback attestor is actually available. Parsed with
/// [`parse_guardrail_flag`].
pub fn allow_static_id() -> bool {
    if production_mode() {
        return false;
    }
    guardrail_opt_in(
        "FERRUM_MESH_ALLOW_STATIC_ID",
        std::env::var("FERRUM_MESH_ALLOW_STATIC_ID"),
    )
}

/// Canonical read of the `FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY` dev opt-in — the
/// per-posture sibling to `FERRUM_MESH_CA_BOOTSTRAP_DEV` /
/// `FERRUM_MESH_ALLOW_STATIC_ID` / `FERRUM_MESH_ALLOW_NO_CA`.
///
/// When `true` and no JWT signing material is configured, the internal CA's JWT
/// authority generates a **process-local** ES256 key. That key is lost on
/// restart and differs on every replica, so tokens minted moments earlier stop
/// validating and two instances of one trust domain publish different JWKS —
/// dev/test only. With this unset and nothing configured, JWT-SVID mint is
/// refused at startup rather than minting tokens nothing can verify.
///
/// Like [`production_mode`] / [`allow_no_ca`] it is read directly from the
/// environment — intentionally **not** parsed into `EnvConfig`, which would both
/// let a config-file-only value re-open the posture and put the setting on
/// surfaces `EnvConfig` values are re-rendered on. It is refused unconditionally
/// under `FERRUM_MESH_PRODUCTION_MODE=true` (see `.claude/rules/tls-security.md`;
/// do not collapse the per-posture opt-ins into one flag). Parsed with
/// [`parse_guardrail_flag`].
pub fn allow_ephemeral_jwt_key() -> bool {
    if production_mode() {
        return false;
    }
    guardrail_opt_in(
        "FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY",
        std::env::var("FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY"),
    )
}

/// The configured JWT signing key PEM for the local trust domain, if any.
///
/// Read directly from the environment — **not** through `EnvConfig` — for two
/// independent reasons: the external-secret suffixes (`_VAULT`, `_AWS`,
/// `_AZURE`, `_GCP`, `_FILE`) have already rewritten the base variable by the
/// time this runs, and a private key must not be held on a struct whose values
/// are re-rendered onto the `validate` report and startup log surfaces. The value
/// is returned in a [`Zeroizing`] buffer and is never logged, echoed in an error,
/// or included in a `Debug` rendering.
///
/// A blank value is treated as absent, matching `EnvConfig`'s blank-is-unset
/// convention for optional settings.
pub fn jwt_signing_key_pem() -> Option<Zeroizing<String>> {
    env_pem("FERRUM_MESH_JWT_SIGNING_KEY_PEM")
}

/// The previous JWT signing key PEM, published for **verification only**.
///
/// Set this to the outgoing primary across a JWT signing-key rotation so tokens
/// it signed stay verifiable for their whole permitted lifetime while the new
/// primary takes over. Same handling rules as [`jwt_signing_key_pem`].
pub fn jwt_previous_signing_key_pem() -> Option<Zeroizing<String>> {
    env_pem("FERRUM_MESH_JWT_PREVIOUS_SIGNING_KEY_PEM")
}

/// Read a PEM-valued environment variable into a zeroizing buffer.
///
/// Uses `var_os` so a non-UTF-8 value is a *rejection* rather than a panic; an
/// undecodable value is reported as absent here and the startup env-secret
/// screen already fails closed on a non-Unicode `FERRUM_*` value, so it cannot
/// silently become "no key configured" without a diagnostic elsewhere.
fn env_pem(key: &str) -> Option<Zeroizing<String>> {
    let raw = std::env::var_os(key)?;
    let value = raw.into_string().ok()?;
    if value.trim().is_empty() {
        return None;
    }
    Some(Zeroizing::new(value))
}

/// A single fetched X.509-SVID with its surrounding trust material.
///
/// Hot-swapped by [`workload_api::fetch_loop`] / [`rotation`] via `ArcSwap`
/// so concurrent readers never observe a partial swap.
pub type SvidPrivateKeyDer = Zeroizing<Vec<u8>>;

pub(crate) struct RedactedPrivateKeyDer;

impl fmt::Debug for RedactedPrivateKeyDer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Clone)]
pub struct SvidBundle {
    pub spiffe_id: SpiffeId,
    /// Leaf-first DER-encoded chain (length ≥ 1).
    pub cert_chain_der: Vec<Vec<u8>>,
    /// PKCS#8 / DER-encoded private key for `cert_chain_der[0]`.
    pub private_key_pkcs8_der: SvidPrivateKeyDer,
    /// Local trust anchors for this SVID's trust domain plus any federated
    /// bundles relevant to peers we expect to communicate with.
    pub trust_bundles: TrustBundleSet,
}

impl fmt::Debug for SvidBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SvidBundle")
            .field("spiffe_id", &self.spiffe_id)
            .field("cert_chain_der", &self.cert_chain_der)
            .field("private_key_pkcs8_der", &RedactedPrivateKeyDer)
            .field("trust_bundles", &self.trust_bundles)
            .finish()
    }
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
///
/// `PartialEq` is the "is this the same authority" predicate the gateway trust
/// publication uses to tell an ADDED root from a WITHDRAWN one
/// (`proxy::mesh_trust_registry::trust_withdrawal_reason`), so it must stay a
/// comparison of the material itself, never of the key id alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtAuthority {
    pub key_id: String,
    pub public_key_pem: String,
}

/// Shared bundle slot type used by both fetch_loop and rotation.
pub type SharedSvidBundle = Arc<arc_swap::ArcSwap<Option<SvidBundle>>>;
