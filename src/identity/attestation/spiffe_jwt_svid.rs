//! Cross-cluster federation attestor.
//!
//! When a workload presents a JWT-SVID minted by a federated trust domain,
//! we validate it against the federated bundle's JWKS and accept the SPIFFE
//! ID claim only if it actually belongs to the JWKS's trust domain.
//!
//! The actual JWT validation is delegated — Phase A wires up the trait and
//! a usable validator interface; later phases hook this into Ferrum's
//! existing JWKS cache (`src/plugins/jwks_auth.rs` already has one).

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use super::{AttestError, Attestor, PeerInfo, WorkloadIdentity};
use crate::identity::spiffe::{SpiffeId, TrustDomain};

/// JWKS validator interface — pluggable so tests don't need real keys.
#[allow(clippy::double_must_use)] // async-trait adds a bare #[must_use]
#[async_trait]
pub trait JwtSvidValidator: Send + Sync + 'static {
    /// Validate a JWT-SVID and return the embedded SPIFFE ID.
    ///
    /// Implementations MUST:
    /// - check the signature against a JWKS for the SVID's trust domain;
    /// - check `exp` (jsonwebtoken's `validate_exp = true` is required by the
    ///   global code-quality rule);
    /// - check `aud` against the configured audience;
    /// - return the `sub` claim parsed as a [`SpiffeId`].
    async fn validate(&self, jwt: &str, audience: &str) -> Result<SpiffeId, String>;
}

/// Configuration for the JWT-SVID federation attestor.
pub struct JwtSvidAttestorConfig {
    /// Federated trust domains the attestor accepts.
    pub federated_trust_domains: Vec<TrustDomain>,
    /// Audience the JWT-SVID must target.
    pub audience: String,
    pub validator: Arc<dyn JwtSvidValidator>,
}

/// JWT-SVID federation attestor.
pub struct JwtSvidAttestor {
    config: JwtSvidAttestorConfig,
}

impl JwtSvidAttestor {
    pub fn new(config: JwtSvidAttestorConfig) -> Result<Self, AttestError> {
        if config.audience.is_empty() {
            return Err(AttestError::Config(
                "audience must not be empty".to_string(),
            ));
        }
        if config.federated_trust_domains.is_empty() {
            return Err(AttestError::Config(
                "federation attestor requires at least one federated trust domain".to_string(),
            ));
        }
        Ok(Self { config })
    }
}

#[async_trait]
impl Attestor for JwtSvidAttestor {
    fn kind(&self) -> &'static str {
        "spiffe_jwt_svid"
    }

    async fn attest(&self, peer: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
        let token = peer
            .bearer_token
            .as_ref()
            .ok_or(AttestError::NotApplicable)?;
        if !looks_like_jwt(token) {
            return Err(AttestError::NotApplicable);
        }

        let id = self
            .config
            .validator
            .validate(token, &self.config.audience)
            .await
            .map_err(AttestError::Failed)?;

        let in_federated = self
            .config
            .federated_trust_domains
            .iter()
            .any(|td| td == id.trust_domain());
        if !in_federated {
            return Err(AttestError::Failed(format!(
                "SPIFFE ID '{}' is not in any federated trust domain",
                id
            )));
        }

        let mut selectors = HashMap::new();
        selectors.insert(
            "federated:trust-domain".to_string(),
            id.trust_domain().to_string(),
        );
        Ok(WorkloadIdentity {
            spiffe_id: id,
            selectors,
            attestor_kind: self.kind().to_string(),
        })
    }
}

/// Cheap heuristic: a JWT has exactly two `.` separators. Good enough to
/// distinguish a JWT-shaped token from random opaque bearer tokens before
/// handing the value to the validator.
///
/// **K8s PSAT tokens are also JWTs and pass this heuristic.** The
/// federation attestor cannot tell them apart by shape. The attestor chain
/// must therefore order K8s PSAT BEFORE the JWT-SVID federation attestor
/// when both are configured: the K8s attestor will either consume the
/// token (returning an identity) or reject it as `NotApplicable` /
/// `Failed`, and the chain runner moves to the next attestor. Reversing
/// the order would cause federation to attempt validating in-cluster SA
/// tokens against federated trust-domain JWKS, fail, and shadow the K8s
/// path.
fn looks_like_jwt(s: &str) -> bool {
    s.matches('.').count() == 2
}
