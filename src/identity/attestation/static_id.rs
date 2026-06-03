//! Dev-only static identity attestor.
//!
//! Returns a hard-coded SPIFFE ID for any peer. Useful in lab and unit-test
//! setups where wiring up a real attestor would be overkill, but **MUST NOT
//! be used in production** — the attestor performs zero proof of identity.
//!
//! Two safety gates control construction:
//!
//! - `FERRUM_MESH_PRODUCTION_MODE=true` ⇒ refuse unconditionally.
//! - `FERRUM_MESH_ALLOW_STATIC_ID=true` ⇒ explicit opt-in. Anything else ⇒ refuse.

use async_trait::async_trait;
use std::collections::HashMap;
use std::env;

use super::{AttestError, Attestor, PeerInfo, WorkloadIdentity};
use crate::identity::spiffe::SpiffeId;

/// Configuration for the static attestor.
#[derive(Debug, Clone)]
pub struct StaticAttestorConfig {
    pub spiffe_id: SpiffeId,
}

/// Static attestor.
pub struct StaticAttestor {
    spiffe_id: SpiffeId,
}

impl StaticAttestor {
    pub fn new(config: StaticAttestorConfig) -> Result<Self, AttestError> {
        if crate::identity::production_mode() {
            return Err(AttestError::Config(
                "FERRUM_MESH_PRODUCTION_MODE=true — refusing to construct StaticAttestor"
                    .to_string(),
            ));
        }
        let opt_in = env::var("FERRUM_MESH_ALLOW_STATIC_ID")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !opt_in {
            return Err(AttestError::Config(
                "FERRUM_MESH_ALLOW_STATIC_ID is not 'true' — StaticAttestor is dev-only \
                 and refuses to construct without explicit opt-in"
                    .to_string(),
            ));
        }
        Ok(Self {
            spiffe_id: config.spiffe_id,
        })
    }
}

#[async_trait]
impl Attestor for StaticAttestor {
    fn kind(&self) -> &'static str {
        "static"
    }

    async fn attest(&self, _peer: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
        Ok(WorkloadIdentity {
            spiffe_id: self.spiffe_id.clone(),
            selectors: HashMap::new(),
            attestor_kind: self.kind().to_string(),
        })
    }
}
