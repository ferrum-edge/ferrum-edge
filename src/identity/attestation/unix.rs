//! Unix-socket peer-credentials attestor.
//!
//! Uses the `SO_PEERCRED` PID/UID/GID the workload-API server read from its
//! Unix domain socket. Operators map the kernel-attested UID to a SPIFFE ID via
//! static config (`FERRUM_MESH_WORKLOAD_API_UNIX_IDENTITY_RULES`); every rule is
//! bound to exactly one UID.
//!
//! Linux-first: macOS exposes `LOCAL_PEERPID` but not `LOCAL_PEEREUID` for
//! arbitrary sockets, and Windows has no equivalent. On non-Linux, the
//! attestor returns [`AttestError::NotApplicable`] so callers can fall back
//! to other attestors.

use async_trait::async_trait;
use std::collections::HashMap;

use super::{AttestError, Attestor, PeerInfo, WorkloadIdentity};
use crate::identity::spiffe::{SpiffeId, TrustDomain};

/// One mapping rule.
#[derive(Debug, Clone)]
pub struct UnixIdentityRule {
    /// The rule matches only when the kernel-attested peer UID is this value.
    pub require_uid: u32,
    /// SPIFFE ID to assign on match. Must be in the configured trust domain.
    pub spiffe_id: SpiffeId,
}

/// Configuration for the unix-peer attestor.
#[derive(Debug, Clone)]
pub struct UnixAttestorConfig {
    pub trust_domain: TrustDomain,
    pub rules: Vec<UnixIdentityRule>,
}

/// Parse one Unix peer-identity mapping rule.
///
/// Accepted forms bind kernel-attested evidence to exactly one SPIFFE ID in
/// the local trust domain:
///
/// - `uid:<uid>=spiffe://<trust-domain>/<path>`
///
/// Diagnostics describe the expected shape without echoing the configured
/// value, which may have been populated with credential-like text by mistake.
pub fn parse_identity_rule(
    entry: &str,
    trust_domain: &TrustDomain,
) -> Result<UnixIdentityRule, AttestError> {
    let (selector, spiffe_id) = entry.split_once('=').ok_or_else(|| {
        AttestError::Config(
            "FERRUM_MESH_WORKLOAD_API_UNIX_IDENTITY_RULES entries must be \
             'uid:<uid>=<spiffe-id>'"
                .to_string(),
        )
    })?;
    let spiffe_id = SpiffeId::new(spiffe_id.trim().to_string()).map_err(|_| {
        AttestError::Config(
            "a FERRUM_MESH_WORKLOAD_API_UNIX_IDENTITY_RULES entry does not name a valid SPIFFE ID"
                .to_string(),
        )
    })?;
    if spiffe_id.trust_domain() != trust_domain {
        return Err(AttestError::Config(format!(
            "a FERRUM_MESH_WORKLOAD_API_UNIX_IDENTITY_RULES entry names a SPIFFE ID outside the \
             local trust domain '{trust_domain}'"
        )));
    }

    let selector = selector.trim();
    if let Some(uid) = selector.strip_prefix("uid:") {
        let uid: u32 = uid.trim().parse().map_err(|_| {
            AttestError::Config(
                "a FERRUM_MESH_WORKLOAD_API_UNIX_IDENTITY_RULES 'uid:' selector is not a numeric uid"
                    .to_string(),
            )
        })?;
        return Ok(UnixIdentityRule {
            require_uid: uid,
            spiffe_id,
        });
    }
    if selector.starts_with("sha256:") {
        return Err(AttestError::Config(
            "FERRUM_MESH_WORKLOAD_API_UNIX_IDENTITY_RULES does not accept sha256-only selectors; \
             bind every workload identity to a kernel-attested uid"
                .to_string(),
        ));
    }
    Err(AttestError::Config(
        "a FERRUM_MESH_WORKLOAD_API_UNIX_IDENTITY_RULES selector must start with 'uid:'"
            .to_string(),
    ))
}

/// Unix-socket peer-credentials attestor.
pub struct UnixAttestor {
    config: UnixAttestorConfig,
}

impl UnixAttestor {
    pub fn new(config: UnixAttestorConfig) -> Result<Self, AttestError> {
        if config.rules.is_empty() {
            return Err(AttestError::Config(
                "unix attestor requires at least one rule".to_string(),
            ));
        }
        for rule in &config.rules {
            if rule.spiffe_id.trust_domain() != &config.trust_domain {
                return Err(AttestError::Config(format!(
                    "rule SPIFFE ID '{}' is outside the configured trust domain '{}'",
                    rule.spiffe_id, config.trust_domain
                )));
            }
        }
        Ok(Self { config })
    }
}

#[async_trait]
impl Attestor for UnixAttestor {
    fn kind(&self) -> &'static str {
        "unix"
    }

    async fn attest(&self, peer: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
        // We need at minimum a PID or UID; without those there's nothing to
        // match against.
        if peer.pid.is_none() && peer.uid.is_none() {
            return Err(AttestError::NotApplicable);
        }

        let pid = peer.pid;
        let uid = peer.uid;

        for rule in &self.config.rules {
            if uid == Some(rule.require_uid) {
                let mut selectors = HashMap::new();
                if let Some(p) = pid {
                    selectors.insert("unix:pid".to_string(), p.to_string());
                }
                if let Some(u) = uid {
                    selectors.insert("unix:uid".to_string(), u.to_string());
                }
                if let Some(g) = peer.gid {
                    selectors.insert("unix:gid".to_string(), g.to_string());
                }
                return Ok(WorkloadIdentity {
                    spiffe_id: rule.spiffe_id.clone(),
                    selectors,
                    attestor_kind: self.kind().to_string(),
                });
            }
        }

        Err(AttestError::Failed(
            "no unix attestor rule matched the peer".to_string(),
        ))
    }
}
