//! Unix-socket peer-credentials attestor.
//!
//! Reads `SO_PEERCRED` (PID/UID/GID) on the Unix domain socket the workload
//! API server is listening on, then walks `/proc/<pid>/exe` and computes a
//! SHA-256 fingerprint of the binary. Operators map the kernel-attested UID
//! to a SPIFFE ID via static config. A binary fingerprint may only strengthen
//! a UID-bound rule; it is never accepted as a principal on its own.
//!
//! Linux-first: macOS exposes `LOCAL_PEERPID` but not `LOCAL_PEEREUID` for
//! arbitrary sockets, and Windows has no equivalent. On non-Linux, the
//! attestor returns [`AttestError::NotApplicable`] so callers can fall back
//! to other attestors.

use async_trait::async_trait;
use std::collections::HashMap;

#[cfg(target_os = "linux")]
use crate::fips::approved::Sha256;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use super::{AttestError, Attestor, PeerInfo, WorkloadIdentity};
use crate::identity::spiffe::{SpiffeId, TrustDomain};

/// One mapping rule.
#[derive(Debug, Clone)]
pub struct UnixIdentityRule {
    /// If set, the rule matches only when the peer UID is this value.
    pub require_uid: Option<u32>,
    /// If set, the rule matches only when the peer's binary SHA-256 matches.
    pub require_binary_sha256: Option<String>,
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
            require_uid: Some(uid),
            require_binary_sha256: None,
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
            if rule.require_uid.is_none() {
                return Err(AttestError::Config(
                    "unix attestor rules must bind the workload identity to a kernel-attested uid"
                        .to_string(),
                ));
            }
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

        // UID-only policies are the common Workload API posture and must not
        // read or hash the caller's executable at all. When a binary selector
        // is configured, keep the blocking filesystem read and SHA-256 work off
        // Tokio's executor threads so a large peer binary cannot stall unrelated
        // RPCs on the runtime.
        #[cfg(target_os = "linux")]
        let binary_sha256 = if self
            .config
            .rules
            .iter()
            .any(|rule| rule.require_binary_sha256.is_some())
        {
            match pid {
                Some(p) if p > 0 => {
                    tokio::task::spawn_blocking(move || binary_fingerprint_linux(p))
                        .await
                        .map_err(|error| {
                            AttestError::Io(format!("binary fingerprint worker failed: {error}"))
                        })??
                }
                _ => None,
            }
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let binary_sha256: Option<String> = None;

        for rule in &self.config.rules {
            let uid_ok = match rule.require_uid {
                Some(expected) => uid == Some(expected),
                None => true,
            };
            let bin_ok = match &rule.require_binary_sha256 {
                Some(expected) => binary_sha256.as_deref() == Some(expected.as_str()),
                None => true,
            };
            if uid_ok && bin_ok {
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
                if let Some(ref sha) = binary_sha256 {
                    selectors.insert("unix:binary-sha256".to_string(), sha.clone());
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

// PERF/SECURITY (Phase B caching deferral):
//
// The current implementation reads `/proc/<pid>/exe` and SHA-256s the entire
// binary on every attestation. Two concerns to resolve before the unix
// attestor sees production sidecar load:
//
//   - **TOCTOU**: an exec-after-attestation race lets a workload swap its
//     binary between the attestation read and the SVID issuance. The pid is
//     the same, but the binary the cert authorises is not the binary that
//     gets to use it.
//   - **DoS**: a 100 MB binary hashed under attestation churn is slow. Binary
//     hashing is dispatched through the blocking pool and is skipped entirely
//     for UID-only rules, but repeated binary-selector attestations still spend
//     CPU and I/O until the cache below exists.
//
// Phase B should cache fingerprints by `(pid, dev, ino, mtime)` with a TTL
// so repeat attestations are O(1) and post-fork cert reissuance does not
// re-hash. The Workload API is a local Unix-socket surface rather than an HTTP
// plugin path, so it must not claim ordinary request plugins rate-limit this
// work; operators using binary selectors should restrict the socket mode/group
// and prefer UID selectors where that is sufficient.
#[cfg(target_os = "linux")]
fn binary_fingerprint_linux(pid: i32) -> Result<Option<String>, AttestError> {
    let exe = PathBuf::from(format!("/proc/{}/exe", pid));
    // Open the procfs link itself so the descriptor pins the executable inode
    // selected by the kernel. Resolving it to a pathname and reopening that
    // pathname would introduce a second lookup and could hash a replacement.
    let mut file = match std::fs::File::open(&exe) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(e) => {
            return Err(AttestError::Io(format!(
                "failed to open /proc/{}/exe: {}",
                pid, e
            )));
        }
    };
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            AttestError::Io(format!(
                "failed to read the executable for peer pid {pid}: {error}"
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Some(hex::encode(hasher.finalize())))
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn binary_fingerprint_linux(_pid: i32) -> Result<Option<String>, AttestError> {
    Ok(None)
}
