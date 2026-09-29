//! Durable hard-upgrade guard for Ambient UDP placement changes (#3703).
//!
//! The readiness handshake (`.udp-ready` -> `.udp-ack-required` ->
//! `.udp-not-ready`) remains the datapath safety boundary. This module adds the
//! durable node-local ownership/generation record which prevents a replacement
//! process from starting a different producer until an explicit cleanup phase
//! has retired the predecessor's exact Ferrum-owned state.

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::config::conf_file::resolve_ferrum_var;

const STATE_FILE: &str = ".udp-placement-state-v1.json";
/// Node-scoped proof that an ownership-safe predecessor retirement ran to
/// completion on THIS node incarnation. Written only by the privileged node
/// preflight (`ferrum-edge ambient-udp-preflight`) after both predecessor
/// placements were retired, and consulted only when the durable placement
/// record is absent. A release-level attestation is desired state; this file is
/// the node-specific evidence that desired state is safe to adopt here.
const NODE_PROOF_FILE: &str = ".udp-node-cleanup-proof-v1.json";
/// Operator-written, node-bound exemption for a node that is intentionally
/// decommissioned or exempt from the preflight (for example a cluster that will
/// not grant the preflight's setns privileges). It carries the same node
/// identity binding as the proof, so it can never be copied to another node or
/// survive the incarnation it was written for.
const NODE_EXEMPT_FILE: &str = ".udp-placement-node-exempt";
/// Operator-written tombstone recording that node-local ownership was
/// quarantined as corrupt/unknown. Its presence means "absent state is NOT
/// evidence of a fresh node", so it refuses every stable bootstrap from absent
/// state — including a release-attested adoption — until an explicit
/// cleanup/finalize pair has proven predecessor state retired.
const QUARANTINE_FILE: &str = ".udp-placement-quarantined";
const REGISTRY_SYNC_FILE: &str = ".udp-registry-synced";
const MAX_STATE_BYTES: u64 = 4096;
const MAX_NODE_ATTESTATION_BYTES: u64 = 1024;
const MAX_GENERATION_BYTES: usize = 64;
/// Decimal digits allowed in the node-proof generation's era ordinal. Ten
/// digits cover every `u32` era the placement contract can reach, so the bound
/// is a parse guard rather than a policy limit.
const MAX_NODE_PROOF_ERA_DIGITS: usize = 10;
const MAX_NODE_IDENTIFIER_BYTES: usize = 128;
/// Current node incarnation identifier. A reboot changes it, and every pod
/// network namespace that could hold predecessor interception rules dies with
/// the previous incarnation, so a change is itself proof that no predecessor
/// pod-netns rule can survive.
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const MAX_REGISTRY_SYNC_MARKER_BYTES: u64 = 256;
const MAX_REGISTRY_SYNC_ENTRIES: usize = 100_000;
const MAX_TEMP_DIRECTORY_ENTRIES_SCANNED_PER_WRITE: usize = 4096;
const MAX_TEMP_FILES_REAPED_PER_WRITE: usize = 16;
const MIN_CRASH_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdpPlacement {
    PodNetns,
    HostNetns,
    Disabled,
}

impl UdpPlacement {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PodNetns => "pod-netns",
            Self::HostNetns => "host-netns",
            Self::Disabled => "disabled",
        }
    }

    pub const fn from_capture_settings(enabled: bool, host_netns: bool) -> Self {
        if !enabled {
            Self::Disabled
        } else if host_netns {
            Self::HostNetns
        } else {
            Self::PodNetns
        }
    }

    fn parse(raw: &str, variable: &str) -> Result<Self, String> {
        match raw.trim() {
            "pod-netns" => Ok(Self::PodNetns),
            "host-netns" => Ok(Self::HostNetns),
            "disabled" => Ok(Self::Disabled),
            _ => Err(format!(
                "{variable} must be one of pod-netns, host-netns, or disabled"
            )),
        }
    }
}

/// The exact machine + incarnation a placement decision is bound to.
///
/// `node_uid` is the IMMUTABLE Kubernetes `Node.metadata.uid`, never the node
/// name: a reused node name on a rebuilt machine gets a fresh UID, so it can
/// never inherit the predecessor's proof. `boot_id` is the kernel's current
/// boot identifier, so proof written before a reboot cannot authorize the
/// incarnation after it (and vice versa).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpNodeIdentity {
    pub node_uid: String,
    pub boot_id: String,
}

impl UdpNodeIdentity {
    pub fn new(node_uid: &str, boot_id: &str) -> Result<Self, String> {
        let identity = Self {
            node_uid: node_uid.trim().to_string(),
            boot_id: boot_id.trim().to_string(),
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Resolve this node's identity from the deployment surface.
    ///
    /// The boot id is always read locally — it is the one half no other process
    /// can attest for this incarnation. The node UID comes from an explicit
    /// `FERRUM_K8S_NODE_UID` (GitOps/client-render pipelines that already know
    /// it) or, failing that, from the node-agent's published identity file in
    /// the shared pod-registry directory: the Kubernetes downward API does not
    /// expose the node UID, and the proxy holds no Kubernetes client, so the
    /// node-agent is the only local publisher of it. A published file is only
    /// honoured when the boot id it recorded is THIS incarnation's, so a file
    /// surviving on a persistent registry path cannot carry a stale UID
    /// forward.
    ///
    /// An unresolvable identity is not an error here: it leaves the caller with
    /// NO node-specific evidence, which every proof-requiring branch treats as
    /// a fail-closed refusal.
    ///
    /// A publication surviving from a PREVIOUS Kubernetes Node object on this
    /// same boot would pass the boot-id check, so the publisher retracts its
    /// file before it can fail (`retract_node_identity`) rather than relying on
    /// this reader to detect staleness it cannot see.
    pub fn resolve(registry_dir: &Path) -> Option<Self> {
        let boot_id = current_boot_id()?;
        if let Some(node_uid) =
            resolve_ferrum_var("FERRUM_K8S_NODE_UID").filter(|value| !value.trim().is_empty())
            && let Ok(identity) = Self::new(&node_uid, &boot_id)
        {
            return Some(identity);
        }
        Self::resolve_published(registry_dir, &boot_id)
    }

    /// The published-file half of `resolve`, taking this incarnation's boot id
    /// explicitly so the publication boundary is decidable without a
    /// process-wide environment read or a `/proc` lookup.
    pub fn resolve_published(registry_dir: &Path, boot_id: &str) -> Option<Self> {
        let published = read_node_identity_file(registry_dir)?;
        (published.boot_id.as_str() == boot_id.trim()).then_some(published)
    }

    fn validate(&self) -> Result<(), String> {
        validate_node_identifier(&self.node_uid, "Kubernetes node UID")?;
        validate_node_identifier(&self.boot_id, "node boot id")
    }
}

fn current_boot_id() -> Option<String> {
    let boot_id_path = resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_NODE_BOOT_ID_PATH")
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| BOOT_ID_PATH.to_string());
    read_bounded_identifier(Path::new(boot_id_path.trim()))
}

const NODE_IDENTITY_FILE: &str = ".node-identity-v1.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeIdentityRecord {
    version: u8,
    node_uid: String,
    boot_id: String,
}

fn read_node_identity_file(registry_dir: &Path) -> Option<UdpNodeIdentity> {
    let path = registry_dir.join(NODE_IDENTITY_FILE);
    let file = open_owned_regular_file(&path, MAX_NODE_ATTESTATION_BYTES).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_NODE_ATTESTATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_NODE_ATTESTATION_BYTES {
        return None;
    }
    let record: NodeIdentityRecord = serde_json::from_slice(&bytes).ok()?;
    if record.version != 1 {
        return None;
    }
    UdpNodeIdentity::new(&record.node_uid, &record.boot_id).ok()
}

/// Publish this node's immutable Kubernetes UID, paired with the boot id it was
/// observed under, into the shared pod-registry directory. Called by the
/// node-agent, which is the only local process with a Kubernetes client.
pub fn publish_node_identity(registry_dir: &Path, node_uid: &str) -> Result<(), String> {
    let boot_id =
        current_boot_id().ok_or_else(|| "could not read this node's boot id".to_string())?;
    publish_node_identity_for(registry_dir, &UdpNodeIdentity::new(node_uid, &boot_id)?)
}

/// Publish an ALREADY-RESOLVED node identity. `publish_node_identity` is the
/// production entry point (it pairs a Kubernetes UID with this incarnation's
/// boot id); this is the incarnation-explicit form, so the retract/publish
/// boundary can be decided without reading `/proc`.
pub fn publish_node_identity_for(
    registry_dir: &Path,
    identity: &UdpNodeIdentity,
) -> Result<(), String> {
    identity.validate()?;
    let identity = identity.clone();
    if read_node_identity_file(registry_dir).as_ref() == Some(&identity) {
        return Ok(());
    }
    std::fs::create_dir_all(registry_dir)
        .map_err(|error| format!("could not create Ambient UDP registry directory: {error}"))?;
    let bytes = serde_json::to_vec(&NodeIdentityRecord {
        version: 1,
        node_uid: identity.node_uid,
        boot_id: identity.boot_id,
    })
    .map_err(|error| format!("could not encode the node identity record: {error}"))?;
    atomic_write(
        registry_dir,
        &registry_dir.join(NODE_IDENTITY_FILE),
        NODE_IDENTITY_FILE,
        &bytes,
        "node identity record",
    )
}

/// Retract this node's published identity so NO node-identity file remains.
///
/// The publisher calls this BEFORE it consults Kubernetes, and again after any
/// failure. A file left by a PREVIOUS Kubernetes Node object on this same boot
/// names a UID this incarnation cannot vouch for, and `resolve` accepts it
/// because the boot id it records IS the current one — so a Node deleted and
/// recreated under the same name could otherwise inherit its predecessor's
/// durable ownership and node-cleanup proof whenever the replacement
/// node-agent failed to read or publish its own UID.
///
/// The removal is narrowly scoped to the exact publication file, never follows
/// a symlink (`remove_file` unlinks the link itself), handles a directory entry
/// explicitly so a crash-left or hostile entry of any type is retracted rather
/// than skipped, and is made durable with a directory sync before the caller
/// can publish or fail.
pub fn retract_node_identity(registry_dir: &Path) -> Result<(), String> {
    retract_registry_file(registry_dir, NODE_IDENTITY_FILE, "node identity")
}

/// Remove any node-scoped cleanup proof left on this registry directory.
///
/// The privileged preflight calls this BEFORE it retires anything, so a proof
/// published by an earlier run — under a previous Kubernetes Node object, an
/// earlier era, or an interrupted pass — cannot survive alongside a retirement
/// this run has not yet completed. Combined with the preflight's own
/// authoritative node-UID lookup and its placement as an init container in the
/// steady-state container's OWN pod, that means the proof a steady-state
/// container reads is always the one its OWN pod's init stage published.
pub fn retract_node_cleanup_proof(registry_dir: &Path) -> Result<(), String> {
    retract_registry_file(registry_dir, NODE_PROOF_FILE, "node cleanup proof")
}

/// After a deadline wins a raced proof publication, make sure no *usable*
/// cleanup attestation remains. A clean retract is preferred; if unlink/sync
/// fails, overwrite the visible file with a record no reader will treat as
/// proof. The caller still returns a deadline outcome (never completion) and
/// must report any retraction/invalidation failure rather than claiming the
/// owned tree was cleaned up.
pub fn withhold_node_cleanup_proof_after_deadline(registry_dir: &Path) -> Result<(), String> {
    match retract_node_cleanup_proof(registry_dir) {
        Ok(()) => Ok(()),
        Err(retract_error) => {
            if !node_cleanup_proof_is_usable(registry_dir) {
                return Err(format!(
                    "node cleanup proof retraction failed ({retract_error}); no usable attestation remains"
                ));
            }
            match invalidate_node_cleanup_proof(registry_dir) {
                Ok(()) if !node_cleanup_proof_is_usable(registry_dir) => Err(format!(
                    "node cleanup proof retraction failed ({retract_error}); the visible file was invalidated so it cannot authorize adoption"
                )),
                Ok(()) => Err(format!(
                    "could not retract ({retract_error}) the node cleanup proof after the deadline, and invalidation left a usable attestation"
                )),
                Err(invalidate_error) if node_cleanup_proof_is_usable(registry_dir) => {
                    Err(format!(
                        "could not retract ({retract_error}) or invalidate ({invalidate_error}) the node cleanup proof after the deadline; a usable attestation may remain"
                    ))
                }
                Err(invalidate_error) => Err(format!(
                    "node cleanup proof retraction failed ({retract_error}); invalidation also failed ({invalidate_error}) but no usable attestation remains"
                )),
            }
        }
    }
}

fn node_cleanup_proof_is_usable(registry_dir: &Path) -> bool {
    matches!(
        read_node_attestation(registry_dir, NODE_PROOF_FILE),
        Ok(Some(_))
    )
}

fn invalidate_node_cleanup_proof(registry_dir: &Path) -> Result<(), String> {
    atomic_write(
        registry_dir,
        &registry_dir.join(NODE_PROOF_FILE),
        NODE_PROOF_FILE,
        b"{\"version\":0}",
        "invalidated node cleanup proof",
    )
}

/// Remove one exact registry publication, durably.
///
/// The removal is narrowly scoped to the exact pathname, never follows a
/// symlink (`remove_file` unlinks the link itself), handles a directory entry
/// explicitly so a crash-left or hostile entry of any type is retracted rather
/// than skipped, and is made durable with a directory sync before the caller
/// can publish or fail.
fn retract_registry_file(registry_dir: &Path, file: &str, description: &str) -> Result<(), String> {
    let path = registry_dir.join(file);
    let removal = match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_dir() => std::fs::remove_dir(&path),
        Ok(_) => std::fs::remove_file(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => Err(error),
    };
    match removal {
        Ok(()) => {}
        // A concurrent publisher already achieved the desired state.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "could not retract the published Ambient UDP {description}: {error}"
            ));
        }
    }
    sync_directory(registry_dir).map_err(|error| {
        format!("could not sync the Ambient UDP {description} retraction: {error}")
    })
}

/// Resolve this node's identity AUTHORITATIVELY, then republish it.
///
/// This is the privileged preflight's resolver, and it deliberately does NOT
/// share `UdpNodeIdentity::resolve`'s published-file fallback. A
/// `.node-identity-v1.json` left by a PREVIOUS Kubernetes Node object on this
/// same boot records the CURRENT boot id, so no reader can tell it from a live
/// one — and the replacement node-agent may not have started (let alone
/// retracted it) by the time this stage runs, because the two DaemonSets have
/// no startup ordering between them. Consuming that file would let the preflight
/// pair a stale identity with the stale cleanup proof written under it and
/// authorize node-name reuse under the wrong immutable UID.
///
/// So the preflight asks the API server itself, bound to the node name the
/// downward API gave this pod, and the ordering is what makes every failure
/// path safe:
///
/// 1. retract the publication FIRST, before anything that can fail — a failure
///    to retract aborts before any lookup, because a surviving stale file is
///    exactly what must not be trusted;
/// 2. read this incarnation's boot id only AFTER that retraction, so an
///    unreadable `/proc` (or override path) cannot leave a predecessor's
///    publication in place;
/// 3. resolve the UID (explicit `FERRUM_K8S_NODE_UID` for client-render
///    pipelines, otherwise one bounded `get` on this node's own object);
/// 4. publish only the resolved identity, and retract again on any failure.
///
/// Every unsuccessful path therefore leaves NO published identity, which the
/// placement guard treats as a fail-closed refusal, and the successful path
/// leaves an identity this run proved against the API server immediately before
/// the steady-state container in the same pod starts.
pub async fn resolve_authoritative_node_identity<F, Fut>(
    registry_dir: &Path,
    explicit_node_uid: Option<&str>,
    node_name: Option<&str>,
    fetch_node_uid: F,
) -> Result<UdpNodeIdentity, String>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    resolve_authoritative_node_identity_reading_boot_id(
        registry_dir,
        explicit_node_uid,
        node_name,
        fetch_node_uid,
        current_boot_id,
    )
    .await
}

/// Retract first, then obtain the boot id, then continue through
/// [`resolve_authoritative_node_identity_with_boot_id`].
///
/// The public resolver passes `current_boot_id`. Tests pass a closure that
/// returns `None` to prove an unreadable boot id cannot leave a stale
/// publication behind. There is no compatibility fallback that skips
/// retraction when the boot id cannot be read.
pub async fn resolve_authoritative_node_identity_reading_boot_id<F, Fut, B>(
    registry_dir: &Path,
    explicit_node_uid: Option<&str>,
    node_name: Option<&str>,
    fetch_node_uid: F,
    read_boot_id: B,
) -> Result<UdpNodeIdentity, String>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
    B: FnOnce() -> Option<String>,
{
    retract_node_identity(registry_dir)?;
    let Some(boot_id) = read_boot_id().filter(|value| !value.trim().is_empty()) else {
        let _ = retract_node_identity(registry_dir);
        return Err("could not read this node's boot id".to_string());
    };
    resolve_authoritative_node_identity_with_boot_id(
        registry_dir,
        &boot_id,
        explicit_node_uid,
        node_name,
        fetch_node_uid,
    )
    .await
}

/// The incarnation-explicit form of [`resolve_authoritative_node_identity`], so
/// the retract/lookup/publish boundary is decidable without a `/proc` read.
pub async fn resolve_authoritative_node_identity_with_boot_id<F, Fut>(
    registry_dir: &Path,
    boot_id: &str,
    explicit_node_uid: Option<&str>,
    node_name: Option<&str>,
    fetch_node_uid: F,
) -> Result<UdpNodeIdentity, String>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    retract_node_identity(registry_dir)?;
    let resolved = match resolve_authoritative_node_uid(explicit_node_uid, node_name) {
        Ok(NodeUidSource::Explicit(node_uid)) => Ok(node_uid),
        Ok(NodeUidSource::Lookup(node_name)) => fetch_node_uid(node_name).await,
        Err(error) => Err(error),
    }
    .and_then(|node_uid| UdpNodeIdentity::new(&node_uid, boot_id));
    let identity = match resolved {
        Ok(identity) => identity,
        Err(error) => {
            let _ = retract_node_identity(registry_dir);
            return Err(error);
        }
    };
    if let Err(error) = publish_node_identity_for(registry_dir, &identity) {
        // A partially published record must not outlive the failure that
        // produced it: the next reader cannot tell it from a proven one.
        let _ = retract_node_identity(registry_dir);
        return Err(error);
    }
    Ok(identity)
}

enum NodeUidSource {
    Explicit(String),
    Lookup(String),
}

fn resolve_authoritative_node_uid(
    explicit_node_uid: Option<&str>,
    node_name: Option<&str>,
) -> Result<NodeUidSource, String> {
    if let Some(node_uid) = parse_explicit_k8s_node_uid(explicit_node_uid)? {
        return Ok(NodeUidSource::Explicit(node_uid));
    }
    node_name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|node_name| NodeUidSource::Lookup(node_name.to_string()))
        .ok_or_else(|| {
            "resolving this node's Kubernetes UID requires its node name; set FERRUM_K8S_NODE_NAME from the downward API `spec.nodeName` (or supply FERRUM_K8S_NODE_UID directly)"
                .to_string()
        })
}

/// Parse an operator-supplied `FERRUM_K8S_NODE_UID`.
///
/// `None` means the variable is unset (callers may fall back to a bounded node
/// GET). A present empty or malformed value is fail-closed: it is not treated
/// as absent, and the returned error never includes the supplied value.
pub fn parse_explicit_k8s_node_uid(raw: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(
            "FERRUM_K8S_NODE_UID is set but empty; refusing to resolve a node identity without a valid UID"
                .to_string(),
        );
    }
    validate_node_identifier(trimmed, "Kubernetes node UID")?;
    Ok(Some(trimmed.to_string()))
}

fn validate_node_identifier(value: &str, description: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_NODE_IDENTIFIER_BYTES
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "{description} must be 1..={MAX_NODE_IDENTIFIER_BYTES} ASCII alphanumeric/./_/- bytes and start alphanumeric"
        ));
    }
    Ok(())
}

/// Read a single-line identifier from a bounded, owned regular file. Used for
/// the kernel boot id, which is a UUID line.
fn read_bounded_identifier(path: &Path) -> Option<String> {
    let file = open_owned_regular_file(path, MAX_NODE_ATTESTATION_BYTES).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_NODE_ATTESTATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_NODE_ATTESTATION_BYTES {
        return None;
    }
    let value = String::from_utf8(bytes).ok()?;
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// Node-scoped, bounded evidence file. Used for both the preflight-written
/// cleanup proof and the operator-written exemption; they differ only in who
/// authors them and in the status they produce, never in how strictly they are
/// bound to this node incarnation, target, and generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeAttestation {
    version: u8,
    node: UdpNodeIdentity,
    target: UdpPlacement,
    generation: String,
}

/// Why a node with no same-incarnation durable record was allowed to start the
/// incoming producer. Bounded and fixed-cardinality: it never carries a node
/// identity, path, generation, or any other operator-supplied value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpAdoptionProof {
    /// No adoption happened: the node is running from its own durable record
    /// written by this incarnation, or no placement decision has been made yet.
    None,
    /// A durable record written by an EARLIER boot of this same node UID. Every
    /// predecessor pod network namespace died with that incarnation.
    NewBoot,
    /// The privileged node preflight retired both predecessor placements on
    /// this exact node UID + boot id and published its completion marker.
    NodeCleanup,
    /// An operator explicitly exempted this node incarnation from the preflight
    /// (decommissioned or otherwise known to carry no predecessor state).
    OperatorExempt,
}

impl UdpAdoptionProof {
    const fn code(self) -> u8 {
        self as u8
    }

    const fn from_code(value: u8) -> Self {
        match value {
            1 => Self::NewBoot,
            2 => Self::NodeCleanup,
            3 => Self::OperatorExempt,
            _ => Self::None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::NewBoot => "new_boot",
            Self::NodeCleanup => "node_cleanup",
            Self::OperatorExempt => "operator_exempt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpMigrationPhase {
    Stable,
    Cleanup,
    Finalize,
}

impl UdpMigrationPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Cleanup => "cleanup",
            Self::Finalize => "finalize",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPlacementRequest {
    pub phase: UdpMigrationPhase,
    pub target: UdpPlacement,
    pub generation: Option<String>,
    pub from: Option<UdpPlacement>,
    pub to: Option<UdpPlacement>,
    /// Release-level attestation that this placement was already established by
    /// a COMPLETED earlier migration release, so a node carrying no durable
    /// record of its own has no predecessor state to retire.
    ///
    /// The chart derives it from the INSTALLED placement ConfigMap and renders
    /// it only when the previously installed contract already recorded this
    /// exact target in a `stable`/`finalize` phase — never during the release
    /// that performs the change. It is consulted ONLY when the node-local
    /// durable record is absent; a present record that disagrees with the
    /// requested placement is still a hard rejection.
    ///
    /// It is DESIRED STATE, never authorization (issue #3809). A release-level
    /// object records no node identity, no node incarnation, and no per-node
    /// cleanup result, so on its own it can never authorize a recordless
    /// same-boot node whose running workloads may still carry predecessor
    /// interception rules. It is necessary but not sufficient: node-specific
    /// proof (`node` + a matching node attestation, or a durable record from an
    /// earlier boot of this same node UID) must agree.
    pub established: Option<UdpPlacement>,
    /// This node's immutable Kubernetes UID plus its current boot/incarnation
    /// id. `None` means the deployment supplied no node identity, which is a
    /// fail-closed refusal for every branch that needs node-specific proof.
    pub node: Option<UdpNodeIdentity>,
    /// The node-proof generation this release expects. A node attestation
    /// written under any other generation is stale and never authorizes this
    /// release, so an interrupted or superseded migration cannot be replayed
    /// into a later one.
    pub node_proof_generation: Option<String>,
}

impl UdpPlacementRequest {
    pub fn from_env(target: UdpPlacement, registry_dir: &Path) -> Result<Self, String> {
        let phase_raw = resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_MIGRATION_PHASE")
            .unwrap_or_else(|| "stable".to_string());
        let phase = match phase_raw.trim() {
            "stable" => UdpMigrationPhase::Stable,
            "cleanup" => UdpMigrationPhase::Cleanup,
            "finalize" => UdpMigrationPhase::Finalize,
            _ => {
                return Err(
                    "FERRUM_MESH_CAPTURE_UDP_MIGRATION_PHASE must be stable, cleanup, or finalize"
                        .to_string(),
                );
            }
        };
        let generation = resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_MIGRATION_GENERATION")
            .filter(|value| !value.trim().is_empty());
        let from = resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_MIGRATION_FROM")
            .filter(|value| !value.trim().is_empty())
            .map(|value| UdpPlacement::parse(&value, "FERRUM_MESH_CAPTURE_UDP_MIGRATION_FROM"))
            .transpose()?;
        let to = resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_MIGRATION_TO")
            .filter(|value| !value.trim().is_empty())
            .map(|value| UdpPlacement::parse(&value, "FERRUM_MESH_CAPTURE_UDP_MIGRATION_TO"))
            .transpose()?;
        // Parsed (and therefore validated) in every phase so a typo is a startup
        // error rather than a silently inert attestation, but only CONSULTED by
        // the stable arm below: cleanup/finalize decide from durable ownership.
        let established = resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED")
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                UdpPlacement::parse(&value, "FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED")
            })
            .transpose()?;

        if phase == UdpMigrationPhase::Stable {
            if generation.is_some() || from.is_some() || to.is_some() {
                return Err(
                    "stable Ambient UDP placement must omit FERRUM_MESH_CAPTURE_UDP_MIGRATION_GENERATION/FROM/TO"
                        .to_string(),
                );
            }
        } else {
            let Some(value) = generation.as_deref() else {
                return Err(format!(
                    "FERRUM_MESH_CAPTURE_UDP_MIGRATION_GENERATION is required during {}",
                    phase.as_str()
                ));
            };
            validate_generation(value)?;
            let Some(from) = from else {
                return Err(
                    "FERRUM_MESH_CAPTURE_UDP_MIGRATION_FROM is required during migration"
                        .to_string(),
                );
            };
            let Some(to) = to else {
                return Err(
                    "FERRUM_MESH_CAPTURE_UDP_MIGRATION_TO is required during migration".to_string(),
                );
            };
            if from == to {
                return Err("Ambient UDP migration FROM and TO must differ".to_string());
            }
            if to != target {
                return Err(format!(
                    "Ambient UDP migration TO={} does not match the requested placement {}",
                    to.as_str(),
                    target.as_str()
                ));
            }
        }

        Ok(Self {
            phase,
            target,
            generation,
            from,
            to,
            established,
            node: UdpNodeIdentity::resolve(registry_dir),
            node_proof_generation: node_proof_generation_from_env()?,
        })
    }

    fn transition(&self) -> Option<UdpMigrationTransition> {
        Some(UdpMigrationTransition {
            generation: self.generation.clone()?,
            from: self.from?,
            to: self.to?,
        })
    }
}

/// The release-bound node-proof generation.
///
/// The chart derives it from the placement contract's PERSISTED
/// `nodeProofGeneration`, which is stamped when a migration starts and then
/// carried forward unchanged through finalize and every settled release after
/// it. That is what makes a superseded attestation detectable as stale.
pub fn node_proof_generation_from_env() -> Result<Option<String>, String> {
    let value = resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION")
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string());
    if let Some(value) = value.as_deref() {
        validate_node_proof_generation(value)?;
    }
    Ok(value)
}

const NODE_PROOF_GENERATION_SHAPE: &str = "FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION must be an era-qualified `e<era>.<migration generation>` token of 1..=64 ASCII alphanumeric/./_/- bytes, where <era> is a 1..=10 digit ordinal with no leading zero";

/// Validate the ERA-QUALIFIED node-proof generation.
///
/// A node attestation is only stale-detectable when the generation it is bound
/// to cannot RECUR. A token derived from the release's observable placement
/// shape — `<target>-<phase>`, say — repeats the moment a target and phase
/// recur, so an attestation written for an old `host-netns` era would authorize
/// a later one after the cluster migrated host -> pod -> host (issue #3809).
///
/// The shape is therefore `e<era>.<migration generation>`, where `<era>` is a
/// strictly increasing decimal ordinal the placement contract increments at
/// every cleanup start and then persists through finalize and every settled
/// release after it. The ordinal alone guarantees non-recurrence; the operator's
/// own migration generation rides along so a proof stays traceable to the
/// transition that produced it.
///
/// This is enforced at the runtime boundary, not only in the chart, so a
/// client-render/GitOps pipeline supplying the variable directly is held to the
/// same non-recurrence contract as a Helm-rendered one.
pub fn validate_node_proof_generation(value: &str) -> Result<(), String> {
    validate_generation(value).map_err(|_| NODE_PROOF_GENERATION_SHAPE.to_string())?;
    let Some(rest) = value.strip_prefix('e') else {
        return Err(NODE_PROOF_GENERATION_SHAPE.to_string());
    };
    let Some((era, generation)) = rest.split_once('.') else {
        return Err(NODE_PROOF_GENERATION_SHAPE.to_string());
    };
    if era.is_empty()
        || era.len() > MAX_NODE_PROOF_ERA_DIGITS
        || era.starts_with('0')
        || !era.bytes().all(|byte| byte.is_ascii_digit())
        || generation.is_empty()
    {
        return Err(NODE_PROOF_GENERATION_SHAPE.to_string());
    }
    Ok(())
}

/// The generation the node-agent publishes its registry-synchronization marker
/// under, and the one every consumer of that marker must require. An explicit
/// migration generation always wins; otherwise the stable release's node-proof
/// generation carries it, so the node preflight can obtain the SAME authoritative
/// registry proof outside a cleanup/finalize rollout.
pub fn registry_sync_generation_from_env() -> Result<Option<String>, String> {
    match migration_generation_from_env()? {
        Some(generation) => Ok(Some(generation)),
        None => node_proof_generation_from_env(),
    }
}

fn validate_generation(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_GENERATION_BYTES
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(
            "FERRUM_MESH_CAPTURE_UDP_MIGRATION_GENERATION must be 1..=64 ASCII alphanumeric/./_/- bytes and start alphanumeric"
                .to_string(),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UdpMigrationTransition {
    generation: String,
    from: UdpPlacement,
    to: UdpPlacement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingMigration {
    transition: UdpMigrationTransition,
    cleanup_both: bool,
    cleanup_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurablePlacementState {
    version: u8,
    active: UdpPlacement,
    pending: Option<PendingMigration>,
    completed: Option<UdpMigrationTransition>,
    /// The node incarnation that last wrote this record. A PRESENT identity
    /// whose node UID disagrees with this machine is a hard rejection, so a
    /// registry directory restored from a backup or reused under a recycled
    /// node name can never hand its ownership to a different machine.
    ///
    /// ABSENT means the record asserts no owning node at all — a pre-#3809
    /// record, or one written by a process that could not resolve an identity.
    /// That is NOT a compatibility escape hatch: an already-present unbound
    /// record can never be ADOPTED for a placement that runs a producer (see
    /// `prepare_placement`'s stable arm). Only `disabled` — which owns no
    /// producer and carries no traffic — stays adoptable, and it is bound as
    /// soon as an identity is resolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    incarnation: Option<UdpNodeIdentity>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct UdpRegistrySyncProof {
    generation: String,
    publication: uuid::Uuid,
    /// The Kubernetes node UID the publishing node-agent resolved
    /// AUTHORITATIVELY for this incarnation, when it could resolve one.
    ///
    /// The marker lives on a persistent registry path, so one left by the
    /// node-agent of a PREVIOUS Kubernetes Node object survives that object's
    /// deletion and names a pod inventory this node no longer has. Carrying the
    /// publisher's node UID lets the privileged preflight refuse it instead of
    /// retiring predecessor rules against a stale enumeration; the migration
    /// cleanup phase, which already decides from durable node-bound ownership,
    /// keeps consuming the marker on generation alone.
    node_uid: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrySyncMarker {
    version: u8,
    generation: String,
    publication: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    node_uid: Option<String>,
}

/// Accumulates repeated cleanup passes only while one exact inter-process
/// registry publication remains continuously current.
pub struct UdpCleanupProofWindow {
    cleanup_pod_netns: bool,
    cleanup_host_netns: bool,
    proof: Option<UdpRegistrySyncProof>,
    last_complete_fingerprint: Option<u64>,
    host_complete_passes: u8,
}

pub struct UdpCleanupProofProgress {
    proof: Option<UdpRegistrySyncProof>,
    host_complete: bool,
    pod_complete: bool,
}

impl UdpCleanupProofProgress {
    pub const fn proof_is_valid(&self) -> bool {
        self.proof.is_some()
    }

    pub const fn host_complete(&self) -> bool {
        self.host_complete
    }

    pub const fn pod_complete(&self) -> bool {
        self.pod_complete
    }

    pub fn completion_proof(&self) -> Option<&UdpRegistrySyncProof> {
        if self.host_complete() && self.pod_complete() {
            self.proof.as_ref()
        } else {
            None
        }
    }
}

impl UdpCleanupProofWindow {
    pub const fn new(cleanup_pod_netns: bool, cleanup_host_netns: bool) -> Self {
        Self {
            cleanup_pod_netns,
            cleanup_host_netns,
            proof: None,
            last_complete_fingerprint: None,
            host_complete_passes: 0,
        }
    }

    pub fn invalidate(&mut self) {
        self.proof = None;
        self.last_complete_fingerprint = None;
        self.host_complete_passes = 0;
    }

    /// Count one host/pod cleanup pass only when the same proof was visible
    /// before and after it. A new proof starts a new repeated-pass window; a
    /// missing or changed after-proof discards every signal from this pass.
    pub fn observe_pass(
        &mut self,
        proof_before: Option<UdpRegistrySyncProof>,
        proof_after: Option<UdpRegistrySyncProof>,
        host_pass_complete: bool,
        pod_complete_fingerprint: Option<u64>,
    ) -> UdpCleanupProofProgress {
        let Some(proof_before) = proof_before else {
            self.invalidate();
            return self.incomplete_progress();
        };
        if self.proof.as_ref() != Some(&proof_before) {
            self.invalidate();
            self.proof = Some(proof_before.clone());
        }
        if proof_after.as_ref() != Some(&proof_before) {
            self.invalidate();
            return self.incomplete_progress();
        }

        if self.cleanup_host_netns {
            if host_pass_complete {
                self.host_complete_passes = self.host_complete_passes.saturating_add(1);
            } else {
                self.host_complete_passes = 0;
            }
        }

        let pod_complete = if self.cleanup_pod_netns {
            if let Some(fingerprint) = pod_complete_fingerprint {
                let complete = self.last_complete_fingerprint == Some(fingerprint);
                self.last_complete_fingerprint = Some(fingerprint);
                complete
            } else {
                self.last_complete_fingerprint = None;
                false
            }
        } else {
            true
        };
        let host_complete = !self.cleanup_host_netns || self.host_complete_passes >= 2;

        UdpCleanupProofProgress {
            proof: self.proof.clone(),
            host_complete,
            pod_complete,
        }
    }

    fn incomplete_progress(&self) -> UdpCleanupProofProgress {
        UdpCleanupProofProgress {
            proof: None,
            host_complete: !self.cleanup_host_netns,
            pod_complete: !self.cleanup_pod_netns,
        }
    }
}

impl DurablePlacementState {
    fn new(active: UdpPlacement, incarnation: Option<UdpNodeIdentity>) -> Self {
        Self {
            version: 1,
            active,
            pending: None,
            completed: None,
            incarnation,
        }
    }
}

pub enum UdpPlacementDecision {
    RunStable,
    RunCleanup(UdpMigrationContext),
}

#[derive(Debug, Clone)]
pub struct UdpMigrationContext {
    registry_dir: PathBuf,
    transition: UdpMigrationTransition,
    cleanup_both: bool,
    /// Set for the privileged node preflight. A preflight owns NO durable
    /// placement state: it publishes a node-scoped completion attestation and
    /// leaves the placement record for the steady-state process to write, so an
    /// interrupted preflight can never strand a pending migration.
    node_preflight: Option<UdpNodeIdentity>,
    /// Procfs root the pod-netns cleanup backend resolves TARGET pids through.
    /// `None` is this process's own `/proc` and is what the mesh data plane's
    /// cleanup phase always uses. Only the one-shot node preflight sets it, so
    /// it can run as an init container in the ambient pod against a read-only
    /// mount of the host's procfs instead of pod-scoped `hostPID` (issue #3809).
    target_proc_root: Option<PathBuf>,
}

impl UdpMigrationContext {
    /// Build the retirement context the privileged node preflight runs.
    ///
    /// The synthetic predecessor is `Disabled`, which makes `cleanup_both` true,
    /// so BOTH the pod-netns and host-netns ownership domains (IPv4 and IPv6
    /// alike) are enumerated and retired by exact Ferrum-owned name. That is the
    /// only sound predecessor claim available to an ambiguous recordless node:
    /// it cannot know which placement ran here before, so it must not guess.
    pub fn for_node_preflight(
        registry_dir: &Path,
        target: UdpPlacement,
        node: UdpNodeIdentity,
        generation: &str,
    ) -> Result<Self, String> {
        validate_node_proof_generation(generation)?;
        node.validate()?;
        if target == UdpPlacement::Disabled {
            return Err(
                "the Ambient UDP node preflight has no incoming placement to prove".to_string(),
            );
        }
        Ok(Self {
            registry_dir: registry_dir.to_path_buf(),
            transition: UdpMigrationTransition {
                generation: generation.to_string(),
                from: UdpPlacement::Disabled,
                to: target,
            },
            cleanup_both: true,
            node_preflight: Some(node),
            target_proc_root: None,
        })
    }

    /// Resolve pod-netns TARGET pids through `root` instead of this process's
    /// own `/proc`.
    ///
    /// Set ONLY by the privileged node preflight, and only because a preflight
    /// that keeps same-pod init-before-container ordering with the steady-state
    /// proxy cannot also take pod-scoped `hostPID` — that field would follow the
    /// long-running proxy container for its whole lifetime. A read-only mount of
    /// the host's procfs, declared on the init container alone, gives the
    /// one-shot stage the same target-pid view and disappears when it exits.
    pub fn with_target_proc_root(mut self, root: Option<PathBuf>) -> Self {
        self.target_proc_root = root;
        self
    }

    /// The procfs root pod-netns cleanup resolves TARGET pids through, if the
    /// caller overrode it.
    pub fn target_proc_root(&self) -> Option<&Path> {
        self.target_proc_root.as_deref()
    }

    pub const fn is_node_preflight(&self) -> bool {
        self.node_preflight.is_some()
    }

    pub const fn from(&self) -> UdpPlacement {
        self.transition.from
    }

    pub const fn to(&self) -> UdpPlacement {
        self.transition.to
    }

    pub fn generation(&self) -> &str {
        &self.transition.generation
    }

    pub fn registry_dir(&self) -> &Path {
        &self.registry_dir
    }

    pub const fn cleanup_pod_netns(&self) -> bool {
        self.cleanup_both
            || matches!(
                self.transition.from,
                UdpPlacement::PodNetns | UdpPlacement::Disabled
            )
    }

    pub const fn cleanup_host_netns(&self) -> bool {
        self.cleanup_both
            || matches!(
                self.transition.from,
                UdpPlacement::HostNetns | UdpPlacement::Disabled
            )
    }

    /// The node-agent's current registry-synchronization publication, when it
    /// is one this context may build on.
    ///
    /// A preflight additionally requires the publication to name THIS node's
    /// authoritatively resolved UID. The marker is the preflight's only evidence
    /// that the pod inventory it is about to retire against is complete, and a
    /// marker left behind by the node-agent of a previous Kubernetes Node object
    /// enumerates that object's pods — so accepting it would let a stale
    /// enumeration and a stale identity agree while live workloads went
    /// unretired.
    pub fn registry_sync_proof(&self) -> Option<UdpRegistrySyncProof> {
        let proof = registry_sync_proof(&self.registry_dir)?;
        if proof.generation.as_str() != self.generation() {
            return None;
        }
        if let Some(node) = self.node_preflight.as_ref()
            && proof.node_uid.as_deref() != Some(node.node_uid.as_str())
        {
            return None;
        }
        Some(proof)
    }

    pub fn mark_cleanup_complete(&self, proof: &UdpRegistrySyncProof) -> Result<(), String> {
        if let Some(node) = &self.node_preflight {
            // The preflight's completion evidence is node-scoped, not placement
            // ownership. Re-check the registry publication immediately before
            // publishing so a marker that changed during the final pass cannot
            // be laundered into proof.
            if self.registry_sync_proof().as_ref() != Some(proof) {
                return Err(
                    "Ambient UDP registry synchronization proof changed before node preflight completion"
                        .to_string(),
                );
            }
            return write_node_attestation(
                &self.registry_dir,
                NODE_PROOF_FILE,
                &NodeAttestation {
                    version: 1,
                    node: node.clone(),
                    target: self.transition.to,
                    generation: self.transition.generation.clone(),
                },
            );
        }
        let mut state = read_state(&self.registry_dir)?.ok_or_else(|| {
            "Ambient UDP migration state disappeared before cleanup completion".to_string()
        })?;
        let Some(pending) = state.pending.as_mut() else {
            return Err("Ambient UDP migration no longer has a pending transition".to_string());
        };
        if pending.transition != self.transition {
            return Err(
                "Ambient UDP migration ownership/generation changed during cleanup".to_string(),
            );
        }
        if self.registry_sync_proof().as_ref() != Some(proof) {
            return Err(
                "Ambient UDP registry synchronization proof changed before cleanup completion"
                    .to_string(),
            );
        }
        pending.cleanup_complete = true;
        write_state(&self.registry_dir, &state)
    }
}

pub fn prepare_placement(
    registry_dir: &Path,
    request: &UdpPlacementRequest,
) -> Result<UdpPlacementDecision, String> {
    let mut state = read_state(registry_dir)?;
    // A durable record is node ownership, so it is only THIS node's ownership
    // when the identity it was written under is this machine. A record whose
    // node UID belongs to another machine (a restored registry hostPath, a
    // recycled node name, a copied artifact) is refused in EVERY phase before
    // any of it is trusted — including as a predecessor claim for cleanup.
    //
    // An identity-bound record therefore cannot be compared away by LOSING the
    // comparison input. If this process cannot resolve the current node
    // identity at all (the node-agent could not read `Node.metadata.uid`
    // because of an RBAC or API-server failure, no `FERRUM_K8S_NODE_UID` was
    // supplied, or the boot id is unreadable), then a restored or reused
    // registry directory carrying another machine's record would be trusted
    // verbatim — exactly the node-name-reuse inheritance this binding exists to
    // refuse. Unresolvable identity is a closed refusal in every phase, before
    // any phase reads the record. A record with NO recorded incarnation asserts
    // no ownership claim to COMPARE, so it passes this block — and is then
    // refused outright by the stable arm for every placement that runs a
    // producer, recoverable only through the explicit cleanup/finalize pair
    // that retires the exact Ferrum-owned predecessor state and binds this
    // node's identity.
    let recorded_incarnation = state.as_ref().and_then(|state| state.incarnation.clone());
    let mut incarnation_changed = false;
    if let Some(recorded) = recorded_incarnation.as_ref() {
        let Some(node) = request.node.as_ref() else {
            set_failure(UdpMigrationFailureReason::NodeIdentityUnresolved);
            return Err(
                "the durable Ambient UDP placement record on this registry directory is bound to a Kubernetes node UID and boot id, but this node's current identity could not be resolved; supply FERRUM_K8S_NODE_UID (or restore the node-agent's node-identity publication) before any placement decision trusts that record"
                    .to_string(),
            );
        };
        if recorded.node_uid != node.node_uid {
            set_failure(UdpMigrationFailureReason::NodeIdentityMismatch);
            return Err(
                "the durable Ambient UDP placement record on this registry directory was written by a different Kubernetes node UID; it cannot be inherited by this node"
                    .to_string(),
            );
        }
        incarnation_changed = recorded.boot_id != node.boot_id;
    }
    match request.phase {
        UdpMigrationPhase::Stable => {
            // A record this call creates is ownership this process is
            // establishing, not ownership it is adopting; only a record that
            // was ALREADY on disk is subject to the unbound-ownership refusal
            // below.
            let record_was_absent = state.is_none();
            if state.is_none() {
                // A node with no durable record is either genuinely new to this
                // placement (fresh node, or a registry directory recreated by a
                // node reboot) or a pre-contract node whose predecessor rules
                // may still be live inside running pods. The node cannot tell
                // those apart by inspection: under the host placement it has
                // deliberately dropped the setns privileges needed to look
                // inside a pod netns, and marker absence is not proof.
                //
                // A RELEASE cannot tell them apart either (issue #3809). The
                // installed placement ConfigMap records only target/phase/
                // generation — no node identity, no node incarnation, no
                // per-node cleanup result — so a node that stayed booted with
                // live workloads while it missed the cleanup and finalize
                // rollout looks exactly like a rebooted one. Adopting on that
                // evidence starts the host producer while every workload's pod
                // netns still redirects UDP to the retired predecessor
                // listener: a deterministic node-local UDP blackhole. The
                // release attestation is therefore kept as a NECESSARY desired
                // state check, and node-specific proof must agree with it
                // before the incoming producer may start.
                //
                // An operator who quarantined unreadable/unknown ownership asked
                // for cleanup to re-establish it. Refuse every stable bootstrap
                // from absent state until a finalize proof clears the tombstone,
                // so a restart between the quarantine and the cleanup release
                // cannot silently adopt any placement instead.
                match ownership_is_quarantined(registry_dir) {
                    Ok(true) => {
                        set_failure(UdpMigrationFailureReason::MigrationRequired);
                        return Err(
                            "Ambient UDP ownership is quarantined on this node and no durable record remains; run an explicit cleanup migration (the quarantine tombstone is cleared only by a finalize that proves predecessor state retired)"
                                .to_string(),
                        );
                    }
                    Ok(false) => {}
                    Err(error) => {
                        set_failure(UdpMigrationFailureReason::DurableStateRejected);
                        return Err(format!(
                            "could not safely inspect the Ambient UDP ownership quarantine marker: {error}"
                        ));
                    }
                }
                let host_target = request.target == UdpPlacement::HostNetns;
                let mut adoption_proof = UdpAdoptionProof::None;
                if host_target {
                    if request.established != Some(request.target) {
                        set_failure(UdpMigrationFailureReason::MigrationRequired);
                        return Err(
                            "host-netns Ambient UDP capture has no durable predecessor proof and this release does not attest an already-established host-netns placement; run an explicit cleanup migration before selecting host-netns"
                                .to_string(),
                        );
                    }
                    adoption_proof = resolve_recordless_node_proof(registry_dir, request)?;
                }
                write_state(
                    registry_dir,
                    &DurablePlacementState::new(request.target, request.node.clone()),
                )?;
                if adoption_proof != UdpAdoptionProof::None {
                    record_adoption(adoption_proof);
                    tracing::info!(
                        placement = request.target.as_str(),
                        proof = adoption_proof.as_str(),
                        "Ambient UDP placement adopted with node-specific predecessor proof; this node carried no durable record and the proof is bound to its exact node UID and boot id"
                    );
                }
                state = read_state(registry_dir)?;
            }
            let mut state = state.ok_or_else(|| {
                "Ambient UDP placement state was not readable after initialization".to_string()
            })?;
            if state.pending.is_some() {
                set_failure(UdpMigrationFailureReason::FinalizeRequired);
                return Err(
                    "Ambient UDP cleanup is pending or complete; use phase=finalize with the same generation before starting the incoming placement"
                        .to_string(),
                );
            }
            if state.active != request.target {
                set_failure(UdpMigrationFailureReason::MigrationRequired);
                return Err(format!(
                    "unsafe one-step Ambient UDP placement change {} -> {} rejected; run cleanup then finalize with an explicit generation",
                    state.active.as_str(),
                    request.target.as_str()
                ));
            }
            // Durable ownership that names NO node cannot prove which machine
            // established the placement it describes. A registry directory
            // restored from a backup, copied between machines, or reattached
            // under a recycled node name presents exactly this shape, as does a
            // record written before the node-identity binding existed. Adopting
            // it would start a producer on ownership this node never earned,
            // while the predecessor's interception rules may still be live in
            // the workloads running here — the issue #3809 blackhole, reached
            // through the record instead of through a release attestation.
            //
            // `disabled` runs no producer and carries no traffic, so it is the
            // one placement an unbound record may still carry (and it is
            // re-stamped below once an identity is resolvable). Every producer
            // placement fails closed until the explicit cleanup/finalize pair
            // has retired the exact Ferrum-owned predecessor state and bound
            // this node's identity to the record. Note that a MISSING current
            // identity is not a way past this: it cannot satisfy the refusal,
            // and cleanup/finalize only bind an identity they can resolve.
            if !record_was_absent
                && state.incarnation.is_none()
                && request.target != UdpPlacement::Disabled
            {
                set_failure(UdpMigrationFailureReason::MigrationRequired);
                return Err(format!(
                    "the durable Ambient UDP placement record on this registry directory names no owning Kubernetes node UID, so it cannot prove this node established the {} placement it describes; run an explicit cleanup migration (cleanup then finalize, with this node's identity resolvable) to retire the predecessor state before this node adopts it",
                    request.target.as_str()
                ));
            }
            // A record from an EARLIER boot of this same node UID is itself
            // node-specific predecessor proof: every pod network namespace that
            // could still hold predecessor interception rules died with that
            // incarnation. Re-stamp the record so the next start reads plain
            // same-incarnation ownership rather than replaying this decision.
            if request.node.is_some() && (incarnation_changed || state.incarnation.is_none()) {
                state.incarnation = request.node.clone();
                write_state(registry_dir, &state)?;
                if incarnation_changed {
                    record_adoption(UdpAdoptionProof::NewBoot);
                    tracing::info!(
                        placement = request.target.as_str(),
                        proof = UdpAdoptionProof::NewBoot.as_str(),
                        "Ambient UDP placement adopted from a durable record written by an earlier boot of this same node UID; no predecessor pod network namespace can have survived the reboot"
                    );
                }
            }
            set_phase(UdpMigrationStatusPhase::Stable, 0);
            clear_failure();
            Ok(UdpPlacementDecision::RunStable)
        }
        UdpMigrationPhase::Cleanup => {
            let transition = request
                .transition()
                .ok_or_else(|| "Ambient UDP cleanup transition is incomplete".to_string())?;
            let state_was_absent = state.is_none();
            let mut state = state.unwrap_or_else(|| {
                DurablePlacementState::new(transition.from, request.node.clone())
            });
            state.incarnation = request.node.clone().or(state.incarnation);
            let cleanup_both = if let Some(pending) = &state.pending {
                if pending.transition != transition {
                    set_failure(UdpMigrationFailureReason::GenerationMismatch);
                    return Err(
                        "a different Ambient UDP migration is already pending on this node"
                            .to_string(),
                    );
                }
                pending.cleanup_both
            } else {
                if state
                    .completed
                    .as_ref()
                    .is_some_and(|completed| completed.generation == transition.generation)
                {
                    set_failure(UdpMigrationFailureReason::GenerationMismatch);
                    return Err(
                        "Ambient UDP migration generation was already completed; choose a new generation for the next transition"
                            .to_string(),
                    );
                }
                if state.active != transition.from {
                    set_failure(UdpMigrationFailureReason::PredecessorMismatch);
                    return Err(format!(
                        "Ambient UDP migration declares predecessor {} but durable active placement is {}",
                        transition.from.as_str(),
                        state.active.as_str()
                    ));
                }
                let cleanup_both = state_was_absent || transition.from == UdpPlacement::Disabled;
                state.pending = Some(PendingMigration {
                    transition: transition.clone(),
                    cleanup_both,
                    cleanup_complete: false,
                });
                state.completed = None;
                write_state(registry_dir, &state)?;
                cleanup_both
            };
            set_phase(UdpMigrationStatusPhase::WaitingForRegistry, 0);
            clear_failure();
            Ok(UdpPlacementDecision::RunCleanup(UdpMigrationContext {
                registry_dir: registry_dir.to_path_buf(),
                transition,
                cleanup_both,
                node_preflight: None,
                target_proc_root: None,
            }))
        }
        UdpMigrationPhase::Finalize => {
            let transition = request
                .transition()
                .ok_or_else(|| "Ambient UDP finalize transition is incomplete".to_string())?;
            let mut state = state.ok_or_else(|| {
                "Ambient UDP finalize has no durable migration state on this node".to_string()
            })?;
            // Finalize is the boundary at which node ownership is ASSERTED: it
            // flips `active` to the incoming placement, returns `RunStable` so
            // the producer starts in this very process, and every later start
            // reads that record as evidence THIS node established the placement.
            // Completing it without a resolvable identity would therefore run a
            // producer on a record that names no owning node UID — the exact
            // shape the stable arm refuses below — so the migration would both
            // start an unproven producer now and be unrecoverable by repeating
            // itself. `disabled` owns no producer and carries no traffic, so it
            // stays finalizable while the identity is unresolvable.
            if transition.to != UdpPlacement::Disabled
                && request.node.is_none()
                && state.incarnation.is_none()
            {
                set_failure(UdpMigrationFailureReason::NodeIdentityUnresolved);
                return Err(format!(
                    "Ambient UDP finalize refused: this node's identity could not be resolved, so completing the migration would leave a durable record that runs the {} producer while naming no owning Kubernetes node UID; supply FERRUM_K8S_NODE_UID (or restore the node-agent's node-identity publication) and re-run finalize with the same generation",
                    transition.to.as_str()
                ));
            }
            if state.active == transition.to
                && state.pending.is_none()
                && state.completed.as_ref() == Some(&transition)
            {
                // Finalize is idempotent, including its quarantine cleanup and
                // its identity binding. A crash or transient filesystem error
                // after the durable state write must not make a later retry skip
                // the tombstone removal, nor leave the record unbound because
                // the run that completed the transition could not resolve an
                // identity this one can.
                if request.node.is_some() && state.incarnation != request.node {
                    state.incarnation = request.node.clone();
                    write_state(registry_dir, &state)?;
                }
                clear_ownership_quarantine(registry_dir);
                set_phase(UdpMigrationStatusPhase::Stable, 0);
                clear_failure();
                return Ok(UdpPlacementDecision::RunStable);
            }
            let Some(pending) = state.pending.as_ref() else {
                set_failure(UdpMigrationFailureReason::CleanupProofMissing);
                return Err("Ambient UDP finalize has no pending cleanup proof".to_string());
            };
            if pending.transition != transition {
                set_failure(UdpMigrationFailureReason::GenerationMismatch);
                return Err(
                    "Ambient UDP finalize generation/from/to does not match durable cleanup ownership"
                        .to_string(),
                );
            }
            if !pending.cleanup_complete {
                set_failure(UdpMigrationFailureReason::CleanupProofMissing);
                return Err(
                    "Ambient UDP finalize refused: predecessor cleanup is not durably complete on this node"
                        .to_string(),
                );
            }
            state.active = transition.to;
            state.pending = None;
            state.completed = Some(transition);
            state.incarnation = request.node.clone().or(state.incarnation);
            write_state(registry_dir, &state)?;
            // A completed cleanup/finalize pair is exactly the proof the
            // quarantine tombstone was waiting for. Clearing it fails soft: the
            // durable record is now present, so a stale tombstone only refuses a
            // future ABSENT-state adoption, which is the safe direction.
            clear_ownership_quarantine(registry_dir);
            set_phase(UdpMigrationStatusPhase::Stable, 0);
            clear_failure();
            Ok(UdpPlacementDecision::RunStable)
        }
    }
}

/// Resolve the node-specific evidence that authorizes a recordless host-netns
/// start, or fail closed as `migration_required`.
///
/// Every acceptance path is bound to the EXACT node UID, the CURRENT boot id,
/// the requested target, and this release's node-proof generation. Node-name
/// reuse under a different UID, a proof written before this incarnation, a
/// superseded generation, a target mismatch, and an unreadable/forged/oversized
/// attestation therefore all refuse.
fn resolve_recordless_node_proof(
    registry_dir: &Path,
    request: &UdpPlacementRequest,
) -> Result<UdpAdoptionProof, String> {
    let Some(node) = request.node.as_ref() else {
        set_failure(UdpMigrationFailureReason::NodeProofMissing);
        return Err(
            "host-netns Ambient UDP capture has no durable predecessor proof and this deployment supplied no node identity; a release-level attestation is desired state and cannot authorize a recordless node"
                .to_string(),
        );
    };
    let Some(expected_generation) = request.node_proof_generation.as_deref() else {
        set_failure(UdpMigrationFailureReason::NodeProofMissing);
        return Err(
            "host-netns Ambient UDP capture has no durable predecessor proof and this release declares no node-proof generation to bind one to"
                .to_string(),
        );
    };
    // A generation that can RECUR proves nothing: an attestation written for an
    // earlier era of the same target/phase would authorize a later one after the
    // cluster migrated away and back (issue #3809). Refuse the release rather
    // than bind a proof to a repeatable token.
    if validate_node_proof_generation(expected_generation).is_err() {
        set_failure(UdpMigrationFailureReason::NodeProofMissing);
        return Err(
            "host-netns Ambient UDP capture has no durable predecessor proof and this release's node-proof generation is not era-qualified, so a node attestation bound to it could be replayed across placement migrations; render the settled release from an installed placement contract (or supply an `e<era>.<generation>` value)"
                .to_string(),
        );
    }
    for (file, proof) in [
        (NODE_PROOF_FILE, UdpAdoptionProof::NodeCleanup),
        (NODE_EXEMPT_FILE, UdpAdoptionProof::OperatorExempt),
    ] {
        let attestation = match read_node_attestation(registry_dir, file) {
            Ok(Some(attestation)) => attestation,
            Ok(None) => continue,
            Err(error) => {
                set_failure(UdpMigrationFailureReason::DurableStateRejected);
                return Err(format!(
                    "could not safely read the node-specific Ambient UDP placement attestation: {error}"
                ));
            }
        };
        if attestation.node.node_uid != node.node_uid {
            set_failure(UdpMigrationFailureReason::NodeIdentityMismatch);
            return Err(
                "the node-specific Ambient UDP placement attestation names a different Kubernetes node UID; node-name reuse cannot inherit another machine's cleanup proof"
                    .to_string(),
            );
        }
        if attestation.node.boot_id != node.boot_id {
            set_failure(UdpMigrationFailureReason::NodeProofMissing);
            return Err(
                "the node-specific Ambient UDP placement attestation was written for an earlier boot of this node; it cannot prove predecessor state was retired on this incarnation"
                    .to_string(),
            );
        }
        if attestation.target != request.target {
            set_failure(UdpMigrationFailureReason::NodeProofMissing);
            return Err(
                "the node-specific Ambient UDP placement attestation proves a different incoming placement than this release requests"
                    .to_string(),
            );
        }
        if attestation.generation != expected_generation {
            set_failure(UdpMigrationFailureReason::GenerationMismatch);
            return Err(
                "the node-specific Ambient UDP placement attestation was written under a superseded node-proof generation"
                    .to_string(),
            );
        }
        return Ok(proof);
    }
    set_failure(UdpMigrationFailureReason::MigrationRequired);
    Err(
        "host-netns Ambient UDP capture has no durable predecessor proof and no node-specific cleanup attestation for this node UID and boot id; run the privileged Ambient UDP node preflight (or an explicit cleanup migration) before starting the host producer"
            .to_string(),
    )
}

fn read_node_attestation(
    registry_dir: &Path,
    file: &str,
) -> Result<Option<NodeAttestation>, String> {
    let path = registry_dir.join(file);
    let opened = match open_owned_regular_file(&path, MAX_NODE_ATTESTATION_BYTES) {
        Ok(opened) => opened,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let mut bytes = Vec::new();
    opened
        .take(MAX_NODE_ATTESTATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_NODE_ATTESTATION_BYTES {
        return Err("attestation exceeds its size limit".to_string());
    }
    let attestation: NodeAttestation =
        serde_json::from_slice(&bytes).map_err(|_| "attestation is malformed".to_string())?;
    if attestation.version != 1 {
        return Err("attestation has an unsupported version".to_string());
    }
    attestation.node.validate()?;
    validate_generation(&attestation.generation)
        .map_err(|_| "attestation has an invalid generation".to_string())?;
    Ok(Some(attestation))
}

fn write_node_attestation(
    registry_dir: &Path,
    file: &str,
    attestation: &NodeAttestation,
) -> Result<(), String> {
    std::fs::create_dir_all(registry_dir)
        .map_err(|error| format!("could not create Ambient UDP registry directory: {error}"))?;
    let bytes = serde_json::to_vec(attestation).map_err(|error| {
        format!("could not encode the Ambient UDP node placement attestation: {error}")
    })?;
    if bytes.len() as u64 > MAX_NODE_ATTESTATION_BYTES {
        return Err(
            "the Ambient UDP node placement attestation exceeds its size limit".to_string(),
        );
    }
    atomic_write(
        registry_dir,
        &registry_dir.join(file),
        file,
        &bytes,
        "Ambient UDP node placement attestation",
    )
}

/// True when this node incarnation already carries a valid, generation-bound
/// cleanup attestation for `target`.
///
/// This is a predicate for tests and diagnostics, not a preflight skip. A newly
/// starting preflight pod must retract any leftover proof and run the
/// idempotent retirement itself: a Helm rollback, re-applied historical
/// manifest, or restored ConfigMap can recreate an earlier era's generation
/// token, and a mutable monotonic counter cannot prove that did not happen.
#[allow(dead_code)] // External integration-test seam is unused by the bin test target.
pub fn node_cleanup_proof_is_current(
    registry_dir: &Path,
    target: UdpPlacement,
    node: &UdpNodeIdentity,
    generation: &str,
) -> Result<bool, String> {
    let Some(attestation) = read_node_attestation(registry_dir, NODE_PROOF_FILE)
        .map_err(|error| format!("could not read the Ambient UDP node cleanup proof: {error}"))?
    else {
        return Ok(false);
    };
    Ok(attestation.node == *node
        && attestation.target == target
        && attestation.generation == generation)
}

fn state_path(registry_dir: &Path) -> PathBuf {
    registry_dir.join(STATE_FILE)
}

/// Any entry at the tombstone path counts, including a symlink or a directory:
/// this is a fail-closed presence check, never a content read.
fn ownership_is_quarantined(registry_dir: &Path) -> Result<bool, std::io::Error> {
    match std::fs::symlink_metadata(registry_dir.join(QUARANTINE_FILE)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn clear_ownership_quarantine(registry_dir: &Path) {
    let path = registry_dir.join(QUARANTINE_FILE);
    let removal = match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_dir() => std::fs::remove_dir(&path),
        Ok(_) => std::fs::remove_file(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => Err(error),
    };
    match removal {
        Ok(()) => {
            if let Err(error) = sync_directory(registry_dir) {
                tracing::warn!(
                    %error,
                    "could not sync Ambient UDP ownership quarantine removal; a surviving tombstone only refuses a future absent-state adoption"
                );
            }
        }
        // A concurrent operator cleanup already achieved the desired state.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(
                %error,
                "could not clear the Ambient UDP ownership quarantine tombstone; remove it manually before relying on release-attested adoption"
            );
        }
    }
}

fn read_state(registry_dir: &Path) -> Result<Option<DurablePlacementState>, String> {
    let path = state_path(registry_dir);
    let file = match open_owned_regular_file(&path, MAX_STATE_BYTES) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "could not securely open Ambient UDP migration state: {error}"
            ));
        }
    };
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read Ambient UDP migration state: {error}"))?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err("Ambient UDP migration state exceeds its size limit".to_string());
    }
    let state: DurablePlacementState = serde_json::from_slice(&bytes)
        .map_err(|_| "Ambient UDP migration state is malformed".to_string())?;
    if state.version != 1 {
        return Err("Ambient UDP migration state has an unsupported version".to_string());
    }
    validate_durable_state(&state)?;
    Ok(Some(state))
}

fn validate_durable_state(state: &DurablePlacementState) -> Result<(), String> {
    let validate_transition = |transition: &UdpMigrationTransition| {
        validate_generation(&transition.generation)
            .map_err(|_| "Ambient UDP migration state has an invalid generation".to_string())?;
        if transition.from == transition.to {
            return Err("Ambient UDP migration state has an invalid no-op transition".to_string());
        }
        Ok(())
    };

    if let Some(incarnation) = &state.incarnation {
        incarnation.validate().map_err(|_| {
            "Ambient UDP migration state has an invalid node incarnation".to_string()
        })?;
    }
    if let Some(pending) = &state.pending {
        validate_transition(&pending.transition)?;
        if state.active != pending.transition.from || state.completed.is_some() {
            return Err(
                "Ambient UDP migration state has inconsistent pending ownership".to_string(),
            );
        }
    } else if let Some(completed) = &state.completed {
        validate_transition(completed)?;
        if state.active != completed.to {
            return Err(
                "Ambient UDP migration state has inconsistent completed ownership".to_string(),
            );
        }
    }
    Ok(())
}

fn write_state(registry_dir: &Path, state: &DurablePlacementState) -> Result<(), String> {
    std::fs::create_dir_all(registry_dir)
        .map_err(|error| format!("could not create Ambient UDP registry directory: {error}"))?;
    let bytes = serde_json::to_vec(state)
        .map_err(|error| format!("could not encode Ambient UDP migration state: {error}"))?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err("Ambient UDP migration state exceeds its size limit".to_string());
    }
    atomic_write(
        registry_dir,
        &state_path(registry_dir),
        STATE_FILE,
        &bytes,
        "Ambient UDP migration state",
    )
}

pub fn migration_generation_from_env() -> Result<Option<String>, String> {
    let value = resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_MIGRATION_GENERATION")
        .filter(|value| !value.trim().is_empty());
    if let Some(value) = value.as_deref() {
        validate_generation(value)?;
    }
    Ok(value)
}

pub fn clear_registry_sync_marker(registry_dir: &Path) -> Result<(), String> {
    let path = registry_dir.join(REGISTRY_SYNC_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => sync_directory(registry_dir).map_err(|error| {
            format!("could not sync Ambient UDP registry marker retraction: {error}")
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not retract Ambient UDP registry synchronization marker: {error}"
        )),
    }
}

/// Publish a fresh generation-bound proof only after every pod UID expected
/// from the node-agent's authoritative relist is present in the securely synced
/// registry snapshot. Unexpected entries remain part of cleanup: they may be
/// stale predecessor ownership and must not be silently omitted. Returns
/// `false` without publishing when an expected pod is not present yet.
///
/// `node_uid` is this node-agent incarnation's AUTHORITATIVELY resolved
/// `Node.metadata.uid`, or `None` when it could not resolve one. It binds the
/// publication to the machine whose pod inventory it enumerates, so a marker
/// surviving on a persistent registry path from a previous Kubernetes Node
/// object cannot satisfy the privileged node preflight.
pub fn publish_registry_sync_marker_for_pods(
    registry_dir: &Path,
    generation: &str,
    expected_pod_uids: &HashSet<String>,
    node_uid: Option<&str>,
) -> Result<bool, String> {
    validate_generation(generation)?;
    if let Some(node_uid) = node_uid {
        validate_node_identifier(node_uid, "Kubernetes node UID")?;
    }
    std::fs::create_dir_all(registry_dir)
        .map_err(|error| format!("could not create Ambient UDP registry directory: {error}"))?;
    let entries = std::fs::read_dir(registry_dir)
        .map_err(|error| format!("could not scan Ambient UDP registry for sync: {error}"))?;
    let mut registry_pod_uids = HashSet::new();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_REGISTRY_SYNC_ENTRIES {
            return Err("Ambient UDP registry exceeds its synchronization entry limit".to_string());
        }
        let entry =
            entry.map_err(|error| format!("could not read Ambient UDP registry entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Ambient UDP registry entry name is not UTF-8")?;
        if name.starts_with('.') {
            continue;
        }
        let file = open_owned_regular_file(&entry.path(), u64::MAX).map_err(|error| {
            format!("could not securely validate Ambient UDP registry entry: {error}")
        })?;
        // Current node-agent entries were file+directory synced when their
        // atomic rename completed. Only an unexpected predecessor entry can
        // predate that contract, so pay the compatibility fsync once for the
        // stale set instead of reopening every live pod on every mutation.
        if !expected_pod_uids.contains(&name) {
            file.sync_all().map_err(|error| {
                format!("could not securely sync stale Ambient UDP registry entry: {error}")
            })?;
        }
        registry_pod_uids.insert(name);
    }
    if !expected_pod_uids.is_subset(&registry_pod_uids) {
        return Ok(false);
    }
    sync_directory(registry_dir)
        .map_err(|error| format!("could not sync Ambient UDP registry directory: {error}"))?;
    let marker = RegistrySyncMarker {
        version: 1,
        generation: generation.to_string(),
        publication: uuid::Uuid::new_v4().simple().to_string(),
        node_uid: node_uid.map(str::to_string),
    };
    let bytes = serde_json::to_vec(&marker)
        .map_err(|error| format!("could not encode Ambient UDP registry sync marker: {error}"))?;
    if bytes.len() as u64 > MAX_REGISTRY_SYNC_MARKER_BYTES {
        return Err("Ambient UDP registry sync marker exceeds its size limit".to_string());
    }
    atomic_write(
        registry_dir,
        &registry_dir.join(REGISTRY_SYNC_FILE),
        REGISTRY_SYNC_FILE,
        &bytes,
        "Ambient UDP registry sync marker",
    )?;
    Ok(true)
}

fn registry_sync_proof(registry_dir: &Path) -> Option<UdpRegistrySyncProof> {
    let path = registry_dir.join(REGISTRY_SYNC_FILE);
    let file = open_owned_regular_file(&path, MAX_REGISTRY_SYNC_MARKER_BYTES).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_REGISTRY_SYNC_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_REGISTRY_SYNC_MARKER_BYTES {
        return None;
    }
    let marker: RegistrySyncMarker = serde_json::from_slice(&bytes).ok()?;
    if marker.version != 1 {
        return None;
    }
    validate_generation(&marker.generation).ok()?;
    if marker.publication.len() != 32
        || !marker
            .publication
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    let publication = uuid::Uuid::parse_str(&marker.publication).ok()?;
    if publication.get_version() != Some(uuid::Version::Random) {
        return None;
    }
    // A present-but-malformed node binding is refused outright rather than
    // downgraded to "unbound": an unbound marker is consumable by the migration
    // cleanup phase, so silently dropping a corrupt value would widen it.
    if let Some(node_uid) = marker.node_uid.as_deref() {
        validate_node_identifier(node_uid, "Kubernetes node UID").ok()?;
    }
    Some(UdpRegistrySyncProof {
        generation: marker.generation,
        publication,
        node_uid: marker.node_uid,
    })
}

fn open_owned_regular_file(path: &Path, max_bytes: u64) -> std::io::Result<File> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file must be a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "file must be singly linked and owned by the process uid",
            ));
        }
    }
    Ok(file)
}

fn atomic_write(
    directory: &Path,
    destination: &Path,
    temporary_prefix: &str,
    bytes: &[u8],
    description: &str,
) -> Result<(), String> {
    reap_owned_temporary_files(directory, temporary_prefix);
    let mut temporary = tempfile::Builder::new()
        .prefix(&format!("{temporary_prefix}.tmp."))
        .tempfile_in(directory)
        .map_err(|error| format!("could not create {description} temporary file: {error}"))?;
    temporary
        .write_all(bytes)
        .map_err(|error| format!("could not write {description}: {error}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("could not sync {description}: {error}"))?;
    temporary
        .persist(destination)
        .map_err(|error| format!("could not publish {description}: {error}"))?;
    sync_directory(directory)
        .map_err(|error| format!("could not sync {description} directory: {error}"))
}

/// Reap only aged crash-left temporary files produced by this module. The age
/// fence avoids racing an overlapping rollout's active atomic write. A bounded
/// scan keeps work predictable; secure open plus an identity recheck refuses
/// symlinks, directories, hard links, foreign owners, and a pathname whose
/// identity changed between the two validation opens.
fn reap_owned_temporary_files(directory: &Path, temporary_prefix: &str) {
    let exact_prefix = format!("{temporary_prefix}.tmp.");
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut reaped = 0usize;
    for entry in entries
        .take(MAX_TEMP_DIRECTORY_ENTRIES_SCANNED_PER_WRITE)
        .flatten()
    {
        if reaped >= MAX_TEMP_FILES_REAPED_PER_WRITE {
            break;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with(&exact_prefix) {
            continue;
        }
        let path = entry.path();
        let Ok(opened) = open_owned_regular_file(&path, u64::MAX) else {
            continue;
        };
        let Ok(opened_metadata) = opened.metadata() else {
            continue;
        };
        let old_enough = opened_metadata
            .modified()
            .ok()
            .and_then(|modified| std::time::SystemTime::now().duration_since(modified).ok())
            .is_some_and(|age| age >= MIN_CRASH_TEMP_AGE);
        if !old_enough {
            continue;
        }
        let Ok(current) = open_owned_regular_file(&path, u64::MAX) else {
            continue;
        };
        let Ok(current_metadata) = current.metadata() else {
            continue;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if opened_metadata.dev() != current_metadata.dev()
                || opened_metadata.ino() != current_metadata.ino()
            {
                continue;
            }
        }
        #[cfg(not(unix))]
        if opened_metadata.len() != current_metadata.len() {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            reaped += 1;
        }
    }
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpMigrationStatusPhase {
    Stable,
    WaitingForRegistry,
    WaitingForGateAck,
    CleaningPodNetns,
    CleaningHostNetns,
    CleanupComplete,
    FinalizeBlocked,
    Failed,
}

impl UdpMigrationStatusPhase {
    const fn code(self) -> u8 {
        self as u8
    }

    const fn from_code(value: u8) -> Self {
        match value {
            1 => Self::WaitingForRegistry,
            2 => Self::WaitingForGateAck,
            3 => Self::CleaningPodNetns,
            4 => Self::CleaningHostNetns,
            5 => Self::CleanupComplete,
            6 => Self::FinalizeBlocked,
            7 => Self::Failed,
            _ => Self::Stable,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::WaitingForRegistry => "waiting_for_registry",
            Self::WaitingForGateAck => "waiting_for_gate_ack",
            Self::CleaningPodNetns => "cleaning_pod_netns",
            Self::CleaningHostNetns => "cleaning_host_netns",
            Self::CleanupComplete => "cleanup_complete",
            Self::FinalizeBlocked => "finalize_blocked",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpMigrationFailureReason {
    None,
    MigrationRequired,
    FinalizeRequired,
    GenerationMismatch,
    PredecessorMismatch,
    RegistryNotSynchronized,
    GateAcknowledgementMissing,
    PodNetnsUnresolved,
    PodCleanupFailed,
    HostCleanupFailed,
    CleanupProofMissing,
    StatePersistenceFailed,
    DurableStateRejected,
    /// A recordless node offered no node-specific cleanup/finalize evidence for
    /// its exact node UID and current boot id, so only release-level desired
    /// state was available and adoption was refused.
    NodeProofMissing,
    /// Durable ownership or a node attestation named a different Kubernetes
    /// node UID than this machine.
    NodeIdentityMismatch,
    /// A durable record is bound to a node identity, but this process could not
    /// resolve the CURRENT node identity to compare it against, so the record's
    /// ownership claim can neither be confirmed nor refuted. Refused rather than
    /// trusted: a restored or reused registry directory would otherwise inherit
    /// another machine's ownership whenever identity resolution fails.
    NodeIdentityUnresolved,
}

impl UdpMigrationFailureReason {
    const fn code(self) -> u8 {
        self as u8
    }

    const fn from_code(value: u8) -> Self {
        match value {
            1 => Self::MigrationRequired,
            2 => Self::FinalizeRequired,
            3 => Self::GenerationMismatch,
            4 => Self::PredecessorMismatch,
            5 => Self::RegistryNotSynchronized,
            6 => Self::GateAcknowledgementMissing,
            7 => Self::PodNetnsUnresolved,
            8 => Self::PodCleanupFailed,
            9 => Self::HostCleanupFailed,
            10 => Self::CleanupProofMissing,
            11 => Self::StatePersistenceFailed,
            12 => Self::DurableStateRejected,
            13 => Self::NodeProofMissing,
            14 => Self::NodeIdentityMismatch,
            15 => Self::NodeIdentityUnresolved,
            _ => Self::None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MigrationRequired => "migration_required",
            Self::FinalizeRequired => "finalize_required",
            Self::GenerationMismatch => "generation_mismatch",
            Self::PredecessorMismatch => "predecessor_mismatch",
            Self::RegistryNotSynchronized => "registry_not_synchronized",
            Self::GateAcknowledgementMissing => "gate_acknowledgement_missing",
            Self::PodNetnsUnresolved => "pod_netns_unresolved",
            Self::PodCleanupFailed => "pod_cleanup_failed",
            Self::HostCleanupFailed => "host_cleanup_failed",
            Self::CleanupProofMissing => "cleanup_proof_missing",
            Self::StatePersistenceFailed => "state_persistence_failed",
            Self::DurableStateRejected => "durable_state_rejected",
            Self::NodeProofMissing => "node_proof_missing",
            Self::NodeIdentityMismatch => "node_identity_mismatch",
            Self::NodeIdentityUnresolved => "node_identity_unresolved",
        }
    }
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static STATUS_PHASE: AtomicU8 = AtomicU8::new(0);
static OUTSTANDING: AtomicU64 = AtomicU64::new(0);
static FAILURE_REASON: AtomicU8 = AtomicU8::new(0);
static FAILURES_TOTAL: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
static ADOPTION_PROOF: AtomicU8 = AtomicU8::new(0);
static ADOPTIONS_TOTAL: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UdpMigrationStatusSnapshot {
    pub enabled: bool,
    pub phase: UdpMigrationStatusPhase,
    pub outstanding: u64,
    pub failure_reason: UdpMigrationFailureReason,
    /// True when this process started its placement WITHOUT a same-incarnation
    /// node-local durable record, i.e. it adopted on node-specific proof.
    pub established_adoption: bool,
    /// Which node-specific proof authorized that adoption. Bounded and
    /// fixed-cardinality; it never carries node identity, paths, generations,
    /// or any other operator-supplied value.
    pub adoption_proof: UdpAdoptionProof,
}

/// Record one adoption that started WITHOUT a same-incarnation durable record.
/// `..._adoptions_total{proof}` carries the per-proof breakdown.
fn record_adoption(proof: UdpAdoptionProof) {
    ENABLED.store(true, Ordering::Relaxed);
    ADOPTION_PROOF.store(proof.code(), Ordering::Relaxed);
    ADOPTIONS_TOTAL[proof.code() as usize].fetch_add(1, Ordering::Relaxed);
}

/// Whether any recordless adoption on a node-specific proof has been recorded
/// by this process.
fn any_established_adoption() -> bool {
    [
        UdpAdoptionProof::NewBoot,
        UdpAdoptionProof::NodeCleanup,
        UdpAdoptionProof::OperatorExempt,
    ]
    .into_iter()
    .any(|proof| ADOPTIONS_TOTAL[proof.code() as usize].load(Ordering::Relaxed) > 0)
}

pub fn set_phase(phase: UdpMigrationStatusPhase, outstanding: usize) {
    ENABLED.store(true, Ordering::Relaxed);
    STATUS_PHASE.store(phase.code(), Ordering::Relaxed);
    OUTSTANDING.store(outstanding as u64, Ordering::Relaxed);
}

pub fn clear_failure() {
    FAILURE_REASON.store(0, Ordering::Relaxed);
}

pub fn set_failure(reason: UdpMigrationFailureReason) {
    ENABLED.store(true, Ordering::Relaxed);
    FAILURE_REASON.store(reason.code(), Ordering::Relaxed);
    FAILURES_TOTAL[reason.code() as usize].fetch_add(1, Ordering::Relaxed);
}

pub fn snapshot() -> UdpMigrationStatusSnapshot {
    UdpMigrationStatusSnapshot {
        enabled: ENABLED.load(Ordering::Relaxed),
        phase: UdpMigrationStatusPhase::from_code(STATUS_PHASE.load(Ordering::Relaxed)),
        outstanding: OUTSTANDING.load(Ordering::Relaxed),
        failure_reason: UdpMigrationFailureReason::from_code(
            FAILURE_REASON.load(Ordering::Relaxed),
        ),
        established_adoption: any_established_adoption(),
        adoption_proof: UdpAdoptionProof::from_code(ADOPTION_PROOF.load(Ordering::Relaxed)),
    }
}

pub fn render_prometheus(output: &mut String, gateway_ns_label: &str) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let snapshot = snapshot();
    output.push_str(
        "# HELP ferrum_mesh_udp_placement_migration_phase Ambient UDP placement migration phase (one bounded phase is 1).\n",
    );
    output.push_str("# TYPE ferrum_mesh_udp_placement_migration_phase gauge\n");
    for phase in [
        UdpMigrationStatusPhase::Stable,
        UdpMigrationStatusPhase::WaitingForRegistry,
        UdpMigrationStatusPhase::WaitingForGateAck,
        UdpMigrationStatusPhase::CleaningPodNetns,
        UdpMigrationStatusPhase::CleaningHostNetns,
        UdpMigrationStatusPhase::CleanupComplete,
        UdpMigrationStatusPhase::FinalizeBlocked,
        UdpMigrationStatusPhase::Failed,
    ] {
        let value = u8::from(snapshot.phase == phase);
        output.push_str(&format!(
            "ferrum_mesh_udp_placement_migration_phase{{phase=\"{}\"{}}} {}\n",
            phase.as_str(),
            gateway_ns_label,
            value
        ));
    }
    output.push_str(
        "# HELP ferrum_mesh_udp_placement_migration_outstanding Outstanding pod netns or gate acknowledgements in the current node-local migration.\n",
    );
    output.push_str("# TYPE ferrum_mesh_udp_placement_migration_outstanding gauge\n");
    render_value(
        output,
        "ferrum_mesh_udp_placement_migration_outstanding",
        snapshot.outstanding,
        gateway_ns_label,
    );
    output.push_str(
        "# HELP ferrum_mesh_udp_placement_migration_adoption_proof Node-specific proof that authorized a recordless Ambient UDP placement adoption (one bounded proof is 1).\n",
    );
    output.push_str("# TYPE ferrum_mesh_udp_placement_migration_adoption_proof gauge\n");
    for proof in [
        UdpAdoptionProof::None,
        UdpAdoptionProof::NewBoot,
        UdpAdoptionProof::NodeCleanup,
        UdpAdoptionProof::OperatorExempt,
    ] {
        output.push_str(&format!(
            "ferrum_mesh_udp_placement_migration_adoption_proof{{proof=\"{}\"{}}} {}\n",
            proof.as_str(),
            gateway_ns_label,
            u8::from(snapshot.adoption_proof == proof)
        ));
    }
    output.push_str(
        "# HELP ferrum_mesh_udp_placement_migration_adoptions_total Recordless Ambient UDP placement adoptions by bounded node-specific proof.\n",
    );
    output.push_str("# TYPE ferrum_mesh_udp_placement_migration_adoptions_total counter\n");
    for proof in [
        UdpAdoptionProof::NewBoot,
        UdpAdoptionProof::NodeCleanup,
        UdpAdoptionProof::OperatorExempt,
    ] {
        output.push_str(&format!(
            "ferrum_mesh_udp_placement_migration_adoptions_total{{proof=\"{}\"{}}} {}\n",
            proof.as_str(),
            gateway_ns_label,
            ADOPTIONS_TOTAL[proof.code() as usize].load(Ordering::Relaxed)
        ));
    }
    output.push_str(
        "# HELP ferrum_mesh_udp_placement_migration_failures_total Ambient UDP placement migration failures by bounded reason.\n",
    );
    output.push_str("# TYPE ferrum_mesh_udp_placement_migration_failures_total counter\n");
    for reason in [
        UdpMigrationFailureReason::MigrationRequired,
        UdpMigrationFailureReason::FinalizeRequired,
        UdpMigrationFailureReason::GenerationMismatch,
        UdpMigrationFailureReason::PredecessorMismatch,
        UdpMigrationFailureReason::RegistryNotSynchronized,
        UdpMigrationFailureReason::GateAcknowledgementMissing,
        UdpMigrationFailureReason::PodNetnsUnresolved,
        UdpMigrationFailureReason::PodCleanupFailed,
        UdpMigrationFailureReason::HostCleanupFailed,
        UdpMigrationFailureReason::CleanupProofMissing,
        UdpMigrationFailureReason::StatePersistenceFailed,
        UdpMigrationFailureReason::DurableStateRejected,
        UdpMigrationFailureReason::NodeProofMissing,
        UdpMigrationFailureReason::NodeIdentityMismatch,
        UdpMigrationFailureReason::NodeIdentityUnresolved,
    ] {
        output.push_str(&format!(
            "ferrum_mesh_udp_placement_migration_failures_total{{reason=\"{}\"{}}} {}\n",
            reason.as_str(),
            gateway_ns_label,
            FAILURES_TOTAL[reason.code() as usize].load(Ordering::Relaxed)
        ));
    }
}

fn render_value(output: &mut String, name: &str, value: u64, gateway_ns_label: &str) {
    if gateway_ns_label.is_empty() {
        output.push_str(&format!("{name} {value}\n"));
    } else {
        let labels = gateway_ns_label
            .strip_prefix(',')
            .unwrap_or(gateway_ns_label);
        output.push_str(&format!("{name}{{{labels}}} {value}\n"));
    }
}
