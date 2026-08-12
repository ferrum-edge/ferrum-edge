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
/// Operator-written tombstone recording that node-local ownership was
/// quarantined as corrupt/unknown. Its presence means "absent state is NOT
/// evidence of a fresh node", so it refuses every stable bootstrap from absent
/// state — including a release-attested adoption — until an explicit
/// cleanup/finalize pair has proven predecessor state retired.
const QUARANTINE_FILE: &str = ".udp-placement-quarantined";
const REGISTRY_SYNC_FILE: &str = ".udp-registry-synced";
const MAX_STATE_BYTES: u64 = 4096;
const MAX_GENERATION_BYTES: usize = 64;
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
    pub established: Option<UdpPlacement>,
}

impl UdpPlacementRequest {
    pub fn from_env(target: UdpPlacement) -> Result<Self, String> {
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
}

#[derive(Clone, PartialEq, Eq)]
pub struct UdpRegistrySyncProof {
    generation: String,
    publication: uuid::Uuid,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrySyncMarker {
    version: u8,
    generation: String,
    publication: String,
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
    fn new(active: UdpPlacement) -> Self {
        Self {
            version: 1,
            active,
            pending: None,
            completed: None,
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
}

impl UdpMigrationContext {
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

    pub fn registry_sync_proof(&self) -> Option<UdpRegistrySyncProof> {
        let proof = registry_sync_proof(&self.registry_dir)?;
        (proof.generation.as_str() == self.generation()).then_some(proof)
    }

    pub fn mark_cleanup_complete(&self, proof: &UdpRegistrySyncProof) -> Result<(), String> {
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
    match request.phase {
        UdpMigrationPhase::Stable => {
            if state.is_none() {
                // A node with no durable record is either genuinely new to this
                // placement (fresh node, or a registry directory recreated by a
                // node reboot) or a pre-contract node whose predecessor rules
                // may still be live inside running pods. The node cannot tell
                // those apart by inspection: under the host placement it has
                // deliberately dropped the setns privileges needed to look
                // inside a pod netns, and marker absence is not proof.
                //
                // The RELEASE can tell them apart, because a completed earlier
                // migration release is exactly the event that retired every
                // then-existing node's predecessor state. Adopt the requested
                // host placement only when the deployment attests that this
                // placement was already established before this release; a
                // present-but-different durable record is never overridden.
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
                let adopted_from_established_release =
                    host_target && request.established == Some(request.target);
                if host_target && !adopted_from_established_release {
                    set_failure(UdpMigrationFailureReason::MigrationRequired);
                    return Err(
                        "host-netns Ambient UDP capture has no durable predecessor proof and this release does not attest an already-established host-netns placement; run an explicit cleanup migration before selecting host-netns"
                            .to_string(),
                    );
                }
                write_state(registry_dir, &DurablePlacementState::new(request.target))?;
                if adopted_from_established_release {
                    record_established_adoption();
                    tracing::info!(
                        placement = request.target.as_str(),
                        "Ambient UDP placement adopted from the release-attested established placement; this node carried no durable record (fresh node or recreated registry directory) and no predecessor cleanup is owed"
                    );
                }
                state = read_state(registry_dir)?;
            }
            let state = state.ok_or_else(|| {
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
            set_phase(UdpMigrationStatusPhase::Stable, 0);
            clear_failure();
            Ok(UdpPlacementDecision::RunStable)
        }
        UdpMigrationPhase::Cleanup => {
            let transition = request
                .transition()
                .ok_or_else(|| "Ambient UDP cleanup transition is incomplete".to_string())?;
            let state_was_absent = state.is_none();
            let mut state = state.unwrap_or_else(|| DurablePlacementState::new(transition.from));
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
            }))
        }
        UdpMigrationPhase::Finalize => {
            let transition = request
                .transition()
                .ok_or_else(|| "Ambient UDP finalize transition is incomplete".to_string())?;
            let mut state = state.ok_or_else(|| {
                "Ambient UDP finalize has no durable migration state on this node".to_string()
            })?;
            if state.active == transition.to
                && state.pending.is_none()
                && state.completed.as_ref() == Some(&transition)
            {
                // Finalize is idempotent, including its quarantine cleanup. A
                // crash or transient filesystem error after the durable state
                // write must not make a later retry skip the tombstone removal.
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
pub fn publish_registry_sync_marker_for_pods(
    registry_dir: &Path,
    generation: &str,
    expected_pod_uids: &HashSet<String>,
) -> Result<bool, String> {
    validate_generation(generation)?;
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
    Some(UdpRegistrySyncProof {
        generation: marker.generation,
        publication,
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
        }
    }
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static STATUS_PHASE: AtomicU8 = AtomicU8::new(0);
static OUTSTANDING: AtomicU64 = AtomicU64::new(0);
static FAILURE_REASON: AtomicU8 = AtomicU8::new(0);
static FAILURES_TOTAL: [AtomicU64; 13] = [const { AtomicU64::new(0) }; 13];
static ESTABLISHED_ADOPTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UdpMigrationStatusSnapshot {
    pub enabled: bool,
    pub phase: UdpMigrationStatusPhase,
    pub outstanding: u64,
    pub failure_reason: UdpMigrationFailureReason,
    /// True when this process started its placement from the release-attested
    /// established placement instead of a node-local durable record.
    pub established_adoption: bool,
}

fn record_established_adoption() {
    ENABLED.store(true, Ordering::Relaxed);
    ESTABLISHED_ADOPTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
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
        established_adoption: ESTABLISHED_ADOPTIONS_TOTAL.load(Ordering::Relaxed) > 0,
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
        "# HELP ferrum_mesh_udp_placement_migration_established_adoptions_total Ambient UDP placements adopted from the release-attested established placement without a node-local durable record.\n",
    );
    output.push_str(
        "# TYPE ferrum_mesh_udp_placement_migration_established_adoptions_total counter\n",
    );
    render_value(
        output,
        "ferrum_mesh_udp_placement_migration_established_adoptions_total",
        ESTABLISHED_ADOPTIONS_TOTAL.load(Ordering::Relaxed),
        gateway_ns_label,
    );
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
