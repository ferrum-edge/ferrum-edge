//! Host-side installer and uninstaller for the `ferrum-cni` binary.
//!
//! The node-agent image is distroless, so Helm cannot use `/bin/sh` to copy
//! files or render a CNI conflist. Instead the init container executes
//! `ferrum-cni install`, and this module performs those filesystem changes
//! directly.
//!
//! # Why uninstall needs ownership evidence
//!
//! Installing writes a chained `*-ferrum.conflist` into the host's shared
//! `/etc/cni/net.d/`. From that moment every pod ADD on the node traverses
//! `ferrum-cni`, so leaving the file behind after the node-agent goes away is
//! a node-wide pod-creation outage (issue #3609). Removal therefore has to be
//! available, idempotent, and — because the directory is shared with the
//! cluster's primary CNI and any other meta-plugin — provably scoped to
//! Ferrum's own artifacts.
//!
//! The proof is written at install time and is checked again at removal time:
//!
//! - the generated conflist carries a `managedBy` / `owner` / `generation`
//!   marker inside its own `ferrum-cni` plugin entry (a place the CNI spec
//!   reserves for the plugin, so no neighbour can be confused by it), and
//! - a sibling [`OWNERSHIP_MANIFEST_FILE_NAME`] manifest records the same
//!   ownership, the names of the artifacts it speaks for, and the SHA-256 of
//!   the binary that was installed.
//!
//! Uninstall removes an artifact only when that evidence is present and
//! matches; anything else is retained and reported. It never reads or
//! rewrites a neighbouring CNI configuration, and it never removes the shared
//! plugin binary while any CNI configuration on the node still references it.
//!
//! # What the manifest's `previousBinarySha256` does and does not prove
//!
//! Observing a digest is not owning the file it describes. `/opt/cni/bin/`
//! is shared, so the regular file already sitting at the plugin path on a
//! first install may belong to an operator or to another product entirely.
//! The installer therefore records a replaced digest **only** when a prior
//! manifest — same owner, naming these exact artifact names — already
//! attested that same digest as one of its own. Absent that attestation the
//! field is written `null`, and cleanup can never be talked into deleting a
//! binary this installer merely hashed. Retaining an unreferenced binary is
//! inert and never fails chain cleanup, so the safe direction is cheap.
//! The manifest's `binaryOwned` bit applies the same rule to its current
//! digest: publishing the staged inode sets it, as does reusing an inode a
//! prior same-owner manifest already attested. Merely finding byte-identical
//! bytes at the shared path leaves it false, so an operator-provided binary
//! cannot become removable through content equality alone.
//!
//! Install applies the same shared-binary rule cleanup does: while any other
//! `.conf` / `.conflist` / `.json` on the node still names `ferrum-cni`, the
//! shared executable is not replaced with different bytes. Republishing the
//! identical bytes is a no-op and stays allowed; evidence that cannot be read
//! fails safe by refusing the replacement.
//!
//! # Concurrency and swap resistance
//!
//! Every mutating path in this module takes an exclusive `flock` on
//! [`INSTALL_LOCK_FILE_NAME`] in the CNI configuration directory first, so an
//! installer publishing a chain and a cleanup run removing one can never
//! interleave on a node. That lock is the ownership boundary the rollback
//! watcher relies on: it cannot delete state while an installer still holds
//! the lock, and an installer cannot publish a conflist while a cleanup run
//! holds it.
//!
//! Within a run, artifacts are opened `O_NOFOLLOW`, classified against the
//! open handle, read with a hard byte cap, and hashed through that same
//! handle. Removal re-opens the path `O_NOFOLLOW` and refuses unless the
//! object still carries the device/inode identity the evidence was read from.
//! Temporary files are created `O_EXCL | O_NOFOLLOW` under an unpredictable
//! name, so a pre-planted symlink or file cannot be followed or truncated, and
//! their final mode is set through the open handle (`fchmod`), never by path.
//! Install additionally fail-closes under the lock before any staging or
//! shared write: an existing target conflist is overwritten only when it is a
//! bounded regular single-link file whose Ferrum ownership marker names this
//! same owner.
//!
//! What that does **not** claim: the final `unlink` is still by pathname, so
//! a writer with write access to the CNI configuration directory could in
//! principle swap the entry between the identity re-check and the unlink.
//! The `flock` removes that race between Ferrum's own processes; against a
//! hostile third party with write access to a root-owned host CNI directory
//! it narrows the window rather than closing it.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
#[cfg(unix)]
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use thiserror::Error;

use crate::fips::approved::Sha256;

const FERRUM_PLUGIN_TYPE: &str = "ferrum-cni";

/// Value of the `managedBy` marker Ferrum writes into both the generated
/// conflist's own plugin entry and the sibling ownership manifest. Uninstall
/// refuses to remove any artifact that does not carry it.
pub const FERRUM_MANAGED_BY: &str = "ferrum-edge";

/// Sibling ownership manifest written next to the generated conflist.
///
/// The name deliberately does not end in `.conf` / `.conflist` / `.json`, so
/// the container runtime never mistakes it for a network configuration and
/// [`find_primary_config`]'s scan skips it outright.
pub const OWNERSHIP_MANIFEST_FILE_NAME: &str = ".ferrum-cni-owned.marker";

/// Cross-process mutual-exclusion file for every mutating lifecycle step.
///
/// Like the manifest, the name carries no CNI configuration extension, so the
/// container runtime and the primary-config scan both ignore it. It is
/// deliberately left behind by cleanup: it holds no state, and removing it
/// would drop the lock a concurrent run may be waiting on.
pub const INSTALL_LOCK_FILE_NAME: &str = ".ferrum-cni-install.lock";

/// Schema version of the ownership manifest. A manifest with any other
/// version is treated as unreadable (ownership unproven) rather than
/// guessed at.
const OWNERSHIP_MANIFEST_SCHEMA_VERSION: u64 = 1;

/// Hard ceiling on the JSON artifacts uninstall is willing to read before
/// deciding ownership. Anything larger was not written by the installer, so
/// it is retained instead of parsed.
const MAX_OWNED_JSON_BYTES: u64 = 1024 * 1024;

/// Hard ceiling on the installed plugin binary uninstall is willing to hash.
const MAX_OWNED_BINARY_BYTES: u64 = 512 * 1024 * 1024;

/// Bound on the opaque operator-supplied owner / generation tokens.
const MAX_OWNERSHIP_TOKEN_BYTES: usize = 128;

/// How long a lifecycle step waits for the node's install lock before giving
/// up. Long enough to sit through a peer's whole publish, short enough that a
/// wedged holder surfaces as a visible failure rather than a hang.
#[cfg(unix)]
const INSTALL_LOCK_WAIT: Duration = Duration::from_secs(60);

/// Gap between install-lock acquisition attempts.
#[cfg(unix)]
const INSTALL_LOCK_RETRY: Duration = Duration::from_millis(100);

/// Attempts at finding an unused temporary name before giving up.
const TEMP_NAME_ATTEMPTS: usize = 8;

/// Copy/hash chunk size.
const COPY_CHUNK_BYTES: usize = 64 * 1024;

/// Fixed reason strings. They are `&'static str` on purpose: cleanup
/// diagnostics print operator-configured paths and these constants, never
/// file contents or any other untrusted input.
const REASON_SYMLINK: &str = "path is a symlink; Ferrum only installs and removes regular files";
const REASON_NOT_REGULAR: &str = "path is not a regular file";
const REASON_HARD_LINKED: &str =
    "path is hard-linked; removing it could affect another name for the same file";
const REASON_TOO_LARGE: &str = "file is larger than any artifact this installer writes";
const REASON_SWAPPED: &str =
    "the file was replaced between the ownership check and removal; nothing was deleted";
/// Existing target conflist has no usable Ferrum ownership marker.
const REASON_TARGET_UNOWNED: &str = "existing configuration carries no Ferrum ownership marker; it was not written by this installer";
/// Existing target has a Ferrum-shaped marker, but its required ownership
/// tokens are absent or outside the installer's bounded alphabet.
const REASON_TARGET_INVALID_MARKER: &str =
    "existing configuration carries an invalid Ferrum ownership marker";
/// Existing target conflist is a valid Ferrum chain for a different release.
const REASON_TARGET_OTHER_OWNER: &str =
    "existing configuration is owned by a different Ferrum install";
/// Another CNI configuration still chains to the shared plugin binary and the
/// staged bytes differ from the installed ones.
const REASON_SHARED_BINARY_REFERENCED: &str = "another CNI configuration on this node still references the ferrum-cni plugin, \
     and the staged binary differs from the installed one";
/// The installed plugin binary could not be classified, so its bytes are
/// unknown, while another configuration still chains to it.
const REASON_SHARED_BINARY_UNCLASSIFIABLE: &str = "the installed plugin binary could not be classified as a plain regular file, \
     and another CNI configuration on this node still references it";
/// The directory scan that decides whether the binary is shared could not be
/// completed, so replacement is refused rather than guessed at.
const REASON_SHARED_BINARY_UNPROVABLE: &str = "the CNI configuration directory could not be scanned for other ferrum-cni references, \
     so the shared plugin binary is not replaced";

/// Install-time identity stamped onto every generated artifact.
///
/// `owner` is expected to be stable across upgrades of one deployment (the
/// Helm chart uses `<release namespace>/<release name>`), while `generation`
/// identifies one concrete install instance (the chart uses the node-agent
/// pod UID). Uninstall matches on `owner`, so it cleans up whatever revision
/// is currently on the node; the readiness rollback watcher matches on both,
/// so it can never remove artifacts a newer install wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CniOwnership {
    pub owner: String,
    pub generation: String,
}

impl CniOwnership {
    fn validate(&self) -> Result<(), CniInstallError> {
        validate_ownership_token("OWNER_ID", &self.owner)?;
        validate_ownership_token("INSTALL_GENERATION", &self.generation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CniInstallConfig {
    pub host_bin_dir: String,
    pub host_conf_dir: String,
    pub host_socket_dir: String,
    pub conf_file_name: String,
    pub chained_with: String,
    pub socket_path: String,
    pub ownership: CniOwnership,
}

impl CniInstallConfig {
    pub fn from_env() -> Result<Self, CniInstallError> {
        Ok(Self {
            host_bin_dir: required_env("HOST_BIN_DIR")?,
            host_conf_dir: required_env("HOST_CONF_DIR")?,
            host_socket_dir: required_env("HOST_SOCKET_DIR")?,
            conf_file_name: required_env("CONF_FILE_NAME")?,
            chained_with: required_env("CHAINED_WITH")?,
            socket_path: required_env("SOCKET_PATH")?,
            ownership: CniOwnership {
                owner: required_env("OWNER_ID")?,
                generation: required_env("INSTALL_GENERATION")?,
            },
        })
    }
}

/// Which Ferrum-generated artifacts a cleanup run may remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CniUninstallConfig {
    pub host_bin_dir: String,
    pub host_conf_dir: String,
    pub conf_file_name: String,
    /// When set, only artifacts recorded under this owner are removed.
    pub expected_owner: Option<String>,
    /// When set, only artifacts recorded under this install generation are
    /// removed. Left unset by `helm uninstall` (any generation of this
    /// owner's install should go) and set by the readiness rollback watcher
    /// (only its own generation may go).
    pub expected_generation: Option<String>,
}

impl CniUninstallConfig {
    pub fn from_env() -> Result<Self, CniInstallError> {
        Ok(Self {
            host_bin_dir: required_env("HOST_BIN_DIR")?,
            host_conf_dir: required_env("HOST_CONF_DIR")?,
            conf_file_name: required_env("CONF_FILE_NAME")?,
            expected_owner: optional_env("EXPECTED_OWNER"),
            expected_generation: optional_env("EXPECTED_GENERATION"),
        })
    }

    /// True when `found` is exactly the scope this cleanup may remove.
    pub fn owns(&self, found: &CniOwnership) -> bool {
        matches!(match_ownership(self, found), OwnershipMatch::Match)
    }

    fn validate(&self) -> Result<(), CniInstallError> {
        validate_single_component("CONF_FILE_NAME", &self.conf_file_name)?;
        if let Some(owner) = self.expected_owner.as_deref() {
            validate_ownership_token("EXPECTED_OWNER", owner)?;
        }
        if let Some(generation) = self.expected_generation.as_deref() {
            validate_ownership_token("EXPECTED_GENERATION", generation)?;
        }
        Ok(())
    }
}

/// What happened to one artifact during cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CniArtifactOutcome {
    /// The artifact was Ferrum-owned and has been removed.
    Removed,
    /// Nothing was there — a repeat cleanup, or an install that never landed.
    AlreadyAbsent,
    /// Something occupies the path but is not provably a Ferrum artifact.
    /// Retained untouched; the reason is a fixed, non-echoing string.
    RetainedForeign(&'static str),
    /// Ferrum-owned, deliberately kept (for example, so a later run can still
    /// prove ownership).
    RetainedDeliberate(&'static str),
    /// Owned by a different install (different `owner` marker).
    RetainedOtherOwner,
    /// Owned by a different generation of this install.
    RetainedOtherGeneration,
}

impl CniArtifactOutcome {
    /// True when the artifact is gone from the node as far as this run is
    /// concerned.
    pub fn is_cleared(&self) -> bool {
        matches!(self, Self::Removed | Self::AlreadyAbsent)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::AlreadyAbsent => "already-absent",
            Self::RetainedForeign(_) => "retained-foreign",
            Self::RetainedDeliberate(_) => "retained",
            Self::RetainedOtherOwner => "retained-other-owner",
            Self::RetainedOtherGeneration => "retained-other-generation",
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Self::Removed => "Ferrum ownership marker matched",
            Self::AlreadyAbsent => "no artifact present",
            Self::RetainedForeign(reason) | Self::RetainedDeliberate(reason) => reason,
            Self::RetainedOtherOwner => "a different Ferrum install owns this artifact",
            Self::RetainedOtherGeneration => {
                "a different generation of this install owns this artifact"
            }
        }
    }
}

/// Per-artifact outcome of one cleanup run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CniUninstallReport {
    pub conf_path: String,
    pub conflist: CniArtifactOutcome,
    pub binary_path: String,
    pub binary: CniArtifactOutcome,
    pub manifest_path: String,
    pub manifest: CniArtifactOutcome,
}

impl CniUninstallReport {
    /// Cleanup succeeded when the chained conflist is no longer Ferrum's
    /// problem on this node: removed, already absent, or provably owned by a
    /// different install that this run must not touch.
    ///
    /// The plugin binary deliberately does not gate success. It is inert once
    /// nothing chains to it, and refusing to complete a `helm uninstall`
    /// because an unreferenced `/opt/cni/bin/ferrum-cni` could not be proven
    /// ours would trade a real outage for a cosmetic one. Its outcome is
    /// still reported so the retention is visible.
    pub fn is_success(&self) -> bool {
        !matches!(self.conflist, CniArtifactOutcome::RetainedForeign(_))
    }

    /// True when this run actually removed the node-wide dependency: the
    /// generated conflist is gone from the node.
    ///
    /// Distinct from [`Self::is_success`], which also accepts "another
    /// install owns this chain, so it is not mine to lift". A caller that
    /// wants to tell an operator "pod creation no longer depends on the
    /// node-agent" must use this, not success.
    pub fn chain_lifted(&self) -> bool {
        self.conflist.is_cleared()
    }

    /// One line per artifact, safe to print to stderr: every field is either
    /// an operator-supplied path or a fixed reason string.
    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!(
                "conflist {}: {} ({})",
                self.conf_path,
                self.conflist.as_str(),
                self.conflist.reason()
            ),
            format!(
                "binary {}: {} ({})",
                self.binary_path,
                self.binary.as_str(),
                self.binary.reason()
            ),
            format!(
                "ownership-manifest {}: {} ({})",
                self.manifest_path,
                self.manifest.as_str(),
                self.manifest.reason()
            ),
        ]
    }
}

#[derive(Debug, Error)]
pub enum CniInstallError {
    #[error("missing required installer env var {0}")]
    MissingEnv(&'static str),
    #[error("filesystem error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid JSON in {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("no primary CNI config matching type {plugin_type:?} found in {conf_dir}")]
    PrimaryConfigNotFound {
        conf_dir: String,
        plugin_type: String,
    },
    #[error("primary CNI config {path} is not a JSON object")]
    PrimaryConfigNotObject { path: String },
    #[error("primary CNI config {path} has an empty plugins array")]
    EmptyPluginList { path: String },
    #[error("could not resolve current executable: {0}")]
    CurrentExe(std::io::Error),
    #[error(
        "another ferrum-cni install or cleanup still holds {path}; \
         refusing to run concurrently with it"
    )]
    LockBusy { path: String },
    #[error("{path} is not a readable regular plugin binary")]
    UnusableSourceBinary { path: String },
    #[error(
        "{name} must be 1..={max} bytes of [A-Za-z0-9._:/@#-]; \
         set it from a stable deployment identity"
    )]
    InvalidOwnershipToken { name: &'static str, max: usize },
    #[error("{name} must be a single file name with no path separators, `.` or `..`")]
    InvalidFileName { name: &'static str },
    #[error("{name} is not valid: expected {expected}")]
    InvalidEnvValue {
        name: &'static str,
        expected: &'static str,
    },
    #[error(
        "{path} exists but is not a plain regular file; refusing to reuse it \
         as this run's cleanup readiness marker"
    )]
    UnsafeReadyMarker { path: String },
    #[error("refusing to overwrite {path}: {reason}")]
    UnsafeInstallTarget { path: String, reason: &'static str },
    #[error("refusing to replace the shared plugin binary {path}: {reason}")]
    SharedBinaryInUse { path: String, reason: &'static str },
}

pub fn install_from_env() -> Result<PathBuf, CniInstallError> {
    let config = CniInstallConfig::from_env()?;
    let source_binary = std::env::current_exe().map_err(CniInstallError::CurrentExe)?;
    install(&config, &source_binary)
}

/// Install (or upgrade in place) the Ferrum CNI artifacts on this node.
///
/// Idempotent: re-running with the same source binary re-stamps ownership and
/// rewrites the chain without touching the published binary at all.
///
/// # Failure is an availability question, not just a cleanliness one
///
/// On a same-owner upgrade the node may already be carrying this owner's
/// PREVIOUS chain. That chain routes every pod ADD through a `ferrum-cni`
/// socket the replacement pod is the one expected to serve, so an install
/// that fails before publishing would leave the node pointing at a node-agent
/// that never starts — and the replacement's rollback watcher, which is
/// scoped to the generation that was never published, would correctly refuse
/// to remove anything. `install` therefore lifts that pre-existing same-owner
/// chain on its ordinary error path, still under the lock and still only
/// after re-proving the exact owner, generation, and device/inode it observed
/// during preflight. A chain that a different owner, or a generation that
/// overtook this run, now occupies is left strictly alone.
pub fn install(
    config: &CniInstallConfig,
    source_binary: &Path,
) -> Result<PathBuf, CniInstallError> {
    config.ownership.validate()?;
    validate_single_component("CONF_FILE_NAME", &config.conf_file_name)?;

    let host_bin_dir = Path::new(&config.host_bin_dir);
    let host_conf_dir = Path::new(&config.host_conf_dir);
    let host_socket_dir = Path::new(&config.host_socket_dir);

    create_dir_all(host_bin_dir)?;
    create_dir_all(host_conf_dir)?;
    create_dir_all(host_socket_dir)?;

    // Nothing shared may change until this node's lifecycle lock is held: a
    // rollback watcher that reached its deadline must not be able to delete
    // an artifact while this run is still publishing the next one. The lock
    // also spans the recovery below, so the chain this run may lift cannot be
    // replaced by a peer installer between the failure and the removal.
    let _lock = InstallLock::acquire(host_conf_dir)?;

    // Fail closed before any staging, manifest, binary, or target-config write:
    // an absent target is fine; an existing one may be overwritten only when it
    // is a bounded regular single-link file whose Ferrum marker names this
    // same owner. A foreign, malformed, or differently-owned file must never
    // be destroyed by install.
    let target_state =
        assert_install_target_reusable(host_conf_dir, &config.conf_file_name, &config.ownership)?;

    match install_under_lock(config, host_bin_dir, host_conf_dir, source_binary) {
        Ok(target_conf) => Ok(target_conf),
        Err(error) => {
            lift_stranded_same_owner_chain(host_conf_dir, &config.conf_file_name, &target_state);
            Err(error)
        }
    }
}

/// The publication sequence, run with the node lifecycle lock already held and
/// the configured target conflist already proven reusable.
///
/// ORDER IS LOAD-BEARING, and every step before the first shared write is
/// there so that a failure cannot leave shared state half-changed.
fn install_under_lock(
    config: &CniInstallConfig,
    host_bin_dir: &Path,
    host_conf_dir: &Path,
    source_binary: &Path,
) -> Result<PathBuf, CniInstallError> {
    let target_conf = host_conf_dir.join(&config.conf_file_name);
    let target_binary = host_bin_dir.join(FERRUM_PLUGIN_TYPE);

    // 1. EVERY non-publication step runs first: finding the primary config,
    //    building the chain, and serializing it. All three can fail on input
    //    this installer does not control (a missing primary, a primary that
    //    is not an object, an empty plugin list), so none of them may run
    //    after the shared manifest or the shared binary has been touched.
    let primary = find_primary_config(host_conf_dir, &config.conf_file_name, &config.chained_with)?;
    let chained = build_chained_conflist(
        &primary.json,
        &config.socket_path,
        &config.ownership,
        &primary.path,
    )?;
    let mut conflist_bytes =
        serde_json::to_vec_pretty(&chained).map_err(|source| CniInstallError::Json {
            path: target_conf.display().to_string(),
            source,
        })?;
    conflist_bytes.push(b'\n');

    // 2. The new binary is staged NEXT TO its destination and hashed as it is
    //    written, so the digest describes exactly the bytes that will be
    //    published, from a file nothing else can reach yet. The staging file
    //    is an unguessable `O_EXCL | O_NOFOLLOW` sibling and is removed on
    //    every exit, so this is still not a shared mutation.
    let staged = StagedBinary::stage(source_binary, &target_binary)?;

    // 3. Decide whether the SHARED executable may be replaced at all, using
    //    the same rule cleanup applies in the other direction. Refusal here
    //    happens before the manifest write, so a refused install leaves the
    //    shared binary and the shared manifest byte-identical.
    let installed = classify_installed_binary(&target_binary)?;
    let publication = plan_binary_publication(
        host_conf_dir,
        &config.conf_file_name,
        &target_binary,
        &installed,
        &staged.sha256,
    )?;

    // 4. The ownership manifest lands BEFORE the shared binary is published.
    //    Nothing this install can leave behind — including after a failure at
    //    any later step — is therefore un-provable, and so nothing it leaves
    //    behind is un-removable. A replaced digest is carried forward only
    //    when prior same-owner manifest evidence already attested it (see the
    //    module docs); merely hashing whatever occupied the path proves
    //    nothing and authorizes nothing.
    let previous_sha256 = attested_previous_binary_digest(host_conf_dir, config, &installed)?;
    // Reusing byte-identical bytes is not proof that Ferrum published the
    // inode already occupying this shared path. Claim it only when this run
    // will publish the staged inode, or prior same-owner evidence already
    // attested the installed one. Otherwise cleanup may remove the chain but
    // must retain the pre-existing binary.
    let binary_owned =
        matches!(publication, BinaryPublication::Publish) || previous_sha256.is_some();
    write_ownership_manifest(
        host_conf_dir,
        &config.ownership,
        &config.conf_file_name,
        &staged.sha256,
        previous_sha256.as_deref(),
        binary_owned,
    )?;

    // 5. The binary is published before anything can reference it, by an
    //    atomic same-directory rename — never an in-place truncate. An
    //    already-exec'd `ferrum-cni` keeps running from the old inode until
    //    it exits, and kubelet's next exec resolves the new one. When the
    //    staged bytes are identical to what is already installed (the routine
    //    `helm upgrade` case) the rename is skipped entirely, so an unchanged
    //    image performs no binary swap at all.
    match publication {
        BinaryPublication::ReuseInstalled => staged.discard(),
        BinaryPublication::Publish => staged.publish(&target_binary)?,
    }

    // 6. The conflist goes down LAST, and atomically: the moment it lands,
    //    every pod ADD on this node traverses ferrum-cni, so nothing that
    //    could fail may still be pending at that point. Its bytes were built
    //    in step 1, so the only remaining failure is the publish itself.
    atomic_write_file(&target_conf, &conflist_bytes, Some(0o644))?;
    Ok(target_conf)
}

/// Recovery for a failed install that found a pre-existing same-owner chain.
///
/// Removes that chain only when it is still, byte-for-byte and inode-for-inode,
/// the object preflight classified: same device/inode/length, and a Ferrum
/// marker naming the same owner AND the same generation. Anything else — a
/// different owner, a generation that overtook this run, a swapped or
/// rewritten file — is retained untouched. Diagnostics carry operator-supplied
/// paths and fixed strings only.
///
/// Failures here are reported, never returned: the caller must surface the
/// original install error, and a recovery that could not run has changed
/// nothing.
fn lift_stranded_same_owner_chain(
    conf_dir: &Path,
    conf_file_name: &str,
    state: &InstallTargetState,
) {
    let InstallTargetState::SameOwnerChain {
        ownership,
        identity,
    } = state
    else {
        return;
    };
    let path = conf_dir.join(conf_file_name);
    let still_ours = match read_bounded_regular_file(&path, MAX_OWNED_JSON_BYTES) {
        Ok(ArtifactRead::Present {
            bytes,
            identity: found,
        }) => found == *identity && conflist_ownership(&bytes).as_ref() == Some(ownership),
        // Nothing is there any more, so nothing holds the node. Not a
        // retention worth reporting.
        Ok(ArtifactRead::Absent) => return,
        Ok(ArtifactRead::Rejected(_)) | Err(_) => false,
    };
    // Diagnostics go to stderr, not `tracing`: `install` only ever runs from
    // the `ferrum-cni` CLI, which installs no subscriber, and an operator
    // reading an init-container log is the whole audience for this. Every
    // interpolated value is an operator-configured path or a fixed string.
    if !still_ours {
        eprintln!(
            "ferrum-cni: install failed; {} is no longer the same-owner chained configuration \
             this run observed, so nothing was removed",
            path.display()
        );
        return;
    }
    match remove_verified(&path, *identity) {
        Ok(CniArtifactOutcome::Removed | CniArtifactOutcome::AlreadyAbsent) => {
            eprintln!(
                "ferrum-cni: install failed during a same-owner upgrade; removed {} so pod \
                 creation on this node no longer depends on a node-agent this install never \
                 published",
                path.display()
            );
        }
        Ok(outcome) => {
            eprintln!(
                "ferrum-cni: install failed and {} could not be removed ({}: {}); pod creation \
                 on this node still depends on the node-agent",
                path.display(),
                outcome.as_str(),
                outcome.reason()
            );
        }
        Err(error) => {
            eprintln!(
                "ferrum-cni: install failed and {} could not be removed: {error}; pod creation \
                 on this node still depends on the node-agent",
                path.display()
            );
        }
    }
}

pub fn uninstall_from_env() -> Result<CniUninstallReport, CniInstallError> {
    uninstall(&CniUninstallConfig::from_env()?)
}

/// Remove the Ferrum-generated CNI artifacts, and only those.
///
/// Idempotent: a repeat run over an already-cleaned node reports
/// `AlreadyAbsent` for every artifact and succeeds. Partial state (manifest
/// without conflist, conflist without manifest, truncated manifest) resolves
/// to the safest action each artifact can independently justify.
pub fn uninstall(config: &CniUninstallConfig) -> Result<CniUninstallReport, CniInstallError> {
    config.validate()?;

    let conf_dir = Path::new(&config.host_conf_dir);
    let bin_dir = Path::new(&config.host_bin_dir);
    let conf_path = conf_dir.join(&config.conf_file_name);
    let manifest_path = conf_dir.join(OWNERSHIP_MANIFEST_FILE_NAME);
    let binary_path = bin_dir.join(FERRUM_PLUGIN_TYPE);

    // Serialize against a concurrent installer for the whole run. A missing
    // configuration directory means nothing was ever installed, so there is
    // nothing to serialize against and nothing to remove.
    let _lock = InstallLock::acquire_if_dir_exists(conf_dir)?;

    let manifest_state = read_ownership_manifest(&manifest_path)?;
    let manifest = match &manifest_state {
        ManifestState::Present(manifest) => Some(manifest),
        ManifestState::Absent | ManifestState::Unusable(_) => None,
    };

    // 1. The chained conflist. This is the artifact that makes the node-agent
    //    a node-wide pod-creation dependency, so it goes first: once it is
    //    gone kubelet stops invoking ferrum-cni and the binary is inert.
    //    Ownership comes from the marker inside the file itself, not from the
    //    manifest, so a lost manifest can never strand the chain.
    let conflist = match read_bounded_regular_file(&conf_path, MAX_OWNED_JSON_BYTES)? {
        ArtifactRead::Absent => CniArtifactOutcome::AlreadyAbsent,
        ArtifactRead::Rejected(reason) => CniArtifactOutcome::RetainedForeign(reason),
        ArtifactRead::Present { bytes, identity } => match conflist_ownership(&bytes) {
            None => CniArtifactOutcome::RetainedForeign(
                "file carries no Ferrum ownership marker; it was not written by this installer",
            ),
            Some(found) => match match_ownership(config, &found) {
                OwnershipMatch::Match => remove_verified(&conf_path, identity)?,
                OwnershipMatch::OtherOwner => CniArtifactOutcome::RetainedOtherOwner,
                OwnershipMatch::OtherGeneration => CniArtifactOutcome::RetainedOtherGeneration,
            },
        },
    };

    // 2. The plugin binary. `/opt/cni/bin/ferrum-cni` is SHARED: another
    //    Ferrum release, or an operator-authored configuration, may chain to
    //    the same executable. It therefore goes only when this run's chain is
    //    gone, NO remaining CNI configuration on the node still names
    //    `ferrum-cni`, and the manifest's recorded digest matches the bytes
    //    on disk. Anything that cannot be proven keeps the binary: it is
    //    inert once nothing references it, so retention costs a stale file
    //    while deletion could break a live release.
    let binary = if !conflist.is_cleared() {
        CniArtifactOutcome::RetainedDeliberate(
            "a chained CNI configuration still references the plugin binary",
        )
    } else {
        match remaining_ferrum_references(conf_dir, &config.conf_file_name) {
            FerrumReferences::Found => CniArtifactOutcome::RetainedDeliberate(
                "another CNI configuration on this node still references the ferrum-cni plugin",
            ),
            FerrumReferences::Unknown => CniArtifactOutcome::RetainedForeign(
                "the CNI configuration directory could not be scanned for remaining \
                 ferrum-cni references, so the shared binary is kept",
            ),
            FerrumReferences::None => remove_owned_binary(config, manifest, &binary_path)?,
        }
    };

    // 3. The ownership manifest itself, only once it has nothing left to
    //    prove. Retaining it after a partial cleanup is what makes a retry
    //    able to finish the job.
    let manifest_outcome = match &manifest_state {
        ManifestState::Absent => CniArtifactOutcome::AlreadyAbsent,
        ManifestState::Unusable(reason) => CniArtifactOutcome::RetainedForeign(reason),
        ManifestState::Present(manifest) => {
            if !conflist.is_cleared() || !binary.is_cleared() {
                CniArtifactOutcome::RetainedDeliberate(
                    "retained so a later cleanup run can still prove ownership",
                )
            } else {
                match match_ownership(config, &manifest.ownership) {
                    OwnershipMatch::Match => remove_verified(&manifest_path, manifest.identity)?,
                    OwnershipMatch::OtherOwner => CniArtifactOutcome::RetainedOtherOwner,
                    OwnershipMatch::OtherGeneration => CniArtifactOutcome::RetainedOtherGeneration,
                }
            }
        }
    };

    Ok(CniUninstallReport {
        conf_path: conf_path.display().to_string(),
        conflist,
        binary_path: binary_path.display().to_string(),
        binary,
        manifest_path: manifest_path.display().to_string(),
        manifest: manifest_outcome,
    })
}

/// Decide the shared plugin binary's fate once the chain is provably gone and
/// nothing else on the node references `ferrum-cni`.
fn remove_owned_binary(
    config: &CniUninstallConfig,
    manifest: Option<&OwnershipManifest>,
    binary_path: &Path,
) -> Result<CniArtifactOutcome, CniInstallError> {
    let Some(manifest) = manifest else {
        return Ok(
            match open_classified(binary_path, MAX_OWNED_BINARY_BYTES)? {
                ClassifiedArtifact::Absent => CniArtifactOutcome::AlreadyAbsent,
                ClassifiedArtifact::Rejected(reason) => CniArtifactOutcome::RetainedForeign(reason),
                ClassifiedArtifact::Present { .. } => CniArtifactOutcome::RetainedForeign(
                    "no ownership manifest records this binary as Ferrum-installed",
                ),
            },
        );
    };
    if !manifest.speaks_for(&config.conf_file_name) {
        return Ok(CniArtifactOutcome::RetainedForeign(
            "the ownership manifest does not name this configuration and plugin binary",
        ));
    }
    match match_ownership(config, &manifest.ownership) {
        OwnershipMatch::OtherOwner => return Ok(CniArtifactOutcome::RetainedOtherOwner),
        OwnershipMatch::OtherGeneration => {
            return Ok(CniArtifactOutcome::RetainedOtherGeneration);
        }
        OwnershipMatch::Match => {}
    }
    // Classify, hash, and remove through ONE open, so the digest that
    // authorizes removal is the digest of the object being removed.
    let (mut file, identity) = match open_classified(binary_path, MAX_OWNED_BINARY_BYTES)? {
        ClassifiedArtifact::Absent => return Ok(CniArtifactOutcome::AlreadyAbsent),
        ClassifiedArtifact::Rejected(reason) => {
            return Ok(CniArtifactOutcome::RetainedForeign(reason));
        }
        ClassifiedArtifact::Present { file, identity } => (file, identity),
    };
    let digest = hash_open_file(&mut file, binary_path, MAX_OWNED_BINARY_BYTES)?;
    drop(file);
    if !manifest.digest_matches(&digest) {
        return Ok(CniArtifactOutcome::RetainedForeign(
            "binary content does not match the digest recorded at install",
        ));
    }
    remove_verified(binary_path, identity)
}

/// Network name of the generated conflist, used by the readiness watcher's
/// STATUS probe. Returns `None` when the file is absent or unreadable — the
/// caller falls back to a constant rather than failing the probe.
pub fn generated_network_name(conf_dir: &str, conf_file_name: &str) -> Option<String> {
    let value = read_generated_conflist(conf_dir, conf_file_name)?;
    let name = value.get("name")?.as_str()?;
    Some(name.to_string())
}

/// Ownership currently published in the generated conflist, or `None` when no
/// Ferrum-generated chain is present at that path.
///
/// The rollback watcher uses this to prove that the install it is watching
/// actually completed: the conflist is written last, so its presence under
/// this generation's marker is the only observable "the install finished and
/// this node now depends on the node-agent" signal.
pub fn published_conflist_ownership(conf_dir: &str, conf_file_name: &str) -> Option<CniOwnership> {
    let value = read_generated_conflist(conf_dir, conf_file_name)?;
    conflist_ownership_value(&value)
}

fn read_generated_conflist(conf_dir: &str, conf_file_name: &str) -> Option<Value> {
    if validate_single_component("CONF_FILE_NAME", conf_file_name).is_err() {
        return None;
    }
    let path = Path::new(conf_dir).join(conf_file_name);
    let bytes = match read_bounded_regular_file(&path, MAX_OWNED_JSON_BYTES) {
        Ok(ArtifactRead::Present { bytes, .. }) => bytes,
        _ => return None,
    };
    serde_json::from_slice(&bytes).ok()
}

struct OwnershipManifest {
    ownership: CniOwnership,
    conf_file_name: String,
    binary_file_name: String,
    binary_owned: bool,
    binary_sha256: String,
    previous_binary_sha256: Option<String>,
    identity: FileIdentity,
}

impl OwnershipManifest {
    /// The manifest is evidence for exactly the artifact names it recorded.
    /// A manifest naming a different conflist or a different binary proves
    /// nothing about the files this run is about to touch.
    fn speaks_for(&self, conf_file_name: &str) -> bool {
        self.conf_file_name == conf_file_name && self.binary_file_name == FERRUM_PLUGIN_TYPE
    }

    /// An upgrade records both the digest it published and the one it
    /// replaced, so a crash between the manifest write and the binary swap
    /// still leaves whichever of the two is on disk provably ours.
    fn digest_matches(&self, digest: &str) -> bool {
        self.binary_owned
            && (self.binary_sha256 == digest
                || self.previous_binary_sha256.as_deref() == Some(digest))
    }
}

/// What the sibling ownership manifest could be made to say.
///
/// `Unusable` is deliberately distinct from `Absent`: a corrupt manifest
/// leaves a real file on disk, and reporting it as "already absent" would be
/// a quiet lie in the cleanup summary.
enum ManifestState {
    Absent,
    Unusable(&'static str),
    Present(OwnershipManifest),
}

enum OwnershipMatch {
    Match,
    OtherOwner,
    OtherGeneration,
}

fn match_ownership(config: &CniUninstallConfig, found: &CniOwnership) -> OwnershipMatch {
    if let Some(expected) = config.expected_owner.as_deref()
        && expected != found.owner
    {
        return OwnershipMatch::OtherOwner;
    }
    if let Some(expected) = config.expected_generation.as_deref()
        && expected != found.generation
    {
        return OwnershipMatch::OtherGeneration;
    }
    OwnershipMatch::Match
}

/// Ownership recorded inside the generated conflist's own plugin entry.
/// Returns `None` for anything that is not a Ferrum-generated chain.
fn conflist_ownership(bytes: &[u8]) -> Option<CniOwnership> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    conflist_ownership_value(&value)
}

/// What the install preflight found at the configured target path.
///
/// The `SameOwnerChain` arm is what makes the failed-upgrade recovery
/// provable: it carries the exact ownership marker and the exact
/// device/inode/length the preflight classified, so the error path can
/// re-prove both before unlinking anything.
enum InstallTargetState {
    Absent,
    SameOwnerChain {
        ownership: CniOwnership,
        identity: FileIdentity,
    },
}

/// Fail-closed install preflight for the configured target conflist.
///
/// Held under the install lock and run before every staging / manifest /
/// binary / target write. Reuses the same bounded `O_NOFOLLOW` open-handle
/// classification and in-file ownership marker helpers uninstall uses; it
/// does not soften uninstall's evidence rules. Same-owner upgrades across
/// generations are allowed; every uncertain or foreign case is refused with
/// a fixed reason and no mutation of shared artifacts.
fn assert_install_target_reusable(
    conf_dir: &Path,
    conf_file_name: &str,
    ownership: &CniOwnership,
) -> Result<InstallTargetState, CniInstallError> {
    let path = conf_dir.join(conf_file_name);
    match read_bounded_regular_file(&path, MAX_OWNED_JSON_BYTES)? {
        ArtifactRead::Absent => Ok(InstallTargetState::Absent),
        ArtifactRead::Rejected(reason) => Err(CniInstallError::UnsafeInstallTarget {
            path: path.display().to_string(),
            reason,
        }),
        ArtifactRead::Present { bytes, identity } => match conflist_ownership(&bytes) {
            None => Err(CniInstallError::UnsafeInstallTarget {
                path: path.display().to_string(),
                reason: REASON_TARGET_UNOWNED,
            }),
            Some(found) if found.validate().is_err() => Err(CniInstallError::UnsafeInstallTarget {
                path: path.display().to_string(),
                reason: REASON_TARGET_INVALID_MARKER,
            }),
            Some(found) if found.owner == ownership.owner => {
                Ok(InstallTargetState::SameOwnerChain {
                    ownership: found,
                    identity,
                })
            }
            Some(_) => Err(CniInstallError::UnsafeInstallTarget {
                path: path.display().to_string(),
                reason: REASON_TARGET_OTHER_OWNER,
            }),
        },
    }
}

/// The plugin binary currently occupying the shared install path.
///
/// `Unreadable` is deliberately distinct from `Absent`: a symlink, a
/// directory, a hard-linked file, or an oversized object all leave something
/// real at the path whose bytes this installer cannot account for, and that
/// uncertainty must fail safe rather than read as "nothing is installed".
enum InstalledBinary {
    Absent,
    Unreadable,
    Present(String),
}

/// Classify and hash whatever occupies the shared plugin binary path, through
/// one open handle so the digest describes the object that was classified.
fn classify_installed_binary(path: &Path) -> Result<InstalledBinary, CniInstallError> {
    match open_classified(path, MAX_OWNED_BINARY_BYTES)? {
        ClassifiedArtifact::Absent => Ok(InstalledBinary::Absent),
        ClassifiedArtifact::Rejected(_) => Ok(InstalledBinary::Unreadable),
        ClassifiedArtifact::Present { mut file, .. } => Ok(InstalledBinary::Present(
            hash_open_file(&mut file, path, MAX_OWNED_BINARY_BYTES)?,
        )),
    }
}

/// Whether this run publishes its staged binary or reuses what is installed.
#[derive(Clone, Copy)]
enum BinaryPublication {
    Publish,
    ReuseInstalled,
}

/// Apply the shared-binary rule at install time.
///
/// `/opt/cni/bin/ferrum-cni` is SHARED: another Ferrum release, or an
/// operator-authored configuration, may chain to the same executable, and
/// cleanup already refuses to delete it while such a reference exists.
/// Install owes that reference the mirror-image guarantee — it must not swap
/// the bytes out from under a live chain. Byte-identical republication is not
/// a replacement and stays allowed; an unreadable installed object or an
/// unscannable directory is ambiguous and fails safe.
fn plan_binary_publication(
    conf_dir: &Path,
    generated_file_name: &str,
    binary_path: &Path,
    installed: &InstalledBinary,
    staged_sha256: &str,
) -> Result<BinaryPublication, CniInstallError> {
    let replacement_reason = match installed {
        // The bytes already on disk are exactly the bytes this run would
        // publish, so nothing is replaced and no reference can be disturbed.
        InstalledBinary::Present(digest) if digest.as_str() == staged_sha256 => {
            return Ok(BinaryPublication::ReuseInstalled);
        }
        // Nothing live occupies the path, so there is no shared executable to
        // protect. A dangling reference from another configuration can only
        // be helped by supplying the binary it names.
        InstalledBinary::Absent => return Ok(BinaryPublication::Publish),
        InstalledBinary::Present(_) => REASON_SHARED_BINARY_REFERENCED,
        InstalledBinary::Unreadable => REASON_SHARED_BINARY_UNCLASSIFIABLE,
    };
    match remaining_ferrum_references(conf_dir, generated_file_name) {
        FerrumReferences::None => Ok(BinaryPublication::Publish),
        FerrumReferences::Found => Err(CniInstallError::SharedBinaryInUse {
            path: binary_path.display().to_string(),
            reason: replacement_reason,
        }),
        FerrumReferences::Unknown => Err(CniInstallError::SharedBinaryInUse {
            path: binary_path.display().to_string(),
            reason: REASON_SHARED_BINARY_UNPROVABLE,
        }),
    }
}

/// The digest of the binary being replaced, but only when prior manifest
/// evidence already proved that digest is this owner's.
///
/// Cleanup treats a recorded previous digest as authorization to delete, so
/// this must be an ATTESTATION, not an observation. The bar is a manifest that
/// (a) parses at the current schema, (b) names these exact artifact names, (c)
/// carries this same owner, and (d) already recorded the digest now on disk as
/// one of its own. That is precisely the repeat-upgrade case the field exists
/// for — a crash between the manifest write and the binary rename still leaves
/// whichever of the two digests is on disk provably ours — while a fresh or
/// partial install records `null` and can never make a pre-existing operator
/// or third-party binary removable.
fn attested_previous_binary_digest(
    conf_dir: &Path,
    config: &CniInstallConfig,
    installed: &InstalledBinary,
) -> Result<Option<String>, CniInstallError> {
    let InstalledBinary::Present(digest) = installed else {
        return Ok(None);
    };
    let manifest_path = conf_dir.join(OWNERSHIP_MANIFEST_FILE_NAME);
    let ManifestState::Present(prior) = read_ownership_manifest(&manifest_path)? else {
        return Ok(None);
    };
    let attested = prior.speaks_for(&config.conf_file_name)
        && prior.ownership.owner == config.ownership.owner
        && prior.digest_matches(digest);
    if !attested {
        tracing::debug!(
            path = %manifest_path.display(),
            "No prior same-owner manifest attests the installed plugin binary; recording no \
             previous digest, so cleanup will retain it rather than claim to own it"
        );
    }
    Ok(attested.then(|| digest.clone()))
}

fn conflist_ownership_value(value: &Value) -> Option<CniOwnership> {
    let ferrum = value
        .get("plugins")?
        .as_array()?
        .iter()
        .find(|plugin| plugin_type(plugin) == Some(FERRUM_PLUGIN_TYPE))?
        .get("ferrum")?
        .as_object()?;
    if ferrum.get("managedBy").and_then(Value::as_str) != Some(FERRUM_MANAGED_BY) {
        return None;
    }
    Some(CniOwnership {
        owner: ferrum
            .get("owner")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        generation: ferrum
            .get("generation")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

/// Whether any CNI configuration still in the directory (other than the
/// generated one this run owns) chains to the `ferrum-cni` plugin.
enum FerrumReferences {
    None,
    Found,
    /// The directory or one of its configuration files could not be read, so
    /// the answer is unknown. Callers fail safe and retain the binary.
    Unknown,
}

fn remaining_ferrum_references(conf_dir: &Path, generated_file_name: &str) -> FerrumReferences {
    let Ok(entries) = fs::read_dir(conf_dir) else {
        return FerrumReferences::Unknown;
    };
    let generated = std::ffi::OsStr::new(generated_file_name);
    let mut unknown = false;
    for entry in entries {
        let Ok(entry) = entry else {
            unknown = true;
            continue;
        };
        let path = entry.path();
        if !is_cni_config_file(&path) {
            continue;
        }
        if path.file_name() == Some(generated) {
            continue;
        }
        match read_bounded_regular_file(&path, MAX_OWNED_JSON_BYTES) {
            Ok(ArtifactRead::Absent) => {}
            // A neighbour that cannot be classified or parsed could be
            // anything, including a configuration that chains to the shared
            // binary. Unknown, not absent.
            Ok(ArtifactRead::Rejected(_)) | Err(_) => unknown = true,
            Ok(ArtifactRead::Present { bytes, .. }) => {
                match serde_json::from_slice::<Value>(&bytes) {
                    Err(_) => unknown = true,
                    Ok(json) => {
                        if contains_plugin_type(&json, FERRUM_PLUGIN_TYPE) {
                            return FerrumReferences::Found;
                        }
                    }
                }
            }
        }
    }
    if unknown {
        FerrumReferences::Unknown
    } else {
        FerrumReferences::None
    }
}

fn write_ownership_manifest(
    conf_dir: &Path,
    ownership: &CniOwnership,
    conf_file_name: &str,
    binary_sha256: &str,
    previous_binary_sha256: Option<&str>,
    binary_owned: bool,
) -> Result<(), CniInstallError> {
    let path = conf_dir.join(OWNERSHIP_MANIFEST_FILE_NAME);
    let manifest = serde_json::json!({
        "schemaVersion": OWNERSHIP_MANIFEST_SCHEMA_VERSION,
        "managedBy": FERRUM_MANAGED_BY,
        "owner": ownership.owner,
        "generation": ownership.generation,
        "confFileName": conf_file_name,
        "binaryFileName": FERRUM_PLUGIN_TYPE,
        "binaryOwned": binary_owned,
        "binarySha256": binary_sha256,
        "previousBinarySha256": previous_binary_sha256,
    });
    let mut bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|source| CniInstallError::Json {
            path: path.display().to_string(),
            source,
        })?;
    bytes.push(b'\n');
    atomic_write_file(&path, &bytes, Some(0o600))
}

/// Read the ownership manifest.
///
/// A missing, non-regular, oversized, malformed, or wrong-schema manifest is
/// reported as "no manifest" with a warning rather than an error: the
/// conflist carries its own marker, so cleanup must still be able to lift the
/// node-wide dependency when the manifest is lost or corrupt.
fn read_ownership_manifest(path: &Path) -> Result<ManifestState, CniInstallError> {
    let (bytes, identity) = match read_bounded_regular_file(path, MAX_OWNED_JSON_BYTES)? {
        ArtifactRead::Absent => return Ok(ManifestState::Absent),
        ArtifactRead::Rejected(reason) => {
            tracing::warn!(
                path = %path.display(),
                reason,
                "Ignoring CNI ownership manifest that is not a plain installer-written file"
            );
            return Ok(ManifestState::Unusable(reason));
        }
        ArtifactRead::Present { bytes, identity } => (bytes, identity),
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        tracing::warn!(
            path = %path.display(),
            "Ignoring unparseable CNI ownership manifest; conflist ownership marker still applies"
        );
        return Ok(ManifestState::Unusable(
            "ownership manifest is not parseable JSON",
        ));
    };
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(OWNERSHIP_MANIFEST_SCHEMA_VERSION)
        || value.get("managedBy").and_then(Value::as_str) != Some(FERRUM_MANAGED_BY)
    {
        tracing::warn!(
            path = %path.display(),
            "Ignoring CNI ownership manifest with an unrecognized schema or managedBy marker"
        );
        return Ok(ManifestState::Unusable(
            "ownership manifest has an unrecognized schema or managedBy marker",
        ));
    }
    let (Some(owner), Some(generation), Some(binary_owned), Some(binary_sha256)) = (
        value.get("owner").and_then(Value::as_str),
        value.get("generation").and_then(Value::as_str),
        value.get("binaryOwned").and_then(Value::as_bool),
        value.get("binarySha256").and_then(Value::as_str),
    ) else {
        tracing::warn!(
            path = %path.display(),
            "Ignoring CNI ownership manifest missing owner/generation/binaryOwned/binarySha256"
        );
        return Ok(ManifestState::Unusable(
            "ownership manifest is missing owner/generation/binaryOwned/binarySha256",
        ));
    };
    let (Some(conf_file_name), Some(binary_file_name)) = (
        value.get("confFileName").and_then(Value::as_str),
        value.get("binaryFileName").and_then(Value::as_str),
    ) else {
        tracing::warn!(
            path = %path.display(),
            "Ignoring CNI ownership manifest that does not name the artifacts it owns"
        );
        return Ok(ManifestState::Unusable(
            "ownership manifest does not name the artifacts it owns",
        ));
    };
    Ok(ManifestState::Present(OwnershipManifest {
        ownership: CniOwnership {
            owner: owner.to_string(),
            generation: generation.to_string(),
        },
        conf_file_name: conf_file_name.to_string(),
        binary_file_name: binary_file_name.to_string(),
        binary_owned,
        binary_sha256: binary_sha256.to_string(),
        previous_binary_sha256: value
            .get("previousBinarySha256")
            .and_then(Value::as_str)
            .map(str::to_string),
        identity,
    }))
}

/// Device / inode / length identity of an artifact, captured from the very
/// handle its ownership evidence was read through.
///
/// Removal re-opens the path `O_NOFOLLOW` and refuses unless the object still
/// has this identity, so a path swapped after the evidence was read is
/// retained rather than deleted. Non-Unix builds exist only for matrix
/// parity (CNI is a Linux concept) and can compare length alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    len: u64,
}

#[cfg(unix)]
fn file_identity(meta: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        device: meta.dev(),
        inode: meta.ino(),
        len: meta.len(),
    }
}

#[cfg(not(unix))]
fn file_identity(meta: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: 0,
        inode: 0,
        len: meta.len(),
    }
}

enum ArtifactRead {
    Absent,
    Rejected(&'static str),
    Present {
        bytes: Vec<u8>,
        identity: FileIdentity,
    },
}

enum ClassifiedArtifact {
    Absent,
    Rejected(&'static str),
    Present { file: File, identity: FileIdentity },
}

enum OpenedArtifact {
    Absent,
    Rejected(&'static str),
    Opened(File),
}

/// Open a path without following symlinks and classify it.
///
/// `O_NOFOLLOW` closes the symlink-swap race that a `symlink_metadata` +
/// `open` pair would leave open: the kernel refuses the open outright, so
/// there is no window in which a traversal target can be substituted.
fn open_no_follow(path: &Path) -> Result<OpenedArtifact, CniInstallError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    match options.open(path) {
        Ok(file) => Ok(OpenedArtifact::Opened(file)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(OpenedArtifact::Absent),
        Err(err) if is_symlink_open_refusal(&err) => Ok(OpenedArtifact::Rejected(REASON_SYMLINK)),
        Err(source) => Err(CniInstallError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

#[cfg(unix)]
fn is_symlink_open_refusal(err: &std::io::Error) -> bool {
    // Linux reports ELOOP for an O_NOFOLLOW symlink; some BSDs report EMLINK.
    matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::EMLINK))
}

#[cfg(not(unix))]
fn is_symlink_open_refusal(_err: &std::io::Error) -> bool {
    false
}

/// Open a path `O_NOFOLLOW` and reject anything that is not a plain,
/// single-linked, plausibly-sized file. Every later decision — read, hash,
/// remove — is made against the returned handle and identity, so they all
/// describe one object rather than one path.
fn open_classified(path: &Path, max_bytes: u64) -> Result<ClassifiedArtifact, CniInstallError> {
    let file = match open_no_follow(path)? {
        OpenedArtifact::Absent => return Ok(ClassifiedArtifact::Absent),
        OpenedArtifact::Rejected(reason) => return Ok(ClassifiedArtifact::Rejected(reason)),
        OpenedArtifact::Opened(file) => file,
    };
    let meta = file.metadata().map_err(|source| CniInstallError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !meta.is_file() {
        return Ok(ClassifiedArtifact::Rejected(REASON_NOT_REGULAR));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Ok(ClassifiedArtifact::Rejected(REASON_HARD_LINKED));
        }
    }
    if meta.len() > max_bytes {
        return Ok(ClassifiedArtifact::Rejected(REASON_TOO_LARGE));
    }
    Ok(ClassifiedArtifact::Present {
        identity: file_identity(&meta),
        file,
    })
}

/// Read a classified artifact with a HARD cap.
///
/// The pre-read length check is advisory only — the file can grow between the
/// `fstat` and the read — so the read itself is bounded by `max_bytes + 1` and
/// anything that reaches the cap is rejected rather than buffered.
fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<ArtifactRead, CniInstallError> {
    let (file, identity) = match open_classified(path, max_bytes)? {
        ClassifiedArtifact::Absent => return Ok(ArtifactRead::Absent),
        ClassifiedArtifact::Rejected(reason) => return Ok(ArtifactRead::Rejected(reason)),
        ClassifiedArtifact::Present { file, identity } => (file, identity),
    };
    let mut bytes = Vec::new();
    let mut capped = file.take(max_bytes.saturating_add(1));
    capped
        .read_to_end(&mut bytes)
        .map_err(|source| CniInstallError::Io {
            path: path.display().to_string(),
            source,
        })?;
    if bytes.len() as u64 > max_bytes {
        return Ok(ArtifactRead::Rejected(REASON_TOO_LARGE));
    }
    Ok(ArtifactRead::Present { bytes, identity })
}

/// Hash an already-classified open handle, refusing to read past `max_bytes`.
fn hash_open_file(file: &mut File, path: &Path, max_bytes: u64) -> Result<String, CniInstallError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; COPY_CHUNK_BYTES];
    let mut total: u64 = 0;
    loop {
        let read = file.read(&mut buf).map_err(|source| CniInstallError::Io {
            path: path.display().to_string(),
            source,
        })?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err(CniInstallError::Io {
                path: path.display().to_string(),
                source: std::io::Error::other("file grew past the supported size while hashing"),
            });
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Unlink a path only after re-proving it is still the object whose ownership
/// evidence was checked.
fn remove_verified(
    path: &Path,
    expected: FileIdentity,
) -> Result<CniArtifactOutcome, CniInstallError> {
    match open_classified(path, u64::MAX)? {
        ClassifiedArtifact::Absent => return Ok(CniArtifactOutcome::AlreadyAbsent),
        ClassifiedArtifact::Rejected(reason) => {
            return Ok(CniArtifactOutcome::RetainedForeign(reason));
        }
        ClassifiedArtifact::Present { file, identity } => {
            drop(file);
            if identity != expected {
                return Ok(CniArtifactOutcome::RetainedForeign(REASON_SWAPPED));
            }
        }
    }
    remove_file(path)?;
    Ok(CniArtifactOutcome::Removed)
}

fn remove_file(path: &Path) -> Result<(), CniInstallError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CniInstallError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// Exclusive whole-node lock over the CNI install lifecycle.
///
/// Held for the entire duration of `install` and `uninstall`. This is what
/// makes rollback ownership provable: a watcher that reached its deadline
/// blocks here until a still-running installer has finished publishing, and
/// then re-reads the ownership markers before deciding anything.
struct InstallLock {
    /// Held so the advisory lock lives as long as this guard. Released by the
    /// kernel when the descriptor closes, including on abnormal exit.
    _file: File,
}

impl InstallLock {
    fn acquire(conf_dir: &Path) -> Result<Self, CniInstallError> {
        let path = conf_dir.join(INSTALL_LOCK_FILE_NAME);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|source| CniInstallError::Io {
            path: path.display().to_string(),
            source,
        })?;
        lock_exclusive(&file, &path)?;
        Ok(Self { _file: file })
    }

    /// Same, but a missing configuration directory simply means nothing was
    /// ever installed — there is no peer to exclude and nothing to remove.
    fn acquire_if_dir_exists(conf_dir: &Path) -> Result<Option<Self>, CniInstallError> {
        if !conf_dir.is_dir() {
            return Ok(None);
        }
        Self::acquire(conf_dir).map(Some)
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &File, path: &Path) -> Result<(), CniInstallError> {
    use std::os::unix::io::AsRawFd;

    let deadline = Instant::now() + INSTALL_LOCK_WAIT;
    loop {
        // SAFETY: `file` owns a live descriptor for the whole call, and
        // `flock` only affects that descriptor's advisory lock state.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EWOULDBLOCK) => {}
            Some(libc::EINTR) => continue,
            _ => {
                return Err(CniInstallError::Io {
                    path: path.display().to_string(),
                    source: err,
                });
            }
        }
        if Instant::now() >= deadline {
            return Err(CniInstallError::LockBusy {
                path: path.display().to_string(),
            });
        }
        std::thread::sleep(INSTALL_LOCK_RETRY);
    }
}

#[cfg(not(unix))]
fn lock_exclusive(_file: &File, _path: &Path) -> Result<(), CniInstallError> {
    Ok(())
}

fn validate_ownership_token(name: &'static str, value: &str) -> Result<(), CniInstallError> {
    fn acceptable_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'#')
    }
    let acceptable = !value.is_empty()
        && value.len() <= MAX_OWNERSHIP_TOKEN_BYTES
        && value.bytes().all(acceptable_byte);
    if acceptable {
        Ok(())
    } else {
        Err(CniInstallError::InvalidOwnershipToken {
            name,
            max: MAX_OWNERSHIP_TOKEN_BYTES,
        })
    }
}

/// Reject anything that is not a single, ordinary file name. The generated
/// conflist name is operator-configurable, and it is joined onto a host
/// directory before a `remove_file`, so `..`, `/`, and empty names must never
/// reach the filesystem.
fn validate_single_component(name: &'static str, value: &str) -> Result<(), CniInstallError> {
    let path = Path::new(value);
    let mut components = path.components();
    let single_normal =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if single_normal
        && !value.is_empty()
        && value.len() <= 255
        && !value.contains('\0')
        && !value.chars().any(char::is_control)
    {
        Ok(())
    } else {
        Err(CniInstallError::InvalidFileName { name })
    }
}

struct PrimaryConfig {
    path: PathBuf,
    json: Value,
}

fn find_primary_config(
    conf_dir: &Path,
    target_file_name: &str,
    chained_with: &str,
) -> Result<PrimaryConfig, CniInstallError> {
    let mut entries = fs::read_dir(conf_dir)
        .map_err(|source| CniInstallError::Io {
            path: conf_dir.display().to_string(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| CniInstallError::Io {
            path: conf_dir.display().to_string(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    let target_file_name = std::ffi::OsStr::new(target_file_name);

    for entry in entries {
        let path = entry.path();
        if !is_cni_config_file(&path) {
            continue;
        }
        let Some(file_name) = path.file_name() else {
            continue;
        };
        if file_name == target_file_name {
            continue;
        }
        let sorts_before_target = file_name < target_file_name;
        let json = match read_json_file(&path) {
            Ok(json) => json,
            Err(error @ CniInstallError::Json { .. }) => {
                if sorts_before_target {
                    return Err(error);
                }
                // A malformed neighbour in the shared CNI conf dir (a
                // half-written or vendor config another installer dropped) must
                // not abort the scan if the generated Ferrum file would sort
                // before it. Malformed files that sort before the generated
                // target remain fatal because the container runtime would pick
                // them before Ferrum's chain.
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "Skipping unparseable CNI config while searching for the primary to chain"
                );
                continue;
            }
            Err(error) => return Err(error),
        };
        if contains_plugin_type(&json, FERRUM_PLUGIN_TYPE) {
            continue;
        }
        if contains_plugin_type(&json, chained_with) {
            return Ok(PrimaryConfig { path, json });
        }
    }

    Err(CniInstallError::PrimaryConfigNotFound {
        conf_dir: conf_dir.display().to_string(),
        plugin_type: chained_with.to_string(),
    })
}

fn is_cni_config_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("conf" | "conflist" | "json")
    )
}

fn read_json_file(path: &Path) -> Result<Value, CniInstallError> {
    let bytes = fs::read(path).map_err(|source| CniInstallError::Io {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| CniInstallError::Json {
        path: path.display().to_string(),
        source,
    })
}

pub fn build_chained_conflist(
    primary_config: &Value,
    socket_path: &str,
    ownership: &CniOwnership,
    source_path: &Path,
) -> Result<Value, CniInstallError> {
    let Some(obj) = primary_config.as_object() else {
        return Err(CniInstallError::PrimaryConfigNotObject {
            path: source_path.display().to_string(),
        });
    };

    let ferrum_plugin = ferrum_plugin(socket_path, ownership);
    if let Some(plugins) = obj.get("plugins").and_then(Value::as_array) {
        if plugins.is_empty() {
            return Err(CniInstallError::EmptyPluginList {
                path: source_path.display().to_string(),
            });
        }
        let mut out = obj.clone();
        let mut chained_plugins: Vec<Value> = plugins
            .iter()
            .filter(|plugin| plugin_type(plugin) != Some(FERRUM_PLUGIN_TYPE))
            .cloned()
            .collect();
        chained_plugins.push(ferrum_plugin);
        out.insert("plugins".to_string(), Value::Array(chained_plugins));
        return Ok(Value::Object(out));
    }

    let mut primary_plugin = obj.clone();
    primary_plugin.remove("cniVersion");
    primary_plugin.remove("name");
    primary_plugin.remove("plugins");

    let mut out = Map::new();
    out.insert(
        "cniVersion".to_string(),
        obj.get("cniVersion")
            .cloned()
            .unwrap_or_else(|| Value::String("0.4.0".to_string())),
    );
    out.insert(
        "name".to_string(),
        obj.get("name")
            .cloned()
            .unwrap_or_else(|| Value::String("ferrum-mesh-chain".to_string())),
    );
    out.insert(
        "plugins".to_string(),
        Value::Array(vec![Value::Object(primary_plugin), ferrum_plugin]),
    );
    Ok(Value::Object(out))
}

/// The chained Ferrum entry.
///
/// The ownership markers live inside the plugin's own `ferrum` object. That
/// is the one place in a conflist the CNI spec reserves for this plugin, so
/// they cannot confuse a neighbouring plugin, they survive kubelet's
/// per-plugin config projection, and `FerrumCniOptions` ignores them on the
/// request path (it models only `socketPath`).
fn ferrum_plugin(socket_path: &str, ownership: &CniOwnership) -> Value {
    serde_json::json!({
        "type": FERRUM_PLUGIN_TYPE,
        "ferrum": {
            "socketPath": socket_path,
            "managedBy": FERRUM_MANAGED_BY,
            "owner": ownership.owner,
            "generation": ownership.generation,
        }
    })
}

fn contains_plugin_type(config: &Value, expected: &str) -> bool {
    if expected.trim().is_empty() {
        return false;
    }
    plugin_type(config) == Some(expected)
        || config
            .get("plugins")
            .and_then(Value::as_array)
            .is_some_and(|plugins| {
                plugins
                    .iter()
                    .any(|plugin| plugin_type(plugin) == Some(expected))
            })
}

fn plugin_type(plugin: &Value) -> Option<&str> {
    plugin.get("type").and_then(Value::as_str)
}

fn required_env(name: &'static str) -> Result<String, CniInstallError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(CniInstallError::MissingEnv(name))
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn create_dir_all(path: &Path) -> Result<(), CniInstallError> {
    fs::create_dir_all(path).map_err(|source| CniInstallError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// The next plugin binary, written to an exclusive temporary file beside its
/// destination and hashed as it was written.
///
/// Staging in the destination directory keeps the publish a same-filesystem
/// `rename`, which is atomic and never truncates the file a concurrently
/// exec'd `ferrum-cni` is running from.
struct StagedBinary {
    path: PathBuf,
    sha256: String,
    consumed: bool,
}

impl StagedBinary {
    fn stage(source: &Path, target: &Path) -> Result<Self, CniInstallError> {
        let (path, mut file) = create_exclusive_temp(target, "install")?;
        let staged = copy_and_hash(source, &mut file, &path)
            .and_then(|sha256| set_executable(&file, &path).map(|()| sha256));
        drop(file);
        let sha256 = match staged {
            Ok(sha256) => sha256,
            Err(error) => {
                let _ = fs::remove_file(&path);
                return Err(error);
            }
        };
        Ok(Self {
            path,
            sha256,
            consumed: false,
        })
    }

    fn publish(mut self, target: &Path) -> Result<(), CniInstallError> {
        atomic_rename(&self.path, target)?;
        self.consumed = true;
        Ok(())
    }

    /// An upgrade whose bytes are already installed publishes nothing.
    fn discard(mut self) {
        self.consumed = true;
        let _ = fs::remove_file(&self.path);
    }
}

impl Drop for StagedBinary {
    fn drop(&mut self) {
        if !self.consumed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Stream `source` into `dest`, hashing the same bytes in one pass so the
/// digest cannot describe a different revision than the one written.
fn copy_and_hash(
    source: &Path,
    dest: &mut File,
    dest_path: &Path,
) -> Result<String, CniInstallError> {
    // The source is only ever READ, so it is checked for the properties that
    // matter to a read — no symlink traversal, a regular file, and the
    // streaming cap below. Deliberately NOT the link-count check `uninstall`
    // applies: nothing here is removed, and a container image layer is free
    // to hard-link the binaries it ships.
    let mut input = match open_no_follow(source)? {
        OpenedArtifact::Opened(file) => file,
        OpenedArtifact::Absent | OpenedArtifact::Rejected(_) => {
            return Err(CniInstallError::UnusableSourceBinary {
                path: source.display().to_string(),
            });
        }
    };
    let source_is_regular =
        input
            .metadata()
            .map(|meta| meta.is_file())
            .map_err(|err| CniInstallError::Io {
                path: source.display().to_string(),
                source: err,
            })?;
    if !source_is_regular {
        return Err(CniInstallError::UnusableSourceBinary {
            path: source.display().to_string(),
        });
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; COPY_CHUNK_BYTES];
    let mut total: u64 = 0;
    loop {
        let read = input.read(&mut buf).map_err(|source| CniInstallError::Io {
            path: dest_path.display().to_string(),
            source,
        })?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_OWNED_BINARY_BYTES {
            return Err(CniInstallError::UnusableSourceBinary {
                path: source.display().to_string(),
            });
        }
        hasher.update(&buf[..read]);
        dest.write_all(&buf[..read])
            .map_err(|source| CniInstallError::Io {
                path: dest_path.display().to_string(),
                source,
            })?;
    }
    dest.sync_all().map_err(|source| CniInstallError::Io {
        path: dest_path.display().to_string(),
        source,
    })?;
    Ok(hex::encode(hasher.finalize()))
}

/// Publish `contents` at `target` in one step: write an unguessable
/// `O_EXCL | O_NOFOLLOW` sibling, then `rename` it into place.
///
/// A reader therefore never observes a half-written file, and the publish
/// itself never follows a symlink sitting at `target` — `rename` replaces the
/// link, it does not traverse it. Shared with the cleanup readiness marker so
/// there is exactly one implementation of this rule.
pub(crate) fn atomic_write_file(
    target: &Path,
    contents: &[u8],
    mode: Option<u32>,
) -> Result<(), CniInstallError> {
    let (tmp_path, mut file) = create_exclusive_temp(target, "tmp")?;
    let written = write_staged(&mut file, &tmp_path, contents, mode);
    drop(file);
    let result = written.and_then(|()| atomic_rename(&tmp_path, target));
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

/// Fill a freshly created staging file and give it its final mode, all
/// through the open handle, then make both durable before the publish.
fn write_staged(
    file: &mut File,
    path: &Path,
    contents: &[u8],
    mode: Option<u32>,
) -> Result<(), CniInstallError> {
    let io_error = |source: std::io::Error| CniInstallError::Io {
        path: path.display().to_string(),
        source,
    };
    file.write_all(contents).map_err(io_error)?;
    if let Some(mode) = mode {
        set_mode(file, path, mode)?;
    }
    file.sync_all().map_err(io_error)
}

/// Create a temporary sibling of `target` that cannot be pre-planted.
///
/// `O_EXCL | O_CREAT` refuses any existing entry — including a symlink, which
/// a predictable PID-derived name would otherwise let an attacker point at an
/// arbitrary file and have the installer truncate. `O_NOFOLLOW` refuses one
/// even in the impossible case, the name carries unguessable randomness, and
/// the mode is `0600` from creation rather than after the fact.
fn create_exclusive_temp(target: &Path, suffix: &str) -> Result<(PathBuf, File), CniInstallError> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let base = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(FERRUM_PLUGIN_TYPE);
    let mut last_error = None;
    for _ in 0..TEMP_NAME_ATTEMPTS {
        let token = random_temp_token();
        let path = dir.join(format!(".{base}.{token:016x}.{suffix}"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => last_error = Some(err),
            Err(source) => {
                return Err(CniInstallError::Io {
                    path: path.display().to_string(),
                    source,
                });
            }
        }
    }
    Err(CniInstallError::Io {
        path: dir.display().to_string(),
        source: last_error
            .unwrap_or_else(|| std::io::Error::other("no unused temporary name was available")),
    })
}

fn random_temp_token() -> u64 {
    use crate::fips::backend::rand::SecureRandom;

    let rng = crate::fips::backend::rand::SystemRandom::new();
    let mut bytes = [0u8; 8];
    if rng.fill(&mut bytes).is_ok() {
        return u64::from_ne_bytes(bytes);
    }
    // Only reachable if the platform RNG fails outright. Falls back to a
    // value that is still unique per process and instant, and the `O_EXCL`
    // creation stays the actual safety property either way.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    nanos ^ u64::from(std::process::id())
}

fn atomic_rename(source: &Path, target: &Path) -> Result<(), CniInstallError> {
    fs::rename(source, target).map_err(|source| CniInstallError::Io {
        path: target.display().to_string(),
        source,
    })
}

#[cfg(unix)]
fn set_executable(file: &File, path: &Path) -> Result<(), CniInstallError> {
    set_mode(file, path, 0o755)
}

#[cfg(not(unix))]
fn set_executable(_file: &File, _path: &Path) -> Result<(), CniInstallError> {
    Ok(())
}

/// Change the mode of an already-open staging file through its handle
/// (`fchmod`). A path-based chmod follows symlinks, so a staging name swapped
/// for a link between creation and chmod would redirect the change onto the
/// link's target; the handle can only ever name the inode this run created.
/// `path` is used only to label the error.
#[cfg(unix)]
fn set_mode(file: &File, path: &Path, mode: u32) -> Result<(), CniInstallError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|source| CniInstallError::Io {
            path: path.display().to_string(),
            source,
        })
}

#[cfg(not(unix))]
fn set_mode(_file: &File, _path: &Path, _mode: u32) -> Result<(), CniInstallError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ownership() -> CniOwnership {
        CniOwnership {
            owner: "ferrum/ferrum-mesh".to_string(),
            generation: "pod-uid-1".to_string(),
        }
    }

    #[test]
    fn wraps_single_primary_conf_and_preserves_ipam() {
        let primary = serde_json::json!({
            "cniVersion": "0.4.0",
            "name": "mynet",
            "type": "bridge",
            "bridge": "cni0",
            "ipam": {"type": "host-local"}
        });

        let chained = build_chained_conflist(
            &primary,
            "/var/run/ferrum/cni.sock",
            &test_ownership(),
            Path::new("10.conf"),
        )
        .expect("single plugin config should wrap");
        assert_eq!(chained["plugins"][0]["type"], "bridge");
        assert_eq!(chained["plugins"][0]["ipam"]["type"], "host-local");
        assert_eq!(chained["plugins"][1]["type"], "ferrum-cni");
        let entry = &chained["plugins"][1]["ferrum"];
        assert_eq!(entry["socketPath"], "/var/run/ferrum/cni.sock");
        assert_eq!(
            entry["managedBy"], FERRUM_MANAGED_BY,
            "the generated entry must carry the ownership marker uninstall checks"
        );
        assert_eq!(entry["owner"], "ferrum/ferrum-mesh");
        assert_eq!(entry["generation"], "pod-uid-1");
    }

    #[test]
    fn appends_to_existing_conflist_without_dropping_primary_fields() {
        let primary = serde_json::json!({
            "cniVersion": "1.0.0",
            "name": "cilium",
            "plugins": [
                {"type": "cilium-cni", "enable-debug": true},
                {"type": "portmap", "capabilities": {"portMappings": true}}
            ]
        });

        let chained = build_chained_conflist(
            &primary,
            "/var/run/ferrum/cni.sock",
            &test_ownership(),
            Path::new("10.conflist"),
        )
        .expect("conflist should append");
        assert_eq!(chained["plugins"].as_array().unwrap().len(), 3);
        assert_eq!(chained["plugins"][0]["type"], "cilium-cni");
        assert_eq!(chained["plugins"][0]["enable-debug"], true);
        assert_eq!(chained["plugins"][1]["type"], "portmap");
        assert_eq!(chained["plugins"][2]["type"], "ferrum-cni");
    }

    #[test]
    fn replaces_existing_ferrum_entry_when_rebuilding_chain() {
        let primary = serde_json::json!({
            "cniVersion": "1.0.0",
            "name": "calico",
            "plugins": [
                {"type": "calico", "ipam": {"type": "calico-ipam"}},
                {"type": "ferrum-cni", "ferrum": {"socketPath": "/old.sock"}}
            ]
        });

        let chained = build_chained_conflist(
            &primary,
            "/new.sock",
            &test_ownership(),
            Path::new("00-ferrum.conflist"),
        )
        .expect("existing ferrum entry should be replaced");
        assert_eq!(chained["plugins"].as_array().unwrap().len(), 2);
        assert_eq!(chained["plugins"][1]["ferrum"]["socketPath"], "/new.sock");
    }

    #[test]
    fn install_replaces_binary_and_config_atomically_visible() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-ferrum-cni");
        fs::write(&source, b"new binary").unwrap();
        let bin_dir = root.path().join("bin");
        let conf_dir = root.path().join("conf");
        let socket_dir = root.path().join("run");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&conf_dir).unwrap();
        fs::write(bin_dir.join("ferrum-cni"), b"old binary").unwrap();
        fs::write(
            conf_dir.join("10-calico.conflist"),
            serde_json::to_vec(&serde_json::json!({
                "cniVersion": "0.4.0",
                "name": "calico",
                "plugins": [{"type": "calico", "ipam": {"type": "calico-ipam"}}]
            }))
            .unwrap(),
        )
        .unwrap();

        let config = CniInstallConfig {
            host_bin_dir: bin_dir.display().to_string(),
            host_conf_dir: conf_dir.display().to_string(),
            host_socket_dir: socket_dir.display().to_string(),
            conf_file_name: "00-ferrum.conflist".to_string(),
            chained_with: "calico".to_string(),
            socket_path: "/var/run/ferrum/node-agent-cni.sock".to_string(),
            ownership: test_ownership(),
        };

        let written = install(&config, &source).expect("install should succeed");
        assert_eq!(fs::read(bin_dir.join("ferrum-cni")).unwrap(), b"new binary");
        let generated: Value =
            serde_json::from_slice(&fs::read(written).unwrap()).expect("generated config parses");
        assert_eq!(generated["plugins"][0]["type"], "calico");
        assert_eq!(
            generated["plugins"][0]["ipam"]["type"], "calico-ipam",
            "primary config should be preserved"
        );
        assert_eq!(generated["plugins"][1]["type"], "ferrum-cni");
        assert!(
            fs::read_dir(bin_dir).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".install")),
            "successful install should not leave staged binary files"
        );
        assert!(
            fs::read_dir(conf_dir).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp")),
            "successful install should not leave temp config files"
        );
    }

    #[test]
    fn install_refuses_an_existing_malformed_target_without_side_effects() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-ferrum-cni");
        fs::write(&source, b"new binary").unwrap();
        let bin_dir = root.path().join("bin");
        let conf_dir = root.path().join("conf");
        let socket_dir = root.path().join("run");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&conf_dir).unwrap();
        fs::write(
            conf_dir.join("10-calico.conflist"),
            serde_json::to_vec(&serde_json::json!({
                "cniVersion": "0.4.0",
                "name": "calico",
                "plugins": [{"type": "calico", "ipam": {"type": "calico-ipam"}}]
            }))
            .unwrap(),
        )
        .unwrap();
        let target = conf_dir.join("00-ferrum.conflist");
        fs::write(&target, b"{truncated").unwrap();
        let primary_before = fs::read(conf_dir.join("10-calico.conflist")).unwrap();

        let config = CniInstallConfig {
            host_bin_dir: bin_dir.display().to_string(),
            host_conf_dir: conf_dir.display().to_string(),
            host_socket_dir: socket_dir.display().to_string(),
            conf_file_name: "00-ferrum.conflist".to_string(),
            chained_with: "calico".to_string(),
            socket_path: "/var/run/ferrum/node-agent-cni.sock".to_string(),
            ownership: test_ownership(),
        };

        let err = install(&config, &source).expect_err("malformed target must be refused");
        assert!(
            matches!(err, CniInstallError::UnsafeInstallTarget { .. }),
            "expected UnsafeInstallTarget, got {err:?}"
        );
        assert_eq!(fs::read(&target).unwrap(), b"{truncated");
        assert!(!bin_dir.join("ferrum-cni").exists());
        assert!(!conf_dir.join(OWNERSHIP_MANIFEST_FILE_NAME).exists());
        assert_eq!(
            fs::read(conf_dir.join("10-calico.conflist")).unwrap(),
            primary_before
        );
        assert!(
            fs::read_dir(&bin_dir).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".install")),
            "refused install must leave no staged binary"
        );
    }

    #[test]
    fn install_skips_malformed_sibling_and_chains_valid_primary() {
        // A malformed NON-target sibling that sorts BEFORE the valid primary
        // must not abort the scan — install should still find and chain the
        // valid primary. (Regression: the parse error previously propagated via
        // `?` and aborted the whole install.)
        //
        // Nothing is pre-installed at the plugin path on purpose: this case is
        // about the primary-config scan, and an unscannable directory
        // separately refuses to REPLACE a live shared binary with different
        // bytes (`plan_binary_publication`). Supplying a binary where none
        // exists replaces nothing, so the two rules do not interact here.
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-ferrum-cni");
        fs::write(&source, b"new binary").unwrap();
        let bin_dir = root.path().join("bin");
        let conf_dir = root.path().join("conf");
        let socket_dir = root.path().join("run");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&conf_dir).unwrap();
        // Malformed sibling sorting before the valid primary.
        fs::write(conf_dir.join("05-broken.conf"), b"{truncated").unwrap();
        fs::write(
            conf_dir.join("10-calico.conflist"),
            serde_json::to_vec(&serde_json::json!({
                "cniVersion": "0.4.0",
                "name": "calico",
                "plugins": [{"type": "calico", "ipam": {"type": "calico-ipam"}}]
            }))
            .unwrap(),
        )
        .unwrap();

        let config = CniInstallConfig {
            host_bin_dir: bin_dir.display().to_string(),
            host_conf_dir: conf_dir.display().to_string(),
            host_socket_dir: socket_dir.display().to_string(),
            conf_file_name: "00-ferrum.conflist".to_string(),
            chained_with: "calico".to_string(),
            socket_path: "/var/run/ferrum/node-agent-cni.sock".to_string(),
            ownership: test_ownership(),
        };

        let written = install(&config, &source)
            .expect("install should skip the malformed sibling and chain the valid primary");
        let generated: Value =
            serde_json::from_slice(&fs::read(written).unwrap()).expect("generated config parses");
        assert_eq!(generated["plugins"][0]["type"], "calico");
        assert_eq!(generated["plugins"][1]["type"], "ferrum-cni");
    }

    #[test]
    fn install_rejects_malformed_config_that_sorts_before_generated_target() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-ferrum-cni");
        fs::write(&source, b"new binary").unwrap();
        let bin_dir = root.path().join("bin");
        let conf_dir = root.path().join("conf");
        let socket_dir = root.path().join("run");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&conf_dir).unwrap();

        fs::write(conf_dir.join("00-alpha.conf"), b"{truncated").unwrap();
        fs::write(
            conf_dir.join("10-calico.conflist"),
            serde_json::to_vec(&serde_json::json!({
                "cniVersion": "0.4.0",
                "name": "calico",
                "plugins": [{"type": "calico"}]
            }))
            .unwrap(),
        )
        .unwrap();

        let config = CniInstallConfig {
            host_bin_dir: bin_dir.display().to_string(),
            host_conf_dir: conf_dir.display().to_string(),
            host_socket_dir: socket_dir.display().to_string(),
            conf_file_name: "00-ferrum.conflist".to_string(),
            chained_with: "calico".to_string(),
            socket_path: "/var/run/ferrum/node-agent-cni.sock".to_string(),
            ownership: test_ownership(),
        };

        let err = install(&config, &source)
            .expect_err("malformed configs before the generated target must fail install");
        assert!(
            matches!(err, CniInstallError::Json { .. }),
            "expected JSON error for earlier malformed config, got {err:?}"
        );
    }

    #[test]
    fn install_propagates_io_error_while_scanning_primary_candidates() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-ferrum-cni");
        fs::write(&source, b"new binary").unwrap();
        let bin_dir = root.path().join("bin");
        let conf_dir = root.path().join("conf");
        let socket_dir = root.path().join("run");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&conf_dir).unwrap();

        // A directory with a CNI config extension sorts before the valid
        // primary and makes fs::read return an I/O error. This must not be
        // treated like malformed JSON or the installer could chain a later
        // stale primary.
        let unreadable_candidate = conf_dir.join("05-unreadable.conf");
        fs::create_dir(&unreadable_candidate).unwrap();
        fs::write(
            conf_dir.join("10-calico.conflist"),
            serde_json::to_vec(&serde_json::json!({
                "cniVersion": "0.4.0",
                "name": "calico",
                "plugins": [{"type": "calico"}]
            }))
            .unwrap(),
        )
        .unwrap();

        let config = CniInstallConfig {
            host_bin_dir: bin_dir.display().to_string(),
            host_conf_dir: conf_dir.display().to_string(),
            host_socket_dir: socket_dir.display().to_string(),
            conf_file_name: "00-ferrum.conflist".to_string(),
            chained_with: "calico".to_string(),
            socket_path: "/var/run/ferrum/node-agent-cni.sock".to_string(),
            ownership: test_ownership(),
        };

        let err = install(&config, &source).expect_err("I/O errors must propagate");
        match err {
            CniInstallError::Io { path, .. } => {
                assert!(
                    path.ends_with("05-unreadable.conf"),
                    "reported path should be the unreadable candidate: {path}"
                );
            }
            other => panic!("expected CNI scan I/O error, got {other:?}"),
        }
    }
}
