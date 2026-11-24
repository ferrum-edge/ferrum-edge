//! Localized file-based mesh config source (`FERRUM_MESH_CONFIG_PROTOCOL=file`).
//!
//! Instead of subscribing to a control plane, the data plane builds its
//! [`MeshSlice`] locally from a YAML/JSON document on disk — the same
//! DP-side materialization path the native/xDS consumers feed
//! (`MeshSlice::from_gateway_config` + the slice-apply task), so a file-built
//! slice is functionally equivalent to a CP-delivered one. Mirrors the
//! gateway's file mode: the initial load is fail-closed (an unreadable or
//! invalid document refuses startup) and SIGHUP (Unix) reloads the document,
//! keeping the last good slice when the reload fails.
//!
//! Reads go through the shared bounded stable-file primitive (regular-file
//! open target, Unix `O_NONBLOCK`, 64 MiB ceiling with `limit + 1`, two
//! identity/content probes separated by a 20ms settle interval). Initial
//! load and SIGHUP reload perform
//! filesystem and parse work on `spawn_blocking`, coalesce repeated signals
//! so only one generation is parsed at a time (with at most one follow-up
//! after an in-flight load), and refuse to let an older completed load
//! overwrite a newer requested generation. Watcher shutdown stops accepting
//! candidates promptly: it drops/aborts the in-flight join handle without
//! awaiting a non-cancellable started blocking job, and a late completion
//! cannot publish. A failed reload raises the shared `config_rejected`
//! admin-health signal (authenticated `/health` degraded) while retaining
//! the last-good slice; sticky recovery clears only when the exact current
//! recovery candidate is accepted (or content-identical no-op accepted) by
//! the proxy apply lifecycle — not on channel send or provisional
//! [`MeshRuntimeState::install_slice`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::Deserialize;
use tracing::{info, warn};

use crate::config::stable_file::{
    MAX_MESH_CONFIG_FILE_BYTES, StableFileReadOptions, detect_json_or_yaml_extension,
    read_stable_file, stable_file_error_anyhow,
};
use crate::config::types::{CURRENT_CONFIG_VERSION, GatewayConfig};
use crate::config::yaml_alias_budget::admit_yaml_alias_expansion;
use crate::modes::mesh::revision::MeshRevisionContentIdentity;
use crate::modes::mesh::runtime::{MeshRuntimeState, MeshSliceInstall, slice_content_identity};
use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use crate::startup::{sanitize_startup_cause, sanitize_startup_scalar};

/// On-disk shape of the localized mesh config document.
///
/// `deny_unknown_fields` is load-bearing: a document carrying gateway
/// resources (`proxies:`, `upstreams:`, ...) fails deserialization with a
/// clear "unknown field" error instead of silently dropping them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeshFileDocument {
    /// Optional config schema version stamp. When present it must match
    /// [`CURRENT_CONFIG_VERSION`]; the mesh model has no file migrations.
    #[serde(default)]
    version: Option<String>,
    #[serde(deserialize_with = "crate::util::json_object::deserialize_object")]
    mesh: Box<crate::modes::mesh::config::MeshConfig>,
}

/// Load the mesh document at `path` and build the node's [`MeshSlice`].
///
/// Runs the same normalization + validation the CP-side slice builder applies
/// (`normalize_fields`/`normalize_mesh_fields` + `validate_mesh_fields`)
/// before narrowing via [`MeshSlice::from_gateway_config`], so a document the
/// initial load accepts cannot later be rejected by the slice-apply task for
/// mesh-field validity.
pub fn load_mesh_slice_from_file(
    path: &Path,
    request: MeshSliceRequest,
) -> Result<MeshSlice, anyhow::Error> {
    let mesh = read_mesh_config_document(path)?;
    let config = normalized_mesh_gateway_config(mesh)?;
    Ok(MeshSlice::from_gateway_config(&config, request))
}

/// Async-runtime wrapper: performs the bounded stable read + parse on a
/// blocking worker so Tokio core workers stay free for heartbeats/shutdown.
pub async fn load_mesh_slice_from_file_off_thread(
    path: PathBuf,
    request: MeshSliceRequest,
) -> Result<MeshSlice, anyhow::Error> {
    tokio::task::spawn_blocking(move || load_mesh_slice_from_file(&path, request))
        .await
        .map_err(|error| {
            let reason = if error.is_cancelled() {
                "cancelled"
            } else {
                "panicked"
            };
            anyhow::anyhow!("Mesh configuration file validation worker failed: {reason}")
        })?
}

/// Parse the mesh document at `path` into its raw (un-normalized, un-validated)
/// [`crate::modes::mesh::config::MeshConfig`].
///
/// Split out of [`load_mesh_slice_from_file`] for the stock xDS
/// interoperability profile (issue #3317), which needs to substitute the
/// discovery-owned `services` / `workloads` before normalization and then run
/// the SAME normalize + validate + project pipeline, so a stock-built slice is
/// structurally indistinguishable from a file-built one.
pub fn read_mesh_config_document(
    path: &Path,
) -> Result<Box<crate::modes::mesh::config::MeshConfig>, anyhow::Error> {
    let content = read_mesh_file_bytes(path)?;

    // Extension only; unknown/extensionless paths use YAML, which also admits
    // ordinary JSON without a separate full-document detection parse.
    let is_yaml = detect_json_or_yaml_extension(path);

    let document: MeshFileDocument = if is_yaml {
        admit_yaml_alias_expansion(&content)
            .map_err(|e| anyhow::anyhow!(mesh_doc_parse_error(e)))?;
        crate::util::deserialization::from_yaml_str(&content)
            .map_err(|e| anyhow::anyhow!(mesh_doc_parse_error(e)))?
    } else {
        crate::util::json_object::from_json_object_slice::<MeshFileDocument>(content.as_bytes())
            .map_err(|e| anyhow::anyhow!(mesh_doc_parse_error(e)))?
    };
    // Deserialization owns all retained fields; do not keep the source buffer
    // alive while slice materialization allocates its runtime structures.
    drop(content);

    if let Some(version) = document.version.as_deref()
        && version != CURRENT_CONFIG_VERSION
    {
        anyhow::bail!(
            "unsupported mesh document version (<redacted scalar>); supported: \
             {CURRENT_CONFIG_VERSION} (the mesh model has no file migrations)"
        );
    }

    Ok(document.mesh)
}

/// Bounded stable read of a localized mesh document. Shared by the real
/// parser and the top-level shape probe so `validate` cannot admit a file the
/// file source would later refuse (size, regularity, UTF-8, settle contract).
fn read_mesh_file_bytes(path: &Path) -> Result<String, anyhow::Error> {
    if !path.exists() {
        anyhow::bail!("mesh configuration file not found: {:?}", path.display());
    }

    // Mirror file mode's credential-hygiene warning: mesh documents can carry
    // JWT issuer material and trust bundles.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode();
            if mode & 0o004 != 0 {
                warn!(
                    "Mesh config file {} is world-readable (mode {:o}). Consider restricting \
                     permissions as it may contain trust material.",
                    sanitize_startup_cause(format!("{path:?}"), &[]),
                    mode & 0o777
                );
            }
        }
    }

    let options = StableFileReadOptions::new(MAX_MESH_CONFIG_FILE_BYTES, "mesh configuration file");
    read_stable_file(path, options).map_err(|error| stable_file_error_anyhow(path, options, error))
}

/// Whether `path` is the localized `{version?, mesh}` document shape.
///
/// Shape-aware, not format-sniffing: format still follows the extension-only
/// rule used by [`read_mesh_config_document`]. This inspects **top-level
/// keys only** so an otherwise localized document with invalid inner mesh
/// fields still selects file-protocol validation; inner validity stays with
/// the real parser. Unknown top-level keys (`proxies`, …) and a missing
/// `mesh` mapping return `Ok(false)`. I/O, regularity, size, and UTF-8
/// failures are `Err` and use the same bounded reader as runtime.
pub fn probe_localized_mesh_file_document(path: &Path) -> Result<bool, anyhow::Error> {
    let content = read_mesh_file_bytes(path)?;
    Ok(content_is_localized_mesh_slice(path, &content))
}

fn content_is_localized_mesh_slice(path: &Path, content: &str) -> bool {
    let is_yaml = detect_json_or_yaml_extension(path);
    if is_yaml {
        if admit_yaml_alias_expansion(content).is_err() {
            return false;
        }
        serde_yaml::from_str::<serde_yaml::Value>(content)
            .ok()
            .is_some_and(|value| yaml_value_is_localized_mesh_slice(&value))
    } else {
        serde_json::from_str::<serde_json::Value>(content)
            .ok()
            .is_some_and(|value| json_value_is_localized_mesh_slice(&value))
    }
}

fn yaml_value_is_localized_mesh_slice(value: &serde_yaml::Value) -> bool {
    let Some(mapping) = value.as_mapping() else {
        return false;
    };
    let mut saw_mesh = false;
    for (key, child) in mapping {
        match key.as_str() {
            Some("version") => {}
            Some("mesh") if child.is_mapping() => saw_mesh = true,
            _ => return false,
        }
    }
    saw_mesh
}

fn json_value_is_localized_mesh_slice(value: &serde_json::Value) -> bool {
    let Some(mapping) = value.as_object() else {
        return false;
    };
    let mut saw_mesh = false;
    for (key, child) in mapping {
        match key.as_str() {
            "version" => {}
            "mesh" if child.is_object() => saw_mesh = true,
            _ => return false,
        }
    }
    saw_mesh
}

/// Wrap a mesh section in a [`GatewayConfig`] and run the same normalization +
/// mesh-field validation the CP-side slice builder applies, so a document this
/// accepts cannot later be rejected by the slice-apply task for mesh-field
/// validity.
pub fn normalized_mesh_gateway_config(
    mesh: Box<crate::modes::mesh::config::MeshConfig>,
) -> Result<GatewayConfig, anyhow::Error> {
    let mut config = GatewayConfig {
        version: CURRENT_CONFIG_VERSION.to_string(),
        mesh: Some(mesh),
        loaded_at: chrono::Utc::now(),
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    config.normalize_mesh_fields();
    let mesh_errors = config.validate_mesh_fields();
    if !mesh_errors.is_empty() {
        anyhow::bail!(
            "mesh configuration validation failed: {}",
            mesh_errors.join("; ")
        );
    }
    Ok(config)
}

/// Wrap a serde error with a pointer at the document contract so an operator
/// who fed a full gateway config file gets steered instead of puzzled by a
/// bare "unknown field `proxies`".
fn mesh_doc_parse_error(err: impl std::fmt::Display) -> String {
    // Document adapters already sanitize the inner error. Never classify this
    // composed diagnostic: its leading path may contain document map keys.
    format!(
        "invalid mesh configuration document: {err} (the localized mesh source consumes only an \
         optional `version` plus the `mesh` section; gateway resources such as proxies/upstreams \
         belong to FERRUM_MODE=file)"
    )
}

/// Record that a localized mesh reload signal was observed.
///
/// Returns the generation that now owns the latest request. Call this when the
/// signal arrives — not when a follow-up worker is later spawned — so an
/// in-flight older candidate becomes stale immediately and cannot install.
pub fn record_mesh_reload_request(latest_requested: &AtomicU64) -> u64 {
    latest_requested.fetch_add(1, Ordering::AcqRel) + 1
}

/// A completed candidate may install only when it still owns the latest
/// requested generation (exact equality). A future/out-of-contract generation
/// must not be treated as current.
pub fn mesh_reload_generation_is_current(generation: u64, latest_requested: u64) -> bool {
    generation == latest_requested
}

/// Reload notification source driving [`run_mesh_local_reload_loop`].
///
/// Production wraps the SIGHUP stream ([`SignalReloadNotifier`]); tests inject
/// an mpsc receiver so the EXACT production loop body can be driven
/// deterministically instead of through a process-global signal.
pub trait MeshReloadNotifier: Send {
    /// Wait for the next reload notification. `None` means the source closed
    /// and no further reloads are possible.
    fn recv(&mut self) -> impl std::future::Future<Output = Option<()>> + Send;

    /// Drop notifications that are already queued, without waiting. Repeated
    /// signals collapse into the single follow-up the loop schedules.
    fn drain_ready(&mut self);
}

/// SIGHUP-backed notifier used by both production reload loops.
#[cfg(unix)]
pub struct SignalReloadNotifier(pub tokio::signal::unix::Signal);

#[cfg(unix)]
impl MeshReloadNotifier for SignalReloadNotifier {
    async fn recv(&mut self) -> Option<()> {
        self.0.recv().await
    }

    fn drain_ready(&mut self) {
        use futures_util::FutureExt as _;
        while self.0.recv().now_or_never().flatten().is_some() {}
    }
}

/// Injected notifier seam: the deterministic stand-in for SIGHUP delivery.
///
/// This is a plain generic impl, not a test-only runtime branch — the loop it
/// drives is byte-for-byte the loop production runs.
impl MeshReloadNotifier for tokio::sync::mpsc::Receiver<()> {
    async fn recv(&mut self) -> Option<()> {
        tokio::sync::mpsc::Receiver::recv(self).await
    }

    fn drain_ready(&mut self) {
        while self.try_recv().is_ok() {}
    }
}

/// Operator-facing log lines for one localized reload loop instance. Keeping
/// them as `&'static str` fields lets both sources share one state machine
/// while retaining their own wording.
#[derive(Debug, Clone, Copy)]
pub struct MeshReloadLoopMessages {
    pub shutdown: &'static str,
    pub notifier_closed: &'static str,
    pub stale_generation: &'static str,
    pub reloaded: &'static str,
    pub load_failed: &'static str,
    pub join_cancelled: &'static str,
    pub worker_panicked: &'static str,
}

/// Outcome of applying one completed reload candidate.
#[derive(Debug, Clone)]
pub struct MeshLocalReloadResult {
    pub apply: MeshLocalReloadApply,
    /// Optional observability stamp (the mesh slice version, when the source
    /// produces one).
    pub version: Option<String>,
}

/// The localized reload state machine shared by the `file` mesh source and the
/// `stock_xds` policy watcher.
///
/// One loop, two instantiations, so the coalescing / generation-fencing /
/// shutdown contract cannot diverge between them:
///
/// * repeated notifications coalesce to ONE in-flight load plus at most ONE
///   follow-up, and the requested generation advances when the notification is
///   OBSERVED, so an older completed load can never install over a newer
///   request;
/// * shutdown is `biased;`-first, so a completion that becomes ready in the
///   same poll cannot publish; shutdown also stops accepting candidates without
///   awaiting a started (non-cancellable) `spawn_blocking` job;
/// * every failure path (load error, worker panic, apply rejection) retains the
///   last-good generation and raises the sticky `config_rejected` signal.
pub async fn run_mesh_local_reload_loop<N, T, S, A>(
    mut notifier: N,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    path: &str,
    recovery: &MeshLocalSourceRecovery,
    messages: &MeshReloadLoopMessages,
    spawn: S,
    mut apply: A,
) where
    N: MeshReloadNotifier,
    T: Send + 'static,
    S: Fn() -> tokio::task::JoinHandle<Result<T, anyhow::Error>>,
    A: FnMut(T) -> MeshLocalReloadResult,
{
    let latest_requested = AtomicU64::new(0);
    let publish_allowed = AtomicBool::new(true);
    let mut accepted_generation = 0u64;
    let mut pending_follow_up = false;
    let mut in_flight: Option<(u64, tokio::task::JoinHandle<Result<T, anyhow::Error>>)> = None;

    loop {
        // `biased;` + shutdown first: when shutdown and completion are both
        // ready, shutdown wins and the completion cannot publish.
        tokio::select! {
            biased;
            _ = super::common::wait_for_shutdown(shutdown_rx) => {
                info!("{}", messages.shutdown);
                stop_accepting_reload_candidates(&publish_allowed, &mut in_flight);
                return;
            }
            received = notifier.recv() => {
                if received.is_none() {
                    warn!("{}", messages.notifier_closed);
                    stop_accepting_reload_candidates(&publish_allowed, &mut in_flight);
                    super::common::wait_for_shutdown(shutdown_rx).await;
                    return;
                }
                // Coalesce any already-queued notifications into one follow-up.
                notifier.drain_ready();

                // Advance the requested generation at observation so an
                // in-flight older candidate becomes stale immediately.
                let generation = record_mesh_reload_request(&latest_requested);
                if in_flight.is_some() {
                    pending_follow_up = true;
                    continue;
                }
                in_flight = Some((generation, spawn()));
            }
            join_result = async {
                match in_flight.as_mut() {
                    Some((_, handle)) => Some(handle.await),
                    None => {
                        std::future::pending::<()>().await;
                        None
                    }
                }
            } => {
                let Some((generation, _)) = in_flight.take() else {
                    continue;
                };
                let Some(join_result) = join_result else {
                    continue;
                };

                if !publish_allowed.load(Ordering::Acquire) {
                    // Shutdown already stopped accepting candidates.
                    continue;
                }

                match join_result {
                    Ok(Ok(loaded)) => {
                        let latest = latest_requested.load(Ordering::Acquire);
                        if !mesh_reload_generation_is_current(generation, latest) {
                            info!(
                                file_path = %sanitize_startup_cause(format!("{path:?}"), &[]),
                                generation,
                                latest,
                                "{}", messages.stale_generation
                            );
                        } else if generation >= accepted_generation {
                            let result = apply(loaded);
                            if matches!(
                                result.apply,
                                MeshLocalReloadApply::Applied | MeshLocalReloadApply::Unchanged
                            ) {
                                info!(
                                    file_path = %sanitize_startup_cause(format!("{path:?}"), &[]),
                                    mesh_slice_version = %sanitize_startup_scalar(result.version.as_deref().unwrap_or("")),
                                    generation,
                                    outcome = ?result.apply,
                                    "{}", messages.reloaded
                                );
                                accepted_generation = generation;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(
                            file_path = %sanitize_startup_cause(format!("{path:?}"), &[]),
                            generation,
                            error = %sanitize_startup_cause(&e, &[]),
                            "{}", messages.load_failed
                        );
                        mark_mesh_local_reload_rejected(recovery);
                    }
                    Err(join_error) if join_error.is_cancelled() => {
                        info!(
                            file_path = %sanitize_startup_cause(format!("{path:?}"), &[]),
                            generation,
                            "{}", messages.join_cancelled
                        );
                    }
                    Err(_) => {
                        warn!(
                            file_path = %sanitize_startup_cause(format!("{path:?}"), &[]),
                            generation,
                            error = "reload worker panicked (details withheld)",
                            "{}", messages.worker_panicked
                        );
                        mark_mesh_local_reload_rejected(recovery);
                    }
                }

                if pending_follow_up && publish_allowed.load(Ordering::Acquire) {
                    pending_follow_up = false;
                    // Reuse the latest requested generation recorded when the
                    // coalesced notification(s) arrived.
                    let generation = latest_requested.load(Ordering::Acquire);
                    in_flight = Some((generation, spawn()));
                }
            }
        }
    }
}

/// What a pending local-source recovery is waiting for.
///
/// At most ONE recovery is pending at a time, so the pending slot's epoch is
/// the linearization tag for "still current".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingRecoveryKind {
    /// File-source candidate: bound to its content digest at creation.
    Slice,
    /// Stock-policy baseline: unbound until the stock client installs a slice
    /// that incorporates it (`bind_installed_slice_if_policy_recovery`).
    Policy,
}

/// The single recovery candidate awaiting proxy acceptance.
#[derive(Debug, Clone, Copy)]
struct PendingRecovery {
    /// Epoch that created this pending state.
    epoch: u64,
    kind: PendingRecoveryKind,
    /// Content digest the proxy must accept before health may clear. `None`
    /// while a stock-policy recovery is still unbound.
    digest: Option<[u8; 32]>,
}

/// Serialized recovery-transition state (see [`MeshLocalSourceRecovery`]).
///
/// Every variant carries the last issued epoch, so "which epoch is current"
/// can never disagree with "what is pending". The epoch advances on every
/// rejection and on every new pending recovery.
#[derive(Debug, Clone, Copy)]
enum MeshLocalRecoveryPhase {
    /// No recovery is outstanding and the latest transition was not a
    /// rejection (startup, or the current candidate was proxy-accepted).
    Idle { last_epoch: u64 },
    /// Exactly one candidate awaits proxy acceptance; its epoch is the last
    /// issued epoch.
    Pending(PendingRecovery),
    /// The latest transition was a rejection issued at `epoch`. Nothing is
    /// pending, so no proxy acceptance can clear health until a new candidate
    /// begins.
    Rejected { epoch: u64 },
}

impl Default for MeshLocalRecoveryPhase {
    fn default() -> Self {
        Self::Idle { last_epoch: 0 }
    }
}

/// One input to [`MeshLocalRecoveryPhase::transition`].
#[derive(Debug, Clone, Copy)]
enum MeshLocalRecoveryEvent {
    /// The current local-source attempt failed (load/parse/validation, revision
    /// quarantine, undeliverable policy, unprovable candidate identity).
    Reject,
    /// A rejection that applies only while SOME recovery is pending (a stock
    /// revision-gate quarantine of an install made under a pending recovery).
    RejectIfPending,
    /// A rejection that applies only while the recovery begun at this epoch is
    /// STILL the pending one (a policy-rebuild failure for that baseline). An
    /// older epoch's failure must not cancel a newer recovery.
    RejectEpoch(u64),
    /// A new candidate begins awaiting proxy acceptance.
    Begin {
        kind: PendingRecoveryKind,
        digest: Option<[u8; 32]>,
    },
    /// The stock client is installing a slice built on the policy baseline
    /// whose recovery began at `epoch`.
    BindPolicy {
        epoch: u64,
        identity: MeshRevisionContentIdentity,
    },
    /// The proxy apply lifecycle accepted a slice with this content digest.
    ProxyAccepted { digest: [u8; 32] },
    /// The proxy apply lifecycle rejected a slice with this content identity.
    ProxyRejected {
        identity: MeshRevisionContentIdentity,
    },
}

/// The `config_rejected` write (if any) owed by one transition. Applied by the
/// caller inside the SAME critical section as the phase change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeshLocalRecoveryEffect {
    /// Stale or irrelevant callback: phase and health are unchanged.
    Ignored,
    /// Phase changed (new candidate / identity bind); health is unchanged.
    Advanced,
    /// Raise `config_rejected`.
    Raise,
    /// Clear `config_rejected`.
    Clear,
}

impl MeshLocalRecoveryPhase {
    fn last_epoch(self) -> u64 {
        match self {
            Self::Idle { last_epoch } => last_epoch,
            Self::Pending(pending) => pending.epoch,
            Self::Rejected { epoch } => epoch,
        }
    }

    fn pending(self) -> Option<PendingRecovery> {
        match self {
            Self::Pending(pending) => Some(pending),
            Self::Idle { .. } | Self::Rejected { .. } => None,
        }
    }

    fn rejected_after(self) -> (Self, MeshLocalRecoveryEffect) {
        (
            Self::Rejected {
                epoch: self.last_epoch().wrapping_add(1),
            },
            MeshLocalRecoveryEffect::Raise,
        )
    }

    /// The ONE transition function of the recovery machine. Pure: the caller
    /// holds the transition lock, stores the returned phase, and performs the
    /// returned health write before releasing it.
    fn transition(self, event: MeshLocalRecoveryEvent) -> (Self, MeshLocalRecoveryEffect) {
        use MeshLocalRecoveryEffect as Effect;
        use MeshLocalRecoveryEvent as Event;
        match (self, event) {
            (_, Event::Reject) => self.rejected_after(),

            (Self::Pending(_), Event::RejectIfPending) => self.rejected_after(),
            (Self::Idle { .. } | Self::Rejected { .. }, Event::RejectIfPending) => {
                (self, Effect::Ignored)
            }

            (Self::Pending(pending), Event::RejectEpoch(epoch)) if pending.epoch == epoch => {
                self.rejected_after()
            }
            // A NEWER recovery is outstanding: the stale failure neither
            // cancels it nor raises health (the newer candidate's own outcome
            // decides). Idle/Rejected: the epoch was already resolved by an
            // acceptance or a rejection that linearized first.
            (Self::Pending(_), Event::RejectEpoch(_))
            | (Self::Idle { .. } | Self::Rejected { .. }, Event::RejectEpoch(_)) => {
                (self, Effect::Ignored)
            }

            (_, Event::Begin { kind, digest }) => (
                Self::Pending(PendingRecovery {
                    epoch: self.last_epoch().wrapping_add(1),
                    kind,
                    digest,
                }),
                Effect::Advanced,
            ),

            (Self::Pending(pending), Event::BindPolicy { epoch, identity })
                if pending.kind == PendingRecoveryKind::Policy && pending.epoch == epoch =>
            {
                match identity {
                    MeshRevisionContentIdentity::Digest(digest) => (
                        Self::Pending(PendingRecovery {
                            digest: Some(digest),
                            ..pending
                        }),
                        Effect::Advanced,
                    ),
                    MeshRevisionContentIdentity::Unavailable => self.rejected_after(),
                }
            }
            // A canceled or superseded (file-slice / newer-epoch) recovery is
            // left exactly as found: a late install can neither resurrect a
            // canceled recovery nor overwrite a newer candidate's identity.
            (Self::Pending(_), Event::BindPolicy { .. })
            | (Self::Idle { .. } | Self::Rejected { .. }, Event::BindPolicy { .. }) => {
                (self, Effect::Ignored)
            }

            (Self::Pending(pending), Event::ProxyAccepted { digest })
                if pending.digest == Some(digest) =>
            {
                (
                    Self::Idle {
                        last_epoch: pending.epoch,
                    },
                    Effect::Clear,
                )
            }
            (Self::Pending(_), Event::ProxyAccepted { .. })
            | (Self::Idle { .. } | Self::Rejected { .. }, Event::ProxyAccepted { .. }) => {
                (self, Effect::Ignored)
            }

            (Self::Pending(pending), Event::ProxyRejected { identity }) => {
                match (pending.digest, identity) {
                    (Some(expected), MeshRevisionContentIdentity::Digest(digest))
                        if digest == expected =>
                    {
                        self.rejected_after()
                    }
                    // An unbound stock policy recovery has not installed a
                    // candidate yet, so any apply callback in that window
                    // belongs to an older slice and must not cancel it. A
                    // mismatched or unprovable identity is likewise not the
                    // pending candidate.
                    (Some(_), MeshRevisionContentIdentity::Digest(_))
                    | (Some(_), MeshRevisionContentIdentity::Unavailable)
                    | (None, _) => (self, Effect::Ignored),
                }
            }
            (Self::Idle { .. } | Self::Rejected { .. }, Event::ProxyRejected { .. }) => {
                (self, Effect::Ignored)
            }
        }
    }
}

/// Sticky local-source health + race-safe recovery handshake (issue #3776).
///
/// `config_rejected` is the authenticated `/health` surface held by
/// [`crate::admin::AdminState`]. Clearing that flag is gated on the exact
/// current recovery candidate being accepted by the proxy apply lifecycle —
/// provisional `install_slice` / policy channel send must not clear it, and an
/// older success must not clear after a newer failure.
///
/// **Linearization contract.** Every transition — cancel, new pending
/// candidate, policy-identity bind, proxy accept, proxy reject — runs as ONE
/// critical section of `state`, and the `config_rejected` write that belongs to
/// that transition happens inside the SAME critical section. A callback
/// therefore decides against the state that is current at the instant it holds
/// the lock; there is no capture-then-act window in which a newer rejection or
/// a newer candidate can land between a stale callback's test and its write. In
/// particular an older success can never clear after a newer failure, and an
/// older rejection can never cancel a newer pending recovery whose identity
/// differs. The `AtomicBool` stays the lock-free AdminState READ surface
/// (`/health`), but it is only ever WRITTEN under this lock.
///
/// The lock is non-reentrant and is the only lock this type takes, so it can
/// neither deadlock against itself nor participate in a lock cycle: public
/// methods take it once and delegate to `*_locked` helpers instead of calling
/// each other.
#[derive(Debug)]
pub struct MeshLocalSourceRecovery {
    config_rejected: Arc<AtomicBool>,
    /// The transition authority. See the type-level linearization contract.
    state: Mutex<MeshLocalRecoveryPhase>,
}

impl MeshLocalSourceRecovery {
    /// Share one recovery handshake across the source watcher, stock install
    /// path, and mesh apply task while exposing the same `Arc<AtomicBool>` to
    /// AdminState.
    pub fn new(config_rejected: Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            config_rejected,
            state: Mutex::new(MeshLocalRecoveryPhase::default()),
        })
    }

    /// Authenticated `/health` sticky signal (unchanged AdminState surface).
    pub fn config_rejected_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.config_rejected)
    }

    /// Whether authenticated health currently reports local-source rejection.
    pub fn is_rejected(&self) -> bool {
        self.config_rejected.load(Ordering::Relaxed)
    }

    /// Epoch currently pending proxy acceptance (`0` = none).
    pub fn pending_epoch(&self) -> u64 {
        match self.state.lock() {
            Ok(state) => state.pending().map_or(0, |pending| pending.epoch),
            Err(_) => {
                self.fail_closed_on_poisoned_state();
                0
            }
        }
    }

    /// A poisoned transition lock means an earlier transition panicked partway
    /// through, so the pending slot can no longer be trusted. Fail closed: hold
    /// (or raise) the sticky degraded signal, never clear it, and refuse the
    /// transition — without an `unwrap`/`expect` panic on a production path.
    fn fail_closed_on_poisoned_state(&self) {
        self.config_rejected.store(true, Ordering::Relaxed);
        warn!(
            "Mesh local-source recovery transition state is poisoned; refusing the recovery \
             transition and holding config_rejected"
        );
    }

    /// Run one transition under the caller-held transition lock and perform the
    /// health write it owes inside the SAME critical section. Never call a
    /// public method from inside a critical section: the mutex is not
    /// reentrant.
    fn transition_locked(
        &self,
        state: &mut MeshLocalRecoveryPhase,
        event: MeshLocalRecoveryEvent,
    ) -> MeshLocalRecoveryEffect {
        let (next, effect) = state.transition(event);
        *state = next;
        match effect {
            MeshLocalRecoveryEffect::Raise => self.config_rejected.store(true, Ordering::Relaxed),
            MeshLocalRecoveryEffect::Clear => {
                crate::modes::clear_config_rejected_after_accepted_full_reload(
                    &self.config_rejected,
                    "mesh local-source recovery",
                );
            }
            MeshLocalRecoveryEffect::Ignored | MeshLocalRecoveryEffect::Advanced => {}
        }
        effect
    }

    /// Lock, transition, and report the effect. A poisoned lock fails closed
    /// and reports `None`.
    fn transition(&self, event: MeshLocalRecoveryEvent) -> Option<MeshLocalRecoveryEffect> {
        match self.state.lock() {
            Ok(mut state) => Some(self.transition_locked(&mut state, event)),
            Err(_) => {
                self.fail_closed_on_poisoned_state();
                None
            }
        }
    }

    /// Raise `config_rejected` and cancel any pending recovery so it can no
    /// longer clear health.
    pub fn mark_rejected(&self) {
        let _ = self.transition(MeshLocalRecoveryEvent::Reject);
    }

    /// Raise `config_rejected` only if a recovery is still pending, as ONE
    /// critical section.
    ///
    /// `pending_epoch() != 0` followed by a separate `mark_rejected()` is a
    /// TOCTOU: the pending slot can be cleared (a concurrent proxy accept) or
    /// replaced (a newer candidate) between the two calls, so the second call
    /// would either raise health for a recovery that already succeeded or
    /// cancel a newer recovery it never tested. Testing and raising under one
    /// lock acquisition removes that window.
    ///
    /// Returns whether the sticky signal was raised. A poisoned lock fails
    /// closed (raises and reports `true`).
    pub fn mark_rejected_if_pending(&self) -> bool {
        self.transition(MeshLocalRecoveryEvent::RejectIfPending)
            .is_none_or(|effect| effect == MeshLocalRecoveryEffect::Raise)
    }

    /// Reject the recovery that began at `epoch` — but ONLY while it is still
    /// the pending recovery, as ONE critical section.
    ///
    /// A policy-rebuild failure belongs to the baseline it was built from. A
    /// newer reload may have begun its own recovery while that older baseline
    /// was being rebuilt; an unconditional [`Self::mark_rejected`] would cancel
    /// the newer recovery, so when the newer candidate later installs nothing
    /// is pending to bind and `config_rejected` sticks while valid policy is
    /// live. A stale epoch is therefore ignored and the newer candidate's own
    /// outcome decides health.
    ///
    /// Returns whether the sticky signal was raised. A poisoned lock fails
    /// closed (raises and reports `true`).
    pub fn mark_rejected_for_epoch(&self, epoch: u64) -> bool {
        self.transition(MeshLocalRecoveryEvent::RejectEpoch(epoch))
            .is_none_or(|effect| effect == MeshLocalRecoveryEffect::Raise)
    }

    /// Whether a pending recovery exists that a slice identity could match.
    ///
    /// Cheap pre-check so the callbacks below can skip canonical slice
    /// digesting entirely when there is nothing to bind, clear, or cancel. It
    /// is only an optimization: every caller re-acquires the lock and
    /// re-validates the pending slot before acting, so a state change in the
    /// gap cannot be acted on stale.
    fn has_digest_bearing_pending(&self) -> bool {
        match self.state.lock() {
            Ok(state) => state
                .pending()
                .is_some_and(|pending| pending.digest.is_some()),
            Err(_) => {
                self.fail_closed_on_poisoned_state();
                false
            }
        }
    }

    /// Mark a provisionally installed file-source recovery candidate.
    ///
    /// Does **not** clear `config_rejected`. An uncomputable content identity
    /// fails closed (stays/sets degraded) because recovery cannot be proven.
    pub fn mark_slice_recovery_pending(&self, slice: &MeshSlice) -> Option<u64> {
        // The digest is a pure function of the candidate, so it is computed
        // outside the transition: the lock covers the state change only.
        let identity = slice_content_identity(slice);
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                self.fail_closed_on_poisoned_state();
                return None;
            }
        };
        match identity {
            MeshRevisionContentIdentity::Digest(digest) => {
                let event = MeshLocalRecoveryEvent::Begin {
                    kind: PendingRecoveryKind::Slice,
                    digest: Some(digest),
                };
                self.transition_locked(&mut state, event);
                state.pending().map(|pending| pending.epoch)
            }
            MeshRevisionContentIdentity::Unavailable => {
                // Same critical section: an unprovable candidate supersedes any
                // pending recovery and fails closed as one transition.
                self.transition_locked(&mut state, MeshLocalRecoveryEvent::Reject);
                drop(state);
                warn!(
                    "Mesh local reload candidate has uncomputable content identity; raising \
                     config_rejected because recovery cannot be proven"
                );
                None
            }
        }
    }

    /// Begin a stock-policy recovery after a valid baseline is published to the
    /// watch channel. Does **not** clear `config_rejected`; the pending slice
    /// identity is bound later when the stock client installs a rebuilt slice.
    ///
    /// Returns the new pending epoch, or `0` when the transition was refused
    /// because the state is poisoned (health is then held degraded).
    pub fn begin_policy_recovery(&self) -> u64 {
        match self.state.lock() {
            Ok(mut state) => {
                let event = MeshLocalRecoveryEvent::Begin {
                    kind: PendingRecoveryKind::Policy,
                    digest: None,
                };
                self.transition_locked(&mut state, event);
                state.pending().map_or(0, |pending| pending.epoch)
            }
            Err(_) => {
                self.fail_closed_on_poisoned_state();
                0
            }
        }
    }

    /// Rebind the pending recovery identity when the stock client installs a
    /// slice that incorporates the active policy recovery (including a later
    /// discovery update on that same recovered baseline).
    ///
    /// `expected_epoch` is carried atomically with the policy snapshot; a
    /// debounced slice built from an older snapshot cannot bind a newer policy
    /// recovery that began before the old slice reached `install_slice`.
    ///
    /// Binds only the still-current policy recovery: a canceled (`None`) or
    /// superseded (file-slice) pending state is left exactly as found, so a
    /// late install can neither resurrect a canceled recovery nor overwrite a
    /// newer candidate's identity.
    pub fn bind_installed_slice_if_policy_recovery(&self, expected_epoch: u64, slice: &MeshSlice) {
        // Cheap pre-check: with no still-current policy recovery for this
        // epoch there is nothing to bind, so skip the canonical digest work
        // entirely. The authoritative test is re-done by the transition below.
        match self.state.lock() {
            Ok(state) => {
                let relevant = state.pending().is_some_and(|pending| {
                    pending.kind == PendingRecoveryKind::Policy && pending.epoch == expected_epoch
                });
                if !relevant {
                    return;
                }
            }
            Err(_) => {
                self.fail_closed_on_poisoned_state();
                return;
            }
        }

        let identity = slice_content_identity(slice);
        // The transition re-validates epoch/kind: the pending slot may have
        // been canceled or superseded while the digest ran.
        let effect = self.transition(MeshLocalRecoveryEvent::BindPolicy {
            epoch: expected_epoch,
            identity,
        });
        if effect == Some(MeshLocalRecoveryEffect::Raise) {
            warn!(
                "Stock policy recovery slice has uncomputable content identity; raising \
                 config_rejected because recovery cannot be proven"
            );
        }
    }

    /// Clear sticky rejection only when the proxy accepted the exact current
    /// pending recovery identity (Applied or content-identical no-op).
    ///
    /// The identity test and the clear share one critical section, so a newer
    /// rejection or a newer candidate that linearizes first is already visible
    /// and this (now stale) success declines.
    pub fn note_proxy_apply_success(&self, slice: &MeshSlice) {
        // No digest-bearing pending recovery ⇒ nothing this success could
        // prove, so do not pay for the canonical slice identity. The pending
        // slot is re-read and re-compared by the transition below.
        if !self.has_digest_bearing_pending() {
            return;
        }
        let MeshRevisionContentIdentity::Digest(digest) = slice_content_identity(slice) else {
            // An unprovable identity can never prove a recovery; it is also not
            // evidence of failure, so health is left untouched.
            return;
        };
        let _ = self.transition(MeshLocalRecoveryEvent::ProxyAccepted { digest });
    }

    /// Proxy rejection / quarantine of a pending recovery leaves degraded and
    /// cancels that pending clear.
    ///
    /// Only the still-current pending identity is cancelable: an older callback
    /// whose candidate no longer matches the pending slot leaves a newer
    /// recovery outstanding.
    pub fn note_proxy_apply_rejection(&self, slice: &MeshSlice) {
        // Only a digest-bearing pending recovery is cancelable (an unbound
        // policy recovery deliberately matches nothing), so skip the canonical
        // digest when there is none. Re-validated by the transition below.
        if !self.has_digest_bearing_pending() {
            return;
        }
        let identity = slice_content_identity(slice);
        let _ = self.transition(MeshLocalRecoveryEvent::ProxyRejected { identity });
    }
}

/// Apply outcome for a localized mesh file/policy reload candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshLocalReloadApply {
    /// Candidate replaced (or was admitted into) live received state.
    /// Sticky health clears only after proxy apply accepts this recovery.
    Applied,
    /// Candidate was valid and content-identical to the live generation.
    /// Sticky health clears only after proxy apply accepts this recovery.
    Unchanged,
    /// Candidate was refused; last-good retained and `config_rejected` raised.
    Rejected,
}

/// Apply a loaded mesh-file reload candidate through the recovery handshake.
///
/// Load failure or revision quarantine raises the sticky degraded signal and
/// cancels any older pending recovery. A provisionally installed candidate
/// marks recovery pending but does **not** clear `config_rejected` — only the
/// mesh apply task does, once the exact current recovery is proxy-accepted.
pub fn apply_mesh_file_reload_candidate(
    state: &MeshRuntimeState,
    recovery: &MeshLocalSourceRecovery,
    candidate: Result<MeshSlice, anyhow::Error>,
) -> MeshLocalReloadApply {
    match candidate {
        Ok(slice) => {
            let unchanged = state
                .snapshot()
                .as_ref()
                .as_ref()
                .is_some_and(|live| live.content_eq(&slice));
            // Register the recovery identity BEFORE `install_slice` wakes the
            // proxy apply task. Otherwise a fast apply can report success while
            // no pending recovery exists yet, leaving sticky health degraded
            // forever even though the exact candidate became live.
            if recovery.mark_slice_recovery_pending(&slice).is_none() {
                return MeshLocalReloadApply::Rejected;
            }
            match state.install_slice(slice) {
                MeshSliceInstall::Installed => {
                    if unchanged {
                        MeshLocalReloadApply::Unchanged
                    } else {
                        MeshLocalReloadApply::Applied
                    }
                }
                MeshSliceInstall::Quarantined(rejection) => {
                    warn!(
                        rejection = %sanitize_startup_cause(&rejection, &[]),
                        "Mesh file reload quarantined by the revision gate; keeping the last \
                         good mesh slice and raising config_rejected"
                    );
                    recovery.mark_rejected();
                    MeshLocalReloadApply::Rejected
                }
            }
        }
        Err(error) => {
            warn!(
                error = %sanitize_startup_cause(&error, &[]),
                "Failed to reload mesh config file; keeping the last good mesh slice and \
                 raising config_rejected"
            );
            recovery.mark_rejected();
            MeshLocalReloadApply::Rejected
        }
    }
}

/// Mark a localized mesh reload failure (join panic, worker failure) on the
/// shared recovery handshake without mutating the live slice.
pub fn mark_mesh_local_reload_rejected(recovery: &MeshLocalSourceRecovery) {
    recovery.mark_rejected();
}

/// Reload the mesh document on SIGHUP (Unix), keeping the last good slice
/// when a reload fails. The initial load happens before this task is spawned
/// (fail-closed at startup); identical reloads are deduped downstream by the
/// slice-apply task's `content_eq` check.
///
/// Filesystem + parse work runs on `spawn_blocking`. Rapid SIGHUP delivery is
/// coalesced: at most one load runs at a time, and a signal that arrives
/// during an in-flight load schedules exactly one follow-up generation. The
/// requested generation advances when the signal is observed so an older
/// completed load cannot install. Watcher shutdown stops accepting candidates
/// immediately and does not await a started (non-cancellable) blocking job.
/// The select is `biased` with shutdown first so a simultaneous completion
/// cannot publish.
pub async fn start_mesh_file_source_with_shutdown(
    path: String,
    request: MeshSliceRequest,
    state: MeshRuntimeState,
    recovery: Arc<MeshLocalSourceRecovery>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    #[cfg(unix)]
    {
        let hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    error = %sanitize_startup_cause(&e, &[]),
                    "Failed to register SIGHUP handler for mesh file source; the mesh \
                     document will not reload until restart"
                );
                super::common::wait_for_shutdown(&mut shutdown_rx).await;
                return;
            }
        };

        run_mesh_local_reload_loop(
            SignalReloadNotifier(hangup),
            &mut shutdown_rx,
            &path,
            &recovery,
            &MESH_FILE_RELOAD_MESSAGES,
            || spawn_mesh_reload(&path, request.clone()),
            |slice| MeshLocalReloadResult {
                version: Some(slice.version.clone()),
                apply: apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice)),
            },
        )
        .await;
    }

    #[cfg(not(unix))]
    {
        info!(
            file_path = %sanitize_startup_cause(format!("{path:?}"), &[]),
            "Mesh file source loaded; live reload is Unix-only (SIGHUP), restart to pick up \
             changes"
        );
        let _ = &request;
        let _ = &state;
        let _ = &recovery;
        super::common::wait_for_shutdown(&mut shutdown_rx).await;
    }
}

/// Log lines for the localized `file` mesh source's reload loop.
pub const MESH_FILE_RELOAD_MESSAGES: MeshReloadLoopMessages = MeshReloadLoopMessages {
    shutdown: "Mesh file source shutting down",
    notifier_closed: "SIGHUP stream closed; mesh file source will not reload until restart",
    stale_generation: "Discarding stale mesh file reload generation",
    reloaded: "Reloaded mesh config file on SIGHUP",
    load_failed: "Failed to reload mesh config file on SIGHUP; keeping the last good mesh slice",
    join_cancelled: "Mesh file reload join cancelled before publish",
    worker_panicked: "Mesh file reload worker panicked; keeping the last good mesh slice",
};

/// Spawn one localized mesh-document load onto the blocking pool.
///
/// Public so tests can drive [`run_mesh_local_reload_loop`] with the exact
/// production loader instead of a stand-in.
pub fn spawn_mesh_reload(
    path: &str,
    request: MeshSliceRequest,
) -> tokio::task::JoinHandle<Result<MeshSlice, anyhow::Error>> {
    let load_path = PathBuf::from(path);
    tokio::task::spawn_blocking(move || load_mesh_slice_from_file(&load_path, request))
}

/// Stop accepting reload candidates and detach any in-flight blocking work.
///
/// Tokio cannot cancel a `spawn_blocking` task once it has started. Aborting
/// the join handle only prevents scheduling if the job has not begun; awaiting
/// a started job would stall watcher shutdown. Dropping the handle detaches
/// the result, and the `publish_allowed` gate prevents a late completion from
/// installing if the join arm still races.
fn stop_accepting_reload_candidates<T>(
    publish_allowed: &AtomicBool,
    in_flight: &mut Option<(u64, tokio::task::JoinHandle<Result<T, anyhow::Error>>)>,
) {
    publish_allowed.store(false, Ordering::Release);
    if let Some((_, handle)) = in_flight.take() {
        handle.abort();
        drop(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::diagnostic_test_support::DiagnosticLogs;
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn reload_emissions_withhold_versions_and_panic_payloads() {
        for panic_worker in [false, true] {
            let logs = DiagnosticLogs::default();
            let _guard = tracing::subscriber::set_default(logs.subscriber());
            let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));
            let (notify_tx, notify_rx) = tokio::sync::mpsc::channel(1);
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
            let applied = std::cell::Cell::new(0);
            notify_tx.send(()).await.unwrap();
            let reload = run_mesh_local_reload_loop(
                notify_rx,
                &mut shutdown_rx,
                "'UNREGISTERED_PATH5591\"\\\n",
                &recovery,
                &MESH_FILE_RELOAD_MESSAGES,
                || {
                    tokio::spawn(async move {
                        if panic_worker {
                            panic!("UNREGISTERED_PANIC5591 '\"\\\n");
                        }
                        Ok(())
                    })
                },
                |()| {
                    applied.set(applied.get() + 1);
                    shutdown_tx.send(true).unwrap();
                    MeshLocalReloadResult {
                        apply: MeshLocalReloadApply::Applied,
                        version: Some("'UNREGISTERED_VERSION5591\"\\\n".to_string()),
                    }
                },
            );
            let stop_after_rejection = async {
                if panic_worker {
                    while !recovery.is_rejected() {
                        tokio::task::yield_now().await;
                    }
                    shutdown_tx.send(true).unwrap();
                }
            };
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                tokio::join!(reload, stop_after_rejection);
            })
            .await
            .expect("reload must complete and observe shutdown");
            assert_eq!(recovery.is_rejected(), panic_worker);
            assert_eq!(applied.get(), usize::from(!panic_worker));
            let output = logs.output();
            assert!(output.contains("file_path="), "{output}");
            assert!(output.contains("generation=1"), "{output}");
            if panic_worker {
                assert!(output.contains("error="), "{output}");
                assert!(output.contains("panicked"), "{output}");
            } else {
                assert!(output.contains("mesh_slice_version="), "{output}");
                assert!(output.contains("outcome=Applied"), "{output}");
            }
            for secret in [
                "UNREGISTERED_PATH5591",
                "UNREGISTERED_VERSION5591",
                "UNREGISTERED_PANIC5591",
            ] {
                assert!(!output.contains(secret), "{output}");
            }
        }
    }
}
