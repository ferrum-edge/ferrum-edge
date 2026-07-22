//! Unix-domain-socket server that services CNI plugin RPCs against the
//! node-agent's existing enrollment state.
//!
//! Architecture:
//! - The CNI binary (`bin/ferrum-cni`) is invoked by kubelet during pod
//!   sandbox setup. It hands the call (ADD/DEL/CHECK + pod identity) to us
//!   over a Unix socket using the length-prefixed JSON wire format in
//!   [`crate::cni::rpc`].
//! - This server runs as a tokio task spawned from
//!   [`crate::modes::node_agent::run_with_backend`]. It accepts one
//!   connection per RPC (CNI is short-lived; no pooling), parses the
//!   request, and forwards a [`CniWorkItem`] to the main node-agent loop
//!   via an `mpsc` channel. The main loop is the single owner of the
//!   `EbpfBackend` and the `pod_states` `DashMap`, so we never need a
//!   `Mutex` around either.
//! - The work item carries a `oneshot::Sender<CniRpcResponse>` so the main
//!   loop can answer back. The server then writes the response on the
//!   same connection and closes it.
//!
//! Fallback semantics: when the CNI plugin is the primary enrollment path,
//! the kube-rs watcher in `node_agent.rs` still runs and reconciles any
//! pods the CNI hook missed (CNI install not rolled out yet, CNI plugin
//! chain rejected, etc.). The CNI hook is an OPTIMIZATION — it gets us
//! deterministic per-pod enrollment at sandbox-setup time, vs the watcher
//! which races kubelet to see the pod after it is already starting.
//!
//! Trust model: the UDS lives at a host-path mount that only the node-
//! agent and the `ferrum-cni` binary (running as root from the kubelet)
//! can reach. Permissions on the socket are 0660 by default; the Helm
//! chart installs both endpoints under directories the operator pre-
//! creates. We do not authenticate individual CNI calls — anyone who
//! can write the socket can already enroll pods at the cgroup level.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::cni::rpc::{CniRpcRequest, CniRpcResponse};
use crate::ebpf::NodeAgentMetrics;

#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use tokio::time::timeout;
#[cfg(unix)]
use tracing::{debug, error, info};

#[cfg(unix)]
use crate::cni::rpc::{
    LENGTH_PREFIX_BYTES, MAX_RPC_BYTES, RpcOutcome, RpcVerb, decode_body, encode_frame,
};
#[cfg(unix)]
use crate::ebpf::{CniCallOutcome, CniCallVerb};

/// One unit of work queued from the CNI server to the main node-agent loop.
///
/// The `respond` channel is consumed exactly once by the main loop and the
/// server task awaits it with a tight timeout — if the main loop is wedged
/// or shutting down, the CNI client sees an IPC error and kubelet retries
/// (or the kube-rs watcher reconciles when the node-agent recovers).
pub struct CniWorkItem {
    pub request: CniRpcRequest,
    pub respond: oneshot::Sender<CniRpcResponse>,
}

/// Sender half of the CNI work queue.
pub type CniWorkSender = mpsc::Sender<CniWorkItem>;
/// Receiver half consumed by the main node-agent loop.
pub type CniWorkReceiver = mpsc::Receiver<CniWorkItem>;

/// Build a bounded queue between the CNI server and the main loop.
///
/// Capacity of 64 is intentional: the main loop processes one request per
/// tokio `select!` iteration, so a deeper queue would just buffer work
/// during scheduling bursts. If the queue fills, the server returns an
/// error and kubelet retries — that is the back-pressure signal we want.
pub fn cni_work_channel() -> (CniWorkSender, CniWorkReceiver) {
    mpsc::channel(64)
}

/// Tight bound on how long the CNI server waits for the main loop to
/// answer a single RPC. Shorter than the CNI binary's own timeout so the
/// binary sees a structured error rather than the kubelet killing it.
#[cfg(unix)]
const MAIN_LOOP_REPLY_TIMEOUT: Duration = Duration::from_secs(3);
/// A legacy generation may predate the lifetime lock. Refuse to unlink its
/// socket when a short local connect probe succeeds or cannot be resolved
/// promptly; only a definitive refused/missing endpoint is stale.
#[cfg(unix)]
const CNI_SOCKET_OWNER_PROBE_TIMEOUT: Duration = Duration::from_millis(250);

/// Spawn the CNI Unix-socket listener.
///
/// The task takes ownership of the socket path and runs until shutdown is
/// signaled. On every accept it forwards the parsed request to the main
/// node-agent loop and pipes the answer back to the client.
///
/// A sibling advisory-lock file is held for the listener's entire lifetime.
/// Startup refuses to evict a live owner; only after acquiring the lock does it
/// remove a stale socket left by a crashed generation. Shutdown compares the
/// published socket's device/inode identity before unlinking, so an older
/// generation can never remove a replacement published at the same pathname.
/// Parent directories are created when missing; installs that pre-create the
/// directory do not change anything.
#[cfg(unix)]
pub fn spawn_cni_listener(
    socket_path: String,
    work_sender: CniWorkSender,
    metrics: Arc<NodeAgentMetrics>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = prepare_socket_parent(&socket_path).await {
            error!(
                socket_path = %socket_path,
                error = %err,
                reason = "ownership_io_error",
                "Failed to prepare node-agent CNI socket parent; CNI plugin path will fall back to kube-rs watcher"
            );
            metrics.record_cni_socket_lifecycle(
                crate::ebpf::CniSocketLifecycleReason::OwnershipIoError,
            );
            return;
        }

        // The lock file is deliberately retained on disk. Deleting it would
        // let two processes lock different inodes for the same socket path.
        // Closing `_ownership_lock` at task exit releases the kernel lock.
        let _ownership_lock = match acquire_socket_ownership(&socket_path) {
            Ok(Some(lock)) => lock,
            Ok(None) => {
                metrics.record_cni_socket_lifecycle(
                    crate::ebpf::CniSocketLifecycleReason::OwnershipConflict,
                );
                error!(
                    socket_path = %socket_path,
                    lock_path = %socket_ownership_lock_path(&socket_path).display(),
                    reason = "ownership_conflict",
                    "Another live node-agent owns the CNI socket; refusing to replace it and falling back to the kube-rs watcher"
                );
                return;
            }
            Err(err) => {
                metrics.record_cni_socket_lifecycle(
                    crate::ebpf::CniSocketLifecycleReason::OwnershipIoError,
                );
                error!(
                    socket_path = %socket_path,
                    lock_path = %socket_ownership_lock_path(&socket_path).display(),
                    error = %err,
                    reason = "ownership_io_error",
                    "Failed to acquire node-agent CNI socket ownership; falling back to the kube-rs watcher"
                );
                return;
            }
        };

        match prepare_socket_after_lock(&socket_path).await {
            Ok(SocketPreparation::Ready) => {}
            Ok(SocketPreparation::LiveLegacyOwner) => {
                metrics.record_cni_socket_lifecycle(
                    crate::ebpf::CniSocketLifecycleReason::OwnershipConflict,
                );
                error!(
                    socket_path = %socket_path,
                    reason = "ownership_conflict",
                    "A live pre-lock node-agent still owns the CNI socket; refusing to evict it and falling back to the kube-rs watcher"
                );
                return;
            }
            Err(err) => {
                error!(
                    socket_path = %socket_path,
                    error = %err,
                    reason = "stale_socket_cleanup_error",
                    "Failed to classify or remove stale node-agent CNI socket after acquiring ownership; CNI plugin path will fall back to kube-rs watcher"
                );
                metrics.record_cni_socket_lifecycle(
                    crate::ebpf::CniSocketLifecycleReason::StaleSocketCleanupError,
                );
                return;
            }
        }

        // bind() creates the socket inode world-reachable (mode 0777 & ~umask)
        // and it is only narrowed to 0660 afterward. Close that window by
        // binding under a freshly-created 0700 staging directory with a short,
        // bounded socket filename, chmod-ing the socket to 0660, then
        // ATOMICALLY renaming it into place. The staging directory lives under
        // the final socket parent, so rename stays on the same filesystem, but
        // the temporary listener path is not traversable by other local UIDs
        // and does not append to a near-limit configured socket pathname.
        let stage = match create_private_socket_stage(&socket_path) {
            Ok(stage) => stage,
            Err(err) => {
                error!(
                    socket_path = %socket_path,
                    error = %err,
                    "Failed to create private staging directory for node-agent CNI socket; CNI plugin path will fall back to kube-rs watcher"
                );
                return;
            }
        };
        let listener = match UnixListener::bind(&stage.socket_path) {
            Ok(listener) => listener,
            Err(err) => {
                error!(
                    socket_path = %socket_path,
                    error = %err,
                    "Failed to bind node-agent CNI socket; CNI plugin path will fall back to kube-rs watcher"
                );
                cleanup_private_socket_stage(&stage);
                return;
            }
        };
        // Narrow to 0660 BEFORE publishing under the well-known name. If this
        // fails, abort rather than publish a world-reachable socket.
        if let Err(err) = set_socket_perms(&stage.socket_path) {
            error!(
                socket_path = %socket_path,
                error = %err,
                "Failed to chmod node-agent CNI socket to 0660 before publish; aborting CNI listener (falling back to kube-rs watcher)"
            );
            cleanup_private_socket_stage(&stage);
            return;
        }
        let published_identity = match SocketIdentity::from_path(&stage.socket_path) {
            Ok(identity) => identity,
            Err(err) => {
                metrics.record_cni_socket_lifecycle(
                    crate::ebpf::CniSocketLifecycleReason::HandoffIdentityError,
                );
                error!(
                    socket_path = %socket_path,
                    error = %err,
                    reason = "handoff_identity_error",
                    "Failed to identify staged node-agent CNI socket; refusing publication"
                );
                cleanup_private_socket_stage(&stage);
                return;
            }
        };
        if let Err(err) = std::fs::rename(&stage.socket_path, &socket_path) {
            error!(
                socket_path = %socket_path,
                error = %err,
                "Failed to publish node-agent CNI socket; CNI plugin path will fall back to kube-rs watcher"
            );
            cleanup_private_socket_stage(&stage);
            return;
        }
        cleanup_private_socket_stage(&stage);
        match SocketIdentity::from_path(&socket_path) {
            Ok(current) if current == published_identity => {}
            Ok(current) => {
                metrics.record_cni_socket_lifecycle(
                    crate::ebpf::CniSocketLifecycleReason::HandoffIdentityError,
                );
                error!(
                    socket_path = %socket_path,
                    expected_device = published_identity.device,
                    expected_inode = published_identity.inode,
                    actual_device = current.device,
                    actual_inode = current.inode,
                    reason = "handoff_identity_error",
                    "Published CNI socket identity changed before verification; dropping the unnamed listener without unlinking the replacement"
                );
                return;
            }
            Err(err) => {
                metrics.record_cni_socket_lifecycle(
                    crate::ebpf::CniSocketLifecycleReason::HandoffIdentityError,
                );
                error!(
                    socket_path = %socket_path,
                    error = %err,
                    reason = "handoff_identity_error",
                    "Published CNI socket could not be verified; dropping the listener"
                );
                return;
            }
        }
        info!(
            socket_path = %socket_path,
            "Node-agent CNI listener bound; ferrum-cni binary may now forward ADD/DEL/CHECK calls"
        );

        let mut accept_backoff = crate::util::accept_backoff::AcceptBackoff::new();
        let mut accept_err_log = crate::util::accept_backoff::LogRateLimiter::new();
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _addr)) => {
                            accept_backoff.on_success();
                            let work_sender = work_sender.clone();
                            let metrics = metrics.clone();
                            tokio::spawn(async move {
                                handle_one_connection(stream, work_sender, metrics).await;
                            });
                        }
                        Err(err) => {
                            // Bound the log rate independently of the backoff
                            // (an abort/reset flood is not backed off): emit the
                            // first error then one summary per second with the
                            // suppressed count.
                            if let Some(suppressed) =
                                accept_err_log.on_event(crate::socket_opts::monotonic_now_ms())
                            {
                                warn!(error = %err, suppressed, "Node-agent CNI listener accept failed");
                            }
                            if let Some(delay) = accept_backoff.on_error(err.kind()) {
                                tokio::time::sleep(delay).await;
                            }
                        }
                    }
                }
            }
        }

        info!(
            socket_path = %socket_path,
            "Node-agent CNI listener shutting down; checking socket ownership before cleanup"
        );
        match remove_published_socket_if_owned(&socket_path, published_identity).await {
            Ok(OwnedSocketCleanup::Removed | OwnedSocketCleanup::AlreadyMissing) => {}
            Ok(OwnedSocketCleanup::ReplacementPreserved { current }) => {
                info!(
                    socket_path = %socket_path,
                    owned_device = published_identity.device,
                    owned_inode = published_identity.inode,
                    current_device = current.device,
                    current_inode = current.inode,
                    reason = "replacement_preserved",
                    "CNI socket path now belongs to another generation; preserving the replacement"
                );
            }
            Err(err) => {
                metrics.record_cni_socket_lifecycle(
                    crate::ebpf::CniSocketLifecycleReason::ShutdownCleanupError,
                );
                warn!(
                    socket_path = %socket_path,
                    error = %err,
                    reason = "shutdown_cleanup_error",
                    "Failed to remove owned CNI socket file on shutdown"
                );
            }
        }
    })
}

/// Non-Unix stub so the release build matrix can compile the shared crate.
///
/// CNI is a Linux/Unix deployment path because the wire transport is a Unix
/// domain socket. On Windows the node-agent falls back to the watcher-only
/// path; this stub preserves that behavior if the mode is ever invoked there.
#[cfg(not(unix))]
pub fn spawn_cni_listener(
    socket_path: String,
    _work_sender: CniWorkSender,
    _metrics: Arc<NodeAgentMetrics>,
    _shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        warn!(
            socket_path = %socket_path,
            "Node-agent CNI listener requested on non-Unix target; listener disabled"
        );
    })
}

#[cfg(unix)]
async fn prepare_socket_parent(socket_path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(socket_path).parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    Ok(())
}

#[cfg(unix)]
fn socket_ownership_lock_path(socket_path: &str) -> PathBuf {
    PathBuf::from(format!("{socket_path}.lock"))
}

/// Acquire the stable, process-lifetime advisory lock for one configured CNI
/// socket path. `Ok(None)` means another live Ferrum generation owns it.
#[cfg(unix)]
fn acquire_socket_ownership(socket_path: &str) -> std::io::Result<Option<File>> {
    let lock_path = socket_ownership_lock_path(socket_path);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&lock_path)?;
    let lock_metadata = file.metadata()?;
    if !lock_metadata.file_type().is_file() || lock_metadata.nlink() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "CNI socket ownership lock '{}' must be a single-link regular file",
                lock_path.display()
            ),
        ));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;

    // SAFETY: `file` owns a valid descriptor for the lifetime of this call and
    // is returned to the listener task on success, keeping the advisory lock
    // alive until that task exits. `flock` does not access Rust-managed memory.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        // Detect a rename-and-replace between open and lock acquisition. Without
        // this fence, two generations could hold locks on different inodes that
        // merely used the same pathname at different instants.
        let path_metadata = std::fs::symlink_metadata(&lock_path)?;
        if !path_metadata.file_type().is_file()
            || path_metadata.nlink() != 1
            || path_metadata.dev() != lock_metadata.dev()
            || path_metadata.ino() != lock_metadata.ino()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "CNI socket ownership lock '{}' changed identity during acquisition",
                    lock_path.display()
                ),
            ));
        }
        return Ok(Some(file));
    }
    let error = std::io::Error::last_os_error();
    let raw_error = error.raw_os_error();
    if raw_error == Some(libc::EWOULDBLOCK) || raw_error == Some(libc::EAGAIN) {
        Ok(None)
    } else {
        Err(error)
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketPreparation {
    Ready,
    LiveLegacyOwner,
}

/// Classify a pre-existing pathname only while the lifetime lock proves no
/// cooperating generation owns it. A successful or inconclusive connect probe
/// protects a live legacy (pre-lock) generation; only a definitive refused or
/// missing endpoint is removed as stale.
#[cfg(unix)]
async fn prepare_socket_after_lock(socket_path: &str) -> std::io::Result<SocketPreparation> {
    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SocketPreparation::Ready);
        }
        Err(err) => return Err(err),
    };

    if metadata.file_type().is_socket() {
        match timeout(
            CNI_SOCKET_OWNER_PROBE_TIMEOUT,
            UnixStream::connect(socket_path),
        )
        .await
        {
            Ok(Ok(stream)) => {
                drop(stream);
                return Ok(SocketPreparation::LiveLegacyOwner);
            }
            Err(_elapsed) => return Ok(SocketPreparation::LiveLegacyOwner),
            Ok(Err(err))
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) => {}
            Ok(Err(err)) => return Err(err),
        }
    }

    match tokio::fs::remove_file(socket_path).await {
        Ok(()) => Ok(SocketPreparation::Ready),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(SocketPreparation::Ready),
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl SocketIdentity {
    fn from_path(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("'{}' is not a Unix socket", path.display()),
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnedSocketCleanup {
    Removed,
    AlreadyMissing,
    ReplacementPreserved { current: SocketIdentity },
}

#[cfg(unix)]
async fn remove_published_socket_if_owned(
    socket_path: &str,
    owned: SocketIdentity,
) -> std::io::Result<OwnedSocketCleanup> {
    let current = match SocketIdentity::from_path(socket_path) {
        Ok(identity) => identity,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OwnedSocketCleanup::AlreadyMissing);
        }
        Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {
            // A non-socket replacement is never ours. Report a sentinel
            // identity in the structured log without following symlinks.
            return Ok(OwnedSocketCleanup::ReplacementPreserved {
                current: SocketIdentity {
                    device: 0,
                    inode: 0,
                },
            });
        }
        Err(err) => return Err(err),
    };
    if current != owned {
        return Ok(OwnedSocketCleanup::ReplacementPreserved { current });
    }

    match tokio::fs::remove_file(socket_path).await {
        Ok(()) => Ok(OwnedSocketCleanup::Removed),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok(OwnedSocketCleanup::AlreadyMissing)
        }
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
fn set_socket_perms(socket_path: impl AsRef<Path>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o660);
    std::fs::set_permissions(socket_path, perms)
}

#[cfg(unix)]
struct PrivateSocketStage {
    dir: PathBuf,
    socket_path: PathBuf,
}

#[cfg(unix)]
fn create_private_socket_stage(socket_path: &str) -> std::io::Result<PrivateSocketStage> {
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::MetadataExt;

    let final_path = Path::new(socket_path);
    let parent = final_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let final_path_len = unix_path_len(final_path);
    let parent_dev = std::fs::metadata(parent).ok().map(|meta| meta.dev());
    let stage_parents = private_socket_stage_parent_candidates(parent, parent_dev, final_path_len);

    let mut last_create_error = None;
    for _ in 0..16 {
        let stage_dir_name = format!(".f{:016x}", random_stage_suffix());
        for stage_parent in &stage_parents {
            let stage_dir = stage_parent.join(&stage_dir_name);
            let socket_path = stage_dir.join("s");
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&stage_dir) {
                Ok(()) => {
                    return Ok(PrivateSocketStage {
                        dir: stage_dir,
                        socket_path,
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    debug!(
                        stage_parent = %stage_parent.display(),
                        error = %err,
                        "Failed to create candidate private CNI socket staging directory"
                    );
                    last_create_error = Some(err);
                    continue;
                }
            }
        }
    }

    Err(last_create_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate unique private CNI socket staging directory",
        )
    }))
}

#[cfg(unix)]
fn private_socket_stage_parent_candidates(
    final_parent: &Path,
    final_parent_dev: Option<u64>,
    final_path_len: usize,
) -> Vec<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let mut candidates = Vec::new();
    for ancestor in final_parent.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        if let Some(dev) = final_parent_dev {
            let Ok(meta) = std::fs::metadata(ancestor) else {
                continue;
            };
            if meta.dev() != dev {
                continue;
            }
        }
        let candidate_socket = ancestor.join(".f0000000000000000").join("s");
        if unix_path_len(&candidate_socket) <= final_path_len {
            candidates.push(ancestor.to_path_buf());
        }
    }

    if candidates.is_empty() {
        candidates.push(final_parent.to_path_buf());
    }
    candidates
}

#[cfg(unix)]
fn unix_path_len(path: &Path) -> usize {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().len()
}

#[cfg(unix)]
fn random_stage_suffix() -> u64 {
    use ring::rand::SecureRandom;

    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 8];
    if rng.fill(&mut bytes).is_ok() {
        return u64::from_ne_bytes(bytes);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    nanos ^ u64::from(std::process::id())
}

#[cfg(unix)]
fn cleanup_private_socket_stage(stage: &PrivateSocketStage) {
    let _ = std::fs::remove_file(&stage.socket_path);
    let _ = std::fs::remove_dir(&stage.dir);
}

/// Read one RPC, ship it to the main loop, write the response.
///
/// Connection is closed after one round-trip. Any error before we have a
/// response logs a `warn!`, increments the `error` outcome counter, and
/// returns — the client side reports the IPC error to kubelet and the
/// kube-rs watcher reconciliation path is unaffected.
#[cfg(unix)]
async fn handle_one_connection(
    mut stream: UnixStream,
    work_sender: CniWorkSender,
    metrics: Arc<NodeAgentMetrics>,
) {
    let request = match read_request_frame(&mut stream).await {
        Ok(req) => req,
        Err(err) => {
            warn!(error = %err, "Failed to read CNI RPC request");
            // We cannot attribute to a specific verb because parsing failed;
            // bump the "error" outcome on each verb? Instead, log only —
            // bad framing means a misconfigured client, not a node-agent
            // signal worth alerting on.
            return;
        }
    };
    let verb = request.verb;
    let metric_verb = match verb {
        RpcVerb::Add => CniCallVerb::Add,
        RpcVerb::Del => CniCallVerb::Del,
        RpcVerb::Check => CniCallVerb::Check,
    };

    let (resp_tx, resp_rx) = oneshot::channel();
    let work = CniWorkItem {
        request,
        respond: resp_tx,
    };
    if let Err(err) = work_sender.try_send(work) {
        warn!(
            verb = ?verb,
            error = %err,
            "Failed to enqueue CNI work; main loop may be saturated or shutting down"
        );
        metrics.record_cni_call(metric_verb, CniCallOutcome::Error);
        let _ = write_response_frame(
            &mut stream,
            &CniRpcResponse::Error {
                reason: "node-agent work queue saturated; retry".to_string(),
            },
        )
        .await;
        return;
    }

    let response = match timeout(MAIN_LOOP_REPLY_TIMEOUT, resp_rx).await {
        Ok(Ok(response)) => response,
        Ok(Err(_canceled)) => {
            warn!(verb = ?verb, "Main loop dropped CNI work item without replying");
            CniRpcResponse::Error {
                reason: "node-agent did not reply".to_string(),
            }
        }
        Err(_elapsed) => {
            warn!(verb = ?verb, "Main loop did not reply to CNI work item within timeout");
            CniRpcResponse::Error {
                reason: "node-agent reply timed out".to_string(),
            }
        }
    };
    let outcome = match response.outcome() {
        RpcOutcome::Success => CniCallOutcome::Success,
        RpcOutcome::Rejected => CniCallOutcome::Rejected,
        RpcOutcome::Error => CniCallOutcome::Error,
    };
    metrics.record_cni_call(metric_verb, outcome);
    debug!(
        verb = ?verb,
        outcome = outcome.label(),
        "Served CNI RPC"
    );
    if let Err(err) = write_response_frame(&mut stream, &response).await {
        warn!(error = %err, "Failed to write CNI RPC response");
    }
}

#[cfg(unix)]
async fn read_request_frame(stream: &mut UnixStream) -> Result<CniRpcRequest, String> {
    let mut len_buf = [0u8; LENGTH_PREFIX_BYTES];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("read length prefix: {e}"))?;
    let body_len = u32::from_be_bytes(len_buf) as usize;
    if body_len == 0 || body_len > MAX_RPC_BYTES {
        return Err(format!("invalid frame length {body_len}"));
    }
    let mut body = vec![0u8; body_len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| format!("read body: {e}"))?;
    decode_body(&body)
}

#[cfg(unix)]
async fn write_response_frame(
    stream: &mut UnixStream,
    response: &CniRpcResponse,
) -> Result<(), String> {
    let frame = encode_frame(response).map_err(|e| format!("encode response: {e}"))?;
    stream
        .write_all(&frame)
        .await
        .map_err(|e| format!("write response: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("flush response: {e}"))?;
    Ok(())
}

/// Translate a CNI RPC request into a `PodEvent` the existing
/// [`crate::modes::node_agent::handle_pod_added`] path can consume.
///
/// This helper intentionally emits only the identity carried on the CNI wire.
/// Production ADD handling enriches the request from the Kubernetes API before
/// it calls the node-agent enrollment path; tests and fallback paths use this
/// minimal shape to verify the no-metadata behavior.
pub fn pod_event_from_request<'a>(
    request: &'a CniRpcRequest,
    labels: &'a HashMap<String, String>,
    annotations: &'a HashMap<String, String>,
) -> crate::modes::node_agent::PodEvent<'a> {
    crate::modes::node_agent::PodEvent {
        pod_uid: request.pod_uid.as_deref().unwrap_or(""),
        pod_name: request.pod_name.as_str(),
        namespace: request.pod_namespace.as_str(),
        // CNI wire carries no service account; the production ADD path enriches
        // identity from the Kubernetes API before enrollment. None here means
        // the FERRUM_WORKLOAD_IDENTITY entry derives from the `default` SA
        // until the kube-rs watcher reconciles the pod with its real SA.
        service_account: None,
        labels,
        annotations,
        pod_ip_str: None,
        pod_source_ips: crate::modes::node_agent::PodSourceIps::default(),
        node_probe_ports: Vec::new(),
        pod_pid: None,
        veth_iface_override: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cni::rpc::{CniRpcRequest, RpcVerb};
    use std::collections::HashMap;

    #[cfg(unix)]
    async fn wait_for_socket(path: &Path) -> SocketIdentity {
        for _ in 0..200 {
            if let Ok(identity) = SocketIdentity::from_path(path) {
                return identity;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("listener did not publish Unix socket '{}'", path.display());
    }

    #[cfg(unix)]
    async fn stop_listener(
        shutdown: tokio::sync::watch::Sender<bool>,
        handle: tokio::task::JoinHandle<()>,
    ) {
        let _ = shutdown.send(true);
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("listener should stop promptly")
            .expect("listener task should not panic");
    }

    #[test]
    fn pod_event_from_request_strips_optional_fields() {
        let request = CniRpcRequest {
            verb: RpcVerb::Add,
            pod_namespace: "demo".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: Some("uid-1".to_string()),
            container_id: "ctr-1".to_string(),
            netns_path: Some("/var/run/netns/cni-1".to_string()),
            args: HashMap::new(),
        };
        let labels = HashMap::new();
        let annotations = HashMap::new();
        let event = pod_event_from_request(&request, &labels, &annotations);
        assert_eq!(event.pod_uid, "uid-1");
        assert_eq!(event.pod_name, "alpha");
        assert_eq!(event.namespace, "demo");
        assert!(event.pod_ip_str.is_none());
        assert_eq!(
            event.pod_source_ips,
            crate::modes::node_agent::PodSourceIps::default()
        );
        assert!(event.pod_pid.is_none());
    }

    #[test]
    fn pod_event_handles_missing_pod_uid_with_empty_string() {
        let request = CniRpcRequest {
            verb: RpcVerb::Del,
            pod_namespace: "demo".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: None,
            container_id: "ctr-1".to_string(),
            netns_path: None,
            args: HashMap::new(),
        };
        let labels = HashMap::new();
        let annotations = HashMap::new();
        let event = pod_event_from_request(&request, &labels, &annotations);
        assert_eq!(
            event.pod_uid, "",
            "missing pod_uid should map to empty string so callers can short-circuit"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn published_cni_socket_is_never_world_permissive() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("node-agent-cni.sock");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let (tx, _rx) = cni_work_channel();
        let metrics = Arc::new(NodeAgentMetrics::default());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = spawn_cni_listener(socket_path_str.clone(), tx, metrics, shutdown_rx);

        // Wait for the listener to publish the socket at the well-known path.
        let mut mode = None;
        for _ in 0..200 {
            if let Ok(meta) = std::fs::metadata(&socket_path) {
                mode = Some(meta.permissions().mode() & 0o777);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let mode = mode.expect("listener should publish the socket");
        assert_eq!(
            mode, 0o660,
            "published socket must be exactly 0660, got {mode:o}"
        );
        assert_eq!(
            mode & 0o007,
            0,
            "published socket must never be world-accessible (even transiently at the well-known path)"
        );

        // The private staging directory must be cleaned up after the atomic
        // rename.
        assert!(
            std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".f")),
            "private staging directory must not linger after publish"
        );

        stop_listener(shutdown_tx, handle).await;
        assert!(!socket_path.exists(), "owned socket must be removed");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_owner_conflict_is_refused_without_replacing_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("node-agent-cni.sock");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let (owner_work, _owner_rx) = cni_work_channel();
        let owner_metrics = Arc::new(NodeAgentMetrics::default());
        let (owner_shutdown, owner_shutdown_rx) = tokio::sync::watch::channel(false);
        let owner = spawn_cni_listener(
            socket_path_str.clone(),
            owner_work,
            owner_metrics,
            owner_shutdown_rx,
        );
        let owner_identity = wait_for_socket(&socket_path).await;

        let (contender_work, _contender_rx) = cni_work_channel();
        let contender_metrics = Arc::new(NodeAgentMetrics::default());
        let (_contender_shutdown, contender_shutdown_rx) = tokio::sync::watch::channel(false);
        let contender = spawn_cni_listener(
            socket_path_str,
            contender_work,
            contender_metrics.clone(),
            contender_shutdown_rx,
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), contender)
            .await
            .expect("conflicting listener must fail promptly")
            .expect("conflicting listener task should not panic");

        assert_eq!(
            SocketIdentity::from_path(&socket_path).unwrap(),
            owner_identity
        );
        assert_eq!(
            contender_metrics.snapshot().cni_socket_lifecycle
                [crate::ebpf::CniSocketLifecycleReason::OwnershipConflict as usize],
            1
        );

        stop_listener(owner_shutdown, owner).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_legacy_owner_without_lock_is_probed_and_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("node-agent-cni.sock");
        let legacy = UnixListener::bind(&socket_path).expect("legacy listener bind");
        let legacy_identity = SocketIdentity::from_path(&socket_path).unwrap();

        let (work, _rx) = cni_work_channel();
        let metrics = Arc::new(NodeAgentMetrics::default());
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let contender = spawn_cni_listener(
            socket_path.to_string_lossy().to_string(),
            work,
            metrics.clone(),
            shutdown_rx,
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), contender)
            .await
            .expect("legacy-owner probe must finish promptly")
            .expect("contender task should not panic");

        assert_eq!(
            SocketIdentity::from_path(&socket_path).unwrap(),
            legacy_identity,
            "legacy live owner must not be unlinked"
        );
        assert_eq!(
            metrics.snapshot().cni_socket_lifecycle
                [crate::ebpf::CniSocketLifecycleReason::OwnershipConflict as usize],
            1
        );

        drop(legacy);
        std::fs::remove_file(&socket_path).expect("remove legacy test socket");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn old_generation_shutdown_preserves_replacement_socket_identity() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("node-agent-cni.sock");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let (work, _rx) = cni_work_channel();
        let metrics = Arc::new(NodeAgentMetrics::default());
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let old = spawn_cni_listener(socket_path_str.clone(), work, metrics, shutdown_rx);
        let old_identity = wait_for_socket(&socket_path).await;

        // Emulate an explicitly coordinated successor that has already
        // published while the old listener still drains. It intentionally
        // bypasses the lifetime lock so this test directly exercises the
        // shutdown inode fence that protects such a handoff.
        let stage = create_private_socket_stage(&socket_path_str).expect("replacement stage");
        let replacement = UnixListener::bind(&stage.socket_path).expect("replacement bind");
        set_socket_perms(&stage.socket_path).expect("replacement permissions");
        let replacement_identity = SocketIdentity::from_path(&stage.socket_path).unwrap();
        assert_ne!(replacement_identity, old_identity);
        std::fs::rename(&stage.socket_path, &socket_path).expect("publish replacement");
        cleanup_private_socket_stage(&stage);

        stop_listener(shutdown, old).await;
        assert_eq!(
            SocketIdentity::from_path(&socket_path).unwrap(),
            replacement_identity,
            "old generation must not unlink the replacement"
        );
        let fresh = UnixStream::connect(&socket_path)
            .await
            .expect("fresh client must still connect to replacement");
        drop(fresh);
        drop(replacement);
        std::fs::remove_file(&socket_path).expect("remove replacement test socket");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stale_unix_socket_is_recovered_after_ownership_lock() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("node-agent-cni.sock");
        let stale =
            std::os::unix::net::UnixListener::bind(&socket_path).expect("create stale Unix socket");
        drop(stale);
        SocketIdentity::from_path(&socket_path).expect("stale socket inode must remain");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let (work, _rx) = cni_work_channel();
        let metrics = Arc::new(NodeAgentMetrics::default());
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let listener = spawn_cni_listener(socket_path_str, work, metrics.clone(), shutdown_rx);
        wait_for_socket(&socket_path).await;
        assert_eq!(
            metrics.snapshot().cni_socket_lifecycle
                [crate::ebpf::CniSocketLifecycleReason::OwnershipConflict as usize],
            0
        );
        stop_listener(shutdown, listener).await;
    }

    #[cfg(unix)]
    #[test]
    fn cni_socket_stage_is_private_and_uses_bounded_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let long_socket_name = format!("{}{}", "n".repeat(72), ".sock");
        let socket_path = dir.path().join(long_socket_name);
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let stage = create_private_socket_stage(&socket_path_str).expect("stage dir");
        let mode = std::fs::metadata(&stage.dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "staging directory must be private");
        assert!(
            unix_path_len(&stage.socket_path) < unix_path_len(&socket_path),
            "stage socket path should use a bounded filename instead of suffixing the configured socket path"
        );

        cleanup_private_socket_stage(&stage);
        assert!(
            !stage.dir.exists(),
            "stage directory should be removable during cleanup"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cni_socket_stage_does_not_lengthen_long_parent_short_filename() {
        let dir = tempfile::tempdir().unwrap();
        let long_parent = dir.path().join("p".repeat(80));
        std::fs::create_dir_all(&long_parent).unwrap();
        let socket_path = long_parent.join("s");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let stage = create_private_socket_stage(&socket_path_str).expect("stage dir");
        assert!(
            unix_path_len(&stage.socket_path) <= unix_path_len(&socket_path),
            "stage socket path must not be longer than a near-limit final socket path"
        );
        assert!(
            !stage.socket_path.starts_with(&long_parent),
            "long final parent should not force the private staged socket under that same long path"
        );

        cleanup_private_socket_stage(&stage);
    }

    #[tokio::test]
    async fn channel_capacity_back_pressures_on_overflow() {
        let (tx, mut rx) = cni_work_channel();
        // Fill the channel beyond capacity — `try_send` should fail with
        // `TrySendError::Full` once the bounded queue is saturated.
        let cap = 64;
        for _ in 0..cap {
            let (_resp, _) = oneshot::channel();
            let item = CniWorkItem {
                request: CniRpcRequest {
                    verb: RpcVerb::Add,
                    pod_namespace: "demo".to_string(),
                    pod_name: "alpha".to_string(),
                    pod_uid: None,
                    container_id: "c".to_string(),
                    netns_path: None,
                    args: HashMap::new(),
                },
                respond: _resp,
            };
            assert!(tx.try_send(item).is_ok(), "queue should accept up to cap");
        }
        let (resp_tx, _resp_rx) = oneshot::channel();
        let overflow = CniWorkItem {
            request: CniRpcRequest {
                verb: RpcVerb::Add,
                pod_namespace: "demo".to_string(),
                pod_name: "overflow".to_string(),
                pod_uid: None,
                container_id: "c".to_string(),
                netns_path: None,
                args: HashMap::new(),
            },
            respond: resp_tx,
        };
        assert!(
            tx.try_send(overflow).is_err(),
            "queue should reject once full"
        );
        // Drain to keep the receiver alive until end of test.
        rx.close();
    }
}
