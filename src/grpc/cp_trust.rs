//! CP-side namespace-bound verification credentials for the CP/DP control
//! plane (advisory GHSA-3f2j-wwqw-grmg).
//!
//! # Why a shared HS256 secret is not an authorization boundary
//!
//! Before this module every data plane, mesh node, and xDS client received the
//! fleet-wide `FERRUM_CP_DP_GRPC_JWT_SECRET` and minted its own HS256 token
//! carrying a self-asserted `ns` claim. The CP verified the signature with the
//! *same* value and then trusted the claim. Signature validation therefore
//! proved possession of a key every tenant already held; it could not
//! establish that the signer was entitled to the namespace it wrote into `ns`.
//! A compromised tenant-A node could re-sign `ns = "tenant-b"` and subscribe to
//! tenant B's ConfigSync, native mesh, or xDS configuration.
//!
//! # The binding
//!
//! Authorization is now **server-derived**. The CP loads a trust bundle
//! ([`CpDpTrustBundle`], `FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH`) in which every
//! verification credential is immutably bound by *CP-side configuration* to a
//! namespace allow-list:
//!
//! - The JWT header `kid` selects **which key verifies the signature**. It is
//!   never an authorization input: a bearer that names another tenant's `kid`
//!   simply fails the signature check, because it does not hold that key.
//! - The selected key's `namespaces` list is the ceiling. The token's `ns`
//!   claim may only **narrow** it (set intersection), never widen it.
//! - When the connection carries an authenticated mTLS peer whose certificate
//!   encodes a SPIFFE identity, the namespace derived from that identity is
//!   intersected too. A shared-CA certificate that encodes no SPIFFE namespace
//!   contributes nothing — certificate validation alone is not namespace
//!   authorization, and it can never widen the bound set.
//! - An empty intersection is refused before any tenant state is serialized.
//!
//! Asymmetric keys (`RS*`/`PS*`/`ES*`/`EdDSA`) are the preferred deployment:
//! the CP holds only public material, so no signing authority exists on any
//! data plane at all. The symmetric migration path (`HS*`) remains usable only
//! because each secret is *per-credential* and bound, CP-side, to the
//! namespaces that credential may reach.
//!
//! # Fail-closed startup
//!
//! A multi-namespace CP (`FERRUM_CP_NAMESPACES` naming a set, or `*`) refuses
//! to start when the only configured credential is the legacy fleet-wide
//! self-minting secret — see
//! [`CpDpVerifier::validate_for_scope`]. There is deliberately no unsafe
//! override and no legacy shim.
//!
//! Bundle loading also refuses a symmetric credential backed by the fleet-wide
//! `FERRUM_CP_DP_GRPC_JWT_SECRET` — by variable name for `secret_env`, and by
//! resolved bytes for `secret` / `secret_path`. Such a credential is
//! structurally valid but semantically identical to the pre-advisory posture:
//! every data plane already holds that value, so any of them could name the
//! credential's `kid` and reach its namespaces.
//!
//! # One coherent source generation
//!
//! The bundle document and every file it references must be read from **one**
//! filesystem generation. Reading the document and then independently
//! re-resolving each `secret_path` / `public_key_path` let a Kubernetes
//! projected mount hand back a *mixed* bundle: the old document's namespace
//! ceiling paired with the new generation's key material (or the inverse).
//! Both halves are individually valid and the mixed result is internally
//! self-consistent, so neither a semantic fingerprint nor last-known-good
//! retention can detect it — the CP simply publishes a namespace binding that
//! existed in no operator configuration.
//!
//! Loading therefore has two phases:
//!
//! 1. [`PinnedTrustBundleSource::pin`] opens the mount's `..data` symlink
//!    **once**. One `open(2)` follows it atomically, so the resulting
//!    descriptor names exactly one generation directory forever after; a later
//!    `..data` swap — including an A→B→A sequence that recreates the original
//!    name — cannot redirect anything. The document itself is read through that
//!    descriptor, so the pin is only ever claimed when the document provably
//!    came from it.
//! 2. [`CpDpTrustBundle::from_pinned_source`] resolves every referenced source
//!    through the pinned descriptor with `openat(…, O_NOFOLLOW)` before any
//!    [`TrustedKey`] is constructed. Material that does not live in the pinned
//!    generation — an arbitrary external path, an ordinary filesystem, a
//!    non-Unix host — has no generation to be pinned to and must instead carry
//!    a manifest-bound `material_sha256`, which binds the bytes to the document
//!    that named them. Absence and mismatch are both fail-closed. Each file and
//!    the aggregate path-backed material retained for one candidate are bounded
//!    to 1 MiB.
//!
//! Inline `public_key_pem`, inline `secret`, and `secret_env` are read
//! atomically from the document or the process environment and keep their
//! documented behavior unchanged.
//!
//! Startup and the periodic reload worker share this one loader, so a mixed
//! candidate can become neither the initial authorization root nor a live
//! replacement. Rejections are classified by the closed
//! [`TrustBundleRejectReason`] set and never replace the last accepted
//! verifier.
//!
//! # Disclosure discipline
//!
//! Nothing in this module renders key material, token bytes, or claim values.
//! Request-time rejections use the closed [`TenantAuthRejectReason`] set, whose
//! labels are compile-time constants suitable for metrics and audit records.
//! Startup errors name only operator-authored identifiers (`kid`, file path)
//! that the operator already wrote into their own configuration.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use arc_swap::ArcSwap;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;
use tokio::sync::{Semaphore, watch};

use crate::fips::approved::Sha256;
use crate::grpc::cp_trust_health::{CpDpTrustReloadStatus, TrustReloadFailure};

/// Upper bound on the trust-bundle document size. The file is operator-owned,
/// but a bounded read keeps a mistyped path (a device node, a huge log) from
/// allocating without limit during startup.
const TRUST_BUNDLE_MAX_BYTES: u64 = 1024 * 1024;

/// Apply the same ceiling to file-backed verification material. Public keys
/// and symmetric secrets are tiny in practice; sharing the document limit
/// keeps the operator surface simple while preventing a path swap from turning
/// the periodic reload worker into an unbounded file reader.
const TRUST_MATERIAL_MAX_BYTES: u64 = TRUST_BUNDLE_MAX_BYTES;

/// Maximum total path-backed material retained while one coherent candidate is
/// assembled. Phase one intentionally resolves every source before semantic
/// construction, so the per-file ceiling alone would permit a small manifest
/// containing thousands of references to retain gigabytes at once.
const TRUST_MATERIAL_TOTAL_MAX_BYTES: u64 = TRUST_BUNDLE_MAX_BYTES;

/// A stalled network filesystem must not silently stop trust-bundle reloads
/// forever. The blocking read itself runs on a detached OS thread because a
/// timed-out `spawn_blocking` task cannot be cancelled.
const TRUST_BUNDLE_RELOAD_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// At most one detached reload read may remain blocked in the kernel. The
/// permit is owned by the OS thread, not by its async waiter, so a timeout
/// cannot start an unbounded sequence of abandoned readers.
static TRUST_BUNDLE_RELOAD_READ_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();

pub(crate) fn trust_bundle_reload_read_limit() -> Arc<Semaphore> {
    Arc::clone(TRUST_BUNDLE_RELOAD_READ_LIMIT.get_or_init(|| Arc::new(Semaphore::new(1))))
}

/// The symlink a Kubernetes projected ConfigMap/Secret volume replaces
/// atomically when it rotates. Every user-visible entry in the mount is a
/// stable symlink of the shape `<name> -> ..data/<name>`, so pinning this one
/// link pins the whole generation.
const PROJECTED_GENERATION_LINK: &str = "..data";

/// Why a trust-bundle load was refused.
///
/// A closed, fixed-cardinality set. It is what the reload worker logs and what
/// [`crate::grpc::cp_trust_health`] projects onto its published failure reason
/// (#3813). No variant carries a path, a digest, a namespace inventory, a
/// credential identifier, or any document or key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustBundleRejectReason {
    /// The bundle document itself is not a readable, bounded, regular UTF-8
    /// file.
    DocumentUnreadable,
    /// The document was read but is not a valid trust-bundle configuration.
    DocumentInvalid,
    /// Path-backed material could not be read as a bounded regular file.
    MaterialUnreadable,
    /// Path-backed material lies outside a provably pinned source generation
    /// and the document binds it to no `material_sha256`, so nothing proves it
    /// belongs to the generation the document came from.
    MaterialIntegrityUnbound,
    /// A declared `material_sha256` is not exactly 64 lowercase hex digits.
    MaterialIntegrityMalformed,
    /// Resolved material does not match the digest the document binds it to.
    MaterialIntegrityMismatch,
    /// A reference that claims to live in the pinned generation traverses out
    /// of it, is a symlink inside it, or does not name a file.
    SourceGenerationEscape,
    /// The pinned generation could not be established or was reclaimed while
    /// it was being read — the ordinary shape of a rotation that landed
    /// mid-load.
    SourceGenerationUnstable,
    /// A projected generation was detected but this platform offers no way to
    /// pin it. Refused rather than downgraded to independent re-resolution.
    #[allow(dead_code)]
    // Constructed on non-Unix; external tests assert the closed reason on Unix.
    SourceGenerationUnsupported,
}

/// A refused trust-bundle load: one closed classification plus an
/// operator-facing detail.
///
/// The detail names only operator-authored identifiers the operator already
/// wrote into their own configuration (the bundle path, a `kid`). It never
/// carries document bytes, key bytes, a referenced material path, a namespace
/// inventory, or either side of a digest comparison. Only the closed
/// [`TrustBundleRejectReason`] is ever logged.
#[derive(Debug, Clone)]
pub struct TrustBundleLoadError {
    reason: TrustBundleRejectReason,
    detail: String,
}

impl TrustBundleLoadError {
    fn new(reason: TrustBundleRejectReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// The closed classification, for audit/metric sinks and for the published
    /// reload-health reason.
    pub fn reason(&self) -> TrustBundleRejectReason {
        self.reason
    }
}

impl std::fmt::Display for TrustBundleLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustBundleReloadError {
    Rejected(TrustBundleRejectReason),
    ReaderUnavailable,
    ReaderFailed,
    ReadTimedOut,
}

impl TrustBundleReloadError {
    /// Project onto the published closed reload-failure set (#3813), so logs,
    /// authenticated health, and metrics all name the same fixed label.
    fn health_failure(self) -> TrustReloadFailure {
        match self {
            Self::Rejected(reason) => TrustReloadFailure::from_reject_reason(reason),
            Self::ReaderUnavailable => TrustReloadFailure::ReaderUnavailable,
            Self::ReaderFailed => TrustReloadFailure::ReaderFailed,
            Self::ReadTimedOut => TrustReloadFailure::ReadTimedOut,
        }
    }
}

/// Open a trust-material path without letting a non-regular source stall the
/// opener.
///
/// This mirrors the contract of [`crate::secrets::credential_file`], which
/// cannot be reused directly here because its `HARD_MAX_CREDENTIAL_FILE_MAX_BYTES`
/// ceiling (64 KiB) is far below the 1 MiB trust-bundle document limit. The two
/// halves are both load-bearing: a FIFO or a carrier-less device opened with a
/// plain blocking `open(2)` parks the caller *before* any regular-file check can
/// run — which would hang CP startup outright, and would wedge the trust-bundle
/// reload worker's `spawn_blocking` thread forever so accepted-credential
/// removals could never be published again.
///
/// Symlinked pathnames are still followed here: this is the *unpinned* opener,
/// reached only for the bundle document itself and for material the document
/// binds by `material_sha256`. Material inside a pinned projected generation
/// goes through [`open_at_nofollow`] instead, which refuses symlinks outright.
///
/// `subject` is the complete operator-facing phrase for diagnostics. Callers
/// deliberately omit referenced material paths from it: a `secret_path` names
/// where a tenant's signing secret lives.
fn open_regular_file_nonblocking(path: &str, subject: &str) -> Result<std::fs::File, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|e| format!("failed to inspect {subject}: {e}"))?;
    if !metadata.file_type().is_symlink() && !metadata.is_file() {
        return Err(format!("{subject} is not a regular file"));
    }

    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
    };
    #[cfg(not(unix))]
    let opened = std::fs::File::open(path);

    opened.map_err(|e| format!("failed to open {subject}: {e}"))
}

/// Read an already-open descriptor as a bounded regular file.
///
/// Split out from the path-based readers so material opened through a pinned
/// generation descriptor shares one bounding contract with material opened by
/// pathname. The descriptor — not the pathname — is authoritative for both.
fn read_open_file_bounded(
    mut file: std::fs::File,
    subject: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    let metadata = file
        .metadata()
        .map_err(|e| format!("failed to inspect {subject}: {e}"))?;
    if !metadata.is_file() {
        return Err(format!("{subject} is not a regular file"));
    }
    if metadata.len() > max_bytes {
        return Err(format!(
            "{subject} is {} bytes, above the {max_bytes}-byte limit",
            metadata.len()
        ));
    }

    // The descriptor metadata check is only an allocation hint. Bound the
    // actual read as well so in-place growth after metadata() cannot bypass
    // the ceiling or force an unbounded allocation.
    let mut raw = Vec::with_capacity(metadata.len().min(max_bytes) as usize);
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|e| format!("failed to read {subject}: {e}"))?;
    if raw.len() as u64 > max_bytes {
        return Err(format!(
            "{subject} grew above the {max_bytes}-byte limit while it was read"
        ));
    }
    Ok(raw)
}

fn read_regular_file_bytes_bounded(
    path: &str,
    subject: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    read_open_file_bounded(
        open_regular_file_nonblocking(path, subject)?,
        subject,
        max_bytes,
    )
}

fn decode_trust_utf8(raw: Vec<u8>, subject: &str) -> Result<String, String> {
    String::from_utf8(raw).map_err(|_| format!("{subject} is not valid UTF-8"))
}

/// `openat(dirfd, name, O_RDONLY|O_NOFOLLOW|…)`.
///
/// The `O_NOFOLLOW` is the escape guard: a symlink planted inside a projected
/// generation directory would otherwise resolve against the *live* filesystem
/// and reintroduce exactly the cross-generation reference this module exists to
/// forbid.
#[cfg(unix)]
fn open_at_nofollow(dir: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "material name contains an interior NUL",
        )
    })?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    // SAFETY: `dir` owns a valid open directory descriptor for the whole call,
    // and `name` is a NUL-terminated C string that outlives it.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a fresh descriptor that this call now solely
    // owns, so wrapping it in a `File` transfers that ownership exactly once.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// The filesystem generation a trust-bundle document was read from.
enum PinnedSourceGeneration {
    /// A Kubernetes-style projected mount. `dir` is an open descriptor for the
    /// exact `..data` generation directory the document was read from, so every
    /// same-mount reference resolves against that one inode no matter how
    /// `..data` moves afterwards.
    #[cfg(unix)]
    Projected {
        dir: std::fs::File,
        mount_dir: std::path::PathBuf,
    },
    /// No generation could be pinned: an ordinary filesystem, a document
    /// outside the projection, or a platform without `openat`. Every
    /// path-backed reference must then carry a manifest-bound digest.
    Unpinned,
}

/// A trust-bundle document plus the filesystem generation it was read from,
/// pinned before the document's own bytes were read.
///
/// Holding this value is what makes coherence provable: the generation every
/// later reference resolves against is already fixed, so no `..data` swap
/// between here and [`CpDpTrustBundle::from_pinned_source`] can mix the
/// document's namespace policy with another generation's key material.
pub struct PinnedTrustBundleSource {
    generation: PinnedSourceGeneration,
    document: String,
    origin: String,
}

impl std::fmt::Debug for PinnedTrustBundleSource {
    /// The document is configuration that may carry inline symmetric material,
    /// so it is never rendered.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedTrustBundleSource")
            .field("origin", &self.origin)
            .field(
                "pinned_generation",
                &!matches!(self.generation, PinnedSourceGeneration::Unpinned),
            )
            .finish_non_exhaustive()
    }
}

impl PinnedTrustBundleSource {
    /// Pin the document's filesystem generation and read the document through
    /// it.
    ///
    /// A projected mount is detected by `<dir>/..data` being a symlink. One
    /// `open(2)` on that link follows it atomically, so the returned descriptor
    /// names one generation directory even if `..data` is replaced in the very
    /// next instant. The pin is claimed only when the document itself can be
    /// opened inside it: a document living elsewhere proves nothing about a
    /// mount, so it falls back to the unpinned contract where every referenced
    /// file needs its own `material_sha256`.
    pub fn pin(path: &str) -> Result<Self, TrustBundleLoadError> {
        let subject = format!("CP/DP trust bundle '{path}'");
        let bundle_path = Path::new(path);

        if let Some(mount_dir) = bundle_path.parent() {
            let data_link = mount_dir.join(PROJECTED_GENERATION_LINK);
            let projected = std::fs::symlink_metadata(&data_link)
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false);
            if projected {
                #[cfg(unix)]
                {
                    if let Some(file_name) = bundle_path.file_name() {
                        let dir = open_projected_generation_dir(&data_link)?;
                        if let Ok(file) = open_at_nofollow(&dir, file_name) {
                            let raw =
                                read_open_file_bounded(file, &subject, TRUST_BUNDLE_MAX_BYTES)
                                    .and_then(|raw| decode_trust_utf8(raw, &subject))
                                    .map_err(|detail| {
                                        TrustBundleLoadError::new(
                                            TrustBundleRejectReason::DocumentUnreadable,
                                            detail,
                                        )
                                    })?;
                            return Ok(Self {
                                generation: PinnedSourceGeneration::Projected {
                                    dir,
                                    mount_dir: mount_dir.to_path_buf(),
                                },
                                document: raw,
                                origin: path.to_string(),
                            });
                        }
                        // The document is not an entry of this projection. Drop
                        // the pin entirely rather than claim a generation the
                        // document did not come from.
                    }
                }
                #[cfg(not(unix))]
                return Err(TrustBundleLoadError::new(
                    TrustBundleRejectReason::SourceGenerationUnsupported,
                    format!(
                        "{subject} is served from a projected '{PROJECTED_GENERATION_LINK}' \
                         generation, which this platform cannot pin. Ferrum refuses to fall back \
                         to re-resolving the live symlink per file, because that is exactly how a \
                         rotation can pair one generation's namespace policy with another \
                         generation's key material. Place the bundle on an ordinary filesystem \
                         and bind each referenced file with `material_sha256`, or inline public \
                         material with `public_key_pem`."
                    ),
                ));
            }
        }

        let document = read_regular_file_bytes_bounded(path, &subject, TRUST_BUNDLE_MAX_BYTES)
            .and_then(|raw| decode_trust_utf8(raw, &subject))
            .map_err(|detail| {
                TrustBundleLoadError::new(TrustBundleRejectReason::DocumentUnreadable, detail)
            })?;
        Ok(Self {
            generation: PinnedSourceGeneration::Unpinned,
            document,
            origin: path.to_string(),
        })
    }
}

#[cfg(unix)]
fn open_projected_generation_dir(data_link: &Path) -> Result<std::fs::File, TrustBundleLoadError> {
    use std::os::unix::fs::OpenOptionsExt;

    // Deliberately one `open(2)` on the symlink rather than readlink-then-open:
    // resolving the name first would leave a window in which `..data` moves
    // between the two syscalls.
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(data_link)
        .map_err(|e| {
            TrustBundleLoadError::new(
                TrustBundleRejectReason::SourceGenerationUnstable,
                format!("CP/DP trust bundle projected generation could not be pinned: {e}"),
            )
        })
}

/// Bound an operator-authored `kid` before it reaches a diagnostic.
///
/// Source resolution runs *before* the semantic `kid` length and control-character
/// checks, so a hostile document must not be able to smuggle an unbounded or
/// control-laden string into a startup error through this earlier phase.
fn diagnostic_kid(kid: &str) -> String {
    kid.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_KEY_ID_LEN)
        .collect()
}

/// Strictly parse a manifest-bound SHA-256: exactly 64 lowercase hex digits,
/// nothing else. No trimming, no uppercase, no `sha256:` prefix — an integrity
/// binding that quietly accepts near-misses is not one.
fn parse_material_sha256(raw: &str) -> Option<[u8; 32]> {
    let bytes = raw.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let high = lower_hex_value(bytes[index * 2])?;
        let low = lower_hex_value(bytes[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Some(out)
}

const fn lower_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Read one entry's material through the pinned generation, or `Ok(None)` when
/// the reference does not live in it.
#[cfg(unix)]
fn read_pinned_material(
    generation: &PinnedSourceGeneration,
    candidate: &Path,
    origin: &str,
    kid: &str,
    subject: &str,
) -> Result<Option<Vec<u8>>, TrustBundleLoadError> {
    let PinnedSourceGeneration::Projected { dir, mount_dir } = generation else {
        return Ok(None);
    };
    if candidate.parent() != Some(mount_dir.as_path()) {
        // A different directory is a different mount as far as this load is
        // concerned. It gets the external contract: bind it by digest.
        return Ok(None);
    }
    let Some(name) = candidate.file_name() else {
        return Err(TrustBundleLoadError::new(
            TrustBundleRejectReason::SourceGenerationEscape,
            format!(
                "CP/DP trust bundle '{origin}': key '{kid}' names no file inside the pinned \
                 projected generation"
            ),
        ));
    };
    let file = match open_at_nofollow(dir, name) {
        Ok(file) => file,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            use std::os::unix::fs::MetadataExt;

            // ENOENT has two materially different meanings. If kubelet
            // reclaimed the directory behind our pinned fd, the generation is
            // transiently unstable. If the pinned directory still exists, the
            // reference simply is not one of its entries: let it use the same
            // digest-bound external-file contract as a path in another
            // directory. This makes a typo fail permanently as unbound instead
            // of masquerading as a rotation race, and lets an explicit digest
            // bind a legitimate regular file beside the projected entries.
            let generation_reclaimed = dir
                .metadata()
                .map_or(true, |metadata| metadata.nlink() == 0);
            if !generation_reclaimed {
                return Ok(None);
            }
            return Err(TrustBundleLoadError::new(
                TrustBundleRejectReason::SourceGenerationUnstable,
                format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' could not be resolved inside the \
                     pinned projected generation: {e}"
                ),
            ));
        }
        Err(e) => {
            // Linux reports ELOOP for O_NOFOLLOW against a symlink; Darwin and
            // FreeBSD report EMLINK. Both are a deliberate in-generation escape
            // attempt, not a retryable projection race.
            let reason = if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::EMLINK)) {
                TrustBundleRejectReason::SourceGenerationEscape
            } else {
                TrustBundleRejectReason::SourceGenerationUnstable
            };
            return Err(TrustBundleLoadError::new(
                reason,
                format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' could not be resolved inside the \
                     pinned projected generation: {e}"
                ),
            ));
        }
    };
    read_open_file_bounded(file, subject, TRUST_MATERIAL_MAX_BYTES)
        .map(Some)
        .map_err(|detail| {
            TrustBundleLoadError::new(TrustBundleRejectReason::MaterialUnreadable, detail)
        })
}

/// Non-Unix hosts have no `openat`, so no generation is ever pinned and every
/// path-backed reference falls to the digest-bound contract.
#[cfg(not(unix))]
fn read_pinned_material(
    generation: &PinnedSourceGeneration,
    candidate: &Path,
    origin: &str,
    kid: &str,
    subject: &str,
) -> Result<Option<Vec<u8>>, TrustBundleLoadError> {
    let _ = (generation, candidate, origin, kid, subject);
    Ok(None)
}

/// Resolve one entry's path-backed material from the pinned generation, or from
/// an external path bound by `material_sha256`.
///
/// Returns `Ok(None)` for inline and environment-backed sources, which are read
/// atomically and keep their documented behavior.
fn resolve_entry_material(
    entry: &TrustBundleKeyDocument,
    origin: &str,
    generation: &PinnedSourceGeneration,
) -> Result<Option<Vec<u8>>, TrustBundleLoadError> {
    let kid = diagnostic_kid(&entry.kid);

    let source_count = [
        entry.secret.is_some(),
        entry.secret_env.is_some(),
        entry.secret_path.is_some(),
        entry.public_key_pem.is_some(),
        entry.public_key_path.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if source_count != 1 {
        return Err(TrustBundleLoadError::new(
            TrustBundleRejectReason::DocumentInvalid,
            format!(
                "CP/DP trust bundle '{origin}': key '{kid}' must declare exactly one of \
                 `secret`, `secret_env`, `secret_path`, `public_key_pem`, or \
                 `public_key_path` (found {source_count})"
            ),
        ));
    }

    let expected = match entry.material_sha256.as_deref() {
        Some(raw) => Some(parse_material_sha256(raw).ok_or_else(|| {
            TrustBundleLoadError::new(
                TrustBundleRejectReason::MaterialIntegrityMalformed,
                format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' declares a `material_sha256` \
                     that is not exactly 64 lowercase hexadecimal digits"
                ),
            )
        })?),
        None => None,
    };

    let path = match entry
        .secret_path
        .as_deref()
        .or(entry.public_key_path.as_deref())
    {
        Some(path) => path,
        None => {
            if expected.is_some() {
                return Err(TrustBundleLoadError::new(
                    TrustBundleRejectReason::DocumentInvalid,
                    format!(
                        "CP/DP trust bundle '{origin}': key '{kid}' declares `material_sha256` \
                         without `secret_path` or `public_key_path`. Inline and \
                         environment-backed material is read atomically with the document and \
                         carries no separate integrity binding."
                    ),
                ));
            }
            return Ok(None);
        }
    };

    let subject = format!(
        "CP/DP trust bundle '{origin}' key '{kid}' {} file",
        if entry.secret_path.is_some() {
            "secret"
        } else {
            "public key"
        }
    );

    let candidate = Path::new(path);
    if candidate
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        // A `..` component can climb out of the pinned generation between the
        // parent-directory comparison and the open, so it is refused outright
        // rather than normalized.
        return Err(TrustBundleLoadError::new(
            TrustBundleRejectReason::SourceGenerationEscape,
            format!(
                "CP/DP trust bundle '{origin}': key '{kid}' references material through a `..` \
                 path component"
            ),
        ));
    }

    let bytes = match read_pinned_material(generation, candidate, origin, &kid, &subject)? {
        Some(bytes) => bytes,
        None => {
            if expected.is_none() {
                return Err(TrustBundleLoadError::new(
                    TrustBundleRejectReason::MaterialIntegrityUnbound,
                    format!(
                        "CP/DP trust bundle '{origin}': key '{kid}' resolves material outside a \
                         pinned projected generation, so nothing proves the bytes read belong to \
                         the generation the document itself was read from — a rotation can pair \
                         one generation's namespace ceiling with another's key material. Declare \
                         this key's `material_sha256`, move the material into the same projected \
                         mount as the bundle document, or inline public material with \
                         `public_key_pem`."
                    ),
                ));
            }
            read_regular_file_bytes_bounded(path, &subject, TRUST_MATERIAL_MAX_BYTES).map_err(
                |detail| {
                    TrustBundleLoadError::new(TrustBundleRejectReason::MaterialUnreadable, detail)
                },
            )?
        }
    };

    if let Some(expected) = expected
        && Sha256::digest(&bytes) != expected
    {
        // Neither digest is rendered: a digest over a symmetric secret is an
        // offline verification oracle for that secret.
        return Err(TrustBundleLoadError::new(
            TrustBundleRejectReason::MaterialIntegrityMismatch,
            format!(
                "CP/DP trust bundle '{origin}': key '{kid}' material does not match the \
                 `material_sha256` the document binds it to"
            ),
        ));
    }

    Ok(Some(bytes))
}

/// One immutable trust-bundle load candidate.
///
/// The document exactly as it was read, plus every referenced source resolved
/// from one coherent filesystem generation. The whole value exists before a
/// single [`TrustedKey`] is constructed, so a candidate assembled from two
/// projected generations can never reach semantic construction — let alone
/// publication.
struct CoherentBundleSources {
    document: TrustBundleDocument,
    /// Parallel to `document.keys`; `None` for inline and environment-backed
    /// entries.
    materials: Vec<Option<Vec<u8>>>,
}

async fn load_trust_bundle_reload_candidate_detached(
    path: String,
    fleet_secret: Option<String>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<CpDpVerifier, TrustBundleReloadError> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let join_handle = std::thread::Builder::new()
        .name("ferrum-cp-trust-reload".to_string())
        .spawn(move || {
            // The permit belongs to the kernel operation. If the async caller
            // times out or shuts down, no replacement reader can start until
            // this detached read actually exits.
            let _permit = permit;
            // The same coherent-generation loader startup uses. A reload that
            // cannot prove one source generation is classified and dropped;
            // the active verifier is retained in full.
            let loaded = CpDpTrustBundle::load_coherent_from_path(&path, fleet_secret.as_deref());
            let candidate = loaded
                .map(CpDpVerifier::TrustBundle)
                .map_err(|e| TrustBundleReloadError::Rejected(e.reason()));
            let _ = sender.send(candidate);
        })
        .map_err(|_| TrustBundleReloadError::ReaderFailed)?;

    // Joining a reader stuck in the kernel would defeat both the timeout and
    // bounded shutdown. Dropping the handle deliberately detaches the thread.
    drop(join_handle);
    receiver
        .await
        .map_err(|_| TrustBundleReloadError::ReaderFailed)?
}

async fn load_trust_bundle_reload_candidate(
    path: String,
    fleet_secret: Option<String>,
) -> Result<CpDpVerifier, TrustBundleReloadError> {
    load_trust_bundle_reload_candidate_with_timeout(
        path,
        fleet_secret,
        TRUST_BUNDLE_RELOAD_READ_TIMEOUT,
    )
    .await
}

async fn load_trust_bundle_reload_candidate_with_timeout(
    path: String,
    fleet_secret: Option<String>,
    timeout: std::time::Duration,
) -> Result<CpDpVerifier, TrustBundleReloadError> {
    let read = async {
        let permit = trust_bundle_reload_read_limit()
            .acquire_owned()
            .await
            .map_err(|_| TrustBundleReloadError::ReaderUnavailable)?;
        load_trust_bundle_reload_candidate_detached(path, fleet_secret, permit).await
    };
    match tokio::time::timeout(timeout, read).await {
        Ok(result) => result,
        Err(_) => Err(TrustBundleReloadError::ReadTimedOut),
    }
}

#[doc(hidden)]
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub(crate) async fn load_trust_bundle_reload_candidate_for_test(
    path: String,
    timeout: std::time::Duration,
) -> Result<(), &'static str> {
    load_trust_bundle_reload_candidate_with_timeout(path, None, timeout)
        .await
        .map(|_| ())
        .map_err(|error| error.health_failure().as_str())
}

/// Upper bound on an operator-authored identifier (`kid`). Bounded so a
/// hostile-looking bundle cannot smuggle an unbounded string into startup
/// diagnostics.
const MAX_KEY_ID_LEN: usize = 128;

/// Minimum length for a symmetric (`HS*`) verification secret, matching the
/// admin-JWT convention elsewhere in the gateway.
const MIN_HS_SECRET_LEN: usize = 32;

/// The fleet-wide CP/DP secret. Backing a *bound* credential with this value
/// silently re-creates the advisory: every data plane already holds it, so any
/// of them could name that credential's `kid` and reach its namespaces. The
/// bundle would be structurally valid and semantically identical to the
/// pre-advisory posture, so loading refuses it outright.
const FLEET_SECRET_ENV: &str = "FERRUM_CP_DP_GRPC_JWT_SECRET";

/// Why a request-time tenant-authorization decision failed.
///
/// A closed, compile-time set used as a bounded metric/audit label. It is never
/// derived from caller-supplied bytes and never carries the token, a claim
/// value, a namespace, or any key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantAuthRejectReason {
    /// The JWS header could not be parsed at all.
    MalformedHeader,
    /// The CP runs a trust bundle but the token names no `kid`, so no
    /// verification credential can be selected deterministically.
    MissingKeyId,
    /// The token names a `kid` this control plane does not trust.
    UnknownKeyId,
    /// The token's `alg` is not the algorithm this credential is configured
    /// for. Refused before verification so a credential can never be used
    /// under an algorithm it was not provisioned for.
    AlgorithmMismatch,
    /// Signature or standard-claim validation failed after credential
    /// selection. Shares the outward message with [`Self::UnknownKeyId`] and
    /// [`Self::AlgorithmMismatch`] so callers cannot enumerate the trusted
    /// inventory from response text.
    TokenValidation,
    /// The bearer's credential, its `ns` claim, and any authenticated peer
    /// identity intersect to no namespace at all.
    NoAuthorizedNamespace,
}

impl TenantAuthRejectReason {
    /// Fixed-cardinality label for metrics and audit records.
    ///
    /// Kept available (and pinned by tests) even where no metric consumes it
    /// yet: the point of the closed set is that any future audit/metric sink
    /// has a bounded label to reach for instead of interpolating token data.
    #[allow(dead_code)]
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::MalformedHeader => "malformed_header",
            Self::MissingKeyId => "missing_key_id",
            Self::UnknownKeyId => "unknown_key_id",
            Self::AlgorithmMismatch => "algorithm_mismatch",
            Self::TokenValidation => "token_validation",
            Self::NoAuthorizedNamespace => "no_authorized_namespace",
        }
    }

    /// Operator-facing message. Deliberately fixed strings: the rejected token,
    /// its `kid`, its claims, and the trusted key inventory are all withheld so
    /// an unauthenticated caller cannot probe the CP's tenant configuration.
    ///
    /// Unknown-key, algorithm-mismatch, and signature/claims-validation
    /// failures share one outward string so response text cannot reveal whether
    /// selection reached a known credential. Missing `kid` stays actionable for
    /// trust-bundle migration.
    pub const fn as_status_message(self) -> &'static str {
        match self {
            Self::MalformedHeader => "Invalid token: malformed JWS header",
            Self::MissingKeyId => {
                "Invalid token: this control plane selects verification credentials by JWS \
                 `kid`, and the token carries none"
            }
            // Shared outward surface: must not distinguish unknown kid /
            // algorithm / signature-or-claims failure.
            Self::UnknownKeyId | Self::AlgorithmMismatch | Self::TokenValidation => {
                "Invalid token: authentication failed"
            }
            Self::NoAuthorizedNamespace => {
                "The presented credential is not authorized for any namespace on this control \
                 plane"
            }
        }
    }
}

/// Namespace scope derived from an authenticated mTLS peer certificate.
///
/// Populated only from a SPIFFE URI SAN of the Istio shape
/// `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`. A peer whose
/// certificate carries no SPIFFE namespace yields `None` — the connection is
/// still authenticated at the TLS layer, it simply contributes no namespace
/// evidence. This is the whole point of the advisory's "shared-CA certificate
/// validation alone is not namespace authorization" requirement: the value can
/// only ever *narrow* what a credential already permits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerNamespaceScope {
    namespaces: Arc<HashSet<String>>,
}

impl PeerNamespaceScope {
    /// Build a scope from a single namespace.
    pub fn single(namespace: impl Into<String>) -> Self {
        let mut set = HashSet::with_capacity(1);
        set.insert(namespace.into());
        Self {
            namespaces: Arc::new(set),
        }
    }

    pub fn namespaces(&self) -> &HashSet<String> {
        &self.namespaces
    }

    /// Derive the scope from a peer certificate chain, using the leaf.
    ///
    /// Returns `None` when there is no leaf, the leaf does not parse, it
    /// carries no SPIFFE URI SAN, or the SPIFFE path encodes no namespace.
    /// Every one of those is "no server-derived evidence", never "authorize
    /// everything".
    pub fn from_peer_cert_der(leaf_der: &[u8]) -> Option<Self> {
        let spiffe_id = crate::identity::spiffe::extract_spiffe_id_from_cert(leaf_der).ok()?;
        let namespace = spiffe_id.namespace()?;
        if namespace.is_empty() {
            return None;
        }
        Some(Self::single(namespace))
    }
}

/// Per-connection information the CP gRPC listener attaches to every request.
///
/// Replaces tonic's `TcpConnectInfo` so the mTLS peer's SPIFFE-derived
/// namespace scope — computed once at handshake completion, not per request —
/// travels with the connection. Requests arriving on a plaintext or
/// non-SPIFFE connection simply carry `peer_namespace_scope: None`.
#[derive(Clone, Debug, Default)]
pub struct CpGrpcConnectInfo {
    /// Preserved from tonic's `TcpConnectInfo`, which this type replaces, so
    /// swapping the connect-info type does not silently drop addresses a
    /// future handler or access log needs.
    #[allow(dead_code)]
    pub local_addr: Option<SocketAddr>,
    #[allow(dead_code)]
    pub remote_addr: Option<SocketAddr>,
    pub peer_namespace_scope: Option<PeerNamespaceScope>,
}

/// One trusted verification credential, bound to a namespace allow-list by
/// control-plane configuration.
pub struct TrustedKey {
    kid: String,
    algorithm: Algorithm,
    decoding_key: DecodingKey,
    /// Stable, process-internal identity of the accepted verification
    /// credential and namespace policy. This is derived from the configured
    /// key material and namespace ceiling but is never logged or exported. It
    /// lets an admitted stream survive an overlapping bundle rotation while
    /// closing if its exact credential or authorization policy is removed.
    identity: VerificationCredentialIdentity,
    /// Immutable namespace ceiling for every token this key verifies. Sourced
    /// exclusively from trusted CP configuration; a bearer can never change it.
    namespaces: HashSet<String>,
}

/// Opaque identity of one verification credential.
///
/// The digest is deliberately private and has no accessor or value-bearing
/// `Debug` implementation. It is used only for equality against later trusted
/// verifier snapshots; token bytes, claims, and key material are never retained
/// by an admitted stream.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VerificationCredentialIdentity([u8; 32]);

impl std::fmt::Debug for VerificationCredentialIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerificationCredentialIdentity(<opaque>)")
    }
}

fn credential_identity(
    kid: Option<&str>,
    algorithm: Algorithm,
    material: &[u8],
) -> VerificationCredentialIdentity {
    let mut hasher = Sha256::new();
    hasher.update(b"ferrum-cp-dp-verification-credential-v1\0");
    hasher.update(algorithm_identity_label(algorithm));
    hasher.update(b"\0");
    if let Some(kid) = kid {
        hasher.update(kid.as_bytes());
    }
    hasher.update(b"\0");
    hasher.update(material);
    VerificationCredentialIdentity(hasher.finalize())
}

/// Bind a verification credential to the trusted namespace policy that was
/// in force when it admitted a stream. Reloading the same key with an expanded
/// or reduced namespace ceiling must not leave an established stream using the
/// old authorization policy until its maximum lifetime happens to elapse.
fn namespace_bound_credential_identity(
    credential: VerificationCredentialIdentity,
    namespaces: &HashSet<String>,
) -> VerificationCredentialIdentity {
    let mut hasher = Sha256::new();
    hasher.update(b"ferrum-cp-dp-authorization-credential-v1\0");
    hasher.update(credential.0);
    let mut namespaces: Vec<&str> = namespaces.iter().map(String::as_str).collect();
    namespaces.sort_unstable();
    for namespace in namespaces {
        hasher.update(namespace.as_bytes());
        hasher.update(b"\0");
    }
    VerificationCredentialIdentity(hasher.finalize())
}

fn algorithm_identity_label(algorithm: Algorithm) -> &'static [u8] {
    match algorithm {
        Algorithm::HS256 => b"HS256",
        Algorithm::HS384 => b"HS384",
        Algorithm::HS512 => b"HS512",
        Algorithm::ES256 => b"ES256",
        Algorithm::ES384 => b"ES384",
        Algorithm::RS256 => b"RS256",
        Algorithm::RS384 => b"RS384",
        Algorithm::RS512 => b"RS512",
        Algorithm::PS256 => b"PS256",
        Algorithm::PS384 => b"PS384",
        Algorithm::PS512 => b"PS512",
        Algorithm::EdDSA => b"EdDSA",
    }
}

fn canonical_public_key_identity_material(pem: &[u8]) -> Vec<u8> {
    pem.iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect()
}

impl std::fmt::Debug for TrustedKey {
    /// Renders the operator-authored `kid` and algorithm only. The decoding key
    /// is credential material and is never formatted, even under `{:#?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedKey")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("namespace_count", &self.namespaces.len())
            .finish_non_exhaustive()
    }
}

/// The CP's trusted verification credentials, indexed by `kid`.
pub struct CpDpTrustBundle {
    keys: HashMap<String, TrustedKey>,
}

impl std::fmt::Debug for CpDpTrustBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CpDpTrustBundle")
            .field("key_count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl CpDpTrustBundle {
    /// Load and validate a trust bundle document from `path`.
    ///
    /// Every failure is fatal at startup: a control plane that cannot state
    /// which credential may reach which tenant must not serve multi-tenant
    /// configuration at all.
    ///
    /// `fleet_secret` is the effective `FERRUM_CP_DP_GRPC_JWT_SECRET`, when the
    /// operator configured one. It is used only to *refuse* a bound credential
    /// backed by that value; it is never rendered.
    pub fn load_from_path(path: &str, fleet_secret: Option<&str>) -> Result<Self, String> {
        Self::load_coherent_from_path(path, fleet_secret).map_err(|e| e.to_string())
    }

    /// [`Self::load_from_path`] with the closed [`TrustBundleRejectReason`]
    /// classification preserved.
    ///
    /// This is the one loader both CP startup and the periodic reload worker
    /// go through, so a mixed-generation candidate can become neither the
    /// initial authorization root nor a live replacement.
    pub fn load_coherent_from_path(
        path: &str,
        fleet_secret: Option<&str>,
    ) -> Result<Self, TrustBundleLoadError> {
        Self::from_pinned_source(PinnedTrustBundleSource::pin(path)?, fleet_secret)
    }

    /// Resolve every referenced source through an already-pinned generation and
    /// build the verifier.
    ///
    /// Separate from [`PinnedTrustBundleSource::pin`] so the coherence boundary
    /// is an explicit value rather than an implicit ordering: by the time this
    /// runs, the generation each reference will resolve against is already
    /// fixed, and no `..data` swap can change it.
    pub fn from_pinned_source(
        source: PinnedTrustBundleSource,
        fleet_secret: Option<&str>,
    ) -> Result<Self, TrustBundleLoadError> {
        let PinnedTrustBundleSource {
            generation,
            document,
            origin,
        } = source;
        let bundle =
            Self::from_document_with_generation(&document, &origin, fleet_secret, &generation);
        // The pinned descriptor is released only once every referenced source
        // has been resolved through it.
        drop(generation);
        bundle
    }

    /// Parse and validate a trust-bundle document. `origin` is used only in
    /// error text so an operator can tell which file failed. `fleet_secret` is
    /// the effective `FERRUM_CP_DP_GRPC_JWT_SECRET`, used only to refuse a
    /// credential backed by it.
    ///
    /// The document carries no pinned generation here, so every `secret_path` /
    /// `public_key_path` it names must be bound by `material_sha256`.
    #[allow(dead_code)] // Public library API exercised by the external integration-test crate.
    pub fn from_document_str(
        raw: &str,
        origin: &str,
        fleet_secret: Option<&str>,
    ) -> Result<Self, String> {
        Self::from_document_with_generation(
            raw,
            origin,
            fleet_secret,
            &PinnedSourceGeneration::Unpinned,
        )
        .map_err(|e| e.to_string())
    }

    fn from_document_with_generation(
        raw: &str,
        origin: &str,
        fleet_secret: Option<&str>,
        generation: &PinnedSourceGeneration,
    ) -> Result<Self, TrustBundleLoadError> {
        let invalid = |detail: String| {
            TrustBundleLoadError::new(TrustBundleRejectReason::DocumentInvalid, detail)
        };

        let document: TrustBundleDocument = serde_json::from_str(raw).map_err(|e| {
            invalid(format!(
                "CP/DP trust bundle '{origin}' is not valid JSON: {e}"
            ))
        })?;
        if let Some(version) = document.version
            && version != 1
        {
            return Err(invalid(format!(
                "CP/DP trust bundle '{origin}' declares unsupported version {version}; only \
                 version 1 is understood"
            )));
        }
        if document.keys.is_empty() {
            return Err(invalid(format!(
                "CP/DP trust bundle '{origin}' declares no keys; a control plane with no \
                 verification credential can authorize nothing"
            )));
        }

        // Phase one: resolve every referenced source from the pinned
        // generation. Nothing semantic is constructed until the whole immutable
        // candidate exists, so an incoherent bundle is refused before a single
        // `TrustedKey` comes into being.
        let mut materials = Vec::with_capacity(document.keys.len());
        let mut material_bytes = 0_u64;
        for entry in &document.keys {
            let material = resolve_entry_material(entry, origin, generation)?;
            if let Some(bytes) = material.as_ref() {
                material_bytes = material_bytes.saturating_add(bytes.len() as u64);
                if material_bytes > TRUST_MATERIAL_TOTAL_MAX_BYTES {
                    return Err(TrustBundleLoadError::new(
                        TrustBundleRejectReason::MaterialUnreadable,
                        format!(
                            "CP/DP trust bundle '{origin}' resolves more than \
                             {TRUST_MATERIAL_TOTAL_MAX_BYTES} bytes of path-backed key material \
                             in one candidate"
                        ),
                    ));
                }
            }
            materials.push(material);
        }
        let candidate = CoherentBundleSources {
            document,
            materials,
        };

        // Phase two: semantic construction, from the immutable candidate only.
        let mut keys: HashMap<String, TrustedKey> =
            HashMap::with_capacity(candidate.document.keys.len());
        let materials = candidate.materials;
        for (entry, material) in candidate.document.keys.into_iter().zip(materials) {
            let key = entry
                .into_trusted_key(origin, fleet_secret, material)
                .map_err(invalid)?;
            if keys.contains_key(&key.kid) {
                // Ambiguous key selection is a configuration error, not a
                // runtime tie-break: two credentials answering to one `kid`
                // would make which namespaces a token can reach depend on map
                // ordering.
                return Err(invalid(format!(
                    "CP/DP trust bundle '{origin}' declares duplicate kid '{}'; key selection \
                     must be unambiguous",
                    key.kid
                )));
            }
            keys.insert(key.kid.clone(), key);
        }

        Ok(Self { keys })
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    fn configuration_fingerprint(&self) -> [u8; 32] {
        let mut kids: Vec<&str> = self.keys.keys().map(String::as_str).collect();
        kids.sort_unstable();
        let mut hasher = Sha256::new();
        hasher.update(b"ferrum-cp-dp-trust-bundle-v1\0");
        for kid in kids {
            let key = &self.keys[kid];
            hasher.update(kid.as_bytes());
            hasher.update(b"\0");
            hasher.update(key.identity.0);
            let mut namespaces: Vec<&str> = key.namespaces.iter().map(String::as_str).collect();
            namespaces.sort_unstable();
            for namespace in namespaces {
                hasher.update(namespace.as_bytes());
                hasher.update(b"\0");
            }
            hasher.update(b"\xff");
        }
        hasher.finalize()
    }

    /// Every namespace any trusted credential may reach. Startup uses this to
    /// warn about served namespaces no credential can subscribe to.
    pub fn bound_namespaces(&self) -> HashSet<&str> {
        self.keys
            .values()
            .flat_map(|key| key.namespaces.iter().map(String::as_str))
            .collect()
    }

    /// Select the verification credential for a token header.
    ///
    /// `kid` is a **selector**, never an authorization input: naming another
    /// tenant's key without holding it fails the subsequent signature check.
    /// `alg` must equal the credential's configured algorithm, so a credential
    /// can never be exercised under an algorithm it was not provisioned for.
    pub fn select(
        &self,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<&TrustedKey, TenantAuthRejectReason> {
        let kid = kid
            .map(str::trim)
            .filter(|kid| !kid.is_empty())
            .ok_or(TenantAuthRejectReason::MissingKeyId)?;
        let key = self
            .keys
            .get(kid)
            .ok_or(TenantAuthRejectReason::UnknownKeyId)?;
        if key.algorithm != alg {
            return Err(TenantAuthRejectReason::AlgorithmMismatch);
        }
        Ok(key)
    }
}

/// How the control plane verifies inbound CP/DP gRPC tokens.
pub enum CpDpVerifier {
    /// Legacy fleet-wide HS256 secret (`FERRUM_CP_DP_GRPC_JWT_SECRET`).
    ///
    /// Provides **no** server-derived namespace binding: everyone who can
    /// present a token can also mint one. It stays supported only where it is
    /// security-equivalent — a genuinely single-namespace control plane, where
    /// there is no second tenant to cross into. Multi-namespace startup
    /// refuses it (see [`CpDpVerifier::validate_for_scope`]).
    SharedSecret(String),
    /// Namespace-bound verification credentials selected by JWS `kid`.
    TrustBundle(CpDpTrustBundle),
}

impl std::fmt::Debug for CpDpVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The secret is credential material and is never rendered.
            Self::SharedSecret(_) => f.write_str("CpDpVerifier::SharedSecret(<redacted>)"),
            Self::TrustBundle(bundle) => f
                .debug_tuple("CpDpVerifier::TrustBundle")
                .field(bundle)
                .finish(),
        }
    }
}

impl CpDpVerifier {
    /// Digest over every credential identity and namespace ceiling.
    ///
    /// This is **private on purpose**. It hashes key material (including an
    /// HS\* secret-derived identity), so anyone who can guess a candidate
    /// secret can recompute it offline; publishing it — or any deterministic
    /// unkeyed function of it, however domain-separated or truncated — would be
    /// a credential-verification oracle. It exists solely so the reload worker
    /// can tell a semantic change from a confirmation, and so the health
    /// module can HMAC it into a replica-stable identifier under a fleet-shared
    /// key that is never this fingerprint.
    pub(crate) fn configuration_fingerprint(&self) -> [u8; 32] {
        match self {
            Self::SharedSecret(secret) => {
                credential_identity(None, Algorithm::HS256, secret.as_bytes()).0
            }
            Self::TrustBundle(bundle) => bundle.configuration_fingerprint(),
        }
    }

    /// True when this verifier provides server-derived namespace binding.
    pub fn has_namespace_binding(&self) -> bool {
        matches!(self, Self::TrustBundle(_))
    }

    /// Fixed-cardinality description for startup logs. Never renders material.
    pub fn describe(&self) -> String {
        match self {
            Self::SharedSecret(_) => {
                "legacy fleet-wide FERRUM_CP_DP_GRPC_JWT_SECRET (no namespace binding)".to_string()
            }
            Self::TrustBundle(bundle) => format!(
                "namespace-bound trust bundle ({} verification credential(s))",
                bundle.key_count()
            ),
        }
    }

    /// Refuse a multi-namespace control plane whose only credential is the
    /// fleet-wide self-minting secret.
    ///
    /// This is the advisory's fail-closed startup requirement. A single
    /// namespace stays usable with the legacy secret because it is genuinely
    /// security-equivalent: there is no other tenant on this control plane for
    /// a forged `ns` claim to reach, and the CP scope check refuses anything
    /// else regardless.
    pub fn validate_for_scope(&self, multi_namespace: bool) -> Result<(), String> {
        if !multi_namespace || self.has_namespace_binding() {
            return Ok(());
        }
        Err(
            "Refusing to start a multi-namespace control plane with only the fleet-wide \
             FERRUM_CP_DP_GRPC_JWT_SECRET. That value is distributed to the very data planes and \
             mesh nodes it is used to authorize, so any tenant holding it can re-sign an `ns` \
             claim naming another tenant (advisory GHSA-3f2j-wwqw-grmg). Configure \
             FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH with per-tenant verification credentials — \
             preferably asymmetric public keys, so no signing authority exists on any data plane \
             — or run one single-namespace control plane per tenant."
                .to_string(),
        )
    }

    /// Resolve the credential for `kid`/`alg` and hand it to `f`.
    ///
    /// The closure form exists because the legacy shared-secret arm has to
    /// build its `DecodingKey` on the fly (the secret is stored as a `String`),
    /// so it cannot lend one out. Both arms therefore go through one seam and
    /// the caller never branches on the verifier shape.
    pub fn with_decoding_key<T>(
        &self,
        kid: Option<&str>,
        alg: Algorithm,
        f: impl FnOnce(
            &DecodingKey,
            Algorithm,
            Option<&HashSet<String>>,
            &VerificationCredentialIdentity,
        ) -> T,
    ) -> Result<T, TenantAuthRejectReason> {
        match self {
            Self::SharedSecret(secret) => {
                if alg != Algorithm::HS256 {
                    return Err(TenantAuthRejectReason::AlgorithmMismatch);
                }
                // Defense in depth. Startup refuses an empty
                // FERRUM_CP_DP_GRPC_JWT_SECRET when no trust bundle is
                // configured, and a bundle-configured CP replaces this arm
                // outright — but every server builder still *seeds* itself
                // with `SharedSecret(jwt_secret)`, and a trust-bundle CP
                // threads `cp_dp_grpc_jwt_secret.unwrap_or_default()` (i.e.
                // `""`) into those builders for token *minting*. A future
                // call site that forgot `.verifier_store(..)` would otherwise
                // verify against the empty HS256 key and accept anything.
                if secret.is_empty() {
                    return Err(TenantAuthRejectReason::TokenValidation);
                }
                let key = DecodingKey::from_secret(secret.as_bytes());
                let identity = credential_identity(None, Algorithm::HS256, secret.as_bytes());
                Ok(f(&key, Algorithm::HS256, None, &identity))
            }
            Self::TrustBundle(bundle) => {
                let key = bundle.select(kid, alg)?;
                Ok(f(
                    &key.decoding_key,
                    key.algorithm,
                    Some(&key.namespaces),
                    &key.identity,
                ))
            }
        }
    }

    fn credential_identities(&self) -> HashSet<VerificationCredentialIdentity> {
        match self {
            Self::SharedSecret(secret) if !secret.is_empty() => [credential_identity(
                None,
                Algorithm::HS256,
                secret.as_bytes(),
            )]
            .into_iter()
            .collect(),
            Self::SharedSecret(_) => HashSet::new(),
            Self::TrustBundle(bundle) => bundle
                .keys
                .values()
                .map(|key| key.identity.clone())
                .collect(),
        }
    }
}

/// One immutable verifier revision used for both token verification and
/// admission-time credential-generation binding.
///
/// The fields stay private so callers cannot inspect credential identities or
/// generations. Keeping the snapshot as the public load result prevents a
/// verifier from being detached from the generation map that was current when
/// it was captured.
pub struct CpDpVerifierSnapshot {
    verifier: Arc<CpDpVerifier>,
    credential_generations: HashMap<VerificationCredentialIdentity, u64>,
    revision: u64,
    store_identity: Arc<()>,
}

impl CpDpVerifierSnapshot {
    pub(crate) fn verifier(&self) -> &CpDpVerifier {
        self.verifier.as_ref()
    }

    pub(crate) fn credential_generation(
        &self,
        identity: &VerificationCredentialIdentity,
    ) -> Option<u64> {
        self.credential_generations.get(identity).copied()
    }
}

/// Atomically reloadable verifier shared by ConfigSync, MeshSubscribe, and
/// both ADS services.
///
/// Verification takes one immutable snapshot. Streams retain only the opaque
/// accepted credential identity plus its store generation and subscribe to the
/// revision counter. A reload wakes every stream, but only streams whose exact
/// credential generation vanished are revoked; adding an overlapping key does
/// not churn established streams, while remove-then-readd cannot resurrect an
/// old stream.
pub struct CpDpVerifierStore {
    active: ArcSwap<CpDpVerifierSnapshot>,
    revision: watch::Sender<u64>,
    replace_lock: Mutex<()>,
    store_identity: Arc<()>,
    /// Published reload health for the source this verifier is loaded from
    /// (#3813). Hanging it on the store — rather than threading it through
    /// every gRPC server builder — is what gives ConfigSync, both MeshSubscribe
    /// surfaces, and both ADS surfaces one shared stale-trust boundary: they
    /// all already hold this store. Stores built outside CP mode get the shared
    /// disabled status, which can never block admission.
    trust_status: Arc<CpDpTrustReloadStatus>,
}

impl std::fmt::Debug for CpDpVerifierStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let active = self.active.load();
        f.debug_struct("CpDpVerifierStore")
            .field("active", active.verifier.as_ref())
            .field(
                "active_credential_count",
                &active.credential_generations.len(),
            )
            .field("revision", &active.revision)
            .finish()
    }
}

impl CpDpVerifierStore {
    pub fn new(verifier: CpDpVerifier) -> Self {
        Self::from_arc(Arc::new(verifier))
    }

    pub fn from_arc(verifier: Arc<CpDpVerifier>) -> Self {
        let (revision, _) = watch::channel(0);
        let store_identity = Arc::new(());
        let credential_generations = verifier
            .credential_identities()
            .into_iter()
            .map(|identity| (identity, 0))
            .collect();
        Self {
            active: ArcSwap::from(Arc::new(CpDpVerifierSnapshot {
                verifier,
                credential_generations,
                revision: 0,
                store_identity: store_identity.clone(),
            })),
            revision,
            replace_lock: Mutex::new(()),
            store_identity,
            trust_status: crate::grpc::cp_trust_health::disabled_status(),
        }
    }

    /// Bind this store to the published trust-reload health for its source.
    ///
    /// CP mode calls this once with the installed status; every other builder
    /// keeps the shared disabled status, so no other mode gains a stale-trust
    /// admission gate it has no watcher to clear.
    pub fn with_trust_status(mut self, status: Arc<CpDpTrustReloadStatus>) -> Self {
        self.trust_status = status;
        self
    }

    /// The published trust-reload health this store's admission gates read.
    pub fn trust_status(&self) -> &Arc<CpDpTrustReloadStatus> {
        &self.trust_status
    }

    /// Capture the verifier and its credential generations as one immutable
    /// admission snapshot.
    pub fn load(&self) -> Arc<CpDpVerifierSnapshot> {
        self.active.load_full()
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revision.subscribe()
    }

    pub fn replace(&self, verifier: CpDpVerifier) {
        let _replace_guard = self.replace_lock.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.active.load();
        let revision = current.revision.saturating_add(1);
        let credential_generations = verifier
            .credential_identities()
            .into_iter()
            .map(|identity| {
                let generation = current
                    .credential_generations
                    .get(&identity)
                    .copied()
                    .unwrap_or(revision);
                (identity, generation)
            })
            .collect();
        let verifier = Arc::new(verifier);
        self.active.store(Arc::new(CpDpVerifierSnapshot {
            verifier,
            credential_generations,
            revision,
            store_identity: self.store_identity.clone(),
        }));
        self.revision.send_replace(revision);
    }

    pub fn credential_generation(&self, identity: &VerificationCredentialIdentity) -> Option<u64> {
        self.active.load().credential_generation(identity)
    }

    pub fn credential_is_active(
        &self,
        identity: &VerificationCredentialIdentity,
        generation: u64,
    ) -> bool {
        self.credential_generation(identity) == Some(generation)
    }

    pub(crate) fn active_generation_from_snapshot(
        &self,
        snapshot: &CpDpVerifierSnapshot,
        identity: &VerificationCredentialIdentity,
    ) -> Option<u64> {
        if !Arc::ptr_eq(&snapshot.store_identity, &self.store_identity) {
            return None;
        }
        let generation = snapshot.credential_generation(identity)?;
        self.credential_is_active(identity, generation)
            .then_some(generation)
    }
}

/// Watch a file-backed namespace trust bundle and atomically publish valid
/// replacements. Invalid or unreadable candidates never replace the last
/// accepted verifier. Semantic fingerprints include resolved referenced key
/// material, so quiet sources do not wake streams while a rotated key file is
/// still detected even when the bundle document itself is unchanged.
///
/// Every attempt, acceptance, and refusal is published to `status` (#3813), so
/// the retained-verifier policy is observable and bounded instead of being a
/// silent local boolean. The returned handle is a **supervisor**: it owns the
/// worker task and converts its disappearance — a panic, or any exit that was
/// not shutdown-signalled — into a visible failure. A clean shutdown is never
/// reported as one.
pub fn spawn_trust_bundle_reload(
    path: String,
    fleet_secret: Option<String>,
    verifier: Arc<CpDpVerifierStore>,
    multi_namespace: bool,
    interval: std::time::Duration,
    status: Arc<CpDpTrustReloadStatus>,
    shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let worker = tokio::spawn(trust_bundle_reload_worker(
        path,
        fleet_secret,
        verifier,
        multi_namespace,
        interval,
        Arc::clone(&status),
        shutdown,
    ));
    tokio::spawn(async move {
        // A panicking worker resolves the join handle with a `JoinError`, and a
        // worker that ever returns `false` left the loop without being asked
        // to. Both are the same operator-visible condition: nothing in this
        // process will publish a credential removal again.
        let clean = matches!(worker.await, Ok(true));
        status.record_worker_stopped(clean);
    })
}

/// Returns `true` when the loop ended because shutdown was signalled.
async fn trust_bundle_reload_worker(
    path: String,
    fleet_secret: Option<String>,
    verifier: Arc<CpDpVerifierStore>,
    multi_namespace: bool,
    interval: std::time::Duration,
    status: Arc<CpDpTrustReloadStatus>,
    mut shutdown: watch::Receiver<bool>,
) -> bool {
    let mut accepted_fingerprint = verifier.load().verifier().configuration_fingerprint();
    let mut ticker = tokio::time::interval(interval.max(std::time::Duration::from_secs(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return true;
                }
                continue;
            }
        }

        status.record_attempt();
        // Bundle parsing resolves file-backed key material. The detached
        // reader plus timeout keeps a stalled mount from pinning Tokio's
        // blocking pool or silently ending credential revocation. A
        // process-wide permit remains with any abandoned OS thread so a
        // persistent outage cannot accumulate blocked readers.
        let read = load_trust_bundle_reload_candidate(path.clone(), fleet_secret.clone());
        tokio::pin!(read);
        let candidate = match tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return true;
                }
                continue;
            }
            candidate = &mut read => candidate,
        } {
            Ok(candidate) => candidate,
            Err(error) => {
                status.record_rejected(error.health_failure());
                continue;
            }
        };
        if candidate.validate_for_scope(multi_namespace).is_err() {
            status.record_rejected(TrustReloadFailure::ScopeValidationFailed);
            continue;
        }
        // The fingerprint never leaves this loop in the clear: it is a change
        // detector, and the only external form is the keyed HMAC identifier
        // published on authenticated health (never logs, metrics, or errors).
        let fingerprint = candidate.configuration_fingerprint();
        let changed = accepted_fingerprint != fingerprint;
        if changed {
            verifier.replace(candidate);
            accepted_fingerprint = fingerprint;
            tracing::info!(
                audit.event = "cp_dp_trust_bundle_reloaded",
                "CP/DP trust bundle reloaded; streams whose accepted credential was removed are closing"
            );
        }
        // A semantically unchanged candidate is still an acceptance: the source
        // was read coherently and re-validated, which is exactly what the stale
        // bound asks about. Recording it is what lets an outage that ends
        // without any configuration change clear degraded state and count one
        // recovery. The same fingerprint yields the same keyed identifier.
        status.record_accepted(changed, &fingerprint);
    }
}

/// Intersect the credential's namespace ceiling with the bearer's `ns` claim
/// and any authenticated peer scope.
///
/// Order matters only for readability; intersection is commutative. What is
/// load-bearing is that **every** input can only remove namespaces:
///
/// - `bound` — CP configuration. The ceiling. `None` for the legacy shared
///   secret, which supplies no ceiling at all (single-namespace CPs only).
/// - `peer` — server-derived mTLS/SPIFFE evidence, when present.
/// - `claim` — the bearer's self-asserted `ns`. Narrows, never widens.
///
/// An empty result is an error, not an empty allow-set, so a mis-scoped
/// credential fails loudly at authentication instead of silently failing every
/// later namespace check.
pub fn resolve_authorized_namespaces(
    bound: Option<&HashSet<String>>,
    peer: Option<&PeerNamespaceScope>,
    claim: Option<&HashSet<String>>,
) -> Result<Option<HashSet<String>>, TenantAuthRejectReason> {
    let mut server_scope: Option<HashSet<String>> = bound.cloned();

    if let Some(peer) = peer {
        server_scope = Some(match server_scope {
            Some(scope) => scope
                .intersection(peer.namespaces())
                .cloned()
                .collect::<HashSet<String>>(),
            None => peer.namespaces().clone(),
        });
    }

    let Some(server_scope) = server_scope else {
        // Legacy shared secret with no peer identity: there is no
        // server-derived scope to intersect, so the claim carries through
        // unchanged. Reachable only on single-namespace control planes —
        // `CpDpVerifier::validate_for_scope` refuses this combination for
        // `Set`/`All` at startup.
        return Ok(claim.cloned());
    };

    let effective: HashSet<String> = match claim {
        Some(claim) => server_scope.intersection(claim).cloned().collect(),
        None => server_scope,
    };

    if effective.is_empty() {
        return Err(TenantAuthRejectReason::NoAuthorizedNamespace);
    }
    Ok(Some(effective))
}

// ── Trust-bundle document ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustBundleDocument {
    #[serde(default)]
    version: Option<u32>,
    keys: Vec<TrustBundleKeyDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustBundleKeyDocument {
    /// Selector matched against the JWS header `kid`.
    kid: String,
    /// JWS algorithm this credential verifies, e.g. `RS256`, `ES256`,
    /// `EdDSA`, or `HS256` for the symmetric migration path.
    algorithm: String,
    /// The immutable namespace allow-list for this credential.
    namespaces: Vec<String>,
    /// Symmetric secret, inline. Prefer `secret_env` or `secret_path`.
    #[serde(default)]
    secret: Option<String>,
    /// Name of an environment variable holding the symmetric secret.
    #[serde(default)]
    secret_env: Option<String>,
    /// Path to a file holding the symmetric secret.
    #[serde(default)]
    secret_path: Option<String>,
    /// PEM-encoded public key, inline. Public material, never a secret.
    #[serde(default)]
    public_key_pem: Option<String>,
    /// Path to a PEM-encoded public key.
    #[serde(default)]
    public_key_path: Option<String>,
    /// Lowercase hex SHA-256 of the exact bytes of this key's `secret_path` /
    /// `public_key_path` file, as `sha256sum` prints them.
    ///
    /// This is the manifest→material binding. Without it, a `secret_path` or
    /// `public_key_path` outside a pinned projected generation is just a name
    /// resolved at some later instant, and a rotation can hand back a different
    /// generation's bytes than the document was read from. Required whenever no
    /// generation could be pinned; verified in addition to the pin when both
    /// are present. Rejected on inline and environment-backed sources, which
    /// are read atomically and have nothing to bind.
    #[serde(default)]
    material_sha256: Option<String>,
}

/// Renders only operator-authored identifiers. The `secret` field carries raw
/// symmetric key material, so the derived `Debug` is deliberately not used —
/// this mirrors [`TrustedKey`]'s hand-written impl and keeps an accidental
/// `{:?}` in an error path from printing a tenant's signing secret.
impl std::fmt::Debug for TrustBundleKeyDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustBundleKeyDocument")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("namespaces", &self.namespaces)
            .field("secret", &"<redacted>")
            .field("secret_env", &self.secret_env)
            .field("secret_path", &self.secret_path)
            .field("public_key_pem", &self.public_key_pem)
            .field("public_key_path", &self.public_key_path)
            // A digest over a symmetric secret is an offline verification
            // oracle for that secret, so it is never rendered either.
            .field("material_sha256", &"<omitted>")
            .finish()
    }
}

/// Diagnostic for a bound credential backed by the fleet-wide secret.
///
/// Renders only operator-authored identifiers (`origin`, `kid`) and the
/// variable *name*; no key material of either credential is included.
fn fleet_secret_reuse_error(origin: &str, kid: &str) -> String {
    format!(
        "CP/DP trust bundle '{origin}': key '{kid}' is backed by the fleet-wide \
         {FLEET_SECRET_ENV}. Every data plane holds that value, so any of them could name this \
         `kid` and reach this credential's namespaces — the cross-tenant forgery advisory \
         GHSA-3f2j-wwqw-grmg exists to close. Give each credential its own material, or use an \
         asymmetric public key so no data plane can sign at all."
    )
}

impl TrustBundleKeyDocument {
    /// Build the credential. `material` is this entry's path-backed bytes, already
    /// resolved from one coherent source generation by
    /// [`resolve_entry_material`] — this function performs no filesystem access
    /// of its own, which is what keeps semantic construction strictly after the
    /// coherence proof.
    fn into_trusted_key(
        self,
        origin: &str,
        fleet_secret: Option<&str>,
        material: Option<Vec<u8>>,
    ) -> Result<TrustedKey, String> {
        let kid = self.kid.trim().to_string();
        if kid.is_empty() {
            return Err(format!(
                "CP/DP trust bundle '{origin}': every key requires a non-empty `kid`"
            ));
        }
        if kid.len() > MAX_KEY_ID_LEN {
            return Err(format!(
                "CP/DP trust bundle '{origin}': `kid` exceeds {MAX_KEY_ID_LEN} bytes"
            ));
        }
        if kid.chars().any(char::is_control) {
            return Err(format!(
                "CP/DP trust bundle '{origin}': `kid` must not contain control characters"
            ));
        }

        let algorithm: Algorithm = self.algorithm.trim().parse().map_err(|_| {
            format!(
                "CP/DP trust bundle '{origin}': key '{kid}' declares unsupported algorithm '{}'",
                self.algorithm.trim()
            )
        })?;
        if crate::fips::is_enforcing()
            && !crate::fips::policy::is_approved_jwt_algorithm(self.algorithm.as_str())
        {
            return Err(format!(
                "CP/DP trust bundle '{origin}': key '{kid}' declares a JWS algorithm outside \
                 Ferrum's approved set while FIPS mode is enforced"
            ));
        }

        let mut namespaces = HashSet::with_capacity(self.namespaces.len());
        for raw in &self.namespaces {
            let namespace = raw.trim();
            if namespace.is_empty() {
                return Err(format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' lists an empty namespace"
                ));
            }
            if namespace.chars().any(char::is_control) {
                return Err(format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' lists a namespace containing \
                     control characters"
                ));
            }
            namespaces.insert(namespace.to_string());
        }
        if namespaces.is_empty() {
            // A credential bound to nothing would authenticate and then
            // authorize nothing. That is almost certainly an operator mistake,
            // and accepting it silently would hide a broken tenant rollout.
            return Err(format!(
                "CP/DP trust bundle '{origin}': key '{kid}' must list at least one namespace"
            ));
        }

        let symmetric = matches!(
            algorithm,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        );
        let secret_sources = usize::from(self.secret.is_some())
            + usize::from(self.secret_env.is_some())
            + usize::from(self.secret_path.is_some());
        let public_sources = usize::from(self.public_key_pem.is_some())
            + usize::from(self.public_key_path.is_some());

        if secret_sources + public_sources != 1 {
            return Err(format!(
                "CP/DP trust bundle '{origin}': key '{kid}' must declare exactly one of \
                 `secret`, `secret_env`, `secret_path`, `public_key_pem`, or `public_key_path` \
                 (found {})",
                secret_sources + public_sources
            ));
        }
        if symmetric && public_sources == 1 {
            return Err(format!(
                "CP/DP trust bundle '{origin}': key '{kid}' declares symmetric algorithm \
                 '{algorithm:?}' with public-key material"
            ));
        }
        if !symmetric && secret_sources == 1 {
            return Err(format!(
                "CP/DP trust bundle '{origin}': key '{kid}' declares asymmetric algorithm \
                 '{algorithm:?}' with symmetric secret material"
            ));
        }

        let (decoding_key, identity) = if symmetric {
            let secret = if let Some(inline) = self.secret {
                inline
            } else if let Some(var) = self.secret_env.as_deref() {
                // Naming the fleet variable is refused by *name*, before the
                // read: it is unambiguous operator intent to bind a credential
                // to the value every data plane already holds, and the
                // by-value check below cannot see it when the effective
                // secret was configured through `ferrum.conf` instead.
                if var.trim() == FLEET_SECRET_ENV {
                    return Err(fleet_secret_reuse_error(origin, &kid));
                }
                std::env::var(var).map_err(|_| {
                    format!(
                        "CP/DP trust bundle '{origin}': key '{kid}' references environment \
                         variable '{var}', which is unset or not valid UTF-8"
                    )
                })?
            } else if self.secret_path.is_some() {
                let raw = material.ok_or_else(|| {
                    format!(
                        "CP/DP trust bundle '{origin}': key '{kid}' has no readable secret source"
                    )
                })?;
                decode_trust_utf8(
                    raw,
                    &format!("CP/DP trust bundle '{origin}' key '{kid}' secret file"),
                )?
                .trim()
                .to_string()
            } else {
                // Unreachable: the source-count check above admits exactly one.
                return Err(format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' has no readable secret source"
                ));
            };
            if secret.len() < MIN_HS_SECRET_LEN {
                // Length only — the value itself is never rendered.
                return Err(format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' symmetric secret must be at \
                     least {MIN_HS_SECRET_LEN} bytes"
                ));
            }
            // Whatever source it came from — inline, env, or file — a bound
            // credential must not carry the fleet-wide secret. Comparing the
            // resolved bytes is what makes `secret_path` (a symlink or copy of
            // the same material) detectable at all.
            if fleet_secret.is_some_and(|fleet| !fleet.is_empty() && fleet == secret.as_str()) {
                return Err(fleet_secret_reuse_error(origin, &kid));
            }
            (
                DecodingKey::from_secret(secret.as_bytes()),
                credential_identity(Some(&kid), algorithm, secret.as_bytes()),
            )
        } else {
            let pem = if let Some(inline) = self.public_key_pem {
                inline
            } else if self.public_key_path.is_some() {
                let raw = material.ok_or_else(|| {
                    format!(
                        "CP/DP trust bundle '{origin}': key '{kid}' has no readable public key \
                         source"
                    )
                })?;
                decode_trust_utf8(
                    raw,
                    &format!("CP/DP trust bundle '{origin}' key '{kid}' public key file"),
                )?
            } else {
                return Err(format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' has no readable public key source"
                ));
            };
            let bytes = pem.as_bytes();
            let parsed = match algorithm {
                Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512 => DecodingKey::from_rsa_pem(bytes),
                Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(bytes),
                Algorithm::EdDSA => DecodingKey::from_ed_pem(bytes),
                Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                    // Unreachable: `symmetric` covers these above.
                    return Err(format!(
                        "CP/DP trust bundle '{origin}': key '{kid}' algorithm/material mismatch"
                    ));
                }
            };
            let decoding_key = parsed.map_err(|e| {
                format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' public key is not valid PEM for \
                     '{algorithm:?}': {e}"
                )
            })?;
            let identity_material = canonical_public_key_identity_material(bytes);
            let identity = credential_identity(Some(&kid), algorithm, &identity_material);
            (decoding_key, identity)
        };

        let identity = namespace_bound_credential_identity(identity, &namespaces);

        Ok(TrustedKey {
            kid,
            algorithm,
            decoding_key,
            identity,
            namespaces,
        })
    }
}
