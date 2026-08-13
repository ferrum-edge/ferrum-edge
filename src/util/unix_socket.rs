//! Admission rules for Unix-domain-socket backend paths.
//!
//! A `unix://` backend path arrives from operator-authored config (an Istio
//! `Sidecar` ingress `defaultEndpoint`) and, on the native/file/xDS carrier,
//! straight from untrusted wire JSON. It names a LOCAL filesystem object that
//! the Ferrum process — often the most privileged process in the pod — would
//! connect to. An unconstrained path is therefore a local privilege boundary:
//! `unix:///var/run/docker.sock` would hand every request-path client the
//! container runtime's API.
//!
//! Admission is a layered, fail-closed gate:
//!
//! 1. [`validate_unix_socket_path`] — pure syntax. Absolute, normalized,
//!    printable, and short enough for `sockaddr_un` on every supported
//!    platform. This is the portion a control plane can apply while translating
//!    an Istio resource.
//! 2. [`admit_configured_path`] — syntax PLUS **containment** inside an
//!    operator-configured allowlist of roots
//!    (`FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS`). The allowlist has **no
//!    default**: with none configured, every `unix://` endpoint is refused, so
//!    the feature is opt-in per deployment and there is no blanket `/run` or
//!    `/var/run` permission to inherit. This policy is data-plane-local: a
//!    control plane does not share the workload's configured roots.
//!
//! At DIAL time [`admit_socket_for_connect`] re-runs both stages and adds the
//! filesystem facts that only exist at connect, returning an explicit
//! [`AdmittedUnixSocket`] — the **checked identity**: the canonical path, the
//! owner uid, and the `(dev, ino)` of the exact object that was checked. The
//! caller dials *that* identity, never the operator-supplied pathname again.
//!
//! The dial-time facts are:
//!
//! * the path is `canonicalize`d (which fully resolves symlinks) and the
//!   RESOLVED path must itself be syntactically dialable and land inside an
//!   allowed root, so a symlink planted at an allowed location cannot redirect
//!   the dial to `/var/run/docker.sock`;
//! * the resolved object must be a Unix **socket**, owned by an admitted uid
//!   (default: the Ferrum process's own effective uid), and not group- or
//!   world-writable;
//! * **every directory from the socket's parent up to and including the matched
//!   containment root** must be a real directory (not a symlink, not any other
//!   file type), owned by a trusted uid, and not group/world-writable without
//!   the sticky bit. Checking only the immediate parent is not sufficient: a
//!   writable ancestor lets an attacker rename or replace an entire checked
//!   subtree, which substitutes the socket without ever touching the parent
//!   directory that was inspected.
//!
//! **Sticky bit and the directory-owner exception.** Sticky (`/tmp` semantics)
//! only stops a user from renaming or unlinking an entry they do **not** own;
//! the directory's owner and the entry's owner can still do so. Sticky is
//! therefore accepted as a mitigation *only because* the same walk independently
//! requires every directory in the chain to be owned by a trusted uid and
//! requires the socket entry itself to be owned by an admitted uid. Together
//! those three rules are what proves no untrusted directory owner and no
//! untrusted group member can rename or replace a checked descendant. Sticky
//! alone never admits anything.
//!
//! Above the matched containment root the walk stops: the root is the operator's
//! declared trust boundary, and whoever can rewrite it can also rewrite the
//! configuration that named it.
//!
//! **TOCTOU.** A filesystem check and the subsequent `connect(2)` cannot be made
//! atomic through the POSIX path API. This module closes the gap on the
//! *identity* side rather than pretending the window does not exist: the caller
//! dials the canonical path from the [`AdmittedUnixSocket`], then — before a
//! single request byte is written — asserts the connected peer's credentials
//! against [`AdmittedUnixSocket::owner_uid`] and re-asserts the path's
//! `(dev, ino)` with [`AdmittedUnixSocket::still_names_checked_object`]. A
//! socket swapped between check and connect fails one of those two assertions
//! and the connection is dropped unused. See
//! `crate::proxy::unix_backend::connect_admitted`.

/// Longest Unix-socket path Ferrum admits, in bytes (excluding the terminating
/// NUL the kernel adds).
///
/// `sockaddr_un.sun_path` is 108 bytes on Linux but only 104 on macOS/BSD, and
/// both reserve one byte for the NUL terminator. Ferrum uses the smaller
/// platform's usable budget everywhere so a config accepted on Linux cannot
/// become an un-dialable `EINVAL`/`ENAMETOOLONG` on another platform (and so a
/// path that passes admission on the control plane still dials on the data
/// plane).
pub const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;

/// Why a Unix-domain socket path is not usable as a backend endpoint.
///
/// Field-specific so callers can keep the operator's diagnostic precise (the
/// Istio status writer's `deferred_fields` report, the mesh listener resolution
/// warning) rather than collapsing every rejection into "unsupported".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixSocketPathRejection {
    /// The path was empty (or `unix://` with nothing after it).
    Empty,
    /// The path has leading or trailing whitespace — almost always a config
    /// typo, and silently trimming it would dial a different path than written.
    SurroundingWhitespace,
    /// The path is not absolute. Relative paths are resolved against the
    /// process CWD, which is not a stable, reviewable location; abstract
    /// (Linux `\0`-prefixed) and `@`-prefixed sockets land here too — Istio
    /// does not define them for `defaultEndpoint`.
    NotAbsolute,
    /// The path contains a `.` or `..` component. Never normalized silently:
    /// a traversal segment can escape the directory an operator reviewed.
    TraversalComponent,
    /// The path contains an empty component (`//`), which is legal to the
    /// kernel but ambiguous to review and to string-equality dedup.
    EmptyComponent,
    /// The path ends with `/`, so it names a directory, never a socket.
    TrailingSlash,
    /// The path contains an interior NUL, which would truncate `sun_path`.
    InteriorNul,
    /// The path contains an ASCII control character.
    ControlCharacter,
    /// The path does not fit `sockaddr_un.sun_path` on every supported
    /// platform (see [`MAX_UNIX_SOCKET_PATH_BYTES`]).
    TooLong,
    /// The secondary h2c marker was present without the primary socket-path
    /// marker. A partially stripped transport identity must fail closed rather
    /// than falling through to the target's placeholder TCP address.
    MissingSocketPathTag,
    /// The primary socket-path marker was present without the explicit wire
    /// protocol marker. Both halves are required so a carrier that loses the
    /// h2c selection cannot silently downgrade the backend to HTTP/1.1.
    MissingWireProtocolTag,
    /// The explicit wire-protocol marker was present but was not the canonical
    /// boolean string `"true"` or `"false"`. Refuse rather than guessing which
    /// protocol the application speaks.
    InvalidWireProtocolTag,
    /// A Unix transport marker was combined with another reserved `mesh.*`
    /// tag. Mesh transport identities are mutually exclusive; accepting a
    /// mixed carrier would let tag ordering choose a different security
    /// boundary than the materializer declared.
    ConflictingTransportTags,
    /// No containment roots are configured
    /// (`FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS` is unset or empty), so no Unix
    /// socket path is admissible. This is the DEFAULT: the feature is opt-in
    /// per deployment rather than shipping a blanket `/run` allowance.
    ContainmentNotConfigured,
    /// A configured containment root is itself unusable — not absolute, bare
    /// `/` (which would contain everything and defeat the gate), or
    /// traversal-like. Refused rather than skipped, so a typo cannot silently
    /// widen or narrow the allowlist.
    InvalidContainmentRoot,
    /// The path is syntactically fine but does not sit under any configured
    /// containment root.
    OutsideAllowedRoots,
    /// The path could not be resolved on this host (missing, or a component of
    /// it is not searchable). Also covers a resolved path that is not valid
    /// UTF-8, which Ferrum's string-typed config cannot represent.
    UnresolvablePath,
    /// The path resolves — through one or more symlinks, a bind mount, or a
    /// mount-namespace difference — to a location OUTSIDE every configured
    /// containment root. This is the escape the lexical check alone cannot
    /// see, and is exactly how `/allowed/app.sock → /var/run/docker.sock`
    /// would otherwise be reached.
    SymlinkEscape,
    /// The resolved object exists but is not a Unix-domain socket (a regular
    /// file, directory, FIFO, or device).
    NotASocket,
    /// The socket's owning uid is not admitted. With
    /// `FERRUM_MESH_UNIX_SOCKET_ALLOWED_UIDS` unset the only admitted owner is
    /// the Ferrum process's own effective uid, so a root-owned system socket
    /// in an allowed root is still refused for a non-root Ferrum.
    UnexpectedOwner,
    /// The socket is group- or world-writable (`g+w` / `o+w`), so a local user
    /// outside the trust boundary could connect to — or, with directory write
    /// access, replace — it.
    WorldWritableSocket,
    /// A directory between the socket and the containment root could not be
    /// inspected, is a symlink, or is not a directory at all. Refused because
    /// an uninspectable mutation path cannot be shown to be safe.
    UnsafeDirectoryComponent,
    /// A directory between the socket and the containment root (inclusive) is
    /// owned by a uid outside the trust boundary. That owner can rename or
    /// replace everything below it — including the checked socket — regardless
    /// of the directory's mode bits or sticky bit.
    UntrustedDirectoryOwner,
    /// A directory between the socket and the containment root (inclusive) is
    /// group- or world-writable WITHOUT the sticky bit, so a user outside the
    /// trust boundary can rename or unlink the checked descendant and bind
    /// their own object in its place. This is the precondition for winning the
    /// check-to-connect race, so it is refused rather than merely narrowed.
    UnsafeDirectoryPermissions,
    /// The build target has no Unix-domain sockets (Windows). Sidecar mesh
    /// deployments are Linux-only, so this is unreachable in practice; it
    /// exists so the non-Unix build refuses rather than silently admitting.
    PlatformUnsupported,
}

impl UnixSocketPathRejection {
    /// Stable, human-readable reason suitable for a status condition or log
    /// field. Never contains the path itself, so a caller decides whether the
    /// operator-supplied value is safe to echo back.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Empty => "unix socket path is empty",
            Self::SurroundingWhitespace => "unix socket path has leading or trailing whitespace",
            Self::NotAbsolute => "unix socket path is not absolute",
            Self::TraversalComponent => "unix socket path contains a '.' or '..' component",
            Self::EmptyComponent => "unix socket path contains an empty ('//') component",
            Self::TrailingSlash => "unix socket path ends with '/' (names a directory)",
            Self::InteriorNul => "unix socket path contains a NUL byte",
            Self::ControlCharacter => "unix socket path contains a control character",
            Self::TooLong => "unix socket path exceeds the portable sockaddr_un limit",
            Self::MissingSocketPathTag => {
                "unix socket h2c marker is missing its socket path marker"
            }
            Self::MissingWireProtocolTag => {
                "unix socket path marker is missing its wire protocol marker"
            }
            Self::InvalidWireProtocolTag => {
                "unix socket wire protocol marker is not 'true' or 'false'"
            }
            Self::ConflictingTransportTags => {
                "unix socket target carries conflicting reserved mesh transport tags"
            }
            Self::ContainmentNotConfigured => {
                "unix socket backends are disabled: FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS is unset"
            }
            Self::InvalidContainmentRoot => {
                "FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS contains an unusable root"
            }
            Self::OutsideAllowedRoots => {
                "unix socket path is outside every configured allowed root"
            }
            Self::UnresolvablePath => "unix socket path could not be resolved on this host",
            Self::SymlinkEscape => {
                "unix socket path resolves outside every configured allowed root"
            }
            Self::NotASocket => "unix socket path does not name a unix-domain socket",
            Self::UnexpectedOwner => "unix socket is not owned by an admitted uid",
            Self::WorldWritableSocket => "unix socket is group- or world-writable",
            Self::UnsafeDirectoryComponent => {
                "a directory between the unix socket and its containment root is not an \
                 inspectable directory"
            }
            Self::UntrustedDirectoryOwner => {
                "a directory between the unix socket and its containment root is owned by an \
                 untrusted uid"
            }
            Self::UnsafeDirectoryPermissions => {
                "a directory between the unix socket and its containment root is group- or \
                 world-writable without the sticky bit"
            }
            Self::PlatformUnsupported => "unix socket backends are unsupported on this platform",
        }
    }
}

/// Admit a Unix-domain socket path for use as a backend endpoint, or explain
/// exactly why it is refused.
///
/// Fail-closed by construction: every accepted path is absolute, free of `.` /
/// `..` / empty components, printable, NUL-free, does not name a directory, and
/// fits `sockaddr_un` on every supported platform. Nothing is normalized or
/// trimmed — the value dialed is byte-for-byte the value the operator wrote.
pub fn validate_unix_socket_path(path: &str) -> Result<(), UnixSocketPathRejection> {
    if path.is_empty() {
        return Err(UnixSocketPathRejection::Empty);
    }
    if path.trim() != path {
        return Err(UnixSocketPathRejection::SurroundingWhitespace);
    }
    if path.contains('\0') {
        return Err(UnixSocketPathRejection::InteriorNul);
    }
    if path.chars().any(char::is_control) {
        return Err(UnixSocketPathRejection::ControlCharacter);
    }
    if !path.starts_with('/') {
        return Err(UnixSocketPathRejection::NotAbsolute);
    }
    // Covers bare `/` too: it names the root directory, never a socket.
    if path.ends_with('/') {
        return Err(UnixSocketPathRejection::TrailingSlash);
    }
    // Skip the leading empty segment produced by the absolute-path `/`.
    for component in path.split('/').skip(1) {
        if component.is_empty() {
            return Err(UnixSocketPathRejection::EmptyComponent);
        }
        if component == "." || component == ".." {
            return Err(UnixSocketPathRejection::TraversalComponent);
        }
    }
    if path.len() > MAX_UNIX_SOCKET_PATH_BYTES {
        return Err(UnixSocketPathRejection::TooLong);
    }
    Ok(())
}

/// Normalize one configured containment root, or explain why it is unusable.
///
/// A root must be an absolute, normalized directory path. A bare `/` is
/// REFUSED: it would contain every path on the host and turn the allowlist into
/// a no-op. A single trailing `/` is tolerated and trimmed (operators write
/// both forms), but nothing else is repaired.
pub fn normalize_allowed_root(root: &str) -> Result<&str, UnixSocketPathRejection> {
    let trimmed = root.strip_suffix('/').unwrap_or(root);
    if trimmed.is_empty() || trimmed == "/" || !trimmed.starts_with('/') {
        return Err(UnixSocketPathRejection::InvalidContainmentRoot);
    }
    if trimmed.contains('\0') || trimmed.chars().any(char::is_control) || trimmed.trim() != trimmed
    {
        return Err(UnixSocketPathRejection::InvalidContainmentRoot);
    }
    for component in trimmed.split('/').skip(1) {
        if component.is_empty() || component == "." || component == ".." {
            return Err(UnixSocketPathRejection::InvalidContainmentRoot);
        }
    }
    Ok(trimmed)
}

/// Validate the operator's configured containment roots at STARTUP, returning
/// the offending entry so the process can refuse to start rather than silently
/// running with a narrower (or wider) allowlist than was written.
pub fn validate_allowed_roots(roots: &[String]) -> Result<(), String> {
    for (index, root) in roots.iter().enumerate() {
        if normalize_allowed_root(root).is_err() {
            return Err(format!(
                "FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS entry {} is not a usable containment root \
                 (must be an absolute, normalized directory path other than '/'); the value is \
                 withheld because filesystem paths are not log-safe",
                index + 1
            ));
        }
    }
    Ok(())
}

/// Whether `path` is a STRICT descendant of `root` (already normalized).
///
/// Compares whole path components — `/var/runner/app.sock` is NOT inside
/// `/var/run` — and requires at least one component below the root, so the root
/// directory itself can never be dialed.
fn path_is_within_root(path: &str, root: &str) -> bool {
    let Some(rest) = path.strip_prefix(root) else {
        return false;
    };
    matches!(rest.as_bytes().first(), Some(b'/')) && rest.len() > 1
}

/// The containment root `path` sits under, or why no configured root contains
/// it.
///
/// Returns the MATCHED root because the dial-time walk needs to know where to
/// stop climbing: the root is the operator's declared trust boundary.
fn contained_root<'a>(
    path: &str,
    allowed_roots: &'a [String],
) -> Result<&'a str, UnixSocketPathRejection> {
    if allowed_roots.is_empty() {
        return Err(UnixSocketPathRejection::ContainmentNotConfigured);
    }
    let mut matched: Option<&str> = None;
    for root in allowed_roots {
        // A malformed root is a hard error, never a skipped entry: skipping
        // would silently narrow the allowlist the operator reviewed. Every root
        // is normalized even after a match, so a typo anywhere in the list is
        // still a startup-visible error rather than order-dependent.
        let root = normalize_allowed_root(root)?;
        if matched.is_none() && path_is_within_root(path, root) {
            matched = Some(root);
        }
    }
    matched.ok_or(UnixSocketPathRejection::OutsideAllowedRoots)
}

/// Whether `path` sits under at least one configured containment root.
fn path_is_contained(path: &str, allowed_roots: &[String]) -> Result<(), UnixSocketPathRejection> {
    contained_root(path, allowed_roots).map(|_| ())
}

/// Admit an operator-configured `unix://` backend path: full syntax rules PLUS
/// containment inside `allowed_roots`.
///
/// This is the DATA-PLANE config gate used for materialization, dispatch, and
/// carrier re-validation. It performs no filesystem I/O; the filesystem facts
/// are checked at dial time by [`admit_socket_for_connect`]. CP-side Sidecar
/// resolution and status classification deliberately use
/// [`validate_unix_socket_path`] alone because a control plane neither shares
/// these configured roots nor knows the workload filesystem.
pub fn admit_configured_path(
    path: &str,
    allowed_roots: &[String],
) -> Result<(), UnixSocketPathRejection> {
    validate_unix_socket_path(path)?;
    path_is_contained(path, allowed_roots)
}

/// The identity of the socket that admission actually CHECKED.
///
/// This exists so the dial is tied to the checked object rather than to the
/// operator-supplied pathname. Re-resolving the configured path after admission
/// would re-open exactly the window admission is meant to close, so the caller
/// connects [`resolved_path`](Self::resolved_path), then proves the connection
/// reached this identity with [`owner_uid`](Self::owner_uid) (compared against
/// the connected peer's credentials) and
/// [`still_names_checked_object`](Self::still_names_checked_object).
///
/// Deliberately carries no `Display`: the resolved path is a filesystem
/// location derived from operator input and must never be logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedUnixSocket {
    resolved_path: std::path::PathBuf,
    owner_uid: u32,
    dev: u64,
    ino: u64,
}

impl AdmittedUnixSocket {
    /// Construct a checked identity inside the admission module only.
    ///
    /// Keeping this private makes the type itself enforce its contract: callers
    /// cannot fabricate an "admitted" identity that never passed the path,
    /// ownership, mode, and ancestor-chain checks above.
    fn new(resolved_path: std::path::PathBuf, owner_uid: u32, dev: u64, ino: u64) -> Self {
        Self {
            resolved_path,
            owner_uid,
            dev,
            ino,
        }
    }

    /// The canonical, symlink-free path that was checked. This is the path to
    /// dial; the configured pathname must not be re-resolved.
    pub fn resolved_path(&self) -> &std::path::Path {
        &self.resolved_path
    }

    /// The uid that owned the checked socket. The connected peer's credentials
    /// must equal this exact uid — not merely some uid in the configured
    /// allowlist — or the connection is refused unused.
    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// Device id of the checked socket object (`st_dev`). Part of the pool-key
    /// identity so a replaced socket at the same path cannot share a pooled
    /// connection admitted against a prior inode.
    pub fn device_id(&self) -> u64 {
        self.dev
    }

    /// Inode of the checked socket object (`st_ino`). See [`device_id`].
    pub fn inode(&self) -> u64 {
        self.ino
    }

    /// Whether a connected peer uid is exactly the checked socket owner.
    ///
    /// This predicate exposes the comparison for focused external regression
    /// coverage without exposing a constructor that could forge an admitted
    /// identity. Membership in the configured uid allowlist is deliberately
    /// insufficient here: the connection must reach the owner of this socket.
    pub fn peer_uid_matches(&self, peer_uid: u32) -> bool {
        peer_uid == self.owner_uid
    }

    /// Whether the checked path STILL names the same filesystem object.
    ///
    /// `(dev, ino)` is the strongest identity POSIX exposes through a pathname:
    /// unlinking and re-binding a socket at the same path always yields a new
    /// inode, so a swap performed between admission and connect is visible here
    /// even when the replacement has the same owner and mode. `Err` means the
    /// object could not be re-inspected at all, which is treated as failure by
    /// the caller (fail closed on identity ambiguity).
    #[cfg(unix)]
    pub fn still_names_checked_object(&self) -> Result<bool, UnixSocketPathRejection> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        let metadata = std::fs::symlink_metadata(&self.resolved_path)
            .map_err(|_| UnixSocketPathRejection::UnresolvablePath)?;
        Ok(metadata.file_type().is_socket()
            && metadata.dev() == self.dev
            && metadata.ino() == self.ino
            && metadata.uid() == self.owner_uid)
    }
}

/// The uids trusted to OWN a directory on the mutation path to an admitted
/// socket.
///
/// Always `uid 0` (root can rewrite any check this module performs, so treating
/// it as untrusted would only produce false refusals) and the Ferrum process's
/// own effective uid, plus every configured `allowed_uids` entry — those name
/// the co-located application, which is the intended peer and is therefore
/// inside the trust boundary by construction. Least privilege: nothing else is
/// trusted, so a directory owned by an arbitrary local user refuses the dial.
#[cfg(unix)]
fn trusted_directory_uids(allowed_uids: &[u32]) -> Vec<u32> {
    // SAFETY: `geteuid` reads the calling process's effective uid. It takes no
    // arguments, touches no memory, and is documented never to fail.
    let euid = unsafe { libc::geteuid() };
    let mut trusted = Vec::with_capacity(allowed_uids.len() + 2);
    trusted.push(0);
    trusted.push(euid);
    for uid in allowed_uids {
        if !trusted.contains(uid) {
            trusted.push(*uid);
        }
    }
    trusted
}

/// The metadata facts about one directory on the mutation path that the
/// admission policy consumes.
///
/// Extracted as a plain value so the policy below is a pure function of the
/// facts: the filesystem walk supplies them, and adversarial tests can supply
/// ownership/permission combinations that cannot be created without root.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryFacts {
    /// Owning uid of the directory.
    pub uid: u32,
    /// Permission and mode bits, including the sticky bit (`0o1000`).
    pub mode: u32,
    /// Whether the entry is a directory.
    pub is_dir: bool,
    /// Whether the entry is a symbolic link.
    pub is_symlink: bool,
}

/// Whether one directory on the mutation path to an admitted socket is safe.
///
/// A directory is safe when all three hold:
///
/// 1. it really is a directory and not a symlink (a symlink would move the
///    whole subtree somewhere the containment check never saw);
/// 2. its owner is inside the trust boundary — an untrusted owner can rename or
///    replace every descendant, and can also `chmod` the sticky bit away, so no
///    mode-bit combination rescues it;
/// 3. it is not group- or world-writable, OR it is sticky. Sticky is accepted
///    only in combination with (2) and with the socket's own owner check: it
///    prevents a non-owner from renaming or unlinking an entry, and every entry
///    on the checked chain is trusted-owned, so no untrusted group member or
///    other local user can substitute a checked descendant.
#[cfg(unix)]
pub fn admit_directory_facts(
    facts: &DirectoryFacts,
    trusted_uids: &[u32],
) -> Result<(), UnixSocketPathRejection> {
    if facts.is_symlink || !facts.is_dir {
        return Err(UnixSocketPathRejection::UnsafeDirectoryComponent);
    }
    if !trusted_uids.contains(&facts.uid) {
        return Err(UnixSocketPathRejection::UntrustedDirectoryOwner);
    }
    let group_or_world_writable = facts.mode & 0o022 != 0;
    let sticky = facts.mode & 0o1000 != 0;
    if group_or_world_writable && !sticky {
        return Err(UnixSocketPathRejection::UnsafeDirectoryPermissions);
    }
    Ok(())
}

/// Walk every directory from `parent` up to and including `root`, refusing the
/// first one that is not a safe mutation path.
///
/// Inclusive of the root: the root is where the operator's trust boundary
/// begins, so it must itself be trusted-owned and non-writable. Climbing above
/// it is deliberately not attempted — whoever can rewrite the root can also
/// rewrite the configuration naming it.
#[cfg(unix)]
fn admit_directory_chain(
    parent: &std::path::Path,
    root: &std::path::Path,
    trusted_uids: &[u32],
) -> Result<(), UnixSocketPathRejection> {
    use std::os::unix::fs::MetadataExt;

    let mut current = parent;
    loop {
        let metadata = std::fs::symlink_metadata(current)
            .map_err(|_| UnixSocketPathRejection::UnsafeDirectoryComponent)?;
        let file_type = metadata.file_type();
        admit_directory_facts(
            &DirectoryFacts {
                uid: metadata.uid(),
                mode: metadata.mode(),
                is_dir: file_type.is_dir(),
                is_symlink: file_type.is_symlink(),
            },
            trusted_uids,
        )?;
        if current == root {
            return Ok(());
        }
        // The socket is a strict descendant of a normalized, absolute root, so
        // this terminates at the root above. A `None` parent means the walk left
        // the tree it was supposed to be inside — fail closed rather than loop.
        current = current
            .parent()
            .ok_or(UnixSocketPathRejection::UnsafeDirectoryComponent)?;
    }
}

/// Re-admit a `unix://` backend path at DIAL time, adding the filesystem facts
/// that only exist at connect, and return the CHECKED IDENTITY to dial.
///
/// Runs the full [`admit_configured_path`] gate again (the value may have
/// crossed a CP/DP or file boundary since syntax-only translation), then:
///
/// * `canonicalize`s the path — which fully resolves symlinks, `..`, and mount
///   points — and requires the RESOLVED path to be syntactically dialable in
///   its own right and to land inside an allowed root. This is the check that
///   stops an attacker-controlled symlink inside an allowed directory from
///   redirecting the dial to a privileged socket such as `/var/run/docker.sock`;
/// * requires the resolved object to be a Unix-domain SOCKET;
/// * requires its owner uid to be admitted — `allowed_uids` when non-empty,
///   otherwise the Ferrum process's own effective uid, so a root-owned system
///   socket that happens to sit in an allowed root is still refused for a
///   non-root Ferrum;
/// * refuses a group- or world-writable socket;
/// * walks EVERY directory from the socket's parent up to and including the
///   matched containment root through [`admit_directory_facts`], so a writable
///   or untrusted-owned ancestor cannot rename a whole checked subtree out from
///   under the dial.
///
/// The returned [`AdmittedUnixSocket`] is what the caller dials and then proves
/// it reached; see the module docs for the full TOCTOU contract.
#[cfg(unix)]
pub fn admit_socket_for_connect(
    path: &str,
    allowed_roots: &[String],
    allowed_uids: &[u32],
) -> Result<AdmittedUnixSocket, UnixSocketPathRejection> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    admit_configured_path(path, allowed_roots)?;

    let resolved =
        std::fs::canonicalize(path).map_err(|_| UnixSocketPathRejection::UnresolvablePath)?;
    let resolved_str = resolved
        .to_str()
        .ok_or(UnixSocketPathRejection::UnresolvablePath)?;
    // The resolved path is the one that will be dialed, so it must satisfy the
    // syntax budget itself — resolution can lengthen a path past `sun_path`.
    validate_unix_socket_path(resolved_str)?;
    // `canonicalize` yields an absolute, symlink-free, `..`-free path, so
    // containment on it is the post-resolution half of the gate. A path that
    // was lexically contained but resolves elsewhere is an ESCAPE, reported
    // distinctly from a plainly out-of-root path.
    let root = match contained_root(resolved_str, allowed_roots) {
        Ok(root) => root,
        Err(UnixSocketPathRejection::OutsideAllowedRoots) => {
            return Err(UnixSocketPathRejection::SymlinkEscape);
        }
        Err(other) => return Err(other),
    };

    // `symlink_metadata` on an already-canonical path cannot traverse a further
    // symlink, so the facts below describe the object the dial will reach.
    let metadata = std::fs::symlink_metadata(&resolved)
        .map_err(|_| UnixSocketPathRejection::UnresolvablePath)?;
    if !metadata.file_type().is_socket() {
        return Err(UnixSocketPathRejection::NotASocket);
    }
    let owner_admitted = if allowed_uids.is_empty() {
        // SAFETY: `geteuid` reads the calling process's effective uid. It takes
        // no arguments, touches no memory, and is documented never to fail.
        metadata.uid() == unsafe { libc::geteuid() }
    } else {
        allowed_uids.contains(&metadata.uid())
    };
    if !owner_admitted {
        return Err(UnixSocketPathRejection::UnexpectedOwner);
    }
    // Group-writable matters as much as world-writable: the group of a shared
    // socket directory is exactly the kind of boundary a co-tenant crosses.
    if metadata.mode() & 0o022 != 0 {
        return Err(UnixSocketPathRejection::WorldWritableSocket);
    }

    let parent = resolved
        .parent()
        .ok_or(UnixSocketPathRejection::UnsafeDirectoryComponent)?;
    admit_directory_chain(
        parent,
        std::path::Path::new(root),
        &trusted_directory_uids(allowed_uids),
    )?;

    Ok(AdmittedUnixSocket::new(
        resolved,
        metadata.uid(),
        metadata.dev(),
        metadata.ino(),
    ))
}

/// Non-Unix build: there is no Unix-domain socket to admit, so the dial-time
/// gate refuses rather than degrading to the lexical checks alone.
#[cfg(not(unix))]
pub fn admit_socket_for_connect(
    _path: &str,
    _allowed_roots: &[String],
    _allowed_uids: &[u32],
) -> Result<AdmittedUnixSocket, UnixSocketPathRejection> {
    Err(UnixSocketPathRejection::PlatformUnsupported)
}
