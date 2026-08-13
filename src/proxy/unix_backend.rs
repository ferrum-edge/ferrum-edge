//! Unix-domain-socket backend transport for Sidecar `ingress[]` listeners.
//!
//! Istio lets a `Sidecar` ingress entry point at a co-located Unix socket
//! (`defaultEndpoint: unix:///var/run/app.sock`). Ferrum models that as a
//! single-target upstream carrying the RESERVED [`MESH_UNIX_SOCKET_TAG`], which
//! the HTTP dispatch path recognizes and dials with
//! [`tokio::net::UnixStream`] instead of TCP.
//!
//! Four properties are load-bearing and must not be relaxed:
//!
//! 1. **The tag is a fail-closed transport marker, never a hint.** A target
//!    carrying it is dialed over a Unix stream or the request is REFUSED — the
//!    dispatch path never falls back to the target's placeholder `host:port`
//!    (which nothing listens on). This mirrors the `mesh.hbone` / `mesh.mtls`
//!    contract.
//! 2. **The path is re-admitted at dial time, and the CONNECTION is bound to the
//!    admitted identity.** The tag rides `UpstreamTarget.tags`, decoded from
//!    config that may have crossed the CP/DP, file, or xDS boundary, so the dial
//!    re-runs the full [`crate::util::unix_socket::admit_socket_for_connect`]
//!    gate — containment, symlink-resolved containment, the whole
//!    parent-to-root directory chain, socket file type, owner uid, and mode —
//!    rather than trusting the value that reached it. With no configured roots
//!    (the default) every tagged target is refused. Admission yields an
//!    [`crate::util::unix_socket::AdmittedUnixSocket`], and
//!    [`connect_admitted`] dials THAT canonical path and then proves, before
//!    writing a single request byte, that the connected peer's uid equals the
//!    checked socket owner's uid and that the path still names the checked
//!    inode. A socket swapped between check and connect is closed unused.
//! 3. **The wire protocol is carried, never inferred.**
//!    [`MESH_UNIX_SOCKET_H2C_TAG`] is resolved at translation from the
//!    listener's declared `port.protocol` and is always the canonical string
//!    `"true"` or `"false"`. A missing or malformed marker is refused, so a
//!    partially stripped carrier cannot silently downgrade h2c to HTTP/1.1.
//!    h2c carries native gRPC over the socket with full request/response
//!    streaming, deadlines, cancellation, and trailers, because it reuses the
//!    sidecar mesh-mTLS dispatch body (see [`dial_unix_h2c_sender`]).
//! 4. **Establishment is bounded, and it is the PEER's preface that ends it.**
//!    hyper's h2c `handshake()` writes the client connection preface and never
//!    reads, so it resolves against a peer that accepted the socket and then
//!    went silent. [`dial_unix_h2c_sender`] therefore waits for the peer's own
//!    initial `SETTINGS` frame (see `crate::proxy::h2c_preface`) and runs
//!    admission, connect, handshake, and that wait inside ONE end-to-end
//!    `backend_connect_timeout_ms` budget, so a wedged local app cannot pin a
//!    request task that the caller supplied no deadline for.
//!
//! Both tags live in the reserved `mesh.` namespace that
//! `strip_reserved_mesh_tags` removes from every operator/workload label copy,
//! so a hand-authored pod label can never forge them.

#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::AtomicBool;

use crate::config::types::UpstreamTarget;
#[cfg(unix)]
use crate::proxy::h2c_preface::{H2cPrefaceFailure, H2cPrefaceIo, await_peer_settings};
#[cfg(unix)]
use crate::util::unix_socket::AdmittedUnixSocket;
use crate::util::unix_socket::{UnixSocketPathRejection, admit_configured_path};

/// Reserved `UpstreamTarget.tags` key carrying the absolute path of the
/// Unix-domain stream socket this target's backend listens on.
pub const MESH_UNIX_SOCKET_TAG: &str = "mesh.unix_socket";

/// Reserved `UpstreamTarget.tags` key marking the socket's wire protocol as
/// **h2c prior-knowledge HTTP/2** rather than HTTP/1.1.
///
/// Value `"true"` for a listener whose declared `port.protocol` is `http2` /
/// `https` / `grpc`; value `"false"` for `http`. Resolved once at translation
/// from that declared protocol and never inferred at dispatch: an absent or
/// malformed tag is refused, so a stripped carrier cannot silently downgrade
/// h2c to HTTP/1.1.
pub const MESH_UNIX_SOCKET_H2C_TAG: &str = "mesh.unix_socket_h2c";

/// Fallback connect timeout when the proxy configures none (`0` = unset).
///
/// A Unix connect is a local, non-routed operation, so it either succeeds
/// immediately or fails with `ENOENT`/`ECONNREFUSED`; the only way it BLOCKS is
/// a full listen backlog on a wedged app. A bound is still required so such an
/// app cannot pin request tasks indefinitely.
pub const DEFAULT_UNIX_CONNECT_TIMEOUT_MS: u64 = 5_000;

/// Why a `mesh.unix_socket`-tagged target could not be dialed.
#[derive(Debug)]
pub enum UnixBackendError {
    /// The tagged path failed data-plane admission (syntax or configured
    /// containment). Fail-closed: a hostile or corrupted carrier never reaches
    /// `connect`; CP-side translation intentionally checks syntax only.
    InadmissiblePath(UnixSocketPathRejection),
    /// `UnixStream::connect` failed — socket missing, not a socket, permission
    /// denied, listen backlog full, or the peer is gone.
    Connect(std::io::Error),
    /// The connect did not complete within the effective timeout.
    ConnectTimeout { timeout_ms: u64 },
    /// The kernel would not report the connected peer's credentials, so the
    /// peer's identity is unknowable. Fail closed: an unverifiable peer is
    /// treated exactly like a mismatched one.
    PeerCredentialsUnavailable(std::io::Error),
    /// The connected peer's uid is not the uid that owned the socket admission
    /// checked. Either the socket was replaced between check and connect, or
    /// the object at that path was never the application's. Refused before any
    /// request byte is written.
    ///
    /// Note this is an EXACT-uid comparison against the checked owner, not
    /// membership in the configured `allowed_uids` allowlist: the allowlist
    /// decides which sockets may be admitted at all, while this decides that
    /// the connection reached the very socket that was admitted.
    PeerUidMismatch { expected: u32, actual: u32 },
    /// The admitted path no longer names the filesystem object admission
    /// checked (`(dev, ino)`, type, or owner changed), or that object could no
    /// longer be inspected. This is the check-to-connect swap, caught after the
    /// connect and before any request byte.
    SocketIdentityChanged,
    /// The HTTP/1.1 client handshake failed on an `http`-declared Unix listener
    /// after the admitted connect succeeded. Pre-wire: no request was issued.
    Http1Handshake(hyper::Error),
    /// The h2c prior-knowledge HTTP/2 client handshake failed on an
    /// `http2`/`grpc`-declared listener. The socket accepted the connection but
    /// the application does not speak h2c on it — a configuration mismatch, not
    /// a reason to silently retry as HTTP/1.1 (that would deliver a request the
    /// declared protocol says the app cannot parse).
    H2Handshake(hyper::Error),
    /// The h2c connection ended before it became usable: the peer closed it
    /// without ever completing its own HTTP/2 connection preface, or hyper
    /// ended it on the very poll that validated that preface. Either way no
    /// request could be issued on it and none was.
    H2ConnectionClosed,
    /// This ingress target already holds its configured maximum of
    /// concurrently open PHYSICAL connections
    /// (`FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS`) and this request would have
    /// required a new one (issue #3731).
    ///
    /// An INBOUND transport ceiling toward the co-located application, not an
    /// Istio `DestinationRule` — that is outbound client-side policy and does
    /// not govern this direction. The payload type is shared with the outbound
    /// limiter purely because "current versus cap" is the same shape.
    ///
    /// Decided BEFORE `connect(2)`, so no socket is opened and no application
    /// byte is written. Reuse of an already-admitted pooled carrier never
    /// reaches this refusal, so a target at its bound still serves every
    /// request that can ride an existing connection.
    BackendConnectionLimit(crate::backend_conn_limit::BackendConnectionLimitExceeded),
    /// The socket accepted the connection but the h2c connection did not become
    /// usable inside the effective connect budget — hyper's client handshake and
    /// the peer's own initial SETTINGS frame (RFC 9113 §3.4) must BOTH land
    /// inside it.
    ///
    /// The peer half is what this bound is for. `handshake()` only writes the
    /// CLIENT preface and never reads, so it completes against a socket whose
    /// peer is silent; without waiting for the peer's preface, an allowed local
    /// app that accepts and then wedges would pin the request task for as long
    /// as the caller's own deadline allows — which is forever when the client
    /// supplied no gRPC deadline and no backend read timeout is configured.
    H2HandshakeTimeout { timeout_ms: u64 },
    /// The RFC 6455 upgrade exchange timed out after the admitted Unix connect
    /// succeeded and `client_async_with_config` had already written and flushed
    /// the backend upgrade request (issue #3764).
    ///
    /// Post-wire by construction: the application may have received the upgrade.
    /// Must NOT be classified as [`Self::ConnectTimeout`] — that class is
    /// pre-wire / replay-safe under `retry_on_connect_failure`, and replaying
    /// an upgrade the peer may already have seen violates the same conservative
    /// reached-wire boundary used for direct tungstenite IO failures and
    /// non-101 handshake responses.
    WebSocketHandshakeTimeout { timeout_ms: u64 },
    /// The pool has been latched closed by graceful shutdown
    /// (`UnixBackendConnectionPool::shutdown_drain`), so this checkout may not
    /// establish or hand out a Unix backend connection (issue #3764).
    ///
    /// Two arrivals produce it, and both are fail-closed:
    ///
    /// * a checkout that STARTS after the latch — refused before the
    ///   establishment deadline, before path admission, and before `connect(2)`,
    ///   so no socket is opened and no slot on the target's bound is reserved;
    /// * a checkout that raced the latch and reached driver registration after
    ///   the tracker closed — the driver is never spawned, the un-polled driver
    ///   future is dropped (closing the socket just established), the target's
    ///   connection slot is released, and the sender is dropped rather than
    ///   returned, because nothing would drive its connection.
    ///
    /// Health-neutral by construction: the gateway is shutting down, which says
    /// nothing about the co-located application.
    PoolShuttingDown,
    /// The build target has no Unix-domain sockets (Windows). Sidecar mesh
    /// deployments are Linux-only, so this is unreachable in practice; it
    /// exists so the non-Unix build refuses the dispatch rather than silently
    /// dropping the transport gate.
    #[cfg_attr(unix, allow(dead_code))]
    PlatformUnsupported,
}

impl std::fmt::Display for UnixBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InadmissiblePath(rejection) => {
                write!(f, "unix backend path rejected: {}", rejection.reason())
            }
            Self::Connect(err) => write!(f, "unix backend connect failed: {err}"),
            Self::ConnectTimeout { timeout_ms } => {
                write!(f, "unix backend connect timed out after {timeout_ms}ms")
            }
            Self::PeerCredentialsUnavailable(err) => {
                write!(f, "unix backend peer credentials unavailable: {err}")
            }
            Self::PeerUidMismatch { expected, actual } => write!(
                f,
                "unix backend peer uid {actual} does not match the admitted socket owner uid \
                 {expected}"
            ),
            Self::SocketIdentityChanged => write!(
                f,
                "unix backend socket was replaced between admission and connect"
            ),
            Self::Http1Handshake(err) => {
                write!(f, "unix backend HTTP/1.1 handshake failed: {err}")
            }
            Self::H2Handshake(err) => {
                write!(f, "unix backend h2c handshake failed: {err}")
            }
            Self::H2ConnectionClosed => write!(
                f,
                "unix backend h2c connection closed before it became usable"
            ),
            Self::H2HandshakeTimeout { timeout_ms } => write!(
                f,
                "unix backend h2c handshake timed out after {timeout_ms}ms"
            ),
            Self::WebSocketHandshakeTimeout { timeout_ms } => write!(
                f,
                "unix backend websocket upgrade timed out after {timeout_ms}ms"
            ),
            Self::BackendConnectionLimit(limit) => {
                write!(f, "unix ingress connection bound reached: {limit}")
            }
            Self::PoolShuttingDown => write!(
                f,
                "unix backend pool is shutting down and cannot establish a connection"
            ),
            Self::PlatformUnsupported => {
                write!(f, "unix backends are not supported on this platform")
            }
        }
    }
}

impl std::error::Error for UnixBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(err) | Self::PeerCredentialsUnavailable(err) => Some(err),
            Self::Http1Handshake(err) | Self::H2Handshake(err) => Some(err),
            // Keep the typed over-cap marker reachable through the source chain
            // so `is_backend_connection_limit_error` recognizes it structurally
            // wherever this error is boxed.
            Self::BackendConnectionLimit(limit) => Some(limit),
            _ => None,
        }
    }
}

impl UnixBackendError {
    /// Retry/circuit-breaker classification.
    ///
    /// Most variants happen strictly BEFORE any application request byte is
    /// written, so `request_reached_wire` is false and a connect-failure replay
    /// is safe. The exception is [`Self::WebSocketHandshakeTimeout`]: the RFC
    /// 6455 upgrade request is flushed before the 101 wait, so a timeout there
    /// is post-wire and must not satisfy `retry_on_connect_failure`.
    ///
    /// Pre-wire variants differ in whether they are EVIDENCE about the backend:
    ///
    /// * an inadmissible path (or a platform with no Unix sockets) is a
    ///   terminal gateway-side policy decision — replaying it anywhere would
    ///   produce the same refusal, and the app is not implicated, so it is
    ///   `DispatchPolicyRejected` (health-neutral, not retried);
    /// * the three connected-peer refusals are also gateway-side policy: the
    ///   peer is not the admitted socket's owner, or its identity could not be
    ///   established. They are health-neutral on purpose — the legitimate
    ///   application must not be ejected because an attacker raced its socket —
    ///   and they are not retried, because a retry would repeat the dial into
    ///   the same substituted object;
    /// * a failed or timed-out connect — or an h2c connection that errored,
    ///   hung up, or never became usable inside the budget — IS evidence the
    ///   local app is down, wedged, or not speaking its declared protocol, so
    ///   those keep the ordinary connect-phase classes;
    /// * an over-bound refusal is the operator's own gateway-side ceiling on
    ///   this ingress target, decided before `connect(2)`. It gets the shared
    ///   typed [`crate::retry::ErrorClass::BackendConnectionLimit`] class every
    ///   other transport uses: pre-wire, health-neutral (no breaker,
    ///   passive-health, or LB penalty for a healthy application that is merely
    ///   at its configured transport capacity), and retryable onto another
    ///   load-balanced target with its own lane;
    /// * a shutdown refusal is likewise gateway-side and health-neutral, and it
    ///   is deliberately NOT retried: every Unix target in this process shares
    ///   the one latched pool, so a replay could only repeat the same refusal
    ///   while the process is trying to exit;
    /// * a WebSocket upgrade-response timeout is POST-wire
    ///   ([`crate::retry::ErrorClass::ReadWriteTimeout`]): the upgrade request
    ///   may already have reached the application, matching the conservative
    ///   boundary used for tungstenite IO and non-101 handshake responses.
    pub fn error_class(&self) -> crate::retry::ErrorClass {
        match self {
            Self::BackendConnectionLimit(_) => crate::retry::ErrorClass::BackendConnectionLimit,
            Self::InadmissiblePath(_)
            | Self::PoolShuttingDown
            | Self::PlatformUnsupported
            | Self::PeerCredentialsUnavailable(_)
            | Self::PeerUidMismatch { .. }
            | Self::SocketIdentityChanged => crate::retry::ErrorClass::DispatchPolicyRejected,
            Self::Connect(_) => crate::retry::ErrorClass::ConnectionRefused,
            Self::ConnectTimeout { .. } => crate::retry::ErrorClass::ConnectionTimeout,
            // Establishment completes before any request frame is written, so
            // these are PRE-wire and replay-safe, but they ARE evidence about
            // the app (it is not speaking the protocol its listener declared, or
            // it hung up before it could) — the same posture the pooled
            // transports give a failed connection setup.
            Self::Http1Handshake(_) | Self::H2Handshake(_) | Self::H2ConnectionClosed => {
                crate::retry::ErrorClass::ConnectionPoolError
            }
            Self::H2HandshakeTimeout { .. } => crate::retry::ErrorClass::ConnectionTimeout,
            // Upgrade request already flushed — reached-wire; not connect-retryable.
            Self::WebSocketHandshakeTimeout { .. } => crate::retry::ErrorClass::ReadWriteTimeout,
        }
    }
}

/// The admitted, CONTAINED Unix-socket path a target dials, or `None` when the
/// target is an ordinary TCP one.
///
/// Returns `Some(Err(..))` when the target IS tagged but its path fails
/// admission, so a caller can tell "not a Unix target" (fall through to the
/// ordinary path) apart from "a Unix target that must fail closed".
///
/// `allowed_roots` is the process's configured containment allowlist
/// (`FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS`); an EMPTY allowlist refuses every
/// tagged target, which is the default posture.
pub fn resolve_unix_socket_target<'a>(
    target: &'a UpstreamTarget,
    allowed_roots: &[String],
) -> Option<Result<&'a str, UnixSocketPathRejection>> {
    if !target_is_unix_backend(target) {
        return None;
    }
    if target.tags.keys().any(|key| {
        key.starts_with("mesh.") && key != MESH_UNIX_SOCKET_TAG && key != MESH_UNIX_SOCKET_H2C_TAG
    }) {
        return Some(Err(UnixSocketPathRejection::ConflictingTransportTags));
    }
    let Some(path) = target.tags.get(MESH_UNIX_SOCKET_TAG).map(String::as_str) else {
        return Some(Err(UnixSocketPathRejection::MissingSocketPathTag));
    };
    match target
        .tags
        .get(MESH_UNIX_SOCKET_H2C_TAG)
        .map(String::as_str)
    {
        Some("true" | "false") => {}
        Some(_) => return Some(Err(UnixSocketPathRejection::InvalidWireProtocolTag)),
        None => return Some(Err(UnixSocketPathRejection::MissingWireProtocolTag)),
    }
    Some(admit_configured_path(path, allowed_roots).map(|()| path))
}

/// Whether this target must be dispatched over a Unix stream, admissible or
/// not. A `true` here means the ordinary TCP path is FORBIDDEN for the target.
#[inline]
pub fn target_is_unix_backend(target: &UpstreamTarget) -> bool {
    target.tags.contains_key(MESH_UNIX_SOCKET_TAG)
        || target.tags.contains_key(MESH_UNIX_SOCKET_H2C_TAG)
}

/// Whether this Unix target speaks h2c prior-knowledge HTTP/2 (and therefore
/// carries gRPC natively) rather than HTTP/1.1.
///
/// Strict equality against `"true"`. Callers must first pass
/// [`resolve_unix_socket_target`], which rejects a missing, malformed, or
/// conflicting transport carrier; `"false"` is the only admitted HTTP/1.1
/// representation.
#[inline]
pub fn target_unix_backend_is_h2c(target: &UpstreamTarget) -> bool {
    target
        .tags
        .get(MESH_UNIX_SOCKET_H2C_TAG)
        .is_some_and(|value| value == "true")
}

/// Effective connect timeout for a Unix dial, in milliseconds.
#[inline]
pub fn effective_connect_timeout_ms(proxy_connect_timeout_ms: u64) -> u64 {
    if proxy_connect_timeout_ms == 0 {
        DEFAULT_UNIX_CONNECT_TIMEOUT_MS
    } else {
        proxy_connect_timeout_ms
    }
}

/// Defensive upper bound on ONE Unix establishment budget, in milliseconds.
///
/// Deliberately the same value config validation already enforces on every
/// operator-facing timeout field ([`crate::config::types::MAX_TIMEOUT_MS`], 24
/// hours), so no value an admitted configuration can produce is affected. It
/// exists because this dial is reached from config that may have crossed the
/// CP/DP, file, or xDS boundary: a `backend_connect_timeout_ms` that escaped
/// validation must fail closed here rather than become an establishment budget
/// no request would ever outlive. The check is not a substitute for the
/// representability check below — it is the bound that does not depend on how
/// wide the platform's `Instant` happens to be.
pub const MAX_UNIX_CONNECT_TIMEOUT_MS: u64 = crate::config::types::MAX_TIMEOUT_MS;

/// Absolute deadline for one Unix transport establishment budget.
///
/// An unreasonable duration — one past [`MAX_UNIX_CONNECT_TIMEOUT_MS`], or one
/// the platform clock cannot represent — must fail closed rather than silently
/// becoming an effectively unbounded wait. Returning the effective millisecond
/// value keeps the timeout response aligned with the default applied when the
/// proxy-level value is zero.
///
/// This is the ONE budget for a Unix transport establishment. It is created
/// once, at the OUTERMOST point of an establishment — before admission, before
/// any pool creation-lock wait, before `connect(2)`, before the protocol
/// handshake, and (for WebSocket) before the RFC 6455 upgrade exchange — and
/// then threaded through every stage as an absolute `Instant`. No stage may
/// derive a fresh budget from `connect_timeout_ms` again: two nested full
/// timeouts would let a single establishment consume twice the configured
/// setup budget (issue #3764).
///
/// A synchronous filesystem admission check cannot be preempted while it runs,
/// but the time it spends is charged against this deadline all the same,
/// because every later stage is awaited through `timeout_at(deadline, ..)` —
/// which resolves `Err` immediately when the deadline has already passed.
pub(crate) fn connect_deadline(
    proxy_connect_timeout_ms: u64,
) -> Result<(u64, tokio::time::Instant), UnixBackendError> {
    let timeout_ms = effective_connect_timeout_ms(proxy_connect_timeout_ms);
    // Fail closed BEFORE any clock arithmetic: a budget larger than the one
    // config validation admits is refused on every platform, whatever range
    // that platform's `Instant` supports.
    if timeout_ms > MAX_UNIX_CONNECT_TIMEOUT_MS {
        return Err(UnixBackendError::ConnectTimeout { timeout_ms });
    }
    let deadline = tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(timeout_ms))
        .ok_or(UnixBackendError::ConnectTimeout { timeout_ms })?;
    Ok((timeout_ms, deadline))
}

/// The connection-driver future of one physical Unix backend connection.
///
/// Returned to the caller rather than spawned internally so the pool can take
/// STRUCTURED OWNERSHIP of every driver it creates (issue #3764): a detached
/// `tokio::spawn` is unreachable at shutdown, and "the sender map was dropped"
/// is not the bounded close/await contract issue #3731 asks for. Boxed because
/// hyper's concrete `Connection` type is not nameable at this boundary; one
/// allocation per PHYSICAL connection, never per request.
#[cfg(unix)]
pub type UnixConnectionDriver =
    std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;

/// HTTP/2 client-connection bounds for an h2c Unix backend.
///
/// Fixed rather than operator-tunable: the peer is a co-located application on
/// the same host reached over a loopback-equivalent transport, so the windows
/// exist to BOUND memory, not to fill a bandwidth-delay product. Every buffer
/// on this transport is bounded by these values plus the request/response body
/// ceilings the caller already applies. Making them configurable is a
/// follow-up, not a correctness requirement.
#[cfg(unix)]
const UNIX_H2C_INITIAL_STREAM_WINDOW: u32 = 1024 * 1024;
#[cfg(unix)]
const UNIX_H2C_INITIAL_CONNECTION_WINDOW: u32 = 2 * 1024 * 1024;
#[cfg(unix)]
const UNIX_H2C_MAX_FRAME_SIZE: u32 = 16 * 1024;
/// Cap on concurrently reset streams the client tracks, so a misbehaving app
/// cannot grow that bookkeeping without bound.
#[cfg(unix)]
const UNIX_H2C_MAX_CONCURRENT_RESET_STREAMS: usize = 1024;

/// The uid of the process on the other end of a CONNECTED Unix stream.
///
/// This is the strong half of the TOCTOU contract: it describes the peer the
/// bytes would actually reach, not a pathname that may since have been
/// re-pointed.
///
/// Platform contract — the `cfg` list below is exactly the set of Unix targets
/// on which the kernel reports connected-peer credentials and tokio exposes
/// them through `UnixStream::peer_cred`:
///
/// * **Linux / Android** — `getsockopt(SOL_SOCKET, SO_PEERCRED)` yields a
///   `struct ucred` captured when the connection was established and never
///   updated afterwards. On the CONNECTING side that is the credential set of
///   the process that called `listen(2)`, which is exactly the fact needed
///   here: it names the peer that will read the request, and the peer cannot
///   change it after the fact by setuid-ing.
/// * **Apple / FreeBSD / DragonFly** — `getpeereid(3)`; **OpenBSD** —
///   `SO_PEERCRED`/`sockpeercred`; **NetBSD** — `LOCAL_PEERCRED`;
///   **illumos / Solaris** — `getpeerucred(3)`. All report the same connect-time
///   effective uid of the listening peer.
///
/// Any other Unix target has no equivalently strong guarantee, so it refuses
/// Unix backends outright (`PlatformUnsupported`) rather than weakening the
/// check Linux can actually enforce.
#[cfg(all(
    unix,
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    )
))]
fn connected_peer_uid(stream: &tokio::net::UnixStream) -> Result<u32, UnixBackendError> {
    stream
        .peer_cred()
        .map(|cred| cred.uid())
        .map_err(UnixBackendError::PeerCredentialsUnavailable)
}

/// Unix target without a connected-peer-credential mechanism: refuse rather
/// than dial with a weaker guarantee than Linux enforces. See the documented
/// platform contract on the supported variant of this function.
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    ))
))]
fn connected_peer_uid(stream: &tokio::net::UnixStream) -> Result<u32, UnixBackendError> {
    let _ = stream;
    Err(UnixBackendError::PlatformUnsupported)
}

/// Dial an already-admitted socket identity and prove the connection reached
/// THAT identity before any request byte is written.
///
/// The dial targets [`AdmittedUnixSocket::resolved_path`] — the canonical,
/// symlink-free path admission inspected — so the configured pathname is never
/// re-resolved and a symlink flipped after admission has nothing to redirect.
///
/// After `connect(2)` returns and before the caller may write anything:
///
/// 1. the connected peer's uid must equal the checked socket owner's uid
///    EXACTLY. Not "some uid in `allowed_uids`": the allowlist decides which
///    sockets may be admitted, this decides that the transport reached the one
///    that was;
/// 2. the checked path must still name the same `(dev, ino)`, file type, and
///    owner. Unlinking and re-binding a socket always yields a new inode, so a
///    swap performed inside the check-to-connect window is visible here even
///    when the replacement is owned by the same uid.
///
/// Either failure — and an unavailable credential, which is identity ambiguity
/// and therefore also a failure — drops the stream unused. There is no fallback
/// to TCP, to the placeholder `host:port`, or to a weaker check.
///
/// `deadline` / `timeout_ms` are the caller's ONE establishment budget (see
/// [`connect_deadline`]); this function never derives its own, so admission
/// time already spent is charged here rather than granted a second full
/// timeout.
#[cfg(unix)]
pub async fn connect_admitted(
    admitted: &AdmittedUnixSocket,
    deadline: tokio::time::Instant,
    timeout_ms: u64,
) -> Result<tokio::net::UnixStream, UnixBackendError> {
    let stream = match tokio::time::timeout_at(
        deadline,
        tokio::net::UnixStream::connect(admitted.resolved_path()),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(UnixBackendError::Connect(err)),
        Err(_) => return Err(UnixBackendError::ConnectTimeout { timeout_ms }),
    };

    let peer_uid = connected_peer_uid(&stream)?;
    if !admitted.peer_uid_matches(peer_uid) {
        return Err(UnixBackendError::PeerUidMismatch {
            expected: admitted.owner_uid(),
            actual: peer_uid,
        });
    }
    // Fail closed on identity ambiguity: an unreadable path is treated the same
    // as a changed one.
    if !admitted.still_names_checked_object().unwrap_or(false) {
        return Err(UnixBackendError::SocketIdentityChanged);
    }
    Ok(stream)
}

/// Admit `path` at the TOCTOU boundary and dial the resulting checked identity,
/// bounded by `connect_timeout_ms`.
///
/// This is the dial-time half of the containment contract:
/// the value reached this process over a CP/DP, file, or xDS boundary, and only
/// this data plane has the local containment policy and filesystem facts. It
/// checks containment, symlink-resolved containment, the full parent-to-root
/// directory chain, socket file type, owner uid, and mode — see
/// [`crate::util::unix_socket::admit_socket_for_connect`] — and hands
/// [`connect_admitted`] the identity to bind the connection to.
///
/// Returns the admitted identity alongside the connected stream so a pool can
/// key and re-verify the connection against the exact `(dev, ino, owner)` that
/// was checked.
#[cfg(unix)]
pub async fn admit_and_connect(
    path: &str,
    deadline: tokio::time::Instant,
    timeout_ms: u64,
    allowed_roots: &[String],
    allowed_uids: &[u32],
) -> Result<(AdmittedUnixSocket, tokio::net::UnixStream), UnixBackendError> {
    let admitted =
        crate::util::unix_socket::admit_socket_for_connect(path, allowed_roots, allowed_uids)
            .map_err(UnixBackendError::InadmissiblePath)?;
    let stream = connect_admitted(&admitted, deadline, timeout_ms).await?;
    Ok((admitted, stream))
}

/// Complete an h2c prior-knowledge HTTP/2 client handshake on an already
/// admitted + connected Unix stream, waiting for the peer's SETTINGS preface
/// inside `deadline`.
///
/// The Unix backend pool's cold path calls this after [`connect_admitted`] so
/// the pooled entry can retain the admitted `(dev, ino, owner)` identity; the
/// 1:1 [`dial_unix_h2c_sender`] helper composes admission + this handshake for
/// focused external tests.
///
/// Returns the driver as a [`UnixConnectionDriver`] instead of spawning it: the
/// caller owns it, so the pool can track, close, and reap every physical
/// connection under a bounded shutdown deadline (issue #3764).
#[cfg(unix)]
pub async fn handshake_unix_h2c_sender(
    stream: tokio::net::UnixStream,
    deadline: tokio::time::Instant,
    timeout_ms: u64,
) -> Result<
    (
        crate::proxy::mesh_mtls_pool::MeshMtlsSender,
        UnixConnectionDriver,
    ),
    UnixBackendError,
> {
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};

    let settings_received = Arc::new(AtomicBool::new(false));
    let io = TokioIo::new(H2cPrefaceIo::new(stream, Arc::clone(&settings_received)));

    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .initial_stream_window_size(UNIX_H2C_INITIAL_STREAM_WINDOW)
        .initial_connection_window_size(UNIX_H2C_INITIAL_CONNECTION_WINDOW)
        .max_frame_size(UNIX_H2C_MAX_FRAME_SIZE)
        .max_concurrent_reset_streams(UNIX_H2C_MAX_CONCURRENT_RESET_STREAMS);

    let handshake = builder.handshake(io);
    let handshake_result = match tokio::time::timeout_at(deadline, handshake).await {
        Ok(result) => result,
        Err(_) => return Err(UnixBackendError::H2HandshakeTimeout { timeout_ms }),
    };
    let (sender, mut connection) = handshake_result.map_err(UnixBackendError::H2Handshake)?;

    let establish = await_peer_settings(&mut connection, &settings_received);
    let established = match tokio::time::timeout_at(deadline, establish).await {
        Ok(result) => result,
        Err(_) => return Err(UnixBackendError::H2HandshakeTimeout { timeout_ms }),
    };
    if let Err(failure) = established {
        return Err(match failure {
            H2cPrefaceFailure::Connection(err) => UnixBackendError::H2Handshake(err),
            H2cPrefaceFailure::ClosedBeforeSettings | H2cPrefaceFailure::ClosedAfterSettings => {
                UnixBackendError::H2ConnectionClosed
            }
        });
    }

    let driver: UnixConnectionDriver = Box::pin(async move {
        if let Err(e) = connection.await {
            tracing::debug!("unix_backend: h2c connection closed: {}", e);
        }
    });
    Ok((sender, driver))
}

/// Dial a co-located Unix-domain STREAM socket and complete an **h2c
/// prior-knowledge HTTP/2** client handshake on it, returning a sender of the
/// same type the sidecar mesh-mTLS pool produces.
///
/// Sharing that sender type is deliberate: it lets the Unix h2c transport reuse
/// `proxy_to_backend_mesh_mtls`'s dispatch body verbatim, so request/response
/// streaming, gRPC deadlines and cancellation, `te: trailers` regeneration, and
/// terminal-trailer forwarding are the SAME code on both transports and cannot
/// drift apart.
///
/// Production dispatch uses the pooled carrier in
/// [`crate::proxy::unix_backend_pool`], whose cold path calls
/// [`admit_and_connect`] + [`handshake_unix_h2c_sender`] directly so it can
/// retain the admitted identity on the pooled entry. This 1:1 helper remains
/// the focused admission/handshake compatibility surface for external unit
/// tests that prove the connect-budget and SETTINGS-preface contracts without
/// constructing a pool.
#[cfg(unix)]
#[allow(dead_code)] // External unit tests call this; the binary/pool cold path uses the split primitives.
pub async fn dial_unix_h2c_sender(
    path: &str,
    connect_timeout_ms: u64,
    allowed_roots: &[String],
    allowed_uids: &[u32],
) -> Result<crate::proxy::mesh_mtls_pool::MeshMtlsSender, UnixBackendError> {
    let (timeout_ms, deadline) = connect_deadline(connect_timeout_ms)?;

    let connect = admit_and_connect(path, deadline, timeout_ms, allowed_roots, allowed_uids);
    let (_admitted, stream) = match tokio::time::timeout_at(deadline, connect).await {
        Ok(result) => result?,
        Err(_) => return Err(UnixBackendError::ConnectTimeout { timeout_ms }),
    };
    // Unpooled compatibility helper: nothing here owns a driver registry, so
    // the driver is tied to the returned sender's lifetime exactly as it was
    // before the pool existed. Production dispatch goes through the pool, which
    // takes structured ownership instead.
    let (sender, driver) = handshake_unix_h2c_sender(stream, deadline, timeout_ms).await?;
    tokio::spawn(driver);
    Ok(sender)
}

/// Non-Unix build: there is no Unix-domain socket to dial, so the shared
/// dispatch body refuses instead of losing the transport gate at compile time.
/// Sidecar mesh deployments are Linux-only, so this is unreachable in practice.
#[cfg(not(unix))]
pub async fn dial_unix_h2c_sender(
    _path: &str,
    _connect_timeout_ms: u64,
    _allowed_roots: &[String],
    _allowed_uids: &[u32],
) -> Result<crate::proxy::mesh_mtls_pool::MeshMtlsSender, UnixBackendError> {
    Err(UnixBackendError::PlatformUnsupported)
}
