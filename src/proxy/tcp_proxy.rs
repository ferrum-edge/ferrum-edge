//! Raw TCP stream proxy with optional TLS termination (frontend) and origination (backend).
//!
//! Each TCP proxy binds its own dedicated port. Incoming connections are
//! forwarded bidirectionally to the configured backend using the fastest
//! relay path available for the configured protocol and timeout policy.

use std::cell::RefCell;
use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
#[cfg(target_os = "linux")]
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};

use crate::backend_conn_limit::{
    BackendConnectionGuard, BackendConnectionLimitExceeded, BackendConnectionLimiter,
};
use crate::circuit_breaker::CircuitBreakerCache;
use crate::tls::TlsPolicy;
use crate::tls::backend::BackendTlsConfigBuilder;

use crate::config::types::{BackendScheme, GatewayConfig, Proxy};
use crate::consumer_index::ConsumerIndex;
use crate::dns::DnsCache;
use crate::health_check::HealthChecker;
use crate::load_balancer::{LoadBalancerCache, LoadBalancerCacheInner};
use crate::modes::mesh::outbound_enforcement::{
    Decision, MeshOutboundEnforcement, PROTOCOL_TCP, PROTOCOL_TCP_TLS,
};
use crate::plugins::{
    Direction, Plugin, PluginResult, ProxyProtocol, StreamBytesKind, StreamConnectionContext,
    StreamTransactionSummary,
};
use crate::proxy::stream_error::{StreamSetupError, StreamSetupKind, find_stream_setup_error};
use crate::request_epoch::{RequestEpoch, RequestEpochStore};
use crate::retry::ErrorClass;

pub(crate) fn classify_stream_error(error: &anyhow::Error) -> crate::retry::ErrorClass {
    crate::retry::classify_boxed_error(error.as_ref())
}

const NODE_WAYPOINT_IDENTITY_WARN_WINDOW_MS: u64 = 60_000;
const NODE_WAYPOINT_IDENTITY_WARN_UNSET_MS: u64 = u64::MAX;

struct NodeWaypointIdentityWarnBucket {
    last_ms: AtomicU64,
    suppressed: AtomicU64,
}

impl NodeWaypointIdentityWarnBucket {
    fn new() -> Self {
        Self {
            last_ms: AtomicU64::new(NODE_WAYPOINT_IDENTITY_WARN_UNSET_MS),
            suppressed: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Copy)]
enum NodeWaypointIdentityErrorKind {
    SocketCookieUnavailable,
    UnknownCookie,
    MissingPodUid,
    MissingWorkloadHash,
    UnknownPod,
    WorkloadHashMismatch,
    PodUidMismatch,
}

impl NodeWaypointIdentityErrorKind {
    const COUNT: usize = 7;

    fn index(self) -> usize {
        match self {
            Self::SocketCookieUnavailable => 0,
            Self::UnknownCookie => 1,
            Self::MissingPodUid => 2,
            Self::MissingWorkloadHash => 3,
            Self::UnknownPod => 4,
            Self::WorkloadHashMismatch => 5,
            Self::PodUidMismatch => 6,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::SocketCookieUnavailable => "socket_cookie_unavailable",
            Self::UnknownCookie => "unknown_cookie",
            Self::MissingPodUid => "missing_pod_uid",
            Self::MissingWorkloadHash => "missing_workload_hash",
            Self::UnknownPod => "unknown_pod",
            Self::WorkloadHashMismatch => "workload_hash_mismatch",
            Self::PodUidMismatch => "pod_uid_mismatch",
        }
    }
}

struct NodeWaypointIdentityWarnLimiter {
    buckets: [NodeWaypointIdentityWarnBucket; NodeWaypointIdentityErrorKind::COUNT],
}

impl NodeWaypointIdentityWarnLimiter {
    fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| NodeWaypointIdentityWarnBucket::new()),
        }
    }

    fn bucket(&self, kind: NodeWaypointIdentityErrorKind) -> &NodeWaypointIdentityWarnBucket {
        &self.buckets[kind.index()]
    }
}

/// Resolve a node-waypoint TCP connection's source pod identity to a per-pod
/// authorization scope, mirroring the HTTP/HBONE admit path in
/// `src/proxy/mod.rs`.
///
/// Returns `(policy_scope, peer_spiffe_id)`:
/// - `policy_scope` is stamped onto `StreamConnectionContext.node_waypoint_policy_scope`
///   so `mesh_authz` enforces Namespace/WorkloadSelector-scoped policies for the
///   resolved source pod rather than treating every stream as mesh-wide.
/// - `peer_spiffe_id` is the resolved pod's SPIFFE ID, stamped into stream
///   metadata as the authenticated source principal (parity with
///   `RequestContext.peer_spiffe_id`).
///
/// Behavior:
/// - `resolver` is `None` outside `NodeWaypoint` topology and for non-mesh TCP
///   proxies → returns `(None, None)`; no per-pod scope is consulted (unchanged
///   pre-fix behavior).
/// - When the connection's `SO_COOKIE` cannot be resolved to an enrolled pod
///   (GAP-2M IPv6 / tuple miss, no node-agent enrollment yet, non-Linux,
///   unknown cookie), or the identity resolves but its workload has left the
///   live slice, returns `(None, None)` and stamps `mesh_authz.scope_missing`.
///   `mesh_authz` then **fails closed** (rejects the stream, 403) when any
///   namespace/selector-scoped policy is configured, and falls through to
///   mesh-wide-only when the mesh has only mesh-wide policies — the same gate
///   the HTTP/HBONE path applies per request.
///
/// **GAP-2M accept-side bridge (IPv4)**: the resolver's cookie records are
/// populated by the connect-side `orig_dst_bridge`, but the accept path looks
/// up the accept-side `SO_COOKIE` — a different kernel socket with a different
/// cookie (see `src/socket_opts.rs` and `src/ebpf/orig_dst_bridge.rs`). The
/// kernel `sock_ops` program bridges them for IPv4 by re-keying the orig-dst
/// record under the accept-side cookie, so IPv4 connections resolve scoped
/// policies with no further proxy-side change. IPv6 is not bridged (its
/// `sock_ops` ctx accessors trip the verifier), so IPv6 accepts get no
/// accept-side record and resolve `None` (fail-closed). The full datapath is CI
/// compile/load-tested but unverified on a live multi-pod node.
///
/// This helper never refuses the stream itself — unlike the HBONE listener,
/// which drops a connection without a resolved identity — because raw TCP
/// proxies in node-waypoint topology may legitimately carry non-captured
/// traffic; it returns `(None, None)` and lets `mesh_authz` make the
/// fail-closed-vs-mesh-wide decision above. The scope (`PolicyScopeCache`) may
/// be `None` even when the identity resolves — the workload carries no scoped
/// policy, or it left the current slice — and is taken from the same slice
/// generation that resolved the identity, so a resolved identity can never be
/// paired with an old/missing scope from a concurrent reload.
fn resolve_node_waypoint_stream_scope(
    resolver: Option<&crate::modes::mesh::node_waypoint::NodeWaypointIdentityResolver>,
    stream: &TcpStream,
    proxy_id: &str,
    client_ip: &str,
    warn_limiter: &NodeWaypointIdentityWarnLimiter,
) -> (
    Option<Arc<crate::modes::mesh::runtime::PolicyScopeCache>>,
    Option<String>,
) {
    let Some(resolver) = resolver else {
        return (None, None);
    };
    // Take the scope FROM the resolve result so the identity gate and the
    // per-pod scope come from the SAME slice generation (the "never partial"
    // reload invariant). The TCP path captures scope once at accept and persists
    // it for the connection's lifetime, so a second `policy_scope_for_pod` call
    // here could read a newer generation's scope against an older gate decision.
    match resolver.resolve_stream(stream) {
        Ok(resolved) => (
            resolved.policy_scope,
            Some(resolved.identity.spiffe_id.as_str().to_string()),
        ),
        Err(error) => {
            warn_node_waypoint_identity_scope_missing(proxy_id, client_ip, &error, warn_limiter);
            (None, None)
        }
    }
}

fn warn_node_waypoint_identity_scope_missing(
    proxy_id: &str,
    client_ip: &str,
    error: &crate::modes::mesh::node_waypoint::NodeWaypointIdentityError,
    warn_limiter: &NodeWaypointIdentityWarnLimiter,
) {
    let error_kind = node_waypoint_identity_error_kind(error);
    let bucket = warn_limiter.bucket(error_kind);
    let now_ms = crate::socket_opts::monotonic_now_ms();
    let last_ms = bucket.last_ms.load(Ordering::Relaxed);
    if last_ms != NODE_WAYPOINT_IDENTITY_WARN_UNSET_MS
        && now_ms.saturating_sub(last_ms) < NODE_WAYPOINT_IDENTITY_WARN_WINDOW_MS
    {
        bucket.suppressed.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if bucket
        .last_ms
        .compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        let suppressed = bucket.suppressed.swap(0, Ordering::Relaxed);
        warn!(
            proxy_id = %proxy_id,
            client = %client_ip,
            error = %error,
            identity_error_kind = error_kind.label(),
            policy_scope = "missing",
            mesh_authz_scope_missing = true,
            suppressed,
            "Node-waypoint TCP stream: no resolved pod identity; \
             per-pod authorization scope unavailable"
        );
    } else {
        bucket.suppressed.fetch_add(1, Ordering::Relaxed);
    }
}

fn node_waypoint_identity_error_kind(
    error: &crate::modes::mesh::node_waypoint::NodeWaypointIdentityError,
) -> NodeWaypointIdentityErrorKind {
    use crate::modes::mesh::node_waypoint::NodeWaypointIdentityError;

    match error {
        NodeWaypointIdentityError::SocketCookieUnavailable(_) => {
            NodeWaypointIdentityErrorKind::SocketCookieUnavailable
        }
        NodeWaypointIdentityError::UnknownCookie(_) => NodeWaypointIdentityErrorKind::UnknownCookie,
        NodeWaypointIdentityError::MissingPodUid(_) => NodeWaypointIdentityErrorKind::MissingPodUid,
        NodeWaypointIdentityError::MissingWorkloadHash { .. } => {
            NodeWaypointIdentityErrorKind::MissingWorkloadHash
        }
        NodeWaypointIdentityError::UnknownPod(_) => NodeWaypointIdentityErrorKind::UnknownPod,
        NodeWaypointIdentityError::WorkloadHashMismatch { .. } => {
            NodeWaypointIdentityErrorKind::WorkloadHashMismatch
        }
        NodeWaypointIdentityError::PodUidMismatch { .. } => {
            NodeWaypointIdentityErrorKind::PodUidMismatch
        }
    }
}

/// Decide whether a write-side error can be treated as the tail of a graceful
/// shutdown rather than a genuine transport failure.
///
/// When the *opposite* half of a bidirectional relay has already completed
/// with a clean EOF (`Ok(())` from `poll_copy_direction`), the two peers are
/// in the middle of a normal close dance — TLS `close_notify` followed by
/// the TCP FIN. A write on the still-live half racing against that FIN can
/// surface as `EPIPE` (BrokenPipe), `ECONNRESET` (ConnectionReset), or a
/// zero-byte write — all three map to the same semantic: "the peer's
/// receive side is already gone, so this byte didn't land, but the session
/// itself terminated cleanly." Marking these as transport errors inflates
/// `total_errors` at the edge of every large payload even when the
/// application layer was satisfied.
///
/// Restricted to the `Write` side because a *read* error after opposite-half
/// EOF (e.g., the backend sending `RST` instead of `FIN` after finishing its
/// response) is a genuine backend misbehaviour that operators must still
/// see. Only write-side benign errnos are reclassified.
///
/// `ConnectionAborted` is intentionally excluded. On Linux it can mean
/// `ECONNABORTED` from the kernel aborting the connection (keepalive failure,
/// listen-queue overflow tail) which is not the close-race signal we're
/// looking for. The retroactive Phase 2 grace-window check uses the
/// precomputed `phase1_benign_write_candidate` flag captured here so that
/// `ConnectionAborted` cannot leak through via post-classification matching
/// (it shares `ErrorClass::ConnectionClosed` with `BrokenPipe`).
fn is_post_eof_benign_write_error(side: StreamIoSide, kind: std::io::ErrorKind) -> bool {
    matches!(side, StreamIoSide::Write)
        && matches!(
            kind,
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::WriteZero
        )
}

/// Second piece of evidence for the close-race reclassification: both
/// directions of the relay must have successfully transferred at least one
/// byte. Without this, "opposite half EOF + this side benign write error"
/// is too permissive — it admits cases that look identical at the TCP
/// layer but are genuine truncations rather than the tail of a clean
/// close dance.
///
/// Cases this guard filters (which would otherwise be silently
/// reclassified as `GracefulShutdown`):
///
/// * **Backend closes before responding to a client upload** — c2b
///   transferred partial upload bytes, then backend FIN'd before
///   processing. b2c never delivered any response (`b2c_bytes == 0`),
///   so `c2b_bytes > 0 && b2c_bytes == 0`. Real backend failure;
///   operators must see it.
/// * **Client connects and immediately half-closes its write side**
///   without sending anything (port scanner, premature abort). Backend
///   may try to push data and hit `BrokenPipe`. Both counters stay 0.
/// * **Connection setup that never carried application traffic** at all
///   on either direction — same `c2b == 0 && b2c == 0` shape.
///
/// What this guard does **not** filter (still reclassified as graceful,
/// which is a deliberate TCP-layer-level limitation): a *symmetric*
/// mid-response disconnect where both directions had transferred bytes
/// but the response was truncated. That case is indistinguishable at the
/// TCP layer from a clean close-race tail; only an application-protocol-
/// aware proxy (HTTP plugin observing `Content-Length`, gRPC noticing
/// missing trailers, etc.) can flag it.
///
/// The bench scenario this PR was written for (wrk2 emitting 1 client
/// error per 70 KB / 500 KB payload after the full request *and*
/// response delivered cleanly) trivially passes the guard — both
/// directions have non-zero counters by the time the close race fires.
fn both_directions_transferred(c2b_bytes: &AtomicU64, b2c_bytes: &AtomicU64) -> bool {
    c2b_bytes.load(Ordering::Relaxed) > 0 && b2c_bytes.load(Ordering::Relaxed) > 0
}

// Legacy stream-error message prefixes.
//
// These are public-API surface for log consumers, dashboards, and
// integration tests that grep on the wording. They are produced at runtime
// by [`StreamSetupKind::prefix`] (`StreamSetupError`'s Display delegates to
// it); a regression test in `stream_error.rs` asserts the constants and the
// typed prefix stay in lockstep.
//
// New construction sites MUST emit a [`StreamSetupError`] rather than a
// bare `anyhow!()` — typed cause/direction attribution then survives
// `.context()`, `.into()`, and downstream error wrapping without depending
// on substring matching.
pub(crate) const STREAM_ERR_FRONTEND_TLS_HANDSHAKE_FAILED: &str = "Frontend TLS handshake failed";
pub(crate) const STREAM_ERR_BACKEND_TLS_HANDSHAKE_FAILED: &str = "Backend TLS handshake failed";
pub(crate) const STREAM_ERR_REJECTED_BY_PLUGIN: &str = "rejected by plugin";
pub(crate) const STREAM_ERR_CLIENT_DISCONNECTED_DURING_ADMISSION: &str =
    "client disconnected during plugin admission";
pub(crate) const STREAM_ERR_NO_HEALTHY_TARGETS: &str = "No healthy targets";
pub(crate) const STREAM_ERR_CIRCUIT_BREAKER_OPEN: &str = "circuit breaker open";
pub(crate) const STREAM_ERR_BACKEND_MAX_CONNECTIONS: &str = "Backend maxConnections reached";
pub(crate) const STREAM_ERR_UNSUPPORTED_STREAM_POLICY: &str = "Unsupported stream policy";

/// Sentinel prefix used by the Linux splice paths
/// (`io_uring_splice_direction`, `libc_splice_loop`) to signal that the
/// idle timer expired. The splice blocking-thread wrappers
/// (`bidirectional_splice_io_uring`) detect this prefix via `starts_with`
/// and map the error to `ErrorClass::ReadWriteTimeout` +
/// `Direction::Unknown` so `disconnect_cause_for_failure` reports
/// `IdleTimeout` — feeding the string through `classify_stream_error`
/// would yield `ConnectionTimeout`, which the cause mapper treats as a
/// recv/backend error. Keep this constant as the sole source of truth
/// for both the emission sites (inside splice loops) and the sentinel
/// checks (in the spawn_blocking closures); a drift between the two
/// would silently skew the `IdleTimeout` slice of `stream_disconnects`
/// metrics. Gated on Linux because splice(2) is Linux-only.
#[cfg(target_os = "linux")]
pub(crate) const STREAM_SPLICE_IDLE_TIMEOUT_PREFIX: &str = "TCP idle timeout";

/// Sentinel prefix for `backend_read_timeout_ms` expiry on a splice path.
/// The b2c splice worker reads from the backend; this fires when that read
/// side stops producing bytes for the configured backend read timeout.
/// Classified as `(BackendToClient, Read, ReadWriteTimeout)`. Re-exported
/// from `socket_opts::io_uring_splice` so the io_uring loop's emission
/// site and the tcp_proxy classifier share one compile-time-coupled value
/// — drift between the two is now a type error, not a silent metric drift.
#[cfg(target_os = "linux")]
pub(crate) const STREAM_SPLICE_BACKEND_READ_TIMEOUT_PREFIX: &str =
    crate::socket_opts::io_uring_splice::BACKEND_READ_TIMEOUT_MSG;

/// Sentinel prefix for `backend_write_timeout_ms` expiry on a splice path.
/// The c2b splice worker writes to the backend; this fires when that write
/// side stops draining bytes for the configured backend write timeout.
/// Classified as `(ClientToBackend, Write, ReadWriteTimeout)`. Shares a
/// compile-time-coupled value with `socket_opts::io_uring_splice` (see the
/// READ constant above).
#[cfg(target_os = "linux")]
pub(crate) const STREAM_SPLICE_BACKEND_WRITE_TIMEOUT_PREFIX: &str =
    crate::socket_opts::io_uring_splice::BACKEND_WRITE_TIMEOUT_MSG;

/// Which end of a half-duplex copy produced the error.
///
/// A single direction of the bidirectional relay consists of a read on the
/// source socket followed by a write to the destination socket. Combining
/// `StreamIoSide` with `Direction` lets the caller identify whether the
/// failure came from the client-facing or backend-facing socket, instead of
/// guessing from direction alone (which is ambiguous — a
/// `Direction::ClientToBackend` half can fail either because reading from the
/// client errored OR because writing to the backend errored).
///
/// | Direction         | Side  | Facing   |
/// |-------------------|-------|----------|
/// | `ClientToBackend` | Read  | Client   |
/// | `ClientToBackend` | Write | Backend  |
/// | `BackendToClient` | Read  | Backend  |
/// | `BackendToClient` | Write | Client   |
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[doc(hidden)]
pub enum StreamIoSide {
    /// Failure reading from the source socket of this half.
    Read,
    /// Failure writing to the destination socket of this half.
    Write,
}

/// Outcome of a bidirectional stream copy between the client and backend.
///
/// Preserves per-direction byte counts even when one half errors — callers
/// use these to record metrics accurately regardless of which side failed.
/// `first_failure` is `Some((direction, class, side, message))` when a half
/// errored before both halves observed a clean EOF; `None` indicates graceful
/// shutdown. `side` is `Some` when the error could be attributed to the read
/// or write end of the failing half; `None` for idle-timeout, pipe-creation,
/// or kTLS-install failures where no specific IO side is responsible. `message`
/// preserves the original I/O error text so `StreamTransactionSummary.
/// connection_error` surfaces concrete syscall/context details instead of just
/// duplicating the classified `error_class` enum name.
/// Ordered tuple recording which half failed first: (direction, classified
/// error, which I/O side within that half, original error text).
pub type StreamFirstFailure = (Direction, ErrorClass, Option<StreamIoSide>, String);

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct StreamCopyResult {
    pub bytes_client_to_backend: u64,
    pub bytes_backend_to_client: u64,
    pub first_failure: Option<StreamFirstFailure>,
}

/// Combine a failure's direction and IO side into the front-end / back-end
/// socket that actually errored.
///
/// * `Read` side of `ClientToBackend` → reading from the client ⇒ client-facing
/// * `Write` side of `ClientToBackend` → writing to the backend ⇒ backend-facing
/// * `Read` side of `BackendToClient` → reading from the backend ⇒ backend-facing
/// * `Write` side of `BackendToClient` → writing to the client ⇒ client-facing
///
/// `None` when the side isn't known (e.g., idle timeout). Callers fall back to
/// `DisconnectCause::RecvError` in that case.
#[doc(hidden)]
pub fn disconnect_cause_for_failure(
    direction: Direction,
    class: &ErrorClass,
    side: Option<StreamIoSide>,
) -> crate::plugins::DisconnectCause {
    use crate::plugins::DisconnectCause;
    // Idle timeout is always unambiguous regardless of direction/side.
    if matches!(class, ErrorClass::ReadWriteTimeout) {
        return DisconnectCause::IdleTimeout;
    }
    match (direction, side) {
        (Direction::ClientToBackend, Some(StreamIoSide::Read)) => DisconnectCause::RecvError,
        (Direction::ClientToBackend, Some(StreamIoSide::Write)) => DisconnectCause::BackendError,
        (Direction::BackendToClient, Some(StreamIoSide::Read)) => DisconnectCause::BackendError,
        (Direction::BackendToClient, Some(StreamIoSide::Write)) => DisconnectCause::RecvError,
        // Side unknown — conservative fallback to RecvError for historical
        // consistency with pre-attribution log consumers.
        _ => DisconnectCause::RecvError,
    }
}

/// Map a pre-copy error class (no bytes flowed, direction unknown) to a
/// `DisconnectCause`. Backend-facing failure classes (DNS lookup, connect,
/// port exhaustion, pool errors) map to `BackendError` so `stream_disconnects`
/// metrics don't misclassify backend outages as client recv errors.
///
/// **Typed-kind first.** When the error chain carries a [`StreamSetupError`]
/// (the canonical wrapper at every construction site that previously emitted
/// a `STREAM_ERR_*` prefix), its [`StreamSetupKind`] is the authoritative
/// signal: `is_client_side()` decides `RecvError` vs `BackendError` directly.
/// The class-based fallback below applies only when the chain has no
/// typed setup error — for example, when the failure originated outside the
/// proxy module or pre-dates the typed infrastructure.
///
/// `TlsError` would otherwise be ambiguous (frontend handshake vs backend
/// handshake) — the typed kind resolves this without inspecting the
/// message.
///
/// Genuinely client-side failures (e.g., `ClientDisconnect`) stay
/// `RecvError`. Timeouts during connect become `BackendError`, not
/// `IdleTimeout`, because idle timeout only applies after the relay starts.
///
/// The match is **exhaustive over `ErrorClass`** (no `_ => ...` catch-all)
/// so that adding a new variant triggers a compile error here. This
/// prevents the silent "unhandled class → RecvError" drift — every
/// backend-facing variant must be explicitly routed to `BackendError`, and
/// every client-facing variant to `RecvError`.
fn pre_copy_disconnect_cause(
    error: &anyhow::Error,
    class: &ErrorClass,
) -> crate::plugins::DisconnectCause {
    use crate::plugins::DisconnectCause;

    // Typed-kind shortcut: when the construction site attached a
    // `StreamSetupError`, we know which side failed without inspecting
    // the message. Stays in lockstep with `pre_copy_disconnect_direction`.
    if let Some(setup_err) = find_stream_setup_error(error) {
        return if setup_err.kind.is_client_side() {
            DisconnectCause::RecvError
        } else {
            DisconnectCause::BackendError
        };
    }

    match class {
        // Backend-facing failure classes — the client never saw a reply,
        // so these are always backend problems regardless of message.
        ErrorClass::DnsLookupError
        | ErrorClass::ConnectionTimeout
        | ErrorClass::ConnectionRefused
        | ErrorClass::PortExhaustion
        | ErrorClass::ConnectionPoolError
        | ErrorClass::ProtocolError
        // Pre-copy `ReadWriteTimeout` only fires if a backend-facing read/
        // write (e.g., TLS handshake I/O) stalls — no traffic has crossed
        // to the client, so it's backend-side.
        | ErrorClass::ReadWriteTimeout
        // Backend oversized its response — by definition backend-side.
        | ErrorClass::ResponseBodyTooLarge => DisconnectCause::BackendError,
        // No typed kind available — `ConnectionReset` / `ConnectionClosed`
        // without `StreamSetupError` originate from outside the typed
        // construction sites; treat conservatively as backend-side since the
        // typed frontend-TLS path would have surfaced via the kind shortcut
        // above.
        ErrorClass::ConnectionReset | ErrorClass::ConnectionClosed => {
            DisconnectCause::BackendError
        }
        // No typed kind — fall back conservatively. The typed path above
        // resolves frontend vs backend TLS without ambiguity; reaching this
        // arm means the chain has no `StreamSetupError`, which is unexpected
        // for TLS errors emitted by the proxy.
        ErrorClass::TlsError => DisconnectCause::RecvError,
        // Client-facing failure classes — the client is the problem or
        // the one that disconnected, so these are always recv-side.
        ErrorClass::ClientDisconnect | ErrorClass::RequestBodyTooLarge => {
            DisconnectCause::RecvError
        }
        // H3-only class: `H3_NO_ERROR` graceful close at the response
        // read boundary. Cannot reach a TCP relay in practice — TCP
        // never produces this — but the exhaustive match means we must
        // route it. A graceful remote close is backend-initiated, so
        // semantically this matches the `ConnectionClosed` branch above.
        ErrorClass::GracefulRemoteClose => DisconnectCause::BackendError,
        // `DispatchPolicyRejected` and `RequestError` are semantic gateway
        // policy/catch-all classes. The typed `StreamSetupError` path above
        // already attributes plugin/ACL/throttle/policy rejects (client-side)
        // and `NoHealthyTargets` (backend-side); reaching here means the chain
        // has no typed kind, so defer to a conservative recv-side fallback
        // rather than substring-matching. Migrate remaining untyped sites to
        // `StreamSetupError` to remove this fallback.
        ErrorClass::DispatchPolicyRejected | ErrorClass::RequestError => {
            DisconnectCause::RecvError
        }
    }
}

/// Map a pre-copy error to the originating direction.
///
/// Mirrors [`pre_copy_disconnect_cause`]: the typed
/// [`StreamSetupError`] kind is authoritative when present
/// ([`StreamSetupKind::direction`]); otherwise the error class is the
/// fallback signal (backend-facing classes → `BackendToClient`,
/// client-facing classes → `ClientToBackend`, ambiguous → `Unknown`).
///
/// Used by every TCP/UDP construction site that builds a
/// `StreamTransactionSummary` with `disconnect_direction: Some(...)` so log
/// consumers see consistent attribution across stream-family protocols.
fn pre_copy_disconnect_direction(error: &anyhow::Error, class: &ErrorClass) -> Direction {
    if let Some(setup_err) = find_stream_setup_error(error) {
        return setup_err.kind.direction();
    }
    match class {
        // Backend-facing classes attribute to the b2c half (the half that
        // tried to talk to the backend).
        ErrorClass::DnsLookupError
        | ErrorClass::ConnectionTimeout
        | ErrorClass::ConnectionRefused
        | ErrorClass::PortExhaustion
        | ErrorClass::ConnectionPoolError
        | ErrorClass::ProtocolError
        | ErrorClass::ReadWriteTimeout
        | ErrorClass::ResponseBodyTooLarge
        | ErrorClass::ConnectionReset
        | ErrorClass::ConnectionClosed
        | ErrorClass::GracefulRemoteClose => Direction::BackendToClient,
        // Client-facing classes attribute to the c2b half.
        ErrorClass::ClientDisconnect | ErrorClass::RequestBodyTooLarge => {
            Direction::ClientToBackend
        }
        // Unknown side — leave it ambiguous so log consumers know the proxy
        // could not attribute the failure.
        ErrorClass::TlsError | ErrorClass::DispatchPolicyRejected | ErrorClass::RequestError => {
            Direction::Unknown
        }
    }
}

/// Crate-visible bounded bidirectional relay used by TCP-family paths that
/// need the same idle and half-close watchdogs as the dedicated TCP proxy.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn bidirectional_copy_for_relay<C, B>(
    client: C,
    backend: B,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
    backend_read_timeout: Option<Duration>,
    backend_write_timeout: Option<Duration>,
    buf_size: usize,
) -> StreamCopyResult
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    bidirectional_copy(
        client,
        backend,
        idle_timeout,
        half_close_cap,
        backend_read_timeout,
        backend_write_timeout,
        buf_size,
    )
    .await
}

/// Crate-visible entry point to `bidirectional_copy` for the `_test_support`
/// module. Exposed only so external integration/unit tests can exercise the
/// direction-tracking behavior without the private function being made `pub`.
///
/// Rustc's dead-code analysis cannot see through the generic instantiations in
/// the `_test_support` re-export (which is consumed by the integration/unit
/// test crates), so the allow is load-bearing — without it CI's `-D warnings`
/// clippy gate fails.
#[allow(dead_code)]
pub(crate) async fn bidirectional_copy_for_test<C, B>(
    client: C,
    backend: B,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
    buf_size: usize,
) -> StreamCopyResult
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    bidirectional_copy_for_relay(
        client,
        backend,
        idle_timeout,
        half_close_cap,
        None,
        None,
        buf_size,
    )
    .await
}

/// Crate-visible entry point exposing the full `bidirectional_copy` signature
/// for tests that need to exercise per-direction `backend_read_timeout` /
/// `backend_write_timeout` enforcement.
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) async fn bidirectional_copy_for_test_with_timeouts<C, B>(
    client: C,
    backend: B,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
    backend_read_timeout: Option<Duration>,
    backend_write_timeout: Option<Duration>,
    buf_size: usize,
) -> StreamCopyResult
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    bidirectional_copy(
        client,
        backend,
        idle_timeout,
        half_close_cap,
        backend_read_timeout,
        backend_write_timeout,
        buf_size,
    )
    .await
}

/// Crate-visible entry point to the Linux `bidirectional_splice` for the
/// `_test_support` module. Only available on Linux because splice(2) is the
/// Linux zero-copy relay path; on other platforms `bidirectional_copy` is used.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) async fn bidirectional_splice_for_test(
    client: TcpStream,
    backend: TcpStream,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
    pipe_size: usize,
) -> StreamCopyResult {
    bidirectional_splice(
        client,
        backend,
        idle_timeout,
        half_close_cap,
        None,
        None,
        pipe_size,
    )
    .await
}

/// Crate-visible entry point to `bidirectional_splice` with the full
/// signature exposed so tests can exercise `backend_read_timeout_ms` /
/// `backend_write_timeout_ms` enforcement on the splice path.
#[cfg(target_os = "linux")]
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) async fn bidirectional_splice_for_test_with_timeouts(
    client: TcpStream,
    backend: TcpStream,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
    backend_read_timeout: Option<Duration>,
    backend_write_timeout: Option<Duration>,
    pipe_size: usize,
) -> StreamCopyResult {
    bidirectional_splice(
        client,
        backend,
        idle_timeout,
        half_close_cap,
        backend_read_timeout,
        backend_write_timeout,
        pipe_size,
    )
    .await
}

/// Crate-visible entry point to `bidirectional_splice_io_uring` for tests
/// that need to exercise the io_uring path with backend directional timeouts.
#[cfg(target_os = "linux")]
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) async fn bidirectional_splice_io_uring_for_test_with_timeouts(
    client: TcpStream,
    backend: TcpStream,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
    backend_read_timeout: Option<Duration>,
    backend_write_timeout: Option<Duration>,
    pipe_size: usize,
) -> StreamCopyResult {
    bidirectional_splice_io_uring(
        client,
        backend,
        idle_timeout,
        half_close_cap,
        backend_read_timeout,
        backend_write_timeout,
        pipe_size,
    )
    .await
}

/// Cached backend TLS configuration to avoid reading certificate files from
/// disk on every connection. Built once per listener lifecycle and reused.
pub(crate) struct CachedBackendTlsConfig {
    config: Arc<rustls::ClientConfig>,
}

impl CachedBackendTlsConfig {
    /// Build a TLS client config from proxy settings, reading cert files once.
    /// Uses the TLS policy's cipher suites and protocol versions when available.
    fn build(
        proxy: &Proxy,
        tls_no_verify: bool,
        global_tls_ca_bundle_path: Option<&str>,
        tls_policy: Option<&TlsPolicy>,
        crls: &crate::tls::CrlList,
    ) -> Result<Self, anyhow::Error> {
        let tls_config = BackendTlsConfigBuilder {
            proxy,
            policy: tls_policy,
            global_ca: global_tls_ca_bundle_path.map(Path::new),
            global_no_verify: tls_no_verify,
            global_client_cert: None,
            global_client_key: None,
            crls,
        }
        .build_rustls()
        .map_err(|e| anyhow::anyhow!("Failed to build backend TLS config: {}", e))?;

        Ok(Self {
            config: Arc::new(tls_config),
        })
    }
}

pub(crate) fn build_cached_backend_tls_config(
    proxy: &Proxy,
    tls_no_verify: bool,
    global_tls_ca_bundle_path: Option<&str>,
    tls_policy: Option<&TlsPolicy>,
    crls: &crate::tls::CrlList,
) -> Result<CachedBackendTlsConfig, anyhow::Error> {
    CachedBackendTlsConfig::build(
        proxy,
        tls_no_verify,
        global_tls_ca_bundle_path,
        tls_policy,
        crls,
    )
}

/// Metrics for a single TCP proxy listener.
#[derive(Default)]
pub struct TcpProxyMetrics {
    pub active_connections: AtomicU64,
    pub active_backend_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    /// Bytes transferred via splice(2) zero-copy (Linux only, plaintext paths).
    /// When non-zero, indicates splice was used instead of userspace copy.
    pub splice_bytes_transferred: AtomicU64,
    /// Per-backend-target open-connection limiter used to enforce
    /// DestinationRule `connectionPool.tcp.maxConnections`. Backed by the
    /// shared lock-free `BackendConnectionLimiter` (`src/backend_conn_limit.rs`),
    /// the same primitive the HTTP-family WebSocket dispatch path uses, so the
    /// stream-family and WebSocket paths can never drift apart. Counters are
    /// lazily created per `(host, port)` target and `CachePadded` so the
    /// read-mostly inflight count doesn't false-share with the hotter
    /// listener-level `active_backend_connections` field.
    pub backend_inflight: BackendConnectionLimiter,
}

struct TcpActiveConnectionGuard {
    metrics: Arc<TcpProxyMetrics>,
}

impl TcpActiveConnectionGuard {
    fn new(metrics: Arc<TcpProxyMetrics>) -> Self {
        metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        Self { metrics }
    }
}

impl Drop for TcpActiveConnectionGuard {
    fn drop(&mut self) {
        self.metrics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tcp_active_connection_guard_tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use super::{TcpActiveConnectionGuard, TcpProxyMetrics};

    #[test]
    fn guard_releases_listener_metric_on_drop() {
        let metrics = Arc::new(TcpProxyMetrics::default());
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);

        {
            let _guard = TcpActiveConnectionGuard::new(Arc::clone(&metrics));
            assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 1);
        }

        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
    }
}

struct TcpBackendSessionGuard<'a> {
    metrics: &'a TcpProxyMetrics,
}

impl<'a> TcpBackendSessionGuard<'a> {
    fn new(metrics: &'a TcpProxyMetrics) -> Self {
        metrics
            .active_backend_connections
            .fetch_add(1, Ordering::Relaxed);
        Self { metrics }
    }
}

impl Drop for TcpBackendSessionGuard<'_> {
    fn drop(&mut self) {
        self.metrics
            .active_backend_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Configuration for starting a TCP proxy listener.
pub struct TcpListenerConfig {
    pub port: u16,
    pub bind_addr: IpAddr,
    pub proxy_id: String,
    pub config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
    pub dns_cache: DnsCache,
    pub request_epoch: Arc<RequestEpochStore>,
    pub health_checker: Arc<HealthChecker>,
    /// Shared frontend TLS slot. The accept loop snapshots this per accept so
    /// a mesh PeerAuthentication live reload that swaps the slot is picked up
    /// on the next inbound TCP+TLS handshake without rebinding the listener.
    /// In-flight TLS sessions keep the config they handshake with until they
    /// end (rustls consults the `ServerConfig` only at handshake time).
    pub frontend_tls_slot: Arc<arc_swap::ArcSwap<Option<Arc<rustls::ServerConfig>>>>,
    pub shutdown: watch::Receiver<bool>,
    /// Optional gateway-wide shutdown receiver (SIGTERM/SIGINT). When `Some`,
    /// the accept loop exits as soon as either this OR the per-listener
    /// `shutdown` channel fires. Injected by [`StreamListenerManager`] from
    /// the watch channel created in `main.rs`.
    pub global_shutdown: Option<watch::Receiver<bool>>,
    pub metrics: Arc<TcpProxyMetrics>,
    pub tls_no_verify: bool,
    /// Global CA bundle path for outbound TLS verification (fallback when proxy has no per-proxy CA).
    pub tls_ca_bundle_path: Option<String>,
    /// Global default TCP idle timeout in seconds. Per-proxy `tcp_idle_timeout_seconds` overrides.
    pub tcp_idle_timeout_seconds: u64,
    /// Hard cap (seconds) on Phase 2 of the TCP bidirectional relay — the
    /// half-close drain where one direction has already completed cleanly.
    /// Applies even when the session idle timeout is disabled, so a stuck
    /// peer cannot wedge the relay task forever. `0` disables the cap.
    pub tcp_half_close_max_wait_seconds: u64,
    /// Frontend TLS handshake timeout in seconds for TCP+TLS stream listeners.
    /// `0` disables the timeout.
    pub frontend_tls_handshake_timeout_seconds: u64,
    /// Circuit breaker cache shared with HTTP proxies.
    pub circuit_breaker_cache: Arc<CircuitBreakerCache>,
    /// TLS hardening policy for backend connections (cipher suites, protocol versions).
    pub tls_policy: Option<Arc<TlsPolicy>>,
    /// Certificate Revocation Lists for backend TLS verification.
    pub crls: crate::tls::CrlList,
    /// Flipped once the listener successfully binds and can accept traffic.
    pub started: Arc<AtomicBool>,
    /// When set, this listener serves multiple passthrough proxies sharing the port.
    /// SNI from the ClientHello selects which proxy to route to.
    /// When `None`, uses the single `proxy_id` (existing behavior).
    pub sni_proxy_ids: Option<Vec<String>>,
    /// Adaptive buffer tracker for dynamic copy buffer sizing.
    pub adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    /// Whether TCP Fast Open is enabled (from `FERRUM_TCP_FASTOPEN_ENABLED`).
    pub tcp_fastopen_enabled: bool,
    /// Listen backlog for the TCP stream proxy socket.
    pub tcp_listen_backlog: u32,
    /// Number of SO_REUSEPORT accept loops for this stream proxy.
    pub accept_threads: usize,
    /// Server-side TCP Fast Open queue length.
    pub tcp_fastopen_queue_len: u16,
    /// Shared overload state for connection accounting and load shedding.
    pub overload: Arc<crate::overload::OverloadState>,
    /// Enable kTLS for splice on TLS paths (from `FERRUM_KTLS_ENABLED`).
    pub ktls_enabled: bool,
    /// Enable io_uring-based splice (from `FERRUM_IO_URING_SPLICE_ENABLED`).
    pub io_uring_splice_enabled: bool,
    /// Whether frontend TCP TLS handshake failures should increment mesh mTLS metrics.
    pub record_mesh_mtls_metric: bool,
    /// Mesh `outboundTrafficPolicy: REGISTRY_ONLY` enforcement slot. `None`
    /// (Option<Arc<...>> stored inside the ArcSwap) outside mesh mode or
    /// when policy is `AllowAny`. When `Some`, the connect path consults
    /// the registry before dialing the backend; unadmitted destinations
    /// are dropped with no backend connect and no circuit-breaker hit.
    pub mesh_outbound_enforcement:
        crate::modes::mesh::outbound_enforcement::SharedMeshOutboundEnforcement,
    /// Node-waypoint identity resolver. `Some` only in `NodeWaypoint`
    /// topology, where each accepted connection's `SO_COOKIE` is resolved to a
    /// source pod identity so the per-pod `PolicyScopeCache` can be stamped
    /// onto `StreamConnectionContext.node_waypoint_policy_scope` (parity with
    /// the HTTP/HBONE admit path in `src/proxy/mod.rs`). `None` for every other
    /// topology and for non-mesh TCP proxies — those pass no per-pod scope, so
    /// `mesh_authz` (when present) evaluates its construction-time-filtered
    /// policy set for the proxy's own workload identity rather than per-pod.
    pub node_waypoint_identity_resolver:
        Option<Arc<crate::modes::mesh::node_waypoint::NodeWaypointIdentityResolver>>,
    /// Pre-parsed trusted proxy CIDR set (from `FERRUM_TRUSTED_PROXIES`).
    /// When a proxy has `stream_proxy_protocol: true`, the accept loop reads
    /// the inbound PROXY protocol header and honors the forwarded address only
    /// when the socket peer belongs to this set. Connections from untrusted
    /// peers are closed immediately to prevent IP spoofing.
    pub trusted_proxies: Arc<crate::proxy::client_ip::TrustedProxies>,
}

#[derive(Clone)]
struct TcpAcceptLoopState {
    port: u16,
    proxy_id: Arc<str>,
    dns_cache: DnsCache,
    request_epoch: Arc<RequestEpochStore>,
    health_checker: Arc<HealthChecker>,
    /// Shared frontend TLS slot. Snapshotted per accept so the latest
    /// `ServerConfig` (e.g. after a mesh PeerAuthentication live reload swap)
    /// is used for the next handshake without rebinding the listener.
    frontend_tls_slot: Arc<arc_swap::ArcSwap<Option<Arc<rustls::ServerConfig>>>>,
    metrics: Arc<TcpProxyMetrics>,
    backend_tls_cache: Option<Arc<CachedBackendTlsConfig>>,
    global_tcp_idle_timeout: u64,
    tcp_half_close_max_wait_seconds: u64,
    frontend_tls_handshake_timeout_seconds: u64,
    circuit_breaker_cache: Arc<CircuitBreakerCache>,
    sni_proxy_ids: Option<Vec<String>>,
    adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    tcp_fastopen_enabled: bool,
    overload: Arc<crate::overload::OverloadState>,
    ktls_enabled: bool,
    io_uring_splice_enabled: bool,
    record_mesh_mtls_metric: bool,
    mesh_outbound_enforcement:
        crate::modes::mesh::outbound_enforcement::SharedMeshOutboundEnforcement,
    node_waypoint_identity_resolver:
        Option<Arc<crate::modes::mesh::node_waypoint::NodeWaypointIdentityResolver>>,
    node_waypoint_identity_warn_limiter: Arc<NodeWaypointIdentityWarnLimiter>,
    trusted_proxies: Arc<crate::proxy::client_ip::TrustedProxies>,
}

/// Start a TCP proxy listener on the given port.
///
/// This binds a dedicated TCP listener and for each accepted connection:
/// 1. Optionally performs TLS termination (if `frontend_tls` is enabled)
/// 2. Resolves the backend target (direct host or via load balancer)
/// 3. Connects to the backend (with optional TLS origination for `TcpTls`)
/// 4. Bidirectional stream copy until one side closes
pub async fn start_tcp_listener(cfg: TcpListenerConfig) -> Result<(), anyhow::Error> {
    let TcpListenerConfig {
        port,
        bind_addr,
        proxy_id,
        config,
        dns_cache,
        request_epoch,
        health_checker,
        frontend_tls_slot,
        shutdown,
        global_shutdown,
        metrics,
        tls_no_verify,
        tls_ca_bundle_path,
        tcp_idle_timeout_seconds: global_tcp_idle_timeout,
        tcp_half_close_max_wait_seconds,
        frontend_tls_handshake_timeout_seconds,
        circuit_breaker_cache,
        tls_policy,
        crls,
        started,
        sni_proxy_ids,
        adaptive_buffer,
        tcp_fastopen_enabled,
        tcp_listen_backlog,
        accept_threads,
        tcp_fastopen_queue_len,
        overload,
        ktls_enabled,
        io_uring_splice_enabled,
        record_mesh_mtls_metric,
        mesh_outbound_enforcement,
        node_waypoint_identity_resolver,
        trusted_proxies,
    } = cfg;
    let addr = SocketAddr::new(bind_addr, port);
    let backlog = tcp_listen_backlog as i32;
    let configured_accept_threads: usize = accept_threads.max(1);
    #[cfg(unix)]
    let actual_accept_threads: usize = configured_accept_threads;
    #[cfg(not(unix))]
    let actual_accept_threads: usize = {
        if configured_accept_threads > 1 {
            warn!(
                configured_accept_threads,
                "FERRUM_ACCEPT_THREADS > 1 requires SO_REUSEPORT; using one TCP stream accept loop on this platform"
            );
        }
        1
    };
    let reuse_port = actual_accept_threads > 1;
    let tfo_queue = if tcp_fastopen_enabled {
        Some(tcp_fastopen_queue_len)
    } else {
        None
    };

    // Create the first listener up front; additional listeners bind below via
    // SO_REUSEPORT so the kernel can distribute stream accepts across workers.
    let first_listener = crate::proxy::create_proxy_socket(addr, backlog, tfo_queue, reuse_port)?;

    // Convert to Arc<str> so per-connection clones are a cheap pointer bump.
    let proxy_id: Arc<str> = Arc::from(proxy_id);

    // Pre-build backend TLS config if this proxy uses Tcps (TCP+TLS) backend scheme.
    // This avoids reading certificate files from disk on every connection.
    let backend_tls_cache: Option<Arc<CachedBackendTlsConfig>> = {
        let current_config = config.load();
        current_config
            .proxies
            .iter()
            .find(|p| *p.id == *proxy_id)
            // Passthrough proxies relay raw bytes without originating backend
            // TLS; their listener must not fail because unrelated TLS material
            // (global CA bundle / upstream-resolved fields) is unreadable.
            .filter(|p| {
                p.dispatch_kind == crate::config::types::DispatchKind::TcpTls && !p.passthrough
            })
            .map(|proxy| {
                build_cached_backend_tls_config(
                    proxy,
                    tls_no_verify,
                    tls_ca_bundle_path.as_deref(),
                    tls_policy.as_deref(),
                    &crls,
                )
                .map(Arc::new)
            })
            .transpose()
            .map_err(|e| anyhow::anyhow!("Failed to pre-build backend TLS config: {}", e))?
    };

    let loop_state = TcpAcceptLoopState {
        port,
        proxy_id: proxy_id.clone(),
        dns_cache,
        request_epoch,
        health_checker,
        frontend_tls_slot,
        metrics,
        backend_tls_cache,
        global_tcp_idle_timeout,
        tcp_half_close_max_wait_seconds,
        frontend_tls_handshake_timeout_seconds,
        circuit_breaker_cache,
        sni_proxy_ids,
        adaptive_buffer,
        tcp_fastopen_enabled,
        overload,
        ktls_enabled,
        io_uring_splice_enabled,
        record_mesh_mtls_metric,
        mesh_outbound_enforcement,
        node_waypoint_identity_resolver,
        node_waypoint_identity_warn_limiter: Arc::new(NodeWaypointIdentityWarnLimiter::new()),
        trusted_proxies,
    };

    // Bind all extra sockets before spawning any accept loops. If one bind
    // fails, every already-bound socket is dropped here and startup fails
    // cleanly without leaving orphan listener tasks behind.
    let mut extra_listeners = Vec::with_capacity(actual_accept_threads.saturating_sub(1));
    for _ in 1..actual_accept_threads {
        extra_listeners.push(crate::proxy::create_proxy_socket(
            addr, backlog, tfo_queue, reuse_port,
        )?);
    }

    let mut handles = Vec::with_capacity(extra_listeners.len());
    for (extra_loop_index, listener) in extra_listeners.into_iter().enumerate() {
        let accept_loop_id = extra_loop_index + 1;
        let state = loop_state.clone();
        let shutdown_rx = shutdown.clone();
        let global_shutdown_rx = global_shutdown.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_tcp_accept_loop(
                listener,
                state,
                shutdown_rx,
                global_shutdown_rx,
                accept_loop_id,
            )
            .await
            {
                warn!(
                    accept_loop = accept_loop_id,
                    "TCP proxy accept loop exited with error: {}", e
                );
            }
        }));
    }

    started.store(true, Ordering::Release);
    info!(
        proxy_id = %proxy_id,
        backlog = backlog,
        accept_threads = actual_accept_threads,
        "TCP proxy listener started on {}",
        addr
    );

    run_tcp_accept_loop(first_listener, loop_state, shutdown, global_shutdown, 0).await?;
    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

async fn run_tcp_accept_loop(
    listener: TcpListener,
    state: TcpAcceptLoopState,
    mut shutdown_rx: watch::Receiver<bool>,
    mut global_shutdown_rx: Option<watch::Receiver<bool>>,
    accept_loop_id: usize,
) -> Result<(), anyhow::Error> {
    // See `run_accept_loop` in proxy/mod.rs: under fd exhaustion (EMFILE/ENFILE)
    // accept() re-fails without consuming the backlog, busy-looping CPU + logs.
    // Back off (capped at 100ms) only on repeated consecutive failures so
    // isolated transient errors (e.g. ECONNABORTED) are not penalized.
    let mut accept_backoff = crate::util::accept_backoff::AcceptBackoff::new();
    let mut accept_err_log = crate::util::accept_backoff::LogRateLimiter::new();
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (mut stream, remote_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        // Bound the log rate independently of the backoff (an
                        // abort/reset flood is not backed off): emit the first
                        // error, then one summary per second with the count.
                        if let Some(suppressed) =
                            accept_err_log.on_event(crate::socket_opts::monotonic_now_ms())
                        {
                            warn!(
                                proxy_id = %state.proxy_id,
                                accept_loop = accept_loop_id,
                                suppressed,
                                "TCP accept error: {}",
                                e
                            );
                        }
                        if let Some(delay) = accept_backoff.on_error(e.kind()) {
                            tokio::time::sleep(delay).await;
                        }
                        continue;
                    }
                };
                accept_backoff.on_success();

                // Reject new connections under critical overload (same as HTTP proxy).
                if state.overload.reject_new_connections.load(Ordering::Relaxed) {
                    drop(stream); // TCP RST
                    continue;
                }

                state.metrics.total_connections.fetch_add(1, Ordering::Relaxed);

                let port = state.port;
                let proxy_id = state.proxy_id.clone();
                let dns_cache = state.dns_cache.clone();
                let request_epoch = state.request_epoch.clone();
                let health_checker = state.health_checker.clone();
                // Snapshot the live frontend TLS slot once per accept so the
                // handshake uses whatever rustls::ServerConfig is current at
                // this instant. Mesh PeerAuthentication live reload swaps this
                // slot under us; in-flight handshakes complete with the
                // snapshot they got.
                let frontend_tls = state.frontend_tls_slot.load().as_ref().clone();
                let metrics = state.metrics.clone();
                let backend_tls = state.backend_tls_cache.clone();
                let cb_cache = state.circuit_breaker_cache.clone();
                let sni_proxy_ids = state.sni_proxy_ids.clone();
                let adaptive_buf = state.adaptive_buffer.clone();
                let overload_for_conn = state.overload.clone();
                let global_tcp_idle_timeout = state.global_tcp_idle_timeout;
                let tcp_half_close_max_wait_seconds = state.tcp_half_close_max_wait_seconds;
                let frontend_tls_handshake_timeout_seconds =
                    state.frontend_tls_handshake_timeout_seconds;
                let tcp_fastopen_enabled = state.tcp_fastopen_enabled;
                let ktls_enabled = state.ktls_enabled;
                let io_uring_splice_enabled = state.io_uring_splice_enabled;
                let record_mesh_mtls_metric = state.record_mesh_mtls_metric;
                let mesh_outbound_enforcement = state.mesh_outbound_enforcement.clone();
                // `Some` only in NodeWaypoint topology; used below to resolve
                // this connection's source pod identity for per-pod policy
                // scoping. Cheap `Option<Arc>` clone per accept; `None`
                // everywhere else short-circuits with zero syscalls.
                let node_waypoint_identity_resolver =
                    state.node_waypoint_identity_resolver.clone();
                let node_waypoint_identity_warn_limiter =
                    state.node_waypoint_identity_warn_limiter.clone();
                let trusted_proxies = state.trusted_proxies.clone();

                tokio::spawn(async move {
                    let _active_metric_guard = TcpActiveConnectionGuard::new(metrics.clone());
                    // Track this connection for global overload accounting and graceful drain.
                    // The guard decrements the counter on drop (all exit paths).
                    let _conn_guard = crate::overload::ConnectionGuard::new(&overload_for_conn);

                    let connected_at = Instant::now();
                    let connected_wall_at = chrono::Utc::now();
                    let direct_client_ip = remote_addr.ip().to_canonical().to_string();

                    // Inbound PROXY protocol (v1 text / v2 binary) — opt-in per proxy.
                    // When `stream_proxy_protocol: true` is set on the Proxy config, every
                    // connection must begin with a PROXY header. The forwarded source address
                    // is honoured only when the socket peer belongs to FERRUM_TRUSTED_PROXIES.
                    // Connections from untrusted peers, or with an invalid/absent header, are
                    // closed immediately (fail closed). This mirrors the HTTP-path semantics
                    // of `direct_client_ip` (socket peer) vs `client_ip` (XFF-resolved).
                    // Load one request epoch for this accepted connection and reuse it for
                    // PROXY parsing, SNI/routing, and stream setup. A live reload that toggles
                    // `stream_proxy_protocol` must not let one connection decide header
                    // consumption from one snapshot and route with another.
                    let epoch = request_epoch.load();
                    let proxy_protocol_enabled = epoch
                        .proxy_by_id(proxy_id.as_ref())
                        .and_then(|p| p.stream_proxy_protocol)
                        .unwrap_or(false);

                    // `client_ip` will be overwritten if PROXY protocol supplies a forwarded addr.
                    let client_ip = if proxy_protocol_enabled {
                        let peer_addr = remote_addr;
                        let peer_ip = peer_addr.ip();
                        // Only honor the PROXY header when the LB's IP is in FERRUM_TRUSTED_PROXIES.
                        if !trusted_proxies.contains(&peer_ip) {
                            crate::proxy::proxy_protocol::warn_untrusted_proxy_peer(
                                &peer_addr,
                                &proxy_id,
                            );
                            return; // close connection immediately
                        }
                        // Parse the PROXY header from the raw TcpStream. The header precedes
                        // the TLS ClientHello so we read it before any TLS handshake.
                        match crate::proxy::proxy_protocol::read_proxy_header(
                            &mut stream,
                            None, // use default 5s safety timeout
                        )
                        .await
                        {
                            Ok(result) => {
                                let (resolved, _direct) =
                                    crate::proxy::proxy_protocol::apply_proxy_result(
                                        result, &peer_addr,
                                    );
                                resolved
                            }
                            Err(e) => {
                                crate::proxy::proxy_protocol::warn_invalid_proxy_header(
                                    &peer_addr,
                                    &proxy_id,
                                    &e,
                                );
                                return; // close connection immediately
                            }
                        }
                    } else {
                        direct_client_ip.clone()
                    };

                    // Node-waypoint per-pod policy scoping (parity with the
                    // HTTP/HBONE admit path in `src/proxy/mod.rs`). When this
                    // listener carries a `NodeWaypointIdentityResolver`
                    // (NodeWaypoint topology only), resolve the accepted
                    // connection's `SO_COOKIE` to its source pod identity, then
                    // look up that pod's `PolicyScopeCache`. The resolved scope
                    // and SPIFFE principal are stamped onto the
                    // `StreamConnectionContext` below so `mesh_authz` enforces
                    // namespace/selector-scoped policies for the correct source
                    // pod instead of treating every stream as mesh-wide. See
                    // [`resolve_node_waypoint_stream_scope`] for the fail-closed
                    // semantics.
                    let (node_waypoint_policy_scope, node_waypoint_peer_spiffe_id) =
                        resolve_node_waypoint_stream_scope(
                            node_waypoint_identity_resolver.as_deref(),
                            &stream,
                            &proxy_id,
                            &client_ip,
                            &node_waypoint_identity_warn_limiter,
                        );
                    let base_proxy = epoch.proxy_by_id(proxy_id.as_ref());
                    let consumer_index =
                        Arc::new(ConsumerIndex::from_inner(Arc::clone(&epoch.consumer_index)));

                    // Build stream context — plugins run inside handle_tcp_connection
                    // (after TLS handshake for TLS proxies, so client cert is available).
                    let mut stream_ctx = StreamConnectionContext::new(
                        client_ip.clone(),
                        // `direct_client_ip` is the canonicalized socket peer. When PROXY
                        // protocol is active `client_ip` may differ (forwarded source IP).
                        direct_client_ip.clone(),
                        proxy_id.to_string(),
                        base_proxy.and_then(|p| p.name.clone()),
                        port,
                        base_proxy
                            .map(|p| p.effective_scheme())
                            .unwrap_or(BackendScheme::Tcp),
                        consumer_index,
                    );
                    stream_ctx.proxy_lifecycle_generation = epoch
                        .plugin_cache
                        .proxy_lifecycle_generation(proxy_id.as_ref());
                    // Populated above from the node-waypoint resolver in
                    // NodeWaypoint topology so `mesh_authz` enforces
                    // namespace/selector-scoped policies per source pod
                    // (parity with the HTTP/HBONE path). `None` for every
                    // other topology and non-mesh TCP proxies, and when the
                    // connection's source pod identity cannot be resolved
                    // (mesh-wide-only fallback + `mesh_authz.scope_missing`).
                    stream_ctx.node_waypoint_policy_scope = node_waypoint_policy_scope;
                    // In node-waypoint topology the resolved pod SPIFFE ID is
                    // the authenticated source principal for this connection
                    // (mirrors `RequestContext.peer_spiffe_id` on the HTTP
                    // path). Stamp it into stream metadata so `mesh_authz`'s
                    // stream path consumes the pod identity for
                    // source-principal-matched policies. Only stamped when the
                    // resolver produced an identity; otherwise the stream keeps
                    // whatever a stream auth plugin establishes.
                    if let Some(peer_spiffe_id) = node_waypoint_peer_spiffe_id {
                        stream_ctx.insert_metadata("peer_spiffe_id".to_string(), peer_spiffe_id);
                    }

                    // `ArcSwap::load()` returns a `Guard` over `Arc<Option<Arc<...>>>`;
                    // pull the inner `Option<Arc<...>>` so the borrow is decoupled from
                    // the guard before the async await suspension.
                    let mesh_enforcement_snapshot =
                        mesh_outbound_enforcement.load_full().as_ref().clone();
                    let result = handle_tcp_connection(
                        stream,
                        remote_addr,
                        &proxy_id,
                        &epoch,
                        &health_checker,
                        &dns_cache,
                        frontend_tls.as_ref(),
                        backend_tls.as_deref(),
                        global_tcp_idle_timeout,
                        tcp_half_close_max_wait_seconds,
                        frontend_tls_handshake_timeout_seconds,
                        &cb_cache,
                        &mut stream_ctx,
                        sni_proxy_ids.as_deref(),
                        &adaptive_buf,
                        tcp_fastopen_enabled,
                        ktls_enabled,
                        io_uring_splice_enabled,
                        record_mesh_mtls_metric,
                        &overload_for_conn,
                        metrics.as_ref(),
                        mesh_enforcement_snapshot.as_ref(),
                    )
                    .await;
                    // The transport has ended. Release admission capacity before
                    // awaiting disconnect observers, which may perform network I/O.
                    stream_ctx.release_admission_permits();

                    let duration_ms = connected_at.elapsed().as_millis() as f64;
                    let final_proxy_id = stream_ctx.proxy_id.clone();
                    // Keep disconnect hooks/logging on the same epoch that
                    // admitted the connection. Long-lived TCP streams can span
                    // config reloads; using the connection epoch preserves a
                    // consistent view of SNI-selected proxy metadata and
                    // stream plugins for the full connection lifetime.
                    let final_proxy = epoch.proxy_by_id(&final_proxy_id);
                    let plugins = epoch
                        .plugin_cache
                        .get_plugins_for_protocol(&final_proxy_id, ProxyProtocol::Tcp);
                    let proxy_name = stream_ctx.proxy_name.clone();
                    let proxy_namespace = final_proxy
                        .map(|p| p.namespace.clone())
                        .unwrap_or_else(crate::config::types::default_namespace);
                    let backend_scheme = final_proxy
                        .map(|p| p.effective_scheme())
                        .unwrap_or(stream_ctx.backend_scheme);
                    let (
                        bytes_in,
                        bytes_out,
                        conn_error,
                        error_class,
                        disconnect_direction,
                        disconnect_cause,
                    ) = match &result.outcome {
                        Ok(s) => {
                            metrics.bytes_in.fetch_add(s.bytes_in, Ordering::Relaxed);
                            metrics.bytes_out.fetch_add(s.bytes_out, Ordering::Relaxed);
                            if s.splice_used {
                                metrics.splice_bytes_transferred.fetch_add(
                                    s.bytes_in.saturating_add(s.bytes_out),
                                    Ordering::Relaxed,
                                );
                            }
                            debug!(
                                proxy_id = %proxy_id,
                                client = %client_ip,
                                bytes_in = s.bytes_in,
                                bytes_out = s.bytes_out,
                                splice = s.splice_used,
                                duration_ms = s.duration.as_millis() as u64,
                                "TCP connection completed"
                            );
                            // Bidirectional copy finished. If `first_failure` is
                            // set, one half errored before both halves observed
                            // a clean EOF — surface the real direction & class.
                            // Otherwise both halves hit EOF cleanly (graceful).
                            //
                            // Combine direction + IO side to pick the correct
                            // DisconnectCause: a `ClientToBackend` half that
                            // errored on its *write* end means the backend
                            // socket failed, not the client — so cause is
                            // BackendError, not RecvError. See
                            // `disconnect_cause_for_failure` for the full table.
                            match &s.first_failure {
                                Some((dir, class, side, message)) => {
                                    let dir = *dir;
                                    let class = *class;
                                    let cause =
                                        disconnect_cause_for_failure(dir, &class, *side);
                                    (
                                        s.bytes_in,
                                        s.bytes_out,
                                        Some(message.clone()),
                                        Some(class),
                                        Some(dir),
                                        Some(cause),
                                    )
                                }
                                None => (
                                    s.bytes_in,
                                    s.bytes_out,
                                    None,
                                    None,
                                    None,
                                    Some(crate::plugins::DisconnectCause::GracefulShutdown),
                                ),
                            }
                        }
                        Err(e) => {
                            debug!(
                                proxy_id = %proxy_id,
                                client = %client_ip,
                                error = %e,
                                "TCP connection error"
                            );
                            let error_message = e.to_string();
                            let err_class = classify_stream_error(e);
                            // Pre-copy error (DNS, connect, plugin reject, TLS
                            // handshake). No bytes flowed; the typed
                            // `StreamSetupError` (when present in the chain)
                            // resolves which side failed without inspecting
                            // the message string. Direction is derived from
                            // the same typed kind so cause/direction stay in
                            // lockstep across protocols.
                            let cause = pre_copy_disconnect_cause(e, &err_class);
                            let direction = pre_copy_disconnect_direction(e, &err_class);
                            (
                                0,
                                0,
                                Some(error_message),
                                Some(err_class),
                                Some(direction),
                                Some(cause),
                            )
                        }
                    };

                    if !plugins.is_empty() || error_class.is_some() {
                        let disconnected_wall_at = chrono::Utc::now();
                        let consumer_username = if !plugins.is_empty() {
                            stream_ctx.effective_identity().map(str::to_owned)
                        } else {
                            None
                        };
                        let summary = StreamTransactionSummary {
                            namespace: proxy_namespace,
                            proxy_id: final_proxy_id,
                            proxy_lifecycle_generation: stream_ctx.proxy_lifecycle_generation,
                            proxy_name,
                            client_ip,
                            consumer_username,
                            auth_method: stream_ctx.auth_method,
                            backend_target: result.backend.backend_target,
                            backend_resolved_ip: result.backend.backend_resolved_ip,
                            protocol: backend_scheme.to_string(),
                            listen_port: port,
                            duration_ms,
                            bytes_sent: bytes_in,
                            bytes_received: bytes_out,
                            connection_error: conn_error,
                            error_class,
                            disconnect_direction,
                            disconnect_cause,
                            timestamp_connected: connected_wall_at.to_rfc3339(),
                            timestamp_disconnected: disconnected_wall_at.to_rfc3339(),
                            // TCP TLS termination and TLS passthrough both stash
                            // ClientHello/handshake SNI on stream_ctx; keep it on
                            // the disconnect summary for logging-sink parity with
                            // DTLS termination and UDP/DTLS passthrough (#2531).
                            sni_hostname: stream_ctx.sni_hostname.clone(),
                            metadata: if !plugins.is_empty() {
                                stream_ctx.take_metadata()
                            } else {
                                Default::default()
                            },
                        };
                        crate::runtime_metrics::global_ref().record_stream_transaction(&summary);
                        if summary.error_class == Some(crate::retry::ErrorClass::ConnectionReset)
                            && let Some(direction) = summary.disconnect_direction
                        {
                            crate::runtime_metrics::global_ref()
                                .record_tcp_rst(&summary.proxy_id, direction);
                        }

                        // Run on_stream_disconnect plugins (logging, metrics, etc.)
                        if !plugins.is_empty() {
                            for plugin in plugins.iter() {
                                plugin.on_stream_disconnect(&summary).await;
                            }
                        }
                    }
                });
            }
            _ = shutdown_rx.changed() => {
                info!(
                    proxy_id = %state.proxy_id,
                    accept_loop = accept_loop_id,
                    "TCP proxy listener shutting down on port {}",
                    state.port
                );
                return Ok(());
            }
            _ = async {
                match global_shutdown_rx.as_mut() {
                    Some(rx) => { let _ = rx.changed().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                info!(
                    proxy_id = %state.proxy_id,
                    accept_loop = accept_loop_id,
                    "TCP proxy listener shutting down on port {} (global SIGTERM)",
                    state.port
                );
                return Ok(());
            }
        }
    }
}

/// Lightweight snapshot of the proxy fields needed per TCP connection.
/// Avoids cloning the entire `Proxy` struct on every accepted connection.
struct TcpConnParams {
    backend_host: String,
    backend_port: u16,
    backend_policy_port: u16,
    backend_scheme: BackendScheme,
    dns_override: Option<String>,
    dns_cache_ttl_seconds: Option<u64>,
    backend_connect_timeout_ms: u64,
    backend_read_timeout_ms: u64,
    backend_write_timeout_ms: u64,
    tcp_idle_timeout_seconds: u64,
    /// Hard cap on Phase 2 (half-close drain). Applies even when the session
    /// idle timeout is disabled, preventing a stalled peer from wedging the
    /// drain future forever. `0` disables the cap.
    tcp_half_close_max_wait_seconds: u64,
    /// Retry config for connection-phase retries (before data transfer).
    retry: Option<crate::config::types::RetryConfig>,
    /// Upstream ID for load-balanced target selection on retry.
    upstream_id: Option<String>,
    /// Optional upstream subset for DestinationRule-style retry target selection.
    upstream_subset: Option<String>,
    /// Stable per-flow key used for initial LB selection. Retries reuse this
    /// key while excluding the failed target so consistent-hash failover stays
    /// distributed by client flow instead of by failed backend hostname.
    lb_hash_key: String,
    /// When true, forward encrypted client bytes directly without TLS termination.
    passthrough: bool,
    /// Whether TCP Fast Open is enabled (gated on `FERRUM_TCP_FASTOPEN_ENABLED`).
    tcp_fastopen_enabled: bool,
    /// Flattened per-port dispatch overrides used by retry attempts.
    dispatch_port_overrides:
        Option<std::collections::HashMap<u16, crate::config::types::ResolvedPortOverride>>,
    /// Per-port LB selection lane engaged for the initial target selection
    /// (single-port upstream with an effective override). Connection-phase
    /// retries must rotate inside the same lane so a per-port algorithm /
    /// locality policy is not escaped by `retry_on_connect_failure`.
    lb_port_lane: Option<u16>,
    /// Per-port health scope used for initial selection and connection-phase
    /// retries. This is independent from `lb_port_lane`: a passive-health-only
    /// port override must scope ejection caps without changing LB lane selection.
    health_port_scope: Option<u16>,
}

/// Lightweight snapshot of the proxy fields needed per TCP connection.
/// Includes circuit breaker config and target key for circuit breaker checks.
struct TcpConnCbInfo {
    cb_config: Option<crate::config::types::CircuitBreakerConfig>,
    cb_target_key: Option<String>,
    is_half_open_probe: bool,
}

/// Backend target info resolved during connection setup, available for logging
/// regardless of whether the connection succeeded or failed.
struct TcpBackendInfo {
    /// The backend target hostname:port (e.g., "db-host:5432").
    backend_target: String,
    /// The DNS-resolved IP address, if resolution succeeded.
    backend_resolved_ip: Option<String>,
}

thread_local! {
    /// Per-thread scratch buffer for formatting `host:port` strings on the
    /// TCP connection hot path. Reused across every accepted connection and
    /// every retry attempt so the `host:port` formatting cost on the
    /// per-connection path is a single allocation (the final `clone()` into
    /// the owned `String` slot on `TcpBackendInfo`) rather than two
    /// short-lived `format!()` allocations.
    ///
    /// `backend_target` must remain an owned `String` because it eventually
    /// moves into `StreamTransactionSummary.backend_target: String` which
    /// crosses an `.await` (logger dispatch) and is serialized into JSON
    /// log sinks — so we still hand the caller an owned value, but build it
    /// off a reused buffer instead of paying a fresh `format!()` allocation
    /// every time. Mirrors the zero-allocation pool-key pattern in
    /// `http2_pool.rs`.
    static BACKEND_TARGET_BUF: RefCell<String> = RefCell::new(String::with_capacity(64));
}

/// Format `host:port` into the thread-local scratch buffer and return a freshly
/// owned `String`. Reuses the buffer's capacity across calls on the same
/// tokio worker thread so the per-connection formatting cost is a single
/// owned-`String` allocation instead of two (one for the `format!()` macro's
/// internal buffer, one for the owned result).
fn format_backend_target(host: &str, port: u16) -> String {
    use std::fmt::Write;
    BACKEND_TARGET_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        // Writing into a `String` cannot fail — `fmt::Error` for `String`
        // requires the formatter itself to error, which `Display` for
        // `&str` / `u16` never does.
        let _ = write!(buf, "{}:{}", host, port);
        buf.clone()
    })
}

#[cfg(test)]
mod backend_target_format_tests {
    use super::{BACKEND_TARGET_BUF, format_backend_target};

    #[test]
    fn formats_host_port_pair_byte_for_byte_like_format_macro() {
        assert_eq!(format_backend_target("db-host", 5432), "db-host:5432");
        assert_eq!(format_backend_target("10.0.0.1", 80), "10.0.0.1:80");
        // IPv6 literals flow through as-is — callers are responsible for
        // bracketing if the consumer requires URL-style framing.
        assert_eq!(
            format_backend_target("[::1]", 443),
            format!("{}:{}", "[::1]", 443)
        );
    }

    #[test]
    fn reuses_thread_local_buffer_capacity_across_calls() {
        // First call grows the buffer to whatever the formatted length needs.
        let _ = format_backend_target("backend-with-a-fairly-long-hostname.example", 65535);
        let capacity_after_first = BACKEND_TARGET_BUF.with(|cell| cell.borrow().capacity());

        // Second call with a shorter target should reuse — never shrink —
        // the existing capacity. We only assert non-shrinkage, since
        // `String::clear()` is allowed to keep capacity but `String::clone()`
        // returns a freshly sized allocation regardless.
        let _ = format_backend_target("h", 1);
        let capacity_after_second = BACKEND_TARGET_BUF.with(|cell| cell.borrow().capacity());

        assert!(
            capacity_after_second >= capacity_after_first,
            "thread-local buffer must reuse capacity across calls \
             (before={capacity_after_first}, after={capacity_after_second})"
        );
    }
}

/// Result of a TCP connection: backend info (always present) plus the outcome.
struct TcpConnectionResult {
    backend: TcpBackendInfo,
    outcome: Result<TcpConnectionSuccess, anyhow::Error>,
}

struct TcpConnectionSuccess {
    bytes_in: u64,
    bytes_out: u64,
    duration: Duration,
    /// Whether splice(2) was used for this connection (Linux plaintext paths only).
    splice_used: bool,
    /// `Some((direction, class, side, message))` when the bidirectional copy
    /// errored before both halves observed a clean EOF. `None` indicates a
    /// graceful shutdown. `side` (when `Some`) tells the caller whether the
    /// failing half errored on its read or write end. `message` is the
    /// original I/O error text preserved for `connection_error` diagnostics.
    first_failure: Option<StreamFirstFailure>,
}

/// Handle a single TCP connection: TLS termination → backend resolution → bidirectional copy.
///
/// Always returns a `TcpConnectionResult` containing backend target info (for logging)
/// and the connection outcome. Backend info is populated as soon as the target is known,
/// so even failed connections log which backend was attempted.
#[allow(clippy::too_many_arguments, unused_variables)]
async fn handle_tcp_connection(
    client_stream: TcpStream,
    remote_addr: SocketAddr,
    proxy_id: &str,
    epoch: &RequestEpoch,
    health_checker: &HealthChecker,
    dns_cache: &DnsCache,
    frontend_tls_config: Option<&Arc<rustls::ServerConfig>>,
    cached_backend_tls: Option<&CachedBackendTlsConfig>,
    global_tcp_idle_timeout: u64,
    tcp_half_close_max_wait_seconds: u64,
    frontend_tls_handshake_timeout_seconds: u64,
    circuit_breaker_cache: &CircuitBreakerCache,
    stream_ctx: &mut StreamConnectionContext,
    sni_proxy_ids: Option<&[String]>,
    adaptive_buffer: &crate::adaptive_buffer::AdaptiveBufferTracker,
    tcp_fastopen: bool,
    ktls_enabled: bool,
    io_uring_splice_enabled: bool,
    record_mesh_mtls_metric: bool,
    overload: &crate::overload::OverloadState,
    metrics: &TcpProxyMetrics,
    mesh_outbound_enforcement: Option<&Arc<MeshOutboundEnforcement>>,
) -> TcpConnectionResult {
    let start = Instant::now();
    if let Err(e) = client_stream.set_nodelay(true) {
        warn!(
            proxy_id = %proxy_id,
            client = %remote_addr,
            "Failed to set TCP_NODELAY on accepted TCP stream: {}",
            e
        );
    }

    // Run the core connection logic, tracking backend info for logging.
    // We use a helper closure so that `?` returns from the closure, not the
    // outer function — allowing us to always populate backend info in the result.
    let mut backend_info = TcpBackendInfo {
        backend_target: String::new(),
        backend_resolved_ip: None,
    };

    let outcome = handle_tcp_connection_inner(
        client_stream,
        remote_addr,
        proxy_id,
        epoch,
        health_checker,
        dns_cache,
        frontend_tls_config,
        cached_backend_tls,
        global_tcp_idle_timeout,
        tcp_half_close_max_wait_seconds,
        frontend_tls_handshake_timeout_seconds,
        circuit_breaker_cache,
        start,
        &mut backend_info,
        stream_ctx,
        sni_proxy_ids,
        adaptive_buffer,
        tcp_fastopen,
        ktls_enabled,
        io_uring_splice_enabled,
        record_mesh_mtls_metric,
        overload,
        metrics,
        mesh_outbound_enforcement,
    )
    .await;

    TcpConnectionResult {
        backend: backend_info,
        outcome,
    }
}

async fn run_tcp_stream_connect_plugins(
    plugins: &[Arc<dyn Plugin>],
    stream_ctx: &mut StreamConnectionContext,
    client_stream: &TcpStream,
    proxy_id: &str,
    client_ip: IpAddr,
    connection_label: &'static str,
    rejection_detail: &'static str,
) -> Result<(), anyhow::Error> {
    for plugin in plugins {
        let result = if plugin.name() == "fault_injection" {
            tokio::select! {
                result = plugin.on_stream_connect(stream_ctx) => result,
                () = wait_for_tcp_peer_reset(client_stream) => {
                    stream_ctx.release_admission_permits();
                    return Err(StreamSetupError::new(
                        StreamSetupKind::ClientDisconnectedDuringAdmission,
                        connection_label,
                    ).into());
                }
            }
        } else {
            plugin.on_stream_connect(stream_ctx).await
        };
        if let PluginResult::Reject { .. } = result {
            stream_ctx.release_admission_permits();
            debug!(
                proxy_id = %proxy_id,
                client = %client_ip,
                connection = connection_label,
                "TCP stream connection rejected by plugin"
            );
            return Err(
                StreamSetupError::new(StreamSetupKind::RejectedByPlugin, rejection_detail).into(),
            );
        }
    }
    Ok(())
}

/// Wait until the accepted TCP peer resets or the socket reports a transport
/// error without consuming any application bytes. A read-half FIN is
/// deliberately not treated as cancellation: request/response protocols may
/// validly send their complete request and then half-close while continuing to
/// wait for the response.
pub(crate) async fn wait_for_tcp_peer_reset(client_stream: &TcpStream) {
    let mut retry_backoff = TcpFaultAdmissionRetryBackoff::new();
    loop {
        // Readiness may be spurious, and readiness polling itself may fail.
        // Neither is evidence that the peer disconnected: only a concrete
        // socket error cancels admission. A bounded increasing retry interval
        // prevents a persistent HUP/error readiness bit from spinning while
        // keeping reset cancellation within 50 ms and preserving cancel safety
        // in the surrounding `select!`.
        let readiness = client_stream.ready(tokio::io::Interest::ERROR).await;
        let socket_error = client_stream.take_error();
        if tcp_fault_admission_should_cancel(&readiness, &socket_error) {
            return;
        }
        tokio::time::sleep(retry_backoff.next_delay()).await;
    }
}

const TCP_FAULT_ADMISSION_RETRY_INITIAL_MS: u64 = 1;
const TCP_FAULT_ADMISSION_RETRY_MAX_MS: u64 = 50;

pub(crate) struct TcpFaultAdmissionRetryBackoff {
    next_ms: u64,
}

impl TcpFaultAdmissionRetryBackoff {
    pub(crate) fn new() -> Self {
        Self {
            next_ms: TCP_FAULT_ADMISSION_RETRY_INITIAL_MS,
        }
    }

    pub(crate) fn next_delay(&mut self) -> Duration {
        let delay = Duration::from_millis(self.next_ms);
        self.next_ms = (self.next_ms * 2).min(TCP_FAULT_ADMISSION_RETRY_MAX_MS);
        delay
    }
}

pub(crate) fn tcp_fault_admission_should_cancel(
    _readiness: &std::io::Result<tokio::io::Ready>,
    socket_error: &std::io::Result<Option<std::io::Error>>,
) -> bool {
    matches!(socket_error, Ok(Some(_)))
}

/// Maximum number of opening client bytes captured for stream first-bytes
/// inspection (e.g. the WAF). Bounds the hot-path capture buffer; inspecting
/// plugins scan up to this many bytes of the first TCP segment (plaintext or
/// passthrough) or the first decrypted application chunk (terminated TLS).
const STREAM_FIRST_BYTES_CAP: usize = 4096;

/// Poll interval for completing a short first-bytes peek. Only used on the cold
/// path where the opening TCP segment arrives fragmented (fewer bytes than an
/// inspecting plugin needs to classify the stream); a normal ClientHello fills
/// the buffer on the first peek and never sleeps. `peek()` is level-triggered —
/// the buffered bytes keep the socket readable, so re-awaiting it would spin —
/// hence a brief sleep between peeks, always bounded by the caller's deadline.
const STREAM_FIRST_BYTES_PEEK_RETRY_INTERVAL: Duration = Duration::from_millis(5);

/// Non-destructively peek up to [`STREAM_FIRST_BYTES_CAP`] bytes from a raw TCP
/// stream for first-bytes inspection. Peeking leaves the bytes in the socket
/// buffer, so the relay — including splice — still forwards them intact and the
/// fast path is preserved.
///
/// `min_len` is the smallest opening prefix an inspecting plugin needs to
/// classify the stream (e.g. the 6-byte TLS record + handshake-type prefix the
/// `tcp_require_tls` shape guard checks; see `Plugin::stream_first_bytes_min_len`).
/// A single `peek()` returns as soon as *any* bytes are buffered, which can be
/// fewer than `min_len` when the client's first TCP segment is fragmented — that
/// would make the guard misread a legitimately split ClientHello as a short
/// non-TLS chunk and reject it in enforce mode. So when a deadline is set we
/// keep peeking (the bytes stay in the socket buffer, untouched by the relay)
/// until at least `min_len` bytes are available, the buffer fills, the peer
/// closes, or the deadline expires. Without a deadline we take a single peek and
/// never loop, so a stalled peer cannot park the task waiting for a prefix that
/// never completes — failing closed on the short prefix is the caller's job.
///
/// Returns `None` when nothing was readable in time.
///
/// `pub(crate)` so the mesh raw-TCP inbound handler
/// (`mesh_tcp_inbound::handle_mesh_tcp_inbound`) can capture the same plaintext
/// prefix before running the global stream plugin chain.
pub(crate) async fn peek_tcp_first_bytes(
    stream: &TcpStream,
    timeout: Option<Duration>,
    min_len: usize,
) -> Option<bytes::Bytes> {
    let want = min_len.clamp(1, STREAM_FIRST_BYTES_CAP);
    let deadline = timeout.map(|d| tokio::time::Instant::now() + d);
    let mut buf = vec![0u8; STREAM_FIRST_BYTES_CAP];
    let mut have = 0usize;
    loop {
        let peek = stream.peek(&mut buf);
        let n = match deadline {
            // On deadline-elapsed or peek error, stop and use whatever prefix we
            // observed on an earlier iteration (still intact in `buf`/`have`).
            Some(dl) => match tokio::time::timeout_at(dl, peek).await {
                Ok(Ok(n)) => n,
                _ => break,
            },
            None => match peek.await {
                Ok(n) => n,
                Err(_) => break,
            },
        };
        if n == 0 {
            // EOF: peer closed the write half without sending (more) bytes.
            break;
        }
        have = n;
        if have >= want || have >= STREAM_FIRST_BYTES_CAP {
            break;
        }
        // Not enough yet. Only wait for more when a deadline bounds the wait;
        // otherwise return what we have rather than risk parking indefinitely.
        let Some(dl) = deadline else { break };
        let now = tokio::time::Instant::now();
        if now >= dl {
            break;
        }
        let wake = (now + STREAM_FIRST_BYTES_PEEK_RETRY_INTERVAL).min(dl);
        tokio::time::sleep_until(wake).await;
    }
    if have == 0 {
        return None;
    }
    buf.truncate(have);
    Some(bytes::Bytes::from(buf))
}

/// Read up to [`STREAM_FIRST_BYTES_CAP`] decrypted application bytes from a
/// TLS-terminated client stream for first-bytes inspection. Unlike the raw peek
/// this *consumes* the bytes from the TLS session, so the caller must forward the
/// returned prefix to the backend before relaying the remainder and must not use
/// kTLS splice for the connection. Returns an empty vec on timeout/EOF; the
/// caller leaves `first_bytes_kind = Some(DecryptedApp)` set so the stream WAF
/// treats the absent prefix as a missing capture and fails closed in `enforce`
/// mode when signatures are configured (see `Waf::on_stream_connect`) rather
/// than as an implicit fail-open "nothing to inspect".
async fn read_decrypted_first_bytes<S>(stream: &mut S, timeout: Option<Duration>) -> Vec<u8>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; STREAM_FIRST_BYTES_CAP];
    let read = stream.read(&mut buf);
    let n = match timeout {
        Some(d) => match tokio::time::timeout(d, read).await {
            Ok(Ok(n)) => n,
            _ => 0,
        },
        None => read.await.unwrap_or(0),
    };
    buf.truncate(n);
    buf
}

/// Inner implementation of TCP connection handling that can use `?` for early returns
/// while the caller always receives backend info for logging.
#[allow(clippy::too_many_arguments, unused_variables)]
async fn handle_tcp_connection_inner(
    client_stream: TcpStream,
    remote_addr: SocketAddr,
    proxy_id: &str,
    epoch: &RequestEpoch,
    health_checker: &HealthChecker,
    dns_cache: &DnsCache,
    frontend_tls_config: Option<&Arc<rustls::ServerConfig>>,
    cached_backend_tls: Option<&CachedBackendTlsConfig>,
    global_tcp_idle_timeout: u64,
    tcp_half_close_max_wait_seconds: u64,
    frontend_tls_handshake_timeout_seconds: u64,
    circuit_breaker_cache: &CircuitBreakerCache,
    start: Instant,
    backend_info: &mut TcpBackendInfo,
    stream_ctx: &mut StreamConnectionContext,
    sni_proxy_ids: Option<&[String]>,
    adaptive_buffer: &crate::adaptive_buffer::AdaptiveBufferTracker,
    tcp_fastopen: bool,
    ktls_enabled: bool,
    io_uring_splice_enabled: bool,
    record_mesh_mtls_metric: bool,
    overload: &crate::overload::OverloadState,
    metrics: &TcpProxyMetrics,
    mesh_outbound_enforcement: Option<&Arc<MeshOutboundEnforcement>>,
) -> Result<TcpConnectionSuccess, anyhow::Error> {
    // Bound the passthrough SNI peek by the same deadline as terminating-TLS
    // handshakes. Without this, a peer that opens a TCP connection and never
    // writes a ClientHello would park the connection-handler task indefinitely.
    // `0` keeps the historical "no timeout" behavior for operators who explicitly
    // disable the handshake clock.
    let sni_peek_timeout = if frontend_tls_handshake_timeout_seconds > 0 {
        Some(std::time::Duration::from_secs(
            frontend_tls_handshake_timeout_seconds,
        ))
    } else {
        None
    };

    // --- SNI-based proxy resolution for shared passthrough ports ---
    // When multiple passthrough proxies share a listen_port, we must peek at
    // the ClientHello to extract SNI before looking up the proxy config.
    let _resolved_proxy_id: Option<String>;
    let proxy_id = if let Some(sni_ids) = sni_proxy_ids {
        let sni = super::sni::extract_sni_from_tcp_stream(&client_stream, sni_peek_timeout).await;
        stream_ctx.sni_hostname = sni.clone();

        let matched = super::sni::resolve_proxy_by_sni_in_epoch(sni.as_deref(), sni_ids, epoch)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No matching passthrough proxy for SNI {:?} on port {}",
                    sni,
                    stream_ctx.listen_port
                )
            })?;
        _resolved_proxy_id = Some(matched.to_string());
        // Update stream_ctx to reflect the resolved proxy
        stream_ctx.proxy_id = matched.to_string();
        stream_ctx.proxy_name = epoch.proxy_by_id(matched).and_then(|p| p.name.clone());
        _resolved_proxy_id.as_deref().unwrap_or(proxy_id)
    } else {
        _resolved_proxy_id = None;
        proxy_id
    };

    // Look up the proxy config and extract only the fields we need.
    let proxy = epoch
        .proxy_by_id(proxy_id)
        .ok_or_else(|| anyhow::anyhow!("Proxy {} not found in config", proxy_id))?;

    let (params, cb_info) = {
        stream_ctx.proxy_id = proxy.id.clone();
        stream_ctx.proxy_name = proxy.name.clone();
        stream_ctx.backend_scheme = proxy.effective_scheme();

        let lb_hash_key = stream_lb_hash_key_for_client_ip(remote_addr.ip());
        let (backend_host, backend_port, backend_policy_port, lb_port_lane, health_port_scope) =
            resolve_backend_target(proxy, &epoch.load_balancer, health_checker, &lb_hash_key)?;

        // Populate backend target as soon as it's known — even if DNS or connect fails,
        // the log will show which target was attempted.
        backend_info.backend_target = format_backend_target(&backend_host, backend_port);

        let cb_target_key = proxy
            .upstream_id
            .as_ref()
            .map(|_| crate::circuit_breaker::target_key(&backend_host, backend_port));

        let cb_info = TcpConnCbInfo {
            cb_config: proxy.circuit_breaker.clone(),
            cb_target_key,
            is_half_open_probe: false,
        };

        // Honor DestinationRule per-port `connect_timeout_ms` overrides on the
        // L4/TCP path. The override is keyed by destination port and lives on
        // the proxy's pre-computed `dispatch_port_overrides` map — single
        // field read, no DashMap/ArcSwap traversal. Pre-port DR
        // connectTimeouts for TCP services (e.g. MySQL on 3306 with a
        // tighter budget than the proxy default) now flow into the relay.
        let port_override = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&backend_policy_port));
        let effective_backend_connect_timeout_ms = port_override
            .and_then(|override_config| override_config.connect_timeout_ms)
            .unwrap_or(proxy.backend_connect_timeout_ms);
        let params = TcpConnParams {
            backend_host,
            backend_port,
            backend_policy_port,
            backend_scheme: proxy.effective_scheme(),
            dns_override: proxy.dns_override.clone(),
            dns_cache_ttl_seconds: proxy.dns_cache_ttl_seconds,
            backend_connect_timeout_ms: effective_backend_connect_timeout_ms,
            backend_read_timeout_ms: proxy.backend_read_timeout_ms,
            backend_write_timeout_ms: proxy.backend_write_timeout_ms,
            tcp_idle_timeout_seconds: proxy
                .tcp_idle_timeout_seconds
                .unwrap_or(global_tcp_idle_timeout),
            tcp_half_close_max_wait_seconds,
            retry: proxy.retry.clone(),
            upstream_id: proxy.upstream_id.clone(),
            upstream_subset: proxy.upstream_subset.clone(),
            lb_hash_key,
            passthrough: proxy.passthrough,
            tcp_fastopen_enabled: tcp_fastopen,
            dispatch_port_overrides: proxy.dispatch_port_overrides.clone(),
            lb_port_lane,
            health_port_scope,
        };

        (params, cb_info)
    };

    enforce_mesh_tcp_outbound_target(
        mesh_outbound_enforcement,
        stream_ctx.listen_port,
        &params.backend_host,
        params.backend_port,
        params.backend_scheme,
        proxy_id,
        remote_addr.ip(),
    )?;

    let plugins = epoch
        .plugin_cache
        .get_plugins_for_protocol(proxy_id, ProxyProtocol::Tcp);

    // Whether any plugin (e.g. the WAF) wants the opening client bytes captured
    // into `stream_ctx.first_bytes` before `on_stream_connect` runs. Computed
    // once; when false the splice/kTLS fast paths are left completely untouched.
    //
    // Two tiers: the cheap non-destructive peek (plain/passthrough) vs. the
    // consuming decrypted read after TLS termination, which blocks until the
    // client speaks and disables kTLS splice. Keeping them separate means a
    // guard-only config (`tcp_require_tls`, a no-op post-handshake) never stalls
    // a TLS-terminating, server-first backend for inspection it won't perform.
    let scan_first_bytes = plugins.iter().any(|p| p.requires_stream_first_bytes());
    let scan_first_bytes_decrypted = plugins
        .iter()
        .any(|p| p.requires_stream_first_bytes_decrypted());

    // Smallest opening-byte prefix any first-bytes-aware plugin needs to classify
    // a plain/passthrough stream (e.g. the 6-byte TLS record+handshake prefix the
    // `tcp_require_tls` shape guard checks). The non-destructive peek below keeps
    // reading the socket buffer until at least this many bytes are available (or
    // the handshake deadline fires), so a ClientHello split across TCP segments
    // is not misread as non-TLS. `0` for signature-only configs preserves the
    // single-peek behavior. Only computed when a peek will actually happen.
    let first_bytes_min_len = if scan_first_bytes {
        plugins
            .iter()
            .map(|p| p.stream_first_bytes_min_len())
            .max()
            .unwrap_or(0)
    } else {
        0
    };

    // ----- Passthrough mode: forward encrypted bytes without TLS termination -----
    if params.passthrough {
        let mut cb_info = cb_info;
        // Peek at the ClientHello to extract SNI for logging/routing.
        // Skip if already extracted during SNI-based proxy resolution above.
        if stream_ctx.sni_hostname.is_none() {
            stream_ctx.sni_hostname =
                super::sni::extract_sni_from_tcp_stream(&client_stream, sni_peek_timeout).await;
        }

        // Passthrough forwards ciphertext the gateway never decrypts, so the
        // captured bytes are only good for transport-shape checks (e.g.
        // validating a TLS ClientHello), never L7 — hence `EncryptedWire`.
        if scan_first_bytes {
            stream_ctx.first_bytes =
                peek_tcp_first_bytes(&client_stream, sni_peek_timeout, first_bytes_min_len).await;
            // Preserve the wire kind even when the timed peek observes no bytes:
            // first-bytes-aware plugins use this to distinguish encrypted
            // passthrough (not L7-inspectable) from missing plaintext.
            stream_ctx.first_bytes_kind = Some(StreamBytesKind::EncryptedWire);
        }

        // Run on_stream_connect plugins (they see SNI but not decrypted data).
        if !plugins.is_empty() {
            run_tcp_stream_connect_plugins(
                plugins.as_ref(),
                stream_ctx,
                &client_stream,
                proxy_id,
                remote_addr.ip(),
                "TCP passthrough",
                "(passthrough)",
            )
            .await?;
        }

        // Circuit breaker check — reject before DNS resolution or backend
        // connect if the passthrough target is open. This mirrors the
        // terminating TCP path; passthrough still records backend outcomes
        // below, so it must also honor breaker admission and preserve the
        // half-open probe flag for the matching record_success/failure call.
        if let Some(ref cb_config) = cb_info.cb_config {
            match circuit_breaker_cache.can_execute(
                proxy_id,
                cb_info.cb_target_key.as_deref(),
                cb_config,
            ) {
                Ok((_cb, is_half_open_probe)) => {
                    cb_info.is_half_open_probe = is_half_open_probe;
                }
                Err(_) => {
                    warn!(
                        proxy_id = %proxy_id,
                        client = %remote_addr,
                        "TCP passthrough connection rejected: circuit breaker open"
                    );
                    return Err(StreamSetupError::new(
                        StreamSetupKind::CircuitBreakerOpen,
                        format!("for {}:{}", params.backend_host, params.backend_port),
                    )
                    .into());
                }
            }
        }

        let connect_timeout = Duration::from_millis(params.backend_connect_timeout_ms);
        let idle_timeout = if params.tcp_idle_timeout_seconds > 0 {
            Some(Duration::from_secs(params.tcp_idle_timeout_seconds))
        } else {
            None
        };
        let half_close_cap = if params.tcp_half_close_max_wait_seconds > 0 {
            Some(Duration::from_secs(params.tcp_half_close_max_wait_seconds))
        } else {
            None
        };
        let backend_read_timeout = if params.backend_read_timeout_ms > 0 {
            Some(Duration::from_millis(params.backend_read_timeout_ms))
        } else {
            None
        };
        let backend_write_timeout = if params.backend_write_timeout_ms > 0 {
            Some(Duration::from_millis(params.backend_write_timeout_ms))
        } else {
            None
        };
        // Linux passthrough is always plain-to-plain raw TCP, so the splice
        // path always runs. Backend directional timeouts are enforced inside
        // the splice loops via per-direction watermarks — there is no longer
        // a userspace-copy fallback for this branch.
        #[cfg(target_os = "linux")]
        let splice_used = true;
        #[cfg(not(target_os = "linux"))]
        let splice_used = false;

        // Resolve backend IP via DNS. A resolution failure is a backend
        // reachability failure: record it against the breaker (mirrors the
        // non-passthrough path) so the failure counts toward opening AND any
        // half-open probe slot claimed by can_execute above is released —
        // otherwise an unresolvable passthrough hostname wedges HALF_OPEN
        // until reload.
        let resolved_ip = match dns_cache
            .resolve(
                &params.backend_host,
                params.dns_override.as_deref(),
                params.dns_cache_ttl_seconds,
            )
            .await
        {
            Ok(ip) => ip,
            Err(e) => {
                if let Some(ref cb_config) = cb_info.cb_config {
                    let cb = circuit_breaker_cache.get_or_create(
                        proxy_id,
                        cb_info.cb_target_key.as_deref(),
                        cb_config,
                    );
                    // A gateway-side egress-policy denial (literal / dns_override /
                    // rebound passthrough host blocked) dialed no backend, so it
                    // must NOT trip the breaker as a connect failure — release any
                    // HALF_OPEN probe slot NEUTRALLY (mirrors the non-passthrough
                    // TCP/UDP paths). Genuine DNS/transport failures still count.
                    if crate::dns::is_egress_policy_denial(&e) {
                        cb.record_neutral(cb_info.is_half_open_probe);
                    } else {
                        cb.record_failure(502, true, cb_info.is_half_open_probe);
                    }
                }
                return Err(anyhow::anyhow!(
                    "DNS resolution failed for {}: {}",
                    params.backend_host,
                    e
                ));
            }
        };
        let addr = SocketAddr::new(resolved_ip, params.backend_port);
        backend_info.backend_resolved_ip = Some(resolved_ip.to_string());

        // DestinationRule `connectionPool.tcp.maxConnections` enforcement on
        // the passthrough path. The cap is checked before connect so we don't
        // count failed handshakes against the cap. The guard's RAII drop
        // covers every relay exit (graceful EOF, idle timeout, error).
        let passthrough_port_override = resolve_port_override(&params, params.backend_policy_port);
        let _backend_inflight_guard = match acquire_backend_inflight_slot(
            passthrough_port_override,
            metrics,
            &params.backend_host,
            params.backend_policy_port,
        ) {
            Ok(guard) => guard,
            Err(reason) => {
                warn!(
                    proxy_id = %proxy_id,
                    backend = %format_backend_target(&params.backend_host, params.backend_port),
                    reason = %reason,
                    "TCP passthrough rejected: backend maxConnections reached"
                );
                // This is a gateway-local policy rejection, not a backend
                // outcome. If the breaker admission above claimed a
                // half-open probe slot, release it neutrally so passthrough
                // traffic cannot wedge HALF_OPEN.
                if let Some(ref cb_config) = cb_info.cb_config {
                    let cb = circuit_breaker_cache.get_or_create(
                        proxy_id,
                        cb_info.cb_target_key.as_deref(),
                        cb_config,
                    );
                    cb.record_neutral(cb_info.is_half_open_probe);
                }
                return Err(StreamSetupError::with_source(
                    StreamSetupKind::BackendMaxConnectionsExceeded,
                    format!(
                        "for {}",
                        format_backend_target(&params.backend_host, params.backend_port)
                    ),
                    reason,
                )
                .into());
            }
        };

        // Connect plain TCP to backend (no TLS origination — the client's encrypted
        // stream passes through directly to the backend which terminates TLS).
        let backend_stream =
            connect_backend_plain(addr, connect_timeout, params.tcp_fastopen_enabled, overload)
                .await
                .inspect_err(|_| {
                    if let Some(ref cb_config) = cb_info.cb_config {
                        let cb = circuit_breaker_cache.get_or_create(
                            proxy_id,
                            cb_info.cb_target_key.as_deref(),
                            cb_config,
                        );
                        cb.record_failure(502, true, cb_info.is_half_open_probe);
                    }
                })?;

        // Apply DR `connectionPool.tcp.tcpKeepalive` on the freshly connected
        // backend socket. Best-effort: a `setsockopt` failure logs and
        // continues rather than dropping the connection.
        apply_backend_tcp_keepalive(
            proxy_id,
            &backend_stream,
            passthrough_port_override.and_then(|o| o.tcp_keepalive.as_ref()),
        );

        let _backend_session_guard = TcpBackendSessionGuard::new(metrics);
        let buf_size = adaptive_buffer.get_buffer_size(proxy_id);

        // On Linux, use splice(2) for zero-copy relay between raw TCP sockets.
        // Passthrough mode is always plain-to-plain (no TLS termination/origination).
        // When io_uring is enabled, use IORING_OP_SPLICE on dedicated blocking threads.
        // Both splice paths enforce backend_{read,write}_timeout_ms via per-direction
        // watermarks inside their loops, so we no longer fall back to bidirectional_copy.
        #[cfg(target_os = "linux")]
        let copy_result = if io_uring_splice_enabled {
            bidirectional_splice_io_uring_bounded_or_async(
                client_stream,
                backend_stream,
                idle_timeout,
                half_close_cap,
                backend_read_timeout,
                backend_write_timeout,
                buf_size,
            )
            .await
        } else {
            bidirectional_splice(
                client_stream,
                backend_stream,
                idle_timeout,
                half_close_cap,
                backend_read_timeout,
                backend_write_timeout,
                buf_size,
            )
            .await
        };
        #[cfg(not(target_os = "linux"))]
        let copy_result = bidirectional_copy(
            client_stream,
            backend_stream,
            idle_timeout,
            half_close_cap,
            backend_read_timeout,
            backend_write_timeout,
            buf_size,
        )
        .await;

        // Only feed SUCCESSFUL relay sizes into the adaptive buffer tracker.
        // Failed relays (connect error, TLS failure, mid-stream RST) contribute
        // zero or partial-byte samples that would pull the EWMA down during
        // outage bursts and hurt buffer sizing after recovery. The circuit
        // breaker below separately records the success/failure outcome — this
        // gate only affects buffer-size adaptation.
        if copy_result.first_failure.is_none() {
            adaptive_buffer.record_connection(
                proxy_id,
                copy_result
                    .bytes_client_to_backend
                    .saturating_add(copy_result.bytes_backend_to_client),
            );
        }

        // Record circuit breaker outcome.
        if let Some(ref cb_config) = cb_info.cb_config {
            let cb = circuit_breaker_cache.get_or_create(
                proxy_id,
                cb_info.cb_target_key.as_deref(),
                cb_config,
            );
            if copy_result.first_failure.is_some() {
                cb.record_failure(502, true, cb_info.is_half_open_probe);
            } else {
                cb.record_success(cb_info.is_half_open_probe);
            }
        }

        return Ok(TcpConnectionSuccess {
            bytes_in: copy_result.bytes_client_to_backend,
            bytes_out: copy_result.bytes_backend_to_client,
            duration: start.elapsed(),
            splice_used,
            first_failure: copy_result.first_failure,
        });
    }

    let is_backend_tls = params.backend_scheme == BackendScheme::Tcps;
    let connect_timeout = Duration::from_millis(params.backend_connect_timeout_ms);
    let idle_timeout = if params.tcp_idle_timeout_seconds > 0 {
        Some(Duration::from_secs(params.tcp_idle_timeout_seconds))
    } else {
        None
    };
    let half_close_cap = if params.tcp_half_close_max_wait_seconds > 0 {
        Some(Duration::from_secs(params.tcp_half_close_max_wait_seconds))
    } else {
        None
    };
    let backend_read_timeout = if params.backend_read_timeout_ms > 0 {
        Some(Duration::from_millis(params.backend_read_timeout_ms))
    } else {
        None
    };
    let backend_write_timeout = if params.backend_write_timeout_ms > 0 {
        Some(Duration::from_millis(params.backend_write_timeout_ms))
    } else {
        None
    };
    // Terminating TCP-TLS should complete the downstream TLS handshake before
    // opening an upstream connection. This avoids spending backend sockets or
    // handshakes on clients that fail frontend TLS or are rejected by
    // stream-connect plugins, matching the conservative enterprise proxy
    // ordering for TLS-terminating TCP listeners.
    // Carries the decrypted opening bytes consumed from a TLS-terminated client
    // so they can be forwarded to the backend before the relay starts. `Some`
    // (even when empty) means we read plaintext from the TLS session and must
    // therefore use a userspace relay (kTLS splice is no longer possible).
    let mut client_first_bytes_forward: Option<Vec<u8>> = None;
    let client_stream = if let Some(tls_config) = frontend_tls_config {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.clone());
        // Frontend TLS failures return before any backend dispatch — no backend
        // circuit-breaker, pool, or socket interaction.
        // The typed `StreamSetupError` carries the kind so
        // `pre_copy_disconnect_cause` reads `Frontend` directly from
        // `StreamSetupKind::FrontendTlsHandshake`, no string match. The accept
        // helper bounds the handshake under the configured timeout so a stalled
        // peer cannot wedge a frontend slot indefinitely.
        let mut tls_stream = crate::tls::accept_with_optional_timeout(
            &acceptor,
            client_stream,
            frontend_tls_handshake_timeout_seconds,
            &remote_addr,
            record_mesh_mtls_metric,
        )
        .await
        .map_err(|e| -> anyhow::Error {
            StreamSetupError::with_source(
                StreamSetupKind::FrontendTlsHandshake,
                format!("from {remote_addr}: {e}"),
                e,
            )
            .into()
        })?;

        // Extract peer certificate DER from TLS handshake for plugin use.
        let peer_chain_der = tls_stream.get_ref().1.peer_certificates().map(|certs| {
            certs
                .iter()
                .map(|cert| cert.to_vec())
                .collect::<Vec<Vec<u8>>>()
        });
        let peer_cert_der = peer_chain_der
            .as_ref()
            .and_then(|certs| certs.first().cloned())
            .map(Arc::new);
        let peer_chain_tail_der = peer_chain_der.and_then(|mut certs| {
            if certs.len() <= 1 {
                None
            } else {
                certs.remove(0);
                Some(Arc::new(certs))
            }
        });
        stream_ctx.tls_client_cert_der = peer_cert_der;
        stream_ctx.tls_client_cert_chain_der = peer_chain_tail_der;
        stream_ctx.sni_hostname = tls_stream
            .get_ref()
            .1
            .server_name()
            .map(str::to_ascii_lowercase);

        // Mark the connection as TLS-terminated for any first-bytes-aware
        // plugin, even when we don't read application bytes below. This lets a
        // transport-shape guard like `tcp_require_tls` recognize the stream as
        // already-TLS (the handshake proved it) instead of failing closed on the
        // absent bytes.
        if scan_first_bytes {
            stream_ctx.first_bytes_kind = Some(StreamBytesKind::DecryptedApp);
        }

        // Capture the opening *decrypted* application bytes for L7 inspection
        // before on_stream_connect runs, so a plugin can reject before any
        // backend is dialed. This consumes the bytes from the TLS session, so
        // we forward them to the backend below and fall back to a userspace
        // relay (kTLS splice needs the raw, undisturbed TLS record stream).
        //
        // Gated on the decrypted-specific signal: a transport-shape guard like
        // `tcp_require_tls` is already satisfied by the completed handshake, so
        // it must not trigger this blocking read on a server-first backend.
        if scan_first_bytes_decrypted {
            let prefix = read_decrypted_first_bytes(&mut tls_stream, sni_peek_timeout).await;
            if !prefix.is_empty() {
                stream_ctx.first_bytes = Some(bytes::Bytes::copy_from_slice(&prefix));
            }
            client_first_bytes_forward = Some(prefix);
        }

        // Run on_stream_connect plugins after TLS handshake so client cert is available.
        if !plugins.is_empty() {
            run_tcp_stream_connect_plugins(
                plugins.as_ref(),
                stream_ctx,
                tls_stream.get_ref().0,
                proxy_id,
                remote_addr.ip(),
                "TCP/TLS",
                "(TCP/TLS)",
            )
            .await?;
        }

        ClientRelayStream::Tls(Box::new(tls_stream))
    } else {
        // Plaintext client: peek (non-destructively) the opening bytes. These are
        // the application bytes on the wire, so they are fully L7-inspectable and
        // the relay (including splice) still forwards them unchanged.
        if scan_first_bytes {
            stream_ctx.first_bytes =
                peek_tcp_first_bytes(&client_stream, sni_peek_timeout, first_bytes_min_len).await;
            // Preserve the wire kind even when the timed peek observes no bytes:
            // an enforcing stream WAF must fail closed instead of letting an
            // idle client send unchecked bytes after the relay starts.
            stream_ctx.first_bytes_kind = Some(StreamBytesKind::PlaintextWire);
        }
        if !plugins.is_empty() {
            run_tcp_stream_connect_plugins(
                plugins.as_ref(),
                stream_ctx,
                &client_stream,
                proxy_id,
                remote_addr.ip(),
                "TCP",
                "(TCP)",
            )
            .await?;
        }
        ClientRelayStream::Plain(client_stream)
    };

    // Helper: record circuit breaker failure for the current target.
    let record_cb_failure = |cb_cache: &CircuitBreakerCache,
                             proxy_id: &str,
                             cb_info: &TcpConnCbInfo| {
        if let Some(ref cb_config) = cb_info.cb_config {
            let cb = cb_cache.get_or_create(proxy_id, cb_info.cb_target_key.as_deref(), cb_config);
            cb.record_failure(502, true, cb_info.is_half_open_probe);
        }
    };

    // Helper: release a half-open probe slot claimed by `can_execute` without
    // recording success or failure. Used when the gateway rejects the
    // connection locally (DestinationRule maxConnections cap), which is not a
    // backend outcome — `record_neutral` decrements `half_open_in_flight` only
    // when a probe was held and leaves breaker health untouched.
    let record_cb_neutral = |cb_cache: &CircuitBreakerCache,
                             proxy_id: &str,
                             cb_info: &TcpConnCbInfo| {
        if let Some(ref cb_config) = cb_info.cb_config {
            let cb = cb_cache.get_or_create(proxy_id, cb_info.cb_target_key.as_deref(), cb_config);
            cb.record_neutral(cb_info.is_half_open_probe);
        }
    };

    // Connection-phase retry loop. Retries DNS resolution + backend connect
    // with a different load-balanced target on each attempt. Once a backend
    // connection is established, bidirectional_copy begins and no further
    // retries are possible (bytes may have been exchanged).
    let can_retry = params
        .retry
        .as_ref()
        .is_some_and(|r| r.retry_on_connect_failure);
    let max_retries = params.retry.as_ref().map(|r| r.max_retries).unwrap_or(0);
    let mut current_host = params.backend_host.clone();
    let mut current_port = params.backend_port;
    let mut current_policy_port = params.backend_policy_port;
    let mut current_cb_info = cb_info;
    let mut last_connect_err: Option<anyhow::Error> = None;

    let mut attempt = 0u32;
    let backend_addr = loop {
        // Circuit breaker check — reject before attempting backend connection if open.
        // When admitted, capture whether this is a half-open probe so downstream
        // record_failure/record_success calls only decrement the in-flight counter
        // for actual probe requests.
        if let Some(ref cb_config) = current_cb_info.cb_config {
            match circuit_breaker_cache.can_execute(
                proxy_id,
                current_cb_info.cb_target_key.as_deref(),
                cb_config,
            ) {
                Ok((_cb, is_half_open_probe)) => {
                    current_cb_info.is_half_open_probe = is_half_open_probe;
                }
                Err(_) => {
                    if can_retry && attempt < max_retries {
                        // Circuit open on this target — try another
                        if let Some(next) = try_next_enforced_target(
                            &params,
                            proxy,
                            health_checker,
                            &current_host,
                            current_port,
                            current_policy_port,
                            &epoch.load_balancer,
                            mesh_outbound_enforcement,
                            stream_ctx.listen_port,
                            proxy_id,
                            remote_addr.ip(),
                        )? {
                            warn!(
                                proxy_id = %proxy_id,
                                attempt,
                                "TCP circuit breaker open for {}:{}, trying {}:{}",
                                current_host, current_port, next.0, next.1
                            );
                            current_host = next.0;
                            current_port = next.1;
                            current_policy_port = next.2;
                            current_cb_info = TcpConnCbInfo {
                                cb_config: current_cb_info.cb_config.clone(),
                                cb_target_key: params.upstream_id.as_ref().map(|_| {
                                    crate::circuit_breaker::target_key(&current_host, current_port)
                                }),
                                is_half_open_probe: false,
                            };
                            // Update backend info to reflect the retry target.
                            backend_info.backend_target =
                                format_backend_target(&current_host, current_port);
                            backend_info.backend_resolved_ip = None;
                            attempt += 1;
                            continue;
                        }
                    }
                    warn!(proxy_id = %proxy_id, client = %remote_addr, "TCP connection rejected: circuit breaker open");
                    return Err(StreamSetupError::new(
                        StreamSetupKind::CircuitBreakerOpen,
                        format!("for {}:{}", current_host, current_port),
                    )
                    .into());
                }
            }
        }

        // Resolve backend IP via DNS
        let resolved_ip = match dns_cache
            .resolve(
                &current_host,
                params.dns_override.as_deref(),
                params.dns_cache_ttl_seconds,
            )
            .await
        {
            Ok(ip) => ip,
            Err(e) => {
                // A backend-egress-policy denial means no backend was dialed, so
                // keep circuit-breaker accounting neutral (a denied literal/rebound
                // target must not trip the breaker as a connect failure). Genuine
                // DNS/transport failures still record a CB failure. Either way we
                // must settle a HALF_OPEN probe slot `can_execute` admitted — a
                // policy denial releases it NEUTRALLY (no count) rather than
                // leaking it, else `half_open_in_flight` stays consumed and the
                // breaker can never recover.
                if crate::dns::is_egress_policy_denial(&e) {
                    record_cb_neutral(circuit_breaker_cache, proxy_id, &current_cb_info);
                } else {
                    record_cb_failure(circuit_breaker_cache, proxy_id, &current_cb_info);
                }
                let err_msg = format!("DNS resolution failed for {}: {}", current_host, e);
                if can_retry
                    && attempt < max_retries
                    && let Some(next) = try_next_enforced_target(
                        &params,
                        proxy,
                        health_checker,
                        &current_host,
                        current_port,
                        current_policy_port,
                        &epoch.load_balancer,
                        mesh_outbound_enforcement,
                        stream_ctx.listen_port,
                        proxy_id,
                        remote_addr.ip(),
                    )?
                {
                    warn!(
                        proxy_id = %proxy_id,
                        attempt,
                        "TCP DNS failed for {}:{}, retrying with {}:{}",
                        current_host, current_port, next.0, next.1
                    );
                    current_host = next.0;
                    current_port = next.1;
                    current_policy_port = next.2;
                    current_cb_info = TcpConnCbInfo {
                        cb_config: current_cb_info.cb_config.clone(),
                        cb_target_key: params.upstream_id.as_ref().map(|_| {
                            crate::circuit_breaker::target_key(&current_host, current_port)
                        }),
                        is_half_open_probe: false,
                    };
                    // Update backend info to reflect the retry target.
                    backend_info.backend_target =
                        format_backend_target(&current_host, current_port);
                    backend_info.backend_resolved_ip = None;
                    last_connect_err = Some(anyhow::anyhow!(err_msg));
                    attempt += 1;
                    if let Some(ref retry_config) = params.retry {
                        tokio::time::sleep(crate::retry::retry_delay(retry_config, attempt)).await;
                    }
                    continue;
                }
                return Err(anyhow::anyhow!(err_msg));
            }
        };
        let addr = SocketAddr::new(resolved_ip, current_port);
        // DNS succeeded — record the resolved IP for logging.
        backend_info.backend_resolved_ip = Some(resolved_ip.to_string());

        // DestinationRule `connectionPool.tcp.maxConnections` enforcement on
        // the non-passthrough connect path. Checked once per retry attempt
        // so failed dials don't consume slots; the guard's `Drop` impl
        // releases the slot when the relay future ends.
        //
        // The slot is rebuilt on each retry against `current_host` and the
        // current target's policy port, so sibling service-port lanes that
        // share a workload dial port keep independent caps. The actual socket
        // still dials `current_port`. `_backend_inflight_guard_attempt` is
        // shadowed at every loop entry — only the latest successful guard
        // survives past the `break`.
        let current_port_override = resolve_port_override(&params, current_policy_port);
        let backend_inflight_guard_attempt = match acquire_backend_inflight_slot(
            current_port_override,
            metrics,
            &current_host,
            current_policy_port,
        ) {
            Ok(guard) => guard,
            Err(reason) => {
                warn!(
                    proxy_id = %proxy_id,
                    backend = %format_backend_target(&current_host, current_port),
                    reason = %reason,
                    "TCP backend rejected: maxConnections reached"
                );
                // Release any half-open probe slot claimed for this target
                // before retrying (which resets is_half_open_probe) or
                // returning (which records no outcome). A gateway-local
                // maxConnections rejection must not leak the probe slot —
                // otherwise a HALF_OPEN breaker stays wedged (always rejecting)
                // until a config reload. This is neutral: the cap is not a
                // backend failure.
                record_cb_neutral(circuit_breaker_cache, proxy_id, &current_cb_info);
                if can_retry
                    && attempt < max_retries
                    && let Some(next) = try_next_enforced_target(
                        &params,
                        proxy,
                        health_checker,
                        &current_host,
                        current_port,
                        current_policy_port,
                        &epoch.load_balancer,
                        mesh_outbound_enforcement,
                        stream_ctx.listen_port,
                        proxy_id,
                        remote_addr.ip(),
                    )?
                {
                    current_host = next.0;
                    current_port = next.1;
                    current_policy_port = next.2;
                    current_cb_info = TcpConnCbInfo {
                        cb_config: current_cb_info.cb_config.clone(),
                        cb_target_key: params.upstream_id.as_ref().map(|_| {
                            crate::circuit_breaker::target_key(&current_host, current_port)
                        }),
                        is_half_open_probe: false,
                    };
                    backend_info.backend_target =
                        format_backend_target(&current_host, current_port);
                    backend_info.backend_resolved_ip = None;
                    last_connect_err = Some(
                        StreamSetupError::with_source(
                            StreamSetupKind::BackendMaxConnectionsExceeded,
                            format!("for {}", format_backend_target(&current_host, current_port)),
                            reason,
                        )
                        .into(),
                    );
                    attempt += 1;
                    if let Some(ref retry_config) = params.retry {
                        tokio::time::sleep(crate::retry::retry_delay(retry_config, attempt)).await;
                    }
                    continue;
                }
                return Err(StreamSetupError::with_source(
                    StreamSetupKind::BackendMaxConnectionsExceeded,
                    format!("for {}", format_backend_target(&current_host, current_port)),
                    reason,
                )
                .into());
            }
        };

        // Attempt backend TCP connection (with optional TLS origination)
        let connect_result = if is_backend_tls {
            connect_backend_tls_cached(
                addr,
                &current_host,
                connect_timeout,
                cached_backend_tls,
                params.tcp_fastopen_enabled,
                overload,
                current_port_override.and_then(|o| o.tcp_keepalive.as_ref()),
                proxy_id,
            )
            .await
            .map(|s| BackendStream::Tls(Box::new(s)))
        } else {
            connect_backend_plain(addr, connect_timeout, params.tcp_fastopen_enabled, overload)
                .await
                .inspect(|stream| {
                    apply_backend_tcp_keepalive(
                        proxy_id,
                        stream,
                        current_port_override.and_then(|o| o.tcp_keepalive.as_ref()),
                    );
                })
                .map(BackendStream::Plain)
        };

        match connect_result {
            Ok(_stream) => {
                // Connection succeeded — break out of retry loop with the
                // address, carrying the inflight guard so the per-target
                // counter is decremented at relay exit.
                break (addr, _stream, backend_inflight_guard_attempt);
            }
            Err(e) => {
                record_cb_failure(circuit_breaker_cache, proxy_id, &current_cb_info);
                if can_retry
                    && attempt < max_retries
                    && let Some(next) = try_next_enforced_target(
                        &params,
                        proxy,
                        health_checker,
                        &current_host,
                        current_port,
                        current_policy_port,
                        &epoch.load_balancer,
                        mesh_outbound_enforcement,
                        stream_ctx.listen_port,
                        proxy_id,
                        remote_addr.ip(),
                    )?
                {
                    warn!(
                        proxy_id = %proxy_id,
                        attempt,
                        error = %e,
                        "TCP connect failed to {}:{}, retrying with {}:{}",
                        current_host, current_port, next.0, next.1
                    );
                    current_host = next.0;
                    current_port = next.1;
                    current_policy_port = next.2;
                    current_cb_info = TcpConnCbInfo {
                        cb_config: current_cb_info.cb_config.clone(),
                        cb_target_key: params.upstream_id.as_ref().map(|_| {
                            crate::circuit_breaker::target_key(&current_host, current_port)
                        }),
                        is_half_open_probe: false,
                    };
                    // Update backend info to reflect the retry target.
                    backend_info.backend_target =
                        format_backend_target(&current_host, current_port);
                    backend_info.backend_resolved_ip = None;
                    last_connect_err = Some(e);
                    attempt += 1;
                    if let Some(ref retry_config) = params.retry {
                        tokio::time::sleep(crate::retry::retry_delay(retry_config, attempt)).await;
                    }
                    continue;
                }
                return Err(e);
            }
        }
    };
    let (_backend_socket_addr, mut backend_stream, _backend_inflight_guard) = backend_addr;
    let _ = last_connect_err; // consumed by retry loop logging
    let _backend_session_guard = TcpBackendSessionGuard::new(metrics);

    // If first-bytes inspection consumed a decrypted opening prefix from a
    // TLS-terminated client, forward it to the backend now — re-encrypting when
    // the backend leg is TLS — before the relay starts, so no application bytes
    // are lost. Reading plaintext also rules out the zero-copy kTLS splice path,
    // so force the userspace relay for this connection.
    let forwarded_prefix_len = match client_first_bytes_forward.as_deref() {
        Some(prefix) if !prefix.is_empty() => {
            use tokio::io::AsyncWriteExt;
            let write_res = match &mut backend_stream {
                BackendStream::Tls(bs) => bs.write_all(prefix).await,
                BackendStream::Plain(bs) => bs.write_all(prefix).await,
            };
            write_res.map_err(|e| {
                anyhow::anyhow!("failed forwarding inspected first bytes to backend: {e}")
            })?;
            prefix.len() as u64
        }
        _ => 0,
    };

    // Start bidirectional copy. From here, no retries — bytes may be exchanged.
    let mut used_splice = false;
    let copy_result = match client_stream {
        ClientRelayStream::Tls(tls_stream) => {
            let tls_stream = *tls_stream;
            let buf_size = adaptive_buffer.get_buffer_size(proxy_id);
            match backend_stream {
                BackendStream::Tls(bs) => {
                    bidirectional_copy(
                        tls_stream,
                        bs,
                        idle_timeout,
                        half_close_cap,
                        backend_read_timeout,
                        backend_write_timeout,
                        buf_size,
                    )
                    .await
                }
                BackendStream::Plain(bs) => {
                    // On Linux with kTLS, attempt to install TLS keys into the kernel
                    // so splice(2) can handle encrypted traffic without userspace copies.
                    // backend_{read,write}_timeout are enforced inside the splice loop
                    // via per-direction watermarks; no eligibility gate required.
                    // Skip kTLS when first-bytes inspection consumed a decrypted
                    // prefix: those plaintext bytes have already left the TLS
                    // session, so the userspace relay must carry the remainder.
                    //
                    // Issue #2955: `try_ktls_splice` additionally refuses handoff
                    // from the buffered tokio-rustls `TlsStream` because the
                    // public buffered rustls API cannot prove inbound record
                    // alignment; those connections keep the userspace relay.
                    #[cfg(target_os = "linux")]
                    {
                        if ktls_enabled && client_first_bytes_forward.is_none() {
                            match try_ktls_splice(
                                tls_stream,
                                bs,
                                idle_timeout,
                                half_close_cap,
                                backend_read_timeout,
                                backend_write_timeout,
                                buf_size,
                            )
                            .await
                            {
                                Ok(result) => {
                                    used_splice = true;
                                    result
                                }
                                Err(KtlsError::Unsupported(streams)) => {
                                    // kTLS not available for this cipher/version — fall back
                                    // to userspace copy with the TLS stream intact.
                                    let (tls_stream_back, bs_back) = *streams;
                                    bidirectional_copy(
                                        tls_stream_back,
                                        bs_back,
                                        idle_timeout,
                                        half_close_cap,
                                        backend_read_timeout,
                                        backend_write_timeout,
                                        buf_size,
                                    )
                                    .await
                                }
                                Err(KtlsError::Installed(e)) => {
                                    // Unrecoverable: TLS stream was consumed via into_inner()
                                    // + dangerous_extract_secrets(). The raw TcpStream has no
                                    // TLS layer — bidirectional_copy would forward plaintext.
                                    // This path only triggers if SOL_TLS key install fails
                                    // AFTER the pre-flight TCP_ULP probe succeeded (e.g.,
                                    // kernel cipher mismatch or ENOMEM). In practice this is
                                    // extremely rare since we validate cipher/version before
                                    // extracting secrets. Attribute the failure at the
                                    // bidirectional-copy boundary — no bytes were exchanged
                                    // through the proxy path, so per-direction counts are 0.
                                    StreamCopyResult {
                                        bytes_client_to_backend: 0,
                                        bytes_backend_to_client: 0,
                                        first_failure: Some((
                                            Direction::Unknown,
                                            classify_stream_error(&e),
                                            None,
                                            e.to_string(),
                                        )),
                                    }
                                }
                            }
                        } else {
                            bidirectional_copy(
                                tls_stream,
                                bs,
                                idle_timeout,
                                half_close_cap,
                                backend_read_timeout,
                                backend_write_timeout,
                                buf_size,
                            )
                            .await
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        bidirectional_copy(
                            tls_stream,
                            bs,
                            idle_timeout,
                            half_close_cap,
                            backend_read_timeout,
                            backend_write_timeout,
                            buf_size,
                        )
                        .await
                    }
                }
            }
        }
        ClientRelayStream::Plain(client_stream) => {
            let buf_size = adaptive_buffer.get_buffer_size(proxy_id);
            match backend_stream {
                BackendStream::Tls(bs) => {
                    used_splice = false;
                    bidirectional_copy(
                        client_stream,
                        bs,
                        idle_timeout,
                        half_close_cap,
                        backend_read_timeout,
                        backend_write_timeout,
                        buf_size,
                    )
                    .await
                }
                BackendStream::Plain(bs) => {
                    // On Linux, use splice(2) for zero-copy relay when both sides
                    // are raw TCP (no frontend TLS, no backend TLS). When io_uring
                    // is enabled, use IORING_OP_SPLICE on blocking threads. Both
                    // splice paths enforce backend_{read,write}_timeout_ms via
                    // per-direction watermarks inside their loops.
                    #[cfg(target_os = "linux")]
                    {
                        used_splice = true;
                        if io_uring_splice_enabled {
                            bidirectional_splice_io_uring_bounded_or_async(
                                client_stream,
                                bs,
                                idle_timeout,
                                half_close_cap,
                                backend_read_timeout,
                                backend_write_timeout,
                                buf_size,
                            )
                            .await
                        } else {
                            bidirectional_splice(
                                client_stream,
                                bs,
                                idle_timeout,
                                half_close_cap,
                                backend_read_timeout,
                                backend_write_timeout,
                                buf_size,
                            )
                            .await
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        used_splice = false;
                        bidirectional_copy(
                            client_stream,
                            bs,
                            idle_timeout,
                            half_close_cap,
                            backend_read_timeout,
                            backend_write_timeout,
                            buf_size,
                        )
                        .await
                    }
                }
            }
        }
    };

    // Record adaptive buffer stats for the TLS/non-passthrough path.
    // Only feed SUCCESSFUL relay sizes into the adaptive buffer tracker — see
    // the passthrough-path site above for the full rationale. Failed relays
    // contribute zero/partial-byte samples that would poison the EWMA during
    // outage bursts.
    if copy_result.first_failure.is_none() {
        adaptive_buffer.record_connection(
            proxy_id,
            copy_result
                .bytes_client_to_backend
                .saturating_add(copy_result.bytes_backend_to_client),
        );
    }

    // Record circuit breaker outcome based on copy result.
    if let Some(ref cb_config) = current_cb_info.cb_config {
        let cb = circuit_breaker_cache.get_or_create(
            proxy_id,
            current_cb_info.cb_target_key.as_deref(),
            cb_config,
        );
        if copy_result.first_failure.is_some() {
            cb.record_failure(502, true, current_cb_info.is_half_open_probe);
        } else {
            cb.record_success(current_cb_info.is_half_open_probe);
        }
    }

    Ok(TcpConnectionSuccess {
        // Include the inspected prefix forwarded out-of-band above so the
        // client→backend byte count in the transaction summary stays accurate.
        bytes_in: copy_result
            .bytes_client_to_backend
            .saturating_add(forwarded_prefix_len),
        bytes_out: copy_result.bytes_backend_to_client,
        duration: start.elapsed(),
        splice_used: used_splice,
        first_failure: copy_result.first_failure,
    })
}

fn mesh_tcp_protocol_label(backend_scheme: BackendScheme) -> &'static str {
    if matches!(backend_scheme, BackendScheme::Tcps) {
        PROTOCOL_TCP_TLS
    } else {
        PROTOCOL_TCP
    }
}

fn enforce_mesh_tcp_outbound_target(
    enforcement: Option<&Arc<MeshOutboundEnforcement>>,
    listen_port: u16,
    backend_host: &str,
    backend_port: u16,
    backend_scheme: BackendScheme,
    proxy_id: &str,
    client_ip: IpAddr,
) -> Result<(), anyhow::Error> {
    let Some(enforcement) = enforcement else {
        return Ok(());
    };
    let protocol_label = mesh_tcp_protocol_label(backend_scheme);
    match enforcement.check_destination(listen_port, backend_host, backend_port) {
        Decision::Admit => {
            enforcement.record_stream_decision(protocol_label, Decision::Admit);
            Ok(())
        }
        Decision::Deny => {
            enforcement.record_stream_decision(protocol_label, Decision::Deny);
            warn!(
                proxy_id = %proxy_id,
                client = %client_ip,
                listen_port = listen_port,
                backend_target = %format_backend_target(backend_host, backend_port),
                protocol = protocol_label,
                "Mesh REGISTRY_ONLY: rejecting TCP egress to unadmitted destination"
            );
            Err(
                StreamSetupError::new(StreamSetupKind::RejectedByPlugin, "(mesh REGISTRY_ONLY)")
                    .into(),
            )
        }
        Decision::Skip => Ok(()),
    }
}

type TcpResolvedBackendTarget = (String, u16, u16, Option<u16>, Option<u16>);

/// Resolve the backend target — either direct from proxy config or via load balancer.
///
/// Per-port DestinationRule policy (LB algorithm, locality-LB) is engaged only when
/// every upstream target shares a single dispatch port (a non-zero
/// `initial_dispatch_port_override`) — the same pre-selection semantics the HTTP
/// dispatch path uses for single-port upstreams. The HTTP path's `backend_port`
/// fallback (`backend_dispatch::initial_dispatch_port`) is deliberately NOT used
/// here: for a stream proxy referencing an upstream, `backend_port` is a
/// placeholder, and a coincidental match with one overridden port of a mixed-port
/// upstream would silently pin selection to that port's targets.
///
/// Returns `(host, port, policy_port, port_lane, health_port_scope)` where
/// `port_lane` is the engaged per-port selection lane (if any) — connection-phase
/// retries must rotate inside the same lane (`try_next_target`). `health_port_scope`
/// records the per-port health/ejection scope independently from lane selection.
/// Stream target selection respects active health checks and passive ejection
/// state recorded by HTTP-family traffic.
fn resolve_backend_target(
    proxy: &Proxy,
    lb_snapshot: &LoadBalancerCacheInner,
    health_checker: &HealthChecker,
    lb_hash_key: &str,
) -> Result<TcpResolvedBackendTarget, anyhow::Error> {
    if let Some(upstream_id) = &proxy.upstream_id {
        let override_port =
            LoadBalancerCache::initial_dispatch_port_override_from(lb_snapshot, upstream_id);
        let health_port_scope = crate::proxy::backend_dispatch::stream_health_port_scope(
            proxy,
            lb_snapshot,
            upstream_id,
            override_port,
        );
        let port_lane = if health_port_scope.is_some()
            && tcp_port_lane_selection_supported(proxy, lb_snapshot, upstream_id, override_port)?
        {
            Some(override_port)
        } else {
            None
        };
        let health_ctx = crate::proxy::backend_dispatch::health_context_for_selection(
            proxy,
            health_checker,
            lb_snapshot,
            upstream_id,
            health_port_scope,
        );

        let selection = if let Some(subset_name) = proxy.upstream_subset.as_deref() {
            if let Some(port) = port_lane {
                LoadBalancerCache::select_target_for_port_subset_from(
                    lb_snapshot,
                    upstream_id,
                    lb_hash_key,
                    port,
                    subset_name,
                    Some(&health_ctx),
                )
            } else {
                LoadBalancerCache::select_target_subset_from(
                    lb_snapshot,
                    upstream_id,
                    lb_hash_key,
                    subset_name,
                    Some(&health_ctx),
                )
            }
        } else if let Some(port) = port_lane {
            LoadBalancerCache::select_target_for_port_from(
                lb_snapshot,
                upstream_id,
                lb_hash_key,
                port,
                Some(&health_ctx),
            )
        } else {
            LoadBalancerCache::select_target_from(
                lb_snapshot,
                upstream_id,
                lb_hash_key,
                Some(&health_ctx),
            )
        }
        .ok_or_else(|| -> anyhow::Error {
            let scope = proxy
                .upstream_subset
                .as_deref()
                .map(|subset| format!("for upstream {upstream_id} subset {subset}"))
                .unwrap_or_else(|| format!("for upstream {upstream_id}"));
            StreamSetupError::new(StreamSetupKind::NoHealthyTargets, scope).into()
        })?;
        Ok((
            selection.target.host.clone(),
            selection.target.port,
            selection.target.dispatch_policy_port(),
            port_lane,
            health_port_scope,
        ))
    } else {
        Ok((
            proxy.backend_host.clone(),
            proxy.backend_port,
            proxy.backend_port,
            None,
            None,
        ))
    }
}

fn tcp_port_lane_selection_supported(
    proxy: &Proxy,
    lb_snapshot: &LoadBalancerCacheInner,
    upstream_id: &str,
    port: u16,
) -> Result<bool, anyhow::Error> {
    let Some(override_config) = proxy
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&port))
    else {
        return Ok(false);
    };
    let unsupported_algorithm = match override_config.algorithm {
        Some(crate::config::types::LoadBalancerAlgorithm::LeastConnections) => Some("LEAST_CONN"),
        Some(crate::config::types::LoadBalancerAlgorithm::LeastLatency) => Some("LEAST_LATENCY"),
        _ => None,
    };
    if let Some(algorithm) = unsupported_algorithm {
        return Err(StreamSetupError::new(
            StreamSetupKind::UnsupportedStreamPolicy,
            format!(
                "for TCP port {port}: per-port {algorithm} requires stream load-balancer accounting"
            ),
        )
        .into());
    }
    let selection_affecting = stream_port_override_affects_selection(
        proxy,
        lb_snapshot,
        upstream_id,
        port,
        override_config,
    );
    if selection_affecting {
        validate_stream_hash_on(proxy, lb_snapshot, upstream_id, port)?;
    }
    Ok(selection_affecting)
}

fn stream_port_override_affects_selection(
    proxy: &Proxy,
    lb_snapshot: &LoadBalancerCacheInner,
    upstream_id: &str,
    port: u16,
    override_config: &crate::config::types::ResolvedPortOverride,
) -> bool {
    if proxy.upstream_subset.is_some() && override_config.algorithm.is_none() {
        return override_config.locality_lb_setting.is_some()
            || (override_config.hash_on.is_some()
                && LoadBalancerCache::effective_algorithm_from(
                    lb_snapshot,
                    upstream_id,
                    Some(port),
                    proxy.upstream_subset.as_deref(),
                ) == Some(crate::config::types::LoadBalancerAlgorithm::ConsistentHashing));
    }
    override_config.algorithm.is_some()
        || override_config.hash_on.is_some()
        || override_config.locality_lb_setting.is_some()
}

fn stream_lb_hash_key_for_client_ip(ip: std::net::IpAddr) -> String {
    ip.to_canonical().to_string()
}

fn validate_stream_hash_on(
    proxy: &Proxy,
    lb_snapshot: &LoadBalancerCacheInner,
    upstream_id: &str,
    port: u16,
) -> Result<(), anyhow::Error> {
    let strategy = LoadBalancerCache::get_hash_on_strategy_for_selection_from(
        lb_snapshot,
        upstream_id,
        Some(port),
        proxy.upstream_subset.as_deref(),
    );
    if matches!(strategy, crate::load_balancer::HashOnStrategy::Ip) {
        return Ok(());
    }
    let protocol = proxy.effective_scheme();
    Err(StreamSetupError::new(
        StreamSetupKind::UnsupportedStreamPolicy,
        format!("for {protocol} port {port}: stream per-port consistent hashing supports only source-IP hash keys"),
    )
    .into())
}

#[cfg(test)]
mod backend_target_selection_tests {
    use super::*;
    use crate::config::types::UpstreamTarget;
    use serde_json::json;
    use std::collections::HashMap;

    fn proxy_with_subset(subset: Option<&str>) -> Proxy {
        serde_json::from_value(json!({
            "id": "tcp-proxy",
            "backend_host": "unused.local",
            "backend_port": 0,
            "backend_scheme": "tcp",
            "listen_port": 7000,
            "upstream_id": "orders",
            "upstream_subset": subset,
        }))
        .expect("proxy should deserialize")
    }

    fn config_with_subset() -> GatewayConfig {
        serde_json::from_value(json!({
            "version": "1",
            "proxies": [],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "orders",
                "targets": [
                    {
                        "host": "stable.local",
                        "port": 1001,
                        "tags": { "version": "stable" }
                    },
                    {
                        "host": "canary.local",
                        "port": 1002,
                        "tags": { "version": "canary" }
                    }
                ],
                "subsets": [{
                    "name": "canary",
                    "labels": { "version": "canary" }
                }]
            }]
        }))
        .expect("gateway config should deserialize")
    }

    fn config_with_two_targets() -> GatewayConfig {
        serde_json::from_value(json!({
            "version": "1",
            "proxies": [],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "orders",
                "targets": [
                    { "host": "allowed.local", "port": 5432 },
                    { "host": "blocked.local", "port": 5432 }
                ]
            }]
        }))
        .expect("gateway config should deserialize")
    }

    fn retry_params() -> TcpConnParams {
        TcpConnParams {
            backend_host: "allowed.local".to_string(),
            backend_port: 5432,
            backend_policy_port: 5432,
            backend_scheme: BackendScheme::Tcp,
            dns_override: None,
            dns_cache_ttl_seconds: None,
            backend_connect_timeout_ms: 1000,
            backend_read_timeout_ms: 0,
            backend_write_timeout_ms: 0,
            tcp_idle_timeout_seconds: 60,
            tcp_half_close_max_wait_seconds: 0,
            retry: None,
            upstream_id: Some("orders".to_string()),
            upstream_subset: None,
            lb_hash_key: "192.0.2.10".to_string(),
            passthrough: false,
            tcp_fastopen_enabled: false,
            dispatch_port_overrides: None,
            lb_port_lane: None,
            health_port_scope: None,
        }
    }

    #[test]
    fn stream_lb_hash_key_canonicalizes_ipv4_mapped_clients() {
        let mapped: std::net::IpAddr = "::ffff:192.0.2.10".parse().expect("mapped IPv4");
        let plain: std::net::IpAddr = "192.0.2.10".parse().expect("plain IPv4");
        let v6: std::net::IpAddr = "2001:db8::10".parse().expect("plain IPv6");

        assert_eq!(
            stream_lb_hash_key_for_client_ip(mapped),
            stream_lb_hash_key_for_client_ip(plain),
            "IPv4-mapped clients must hash like their plain IPv4 form"
        );
        assert_eq!(stream_lb_hash_key_for_client_ip(v6), "2001:db8::10");
    }

    fn enforcement(entries: &[&str]) -> std::sync::Arc<MeshOutboundEnforcement> {
        let registry = crate::plugins::mesh::outbound_registry::OutboundRegistry::new(&json!({
            "registry": entries
        }))
        .expect("valid registry");
        std::sync::Arc::new(MeshOutboundEnforcement::from_registry(
            "default",
            vec![15001],
            registry,
        ))
    }

    #[test]
    fn resolve_backend_target_honors_upstream_subset() {
        let config = config_with_subset();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let proxy = proxy_with_subset(Some("canary"));

        let (host, port, policy_port, port_lane, _) =
            resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
                .expect("target selected");

        assert_eq!(host, "canary.local");
        assert_eq!(port, 1002);
        assert_eq!(policy_port, 1002);
        assert_eq!(port_lane, None, "no port override configured");
    }

    #[test]
    fn resolve_backend_target_errors_for_unknown_subset() {
        let config = config_with_subset();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let proxy = proxy_with_subset(Some("missing"));

        let err = resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
            .expect_err("missing subset rejected");

        assert!(err.to_string().contains("subset missing"));
    }

    #[test]
    fn resolve_backend_target_skips_active_unhealthy_targets() {
        let mut config = config_with_two_targets();
        config.upstreams[0].algorithm = crate::config::types::LoadBalancerAlgorithm::RoundRobin;
        let unhealthy_target = config.upstreams[0].targets[0].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let mut proxy = proxy_with_subset(None);
        proxy.upstream_id = Some("orders".to_string());
        let health_checker = HealthChecker::new();
        health_checker.active_unhealthy_targets.insert(
            crate::load_balancer::target_key("orders", &unhealthy_target),
            1,
        );

        let (host, port, _, _, _) =
            resolve_backend_target(&proxy, &snapshot, &health_checker, "192.0.2.10")
                .expect("healthy target selected");

        assert_eq!(host, "blocked.local");
        assert_eq!(port, 5432);
    }

    #[test]
    fn resolve_backend_target_skips_passively_ejected_targets() {
        let mut config = config_with_two_targets();
        config.upstreams[0].algorithm = crate::config::types::LoadBalancerAlgorithm::RoundRobin;
        let unhealthy_target = config.upstreams[0].targets[0].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let mut proxy = proxy_with_subset(None);
        proxy.id = "orders-stream".to_string();
        proxy.upstream_id = Some("orders".to_string());
        let health_checker = HealthChecker::new();
        let passive = crate::config::types::PassiveHealthCheck {
            unhealthy_threshold: 1,
            ..Default::default()
        };
        health_checker.report_response(
            &proxy.id,
            "tcp-upstream",
            &unhealthy_target,
            500,
            false,
            Some(&passive),
        );

        let (host, port, _, _, _) =
            resolve_backend_target(&proxy, &snapshot, &health_checker, "192.0.2.10")
                .expect("healthy target selected");

        assert_eq!(host, "blocked.local");
        assert_eq!(port, 5432);
    }

    #[test]
    fn tcp_retry_target_is_checked_against_mesh_registry() {
        let config = config_with_two_targets();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let params = retry_params();
        let proxy = proxy_with_subset(None);
        let health_checker = HealthChecker::new();
        let enforcement = enforcement(&["allowed.local:5432"]);

        let err = try_next_enforced_target(
            &params,
            &proxy,
            &health_checker,
            "allowed.local",
            5432,
            5432,
            &snapshot,
            Some(&enforcement),
            15001,
            "tcp-proxy",
            "127.0.0.1".parse().unwrap(),
        )
        .expect_err("unadmitted retry target must fail closed");

        assert!(err.to_string().contains("mesh REGISTRY_ONLY"));
    }

    #[test]
    fn tcp_retry_target_skips_mesh_registry_on_non_capture_listener() {
        let config = config_with_two_targets();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let params = retry_params();
        let proxy = proxy_with_subset(None);
        let health_checker = HealthChecker::new();
        let enforcement = enforcement(&["allowed.local:5432"]);

        let (host, port, policy_port) = try_next_enforced_target(
            &params,
            &proxy,
            &health_checker,
            "allowed.local",
            5432,
            5432,
            &snapshot,
            Some(&enforcement),
            8080,
            "tcp-proxy",
            "127.0.0.1".parse().unwrap(),
        )
        .expect("non-capture listener should skip enforcement")
        .expect("alternate target should be selected");

        assert_eq!(host, "blocked.local");
        assert_eq!(port, 5432);
        assert_eq!(policy_port, 5432);
    }

    #[test]
    fn tcp_retry_exclusion_uses_current_policy_port() {
        let mut config = config_with_two_targets();
        config.upstreams[0].targets = vec![
            UpstreamTarget {
                host: "shared.local".into(),
                port: 6380,
                service_port_policy_key: Some(6379),
                weight: 1,
                tags: HashMap::new(),
                locality: None,
                path: None,
            },
            UpstreamTarget {
                host: "shared.local".into(),
                port: 6380,
                service_port_policy_key: Some(6381),
                weight: 1,
                tags: HashMap::new(),
                locality: None,
                path: None,
            },
        ];
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let params = retry_params();
        let proxy = proxy_with_subset(None);
        let health_checker = HealthChecker::new();

        let next = try_next_target(
            &params,
            &proxy,
            &health_checker,
            "shared.local",
            6380,
            6379,
            &snapshot,
        );

        assert!(
            next.is_some(),
            "the sibling policy lane remains selectable when excluding lane 6379"
        );
        let (host, port, policy_port) = next.expect("sibling lane selected");
        assert_eq!(host, "shared.local");
        assert_eq!(port, 6380);
        assert_eq!(policy_port, 6381);

        assert!(
            try_next_target(
                &params,
                &proxy,
                &health_checker,
                "shared.local",
                6380,
                6381,
                &snapshot
            )
            .is_some(),
            "lane 6379 remains selectable when excluding lane 6381"
        );
    }

    #[test]
    fn tcp_retry_target_skips_unhealthy_alternate_target() {
        let mut config = config_with_two_targets();
        config.upstreams[0].algorithm = crate::config::types::LoadBalancerAlgorithm::RoundRobin;
        let unhealthy_target = config.upstreams[0].targets[1].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let params = retry_params();
        let proxy = proxy_with_subset(None);
        let health_checker = HealthChecker::new();
        health_checker.active_unhealthy_targets.insert(
            crate::load_balancer::target_key("orders", &unhealthy_target),
            1,
        );

        let next = try_next_target(
            &params,
            &proxy,
            &health_checker,
            "allowed.local",
            5432,
            5432,
            &snapshot,
        );

        assert_eq!(
            next, None,
            "connect retry must not rotate to an unhealthy alternate target"
        );
    }

    /// A stream proxy's `backend_port` is a placeholder when an upstream is
    /// configured. On a mixed-port upstream it must NOT engage the per-port
    /// lane even when it coincides with an overridden target port (codex
    /// round-1 P2 on PR #2016).
    #[test]
    fn resolve_backend_target_ignores_backend_port_placeholder_on_mixed_port_upstream() {
        let mut config = config_with_subset();
        // Targets sit on 1001 and 1002; add a per-port override on 1001 and
        // make the proxy's placeholder backend_port coincide with it.
        config.upstreams[0].port_overrides.insert(
            1001,
            crate::config::types::UpstreamPortOverride {
                algorithm: Some(crate::config::types::LoadBalancerAlgorithm::RoundRobin),
                ..Default::default()
            },
        );
        // `resolve_dispatch_port_overrides` projects upstream overrides onto
        // every referencing proxy — mirror the load path.
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let mut proxy = proxy_with_subset(None);
        proxy.backend_port = 1001;
        config.proxies.push(proxy);
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies.pop().expect("proxy pushed above");
        assert!(
            proxy
                .dispatch_port_overrides
                .as_ref()
                .is_some_and(|o| o.contains_key(&1001)),
            "projection must land the 1001 override on the proxy"
        );

        let mut hosts = std::collections::HashSet::new();
        for _ in 0..8 {
            let (host, _, _, port_lane, _) =
                resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
                    .expect("target selected");
            assert_eq!(
                port_lane, None,
                "mixed-port upstream must not resolve a per-port lane from the placeholder"
            );
            hosts.insert(host);
        }
        assert!(
            hosts.contains("stable.local") && hosts.contains("canary.local"),
            "selection must rotate across ALL targets, not pin to the placeholder port: {hosts:?}"
        );
    }

    /// Connection-phase retry rotation must stay inside the engaged per-port
    /// lane (codex round-1 P2 on PR #2016): with `lb_port_lane` set, the
    /// port-scoped next-target variant is used and still rotates to the
    /// sibling target on that port.
    #[test]
    fn tcp_retry_rotation_stays_in_port_lane() {
        let mut config = config_with_two_targets();
        config.upstreams[0].port_overrides.insert(
            5432,
            crate::config::types::UpstreamPortOverride {
                algorithm: Some(crate::config::types::LoadBalancerAlgorithm::RoundRobin),
                ..Default::default()
            },
        );
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let mut params = retry_params();
        params.lb_port_lane = Some(5432);
        let proxy = proxy_with_subset(None);
        let health_checker = HealthChecker::new();

        let (host, port, policy_port) = try_next_target(
            &params,
            &proxy,
            &health_checker,
            "allowed.local",
            5432,
            5432,
            &snapshot,
        )
        .expect("alternate target inside the port lane");
        assert_eq!(host, "blocked.local");
        assert_eq!(port, 5432);
        assert_eq!(policy_port, 5432);
    }

    #[test]
    fn tcp_port_lane_retry_reuses_original_hash_key() {
        let mut config = config_with_two_targets();
        config.upstreams[0].targets.push(UpstreamTarget {
            host: "backup.local".into(),
            port: 5432,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        });
        config.upstreams[0].algorithm = crate::config::types::LoadBalancerAlgorithm::RoundRobin;
        config.upstreams[0].port_overrides.insert(
            5432,
            crate::config::types::UpstreamPortOverride {
                algorithm: Some(crate::config::types::LoadBalancerAlgorithm::ConsistentHashing),
                ..Default::default()
            },
        );
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let (flow_key, failed) = (1..=256)
            .find_map(|i| {
                let key = format!("198.51.100.{i}");
                let initial = LoadBalancerCache::select_target_for_port_from(
                    &snapshot, "orders", &key, 5432, None,
                )?;
                let exclude = UpstreamTarget {
                    host: initial.target.host.clone(),
                    port: initial.target.port,
                    service_port_policy_key: Some(initial.target.dispatch_policy_port()),
                    weight: 1,
                    path: None,
                    tags: HashMap::new(),
                    locality: None,
                };
                let expected = LoadBalancerCache::select_next_target_for_port_from(
                    &snapshot, "orders", &key, 5432, &exclude, None,
                )?;
                let failed_host_key = LoadBalancerCache::select_next_target_for_port_from(
                    &snapshot,
                    "orders",
                    &initial.target.host,
                    5432,
                    &exclude,
                    None,
                )?;
                (expected.host != failed_host_key.host)
                    .then(|| (key, (initial.target.host.clone(), initial.target.port)))
            })
            .expect("test fixture should expose distinct retry hash outcomes");

        let mut params = retry_params();
        params.lb_port_lane = Some(5432);
        params.lb_hash_key = flow_key.clone();
        let proxy = proxy_with_subset(None);
        let health_checker = HealthChecker::new();

        let (host, port, policy_port) = try_next_target(
            &params,
            &proxy,
            &health_checker,
            &failed.0,
            failed.1,
            5432,
            &snapshot,
        )
        .expect("alternate target inside the port lane");

        let exclude = UpstreamTarget {
            host: failed.0,
            port: failed.1,
            service_port_policy_key: Some(5432),
            weight: 1,
            path: None,
            tags: HashMap::new(),
            locality: None,
        };
        let expected = LoadBalancerCache::select_next_target_for_port_from(
            &snapshot, "orders", &flow_key, 5432, &exclude, None,
        )
        .expect("expected retry target");
        assert_eq!(host, expected.host);
        assert_eq!(port, expected.port);
        assert_eq!(policy_port, expected.dispatch_policy_port());
    }

    #[test]
    fn resolve_backend_target_hashes_port_lane_by_client_key() {
        let mut config = config_with_two_targets();
        config.upstreams[0].algorithm = crate::config::types::LoadBalancerAlgorithm::RoundRobin;
        config.upstreams[0].port_overrides.insert(
            5432,
            crate::config::types::UpstreamPortOverride {
                algorithm: Some(crate::config::types::LoadBalancerAlgorithm::ConsistentHashing),
                ..Default::default()
            },
        );
        let mut proxy = proxy_with_subset(None);
        proxy.upstream_id = Some("orders".to_string());
        config.proxies.push(proxy);
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies.pop().expect("proxy pushed above");
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let mut hosts = std::collections::HashSet::new();
        for i in 1..=64 {
            let key = format!("192.0.2.{i}");
            let (host, _, _, port_lane, _) =
                resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), &key)
                    .expect("target selected");
            assert_eq!(port_lane, Some(5432));
            hosts.insert(host);
        }

        assert!(
            hosts.contains("allowed.local") && hosts.contains("blocked.local"),
            "per-port consistent hashing must use the per-flow key, not a constant proxy id: {hosts:?}"
        );
    }

    #[test]
    fn resolve_backend_target_rejects_tcp_port_lane_for_least_connections() {
        let mut config = config_with_two_targets();
        config.upstreams[0].algorithm = crate::config::types::LoadBalancerAlgorithm::RoundRobin;
        config.upstreams[0].port_overrides.insert(
            5432,
            crate::config::types::UpstreamPortOverride {
                algorithm: Some(crate::config::types::LoadBalancerAlgorithm::LeastConnections),
                ..Default::default()
            },
        );
        let mut proxy = proxy_with_subset(None);
        proxy.upstream_id = Some("orders".to_string());
        config.proxies.push(proxy);
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies.pop().expect("proxy pushed above");
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let err = resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
            .expect_err("per-port LEAST_CONN must be rejected explicitly");
        let setup = find_stream_setup_error(&err).expect("typed stream setup error");

        assert_eq!(setup.kind, StreamSetupKind::UnsupportedStreamPolicy);
        assert!(
            setup.message.contains("per-port LEAST_CONN"),
            "error should make the unsupported policy explicit: {}",
            setup.message
        );
    }

    #[test]
    fn resolve_backend_target_rejects_tcp_port_lane_for_least_latency() {
        let mut config = config_with_two_targets();
        config.upstreams[0].algorithm = crate::config::types::LoadBalancerAlgorithm::RoundRobin;
        config.upstreams[0].port_overrides.insert(
            5432,
            crate::config::types::UpstreamPortOverride {
                algorithm: Some(crate::config::types::LoadBalancerAlgorithm::LeastLatency),
                ..Default::default()
            },
        );
        let mut proxy = proxy_with_subset(None);
        proxy.upstream_id = Some("orders".to_string());
        config.proxies.push(proxy);
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies.pop().expect("proxy pushed above");
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let err = resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
            .expect_err("per-port LEAST_LATENCY must be rejected explicitly");
        let setup = find_stream_setup_error(&err).expect("typed stream setup error");

        assert_eq!(setup.kind, StreamSetupKind::UnsupportedStreamPolicy);
        assert!(
            setup.message.contains("per-port LEAST_LATENCY"),
            "error should make the unsupported policy explicit: {}",
            setup.message
        );
    }

    #[test]
    fn resolve_backend_target_rejects_tcp_port_lane_for_non_ip_hash_on() {
        let mut config = config_with_two_targets();
        config.upstreams[0].algorithm = crate::config::types::LoadBalancerAlgorithm::RoundRobin;
        config.upstreams[0].port_overrides.insert(
            5432,
            crate::config::types::UpstreamPortOverride {
                algorithm: Some(crate::config::types::LoadBalancerAlgorithm::ConsistentHashing),
                hash_on: Some("header:x-user-id".to_string()),
                ..Default::default()
            },
        );
        let mut proxy = proxy_with_subset(None);
        proxy.upstream_id = Some("orders".to_string());
        config.proxies.push(proxy);
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies.pop().expect("proxy pushed above");
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let err = resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
            .expect_err("stream hash_on header must be rejected explicitly");
        let setup = find_stream_setup_error(&err).expect("typed stream setup error");

        assert_eq!(setup.kind, StreamSetupKind::UnsupportedStreamPolicy);
        assert!(
            setup.message.contains("source-IP hash keys"),
            "error should make the unsupported hash key explicit: {}",
            setup.message
        );
    }

    #[test]
    fn resolve_backend_target_rejects_tcp_port_lane_for_inherited_non_ip_hash_on() {
        let mut config = config_with_two_targets();
        config.upstreams[0].algorithm = crate::config::types::LoadBalancerAlgorithm::RoundRobin;
        config.upstreams[0].hash_on = Some("cookie:ferrum-affinity".to_string());
        config.upstreams[0].port_overrides.insert(
            5432,
            crate::config::types::UpstreamPortOverride {
                algorithm: Some(crate::config::types::LoadBalancerAlgorithm::ConsistentHashing),
                ..Default::default()
            },
        );
        let mut proxy = proxy_with_subset(None);
        proxy.upstream_id = Some("orders".to_string());
        config.proxies.push(proxy);
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies.pop().expect("proxy pushed above");
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let err = resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
            .expect_err("inherited stream hash_on cookie must be rejected explicitly");
        let setup = find_stream_setup_error(&err).expect("typed stream setup error");

        assert_eq!(setup.kind, StreamSetupKind::UnsupportedStreamPolicy);
        assert!(
            setup.message.contains("source-IP hash keys"),
            "error should make the inherited unsupported hash key explicit: {}",
            setup.message
        );
    }

    #[test]
    fn resolve_backend_target_preserves_subset_lb_for_non_lb_port_override() {
        let mut config: GatewayConfig = serde_json::from_value(json!({
            "version": "1",
            "proxies": [{
                "id": "orders-proxy",
                "backend_scheme": "tcp",
                "backend_host": "unused.local",
                "backend_port": 0,
                "listen_port": 15432,
                "upstream_id": "orders",
                "upstream_subset": "canary"
            }],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "orders",
                "algorithm": "round_robin",
                "targets": [
                    {
                        "host": "canary-a.local",
                        "port": 5432,
                        "tags": { "version": "canary" }
                    },
                    {
                        "host": "canary-b.local",
                        "port": 5432,
                        "tags": { "version": "canary" }
                    }
                ],
                "subsets": [{
                    "name": "canary",
                    "labels": { "version": "canary" },
                    "traffic_policy": { "load_balancer_algorithm": "consistent_hashing" }
                }],
                "port_overrides": {
                    "5432": { "connect_timeout_ms": 250 }
                }
            }]
        }))
        .expect("gateway config should deserialize");
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies[0].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let (_, _, _, port_lane, _) =
            resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
                .expect("target selected");

        assert_eq!(
            port_lane, None,
            "a connect-timeout-only port override must not bypass the subset LB lane"
        );
    }

    #[test]
    fn resolve_backend_target_honors_hash_only_subset_port_override() {
        let mut config: GatewayConfig = serde_json::from_value(json!({
            "version": "1",
            "proxies": [{
                "id": "orders-proxy",
                "backend_scheme": "tcp",
                "backend_host": "unused.local",
                "backend_port": 0,
                "listen_port": 15432,
                "upstream_id": "orders",
                "upstream_subset": "canary"
            }],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "orders",
                "algorithm": "round_robin",
                "targets": [
                    {
                        "host": "canary-a.local",
                        "port": 5432,
                        "tags": { "version": "canary" }
                    },
                    {
                        "host": "canary-b.local",
                        "port": 5432,
                        "tags": { "version": "canary" }
                    }
                ],
                "subsets": [{
                    "name": "canary",
                    "labels": { "version": "canary" },
                    "traffic_policy": { "load_balancer_algorithm": "consistent_hashing" }
                }],
                "port_overrides": {
                    "5432": { "hash_on": "ip" }
                }
            }]
        }))
        .expect("gateway config should deserialize");
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies[0].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let (_, _, _, port_lane, _) =
            resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
                .expect("target selected");

        assert_eq!(
            port_lane,
            Some(5432),
            "a source-IP hash-only port override should engage the port lane while preserving the subset algorithm"
        );
    }

    #[test]
    fn resolve_backend_target_rejects_hash_only_subset_port_override_for_non_ip_hash() {
        let mut config: GatewayConfig = serde_json::from_value(json!({
            "version": "1",
            "proxies": [{
                "id": "orders-proxy",
                "backend_scheme": "tcp",
                "backend_host": "unused.local",
                "backend_port": 0,
                "listen_port": 15432,
                "upstream_id": "orders",
                "upstream_subset": "canary"
            }],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "orders",
                "algorithm": "round_robin",
                "targets": [
                    {
                        "host": "canary-a.local",
                        "port": 5432,
                        "tags": { "version": "canary" }
                    },
                    {
                        "host": "canary-b.local",
                        "port": 5432,
                        "tags": { "version": "canary" }
                    }
                ],
                "subsets": [{
                    "name": "canary",
                    "labels": { "version": "canary" },
                    "traffic_policy": { "load_balancer_algorithm": "consistent_hashing" }
                }],
                "port_overrides": {
                    "5432": { "hash_on": "cookie:session" }
                }
            }]
        }))
        .expect("gateway config should deserialize");
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies[0].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let err = resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
            .expect_err("stream hash_on cookie must be rejected explicitly");
        let setup = find_stream_setup_error(&err).expect("typed stream setup error");

        assert_eq!(setup.kind, StreamSetupKind::UnsupportedStreamPolicy);
        assert!(
            setup.message.contains("source-IP hash keys"),
            "error should make the unsupported hash key explicit: {}",
            setup.message
        );
    }

    #[test]
    fn resolve_backend_target_honors_locality_only_port_lane_without_bypassing_subset_lb() {
        let mut config: GatewayConfig = serde_json::from_value(json!({
            "version": "1",
            "proxies": [{
                "id": "orders-proxy",
                "backend_scheme": "tcp",
                "backend_host": "unused.local",
                "backend_port": 0,
                "listen_port": 15432,
                "upstream_id": "orders",
                "upstream_subset": "canary"
            }],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "orders",
                "algorithm": "round_robin",
                "targets": [
                    {
                        "host": "canary-a.local",
                        "port": 5432,
                        "tags": { "version": "canary" },
                        "locality": "region-a/zone-a"
                    },
                    {
                        "host": "canary-b.local",
                        "port": 5432,
                        "tags": { "version": "canary" },
                        "locality": "region-b/zone-b"
                    }
                ],
                "subsets": [{
                    "name": "canary",
                    "labels": { "version": "canary" },
                    "traffic_policy": { "load_balancer_algorithm": "consistent_hashing" }
                }],
                "port_overrides": {
                    "5432": { "locality_lb_setting": { "enabled": true } }
                }
            }]
        }))
        .expect("gateway config should deserialize");
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies[0].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let (first_host, _, _, port_lane, _) =
            resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
                .expect("target selected");
        let (second_host, _, _, second_port_lane, _) =
            resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
                .expect("target selected");

        assert_eq!(
            port_lane,
            Some(5432),
            "locality-only port policy must engage the port lane"
        );
        assert_eq!(second_port_lane, Some(5432));
        assert_eq!(
            first_host, second_host,
            "port+subset selection must keep the subset consistent-hash algorithm when the \
             port override supplies only locality policy"
        );
    }

    #[test]
    fn resolve_backend_target_preserves_subset_lb_for_passive_health_only_port_override() {
        let mut config: GatewayConfig = serde_json::from_value(json!({
            "version": "1",
            "proxies": [{
                "id": "orders-proxy",
                "backend_scheme": "tcp",
                "backend_host": "unused.local",
                "backend_port": 0,
                "listen_port": 15432,
                "upstream_id": "orders",
                "upstream_subset": "canary"
            }],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "orders",
                "algorithm": "round_robin",
                "targets": [
                    {
                        "host": "canary-a.local",
                        "port": 5432,
                        "tags": { "version": "canary" }
                    },
                    {
                        "host": "canary-b.local",
                        "port": 5432,
                        "tags": { "version": "canary" }
                    }
                ],
                "subsets": [{
                    "name": "canary",
                    "labels": { "version": "canary" },
                    "traffic_policy": { "load_balancer_algorithm": "consistent_hashing" }
                }],
                "port_overrides": {
                    "5432": {
                        "passive_health_check": {
                            "unhealthy_threshold": 3,
                            "max_ejection_percent": 50
                        }
                    }
                }
            }]
        }))
        .expect("gateway config should deserialize");
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies[0].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let (_, _, _, port_lane, health_port_scope) =
            resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
                .expect("target selected");

        assert_eq!(
            port_lane, None,
            "a passive-health-only port override must not bypass the subset LB lane"
        );
        assert_eq!(
            health_port_scope,
            Some(5432),
            "passive-health-only port overrides must still scope stream health selection"
        );
    }
}

/// Backend stream type for the connection-phase retry loop.
/// Wraps either a plain TCP or TLS stream so the retry loop can return
/// a single type regardless of backend TLS configuration.
enum BackendStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// Client-side stream after optional frontend TLS termination.
enum ClientRelayStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

/// Try to select a different upstream target for retry, excluding the current one.
/// Returns `None` if no upstream is configured or no alternate target is available.
fn try_next_target(
    params: &TcpConnParams,
    proxy: &Proxy,
    health_checker: &HealthChecker,
    current_host: &str,
    current_port: u16,
    current_policy_port: u16,
    lb_snapshot: &LoadBalancerCacheInner,
) -> Option<(String, u16, u16)> {
    let upstream_id = params.upstream_id.as_ref()?;
    let health_ctx = crate::proxy::backend_dispatch::health_context_for_selection(
        proxy,
        health_checker,
        lb_snapshot,
        upstream_id,
        params.health_port_scope,
    );
    let exclude = crate::config::types::UpstreamTarget {
        host: current_host.to_string(),
        port: current_port,
        service_port_policy_key: Some(current_policy_port),
        weight: 1,
        path: None,
        tags: std::collections::HashMap::new(),
        locality: None,
    };
    // Rotate inside the per-port lane the initial selection used (if any), so
    // a per-port algorithm/locality override is not escaped on connect retry.
    let lb_hash_key = params.lb_hash_key.as_str();
    let next = match (params.upstream_subset.as_deref(), params.lb_port_lane) {
        (Some(subset_name), Some(port)) => {
            LoadBalancerCache::select_next_target_for_port_subset_from(
                lb_snapshot,
                upstream_id,
                lb_hash_key,
                port,
                subset_name,
                &exclude,
                Some(&health_ctx),
            )
        }
        (Some(subset_name), None) => LoadBalancerCache::select_next_target_subset_from(
            lb_snapshot,
            upstream_id,
            lb_hash_key,
            subset_name,
            &exclude,
            Some(&health_ctx),
        ),
        (None, Some(port)) => LoadBalancerCache::select_next_target_for_port_from(
            lb_snapshot,
            upstream_id,
            lb_hash_key,
            port,
            &exclude,
            Some(&health_ctx),
        ),
        (None, None) => LoadBalancerCache::select_next_target_from(
            lb_snapshot,
            upstream_id,
            lb_hash_key,
            &exclude,
            Some(&health_ctx),
        ),
    }?;
    Some((next.host.clone(), next.port, next.dispatch_policy_port()))
}

#[allow(clippy::too_many_arguments)]
fn try_next_enforced_target(
    params: &TcpConnParams,
    proxy: &Proxy,
    health_checker: &HealthChecker,
    current_host: &str,
    current_port: u16,
    current_policy_port: u16,
    lb_snapshot: &LoadBalancerCacheInner,
    enforcement: Option<&Arc<MeshOutboundEnforcement>>,
    listen_port: u16,
    proxy_id: &str,
    client_ip: IpAddr,
) -> Result<Option<(String, u16, u16)>, anyhow::Error> {
    let Some((next_host, next_port, next_policy_port)) = try_next_target(
        params,
        proxy,
        health_checker,
        current_host,
        current_port,
        current_policy_port,
        lb_snapshot,
    ) else {
        return Ok(None);
    };
    enforce_mesh_tcp_outbound_target(
        enforcement,
        listen_port,
        &next_host,
        next_port,
        params.backend_scheme,
        proxy_id,
        client_ip,
    )?;
    Ok(Some((next_host, next_port, next_policy_port)))
}

fn resolve_port_override(
    params: &TcpConnParams,
    port: u16,
) -> Option<&crate::config::types::ResolvedPortOverride> {
    params
        .dispatch_port_overrides
        .as_ref()
        .and_then(|m| m.get(&port))
}

/// Try to acquire a per-target open-connection slot for DR
/// `connectionPool.tcp.maxConnections`, delegating to the shared
/// `BackendConnectionLimiter`. Returns:
///   * `Ok(None)` when no cap is configured (hot path: zero overhead, no
///     `DashMap` touch).
///   * `Ok(Some(guard))` when a slot was acquired. The guard's `Drop` impl
///     decrements the counter.
///   * `Err(BackendConnectionLimitExceeded)` when the cap is already reached.
fn acquire_backend_inflight_slot(
    port_override: Option<&crate::config::types::ResolvedPortOverride>,
    metrics: &TcpProxyMetrics,
    host: &str,
    port: u16,
) -> Result<Option<BackendConnectionGuard>, BackendConnectionLimitExceeded> {
    let cap = port_override.and_then(|override_config| override_config.max_connections);
    metrics.backend_inflight.try_acquire(host, port, cap)
}

/// Apply DestinationRule `connectionPool.tcp.tcpKeepalive` on a freshly
/// connected backend `TcpStream`. Best-effort: a `setsockopt` failure logs
/// at `warn!` and continues rather than dropping the backend connection —
/// keepalive is an operational hint, not a correctness requirement.
fn apply_backend_tcp_keepalive(
    proxy_id: &str,
    stream: &TcpStream,
    cfg: Option<&crate::config::types::TcpKeepaliveCfg>,
) {
    let Some(cfg) = cfg else {
        return;
    };
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        if let Err(e) = crate::socket_opts::apply_tcp_keepalive(stream.as_raw_fd(), cfg) {
            warn!(
                proxy_id = %proxy_id,
                error = %e,
                "Failed to apply DestinationRule TCP keepalive on backend socket; continuing"
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        if let Err(e) = crate::socket_opts::apply_tcp_keepalive(stream.as_raw_socket(), cfg) {
            warn!(
                proxy_id = %proxy_id,
                error = %e,
                "Failed to apply DestinationRule TCP keepalive on backend socket; continuing"
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Other platforms: keepalive is unreachable via socket2 here, but the
        // K8s translator still accepts the configuration. Surface that the
        // operator intent landed in slice apply but cannot take effect on
        // this build target.
        debug!(
            proxy_id = %proxy_id,
            "DestinationRule TCP keepalive configured but unsupported on this platform; skipping"
        );
        let _ = (stream, cfg);
    }
}

/// Connect to a plain TCP backend with the given connect timeout.
///
/// On Linux, applies `IP_BIND_ADDRESS_NO_PORT` and `TCP_FASTOPEN_CONNECT`
/// BEFORE `connect()` so they take effect on the connection attempt. These
/// must be set pre-connect: `IP_BIND_ADDRESS_NO_PORT` defers ephemeral port
/// allocation to `connect()` for 4-tuple co-selection, and `TCP_FASTOPEN_CONNECT`
/// sends data in the SYN packet.
async fn connect_backend_plain(
    addr: SocketAddr,
    connect_timeout: Duration,
    tcp_fastopen: bool,
    overload: &crate::overload::OverloadState,
) -> Result<TcpStream, anyhow::Error> {
    // Use TcpSocket to set socket options BEFORE connect(). This is the same
    // pattern as socket_opts::connect_with_socket_opts() but adds TFO and
    // port exhaustion detection.
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };

    // Apply pre-connect options on the raw fd.
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        if let Err(e) = crate::socket_opts::set_ip_bind_address_no_port(fd, true) {
            warn!(
                backend = %addr,
                "Failed to enable IP_BIND_ADDRESS_NO_PORT on outbound TCP socket: {}",
                e
            );
        }
        if tcp_fastopen && let Err(e) = crate::socket_opts::set_tcp_fastopen_client(fd) {
            warn!(
                backend = %addr,
                "Failed to enable TCP_FASTOPEN_CONNECT on outbound TCP socket: {}",
                e
            );
        }
    }
    #[cfg(not(unix))]
    let _ = tcp_fastopen;

    let stream = tokio::time::timeout(connect_timeout, socket.connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("Backend connect timeout to {}", addr))?
        .map_err(|e| {
            if crate::retry::is_port_exhaustion(&e) {
                tracing::error!(
                    "tcp_proxy: PORT EXHAUSTION connecting to backend {}: {} — \
                     reduce outbound connection rate or increase net.ipv4.ip_local_port_range",
                    addr,
                    e
                );
                overload.record_port_exhaustion();
            }
            anyhow::anyhow!("Backend connect failed to {}: {}", addr, e)
        })?;

    if let Err(e) = stream.set_nodelay(true) {
        warn!(
            backend = %addr,
            "Failed to set TCP_NODELAY on outbound TCP stream: {}",
            e
        );
    }
    Ok(stream)
}

/// Connect to a TLS-enabled backend using the cached TLS config when available.
/// Falls back to building the config from disk if no cache is provided.
///
/// `keepalive` carries DestinationRule `connectionPool.tcp.tcpKeepalive`. We
/// apply it to the underlying `TcpStream` BEFORE the TLS handshake starts so
/// the kernel begins counting idle time from connection establishment, not
/// from handshake completion. Best-effort: `setsockopt` failures log and
/// continue rather than aborting the connection (keepalive is an operational
/// hint).
#[allow(clippy::too_many_arguments)]
async fn connect_backend_tls_cached(
    addr: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    cached_tls: Option<&CachedBackendTlsConfig>,
    tcp_fastopen: bool,
    overload: &crate::overload::OverloadState,
    keepalive: Option<&crate::config::types::TcpKeepaliveCfg>,
    proxy_id: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, anyhow::Error> {
    let connect_started = Instant::now();
    let tcp_stream = connect_backend_plain(addr, connect_timeout, tcp_fastopen, overload).await?;
    apply_backend_tcp_keepalive(proxy_id, &tcp_stream, keepalive);

    let tls_config = cached_tls
        .map(|c| c.config.clone())
        .ok_or_else(|| anyhow::anyhow!("Backend TLS config not available for {}", addr))?;

    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
        .map_err(|e| anyhow::anyhow!("Invalid server name '{}': {}", hostname, e))?;

    // Typed `StreamSetupError::BackendTlsHandshake` lets cause mappers read
    // the side directly from the kind — no substring match against the
    // legacy `STREAM_ERR_BACKEND_TLS_HANDSHAKE_FAILED` prefix. Both timeout
    // arms below funnel through the same kind so a handshake-budget
    // exhaustion classifies identically to a handshake-error failure.
    let remaining = crate::pool::remaining_connect_timeout(connect_started, connect_timeout)
        .ok_or_else(|| -> anyhow::Error {
            StreamSetupError::new(
                StreamSetupKind::BackendTlsHandshake,
                format!("to {addr}: connect budget exhausted before TLS handshake started"),
            )
            .into()
        })?;

    let tls_stream = tokio::time::timeout(remaining, connector.connect(server_name, tcp_stream))
        .await
        .map_err(|_| -> anyhow::Error {
            StreamSetupError::new(
                StreamSetupKind::BackendTlsHandshake,
                format!(
                    "to {addr}: handshake timeout after {}ms",
                    connect_timeout.as_millis()
                ),
            )
            .into()
        })?
        .map_err(|e| -> anyhow::Error {
            StreamSetupError::with_source(
                StreamSetupKind::BackendTlsHandshake,
                format!("to {addr}: {e}"),
                e,
            )
            .into()
        })?;

    Ok(tls_stream)
}

/// How long to wait for the opposite direction to drain after the first half
/// finishes (cleanly or with an error). Matches the splice-path grace window.
const BIDIRECTIONAL_DRAIN_GRACE: Duration = Duration::from_millis(100);

const TCP_COPY_BUFFER_MIN_SIZE: usize = 4096;
const TCP_COPY_BUFFER_POOL_MAX_BUFFERS: usize = 64;
const TCP_COPY_BUFFER_POOL_MAX_RETAIN: usize = 512 * 1024;

thread_local! {
    static TCP_COPY_BUFFER_POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

fn take_pooled_copy_buffer(buf_size: usize) -> Option<Vec<u8>> {
    TCP_COPY_BUFFER_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        let best_fit = pool
            .iter()
            .enumerate()
            .filter(|(_, buf)| buf.capacity() >= buf_size)
            .min_by_key(|(_, buf)| buf.capacity())
            .map(|(idx, _)| idx);
        if let Some(idx) = best_fit {
            return Some(pool.swap_remove(idx));
        }

        // The pool is thread-local rather than task-local. Tokio may move a
        // relay future before drop, so a miss on a full worker-local pool
        // evicts the least useful retained buffer without returning one here;
        // the current allocation can then be retained on drop if it is reusable.
        if buf_size <= TCP_COPY_BUFFER_POOL_MAX_RETAIN
            && pool.len() >= TCP_COPY_BUFFER_POOL_MAX_BUFFERS
            && let Some(idx) = pool
                .iter()
                .enumerate()
                .min_by_key(|(_, buf)| buf.capacity())
                .map(|(idx, _)| idx)
        {
            let _ = pool.swap_remove(idx);
        }

        None
    })
}

struct PooledCopyBuffer {
    buf: Vec<u8>,
}

impl PooledCopyBuffer {
    fn new(buf_size: usize) -> Self {
        let buf_size = buf_size.max(TCP_COPY_BUFFER_MIN_SIZE);
        let mut buf =
            take_pooled_copy_buffer(buf_size).unwrap_or_else(|| Vec::with_capacity(buf_size));
        buf.resize(buf_size, 0);
        Self { buf }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }

    fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

impl Drop for PooledCopyBuffer {
    fn drop(&mut self) {
        let mut buf = std::mem::take(&mut self.buf);
        if buf.capacity() > TCP_COPY_BUFFER_POOL_MAX_RETAIN {
            return;
        }
        buf.clear();
        TCP_COPY_BUFFER_POOL.with(move |pool| {
            let mut pool = pool.borrow_mut();
            if pool.len() < TCP_COPY_BUFFER_POOL_MAX_BUFFERS {
                pool.push(buf);
            }
        });
    }
}

#[cfg(test)]
mod pooled_copy_buffer_tests {
    use super::{
        PooledCopyBuffer, TCP_COPY_BUFFER_POOL, TCP_COPY_BUFFER_POOL_MAX_BUFFERS,
        TCP_COPY_BUFFER_POOL_MAX_RETAIN,
    };

    fn clear_pool() {
        TCP_COPY_BUFFER_POOL.with(|pool| pool.borrow_mut().clear());
    }

    fn pool_capacities() -> Vec<usize> {
        TCP_COPY_BUFFER_POOL
            .with(|pool| pool.borrow().iter().map(Vec::capacity).collect::<Vec<_>>())
    }

    #[test]
    fn new_reuses_smallest_sufficient_pooled_capacity() {
        clear_pool();

        let small = Vec::<u8>::with_capacity(4 * 1024);
        let medium = Vec::<u8>::with_capacity(64 * 1024);
        let large = Vec::<u8>::with_capacity(256 * 1024);
        let medium_capacity = medium.capacity();
        TCP_COPY_BUFFER_POOL.with(|pool| {
            let mut pool = pool.borrow_mut();
            pool.push(small);
            pool.push(large);
            pool.push(medium);
        });

        let buf = PooledCopyBuffer::new(32 * 1024);
        assert_eq!(
            buf.buf.capacity(),
            medium_capacity,
            "the pool should choose the smallest retained buffer that satisfies the request"
        );
        assert_eq!(buf.buf.len(), 32 * 1024);

        drop(buf);
        clear_pool();
    }

    #[test]
    fn full_pool_evicts_undersized_buffer_so_larger_reusable_capacity_can_enter() {
        clear_pool();

        TCP_COPY_BUFFER_POOL.with(|pool| {
            let mut pool = pool.borrow_mut();
            for _ in 0..TCP_COPY_BUFFER_POOL_MAX_BUFFERS {
                pool.push(Vec::<u8>::with_capacity(4 * 1024));
            }
        });

        let buf = PooledCopyBuffer::new(64 * 1024);
        assert_eq!(
            pool_capacities().len(),
            TCP_COPY_BUFFER_POOL_MAX_BUFFERS - 1,
            "taking a miss from a full undersized pool should make room for the new capacity"
        );
        drop(buf);

        let capacities = pool_capacities();
        assert_eq!(capacities.len(), TCP_COPY_BUFFER_POOL_MAX_BUFFERS);
        assert!(
            capacities.iter().any(|&capacity| capacity >= 64 * 1024),
            "dropping the larger buffer should retain it for future matching requests"
        );

        clear_pool();
    }

    #[test]
    fn oversized_buffer_is_not_retained_or_evicted_into_pool() {
        clear_pool();

        TCP_COPY_BUFFER_POOL.with(|pool| {
            let mut pool = pool.borrow_mut();
            for _ in 0..TCP_COPY_BUFFER_POOL_MAX_BUFFERS {
                pool.push(Vec::<u8>::with_capacity(4 * 1024));
            }
        });

        let buf = PooledCopyBuffer::new(TCP_COPY_BUFFER_POOL_MAX_RETAIN + 1);
        assert_eq!(
            pool_capacities().len(),
            TCP_COPY_BUFFER_POOL_MAX_BUFFERS,
            "oversized allocations are not reusable, so they should not evict retained buffers"
        );
        drop(buf);

        let capacities = pool_capacities();
        assert_eq!(capacities.len(), TCP_COPY_BUFFER_POOL_MAX_BUFFERS);
        assert!(
            capacities.iter().all(|&capacity| capacity < 64 * 1024),
            "oversized buffers should be discarded instead of retained in the pool"
        );

        clear_pool();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CopyPhase {
    Reading,
    Writing,
    ShuttingDown,
    Done,
}

struct CopyDirectionState {
    phase: CopyPhase,
    buf: PooledCopyBuffer,
    pos: usize,
    cap: usize,
}

impl CopyDirectionState {
    fn new(buf_size: usize) -> Self {
        Self {
            phase: CopyPhase::Reading,
            buf: PooledCopyBuffer::new(buf_size),
            pos: 0,
            cap: 0,
        }
    }
}

enum Phase1Outcome {
    ClientToBackend(Result<(), (StreamIoSide, std::io::Error)>),
    BackendToClient(Result<(), (StreamIoSide, std::io::Error)>),
    Watchdog(StreamFirstFailure),
}

fn relay_watchdog_interval(timeouts: &[Option<Duration>]) -> Duration {
    let min_active = timeouts
        .iter()
        .flatten()
        .copied()
        .filter(|d| !d.is_zero())
        .min();
    if min_active.is_some_and(|d| d >= Duration::from_secs(30)) {
        Duration::from_secs(5)
    } else {
        Duration::from_secs(1)
    }
}

fn relay_watchdog(interval: Duration) -> tokio::time::Interval {
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker
}

/// Poll one half-duplex copy without splitting the underlying streams.
///
/// **Idle-timer refresh pattern (two-phase):**
/// `last_activity` is stored **before** the write (post-read, pre-write)
/// AND **after** the write (post-write). The pre-write refresh prevents
/// a backpressured write from masquerading as inactivity.
///
/// `read_watermark` / `write_watermark` are per-direction inactivity
/// timestamps polled by the `bidirectional_copy` watchdog. Shared via
/// bare references to parent-scoped `AtomicU64`s — no `Arc` indirection
/// on the hot path.
#[allow(clippy::too_many_arguments)]
fn poll_copy_direction<R, W>(
    cx: &mut std::task::Context<'_>,
    mut reader: Pin<&mut R>,
    mut writer: Pin<&mut W>,
    state: &mut CopyDirectionState,
    bytes: &AtomicU64,
    last_activity: Option<&AtomicU64>,
    read_watermark: Option<&AtomicU64>,
    write_watermark: Option<&AtomicU64>,
) -> Poll<Result<(), (StreamIoSide, std::io::Error)>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        match state.phase {
            CopyPhase::Done => return Poll::Ready(Ok(())),
            CopyPhase::ShuttingDown => {
                return match writer.as_mut().poll_shutdown(cx) {
                    Poll::Ready(_) => {
                        state.phase = CopyPhase::Done;
                        Poll::Ready(Ok(()))
                    }
                    Poll::Pending => Poll::Pending,
                };
            }
            CopyPhase::Reading => {
                let n = {
                    let mut read_buf = ReadBuf::new(state.buf.as_mut_slice());
                    match reader.as_mut().poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => read_buf.filled().len(),
                        Poll::Ready(Err(e)) => return Poll::Ready(Err((StreamIoSide::Read, e))),
                        Poll::Pending => return Poll::Pending,
                    }
                };
                if n == 0 {
                    state.phase = CopyPhase::ShuttingDown;
                    continue;
                }

                // Single clock read for both watermark + idle refresh.
                let now = coarse_now_ms();
                if let Some(wm) = read_watermark {
                    wm.store(now, Ordering::Relaxed);
                }
                if let Some(la) = last_activity {
                    la.store(now, Ordering::Relaxed);
                }
                if let Some(wm) = write_watermark {
                    // Prime the watermark before entering the write loop —
                    // captures "we have `n` bytes ready to write as of `now`".
                    wm.store(now, Ordering::Relaxed);
                }
                state.pos = 0;
                state.cap = n;
                state.phase = CopyPhase::Writing;
            }
            CopyPhase::Writing => {
                while state.pos < state.cap {
                    let poll_result = {
                        let chunk = &state.buf.as_slice()[state.pos..state.cap];
                        writer.as_mut().poll_write(cx, chunk)
                    };
                    match poll_result {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err((
                                StreamIoSide::Write,
                                std::io::Error::new(
                                    std::io::ErrorKind::WriteZero,
                                    "write returned 0 bytes",
                                ),
                            )));
                        }
                        Poll::Ready(Ok(nw)) => {
                            state.pos += nw;
                            if let Some(wm) = write_watermark {
                                wm.store(coarse_now_ms(), Ordering::Relaxed);
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(Err((StreamIoSide::Write, e)));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }

                bytes.fetch_add(state.cap as u64, Ordering::Relaxed);
                state.pos = 0;
                state.cap = 0;
                state.phase = CopyPhase::Reading;
                if let Some(la) = last_activity {
                    la.store(coarse_now_ms(), Ordering::Relaxed);
                }
            }
        }
    }
}

async fn copy_direction_to_completion<R, W>(
    reader: &mut R,
    writer: &mut W,
    state: &mut CopyDirectionState,
    bytes: &AtomicU64,
    last_activity: Option<&AtomicU64>,
    read_watermark: Option<&AtomicU64>,
    write_watermark: Option<&AtomicU64>,
) -> Result<(), (StreamIoSide, std::io::Error)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    poll_fn(|cx| {
        poll_copy_direction(
            cx,
            Pin::new(&mut *reader),
            Pin::new(&mut *writer),
            state,
            bytes,
            last_activity,
            read_watermark,
            write_watermark,
        )
    })
    .await
}

fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::ClientToBackend => "client→backend",
        Direction::BackendToClient => "backend→client",
        Direction::Unknown => "unknown",
    }
}

fn classify_phase1_copy_failure(
    direction: Direction,
    side: StreamIoSide,
    e: std::io::Error,
) -> (StreamFirstFailure, bool) {
    // Capture raw kind before `e` is consumed by anyhow::Error::new.
    let benign_write = is_post_eof_benign_write_error(side, e.kind());
    let label = direction_label(direction);
    let msg = format!("Bidirectional copy error ({}, {:?}): {}", label, side, e);
    // Wrap via `anyhow::Error::new(e)` so the source chain keeps the
    // underlying `io::Error` — `classify_stream_error` walks
    // `Error::source()` to downcast and read `io::ErrorKind`.
    let err: anyhow::Error =
        anyhow::Error::new(e).context(format!("Bidirectional copy error ({}, {:?})", label, side));
    (
        (direction, classify_stream_error(&err), Some(side), msg),
        benign_write,
    )
}

fn phase1_watchdog_failure(
    last_activity: Option<&AtomicU64>,
    timeout_ms: u64,
    b2c_read_watermark: Option<&AtomicU64>,
    backend_read_timeout_ms: u64,
    c2b_write_watermark: Option<&AtomicU64>,
    backend_write_timeout_ms: u64,
) -> Option<StreamFirstFailure> {
    let now = coarse_now_ms();
    // Per-direction inactivity checks (backend_read_timeout /
    // backend_write_timeout). Checked before the bidirectional idle timeout so
    // a stale single direction is caught even when the other direction is
    // still active.
    if let Some(wm) = b2c_read_watermark
        && now.saturating_sub(wm.load(Ordering::Relaxed)) >= backend_read_timeout_ms
    {
        return Some((
            Direction::BackendToClient,
            ErrorClass::ReadWriteTimeout,
            Some(StreamIoSide::Read),
            "backend read inactivity timeout".to_string(),
        ));
    }
    if let Some(wm) = c2b_write_watermark
        && now.saturating_sub(wm.load(Ordering::Relaxed)) >= backend_write_timeout_ms
    {
        return Some((
            Direction::ClientToBackend,
            ErrorClass::ReadWriteTimeout,
            Some(StreamIoSide::Write),
            "backend write inactivity timeout".to_string(),
        ));
    }
    if let Some(la) = last_activity
        && now.saturating_sub(la.load(Ordering::Relaxed)) >= timeout_ms
    {
        return Some((
            Direction::Unknown,
            ErrorClass::ReadWriteTimeout,
            None,
            "idle timeout".to_string(),
        ));
    }
    None
}

fn poll_ready_watchdog_ticks(
    watchdog: &mut tokio::time::Interval,
    cx: &mut std::task::Context<'_>,
    mut on_tick: impl FnMut() -> Option<StreamFirstFailure>,
) -> Poll<Option<StreamFirstFailure>> {
    loop {
        match Pin::new(&mut *watchdog).poll_tick(cx) {
            Poll::Ready(_) => {
                if let Some(failure) = on_tick() {
                    return Poll::Ready(Some(failure));
                }
            }
            Poll::Pending => return Poll::Pending,
        }
    }
}

/// Bidirectional stream copy between client and backend.
///
/// Polls both half-duplex copies from one task against pinned mutable stream
/// references so whichever direction fails first is recorded in
/// `first_failure`. Per-direction byte counts are preserved even when one half
/// errors.
///
/// After Phase 1 (race the two directions) completes, Phase 2 waits for the
/// remaining direction:
///
/// * If Phase 1 ended with a **clean EOF** (one side finished its send without
///   error), the remaining direction is awaited **unbounded** — this preserves
///   half-close semantics for request/response protocols (SMTP, IMAP,
///   HTTP-over-TCP passthrough) where the client finishes sending first and
///   the backend then takes arbitrary time to respond. The idle timeout still
///   applies, so a stuck peer cannot wedge the connection indefinitely.
/// * If Phase 1 ended with an **error** or the **idle timeout** fired, the
///   remaining direction is awaited with a short 100ms grace window so we
///   can capture any error it would produce without hanging on a bad peer.
///
/// When `idle_timeout` is `Some(d)` and non-zero, the connection is closed
/// if no data is received on either side for the given duration.
///
/// **Fast path**: When `idle_timeout`, `half_close_cap`,
/// `backend_read_timeout`, and `backend_write_timeout` are all `None` or zero,
/// the function delegates to `tokio::io::copy_bidirectional_with_sizes`,
/// skipping the Phase 1/Phase 2 machinery. This restores the historical
/// zero-overhead behaviour for deployments that explicitly disable all relay
/// bounds. The trade-off: on error the fast path loses `first_failure`
/// direction attribution (reports `Direction::Unknown`) — acceptable because
/// the user opted out of those observability bounds. Clean completion preserves
/// per-direction byte counts.
async fn bidirectional_copy<C, B>(
    mut client: C,
    mut backend: B,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
    backend_read_timeout: Option<Duration>,
    backend_write_timeout: Option<Duration>,
    buf_size: usize,
) -> StreamCopyResult
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // Fast path: all per-direction bounds disabled → use tokio's optimised
    // bidirectional copy directly. No split (no BiLock overhead), no select
    // loop. On error we classify with `Direction::Unknown` because
    // `copy_bidirectional_with_sizes` doesn't report which half failed first.
    // `backend_read_timeout` / `backend_write_timeout` inherently require the
    // direction-tracking path — they wrap individual `read`/`write` polls,
    // which tokio's bidirectional copy does not expose. Any non-zero timeout
    // here opts out of the fast path.
    let idle_disabled = idle_timeout.is_none_or(|d| d.is_zero());
    let cap_disabled = half_close_cap.is_none_or(|d| d.is_zero());
    let read_to_disabled = backend_read_timeout.is_none_or(|d| d.is_zero());
    let write_to_disabled = backend_write_timeout.is_none_or(|d| d.is_zero());
    if idle_disabled && cap_disabled && read_to_disabled && write_to_disabled {
        return match tokio::io::copy_bidirectional_with_sizes(
            &mut client,
            &mut backend,
            buf_size,
            buf_size,
        )
        .await
        {
            Ok((c2b, b2c)) => StreamCopyResult {
                bytes_client_to_backend: c2b,
                bytes_backend_to_client: b2c,
                first_failure: None,
            },
            Err(e) => {
                let msg = e.to_string();
                let err: anyhow::Error = anyhow::anyhow!("Bidirectional copy error: {}", e);
                StreamCopyResult {
                    bytes_client_to_backend: 0,
                    bytes_backend_to_client: 0,
                    first_failure: Some((
                        Direction::Unknown,
                        classify_stream_error(&err),
                        None,
                        msg,
                    )),
                }
            }
        };
    }

    // Stack-allocated counters and watermarks — no Arc indirection on the
    // hot path. The pinned futures borrow these directly via references.
    let c2b_bytes = AtomicU64::new(0);
    let b2c_bytes = AtomicU64::new(0);

    let now = coarse_now_ms();
    let last_activity_storage = AtomicU64::new(now);
    let idle_timeout_active = idle_timeout.is_some_and(|t| !t.is_zero());
    let last_activity: Option<&AtomicU64> = if idle_timeout_active {
        Some(&last_activity_storage)
    } else {
        None
    };

    // Per-direction inactivity watermarks. Stored on the stack alongside the
    // futures they protect — zero heap allocation, zero pointer chase.
    // Read watermark starts at `now` — a silent backend is immediately stale.
    // Write watermark starts at u64::MAX (sentinel) so the check stays inert
    // while c2b has no data queued to send. `poll_copy_direction` primes it
    // with `now` the moment a read succeeds (before the write loop), so a
    // stuck backend send buffer still fires the timeout. Without the sentinel,
    // push-only traffic (backend→client, client silent) would falsely fire the
    // write timeout because no c2b read/write ever refreshes the watermark.
    let b2c_read_wm_storage = AtomicU64::new(now);
    let c2b_write_wm_storage = AtomicU64::new(u64::MAX);
    let read_wm_active = backend_read_timeout.is_some_and(|d| !d.is_zero());
    let write_wm_active = backend_write_timeout.is_some_and(|d| !d.is_zero());
    let b2c_read_watermark: Option<&AtomicU64> = if read_wm_active {
        Some(&b2c_read_wm_storage)
    } else {
        None
    };
    let c2b_write_watermark: Option<&AtomicU64> = if write_wm_active {
        Some(&c2b_write_wm_storage)
    } else {
        None
    };

    // Per-direction layout:
    // * c2b reads from CLIENT and writes to BACKEND — the write watermark
    //   tracks `backend_write_timeout` (c2b_write_watermark).
    // * b2c reads from BACKEND and writes to CLIENT — the read watermark
    //   tracks `backend_read_timeout` (b2c_read_watermark).
    //
    // Both states are polled from this single task against pinned `&mut`
    // streams. That preserves the old race/timeout semantics without
    // `tokio::io::split()`'s BiLock on every read/write.
    let mut c2b_state = CopyDirectionState::new(buf_size);
    let mut b2c_state = CopyDirectionState::new(buf_size);

    let timeout_ms = idle_timeout.map(|t| t.as_millis() as u64).unwrap_or(0);
    let backend_read_timeout_ms = backend_read_timeout
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let backend_write_timeout_ms = backend_write_timeout
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let any_watchdog_active = idle_timeout_active || read_wm_active || write_wm_active;
    let mut watchdog = any_watchdog_active.then(|| {
        relay_watchdog(relay_watchdog_interval(&[
            idle_timeout,
            backend_read_timeout,
            backend_write_timeout,
        ]))
    });

    // Phase 1: race the two directions (plus optional idle check).
    let mut first_failure: Option<(Direction, ErrorClass, Option<StreamIoSide>, String)> = None;
    // Captured *before* `e` is moved into `anyhow::Error::new(e)` so that the
    // Phase 2 grace-window reclassification can use the precise raw
    // `io::ErrorKind` rather than the lossy classified `ErrorClass`. Two
    // failure kinds collide on `ErrorClass::ConnectionClosed`: `BrokenPipe`
    // (benign close race, admit) and `ConnectionAborted` (kernel abort, do
    // NOT admit). `WriteZero` collapses to `ErrorClass::RequestError` and
    // would otherwise be missed entirely. Storing the precise admission
    // decision here keeps Phase 2 in lockstep with `is_post_eof_benign_write_error`.
    let mut phase1_benign_write_candidate: bool = false;
    let mut c2b_done = false;
    let mut b2c_done = false;
    let mut poll_c2b_first = true;

    let phase1_outcome = poll_fn(|cx| {
        // Fairness invariant: each live direction is polled exactly once per
        // poll_fn invocation; the first-polled direction alternates each call.
        let poll_c2b_this_turn = poll_c2b_first;
        poll_c2b_first = !poll_c2b_first;

        if poll_c2b_this_turn && !c2b_done {
            match poll_copy_direction(
                cx,
                Pin::new(&mut client),
                Pin::new(&mut backend),
                &mut c2b_state,
                &c2b_bytes,
                last_activity,
                None,
                c2b_write_watermark,
            ) {
                Poll::Ready(result) => return Poll::Ready(Phase1Outcome::ClientToBackend(result)),
                Poll::Pending => {}
            }
        }
        if !b2c_done {
            match poll_copy_direction(
                cx,
                Pin::new(&mut backend),
                Pin::new(&mut client),
                &mut b2c_state,
                &b2c_bytes,
                last_activity,
                b2c_read_watermark,
                None,
            ) {
                Poll::Ready(result) => return Poll::Ready(Phase1Outcome::BackendToClient(result)),
                Poll::Pending => {}
            }
        }
        if !poll_c2b_this_turn && !c2b_done {
            match poll_copy_direction(
                cx,
                Pin::new(&mut client),
                Pin::new(&mut backend),
                &mut c2b_state,
                &c2b_bytes,
                last_activity,
                None,
                c2b_write_watermark,
            ) {
                Poll::Ready(result) => return Poll::Ready(Phase1Outcome::ClientToBackend(result)),
                Poll::Pending => {}
            }
        }
        if let Some(watchdog) = watchdog.as_mut() {
            match poll_ready_watchdog_ticks(watchdog, cx, || {
                phase1_watchdog_failure(
                    last_activity,
                    timeout_ms,
                    b2c_read_watermark,
                    backend_read_timeout_ms,
                    c2b_write_watermark,
                    backend_write_timeout_ms,
                )
            }) {
                Poll::Ready(Some(failure)) => return Poll::Ready(Phase1Outcome::Watchdog(failure)),
                Poll::Ready(None) | Poll::Pending => {}
            }
        }
        Poll::Pending
    })
    .await;

    match phase1_outcome {
        Phase1Outcome::ClientToBackend(result) => {
            c2b_done = true;
            if let Err((side, e)) = result {
                let (failure, benign_write) =
                    classify_phase1_copy_failure(Direction::ClientToBackend, side, e);
                first_failure = Some(failure);
                phase1_benign_write_candidate = benign_write;
            }
        }
        Phase1Outcome::BackendToClient(result) => {
            b2c_done = true;
            if let Err((side, e)) = result {
                let (failure, benign_write) =
                    classify_phase1_copy_failure(Direction::BackendToClient, side, e);
                first_failure = Some(failure);
                phase1_benign_write_candidate = benign_write;
            }
        }
        Phase1Outcome::Watchdog(failure) => {
            first_failure = Some(failure);
        }
    }

    // Phase 2: drain the remaining direction.
    //
    // Two cases:
    //
    // * **Clean EOF** (`first_failure.is_none()`): one side finished its send
    //   without error — most commonly a half-close where the client finished
    //   sending and the backend is still generating a large/slow response (or
    //   vice versa). Wait for the remaining direction to complete naturally,
    //   bounded by (a) the idle timeout and (b) the half-close hard cap. The
    //   idle timeout handles "peer went silent"; the hard cap (`half_close_cap`)
    //   handles the pathological case where idle timeout is disabled
    //   (`FERRUM_TCP_IDLE_TIMEOUT_SECONDS=0`) and the peer stalls forever.
    //   Capping at 100ms here would truncate slow-response protocols (SMTP,
    //   IMAP, HTTP-over-TCP passthrough) — the default 5 min hard cap is
    //   generous enough for any realistic response, while still preventing
    //   permanent task leaks.
    //
    // * **Error or idle timeout** (`first_failure.is_some()`): both halves are
    //   likely in a bad state. Give the remaining direction a brief grace
    //   window to capture any error it would produce, then move on. Do not
    //   block the connection teardown on a stuck peer.
    let clean_eof = first_failure.is_none();
    if !c2b_done {
        if clean_eof {
            first_failure = drain_half_close_direction(
                &mut client,
                &mut backend,
                &mut c2b_state,
                &c2b_bytes,
                last_activity,
                idle_timeout,
                timeout_ms,
                half_close_cap,
                Direction::ClientToBackend,
                c2b_write_watermark,
                backend_write_timeout_ms,
                &c2b_bytes,
                &b2c_bytes,
            )
            .await;
        } else {
            match tokio::time::timeout(
                BIDIRECTIONAL_DRAIN_GRACE,
                copy_direction_to_completion(
                    &mut client,
                    &mut backend,
                    &mut c2b_state,
                    &c2b_bytes,
                    last_activity,
                    None,
                    c2b_write_watermark,
                ),
            )
            .await
            {
                Ok(Ok(())) => {
                    // Phase 1 errored on b2c but c2b completed cleanly in
                    // the grace window. Reclassify as graceful only if:
                    //   (a) the Phase 1 error was a benign write-after-close
                    //       (precise raw-`io::ErrorKind` check captured at
                    //       Phase 1 time — see `phase1_benign_write_candidate`),
                    //   AND
                    //   (b) both directions actually transferred bytes — this
                    //       filters the "backend died before responding"
                    //       and "connection never carried traffic" cases
                    //       that would otherwise be silently re-labelled
                    //       as graceful (see `both_directions_transferred`).
                    if phase1_benign_write_candidate
                        && both_directions_transferred(&c2b_bytes, &b2c_bytes)
                    {
                        first_failure = None;
                    }
                }
                Ok(Err((side, e))) => {
                    if first_failure.is_none() {
                        let (failure, _) =
                            classify_phase1_copy_failure(Direction::ClientToBackend, side, e);
                        first_failure = Some(failure);
                    }
                }
                Err(_) => { /* grace expired — leave counters as-is */ }
            }
        }
    }
    if !b2c_done {
        if clean_eof {
            first_failure = drain_half_close_direction(
                &mut backend,
                &mut client,
                &mut b2c_state,
                &b2c_bytes,
                last_activity,
                idle_timeout,
                timeout_ms,
                half_close_cap,
                Direction::BackendToClient,
                b2c_read_watermark,
                backend_read_timeout_ms,
                &c2b_bytes,
                &b2c_bytes,
            )
            .await;
        } else {
            match tokio::time::timeout(
                BIDIRECTIONAL_DRAIN_GRACE,
                copy_direction_to_completion(
                    &mut backend,
                    &mut client,
                    &mut b2c_state,
                    &b2c_bytes,
                    last_activity,
                    b2c_read_watermark,
                    None,
                ),
            )
            .await
            {
                Ok(Ok(())) => {
                    // Symmetric to the c2b grace path — see comment above.
                    if phase1_benign_write_candidate
                        && both_directions_transferred(&c2b_bytes, &b2c_bytes)
                    {
                        first_failure = None;
                    }
                }
                Ok(Err((side, e))) => {
                    if first_failure.is_none() {
                        let (failure, _) =
                            classify_phase1_copy_failure(Direction::BackendToClient, side, e);
                        first_failure = Some(failure);
                    }
                }
                Err(_) => { /* grace expired — leave counters as-is */ }
            }
        }
    }

    StreamCopyResult {
        bytes_client_to_backend: c2b_bytes.load(Ordering::Relaxed),
        bytes_backend_to_client: b2c_bytes.load(Ordering::Relaxed),
        first_failure,
    }
}

/// Drain one direction of the bidirectional copy during the clean-EOF half-close
/// phase. Returns `Some(first_failure_tuple)` when the drain ends in an error,
/// an idle timeout, a per-direction inactivity timeout, or the half-close hard
/// cap. Returns `None` when the drain completes cleanly.
///
/// Precondition: the *opposite* half of the bidirectional relay has already
/// completed with a clean EOF (the caller only invokes this function on the
/// `clean_eof` branch). This is load-bearing for the write-after-close
/// reclassification below — a benign `EPIPE` / `ECONNRESET` / `WriteZero`
/// on the remaining direction's write side is the tail of the opposite
/// peer's TLS close_notify → FIN dance, and should be reported as
/// graceful shutdown (return `None`) rather than a transport error.
#[allow(clippy::too_many_arguments)]
async fn drain_half_close_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    state: &mut CopyDirectionState,
    bytes: &AtomicU64,
    last_activity: Option<&AtomicU64>,
    idle_timeout: Option<Duration>,
    timeout_ms: u64,
    half_close_cap: Option<Duration>,
    direction: Direction,
    direction_watermark: Option<&AtomicU64>,
    direction_timeout_ms: u64,
    c2b_bytes: &AtomicU64,
    b2c_bytes: &AtomicU64,
) -> Option<(Direction, ErrorClass, Option<StreamIoSide>, String)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let half_close_cap_active = half_close_cap.is_some_and(|d| !d.is_zero());
    let any_timer_active =
        last_activity.is_some() || direction_watermark.is_some() || half_close_cap_active;
    let mut watchdog = any_timer_active.then(|| {
        relay_watchdog(relay_watchdog_interval(&[
            idle_timeout,
            direction_watermark.map(|_| Duration::from_millis(direction_timeout_ms)),
            half_close_cap,
        ]))
    });
    let phase2_start = Instant::now();
    poll_fn(|cx| {
        match poll_copy_direction(
            cx,
            Pin::new(&mut *reader),
            Pin::new(&mut *writer),
            state,
            bytes,
            last_activity,
            if direction == Direction::BackendToClient {
                direction_watermark
            } else {
                None
            },
            if direction == Direction::ClientToBackend {
                direction_watermark
            } else {
                None
            },
        ) {
            Poll::Ready(result) => {
                if let Err((side, e)) = result {
                    // Opposite half already EOF'd cleanly (drain_half_close_direction
                    // precondition). A benign write-after-close here is the tail
                    // of graceful shutdown — but only if both directions
                    // actually transferred bytes. Without that second piece of
                    // evidence we'd silently re-label "client connected and
                    // immediately half-closed" or "backend died before
                    // responding" (asymmetric truncation) as graceful and
                    // hide real failures from operator dashboards.
                    if is_post_eof_benign_write_error(side, e.kind())
                        && both_directions_transferred(c2b_bytes, b2c_bytes)
                    {
                        return Poll::Ready(None);
                    }
                    let msg = e.to_string();
                    let dir_label = direction_label(direction);
                    let err: anyhow::Error = anyhow::Error::new(e).context(format!(
                        "Bidirectional copy error ({}, {:?})",
                        dir_label, side
                    ));
                    return Poll::Ready(Some((
                        direction,
                        classify_stream_error(&err),
                        Some(side),
                        msg,
                    )));
                }
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }

        if let Some(watchdog) = watchdog.as_mut() {
            match poll_ready_watchdog_ticks(watchdog, cx, || {
                let now = coarse_now_ms();
                if let Some(wm) = direction_watermark
                    && now.saturating_sub(wm.load(Ordering::Relaxed)) >= direction_timeout_ms
                {
                    let side = match direction {
                        Direction::BackendToClient => Some(StreamIoSide::Read),
                        Direction::ClientToBackend => Some(StreamIoSide::Write),
                        Direction::Unknown => None,
                    };
                    let label = match direction {
                        Direction::BackendToClient => "backend read inactivity timeout",
                        Direction::ClientToBackend => "backend write inactivity timeout",
                        Direction::Unknown => "backend inactivity timeout",
                    };
                    return Some((
                        direction,
                        ErrorClass::ReadWriteTimeout,
                        side,
                        label.to_string(),
                    ));
                }
                if let Some(la) = last_activity
                    && now.saturating_sub(la.load(Ordering::Relaxed)) >= timeout_ms
                {
                    return Some((
                        Direction::Unknown,
                        ErrorClass::ReadWriteTimeout,
                        None,
                        "idle timeout".to_string(),
                    ));
                }
                if let Some(cap) = half_close_cap
                    && !cap.is_zero()
                    && phase2_start.elapsed() >= cap
                {
                    return Some((
                        Direction::Unknown,
                        ErrorClass::ReadWriteTimeout,
                        None,
                        "tcp half-close max wait exceeded".to_string(),
                    ));
                }
                None
            }) {
                Poll::Ready(Some(failure)) => return Poll::Ready(Some(failure)),
                Poll::Ready(None) | Poll::Pending => {}
            }
        }
        Poll::Pending
    })
    .await
}

/// Wait the full `half_close_cap` duration or return immediately when `None`.
/// Used as a safety-net branch in the splice-path Phase 2 `select!` so the
/// hard cap fires even when the idle timeout is disabled.
#[cfg(target_os = "linux")]
async fn sleep_for_cap(half_close_cap: Option<Duration>) {
    match half_close_cap {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

// ── Linux splice(2) zero-copy TCP relay ──────────────────────────────────────
//
// On Linux, splice(2) moves data between two file descriptors via a kernel-side
// pipe buffer without copying to userspace. This eliminates two memory copies
// per chunk (kernel→user read + user→kernel write) compared to the standard
// `copy_bidirectional` approach. Inspired by nginx's sendfile and HAProxy's
// splice-based TCP proxying.
//
// Only used when both endpoints are raw `TcpStream` (no TLS wrapping) — splice
// operates on OS-level file descriptors and cannot see through rustls encryption.
// Falls back to `bidirectional_copy` on non-Linux and for all TLS paths.

/// Bidirectional zero-copy relay between two raw TCP streams using Linux splice(2).
///
/// Creates a kernel pipe for each direction (client→backend, backend→client) and
/// uses `splice()` to move data through the pipe without userspace copies.
///
/// Both directions run within a single task using `tokio::select!` instead of
/// spawning two separate tasks. This halves task overhead (creation, scheduling,
/// memory) per TCP connection.
///
/// After Phase 1 (race the two directions) completes, Phase 2 waits for the
/// remaining direction with the same semantics as `bidirectional_copy`:
///
/// * If Phase 1 ended with a **clean EOF** (one side finished its splice without
///   error), the remaining direction is awaited **unbounded** — this preserves
///   half-close semantics for request/response protocols (SMTP, IMAP,
///   HTTP-over-TCP passthrough) where the client finishes sending first and
///   the backend then takes arbitrary time to respond. The idle timeout still
///   applies, so a stuck peer cannot wedge the connection indefinitely.
/// * If Phase 1 ended with an **error** or the **idle timeout** fired, the
///   remaining direction is awaited with a short 100ms grace window so we
///   can capture any error it would produce without hanging on a bad peer.
///
/// When `idle_timeout` is `Some(d)` and non-zero, the connection is closed
/// if no data is received on either side for the given duration.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn bidirectional_splice(
    client: TcpStream,
    backend: TcpStream,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
    backend_read_timeout: Option<Duration>,
    backend_write_timeout: Option<Duration>,
    pipe_size: usize,
) -> StreamCopyResult {
    // Create two pipes: one for each direction. Guards close fds on drop.
    let (c2b_pipe_r, c2b_pipe_w) = match create_splice_pipe(pipe_size) {
        Ok(p) => p,
        Err(e) => {
            return StreamCopyResult {
                bytes_client_to_backend: 0,
                bytes_backend_to_client: 0,
                first_failure: Some((
                    Direction::Unknown,
                    classify_stream_error(&e),
                    None,
                    e.to_string(),
                )),
            };
        }
    };
    let _c2b_guard = SplicePipeGuard(c2b_pipe_r, c2b_pipe_w);
    let (b2c_pipe_r, b2c_pipe_w) = match create_splice_pipe(pipe_size) {
        Ok(p) => p,
        Err(e) => {
            return StreamCopyResult {
                bytes_client_to_backend: 0,
                bytes_backend_to_client: 0,
                first_failure: Some((
                    Direction::Unknown,
                    classify_stream_error(&e),
                    None,
                    e.to_string(),
                )),
            };
        }
    };
    let _b2c_guard = SplicePipeGuard(b2c_pipe_r, b2c_pipe_w);

    let now = coarse_now_ms();
    let last_activity = if idle_timeout.is_some_and(|t| !t.is_zero()) {
        Some(Arc::new(AtomicU64::new(now)))
    } else {
        None
    };

    // Per-direction inactivity watermarks. b2c reads from backend, so
    // `backend_read_timeout_ms` watches b2c_read_watermark. c2b writes to
    // backend, so `backend_write_timeout_ms` watches c2b_write_watermark.
    // Read watermark starts at `now` (silent backend is immediately stale).
    // Write watermark starts at u64::MAX (sentinel) so the check stays inert
    // until c2b actually has queued bytes — `splice_one_direction_no_guard`
    // primes it with `now` the moment its src→pipe splice succeeds.
    let read_wm_active = backend_read_timeout.is_some_and(|d| !d.is_zero());
    let write_wm_active = backend_write_timeout.is_some_and(|d| !d.is_zero());
    let b2c_read_watermark = read_wm_active.then(|| Arc::new(AtomicU64::new(now)));
    let c2b_write_watermark = write_wm_active.then(|| Arc::new(AtomicU64::new(u64::MAX)));

    let c2b_bytes = Arc::new(AtomicU64::new(0));
    let b2c_bytes = Arc::new(AtomicU64::new(0));

    let la_c2b = last_activity.clone();
    let la_b2c = last_activity.clone();
    let c2b_bytes_task = c2b_bytes.clone();
    let b2c_bytes_task = b2c_bytes.clone();

    // Pin both direction futures for use with select! — no spawned tasks.
    let c2b_fut = splice_one_direction_no_guard(
        &client,
        c2b_pipe_w,
        c2b_pipe_r,
        &backend,
        la_c2b,
        c2b_bytes_task,
        None,
        c2b_write_watermark.clone(),
    );
    let b2c_fut = splice_one_direction_no_guard(
        &backend,
        b2c_pipe_w,
        b2c_pipe_r,
        &client,
        la_b2c,
        b2c_bytes_task,
        b2c_read_watermark.clone(),
        None,
    );
    tokio::pin!(c2b_fut);
    tokio::pin!(b2c_fut);

    let idle_timeout_active = idle_timeout.is_some_and(|t| !t.is_zero());
    let timeout_ms = idle_timeout.map(|t| t.as_millis() as u64).unwrap_or(0);
    let backend_read_timeout_ms = backend_read_timeout
        .map(|t| t.as_millis() as u64)
        .unwrap_or(0);
    let backend_write_timeout_ms = backend_write_timeout
        .map(|t| t.as_millis() as u64)
        .unwrap_or(0);
    let any_watchdog_active = idle_timeout_active || read_wm_active || write_wm_active;
    let watchdog_interval =
        relay_watchdog_interval(&[idle_timeout, backend_read_timeout, backend_write_timeout]);

    let mut first_failure: Option<(Direction, ErrorClass, Option<StreamIoSide>, String)> = None;
    let mut c2b_done = false;
    let mut b2c_done = false;

    // Phase 1: race the two directions (plus optional watchdog).
    loop {
        tokio::select! {
            biased;
            c2b_result = &mut c2b_fut, if !c2b_done => {
                c2b_done = true;
                if let Err((side, e)) = c2b_result
                    && first_failure.is_none()
                {
                    let msg = e.to_string();
                    first_failure = Some((
                        Direction::ClientToBackend,
                        classify_stream_error(&e),
                        Some(side),
                        msg,
                    ));
                }
                break;
            }
            b2c_result = &mut b2c_fut, if !b2c_done => {
                b2c_done = true;
                if let Err((side, e)) = b2c_result
                    && first_failure.is_none()
                {
                    let msg = e.to_string();
                    first_failure = Some((
                        Direction::BackendToClient,
                        classify_stream_error(&e),
                        Some(side),
                        msg,
                    ));
                }
                break;
            }
            // Watchdog tick — idle + per-direction backend timeouts.
            _ = tokio::time::sleep(watchdog_interval), if any_watchdog_active => {
                let now = coarse_now_ms();
                if let Some(ref wm) = b2c_read_watermark
                    && now.saturating_sub(wm.load(Ordering::Relaxed)) >= backend_read_timeout_ms
                {
                    first_failure = Some((
                        Direction::BackendToClient,
                        ErrorClass::ReadWriteTimeout,
                        Some(StreamIoSide::Read),
                        STREAM_SPLICE_BACKEND_READ_TIMEOUT_PREFIX.to_string(),
                    ));
                    break;
                }
                if let Some(ref wm) = c2b_write_watermark
                    && now.saturating_sub(wm.load(Ordering::Relaxed)) >= backend_write_timeout_ms
                {
                    first_failure = Some((
                        Direction::ClientToBackend,
                        ErrorClass::ReadWriteTimeout,
                        Some(StreamIoSide::Write),
                        STREAM_SPLICE_BACKEND_WRITE_TIMEOUT_PREFIX.to_string(),
                    ));
                    break;
                }
                if let Some(ref la) = last_activity {
                    let last = la.load(Ordering::Relaxed);
                    if now.saturating_sub(last) >= timeout_ms {
                        first_failure = Some((
                            Direction::Unknown,
                            ErrorClass::ReadWriteTimeout,
                            None,
                            "idle timeout".to_string(),
                        ));
                        break;
                    }
                }
            }
        }
    }

    // Phase 2: drain the remaining direction.
    //
    // Two cases:
    //
    // * **Clean EOF** (`first_failure.is_none()`): one side finished its splice
    //   without error — most commonly a half-close where the client finished
    //   sending and the backend is still generating a large/slow response (or
    //   vice versa). Wait for the remaining direction to complete naturally,
    //   bounded by the idle timeout AND the half-close hard cap. See
    //   `bidirectional_copy` for the full rationale — the hard cap matters
    //   here because `FERRUM_TCP_IDLE_TIMEOUT_SECONDS=0` disables idle
    //   bookkeeping but the splice task still needs a safety net.
    //
    // * **Error or idle timeout** (`first_failure.is_some()`): both halves are
    //   likely in a bad state. Give the remaining direction a brief grace
    //   window to capture any error it would produce, then move on. Do not
    //   block the connection teardown on a stuck peer.
    let clean_eof = first_failure.is_none();
    if !c2b_done {
        if clean_eof {
            first_failure = drain_half_close_splice(
                &mut c2b_fut,
                &last_activity,
                idle_timeout_active,
                timeout_ms,
                half_close_cap,
                Direction::ClientToBackend,
                c2b_write_watermark.as_deref(),
                backend_write_timeout_ms,
                StreamIoSide::Write,
                STREAM_SPLICE_BACKEND_WRITE_TIMEOUT_PREFIX,
                watchdog_interval,
            )
            .await;
        } else {
            match tokio::time::timeout(BIDIRECTIONAL_DRAIN_GRACE, &mut c2b_fut).await {
                Ok(Ok(())) => {}
                Ok(Err((side, e))) => {
                    if first_failure.is_none() {
                        let msg = e.to_string();
                        first_failure = Some((
                            Direction::ClientToBackend,
                            classify_stream_error(&e),
                            Some(side),
                            msg,
                        ));
                    }
                }
                Err(_) => { /* grace expired — leave counters as-is */ }
            }
        }
    }
    if !b2c_done {
        if clean_eof {
            first_failure = drain_half_close_splice(
                &mut b2c_fut,
                &last_activity,
                idle_timeout_active,
                timeout_ms,
                half_close_cap,
                Direction::BackendToClient,
                b2c_read_watermark.as_deref(),
                backend_read_timeout_ms,
                StreamIoSide::Read,
                STREAM_SPLICE_BACKEND_READ_TIMEOUT_PREFIX,
                watchdog_interval,
            )
            .await;
        } else {
            match tokio::time::timeout(BIDIRECTIONAL_DRAIN_GRACE, &mut b2c_fut).await {
                Ok(Ok(())) => {}
                Ok(Err((side, e))) => {
                    if first_failure.is_none() {
                        let msg = e.to_string();
                        first_failure = Some((
                            Direction::BackendToClient,
                            classify_stream_error(&e),
                            Some(side),
                            msg,
                        ));
                    }
                }
                Err(_) => { /* grace expired — leave counters as-is */ }
            }
        }
    }

    StreamCopyResult {
        bytes_client_to_backend: c2b_bytes.load(Ordering::Relaxed),
        bytes_backend_to_client: b2c_bytes.load(Ordering::Relaxed),
        first_failure,
    }
}

/// Propagate a clean EOF across a splice relay.
///
/// `tokio::io::copy_bidirectional` half-closes the opposite write side when
/// one read side reaches EOF. The splice path works with raw fds, so we must
/// do that explicitly; otherwise request/response backends can wait forever
/// for EOF and the connection task never reaches stream-disconnect hooks.
#[cfg(target_os = "linux")]
fn shutdown_write_fd(fd: i32) {
    // Ignore errors: the peer may already have closed/reset the socket. This is
    // best-effort half-close propagation, not an additional failure source.
    unsafe {
        libc::shutdown(fd, libc::SHUT_WR);
    }
}

/// Splice-path equivalent of `drain_half_close_copy`. Separate function
/// because the splice direction future's `Ok` branch returns `anyhow::Error`
/// rather than `std::io::Error`, and the classifier takes the outer anyhow
/// value directly.
///
/// `direction_watermark` / `direction_timeout_ms` enforce the per-direction
/// backend timeout for whichever side is being drained:
/// * `Direction::ClientToBackend` → c2b_write_watermark + backend_write_timeout
/// * `Direction::BackendToClient` → b2c_read_watermark + backend_read_timeout
///
/// `direction_side` is the `StreamIoSide` attribution for the timeout case
/// (Write for c2b, Read for b2c) and `direction_prefix` is the matching
/// sentinel constant for the failure message.
///
/// `watchdog_interval` should be the same `relay_watchdog_interval` value
/// Phase 1 used — passing it through keeps Phase 1 and Phase 2 ticks on the
/// same cadence, matching the "1 s under 30 s timeouts, 5 s otherwise"
/// guarantee documented in `docs/tcp_udp_proxy.md`.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn drain_half_close_splice<F>(
    drain_fut: &mut F,
    last_activity: &Option<Arc<AtomicU64>>,
    idle_timeout_active: bool,
    timeout_ms: u64,
    half_close_cap: Option<Duration>,
    direction: Direction,
    direction_watermark: Option<&AtomicU64>,
    direction_timeout_ms: u64,
    direction_side: StreamIoSide,
    direction_prefix: &'static str,
    watchdog_interval: Duration,
) -> Option<(Direction, ErrorClass, Option<StreamIoSide>, String)>
where
    F: std::future::Future<Output = Result<(), (StreamIoSide, anyhow::Error)>> + Unpin,
{
    let direction_wm_active = direction_watermark.is_some() && direction_timeout_ms > 0;
    let any_tick_active = idle_timeout_active || direction_wm_active;
    let phase2_start = Instant::now();
    loop {
        tokio::select! {
            biased;
            result = &mut *drain_fut => {
                if let Err((side, e)) = result {
                    let msg = e.to_string();
                    return Some((direction, classify_stream_error(&e), Some(side), msg));
                }
                return None;
            }
            _ = tokio::time::sleep(watchdog_interval), if any_tick_active => {
                let now = coarse_now_ms();
                if let Some(wm) = direction_watermark
                    && direction_timeout_ms > 0
                    && now.saturating_sub(wm.load(Ordering::Relaxed)) >= direction_timeout_ms
                {
                    return Some((
                        direction,
                        ErrorClass::ReadWriteTimeout,
                        Some(direction_side),
                        direction_prefix.to_string(),
                    ));
                }
                if let Some(la) = last_activity.as_ref() {
                    let last = la.load(Ordering::Relaxed);
                    if now.saturating_sub(last) >= timeout_ms {
                        return Some((
                            Direction::Unknown,
                            ErrorClass::ReadWriteTimeout,
                            None,
                            "idle timeout".to_string(),
                        ));
                    }
                }
                if let Some(cap) = half_close_cap
                    && phase2_start.elapsed() >= cap
                {
                    return Some((
                        Direction::Unknown,
                        ErrorClass::ReadWriteTimeout,
                        None,
                        "tcp half-close max wait exceeded".to_string(),
                    ));
                }
            }
            _ = sleep_for_cap(half_close_cap), if half_close_cap.is_some() && !any_tick_active => {
                return Some((
                    Direction::Unknown,
                    ErrorClass::ReadWriteTimeout,
                    None,
                    "tcp half-close max wait exceeded".to_string(),
                ));
            }
        }
    }
}

/// Classify an io_uring/libc splice worker's failure into a
/// `StreamFirstFailure` tuple. The worker emits one of three sentinel
/// prefixes for timeout cases, each mapping to distinct attribution:
/// * `STREAM_SPLICE_IDLE_TIMEOUT_PREFIX` → `(Unknown, ReadWriteTimeout, None)`
/// * `STREAM_SPLICE_BACKEND_READ_TIMEOUT_PREFIX` → `(worker_dir, ReadWriteTimeout, Read)`
/// * `STREAM_SPLICE_BACKEND_WRITE_TIMEOUT_PREFIX` → `(worker_dir, ReadWriteTimeout, Write)`
///
/// Everything else falls through to `classify_stream_error` with the
/// worker's direction and the side returned by the splice loop.
#[cfg(target_os = "linux")]
fn classify_splice_worker_failure(
    worker_direction: Direction,
    side: StreamIoSide,
    msg: &str,
    err: &anyhow::Error,
) -> StreamFirstFailure {
    if msg.starts_with(STREAM_SPLICE_IDLE_TIMEOUT_PREFIX) {
        (
            Direction::Unknown,
            ErrorClass::ReadWriteTimeout,
            None,
            msg.to_string(),
        )
    } else if msg.starts_with(STREAM_SPLICE_BACKEND_READ_TIMEOUT_PREFIX) {
        (
            worker_direction,
            ErrorClass::ReadWriteTimeout,
            Some(StreamIoSide::Read),
            msg.to_string(),
        )
    } else if msg.starts_with(STREAM_SPLICE_BACKEND_WRITE_TIMEOUT_PREFIX) {
        (
            worker_direction,
            ErrorClass::ReadWriteTimeout,
            Some(StreamIoSide::Write),
            msg.to_string(),
        )
    } else {
        (
            worker_direction,
            classify_stream_error(err),
            Some(side),
            msg.to_string(),
        )
    }
}

#[cfg(target_os = "linux")]
const IO_URING_SPLICE_MAX_CONCURRENT: usize = 128;

#[cfg(target_os = "linux")]
static IO_URING_SPLICE_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[cfg(target_os = "linux")]
fn io_uring_splice_limit() -> Arc<Semaphore> {
    IO_URING_SPLICE_LIMIT
        .get_or_init(|| Arc::new(Semaphore::new(IO_URING_SPLICE_MAX_CONCURRENT)))
        .clone()
}

#[cfg(target_os = "linux")]
fn try_acquire_io_uring_splice_permit(limit: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    limit.clone().try_acquire_owned().ok()
}

#[cfg(all(test, target_os = "linux"))]
mod io_uring_splice_limit_tests {
    use super::*;

    #[test]
    fn permit_gate_returns_none_when_limit_is_exhausted() {
        let limit = Arc::new(Semaphore::new(1));
        let permit =
            try_acquire_io_uring_splice_permit(&limit).expect("first permit should be available");

        assert!(
            try_acquire_io_uring_splice_permit(&limit).is_none(),
            "saturated io_uring splice limit should decline another relay"
        );

        drop(permit);
        assert!(
            try_acquire_io_uring_splice_permit(&limit).is_some(),
            "released permit should make the relay slot available again"
        );
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn bidirectional_splice_io_uring_bounded_or_async(
    client: TcpStream,
    backend: TcpStream,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
    backend_read_timeout: Option<Duration>,
    backend_write_timeout: Option<Duration>,
    pipe_size: usize,
) -> StreamCopyResult {
    let limit = io_uring_splice_limit();
    if let Some(_permit) = try_acquire_io_uring_splice_permit(&limit) {
        bidirectional_splice_io_uring(
            client,
            backend,
            idle_timeout,
            half_close_cap,
            backend_read_timeout,
            backend_write_timeout,
            pipe_size,
        )
        .await
    } else {
        debug!(
            max_concurrent = IO_URING_SPLICE_MAX_CONCURRENT,
            "io_uring splice concurrency limit reached; falling back to async splice"
        );
        bidirectional_splice(
            client,
            backend,
            idle_timeout,
            half_close_cap,
            backend_read_timeout,
            backend_write_timeout,
            pipe_size,
        )
        .await
    }
}

/// Bidirectional zero-copy relay using io_uring `IORING_OP_SPLICE`.
///
/// Each direction gets its own io_uring ring (8 entries) and runs on a
/// dedicated blocking thread via `tokio::task::spawn_blocking`. This avoids
/// the async yield_now polling loop used by the libc splice path and reduces
/// per-operation syscall overhead.
///
/// Resource management is fully RAII: pipe fds are managed by `SplicePipeGuard`,
/// and `client`/`backend` streams stay alive on the stack until after the join.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn bidirectional_splice_io_uring(
    client: TcpStream,
    backend: TcpStream,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
    backend_read_timeout: Option<Duration>,
    backend_write_timeout: Option<Duration>,
    pipe_size: usize,
) -> StreamCopyResult {
    // `half_close_cap` bounds the time we wait for the second direction once
    // the first has completed. The io_uring workers run on blocking threads
    // and cannot observe a Phase 1 / Phase 2 split directly, so we enforce
    // the cap by racing the join with a timer and — on timeout — calling
    // `shutdown(SHUT_RDWR)` on both sockets. That forces the splice syscall
    // in the still-running worker to return, letting the blocking thread
    // unwind instead of pinning under a stalled peer when
    // `FERRUM_TCP_IDLE_TIMEOUT_SECONDS=0`.
    use std::os::unix::io::AsRawFd;
    let client_fd = client.as_raw_fd();
    let backend_fd = backend.as_raw_fd();

    // Create pipes with RAII guards — guards close fds on drop, ensuring cleanup
    // even if spawn_blocking panics or the function returns early.
    let (c2b_pipe_r, c2b_pipe_w) = match create_splice_pipe(pipe_size) {
        Ok(p) => p,
        Err(e) => {
            return StreamCopyResult {
                bytes_client_to_backend: 0,
                bytes_backend_to_client: 0,
                first_failure: Some((
                    Direction::Unknown,
                    classify_stream_error(&e),
                    None,
                    e.to_string(),
                )),
            };
        }
    };
    let _c2b_guard = SplicePipeGuard(c2b_pipe_r, c2b_pipe_w);
    let (b2c_pipe_r, b2c_pipe_w) = match create_splice_pipe(pipe_size) {
        Ok(p) => p,
        Err(e) => {
            return StreamCopyResult {
                bytes_client_to_backend: 0,
                bytes_backend_to_client: 0,
                first_failure: Some((
                    Direction::Unknown,
                    classify_stream_error(&e),
                    None,
                    e.to_string(),
                )),
            };
        }
    };
    let _b2c_guard = SplicePipeGuard(b2c_pipe_r, b2c_pipe_w);

    let timeout_ms = idle_timeout
        .filter(|t| !t.is_zero())
        .map(|t| t.as_millis() as u64)
        .unwrap_or(0);
    let backend_read_timeout_ms = backend_read_timeout
        .filter(|t| !t.is_zero())
        .map(|t| t.as_millis() as u64)
        .unwrap_or(0);
    let backend_write_timeout_ms = backend_write_timeout
        .filter(|t| !t.is_zero())
        .map(|t| t.as_millis() as u64)
        .unwrap_or(0);

    let now = coarse_now_ms();

    // Shared last-activity timestamp across both directions. Activity in either
    // direction refreshes the timestamp, preventing one-way streams (e.g., downloads)
    // from timing out on the idle send direction.
    let shared_activity = Arc::new(AtomicU64::new(now));
    let sa_c2b = shared_activity.clone();
    let sa_b2c = shared_activity;

    // Per-direction watermarks for backend_{read,write}_timeout enforcement.
    // b2c reads from backend → backend_read_timeout watches b2c_read_wm.
    // c2b writes to backend → backend_write_timeout watches c2b_write_wm.
    // Read watermark starts at `now` (a silent backend is immediately stale).
    // Write watermark starts at u64::MAX so the check stays inert until c2b
    // primes it when its first read produces queued bytes.
    let b2c_read_wm = (backend_read_timeout_ms > 0).then(|| Arc::new(AtomicU64::new(now)));
    let c2b_write_wm = (backend_write_timeout_ms > 0).then(|| Arc::new(AtomicU64::new(u64::MAX)));
    let b2c_read_wm_worker = b2c_read_wm.clone();
    let c2b_write_wm_worker = c2b_write_wm.clone();

    // First-failure attribution across the two blocking threads. Each worker
    // writes into the `OnceLock` at the moment its splice call errors, so the
    // slot records whichever direction actually failed first in the kernel
    // rather than a deterministic post-join order. `OnceLock::set()` is
    // first-writer-wins; later writes from the opposite worker (or the
    // post-join fallback) are silently ignored.
    let first_failure: Arc<OnceLock<StreamFirstFailure>> = Arc::new(OnceLock::new());
    let ff_c2b = first_failure.clone();
    let ff_b2c = first_failure.clone();

    // Each direction runs on its own blocking thread with its own io_uring ring.
    // Timeout expirations from the splice loop are reported as anyhow errors
    // whose text starts with one of three sentinel constants:
    //   * STREAM_SPLICE_IDLE_TIMEOUT_PREFIX            → (Unknown, None) — bi-directional idle
    //   * STREAM_SPLICE_BACKEND_READ_TIMEOUT_PREFIX    → (worker dir, Read) — backend stopped sending
    //   * STREAM_SPLICE_BACKEND_WRITE_TIMEOUT_PREFIX   → (worker dir, Write) — backend stopped accepting
    // Mapping these directly to `ErrorClass::ReadWriteTimeout` keeps
    // `disconnect_cause_for_failure` consistent with the userspace
    // `bidirectional_copy` path. Running them through `classify_stream_error`
    // would return `ConnectionTimeout`, which the cause mapper treats as a
    // recv/backend error. The emission sites in `io_uring_splice_loop` /
    // `libc_splice_loop` reference the same constants so a rename is a
    // compile-time coupling, not a silent drift.
    let c2b_handle = tokio::task::spawn_blocking(move || {
        let res = io_uring_splice_direction(
            client_fd,
            c2b_pipe_w,
            c2b_pipe_r,
            backend_fd,
            timeout_ms,
            &sa_c2b,
            None,
            0,
            c2b_write_wm_worker.as_deref(),
            backend_write_timeout_ms,
        );
        if let Err((side, ref e)) = res {
            let msg = e.to_string();
            let entry = classify_splice_worker_failure(Direction::ClientToBackend, side, &msg, e);
            let _ = ff_c2b.set(entry);
        }
        res
    });
    let b2c_handle = tokio::task::spawn_blocking(move || {
        let res = io_uring_splice_direction(
            backend_fd,
            b2c_pipe_w,
            b2c_pipe_r,
            client_fd,
            timeout_ms,
            &sa_b2c,
            b2c_read_wm_worker.as_deref(),
            backend_read_timeout_ms,
            None,
            0,
        );
        if let Err((side, ref e)) = res {
            let msg = e.to_string();
            let entry = classify_splice_worker_failure(Direction::BackendToClient, side, &msg, e);
            let _ = ff_b2c.set(entry);
        }
        res
    });

    // Wait for the first direction to complete, then bound the second with
    // `half_close_cap`. On cap timeout, force-shutdown both sockets so the
    // splice syscall in the remaining blocking worker returns and the
    // thread unwinds. Pipe guards (`_c2b_guard`, `_b2c_guard`) close pipe
    // fds on drop regardless.
    //
    // When the first worker exits with an *error* (not a clean EOF), the
    // surviving worker is force-shutdown immediately so it cannot hang
    // waiting on a peer that the other half has already torn down. This
    // mirrors `bidirectional_copy`'s `BIDIRECTIONAL_DRAIN_GRACE` for the
    // error case: the connection is already broken; we should not wait
    // `half_close_cap` (typically 5 min) for the other side to notice.
    let mut c2b_handle = c2b_handle;
    let mut b2c_handle = b2c_handle;
    let ff_cap = first_failure.clone();
    let force_shutdown = move || unsafe {
        libc::shutdown(client_fd, libc::SHUT_RDWR);
        libc::shutdown(backend_fd, libc::SHUT_RDWR);
    };
    let (c2b_result, b2c_result) = tokio::select! {
        c2b_res = &mut c2b_handle => {
            let first_errored = matches!(&c2b_res, Ok(Err(_)));
            if first_errored {
                force_shutdown();
            }
            let b2c_res = match half_close_cap.filter(|t| !t.is_zero()) {
                Some(cap) => match tokio::time::timeout(cap, &mut b2c_handle).await {
                    Ok(r) => r,
                    Err(_) => {
                        let _ = ff_cap.set((
                            Direction::BackendToClient,
                            ErrorClass::ReadWriteTimeout,
                            None,
                            "TCP half-close cap exceeded (io_uring splice)".to_string(),
                        ));
                        force_shutdown();
                        (&mut b2c_handle).await
                    }
                },
                None => (&mut b2c_handle).await,
            };
            (c2b_res, b2c_res)
        }
        b2c_res = &mut b2c_handle => {
            let first_errored = matches!(&b2c_res, Ok(Err(_)));
            if first_errored {
                force_shutdown();
            }
            let c2b_res = match half_close_cap.filter(|t| !t.is_zero()) {
                Some(cap) => match tokio::time::timeout(cap, &mut c2b_handle).await {
                    Ok(r) => r,
                    Err(_) => {
                        let _ = ff_cap.set((
                            Direction::ClientToBackend,
                            ErrorClass::ReadWriteTimeout,
                            None,
                            "TCP half-close cap exceeded (io_uring splice)".to_string(),
                        ));
                        force_shutdown();
                        (&mut c2b_handle).await
                    }
                },
                None => (&mut c2b_handle).await,
            };
            (c2b_res, b2c_res)
        }
    };

    let c2b_bytes = match c2b_result {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => 0, // already recorded from inside the worker
        Err(e) => {
            // JoinError (task panicked or was cancelled) — side is not
            // meaningful. Only records if the worker didn't already set it.
            let anyhow_err = anyhow::anyhow!("io_uring splice spawn error: {}", e);
            let msg = anyhow_err.to_string();
            let _ = first_failure.set((
                Direction::ClientToBackend,
                classify_stream_error(&anyhow_err),
                None,
                msg,
            ));
            0
        }
    };
    let b2c_bytes = match b2c_result {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => 0,
        Err(e) => {
            let anyhow_err = anyhow::anyhow!("io_uring splice spawn error: {}", e);
            let msg = anyhow_err.to_string();
            let _ = first_failure.set((
                Direction::BackendToClient,
                classify_stream_error(&anyhow_err),
                None,
                msg,
            ));
            0
        }
    };

    StreamCopyResult {
        bytes_client_to_backend: c2b_bytes,
        bytes_backend_to_client: b2c_bytes,
        first_failure: first_failure.get().cloned(),
    }
    // Drop order (guaranteed by Rust): result returned → _b2c_guard closes pipes →
    // _c2b_guard closes pipes → backend dropped (fd closed) → client dropped (fd closed).
    // Blocking threads have already joined, so raw fds are no longer in use.
}

/// Run the io_uring splice loop for one direction on a blocking thread.
///
/// Falls back to libc::splice if io_uring ring creation fails (memlock
/// pressure, resource limits). The idle timeout is checked inline inside
/// the io_uring loop to prevent indefinite blocking on idle connections.
///
/// `read_watermark` / `read_timeout_ms` and `write_watermark` /
/// `write_timeout_ms` enforce `backend_read_timeout_ms` and
/// `backend_write_timeout_ms` respectively. Pass `None` / `0` on the side
/// that does not face the backend — see `bidirectional_splice_io_uring`
/// for which worker carries which watermark.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn io_uring_splice_direction(
    src_fd: i32,
    pipe_w: i32,
    pipe_r: i32,
    dst_fd: i32,
    timeout_ms: u64,
    shared_activity: &AtomicU64,
    read_watermark: Option<&AtomicU64>,
    read_timeout_ms: u64,
    write_watermark: Option<&AtomicU64>,
    write_timeout_ms: u64,
) -> Result<u64, (StreamIoSide, anyhow::Error)> {
    let result = match crate::socket_opts::io_uring_splice::io_uring_splice_loop(
        src_fd,
        pipe_w,
        pipe_r,
        dst_fd,
        shared_activity,
        timeout_ms,
        read_watermark,
        read_timeout_ms,
        write_watermark,
        write_timeout_ms,
    ) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.source.kind() == std::io::ErrorKind::Unsupported => {
            // io_uring ring creation failed — fall back to libc::splice.
            // This can happen under memlock pressure even though startup
            // probing succeeded.
            tracing::debug!("io_uring ring creation failed, falling back to libc splice");
            libc_splice_loop(
                src_fd,
                pipe_w,
                pipe_r,
                dst_fd,
                timeout_ms,
                shared_activity,
                read_watermark,
                read_timeout_ms,
                write_watermark,
                write_timeout_ms,
            )
        }
        Err(e) => {
            let side = if e.is_write_side {
                StreamIoSide::Write
            } else {
                StreamIoSide::Read
            };
            if e.source.kind() == std::io::ErrorKind::TimedOut {
                // Use `.starts_with(...)` to match the contract of
                // `classify_splice_worker_failure` (the downstream classifier):
                // if `io_uring_splice_loop` ever wraps the sentinel with extra
                // context (e.g. byte counts in a debug aid) an exact-match
                // here would silently fall through to the idle arm and
                // mis-attribute the timeout.
                let body = e.source.to_string();
                if body.starts_with(STREAM_SPLICE_BACKEND_READ_TIMEOUT_PREFIX) {
                    Err((
                        side,
                        anyhow::anyhow!(
                            "{} (io_uring splice)",
                            STREAM_SPLICE_BACKEND_READ_TIMEOUT_PREFIX
                        ),
                    ))
                } else if body.starts_with(STREAM_SPLICE_BACKEND_WRITE_TIMEOUT_PREFIX) {
                    Err((
                        side,
                        anyhow::anyhow!(
                            "{} (io_uring splice)",
                            STREAM_SPLICE_BACKEND_WRITE_TIMEOUT_PREFIX
                        ),
                    ))
                } else {
                    Err((
                        side,
                        anyhow::anyhow!("{} (io_uring splice)", STREAM_SPLICE_IDLE_TIMEOUT_PREFIX),
                    ))
                }
            } else {
                Err((side, anyhow::anyhow!("io_uring splice error: {}", e.source)))
            }
        }
    };

    if result.is_ok() {
        shutdown_write_fd(dst_fd);
    }

    result
}

/// Fallback libc::splice loop for when io_uring ring creation fails.
/// Same logic as `splice_one_direction_no_guard` but synchronous (runs
/// on a blocking thread). Errors are tagged with the side (Read for the
/// src_fd → pipe splice, Write for the pipe → dst_fd splice) so the
/// caller can attribute the failure to the correct socket.
///
/// `read_watermark` / `read_timeout_ms` and `write_watermark` /
/// `write_timeout_ms` mirror the io_uring path — see
/// `io_uring_splice_direction` for which worker carries which watermark.
#[cfg(target_os = "linux")]
fn splice_once(in_fd: i32, out_fd: i32, len: usize, flags: u32) -> std::io::Result<isize> {
    let n = unsafe {
        libc::splice(
            in_fd,
            std::ptr::null_mut(),
            out_fd,
            std::ptr::null_mut(),
            len,
            flags,
        )
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n)
    }
}

#[cfg(target_os = "linux")]
async fn splice_when_ready<F>(
    stream: &TcpStream,
    interest: tokio::io::Interest,
    mut op: F,
) -> std::io::Result<isize>
where
    F: FnMut() -> std::io::Result<isize>,
{
    loop {
        stream.ready(interest).await?;
        match stream.try_io(interest, &mut op) {
            Ok(n) => return Ok(n),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
fn min_splice_deadline_remaining(
    current_min: &mut Option<u64>,
    now: u64,
    last: u64,
    timeout_ms: u64,
) {
    if timeout_ms == 0 || last == u64::MAX {
        return;
    }
    let remaining = timeout_ms.saturating_sub(now.saturating_sub(last));
    *current_min = Some(current_min.map_or(remaining, |min| min.min(remaining)));
}

#[cfg(any(test, target_os = "linux"))]
fn splice_poll_timeout_ms_at(
    now: u64,
    timeout_ms: u64,
    shared_activity: &AtomicU64,
    read_watermark: Option<&AtomicU64>,
    read_timeout_ms: u64,
    write_watermark: Option<&AtomicU64>,
    write_timeout_ms: u64,
) -> i32 {
    let mut remaining = None;
    min_splice_deadline_remaining(
        &mut remaining,
        now,
        shared_activity.load(Ordering::Relaxed),
        timeout_ms,
    );
    if let Some(wm) = read_watermark {
        min_splice_deadline_remaining(
            &mut remaining,
            now,
            wm.load(Ordering::Relaxed),
            read_timeout_ms,
        );
    }
    if let Some(wm) = write_watermark {
        min_splice_deadline_remaining(
            &mut remaining,
            now,
            wm.load(Ordering::Relaxed),
            write_timeout_ms,
        );
    }
    remaining.map_or(-1, |ms| ms.min(i32::MAX as u64) as i32)
}

#[cfg(target_os = "linux")]
fn splice_poll_timeout_ms(
    timeout_ms: u64,
    shared_activity: &AtomicU64,
    read_watermark: Option<&AtomicU64>,
    read_timeout_ms: u64,
    write_watermark: Option<&AtomicU64>,
    write_timeout_ms: u64,
) -> i32 {
    splice_poll_timeout_ms_at(
        coarse_now_ms(),
        timeout_ms,
        shared_activity,
        read_watermark,
        read_timeout_ms,
        write_watermark,
        write_timeout_ms,
    )
}

#[cfg(target_os = "linux")]
fn poll_splice_fd(fd: i32, events: libc::c_short, timeout_ms: i32) -> std::io::Result<()> {
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret >= 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn libc_splice_loop(
    src_fd: i32,
    pipe_w: i32,
    pipe_r: i32,
    dst_fd: i32,
    timeout_ms: u64,
    shared_activity: &AtomicU64,
    read_watermark: Option<&AtomicU64>,
    read_timeout_ms: u64,
    write_watermark: Option<&AtomicU64>,
    write_timeout_ms: u64,
) -> Result<u64, (StreamIoSide, anyhow::Error)> {
    let splice_flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;
    let mut total: u64 = 0;
    let read_wm_active = read_watermark.is_some() && read_timeout_ms > 0;
    let write_wm_active = write_watermark.is_some() && write_timeout_ms > 0;

    loop {
        if timeout_ms > 0 {
            let last = shared_activity.load(Ordering::Relaxed);
            if coarse_now_ms().saturating_sub(last) >= timeout_ms {
                return Err((
                    StreamIoSide::Read,
                    anyhow::anyhow!(
                        "{} (libc splice fallback)",
                        STREAM_SPLICE_IDLE_TIMEOUT_PREFIX
                    ),
                ));
            }
        }
        if read_wm_active && let Some(wm) = read_watermark {
            let last = wm.load(Ordering::Relaxed);
            if coarse_now_ms().saturating_sub(last) >= read_timeout_ms {
                return Err((
                    StreamIoSide::Read,
                    anyhow::anyhow!(
                        "{} (libc splice fallback)",
                        STREAM_SPLICE_BACKEND_READ_TIMEOUT_PREFIX
                    ),
                ));
            }
        }
        // See the io_uring loop's analogous block — the c2b worker must fire
        // `backend_write_timeout_ms` even when stuck in the Reading phase, to
        // match `bidirectional_copy`'s parent-watchdog semantics and the
        // libc-async splice path's parent watchdog. The watermark is
        // `u64::MAX` until c2b primes it on its first successful read, so
        // this check stays inert until c2b actually carries data.
        if write_wm_active && let Some(wm) = write_watermark {
            let last = wm.load(Ordering::Relaxed);
            if coarse_now_ms().saturating_sub(last) >= write_timeout_ms {
                return Err((
                    StreamIoSide::Write,
                    anyhow::anyhow!(
                        "{} (libc splice fallback)",
                        STREAM_SPLICE_BACKEND_WRITE_TIMEOUT_PREFIX
                    ),
                ));
            }
        }

        let n = unsafe {
            libc::splice(
                src_fd,
                std::ptr::null_mut(),
                pipe_w,
                std::ptr::null_mut(),
                128 * 1024,
                splice_flags,
            )
        };

        if n > 0 {
            let post_read_now = coarse_now_ms();
            if read_wm_active && let Some(wm) = read_watermark {
                wm.store(post_read_now, Ordering::Relaxed);
            }
            if write_wm_active && let Some(wm) = write_watermark {
                wm.store(post_read_now, Ordering::Relaxed);
            }
            let mut remaining = n as usize;
            while remaining > 0 {
                let written = unsafe {
                    libc::splice(
                        pipe_r,
                        std::ptr::null_mut(),
                        dst_fd,
                        std::ptr::null_mut(),
                        remaining,
                        splice_flags,
                    )
                };
                if written > 0 {
                    remaining -= written as usize;
                    total += written as u64;
                    // Refresh shared idle timeout — visible to both directions.
                    let post_write_now = coarse_now_ms();
                    if timeout_ms > 0 {
                        shared_activity.store(post_write_now, Ordering::Relaxed);
                    }
                    if write_wm_active && let Some(wm) = write_watermark {
                        wm.store(post_write_now, Ordering::Relaxed);
                    }
                } else if written == 0 {
                    // A zero-byte pipe -> destination splice is a clean
                    // terminal write-side condition. We are returning Ok
                    // and ending this relay direction, so mirror the read-EOF
                    // path and propagate a best-effort half-close.
                    shutdown_write_fd(dst_fd);
                    return Ok(total);
                } else {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        // CRITICAL: This inner-loop WouldBlock branch must recheck
                        // the idle timeout before sleeping. The `while remaining > 0`
                        // loop has no timeout check, so if the destination socket
                        // stops reading while data is buffered in the pipe, this
                        // branch would spin at 1000 iters/sec forever without
                        // releasing the blocking thread to the tokio pool.
                        if timeout_ms > 0 {
                            let last = shared_activity.load(Ordering::Relaxed);
                            if coarse_now_ms().saturating_sub(last) >= timeout_ms {
                                return Err((
                                    StreamIoSide::Write,
                                    anyhow::anyhow!(
                                        "{} (libc splice fallback, write phase)",
                                        STREAM_SPLICE_IDLE_TIMEOUT_PREFIX
                                    ),
                                ));
                            }
                        }
                        if write_wm_active && let Some(wm) = write_watermark {
                            let last = wm.load(Ordering::Relaxed);
                            if coarse_now_ms().saturating_sub(last) >= write_timeout_ms {
                                return Err((
                                    StreamIoSide::Write,
                                    anyhow::anyhow!(
                                        "{} (libc splice fallback)",
                                        STREAM_SPLICE_BACKEND_WRITE_TIMEOUT_PREFIX
                                    ),
                                ));
                            }
                        }
                        // The b2c worker can be stalled in Phase 2 (client
                        // not reading) while the backend has gone silent —
                        // check read_watermark here too so firing matches
                        // the parent-watchdog semantics of the libc-async
                        // splice path and the io_uring loop.
                        if read_wm_active && let Some(wm) = read_watermark {
                            let last = wm.load(Ordering::Relaxed);
                            if coarse_now_ms().saturating_sub(last) >= read_timeout_ms {
                                return Err((
                                    StreamIoSide::Read,
                                    anyhow::anyhow!(
                                        "{} (libc splice fallback)",
                                        STREAM_SPLICE_BACKEND_READ_TIMEOUT_PREFIX
                                    ),
                                ));
                            }
                        }
                        let wait_ms = splice_poll_timeout_ms(
                            timeout_ms,
                            shared_activity,
                            read_watermark,
                            read_timeout_ms,
                            write_watermark,
                            write_timeout_ms,
                        );
                        if let Err(err) = poll_splice_fd(dst_fd, libc::POLLOUT, wait_ms) {
                            return Err((
                                StreamIoSide::Write,
                                anyhow::anyhow!("splice write readiness error: {}", err),
                            ));
                        }
                        continue;
                    }
                    return Err((
                        StreamIoSide::Write,
                        anyhow::anyhow!("splice write error: {}", err),
                    ));
                }
            }
        } else if n == 0 {
            shutdown_write_fd(dst_fd);
            return Ok(total);
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                // The outer `loop` at the top rechecks the timeout, but add an
                // inline check here for uniformity with the Phase 2 branch above.
                if timeout_ms > 0 {
                    let last = shared_activity.load(Ordering::Relaxed);
                    if coarse_now_ms().saturating_sub(last) >= timeout_ms {
                        return Err((
                            StreamIoSide::Read,
                            anyhow::anyhow!(
                                "{} (libc splice fallback, read phase)",
                                STREAM_SPLICE_IDLE_TIMEOUT_PREFIX
                            ),
                        ));
                    }
                }
                if read_wm_active && let Some(wm) = read_watermark {
                    let last = wm.load(Ordering::Relaxed);
                    if coarse_now_ms().saturating_sub(last) >= read_timeout_ms {
                        return Err((
                            StreamIoSide::Read,
                            anyhow::anyhow!(
                                "{} (libc splice fallback)",
                                STREAM_SPLICE_BACKEND_READ_TIMEOUT_PREFIX
                            ),
                        ));
                    }
                }
                // Mirror the outer-loop check: the c2b worker must also
                // fire backend_write_timeout when stuck in Phase 1 with
                // stale queued bytes. See the outer-loop comment above.
                if write_wm_active && let Some(wm) = write_watermark {
                    let last = wm.load(Ordering::Relaxed);
                    if coarse_now_ms().saturating_sub(last) >= write_timeout_ms {
                        return Err((
                            StreamIoSide::Write,
                            anyhow::anyhow!(
                                "{} (libc splice fallback)",
                                STREAM_SPLICE_BACKEND_WRITE_TIMEOUT_PREFIX
                            ),
                        ));
                    }
                }
                let wait_ms = splice_poll_timeout_ms(
                    timeout_ms,
                    shared_activity,
                    read_watermark,
                    read_timeout_ms,
                    write_watermark,
                    write_timeout_ms,
                );
                if let Err(err) = poll_splice_fd(src_fd, libc::POLLIN, wait_ms) {
                    return Err((
                        StreamIoSide::Read,
                        anyhow::anyhow!("splice read readiness error: {}", err),
                    ));
                }
                continue;
            }
            return Err((
                StreamIoSide::Read,
                anyhow::anyhow!("splice read error: {}", err),
            ));
        }
    }
}

/// Create a pipe suitable for splice, sized to match the proxy buffer tier.
#[cfg(target_os = "linux")]
fn create_splice_pipe(desired_size: usize) -> Result<(i32, i32), anyhow::Error> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create splice pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Try to resize the pipe to match the adaptive buffer tier.
    // Failures are non-fatal — the kernel default (64 KB on most systems) is fine.
    unsafe {
        libc::fcntl(fds[1], libc::F_SETPIPE_SZ, desired_size as libc::c_int);
    }
    Ok((fds[0], fds[1]))
}

/// Splice data in one direction: src_fd → pipe → dst_fd.
///
/// Bytes transferred are accumulated into `bytes` so the caller can observe
/// the final count regardless of whether this direction completes cleanly or
/// errors. Pipe fds are managed by the caller's `SplicePipeGuard` — this
/// function does not close them. Errors are tagged with `StreamIoSide::Read`
/// when the src_fd → pipe splice fails and `StreamIoSide::Write` when the
/// pipe → dst_fd splice fails, so the caller can attribute the failure to
/// the correct socket (client-facing vs backend-facing).
///
/// `read_watermark` is refreshed on every successful src→pipe splice. The
/// caller (Phase 1 watchdog in `bidirectional_splice`) reads it to fire
/// `backend_read_timeout_ms` when the b2c direction's backend stops sending.
/// `write_watermark` is primed when src→pipe produces queued bytes and
/// refreshed on every successful pipe→dst splice. The caller fires
/// `backend_write_timeout_ms` from it for the c2b direction. Both are
/// `Option<&AtomicU64>` because c2b only carries write_watermark and b2c only
/// carries read_watermark — they share scope with the watchdog instead of
/// going through `Arc`.
#[cfg(target_os = "linux")]
fn refresh_splice_write_progress(
    last_activity: Option<&AtomicU64>,
    write_watermark: Option<&AtomicU64>,
) {
    let now = coarse_now_ms();
    if let Some(la) = last_activity {
        la.store(now, Ordering::Relaxed);
    }
    if let Some(wm) = write_watermark {
        wm.store(now, Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn splice_one_direction_no_guard(
    src: &TcpStream,
    pipe_w: i32,
    pipe_r: i32,
    dst: &TcpStream,
    last_activity: Option<Arc<AtomicU64>>,
    bytes: Arc<AtomicU64>,
    read_watermark: Option<Arc<AtomicU64>>,
    write_watermark: Option<Arc<AtomicU64>>,
) -> Result<(), (StreamIoSide, anyhow::Error)> {
    use std::os::unix::io::AsRawFd;

    let splice_flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;
    let src_fd = src.as_raw_fd();
    let dst_fd = dst.as_raw_fd();

    loop {
        // Phase 1: splice from source fd into write end of pipe
        let n = match splice_when_ready(src, tokio::io::Interest::READABLE, || {
            // Use 128 KB per splice call — large enough to amortize syscall
            // overhead, small enough to avoid holding the pipe buffer too long.
            splice_once(src_fd, pipe_w, 128 * 1024, splice_flags)
        })
        .await
        {
            Ok(n) => n,
            Err(err) => {
                return Err((
                    StreamIoSide::Read,
                    anyhow::anyhow!("splice read readiness error: {}", err),
                ));
            }
        };

        if n > 0 {
            let now = coarse_now_ms();
            if let Some(ref la) = last_activity {
                la.store(now, Ordering::Relaxed);
            }
            if let Some(ref wm) = read_watermark {
                wm.store(now, Ordering::Relaxed);
            }
            if let Some(ref wm) = write_watermark {
                // Prime the watermark before entering the write loop —
                // captures "we have `n` bytes ready to write as of `now`".
                wm.store(now, Ordering::Relaxed);
            }

            // Phase 2: splice from read end of pipe into destination fd
            let mut remaining = n as usize;
            while remaining > 0 {
                let written = match splice_when_ready(dst, tokio::io::Interest::WRITABLE, || {
                    splice_once(pipe_r, dst_fd, remaining, splice_flags)
                })
                .await
                {
                    Ok(n) => n,
                    Err(err) => {
                        return Err((
                            StreamIoSide::Write,
                            anyhow::anyhow!("splice write readiness error: {}", err),
                        ));
                    }
                };
                if written > 0 {
                    remaining -= written as usize;
                    bytes.fetch_add(written as u64, Ordering::Relaxed);
                    refresh_splice_write_progress(
                        last_activity.as_deref(),
                        write_watermark.as_deref(),
                    );
                } else if written == 0 {
                    // See the synchronous libc fallback above: a clean
                    // terminal write-side condition should still propagate
                    // the relay half-close before this direction exits Ok.
                    shutdown_write_fd(dst_fd);
                    return Ok(());
                }
            }
        } else if n == 0 {
            // EOF — source closed
            shutdown_write_fd(dst_fd);
            return Ok(());
        }
    }
}

/// RAII guard that closes pipe file descriptors on drop.
#[cfg(target_os = "linux")]
struct SplicePipeGuard(i32, i32);

#[cfg(target_os = "linux")]
impl Drop for SplicePipeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
            libc::close(self.1);
        }
    }
}

/// Returns monotonic milliseconds since the process's first call to the shared
/// clock helper. Used for coarse idle tracking — does not need sub-millisecond
/// precision, but MUST be monotonic so wall-clock slew or NTP corrections
/// cannot cause `saturating_sub` to pin the elapsed duration at 0 (which would
/// disable the idle timeout).
///
/// Delegates to `crate::socket_opts::monotonic_now_ms` so the libc splice loop
/// and the io_uring splice loop share the same clock via the
/// `shared_last_activity_ms: Arc<AtomicU64>` they both read/write.
#[inline]
fn coarse_now_ms() -> u64 {
    crate::socket_opts::monotonic_now_ms()
}

// ---------------------------------------------------------------------------
// kTLS support: install TLS session keys into the kernel so splice(2) works
// on encrypted TCP connections (Linux 4.13+).
// ---------------------------------------------------------------------------

/// Error type for the kTLS attempt. Distinguishes between pre-install failures
/// (where the TLS stream is still usable) and post-install failures (where the
/// connection is consumed and cannot be recovered).
#[cfg(target_os = "linux")]
enum KtlsError {
    /// kTLS could not be installed (unsupported cipher, wrong TLS version, etc.).
    /// The original streams are returned so the caller can fall back to userspace copy.
    Unsupported(Box<(tokio_rustls::server::TlsStream<TcpStream>, TcpStream)>),
    /// kTLS keys were installed into the kernel but the subsequent splice failed.
    /// The TLS stream has been consumed (into_inner + dangerous_extract_secrets)
    /// so there is no way to recover — propagate the error.
    Installed(anyhow::Error),
}

/// Return whether a **buffered** rustls `ServerConnection` (as held inside a
/// tokio-rustls `TlsStream`) may be abandoned for kernel TLS.
///
/// Always returns `false`.
///
/// ## Why this is fail-closed
///
/// `ServerConnection::dangerous_extract_secrets` delegates to
/// `dangerous_into_kernel_connection`, which refuses handoff only when secret
/// extraction is disabled, the handshake is incomplete, or **outbound** TLS
/// records remain in `sendable_tls`. It silently discards:
/// 1. decrypted-but-unread **received** plaintext, and
/// 2. any residual **inbound** bytes still sitting in rustls's private
///    deframer — in particular the head of a partial TLS record.
///
/// kTLS resumes decryption straight from the socket at the extracted `rx`
/// sequence number, so handoff is sound only if the next byte the kernel reads
/// is the first byte of that record. Case (1) is observable (`wants_read()` is
/// false while plaintext is staged). Case (2) is **not**: `ConnectionCommon`'s
/// deframer buffer is private and has no public accessor, so a session that
/// looks completely idle can still be holding the front of a record the kernel
/// will never see. Both cases are produced by exactly the client behaviour
/// that motivated issue #2955 — coalescing application data with the handshake
/// tail — so on this API there is no narrower predicate that is still sound.
///
/// rustls's supported kernel-handoff entry point is the **unbuffered** path:
/// drive `rustls::server::UnbufferedServerConnection` until
/// `ConnectionState::WriteTraffic`, then call
/// `dangerous_into_kernel_connection`. Reaching `WriteTraffic` proves the
/// caller-owned input buffer is drained at a record boundary. This gateway's
/// TCP frontend still handshakes through buffered tokio-rustls, so that proof
/// is unavailable here. Correctness wins over acceleration: keep the
/// `TlsStream` and relay in userspace.
///
/// The session is borrowed **immutably** on purpose. The refusal path must not
/// be able to consume, drain, or otherwise disturb rustls state: every
/// application byte already decrypted has to stay readable through the
/// `TlsStream` the caller falls back to. The logged reason therefore uses the
/// `&self` observables only (`wants_write`/`wants_read`), which tokio-rustls
/// has already refreshed via `process_new_packets` while completing `accept()`.
//
// Referenced by `try_ktls_splice` (Linux only) and by `crate::_test_support` in
// the library target. The binary target compiles this module directly and does
// not include `_test_support`, so non-Linux binaries have no caller.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn ktls_rustls_buffers_safe_for_kernel_handoff(
    server_conn: &rustls::ServerConnection,
) -> bool {
    // Operator-visible evidence that the buffered accept path never hands off.
    static LOG_ONCE: std::sync::Once = std::sync::Once::new();
    LOG_ONCE.call_once(|| {
        info!(
            "kTLS: kernel handoff from the buffered tokio-rustls TlsStream is disabled - \
             the public rustls ServerConnection API cannot prove that the inbound deframer \
             is empty and record-aligned (issue #2955), so frontend-TLS TCP keeps the \
             userspace relay"
        );
    });

    if server_conn.wants_write() {
        debug!(
            "kTLS: rustls still holds outbound TLS records; refusing kernel handoff, \
             retaining userspace TlsStream"
        );
    } else if !server_conn.wants_read() {
        debug!(
            "kTLS: rustls holds unread decrypted plaintext (or a received close_notify) \
             after the handshake; refusing kernel handoff, retaining userspace TlsStream"
        );
    } else {
        debug!(
            "kTLS: buffered rustls ServerConnection cannot prove an empty, record-aligned \
             inbound deframer; refusing kernel handoff (issue #2955), retaining userspace \
             TlsStream"
        );
    }

    false
}

/// Attempt kTLS-accelerated splice for a frontend-TLS + plain-backend connection.
///
/// 1. Check that the negotiated cipher is AES-128-GCM or AES-256-GCM.
/// 2. Check that the negotiated TLS version is TLS 1.2 (see below).
/// 3. Refuse handoff from the buffered tokio-rustls `TlsStream` (see
///    [`ktls_rustls_buffers_safe_for_kernel_handoff`] — always fails closed
///    until an unbuffered handshake can prove record alignment; issue #2955).
/// 4. Extract TLS session keys via `dangerous_extract_secrets()`.
/// 5. Install keys into the kernel via `enable_ktls()`.
/// 6. Use `bidirectional_splice()` for zero-copy relay.
///
/// Returns `KtlsError::Unsupported` with the original streams if kTLS cannot
/// be used, allowing the caller to fall back to userspace `bidirectional_copy`.
///
/// **TLS 1.2 ONLY.** TLS 1.3 connections fall back to userspace relay because
/// this implementation does not handle KeyUpdate — the kernel holds a static
/// copy of the application traffic secret, and a peer-initiated KeyUpdate
/// would silently desynchronize decryption mid-stream.
///
/// **Buffered handoff disabled.** Steps 4–6 are currently unreachable for
/// connections accepted via tokio-rustls: the public buffered rustls API
/// cannot prove the inbound deframer is empty, so step 3 always returns the
/// streams for userspace relay. Secret extraction is never attempted on that
/// path.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn try_ktls_splice(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    backend_stream: TcpStream,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
    backend_read_timeout: Option<Duration>,
    backend_write_timeout: Option<Duration>,
    buf_size: usize,
) -> Result<StreamCopyResult, KtlsError> {
    use std::os::unix::io::AsRawFd;

    // Check cipher suite compatibility AND per-cipher kernel support before
    // consuming the TLS stream. Supported ciphers: AES-128-GCM, AES-256-GCM,
    // and ChaCha20-Poly1305.
    //
    // CRITICAL: Each cipher landed in kTLS in a different kernel version
    // (AES-GCM in 4.13/4.17, ChaCha20-Poly1305 in 5.11+). A blanket
    // `is_ktls_available()` answer is NOT sufficient: a kernel may accept
    // the ULP and AES-128 keys while rejecting ChaCha20 keys with
    // EINVAL/EOPNOTSUPP. If we only checked the cipher suite name and
    // assumed the kernel supports it, the install would fail AFTER we
    // have already consumed the TLS stream via `into_inner()` +
    // `dangerous_extract_secrets()`, forcing a hard connection drop with
    // no safe fallback to userspace TLS. The per-cipher gate below
    // prevents this by refusing connections whose kernel probe failed
    // BEFORE we extract secrets.
    let cipher_ok = {
        let (_, server_conn) = tls_stream.get_ref();
        match server_conn.negotiated_cipher_suite() {
            Some(suite) => {
                let name = format!("{:?}", suite.suite());
                if name.contains("AES_128_GCM") {
                    crate::socket_opts::ktls::is_ktls_aes128gcm_available()
                } else if name.contains("AES_256_GCM") {
                    crate::socket_opts::ktls::is_ktls_aes256gcm_available()
                } else if name.contains("CHACHA20_POLY1305") {
                    crate::socket_opts::ktls::is_ktls_chacha20_poly1305_available()
                } else {
                    false
                }
            }
            None => false,
        }
    };

    if !cipher_ok {
        debug!(
            "kTLS: unsupported cipher suite or kernel lacks per-cipher support, \
             falling back to userspace copy"
        );
        return Err(KtlsError::Unsupported(Box::new((
            tls_stream,
            backend_stream,
        ))));
    }

    // Check TLS version — kTLS is restricted to TLS 1.2 ONLY in this gateway.
    //
    // TLS 1.3 is intentionally NOT supported because `dangerous_extract_secrets()`
    // returns the CURRENT application traffic secret. In TLS 1.3 either peer may
    // issue a KeyUpdate message at any time (RFC 8446 §4.6.3) to rotate keys.
    // Because we install keys into the kernel ONCE and then splice the socket
    // directly (no userspace TLS state machine), a peer-initiated KeyUpdate
    // would silently desynchronize the kernel from the negotiated peer state
    // mid-stream, producing decryption failures with no opportunity to rekey
    // the kernel. For long-lived TCP streams this is a reachable correctness
    // bug, so we fall back to userspace TLS for TLS 1.3 connections.
    let tls_version = {
        let (_, server_conn) = tls_stream.get_ref();
        server_conn.protocol_version()
    };
    let tls_ver_u16 = match tls_version {
        Some(rustls::ProtocolVersion::TLSv1_2) => 0x0303_u16,
        Some(rustls::ProtocolVersion::TLSv1_3) => {
            debug!("kTLS: TLS 1.3 KeyUpdate handling not implemented, falling back to userspace");
            return Err(KtlsError::Unsupported(Box::new((
                tls_stream,
                backend_stream,
            ))));
        }
        _ => {
            debug!(
                "kTLS: unsupported TLS version {:?}, falling back",
                tls_version
            );
            return Err(KtlsError::Unsupported(Box::new((
                tls_stream,
                backend_stream,
            ))));
        }
    };

    // Fail closed BEFORE TCP_ULP or `into_inner()`. The buffered tokio-rustls
    // `ServerConnection` cannot prove inbound record alignment (issue #2955),
    // so `ktls_rustls_buffers_safe_for_kernel_handoff` always returns false and
    // we keep the `TlsStream` intact — including any plaintext rustls already
    // decrypted out of the client's handshake-tail segment. The check only
    // borrows the session immutably, so the refusal path cannot drop a single
    // application byte, and it runs before the ULP probe because TCP_ULP is
    // sticky on the fd once installed.
    {
        let (_, server_conn) = tls_stream.get_ref();
        if !ktls_rustls_buffers_safe_for_kernel_handoff(server_conn) {
            return Err(KtlsError::Unsupported(Box::new((
                tls_stream,
                backend_stream,
            ))));
        }
    }

    // Pre-flight: probe TCP_ULP installation on the raw fd BEFORE consuming
    // the TLS stream. If the kernel doesn't support kTLS (ENOPROTOOPT), we
    // can still fall back with the TLS stream intact.
    //
    // NOTE: Today the buffered-API gate above always refuses, so this block
    // is only reached if that gate is later relaxed for an unbuffered
    // `UnbufferedServerConnection` → `WriteTraffic` →
    // `dangerous_into_kernel_connection` path that can prove alignment.
    {
        let (tcp_ref, _) = tls_stream.get_ref();
        let fd = tcp_ref.as_raw_fd();
        let ulp_name = b"tls\0";
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_ULP,
                ulp_name.as_ptr() as *const libc::c_void,
                ulp_name.len() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            debug!("kTLS: TCP_ULP probe failed ({}), falling back", err);
            return Err(KtlsError::Unsupported(Box::new((
                tls_stream,
                backend_stream,
            ))));
        }
        // TCP_ULP installed successfully — kTLS is available on this socket.
        // Proceed to extract secrets (point of no return after this block).
    }

    // Point of no return: consume the TLS stream to extract secrets.
    // TCP_ULP is already installed on the underlying fd, so kTLS key
    // installation should succeed. Only reachable if the buffered-API
    // alignment gate above is later satisfied by a proven-safe handshake.
    let (tcp_stream, server_conn) = tls_stream.into_inner();

    let secrets = match server_conn.dangerous_extract_secrets() {
        Ok(s) => s,
        Err(e) => {
            warn!("kTLS: failed to extract TLS secrets: {}", e);
            return Err(KtlsError::Installed(anyhow::anyhow!(
                "kTLS secret extraction failed: {}",
                e
            )));
        }
    };

    // Map rustls secrets to kTLS parameters.
    let params = match build_ktls_params(tls_ver_u16, &secrets) {
        Some(p) => p,
        None => {
            warn!("kTLS: cipher not mappable to kTLS params");
            return Err(KtlsError::Installed(anyhow::anyhow!(
                "kTLS: unsupported cipher in extracted secrets"
            )));
        }
    };

    // Install kTLS on the raw TCP socket.
    let fd = tcp_stream.as_raw_fd();
    match crate::socket_opts::ktls::enable_ktls(fd, &params) {
        Ok(true) => {
            debug!("kTLS installed successfully, using splice for TLS connection");
            Ok(bidirectional_splice(
                tcp_stream,
                backend_stream,
                idle_timeout,
                half_close_cap,
                backend_read_timeout,
                backend_write_timeout,
                buf_size,
            )
            .await)
        }
        Ok(false) => {
            // Kernel doesn't support kTLS (ENOPROTOOPT) — but we already consumed
            // the TLS stream so we cannot recover.
            warn!("kTLS: kernel returned ENOPROTOOPT after secret extraction");
            Err(KtlsError::Installed(anyhow::anyhow!(
                "kTLS not supported by kernel after secret extraction"
            )))
        }
        Err(e) => {
            warn!("kTLS: setsockopt failed: {}", e);
            Err(KtlsError::Installed(anyhow::anyhow!(
                "kTLS setsockopt failed: {}",
                e
            )))
        }
    }
}

/// Map rustls `ExtractedSecrets` to `KtlsParams` for the kernel TLS ULP.
///
/// Returns `None` if the cipher suite is not AES-128-GCM, AES-256-GCM, or
/// ChaCha20-Poly1305.
///
/// Secret material is wrapped in `Zeroizing<Vec<u8>>` so the heap backing
/// is volatile-zeroed on drop. This applies to the intermediate allocations
/// in this function (they are `Zeroizing` from the moment they are created)
/// as well as any downstream storage inside `KtlsParams`.
#[cfg(target_os = "linux")]
fn build_ktls_params(
    tls_version: u16,
    secrets: &rustls::ExtractedSecrets,
) -> Option<crate::socket_opts::ktls::KtlsParams> {
    use crate::socket_opts::ktls::{KtlsCipher, KtlsParams};
    use rustls::ConnectionTrafficSecrets;
    use zeroize::Zeroizing;

    let (tx_seq, ref tx_secrets) = secrets.tx;
    let (rx_seq, ref rx_secrets) = secrets.rx;

    let (cipher_suite, tx_key, tx_iv, rx_key, rx_iv) = match (tx_secrets, rx_secrets) {
        (
            ConnectionTrafficSecrets::Aes128Gcm { key: tk, iv: tiv },
            ConnectionTrafficSecrets::Aes128Gcm { key: rk, iv: riv },
        ) => (
            KtlsCipher::Aes128Gcm,
            Zeroizing::new(tk.as_ref().to_vec()),
            Zeroizing::new(tiv.as_ref().to_vec()),
            Zeroizing::new(rk.as_ref().to_vec()),
            Zeroizing::new(riv.as_ref().to_vec()),
        ),
        (
            ConnectionTrafficSecrets::Aes256Gcm { key: tk, iv: tiv },
            ConnectionTrafficSecrets::Aes256Gcm { key: rk, iv: riv },
        ) => (
            KtlsCipher::Aes256Gcm,
            Zeroizing::new(tk.as_ref().to_vec()),
            Zeroizing::new(tiv.as_ref().to_vec()),
            Zeroizing::new(rk.as_ref().to_vec()),
            Zeroizing::new(riv.as_ref().to_vec()),
        ),
        (
            ConnectionTrafficSecrets::Chacha20Poly1305 { key: tk, iv: tiv },
            ConnectionTrafficSecrets::Chacha20Poly1305 { key: rk, iv: riv },
        ) => (
            KtlsCipher::Chacha20Poly1305,
            Zeroizing::new(tk.as_ref().to_vec()),
            Zeroizing::new(tiv.as_ref().to_vec()),
            Zeroizing::new(rk.as_ref().to_vec()),
            Zeroizing::new(riv.as_ref().to_vec()),
        ),
        _ => return None,
    };

    Some(KtlsParams {
        tls_version,
        cipher_suite,
        tx_key,
        tx_iv,
        tx_seq: tx_seq.to_be_bytes(),
        rx_key,
        rx_iv,
        rx_seq: rx_seq.to_be_bytes(),
    })
}

#[cfg(all(test, target_os = "linux"))]
mod ktls_param_tests {
    //! Tests for `build_ktls_params` — the rustls-ExtractedSecrets to
    //! KtlsParams mapping. These run inline because `build_ktls_params`
    //! is a private function and the rustls types it consumes are not
    //! re-exported from the gateway crate.
    //!
    //! We use `AeadKey::from([u8; 32])` (the only stable public constructor)
    //! which yields a 32-byte key regardless of the cipher's real key length.
    //! That is harmless for this unit test since we are exercising the match
    //! arm selection and byte plumbing, not the kernel install path.

    use super::build_ktls_params;
    use crate::socket_opts::ktls::KtlsCipher;
    use rustls::ConnectionTrafficSecrets;
    use rustls::ExtractedSecrets;
    use rustls::crypto::cipher::{AeadKey, Iv};

    fn aead_key(byte: u8) -> AeadKey {
        AeadKey::from([byte; 32])
    }

    fn iv(byte: u8) -> Iv {
        Iv::from([byte; 12])
    }

    #[test]
    fn aes128_gcm_both_sides_maps_to_aes128() {
        let secrets = ExtractedSecrets {
            tx: (
                0x1122_3344_5566_7788,
                ConnectionTrafficSecrets::Aes128Gcm {
                    key: aead_key(0x11),
                    iv: iv(0x22),
                },
            ),
            rx: (
                0xdead_beef_0000_0001,
                ConnectionTrafficSecrets::Aes128Gcm {
                    key: aead_key(0x33),
                    iv: iv(0x44),
                },
            ),
        };
        let params = build_ktls_params(0x0303, &secrets).expect("AES-128 pair must map");
        assert!(matches!(params.cipher_suite, KtlsCipher::Aes128Gcm));
        assert_eq!(params.tls_version, 0x0303);
        assert_eq!(params.tx_seq, 0x1122_3344_5566_7788_u64.to_be_bytes());
        assert_eq!(params.rx_seq, 0xdead_beef_0000_0001_u64.to_be_bytes());
        assert_eq!(params.tx_iv.len(), 12);
        assert_eq!(params.rx_iv.len(), 12);
    }

    #[test]
    fn aes256_gcm_both_sides_maps_to_aes256() {
        let secrets = ExtractedSecrets {
            tx: (
                1,
                ConnectionTrafficSecrets::Aes256Gcm {
                    key: aead_key(0xaa),
                    iv: iv(0xbb),
                },
            ),
            rx: (
                2,
                ConnectionTrafficSecrets::Aes256Gcm {
                    key: aead_key(0xcc),
                    iv: iv(0xdd),
                },
            ),
        };
        let params = build_ktls_params(0x0303, &secrets).expect("AES-256 pair must map");
        assert!(matches!(params.cipher_suite, KtlsCipher::Aes256Gcm));
        assert_eq!(params.tx_seq, 1u64.to_be_bytes());
        assert_eq!(params.rx_seq, 2u64.to_be_bytes());
    }

    #[test]
    fn mismatched_cipher_families_return_none() {
        let secrets = ExtractedSecrets {
            tx: (
                0,
                ConnectionTrafficSecrets::Aes128Gcm {
                    key: aead_key(0x11),
                    iv: iv(0x22),
                },
            ),
            rx: (
                0,
                ConnectionTrafficSecrets::Aes256Gcm {
                    key: aead_key(0x33),
                    iv: iv(0x44),
                },
            ),
        };
        assert!(build_ktls_params(0x0303, &secrets).is_none());
    }

    #[test]
    fn chacha20_poly1305_both_sides_maps_to_chacha20() {
        let secrets = ExtractedSecrets {
            tx: (
                7,
                ConnectionTrafficSecrets::Chacha20Poly1305 {
                    key: aead_key(0x11),
                    iv: iv(0x22),
                },
            ),
            rx: (
                8,
                ConnectionTrafficSecrets::Chacha20Poly1305 {
                    key: aead_key(0x33),
                    iv: iv(0x44),
                },
            ),
        };
        let params = build_ktls_params(0x0304, &secrets).expect("ChaCha20-Poly1305 pair must map");
        assert!(matches!(params.cipher_suite, KtlsCipher::Chacha20Poly1305));
        assert_eq!(params.tls_version, 0x0304);
        assert_eq!(params.tx_seq, 7u64.to_be_bytes());
        assert_eq!(params.rx_seq, 8u64.to_be_bytes());
        // ChaCha20-Poly1305 uses the full 12-byte IV directly.
        assert_eq!(params.tx_iv.len(), 12);
        assert_eq!(params.rx_iv.len(), 12);
    }

    #[test]
    fn chacha20_mixed_with_aes_returns_none() {
        // TX ChaCha20, RX AES-128 — not a supported mixed pairing.
        let secrets = ExtractedSecrets {
            tx: (
                0,
                ConnectionTrafficSecrets::Chacha20Poly1305 {
                    key: aead_key(0x11),
                    iv: iv(0x22),
                },
            ),
            rx: (
                0,
                ConnectionTrafficSecrets::Aes128Gcm {
                    key: aead_key(0x33),
                    iv: iv(0x44),
                },
            ),
        };
        assert!(build_ktls_params(0x0303, &secrets).is_none());
    }
}

#[cfg(test)]
mod splice_readiness_wait_tests {
    #[cfg(target_os = "linux")]
    use super::refresh_splice_write_progress;
    use super::splice_poll_timeout_ms_at;
    use std::sync::atomic::{AtomicU64, Ordering};

    const NOW_MS: u64 = 10_000;

    #[test]
    fn splice_poll_timeout_waits_indefinitely_without_active_deadlines() {
        let now = NOW_MS;
        let activity = AtomicU64::new(now);

        assert_eq!(
            splice_poll_timeout_ms_at(now, 0, &activity, None, 0, None, 0),
            -1
        );
    }

    #[test]
    fn splice_poll_timeout_uses_nearest_active_watermark_deadline() {
        let now = NOW_MS;
        let activity = AtomicU64::new(now.saturating_sub(100));
        let read = AtomicU64::new(now.saturating_sub(750));
        let write = AtomicU64::new(now.saturating_sub(200));

        let wait = splice_poll_timeout_ms_at(
            now,
            5_000,
            &activity,
            Some(&read),
            1_000,
            Some(&write),
            2_000,
        );

        assert_eq!(wait, 250);
    }

    #[test]
    fn splice_poll_timeout_ignores_unprimed_write_watermark() {
        let now = NOW_MS;
        let activity = AtomicU64::new(now);
        let write = AtomicU64::new(u64::MAX);

        let wait = splice_poll_timeout_ms_at(now, 2_000, &activity, None, 0, Some(&write), 10);

        assert_eq!(wait, 2_000);
    }

    #[test]
    fn splice_poll_timeout_returns_zero_for_expired_deadline() {
        let now = NOW_MS;
        let activity = AtomicU64::new(now.saturating_sub(2_000));

        assert_eq!(
            splice_poll_timeout_ms_at(now, 1_000, &activity, None, 0, None, 0),
            0
        );
    }

    #[test]
    fn splice_poll_timeout_observes_updated_activity() {
        let now = NOW_MS;
        let activity = AtomicU64::new(now.saturating_sub(900));

        activity.store(now, Ordering::Relaxed);

        let wait = splice_poll_timeout_ms_at(now, 1_000, &activity, None, 0, None, 0);
        assert_eq!(wait, 1_000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn splice_write_progress_refreshes_idle_clock_and_write_watermark() {
        let idle = AtomicU64::new(u64::MAX);
        let write = AtomicU64::new(u64::MAX);

        refresh_splice_write_progress(Some(&idle), Some(&write));

        let idle_value = idle.load(Ordering::Relaxed);
        let write_value = write.load(Ordering::Relaxed);
        assert_ne!(idle_value, u64::MAX);
        assert_eq!(idle_value, write_value);
    }
}

#[cfg(test)]
mod cause_direction_tests {
    //! Tests for `pre_copy_disconnect_cause` / `pre_copy_disconnect_direction`,
    //! the typed-kind-first cause/direction mappers shared between TCP and UDP
    //! disconnect logging. Inline because both functions are private to the
    //! module.
    use super::{pre_copy_disconnect_cause, pre_copy_disconnect_direction};
    use crate::plugins::{Direction, DisconnectCause};
    use crate::proxy::stream_error::{StreamSetupError, StreamSetupKind};
    use crate::retry::ErrorClass;

    fn err(kind: StreamSetupKind) -> anyhow::Error {
        StreamSetupError::new(kind, "test detail").into()
    }

    #[test]
    fn typed_frontend_tls_maps_to_recv_error_and_client_direction() {
        let e = err(StreamSetupKind::FrontendTlsHandshake);
        assert_eq!(
            pre_copy_disconnect_cause(&e, &ErrorClass::TlsError),
            DisconnectCause::RecvError
        );
        assert_eq!(
            pre_copy_disconnect_direction(&e, &ErrorClass::TlsError),
            Direction::ClientToBackend
        );
    }

    #[test]
    fn typed_backend_tls_maps_to_backend_error_and_backend_direction() {
        let e = err(StreamSetupKind::BackendTlsHandshake);
        assert_eq!(
            pre_copy_disconnect_cause(&e, &ErrorClass::TlsError),
            DisconnectCause::BackendError
        );
        assert_eq!(
            pre_copy_disconnect_direction(&e, &ErrorClass::TlsError),
            Direction::BackendToClient
        );
    }

    #[test]
    fn typed_no_healthy_targets_maps_to_backend_error_and_backend_direction() {
        let e = err(StreamSetupKind::NoHealthyTargets);
        assert_eq!(
            pre_copy_disconnect_cause(&e, &ErrorClass::RequestError),
            DisconnectCause::BackendError
        );
        assert_eq!(
            pre_copy_disconnect_direction(&e, &ErrorClass::RequestError),
            Direction::BackendToClient
        );
    }

    #[test]
    fn typed_circuit_breaker_open_maps_to_backend_error_and_backend_direction() {
        // Circuit-breaker rejects are gateway shedding traffic away from a
        // known-bad upstream — backend-side, not client-side. Without the
        // typed kind they classify as RequestError and the class-based
        // fallback routes them to RecvError / ClientToBackend (a
        // misattribution that breaks backend-error dashboards).
        let e = err(StreamSetupKind::CircuitBreakerOpen);
        assert_eq!(
            pre_copy_disconnect_cause(&e, &ErrorClass::RequestError),
            DisconnectCause::BackendError
        );
        assert_eq!(
            pre_copy_disconnect_direction(&e, &ErrorClass::RequestError),
            Direction::BackendToClient
        );
    }

    #[test]
    fn typed_plugin_reject_maps_to_recv_error_and_client_direction() {
        let e = err(StreamSetupKind::RejectedByPlugin);
        assert_eq!(
            pre_copy_disconnect_cause(&e, &ErrorClass::RequestError),
            DisconnectCause::RecvError
        );
        assert_eq!(
            pre_copy_disconnect_direction(&e, &ErrorClass::RequestError),
            Direction::ClientToBackend
        );
    }

    #[test]
    fn typed_admission_disconnect_maps_to_recv_error_and_client_direction() {
        let e = err(StreamSetupKind::ClientDisconnectedDuringAdmission);
        assert_eq!(
            pre_copy_disconnect_cause(&e, &ErrorClass::RequestError),
            DisconnectCause::RecvError
        );
        assert_eq!(
            pre_copy_disconnect_direction(&e, &ErrorClass::RequestError),
            Direction::ClientToBackend
        );
    }

    #[test]
    fn typed_kind_takes_precedence_over_misleading_error_class() {
        // Adversarial: RejectedByPlugin (client-side) classified as
        // ConnectionTimeout (which the class-fallback would call backend).
        // The typed kind must win.
        let e = err(StreamSetupKind::RejectedByPlugin);
        assert_eq!(
            pre_copy_disconnect_cause(&e, &ErrorClass::ConnectionTimeout),
            DisconnectCause::RecvError,
            "typed kind must override class-based inference"
        );
        assert_eq!(
            pre_copy_disconnect_direction(&e, &ErrorClass::ConnectionTimeout),
            Direction::ClientToBackend
        );
    }

    #[test]
    fn untyped_dns_lookup_falls_back_to_backend_via_class() {
        // No StreamSetupError in the chain — class fallback drives the
        // mapping. DNS failures attribute to the backend half.
        let e: anyhow::Error = anyhow::anyhow!("nxdomain");
        assert_eq!(
            pre_copy_disconnect_cause(&e, &ErrorClass::DnsLookupError),
            DisconnectCause::BackendError
        );
        assert_eq!(
            pre_copy_disconnect_direction(&e, &ErrorClass::DnsLookupError),
            Direction::BackendToClient
        );
    }

    #[test]
    fn typed_backend_max_connections_maps_to_backend_error_and_backend_direction() {
        // DR `connectionPool.tcp.maxConnections` enforcement is a backend-side
        // policy decision (the gateway is applying the operator's intent to
        // shed traffic away from this target). Symmetric to
        // `CircuitBreakerOpen` — both must NOT misclassify as client-side.
        let e = err(StreamSetupKind::BackendMaxConnectionsExceeded);
        assert_eq!(
            pre_copy_disconnect_cause(&e, &ErrorClass::RequestError),
            DisconnectCause::BackendError
        );
        assert_eq!(
            pre_copy_disconnect_direction(&e, &ErrorClass::RequestError),
            Direction::BackendToClient
        );
    }
}

#[cfg(test)]
mod node_waypoint_stream_scope_tests {
    //! Unit tests for [`resolve_node_waypoint_stream_scope`], the TCP stream
    //! accept-path helper that maps a connection to its source pod's
    //! per-pod authorization scope (parity with the HTTP/HBONE admit path).

    use super::{NodeWaypointIdentityWarnLimiter, resolve_node_waypoint_stream_scope};

    /// Non-node-waypoint topologies (and non-mesh TCP proxies) pass no resolver,
    /// so the accept path stamps no per-pod scope — behavior is unchanged.
    /// `stream` is never touched on this path, so a real socket is unnecessary.
    #[tokio::test]
    async fn none_resolver_yields_no_scope_and_no_principal() {
        // Bind+connect so we have a genuine `TcpStream` to pass; the helper
        // short-circuits on `None` before reading it.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let connect = tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await });
        let (accepted, _peer) = listener.accept().await.expect("accept");
        let _client = connect.await.expect("join").expect("connect");

        let warn_limiter = NodeWaypointIdentityWarnLimiter::new();
        let (scope, principal) = resolve_node_waypoint_stream_scope(
            None,
            &accepted,
            "proxy",
            "127.0.0.1",
            &warn_limiter,
        );
        assert!(scope.is_none(), "no resolver must yield no per-pod scope");
        assert!(principal.is_none(), "no resolver must yield no principal");
    }

    /// Full resolution against a real accepted socket: the helper reads the
    /// connection's `SO_COOKIE`, resolves it to the enrolled pod, and returns
    /// that pod's installed `PolicyScopeCache` plus its SPIFFE principal —
    /// exactly what the accept loop stamps onto the stream context. Linux-only
    /// because `SO_COOKIE` is a Linux socket option.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn resolver_maps_real_socket_to_installed_scope() {
        use std::collections::HashMap;
        use std::sync::Arc;

        use ferrum_ebpf_common::OrigDst4;

        use crate::identity::{SpiffeId, TrustDomain};
        use crate::modes::mesh::config::{Workload, WorkloadSelector};
        use crate::modes::mesh::node_waypoint::{
            NodeWaypointIdentity, NodeWaypointIdentityResolver, parse_pod_uid,
        };

        let resolver = Arc::new(NodeWaypointIdentityResolver::new(0));
        let pod = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let spiffe = SpiffeId::new("spiffe://cluster.local/ns/team-a/sa/api").unwrap();
        let identity = NodeWaypointIdentity::new(pod, spiffe.clone());
        let hash = identity.workload_spiffe_hash;
        resolver.upsert_identity(identity);

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let connect = tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await });
        let (accepted, _peer) = listener.accept().await.expect("accept");
        let _client = connect.await.expect("join").expect("connect");

        // Register the orig-dst record under the *accepted* socket's real
        // cookie (the accept-side registrar contract).
        let cookie = crate::socket_opts::socket_cookie(&accepted).expect("SO_COOKIE");
        resolver.record_orig_dst4(
            cookie,
            OrigDst4 {
                addr: u32::from_ne_bytes([10, 0, 0, 1]),
                port: 8080,
                pod_uid: pod,
                workload_spiffe_hash: hash,
            },
        );
        // Install the pod's scope the way production does — from the slice's
        // workload set. The workload carries this pod's `metadata.uid` so the
        // per-UID scope index (`scopes_by_pod_uid`) is keyed to match the
        // captured pod; it also seeds the `workload_spiffe_hash` gate, which
        // `resolve_record` re-validates against so a cached identity resolves
        // only while its workload is still in the slice.
        let workload = Workload {
            spiffe_id: spiffe.clone(),
            selector: WorkloadSelector {
                labels: HashMap::new(),
                namespace: Some("team-a".to_string()),
            },
            service_name: "api".to_string(),
            addresses: Vec::new(),
            ports: Vec::new(),
            trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
            namespace: "team-a".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: Some("11111111-1111-1111-1111-111111111111".to_string()),
            node_waypoint: None,
            remote_provenance: false,
        };
        resolver.install_policy_scopes_from_workloads(&[workload]);

        let (scope, principal) = resolve_node_waypoint_stream_scope(
            Some(resolver.as_ref()),
            &accepted,
            "proxy",
            "127.0.0.1",
            &NodeWaypointIdentityWarnLimiter::new(),
        );
        assert!(
            scope.is_some(),
            "resolved pod with an installed scope must yield Some(scope)"
        );
        assert_eq!(
            principal.as_deref(),
            Some("spiffe://cluster.local/ns/team-a/sa/api"),
            "resolved pod SPIFFE ID must be returned as the source principal"
        );
    }
}

#[cfg(test)]
mod first_bytes_peek_tests {
    //! Coverage for `peek_tcp_first_bytes`, which captures the opening client
    //! bytes for stream-aware plugins (e.g. the WAF `tcp_require_tls` guard)
    //! without consuming them from the socket buffer.

    use std::time::Duration;

    use tokio::io::AsyncWriteExt;

    use super::peek_tcp_first_bytes;

    /// Bind a loopback listener and return it with its address.
    async fn listener() -> (tokio::net::TcpListener, std::net::SocketAddr) {
        let l = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let addr = l.local_addr().expect("addr");
        (l, addr)
    }

    /// A first TCP segment shorter than `min_len` must be reassembled by further
    /// non-destructive peeks until the full prefix is buffered — so a TLS
    /// ClientHello split across segments is not misread as a short non-TLS chunk.
    /// This is the regression test for the single-`peek()` classification bug.
    #[tokio::test]
    async fn accumulates_fragmented_prefix_up_to_min_len() {
        let (l, addr) = listener().await;
        let writer = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(addr).await.expect("connect");
            // First segment carries fewer than `min_len` (6) bytes...
            c.write_all(&[0x16, 0x03, 0x01]).await.expect("write1");
            c.flush().await.expect("flush1");
            tokio::time::sleep(Duration::from_millis(20)).await;
            // ...the rest of the record + handshake header arrives later.
            c.write_all(&[0x00, 0x05, 0x01]).await.expect("write2");
            c.flush().await.expect("flush2");
            // Hold the connection so the peeked bytes stay buffered.
            tokio::time::sleep(Duration::from_millis(500)).await;
            drop(c);
        });
        let (accepted, _) = l.accept().await.expect("accept");

        let bytes = peek_tcp_first_bytes(&accepted, Some(Duration::from_secs(5)), 6)
            .await
            .expect("should observe the reassembled prefix, not None");
        assert!(
            bytes.len() >= 6,
            "expected the full >= 6-byte prefix, got {}",
            bytes.len()
        );
        assert_eq!(&bytes[..6], &[0x16, 0x03, 0x01, 0x00, 0x05, 0x01]);

        writer.await.expect("writer task");
    }

    /// The peek must not consume bytes: they stay in the socket buffer so the
    /// relay (and the Linux splice fast path) still forwards them intact. Two
    /// peeks in a row therefore observe the same opening bytes.
    #[tokio::test]
    async fn peek_does_not_consume_bytes() {
        let (l, addr) = listener().await;
        let writer = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(addr).await.expect("connect");
            c.write_all(b"hello-world").await.expect("write");
            c.flush().await.expect("flush");
            tokio::time::sleep(Duration::from_millis(500)).await;
            drop(c);
        });
        let (accepted, _) = l.accept().await.expect("accept");

        let first = peek_tcp_first_bytes(&accepted, Some(Duration::from_secs(5)), 1)
            .await
            .expect("first peek");
        let second = peek_tcp_first_bytes(&accepted, Some(Duration::from_secs(5)), 1)
            .await
            .expect("second peek");
        assert_eq!(&first[..], b"hello-world");
        assert_eq!(&second[..], b"hello-world", "peek must not consume bytes");

        writer.await.expect("writer task");
    }

    /// When the client stalls below `min_len`, the deadline caps the reassembly
    /// wait: the function returns the short prefix it managed to observe (so the
    /// WAF can fail closed on it) instead of hanging forever.
    #[tokio::test]
    async fn returns_short_prefix_when_deadline_expires() {
        let (l, addr) = listener().await;
        let writer = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(addr).await.expect("connect");
            // Two bytes that never complete the 6-byte prefix.
            c.write_all(&[0x16, 0x03]).await.expect("write");
            c.flush().await.expect("flush");
            tokio::time::sleep(Duration::from_millis(800)).await;
            drop(c);
        });
        let (accepted, _) = l.accept().await.expect("accept");

        let bytes = peek_tcp_first_bytes(&accepted, Some(Duration::from_millis(200)), 6)
            .await
            .expect("should return the short prefix, not None");
        assert_eq!(
            &bytes[..],
            &[0x16, 0x03],
            "returns exactly what arrived before the deadline"
        );

        writer.await.expect("writer task");
    }
}
