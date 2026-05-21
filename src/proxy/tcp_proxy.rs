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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::circuit_breaker::CircuitBreakerCache;
use crate::tls::TlsPolicy;
use crate::tls::backend::BackendTlsConfigBuilder;

use crate::config::types::{BackendScheme, GatewayConfig, Proxy};
use crate::consumer_index::ConsumerIndex;
use crate::dns::DnsCache;
use crate::load_balancer::{LoadBalancerCache, LoadBalancerCacheInner};
use crate::plugins::{
    Direction, Plugin, PluginResult, ProxyProtocol, StreamConnectionContext,
    StreamTransactionSummary,
};
use crate::proxy::stream_error::{StreamSetupError, StreamSetupKind, find_stream_setup_error};
use crate::request_epoch::{RequestEpoch, RequestEpochStore};
use crate::retry::ErrorClass;

pub(crate) fn classify_stream_error(error: &anyhow::Error) -> crate::retry::ErrorClass {
    crate::retry::classify_boxed_error(error.as_ref())
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
pub(crate) const STREAM_ERR_NO_HEALTHY_TARGETS: &str = "No healthy targets";
pub(crate) const STREAM_ERR_CIRCUIT_BREAKER_OPEN: &str = "circuit breaker open";
pub(crate) const STREAM_ERR_BACKEND_MAX_CONNECTIONS: &str = "Backend maxConnections reached";

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
    bidirectional_splice(client, backend, idle_timeout, half_close_cap, pipe_size).await
}

/// Cached backend TLS configuration to avoid reading certificate files from
/// disk on every connection. Built once per listener lifecycle and reused.
struct CachedBackendTlsConfig {
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
    /// Per-backend-target inflight TCP connection counters used to enforce
    /// DestinationRule `connectionPool.tcp.maxConnections`. Lazily created on
    /// first hit per `(host, port)` target. The counters are
    /// [`crossbeam_utils::CachePadded`] so the read-mostly inflight count
    /// doesn't share a cache line with the hotter listener-level
    /// `active_backend_connections` field — at high stream-proxy QPS, false
    /// sharing turned every cmpxchg into a coherence stall.
    ///
    /// Key components cannot contain `|` because hostnames are admission-
    /// validated and ports are `u16` — see `crate::config::types`
    /// normalisation rules.
    pub backend_inflight: BackendInflightCounters,
}

/// Lazy per-target inflight counter map. Wrapped in its own struct so we can
/// implement `Default` (DashMap doesn't derive it for us with custom shard
/// sizing) and so future callers (HTTP-family follow-on) can extend the API
/// without touching every `TcpProxyMetrics` initialiser.
#[derive(Clone)]
pub struct BackendInflightCounters {
    inner: Arc<dashmap::DashMap<BackendInflightKey, Arc<crossbeam_utils::CachePadded<AtomicU64>>>>,
}

/// `(host, port)` key for per-backend-target inflight counters. Owned host
/// `String` so the key survives across DNS-cache-refreshed connect attempts
/// and the host doesn't have to be reborrowed from the proxy struct on every
/// connect.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct BackendInflightKey {
    host: String,
    port: u16,
}

impl Default for BackendInflightCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendInflightCounters {
    pub fn new() -> Self {
        // Conservative cardinality: a single TCP proxy maps to one upstream
        // group, typically 1–10 backend targets. We still go through
        // `pool_shard_amount` for consistency with the rest of the hot-path
        // map sizing — a 0 override means "auto" (`max(64, num_cpus * 16)`).
        let shards = crate::util::sharding::pool_shard_amount(0);
        Self {
            inner: Arc::new(dashmap::DashMap::with_shard_amount(shards)),
        }
    }

    /// Look up or insert the counter for the given target, returning a cheap
    /// `Arc` handle so the guard can hold the same counter even if the
    /// DashMap entry is concurrently evicted later (cleanup is currently a
    /// non-feature — counters stick around for the listener's lifetime — so
    /// this is forward-compatible).
    fn counter_for(&self, host: &str, port: u16) -> Arc<crossbeam_utils::CachePadded<AtomicU64>> {
        // Two-phase: cheap read first, fall back to entry-API only when the
        // key is missing. Hot path is always cache-hit because steady-state
        // traffic reuses the same target set.
        if let Some(existing) = self.inner.get(&BackendInflightKey {
            host: host.to_string(),
            port,
        }) {
            return existing.clone();
        }
        let key = BackendInflightKey {
            host: host.to_string(),
            port,
        };
        self.inner
            .entry(key)
            .or_insert_with(|| Arc::new(crossbeam_utils::CachePadded::new(AtomicU64::new(0))))
            .clone()
    }

    /// Read the current inflight count for a target. Test- and metrics-only
    /// access — the production hot path uses `counter_for` directly.
    #[allow(dead_code)]
    pub fn inflight(&self, host: &str, port: u16) -> u64 {
        self.inner
            .get(&BackendInflightKey {
                host: host.to_string(),
                port,
            })
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// RAII guard that increments a per-target inflight counter on construction
/// and decrements on drop. Held alongside the per-listener
/// `TcpBackendSessionGuard` so both the global and per-target totals stay in
/// sync across all relay exits (graceful close, idle timeout, error).
#[derive(Debug)]
struct BackendInflightGuard {
    counter: Arc<crossbeam_utils::CachePadded<AtomicU64>>,
}

impl BackendInflightGuard {
    /// Acquire a slot, returning `Ok(guard)` if under the cap or `Err` when
    /// the cap is already reached. The `cap` is `Option<u32>` so callers
    /// pass `None` for "no cap configured" (the hot path then skips the
    /// counter entirely and avoids the inflight DashMap lookup).
    fn try_acquire(
        counters: &BackendInflightCounters,
        host: &str,
        port: u16,
        cap: u32,
    ) -> Result<Self, BackendInflightAcquireError> {
        let counter = counters.counter_for(host, port);
        let cap_u64 = u64::from(cap);
        loop {
            let current = counter.load(Ordering::Relaxed);
            if current >= cap_u64 {
                return Err(BackendInflightAcquireError {
                    current,
                    cap: cap_u64,
                });
            }
            // Use compare-exchange-weak in a CAS loop so two concurrent
            // accepting threads can never both squeak past `cap - 1`. A
            // `fetch_add + check + rollback` race-free shape is harder to
            // read and gives the same throughput on uncontended paths.
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Self { counter }),
                Err(_) => continue,
            }
        }
    }
}

impl Drop for BackendInflightGuard {
    fn drop(&mut self) {
        // `saturating_sub` would mask a counter underflow bug — use the
        // straight `fetch_sub` and rely on the test suite to catch any
        // missing-guard regression.
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone, Copy)]
struct BackendInflightAcquireError {
    current: u64,
    cap: u64,
}

impl std::fmt::Display for BackendInflightAcquireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend max_connections reached: {} inflight (cap {})",
            self.current, self.cap
        )
    }
}

impl std::error::Error for BackendInflightAcquireError {}

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
}

#[derive(Clone)]
struct TcpAcceptLoopState {
    port: u16,
    proxy_id: Arc<str>,
    dns_cache: DnsCache,
    request_epoch: Arc<RequestEpochStore>,
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
            .filter(|p| p.dispatch_kind == crate::config::types::DispatchKind::TcpTls)
            .map(|proxy| {
                CachedBackendTlsConfig::build(
                    proxy,
                    tls_no_verify,
                    tls_ca_bundle_path.as_deref(),
                    tls_policy.as_deref(),
                    &crls,
                )
                    .map(Arc::new)
                    .unwrap_or_else(|e| {
                        warn!(proxy_id = %proxy_id, "Failed to pre-build backend TLS config: {}, will retry per-connection", e);
                        // Return a dummy config that will be rebuilt per-connection
                        let dummy_builder = crate::tls::backend_client_config_builder(tls_policy.as_deref())
                            .unwrap_or_else(|_| rustls::ClientConfig::builder());
                        Arc::new(CachedBackendTlsConfig {
                            config: Arc::new(
                                dummy_builder
                                    .with_root_certificates(rustls::RootCertStore::empty())
                                    .with_no_client_auth()
                            ),
                        })
                    })
            })
    };

    let loop_state = TcpAcceptLoopState {
        port,
        proxy_id: proxy_id.clone(),
        dns_cache,
        request_epoch,
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
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, remote_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!(
                            proxy_id = %state.proxy_id,
                            accept_loop = accept_loop_id,
                            "TCP accept error: {}",
                            e
                        );
                        continue;
                    }
                };

                // Reject new connections under critical overload (same as HTTP proxy).
                if state.overload.reject_new_connections.load(Ordering::Relaxed) {
                    drop(stream); // TCP RST
                    continue;
                }

                state.metrics.total_connections.fetch_add(1, Ordering::Relaxed);
                state.metrics.active_connections.fetch_add(1, Ordering::Relaxed);

                let port = state.port;
                let proxy_id = state.proxy_id.clone();
                let dns_cache = state.dns_cache.clone();
                let request_epoch = state.request_epoch.clone();
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

                tokio::spawn(async move {
                    // Track this connection for global overload accounting and graceful drain.
                    // The guard decrements the counter on drop (all exit paths).
                    let _conn_guard = crate::overload::ConnectionGuard::new(&overload_for_conn);

                    let connected_at = Instant::now();
                    let connected_wall_at = chrono::Utc::now();
                    let client_ip = remote_addr.ip().to_string();
                    let epoch = request_epoch.load();
                    let base_proxy = epoch
                        .config
                        .proxies
                        .iter()
                        .find(|p| p.id.as_str() == proxy_id.as_ref());
                    let consumer_index =
                        Arc::new(ConsumerIndex::from_inner(Arc::clone(&epoch.consumer_index)));

                    // Build stream context — plugins run inside handle_tcp_connection
                    // (after TLS handshake for TLS proxies, so client cert is available).
                    let mut stream_ctx = StreamConnectionContext {
                        client_ip: client_ip.clone(),
                        proxy_id: proxy_id.to_string(),
                        proxy_name: base_proxy.and_then(|p| p.name.clone()),
                        listen_port: port,
                        backend_scheme: base_proxy
                            .map(|p| p.effective_scheme())
                            .unwrap_or(BackendScheme::Tcp),
                        consumer_index,
                        identified_consumer: None,
                        authenticated_identity: None,
                        auth_method: None,
                        metadata: None,
                        tls_client_cert_der: None,
                        tls_client_cert_chain_der: None,
                        sni_hostname: None,
                        mesh_direction: None,
                    };

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

                    let duration_ms = connected_at.elapsed().as_millis() as f64;
                    let final_proxy_id = stream_ctx.proxy_id.clone();
                    // Keep disconnect hooks/logging on the same epoch that
                    // admitted the connection. Long-lived TCP streams can span
                    // config reloads; using the connection epoch preserves a
                    // consistent view of SNI-selected proxy metadata and
                    // stream plugins for the full connection lifetime.
                    let final_proxy = epoch
                        .config
                        .proxies
                        .iter()
                        .find(|p| p.id == final_proxy_id);
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

                    metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
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
    /// When true, forward encrypted client bytes directly without TLS termination.
    passthrough: bool,
    /// Whether TCP Fast Open is enabled (gated on `FERRUM_TCP_FASTOPEN_ENABLED`).
    tcp_fastopen_enabled: bool,
    /// Flattened per-port dispatch overrides used by retry attempts.
    dispatch_port_overrides:
        Option<std::collections::HashMap<u16, crate::config::types::ResolvedPortOverride>>,
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
    mesh_outbound_enforcement: Option<
        &Arc<crate::modes::mesh::outbound_enforcement::MeshOutboundEnforcement>,
    >,
) -> TcpConnectionResult {
    let start = Instant::now();
    let _ = client_stream.set_nodelay(true);

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
    proxy_id: &str,
    client_ip: IpAddr,
    connection_label: &'static str,
    rejection_detail: &'static str,
) -> Result<(), anyhow::Error> {
    for plugin in plugins {
        if let PluginResult::Reject { .. } = plugin.on_stream_connect(stream_ctx).await {
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

/// Inner implementation of TCP connection handling that can use `?` for early returns
/// while the caller always receives backend info for logging.
#[allow(clippy::too_many_arguments, unused_variables)]
async fn handle_tcp_connection_inner(
    client_stream: TcpStream,
    remote_addr: SocketAddr,
    proxy_id: &str,
    epoch: &RequestEpoch,
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
    mesh_outbound_enforcement: Option<
        &Arc<crate::modes::mesh::outbound_enforcement::MeshOutboundEnforcement>,
    >,
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

        let matched = super::sni::resolve_proxy_by_sni(sni.as_deref(), sni_ids, &epoch.config)
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
        stream_ctx.proxy_name = epoch
            .config
            .proxies
            .iter()
            .find(|p| p.id == matched)
            .and_then(|p| p.name.clone());
        _resolved_proxy_id.as_deref().unwrap_or(proxy_id)
    } else {
        _resolved_proxy_id = None;
        proxy_id
    };

    // Look up the proxy config and extract only the fields we need.
    let (params, cb_info) = {
        let proxy = epoch
            .config
            .proxies
            .iter()
            .find(|p| p.id == proxy_id)
            .ok_or_else(|| anyhow::anyhow!("Proxy {} not found in config", proxy_id))?;

        stream_ctx.proxy_id = proxy.id.clone();
        stream_ctx.proxy_name = proxy.name.clone();
        stream_ctx.backend_scheme = proxy.effective_scheme();

        let (backend_host, backend_port) = resolve_backend_target(proxy, &epoch.load_balancer)?;

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
            .and_then(|m| m.get(&backend_port));
        let effective_backend_connect_timeout_ms = port_override
            .and_then(|override_config| override_config.connect_timeout_ms)
            .unwrap_or(proxy.backend_connect_timeout_ms);
        let params = TcpConnParams {
            backend_host,
            backend_port,
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
            passthrough: proxy.passthrough,
            tcp_fastopen_enabled: tcp_fastopen,
            dispatch_port_overrides: proxy.dispatch_port_overrides.clone(),
        };

        (params, cb_info)
    };

    // Mesh `outboundTrafficPolicy: REGISTRY_ONLY` enforcement (T5-B).
    // When the runtime carries an enforcement snapshot AND this listener is
    // a mesh outbound capture port AND the destination is not in the
    // admitted registry, drop the inbound TCP connection with a graceful
    // close before dialing the backend. This matches Istio's REGISTRY_ONLY
    // semantics for stream-family egress: an unadmitted destination must
    // never reach a backend connect, so backend circuit breakers, pool
    // entries, and DNS caches stay untouched by hostile traffic.
    //
    // The enforcement check sits BEFORE the connect (and even before the
    // SNI plugin loop for passthrough below); on `Decision::Skip` the
    // listener is not an outbound capture port (inbound / HBONE / admin
    // / east-west / egress-gateway) and we flow through unchanged. On
    // `Decision::Admit` we record the metric and continue. On
    // `Decision::Deny` we record the metric, log once per
    // (cgroup-substitute, destination) — keyed by `(stream_ctx.client_ip,
    // backend_target)` so repeated unauthorised attempts surface without
    // log spam — and return a typed `StreamSetupError` that the listener
    // wrapper turns into a closed inbound connection.
    if let Some(enforcement) = mesh_outbound_enforcement {
        use crate::modes::mesh::outbound_enforcement::{Decision, PROTOCOL_TCP, PROTOCOL_TCP_TLS};
        let decision = enforcement.check_destination(
            stream_ctx.listen_port,
            &params.backend_host,
            params.backend_port,
        );
        let protocol_label = if matches!(params.backend_scheme, BackendScheme::Tcps) {
            PROTOCOL_TCP_TLS
        } else {
            PROTOCOL_TCP
        };
        match decision {
            Decision::Admit => {
                enforcement.record_stream_decision(protocol_label, Decision::Admit);
            }
            Decision::Deny => {
                enforcement.record_stream_decision(protocol_label, Decision::Deny);
                warn!(
                    proxy_id = %proxy_id,
                    client = %remote_addr.ip(),
                    listen_port = stream_ctx.listen_port,
                    backend_target = %backend_info.backend_target,
                    protocol = protocol_label,
                    "Mesh REGISTRY_ONLY: rejecting TCP egress to unadmitted destination"
                );
                return Err(StreamSetupError::new(
                    StreamSetupKind::RejectedByPlugin,
                    "(mesh REGISTRY_ONLY)",
                )
                .into());
            }
            Decision::Skip => {}
        }
    }

    let plugins = epoch
        .plugin_cache
        .get_plugins_for_protocol(proxy_id, ProxyProtocol::Tcp);

    // ----- Passthrough mode: forward encrypted bytes without TLS termination -----
    if params.passthrough {
        // Peek at the ClientHello to extract SNI for logging/routing.
        // Skip if already extracted during SNI-based proxy resolution above.
        if stream_ctx.sni_hostname.is_none() {
            stream_ctx.sni_hostname =
                super::sni::extract_sni_from_tcp_stream(&client_stream, sni_peek_timeout).await;
        }

        // Run on_stream_connect plugins (they see SNI but not decrypted data).
        if !plugins.is_empty() {
            for plugin in plugins.iter() {
                if let PluginResult::Reject { .. } = plugin.on_stream_connect(stream_ctx).await {
                    debug!(
                        proxy_id = %proxy_id,
                        client = %remote_addr.ip(),
                        sni = ?stream_ctx.sni_hostname,
                        "TCP passthrough connection rejected by plugin"
                    );
                    return Err(StreamSetupError::new(
                        StreamSetupKind::RejectedByPlugin,
                        "(passthrough)",
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

        // Resolve backend IP via DNS
        let resolved_ip = dns_cache
            .resolve(
                &params.backend_host,
                params.dns_override.as_deref(),
                params.dns_cache_ttl_seconds,
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!("DNS resolution failed for {}: {}", params.backend_host, e)
            })?;
        let addr = SocketAddr::new(resolved_ip, params.backend_port);
        backend_info.backend_resolved_ip = Some(resolved_ip.to_string());

        // DestinationRule `connectionPool.tcp.maxConnections` enforcement on
        // the passthrough path. The cap is checked before connect so we don't
        // count failed handshakes against the cap. The guard's RAII drop
        // covers every relay exit (graceful EOF, idle timeout, error).
        let passthrough_port_override = resolve_port_override(&params, params.backend_port);
        let _backend_inflight_guard = match acquire_backend_inflight_slot(
            passthrough_port_override,
            metrics,
            &params.backend_host,
            params.backend_port,
        ) {
            Ok(guard) => guard,
            Err(reason) => {
                warn!(
                    proxy_id = %proxy_id,
                    backend = %format_backend_target(&params.backend_host, params.backend_port),
                    reason = %reason,
                    "TCP passthrough rejected: backend maxConnections reached"
                );
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

        let buf_size = adaptive_buffer.get_buffer_size(proxy_id);

        // On Linux, use splice(2) for zero-copy relay between raw TCP sockets.
        // Passthrough mode is always plain-to-plain (no TLS termination/origination).
        // When io_uring is enabled, use IORING_OP_SPLICE on dedicated blocking threads.
        #[cfg(target_os = "linux")]
        let copy_result = if io_uring_splice_enabled {
            bidirectional_splice_io_uring(
                client_stream,
                backend_stream,
                idle_timeout,
                half_close_cap,
                buf_size,
            )
            .await
        } else {
            bidirectional_splice(
                client_stream,
                backend_stream,
                idle_timeout,
                half_close_cap,
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
            splice_used: cfg!(target_os = "linux"),
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
    let client_stream = if let Some(tls_config) = frontend_tls_config {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.clone());
        // Frontend TLS failures return before any backend dispatch — no backend
        // circuit-breaker, pool, or socket interaction.
        // The typed `StreamSetupError` carries the kind so
        // `pre_copy_disconnect_cause` reads `Frontend` directly from
        // `StreamSetupKind::FrontendTlsHandshake`, no string match. The accept
        // helper bounds the handshake under the configured timeout so a stalled
        // peer cannot wedge a frontend slot indefinitely.
        let tls_stream = crate::tls::accept_with_optional_timeout(
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

        // Run on_stream_connect plugins after TLS handshake so client cert is available.
        if !plugins.is_empty() {
            run_tcp_stream_connect_plugins(
                plugins.as_ref(),
                stream_ctx,
                proxy_id,
                remote_addr.ip(),
                "TCP/TLS",
                "(TCP/TLS)",
            )
            .await?;
        }

        ClientRelayStream::Tls(Box::new(tls_stream))
    } else {
        if !plugins.is_empty() {
            run_tcp_stream_connect_plugins(
                plugins.as_ref(),
                stream_ctx,
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
                        if let Some(next) = try_next_target(
                            &params,
                            &current_host,
                            current_port,
                            &epoch.load_balancer,
                        ) {
                            warn!(
                                proxy_id = %proxy_id,
                                attempt,
                                "TCP circuit breaker open for {}:{}, trying {}:{}",
                                current_host, current_port, next.0, next.1
                            );
                            current_host = next.0;
                            current_port = next.1;
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
                record_cb_failure(circuit_breaker_cache, proxy_id, &current_cb_info);
                let err_msg = format!("DNS resolution failed for {}: {}", current_host, e);
                if can_retry
                    && attempt < max_retries
                    && let Some(next) =
                        try_next_target(&params, &current_host, current_port, &epoch.load_balancer)
                {
                    warn!(
                        proxy_id = %proxy_id,
                        attempt,
                        "TCP DNS failed for {}:{}, retrying with {}:{}",
                        current_host, current_port, next.0, next.1
                    );
                    current_host = next.0;
                    current_port = next.1;
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
        // The slot is rebuilt on each retry against `current_host` /
        // `current_port` so that a load-balancer rotation to a sibling
        // target counts against the new target's counter, not the failed
        // one. `_backend_inflight_guard_attempt` is shadowed at every loop
        // entry — only the latest successful guard survives past the `break`.
        let current_port_override = resolve_port_override(&params, current_port);
        let backend_inflight_guard_attempt = match acquire_backend_inflight_slot(
            current_port_override,
            metrics,
            &current_host,
            current_port,
        ) {
            Ok(guard) => guard,
            Err(reason) => {
                warn!(
                    proxy_id = %proxy_id,
                    backend = %format_backend_target(&current_host, current_port),
                    reason = %reason,
                    "TCP backend rejected: maxConnections reached"
                );
                if can_retry
                    && attempt < max_retries
                    && let Some(next) =
                        try_next_target(&params, &current_host, current_port, &epoch.load_balancer)
                {
                    current_host = next.0;
                    current_port = next.1;
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
                    && let Some(next) =
                        try_next_target(&params, &current_host, current_port, &epoch.load_balancer)
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
    let (_backend_socket_addr, backend_stream, _backend_inflight_guard) = backend_addr;
    let _ = last_connect_err; // consumed by retry loop logging
    let _backend_session_guard = TcpBackendSessionGuard::new(metrics);

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
                    #[cfg(target_os = "linux")]
                    {
                        if ktls_enabled {
                            match try_ktls_splice(
                                tls_stream,
                                bs,
                                idle_timeout,
                                half_close_cap,
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
                    // are raw TCP (no frontend TLS, no backend TLS).
                    // When io_uring is enabled, use IORING_OP_SPLICE on blocking threads.
                    #[cfg(target_os = "linux")]
                    {
                        used_splice = true;
                        if io_uring_splice_enabled {
                            bidirectional_splice_io_uring(
                                client_stream,
                                bs,
                                idle_timeout,
                                half_close_cap,
                                buf_size,
                            )
                            .await
                        } else {
                            bidirectional_splice(
                                client_stream,
                                bs,
                                idle_timeout,
                                half_close_cap,
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
        bytes_in: copy_result.bytes_client_to_backend,
        bytes_out: copy_result.bytes_backend_to_client,
        duration: start.elapsed(),
        splice_used: used_splice,
        first_failure: copy_result.first_failure,
    })
}

/// Resolve the backend target — either direct from proxy config or via load balancer.
fn resolve_backend_target(
    proxy: &Proxy,
    lb_snapshot: &LoadBalancerCacheInner,
) -> Result<(String, u16), anyhow::Error> {
    if let Some(upstream_id) = &proxy.upstream_id {
        let selection = if let Some(subset_name) = proxy.upstream_subset.as_deref() {
            LoadBalancerCache::select_target_subset_from(
                lb_snapshot,
                upstream_id,
                &proxy.id,
                subset_name,
                None,
            )
        } else {
            LoadBalancerCache::select_target_from(lb_snapshot, upstream_id, &proxy.id, None)
        }
        .ok_or_else(|| -> anyhow::Error {
            let scope = proxy
                .upstream_subset
                .as_deref()
                .map(|subset| format!("for upstream {upstream_id} subset {subset}"))
                .unwrap_or_else(|| format!("for upstream {upstream_id}"));
            StreamSetupError::new(StreamSetupKind::NoHealthyTargets, scope).into()
        })?;
        Ok((selection.target.host.clone(), selection.target.port))
    } else {
        Ok((proxy.backend_host.clone(), proxy.backend_port))
    }
}

#[cfg(test)]
mod backend_target_selection_tests {
    use super::*;
    use serde_json::json;

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

    #[test]
    fn resolve_backend_target_honors_upstream_subset() {
        let config = config_with_subset();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let proxy = proxy_with_subset(Some("canary"));

        let (host, port) = resolve_backend_target(&proxy, &snapshot).expect("target selected");

        assert_eq!(host, "canary.local");
        assert_eq!(port, 1002);
    }

    #[test]
    fn resolve_backend_target_errors_for_unknown_subset() {
        let config = config_with_subset();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let proxy = proxy_with_subset(Some("missing"));

        let err = resolve_backend_target(&proxy, &snapshot).expect_err("missing subset rejected");

        assert!(err.to_string().contains("subset missing"));
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
    current_host: &str,
    current_port: u16,
    lb_snapshot: &LoadBalancerCacheInner,
) -> Option<(String, u16)> {
    let upstream_id = params.upstream_id.as_ref()?;
    let exclude = crate::config::types::UpstreamTarget {
        host: current_host.to_string(),
        port: current_port,
        weight: 1,
        path: None,
        tags: std::collections::HashMap::new(),
        locality: None,
    };
    let next = if let Some(subset_name) = params.upstream_subset.as_deref() {
        LoadBalancerCache::select_next_target_subset_from(
            lb_snapshot,
            upstream_id,
            current_host,
            subset_name,
            &exclude,
            None,
        )
    } else {
        LoadBalancerCache::select_next_target_from(
            lb_snapshot,
            upstream_id,
            current_host,
            &exclude,
            None,
        )
    }?;
    Some((next.host.clone(), next.port))
}

/// Try to acquire a per-target inflight slot for DR
/// `connectionPool.tcp.maxConnections`. Returns:
///   * `Ok(None)` when no cap is configured (hot path: zero overhead).
///   * `Ok(Some(guard))` when a slot was acquired. The guard's `Drop` impl
///     decrements the counter.
///   * `Err(BackendInflightAcquireError)` when the cap is already reached.
fn resolve_port_override(
    params: &TcpConnParams,
    port: u16,
) -> Option<&crate::config::types::ResolvedPortOverride> {
    params
        .dispatch_port_overrides
        .as_ref()
        .and_then(|m| m.get(&port))
}

fn acquire_backend_inflight_slot(
    port_override: Option<&crate::config::types::ResolvedPortOverride>,
    metrics: &TcpProxyMetrics,
    host: &str,
    port: u16,
) -> Result<Option<BackendInflightGuard>, BackendInflightAcquireError> {
    let Some(cap) = port_override.and_then(|override_config| override_config.max_connections)
    else {
        return Ok(None);
    };
    let guard = BackendInflightGuard::try_acquire(&metrics.backend_inflight, host, port, cap)?;
    Ok(Some(guard))
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
        let _ = crate::socket_opts::set_ip_bind_address_no_port(fd, true);
        if tcp_fastopen {
            let _ = crate::socket_opts::set_tcp_fastopen_client(fd);
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

    let _ = stream.set_nodelay(true);
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
async fn bidirectional_splice(
    client: TcpStream,
    backend: TcpStream,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
    pipe_size: usize,
) -> StreamCopyResult {
    use std::os::unix::io::AsRawFd;

    let client_fd = client.as_raw_fd();
    let backend_fd = backend.as_raw_fd();

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

    let last_activity = if idle_timeout.is_some_and(|t| !t.is_zero()) {
        Some(Arc::new(AtomicU64::new(coarse_now_ms())))
    } else {
        None
    };

    let c2b_bytes = Arc::new(AtomicU64::new(0));
    let b2c_bytes = Arc::new(AtomicU64::new(0));

    let la_c2b = last_activity.clone();
    let la_b2c = last_activity.clone();
    let c2b_bytes_task = c2b_bytes.clone();
    let b2c_bytes_task = b2c_bytes.clone();

    // Pin both direction futures for use with select! — no spawned tasks.
    let c2b_fut = splice_one_direction_no_guard(
        client_fd,
        c2b_pipe_w,
        c2b_pipe_r,
        backend_fd,
        la_c2b,
        c2b_bytes_task,
    );
    let b2c_fut = splice_one_direction_no_guard(
        backend_fd,
        b2c_pipe_w,
        b2c_pipe_r,
        client_fd,
        la_b2c,
        b2c_bytes_task,
    );
    tokio::pin!(c2b_fut);
    tokio::pin!(b2c_fut);

    let idle_timeout_active = idle_timeout.is_some_and(|t| !t.is_zero());
    let timeout_ms = idle_timeout.map(|t| t.as_millis() as u64).unwrap_or(0);

    let mut first_failure: Option<(Direction, ErrorClass, Option<StreamIoSide>, String)> = None;
    let mut c2b_done = false;
    let mut b2c_done = false;

    // Phase 1: race the two directions (plus optional idle check).
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
            // Idle timeout check — wake every second.
            _ = tokio::time::sleep(Duration::from_secs(1)), if idle_timeout_active => {
                if let Some(ref la) = last_activity {
                    let last = la.load(Ordering::Relaxed);
                    if coarse_now_ms().saturating_sub(last) >= timeout_ms {
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
#[cfg(target_os = "linux")]
async fn drain_half_close_splice<F>(
    drain_fut: &mut F,
    last_activity: &Option<Arc<AtomicU64>>,
    idle_timeout_active: bool,
    timeout_ms: u64,
    half_close_cap: Option<Duration>,
    direction: Direction,
) -> Option<(Direction, ErrorClass, Option<StreamIoSide>, String)>
where
    F: std::future::Future<Output = Result<(), (StreamIoSide, anyhow::Error)>> + Unpin,
{
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
            _ = tokio::time::sleep(Duration::from_secs(1)), if idle_timeout_active => {
                if let Some(la) = last_activity.as_ref() {
                    let last = la.load(Ordering::Relaxed);
                    if coarse_now_ms().saturating_sub(last) >= timeout_ms {
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
            _ = sleep_for_cap(half_close_cap), if half_close_cap.is_some() && !idle_timeout_active => {
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
async fn bidirectional_splice_io_uring(
    client: TcpStream,
    backend: TcpStream,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
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
    use std::sync::OnceLock;

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

    // Shared last-activity timestamp across both directions. Activity in either
    // direction refreshes the timestamp, preventing one-way streams (e.g., downloads)
    // from timing out on the idle send direction.
    let shared_activity = Arc::new(AtomicU64::new(coarse_now_ms()));
    let sa_c2b = shared_activity.clone();
    let sa_b2c = shared_activity;

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
    // Idle expirations from the splice loop are reported as anyhow errors whose
    // text starts with `STREAM_SPLICE_IDLE_TIMEOUT_PREFIX` ("TCP idle timeout")
    // — classify them directly as `ReadWriteTimeout` + `Direction::Unknown` +
    // `side: None` so `disconnect_cause_for_failure` maps them to `IdleTimeout`.
    // Running them through `classify_stream_error` would return
    // `ConnectionTimeout` (or even `RequestError`), which the mapper treats as
    // a recv/backend error. The emission sites in `io_uring_splice_direction`
    // and `libc_splice_loop` reference the same constant so a rename is a
    // compile-time coupling, not a silent drift.
    let c2b_handle = tokio::task::spawn_blocking(move || {
        let res = io_uring_splice_direction(
            client_fd, c2b_pipe_w, c2b_pipe_r, backend_fd, timeout_ms, &sa_c2b,
        );
        if let Err((side, ref e)) = res {
            let msg = e.to_string();
            let entry = if msg.starts_with(STREAM_SPLICE_IDLE_TIMEOUT_PREFIX) {
                (Direction::Unknown, ErrorClass::ReadWriteTimeout, None, msg)
            } else {
                (
                    Direction::ClientToBackend,
                    classify_stream_error(e),
                    Some(side),
                    msg,
                )
            };
            let _ = ff_c2b.set(entry);
        }
        res
    });
    let b2c_handle = tokio::task::spawn_blocking(move || {
        let res = io_uring_splice_direction(
            backend_fd, b2c_pipe_w, b2c_pipe_r, client_fd, timeout_ms, &sa_b2c,
        );
        if let Err((side, ref e)) = res {
            let msg = e.to_string();
            let entry = if msg.starts_with(STREAM_SPLICE_IDLE_TIMEOUT_PREFIX) {
                (Direction::Unknown, ErrorClass::ReadWriteTimeout, None, msg)
            } else {
                (
                    Direction::BackendToClient,
                    classify_stream_error(e),
                    Some(side),
                    msg,
                )
            };
            let _ = ff_b2c.set(entry);
        }
        res
    });

    // Wait for the first direction to complete, then bound the second with
    // `half_close_cap`. On cap timeout, force-shutdown both sockets so the
    // splice syscall in the remaining blocking worker returns and the
    // thread unwinds. Pipe guards (`_c2b_guard`, `_b2c_guard`) close pipe
    // fds on drop regardless.
    let mut c2b_handle = c2b_handle;
    let mut b2c_handle = b2c_handle;
    let ff_cap = first_failure.clone();
    let force_shutdown = move || unsafe {
        libc::shutdown(client_fd, libc::SHUT_RDWR);
        libc::shutdown(backend_fd, libc::SHUT_RDWR);
    };
    let (c2b_result, b2c_result) = tokio::select! {
        c2b_res = &mut c2b_handle => {
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
#[cfg(target_os = "linux")]
fn io_uring_splice_direction(
    src_fd: i32,
    pipe_w: i32,
    pipe_r: i32,
    dst_fd: i32,
    timeout_ms: u64,
    shared_activity: &AtomicU64,
) -> Result<u64, (StreamIoSide, anyhow::Error)> {
    let result = match crate::socket_opts::io_uring_splice::io_uring_splice_loop(
        src_fd,
        pipe_w,
        pipe_r,
        dst_fd,
        shared_activity,
        timeout_ms,
    ) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.source.kind() == std::io::ErrorKind::Unsupported => {
            // io_uring ring creation failed — fall back to libc::splice.
            // This can happen under memlock pressure even though startup
            // probing succeeded.
            tracing::debug!("io_uring ring creation failed, falling back to libc splice");
            libc_splice_loop(src_fd, pipe_w, pipe_r, dst_fd, timeout_ms, shared_activity)
        }
        Err(e) => {
            let side = if e.is_write_side {
                StreamIoSide::Write
            } else {
                StreamIoSide::Read
            };
            if e.source.kind() == std::io::ErrorKind::TimedOut {
                Err((
                    side,
                    anyhow::anyhow!("{} (io_uring splice)", STREAM_SPLICE_IDLE_TIMEOUT_PREFIX),
                ))
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
#[cfg(target_os = "linux")]
fn libc_splice_loop(
    src_fd: i32,
    pipe_w: i32,
    pipe_r: i32,
    dst_fd: i32,
    timeout_ms: u64,
    shared_activity: &AtomicU64,
) -> Result<u64, (StreamIoSide, anyhow::Error)> {
    let splice_flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;
    let mut total: u64 = 0;

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
                    if timeout_ms > 0 {
                        shared_activity.store(coarse_now_ms(), Ordering::Relaxed);
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
                        std::thread::sleep(std::time::Duration::from_millis(1));
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
                std::thread::sleep(std::time::Duration::from_millis(1));
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
#[cfg(target_os = "linux")]
async fn splice_one_direction_no_guard(
    src_fd: i32,
    pipe_w: i32,
    pipe_r: i32,
    dst_fd: i32,
    last_activity: Option<Arc<AtomicU64>>,
    bytes: Arc<AtomicU64>,
) -> Result<(), (StreamIoSide, anyhow::Error)> {
    let splice_flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;

    loop {
        // Phase 1: splice from source fd into write end of pipe
        let n = unsafe {
            libc::splice(
                src_fd,
                std::ptr::null_mut(),
                pipe_w,
                std::ptr::null_mut(),
                // Use 128 KB per splice call — large enough to amortize syscall
                // overhead, small enough to avoid holding the pipe buffer too long.
                128 * 1024,
                splice_flags,
            )
        };

        if n > 0 {
            if let Some(ref la) = last_activity {
                la.store(coarse_now_ms(), Ordering::Relaxed);
            }

            // Phase 2: splice from read end of pipe into destination fd
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
                    bytes.fetch_add(written as u64, Ordering::Relaxed);
                } else if written == 0 {
                    // See the synchronous libc fallback above: a clean
                    // terminal write-side condition should still propagate
                    // the relay half-close before this direction exits Ok.
                    shutdown_write_fd(dst_fd);
                    return Ok(());
                } else {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        // Destination not ready — back off briefly before retrying
                        // so idle sockets cannot busy-spin the worker thread.
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        continue;
                    }
                    return Err((
                        StreamIoSide::Write,
                        anyhow::anyhow!("splice write error: {}", err),
                    ));
                }
            }
        } else if n == 0 {
            // EOF — source closed
            shutdown_write_fd(dst_fd);
            return Ok(());
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                // Source not ready — back off briefly before retrying
                // so idle sockets cannot busy-spin the worker thread.
                tokio::time::sleep(Duration::from_millis(1)).await;
                continue;
            }
            return Err((
                StreamIoSide::Read,
                anyhow::anyhow!("splice read error: {}", err),
            ));
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

/// Attempt kTLS-accelerated splice for a frontend-TLS + plain-backend connection.
///
/// 1. Check that the negotiated cipher is AES-128-GCM or AES-256-GCM.
/// 2. Check that the negotiated TLS version is TLS 1.2 (see below).
/// 3. Extract TLS session keys via `dangerous_extract_secrets()`.
/// 4. Install keys into the kernel via `enable_ktls()`.
/// 5. Use `bidirectional_splice()` for zero-copy relay.
///
/// Returns `KtlsError::Unsupported` with the original streams if kTLS cannot
/// be used, allowing the caller to fall back to userspace `bidirectional_copy`.
///
/// **TLS 1.2 ONLY.** TLS 1.3 connections fall back to userspace relay because
/// this implementation does not handle KeyUpdate — the kernel holds a static
/// copy of the application traffic secret, and a peer-initiated KeyUpdate
/// would silently desynchronize decryption mid-stream.
#[cfg(target_os = "linux")]
async fn try_ktls_splice(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    backend_stream: TcpStream,
    idle_timeout: Option<Duration>,
    half_close_cap: Option<Duration>,
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

    // Pre-flight: probe TCP_ULP installation on the raw fd BEFORE consuming
    // the TLS stream. If the kernel doesn't support kTLS (ENOPROTOOPT), we
    // can still fall back with the TLS stream intact.
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
    // installation should succeed.
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
mod backend_inflight_tests {
    //! Unit tests for the per-backend-target inflight counter used by
    //! DestinationRule `connectionPool.tcp.maxConnections` enforcement.

    use super::{BackendInflightCounters, BackendInflightGuard};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn guard_increments_and_decrements_counter() {
        let counters = BackendInflightCounters::new();
        assert_eq!(counters.inflight("backend", 8080), 0);
        {
            let _guard =
                BackendInflightGuard::try_acquire(&counters, "backend", 8080, 5).expect("acquire");
            assert_eq!(counters.inflight("backend", 8080), 1);
        }
        assert_eq!(counters.inflight("backend", 8080), 0, "drop must decrement");
    }

    #[test]
    fn guards_for_different_targets_do_not_share_a_counter() {
        let counters = BackendInflightCounters::new();
        let _g1 =
            BackendInflightGuard::try_acquire(&counters, "backend-a", 80, 2).expect("acquire a");
        let _g2 =
            BackendInflightGuard::try_acquire(&counters, "backend-b", 80, 2).expect("acquire b");
        assert_eq!(counters.inflight("backend-a", 80), 1);
        assert_eq!(counters.inflight("backend-b", 80), 1);
    }

    #[test]
    fn cap_is_enforced_and_release_lets_next_acquire_succeed() {
        let counters = BackendInflightCounters::new();
        let g1 = BackendInflightGuard::try_acquire(&counters, "h", 7777, 1).expect("first slot");
        let err = BackendInflightGuard::try_acquire(&counters, "h", 7777, 1).expect_err("cap hit");
        // The displayed error includes the current count and cap so logs
        // surface the right context. Don't byte-match the wording — just
        // sanity-check the cap value is in there.
        let msg = err.to_string();
        assert!(msg.contains("cap 1"), "unexpected error wording: {msg}");
        drop(g1);
        // Re-acquire works once the slot is released.
        let _g2 = BackendInflightGuard::try_acquire(&counters, "h", 7777, 1)
            .expect("re-acquire after release");
        assert_eq!(counters.inflight("h", 7777), 1);
    }

    #[test]
    fn concurrent_acquire_release_never_goes_negative_or_exceeds_cap() {
        let counters = Arc::new(BackendInflightCounters::new());
        let cap: u32 = 32;
        let threads = 8usize;
        let ops_per_thread = 5_000usize;

        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let counters = Arc::clone(&counters);
            handles.push(thread::spawn(move || {
                let mut acquired_at_least_once = false;
                for _ in 0..ops_per_thread {
                    if let Ok(guard) = BackendInflightGuard::try_acquire(&counters, "h", 9090, cap)
                    {
                        acquired_at_least_once = true;
                        // Hold the slot briefly so the inflight count
                        // exercises the cap boundary across threads.
                        std::hint::spin_loop();
                        drop(guard);
                    }
                }
                acquired_at_least_once
            }));
        }
        let mut at_least_one_success = false;
        for h in handles {
            at_least_one_success |= h.join().expect("thread join");
        }
        assert!(
            at_least_one_success,
            "at least one thread should have acquired the slot during the stress run"
        );
        let final_inflight = counters.inflight("h", 9090);
        assert_eq!(
            final_inflight, 0,
            "after every guard is dropped the counter must be exactly zero \
             (was {final_inflight}); negative values would have wrapped to u64::MAX"
        );
    }

    #[test]
    fn cap_zero_rejects_everything() {
        // `max_connections == 0` is rejected at translate time, but the
        // guard helper must still behave sanely if a caller ever passes
        // `0` through (defence-in-depth).
        let counters = BackendInflightCounters::new();
        let err =
            BackendInflightGuard::try_acquire(&counters, "h", 1, 0).expect_err("cap 0 rejects");
        assert!(err.to_string().contains("cap 0"));
        assert_eq!(counters.inflight("h", 1), 0);
    }
}
