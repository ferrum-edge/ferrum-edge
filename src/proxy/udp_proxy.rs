//! Raw UDP datagram proxy with session tracking and optional DTLS encryption.
//!
//! Each UDP proxy binds its own dedicated port. Client datagrams are forwarded
//! to the backend via per-client sessions. Backend replies are forwarded back
//! to the original client address. Sessions are cleaned up after an idle timeout.
//!
//! **Backend DTLS**: When `backend_scheme` is `Dtls`, backend connections are
//! wrapped with DTLS 1.2/1.3 encryption using the `dimpl` crate. The proxy TLS
//! settings (`backend_tls_verify_server_cert`, etc.) control the DTLS handshake.
//!
//! **Frontend DTLS**: When `frontend_dtls_config` is provided, the listener
//! accepts DTLS-encrypted connections from clients instead of plain UDP. Each
//! client gets a dedicated DTLS session with transparent encrypt/decrypt.
//! Decrypted datagrams are forwarded to the backend (plain UDP or DTLS).
//!
//! **Datagram client-address metadata**: when the proxy sets
//! `stream_proxy_protocol: true`, every datagram must arrive wrapped in the
//! authenticated PROXY v2 DGRAM envelope described in
//! [`crate::proxy::datagram_client_address`]. The socket peer stays
//! `direct_client_ip`; the envelope's forwarded address becomes `client_ip`.
//! Anything that does not decode is dropped (issue #3289) — including an
//! envelope minted for another listener (issue #3856) and a duplicate or stale
//! authenticated sequence (issue #3862), both refused at the same single
//! receive boundary, before any session, hook, or backend effect.

use bytes::Bytes;
use dashmap::DashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::circuit_breaker::CircuitBreakerCache;
use crate::config::db_backend::NamespacedResourceId;
use crate::config::types::{BackendScheme, Proxy};
use crate::consumer_index::ConsumerIndex;
use crate::dns::DnsCache;
use crate::health_check::HealthChecker;
use crate::load_balancer::{LoadBalancerCache, LoadBalancerCacheInner};
use crate::plugins::{
    CorrelationIdState, Direction, Plugin, PluginResult, ProxyProtocol, StreamBytesKind,
    StreamConnectionContext, StreamTransactionSummary, UdpDatagramContext, UdpDatagramDirection,
    UdpDatagramVerdict, UdpMetadataSink,
};
use crate::proxy::datagram_client_address::{
    DatagramClientAddressGate, DatagramClientIdentity, DatagramMetadataError,
};
use crate::proxy::stream_error::{StreamSetupError, StreamSetupKind, find_stream_setup_error};
use crate::request_epoch::{RequestEpoch, RequestEpochStore};

/// Maximum datagram size for UDP forwarding.
const MAX_UDP_DATAGRAM_SIZE: usize = 65535;

/// Canonical identity used at every UDP/DTLS session-admission boundary.
pub fn udp_session_client_ip(client_addr: SocketAddr) -> Arc<str> {
    crate::util::client_identity::canonical_ip_arc(client_addr.ip())
}

/// Canonical client endpoint for diagnostics. Transport paths retain the raw
/// socket address for reply routing and DTLS demux, but log fields must not
/// split one IPv4 client across native and mapped-IPv6 representations.
#[inline]
fn udp_client_log_addr(client_addr: SocketAddr) -> SocketAddr {
    crate::util::client_identity::canonical_socket_addr(client_addr)
}

/// Count and (rate-limited) report a datagram refused by the client-address
/// metadata gate.
///
/// The record names the field that failed and the socket peer; it never carries
/// payload bytes, tag material, or the forwarded address a hostile sender was
/// trying to assert.
fn record_client_address_metadata_drop(
    metrics: &UdpProxyMetrics,
    proxy_id: &str,
    listen_port: u16,
    socket_peer: SocketAddr,
    error: &DatagramMetadataError,
) {
    metrics
        .client_address_metadata_drops
        .fetch_add(1, Ordering::Relaxed);
    if let Some(suppressed) = metrics
        .client_address_metadata_warn
        .on_event(coarse_epoch_millis())
    {
        warn!(
            proxy_id = %proxy_id,
            listen_port = listen_port,
            peer = %udp_client_log_addr(socket_peer),
            reason = error.reason(),
            suppressed = suppressed,
            "Dropping datagram: client-address metadata refused ({error})"
        );
    }
}

/// Admit one backend→client datagram against the session's remaining
/// per-request amplification budget. Unlimited proxies (`factor == None`) skip
/// the check. Empty responses still consume one unit of remaining budget
/// (plain UDP, DTLS, and batched paths share this helper). Drops are
/// rate-limited and never log client addresses, sizes, factors, or payload.
fn admit_udp_response(
    remaining: &AtomicU64,
    factor: Option<f32>,
    len: u64,
    proxy_id: &str,
    listen_port: u16,
) -> bool {
    if factor.is_none() {
        return true;
    }
    if crate::udp_amplification::charge_response_budget(remaining, len) {
        crate::udp_amplification::record_response_allowed();
        true
    } else {
        let n = crate::udp_amplification::record_response_dropped();
        if n == 1 || n.is_multiple_of(100) {
            warn!(
                proxy_id = %proxy_id,
                listen_port,
                drops = n,
                "UDP response dropped: exceeds amplification budget"
            );
        }
        false
    }
}

fn publish_session_request_budget(session: &UdpSession, request_size: u64) {
    session
        .last_request_size
        .store(request_size, Ordering::Release);
    if let Some(factor) = session.amplification_factor {
        crate::udp_amplification::publish_request_budget(
            &session.response_budget_remaining,
            request_size,
            factor,
        );
    }
}

/// Metrics for a single UDP proxy listener.
#[derive(Default)]
pub struct UdpProxyMetrics {
    pub active_sessions: AtomicU64,
    /// DTLS demux peers tracked by the frontend DTLS server. Includes peers
    /// that have not completed the handshake yet.
    pub dtls_demux_sessions: Arc<AtomicU64>,
    pub total_sessions: AtomicU64,
    pub datagrams_in: AtomicU64,
    pub datagrams_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    /// Client→backend datagrams dropped because a session's bounded
    /// `on_udp_datagram` ingress queue was full or closed. Fail-closed:
    /// overload never bypasses required hooks.
    pub hook_ingress_drops: AtomicU64,
    /// Payload bytes retained across all established-session hook queues and
    /// in-flight hook awaits for this listener. Used as a listener-wide
    /// admission budget.
    hook_ingress_queued_bytes: AtomicUsize,
    /// Datagrams dropped by the client-address metadata gate: untrusted peer,
    /// missing/failed authentication, malformed envelope, a binding that names
    /// another listener, a duplicate/stale/malformed freshness record, replay
    /// state exhaustion, or a forwarded client that disagreed with the
    /// established session. Every one of these is a fail-closed refusal, never a
    /// fallback
    /// to the socket peer. This is internal listener-local accounting shared
    /// with the frontend DTLS demuxer so both datagram paths report one
    /// counter; it is not an exported Prometheus or admin metric.
    pub client_address_metadata_drops: Arc<AtomicU64>,
    /// Bounds the per-listener rate of the metadata-drop warning so a hostile
    /// flood cannot turn one dropped datagram into one log record.
    client_address_metadata_warn: crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter,
}

/// A UDP session tracking a single client's connection to a backend.
struct UdpSession {
    /// Plain UDP backend socket. `None` when using DTLS (traffic goes through `dtls_conn`).
    backend_socket: Option<Arc<UdpSocket>>,
    /// DTLS connection wrapping the backend socket (set when `backend_scheme == Dtls`).
    dtls_conn: Option<Arc<crate::dtls::DtlsConnection>>,
    /// Last packet activity on a process-monotonic clock (coarse millis).
    /// Never derived from wall/UTC time — NTP corrections must not freeze or
    /// prematurely fire idle expiry.
    last_activity: AtomicU64,
    /// Session creation on the same monotonic clock used by `last_activity`.
    /// `duration_ms` in disconnect summaries is `disconnected − created` on
    /// this clock; wall timestamps are stored separately for rendering.
    created_at: AtomicU64,
    /// Civil/UTC connect time for human-readable `timestamp_connected` only.
    connected_wall_at: chrono::DateTime<chrono::Utc>,
    /// Set to `true` by the idle-cleanup task immediately before the
    /// session is removed from the session map. The recv-loop
    /// `last_client` fast path checks this flag and falls through to
    /// session creation when it sees an expired session, so
    /// a cached `Arc<UdpSession>` that survived the map removal can't
    /// keep routing traffic through an orphaned backend leg. Without
    /// this gate the fast path serves stale sessions for as long as
    /// the cache holds them, which silently bypasses the configured
    /// `udp_idle_timeout_seconds`.
    expired: std::sync::atomic::AtomicBool,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    /// Size of the latest accepted client→backend datagram for amplification
    /// factor checking. Published before the backend send so a loopback reply
    /// cannot race ahead of the response budget.
    /// Updated on each policy-accepted request; read on each backend→client response.
    last_request_size: AtomicU64,
    /// Remaining backend→client payload bytes for the current admitted request.
    /// Charged by every response datagram until the next client request resets
    /// it. Lives on the session (not the backend) so weighted multi-backend
    /// selection cannot reset or multiply the budget.
    response_budget_remaining: AtomicU64,
    /// Copied from the proxy at session admission. `None` skips the guard.
    amplification_factor: Option<f32>,
    /// Backend target for logging (e.g., "10.0.2.10:5353").
    backend_target: String,
    /// DNS-resolved IP address of the backend for logging.
    backend_resolved_ip: String,
    /// SNI hostname extracted from the first DTLS ClientHello during passthrough mode.
    sni_hostname: Option<String>,
    /// Local destination IP captured from IP(v6)_PKTINFO cmsg on the first
    /// inbound datagram that exposes one. Used as the reply source address on
    /// send so the kernel can skip the routing-table lookup and return traffic
    /// exits the same interface the client targeted. Written once via
    /// `OnceLock::set`; reads are lock-free atomic loads. Empty when pktinfo
    /// is disabled, unsupported, or the first datagram did not carry a cmsg
    /// (e.g., it came through tokio's cmsg-less `recv_from`).
    local_addr: std::sync::OnceLock<crate::socket_opts::PktinfoLocal>,
    /// Identified consumer username (gateway Consumer or external identity) resolved
    /// during `on_stream_connect`. Carried to `on_stream_disconnect` for logging.
    consumer_username: Option<String>,
    /// Authentication mechanism that succeeded, carried to `on_stream_disconnect`.
    auth_method: Option<&'static str>,
    /// Plugin metadata from on_stream_connect, carried to on_stream_disconnect.
    metadata: std::sync::Mutex<std::collections::HashMap<String, String>>,
    /// Per-instance execution-trigger decisions taken during
    /// `on_stream_connect`, carried so `on_stream_disconnect` agrees. Opaque and
    /// immutable for the session's lifetime — unlike `metadata`, no plugin can
    /// write it.
    plugin_trigger_decisions: crate::plugins::StreamTriggerDecisions,
    /// Immutable authoritative correlation ownership captured after admission.
    /// Per-datagram hooks mutate only `metadata`; disconnect-summary construction
    /// re-projects this state after cloning that final writable map.
    correlation_ids: CorrelationIdState,
    /// Plugins and proxy metadata resolved from the RequestEpoch used to create this session.
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
    datagram_plugins: Arc<[Arc<dyn Plugin>]>,
    datagram_client_ip: Arc<str>,
    /// Authenticated forwarded client this session was admitted with, when the
    /// listener runs the datagram client-address gate. Later datagrams from the
    /// same socket peer must carry the same value; a different one is dropped
    /// rather than silently attributed to this session's identity.
    forwarded_client: Option<SocketAddr>,
    datagram_proxy_id: Arc<str>,
    datagram_proxy_name: Option<Arc<str>>,
    /// Nature of the per-datagram payloads this (plain-UDP-frontend) session
    /// hands to `on_udp_datagram`: `PlaintextWire` for plain UDP, or
    /// `EncryptedWire` for passthrough proxies that forward ciphertext. The
    /// DTLS-terminating frontend path reports `DecryptedApp` inline instead.
    datagram_payload_kind: StreamBytesKind,
    proxy_id: String,
    proxy_name: Option<String>,
    /// Ownership generation captured at UDP/DTLS session admission.
    proxy_lifecycle_generation: Option<u64>,
    proxy_namespace: String,
    backend_scheme: BackendScheme,
    listen_port: u16,
    idle_timeout_ms: u64,
    /// Set by idle cleanup before [`Self::stop_notify`] so the reply task can
    /// observe stop either via this flag (register-then-check) or via the
    /// permit stored by [`signal_udp_reply_task_stop`]. Also observed by the
    /// hook-ingress worker (flag only — that worker must not wait on
    /// [`Self::stop_notify`]).
    stop_reply_task: std::sync::atomic::AtomicBool,
    /// Per-session **reply-task** stop wake. Signaled with `Notify::notify_one`
    /// (permit storing) so a store+notify cannot be lost if the reply task has
    /// not yet registered a waiter between loop-top checks. Dedicated to the
    /// backend reply task: a second waiter (for example the hook-ingress
    /// worker) would steal the single `notify_one` permit and leave `recv`
    /// blocked after cleanup.
    stop_notify: Arc<tokio::sync::Notify>,
    /// RAII guard that increments [`crate::overload::OverloadState::active_connections`]
    /// on construction and decrements on drop. Each UDP session counts as one
    /// connection toward the global pressure-shedding threshold so pure-UDP
    /// gateways and mixed deployments contribute correctly to overload state
    /// (parity with TCP/H3, which carry their own `ConnectionGuard` in the
    /// per-connection task). Removal paths take the guard before the final
    /// `Arc<UdpSession>` drops so listener-local caches cannot pin the global
    /// overload counter past session expiry.
    overload_guard: std::sync::Mutex<Option<crate::overload::ConnectionGuard>>,
    /// Bounded client→backend ingress channel for sessions that run
    /// `on_udp_datagram` hooks. The shared listener recv loop enqueues here
    /// (never awaits hooks) so a slow Redis/I/O-bound plugin for one client
    /// cannot stall every other session on the listener. `None` when the
    /// session has no datagram hooks (inline forward path). Taken on session
    /// expiry/stop so the per-session worker observes channel close promptly.
    hook_ingress_tx: std::sync::Mutex<Option<mpsc::Sender<Bytes>>>,
    /// Bytes currently queued in [`Self::hook_ingress_tx`], shared with the
    /// ingress worker so the recv loop can enforce a per-session byte cap
    /// without walking the channel.
    hook_ingress_queued_bytes: Arc<AtomicUsize>,
    /// Dedicated cancellation wake for an in-flight datagram hook. Unlike
    /// `stop_notify`, this is not shared with the backend reply task.
    hook_ingress_stop_notify: Arc<tokio::sync::Notify>,
    /// Absolute authorization lifetime of the credential that admitted this
    /// plain-UDP session, plus the once-only settlement latch shared with the
    /// post-admission setup stages (issue #3816).
    ///
    /// `None` for an unauthenticated session — no principal was admitted, so
    /// there is no authorization lifetime to bound, and every datagram path
    /// below short-circuits without reading a clock.
    authorization: Option<UdpSessionAuthorization>,
}

/// The admitted plain-UDP session's absolute authorization plan and its
/// once-only settlement latch.
///
/// The plan is anchored at session admission and NEVER refreshed by relayed
/// datagrams: continuous traffic cannot extend an admitted credential's
/// authorized lifetime. The latch is shared (an `Arc` internally) with the
/// post-admission setup stages, so exactly one termination is counted and
/// exactly one bounded class is stamped no matter which phase — setup, the
/// client→backend direction, or the backend reply task — observed the expiry
/// first.
#[derive(Debug, Clone)]
struct UdpSessionAuthorization {
    plan: crate::proxy::auth_lifetime::StreamAuthDeadline,
    latch: crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
}

impl UdpSession {
    /// The bounded termination class when this session's authorization
    /// lifetime has elapsed, WITHOUT settling anything.
    ///
    /// One monotonic instant comparison for an authenticated session and a
    /// single `Option` discriminant test for an unauthenticated one, so the
    /// unauthenticated plain-UDP datagram path never consults a clock and is
    /// byte-for-byte what it was.
    #[inline]
    fn authorization_expired_now(
        &self,
    ) -> Option<crate::proxy::auth_lifetime::StreamAuthTermination> {
        let authorization = self.authorization.as_ref();
        udp_reply_expired_at_commit(authorization.map(|authorization| authorization.plan))
    }

    /// Settle this session's authorization expiry exactly once.
    ///
    /// Returns `true` for the FIRST caller only — the one that recorded the
    /// fixed-cardinality `stream_udp` counter and stamped the bounded class
    /// into the session metadata that `build_udp_stream_summary` reads. Every
    /// later caller pays only the latch's compare-exchange, so a datagram
    /// burst arriving between expiry and teardown never takes the metadata
    /// mutex.
    fn settle_authorization_expiry(
        &self,
        termination: crate::proxy::auth_lifetime::StreamAuthTermination,
    ) -> bool {
        let Some(authorization) = self.authorization.as_ref() else {
            return false;
        };
        settle_stream_udp_auth_expiry(termination, &authorization.latch, &self.metadata)
    }

    /// The bounded class this session was terminated with, if the
    /// authorization contract ended it. Read at reply-task exit so the
    /// disconnect summary reports the security decision whichever direction
    /// observed it.
    fn observed_authorization_termination(
        &self,
    ) -> Option<crate::proxy::auth_lifetime::StreamAuthTermination> {
        self.authorization.as_ref()?.latch.observed()
    }

    /// Hot-path authorization gate for one client→backend datagram.
    ///
    /// Returns the bounded termination class when this datagram must be
    /// refused. The FIRST observer also wakes the backend reply task, which
    /// owns the single teardown (map removal, socket/task/channel close,
    /// overload + active-session release, disconnect summary) — so an elapsed
    /// deadline drops the datagram immediately instead of waiting for a timer
    /// task to be scheduled.
    fn refuse_if_authorization_expired(
        &self,
    ) -> Option<crate::proxy::auth_lifetime::StreamAuthTermination> {
        let termination = self.authorization_expired_now()?;
        if self.settle_authorization_expiry(termination) {
            // Permit-storing wake: the reply task may be parked in `recv` with
            // no backend datagram coming, and teardown must not wait for one.
            signal_udp_reply_task_stop(&self.stop_reply_task, self.stop_notify.as_ref());
        }
        Some(termination)
    }

    fn release_overload_guard(&self) {
        let mut guard = self
            .overload_guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.take();
    }

    /// Drop the hook-ingress sender so an idle per-session worker wakes from
    /// `recv` and exits without waiting for further client datagrams. This is
    /// the worker's cancellation / idle-wake path (paired with reply-task stop
    /// and session expiry). It must not share [`Self::stop_notify`].
    fn close_hook_ingress(&self) {
        let mut guard = self
            .hook_ingress_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.take();
        // `notify_one` stores a permit if the worker is between its stop-flag
        // check and registering the hook-cancellation waiter.
        self.hook_ingress_stop_notify.notify_one();
    }
}

/// Signal a UDP backend reply task to exit without waiting for backend traffic.
///
/// Stores the stop flag, then wakes with `Notify::notify_one` so a permit is
/// retained when the reply task has not yet registered a waiter. Paired with
/// [`udp_reply_recv_until_stop`]'s register-then-check ordering, store+notify
/// cannot be missed in the gap that previously lost `notify_waiters` wakes.
pub(crate) fn signal_udp_reply_task_stop(
    stop_flag: &std::sync::atomic::AtomicBool,
    stop_notify: &tokio::sync::Notify,
) {
    stop_flag.store(true, std::sync::atomic::Ordering::Release);
    stop_notify.notify_one();
}

/// Wait until listener or global shutdown flips true.
///
/// Composed into [`udp_reply_recv_until_stop`]'s cancel arm so the production
/// reply loop and the deterministic stop tests share one register-then-check
/// implementation. Stack-allocated via `async fn` (no per-datagram heap).
async fn udp_reply_shutdown_cancel(
    listener_shutdown: &mut tokio::sync::watch::Receiver<bool>,
    global_shutdown: &mut Option<tokio::sync::watch::Receiver<bool>>,
) {
    tokio::select! {
        _ = listener_shutdown.changed() => {},
        _ = async {
            match global_shutdown.as_mut() {
                Some(rx) => {
                    let _ = rx.changed().await;
                }
                None => std::future::pending::<()>().await,
            }
        } => {},
    }
}

/// Race `recv` against the per-session reply-task stop signal and an optional
/// additional cancellation future (listener/global shutdown in production;
/// `pending()` in unit tests).
///
/// Registers as a `Notify` waiter (via `Notified::enable`) **before** loading
/// `stop_flag`, then selects the already-enabled future against `recv` and
/// `cancel`. Returns `None` when stop or cancel wins (or stop was already
/// set); `Some` when `recv` completes first. This is the sole copy of the
/// register-then-check ordering used by `create_session`'s reply loop.
pub(crate) async fn udp_reply_recv_until_stop<F, C, T>(
    stop_flag: &std::sync::atomic::AtomicBool,
    stop_notify: &tokio::sync::Notify,
    recv: F,
    cancel: C,
) -> Option<T>
where
    F: std::future::Future<Output = T>,
    C: std::future::Future<Output = ()>,
{
    let notified = stop_notify.notified();
    tokio::pin!(notified);
    // Register before the flag load so a concurrent store+notify cannot land
    // between the check and select registration (notify_waiters lost-wakeup).
    notified.as_mut().enable();

    if stop_flag.load(std::sync::atomic::Ordering::Acquire) {
        return None;
    }

    tokio::select! {
        result = recv => Some(result),
        _ = notified => None,
        _ = cancel => None,
    }
}

/// Resolve a live `last_client` cache hit, clearing the entry when the cached
/// session has been marked expired.
///
/// The idle-cleanup path removes sessions from the map but the recv loop may
/// still hold an `Arc` in `last_client`. Clearing on the fast-path expired
/// check prevents a quiet listener from pinning the backend socket/session
/// until some later datagram overwrites the cache.
#[allow(dead_code)] // also reached via `_test_support`
pub(crate) fn take_udp_last_client_if_live<T>(
    last_client: &mut Option<(SocketAddr, Arc<T>)>,
    client_addr: SocketAddr,
    is_expired: impl FnOnce(&T) -> bool,
) -> Option<Arc<T>> {
    match last_client {
        Some((cached_addr, cached)) if *cached_addr == client_addr => {
            if is_expired(cached.as_ref()) {
                *last_client = None;
                None
            } else {
                Some(Arc::clone(cached))
            }
        }
        _ => None,
    }
}

/// UDP session map using ahash (AES-NI accelerated) for faster per-datagram lookups.
/// SocketAddr keys are kernel-provided (not attacker-controlled), so cryptographic
/// hashing is unnecessary — speed wins here.
type SessionMap = Arc<DashMap<SocketAddr, Arc<UdpSession>, ahash::RandomState>>;
type BackendDtlsConfigCache = Arc<BackendDtlsConfigCacheState>;

/// Listener-local cache of built backend DTLS params keyed by the owning
/// `(namespace, proxy_id)` and the inputs that affect the resulting config.
/// The key is path/options-based, so it cannot
/// observe in-place cert/key/CA rotation — backend TLS live reload bumps the
/// shared `reload_epoch` (via
/// `StreamListenerManager::bump_backend_tls_reload_epoch`, called from
/// `reload_backend_tls_material`), the epoch is part of every key (stale
/// entries become unreachable immediately), and a detected bump clears the
/// map so retired entries don't accumulate.
struct BackendDtlsConfigCacheState {
    entries: DashMap<BackendDtlsConfigCacheKey, Arc<crate::dtls::BackendDtlsParams>>,
    /// Epoch the cached entries were last validated against; lags
    /// `reload_epoch` until the next session creation observes the bump.
    built_under_epoch: AtomicU64,
    /// Shared backend TLS reload epoch owned by the stream listener manager.
    reload_epoch: Arc<AtomicU64>,
}

impl BackendDtlsConfigCacheState {
    fn new(reload_epoch: Arc<AtomicU64>) -> Self {
        Self {
            entries: DashMap::new(),
            built_under_epoch: AtomicU64::new(reload_epoch.load(Ordering::Acquire)),
            reload_epoch,
        }
    }
}

type PendingSessionMap = Arc<DashMap<SocketAddr, PendingDatagramQueue, ahash::RandomState>>;

/// Maximum number of follow-up datagrams queued per pending (setup-in-progress)
/// session. Sized for real opening flights — a QUIC Initial + 0-RTT coalesced
/// flight or a multi-record DTLS ClientHello is well under this — while keeping
/// the per-source memory bound tight.
const PENDING_SESSION_MAX_QUEUED_DATAGRAMS: usize = 16;

/// Maximum total bytes queued per pending session. Together with
/// `FERRUM_UDP_MAX_SESSIONS` (also used to cap pending gates) this bounds
/// worst-case pending-queue memory to
/// `max_sessions * PENDING_SESSION_MAX_QUEUED_BYTES`, so a spoofed-source
/// flood cannot grow memory past the same flood bound that limits sessions.
const PENDING_SESSION_MAX_QUEUED_BYTES: usize = 16 * 1024;

/// Per-session `on_udp_datagram` ingress channel depth (established sessions).
/// The shared listener recv loop enqueues here and returns immediately; a
/// dedicated per-session worker drains in arrival order, runs hooks, then
/// forwards. Sized for a brief Redis/I/O stall without spawning one task per
/// datagram. Paired with [`SESSION_HOOK_INGRESS_MAX_QUEUED_BYTES`].
const SESSION_HOOK_INGRESS_MAX_DATAGRAMS: usize = 256;

/// Maximum total bytes queued per established session awaiting
/// `on_udp_datagram` + backend forward. The listener-wide cap below prevents
/// this per-session allowance from scaling retained memory with session count.
/// Over-cap datagrams are dropped (fail closed — never forwarded without hooks).
const SESSION_HOOK_INGRESS_MAX_QUEUED_BYTES: usize = 256 * 1024;

/// Maximum payload retained by established-session hook queues across one
/// listener. This keeps the aggregate bound independent of the session cap.
const LISTENER_HOOK_INGRESS_MAX_QUEUED_BYTES: usize = 16 * 1024 * 1024;

/// Emit a rate-limited warning for hook-ingress drops (first drop, then every
/// 100th). Omits client addresses so labels/log fields stay bounded.
fn record_hook_ingress_drop(metrics: &UdpProxyMetrics, proxy_id: &str, listen_port: u16) {
    let n = metrics.hook_ingress_drops.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_multiple_of(100) {
        warn!(
            proxy_id = %proxy_id,
            listen_port,
            drops = n,
            "UDP datagram hook ingress queue full or closed; dropping datagram (fail closed)"
        );
    }
}

/// Enqueue one client→backend datagram onto a session's hook-ingress channel.
///
/// Returns `true` when admitted. Returns `false` (and increments
/// [`UdpProxyMetrics::hook_ingress_drops`]) when the datagram or byte cap
/// would be exceeded, or when the worker has stopped — never blocks the
/// shared recv loop and never bypasses required hooks.
fn enqueue_session_hook_datagram(
    session: &UdpSession,
    data: &[u8],
    metrics: &UdpProxyMetrics,
) -> bool {
    // Authorization-lifetime gate for the hook-ingress direction (issue
    // #3816). An expired session must not queue a payload, run a datagram
    // hook, or retain bytes against the ingress budget. This is a policy
    // refusal, not a queue-overload drop, so it deliberately does NOT move
    // `hook_ingress_drops` — that counter measures gateway backpressure.
    if session.refuse_if_authorization_expired().is_some() {
        return false;
    }

    let tx = {
        let guard = session
            .hook_ingress_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match guard.as_ref() {
            Some(tx) => tx.clone(),
            None => {
                record_hook_ingress_drop(metrics, &session.proxy_id, session.listen_port);
                return false;
            }
        }
    };

    let listener_queued = &metrics.hook_ingress_queued_bytes;
    let listener_prev = listener_queued.fetch_add(data.len(), Ordering::Relaxed);
    if listener_prev.saturating_add(data.len()) > LISTENER_HOOK_INGRESS_MAX_QUEUED_BYTES {
        listener_queued.fetch_sub(data.len(), Ordering::Relaxed);
        record_hook_ingress_drop(metrics, &session.proxy_id, session.listen_port);
        return false;
    }

    let queued = &session.hook_ingress_queued_bytes;
    let prev = queued.fetch_add(data.len(), Ordering::Relaxed);
    if prev.saturating_add(data.len()) > SESSION_HOOK_INGRESS_MAX_QUEUED_BYTES {
        queued.fetch_sub(data.len(), Ordering::Relaxed);
        listener_queued.fetch_sub(data.len(), Ordering::Relaxed);
        record_hook_ingress_drop(metrics, &session.proxy_id, session.listen_port);
        return false;
    }

    if tx.try_send(Bytes::copy_from_slice(data)).is_err() {
        queued.fetch_sub(data.len(), Ordering::Relaxed);
        listener_queued.fetch_sub(data.len(), Ordering::Relaxed);
        record_hook_ingress_drop(metrics, &session.proxy_id, session.listen_port);
        return false;
    }
    true
}

fn release_hook_ingress_retained_bytes(
    session: &UdpSession,
    metrics: &UdpProxyMetrics,
    len: usize,
) {
    session
        .hook_ingress_queued_bytes
        .fetch_sub(len, Ordering::Relaxed);
    metrics
        .hook_ingress_queued_bytes
        .fetch_sub(len, Ordering::Relaxed);
}

/// Keeps one admitted payload charged until it is no longer retained by either
/// the queue or an in-flight hook/forward future. Drop-based release covers
/// every early-exit and hook-cancellation path without duplicated decrements.
struct HookIngressRetainedBytesGuard<'a> {
    session: &'a UdpSession,
    metrics: &'a UdpProxyMetrics,
    len: usize,
}

impl Drop for HookIngressRetainedBytesGuard<'_> {
    fn drop(&mut self) {
        release_hook_ingress_retained_bytes(self.session, self.metrics, self.len);
    }
}

/// Per-session worker: drain hook-ingress FIFO, enforce `on_udp_datagram`, then
/// forward. One task per session (not per datagram). Idle wake / cancellation
/// is the bounded channel's sender drop ([`UdpSession::close_hook_ingress`]),
/// not [`UdpSession::stop_notify`] — that Notify's `notify_one` permit is
/// reserved for the backend reply task. Exit when the sender is dropped or
/// stop/expired flags are observed. A dedicated notification cancels an
/// in-flight hook await so cleanup cannot leave detached session resources.
fn spawn_session_hook_ingress_worker(
    session: Arc<UdpSession>,
    mut rx: mpsc::Receiver<Bytes>,
    metrics: Arc<UdpProxyMetrics>,
    client_addr: SocketAddr,
) {
    tokio::spawn(async move {
        loop {
            if session
                .stop_reply_task
                .load(std::sync::atomic::Ordering::Acquire)
                || session.expired.load(std::sync::atomic::Ordering::Acquire)
            {
                break;
            }

            let data = match rx.recv().await {
                Some(d) => d,
                None => break,
            };

            let len = data.len();
            let _retained_bytes = HookIngressRetainedBytesGuard {
                session: session.as_ref(),
                metrics: metrics.as_ref(),
                len,
            };

            // Cleanup/expiry may have raced the receive; do not run hooks for a
            // stopped session (residuals are drained below without hooks).
            if session
                .stop_reply_task
                .load(std::sync::atomic::Ordering::Acquire)
                || session.expired.load(std::sync::atomic::Ordering::Acquire)
            {
                break;
            }

            let allowed = tokio::select! {
                allowed = udp_datagram_allowed(
                &session.datagram_plugins,
                Arc::clone(&session.datagram_client_ip),
                Arc::clone(&session.datagram_proxy_id),
                session.datagram_proxy_name.clone(),
                session.listen_port,
                &data,
                session.datagram_payload_kind,
                UdpDatagramDirection::ClientToBackend,
                Some(UdpMetadataSink::new(&session.metadata)),
                ) => allowed,
                _ = session.hook_ingress_stop_notify.notified() => break,
            };
            if !allowed {
                continue;
            }

            // Re-check after the hook await: expiry during a slow plugin must
            // not produce a late backend side effect.
            if session
                .stop_reply_task
                .load(std::sync::atomic::Ordering::Acquire)
                || session.expired.load(std::sync::atomic::Ordering::Acquire)
            {
                break;
            }

            if let Err(e) = forward_client_datagram_to_backend(&session, &data).await {
                debug!(
                    proxy_id = %session.datagram_proxy_id,
                    client = %udp_client_log_addr(client_addr),
                    listen_port = session.listen_port,
                    error = %e,
                    "UDP hook-ingress forward error"
                );
                continue;
            }
            metrics.datagrams_out.fetch_add(1, Ordering::Relaxed);
            metrics.bytes_out.fetch_add(len as u64, Ordering::Relaxed);
        }

        // Drain any residual so queued-byte accounting cannot leak if the
        // worker exits while the channel still holds payloads (sender may
        // already be closed). Never run hooks or forward after stop.
        while let Ok(data) = rx.try_recv() {
            release_hook_ingress_retained_bytes(&session, &metrics, data.len());
        }
    });
}

/// Bounded FIFO of datagrams that arrived for a source while its session
/// setup (DNS, `on_stream_connect` plugins, backend DTLS handshake) is still
/// running in the background task. The previous synchronous setup path left
/// these packets in the kernel socket buffer and forwarded them after setup;
/// this queue preserves that behavior without blocking the recv loop.
#[derive(Default)]
struct PendingDatagramQueue {
    datagrams: Vec<Vec<u8>>,
    queued_bytes: usize,
    /// Forwarded client the in-flight setup was started for, when the listener
    /// runs the datagram client-address gate. A follow-up datagram asserting a
    /// different client is dropped instead of being queued behind an identity
    /// it does not belong to. Always `None` when the gate is disabled.
    forwarded_client: Option<SocketAddr>,
}

impl PendingDatagramQueue {
    /// Append a follow-up datagram, tail-dropping once either cap is hit.
    /// Returns `false` when the datagram was dropped. Zero-length datagrams
    /// are valid UDP and are queued like any other.
    fn push_bounded(&mut self, data: &[u8]) -> bool {
        if self.datagrams.len() >= PENDING_SESSION_MAX_QUEUED_DATAGRAMS
            || self.queued_bytes.saturating_add(data.len()) > PENDING_SESSION_MAX_QUEUED_BYTES
        {
            return false;
        }
        self.queued_bytes += data.len();
        self.datagrams.push(data.to_vec());
        true
    }
}

/// Removes the pending-session gate (dropping any still-queued datagrams) when
/// the setup task exits without completing the queue handoff — setup error,
/// plugin block, mesh deny, or mid-drain forward failure. The success path
/// removes the gate atomically via [`take_pending_datagrams`] and disarms.
struct PendingSessionGate {
    pending_sessions: PendingSessionMap,
    client_addr: SocketAddr,
    armed: bool,
}

impl PendingSessionGate {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingSessionGate {
    fn drop(&mut self) {
        if self.armed {
            self.pending_sessions.remove(&self.client_addr);
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct BackendDtlsConfigCacheKey {
    /// Required for shared SNI listeners, which can serve same-ID proxies from
    /// different namespaces through one listener-local cache.
    proxy_namespace: String,
    proxy_id: String,
    backend_host: String,
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
    server_ca_cert_path: Option<String>,
    verify_server_cert: bool,
    tls_no_verify: bool,
    global_ca_bundle_path: Option<String>,
    san_allow_list: Vec<String>,
    connect_timeout_ms: u64,
    crls_ptr: usize,
    /// Backend TLS reload epoch the entry was built under. In-place cert/key/
    /// CA rotation changes no path, so the epoch is the only key field that
    /// distinguishes pre- from post-rotation material.
    reload_epoch: u64,
}

impl Hash for BackendDtlsConfigCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.proxy_namespace.hash(state);
        self.proxy_id.hash(state);
        self.backend_host.hash(state);
        self.client_cert_path.hash(state);
        self.client_key_path.hash(state);
        self.server_ca_cert_path.hash(state);
        self.verify_server_cert.hash(state);
        self.tls_no_verify.hash(state);
        self.global_ca_bundle_path.hash(state);
        self.san_allow_list.hash(state);
        self.connect_timeout_ms.hash(state);
        self.crls_ptr.hash(state);
        self.reload_epoch.hash(state);
    }
}

#[allow(clippy::too_many_arguments)]
fn backend_dtls_config_cache_key(
    proxy: &Proxy,
    backend_host: &str,
    tls_no_verify: bool,
    global_ca_bundle_path: Option<&str>,
    crls: &crate::tls::CrlList,
    reload_epoch: u64,
) -> BackendDtlsConfigCacheKey {
    BackendDtlsConfigCacheKey {
        proxy_namespace: proxy.namespace.clone(),
        proxy_id: proxy.id.clone(),
        backend_host: backend_host.to_string(),
        client_cert_path: proxy.resolved_tls.client_cert_path.clone(),
        client_key_path: proxy.resolved_tls.client_key_path.clone(),
        server_ca_cert_path: proxy.resolved_tls.server_ca_cert_path.clone(),
        verify_server_cert: proxy.resolved_tls.verify_server_cert,
        tls_no_verify,
        global_ca_bundle_path: global_ca_bundle_path.map(str::to_string),
        san_allow_list: proxy.resolved_tls.san_allow_list.clone(),
        connect_timeout_ms: proxy.backend_connect_timeout_ms,
        crls_ptr: Arc::as_ptr(crls) as usize,
        reload_epoch,
    }
}

fn cached_backend_dtls_config(
    cache: &BackendDtlsConfigCache,
    proxy: &Proxy,
    backend_host: &str,
    tls_no_verify: bool,
    crls: &crate::tls::CrlList,
    global_ca_bundle_path: Option<&str>,
) -> Result<crate::dtls::BackendDtlsParams, anyhow::Error> {
    let epoch = cache.reload_epoch.load(Ordering::Acquire);
    if cache.built_under_epoch.swap(epoch, Ordering::AcqRel) != epoch {
        // Backend TLS material was reloaded in place: entries built from the
        // old bytes are already unreachable (epoch is in the key); clearing
        // just garbage-collects them.
        cache.entries.clear();
    }

    let key = backend_dtls_config_cache_key(
        proxy,
        backend_host,
        tls_no_verify,
        global_ca_bundle_path,
        crls,
        epoch,
    );
    if let Some(entry) = cache.entries.get(&key) {
        return Ok(entry.value().as_ref().clone());
    }

    let params = crate::dtls::build_backend_dtls_config(
        proxy,
        backend_host,
        tls_no_verify,
        crls,
        global_ca_bundle_path,
    )?;
    let cached = Arc::new(params);
    let entry = cache.entries.entry(key).or_insert_with(|| cached.clone());
    Ok(entry.value().as_ref().clone())
}

enum ConnectedUdpBackend {
    Plain(UdpSocket),
    Dtls(crate::dtls::DtlsConnection),
}

enum UdpBackendCandidateError {
    Io(std::io::Error),
    Dtls(anyhow::Error),
}

impl From<std::io::Error> for UdpBackendCandidateError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Bind, connect, and (when requested) complete DTLS using the shared rotated
/// DNS order. The DTLS parameters retain the original hostname for SNI and
/// certificate verification; only the UDP peer address changes per attempt.
async fn connect_udp_backend_candidates(
    candidates: &crate::dns::ResolvedAddresses,
    port: u16,
    connect_timeout: Duration,
    dtls_params: Option<crate::dtls::BackendDtlsParams>,
) -> Result<(ConnectedUdpBackend, SocketAddr), anyhow::Error> {
    crate::dns::connect_candidates(candidates, port, connect_timeout, |addr| {
        let dtls_params = dtls_params.clone();
        async move {
            let bind_addr = if addr.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let socket = UdpSocket::bind(bind_addr).await?;
            socket.connect(addr).await?;
            match dtls_params {
                Some(params) => crate::dtls::DtlsConnection::connect(socket, params)
                    .await
                    .map(ConnectedUdpBackend::Dtls)
                    .map_err(UdpBackendCandidateError::Dtls),
                None => Ok(ConnectedUdpBackend::Plain(socket)),
            }
        }
    })
    .await
    .map_err(|error| match error {
        crate::dns::CandidateConnectError::TimedOut { last_addr } => anyhow::anyhow!(
            "UDP/DTLS connect budget exhausted after {}ms (last={})",
            connect_timeout.as_millis(),
            last_addr
        ),
        crate::dns::CandidateConnectError::Failed {
            last_addr,
            source: UdpBackendCandidateError::Io(source),
        } => anyhow::anyhow!(
            "All UDP DNS candidates failed (last={}): {}",
            last_addr,
            source
        ),
        crate::dns::CandidateConnectError::Failed {
            source: UdpBackendCandidateError::Dtls(source),
            ..
        } => StreamSetupError::with_colon_detail(
            StreamSetupKind::BackendDtlsHandshake,
            format!("{source:#}"),
        )
        .into(),
    })
}

/// Insert a pending-session gate for a new source without consuming an active
/// session slot. The active slot is reserved only after first-datagram plugin
/// checks and mesh destination enforcement admit the flow.
fn try_insert_pending_session_gate(
    pending_sessions: &PendingSessionMap,
    client_addr: SocketAddr,
    max_sessions: usize,
    forwarded_client: Option<SocketAddr>,
) -> Result<bool, anyhow::Error> {
    if pending_sessions.len() >= max_sessions {
        return Err(anyhow::anyhow!(
            "UDP pending session limit reached ({}), dropping datagram",
            max_sessions
        ));
    }
    match pending_sessions.entry(client_addr) {
        dashmap::mapref::entry::Entry::Occupied(_) => Ok(false),
        dashmap::mapref::entry::Entry::Vacant(vacant) => {
            vacant.insert(PendingDatagramQueue {
                forwarded_client,
                ..Default::default()
            });
            Ok(true)
        }
    }
}

/// Non-consuming check of the active-session cap. Returns `true` when the
/// listener already holds `FERRUM_UDP_MAX_SESSIONS` active sessions, so a
/// datagram from a new source can be dropped cheaply — before a pending gate is
/// created, a setup task is spawned, or first-datagram policy runs — without
/// reserving a slot. The real reservation still happens post-admission in
/// `process_new_session_datagram` for flows that pass plugin + mesh checks.
///
/// This restores the active-session cap's role as a cheap flood shield for a
/// maxed-out listener: once the slot reservation moved past admission, a
/// spoofed-source flood against a full listener could otherwise spawn setup
/// tasks and execute policy hooks for traffic the post-admission reservation is
/// certain to reject.
fn udp_active_session_cap_reached(metrics: &UdpProxyMetrics, max_sessions: usize) -> bool {
    metrics.active_sessions.load(Ordering::Relaxed) >= max_sessions as u64
}

/// Whether a datagram from a source with no established session must be
/// dropped.
///
/// Two independent process-level reasons, both a single relaxed atomic load and
/// neither allocating or locking:
///
/// * critical overload shedding, and
/// * the bounded last-known-good configuration fence (issue #3726) — a data
///   plane whose applied CP snapshot aged past
///   `FERRUM_DP_CONFIG_MAX_STALE_SECONDS` with no authoritative CP can no longer
///   be told that this listener, its backends, or its policy were revoked.
///
/// UDP has no handshake, but it does have a real new-session boundary: the
/// caller pairs this with `!sessions.contains_key(..)`, so established sessions
/// keep draining while no new source can start one under revoked policy. The
/// same predicate gates the DTLS pre-allocation and post-accept admission
/// checks, so no association path admits new work behind a stale configuration.
#[inline]
fn refuse_new_udp_source(overload: &crate::overload::OverloadState) -> bool {
    overload.reject_new_connections.load(Ordering::Relaxed)
        || crate::dp_config_freshness::new_traffic_blocked()
}

/// Atomically either remove the pending gate (when its queue is observed
/// empty) or take the queued datagrams for draining. Both the empty-check +
/// removal and the take happen under the same DashMap shard lock the recv
/// loop's append path uses, so a datagram appended concurrently is either
/// returned by a later call here or forwarded directly by the recv loop once
/// the gate is gone — never lost in between, never reordered relative to
/// backend sends.
fn take_pending_datagrams(
    pending_sessions: &PendingSessionMap,
    client_addr: SocketAddr,
) -> Option<Vec<Vec<u8>>> {
    match pending_sessions.entry(client_addr) {
        dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
            if occupied.get().datagrams.is_empty() {
                occupied.remove();
                None
            } else {
                let queue = occupied.get_mut();
                queue.queued_bytes = 0;
                Some(std::mem::take(&mut queue.datagrams))
            }
        }
        dashmap::mapref::entry::Entry::Vacant(_) => None,
    }
}

#[derive(Debug)]
struct UdpDtlsIdleTimeout;

impl std::fmt::Display for UdpDtlsIdleTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UDP DTLS idle timeout")
    }
}

impl std::error::Error for UdpDtlsIdleTimeout {}

fn is_udp_dtls_idle_timeout(error: &anyhow::Error) -> bool {
    error.downcast_ref::<UdpDtlsIdleTimeout>().is_some()
}

struct UdpSessionSlotReservation {
    metrics: Arc<UdpProxyMetrics>,
    active: bool,
}

impl UdpSessionSlotReservation {
    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for UdpSessionSlotReservation {
    fn drop(&mut self) {
        if self.active {
            self.metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

fn reserve_udp_session_slot(
    metrics: &Arc<UdpProxyMetrics>,
    max_sessions: usize,
) -> Result<UdpSessionSlotReservation, anyhow::Error> {
    let prev = metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
    if prev >= max_sessions as u64 {
        metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        return Err(anyhow::anyhow!(
            "UDP session limit reached ({}), dropping datagram",
            max_sessions
        ));
    }

    Ok(UdpSessionSlotReservation {
        metrics: Arc::clone(metrics),
        active: true,
    })
}

fn udp_session_shard_amount(override_value: usize) -> usize {
    crate::util::sharding::pool_shard_amount(override_value)
}

struct UdpSessionEpochView {
    proxy: Proxy,
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
    datagram_plugins: Arc<[Arc<dyn Plugin>]>,
    consumer_index: Arc<ConsumerIndex>,
    sni_hostname: Option<String>,
}

fn resolve_udp_session_epoch_view(
    listener_proxy_id: &str,
    listener_proxy_namespace: &str,
    epoch: &RequestEpoch,
    initial_data: &[u8],
    sni_proxy_ids: Option<&[NamespacedResourceId]>,
    listen_port: u16,
) -> Result<UdpSessionEpochView, anyhow::Error> {
    let base_proxy = epoch
        .proxy_by_namespaced_id(listener_proxy_namespace, listener_proxy_id)
        .ok_or_else(|| {
            anyhow::anyhow!("Proxy {listener_proxy_namespace}/{listener_proxy_id} not found")
        })?;

    let sni_hostname = if base_proxy.passthrough {
        match super::sni::extract_sni_from_dtls_client_hello(initial_data) {
            super::sni::DtlsSniResult::Hostname(host) => Some(host),
            super::sni::DtlsSniResult::NoSni => None,
            super::sni::DtlsSniResult::InvalidFragment => {
                // A DTLS continuation fragment (fragment_offset != 0) as the first
                // datagram for this client tuple carries no parseable ClientHello
                // start. Drop it instead of letting `None` (no-SNI) bind it to the
                // empty-host catch-all proxy and create a bogus session.
                return Err(anyhow::anyhow!(
                    "Dropping DTLS continuation fragment (no ClientHello start) on port {}",
                    listen_port
                ));
            }
        }
    } else {
        None
    };

    // Shared passthrough ports can host same-ID proxies owned by different
    // namespaces, so SNI selects a full `(namespace, id)` identity.
    let (resolved_namespace, resolved_proxy_id) = if let Some(sni_ids) = sni_proxy_ids {
        let matched =
            super::sni::resolve_proxy_by_sni_in_epoch(sni_hostname.as_deref(), sni_ids, epoch)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No matching passthrough proxy for SNI {:?} on port {}",
                        sni_hostname,
                        listen_port
                    )
                })?;
        (matched.namespace.as_str(), matched.id.as_str())
    } else {
        (listener_proxy_namespace, listener_proxy_id)
    };

    let proxy = epoch
        .proxy_by_namespaced_id(resolved_namespace, resolved_proxy_id)
        .ok_or_else(|| anyhow::anyhow!("Proxy {resolved_namespace}/{resolved_proxy_id} not found"))?
        .clone();
    let plugins =
        epoch
            .plugin_cache
            .plugins_for_protocol(&proxy.namespace, &proxy.id, ProxyProtocol::Udp);
    let datagram_plugins: Arc<[Arc<dyn Plugin>]> = plugins
        .iter()
        .filter(|p| p.requires_udp_datagram_hooks())
        .cloned()
        .collect();
    let consumer_index = Arc::new(ConsumerIndex::from_inner(Arc::clone(&epoch.consumer_index)));

    Ok(UdpSessionEpochView {
        proxy,
        plugins,
        datagram_plugins,
        consumer_index,
        sni_hostname,
    })
}

#[allow(clippy::too_many_arguments)]
async fn udp_datagram_allowed(
    datagram_plugins: &[Arc<dyn Plugin>],
    client_ip: Arc<str>,
    proxy_id: Arc<str>,
    proxy_name: Option<Arc<str>>,
    listen_port: u16,
    payload: &[u8],
    payload_kind: StreamBytesKind,
    direction: UdpDatagramDirection,
    metadata_sink: Option<UdpMetadataSink<'_>>,
) -> bool {
    if datagram_plugins.is_empty() {
        return true;
    }

    let ctx = UdpDatagramContext {
        client_ip,
        proxy_id,
        proxy_name,
        listen_port,
        datagram_size: payload.len(),
        direction,
        payload,
        payload_kind,
        metadata_sink,
    };
    for plugin in datagram_plugins {
        if matches!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop) {
            return false;
        }
    }
    true
}

struct UdpDisconnectContext<'a> {
    namespace: &'a str,
    proxy_id: &'a str,
    proxy_name: Option<&'a str>,
    session: &'a UdpSession,
    backend_scheme: BackendScheme,
    listen_port: u16,
    /// Process-monotonic disconnect instant (same clock as `created_at`).
    disconnected_ms: u64,
    /// Civil/UTC disconnect time for `timestamp_disconnected` rendering only.
    disconnected_wall_at: chrono::DateTime<chrono::Utc>,
    connection_error: Option<String>,
    error_class: Option<crate::retry::ErrorClass>,
    disconnect_direction: Option<crate::plugins::Direction>,
    disconnect_cause: Option<crate::plugins::DisconnectCause>,
}

/// Elapsed session/idle duration from monotonic endpoints. Wall clocks are
/// never consulted — a backward civil-clock step must not clamp duration to
/// zero, and a forward step must not inflate it.
#[inline]
fn stream_duration_ms_from_mono(start_ms: u64, end_ms: u64) -> f64 {
    end_ms.saturating_sub(start_ms) as f64
}

/// Idle-expiry predicate on the shared coarse monotonic clock.
#[inline]
pub(crate) fn udp_idle_expired(
    now_mono_ms: u64,
    last_activity_ms: u64,
    idle_timeout_ms: u64,
) -> bool {
    now_mono_ms.saturating_sub(last_activity_ms) > idle_timeout_ms
}

/// Whether a UDP/DTLS application-datagram outcome should refresh the shared
/// idle watermark used by session cleanup / `dtls_shared_idle_watchdog`.
///
/// Policy-rejected receives (for example `udp_rate_limiting` Drop) and failed
/// forwards must not extend session lifetime. Handshake/control traffic is
/// handled by the DTLS stack before the application relay and is not gated by
/// this predicate; admitted client→backend and successfully delivered
/// backend→client application datagrams must refresh.
#[inline]
pub(crate) fn udp_idle_activity_should_refresh(
    policy_admitted: bool,
    forward_or_deliver_succeeded: bool,
) -> bool {
    policy_admitted && forward_or_deliver_succeeded
}

/// Advance the shared idle watermark to `now_ms` when
/// [`udp_idle_activity_should_refresh`] is true.
#[inline]
pub(crate) fn maybe_touch_udp_idle_activity(
    activity_ms: &AtomicU64,
    now_ms: u64,
    policy_admitted: bool,
    forward_or_deliver_succeeded: bool,
) {
    if udp_idle_activity_should_refresh(policy_admitted, forward_or_deliver_succeeded) {
        activity_ms.store(now_ms, Ordering::Relaxed);
    }
}

/// Restore private correlation ownership after every plugin-writable metadata
/// merge and immediately before the disconnect summary becomes observable.
pub(crate) fn finalize_stream_summary_metadata(
    mut metadata: std::collections::HashMap<String, String>,
    correlation_ids: &CorrelationIdState,
) -> std::collections::HashMap<String, String> {
    correlation_ids.project_correlation_ids(&mut metadata);
    metadata
}

fn build_udp_stream_summary(context: UdpDisconnectContext<'_>) -> StreamTransactionSummary {
    let created_ms = context.session.created_at.load(Ordering::Relaxed);
    let writable_metadata = context
        .session
        .metadata
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let metadata =
        finalize_stream_summary_metadata(writable_metadata, &context.session.correlation_ids);

    StreamTransactionSummary {
        namespace: context.namespace.to_string(),
        proxy_id: context.proxy_id.to_string(),
        proxy_lifecycle_generation: context.session.proxy_lifecycle_generation,
        // Carry the connect-time execution-trigger outcomes so a skipped
        // instance stays skipped at disconnect.
        plugin_trigger_decisions: context.session.plugin_trigger_decisions.clone(),
        proxy_name: context.proxy_name.map(|name| name.to_string()),
        // Resolved client identity captured at admission (the authenticated
        // forwarded client when datagram metadata supplied one, else the socket
        // peer), so connect and disconnect records agree.
        client_ip: context.session.datagram_client_ip.to_string(),
        consumer_username: context.session.consumer_username.clone(),
        auth_method: context.session.auth_method,
        backend_target: context.session.backend_target.clone(),
        backend_resolved_ip: Some(context.session.backend_resolved_ip.clone()),
        protocol: context.backend_scheme.to_string(),
        listen_port: context.listen_port,
        duration_ms: stream_duration_ms_from_mono(created_ms, context.disconnected_ms),
        bytes_sent: context.session.bytes_sent.load(Ordering::Relaxed),
        bytes_received: context.session.bytes_received.load(Ordering::Relaxed),
        connection_error: context.connection_error,
        error_class: context.error_class,
        disconnect_direction: context.disconnect_direction,
        disconnect_cause: context.disconnect_cause,
        timestamp_connected: context.session.connected_wall_at.to_rfc3339(),
        timestamp_disconnected: context.disconnected_wall_at.to_rfc3339(),
        sni_hostname: context.session.sni_hostname.clone(),
        metadata,
    }
}

async fn emit_udp_stream_disconnect(
    plugins: &[Arc<dyn Plugin>],
    context: UdpDisconnectContext<'_>,
) {
    if plugins.is_empty() && context.error_class.is_none() {
        return;
    }

    let summary = build_udp_stream_summary(context);
    crate::runtime_metrics::global_ref().record_stream_transaction(&summary);
    if plugins.is_empty() {
        return;
    }
    for plugin in plugins {
        plugin.on_stream_disconnect(&summary).await;
    }
}

struct DtlsDisconnectContext<'a> {
    namespace: &'a str,
    proxy_id: &'a str,
    proxy_name: Option<&'a str>,
    proxy_lifecycle_generation: Option<u64>,
    /// Resolved client endpoint: the authenticated forwarded client when the
    /// datagram client-address gate supplied one, else the socket peer. This is
    /// the summary's `client_ip`, matching what `on_stream_connect` saw.
    resolved_client: SocketAddr,
    consumer_username: Option<String>,
    auth_method: Option<&'static str>,
    backend_target: &'a str,
    backend_resolved_ip: Option<&'a str>,
    backend_scheme: BackendScheme,
    listen_port: u16,
    /// Civil/UTC connect time for human-readable rendering only.
    connected_at: chrono::DateTime<chrono::Utc>,
    /// Civil/UTC disconnect time for human-readable rendering only.
    disconnected_at: chrono::DateTime<chrono::Utc>,
    /// Elapsed session duration from `Instant` (monotonic), never wall delta.
    duration_ms: f64,
    bytes_sent: u64,
    bytes_received: u64,
    connection_error: Option<String>,
    error_class: Option<crate::retry::ErrorClass>,
    disconnect_direction: Option<crate::plugins::Direction>,
    disconnect_cause: Option<crate::plugins::DisconnectCause>,
    /// Frontend DTLS ClientHello SNI captured at accept and exposed on
    /// `StreamConnectionContext` during `on_stream_connect`. Carried into the
    /// disconnect summary so logging sinks keep connect/disconnect parity.
    sni_hostname: Option<String>,
    metadata: &'a std::collections::HashMap<String, String>,
    correlation_ids: &'a CorrelationIdState,
    /// Per-instance execution-trigger decisions captured from the accepted
    /// connection's `StreamConnectionContext`, so `on_stream_disconnect` agrees
    /// with `on_stream_connect`.
    plugin_trigger_decisions: crate::plugins::StreamTriggerDecisions,
}

fn build_dtls_stream_summary(context: DtlsDisconnectContext<'_>) -> StreamTransactionSummary {
    let metadata =
        finalize_stream_summary_metadata(context.metadata.clone(), context.correlation_ids);

    StreamTransactionSummary {
        namespace: context.namespace.to_string(),
        proxy_id: context.proxy_id.to_string(),
        proxy_lifecycle_generation: context.proxy_lifecycle_generation,
        plugin_trigger_decisions: context.plugin_trigger_decisions,
        proxy_name: context.proxy_name.map(|name| name.to_string()),
        client_ip: crate::util::client_identity::canonical_ip_string(context.resolved_client.ip()),
        consumer_username: context.consumer_username,
        auth_method: context.auth_method,
        backend_target: context.backend_target.to_string(),
        backend_resolved_ip: context.backend_resolved_ip.map(str::to_string),
        protocol: context.backend_scheme.to_string(),
        listen_port: context.listen_port,
        duration_ms: context.duration_ms,
        bytes_sent: context.bytes_sent,
        bytes_received: context.bytes_received,
        connection_error: context.connection_error,
        error_class: context.error_class,
        disconnect_direction: context.disconnect_direction,
        disconnect_cause: context.disconnect_cause,
        timestamp_connected: context.connected_at.to_rfc3339(),
        timestamp_disconnected: context.disconnected_at.to_rfc3339(),
        sni_hostname: context.sni_hostname,
        metadata,
    }
}

/// Flush a GSO batch buffer to the client via the frontend socket.
///
/// When `local` is `Some`, an IP(v6)_PKTINFO cmsg is attached so the kernel
/// uses it as the reply source (skipping the routing lookup). The address
/// family must match `client_addr` — mismatched families fall through to the
/// legacy GSO path without pktinfo. The captured `ifindex` is carried through
/// so scoped IPv6 (link-local) replies egress the correct interface zone.
#[cfg(target_os = "linux")]
fn flush_gso_batch(
    gso_batch: &mut super::udp_batch::GsoBatchBuf,
    frontend: &Arc<UdpSocket>,
    client_addr: SocketAddr,
    local: Option<crate::socket_opts::PktinfoLocal>,
) -> std::io::Result<usize> {
    use std::os::unix::io::AsRawFd;
    let (dest, dest_len) = super::udp_batch::std_to_sockaddr_storage(client_addr);
    let effective_local = match (local.map(|l| l.ip), client_addr) {
        (Some(IpAddr::V4(_)), SocketAddr::V4(_)) | (Some(IpAddr::V6(_)), SocketAddr::V6(_)) => {
            local
        }
        _ => None,
    };
    gso_batch.flush_to(frontend.as_raw_fd(), &dest, dest_len, effective_local)
}

/// Send a single datagram directly to the client, honoring the captured
/// IP(v6)_PKTINFO reply-source address when present.
///
/// Escape hatch for datagrams the GSO batch cannot represent — zero-length
/// keepalives (`GsoBatchBuf::push` rejects empty payloads because a UDP GSO
/// segment cannot be zero-sized) and oversize post-flush refusals. Plain
/// `UdpSocket::send_to` here would bypass pktinfo and let the kernel pick the
/// source IP, so replies from a wildcard-bound listener could leave with the
/// wrong source address and be discarded by the client.
///
/// Every asynchronous wait (`send_to`, `writable`) is owned by the admitted
/// absolute authorization plan. After `writable()` reports readiness the plan
/// is re-read immediately before the pktinfo syscall so expiry wins over send
/// readiness at that boundary too.
#[cfg(target_os = "linux")]
async fn direct_send_to_client(
    frontend: &Arc<UdpSocket>,
    data: &[u8],
    client_addr: SocketAddr,
    local: Option<crate::socket_opts::PktinfoLocal>,
    authorization: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
) -> UdpFrontendSendOutcome<std::io::Result<usize>> {
    use std::os::unix::io::AsRawFd;
    // Only honor the local source when its address family matches the
    // destination — mirrors `flush_gso_batch` / `SendMmsgBatch::push_with_local`.
    let effective_local = match (local.map(|l| l.ip), client_addr) {
        (Some(IpAddr::V4(_)), SocketAddr::V4(_)) | (Some(IpAddr::V6(_)), SocketAddr::V6(_)) => {
            local
        }
        _ => None,
    };
    let Some(local) = effective_local else {
        return udp_frontend_send_until_expiry(authorization, frontend.send_to(data, client_addr))
            .await;
    };
    let (dest, dest_len) = super::udp_batch::std_to_sockaddr_storage(client_addr);
    loop {
        if let Some(termination) = udp_reply_expired_at_commit(authorization) {
            return UdpFrontendSendOutcome::AuthorizationExpired(termination);
        }
        match crate::socket_opts::send_with_pktinfo(
            frontend.as_raw_fd(),
            data,
            local,
            &dest,
            dest_len,
            None,
        ) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                match udp_frontend_writable_until_expiry(authorization, frontend.writable()).await {
                    UdpFrontendSendOutcome::AuthorizationExpired(termination) => {
                        return UdpFrontendSendOutcome::AuthorizationExpired(termination);
                    }
                    UdpFrontendSendOutcome::Sent(Err(e)) => {
                        return UdpFrontendSendOutcome::Sent(Err(e));
                    }
                    UdpFrontendSendOutcome::Sent(Ok(())) => {}
                }
            }
            other => return UdpFrontendSendOutcome::Sent(other),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct UdpReplySendDrops {
    datagrams: u64,
    bytes: u64,
}

#[cfg(target_os = "linux")]
impl UdpReplySendDrops {
    fn record_stats(&mut self, stats: super::udp_batch::SendMmsgFlush) {
        self.datagrams = self.datagrams.saturating_add(stats.datagrams as u64);
        self.bytes = self.bytes.saturating_add(stats.bytes as u64);
    }

    fn record_datagram(&mut self, len: usize) {
        self.datagrams = self.datagrams.saturating_add(1);
        self.bytes = self.bytes.saturating_add(len as u64);
    }
}

#[cfg(target_os = "linux")]
fn flush_sendmmsg_best_effort(
    send_batch: &mut super::udp_batch::SendMmsgBatch,
    fd: std::os::fd::RawFd,
    drops: &mut UdpReplySendDrops,
) -> std::io::Result<super::udp_batch::SendMmsgFlush> {
    let pending = send_batch.pending_stats();
    match send_batch.flush(fd) {
        Ok(flushed) => Ok(flushed),
        Err(e) => {
            drops.record_stats(pending);
            Err(e)
        }
    }
}

/// Direct-send a reply datagram that the batched paths cannot represent
/// (GSO-incompatible, sendmmsg-oversized, or post-flush refusal).
///
/// Rechecks the admitted absolute authorization plan immediately before the
/// client send so a prior `await` (hook, batch flush) cannot even enter the
/// escape hatch after expiry. The send itself is then owned by the same plan
/// (`send_to` / `writable` cannot emit after the deadline). Returns the
/// bounded termination when the send must not happen.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn direct_send_reply_or_drop(
    frontend: &Arc<UdpSocket>,
    data: &[u8],
    client_addr: SocketAddr,
    local_ip: Option<crate::socket_opts::PktinfoLocal>,
    proxy_id: &str,
    reason: &str,
    send_drops: &mut UdpReplySendDrops,
    authorization: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
) -> Option<crate::proxy::auth_lifetime::StreamAuthTermination> {
    if let Some(termination) = udp_reply_expired_at_commit(authorization) {
        return Some(termination);
    }
    debug!(
        proxy_id = %proxy_id,
        client = %udp_client_log_addr(client_addr),
        size = data.len(),
        reason,
        "UDP reply using direct-send escape hatch"
    );
    match direct_send_to_client(frontend, data, client_addr, local_ip, authorization).await {
        UdpFrontendSendOutcome::AuthorizationExpired(termination) => Some(termination),
        UdpFrontendSendOutcome::Sent(Err(e)) => {
            send_drops.record_datagram(data.len());
            warn!(
                proxy_id = %proxy_id,
                client = %udp_client_log_addr(client_addr),
                size = data.len(),
                error = %e,
                "UDP fallback direct-send failed; datagram lost"
            );
            None
        }
        UdpFrontendSendOutcome::Sent(Ok(_)) => None,
    }
}

/// Queue into `send_batch`, flushing once on `Full` and direct-sending on
/// `Oversized` (datagram larger than the lazy sendmmsg slot) or a stubborn
/// post-flush `Full`.
///
/// Rechecks the admitted absolute plan immediately before every flush or
/// fallback send. Returns the bounded termination when queued payloads must
/// be discarded rather than sent.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn enqueue_sendmmsg_or_direct(
    send_batch: &mut super::udp_batch::SendMmsgBatch,
    frontend: &Arc<UdpSocket>,
    client_addr: SocketAddr,
    data: &[u8],
    local_ip: Option<crate::socket_opts::PktinfoLocal>,
    proxy_id: &str,
    send_drops: &mut UdpReplySendDrops,
    authorization: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
) -> Option<crate::proxy::auth_lifetime::StreamAuthTermination> {
    use super::udp_batch::SendMmsgPushResult;
    use std::os::unix::io::AsRawFd;

    if let Some(termination) = udp_reply_expired_at_commit(authorization) {
        return Some(termination);
    }

    match send_batch.push_with_local(data, client_addr, local_ip) {
        SendMmsgPushResult::Queued => None,
        SendMmsgPushResult::Oversized => {
            // Preserve backend reply order: an oversized direct send must not
            // overtake ordinary datagrams already queued in sendmmsg.
            while !send_batch.is_empty() {
                if let Some(termination) = udp_reply_expired_at_commit(authorization) {
                    return Some(termination);
                }
                if flush_sendmmsg_best_effort(send_batch, frontend.as_raw_fd(), send_drops).is_err()
                {
                    break;
                }
            }
            direct_send_reply_or_drop(
                frontend,
                data,
                client_addr,
                local_ip,
                proxy_id,
                "sendmmsg_oversized",
                send_drops,
                authorization,
            )
            .await
        }
        SendMmsgPushResult::Full => {
            if let Some(termination) = udp_reply_expired_at_commit(authorization) {
                return Some(termination);
            }
            let _ = flush_sendmmsg_best_effort(send_batch, frontend.as_raw_fd(), send_drops);
            match send_batch.push_with_local(data, client_addr, local_ip) {
                SendMmsgPushResult::Queued => None,
                SendMmsgPushResult::Oversized => {
                    direct_send_reply_or_drop(
                        frontend,
                        data,
                        client_addr,
                        local_ip,
                        proxy_id,
                        "sendmmsg_oversized",
                        send_drops,
                        authorization,
                    )
                    .await
                }
                SendMmsgPushResult::Full => {
                    // Still full after flush (socket likely congested / flush
                    // dropped the queue). Best-effort UDP: direct-send once.
                    direct_send_reply_or_drop(
                        frontend,
                        data,
                        client_addr,
                        local_ip,
                        proxy_id,
                        "sendmmsg_post_flush_full",
                        send_drops,
                        authorization,
                    )
                    .await
                }
            }
        }
    }
}

/// Drain a GSO buffer into sendmmsg, flushing when the batch fills and
/// direct-sending when a segment exceeds the sendmmsg slot size.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn drain_gso_to_sendmmsg_or_direct(
    gso_batch: &mut super::udp_batch::GsoBatchBuf,
    send_batch: &mut super::udp_batch::SendMmsgBatch,
    frontend: &Arc<UdpSocket>,
    client_addr: SocketAddr,
    local_ip: Option<crate::socket_opts::PktinfoLocal>,
    proxy_id: &str,
    send_drops: &mut UdpReplySendDrops,
    authorization: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
) -> Option<crate::proxy::auth_lifetime::StreamAuthTermination> {
    use std::os::unix::io::AsRawFd;

    loop {
        if let Some(termination) = udp_reply_expired_at_commit(authorization) {
            return Some(termination);
        }
        gso_batch.drain_to_sendmmsg(send_batch, client_addr, local_ip);
        if gso_batch.is_empty() {
            return None;
        }
        if send_batch.is_empty() {
            // Stuck on an oversized front segment — escape via direct-send.
            let dgram = gso_batch.take_front_datagram()?;
            if let Some(termination) = direct_send_reply_or_drop(
                frontend,
                &dgram,
                client_addr,
                local_ip,
                proxy_id,
                "gso_drain_sendmmsg_oversized",
                send_drops,
                authorization,
            )
            .await
            {
                return Some(termination);
            }
            continue;
        }
        if let Some(termination) = udp_reply_expired_at_commit(authorization) {
            return Some(termination);
        }
        let _ = flush_sendmmsg_best_effort(send_batch, frontend.as_raw_fd(), send_drops);
    }
}

/// Try to enqueue a datagram into the GSO batch; on batch-full or size-mismatch,
/// flush and retry, and on GSO socket failure drain the buffered datagrams
/// through the sendmmsg fallback.
///
/// This collapses three near-identical GSO→sendmmsg fallback blocks that
/// previously existed inline in `create_session`. Centralising it means the
/// "post-flush push dropped the datagram" silent-drop guard (tracked as MED-5
/// in the PR review) only has to be fixed in one place.
///
/// `gso_failed` is set to `true` if we have to abandon GSO for this session.
/// The caller must stop calling this helper after that and drive `send_batch`
/// directly.
///
/// Rechecks the admitted absolute plan immediately before every flush or
/// fallback send so a payload queued before expiry is discarded rather than
/// flushed afterwards. Returns the bounded termination when the caller must
/// abandon the reply loop.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn try_gso_send_or_fallback(
    gso_batch: &mut super::udp_batch::GsoBatchBuf,
    send_batch: &mut super::udp_batch::SendMmsgBatch,
    frontend: &Arc<UdpSocket>,
    client_addr: SocketAddr,
    data: &[u8],
    gso_failed: &mut bool,
    proxy_id: &str,
    local_ip: Option<crate::socket_opts::PktinfoLocal>,
    send_drops: &mut UdpReplySendDrops,
    authorization: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
) -> Option<crate::proxy::auth_lifetime::StreamAuthTermination> {
    if let Some(termination) = udp_reply_expired_at_commit(authorization) {
        return Some(termination);
    }
    if gso_batch.push(data) {
        return None;
    }
    // Batch full or size-mismatch — flush current batch and try once more.
    if let Some(termination) = udp_reply_expired_at_commit(authorization) {
        return Some(termination);
    }
    match flush_gso_batch(gso_batch, frontend, client_addr, local_ip) {
        Ok(_) => {
            if !gso_batch.push(data) {
                // Post-flush push still refused (zero-length or oversize /
                // >max_bytes — GSO cannot represent either). Send it directly
                // as a single datagram through the pktinfo-aware path so the
                // reply still leaves with the captured source address.
                return direct_send_reply_or_drop(
                    frontend,
                    data,
                    client_addr,
                    local_ip,
                    proxy_id,
                    "gso_post_flush_refused",
                    send_drops,
                    authorization,
                )
                .await;
            }
            None
        }
        Err(e) => {
            // GSO sendmsg itself failed — abandon GSO for this session.
            debug!(
                proxy_id = %proxy_id,
                client = %udp_client_log_addr(client_addr),
                "GSO send failed ({}), falling back to sendmmsg",
                e
            );
            *gso_failed = true;
            if let Some(termination) = drain_gso_to_sendmmsg_or_direct(
                gso_batch,
                send_batch,
                frontend,
                client_addr,
                local_ip,
                proxy_id,
                send_drops,
                authorization,
            )
            .await
            {
                return Some(termination);
            }
            // Now push the current datagram (or direct-send if oversized/full).
            enqueue_sendmmsg_or_direct(
                send_batch,
                frontend,
                client_addr,
                data,
                local_ip,
                proxy_id,
                send_drops,
                authorization,
            )
            .await
        }
    }
}

/// Configuration for starting a UDP proxy listener.
pub struct UdpListenerConfig {
    pub port: u16,
    pub bind_addr: IpAddr,
    pub proxy_id: String,
    /// Namespace owning `proxy_id`. Runtime state keyed by proxy identity —
    /// notably the adaptive batch-limit EWMA — must be qualified by this so a
    /// same-id proxy in another namespace never shares or prunes it.
    pub proxy_namespace: String,
    pub dns_cache: DnsCache,
    pub request_epoch: Arc<RequestEpochStore>,
    pub health_checker: Arc<HealthChecker>,
    pub shutdown: watch::Receiver<bool>,
    /// Optional gateway-wide shutdown receiver (SIGTERM/SIGINT). When `Some`,
    /// the receive loop exits as soon as either this OR the per-listener
    /// `shutdown` channel fires. Injected by [`crate::proxy::stream_listener::StreamListenerManager`]
    /// from the watch channel created in `main.rs`.
    pub global_shutdown: Option<watch::Receiver<bool>>,
    pub metrics: Arc<UdpProxyMetrics>,
    /// DTLS server config for frontend termination. When `Some`, the listener
    /// accepts DTLS connections from clients instead of plain UDP.
    pub frontend_dtls_config: Option<crate::dtls::FrontendDtlsConfig>,
    /// Optional sender that receives the `Arc<DtlsServer>` once the DTLS
    /// listener has bound and constructed its server instance. Used by
    /// [`crate::proxy::stream_listener::StreamListenerManager`] so ordinary
    /// frontend DTLS generation publish can call
    /// [`crate::dtls::DtlsServer::swap_frontend_config`] on the same instance
    /// the recv loop is using. `None` for plain UDP listeners (no DTLS server
    /// is built).
    pub dtls_server_tx: Option<tokio::sync::oneshot::Sender<Arc<crate::dtls::DtlsServer>>>,
    pub tls_no_verify: bool,
    /// Global CA bundle path for outbound TLS verification (fallback when proxy has no per-proxy CA).
    pub tls_ca_bundle_path: Option<String>,
    /// Maximum concurrent sessions per proxy (from `FERRUM_UDP_MAX_SESSIONS`, default 10000).
    pub max_sessions: usize,
    /// Frontend TLS/DTLS handshake timeout in seconds. 0 disables the deadline.
    pub frontend_tls_handshake_timeout_seconds: u64,
    /// Session cleanup interval in seconds (from `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS`, default 10).
    pub cleanup_interval_seconds: u64,
    /// Circuit breaker cache shared with HTTP proxies.
    pub circuit_breaker_cache: Arc<CircuitBreakerCache>,
    /// Certificate Revocation Lists for backend DTLS verification.
    pub crls: crate::tls::CrlList,
    /// Shared backend TLS reload epoch from the stream listener manager.
    /// `reload_backend_tls_material` bumps it after backend cert/key/CA bytes
    /// change in place so the listener-local backend DTLS config cache drops
    /// entries built from the pre-rotation material.
    pub backend_tls_reload_epoch: Arc<AtomicU64>,
    /// Flipped once the listener successfully binds and can accept traffic.
    pub started: Arc<AtomicBool>,
    /// When set, this listener serves multiple passthrough proxies sharing the port.
    /// SNI from the DTLS ClientHello selects which proxy to route to.
    ///
    /// Candidates are namespace-qualified: one shared port may host same-ID
    /// passthrough proxies owned by different namespaces.
    pub sni_proxy_ids: Option<Vec<NamespacedResourceId>>,
    /// Adaptive buffer tracker for dynamic batch limit sizing.
    pub adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    /// Number of datagrams per `recvmmsg` syscall on Linux (default: 64).
    /// Ignored on non-Linux platforms.
    pub recvmmsg_batch_size: usize,
    /// DashMap shard count for the per-client UDP session map.
    pub session_shard_amount: usize,
    /// Shared overload state for session accounting and load shedding.
    pub overload: Arc<crate::overload::OverloadState>,
    /// SO_BUSY_POLL duration in microseconds for low-latency receive.
    pub so_busy_poll_us: u32,
    /// Enable UDP GRO on the frontend socket.
    pub udp_gro_enabled: bool,
    /// Enable UDP GSO for batched sending.
    pub udp_gso_enabled: bool,
    /// Enable IP(v6)_PKTINFO on the frontend socket (Linux only). When enabled
    /// the recv path captures the per-datagram local destination address and
    /// the reply path attaches it to sendmsg ancillary data, saving one kernel
    /// routing-table lookup per send.
    pub udp_pktinfo_enabled: bool,
    /// Mesh `outboundTrafficPolicy: REGISTRY_ONLY` enforcement slot. `None`
    /// (Option<Arc<...>> stored inside the ArcSwap) outside mesh mode or
    /// when policy is `AllowAny`. When `Some`, the first datagram of each
    /// new session is checked against the admitted registry; unadmitted
    /// destinations are silently dropped (UDP has no RST analogue).
    pub mesh_outbound_enforcement:
        crate::modes::mesh::outbound_enforcement::SharedMeshOutboundEnforcement,
    /// Datagram client-address metadata gate (issues #3289, #3856, #3862).
    /// `Some` only when the proxy sets `stream_proxy_protocol: true`; then EVERY
    /// datagram must carry a trusted, well-formed (and, when a secret is
    /// configured, listener-bound, authenticated, and fresh) PROXY v2 DGRAM
    /// envelope or it is dropped. The gate owns this listener's replay window,
    /// so it is per-listener and rebuilt on reload. `None` keeps ordinary
    /// UDP/DTLS behavior with the socket peer as the only identity.
    pub datagram_client_address: Option<Arc<DatagramClientAddressGate>>,
}

/// Start a UDP proxy listener on the given port.
///
/// For each incoming datagram from a new client address, a session is created
/// with a dedicated backend socket. Datagrams are forwarded bidirectionally.
/// Idle sessions are cleaned up periodically.
///
/// When `frontend_dtls_config` is `Some`, the listener accepts DTLS-encrypted
/// connections from clients (frontend DTLS termination). Otherwise, plain UDP.
pub async fn start_udp_listener(cfg: UdpListenerConfig) -> Result<(), anyhow::Error> {
    let UdpListenerConfig {
        port,
        bind_addr,
        proxy_id,
        proxy_namespace,
        dns_cache,
        request_epoch,
        health_checker,
        shutdown,
        global_shutdown,
        metrics,
        frontend_dtls_config,
        dtls_server_tx,
        tls_no_verify,
        tls_ca_bundle_path,
        max_sessions,
        frontend_tls_handshake_timeout_seconds,
        cleanup_interval_seconds,
        circuit_breaker_cache,
        crls,
        backend_tls_reload_epoch,
        started,
        sni_proxy_ids,
        adaptive_buffer,
        recvmmsg_batch_size,
        session_shard_amount,
        overload,
        so_busy_poll_us,
        udp_gro_enabled,
        udp_gso_enabled,
        udp_pktinfo_enabled,
        mesh_outbound_enforcement,
        datagram_client_address,
    } = cfg;
    // An enabled gate with an empty trust set can never admit a datagram. Say
    // so once here rather than dropping every datagram with only a rate-limited
    // per-datagram record to explain it.
    if let Some(gate) = datagram_client_address.as_ref() {
        if !gate.has_trusted_peers() {
            warn!(
                proxy_id = %proxy_id,
                listen_port = port,
                "stream_proxy_protocol is enabled on this udp/dtls listener but \
                 FERRUM_TRUSTED_PROXIES is empty — every datagram will be dropped until a \
                 trusted datagram load balancer is configured"
            );
        } else if !gate.requires_authentication() {
            warn!(
                proxy_id = %proxy_id,
                listen_port = port,
                "stream_proxy_protocol is enabled on this udp/dtls listener without \
                 FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET — forwarded client addresses are trusted \
                 on the strength of the source address alone, which is spoofable unless the \
                 network path to the load balancer is protected"
            );
        }
    }
    let session_shard_amount = udp_session_shard_amount(session_shard_amount);
    // so_busy_poll_us and udp_gro_enabled are used in #[cfg(target_os = "linux")] blocks below.
    #[cfg(not(target_os = "linux"))]
    let _ = (so_busy_poll_us, udp_gro_enabled, udp_pktinfo_enabled);

    if let Some(dtls_config) = frontend_dtls_config {
        return start_dtls_frontend_listener(
            port,
            bind_addr,
            proxy_id,
            proxy_namespace,
            dns_cache,
            request_epoch,
            health_checker,
            shutdown,
            global_shutdown,
            metrics,
            dtls_config,
            dtls_server_tx,
            tls_no_verify,
            tls_ca_bundle_path,
            max_sessions,
            frontend_tls_handshake_timeout_seconds,
            circuit_breaker_cache,
            crls,
            started,
            overload,
            Arc::new(BackendDtlsConfigCacheState::new(backend_tls_reload_epoch)),
            datagram_client_address,
        )
        .await;
    }
    // Plain-UDP listeners have no DTLS server to publish; if a sender was
    // supplied we drop it here, which makes any waiting receiver see
    // `oneshot` closure semantics rather than blocking forever.
    let _ = dtls_server_tx;

    let addr = SocketAddr::new(bind_addr, port);
    let frontend_socket = Arc::new(UdpSocket::bind(addr).await?);

    // Apply Linux socket optimizations on the frontend UDP socket.
    #[cfg(target_os = "linux")]
    let mut pktinfo_active = false;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = frontend_socket.as_raw_fd();
        // SO_BUSY_POLL: spin in kernel for low-latency recv (Linux 3.11+).
        if so_busy_poll_us > 0 {
            if let Err(e) = crate::socket_opts::set_so_busy_poll(fd, so_busy_poll_us) {
                warn!(
                    proxy_id = %proxy_id,
                    listen_port = port,
                    so_busy_poll_us,
                    "Failed to enable SO_BUSY_POLL on UDP listener: {}",
                    e
                );
            }
            if let Err(e) = crate::socket_opts::set_so_prefer_busy_poll(fd, true) {
                warn!(
                    proxy_id = %proxy_id,
                    listen_port = port,
                    "Failed to enable SO_PREFER_BUSY_POLL on UDP listener: {}",
                    e
                );
            }
        }
        // IP(v6)_PKTINFO: capture the per-datagram local destination address on
        // recv and reuse it as the reply source on send (skips the kernel
        // routing lookup). Request both v4 and v6 variants so a dual-stack
        // listener captures pktinfo regardless of the client's family. Logged
        // as warn on failure but never fatal — replies fall back to routing.
        if udp_pktinfo_enabled {
            // Try both v4 and v6 variants — one will succeed for v4 sockets,
            // the other (or both, for dual-stack `::` binds) for v6. A v4
            // socket returns ENOPROTOOPT for IPV6_RECVPKTINFO which is fine.
            let v4_ok = crate::socket_opts::set_ip_pktinfo(fd).is_ok();
            let v6_ok = crate::socket_opts::set_ipv6_recvpktinfo(fd).is_ok();
            pktinfo_active = v4_ok || v6_ok;
            if pktinfo_active {
                info!(
                    proxy_id = %proxy_id,
                    port = port,
                    v4 = v4_ok,
                    v6 = v6_ok,
                    "IP_PKTINFO active on UDP listener; reply path will set source via cmsg (routing lookup skipped) and recv path uses readable()+recvmmsg"
                );
            } else {
                warn!(
                    proxy_id = %proxy_id,
                    port = port,
                    "IP_PKTINFO setsockopt failed on both v4 and v6; reply path will use routing lookup and recv path remains on recv_from"
                );
            }
        } else {
            debug!(
                proxy_id = %proxy_id,
                port = port,
                "IP_PKTINFO disabled (FERRUM_UDP_PKTINFO_ENABLED=false or auto-probe failed at startup); reply path uses routing lookup"
            );
        }
        // UDP_GRO cannot be enabled because the primary receive path uses
        // tokio's recv_from() in the select! loop, which doesn't expose cmsg
        // metadata. GRO-coalesced buffers from recv_from would be forwarded as
        // single oversized datagrams, breaking UDP message boundaries.
        // The recvmmsg drain loop has cmsg parsing for GRO splitting, but it's
        // only the secondary path — the first datagram per wakeup always goes
        // through recv_from. GRO requires ALL receive paths to support cmsg.
        // To enable GRO, the entire receive loop would need to be rewritten to
        // use recvmmsg as the primary wakeup mechanism (via AsyncFd + try_io).
        let _ = udp_gro_enabled;
    }

    // GSO is applied at send time in the reply handler — the flag is threaded through
    // to create_session so the reply handler can use send_with_gso() for batched sending
    // of same-size datagrams to the client.
    #[cfg(not(target_os = "linux"))]
    let _ = udp_gso_enabled;

    ensure_coarse_timer_started();
    started.store(true, Ordering::Release);
    info!(proxy_id = %proxy_id, "UDP proxy listener started on {}", addr);

    let backend_dtls_config_cache: BackendDtlsConfigCache =
        Arc::new(BackendDtlsConfigCacheState::new(backend_tls_reload_epoch));
    // Both maps are consulted on every received datagram, so shard sizing
    // goes through the shared hot-path contract instead of DashMap's
    // `4 * num_cpus` default.
    let sessions: SessionMap = Arc::new(DashMap::with_hasher_and_shard_amount(
        ahash::RandomState::default(),
        session_shard_amount,
    ));
    let pending_sessions: PendingSessionMap = Arc::new(DashMap::with_hasher_and_shard_amount(
        ahash::RandomState::default(),
        session_shard_amount,
    ));

    // Spawn session cleanup task
    spawn_session_cleanup(
        sessions.clone(),
        metrics.clone(),
        proxy_id.clone(),
        shutdown.clone(),
        cleanup_interval_seconds,
    );

    let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
    let mut shutdown_rx = shutdown;
    // Optional gateway-wide shutdown — fires on SIGTERM/SIGINT regardless of
    // per-listener config-driven removal. We watch BOTH so the recv loop
    // exits promptly during graceful drain.
    let mut global_shutdown_rx = global_shutdown;

    // Pre-allocate recvmmsg batch buffers (Linux only). On non-Linux, this is a no-op stub.
    // `false`: plain UDP proxy listeners never enable `IP_RECVORIGDSTADDR`, so
    // skip the per-datagram orig-dst cmsg scan (it would always yield `None`).
    #[cfg(target_os = "linux")]
    let mut recv_batch = super::udp_batch::RecvMmsgBatch::new(recvmmsg_batch_size, false);
    #[cfg(not(target_os = "linux"))]
    let _ = recvmmsg_batch_size; // suppress unused variable warning

    // Hot-path cache: skip DashMap lookup when consecutive datagrams come from the
    // same client address (very common in streaming UDP protocols).
    let mut last_client: Option<(SocketAddr, Arc<UdpSession>)> = None;

    // When pktinfo is active on Linux, drive the recv loop via `readable()` +
    // `recvmmsg` so the first datagram in each wakeup also surfaces its
    // IP(v6)_PKTINFO cmsg. tokio's `recv_from` wraps `recvfrom(2)` which does
    // not return cmsg — using it for the first packet loses the destination IP
    // for one-shot exchanges (e.g. DNS) where the drain loop never runs.
    #[cfg(target_os = "linux")]
    let pktinfo_primary = pktinfo_active;
    #[cfg(not(target_os = "linux"))]
    let pktinfo_primary = false;

    loop {
        tokio::select! {
            ready = frontend_socket.readable(), if pktinfo_primary => {
                if let Err(e) = ready {
                    warn!(proxy_id = %proxy_id, "UDP readable error: {}", e);
                    continue;
                }

                #[cfg(target_os = "linux")]
                {
                    let mut batch_dgrams_in: u64 = 0;
                    let mut batch_bytes_in: u64 = 0;
                    let mut batch_dgrams_out: u64 = 0;
                    let mut batch_bytes_out: u64 = 0;
                    let batch_limit = adaptive_buffer.get_batch_limit(&proxy_namespace, &proxy_id);
                    use std::os::fd::AsRawFd;
                    // One admission decision per batch: overload shedding and
                    // the #3726 stale-configuration fence are both process-level
                    // relaxed atomics, so reading them once here keeps the
                    // per-datagram cost at zero extra loads.
                    let refuse_new_udp_sources = refuse_new_udp_source(&overload);
                    let fd = frontend_socket.as_raw_fd();
                    let mut total_drained: usize = 0;
                    'drain: while total_drained < batch_limit {
                        let max_this_call =
                            (batch_limit - total_drained).min(recv_batch.capacity());
                        match frontend_socket.try_io(tokio::io::Interest::READABLE, || {
                            recv_batch.recv(fd, max_this_call)
                        }) {
                            Ok(n) if n > 0 => {
                                for i in 0..n {
                                    let (data, addr2) = recv_batch.datagram(i);

                                    // Reject datagrams from new clients under
                                    // critical overload, or while the DP's
                                    // applied CP configuration is stale beyond
                                    // its bound (issue #3726). Existing
                                    // sessions continue to be served, so
                                    // established flows drain while no new
                                    // source can start one under revoked
                                    // policy. `refuse_new_udp_sources` is
                                    // hoisted out of the batch: two relaxed
                                    // loads per batch, none per datagram.
                                    if refuse_new_udp_sources && !sessions.contains_key(&addr2) {
                                        continue;
                                    }

                                    let local2 = recv_batch.local_addr(i);

                                    // GRO splitting: if the kernel coalesced multiple same-size
                                    // datagrams into one buffer, split by segment size.
                                    if let Some(seg_size) = recv_batch.gro_segment_size(i) {
                                        let seg = seg_size as usize;
                                        if seg > 0 && data.len() > seg {
                                            let mut offset = 0;
                                            while offset < data.len() {
                                                let end = (offset + seg).min(data.len());
                                                let chunk = &data[offset..end];
                                                batch_dgrams_in += 1;
                                                batch_bytes_in += chunk.len() as u64;

                                                let result = process_datagram(
                                                    chunk,
                                                    addr2,
                                                    &proxy_id,
                                                    &proxy_namespace,
                                                    &request_epoch,
                                                    &health_checker,
                                                    &dns_cache,
                                                    &frontend_socket,
                                                    &sessions,
                                                    &pending_sessions,
                                                    &metrics,
                                                    tls_no_verify,
                                                    tls_ca_bundle_path.as_deref(),
                                                    &backend_dtls_config_cache,
                                                    max_sessions,
                                                    &mut last_client,
                                                    &mut batch_dgrams_out,
                                                    &mut batch_bytes_out,
                                                    port,
                                                    &circuit_breaker_cache,
                                                    &crls,
                                                    sni_proxy_ids.as_deref(),
                                                    &adaptive_buffer,
                                                    udp_gso_enabled,
                                                    local2,
                                                    &shutdown_rx,
                                                    global_shutdown_rx.as_ref(),
                                                    &overload,
                                                    &mesh_outbound_enforcement,
                                                    datagram_client_address.as_ref(),
                                                )
                                                .await;
                                                if let Err(e) = result {
                                                    debug!(proxy_id = %proxy_id, client = %addr2, "UDP forward error: {}", e);
                                                }
                                                offset = end;
                                            }
                                            continue; // already counted per-segment
                                        }
                                    }

                                    // Non-GRO path (single datagram).
                                    batch_dgrams_in += 1;
                                    batch_bytes_in += data.len() as u64;

                                    let result = process_datagram(
                                        data,
                                        addr2,
                                        &proxy_id,
                                        &proxy_namespace,
                                        &request_epoch,
                                        &health_checker,
                                        &dns_cache,
                                        &frontend_socket,
                                        &sessions,
                                        &pending_sessions,
                                        &metrics,
                                        tls_no_verify,
                                        tls_ca_bundle_path.as_deref(),
                                        &backend_dtls_config_cache,
                                        max_sessions,
                                        &mut last_client,
                                        &mut batch_dgrams_out,
                                        &mut batch_bytes_out,
                                        port,
                                        &circuit_breaker_cache,
                                        &crls,
                                        sni_proxy_ids.as_deref(),
                                        &adaptive_buffer,
                                        udp_gso_enabled,
                                        local2,
                                        &shutdown_rx,
                                        global_shutdown_rx.as_ref(),
                                        &overload,
                                        &mesh_outbound_enforcement,
                                        datagram_client_address.as_ref(),
                                    )
                                    .await;
                                    if let Err(e) = result {
                                        debug!(proxy_id = %proxy_id, client = %addr2, "UDP forward error: {}", e);
                                    }
                                }
                                total_drained += n;
                            }
                            _ => break 'drain, // WouldBlock or error — socket drained
                        }
                    }

                    if batch_dgrams_in > 0 {
                        adaptive_buffer.record_batch_cycle(
                            &proxy_namespace,
                            &proxy_id,
                            batch_dgrams_in,
                        );
                        metrics.datagrams_in.fetch_add(batch_dgrams_in, Ordering::Relaxed);
                        metrics.bytes_in.fetch_add(batch_bytes_in, Ordering::Relaxed);
                        metrics.datagrams_out.fetch_add(batch_dgrams_out, Ordering::Relaxed);
                        metrics.bytes_out.fetch_add(batch_bytes_out, Ordering::Relaxed);
                    }
                }
            }
            result = frontend_socket.recv_from(&mut buf), if !pktinfo_primary => {
                let (len, client_addr) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(proxy_id = %proxy_id, "UDP recv error: {}", e);
                        continue;
                    }
                };

                // Reject datagrams from new clients under critical overload, or
                // while the DP's applied CP configuration is stale beyond its
                // bound (issue #3726). Existing sessions continue to be served
                // (UDP is sessionless at the wire level, so we only block
                // session creation, not in-flight traffic).
                if refuse_new_udp_source(&overload) && !sessions.contains_key(&client_addr) {
                    continue;
                }

                // Batch-local metric accumulators — flushed to atomics once per batch.
                let mut batch_dgrams_in: u64 = 1;
                let mut batch_bytes_in: u64 = len as u64;
                let mut batch_dgrams_out: u64 = 0;
                let mut batch_bytes_out: u64 = 0;

                // Process first datagram then drain more with try_recv_from.
                // This arm is only used when pktinfo is inactive (non-Linux, or
                // pktinfo probe failed). `recv_from` uses `recvfrom(2)` which
                // does not surface cmsg, so `local_addr` is None. When pktinfo
                // is active on Linux the `readable()` arm above handles the
                // primary path via `recvmmsg` so the first datagram also carries
                // its IP(v6)_PKTINFO destination IP.
                let result = process_datagram(
                    &buf[..len],
                    client_addr,
                    &proxy_id,
                    &proxy_namespace,
                    &request_epoch,
                    &health_checker,
                    &dns_cache,
                    &frontend_socket,
                    &sessions,
                    &pending_sessions,
                    &metrics,
                    tls_no_verify,
                    tls_ca_bundle_path.as_deref(),
                    &backend_dtls_config_cache,
                    max_sessions,
                    &mut last_client,
                    &mut batch_dgrams_out,
                    &mut batch_bytes_out,
                    port,
                    &circuit_breaker_cache,
                    &crls,
                    sni_proxy_ids.as_deref(),
                    &adaptive_buffer,
                    udp_gso_enabled,
                    None,
                    &shutdown_rx,
                    global_shutdown_rx.as_ref(),
                    &overload,
                    &mesh_outbound_enforcement,
                    datagram_client_address.as_ref(),
                )
                .await;
                if let Err(e) = result {
                    debug!(
                        proxy_id = %proxy_id,
                        client = %udp_client_log_addr(client_addr),
                        "UDP forward error: {}",
                        e
                    );
                }

                // Drain additional pending datagrams without yielding to the runtime.
                // On Linux, uses recvmmsg to batch multiple datagrams per syscall.
                // On other platforms, falls back to individual try_recv_from calls.
                let batch_limit = adaptive_buffer.get_batch_limit(&proxy_namespace, &proxy_id);

                #[cfg(target_os = "linux")]
                {
                    use std::os::fd::AsRawFd;
                    // One admission decision per batch: overload shedding and
                    // the #3726 stale-configuration fence are both process-level
                    // relaxed atomics, so reading them once here keeps the
                    // per-datagram cost at zero extra loads.
                    let refuse_new_udp_sources = refuse_new_udp_source(&overload);
                    let fd = frontend_socket.as_raw_fd();
                    let mut total_drained: usize = 0;
                    'drain: while total_drained < batch_limit {
                        let max_this_call =
                            (batch_limit - total_drained).min(recv_batch.capacity());
                        match frontend_socket.try_io(tokio::io::Interest::READABLE, || {
                            recv_batch.recv(fd, max_this_call)
                        }) {
                            Ok(n) if n > 0 => {
                                for i in 0..n {
                                    let (data, addr2) = recv_batch.datagram(i);
                                    let local2 = if pktinfo_active {
                                        recv_batch.local_addr(i)
                                    } else {
                                        None
                                    };

                                    // Reject datagrams from new clients under
                                    // critical overload, or while the DP's
                                    // applied CP configuration is stale beyond
                                    // its bound (issue #3726). Existing
                                    // sessions continue to be served, so
                                    // established flows drain while no new
                                    // source can start one under revoked
                                    // policy. `refuse_new_udp_sources` is
                                    // hoisted out of the batch: two relaxed
                                    // loads per batch, none per datagram.
                                    if refuse_new_udp_sources && !sessions.contains_key(&addr2) {
                                        continue;
                                    }

                                    // GRO splitting: if the kernel coalesced multiple same-size
                                    // datagrams into one buffer, split by segment size.
                                    if let Some(seg_size) = recv_batch.gro_segment_size(i) {
                                        let seg = seg_size as usize;
                                        if seg > 0 && data.len() > seg {
                                            let mut offset = 0;
                                            while offset < data.len() {
                                                let end = (offset + seg).min(data.len());
                                                let chunk = &data[offset..end];
                                                batch_dgrams_in += 1;
                                                batch_bytes_in += chunk.len() as u64;

                                                let result = process_datagram(
                                                    chunk,
                                                    addr2,
                                                    &proxy_id,
                                                    &proxy_namespace,
                                                    &request_epoch,
                                                    &health_checker,
                                                    &dns_cache,
                                                    &frontend_socket,
                                                    &sessions,
                                                    &pending_sessions,
                                                    &metrics,
                                                    tls_no_verify,
                                                    tls_ca_bundle_path.as_deref(),
                                                    &backend_dtls_config_cache,
                                                    max_sessions,
                                                    &mut last_client,
                                                    &mut batch_dgrams_out,
                                                    &mut batch_bytes_out,
                                                    port,
                                                    &circuit_breaker_cache,
                                                    &crls,
                                                    sni_proxy_ids.as_deref(),
                                                    &adaptive_buffer,
                                                    udp_gso_enabled,
                                                    local2,
                                                    &shutdown_rx,
                                                    global_shutdown_rx.as_ref(),
                                                    &overload,
                                                    &mesh_outbound_enforcement,
                                                    datagram_client_address.as_ref(),
                                                )
                                                .await;
                                                if let Err(e) = result {
                                                    debug!(proxy_id = %proxy_id, client = %addr2, "UDP forward error: {}", e);
                                                }
                                                offset = end;
                                            }
                                            continue; // already counted per-segment
                                        }
                                    }

                                    // Non-GRO path (single datagram).
                                    batch_dgrams_in += 1;
                                    batch_bytes_in += data.len() as u64;

                                    let result = process_datagram(
                                        data,
                                        addr2,
                                        &proxy_id,
                                        &proxy_namespace,
                                        &request_epoch,
                                        &health_checker,
                                        &dns_cache,
                                        &frontend_socket,
                                        &sessions,
                                        &pending_sessions,
                                        &metrics,
                                        tls_no_verify,
                                        tls_ca_bundle_path.as_deref(),
                                        &backend_dtls_config_cache,
                                        max_sessions,
                                        &mut last_client,
                                        &mut batch_dgrams_out,
                                        &mut batch_bytes_out,
                                        port,
                                        &circuit_breaker_cache,
                                        &crls,
                                        sni_proxy_ids.as_deref(),
                                        &adaptive_buffer,
                                        udp_gso_enabled,
                                        local2,
                                        &shutdown_rx,
                                        global_shutdown_rx.as_ref(),
                                        &overload,
                                        &mesh_outbound_enforcement,
                                        datagram_client_address.as_ref(),
                                    )
                                    .await;
                                    if let Err(e) = result {
                                        debug!(proxy_id = %proxy_id, client = %addr2, "UDP forward error: {}", e);
                                    }
                                }
                                total_drained += n;
                            }
                            _ => break 'drain, // WouldBlock or error — socket drained
                        }
                    }
                }

                #[cfg(not(target_os = "linux"))]
                {
                    // One admission decision per batch: overload shedding and
                    // the #3726 stale-configuration fence are both process-level
                    // relaxed atomics, so reading them once here keeps the
                    // per-datagram cost at zero extra loads.
                    let refuse_new_udp_sources = refuse_new_udp_source(&overload);

                    for _ in 0..batch_limit {
                        match frontend_socket.try_recv_from(&mut buf) {
                            Ok((len2, addr2)) => {
                                // Reject datagrams from new clients under
                                // critical overload, or while the applied CP
                                // configuration is stale beyond its bound
                                // (issue #3726). Existing sessions drain.
                                if refuse_new_udp_sources && !sessions.contains_key(&addr2) {
                                    continue;
                                }

                                batch_dgrams_in += 1;
                                batch_bytes_in += len2 as u64;

                                let result = process_datagram(
                                    &buf[..len2],
                                    addr2,
                                    &proxy_id,
                                    &proxy_namespace,
                                    &request_epoch,
                                    &health_checker,
                                    &dns_cache,
                                    &frontend_socket,
                                    &sessions,
                                    &pending_sessions,
                                    &metrics,
                                    tls_no_verify,
                                    tls_ca_bundle_path.as_deref(),
                                    &backend_dtls_config_cache,
                                    max_sessions,
                                    &mut last_client,
                                    &mut batch_dgrams_out,
                                    &mut batch_bytes_out,
                                    port,
                                    &circuit_breaker_cache,
                                    &crls,
                                    sni_proxy_ids.as_deref(),
                                    &adaptive_buffer,
                                    udp_gso_enabled,
                                    None,
                                    &shutdown_rx,
                                    global_shutdown_rx.as_ref(),
                                    &overload,
                                    &mesh_outbound_enforcement,
                                    datagram_client_address.as_ref(),
                                )
                                .await;
                                if let Err(e) = result {
                                    debug!(proxy_id = %proxy_id, client = %addr2, "UDP forward error: {}", e);
                                }
                            }
                            Err(_) => break, // WouldBlock — socket drained
                        }
                    }
                }

                // Record batch cycle for adaptive batch limit tuning.
                adaptive_buffer.record_batch_cycle(&proxy_namespace, &proxy_id, batch_dgrams_in);

                // Flush batched metrics to atomics once.
                metrics.datagrams_in.fetch_add(batch_dgrams_in, Ordering::Relaxed);
                metrics.bytes_in.fetch_add(batch_bytes_in, Ordering::Relaxed);
                metrics.datagrams_out.fetch_add(batch_dgrams_out, Ordering::Relaxed);
                metrics.bytes_out.fetch_add(batch_bytes_out, Ordering::Relaxed);
            }
            _ = shutdown_rx.changed() => {
                info!(proxy_id = %proxy_id, "UDP proxy listener shutting down on port {}", port);
                return Ok(());
            }
            _ = async {
                match global_shutdown_rx.as_mut() {
                    Some(rx) => { let _ = rx.changed().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                info!(proxy_id = %proxy_id, "UDP proxy listener shutting down on port {} (global SIGTERM)", port);
                return Ok(());
            }
        }
    }
}

/// Process a single datagram: resolve session, forward to backend, update batch counters.
///
/// Uses `last_client` as a hot-path cache to avoid DashMap lookups when consecutive
/// datagrams arrive from the same client address.
#[allow(clippy::too_many_arguments)]
async fn process_datagram(
    data: &[u8],
    client_addr: SocketAddr,
    proxy_id: &str,
    proxy_namespace: &str,
    request_epoch: &Arc<RequestEpochStore>,
    health_checker: &Arc<HealthChecker>,
    dns_cache: &DnsCache,
    frontend_socket: &Arc<UdpSocket>,
    sessions: &SessionMap,
    pending_sessions: &PendingSessionMap,
    metrics: &Arc<UdpProxyMetrics>,
    tls_no_verify: bool,
    tls_ca_bundle_path: Option<&str>,
    backend_dtls_config_cache: &BackendDtlsConfigCache,
    max_sessions: usize,
    last_client: &mut Option<(SocketAddr, Arc<UdpSession>)>,
    batch_dgrams_out: &mut u64,
    batch_bytes_out: &mut u64,
    listen_port: u16,
    circuit_breaker_cache: &Arc<CircuitBreakerCache>,
    crls: &crate::tls::CrlList,
    sni_proxy_ids: Option<&[NamespacedResourceId]>,
    adaptive_buffer: &Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    udp_gso_enabled: bool,
    local_addr: Option<crate::socket_opts::PktinfoLocal>,
    listener_shutdown: &watch::Receiver<bool>,
    global_shutdown: Option<&watch::Receiver<bool>>,
    overload: &Arc<crate::overload::OverloadState>,
    mesh_outbound_enforcement:
        &crate::modes::mesh::outbound_enforcement::SharedMeshOutboundEnforcement,
    datagram_client_address: Option<&Arc<DatagramClientAddressGate>>,
) -> Result<(), anyhow::Error> {
    // Client-address metadata boundary (issue #3289). When the listener runs
    // the gate, the envelope is stripped here — once, before any session
    // lookup, queueing, plugin hook, or backend forward — so no later stage can
    // observe a datagram that failed to authenticate, and no payload byte is
    // forwarded still wrapped. When the gate is off, `data` and the socket peer
    // pass through exactly as before.
    let (data, identity) = match datagram_client_address {
        None => (data, DatagramClientIdentity::direct(client_addr)),
        Some(gate) => match gate.decode(data, &client_addr) {
            Ok(decoded) => (
                decoded.payload,
                DatagramClientIdentity {
                    socket_peer: client_addr,
                    forwarded: decoded.forwarded,
                },
            ),
            Err(error) => {
                record_client_address_metadata_drop(
                    metrics,
                    proxy_id,
                    listen_port,
                    client_addr,
                    &error,
                );
                return Ok(());
            }
        },
    };

    if let Some(mut pending) = pending_sessions.get_mut(&client_addr) {
        // A follow-up datagram must belong to the same client the in-flight
        // setup was started for. Queueing a different forwarded client here
        // would hand its payload to a session admitted under another identity.
        if pending.forwarded_client != identity.forwarded {
            drop(pending);
            record_client_address_metadata_drop(
                metrics,
                proxy_id,
                listen_port,
                client_addr,
                &DatagramMetadataError::ForwardedClientChanged,
            );
            return Ok(());
        }
        // Session setup for this source is still in flight. Queue the
        // datagram (bounded) so opening flights spanning multiple datagrams
        // (QUIC Initial + 0-RTT, multi-record DTLS ClientHello) survive setup
        // instead of being dropped; the setup task drains the queue in
        // arrival order before releasing the gate. Beyond the caps we
        // tail-drop, preserving the pending gate's flood-resistance bound.
        let _ = pending.push_bounded(data);
        return Ok(());
    }

    // Fast path: check last-client cache before hitting DashMap.
    // Skip (and clear) the cache when the cached session has been flagged
    // expired by the idle-cleanup task — that path removes the session from
    // the map but the recv-loop's `Arc` keeps it alive, so without clearing
    // we'd pin the backend socket/session on a quiet listener and keep
    // forwarding through a session the cleanup task already declared dead.
    let existing_session =
        take_udp_last_client_if_live(last_client, client_addr, |cached_session| {
            cached_session
                .expired
                .load(std::sync::atomic::Ordering::Acquire)
        })
        .or_else(|| {
            sessions
                .get(&client_addr)
                .map(|entry| entry.value().clone())
        });

    let Some(session) = existing_session else {
        // Cheap flood shield: when the active-session cap is already full, drop a
        // new-source datagram before creating a pending gate, spawning setup, or
        // running first-datagram plugin + mesh checks — the post-admission
        // `reserve_udp_session_slot` would reject it anyway. This is a
        // non-consuming read (no slot reserved), so admitted flows still reserve
        // their slot after passing policy. Without it, a spoofed-source flood
        // against a maxed-out listener would spawn tasks and execute policy
        // hooks for traffic certain to be dropped.
        if udp_active_session_cap_reached(metrics, max_sessions) {
            return Err(anyhow::anyhow!(
                "UDP session limit reached ({}), dropping datagram",
                max_sessions
            ));
        }
        if !try_insert_pending_session_gate(
            pending_sessions,
            client_addr,
            max_sessions,
            identity.forwarded,
        )? {
            // Defensive: a gate appeared after the check at the top of this
            // function (not expected — the recv loop is a single task). Treat
            // this datagram as a follow-up for the in-flight setup, subject to
            // the same forwarded-client agreement as the ordinary queue path.
            if let Some(mut pending) = pending_sessions.get_mut(&client_addr) {
                if pending.forwarded_client == identity.forwarded {
                    let _ = pending.push_bounded(data);
                } else {
                    drop(pending);
                    record_client_address_metadata_drop(
                        metrics,
                        proxy_id,
                        listen_port,
                        client_addr,
                        &DatagramMetadataError::ForwardedClientChanged,
                    );
                }
            }
            return Ok(());
        }
        spawn_new_session_datagram(
            data.to_vec(),
            identity,
            proxy_id.to_string(),
            proxy_namespace.to_string(),
            Arc::clone(request_epoch),
            Arc::clone(health_checker),
            dns_cache.clone(),
            Arc::clone(frontend_socket),
            Arc::clone(sessions),
            Arc::clone(pending_sessions),
            Arc::clone(metrics),
            tls_no_verify,
            tls_ca_bundle_path.map(str::to_owned),
            Arc::clone(backend_dtls_config_cache),
            listen_port,
            Arc::clone(circuit_breaker_cache),
            Arc::clone(crls),
            sni_proxy_ids.map(|ids| ids.to_vec()),
            Arc::clone(adaptive_buffer),
            udp_gso_enabled,
            local_addr,
            listener_shutdown.clone(),
            global_shutdown.cloned(),
            Arc::clone(overload),
            Arc::clone(mesh_outbound_enforcement),
            max_sessions,
        );
        return Ok(());
    };

    // The established session was admitted under one authenticated client. A
    // datagram from the same socket peer asserting a different one is refused:
    // forwarding it would attribute another client's traffic to this session's
    // identity for authz, rate limits, and audit.
    if !identity.matches_session(session.forwarded_client) {
        record_client_address_metadata_drop(
            metrics,
            proxy_id,
            listen_port,
            client_addr,
            &DatagramMetadataError::ForwardedClientChanged,
        );
        return Ok(());
    }

    if !session.datagram_plugins.is_empty() {
        // Decouple potentially I/O-bound `on_udp_datagram` hooks from the
        // shared listener recv/drain loop: enqueue onto this session's
        // bounded ingress worker (fail closed on overload). Per-session
        // FIFO preserves client ordering without one task per datagram.
        if let Some(la) = local_addr {
            let _ = session.local_addr.set(la);
        }
        *last_client = Some((client_addr, session.clone()));
        let _ = enqueue_session_hook_datagram(&session, data, metrics);
        return Ok(());
    }

    // Record the per-datagram local (destination) address on the session the
    // first time the kernel exposes one. `OnceLock::set` is a no-op if already
    // set, so this is cheap on subsequent datagrams.
    if let Some(la) = local_addr {
        let _ = session.local_addr.set(la);
    }

    // Update cache for next datagram.
    *last_client = Some((client_addr, session.clone()));

    forward_client_datagram_to_backend(&session, data).await?;
    *batch_dgrams_out += 1;
    *batch_bytes_out += data.len() as u64;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_new_session_datagram(
    data: Vec<u8>,
    // Socket peer plus the authenticated forwarded client, when the listener
    // runs the datagram client-address gate.
    identity: DatagramClientIdentity,
    proxy_id: String,
    proxy_namespace: String,
    request_epoch: Arc<RequestEpochStore>,
    health_checker: Arc<HealthChecker>,
    dns_cache: DnsCache,
    frontend_socket: Arc<UdpSocket>,
    sessions: SessionMap,
    pending_sessions: PendingSessionMap,
    metrics: Arc<UdpProxyMetrics>,
    tls_no_verify: bool,
    tls_ca_bundle_path: Option<String>,
    backend_dtls_config_cache: BackendDtlsConfigCache,
    listen_port: u16,
    circuit_breaker_cache: Arc<CircuitBreakerCache>,
    crls: crate::tls::CrlList,
    sni_proxy_ids: Option<Vec<NamespacedResourceId>>,
    adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    udp_gso_enabled: bool,
    local_addr: Option<crate::socket_opts::PktinfoLocal>,
    listener_shutdown: watch::Receiver<bool>,
    global_shutdown: Option<watch::Receiver<bool>>,
    overload: Arc<crate::overload::OverloadState>,
    mesh_outbound_enforcement:
        crate::modes::mesh::outbound_enforcement::SharedMeshOutboundEnforcement,
    max_sessions: usize,
) {
    let client_addr = identity.socket_peer;
    tokio::spawn(async move {
        // The gate removes the pending entry (dropping any queued follow-up
        // datagrams wholesale) on every path that doesn't complete the
        // queue-drain handoff; the success path removes the entry atomically
        // inside `take_pending_datagrams` and disarms the gate.
        let gate = PendingSessionGate {
            pending_sessions: Arc::clone(&pending_sessions),
            client_addr,
            armed: true,
        };
        let result = process_new_session_datagram(
            data,
            identity,
            &proxy_id,
            &proxy_namespace,
            &request_epoch,
            &health_checker,
            &dns_cache,
            &frontend_socket,
            &sessions,
            &pending_sessions,
            &metrics,
            tls_no_verify,
            tls_ca_bundle_path.as_deref(),
            &backend_dtls_config_cache,
            listen_port,
            &circuit_breaker_cache,
            &crls,
            sni_proxy_ids.as_deref(),
            &adaptive_buffer,
            udp_gso_enabled,
            local_addr,
            &listener_shutdown,
            global_shutdown.as_ref(),
            &overload,
            &mesh_outbound_enforcement,
            max_sessions,
            gate,
        )
        .await;
        if let Err(e) = result {
            if is_client_or_policy_udp_setup_drop(&e) {
                debug!(
                    proxy_id = %proxy_id,
                    client = %udp_client_log_addr(client_addr),
                    listen_port = listen_port,
                    error = %e,
                    "UDP session setup dropped client datagram"
                );
            } else {
                warn!(
                    proxy_id = %proxy_id,
                    client = %udp_client_log_addr(client_addr),
                    listen_port = listen_port,
                    error = %e,
                    "UDP session setup or initial forward failed"
                );
            }
        }
    });
}

fn is_client_or_policy_udp_setup_drop(error: &anyhow::Error) -> bool {
    if let Some(setup_error) = find_stream_setup_error(error)
        && setup_error.kind.is_client_side()
    {
        return true;
    }

    let message = error.to_string();
    message.starts_with("Dropping DTLS continuation fragment")
        || message.starts_with("No matching passthrough proxy for SNI")
        || message.starts_with("UDP session limit reached")
}

#[allow(clippy::too_many_arguments)]
async fn process_new_session_datagram(
    data: Vec<u8>,
    identity: DatagramClientIdentity,
    proxy_id: &str,
    proxy_namespace: &str,
    request_epoch: &RequestEpochStore,
    health_checker: &HealthChecker,
    dns_cache: &DnsCache,
    frontend_socket: &Arc<UdpSocket>,
    sessions: &SessionMap,
    pending_sessions: &PendingSessionMap,
    metrics: &Arc<UdpProxyMetrics>,
    tls_no_verify: bool,
    tls_ca_bundle_path: Option<&str>,
    backend_dtls_config_cache: &BackendDtlsConfigCache,
    listen_port: u16,
    circuit_breaker_cache: &CircuitBreakerCache,
    crls: &crate::tls::CrlList,
    sni_proxy_ids: Option<&[NamespacedResourceId]>,
    adaptive_buffer: &Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    udp_gso_enabled: bool,
    local_addr: Option<crate::socket_opts::PktinfoLocal>,
    listener_shutdown: &watch::Receiver<bool>,
    global_shutdown: Option<&watch::Receiver<bool>>,
    overload: &Arc<crate::overload::OverloadState>,
    mesh_outbound_enforcement:
        &crate::modes::mesh::outbound_enforcement::SharedMeshOutboundEnforcement,
    max_sessions: usize,
    mut gate: PendingSessionGate,
) -> Result<(), anyhow::Error> {
    let client_addr = identity.socket_peer;
    if sessions.contains_key(&client_addr) {
        return Ok(());
    }

    // Anchor the finite authenticated-stream fallback maximum ONCE, here: the
    // instant this source's first datagram entered session admission, before
    // the epoch resolve, the mesh egress decision, and the `on_stream_connect`
    // chain (issue #3816). Anchoring after that chain — the shape the DTLS
    // accept path uses, where the accept itself is the admission instant —
    // would let a deliberately slow stream-connect plugin buy the admitted
    // session extra authorized lifetime. The published maximum is read once on
    // the same seam so a mid-setup reload cannot move this session's bound.
    let auth_anchor = tokio::time::Instant::now();
    let auth_max_lifetime_seconds =
        crate::proxy::auth_lifetime::authenticated_stream_max_lifetime_seconds();

    let epoch = request_epoch.load();
    let view = resolve_udp_session_epoch_view(
        proxy_id,
        proxy_namespace,
        &epoch,
        &data,
        sni_proxy_ids,
        listen_port,
    )?;
    let mesh_enforcement_snapshot = mesh_outbound_enforcement.load_full();
    let mut preselected_backend_target = None;
    if let Some(enforcement) = mesh_enforcement_snapshot.as_ref() {
        use crate::modes::mesh::outbound_enforcement::{Decision, PROTOCOL_UDP, PROTOCOL_UDP_DTLS};
        // Hash on the resolved client so backend stickiness follows the real
        // client rather than the load balancer's socket address.
        let lb_hash_key = udp_lb_hash_key_for_client_ip(identity.resolved().ip());
        let (backend_host, backend_port) = resolve_backend_target(
            &view.proxy,
            &epoch.load_balancer,
            health_checker,
            &lb_hash_key,
        )?;
        preselected_backend_target = Some((backend_host.clone(), backend_port));
        let protocol_label = if matches!(view.proxy.effective_scheme(), BackendScheme::Dtls) {
            PROTOCOL_UDP_DTLS
        } else {
            PROTOCOL_UDP
        };
        match enforcement.check_destination(listen_port, &backend_host, backend_port) {
            Decision::Admit => {
                enforcement.record_stream_decision(protocol_label, Decision::Admit);
            }
            Decision::Deny => {
                enforcement.record_stream_decision(protocol_label, Decision::Deny);
                // Same canonical principal the session identity and rate-limit
                // keys use, so a dropped datagram is attributable to the client
                // those keys name (GHSA-vjwj-657f-5w9g).
                let peer_ip = crate::util::client_identity::canonical_ip(identity.resolved().ip());
                warn!(
                    proxy_id = %view.proxy.id,
                    client = %peer_ip,
                    listen_port = listen_port,
                    backend_host = %backend_host,
                    backend_port = backend_port,
                    protocol = protocol_label,
                    "Mesh REGISTRY_ONLY: dropping UDP datagram to unadmitted destination"
                );
                return Ok(());
            }
            Decision::Skip => {}
        }
    }

    // Admit the session before running datagram hooks. Some hooks (notably
    // fault injection) may deliberately retain work for an extended period;
    // unauthenticated clients must not be able to consume that bounded work
    // budget or remain in the pending-session map while stream policy will
    // ultimately reject them.
    let stream_ctx = admit_plain_udp_stream(&epoch, &view, identity, listen_port).await?;

    // Effective authorization lifetime for the admitted plain-UDP session
    // (issue #3816). `on_stream_connect` runs once, at admission, and is never
    // repeated — an `on_stream_connect` plugin that identified a consumer or
    // an external identity (including a custom or future stream-auth plugin)
    // would otherwise create an indefinitely authorized UDP session. Earliest
    // of the accepted credential's own deadline and the finite
    // authenticated-stream maximum, anchored above and never refreshed by
    // relayed datagrams. `None` for an unauthenticated session, which this
    // contract does not bound and whose behavior is unchanged.
    let auth_deadline = crate::proxy::auth_lifetime::effective_stream_auth_deadline(
        stream_ctx.is_authenticated(),
        stream_ctx.credential_deadline_at(),
        auth_anchor,
        auth_max_lifetime_seconds,
    );
    // Once-only settlement shared by every phase below and by the established
    // session's two directions, so a session is counted and stamped exactly
    // once whichever phase observes the expiry first.
    let auth_latch = crate::proxy::auth_lifetime::StreamAuthTerminationLatch::default();

    // Bind the flow's datagram hooks to the decisions the admission chain just
    // memoized. Evaluated once here; every datagram of this session — starting
    // with this one — consumes the resulting list without re-evaluating a
    // predicate (issue #3734).
    let admitted_datagram_plugins = crate::plugins::admitted_datagram_plugins(
        &view.datagram_plugins,
        &stream_ctx.plugin_trigger_decisions(),
    );

    let first_datagram_metadata =
        std::sync::Mutex::new(std::collections::HashMap::<String, String>::new());
    // The first-datagram policy hooks are post-admission awaitable setup: a
    // deliberately slow `on_udp_datagram` hook must not carry this session past
    // the credential that admitted it. No circuit-breaker probe has been
    // claimed yet, so there is nothing to release on expiry.
    let first_datagram_allowed = stream_udp_setup_stage_under_authorization(
        auth_deadline,
        &auth_latch,
        &first_datagram_metadata,
        UDP_SESSION_SETUP_CONTEXT,
        || {},
        || {
            udp_datagram_allowed(
                &admitted_datagram_plugins,
                udp_session_client_ip(identity.resolved()),
                Arc::from(view.proxy.id.as_str()),
                view.proxy.name.as_deref().map(Arc::from),
                listen_port,
                &data,
                if view.proxy.passthrough {
                    StreamBytesKind::EncryptedWire
                } else {
                    StreamBytesKind::PlaintextWire
                },
                UdpDatagramDirection::ClientToBackend,
                Some(UdpMetadataSink::new(&first_datagram_metadata)),
            )
        },
    )
    .await?;
    if !first_datagram_allowed {
        return Ok(());
    }

    let mut reservation = reserve_udp_session_slot(metrics, max_sessions)?;

    let session = create_session(
        &epoch,
        view,
        dns_cache,
        frontend_socket,
        identity,
        sessions,
        metrics,
        tls_no_verify,
        tls_ca_bundle_path,
        backend_dtls_config_cache,
        listen_port,
        circuit_breaker_cache,
        crls,
        &data,
        adaptive_buffer,
        udp_gso_enabled,
        listener_shutdown,
        global_shutdown,
        overload,
        health_checker,
        preselected_backend_target,
        admitted_datagram_plugins,
        stream_ctx,
        auth_deadline,
        &auth_latch,
        &first_datagram_metadata,
    )
    .await?;
    reservation.disarm();

    let seed = first_datagram_metadata
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !seed.is_empty() {
        let mut session_meta = session
            .metadata
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (key, value) in seed {
            session_meta.entry(key).or_insert(value);
        }
    }

    if let Some(la) = local_addr {
        let _ = session.local_addr.set(la);
    }

    forward_client_datagram_to_backend(&session, &data).await?;
    metrics.datagrams_out.fetch_add(1, Ordering::Relaxed);
    metrics
        .bytes_out
        .fetch_add(data.len() as u64, Ordering::Relaxed);

    // Drain follow-up datagrams that arrived while setup ran, in arrival
    // order, then atomically remove the pending gate. Each drained datagram
    // goes through the same per-datagram plugin hooks and debug-level
    // packet-error handling as the established-session path.
    'drain: while let Some(batch) = take_pending_datagrams(pending_sessions, client_addr) {
        for dgram in batch {
            // Stop the drain the moment the admitted credential stops
            // authorizing this session: no further hook runs and no further
            // backend datagram is produced for this source. The forward below
            // would refuse anyway; breaking here also keeps a slow
            // `on_udp_datagram` hook from running post-expiry. The gate entry
            // was already removed under the shard lock by
            // `take_pending_datagrams`, so `gate.disarm()` below is still
            // correct on this path.
            if session.refuse_if_authorization_expired().is_some() {
                break 'drain;
            }
            if !udp_datagram_allowed(
                &session.datagram_plugins,
                Arc::clone(&session.datagram_client_ip),
                Arc::clone(&session.datagram_proxy_id),
                session.datagram_proxy_name.clone(),
                session.listen_port,
                &dgram,
                session.datagram_payload_kind,
                UdpDatagramDirection::ClientToBackend,
                Some(UdpMetadataSink::new(&session.metadata)),
            )
            .await
            {
                continue;
            }
            if let Err(e) = forward_client_datagram_to_backend(&session, &dgram).await {
                debug!(
                    proxy_id = %session.datagram_proxy_id,
                    client = %udp_client_log_addr(client_addr),
                    listen_port = session.listen_port,
                    error = %e,
                    "UDP pending datagram forward error"
                );
                continue;
            }
            metrics.datagrams_out.fetch_add(1, Ordering::Relaxed);
            metrics
                .bytes_out
                .fetch_add(dgram.len() as u64, Ordering::Relaxed);
        }
    }
    // `take_pending_datagrams` removed the gate entry under the shard lock;
    // disarm so Drop doesn't double-remove (harmless, but explicit).
    gate.disarm();
    Ok(())
}

async fn forward_client_datagram_to_backend(
    session: &Arc<UdpSession>,
    data: &[u8],
) -> Result<(), anyhow::Error> {
    let send = async {
        if let Some(ref dtls) = session.dtls_conn {
            dtls.send(data)
                .await
                .map(|()| data.len())
                .map_err(|e| std::io::Error::other(e.to_string()))
        } else if let Some(ref sock) = session.backend_socket {
            sock.send(data).await
        } else {
            Err(std::io::Error::other("no backend socket available"))
        }
    };
    forward_client_datagram_commit(session, data, send).await
}

/// Authorization-aware client→backend datagram commit (issue #3816 / #3820).
///
/// The pre-send `refuse_if_authorization_expired` check still refuses an
/// already-elapsed plan before any amplification budget is published. The
/// gateway-owned send itself is then raced through
/// [`udp_frontend_send_until_expiry`]: a socket parked on writability cannot
/// commit after the absolute deadline, an already-elapsed plan never polls
/// `send`, and an exact-deadline tie is expiry-first. Settlement goes through
/// the session latch and reply-task wake exactly once — never as hook-ingress
/// overload or a backend health failure.
///
/// Unauthenticated sessions (`authorization == None`) take the `Option`
/// discriminant only: no extra clock read, lock, allocation, or timer beyond
/// that existing gate.
///
/// `send` is the production backend send, or a parked test future that stands
/// in for a socket waiting on writability.
async fn forward_client_datagram_commit<F>(
    session: &Arc<UdpSession>,
    data: &[u8],
    send: F,
) -> Result<(), anyhow::Error>
where
    F: std::future::Future<Output = Result<usize, std::io::Error>>,
{
    // Authorization-lifetime gate for the client→backend direction (issue
    // #3816). Placed ahead of the amplification-budget publish and the backend
    // send so an expired credential moves no gateway state and produces no
    // backend datagram. An already-elapsed deadline refuses THIS datagram
    // immediately rather than waiting for the reply task's timer arm to be
    // scheduled.
    //
    // Cost on the datagram hot path: one `Option` discriminant test for an
    // unauthenticated session (no clock read, no lock, no allocation, no timer)
    // and one additional monotonic instant comparison for an authenticated one.
    if session.refuse_if_authorization_expired().is_some() {
        return Err(udp_authorization_expired_error());
    }

    // Publish the response budget before the send. In particular, a loopback
    // backend can receive and answer between the send syscall and this task
    // being polled again; publishing only after send completion lets that first
    // response bypass the amplification guard. A failed send still leaves a
    // conservative budget based on bytes accepted from the client.
    publish_session_request_budget(session, data.len() as u64);

    let plan = session
        .authorization
        .as_ref()
        .map(|authorization| authorization.plan);
    match udp_frontend_send_until_expiry(plan, send).await {
        UdpFrontendSendOutcome::AuthorizationExpired(_) => {
            // Settle through the existing session latch and wake the reply task
            // exactly once. A parked send that lost the race is dropped, so it
            // cannot complete afterwards.
            let _ = session.refuse_if_authorization_expired();
            Err(udp_authorization_expired_error())
        }
        UdpFrontendSendOutcome::Sent(Ok(_)) => {
            session
                .last_activity
                .store(coarse_epoch_millis(), Ordering::Relaxed);
            session
                .bytes_sent
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            Ok(())
        }
        UdpFrontendSendOutcome::Sent(Err(e)) if e.to_string() == "no backend socket available" => {
            Err(anyhow::anyhow!("no backend socket available"))
        }
        UdpFrontendSendOutcome::Sent(Err(e)) => {
            Err(anyhow::anyhow!("send to backend failed: {}", e))
        }
    }
}

/// Spawn a background task that periodically removes idle UDP sessions.
#[allow(clippy::too_many_arguments)]
fn spawn_session_cleanup(
    sessions: SessionMap,
    metrics: Arc<UdpProxyMetrics>,
    proxy_id: String,
    mut shutdown: watch::Receiver<bool>,
    cleanup_interval_seconds: u64,
) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(cleanup_interval_seconds.max(1)));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = coarse_epoch_millis();
                    let mut expired: Vec<(SocketAddr, Arc<UdpSession>)> = Vec::new();

                    for entry in sessions.iter() {
                        let last = entry.value().last_activity.load(Ordering::Relaxed);
                        if udp_idle_expired(now, last, entry.value().idle_timeout_ms) {
                            // Capture the Arc so removal below is identity-aware:
                            // a session re-created at the same client address
                            // between this scan and the remove must NOT be
                            // evicted by us (it is a newer, still-live session).
                            expired.push((*entry.key(), entry.value().clone()));
                        }
                    }

                    for (addr, expired_session) in &expired {
                        if let Some((_, session)) =
                            sessions.remove_if(addr, |_, v| Arc::ptr_eq(v, expired_session))
                        {
                            // Mark the session expired BEFORE we let go of
                            // any reference. The recv-loop fast path may
                            // hold a `last_client` Arc to this session
                            // that survives the map removal; the flag is
                            // how that path notices it must re-create.
                            session
                                .expired
                                .store(true, std::sync::atomic::Ordering::Release);
                            // Close DTLS connection if active
                            if let Some(ref dtls) = session.dtls_conn {
                                let _ = dtls.close().await;
                            }
                            // Signal plain-UDP backend reply tasks to stop even
                            // when no backend datagram arrives to wake recv().
                            // notify_one stores a permit so the wakeup cannot be
                            // lost if the reply task has not registered yet.
                            signal_udp_reply_task_stop(
                                &session.stop_reply_task,
                                session.stop_notify.as_ref(),
                            );
                            session.close_hook_ingress();
                            let bs = session.bytes_sent.load(Ordering::Relaxed);
                            let br = session.bytes_received.load(Ordering::Relaxed);
                            session.release_overload_guard();
                            metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                            debug!(
                                proxy_id = %proxy_id,
                                client = %addr,
                                bytes_sent = bs,
                                bytes_received = br,
                                "UDP session expired (idle timeout)"
                            );

                            emit_udp_stream_disconnect(
                                session.plugins.as_ref(),
                                UdpDisconnectContext {
                                    namespace: &session.proxy_namespace,
                                    proxy_id: &session.proxy_id,
                                    proxy_name: session.proxy_name.as_deref(),
                                    session: &session,
                                    backend_scheme: session.backend_scheme,
                                    listen_port: session.listen_port,
                                    disconnected_ms: now,
                                    disconnected_wall_at: chrono::Utc::now(),
                                    connection_error: None,
                                    error_class: None,
                                    disconnect_direction: None,
                                    disconnect_cause: Some(
                                        crate::plugins::DisconnectCause::IdleTimeout,
                                    ),
                                },
                            )
                            .await;
                        }
                    }
                }
                _ = shutdown.changed() => {
                    return;
                }
            }
        }
    });
}

/// Classify an unexpected DTLS recv-loop task exit for listener failure.
///
/// Any completion of the recv-loop task while the accept loop is still live is
/// an operational failure: graceful shutdown closes the server on a different
/// select arm and awaits the task there. `Ok(())` without that path means the
/// loop stopped without an operator/listener shutdown signal.
pub(crate) fn classify_dtls_recv_loop_exit(
    join_result: Result<Result<(), anyhow::Error>, tokio::task::JoinError>,
) -> anyhow::Error {
    match join_result {
        Ok(Ok(())) => {
            anyhow::anyhow!("DTLS server recv loop exited unexpectedly without error")
        }
        Ok(Err(err)) => err.context("DTLS server recv loop exited with error"),
        Err(join_err) if join_err.is_cancelled() => {
            anyhow::anyhow!("DTLS server recv loop was cancelled unexpectedly")
        }
        Err(join_err) if join_err.is_panic() => {
            anyhow::anyhow!("DTLS server recv loop panicked: {join_err}")
        }
        Err(join_err) => {
            anyhow::anyhow!("DTLS server recv loop failed to join: {join_err}")
        }
    }
}

/// Fail the DTLS frontend listener after an unexpected recv-loop exit.
///
/// Clears `started` so readiness cannot stay healthy while UDP demux has
/// stopped, then returns a contextual error for `StreamListenerManager`
/// async bind-failure / reconcile.
pub(crate) fn fail_dtls_listener_on_recv_loop_exit(
    started: &AtomicBool,
    join_result: Result<Result<(), anyhow::Error>, tokio::task::JoinError>,
) -> anyhow::Error {
    let err = classify_dtls_recv_loop_exit(join_result);
    error!(
        error = %err,
        "DTLS server recv loop exited unexpectedly; failing listener"
    );
    started.store(false, Ordering::Release);
    err
}

/// Supervise the DTLS recv-loop task against operator/global shutdown.
///
/// Production wires the same classification beside `server.accept()` in
/// [`start_dtls_frontend_listener`]. This seam lets external tests drive
/// panic/error/shutdown classification with synthetic tasks without a
/// production panic or socket fault injector.
#[allow(dead_code)] // Intentionally exposed via library `_test_support`; unused by the binary target.
pub(crate) async fn supervise_dtls_recv_loop_task(
    mut server_task: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    mut shutdown_rx: watch::Receiver<bool>,
    mut global_shutdown_rx: Option<watch::Receiver<bool>>,
    started: Arc<AtomicBool>,
    on_shutdown: impl FnOnce(),
) -> Result<(), anyhow::Error> {
    tokio::select! {
        join_result = &mut server_task => {
            Err(fail_dtls_listener_on_recv_loop_exit(&started, join_result))
        }
        _ = shutdown_rx.changed() => {
            on_shutdown();
            let _ = server_task.await;
            Ok(())
        }
        _ = async {
            match global_shutdown_rx.as_mut() {
                Some(rx) => {
                    let _ = rx.changed().await;
                }
                None => std::future::pending::<()>().await,
            }
        } => {
            on_shutdown();
            let _ = server_task.await;
            Ok(())
        }
    }
}

/// Start a DTLS frontend listener that accepts encrypted client connections.
///
/// Uses `DtlsServer` from the `dtls` module which demultiplexes incoming UDP
/// datagrams by source address and manages per-client DTLS 1.2/1.3 sessions.
/// Each accepted client (post-handshake) is handled in its own spawned task,
/// including epoch lookup and the full `on_stream_connect` admission chain so
/// a slow stream-connect plugin cannot stall the shared accept loop.
#[allow(clippy::too_many_arguments)]
async fn start_dtls_frontend_listener(
    port: u16,
    bind_addr: IpAddr,
    proxy_id: String,
    // Namespace owning `proxy_id`, carried from the listener's exact identity.
    proxy_namespace: String,
    dns_cache: DnsCache,
    request_epoch: Arc<RequestEpochStore>,
    health_checker: Arc<HealthChecker>,
    shutdown: watch::Receiver<bool>,
    global_shutdown: Option<watch::Receiver<bool>>,
    metrics: Arc<UdpProxyMetrics>,
    dtls_config: crate::dtls::FrontendDtlsConfig,
    dtls_server_tx: Option<tokio::sync::oneshot::Sender<Arc<crate::dtls::DtlsServer>>>,
    tls_no_verify: bool,
    tls_ca_bundle_path: Option<String>,
    max_sessions: usize,
    frontend_tls_handshake_timeout_seconds: u64,
    circuit_breaker_cache: Arc<CircuitBreakerCache>,
    crls: crate::tls::CrlList,
    started: Arc<AtomicBool>,
    overload: Arc<crate::overload::OverloadState>,
    backend_dtls_config_cache: BackendDtlsConfigCache,
    datagram_client_address: Option<Arc<DatagramClientAddressGate>>,
) -> Result<(), anyhow::Error> {
    let addr = SocketAddr::new(bind_addr, port);
    let admission_overload = overload.clone();
    let dtls_limits = crate::dtls::DtlsServerLimits {
        max_sessions: Some(max_sessions),
        handshake_timeout: (frontend_tls_handshake_timeout_seconds > 0)
            .then_some(Duration::from_secs(frontend_tls_handshake_timeout_seconds)),
        // Pre-allocation admission: refused before the server allocates any
        // association state. Covers critical overload AND the #3726 stale
        // last-known-good configuration fence, so a DP that can no longer be
        // told this listener or its policy was revoked stops admitting new
        // DTLS associations while established sessions drain.
        allow_new_session: Some(Arc::new(move || {
            !refuse_new_udp_source(&admission_overload)
        })),
        active_session_mirror: Some(metrics.dtls_demux_sessions.clone()),
        // Envelope validation happens inside the demux loop, ahead of any
        // per-peer allocation, so an unauthenticated datagram never reserves a
        // session slot.
        datagram_client_address,
        datagram_client_address_drops: Some(Arc::clone(&metrics.client_address_metadata_drops)),
        // Refusal diagnostics on the demux path name the same listener the
        // plain-UDP path's do. Built once here, never per datagram.
        datagram_client_address_listener: Some((Arc::from(proxy_id.as_str()), port)),
    };
    let server =
        Arc::new(crate::dtls::DtlsServer::bind_with_limits(addr, dtls_config, dtls_limits).await?);
    // Publish the live DTLS server handle so ordinary frontend DTLS live
    // reload (`publish_frontend_dtls_generation`) can call
    // `swap_frontend_config` on the same instance the recv loop is using.
    // Send-failure is benign: the receiver may have been dropped or the
    // manager may have moved on without wanting the handle.
    if let Some(tx) = dtls_server_tx {
        let _ = tx.send(server.clone());
    }
    ensure_coarse_timer_started();
    started.store(true, Ordering::Release);
    info!(proxy_id = %proxy_id, "DTLS frontend listener started on {}", addr);

    // Spawn the server's recv loop in a background task. The accept select
    // below supervises this handle (issue #3215): an unexpected exit must
    // fail the listener promptly rather than leaving `accept()` blocked with
    // `started` still true while no task reads UDP.
    let server_runner = server.clone();
    let mut server_task = tokio::spawn(async move { server_runner.run().await });

    let mut shutdown_rx = shutdown;
    // Optional gateway-wide shutdown — fires on SIGTERM/SIGINT regardless of
    // per-listener config-driven removal. Watch BOTH so the DTLS accept loop
    // exits promptly during graceful drain.
    let mut global_shutdown_rx = global_shutdown;

    loop {
        tokio::select! {
            result = server.accept() => {
                let (client_conn, client_addr) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(proxy_id = %proxy_id, "DTLS accept error: {}", e);
                        continue;
                    }
                };

                // Post-accept admission: `allow_new_session` is a soft
                // pre-allocation gate, so re-check the same predicate here —
                // critical overload or a stale applied configuration (#3726) —
                // and close any association that raced past it. Neither race
                // path may admit new work behind revoked policy.
                if refuse_new_udp_source(&overload) {
                    client_conn.close().await;
                    continue;
                }

                // Atomically reserve a session slot. Epoch lookup and the full
                // `on_stream_connect` admission chain run inside the per-client
                // task below (TCP accept-loop isolation parity) so a slow or
                // hung stream-connect plugin cannot stall `server.accept()`.
                let prev = metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
                if prev >= max_sessions as u64 {
                    metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                    warn!(
                        proxy_id = %proxy_id,
                        client = %udp_client_log_addr(client_addr),
                        "DTLS session limit reached ({}), rejecting connection",
                        max_sessions
                    );
                    client_conn.close().await;
                    continue;
                }

                // Spawn per-client handler. Epoch lookup + stream-connect
                // admission run inside the task (main's accept-loop isolation);
                // plugin-cache lookups use the namespace-qualified proxy key.
                let handler_proxy_id = proxy_id.clone();
                let handler_proxy_namespace = proxy_namespace.clone();
                let handler_request_epoch = Arc::clone(&request_epoch);
                let handler_health_checker = health_checker.clone();
                let handler_dns = dns_cache.clone();
                let handler_metrics = metrics.clone();
                let handler_cb_cache = circuit_breaker_cache.clone();
                let handler_crls = crls.clone();
                let handler_ca_bundle = tls_ca_bundle_path.clone();
                let handler_dtls_cache = backend_dtls_config_cache.clone();
                let handler_overload = overload.clone();
                // Monotonic session start for duration_ms; wall clock is only
                // for human-readable connect/disconnect timestamps. Captured
                // at accept so admission wait is included in the summary.
                let connected_mono = Instant::now();
                let connected_at = chrono::Utc::now();
                tokio::spawn(async move {
                    let epoch = handler_request_epoch.load();
                    let Some(proxy) = epoch
                        .proxy_by_namespaced_id(&handler_proxy_namespace, &handler_proxy_id)
                    else {
                        handler_metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                        client_conn.close().await;
                        warn!(
                            namespace = %handler_proxy_namespace,
                            proxy_id = %handler_proxy_id,
                            "DTLS listener proxy no longer exists in request epoch"
                        );
                        return;
                    };
                    // Extract the few fields needed for admission/logging
                    // without cloning the full Proxy (hot-path ownership).
                    let resolved_proxy_id = proxy.id.clone();
                    let proxy_name = proxy.name.clone();
                    let proxy_namespace = proxy.namespace.clone();
                    let backend_scheme = proxy.effective_scheme();
                    let plugins = epoch.plugin_cache.plugins_for_protocol(
                        &proxy_namespace,
                        &resolved_proxy_id,
                        ProxyProtocol::Udp,
                    );
                    let datagram_plugins: Arc<[Arc<dyn Plugin>]> = plugins
                        .iter()
                        .filter(|p| p.requires_udp_datagram_hooks())
                        .cloned()
                        .collect();
                    let consumer_index =
                        Arc::new(ConsumerIndex::from_inner(Arc::clone(&epoch.consumer_index)));
                    // `client_ip` (remote.ip) follows the authenticated
                    // forwarded client when the datagram client-address gate
                    // supplied one; `direct_client_ip` (source.ip) is always
                    // the socket peer. Without the gate both are the peer,
                    // which is the historical DTLS behavior.
                    let identity = DatagramClientIdentity {
                        socket_peer: client_addr,
                        forwarded: client_conn.forwarded_client_addr,
                    };
                    let client_ip = udp_session_client_ip(identity.resolved());

                    // Run on_stream_connect plugins (with DTLS client cert if available)
                    let stream_client_ip = client_ip.to_string();
                    let stream_direct_client_ip =
                        udp_session_client_ip(identity.socket_peer).to_string();
                    let mut stream_ctx = StreamConnectionContext::new(
                        stream_client_ip,
                        stream_direct_client_ip,
                        resolved_proxy_id.clone(),
                        proxy_name.clone(),
                        port,
                        backend_scheme,
                        consumer_index,
                    );
                    stream_ctx.frontend_transport =
                        crate::plugins::StreamFrontendTransport::Dtls;
                    stream_ctx.proxy_namespace = proxy_namespace.clone();
                    stream_ctx.proxy_lifecycle_generation = epoch
                        .plugin_cache
                        .proxy_lifecycle_generation(&proxy_namespace, &resolved_proxy_id);
                    stream_ctx.tls_client_cert_der = client_conn.tls_client_cert_der.clone();
                    stream_ctx.tls_client_cert_chain_der =
                        client_conn.tls_client_cert_chain_der.clone();
                    stream_ctx.sni_hostname = client_conn.sni_hostname.clone();
                    // The constructor intentionally leaves node-waypoint per-pod
                    // policy scope absent: UDP/DTLS cannot wire it without a new
                    // capture path. Identity is keyed by the per-connection socket
                    // cookie (`SO_COOKIE`), which node-agent eBPF stamps from
                    // the source pod via the `connect4`/`connect6` cgroup hooks;
                    // there are no UDP capture hooks, and a UDP stream proxy
                    // serves all clients from one shared frontend socket with a
                    // single cookie, so there is no per-source-pod cookie to
                    // resolve here. With `per_pod_policy_scoping` on
                    // (node-waypoint topology), `mesh_authz` stamps
                    // `mesh_authz.scope_missing` and, because the per-pod scope is
                    // always absent here, fails closed (rejects the stream, 403)
                    // when any namespace/selector-scoped policy is configured;
                    // with only mesh-wide policies it evaluates them normally.
                    // Per-pod scoped enforcement is unavailable for DTLS streams
                    // (TCP and HTTP/HBONE have it). See docs/mesh.md.
                    for plugin in plugins.iter() {
                        if let PluginResult::Reject { .. } =
                            plugin.on_stream_connect(&mut stream_ctx).await
                        {
                            debug!(
                                proxy_id = %handler_proxy_id,
                                client = %udp_client_log_addr(client_addr),
                                "DTLS connection rejected by plugin"
                            );
                            client_conn.close().await;
                            handler_metrics
                                .active_sessions
                                .fetch_sub(1, Ordering::Relaxed);
                            return;
                        }
                    }

                    handler_metrics.total_sessions.fetch_add(1, Ordering::Relaxed);

                    debug!(
                        proxy_id = %handler_proxy_id,
                        client = %udp_client_log_addr(client_addr),
                        "DTLS frontend connection accepted"
                    );

                    // Acquire the OverloadState connection guard for the accepted
                    // (post-handshake, post-admission) DTLS session. Pre-handshake
                    // demux peers are tracked separately in
                    // `metrics.dtls_demux_sessions` and via the
                    // `allow_new_session` callback; we intentionally only
                    // contribute to `OverloadState.active_connections` after the
                    // handshake completed and plugin checks passed, so the global
                    // counter reflects committed sessions (parity with TCP/H3).
                    // Drop at task exit decrements regardless of exit path.
                    let _overload_guard =
                        crate::overload::ConnectionGuard::new(&handler_overload);

                    let handler_has_plugins = !plugins.is_empty();
                    let handler_consumer_username = if handler_has_plugins {
                        stream_ctx.effective_identity().map(str::to_owned)
                    } else {
                        None
                    };
                    let handler_auth_method = stream_ctx.auth_method;
                    let handler_proxy_lifecycle_generation = stream_ctx.proxy_lifecycle_generation;
                    // Preserve the accepted connection's SNI across the session
                    // so disconnect summaries match `on_stream_connect`.
                    let handler_sni_hostname = stream_ctx.sni_hostname.clone();
                    // Opaque connect-time execution-trigger outcomes, carried to
                    // the disconnect summary so a skipped instance stays skipped.
                    let handler_trigger_decisions = stream_ctx.plugin_trigger_decisions();
                    // Bind this DTLS flow's datagram hooks to the same
                    // decisions, once, before any datagram hook runs. Every
                    // later datagram traverses the filtered list with no
                    // predicate re-evaluation (issue #3734).
                    let datagram_plugins = crate::plugins::admitted_datagram_plugins(
                        &datagram_plugins,
                        &handler_trigger_decisions,
                    );
                    let (handler_metadata, handler_correlation_ids) = if handler_has_plugins {
                        stream_ctx.take_metadata_with_correlation_ids()
                    } else {
                        Default::default()
                    };

                    // Authorization lifetime for the admitted DTLS session
                    // (issue #3816). `on_stream_connect` ran once at admission
                    // and is never repeated, so the session would otherwise
                    // outlive the certificate that admitted it. Earliest of the
                    // accepted credential's own deadline and the finite
                    // authenticated-stream maximum, anchored here and never
                    // refreshed by relayed datagrams. `None` for an
                    // unauthenticated session.
                    let handler_auth_max_lifetime =
                        crate::proxy::auth_lifetime::authenticated_stream_max_lifetime_seconds();
                    let handler_auth_deadline =
                        crate::proxy::auth_lifetime::effective_stream_auth_deadline(
                            stream_ctx.is_authenticated(),
                            stream_ctx.credential_deadline_at(),
                            tokio::time::Instant::now(),
                            handler_auth_max_lifetime,
                        );

                    let result = handle_dtls_client(
                        client_conn,
                        identity,
                        &resolved_proxy_id,
                        &proxy_namespace,
                        &epoch,
                        &handler_health_checker,
                        &handler_dns,
                        &handler_metrics,
                        tls_no_verify,
                        handler_ca_bundle.as_deref(),
                        &handler_cb_cache,
                        &datagram_plugins,
                        proxy_name.as_deref(),
                        port,
                        &handler_crls,
                        &handler_dtls_cache,
                        handler_auth_deadline,
                    )
                    .await;
                    let (err_msg, error_class, disconnect_cause, disconnect_direction) =
                        match &result.outcome {
                            Ok(()) => (
                                None,
                                None,
                                Some(crate::plugins::DisconnectCause::GracefulShutdown),
                                None,
                            ),
                            Err(e) => {
                                debug!(
                                    proxy_id = %resolved_proxy_id,
                                    client = %udp_client_log_addr(client_addr),
                                    "DTLS client session ended: {}",
                                    e
                                );
                                let error_message = e.to_string();
                                let err_class = dtls_error_class(e);
                                // handle_dtls_client_inner can fail on
                                // backend-side setup (DNS, backend UDP bind,
                                // backend DTLS handshake) as well as
                                // client-side session errors. The typed
                                // `StreamSetupError` (when present) drives
                                // both cause and direction; otherwise we fall
                                // back to error-class inference.
                                let cause = dtls_disconnect_cause(e, &err_class);
                                let direction = dtls_disconnect_direction(e, &err_class);
                                (
                                    Some(error_message),
                                    Some(err_class),
                                    Some(cause),
                                    Some(direction),
                                )
                            }
                        };

                    if !plugins.is_empty() || error_class.is_some() {
                        let duration_ms = connected_mono.elapsed().as_millis() as f64;
                        let disconnected_at = chrono::Utc::now();
                        // Merge per-datagram WAF metadata recorded during
                        // forwarding with any on_stream_connect metadata so DTLS
                        // hits ride the transaction summary by default.
                        let mut merged_metadata = handler_metadata;
                        merged_metadata.extend(result.metadata);
                        let summary = build_dtls_stream_summary(DtlsDisconnectContext {
                            namespace: &proxy_namespace,
                            proxy_id: &resolved_proxy_id,
                            proxy_name: proxy_name.as_deref(),
                            proxy_lifecycle_generation: handler_proxy_lifecycle_generation,
                            resolved_client: identity.resolved(),
                            consumer_username: handler_consumer_username.clone(),
                            auth_method: handler_auth_method,
                            backend_target: &result.backend.backend_target,
                            backend_resolved_ip: result.backend.backend_resolved_ip.as_deref(),
                            backend_scheme,
                            listen_port: port,
                            connected_at,
                            disconnected_at,
                            duration_ms,
                            bytes_sent: result.bytes_sent,
                            bytes_received: result.bytes_received,
                            connection_error: err_msg,
                            error_class,
                            disconnect_direction,
                            disconnect_cause,
                            sni_hostname: handler_sni_hostname.clone(),
                            metadata: &merged_metadata,
                            correlation_ids: &handler_correlation_ids,
                            plugin_trigger_decisions: handler_trigger_decisions,
                        });
                        crate::runtime_metrics::global_ref().record_stream_transaction(&summary);

                        // Fire on_stream_disconnect plugins
                        if !plugins.is_empty() {
                            for plugin in plugins.iter() {
                                plugin.on_stream_disconnect(&summary).await;
                            }
                        }
                    }

                    handler_metrics
                        .active_sessions
                        .fetch_sub(1, Ordering::Relaxed);
                });
            }
            join_result = &mut server_task => {
                // Recv loop terminated while accept was still live. Close so
                // any lingering accept waiters / sessions stop, clear started,
                // and return Err for StreamListenerManager reconcile.
                let err = fail_dtls_listener_on_recv_loop_exit(&started, join_result);
                server.close().await;
                return Err(err);
            }
            _ = shutdown_rx.changed() => {
                info!(proxy_id = %proxy_id, "DTLS frontend listener shutting down on port {}", port);
                server.close().await;
                let _ = server_task.await;
                return Ok(());
            }
            _ = async {
                match global_shutdown_rx.as_mut() {
                    Some(rx) => { let _ = rx.changed().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                info!(proxy_id = %proxy_id, "DTLS frontend listener shutting down on port {} (global SIGTERM)", port);
                server.close().await;
                let _ = server_task.await;
                return Ok(());
            }
        }
    }
}

/// Backend target info resolved during DTLS connection setup, available for logging
/// regardless of whether the connection succeeded or failed.
struct DtlsBackendInfo {
    /// The backend target hostname:port (e.g., "10.0.2.10:5353").
    backend_target: String,
    /// The DNS-resolved IP address, if resolution succeeded.
    backend_resolved_ip: Option<String>,
}

/// Result of a DTLS client handler: backend info (always present) plus the outcome.
struct DtlsHandlerResult {
    backend: DtlsBackendInfo,
    bytes_sent: u64,
    bytes_received: u64,
    /// Session metadata recorded by per-datagram hooks during forwarding (e.g.
    /// WAF `waf.*` signature hits), merged into the disconnect summary.
    metadata: std::collections::HashMap<String, String>,
    outcome: Result<(), anyhow::Error>,
}

/// Handle a single DTLS frontend client connection.
///
/// Reads decrypted datagrams from the client via the DTLS connection and forwards
/// them to the backend (plain UDP or backend DTLS). Backend replies are forwarded
/// back through the client's DTLS connection.
///
/// Always returns a `DtlsHandlerResult` containing backend info (for logging)
/// and the connection outcome, so even failed connections log which backend was attempted.
#[allow(clippy::too_many_arguments)]
async fn handle_dtls_client(
    client_conn: crate::dtls::DtlsServerConn,
    identity: DatagramClientIdentity,
    proxy_id: &str,
    proxy_namespace: &str,
    epoch: &RequestEpoch,
    health_checker: &HealthChecker,
    dns_cache: &DnsCache,
    metrics: &Arc<UdpProxyMetrics>,
    tls_no_verify: bool,
    tls_ca_bundle_path: Option<&str>,
    circuit_breaker_cache: &CircuitBreakerCache,
    datagram_plugins: &Arc<[Arc<dyn Plugin>]>,
    proxy_name: Option<&str>,
    listen_port: u16,
    crls: &crate::tls::CrlList,
    backend_dtls_config_cache: &BackendDtlsConfigCache,
    auth_deadline: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
) -> DtlsHandlerResult {
    let mut backend_info = DtlsBackendInfo {
        backend_target: String::new(),
        backend_resolved_ip: None,
    };
    let bytes_sent = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));
    let last_request_size = Arc::new(AtomicU64::new(0));
    let response_budget_remaining = Arc::new(AtomicU64::new(0));
    // Shared sink for per-datagram WAF metadata recorded by the forwarding tasks
    // inside `handle_dtls_client_inner`; drained into the disconnect summary
    // below so DTLS hits are observable by default (parity with plain UDP/TCP).
    let datagram_metadata = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let outcome = handle_dtls_client_inner(
        client_conn,
        identity,
        proxy_id,
        proxy_namespace,
        epoch,
        health_checker,
        dns_cache,
        metrics,
        tls_no_verify,
        tls_ca_bundle_path,
        circuit_breaker_cache,
        &mut backend_info,
        Arc::clone(&bytes_sent),
        Arc::clone(&bytes_received),
        Arc::clone(&last_request_size),
        Arc::clone(&response_budget_remaining),
        Arc::clone(&datagram_metadata),
        datagram_plugins,
        proxy_name,
        listen_port,
        crls,
        backend_dtls_config_cache,
        auth_deadline,
    )
    .await;
    DtlsHandlerResult {
        backend: backend_info,
        bytes_sent: bytes_sent.load(Ordering::Relaxed),
        bytes_received: bytes_received.load(Ordering::Relaxed),
        metadata: datagram_metadata
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone(),
        outcome,
    }
}

/// Legacy DTLS error-message prefix.
///
/// Now produced by [`StreamSetupKind::BackendDtlsHandshake`] via
/// [`StreamSetupError`]; the constant remains as a public-API surface for
/// log consumers and integration tests. New construction sites MUST use the
/// typed error wrapper. See [`crate::proxy::stream_error`] for the rationale.
pub(crate) const STREAM_ERR_BACKEND_DTLS_HANDSHAKE_FAILED: &str = "Backend DTLS handshake failed";

/// Error class for a DTLS session failure.
///
/// Typed markers first: the idle watchdog and the authorization-lifetime
/// terminator are both explicit types, so neither is inferred from message
/// text. Everything else falls back to the shared boxed-error classifier.
pub(crate) fn dtls_error_class(error: &anyhow::Error) -> crate::retry::ErrorClass {
    if is_udp_dtls_idle_timeout(error) {
        return crate::retry::ErrorClass::ReadWriteTimeout;
    }
    if is_dtls_authorization_expired(error) {
        // The same class the typed setup-phase `AuthorizationExpired` kind maps
        // to, so a policy expiry never reads as a transport or backend fault.
        return crate::retry::ErrorClass::RequestError;
    }
    crate::retry::classify_boxed_error(error.as_ref())
}

/// Map a DTLS session failure to a `DisconnectCause`.
///
/// **Typed-kind first.** When the chain carries a [`StreamSetupError`] (the
/// canonical wrapper at every DTLS construction site that previously used the
/// `STREAM_ERR_BACKEND_DTLS_HANDSHAKE_FAILED` prefix), its
/// [`StreamSetupKind`] is the authoritative signal and the error class is
/// only used as a backup for non-setup failures (raw recv errors, generic
/// I/O timeouts).
///
/// Backend-facing classes (DNS, connect, port exhaustion, pool) map to
/// `BackendError` so DTLS `stream_disconnects` metrics don't collapse every
/// failure into `recv_error`. Generic decrypt errors remain client-side
/// (`RecvError`).
pub(crate) fn dtls_disconnect_cause(
    error: &anyhow::Error,
    class: &crate::retry::ErrorClass,
) -> crate::plugins::DisconnectCause {
    use crate::plugins::DisconnectCause;
    use crate::retry::ErrorClass;

    if is_udp_dtls_idle_timeout(error) {
        return DisconnectCause::IdleTimeout;
    }

    // A relay-phase authorization expiry is a gateway-policy decision about the
    // client's own credential, so it is attributed client-side exactly like the
    // setup-phase `StreamSetupKind::AuthorizationExpired` below, and never as a
    // backend fault.
    if is_dtls_authorization_expired(error) {
        return DisconnectCause::RecvError;
    }

    if let Some(setup_err) = find_stream_setup_error(error) {
        return if setup_err.kind.is_client_side() {
            DisconnectCause::RecvError
        } else {
            DisconnectCause::BackendError
        };
    }

    match class {
        ErrorClass::DnsLookupError
        | ErrorClass::ConnectionTimeout
        | ErrorClass::ConnectionRefused
        | ErrorClass::ConnectionReset
        | ErrorClass::ConnectionClosed
        | ErrorClass::PortExhaustion
        | ErrorClass::ConnectionPoolError
        | ErrorClass::ProtocolError => DisconnectCause::BackendError,
        ErrorClass::TlsError => {
            // Untyped TLS error in the chain — conservative default. Migrate
            // remaining sites to `StreamSetupError` to remove this fallback.
            DisconnectCause::RecvError
        }
        _ => DisconnectCause::RecvError,
    }
}

/// Direction attribution for DTLS session failures, mirroring
/// [`dtls_disconnect_cause`]. Used to populate
/// [`StreamTransactionSummary::disconnect_direction`] for UDP/DTLS sessions
/// — historically `None`, now derived from the typed kind (when present) or
/// inferred from the error class so operators can tell whether the client or
/// the backend tore down the session.
pub(crate) fn dtls_disconnect_direction(
    error: &anyhow::Error,
    class: &crate::retry::ErrorClass,
) -> Direction {
    use crate::retry::ErrorClass;
    if is_udp_dtls_idle_timeout(error) {
        return Direction::Unknown;
    }
    // Same client-side attribution as the setup-phase typed kind.
    if is_dtls_authorization_expired(error) {
        return Direction::ClientToBackend;
    }
    if let Some(setup_err) = find_stream_setup_error(error) {
        return setup_err.kind.direction();
    }
    match class {
        ErrorClass::DnsLookupError
        | ErrorClass::ConnectionTimeout
        | ErrorClass::ConnectionRefused
        | ErrorClass::ConnectionReset
        | ErrorClass::ConnectionClosed
        | ErrorClass::PortExhaustion
        | ErrorClass::ConnectionPoolError
        | ErrorClass::ProtocolError => Direction::BackendToClient,
        ErrorClass::ClientDisconnect | ErrorClass::RequestBodyTooLarge => {
            Direction::ClientToBackend
        }
        _ => Direction::Unknown,
    }
}

async fn dtls_shared_idle_watchdog(
    last_activity_ms: Arc<AtomicU64>,
    idle_timeout: Duration,
) -> Result<(), anyhow::Error> {
    let idle_timeout_ms = idle_timeout.as_millis().min(u64::MAX as u128) as u64;
    let poll_ms = (idle_timeout_ms / 4).clamp(100, 1_000);
    let mut interval = tokio::time::interval(Duration::from_millis(poll_ms));
    loop {
        interval.tick().await;
        let now = coarse_epoch_millis();
        let last = last_activity_ms.load(Ordering::Relaxed);
        if udp_idle_expired(now, last, idle_timeout_ms) {
            return Err(UdpDtlsIdleTimeout.into());
        }
    }
}

/// A DTLS session terminated because the authorization lifetime of the
/// credential that admitted it elapsed while the relay was running (issue
/// #3816).
///
/// Typed rather than a bare `anyhow!` so the disconnect cause, direction, and
/// error class are derived from the type instead of inferred from message text.
/// Its `Display` is a compiled-in literal: it names the contract, never the
/// credential, its subject, its provider, its expiry instant, or the client.
#[derive(Debug)]
pub(crate) struct DtlsAuthorizationExpired;

impl std::fmt::Display for DtlsAuthorizationExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("authenticated DTLS session terminated: authorization lifetime reached")
    }
}

impl std::error::Error for DtlsAuthorizationExpired {}

/// `true` when this DTLS session failure is the relay-phase authorization
/// expiry above. Health-neutral and client-side: it is a gateway-policy
/// decision about the client's own credential, not a backend fault.
pub(crate) fn is_dtls_authorization_expired(error: &anyhow::Error) -> bool {
    error.downcast_ref::<DtlsAuthorizationExpired>().is_some()
}

/// Settle a UDP/DTLS stream-session authorization expiry exactly once, in any
/// phase.
///
/// The shared latch records the fixed-cardinality `stream_udp` termination
/// counter for the FIRST caller only, and only that caller stamps the bounded
/// class into the session metadata map; the return value reports whether THIS
/// call owned the settlement. `handle_dtls_client` drains that map into
/// `DtlsHandlerResult::metadata`, which the accept loop merges into the
/// `StreamTransactionSummary` and delivers to `on_stream_disconnect`; the
/// plain-UDP session writes the same key straight into `UdpSession::metadata`,
/// which `build_udp_stream_summary` reads. Either way the setup phase and the
/// relay phase reach the summary through the ordinary lifecycle. Only the
/// bounded class string is published: no identity, certificate field, expiry
/// instant, provider detail, or client address.
pub(crate) fn settle_stream_udp_auth_expiry(
    termination: crate::proxy::auth_lifetime::StreamAuthTermination,
    latch: &crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
    session_metadata: &std::sync::Mutex<std::collections::HashMap<String, String>>,
) -> bool {
    let won = latch.record_once(
        termination,
        crate::proxy::auth_lifetime::StreamAuthProtocolFamily::StreamUdp,
    );
    if won {
        session_metadata
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                crate::proxy::auth_lifetime::STREAM_AUTH_TERMINATION_METADATA_KEY.to_string(),
                termination.as_str().to_string(),
            );
    }
    won
}

/// DTLS-named alias retained for the DTLS relay/setup call sites and their
/// external coverage. The implementation is protocol-neutral because plain UDP
/// and DTLS share one `stream_udp` counter family and one metadata key.
pub(crate) fn settle_dtls_auth_expiry(
    termination: crate::proxy::auth_lifetime::StreamAuthTermination,
    latch: &crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
    session_metadata: &std::sync::Mutex<std::collections::HashMap<String, String>>,
) {
    let _settled = settle_stream_udp_auth_expiry(termination, latch, session_metadata);
}

/// Fixed suffix identifying the plain-UDP session lifecycle in the typed
/// authorization setup error. Names the contract, never the credential.
pub(crate) const UDP_SESSION_SETUP_CONTEXT: &str = "(UDP session)";
/// Fixed suffix identifying the DTLS session lifecycle in the same error.
pub(crate) const DTLS_SESSION_SETUP_CONTEXT: &str = "(DTLS session)";

/// The typed, client-side, health-neutral error returned when authorization
/// elapsed during post-admission DTLS setup, before any backend or application
/// datagram was forwarded. Fixed redacted wording.
pub(crate) fn dtls_authorization_setup_error() -> anyhow::Error {
    StreamSetupError::new(
        StreamSetupKind::AuthorizationExpired,
        DTLS_SESSION_SETUP_CONTEXT,
    )
    .into()
}

/// The typed, client-side, health-neutral error returned when a plain-UDP
/// session's authorization lifetime elapsed — during post-admission setup
/// (before any backend datagram was sent) or on an established session's
/// client→backend forward.
///
/// `StreamSetupKind::AuthorizationExpired` is client-side, so
/// `is_client_or_policy_udp_setup_drop` logs it at `debug!` and no backend
/// health, circuit-breaker, or load-balancer state moves. Its wording is a
/// compiled-in literal that names the contract, never the credential, its
/// subject, its provider, its expiry instant, or the client address.
pub(crate) fn udp_authorization_expired_error() -> anyhow::Error {
    StreamSetupError::new(
        StreamSetupKind::AuthorizationExpired,
        UDP_SESSION_SETUP_CONTEXT,
    )
    .into()
}

/// Fixed `StreamTransactionSummary::connection_error` for a plain-UDP session
/// the authorization contract terminated. A compiled-in literal, redacted the
/// same way [`DtlsAuthorizationExpired`]'s `Display` is.
pub(crate) const UDP_AUTHORIZATION_EXPIRED_MESSAGE: &str =
    "authenticated UDP session terminated: authorization lifetime reached";

/// Disconnect attribution for a plain-UDP session ended by the authorization
/// contract.
///
/// Client-side and backend-health-neutral by construction, matching
/// [`dtls_error_class`] / [`dtls_disconnect_cause`] / [`dtls_disconnect_direction`]
/// for the DTLS equivalent: this is a gateway policy decision about the
/// CLIENT's own credential, so `stream_disconnects` must not read it as a
/// backend outage and no upstream is scored for it.
pub(crate) fn udp_authorization_disconnect_classification() -> (
    String,
    crate::retry::ErrorClass,
    crate::plugins::DisconnectCause,
    Direction,
) {
    (
        UDP_AUTHORIZATION_EXPIRED_MESSAGE.to_string(),
        crate::retry::ErrorClass::RequestError,
        crate::plugins::DisconnectCause::RecvError,
        Direction::ClientToBackend,
    )
}

/// Outcome of one authorization-bounded backend-reply receive.
#[derive(Debug)]
pub(crate) enum UdpReplyRecvOutcome<T> {
    /// A backend datagram (or a backend receive error) arrived first.
    Received(T),
    /// Per-session stop, listener shutdown, or global shutdown won.
    Stopped,
    /// The admitted session's authorization lifetime elapsed.
    AuthorizationExpired(crate::proxy::auth_lifetime::StreamAuthTermination),
}

/// Outcome of one backend→client datagram after the awaitable hook chain is
/// raced against the admitted absolute authorization plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpReplyDatagramCommit {
    /// The datagram may be sent or enqueued for the client.
    Commit,
    /// A plugin dropped it while the session was still authorized; continue
    /// receiving.
    Drop,
    /// The absolute plan elapsed while a hook was pending, or was already
    /// elapsed before the chain was polled. The still-pending hook future is
    /// dropped. The datagram must not be sent or enqueued, and the reply task
    /// must tear down.
    AuthorizationExpired(crate::proxy::auth_lifetime::StreamAuthTermination),
}

/// Recheck the admitted absolute authorization plan at a backend→client
/// post-receive commitment boundary (issue #3816).
///
/// Unauthenticated sessions (`None`) take the `Option` miss only — no clock,
/// timer, lock, or allocation. Authenticated sessions pay one monotonic
/// comparison against the SAME absolute plan armed outside the receive loop.
/// Relayed datagrams never refresh it.
///
/// This predicate is the synchronous gate used before enqueue, flush, and the
/// post-`writable()` syscall. It cannot own an asynchronous client send: a
/// check followed by `send_to`/`writable().await` can stay pending across the
/// deadline and still emit. Those awaits go through
/// [`udp_frontend_send_until_expiry`] / [`udp_frontend_writable_until_expiry`].
#[inline]
pub(crate) fn udp_reply_expired_at_commit(
    plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
) -> Option<crate::proxy::auth_lifetime::StreamAuthTermination> {
    let plan = plan?;
    (tokio::time::Instant::now() >= plan.at).then_some(plan.termination)
}

/// Outcome of racing one client-facing UDP/DTLS frontend send (or writable
/// wait) against the admitted absolute authorization plan.
#[derive(Debug)]
pub(crate) enum UdpFrontendSendOutcome<T> {
    /// The send or writable wait completed while the session was still
    /// authorized. The inner value is the operation's own result.
    Sent(T),
    /// The absolute plan elapsed before the operation was allowed to emit.
    /// The send/writable future was dropped, so it cannot complete afterwards.
    AuthorizationExpired(crate::proxy::auth_lifetime::StreamAuthTermination),
}

/// Race one client-facing send against the admitted absolute authorization
/// plan (issue #3816 / #3820).
///
/// A pre-send `udp_reply_expired_at_commit` check is not enough: `send_to`
/// can remain pending across the deadline and still emit a client-facing
/// packet. This helper owns the send future for the whole wait.
///
/// Authenticated sessions: an already-elapsed plan never polls `send`.
/// Otherwise the expiry arm is `biased` FIRST so an exact-deadline tie fails
/// closed (expiry wins over send readiness). `timeout_at` is refused here
/// because it polls the inner future before the timer. The plan is never
/// refreshed. The send future is dropped when expiry wins — it is not
/// detached and cannot outlive the race. For terminating frontend DTLS the
/// raced future is `DtlsServerSender::send_committed`: dropping it also
/// cancels the queued driver request so ciphertext cannot be encrypted or
/// written after the bound.
///
/// Unauthenticated sessions (`None`) await `send` with no timer, lock, or
/// clock read — the previous fast path.
pub(crate) async fn udp_frontend_send_until_expiry<F>(
    plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    send: F,
) -> UdpFrontendSendOutcome<F::Output>
where
    F: std::future::Future,
{
    let Some(plan) = plan else {
        return UdpFrontendSendOutcome::Sent(send.await);
    };
    if tokio::time::Instant::now() >= plan.at {
        return UdpFrontendSendOutcome::AuthorizationExpired(plan.termination);
    }
    tokio::select! {
        biased;
        () = tokio::time::sleep_until(plan.at) => {
            UdpFrontendSendOutcome::AuthorizationExpired(plan.termination)
        }
        result = send => UdpFrontendSendOutcome::Sent(result),
    }
}

/// Race one DTLS client→backend stage — receive, an awaited hook, or the
/// backend application-datagram commit — against the admitted absolute
/// authorization plan (issue #3816 / #3820).
///
/// The client-to-backend task owns this boundary: the outer relay select is
/// not sufficient, because abort is scheduled after the inner task may already
/// have committed. An already-elapsed plan never polls `stage`. An exact
/// deadline tie is expiry-first. Settlement goes through the shared session
/// latch exactly once and is not counted as hook-ingress overload or a backend
/// health failure.
///
/// Unauthenticated sessions (`None`) await `stage` with no timer, lock, or
/// clock read.
pub(crate) async fn dtls_c2b_until_expiry<F>(
    plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    latch: &crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
    session_metadata: &std::sync::Mutex<std::collections::HashMap<String, String>>,
    stage: F,
) -> Result<F::Output, crate::proxy::auth_lifetime::StreamAuthTermination>
where
    F: std::future::Future,
{
    match udp_frontend_send_until_expiry(plan, stage).await {
        UdpFrontendSendOutcome::AuthorizationExpired(termination) => {
            settle_dtls_auth_expiry(termination, latch, session_metadata);
            Err(termination)
        }
        UdpFrontendSendOutcome::Sent(value) => Ok(value),
    }
}

/// Race a client-facing `writable()` wait against the same absolute plan,
/// then re-read the plan after readiness and before the caller may issue
/// the send syscall.
///
/// `writable()` becoming ready is not permission to emit. Exact-deadline
/// ties fail closed in the race, and the post-ready recheck catches a clock
/// that has already reached `plan.at` even if the Sleep arm was not the one
/// `select!` observed. Unauthenticated sessions skip both the timer and the
/// clock read.
pub(crate) async fn udp_frontend_writable_until_expiry<W>(
    plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    writable: W,
) -> UdpFrontendSendOutcome<W::Output>
where
    W: std::future::Future,
{
    match udp_frontend_send_until_expiry(plan, writable).await {
        UdpFrontendSendOutcome::AuthorizationExpired(termination) => {
            UdpFrontendSendOutcome::AuthorizationExpired(termination)
        }
        UdpFrontendSendOutcome::Sent(ready) => {
            if let Some(termination) = udp_reply_expired_at_commit(plan) {
                UdpFrontendSendOutcome::AuthorizationExpired(termination)
            } else {
                UdpFrontendSendOutcome::Sent(ready)
            }
        }
    }
}

/// Run the backend→client `on_udp_datagram` chain raced against the admitted
/// absolute authorization plan (issue #3816 / #3820).
///
/// A post-hook clock recheck is not enough: if a hook stays pending, the
/// reply task no longer polls the session deadline and the authenticated
/// session, backend socket, guards, retained payload, and hook future can
/// survive indefinitely. This helper owns the hook-chain future for the whole
/// wait. When expiry wins, that future is dropped immediately — it is not
/// detached and cannot complete afterwards.
///
/// Authenticated sessions: an already-elapsed plan never polls a hook.
/// Otherwise the chain is raced with the SAME absolute `StreamAuthDeadline`
/// (never refreshed per hook or datagram) through
/// [`udp_frontend_send_until_expiry`], so an exact-deadline tie is expiry-first
/// (`biased`). A plugin `Drop` is honored only when it becomes ready strictly
/// before expiry; if expiry and Drop are ready together, expiry wins.
///
/// Unauthenticated sessions (`plan == None`) await the chain with no timer,
/// lock, or clock read — the previous fast path.
pub(crate) async fn udp_reply_commit_after_backend_hooks(
    datagram_plugins: &[Arc<dyn Plugin>],
    ctx: &UdpDatagramContext<'_>,
    plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
) -> UdpReplyDatagramCommit {
    let chain = async {
        for plugin in datagram_plugins {
            if matches!(plugin.on_udp_datagram(ctx).await, UdpDatagramVerdict::Drop) {
                return UdpReplyDatagramCommit::Drop;
            }
        }
        UdpReplyDatagramCommit::Commit
    };
    match udp_frontend_send_until_expiry(plan, chain).await {
        UdpFrontendSendOutcome::AuthorizationExpired(termination) => {
            UdpReplyDatagramCommit::AuthorizationExpired(termination)
        }
        UdpFrontendSendOutcome::Sent(commit) => commit,
    }
}

/// Race one backend-reply receive against the session's absolute authorization
/// deadline, the per-session stop signal, and listener/global shutdown.
///
/// The authorization arm is `biased` FIRST, and an ALREADY-elapsed plan settles
/// without polling `recv` at all: a backend datagram that is already readable
/// must not be delivered to a client whose credential has stopped authorizing
/// the session, and the decision must not depend on `select!`'s scheduling.
///
/// `authorization_deadline` is armed ONCE by the caller, outside its receive
/// loop, so no per-datagram timer is registered. An unauthenticated session
/// passes `None` and takes the previous code path exactly, with no timer arm.
pub(crate) async fn udp_reply_recv_until_stop_or_expiry<F, C, T>(
    stop_flag: &std::sync::atomic::AtomicBool,
    stop_notify: &tokio::sync::Notify,
    authorization: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    authorization_deadline: &mut std::pin::Pin<Box<tokio::time::Sleep>>,
    recv: F,
    cancel: C,
) -> UdpReplyRecvOutcome<T>
where
    F: std::future::Future<Output = T>,
    C: std::future::Future<Output = ()>,
{
    let Some(plan) = authorization else {
        return match udp_reply_recv_until_stop(stop_flag, stop_notify, recv, cancel).await {
            Some(value) => UdpReplyRecvOutcome::Received(value),
            None => UdpReplyRecvOutcome::Stopped,
        };
    };
    if tokio::time::Instant::now() >= plan.at {
        return UdpReplyRecvOutcome::AuthorizationExpired(plan.termination);
    }
    tokio::select! {
        biased;
        () = authorization_deadline.as_mut() => {
            UdpReplyRecvOutcome::AuthorizationExpired(plan.termination)
        }
        inner = udp_reply_recv_until_stop(stop_flag, stop_notify, recv, cancel) => match inner {
            Some(value) => UdpReplyRecvOutcome::Received(value),
            None => UdpReplyRecvOutcome::Stopped,
        },
    }
}

/// Whether an admitted DTLS session may still be handed to the relay tasks.
///
/// Setup between two await points is synchronous work the deadline arms cannot
/// observe, so the absolute plan is re-checked immediately before backend
/// success accounting and relay task creation. Returns the bounded termination
/// class when the session may no longer be admitted. `None` (unauthenticated)
/// is always admissible.
pub(crate) fn dtls_authorization_expired_before_relay(
    plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    now: tokio::time::Instant,
) -> Option<crate::proxy::auth_lifetime::StreamAuthTermination> {
    plan.filter(|plan| now >= plan.at)
        .map(|plan| plan.termination)
}

/// Whether an admitted plain-UDP session may still be COMMITTED: inserted into
/// the session map, counted as a backend success, handed a reply task, and
/// given its first backend send.
///
/// Identical contract to [`dtls_authorization_expired_before_relay`] — the
/// synchronous work between two `await` points is invisible to the deadline
/// arms, so the absolute plan is re-read immediately before commitment. `None`
/// (unauthenticated) is always committable.
pub(crate) fn udp_authorization_expired_before_commit(
    plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    now: tokio::time::Instant,
) -> Option<crate::proxy::auth_lifetime::StreamAuthTermination> {
    dtls_authorization_expired_before_relay(plan, now)
}

/// Run one awaitable post-admission UDP/DTLS stream-setup stage — the
/// first-datagram policy hooks, DNS resolution, backend UDP/DTLS connect and
/// handshake — under the admitted credential's absolute authorization deadline
/// (issue #3816).
///
/// The deadline is anchored at admission and never refreshed, so composing it
/// over a stage cannot extend it. An already-elapsed plan never builds or polls
/// the stage at all, so an expired session runs no hook, resolves no name and
/// dials no backend; a stage that started earlier has its future DROPPED at the
/// deadline, so a partially completed connect or DTLS handshake is abandoned
/// rather than finished.
///
/// On expiry `release_probe` runs first — the caller uses it to release a
/// claimed HALF_OPEN circuit-breaker probe slot NEUTRALLY, because this is a
/// gateway security decision and must record neither backend success nor
/// backend failure — then the termination is settled once and the typed
/// client-side setup error is returned, carrying `context` as its fixed,
/// credential-free suffix.
///
/// `None` (an unauthenticated UDP/DTLS session) runs the stage unbounded, with
/// no timer registered at all.
pub(crate) async fn stream_udp_setup_stage_under_authorization<S, F>(
    plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    latch: &crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
    session_metadata: &std::sync::Mutex<std::collections::HashMap<String, String>>,
    context: &'static str,
    release_probe: impl FnOnce(),
    stage: S,
) -> Result<F::Output, anyhow::Error>
where
    S: FnOnce() -> F,
    F: std::future::Future,
{
    if let Some(termination) =
        dtls_authorization_expired_before_relay(plan, tokio::time::Instant::now())
    {
        release_probe();
        settle_stream_udp_auth_expiry(termination, latch, session_metadata);
        return Err(StreamSetupError::new(StreamSetupKind::AuthorizationExpired, context).into());
    }
    match crate::proxy::tcp_proxy::within_stream_auth_deadline(plan, stage()).await {
        Ok(output) => Ok(output),
        Err(termination) => {
            release_probe();
            settle_stream_udp_auth_expiry(termination, latch, session_metadata);
            Err(StreamSetupError::new(StreamSetupKind::AuthorizationExpired, context).into())
        }
    }
}

/// DTLS projection of [`stream_udp_setup_stage_under_authorization`].
pub(crate) async fn dtls_setup_stage_under_authorization<S, F>(
    plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    latch: &crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
    session_metadata: &std::sync::Mutex<std::collections::HashMap<String, String>>,
    release_probe: impl FnOnce(),
    stage: S,
) -> Result<F::Output, anyhow::Error>
where
    S: FnOnce() -> F,
    F: std::future::Future,
{
    stream_udp_setup_stage_under_authorization(
        plan,
        latch,
        session_metadata,
        DTLS_SESSION_SETUP_CONTEXT,
        release_probe,
        stage,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_dtls_client_inner(
    client_conn: crate::dtls::DtlsServerConn,
    identity: DatagramClientIdentity,
    proxy_id: &str,
    proxy_namespace: &str,
    epoch: &RequestEpoch,
    health_checker: &HealthChecker,
    dns_cache: &DnsCache,
    metrics: &Arc<UdpProxyMetrics>,
    tls_no_verify: bool,
    tls_ca_bundle_path: Option<&str>,
    circuit_breaker_cache: &CircuitBreakerCache,
    backend_info: &mut DtlsBackendInfo,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    last_request_size: Arc<AtomicU64>,
    response_budget_remaining: Arc<AtomicU64>,
    datagram_metadata: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    datagram_plugins: &Arc<[Arc<dyn Plugin>]>,
    proxy_name: Option<&str>,
    listen_port: u16,
    crls: &crate::tls::CrlList,
    backend_dtls_config_cache: &BackendDtlsConfigCache,
    auth_deadline: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
) -> Result<(), anyhow::Error> {
    // Look up proxy config
    let proxy = epoch
        .proxy_by_namespaced_id(proxy_namespace, proxy_id)
        .ok_or_else(|| anyhow::anyhow!("Proxy {proxy_namespace}/{proxy_id} not found"))?
        .clone();
    let idle_timeout = Duration::from_secs(proxy.udp_idle_timeout_seconds.max(1));
    if proxy.udp_max_response_amplification_factor.is_none() {
        crate::udp_amplification::record_policy_unlimited();
    }
    // Socket peer for reply routing and diagnostics; resolved client for
    // identity-bearing values (backend stickiness, per-datagram hook context).
    let client_addr = identity.socket_peer;

    // Resolve backend target
    let lb_hash_key = udp_lb_hash_key_for_client_ip(identity.resolved().ip());
    let (backend_host, backend_port) =
        resolve_backend_target(&proxy, &epoch.load_balancer, health_checker, &lb_hash_key)?;
    // Populate backend target as soon as it's known — even if DNS or connect fails.
    backend_info.backend_target = format!("{}:{}", backend_host, backend_port);

    // Circuit breaker check — reject before creating backend connection if open.
    // When admitted, capture whether this is a half-open probe so downstream
    // record_failure/record_success calls only decrement the in-flight counter
    // for actual probe requests.
    let cb_target_key = proxy
        .upstream_id
        .as_ref()
        .map(|_| crate::circuit_breaker::target_key(&backend_host, backend_port));
    let mut cb_is_half_open_probe = false;
    if let Some(ref cb_config) = proxy.circuit_breaker {
        match circuit_breaker_cache.can_execute(
            &proxy.namespace,
            proxy_id,
            cb_target_key.as_deref(),
            cb_config,
        ) {
            Ok((_cb, is_half_open_probe)) => {
                cb_is_half_open_probe = is_half_open_probe;
            }
            Err(_) => {
                warn!(
                    proxy_id = %proxy_id,
                    client = %udp_client_log_addr(client_addr),
                    "DTLS session rejected: circuit breaker open"
                );
                return Err(StreamSetupError::new(
                    StreamSetupKind::CircuitBreakerOpen,
                    "(DTLS session)",
                )
                .into());
            }
        }
    }

    // Once-only settlement for this session's authorization lifetime, shared by
    // the setup-phase stages below and the relay-phase deadline arm, so a
    // session is counted and stamped exactly once no matter which phase ended
    // it (issue #3816).
    let auth_termination_latch = crate::proxy::auth_lifetime::StreamAuthTerminationLatch::default();
    // Release a claimed HALF_OPEN probe slot NEUTRALLY on an authorization
    // expiry: the gateway dialed nothing on behalf of this credential, so the
    // breaker must record neither success nor failure, and the slot must not
    // leak or the breaker could never recover.
    let release_half_open_probe = || {
        if let Some(ref cb_config) = proxy.circuit_breaker {
            let cb = circuit_breaker_cache.get_or_create(
                &proxy.namespace,
                proxy_id,
                cb_target_key.as_deref(),
                cb_config,
            );
            cb.record_neutral(cb_is_half_open_probe);
        }
    };

    let candidates = match dtls_setup_stage_under_authorization(
        auth_deadline,
        &auth_termination_latch,
        &datagram_metadata,
        &release_half_open_probe,
        || {
            dns_cache.resolve_candidates(
                &backend_host,
                proxy.dns_override.as_deref(),
                proxy.dns_cache_ttl_seconds,
            )
        },
    )
    .await?
    {
        Ok(addresses) => addresses,
        Err(e) => {
            // Settle any HALF_OPEN probe slot `can_execute` admitted. A
            // backend-egress-policy denial dialed no backend, so release the slot
            // NEUTRALLY (no count) rather than leaking it — otherwise
            // `half_open_in_flight` stays consumed and the breaker can never
            // recover. Genuine DNS/transport failures still record a failure.
            if let Some(ref cb_config) = proxy.circuit_breaker {
                let cb = circuit_breaker_cache.get_or_create(
                    &proxy.namespace,
                    proxy_id,
                    cb_target_key.as_deref(),
                    cb_config,
                );
                if crate::dns::is_egress_policy_denial(&e) {
                    cb.record_neutral(cb_is_half_open_probe);
                } else {
                    cb.record_failure(502, true, cb_is_half_open_probe);
                }
            }
            return Err(anyhow::anyhow!(
                "DNS resolution failed for {}: {}",
                backend_host,
                e
            ));
        }
    };
    let dtls_params = (proxy.effective_scheme() == BackendScheme::Dtls)
        .then(|| {
            cached_backend_dtls_config(
                backend_dtls_config_cache,
                &proxy,
                &backend_host,
                tls_no_verify,
                crls,
                tls_ca_bundle_path,
            )
        })
        .transpose()?;
    let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);
    let (connected, backend_addr) = match dtls_setup_stage_under_authorization(
        auth_deadline,
        &auth_termination_latch,
        &datagram_metadata,
        &release_half_open_probe,
        || connect_udp_backend_candidates(&candidates, backend_port, connect_timeout, dtls_params),
    )
    .await?
    {
        Ok(connected) => connected,
        Err(error) => {
            if let Some(ref cb_config) = proxy.circuit_breaker {
                let cb = circuit_breaker_cache.get_or_create(
                    &proxy.namespace,
                    proxy_id,
                    cb_target_key.as_deref(),
                    cb_config,
                );
                cb.record_failure(502, true, cb_is_half_open_probe);
            }
            return Err(error);
        }
    };
    backend_info.backend_resolved_ip = Some(backend_addr.ip().to_string());
    let (backend_udp, backend_dtls) = match connected {
        ConnectedUdpBackend::Plain(socket) => (Some(Arc::new(socket)), None),
        ConnectedUdpBackend::Dtls(connection) => (None, Some(Arc::new(connection))),
    };

    // Synchronous work between the await points above is invisible to the
    // deadline arms, so re-check the absolute plan before ANY backend success is
    // recorded and before either relay task exists (issue #3816). The backend
    // socket / DTLS connection just established is dropped on return, so an
    // expired session forwards no application datagram and leaves no detached
    // producer.
    if let Some(termination) =
        dtls_authorization_expired_before_relay(auth_deadline, tokio::time::Instant::now())
    {
        release_half_open_probe();
        settle_dtls_auth_expiry(termination, &auth_termination_latch, &datagram_metadata);
        return Err(dtls_authorization_setup_error());
    }

    // Record circuit breaker success — backend connection established.
    if let Some(ref cb_config) = proxy.circuit_breaker {
        let cb = circuit_breaker_cache.get_or_create(
            &proxy.namespace,
            proxy_id,
            cb_target_key.as_deref(),
            cb_config,
        );
        cb.record_success(cb_is_half_open_probe);
    }

    debug!(
        proxy_id = %proxy_id,
        client = %udp_client_log_addr(client_addr),
        backend = %backend_addr,
        dtls_backend = backend_dtls.is_some(),
        "DTLS frontend session established"
    );

    // Bidirectional forwarding: client (DTLS) ↔ backend (UDP or DTLS)
    // Clone a sender for the backend→client direction before moving client_conn.
    let client_sender = client_conn.clone_sender();
    if let Some(plan) = auth_deadline {
        client_sender.bind_authorization_deadline(plan.at);
    }
    let client_close = client_sender.clone();
    let backend_dtls_write = backend_dtls.clone();
    let backend_udp_write = backend_udp.clone();
    let backend_dtls_cleanup = backend_dtls.clone();
    let metrics_fwd = metrics.clone();
    let proxy_id_fwd = proxy_id.to_string();
    let bytes_sent_fwd = Arc::clone(&bytes_sent);
    let last_request_size_fwd = Arc::clone(&last_request_size);
    let remaining_fwd = Arc::clone(&response_budget_remaining);
    let amplification_factor_fwd = proxy.udp_max_response_amplification_factor;
    // Pre-compute datagram plugin list once, share between both direction tasks.
    // Arc<[...]> avoids the per-session filter+collect being done twice.
    let dgram_plugins = Arc::clone(datagram_plugins);
    // Pre-compute context strings as Arc<str> — per-datagram "clone" is a pointer
    // bump (~5ns) instead of heap allocation + memcpy.
    let dgram_client_ip = udp_session_client_ip(identity.resolved());
    let dgram_proxy_id: Arc<str> = Arc::from(proxy_id);
    let dgram_proxy_name: Option<Arc<str>> = proxy_name.map(Arc::from);
    let dgram_listen_port = listen_port;
    // Clone Arcs for the reverse direction BEFORE the forward spawn moves them.
    let dgram_plugins_rev = Arc::clone(&dgram_plugins);
    let dgram_client_ip_rev = Arc::clone(&dgram_client_ip);
    let dgram_proxy_id_rev = Arc::clone(&dgram_proxy_id);
    let dgram_proxy_name_rev = dgram_proxy_name.clone();
    // Shared per-datagram WAF metadata sink, one clone per direction task; both
    // feed the same session map drained into the disconnect summary.
    let dgram_metadata_fwd = Arc::clone(&datagram_metadata);
    let dgram_metadata_rev = Arc::clone(&datagram_metadata);
    let shared_activity_ms = Arc::new(AtomicU64::new(coarse_epoch_millis()));

    // Client → Backend
    // Idle activity advances only after policy admission + successful forward
    // (parity with plain UDP). Decrypt/receive alone must not refresh the
    // watchdog — otherwise rate-rejected application datagrams pin the session.
    let activity_fwd = Arc::clone(&shared_activity_ms);
    // The client→backend task owns the absolute authorization boundary around
    // receive, every awaited hook, and the backend application-datagram commit.
    // The outer select abort is scheduled after this task may already commit,
    // so a parked recv/hook/send must race the plan itself (issue #3816 / #3820).
    let c2b_auth_plan = auth_deadline;
    let c2b_auth_latch = auth_termination_latch.clone();
    let client_to_backend = tokio::spawn(async move {
        'c2b: loop {
            let data = match dtls_c2b_until_expiry(
                c2b_auth_plan,
                &c2b_auth_latch,
                dgram_metadata_fwd.as_ref(),
                client_conn.recv(),
            )
            .await
            {
                Ok(Ok(d)) => d,
                Ok(Err(_)) => break,
                Err(_) => break,
            };
            let len = data.len();

            metrics_fwd.datagrams_in.fetch_add(1, Ordering::Relaxed);
            metrics_fwd
                .bytes_in
                .fetch_add(len as u64, Ordering::Relaxed);

            // Run per-datagram plugins before forwarding. Each awaited hook is
            // itself an authorization boundary: a blocked plugin cannot commit
            // an application datagram after the credential expires.
            if !dgram_plugins.is_empty() {
                let ctx = UdpDatagramContext {
                    client_ip: Arc::clone(&dgram_client_ip),
                    proxy_id: Arc::clone(&dgram_proxy_id),
                    proxy_name: dgram_proxy_name.clone(),
                    listen_port: dgram_listen_port,
                    datagram_size: len,
                    direction: UdpDatagramDirection::ClientToBackend,
                    // DTLS-terminating frontend: `data` is decrypted plaintext.
                    payload: &data,
                    payload_kind: StreamBytesKind::DecryptedApp,
                    metadata_sink: Some(UdpMetadataSink::new(dgram_metadata_fwd.as_ref())),
                };
                let mut dropped = false;
                for plugin in dgram_plugins.iter() {
                    match dtls_c2b_until_expiry(
                        c2b_auth_plan,
                        &c2b_auth_latch,
                        dgram_metadata_fwd.as_ref(),
                        plugin.on_udp_datagram(&ctx),
                    )
                    .await
                    {
                        Ok(UdpDatagramVerdict::Drop) => {
                            dropped = true;
                            break;
                        }
                        Ok(_) => {}
                        Err(_) => break 'c2b,
                    }
                }
                if dropped {
                    // Rejected application datagram: leave shared idle watermark
                    // untouched so the session can still expire.
                    continue; // Silent drop — standard UDP behavior
                }
            }

            // Publish before sending so a fast backend reply cannot observe a
            // zero or stale amplification budget.
            last_request_size_fwd.store(len as u64, Ordering::Release);
            if let Some(factor) = amplification_factor_fwd {
                crate::udp_amplification::publish_request_budget(
                    remaining_fwd.as_ref(),
                    len as u64,
                    factor,
                );
            }
            let send = async {
                if let Some(ref dtls) = backend_dtls_write {
                    dtls.send(&data).await.map_err(|e| e.to_string())
                } else if let Some(ref sock) = backend_udp_write {
                    sock.send(&data)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                } else {
                    Err("no backend socket available".to_string())
                }
            };
            match dtls_c2b_until_expiry(
                c2b_auth_plan,
                &c2b_auth_latch,
                dgram_metadata_fwd.as_ref(),
                send,
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if e != "no backend socket available" {
                        debug!(
                            proxy_id = %proxy_id_fwd,
                            "DTLS client→backend send failed: {}", e
                        );
                    }
                    break;
                }
                Err(_) => break,
            }

            metrics_fwd.datagrams_out.fetch_add(1, Ordering::Relaxed);
            metrics_fwd
                .bytes_out
                .fetch_add(len as u64, Ordering::Relaxed);
            bytes_sent_fwd.fetch_add(len as u64, Ordering::Relaxed);
            maybe_touch_udp_idle_activity(activity_fwd.as_ref(), coarse_epoch_millis(), true, true);
        }
    });

    // Backend → Client — reuse pre-computed plugin list and context strings
    // (dgram_*_rev cloned above before the forward spawn moved the originals).
    let metrics_rev = metrics.clone();
    let proxy_id_rev = dgram_proxy_id_rev.to_string();
    let bytes_received_rev = Arc::clone(&bytes_received);
    let amplification_factor_rev = proxy.udp_max_response_amplification_factor;
    let remaining_rev = Arc::clone(&response_budget_remaining);
    let listen_port_rev = listen_port;

    // Backend → Client (plain UDP or backend-DTLS): refresh idle only after
    // amplification/plugin admission and successful client delivery.
    let activity_rev = Arc::clone(&shared_activity_ms);
    // The reply task owns client-facing DTLS sends against the same absolute
    // plan the outer deadline arm uses. Clone the latch so expiry on a pending
    // send settles exactly once even if this task exits before that arm fires.
    let reply_auth_plan = auth_deadline;
    let reply_auth_latch = auth_termination_latch.clone();
    let backend_to_client = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
        loop {
            let data = if let Some(ref dtls) = backend_dtls {
                match dtls.recv().await {
                    Ok(d) => d,
                    Err(_) => break,
                }
            } else if let Some(ref sock) = backend_udp {
                match sock.recv(&mut buf).await {
                    Ok(n) => buf[..n].to_vec(),
                    Err(_) => break,
                }
            } else {
                break;
            };
            let len = data.len();

            metrics_rev.datagrams_in.fetch_add(1, Ordering::Relaxed);
            metrics_rev
                .bytes_in
                .fetch_add(len as u64, Ordering::Relaxed);

            // Amplification factor check for DTLS path — cumulative remaining
            // budget, same contract as plain UDP.
            if !admit_udp_response(
                remaining_rev.as_ref(),
                amplification_factor_rev,
                len as u64,
                &proxy_id_rev,
                listen_port_rev,
            ) {
                continue; // Drop oversized / over-budget response
            }

            // Backend→client plugin hooks share the raced helper: a pending
            // hook is cancelled at the absolute plan, and settlement goes
            // through the shared latch exactly once.
            if !dgram_plugins_rev.is_empty() {
                let ctx = UdpDatagramContext {
                    client_ip: dgram_client_ip_rev.clone(),
                    proxy_id: dgram_proxy_id_rev.clone(),
                    proxy_name: dgram_proxy_name_rev.clone(),
                    listen_port,
                    datagram_size: len,
                    direction: UdpDatagramDirection::BackendToClient,
                    // DTLS-terminating frontend: `data` is decrypted plaintext.
                    payload: &data,
                    payload_kind: StreamBytesKind::DecryptedApp,
                    metadata_sink: Some(UdpMetadataSink::new(dgram_metadata_rev.as_ref())),
                };
                match udp_reply_commit_after_backend_hooks(
                    dgram_plugins_rev.as_ref(),
                    &ctx,
                    reply_auth_plan,
                )
                .await
                {
                    UdpReplyDatagramCommit::Drop => continue,
                    UdpReplyDatagramCommit::AuthorizationExpired(termination) => {
                        settle_dtls_auth_expiry(
                            termination,
                            &reply_auth_latch,
                            dgram_metadata_rev.as_ref(),
                        );
                        break;
                    }
                    UdpReplyDatagramCommit::Commit => {}
                }
            }

            match udp_frontend_send_until_expiry(
                reply_auth_plan,
                client_sender.send_committed(&data, reply_auth_plan.map(|plan| plan.at)),
            )
            .await
            {
                UdpFrontendSendOutcome::AuthorizationExpired(termination) => {
                    settle_dtls_auth_expiry(
                        termination,
                        &reply_auth_latch,
                        dgram_metadata_rev.as_ref(),
                    );
                    break;
                }
                UdpFrontendSendOutcome::Sent(Err(_)) => {
                    if let Some(termination) = udp_reply_expired_at_commit(reply_auth_plan) {
                        settle_dtls_auth_expiry(
                            termination,
                            &reply_auth_latch,
                            dgram_metadata_rev.as_ref(),
                        );
                        break;
                    }
                    debug!(
                        proxy_id = %proxy_id_rev,
                        "DTLS backend→client send failed"
                    );
                    break;
                }
                UdpFrontendSendOutcome::Sent(Ok(())) => {}
            }

            metrics_rev.datagrams_out.fetch_add(1, Ordering::Relaxed);
            metrics_rev
                .bytes_out
                .fetch_add(len as u64, Ordering::Relaxed);
            bytes_received_rev.fetch_add(len as u64, Ordering::Relaxed);
            maybe_touch_udp_idle_activity(activity_rev.as_ref(), coarse_epoch_millis(), true, true);
        }
    });

    let mut client_to_backend = client_to_backend;
    let mut backend_to_client = backend_to_client;
    let mut idle_watchdog = Box::pin(dtls_shared_idle_watchdog(shared_activity_ms, idle_timeout));
    // Absolute authorization deadline for the admitted session. Armed once and
    // never refreshed by relayed datagrams, unlike the idle watchdog beside it.
    // An unauthenticated session (or one whose plan is absent) leaves the arm
    // permanently pending, so the relay behaves exactly as before.
    let authorization_deadline_active = auth_deadline.is_some();
    let mut authorization_deadline = Box::pin(tokio::time::sleep_until(
        auth_deadline
            .map(|plan| plan.at)
            .unwrap_or_else(tokio::time::Instant::now),
    ));
    let outcome = tokio::select! {
        biased;
        _ = &mut authorization_deadline, if authorization_deadline_active => {
            // Fixed-cardinality termination class, recorded once through the
            // same latch the setup phase uses, and stamped into the session
            // metadata so the bounded class reaches the stream transaction
            // summary and `on_stream_disconnect` (issue #3816). Authorization
            // is first so an exact tie with a relay task completing (or the
            // idle watchdog) is attributed to the security bound.
            if let Some(plan) = auth_deadline {
                settle_dtls_auth_expiry(
                    plan.termination,
                    &auth_termination_latch,
                    &datagram_metadata,
                );
            }
            // Typed and health-neutral: no expiry value, identity, or
            // certificate detail reaches the message.
            Err(DtlsAuthorizationExpired.into())
        }
        _ = &mut client_to_backend => Ok(()),
        _ = &mut backend_to_client => Ok(()),
        result = &mut idle_watchdog => result,
    };
    // Both relay directions and the backend connection are torn down on every
    // exit path below, including the authorization deadline, so no detached
    // producer remains and the disconnect/accounting runs exactly once.
    client_to_backend.abort();
    backend_to_client.abort();

    client_close.close().await;
    if let Some(ref dtls) = backend_dtls_cleanup {
        dtls.close().await;
    }

    // A pending client-facing send that lost the authorization race settles
    // the latch and exits the reply task. That completion can win this select
    // before the deadline arm, so re-read the latch: teardown above still
    // runs exactly once, and the close reason stays the typed expiry.
    if outcome.is_ok() && auth_termination_latch.observed().is_some() {
        Err(DtlsAuthorizationExpired.into())
    } else {
        outcome
    }
}

/// Create a new UDP session for a client (plain UDP frontend path).
async fn admit_plain_udp_stream(
    epoch: &RequestEpoch,
    view: &UdpSessionEpochView,
    identity: DatagramClientIdentity,
    listen_port: u16,
) -> Result<StreamConnectionContext, anyhow::Error> {
    // `client_ip` (remote.ip) is the authenticated forwarded client when the
    // datagram client-address gate supplied one; `direct_client_ip` (source.ip)
    // is always the socket peer. Without the gate the two are identical, which
    // is the historical UDP behavior.
    let client_ip = udp_session_client_ip(identity.resolved()).to_string();
    let direct_client_ip = udp_session_client_ip(identity.socket_peer).to_string();
    let mut stream_ctx = StreamConnectionContext::new(
        client_ip,
        direct_client_ip,
        view.proxy.id.clone(),
        view.proxy.name.clone(),
        listen_port,
        view.proxy.effective_scheme(),
        Arc::clone(&view.consumer_index),
    );
    stream_ctx.frontend_transport = crate::plugins::StreamFrontendTransport::Udp;
    stream_ctx.proxy_namespace = view.proxy.namespace.clone();
    stream_ctx.proxy_lifecycle_generation = epoch
        .plugin_cache
        .proxy_lifecycle_generation(&view.proxy.namespace, &view.proxy.id);
    stream_ctx.sni_hostname = view.sni_hostname.clone();
    // The constructor intentionally leaves node-waypoint per-pod policy scope
    // absent: plain UDP cannot wire it without a new capture path. Identity is
    // keyed by the shared frontend socket rather than an individual client.
    // Consequently mesh_authz fails closed when scoped policy requires the
    // unavailable per-pod identity. See docs/mesh.md.
    for plugin in view.plugins.iter() {
        if let PluginResult::Reject { .. } = plugin.on_stream_connect(&mut stream_ctx).await {
            return Err(
                StreamSetupError::new(StreamSetupKind::RejectedByPlugin, "(UDP session)").into(),
            );
        }
    }
    Ok(stream_ctx)
}

/// Create a new UDP session after stream admission and first-datagram policy.
#[allow(clippy::too_many_arguments)]
async fn create_session(
    epoch: &RequestEpoch,
    view: UdpSessionEpochView,
    dns_cache: &DnsCache,
    frontend_socket: &Arc<UdpSocket>,
    identity: DatagramClientIdentity,
    sessions: &SessionMap,
    metrics: &Arc<UdpProxyMetrics>,
    tls_no_verify: bool,
    tls_ca_bundle_path: Option<&str>,
    backend_dtls_config_cache: &BackendDtlsConfigCache,
    listen_port: u16,
    circuit_breaker_cache: &CircuitBreakerCache,
    crls: &crate::tls::CrlList,
    initial_data: &[u8],
    adaptive_buffer: &Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    udp_gso_enabled: bool,
    listener_shutdown: &watch::Receiver<bool>,
    global_shutdown: Option<&watch::Receiver<bool>>,
    overload: &Arc<crate::overload::OverloadState>,
    health_checker: &HealthChecker,
    preselected_backend_target: Option<(String, u16)>,
    admitted_datagram_plugins: Arc<[Arc<dyn Plugin>]>,
    mut stream_ctx: StreamConnectionContext,
    auth_deadline: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    auth_latch: &crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
    setup_metadata: &std::sync::Mutex<std::collections::HashMap<String, String>>,
) -> Result<Arc<UdpSession>, anyhow::Error> {
    let UdpSessionEpochView {
        proxy,
        plugins,
        datagram_plugins: _,
        consumer_index: _,
        sni_hostname: _,
    } = view;
    // The caller bound this list once before applying first-datagram policy.
    // Reuse that exact list for the session so admission counters and wrapper
    // hooks are not consulted a second time.
    let datagram_plugins = admitted_datagram_plugins;
    let proxy_id = proxy.id.as_str();
    let proxy_name = proxy.name.clone();
    let proxy_namespace = proxy.namespace.clone();
    let backend_scheme = proxy.effective_scheme();
    let is_passthrough = proxy.passthrough;
    let client_addr = identity.socket_peer;
    // Session identity strings follow the resolved (authenticated) client.
    let client_ip = udp_session_client_ip(identity.resolved());

    let lb_hash_key = udp_lb_hash_key_for_client_ip(identity.resolved().ip());
    let (backend_host, backend_port) = resolve_or_reuse_backend_target(
        preselected_backend_target,
        &proxy,
        &epoch.load_balancer,
        health_checker,
        &lb_hash_key,
    )?;

    // Circuit breaker check — reject before creating backend socket if open.
    // When admitted, capture whether this is a half-open probe so downstream
    // record_failure/record_success calls only decrement the in-flight counter
    // for actual probe requests.
    let cb_target_key = proxy
        .upstream_id
        .as_ref()
        .map(|_| crate::circuit_breaker::target_key(&backend_host, backend_port));
    let mut cb_is_half_open_probe = false;
    if let Some(ref cb_config) = proxy.circuit_breaker {
        match circuit_breaker_cache.can_execute(
            &proxy.namespace,
            proxy_id,
            cb_target_key.as_deref(),
            cb_config,
        ) {
            Ok((_cb, is_half_open_probe)) => {
                cb_is_half_open_probe = is_half_open_probe;
            }
            Err(_) => {
                warn!(
                    proxy_id = %proxy_id,
                    client = %udp_client_log_addr(client_addr),
                    "UDP session rejected: circuit breaker open"
                );
                return Err(StreamSetupError::new(
                    StreamSetupKind::CircuitBreakerOpen,
                    "(UDP session)",
                )
                .into());
            }
        }
    }

    // Release a claimed HALF_OPEN probe slot NEUTRALLY on an authorization
    // expiry: the gateway dialed nothing on behalf of this credential, so the
    // breaker must record neither success nor failure, and the slot must not
    // leak or the breaker could never recover.
    let release_half_open_probe = || {
        if let Some(ref cb_config) = proxy.circuit_breaker {
            let cb = circuit_breaker_cache.get_or_create(
                &proxy.namespace,
                proxy_id,
                cb_target_key.as_deref(),
                cb_config,
            );
            cb.record_neutral(cb_is_half_open_probe);
        }
    };

    // DNS resolve, bounded by the admitted credential's absolute authorization
    // deadline (issue #3816). An already-elapsed plan resolves no name at all.
    let candidates = match stream_udp_setup_stage_under_authorization(
        auth_deadline,
        auth_latch,
        setup_metadata,
        UDP_SESSION_SETUP_CONTEXT,
        &release_half_open_probe,
        || {
            dns_cache.resolve_candidates(
                &backend_host,
                proxy.dns_override.as_deref(),
                proxy.dns_cache_ttl_seconds,
            )
        },
    )
    .await?
    {
        Ok(addresses) => addresses,
        Err(e) => {
            // Settle any HALF_OPEN probe slot `can_execute` admitted. A
            // backend-egress-policy denial dialed no backend, so release the slot
            // NEUTRALLY (no count) rather than leaking it — otherwise
            // `half_open_in_flight` stays consumed and the breaker can never
            // recover. Genuine DNS/transport failures still record a failure.
            if let Some(ref cb_config) = proxy.circuit_breaker {
                let cb = circuit_breaker_cache.get_or_create(
                    &proxy.namespace,
                    proxy_id,
                    cb_target_key.as_deref(),
                    cb_config,
                );
                if crate::dns::is_egress_policy_denial(&e) {
                    cb.record_neutral(cb_is_half_open_probe);
                } else {
                    cb.record_failure(502, true, cb_is_half_open_probe);
                }
            }
            return Err(anyhow::anyhow!(
                "DNS resolution failed for {}: {}",
                backend_host,
                e
            ));
        }
    };
    let use_dtls = proxy.effective_scheme() == BackendScheme::Dtls && !is_passthrough;
    let dtls_params = use_dtls
        .then(|| {
            cached_backend_dtls_config(
                backend_dtls_config_cache,
                &proxy,
                &backend_host,
                tls_no_verify,
                crls,
                tls_ca_bundle_path,
            )
        })
        .transpose()?;
    let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);
    // Backend bind/connect (and backend DTLS handshake) under the same absolute
    // deadline: a stage that started earlier has its future DROPPED at expiry,
    // so a partially completed connect or handshake is abandoned rather than
    // finished on behalf of a credential that is no longer authorizing.
    let (connected, backend_addr) = match stream_udp_setup_stage_under_authorization(
        auth_deadline,
        auth_latch,
        setup_metadata,
        UDP_SESSION_SETUP_CONTEXT,
        &release_half_open_probe,
        || connect_udp_backend_candidates(&candidates, backend_port, connect_timeout, dtls_params),
    )
    .await?
    {
        Ok(connected) => connected,
        Err(error) => {
            if let Some(ref cb_config) = proxy.circuit_breaker {
                let cb = circuit_breaker_cache.get_or_create(
                    &proxy.namespace,
                    proxy_id,
                    cb_target_key.as_deref(),
                    cb_config,
                );
                cb.record_failure(502, true, cb_is_half_open_probe);
            }
            return Err(error);
        }
    };
    let resolved_ip = backend_addr.ip();
    let (backend_socket, dtls_conn) = match connected {
        ConnectedUdpBackend::Plain(socket) => (Some(Arc::new(socket)), None),
        ConnectedUdpBackend::Dtls(connection) => (None, Some(Arc::new(connection))),
    };

    // Synchronous work between the await points above is invisible to the
    // deadline arms, so re-read the absolute plan before ANY backend success is
    // recorded and before this session is COMMITTED — inserted into the session
    // map, given a reply task, or handed its first backend send (issue #3816).
    // Returning here releases everything this setup claimed: the HALF_OPEN
    // probe slot goes back NEUTRALLY, the caller's session-slot reservation is
    // released by its own guard (it is disarmed only on success), no overload
    // `ConnectionGuard` was taken yet, and the backend socket / DTLS connection
    // just established is closed and dropped — so no detached producer remains
    // and no application datagram is ever forwarded.
    if let Some(termination) =
        udp_authorization_expired_before_commit(auth_deadline, tokio::time::Instant::now())
    {
        release_half_open_probe();
        settle_stream_udp_auth_expiry(termination, auth_latch, setup_metadata);
        if let Some(ref dtls) = dtls_conn {
            dtls.close().await;
        }
        return Err(udp_authorization_expired_error());
    }

    // Record circuit breaker success — backend socket established.
    if let Some(ref cb_config) = proxy.circuit_breaker {
        let cb = circuit_breaker_cache.get_or_create(
            &proxy.namespace,
            proxy_id,
            cb_target_key.as_deref(),
            cb_config,
        );
        cb.record_success(cb_is_half_open_probe);
    }

    let now = coarse_epoch_millis();
    let connected_wall_at = chrono::Utc::now();
    let consumer_username = stream_ctx.effective_identity().map(str::to_owned);
    let auth_method = stream_ctx.auth_method;
    let datagram_client_ip = Arc::clone(&client_ip);
    let datagram_proxy_id: Arc<str> = Arc::from(proxy_id);
    let datagram_proxy_name: Option<Arc<str>> = proxy_name.as_deref().map(Arc::from);
    let (metadata, correlation_ids) = stream_ctx.take_metadata_with_correlation_ids();
    let (hook_ingress_tx, hook_ingress_rx) = if datagram_plugins.is_empty() {
        (None, None)
    } else {
        let (tx, rx) = mpsc::channel(SESSION_HOOK_INGRESS_MAX_DATAGRAMS);
        (Some(tx), Some(rx))
    };
    let hook_ingress_queued_bytes = Arc::new(AtomicUsize::new(0));
    if proxy.udp_max_response_amplification_factor.is_none() {
        crate::udp_amplification::record_policy_unlimited();
    }
    let session = Arc::new(UdpSession {
        backend_socket: backend_socket.clone(),
        dtls_conn: dtls_conn.clone(),
        last_activity: AtomicU64::new(now),
        created_at: AtomicU64::new(now),
        connected_wall_at,
        expired: std::sync::atomic::AtomicBool::new(false),
        bytes_sent: AtomicU64::new(0),
        bytes_received: AtomicU64::new(0),
        // Establish the first response budget before the reply task is spawned.
        // The caller has already accepted this datagram through policy hooks.
        last_request_size: AtomicU64::new(initial_data.len() as u64),
        response_budget_remaining: AtomicU64::new(
            proxy
                .udp_max_response_amplification_factor
                .map(|factor| {
                    crate::udp_amplification::udp_amplification_response_budget(
                        initial_data.len() as u64,
                        factor,
                    )
                })
                .unwrap_or(0),
        ),
        amplification_factor: proxy.udp_max_response_amplification_factor,
        backend_target: format!("{}:{}", backend_host, backend_port),
        backend_resolved_ip: resolved_ip.to_string(),
        sni_hostname: stream_ctx.sni_hostname.clone(),
        consumer_username,
        auth_method,
        metadata: std::sync::Mutex::new(metadata),
        plugin_trigger_decisions: stream_ctx.plugin_trigger_decisions(),
        correlation_ids,
        local_addr: std::sync::OnceLock::new(),
        plugins: Arc::clone(&plugins),
        datagram_plugins: Arc::clone(&datagram_plugins),
        datagram_client_ip: Arc::clone(&datagram_client_ip),
        forwarded_client: identity.forwarded,
        datagram_proxy_id: Arc::clone(&datagram_proxy_id),
        datagram_proxy_name: datagram_proxy_name.clone(),
        datagram_payload_kind: if is_passthrough {
            StreamBytesKind::EncryptedWire
        } else {
            StreamBytesKind::PlaintextWire
        },
        proxy_id: proxy_id.to_string(),
        proxy_name: proxy_name.clone(),
        proxy_lifecycle_generation: stream_ctx.proxy_lifecycle_generation,
        proxy_namespace: proxy_namespace.clone(),
        backend_scheme,
        listen_port,
        idle_timeout_ms: proxy.udp_idle_timeout_seconds.saturating_mul(1000),
        stop_reply_task: std::sync::atomic::AtomicBool::new(false),
        stop_notify: Arc::new(tokio::sync::Notify::new()),
        // Increment OverloadState.active_connections for each accepted UDP
        // session so per-session pressure shedding works the same as TCP/H3.
        // Decrements automatically on session drop (idle expiry, backend
        // disconnect, listener shutdown).
        overload_guard: std::sync::Mutex::new(Some(crate::overload::ConnectionGuard::new(
            overload,
        ))),
        hook_ingress_tx: std::sync::Mutex::new(hook_ingress_tx),
        hook_ingress_queued_bytes,
        hook_ingress_stop_notify: Arc::new(tokio::sync::Notify::new()),
        // The SAME latch the setup stages above used, so the setup phase, the
        // client→backend direction, and the backend reply task settle exactly
        // one termination between them.
        authorization: auth_deadline.map(|plan| UdpSessionAuthorization {
            plan,
            latch: auth_latch.clone(),
        }),
    });

    if let Some(rx) = hook_ingress_rx {
        spawn_session_hook_ingress_worker(
            Arc::clone(&session),
            rx,
            Arc::clone(metrics),
            client_addr,
        );
    }

    sessions.insert(client_addr, session.clone());
    // Note: active_sessions is reserved by the receive loop before the
    // background setup task calls create_session, avoiding TOCTOU races.
    metrics.total_sessions.fetch_add(1, Ordering::Relaxed);

    debug!(
        proxy_id = %proxy_id,
        client = %udp_client_log_addr(client_addr),
        backend = %backend_addr,
        "New UDP session created"
    );

    // Spawn backend → client reply forwarder with batch recv optimization.
    let frontend = frontend_socket.clone();
    let reply_session = session.clone();
    let reply_proxy_id = proxy_id.to_string();
    let reply_metrics = metrics.clone();
    let reply_sessions = sessions.clone();
    let reply_dtls = dtls_conn;
    let reply_plugins = plugins.to_vec();
    let reply_proxy_name = proxy_name.clone();
    let reply_proxy_namespace = proxy_namespace.clone();
    let reply_backend_scheme = backend_scheme;
    let reply_amplification_factor = proxy.udp_max_response_amplification_factor;
    let reply_adaptive_buffer = adaptive_buffer.clone();
    let reply_datagram_plugins = Arc::clone(&datagram_plugins);
    let reply_dgram_client_ip = Arc::clone(&datagram_client_ip);
    let reply_dgram_proxy_id = Arc::clone(&datagram_proxy_id);
    let reply_dgram_proxy_name = datagram_proxy_name;
    let reply_listen_port = listen_port;
    let reply_stop_notify = Arc::clone(&session.stop_notify);
    // Absolute authorization plan for the backend→client direction. Armed once
    // below, never refreshed by relayed datagrams.
    let reply_authorization_plan = session
        .authorization
        .as_ref()
        .map(|authorization| authorization.plan);
    let mut reply_listener_shutdown = listener_shutdown.clone();
    let mut reply_global_shutdown = global_shutdown.cloned();
    let is_dtls = reply_dtls.is_some();
    #[cfg(target_os = "linux")]
    let reply_udp_gso = udp_gso_enabled;
    #[cfg(not(target_os = "linux"))]
    let _ = udp_gso_enabled;
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];

        // Authorization arm for the backend→client direction, armed ONCE here
        // rather than per receive, so no per-datagram timer is registered
        // (issue #3816). An unauthenticated session leaves the arm unpolled:
        // `reply_authorization_plan` is `None`, so
        // `udp_reply_recv_until_stop_or_expiry` takes the previous code path
        // verbatim. Boxed to keep the spawned task's frame small.
        let mut reply_authorization_deadline = Box::pin(tokio::time::sleep_until(
            reply_authorization_plan.map_or_else(tokio::time::Instant::now, |plan| plan.at),
        ));

        // Third tuple element carries the DisconnectCause so the final
        // metric-emitting branch preserves client-side vs backend-side
        // attribution (backend recv failures vs. client send failures both
        // terminate this task, and mislabeling them skews cause-based
        // alerting).
        let mut disconnect_error: Option<(
            String,
            crate::retry::ErrorClass,
            crate::plugins::DisconnectCause,
            crate::plugins::Direction,
        )> = None;
        // Pre-allocate sendmmsg batch for batched client replies (Linux only).
        #[cfg(target_os = "linux")]
        let mut send_batch = super::udp_batch::SendMmsgBatch::new(64);
        // Pre-allocate GSO batch buffer for concatenating same-size datagrams (Linux only).
        // GSO is preferred over sendmmsg when available — fewer syscalls for same-size bursts.
        #[cfg(target_os = "linux")]
        let mut gso_batch = super::udp_batch::GsoBatchBuf::new(65535);
        // Track whether GSO send has failed, to avoid retrying on kernels that don't support it.
        #[cfg(target_os = "linux")]
        let mut gso_failed = false;
        'reply: loop {
            // Listener/global shutdown may already be set; borrow() also
            // advances each watch "seen" version so the cancel future's
            // changed() waits for a subsequent change.
            if *reply_listener_shutdown.borrow()
                || reply_global_shutdown
                    .as_ref()
                    .is_some_and(|rx| *rx.borrow())
            {
                break;
            }

            // Read from backend — via DTLS (channel-based) or raw UDP
            // (socket-based). Both paths share `udp_reply_recv_until_stop`
            // so the register-then-check stop ordering cannot drift from the
            // deterministic unit tests.
            let (data_slice, data_vec);
            let len;
            if let Some(ref dtls) = reply_dtls {
                let recv_result = udp_reply_recv_until_stop_or_expiry(
                    &reply_session.stop_reply_task,
                    reply_stop_notify.as_ref(),
                    reply_authorization_plan,
                    &mut reply_authorization_deadline,
                    dtls.recv(),
                    udp_reply_shutdown_cancel(
                        &mut reply_listener_shutdown,
                        &mut reply_global_shutdown,
                    ),
                )
                .await;
                match recv_result {
                    UdpReplyRecvOutcome::Stopped => break,
                    UdpReplyRecvOutcome::AuthorizationExpired(termination) => {
                        // Settle once, discard any payload that never reached
                        // the client, then fall through to the shared exit
                        // path: it closes the backend connection, marks this
                        // generation expired, closes the hook-ingress channel,
                        // removes only this exact generation, and releases the
                        // overload guard and active-session count.
                        reply_session.settle_authorization_expiry(termination);
                        #[cfg(target_os = "linux")]
                        {
                            gso_batch.discard();
                            send_batch.discard();
                        }
                        break 'reply;
                    }
                    UdpReplyRecvOutcome::Received(Ok(d)) => {
                        len = d.len();
                        data_vec = Some(d);
                        data_slice = None;
                    }
                    UdpReplyRecvOutcome::Received(Err(e)) => {
                        debug!(
                            proxy_id = %reply_proxy_id,
                            client = %udp_client_log_addr(client_addr),
                            "UDP backend DTLS recv error: {}",
                            e
                        );
                        let error_message = e.to_string();
                        disconnect_error = Some((
                            error_message.clone(),
                            crate::retry::classify_boxed_error(
                                anyhow::anyhow!(error_message).as_ref(),
                            ),
                            crate::plugins::DisconnectCause::BackendError,
                            crate::plugins::Direction::BackendToClient,
                        ));
                        break;
                    }
                }
            } else if let Some(ref sock) = backend_socket {
                let recv_result = udp_reply_recv_until_stop_or_expiry(
                    &reply_session.stop_reply_task,
                    reply_stop_notify.as_ref(),
                    reply_authorization_plan,
                    &mut reply_authorization_deadline,
                    sock.recv(&mut buf),
                    udp_reply_shutdown_cancel(
                        &mut reply_listener_shutdown,
                        &mut reply_global_shutdown,
                    ),
                )
                .await;
                match recv_result {
                    UdpReplyRecvOutcome::Stopped => break,
                    UdpReplyRecvOutcome::AuthorizationExpired(termination) => {
                        // Same shared exit path as the DTLS-backend arm above.
                        reply_session.settle_authorization_expiry(termination);
                        #[cfg(target_os = "linux")]
                        {
                            gso_batch.discard();
                            send_batch.discard();
                        }
                        break 'reply;
                    }
                    UdpReplyRecvOutcome::Received(Ok(n)) => {
                        len = n;
                        data_vec = None;
                        data_slice = Some(&buf[..n]);
                    }
                    UdpReplyRecvOutcome::Received(Err(e)) => {
                        debug!(
                            proxy_id = %reply_proxy_id,
                            client = %udp_client_log_addr(client_addr),
                            "UDP backend recv error: {}",
                            e
                        );
                        let error_message = e.to_string();
                        disconnect_error = Some((
                            error_message.clone(),
                            crate::retry::classify_boxed_error(
                                anyhow::anyhow!(error_message).as_ref(),
                            ),
                            crate::plugins::DisconnectCause::BackendError,
                            crate::plugins::Direction::BackendToClient,
                        ));
                        break;
                    }
                }
            } else {
                break;
            };

            let send_data = if let Some(ref d) = data_vec {
                d.as_slice()
            } else if let Some(d) = data_slice {
                d
            } else {
                break;
            };

            // Recheck immediately after the receive returns, before any
            // processing or client send: a datagram that won the receive race
            // just before expiry must not be forwarded once the credential no
            // longer authorizes the session.
            if let Some(termination) = udp_reply_expired_at_commit(reply_authorization_plan) {
                reply_session.settle_authorization_expiry(termination);
                #[cfg(target_os = "linux")]
                {
                    gso_batch.discard();
                    send_batch.discard();
                }
                break 'reply;
            }

            // Amplification factor check: drop backend responses that exceed
            // the remaining per-request byte budget (cumulative across replies).
            if !admit_udp_response(
                &reply_session.response_budget_remaining,
                reply_amplification_factor,
                len as u64,
                &reply_proxy_id,
                reply_listen_port,
            ) {
                continue; // Drop this response datagram, continue receiving
            }

            // Run backend→client per-datagram plugin hooks raced against the
            // same absolute plan. A hook that stays pending past the deadline
            // is cancelled immediately; the payload is not delivered.
            if !reply_datagram_plugins.is_empty() {
                let ctx = UdpDatagramContext {
                    client_ip: reply_dgram_client_ip.clone(),
                    proxy_id: reply_dgram_proxy_id.clone(),
                    proxy_name: reply_dgram_proxy_name.clone(),
                    listen_port: reply_listen_port,
                    datagram_size: len,
                    direction: UdpDatagramDirection::BackendToClient,
                    payload: send_data,
                    payload_kind: reply_session.datagram_payload_kind,
                    metadata_sink: Some(UdpMetadataSink::new(&reply_session.metadata)),
                };
                match udp_reply_commit_after_backend_hooks(
                    reply_datagram_plugins.as_ref(),
                    &ctx,
                    reply_authorization_plan,
                )
                .await
                {
                    UdpReplyDatagramCommit::Drop => continue, // Silent drop
                    UdpReplyDatagramCommit::AuthorizationExpired(termination) => {
                        reply_session.settle_authorization_expiry(termination);
                        #[cfg(target_os = "linux")]
                        {
                            gso_batch.discard();
                            send_batch.discard();
                        }
                        break 'reply;
                    }
                    UdpReplyDatagramCommit::Commit => {}
                }
            } else if let Some(termination) = udp_reply_expired_at_commit(reply_authorization_plan)
            {
                reply_session.settle_authorization_expiry(termination);
                #[cfg(target_os = "linux")]
                {
                    gso_batch.discard();
                    send_batch.discard();
                }
                break 'reply;
            }

            // Batch-local counters for this recv burst.
            let mut batch_dgrams: u64 = 1;
            let mut batch_bytes: u64 = len as u64;
            let mut batch_bytes_received: u64 = len as u64;
            let now = coarse_epoch_millis();
            #[cfg(target_os = "linux")]
            let mut send_drops = UdpReplySendDrops::default();

            // --- Batched send path (Linux, plain UDP only) ---
            // When GSO is available, concatenate same-size datagrams into a single
            // sendmsg+UDP_SEGMENT call. Falls back to sendmmsg if GSO is disabled
            // or has failed on this socket.
            #[cfg(target_os = "linux")]
            let send_batched = !is_dtls;
            #[cfg(not(target_os = "linux"))]
            let send_batched = false;

            // Snapshot the session's captured local (reply-source) address —
            // cheap lock-free `OnceLock::get()` — so every sendmsg in this
            // iteration can attach it as IP(v6)_PKTINFO cmsg and skip the
            // routing lookup.
            #[cfg(target_os = "linux")]
            let session_local_ip: Option<crate::socket_opts::PktinfoLocal> =
                reply_session.local_addr.get().copied();

            if send_batched {
                #[cfg(target_os = "linux")]
                {
                    if reply_udp_gso && !gso_failed {
                        if let Some(termination) = try_gso_send_or_fallback(
                            &mut gso_batch,
                            &mut send_batch,
                            &frontend,
                            client_addr,
                            send_data,
                            &mut gso_failed,
                            &reply_proxy_id,
                            session_local_ip,
                            &mut send_drops,
                            reply_authorization_plan,
                        )
                        .await
                        {
                            reply_session.settle_authorization_expiry(termination);
                            gso_batch.discard();
                            send_batch.discard();
                            break 'reply;
                        }
                    } else if let Some(termination) = enqueue_sendmmsg_or_direct(
                        &mut send_batch,
                        &frontend,
                        client_addr,
                        send_data,
                        session_local_ip,
                        &reply_proxy_id,
                        &mut send_drops,
                        reply_authorization_plan,
                    )
                    .await
                    {
                        reply_session.settle_authorization_expiry(termination);
                        gso_batch.discard();
                        send_batch.discard();
                        break 'reply;
                    }
                }
            } else {
                // Non-batched path: Linux DTLS-backend replies, and every
                // non-Linux frontend send. The send future is owned by the
                // same absolute plan — a pre-send check cannot cover a
                // pending `send_to`.
                match udp_frontend_send_until_expiry(
                    reply_authorization_plan,
                    frontend.send_to(send_data, client_addr),
                )
                .await
                {
                    UdpFrontendSendOutcome::AuthorizationExpired(termination) => {
                        reply_session.settle_authorization_expiry(termination);
                        #[cfg(target_os = "linux")]
                        {
                            gso_batch.discard();
                            send_batch.discard();
                        }
                        break 'reply;
                    }
                    UdpFrontendSendOutcome::Sent(Err(e)) => {
                        debug!(
                            proxy_id = %reply_proxy_id,
                            client = %udp_client_log_addr(client_addr),
                            "UDP send to client failed: {}",
                            e
                        );
                        let error_message = e.to_string();
                        // Client-facing send failure — the backend is healthy, so
                        // attribute the session teardown to the client recv path.
                        disconnect_error = Some((
                            error_message.clone(),
                            crate::retry::classify_boxed_error(
                                anyhow::anyhow!(error_message).as_ref(),
                            ),
                            crate::plugins::DisconnectCause::RecvError,
                            crate::plugins::Direction::BackendToClient,
                        ));
                        break;
                    }
                    UdpFrontendSendOutcome::Sent(Ok(_)) => {}
                }
            }

            // For plain UDP, drain additional pending replies without yielding.
            // DTLS reads are channel-based (async only), so skip batching for DTLS backends.
            if !is_dtls {
                let Some(ref sock) = backend_socket else {
                    break;
                };
                let batch_limit =
                    reply_adaptive_buffer.get_batch_limit(&reply_proxy_namespace, &reply_proxy_id);
                for _ in 0..batch_limit {
                    // Expiry during/among try_recv processing must stop accepting
                    // further backend payloads; already-queued client datagrams
                    // are discarded rather than flushed.
                    if let Some(termination) = udp_reply_expired_at_commit(reply_authorization_plan)
                    {
                        reply_session.settle_authorization_expiry(termination);
                        #[cfg(target_os = "linux")]
                        {
                            gso_batch.discard();
                            send_batch.discard();
                        }
                        break 'reply;
                    }
                    match sock.try_recv(&mut buf) {
                        Ok(len2) => {
                            // Amplification check on batched response datagram
                            if !admit_udp_response(
                                &reply_session.response_budget_remaining,
                                reply_amplification_factor,
                                len2 as u64,
                                &reply_proxy_id,
                                reply_listen_port,
                            ) {
                                continue; // Drop oversized / over-budget response
                            }
                            // Backend→client plugin hooks on batched datagram,
                            // raced against the same absolute plan.
                            if !reply_datagram_plugins.is_empty() {
                                let ctx = UdpDatagramContext {
                                    client_ip: reply_dgram_client_ip.clone(),
                                    proxy_id: reply_dgram_proxy_id.clone(),
                                    proxy_name: reply_dgram_proxy_name.clone(),
                                    listen_port: reply_listen_port,
                                    datagram_size: len2,
                                    direction: UdpDatagramDirection::BackendToClient,
                                    payload: &buf[..len2],
                                    payload_kind: reply_session.datagram_payload_kind,
                                    metadata_sink: Some(UdpMetadataSink::new(
                                        &reply_session.metadata,
                                    )),
                                };
                                match udp_reply_commit_after_backend_hooks(
                                    reply_datagram_plugins.as_ref(),
                                    &ctx,
                                    reply_authorization_plan,
                                )
                                .await
                                {
                                    UdpReplyDatagramCommit::Drop => continue,
                                    UdpReplyDatagramCommit::AuthorizationExpired(termination) => {
                                        reply_session.settle_authorization_expiry(termination);
                                        #[cfg(target_os = "linux")]
                                        {
                                            gso_batch.discard();
                                            send_batch.discard();
                                        }
                                        break 'reply;
                                    }
                                    UdpReplyDatagramCommit::Commit => {}
                                }
                            } else if let Some(termination) =
                                udp_reply_expired_at_commit(reply_authorization_plan)
                            {
                                reply_session.settle_authorization_expiry(termination);
                                #[cfg(target_os = "linux")]
                                {
                                    gso_batch.discard();
                                    send_batch.discard();
                                }
                                break 'reply;
                            }

                            batch_dgrams += 1;
                            batch_bytes += len2 as u64;
                            batch_bytes_received += len2 as u64;

                            if send_batched {
                                #[cfg(target_os = "linux")]
                                {
                                    if reply_udp_gso && !gso_failed {
                                        if let Some(termination) = try_gso_send_or_fallback(
                                            &mut gso_batch,
                                            &mut send_batch,
                                            &frontend,
                                            client_addr,
                                            &buf[..len2],
                                            &mut gso_failed,
                                            &reply_proxy_id,
                                            session_local_ip,
                                            &mut send_drops,
                                            reply_authorization_plan,
                                        )
                                        .await
                                        {
                                            reply_session.settle_authorization_expiry(termination);
                                            gso_batch.discard();
                                            send_batch.discard();
                                            break 'reply;
                                        }
                                    } else if let Some(termination) = enqueue_sendmmsg_or_direct(
                                        &mut send_batch,
                                        &frontend,
                                        client_addr,
                                        &buf[..len2],
                                        session_local_ip,
                                        &reply_proxy_id,
                                        &mut send_drops,
                                        reply_authorization_plan,
                                    )
                                    .await
                                    {
                                        reply_session.settle_authorization_expiry(termination);
                                        gso_batch.discard();
                                        send_batch.discard();
                                        break 'reply;
                                    }
                                }
                            } else {
                                match udp_frontend_send_until_expiry(
                                    reply_authorization_plan,
                                    frontend.send_to(&buf[..len2], client_addr),
                                )
                                .await
                                {
                                    UdpFrontendSendOutcome::AuthorizationExpired(termination) => {
                                        reply_session.settle_authorization_expiry(termination);
                                        #[cfg(target_os = "linux")]
                                        {
                                            gso_batch.discard();
                                            send_batch.discard();
                                        }
                                        break 'reply;
                                    }
                                    UdpFrontendSendOutcome::Sent(Ok(_)) => {}
                                    UdpFrontendSendOutcome::Sent(Err(e)) => {
                                        debug!(
                                            proxy_id = %reply_proxy_id,
                                            client = %udp_client_log_addr(client_addr),
                                            "UDP send to client failed: {}",
                                            e
                                        );
                                        reply_session.last_activity.store(now, Ordering::Relaxed);
                                        reply_session
                                            .bytes_received
                                            .fetch_add(batch_bytes_received, Ordering::Relaxed);
                                        reply_metrics
                                            .datagrams_out
                                            .fetch_add(batch_dgrams, Ordering::Relaxed);
                                        reply_metrics
                                            .bytes_out
                                            .fetch_add(batch_bytes, Ordering::Relaxed);
                                        if let Some(ref dtls) = reply_dtls {
                                            dtls.close().await;
                                        }
                                        // Mark expired BEFORE removal so the recv-loop's
                                        // `last_client` fast-path cache (which checks only
                                        // this flag) stops forwarding through the dead
                                        // session and re-creates one — otherwise a
                                        // single-client listener is blackholed: datagrams
                                        // keep flowing into a session whose reply task is
                                        // gone and which the idle cleaner can no longer
                                        // see (it is out of the map).
                                        reply_session
                                            .expired
                                            .store(true, std::sync::atomic::Ordering::Release);
                                        reply_session.close_hook_ingress();
                                        if reply_sessions
                                            .remove_if(&client_addr, |_, v| {
                                                Arc::ptr_eq(v, &reply_session)
                                            })
                                            .is_some()
                                        {
                                            reply_session.release_overload_guard();
                                            reply_metrics
                                                .active_sessions
                                                .fetch_sub(1, Ordering::Relaxed);
                                            let error_message = e.to_string();
                                            emit_udp_stream_disconnect(
                                                &reply_plugins,
                                                UdpDisconnectContext {
                                                    namespace: &reply_proxy_namespace,
                                                    proxy_id: &reply_proxy_id,
                                                    proxy_name: reply_proxy_name.as_deref(),
                                                    session: &reply_session,
                                                    backend_scheme: reply_backend_scheme,
                                                    listen_port: reply_listen_port,
                                                    disconnected_ms: now,
                                                    disconnected_wall_at: chrono::Utc::now(),
                                                    connection_error: Some(error_message.clone()),
                                                    error_class: Some(
                                                        crate::retry::classify_boxed_error(
                                                            anyhow::anyhow!(error_message).as_ref(),
                                                        ),
                                                    ),
                                                    disconnect_direction: Some(
                                                        crate::plugins::Direction::BackendToClient,
                                                    ),
                                                    // frontend.send_to failure is a
                                                    // client-facing write — the backend
                                                    // is healthy, so label the cause as
                                                    // a client-side (RecvError) event
                                                    // rather than a backend outage.
                                                    disconnect_cause: Some(
                                                        crate::plugins::DisconnectCause::RecvError,
                                                    ),
                                                },
                                            )
                                            .await;
                                        }
                                        return;
                                    }
                                }
                            }
                        }
                        Err(_) => break, // WouldBlock — socket drained
                    }
                }
            }

            // Flush batched sends after draining all pending replies.
            #[cfg(target_os = "linux")]
            if send_batched {
                // Recheck immediately before any GSO/sendmmsg flush so a payload
                // queued before expiry is discarded rather than sent.
                if let Some(termination) = udp_reply_expired_at_commit(reply_authorization_plan) {
                    reply_session.settle_authorization_expiry(termination);
                    gso_batch.discard();
                    send_batch.discard();
                    break 'reply;
                }
                // Flush GSO batch first (if used).
                if reply_udp_gso && !gso_failed && !gso_batch.is_empty() {
                    let flush_result =
                        flush_gso_batch(&mut gso_batch, &frontend, client_addr, session_local_ip);
                    if let Err(e) = flush_result {
                        debug!(
                            proxy_id = %reply_proxy_id,
                            client = %udp_client_log_addr(client_addr),
                            "GSO flush failed ({}), falling back to sendmmsg",
                            e
                        );
                        gso_failed = true;
                        // Replay all buffered datagrams through sendmmsg /
                        // direct-send for segments that exceed the slot size.
                        if let Some(termination) = drain_gso_to_sendmmsg_or_direct(
                            &mut gso_batch,
                            &mut send_batch,
                            &frontend,
                            client_addr,
                            session_local_ip,
                            &reply_proxy_id,
                            &mut send_drops,
                            reply_authorization_plan,
                        )
                        .await
                        {
                            reply_session.settle_authorization_expiry(termination);
                            gso_batch.discard();
                            send_batch.discard();
                            break 'reply;
                        }
                    }
                }
                // Flush sendmmsg batch (used when GSO is disabled/failed, or GSO drain).
                if !send_batch.is_empty() {
                    if let Some(termination) = udp_reply_expired_at_commit(reply_authorization_plan)
                    {
                        reply_session.settle_authorization_expiry(termination);
                        gso_batch.discard();
                        send_batch.discard();
                        break 'reply;
                    }
                    use std::os::unix::io::AsRawFd;
                    let fd = frontend.as_raw_fd();
                    loop {
                        if let Some(termination) =
                            udp_reply_expired_at_commit(reply_authorization_plan)
                        {
                            reply_session.settle_authorization_expiry(termination);
                            gso_batch.discard();
                            send_batch.discard();
                            break 'reply;
                        }
                        match flush_sendmmsg_best_effort(&mut send_batch, fd, &mut send_drops) {
                            Ok(_) if send_batch.is_empty() => break,
                            Ok(_) => continue, // partial send — retry remaining
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break, // socket full, drop remainder (UDP best-effort)
                            Err(e) => {
                                debug!(
                                    proxy_id = %reply_proxy_id,
                                    client = %udp_client_log_addr(client_addr),
                                    "UDP sendmmsg to client failed: {}",
                                    e
                                );
                                let error_message = e.to_string();
                                // sendmmsg flush targets the frontend socket
                                // (client), not the backend — client-side.
                                disconnect_error = Some((
                                    error_message.clone(),
                                    crate::retry::classify_boxed_error(
                                        anyhow::anyhow!(error_message).as_ref(),
                                    ),
                                    crate::plugins::DisconnectCause::RecvError,
                                    crate::plugins::Direction::BackendToClient,
                                ));
                                break;
                            }
                        }
                    }
                }
                if disconnect_error.is_some() {
                    break;
                }
            }

            // Flush batched metrics.
            reply_session.last_activity.store(now, Ordering::Relaxed);
            reply_session
                .bytes_received
                .fetch_add(batch_bytes_received, Ordering::Relaxed);
            #[cfg(target_os = "linux")]
            if send_batched {
                batch_dgrams = batch_dgrams.saturating_sub(send_drops.datagrams);
                batch_bytes = batch_bytes.saturating_sub(send_drops.bytes);
            }
            reply_metrics
                .datagrams_out
                .fetch_add(batch_dgrams, Ordering::Relaxed);
            reply_metrics
                .bytes_out
                .fetch_add(batch_bytes, Ordering::Relaxed);
        }
        // Session's backend receiver exited — remove session.
        //
        // Authorization attribution is taken from the session's own settlement
        // LATCH rather than from which select arm broke the loop (issue
        // #3816): the client→backend direction and the hook-ingress worker can
        // both observe the expiry first and then wake this task through the
        // ordinary stop signal, which is indistinguishable from an idle-cleanup
        // stop at this point. The latch IS the record of the decision, so the
        // summary reports it whichever direction saw it. A genuine backend or
        // client-write failure that already broke the loop keeps its own
        // attribution — that failure really is what ended the session.
        if disconnect_error.is_none()
            && reply_session.observed_authorization_termination().is_some()
        {
            disconnect_error = Some(udp_authorization_disconnect_classification());
        }
        // Close DTLS connection if active
        if let Some(ref dtls) = reply_dtls {
            dtls.close().await;
        }
        // Mark expired BEFORE removal so the recv-loop's `last_client`
        // fast-path cache (which checks only this flag) stops forwarding
        // through the dead session and re-creates one. The flag is on THIS
        // generation's Arc, so a newer session re-created at the same client
        // address is unaffected.
        reply_session
            .expired
            .store(true, std::sync::atomic::Ordering::Release);
        reply_session.close_hook_ingress();
        // Only decrement active_sessions if we actually removed THIS session
        // (the cleanup task may have already removed and decremented it, or a
        // newer session may have been re-created at the same client address —
        // identity-aware removal must not evict that newer generation).
        if reply_sessions
            .remove_if(&client_addr, |_, v| Arc::ptr_eq(v, &reply_session))
            .is_some()
        {
            reply_session.release_overload_guard();
            reply_metrics
                .active_sessions
                .fetch_sub(1, Ordering::Relaxed);
            let disconnected_ms = coarse_epoch_millis();
            let disconnected_wall_at = chrono::Utc::now();
            let (connection_error, error_class, disconnect_cause, disconnect_direction) =
                match disconnect_error {
                    Some((message, error_class, cause, direction)) => (
                        Some(message),
                        Some(error_class),
                        Some(cause),
                        Some(direction),
                    ),
                    None => (
                        None,
                        None,
                        Some(crate::plugins::DisconnectCause::GracefulShutdown),
                        None,
                    ),
                };
            emit_udp_stream_disconnect(
                &reply_plugins,
                UdpDisconnectContext {
                    namespace: &reply_proxy_namespace,
                    proxy_id: &reply_proxy_id,
                    proxy_name: reply_proxy_name.as_deref(),
                    session: &reply_session,
                    backend_scheme: reply_backend_scheme,
                    listen_port: reply_listen_port,
                    disconnected_ms,
                    disconnected_wall_at,
                    connection_error,
                    error_class,
                    disconnect_direction,
                    disconnect_cause,
                },
            )
            .await;
        }
    });

    Ok(session)
}

/// Resolve the backend target — either direct from proxy config or via load balancer.
///
/// Returns a typed [`StreamSetupError`] (boxed into `anyhow::Error`) on
/// load-balancer failure so [`dtls_disconnect_cause`] /
/// [`dtls_disconnect_direction`] read the kind directly via
/// [`find_stream_setup_error`] rather than falling through to the
/// `RequestError` class fallback (which would attribute the disconnect to
/// the client-side `RecvError` instead of the correct backend-side
/// `BackendError`). Mirrors the TCP resolver in
/// [`crate::proxy::tcp_proxy::resolve_backend_target`].
///
/// Per-port DestinationRule LB/locality policy engages only when
/// `initial_dispatch_port_override` is non-zero (all targets on one port);
/// the HTTP path's `backend_port` fallback is deliberately not used (a
/// placeholder port must never pin a mixed-port upstream). Stream target
/// selection respects active health checks and passive ejection state recorded
/// by HTTP-family traffic.
fn resolve_backend_target(
    proxy: &Proxy,
    lb_snapshot: &LoadBalancerCacheInner,
    health_checker: &HealthChecker,
    lb_hash_key: &str,
) -> Result<(String, u16), anyhow::Error> {
    if let Some(upstream_id) = &proxy.upstream_id {
        // Engage the per-port LB lane only when every upstream target shares a
        // single dispatch port (non-zero `initial_dispatch_port_override`). The
        // HTTP path's `backend_port` fallback is deliberately not used: for a
        // stream proxy referencing an upstream, `backend_port` is a placeholder,
        // and a coincidental match with one overridden port of a mixed-port
        // upstream would silently pin selection to that port's targets.
        let override_port = LoadBalancerCache::initial_dispatch_port_override_from(
            lb_snapshot,
            &proxy.namespace,
            upstream_id,
        );
        let health_port_scope = crate::proxy::backend_dispatch::stream_health_port_scope(
            proxy,
            lb_snapshot,
            upstream_id,
            override_port,
        );
        let port_lane = if health_port_scope.is_some()
            && udp_port_lane_selection_supported(proxy, lb_snapshot, upstream_id, override_port)?
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

        let selection = if let Some(port) = port_lane {
            LoadBalancerCache::select_target_for_port_from(
                lb_snapshot,
                &proxy.namespace,
                upstream_id,
                lb_hash_key,
                port,
                Some(&health_ctx),
            )
        } else {
            LoadBalancerCache::select_target_from(
                lb_snapshot,
                &proxy.namespace,
                upstream_id,
                lb_hash_key,
                Some(&health_ctx),
            )
        }
        .ok_or_else(|| -> anyhow::Error {
            StreamSetupError::new(
                StreamSetupKind::NoHealthyTargets,
                format!("for upstream {upstream_id}"),
            )
            .into()
        })?;
        Ok((selection.target.host.clone(), selection.target.port))
    } else {
        Ok((proxy.backend_host.clone(), proxy.backend_port))
    }
}

fn udp_lb_hash_key_for_client_ip(ip: std::net::IpAddr) -> String {
    crate::util::client_identity::canonical_ip_string(ip)
}

fn udp_port_lane_selection_supported(
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
                "for UDP port {port}: per-port {algorithm} requires stream load-balancer accounting"
            ),
        )
        .into());
    }
    let selection_affecting = stream_port_override_affects_selection(override_config);
    if selection_affecting {
        validate_stream_hash_on(proxy, lb_snapshot, upstream_id, port)?;
    }
    Ok(selection_affecting)
}

fn stream_port_override_affects_selection(
    override_config: &crate::config::types::ResolvedPortOverride,
) -> bool {
    override_config.algorithm.is_some()
        || override_config.hash_on.is_some()
        || override_config.locality_lb_setting.is_some()
}

fn validate_stream_hash_on(
    proxy: &Proxy,
    lb_snapshot: &LoadBalancerCacheInner,
    upstream_id: &str,
    port: u16,
) -> Result<(), anyhow::Error> {
    let strategy = LoadBalancerCache::get_hash_on_strategy_for_selection_from(
        lb_snapshot,
        &proxy.namespace,
        upstream_id,
        Some(port),
        None,
    );
    if matches!(strategy, crate::load_balancer::HashOnStrategy::Ip) {
        return Ok(());
    }
    Err(StreamSetupError::new(
        StreamSetupKind::UnsupportedStreamPolicy,
        format!("for UDP port {port}: stream per-port consistent hashing supports only source-IP hash keys"),
    )
    .into())
}

fn resolve_or_reuse_backend_target(
    preselected: Option<(String, u16)>,
    proxy: &Proxy,
    lb_snapshot: &LoadBalancerCacheInner,
    health_checker: &HealthChecker,
    lb_hash_key: &str,
) -> Result<(String, u16), anyhow::Error> {
    match preselected {
        Some(target) => Ok(target),
        None => resolve_backend_target(proxy, lb_snapshot, health_checker, lb_hash_key),
    }
}

/// Coarse-grained process-monotonic millisecond counter updated periodically.
/// Avoids calling `monotonic_now_ms()` on every datagram in the hot path.
/// Resolution is ~100ms which is more than sufficient for session idle timeout
/// tracking (timeouts are typically 60s+) while saving ~990 timer wakes/sec
/// compared to the previous 1ms resolution.
///
/// Backed by [`crate::socket_opts::monotonic_now_ms`] (Instant-based), never
/// `SystemTime`/UTC — wall-clock corrections must not freeze or prematurely
/// fire UDP/DTLS idle expiry, and must not distort `duration_ms`.
static COARSE_EPOCH_MS: AtomicU64 = AtomicU64::new(0);

/// Start the background timer that updates `COARSE_EPOCH_MS` every 100ms.
/// Safe to call multiple times; only the first call spawns the task.
fn ensure_coarse_timer_started() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Seed with the process-monotonic clock.
        COARSE_EPOCH_MS.store(mono_millis_precise(), Ordering::Relaxed);
        tokio::spawn(async {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                COARSE_EPOCH_MS.store(mono_millis_precise(), Ordering::Relaxed);
            }
        });
    });
}

/// Get the coarse-grained cached monotonic timestamp (updated every ~100ms).
///
/// Shared with the frontend DTLS demuxer so both datagram paths rate-limit
/// their client-address metadata diagnostics on one clock without adding a
/// per-datagram `Instant::now()`. Every DTLS listener calls
/// [`ensure_coarse_timer_started`] before its recv loop runs, so the value is
/// live wherever the gate can refuse anything.
#[inline(always)]
pub(crate) fn coarse_epoch_millis() -> u64 {
    COARSE_EPOCH_MS.load(Ordering::Relaxed)
}

/// Precise monotonic millis — used for timer updates and initial seeding.
fn mono_millis_precise() -> u64 {
    crate::socket_opts::monotonic_now_ms()
}

/// External-test seam for the plain-UDP authorization lifetime (issue #3816).
///
/// Builds a REAL [`UdpSession`] — the same struct the listener creates — with a
/// real connected backend socket, a real [`crate::overload::ConnectionGuard`],
/// and a real hook-ingress channel, and drives the production datagram paths
/// (`forward_client_datagram_to_backend`, `enqueue_session_hook_datagram`,
/// `spawn_session_hook_ingress_worker`) rather than a restatement of them. It
/// exists so the coverage under `tests/` can be external instead of inline.
#[allow(dead_code)] // Library test seam; the separately compiled binary never builds one.
pub struct UdpAuthorizationSessionProbe {
    session: Arc<UdpSession>,
    metrics: Arc<UdpProxyMetrics>,
    overload: Arc<crate::overload::OverloadState>,
    sessions: SessionMap,
    client_addr: SocketAddr,
    hook_ingress_rx: std::sync::Mutex<Option<mpsc::Receiver<Bytes>>>,
    /// The peer the session's backend socket is connected to. Kept bound so
    /// "no datagram was forwarded after expiry" is observable, not inferred.
    backend_peer: Arc<UdpSocket>,
}

#[allow(dead_code)] // Library test seam; see the type-level note.
impl UdpAuthorizationSessionProbe {
    /// Build one probe session. `plan`/`latch` mirror exactly what
    /// `create_session` stores; `with_datagram_hooks` decides whether the
    /// bounded hook-ingress channel exists (the inline-forward path has none).
    pub async fn new(
        plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
        latch: crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
        with_datagram_hooks: bool,
    ) -> Result<Self, String> {
        Self::assemble(latch, with_datagram_hooks, || plan).await
    }

    /// Bind the probe sockets, then anchor `remaining` from that instant.
    ///
    /// Loopback bind/connect are real awaits. Under a paused test clock the
    /// hosted coverage scheduler can auto-advance to a plan captured *before*
    /// those awaits, so the first production forward already sees an elapsed
    /// lifetime. Setup-expiry is covered by the dedicated setup-stage tests;
    /// this constructor is for post-commit relay contracts that need a live
    /// remaining budget that starts after fixture I/O has finished.
    pub async fn with_lifetime_after_setup(
        remaining: Duration,
        termination: crate::proxy::auth_lifetime::StreamAuthTermination,
        latch: crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
        with_datagram_hooks: bool,
    ) -> Result<Self, String> {
        Self::assemble(latch, with_datagram_hooks, || {
            Some(crate::proxy::auth_lifetime::StreamAuthDeadline {
                at: tokio::time::Instant::now() + remaining,
                termination,
            })
        })
        .await
    }

    async fn assemble(
        latch: crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
        with_datagram_hooks: bool,
        plan: impl FnOnce() -> Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    ) -> Result<Self, String> {
        let backend_peer = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(|e| format!("probe backend bind failed: {e}"))?,
        );
        let backend_addr = backend_peer
            .local_addr()
            .map_err(|e| format!("probe backend addr failed: {e}"))?;
        let backend_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("probe session socket bind failed: {e}"))?;
        backend_socket
            .connect(backend_addr)
            .await
            .map_err(|e| format!("probe session socket connect failed: {e}"))?;

        let metrics = Arc::new(UdpProxyMetrics::default());
        let overload = Arc::new(crate::overload::OverloadState::default());
        let (hook_ingress_tx, hook_ingress_rx) = if with_datagram_hooks {
            let (tx, rx) = mpsc::channel(SESSION_HOOK_INGRESS_MAX_DATAGRAMS);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let now = coarse_epoch_millis();
        let client_addr: SocketAddr = "127.0.0.1:34567"
            .parse()
            .map_err(|e| format!("probe client addr: {e}"))?;
        let session = Arc::new(UdpSession {
            backend_socket: Some(Arc::new(backend_socket)),
            dtls_conn: None,
            last_activity: AtomicU64::new(now),
            created_at: AtomicU64::new(now),
            connected_wall_at: chrono::Utc::now(),
            expired: std::sync::atomic::AtomicBool::new(false),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            last_request_size: AtomicU64::new(0),
            response_budget_remaining: AtomicU64::new(0),
            amplification_factor: None,
            backend_target: backend_addr.to_string(),
            backend_resolved_ip: backend_addr.ip().to_string(),
            sni_hostname: None,
            consumer_username: Some("probe-consumer".to_string()),
            auth_method: Some("key_auth"),
            metadata: std::sync::Mutex::new(std::collections::HashMap::new()),
            plugin_trigger_decisions: Default::default(),
            correlation_ids: Default::default(),
            local_addr: std::sync::OnceLock::new(),
            plugins: Arc::new(Vec::new()),
            datagram_plugins: Arc::from([]),
            datagram_client_ip: Arc::from("127.0.0.1"),
            forwarded_client: None,
            datagram_proxy_id: Arc::from("udp-proxy"),
            datagram_proxy_name: Some(Arc::from("UDP Proxy")),
            datagram_payload_kind: StreamBytesKind::PlaintextWire,
            proxy_id: "udp-proxy".to_string(),
            proxy_name: Some("UDP Proxy".to_string()),
            proxy_lifecycle_generation: None,
            proxy_namespace: "ferrum".to_string(),
            backend_scheme: BackendScheme::Udp,
            listen_port: 5300,
            idle_timeout_ms: 60_000,
            stop_reply_task: std::sync::atomic::AtomicBool::new(false),
            stop_notify: Arc::new(tokio::sync::Notify::new()),
            overload_guard: std::sync::Mutex::new(Some(crate::overload::ConnectionGuard::new(
                &overload,
            ))),
            hook_ingress_tx: std::sync::Mutex::new(hook_ingress_tx),
            hook_ingress_queued_bytes: Arc::new(AtomicUsize::new(0)),
            hook_ingress_stop_notify: Arc::new(tokio::sync::Notify::new()),
            authorization: plan().map(|plan| UdpSessionAuthorization { plan, latch }),
        });
        let sessions: SessionMap = Arc::new(DashMap::with_hasher_and_shard_amount(
            ahash::RandomState::new(),
            udp_session_shard_amount(0),
        ));
        sessions.insert(client_addr, Arc::clone(&session));
        metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            session,
            metrics,
            overload,
            sessions,
            client_addr,
            hook_ingress_rx: std::sync::Mutex::new(hook_ingress_rx),
            backend_peer,
        })
    }

    /// Drive the production client→backend forward for one datagram.
    pub async fn forward(&self, data: &[u8]) -> Result<(), String> {
        forward_client_datagram_to_backend(&self.session, data)
            .await
            .map_err(|e| e.to_string())
    }

    /// Drive the production client→backend commit with a caller-owned send
    /// future in place of the socket syscall. Used to park the send on
    /// writability without sleeping: expiry must drop the future before it
    /// can emit a backend datagram.
    pub async fn forward_commit_with<F>(&self, data: &[u8], send: F) -> Result<(), String>
    where
        F: std::future::Future<Output = Result<usize, std::io::Error>>,
    {
        forward_client_datagram_commit(&self.session, data, send)
            .await
            .map_err(|e| e.to_string())
    }

    /// Drive the production bounded hook-ingress admission for one datagram.
    pub fn enqueue_hook_datagram(&self, data: &[u8]) -> bool {
        enqueue_session_hook_datagram(&self.session, data, &self.metrics)
    }

    /// Spawn the real per-session hook-ingress worker. Returns `false` when the
    /// probe was built without hooks, or when the worker was already spawned.
    pub fn spawn_hook_ingress_worker(&self) -> bool {
        let rx = self
            .hook_ingress_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(rx) = rx else {
            return false;
        };
        spawn_session_hook_ingress_worker(
            Arc::clone(&self.session),
            rx,
            Arc::clone(&self.metrics),
            self.client_addr,
        );
        true
    }

    /// Await one datagram at the backend peer. Used only where the caller has
    /// already established that a datagram was sent.
    pub async fn backend_recv(&self) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
        let n = self
            .backend_peer
            .recv(&mut buf)
            .await
            .map_err(|e| format!("probe backend recv failed: {e}"))?;
        Ok(buf[..n].to_vec())
    }

    /// Non-blocking read of whatever actually reached the backend peer.
    pub fn backend_received(&self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
        match self.backend_peer.try_recv(&mut buf) {
            Ok(n) => Some(buf[..n].to_vec()),
            Err(_) => None,
        }
    }

    /// The bounded class settled for this session, if any.
    pub fn observed_termination(
        &self,
    ) -> Option<crate::proxy::auth_lifetime::StreamAuthTermination> {
        self.session.observed_authorization_termination()
    }

    /// The session metadata the disconnect summary is built from.
    pub fn metadata(&self) -> std::collections::HashMap<String, String> {
        self.session
            .metadata
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Whether the bounded hook-ingress sender is still installed. Teardown
    /// takes it (`close_hook_ingress`), which is the per-session worker's
    /// cancellation / idle-wake path.
    pub fn hook_ingress_sender_present(&self) -> bool {
        self.session
            .hook_ingress_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }

    /// Whether the backend reply task has been asked to stop.
    pub fn reply_task_stop_requested(&self) -> bool {
        let flag = &self.session.stop_reply_task;
        flag.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Whether the recv-loop `last_client` cache still resolves this exact
    /// generation, using the production cache helper.
    ///
    /// Returns `(resolved_a_live_generation, cache_entry_retained)`; the two
    /// must agree, which is what the external coverage asserts.
    pub fn cached_generation_is_live(&self) -> (bool, bool) {
        let mut cache = Some((self.client_addr, Arc::clone(&self.session)));
        let live = take_udp_last_client_if_live(&mut cache, self.client_addr, |cached| {
            cached.expired.load(std::sync::atomic::Ordering::Acquire)
        })
        .is_some();
        (live, cache.is_some())
    }

    /// Run the production teardown the backend reply task performs at exit:
    /// authorization attribution from the latch, mark expired, close the
    /// hook-ingress channel, identity-aware removal of ONLY this generation,
    /// and a single overload / active-session release. Returns the disconnect
    /// summary when this call owned the removal.
    pub fn run_reply_task_exit_teardown(&self) -> Option<crate::plugins::StreamTransactionSummary> {
        let terminated = self.session.observed_authorization_termination().is_some();
        self.session
            .expired
            .store(true, std::sync::atomic::Ordering::Release);
        self.session.close_hook_ingress();
        let removed = self
            .sessions
            .remove_if(&self.client_addr, |_, v| Arc::ptr_eq(v, &self.session))
            .is_some();
        if !removed {
            return None;
        }
        self.session.release_overload_guard();
        self.metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        let mut connection_error = None;
        let mut error_class = None;
        let mut disconnect_cause = None;
        let mut disconnect_direction = None;
        if terminated {
            let (message, class, cause, direction) = udp_authorization_disconnect_classification();
            connection_error = Some(message);
            error_class = Some(class);
            disconnect_cause = Some(cause);
            disconnect_direction = Some(direction);
        }
        Some(build_udp_stream_summary(UdpDisconnectContext {
            namespace: &self.session.proxy_namespace,
            proxy_id: &self.session.proxy_id,
            proxy_name: self.session.proxy_name.as_deref(),
            session: &self.session,
            backend_scheme: self.session.backend_scheme,
            listen_port: self.session.listen_port,
            disconnected_ms: coarse_epoch_millis(),
            disconnected_wall_at: chrono::Utc::now(),
            connection_error,
            error_class,
            disconnect_direction,
            disconnect_cause,
        }))
    }

    /// Remove this generation the way the idle-cleanup task does, so a
    /// simultaneous idle expiry and authorization expiry can be raced.
    pub fn run_idle_cleanup_removal(&self) -> bool {
        let Some((_, session)) = self
            .sessions
            .remove_if(&self.client_addr, |_, v| Arc::ptr_eq(v, &self.session))
        else {
            return false;
        };
        session
            .expired
            .store(true, std::sync::atomic::Ordering::Release);
        signal_udp_reply_task_stop(&session.stop_reply_task, session.stop_notify.as_ref());
        session.close_hook_ingress();
        session.release_overload_guard();
        self.metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        true
    }

    /// Live `OverloadState.active_connections` this session contributes to.
    pub fn overload_active_connections(&self) -> u64 {
        let counter = &self.overload.active_connections;
        counter.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Live listener `active_sessions` gauge.
    pub fn active_sessions(&self) -> u64 {
        self.metrics.active_sessions.load(Ordering::Relaxed)
    }

    /// Client→backend bytes actually accounted to this session.
    pub fn bytes_sent(&self) -> u64 {
        self.session.bytes_sent.load(Ordering::Relaxed)
    }

    /// Hook-ingress drops (gateway backpressure), which a policy refusal must
    /// never move.
    pub fn hook_ingress_drops(&self) -> u64 {
        self.metrics.hook_ingress_drops.load(Ordering::Relaxed)
    }

    /// Whether the session is still resolvable in the listener session map.
    pub fn session_map_contains(&self) -> bool {
        self.sessions.contains_key(&self.client_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BackendDtlsConfigCache, BackendDtlsConfigCacheState, DtlsDisconnectContext,
        STREAM_ERR_BACKEND_DTLS_HANDSHAKE_FAILED, StreamSetupKind, UdpDisconnectContext,
        UdpSession, build_dtls_stream_summary, build_udp_stream_summary,
        cached_backend_dtls_config, dtls_disconnect_cause, dtls_disconnect_direction,
        emit_udp_stream_disconnect, find_stream_setup_error, forward_client_datagram_to_backend,
        reserve_udp_session_slot, resolve_or_reuse_backend_target, stream_duration_ms_from_mono,
        udp_idle_expired, udp_session_shard_amount,
    };
    use crate::config::types::{BackendScheme, BackendTlsConfig, Proxy};
    use crate::health_check::HealthChecker;
    use crate::load_balancer::LoadBalancerCache;
    use crate::plugins::{
        Plugin, StreamTransactionSummary, UdpDatagramContext, UdpDatagramVerdict,
    };
    use crate::proxy::GatewayConfig;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::sync::oneshot;

    fn make_udp_session() -> UdpSession {
        UdpSession {
            plugin_trigger_decisions: Default::default(),
            backend_socket: None,
            dtls_conn: None,
            last_activity: AtomicU64::new(1_710_000_000_500),
            created_at: AtomicU64::new(1_710_000_000_000),
            connected_wall_at: chrono::DateTime::from_timestamp_millis(1_710_000_000_000)
                .expect("fixed test wall connect time"),
            expired: std::sync::atomic::AtomicBool::new(false),
            bytes_sent: AtomicU64::new(128),
            bytes_received: AtomicU64::new(256),
            last_request_size: AtomicU64::new(64),
            response_budget_remaining: AtomicU64::new(0),
            amplification_factor: None,
            backend_target: "10.0.0.50:5353".to_string(),
            backend_resolved_ip: "10.0.0.50".to_string(),
            sni_hostname: None,
            consumer_username: None,
            auth_method: None,
            metadata: std::sync::Mutex::new(HashMap::from([(
                "request_id".to_string(),
                "stream-123".to_string(),
            )])),
            correlation_ids: Default::default(),
            local_addr: std::sync::OnceLock::new(),
            plugins: Arc::new(Vec::new()),
            datagram_plugins: Arc::from([]),
            datagram_client_ip: Arc::from("127.0.0.1"),
            forwarded_client: None,
            datagram_proxy_id: Arc::from("udp-proxy"),
            datagram_proxy_name: Some(Arc::from("UDP Proxy")),
            datagram_payload_kind: crate::plugins::StreamBytesKind::PlaintextWire,
            proxy_id: "udp-proxy".to_string(),
            proxy_name: Some("UDP Proxy".to_string()),
            proxy_lifecycle_generation: None,
            proxy_namespace: "ferrum".to_string(),
            backend_scheme: BackendScheme::Udp,
            listen_port: 5300,
            idle_timeout_ms: 60_000,
            stop_reply_task: std::sync::atomic::AtomicBool::new(false),
            stop_notify: Arc::new(tokio::sync::Notify::new()),
            // Tests build sessions without an overload state; the guard slot
            // stays empty for unit tests that exercise summary emission only.
            overload_guard: std::sync::Mutex::new(None),
            hook_ingress_tx: std::sync::Mutex::new(None),
            hook_ingress_queued_bytes: Arc::new(AtomicUsize::new(0)),
            hook_ingress_stop_notify: Arc::new(tokio::sync::Notify::new()),
            // Unauthenticated by default: the authorization contract does not
            // bound a session that admitted no principal.
            authorization: None,
        }
    }

    #[tokio::test]
    async fn failed_backend_forward_preserves_activity_and_response_budget() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut raw_session = make_udp_session();
        raw_session.backend_socket = Some(socket);
        // A guarded session is what makes the "publish before send" invariant
        // observable: the remaining budget, not `last_request_size`, is what
        // the backend→client path now charges.
        raw_session.amplification_factor = Some(2.0);
        raw_session
            .last_activity
            .store(1_710_000_000_500, Ordering::Relaxed);
        let session = Arc::new(raw_session);
        super::COARSE_EPOCH_MS.store(1_710_000_001_000, Ordering::Relaxed);

        let err = forward_client_datagram_to_backend(&session, b"payload")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("send to backend failed"),
            "expected unconnected UDP socket send failure, got {err}"
        );
        assert_eq!(
            session.last_activity.load(Ordering::Relaxed),
            1_710_000_000_500,
            "failed client-to-backend forwards must not refresh idle activity"
        );
        assert_eq!(
            session.bytes_sent.load(Ordering::Relaxed),
            128,
            "failed sends must not increment bytes_sent"
        );
        assert_eq!(
            session.last_request_size.load(Ordering::Relaxed),
            b"payload".len() as u64,
            "accepted client datagrams must record their request size before send"
        );
        assert_eq!(
            session.response_budget_remaining.load(Ordering::Acquire),
            b"payload".len() as u64 * 2,
            "a failed send must still leave the earned response budget"
        );
    }

    fn test_dtls_proxy() -> Proxy {
        let mut proxy: Proxy = serde_yaml::from_str(
            r#"
id: dtls-proxy
backend_scheme: dtls
backend_host: localhost
backend_port: 8443
listen_port: 9443
backend_tls_verify_server_cert: false
"#,
        )
        .unwrap();
        proxy.resolved_tls = BackendTlsConfig::from_proxy(&proxy);
        proxy
    }

    #[test]
    fn backend_dtls_config_cache_reuses_ephemeral_certificate() {
        let proxy = test_dtls_proxy();
        let cache: BackendDtlsConfigCache = Arc::new(BackendDtlsConfigCacheState::new(Arc::new(
            AtomicU64::new(0),
        )));
        let crls = Arc::new(Vec::new());

        let first =
            cached_backend_dtls_config(&cache, &proxy, "localhost", true, &crls, None).unwrap();
        let second =
            cached_backend_dtls_config(&cache, &proxy, "localhost", true, &crls, None).unwrap();

        assert_eq!(cache.entries.len(), 1);
        assert_eq!(
            first.certificate.certificates(),
            second.certificate.certificates(),
            "cached DTLS params should reuse the generated ephemeral certificate"
        );
    }

    #[test]
    fn backend_dtls_config_cache_isolates_same_id_across_namespaces() {
        let proxy = test_dtls_proxy();
        let mut other_namespace = proxy.clone();
        other_namespace.namespace = "tenant-b".to_string();
        let cache: BackendDtlsConfigCache = Arc::new(BackendDtlsConfigCacheState::new(Arc::new(
            AtomicU64::new(0),
        )));
        let crls = Arc::new(Vec::new());

        let first =
            cached_backend_dtls_config(&cache, &proxy, "localhost", true, &crls, None).unwrap();
        let second =
            cached_backend_dtls_config(&cache, &other_namespace, "localhost", true, &crls, None)
                .unwrap();

        assert_eq!(
            cache.entries.len(),
            2,
            "same-ID proxies in different namespaces need distinct DTLS cache entries"
        );
        assert_ne!(
            first.certificate.certificates(),
            second.certificate.certificates(),
            "one namespace must not reuse another namespace's generated DTLS client identity"
        );
    }

    #[test]
    fn backend_dtls_config_cache_rebuilds_after_reload_epoch_bump() {
        let proxy = test_dtls_proxy();
        let reload_epoch = Arc::new(AtomicU64::new(0));
        let cache: BackendDtlsConfigCache =
            Arc::new(BackendDtlsConfigCacheState::new(reload_epoch.clone()));
        let crls = Arc::new(Vec::new());

        let first =
            cached_backend_dtls_config(&cache, &proxy, "localhost", true, &crls, None).unwrap();
        assert_eq!(cache.entries.len(), 1);

        // Backend TLS live reload observed rotated bytes on disk and bumped
        // the shared epoch: the next session must rebuild instead of serving
        // the stale params, and the stale entry must be garbage-collected.
        reload_epoch.fetch_add(1, Ordering::AcqRel);
        let second =
            cached_backend_dtls_config(&cache, &proxy, "localhost", true, &crls, None).unwrap();

        assert_eq!(
            cache.entries.len(),
            1,
            "pre-reload entry should be cleared, leaving only the rebuilt one"
        );
        assert_ne!(
            first.certificate.certificates(),
            second.certificate.certificates(),
            "a reload epoch bump must rebuild DTLS params (fresh ephemeral cert)"
        );

        // Stable epoch afterwards: the rebuilt entry is reused again.
        let third =
            cached_backend_dtls_config(&cache, &proxy, "localhost", true, &crls, None).unwrap();
        assert_eq!(
            second.certificate.certificates(),
            third.certificate.certificates(),
            "without another reload the rebuilt params are served from cache"
        );
    }

    #[test]
    fn test_build_dtls_stream_summary_preserves_bytes_error_and_metadata() {
        let client_addr: SocketAddr = "127.0.0.1:54000".parse().unwrap();
        // Wall timestamps deliberately disagree with the monotonic duration to
        // prove duration_ms is not derived from civil-clock subtraction.
        let connected_at = chrono::Utc::now() - chrono::TimeDelta::hours(2);
        let disconnected_at = chrono::Utc::now() - chrono::TimeDelta::hours(3);
        let metadata = HashMap::from([("request_id".to_string(), "dtls-123".to_string())]);
        let correlation_ids = Default::default();

        let summary = build_dtls_stream_summary(DtlsDisconnectContext {
            plugin_trigger_decisions: Default::default(),
            namespace: "ferrum",
            proxy_id: "dtls-proxy",
            proxy_name: Some("DTLS Proxy"),
            proxy_lifecycle_generation: None,
            resolved_client: client_addr,
            consumer_username: Some("alice".to_string()),
            auth_method: None,
            backend_target: "10.0.0.60:7443",
            backend_resolved_ip: Some("10.0.0.60"),
            backend_scheme: BackendScheme::Dtls,
            listen_port: 7443,
            connected_at,
            disconnected_at,
            duration_ms: 750.0,
            bytes_sent: 321,
            bytes_received: 654,
            connection_error: Some("tls alert".to_string()),
            error_class: Some(crate::retry::ErrorClass::TlsError),
            disconnect_direction: None,
            disconnect_cause: Some(crate::plugins::DisconnectCause::RecvError),
            sni_hostname: None,
            metadata: &metadata,
            correlation_ids: &correlation_ids,
        });

        assert_eq!(summary.proxy_id, "dtls-proxy");
        assert_eq!(summary.proxy_name.as_deref(), Some("DTLS Proxy"));
        assert_eq!(summary.client_ip, "127.0.0.1");
        assert_eq!(summary.consumer_username.as_deref(), Some("alice"));
        assert_eq!(summary.backend_target, "10.0.0.60:7443");
        assert_eq!(summary.backend_resolved_ip.as_deref(), Some("10.0.0.60"));
        assert_eq!(summary.protocol, "dtls");
        assert_eq!(summary.listen_port, 7443);
        assert_eq!(summary.bytes_sent, 321);
        assert_eq!(summary.bytes_received, 654);
        assert_eq!(summary.connection_error.as_deref(), Some("tls alert"));
        assert_eq!(
            summary.error_class,
            Some(crate::retry::ErrorClass::TlsError)
        );
        assert_eq!(summary.sni_hostname, None);
        assert_eq!(
            summary
                .metadata
                .get(crate::plugins::REQUEST_ID_METADATA_KEY)
                .map(String::as_str),
            Some("dtls-123")
        );
        assert_eq!(summary.duration_ms, 750.0);
        assert_eq!(summary.timestamp_connected, connected_at.to_rfc3339());
        assert_eq!(summary.timestamp_disconnected, disconnected_at.to_rfc3339());
    }

    #[test]
    fn test_build_dtls_stream_summary_preserves_terminating_sni() {
        // Terminating DTLS extracts ClientHello SNI into the accepted connection
        // and StreamConnectionContext; the disconnect summary must keep the same
        // value for logging sinks (issue #2531).
        let client_addr: SocketAddr = "127.0.0.1:54000".parse().unwrap();
        let connected_at = chrono::Utc::now();
        let disconnected_at = connected_at + chrono::TimeDelta::milliseconds(42);
        let metadata = HashMap::new();
        let correlation_ids = Default::default();
        let sni = Some("device.example".to_string());

        let summary = build_dtls_stream_summary(DtlsDisconnectContext {
            plugin_trigger_decisions: Default::default(),
            namespace: "ferrum",
            proxy_id: "dtls-proxy",
            proxy_name: Some("DTLS Proxy"),
            proxy_lifecycle_generation: None,
            resolved_client: client_addr,
            consumer_username: Some("alice".to_string()),
            auth_method: Some("mtls_auth"),
            backend_target: "10.0.0.60:7443",
            backend_resolved_ip: Some("10.0.0.60"),
            backend_scheme: BackendScheme::Dtls,
            listen_port: 7443,
            connected_at,
            disconnected_at,
            duration_ms: 42.0,
            bytes_sent: 16,
            bytes_received: 32,
            connection_error: None,
            error_class: None,
            disconnect_direction: None,
            disconnect_cause: Some(crate::plugins::DisconnectCause::GracefulShutdown),
            sni_hostname: sni.clone(),
            metadata: &metadata,
            correlation_ids: &correlation_ids,
        });

        assert_eq!(summary.sni_hostname.as_deref(), Some("device.example"));
        assert_eq!(summary.consumer_username.as_deref(), Some("alice"));
        assert_eq!(summary.auth_method, Some("mtls_auth"));
        assert_eq!(
            summary.sni_hostname, sni,
            "disconnect SNI must match the connect-time value"
        );
        let json = serde_json::to_value(&summary).expect("stream summary serializes");
        assert_eq!(json["sni_hostname"], "device.example");
    }

    struct CapturePlugin {
        summaries: Arc<Mutex<Vec<StreamTransactionSummary>>>,
    }

    #[async_trait]
    impl Plugin for CapturePlugin {
        fn name(&self) -> &str {
            "capture"
        }

        async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
            lock(&self.summaries).push(summary.clone());
        }
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_build_udp_stream_summary_preserves_bytes_error_and_metadata() {
        let session = make_udp_session();
        let disconnected_wall_at =
            chrono::DateTime::from_timestamp_millis(1_710_000_001_500).unwrap();

        let summary = build_udp_stream_summary(UdpDisconnectContext {
            namespace: "ferrum",
            proxy_id: "udp-proxy",
            proxy_name: Some("UDP Proxy"),
            session: &session,
            backend_scheme: BackendScheme::Udp,
            listen_port: 5353,
            disconnected_ms: 1_710_000_001_500,
            disconnected_wall_at,
            connection_error: Some("connection reset by peer".to_string()),
            error_class: Some(crate::retry::ErrorClass::ConnectionReset),
            disconnect_direction: Some(crate::plugins::Direction::BackendToClient),
            disconnect_cause: Some(crate::plugins::DisconnectCause::BackendError),
        });

        assert_eq!(summary.proxy_id, "udp-proxy");
        assert_eq!(summary.proxy_name.as_deref(), Some("UDP Proxy"));
        assert_eq!(summary.client_ip, "127.0.0.1");
        assert_eq!(summary.backend_target, "10.0.0.50:5353");
        assert_eq!(summary.backend_resolved_ip.as_deref(), Some("10.0.0.50"));
        assert_eq!(summary.protocol, "udp");
        assert_eq!(summary.listen_port, 5353);
        assert_eq!(summary.duration_ms, 1500.0);
        assert_eq!(summary.bytes_sent, 128);
        assert_eq!(summary.bytes_received, 256);
        assert_eq!(
            summary.connection_error.as_deref(),
            Some("connection reset by peer")
        );
        assert_eq!(
            summary.error_class,
            Some(crate::retry::ErrorClass::ConnectionReset)
        );
        assert_eq!(
            summary
                .metadata
                .get(crate::plugins::REQUEST_ID_METADATA_KEY)
                .map(String::as_str),
            Some("stream-123")
        );
        assert_eq!(
            summary.timestamp_connected,
            session.connected_wall_at.to_rfc3339()
        );
        assert_eq!(
            summary.timestamp_disconnected,
            disconnected_wall_at.to_rfc3339()
        );
        assert_eq!(summary.sni_hostname, None);
    }

    #[test]
    fn test_build_udp_stream_summary_preserves_passthrough_sni() {
        // UDP/DTLS passthrough peeks ClientHello SNI into UdpSession and must
        // surface it on the disconnect summary (parity with terminating DTLS).
        let mut session = make_udp_session();
        session.sni_hostname = Some("passthrough.example".to_string());
        let disconnected_wall_at =
            chrono::DateTime::from_timestamp_millis(1_710_000_001_500).unwrap();

        let summary = build_udp_stream_summary(UdpDisconnectContext {
            namespace: "ferrum",
            proxy_id: "udp-proxy",
            proxy_name: Some("UDP Proxy"),
            session: &session,
            backend_scheme: BackendScheme::Udp,
            listen_port: 5353,
            disconnected_ms: 1_710_000_001_500,
            disconnected_wall_at,
            connection_error: None,
            error_class: None,
            disconnect_direction: None,
            disconnect_cause: Some(crate::plugins::DisconnectCause::GracefulShutdown),
        });

        assert_eq!(summary.sni_hostname.as_deref(), Some("passthrough.example"));
        let json = serde_json::to_value(&summary).expect("udp summary serializes");
        assert_eq!(json["sni_hostname"], "passthrough.example");
    }

    #[test]
    fn udp_duration_and_idle_use_monotonic_clock_not_wall() {
        // Injected mono endpoints: 1500 ms elapsed even when wall jumps
        // backward (disconnect wall before connect wall).
        assert_eq!(
            stream_duration_ms_from_mono(1_000, 2_500),
            1_500.0,
            "normal mono advance"
        );
        assert_eq!(
            stream_duration_ms_from_mono(2_500, 1_000),
            0.0,
            "saturating_sub must not go negative on mono inversion"
        );

        let session = make_udp_session();
        // Wall disconnect is an hour *before* connect — the old wall-delta
        // path would clamp toward zero / go negative. Mono endpoints still
        // report the real 1500 ms session.
        let wall_disconnect = session.connected_wall_at - chrono::TimeDelta::hours(1);
        let summary = build_udp_stream_summary(UdpDisconnectContext {
            namespace: "ferrum",
            proxy_id: "udp-proxy",
            proxy_name: Some("UDP Proxy"),
            session: &session,
            backend_scheme: BackendScheme::Udp,
            listen_port: 5353,
            disconnected_ms: 1_710_000_001_500,
            disconnected_wall_at: wall_disconnect,
            connection_error: None,
            error_class: None,
            disconnect_direction: None,
            disconnect_cause: Some(crate::plugins::DisconnectCause::GracefulShutdown),
        });
        assert_eq!(summary.duration_ms, 1_500.0);
        assert_eq!(summary.timestamp_disconnected, wall_disconnect.to_rfc3339());

        // Idle expiry follows injected mono, independent of wall.
        assert!(
            !udp_idle_expired(1_000, 1_000, 60_000),
            "fresh activity must not expire"
        );
        assert!(
            !udp_idle_expired(61_000, 1_000, 60_000),
            "exactly at timeout is still alive (strict >)"
        );
        assert!(
            udp_idle_expired(61_001, 1_000, 60_000),
            "mono advance past timeout must expire"
        );
        assert!(
            !udp_idle_expired(500, 1_000, 60_000),
            "mono going \"backward\" saturates to zero elapsed — never freezes forever"
        );

        // Forward wall jump without mono advance: duration stays at the mono
        // delta (not inflated by civil-clock skew).
        let forward_wall = session.connected_wall_at + chrono::TimeDelta::hours(5);
        let forward_summary = build_udp_stream_summary(UdpDisconnectContext {
            namespace: "ferrum",
            proxy_id: "udp-proxy",
            proxy_name: None,
            session: &session,
            backend_scheme: BackendScheme::Udp,
            listen_port: 5353,
            disconnected_ms: 1_710_000_000_250,
            disconnected_wall_at: forward_wall,
            connection_error: None,
            error_class: None,
            disconnect_direction: None,
            disconnect_cause: None,
        });
        assert_eq!(forward_summary.duration_ms, 250.0);
    }

    #[test]
    fn dtls_summary_duration_ignores_wall_clock_rollback() {
        let connected_at = chrono::Utc::now();
        // Wall jumped backward an hour while the Instant-derived duration is 900 ms.
        let disconnected_at = connected_at - chrono::TimeDelta::hours(1);
        let correlation_ids = Default::default();
        let metadata = HashMap::new();
        let summary = build_dtls_stream_summary(DtlsDisconnectContext {
            plugin_trigger_decisions: Default::default(),
            namespace: "ferrum",
            proxy_id: "dtls-proxy",
            proxy_name: None,
            proxy_lifecycle_generation: None,
            resolved_client: "127.0.0.1:54000".parse().unwrap(),
            consumer_username: None,
            auth_method: None,
            backend_target: "10.0.0.60:7443",
            backend_resolved_ip: None,
            backend_scheme: BackendScheme::Dtls,
            listen_port: 7443,
            connected_at,
            disconnected_at,
            duration_ms: 900.0,
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: None,
            error_class: None,
            disconnect_direction: None,
            disconnect_cause: Some(crate::plugins::DisconnectCause::IdleTimeout),
            sni_hostname: None,
            metadata: &metadata,
            correlation_ids: &correlation_ids,
        });
        assert_eq!(summary.duration_ms, 900.0);
        assert!(
            (disconnected_at - connected_at).num_milliseconds() < 0,
            "fixture must keep a negative wall delta"
        );
    }

    #[test]
    fn dtls_frontend_duration_and_idle_use_monotonic_clock() {
        // Mirrors the frontend DTLS handler: Instant for duration_ms, wall
        // clocks only for rendering, idle via the same udp_idle_expired
        // predicate as `dtls_shared_idle_watchdog`.
        use std::time::Instant;

        let connected_mono = Instant::now();
        let connected_wall = chrono::Utc::now();
        let disconnected_wall_rollback = connected_wall - chrono::TimeDelta::hours(1);
        let correlation_ids = Default::default();
        let metadata = HashMap::new();

        // Production pattern: duration_ms = connected_mono.elapsed(), never
        // (disconnected_wall - connected_wall).
        let duration_ms = connected_mono.elapsed().as_millis() as f64;
        let summary = build_dtls_stream_summary(DtlsDisconnectContext {
            plugin_trigger_decisions: Default::default(),
            namespace: "ferrum",
            proxy_id: "dtls-proxy",
            proxy_name: Some("DTLS Frontend"),
            proxy_lifecycle_generation: None,
            resolved_client: "127.0.0.1:54000".parse().unwrap(),
            consumer_username: None,
            auth_method: None,
            backend_target: "10.0.0.60:7443",
            backend_resolved_ip: Some("10.0.0.60"),
            backend_scheme: BackendScheme::Dtls,
            listen_port: 7443,
            connected_at: connected_wall,
            disconnected_at: disconnected_wall_rollback,
            duration_ms,
            bytes_sent: 16,
            bytes_received: 32,
            connection_error: None,
            error_class: None,
            disconnect_direction: None,
            disconnect_cause: Some(crate::plugins::DisconnectCause::IdleTimeout),
            sni_hostname: None,
            metadata: &metadata,
            correlation_ids: &correlation_ids,
        });
        assert!(
            summary.duration_ms < 5_000.0,
            "Instant elapsed must ignore hour wall rollback; got {}",
            summary.duration_ms
        );
        assert!(
            (disconnected_wall_rollback - connected_wall).num_milliseconds() < 0,
            "fixture must keep a negative wall delta"
        );
        assert_eq!(
            summary.timestamp_connected,
            connected_wall.to_rfc3339(),
            "wall connect preserved for rendering"
        );
        assert_eq!(
            summary.timestamp_disconnected,
            disconnected_wall_rollback.to_rfc3339(),
            "wall disconnect preserved for rendering"
        );

        // Forward civil-clock step: duration still Instant-based (not inflated).
        let disconnected_wall_forward = connected_wall + chrono::TimeDelta::hours(5);
        let duration_forward = connected_mono.elapsed().as_millis() as f64;
        let forward_summary = build_dtls_stream_summary(DtlsDisconnectContext {
            plugin_trigger_decisions: Default::default(),
            namespace: "ferrum",
            proxy_id: "dtls-proxy",
            proxy_name: None,
            proxy_lifecycle_generation: None,
            resolved_client: "127.0.0.1:54000".parse().unwrap(),
            consumer_username: None,
            auth_method: None,
            backend_target: "10.0.0.60:7443",
            backend_resolved_ip: None,
            backend_scheme: BackendScheme::Dtls,
            listen_port: 7443,
            connected_at: connected_wall,
            disconnected_at: disconnected_wall_forward,
            duration_ms: duration_forward,
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: None,
            error_class: None,
            disconnect_direction: None,
            disconnect_cause: None,
            sni_hostname: None,
            metadata: &metadata,
            correlation_ids: &correlation_ids,
        });
        assert!(
            forward_summary.duration_ms < 5_000.0,
            "Instant elapsed must ignore forward wall jump; got {}",
            forward_summary.duration_ms
        );
        assert_eq!(
            forward_summary.timestamp_disconnected,
            disconnected_wall_forward.to_rfc3339()
        );

        // DTLS idle watchdog: injected mono endpoints, independent of wall.
        // Forward wall would have expired an epoch-based watchdog immediately;
        // mono without advance must keep the session alive.
        assert!(
            !udp_idle_expired(1_000, 1_000, 60_000),
            "DTLS idle: no mono advance → not expired"
        );
        assert!(
            !udp_idle_expired(61_000, 1_000, 60_000),
            "DTLS idle: exactly at timeout still alive (strict >)"
        );
        assert!(
            udp_idle_expired(61_001, 1_000, 60_000),
            "DTLS idle: mono past timeout must expire"
        );
        assert!(
            !udp_idle_expired(500, 1_000, 60_000),
            "DTLS idle: mono \"rollback\" saturates — must not freeze forever"
        );
    }

    #[tokio::test]
    async fn test_emit_udp_stream_disconnect_notifies_plugins() {
        let session = make_udp_session();
        session.bytes_sent.store(512, Ordering::Relaxed);
        session.bytes_received.store(1024, Ordering::Relaxed);

        let captured = Arc::new(Mutex::new(Vec::new()));
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(CapturePlugin {
            summaries: Arc::clone(&captured),
        })];

        emit_udp_stream_disconnect(
            &plugins,
            UdpDisconnectContext {
                namespace: "ferrum",
                proxy_id: "udp-proxy",
                proxy_name: Some("UDP Proxy"),
                session: &session,
                backend_scheme: BackendScheme::Dtls,
                listen_port: 7443,
                disconnected_ms: 1_710_000_002_000,
                disconnected_wall_at: chrono::Utc::now(),
                connection_error: Some(STREAM_ERR_BACKEND_DTLS_HANDSHAKE_FAILED.to_string()),
                error_class: Some(crate::retry::ErrorClass::TlsError),
                disconnect_direction: Some(crate::plugins::Direction::BackendToClient),
                disconnect_cause: Some(crate::plugins::DisconnectCause::BackendError),
            },
        )
        .await;

        let summaries = lock(&captured);
        assert_eq!(summaries.len(), 1);
        let summary = &summaries[0];
        assert_eq!(summary.protocol, "dtls");
        assert_eq!(summary.bytes_sent, 512);
        assert_eq!(summary.bytes_received, 1024);
        assert_eq!(summary.listen_port, 7443);
        assert_eq!(
            summary.connection_error.as_deref(),
            Some(STREAM_ERR_BACKEND_DTLS_HANDSHAKE_FAILED)
        );
        assert_eq!(
            summary.error_class,
            Some(crate::retry::ErrorClass::TlsError)
        );
    }

    // --- typed cause/direction tests for DTLS sessions (Gap 2 + Gap 4) ---

    #[test]
    fn typed_dtls_kind_drives_cause_and_direction() {
        use crate::plugins::{Direction, DisconnectCause};
        use crate::proxy::stream_error::{StreamSetupError, StreamSetupKind};
        use crate::retry::ErrorClass;

        // Backend DTLS handshake = backend-side, b2c direction.
        let e: anyhow::Error =
            StreamSetupError::new(StreamSetupKind::BackendDtlsHandshake, ": handshake failed")
                .into();
        assert_eq!(
            dtls_disconnect_cause(&e, &ErrorClass::TlsError),
            DisconnectCause::BackendError
        );
        assert_eq!(
            dtls_disconnect_direction(&e, &ErrorClass::TlsError),
            Direction::BackendToClient
        );
    }

    #[test]
    fn untyped_dtls_session_falls_back_to_class() {
        use crate::plugins::{Direction, DisconnectCause};
        use crate::retry::ErrorClass;

        // Generic recv error from the DTLS session — no typed kind in chain.
        // Falls back to class: ConnectionReset → backend-side / b2c.
        let e: anyhow::Error = anyhow::anyhow!("decrypt error mid-session");
        assert_eq!(
            dtls_disconnect_cause(&e, &ErrorClass::ConnectionReset),
            DisconnectCause::BackendError
        );
        assert_eq!(
            dtls_disconnect_direction(&e, &ErrorClass::ConnectionReset),
            Direction::BackendToClient
        );
    }

    #[test]
    fn typed_kind_overrides_class_for_dtls_too() {
        use crate::plugins::{Direction, DisconnectCause};
        use crate::proxy::stream_error::{StreamSetupError, StreamSetupKind};
        use crate::retry::ErrorClass;

        // RejectedByPlugin (client-side) classified misleadingly as
        // ConnectionReset (which the class fallback calls backend-side).
        // Typed kind must win.
        let e: anyhow::Error =
            StreamSetupError::new(StreamSetupKind::RejectedByPlugin, "(UDP session)").into();
        assert_eq!(
            dtls_disconnect_cause(&e, &ErrorClass::ConnectionReset),
            DisconnectCause::RecvError
        );
        assert_eq!(
            dtls_disconnect_direction(&e, &ErrorClass::ConnectionReset),
            Direction::ClientToBackend
        );
    }

    #[test]
    fn udp_dtls_idle_timeout_maps_to_idle_cause() {
        use crate::plugins::{Direction, DisconnectCause};
        use crate::retry::ErrorClass;

        let e: anyhow::Error = super::UdpDtlsIdleTimeout.into();
        assert_eq!(
            dtls_disconnect_cause(&e, &ErrorClass::ReadWriteTimeout),
            DisconnectCause::IdleTimeout
        );
        assert_eq!(
            dtls_disconnect_direction(&e, &ErrorClass::ReadWriteTimeout),
            Direction::Unknown
        );
    }

    fn test_pending_map() -> super::PendingSessionMap {
        Arc::new(dashmap::DashMap::with_hasher(ahash::RandomState::default()))
    }

    fn test_client_addr() -> std::net::SocketAddr {
        "127.0.0.1:40000".parse().expect("valid addr")
    }

    #[test]
    fn pending_datagram_queue_preserves_order_and_enforces_caps() {
        let mut queue = super::PendingDatagramQueue::default();

        // Zero-length datagrams are valid UDP and must be queued.
        assert!(queue.push_bounded(&[]));
        assert!(queue.push_bounded(&[1]));
        assert!(queue.push_bounded(&[2, 2]));
        assert_eq!(
            queue.datagrams,
            vec![Vec::<u8>::new(), vec![1], vec![2, 2]],
            "queue must preserve arrival order"
        );
        assert_eq!(queue.queued_bytes, 3);

        // Byte cap: a datagram that would exceed the total byte budget is
        // tail-dropped without touching the queue.
        let oversize = vec![0u8; super::PENDING_SESSION_MAX_QUEUED_BYTES];
        assert!(!queue.push_bounded(&oversize));
        assert_eq!(queue.datagrams.len(), 3);
        assert_eq!(queue.queued_bytes, 3);

        // Datagram-count cap: beyond the max entry count everything is
        // tail-dropped, even zero-length datagrams.
        for _ in queue.datagrams.len()..super::PENDING_SESSION_MAX_QUEUED_DATAGRAMS {
            assert!(queue.push_bounded(&[7]));
        }
        assert!(!queue.push_bounded(&[8]));
        assert!(!queue.push_bounded(&[]));
        assert_eq!(
            queue.datagrams.len(),
            super::PENDING_SESSION_MAX_QUEUED_DATAGRAMS
        );
    }

    #[tokio::test]
    async fn session_hook_ingress_enqueue_enforces_byte_and_count_caps() {
        let metrics = Arc::new(super::UdpProxyMetrics::default());
        let (tx, mut rx) = tokio::sync::mpsc::channel(super::SESSION_HOOK_INGRESS_MAX_DATAGRAMS);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let mut session = make_udp_session();
        session.hook_ingress_tx = std::sync::Mutex::new(Some(tx));
        session.hook_ingress_queued_bytes = Arc::clone(&queued_bytes);

        assert!(super::enqueue_session_hook_datagram(
            &session,
            b"one",
            metrics.as_ref()
        ));
        assert_eq!(queued_bytes.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.hook_ingress_drops.load(Ordering::Relaxed), 0);

        // Byte cap: refuse a datagram that would exceed the retained-byte bound.
        let oversize = vec![0u8; super::SESSION_HOOK_INGRESS_MAX_QUEUED_BYTES];
        assert!(!super::enqueue_session_hook_datagram(
            &session,
            &oversize,
            metrics.as_ref()
        ));
        assert_eq!(queued_bytes.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.hook_ingress_drops.load(Ordering::Relaxed), 1);

        // Listener cap: refuse payload even when this session has capacity.
        metrics.hook_ingress_queued_bytes.store(
            super::LISTENER_HOOK_INGRESS_MAX_QUEUED_BYTES - 1,
            Ordering::Relaxed,
        );
        assert!(!super::enqueue_session_hook_datagram(
            &session,
            b"two",
            metrics.as_ref()
        ));
        assert_eq!(queued_bytes.load(Ordering::Relaxed), 3);
        metrics
            .hook_ingress_queued_bytes
            .store(3, Ordering::Relaxed);

        // Drain the admitted payload so the channel is empty for the count test.
        let first = rx.recv().await.expect("admitted datagram");
        assert_eq!(&first[..], b"one");
        queued_bytes.fetch_sub(first.len(), Ordering::Relaxed);
        metrics
            .hook_ingress_queued_bytes
            .fetch_sub(first.len(), Ordering::Relaxed);

        // Fill to the datagram-count bound, then the next must fail closed.
        for i in 0..super::SESSION_HOOK_INGRESS_MAX_DATAGRAMS {
            assert!(
                super::enqueue_session_hook_datagram(&session, &[i as u8], metrics.as_ref()),
                "datagram {i} must fit under the count cap"
            );
        }
        assert!(!super::enqueue_session_hook_datagram(
            &session,
            b"overflow",
            metrics.as_ref()
        ));
        assert_eq!(metrics.hook_ingress_drops.load(Ordering::Relaxed), 3);

        // Closing the sender fails closed (worker gone / session torn down).
        session.close_hook_ingress();
        assert!(!super::enqueue_session_hook_datagram(
            &session,
            b"after-close",
            metrics.as_ref()
        ));
        assert_eq!(metrics.hook_ingress_drops.load(Ordering::Relaxed), 4);
    }

    /// The hook-ingress worker must not wait on `stop_notify`: that Notify's
    /// `notify_one` permit is dedicated to the backend reply task. Cleanup
    /// wakes the idle hook worker via sender close instead.
    #[tokio::test(start_paused = true)]
    async fn hook_ingress_worker_does_not_consume_reply_stop_notify() {
        let metrics = Arc::new(super::UdpProxyMetrics::default());
        let (tx, rx) = tokio::sync::mpsc::channel(super::SESSION_HOOK_INGRESS_MAX_DATAGRAMS);
        let mut raw = make_udp_session();
        raw.hook_ingress_tx = std::sync::Mutex::new(Some(tx));
        let session = Arc::new(raw);
        let client_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();

        super::spawn_session_hook_ingress_worker(
            Arc::clone(&session),
            rx,
            Arc::clone(&metrics),
            client_addr,
        );

        let waiter = {
            let session = Arc::clone(&session);
            tokio::spawn(async move {
                super::udp_reply_recv_until_stop(
                    &session.stop_reply_task,
                    session.stop_notify.as_ref(),
                    std::future::pending::<()>(),
                    std::future::pending::<()>(),
                )
                .await
            })
        };

        // Park the reply waiter on Notify (hook worker must stay on channel recv).
        tokio::task::yield_now().await;

        super::signal_udp_reply_task_stop(&session.stop_reply_task, session.stop_notify.as_ref());

        let outcome = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("reply stop notify must wake the reply waiter, not the hook worker")
            .expect("reply waiter task panicked");
        assert!(
            outcome.is_none(),
            "reply-task stop branch must win over pending backend recv"
        );

        // Idle hook worker wakes from sender closure (not from stop_notify).
        session.close_hook_ingress();
        tokio::task::yield_now().await;
        assert_eq!(
            session.hook_ingress_queued_bytes.load(Ordering::Relaxed),
            0,
            "idle stop must leave queued-byte accounting clean"
        );
    }

    /// Gated plugin: hold the first hook, queue residuals, then expire/stop
    /// before release. The in-flight datagram must not forward after the hook
    /// returns, and residuals must drain without further hook invocations.
    #[tokio::test(start_paused = true)]
    async fn hook_ingress_worker_skips_forward_and_residual_hooks_after_stop() {
        let (entered_tx, entered_rx) = oneshot::channel::<()>();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let hook_calls = Arc::new(AtomicUsize::new(0));
        let plugin = Arc::new(GatedHookIngressPlugin {
            entered: std::sync::Mutex::new(Some(entered_tx)),
            release: tokio::sync::Mutex::new(Some(release_rx)),
            calls: Arc::clone(&hook_calls),
        });

        let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let session_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        session_sock
            .connect(backend.local_addr().unwrap())
            .await
            .unwrap();

        let metrics = Arc::new(super::UdpProxyMetrics::default());
        let (tx, rx) = tokio::sync::mpsc::channel(super::SESSION_HOOK_INGRESS_MAX_DATAGRAMS);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let mut raw = make_udp_session();
        raw.backend_socket = Some(session_sock);
        raw.datagram_plugins = Arc::from([plugin as Arc<dyn Plugin>]);
        raw.hook_ingress_tx = std::sync::Mutex::new(Some(tx));
        raw.hook_ingress_queued_bytes = Arc::clone(&queued_bytes);
        let session = Arc::new(raw);
        let client_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();

        super::spawn_session_hook_ingress_worker(
            Arc::clone(&session),
            rx,
            Arc::clone(&metrics),
            client_addr,
        );

        assert!(super::enqueue_session_hook_datagram(
            &session,
            b"first",
            metrics.as_ref()
        ));
        tokio::time::timeout(Duration::from_secs(1), entered_rx)
            .await
            .expect("worker must enter the gated hook")
            .expect("entered oneshot dropped");

        // Residuals arrive while the first hook is still awaiting.
        assert!(super::enqueue_session_hook_datagram(
            &session,
            b"second",
            metrics.as_ref()
        ));
        assert!(super::enqueue_session_hook_datagram(
            &session,
            b"third",
            metrics.as_ref()
        ));
        assert_eq!(
            queued_bytes.load(Ordering::Relaxed),
            b"first".len() + b"second".len() + b"third".len(),
            "the in-flight hook payload must remain charged with queued residuals"
        );
        assert_eq!(
            metrics.hook_ingress_queued_bytes.load(Ordering::Relaxed),
            b"first".len() + b"second".len() + b"third".len(),
            "listener admission must include the in-flight hook payload"
        );

        session
            .expired
            .store(true, std::sync::atomic::Ordering::Release);
        super::signal_udp_reply_task_stop(&session.stop_reply_task, session.stop_notify.as_ref());
        session.close_hook_ingress();

        for _ in 0..64 {
            if queued_bytes.load(Ordering::Relaxed) == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            queued_bytes.load(Ordering::Relaxed),
            0,
            "stopped worker must drain residual queued-byte accounting"
        );

        assert_eq!(
            hook_calls.load(Ordering::Relaxed),
            1,
            "residuals after stop must not run hooks"
        );
        assert!(
            release_tx.send(()).is_err(),
            "stopping the session must cancel the in-flight hook future"
        );
        assert_eq!(
            metrics.hook_ingress_queued_bytes.load(Ordering::Relaxed),
            0,
            "stopped worker must release the listener-wide byte budget"
        );
        assert_eq!(
            metrics.datagrams_out.load(Ordering::Relaxed),
            0,
            "expired/stopped session must not forward post-hook or residual datagrams"
        );
        assert_eq!(
            metrics.bytes_out.load(Ordering::Relaxed),
            0,
            "no backend bytes after stop"
        );

        let mut buf = [0u8; 64];
        assert!(
            matches!(
                backend.try_recv(&mut buf),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
            ),
            "backend must not observe a late forward after stop"
        );
    }

    /// Holds the first `on_udp_datagram` until `release` fires (after signaling
    /// `entered`). Counts hook invocations for residual-skip assertions.
    struct GatedHookIngressPlugin {
        entered: std::sync::Mutex<Option<oneshot::Sender<()>>>,
        release: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Plugin for GatedHookIngressPlugin {
        fn name(&self) -> &str {
            "test_gated_hook_ingress"
        }

        fn requires_udp_datagram_hooks(&self) -> bool {
            true
        }

        async fn on_udp_datagram(&self, _ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if let Some(tx) = self
                .entered
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                let _ = tx.send(());
            }
            if let Some(release) = self.release.lock().await.take() {
                let _ = release.await;
            }
            UdpDatagramVerdict::Forward
        }
    }

    #[test]
    fn take_pending_datagrams_drains_in_order_then_removes_gate() {
        let pending = test_pending_map();
        let addr = test_client_addr();

        // Absent entry: nothing to drain, nothing inserted.
        assert!(super::take_pending_datagrams(&pending, addr).is_none());
        assert!(!pending.contains_key(&addr));

        pending.insert(addr, super::PendingDatagramQueue::default());
        {
            let mut entry = pending.get_mut(&addr).expect("gate present");
            assert!(entry.push_bounded(&[1]));
            assert!(entry.push_bounded(&[2]));
        }

        // First take hands off the queued batch in arrival order and leaves
        // the gate in place so concurrent arrivals keep queueing.
        let batch = super::take_pending_datagrams(&pending, addr).expect("queued batch");
        assert_eq!(batch, vec![vec![1], vec![2]]);
        assert!(
            pending.contains_key(&addr),
            "gate must survive a non-empty take"
        );

        // A datagram that "arrived during the drain" is returned by the next
        // take, byte accounting reset in between.
        {
            let mut entry = pending.get_mut(&addr).expect("gate present");
            assert_eq!(entry.queued_bytes, 0, "take must reset byte accounting");
            assert!(entry.push_bounded(&[3]));
        }
        let batch = super::take_pending_datagrams(&pending, addr).expect("late batch");
        assert_eq!(batch, vec![vec![3]]);

        // Empty queue: the gate is removed atomically and the drain ends.
        assert!(super::take_pending_datagrams(&pending, addr).is_none());
        assert!(
            !pending.contains_key(&addr),
            "empty take must remove the pending gate"
        );
    }

    #[test]
    fn pending_session_gate_drops_queue_unless_disarmed() {
        let pending = test_pending_map();
        let addr = test_client_addr();

        // Armed gate (setup failure path): entry and queued datagrams removed.
        pending.insert(addr, super::PendingDatagramQueue::default());
        {
            let _gate = super::PendingSessionGate {
                pending_sessions: Arc::clone(&pending),
                client_addr: addr,
                armed: true,
            };
        }
        assert!(
            !pending.contains_key(&addr),
            "armed gate must remove the pending entry on drop"
        );

        // Disarmed gate (successful handoff): entry left alone.
        pending.insert(addr, super::PendingDatagramQueue::default());
        {
            let mut gate = super::PendingSessionGate {
                pending_sessions: Arc::clone(&pending),
                client_addr: addr,
                armed: true,
            };
            gate.disarm();
        }
        assert!(
            pending.contains_key(&addr),
            "disarmed gate must not touch the map"
        );
    }

    #[test]
    fn pending_session_gate_limit_does_not_consume_active_session_slots() {
        let pending = test_pending_map();
        let metrics = Arc::new(super::UdpProxyMetrics::default());
        let first = test_client_addr();
        let second: SocketAddr = "127.0.0.1:40001".parse().expect("valid addr");

        assert!(super::try_insert_pending_session_gate(&pending, first, 1, None).unwrap());
        let err = super::try_insert_pending_session_gate(&pending, second, 1, None)
            .expect_err("second pending gate should hit pending limit");

        assert!(
            err.to_string()
                .contains("UDP pending session limit reached"),
            "unexpected error: {err}"
        );
        assert_eq!(
            metrics.active_sessions.load(Ordering::Relaxed),
            0,
            "pending gates must not consume active session capacity before policy checks pass"
        );
    }

    #[test]
    fn active_session_cap_reached_short_circuits_before_pending_gate() {
        let metrics = Arc::new(super::UdpProxyMetrics::default());

        // Below the cap: capacity is available.
        assert!(!super::udp_active_session_cap_reached(&metrics, 1));

        // At the cap: a new source must be reported as over-capacity so the recv
        // loop drops it before creating a pending gate or running policy.
        let reservation = reserve_udp_session_slot(&metrics, 1).unwrap();
        assert_eq!(metrics.active_sessions.load(Ordering::Relaxed), 1);
        assert!(
            super::udp_active_session_cap_reached(&metrics, 1),
            "a maxed-out listener must report the active-session cap as reached"
        );

        // The check itself is non-consuming — it neither reserves nor releases.
        assert_eq!(
            metrics.active_sessions.load(Ordering::Relaxed),
            1,
            "the active-cap check must not mutate the active-session count"
        );

        drop(reservation);
        assert!(
            !super::udp_active_session_cap_reached(&metrics, 1),
            "freeing the slot must reopen capacity for new sessions"
        );
    }

    #[test]
    fn udp_session_slot_reservation_releases_unclaimed_slot_on_drop() {
        let metrics = Arc::new(super::UdpProxyMetrics::default());

        {
            let _reservation = reserve_udp_session_slot(&metrics, 1).unwrap();
            assert_eq!(metrics.active_sessions.load(Ordering::Relaxed), 1);
        }

        assert_eq!(
            metrics.active_sessions.load(Ordering::Relaxed),
            0,
            "dropping an unclaimed UDP session reservation must release the active slot"
        );
    }

    #[test]
    fn udp_session_slot_reservation_disarm_transfers_slot_to_session() {
        let metrics = Arc::new(super::UdpProxyMetrics::default());
        let mut reservation = reserve_udp_session_slot(&metrics, 1).unwrap();
        reservation.disarm();
        drop(reservation);

        assert_eq!(
            metrics.active_sessions.load(Ordering::Relaxed),
            1,
            "disarmed reservations are owned by the created session lifecycle"
        );
        metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    // --- OverloadState.active_connections parity (UDP <-> TCP/H3) ---

    /// Build a `UdpSession` that holds a real `ConnectionGuard` against
    /// `state`. Mirrors the production construction in `create_session()` —
    /// every field except the guard is filler. This is the smallest faithful
    /// reproduction of the production code path that exercises the guard
    /// lifecycle without spinning up a UDP listener.
    fn make_udp_session_with_overload(state: &Arc<crate::overload::OverloadState>) -> UdpSession {
        UdpSession {
            plugin_trigger_decisions: Default::default(),
            backend_socket: None,
            dtls_conn: None,
            last_activity: AtomicU64::new(0),
            created_at: AtomicU64::new(0),
            connected_wall_at: chrono::Utc::now(),
            expired: std::sync::atomic::AtomicBool::new(false),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            last_request_size: AtomicU64::new(0),
            response_budget_remaining: AtomicU64::new(0),
            amplification_factor: None,
            backend_target: "10.0.0.50:5353".to_string(),
            backend_resolved_ip: "10.0.0.50".to_string(),
            sni_hostname: None,
            consumer_username: None,
            auth_method: None,
            metadata: std::sync::Mutex::new(HashMap::new()),
            correlation_ids: Default::default(),
            local_addr: std::sync::OnceLock::new(),
            plugins: Arc::new(Vec::new()),
            datagram_plugins: Arc::from([]),
            datagram_client_ip: Arc::from("127.0.0.1"),
            forwarded_client: None,
            datagram_proxy_id: Arc::from("udp-proxy"),
            datagram_proxy_name: Some(Arc::from("UDP Proxy")),
            datagram_payload_kind: crate::plugins::StreamBytesKind::PlaintextWire,
            proxy_id: "udp-proxy".to_string(),
            proxy_name: Some("UDP Proxy".to_string()),
            proxy_lifecycle_generation: None,
            proxy_namespace: "ferrum".to_string(),
            backend_scheme: BackendScheme::Udp,
            listen_port: 5300,
            idle_timeout_ms: 60_000,
            stop_reply_task: std::sync::atomic::AtomicBool::new(false),
            stop_notify: Arc::new(tokio::sync::Notify::new()),
            overload_guard: std::sync::Mutex::new(Some(crate::overload::ConnectionGuard::new(
                state,
            ))),
            hook_ingress_tx: std::sync::Mutex::new(None),
            hook_ingress_queued_bytes: Arc::new(AtomicUsize::new(0)),
            hook_ingress_stop_notify: Arc::new(tokio::sync::Notify::new()),
            // Unauthenticated by default: the authorization contract does not
            // bound a session that admitted no principal.
            authorization: None,
        }
    }

    #[test]
    fn udp_session_increments_overload_active_connections_on_create() {
        let state = Arc::new(crate::overload::OverloadState::new());
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);

        let session = make_udp_session_with_overload(&state);
        assert_eq!(
            state.active_connections.load(Ordering::Relaxed),
            1,
            "creating a UDP session must increment OverloadState.active_connections (parity with TCP/H3)"
        );

        drop(session);
        assert_eq!(
            state.active_connections.load(Ordering::Relaxed),
            0,
            "dropping the UDP session must release the global connection slot"
        );
    }

    #[test]
    fn udp_session_overload_guard_can_release_before_last_arc_drop() {
        let state = Arc::new(crate::overload::OverloadState::new());
        let session = Arc::new(make_udp_session_with_overload(&state));
        let cached = Arc::clone(&session);
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);

        session.release_overload_guard();
        assert_eq!(
            state.active_connections.load(Ordering::Relaxed),
            0,
            "session expiry must release overload pressure even if a cache still holds an Arc"
        );

        cached.release_overload_guard();
        drop(session);
        drop(cached);
        assert_eq!(
            state.active_connections.load(Ordering::Relaxed),
            0,
            "early release must be idempotent and not double-decrement on drop"
        );
    }

    #[test]
    fn udp_session_caches_datagram_plugin_context_strings() {
        let session = make_udp_session();

        assert_eq!(session.datagram_client_ip.as_ref(), "127.0.0.1");
        assert_eq!(session.datagram_proxy_id.as_ref(), "udp-proxy");
        assert_eq!(
            session
                .datagram_proxy_name
                .as_ref()
                .map(|name| name.as_ref()),
            Some("UDP Proxy")
        );
    }

    #[test]
    fn udp_session_shard_amount_uses_pool_sharding_helper() {
        assert_eq!(udp_session_shard_amount(3), 4);
        assert_eq!(
            udp_session_shard_amount(0),
            crate::util::sharding::pool_shard_amount(0)
        );
    }

    #[test]
    fn preselected_udp_backend_target_is_reused() {
        let config = GatewayConfig::default();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let proxy: Proxy = serde_yaml::from_str(
            r#"
id: udp-proxy
backend_scheme: udp
backend_host: direct.local
backend_port: 5353
listen_port: 5300
"#,
        )
        .unwrap();

        let (host, port) = resolve_or_reuse_backend_target(
            Some(("admitted.local".to_string(), 5354)),
            &proxy,
            &snapshot,
            &HealthChecker::new(),
            "127.0.0.1",
        )
        .unwrap();

        assert_eq!(host, "admitted.local");
        assert_eq!(port, 5354);
    }

    #[test]
    fn resolve_udp_backend_target_hashes_port_lane_by_client_key() {
        let mut config: GatewayConfig = serde_json::from_value(serde_json::json!({
            "version": "1",
            "proxies": [{
                "id": "udp-proxy",
                "backend_scheme": "udp",
                "backend_host": "unused.local",
                "backend_port": 0,
                "listen_port": 5300,
                "upstream_id": "dns",
            }],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "dns",
                "algorithm": "round_robin",
                "targets": [
                    { "host": "a.local", "port": 5353 },
                    { "host": "b.local", "port": 5353 }
                ],
                "port_overrides": {
                    "5353": { "algorithm": "consistent_hashing" }
                }
            }]
        }))
        .expect("gateway config should deserialize");
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies[0].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let mut hosts = std::collections::HashSet::new();
        for i in 1..=64 {
            let key = format!("192.0.2.{i}");
            let (host, port) =
                super::resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), &key)
                    .expect("target selected");
            assert_eq!(port, 5353);
            hosts.insert(host);
        }

        assert!(
            hosts.contains("a.local") && hosts.contains("b.local"),
            "per-port UDP consistent hashing must use the session key, not a constant proxy id: {hosts:?}"
        );
    }

    #[test]
    fn udp_lb_hash_key_canonicalizes_ipv4_mapped_clients() {
        let mapped: std::net::IpAddr = "::ffff:192.0.2.10".parse().expect("mapped IPv4");
        let plain: std::net::IpAddr = "192.0.2.10".parse().expect("plain IPv4");
        let v6: std::net::IpAddr = "2001:db8::10".parse().expect("plain IPv6");

        assert_eq!(
            super::udp_lb_hash_key_for_client_ip(mapped),
            super::udp_lb_hash_key_for_client_ip(plain),
            "IPv4-mapped UDP clients must hash like their plain IPv4 form"
        );
        assert_eq!(super::udp_lb_hash_key_for_client_ip(v6), "2001:db8::10");
    }

    #[test]
    fn resolve_udp_backend_target_rejects_port_lane_for_least_connections() {
        let mut config: GatewayConfig = serde_json::from_value(serde_json::json!({
            "version": "1",
            "proxies": [{
                "id": "udp-proxy",
                "backend_scheme": "udp",
                "backend_host": "unused.local",
                "backend_port": 0,
                "listen_port": 5300,
                "upstream_id": "dns",
            }],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "dns",
                "algorithm": "round_robin",
                "targets": [
                    { "host": "a.local", "port": 5353 },
                    { "host": "b.local", "port": 5353 }
                ],
                "port_overrides": {
                    "5353": { "algorithm": "least_connections" }
                }
            }]
        }))
        .expect("gateway config should deserialize");
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies[0].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let err =
            super::resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
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
    fn resolve_udp_backend_target_rejects_port_lane_for_least_latency() {
        let mut config: GatewayConfig = serde_json::from_value(serde_json::json!({
            "version": "1",
            "proxies": [{
                "id": "udp-proxy",
                "backend_scheme": "udp",
                "backend_host": "unused.local",
                "backend_port": 0,
                "listen_port": 5300,
                "upstream_id": "dns",
            }],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "dns",
                "algorithm": "round_robin",
                "targets": [
                    { "host": "a.local", "port": 5353 },
                    { "host": "b.local", "port": 5353 }
                ],
                "port_overrides": {
                    "5353": { "algorithm": "least_latency" }
                }
            }]
        }))
        .expect("gateway config should deserialize");
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies[0].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let err =
            super::resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
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
    fn resolve_udp_backend_target_rejects_port_lane_for_non_ip_hash_on() {
        let mut config: GatewayConfig = serde_json::from_value(serde_json::json!({
            "version": "1",
            "proxies": [{
                "id": "udp-proxy",
                "backend_scheme": "udp",
                "backend_host": "unused.local",
                "backend_port": 0,
                "listen_port": 5300,
                "upstream_id": "dns",
            }],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "dns",
                "algorithm": "round_robin",
                "targets": [
                    { "host": "a.local", "port": 5353 },
                    { "host": "b.local", "port": 5353 }
                ],
                "port_overrides": {
                    "5353": {
                        "algorithm": "consistent_hashing",
                        "hash_on": "cookie:ferrum-affinity"
                    }
                }
            }]
        }))
        .expect("gateway config should deserialize");
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies[0].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let err =
            super::resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
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
    fn resolve_udp_backend_target_rejects_port_lane_for_inherited_non_ip_hash_on() {
        let mut config: GatewayConfig = serde_json::from_value(serde_json::json!({
            "version": "1",
            "proxies": [{
                "id": "udp-proxy",
                "backend_scheme": "udp",
                "backend_host": "unused.local",
                "backend_port": 0,
                "listen_port": 5300,
                "upstream_id": "dns",
            }],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "dns",
                "algorithm": "round_robin",
                "hash_on": "header:x-user-id",
                "targets": [
                    { "host": "a.local", "port": 5353 },
                    { "host": "b.local", "port": 5353 }
                ],
                "port_overrides": {
                    "5353": { "algorithm": "consistent_hashing" }
                }
            }]
        }))
        .expect("gateway config should deserialize");
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies[0].clone();
        let cache = LoadBalancerCache::new(&config);
        let snapshot = cache.load();

        let err =
            super::resolve_backend_target(&proxy, &snapshot, &HealthChecker::new(), "192.0.2.10")
                .expect_err("inherited stream hash_on header must be rejected explicitly");
        let setup = find_stream_setup_error(&err).expect("typed stream setup error");

        assert_eq!(setup.kind, StreamSetupKind::UnsupportedStreamPolicy);
        assert!(
            setup.message.contains("source-IP hash keys"),
            "error should make the inherited unsupported hash key explicit: {}",
            setup.message
        );
    }

    #[test]
    fn multiple_udp_sessions_track_concurrent_load() {
        let state = Arc::new(crate::overload::OverloadState::new());

        let s1 = make_udp_session_with_overload(&state);
        let s2 = make_udp_session_with_overload(&state);
        let s3 = make_udp_session_with_overload(&state);
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 3);

        // Drop in non-LIFO order to exercise per-session ownership.
        drop(s2);
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 2);

        drop(s1);
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);

        drop(s3);
        assert_eq!(
            state.active_connections.load(Ordering::Relaxed),
            0,
            "all UDP sessions released — global counter must return to 0"
        );
    }

    #[test]
    fn udp_session_decrement_via_arc_unwrap_lifecycle() {
        // The production code stores sessions as `Arc<UdpSession>` in the
        // session map and clones them into the recv-loop fast-path cache and
        // the spawned reply task. The guard must only fire when the LAST Arc
        // is dropped. Verify Arc ref-counting interacts correctly.
        let state = Arc::new(crate::overload::OverloadState::new());

        let session = Arc::new(make_udp_session_with_overload(&state));
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);

        let cloned = session.clone();
        let cloned2 = session.clone();
        // Cloning the Arc must not double-count.
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);

        drop(cloned);
        drop(cloned2);
        // Dropping clones leaves one Arc — guard still alive.
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);

        drop(session);
        // Last Arc dropped → UdpSession dropped → guard dropped → counter 0.
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
    }
}
