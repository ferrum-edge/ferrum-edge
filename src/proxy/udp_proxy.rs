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

use dashmap::DashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, trace, warn};

use crate::circuit_breaker::CircuitBreakerCache;
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
use crate::proxy::stream_error::{StreamSetupError, StreamSetupKind, find_stream_setup_error};
use crate::request_epoch::{RequestEpoch, RequestEpochStore};

/// Maximum datagram size for UDP forwarding.
const MAX_UDP_DATAGRAM_SIZE: usize = 65535;

/// Bounded client→backend forward queue depth when datagram plugin hooks are
/// opted in. Keeps the shared recv loop non-blocking (try_send) while preserving
/// per-session hook ordering; overflow drops are UDP-best-effort / fail-closed
/// under backpressure.
const CLIENT_FORWARD_CHANNEL_CAP: usize = 256;

/// Datagram handed from the shared recv loop to a per-session forward task when
/// `on_udp_datagram` hooks are configured for the session.
struct ClientForwardDatagram {
    data: Vec<u8>,
    local_addr: Option<crate::socket_opts::PktinfoLocal>,
}

/// Canonical identity used at every UDP/DTLS session-admission boundary.
pub fn udp_session_client_ip(client_addr: SocketAddr) -> Arc<str> {
    Arc::from(client_addr.ip().to_canonical().to_string())
}

/// Maximum response payload allowed by the UDP amplification guard.
///
/// A zero-length request receives an explicit one-byte reply allowance so the
/// legal datagram does not create a black-holed session. Nonempty requests keep
/// the configured payload ratio exactly.
pub fn udp_amplification_response_budget(request_size: u64, factor: f32) -> u64 {
    if request_size == 0 {
        1
    } else {
        (request_size as f64 * factor as f64) as u64
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
    /// Immutable authoritative correlation ownership captured after admission.
    /// Per-datagram hooks mutate only `metadata`; disconnect-summary construction
    /// re-projects this state after cloning that final writable map.
    correlation_ids: CorrelationIdState,
    /// Plugins and proxy metadata resolved from the RequestEpoch used to create this session.
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
    datagram_plugins: Arc<[Arc<dyn Plugin>]>,
    datagram_client_ip: Arc<str>,
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
    stop_reply_task: std::sync::atomic::AtomicBool,
    stop_notify: Arc<tokio::sync::Notify>,
    /// When `Some`, established-session client→backend datagrams (and their
    /// plugin hooks) are enqueued here instead of being awaited inline on the
    /// shared listener recv loop. `None` when no datagram hooks are configured
    /// so the zero-plugin fast path stays allocation-free and inline.
    client_forward_tx: Option<mpsc::Sender<ClientForwardDatagram>>,
    /// RAII guard that increments [`crate::overload::OverloadState::active_connections`]
    /// on construction and decrements on drop. Each UDP session counts as one
    /// connection toward the global pressure-shedding threshold so pure-UDP
    /// gateways and mixed deployments contribute correctly to overload state
    /// (parity with TCP/H3, which carry their own `ConnectionGuard` in the
    /// per-connection task). Removal paths take the guard before the final
    /// `Arc<UdpSession>` drops so listener-local caches cannot pin the global
    /// overload counter past session expiry.
    overload_guard: std::sync::Mutex<Option<crate::overload::ConnectionGuard>>,
}

impl UdpSession {
    fn release_overload_guard(&self) {
        let mut guard = self
            .overload_guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.take();
    }
}

/// UDP session map using ahash (AES-NI accelerated) for faster per-datagram lookups.
/// SocketAddr keys are kernel-provided (not attacker-controlled), so cryptographic
/// hashing is unnecessary — speed wins here.
type SessionMap = Arc<DashMap<SocketAddr, Arc<UdpSession>, ahash::RandomState>>;
type BackendDtlsConfigCache = Arc<BackendDtlsConfigCacheState>;

/// Listener-local cache of built backend DTLS params keyed by the inputs that
/// affect the resulting config. The key is path/options-based, so it cannot
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

/// Bounded FIFO of datagrams that arrived for a source while its session
/// setup (DNS, `on_stream_connect` plugins, backend DTLS handshake) is still
/// running in the background task. The previous synchronous setup path left
/// these packets in the kernel socket buffer and forwarded them after setup;
/// this queue preserves that behavior without blocking the recv loop.
#[derive(Default)]
struct PendingDatagramQueue {
    datagrams: Vec<Vec<u8>>,
    queued_bytes: usize,
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

/// Insert a pending-session gate for a new source without consuming an active
/// session slot. The active slot is reserved only after first-datagram plugin
/// checks and mesh destination enforcement admit the flow.
fn try_insert_pending_session_gate(
    pending_sessions: &PendingSessionMap,
    client_addr: SocketAddr,
    max_sessions: usize,
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
            vacant.insert(PendingDatagramQueue::default());
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
    epoch: &RequestEpoch,
    initial_data: &[u8],
    sni_proxy_ids: Option<&[String]>,
    listen_port: u16,
) -> Result<UdpSessionEpochView, anyhow::Error> {
    let base_proxy = epoch
        .proxy_by_id(listener_proxy_id)
        .ok_or_else(|| anyhow::anyhow!("Proxy {} not found", listener_proxy_id))?;

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

    let resolved_proxy_id = if let Some(sni_ids) = sni_proxy_ids {
        super::sni::resolve_proxy_by_sni_in_epoch(sni_hostname.as_deref(), sni_ids, epoch)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No matching passthrough proxy for SNI {:?} on port {}",
                    sni_hostname,
                    listen_port
                )
            })?
    } else {
        listener_proxy_id
    };

    let proxy = epoch
        .proxy_by_id(resolved_proxy_id)
        .ok_or_else(|| anyhow::anyhow!("Proxy {} not found", resolved_proxy_id))?
        .clone();
    let plugins = epoch
        .plugin_cache
        .get_plugins_for_protocol(&proxy.id, ProxyProtocol::Udp);
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
    client_addr: SocketAddr,
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
fn udp_idle_expired(now_mono_ms: u64, last_activity_ms: u64, idle_timeout_ms: u64) -> bool {
    now_mono_ms.saturating_sub(last_activity_ms) > idle_timeout_ms
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
        proxy_name: context.proxy_name.map(|name| name.to_string()),
        client_ip: context.client_addr.ip().to_canonical().to_string(),
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
    client_addr: SocketAddr,
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
}

fn build_dtls_stream_summary(context: DtlsDisconnectContext<'_>) -> StreamTransactionSummary {
    let metadata =
        finalize_stream_summary_metadata(context.metadata.clone(), context.correlation_ids);

    StreamTransactionSummary {
        namespace: context.namespace.to_string(),
        proxy_id: context.proxy_id.to_string(),
        proxy_lifecycle_generation: context.proxy_lifecycle_generation,
        proxy_name: context.proxy_name.map(|name| name.to_string()),
        client_ip: context.client_addr.ip().to_canonical().to_string(),
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
#[cfg(target_os = "linux")]
async fn direct_send_to_client(
    frontend: &Arc<UdpSocket>,
    data: &[u8],
    client_addr: SocketAddr,
    local: Option<crate::socket_opts::PktinfoLocal>,
) -> std::io::Result<usize> {
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
        return frontend.send_to(data, client_addr).await;
    };
    let (dest, dest_len) = super::udp_batch::std_to_sockaddr_storage(client_addr);
    loop {
        match crate::socket_opts::send_with_pktinfo(
            frontend.as_raw_fd(),
            data,
            local,
            &dest,
            dest_len,
            None,
        ) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                frontend.writable().await?;
            }
            other => return other,
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

/// Queue `data` into `send_batch`, flushing once if the batch is full. Datagrams
/// that exceed the per-slot size (or still refuse after a flush) take the
/// pktinfo-aware direct-send path so oversized replies are never truncated or
/// silently dropped.
#[cfg(target_os = "linux")]
async fn push_sendmmsg_or_direct(
    send_batch: &mut super::udp_batch::SendMmsgBatch,
    frontend: &Arc<UdpSocket>,
    client_addr: SocketAddr,
    data: &[u8],
    local_ip: Option<crate::socket_opts::PktinfoLocal>,
    proxy_id: &str,
    send_drops: &mut UdpReplySendDrops,
) {
    use std::os::unix::io::AsRawFd;
    if send_batch.push_with_local(data, client_addr, local_ip) {
        return;
    }
    if !send_batch.is_empty() {
        let _ = flush_sendmmsg_best_effort(send_batch, frontend.as_raw_fd(), send_drops);
        if send_batch.push_with_local(data, client_addr, local_ip) {
            return;
        }
    }
    debug!(
        proxy_id = %proxy_id,
        client = %client_addr,
        size = data.len(),
        "sendmmsg push refused datagram, sending directly"
    );
    if let Err(e) = direct_send_to_client(frontend, data, client_addr, local_ip).await {
        send_drops.record_datagram(data.len());
        warn!(
            proxy_id = %proxy_id,
            client = %client_addr,
            size = data.len(),
            error = %e,
            "UDP fallback direct-send failed; datagram lost"
        );
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
) {
    use std::os::unix::io::AsRawFd;

    if gso_batch.push(data) {
        return;
    }
    // Batch full or size-mismatch — flush current batch and try once more.
    match flush_gso_batch(gso_batch, frontend, client_addr, local_ip) {
        Ok(_) => {
            if !gso_batch.push(data) {
                // Post-flush push still refused (zero-length or oversize /
                // >max_bytes — GSO cannot represent either). Send it directly
                // as a single datagram through the pktinfo-aware path so the
                // reply still leaves with the captured source address.
                debug!(
                    proxy_id = %proxy_id,
                    client = %client_addr,
                    size = data.len(),
                    "GSO post-flush push refused datagram, sending directly"
                );
                if let Err(e) = direct_send_to_client(frontend, data, client_addr, local_ip).await {
                    send_drops.record_datagram(data.len());
                    warn!(
                        proxy_id = %proxy_id,
                        client = %client_addr,
                        size = data.len(),
                        error = %e,
                        "UDP fallback direct-send failed; datagram lost"
                    );
                }
            }
        }
        Err(e) => {
            // GSO sendmsg itself failed — abandon GSO for this session.
            debug!(
                proxy_id = %proxy_id,
                client = %client_addr,
                "GSO send failed ({}), falling back to sendmmsg",
                e
            );
            *gso_failed = true;
            // Drain already-buffered GSO datagrams through sendmmsg. Loop because
            // `drain_to_sendmmsg` may partially fill `send_batch`, or leave an
            // oversize head that must take the direct-send path.
            loop {
                let drained = gso_batch.drain_to_sendmmsg(send_batch, client_addr, local_ip);
                if gso_batch.is_empty() {
                    break;
                }
                if send_batch.is_empty() && drained == 0 {
                    if let Some(seg) = gso_batch.take_front_segment() {
                        if let Err(e) =
                            direct_send_to_client(frontend, &seg, client_addr, local_ip).await
                        {
                            send_drops.record_datagram(seg.len());
                            warn!(
                                proxy_id = %proxy_id,
                                client = %client_addr,
                                size = seg.len(),
                                error = %e,
                                "UDP GSO→direct-send oversize drain failed; datagram lost"
                            );
                        }
                        continue;
                    }
                    break;
                }
                let _ = flush_sendmmsg_best_effort(send_batch, frontend.as_raw_fd(), send_drops);
            }
            // Now push the current datagram, flushing once if necessary.
            // An empty batch + refused push means oversized for the slot.
            push_sendmmsg_or_direct(
                send_batch,
                frontend,
                client_addr,
                data,
                local_ip,
                proxy_id,
                send_drops,
            )
            .await;
        }
    }
}

/// Configuration for starting a UDP proxy listener.
pub struct UdpListenerConfig {
    pub port: u16,
    pub bind_addr: IpAddr,
    pub proxy_id: String,
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
    /// [`crate::proxy::stream_listener::StreamListenerManager`] so mesh
    /// PeerAuthentication live reload can call
    /// [`crate::dtls::DtlsServer::swap_frontend_config`] on the same instance
    /// the recv loop is using. `None` for non-mesh paths and for plain UDP
    /// listeners (no DTLS server is built).
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
    pub sni_proxy_ids: Option<Vec<String>>,
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
    } = cfg;
    let session_shard_amount = udp_session_shard_amount(session_shard_amount);
    // so_busy_poll_us and udp_gro_enabled are used in #[cfg(target_os = "linux")] blocks below.
    #[cfg(not(target_os = "linux"))]
    let _ = (so_busy_poll_us, udp_gro_enabled, udp_pktinfo_enabled);

    if let Some(dtls_config) = frontend_dtls_config {
        return start_dtls_frontend_listener(
            port,
            bind_addr,
            proxy_id,
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
                    let batch_limit = adaptive_buffer.get_batch_limit(&proxy_id);

                    use std::os::fd::AsRawFd;
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

                                    // Reject datagrams from new clients under critical overload.
                                    // Existing sessions continue to be served.
                                    if overload.reject_new_connections.load(Ordering::Relaxed)
                                        && !sessions.contains_key(&addr2)
                                    {
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
                        adaptive_buffer.record_batch_cycle(&proxy_id, batch_dgrams_in);
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

                // Reject datagrams from new clients under critical overload.
                // Existing sessions continue to be served (UDP is sessionless at the
                // wire level, so we only block session creation, not in-flight traffic).
                if overload.reject_new_connections.load(Ordering::Relaxed)
                    && !sessions.contains_key(&client_addr)
                {
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
                )
                .await;
                if let Err(e) = result {
                    debug!(proxy_id = %proxy_id, client = %client_addr, "UDP forward error: {}", e);
                }

                // Drain additional pending datagrams without yielding to the runtime.
                // On Linux, uses recvmmsg to batch multiple datagrams per syscall.
                // On other platforms, falls back to individual try_recv_from calls.
                let batch_limit = adaptive_buffer.get_batch_limit(&proxy_id);

                #[cfg(target_os = "linux")]
                {
                    use std::os::fd::AsRawFd;
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

                                    // Reject datagrams from new clients under critical overload.
                                    // Existing sessions continue to be served.
                                    if overload.reject_new_connections.load(Ordering::Relaxed)
                                        && !sessions.contains_key(&addr2)
                                    {
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
                    for _ in 0..batch_limit {
                        match frontend_socket.try_recv_from(&mut buf) {
                            Ok((len2, addr2)) => {
                                // Reject datagrams from new clients under critical overload.
                                // Existing sessions continue to be served.
                                if overload.reject_new_connections.load(Ordering::Relaxed)
                                    && !sessions.contains_key(&addr2)
                                {
                                    continue;
                                }

                                batch_dgrams_in += 1;
                                batch_bytes_in += len2 as u64;

                                let result = process_datagram(
                                    &buf[..len2],
                                    addr2,
                                    &proxy_id,
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
                adaptive_buffer.record_batch_cycle(&proxy_id, batch_dgrams_in);

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
    sni_proxy_ids: Option<&[String]>,
    adaptive_buffer: &Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    udp_gso_enabled: bool,
    local_addr: Option<crate::socket_opts::PktinfoLocal>,
    listener_shutdown: &watch::Receiver<bool>,
    global_shutdown: Option<&watch::Receiver<bool>>,
    overload: &Arc<crate::overload::OverloadState>,
    mesh_outbound_enforcement:
        &crate::modes::mesh::outbound_enforcement::SharedMeshOutboundEnforcement,
) -> Result<(), anyhow::Error> {
    if let Some(mut pending) = pending_sessions.get_mut(&client_addr) {
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
    // Skip the cache when the cached session has been flagged expired
    // by the idle-cleanup task — that path removes the session from
    // the map but the recv-loop's `Arc` keeps it alive, so without
    // this check we'd keep forwarding through a session the cleanup
    // task already declared dead and the configured
    // `udp_idle_timeout_seconds` would be quietly ignored. Clear the
    // cache entry when the expired check trips so a quiet listener
    // does not pin the last session's Arc (and backend fd) forever.
    let existing_session = match last_client.as_ref() {
        Some((cached_addr, cached_session)) if *cached_addr == client_addr => {
            if cached_session
                .expired
                .load(std::sync::atomic::Ordering::Acquire)
            {
                *last_client = None;
                sessions
                    .get(&client_addr)
                    .map(|entry| entry.value().clone())
            } else {
                Some(cached_session.clone())
            }
        }
        _ => {
            if let Some((_, cached_session)) = last_client.as_ref()
                && cached_session
                    .expired
                    .load(std::sync::atomic::Ordering::Acquire)
            {
                *last_client = None;
            }
            sessions
                .get(&client_addr)
                .map(|entry| entry.value().clone())
        }
    };

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
        if !try_insert_pending_session_gate(pending_sessions, client_addr, max_sessions)? {
            // Defensive: a gate appeared after the check at the top of this
            // function (not expected — the recv loop is a single task). Treat
            // this datagram as a follow-up for the in-flight setup.
            if let Some(mut pending) = pending_sessions.get_mut(&client_addr) {
                let _ = pending.push_bounded(data);
            }
            return Ok(());
        }
        spawn_new_session_datagram(
            data.to_vec(),
            client_addr,
            proxy_id.to_string(),
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

    // Record the per-datagram local (destination) address on the session the
    // first time the kernel exposes one. `OnceLock::set` is a no-op if already
    // set, so this is cheap on subsequent datagrams.
    if let Some(la) = local_addr {
        let _ = session.local_addr.set(la);
    }

    // Update cache for next datagram.
    *last_client = Some((client_addr, session.clone()));

    // When datagram hooks are configured, enqueue onto the per-session forward
    // task instead of awaiting plugins inline on this single recv loop. A slow
    // Redis-backed rate limiter (or any hook I/O) for one client must not
    // serialize every other session on the listener.
    if let Some(ref forward_tx) = session.client_forward_tx {
        match forward_tx.try_send(ClientForwardDatagram {
            data: data.to_vec(),
            local_addr,
        }) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                trace!(
                    proxy_id = %session.proxy_id,
                    client = %client_addr,
                    "UDP client-forward channel full; dropping datagram"
                );
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Forward task exited — treat as session dying; next datagram
                // will miss the cache/map and recreate.
                Ok(())
            }
        }
    } else {
        // No datagram hooks: keep the inline zero-overhead forward path.
        forward_client_datagram_to_backend(&session, data).await?;
        *batch_dgrams_out += 1;
        *batch_bytes_out += data.len() as u64;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_new_session_datagram(
    data: Vec<u8>,
    client_addr: SocketAddr,
    proxy_id: String,
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
    sni_proxy_ids: Option<Vec<String>>,
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
            client_addr,
            &proxy_id,
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
                    client = %client_addr,
                    listen_port = listen_port,
                    error = %e,
                    "UDP session setup dropped client datagram"
                );
            } else {
                warn!(
                    proxy_id = %proxy_id,
                    client = %client_addr,
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
    client_addr: SocketAddr,
    proxy_id: &str,
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
    sni_proxy_ids: Option<&[String]>,
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
    if sessions.contains_key(&client_addr) {
        return Ok(());
    }

    let epoch = request_epoch.load();
    let view = resolve_udp_session_epoch_view(proxy_id, &epoch, &data, sni_proxy_ids, listen_port)?;
    let first_datagram_metadata =
        std::sync::Mutex::new(std::collections::HashMap::<String, String>::new());
    if !udp_datagram_allowed(
        &view.datagram_plugins,
        udp_session_client_ip(client_addr),
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
    .await
    {
        return Ok(());
    }

    let mesh_enforcement_snapshot = mesh_outbound_enforcement.load_full();
    let mut preselected_backend_target = None;
    if let Some(enforcement) = mesh_enforcement_snapshot.as_ref() {
        use crate::modes::mesh::outbound_enforcement::{Decision, PROTOCOL_UDP, PROTOCOL_UDP_DTLS};
        let lb_hash_key = udp_lb_hash_key_for_client_ip(client_addr.ip());
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
                warn!(
                    proxy_id = %view.proxy.id,
                    client = %client_addr.ip(),
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

    let mut reservation = reserve_udp_session_slot(metrics, max_sessions)?;

    let session = create_session(
        &epoch,
        view,
        dns_cache,
        frontend_socket,
        client_addr,
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
    while let Some(batch) = take_pending_datagrams(pending_sessions, client_addr) {
        for dgram in batch {
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
                    client = %client_addr,
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
    // Publish the response budget before the send. In particular, a loopback
    // backend can receive and answer between the send syscall and this task
    // being polled again; publishing only after send completion lets that first
    // response bypass the amplification guard. A failed send still leaves a
    // conservative budget based on bytes accepted from the client.
    session
        .last_request_size
        .store(data.len() as u64, Ordering::Release);

    let send_result = if let Some(ref dtls) = session.dtls_conn {
        dtls.send(data)
            .await
            .map(|()| data.len())
            .map_err(|e| std::io::Error::other(e.to_string()))
    } else if let Some(ref sock) = session.backend_socket {
        sock.send(data).await
    } else {
        return Err(anyhow::anyhow!("no backend socket available"));
    };

    match send_result {
        Ok(_) => {
            session
                .last_activity
                .store(coarse_epoch_millis(), Ordering::Relaxed);
            session
                .bytes_sent
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("send to backend failed: {}", e)),
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
                            session
                                .stop_reply_task
                                .store(true, std::sync::atomic::Ordering::Release);
                            // `notify_one` stores a permit so a stop that races
                            // between the reply task's flag check and its
                            // `notified()` registration cannot be lost.
                            session.stop_notify.notify_one();
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
                                    client_addr: *addr,
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

/// Start a DTLS frontend listener that accepts encrypted client connections.
///
/// Uses `DtlsServer` from the `dtls` module which demultiplexes incoming UDP
/// datagrams by source address and manages per-client DTLS 1.2/1.3 sessions.
/// Each accepted client (post-handshake) is handled in its own spawned task.
#[allow(clippy::too_many_arguments)]
async fn start_dtls_frontend_listener(
    port: u16,
    bind_addr: IpAddr,
    proxy_id: String,
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
) -> Result<(), anyhow::Error> {
    let addr = SocketAddr::new(bind_addr, port);
    let admission_overload = overload.clone();
    let dtls_limits = crate::dtls::DtlsServerLimits {
        max_sessions: Some(max_sessions),
        handshake_timeout: (frontend_tls_handshake_timeout_seconds > 0)
            .then_some(Duration::from_secs(frontend_tls_handshake_timeout_seconds)),
        allow_new_session: Some(Arc::new(move || {
            !admission_overload
                .reject_new_connections
                .load(Ordering::Relaxed)
        })),
        active_session_mirror: Some(metrics.dtls_demux_sessions.clone()),
    };
    let server =
        Arc::new(crate::dtls::DtlsServer::bind_with_limits(addr, dtls_config, dtls_limits).await?);
    // Publish the live DTLS server handle so mesh PeerAuthentication live
    // reload (extending the existing HTTP/HBONE carve-out to UDP+DTLS stream
    // listeners) can call `swap_frontend_config` on the same instance the
    // recv loop is using. Send-failure is benign: the receiver may have been
    // dropped (non-mesh path) or the manager may have moved on without
    // wanting the handle.
    if let Some(tx) = dtls_server_tx {
        let _ = tx.send(server.clone());
    }
    ensure_coarse_timer_started();
    started.store(true, Ordering::Release);
    info!(proxy_id = %proxy_id, "DTLS frontend listener started on {}", addr);

    // Spawn the server's recv loop in a background task
    let server_runner = server.clone();
    let runner_proxy_id = proxy_id.clone();
    let server_task = tokio::spawn(async move {
        if let Err(e) = server_runner.run().await {
            warn!(proxy_id = %runner_proxy_id, "DTLS server recv loop error: {}", e);
        }
    });

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

                // Reject new DTLS connections under critical overload.
                if overload.reject_new_connections.load(Ordering::Relaxed) {
                    client_conn.close().await;
                    continue;
                }

                // Atomically reserve a session slot. Epoch lookup, plugin
                // admission (`on_stream_connect`), and forwarding run inside the
                // per-client task — matching the TCP path — so a slow stream
                // plugin cannot stall accept for every other completed handshake.
                let prev = metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
                if prev >= max_sessions as u64 {
                    metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                    warn!(
                        proxy_id = %proxy_id,
                        client = %client_addr,
                        "DTLS session limit reached ({}), rejecting connection",
                        max_sessions
                    );
                    client_conn.close().await;
                    continue;
                }

                let handler_proxy_id = proxy_id.clone();
                let handler_epoch_store = Arc::clone(&request_epoch);
                let handler_health_checker = health_checker.clone();
                let handler_dns = dns_cache.clone();
                let handler_metrics = metrics.clone();
                let handler_cb_cache = circuit_breaker_cache.clone();
                let handler_crls = crls.clone();
                let handler_ca_bundle = tls_ca_bundle_path.clone();
                let handler_dtls_cache = backend_dtls_config_cache.clone();
                let handler_overload = overload.clone();
                // Monotonic session start for duration_ms; wall clock is only
                // for human-readable connect/disconnect timestamps.
                let connected_mono = Instant::now();
                let connected_at = chrono::Utc::now();
                tokio::spawn(async move {
                    let epoch = handler_epoch_store.load();
                    let Some(proxy) = epoch.proxy_by_id(&handler_proxy_id).cloned() else {
                        handler_metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                        client_conn.close().await;
                        warn!(
                            proxy_id = %handler_proxy_id,
                            "DTLS listener proxy no longer exists in request epoch"
                        );
                        return;
                    };
                    let plugins = epoch
                        .plugin_cache
                        .get_plugins_for_protocol(&proxy.id, ProxyProtocol::Udp);
                    let datagram_plugins: Arc<[Arc<dyn Plugin>]> = plugins
                        .iter()
                        .filter(|p| p.requires_udp_datagram_hooks())
                        .cloned()
                        .collect();
                    let consumer_index =
                        Arc::new(ConsumerIndex::from_inner(Arc::clone(&epoch.consumer_index)));
                    let proxy_name = proxy.name.clone();
                    let proxy_namespace = proxy.namespace.clone();
                    let backend_scheme = proxy.effective_scheme();
                    let client_ip = udp_session_client_ip(client_addr);

                    // Run on_stream_connect plugins (with DTLS client cert if available)
                    let stream_client_ip = client_ip.to_string();
                    let mut stream_ctx = StreamConnectionContext::new(
                        stream_client_ip.clone(),
                        // PROXY protocol is not supported on UDP/DTLS (TCP-borne only);
                        // direct_client_ip always equals client_ip for UDP sessions.
                        stream_client_ip,
                        proxy.id.clone(),
                        proxy_name.clone(),
                        port,
                        backend_scheme,
                        consumer_index,
                    );
                    stream_ctx.proxy_lifecycle_generation = epoch
                        .plugin_cache
                        .proxy_lifecycle_generation(proxy.id.as_str());
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
                                client = %client_addr,
                                "DTLS connection rejected by plugin"
                            );
                            client_conn.close().await;
                            handler_metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                            return;
                        }
                    }

                    handler_metrics.total_sessions.fetch_add(1, Ordering::Relaxed);

                    debug!(
                        proxy_id = %handler_proxy_id,
                        client = %client_addr,
                        "DTLS frontend connection accepted"
                    );

                    // Acquire the OverloadState connection guard for the accepted
                    // (post-handshake, post-plugin) DTLS session. Pre-handshake
                    // demux peers are tracked separately in
                    // `metrics.dtls_demux_sessions` and via the
                    // `allow_new_session` callback; we intentionally only
                    // contribute to `OverloadState.active_connections` after the
                    // handshake completed and plugin checks passed, so the global
                    // counter reflects committed sessions (parity with TCP/H3).
                    // Drop at task exit decrements automatically.
                    let _overload_guard =
                        crate::overload::ConnectionGuard::new(&handler_overload);

                    let handler_proxy_id = proxy.id.clone();
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
                    let (handler_metadata, handler_correlation_ids) = if handler_has_plugins {
                        stream_ctx.take_metadata_with_correlation_ids()
                    } else {
                        Default::default()
                    };

                    let result = handle_dtls_client(
                        client_conn,
                        client_addr,
                        &handler_proxy_id,
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
                                    proxy_id = %handler_proxy_id,
                                    client = %client_addr,
                                    "DTLS client session ended: {}",
                                    e
                                );
                                let error_message = e.to_string();
                                let err_class = if is_udp_dtls_idle_timeout(e) {
                                    crate::retry::ErrorClass::ReadWriteTimeout
                                } else {
                                    crate::retry::classify_boxed_error(e.as_ref())
                                };
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
                            proxy_id: &handler_proxy_id,
                            proxy_name: proxy_name.as_deref(),
                            proxy_lifecycle_generation: handler_proxy_lifecycle_generation,
                            client_addr,
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
    client_addr: SocketAddr,
    proxy_id: &str,
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
) -> DtlsHandlerResult {
    let mut backend_info = DtlsBackendInfo {
        backend_target: String::new(),
        backend_resolved_ip: None,
    };
    let bytes_sent = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));
    let last_request_size = Arc::new(AtomicU64::new(0));
    // Shared sink for per-datagram WAF metadata recorded by the forwarding tasks
    // inside `handle_dtls_client_inner`; drained into the disconnect summary
    // below so DTLS hits are observable by default (parity with plain UDP/TCP).
    let datagram_metadata = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let outcome = handle_dtls_client_inner(
        client_conn,
        client_addr,
        proxy_id,
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
        Arc::clone(&datagram_metadata),
        datagram_plugins,
        proxy_name,
        listen_port,
        crls,
        backend_dtls_config_cache,
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
fn dtls_disconnect_cause(
    error: &anyhow::Error,
    class: &crate::retry::ErrorClass,
) -> crate::plugins::DisconnectCause {
    use crate::plugins::DisconnectCause;
    use crate::retry::ErrorClass;

    if is_udp_dtls_idle_timeout(error) {
        return DisconnectCause::IdleTimeout;
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
fn dtls_disconnect_direction(error: &anyhow::Error, class: &crate::retry::ErrorClass) -> Direction {
    use crate::retry::ErrorClass;
    if is_udp_dtls_idle_timeout(error) {
        return Direction::Unknown;
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

#[allow(clippy::too_many_arguments)]
async fn handle_dtls_client_inner(
    client_conn: crate::dtls::DtlsServerConn,
    client_addr: SocketAddr,
    proxy_id: &str,
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
    datagram_metadata: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    datagram_plugins: &Arc<[Arc<dyn Plugin>]>,
    proxy_name: Option<&str>,
    listen_port: u16,
    crls: &crate::tls::CrlList,
    backend_dtls_config_cache: &BackendDtlsConfigCache,
) -> Result<(), anyhow::Error> {
    // Look up proxy config
    let proxy = epoch
        .proxy_by_id(proxy_id)
        .ok_or_else(|| anyhow::anyhow!("Proxy {} not found", proxy_id))?
        .clone();
    let idle_timeout = Duration::from_secs(proxy.udp_idle_timeout_seconds.max(1));

    // Resolve backend target
    let lb_hash_key = udp_lb_hash_key_for_client_ip(client_addr.ip());
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
        match circuit_breaker_cache.can_execute(proxy_id, cb_target_key.as_deref(), cb_config) {
            Ok((_cb, is_half_open_probe)) => {
                cb_is_half_open_probe = is_half_open_probe;
            }
            Err(_) => {
                warn!(
                    proxy_id = %proxy_id,
                    client = %client_addr,
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

    let resolved_ip = match dns_cache
        .resolve(
            &backend_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
    {
        Ok(ip) => ip,
        Err(e) => {
            // Settle any HALF_OPEN probe slot `can_execute` admitted. A
            // backend-egress-policy denial dialed no backend, so release the slot
            // NEUTRALLY (no count) rather than leaking it — otherwise
            // `half_open_in_flight` stays consumed and the breaker can never
            // recover. Genuine DNS/transport failures still record a failure.
            if let Some(ref cb_config) = proxy.circuit_breaker {
                let cb = circuit_breaker_cache.get_or_create(
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
    let backend_addr = SocketAddr::new(resolved_ip, backend_port);
    // DNS succeeded — record the resolved IP for logging.
    backend_info.backend_resolved_ip = Some(resolved_ip.to_string());

    // Create backend connection — plain UDP or DTLS depending on backend_scheme.
    // Frontend DTLS termination can forward to either plain UDP or DTLS backends.
    // Bind ephemeral socket to the correct address family matching the backend.
    let ephemeral_bind: &str = if backend_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let (backend_udp, backend_dtls): (
        Option<Arc<UdpSocket>>,
        Option<Arc<crate::dtls::DtlsConnection>>,
    ) = if proxy.effective_scheme() == BackendScheme::Dtls {
        let socket = match UdpSocket::bind(ephemeral_bind).await {
            Ok(s) => s,
            Err(e) => {
                if let Some(ref cb_config) = proxy.circuit_breaker {
                    let cb = circuit_breaker_cache.get_or_create(
                        proxy_id,
                        cb_target_key.as_deref(),
                        cb_config,
                    );
                    cb.record_failure(502, true, cb_is_half_open_probe);
                }
                return Err(anyhow::anyhow!("Failed to bind UDP socket: {}", e));
            }
        };
        if let Err(e) = socket.connect(backend_addr).await {
            if let Some(ref cb_config) = proxy.circuit_breaker {
                let cb = circuit_breaker_cache.get_or_create(
                    proxy_id,
                    cb_target_key.as_deref(),
                    cb_config,
                );
                cb.record_failure(502, true, cb_is_half_open_probe);
            }
            return Err(anyhow::anyhow!(
                "Failed to connect to backend {}: {}",
                backend_addr,
                e
            ));
        }
        let dtls_params = cached_backend_dtls_config(
            backend_dtls_config_cache,
            &proxy,
            &backend_host,
            tls_no_verify,
            crls,
            tls_ca_bundle_path,
        )?;
        let dtls = match crate::dtls::DtlsConnection::connect(socket, dtls_params).await {
            Ok(d) => Arc::new(d),
            Err(e) => {
                if let Some(ref cb_config) = proxy.circuit_breaker {
                    let cb = circuit_breaker_cache.get_or_create(
                        proxy_id,
                        cb_target_key.as_deref(),
                        cb_config,
                    );
                    cb.record_failure(502, true, cb_is_half_open_probe);
                }
                // dtls::DtlsConnection::connect returns anyhow::Error, which
                // doesn't implement std::error::Error directly — render the
                // chain into the message so log lines and source-walking
                // consumers still see the underlying cause.
                //
                // `with_colon_detail` joins as `"{prefix}: {detail}"`,
                // matching the legacy `anyhow!("{}: {}", STREAM_ERR_..., e)`
                // wording byte-for-byte so exact-match log pipelines keyed
                // on the old token keep working.
                return Err(StreamSetupError::with_colon_detail(
                    StreamSetupKind::BackendDtlsHandshake,
                    format!("{e:#}"),
                )
                .into());
            }
        };
        debug!(
            proxy_id = %proxy_id,
            client = %client_addr,
            backend = %backend_addr,
            "Backend DTLS handshake completed (frontend DTLS session)"
        );
        (None, Some(dtls))
    } else {
        let sock = match UdpSocket::bind(ephemeral_bind).await {
            Ok(s) => s,
            Err(e) => {
                if let Some(ref cb_config) = proxy.circuit_breaker {
                    let cb = circuit_breaker_cache.get_or_create(
                        proxy_id,
                        cb_target_key.as_deref(),
                        cb_config,
                    );
                    cb.record_failure(502, true, cb_is_half_open_probe);
                }
                return Err(anyhow::anyhow!("Failed to bind UDP socket: {}", e));
            }
        };
        if let Err(e) = sock.connect(backend_addr).await {
            if let Some(ref cb_config) = proxy.circuit_breaker {
                let cb = circuit_breaker_cache.get_or_create(
                    proxy_id,
                    cb_target_key.as_deref(),
                    cb_config,
                );
                cb.record_failure(502, true, cb_is_half_open_probe);
            }
            return Err(anyhow::anyhow!(
                "Failed to connect to backend {}: {}",
                backend_addr,
                e
            ));
        }
        (Some(Arc::new(sock)), None)
    };

    // Record circuit breaker success — backend connection established.
    if let Some(ref cb_config) = proxy.circuit_breaker {
        let cb = circuit_breaker_cache.get_or_create(proxy_id, cb_target_key.as_deref(), cb_config);
        cb.record_success(cb_is_half_open_probe);
    }

    debug!(
        proxy_id = %proxy_id,
        client = %client_addr,
        backend = %backend_addr,
        dtls_backend = backend_dtls.is_some(),
        "DTLS frontend session established"
    );

    // Bidirectional forwarding: client (DTLS) ↔ backend (UDP or DTLS)
    // Clone a sender for the backend→client direction before moving client_conn.
    let client_sender = client_conn.clone_sender();
    let client_close = client_sender.clone();
    let backend_dtls_write = backend_dtls.clone();
    let backend_udp_write = backend_udp.clone();
    let backend_dtls_cleanup = backend_dtls.clone();
    let metrics_fwd = metrics.clone();
    let proxy_id_fwd = proxy_id.to_string();
    let bytes_sent_fwd = Arc::clone(&bytes_sent);
    let last_request_size_fwd = Arc::clone(&last_request_size);
    // Pre-compute datagram plugin list once, share between both direction tasks.
    // Arc<[...]> avoids the per-session filter+collect being done twice.
    let dgram_plugins = Arc::clone(datagram_plugins);
    // Pre-compute context strings as Arc<str> — per-datagram "clone" is a pointer
    // bump (~5ns) instead of heap allocation + memcpy.
    let dgram_client_ip = udp_session_client_ip(client_addr);
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
    let activity_fwd = Arc::clone(&shared_activity_ms);
    let client_to_backend = tokio::spawn(async move {
        loop {
            let data = match client_conn.recv().await {
                Ok(d) => d,
                Err(_) => break,
            };
            let len = data.len();
            activity_fwd.store(coarse_epoch_millis(), Ordering::Relaxed);

            metrics_fwd.datagrams_in.fetch_add(1, Ordering::Relaxed);
            metrics_fwd
                .bytes_in
                .fetch_add(len as u64, Ordering::Relaxed);

            // Run per-datagram plugins before forwarding.
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
                    if matches!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop) {
                        dropped = true;
                        break;
                    }
                }
                if dropped {
                    continue; // Silent drop — standard UDP behavior
                }
            }

            // Publish before sending so a fast backend reply cannot observe a
            // zero or stale amplification budget.
            last_request_size_fwd.store(len as u64, Ordering::Release);
            let send_ok = if let Some(ref dtls) = backend_dtls_write {
                dtls.send(&data).await.map_err(|e| e.to_string())
            } else if let Some(ref sock) = backend_udp_write {
                sock.send(&data)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            } else {
                break;
            };

            if let Err(e) = send_ok {
                debug!(
                    proxy_id = %proxy_id_fwd,
                    "DTLS client→backend send failed: {}", e
                );
                break;
            }

            metrics_fwd.datagrams_out.fetch_add(1, Ordering::Relaxed);
            metrics_fwd
                .bytes_out
                .fetch_add(len as u64, Ordering::Relaxed);
            bytes_sent_fwd.fetch_add(len as u64, Ordering::Relaxed);
            activity_fwd.store(coarse_epoch_millis(), Ordering::Relaxed);
        }
    });

    // Backend → Client — reuse pre-computed plugin list and context strings
    // (dgram_*_rev cloned above before the forward spawn moved the originals).
    let metrics_rev = metrics.clone();
    let proxy_id_rev = dgram_proxy_id_rev.to_string();
    let bytes_received_rev = Arc::clone(&bytes_received);
    let amplification_factor_rev = proxy.udp_max_response_amplification_factor;
    let last_request_size_rev = Arc::clone(&last_request_size);

    let activity_rev = Arc::clone(&shared_activity_ms);
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
            activity_rev.store(coarse_epoch_millis(), Ordering::Relaxed);

            metrics_rev.datagrams_in.fetch_add(1, Ordering::Relaxed);
            metrics_rev
                .bytes_in
                .fetch_add(len as u64, Ordering::Relaxed);

            // Amplification factor check for DTLS path
            if let Some(factor) = amplification_factor_rev {
                let req_size = last_request_size_rev.load(Ordering::Acquire);
                let max_response = udp_amplification_response_budget(req_size, factor);
                if len as u64 > max_response {
                    continue; // Drop oversized response
                }
            }

            // Backend→client plugin hooks for DTLS path
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
                let mut drop = false;
                for plugin in dgram_plugins_rev.iter() {
                    if matches!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop) {
                        drop = true;
                        break;
                    }
                }
                if drop {
                    continue;
                }
            }

            if client_sender.send(&data).await.is_err() {
                debug!(
                    proxy_id = %proxy_id_rev,
                    "DTLS backend→client send failed"
                );
                break;
            }

            metrics_rev.datagrams_out.fetch_add(1, Ordering::Relaxed);
            metrics_rev
                .bytes_out
                .fetch_add(len as u64, Ordering::Relaxed);
            bytes_received_rev.fetch_add(len as u64, Ordering::Relaxed);
            activity_rev.store(coarse_epoch_millis(), Ordering::Relaxed);
        }
    });

    let mut client_to_backend = client_to_backend;
    let mut backend_to_client = backend_to_client;
    let mut idle_watchdog = Box::pin(dtls_shared_idle_watchdog(shared_activity_ms, idle_timeout));
    let outcome = tokio::select! {
        _ = &mut client_to_backend => Ok(()),
        _ = &mut backend_to_client => Ok(()),
        result = &mut idle_watchdog => result,
    };
    client_to_backend.abort();
    backend_to_client.abort();

    client_close.close().await;
    if let Some(ref dtls) = backend_dtls_cleanup {
        dtls.close().await;
    }

    outcome
}

/// Create a new UDP session for a client (plain UDP frontend path).
#[allow(clippy::too_many_arguments)]
async fn create_session(
    epoch: &RequestEpoch,
    view: UdpSessionEpochView,
    dns_cache: &DnsCache,
    frontend_socket: &Arc<UdpSocket>,
    client_addr: SocketAddr,
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
) -> Result<Arc<UdpSession>, anyhow::Error> {
    let UdpSessionEpochView {
        proxy,
        plugins,
        datagram_plugins,
        consumer_index,
        sni_hostname,
    } = view;
    let proxy_id = proxy.id.as_str();
    let proxy_name = proxy.name.clone();
    let proxy_namespace = proxy.namespace.clone();
    let backend_scheme = proxy.effective_scheme();
    let is_passthrough = proxy.passthrough;
    let client_ip = udp_session_client_ip(client_addr);

    // Run on_stream_connect plugins before creating backend connection
    let stream_client_ip = client_ip.to_string();
    let mut stream_ctx = StreamConnectionContext::new(
        stream_client_ip.clone(),
        // PROXY protocol is not supported on plain UDP (TCP-borne only);
        // direct_client_ip always equals client_ip for UDP sessions.
        stream_client_ip,
        proxy_id.to_string(),
        proxy_name.clone(),
        listen_port,
        backend_scheme,
        consumer_index,
    );
    stream_ctx.proxy_lifecycle_generation = epoch.plugin_cache.proxy_lifecycle_generation(proxy_id);
    stream_ctx.sni_hostname = sni_hostname;
    // The constructor intentionally leaves node-waypoint per-pod policy scope
    // absent: plain UDP cannot wire it without a new capture path. Identity is
    // keyed by the per-connection socket cookie (`SO_COOKIE`) that node-agent
    // eBPF stamps from the source pod via the `connect4`/`connect6` cgroup
    // hooks; there are no UDP capture hooks, and this UDP proxy demultiplexes
    // every client off one shared frontend socket with a single cookie, so
    // there is no per-source-pod cookie to resolve here. With
    // `per_pod_policy_scoping` on (node-waypoint topology), `mesh_authz`
    // stamps `mesh_authz.scope_missing` and, because the per-pod scope is
    // always absent here, fails closed (rejects the stream, 403) when any
    // namespace/selector-scoped policy is configured; with only mesh-wide
    // policies it evaluates them normally. Per-pod scoped enforcement is
    // unavailable for UDP streams (TCP and HTTP/HBONE have it). See docs/mesh.md.
    for plugin in plugins.iter() {
        if let PluginResult::Reject { .. } = plugin.on_stream_connect(&mut stream_ctx).await {
            return Err(
                StreamSetupError::new(StreamSetupKind::RejectedByPlugin, "(UDP session)").into(),
            );
        }
    }

    let lb_hash_key = udp_lb_hash_key_for_client_ip(client_addr.ip());
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
        match circuit_breaker_cache.can_execute(proxy_id, cb_target_key.as_deref(), cb_config) {
            Ok((_cb, is_half_open_probe)) => {
                cb_is_half_open_probe = is_half_open_probe;
            }
            Err(_) => {
                warn!(
                    proxy_id = %proxy_id,
                    client = %client_addr,
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

    // DNS resolve
    let resolved_ip = match dns_cache
        .resolve(
            &backend_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
    {
        Ok(ip) => ip,
        Err(e) => {
            // Settle any HALF_OPEN probe slot `can_execute` admitted. A
            // backend-egress-policy denial dialed no backend, so release the slot
            // NEUTRALLY (no count) rather than leaking it — otherwise
            // `half_open_in_flight` stays consumed and the breaker can never
            // recover. Genuine DNS/transport failures still record a failure.
            if let Some(ref cb_config) = proxy.circuit_breaker {
                let cb = circuit_breaker_cache.get_or_create(
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
    let backend_addr = SocketAddr::new(resolved_ip, backend_port);

    // Create backend connection — plain UDP or DTLS.
    // In passthrough mode, always use plain UDP — the client's encrypted DTLS
    // datagrams pass through directly to the backend which terminates DTLS.
    // Bind ephemeral socket to the correct address family matching the backend.
    let ephemeral_bind: &str = if backend_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let (backend_socket, dtls_conn) =
        if proxy.effective_scheme() == BackendScheme::Dtls && !is_passthrough {
            // DTLS: create a connected socket and perform DTLS handshake via dimpl.
            let socket = match UdpSocket::bind(ephemeral_bind).await {
                Ok(s) => s,
                Err(e) => {
                    if let Some(ref cb_config) = proxy.circuit_breaker {
                        let cb = circuit_breaker_cache.get_or_create(
                            proxy_id,
                            cb_target_key.as_deref(),
                            cb_config,
                        );
                        cb.record_failure(502, true, cb_is_half_open_probe);
                    }
                    return Err(anyhow::anyhow!("Failed to bind UDP socket: {}", e));
                }
            };
            if let Err(e) = socket.connect(backend_addr).await {
                if let Some(ref cb_config) = proxy.circuit_breaker {
                    let cb = circuit_breaker_cache.get_or_create(
                        proxy_id,
                        cb_target_key.as_deref(),
                        cb_config,
                    );
                    cb.record_failure(502, true, cb_is_half_open_probe);
                }
                return Err(anyhow::anyhow!(
                    "Failed to connect UDP socket to {}: {}",
                    backend_addr,
                    e
                ));
            }

            let dtls_params = cached_backend_dtls_config(
                backend_dtls_config_cache,
                &proxy,
                &backend_host,
                tls_no_verify,
                crls,
                tls_ca_bundle_path,
            )?;
            let dtls = match crate::dtls::DtlsConnection::connect(socket, dtls_params).await {
                Ok(d) => Arc::new(d),
                Err(e) => {
                    if let Some(ref cb_config) = proxy.circuit_breaker {
                        let cb = circuit_breaker_cache.get_or_create(
                            proxy_id,
                            cb_target_key.as_deref(),
                            cb_config,
                        );
                        cb.record_failure(502, true, cb_is_half_open_probe);
                    }
                    // dtls::DtlsConnection::connect returns anyhow::Error,
                    // which doesn't implement std::error::Error directly —
                    // render the chain into the message so consumers still
                    // see the underlying cause. See the sibling DTLS site
                    // above for the `with_colon_detail` rationale (legacy
                    // `"{prefix}: {err}"` wording stability).
                    return Err(StreamSetupError::with_colon_detail(
                        StreamSetupKind::BackendDtlsHandshake,
                        format!("{e:#}"),
                    )
                    .into());
                }
            };
            debug!(
                proxy_id = %proxy_id,
                client = %client_addr,
                backend = %backend_addr,
                "DTLS handshake completed for backend connection"
            );
            (None, Some(dtls))
        } else {
            // Plain UDP
            let socket = match UdpSocket::bind(ephemeral_bind).await {
                Ok(s) => s,
                Err(e) => {
                    if let Some(ref cb_config) = proxy.circuit_breaker {
                        let cb = circuit_breaker_cache.get_or_create(
                            proxy_id,
                            cb_target_key.as_deref(),
                            cb_config,
                        );
                        cb.record_failure(502, true, cb_is_half_open_probe);
                    }
                    return Err(anyhow::anyhow!("Failed to bind UDP socket: {}", e));
                }
            };
            if let Err(e) = socket.connect(backend_addr).await {
                if let Some(ref cb_config) = proxy.circuit_breaker {
                    let cb = circuit_breaker_cache.get_or_create(
                        proxy_id,
                        cb_target_key.as_deref(),
                        cb_config,
                    );
                    cb.record_failure(502, true, cb_is_half_open_probe);
                }
                return Err(anyhow::anyhow!(
                    "Failed to connect UDP socket to {}: {}",
                    backend_addr,
                    e
                ));
            }
            (Some(Arc::new(socket)), None)
        };

    // Record circuit breaker success — backend socket established.
    if let Some(ref cb_config) = proxy.circuit_breaker {
        let cb = circuit_breaker_cache.get_or_create(proxy_id, cb_target_key.as_deref(), cb_config);
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
    let (client_forward_tx, client_forward_rx) = if datagram_plugins.is_empty() {
        (None, None)
    } else {
        let (tx, rx) = mpsc::channel(CLIENT_FORWARD_CHANNEL_CAP);
        (Some(tx), Some(rx))
    };
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
        backend_target: format!("{}:{}", backend_host, backend_port),
        backend_resolved_ip: resolved_ip.to_string(),
        sni_hostname: stream_ctx.sni_hostname.clone(),
        consumer_username,
        auth_method,
        metadata: std::sync::Mutex::new(metadata),
        correlation_ids,
        local_addr: std::sync::OnceLock::new(),
        plugins: Arc::clone(&plugins),
        datagram_plugins: Arc::clone(&datagram_plugins),
        datagram_client_ip: Arc::clone(&datagram_client_ip),
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
        client_forward_tx,
        // Increment OverloadState.active_connections for each accepted UDP
        // session so per-session pressure shedding works the same as TCP/H3.
        // Decrements automatically on session drop (idle expiry, backend
        // disconnect, listener shutdown).
        overload_guard: std::sync::Mutex::new(Some(crate::overload::ConnectionGuard::new(
            overload,
        ))),
    });

    sessions.insert(client_addr, session.clone());
    // Note: active_sessions is reserved by the receive loop before the
    // background setup task calls create_session, avoiding TOCTOU races.
    metrics.total_sessions.fetch_add(1, Ordering::Relaxed);

    debug!(
        proxy_id = %proxy_id,
        client = %client_addr,
        backend = %backend_addr,
        "New UDP session created"
    );

    if let Some(mut forward_rx) = client_forward_rx {
        let forward_session = session.clone();
        let forward_metrics = metrics.clone();
        let forward_stop = Arc::clone(&session.stop_notify);
        tokio::spawn(async move {
            loop {
                // Register stop waiters before checking the flag so store→notify
                // cannot be lost between the load and select registration.
                let stop = forward_stop.notified();
                tokio::pin!(stop);
                if forward_session
                    .stop_reply_task
                    .load(std::sync::atomic::Ordering::Acquire)
                    || forward_session
                        .expired
                        .load(std::sync::atomic::Ordering::Acquire)
                {
                    break;
                }
                let dgram = tokio::select! {
                    dgram = forward_rx.recv() => dgram,
                    _ = &mut stop => None,
                };
                let Some(dgram) = dgram else {
                    break;
                };
                if let Some(la) = dgram.local_addr {
                    let _ = forward_session.local_addr.set(la);
                }
                if !udp_datagram_allowed(
                    &forward_session.datagram_plugins,
                    Arc::clone(&forward_session.datagram_client_ip),
                    Arc::clone(&forward_session.datagram_proxy_id),
                    forward_session.datagram_proxy_name.clone(),
                    forward_session.listen_port,
                    &dgram.data,
                    forward_session.datagram_payload_kind,
                    UdpDatagramDirection::ClientToBackend,
                    Some(UdpMetadataSink::new(&forward_session.metadata)),
                )
                .await
                {
                    continue;
                }
                match forward_client_datagram_to_backend(&forward_session, &dgram.data).await {
                    Ok(()) => {
                        forward_metrics
                            .datagrams_out
                            .fetch_add(1, Ordering::Relaxed);
                        forward_metrics
                            .bytes_out
                            .fetch_add(dgram.data.len() as u64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        debug!(
                            proxy_id = %forward_session.proxy_id,
                            "UDP client-forward to backend failed: {e}"
                        );
                    }
                }
            }
        });
    }

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
    let mut reply_listener_shutdown = listener_shutdown.clone();
    let mut reply_global_shutdown = global_shutdown.cloned();
    let is_dtls = reply_dtls.is_some();
    #[cfg(target_os = "linux")]
    let reply_udp_gso = udp_gso_enabled;
    #[cfg(not(target_os = "linux"))]
    let _ = udp_gso_enabled;
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];

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
        loop {
            // Create the stop waiter *before* loading the flag so a
            // store→notify_one that races between the check and select
            // registration still delivers a permit to this future.
            let stop = reply_stop_notify.notified();
            tokio::pin!(stop);
            if reply_session
                .stop_reply_task
                .load(std::sync::atomic::Ordering::Acquire)
            {
                break;
            }
            if *reply_listener_shutdown.borrow()
                || reply_global_shutdown
                    .as_ref()
                    .is_some_and(|rx| *rx.borrow())
            {
                break;
            }

            // Read from backend — via DTLS (channel-based) or raw UDP (socket-based)
            let (data_slice, data_vec);
            let len;
            if let Some(ref dtls) = reply_dtls {
                let recv_result = tokio::select! {
                    result = dtls.recv() => Some(result),
                    _ = &mut stop => None,
                    _ = reply_listener_shutdown.changed() => None,
                    _ = async {
                        match reply_global_shutdown.as_mut() {
                            Some(rx) => { let _ = rx.changed().await; }
                            None => std::future::pending::<()>().await,
                        }
                    } => None,
                };
                match recv_result {
                    None => break,
                    Some(Ok(d)) => {
                        len = d.len();
                        data_vec = Some(d);
                        data_slice = None;
                    }
                    Some(Err(e)) => {
                        debug!(
                            proxy_id = %reply_proxy_id,
                            client = %client_addr,
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
                let recv_result = tokio::select! {
                    result = sock.recv(&mut buf) => Some(result),
                    _ = &mut stop => None,
                    _ = reply_listener_shutdown.changed() => None,
                    _ = async {
                        match reply_global_shutdown.as_mut() {
                            Some(rx) => { let _ = rx.changed().await; }
                            None => std::future::pending::<()>().await,
                        }
                    } => None,
                };
                match recv_result {
                    None => break,
                    Some(Ok(n)) => {
                        len = n;
                        data_vec = None;
                        data_slice = Some(&buf[..n]);
                    }
                    Some(Err(e)) => {
                        debug!(
                            proxy_id = %reply_proxy_id,
                            client = %client_addr,
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

            // Amplification factor check: drop backend responses that exceed
            // the configured ratio relative to the last client request size.
            if let Some(factor) = reply_amplification_factor {
                let req_size = reply_session.last_request_size.load(Ordering::Acquire);
                let max_response = udp_amplification_response_budget(req_size, factor);
                if len as u64 > max_response {
                    warn!(
                        proxy_id = %reply_proxy_id,
                        client = %client_addr,
                        response_size = len,
                        request_size = req_size,
                        factor = factor,
                        "UDP response dropped: exceeds amplification factor"
                    );
                    continue; // Drop this response datagram, continue receiving
                }
            }

            // Run backend→client per-datagram plugin hooks.
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
                let mut drop = false;
                for plugin in reply_datagram_plugins.iter() {
                    if matches!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop) {
                        drop = true;
                        break;
                    }
                }
                if drop {
                    continue; // Silent drop
                }
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
                        try_gso_send_or_fallback(
                            &mut gso_batch,
                            &mut send_batch,
                            &frontend,
                            client_addr,
                            send_data,
                            &mut gso_failed,
                            &reply_proxy_id,
                            session_local_ip,
                            &mut send_drops,
                        )
                        .await;
                    } else {
                        push_sendmmsg_or_direct(
                            &mut send_batch,
                            &frontend,
                            client_addr,
                            send_data,
                            session_local_ip,
                            &reply_proxy_id,
                            &mut send_drops,
                        )
                        .await;
                    }
                }
            } else if let Err(e) = frontend.send_to(send_data, client_addr).await {
                debug!(
                    proxy_id = %reply_proxy_id,
                    client = %client_addr,
                    "UDP send to client failed: {}",
                    e
                );
                let error_message = e.to_string();
                // Client-facing send failure — the backend is healthy, so
                // attribute the session teardown to the client recv path.
                disconnect_error = Some((
                    error_message.clone(),
                    crate::retry::classify_boxed_error(anyhow::anyhow!(error_message).as_ref()),
                    crate::plugins::DisconnectCause::RecvError,
                    crate::plugins::Direction::BackendToClient,
                ));
                break;
            }

            // For plain UDP, drain additional pending replies without yielding.
            // DTLS reads are channel-based (async only), so skip batching for DTLS backends.
            if !is_dtls {
                let Some(ref sock) = backend_socket else {
                    break;
                };
                let batch_limit = reply_adaptive_buffer.get_batch_limit(&reply_proxy_id);
                for _ in 0..batch_limit {
                    match sock.try_recv(&mut buf) {
                        Ok(len2) => {
                            // Amplification check on batched response datagram
                            if let Some(factor) = reply_amplification_factor {
                                let req_size =
                                    reply_session.last_request_size.load(Ordering::Acquire);
                                let max_response =
                                    udp_amplification_response_budget(req_size, factor);
                                if len2 as u64 > max_response {
                                    continue; // Drop oversized response
                                }
                            }
                            // Backend→client plugin hooks on batched datagram
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
                                let mut drop = false;
                                for plugin in reply_datagram_plugins.iter() {
                                    if matches!(
                                        plugin.on_udp_datagram(&ctx).await,
                                        UdpDatagramVerdict::Drop
                                    ) {
                                        drop = true;
                                        break;
                                    }
                                }
                                if drop {
                                    continue;
                                }
                            }

                            batch_dgrams += 1;
                            batch_bytes += len2 as u64;
                            batch_bytes_received += len2 as u64;

                            if send_batched {
                                #[cfg(target_os = "linux")]
                                {
                                    if reply_udp_gso && !gso_failed {
                                        try_gso_send_or_fallback(
                                            &mut gso_batch,
                                            &mut send_batch,
                                            &frontend,
                                            client_addr,
                                            &buf[..len2],
                                            &mut gso_failed,
                                            &reply_proxy_id,
                                            session_local_ip,
                                            &mut send_drops,
                                        )
                                        .await;
                                    } else {
                                        push_sendmmsg_or_direct(
                                            &mut send_batch,
                                            &frontend,
                                            client_addr,
                                            &buf[..len2],
                                            session_local_ip,
                                            &reply_proxy_id,
                                            &mut send_drops,
                                        )
                                        .await;
                                    }
                                }
                            } else if let Err(e) = frontend.send_to(&buf[..len2], client_addr).await
                            {
                                debug!(
                                    proxy_id = %reply_proxy_id,
                                    client = %client_addr,
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
                                if reply_sessions
                                    .remove_if(&client_addr, |_, v| Arc::ptr_eq(v, &reply_session))
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
                                            client_addr,
                                            session: &reply_session,
                                            backend_scheme: reply_backend_scheme,
                                            listen_port: reply_listen_port,
                                            disconnected_ms: now,
                                            disconnected_wall_at: chrono::Utc::now(),
                                            connection_error: Some(error_message.clone()),
                                            error_class: Some(crate::retry::classify_boxed_error(
                                                anyhow::anyhow!(error_message).as_ref(),
                                            )),
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
                        Err(_) => break, // WouldBlock — socket drained
                    }
                }
            }

            // Flush batched sends after draining all pending replies.
            #[cfg(target_os = "linux")]
            if send_batched {
                // Flush GSO batch first (if used).
                if reply_udp_gso && !gso_failed && !gso_batch.is_empty() {
                    let flush_result =
                        flush_gso_batch(&mut gso_batch, &frontend, client_addr, session_local_ip);
                    if let Err(e) = flush_result {
                        debug!(
                            proxy_id = %reply_proxy_id,
                            client = %client_addr,
                            "GSO flush failed ({}), falling back to sendmmsg",
                            e
                        );
                        gso_failed = true;
                        // Replay all buffered datagrams through sendmmsg /
                        // direct-send for any oversize head segments.
                        loop {
                            let drained = gso_batch.drain_to_sendmmsg(
                                &mut send_batch,
                                client_addr,
                                session_local_ip,
                            );
                            if gso_batch.is_empty() {
                                break;
                            }
                            if send_batch.is_empty() && drained == 0 {
                                if let Some(seg) = gso_batch.take_front_segment() {
                                    if let Err(e) = direct_send_to_client(
                                        &frontend,
                                        &seg,
                                        client_addr,
                                        session_local_ip,
                                    )
                                    .await
                                    {
                                        send_drops.record_datagram(seg.len());
                                        warn!(
                                            proxy_id = %reply_proxy_id,
                                            client = %client_addr,
                                            size = seg.len(),
                                            error = %e,
                                            "UDP GSO→direct-send oversize drain failed; datagram lost"
                                        );
                                    }
                                    continue;
                                }
                                break;
                            }
                            use std::os::unix::io::AsRawFd;
                            let _ = flush_sendmmsg_best_effort(
                                &mut send_batch,
                                frontend.as_raw_fd(),
                                &mut send_drops,
                            );
                        }
                    }
                }
                // Flush sendmmsg batch (used when GSO is disabled/failed, or GSO drain).
                if !send_batch.is_empty() {
                    use std::os::unix::io::AsRawFd;
                    let fd = frontend.as_raw_fd();
                    loop {
                        match flush_sendmmsg_best_effort(&mut send_batch, fd, &mut send_drops) {
                            Ok(_) if send_batch.is_empty() => break,
                            Ok(_) => continue, // partial send — retry remaining
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break, // socket full, drop remainder (UDP best-effort)
                            Err(e) => {
                                debug!(
                                    proxy_id = %reply_proxy_id,
                                    client = %client_addr,
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
        // Session's backend receiver exited — remove session
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
                    client_addr,
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
        let override_port =
            LoadBalancerCache::initial_dispatch_port_override_from(lb_snapshot, upstream_id);
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
    ip.to_canonical().to_string()
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
        validate_stream_hash_on(lb_snapshot, upstream_id, port)?;
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
    lb_snapshot: &LoadBalancerCacheInner,
    upstream_id: &str,
    port: u16,
) -> Result<(), anyhow::Error> {
    let strategy = LoadBalancerCache::get_hash_on_strategy_for_selection_from(
        lb_snapshot,
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
#[inline(always)]
fn coarse_epoch_millis() -> u64 {
    COARSE_EPOCH_MS.load(Ordering::Relaxed)
}

/// Precise monotonic millis — used for timer updates and initial seeding.
fn mono_millis_precise() -> u64 {
    crate::socket_opts::monotonic_now_ms()
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
    use crate::plugins::{Plugin, StreamTransactionSummary};
    use crate::proxy::GatewayConfig;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};
    use std::time::{Duration, Instant};
    use tokio::net::UdpSocket;

    fn make_udp_session() -> UdpSession {
        UdpSession {
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
            client_forward_tx: None,
            // Tests build sessions without an overload state; the guard slot
            // stays empty for unit tests that exercise summary emission only.
            overload_guard: std::sync::Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn failed_backend_forward_preserves_activity_and_response_budget() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut raw_session = make_udp_session();
        raw_session.backend_socket = Some(socket);
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
            "accepted client datagrams must establish the amplification budget before send"
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
            first.certificate.certificate, second.certificate.certificate,
            "cached DTLS params should reuse the generated ephemeral certificate"
        );
        assert_eq!(
            first.certificate.private_key, second.certificate.private_key,
            "cached DTLS params should reuse the generated ephemeral key"
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
            first.certificate.certificate, second.certificate.certificate,
            "a reload epoch bump must rebuild DTLS params (fresh ephemeral cert)"
        );

        // Stable epoch afterwards: the rebuilt entry is reused again.
        let third =
            cached_backend_dtls_config(&cache, &proxy, "localhost", true, &crls, None).unwrap();
        assert_eq!(
            second.certificate.certificate, third.certificate.certificate,
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
            namespace: "ferrum",
            proxy_id: "dtls-proxy",
            proxy_name: Some("DTLS Proxy"),
            proxy_lifecycle_generation: None,
            client_addr,
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
            namespace: "ferrum",
            proxy_id: "dtls-proxy",
            proxy_name: Some("DTLS Proxy"),
            proxy_lifecycle_generation: None,
            client_addr,
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
        let client_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let session = make_udp_session();
        let disconnected_wall_at =
            chrono::DateTime::from_timestamp_millis(1_710_000_001_500).unwrap();

        let summary = build_udp_stream_summary(UdpDisconnectContext {
            namespace: "ferrum",
            proxy_id: "udp-proxy",
            proxy_name: Some("UDP Proxy"),
            client_addr,
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
        let client_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let mut session = make_udp_session();
        session.sni_hostname = Some("passthrough.example".to_string());
        let disconnected_wall_at =
            chrono::DateTime::from_timestamp_millis(1_710_000_001_500).unwrap();

        let summary = build_udp_stream_summary(UdpDisconnectContext {
            namespace: "ferrum",
            proxy_id: "udp-proxy",
            proxy_name: Some("UDP Proxy"),
            client_addr,
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
            client_addr: "127.0.0.1:53000".parse().unwrap(),
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
            client_addr: "127.0.0.1:53000".parse().unwrap(),
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
            namespace: "ferrum",
            proxy_id: "dtls-proxy",
            proxy_name: None,
            proxy_lifecycle_generation: None,
            client_addr: "127.0.0.1:54000".parse().unwrap(),
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
            namespace: "ferrum",
            proxy_id: "dtls-proxy",
            proxy_name: Some("DTLS Frontend"),
            proxy_lifecycle_generation: None,
            client_addr: "127.0.0.1:54000".parse().unwrap(),
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
            namespace: "ferrum",
            proxy_id: "dtls-proxy",
            proxy_name: None,
            proxy_lifecycle_generation: None,
            client_addr: "127.0.0.1:54000".parse().unwrap(),
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
        let client_addr: SocketAddr = "127.0.0.1:53001".parse().unwrap();
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
                client_addr,
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

        assert!(super::try_insert_pending_session_gate(&pending, first, 1).unwrap());
        let err = super::try_insert_pending_session_gate(&pending, second, 1)
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
            backend_socket: None,
            dtls_conn: None,
            last_activity: AtomicU64::new(0),
            created_at: AtomicU64::new(0),
            connected_wall_at: chrono::Utc::now(),
            expired: std::sync::atomic::AtomicBool::new(false),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            last_request_size: AtomicU64::new(0),
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
            client_forward_tx: None,
            overload_guard: std::sync::Mutex::new(Some(crate::overload::ConnectionGuard::new(
                state,
            ))),
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

    /// #2958 — store + notify_one must wake a reply-style waiter even when the
    /// notify lands in the window between the stop-flag check and select
    /// registration of a fresh `notified()` future (the classic lost-wakeup).
    #[tokio::test(start_paused = true)]
    async fn reply_stop_notify_one_is_observed_without_backend_traffic() {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_notify = Arc::new(tokio::sync::Notify::new());
        let stop_notify_task = Arc::clone(&stop_notify);
        let stop_flag_task = Arc::clone(&stop_flag);

        let waiter = tokio::spawn(async move {
            loop {
                let notified = stop_notify_task.notified();
                tokio::pin!(notified);
                if stop_flag_task.load(Ordering::Acquire) {
                    return;
                }
                // Park until notified (no backend recv). With notify_one the
                // permit stored before this future is polled still wakes us.
                notified.await;
                if stop_flag_task.load(Ordering::Acquire) {
                    return;
                }
            }
        });

        // Yield so the waiter reaches the register-before-check / await path.
        tokio::task::yield_now().await;

        stop_flag.store(true, Ordering::Release);
        stop_notify.notify_one();

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("stop signal must be observed without backend traffic")
            .expect("waiter task");
    }

    /// #2956 — per-session forward channel keeps a slow datagram hook for
    /// client A from delaying client B's enqueue on the shared recv path.
    #[tokio::test(start_paused = true)]
    async fn client_forward_channel_isolates_slow_datagram_hooks() {
        use crate::plugins::{Plugin, ProxyProtocol, UdpDatagramContext, UdpDatagramVerdict};
        use async_trait::async_trait;

        struct SlowForSuffix {
            suffix: String,
            slow_entered: Arc<AtomicBool>,
        }

        #[async_trait]
        impl Plugin for SlowForSuffix {
            fn name(&self) -> &str {
                "test_slow_datagram"
            }
            fn supported_protocols(&self) -> &'static [ProxyProtocol] {
                &[ProxyProtocol::Udp]
            }
            fn requires_udp_datagram_hooks(&self) -> bool {
                true
            }
            async fn on_udp_datagram(&self, ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
                if ctx.client_ip.ends_with(&self.suffix) {
                    self.slow_entered.store(true, Ordering::Release);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                UdpDatagramVerdict::Forward
            }
        }

        let slow_entered = Arc::new(AtomicBool::new(false));
        let plugin: Arc<dyn Plugin> = Arc::new(SlowForSuffix {
            suffix: "1".to_string(),
            slow_entered: Arc::clone(&slow_entered),
        });

        let (tx_a, mut rx_a) = mpsc::channel::<ClientForwardDatagram>(CLIENT_FORWARD_CHANNEL_CAP);
        let (tx_b, mut rx_b) = mpsc::channel::<ClientForwardDatagram>(CLIENT_FORWARD_CHANNEL_CAP);

        // Simulate the shared recv loop: try_send must return immediately for
        // both clients even while A's forward task is blocked in the hook.
        let enqueue_start = Instant::now();
        tx_a.try_send(ClientForwardDatagram {
            data: b"from-a".to_vec(),
            local_addr: None,
        })
        .expect("enqueue A");
        tx_b.try_send(ClientForwardDatagram {
            data: b"from-b".to_vec(),
            local_addr: None,
        })
        .expect("enqueue B");
        assert!(
            enqueue_start.elapsed() < Duration::from_millis(10),
            "recv-loop enqueue must not await per-client datagram hooks"
        );

        let plugin_a = Arc::clone(&plugin);
        let forward_a = tokio::spawn(async move {
            let dgram = rx_a.recv().await.expect("A datagram");
            let ctx = UdpDatagramContext {
                client_ip: Arc::from("10.0.0.1"),
                proxy_id: Arc::from("p"),
                proxy_name: None,
                listen_port: 5300,
                datagram_size: dgram.data.len(),
                direction: UdpDatagramDirection::ClientToBackend,
                payload: &dgram.data,
                payload_kind: crate::plugins::StreamBytesKind::PlaintextWire,
                metadata_sink: None,
            };
            let _ = plugin_a.on_udp_datagram(&ctx).await;
        });

        let plugin_b = Arc::clone(&plugin);
        let b_done = Arc::new(AtomicBool::new(false));
        let b_done_flag = Arc::clone(&b_done);
        let forward_b = tokio::spawn(async move {
            let dgram = rx_b.recv().await.expect("B datagram");
            let ctx = UdpDatagramContext {
                client_ip: Arc::from("10.0.0.2"),
                proxy_id: Arc::from("p"),
                proxy_name: None,
                listen_port: 5300,
                datagram_size: dgram.data.len(),
                direction: UdpDatagramDirection::ClientToBackend,
                payload: &dgram.data,
                payload_kind: crate::plugins::StreamBytesKind::PlaintextWire,
                metadata_sink: None,
            };
            let start = Instant::now();
            let _ = plugin_b.on_udp_datagram(&ctx).await;
            assert!(
                start.elapsed() < Duration::from_millis(10),
                "client B must not inherit client A's hook delay"
            );
            b_done_flag.store(true, Ordering::Release);
        });

        // Advance virtual time so A's 100ms sleep can complete after B finishes.
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(
            b_done.load(Ordering::Acquire),
            "client B forward must complete while A is still sleeping"
        );
        assert!(
            slow_entered.load(Ordering::Acquire),
            "client A slow hook must have started"
        );

        tokio::time::advance(Duration::from_millis(100)).await;
        forward_a.await.expect("A");
        forward_b.await.expect("B");
    }
}
