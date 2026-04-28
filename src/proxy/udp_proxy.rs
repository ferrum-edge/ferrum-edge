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
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::circuit_breaker::CircuitBreakerCache;
use crate::config::types::{BackendScheme, GatewayConfig, Proxy};
use crate::consumer_index::ConsumerIndex;
use crate::dns::DnsCache;
use crate::load_balancer::LoadBalancerCache;
use crate::plugin_cache::PluginCache;
use crate::plugins::{
    Direction, Plugin, PluginResult, ProxyProtocol, StreamConnectionContext,
    StreamTransactionSummary, UdpDatagramContext, UdpDatagramDirection, UdpDatagramVerdict,
};
use crate::proxy::stream_error::{StreamSetupError, StreamSetupKind, find_stream_setup_error};

/// Maximum datagram size for UDP forwarding.
const MAX_UDP_DATAGRAM_SIZE: usize = 65535;

/// Metrics for a single UDP proxy listener.
#[derive(Default)]
pub struct UdpProxyMetrics {
    pub active_sessions: AtomicU64,
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
    last_activity: AtomicU64, // epoch millis
    created_at: AtomicU64,    // epoch millis
    /// Set to `true` by the idle-cleanup task immediately before the
    /// session is removed from the session map. The recv-loop
    /// `last_client` fast path checks this flag and falls through to
    /// `lookup_or_create_session` when it sees an expired session, so
    /// a cached `Arc<UdpSession>` that survived the map removal can't
    /// keep routing traffic through an orphaned backend leg. Without
    /// this gate the fast path serves stale sessions for as long as
    /// the cache holds them, which silently bypasses the configured
    /// `udp_idle_timeout_seconds`.
    expired: std::sync::atomic::AtomicBool,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    /// Size of the last client→backend datagram for amplification factor checking.
    /// Updated on each forwarded request; read on each backend→client response.
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
    /// Plugin metadata from on_stream_connect, carried to on_stream_disconnect.
    metadata: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

/// UDP session map using ahash (AES-NI accelerated) for faster per-datagram lookups.
/// SocketAddr keys are kernel-provided (not attacker-controlled), so cryptographic
/// hashing is unnecessary — speed wins here.
type SessionMap = Arc<DashMap<SocketAddr, Arc<UdpSession>, ahash::RandomState>>;

struct UdpDisconnectContext<'a> {
    namespace: &'a str,
    proxy_id: &'a str,
    proxy_name: Option<&'a str>,
    client_addr: SocketAddr,
    session: &'a UdpSession,
    backend_scheme: BackendScheme,
    listen_port: u16,
    disconnected_ms: u64,
    connection_error: Option<String>,
    error_class: Option<crate::retry::ErrorClass>,
    disconnect_direction: Option<crate::plugins::Direction>,
    disconnect_cause: Option<crate::plugins::DisconnectCause>,
}

fn rfc3339_from_epoch_millis(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

fn build_udp_stream_summary(context: UdpDisconnectContext<'_>) -> StreamTransactionSummary {
    let created_ms = context.session.created_at.load(Ordering::Relaxed);
    let metadata = context
        .session
        .metadata
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    StreamTransactionSummary {
        namespace: context.namespace.to_string(),
        proxy_id: context.proxy_id.to_string(),
        proxy_name: context.proxy_name.map(|name| name.to_string()),
        client_ip: context.client_addr.ip().to_string(),
        consumer_username: context.session.consumer_username.clone(),
        backend_target: context.session.backend_target.clone(),
        backend_resolved_ip: Some(context.session.backend_resolved_ip.clone()),
        protocol: context.backend_scheme.to_string(),
        listen_port: context.listen_port,
        duration_ms: context.disconnected_ms.saturating_sub(created_ms) as f64,
        bytes_sent: context.session.bytes_sent.load(Ordering::Relaxed),
        bytes_received: context.session.bytes_received.load(Ordering::Relaxed),
        connection_error: context.connection_error,
        error_class: context.error_class,
        disconnect_direction: context.disconnect_direction,
        disconnect_cause: context.disconnect_cause,
        timestamp_connected: rfc3339_from_epoch_millis(created_ms),
        timestamp_disconnected: rfc3339_from_epoch_millis(context.disconnected_ms),
        sni_hostname: context.session.sni_hostname.clone(),
        metadata,
    }
}

async fn emit_udp_stream_disconnect(
    plugins: &[Arc<dyn Plugin>],
    context: UdpDisconnectContext<'_>,
) {
    if plugins.is_empty() {
        return;
    }

    let summary = build_udp_stream_summary(context);
    for plugin in plugins {
        plugin.on_stream_disconnect(&summary).await;
    }
}

struct DtlsDisconnectContext<'a> {
    namespace: &'a str,
    proxy_id: &'a str,
    proxy_name: Option<&'a str>,
    client_addr: SocketAddr,
    consumer_username: Option<String>,
    backend_target: &'a str,
    backend_resolved_ip: Option<&'a str>,
    backend_scheme: BackendScheme,
    listen_port: u16,
    connected_at: chrono::DateTime<chrono::Utc>,
    disconnected_at: chrono::DateTime<chrono::Utc>,
    bytes_sent: u64,
    bytes_received: u64,
    connection_error: Option<String>,
    error_class: Option<crate::retry::ErrorClass>,
    disconnect_direction: Option<crate::plugins::Direction>,
    disconnect_cause: Option<crate::plugins::DisconnectCause>,
    metadata: &'a std::collections::HashMap<String, String>,
}

fn build_dtls_stream_summary(context: DtlsDisconnectContext<'_>) -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: context.namespace.to_string(),
        proxy_id: context.proxy_id.to_string(),
        proxy_name: context.proxy_name.map(|name| name.to_string()),
        client_ip: context.client_addr.ip().to_string(),
        consumer_username: context.consumer_username,
        backend_target: context.backend_target.to_string(),
        backend_resolved_ip: context.backend_resolved_ip.map(str::to_string),
        protocol: context.backend_scheme.to_string(),
        listen_port: context.listen_port,
        duration_ms: (context.disconnected_at - context.connected_at).num_milliseconds() as f64,
        bytes_sent: context.bytes_sent,
        bytes_received: context.bytes_received,
        connection_error: context.connection_error,
        error_class: context.error_class,
        disconnect_direction: context.disconnect_direction,
        disconnect_cause: context.disconnect_cause,
        timestamp_connected: context.connected_at.to_rfc3339(),
        timestamp_disconnected: context.disconnected_at.to_rfc3339(),
        sni_hostname: None,
        metadata: context.metadata.clone(),
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
) {
    use std::os::unix::io::AsRawFd;

    if gso_batch.push(data) {
        return;
    }
    // Batch full or size-mismatch — flush current batch and try once more.
    match flush_gso_batch(gso_batch, frontend, client_addr, local_ip) {
        Ok(_) => {
            if !gso_batch.push(data) {
                // Post-flush push still refused (oversize / >max_bytes). Previously
                // this datagram was silently dropped. Log and send it directly as
                // a best-effort single datagram so at least we don't vanish it.
                debug!(
                    proxy_id = %proxy_id,
                    client = %client_addr,
                    size = data.len(),
                    "GSO post-flush push refused datagram, sending directly"
                );
                let _ = frontend.send_to(data, client_addr).await;
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
            // `drain_to_sendmmsg` may partially fill `send_batch`; in that case we
            // flush and keep draining.
            loop {
                gso_batch.drain_to_sendmmsg(send_batch, client_addr, local_ip);
                if gso_batch.is_empty() {
                    break;
                }
                let _ = send_batch.flush(frontend.as_raw_fd());
            }
            // Now push the current datagram, flushing once if necessary.
            if !send_batch.push_with_local(data, client_addr, local_ip) {
                let _ = send_batch.flush(frontend.as_raw_fd());
                if !send_batch.push_with_local(data, client_addr, local_ip) {
                    debug!(
                        proxy_id = %proxy_id,
                        client = %client_addr,
                        size = data.len(),
                        "sendmmsg post-flush push refused datagram, sending directly"
                    );
                    let _ = frontend.send_to(data, client_addr).await;
                }
            }
        }
    }
}

/// Configuration for starting a UDP proxy listener.
pub struct UdpListenerConfig {
    pub port: u16,
    pub bind_addr: IpAddr,
    pub proxy_id: String,
    pub config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
    pub dns_cache: DnsCache,
    pub load_balancer_cache: Arc<LoadBalancerCache>,
    pub consumer_index: Arc<ConsumerIndex>,
    pub shutdown: watch::Receiver<bool>,
    pub metrics: Arc<UdpProxyMetrics>,
    /// DTLS server config for frontend termination. When `Some`, the listener
    /// accepts DTLS connections from clients instead of plain UDP.
    pub frontend_dtls_config: Option<crate::dtls::FrontendDtlsConfig>,
    pub tls_no_verify: bool,
    /// Maximum concurrent sessions per proxy (from `FERRUM_UDP_MAX_SESSIONS`, default 10000).
    pub max_sessions: usize,
    /// Session cleanup interval in seconds (from `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS`, default 10).
    pub cleanup_interval_seconds: u64,
    pub plugin_cache: Arc<PluginCache>,
    /// Circuit breaker cache shared with HTTP proxies.
    pub circuit_breaker_cache: Arc<CircuitBreakerCache>,
    /// Certificate Revocation Lists for backend DTLS verification.
    pub crls: crate::tls::CrlList,
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
        config,
        dns_cache,
        load_balancer_cache,
        consumer_index,
        shutdown,
        metrics,
        frontend_dtls_config,
        tls_no_verify,
        max_sessions,
        cleanup_interval_seconds,
        plugin_cache,
        circuit_breaker_cache,
        crls,
        started,
        sni_proxy_ids,
        adaptive_buffer,
        recvmmsg_batch_size,
        overload,
        so_busy_poll_us,
        udp_gro_enabled,
        udp_gso_enabled,
        udp_pktinfo_enabled,
    } = cfg;
    // so_busy_poll_us and udp_gro_enabled are used in #[cfg(target_os = "linux")] blocks below.
    #[cfg(not(target_os = "linux"))]
    let _ = (so_busy_poll_us, udp_gro_enabled, udp_pktinfo_enabled);

    if let Some(dtls_config) = frontend_dtls_config {
        return start_dtls_frontend_listener(
            port,
            bind_addr,
            proxy_id,
            config,
            dns_cache,
            load_balancer_cache,
            consumer_index,
            shutdown,
            metrics,
            dtls_config,
            tls_no_verify,
            max_sessions,
            plugin_cache,
            circuit_breaker_cache,
            crls,
            started,
            overload,
        )
        .await;
    }

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
            let _ = crate::socket_opts::set_so_busy_poll(fd, so_busy_poll_us);
            let _ = crate::socket_opts::set_so_prefer_busy_poll(fd, true);
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

    let sessions: SessionMap = Arc::new(DashMap::with_hasher(ahash::RandomState::default()));

    // Pre-resolve plugins and proxy metadata for this listener.
    let plugins = plugin_cache.get_plugins_for_protocol(&proxy_id, ProxyProtocol::Udp);
    let has_datagram_plugins = plugins.iter().any(|p| p.requires_udp_datagram_hooks());
    let (proxy_name, proxy_namespace, backend_scheme) = {
        let current = config.load();
        current
            .proxies
            .iter()
            .find(|p| p.id == proxy_id)
            .map(|p| (p.name.clone(), p.namespace.clone(), p.effective_scheme()))
            .unwrap_or((
                None,
                crate::config::types::default_namespace(),
                BackendScheme::Udp,
            ))
    };

    // Look up idle timeout from config
    let idle_timeout = {
        let current = config.load();
        current
            .proxies
            .iter()
            .find(|p| p.id == proxy_id)
            .map(|p| p.udp_idle_timeout_seconds)
            .unwrap_or(60)
    };

    // Spawn session cleanup task
    spawn_session_cleanup(
        sessions.clone(),
        metrics.clone(),
        proxy_id.clone(),
        idle_timeout,
        shutdown.clone(),
        cleanup_interval_seconds,
        plugins.clone(),
        proxy_name.clone(),
        proxy_namespace.clone(),
        backend_scheme,
        port,
    );

    let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
    let mut shutdown_rx = shutdown;

    // Pre-allocate recvmmsg batch buffers (Linux only). On non-Linux, this is a no-op stub.
    #[cfg(target_os = "linux")]
    let mut recv_batch = super::udp_batch::RecvMmsgBatch::new(recvmmsg_batch_size);
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
                                                    &config,
                                                    &dns_cache,
                                                    &load_balancer_cache,
                                                    &frontend_socket,
                                                    &sessions,
                                                    &metrics,
                                                    tls_no_verify,
                                                    max_sessions,
                                                    &mut last_client,
                                                    &mut batch_dgrams_out,
                                                    &mut batch_bytes_out,
                                                    &plugins,
                                                    proxy_name.as_deref(),
                                                    &proxy_namespace,
                                                    backend_scheme,
                                                    port,
                                                    &circuit_breaker_cache,
                                                    &consumer_index,
                                                    has_datagram_plugins,
                                                    &crls,
                                                    sni_proxy_ids.as_deref(),
                                                    &adaptive_buffer,
                                                    udp_gso_enabled,
                                                    local2,
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
                                        &config,
                                        &dns_cache,
                                        &load_balancer_cache,
                                        &frontend_socket,
                                        &sessions,
                                        &metrics,
                                        tls_no_verify,
                                        max_sessions,
                                        &mut last_client,
                                        &mut batch_dgrams_out,
                                        &mut batch_bytes_out,
                                        &plugins,
                                        proxy_name.as_deref(),
                                        &proxy_namespace,
                                        backend_scheme,
                                        port,
                                        &circuit_breaker_cache,
                                        &consumer_index,
                                        has_datagram_plugins,
                                        &crls,
                                        sni_proxy_ids.as_deref(),
                                        &adaptive_buffer,
                                        udp_gso_enabled,
                                        local2,
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
                    &config,
                    &dns_cache,
                    &load_balancer_cache,
                    &frontend_socket,
                    &sessions,
                    &metrics,
                    tls_no_verify,
                    max_sessions,
                    &mut last_client,
                    &mut batch_dgrams_out,
                    &mut batch_bytes_out,
                    &plugins,
                    proxy_name.as_deref(),
                    &proxy_namespace,
                    backend_scheme,
                    port,
                    &circuit_breaker_cache,
                    &consumer_index,
                    has_datagram_plugins,
                    &crls,
                    sni_proxy_ids.as_deref(),
                    &adaptive_buffer,
                    udp_gso_enabled,
                    None,
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
                                                    &config,
                                                    &dns_cache,
                                                    &load_balancer_cache,
                                                    &frontend_socket,
                                                    &sessions,
                                                    &metrics,
                                                    tls_no_verify,
                                                    max_sessions,
                                                    &mut last_client,
                                                    &mut batch_dgrams_out,
                                                    &mut batch_bytes_out,
                                                    &plugins,
                                                    proxy_name.as_deref(),
                                                    &proxy_namespace,
                                                    backend_scheme,
                                                    port,
                                                    &circuit_breaker_cache,
                                                    &consumer_index,
                                                    has_datagram_plugins,
                                                    &crls,
                                                    sni_proxy_ids.as_deref(),
                                                    &adaptive_buffer,
                                                    udp_gso_enabled,
                                                    local2,
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
                                        &config,
                                        &dns_cache,
                                        &load_balancer_cache,
                                        &frontend_socket,
                                        &sessions,
                                        &metrics,
                                        tls_no_verify,
                                        max_sessions,
                                        &mut last_client,
                                        &mut batch_dgrams_out,
                                        &mut batch_bytes_out,
                                        &plugins,
                                        proxy_name.as_deref(),
                                        &proxy_namespace,
                                        backend_scheme,
                                        port,
                                        &circuit_breaker_cache,
                                        &consumer_index,
                                        has_datagram_plugins,
                                        &crls,
                                        sni_proxy_ids.as_deref(),
                                        &adaptive_buffer,
                                        udp_gso_enabled,
                                        local2,
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
                                batch_dgrams_in += 1;
                                batch_bytes_in += len2 as u64;

                                let result = process_datagram(
                                    &buf[..len2],
                                    addr2,
                                    &proxy_id,
                                    &config,
                                    &dns_cache,
                                    &load_balancer_cache,
                                    &frontend_socket,
                                    &sessions,
                                    &metrics,
                                    tls_no_verify,
                                    max_sessions,
                                    &mut last_client,
                                    &mut batch_dgrams_out,
                                    &mut batch_bytes_out,
                                    &plugins,
                                    proxy_name.as_deref(),
                                    &proxy_namespace,
                                    backend_scheme,
                                    port,
                                    &circuit_breaker_cache,
                                    &consumer_index,
                                    has_datagram_plugins,
                                    &crls,
                                    sni_proxy_ids.as_deref(),
                                    &adaptive_buffer,
                                    udp_gso_enabled,
                                    None,
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
    config: &arc_swap::ArcSwap<GatewayConfig>,
    dns_cache: &DnsCache,
    lb_cache: &LoadBalancerCache,
    frontend_socket: &Arc<UdpSocket>,
    sessions: &SessionMap,
    metrics: &Arc<UdpProxyMetrics>,
    tls_no_verify: bool,
    max_sessions: usize,
    last_client: &mut Option<(SocketAddr, Arc<UdpSession>)>,
    batch_dgrams_out: &mut u64,
    batch_bytes_out: &mut u64,
    plugins: &[Arc<dyn Plugin>],
    proxy_name: Option<&str>,
    proxy_namespace: &str,
    backend_scheme: BackendScheme,
    listen_port: u16,
    circuit_breaker_cache: &CircuitBreakerCache,
    consumer_index: &Arc<ConsumerIndex>,
    has_datagram_plugins: bool,
    crls: &crate::tls::CrlList,
    sni_proxy_ids: Option<&[String]>,
    adaptive_buffer: &Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    udp_gso_enabled: bool,
    local_addr: Option<crate::socket_opts::PktinfoLocal>,
) -> Result<(), anyhow::Error> {
    // Run per-datagram plugins (e.g., udp_rate_limiting) before session
    // allocation so dropped datagrams don't consume session slots or trigger
    // backend connection setup.
    if has_datagram_plugins {
        let ctx = UdpDatagramContext {
            client_ip: Arc::from(client_addr.ip().to_string()),
            proxy_id: Arc::from(proxy_id),
            proxy_name: proxy_name.map(Arc::from),
            listen_port,
            datagram_size: data.len(),
            direction: UdpDatagramDirection::ClientToBackend,
        };
        for plugin in plugins {
            if plugin.requires_udp_datagram_hooks()
                && matches!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop)
            {
                return Ok(()); // Silent drop — standard UDP behavior
            }
        }
    }

    // Fast path: check last-client cache before hitting DashMap.
    // Skip the cache when the cached session has been flagged expired
    // by the idle-cleanup task — that path removes the session from
    // the map but the recv-loop's `Arc` keeps it alive, so without
    // this check we'd keep forwarding through a session the cleanup
    // task already declared dead and the configured
    // `udp_idle_timeout_seconds` would be quietly ignored.
    let session = if let Some((cached_addr, ref cached_session)) = *last_client
        && cached_addr == client_addr
        && !cached_session
            .expired
            .load(std::sync::atomic::Ordering::Acquire)
    {
        cached_session.clone()
    } else {
        lookup_or_create_session(
            client_addr,
            proxy_id,
            config,
            dns_cache,
            lb_cache,
            frontend_socket,
            sessions,
            metrics,
            tls_no_verify,
            max_sessions,
            plugins,
            proxy_name,
            proxy_namespace,
            backend_scheme,
            listen_port,
            circuit_breaker_cache,
            consumer_index,
            crls,
            data,
            sni_proxy_ids,
            adaptive_buffer,
            udp_gso_enabled,
        )
        .await?
    };

    // Record the per-datagram local (destination) address on the session the
    // first time the kernel exposes one. `OnceLock::set` is a no-op if already
    // set, so this is cheap on subsequent datagrams.
    if let Some(la) = local_addr {
        let _ = session.local_addr.set(la);
    }

    // Update cache for next datagram.
    *last_client = Some((client_addr, session.clone()));

    // Forward to backend.
    session
        .last_activity
        .store(coarse_epoch_millis(), Ordering::Relaxed);
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
                .bytes_sent
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            session
                .last_request_size
                .store(data.len() as u64, Ordering::Relaxed);
            *batch_dgrams_out += 1;
            *batch_bytes_out += data.len() as u64;
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("send to backend failed: {}", e)),
    }
}

/// Look up an existing session or create a new one.
#[allow(clippy::too_many_arguments)]
async fn lookup_or_create_session(
    client_addr: SocketAddr,
    proxy_id: &str,
    config: &arc_swap::ArcSwap<GatewayConfig>,
    dns_cache: &DnsCache,
    lb_cache: &LoadBalancerCache,
    frontend_socket: &Arc<UdpSocket>,
    sessions: &SessionMap,
    metrics: &Arc<UdpProxyMetrics>,
    tls_no_verify: bool,
    max_sessions: usize,
    plugins: &[Arc<dyn Plugin>],
    proxy_name: Option<&str>,
    proxy_namespace: &str,
    backend_scheme: BackendScheme,
    listen_port: u16,
    circuit_breaker_cache: &CircuitBreakerCache,
    consumer_index: &Arc<ConsumerIndex>,
    crls: &crate::tls::CrlList,
    initial_data: &[u8],
    sni_proxy_ids: Option<&[String]>,
    adaptive_buffer: &Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    udp_gso_enabled: bool,
) -> Result<Arc<UdpSession>, anyhow::Error> {
    if let Some(existing) = sessions.get(&client_addr) {
        return Ok(existing.value().clone());
    }

    // Atomically reserve a slot: increment active_sessions first, then check the limit.
    // If we exceed the limit, undo the increment and reject. This prevents the TOCTOU
    // race where multiple concurrent connections all pass a len() check before any insert.
    let prev = metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
    if prev >= max_sessions as u64 {
        metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        return Err(anyhow::anyhow!(
            "UDP session limit reached ({}), dropping datagram",
            max_sessions
        ));
    }

    match create_session(
        proxy_id,
        config,
        dns_cache,
        lb_cache,
        frontend_socket,
        client_addr,
        sessions,
        metrics,
        tls_no_verify,
        plugins,
        proxy_name,
        proxy_namespace,
        backend_scheme,
        listen_port,
        circuit_breaker_cache,
        consumer_index,
        crls,
        initial_data,
        sni_proxy_ids,
        adaptive_buffer,
        udp_gso_enabled,
    )
    .await
    {
        Ok(session) => Ok(session),
        Err(e) => {
            // Session creation failed — release the reserved slot.
            metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
            Err(e)
        }
    }
}

/// Spawn a background task that periodically removes idle UDP sessions.
#[allow(clippy::too_many_arguments)]
fn spawn_session_cleanup(
    sessions: SessionMap,
    metrics: Arc<UdpProxyMetrics>,
    proxy_id: String,
    idle_timeout_seconds: u64,
    mut shutdown: watch::Receiver<bool>,
    cleanup_interval_seconds: u64,
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
    proxy_name: Option<String>,
    proxy_namespace: String,
    backend_scheme: BackendScheme,
    listen_port: u16,
) {
    let idle_timeout_ms = idle_timeout_seconds * 1000;

    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(cleanup_interval_seconds.max(1)));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = coarse_epoch_millis();
                    let mut expired = Vec::new();

                    for entry in sessions.iter() {
                        let last = entry.value().last_activity.load(Ordering::Relaxed);
                        if now.saturating_sub(last) > idle_timeout_ms {
                            expired.push(*entry.key());
                        }
                    }

                    for addr in &expired {
                        if let Some((_, session)) = sessions.remove(addr) {
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
                            let bs = session.bytes_sent.load(Ordering::Relaxed);
                            let br = session.bytes_received.load(Ordering::Relaxed);
                            metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                            debug!(
                                proxy_id = %proxy_id,
                                client = %addr,
                                bytes_sent = bs,
                                bytes_received = br,
                                "UDP session expired (idle timeout)"
                            );

                            emit_udp_stream_disconnect(
                                &plugins,
                                UdpDisconnectContext {
                                    namespace: &proxy_namespace,
                                    proxy_id: &proxy_id,
                                    proxy_name: proxy_name.as_deref(),
                                    client_addr: *addr,
                                    session: &session,
                                    backend_scheme,
                                    listen_port,
                                    disconnected_ms: now,
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
    config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
    dns_cache: DnsCache,
    load_balancer_cache: Arc<LoadBalancerCache>,
    consumer_index: Arc<ConsumerIndex>,
    shutdown: watch::Receiver<bool>,
    metrics: Arc<UdpProxyMetrics>,
    dtls_config: crate::dtls::FrontendDtlsConfig,
    tls_no_verify: bool,
    max_sessions: usize,
    plugin_cache: Arc<PluginCache>,
    circuit_breaker_cache: Arc<CircuitBreakerCache>,
    crls: crate::tls::CrlList,
    started: Arc<AtomicBool>,
    overload: Arc<crate::overload::OverloadState>,
) -> Result<(), anyhow::Error> {
    let addr = SocketAddr::new(bind_addr, port);
    let server = Arc::new(crate::dtls::DtlsServer::bind(addr, dtls_config).await?);
    ensure_coarse_timer_started();
    started.store(true, Ordering::Release);
    info!(proxy_id = %proxy_id, "DTLS frontend listener started on {}", addr);

    // Pre-resolve plugins and proxy metadata for this listener.
    let plugins = plugin_cache.get_plugins_for_protocol(&proxy_id, ProxyProtocol::Udp);
    let has_datagram_plugins = plugins.iter().any(|p| p.requires_udp_datagram_hooks());
    let (proxy_name, proxy_namespace, backend_scheme) = {
        let current = config.load();
        current
            .proxies
            .iter()
            .find(|p| p.id == proxy_id)
            .map(|p| (p.name.clone(), p.namespace.clone(), p.effective_scheme()))
            .unwrap_or((
                None,
                crate::config::types::default_namespace(),
                BackendScheme::Dtls,
            ))
    };

    // Spawn the server's recv loop in a background task
    let server_runner = server.clone();
    let runner_proxy_id = proxy_id.clone();
    let server_task = tokio::spawn(async move {
        if let Err(e) = server_runner.run().await {
            warn!(proxy_id = %runner_proxy_id, "DTLS server recv loop error: {}", e);
        }
    });

    let mut shutdown_rx = shutdown;

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

                // Atomically reserve a session slot
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

                // Run on_stream_connect plugins (with DTLS client cert if available)
                let mut stream_ctx = StreamConnectionContext {
                    client_ip: client_addr.ip().to_string(),
                    proxy_id: proxy_id.clone(),
                    proxy_name: proxy_name.clone(),
                    listen_port: port,
                    backend_scheme,
                    consumer_index: consumer_index.clone(),
                    identified_consumer: None,
                    authenticated_identity: None,
                    metadata: None,
                    tls_client_cert_der: client_conn.tls_client_cert_der.clone(),
                    tls_client_cert_chain_der: client_conn.tls_client_cert_chain_der.clone(),
                    sni_hostname: None,
                };
                let mut rejected = false;
                for plugin in plugins.iter() {
                    if let PluginResult::Reject { .. } = plugin.on_stream_connect(&mut stream_ctx).await {
                        debug!(
                            proxy_id = %proxy_id,
                            client = %client_addr,
                            "DTLS connection rejected by plugin"
                        );
                        client_conn.close().await;
                        rejected = true;
                        break;
                    }
                }
                if rejected {
                    metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }

                metrics.total_sessions.fetch_add(1, Ordering::Relaxed);

                debug!(
                    proxy_id = %proxy_id,
                    client = %client_addr,
                    "DTLS frontend connection accepted"
                );

                // Spawn per-client handler
                let handler_proxy_id = proxy_id.clone();
                let handler_config = config.clone();
                let handler_dns = dns_cache.clone();
                let handler_lb = load_balancer_cache.clone();
                let handler_metrics = metrics.clone();
                let handler_plugins = plugins.clone();
                let handler_proxy_name = proxy_name.clone();
                let handler_proxy_namespace = proxy_namespace.clone();
                let handler_consumer_username = stream_ctx.effective_identity().map(str::to_owned);
                let handler_metadata = stream_ctx.take_metadata();
                let handler_cb_cache = circuit_breaker_cache.clone();
                let connected_at = chrono::Utc::now();

                let handler_has_dgram_plugins = has_datagram_plugins;
                let handler_crls = crls.clone();
                tokio::spawn(async move {
                    let result = handle_dtls_client(
                        client_conn,
                        client_addr,
                        &handler_proxy_id,
                        &handler_config,
                        &handler_dns,
                        &handler_lb,
                        &handler_metrics,
                        tls_no_verify,
                        &handler_cb_cache,
                        &handler_plugins,
                        handler_proxy_name.as_deref(),
                        port,
                        handler_has_dgram_plugins,
                        &handler_crls,
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
                                let err_class = crate::retry::classify_boxed_error(e.as_ref());
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

                    // Fire on_stream_disconnect plugins
                    if !handler_plugins.is_empty() {
                        let disconnected_at = chrono::Utc::now();
                        let summary = build_dtls_stream_summary(DtlsDisconnectContext {
                            namespace: &handler_proxy_namespace,
                            proxy_id: &handler_proxy_id,
                            proxy_name: handler_proxy_name.as_deref(),
                            client_addr,
                            consumer_username: handler_consumer_username.clone(),
                            backend_target: &result.backend.backend_target,
                            backend_resolved_ip: result.backend.backend_resolved_ip.as_deref(),
                            backend_scheme,
                            listen_port: port,
                            connected_at,
                            disconnected_at,
                            bytes_sent: result.bytes_sent,
                            bytes_received: result.bytes_received,
                            connection_error: err_msg,
                            error_class,
                            disconnect_direction,
                            disconnect_cause,
                            metadata: &handler_metadata,
                        });
                        for plugin in handler_plugins.iter() {
                            plugin.on_stream_disconnect(&summary).await;
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
    config: &arc_swap::ArcSwap<GatewayConfig>,
    dns_cache: &DnsCache,
    lb_cache: &LoadBalancerCache,
    metrics: &Arc<UdpProxyMetrics>,
    tls_no_verify: bool,
    circuit_breaker_cache: &CircuitBreakerCache,
    plugins: &[Arc<dyn Plugin>],
    proxy_name: Option<&str>,
    listen_port: u16,
    has_datagram_plugins: bool,
    crls: &crate::tls::CrlList,
) -> DtlsHandlerResult {
    let mut backend_info = DtlsBackendInfo {
        backend_target: String::new(),
        backend_resolved_ip: None,
    };
    let bytes_sent = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));
    let last_request_size = Arc::new(AtomicU64::new(0));
    let outcome = handle_dtls_client_inner(
        client_conn,
        client_addr,
        proxy_id,
        config,
        dns_cache,
        lb_cache,
        metrics,
        tls_no_verify,
        circuit_breaker_cache,
        &mut backend_info,
        Arc::clone(&bytes_sent),
        Arc::clone(&bytes_received),
        Arc::clone(&last_request_size),
        plugins,
        proxy_name,
        listen_port,
        has_datagram_plugins,
        crls,
    )
    .await;
    DtlsHandlerResult {
        backend: backend_info,
        bytes_sent: bytes_sent.load(Ordering::Relaxed),
        bytes_received: bytes_received.load(Ordering::Relaxed),
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

#[allow(clippy::too_many_arguments)]
async fn handle_dtls_client_inner(
    client_conn: crate::dtls::DtlsServerConn,
    client_addr: SocketAddr,
    proxy_id: &str,
    config: &arc_swap::ArcSwap<GatewayConfig>,
    dns_cache: &DnsCache,
    lb_cache: &LoadBalancerCache,
    metrics: &Arc<UdpProxyMetrics>,
    tls_no_verify: bool,
    circuit_breaker_cache: &CircuitBreakerCache,
    backend_info: &mut DtlsBackendInfo,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    last_request_size: Arc<AtomicU64>,
    plugins: &[Arc<dyn Plugin>],
    proxy_name: Option<&str>,
    listen_port: u16,
    has_datagram_plugins: bool,
    crls: &crate::tls::CrlList,
) -> Result<(), anyhow::Error> {
    // Look up proxy config
    let current_config = config.load();
    let proxy = current_config
        .proxies
        .iter()
        .find(|p| p.id == proxy_id)
        .ok_or_else(|| anyhow::anyhow!("Proxy {} not found", proxy_id))?
        .clone();

    // Resolve backend target
    let (backend_host, backend_port) = resolve_backend_target(&proxy, lb_cache)?;
    // Populate backend target as soon as it's known — even if DNS or connect fails.
    backend_info.backend_target = format!("{}:{}", backend_host, backend_port);

    // Circuit breaker check — reject before creating backend connection if open.
    let cb_target_key = proxy
        .upstream_id
        .as_ref()
        .map(|_| crate::circuit_breaker::target_key(&backend_host, backend_port));
    if let Some(ref cb_config) = proxy.circuit_breaker
        && circuit_breaker_cache
            .can_execute(proxy_id, cb_target_key.as_deref(), cb_config)
            .is_err()
    {
        warn!(
            proxy_id = %proxy_id,
            client = %client_addr,
            "DTLS session rejected: circuit breaker open"
        );
        return Err(anyhow::anyhow!("circuit breaker open"));
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
            if let Some(ref cb_config) = proxy.circuit_breaker {
                let cb = circuit_breaker_cache.get_or_create(
                    proxy_id,
                    cb_target_key.as_deref(),
                    cb_config,
                );
                cb.record_failure(502, true);
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
                    cb.record_failure(502, true);
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
                cb.record_failure(502, true);
            }
            return Err(anyhow::anyhow!(
                "Failed to connect to backend {}: {}",
                backend_addr,
                e
            ));
        }
        let dtls_params =
            crate::dtls::build_backend_dtls_config(&proxy, &backend_host, tls_no_verify, crls)?;
        let dtls = match crate::dtls::DtlsConnection::connect(socket, dtls_params).await {
            Ok(d) => Arc::new(d),
            Err(e) => {
                if let Some(ref cb_config) = proxy.circuit_breaker {
                    let cb = circuit_breaker_cache.get_or_create(
                        proxy_id,
                        cb_target_key.as_deref(),
                        cb_config,
                    );
                    cb.record_failure(502, true);
                }
                // dtls::DtlsConnection::connect returns anyhow::Error, which
                // doesn't implement std::error::Error directly — render the
                // chain into the message so log lines and source-walking
                // consumers still see the underlying cause.
                return Err(StreamSetupError::new(
                    StreamSetupKind::BackendDtlsHandshake,
                    format!(": {e:#}"),
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
                    cb.record_failure(502, true);
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
                cb.record_failure(502, true);
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
        cb.record_success();
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
    let dgram_plugins: Arc<[Arc<dyn Plugin>]> = if has_datagram_plugins {
        plugins
            .iter()
            .filter(|p| p.requires_udp_datagram_hooks())
            .cloned()
            .collect()
    } else {
        Arc::from([])
    };
    // Pre-compute context strings as Arc<str> — per-datagram "clone" is a pointer
    // bump (~5ns) instead of heap allocation + memcpy.
    let dgram_client_ip: Arc<str> = Arc::from(client_addr.ip().to_string());
    let dgram_proxy_id: Arc<str> = Arc::from(proxy_id);
    let dgram_proxy_name: Option<Arc<str>> = proxy_name.map(Arc::from);
    let dgram_listen_port = listen_port;
    // Clone Arcs for the reverse direction BEFORE the forward spawn moves them.
    let dgram_plugins_rev = Arc::clone(&dgram_plugins);
    let dgram_client_ip_rev = Arc::clone(&dgram_client_ip);
    let dgram_proxy_id_rev = Arc::clone(&dgram_proxy_id);
    let dgram_proxy_name_rev = dgram_proxy_name.clone();

    // Client → Backend
    let client_to_backend = tokio::spawn(async move {
        loop {
            let data = match client_conn.recv().await {
                Ok(d) if d.is_empty() => break,
                Ok(d) => d,
                Err(_) => break,
            };
            let len = data.len();

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
            last_request_size_fwd.store(len as u64, Ordering::Relaxed);
        }
    });

    // Backend → Client — reuse pre-computed plugin list and context strings
    // (dgram_*_rev cloned above before the forward spawn moved the originals).
    let metrics_rev = metrics.clone();
    let proxy_id_rev = dgram_proxy_id_rev.to_string();
    let bytes_received_rev = Arc::clone(&bytes_received);
    let amplification_factor_rev = proxy.udp_max_response_amplification_factor;
    let last_request_size_rev = Arc::clone(&last_request_size);

    let backend_to_client = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
        loop {
            let data = if let Some(ref dtls) = backend_dtls {
                match dtls.recv().await {
                    Ok(d) if d.is_empty() => break,
                    Ok(d) => d,
                    Err(_) => break,
                }
            } else if let Some(ref sock) = backend_udp {
                match sock.recv(&mut buf).await {
                    Ok(0) => break,
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

            // Amplification factor check for DTLS path
            if let Some(factor) = amplification_factor_rev {
                let req_size = last_request_size_rev.load(Ordering::Relaxed);
                if req_size > 0 {
                    let max_response = (req_size as f64 * factor as f64) as u64;
                    if len as u64 > max_response {
                        continue; // Drop oversized response
                    }
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
        }
    });

    // Wait for either direction to finish, then clean up
    tokio::select! {
        _ = client_to_backend => {}
        _ = backend_to_client => {}
    }

    client_close.close().await;
    if let Some(ref dtls) = backend_dtls_cleanup {
        dtls.close().await;
    }

    Ok(())
}

/// Create a new UDP session for a client (plain UDP frontend path).
#[allow(clippy::too_many_arguments)]
async fn create_session(
    proxy_id: &str,
    config: &arc_swap::ArcSwap<GatewayConfig>,
    dns_cache: &DnsCache,
    lb_cache: &LoadBalancerCache,
    frontend_socket: &Arc<UdpSocket>,
    client_addr: SocketAddr,
    sessions: &SessionMap,
    metrics: &Arc<UdpProxyMetrics>,
    tls_no_verify: bool,
    plugins: &[Arc<dyn Plugin>],
    proxy_name: Option<&str>,
    proxy_namespace: &str,
    backend_scheme: BackendScheme,
    listen_port: u16,
    circuit_breaker_cache: &CircuitBreakerCache,
    consumer_index: &Arc<ConsumerIndex>,
    crls: &crate::tls::CrlList,
    initial_data: &[u8],
    sni_proxy_ids: Option<&[String]>,
    adaptive_buffer: &Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    udp_gso_enabled: bool,
) -> Result<Arc<UdpSession>, anyhow::Error> {
    // Check if this proxy uses passthrough mode (extract from config once).
    let is_passthrough = {
        let current = config.load();
        current
            .proxies
            .iter()
            .find(|p| p.id == proxy_id)
            .map(|p| p.passthrough)
            .unwrap_or(false)
    };

    // In passthrough mode, extract SNI from the first DTLS ClientHello datagram.
    let sni_hostname = if is_passthrough {
        super::sni::extract_sni_from_dtls_client_hello(initial_data)
    } else {
        None
    };

    // --- SNI-based proxy resolution for shared passthrough ports ---
    let _resolved_proxy_id: Option<String>;
    let proxy_id = if let Some(sni_ids) = sni_proxy_ids {
        let current_config = config.load();
        let matched =
            super::sni::resolve_proxy_by_sni(sni_hostname.as_deref(), sni_ids, &current_config)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No matching passthrough proxy for SNI {:?} on port {}",
                        sni_hostname,
                        listen_port
                    )
                })?;
        _resolved_proxy_id = Some(matched.to_string());
        _resolved_proxy_id.as_deref().unwrap_or(proxy_id)
    } else {
        _resolved_proxy_id = None;
        proxy_id
    };

    // Run on_stream_connect plugins before creating backend connection
    let mut stream_ctx = StreamConnectionContext {
        client_ip: client_addr.ip().to_string(),
        proxy_id: proxy_id.to_string(),
        proxy_name: proxy_name.map(|s| s.to_string()),
        listen_port,
        backend_scheme,
        consumer_index: consumer_index.clone(),
        identified_consumer: None,
        authenticated_identity: None,
        metadata: None,
        tls_client_cert_der: None,
        tls_client_cert_chain_der: None,
        sni_hostname,
    };
    for plugin in plugins {
        if let PluginResult::Reject { .. } = plugin.on_stream_connect(&mut stream_ctx).await {
            return Err(
                StreamSetupError::new(StreamSetupKind::RejectedByPlugin, "(UDP session)").into(),
            );
        }
    }

    let current_config = config.load();
    let proxy = current_config
        .proxies
        .iter()
        .find(|p| p.id == proxy_id)
        .ok_or_else(|| anyhow::anyhow!("Proxy {} not found", proxy_id))?
        .clone();

    // Resolve backend target
    let (backend_host, backend_port) = resolve_backend_target(&proxy, lb_cache)?;

    // Circuit breaker check — reject before creating backend socket if open.
    let cb_target_key = proxy
        .upstream_id
        .as_ref()
        .map(|_| crate::circuit_breaker::target_key(&backend_host, backend_port));
    if let Some(ref cb_config) = proxy.circuit_breaker
        && circuit_breaker_cache
            .can_execute(proxy_id, cb_target_key.as_deref(), cb_config)
            .is_err()
    {
        warn!(
            proxy_id = %proxy_id,
            client = %client_addr,
            "UDP session rejected: circuit breaker open"
        );
        return Err(anyhow::anyhow!("circuit breaker open"));
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
            if let Some(ref cb_config) = proxy.circuit_breaker {
                let cb = circuit_breaker_cache.get_or_create(
                    proxy_id,
                    cb_target_key.as_deref(),
                    cb_config,
                );
                cb.record_failure(502, true);
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
                        cb.record_failure(502, true);
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
                    cb.record_failure(502, true);
                }
                return Err(anyhow::anyhow!(
                    "Failed to connect UDP socket to {}: {}",
                    backend_addr,
                    e
                ));
            }

            let dtls_params =
                crate::dtls::build_backend_dtls_config(&proxy, &backend_host, tls_no_verify, crls)?;
            let dtls = match crate::dtls::DtlsConnection::connect(socket, dtls_params).await {
                Ok(d) => Arc::new(d),
                Err(e) => {
                    if let Some(ref cb_config) = proxy.circuit_breaker {
                        let cb = circuit_breaker_cache.get_or_create(
                            proxy_id,
                            cb_target_key.as_deref(),
                            cb_config,
                        );
                        cb.record_failure(502, true);
                    }
                    // dtls::DtlsConnection::connect returns anyhow::Error,
                    // which doesn't implement std::error::Error directly —
                    // render the chain into the message so consumers still
                    // see the underlying cause.
                    return Err(StreamSetupError::new(
                        StreamSetupKind::BackendDtlsHandshake,
                        format!(": {e:#}"),
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
                        cb.record_failure(502, true);
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
                    cb.record_failure(502, true);
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
        cb.record_success();
    }

    let now = coarse_epoch_millis();
    let consumer_username = stream_ctx.effective_identity().map(str::to_owned);
    let session = Arc::new(UdpSession {
        backend_socket: backend_socket.clone(),
        dtls_conn: dtls_conn.clone(),
        last_activity: AtomicU64::new(now),
        created_at: AtomicU64::new(now),
        expired: std::sync::atomic::AtomicBool::new(false),
        bytes_sent: AtomicU64::new(0),
        bytes_received: AtomicU64::new(0),
        last_request_size: AtomicU64::new(0),
        backend_target: format!("{}:{}", backend_host, backend_port),
        backend_resolved_ip: resolved_ip.to_string(),
        sni_hostname: stream_ctx.sni_hostname.clone(),
        consumer_username,
        metadata: std::sync::Mutex::new(stream_ctx.take_metadata()),
        local_addr: std::sync::OnceLock::new(),
    });

    sessions.insert(client_addr, session.clone());
    // Note: active_sessions is incremented by the caller (lookup_or_create_session)
    // before create_session is called, to avoid TOCTOU race conditions.
    metrics.total_sessions.fetch_add(1, Ordering::Relaxed);

    debug!(
        proxy_id = %proxy_id,
        client = %client_addr,
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
    let reply_proxy_name = proxy_name.map(str::to_string);
    let reply_proxy_namespace = proxy_namespace.to_string();
    let reply_backend_scheme = backend_scheme;
    let reply_amplification_factor = proxy.udp_max_response_amplification_factor;
    let reply_adaptive_buffer = adaptive_buffer.clone();
    let reply_has_datagram_plugins = plugins.iter().any(|p| p.requires_udp_datagram_hooks());
    let reply_datagram_plugins: Vec<Arc<dyn Plugin>> = if reply_has_datagram_plugins {
        plugins
            .iter()
            .filter(|p| p.requires_udp_datagram_hooks())
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let reply_dgram_client_ip: Arc<str> = Arc::from(client_addr.ip().to_string());
    let reply_dgram_proxy_id: Arc<str> = Arc::from(proxy_id);
    let reply_dgram_proxy_name2: Option<Arc<str>> = proxy_name.map(Arc::from);
    let reply_listen_port = listen_port;
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
            // Read from backend — via DTLS (channel-based) or raw UDP (socket-based)
            let (data_slice, data_vec);
            let len;
            if let Some(ref dtls) = reply_dtls {
                match dtls.recv().await {
                    Ok(d) if d.is_empty() => break,
                    Ok(d) => {
                        len = d.len();
                        data_vec = Some(d);
                        data_slice = None;
                    }
                    Err(e) => {
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
                match sock.recv(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        len = n;
                        data_vec = None;
                        data_slice = Some(&buf[..n]);
                    }
                    Err(e) => {
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
                let req_size = reply_session.last_request_size.load(Ordering::Relaxed);
                if req_size > 0 {
                    let max_response = (req_size as f64 * factor as f64) as u64;
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
            }

            // Run backend→client per-datagram plugin hooks.
            if reply_has_datagram_plugins {
                let ctx = UdpDatagramContext {
                    client_ip: reply_dgram_client_ip.clone(),
                    proxy_id: reply_dgram_proxy_id.clone(),
                    proxy_name: reply_dgram_proxy_name2.clone(),
                    listen_port: reply_listen_port,
                    datagram_size: len,
                    direction: UdpDatagramDirection::BackendToClient,
                };
                let mut drop = false;
                for plugin in &reply_datagram_plugins {
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
                        )
                        .await;
                    } else {
                        send_batch.push_with_local(send_data, client_addr, session_local_ip);
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
                                    reply_session.last_request_size.load(Ordering::Relaxed);
                                if req_size > 0 {
                                    let max_response = (req_size as f64 * factor as f64) as u64;
                                    if len2 as u64 > max_response {
                                        continue; // Drop oversized response
                                    }
                                }
                            }
                            // Backend→client plugin hooks on batched datagram
                            if reply_has_datagram_plugins {
                                let ctx = UdpDatagramContext {
                                    client_ip: reply_dgram_client_ip.clone(),
                                    proxy_id: reply_dgram_proxy_id.clone(),
                                    proxy_name: reply_dgram_proxy_name2.clone(),
                                    listen_port: reply_listen_port,
                                    datagram_size: len2,
                                    direction: UdpDatagramDirection::BackendToClient,
                                };
                                let mut drop = false;
                                for plugin in &reply_datagram_plugins {
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
                                        )
                                        .await;
                                    } else if !send_batch.push_with_local(
                                        &buf[..len2],
                                        client_addr,
                                        session_local_ip,
                                    ) {
                                        // Batch full — flush and push again.
                                        use std::os::unix::io::AsRawFd;
                                        let _ = send_batch.flush(frontend.as_raw_fd());
                                        send_batch.push_with_local(
                                            &buf[..len2],
                                            client_addr,
                                            session_local_ip,
                                        );
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
                                if reply_sessions.remove(&client_addr).is_some() {
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
                        // Replay all buffered datagrams through sendmmsg.
                        loop {
                            gso_batch.drain_to_sendmmsg(
                                &mut send_batch,
                                client_addr,
                                session_local_ip,
                            );
                            if gso_batch.is_empty() {
                                break;
                            }
                            use std::os::unix::io::AsRawFd;
                            let _ = send_batch.flush(frontend.as_raw_fd());
                        }
                    }
                }
                // Flush sendmmsg batch (used when GSO is disabled/failed, or GSO drain).
                if !send_batch.is_empty() {
                    use std::os::unix::io::AsRawFd;
                    let fd = frontend.as_raw_fd();
                    loop {
                        match send_batch.flush(fd) {
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
        // Only decrement active_sessions if we actually removed the session
        // (the cleanup task may have already removed and decremented it).
        if reply_sessions.remove(&client_addr).is_some() {
            reply_metrics
                .active_sessions
                .fetch_sub(1, Ordering::Relaxed);
            let disconnected_ms = coarse_epoch_millis();
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
fn resolve_backend_target(
    proxy: &Proxy,
    lb_cache: &LoadBalancerCache,
) -> Result<(String, u16), anyhow::Error> {
    if let Some(upstream_id) = &proxy.upstream_id {
        let selection = lb_cache
            .select_target(upstream_id, &proxy.id, None)
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

/// Coarse-grained epoch millisecond timestamp updated periodically.
/// Avoids calling `SystemTime::now()` on every datagram in the hot path.
/// Resolution is ~100ms which is more than sufficient for session idle timeout
/// tracking (timeouts are typically 60s+) while saving ~990 timer wakes/sec
/// compared to the previous 1ms resolution.
static COARSE_EPOCH_MS: AtomicU64 = AtomicU64::new(0);

/// Start the background timer that updates `COARSE_EPOCH_MS` every 100ms.
/// Safe to call multiple times; only the first call spawns the task.
fn ensure_coarse_timer_started() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Seed with current time
        COARSE_EPOCH_MS.store(epoch_millis_precise(), Ordering::Relaxed);
        tokio::spawn(async {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                COARSE_EPOCH_MS.store(epoch_millis_precise(), Ordering::Relaxed);
            }
        });
    });
}

/// Get the coarse-grained cached timestamp (updated every ~1ms).
#[inline(always)]
fn coarse_epoch_millis() -> u64 {
    COARSE_EPOCH_MS.load(Ordering::Relaxed)
}

/// Precise epoch millis - used for timer updates and initial seeding.
fn epoch_millis_precise() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::{
        DtlsDisconnectContext, STREAM_ERR_BACKEND_DTLS_HANDSHAKE_FAILED, UdpDisconnectContext,
        UdpSession, build_dtls_stream_summary, build_udp_stream_summary, dtls_disconnect_cause,
        dtls_disconnect_direction, emit_udp_stream_disconnect,
    };
    use crate::config::types::BackendScheme;
    use crate::plugins::{Plugin, StreamTransactionSummary};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::sync::{Mutex, MutexGuard};

    fn make_udp_session() -> UdpSession {
        UdpSession {
            backend_socket: None,
            dtls_conn: None,
            last_activity: AtomicU64::new(1_710_000_000_500),
            created_at: AtomicU64::new(1_710_000_000_000),
            expired: std::sync::atomic::AtomicBool::new(false),
            bytes_sent: AtomicU64::new(128),
            bytes_received: AtomicU64::new(256),
            last_request_size: AtomicU64::new(64),
            backend_target: "10.0.0.50:5353".to_string(),
            backend_resolved_ip: "10.0.0.50".to_string(),
            sni_hostname: None,
            consumer_username: None,
            metadata: std::sync::Mutex::new(HashMap::from([(
                "request_id".to_string(),
                "stream-123".to_string(),
            )])),
            local_addr: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn test_build_dtls_stream_summary_preserves_bytes_error_and_metadata() {
        let client_addr: SocketAddr = "127.0.0.1:54000".parse().unwrap();
        let connected_at = chrono::Utc::now() - chrono::TimeDelta::milliseconds(750);
        let disconnected_at = chrono::Utc::now();
        let metadata = HashMap::from([("request_id".to_string(), "dtls-123".to_string())]);

        let summary = build_dtls_stream_summary(DtlsDisconnectContext {
            namespace: "ferrum",
            proxy_id: "dtls-proxy",
            proxy_name: Some("DTLS Proxy"),
            client_addr,
            consumer_username: Some("alice".to_string()),
            backend_target: "10.0.0.60:7443",
            backend_resolved_ip: Some("10.0.0.60"),
            backend_scheme: BackendScheme::Dtls,
            listen_port: 7443,
            connected_at,
            disconnected_at,
            bytes_sent: 321,
            bytes_received: 654,
            connection_error: Some("tls alert".to_string()),
            error_class: Some(crate::retry::ErrorClass::TlsError),
            disconnect_direction: None,
            disconnect_cause: Some(crate::plugins::DisconnectCause::RecvError),
            metadata: &metadata,
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
        assert_eq!(
            summary.metadata.get("request_id").map(String::as_str),
            Some("dtls-123")
        );
        assert!(summary.duration_ms >= 0.0);
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

        let summary = build_udp_stream_summary(UdpDisconnectContext {
            namespace: "ferrum",
            proxy_id: "udp-proxy",
            proxy_name: Some("UDP Proxy"),
            client_addr,
            session: &session,
            backend_scheme: BackendScheme::Udp,
            listen_port: 5353,
            disconnected_ms: 1_710_000_001_500,
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
            summary.metadata.get("request_id").map(String::as_str),
            Some("stream-123")
        );
        assert!(
            summary.timestamp_connected.ends_with("+00:00")
                || summary.timestamp_connected.ends_with('Z')
        );
        assert!(
            summary.timestamp_disconnected.ends_with("+00:00")
                || summary.timestamp_disconnected.ends_with('Z')
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
}
