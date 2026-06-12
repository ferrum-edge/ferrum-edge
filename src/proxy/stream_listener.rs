//! Manages lifecycle of TCP/UDP stream proxy listeners.
//!
//! The `StreamListenerManager` reconciles the set of active listeners against
//! the current `GatewayConfig`. On config reload it starts new listeners,
//! stops removed ones, and restarts listeners whose port or protocol changed.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::circuit_breaker::CircuitBreakerCache;
use crate::config::types::{BackendScheme, GatewayConfig};
use crate::dns::DnsCache;
use crate::modes::mesh::node_waypoint::NodeWaypointIdentityResolver;
use crate::request_epoch::RequestEpochStore;
use crate::tls::TlsPolicy;

use super::tcp_proxy::{TcpListenerConfig, TcpProxyMetrics};
use super::udp_proxy::{UdpListenerConfig, UdpProxyMetrics};

/// Live slot for a per-listener `DtlsServer`. The inner `Option<Arc<...>>` is
/// `None` until the listener task publishes the server (post-bind) and
/// becomes `Some` for the lifetime of the listener.
type DtlsServerSlot = Arc<arc_swap::ArcSwap<Option<Arc<crate::dtls::DtlsServer>>>>;

/// Handle for a running stream listener — keeps the shutdown channel and task handle.
struct ListenerHandle {
    shutdown_tx: watch::Sender<bool>,
    _join_handle: JoinHandle<()>,
    listen_port: u16,
    scheme: BackendScheme,
    frontend_tls: bool,
    passthrough: bool,
    backend_tls_reload_key: Option<BackendTlsReloadKey>,
    /// Sorted SNI-group member proxy IDs for shared `__sni_{port}` passthrough
    /// listeners (`None` for individual listeners). Part of the restart key:
    /// the accept loop captures the candidate-ID list at spawn, so a
    /// membership change (proxy added to / removed from a shared passthrough
    /// port) must restart the listener or new connections keep routing
    /// against the stale set.
    sni_ids: Option<Vec<String>>,
    started: Arc<AtomicBool>,
    tcp_metrics: Option<Arc<TcpProxyMetrics>>,
    udp_metrics: Option<Arc<UdpProxyMetrics>>,
    /// Live DTLS server slot for UDP+DTLS listeners. The collector task
    /// publishes the server into this slot once
    /// `start_dtls_frontend_listener` has bound and constructed it. Held so
    /// mesh PeerAuth live reload can call
    /// [`crate::dtls::DtlsServer::swap_frontend_config`] on the same instance
    /// the recv loop is using. `None` for TCP/UDP-plain listeners.
    dtls_server: Option<DtlsServerSlot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BackendTlsReloadKey {
    verify_server_cert: bool,
    server_ca_cert_path: Option<String>,
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct StreamListenerOverloadSnapshot {
    pub dtls_demux_sessions_total: u64,
    pub dtls_demux_sessions: Vec<DtlsDemuxSessionSnapshot>,
}

#[derive(Debug, serde::Serialize)]
pub struct DtlsDemuxSessionSnapshot {
    pub listener_key: String,
    pub listen_port: u16,
    pub sessions: u64,
}

struct DtlsDemuxMetricEntry {
    listener_key: String,
    listen_port: u16,
    sessions: Arc<AtomicU64>,
}

enum StreamBackendMetricEntry {
    Tcp(Arc<TcpProxyMetrics>),
    Udp(Arc<UdpProxyMetrics>),
}

/// Manages the set of active TCP/UDP stream listeners.
///
/// All state is behind a tokio `Mutex` to serialize reconciliation calls.
/// Reconciliation happens only on config reload — not on the hot request path.
pub struct StreamListenerManager {
    listeners: tokio::sync::Mutex<std::collections::HashMap<String, ListenerHandle>>,
    dtls_metrics: arc_swap::ArcSwap<Vec<DtlsDemuxMetricEntry>>,
    stream_backend_metrics: arc_swap::ArcSwap<Vec<StreamBackendMetricEntry>>,
    bind_addr: IpAddr,
    config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
    dns_cache: DnsCache,
    request_epoch: Arc<RequestEpochStore>,
    circuit_breaker_cache: Arc<CircuitBreakerCache>,
    /// Frontend TLS config for TCP stream proxies with `frontend_tls: true`.
    /// Uses `Arc<ArcSwap<...>>` so the **same** slot can be cloned into every
    /// TCP accept loop and snapshotted per accept. This lets mesh
    /// PeerAuthentication live reload swap the slot once and have every
    /// active TCP+TLS listener pick up the new `ServerConfig` on the next
    /// handshake without rebinding the listener. The TLS config may also be
    /// loaded after `ProxyState::new()` (e.g., file mode where TLS certs are
    /// validated after the proxy state is built).
    frontend_tls_config: Arc<arc_swap::ArcSwap<Option<Arc<rustls::ServerConfig>>>>,
    /// DTLS frontend material for UDP stream proxies with `frontend_tls: true`.
    /// Stored as a single ArcSwap payload so cert/key and optional client-CA
    /// path are published atomically to reconcile() and listener startup.
    frontend_dtls_material: arc_swap::ArcSwap<Option<(String, String, Option<String>)>>,
    /// Global override to disable backend TLS certificate verification.
    tls_no_verify: bool,
    /// Global CA bundle path for outbound TLS verification (fallback when proxy has no per-proxy CA).
    tls_ca_bundle_path: Option<String>,
    /// Global default TCP idle timeout in seconds (per-proxy `tcp_idle_timeout_seconds` overrides).
    tcp_idle_timeout_seconds: u64,
    /// Hard cap (seconds) on Phase 2 of the TCP bidirectional relay.
    /// Bounds the half-close drain even when `tcp_idle_timeout_seconds = 0`.
    tcp_half_close_max_wait_seconds: u64,
    /// Frontend TLS handshake timeout in seconds for TCP+TLS stream listeners.
    frontend_tls_handshake_timeout_seconds: u64,
    /// Maximum concurrent UDP sessions per proxy.
    udp_max_sessions: usize,
    /// UDP session cleanup interval in seconds.
    udp_cleanup_interval_seconds: u64,
    /// TLS hardening policy for backend connections (cipher suites, protocol versions).
    tls_policy: Option<Arc<TlsPolicy>>,
    /// Certificate Revocation Lists for backend TLS verification.
    crls: crate::tls::CrlList,
    /// Adaptive buffer tracker for dynamic copy buffer and batch limit sizing.
    adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    /// Number of datagrams per `recvmmsg` syscall on Linux.
    udp_recvmmsg_batch_size: usize,
    /// Normalized shard count for hot UDP session maps.
    pool_shard_amount: usize,
    /// Whether TCP Fast Open is enabled for TCP stream proxy sockets.
    tcp_fastopen_enabled: bool,
    /// Listen backlog for TCP stream proxy sockets.
    tcp_listen_backlog: u32,
    /// Number of SO_REUSEPORT TCP stream accept loops.
    accept_threads: usize,
    /// Server-side TCP Fast Open queue length for TCP stream proxy sockets.
    tcp_fastopen_queue_len: u16,
    /// Shared overload state for connection accounting and load shedding.
    overload: Arc<crate::overload::OverloadState>,
    /// Enable kTLS for splice on TLS paths.
    ktls_enabled: bool,
    /// Enable io_uring-based splice.
    io_uring_splice_enabled: bool,
    /// Whether frontend TCP TLS handshake failures should increment mesh mTLS metrics.
    record_mesh_mtls_metric: bool,
    /// SO_BUSY_POLL duration in microseconds for UDP sockets.
    so_busy_poll_us: u32,
    /// Enable UDP GRO on frontend sockets.
    udp_gro_enabled: bool,
    /// Enable UDP GSO for batched sending.
    udp_gso_enabled: bool,
    /// Enable IP_PKTINFO / IPV6_PKTINFO on frontend UDP sockets.
    udp_pktinfo_enabled: bool,
    /// Global shutdown receiver. When the gateway-wide SIGTERM/SIGINT fires,
    /// every spawned listener observes it via this receiver in addition to the
    /// per-listener `shutdown_tx` (which is only fired on config-driven removal).
    ///
    /// Stored in `ArcSwap` because it is injected after construction by
    /// [`Self::set_global_shutdown_rx`] — `StreamListenerManager` is built
    /// inside `ProxyState::new()` (synchronous) but the watch channel is
    /// created in `main.rs` and threaded into each mode separately.
    global_shutdown_rx: arc_swap::ArcSwap<Option<watch::Receiver<bool>>>,
    /// Backend TLS reload epoch shared with every spawned UDP/DTLS listener.
    /// `reload_backend_tls_material` bumps it (via
    /// [`Self::bump_backend_tls_reload_epoch`]) after backend cert/key/CA
    /// bytes change in place, so listener-local backend DTLS config caches —
    /// keyed by paths/options, which cannot observe content rotation — drop
    /// entries built from the pre-rotation material. TCP listeners use the
    /// config-path-based `BackendTlsReloadKey` restart instead.
    backend_tls_reload_epoch: Arc<AtomicU64>,
    /// Mesh `outboundTrafficPolicy: REGISTRY_ONLY` enforcement slot shared
    /// with `ProxyState`. Each spawned TCP / UDP listener gets the same
    /// `Arc<ArcSwap<...>>` so slice updates that swap the contents are
    /// observed without restarting the listener. `None` outside mesh mode
    /// — readers short-circuit on the contained `Option::None`.
    mesh_outbound_enforcement:
        crate::modes::mesh::outbound_enforcement::SharedMeshOutboundEnforcement,
    /// Node-waypoint identity resolver shared with `ProxyState`. Present only
    /// in `NodeWaypoint` topology; `None` everywhere else. When set, each
    /// spawned **TCP** stream accept loop resolves the accepted connection's
    /// socket cookie to a source pod identity and stamps the per-pod
    /// `PolicyScopeCache` onto `StreamConnectionContext.node_waypoint_policy_scope`
    /// so `mesh_authz` enforces namespace/selector-scoped policies per source
    /// pod (parity with the HTTP/HBONE path in `src/proxy/mod.rs`).
    ///
    /// Stored in `ArcSwap` because it is injected after construction by
    /// [`Self::set_node_waypoint_identity_resolver`] — the manager is built
    /// inside `ProxyState::new()` (synchronous) while the resolver is created
    /// later in the mesh runtime, before the first `reconcile()`.
    ///
    /// UDP/DTLS listeners deliberately do NOT consume this: node-waypoint
    /// capture is socket-cookie based on per-connection TCP sockets
    /// (`connect4`/`connect6` cgroup hooks), and a shared UDP frontend socket
    /// has no per-source-pod cookie. See [`Self::set_node_waypoint_identity_resolver`].
    node_waypoint_identity_resolver: arc_swap::ArcSwap<Option<Arc<NodeWaypointIdentityResolver>>>,
}

impl StreamListenerManager {
    #[allow(dead_code, clippy::too_many_arguments)]
    pub fn new(
        bind_addr: IpAddr,
        config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
        dns_cache: DnsCache,
        request_epoch: Arc<RequestEpochStore>,
        circuit_breaker_cache: Arc<CircuitBreakerCache>,
        frontend_tls_config: Option<Arc<rustls::ServerConfig>>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<String>,
        tcp_idle_timeout_seconds: u64,
        tcp_half_close_max_wait_seconds: u64,
        frontend_tls_handshake_timeout_seconds: u64,
        udp_max_sessions: usize,
        udp_cleanup_interval_seconds: u64,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
        adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
        udp_recvmmsg_batch_size: usize,
        tcp_fastopen_enabled: bool,
        tcp_listen_backlog: u32,
        accept_threads: usize,
        tcp_fastopen_queue_len: u16,
        overload: Arc<crate::overload::OverloadState>,
        ktls_enabled: bool,
        io_uring_splice_enabled: bool,
        record_mesh_mtls_metric: bool,
        so_busy_poll_us: u32,
        udp_gro_enabled: bool,
        udp_gso_enabled: bool,
        udp_pktinfo_enabled: bool,
    ) -> Self {
        Self::new_with_epoch(
            bind_addr,
            config,
            dns_cache,
            request_epoch,
            circuit_breaker_cache,
            frontend_tls_config,
            tls_no_verify,
            tls_ca_bundle_path,
            tcp_idle_timeout_seconds,
            tcp_half_close_max_wait_seconds,
            frontend_tls_handshake_timeout_seconds,
            udp_max_sessions,
            udp_cleanup_interval_seconds,
            tls_policy,
            crls,
            adaptive_buffer,
            udp_recvmmsg_batch_size,
            tcp_fastopen_enabled,
            tcp_listen_backlog,
            accept_threads,
            tcp_fastopen_queue_len,
            overload,
            ktls_enabled,
            io_uring_splice_enabled,
            record_mesh_mtls_metric,
            so_busy_poll_us,
            udp_gro_enabled,
            udp_gso_enabled,
            udp_pktinfo_enabled,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_epoch(
        bind_addr: IpAddr,
        config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
        dns_cache: DnsCache,
        request_epoch: Arc<RequestEpochStore>,
        circuit_breaker_cache: Arc<CircuitBreakerCache>,
        frontend_tls_config: Option<Arc<rustls::ServerConfig>>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<String>,
        tcp_idle_timeout_seconds: u64,
        tcp_half_close_max_wait_seconds: u64,
        frontend_tls_handshake_timeout_seconds: u64,
        udp_max_sessions: usize,
        udp_cleanup_interval_seconds: u64,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
        adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
        udp_recvmmsg_batch_size: usize,
        tcp_fastopen_enabled: bool,
        tcp_listen_backlog: u32,
        accept_threads: usize,
        tcp_fastopen_queue_len: u16,
        overload: Arc<crate::overload::OverloadState>,
        ktls_enabled: bool,
        io_uring_splice_enabled: bool,
        record_mesh_mtls_metric: bool,
        so_busy_poll_us: u32,
        udp_gro_enabled: bool,
        udp_gso_enabled: bool,
        udp_pktinfo_enabled: bool,
    ) -> Self {
        Self::new_with_epoch_and_mesh_enforcement(
            bind_addr,
            config,
            dns_cache,
            request_epoch,
            circuit_breaker_cache,
            frontend_tls_config,
            tls_no_verify,
            tls_ca_bundle_path,
            tcp_idle_timeout_seconds,
            tcp_half_close_max_wait_seconds,
            frontend_tls_handshake_timeout_seconds,
            udp_max_sessions,
            udp_cleanup_interval_seconds,
            tls_policy,
            crls,
            adaptive_buffer,
            udp_recvmmsg_batch_size,
            tcp_fastopen_enabled,
            tcp_listen_backlog,
            accept_threads,
            tcp_fastopen_queue_len,
            overload,
            ktls_enabled,
            io_uring_splice_enabled,
            record_mesh_mtls_metric,
            so_busy_poll_us,
            udp_gro_enabled,
            udp_gso_enabled,
            udp_pktinfo_enabled,
            0,
            crate::modes::mesh::outbound_enforcement::empty_slot(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_epoch_and_mesh_enforcement(
        bind_addr: IpAddr,
        config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
        dns_cache: DnsCache,
        request_epoch: Arc<RequestEpochStore>,
        circuit_breaker_cache: Arc<CircuitBreakerCache>,
        frontend_tls_config: Option<Arc<rustls::ServerConfig>>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<String>,
        tcp_idle_timeout_seconds: u64,
        tcp_half_close_max_wait_seconds: u64,
        frontend_tls_handshake_timeout_seconds: u64,
        udp_max_sessions: usize,
        udp_cleanup_interval_seconds: u64,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
        adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
        udp_recvmmsg_batch_size: usize,
        tcp_fastopen_enabled: bool,
        tcp_listen_backlog: u32,
        accept_threads: usize,
        tcp_fastopen_queue_len: u16,
        overload: Arc<crate::overload::OverloadState>,
        ktls_enabled: bool,
        io_uring_splice_enabled: bool,
        record_mesh_mtls_metric: bool,
        so_busy_poll_us: u32,
        udp_gro_enabled: bool,
        udp_gso_enabled: bool,
        udp_pktinfo_enabled: bool,
        pool_shard_amount: usize,
        mesh_outbound_enforcement:
            crate::modes::mesh::outbound_enforcement::SharedMeshOutboundEnforcement,
    ) -> Self {
        Self {
            listeners: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            dtls_metrics: arc_swap::ArcSwap::new(Arc::new(Vec::new())),
            stream_backend_metrics: arc_swap::ArcSwap::new(Arc::new(Vec::new())),
            bind_addr,
            config,
            dns_cache,
            request_epoch,
            circuit_breaker_cache,
            frontend_tls_config: Arc::new(arc_swap::ArcSwap::new(Arc::new(frontend_tls_config))),
            frontend_dtls_material: arc_swap::ArcSwap::new(Arc::new(None)),
            tls_no_verify,
            tls_ca_bundle_path,
            tcp_idle_timeout_seconds,
            tcp_half_close_max_wait_seconds,
            frontend_tls_handshake_timeout_seconds,
            udp_max_sessions,
            udp_cleanup_interval_seconds,
            tls_policy,
            crls,
            adaptive_buffer,
            udp_recvmmsg_batch_size,
            pool_shard_amount: crate::util::sharding::pool_shard_amount(pool_shard_amount),
            tcp_fastopen_enabled,
            tcp_listen_backlog,
            accept_threads,
            tcp_fastopen_queue_len,
            overload,
            ktls_enabled,
            io_uring_splice_enabled,
            record_mesh_mtls_metric,
            so_busy_poll_us,
            udp_gro_enabled,
            udp_gso_enabled,
            udp_pktinfo_enabled,
            global_shutdown_rx: arc_swap::ArcSwap::new(Arc::new(None)),
            backend_tls_reload_epoch: Arc::new(AtomicU64::new(0)),
            mesh_outbound_enforcement,
            node_waypoint_identity_resolver: arc_swap::ArcSwap::new(Arc::new(None)),
        }
    }

    /// Inject the gateway-wide shutdown receiver. Each subsequently spawned
    /// stream listener (TCP/UDP/DTLS) will observe SIGTERM/SIGINT through this
    /// receiver in addition to its private per-listener channel, so accept
    /// loops exit promptly during graceful drain.
    ///
    /// Must be called once per mode after [`Self::new`] and BEFORE the first
    /// `reconcile()` so listeners that bind on initial startup pick up the
    /// receiver. Listeners spawned by later reconciles also pick it up via
    /// the `ArcSwap` load.
    pub fn set_global_shutdown_rx(&self, rx: watch::Receiver<bool>) {
        self.global_shutdown_rx.store(Arc::new(Some(rx)));
    }

    /// Bump the backend TLS reload epoch shared with UDP/DTLS listeners.
    ///
    /// Called by `reload_backend_tls_material` after backend cert/key/CA
    /// bytes were validated and swapped, so listener-local backend DTLS
    /// config caches rebuild from the rotated material on the next session
    /// instead of serving stale params until restart.
    pub fn bump_backend_tls_reload_epoch(&self) {
        self.backend_tls_reload_epoch.fetch_add(1, Ordering::AcqRel);
    }

    /// Inject the node-waypoint identity resolver shared with `ProxyState`.
    ///
    /// Mesh `NodeWaypoint` runtime calls this once after building the resolver
    /// and BEFORE the first stream-listener `reconcile()`, so TCP listeners
    /// that bind on initial startup already see it; listeners spawned by later
    /// reconciles also pick it up via the `ArcSwap` load. Cloning the resolved
    /// `Arc` into each TCP accept loop lets that loop resolve the accepted
    /// connection's `SO_COOKIE` to a source pod identity and stamp the per-pod
    /// `PolicyScopeCache`, mirroring the HTTP/HBONE admit path.
    ///
    /// Scope is strictly `NodeWaypoint`: only that topology installs a
    /// resolver, so Sidecar/Ambient/east-west/egress and non-mesh stream
    /// proxies continue to pass `node_waypoint_policy_scope: None` and behave
    /// exactly as before.
    ///
    /// Deliberately TCP-only. Node-waypoint capture keys identity by the
    /// per-connection TCP socket cookie (`connect4`/`connect6` cgroup hooks
    /// stamp the source pod into `FERRUM_ORIG_DST4/6`, looked up at accept time
    /// via `getsockopt(SO_COOKIE)`). A UDP stream proxy has a single shared
    /// frontend socket with one cookie for every client, and there are no UDP
    /// capture hooks, so there is no per-source-pod cookie to resolve. UDP/DTLS
    /// node-waypoint streams therefore remain mesh-wide-only (the existing
    /// fail-closed default) — see `src/proxy/udp_proxy.rs` and `docs/mesh.md`.
    pub fn set_node_waypoint_identity_resolver(&self, resolver: Arc<NodeWaypointIdentityResolver>) {
        self.node_waypoint_identity_resolver
            .store(Arc::new(Some(resolver)));
    }

    /// Update the frontend TLS configuration used for TCP stream proxies with `frontend_tls: true`.
    ///
    /// After storing the config, automatically reconciles stream listeners so
    /// any previously deferred TCP listeners (waiting for TLS) are started.
    /// This is safe to call before the first `reconcile()` — the reconcile is
    /// a no-op when there are no stream proxies in the config yet.
    pub async fn set_frontend_tls_config(&self, tls_config: Option<Arc<rustls::ServerConfig>>) {
        let is_some = tls_config.is_some();
        self.frontend_tls_config.store(Arc::new(tls_config));
        // Reconcile to start any listeners that were deferred due to missing TLS config.
        if is_some {
            let failures = self.reconcile().await;
            for (proxy_id, port, err) in &failures {
                warn!(
                    proxy_id = %proxy_id,
                    port = port,
                    "Stream listener failed to bind after TLS config loaded: {}",
                    err
                );
            }
        }
    }

    /// Update the DTLS cert/key paths used for UDP stream proxies with `frontend_tls: true`.
    ///
    /// After storing the config, automatically reconciles stream listeners so
    /// any previously deferred UDP/DTLS listeners are started.
    pub async fn set_frontend_dtls_cert_key(
        &self,
        cert_path: String,
        key_path: String,
        client_ca_cert_path: Option<String>,
    ) {
        self.frontend_dtls_material.store(Arc::new(Some((
            cert_path,
            key_path,
            client_ca_cert_path,
        ))));
        // Reconcile to start any listeners that were deferred due to missing DTLS config.
        let failures = self.reconcile().await;
        for (proxy_id, port, err) in &failures {
            warn!(
                proxy_id = %proxy_id,
                port = port,
                "Stream listener failed to bind after DTLS config loaded: {}",
                err
            );
        }
    }

    /// Live-swap the frontend TLS `ServerConfig` used by mesh-shared TCP+TLS
    /// stream listeners.
    ///
    /// Unlike [`Self::set_frontend_tls_config`] this does NOT trigger a
    /// reconcile — the slot is shared with every active TCP+TLS accept loop,
    /// which snapshots it per accept. Existing connections keep the
    /// `ServerConfig` they handshake with until they end (rustls consults
    /// the config only at handshake time). New accepts use the swapped
    /// config on the next handshake.
    ///
    /// Used by mesh PeerAuthentication live reload alongside
    /// [`Self::swap_active_dtls_frontend_configs`]; ordinary HTTPS / non-mesh
    /// modes continue to use [`Self::set_frontend_tls_config`] at startup
    /// (followed by a static lifetime — those modes do not call swap).
    pub fn swap_frontend_tls_config(&self, tls_config: Option<Arc<rustls::ServerConfig>>) {
        self.frontend_tls_config.store(Arc::new(tls_config));
    }

    /// Returns a snapshot of the current frontend TLS slot value. Tests use
    /// pointer-equality on the inner `Arc<ServerConfig>` to prove
    /// [`Self::swap_frontend_tls_config`] replaced the slot rather than
    /// mutated in place; non-test callers may also use this to observe the
    /// startup-set frontend TLS config.
    #[allow(dead_code)] // Test / introspection surface.
    pub fn snapshot_frontend_tls_config(&self) -> Option<Arc<rustls::ServerConfig>> {
        self.frontend_tls_config.load().as_ref().clone()
    }

    /// Live-swap the frontend DTLS crypto material on every active DTLS
    /// server held by this manager.
    ///
    /// `build_config` is invoked once per active DTLS listener so the caller
    /// can rebuild a fresh `FrontendDtlsConfig` for each (cloning the
    /// `DtlsCertificate` and verifier is cheap; the dimpl `Config` itself
    /// can be re-used since the build is symmetric). Existing in-flight
    /// DTLS sessions keep the snapshot they handshake with until they end;
    /// new sessions pick up the swapped material on the next ClientHello.
    ///
    /// Returns the number of listeners whose DTLS server was swapped.
    /// Listeners whose `dtls_server` slot has not yet been populated by the
    /// collector task (a brief race window post-bind) are skipped — the
    /// next slice apply re-runs this swap, and the in-flight session would
    /// have been rejected anyway since no peer can complete a handshake
    /// before the listener binds.
    pub async fn swap_active_dtls_frontend_configs<F>(&self, mut build_config: F) -> usize
    where
        F: FnMut() -> Result<crate::dtls::FrontendDtlsConfig, anyhow::Error>,
    {
        let mut swapped = 0usize;
        let listeners = self.listeners.lock().await;
        for handle in listeners.values() {
            let Some(slot) = handle.dtls_server.as_ref() else {
                continue;
            };
            let snapshot = slot.load();
            let Some(server) = snapshot.as_ref().clone() else {
                // Collector task has not yet published the server (race with
                // bind). Skip — the next live-reload swap will catch it.
                continue;
            };
            match build_config() {
                Ok(cfg) => {
                    server.swap_frontend_config(cfg);
                    swapped += 1;
                }
                Err(err) => {
                    warn!(
                        listen_port = handle.listen_port,
                        "Failed to rebuild frontend DTLS config for live swap: {}; \
                         keeping previous DTLS config on remaining listeners",
                        err
                    );
                    // `build_config` is invariant under iteration — the cert/key
                    // paths and CRL list it closes over do not change across
                    // listeners — so a failure on iteration N would have failed
                    // on iteration 0 as well. The only realistic divergence is
                    // a transient FS race (cert file briefly unreadable). Bail
                    // out so a stuttering FS does not produce a mix of new and
                    // old configs across long-lived listeners; the next slice
                    // apply re-runs the swap and converges everything to the
                    // newest material. Any listener already swapped this pass
                    // keeps the new config — that is the desired direction of
                    // travel.
                    return swapped;
                }
            }
        }
        swapped
    }

    /// Reconcile active listeners against the current config.
    ///
    /// - Starts listeners for new stream proxies (TCP and UDP)
    /// - Stops listeners for removed stream proxies
    /// - Restarts listeners whose port or protocol changed
    ///
    /// Returns a list of `(proxy_id, port, error_message)` for any listeners
    /// that failed to start due to port binding errors. An empty vec means all
    /// listeners started successfully.
    pub async fn reconcile(&self) -> Vec<(String, u16, String)> {
        let mut bind_failures = Vec::new();
        let current_config = self.config.load();
        let mut listeners = self.listeners.lock().await;

        // Collect all desired stream proxies from config
        let desired: std::collections::HashMap<
            String,
            (u16, BackendScheme, bool, bool, Option<BackendTlsReloadKey>),
        > = current_config
            .proxies
            .iter()
            .filter(|p| p.dispatch_kind.is_stream())
            .filter_map(|p| {
                p.listen_port.map(|port| {
                    let backend_tls_reload_key =
                        if p.dispatch_kind == crate::config::types::DispatchKind::TcpTls {
                            Some(BackendTlsReloadKey {
                                verify_server_cert: p.backend_tls_verify_server_cert,
                                server_ca_cert_path: p.backend_tls_server_ca_cert_path.clone(),
                                client_cert_path: p.backend_tls_client_cert_path.clone(),
                                client_key_path: p.backend_tls_client_key_path.clone(),
                            })
                        } else {
                            None
                        };
                    (
                        p.id.clone(),
                        (
                            port,
                            p.effective_scheme(),
                            p.frontend_tls,
                            p.passthrough,
                            backend_tls_reload_key,
                        ),
                    )
                })
            })
            .collect();

        // Detect passthrough port groups that must be resolved by SNI.
        // Multiple passthrough proxies sharing a port need one shared listener keyed by
        // "__sni_{port}". A single passthrough proxy with configured hosts also needs
        // SNI resolution so those host predicates are enforced instead of becoming a
        // port-wide catch-all.
        let mut passthrough_groups: std::collections::HashMap<u16, Vec<String>> =
            std::collections::HashMap::new();
        for (proxy_id, (port, _protocol, _frontend_tls, passthrough, _)) in &desired {
            if *passthrough {
                passthrough_groups
                    .entry(*port)
                    .or_default()
                    .push(proxy_id.clone());
            }
        }
        passthrough_groups.retain(|_, ids| {
            ids.len() > 1
                || ids.iter().any(|id| {
                    current_config
                        .proxies
                        .iter()
                        .any(|p| p.id.as_str() == id.as_str() && !p.hosts.is_empty())
                })
        });
        // Sort IDs for stable comparison on reconcile
        for ids in passthrough_groups.values_mut() {
            ids.sort();
        }

        // Build the effective desired map: individual proxies + SNI group entries.
        // Proxies in a group are replaced by a single "__sni_{port}" entry.
        let grouped_proxy_ids: std::collections::HashSet<&str> = passthrough_groups
            .values()
            .flat_map(|ids| ids.iter().map(|s| s.as_str()))
            .collect();

        #[allow(clippy::type_complexity)]
        let mut effective_desired: std::collections::HashMap<
            String,
            (
                u16,
                BackendScheme,
                bool,
                bool,
                Option<BackendTlsReloadKey>,
                Option<Vec<String>>,
            ),
        > = std::collections::HashMap::new();

        for (proxy_id, (port, scheme, frontend_tls, passthrough, backend_tls_reload_key)) in
            &desired
        {
            if grouped_proxy_ids.contains(proxy_id.as_str()) {
                continue; // Handled as part of a group below
            }
            effective_desired.insert(
                proxy_id.clone(),
                (
                    *port,
                    *scheme,
                    *frontend_tls,
                    *passthrough,
                    backend_tls_reload_key.clone(),
                    None,
                ),
            );
        }
        for (port, ids) in &passthrough_groups {
            let key = format!("__sni_{}", port);
            // Use the first proxy's scheme for the listener
            if let Some((_, scheme, frontend_tls, passthrough, backend_tls_reload_key)) =
                desired.get(&ids[0])
            {
                effective_desired.insert(
                    key,
                    (
                        *port,
                        *scheme,
                        *frontend_tls,
                        *passthrough,
                        backend_tls_reload_key.clone(),
                        Some(ids.clone()),
                    ),
                );
            }
        }

        // Stop listeners for removed proxies or changed config
        let mut to_remove = Vec::new();
        for (key, handle) in listeners.iter() {
            match effective_desired.get(key) {
                None => {
                    to_remove.push(key.clone());
                }
                Some((
                    port,
                    scheme,
                    frontend_tls,
                    passthrough,
                    backend_tls_reload_key,
                    sni_ids,
                )) => {
                    if handle.listen_port != *port
                        || handle.scheme != *scheme
                        || handle.frontend_tls != *frontend_tls
                        || handle.passthrough != *passthrough
                        || handle.backend_tls_reload_key != *backend_tls_reload_key
                        // SNI-group membership change on a shared passthrough
                        // port: the running listener captured the old candidate
                        // ID list at spawn, so it must be restarted. IDs are
                        // sorted at group construction, making this a stable
                        // comparison.
                        || handle.sni_ids != *sni_ids
                    {
                        to_remove.push(key.clone());
                    }
                }
            }
        }

        for key in &to_remove {
            if let Some(handle) = listeners.remove(key) {
                info!(
                    listener_key = %key,
                    port = handle.listen_port,
                    scheme = %handle.scheme,
                    "Stopping stream listener"
                );
                let _ = handle.shutdown_tx.send(true);
            }
        }

        // Start listeners for new or restarted entries
        for (key, (port, scheme, frontend_tls, passthrough, backend_tls_reload_key, sni_ids)) in
            &effective_desired
        {
            if listeners.contains_key(key) {
                continue;
            }
            // Resolve the proxy_id to use (first in group or the individual proxy_id)
            let proxy_id = sni_ids.as_ref().and_then(|ids| ids.first()).unwrap_or(key);

            // Skip frontend_tls proxies when the required encryption config is not yet loaded.
            // For TCP: needs rustls ServerConfig. For UDP: needs DTLS cert/key paths.
            // The set_frontend_tls_config() / set_frontend_dtls_cert_key() methods
            // automatically call reconcile() after storing the config, so deferred
            // listeners will be started once TLS materials arrive.
            // Passthrough proxies never terminate TLS, so they skip this check entirely.
            if *frontend_tls && !*passthrough {
                if scheme.is_udp() {
                    if self.frontend_dtls_material.load().is_none() {
                        info!(
                            proxy_id = %proxy_id,
                            port = port,
                            "Deferring UDP listener start: frontend_tls requires DTLS cert/key"
                        );
                        continue;
                    }
                } else if self.frontend_tls_config.load().is_none() {
                    info!(
                        proxy_id = %proxy_id,
                        port = port,
                        "Deferring TCP listener start: frontend_tls requires TLS config"
                    );
                    continue;
                }
            }

            // Pre-check port availability before spawning the listener task.
            // This catches EADDRINUSE early with a clear error rather than having
            // the spawned task fail silently in the background.
            let bind_addr = self.bind_addr;
            let port_val = *port;
            let probe_addr = std::net::SocketAddr::new(bind_addr, port_val);
            let probe_result = if scheme.is_udp() {
                tokio::net::UdpSocket::bind(probe_addr).await.map(drop)
            } else {
                tokio::net::TcpListener::bind(probe_addr).await.map(drop)
            };
            if let Err(e) = probe_result {
                let msg = format!(
                    "Port {} is already in use on {}: {}",
                    port_val, bind_addr, e
                );
                error!(
                    proxy_id = %proxy_id,
                    port = port_val,
                    "Stream listener bind failed: {}",
                    msg
                );
                bind_failures.push((proxy_id.clone(), port_val, msg));
                continue;
            }

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let proxy_id_owned = proxy_id.clone();
            let config = self.config.clone();
            let dns_cache = self.dns_cache.clone();
            let request_epoch = self.request_epoch.clone();
            let tls_no_verify = self.tls_no_verify;
            let cb_cache = self.circuit_breaker_cache.clone();
            let started = Arc::new(AtomicBool::new(false));
            // Clone the global shutdown receiver (if injected) so the spawned
            // listener observes both per-listener removal AND global SIGTERM.
            let global_shutdown = self.global_shutdown_rx.load().as_ref().clone();

            let (join_handle, tcp_metrics, udp_metrics, dtls_server) = if scheme.is_udp() {
                let started_for_listener = started.clone();
                // UDP or DTLS listener
                // Passthrough proxies forward raw encrypted datagrams — no DTLS termination.
                let frontend_dtls_config = if *frontend_tls && !*passthrough {
                    let dtls_material = self.frontend_dtls_material.load();
                    match dtls_material.as_ref() {
                        Some((cert_path, key_path, client_ca_cert_path)) => {
                            match crate::dtls::build_frontend_dtls_config(
                                cert_path,
                                key_path,
                                client_ca_cert_path.as_deref(),
                                &self.crls,
                            ) {
                                Ok(cfg) => Some(cfg),
                                Err(e) => {
                                    warn!(
                                        proxy_id = %proxy_id,
                                        "Failed to build frontend DTLS config: {}", e
                                    );
                                    continue;
                                }
                            }
                        }
                        None => {
                            // Should not happen — guarded above, but be safe
                            continue;
                        }
                    }
                } else {
                    None
                };
                let metrics = Arc::new(UdpProxyMetrics::default());
                let udp_max_sessions = self.udp_max_sessions;
                let frontend_tls_handshake_timeout = self.frontend_tls_handshake_timeout_seconds;
                let udp_cleanup_interval = self.udp_cleanup_interval_seconds;
                let crls = self.crls.clone();
                let backend_tls_reload_epoch = self.backend_tls_reload_epoch.clone();
                let tls_ca_bundle_path = self.tls_ca_bundle_path.clone();
                let sni_ids = sni_ids.clone();
                let adaptive_buf = self.adaptive_buffer.clone();
                let recvmmsg_batch = self.udp_recvmmsg_batch_size;
                let session_shards = self.pool_shard_amount;
                let overload = self.overload.clone();
                let so_busy_poll_us = self.so_busy_poll_us;
                let udp_gro_enabled = self.udp_gro_enabled;
                let udp_gso_enabled = self.udp_gso_enabled;
                let udp_pktinfo_enabled = self.udp_pktinfo_enabled;
                let listener_udp_metrics = Some(metrics.clone());
                let global_shutdown_for_listener = global_shutdown.clone();
                let mesh_outbound_enforcement = self.mesh_outbound_enforcement.clone();
                // Reserve a oneshot so the listener can publish the live
                // `Arc<DtlsServer>` back here once it has bound. Only meaningful
                // for actual DTLS listeners; plain UDP listeners drop the
                // sender unused.
                let (dtls_server_tx, dtls_server_rx) = tokio::sync::oneshot::channel();
                let dtls_server_tx = if *frontend_tls && !*passthrough {
                    Some(dtls_server_tx)
                } else {
                    None
                };
                let join_handle = tokio::spawn(async move {
                    if let Err(e) = super::udp_proxy::start_udp_listener(UdpListenerConfig {
                        port: port_val,
                        bind_addr,
                        proxy_id: proxy_id_owned.clone(),
                        dns_cache,
                        request_epoch,
                        shutdown: shutdown_rx,
                        global_shutdown: global_shutdown_for_listener,
                        metrics,
                        frontend_dtls_config,
                        dtls_server_tx,
                        tls_no_verify,
                        tls_ca_bundle_path,
                        max_sessions: udp_max_sessions,
                        frontend_tls_handshake_timeout_seconds: frontend_tls_handshake_timeout,
                        cleanup_interval_seconds: udp_cleanup_interval,
                        circuit_breaker_cache: cb_cache,
                        crls,
                        backend_tls_reload_epoch,
                        started: started_for_listener,
                        sni_proxy_ids: sni_ids,
                        adaptive_buffer: adaptive_buf,
                        recvmmsg_batch_size: recvmmsg_batch,
                        session_shard_amount: session_shards,
                        overload,
                        so_busy_poll_us,
                        udp_gro_enabled,
                        udp_gso_enabled,
                        udp_pktinfo_enabled,
                        mesh_outbound_enforcement,
                    })
                    .await
                    {
                        error!(
                            proxy_id = %proxy_id_owned,
                            port = port_val,
                            "UDP stream listener failed: {}",
                            e
                        );
                    }
                });
                // The DTLS server `Arc` will be published shortly after the
                // listener task binds. Stash a shared slot here so the spawned
                // collector task can store it once `start_dtls_frontend_listener`
                // sends. Reconcile does not block waiting for the bind; if the
                // first PeerAuth live-reload swap fires before the collector
                // resolves, the swap path simply finds an empty slot for that
                // listener and skips it (re-reconcile or the next swap picks
                // it up — the swap is idempotent over slice apply).
                let dtls_server_slot: Arc<arc_swap::ArcSwap<Option<Arc<crate::dtls::DtlsServer>>>> =
                    Arc::new(arc_swap::ArcSwap::from_pointee(None));
                let dtls_server_slot_for_collector = Arc::clone(&dtls_server_slot);
                tokio::spawn(async move {
                    if let Ok(server) = dtls_server_rx.await {
                        dtls_server_slot_for_collector.store(Arc::new(Some(server)));
                    }
                });
                (
                    join_handle,
                    None,
                    listener_udp_metrics,
                    Some(dtls_server_slot),
                )
            } else {
                let started_for_listener = started.clone();
                // TCP or TcpTls listener
                // Passthrough proxies forward raw encrypted bytes — no TLS termination.
                // Hand the shared TLS slot to the listener so PeerAuth live reload
                // (mesh mode) can swap the inbound TLS config under a running
                // listener; the accept loop snapshots per accept. For listeners
                // that never terminate TLS (passthrough or non-TLS schemes) we
                // hand them a fresh per-listener empty slot so the listener task
                // is unconditionally typed and we don't fork the call path.
                let tls_slot = if *frontend_tls && !*passthrough {
                    Arc::clone(&self.frontend_tls_config)
                } else {
                    Arc::new(arc_swap::ArcSwap::new(Arc::new(None)))
                };
                let metrics = Arc::new(TcpProxyMetrics::default());
                let listener_tcp_metrics = Some(metrics.clone());
                let tcp_idle_timeout = self.tcp_idle_timeout_seconds;
                let tcp_half_close_max_wait = self.tcp_half_close_max_wait_seconds;
                let frontend_tls_handshake_timeout = self.frontend_tls_handshake_timeout_seconds;
                let tls_policy = self.tls_policy.clone();
                let crls = self.crls.clone();
                let tls_ca_bundle_path = self.tls_ca_bundle_path.clone();
                let sni_ids = sni_ids.clone();
                let adaptive_buf = self.adaptive_buffer.clone();
                let tcp_fastopen = self.tcp_fastopen_enabled;
                let tcp_listen_backlog = self.tcp_listen_backlog;
                let accept_threads = self.accept_threads;
                let tcp_fastopen_queue_len = self.tcp_fastopen_queue_len;
                let overload = self.overload.clone();
                let ktls_enabled = self.ktls_enabled;
                let io_uring_splice_enabled = self.io_uring_splice_enabled;
                let record_mesh_mtls_metric = self.record_mesh_mtls_metric;
                let global_shutdown_for_listener = global_shutdown.clone();
                let mesh_outbound_enforcement = self.mesh_outbound_enforcement.clone();
                // Snapshot the node-waypoint resolver slot once per listener
                // spawn. `None` outside NodeWaypoint topology; when present the
                // accept loop resolves each connection's source pod identity to
                // stamp the per-pod policy scope (TCP only — see
                // `set_node_waypoint_identity_resolver`).
                let node_waypoint_identity_resolver = self
                    .node_waypoint_identity_resolver
                    .load_full()
                    .as_ref()
                    .clone();
                let join_handle = tokio::spawn(async move {
                    if let Err(e) = super::tcp_proxy::start_tcp_listener(TcpListenerConfig {
                        port: port_val,
                        bind_addr,
                        proxy_id: proxy_id_owned.clone(),
                        config,
                        dns_cache,
                        request_epoch,
                        frontend_tls_slot: tls_slot,
                        shutdown: shutdown_rx,
                        global_shutdown: global_shutdown_for_listener,
                        metrics,
                        tls_no_verify,
                        tls_ca_bundle_path,
                        tcp_idle_timeout_seconds: tcp_idle_timeout,
                        tcp_half_close_max_wait_seconds: tcp_half_close_max_wait,
                        frontend_tls_handshake_timeout_seconds: frontend_tls_handshake_timeout,
                        circuit_breaker_cache: cb_cache,
                        tls_policy,
                        crls,
                        started: started_for_listener,
                        sni_proxy_ids: sni_ids,
                        adaptive_buffer: adaptive_buf,
                        tcp_fastopen_enabled: tcp_fastopen,
                        tcp_listen_backlog,
                        accept_threads,
                        tcp_fastopen_queue_len,
                        overload,
                        ktls_enabled,
                        io_uring_splice_enabled,
                        record_mesh_mtls_metric,
                        mesh_outbound_enforcement,
                        node_waypoint_identity_resolver,
                    })
                    .await
                    {
                        error!(
                            proxy_id = %proxy_id_owned,
                            port = port_val,
                            "TCP stream listener failed: {}",
                            e
                        );
                    }
                });
                (join_handle, listener_tcp_metrics, None, None)
            };

            info!(
                listener_key = %key,
                proxy_id = %proxy_id,
                port = port,
                scheme = %scheme,
                "Started stream listener"
            );

            listeners.insert(
                key.clone(),
                ListenerHandle {
                    shutdown_tx,
                    _join_handle: join_handle,
                    listen_port: *port,
                    scheme: *scheme,
                    frontend_tls: *frontend_tls,
                    passthrough: *passthrough,
                    backend_tls_reload_key: backend_tls_reload_key.clone(),
                    sni_ids: sni_ids.clone(),
                    started,
                    tcp_metrics,
                    udp_metrics,
                    dtls_server,
                },
            );
        }

        let mut dtls_entries: Vec<DtlsDemuxMetricEntry> = listeners
            .iter()
            .filter(|(_, h)| h.frontend_tls)
            .filter_map(|(key, h)| {
                h.udp_metrics.as_ref().map(|m| DtlsDemuxMetricEntry {
                    listener_key: key.clone(),
                    listen_port: h.listen_port,
                    sessions: m.dtls_demux_sessions.clone(),
                })
            })
            .collect();
        dtls_entries.sort_by(|a, b| a.listener_key.cmp(&b.listener_key));
        self.dtls_metrics.store(Arc::new(dtls_entries));

        let stream_backend_entries: Vec<StreamBackendMetricEntry> = listeners
            .values()
            .filter_map(|h| match h.scheme {
                BackendScheme::Tcp | BackendScheme::Tcps => h
                    .tcp_metrics
                    .as_ref()
                    .map(|m| StreamBackendMetricEntry::Tcp(m.clone())),
                BackendScheme::Udp | BackendScheme::Dtls => h
                    .udp_metrics
                    .as_ref()
                    .map(|m| StreamBackendMetricEntry::Udp(m.clone())),
                BackendScheme::Http | BackendScheme::Https => None,
            })
            .collect();
        self.stream_backend_metrics
            .store(Arc::new(stream_backend_entries));

        bind_failures
    }

    /// Lightweight stream-listener diagnostics included in the admin `/overload`
    /// response. Lock-free: reads pre-built metric references from an `ArcSwap`
    /// updated during reconciliation, so this never contends with config reloads.
    pub fn overload_snapshot(&self) -> StreamListenerOverloadSnapshot {
        let entries = self.dtls_metrics.load();
        let mut dtls_demux_sessions = Vec::with_capacity(entries.len());
        let mut dtls_demux_sessions_total = 0;

        for entry in entries.iter() {
            let sessions = entry.sessions.load(Ordering::Relaxed);
            dtls_demux_sessions_total += sessions;
            dtls_demux_sessions.push(DtlsDemuxSessionSnapshot {
                listener_key: entry.listener_key.clone(),
                listen_port: entry.listen_port,
                sessions,
            });
        }

        StreamListenerOverloadSnapshot {
            dtls_demux_sessions_total,
            dtls_demux_sessions,
        }
    }

    /// Estimate active stream backend sockets without including frontend HTTP/WebSocket sessions.
    pub fn active_backend_session_estimate(&self) -> u64 {
        let entries = self.stream_backend_metrics.load();
        active_backend_session_estimate_from_entries(&entries)
    }

    /// Wait until all currently configured stream listeners have successfully
    /// bound and can accept traffic.
    pub async fn wait_until_started(&self, timeout: Duration) -> Result<(), anyhow::Error> {
        let deadline = Instant::now() + timeout;

        loop {
            let current_config = self.config.load();
            let desired: Vec<(String, u16, BackendScheme, bool, bool, bool)> = current_config
                .proxies
                .iter()
                .filter(|p| p.dispatch_kind.is_stream())
                .filter_map(|p| {
                    p.listen_port.map(|port| {
                        (
                            p.id.clone(),
                            port,
                            p.effective_scheme(),
                            p.frontend_tls,
                            p.passthrough,
                            !p.hosts.is_empty(),
                        )
                    })
                })
                .collect();

            if desired.is_empty() {
                return Ok(());
            }

            // Detect SNI port groups to map proxy_ids to their listener key.
            let mut pt_ports: std::collections::HashMap<u16, (usize, bool)> =
                std::collections::HashMap::new();
            for (_, port, _, _, passthrough, has_hosts) in &desired {
                if *passthrough {
                    let entry = pt_ports.entry(*port).or_default();
                    entry.0 += 1;
                    entry.1 |= *has_hosts;
                }
            }

            let all_started = {
                let listeners = self.listeners.lock().await;
                desired
                    .iter()
                    .all(|(proxy_id, port, scheme, frontend_tls, passthrough, _)| {
                        // For SNI groups, the listener key is "__sni_{port}" not the proxy_id.
                        let key = if *passthrough
                            && pt_ports
                                .get(port)
                                .is_some_and(|(count, has_hosts)| *count > 1 || *has_hosts)
                        {
                            format!("__sni_{}", port)
                        } else {
                            proxy_id.clone()
                        };
                        listeners.get(&key).is_some_and(|handle| {
                            handle.listen_port == *port
                                && handle.scheme == *scheme
                                && handle.frontend_tls == *frontend_tls
                                && handle.started.load(Ordering::Acquire)
                        })
                    })
            };

            if all_started {
                return Ok(());
            }

            if Instant::now() >= deadline {
                return Err(anyhow::anyhow!(
                    "Timed out waiting for stream listeners to complete startup"
                ));
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Shut down all active stream listeners.
    ///
    /// Called from each mode's graceful-shutdown path AFTER HTTP listener
    /// handles have been awaited and BEFORE `wait_for_drain` runs. The
    /// per-listener watch channel fires alongside the global SIGTERM channel
    /// (see [`Self::set_global_shutdown_rx`]) so accept loops exit promptly
    /// regardless of which signal arrives first; calling this here also
    /// ensures the `JoinHandle` set is cleared even when the global channel
    /// is not injected (e.g. unit tests that build a manager standalone).
    pub async fn shutdown_all(&self) {
        let mut listeners = self.listeners.lock().await;
        for (proxy_id, handle) in listeners.drain() {
            info!(proxy_id = %proxy_id, port = handle.listen_port, "Shutting down stream listener");
            let _ = handle.shutdown_tx.send(true);
        }
    }
}

fn active_backend_session_estimate_from_entries(entries: &[StreamBackendMetricEntry]) -> u64 {
    entries.iter().fold(0u64, |total, entry| {
        let active = match entry {
            StreamBackendMetricEntry::Tcp(metrics) => {
                metrics.active_backend_connections.load(Ordering::Relaxed)
            }
            StreamBackendMetricEntry::Udp(metrics) => {
                metrics.active_sessions.load(Ordering::Relaxed)
            }
        };
        total.saturating_add(active)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    #[test]
    fn active_backend_session_estimate_sums_tcp_and_udp_stream_sessions() {
        let tcp_metrics = Arc::new(TcpProxyMetrics::default());
        let udp_metrics = Arc::new(UdpProxyMetrics::default());
        tcp_metrics.active_connections.store(99, Ordering::Relaxed);
        tcp_metrics
            .active_backend_connections
            .store(2, Ordering::Relaxed);
        udp_metrics.active_sessions.store(3, Ordering::Relaxed);
        let entries = vec![
            StreamBackendMetricEntry::Tcp(tcp_metrics),
            StreamBackendMetricEntry::Udp(udp_metrics),
        ];

        assert_eq!(active_backend_session_estimate_from_entries(&entries), 5);
    }
}
