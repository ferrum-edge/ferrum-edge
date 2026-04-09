//! Manages lifecycle of TCP/UDP stream proxy listeners.
//!
//! The `StreamListenerManager` reconciles the set of active listeners against
//! the current `GatewayConfig`. On config reload it starts new listeners,
//! stops removed ones, and restarts listeners whose port or protocol changed.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::circuit_breaker::CircuitBreakerCache;
use crate::config::types::{BackendProtocol, GatewayConfig};
use crate::consumer_index::ConsumerIndex;
use crate::dns::DnsCache;
use crate::load_balancer::LoadBalancerCache;
use crate::plugin_cache::PluginCache;
use crate::tls::TlsPolicy;

use super::tcp_proxy::{TcpListenerConfig, TcpProxyMetrics};
use super::udp_proxy::{UdpListenerConfig, UdpProxyMetrics};

/// Handle for a running stream listener — keeps the shutdown channel and task handle.
struct ListenerHandle {
    shutdown_tx: watch::Sender<bool>,
    _join_handle: JoinHandle<()>,
    listen_port: u16,
    protocol: BackendProtocol,
    frontend_tls: bool,
    passthrough: bool,
    started: Arc<AtomicBool>,
}

/// Manages the set of active TCP/UDP stream listeners.
///
/// All state is behind a tokio `Mutex` to serialize reconciliation calls.
/// Reconciliation happens only on config reload — not on the hot request path.
pub struct StreamListenerManager {
    listeners: tokio::sync::Mutex<std::collections::HashMap<String, ListenerHandle>>,
    bind_addr: IpAddr,
    config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
    dns_cache: DnsCache,
    load_balancer_cache: Arc<LoadBalancerCache>,
    consumer_index: Arc<ConsumerIndex>,
    plugin_cache: Arc<PluginCache>,
    circuit_breaker_cache: Arc<CircuitBreakerCache>,
    /// Frontend TLS config for TCP stream proxies with `frontend_tls: true`.
    /// Uses `ArcSwap` because the TLS config may be loaded after `ProxyState::new()`
    /// (e.g., in file mode where TLS certs are validated after the proxy state is built).
    frontend_tls_config: arc_swap::ArcSwap<Option<Arc<rustls::ServerConfig>>>,
    /// DTLS cert/key paths for frontend DTLS termination on UDP proxies.
    /// When a UDP proxy has `frontend_tls: true`, these paths are used to build
    /// the DTLS server config. Requires ECDSA P-256 or Ed25519 certificates.
    frontend_dtls_cert_key: arc_swap::ArcSwap<Option<(String, String)>>,
    /// Optional DTLS client CA certificate path for frontend mTLS.
    /// When set, the gateway requires and verifies client DTLS certificates
    /// using this trust store (separate from TCP TLS client CA).
    frontend_dtls_client_ca_path: arc_swap::ArcSwap<Option<String>>,
    /// Global override to disable backend TLS certificate verification.
    tls_no_verify: bool,
    /// Global CA bundle path for outbound TLS verification (fallback when proxy has no per-proxy CA).
    tls_ca_bundle_path: Option<String>,
    /// Global default TCP idle timeout in seconds (per-proxy `tcp_idle_timeout_seconds` overrides).
    tcp_idle_timeout_seconds: u64,
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
}

impl StreamListenerManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bind_addr: IpAddr,
        config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
        dns_cache: DnsCache,
        load_balancer_cache: Arc<LoadBalancerCache>,
        consumer_index: Arc<ConsumerIndex>,
        plugin_cache: Arc<PluginCache>,
        circuit_breaker_cache: Arc<CircuitBreakerCache>,
        frontend_tls_config: Option<Arc<rustls::ServerConfig>>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<String>,
        tcp_idle_timeout_seconds: u64,
        udp_max_sessions: usize,
        udp_cleanup_interval_seconds: u64,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
        adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    ) -> Self {
        Self {
            listeners: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            bind_addr,
            config,
            dns_cache,
            load_balancer_cache,
            consumer_index,
            plugin_cache,
            circuit_breaker_cache,
            frontend_tls_config: arc_swap::ArcSwap::new(Arc::new(frontend_tls_config)),
            frontend_dtls_cert_key: arc_swap::ArcSwap::new(Arc::new(None)),
            frontend_dtls_client_ca_path: arc_swap::ArcSwap::new(Arc::new(None)),
            tls_no_verify,
            tls_ca_bundle_path,
            tcp_idle_timeout_seconds,
            udp_max_sessions,
            udp_cleanup_interval_seconds,
            tls_policy,
            crls,
            adaptive_buffer,
        }
    }

    /// Update the frontend TLS configuration used for TCP stream proxies with `frontend_tls: true`.
    ///
    /// Call this once the gateway's TLS certificates are loaded, then call
    /// `reconcile()` to restart any listeners that need frontend TLS.
    pub fn set_frontend_tls_config(&self, tls_config: Option<Arc<rustls::ServerConfig>>) {
        self.frontend_tls_config.store(Arc::new(tls_config));
    }

    /// Update the DTLS cert/key paths used for UDP stream proxies with `frontend_tls: true`.
    ///
    /// Call this after loading DTLS certificates, then call `reconcile()` to start
    /// any deferred DTLS frontend listeners.
    pub fn set_frontend_dtls_cert_key(
        &self,
        cert_path: String,
        key_path: String,
        client_ca_cert_path: Option<String>,
    ) {
        self.frontend_dtls_cert_key
            .store(Arc::new(Some((cert_path, key_path))));
        self.frontend_dtls_client_ca_path
            .store(Arc::new(client_ca_cert_path));
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
        let desired: std::collections::HashMap<String, (u16, BackendProtocol, bool, bool)> =
            current_config
                .proxies
                .iter()
                .filter(|p| p.backend_protocol.is_stream_proxy())
                .filter_map(|p| {
                    p.listen_port.map(|port| {
                        (
                            p.id.clone(),
                            (port, p.backend_protocol, p.frontend_tls, p.passthrough),
                        )
                    })
                })
                .collect();

        // Detect passthrough port groups: multiple passthrough proxies sharing a port.
        // These get a single shared listener keyed by "__sni_{port}" instead of individual
        // proxy_id keys. The listener dispatches connections based on SNI.
        let mut passthrough_groups: std::collections::HashMap<u16, Vec<String>> =
            std::collections::HashMap::new();
        for (proxy_id, (port, _protocol, _frontend_tls, passthrough)) in &desired {
            if *passthrough {
                passthrough_groups
                    .entry(*port)
                    .or_default()
                    .push(proxy_id.clone());
            }
        }
        // Only ports with 2+ passthrough proxies are SNI-routed groups
        passthrough_groups.retain(|_, ids| ids.len() > 1);
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
            (u16, BackendProtocol, bool, bool, Option<Vec<String>>),
        > = std::collections::HashMap::new();

        for (proxy_id, (port, protocol, frontend_tls, passthrough)) in &desired {
            if grouped_proxy_ids.contains(proxy_id.as_str()) {
                continue; // Handled as part of a group below
            }
            effective_desired.insert(
                proxy_id.clone(),
                (*port, *protocol, *frontend_tls, *passthrough, None),
            );
        }
        for (port, ids) in &passthrough_groups {
            let key = format!("__sni_{}", port);
            // Use the first proxy's protocol for the listener
            if let Some((_, protocol, frontend_tls, passthrough)) = desired.get(&ids[0]) {
                effective_desired.insert(
                    key,
                    (
                        *port,
                        *protocol,
                        *frontend_tls,
                        *passthrough,
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
                Some((port, protocol, frontend_tls, passthrough, _)) => {
                    if handle.listen_port != *port
                        || handle.protocol != *protocol
                        || handle.frontend_tls != *frontend_tls
                        || handle.passthrough != *passthrough
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
                    protocol = %handle.protocol,
                    "Stopping stream listener"
                );
                let _ = handle.shutdown_tx.send(true);
            }
        }

        // Start listeners for new or restarted entries
        for (key, (port, protocol, frontend_tls, passthrough, sni_ids)) in &effective_desired {
            if listeners.contains_key(key) {
                continue;
            }
            // Resolve the proxy_id to use (first in group or the individual proxy_id)
            let proxy_id = sni_ids.as_ref().and_then(|ids| ids.first()).unwrap_or(key);

            // Skip frontend_tls proxies when the required encryption config is not yet loaded.
            // For TCP: needs rustls ServerConfig. For UDP: needs DTLS cert/key paths.
            // The mode will call reconcile() again after setting the config.
            // Passthrough proxies never terminate TLS, so they skip this check entirely.
            if *frontend_tls && !*passthrough {
                if protocol.is_udp() {
                    if self.frontend_dtls_cert_key.load().is_none() {
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
            let probe_result = if protocol.is_udp() {
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
            let lb_cache = self.load_balancer_cache.clone();
            let tls_no_verify = self.tls_no_verify;
            let cb_cache = self.circuit_breaker_cache.clone();
            let started = Arc::new(AtomicBool::new(false));

            let join_handle = if protocol.is_udp() {
                let started_for_listener = started.clone();
                // UDP or DTLS listener
                // Passthrough proxies forward raw encrypted datagrams — no DTLS termination.
                let frontend_dtls_config = if *frontend_tls && !*passthrough {
                    let paths = self.frontend_dtls_cert_key.load();
                    match paths.as_ref() {
                        Some((cert_path, key_path)) => {
                            let client_ca = self.frontend_dtls_client_ca_path.load();
                            let client_ca_ref = client_ca.as_deref();
                            match crate::dtls::build_frontend_dtls_config(
                                cert_path,
                                key_path,
                                client_ca_ref,
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
                let udp_cleanup_interval = self.udp_cleanup_interval_seconds;
                let consumer_index = self.consumer_index.clone();
                let plugin_cache = self.plugin_cache.clone();
                let crls = self.crls.clone();
                let sni_ids = sni_ids.clone();
                let adaptive_buf = self.adaptive_buffer.clone();
                tokio::spawn(async move {
                    if let Err(e) = super::udp_proxy::start_udp_listener(UdpListenerConfig {
                        port: port_val,
                        bind_addr,
                        proxy_id: proxy_id_owned.clone(),
                        config,
                        dns_cache,
                        load_balancer_cache: lb_cache,
                        consumer_index,
                        shutdown: shutdown_rx,
                        metrics,
                        frontend_dtls_config,
                        tls_no_verify,
                        max_sessions: udp_max_sessions,
                        cleanup_interval_seconds: udp_cleanup_interval,
                        plugin_cache,
                        circuit_breaker_cache: cb_cache,
                        crls,
                        started: started_for_listener,
                        sni_proxy_ids: sni_ids,
                        adaptive_buffer: adaptive_buf,
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
                })
            } else {
                let started_for_listener = started.clone();
                // TCP or TcpTls listener
                // Passthrough proxies forward raw encrypted bytes — no TLS termination.
                let tls_config = if *frontend_tls && !*passthrough {
                    self.frontend_tls_config.load().as_ref().clone()
                } else {
                    None
                };
                let metrics = Arc::new(TcpProxyMetrics::default());
                let consumer_index = self.consumer_index.clone();
                let plugin_cache = self.plugin_cache.clone();
                let tcp_idle_timeout = self.tcp_idle_timeout_seconds;
                let tls_policy = self.tls_policy.clone();
                let crls = self.crls.clone();
                let tls_ca_bundle_path = self.tls_ca_bundle_path.clone();
                let sni_ids = sni_ids.clone();
                let adaptive_buf = self.adaptive_buffer.clone();
                tokio::spawn(async move {
                    if let Err(e) = super::tcp_proxy::start_tcp_listener(TcpListenerConfig {
                        port: port_val,
                        bind_addr,
                        proxy_id: proxy_id_owned.clone(),
                        config,
                        dns_cache,
                        load_balancer_cache: lb_cache,
                        consumer_index,
                        frontend_tls_config: tls_config,
                        shutdown: shutdown_rx,
                        metrics,
                        tls_no_verify,
                        tls_ca_bundle_path,
                        plugin_cache,
                        tcp_idle_timeout_seconds: tcp_idle_timeout,
                        circuit_breaker_cache: cb_cache,
                        tls_policy,
                        crls,
                        started: started_for_listener,
                        sni_proxy_ids: sni_ids,
                        adaptive_buffer: adaptive_buf,
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
                })
            };

            info!(
                listener_key = %key,
                proxy_id = %proxy_id,
                port = port,
                protocol = %protocol,
                "Started stream listener"
            );

            listeners.insert(
                key.clone(),
                ListenerHandle {
                    shutdown_tx,
                    _join_handle: join_handle,
                    listen_port: *port,
                    protocol: *protocol,
                    frontend_tls: *frontend_tls,
                    passthrough: *passthrough,
                    started,
                },
            );
        }

        bind_failures
    }

    /// Wait until all currently configured stream listeners have successfully
    /// bound and can accept traffic.
    pub async fn wait_until_started(&self, timeout: Duration) -> Result<(), anyhow::Error> {
        let deadline = Instant::now() + timeout;

        loop {
            let current_config = self.config.load();
            let desired: Vec<(String, u16, BackendProtocol, bool, bool)> = current_config
                .proxies
                .iter()
                .filter(|p| p.backend_protocol.is_stream_proxy())
                .filter_map(|p| {
                    p.listen_port.map(|port| {
                        (
                            p.id.clone(),
                            port,
                            p.backend_protocol,
                            p.frontend_tls,
                            p.passthrough,
                        )
                    })
                })
                .collect();

            if desired.is_empty() {
                return Ok(());
            }

            // Detect SNI port groups to map proxy_ids to their listener key
            let mut pt_port_count: std::collections::HashMap<u16, usize> =
                std::collections::HashMap::new();
            for (_, port, _, _, passthrough) in &desired {
                if *passthrough {
                    *pt_port_count.entry(*port).or_default() += 1;
                }
            }

            let all_started = {
                let listeners = self.listeners.lock().await;
                desired
                    .iter()
                    .all(|(proxy_id, port, protocol, frontend_tls, passthrough)| {
                        // For SNI groups, the listener key is "__sni_{port}" not the proxy_id
                        let key =
                            if *passthrough && pt_port_count.get(port).copied().unwrap_or(0) > 1 {
                                format!("__sni_{}", port)
                            } else {
                                proxy_id.clone()
                            };
                        listeners.get(&key).is_some_and(|handle| {
                            handle.listen_port == *port
                                && handle.protocol == *protocol
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
    #[allow(dead_code)] // Called during gateway shutdown
    pub async fn shutdown_all(&self) {
        let mut listeners = self.listeners.lock().await;
        for (proxy_id, handle) in listeners.drain() {
            info!(proxy_id = %proxy_id, port = handle.listen_port, "Shutting down stream listener");
            let _ = handle.shutdown_tx.send(true);
        }
    }
}
