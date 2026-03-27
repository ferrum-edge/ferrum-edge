//! Manages lifecycle of TCP/UDP stream proxy listeners.
//!
//! The `StreamListenerManager` reconciles the set of active listeners against
//! the current `GatewayConfig`. On config reload it starts new listeners,
//! stops removed ones, and restarts listeners whose port or protocol changed.

use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::types::{BackendProtocol, GatewayConfig};
use crate::dns::DnsCache;
use crate::load_balancer::LoadBalancerCache;

use super::tcp_proxy::{TcpListenerConfig, TcpProxyMetrics};
use super::udp_proxy::{UdpListenerConfig, UdpProxyMetrics};

/// Handle for a running stream listener — keeps the shutdown channel and task handle.
struct ListenerHandle {
    shutdown_tx: watch::Sender<bool>,
    _join_handle: JoinHandle<()>,
    listen_port: u16,
    protocol: BackendProtocol,
    frontend_tls: bool,
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
    /// Maximum concurrent UDP sessions per proxy.
    udp_max_sessions: usize,
    /// UDP session cleanup interval in seconds.
    udp_cleanup_interval_seconds: u64,
}

impl StreamListenerManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bind_addr: IpAddr,
        config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
        dns_cache: DnsCache,
        load_balancer_cache: Arc<LoadBalancerCache>,
        frontend_tls_config: Option<Arc<rustls::ServerConfig>>,
        tls_no_verify: bool,
        udp_max_sessions: usize,
        udp_cleanup_interval_seconds: u64,
    ) -> Self {
        Self {
            listeners: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            bind_addr,
            config,
            dns_cache,
            load_balancer_cache,
            frontend_tls_config: arc_swap::ArcSwap::new(Arc::new(frontend_tls_config)),
            frontend_dtls_cert_key: arc_swap::ArcSwap::new(Arc::new(None)),
            frontend_dtls_client_ca_path: arc_swap::ArcSwap::new(Arc::new(None)),
            tls_no_verify,
            udp_max_sessions,
            udp_cleanup_interval_seconds,
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
    pub async fn reconcile(&self) {
        let current_config = self.config.load();
        let mut listeners = self.listeners.lock().await;

        // Collect all desired stream proxies from config
        let desired: std::collections::HashMap<String, (u16, BackendProtocol, bool)> =
            current_config
                .proxies
                .iter()
                .filter(|p| p.backend_protocol.is_stream_proxy())
                .filter_map(|p| {
                    p.listen_port
                        .map(|port| (p.id.clone(), (port, p.backend_protocol, p.frontend_tls)))
                })
                .collect();

        // Stop listeners for removed proxies or changed port/protocol
        let mut to_remove = Vec::new();
        for (proxy_id, handle) in listeners.iter() {
            match desired.get(proxy_id) {
                None => {
                    to_remove.push(proxy_id.clone());
                }
                Some((port, protocol, frontend_tls)) => {
                    if handle.listen_port != *port
                        || handle.protocol != *protocol
                        || handle.frontend_tls != *frontend_tls
                    {
                        to_remove.push(proxy_id.clone());
                    }
                }
            }
        }

        for proxy_id in &to_remove {
            if let Some(handle) = listeners.remove(proxy_id) {
                info!(
                    proxy_id = %proxy_id,
                    port = handle.listen_port,
                    protocol = %handle.protocol,
                    "Stopping stream listener"
                );
                let _ = handle.shutdown_tx.send(true);
            }
        }

        // Start listeners for new or restarted proxies
        for (proxy_id, (port, protocol, frontend_tls)) in &desired {
            if listeners.contains_key(proxy_id) {
                continue;
            }

            // Skip frontend_tls proxies when the required encryption config is not yet loaded.
            // For TCP: needs rustls ServerConfig. For UDP: needs DTLS cert/key paths.
            // The mode will call reconcile() again after setting the config.
            if *frontend_tls {
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

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let proxy_id_owned = proxy_id.clone();
            let bind_addr = self.bind_addr;
            let port_val = *port;
            let config = self.config.clone();
            let dns_cache = self.dns_cache.clone();
            let lb_cache = self.load_balancer_cache.clone();
            let tls_no_verify = self.tls_no_verify;

            let join_handle = if protocol.is_udp() {
                // UDP or DTLS listener
                let frontend_dtls_config = if *frontend_tls {
                    let paths = self.frontend_dtls_cert_key.load();
                    match paths.as_ref() {
                        Some((cert_path, key_path)) => {
                            let client_ca = self.frontend_dtls_client_ca_path.load();
                            let client_ca_ref = client_ca.as_deref();
                            match crate::dtls::build_frontend_dtls_config(
                                cert_path,
                                key_path,
                                client_ca_ref,
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
                tokio::spawn(async move {
                    if let Err(e) = super::udp_proxy::start_udp_listener(UdpListenerConfig {
                        port: port_val,
                        bind_addr,
                        proxy_id: proxy_id_owned.clone(),
                        config,
                        dns_cache,
                        load_balancer_cache: lb_cache,
                        shutdown: shutdown_rx,
                        metrics,
                        frontend_dtls_config,
                        tls_no_verify,
                        max_sessions: udp_max_sessions,
                        cleanup_interval_seconds: udp_cleanup_interval,
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
                // TCP or TcpTls listener
                let tls_config = if *frontend_tls {
                    self.frontend_tls_config.load().as_ref().clone()
                } else {
                    None
                };
                let metrics = Arc::new(TcpProxyMetrics::default());
                tokio::spawn(async move {
                    if let Err(e) = super::tcp_proxy::start_tcp_listener(TcpListenerConfig {
                        port: port_val,
                        bind_addr,
                        proxy_id: proxy_id_owned.clone(),
                        config,
                        dns_cache,
                        load_balancer_cache: lb_cache,
                        frontend_tls_config: tls_config,
                        shutdown: shutdown_rx,
                        metrics,
                        tls_no_verify,
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
                proxy_id = %proxy_id,
                port = port,
                protocol = %protocol,
                "Started stream listener"
            );

            listeners.insert(
                proxy_id.clone(),
                ListenerHandle {
                    shutdown_tx,
                    _join_handle: join_handle,
                    listen_port: *port,
                    protocol: *protocol,
                    frontend_tls: *frontend_tls,
                },
            );
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
