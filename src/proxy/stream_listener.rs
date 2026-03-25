//! Manages lifecycle of TCP/UDP stream proxy listeners.
//!
//! The `StreamListenerManager` reconciles the set of active listeners against
//! the current `GatewayConfig`. On config reload it starts new listeners,
//! stops removed ones, and restarts listeners whose port or protocol changed.

use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info};

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
    /// Frontend TLS config for stream proxies with `frontend_tls: true`.
    /// Uses `ArcSwap` because the TLS config may be loaded after `ProxyState::new()`
    /// (e.g., in file mode where TLS certs are validated after the proxy state is built).
    frontend_tls_config: arc_swap::ArcSwap<Option<Arc<rustls::ServerConfig>>>,
}

impl StreamListenerManager {
    pub fn new(
        bind_addr: IpAddr,
        config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
        dns_cache: DnsCache,
        load_balancer_cache: Arc<LoadBalancerCache>,
        frontend_tls_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Self {
        Self {
            listeners: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            bind_addr,
            config,
            dns_cache,
            load_balancer_cache,
            frontend_tls_config: arc_swap::ArcSwap::new(Arc::new(frontend_tls_config)),
        }
    }

    /// Update the frontend TLS configuration used for stream proxies with `frontend_tls: true`.
    ///
    /// Call this once the gateway's TLS certificates are loaded, then call
    /// `reconcile()` to restart any listeners that need frontend TLS.
    pub fn set_frontend_tls_config(&self, tls_config: Option<Arc<rustls::ServerConfig>>) {
        self.frontend_tls_config.store(Arc::new(tls_config));
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
                Some((port, protocol, _frontend_tls)) => {
                    if handle.listen_port != *port || handle.protocol != *protocol {
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

            // Skip frontend_tls proxies when TLS config is not yet loaded.
            // This happens at initial startup before the mode sets the TLS config.
            // The mode will call reconcile() again after setting TLS, at which point
            // the listener will be started with the TLS config.
            if *frontend_tls && self.frontend_tls_config.load().is_none() {
                info!(
                    proxy_id = %proxy_id,
                    port = port,
                    "Deferring stream listener start: frontend_tls requires TLS config"
                );
                continue;
            }

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let proxy_id_owned = proxy_id.clone();
            let bind_addr = self.bind_addr;
            let port_val = *port;
            let config = self.config.clone();
            let dns_cache = self.dns_cache.clone();
            let lb_cache = self.load_balancer_cache.clone();

            let join_handle = if protocol.is_udp() {
                // UDP or DTLS listener
                let metrics = Arc::new(UdpProxyMetrics::default());
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
