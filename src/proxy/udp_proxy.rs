//! Raw UDP datagram proxy with session tracking and optional DTLS encryption.
//!
//! Each UDP proxy binds its own dedicated port. Client datagrams are forwarded
//! to the backend via per-client sessions. Backend replies are forwarded back
//! to the original client address. Sessions are cleaned up after an idle timeout.
//!
//! When `backend_protocol` is `Dtls`, backend connections are wrapped with DTLS
//! encryption using the `webrtc-dtls` crate. The proxy TLS settings
//! (`backend_tls_verify_server_cert`, etc.) control the DTLS handshake.

use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::types::{BackendProtocol, GatewayConfig, Proxy};
use crate::dns::DnsCache;
use crate::load_balancer::LoadBalancerCache;

/// Maximum datagram size for UDP forwarding.
const MAX_UDP_DATAGRAM_SIZE: usize = 65535;

/// Default maximum number of concurrent sessions per proxy.
const DEFAULT_MAX_SESSIONS: usize = 10_000;

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
    backend_socket: Arc<UdpSocket>,
    /// DTLS connection wrapping the backend socket (set when `backend_protocol == Dtls`).
    dtls_conn: Option<Arc<webrtc_dtls::conn::DTLSConn>>,
    last_activity: AtomicU64, // epoch millis
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

type SessionMap = Arc<DashMap<SocketAddr, Arc<UdpSession>>>;

/// Configuration for starting a UDP proxy listener.
pub struct UdpListenerConfig {
    pub port: u16,
    pub bind_addr: IpAddr,
    pub proxy_id: String,
    pub config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
    pub dns_cache: DnsCache,
    pub load_balancer_cache: Arc<LoadBalancerCache>,
    pub shutdown: watch::Receiver<bool>,
    pub metrics: Arc<UdpProxyMetrics>,
}

/// Start a UDP proxy listener on the given port.
///
/// For each incoming datagram from a new client address, a session is created
/// with a dedicated backend socket. Datagrams are forwarded bidirectionally.
/// Idle sessions are cleaned up periodically.
pub async fn start_udp_listener(cfg: UdpListenerConfig) -> Result<(), anyhow::Error> {
    let UdpListenerConfig {
        port,
        bind_addr,
        proxy_id,
        config,
        dns_cache,
        load_balancer_cache,
        shutdown,
        metrics,
    } = cfg;

    let addr = SocketAddr::new(bind_addr, port);
    let frontend_socket = Arc::new(UdpSocket::bind(addr).await?);
    info!(proxy_id = %proxy_id, "UDP proxy listener started on {}", addr);

    let sessions: SessionMap = Arc::new(DashMap::new());

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
    let cleanup_sessions = sessions.clone();
    let cleanup_metrics = metrics.clone();
    let cleanup_proxy_id = proxy_id.clone();
    let mut cleanup_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = epoch_millis();
                    let timeout_ms = idle_timeout * 1000;
                    let mut expired = Vec::new();
                    for entry in cleanup_sessions.iter() {
                        let last = entry.value().last_activity.load(Ordering::Relaxed);
                        if now.saturating_sub(last) > timeout_ms {
                            expired.push(*entry.key());
                        }
                    }
                    for addr in expired {
                        cleanup_sessions.remove(&addr);
                        cleanup_metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                        debug!(
                            proxy_id = %cleanup_proxy_id,
                            client = %addr,
                            "UDP session expired (idle timeout)"
                        );
                    }
                }
                _ = cleanup_shutdown.changed() => {
                    return;
                }
            }
        }
    });

    let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
    let mut shutdown_rx = shutdown;

    loop {
        tokio::select! {
            result = frontend_socket.recv_from(&mut buf) => {
                let (len, client_addr) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(proxy_id = %proxy_id, "UDP recv error: {}", e);
                        continue;
                    }
                };

                metrics.datagrams_in.fetch_add(1, Ordering::Relaxed);
                metrics.bytes_in.fetch_add(len as u64, Ordering::Relaxed);

                let data = &buf[..len];

                // Get or create session
                let session = if let Some(existing) = sessions.get(&client_addr) {
                    existing.value().clone()
                } else {
                    // Check session limit
                    if sessions.len() >= DEFAULT_MAX_SESSIONS {
                        warn!(
                            proxy_id = %proxy_id,
                            client = %client_addr,
                            "UDP session limit reached ({}), dropping datagram",
                            DEFAULT_MAX_SESSIONS
                        );
                        continue;
                    }

                    // Create new session
                    match create_session(
                        &proxy_id,
                        &config,
                        &dns_cache,
                        &load_balancer_cache,
                        &frontend_socket,
                        client_addr,
                        &sessions,
                        &metrics,
                    ).await {
                        Ok(session) => session,
                        Err(e) => {
                            warn!(
                                proxy_id = %proxy_id,
                                client = %client_addr,
                                "Failed to create UDP session: {}",
                                e
                            );
                            continue;
                        }
                    }
                };

                // Forward datagram to backend (via DTLS if configured)
                session.last_activity.store(epoch_millis(), Ordering::Relaxed);
                let send_result = if let Some(ref dtls) = session.dtls_conn {
                    dtls.write(data, None).await.map_err(|e| std::io::Error::other(e.to_string()))
                } else {
                    session.backend_socket.send(data).await
                };

                if let Err(e) = send_result {
                    debug!(
                        proxy_id = %proxy_id,
                        client = %client_addr,
                        "UDP send to backend failed: {}",
                        e
                    );
                } else {
                    session.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
                    metrics.datagrams_out.fetch_add(1, Ordering::Relaxed);
                    metrics.bytes_out.fetch_add(len as u64, Ordering::Relaxed);
                }
            }
            _ = shutdown_rx.changed() => {
                info!(proxy_id = %proxy_id, "UDP proxy listener shutting down on port {}", port);
                return Ok(());
            }
        }
    }
}

/// Create a new UDP session for a client.
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
) -> Result<Arc<UdpSession>, anyhow::Error> {
    let current_config = config.load();
    let proxy = current_config
        .proxies
        .iter()
        .find(|p| p.id == proxy_id)
        .ok_or_else(|| anyhow::anyhow!("Proxy {} not found", proxy_id))?
        .clone();

    // Resolve backend target
    let (backend_host, backend_port) = resolve_backend_target(&proxy, lb_cache)?;

    // DNS resolve
    let resolved_ip = dns_cache
        .resolve(
            &backend_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .map_err(|e| anyhow::anyhow!("DNS resolution failed for {}: {}", backend_host, e))?;
    let backend_addr = SocketAddr::new(resolved_ip, backend_port);

    // Create backend connection — plain UDP or DTLS
    let (backend_socket, dtls_conn) = if proxy.backend_protocol == BackendProtocol::Dtls {
        // DTLS: create a socket and wrap it with DTLSConn
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(backend_addr).await?;
        let backend_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

        let dtls_config = crate::dtls::build_backend_dtls_config(&proxy, &backend_host)?;
        let dtls = crate::dtls::connect_dtls_backend(socket, dtls_config).await?;
        debug!(
            proxy_id = %proxy_id,
            client = %client_addr,
            backend = %backend_addr,
            "DTLS handshake completed for backend connection"
        );
        (backend_socket, Some(dtls))
    } else {
        // Plain UDP
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(backend_addr).await?;
        (Arc::new(socket), None)
    };

    let session = Arc::new(UdpSession {
        backend_socket: backend_socket.clone(),
        dtls_conn: dtls_conn.clone(),
        last_activity: AtomicU64::new(epoch_millis()),
        bytes_sent: AtomicU64::new(0),
        bytes_received: AtomicU64::new(0),
    });

    sessions.insert(client_addr, session.clone());
    metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
    metrics.total_sessions.fetch_add(1, Ordering::Relaxed);

    debug!(
        proxy_id = %proxy_id,
        client = %client_addr,
        backend = %backend_addr,
        "New UDP session created"
    );

    // Spawn backend → client reply forwarder
    let frontend = frontend_socket.clone();
    let reply_session = session.clone();
    let reply_proxy_id = proxy_id.to_string();
    let reply_metrics = metrics.clone();
    let reply_sessions = sessions.clone();
    let reply_dtls = dtls_conn;
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
        loop {
            // Read from backend — via DTLS or raw UDP
            let recv_result = if let Some(ref dtls) = reply_dtls {
                dtls.read(&mut buf, None)
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))
            } else {
                backend_socket.recv(&mut buf).await
            };

            match recv_result {
                Ok(len) => {
                    reply_session
                        .last_activity
                        .store(epoch_millis(), Ordering::Relaxed);
                    reply_session
                        .bytes_received
                        .fetch_add(len as u64, Ordering::Relaxed);
                    reply_metrics.datagrams_out.fetch_add(1, Ordering::Relaxed);
                    reply_metrics
                        .bytes_out
                        .fetch_add(len as u64, Ordering::Relaxed);

                    if let Err(e) = frontend.send_to(&buf[..len], client_addr).await {
                        debug!(
                            proxy_id = %reply_proxy_id,
                            client = %client_addr,
                            "UDP send to client failed: {}",
                            e
                        );
                        break;
                    }
                }
                Err(e) => {
                    // Backend socket closed or error — clean up session
                    debug!(
                        proxy_id = %reply_proxy_id,
                        client = %client_addr,
                        "UDP backend recv error: {}",
                        e
                    );
                    break;
                }
            }
        }
        // Session's backend receiver exited — remove session
        // Close DTLS connection if active
        if let Some(ref dtls) = reply_dtls {
            let _ = dtls.close().await;
        }
        reply_sessions.remove(&client_addr);
        reply_metrics
            .active_sessions
            .fetch_sub(1, Ordering::Relaxed);
    });

    Ok(session)
}

/// Resolve the backend target — either direct from proxy config or via load balancer.
fn resolve_backend_target(
    proxy: &Proxy,
    lb_cache: &LoadBalancerCache,
) -> Result<(String, u16), anyhow::Error> {
    if let Some(upstream_id) = &proxy.upstream_id {
        let selection = lb_cache
            .select_target(upstream_id, &proxy.id, None)
            .ok_or_else(|| anyhow::anyhow!("No healthy targets for upstream {}", upstream_id))?;
        Ok((selection.target.host.clone(), selection.target.port))
    } else {
        Ok((proxy.backend_host.clone(), proxy.backend_port))
    }
}

fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
