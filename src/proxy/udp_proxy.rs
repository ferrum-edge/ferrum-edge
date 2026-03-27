//! Raw UDP datagram proxy with session tracking and optional DTLS encryption.
//!
//! Each UDP proxy binds its own dedicated port. Client datagrams are forwarded
//! to the backend via per-client sessions. Backend replies are forwarded back
//! to the original client address. Sessions are cleaned up after an idle timeout.
//!
//! **Backend DTLS**: When `backend_protocol` is `Dtls`, backend connections are
//! wrapped with DTLS encryption using the `webrtc-dtls` crate. The proxy TLS
//! settings (`backend_tls_verify_server_cert`, etc.) control the DTLS handshake.
//!
//! **Frontend DTLS**: When `frontend_dtls_config` is provided, the listener
//! accepts DTLS-encrypted connections from clients instead of plain UDP. Each
//! client gets a dedicated DTLS session with transparent encrypt/decrypt.
//! Decrypted datagrams are forwarded to the backend (plain UDP or DTLS).

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
    /// DTLS server config for frontend termination. When `Some`, the listener
    /// accepts DTLS connections from clients instead of plain UDP.
    pub frontend_dtls_config: Option<webrtc_dtls::config::Config>,
    pub tls_no_verify: bool,
    /// Maximum concurrent sessions per proxy (from `FERRUM_UDP_MAX_SESSIONS`, default 10000).
    pub max_sessions: usize,
    /// Session cleanup interval in seconds (from `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS`, default 10).
    pub cleanup_interval_seconds: u64,
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
        shutdown,
        metrics,
        frontend_dtls_config,
        tls_no_verify,
        max_sessions,
        cleanup_interval_seconds,
    } = cfg;

    if let Some(dtls_config) = frontend_dtls_config {
        return start_dtls_frontend_listener(
            port,
            bind_addr,
            proxy_id,
            config,
            dns_cache,
            load_balancer_cache,
            shutdown,
            metrics,
            dtls_config,
            tls_no_verify,
            max_sessions,
        )
        .await;
    }

    let addr = SocketAddr::new(bind_addr, port);
    let frontend_socket = Arc::new(UdpSocket::bind(addr).await?);
    ensure_coarse_timer_started();
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
    spawn_session_cleanup(
        sessions.clone(),
        metrics.clone(),
        proxy_id.clone(),
        idle_timeout,
        shutdown.clone(),
        cleanup_interval_seconds,
    );

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
                    if sessions.len() >= max_sessions {
                        warn!(
                            proxy_id = %proxy_id,
                            client = %client_addr,
                            "UDP session limit reached ({}), dropping datagram",
                            max_sessions
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
                        tls_no_verify,
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
                session.last_activity.store(coarse_epoch_millis(), Ordering::Relaxed);
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

/// Spawn a background task that periodically removes idle UDP sessions.
fn spawn_session_cleanup(
    sessions: SessionMap,
    metrics: Arc<UdpProxyMetrics>,
    proxy_id: String,
    idle_timeout_seconds: u64,
    mut shutdown: watch::Receiver<bool>,
    cleanup_interval_seconds: u64,
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
                            // Close DTLS connection if active
                            if let Some(ref dtls) = session.dtls_conn {
                                let _ = dtls.close().await;
                            }
                            metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                            debug!(
                                proxy_id = %proxy_id,
                                client = %addr,
                                bytes_sent = session.bytes_sent.load(Ordering::Relaxed),
                                bytes_received = session.bytes_received.load(Ordering::Relaxed),
                                "UDP session expired (idle timeout)"
                            );
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
/// Unlike the plain UDP path (which uses a single socket with `recv_from` to demux
/// by client address), the DTLS path uses `DTLSListener::accept()` which yields a
/// per-client `Arc<dyn Conn>` with transparent DTLS encryption/decryption. Each
/// accepted client is handled in its own spawned task.
#[allow(clippy::too_many_arguments)]
async fn start_dtls_frontend_listener(
    port: u16,
    bind_addr: IpAddr,
    proxy_id: String,
    config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
    dns_cache: DnsCache,
    load_balancer_cache: Arc<LoadBalancerCache>,
    shutdown: watch::Receiver<bool>,
    metrics: Arc<UdpProxyMetrics>,
    dtls_config: webrtc_dtls::config::Config,
    tls_no_verify: bool,
    max_sessions: usize,
) -> Result<(), anyhow::Error> {
    use webrtc_util::conn::Listener;

    let addr = SocketAddr::new(bind_addr, port);
    let listener = crate::dtls::start_dtls_listener(addr, dtls_config).await?;
    ensure_coarse_timer_started();
    info!(proxy_id = %proxy_id, "DTLS frontend listener started on {}", addr);

    let mut shutdown_rx = shutdown;

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (client_conn, client_addr): (Arc<dyn webrtc_util::Conn + Send + Sync>, SocketAddr) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(proxy_id = %proxy_id, "DTLS accept error: {}", e);
                        continue;
                    }
                };

                // Check session limit
                let active = metrics.active_sessions.load(Ordering::Relaxed);
                if active >= max_sessions as u64 {
                    warn!(
                        proxy_id = %proxy_id,
                        client = %client_addr,
                        "DTLS session limit reached ({}), rejecting connection",
                        max_sessions
                    );
                    let _ = client_conn.close().await;
                    continue;
                }

                metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
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

                tokio::spawn(async move {
                    if let Err(e) = handle_dtls_client(
                        client_conn,
                        client_addr,
                        &handler_proxy_id,
                        &handler_config,
                        &handler_dns,
                        &handler_lb,
                        &handler_metrics,
                        tls_no_verify,
                    )
                    .await
                    {
                        debug!(
                            proxy_id = %handler_proxy_id,
                            client = %client_addr,
                            "DTLS client session ended: {}",
                            e
                        );
                    }
                    handler_metrics
                        .active_sessions
                        .fetch_sub(1, Ordering::Relaxed);
                });
            }
            _ = shutdown_rx.changed() => {
                info!(proxy_id = %proxy_id, "DTLS frontend listener shutting down on port {}", port);
                let _ = listener.close().await;
                return Ok(());
            }
        }
    }
}

/// Handle a single DTLS frontend client connection.
///
/// Reads decrypted datagrams from the client via the DTLS connection and forwards
/// them to the backend (plain UDP or backend DTLS). Backend replies are forwarded
/// back through the client's DTLS connection.
#[allow(clippy::too_many_arguments)]
async fn handle_dtls_client(
    client_conn: Arc<dyn webrtc_util::Conn + Send + Sync>,
    client_addr: SocketAddr,
    proxy_id: &str,
    config: &arc_swap::ArcSwap<GatewayConfig>,
    dns_cache: &DnsCache,
    lb_cache: &LoadBalancerCache,
    metrics: &Arc<UdpProxyMetrics>,
    tls_no_verify: bool,
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
    let resolved_ip = dns_cache
        .resolve(
            &backend_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .map_err(|e| anyhow::anyhow!("DNS resolution failed for {}: {}", backend_host, e))?;
    let backend_addr = SocketAddr::new(resolved_ip, backend_port);

    // Create backend connection — plain UDP or DTLS depending on backend_protocol.
    // Frontend DTLS termination can forward to either plain UDP or DTLS backends.
    let (backend_udp, backend_dtls): (
        Option<Arc<UdpSocket>>,
        Option<Arc<webrtc_dtls::conn::DTLSConn>>,
    ) = if proxy.backend_protocol == BackendProtocol::Dtls {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(backend_addr).await?;
        let dtls_config =
            crate::dtls::build_backend_dtls_config(&proxy, &backend_host, tls_no_verify)?;
        let dtls = crate::dtls::connect_dtls_backend(socket, dtls_config).await?;
        debug!(
            proxy_id = %proxy_id,
            client = %client_addr,
            backend = %backend_addr,
            "Backend DTLS handshake completed (frontend DTLS session)"
        );
        (None, Some(dtls))
    } else {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(backend_addr).await?;
        (Some(Arc::new(sock)), None)
    };

    debug!(
        proxy_id = %proxy_id,
        client = %client_addr,
        backend = %backend_addr,
        dtls_backend = backend_dtls.is_some(),
        "DTLS frontend session established"
    );

    // Bidirectional forwarding: client (DTLS) ↔ backend (UDP or DTLS)
    let client_read = client_conn.clone();
    let backend_dtls_write = backend_dtls.clone();
    let backend_udp_write = backend_udp.clone();
    let metrics_fwd = metrics.clone();
    let proxy_id_fwd = proxy_id.to_string();

    // Client → Backend
    let client_to_backend = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
        loop {
            let len = match client_read.recv(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            metrics_fwd.datagrams_in.fetch_add(1, Ordering::Relaxed);
            metrics_fwd
                .bytes_in
                .fetch_add(len as u64, Ordering::Relaxed);

            let send_ok = if let Some(ref dtls) = backend_dtls_write {
                dtls.write(&buf[..len], None)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            } else if let Some(ref sock) = backend_udp_write {
                sock.send(&buf[..len])
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
        }
    });

    // Backend → Client
    let client_write = client_conn.clone();
    let metrics_rev = metrics.clone();
    let proxy_id_rev = proxy_id.to_string();

    let backend_to_client = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
        loop {
            let len = if let Some(ref dtls) = backend_dtls {
                match dtls.read(&mut buf, None).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                }
            } else if let Some(ref sock) = backend_udp {
                match sock.recv(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                }
            } else {
                break;
            };

            metrics_rev.datagrams_in.fetch_add(1, Ordering::Relaxed);
            metrics_rev
                .bytes_in
                .fetch_add(len as u64, Ordering::Relaxed);

            if client_write.send(&buf[..len]).await.is_err() {
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
        }
    });

    // Wait for either direction to finish, then clean up
    tokio::select! {
        _ = client_to_backend => {}
        _ = backend_to_client => {}
    }

    // Close client DTLS connection
    let _ = client_conn.close().await;

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
        // DTLS: create a connected socket and wrap it with DTLSConn.
        // The DTLS layer takes ownership of the connected socket; we keep a
        // placeholder backend_socket for the session struct (unused for I/O).
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(backend_addr).await?;
        let placeholder = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

        let dtls_config =
            crate::dtls::build_backend_dtls_config(&proxy, &backend_host, tls_no_verify)?;
        let dtls = crate::dtls::connect_dtls_backend(socket, dtls_config).await?;
        debug!(
            proxy_id = %proxy_id,
            client = %client_addr,
            backend = %backend_addr,
            "DTLS handshake completed for backend connection"
        );
        (placeholder, Some(dtls))
    } else {
        // Plain UDP
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(backend_addr).await?;
        (Arc::new(socket), None)
    };

    let session = Arc::new(UdpSession {
        backend_socket: backend_socket.clone(),
        dtls_conn: dtls_conn.clone(),
        last_activity: AtomicU64::new(coarse_epoch_millis()),
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
                        .store(coarse_epoch_millis(), Ordering::Relaxed);
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

/// Coarse-grained epoch millisecond timestamp updated periodically.
/// Avoids calling `SystemTime::now()` on every datagram in the hot path.
/// Resolution is ~1ms which is sufficient for session idle timeout tracking.
static COARSE_EPOCH_MS: AtomicU64 = AtomicU64::new(0);

/// Start the background timer that updates `COARSE_EPOCH_MS` every millisecond.
/// Safe to call multiple times; only the first call spawns the task.
fn ensure_coarse_timer_started() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Seed with current time
        COARSE_EPOCH_MS.store(epoch_millis_precise(), Ordering::Relaxed);
        tokio::spawn(async {
            let mut interval = tokio::time::interval(Duration::from_millis(1));
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
