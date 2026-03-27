//! Raw TCP stream proxy with optional TLS termination (frontend) and origination (backend).
//!
//! Each TCP proxy binds its own dedicated port. Incoming connections are
//! forwarded bidirectionally to the configured backend using
//! `tokio::io::copy_bidirectional` for optimal zero-copy throughput.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::tls::NoVerifier;

use crate::config::types::{BackendProtocol, GatewayConfig, Proxy};
use crate::dns::DnsCache;
use crate::load_balancer::LoadBalancerCache;

/// Cached backend TLS configuration to avoid reading certificate files from
/// disk on every connection. Built once per listener lifecycle and reused.
struct CachedBackendTlsConfig {
    config: Arc<rustls::ClientConfig>,
}

impl CachedBackendTlsConfig {
    /// Build a TLS client config from proxy settings, reading cert files once.
    fn build(proxy: &Proxy, tls_no_verify: bool) -> Result<Self, anyhow::Error> {
        // Build root certificate store
        let mut root_store = rustls::RootCertStore::empty();
        if let Some(ca_path) = &proxy.backend_tls_server_ca_cert_path {
            let ca_data = std::fs::read(ca_path)
                .map_err(|e| anyhow::anyhow!("Failed to read CA cert {}: {}", ca_path, e))?;
            let certs = rustls_pemfile::certs(&mut &ca_data[..])
                .filter_map(|r| r.ok())
                .collect::<Vec<_>>();
            for cert in certs {
                root_store
                    .add(cert)
                    .map_err(|e| anyhow::anyhow!("Failed to add CA cert: {}", e))?;
            }
        } else {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        // Build TLS client config with optional client auth
        let mut tls_config = if let (Some(cert_path), Some(key_path)) = (
            &proxy.backend_tls_client_cert_path,
            &proxy.backend_tls_client_key_path,
        ) {
            let cert_data = std::fs::read(cert_path)?;
            let key_data = std::fs::read(key_path)?;
            let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_data[..])
                .filter_map(|r| r.ok())
                .collect();
            let key = rustls_pemfile::private_key(&mut &key_data[..])
                .map_err(|e| anyhow::anyhow!("Failed to parse private key: {}", e))?
                .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path))?;
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(certs, key)
                .map_err(|e| anyhow::anyhow!("Failed to set client auth cert: {}", e))?
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        if !proxy.backend_tls_verify_server_cert || tls_no_verify {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier));
        }

        Ok(Self {
            config: Arc::new(tls_config),
        })
    }
}

/// Metrics for a single TCP proxy listener.
#[derive(Default)]
pub struct TcpProxyMetrics {
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}

/// Configuration for starting a TCP proxy listener.
pub struct TcpListenerConfig {
    pub port: u16,
    pub bind_addr: IpAddr,
    pub proxy_id: String,
    pub config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
    pub dns_cache: DnsCache,
    pub load_balancer_cache: Arc<LoadBalancerCache>,
    pub frontend_tls_config: Option<Arc<rustls::ServerConfig>>,
    pub shutdown: watch::Receiver<bool>,
    pub metrics: Arc<TcpProxyMetrics>,
    pub tls_no_verify: bool,
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
        load_balancer_cache,
        frontend_tls_config,
        shutdown,
        metrics,
        tls_no_verify,
    } = cfg;
    let addr = SocketAddr::new(bind_addr, port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(
        proxy_id = %proxy_id,
        "TCP proxy listener started on {}",
        addr
    );

    // Pre-build backend TLS config if this proxy uses TcpTls backend protocol.
    // This avoids reading certificate files from disk on every connection.
    let backend_tls_cache: Option<Arc<CachedBackendTlsConfig>> = {
        let current_config = config.load();
        current_config
            .proxies
            .iter()
            .find(|p| p.id == proxy_id)
            .filter(|p| p.backend_protocol == BackendProtocol::TcpTls)
            .map(|proxy| {
                CachedBackendTlsConfig::build(proxy, tls_no_verify)
                    .map(Arc::new)
                    .unwrap_or_else(|e| {
                        warn!(proxy_id = %proxy_id, "Failed to pre-build backend TLS config: {}, will retry per-connection", e);
                        // Return a dummy config that will be rebuilt per-connection
                        Arc::new(CachedBackendTlsConfig {
                            config: Arc::new(
                                rustls::ClientConfig::builder()
                                    .with_root_certificates(rustls::RootCertStore::empty())
                                    .with_no_client_auth()
                            ),
                        })
                    })
            })
    };

    let mut shutdown_rx = shutdown;

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, remote_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!(proxy_id = %proxy_id, "TCP accept error: {}", e);
                        continue;
                    }
                };

                metrics.total_connections.fetch_add(1, Ordering::Relaxed);
                metrics.active_connections.fetch_add(1, Ordering::Relaxed);

                let proxy_id = proxy_id.clone();
                let config = config.clone();
                let dns_cache = dns_cache.clone();
                let lb_cache = load_balancer_cache.clone();
                let frontend_tls = frontend_tls_config.clone();
                let metrics = metrics.clone();
                let backend_tls = backend_tls_cache.clone();

                tokio::spawn(async move {
                    let result = handle_tcp_connection(
                        stream,
                        remote_addr,
                        &proxy_id,
                        &config,
                        &dns_cache,
                        &lb_cache,
                        frontend_tls.as_ref(),
                        tls_no_verify,
                        backend_tls.as_deref(),
                    )
                    .await;

                    match &result {
                        Ok((bytes_in, bytes_out, duration)) => {
                            metrics.bytes_in.fetch_add(*bytes_in, Ordering::Relaxed);
                            metrics.bytes_out.fetch_add(*bytes_out, Ordering::Relaxed);
                            debug!(
                                proxy_id = %proxy_id,
                                client = %remote_addr.ip(),
                                bytes_in = bytes_in,
                                bytes_out = bytes_out,
                                duration_ms = duration.as_millis() as u64,
                                "TCP connection completed"
                            );
                        }
                        Err(e) => {
                            debug!(
                                proxy_id = %proxy_id,
                                client = %remote_addr.ip(),
                                error = %e,
                                "TCP connection error"
                            );
                        }
                    }

                    metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
                });
            }
            _ = shutdown_rx.changed() => {
                info!(proxy_id = %proxy_id, "TCP proxy listener shutting down on port {}", port);
                return Ok(());
            }
        }
    }
}

/// Handle a single TCP connection: TLS termination → backend resolution → bidirectional copy.
#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection(
    client_stream: TcpStream,
    remote_addr: SocketAddr,
    proxy_id: &str,
    config: &arc_swap::ArcSwap<GatewayConfig>,
    dns_cache: &DnsCache,
    lb_cache: &LoadBalancerCache,
    frontend_tls_config: Option<&Arc<rustls::ServerConfig>>,
    tls_no_verify: bool,
    cached_backend_tls: Option<&CachedBackendTlsConfig>,
) -> Result<(u64, u64, Duration), anyhow::Error> {
    let start = Instant::now();
    let _ = client_stream.set_nodelay(true);

    // Look up the proxy config
    let current_config = config.load();
    let proxy = current_config
        .proxies
        .iter()
        .find(|p| p.id == proxy_id)
        .ok_or_else(|| anyhow::anyhow!("Proxy {} not found in config", proxy_id))?
        .clone();

    // Resolve backend target
    let (backend_host, backend_port) = resolve_backend_target(&proxy, lb_cache)?;

    // Resolve backend IP via DNS
    let resolved_ip = dns_cache
        .resolve(
            &backend_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .map_err(|e| anyhow::anyhow!("DNS resolution failed for {}: {}", backend_host, e))?;
    let backend_addr = SocketAddr::new(resolved_ip, backend_port);

    // Apply frontend TLS termination if configured
    if let Some(tls_config) = frontend_tls_config {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.clone());
        let tls_stream = acceptor.accept(client_stream).await.map_err(|e| {
            anyhow::anyhow!("Frontend TLS handshake failed from {}: {}", remote_addr, e)
        })?;

        // Connect to backend (with or without TLS origination)
        if proxy.backend_protocol == BackendProtocol::TcpTls {
            let backend_stream = connect_backend_tls_cached(
                backend_addr,
                &backend_host,
                &proxy,
                tls_no_verify,
                cached_backend_tls,
            )
            .await?;
            bidirectional_copy(tls_stream, backend_stream).await
        } else {
            let backend_stream = connect_backend_plain(backend_addr, &proxy).await?;
            bidirectional_copy(tls_stream, backend_stream).await
        }
    } else {
        // No frontend TLS — raw TCP
        if proxy.backend_protocol == BackendProtocol::TcpTls {
            let backend_stream = connect_backend_tls_cached(
                backend_addr,
                &backend_host,
                &proxy,
                tls_no_verify,
                cached_backend_tls,
            )
            .await?;
            bidirectional_copy(client_stream, backend_stream).await
        } else {
            let backend_stream = connect_backend_plain(backend_addr, &proxy).await?;
            bidirectional_copy(client_stream, backend_stream).await
        }
    }
    .map(|(bytes_in, bytes_out)| (bytes_in, bytes_out, start.elapsed()))
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

/// Connect to a plain TCP backend with the proxy's configured timeout.
async fn connect_backend_plain(
    addr: SocketAddr,
    proxy: &Proxy,
) -> Result<TcpStream, anyhow::Error> {
    let timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("Backend connect timeout to {}", addr))?
        .map_err(|e| anyhow::anyhow!("Backend connect failed to {}: {}", addr, e))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Connect to a TLS-enabled backend using the cached TLS config when available.
/// Falls back to building the config from disk if no cache is provided.
async fn connect_backend_tls_cached(
    addr: SocketAddr,
    hostname: &str,
    proxy: &Proxy,
    tls_no_verify: bool,
    cached_tls: Option<&CachedBackendTlsConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, anyhow::Error> {
    let tcp_stream = connect_backend_plain(addr, proxy).await?;

    let tls_config = if let Some(cached) = cached_tls {
        // Fast path: use pre-built TLS config (no disk I/O)
        cached.config.clone()
    } else {
        // Slow path: build TLS config from disk (fallback)
        let built = CachedBackendTlsConfig::build(proxy, tls_no_verify)?;
        built.config
    };

    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
        .map_err(|e| anyhow::anyhow!("Invalid server name '{}': {}", hostname, e))?;

    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| anyhow::anyhow!("Backend TLS handshake failed to {}: {}", addr, e))?;

    Ok(tls_stream)
}

/// Bidirectional stream copy between client and backend.
/// Returns (bytes_client_to_backend, bytes_backend_to_client).
async fn bidirectional_copy<C, B>(
    mut client: C,
    mut backend: B,
) -> Result<(u64, u64), anyhow::Error>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (bytes_to_backend, bytes_to_client) =
        tokio::io::copy_bidirectional(&mut client, &mut backend)
            .await
            .map_err(|e| anyhow::anyhow!("Bidirectional copy error: {}", e))?;
    Ok((bytes_to_backend, bytes_to_client))
}
