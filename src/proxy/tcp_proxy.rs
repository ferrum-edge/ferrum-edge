//! Raw TCP stream proxy with optional TLS termination (frontend) and origination (backend).
//!
//! Each TCP proxy binds its own dedicated port. Incoming connections are
//! forwarded bidirectionally to the configured backend using
//! `tokio::io::copy_bidirectional` for optimal zero-copy throughput.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::circuit_breaker::CircuitBreakerCache;
use crate::tls::{NoVerifier, TlsPolicy};

use crate::config::types::{BackendProtocol, GatewayConfig, Proxy};
use crate::consumer_index::ConsumerIndex;
use crate::dns::DnsCache;
use crate::load_balancer::LoadBalancerCache;
use crate::plugin_cache::PluginCache;
use crate::plugins::{
    PluginResult, ProxyProtocol, StreamConnectionContext, StreamTransactionSummary,
};

pub(crate) fn classify_stream_error(error: &anyhow::Error) -> crate::retry::ErrorClass {
    crate::retry::classify_boxed_error(error.as_ref())
}

/// Cached backend TLS configuration to avoid reading certificate files from
/// disk on every connection. Built once per listener lifecycle and reused.
struct CachedBackendTlsConfig {
    config: Arc<rustls::ClientConfig>,
}

impl CachedBackendTlsConfig {
    /// Build a TLS client config from proxy settings, reading cert files once.
    /// Uses the TLS policy's cipher suites and protocol versions when available.
    fn build(
        proxy: &Proxy,
        tls_no_verify: bool,
        global_tls_ca_bundle_path: Option<&str>,
        tls_policy: Option<&TlsPolicy>,
        crls: &crate::tls::CrlList,
    ) -> Result<Self, anyhow::Error> {
        // Build root certificate store:
        // - Custom CA configured → empty store + only that CA (no public roots)
        // - No CA configured → webpki/system roots as default fallback
        let ca_path = proxy
            .resolved_tls
            .server_ca_cert_path
            .as_deref()
            .or(global_tls_ca_bundle_path);
        let mut root_store = if ca_path.is_some() {
            rustls::RootCertStore::empty()
        } else {
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
        };
        if let Some(ca_path) = ca_path {
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
        }

        // Build TLS client config with optional client auth, using TLS policy
        let verifier = crate::tls::build_server_verifier_with_crls(root_store, crls)?;
        let builder = crate::tls::backend_client_config_builder(tls_policy)?;
        let mut tls_config = if let (Some(cert_path), Some(key_path)) = (
            &proxy.resolved_tls.client_cert_path,
            &proxy.resolved_tls.client_key_path,
        ) {
            let cert_data = std::fs::read(cert_path)?;
            let key_data = std::fs::read(key_path)?;
            let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_data[..])
                .filter_map(|r| r.ok())
                .collect();
            let key = rustls_pemfile::private_key(&mut &key_data[..])
                .map_err(|e| anyhow::anyhow!("Failed to parse private key: {}", e))?
                .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path))?;
            builder
                .with_webpki_verifier(verifier)
                .with_client_auth_cert(certs, key)
                .map_err(|e| anyhow::anyhow!("Failed to set client auth cert: {}", e))?
        } else {
            builder.with_webpki_verifier(verifier).with_no_client_auth()
        };

        // Disable verification only if explicitly requested
        if !proxy.resolved_tls.verify_server_cert || tls_no_verify {
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
    /// Bytes transferred via splice(2) zero-copy (Linux only, plaintext paths).
    /// When non-zero, indicates splice was used instead of userspace copy.
    pub splice_bytes_transferred: AtomicU64,
}

/// Configuration for starting a TCP proxy listener.
pub struct TcpListenerConfig {
    pub port: u16,
    pub bind_addr: IpAddr,
    pub proxy_id: String,
    pub config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
    pub dns_cache: DnsCache,
    pub load_balancer_cache: Arc<LoadBalancerCache>,
    pub consumer_index: Arc<ConsumerIndex>,
    pub frontend_tls_config: Option<Arc<rustls::ServerConfig>>,
    pub shutdown: watch::Receiver<bool>,
    pub metrics: Arc<TcpProxyMetrics>,
    pub tls_no_verify: bool,
    /// Global CA bundle path for outbound TLS verification (fallback when proxy has no per-proxy CA).
    pub tls_ca_bundle_path: Option<String>,
    pub plugin_cache: Arc<PluginCache>,
    /// Global default TCP idle timeout in seconds. Per-proxy `tcp_idle_timeout_seconds` overrides.
    pub tcp_idle_timeout_seconds: u64,
    /// Circuit breaker cache shared with HTTP proxies.
    pub circuit_breaker_cache: Arc<CircuitBreakerCache>,
    /// TLS hardening policy for backend connections (cipher suites, protocol versions).
    pub tls_policy: Option<Arc<TlsPolicy>>,
    /// Certificate Revocation Lists for backend TLS verification.
    pub crls: crate::tls::CrlList,
    /// Flipped once the listener successfully binds and can accept traffic.
    pub started: Arc<AtomicBool>,
    /// When set, this listener serves multiple passthrough proxies sharing the port.
    /// SNI from the ClientHello selects which proxy to route to.
    /// When `None`, uses the single `proxy_id` (existing behavior).
    pub sni_proxy_ids: Option<Vec<String>>,
    /// Adaptive buffer tracker for dynamic copy buffer sizing.
    pub adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    /// Whether TCP Fast Open is enabled (from `FERRUM_TCP_FASTOPEN_ENABLED`).
    pub tcp_fastopen_enabled: bool,
    /// Shared overload state for connection accounting and load shedding.
    pub overload: Arc<crate::overload::OverloadState>,
    /// Enable kTLS for splice on TLS paths (from `FERRUM_KTLS_ENABLED`).
    pub ktls_enabled: bool,
    /// Enable io_uring-based splice (from `FERRUM_IO_URING_SPLICE_ENABLED`).
    pub io_uring_splice_enabled: bool,
    /// Enable MSG_ZEROCOPY for large sends (from `FERRUM_MSG_ZEROCOPY_ENABLED`).
    pub msg_zerocopy_enabled: bool,
    /// Threshold in bytes for MSG_ZEROCOPY (from `FERRUM_MSG_ZEROCOPY_THRESHOLD`).
    pub msg_zerocopy_threshold: usize,
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
        consumer_index,
        frontend_tls_config,
        shutdown,
        metrics,
        tls_no_verify,
        tls_ca_bundle_path,
        plugin_cache,
        tcp_idle_timeout_seconds: global_tcp_idle_timeout,
        circuit_breaker_cache,
        tls_policy,
        crls,
        started,
        sni_proxy_ids,
        adaptive_buffer,
        tcp_fastopen_enabled,
        overload,
        ktls_enabled,
        io_uring_splice_enabled,
        msg_zerocopy_enabled,
        msg_zerocopy_threshold,
    } = cfg;
    let addr = SocketAddr::new(bind_addr, port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // Convert to Arc<str> so per-connection clones are a cheap pointer bump.
    let proxy_id: Arc<str> = Arc::from(proxy_id);
    started.store(true, Ordering::Release);
    info!(
        proxy_id = %proxy_id,
        "TCP proxy listener started on {}",
        addr
    );

    // Pre-capture proxy metadata for plugin context (static for this listener's lifetime).
    let (proxy_name, proxy_namespace, backend_protocol) = {
        let current_config = config.load();
        current_config
            .proxies
            .iter()
            .find(|p| *p.id == *proxy_id)
            .map(|p| (p.name.clone(), p.namespace.clone(), p.backend_protocol))
            .unwrap_or((
                None,
                crate::config::types::default_namespace(),
                BackendProtocol::Tcp,
            ))
    };

    // Pre-resolve plugins for this proxy's protocol (TCP).
    let plugins = plugin_cache.get_plugins_for_protocol(&proxy_id, ProxyProtocol::Tcp);

    // Pre-build backend TLS config if this proxy uses TcpTls backend protocol.
    // This avoids reading certificate files from disk on every connection.
    let backend_tls_cache: Option<Arc<CachedBackendTlsConfig>> = {
        let current_config = config.load();
        current_config
            .proxies
            .iter()
            .find(|p| *p.id == *proxy_id)
            .filter(|p| p.backend_protocol == BackendProtocol::TcpTls)
            .map(|proxy| {
                CachedBackendTlsConfig::build(proxy, tls_no_verify, tls_ca_bundle_path.as_deref(), tls_policy.as_deref(), &crls)
                    .map(Arc::new)
                    .unwrap_or_else(|e| {
                        warn!(proxy_id = %proxy_id, "Failed to pre-build backend TLS config: {}, will retry per-connection", e);
                        // Return a dummy config that will be rebuilt per-connection
                        let dummy_builder = crate::tls::backend_client_config_builder(tls_policy.as_deref())
                            .unwrap_or_else(|_| rustls::ClientConfig::builder());
                        Arc::new(CachedBackendTlsConfig {
                            config: Arc::new(
                                dummy_builder
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

                // Reject new connections under critical overload (same as HTTP proxy).
                if overload.reject_new_connections.load(Ordering::Relaxed) {
                    drop(stream); // TCP RST
                    continue;
                }

                metrics.total_connections.fetch_add(1, Ordering::Relaxed);
                metrics.active_connections.fetch_add(1, Ordering::Relaxed);

                let proxy_id = proxy_id.clone();
                let config = config.clone();
                let dns_cache = dns_cache.clone();
                let lb_cache = load_balancer_cache.clone();
                let consumer_index = consumer_index.clone();
                let frontend_tls = frontend_tls_config.clone();
                let metrics = metrics.clone();
                let backend_tls = backend_tls_cache.clone();
                let plugins = plugins.clone();
                let proxy_name = proxy_name.clone();
                let proxy_namespace = proxy_namespace.clone();
                let cb_cache = circuit_breaker_cache.clone();
                let sni_proxy_ids = sni_proxy_ids.clone();
                let adaptive_buf = adaptive_buffer.clone();
                let overload_for_conn = overload.clone();

                tokio::spawn(async move {
                    // Track this connection for global overload accounting and graceful drain.
                    // The guard decrements the counter on drop (all exit paths).
                    let _conn_guard = crate::overload::ConnectionGuard::new(&overload_for_conn);

                    let connected_at = chrono::Utc::now();

                    // Build stream context — plugins run inside handle_tcp_connection
                    // (after TLS handshake for TLS proxies, so client cert is available).
                    let mut stream_ctx = StreamConnectionContext {
                        client_ip: remote_addr.ip().to_string(),
                        proxy_id: proxy_id.to_string(),
                        proxy_name: proxy_name.clone(),
                        listen_port: port,
                        backend_protocol,
                        consumer_index,
                        identified_consumer: None,
                        authenticated_identity: None,
                        metadata: None,
                        tls_client_cert_der: None,
                        tls_client_cert_chain_der: None,
                        sni_hostname: None,
                    };

                    let result = handle_tcp_connection(
                        stream,
                        remote_addr,
                        &proxy_id,
                        &config,
                        &dns_cache,
                        &lb_cache,
                        frontend_tls.as_ref(),
                        backend_tls.as_deref(),
                        global_tcp_idle_timeout,
                        &cb_cache,
                        &plugins,
                        &mut stream_ctx,
                        sni_proxy_ids.as_deref(),
                        &adaptive_buf,
                        tcp_fastopen_enabled,
                        msg_zerocopy_enabled,
                        msg_zerocopy_threshold,
                        ktls_enabled,
                        io_uring_splice_enabled,
                    )
                    .await;

                    let disconnected_at = chrono::Utc::now();
                    let duration_ms = (disconnected_at - connected_at).num_milliseconds().max(0) as f64;
                    let (bytes_in, bytes_out, conn_error, error_class) = match &result.outcome {
                        Ok(s) => {
                            metrics.bytes_in.fetch_add(s.bytes_in, Ordering::Relaxed);
                            metrics.bytes_out.fetch_add(s.bytes_out, Ordering::Relaxed);
                            if s.splice_used {
                                metrics.splice_bytes_transferred.fetch_add(
                                    s.bytes_in.saturating_add(s.bytes_out),
                                    Ordering::Relaxed,
                                );
                            }
                            debug!(
                                proxy_id = %proxy_id,
                                client = %remote_addr.ip(),
                                bytes_in = s.bytes_in,
                                bytes_out = s.bytes_out,
                                splice = s.splice_used,
                                duration_ms = s.duration.as_millis() as u64,
                                "TCP connection completed"
                            );
                            (s.bytes_in, s.bytes_out, None, None)
                        }
                        Err(e) => {
                            debug!(
                                proxy_id = %proxy_id,
                                client = %remote_addr.ip(),
                                error = %e,
                                "TCP connection error"
                            );
                            let error_message = e.to_string();
                            (
                                0,
                                0,
                                Some(error_message),
                                Some(classify_stream_error(e)),
                            )
                        }
                    };

                    // Run on_stream_disconnect plugins (logging, metrics, etc.)
                    if !plugins.is_empty() {
                        let summary = StreamTransactionSummary {
                            namespace: proxy_namespace,
                            proxy_id: proxy_id.to_string(),
                            proxy_name,
                            client_ip: remote_addr.ip().to_string(),
                            backend_target: result.backend.backend_target,
                            backend_resolved_ip: result.backend.backend_resolved_ip,
                            protocol: backend_protocol.to_string(),
                            listen_port: port,
                            duration_ms,
                            bytes_sent: bytes_in,
                            bytes_received: bytes_out,
                            connection_error: conn_error,
                            error_class,
                            timestamp_connected: connected_at.to_rfc3339(),
                            timestamp_disconnected: disconnected_at.to_rfc3339(),
                            sni_hostname: stream_ctx.sni_hostname.clone(),
                            metadata: stream_ctx.take_metadata(),
                        };
                        for plugin in plugins.iter() {
                            plugin.on_stream_disconnect(&summary).await;
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

/// Lightweight snapshot of the proxy fields needed per TCP connection.
/// Avoids cloning the entire `Proxy` struct on every accepted connection.
struct TcpConnParams {
    backend_host: String,
    backend_port: u16,
    backend_protocol: BackendProtocol,
    dns_override: Option<String>,
    dns_cache_ttl_seconds: Option<u64>,
    backend_connect_timeout_ms: u64,
    tcp_idle_timeout_seconds: u64,
    /// Retry config for connection-phase retries (before data transfer).
    retry: Option<crate::config::types::RetryConfig>,
    /// Upstream ID for load-balanced target selection on retry.
    upstream_id: Option<String>,
    /// When true, forward encrypted client bytes directly without TLS termination.
    passthrough: bool,
    /// Whether TCP Fast Open is enabled (gated on `FERRUM_TCP_FASTOPEN_ENABLED`).
    tcp_fastopen_enabled: bool,
}

/// Lightweight snapshot of the proxy fields needed per TCP connection.
/// Includes circuit breaker config and target key for circuit breaker checks.
struct TcpConnCbInfo {
    cb_config: Option<crate::config::types::CircuitBreakerConfig>,
    cb_target_key: Option<String>,
}

/// Backend target info resolved during connection setup, available for logging
/// regardless of whether the connection succeeded or failed.
struct TcpBackendInfo {
    /// The backend target hostname:port (e.g., "db-host:5432").
    backend_target: String,
    /// The DNS-resolved IP address, if resolution succeeded.
    backend_resolved_ip: Option<String>,
}

/// Result of a TCP connection: backend info (always present) plus the outcome.
struct TcpConnectionResult {
    backend: TcpBackendInfo,
    outcome: Result<TcpConnectionSuccess, anyhow::Error>,
}

struct TcpConnectionSuccess {
    bytes_in: u64,
    bytes_out: u64,
    duration: Duration,
    /// Whether splice(2) was used for this connection (Linux plaintext paths only).
    splice_used: bool,
}

/// Handle a single TCP connection: TLS termination → backend resolution → bidirectional copy.
///
/// Always returns a `TcpConnectionResult` containing backend target info (for logging)
/// and the connection outcome. Backend info is populated as soon as the target is known,
/// so even failed connections log which backend was attempted.
#[allow(clippy::too_many_arguments, unused_variables)]
async fn handle_tcp_connection(
    client_stream: TcpStream,
    remote_addr: SocketAddr,
    proxy_id: &str,
    config: &arc_swap::ArcSwap<GatewayConfig>,
    dns_cache: &DnsCache,
    lb_cache: &LoadBalancerCache,
    frontend_tls_config: Option<&Arc<rustls::ServerConfig>>,
    cached_backend_tls: Option<&CachedBackendTlsConfig>,
    global_tcp_idle_timeout: u64,
    circuit_breaker_cache: &CircuitBreakerCache,
    plugins: &[Arc<dyn crate::plugins::Plugin>],
    stream_ctx: &mut StreamConnectionContext,
    sni_proxy_ids: Option<&[String]>,
    adaptive_buffer: &crate::adaptive_buffer::AdaptiveBufferTracker,
    tcp_fastopen: bool,
    msg_zerocopy_enabled: bool,
    _msg_zerocopy_threshold: usize,
    ktls_enabled: bool,
    io_uring_splice_enabled: bool,
) -> TcpConnectionResult {
    let start = Instant::now();
    let _ = client_stream.set_nodelay(true);

    // Apply MSG_ZEROCOPY on the client socket for large sends (Linux 4.14+).
    #[cfg(target_os = "linux")]
    if msg_zerocopy_enabled {
        use std::os::unix::io::AsRawFd;
        let _ = crate::socket_opts::set_so_zerocopy(client_stream.as_raw_fd(), true);
    }

    // Run the core connection logic, tracking backend info for logging.
    // We use a helper closure so that `?` returns from the closure, not the
    // outer function — allowing us to always populate backend info in the result.
    let mut backend_info = TcpBackendInfo {
        backend_target: String::new(),
        backend_resolved_ip: None,
    };

    let outcome = handle_tcp_connection_inner(
        client_stream,
        remote_addr,
        proxy_id,
        config,
        dns_cache,
        lb_cache,
        frontend_tls_config,
        cached_backend_tls,
        global_tcp_idle_timeout,
        circuit_breaker_cache,
        start,
        &mut backend_info,
        plugins,
        stream_ctx,
        sni_proxy_ids,
        adaptive_buffer,
        tcp_fastopen,
        msg_zerocopy_enabled,
        ktls_enabled,
        io_uring_splice_enabled,
    )
    .await;

    TcpConnectionResult {
        backend: backend_info,
        outcome,
    }
}

/// Inner implementation of TCP connection handling that can use `?` for early returns
/// while the caller always receives backend info for logging.
#[allow(clippy::too_many_arguments, unused_variables)]
async fn handle_tcp_connection_inner(
    client_stream: TcpStream,
    remote_addr: SocketAddr,
    proxy_id: &str,
    config: &arc_swap::ArcSwap<GatewayConfig>,
    dns_cache: &DnsCache,
    lb_cache: &LoadBalancerCache,
    frontend_tls_config: Option<&Arc<rustls::ServerConfig>>,
    cached_backend_tls: Option<&CachedBackendTlsConfig>,
    global_tcp_idle_timeout: u64,
    circuit_breaker_cache: &CircuitBreakerCache,
    start: Instant,
    backend_info: &mut TcpBackendInfo,
    plugins: &[Arc<dyn crate::plugins::Plugin>],
    stream_ctx: &mut StreamConnectionContext,
    sni_proxy_ids: Option<&[String]>,
    adaptive_buffer: &crate::adaptive_buffer::AdaptiveBufferTracker,
    tcp_fastopen: bool,
    msg_zerocopy_enabled: bool,
    ktls_enabled: bool,
    io_uring_splice_enabled: bool,
) -> Result<TcpConnectionSuccess, anyhow::Error> {
    // --- SNI-based proxy resolution for shared passthrough ports ---
    // When multiple passthrough proxies share a listen_port, we must peek at
    // the ClientHello to extract SNI before looking up the proxy config.
    let _resolved_proxy_id: Option<String>;
    let proxy_id = if let Some(sni_ids) = sni_proxy_ids {
        let sni = super::sni::extract_sni_from_tcp_stream(&client_stream).await;
        stream_ctx.sni_hostname = sni.clone();

        let current_config = config.load();
        let matched = super::sni::resolve_proxy_by_sni(sni.as_deref(), sni_ids, &current_config)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No matching passthrough proxy for SNI {:?} on port {}",
                    sni,
                    stream_ctx.listen_port
                )
            })?;
        _resolved_proxy_id = Some(matched.to_string());
        // Update stream_ctx to reflect the resolved proxy
        stream_ctx.proxy_id = matched.to_string();
        stream_ctx.proxy_name = current_config
            .proxies
            .iter()
            .find(|p| p.id == matched)
            .and_then(|p| p.name.clone());
        _resolved_proxy_id.as_deref().unwrap_or(proxy_id)
    } else {
        _resolved_proxy_id = None;
        proxy_id
    };

    // Look up the proxy config and extract only the fields we need.
    // The ArcSwap guard (and full Proxy) is dropped before any async work.
    let (params, cb_info) = {
        let current_config = config.load();
        let proxy = current_config
            .proxies
            .iter()
            .find(|p| p.id == proxy_id)
            .ok_or_else(|| anyhow::anyhow!("Proxy {} not found in config", proxy_id))?;

        let (backend_host, backend_port) = resolve_backend_target(proxy, lb_cache)?;

        // Populate backend target as soon as it's known — even if DNS or connect fails,
        // the log will show which target was attempted.
        backend_info.backend_target = format!("{}:{}", backend_host, backend_port);

        let cb_target_key = proxy
            .upstream_id
            .as_ref()
            .map(|_| crate::circuit_breaker::target_key(&backend_host, backend_port));

        let cb_info = TcpConnCbInfo {
            cb_config: proxy.circuit_breaker.clone(),
            cb_target_key,
        };

        let params = TcpConnParams {
            backend_host,
            backend_port,
            backend_protocol: proxy.backend_protocol,
            dns_override: proxy.dns_override.clone(),
            dns_cache_ttl_seconds: proxy.dns_cache_ttl_seconds,
            backend_connect_timeout_ms: proxy.backend_connect_timeout_ms,
            tcp_idle_timeout_seconds: proxy
                .tcp_idle_timeout_seconds
                .unwrap_or(global_tcp_idle_timeout),
            retry: proxy.retry.clone(),
            upstream_id: proxy.upstream_id.clone(),
            passthrough: proxy.passthrough,
            tcp_fastopen_enabled: tcp_fastopen,
        };

        (params, cb_info)
    };

    // ----- Passthrough mode: forward encrypted bytes without TLS termination -----
    if params.passthrough {
        // Peek at the ClientHello to extract SNI for logging/routing.
        // Skip if already extracted during SNI-based proxy resolution above.
        if stream_ctx.sni_hostname.is_none() {
            stream_ctx.sni_hostname = super::sni::extract_sni_from_tcp_stream(&client_stream).await;
        }

        // Run on_stream_connect plugins (they see SNI but not decrypted data).
        if !plugins.is_empty() {
            for plugin in plugins {
                if let PluginResult::Reject { .. } = plugin.on_stream_connect(stream_ctx).await {
                    debug!(
                        proxy_id = %proxy_id,
                        client = %remote_addr.ip(),
                        sni = ?stream_ctx.sni_hostname,
                        "TCP passthrough connection rejected by plugin"
                    );
                    return Err(anyhow::anyhow!("Connection rejected by plugin"));
                }
            }
        }

        let connect_timeout = Duration::from_millis(params.backend_connect_timeout_ms);
        let idle_timeout = if params.tcp_idle_timeout_seconds > 0 {
            Some(Duration::from_secs(params.tcp_idle_timeout_seconds))
        } else {
            None
        };

        // Resolve backend IP via DNS
        let resolved_ip = dns_cache
            .resolve(
                &params.backend_host,
                params.dns_override.as_deref(),
                params.dns_cache_ttl_seconds,
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!("DNS resolution failed for {}: {}", params.backend_host, e)
            })?;
        let addr = SocketAddr::new(resolved_ip, params.backend_port);
        backend_info.backend_resolved_ip = Some(resolved_ip.to_string());

        // Connect plain TCP to backend (no TLS origination — the client's encrypted
        // stream passes through directly to the backend which terminates TLS).
        let backend_stream =
            connect_backend_plain(addr, connect_timeout, params.tcp_fastopen_enabled)
                .await
                .inspect_err(|_| {
                    if let Some(ref cb_config) = cb_info.cb_config {
                        let cb = circuit_breaker_cache.get_or_create(
                            proxy_id,
                            cb_info.cb_target_key.as_deref(),
                            cb_config,
                        );
                        cb.record_failure(502, true);
                    }
                })?;

        let buf_size = adaptive_buffer.get_buffer_size(proxy_id);

        // Apply MSG_ZEROCOPY on the backend socket for large sends (Linux 4.14+).
        #[cfg(target_os = "linux")]
        if msg_zerocopy_enabled {
            use std::os::unix::io::AsRawFd;
            let _ = crate::socket_opts::set_so_zerocopy(backend_stream.as_raw_fd(), true);
        }

        // On Linux, use splice(2) for zero-copy relay between raw TCP sockets.
        // Passthrough mode is always plain-to-plain (no TLS termination/origination).
        // When io_uring is enabled, use IORING_OP_SPLICE on dedicated blocking threads.
        #[cfg(target_os = "linux")]
        let copy_result = if io_uring_splice_enabled {
            bidirectional_splice_io_uring(client_stream, backend_stream, idle_timeout, buf_size)
                .await
        } else {
            bidirectional_splice(client_stream, backend_stream, idle_timeout, buf_size).await
        };
        #[cfg(not(target_os = "linux"))]
        let copy_result =
            bidirectional_copy(client_stream, backend_stream, idle_timeout, buf_size).await;

        if let Ok((c2b, b2c)) = &copy_result {
            adaptive_buffer.record_connection(proxy_id, c2b.saturating_add(*b2c));
        }

        // Record circuit breaker outcome.
        if let Some(ref cb_config) = cb_info.cb_config {
            let cb = circuit_breaker_cache.get_or_create(
                proxy_id,
                cb_info.cb_target_key.as_deref(),
                cb_config,
            );
            match &copy_result {
                Ok(_) => cb.record_success(),
                Err(_) => cb.record_failure(502, true),
            }
        }

        return copy_result.map(|(bytes_in, bytes_out)| TcpConnectionSuccess {
            bytes_in,
            bytes_out,
            duration: start.elapsed(),
            splice_used: cfg!(target_os = "linux"),
        });
    }

    let is_backend_tls = params.backend_protocol == BackendProtocol::TcpTls;
    let connect_timeout = Duration::from_millis(params.backend_connect_timeout_ms);
    let idle_timeout = if params.tcp_idle_timeout_seconds > 0 {
        Some(Duration::from_secs(params.tcp_idle_timeout_seconds))
    } else {
        None
    };

    // For non-TLS proxies, run on_stream_connect plugins before backend connection.
    // TLS proxies defer this until after the TLS handshake so client cert is available.
    if frontend_tls_config.is_none() && !plugins.is_empty() {
        for plugin in plugins {
            if let PluginResult::Reject { .. } = plugin.on_stream_connect(stream_ctx).await {
                debug!(
                    proxy_id = %proxy_id,
                    client = %remote_addr.ip(),
                    "TCP connection rejected by plugin"
                );
                return Err(anyhow::anyhow!("Connection rejected by plugin"));
            }
        }
    }

    // Helper: record circuit breaker failure for the current target.
    let record_cb_failure = |cb_cache: &CircuitBreakerCache,
                             proxy_id: &str,
                             cb_info: &TcpConnCbInfo| {
        if let Some(ref cb_config) = cb_info.cb_config {
            let cb = cb_cache.get_or_create(proxy_id, cb_info.cb_target_key.as_deref(), cb_config);
            cb.record_failure(502, true);
        }
    };

    // Connection-phase retry loop. Retries DNS resolution + backend connect
    // with a different load-balanced target on each attempt. Once a backend
    // connection is established, bidirectional_copy begins and no further
    // retries are possible (bytes may have been exchanged).
    let can_retry = params
        .retry
        .as_ref()
        .is_some_and(|r| r.retry_on_connect_failure);
    let max_retries = params.retry.as_ref().map(|r| r.max_retries).unwrap_or(0);
    let mut current_host = params.backend_host.clone();
    let mut current_port = params.backend_port;
    let mut current_cb_info = cb_info;
    let mut last_connect_err: Option<anyhow::Error> = None;

    let mut attempt = 0u32;
    let backend_addr = loop {
        // Circuit breaker check — reject before attempting backend connection if open.
        if let Some(ref cb_config) = current_cb_info.cb_config
            && circuit_breaker_cache
                .can_execute(
                    proxy_id,
                    current_cb_info.cb_target_key.as_deref(),
                    cb_config,
                )
                .is_err()
        {
            if can_retry && attempt < max_retries {
                // Circuit open on this target — try another
                if let Some(next) = try_next_target(&params, &current_host, current_port, lb_cache)
                {
                    warn!(
                        proxy_id = %proxy_id,
                        attempt,
                        "TCP circuit breaker open for {}:{}, trying {}:{}",
                        current_host, current_port, next.0, next.1
                    );
                    current_host = next.0;
                    current_port = next.1;
                    current_cb_info = TcpConnCbInfo {
                        cb_config: current_cb_info.cb_config.clone(),
                        cb_target_key: params.upstream_id.as_ref().map(|_| {
                            crate::circuit_breaker::target_key(&current_host, current_port)
                        }),
                    };
                    // Update backend info to reflect the retry target.
                    backend_info.backend_target = format!("{}:{}", current_host, current_port);
                    backend_info.backend_resolved_ip = None;
                    attempt += 1;
                    continue;
                }
            }
            warn!(proxy_id = %proxy_id, client = %remote_addr, "TCP connection rejected: circuit breaker open");
            return Err(anyhow::anyhow!("circuit breaker open"));
        }

        // Resolve backend IP via DNS
        let resolved_ip = match dns_cache
            .resolve(
                &current_host,
                params.dns_override.as_deref(),
                params.dns_cache_ttl_seconds,
            )
            .await
        {
            Ok(ip) => ip,
            Err(e) => {
                record_cb_failure(circuit_breaker_cache, proxy_id, &current_cb_info);
                let err_msg = format!("DNS resolution failed for {}: {}", current_host, e);
                if can_retry
                    && attempt < max_retries
                    && let Some(next) =
                        try_next_target(&params, &current_host, current_port, lb_cache)
                {
                    warn!(
                        proxy_id = %proxy_id,
                        attempt,
                        "TCP DNS failed for {}:{}, retrying with {}:{}",
                        current_host, current_port, next.0, next.1
                    );
                    current_host = next.0;
                    current_port = next.1;
                    current_cb_info = TcpConnCbInfo {
                        cb_config: current_cb_info.cb_config.clone(),
                        cb_target_key: params.upstream_id.as_ref().map(|_| {
                            crate::circuit_breaker::target_key(&current_host, current_port)
                        }),
                    };
                    // Update backend info to reflect the retry target.
                    backend_info.backend_target = format!("{}:{}", current_host, current_port);
                    backend_info.backend_resolved_ip = None;
                    last_connect_err = Some(anyhow::anyhow!(err_msg));
                    attempt += 1;
                    if let Some(ref retry_config) = params.retry {
                        tokio::time::sleep(crate::retry::retry_delay(retry_config, attempt)).await;
                    }
                    continue;
                }
                return Err(anyhow::anyhow!(err_msg));
            }
        };
        let addr = SocketAddr::new(resolved_ip, current_port);
        // DNS succeeded — record the resolved IP for logging.
        backend_info.backend_resolved_ip = Some(resolved_ip.to_string());

        // Attempt backend TCP connection (with optional TLS origination)
        let connect_result = if is_backend_tls {
            connect_backend_tls_cached(
                addr,
                &current_host,
                connect_timeout,
                cached_backend_tls,
                params.tcp_fastopen_enabled,
            )
            .await
            .map(|s| BackendStream::Tls(Box::new(s)))
        } else {
            connect_backend_plain(addr, connect_timeout, params.tcp_fastopen_enabled)
                .await
                .map(BackendStream::Plain)
        };

        match connect_result {
            Ok(_stream) => {
                // Connection succeeded — break out of retry loop with the address.
                // We pass the stream via BackendStream enum below.
                break (addr, _stream);
            }
            Err(e) => {
                record_cb_failure(circuit_breaker_cache, proxy_id, &current_cb_info);
                if can_retry
                    && attempt < max_retries
                    && let Some(next) =
                        try_next_target(&params, &current_host, current_port, lb_cache)
                {
                    warn!(
                        proxy_id = %proxy_id,
                        attempt,
                        error = %e,
                        "TCP connect failed to {}:{}, retrying with {}:{}",
                        current_host, current_port, next.0, next.1
                    );
                    current_host = next.0;
                    current_port = next.1;
                    current_cb_info = TcpConnCbInfo {
                        cb_config: current_cb_info.cb_config.clone(),
                        cb_target_key: params.upstream_id.as_ref().map(|_| {
                            crate::circuit_breaker::target_key(&current_host, current_port)
                        }),
                    };
                    // Update backend info to reflect the retry target.
                    backend_info.backend_target = format!("{}:{}", current_host, current_port);
                    backend_info.backend_resolved_ip = None;
                    last_connect_err = Some(e);
                    attempt += 1;
                    if let Some(ref retry_config) = params.retry {
                        tokio::time::sleep(crate::retry::retry_delay(retry_config, attempt)).await;
                    }
                    continue;
                }
                return Err(e);
            }
        }
    };
    let (_backend_socket_addr, backend_stream) = backend_addr;
    let _ = last_connect_err; // consumed by retry loop logging

    // Apply MSG_ZEROCOPY on the backend socket for large sends (Linux 4.14+).
    #[cfg(target_os = "linux")]
    if msg_zerocopy_enabled {
        use std::os::unix::io::AsRawFd;
        match &backend_stream {
            BackendStream::Plain(s) => {
                let _ = crate::socket_opts::set_so_zerocopy(s.as_raw_fd(), true);
            }
            BackendStream::Tls(_) => {} // TLS stream wraps the fd; zerocopy on raw fd won't help
        }
    }

    // Apply frontend TLS termination if configured, then start bidirectional copy.
    // From here, no retries — bytes may be exchanged.
    let mut used_splice = false;
    let copy_result = if let Some(tls_config) = frontend_tls_config {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.clone());
        let tls_stream = match acceptor.accept(client_stream).await {
            Ok(s) => s,
            Err(e) => {
                // Frontend TLS failures are client-side — do not penalise the backend CB.
                return Err(anyhow::anyhow!(
                    "Frontend TLS handshake failed from {}: {}",
                    remote_addr,
                    e
                ));
            }
        };

        // Extract peer certificate DER from TLS handshake for plugin use.
        let peer_chain_der = tls_stream.get_ref().1.peer_certificates().map(|certs| {
            certs
                .iter()
                .map(|cert| cert.to_vec())
                .collect::<Vec<Vec<u8>>>()
        });
        let peer_cert_der = peer_chain_der
            .as_ref()
            .and_then(|certs| certs.first().cloned())
            .map(Arc::new);
        let peer_chain_tail_der = peer_chain_der.and_then(|mut certs| {
            if certs.len() <= 1 {
                None
            } else {
                certs.remove(0);
                Some(Arc::new(certs))
            }
        });
        stream_ctx.tls_client_cert_der = peer_cert_der;
        stream_ctx.tls_client_cert_chain_der = peer_chain_tail_der;

        // Run on_stream_connect plugins after TLS handshake so client cert is available.
        if !plugins.is_empty() {
            for plugin in plugins {
                if let PluginResult::Reject { .. } = plugin.on_stream_connect(stream_ctx).await {
                    debug!(
                        proxy_id = %proxy_id,
                        client = %remote_addr.ip(),
                        "TCP/TLS connection rejected by plugin"
                    );
                    return Err(anyhow::anyhow!("Connection rejected by plugin"));
                }
            }
        }

        let buf_size = adaptive_buffer.get_buffer_size(proxy_id);
        match backend_stream {
            BackendStream::Tls(bs) => {
                bidirectional_copy(tls_stream, bs, idle_timeout, buf_size).await
            }
            BackendStream::Plain(bs) => {
                // On Linux with kTLS, attempt to install TLS keys into the kernel
                // so splice(2) can handle encrypted traffic without userspace copies.
                #[cfg(target_os = "linux")]
                {
                    if ktls_enabled {
                        match try_ktls_splice(tls_stream, bs, idle_timeout, buf_size).await {
                            Ok(result) => {
                                used_splice = true;
                                Ok(result)
                            }
                            Err(KtlsError::Unsupported(tls_stream_back, bs_back)) => {
                                // kTLS not available for this cipher/version — fall back
                                // to userspace copy with the TLS stream intact.
                                bidirectional_copy(tls_stream_back, bs_back, idle_timeout, buf_size)
                                    .await
                            }
                            Err(KtlsError::Installed(e)) => {
                                // kTLS keys were installed but splice failed — connection
                                // is consumed, propagate the error.
                                Err(e)
                            }
                        }
                    } else {
                        bidirectional_copy(tls_stream, bs, idle_timeout, buf_size).await
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    bidirectional_copy(tls_stream, bs, idle_timeout, buf_size).await
                }
            }
        }
    } else {
        let buf_size = adaptive_buffer.get_buffer_size(proxy_id);
        match backend_stream {
            BackendStream::Tls(bs) => {
                used_splice = false;
                bidirectional_copy(client_stream, bs, idle_timeout, buf_size).await
            }
            BackendStream::Plain(bs) => {
                // On Linux, use splice(2) for zero-copy relay when both sides
                // are raw TCP (no frontend TLS, no backend TLS).
                // When io_uring is enabled, use IORING_OP_SPLICE on blocking threads.
                #[cfg(target_os = "linux")]
                {
                    used_splice = true;
                    if io_uring_splice_enabled {
                        bidirectional_splice_io_uring(client_stream, bs, idle_timeout, buf_size)
                            .await
                    } else {
                        bidirectional_splice(client_stream, bs, idle_timeout, buf_size).await
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    used_splice = false;
                    bidirectional_copy(client_stream, bs, idle_timeout, buf_size).await
                }
            }
        }
    };

    // Record adaptive buffer stats for the TLS/non-passthrough path.
    if let Ok((c2b, b2c)) = &copy_result {
        adaptive_buffer.record_connection(proxy_id, c2b.saturating_add(*b2c));
    }

    // Record circuit breaker outcome based on copy result.
    if let Some(ref cb_config) = current_cb_info.cb_config {
        let cb = circuit_breaker_cache.get_or_create(
            proxy_id,
            current_cb_info.cb_target_key.as_deref(),
            cb_config,
        );
        match &copy_result {
            Ok(_) => cb.record_success(),
            Err(_) => cb.record_failure(502, true),
        }
    }

    copy_result.map(|(bytes_in, bytes_out)| TcpConnectionSuccess {
        bytes_in,
        bytes_out,
        duration: start.elapsed(),
        splice_used: used_splice,
    })
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

/// Backend stream type for the connection-phase retry loop.
/// Wraps either a plain TCP or TLS stream so the retry loop can return
/// a single type regardless of backend TLS configuration.
enum BackendStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// Try to select a different upstream target for retry, excluding the current one.
/// Returns `None` if no upstream is configured or no alternate target is available.
fn try_next_target(
    params: &TcpConnParams,
    current_host: &str,
    current_port: u16,
    lb_cache: &LoadBalancerCache,
) -> Option<(String, u16)> {
    let upstream_id = params.upstream_id.as_ref()?;
    let exclude = crate::config::types::UpstreamTarget {
        host: current_host.to_string(),
        port: current_port,
        weight: 1,
        path: None,
        tags: std::collections::HashMap::new(),
    };
    let next = lb_cache.select_next_target(upstream_id, current_host, &exclude, None)?;
    Some((next.host.clone(), next.port))
}

/// Connect to a plain TCP backend with the given connect timeout.
///
/// On Linux, applies `IP_BIND_ADDRESS_NO_PORT` (defers ephemeral port allocation
/// to connect() for better 4-tuple distribution) and `TCP_FASTOPEN_CONNECT`
/// (saves 1 RTT on repeat connections) when `tcp_fastopen` is true.
async fn connect_backend_plain(
    addr: SocketAddr,
    connect_timeout: Duration,
    _tcp_fastopen: bool,
) -> Result<TcpStream, anyhow::Error> {
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("Backend connect timeout to {}", addr))?
        .map_err(|e| anyhow::anyhow!("Backend connect failed to {}: {}", addr, e))?;
    let _ = stream.set_nodelay(true);

    // Apply Linux/Unix socket optimizations on the connected socket.
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        // IP_BIND_ADDRESS_NO_PORT: defer ephemeral port allocation to connect(),
        // enabling 4-tuple co-selection to prevent port exhaustion at high rates.
        let _ = crate::socket_opts::set_ip_bind_address_no_port(fd, true);
        if _tcp_fastopen {
            // TCP_FASTOPEN_CONNECT: send data in SYN on repeat connections (1 RTT saved).
            let _ = crate::socket_opts::set_tcp_fastopen_client(fd);
        }
    }

    Ok(stream)
}

/// Connect to a TLS-enabled backend using the cached TLS config when available.
/// Falls back to building the config from disk if no cache is provided.
async fn connect_backend_tls_cached(
    addr: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    cached_tls: Option<&CachedBackendTlsConfig>,
    tcp_fastopen: bool,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, anyhow::Error> {
    let tcp_stream = connect_backend_plain(addr, connect_timeout, tcp_fastopen).await?;

    let tls_config = cached_tls
        .map(|c| c.config.clone())
        .ok_or_else(|| anyhow::anyhow!("Backend TLS config not available for {}", addr))?;

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
///
/// When `idle_timeout` is `Some(d)` and non-zero, the connection is closed
/// if no data is received on either side for the given duration.
/// When `idle_timeout` is `None` or zero, uses the fast path with no overhead.
async fn bidirectional_copy<C, B>(
    mut client: C,
    mut backend: B,
    idle_timeout: Option<Duration>,
    buf_size: usize,
) -> Result<(u64, u64), anyhow::Error>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    match idle_timeout {
        Some(timeout) if !timeout.is_zero() => {
            let last_activity = Arc::new(AtomicU64::new(coarse_now_ms()));
            let mut tracked_client = IdleTrackingStream::new(client, last_activity.clone());
            let mut tracked_backend = IdleTrackingStream::new(backend, last_activity.clone());

            let copy_fut = tokio::io::copy_bidirectional_with_sizes(
                &mut tracked_client,
                &mut tracked_backend,
                buf_size,
                buf_size,
            );
            tokio::pin!(copy_fut);

            let idle_check = async {
                let timeout_ms = timeout.as_millis() as u64;
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let last = last_activity.load(Ordering::Relaxed);
                    if coarse_now_ms().saturating_sub(last) >= timeout_ms {
                        return;
                    }
                }
            };
            tokio::pin!(idle_check);

            tokio::select! {
                result = &mut copy_fut => {
                    result
                        .map_err(|e| anyhow::anyhow!("Bidirectional copy error: {}", e))
                }
                _ = &mut idle_check => {
                    Err(anyhow::anyhow!("TCP idle timeout after {}s", timeout.as_secs()))
                }
            }
        }
        _ => {
            // No idle timeout — fast path with zero overhead.
            tokio::io::copy_bidirectional_with_sizes(&mut client, &mut backend, buf_size, buf_size)
                .await
                .map_err(|e| anyhow::anyhow!("Bidirectional copy error: {}", e))
        }
    }
}

// ── Linux splice(2) zero-copy TCP relay ──────────────────────────────────────
//
// On Linux, splice(2) moves data between two file descriptors via a kernel-side
// pipe buffer without copying to userspace. This eliminates two memory copies
// per chunk (kernel→user read + user→kernel write) compared to the standard
// `copy_bidirectional` approach. Inspired by nginx's sendfile and HAProxy's
// splice-based TCP proxying.
//
// Only used when both endpoints are raw `TcpStream` (no TLS wrapping) — splice
// operates on OS-level file descriptors and cannot see through rustls encryption.
// Falls back to `bidirectional_copy` on non-Linux and for all TLS paths.

/// Bidirectional zero-copy relay between two raw TCP streams using Linux splice(2).
///
/// Creates a kernel pipe for each direction (client→backend, backend→client) and
/// uses `splice()` to move data through the pipe without userspace copies.
/// Returns (bytes_client_to_backend, bytes_backend_to_client).
///
/// Both directions run within a single task using `tokio::select!` instead of
/// spawning two separate tasks. This halves task overhead (creation, scheduling,
/// memory) per TCP connection. When one direction hits EOF, the other gets a brief
/// grace period to drain remaining data.
///
/// When `idle_timeout` is `Some(d)` and non-zero, the connection is closed
/// if no data is received on either side for the given duration.
#[cfg(target_os = "linux")]
async fn bidirectional_splice(
    client: TcpStream,
    backend: TcpStream,
    idle_timeout: Option<Duration>,
    pipe_size: usize,
) -> Result<(u64, u64), anyhow::Error> {
    use std::os::unix::io::AsRawFd;

    let client_fd = client.as_raw_fd();
    let backend_fd = backend.as_raw_fd();

    // Create two pipes: one for each direction. Guards close fds on drop.
    let (c2b_pipe_r, c2b_pipe_w) = create_splice_pipe(pipe_size)?;
    let _c2b_guard = SplicePipeGuard(c2b_pipe_r, c2b_pipe_w);
    let (b2c_pipe_r, b2c_pipe_w) = create_splice_pipe(pipe_size)?;
    let _b2c_guard = SplicePipeGuard(b2c_pipe_r, b2c_pipe_w);

    let last_activity = if idle_timeout.is_some_and(|t| !t.is_zero()) {
        Some(Arc::new(AtomicU64::new(coarse_now_ms())))
    } else {
        None
    };

    let la_c2b = last_activity.clone();
    let la_b2c = last_activity.clone();

    // Pin both direction futures for use with select! — no spawned tasks.
    let c2b_fut =
        splice_one_direction_no_guard(client_fd, c2b_pipe_w, c2b_pipe_r, backend_fd, la_c2b);
    let b2c_fut =
        splice_one_direction_no_guard(backend_fd, b2c_pipe_w, b2c_pipe_r, client_fd, la_b2c);
    tokio::pin!(c2b_fut);
    tokio::pin!(b2c_fut);

    let idle_timeout_active = idle_timeout.is_some_and(|t| !t.is_zero());

    // Run both directions concurrently in a single task.
    // When one finishes (EOF or error), give the other 100ms to drain.
    loop {
        if idle_timeout_active {
            let la = last_activity.as_ref().unwrap();
            let timeout_ms = idle_timeout.unwrap().as_millis() as u64;
            let last = la.load(Ordering::Relaxed);
            if coarse_now_ms().saturating_sub(last) >= timeout_ms {
                return Err(anyhow::anyhow!(
                    "TCP idle timeout after {}s",
                    idle_timeout.unwrap().as_secs()
                ));
            }
        }

        tokio::select! {
            c2b_result = &mut c2b_fut => {
                let c2b_bytes = c2b_result?;
                // Client→Backend done (EOF); wait for Backend→Client to finish
                // fully — the backend may still be sending response data after
                // the client closed its write half (half-closed TCP flows).
                let b2c_bytes = b2c_fut.await.unwrap_or(0);
                return Ok((c2b_bytes, b2c_bytes));
            }
            b2c_result = &mut b2c_fut => {
                let b2c_bytes = b2c_result?;
                // Backend→Client done (EOF); wait for Client→Backend to finish.
                let c2b_bytes = c2b_fut.await.unwrap_or(0);
                return Ok((c2b_bytes, b2c_bytes));
            }
            // Idle timeout check — wake every second.
            _ = tokio::time::sleep(Duration::from_secs(1)), if idle_timeout_active => {
                continue; // loop back to check idle timeout at top
            }
        }
    }
}

/// Bidirectional zero-copy relay using io_uring `IORING_OP_SPLICE`.
///
/// Each direction gets its own io_uring ring (8 entries) and runs on a
/// dedicated blocking thread via `tokio::task::spawn_blocking`. This avoids
/// the async yield_now polling loop used by the libc splice path and reduces
/// per-operation syscall overhead.
///
/// The caller must keep `client` and `backend` alive until this function
/// returns (they own the fds that the blocking threads use).
#[cfg(target_os = "linux")]
async fn bidirectional_splice_io_uring(
    client: TcpStream,
    backend: TcpStream,
    idle_timeout: Option<Duration>,
    pipe_size: usize,
) -> Result<(u64, u64), anyhow::Error> {
    use std::os::unix::io::AsRawFd;

    let client_fd = client.as_raw_fd();
    let backend_fd = backend.as_raw_fd();

    // Create pipes — managed manually since spawn_blocking captures fd ints.
    let (c2b_pipe_r, c2b_pipe_w) = create_splice_pipe(pipe_size)?;
    let (b2c_pipe_r, b2c_pipe_w) = create_splice_pipe(pipe_size)?;

    let timeout_ms = idle_timeout
        .filter(|t| !t.is_zero())
        .map(|t| t.as_millis() as u64)
        .unwrap_or(0);

    // Each direction runs on its own blocking thread with its own io_uring ring.
    let c2b_handle = tokio::task::spawn_blocking(move || {
        io_uring_splice_direction(client_fd, c2b_pipe_w, c2b_pipe_r, backend_fd, timeout_ms)
    });
    let b2c_handle = tokio::task::spawn_blocking(move || {
        io_uring_splice_direction(backend_fd, b2c_pipe_w, b2c_pipe_r, client_fd, timeout_ms)
    });

    // Wait for both directions. Streams stay alive on this task's stack.
    let (c2b_result, b2c_result) = tokio::join!(c2b_handle, b2c_handle);

    // Close pipes after both directions complete.
    unsafe {
        libc::close(c2b_pipe_r);
        libc::close(c2b_pipe_w);
        libc::close(b2c_pipe_r);
        libc::close(b2c_pipe_w);
    }

    // Keep streams alive until pipes are closed.
    let _ = (&client, &backend);

    let c2b = c2b_result.map_err(|e| anyhow::anyhow!("io_uring splice spawn error: {}", e))??;
    let b2c = b2c_result.map_err(|e| anyhow::anyhow!("io_uring splice spawn error: {}", e))??;
    Ok((c2b, b2c))
}

/// Run the io_uring splice loop for one direction on a blocking thread.
///
/// Falls back to libc::splice if io_uring ring creation fails (memlock
/// pressure, resource limits). The idle timeout is checked inline inside
/// the io_uring loop to prevent indefinite blocking on idle connections.
#[cfg(target_os = "linux")]
fn io_uring_splice_direction(
    src_fd: i32,
    pipe_w: i32,
    pipe_r: i32,
    dst_fd: i32,
    timeout_ms: u64,
) -> Result<u64, anyhow::Error> {
    let start_ms = coarse_now_ms();
    match crate::socket_opts::io_uring_splice::io_uring_splice_loop(
        src_fd, pipe_w, pipe_r, dst_fd, start_ms, timeout_ms,
    ) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            // io_uring ring creation failed — fall back to libc::splice.
            // This can happen under memlock pressure even though startup
            // probing succeeded.
            tracing::debug!("io_uring ring creation failed, falling back to libc splice");
            libc_splice_loop(src_fd, pipe_w, pipe_r, dst_fd, timeout_ms)
        }
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            Err(anyhow::anyhow!("TCP idle timeout (io_uring splice)"))
        }
        Err(e) => Err(anyhow::anyhow!("io_uring splice error: {}", e)),
    }
}

/// Fallback libc::splice loop for when io_uring ring creation fails.
/// Same logic as `splice_one_direction_no_guard` but synchronous (runs
/// on a blocking thread).
#[cfg(target_os = "linux")]
fn libc_splice_loop(
    src_fd: i32,
    pipe_w: i32,
    pipe_r: i32,
    dst_fd: i32,
    timeout_ms: u64,
) -> Result<u64, anyhow::Error> {
    let start_ms = coarse_now_ms();
    let splice_flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;
    let mut total: u64 = 0;

    loop {
        if timeout_ms > 0 && coarse_now_ms().saturating_sub(start_ms) >= timeout_ms {
            return Err(anyhow::anyhow!("TCP idle timeout (libc splice fallback)"));
        }

        let n = unsafe {
            libc::splice(
                src_fd,
                std::ptr::null_mut(),
                pipe_w,
                std::ptr::null_mut(),
                128 * 1024,
                splice_flags,
            )
        };

        if n > 0 {
            let mut remaining = n as usize;
            while remaining > 0 {
                let written = unsafe {
                    libc::splice(
                        pipe_r,
                        std::ptr::null_mut(),
                        dst_fd,
                        std::ptr::null_mut(),
                        remaining,
                        splice_flags,
                    )
                };
                if written > 0 {
                    remaining -= written as usize;
                    total += written as u64;
                } else if written == 0 {
                    return Ok(total);
                } else {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                    return Err(anyhow::anyhow!("splice write error: {}", err));
                }
            }
        } else if n == 0 {
            return Ok(total);
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            return Err(anyhow::anyhow!("splice read error: {}", err));
        }
    }
}

/// Create a pipe suitable for splice, sized to match the proxy buffer tier.
#[cfg(target_os = "linux")]
fn create_splice_pipe(desired_size: usize) -> Result<(i32, i32), anyhow::Error> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create splice pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Try to resize the pipe to match the adaptive buffer tier.
    // Failures are non-fatal — the kernel default (64 KB on most systems) is fine.
    unsafe {
        libc::fcntl(fds[1], libc::F_SETPIPE_SZ, desired_size as libc::c_int);
    }
    Ok((fds[0], fds[1]))
}

/// Splice data in one direction: src_fd → pipe → dst_fd.
/// Returns total bytes transferred. Pipe fds are managed by the caller's
/// `SplicePipeGuard` — this function does not close them.
#[cfg(target_os = "linux")]
async fn splice_one_direction_no_guard(
    src_fd: i32,
    pipe_w: i32,
    pipe_r: i32,
    dst_fd: i32,
    last_activity: Option<Arc<AtomicU64>>,
) -> Result<u64, anyhow::Error> {
    let mut total: u64 = 0;
    let splice_flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;

    loop {
        // Phase 1: splice from source fd into write end of pipe
        let n = unsafe {
            libc::splice(
                src_fd,
                std::ptr::null_mut(),
                pipe_w,
                std::ptr::null_mut(),
                // Use 128 KB per splice call — large enough to amortize syscall
                // overhead, small enough to avoid holding the pipe buffer too long.
                128 * 1024,
                splice_flags,
            )
        };

        if n > 0 {
            if let Some(ref la) = last_activity {
                la.store(coarse_now_ms(), Ordering::Relaxed);
            }

            // Phase 2: splice from read end of pipe into destination fd
            let mut remaining = n as usize;
            while remaining > 0 {
                let written = unsafe {
                    libc::splice(
                        pipe_r,
                        std::ptr::null_mut(),
                        dst_fd,
                        std::ptr::null_mut(),
                        remaining,
                        splice_flags,
                    )
                };
                if written > 0 {
                    remaining -= written as usize;
                    total += written as u64;
                } else if written == 0 {
                    return Ok(total);
                } else {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        // Destination not ready — yield and retry
                        tokio::task::yield_now().await;
                        continue;
                    }
                    return Err(anyhow::anyhow!("splice write error: {}", err));
                }
            }
        } else if n == 0 {
            // EOF — source closed
            return Ok(total);
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                // Source not ready — yield and retry
                tokio::task::yield_now().await;
                continue;
            }
            return Err(anyhow::anyhow!("splice read error: {}", err));
        }
    }
}

/// RAII guard that closes pipe file descriptors on drop.
#[cfg(target_os = "linux")]
struct SplicePipeGuard(i32, i32);

#[cfg(target_os = "linux")]
impl Drop for SplicePipeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
            libc::close(self.1);
        }
    }
}

/// Returns the current time as milliseconds since the Unix epoch.
/// Used for coarse idle tracking — does not need sub-millisecond precision.
fn coarse_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Wraps an `AsyncRead + AsyncWrite` stream, updating a shared timestamp
/// whenever bytes are successfully read. Used for idle connection detection.
///
/// Only reads are tracked: bidirectional data flow means a read on either
/// side (client or backend) indicates the connection is actively in use.
struct IdleTrackingStream<S> {
    inner: S,
    last_activity: Arc<AtomicU64>,
}

impl<S> IdleTrackingStream<S> {
    fn new(inner: S, last_activity: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            last_activity,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTrackingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result
            && buf.filled().len() > before
        {
            this.last_activity.store(coarse_now_ms(), Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTrackingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// kTLS support: install TLS session keys into the kernel so splice(2) works
// on encrypted TCP connections (Linux 4.13+).
// ---------------------------------------------------------------------------

/// Error type for the kTLS attempt. Distinguishes between pre-install failures
/// (where the TLS stream is still usable) and post-install failures (where the
/// connection is consumed and cannot be recovered).
#[cfg(target_os = "linux")]
enum KtlsError {
    /// kTLS could not be installed (unsupported cipher, wrong TLS version, etc.).
    /// The original streams are returned so the caller can fall back to userspace copy.
    Unsupported(tokio_rustls::server::TlsStream<TcpStream>, TcpStream),
    /// kTLS keys were installed into the kernel but the subsequent splice failed.
    /// The TLS stream has been consumed (into_inner + dangerous_extract_secrets)
    /// so there is no way to recover — propagate the error.
    Installed(anyhow::Error),
}

/// Attempt kTLS-accelerated splice for a frontend-TLS + plain-backend connection.
///
/// 1. Check that the negotiated cipher is AES-128-GCM or AES-256-GCM.
/// 2. Extract TLS session keys via `dangerous_extract_secrets()`.
/// 3. Install keys into the kernel via `enable_ktls()`.
/// 4. Use `bidirectional_splice()` for zero-copy relay.
///
/// Returns `KtlsError::Unsupported` with the original streams if kTLS cannot
/// be used, allowing the caller to fall back to userspace `bidirectional_copy`.
#[cfg(target_os = "linux")]
async fn try_ktls_splice(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    backend_stream: TcpStream,
    idle_timeout: Option<Duration>,
    buf_size: usize,
) -> Result<(u64, u64), KtlsError> {
    use std::os::unix::io::AsRawFd;

    // Check cipher suite compatibility before consuming the TLS stream.
    let cipher_ok = {
        let (_, server_conn) = tls_stream.get_ref();
        match server_conn.negotiated_cipher_suite() {
            Some(suite) => {
                let name = format!("{:?}", suite.suite());
                name.contains("AES_128_GCM") || name.contains("AES_256_GCM")
            }
            None => false,
        }
    };

    if !cipher_ok {
        debug!("kTLS: unsupported cipher suite, falling back to userspace copy");
        return Err(KtlsError::Unsupported(tls_stream, backend_stream));
    }

    // Check TLS version — kTLS supports TLS 1.2 and 1.3.
    let tls_version = {
        let (_, server_conn) = tls_stream.get_ref();
        server_conn.protocol_version()
    };
    let tls_ver_u16 = match tls_version {
        Some(rustls::ProtocolVersion::TLSv1_2) => 0x0303_u16,
        Some(rustls::ProtocolVersion::TLSv1_3) => 0x0304_u16,
        _ => {
            debug!(
                "kTLS: unsupported TLS version {:?}, falling back",
                tls_version
            );
            return Err(KtlsError::Unsupported(tls_stream, backend_stream));
        }
    };

    // Pre-flight: probe TCP_ULP installation on the raw fd BEFORE consuming
    // the TLS stream. If the kernel doesn't support kTLS (ENOPROTOOPT), we
    // can still fall back with the TLS stream intact.
    {
        let (tcp_ref, _) = tls_stream.get_ref();
        let fd = tcp_ref.as_raw_fd();
        let ulp_name = b"tls\0";
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_ULP,
                ulp_name.as_ptr() as *const libc::c_void,
                ulp_name.len() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            debug!("kTLS: TCP_ULP probe failed ({}), falling back", err);
            return Err(KtlsError::Unsupported(tls_stream, backend_stream));
        }
        // TCP_ULP installed successfully — kTLS is available on this socket.
        // Proceed to extract secrets (point of no return after this block).
    }

    // Point of no return: consume the TLS stream to extract secrets.
    // TCP_ULP is already installed on the underlying fd, so kTLS key
    // installation should succeed.
    let (tcp_stream, server_conn) = tls_stream.into_inner();

    let secrets = match server_conn.dangerous_extract_secrets() {
        Ok(s) => s,
        Err(e) => {
            warn!("kTLS: failed to extract TLS secrets: {}", e);
            return Err(KtlsError::Installed(anyhow::anyhow!(
                "kTLS secret extraction failed: {}",
                e
            )));
        }
    };

    // Map rustls secrets to kTLS parameters.
    let params = match build_ktls_params(tls_ver_u16, &secrets) {
        Some(p) => p,
        None => {
            warn!("kTLS: cipher not mappable to kTLS params");
            return Err(KtlsError::Installed(anyhow::anyhow!(
                "kTLS: unsupported cipher in extracted secrets"
            )));
        }
    };

    // Install kTLS on the raw TCP socket.
    let fd = tcp_stream.as_raw_fd();
    match crate::socket_opts::ktls::enable_ktls(fd, &params) {
        Ok(true) => {
            debug!("kTLS installed successfully, using splice for TLS connection");
            bidirectional_splice(tcp_stream, backend_stream, idle_timeout, buf_size)
                .await
                .map_err(KtlsError::Installed)
        }
        Ok(false) => {
            // Kernel doesn't support kTLS (ENOPROTOOPT) — but we already consumed
            // the TLS stream so we cannot recover.
            warn!("kTLS: kernel returned ENOPROTOOPT after secret extraction");
            Err(KtlsError::Installed(anyhow::anyhow!(
                "kTLS not supported by kernel after secret extraction"
            )))
        }
        Err(e) => {
            warn!("kTLS: setsockopt failed: {}", e);
            Err(KtlsError::Installed(anyhow::anyhow!(
                "kTLS setsockopt failed: {}",
                e
            )))
        }
    }
}

/// Map rustls `ExtractedSecrets` to `KtlsParams` for the kernel TLS ULP.
///
/// Returns `None` if the cipher suite is not AES-128-GCM or AES-256-GCM.
#[cfg(target_os = "linux")]
fn build_ktls_params(
    tls_version: u16,
    secrets: &rustls::ExtractedSecrets,
) -> Option<crate::socket_opts::ktls::KtlsParams> {
    use crate::socket_opts::ktls::{KtlsCipher, KtlsParams};
    use rustls::ConnectionTrafficSecrets;

    let (tx_seq, ref tx_secrets) = secrets.tx;
    let (rx_seq, ref rx_secrets) = secrets.rx;

    let (cipher_suite, tx_key, tx_iv, rx_key, rx_iv) = match (tx_secrets, rx_secrets) {
        (
            ConnectionTrafficSecrets::Aes128Gcm { key: tk, iv: tiv },
            ConnectionTrafficSecrets::Aes128Gcm { key: rk, iv: riv },
        ) => (
            KtlsCipher::Aes128Gcm,
            tk.as_ref().to_vec(),
            tiv.as_ref().to_vec(),
            rk.as_ref().to_vec(),
            riv.as_ref().to_vec(),
        ),
        (
            ConnectionTrafficSecrets::Aes256Gcm { key: tk, iv: tiv },
            ConnectionTrafficSecrets::Aes256Gcm { key: rk, iv: riv },
        ) => (
            KtlsCipher::Aes256Gcm,
            tk.as_ref().to_vec(),
            tiv.as_ref().to_vec(),
            rk.as_ref().to_vec(),
            riv.as_ref().to_vec(),
        ),
        _ => return None,
    };

    Some(KtlsParams {
        tls_version,
        cipher_suite,
        tx_key,
        tx_iv,
        tx_seq: tx_seq.to_be_bytes(),
        rx_key,
        rx_iv,
        rx_seq: rx_seq.to_be_bytes(),
    })
}
