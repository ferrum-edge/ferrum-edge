//! Raw TCP stream proxy with optional TLS termination (frontend) and origination (backend).
//!
//! Each TCP proxy binds its own dedicated port. Incoming connections are
//! forwarded bidirectionally to the configured backend using
//! `tokio::io::copy_bidirectional` for optimal zero-copy throughput.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    Direction, PluginResult, ProxyProtocol, StreamConnectionContext, StreamTransactionSummary,
};
use crate::retry::ErrorClass;

pub(crate) fn classify_stream_error(error: &anyhow::Error) -> crate::retry::ErrorClass {
    crate::retry::classify_boxed_error(error.as_ref())
}

/// Outcome of a bidirectional stream copy between the client and backend.
///
/// Preserves per-direction byte counts even when one half errors — callers
/// use these to record metrics accurately regardless of which side failed.
/// `first_failure` is `Some((direction, class))` when a half errored before
/// both halves observed a clean EOF; `None` indicates graceful shutdown.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct StreamCopyResult {
    pub bytes_client_to_backend: u64,
    pub bytes_backend_to_client: u64,
    pub first_failure: Option<(Direction, ErrorClass)>,
}

/// Crate-visible entry point to `bidirectional_copy` for the `_test_support`
/// module. Exposed only so external integration/unit tests can exercise the
/// direction-tracking behavior without the private function being made `pub`.
///
/// Rustc's dead-code analysis cannot see through the generic instantiations in
/// the `_test_support` re-export (which is consumed by the integration/unit
/// test crates), so the allow is load-bearing — without it CI's `-D warnings`
/// clippy gate fails.
#[allow(dead_code)]
pub(crate) async fn bidirectional_copy_for_test<C, B>(
    client: C,
    backend: B,
    idle_timeout: Option<Duration>,
    buf_size: usize,
) -> StreamCopyResult
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    bidirectional_copy(client, backend, idle_timeout, buf_size).await
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
                                        ktls_enabled,
                        io_uring_splice_enabled,
                        &overload_for_conn,
                    )
                    .await;

                    let disconnected_at = chrono::Utc::now();
                    let duration_ms = (disconnected_at - connected_at).num_milliseconds().max(0) as f64;
                    let (
                        bytes_in,
                        bytes_out,
                        conn_error,
                        error_class,
                        disconnect_direction,
                        disconnect_cause,
                    ) = match &result.outcome {
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
                            // Bidirectional copy finished. If `first_failure` is
                            // set, one half errored before both halves observed
                            // a clean EOF — surface the real direction & class.
                            // Otherwise both halves hit EOF cleanly (graceful).
                            match &s.first_failure {
                                Some((dir, class)) => {
                                    let dir = *dir;
                                    let class = class.clone();
                                    let cause = match dir {
                                        Direction::ClientToBackend => {
                                            crate::plugins::DisconnectCause::RecvError
                                        }
                                        Direction::BackendToClient => {
                                            crate::plugins::DisconnectCause::BackendError
                                        }
                                        Direction::Unknown => {
                                            if class == ErrorClass::ReadWriteTimeout {
                                                crate::plugins::DisconnectCause::IdleTimeout
                                            } else {
                                                crate::plugins::DisconnectCause::RecvError
                                            }
                                        }
                                    };
                                    (
                                        s.bytes_in,
                                        s.bytes_out,
                                        Some(class.to_string()),
                                        Some(class),
                                        Some(dir),
                                        Some(cause),
                                    )
                                }
                                None => (
                                    s.bytes_in,
                                    s.bytes_out,
                                    None,
                                    None,
                                    None,
                                    Some(crate::plugins::DisconnectCause::GracefulShutdown),
                                ),
                            }
                        }
                        Err(e) => {
                            debug!(
                                proxy_id = %proxy_id,
                                client = %remote_addr.ip(),
                                error = %e,
                                "TCP connection error"
                            );
                            let error_message = e.to_string();
                            let err_class = classify_stream_error(e);
                            // Pre-copy error (DNS, connect, plugin reject, TLS
                            // handshake). No bytes flowed and direction can't
                            // be attributed to a specific half, so use Unknown.
                            (
                                0,
                                0,
                                Some(error_message),
                                Some(err_class),
                                Some(Direction::Unknown),
                                Some(crate::plugins::DisconnectCause::RecvError),
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
                            disconnect_direction,
                            disconnect_cause,
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
    /// `Some((direction, class))` when the bidirectional copy errored before
    /// both halves observed a clean EOF. `None` indicates a graceful shutdown.
    first_failure: Option<(Direction, ErrorClass)>,
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
    ktls_enabled: bool,
    io_uring_splice_enabled: bool,
    overload: &crate::overload::OverloadState,
) -> TcpConnectionResult {
    let start = Instant::now();
    let _ = client_stream.set_nodelay(true);

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
        ktls_enabled,
        io_uring_splice_enabled,
        overload,
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
    ktls_enabled: bool,
    io_uring_splice_enabled: bool,
    overload: &crate::overload::OverloadState,
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
            connect_backend_plain(addr, connect_timeout, params.tcp_fastopen_enabled, overload)
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

        adaptive_buffer.record_connection(
            proxy_id,
            copy_result
                .bytes_client_to_backend
                .saturating_add(copy_result.bytes_backend_to_client),
        );

        // Record circuit breaker outcome.
        if let Some(ref cb_config) = cb_info.cb_config {
            let cb = circuit_breaker_cache.get_or_create(
                proxy_id,
                cb_info.cb_target_key.as_deref(),
                cb_config,
            );
            if copy_result.first_failure.is_some() {
                cb.record_failure(502, true);
            } else {
                cb.record_success();
            }
        }

        return Ok(TcpConnectionSuccess {
            bytes_in: copy_result.bytes_client_to_backend,
            bytes_out: copy_result.bytes_backend_to_client,
            duration: start.elapsed(),
            splice_used: cfg!(target_os = "linux"),
            first_failure: copy_result.first_failure,
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
                overload,
            )
            .await
            .map(|s| BackendStream::Tls(Box::new(s)))
        } else {
            connect_backend_plain(addr, connect_timeout, params.tcp_fastopen_enabled, overload)
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
                            Err(KtlsError::Unsupported(streams)) => {
                                // kTLS not available for this cipher/version — fall back
                                // to userspace copy with the TLS stream intact.
                                let (tls_stream_back, bs_back) = *streams;
                                bidirectional_copy(tls_stream_back, bs_back, idle_timeout, buf_size)
                                    .await
                            }
                            Err(KtlsError::Installed(e)) => {
                                // Unrecoverable: TLS stream was consumed via into_inner()
                                // + dangerous_extract_secrets(). The raw TcpStream has no
                                // TLS layer — bidirectional_copy would forward plaintext.
                                // This path only triggers if SOL_TLS key install fails
                                // AFTER the pre-flight TCP_ULP probe succeeded (e.g.,
                                // kernel cipher mismatch or ENOMEM). In practice this is
                                // extremely rare since we validate cipher/version before
                                // extracting secrets.
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
    adaptive_buffer.record_connection(
        proxy_id,
        copy_result
            .bytes_client_to_backend
            .saturating_add(copy_result.bytes_backend_to_client),
    );

    // Record circuit breaker outcome based on copy result.
    if let Some(ref cb_config) = current_cb_info.cb_config {
        let cb = circuit_breaker_cache.get_or_create(
            proxy_id,
            current_cb_info.cb_target_key.as_deref(),
            cb_config,
        );
        if copy_result.first_failure.is_some() {
            cb.record_failure(502, true);
        } else {
            cb.record_success();
        }
    }

    Ok(TcpConnectionSuccess {
        bytes_in: copy_result.bytes_client_to_backend,
        bytes_out: copy_result.bytes_backend_to_client,
        duration: start.elapsed(),
        splice_used: used_splice,
        first_failure: copy_result.first_failure,
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
/// On Linux, applies `IP_BIND_ADDRESS_NO_PORT` and `TCP_FASTOPEN_CONNECT`
/// BEFORE `connect()` so they take effect on the connection attempt. These
/// must be set pre-connect: `IP_BIND_ADDRESS_NO_PORT` defers ephemeral port
/// allocation to `connect()` for 4-tuple co-selection, and `TCP_FASTOPEN_CONNECT`
/// sends data in the SYN packet.
async fn connect_backend_plain(
    addr: SocketAddr,
    connect_timeout: Duration,
    tcp_fastopen: bool,
    overload: &crate::overload::OverloadState,
) -> Result<TcpStream, anyhow::Error> {
    // Use TcpSocket to set socket options BEFORE connect(). This is the same
    // pattern as socket_opts::connect_with_socket_opts() but adds TFO and
    // port exhaustion detection.
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };

    // Apply pre-connect options on the raw fd.
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let _ = crate::socket_opts::set_ip_bind_address_no_port(fd, true);
        if tcp_fastopen {
            let _ = crate::socket_opts::set_tcp_fastopen_client(fd);
        }
    }
    #[cfg(not(unix))]
    let _ = tcp_fastopen;

    let stream = tokio::time::timeout(connect_timeout, socket.connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("Backend connect timeout to {}", addr))?
        .map_err(|e| {
            if crate::retry::is_port_exhaustion(&e) {
                tracing::error!(
                    "tcp_proxy: PORT EXHAUSTION connecting to backend {}: {} — \
                     reduce outbound connection rate or increase net.ipv4.ip_local_port_range",
                    addr,
                    e
                );
                overload.record_port_exhaustion();
            }
            anyhow::anyhow!("Backend connect failed to {}: {}", addr, e)
        })?;

    let _ = stream.set_nodelay(true);
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
    overload: &crate::overload::OverloadState,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, anyhow::Error> {
    let tcp_stream = connect_backend_plain(addr, connect_timeout, tcp_fastopen, overload).await?;

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

/// How long to wait for the opposite direction to drain after the first half
/// finishes (cleanly or with an error). Matches the splice-path grace window.
const BIDIRECTIONAL_DRAIN_GRACE: Duration = Duration::from_millis(100);

/// Copy bytes from `reader` into `writer` until EOF, updating `bytes` and
/// optionally `last_activity` on each read. Returns `Ok(())` on EOF or an
/// error on the first read/write failure.
async fn copy_one_direction<R, W>(
    mut reader: R,
    mut writer: W,
    buf_size: usize,
    bytes: Arc<AtomicU64>,
    last_activity: Option<Arc<AtomicU64>>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buf_size.max(4096)];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            // Clean EOF — shut down the writer side so the peer observes a
            // half-close. Ignore shutdown errors (peer may already be gone).
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
        bytes.fetch_add(n as u64, Ordering::Relaxed);
        if let Some(ref la) = last_activity {
            la.store(coarse_now_ms(), Ordering::Relaxed);
        }
    }
}

/// Bidirectional stream copy between client and backend.
///
/// Runs the two half-duplex copies concurrently via `tokio::select!` so that
/// whichever direction fails first is recorded in `first_failure`. Per-direction
/// byte counts are preserved even when one half errors.
///
/// After Phase 1 (race the two directions) completes, Phase 2 waits for the
/// remaining direction:
///
/// * If Phase 1 ended with a **clean EOF** (one side finished its send without
///   error), the remaining direction is awaited **unbounded** — this preserves
///   half-close semantics for request/response protocols (SMTP, IMAP,
///   HTTP-over-TCP passthrough) where the client finishes sending first and
///   the backend then takes arbitrary time to respond. The idle timeout still
///   applies, so a stuck peer cannot wedge the connection indefinitely.
/// * If Phase 1 ended with an **error** or the **idle timeout** fired, the
///   remaining direction is awaited with a short 100ms grace window so we
///   can capture any error it would produce without hanging on a bad peer.
///
/// When `idle_timeout` is `Some(d)` and non-zero, the connection is closed
/// if no data is received on either side for the given duration.
async fn bidirectional_copy<C, B>(
    client: C,
    backend: B,
    idle_timeout: Option<Duration>,
    buf_size: usize,
) -> StreamCopyResult
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let c2b_bytes = Arc::new(AtomicU64::new(0));
    let b2c_bytes = Arc::new(AtomicU64::new(0));

    let last_activity = match idle_timeout {
        Some(t) if !t.is_zero() => Some(Arc::new(AtomicU64::new(coarse_now_ms()))),
        _ => None,
    };

    let (client_read, client_write) = tokio::io::split(client);
    let (backend_read, backend_write) = tokio::io::split(backend);

    let c2b_bytes_task = c2b_bytes.clone();
    let b2c_bytes_task = b2c_bytes.clone();
    let la_c2b = last_activity.clone();
    let la_b2c = last_activity.clone();

    let c2b_fut = copy_one_direction(client_read, backend_write, buf_size, c2b_bytes_task, la_c2b);
    let b2c_fut = copy_one_direction(backend_read, client_write, buf_size, b2c_bytes_task, la_b2c);
    tokio::pin!(c2b_fut);
    tokio::pin!(b2c_fut);

    let idle_timeout_active = last_activity.is_some();
    let timeout_ms = idle_timeout.map(|t| t.as_millis() as u64).unwrap_or(0);

    // Phase 1: race the two directions (plus optional idle check).
    let mut first_failure: Option<(Direction, ErrorClass)> = None;
    let mut c2b_done = false;
    let mut b2c_done = false;

    loop {
        tokio::select! {
            biased;
            result = &mut c2b_fut, if !c2b_done => {
                c2b_done = true;
                if let Err(e) = result {
                    let err: anyhow::Error =
                        anyhow::anyhow!("Bidirectional copy error (client→backend): {}", e);
                    if first_failure.is_none() {
                        first_failure =
                            Some((Direction::ClientToBackend, classify_stream_error(&err)));
                    }
                }
                break;
            }
            result = &mut b2c_fut, if !b2c_done => {
                b2c_done = true;
                if let Err(e) = result {
                    let err: anyhow::Error =
                        anyhow::anyhow!("Bidirectional copy error (backend→client): {}", e);
                    if first_failure.is_none() {
                        first_failure =
                            Some((Direction::BackendToClient, classify_stream_error(&err)));
                    }
                }
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(1)), if idle_timeout_active => {
                if let Some(ref la) = last_activity {
                    let last = la.load(Ordering::Relaxed);
                    if coarse_now_ms().saturating_sub(last) >= timeout_ms {
                        // Idle timeout — treat as "unknown" direction since
                        // neither half produced an error. Use ReadWriteTimeout
                        // class so disconnect_cause downstream is IdleTimeout.
                        first_failure =
                            Some((Direction::Unknown, ErrorClass::ReadWriteTimeout));
                        break;
                    }
                }
            }
        }
    }

    // Phase 2: drain the remaining direction.
    //
    // Two cases:
    //
    // * **Clean EOF** (`first_failure.is_none()`): one side finished its send
    //   without error — most commonly a half-close where the client finished
    //   sending and the backend is still generating a large/slow response (or
    //   vice versa). Wait for the remaining direction to complete naturally,
    //   bounded only by the idle timeout. Capping this at 100ms would truncate
    //   response bodies on request/response protocols (SMTP, IMAP, HTTP-over-
    //   TCP passthrough) whenever the peer takes longer than 100ms to respond.
    //
    // * **Error or idle timeout** (`first_failure.is_some()`): both halves are
    //   likely in a bad state. Give the remaining direction a brief grace
    //   window to capture any error it would produce, then move on. Do not
    //   block the connection teardown on a stuck peer.
    let clean_eof = first_failure.is_none();
    if !c2b_done {
        if clean_eof {
            // Unbounded wait, still bounded by the idle timeout so a stuck
            // peer can't wedge the connection indefinitely.
            loop {
                tokio::select! {
                    biased;
                    result = &mut c2b_fut => {
                        if let Err(e) = result {
                            let err: anyhow::Error =
                                anyhow::anyhow!("Bidirectional copy error (client→backend): {}", e);
                            first_failure =
                                Some((Direction::ClientToBackend, classify_stream_error(&err)));
                        }
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(1)), if idle_timeout_active => {
                        if let Some(ref la) = last_activity {
                            let last = la.load(Ordering::Relaxed);
                            if coarse_now_ms().saturating_sub(last) >= timeout_ms {
                                first_failure =
                                    Some((Direction::Unknown, ErrorClass::ReadWriteTimeout));
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            match tokio::time::timeout(BIDIRECTIONAL_DRAIN_GRACE, &mut c2b_fut).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_failure.is_none() {
                        let err: anyhow::Error =
                            anyhow::anyhow!("Bidirectional copy error (client→backend): {}", e);
                        first_failure =
                            Some((Direction::ClientToBackend, classify_stream_error(&err)));
                    }
                }
                Err(_) => { /* grace expired — leave counters as-is */ }
            }
        }
    }
    if !b2c_done {
        if clean_eof {
            loop {
                tokio::select! {
                    biased;
                    result = &mut b2c_fut => {
                        if let Err(e) = result {
                            let err: anyhow::Error =
                                anyhow::anyhow!("Bidirectional copy error (backend→client): {}", e);
                            first_failure =
                                Some((Direction::BackendToClient, classify_stream_error(&err)));
                        }
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(1)), if idle_timeout_active => {
                        if let Some(ref la) = last_activity {
                            let last = la.load(Ordering::Relaxed);
                            if coarse_now_ms().saturating_sub(last) >= timeout_ms {
                                first_failure =
                                    Some((Direction::Unknown, ErrorClass::ReadWriteTimeout));
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            match tokio::time::timeout(BIDIRECTIONAL_DRAIN_GRACE, &mut b2c_fut).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_failure.is_none() {
                        let err: anyhow::Error =
                            anyhow::anyhow!("Bidirectional copy error (backend→client): {}", e);
                        first_failure =
                            Some((Direction::BackendToClient, classify_stream_error(&err)));
                    }
                }
                Err(_) => { /* grace expired — leave counters as-is */ }
            }
        }
    }

    StreamCopyResult {
        bytes_client_to_backend: c2b_bytes.load(Ordering::Relaxed),
        bytes_backend_to_client: b2c_bytes.load(Ordering::Relaxed),
        first_failure,
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
) -> StreamCopyResult {
    use std::os::unix::io::AsRawFd;

    let client_fd = client.as_raw_fd();
    let backend_fd = backend.as_raw_fd();

    // Create two pipes: one for each direction. Guards close fds on drop.
    let (c2b_pipe_r, c2b_pipe_w) = match create_splice_pipe(pipe_size) {
        Ok(p) => p,
        Err(e) => {
            return StreamCopyResult {
                bytes_client_to_backend: 0,
                bytes_backend_to_client: 0,
                first_failure: Some((Direction::Unknown, classify_stream_error(&e))),
            };
        }
    };
    let _c2b_guard = SplicePipeGuard(c2b_pipe_r, c2b_pipe_w);
    let (b2c_pipe_r, b2c_pipe_w) = match create_splice_pipe(pipe_size) {
        Ok(p) => p,
        Err(e) => {
            return StreamCopyResult {
                bytes_client_to_backend: 0,
                bytes_backend_to_client: 0,
                first_failure: Some((Direction::Unknown, classify_stream_error(&e))),
            };
        }
    };
    let _b2c_guard = SplicePipeGuard(b2c_pipe_r, b2c_pipe_w);

    let last_activity = if idle_timeout.is_some_and(|t| !t.is_zero()) {
        Some(Arc::new(AtomicU64::new(coarse_now_ms())))
    } else {
        None
    };

    let c2b_bytes = Arc::new(AtomicU64::new(0));
    let b2c_bytes = Arc::new(AtomicU64::new(0));

    let la_c2b = last_activity.clone();
    let la_b2c = last_activity.clone();
    let c2b_bytes_task = c2b_bytes.clone();
    let b2c_bytes_task = b2c_bytes.clone();

    // Pin both direction futures for use with select! — no spawned tasks.
    let c2b_fut = splice_one_direction_no_guard(
        client_fd,
        c2b_pipe_w,
        c2b_pipe_r,
        backend_fd,
        la_c2b,
        c2b_bytes_task,
    );
    let b2c_fut = splice_one_direction_no_guard(
        backend_fd,
        b2c_pipe_w,
        b2c_pipe_r,
        client_fd,
        la_b2c,
        b2c_bytes_task,
    );
    tokio::pin!(c2b_fut);
    tokio::pin!(b2c_fut);

    let idle_timeout_active = idle_timeout.is_some_and(|t| !t.is_zero());
    let timeout_ms = idle_timeout.map(|t| t.as_millis() as u64).unwrap_or(0);

    let mut first_failure: Option<(Direction, ErrorClass)> = None;
    let mut c2b_done = false;
    let mut b2c_done = false;

    // Phase 1: race the two directions (plus optional idle check).
    loop {
        tokio::select! {
            biased;
            c2b_result = &mut c2b_fut, if !c2b_done => {
                c2b_done = true;
                if let Err(e) = c2b_result
                    && first_failure.is_none()
                {
                    first_failure =
                        Some((Direction::ClientToBackend, classify_stream_error(&e)));
                }
                break;
            }
            b2c_result = &mut b2c_fut, if !b2c_done => {
                b2c_done = true;
                if let Err(e) = b2c_result
                    && first_failure.is_none()
                {
                    first_failure =
                        Some((Direction::BackendToClient, classify_stream_error(&e)));
                }
                break;
            }
            // Idle timeout check — wake every second.
            _ = tokio::time::sleep(Duration::from_secs(1)), if idle_timeout_active => {
                if let Some(ref la) = last_activity {
                    let last = la.load(Ordering::Relaxed);
                    if coarse_now_ms().saturating_sub(last) >= timeout_ms {
                        first_failure =
                            Some((Direction::Unknown, ErrorClass::ReadWriteTimeout));
                        break;
                    }
                }
            }
        }
    }

    // Phase 2: give the other half a brief grace window to drain remaining data.
    if !c2b_done {
        match tokio::time::timeout(BIDIRECTIONAL_DRAIN_GRACE, &mut c2b_fut).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                if first_failure.is_none() {
                    first_failure = Some((Direction::ClientToBackend, classify_stream_error(&e)));
                }
            }
            Err(_) => {}
        }
    }
    if !b2c_done {
        match tokio::time::timeout(BIDIRECTIONAL_DRAIN_GRACE, &mut b2c_fut).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                if first_failure.is_none() {
                    first_failure = Some((Direction::BackendToClient, classify_stream_error(&e)));
                }
            }
            Err(_) => {}
        }
    }

    StreamCopyResult {
        bytes_client_to_backend: c2b_bytes.load(Ordering::Relaxed),
        bytes_backend_to_client: b2c_bytes.load(Ordering::Relaxed),
        first_failure,
    }
}

/// Bidirectional zero-copy relay using io_uring `IORING_OP_SPLICE`.
///
/// Each direction gets its own io_uring ring (8 entries) and runs on a
/// dedicated blocking thread via `tokio::task::spawn_blocking`. This avoids
/// the async yield_now polling loop used by the libc splice path and reduces
/// per-operation syscall overhead.
///
/// Resource management is fully RAII: pipe fds are managed by `SplicePipeGuard`,
/// and `client`/`backend` streams stay alive on the stack until after the join.
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

    // Create pipes with RAII guards — guards close fds on drop, ensuring cleanup
    // even if spawn_blocking panics or the function returns early.
    let (c2b_pipe_r, c2b_pipe_w) = create_splice_pipe(pipe_size)?;
    let _c2b_guard = SplicePipeGuard(c2b_pipe_r, c2b_pipe_w);
    let (b2c_pipe_r, b2c_pipe_w) = create_splice_pipe(pipe_size)?;
    let _b2c_guard = SplicePipeGuard(b2c_pipe_r, b2c_pipe_w);

    let timeout_ms = idle_timeout
        .filter(|t| !t.is_zero())
        .map(|t| t.as_millis() as u64)
        .unwrap_or(0);

    // Shared last-activity timestamp across both directions. Activity in either
    // direction refreshes the timestamp, preventing one-way streams (e.g., downloads)
    // from timing out on the idle send direction.
    let shared_activity = Arc::new(AtomicU64::new(coarse_now_ms()));
    let sa_c2b = shared_activity.clone();
    let sa_b2c = shared_activity;

    // Each direction runs on its own blocking thread with its own io_uring ring.
    let c2b_handle = tokio::task::spawn_blocking(move || {
        io_uring_splice_direction(
            client_fd, c2b_pipe_w, c2b_pipe_r, backend_fd, timeout_ms, &sa_c2b,
        )
    });
    let b2c_handle = tokio::task::spawn_blocking(move || {
        io_uring_splice_direction(
            backend_fd, b2c_pipe_w, b2c_pipe_r, client_fd, timeout_ms, &sa_b2c,
        )
    });

    // Wait for both directions. Streams (`client`, `backend`) stay alive on this
    // stack frame until the function returns. Pipe guards (`_c2b_guard`, `_b2c_guard`)
    // close pipe fds on drop. All resource cleanup is RAII — no manual close needed.
    let (c2b_result, b2c_result) = tokio::join!(c2b_handle, b2c_handle);

    let c2b = c2b_result.map_err(|e| anyhow::anyhow!("io_uring splice spawn error: {}", e))??;
    let b2c = b2c_result.map_err(|e| anyhow::anyhow!("io_uring splice spawn error: {}", e))??;
    Ok((c2b, b2c))
    // Drop order (guaranteed by Rust): c2b, b2c returned → _b2c_guard closes pipes →
    // _c2b_guard closes pipes → backend dropped (fd closed) → client dropped (fd closed).
    // Blocking threads have already joined, so raw fds are no longer in use.
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
    shared_activity: &AtomicU64,
) -> Result<u64, anyhow::Error> {
    match crate::socket_opts::io_uring_splice::io_uring_splice_loop(
        src_fd,
        pipe_w,
        pipe_r,
        dst_fd,
        shared_activity,
        timeout_ms,
    ) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            // io_uring ring creation failed — fall back to libc::splice.
            // This can happen under memlock pressure even though startup
            // probing succeeded.
            tracing::debug!("io_uring ring creation failed, falling back to libc splice");
            libc_splice_loop(src_fd, pipe_w, pipe_r, dst_fd, timeout_ms, shared_activity)
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
    shared_activity: &AtomicU64,
) -> Result<u64, anyhow::Error> {
    let splice_flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;
    let mut total: u64 = 0;

    loop {
        if timeout_ms > 0 {
            let last = shared_activity.load(Ordering::Relaxed);
            if coarse_now_ms().saturating_sub(last) >= timeout_ms {
                return Err(anyhow::anyhow!("TCP idle timeout (libc splice fallback)"));
            }
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
                    // Refresh shared idle timeout — visible to both directions.
                    if timeout_ms > 0 {
                        shared_activity.store(coarse_now_ms(), Ordering::Relaxed);
                    }
                } else if written == 0 {
                    return Ok(total);
                } else {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        // CRITICAL: This inner-loop WouldBlock branch must recheck
                        // the idle timeout before sleeping. The `while remaining > 0`
                        // loop has no timeout check, so if the destination socket
                        // stops reading while data is buffered in the pipe, this
                        // branch would spin at 1000 iters/sec forever without
                        // releasing the blocking thread to the tokio pool.
                        if timeout_ms > 0 {
                            let last = shared_activity.load(Ordering::Relaxed);
                            if coarse_now_ms().saturating_sub(last) >= timeout_ms {
                                return Err(anyhow::anyhow!(
                                    "TCP idle timeout (libc splice fallback, write phase)"
                                ));
                            }
                        }
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
                // The outer `loop` at the top rechecks the timeout, but add an
                // inline check here for uniformity with the Phase 2 branch above.
                if timeout_ms > 0 {
                    let last = shared_activity.load(Ordering::Relaxed);
                    if coarse_now_ms().saturating_sub(last) >= timeout_ms {
                        return Err(anyhow::anyhow!(
                            "TCP idle timeout (libc splice fallback, read phase)"
                        ));
                    }
                }
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
///
/// Bytes transferred are accumulated into `bytes` so the caller can observe
/// the final count regardless of whether this direction completes cleanly or
/// errors. Pipe fds are managed by the caller's `SplicePipeGuard` — this
/// function does not close them.
#[cfg(target_os = "linux")]
async fn splice_one_direction_no_guard(
    src_fd: i32,
    pipe_w: i32,
    pipe_r: i32,
    dst_fd: i32,
    last_activity: Option<Arc<AtomicU64>>,
    bytes: Arc<AtomicU64>,
) -> Result<(), anyhow::Error> {
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
                    bytes.fetch_add(written as u64, Ordering::Relaxed);
                } else if written == 0 {
                    return Ok(());
                } else {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        // Destination not ready — yield to tokio scheduler and retry.
                        // yield_now() is correct here (async splice runs on a tokio worker).
                        // sleep(1ms) would add unnecessary latency per retry.
                        tokio::task::yield_now().await;
                        continue;
                    }
                    return Err(anyhow::anyhow!("splice write error: {}", err));
                }
            }
        } else if n == 0 {
            // EOF — source closed
            return Ok(());
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                // Source not ready — yield to tokio scheduler and retry.
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

/// Returns monotonic milliseconds since the process's first call to the shared
/// clock helper. Used for coarse idle tracking — does not need sub-millisecond
/// precision, but MUST be monotonic so wall-clock slew or NTP corrections
/// cannot cause `saturating_sub` to pin the elapsed duration at 0 (which would
/// disable the idle timeout).
///
/// Delegates to `crate::socket_opts::monotonic_now_ms` so the libc splice loop
/// and the io_uring splice loop share the same clock via the
/// `shared_last_activity_ms: Arc<AtomicU64>` they both read/write.
#[inline]
fn coarse_now_ms() -> u64 {
    crate::socket_opts::monotonic_now_ms()
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
    Unsupported(Box<(tokio_rustls::server::TlsStream<TcpStream>, TcpStream)>),
    /// kTLS keys were installed into the kernel but the subsequent splice failed.
    /// The TLS stream has been consumed (into_inner + dangerous_extract_secrets)
    /// so there is no way to recover — propagate the error.
    Installed(anyhow::Error),
}

/// Attempt kTLS-accelerated splice for a frontend-TLS + plain-backend connection.
///
/// 1. Check that the negotiated cipher is AES-128-GCM or AES-256-GCM.
/// 2. Check that the negotiated TLS version is TLS 1.2 (see below).
/// 3. Extract TLS session keys via `dangerous_extract_secrets()`.
/// 4. Install keys into the kernel via `enable_ktls()`.
/// 5. Use `bidirectional_splice()` for zero-copy relay.
///
/// Returns `KtlsError::Unsupported` with the original streams if kTLS cannot
/// be used, allowing the caller to fall back to userspace `bidirectional_copy`.
///
/// **TLS 1.2 ONLY.** TLS 1.3 connections fall back to userspace relay because
/// this implementation does not handle KeyUpdate — the kernel holds a static
/// copy of the application traffic secret, and a peer-initiated KeyUpdate
/// would silently desynchronize decryption mid-stream.
#[cfg(target_os = "linux")]
async fn try_ktls_splice(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    backend_stream: TcpStream,
    idle_timeout: Option<Duration>,
    buf_size: usize,
) -> Result<(u64, u64), KtlsError> {
    use std::os::unix::io::AsRawFd;

    // Check cipher suite compatibility AND per-cipher kernel support before
    // consuming the TLS stream. Supported ciphers: AES-128-GCM, AES-256-GCM,
    // and ChaCha20-Poly1305.
    //
    // CRITICAL: Each cipher landed in kTLS in a different kernel version
    // (AES-GCM in 4.13/4.17, ChaCha20-Poly1305 in 5.11+). A blanket
    // `is_ktls_available()` answer is NOT sufficient: a kernel may accept
    // the ULP and AES-128 keys while rejecting ChaCha20 keys with
    // EINVAL/EOPNOTSUPP. If we only checked the cipher suite name and
    // assumed the kernel supports it, the install would fail AFTER we
    // have already consumed the TLS stream via `into_inner()` +
    // `dangerous_extract_secrets()`, forcing a hard connection drop with
    // no safe fallback to userspace TLS. The per-cipher gate below
    // prevents this by refusing connections whose kernel probe failed
    // BEFORE we extract secrets.
    let cipher_ok = {
        let (_, server_conn) = tls_stream.get_ref();
        match server_conn.negotiated_cipher_suite() {
            Some(suite) => {
                let name = format!("{:?}", suite.suite());
                if name.contains("AES_128_GCM") {
                    crate::socket_opts::ktls::is_ktls_aes128gcm_available()
                } else if name.contains("AES_256_GCM") {
                    crate::socket_opts::ktls::is_ktls_aes256gcm_available()
                } else if name.contains("CHACHA20_POLY1305") {
                    crate::socket_opts::ktls::is_ktls_chacha20_poly1305_available()
                } else {
                    false
                }
            }
            None => false,
        }
    };

    if !cipher_ok {
        debug!(
            "kTLS: unsupported cipher suite or kernel lacks per-cipher support, \
             falling back to userspace copy"
        );
        return Err(KtlsError::Unsupported(Box::new((
            tls_stream,
            backend_stream,
        ))));
    }

    // Check TLS version — kTLS is restricted to TLS 1.2 ONLY in this gateway.
    //
    // TLS 1.3 is intentionally NOT supported because `dangerous_extract_secrets()`
    // returns the CURRENT application traffic secret. In TLS 1.3 either peer may
    // issue a KeyUpdate message at any time (RFC 8446 §4.6.3) to rotate keys.
    // Because we install keys into the kernel ONCE and then splice the socket
    // directly (no userspace TLS state machine), a peer-initiated KeyUpdate
    // would silently desynchronize the kernel from the negotiated peer state
    // mid-stream, producing decryption failures with no opportunity to rekey
    // the kernel. For long-lived TCP streams this is a reachable correctness
    // bug, so we fall back to userspace TLS for TLS 1.3 connections.
    let tls_version = {
        let (_, server_conn) = tls_stream.get_ref();
        server_conn.protocol_version()
    };
    let tls_ver_u16 = match tls_version {
        Some(rustls::ProtocolVersion::TLSv1_2) => 0x0303_u16,
        Some(rustls::ProtocolVersion::TLSv1_3) => {
            debug!("kTLS: TLS 1.3 KeyUpdate handling not implemented, falling back to userspace");
            return Err(KtlsError::Unsupported(Box::new((
                tls_stream,
                backend_stream,
            ))));
        }
        _ => {
            debug!(
                "kTLS: unsupported TLS version {:?}, falling back",
                tls_version
            );
            return Err(KtlsError::Unsupported(Box::new((
                tls_stream,
                backend_stream,
            ))));
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
            return Err(KtlsError::Unsupported(Box::new((
                tls_stream,
                backend_stream,
            ))));
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
/// Returns `None` if the cipher suite is not AES-128-GCM, AES-256-GCM, or
/// ChaCha20-Poly1305.
///
/// Secret material is wrapped in `Zeroizing<Vec<u8>>` so the heap backing
/// is volatile-zeroed on drop. This applies to the intermediate allocations
/// in this function (they are `Zeroizing` from the moment they are created)
/// as well as any downstream storage inside `KtlsParams`.
#[cfg(target_os = "linux")]
fn build_ktls_params(
    tls_version: u16,
    secrets: &rustls::ExtractedSecrets,
) -> Option<crate::socket_opts::ktls::KtlsParams> {
    use crate::socket_opts::ktls::{KtlsCipher, KtlsParams};
    use rustls::ConnectionTrafficSecrets;
    use zeroize::Zeroizing;

    let (tx_seq, ref tx_secrets) = secrets.tx;
    let (rx_seq, ref rx_secrets) = secrets.rx;

    let (cipher_suite, tx_key, tx_iv, rx_key, rx_iv) = match (tx_secrets, rx_secrets) {
        (
            ConnectionTrafficSecrets::Aes128Gcm { key: tk, iv: tiv },
            ConnectionTrafficSecrets::Aes128Gcm { key: rk, iv: riv },
        ) => (
            KtlsCipher::Aes128Gcm,
            Zeroizing::new(tk.as_ref().to_vec()),
            Zeroizing::new(tiv.as_ref().to_vec()),
            Zeroizing::new(rk.as_ref().to_vec()),
            Zeroizing::new(riv.as_ref().to_vec()),
        ),
        (
            ConnectionTrafficSecrets::Aes256Gcm { key: tk, iv: tiv },
            ConnectionTrafficSecrets::Aes256Gcm { key: rk, iv: riv },
        ) => (
            KtlsCipher::Aes256Gcm,
            Zeroizing::new(tk.as_ref().to_vec()),
            Zeroizing::new(tiv.as_ref().to_vec()),
            Zeroizing::new(rk.as_ref().to_vec()),
            Zeroizing::new(riv.as_ref().to_vec()),
        ),
        (
            ConnectionTrafficSecrets::Chacha20Poly1305 { key: tk, iv: tiv },
            ConnectionTrafficSecrets::Chacha20Poly1305 { key: rk, iv: riv },
        ) => (
            KtlsCipher::Chacha20Poly1305,
            Zeroizing::new(tk.as_ref().to_vec()),
            Zeroizing::new(tiv.as_ref().to_vec()),
            Zeroizing::new(rk.as_ref().to_vec()),
            Zeroizing::new(riv.as_ref().to_vec()),
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

#[cfg(all(test, target_os = "linux"))]
mod ktls_param_tests {
    //! Tests for `build_ktls_params` — the rustls-ExtractedSecrets to
    //! KtlsParams mapping. These run inline because `build_ktls_params`
    //! is a private function and the rustls types it consumes are not
    //! re-exported from the gateway crate.
    //!
    //! We use `AeadKey::from([u8; 32])` (the only stable public constructor)
    //! which yields a 32-byte key regardless of the cipher's real key length.
    //! That is harmless for this unit test since we are exercising the match
    //! arm selection and byte plumbing, not the kernel install path.

    use super::build_ktls_params;
    use crate::socket_opts::ktls::KtlsCipher;
    use rustls::ConnectionTrafficSecrets;
    use rustls::ExtractedSecrets;
    use rustls::crypto::cipher::{AeadKey, Iv};

    fn aead_key(byte: u8) -> AeadKey {
        AeadKey::from([byte; 32])
    }

    fn iv(byte: u8) -> Iv {
        Iv::from([byte; 12])
    }

    #[test]
    fn aes128_gcm_both_sides_maps_to_aes128() {
        let secrets = ExtractedSecrets {
            tx: (
                0x1122_3344_5566_7788,
                ConnectionTrafficSecrets::Aes128Gcm {
                    key: aead_key(0x11),
                    iv: iv(0x22),
                },
            ),
            rx: (
                0xdead_beef_0000_0001,
                ConnectionTrafficSecrets::Aes128Gcm {
                    key: aead_key(0x33),
                    iv: iv(0x44),
                },
            ),
        };
        let params = build_ktls_params(0x0303, &secrets).expect("AES-128 pair must map");
        assert!(matches!(params.cipher_suite, KtlsCipher::Aes128Gcm));
        assert_eq!(params.tls_version, 0x0303);
        assert_eq!(params.tx_seq, 0x1122_3344_5566_7788_u64.to_be_bytes());
        assert_eq!(params.rx_seq, 0xdead_beef_0000_0001_u64.to_be_bytes());
        assert_eq!(params.tx_iv.len(), 12);
        assert_eq!(params.rx_iv.len(), 12);
    }

    #[test]
    fn aes256_gcm_both_sides_maps_to_aes256() {
        let secrets = ExtractedSecrets {
            tx: (
                1,
                ConnectionTrafficSecrets::Aes256Gcm {
                    key: aead_key(0xaa),
                    iv: iv(0xbb),
                },
            ),
            rx: (
                2,
                ConnectionTrafficSecrets::Aes256Gcm {
                    key: aead_key(0xcc),
                    iv: iv(0xdd),
                },
            ),
        };
        let params = build_ktls_params(0x0303, &secrets).expect("AES-256 pair must map");
        assert!(matches!(params.cipher_suite, KtlsCipher::Aes256Gcm));
        assert_eq!(params.tx_seq, 1u64.to_be_bytes());
        assert_eq!(params.rx_seq, 2u64.to_be_bytes());
    }

    #[test]
    fn mismatched_cipher_families_return_none() {
        let secrets = ExtractedSecrets {
            tx: (
                0,
                ConnectionTrafficSecrets::Aes128Gcm {
                    key: aead_key(0x11),
                    iv: iv(0x22),
                },
            ),
            rx: (
                0,
                ConnectionTrafficSecrets::Aes256Gcm {
                    key: aead_key(0x33),
                    iv: iv(0x44),
                },
            ),
        };
        assert!(build_ktls_params(0x0303, &secrets).is_none());
    }

    #[test]
    fn chacha20_poly1305_both_sides_maps_to_chacha20() {
        let secrets = ExtractedSecrets {
            tx: (
                7,
                ConnectionTrafficSecrets::Chacha20Poly1305 {
                    key: aead_key(0x11),
                    iv: iv(0x22),
                },
            ),
            rx: (
                8,
                ConnectionTrafficSecrets::Chacha20Poly1305 {
                    key: aead_key(0x33),
                    iv: iv(0x44),
                },
            ),
        };
        let params = build_ktls_params(0x0304, &secrets).expect("ChaCha20-Poly1305 pair must map");
        assert!(matches!(params.cipher_suite, KtlsCipher::Chacha20Poly1305));
        assert_eq!(params.tls_version, 0x0304);
        assert_eq!(params.tx_seq, 7u64.to_be_bytes());
        assert_eq!(params.rx_seq, 8u64.to_be_bytes());
        // ChaCha20-Poly1305 uses the full 12-byte IV directly.
        assert_eq!(params.tx_iv.len(), 12);
        assert_eq!(params.rx_iv.len(), 12);
    }

    #[test]
    fn chacha20_mixed_with_aes_returns_none() {
        // TX ChaCha20, RX AES-128 — not a supported mixed pairing.
        let secrets = ExtractedSecrets {
            tx: (
                0,
                ConnectionTrafficSecrets::Chacha20Poly1305 {
                    key: aead_key(0x11),
                    iv: iv(0x22),
                },
            ),
            rx: (
                0,
                ConnectionTrafficSecrets::Aes128Gcm {
                    key: aead_key(0x33),
                    iv: iv(0x44),
                },
            ),
        };
        assert!(build_ktls_params(0x0303, &secrets).is_none());
    }
}
