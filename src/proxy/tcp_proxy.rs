//! Raw TCP stream proxy with optional TLS termination (frontend) and origination (backend).
//!
//! Each TCP proxy binds its own dedicated port. Incoming connections are
//! forwarded bidirectionally to the configured backend using
//! `tokio::io::copy_bidirectional` for optimal zero-copy throughput.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::circuit_breaker::CircuitBreakerCache;
use crate::tls::{NoVerifier, TlsPolicy};

use crate::config::types::{BackendProtocol, GatewayConfig, Proxy};
use crate::dns::DnsCache;
use crate::load_balancer::LoadBalancerCache;
use crate::plugin_cache::PluginCache;
use crate::plugins::{
    PluginResult, ProxyProtocol, StreamConnectionContext, StreamTransactionSummary,
};

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
    ) -> Result<Self, anyhow::Error> {
        // Build root certificate store:
        // - Custom CA configured → empty store + only that CA (no public roots)
        // - No CA configured → webpki/system roots as default fallback
        let ca_path = proxy
            .backend_tls_server_ca_cert_path
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
        let builder = crate::tls::backend_client_config_builder(tls_policy)?;
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
            builder
                .with_root_certificates(root_store)
                .with_client_auth_cert(certs, key)
                .map_err(|e| anyhow::anyhow!("Failed to set client auth cert: {}", e))?
        } else {
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        // Disable verification only if explicitly requested
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
    /// Global CA bundle path for outbound TLS verification (fallback when proxy has no per-proxy CA).
    pub tls_ca_bundle_path: Option<String>,
    pub plugin_cache: Arc<PluginCache>,
    /// Global default TCP idle timeout in seconds. Per-proxy `tcp_idle_timeout_seconds` overrides.
    pub tcp_idle_timeout_seconds: u64,
    /// Circuit breaker cache shared with HTTP proxies.
    pub circuit_breaker_cache: Arc<CircuitBreakerCache>,
    /// TLS hardening policy for backend connections (cipher suites, protocol versions).
    pub tls_policy: Option<Arc<TlsPolicy>>,
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
        tls_ca_bundle_path,
        plugin_cache,
        tcp_idle_timeout_seconds: global_tcp_idle_timeout,
        circuit_breaker_cache,
        tls_policy,
    } = cfg;
    let addr = SocketAddr::new(bind_addr, port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // Convert to Arc<str> so per-connection clones are a cheap pointer bump.
    let proxy_id: Arc<str> = Arc::from(proxy_id);
    info!(
        proxy_id = %proxy_id,
        "TCP proxy listener started on {}",
        addr
    );

    // Pre-capture proxy metadata for plugin context (static for this listener's lifetime).
    let (proxy_name, backend_protocol) = {
        let current_config = config.load();
        current_config
            .proxies
            .iter()
            .find(|p| *p.id == *proxy_id)
            .map(|p| (p.name.clone(), p.backend_protocol))
            .unwrap_or((None, BackendProtocol::Tcp))
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
                CachedBackendTlsConfig::build(proxy, tls_no_verify, tls_ca_bundle_path.as_deref(), tls_policy.as_deref())
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

                metrics.total_connections.fetch_add(1, Ordering::Relaxed);
                metrics.active_connections.fetch_add(1, Ordering::Relaxed);

                let proxy_id = proxy_id.clone();
                let config = config.clone();
                let dns_cache = dns_cache.clone();
                let lb_cache = load_balancer_cache.clone();
                let frontend_tls = frontend_tls_config.clone();
                let metrics = metrics.clone();
                let backend_tls = backend_tls_cache.clone();
                let plugins = plugins.clone();
                let proxy_name = proxy_name.clone();
                let cb_cache = circuit_breaker_cache.clone();

                tokio::spawn(async move {
                    let connected_at = chrono::Utc::now();

                    // Run on_stream_connect plugins (ip_restriction, rate_limiting, etc.)
                    let mut stream_ctx = StreamConnectionContext {
                        client_ip: remote_addr.ip().to_string(),
                        proxy_id: proxy_id.to_string(),
                        proxy_name: proxy_name.clone(),
                        listen_port: port,
                        backend_protocol,
                        metadata: std::collections::HashMap::new(),
                    };
                    for plugin in plugins.iter() {
                        if let PluginResult::Reject { .. } = plugin.on_stream_connect(&mut stream_ctx).await {
                            debug!(
                                proxy_id = %proxy_id,
                                client = %remote_addr.ip(),
                                "TCP connection rejected by plugin"
                            );
                            metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
                            return;
                        }
                    }

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
                    )
                    .await;

                    let disconnected_at = chrono::Utc::now();
                    let duration_ms = (disconnected_at - connected_at).num_milliseconds().max(0) as f64;
                    let (bytes_in, bytes_out, conn_error, error_class) = match &result.outcome {
                        Ok(s) => {
                            metrics.bytes_in.fetch_add(s.bytes_in, Ordering::Relaxed);
                            metrics.bytes_out.fetch_add(s.bytes_out, Ordering::Relaxed);
                            debug!(
                                proxy_id = %proxy_id,
                                client = %remote_addr.ip(),
                                bytes_in = s.bytes_in,
                                bytes_out = s.bytes_out,
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
                            (0, 0, Some(e.to_string()), Some(crate::retry::ErrorClass::ConnectionTimeout))
                        }
                    };

                    // Run on_stream_disconnect plugins (logging, metrics, etc.)
                    if !plugins.is_empty() {
                        let summary = StreamTransactionSummary {
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
                            metadata: stream_ctx.metadata,
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
}

/// Handle a single TCP connection: TLS termination → backend resolution → bidirectional copy.
///
/// Always returns a `TcpConnectionResult` containing backend target info (for logging)
/// and the connection outcome. Backend info is populated as soon as the target is known,
/// so even failed connections log which backend was attempted.
#[allow(clippy::too_many_arguments)]
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
    )
    .await;

    TcpConnectionResult {
        backend: backend_info,
        outcome,
    }
}

/// Inner implementation of TCP connection handling that can use `?` for early returns
/// while the caller always receives backend info for logging.
#[allow(clippy::too_many_arguments)]
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
) -> Result<TcpConnectionSuccess, anyhow::Error> {
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
        };

        (params, cb_info)
    };

    let is_backend_tls = params.backend_protocol == BackendProtocol::TcpTls;
    let connect_timeout = Duration::from_millis(params.backend_connect_timeout_ms);
    let idle_timeout = if params.tcp_idle_timeout_seconds > 0 {
        Some(Duration::from_secs(params.tcp_idle_timeout_seconds))
    } else {
        None
    };

    // Helper: record circuit breaker failure for the current target.
    let record_cb_failure = |cb_cache: &CircuitBreakerCache,
                             proxy_id: &str,
                             cb_info: &TcpConnCbInfo| {
        if let Some(ref cb_config) = cb_info.cb_config {
            let cb = cb_cache.get_or_create(proxy_id, cb_info.cb_target_key.as_deref(), cb_config);
            cb.record_failure(502);
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
            connect_backend_tls_cached(addr, &current_host, connect_timeout, cached_backend_tls)
                .await
                .map(|s| BackendStream::Tls(Box::new(s)))
        } else {
            connect_backend_plain(addr, connect_timeout)
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

        match backend_stream {
            BackendStream::Tls(bs) => bidirectional_copy(tls_stream, bs, idle_timeout).await,
            BackendStream::Plain(bs) => bidirectional_copy(tls_stream, bs, idle_timeout).await,
        }
    } else {
        match backend_stream {
            BackendStream::Tls(bs) => bidirectional_copy(client_stream, bs, idle_timeout).await,
            BackendStream::Plain(bs) => bidirectional_copy(client_stream, bs, idle_timeout).await,
        }
    };

    // Record circuit breaker outcome based on copy result.
    if let Some(ref cb_config) = current_cb_info.cb_config {
        let cb = circuit_breaker_cache.get_or_create(
            proxy_id,
            current_cb_info.cb_target_key.as_deref(),
            cb_config,
        );
        match &copy_result {
            Ok(_) => cb.record_success(),
            Err(_) => cb.record_failure(502),
        }
    }

    copy_result.map(|(bytes_in, bytes_out)| TcpConnectionSuccess {
        bytes_in,
        bytes_out,
        duration: start.elapsed(),
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
    Some((next.host, next.port))
}

/// Connect to a plain TCP backend with the given connect timeout.
async fn connect_backend_plain(
    addr: SocketAddr,
    connect_timeout: Duration,
) -> Result<TcpStream, anyhow::Error> {
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
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
    connect_timeout: Duration,
    cached_tls: Option<&CachedBackendTlsConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, anyhow::Error> {
    let tcp_stream = connect_backend_plain(addr, connect_timeout).await?;

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

/// Buffer size for bidirectional TCP copy. 64 KiB reduces syscall overhead
/// compared to the tokio default of 8 KiB, yielding significantly higher
/// throughput for bulk TCP traffic.
const TCP_COPY_BUF_SIZE: usize = 64 * 1024;

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
                TCP_COPY_BUF_SIZE,
                TCP_COPY_BUF_SIZE,
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
            tokio::io::copy_bidirectional_with_sizes(
                &mut client,
                &mut backend,
                TCP_COPY_BUF_SIZE,
                TCP_COPY_BUF_SIZE,
            )
            .await
            .map_err(|e| anyhow::anyhow!("Bidirectional copy error: {}", e))
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
