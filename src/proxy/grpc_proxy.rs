//! gRPC reverse proxy handler using hyper's HTTP/2 client directly.
//!
//! Unlike the standard HTTP proxy path (which uses reqwest and may drop trailers),
//! this module uses hyper's HTTP/2 client to get:
//! - HTTP/2 trailer forwarding (`grpc-status`, `grpc-message`)
//! - h2c (cleartext HTTP/2) via prior knowledge handshake
//! - Proper gRPC error responses when the backend is unavailable
//!
//! Connection pool features (matching the HTTP `ConnectionPool`):
//! - Connect timeout from `proxy.backend_connect_timeout_ms`
//! - Read timeout from `proxy.backend_read_timeout_ms`
//! - TCP keepalive from `PoolConfig.tcp_keepalive_seconds`
//! - HTTP/2 PING keepalive from `PoolConfig.http2_keep_alive_interval/timeout`
//! - Idle connection cleanup via background task
//! - Per-proxy pool configuration overrides
//! - mTLS client certificates (global + per-proxy)
//! - Custom CA bundles via `FERRUM_TLS_CA_BUNDLE_PATH`
//!
//! gRPC metadata maps to HTTP/2 headers, so existing auth plugins work unchanged.

use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, error, warn};

use crate::config::PoolConfig;
use crate::config::types::{BackendProtocol, Proxy};
use crate::dns::DnsCache;
use crate::tls::{NoVerifier, TlsPolicy};

/// Pool entry tracking a sender handle and its last-used timestamp.
struct GrpcPoolEntry {
    sender: http2::SendRequest<Full<Bytes>>,
    last_used_epoch_ms: Arc<AtomicU64>,
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// gRPC-specific HTTP/2 connection pool.
///
/// Manages reusable HTTP/2 connections to gRPC backends. Unlike the reqwest-based
/// `ConnectionPool`, this uses hyper's HTTP/2 client directly to support h2c
/// (cleartext HTTP/2) and trailer forwarding.
///
/// Honors the same configuration as the HTTP pool:
/// - Global `PoolConfig` from environment variables
/// - Per-proxy overrides (`pool_*` fields on `Proxy`)
/// - Global mTLS and CA bundle settings from `EnvConfig`
/// - Background idle connection cleanup
pub struct GrpcConnectionPool {
    /// Cached sender handles keyed by `host:port:tls#shard`
    entries: Arc<DashMap<String, GrpcPoolEntry>>,
    /// Round-robin counters keyed by the base backend host:port:tls tuple.
    rr_counters: Arc<DashMap<String, Arc<AtomicUsize>>>,
    /// Global pool configuration (idle timeout, keepalive, etc.)
    global_pool_config: PoolConfig,
    /// Global TLS/mTLS configuration
    global_env_config: crate::config::EnvConfig,
    /// TLS hardening policy for backend connections (cipher suites, protocol versions).
    tls_policy: Option<Arc<TlsPolicy>>,
}

impl Default for GrpcConnectionPool {
    fn default() -> Self {
        Self::new(
            PoolConfig::default(),
            crate::config::EnvConfig::default(),
            None,
        )
    }
}

impl GrpcConnectionPool {
    pub fn new(
        global_pool_config: PoolConfig,
        global_env_config: crate::config::EnvConfig,
        tls_policy: Option<Arc<TlsPolicy>>,
    ) -> Self {
        let pool = Self {
            entries: Arc::new(DashMap::new()),
            rr_counters: Arc::new(DashMap::new()),
            global_pool_config,
            global_env_config,
            tls_policy,
        };

        pool.start_cleanup_task();
        pool
    }

    /// Number of connections in the pool (for metrics).
    pub fn pool_size(&self) -> usize {
        self.entries.len()
    }

    /// ⚠️  CRITICAL — DO NOT add fields to this key without careful analysis.
    /// Adding fields causes pool fragmentation and P95 latency regressions.
    /// See `ConnectionPool::create_pool_key` for detailed rationale.
    ///
    /// Includes all fields that affect connection *identity*: destination,
    /// TLS mode, DNS override, CA cert, mTLS client cert, and server cert verification.
    /// Uses `|` as field delimiter to avoid ambiguity with `:` in IPv6 addresses.
    ///
    /// Returns the base key (without shard suffix). For shard keys, the caller
    /// appends `#N` using `write!` to avoid extra allocations.
    fn pool_key(proxy: &Proxy) -> String {
        let tls = matches!(proxy.backend_protocol, BackendProtocol::Grpcs);
        let dns = proxy.dns_override.as_deref().unwrap_or_default();
        let ca = proxy
            .backend_tls_server_ca_cert_path
            .as_deref()
            .unwrap_or_default();
        let mtls_cert = proxy
            .backend_tls_client_cert_path
            .as_deref()
            .unwrap_or_default();
        let verify = proxy.backend_tls_verify_server_cert;
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            proxy.backend_host, proxy.backend_port, tls, dns, ca, mtls_cert, verify as u8,
        )
    }

    /// Build a shard key by appending the shard index to a pre-allocated buffer.
    /// Reuses the same buffer across calls to minimize allocations.
    fn write_shard_key(buf: &mut String, base_key: &str, shard: usize) {
        buf.clear();
        buf.push_str(base_key);
        buf.push('#');
        // Inline integer formatting for small numbers (0-9 are single digit)
        if shard < 10 {
            buf.push((b'0' + shard as u8) as char);
        } else {
            use std::fmt::Write;
            let _ = write!(buf, "{shard}");
        }
    }

    /// Get or create an HTTP/2 connection to the gRPC backend.
    ///
    /// Returns a sender that has been `ready()`-checked, meaning the H2
    /// connection has capacity for at least one more stream. Uses the same
    /// two-phase readiness strategy as `Http2ConnectionPool::get_sender`.
    pub async fn get_sender(
        &self,
        proxy: &Proxy,
        dns_cache: &DnsCache,
    ) -> Result<http2::SendRequest<Full<Bytes>>, GrpcProxyError> {
        let base_key = Self::pool_key(proxy);
        let pool_config = self.global_pool_config.for_proxy(proxy);
        let shard_count = pool_config.http2_connections_per_host.max(1);
        let rr = self
            .rr_counters
            .entry(base_key.clone())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();
        let start = rr.fetch_add(1, Ordering::Relaxed) % shard_count;

        // Reusable buffer for shard key construction (avoids per-request String allocation)
        let mut key_buf = String::with_capacity(base_key.len() + 4);

        // Two-phase readiness check (see Http2ConnectionPool::get_sender for rationale):
        // Phase 1: instant poll each shard without blocking.
        // Phase 2: if none ready, wait briefly on first live shard.
        let mut first_live_key: Option<String> = None;
        for offset in 0..shard_count {
            let shard = (start + offset) % shard_count;
            Self::write_shard_key(&mut key_buf, &base_key, shard);

            if let Some(entry) = self.entries.get(&key_buf) {
                if entry.sender.is_closed() {
                    drop(entry);
                    self.entries.remove(&key_buf);
                    continue;
                }
                let mut sender = entry.sender.clone();
                entry
                    .last_used_epoch_ms
                    .store(now_epoch_ms(), Ordering::Relaxed);
                drop(entry);

                match futures_util::FutureExt::now_or_never(sender.ready()) {
                    Some(Ok(())) => return Ok(sender),
                    Some(Err(_)) => {
                        self.entries.remove(&key_buf);
                        continue;
                    }
                    None => {
                        if first_live_key.is_none() {
                            first_live_key = Some(key_buf.clone());
                        }
                    }
                }
            }
        }

        // Phase 2: wait briefly on first live shard for a stream slot to free up.
        if let Some(key) = first_live_key
            && let Some(entry) = self.entries.get(&key)
        {
            let mut sender = entry.sender.clone();
            drop(entry);
            match tokio::time::timeout(Duration::from_millis(5), sender.ready()).await {
                Ok(Ok(())) => return Ok(sender),
                Ok(Err(_)) => {
                    self.entries.remove(&key);
                }
                Err(_) => {
                    // Still not ready after 5ms — fall through to create new connection
                }
            }
        }

        // No existing shard was ready — create a new connection.
        Self::write_shard_key(&mut key_buf, &base_key, start);
        let sender = match self.create_connection(proxy, dns_cache).await {
            Ok(sender) => sender,
            Err(err) => {
                for offset in 1..shard_count {
                    let shard = (start + offset) % shard_count;
                    Self::write_shard_key(&mut key_buf, &base_key, shard);
                    if let Some(entry) = self.entries.get(&key_buf) {
                        if !entry.sender.is_closed() {
                            entry
                                .last_used_epoch_ms
                                .store(now_epoch_ms(), Ordering::Relaxed);
                            return Ok(entry.sender.clone());
                        }
                        drop(entry);
                        self.entries.remove(&key_buf);
                    }
                }
                return Err(err);
            }
        };
        Self::write_shard_key(&mut key_buf, &base_key, start);
        let sender = match self.entries.entry(key_buf) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                if occupied.get().sender.is_closed() {
                    occupied.insert(GrpcPoolEntry {
                        sender: sender.clone(),
                        last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
                    });
                    sender
                } else {
                    occupied.get().sender.clone()
                }
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(GrpcPoolEntry {
                    sender: sender.clone(),
                    last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
                });
                sender
            }
        };
        Ok(sender)
    }

    async fn create_connection(
        &self,
        proxy: &Proxy,
        dns_cache: &DnsCache,
    ) -> Result<http2::SendRequest<Full<Bytes>>, GrpcProxyError> {
        let host = &proxy.backend_host;
        let port = proxy.backend_port;

        // Resolve backend hostname via DNS cache
        let target_host = match dns_cache
            .resolve(
                host,
                proxy.dns_override.as_deref(),
                proxy.dns_cache_ttl_seconds,
            )
            .await
        {
            Ok(ip) => ip.to_string(),
            Err(_) => host.clone(),
        };

        let addr = format!("{}:{}", target_host, port);
        let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);

        // Connect with timeout
        let tcp = tokio::time::timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| {
                warn!(
                    "gRPC: connect timeout ({}ms) to backend {}",
                    proxy.backend_connect_timeout_ms, addr
                );
                GrpcProxyError::BackendTimeout(format!(
                    "Connect timeout after {}ms to {}",
                    proxy.backend_connect_timeout_ms, addr
                ))
            })?
            .map_err(|e| {
                warn!("gRPC: failed to connect to backend {}: {}", addr, e);
                GrpcProxyError::BackendUnavailable(format!("Connection refused: {}", e))
            })?;

        // Disable Nagle for lower latency
        let _ = tcp.set_nodelay(true);

        // Apply TCP keepalive using per-proxy pool config
        let pool_config = self.global_pool_config.for_proxy(proxy);
        if pool_config.enable_http_keep_alive {
            Self::set_tcp_keepalive(&tcp, pool_config.tcp_keepalive_seconds);
        }

        let use_tls = matches!(proxy.backend_protocol, BackendProtocol::Grpcs);

        if use_tls {
            self.create_tls_connection(tcp, host, proxy, &pool_config)
                .await
        } else {
            self.create_h2c_connection(tcp, &pool_config).await
        }
    }

    /// Build an HTTP/2 client builder with keepalive and flow-control settings.
    fn build_h2_builder(pool_config: &PoolConfig) -> http2::Builder<TokioExecutor> {
        let mut builder = http2::Builder::new(TokioExecutor::new());

        // Timer is required for keep_alive_interval and keep_alive_timeout to work
        builder.timer(TokioTimer::new());

        if pool_config.enable_http2 {
            builder
                .keep_alive_interval(Duration::from_secs(
                    pool_config.http2_keep_alive_interval_seconds,
                ))
                .keep_alive_timeout(Duration::from_secs(
                    pool_config.http2_keep_alive_timeout_seconds,
                ))
                .max_concurrent_reset_streams(4096);
        }

        // Flow-control tuning — larger windows dramatically improve throughput
        // by allowing more data in flight before waiting for WINDOW_UPDATEs.
        builder
            .initial_stream_window_size(pool_config.http2_initial_stream_window_size)
            .initial_connection_window_size(pool_config.http2_initial_connection_window_size)
            .adaptive_window(pool_config.http2_adaptive_window)
            .max_frame_size(pool_config.http2_max_frame_size);

        if let Some(max_streams) = pool_config.http2_max_concurrent_streams {
            builder.max_concurrent_streams(max_streams);
        }

        builder
    }

    /// Set TCP keepalive on a stream to detect dead backend connections.
    fn set_tcp_keepalive(stream: &TcpStream, keepalive_seconds: u64) {
        use std::os::fd::AsFd;
        let fd = stream.as_fd();
        let socket = socket2::SockRef::from(&fd);
        let keepalive =
            socket2::TcpKeepalive::new().with_time(Duration::from_secs(keepalive_seconds));
        if let Err(e) = socket.set_tcp_keepalive(&keepalive) {
            debug!("gRPC: failed to set TCP keepalive: {}", e);
        }
    }

    /// Create an h2c (cleartext HTTP/2) connection using prior knowledge.
    async fn create_h2c_connection(
        &self,
        tcp: TcpStream,
        pool_config: &PoolConfig,
    ) -> Result<http2::SendRequest<Full<Bytes>>, GrpcProxyError> {
        let io = TokioIo::new(tcp);
        let builder = Self::build_h2_builder(pool_config);

        let (sender, conn) = builder.handshake(io).await.map_err(|e| {
            GrpcProxyError::BackendUnavailable(format!("h2c handshake failed: {}", e))
        })?;

        // Spawn the connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("gRPC h2c connection closed: {}", e);
            }
        });

        Ok(sender)
    }

    /// Create an h2 (TLS) connection with ALPN negotiation, mTLS, and custom CA bundles.
    async fn create_tls_connection(
        &self,
        tcp: TcpStream,
        host: &str,
        proxy: &Proxy,
        pool_config: &PoolConfig,
    ) -> Result<http2::SendRequest<Full<Bytes>>, GrpcProxyError> {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        // Build root certificate store:
        // - Custom CA configured → empty store + only that CA (no public roots)
        // - No CA configured → webpki/system roots as default fallback
        let ca_path = proxy
            .backend_tls_server_ca_cert_path
            .as_ref()
            .or(self.global_env_config.tls_ca_bundle_path.as_ref());
        let mut root_store = if ca_path.is_some() {
            rustls::RootCertStore::empty()
        } else {
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
        };

        if let Some(ca_bundle_path) = ca_path {
            let ca_pem = std::fs::read(ca_bundle_path).map_err(|e| {
                GrpcProxyError::Internal(format!(
                    "Failed to read CA bundle from {}: {}",
                    ca_bundle_path, e
                ))
            })?;
            let mut reader = std::io::BufReader::new(&ca_pem[..]);
            let certs = rustls_pemfile::certs(&mut reader);
            for cert in certs.flatten() {
                if let Err(e) = root_store.add(cert) {
                    warn!("gRPC: failed to add CA cert from bundle: {}", e);
                }
            }
            debug!("gRPC: loaded custom CA bundle from {}", ca_bundle_path);
        }

        // Load mTLS client certificate if configured (proxy-specific overrides take priority)
        let cert_path = proxy
            .backend_tls_client_cert_path
            .as_ref()
            .or(self.global_env_config.backend_tls_client_cert_path.as_ref());
        let key_path = proxy
            .backend_tls_client_key_path
            .as_ref()
            .or(self.global_env_config.backend_tls_client_key_path.as_ref());

        let tls_config = if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
            // Load client cert chain
            let cert_pem = std::fs::read(cert_path).map_err(|e| {
                GrpcProxyError::Internal(format!(
                    "Failed to read client cert from {}: {}",
                    cert_path, e
                ))
            })?;
            let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&cert_pem[..]))
                .flatten()
                .collect();

            // Load client private key
            let key_pem = std::fs::read(key_path).map_err(|e| {
                GrpcProxyError::Internal(format!(
                    "Failed to read client key from {}: {}",
                    key_path, e
                ))
            })?;
            let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(&key_pem[..]))
                .map_err(|e| {
                    GrpcProxyError::Internal(format!("Failed to parse client key: {}", e))
                })?
                .ok_or_else(|| {
                    GrpcProxyError::Internal(format!("No private key found in {}", key_path))
                })?;

            debug!(
                "gRPC: using mTLS client cert from {} and key from {}",
                cert_path, key_path
            );

            crate::tls::backend_client_config_builder(self.tls_policy.as_deref())
                .map_err(|e| GrpcProxyError::Internal(format!("TLS policy error: {}", e)))?
                .with_root_certificates(root_store)
                .with_client_auth_cert(certs, key)
                .map_err(|e| {
                    GrpcProxyError::Internal(format!("Invalid client certificate/key: {}", e))
                })?
        } else {
            crate::tls::backend_client_config_builder(self.tls_policy.as_deref())
                .map_err(|e| GrpcProxyError::Internal(format!("TLS policy error: {}", e)))?
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        // Apply remaining TLS options
        let mut tls_config = tls_config;

        // Force HTTP/2 via ALPN
        tls_config.alpn_protocols = vec![b"h2".to_vec()];

        // Skip server cert verification only if explicitly disabled or global no_verify
        if !proxy.backend_tls_verify_server_cert || self.global_env_config.tls_no_verify {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier));
        }

        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = ServerName::try_from(host.to_string()).map_err(|e| {
            GrpcProxyError::BackendUnavailable(format!("Invalid server name: {}", e))
        })?;

        let tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
            GrpcProxyError::BackendUnavailable(format!("TLS handshake failed: {}", e))
        })?;

        let io = TokioIo::new(tls_stream);
        let builder = Self::build_h2_builder(pool_config);

        let (sender, conn) = builder.handshake(io).await.map_err(|e| {
            GrpcProxyError::BackendUnavailable(format!("h2 handshake failed: {}", e))
        })?;

        // Spawn the connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("gRPC h2 TLS connection closed: {}", e);
            }
        });

        Ok(sender)
    }

    /// Start background cleanup task that evicts idle connections.
    fn start_cleanup_task(&self) {
        let entries = self.entries.clone();
        let idle_timeout_ms = self
            .global_pool_config
            .idle_timeout_seconds
            .saturating_mul(1000);
        let cleanup_secs = self.global_env_config.pool_cleanup_interval_seconds.max(1);

        tokio::spawn(async move {
            let mut cleanup_timer = tokio::time::interval(Duration::from_secs(cleanup_secs));

            loop {
                cleanup_timer.tick().await;

                let now = now_epoch_ms();
                let mut keys_to_remove = Vec::new();

                for entry in entries.iter() {
                    let last_used = entry.last_used_epoch_ms.load(Ordering::Relaxed);
                    let idle_ms = now.saturating_sub(last_used);

                    // Evict if idle too long or if the connection is already closed
                    if idle_ms > idle_timeout_ms || entry.sender.is_closed() {
                        keys_to_remove.push(entry.key().clone());
                    }
                }

                if !keys_to_remove.is_empty() {
                    debug!(
                        "gRPC pool cleanup: evicting {} idle/closed connections",
                        keys_to_remove.len()
                    );
                    for key in keys_to_remove {
                        entries.remove(&key);
                    }
                }
            }
        });
    }
}

/// Errors specific to gRPC proxying.
#[derive(Debug)]
pub enum GrpcProxyError {
    BackendUnavailable(String),
    BackendTimeout(String),
    Internal(String),
}

/// gRPC status codes for gateway-generated errors.
pub mod grpc_status {
    pub const DEADLINE_EXCEEDED: u32 = 4;
    pub const UNAVAILABLE: u32 = 14;
}

/// Build a gRPC error response with proper Trailers-Only encoding.
///
/// gRPC errors use HTTP 200 with `grpc-status` and `grpc-message` as headers
/// (Trailers-Only responses pack trailers into the header block).
pub fn build_grpc_error_response(status: u32, message: &str) -> hyper::Response<super::ProxyBody> {
    hyper::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .header("grpc-status", status.to_string())
        .header("grpc-message", message)
        .body(super::ProxyBody::empty())
        .unwrap_or_else(|_| hyper::Response::new(super::ProxyBody::empty()))
}

/// Collected gRPC response with body and trailers.
pub struct GrpcResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    /// Trailers (grpc-status, grpc-message, etc.) forwarded from backend
    pub trailers: HashMap<String, String>,
}

/// Streaming gRPC response — headers received, body streams frame-by-frame with trailers.
///
/// The `body` field is an `Incoming` body from hyper. When passed through as
/// a `ProxyBody::streaming_h2`, hyper's HTTP/2 server automatically forwards
/// DATA frames and TRAILERS frames to the downstream client as they arrive,
/// preserving gRPC streaming semantics without buffering the full response.
pub struct GrpcStreamingResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Incoming,
}

/// Either a fully-buffered or streaming gRPC response.
pub enum GrpcResponseKind {
    /// Response body was fully collected into memory (with trailers extracted).
    Buffered(GrpcResponse),
    /// Response headers received; body and trailers stream frame-by-frame.
    Streaming(GrpcStreamingResponse),
}

/// Proxy a gRPC request to the backend using hyper's HTTP/2 client.
///
/// Collects the incoming request body, then delegates to the core send logic.
/// Returns the collected request body bytes alongside the result so the caller
/// can replay them on retry.
///
/// When `stream_response` is true, the response body is NOT buffered — it is
/// returned as a live `Incoming` stream so frames flow frame-by-frame to the
/// downstream client. This is only safe when retries are NOT configured (the
/// body has already been consumed by the time we know if a retry is needed).
pub async fn proxy_grpc_request(
    req: Request<Incoming>,
    proxy: &Proxy,
    backend_url: &str,
    grpc_pool: &GrpcConnectionPool,
    dns_cache: &DnsCache,
    proxy_headers: &HashMap<String, String>,
    stream_response: bool,
) -> (Result<GrpcResponseKind, GrpcProxyError>, Bytes) {
    // Collect the incoming body for potential retry replay
    let (parts, body) = req.into_parts();
    let body_bytes = match BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            return (
                Err(GrpcProxyError::Internal(format!(
                    "Failed to read request body: {}",
                    e
                ))),
                Bytes::new(),
            );
        }
    };

    if stream_response {
        // Streaming — no retries possible, avoid clones
        let result = proxy_grpc_request_core(
            parts.method,
            parts.headers,
            body_bytes,
            proxy,
            backend_url,
            grpc_pool,
            dns_cache,
            proxy_headers,
            true,
        )
        .await;
        (result, Bytes::new()) // No body to return for retry
    } else {
        // Buffered — caller may retry, preserve body
        let result = proxy_grpc_request_core(
            parts.method.clone(),
            parts.headers.clone(),
            body_bytes.clone(),
            proxy,
            backend_url,
            grpc_pool,
            dns_cache,
            proxy_headers,
            false,
        )
        .await;
        (result, body_bytes)
    }
}

/// Proxy a gRPC request using pre-collected body bytes.
///
/// Used for retry attempts where the request body has already been buffered.
/// Always uses buffered mode — retries must be able to inspect the response.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_grpc_request_from_bytes(
    method: hyper::Method,
    headers: hyper::HeaderMap,
    body_bytes: Bytes,
    proxy: &Proxy,
    backend_url: &str,
    grpc_pool: &GrpcConnectionPool,
    dns_cache: &DnsCache,
    proxy_headers: &HashMap<String, String>,
) -> Result<GrpcResponseKind, GrpcProxyError> {
    // Retries always use buffered mode so the response can be inspected
    proxy_grpc_request_core(
        method,
        headers,
        body_bytes,
        proxy,
        backend_url,
        grpc_pool,
        dns_cache,
        proxy_headers,
        false,
    )
    .await
}

/// Core gRPC proxy logic shared by initial requests and retries.
///
/// When `stream_response` is true, returns `GrpcResponseKind::Streaming` with
/// the live `Incoming` body instead of buffering the full response. The caller
/// is responsible for ensuring this is only used when retries are not needed.
#[allow(clippy::too_many_arguments)]
async fn proxy_grpc_request_core(
    method: hyper::Method,
    mut headers: hyper::HeaderMap,
    body_bytes: Bytes,
    proxy: &Proxy,
    backend_url: &str,
    grpc_pool: &GrpcConnectionPool,
    dns_cache: &DnsCache,
    proxy_headers: &HashMap<String, String>,
    stream_response: bool,
) -> Result<GrpcResponseKind, GrpcProxyError> {
    // Get or create HTTP/2 connection to backend (round-robins across pool)
    let mut sender = grpc_pool.get_sender(proxy, dns_cache).await?;
    // Parse the backend URL to extract path and authority
    let uri: hyper::Uri = backend_url
        .parse()
        .map_err(|e| GrpcProxyError::Internal(format!("Invalid backend URL: {}", e)))?;

    // Clear hop-by-hop headers
    headers.remove("connection");
    headers.remove("transfer-encoding");

    // Apply proxy headers from the plugin pipeline (before_proxy transformations)
    for (k, v) in proxy_headers {
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }

    let mut backend_req = Request::new(Full::new(body_bytes));
    *backend_req.method_mut() = method;
    *backend_req.uri_mut() = uri;
    *backend_req.headers_mut() = headers;

    // Send to backend with read timeout
    let read_timeout = Duration::from_millis(proxy.backend_read_timeout_ms);
    let response = tokio::time::timeout(read_timeout, sender.send_request(backend_req))
        .await
        .map_err(|_| {
            warn!(
                "gRPC: read timeout ({}ms) waiting for backend response",
                proxy.backend_read_timeout_ms
            );
            GrpcProxyError::BackendTimeout(format!(
                "Read timeout after {}ms",
                proxy.backend_read_timeout_ms
            ))
        })?
        .map_err(|e| {
            error!("gRPC: backend request failed: {}", e);
            if e.is_timeout() {
                GrpcProxyError::BackendTimeout(format!("Backend timeout: {}", e))
            } else {
                GrpcProxyError::BackendUnavailable(format!("Backend error: {}", e))
            }
        })?;

    // Extract response status and headers
    let status = response.status().as_u16();
    let mut resp_headers = HashMap::with_capacity(response.headers().keys_len());
    for (k, v) in response.headers() {
        if let Ok(vs) = v.to_str() {
            resp_headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }

    // Streaming mode: return the live Incoming body without buffering.
    // The caller (mod.rs) wraps it in ProxyBody::streaming_h2 so hyper
    // forwards DATA frames and TRAILERS to the downstream client as they arrive.
    if stream_response {
        return Ok(GrpcResponseKind::Streaming(GrpcStreamingResponse {
            status,
            headers: resp_headers,
            body: response.into_body(),
        }));
    }

    // Buffered mode: collect body and extract trailers (also under read timeout).
    let body_capacity = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256);
    let mut body_bytes = Vec::with_capacity(body_capacity);
    let mut trailers = HashMap::new();

    let body_collection = async {
        let mut body = response.into_body();
        while let Some(frame_result) = body.frame().await {
            match frame_result {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        body_bytes.extend_from_slice(data);
                    } else if let Ok(trailer_map) = frame.into_trailers() {
                        for (k, v) in &trailer_map {
                            if let Ok(vs) = v.to_str() {
                                trailers.insert(k.as_str().to_string(), vs.to_string());
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("gRPC: error reading backend response frame: {}", e);
                    break;
                }
            }
        }
    };

    tokio::time::timeout(read_timeout, body_collection)
        .await
        .map_err(|_| {
            warn!(
                "gRPC: read timeout ({}ms) while collecting response body",
                proxy.backend_read_timeout_ms
            );
            GrpcProxyError::BackendTimeout(format!(
                "Body read timeout after {}ms",
                proxy.backend_read_timeout_ms
            ))
        })?;

    Ok(GrpcResponseKind::Buffered(GrpcResponse {
        status,
        headers: resp_headers,
        body: body_bytes,
        trailers,
    }))
}

/// Check if a request is a gRPC request based on content-type.
pub fn is_grpc_request(req: &Request<Incoming>) -> bool {
    is_grpc_content_type(req.headers())
}

/// Check if headers indicate a gRPC request (content-type starts with "application/grpc").
pub fn is_grpc_content_type(headers: &hyper::HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/grpc"))
}
