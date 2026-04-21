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

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, error, warn};

use crate::config::PoolConfig;
use crate::config::types::{BackendScheme, Proxy};
use crate::dns::{DnsCache, DnsConfig};
use crate::pool::{GenericPool, PoolManager};
use crate::tls::TlsPolicy;
use crate::tls::backend::{BackendTlsConfigBuilder, BackendTlsConfigCache};

/// Sum type for gRPC request bodies: either pre-buffered or streaming from the
/// client. This allows a single pool type (`SendRequest<GrpcBody>`) to handle
/// both buffered (retries, plugins) and streaming (zero-copy fast path) bodies.
pub enum GrpcBody {
    /// Complete body in memory (retries, plugin transforms).
    Buffered(Full<Bytes>),
    /// Streaming body from the client with inline size enforcement.
    /// When `max_bytes > 0`, tracks accumulated bytes and sets the shared
    /// `exceeded` flag if the limit is breached. The caller checks the flag
    /// after `send_request()` completes to return a proper gRPC error.
    Streaming {
        incoming: Incoming,
        bytes_seen: usize,
        max_bytes: usize,
        exceeded: Arc<AtomicBool>,
    },
}

impl http_body::Body for GrpcBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            GrpcBody::Buffered(full) => Pin::new(full)
                .poll_frame(cx)
                .map_err(|never| match never {}),
            GrpcBody::Streaming {
                incoming,
                bytes_seen,
                max_bytes,
                exceeded,
            } => match Pin::new(incoming).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if *max_bytes > 0
                        && let Some(data) = frame.data_ref()
                    {
                        *bytes_seen += data.len();
                        if *bytes_seen > *max_bytes {
                            exceeded.store(true, Ordering::Release);
                            // Return an error to RST_STREAM the request,
                            // preventing the backend from treating a truncated
                            // prefix as a completed stream.
                            return Poll::Ready(Some(Err(format!(
                                "gRPC request payload exceeds maximum of {} bytes",
                                max_bytes
                            )
                            .into())));
                        }
                    }
                    Poll::Ready(Some(Ok(frame)))
                }
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Box::new(e)))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            GrpcBody::Buffered(full) => full.is_end_stream(),
            GrpcBody::Streaming {
                incoming, exceeded, ..
            } => incoming.is_end_stream() || exceeded.load(Ordering::Relaxed),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            GrpcBody::Buffered(full) => full.size_hint(),
            GrpcBody::Streaming { incoming, .. } => incoming.size_hint(),
        }
    }
}

fn write_grpc_pool_key(buf: &mut String, host: &str, port: u16, proxy: &Proxy) {
    use std::fmt::Write;
    buf.clear();
    // TLS intent comes from the backend scheme; flavor (gRPC vs plain HTTP)
    // is detected at request time and doesn't affect pool identity — an
    // Https pool entry serves both gRPC and Plain requests.
    let tls = matches!(proxy.backend_scheme, Some(BackendScheme::Https)) as u8;
    let _ = write!(buf, "{}|{}|{}|", host, port, tls);
    buf.push_str(proxy.dns_override.as_deref().unwrap_or_default());
    buf.push('|');
    buf.push_str(
        proxy
            .resolved_tls
            .server_ca_cert_path
            .as_deref()
            .unwrap_or_default(),
    );
    buf.push('|');
    buf.push_str(
        proxy
            .resolved_tls
            .client_cert_path
            .as_deref()
            .unwrap_or_default(),
    );
    buf.push('|');
    buf.push(if proxy.resolved_tls.verify_server_cert {
        '1'
    } else {
        '0'
    });
}

fn grpc_pool_key_owned(proxy: &Proxy) -> String {
    let mut buf = String::with_capacity(128);
    write_grpc_pool_key(&mut buf, &proxy.backend_host, proxy.backend_port, proxy);
    buf
}

fn write_grpc_shard_key_inplace(buf: &mut String, base_len: usize, shard: usize) {
    buf.truncate(base_len);
    buf.push('#');
    if shard < 10 {
        buf.push((b'0' + shard as u8) as char);
    } else {
        use std::fmt::Write;
        let _ = write!(buf, "{shard}");
    }
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
    pool: Arc<GenericPool<GrpcPoolManager>>,
    rr_counters: Arc<DashMap<String, Arc<AtomicUsize>>>,
}

#[derive(Clone)]
struct GrpcPoolManager {
    global_pool_config: PoolConfig,
    global_env_config: crate::config::EnvConfig,
    dns_cache: DnsCache,
    tls_policy: Option<Arc<TlsPolicy>>,
    crls: crate::tls::CrlList,
    tls_configs: BackendTlsConfigCache,
}

impl Default for GrpcConnectionPool {
    fn default() -> Self {
        Self::new(
            PoolConfig::default(),
            crate::config::EnvConfig::default(),
            DnsCache::new(DnsConfig::default()),
            None,
            Arc::new(Vec::new()),
        )
    }
}

impl GrpcConnectionPool {
    pub fn new(
        global_pool_config: PoolConfig,
        global_env_config: crate::config::EnvConfig,
        dns_cache: DnsCache,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
    ) -> Self {
        let cleanup_interval =
            Duration::from_secs(global_env_config.pool_cleanup_interval_seconds.max(1));
        let manager = Arc::new(GrpcPoolManager {
            global_pool_config: global_pool_config.clone(),
            global_env_config,
            dns_cache,
            tls_policy,
            crls,
            tls_configs: BackendTlsConfigCache::new(),
        });

        Self {
            pool: GenericPool::new(manager, global_pool_config, cleanup_interval),
            rr_counters: Arc::new(DashMap::new()),
        }
    }

    /// Number of connections in the pool (for metrics).
    pub fn pool_size(&self) -> usize {
        self.pool.pool_size()
    }

    /// ⚠️  CRITICAL — DO NOT add fields to this key without careful analysis.
    /// Adding fields causes pool fragmentation and P95 latency regressions.
    /// See `ConnectionPool::create_pool_key` for detailed rationale.
    ///
    /// Includes all fields that affect connection *identity*: destination,
    /// TLS mode, DNS override, CA cert, mTLS client cert, and server cert verification.
    /// Uses `|` as field delimiter to avoid ambiguity with `:` in IPv6 addresses.
    ///
    /// Writes the base key (without shard suffix) into `buf`. For shard keys,
    /// `write_shard_key_inplace()` appends `#N` by truncating to the base length.
    fn write_pool_key(buf: &mut String, proxy: &Proxy) {
        write_grpc_pool_key(buf, &proxy.backend_host, proxy.backend_port, proxy);
    }

    /// Allocating version of the pool key — only used for warmup deduplication
    /// where the key must outlive the thread-local buffer. Currently unused
    /// post-refactor (gRPC pool warms lazily); retained for future re-enablement.
    #[allow(dead_code)]
    fn pool_key_owned(proxy: &Proxy) -> String {
        grpc_pool_key_owned(proxy)
    }

    /// Expose the base pool key for warmup deduplication (without shard suffix).
    /// Currently unused post-refactor; see `pool_key_owned`.
    #[allow(dead_code)]
    pub(crate) fn pool_key_for_warmup(proxy: &Proxy) -> String {
        Self::pool_key_owned(proxy)
    }

    /// Append a shard suffix in-place by truncating to `base_len` first.
    /// Avoids clearing and rewriting the base key on every shard iteration.
    fn write_shard_key_inplace(buf: &mut String, base_len: usize, shard: usize) {
        write_grpc_shard_key_inplace(buf, base_len, shard);
    }

    pub async fn get_sender(
        &self,
        proxy: &Proxy,
    ) -> Result<http2::SendRequest<GrpcBody>, GrpcProxyError> {
        let manager = self.pool.manager();
        let pool_config = manager.global_pool_config.for_proxy(proxy);
        let shard_count = pool_config.http2_connections_per_host.max(1);

        let mut key_buf = String::with_capacity(128);
        Self::write_pool_key(&mut key_buf, proxy);
        let base_len = key_buf.len();

        let rr = match self.rr_counters.get(&key_buf) {
            Some(existing) => existing.value().clone(),
            None => self
                .rr_counters
                .entry(key_buf[..base_len].to_owned())
                .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
                .clone(),
        };
        let start = rr.fetch_add(1, Ordering::Relaxed) % shard_count;
        let sender_ready_wait =
            Duration::from_millis(manager.global_env_config.grpc_pool_ready_wait_ms);

        let mut first_live: Option<(String, http2::SendRequest<GrpcBody>)> = None;
        for offset in 0..shard_count {
            let shard = (start + offset) % shard_count;
            Self::write_shard_key_inplace(&mut key_buf, base_len, shard);

            if let Some(mut sender) = self.pool.cached(&key_buf) {
                match futures_util::FutureExt::now_or_never(sender.ready()) {
                    Some(Ok(())) => return Ok(sender),
                    Some(Err(_)) => self.pool.invalidate(&key_buf),
                    None => {
                        if first_live.is_none() {
                            first_live = Some((key_buf.clone(), sender));
                        }
                    }
                }
            }
        }

        if let Some((key, mut sender)) = first_live {
            match tokio::time::timeout(sender_ready_wait, sender.ready()).await {
                Ok(Ok(())) => return Ok(sender),
                Ok(Err(_)) => self.pool.invalidate(&key),
                Err(_) => {}
            }
        }

        Self::write_shard_key_inplace(&mut key_buf, base_len, start);
        let selected_key = key_buf.clone();
        let manager = Arc::clone(self.pool.manager());
        match self
            .pool
            .create_or_get_existing_owned(selected_key, |key| async move {
                let _ = key;
                manager.create_connection(proxy).await
            })
            .await
        {
            Ok(sender) => Ok(sender),
            Err(err) => {
                for offset in 1..shard_count {
                    let shard = (start + offset) % shard_count;
                    Self::write_shard_key_inplace(&mut key_buf, base_len, shard);
                    if let Some(sender) = self.pool.cached(&key_buf) {
                        return Ok(sender);
                    }
                }
                Err(err)
            }
        }
    }
}

impl GrpcPoolManager {
    fn get_tls_config(&self, proxy: &Proxy) -> Result<Arc<rustls::ClientConfig>, GrpcProxyError> {
        self.tls_configs
            .get_or_try_build(grpc_pool_key_owned(proxy), || {
                let mut tls_config = BackendTlsConfigBuilder {
                    proxy,
                    policy: self.tls_policy.as_deref(),
                    global_ca: self
                        .global_env_config
                        .tls_ca_bundle_path
                        .as_deref()
                        .map(Path::new),
                    global_no_verify: self.global_env_config.tls_no_verify,
                    global_client_cert: self
                        .global_env_config
                        .backend_tls_client_cert_path
                        .as_deref()
                        .map(Path::new),
                    global_client_key: self
                        .global_env_config
                        .backend_tls_client_key_path
                        .as_deref()
                        .map(Path::new),
                    crls: &self.crls,
                }
                .build_rustls()
                .map_err(|e| {
                    GrpcProxyError::Internal(format!("Failed to build backend TLS config: {}", e))
                })?;

                tls_config.alpn_protocols = vec![b"h2".to_vec()];
                Ok(tls_config)
            })
    }

    async fn create_connection(
        &self,
        proxy: &Proxy,
    ) -> Result<http2::SendRequest<GrpcBody>, GrpcProxyError> {
        let host = &proxy.backend_host;
        let port = proxy.backend_port;

        // Resolve backend hostname via the shared DNS cache. Errors propagate
        // — no silent fallback to raw hostname that would bypass the cache.
        let resolved_ip = self
            .dns_cache
            .resolve(
                host,
                proxy.dns_override.as_deref(),
                proxy.dns_cache_ttl_seconds,
            )
            .await
            .map_err(|e| {
                GrpcProxyError::BackendUnavailable(format!(
                    "DNS resolution failed for {}: {}",
                    host, e
                ))
            })?;

        // Construct SocketAddr from the resolved IpAddr + port directly.
        // This handles both IPv4 and IPv6 correctly without string formatting
        // issues (IPv6 addresses from IpAddr::to_string() are unbracketed,
        // which breaks "ip:port" string parsing).
        let sock_addr = std::net::SocketAddr::new(resolved_ip, port);
        let addr = sock_addr.to_string();
        let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);

        // Connect with timeout, using TcpSocket to set IP_BIND_ADDRESS_NO_PORT
        // before connect() so the kernel can co-select ephemeral ports.
        let tcp = tokio::time::timeout(
            connect_timeout,
            crate::socket_opts::connect_with_socket_opts(sock_addr),
        )
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
            if crate::retry::is_port_exhaustion(&e) {
                tracing::error!(
                    "gRPC: PORT EXHAUSTION connecting to backend {}: {} — \
                         reduce outbound connection rate or increase net.ipv4.ip_local_port_range",
                    addr,
                    e
                );
            } else {
                warn!("gRPC: failed to connect to backend {}: {}", addr, e);
            }
            GrpcProxyError::BackendUnavailable(format!("Connection failed: {}", e))
        })?;

        // Disable Nagle for lower latency
        let _ = tcp.set_nodelay(true);

        // Apply TCP keepalive using per-proxy pool config
        let pool_config = self.global_pool_config.for_proxy(proxy);
        if pool_config.enable_http_keep_alive {
            Self::set_tcp_keepalive(&tcp, pool_config.tcp_keepalive_seconds);
        }

        let use_tls = matches!(proxy.backend_scheme, Some(BackendScheme::Https));

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
        #[cfg(unix)]
        use std::os::fd::AsFd;
        #[cfg(windows)]
        use std::os::windows::io::AsSocket;

        #[cfg(unix)]
        let borrowed = stream.as_fd();
        #[cfg(windows)]
        let borrowed = stream.as_socket();
        let socket = socket2::SockRef::from(&borrowed);
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
    ) -> Result<http2::SendRequest<GrpcBody>, GrpcProxyError> {
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
    ) -> Result<http2::SendRequest<GrpcBody>, GrpcProxyError> {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let tls_config = self.get_tls_config(proxy)?;
        let connector = TlsConnector::from(tls_config);
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
}

#[async_trait]
impl PoolManager for GrpcPoolManager {
    type Connection = http2::SendRequest<GrpcBody>;

    fn build_key(&self, proxy: &Proxy, host: &str, port: u16, shard: usize, buf: &mut String) {
        write_grpc_pool_key(buf, host, port, proxy);
        let base_len = buf.len();
        write_grpc_shard_key_inplace(buf, base_len, shard);
    }

    async fn create(&self, _key: &str, proxy: &Proxy) -> Result<http2::SendRequest<GrpcBody>> {
        self.create_connection(proxy)
            .await
            .map_err(anyhow::Error::from)
    }

    fn is_healthy(&self, conn: &Self::Connection) -> bool {
        !conn.is_closed()
    }

    fn destroy(&self, conn: Self::Connection) {
        drop(conn);
    }
}

/// Errors specific to gRPC proxying.
#[derive(Debug)]
pub enum GrpcProxyError {
    BackendUnavailable(String),
    BackendTimeout(String),
    ResourceExhausted(String),
    Internal(String),
}

impl std::fmt::Display for GrpcProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendUnavailable(msg)
            | Self::BackendTimeout(msg)
            | Self::ResourceExhausted(msg)
            | Self::Internal(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for GrpcProxyError {}

/// gRPC status codes for gateway-generated errors.
pub mod grpc_status {
    pub const INVALID_ARGUMENT: u32 = 3;
    pub const DEADLINE_EXCEEDED: u32 = 4;
    pub const NOT_FOUND: u32 = 5;
    pub const PERMISSION_DENIED: u32 = 7;
    pub const RESOURCE_EXHAUSTED: u32 = 8;
    pub const FAILED_PRECONDITION: u32 = 9;
    pub const ABORTED: u32 = 10;
    pub const UNIMPLEMENTED: u32 = 12;
    pub const INTERNAL: u32 = 13;
    pub const UNAVAILABLE: u32 = 14;
    pub const UNAUTHENTICATED: u32 = 16;
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
/// a `CoalescingH2Body`, hyper's HTTP/2 server forwards coalesced DATA frames
/// and TRAILERS frames to the downstream client as they arrive,
/// preserving gRPC streaming semantics without buffering the full response.
pub struct GrpcStreamingResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Incoming,
    /// Set to `true` if the streaming request body exceeded
    /// `max_grpc_recv_size_bytes`. The response body consumer should check
    /// this flag and abort the response if set — the backend received a
    /// truncated request so the response is likely invalid.
    pub request_body_exceeded: Option<Arc<AtomicBool>>,
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
#[allow(clippy::too_many_arguments)]
pub async fn proxy_grpc_request(
    req: Request<Incoming>,
    proxy: &Proxy,
    backend_url: &str,
    grpc_pool: &GrpcConnectionPool,
    dns_cache: &DnsCache,
    proxy_headers: &HashMap<String, String>,
    stream_response: bool,
    max_grpc_recv_size_bytes: usize,
) -> (Result<GrpcResponseKind, GrpcProxyError>, Bytes) {
    // Collect the incoming body for potential retry replay
    let (parts, body) = req.into_parts();
    let body_bytes = if max_grpc_recv_size_bytes > 0 {
        // Use http_body_util::Limited to enforce max gRPC recv size during body collection
        let limited = http_body_util::Limited::new(body, max_grpc_recv_size_bytes);
        match BodyExt::collect(limited).await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("length limit exceeded") {
                    return (
                        Err(GrpcProxyError::ResourceExhausted(format!(
                            "gRPC request payload size exceeds maximum of {} bytes",
                            max_grpc_recv_size_bytes
                        ))),
                        Bytes::new(),
                    );
                }
                return (
                    Err(GrpcProxyError::Internal(format!(
                        "Failed to read request body: {}",
                        e
                    ))),
                    Bytes::new(),
                );
            }
        }
    } else {
        match BodyExt::collect(body).await {
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

/// Proxy a gRPC request by streaming the request body directly to the backend
/// without collecting it into memory first.
///
/// Used on the fast path when no plugins need the request body and no retries
/// are configured. The response is always streamed (since no retries are possible
/// when the request body has already been consumed).
///
/// Request body size limits (`max_grpc_recv_size_bytes`) are enforced inline via
/// byte counting in `GrpcBody::Streaming`. Each frame's size is accumulated and
/// the stream errors if the limit is exceeded, causing the H2 connection to reset.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_grpc_request_streaming(
    req: Request<Incoming>,
    proxy: &Proxy,
    backend_url: &str,
    grpc_pool: &GrpcConnectionPool,
    _dns_cache: &DnsCache,
    proxy_headers: &HashMap<String, String>,
    max_grpc_recv_size_bytes: usize,
) -> Result<GrpcResponseKind, GrpcProxyError> {
    let (parts, body) = req.into_parts();
    let body_size_exceeded = Arc::new(AtomicBool::new(false));
    let grpc_body = GrpcBody::Streaming {
        incoming: body,
        bytes_seen: 0,
        max_bytes: max_grpc_recv_size_bytes,
        exceeded: Arc::clone(&body_size_exceeded),
    };

    // Build headers, apply proxy transforms
    let mut headers = parts.headers;
    headers.remove("connection");
    headers.remove("transfer-encoding");
    for (k, v) in proxy_headers {
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }

    // For the streaming path, send_request() covers both body upload and
    // response header wait. Unlike the buffered path (where body sends
    // instantly so backend_read_timeout_ms ≈ response wait), the streaming
    // timeout must account for upload time.
    //
    // When a gRPC deadline is set: use it directly WITHOUT capping by
    // backend_read_timeout_ms. The client's deadline covers the entire RPC
    // lifecycle including upload — capping it would penalize large uploads
    // that the client explicitly budgeted time for.
    //
    // When no gRPC deadline is set: fall back to backend_read_timeout_ms
    // as a safety net against indefinitely stalled backends. Slow uploads
    // without deadlines should be bounded.
    let effective_timeout_ms = match parse_grpc_timeout_ms(&headers) {
        Some(grpc_ms) => grpc_ms,
        None => proxy.backend_read_timeout_ms,
    };

    let uri: hyper::Uri = backend_url
        .parse()
        .map_err(|e| GrpcProxyError::Internal(format!("Invalid backend URL: {}", e)))?;

    let mut backend_req = Request::new(grpc_body);
    *backend_req.method_mut() = parts.method;
    *backend_req.uri_mut() = uri;
    *backend_req.headers_mut() = headers;

    let mut sender = grpc_pool.get_sender(proxy).await?;
    let read_timeout = Duration::from_millis(effective_timeout_ms);
    let response = tokio::time::timeout(read_timeout, sender.send_request(backend_req))
        .await
        .map_err(|_| {
            warn!(
                "gRPC: timeout ({}ms) waiting for streaming RPC completion",
                effective_timeout_ms
            );
            GrpcProxyError::BackendTimeout(format!(
                "gRPC streaming RPC timeout after {}ms",
                effective_timeout_ms
            ))
        })?
        .map_err(|e| {
            // Check if the failure was caused by the request body exceeding the
            // size limit. The GrpcBody::Streaming error triggers an h2 stream
            // reset which surfaces here as a send_request error. Return
            // ResourceExhausted instead of BackendUnavailable so clients get
            // the correct gRPC status code.
            if body_size_exceeded.load(Ordering::Acquire) {
                return GrpcProxyError::ResourceExhausted(format!(
                    "gRPC request payload size exceeds maximum of {} bytes",
                    max_grpc_recv_size_bytes
                ));
            }
            error!("gRPC backend request failed (streaming body): {}", e);
            GrpcProxyError::BackendUnavailable(format!("Backend request failed: {}", e))
        })?;

    // Check if the request body already exceeded the limit before response
    // headers arrived. If so, fail immediately with a clear error.
    if body_size_exceeded.load(Ordering::Acquire) {
        return Err(GrpcProxyError::ResourceExhausted(format!(
            "gRPC request payload size exceeds maximum of {} bytes",
            max_grpc_recv_size_bytes
        )));
    }

    // Return streaming response with the exceeded flag so the response body
    // consumer can detect late-arriving size violations (bidi/client-streaming
    // RPCs where request frames continue after response headers arrive).
    let status = response.status().as_u16();
    let mut resp_headers = HashMap::with_capacity(response.headers().keys_len());
    for (k, v) in response.headers() {
        if let Ok(vs) = v.to_str() {
            resp_headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }
    Ok(GrpcResponseKind::Streaming(GrpcStreamingResponse {
        status,
        headers: resp_headers,
        body: response.into_body(),
        request_body_exceeded: if max_grpc_recv_size_bytes > 0 {
            Some(body_size_exceeded)
        } else {
            None
        },
    }))
}

/// Collect the incoming gRPC request body and split the `Request<Incoming>` into
/// its constituent parts for separate validation and dispatch.
///
/// This is used when plugins require request body buffering for gRPC proxies
/// (e.g., protobuf validation). The body bytes, method, and headers are returned
/// so the caller can run plugin hooks before dispatching via `proxy_grpc_request_core`.
pub async fn collect_grpc_request_body(
    req: Request<Incoming>,
    max_grpc_recv_size_bytes: usize,
) -> Result<(hyper::Method, hyper::HeaderMap, Bytes), GrpcProxyError> {
    let (parts, body) = req.into_parts();
    let body_bytes = if max_grpc_recv_size_bytes > 0 {
        let limited = http_body_util::Limited::new(body, max_grpc_recv_size_bytes);
        match BodyExt::collect(limited).await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("length limit exceeded") {
                    return Err(GrpcProxyError::ResourceExhausted(format!(
                        "gRPC request payload size exceeds maximum of {} bytes",
                        max_grpc_recv_size_bytes
                    )));
                }
                return Err(GrpcProxyError::Internal(format!(
                    "Failed to read request body: {}",
                    e
                )));
            }
        }
    } else {
        BodyExt::collect(body)
            .await
            .map_err(|e| GrpcProxyError::Internal(format!("Failed to read request body: {}", e)))?
            .to_bytes()
    };
    Ok((parts.method, parts.headers, body_bytes))
}

/// Core gRPC proxy logic shared by initial requests and retries.
///
/// When `stream_response` is true, returns `GrpcResponseKind::Streaming` with
/// the live `Incoming` body instead of buffering the full response. The caller
/// is responsible for ensuring this is only used when retries are not needed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_grpc_request_core(
    method: hyper::Method,
    mut headers: hyper::HeaderMap,
    body_bytes: Bytes,
    proxy: &Proxy,
    backend_url: &str,
    grpc_pool: &GrpcConnectionPool,
    _dns_cache: &DnsCache,
    proxy_headers: &HashMap<String, String>,
    stream_response: bool,
) -> Result<GrpcResponseKind, GrpcProxyError> {
    // Get or create HTTP/2 connection to backend (round-robins across pool)
    let mut sender = grpc_pool.get_sender(proxy).await?;
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

    // Parse gRPC deadline AFTER proxy_headers merge so that before_proxy plugins
    // that add/replace/remove grpc-timeout are reflected in the effective timeout.
    // Cap by the proxy's backend_read_timeout_ms so client deadlines propagate
    // without exceeding the operator-configured maximum.
    let effective_timeout_ms = match parse_grpc_timeout_ms(&headers) {
        Some(grpc_ms) => grpc_ms.min(proxy.backend_read_timeout_ms),
        None => proxy.backend_read_timeout_ms,
    };

    let mut backend_req = Request::new(GrpcBody::Buffered(Full::new(body_bytes)));
    *backend_req.method_mut() = method;
    *backend_req.uri_mut() = uri;
    *backend_req.headers_mut() = headers;
    let read_timeout = Duration::from_millis(effective_timeout_ms);
    let response = tokio::time::timeout(read_timeout, sender.send_request(backend_req))
        .await
        .map_err(|_| {
            warn!(
                "gRPC: read timeout ({}ms) waiting for backend response",
                effective_timeout_ms
            );
            GrpcProxyError::BackendTimeout(format!("Read timeout after {}ms", effective_timeout_ms))
        })?
        .map_err(|e| {
            error!("gRPC: backend request failed: {}", e);
            if e.is_timeout() {
                GrpcProxyError::BackendTimeout(format!("Backend timeout: {}", e))
            } else {
                GrpcProxyError::BackendUnavailable(format!("Backend error: {}", e))
            }
        })?;

    // Extract response status and headers, stripping hop-by-hop headers per RFC 9110 §7.6.1.
    let status = response.status().as_u16();
    let mut resp_headers = HashMap::with_capacity(response.headers().keys_len());
    for (k, v) in response.headers() {
        match k.as_str() {
            "connection" | "keep-alive" | "proxy-authenticate" | "proxy-connection" | "te"
            | "trailer" | "transfer-encoding" | "upgrade" => continue,
            _ => {}
        }
        if let Ok(vs) = v.to_str() {
            resp_headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }

    // Streaming mode: return the live Incoming body without buffering.
    // The caller (mod.rs) wraps it in CoalescingH2Body so hyper
    // forwards DATA frames and TRAILERS to the downstream client as they arrive.
    if stream_response {
        return Ok(GrpcResponseKind::Streaming(GrpcStreamingResponse {
            status,
            headers: resp_headers,
            body: response.into_body(),
            request_body_exceeded: None, // buffered request body — already fully sent
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

/// Parse the `grpc-timeout` header value into milliseconds.
///
/// Format: `{value}{unit}` where unit is one of:
///   H (hours), M (minutes), S (seconds), m (milliseconds),
///   u (microseconds), n (nanoseconds)
///
/// Returns `None` if the header is absent, malformed, or the value is 0.
/// Per the gRPC spec, the timeout is a positive integer followed by a unit suffix.
pub fn parse_grpc_timeout_ms(headers: &hyper::HeaderMap) -> Option<u64> {
    let val = headers.get("grpc-timeout")?.to_str().ok()?;
    let bytes = val.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    // The unit suffix is always a single ASCII byte per the gRPC spec.
    // Split on the last byte to avoid panicking on multi-byte UTF-8 input.
    let unit = *bytes.last()?;
    let num_str = std::str::from_utf8(&bytes[..bytes.len() - 1]).ok()?;
    let num: u64 = num_str.parse().ok()?;
    if num == 0 {
        return None;
    }
    let ms = match unit {
        b'H' => num.checked_mul(3_600_000),
        b'M' => num.checked_mul(60_000),
        b'S' => num.checked_mul(1_000),
        b'm' => Some(num),
        b'u' => Some(num / 1_000), // microseconds → ms, floor to 0 is handled by max(1) below
        b'n' => Some(num / 1_000_000),
        _ => None,
    }?;
    // Ensure at least 1ms for sub-millisecond timeouts
    Some(ms.max(1))
}
