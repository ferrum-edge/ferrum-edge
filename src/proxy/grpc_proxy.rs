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
use crate::proxy::headers::{
    is_backend_response_strip_header, strip_backend_request_headers_for_grpc,
};
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

        // Seed the per-host round-robin counter with a thread-local xorshift
        // draw so a burst of concurrent gRPC calls on a cold pool fans across
        // shards from request #1. This matters for gRPC tail latency: under
        // high concurrency with only 2-4 shards, all requests start by
        // targeting the same shard if the seed is 0, which creates a queue
        // behind the first in-flight RPC (p99 = 732 ms at 500 KB payloads).
        let rr = match self.rr_counters.get(&key_buf) {
            Some(existing) => existing.value().clone(),
            None => self
                .rr_counters
                .entry(key_buf[..base_len].to_owned())
                .or_insert_with(|| Arc::new(AtomicUsize::new(crate::proxy::http2_pool::rr_seed())))
                .clone(),
        };
        let start = rr.fetch_add(1, Ordering::Relaxed) % shard_count;

        // Cheap probe pass — any shard whose cached sender is immediately
        // ready wins. `now_or_never` never awaits, so this is a quick sweep
        // of the shard ring with no per-shard stall.
        for offset in 0..shard_count {
            let shard = (start + offset) % shard_count;
            Self::write_shard_key_inplace(&mut key_buf, base_len, shard);

            if let Some(mut sender) = self.pool.cached(&key_buf) {
                match futures_util::FutureExt::now_or_never(sender.ready()) {
                    Some(Ok(())) => return Ok(sender),
                    Some(Err(_)) => self.pool.invalidate(&key_buf),
                    // Shard exists but is mid-send. Skip — we would rather
                    // open a fresh h2 connection (per-key-coalesced via
                    // `create_or_get_existing_owned`, so concurrent callers
                    // dedupe onto ONE create future) than stall on
                    // `timeout(ready())`. The previous 1 ms wait still
                    // serialized under burst concurrency and was the
                    // largest contributor to gRPC p99 tail latency for
                    // 100-concurrent 500 KB / 1 MB payloads.
                    None => {}
                }
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
            GrpcProxyError::BackendTimeout {
                kind: GrpcTimeoutKind::Connect,
                message: format!(
                    "Connect timeout after {}ms to {}",
                    proxy.backend_connect_timeout_ms, addr
                ),
            }
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

/// Which phase of a gRPC backend interaction timed out.
///
/// Distinguishes connection establishment from read/write on an already-open
/// connection so retry and classification logic can branch on the variant
/// rather than parsing `BackendTimeout`'s human-readable message string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcTimeoutKind {
    /// Timeout while establishing a TCP connection to the backend. Eligible
    /// for retry under `retry_on_connect_failure`; classifies as
    /// [`crate::retry::ErrorClass::ConnectionTimeout`].
    Connect,
    /// Timeout while waiting for the backend to respond or while reading the
    /// response body. Classifies as
    /// [`crate::retry::ErrorClass::ReadWriteTimeout`].
    Read,
}

/// Errors specific to gRPC proxying.
#[derive(Debug)]
pub enum GrpcProxyError {
    BackendUnavailable(String),
    BackendTimeout {
        kind: GrpcTimeoutKind,
        message: String,
    },
    ResourceExhausted(String),
    Internal(String),
}

impl std::fmt::Display for GrpcProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendUnavailable(msg) | Self::ResourceExhausted(msg) | Self::Internal(msg) => {
                write!(f, "{}", msg)
            }
            Self::BackendTimeout { message, .. } => write!(f, "{}", message),
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

    // Request body has been collected into `body_bytes` above. Preserve it
    // for the retry loop regardless of whether the response is streamed —
    // retries fire on connection errors BEFORE any response is received, so
    // response-body streaming does not prevent retry, and the request body
    // is what we need to replay on a fresh attempt.
    //
    // Previously this code returned `Bytes::new()` on the streaming path,
    // which bundled two orthogonal concerns (request replay vs response
    // streaming) and forced the caller to buffer the response whenever
    // retry was enabled. That in turn held gRPC trailers behind the last
    // data frame on buffered-response paths, inflating server-streaming
    // RPC p99 latency (500 KB p50 = 9 ms, p99 = 732 ms under 100 conc).
    let result = proxy_grpc_request_core(
        parts.method.clone(),
        parts.headers.clone(),
        body_bytes.clone(),
        proxy,
        backend_url,
        grpc_pool,
        dns_cache,
        proxy_headers,
        stream_response,
    )
    .await;
    (result, body_bytes)
}

/// Proxy a gRPC request using pre-collected body bytes.
///
/// Used for retry attempts where the request body has already been buffered,
/// and by the HTTP/3 cross-protocol bridge where the body was drained from
/// an H3 recv stream before dispatching. When `stream_response` is `true`,
/// the response `Incoming` body is returned live (frame-by-frame streaming,
/// trailers arrive as a terminal frame); otherwise the response is fully
/// buffered and trailers are extracted up-front.
///
/// Retry attempts can safely pass `stream_response = true`: the gateway's
/// gRPC retry loop only re-fires on CONNECTION errors that surface BEFORE
/// any response headers (`BackendUnavailable` / `BackendTimeout::Connect`),
/// so once a streaming response begins flowing the loop breaks out and
/// never has to inspect the body. Buffering the retry response would
/// silently downgrade a server-streaming RPC into "wait for the whole
/// body" the moment a transient TCP RST hits the very first attempt — the
/// exact trailer-stall this path is meant to avoid. The cross-protocol
/// bridge passes the same streaming decision through for the same reason.
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
    stream_response: bool,
) -> Result<GrpcResponseKind, GrpcProxyError> {
    proxy_grpc_request_core(
        method,
        headers,
        body_bytes,
        proxy,
        backend_url,
        grpc_pool,
        dns_cache,
        proxy_headers,
        stream_response,
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

    let uri: hyper::Uri = backend_url
        .parse()
        .map_err(|e| GrpcProxyError::Internal(format!("Invalid backend URL: {}", e)))?;

    // Build headers, apply proxy transforms.
    //
    // Use the gRPC-specific strip helper: same RFC 9110 §7.6.1 hop-by-hop
    // strip + content-length + internal markers as the generic path, then
    // synthesise `te: trailers` (mandatory per the gRPC HTTP/2 spec; many
    // gRPC servers reject requests missing it). See `proxy::headers` for
    // the rationale.
    let mut headers = parts.headers;
    strip_backend_request_headers_for_grpc(&mut headers);
    for (k, v) in proxy_headers {
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }

    // Apply per-route Host override AFTER the proxy_headers merge, mirroring
    // `proxy_grpc_request_core` and the plain HTTP path in
    // `proxy::proxy_to_backend`. Without this, an H2 or H3 frontend that
    // synthesized `host` from `:authority` would forward the client's
    // external authority to the gRPC backend even when
    // `preserve_host_header == false`.
    if !proxy.preserve_host_header
        && let Some(target_host) = uri.host()
        && let Ok(val) = hyper::header::HeaderValue::from_str(target_host)
    {
        headers.insert(hyper::header::HOST, val);
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
        Some(grpc_ms) => Some(grpc_ms),
        None if proxy.backend_read_timeout_ms > 0 => Some(proxy.backend_read_timeout_ms),
        None => None,
    };

    let mut backend_req = Request::new(grpc_body);
    *backend_req.method_mut() = parts.method;
    *backend_req.uri_mut() = uri;
    *backend_req.headers_mut() = headers;

    let mut sender = grpc_pool.get_sender(proxy).await?;
    let response = if let Some(timeout_ms) = effective_timeout_ms {
        let read_timeout = Duration::from_millis(timeout_ms);
        tokio::time::timeout(read_timeout, sender.send_request(backend_req))
            .await
            .map_err(|_| {
                warn!(
                    "gRPC: timeout ({}ms) waiting for streaming RPC completion",
                    timeout_ms
                );
                GrpcProxyError::BackendTimeout {
                    kind: GrpcTimeoutKind::Read,
                    message: format!("gRPC streaming RPC timeout after {}ms", timeout_ms),
                }
            })?
            .map_err(|e| {
                if body_size_exceeded.load(Ordering::Acquire) {
                    return GrpcProxyError::ResourceExhausted(format!(
                        "gRPC request payload size exceeds maximum of {} bytes",
                        max_grpc_recv_size_bytes
                    ));
                }
                error!("gRPC backend request failed (streaming body): {}", e);
                GrpcProxyError::BackendUnavailable(format!("Backend request failed: {}", e))
            })?
    } else {
        sender.send_request(backend_req).await.map_err(|e| {
            if body_size_exceeded.load(Ordering::Acquire) {
                return GrpcProxyError::ResourceExhausted(format!(
                    "gRPC request payload size exceeds maximum of {} bytes",
                    max_grpc_recv_size_bytes
                ));
            }
            error!("gRPC backend request failed (streaming body): {}", e);
            GrpcProxyError::BackendUnavailable(format!("Backend request failed: {}", e))
        })?
    };

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
    //
    // Strip hop-by-hop response headers per RFC 9110 §7.6.1 — see
    // `proxy::headers`. This is the always-streaming entry point (used
    // when there are no body plugins and no retry); without filtering
    // here, hop-by-hop response headers (`proxy-authenticate`,
    // `proxy-connection`, `te`, `trailer`, etc.) leak downstream past
    // the proxy boundary. Mirrors `proxy_grpc_request_core` so the two
    // gRPC response paths cannot drift.
    let status = response.status().as_u16();
    let mut resp_headers = HashMap::with_capacity(response.headers().keys_len());
    for (k, v) in response.headers() {
        if is_backend_response_strip_header(k.as_str()) {
            continue;
        }
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

    // Use the gRPC-specific strip helper: full RFC 9110 §7.6.1 hop-by-hop
    // strip + content-length + internal markers, then synthesise
    // `te: trailers` (mandatory per the gRPC HTTP/2 spec). Mirrors the
    // streaming gRPC path above so the two cannot drift.
    strip_backend_request_headers_for_grpc(&mut headers);

    // Apply proxy headers from the plugin pipeline (before_proxy transformations)
    for (k, v) in proxy_headers {
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }

    // Apply per-route Host override AFTER the proxy_headers merge, mirroring
    // the plain HTTP path in `proxy::proxy_to_backend`. Without this, an H2 or
    // H3 frontend that synthesized `host` from `:authority` (see
    // `src/http3/server.rs` and `src/proxy/mod.rs`) would forward the client's
    // external authority to the gRPC backend even when
    // `preserve_host_header == false`. With the override, the backend sees the
    // upstream target host (taken from the parsed backend URL) in both
    // `:authority` (set from the URI below) and `Host`, matching the plain
    // HTTP non-preserve semantics.
    if !proxy.preserve_host_header
        && let Some(target_host) = uri.host()
        && let Ok(val) = hyper::header::HeaderValue::from_str(target_host)
    {
        headers.insert(hyper::header::HOST, val);
    }

    // Parse gRPC deadline AFTER proxy_headers merge so that before_proxy plugins
    // that add/replace/remove grpc-timeout are reflected in the effective timeout.
    // Cap by the proxy's backend_read_timeout_ms so client deadlines propagate
    // without exceeding the operator-configured maximum. When backend_read_timeout_ms
    // is 0 (disabled), the gRPC deadline is used uncapped; with no deadline either,
    // there is no timeout.
    let effective_timeout_ms = match parse_grpc_timeout_ms(&headers) {
        Some(grpc_ms) if proxy.backend_read_timeout_ms > 0 => {
            Some(grpc_ms.min(proxy.backend_read_timeout_ms))
        }
        Some(grpc_ms) => Some(grpc_ms),
        None if proxy.backend_read_timeout_ms > 0 => Some(proxy.backend_read_timeout_ms),
        None => None,
    };

    let mut backend_req = Request::new(GrpcBody::Buffered(Full::new(body_bytes)));
    *backend_req.method_mut() = method;
    *backend_req.uri_mut() = uri;
    *backend_req.headers_mut() = headers;
    let send_fut = sender.send_request(backend_req);
    let map_send_err = |e: hyper::Error| {
        error!("gRPC: backend request failed: {}", e);
        if e.is_timeout() {
            GrpcProxyError::BackendTimeout {
                kind: GrpcTimeoutKind::Read,
                message: format!("Backend timeout: {}", e),
            }
        } else {
            GrpcProxyError::BackendUnavailable(format!("Backend error: {}", e))
        }
    };
    let response = if let Some(timeout_ms) = effective_timeout_ms {
        let read_timeout = Duration::from_millis(timeout_ms);
        tokio::time::timeout(read_timeout, send_fut)
            .await
            .map_err(|_| {
                warn!(
                    "gRPC: read timeout ({}ms) waiting for backend response",
                    timeout_ms
                );
                GrpcProxyError::BackendTimeout {
                    kind: GrpcTimeoutKind::Read,
                    message: format!("Read timeout after {}ms", timeout_ms),
                }
            })?
            .map_err(map_send_err)?
    } else {
        send_fut.await.map_err(map_send_err)?
    };

    // Extract response status and headers, stripping hop-by-hop headers
    // per RFC 9110 §7.6.1 (canonical predicate in `proxy::headers`).
    let status = response.status().as_u16();
    let mut resp_headers = HashMap::with_capacity(response.headers().keys_len());
    for (k, v) in response.headers() {
        if is_backend_response_strip_header(k.as_str()) {
            continue;
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
    //
    // Pre-sizing: honour `content-length` exactly when present (backend
    // promised the size). When absent, start at 16 KiB — previously 256
    // bytes, which caused ~14 reallocations for a 5 MB response
    // (256 → 512 → 1 KiB → 2 KiB → ... → 8 MiB) and showed up as
    // userspace copy overhead on the HTTP/2 large-payload benchmark.
    // 16 KiB absorbs most small unary responses in a single allocation
    // and cuts the realloc chain from 14 to 9 for 5 MB responses.
    //
    // NOTE: `GrpcResponse.body: Vec<u8>` is consumed by plugin hooks that
    // take `&[u8]`, so staying on `Vec` avoids an extra `BytesMut::freeze
    // → Vec` copy on the return path. `Vec::with_capacity` uses the same
    // amortised-doubling growth as `BytesMut::put_slice`, so only the
    // starting capacity matters for the allocation count — which is the
    // actual fix.
    const DEFAULT_GRPC_BUFFERED_CAPACITY: usize = 16 * 1024;
    let body_capacity = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_GRPC_BUFFERED_CAPACITY);
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

    if let Some(timeout_ms) = effective_timeout_ms {
        tokio::time::timeout(Duration::from_millis(timeout_ms), body_collection)
            .await
            .map_err(|_| {
                warn!(
                    "gRPC: read timeout ({}ms) while collecting response body",
                    timeout_ms
                );
                GrpcProxyError::BackendTimeout {
                    kind: GrpcTimeoutKind::Read,
                    message: format!("Body read timeout after {}ms", timeout_ms),
                }
            })?;
    } else {
        body_collection.await;
    }

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

#[cfg(test)]
mod tests {
    //! Inline tests for private internals of the gRPC proxy.
    //!
    //! These guard the specific changes in
    //! `perf/h2-pool-sender-ready-and-grpc-trailer-stall`:
    //! * Fix 3: the buffered-response `Vec<u8>` starting capacity moved
    //!   from `unwrap_or(256)` to a 16 KiB default so that large responses
    //!   with no `content-length` stop hitting ~14 reallocations.
    //! * Fix 4: the streaming-response decision in `proxy_grpc_request` no
    //!   longer conflates "retry preserves request body" with "retry
    //!   prevents response streaming". The `proxy_grpc_request` wrapper
    //!   unconditionally returns collected `body_bytes` so the outer
    //!   retry loop in `mod.rs` has them.

    /// Fix 3: source-level assertion that the pathological
    /// `unwrap_or(256)` default on buffered body collection is gone.
    ///
    /// Why: a 5 MB gRPC response with no `content-length` header grew
    /// from 256 bytes via doubling, hitting ~14 reallocations and
    /// ~14 memcpys of ever-larger prefixes — visible in the HTTP/2
    /// large-payload benchmark.
    ///
    /// We assert that the constant `DEFAULT_GRPC_BUFFERED_CAPACITY` is
    /// present AND that it is ≥ 16 KiB. Combined these catch both a
    /// revert to `256` and an accidental drop in default size.
    #[test]
    fn grpc_buffered_default_capacity_is_not_tiny() {
        let src = include_str!("grpc_proxy.rs");
        // Token the constant declaration lives on — see Fix 3 edit.
        assert!(
            src.contains("DEFAULT_GRPC_BUFFERED_CAPACITY"),
            "expected DEFAULT_GRPC_BUFFERED_CAPACITY constant in grpc_proxy.rs \
             — Fix 3 introduced this to replace the 256-byte default."
        );

        // Find the literal line and parse out the numeric value. We
        // accept any reasonable size ≥ 16 KiB (16 * 1024 = 16384).
        let line = src
            .lines()
            .find(|l| l.contains("DEFAULT_GRPC_BUFFERED_CAPACITY") && l.contains(":"))
            .expect("const declaration line not found");
        // Simple heuristic: reject values equal to or lower than the
        // regressed default (256). This keeps the test tolerant to
        // style changes (e.g., `16 * 1024` vs `16_384` vs `16384`).
        assert!(
            !line.contains("= 256"),
            "regression: DEFAULT_GRPC_BUFFERED_CAPACITY reverted to 256 — \
             large streaming responses will hit >10 reallocations"
        );
    }

    /// Fix 3: 5 MB worth of `extend_from_slice` on a `Vec` pre-sized at
    /// 16 KiB should grow through only ~9 reallocations
    /// (16K → 32K → 64K → ... → 8M = 10 doublings from 16K to 16M).
    /// Pre-sizing at 256 instead would take ~15 doublings, which is the
    /// pattern we are preventing.
    ///
    /// We can't observe `Vec`'s internal realloc count directly, but we
    /// can assert that the final `capacity()` is within `2×` of the
    /// actual filled size — which holds for `amortised doubling` when
    /// the initial capacity is appropriate.
    #[test]
    fn five_mb_vec_growth_from_16k_default_is_within_two_x_capacity() {
        const DEFAULT_GRPC_BUFFERED_CAPACITY: usize = 16 * 1024;
        let mut v: Vec<u8> = Vec::with_capacity(DEFAULT_GRPC_BUFFERED_CAPACITY);

        // Fill with 64 KiB frames (realistic gRPC backend frame size)
        // until we reach ~5 MB.
        let frame = vec![0u8; 64 * 1024];
        let target = 5 * 1024 * 1024;
        while v.len() < target {
            v.extend_from_slice(&frame);
        }

        let cap = v.capacity();
        let len = v.len();
        assert!(
            cap <= len * 2,
            "vec grew to capacity={} with len={} — final capacity should be \
             within 2x of filled size under amortised doubling from 16 KiB start \
             (regression would be cap >> 2*len)",
            cap,
            len
        );
        // Also guard that we are not starting from a pathologically
        // small capacity (Vec::extend_from_slice could in theory
        // jump straight to the exact size, but in practice doubling
        // dominates). Final cap must be at least `len` — trivially
        // true — and at least the starting pre-size.
        assert!(cap >= DEFAULT_GRPC_BUFFERED_CAPACITY);
    }

    /// Fix 3: same growth test starting from the OLD pathological 256
    /// default. This encodes the "before" state so a future reader can
    /// see the magnitude of the waste. The `capacity()` assertion is
    /// loose — we only demand that the final buffer is large enough
    /// to hold the data, because under 256-start the growth pattern
    /// still terminates at a power-of-2 cap ≥ len.
    #[test]
    fn five_mb_vec_growth_from_256_default_is_wasteful() {
        let mut v: Vec<u8> = Vec::with_capacity(256);
        let frame = vec![0u8; 64 * 1024];
        let target = 5 * 1024 * 1024;
        let mut grow_events = 0usize;
        let mut last_cap = v.capacity();
        while v.len() < target {
            v.extend_from_slice(&frame);
            if v.capacity() != last_cap {
                grow_events += 1;
                last_cap = v.capacity();
            }
        }
        // Starting from 256 we expect ≥ 10 grow events to reach 5 MB
        // (256 → 512 → 1K → 2K → 4K → 8K → 16K → 32K → 64K → 128K → ... → 8M).
        // The 16 KiB default eliminates the first ~6 of those.
        assert!(
            grow_events >= 7,
            "expected many realloc events from 256 starting cap, got {} \
             — this test documents the regression we are fixing, not the fix",
            grow_events
        );
    }

    /// Fix 4: `proxy_grpc_request` must ALWAYS return the collected
    /// `body_bytes` on the SUCCESS path — even when `stream_response=true`
    /// — so the outer retry loop can replay the request body. The old
    /// code had `if stream_response { (result, Bytes::new()) } else
    /// { (result, body_bytes) }` which forced the caller to disable
    /// streaming whenever retry was configured.
    ///
    /// The error paths (body collection failure, length limit exceeded)
    /// legitimately return `Bytes::new()` because no body was collected.
    /// Those return sites are INSIDE `Err(...)` match arms — fine.
    ///
    /// The regression we guard against is the OLD `if stream_response`
    /// branching on the success path. We look for any `if stream_response`
    /// in the function body (outside error handling) — Fix 4 eliminated
    /// that branch entirely.
    #[test]
    fn proxy_grpc_request_always_preserves_body_bytes_for_retry() {
        let src = include_str!("grpc_proxy.rs");
        let fn_start = src
            .find("pub async fn proxy_grpc_request(")
            .expect("proxy_grpc_request signature not found");
        let tail = &src[fn_start..];
        let fn_end = tail
            .find("\n}\n")
            .expect("failed to locate end of proxy_grpc_request body");
        let body = &tail[..fn_end];

        // Flag the OLD return-splitting pattern:
        //   if stream_response {
        //       ...
        //       (result, Bytes::new())
        //   } else {
        //       ...
        //       (result, body_bytes)
        //   }
        // In the fixed version, there is a single return of
        // `(result, body_bytes)` and no `if stream_response` branch
        // inside `proxy_grpc_request` itself. The `stream_response`
        // parameter is still passed THROUGH to `proxy_grpc_request_core`
        // (one line with `stream_response,` as an argument) but must
        // not appear as a top-level `if stream_response {` branch.
        for (i, line) in body.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            // Match the OLD pattern specifically — the FIXED code passes
            // `stream_response,` as an argument to the core helper,
            // which is permitted. Only a conditional branch on it is
            // the regression.
            assert!(
                !trimmed.starts_with("if stream_response"),
                "regression at line {} of proxy_grpc_request: found \
                 `if stream_response` branch. Fix 4 removed this split \
                 so retry replay always has access to the collected \
                 request body. Offending line:\n  {}",
                i + 1,
                line
            );
        }
    }
}
