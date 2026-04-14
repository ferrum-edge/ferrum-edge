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
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, error, warn};

use crate::config::PoolConfig;
use crate::config::types::{BackendProtocol, Proxy};
use crate::dns::DnsCache;
use crate::tls::{NoVerifier, TlsPolicy};

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
    type Error = hyper::Error;

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
                            // Signal end-of-stream. The caller detects the
                            // exceeded flag and returns ResourceExhausted.
                            return Poll::Ready(None);
                        }
                    }
                    Poll::Ready(Some(Ok(frame)))
                }
                other => other,
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

/// Pool entry tracking a sender handle and its last-used timestamp.
struct GrpcPoolEntry {
    sender: http2::SendRequest<GrpcBody>,
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
    /// Certificate Revocation Lists for backend TLS verification.
    crls: crate::tls::CrlList,
    /// How long to wait for stream capacity on a live sender before opening a
    /// new backend connection shard.
    sender_ready_wait: Duration,
}

impl Default for GrpcConnectionPool {
    fn default() -> Self {
        Self::new(
            PoolConfig::default(),
            crate::config::EnvConfig::default(),
            None,
            Arc::new(Vec::new()),
        )
    }
}

impl GrpcConnectionPool {
    pub fn new(
        global_pool_config: PoolConfig,
        global_env_config: crate::config::EnvConfig,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
    ) -> Self {
        let sender_ready_wait = Duration::from_millis(global_env_config.grpc_pool_ready_wait_ms);
        let pool = Self {
            entries: Arc::new(DashMap::new()),
            rr_counters: Arc::new(DashMap::new()),
            global_pool_config,
            global_env_config,
            tls_policy,
            crls,
            sender_ready_wait,
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
    /// Writes the base key (without shard suffix) into `buf`. For shard keys,
    /// `write_shard_key_inplace()` appends `#N` by truncating to the base length.
    fn write_pool_key(buf: &mut String, proxy: &Proxy) {
        use std::fmt::Write;
        buf.clear();
        let tls = matches!(proxy.backend_protocol, BackendProtocol::Grpcs) as u8;
        let _ = write!(
            buf,
            "{}|{}|{}|",
            proxy.backend_host, proxy.backend_port, tls
        );
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

    /// Allocating version of the pool key — only used for warmup deduplication
    /// where the key must outlive the thread-local buffer.
    fn pool_key_owned(proxy: &Proxy) -> String {
        let mut buf = String::with_capacity(128);
        Self::write_pool_key(&mut buf, proxy);
        buf
    }

    /// Expose the base pool key for warmup deduplication (without shard suffix).
    pub(crate) fn pool_key_for_warmup(proxy: &Proxy) -> String {
        Self::pool_key_owned(proxy)
    }

    /// Append a shard suffix in-place by truncating to `base_len` first.
    /// Avoids clearing and rewriting the base key on every shard iteration.
    fn write_shard_key_inplace(buf: &mut String, base_len: usize, shard: usize) {
        buf.truncate(base_len);
        buf.push('#');
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
    ) -> Result<http2::SendRequest<GrpcBody>, GrpcProxyError> {
        let pool_config = self.global_pool_config.for_proxy(proxy);
        let shard_count = pool_config.http2_connections_per_host.max(1);

        // Build the base pool key and resolve the round-robin start shard.
        // The rr_counters lookup uses get() first (read-only, no allocation).
        // Only on the first request for a given base key does entry() allocate.
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

        // Two-phase readiness check (see Http2ConnectionPool::get_sender for rationale):
        // Phase 1: instant poll each shard without blocking.
        // Phase 2: if none ready, wait briefly on first live shard.
        let mut first_live_key: Option<String> = None;
        for offset in 0..shard_count {
            let shard = (start + offset) % shard_count;
            Self::write_shard_key_inplace(&mut key_buf, base_len, shard);

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
        // Keep this shorter than a typical successful unary gRPC round trip so
        // backpressure doesn't turn into queueing latency under load.
        if let Some(key) = first_live_key
            && let Some(entry) = self.entries.get(&key)
        {
            let mut sender = entry.sender.clone();
            drop(entry);
            match tokio::time::timeout(self.sender_ready_wait, sender.ready()).await {
                Ok(Ok(())) => return Ok(sender),
                Ok(Err(_)) => {
                    self.entries.remove(&key);
                }
                Err(_) => {
                    // Still not ready after the configured wait — fall through
                    // to create a new connection.
                }
            }
        }

        // No existing shard was ready — create a new connection.
        Self::write_shard_key_inplace(&mut key_buf, base_len, start);
        let sender = match self.create_connection(proxy, dns_cache).await {
            Ok(sender) => sender,
            Err(err) => {
                for offset in 1..shard_count {
                    let shard = (start + offset) % shard_count;
                    Self::write_shard_key_inplace(&mut key_buf, base_len, shard);
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
        Self::write_shard_key_inplace(&mut key_buf, base_len, start);
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
    ) -> Result<http2::SendRequest<GrpcBody>, GrpcProxyError> {
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
                GrpcProxyError::BackendUnavailable(format!("Connection failed: {}", e))
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

        // Build root certificate store:
        // - Custom CA configured → empty store + only that CA (no public roots)
        // - No CA configured → webpki/system roots as default fallback
        let ca_path = proxy
            .resolved_tls
            .server_ca_cert_path
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

        // Load mTLS client certificate if configured (resolved_tls overrides take priority)
        let cert_path = proxy
            .resolved_tls
            .client_cert_path
            .as_ref()
            .or(self.global_env_config.backend_tls_client_cert_path.as_ref());
        let key_path = proxy
            .resolved_tls
            .client_key_path
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

            let verifier = crate::tls::build_server_verifier_with_crls(root_store, &self.crls)
                .map_err(|e| GrpcProxyError::Internal(format!("CRL verifier error: {}", e)))?;
            crate::tls::backend_client_config_builder(self.tls_policy.as_deref())
                .map_err(|e| GrpcProxyError::Internal(format!("TLS policy error: {}", e)))?
                .with_webpki_verifier(verifier)
                .with_client_auth_cert(certs, key)
                .map_err(|e| {
                    GrpcProxyError::Internal(format!("Invalid client certificate/key: {}", e))
                })?
        } else {
            let verifier = crate::tls::build_server_verifier_with_crls(root_store, &self.crls)
                .map_err(|e| GrpcProxyError::Internal(format!("CRL verifier error: {}", e)))?;
            crate::tls::backend_client_config_builder(self.tls_policy.as_deref())
                .map_err(|e| GrpcProxyError::Internal(format!("TLS policy error: {}", e)))?
                .with_webpki_verifier(verifier)
                .with_no_client_auth()
        };

        // Apply remaining TLS options
        let mut tls_config = tls_config;

        // Force HTTP/2 via ALPN
        tls_config.alpn_protocols = vec![b"h2".to_vec()];

        // Skip server cert verification only if explicitly disabled or global no_verify
        if !proxy.resolved_tls.verify_server_cert || self.global_env_config.tls_no_verify {
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
    ResourceExhausted(String),
    Internal(String),
}

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
    dns_cache: &DnsCache,
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

    let effective_timeout_ms = match parse_grpc_timeout_ms(&headers) {
        Some(grpc_ms) => grpc_ms.min(proxy.backend_read_timeout_ms),
        None => proxy.backend_read_timeout_ms,
    };

    let uri: hyper::Uri = backend_url
        .parse()
        .map_err(|e| GrpcProxyError::Internal(format!("Invalid backend URL: {}", e)))?;

    let mut backend_req = Request::new(grpc_body);
    *backend_req.method_mut() = parts.method;
    *backend_req.uri_mut() = uri;
    *backend_req.headers_mut() = headers;

    let mut sender = grpc_pool.get_sender(proxy, dns_cache).await?;
    let read_timeout = Duration::from_millis(effective_timeout_ms);
    let response = tokio::time::timeout(read_timeout, sender.send_request(backend_req))
        .await
        .map_err(|_| {
            warn!(
                "gRPC: read timeout ({}ms) waiting for backend response (streaming request body)",
                effective_timeout_ms
            );
            GrpcProxyError::BackendTimeout(format!(
                "gRPC read timeout after {}ms",
                effective_timeout_ms
            ))
        })?
        .map_err(|e| {
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
