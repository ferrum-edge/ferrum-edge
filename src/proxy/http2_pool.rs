//! HTTP/2 connection pool using hyper's HTTP/2 client directly.
//!
//! Provides proper HTTP/2 stream multiplexing over a single persistent TLS
//! connection, avoiding the connection-per-request churn that reqwest exhibits
//! under concurrent load. Modeled on the `GrpcConnectionPool` pattern.
//!
//! Used when a proxy has `backend_protocol: https` and `pool_enable_http2: true`.

use dashmap::DashMap;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::PoolConfig;
use crate::config::types::Proxy;
use crate::dns::DnsCache;
use crate::tls::backend::BackendTlsConfigBuilder;
use crate::tls::TlsPolicy;

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Pool entry tracking a sender handle and its last-used timestamp.
struct Http2PoolEntry {
    sender: http2::SendRequest<Incoming>,
    last_used_epoch_ms: Arc<AtomicU64>,
}

/// HTTP/2 connection pool for HTTPS backends.
///
/// Manages reusable HTTP/2 connections with proper stream multiplexing.
/// Unlike the reqwest-based `ConnectionPool`, this uses hyper's HTTP/2 client
/// directly to multiplex concurrent requests over a single TLS connection,
/// eliminating the TLS handshake overhead that reqwest incurs under load.
///
/// Honors the same configuration as the HTTP pool:
/// - Global `PoolConfig` from environment variables
/// - Per-proxy overrides (`pool_*` fields on `Proxy`)
/// - Global mTLS and CA bundle settings from `EnvConfig`
/// - Background idle connection cleanup
pub struct Http2ConnectionPool {
    /// Cached sender handles keyed by `host:port#shard`
    entries: Arc<DashMap<String, Http2PoolEntry>>,
    /// Round-robin counters keyed by base backend host:port.
    rr_counters: Arc<DashMap<String, Arc<AtomicUsize>>>,
    /// Global pool configuration (idle timeout, keepalive, etc.)
    global_pool_config: PoolConfig,
    /// Global TLS/mTLS configuration
    global_env_config: crate::config::EnvConfig,
    /// TLS hardening policy for backend connections (cipher suites, protocol versions).
    tls_policy: Option<Arc<TlsPolicy>>,
    /// Certificate Revocation Lists for backend TLS verification.
    crls: crate::tls::CrlList,
}

impl Default for Http2ConnectionPool {
    fn default() -> Self {
        Self::new(
            PoolConfig::default(),
            crate::config::EnvConfig::default(),
            None,
            Arc::new(Vec::new()),
        )
    }
}

impl Http2ConnectionPool {
    pub fn new(
        global_pool_config: PoolConfig,
        global_env_config: crate::config::EnvConfig,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
    ) -> Self {
        let pool = Self {
            entries: Arc::new(DashMap::new()),
            rr_counters: Arc::new(DashMap::new()),
            global_pool_config,
            global_env_config,
            tls_policy,
            crls,
        };

        pool.start_cleanup_task();
        pool
    }

    /// Number of connections in the pool (for metrics).
    pub fn pool_size(&self) -> usize {
        self.entries.len()
    }

    /// Pool key — includes all fields that affect connection identity.
    /// Uses `|` as delimiter to avoid ambiguity with `:` in IPv6 addresses.
    /// Writes into `buf` to allow thread-local reuse on the hot path.
    fn write_pool_key(buf: &mut String, proxy: &Proxy) {
        use std::fmt::Write;
        buf.clear();
        let _ = write!(buf, "{}|{}|", proxy.backend_host, proxy.backend_port);
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
    pub fn pool_key_for_warmup(proxy: &Proxy) -> String {
        Self::pool_key_owned(proxy)
    }

    /// Build a shard key by appending the shard index to a pre-allocated buffer.
    /// Reuses the same buffer across calls to minimize allocations.
    /// Internally superseded by `write_shard_key_inplace`; kept public for
    /// external test verification of the shard key format.
    #[allow(dead_code)]
    pub fn write_shard_key(buf: &mut String, base_key: &str, shard: usize) {
        buf.clear();
        buf.push_str(base_key);
        buf.push('#');
        if shard < 10 {
            buf.push((b'0' + shard as u8) as char);
        } else {
            use std::fmt::Write;
            let _ = write!(buf, "{shard}");
        }
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

    /// Get or create an HTTP/2 connection to the HTTPS backend.
    ///
    /// Returns a sender that has been `ready()`-checked, meaning the H2
    /// connection has capacity for at least one more stream. This is critical
    /// for scaling under high concurrency: without the readiness check, all
    /// concurrent requests pile onto one sender and exceed
    /// `MAX_CONCURRENT_STREAMS`, causing stream resets and errors.
    ///
    /// When the selected shard's sender is not ready (back-pressure), we
    /// try other shards round-robin before blocking, spreading load across
    /// all pooled connections.
    pub async fn get_sender(
        &self,
        proxy: &Proxy,
        dns_cache: &DnsCache,
    ) -> Result<http2::SendRequest<Incoming>, Http2PoolError> {
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

        // Two-phase readiness check:
        //
        // Phase 1 (zero-cost): poll each shard's sender once without blocking.
        //   At low concurrency, the sender is almost always immediately ready,
        //   so this returns in nanoseconds with no timeout overhead.
        //
        // Phase 2 (back-pressure): if no shard was instantly ready, re-scan
        //   with a short timeout per shard, giving each H2 connection a chance
        //   to free a stream slot before we fall through to creating a new connection.
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

                // Instant poll — no timer, no allocation, just check if ready now
                match futures_util::FutureExt::now_or_never(sender.ready()) {
                    Some(Ok(())) => return Ok(sender),
                    Some(Err(_)) => {
                        // Connection error — evict and try next shard
                        self.entries.remove(&key_buf);
                        continue;
                    }
                    None => {
                        // Not ready yet — remember this shard for phase 2
                        if first_live_key.is_none() {
                            first_live_key = Some(key_buf.clone());
                        }
                    }
                }
            }
        }

        // Phase 2: no shard was instantly ready (high concurrency / back-pressure).
        // Wait briefly on the first live shard for a stream slot to free up.
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

        // No existing shard was ready — create a new connection on the
        // originally selected shard.
        Self::write_shard_key_inplace(&mut key_buf, base_len, start);
        let sender = match self.create_connection(proxy, dns_cache).await {
            Ok(sender) => sender,
            Err(err) => {
                // Connection failed — try to find any live shard as fallback
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
        let sender = match self.entries.entry(key_buf) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                if occupied.get().sender.is_closed() {
                    occupied.insert(Http2PoolEntry {
                        sender: sender.clone(),
                        last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
                    });
                    sender
                } else {
                    occupied.get().sender.clone()
                }
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(Http2PoolEntry {
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
    ) -> Result<http2::SendRequest<Incoming>, Http2PoolError> {
        let host = &proxy.backend_host;
        let port = proxy.backend_port;

        // Resolve backend hostname via the shared DNS cache. Errors propagate
        // — no silent fallback to raw hostname that would bypass the cache.
        let resolved_ip = dns_cache
            .resolve(
                host,
                proxy.dns_override.as_deref(),
                proxy.dns_cache_ttl_seconds,
            )
            .await
            .map_err(|e| Http2PoolError::BackendUnavailable {
                message: format!("DNS resolution failed for {}: {}", host, e),
                source: Some(BackendUnavailableSource::Dns),
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
                "http2_pool: connect timeout ({}ms) to backend {}",
                proxy.backend_connect_timeout_ms, addr
            );
            // Synthesize an io::Error so downstream classification can walk
            // the typed chain instead of string-matching "timeout".
            Http2PoolError::BackendTimeout {
                message: format!(
                    "Connect timeout after {}ms to {}",
                    proxy.backend_connect_timeout_ms, addr
                ),
                source: Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "backend connect timed out",
                )),
            }
        })?
        .map_err(|e| {
            if crate::retry::is_port_exhaustion(&e) {
                tracing::error!(
                    "http2_pool: PORT EXHAUSTION connecting to backend {}: {} — \
                         reduce outbound connection rate or increase net.ipv4.ip_local_port_range",
                    addr,
                    e
                );
            } else {
                warn!("http2_pool: failed to connect to backend {}: {}", addr, e);
            }
            // Preserve the typed io::Error so classify_http2_pool_error() can
            // walk the source chain (ErrorKind::ConnectionRefused, raw_os_error
            // for EADDRNOTAVAIL, etc.) regardless of Display wording.
            Http2PoolError::BackendUnavailable {
                message: format!("Connection refused: {}", e),
                source: Some(BackendUnavailableSource::Io(e)),
            }
        })?;

        // Disable Nagle for lower latency
        let _ = tcp.set_nodelay(true);

        // Apply TCP keepalive using per-proxy pool config
        let pool_config = self.global_pool_config.for_proxy(proxy);
        if pool_config.enable_http_keep_alive {
            Self::set_tcp_keepalive(&tcp, pool_config.tcp_keepalive_seconds);
        }

        self.create_tls_connection(tcp, host, proxy, &pool_config)
            .await
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
            debug!("http2_pool: failed to set TCP keepalive: {}", e);
        }
    }

    /// Create an h2 (TLS) connection with ALPN negotiation, mTLS, and custom CA bundles.
    async fn create_tls_connection(
        &self,
        tcp: TcpStream,
        host: &str,
        proxy: &Proxy,
        pool_config: &PoolConfig,
    ) -> Result<http2::SendRequest<Incoming>, Http2PoolError> {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let mut tls_config = BackendTlsConfigBuilder {
            proxy,
            policy: self.tls_policy.as_deref(),
            global_ca: self.global_env_config.tls_ca_bundle_path.as_deref().map(Path::new),
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
        .map_err(|e| Http2PoolError::Internal {
            message: format!("Failed to build backend TLS config: {}", e),
            source: Some(InternalSource::Message(e.to_string())),
        })?;

        tls_config.alpn_protocols = vec![b"h2".to_vec()];

        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = ServerName::try_from(host.to_string()).map_err(|e| {
            // Invalid SNI server name is a configuration/DNS problem, not a
            // transient backend issue — classify as DNS lookup.
            Http2PoolError::BackendUnavailable {
                message: format!("Invalid server name: {}", e),
                source: Some(BackendUnavailableSource::InvalidDnsName),
            }
        })?;

        let tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
            Http2PoolError::BackendUnavailable {
                message: format!("TLS handshake failed: {}", e),
                source: Some(BackendUnavailableSource::Tls(e)),
            }
        })?;

        let io = TokioIo::new(tls_stream);
        let builder = Self::build_h2_builder(pool_config);

        let (sender, conn) =
            builder
                .handshake(io)
                .await
                .map_err(|e| Http2PoolError::BackendUnavailable {
                    message: format!("h2 handshake failed: {}", e),
                    source: Some(BackendUnavailableSource::Hyper(e)),
                })?;

        // Spawn the connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("http2_pool: TLS connection closed: {}", e);
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
                        "http2_pool cleanup: evicting {} idle/closed connections",
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

/// Classify an `Http2PoolError` into the shared `ErrorClass` taxonomy.
///
/// Prefers **typed source-chain classification** — walks `std::error::Error::source()`
/// looking for `io::Error` kinds (ConnectionRefused, ConnectionReset, TimedOut,
/// BrokenPipe, EADDRNOTAVAIL) and `hyper::Error` variants, mirroring
/// `classify_http3_error`. Falls back to string heuristics only when no typed
/// cause is present (e.g., `Internal` variants with a message-only source, or
/// `BackendUnavailable::Dns` / `InvalidDnsName` markers that don't carry a
/// concrete error value).
///
/// Without this, classification was fragile — swapping `"refused"` for
/// `"denied"` in a wrapper would have silently changed the `error_class` label.
pub fn classify_http2_pool_error(err: &Http2PoolError) -> crate::retry::ErrorClass {
    use crate::retry::ErrorClass;

    // 1. Walk the typed source chain first — covers io::Error, hyper::Error,
    //    rustls::Error anywhere in the nested chain.
    if let Some(cls) = classify_typed_chain(err) {
        return cls;
    }

    // 2. Marker variants that intentionally do not carry a concrete error
    //    value (DNS resolution failed inside the cache, InvalidDnsName parse
    //    error from rustls ServerName).
    match err {
        Http2PoolError::BackendUnavailable {
            source: Some(BackendUnavailableSource::Dns),
            ..
        } => return ErrorClass::DnsLookupError,
        Http2PoolError::BackendUnavailable {
            source: Some(BackendUnavailableSource::InvalidDnsName),
            ..
        } => return ErrorClass::DnsLookupError,
        _ => {}
    }

    // 3. Internal variants with a Message-only source (no typed cause) — the
    //    message came from our own error builders (CRL / TLS policy / etc.)
    //    so it is always ConnectionPoolError territory.
    if matches!(
        err,
        Http2PoolError::Internal {
            source: Some(InternalSource::Message(_)) | None,
            ..
        }
    ) {
        return ErrorClass::ConnectionPoolError;
    }

    // 4. Last-resort string fallback — preserved for completeness so hand-
    //    crafted tests with bare `BackendUnavailable { source: None }` still
    //    get a meaningful classification. Production paths always populate
    //    a source.
    let message = match err {
        Http2PoolError::BackendUnavailable { message, .. } => message,
        Http2PoolError::BackendTimeout { message, .. } => message,
        Http2PoolError::Internal { message, .. } => message,
    };
    let lower = message.to_ascii_lowercase();

    match err {
        Http2PoolError::BackendTimeout { .. } => {
            if lower.contains("connect") {
                ErrorClass::ConnectionTimeout
            } else {
                ErrorClass::ReadWriteTimeout
            }
        }
        Http2PoolError::BackendUnavailable { .. } => {
            if crate::retry::is_port_exhaustion_message(&lower) {
                ErrorClass::PortExhaustion
            } else if lower.contains("dns") || lower.contains("resolve") {
                ErrorClass::DnsLookupError
            } else if lower.contains("tls")
                || lower.contains("certificate")
                || lower.contains("handshake")
            {
                ErrorClass::TlsError
            } else if lower.contains("refused") {
                ErrorClass::ConnectionRefused
            } else if lower.contains("reset") {
                ErrorClass::ConnectionReset
            } else if lower.contains("broken pipe") || lower.contains("closed") {
                ErrorClass::ConnectionClosed
            } else if lower.contains("goaway") || lower.contains("protocol") {
                ErrorClass::ProtocolError
            } else {
                ErrorClass::ConnectionPoolError
            }
        }
        Http2PoolError::Internal { .. } => ErrorClass::ConnectionPoolError,
    }
}

/// Walk the error source chain, mapping the first recognisable typed variant
/// to an `ErrorClass`. Returns `None` when the chain carries no io/hyper/rustls
/// variant that the taxonomy can pin down.
fn classify_typed_chain(err: &Http2PoolError) -> Option<crate::retry::ErrorClass> {
    use crate::retry::ErrorClass;

    // For the BackendTimeout marker we want to return ConnectionTimeout even
    // if the chain only contains a synthesized TimedOut io::Error — consult
    // the variant up-front.
    let timeout_is_connect = matches!(err, Http2PoolError::BackendTimeout { .. });

    // First hop: inspect the immediate `BackendUnavailableSource` so we can
    // map the `Tls` marker to `TlsError` directly. After that we walk the
    // generic source chain looking for io/hyper/rustls variants.
    //
    // Note: once inside `classify_chain_from` we trust typed io::ErrorKind
    // signals — so `Tls(io::Error { kind: ConnectionReset, ... })` would
    // classify as ConnectionReset, which is correct (a TLS session that
    // died mid-stream on a reset *is* a reset, not a handshake failure).
    // Only generic `Other` / `InvalidData` wrappers fall through to the
    // TLS marker override below.
    match err {
        Http2PoolError::BackendUnavailable {
            source: Some(BackendUnavailableSource::Tls(io_err)),
            ..
        } => {
            // Let typed ErrorKind win if set, otherwise fall back to TlsError.
            if let Some(cls) = classify_io_error(io_err, timeout_is_connect) {
                return Some(cls);
            }
            return Some(ErrorClass::TlsError);
        }
        Http2PoolError::BackendUnavailable {
            source: Some(BackendUnavailableSource::Hyper(hyper_err)),
            ..
        } => {
            if let Some(cls) = classify_hyper_error(hyper_err) {
                return Some(cls);
            }
            // Walk the hyper error's source chain for an inner io::Error.
            let mut current: Option<&(dyn std::error::Error + 'static)> =
                std::error::Error::source(hyper_err as &dyn std::error::Error);
            while let Some(node) = current {
                if let Some(io_err) = node.downcast_ref::<std::io::Error>()
                    && let Some(cls) = classify_io_error(io_err, timeout_is_connect)
                {
                    return Some(cls);
                }
                current = node.source();
            }
            return Some(ErrorClass::ProtocolError);
        }
        _ => {}
    }

    // General source-chain walk — handles BackendUnavailable::Io,
    // BackendTimeout, and any Internal::Io / Internal::Rustls paths.
    classify_chain_from(
        std::error::Error::source(err as &dyn std::error::Error),
        timeout_is_connect,
    )
}

/// Walk an `std::error::Error` chain starting at `start`, returning the first
/// classification we can pin down from a typed node.
fn classify_chain_from(
    start: Option<&(dyn std::error::Error + 'static)>,
    timeout_is_connect: bool,
) -> Option<crate::retry::ErrorClass> {
    use crate::retry::ErrorClass;
    let mut current = start;
    while let Some(node) = current {
        if let Some(io_err) = node.downcast_ref::<std::io::Error>()
            && let Some(cls) = classify_io_error(io_err, timeout_is_connect)
        {
            return Some(cls);
        }
        if let Some(hyper_err) = node.downcast_ref::<hyper::Error>()
            && let Some(cls) = classify_hyper_error(hyper_err)
        {
            return Some(cls);
        }
        if node.downcast_ref::<rustls::Error>().is_some() {
            return Some(ErrorClass::TlsError);
        }
        current = node.source();
    }
    None
}

fn classify_io_error(
    io_err: &std::io::Error,
    timeout_is_connect: bool,
) -> Option<crate::retry::ErrorClass> {
    use crate::retry::ErrorClass;
    if matches!(io_err.raw_os_error(), Some(99) | Some(49) | Some(10049)) {
        return Some(ErrorClass::PortExhaustion);
    }
    match io_err.kind() {
        std::io::ErrorKind::TimedOut => Some(if timeout_is_connect {
            ErrorClass::ConnectionTimeout
        } else {
            ErrorClass::ReadWriteTimeout
        }),
        std::io::ErrorKind::ConnectionRefused => Some(ErrorClass::ConnectionRefused),
        std::io::ErrorKind::ConnectionReset => Some(ErrorClass::ConnectionReset),
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionAborted => {
            Some(ErrorClass::ConnectionClosed)
        }
        // Generic kinds (Other, InvalidData, etc.) commonly wrap
        // TLS / protocol errors — let the caller keep walking.
        _ => None,
    }
}

fn classify_hyper_error(hyper_err: &hyper::Error) -> Option<crate::retry::ErrorClass> {
    use crate::retry::ErrorClass;
    if hyper_err.is_timeout() {
        return Some(ErrorClass::ReadWriteTimeout);
    }
    if hyper_err.is_incomplete_message() {
        return Some(ErrorClass::ConnectionClosed);
    }
    // Generic hyper error — try to detect protocol/GOAWAY in Debug.
    let debug = format!("{:?}", hyper_err);
    if debug.contains("GoAway") || debug.contains("goaway") || debug.contains("Protocol") {
        return Some(ErrorClass::ProtocolError);
    }
    None
}

/// Errors specific to HTTP/2 pool operations.
///
/// Each variant carries a human-readable `message` (for logs) and an optional
/// typed `source` so classification can walk the real error chain instead of
/// string-matching on the message. `std::error::Error::source()` is implemented
/// so external consumers (logging, tracing, `anyhow` attach-context) can walk
/// to the root cause.
#[derive(Debug)]
pub enum Http2PoolError {
    /// The backend is reachable in name only — TCP connect failed, TLS
    /// handshake failed, DNS didn't resolve, or an h2 handshake produced an
    /// error. Carries the source so classifiers and logs can dig into the
    /// original cause.
    BackendUnavailable {
        message: String,
        source: Option<BackendUnavailableSource>,
    },
    /// Connection or operation timed out. `source` is populated with an
    /// `io::Error` whose kind is `TimedOut` so classifiers can detect this
    /// via `ErrorKind`, not via the string.
    BackendTimeout {
        message: String,
        source: Option<std::io::Error>,
    },
    /// Internal pool error — certificate loading, TLS policy build,
    /// configuration problems. These are almost always config/setup bugs
    /// rather than transient backend issues; classified as
    /// `ConnectionPoolError`.
    Internal {
        message: String,
        source: Option<InternalSource>,
    },
}

/// Typed source for `Http2PoolError::BackendUnavailable` so classification can
/// distinguish between IO failures (with an `io::Error` carrying
/// `ErrorKind::ConnectionRefused`, etc.), TLS handshake failures, hyper-level
/// framing errors, and DNS/SNI-name parse failures.
#[derive(Debug)]
pub enum BackendUnavailableSource {
    /// TCP connect or socket layer failure. The inner `io::Error` carries the
    /// typed kind (`ConnectionRefused`, `ConnectionReset`, `TimedOut`, etc.).
    Io(std::io::Error),
    /// TLS handshake failure. Many rustls errors arrive as an `io::Error`
    /// wrapper, but tokio_rustls occasionally surfaces the original
    /// `rustls::Error` — both get classified as `TlsError`.
    Tls(std::io::Error),
    /// HTTP/2 framing/handshake failure from hyper — `is_timeout` or
    /// `is_incomplete_message` further narrow the class; other wording
    /// containing `GoAway` / `Protocol` implies `ProtocolError`.
    Hyper(hyper::Error),
    /// DNS resolution failed inside the shared cache. The upstream error
    /// doesn't downcast to anything useful here, so we carry a marker and
    /// classify as `DnsLookupError`.
    Dns,
    /// `rustls::pki_types::ServerName::try_from` rejected the hostname
    /// (invalid SNI label). Classified as `DnsLookupError` because the
    /// remediation is a DNS/config change.
    InvalidDnsName,
}

impl std::error::Error for BackendUnavailableSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) | Self::Tls(e) => Some(e),
            Self::Hyper(e) => Some(e),
            Self::Dns | Self::InvalidDnsName => None,
        }
    }
}

impl std::fmt::Display for BackendUnavailableSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{}", e),
            Self::Tls(e) => write!(f, "{}", e),
            Self::Hyper(e) => write!(f, "{}", e),
            Self::Dns => write!(f, "dns resolution failed"),
            Self::InvalidDnsName => write!(f, "invalid dns name"),
        }
    }
}

/// Typed source for `Http2PoolError::Internal`.
#[derive(Debug)]
pub enum InternalSource {
    /// Filesystem read / PEM parse failure.
    Io(std::io::Error),
    /// rustls configuration error (invalid cert chain, bad key, etc.).
    Rustls(rustls::Error),
    /// A string-only error from an upstream helper that doesn't expose a
    /// typed chain. Kept last-resort so we don't pretend we have more
    /// information than we actually do.
    Message(String),
}

impl std::error::Error for InternalSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Rustls(e) => Some(e),
            Self::Message(_) => None,
        }
    }
}

impl std::fmt::Display for InternalSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{}", e),
            Self::Rustls(e) => write!(f, "{}", e),
            Self::Message(m) => write!(f, "{}", m),
        }
    }
}

impl std::fmt::Display for Http2PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendUnavailable { message, .. } => write!(f, "{}", message),
            Self::BackendTimeout { message, .. } => write!(f, "{}", message),
            Self::Internal { message, .. } => write!(f, "{}", message),
        }
    }
}

impl std::error::Error for Http2PoolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BackendUnavailable { source, .. } => source
                .as_ref()
                .map(|s| s as &(dyn std::error::Error + 'static)),
            Self::BackendTimeout { source, .. } => source
                .as_ref()
                .map(|s| s as &(dyn std::error::Error + 'static)),
            Self::Internal { source, .. } => source
                .as_ref()
                .map(|s| s as &(dyn std::error::Error + 'static)),
        }
    }
}

impl Http2PoolError {
    /// Return the human-readable message for this error. Used by consumers
    /// that need to propagate the message into a response body or log line.
    pub fn message(&self) -> &str {
        match self {
            Self::BackendUnavailable { message, .. } => message,
            Self::BackendTimeout { message, .. } => message,
            Self::Internal { message, .. } => message,
        }
    }
}
