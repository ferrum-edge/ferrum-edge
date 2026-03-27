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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::PoolConfig;
use crate::config::types::Proxy;
use crate::dns::DnsCache;
use crate::tls::NoVerifier;

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
}

impl Default for Http2ConnectionPool {
    fn default() -> Self {
        Self::new(PoolConfig::default(), crate::config::EnvConfig::default())
    }
}

impl Http2ConnectionPool {
    pub fn new(
        global_pool_config: PoolConfig,
        global_env_config: crate::config::EnvConfig,
    ) -> Self {
        let pool = Self {
            entries: Arc::new(DashMap::new()),
            rr_counters: Arc::new(DashMap::new()),
            global_pool_config,
            global_env_config,
        };

        pool.start_cleanup_task();
        pool
    }

    /// Pool key — kept minimal to avoid fragmentation.
    fn pool_key(proxy: &Proxy) -> String {
        format!("{}:{}", proxy.backend_host, proxy.backend_port)
    }

    fn shard_key(base_key: &str, shard: usize) -> String {
        format!("{base_key}#{shard}")
    }

    /// Get or create an HTTP/2 connection to the HTTPS backend.
    pub async fn get_sender(
        &self,
        proxy: &Proxy,
        dns_cache: &DnsCache,
    ) -> Result<http2::SendRequest<Incoming>, Http2PoolError> {
        let base_key = Self::pool_key(proxy);
        let pool_config = self.global_pool_config.for_proxy(proxy);
        let shard_count = pool_config.http2_connections_per_host.max(1);
        let rr = self
            .rr_counters
            .entry(base_key.clone())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();
        let start = rr.fetch_add(1, Ordering::Relaxed) % shard_count;
        let selected_key = Self::shard_key(&base_key, start);

        if let Some(entry) = self.entries.get(&selected_key) {
            if !entry.sender.is_closed() {
                entry
                    .last_used_epoch_ms
                    .store(now_epoch_ms(), Ordering::Relaxed);
                return Ok(entry.sender.clone());
            }
            drop(entry);
            self.entries.remove(&selected_key);
        }

        // Fill the selected shard eagerly so round-robin distribution actually
        // materializes multiple backend connections under load.
        let sender = match self.create_connection(proxy, dns_cache).await {
            Ok(sender) => sender,
            Err(err) => {
                for offset in 1..shard_count {
                    let shard = (start + offset) % shard_count;
                    let key = Self::shard_key(&base_key, shard);
                    if let Some(entry) = self.entries.get(&key) {
                        if !entry.sender.is_closed() {
                            entry
                                .last_used_epoch_ms
                                .store(now_epoch_ms(), Ordering::Relaxed);
                            return Ok(entry.sender.clone());
                        }
                        drop(entry);
                        self.entries.remove(&key);
                    }
                }
                return Err(err);
            }
        };
        let sender = match self.entries.entry(selected_key) {
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
                    "http2_pool: connect timeout ({}ms) to backend {}",
                    proxy.backend_connect_timeout_ms, addr
                );
                Http2PoolError::BackendTimeout(format!(
                    "Connect timeout after {}ms to {}",
                    proxy.backend_connect_timeout_ms, addr
                ))
            })?
            .map_err(|e| {
                warn!("http2_pool: failed to connect to backend {}: {}", addr, e);
                Http2PoolError::BackendUnavailable(format!("Connection refused: {}", e))
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
        use std::os::fd::AsFd;
        let fd = stream.as_fd();
        let socket = socket2::SockRef::from(&fd);
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

        // Build root certificate store
        let mut root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };

        // Add custom CA bundle if configured (unless no_verify is set)
        if !self.global_env_config.tls_no_verify
            && let Some(ca_bundle_path) = &self.global_env_config.tls_ca_bundle_path
        {
            match std::fs::read(ca_bundle_path) {
                Ok(ca_pem) => {
                    let mut reader = std::io::BufReader::new(&ca_pem[..]);
                    let certs = rustls_pemfile::certs(&mut reader);
                    for cert in certs.flatten() {
                        if let Err(e) = root_store.add(cert) {
                            warn!("http2_pool: failed to add CA cert from bundle: {}", e);
                        }
                    }
                    debug!(
                        "http2_pool: loaded custom CA bundle from {}",
                        ca_bundle_path
                    );
                }
                Err(e) => {
                    warn!(
                        "http2_pool: failed to read CA bundle from {}: {}",
                        ca_bundle_path, e
                    );
                }
            }
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
                Http2PoolError::Internal(format!(
                    "Failed to read client cert from {}: {}",
                    cert_path, e
                ))
            })?;
            let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&cert_pem[..]))
                .flatten()
                .collect();

            // Load client private key
            let key_pem = std::fs::read(key_path).map_err(|e| {
                Http2PoolError::Internal(format!(
                    "Failed to read client key from {}: {}",
                    key_path, e
                ))
            })?;
            let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(&key_pem[..]))
                .map_err(|e| {
                    Http2PoolError::Internal(format!("Failed to parse client key: {}", e))
                })?
                .ok_or_else(|| {
                    Http2PoolError::Internal(format!("No private key found in {}", key_path))
                })?;

            debug!(
                "http2_pool: using mTLS client cert from {} and key from {}",
                cert_path, key_path
            );

            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(certs, key)
                .map_err(|e| {
                    Http2PoolError::Internal(format!("Invalid client certificate/key: {}", e))
                })?
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        // Apply remaining TLS options
        let mut tls_config = tls_config;

        // Force HTTP/2 via ALPN
        tls_config.alpn_protocols = vec![b"h2".to_vec()];

        // Optionally skip server cert verification
        if !proxy.backend_tls_verify_server_cert || self.global_env_config.tls_no_verify {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier));
        }

        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = ServerName::try_from(host.to_string()).map_err(|e| {
            Http2PoolError::BackendUnavailable(format!("Invalid server name: {}", e))
        })?;

        let tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
            Http2PoolError::BackendUnavailable(format!("TLS handshake failed: {}", e))
        })?;

        let io = TokioIo::new(tls_stream);
        let builder = Self::build_h2_builder(pool_config);

        let (sender, conn) = builder.handshake(io).await.map_err(|e| {
            Http2PoolError::BackendUnavailable(format!("h2 handshake failed: {}", e))
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

/// Errors specific to HTTP/2 pool operations.
#[derive(Debug)]
pub enum Http2PoolError {
    BackendUnavailable(String),
    BackendTimeout(String),
    Internal(String),
}
