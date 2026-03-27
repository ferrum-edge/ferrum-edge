//! HTTP/2 connection pool using hyper's HTTP/2 client directly.
//!
//! Provides proper HTTP/2 stream multiplexing over multiple persistent TLS
//! connections, distributing load via round-robin to avoid serialization on
//! a single connection's state machine. The number of connections per backend
//! is governed by `max_idle_per_host` from the global or per-proxy pool config.
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

/// A slot holding multiple HTTP/2 connections to the same backend.
/// Round-robin selection distributes load across connections to avoid
/// serialization on a single HTTP/2 state machine.
struct Http2PoolSlot {
    entries: Vec<Http2PoolEntry>,
    counter: AtomicUsize,
}

/// HTTP/2 connection pool for HTTPS backends.
///
/// Manages reusable HTTP/2 connections with proper stream multiplexing.
/// Unlike the reqwest-based `ConnectionPool`, this uses hyper's HTTP/2 client
/// directly to multiplex concurrent requests over persistent TLS connections.
///
/// Multiple connections per backend (up to `max_idle_per_host`) are maintained
/// and selected via round-robin to distribute stream-level contention across
/// connections, avoiding the bottleneck of a single HTTP/2 state machine.
///
/// Honors the same configuration as the HTTP pool:
/// - Global `PoolConfig` from environment variables
/// - Per-proxy overrides (`pool_*` fields on `Proxy`)
/// - Global mTLS and CA bundle settings from `EnvConfig`
/// - Background idle connection cleanup
pub struct Http2ConnectionPool {
    /// Cached sender handles keyed by `host:port`, with multiple connections per slot
    entries: Arc<DashMap<String, Http2PoolSlot>>,
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

    /// Get or create an HTTP/2 connection to the HTTPS backend.
    ///
    /// Connections are selected via round-robin across the pool slot. If all
    /// connections in the slot are closed, or the slot doesn't exist yet, a
    /// new connection is created. The pool grows lazily up to `max_idle_per_host`.
    pub async fn get_sender(
        &self,
        proxy: &Proxy,
        dns_cache: &DnsCache,
    ) -> Result<http2::SendRequest<Incoming>, Http2PoolError> {
        let key = Self::pool_key(proxy);

        // Fast path: read-only round-robin selection from existing slot
        if let Some(slot) = self.entries.get(&key) {
            let len = slot.entries.len();
            if len > 0 {
                // Try each sender in round-robin order to find a live one
                for _ in 0..len {
                    let idx = slot.counter.fetch_add(1, Ordering::Relaxed) % len;
                    let entry = &slot.entries[idx];
                    if !entry.sender.is_closed() {
                        entry
                            .last_used_epoch_ms
                            .store(now_epoch_ms(), Ordering::Relaxed);
                        return Ok(entry.sender.clone());
                    }
                }
            }
            drop(slot); // release read lock before write path
        }

        // Slow path: create a new connection and add it to the pool
        let sender = self.create_connection(proxy, dns_cache).await?;
        let pool_config = self.global_pool_config.for_proxy(proxy);

        let mut slot = self.entries.entry(key).or_insert_with(|| Http2PoolSlot {
            entries: Vec::with_capacity(pool_config.max_idle_per_host.min(32)),
            counter: AtomicUsize::new(0),
        });

        // Clean out closed connections while we hold the write lock
        slot.entries.retain(|e| !e.sender.is_closed());

        // Add the new connection if we haven't hit the cap
        if slot.entries.len() < pool_config.max_idle_per_host {
            slot.entries.push(Http2PoolEntry {
                sender: sender.clone(),
                last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            });
        }

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

    /// Build an HTTP/2 client builder with keepalive and flow control settings.
    ///
    /// Configures larger initial window sizes for higher throughput under
    /// concurrent load, matching common production HTTP/2 tuning.
    fn build_h2_builder(pool_config: &PoolConfig) -> http2::Builder<TokioExecutor> {
        let mut builder = http2::Builder::new(TokioExecutor::new());

        // Timer is required for keep_alive_interval and keep_alive_timeout to work
        builder.timer(TokioTimer::new());

        // Increase flow control windows and frame size for higher throughput.
        // Defaults (65535 bytes / 16KB frames) throttle concurrent streams on a
        // single connection — these values are standard production tuning.
        builder
            .initial_connection_window_size(2 * 1024 * 1024) // 2 MB (default 65535)
            .initial_stream_window_size(1024 * 1024) // 1 MB (default 65535)
            .max_frame_size(32 * 1024); // 32 KB (default 16384)

        if pool_config.enable_http2 {
            builder
                .keep_alive_interval(Duration::from_secs(
                    pool_config.http2_keep_alive_interval_seconds,
                ))
                .keep_alive_timeout(Duration::from_secs(
                    pool_config.http2_keep_alive_timeout_seconds,
                ));
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
                .set_certificate_verifier(Arc::new(NoCertificateVerification));
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

    /// Start background cleanup task that evicts idle and closed connections.
    fn start_cleanup_task(&self) {
        let entries = self.entries.clone();
        let idle_timeout_ms = self
            .global_pool_config
            .idle_timeout_seconds
            .saturating_mul(1000);

        tokio::spawn(async move {
            let mut cleanup_timer = tokio::time::interval(Duration::from_secs(30));

            loop {
                cleanup_timer.tick().await;

                let now = now_epoch_ms();
                let mut empty_keys = Vec::new();

                for mut slot in entries.iter_mut() {
                    // Remove closed or idle connections from the slot
                    slot.entries.retain(|entry| {
                        let last_used = entry.last_used_epoch_ms.load(Ordering::Relaxed);
                        let idle_ms = now.saturating_sub(last_used);
                        !entry.sender.is_closed() && idle_ms <= idle_timeout_ms
                    });

                    if slot.entries.is_empty() {
                        empty_keys.push(slot.key().clone());
                    }
                }

                // Remove completely empty slots
                for key in &empty_keys {
                    entries.remove(key);
                }

                if !empty_keys.is_empty() {
                    debug!(
                        "http2_pool cleanup: removed {} empty slots",
                        empty_keys.len()
                    );
                }
            }
        });
    }
}

/// Dangerous: skip TLS certificate verification (for testing or self-signed certs).
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Errors specific to HTTP/2 pool operations.
#[derive(Debug)]
pub enum Http2PoolError {
    BackendUnavailable(String),
    BackendTimeout(String),
    Internal(String),
}
