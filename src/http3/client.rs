//! HTTP/3 client connection pool for proxying to HTTP/3 backends.
//!
//! Uses `connections_per_backend` QUIC connections per target to distribute
//! frame processing across driver tasks (prevents CPU bottleneck on a single
//! QUIC connection). The pool key includes a connection index for sharding.
//!
//! TLS config is constructed lazily via closure to avoid cloning root cert
//! stores on every request. On connection failure, a fallback scan checks
//! other cached connection indices before creating a new connection.
//!
//! This pool is used by both the main hyper-based proxy path (`proxy/mod.rs`)
//! for H3 backend targets and the H3 frontend server (`http3/server.rs`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Buf;
use dashmap::DashMap;
use http::Request;
use quinn::crypto::rustls::QuicClientConfig;
use tracing::debug;

use crate::config::types::Proxy;

/// Classify an HTTP/3 backend error into the shared `ErrorClass` taxonomy.
///
/// Walks the error source chain looking for recognizable `quinn::ConnectionError`
/// variants, and falls back to string heuristics for `h3::Error` wrappers and
/// anyhow chains. Without this, H3-specific errors previously landed in the
/// transaction log with no `error_class` because `classify_boxed_error` only
/// knew about reqwest/hyper patterns.
pub fn classify_http3_error(err: &(dyn std::error::Error + 'static)) -> crate::retry::ErrorClass {
    use crate::retry::ErrorClass;

    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(node) = current {
        if let Some(ce) = node.downcast_ref::<quinn::ConnectionError>() {
            return match ce {
                quinn::ConnectionError::TimedOut => ErrorClass::ConnectionTimeout,
                quinn::ConnectionError::Reset => ErrorClass::ConnectionReset,
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::ConnectionClosed(_)
                | quinn::ConnectionError::LocallyClosed => ErrorClass::ConnectionClosed,
                quinn::ConnectionError::VersionMismatch
                | quinn::ConnectionError::TransportError(_) => ErrorClass::ProtocolError,
                quinn::ConnectionError::CidsExhausted => ErrorClass::ConnectionPoolError,
            };
        }
        if let Some(ce) = node.downcast_ref::<quinn::ConnectError>() {
            return match ce {
                quinn::ConnectError::EndpointStopping
                | quinn::ConnectError::CidsExhausted
                | quinn::ConnectError::NoDefaultClientConfig => ErrorClass::ConnectionPoolError,
                quinn::ConnectError::UnsupportedVersion => ErrorClass::ProtocolError,
                quinn::ConnectError::InvalidRemoteAddress(_)
                | quinn::ConnectError::InvalidServerName(_) => ErrorClass::DnsLookupError,
            };
        }
        if let Some(io) = node.downcast_ref::<std::io::Error>() {
            if matches!(io.raw_os_error(), Some(99) | Some(49) | Some(10049)) {
                return ErrorClass::PortExhaustion;
            }
            match io.kind() {
                std::io::ErrorKind::TimedOut => return ErrorClass::ConnectionTimeout,
                std::io::ErrorKind::ConnectionRefused => return ErrorClass::ConnectionRefused,
                std::io::ErrorKind::ConnectionReset => return ErrorClass::ConnectionReset,
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionAborted => {
                    return ErrorClass::ConnectionClosed;
                }
                // Generic kinds (Other, etc.) commonly wrap QUIC/H3 typed
                // errors — keep walking the source chain so typed variants
                // and string heuristics can still classify them.
                _ => {}
            }
        }
        current = node.source();
    }

    // Fallback string heuristics for h3::Error and anyhow-wrapped errors that
    // don't expose a typed chain.
    let msg = err.to_string().to_ascii_lowercase();
    if crate::retry::is_port_exhaustion_message(&msg) {
        ErrorClass::PortExhaustion
    } else if msg.contains("dns") || msg.contains("resolve") {
        ErrorClass::DnsLookupError
    } else if msg.contains("tls") || msg.contains("certificate") || msg.contains("handshake") {
        ErrorClass::TlsError
    } else if msg.contains("timed out") || msg.contains("timeout") {
        if msg.contains("connect") {
            ErrorClass::ConnectionTimeout
        } else {
            ErrorClass::ReadWriteTimeout
        }
    } else if msg.contains("refused") {
        ErrorClass::ConnectionRefused
    } else if msg.contains("reset") {
        ErrorClass::ConnectionReset
    } else if msg.contains("broken pipe") || msg.contains("closed") {
        ErrorClass::ConnectionClosed
    } else if msg.contains("goaway") || msg.contains("protocol") || msg.contains("stream") {
        ErrorClass::ProtocolError
    } else {
        ErrorClass::RequestError
    }
}

/// Type alias for the h3 send request handle.
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;

/// Type alias for the h3 client request stream (bidirectional).
pub type H3RequestStream =
    h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>;

/// Result of a streaming HTTP/3 request — headers received, body still in flight.
///
/// The caller reads response body chunks via `recv_stream.recv_data()`.
pub struct H3StreamingResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub recv_stream: H3RequestStream,
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Cached HTTP/3 connection entry.
struct H3PoolEntry {
    send_request: H3SendRequest,
    last_used_epoch_ms: Arc<AtomicU64>,
}

/// HTTP/3 connection pool for proxying requests to HTTP/3 backends.
///
/// Caches QUIC connections and h3 session handles per backend `host:port`,
/// avoiding the enormous overhead of creating a new UDP socket, QUIC handshake,
/// and h3 session for every request. Each cached connection supports full
/// HTTP/3 multiplexing (concurrent streams).
pub struct Http3ConnectionPool {
    entries: Arc<DashMap<String, H3PoolEntry>>,
    env_config: Arc<crate::config::EnvConfig>,
    /// Shared DNS cache for backend hostname resolution.
    dns_cache: crate::dns::DnsCache,
    /// Round-robin counter for distributing streams across backend connections.
    conn_counter: AtomicU64,
    /// Number of QUIC connections to maintain per backend. Multiple connections
    /// distribute frame processing across QUIC driver tasks, preventing a
    /// single-driver CPU bottleneck at high concurrency.
    connections_per_backend: usize,
    /// Shared QUIC endpoint for IPv4 backends. All IPv4 connections share a
    /// single UDP socket, reducing FD usage and enabling kernel-level port reuse.
    ipv4_endpoint: tokio::sync::OnceCell<quinn::Endpoint>,
    /// Shared QUIC endpoint for IPv6 backends.
    ipv6_endpoint: tokio::sync::OnceCell<quinn::Endpoint>,
}

impl Http3ConnectionPool {
    pub fn new(env_config: Arc<crate::config::EnvConfig>, dns_cache: crate::dns::DnsCache) -> Self {
        let connections_per_backend = env_config.http3_connections_per_backend;
        let pool = Self {
            entries: Arc::new(DashMap::new()),
            env_config,
            dns_cache,
            conn_counter: AtomicU64::new(0),
            connections_per_backend,
            ipv4_endpoint: tokio::sync::OnceCell::new(),
            ipv6_endpoint: tokio::sync::OnceCell::new(),
        };
        pool.start_cleanup_task();
        pool
    }

    /// Get or lazily create the shared QUIC endpoint for the given address family.
    ///
    /// All connections to backends of the same address family share a single UDP
    /// socket, reducing FD usage from O(connections) to O(1) per address family.
    async fn get_shared_endpoint(&self, is_ipv6: bool) -> Result<quinn::Endpoint, anyhow::Error> {
        let cell = if is_ipv6 {
            &self.ipv6_endpoint
        } else {
            &self.ipv4_endpoint
        };
        let endpoint = cell
            .get_or_try_init(|| async { create_shared_quic_endpoint(is_ipv6) })
            .await?;
        Ok(endpoint.clone())
    }

    /// Number of connections in the pool (for metrics).
    pub fn pool_size(&self) -> usize {
        self.entries.len()
    }

    /// Pool key — includes TLS-differentiating fields (CA, mTLS, verify).
    /// Uses `|` as delimiter to avoid ambiguity with `:` in IPv6 addresses.
    pub fn pool_key(proxy: &Proxy, index: usize) -> String {
        let mut key = String::with_capacity(128);
        Self::write_pool_key(&mut key, proxy, index);
        key
    }

    /// Write pool key into the provided buffer, avoiding intermediate
    /// `format!()` allocations. Called from both the allocating `pool_key()`
    /// (cold path) and the thread-local buffer lookup (hot path).
    fn write_pool_key(buf: &mut String, proxy: &Proxy, index: usize) {
        use std::fmt::Write;
        buf.clear();
        let _ = write!(
            buf,
            "{}|{}|{}|{}|{}|{}",
            proxy.backend_host,
            proxy.backend_port,
            index,
            proxy
                .resolved_tls
                .server_ca_cert_path
                .as_deref()
                .unwrap_or_default(),
            proxy
                .resolved_tls
                .client_cert_path
                .as_deref()
                .unwrap_or_default(),
            proxy.resolved_tls.verify_server_cert as u8,
        );
    }

    pub fn pool_key_for_target(host: &str, port: u16, index: usize) -> String {
        // Target keys are used by the retry path where host:port come from
        // upstream targets. TLS config is inherited from the proxy that
        // originated the request, but all requests through this path share
        // the same proxy TLS settings, so host|port|index is sufficient
        // for uniqueness within a single retry sequence.
        let mut key = String::with_capacity(64);
        use std::fmt::Write;
        let _ = write!(key, "{}|{}|{}", host, port, index);
        key
    }

    /// Pre-establish a QUIC connection and cache it in the pool (shard 0 only).
    ///
    /// Used at startup to warm the connection pool so the first request to each
    /// H3 backend does not pay the QUIC + TLS 1.3 handshake cost.
    pub async fn warmup_connection(
        &self,
        proxy: &Proxy,
        tls_config: &Arc<rustls::ClientConfig>,
    ) -> Result<(), anyhow::Error> {
        let key = Self::pool_key(proxy, 0);
        if self.entries.contains_key(&key) {
            return Ok(());
        }
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_connection(proxy, tls_config, Some(&h3_config))
            .await?;
        self.entries.insert(
            key,
            H3PoolEntry {
                send_request: sr,
                last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            },
        );
        Ok(())
    }

    /// Pre-establish a QUIC connection to an explicit host/port target.
    ///
    /// Used at startup to warm pool entries for upstream targets where the
    /// backend host/port differs from the proxy's configured backend.
    pub async fn warmup_connection_to_target(
        &self,
        host: &str,
        port: u16,
        tls_config: &Arc<rustls::ClientConfig>,
    ) -> Result<(), anyhow::Error> {
        let key = Self::pool_key_for_target(host, port, 0);
        if self.entries.contains_key(&key) {
            return Ok(());
        }
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_connection_to_target(host, port, tls_config, Some(&h3_config))
            .await?;
        self.entries.insert(
            key,
            H3PoolEntry {
                send_request: sr,
                last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            },
        );
        Ok(())
    }

    /// Send an HTTP/3 request, reusing a cached QUIC connection if available.
    ///
    /// Round-robins across `connections_per_backend` connections to distribute
    /// QUIC frame processing across multiple driver tasks.
    /// Send an HTTP/3 request, reusing a cached QUIC connection if available.
    ///
    /// The `tls_config_fn` closure is only called on cache miss (when a new
    /// QUIC connection must be established), avoiding the overhead of cloning
    /// the TLS root certificate store on every request.
    pub async fn request(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> Result<(u16, Vec<u8>, HashMap<String, String>), anyhow::Error> {
        // Per-proxy override takes priority over global default
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;

        // Fast path: use a thread-local buffer for pool key lookup to avoid
        // allocating a String on every request. On cache hit + successful
        // request, we return without any String allocation.
        thread_local! {
            static KEY_BUF: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(128));
        }
        let cached = KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            Self::write_pool_key(&mut buf, proxy, start);
            if let Some(entry) = self.entries.get(&*buf) {
                entry
                    .last_used_epoch_ms
                    .store(now_epoch_ms(), Ordering::Relaxed);
                let sr = entry.send_request.clone();
                drop(entry);
                return Some(sr);
            }
            None
        });
        if let Some(mut sr) = cached {
            match Self::do_request(&mut sr, proxy, method, backend_url, headers, body.clone()).await
            {
                Ok(result) => return Ok(result),
                Err(_) => {
                    // Cached connection failed — fall through to the full
                    // retry/reconnect path below which allocates pool keys.
                }
            }
        }

        // Slow path: allocate pool key String for cache miss, error recovery,
        // and new connection creation.
        let key = Self::pool_key(proxy, start);

        // Try cached connection on the selected index first
        if let Some(entry) = self.entries.get(&key) {
            entry
                .last_used_epoch_ms
                .store(now_epoch_ms(), Ordering::Relaxed);
            let mut sr = entry.send_request.clone();
            drop(entry); // Release DashMap lock before async work

            match Self::do_request(&mut sr, proxy, method, backend_url, headers, body.clone()).await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!("HTTP/3 cached connection failed, reconnecting: {}", e);
                    self.entries.remove(&key);

                    // Try other cached indices before creating a new connection
                    for offset in 1..conns_per_backend {
                        let fallback_index = (start + offset) % conns_per_backend;
                        let fallback_key = Self::pool_key(proxy, fallback_index);
                        if let Some(entry) = self.entries.get(&fallback_key) {
                            entry
                                .last_used_epoch_ms
                                .store(now_epoch_ms(), Ordering::Relaxed);
                            let mut fallback_sr = entry.send_request.clone();
                            drop(entry);
                            match Self::do_request(
                                &mut fallback_sr,
                                proxy,
                                method,
                                backend_url,
                                headers,
                                body.clone(),
                            )
                            .await
                            {
                                Ok(result) => return Ok(result),
                                Err(_) => {
                                    self.entries.remove(&fallback_key);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Create new connection — only now do we need the TLS config
        let tls_config = tls_config_fn()?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_connection(proxy, &tls_config, Some(&h3_config))
            .await?;
        let mut sr_for_request = sr.clone();

        self.entries.insert(
            key,
            H3PoolEntry {
                send_request: sr,
                last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            },
        );

        Self::do_request(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            body,
        )
        .await
    }

    /// Send an HTTP/3 request to an explicit host/port target, independent of
    /// `proxy.backend_host`/`proxy.backend_port`. Used by the retry path to
    /// route to a different load-balanced upstream target.
    ///
    /// Pool entries are keyed by the explicit target host:port so connections
    /// are cached and reused per target, not per proxy.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_with_target(
        &self,
        proxy: &Proxy,
        target_host: &str,
        target_port: u16,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> Result<(u16, Vec<u8>, HashMap<String, String>), anyhow::Error> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        let key = Self::pool_key_for_target(target_host, target_port, start);

        // Try cached connection on the selected index first
        if let Some(entry) = self.entries.get(&key) {
            entry
                .last_used_epoch_ms
                .store(now_epoch_ms(), Ordering::Relaxed);
            let mut sr = entry.send_request.clone();
            drop(entry);

            match Self::do_request(&mut sr, proxy, method, backend_url, headers, body.clone()).await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!(
                        "HTTP/3 cached connection to {}:{} failed, reconnecting: {}",
                        target_host, target_port, e
                    );
                    self.entries.remove(&key);

                    // Try other cached indices before creating a new connection
                    for offset in 1..conns_per_backend {
                        let fallback_index = (start + offset) % conns_per_backend;
                        let fallback_key =
                            Self::pool_key_for_target(target_host, target_port, fallback_index);
                        if let Some(entry) = self.entries.get(&fallback_key) {
                            entry
                                .last_used_epoch_ms
                                .store(now_epoch_ms(), Ordering::Relaxed);
                            let mut fallback_sr = entry.send_request.clone();
                            drop(entry);
                            match Self::do_request(
                                &mut fallback_sr,
                                proxy,
                                method,
                                backend_url,
                                headers,
                                body.clone(),
                            )
                            .await
                            {
                                Ok(result) => return Ok(result),
                                Err(_) => {
                                    self.entries.remove(&fallback_key);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Create new connection to the explicit target
        let tls_config = tls_config_fn()?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_connection_to_target(target_host, target_port, &tls_config, Some(&h3_config))
            .await?;
        let mut sr_for_request = sr.clone();

        self.entries.insert(
            key,
            H3PoolEntry {
                send_request: sr,
                last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            },
        );

        Self::do_request(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            body,
        )
        .await
    }

    /// Create a new QUIC connection + h3 session using a shared endpoint.
    ///
    /// Reuses the pool's shared IPv4/IPv6 QUIC endpoint instead of creating
    /// a new UDP socket per connection, reducing FD usage from O(connections)
    /// to O(1) per address family.
    async fn create_connection(
        &self,
        proxy: &Proxy,
        tls_config: &Arc<rustls::ClientConfig>,
        h3_config: Option<&super::config::Http3ServerConfig>,
    ) -> Result<H3SendRequest, anyhow::Error> {
        let quic_client_config = QuicClientConfig::try_from(tls_config.clone()).map_err(|e| {
            anyhow::anyhow!(
                "Failed to create QUIC client config (ensure TLS 1.3 cipher suites are available): {}",
                e
            )
        })?;

        let default_cfg = super::config::Http3ServerConfig::default();
        let cfg = h3_config.unwrap_or(&default_cfg);

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.stream_receive_window(
            quinn::VarInt::from_u64(cfg.stream_receive_window)
                .unwrap_or(quinn::VarInt::from_u32(1_048_576)),
        );
        transport_config.receive_window(
            quinn::VarInt::from_u64(cfg.receive_window)
                .unwrap_or(quinn::VarInt::from_u32(4_194_304)),
        );
        transport_config.send_window(cfg.send_window);

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport_config));

        let host = &proxy.backend_host;
        let port = proxy.backend_port;
        let addr = resolve_backend_addr_cached(
            host,
            port,
            &self.dns_cache,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await?;

        let endpoint = self.get_shared_endpoint(addr.is_ipv6()).await?;

        debug!(
            "HTTP/3 pool: connecting to {}:{} (resolved: {})",
            host, port, addr
        );

        let connection = endpoint
            .connect_with(client_config, addr, host)?
            .await
            .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))?;

        let (mut driver, send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;

        tokio::spawn(async move {
            let err = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            debug!("HTTP/3 pool connection driver closed: {}", err);
        });

        Ok(send_request)
    }

    /// Create a new QUIC connection + h3 session to an explicit host/port
    /// using a shared endpoint.
    ///
    /// Used by `request_with_target` for load-balanced retries where the target
    /// differs from `proxy.backend_host`/`proxy.backend_port`.
    async fn create_connection_to_target(
        &self,
        host: &str,
        port: u16,
        tls_config: &Arc<rustls::ClientConfig>,
        h3_config: Option<&super::config::Http3ServerConfig>,
    ) -> Result<H3SendRequest, anyhow::Error> {
        let quic_client_config = QuicClientConfig::try_from(tls_config.clone()).map_err(|e| {
            anyhow::anyhow!(
                "Failed to create QUIC client config (ensure TLS 1.3 cipher suites are available): {}",
                e
            )
        })?;

        let default_cfg = super::config::Http3ServerConfig::default();
        let cfg = h3_config.unwrap_or(&default_cfg);

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.stream_receive_window(
            quinn::VarInt::from_u64(cfg.stream_receive_window)
                .unwrap_or(quinn::VarInt::from_u32(1_048_576)),
        );
        transport_config.receive_window(
            quinn::VarInt::from_u64(cfg.receive_window)
                .unwrap_or(quinn::VarInt::from_u32(4_194_304)),
        );
        transport_config.send_window(cfg.send_window);

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport_config));

        let addr = resolve_backend_addr_cached(host, port, &self.dns_cache, None, None).await?;

        let endpoint = self.get_shared_endpoint(addr.is_ipv6()).await?;

        debug!(
            "HTTP/3 pool: connecting to {}:{} (resolved: {})",
            host, port, addr
        );

        let connection = endpoint
            .connect_with(client_config, addr, host)?
            .await
            .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))?;

        let (mut driver, send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;

        tokio::spawn(async move {
            let err = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            debug!("HTTP/3 pool connection driver closed: {}", err);
        });

        Ok(send_request)
    }

    /// Execute an HTTP/3 request on an existing SendRequest handle.
    async fn do_request(
        send_request: &mut H3SendRequest,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
    ) -> Result<(u16, Vec<u8>, HashMap<String, String>), anyhow::Error> {
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid backend URL: {}", e))?;

        let _host = uri.host().unwrap_or(&proxy.backend_host);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let req_method: http::Method = method
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid HTTP method: {}", method))?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);
        for (name, value) in headers {
            match name.as_str() {
                "connection" | "transfer-encoding" | "keep-alive" | "upgrade" => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(())?;
        let mut stream = send_request.send_request(req).await?;

        if !body.is_empty() {
            stream.send_data(body).await?;
        }
        stream.finish().await?;

        let response = stream.recv_response().await?;
        let status = response.status().as_u16();

        let mut response_headers = HashMap::with_capacity(response.headers().keys_len());
        for (name, value) in response.headers() {
            // Skip hop-by-hop headers during collection (avoids allocating
            // String keys that would be immediately removed by the caller).
            match name.as_str() {
                "connection" | "keep-alive" | "proxy-authenticate" | "proxy-connection" | "te"
                | "trailer" | "transfer-encoding" | "upgrade" => continue,
                _ => {}
            }
            if let Ok(value_str) = value.to_str() {
                response_headers.insert(name.as_str().to_string(), value_str.to_string());
            }
        }

        let mut response_body = Vec::new();
        while let Some(chunk) = stream.recv_data().await? {
            response_body.extend_from_slice(chunk.chunk());
        }

        Ok((status, response_body, response_headers))
    }

    /// Execute an HTTP/3 request, returning headers and a stream handle for the
    /// response body. Unlike `do_request`, this does NOT buffer the body — the
    /// caller reads chunks via `recv_stream.recv_data()`.
    async fn do_request_streaming(
        send_request: &mut H3SendRequest,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
    ) -> Result<H3StreamingResponse, anyhow::Error> {
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid backend URL: {}", e))?;

        let _host = uri.host().unwrap_or(&proxy.backend_host);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let req_method: http::Method = method
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid HTTP method: {}", method))?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);
        for (name, value) in headers {
            match name.as_str() {
                "connection" | "transfer-encoding" | "keep-alive" | "upgrade" => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(())?;
        let mut stream = send_request.send_request(req).await?;

        if !body.is_empty() {
            stream.send_data(body).await?;
        }
        stream.finish().await?;

        let response = stream.recv_response().await?;
        let status = response.status().as_u16();

        let mut response_headers = HashMap::with_capacity(response.headers().keys_len());
        for (name, value) in response.headers() {
            // Skip hop-by-hop headers during collection (avoids allocating
            // String keys that would be immediately removed by the caller).
            match name.as_str() {
                "connection" | "keep-alive" | "proxy-authenticate" | "proxy-connection" | "te"
                | "trailer" | "transfer-encoding" | "upgrade" => continue,
                _ => {}
            }
            if let Ok(value_str) = value.to_str() {
                response_headers.insert(name.as_str().to_string(), value_str.to_string());
            }
        }

        Ok(H3StreamingResponse {
            status,
            headers: response_headers,
            recv_stream: stream,
        })
    }

    /// Execute an HTTP/3 request, streaming the request body from an h3 server
    /// frontend stream directly to the backend without buffering into `Vec<u8>`.
    ///
    /// Returns headers and a stream handle for the response body. Body size
    /// limits are enforced inline during streaming. This is the zero-copy
    /// request body path for the H3 frontend when no plugins need body buffering
    /// and no retries are configured.
    async fn do_request_streaming_body(
        send_request: &mut H3SendRequest,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        frontend_stream: &mut h3::server::RequestStream<
            h3_quinn::BidiStream<bytes::Bytes>,
            bytes::Bytes,
        >,
        max_request_body_size: usize,
    ) -> Result<H3StreamingResponse, anyhow::Error> {
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid backend URL: {}", e))?;

        let _host = uri.host().unwrap_or(&proxy.backend_host);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let req_method: http::Method = method
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid HTTP method: {}", method))?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);
        for (name, value) in headers {
            match name.as_str() {
                "connection" | "transfer-encoding" | "keep-alive" | "upgrade" => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(())?;
        let mut backend_stream = send_request.send_request(req).await?;

        // Stream request body: read chunks from frontend, forward to backend.
        // Uses Buf::copy_to_bytes() which is zero-copy when the underlying
        // buffer is already bytes::Bytes (common with h3-quinn).
        let mut total_sent: usize = 0;
        while let Some(mut chunk) = frontend_stream.recv_data().await? {
            let len = chunk.remaining();
            if max_request_body_size > 0 {
                total_sent += len;
                if total_sent > max_request_body_size {
                    return Err(anyhow::anyhow!("Request body exceeds maximum size"));
                }
            }
            backend_stream.send_data(chunk.copy_to_bytes(len)).await?;
        }
        backend_stream.finish().await?;

        let response = backend_stream.recv_response().await?;
        let status = response.status().as_u16();

        let mut response_headers = HashMap::with_capacity(response.headers().keys_len());
        for (name, value) in response.headers() {
            // Skip hop-by-hop headers during collection (avoids allocating
            // String keys that would be immediately removed by the caller).
            match name.as_str() {
                "connection" | "keep-alive" | "proxy-authenticate" | "proxy-connection" | "te"
                | "trailer" | "transfer-encoding" | "upgrade" => continue,
                _ => {}
            }
            if let Ok(value_str) = value.to_str() {
                response_headers.insert(name.as_str().to_string(), value_str.to_string());
            }
        }

        Ok(H3StreamingResponse {
            status,
            headers: response_headers,
            recv_stream: backend_stream,
        })
    }

    /// Send an HTTP/3 request with a streaming request body from the frontend,
    /// returning headers and a stream handle for the response body.
    ///
    /// The request body is read from `frontend_stream.recv_data()` and forwarded
    /// directly to the backend without buffering. This avoids `Vec<u8>` allocation
    /// for large request bodies when no plugins need body inspection.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_streaming_body(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        frontend_stream: &mut h3::server::RequestStream<
            h3_quinn::BidiStream<bytes::Bytes>,
            bytes::Bytes,
        >,
        max_request_body_size: usize,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> Result<H3StreamingResponse, anyhow::Error> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;

        // No thread-local fast path for streaming body — the frontend stream is
        // consumed during the request, so we can't retry on a different connection
        // if the first attempt fails mid-body. Go straight to the slow path.
        let key = Self::pool_key(proxy, start);

        if let Some(entry) = self.entries.get(&key) {
            entry
                .last_used_epoch_ms
                .store(now_epoch_ms(), Ordering::Relaxed);
            let mut sr = entry.send_request.clone();
            drop(entry);

            // Single attempt — body is consumed, no retry possible.
            // On error, evict the stale connection so subsequent requests
            // don't repeatedly fail on the same dead QUIC handle.
            match Self::do_request_streaming_body(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                frontend_stream,
                max_request_body_size,
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!(
                        "HTTP/3 streaming body: cached connection failed, evicting: {}",
                        e
                    );
                    self.entries.remove(&key);
                    return Err(e);
                }
            }
        }

        // Create new connection
        let tls_config = tls_config_fn()?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_connection(proxy, &tls_config, Some(&h3_config))
            .await?;
        let mut sr_for_request = sr.clone();

        self.entries.insert(
            key,
            H3PoolEntry {
                send_request: sr,
                last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            },
        );

        Self::do_request_streaming_body(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            frontend_stream,
            max_request_body_size,
        )
        .await
    }

    /// Send an HTTP/3 request with a streaming request body to an explicit
    /// host/port target.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_with_target_streaming_body(
        &self,
        proxy: &Proxy,
        target_host: &str,
        target_port: u16,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        frontend_stream: &mut h3::server::RequestStream<
            h3_quinn::BidiStream<bytes::Bytes>,
            bytes::Bytes,
        >,
        max_request_body_size: usize,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> Result<H3StreamingResponse, anyhow::Error> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        let key = Self::pool_key_for_target(target_host, target_port, start);

        if let Some(entry) = self.entries.get(&key) {
            entry
                .last_used_epoch_ms
                .store(now_epoch_ms(), Ordering::Relaxed);
            let mut sr = entry.send_request.clone();
            drop(entry);

            match Self::do_request_streaming_body(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                frontend_stream,
                max_request_body_size,
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!(
                        "HTTP/3 streaming body: cached connection to {}:{} failed, evicting: {}",
                        target_host, target_port, e
                    );
                    self.entries.remove(&key);
                    return Err(e);
                }
            }
        }

        let tls_config = tls_config_fn()?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_connection_to_target(target_host, target_port, &tls_config, Some(&h3_config))
            .await?;
        let mut sr_for_request = sr.clone();

        self.entries.insert(
            key,
            H3PoolEntry {
                send_request: sr,
                last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            },
        );

        Self::do_request_streaming_body(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            frontend_stream,
            max_request_body_size,
        )
        .await
    }

    /// Send an HTTP/3 request, returning headers and a stream handle for the
    /// response body. Same pool key / fallback / reconnect logic as `request()`.
    pub async fn request_streaming(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> Result<H3StreamingResponse, anyhow::Error> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;

        // Fast path: thread-local buffer lookup (zero allocation on cache hit)
        thread_local! {
            static KEY_BUF: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(128));
        }
        let cached = KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            Self::write_pool_key(&mut buf, proxy, start);
            if let Some(entry) = self.entries.get(&*buf) {
                entry
                    .last_used_epoch_ms
                    .store(now_epoch_ms(), Ordering::Relaxed);
                let sr = entry.send_request.clone();
                drop(entry);
                return Some(sr);
            }
            None
        });
        if let Some(mut sr) = cached
            && let Ok(result) = Self::do_request_streaming(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                body.clone(),
            )
            .await
        {
            return Ok(result);
        }

        // Slow path: allocate pool key String
        let key = Self::pool_key(proxy, start);

        if let Some(entry) = self.entries.get(&key) {
            entry
                .last_used_epoch_ms
                .store(now_epoch_ms(), Ordering::Relaxed);
            let mut sr = entry.send_request.clone();
            drop(entry);

            match Self::do_request_streaming(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                body.clone(),
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!("HTTP/3 cached connection failed, reconnecting: {}", e);
                    self.entries.remove(&key);

                    for offset in 1..conns_per_backend {
                        let fallback_index = (start + offset) % conns_per_backend;
                        let fallback_key = Self::pool_key(proxy, fallback_index);
                        if let Some(entry) = self.entries.get(&fallback_key) {
                            entry
                                .last_used_epoch_ms
                                .store(now_epoch_ms(), Ordering::Relaxed);
                            let mut fallback_sr = entry.send_request.clone();
                            drop(entry);
                            match Self::do_request_streaming(
                                &mut fallback_sr,
                                proxy,
                                method,
                                backend_url,
                                headers,
                                body.clone(),
                            )
                            .await
                            {
                                Ok(result) => return Ok(result),
                                Err(_) => {
                                    self.entries.remove(&fallback_key);
                                }
                            }
                        }
                    }
                }
            }
        }

        let tls_config = tls_config_fn()?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_connection(proxy, &tls_config, Some(&h3_config))
            .await?;
        let mut sr_for_request = sr.clone();

        self.entries.insert(
            key,
            H3PoolEntry {
                send_request: sr,
                last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            },
        );

        Self::do_request_streaming(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            body,
        )
        .await
    }

    /// Send an HTTP/3 request to an explicit host/port target, returning headers
    /// and a stream handle for the response body.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_with_target_streaming(
        &self,
        proxy: &Proxy,
        target_host: &str,
        target_port: u16,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> Result<H3StreamingResponse, anyhow::Error> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        let key = Self::pool_key_for_target(target_host, target_port, start);

        if let Some(entry) = self.entries.get(&key) {
            entry
                .last_used_epoch_ms
                .store(now_epoch_ms(), Ordering::Relaxed);
            let mut sr = entry.send_request.clone();
            drop(entry);

            match Self::do_request_streaming(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                body.clone(),
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!(
                        "HTTP/3 cached connection to {}:{} failed, reconnecting: {}",
                        target_host, target_port, e
                    );
                    self.entries.remove(&key);

                    for offset in 1..conns_per_backend {
                        let fallback_index = (start + offset) % conns_per_backend;
                        let fallback_key =
                            Self::pool_key_for_target(target_host, target_port, fallback_index);
                        if let Some(entry) = self.entries.get(&fallback_key) {
                            entry
                                .last_used_epoch_ms
                                .store(now_epoch_ms(), Ordering::Relaxed);
                            let mut fallback_sr = entry.send_request.clone();
                            drop(entry);
                            match Self::do_request_streaming(
                                &mut fallback_sr,
                                proxy,
                                method,
                                backend_url,
                                headers,
                                body.clone(),
                            )
                            .await
                            {
                                Ok(result) => return Ok(result),
                                Err(_) => {
                                    self.entries.remove(&fallback_key);
                                }
                            }
                        }
                    }
                }
            }
        }

        let tls_config = tls_config_fn()?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_connection_to_target(target_host, target_port, &tls_config, Some(&h3_config))
            .await?;
        let mut sr_for_request = sr.clone();

        self.entries.insert(
            key,
            H3PoolEntry {
                send_request: sr,
                last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            },
        );

        Self::do_request_streaming(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            body,
        )
        .await
    }

    /// Background cleanup task that evicts idle connections.
    fn start_cleanup_task(&self) {
        let entries = self.entries.clone();
        let cleanup_secs = self.env_config.pool_cleanup_interval_seconds.max(1);
        let idle_timeout_ms = self
            .env_config
            .http3_pool_idle_timeout_seconds
            .saturating_mul(1000);
        tokio::spawn(async move {
            let mut cleanup_timer = tokio::time::interval(Duration::from_secs(cleanup_secs));
            loop {
                cleanup_timer.tick().await;
                let now = now_epoch_ms();
                let mut keys_to_remove = Vec::new();
                for entry in entries.iter() {
                    let last_used = entry.last_used_epoch_ms.load(Ordering::Relaxed);
                    let idle_ms = now.saturating_sub(last_used);
                    if idle_ms > idle_timeout_ms {
                        keys_to_remove.push(entry.key().clone());
                    }
                }
                if !keys_to_remove.is_empty() {
                    debug!(
                        "HTTP/3 pool cleanup: evicting {} idle connections",
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

/// HTTP/3 client for connecting to backend services over QUIC.
///
/// Note: For the reverse proxy hot path, use `Http3ConnectionPool` instead.
/// This client creates a new QUIC endpoint per instance and a new connection
/// per `request()` call — suitable for integration tests but not for
/// high-throughput proxying.
#[derive(Clone)]
pub struct Http3Client {
    endpoint: quinn::Endpoint,
}

#[allow(dead_code)]
impl Http3Client {
    /// Create a new HTTP/3 client with the given TLS configuration.
    ///
    /// The `tls_config` must have ALPN protocols set (typically `b"h3"` for HTTP/3).
    /// The crypto provider must be installed before calling this function
    /// (typically once at application startup via `rustls::crypto::ring::default_provider().install_default()`).
    ///
    /// The optional `h3_config` provides QUIC transport tuning parameters
    /// (stream/connection window sizes, send window). When `None`, uses
    /// the same optimized defaults as `Http3ServerConfig::default()`.
    pub fn new(
        tls_config: Arc<rustls::ClientConfig>,
        h3_config: Option<&super::config::Http3ServerConfig>,
    ) -> Result<Self, anyhow::Error> {
        // Convert rustls config to QUIC-compatible config.
        // This validates that the config has TLS 1.3 support with an appropriate
        // initial cipher suite (AES-128-GCM-SHA256).
        let quic_client_config = QuicClientConfig::try_from(tls_config)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC client config (ensure TLS 1.3 cipher suites are available): {}", e))?;

        let default_cfg = super::config::Http3ServerConfig::default();
        let cfg = h3_config.unwrap_or(&default_cfg);

        // Apply QUIC transport tuning for the client side
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.stream_receive_window(
            quinn::VarInt::from_u64(cfg.stream_receive_window)
                .unwrap_or(quinn::VarInt::from_u32(1_048_576)),
        );
        transport_config.receive_window(
            quinn::VarInt::from_u64(cfg.receive_window)
                .unwrap_or(quinn::VarInt::from_u32(4_194_304)),
        );
        transport_config.send_window(cfg.send_window);

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport_config));

        // Bind to any available local UDP port
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Send an HTTP/3 request to the specified backend.
    pub async fn request(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: Vec<(http::header::HeaderName, http::header::HeaderValue)>,
        body: bytes::Bytes,
    ) -> Result<(u16, Vec<u8>, std::collections::HashMap<String, String>), anyhow::Error> {
        // Parse URL to get host and port
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid backend URL: {}", e))?;

        let host = uri.host().unwrap_or(&proxy.backend_host);
        let port = uri.port_u16().unwrap_or(proxy.backend_port);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // Resolve the backend address
        let addr = resolve_backend_addr(host, port).await?;

        debug!(
            "HTTP/3 client connecting to {}:{} (resolved: {})",
            host, port, addr
        );

        // Establish QUIC connection
        let connection = self
            .endpoint
            .connect(addr, host)?
            .await
            .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))?;

        // Create HTTP/3 connection
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;

        // Drive the connection in background. The driver future completes when
        // the connection is closed, so we spawn it and let it clean up naturally.
        tokio::spawn(async move {
            let err = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            debug!("HTTP/3 connection driver closed: {}", err);
        });

        // Build the request with the correct URI (path only, not full URL)
        let req_method: http::Method = method
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid HTTP method: {}", method))?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);

        // Add headers, skipping connection-level headers not valid in HTTP/3
        for (name, value) in &headers {
            match name.as_str() {
                // These are hop-by-hop headers from HTTP/1.1, not valid in HTTP/3
                "connection" | "transfer-encoding" | "keep-alive" | "upgrade" => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(())?;

        // Send request
        let mut stream = send_request.send_request(req).await?;

        // Send body if present
        if !body.is_empty() {
            stream.send_data(body).await?;
        }
        stream.finish().await?;

        // Receive response
        let response = stream.recv_response().await?;
        let status = response.status().as_u16();

        // Collect response headers
        let mut response_headers = std::collections::HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                response_headers.insert(name.as_str().to_string(), value_str.to_string());
            }
        }

        // Collect response body
        let mut response_body = Vec::new();
        while let Some(chunk) = stream.recv_data().await? {
            response_body.extend_from_slice(chunk.chunk());
        }

        Ok((status, response_body, response_headers))
    }
}

/// Create a shared QUIC endpoint for one address family (IPv4 or IPv6).
///
/// The endpoint has no default client config — callers use `connect_with()`
/// to pass per-connection TLS config. On Linux, applies `IP_BIND_ADDRESS_NO_PORT`
/// to defer ephemeral port allocation to `connect()` time.
fn create_shared_quic_endpoint(is_ipv6: bool) -> Result<quinn::Endpoint, anyhow::Error> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let _ = crate::socket_opts::set_ip_bind_address_no_port(socket.as_raw_fd(), true);
    }

    let bind_addr: SocketAddr = if is_ipv6 {
        "[::]:0".parse()?
    } else {
        "0.0.0.0:0".parse()?
    };
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;

    let std_socket: std::net::UdpSocket = socket.into();
    let runtime =
        quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("No async runtime found"))?;
    let endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, std_socket, runtime)?;
    Ok(endpoint)
}

/// Resolve a hostname:port to a SocketAddr using the shared DNS cache.
///
/// Uses the gateway's `DnsCache` exclusively — no fallback to system DNS.
/// The cache is pre-warmed at startup and refreshes in the background.
async fn resolve_backend_addr_cached(
    host: &str,
    port: u16,
    dns_cache: &crate::dns::DnsCache,
    dns_override: Option<&str>,
    dns_cache_ttl_seconds: Option<u64>,
) -> Result<SocketAddr, anyhow::Error> {
    // Fast path: IP literal needs no DNS
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    let ip = dns_cache
        .resolve(host, dns_override, dns_cache_ttl_seconds)
        .await
        .map_err(|e| anyhow::anyhow!("DNS resolution failed for {}:{}: {}", host, port, e))?;

    Ok(SocketAddr::new(ip, port))
}

/// Resolve a hostname:port to a SocketAddr (system DNS, no cache).
///
/// Used only by `Http3Client` (test/integration client). The pool uses
/// `resolve_backend_addr_cached` instead.
async fn resolve_backend_addr(host: &str, port: u16) -> Result<SocketAddr, anyhow::Error> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    let addr = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|e| anyhow::anyhow!("DNS resolution failed for {}:{}: {}", host, port, e))?
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!("DNS resolution returned no addresses for {}:{}", host, port)
        })?;

    Ok(addr)
}
