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

use anyhow::Result;
use async_trait::async_trait;
use bytes::Buf;
use http::Request;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use quinn::crypto::rustls::QuicClientConfig;
use tracing::debug;

use crate::config::PoolConfig;
use crate::config::types::Proxy;
use crate::pool::{GenericPool, PoolManager};

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
    // IMPORTANT: H3/QUIC stream-protocol markers must be checked BEFORE the
    // generic "reset" / "closed" substrings below. `RESET_STREAM` (an H3
    // frame that aborts a single stream, not the whole connection) contains
    // "reset", and `stream_closed` contains "closed" — classifying these as
    // `ConnectionReset` / `ConnectionClosed` would hide the fact that they
    // are protocol-level stream errors. Also do NOT use the bare substring
    // "stream" here — it would match "upstream" (as in "upstream target",
    // "upstream id") and mislabel load-balancer / backend-selection failures
    // as protocol errors. Keep the matches anchored to tokens h3/quinn
    // actually emit.
    } else if msg.contains("goaway")
        || msg.contains("protocol")
        || msg.contains("reset_stream")
        || msg.contains("stream reset")
        || msg.contains("stream id")
        || msg.contains("stream_id")
        || msg.contains("stream_closed")
        || msg.contains("stream closed")
        // h3 0.0.8 emits typed `LocalError::Application { code: H3_*, ... }`
        // variants on protocol violations (e.g. stream finished without
        // response headers after a GOAWAY) that render with an `H3_` prefix
        // in the message. Treat any `h3_` token as a protocol error so the
        // downgrade path fires for the full family of H3 protocol faults
        // (H3_FRAME_UNEXPECTED, H3_FRAME_ERROR, H3_GENERAL_PROTOCOL_ERROR,
        // etc.). `h3::` is kept for typed errors that render with the
        // fully-qualified Rust path.
        || msg.contains("stream finished")
        || msg.contains("h3::")
        || msg.contains("h3_")
        || msg.contains("quic")
    {
        ErrorClass::ProtocolError
    } else if msg.contains("reset") {
        ErrorClass::ConnectionReset
    } else if msg.contains("broken pipe")
        || msg.contains("closed")
        // h3 0.0.8 renders `ConnectionErrorIncoming::ApplicationClose` as
        // `"ApplicationClose"` (no trailing 'd') — doesn't match the
        // `"closed"` substring above, leaving these as RequestError and
        // bypassing the H3 capability-registry downgrade. The typed chain
        // doesn't help either: h3's error types don't implement `source()`
        // so we never reach the quinn::ConnectionError downcast. Match
        // the h3 spelling explicitly.
        || msg.contains("applicationclose")
    {
        ErrorClass::ConnectionClosed
    } else {
        ErrorClass::RequestError
    }
}

/// Type alias for the h3 send request handle.
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;

/// Type alias for the h3 client request stream (bidirectional).
pub type H3RequestStream =
    h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>;

/// Error returned by [`Http3ConnectionPool`] when an HTTP/3 request fails.
///
/// Carries the underlying [`anyhow::Error`] alongside `request_on_wire`, a
/// sticky boolean tracking whether the request was committed to the
/// backend's application layer on ANY attempt within this pool call —
/// including internal cached-then-fallback retries. Once `request_on_wire`
/// is `true`, gateway-level retries must respect `retry_on_methods` because
/// the backend may have processed the request; replaying it could cause
/// non-idempotent double-execution.
///
/// Set to `true` as soon as `send_request().await` succeeds (the QUIC
/// stream is opened and request headers are committed) — regardless of
/// whether `send_data` / `finish` / `recv_response` succeeds afterwards.
/// The pool's internal retry chain promotes the flag forward so a later
/// failed-connect attempt cannot mask the earlier wire commitment.
///
/// Constructors:
/// - [`H3PoolError::pre_wire`] — request never reached the backend (DNS,
///   TLS, connect, h3 session creation, or `send_request` itself failed).
/// - [`H3PoolError::post_wire`] — request was at least partially sent;
///   any failure here loses idempotency safety.
/// - [`H3PoolError::promote_on_wire_if`] — conditionally promote a stored
///   error to `request_on_wire=true` (no-op when the condition is false).
///   Used by the pool's internal retry chain to surface the "any attempt
///   committed" semantics: each fresh-connect setup `?` exit threads
///   `any_request_on_wire` through this method so a previous post-wire
///   attempt's commitment is preserved across the final error.
#[derive(Debug)]
pub struct H3PoolError {
    inner: anyhow::Error,
    request_on_wire: bool,
}

impl H3PoolError {
    /// Construct an error for a failure that occurred BEFORE the request
    /// reached the backend's application layer (DNS / TLS / handshake /
    /// `send_request` itself failed). Safe to retry regardless of
    /// idempotency.
    pub fn pre_wire(error: impl Into<anyhow::Error>) -> Self {
        Self {
            inner: error.into(),
            request_on_wire: false,
        }
    }

    /// Construct an error for a failure that occurred AFTER the H3 stream
    /// was opened (request headers were committed). Even if the body is
    /// only partially sent, the backend may have processed the request,
    /// so retries must respect `retry_on_methods`.
    pub fn post_wire(error: impl Into<anyhow::Error>) -> Self {
        Self {
            inner: error.into(),
            request_on_wire: true,
        }
    }

    /// Borrow the underlying error for downcast / display / `tracing` use.
    pub fn as_error(&self) -> &anyhow::Error {
        &self.inner
    }

    /// Returns `true` if the request was committed to the wire on any
    /// attempt covered by this error. Drives `BackendResponse::connection_error`
    /// at the gateway: `connection_error = !request_on_wire`.
    pub fn request_on_wire(&self) -> bool {
        self.request_on_wire
    }

    /// Conditionally promote the sticky `request_on_wire` flag.
    ///
    /// - When `condition` is `true`, the flag is set to `true` (no-op if
    ///   already `true`).
    /// - When `condition` is `false`, this is a NO-OP — the existing flag
    ///   is preserved, never demoted from `true` back to `false`.
    ///
    /// This asymmetry is deliberate: the pool's internal retry chain
    /// tracks `any_request_on_wire` across attempts, and threads that
    /// boolean through `?` exits via `e.promote_on_wire_if(any_request_on_wire)`.
    /// A `false` value just means "no earlier attempt committed the
    /// body" — it must NOT clobber a `true` flag that an earlier
    /// `H3PoolError::post_wire(...)` constructor set.
    pub fn promote_on_wire_if(mut self, condition: bool) -> Self {
        if condition {
            self.request_on_wire = true;
        }
        self
    }

    /// Consume and return the underlying error, dropping the body-on-wire
    /// signal. Used by callers that have already extracted the signal.
    #[allow(dead_code)] // Public escape hatch for callers that need owned anyhow::Error.
    pub fn into_error(self) -> anyhow::Error {
        self.inner
    }
}

impl std::fmt::Display for H3PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.inner, f)
    }
}

impl std::error::Error for H3PoolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // `anyhow::Error::source()` walks through the chain to the next
        // typed cause — exactly what classifiers expect.
        self.inner.source()
    }
}

/// Convenience: lets callers pass `&H3PoolError` directly to classifiers
/// that take `&(dyn std::error::Error + 'static)` (e.g.
/// [`classify_http3_error`] and the H3 dispatcher's `classify_h3_error`
/// wrapper).
///
/// Without this impl, every call site would need a manual
/// `e.as_error().as_ref()` to peel back to the inner anyhow chain —
/// `anyhow::Error::deref` returns `&(dyn Error + Send + Sync + 'static)`,
/// not the same trait-object shape the classifier signature expects, and
/// `H3PoolError::as_error()` returns the wrapper rather than a trait
/// object. Implementing `AsRef<dyn Error + Send + Sync + 'static>`
/// lets `e.as_ref()` flow through the wrapper to the inner anyhow's
/// `as_ref()` in one step, which the Rust trait-object upcast at the
/// classifier signature accepts.
///
/// Net effect at call sites: `classify_h3_error(e.as_ref())` reads as
/// "classify the underlying error chain" without leaking the
/// `H3PoolError` -> `anyhow::Error` -> `dyn Error` shuffle.
impl AsRef<dyn std::error::Error + Send + Sync + 'static> for H3PoolError {
    fn as_ref(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self.inner.as_ref()
    }
}

/// Result type alias for the H3 pool.
pub type H3PoolResult<T> = std::result::Result<T, H3PoolError>;

/// Result of a streaming HTTP/3 request — headers received, body still in flight.
///
/// The caller reads response body chunks via `recv_stream.recv_data()`.
pub struct H3StreamingResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub recv_stream: H3RequestStream,
}

/// HTTP/3 connection pool for proxying requests to HTTP/3 backends.
///
/// Caches QUIC connections and h3 session handles per backend `host:port`,
/// avoiding the enormous overhead of creating a new UDP socket, QUIC handshake,
/// and h3 session for every request. Each cached connection supports full
/// HTTP/3 multiplexing (concurrent streams).
pub struct Http3ConnectionPool {
    pool: Arc<GenericPool<Http3PoolManager>>,
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

#[derive(Clone, Default)]
struct Http3PoolManager;

#[async_trait]
impl PoolManager for Http3PoolManager {
    type Connection = H3SendRequest;

    fn build_key(&self, proxy: &Proxy, host: &str, port: u16, shard: usize, buf: &mut String) {
        Http3ConnectionPool::write_pool_key_with_host(buf, host, port, proxy, shard);
    }

    // HTTP/3 request paths establish new connections through
    // `GenericPool::create_or_get_existing_owned()` because QUIC setup needs
    // per-call TLS and H3 config objects that are not part of the manager.
    async fn create(&self, _key: &str, _proxy: &Proxy) -> Result<Self::Connection> {
        Err(anyhow::anyhow!(
            "Http3ConnectionPool uses GenericPool::create_or_get_existing_owned for creation"
        ))
    }

    fn is_healthy(&self, _conn: &Self::Connection) -> bool {
        true
    }

    fn destroy(&self, conn: Self::Connection) {
        drop(conn);
    }
}

impl Http3ConnectionPool {
    pub fn new(env_config: Arc<crate::config::EnvConfig>, dns_cache: crate::dns::DnsCache) -> Self {
        let connections_per_backend = env_config.http3_connections_per_backend;
        let cleanup_interval = Duration::from_secs(env_config.pool_cleanup_interval_seconds.max(1));
        let pool_cfg = PoolConfig {
            idle_timeout_seconds: env_config.http3_pool_idle_timeout_seconds,
            max_idle_per_host: connections_per_backend.max(1),
            ..PoolConfig::default()
        };

        Self {
            pool: GenericPool::new(Arc::new(Http3PoolManager), pool_cfg, cleanup_interval),
            env_config,
            dns_cache,
            conn_counter: AtomicU64::new(0),
            connections_per_backend,
            ipv4_endpoint: tokio::sync::OnceCell::new(),
            ipv6_endpoint: tokio::sync::OnceCell::new(),
        }
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
        self.pool.pool_size()
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
        Self::write_pool_key_with_host(buf, &proxy.backend_host, proxy.backend_port, proxy, index);
    }

    fn write_pool_key_with_host(
        buf: &mut String,
        host: &str,
        port: u16,
        proxy: &Proxy,
        index: usize,
    ) {
        use std::fmt::Write;
        buf.clear();
        // Key shape:
        //   host|port|index|dns_override|ca|mtls_cert|mtls_key|verify
        //
        // This must cover every dimension that affects QUIC connection
        // identity *and* matches the backend-capability registry key for
        // the same target (see `backend_capabilities::write_capability_key`).
        // Dropping `dns_override` or either mTLS path would let one proxy's
        // probed QUIC connection be reused for another proxy whose
        // resolver / cert material differs — the exact wrong-backend /
        // wrong-identity bug the reviewer flagged.
        let _ = write!(
            buf,
            "{}|{}|{}|{}|",
            host,
            port,
            index,
            proxy.dns_override.as_deref().unwrap_or_default(),
        );
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
        buf.push_str(
            proxy
                .resolved_tls
                .client_key_path
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

    /// Pool key for the retry / upstream-target path.
    ///
    /// Takes `&Proxy` (not just host/port) so the key includes every
    /// dimension that affects QUIC connection identity —
    /// `dns_override`, CA, mTLS cert/key, verify flag — matching the
    /// backend-capability registry key for the same target. Without this,
    /// a capability probed through one proxy's resolver / cert material
    /// could be served by a pooled QUIC connection originated by a
    /// different proxy.
    pub fn pool_key_for_target(proxy: &Proxy, host: &str, port: u16, index: usize) -> String {
        let mut key = String::with_capacity(128);
        Self::write_pool_key_with_host(&mut key, host, port, proxy, index);
        key
    }

    async fn create_or_get_proxy_sender(
        &self,
        key: String,
        proxy: &Proxy,
        tls_config: Arc<rustls::ClientConfig>,
        h3_config: super::config::Http3ServerConfig,
    ) -> Result<H3SendRequest, anyhow::Error> {
        // H3 is the one pool that needs extra creation context beyond the
        // `Proxy`, so it uses the shared shell's explicit creation closure.
        self.pool
            .create_or_get_existing_owned(key, |_| {
                let tls_config = tls_config.clone();
                let h3_config = h3_config.clone();
                async move {
                    self.create_connection(proxy, &tls_config, Some(&h3_config))
                        .await
                }
            })
            .await
    }

    async fn create_or_get_target_sender(
        &self,
        key: String,
        proxy: &Proxy,
        host: &str,
        port: u16,
        tls_config: Arc<rustls::ClientConfig>,
        h3_config: super::config::Http3ServerConfig,
    ) -> Result<H3SendRequest, anyhow::Error> {
        self.pool
            .create_or_get_existing_owned(key, |_| {
                let tls_config = tls_config.clone();
                let h3_config = h3_config.clone();
                async move {
                    self.create_connection_to_target(
                        proxy,
                        host,
                        port,
                        &tls_config,
                        Some(&h3_config),
                    )
                    .await
                }
            })
            .await
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
        if self.pool.cached(&key).is_some() {
            return Ok(());
        }
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let _ = self
            .create_or_get_proxy_sender(key, proxy, tls_config.clone(), h3_config)
            .await?;
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
    ///
    /// Body-on-wire tracking: the pool tries the cached connection first, then
    /// falls back across other cached indices, then opens a new connection.
    /// `any_request_on_wire` is set sticky across all internal attempts — once
    /// one of them got past `send_request` (request headers committed), the
    /// final returned [`H3PoolError`] reports `request_on_wire=true` regardless
    /// of which later attempt produced the actual error message. This prevents
    /// the gateway from inferring `connection_error=true` and replaying a
    /// non-idempotent request that may already have reached the backend on
    /// an earlier internal attempt.
    pub async fn request(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> H3PoolResult<(u16, Vec<u8>, HashMap<String, String>)> {
        // Per-proxy override takes priority over global default
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;

        let mut any_request_on_wire = false;

        let cached = self
            .pool
            .cached_with(|buf| Self::write_pool_key(buf, proxy, start));
        if let Some(mut sr) = cached {
            match Self::do_request(&mut sr, proxy, method, backend_url, headers, body.clone()).await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if e.request_on_wire() {
                        any_request_on_wire = true;
                    }
                    // Cached connection failed — fall through to the full
                    // retry/reconnect path below which allocates pool keys.
                }
            }
        }

        // Slow path: allocate pool key String for cache miss, error recovery,
        // and new connection creation.
        let key = Self::pool_key(proxy, start);

        // Try cached connection on the selected index first
        if let Some(mut sr) = self.pool.cached(&key) {
            match Self::do_request(&mut sr, proxy, method, backend_url, headers, body.clone()).await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if e.request_on_wire() {
                        any_request_on_wire = true;
                    }
                    debug!("HTTP/3 cached connection failed, reconnecting: {}", e);
                    self.pool.invalidate(&key);

                    // Try other cached indices before creating a new connection
                    for offset in 1..conns_per_backend {
                        let fallback_index = (start + offset) % conns_per_backend;
                        let fallback_key = Self::pool_key(proxy, fallback_index);
                        if let Some(mut fallback_sr) = self.pool.cached(&fallback_key) {
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
                                Err(e) => {
                                    if e.request_on_wire() {
                                        any_request_on_wire = true;
                                    }
                                    self.pool.invalidate(&fallback_key);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Create new connection — only now do we need the TLS config.
        //
        // CRITICAL: `tls_config_fn()` and `create_or_get_proxy_sender()`
        // can fail BEFORE `do_request` runs. If an earlier internal
        // attempt above already set `any_request_on_wire = true`, those
        // setup failures must STILL promote the sticky flag — otherwise
        // a post-wire first attempt followed by a fresh-connect setup
        // failure would surface as `request_on_wire=false`, and the
        // gateway would treat the call as pre-wire and replay a
        // non-idempotent request via `retry_on_connect_failure`. Each
        // `?` exit applies the promotion explicitly.
        let tls_config = tls_config_fn()
            .map_err(|e| H3PoolError::pre_wire(e).promote_on_wire_if(any_request_on_wire))?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_or_get_proxy_sender(key, proxy, tls_config, h3_config)
            .await
            .map_err(|e| H3PoolError::pre_wire(e).promote_on_wire_if(any_request_on_wire))?;
        let mut sr_for_request = sr.clone();

        Self::do_request(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            body,
        )
        .await
        .map_err(|e| e.promote_on_wire_if(any_request_on_wire))
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
    ) -> H3PoolResult<(u16, Vec<u8>, HashMap<String, String>)> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        let key = Self::pool_key_for_target(proxy, target_host, target_port, start);

        let mut any_request_on_wire = false;

        // Try cached connection on the selected index first
        if let Some(mut sr) = self.pool.cached(&key) {
            match Self::do_request(&mut sr, proxy, method, backend_url, headers, body.clone()).await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if e.request_on_wire() {
                        any_request_on_wire = true;
                    }
                    debug!(
                        "HTTP/3 cached connection to {}:{} failed, reconnecting: {}",
                        target_host, target_port, e
                    );
                    self.pool.invalidate(&key);

                    // Try other cached indices before creating a new connection
                    for offset in 1..conns_per_backend {
                        let fallback_index = (start + offset) % conns_per_backend;
                        let fallback_key = Self::pool_key_for_target(
                            proxy,
                            target_host,
                            target_port,
                            fallback_index,
                        );
                        if let Some(mut fallback_sr) = self.pool.cached(&fallback_key) {
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
                                Err(e) => {
                                    if e.request_on_wire() {
                                        any_request_on_wire = true;
                                    }
                                    self.pool.invalidate(&fallback_key);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Create new connection to the explicit target.
        // See `request()` for why these `?` exits must apply the
        // sticky `any_request_on_wire` promotion (post-wire cached
        // attempt → fresh-connect setup failure must NOT report
        // request_on_wire=false).
        let tls_config = tls_config_fn()
            .map_err(|e| H3PoolError::pre_wire(e).promote_on_wire_if(any_request_on_wire))?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_or_get_target_sender(
                key,
                proxy,
                target_host,
                target_port,
                tls_config,
                h3_config,
            )
            .await
            .map_err(|e| H3PoolError::pre_wire(e).promote_on_wire_if(any_request_on_wire))?;
        let mut sr_for_request = sr.clone();

        Self::do_request(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            body,
        )
        .await
        .map_err(|e| e.promote_on_wire_if(any_request_on_wire))
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
        transport_config.initial_mtu(cfg.initial_mtu);
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
    /// differs from `proxy.backend_host`/`proxy.backend_port`. Honors the
    /// proxy's `dns_override` / `dns_cache_ttl_seconds` so retries resolve
    /// through the same path the capability probe used — otherwise a
    /// proxy pinning a specific IP via `dns_override` would silently dial
    /// the default DNS answer for the load-balanced target instead.
    async fn create_connection_to_target(
        &self,
        proxy: &Proxy,
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
        transport_config.initial_mtu(cfg.initial_mtu);
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

    /// Execute an HTTP/3 request on an existing SendRequest handle.
    ///
    /// Returns [`H3PoolError`] on failure with `request_on_wire` set
    /// according to whether `send_request` had already opened the QUIC
    /// stream when the failure surfaced — once the stream is open, the
    /// request headers (and possibly body bytes) are committed and the
    /// backend may have processed the request, so the gateway must
    /// respect `retry_on_methods` instead of replaying blindly.
    async fn do_request(
        send_request: &mut H3SendRequest,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
    ) -> H3PoolResult<(u16, Vec<u8>, HashMap<String, String>)> {
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("Invalid backend URL: {}", e)))?;

        let _host = uri.host().unwrap_or(&proxy.backend_host);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let req_method: http::Method = method.parse().map_err(|_| {
            H3PoolError::pre_wire(anyhow::anyhow!("Invalid HTTP method: {}", method))
        })?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);
        for (name, value) in headers {
            match name.as_str() {
                "connection" | "transfer-encoding" | "keep-alive" | "upgrade" => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(()).map_err(H3PoolError::pre_wire)?;
        // `send_request().await` opens the QUIC stream and commits the
        // request headers. Failure here is pre-wire (no stream, no body
        // delivery). Anything below this line is post-wire — the
        // backend may already be processing the request.
        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("send_request failed: {}", e)))?;

        if !body.is_empty() {
            stream
                .send_data(body)
                .await
                .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("send_data failed: {}", e)))?;
        }
        stream
            .finish()
            .await
            .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("finish failed: {}", e)))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("recv_response failed: {}", e)))?;
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
        loop {
            match stream.recv_data().await {
                Ok(Some(chunk)) => response_body.extend_from_slice(chunk.chunk()),
                Ok(None) => break,
                Err(e) => {
                    return Err(H3PoolError::post_wire(anyhow::anyhow!(
                        "recv_data failed: {}",
                        e
                    )));
                }
            }
        }

        Ok((status, response_body, response_headers))
    }

    /// Execute an HTTP/3 request, returning headers and a stream handle for the
    /// response body. Unlike `do_request`, this does NOT buffer the body — the
    /// caller reads chunks via `recv_stream.recv_data()`.
    ///
    /// Body-on-wire semantics match [`do_request`] — `request_on_wire`
    /// flips to `true` once `send_request().await` succeeds.
    async fn do_request_streaming(
        send_request: &mut H3SendRequest,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
    ) -> H3PoolResult<H3StreamingResponse> {
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("Invalid backend URL: {}", e)))?;

        let _host = uri.host().unwrap_or(&proxy.backend_host);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let req_method: http::Method = method.parse().map_err(|_| {
            H3PoolError::pre_wire(anyhow::anyhow!("Invalid HTTP method: {}", method))
        })?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);
        for (name, value) in headers {
            match name.as_str() {
                "connection" | "transfer-encoding" | "keep-alive" | "upgrade" => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(()).map_err(H3PoolError::pre_wire)?;
        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("send_request failed: {}", e)))?;

        if !body.is_empty() {
            stream
                .send_data(body)
                .await
                .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("send_data failed: {}", e)))?;
        }
        stream
            .finish()
            .await
            .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("finish failed: {}", e)))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("recv_response failed: {}", e)))?;
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
    ///
    /// Body-on-wire semantics: `request_on_wire` flips to `true` once the
    /// QUIC stream is opened (`send_request` succeeded). The size-limit
    /// rejection is post-wire because we cannot abort the stream cleanly
    /// after dispatch — the H3 server callers translate this back into a
    /// 413 status which is intentionally not a transport-class failure.
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
    ) -> H3PoolResult<H3StreamingResponse> {
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("Invalid backend URL: {}", e)))?;

        let _host = uri.host().unwrap_or(&proxy.backend_host);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let req_method: http::Method = method.parse().map_err(|_| {
            H3PoolError::pre_wire(anyhow::anyhow!("Invalid HTTP method: {}", method))
        })?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);
        for (name, value) in headers {
            match name.as_str() {
                "connection" | "transfer-encoding" | "keep-alive" | "upgrade" => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(()).map_err(H3PoolError::pre_wire)?;
        let mut backend_stream = send_request
            .send_request(req)
            .await
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("send_request failed: {}", e)))?;

        // Stream request body: read chunks from frontend, forward to backend.
        // Uses Buf::copy_to_bytes() which is zero-copy when the underlying
        // buffer is already bytes::Bytes (common with h3-quinn).
        let mut total_sent: usize = 0;
        loop {
            let recv_res = frontend_stream.recv_data().await;
            let chunk_opt = match recv_res {
                Ok(c) => c,
                Err(e) => {
                    return Err(H3PoolError::post_wire(anyhow::anyhow!(
                        "client disconnected while sending request body: {}",
                        e
                    )));
                }
            };
            let Some(mut chunk) = chunk_opt else { break };
            let len = chunk.remaining();
            if max_request_body_size > 0 {
                total_sent += len;
                if total_sent > max_request_body_size {
                    return Err(H3PoolError::post_wire(anyhow::anyhow!(
                        "Request body exceeds maximum size"
                    )));
                }
            }
            backend_stream
                .send_data(chunk.copy_to_bytes(len))
                .await
                .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("send_data failed: {}", e)))?;
        }
        backend_stream
            .finish()
            .await
            .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("finish failed: {}", e)))?;

        let response = backend_stream
            .recv_response()
            .await
            .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("recv_response failed: {}", e)))?;
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

    /// Execute an HTTP/3 request, streaming the request body from a hyper
    /// `Incoming` body directly to the backend without collecting into `Vec<u8>`.
    ///
    /// Used by the H1/H2 frontend -> H3 backend path when no request-body
    /// plugins need buffering and no retries can replay the body.
    ///
    /// Body-on-wire semantics: `request_on_wire` flips to `true` once
    /// `send_request` succeeds; subsequent client-disconnect / size-limit
    /// errors are post-wire because the backend already received headers.
    #[allow(clippy::too_many_arguments)]
    async fn do_request_streaming_incoming_body(
        send_request: &mut H3SendRequest,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        mut frontend_body: Incoming,
        max_request_body_size: usize,
        bytes_seen: Arc<AtomicU64>,
    ) -> H3PoolResult<H3StreamingResponse> {
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("Invalid backend URL: {}", e)))?;

        let _host = uri.host().unwrap_or(&proxy.backend_host);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let req_method: http::Method = method.parse().map_err(|_| {
            H3PoolError::pre_wire(anyhow::anyhow!("Invalid HTTP method: {}", method))
        })?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);
        for (name, value) in headers {
            match name.as_str() {
                "connection" | "transfer-encoding" | "keep-alive" | "upgrade" => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(()).map_err(H3PoolError::pre_wire)?;
        let mut backend_stream = send_request
            .send_request(req)
            .await
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("send_request failed: {}", e)))?;

        let mut total_sent: usize = 0;
        while let Some(frame_result) = frontend_body.frame().await {
            let frame = frame_result.map_err(|e| {
                H3PoolError::post_wire(anyhow::anyhow!(
                    "Client disconnected while sending request body: {}",
                    e
                ))
            })?;
            let Ok(mut chunk) = frame.into_data() else {
                continue;
            };
            let len = chunk.remaining();
            if max_request_body_size > 0 {
                total_sent += len;
                if total_sent > max_request_body_size {
                    return Err(H3PoolError::post_wire(anyhow::anyhow!(
                        "Request body exceeds maximum size"
                    )));
                }
            }
            if len == 0 {
                continue;
            }
            bytes_seen.fetch_add(len as u64, Ordering::Release);
            backend_stream
                .send_data(chunk.copy_to_bytes(len))
                .await
                .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("send_data failed: {}", e)))?;
        }
        backend_stream
            .finish()
            .await
            .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("finish failed: {}", e)))?;

        let response = backend_stream
            .recv_response()
            .await
            .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("recv_response failed: {}", e)))?;
        let status = response.status().as_u16();

        let mut response_headers = HashMap::with_capacity(response.headers().keys_len());
        for (name, value) in response.headers() {
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
    ) -> H3PoolResult<H3StreamingResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;

        // No thread-local fast path for streaming body — the frontend stream is
        // consumed during the request, so we can't retry on a different connection
        // if the first attempt fails mid-body. Go straight to the slow path.
        let key = Self::pool_key(proxy, start);

        if let Some(mut sr) = self.pool.cached(&key) {
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
                    self.pool.invalidate(&key);
                    return Err(e);
                }
            }
        }

        // Create new connection
        let tls_config = tls_config_fn().map_err(H3PoolError::pre_wire)?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_or_get_proxy_sender(key, proxy, tls_config, h3_config)
            .await
            .map_err(H3PoolError::pre_wire)?;
        let mut sr_for_request = sr.clone();

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

    /// Send an HTTP/3 request with a streaming request body sourced from a
    /// hyper `Incoming` body, returning headers and a stream handle for the
    /// response body.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_streaming_incoming_body(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        frontend_body: Incoming,
        max_request_body_size: usize,
        bytes_seen: Arc<AtomicU64>,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> H3PoolResult<H3StreamingResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        let key = Self::pool_key(proxy, start);
        let mut frontend_body = Some(frontend_body);

        if let Some(mut sr) = self.pool.cached(&key) {
            match Self::do_request_streaming_incoming_body(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                frontend_body
                    .take()
                    .expect("frontend body should be available before first send"),
                max_request_body_size,
                Arc::clone(&bytes_seen),
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!(
                        "HTTP/3 streaming body from Incoming: cached connection failed, evicting: {}",
                        e
                    );
                    self.pool.invalidate(&key);
                    return Err(e);
                }
            }
        }

        let tls_config = tls_config_fn().map_err(H3PoolError::pre_wire)?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_or_get_proxy_sender(key, proxy, tls_config, h3_config)
            .await
            .map_err(H3PoolError::pre_wire)?;
        let mut sr_for_request = sr.clone();

        Self::do_request_streaming_incoming_body(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            frontend_body.expect("frontend body should not be consumed on cache miss"),
            max_request_body_size,
            bytes_seen,
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
    ) -> H3PoolResult<H3StreamingResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        let key = Self::pool_key_for_target(proxy, target_host, target_port, start);

        if let Some(mut sr) = self.pool.cached(&key) {
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
                    self.pool.invalidate(&key);
                    return Err(e);
                }
            }
        }

        let tls_config = tls_config_fn().map_err(H3PoolError::pre_wire)?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_or_get_target_sender(
                key,
                proxy,
                target_host,
                target_port,
                tls_config,
                h3_config,
            )
            .await
            .map_err(H3PoolError::pre_wire)?;
        let mut sr_for_request = sr.clone();

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

    /// Send an HTTP/3 request with a streaming `Incoming` request body to an
    /// explicit host/port target.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_with_target_streaming_incoming_body(
        &self,
        proxy: &Proxy,
        target_host: &str,
        target_port: u16,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        frontend_body: Incoming,
        max_request_body_size: usize,
        bytes_seen: Arc<AtomicU64>,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> H3PoolResult<H3StreamingResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        let key = Self::pool_key_for_target(proxy, target_host, target_port, start);
        let mut frontend_body = Some(frontend_body);

        if let Some(mut sr) = self.pool.cached(&key) {
            match Self::do_request_streaming_incoming_body(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                frontend_body
                    .take()
                    .expect("frontend body should be available before first send"),
                max_request_body_size,
                Arc::clone(&bytes_seen),
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!(
                        "HTTP/3 streaming body from Incoming: cached connection to {}:{} failed, evicting: {}",
                        target_host, target_port, e
                    );
                    self.pool.invalidate(&key);
                    return Err(e);
                }
            }
        }

        let tls_config = tls_config_fn().map_err(H3PoolError::pre_wire)?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_or_get_target_sender(
                key,
                proxy,
                target_host,
                target_port,
                tls_config,
                h3_config,
            )
            .await
            .map_err(H3PoolError::pre_wire)?;
        let mut sr_for_request = sr.clone();

        Self::do_request_streaming_incoming_body(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            frontend_body.expect("frontend body should not be consumed on cache miss"),
            max_request_body_size,
            bytes_seen,
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
    ) -> H3PoolResult<H3StreamingResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;

        let mut any_request_on_wire = false;

        let cached = self
            .pool
            .cached_with(|buf| Self::write_pool_key(buf, proxy, start));
        if let Some(mut sr) = cached {
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
                    if e.request_on_wire() {
                        any_request_on_wire = true;
                    }
                }
            }
        }

        // Slow path: allocate pool key String
        let key = Self::pool_key(proxy, start);

        if let Some(mut sr) = self.pool.cached(&key) {
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
                    if e.request_on_wire() {
                        any_request_on_wire = true;
                    }
                    debug!("HTTP/3 cached connection failed, reconnecting: {}", e);
                    self.pool.invalidate(&key);

                    for offset in 1..conns_per_backend {
                        let fallback_index = (start + offset) % conns_per_backend;
                        let fallback_key = Self::pool_key(proxy, fallback_index);
                        if let Some(mut fallback_sr) = self.pool.cached(&fallback_key) {
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
                                Err(e) => {
                                    if e.request_on_wire() {
                                        any_request_on_wire = true;
                                    }
                                    self.pool.invalidate(&fallback_key);
                                }
                            }
                        }
                    }
                }
            }
        }

        // See `request()` for why these `?` exits must apply the
        // sticky `any_request_on_wire` promotion.
        let tls_config = tls_config_fn()
            .map_err(|e| H3PoolError::pre_wire(e).promote_on_wire_if(any_request_on_wire))?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_or_get_proxy_sender(key, proxy, tls_config, h3_config)
            .await
            .map_err(|e| H3PoolError::pre_wire(e).promote_on_wire_if(any_request_on_wire))?;
        let mut sr_for_request = sr.clone();

        Self::do_request_streaming(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            body,
        )
        .await
        .map_err(|e| e.promote_on_wire_if(any_request_on_wire))
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
    ) -> H3PoolResult<H3StreamingResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        let key = Self::pool_key_for_target(proxy, target_host, target_port, start);

        let mut any_request_on_wire = false;

        if let Some(mut sr) = self.pool.cached(&key) {
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
                    if e.request_on_wire() {
                        any_request_on_wire = true;
                    }
                    debug!(
                        "HTTP/3 cached connection to {}:{} failed, reconnecting: {}",
                        target_host, target_port, e
                    );
                    self.pool.invalidate(&key);

                    for offset in 1..conns_per_backend {
                        let fallback_index = (start + offset) % conns_per_backend;
                        let fallback_key = Self::pool_key_for_target(
                            proxy,
                            target_host,
                            target_port,
                            fallback_index,
                        );
                        if let Some(mut fallback_sr) = self.pool.cached(&fallback_key) {
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
                                Err(e) => {
                                    if e.request_on_wire() {
                                        any_request_on_wire = true;
                                    }
                                    self.pool.invalidate(&fallback_key);
                                }
                            }
                        }
                    }
                }
            }
        }

        // See `request()` for why these `?` exits must apply the
        // sticky `any_request_on_wire` promotion.
        let tls_config = tls_config_fn()
            .map_err(|e| H3PoolError::pre_wire(e).promote_on_wire_if(any_request_on_wire))?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let sr = self
            .create_or_get_target_sender(
                key,
                proxy,
                target_host,
                target_port,
                tls_config,
                h3_config,
            )
            .await
            .map_err(|e| H3PoolError::pre_wire(e).promote_on_wire_if(any_request_on_wire))?;
        let mut sr_for_request = sr.clone();

        Self::do_request_streaming(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            body,
        )
        .await
        .map_err(|e| e.promote_on_wire_if(any_request_on_wire))
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
        transport_config.initial_mtu(cfg.initial_mtu);
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

#[cfg(test)]
mod h3_pool_error_tests {
    //! Inline tests for the body-on-wire signal carried by [`H3PoolError`].
    //!
    //! These cover the construction primitives and the sticky-promotion
    //! behaviour that the pool's internal retry chain relies on. The
    //! end-to-end body-on-wire integration is exercised by the new
    //! functional test in `tests/functional/`.

    use super::*;

    #[test]
    fn pre_wire_marks_request_not_committed() {
        let e = H3PoolError::pre_wire(anyhow::anyhow!("connect refused"));
        assert!(
            !e.request_on_wire(),
            "pre_wire constructor must report request_on_wire=false"
        );
    }

    #[test]
    fn post_wire_marks_request_committed() {
        let e = H3PoolError::post_wire(anyhow::anyhow!("send_data failed"));
        assert!(
            e.request_on_wire(),
            "post_wire constructor must report request_on_wire=true"
        );
    }

    #[test]
    fn promote_on_wire_if_only_promotes_false_to_true() {
        // The pool's retry chain calls `e.promote_on_wire_if(any_request_on_wire)`
        // on each fresh-connect setup `?` exit. The contract is asymmetric:
        // `condition=true` flips false → true; `condition=false` is a no-op.
        let pre = H3PoolError::pre_wire(anyhow::anyhow!("connect refused"));
        let promoted = pre.promote_on_wire_if(true);
        assert!(promoted.request_on_wire());

        // `condition=false` must NOT demote an already-true flag — that's
        // exactly the case where an earlier post-wire attempt set the
        // flag and a later pre-wire setup failure would otherwise clobber
        // it. Verify both directions: `true → true` is idempotent and
        // `false on an already-true` is a no-op.
        let post = H3PoolError::post_wire(anyhow::anyhow!("recv_response failed"));
        assert!(post.promote_on_wire_if(false).request_on_wire());

        let post = H3PoolError::post_wire(anyhow::anyhow!("recv_response failed"));
        assert!(post.promote_on_wire_if(true).request_on_wire());
    }

    #[test]
    fn display_forwards_to_inner_error() {
        let e = H3PoolError::pre_wire(anyhow::anyhow!("synthetic connect failure"));
        let rendered = format!("{}", e);
        assert!(
            rendered.contains("synthetic connect failure"),
            "Display must forward to inner anyhow::Error: got {:?}",
            rendered
        );
    }

    #[test]
    fn classify_http3_error_picks_protocol_for_application_close() {
        // Regression: h3 0.0.8 renders ConnectionError::ApplicationClose
        // as the bare token "ApplicationClose" (no trailing 'd'), so the
        // generic "closed" substring used to miss it. The shared
        // classifier explicitly handles `applicationclose`.
        let err: anyhow::Error = anyhow::anyhow!("connection ApplicationClose received");
        let class = classify_http3_error(err.as_ref());
        assert_eq!(
            class,
            crate::retry::ErrorClass::ConnectionClosed,
            "ApplicationClose must classify as ConnectionClosed (post-wire)"
        );
    }

    #[test]
    fn classify_http3_error_keeps_h3_protocol_codes_as_protocol() {
        // Regression: a stream-level RESET_STREAM contains "reset", and
        // the classifier used to short-circuit on bare "reset" before
        // checking the more specific protocol tokens. The fix puts
        // protocol tokens first.
        let err: anyhow::Error = anyhow::anyhow!("h3 stream RESET_STREAM code=H3_REQUEST_REJECTED");
        assert_eq!(
            classify_http3_error(err.as_ref()),
            crate::retry::ErrorClass::ProtocolError,
            "RESET_STREAM is application-layer (stream abort), not connection reset"
        );
    }

    /// Codex P1 regression: when an earlier internal attempt set
    /// `any_request_on_wire = true` (post-wire) and then `tls_config_fn()`
    /// or `create_or_get_proxy_sender()` fails on the fresh-connect
    /// fallback, the pool MUST promote the sticky flag onto the resulting
    /// `H3PoolError::pre_wire`. Without that promotion, the gateway sees
    /// `request_on_wire=false`, treats the call as pre-wire, and replays
    /// a non-idempotent request via `retry_on_connect_failure` even
    /// though the FIRST internal attempt may already have been processed
    /// by the backend.
    ///
    /// **Coverage scope.** This test is unit-level and only verifies the
    /// closure shape — `H3PoolError::pre_wire(e).promote_on_wire_if(true)`
    /// returns `request_on_wire=true`. It does NOT exercise the live
    /// `Http3ConnectionPool::request*` retry chain (cached attempt's
    /// post-wire failure → fresh-connect setup failure) end-to-end,
    /// because doing that requires a scripted QUIC backend that:
    /// (a) accepts the QUIC handshake, (b) accepts the stream open, (c)
    /// fails the body / response so the cached attempt is post-wire,
    /// then (d) refuses subsequent connect attempts so the fresh-connect
    /// setup also fails. The functional test
    /// `retry_on_connect_failure_fires_with_empty_methods_and_statuses`
    /// covers the gateway-level retry contract end-to-end via ECONNREFUSED
    /// but does not tickle this specific cached-success → fresh-connect
    /// setup-failure ordering. Tracked as a follow-up coverage gap; the
    /// closure-shape assertion below is the regression guard for the
    /// fix that this PR introduces.
    #[test]
    fn pre_wire_setup_failure_after_post_wire_attempt_preserves_sticky_flag() {
        // Simulate: any_request_on_wire = true (an earlier internal attempt
        // sent the request body). Now tls_config_fn() fails.
        let any_request_on_wire = true;
        let synthetic_setup_failure = anyhow::anyhow!("synthetic tls_config_fn() failure");

        let propagated: H3PoolError =
            H3PoolError::pre_wire(synthetic_setup_failure).promote_on_wire_if(any_request_on_wire);

        assert!(
            propagated.request_on_wire(),
            "TLS / sender-creation failure path must propagate sticky \
             request_on_wire=true so the gateway respects retry_on_methods \
             instead of replaying via retry_on_connect_failure. If this \
             assertion fails, a future refactor likely reverted to the \
             bare `map_err(pre_wire)?` shape — restore the closure form: \
             `|e| H3PoolError::pre_wire(e).promote_on_wire_if(any_request_on_wire)`"
        );
    }

    #[test]
    fn pre_wire_setup_failure_with_no_prior_post_wire_attempt_stays_pre_wire() {
        // Counterpart: if NO earlier internal attempt sent the body
        // (any_request_on_wire = false), the same closure must NOT
        // mistakenly mark the error as post-wire.
        let any_request_on_wire = false;
        let synthetic_setup_failure = anyhow::anyhow!("synthetic tls_config_fn() failure");

        let propagated: H3PoolError =
            H3PoolError::pre_wire(synthetic_setup_failure).promote_on_wire_if(any_request_on_wire);

        assert!(
            !propagated.request_on_wire(),
            "Setup failure with no prior post-wire attempt must remain \
             request_on_wire=false so retry_on_connect_failure can fire"
        );
    }
}
