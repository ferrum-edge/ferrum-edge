//! HTTP/2 connection pool using hyper's HTTP/2 client directly.
//!
//! Provides proper HTTP/2 stream multiplexing over a single persistent TLS
//! connection, avoiding the connection-per-request churn that reqwest exhibits
//! under concurrent load. The shared `GenericPool` owns the DashMap, key reuse,
//! and cleanup sweep; this wrapper keeps the readiness and shard-selection logic.

use anyhow::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::cell::Cell;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::PoolConfig;
use crate::config::types::Proxy;
use crate::dns::{DnsCache, DnsConfig};
use crate::pool::{GenericPool, PoolManager};
use crate::tls::TlsPolicy;
use crate::tls::backend::{BackendTlsConfigBuilder, BackendTlsConfigCache};

fn write_http2_pool_key(buf: &mut String, host: &str, port: u16, proxy: &Proxy) {
    use std::fmt::Write;
    buf.clear();
    let _ = write!(buf, "{}|{}|", host, port);
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

fn pool_key_owned(proxy: &Proxy) -> String {
    let mut buf = String::with_capacity(128);
    write_http2_pool_key(&mut buf, &proxy.backend_host, proxy.backend_port, proxy);
    buf
}

fn write_http2_shard_key_inplace(buf: &mut String, base_len: usize, shard: usize) {
    buf.truncate(base_len);
    buf.push('#');
    if shard < 10 {
        buf.push((b'0' + shard as u8) as char);
    } else {
        use std::fmt::Write;
        let _ = write!(buf, "{shard}");
    }
}

#[derive(Clone)]
struct Http2PoolManager {
    global_pool_config: PoolConfig,
    global_env_config: crate::config::EnvConfig,
    dns_cache: DnsCache,
    tls_policy: Option<Arc<TlsPolicy>>,
    crls: crate::tls::CrlList,
    tls_configs: BackendTlsConfigCache,
}

impl Http2PoolManager {
    async fn create_connection(
        &self,
        proxy: &Proxy,
    ) -> Result<http2::SendRequest<Incoming>, Http2PoolError> {
        let host = &proxy.backend_host;
        let port = proxy.backend_port;

        let resolved_ip = self
            .dns_cache
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

        let sock_addr = std::net::SocketAddr::new(resolved_ip, port);
        let addr = sock_addr.to_string();
        let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);

        let tcp = tokio::time::timeout(
            connect_timeout,
            crate::socket_opts::connect_with_socket_opts(sock_addr),
        )
        .await
        .map_err(|_| Http2PoolError::BackendTimeout {
            message: format!(
                "Connect timeout after {}ms to {}",
                proxy.backend_connect_timeout_ms, addr
            ),
            source: Some(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "backend connect timed out",
            )),
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
            Http2PoolError::BackendUnavailable {
                message: format!("Connection refused: {}", e),
                source: Some(BackendUnavailableSource::Io(e)),
            }
        })?;

        let _ = tcp.set_nodelay(true);

        let pool_config = self.global_pool_config.for_proxy(proxy);
        if pool_config.enable_http_keep_alive {
            Self::set_tcp_keepalive(&tcp, pool_config.tcp_keepalive_seconds);
        }

        self.create_tls_connection(tcp, host, proxy, &pool_config)
            .await
    }

    fn build_h2_builder(pool_config: &PoolConfig) -> http2::Builder<TokioExecutor> {
        let mut builder = http2::Builder::new(TokioExecutor::new());
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

    fn get_tls_config(&self, proxy: &Proxy) -> Result<Arc<rustls::ClientConfig>, Http2PoolError> {
        self.tls_configs
            .get_or_try_build(pool_key_owned(proxy), || {
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
                    let message = format!("Failed to build backend TLS config: {}", e);
                    let source = match e {
                        crate::tls::backend::TlsError::Io { source, .. } => {
                            Some(InternalSource::Io(source))
                        }
                        crate::tls::backend::TlsError::Pem { .. }
                        | crate::tls::backend::TlsError::Rustls(_) => {
                            Some(InternalSource::Message(message.clone()))
                        }
                    };
                    Http2PoolError::Internal { message, source }
                })?;

                // Advertise both `h2` and `http/1.1` — the backend picks.
                // If it picks h2 we use this pool; if it picks http/1.1 the
                // caller (create_tls_connection) returns
                // `BackendSelectedHttp1` so the dispatcher can route via
                // reqwest. Advertising only `h2` would fail the handshake
                // against h1-only servers with no graceful recovery.
                tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                Ok::<rustls::ClientConfig, Http2PoolError>(tls_config)
            })
    }

    async fn create_tls_connection(
        &self,
        tcp: TcpStream,
        host: &str,
        proxy: &Proxy,
        pool_config: &PoolConfig,
    ) -> Result<http2::SendRequest<Incoming>, Http2PoolError> {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let tls_config = self.get_tls_config(proxy)?;
        let connector = TlsConnector::from(tls_config);
        let server_name = ServerName::try_from(host.to_string()).map_err(|e| {
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

        // Inspect negotiated ALPN. rustls 0.22+ exposes the chosen protocol
        // on the client session; `get_ref().1` is the `ClientConnection`.
        // If the backend picked http/1.1 (or advertised nothing), short-circuit
        // rather than trying an h2 handshake that will fail anyway. Capability
        // learning happens outside this pool now, so we return the signal but
        // do not cache it here.
        let pool_key = pool_key_owned(proxy);
        let negotiated_is_h2 = matches!(tls_stream.get_ref().1.alpn_protocol(), Some(b"h2"));
        if !negotiated_is_h2 {
            return Err(Http2PoolError::BackendSelectedHttp1 { pool_key });
        }

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

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("http2_pool: TLS connection closed: {}", e);
            }
        });

        Ok(sender)
    }
}

#[async_trait]
impl PoolManager for Http2PoolManager {
    type Connection = http2::SendRequest<Incoming>;

    fn build_key(&self, proxy: &Proxy, host: &str, port: u16, shard: usize, buf: &mut String) {
        write_http2_pool_key(buf, host, port, proxy);
        let base_len = buf.len();
        write_http2_shard_key_inplace(buf, base_len, shard);
    }

    async fn create(&self, _key: &str, proxy: &Proxy) -> Result<http2::SendRequest<Incoming>> {
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

/// HTTP/2 connection pool for HTTPS backends.
pub struct Http2ConnectionPool {
    pool: Arc<GenericPool<Http2PoolManager>>,
    rr_counters: Arc<DashMap<String, Arc<AtomicUsize>>>,
}

impl Default for Http2ConnectionPool {
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

impl Http2ConnectionPool {
    pub fn new(
        global_pool_config: PoolConfig,
        global_env_config: crate::config::EnvConfig,
        dns_cache: DnsCache,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
    ) -> Self {
        let cleanup_interval =
            Duration::from_secs(global_env_config.pool_cleanup_interval_seconds.max(1));
        let manager = Arc::new(Http2PoolManager {
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

    pub fn pool_size(&self) -> usize {
        self.pool.pool_size()
    }

    #[allow(dead_code)] // exercised from integration/unit tests
    pub fn pool_key_for_warmup(proxy: &Proxy) -> String {
        pool_key_owned(proxy)
    }

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

    fn write_shard_key_inplace(buf: &mut String, base_len: usize, shard: usize) {
        write_http2_shard_key_inplace(buf, base_len, shard);
    }

    pub async fn get_sender(
        &self,
        proxy: &Proxy,
    ) -> Result<http2::SendRequest<Incoming>, Http2PoolError> {
        let pool_config = self.pool.manager().global_pool_config.for_proxy(proxy);
        let shard_count = pool_config.http2_connections_per_host.max(1);

        let mut key_buf = String::with_capacity(128);
        write_http2_pool_key(&mut key_buf, &proxy.backend_host, proxy.backend_port, proxy);
        let base_len = key_buf.len();

        // Round-robin counter is per-host, but on FIRST access we seed it with
        // a thread-local PRNG offset so a burst of concurrent requests on a
        // cold pool does not land all on shard 0 before the atomic counter
        // wraps around. `AtomicUsize::fetch_add(1, Relaxed)` is wait-free
        // after the seed — the seed only matters for the first `shard_count`
        // picks per host on this gateway.
        let rr = match self.rr_counters.get(&key_buf) {
            Some(existing) => existing.value().clone(),
            None => self
                .rr_counters
                .entry(key_buf[..base_len].to_owned())
                .or_insert_with(|| Arc::new(AtomicUsize::new(rr_seed())))
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
                    Some(Err(_)) => {
                        self.pool.invalidate(&key_buf);
                    }
                    // Shard exists but is mid-send. Previously we stashed
                    // the first such sender and `timeout(5ms, ready())`ed
                    // on it, which serialized ~100-concurrent bursts onto
                    // the already-busy shard and net-pessimized throughput
                    // (5 MB/100-conc HTTP/2 stuck at 81 RPS vs direct 232).
                    // Skip — we would rather open a fresh connection than
                    // wait on this one. `create_or_get_existing_owned` is
                    // per-key-coalesced, so a burst of concurrent callers
                    // for the same shard key dedupes onto ONE create future
                    // (no thundering herd).
                    None => {}
                }
            }
        }

        Self::write_shard_key_inplace(&mut key_buf, base_len, start);
        let selected_key = key_buf.clone();
        let manager = Arc::clone(self.pool.manager());
        let sender = match self
            .pool
            .create_or_get_existing_owned(selected_key, |key| async move {
                let _ = key;
                manager.create_connection(proxy).await
            })
            .await
        {
            Ok(sender) => sender,
            Err(err) => {
                for offset in 1..shard_count {
                    let shard = (start + offset) % shard_count;
                    Self::write_shard_key_inplace(&mut key_buf, base_len, shard);
                    if let Some(sender) = self.pool.cached(&key_buf) {
                        return Ok(sender);
                    }
                }
                return Err(err);
            }
        };
        Ok(sender)
    }
}

/// Thread-local PRNG used to seed per-host round-robin counters on first
/// access so cold-start bursts spread across shards from request #1 rather
/// than all funneling onto shard 0. Uses xorshift64 for zero heap traffic
/// and nanosecond seed time. Shared with `grpc_proxy::GrpcConnectionPool`
/// so both H2 pools seed their counters from the same draw stream.
pub(crate) fn rr_seed() -> usize {
    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0) };
    }
    STATE.with(|cell| {
        let mut s = cell.get();
        if s == 0 {
            // Mix the thread id with the monotonic time so different
            // threads/workers start on different shards. Falling back to
            // `1` on the astronomically unlikely case where the product
            // is zero keeps the generator from getting stuck on 0.
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1);
            let tid = thread_id_mix();
            s = nanos ^ tid;
            if s == 0 {
                s = 1;
            }
        }
        // xorshift64 — one multiply-free round, good enough for a uniform
        // shard offset.
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        cell.set(s);
        s as usize
    })
}

/// Mix the current thread id into a `u64` using a stable per-call hash
/// of the `Debug` repr. `ThreadId::as_u64` is unstable; this avoids the
/// nightly-only API while still giving each worker a distinct seed.
fn thread_id_mix() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let id = std::thread::current().id();
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    // `ThreadId` implements Hash; feed it directly.
    std::hash::Hash::hash(&id, &mut h);
    h.finish()
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

    // 0. `BackendSelectedHttp1` is an intentional signal to the dispatcher
    //    — the backend negotiated h1.1 via ALPN and the caller should route
    //    via reqwest. Classify as ProtocolError so operators see this in
    //    logs as a policy/config mismatch rather than a transient fault.
    if matches!(err, Http2PoolError::BackendSelectedHttp1 { .. }) {
        return ErrorClass::ProtocolError;
    }

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
        Http2PoolError::BackendUnavailable { message, .. } => message.as_str(),
        Http2PoolError::BackendTimeout { message, .. } => message.as_str(),
        Http2PoolError::Internal { message, .. } => message.as_str(),
        // Already returned above — keep match exhaustive.
        Http2PoolError::BackendSelectedHttp1 { .. } => return ErrorClass::ProtocolError,
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
        Http2PoolError::BackendSelectedHttp1 { .. } => ErrorClass::ProtocolError,
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
    /// TLS ALPN negotiation picked `http/1.1` (or no protocol). The direct
    /// HTTP/2 pool cannot speak to this backend — the caller should fall
    /// back to the reqwest path, which handles both h1.1 and h2 via its
    /// own ALPN negotiation. `pool_key` is returned so the caller can log
    /// it and the pool can cache the negative result to short-circuit
    /// future attempts to the same backend.
    BackendSelectedHttp1 { pool_key: String },
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
    /// A string-only error from an upstream helper that doesn't expose a
    /// typed chain. Kept last-resort so we don't pretend we have more
    /// information than we actually do.
    Message(String),
}

impl std::error::Error for InternalSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Message(_) => None,
        }
    }
}

impl std::fmt::Display for InternalSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{}", e),
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
            Self::BackendSelectedHttp1 { pool_key } => write!(
                f,
                "backend negotiated http/1.1 via ALPN (pool key: {}); falling back to reqwest",
                pool_key
            ),
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
            Self::BackendSelectedHttp1 { .. } => None,
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
            // Short static string — this error is a signal, not a user-facing
            // message. The dispatching caller routes via reqwest on this
            // variant rather than surfacing the message to clients.
            Self::BackendSelectedHttp1 { .. } => "backend does not support http/2",
        }
    }
}

#[cfg(test)]
mod tests {
    //! Inline tests for private internals of the HTTP/2 connection pool.
    //!
    //! These test helpers that are `pub(crate)` at best — promoting them to
    //! `pub` solely for `tests/` access would expose them on the crate's
    //! external API, which we want to avoid.
    //!
    //! The functional behaviour of `get_sender` (burst concurrency against a
    //! live backend) is exercised in `tests/integration/http2_pool_tests.rs`;
    //! the tests below target the specific code-path changes in
    //! `perf/h2-pool-sender-ready-and-grpc-trailer-stall`.
    use super::*;
    use std::collections::HashSet;

    /// Fix 2: the thread-local PRNG that seeds per-host RR counters should
    /// produce non-zero draws. Seeding with `0` would make all cold bursts
    /// land on shard 0, which is the bug we are fixing.
    #[test]
    fn rr_seed_is_non_zero() {
        for _ in 0..64 {
            assert_ne!(rr_seed(), 0, "rr_seed() must never return 0");
        }
    }

    /// Fix 2: consecutive draws from the same thread should differ — the
    /// seed is persisted in a `Cell<u64>` and stepped once per call.
    /// `thread_local!` means the Cell persists across calls from the same
    /// thread; xorshift64 has period ~2^64 - 1 so a collision in a tiny
    /// sample is astronomically unlikely.
    #[test]
    fn rr_seed_draws_diverge_within_thread() {
        let mut seen = HashSet::new();
        for _ in 0..32 {
            seen.insert(rr_seed());
        }
        // 32 independent xorshift draws should all be distinct.
        assert_eq!(
            seen.len(),
            32,
            "expected 32 distinct RR seeds, got {}",
            seen.len()
        );
    }

    /// Fix 2: even when `shard_count` is small (e.g., 4), the seeded RR
    /// counter should cover all shards within a few draws — not get stuck
    /// on one position. This validates that the modulo distribution is
    /// not degenerate on common shard counts.
    #[test]
    fn rr_seed_spans_all_shards_for_small_shard_counts() {
        for &shard_count in &[2usize, 4, 8, 16] {
            let mut visited = vec![false; shard_count];
            // 64 draws is ~16x the shard count — coupon-collector
            // expectation says every shard is hit with overwhelming
            // probability. If the seed is deterministic and modular bias
            // is pathological we would miss a shard.
            let mut rr = AtomicUsize::new(rr_seed());
            for _ in 0..64 {
                let start = rr.fetch_add(1, Ordering::Relaxed) % shard_count;
                visited[start] = true;
                // Recreate the counter occasionally so we emulate the
                // cold-start seed path on many distinct hosts.
                if rand_lite().is_multiple_of(8) {
                    rr = AtomicUsize::new(rr_seed());
                }
            }
            assert!(
                visited.iter().all(|v| *v),
                "shard_count={} should have visited all shards, got {:?}",
                shard_count,
                visited
            );
        }
    }

    /// Bare-bones pseudo-random helper for the test above. Reads from the
    /// thread-local state directly by re-calling `rr_seed`.
    fn rand_lite() -> usize {
        rr_seed()
    }

    /// Fix 1: source-level assertion that the 5 ms timeout branch has
    /// been removed from `get_sender`. Protects against a future re-add
    /// of the `tokio::time::timeout(Duration::from_millis(5), ...)` pattern.
    ///
    /// We read our own source file at compile time (`include_str!`) and
    /// check that no line contains the regression pattern. This is a
    /// belt-and-braces guard — cheaper and more specific than a runtime
    /// benchmark, and catches the accidental revert immediately.
    #[test]
    fn no_five_millisecond_sender_ready_wait() {
        let src = include_str!("http2_pool.rs");
        let mut in_test_mod = false;
        for (i, line) in src.lines().enumerate() {
            // Skip the test module itself — the assertion string below
            // would otherwise match.
            if line.contains("#[cfg(test)]") {
                in_test_mod = true;
            }
            if in_test_mod {
                continue;
            }
            assert!(
                !line.contains("Duration::from_millis(5)"),
                "regression: found `Duration::from_millis(5)` at line {} — \
                 the 5 ms sender-ready wait was removed on purpose (see Fix 1 \
                 in perf/h2-pool-sender-ready-and-grpc-trailer-stall). \
                 Open a new connection via `create_or_get_existing_owned` \
                 instead of stalling on a busy shard's `ready()`.",
                i + 1
            );
        }
    }

    /// Fix 1: source-level assertion that `first_live` stash has been
    /// removed. The previous control flow cached the first non-ready
    /// sender into `first_live`, then timed out on it — deleting this
    /// path is the essence of Fix 1.
    #[test]
    fn no_first_live_stash_in_get_sender() {
        let src = include_str!("http2_pool.rs");
        let mut in_test_mod = false;
        for (i, line) in src.lines().enumerate() {
            if line.contains("#[cfg(test)]") {
                in_test_mod = true;
            }
            if in_test_mod {
                continue;
            }
            // Allow the pattern inside comments — we only care about the
            // binding itself.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            assert!(
                !line.contains("first_live"),
                "regression: `first_live` stash detected at line {}. \
                 Fix 1 removed this branch; restore fix before re-adding.",
                i + 1
            );
        }
    }
}
