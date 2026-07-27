//! HTTP/2 connection pool using hyper's HTTP/2 client directly.
//!
//! Provides proper HTTP/2 stream multiplexing over a single persistent TLS
//! connection, avoiding the connection-per-request churn that reqwest exhibits
//! under concurrent load. The shared `GenericPool` owns the DashMap, key reuse,
//! and cleanup sweep; this wrapper keeps the readiness and shard-selection logic.

use anyhow::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::cell::{Cell, RefCell};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tracing::{debug, warn};

use crate::config::PoolConfig;
use crate::config::types::Proxy;
use crate::dns::{DnsCache, DnsConfig};
use crate::pool::{GenericPool, PoolManager};
use crate::proxy::body::SizeLimitedIncoming;
use crate::tls::TlsPolicy;
use crate::tls::backend::{
    BackendSvidGeneration, BackendTlsConfigBuilder, BackendTlsConfigCache, SvidGenerationMatcher,
    append_backend_tls_pool_key_fields, append_optional_pool_key_component,
    append_pool_key_component, backend_svid_generation_for_client_cert,
};

thread_local! {
    /// Reused per-thread buffer for direct H2 pool-key construction on the
    /// request hot path. Mirrors the zero-allocation strategy used by
    /// `CAPABILITY_KEY_BUF` in `backend_capabilities.rs` and `KEY_BUF` in
    /// `pool/mod.rs` so `get_sender()` performs zero `String` allocations on
    /// repeat cache-hit calls from the same tokio worker thread.
    ///
    /// The buffer is reset before each lookup. Owned `String` keys are still
    /// produced via `.clone()` at the moment of insert (cache miss path,
    /// `rr_counters` cold-start, error-variant payloads), so the allocation
    /// moves off the cache-hit fast path entirely.
    ///
    /// Cannot be borrowed across `await`. `with_http2_pool_key` and the
    /// pre-/post-await scopes in `get_sender` keep every `borrow_mut()`
    /// inside a synchronous block.
    static HTTP2_POOL_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(128));
}

/// Multiplexed hyper H2 sender for the plain-HTTPS direct pool.
///
/// Body type is [`SizeLimitedIncoming`] so SNI-required (and any other)
/// direct-H2 dispatches can enforce `max_request_body_size_bytes` while
/// streaming the client upload — mirroring the mesh-mTLS / HBONE pools.
/// Callers wrap with `usize::MAX` when the operator limit is disabled (`0`).
pub type Http2Sender = http2::SendRequest<SizeLimitedIncoming>;

/// Terminal protocol outcome for one DNS candidate.
///
/// Negotiated HTTP/1.1 is a usable backend capability result, not a failed
/// address attempt: the dispatcher can route it through reqwest. Keeping it in
/// the successful candidate channel prevents a later transport or handshake
/// failure from overwriting the downgrade signal.
enum Http2CandidateOutcome {
    Established(Http2Sender),
    BackendSelectedHttp1 { pool_key: String },
}

/// Run `f` against a thread-local buffer pre-populated with the direct H2
/// pool key for `proxy` (no shard suffix). Callers can append `#<shard>`
/// via `write_http2_shard_key_inplace` using `buf.len()` as `base_len`.
///
/// The closure must be synchronous — the underlying `RefCell::borrow_mut`
/// cannot cross an `.await`. `now_or_never(...)` polling and DashMap
/// lookups are fine.
fn with_http2_pool_key<R>(
    proxy: &Proxy,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
    svid_generation: Option<u64>,
    f: impl FnOnce(&mut String) -> R,
) -> R {
    HTTP2_POOL_KEY_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        write_http2_pool_key(
            &mut buf,
            &proxy.backend_host,
            proxy.backend_port,
            proxy,
            client_cert_path,
            client_key_path,
            svid_generation,
        );
        f(&mut buf)
    })
}

fn write_http2_pool_key(
    buf: &mut String,
    host: &str,
    port: u16,
    proxy: &Proxy,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
    svid_generation: Option<u64>,
) {
    use std::fmt::Write;
    buf.clear();
    append_pool_key_component(buf, host);
    let _ = write!(buf, "|{port}|");
    append_optional_pool_key_component(buf, proxy.dns_override.as_deref());
    buf.push('|');
    // Subset name partitions H2 pools so two proxies that share
    // `(host, port, dns_override)` but select different DestinationRule
    // subsets cannot share an H2 sender even when their TLS material is
    // byte-identical. Empty when the proxy has no `upstream_subset`.
    append_optional_pool_key_component(buf, proxy.upstream_subset.as_deref());
    buf.push('|');
    append_backend_tls_pool_key_fields(
        buf,
        &proxy.resolved_tls,
        client_cert_path,
        client_key_path,
        proxy.resolved_tls.verify_server_cert,
        svid_generation,
    );
}

fn pool_key_owned(proxy: &Proxy, svid_generation: Option<u64>) -> String {
    let mut buf = String::with_capacity(128);
    write_http2_pool_key(
        &mut buf,
        &proxy.backend_host,
        proxy.backend_port,
        proxy,
        proxy.resolved_tls.client_cert_path.as_deref(),
        proxy.resolved_tls.client_key_path.as_deref(),
        svid_generation,
    );
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
    crls: crate::tls::SharedCrlList,
    tls_configs: BackendTlsConfigCache,
    backend_svid_generation: BackendSvidGeneration,
    workload_svid_cert_path: Option<String>,
}

impl Http2PoolManager {
    async fn create_connection(
        &self,
        proxy: &Proxy,
        svid_generation: Option<u64>,
    ) -> Result<Http2Sender, Http2PoolError> {
        let host = &proxy.backend_host;
        let port = proxy.backend_port;

        let candidates = self
            .dns_cache
            .resolve_candidates(
                host,
                proxy.dns_override.as_deref(),
                proxy.dns_cache_ttl_seconds,
            )
            .await
            .map_err(|e| Http2PoolError::BackendUnavailable {
                message: format!("DNS resolution failed for {}: {}", host, e),
                source: Some(BackendUnavailableSource::Dns),
            })?;

        let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);
        let pool_config = self.global_pool_config.for_proxy(proxy);
        let tls_config = self.get_tls_config(proxy, svid_generation)?;
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let server_name =
            crate::tls::backend::backend_tls_server_name_owned(&proxy.resolved_tls, host).map_err(
                |e| Http2PoolError::BackendUnavailable {
                    message: format!("Invalid server name: {}", e),
                    source: Some(BackendUnavailableSource::InvalidDnsName),
                },
            )?;
        let keepalive_override = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&port))
            .and_then(|o| o.tcp_keepalive.as_ref());

        crate::dns::connect_candidates(&candidates, port, connect_timeout, |sock_addr| {
            let connector = connector.clone();
            let server_name = server_name.clone();
            let pool_config = &pool_config;
            async move {
                let tcp = crate::socket_opts::connect_with_socket_opts(sock_addr)
                    .await
                    .map_err(|e| Http2PoolError::BackendUnavailable {
                        message: format!("Connection refused: {}", e),
                        source: Some(BackendUnavailableSource::Io(e)),
                    })?;

                let _ = tcp.set_nodelay(true);
                // Honor the DestinationRule `connectionPool.tcp.tcpKeepalive`
                // per-port override on every candidate attempt, falling back
                // to the global pool keepalive. Keepalive is intentionally not
                // in the pool key, so the first materializer still wins.
                crate::socket_opts::apply_pooled_tcp_keepalive(
                    "http2_pool",
                    &tcp,
                    keepalive_override,
                    pool_config.enable_http_keep_alive,
                    pool_config.tcp_keepalive_seconds,
                );

                let tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
                    Http2PoolError::BackendUnavailable {
                        message: format!("TLS handshake failed: {}", e),
                        source: Some(BackendUnavailableSource::Tls(e)),
                    }
                })?;

                // A TCP-successful candidate is not usable by this pool until
                // it negotiates ALPN h2 and completes the HTTP/2 handshake.
                // Keep both phases inside the candidate attempt so a bad first
                // address cannot suppress a healthy later DNS answer.
                if !matches!(tls_stream.get_ref().1.alpn_protocol(), Some(b"h2")) {
                    return Ok(Http2CandidateOutcome::BackendSelectedHttp1 {
                        pool_key: self.pool_key_owned(proxy, svid_generation),
                    });
                }

                let io = TokioIo::new(tls_stream);
                let builder = Self::build_h2_builder(pool_config);
                let (sender, conn) = builder.handshake(io).await.map_err(|e| {
                    Http2PoolError::BackendUnavailable {
                        message: format!("h2 handshake failed: {}", e),
                        source: Some(BackendUnavailableSource::Hyper(e)),
                    }
                })?;

                // ALPN has already proved H2 for this TLS candidate.
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        debug!("http2_pool: TLS connection closed: {}", e);
                    }
                });
                Ok(Http2CandidateOutcome::Established(sender))
            }
        })
        .await
        .map(|(outcome, _)| match outcome {
            Http2CandidateOutcome::Established(sender) => Ok(sender),
            Http2CandidateOutcome::BackendSelectedHttp1 { pool_key } => {
                Err(Http2PoolError::BackendSelectedHttp1 { pool_key })
            }
        })
        .map_err(|error| match error {
            crate::dns::CandidateConnectError::TimedOut { last_addr } => {
                Http2PoolError::BackendTimeout {
                    message: format!(
                        "Connect timeout after {}ms establishing HTTP/2 to {}",
                        proxy.backend_connect_timeout_ms, last_addr
                    ),
                    source: Some(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "backend HTTP/2 establishment timed out",
                    )),
                }
            }
            crate::dns::CandidateConnectError::Failed { last_addr, source } => {
                if crate::retry::is_port_exhaustion(&source) {
                    tracing::error!(
                        "http2_pool: PORT EXHAUSTION connecting to backend {}: {} — \
                         reduce outbound connection rate or increase net.ipv4.ip_local_port_range",
                        last_addr,
                        source
                    );
                } else {
                    warn!(
                        "http2_pool: all DNS candidates failed HTTP/2 establishment for backend {} \
                         (last={}): {}",
                        host, last_addr, source
                    );
                }
                source
            }
        })?
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
            // Cap server-initiated streams (push) and preserve the operator's
            // initial outbound concurrency bound until peer SETTINGS arrive.
            builder.max_concurrent_streams(max_streams);
            builder.initial_max_send_streams(max_streams as usize);
        }

        builder
    }

    fn get_tls_config(
        &self,
        proxy: &Proxy,
        svid_generation: Option<u64>,
    ) -> Result<Arc<rustls::ClientConfig>, Http2PoolError> {
        let cache_key = self.pool_key_owned(proxy, svid_generation);
        self.tls_configs.get_or_try_build(cache_key, || {
            let crls = self.crls.load_full();
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
                crls: crls.as_ref().as_slice(),
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
}

#[async_trait]
impl PoolManager for Http2PoolManager {
    type Connection = Http2Sender;

    fn build_key(&self, proxy: &Proxy, host: &str, port: u16, shard: usize, buf: &mut String) {
        self.write_pool_key(
            buf,
            host,
            port,
            proxy,
            self.svid_generation_for_proxy(proxy),
        );
        let base_len = buf.len();
        write_http2_shard_key_inplace(buf, base_len, shard);
    }

    async fn create(&self, _key: &str, proxy: &Proxy) -> Result<Http2Sender> {
        self.create_connection(proxy, self.svid_generation_for_proxy(proxy))
            .await
            .map_err(anyhow::Error::from)
    }

    fn is_healthy(&self, conn: &Self::Connection) -> bool {
        !conn.is_closed()
    }

    fn destroy(&self, conn: Self::Connection) {
        drop(conn);
    }

    fn runtime_metrics_kind(&self) -> Option<crate::runtime_metrics::PoolKind> {
        Some(crate::runtime_metrics::PoolKind::Http2Direct)
    }
}

impl Http2PoolManager {
    fn current_svid_generation(&self) -> u64 {
        self.backend_svid_generation.load(Ordering::Acquire)
    }

    fn effective_client_cert_path<'a>(&'a self, proxy: &'a Proxy) -> Option<&'a str> {
        proxy.resolved_tls.client_cert_path.as_deref().or(self
            .global_env_config
            .backend_tls_client_cert_path
            .as_deref())
    }

    fn effective_client_key_path<'a>(&'a self, proxy: &'a Proxy) -> Option<&'a str> {
        proxy.resolved_tls.client_key_path.as_deref().or(self
            .global_env_config
            .backend_tls_client_key_path
            .as_deref())
    }

    fn write_pool_key(
        &self,
        buf: &mut String,
        host: &str,
        port: u16,
        proxy: &Proxy,
        svid_generation: Option<u64>,
    ) {
        write_http2_pool_key(
            buf,
            host,
            port,
            proxy,
            self.effective_client_cert_path(proxy),
            self.effective_client_key_path(proxy),
            svid_generation,
        );
    }

    fn pool_key_owned(&self, proxy: &Proxy, svid_generation: Option<u64>) -> String {
        let mut buf = String::with_capacity(128);
        self.write_pool_key(
            &mut buf,
            &proxy.backend_host,
            proxy.backend_port,
            proxy,
            svid_generation,
        );
        buf
    }

    fn svid_generation_for_proxy(&self, proxy: &Proxy) -> Option<u64> {
        backend_svid_generation_for_client_cert(
            self.effective_client_cert_path(proxy),
            self.workload_svid_cert_path.as_deref(),
            self.current_svid_generation(),
        )
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
        Self::new_with_svid_generation(
            global_pool_config,
            global_env_config,
            dns_cache,
            tls_policy,
            crls,
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        )
    }

    pub fn new_with_svid_generation(
        global_pool_config: PoolConfig,
        global_env_config: crate::config::EnvConfig,
        dns_cache: DnsCache,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
        backend_svid_generation: BackendSvidGeneration,
    ) -> Self {
        Self::new_with_svid_generation_and_shared_crls(
            global_pool_config,
            global_env_config,
            dns_cache,
            tls_policy,
            crate::tls::shared_crl_list(crls),
            backend_svid_generation,
        )
    }

    pub fn new_with_svid_generation_and_shared_crls(
        global_pool_config: PoolConfig,
        global_env_config: crate::config::EnvConfig,
        dns_cache: DnsCache,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::SharedCrlList,
        backend_svid_generation: BackendSvidGeneration,
    ) -> Self {
        let cleanup_interval =
            Duration::from_secs(global_env_config.pool_cleanup_interval_seconds.max(1));
        let shards = crate::util::sharding::pool_shard_amount(global_env_config.pool_shard_amount);
        let workload_svid_cert_path = global_env_config.gateway_svid_cert_path.clone();
        let manager = Arc::new(Http2PoolManager {
            global_pool_config: global_pool_config.clone(),
            global_env_config,
            dns_cache,
            tls_policy,
            crls,
            tls_configs: BackendTlsConfigCache::with_shards(shards),
            backend_svid_generation,
            workload_svid_cert_path,
        });

        Self {
            pool: GenericPool::new(manager, global_pool_config, cleanup_interval, shards),
            rr_counters: Arc::new(DashMap::with_shard_amount(shards)),
        }
    }

    pub fn pool_size(&self) -> usize {
        self.pool.pool_size()
    }

    pub fn drain_backend_tls_config_cache_svid_generation(&self, generation: u64) {
        self.pool
            .manager()
            .tls_configs
            .drain_svid_generation(generation);
    }

    pub fn clear_backend_tls_config_cache(&self) {
        self.pool.manager().tls_configs.clear();
    }

    pub fn force_drain_svid_generation(&self, generation: u64) {
        let matcher = SvidGenerationMatcher::new(generation);
        self.pool.invalidate_matching(|key| matcher.matches(key));
        self.rr_counters.retain(|key, _| !matcher.matches(key));
    }

    pub fn force_drain_all(&self) {
        self.pool.clear();
        self.rr_counters.clear();
    }

    #[allow(dead_code)] // exercised from integration/unit tests
    pub fn pool_key_for_warmup(proxy: &Proxy) -> String {
        pool_key_owned(proxy, None)
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

    fn with_pool_key<R>(
        &self,
        proxy: &Proxy,
        svid_generation: Option<u64>,
        f: impl FnOnce(&mut String) -> R,
    ) -> R {
        let manager = self.pool.manager();
        with_http2_pool_key(
            proxy,
            manager.effective_client_cert_path(proxy),
            manager.effective_client_key_path(proxy),
            svid_generation,
            f,
        )
    }

    pub async fn get_sender(&self, proxy: &Proxy) -> Result<Http2Sender, Http2PoolError> {
        let pool_config = self.pool.manager().global_pool_config.for_proxy(proxy);
        let shard_count = pool_config.http2_connections_per_host.max(1);

        // Phase 1 (synchronous): build the pool key in the thread-local
        // buffer, pick a starting shard via the per-host RR counter, and
        // probe every shard for an immediately-ready sender. On a cache hit
        // we return early without ever cloning the key. On a miss we clone
        // the buffer once into `selected_key` so the await below has an
        // owned String to hand to `create_or_get_existing_owned`.
        //
        // The closure body is synchronous — `now_or_never(sender.ready())`
        // polls once without yielding, and DashMap lookups never await — so
        // the `RefCell::borrow_mut()` lifetime stays inside this block.
        let svid_generation = self.pool.manager().svid_generation_for_proxy(proxy);
        let phase1 = self.with_pool_key(proxy, svid_generation, |key_buf| -> Phase1 {
            let base_len = key_buf.len();

            // Round-robin counter is per-host, but on FIRST access we seed it
            // with a thread-local PRNG offset so a burst of concurrent
            // requests on a cold pool does not land all on shard 0 before
            // the atomic counter wraps around. `AtomicUsize::fetch_add(1,
            // Relaxed)` is wait-free after the seed — the seed only matters
            // for the first `shard_count` picks per host on this gateway.
            let rr = match self.rr_counters.get(key_buf.as_str()) {
                Some(existing) => existing.value().clone(),
                // Cold-path allocation: `to_owned()` runs only on the first
                // request to a given backend host — subsequent requests find
                // the existing entry via the `get()` above.
                None => self
                    .rr_counters
                    .entry(key_buf[..base_len].to_owned())
                    .or_insert_with(|| Arc::new(AtomicUsize::new(rr_seed())))
                    .clone(),
            };
            let start = rr.fetch_add(1, Ordering::Relaxed) % shard_count;

            // Cheap probe pass — any shard whose cached sender is
            // immediately ready wins. `now_or_never` never awaits, so this
            // is a quick sweep of the shard ring with no per-shard stall.
            for offset in 0..shard_count {
                let shard = (start + offset) % shard_count;
                Self::write_shard_key_inplace(key_buf, base_len, shard);

                if let Some(mut sender) = self.pool.cached(key_buf) {
                    match futures_util::FutureExt::now_or_never(sender.ready()) {
                        Some(Ok(())) => return Phase1::Hit(sender),
                        Some(Err(_)) => {
                            self.pool.invalidate(key_buf);
                        }
                        // Shard exists but is mid-send. Previously we
                        // stashed the first such sender and `timeout(5ms,
                        // ready())`ed on it, which serialized ~100-
                        // concurrent bursts onto the already-busy shard and
                        // net-pessimized throughput (5 MB/100-conc HTTP/2
                        // stuck at 81 RPS vs direct 232). Skip — phase 2's
                        // `create_or_get_existing_owned` checks `cached()`
                        // first; the existing sender is still healthy
                        // (`!is_closed()`), so the create closure never runs
                        // and the pool does NOT grow beyond the shard ring.
                        // Callers queue on the start shard's existing sender
                        // via H2 readiness / stream-cap backpressure.
                        None => {}
                    }
                }
            }

            Self::write_shard_key_inplace(key_buf, base_len, start);
            // Single allocation: clone the thread-local buffer into the
            // owned key that `create_or_get_existing_owned` consumes. This
            // is the only `String` allocation on the cache-miss path now —
            // cache hits take the early return above without allocating.
            Phase1::Miss {
                selected_key: key_buf.clone(),
                base_len,
                start,
            }
        });

        let (selected_key, base_len, start) = match phase1 {
            Phase1::Hit(sender) => return Ok(sender),
            Phase1::Miss {
                selected_key,
                base_len,
                start,
            } => (selected_key, base_len, start),
        };

        let manager = Arc::clone(self.pool.manager());
        match self
            .pool
            .create_or_get_existing_owned(selected_key, |key| async move {
                let _ = key;
                manager.create_connection(proxy, svid_generation).await
            })
            .await
        {
            Ok(sender) => Ok(sender),
            Err(err) => {
                // Phase 2 (synchronous re-borrow): rebuild the pool key in
                // the same thread-local buffer and probe alternative shards.
                // The proxy outlives this future and is read-only, so the
                // build is identical to phase 1's prelude.
                let recovered = self.with_pool_key(proxy, svid_generation, |key_buf| {
                    debug_assert_eq!(key_buf.len(), base_len);
                    for offset in 1..shard_count {
                        let shard = (start + offset) % shard_count;
                        Self::write_shard_key_inplace(key_buf, base_len, shard);
                        if let Some(sender) = self.pool.cached(key_buf) {
                            return Some(sender);
                        }
                    }
                    None
                });
                match recovered {
                    Some(sender) => Ok(sender),
                    None => Err(err),
                }
            }
        }
    }
}

/// Outcome of the synchronous phase-1 sweep in `get_sender`.
enum Phase1 {
    /// A cached sender was immediately ready — short-circuit to the caller
    /// without cloning the pool key or hitting `create_or_get_existing_owned`.
    Hit(Http2Sender),
    /// No shard was immediately ready. Carry the cloned shard key (with
    /// `#<start_shard>` appended) plus the unsharded `base_len` and
    /// `start` so the post-await error fallback can reconstruct shard
    /// keys without recomputing them.
    Miss {
        selected_key: String,
        base_len: usize,
        start: usize,
    },
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

    // Coalesced-create waiter reconstruction attaches the broadcast payload as
    // `BackendUnavailableSource::Shared`. Prefer its captured ErrorClass so
    // DNS/TLS/timeout/egress/port-exhaustion stay aligned with the creator.
    if let Http2PoolError::BackendUnavailable {
        source: Some(BackendUnavailableSource::Shared(shared)),
        ..
    } = err
    {
        return shared.error_class();
    }

    // A DnsCacheResolver egress-policy denial (a hostname that resolves — or
    // rebinds — to a blocked IP) surfaces here inside a `BackendUnavailable`
    // whose message carries "...denied by backend egress policy...". Classify it
    // as the non-retryable, backend-health-neutral DispatchPolicyRejected BEFORE
    // the `Dns` marker below maps it to DnsLookupError (retryable,
    // connection_error=true), which would retry it and charge passive health /
    // adaptive concurrency even though no backend was dialed.
    if format!("{err:?}").contains("egress policy") {
        return ErrorClass::DispatchPolicyRejected;
    }

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

    // The HTTP/2 pool is a pure connection-establishment layer — it
    // returns a sender that the caller uses for the actual request.
    // Every error it surfaces happens during DNS / TCP connect / TLS
    // handshake / h2 handshake, all of which are pre-wire. Pass
    // `phase_is_connect=true` so io::ErrorKind::TimedOut maps to
    // `ConnectionTimeout` and io::ErrorKind::ConnectionReset maps to
    // `ConnectionRefused` (a SYN-RST is functionally equivalent to
    // ECONNREFUSED — request never reached the wire). Both classes
    // satisfy `request_reached_wire(class) == false`, so the gateway's
    // `retry_on_connect_failure` fires correctly.
    let phase_is_connect = true;

    // First hop: inspect the immediate `BackendUnavailableSource` so we can
    // map the `Tls` marker to `TlsError` directly. After that we walk the
    // generic source chain looking for io/hyper/rustls variants.
    match err {
        Http2PoolError::BackendUnavailable {
            source: Some(BackendUnavailableSource::Tls(io_err)),
            ..
        } => {
            // Let typed ErrorKind win if set, otherwise fall back to TlsError.
            if let Some(cls) = classify_io_error(io_err, phase_is_connect) {
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
                    && let Some(cls) = classify_io_error(io_err, phase_is_connect)
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
        phase_is_connect,
    )
}

/// Walk an `std::error::Error` chain starting at `start`, returning the first
/// classification we can pin down from a typed node.
fn classify_chain_from(
    start: Option<&(dyn std::error::Error + 'static)>,
    phase_is_connect: bool,
) -> Option<crate::retry::ErrorClass> {
    use crate::retry::ErrorClass;
    let mut current = start;
    while let Some(node) = current {
        if let Some(io_err) = node.downcast_ref::<std::io::Error>()
            && let Some(cls) = classify_io_error(io_err, phase_is_connect)
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
    phase_is_connect: bool,
) -> Option<crate::retry::ErrorClass> {
    use crate::retry::ErrorClass;
    if matches!(io_err.raw_os_error(), Some(99) | Some(49) | Some(10049)) {
        return Some(ErrorClass::PortExhaustion);
    }
    match io_err.kind() {
        std::io::ErrorKind::TimedOut => Some(if phase_is_connect {
            ErrorClass::ConnectionTimeout
        } else {
            ErrorClass::ReadWriteTimeout
        }),
        std::io::ErrorKind::ConnectionRefused => Some(ErrorClass::ConnectionRefused),
        // Connect-phase RSTs (SYN answered with RST, TLS reset before
        // handshake completes) must NOT classify as `ConnectionReset`
        // because the unified `request_reached_wire` boundary treats
        // that variant as post-wire (mid-stream reset). The H2 pool is
        // a pure connection-establishment layer, so every io error here
        // is pre-wire — collapse RSTs into `ConnectionRefused`.
        std::io::ErrorKind::ConnectionReset => Some(if phase_is_connect {
            ErrorClass::ConnectionRefused
        } else {
            ErrorClass::ConnectionReset
        }),
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
    if hyper_err.is_canceled() {
        // hyper contract: the request was never dispatched onto the wire.
        // Treat as a stale pooled-sender / pool failure (pre-wire).
        return Some(ErrorClass::ConnectionPoolError);
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

/// Classify a hyper error from `SendRequest::send_request` on an already-pooled
/// HTTP/2 sender (direct-H2 dispatch).
///
/// `is_canceled` means the request was never dispatched (stale idle /
/// GOAWAY race) and maps pre-wire. Other failures walk the hyper/io chain
/// with `phase_is_connect = false` so mid-stream resets stay post-wire.
/// Unknown errors default to [`ErrorClass::ProtocolError`] (post-wire
/// conservative) rather than inventing a connect-class label.
pub fn classify_pooled_h2_send_request_error(e: &hyper::Error) -> crate::retry::ErrorClass {
    use crate::retry::ErrorClass;
    if let Some(cls) = classify_hyper_error(e) {
        return cls;
    }
    let mut current: Option<&(dyn std::error::Error + 'static)> =
        std::error::Error::source(e as &dyn std::error::Error);
    while let Some(node) = current {
        if let Some(io_err) = node.downcast_ref::<std::io::Error>()
            && let Some(cls) = classify_io_error(io_err, /* phase_is_connect */ false)
        {
            return normalize_pooled_h2_send_post_wire_class(cls);
        }
        current = node.source();
    }
    ErrorClass::ProtocolError
}

/// Keep source-chain classifications from turning an already-pooled H2 send
/// into a connect failure.
///
/// `hyper::Error::is_canceled()` is handled before the source-chain walk and is
/// the only proof that this dispatch never reached the wire. An inner
/// `io::ErrorKind::ConnectionRefused` (or a platform port-exhaustion errno)
/// cannot establish that boundary for an already-connected sender, so any
/// connect-only class discovered below the hyper error must fail closed as a
/// post-wire protocol error.
pub(crate) fn normalize_pooled_h2_send_post_wire_class(
    class: crate::retry::ErrorClass,
) -> crate::retry::ErrorClass {
    if crate::retry::request_reached_wire(class) {
        class
    } else {
        crate::retry::ErrorClass::ProtocolError
    }
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
    /// Classification captured when broadcasting a coalesced create failure.
    /// Carries no live IO handle; classifiers read [`SharedPoolCreateError::error_class`].
    Shared(crate::pool::SharedPoolCreateError),
}

impl std::error::Error for BackendUnavailableSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) | Self::Tls(e) => Some(e),
            Self::Hyper(e) => Some(e),
            Self::Shared(e) => Some(e),
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
            Self::Shared(e) => write!(f, "{}", e),
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

/// Zero-based field offsets of the backend mTLS client cert and key components
/// inside a direct-H2 pool key. The key is built as
/// `host|port|dns_override|subset|ca|cert|key|sni|san_digest|verify+svid` by
/// `write_http2_pool_key` -> `append_backend_tls_pool_key_fields`; the cert and
/// key fields are credential paths (or inline-PEM digests). Pool-key components
/// escape literal `|` as `%7C` (see `append_pool_key_component`), so splitting on
/// `|` recovers exactly these fields without a separator ever bleeding across a
/// boundary.
const POOL_KEY_CLIENT_CERT_FIELD: usize = 5;
const POOL_KEY_CLIENT_KEY_FIELD: usize = 6;

/// Render a direct-H2 pool key with its backend mTLS client cert/key components
/// scrubbed for safe inclusion in logs and error displays.
///
/// The pool key itself must retain the real cert/key components so pools stay
/// partitioned by client identity (see `append_backend_tls_pool_key_fields`); we
/// redact only at the log/Display boundary because the repo rule forbids logging
/// unredacted credential metadata — and a configured cert/key path counts. This
/// runs off the request hot path: it is only reached when a `BackendSelectedHttp1`
/// error is formatted on the H2->reqwest fallback, never during pool-key build.
fn redact_pool_key_tls_material(pool_key: &str) -> String {
    let mut out = String::with_capacity(pool_key.len());
    for (idx, field) in pool_key.split('|').enumerate() {
        if idx != 0 {
            out.push('|');
        }
        if (idx == POOL_KEY_CLIENT_CERT_FIELD || idx == POOL_KEY_CLIENT_KEY_FIELD)
            && !field.is_empty()
        {
            out.push_str("<redacted>");
        } else {
            out.push_str(field);
        }
    }
    out
}

impl std::fmt::Display for Http2PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendUnavailable { message, .. } => write!(f, "{}", message),
            Self::BackendTimeout { message, .. } => write!(f, "{}", message),
            Self::Internal { message, .. } => write!(f, "{}", message),
            // The pool key embeds backend mTLS client cert/key components, so
            // redact them before they can reach a log line via this Display.
            Self::BackendSelectedHttp1 { pool_key } => write!(
                f,
                "backend negotiated http/1.1 via ALPN (pool key: {}); falling back to reqwest",
                redact_pool_key_tls_material(pool_key)
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

impl From<crate::pool::SharedPoolCreateError> for Http2PoolError {
    fn from(err: crate::pool::SharedPoolCreateError) -> Self {
        use crate::pool::SharedPoolCreateKind;

        let message = err.message().to_string();
        match err.kind() {
            SharedPoolCreateKind::TimedOut => Self::BackendTimeout {
                message: message.clone(),
                source: Some(std::io::Error::new(std::io::ErrorKind::TimedOut, message)),
            },
            SharedPoolCreateKind::Internal => Self::Internal {
                message: message.clone(),
                source: Some(InternalSource::Message(message)),
            },
            SharedPoolCreateKind::NegotiatedHttp1 => Self::BackendSelectedHttp1 {
                pool_key: err.detail().unwrap_or(err.message()).to_string(),
            },
            SharedPoolCreateKind::Dns
            | SharedPoolCreateKind::Tls
            | SharedPoolCreateKind::ConnectionRefused
            | SharedPoolCreateKind::ConnectionClosed
            | SharedPoolCreateKind::Protocol
            | SharedPoolCreateKind::PortExhaustion
            | SharedPoolCreateKind::DispatchPolicyRejected
            | SharedPoolCreateKind::Unavailable
            | SharedPoolCreateKind::Other => {
                // Always attach the broadcast payload. Reconstructed io/DNS/TLS
                // markers can drift from the creator's captured ErrorClass
                // (egress denial, port exhaustion, ConnectionClosed wire
                // boundary). `classify_http2_pool_error` prefers Shared so
                // waiters keep creator ErrorClass / connection_error / retry
                // semantics without cloning non-Clone sources.
                Self::BackendUnavailable {
                    message,
                    source: Some(BackendUnavailableSource::Shared(err)),
                }
            }
        }
    }
}

impl crate::pool::ShareablePoolCreateError for Http2PoolError {
    fn to_shared(&self) -> crate::pool::SharedPoolCreateError {
        use crate::pool::{SharedPoolCreateError, SharedPoolCreateKind};
        use crate::retry::ErrorClass;

        let error_class = classify_http2_pool_error(self);
        match self {
            Self::BackendSelectedHttp1 { pool_key } => SharedPoolCreateError::new(
                self.message().to_string(),
                SharedPoolCreateKind::NegotiatedHttp1,
                ErrorClass::ProtocolError,
                Some(pool_key.clone()),
            ),
            Self::BackendTimeout { message, .. } => SharedPoolCreateError::new(
                message.clone(),
                SharedPoolCreateKind::TimedOut,
                error_class,
                None,
            ),
            Self::Internal { message, .. } => SharedPoolCreateError::new(
                message.clone(),
                SharedPoolCreateKind::Internal,
                error_class,
                None,
            ),
            Self::BackendUnavailable { message, .. } => {
                let kind = match error_class {
                    ErrorClass::DnsLookupError => SharedPoolCreateKind::Dns,
                    ErrorClass::TlsError => SharedPoolCreateKind::Tls,
                    ErrorClass::ConnectionRefused => SharedPoolCreateKind::ConnectionRefused,
                    ErrorClass::ConnectionClosed => SharedPoolCreateKind::ConnectionClosed,
                    ErrorClass::ProtocolError => SharedPoolCreateKind::Protocol,
                    ErrorClass::PortExhaustion => SharedPoolCreateKind::PortExhaustion,
                    ErrorClass::DispatchPolicyRejected => {
                        SharedPoolCreateKind::DispatchPolicyRejected
                    }
                    ErrorClass::ConnectionTimeout | ErrorClass::ReadWriteTimeout => {
                        SharedPoolCreateKind::TimedOut
                    }
                    ErrorClass::ConnectionPoolError => SharedPoolCreateKind::Unavailable,
                    _ => SharedPoolCreateKind::from_error_class(error_class),
                };
                SharedPoolCreateError::new(message.clone(), kind, error_class, None)
            }
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
    /// on one position. Once a host's RR counter is initialized from any
    /// seed, `fetch_add(1) % shard_count` must visit every shard in exactly
    /// `shard_count` picks.
    #[test]
    fn rr_seed_spans_all_shards_for_small_shard_counts() {
        for &shard_count in &[2usize, 4, 8, 16] {
            for _ in 0..32 {
                let rr = AtomicUsize::new(rr_seed());
                let mut visited = vec![false; shard_count];
                for _ in 0..shard_count {
                    let start = rr.fetch_add(1, Ordering::Relaxed) % shard_count;
                    visited[start] = true;
                }
                assert!(
                    visited.iter().all(|v| *v),
                    "shard_count={} should have visited all shards, got {:?}",
                    shard_count,
                    visited
                );
            }
        }
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

    /// Codex P1 follow-up: connect-phase resets must classify as
    /// `ConnectionRefused`, not `ConnectionReset`. The H2 pool is a pure
    /// connection-establishment layer — every io error it surfaces is
    /// pre-wire — so a SYN-RST'd connect attempt and a closed-port
    /// ECONNREFUSED'd connect attempt collapse to the same class. Without
    /// this, the unified `request_reached_wire(ConnectionReset) == true`
    /// boundary would treat the failure as post-wire and skip
    /// `retry_on_connect_failure`.
    #[test]
    fn h2_pool_connect_phase_reset_classifies_as_connection_refused() {
        let err = Http2PoolError::BackendUnavailable {
            message: "Connection refused: ECONNRESET during connect".to_string(),
            source: Some(BackendUnavailableSource::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "synthetic connect-phase RST",
            ))),
        };
        assert_eq!(
            classify_http2_pool_error(&err),
            crate::retry::ErrorClass::ConnectionRefused,
            "H2 pool's io::Error(ConnectionReset) is connect-phase only — \
             must NOT classify as ConnectionReset (which is post-wire). \
             If this fails, the gateway will skip retry_on_connect_failure \
             for SYN-RST'd backends."
        );
        assert!(
            !crate::retry::request_reached_wire(classify_http2_pool_error(&err)),
            "connect-phase RST must be pre-wire so retry_on_connect_failure fires"
        );
    }

    #[test]
    fn h2_pool_connect_phase_timeout_classifies_as_connection_timeout() {
        let err = Http2PoolError::BackendUnavailable {
            message: "TLS handshake timed out".to_string(),
            source: Some(BackendUnavailableSource::Tls(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "synthetic TLS-handshake timeout",
            ))),
        };
        assert_eq!(
            classify_http2_pool_error(&err),
            crate::retry::ErrorClass::ConnectionTimeout,
            "H2 pool TLS-handshake timeout is connect-phase — must NOT \
             classify as ReadWriteTimeout (which is post-wire)"
        );
    }

    #[test]
    fn h2_pool_typed_connection_refused_still_classifies_correctly() {
        // Sanity: ConnectionRefused stays ConnectionRefused.
        let err = Http2PoolError::BackendUnavailable {
            message: "Connection refused".to_string(),
            source: Some(BackendUnavailableSource::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "ECONNREFUSED",
            ))),
        };
        assert_eq!(
            classify_http2_pool_error(&err),
            crate::retry::ErrorClass::ConnectionRefused
        );
    }

    // -----------------------------------------------------------------------
    // HTTP2_POOL_KEY_BUF thread-local helper tests
    //
    // CLAUDE.md mandates that pool keys on the hot path use thread-local
    // `String` buffers via `write!()` for zero-allocation cache hits. Mirrors
    // the pattern in `proxy/backend_capabilities.rs` (`CAPABILITY_KEY_BUF`)
    // and `pool/mod.rs` (`KEY_BUF`). The previous `String::with_capacity(128)`
    // allocation in `get_sender()` ran on every direct-H2 dispatch.
    // -----------------------------------------------------------------------

    use crate::config::types::{
        AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, ResponseBodyMode,
    };
    use chrono::Utc;

    /// Build a minimal `Proxy` for thread-local key tests. Uses HTTPS so the
    /// direct H2 pool path is the realistic codepath.
    fn http2_pool_test_proxy() -> Proxy {
        let now = Utc::now();
        Proxy {
            id: "p-h2".to_string(),
            namespace: crate::config::types::default_namespace(),
            name: None,
            hosts: vec![],
            listen_path: Some("/".to_string()),
            backend_scheme: Some(BackendScheme::Https),
            dispatch_kind: DispatchKind::from(BackendScheme::Https),
            backend_host: "backend.test".to_string(),
            backend_port: 443,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: 5_000,
            backend_read_timeout_ms: 30_000,
            backend_write_timeout_ms: 30_000,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            resolved_tls: BackendTlsConfig::default_verify(),
            dispatch_port_overrides: None,
            dispatch_port_override_fallback: None,
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: AuthMode::Single,
            plugins: vec![],
            pool_idle_timeout_seconds: None,
            pool_enable_http_keep_alive: None,
            pool_enable_http2: None,
            pool_tcp_keepalive_seconds: None,
            pool_http2_keep_alive_interval_seconds: None,
            pool_http2_keep_alive_timeout_seconds: None,
            pool_http2_initial_stream_window_size: None,
            pool_http2_initial_connection_window_size: None,
            pool_http2_adaptive_window: None,
            pool_http2_max_frame_size: None,
            pool_http2_max_concurrent_streams: None,
            pool_http3_connections_per_backend: None,
            h2_upgrade_policy: None,
            pool_max_requests_per_connection: None,
            pool_http1_max_pending_requests: None,
            upstream_id: None,
            upstream_subset: None,
            api_spec_id: None,
            circuit_breaker: None,
            retry: None,
            response_body_mode: ResponseBodyMode::default(),
            listen_port: None,
            frontend_tls: false,
            passthrough: false,
            udp_idle_timeout_seconds: 60,
            tcp_idle_timeout_seconds: Some(300),
            websocket_idle_timeout_seconds: None,
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            stream_proxy_protocol: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn http2_pool_key_can_partition_on_svid_generation() {
        let proxy = http2_pool_test_proxy();
        let key = pool_key_owned(&proxy, Some(17));

        assert!(
            key.ends_with("|svidg=17"),
            "workload SVID generation must be represented in the HTTP/2 pool key: {key}"
        );
    }

    #[tokio::test]
    async fn http2_manager_pool_key_uses_global_mtls_fallback() {
        let proxy = http2_pool_test_proxy();
        let env_config = crate::config::EnvConfig {
            backend_tls_client_cert_path: Some("/global/client.pem".to_string()),
            backend_tls_client_key_path: Some("/global/client.key".to_string()),
            ..Default::default()
        };
        let pool = Http2ConnectionPool::new(
            PoolConfig::default(),
            env_config,
            DnsCache::new(DnsConfig::default()),
            None,
            Arc::new(Vec::new()),
        );

        let key = pool.with_pool_key(&proxy, None, |buf| buf.clone());

        assert!(
            key.contains("|/global/client.pem|/global/client.key|"),
            "runtime H2 pool key must include global backend mTLS fallback: {key}"
        );

        // The pool key partitions correctly on the cert/key paths above, but
        // those paths are credential metadata and must never reach a log line.
        // The H2->reqwest fallback formats `BackendSelectedHttp1` via Display,
        // so that rendering must scrub the cert/key components.
        let displayed = Http2PoolError::BackendSelectedHttp1 {
            pool_key: key.clone(),
        }
        .to_string();
        assert!(
            !displayed.contains("/global/client.pem"),
            "mTLS client cert path leaked into H2 fallback log/Display: {displayed}"
        );
        assert!(
            !displayed.contains("/global/client.key"),
            "mTLS client key path leaked into H2 fallback log/Display: {displayed}"
        );
        assert!(
            displayed.contains("<redacted>"),
            "redaction marker missing from H2 fallback Display: {displayed}"
        );
        // Non-credential fields must survive so the log stays useful.
        assert!(
            displayed.contains(&proxy.backend_host),
            "backend host should remain in the redacted fallback Display: {displayed}"
        );
    }

    /// Redaction operates field-positionally on the `|`-delimited pool key:
    /// only the cert (idx 5) and key (idx 6) slots are scrubbed, empty slots
    /// stay empty (no spurious `<redacted>`), and non-TLS fields are preserved.
    #[test]
    fn redact_pool_key_scrubs_only_cert_and_key_fields() {
        // host|port|dns|subset|ca|cert|key|sni|san|verify+svid
        let key = "backend.test|443||sub|/etc/ca.pem|/etc/client.crt|/etc/client.key|sni.test|deadbeef|1|svidg=17";
        let redacted = redact_pool_key_tls_material(key);
        assert_eq!(
            redacted,
            "backend.test|443||sub|/etc/ca.pem|<redacted>|<redacted>|sni.test|deadbeef|1|svidg=17",
            "only the cert and key fields should be scrubbed"
        );

        // Empty cert/key (the common global-fallback-absent case) must not be
        // replaced with a marker — an empty field carries no credential.
        let empty_tls = "backend.test|443|||/etc/ca.pem||||deadbeef|1|svidg=static";
        assert_eq!(
            redact_pool_key_tls_material(empty_tls),
            empty_tls,
            "empty cert/key fields must remain empty"
        );
    }

    #[tokio::test]
    async fn force_drain_svid_generation_removes_rr_counter_keys() {
        let pool = Http2ConnectionPool::default();

        pool.rr_counters.insert(
            "backend|443|fields|svidg=17".to_string(),
            Arc::new(AtomicUsize::new(1)),
        );
        pool.rr_counters.insert(
            "backend|443|fields|svidg=18".to_string(),
            Arc::new(AtomicUsize::new(1)),
        );
        pool.rr_counters.insert(
            "backend|443|fields|svidg=static".to_string(),
            Arc::new(AtomicUsize::new(1)),
        );

        pool.force_drain_svid_generation(17);

        assert!(!pool.rr_counters.contains_key("backend|443|fields|svidg=17"));
        assert!(pool.rr_counters.contains_key("backend|443|fields|svidg=18"));
        assert!(
            pool.rr_counters
                .contains_key("backend|443|fields|svidg=static")
        );
    }

    /// Correctness: the thread-local helper must produce the same byte string
    /// as the long-standing `pool_key_owned()` helper. If these ever diverge
    /// the H2 pool would silently fragment (one allocation path inserts
    /// keys, the other looks them up — a mismatch would never hit a cached
    /// connection).
    fn with_http2_test_pool_key<R>(
        proxy: &Proxy,
        svid_generation: Option<u64>,
        f: impl FnOnce(&mut String) -> R,
    ) -> R {
        with_http2_pool_key(
            proxy,
            proxy.resolved_tls.client_cert_path.as_deref(),
            proxy.resolved_tls.client_key_path.as_deref(),
            svid_generation,
            f,
        )
    }

    #[test]
    fn with_http2_pool_key_matches_pool_key_owned() {
        let proxy = http2_pool_test_proxy();
        let owned = pool_key_owned(&proxy, None);
        let from_thread_local = with_http2_test_pool_key(&proxy, None, |buf| buf.clone());
        assert_eq!(
            owned, from_thread_local,
            "thread-local key must equal pool_key_owned bytes — divergence would split the cache"
        );
    }

    /// Correctness across runs: a second `with_http2_pool_key` invocation
    /// against the same `Proxy` must produce the identical key. Catches a
    /// future bug where stale buffer contents leak through if `clear()` is
    /// dropped from `write_http2_pool_key`.
    #[test]
    fn with_http2_pool_key_is_idempotent_across_calls() {
        let proxy = http2_pool_test_proxy();
        let k1 = with_http2_test_pool_key(&proxy, None, |buf| buf.clone());
        // Force the buffer to grow in between by running a different proxy
        // with a longer host through the helper.
        let mut other = http2_pool_test_proxy();
        other.backend_host =
            "very-long-backend-hostname-that-grows-the-buffer.subdomain.example.com".to_string();
        let _ = with_http2_test_pool_key(&other, None, |buf| buf.clone());
        let k2 = with_http2_test_pool_key(&proxy, None, |buf| buf.clone());
        assert_eq!(k1, k2, "same proxy must always yield the same key");
    }

    /// Reuse: repeated `with_http2_pool_key` calls on the same thread must
    /// reuse the underlying heap buffer, not allocate a fresh one each call.
    /// We capture the heap pointer of the buffer's storage between
    /// invocations and assert it never moves once the capacity is large
    /// enough to hold the key. This is the load-bearing assertion for the
    /// CLAUDE.md "zero-allocation hot path" rule.
    #[test]
    fn with_http2_pool_key_reuses_heap_buffer_across_calls() {
        let proxy = http2_pool_test_proxy();

        // Prime the buffer once so the initial capacity is sized to hold
        // the key. The thread-local was constructed with capacity 128
        // (well above the typical key length), so this should not realloc.
        let (first_ptr, first_capacity) =
            with_http2_test_pool_key(&proxy, None, |buf| (buf.as_ptr() as usize, buf.capacity()));
        assert!(
            first_capacity >= 128,
            "expected pre-sized capacity (>=128), got {first_capacity}"
        );

        // Run a tight loop and assert the heap pointer NEVER moves. If the
        // optimization regresses to per-call `String::with_capacity(...)`,
        // the pointer would change on every iteration.
        for i in 0..1024 {
            let (ptr, cap) = with_http2_test_pool_key(&proxy, None, |buf| {
                (buf.as_ptr() as usize, buf.capacity())
            });
            assert_eq!(
                ptr, first_ptr,
                "iteration {i}: heap pointer changed (was {first_ptr:#x}, now {ptr:#x}) — \
                 thread-local buffer was reallocated, defeating the optimization"
            );
            assert_eq!(
                cap, first_capacity,
                "iteration {i}: capacity changed without a heap move — \
                 unexpected, would imply ZST or alias chicanery"
            );
        }
    }

    /// Phase-2 (post-await fallback) compatibility: the `debug_assert_eq!`
    /// in `get_sender`'s error path requires that re-running
    /// `write_http2_pool_key` against the same proxy produces a buffer
    /// whose `len()` equals the `base_len` captured pre-await. If a future
    /// refactor adds non-deterministic content to the key (e.g. timestamps)
    /// the assertion would fire under -C debug-assertions=on.
    #[test]
    fn with_http2_pool_key_base_len_is_stable() {
        let proxy = http2_pool_test_proxy();
        let len1 = with_http2_test_pool_key(&proxy, None, |buf| buf.len());
        let len2 = with_http2_test_pool_key(&proxy, None, |buf| buf.len());
        assert_eq!(
            len1, len2,
            "base_len must be deterministic across calls — \
             the post-await fallback in get_sender relies on this"
        );
    }
}
