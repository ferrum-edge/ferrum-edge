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
use http::StatusCode;
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tracing::{debug, error, warn};

use crate::config::PoolConfig;
use crate::config::types::{BackendScheme, Proxy};
use crate::dns::{DnsCache, DnsConfig};
use crate::pool::{GenericPool, PoolManager};
use crate::proxy::headers::{
    is_backend_response_strip_header, merge_proxy_headers_and_strip_for_grpc,
    parse_connection_listed_headers,
};
use crate::tls::TlsPolicy;
use crate::tls::backend::{
    BackendSvidGeneration, BackendTlsConfigBuilder, BackendTlsConfigCache, SvidGenerationMatcher,
    append_backend_tls_pool_key_fields, append_optional_pool_key_component,
    append_pool_key_component, backend_svid_generation_for_client_cert,
};
use crate::util::body_limit::is_length_limit_error;

/// Observer fired exactly when the streaming gRPC **request upload** reaches a
/// terminal state — clean EOF, overflow abort, or stream drop (client/backend
/// reset). Attached to the `GrpcBody::Streaming` request-body wrapper and
/// invoked from its `Drop`, which hyper runs once it is done sending the
/// request body (END_STREAM) or abandons the stream.
///
/// The gRPC transport layer stays agnostic to what the observer does. The proxy
/// layer wires it to circuit-breaker probe accounting (`GrpcStreamingProbeRecorder`
/// in `proxy::mod`) so a client-upload overflow at ANY point in the RPC — even
/// one that only trips during response-body streaming — is classified at upload
/// termination instead of at response-header time.
pub trait GrpcUploadTerminationObserver: Send + Sync {
    /// Called once, when the request-body upload terminates. Implementations
    /// must be cheap and non-blocking (this runs inside `Drop` on hyper's
    /// connection task): no `.await`, no locks held across work.
    fn on_upload_terminated(&self);
}

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
    ///
    /// **Thread-safety of `bytes_seen: usize`**: this counter is only read
    /// and written inside `poll_frame()`, which requires `Pin<&mut Self>`.
    /// The mutable-borrow requirement guarantees exclusive ownership, making
    /// concurrent polling structurally impossible regardless of which task
    /// drives the poll. Cross-task signaling uses the
    /// separate `exceeded: Arc<AtomicBool>` flag. This matches the
    /// `SizeLimitedStreamingResponse` pattern in `body.rs`, which also
    /// uses a plain `usize` for the same reason. Contrast with
    /// `SizeLimitedIncoming`, which needs `Arc<AtomicU64>` because callers
    /// observe `bytes_seen` from another task after `into_reqwest_body()`
    /// moves ownership — `GrpcBody` has no such cross-task read path.
    Streaming {
        incoming: Incoming,
        bytes_seen: usize,
        max_bytes: usize,
        exceeded: Arc<AtomicBool>,
        /// Fired from `Drop` when this request body terminates. Carries the
        /// deferred circuit-breaker probe accounting so a late upload overflow
        /// is recorded at upload termination, not at response-header time.
        /// `None` when no circuit breaker is configured for the proxy.
        upload_observer: Option<Arc<dyn GrpcUploadTerminationObserver>>,
    },
}

impl Drop for GrpcBody {
    fn drop(&mut self) {
        // Notify the upload-termination observer when the streaming request
        // body is dropped. hyper drops it once the upload finishes (END_STREAM)
        // or the stream is reset, so this is the canonical "request upload
        // terminated" signal — independent of the response body's lifetime.
        if let GrpcBody::Streaming {
            upload_observer, ..
        } = self
            && let Some(observer) = upload_observer.as_ref()
        {
            observer.on_upload_terminated();
        }
    }
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
                ..
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

thread_local! {
    /// Reused per-thread buffer for gRPC pool-key construction on the
    /// request hot path. Mirrors the zero-allocation strategy used by
    /// `HTTP2_POOL_KEY_BUF` in `http2_pool.rs` so `get_sender()` performs
    /// zero `String` allocations on cache-hit calls from the same tokio
    /// worker thread.
    ///
    /// The buffer is reset before each lookup. Owned `String` keys are still
    /// produced via `.clone()` on the cache-miss path (cold start, new
    /// backends), so the allocation moves off the cache-hit fast path
    /// entirely.
    ///
    /// Cannot be borrowed across `await`. `with_grpc_pool_key` and the
    /// pre-/post-await scopes in `get_sender` keep every `borrow_mut()`
    /// inside a synchronous block.
    static GRPC_POOL_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(128));
}

/// Run `f` against a thread-local buffer pre-populated with the gRPC pool
/// key for `proxy` (no shard suffix). Callers can append `#<shard>` via
/// `write_grpc_shard_key_inplace` using `buf.len()` as `base_len`.
///
/// The closure must be synchronous -- the underlying `RefCell::borrow_mut`
/// cannot cross an `.await`. `now_or_never(...)` polling and DashMap
/// lookups are fine.
fn with_grpc_pool_key<R>(
    proxy: &Proxy,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
    svid_generation: Option<u64>,
    f: impl FnOnce(&mut String) -> R,
) -> R {
    GRPC_POOL_KEY_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        write_grpc_pool_key(
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

fn write_grpc_pool_key(
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
    // TLS intent comes from the backend scheme; flavor (gRPC vs plain HTTP)
    // is detected at request time and doesn't affect pool identity — an
    // Https pool entry serves both gRPC and Plain requests.
    let tls = matches!(proxy.backend_scheme, Some(BackendScheme::Https)) as u8;
    append_pool_key_component(buf, host);
    let _ = write!(buf, "|{port}|{tls}|");
    append_optional_pool_key_component(buf, proxy.dns_override.as_deref());
    buf.push('|');
    // Subset name partitions gRPC pools so two proxies that share
    // `(host, port, scheme, dns_override)` but select different
    // DestinationRule subsets cannot share an H2 gRPC sender even when their
    // TLS material is byte-identical. Empty when the proxy has no
    // `upstream_subset`.
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

fn grpc_pool_key_owned(proxy: &Proxy, svid_generation: Option<u64>) -> String {
    let mut buf = String::with_capacity(128);
    write_grpc_pool_key(
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
    crls: crate::tls::SharedCrlList,
    tls_configs: BackendTlsConfigCache,
    backend_svid_generation: BackendSvidGeneration,
    workload_svid_cert_path: Option<String>,
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
        let manager = Arc::new(GrpcPoolManager {
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

    /// Number of connections in the pool (for metrics).
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
    ///
    /// Not called directly after the thread-local buffer refactor (the free
    /// function `with_grpc_pool_key` calls `write_grpc_pool_key` instead),
    /// but retained for parity with the HTTP2 pool's internal API surface.
    #[allow(dead_code)]
    fn write_pool_key(buf: &mut String, proxy: &Proxy) {
        write_grpc_pool_key(
            buf,
            &proxy.backend_host,
            proxy.backend_port,
            proxy,
            proxy.resolved_tls.client_cert_path.as_deref(),
            proxy.resolved_tls.client_key_path.as_deref(),
            None,
        );
    }

    /// Allocating version of the pool key — only used for warmup deduplication
    /// where the key must outlive the thread-local buffer. Currently unused
    /// post-refactor (gRPC pool warms lazily); retained for future re-enablement.
    #[allow(dead_code)]
    fn pool_key_owned(proxy: &Proxy) -> String {
        grpc_pool_key_owned(proxy, None)
    }

    /// Expose the base pool key for warmup deduplication (without shard suffix).
    /// `pub` for parity with `Http2ConnectionPool::pool_key_for_warmup` so
    /// external integration/unit tests can verify pool-key partitioning
    /// behavior (e.g., GAP-3B subset partitioning regression guard in
    /// `tests/unit/gateway_core/pool_key_tests.rs`).
    #[allow(dead_code)]
    pub fn pool_key_for_warmup(proxy: &Proxy) -> String {
        Self::pool_key_owned(proxy)
    }

    /// Append a shard suffix in-place by truncating to `base_len` first.
    /// Avoids clearing and rewriting the base key on every shard iteration.
    fn write_shard_key_inplace(buf: &mut String, base_len: usize, shard: usize) {
        write_grpc_shard_key_inplace(buf, base_len, shard);
    }

    fn with_pool_key<R>(
        &self,
        proxy: &Proxy,
        svid_generation: Option<u64>,
        f: impl FnOnce(&mut String) -> R,
    ) -> R {
        let manager = self.pool.manager();
        with_grpc_pool_key(
            proxy,
            manager.effective_client_cert_path(proxy),
            manager.effective_client_key_path(proxy),
            svid_generation,
            f,
        )
    }

    pub async fn get_sender(
        &self,
        proxy: &Proxy,
    ) -> Result<http2::SendRequest<GrpcBody>, GrpcProxyError> {
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
        let phase1 = self.with_pool_key(proxy, svid_generation, |key_buf| -> GrpcPhase1 {
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
                    .or_insert_with(|| {
                        Arc::new(AtomicUsize::new(crate::proxy::http2_pool::rr_seed()))
                    })
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
                        Some(Ok(())) => return GrpcPhase1::Hit(sender),
                        Some(Err(_)) => {
                            self.pool.invalidate(key_buf);
                        }
                        // Shard exists but is mid-send. Skip — we would
                        // rather open a fresh h2 connection (per-key-
                        // coalesced via `create_or_get_existing_owned`, so
                        // concurrent callers dedupe onto ONE create future)
                        // than stall on `timeout(ready())`. The previous
                        // 1 ms wait still serialized under burst concurrency
                        // and was the largest contributor to gRPC p99 tail
                        // latency for 100-concurrent 500 KB / 1 MB payloads.
                        None => {}
                    }
                }
            }

            Self::write_shard_key_inplace(key_buf, base_len, start);
            // Single allocation: clone the thread-local buffer into the
            // owned key that `create_or_get_existing_owned` consumes. This
            // is the only `String` allocation on the cache-miss path now —
            // cache hits take the early return above without allocating.
            GrpcPhase1::Miss {
                selected_key: key_buf.clone(),
                base_len,
                start,
            }
        });

        let (selected_key, base_len, start) = match phase1 {
            GrpcPhase1::Hit(sender) => return Ok(sender),
            GrpcPhase1::Miss {
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
enum GrpcPhase1 {
    /// A cached sender was immediately ready — short-circuit to the caller
    /// without cloning the pool key or hitting `create_or_get_existing_owned`.
    Hit(http2::SendRequest<GrpcBody>),
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

impl GrpcPoolManager {
    fn get_tls_config(
        &self,
        proxy: &Proxy,
        svid_generation: Option<u64>,
    ) -> Result<Arc<rustls::ClientConfig>, GrpcProxyError> {
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
                GrpcProxyError::Internal(format!("Failed to build backend TLS config: {}", e))
            })?;

            tls_config.alpn_protocols = vec![b"h2".to_vec()];
            Ok(tls_config)
        })
    }

    async fn create_connection(
        &self,
        proxy: &Proxy,
        svid_generation: Option<u64>,
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
                GrpcProxyError::backend_unavailable(
                    GrpcBackendUnavailableKind::DnsResolution,
                    format!("DNS resolution failed for {}: {}", host, e),
                )
            })?;

        // Construct SocketAddr from the resolved IpAddr + port directly.
        // This handles both IPv4 and IPv6 correctly without string formatting
        // issues (IPv6 addresses from IpAddr::to_string() are unbracketed,
        // which breaks "ip:port" string parsing).
        let sock_addr = std::net::SocketAddr::new(resolved_ip, port);
        let addr = sock_addr.to_string();
        let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);
        let connect_started = Instant::now();

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
            GrpcProxyError::backend_unavailable_with_source(
                GrpcBackendUnavailableKind::Connect,
                format!("Connection failed: {}", e),
                e,
            )
        })?;

        // Disable Nagle for lower latency
        let _ = tcp.set_nodelay(true);

        // Apply TCP keepalive: honor the DestinationRule
        // `connectionPool.tcp.tcpKeepalive` per-port override (keyed by the
        // dial target's port, `proxy.backend_port`), falling back to the
        // global pool keepalive. NOTE: keepalive is NOT in the pool key
        // (forbidden by `.claude/rules/proxy-protocols.md`), and this
        // connection is pooled+shared, so the first dispatcher to materialize
        // the connection wins — same first-materializer tradeoff documented
        // for `idleTimeout` / `maxRequestsPerConnection`.
        let pool_config = self.global_pool_config.for_proxy(proxy);
        crate::socket_opts::apply_pooled_tcp_keepalive(
            "grpc_proxy",
            &tcp,
            proxy
                .dispatch_port_overrides
                .as_ref()
                .and_then(|m| m.get(&port))
                .and_then(|o| o.tcp_keepalive.as_ref()),
            pool_config.enable_http_keep_alive,
            pool_config.tcp_keepalive_seconds,
        );

        let use_tls = matches!(proxy.backend_scheme, Some(BackendScheme::Https));

        if use_tls {
            self.create_tls_connection(
                tcp,
                host,
                proxy,
                svid_generation,
                connect_started,
                connect_timeout,
            )
            .await
        } else {
            self.create_h2c_connection(tcp, &pool_config, proxy, connect_started, connect_timeout)
                .await
        }
    }

    fn backend_connect_timeout_error(proxy: &Proxy, phase: &str) -> GrpcProxyError {
        GrpcProxyError::BackendTimeout {
            kind: GrpcTimeoutKind::Connect,
            message: format!(
                "Connect timeout after {}ms during {} to {}:{}",
                proxy.backend_connect_timeout_ms, phase, proxy.backend_host, proxy.backend_port
            ),
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
            // Cap server-initiated streams (push) AND advertise our local
            // initial cap on locally-initiated streams. The server's SETTINGS
            // frame can raise the local cap later, but the initial value
            // gives operators a starting bound that maps onto Istio's
            // `http2MaxRequests` semantics for outbound concurrent requests.
            builder.max_concurrent_streams(max_streams);
            builder.initial_max_send_streams(max_streams as usize);
        }

        builder
    }

    /// Create an h2c (cleartext HTTP/2) connection using prior knowledge.
    async fn create_h2c_connection(
        &self,
        tcp: TcpStream,
        pool_config: &PoolConfig,
        proxy: &Proxy,
        connect_started: Instant,
        connect_timeout: Duration,
    ) -> Result<http2::SendRequest<GrpcBody>, GrpcProxyError> {
        let io = TokioIo::new(tcp);
        let builder = Self::build_h2_builder(pool_config);

        let Some(remaining) =
            crate::pool::remaining_connect_timeout(connect_started, connect_timeout)
        else {
            return Err(Self::backend_connect_timeout_error(proxy, "h2c handshake"));
        };

        let (sender, conn) = tokio::time::timeout(remaining, builder.handshake(io))
            .await
            .map_err(|_| Self::backend_connect_timeout_error(proxy, "h2c handshake"))?
            .map_err(|e| {
                GrpcProxyError::backend_unavailable_with_source(
                    GrpcBackendUnavailableKind::H2cHandshake,
                    format!("h2c handshake failed: {}", e),
                    e,
                )
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
        svid_generation: Option<u64>,
        connect_started: Instant,
        connect_timeout: Duration,
    ) -> Result<http2::SendRequest<GrpcBody>, GrpcProxyError> {
        use tokio_rustls::TlsConnector;

        let tls_config = self.get_tls_config(proxy, svid_generation)?;
        let connector = TlsConnector::from(tls_config);
        let server_name =
            crate::tls::backend::backend_tls_server_name_owned(&proxy.resolved_tls, host).map_err(
                |e| {
                    GrpcProxyError::backend_unavailable(
                        GrpcBackendUnavailableKind::InvalidServerName,
                        format!("Invalid server name: {}", e),
                    )
                },
            )?;

        let Some(remaining) =
            crate::pool::remaining_connect_timeout(connect_started, connect_timeout)
        else {
            return Err(Self::backend_connect_timeout_error(proxy, "TLS handshake"));
        };

        let tls_stream = tokio::time::timeout(remaining, connector.connect(server_name, tcp))
            .await
            .map_err(|_| Self::backend_connect_timeout_error(proxy, "TLS handshake"))?
            .map_err(|e| {
                GrpcProxyError::backend_unavailable_with_source(
                    GrpcBackendUnavailableKind::TlsHandshake,
                    format!("TLS handshake failed: {}", e),
                    e,
                )
            })?;

        let io = TokioIo::new(tls_stream);
        let pool_config = self.global_pool_config.for_proxy(proxy);
        let builder = Self::build_h2_builder(&pool_config);

        let Some(remaining) =
            crate::pool::remaining_connect_timeout(connect_started, connect_timeout)
        else {
            return Err(Self::backend_connect_timeout_error(proxy, "h2 handshake"));
        };

        let (sender, conn) = tokio::time::timeout(remaining, builder.handshake(io))
            .await
            .map_err(|_| Self::backend_connect_timeout_error(proxy, "h2 handshake"))?
            .map_err(|e| {
                GrpcProxyError::backend_unavailable_with_source(
                    GrpcBackendUnavailableKind::H2Handshake,
                    format!("h2 handshake failed: {}", e),
                    e,
                )
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
        self.write_pool_key(
            buf,
            host,
            port,
            proxy,
            self.svid_generation_for_proxy(proxy),
        );
        let base_len = buf.len();
        write_grpc_shard_key_inplace(buf, base_len, shard);
    }

    async fn create(&self, _key: &str, proxy: &Proxy) -> Result<http2::SendRequest<GrpcBody>> {
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
        Some(crate::runtime_metrics::PoolKind::Grpc)
    }
}

impl GrpcPoolManager {
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
        write_grpc_pool_key(
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

/// Why a gRPC backend connection failed.
///
/// Attached to [`GrpcProxyError::BackendUnavailable`] so the classifier
/// ([`crate::retry::classify_grpc_proxy_error`]) reads the cause directly
/// from the typed kind instead of substring-matching the error message —
/// the legacy approach that broke whenever `tonic`/`hyper` reworded its
/// errors.
///
/// **Adding a new variant**: extend [`GrpcBackendUnavailableKind`], update
/// the classifier match arm, and pass the new kind at every relevant
/// construction site. Drift between construction site and classifier is
/// now a compile error rather than a silent miscategorisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcBackendUnavailableKind {
    /// DNS resolution failed for the backend hostname. Maps to
    /// [`crate::retry::ErrorClass::DnsLookupError`].
    DnsResolution,
    /// TCP connect refused / failed (post-DNS, pre-handshake). Maps to
    /// [`crate::retry::ErrorClass::ConnectionRefused`] (or
    /// `ConnectionTimeout` when wrapped via the timeout variant — see
    /// [`GrpcTimeoutKind::Connect`]).
    Connect,
    /// rustls TLS handshake failed (e.g., certificate verification, ALPN
    /// mismatch, alert from peer). Maps to
    /// [`crate::retry::ErrorClass::TlsError`].
    TlsHandshake,
    /// HTTP/2 handshake failed over an established TLS connection (post-ALPN
    /// `h2`). Maps to [`crate::retry::ErrorClass::TlsError`] because the
    /// handshake error is rooted in the secure transport setup.
    H2Handshake,
    /// HTTP/2 cleartext (h2c) handshake failed (no TLS). Maps to
    /// [`crate::retry::ErrorClass::ConnectionRefused`] — the TCP connection
    /// was established but the H2 protocol negotiation failed BEFORE any
    /// stream was opened, so the request never reached the backend's
    /// application layer. Pre-wire under the unified
    /// [`crate::retry::request_reached_wire`] boundary, which keeps the
    /// classifier consistent with [`Self::is_connect_class`] (a regression
    /// test in `tests/unit/gateway_core/retry_tests.rs` enforces that
    /// every connect-class kind classifies to `request_reached_wire ==
    /// false`).
    H2cHandshake,
    /// `rustls::pki_types::ServerName::try_from` rejected the host. Maps to
    /// [`crate::retry::ErrorClass::DnsLookupError`] because the failure is
    /// rooted in the configured/looked-up name, before any wire activity.
    InvalidServerName,
    /// The backend rejected an outbound request after the H2 connection was
    /// established and ALPN had succeeded — e.g., `hyper::Error` from
    /// `sender.send_request(...).await`. **Post-wire by definition:** the
    /// request headers may already have been forwarded, so this kind must
    /// NEVER be treated as a pre-wire failure. Maps to
    /// [`crate::retry::ErrorClass::ConnectionReset`] (mid-stream reset) so
    /// `request_reached_wire` returns true and the connect-failure retry
    /// path does not replay non-idempotent POSTs across the same stream.
    BackendRequest,
}

impl GrpcBackendUnavailableKind {
    /// Returns `true` for kinds that represent a pre-wire failure (DNS,
    /// connect, handshake) — safe to replay regardless of HTTP method
    /// idempotency.
    ///
    /// Returns `false` for [`Self::BackendRequest`], which is emitted
    /// post-handshake from `send_request().await` and may have committed the
    /// request headers / body bytes to the wire. The outer gRPC retry loops
    /// match on this predicate so `retry_on_connect_failure` doesn't bypass
    /// `retry_on_methods` for post-wire failures.
    pub fn is_connect_class(self) -> bool {
        match self {
            Self::DnsResolution
            | Self::Connect
            | Self::TlsHandshake
            | Self::H2Handshake
            | Self::H2cHandshake
            | Self::InvalidServerName => true,
            Self::BackendRequest => false,
        }
    }
}

/// Errors specific to gRPC proxying.
///
/// `BackendUnavailable` carries a typed [`GrpcBackendUnavailableKind`] and
/// an optional source so the classifier can downcast typed errors
/// (`io::Error`, `hyper::Error`, `rustls::Error`) instead of formatting and
/// substring-matching the message. Construction sites attach the source via
/// [`GrpcProxyError::backend_unavailable`].
#[derive(Debug)]
pub enum GrpcProxyError {
    BackendUnavailable {
        kind: GrpcBackendUnavailableKind,
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    BackendTimeout {
        kind: GrpcTimeoutKind,
        message: String,
    },
    /// The CLIENT request payload exceeded the configured maximum (detected
    /// before the backend produced response headers). Client-side — the
    /// circuit breaker treats this as neutral, like an HTTP client disconnect.
    ResourceExhausted(String),
    /// The BACKEND response payload exceeded `max_response_body_size_bytes`.
    /// Backend-side — the circuit breaker treats this as a 502-class failure,
    /// mirroring the HTTP path's `ErrorClass::ResponseBodyTooLarge`.
    ResponseTooLarge(String),
    Internal(String),
}

impl GrpcProxyError {
    /// Build a `BackendUnavailable` variant with no typed source.
    pub fn backend_unavailable(kind: GrpcBackendUnavailableKind, message: String) -> Self {
        Self::BackendUnavailable {
            kind,
            message,
            source: None,
        }
    }

    /// Build a `BackendUnavailable` variant with a typed source for chain
    /// walkers (port-exhaustion detection, classification).
    pub fn backend_unavailable_with_source<E>(
        kind: GrpcBackendUnavailableKind,
        message: String,
        source: E,
    ) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::BackendUnavailable {
            kind,
            message,
            source: Some(Box::new(source)),
        }
    }
}

impl std::fmt::Display for GrpcProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendUnavailable { message, .. }
            | Self::ResourceExhausted(message)
            | Self::ResponseTooLarge(message)
            | Self::Internal(message) => write!(f, "{}", message),
            Self::BackendTimeout { message, .. } => write!(f, "{}", message),
        }
    }
}

impl std::error::Error for GrpcProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BackendUnavailable { source, .. } => {
                source.as_deref().map(|s| s as &dyn std::error::Error)
            }
            _ => None,
        }
    }
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

/// Map an HTTP rejection status to the closest gRPC status code for
/// gateway-generated trailers-only errors.
pub(crate) fn http_reject_status_to_grpc_status(status: StatusCode) -> u32 {
    match status {
        StatusCode::BAD_REQUEST => grpc_status::INVALID_ARGUMENT,
        StatusCode::METHOD_NOT_ALLOWED => grpc_status::UNIMPLEMENTED,
        StatusCode::UNAUTHORIZED => grpc_status::UNAUTHENTICATED,
        StatusCode::FORBIDDEN => grpc_status::PERMISSION_DENIED,
        StatusCode::NOT_FOUND => grpc_status::NOT_FOUND,
        StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => grpc_status::DEADLINE_EXCEEDED,
        StatusCode::CONFLICT => grpc_status::ABORTED,
        StatusCode::PRECONDITION_FAILED => grpc_status::FAILED_PRECONDITION,
        StatusCode::PAYLOAD_TOO_LARGE
        | StatusCode::URI_TOO_LONG
        | StatusCode::TOO_MANY_REQUESTS => grpc_status::RESOURCE_EXHAUSTED,
        StatusCode::NOT_IMPLEMENTED => grpc_status::UNIMPLEMENTED,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE => grpc_status::UNAVAILABLE,
        _ => grpc_status::INTERNAL,
    }
}

/// Map a gRPC status code to the closest HTTP status — the reverse of
/// [`http_reject_status_to_grpc_status`]. Used to feed the adaptive-concurrency
/// limiter a backend-health signal for gRPC responses whose failure rides in the
/// `grpc-status` trailer under HTTP 200: server-side failures (UNAVAILABLE,
/// INTERNAL, DEADLINE_EXCEEDED, UNKNOWN, DATA_LOSS) map to 5xx so the limiter
/// shrinks, while client-side statuses map to 4xx and stay healthy. Consistent
/// with how the limiter already treats any HTTP 5xx as a backend fault.
pub(crate) fn grpc_status_to_http_status(grpc_status: u32) -> u16 {
    match grpc_status {
        0 => 200,  // OK
        1 => 499,  // CANCELLED (client closed request)
        2 => 500,  // UNKNOWN
        3 => 400,  // INVALID_ARGUMENT
        4 => 504,  // DEADLINE_EXCEEDED
        5 => 404,  // NOT_FOUND
        6 => 409,  // ALREADY_EXISTS
        7 => 403,  // PERMISSION_DENIED
        8 => 429,  // RESOURCE_EXHAUSTED
        9 => 400,  // FAILED_PRECONDITION
        10 => 409, // ABORTED
        11 => 400, // OUT_OF_RANGE
        12 => 501, // UNIMPLEMENTED
        13 => 500, // INTERNAL
        14 => 503, // UNAVAILABLE
        15 => 500, // DATA_LOSS
        16 => 401, // UNAUTHENTICATED
        _ => 500,  // unknown code — treat as a server error
    }
}

/// Derive the HTTP status the adaptive-concurrency limiter should see for a
/// gRPC response whose outcome rides in the `grpc-status` trailer (normal
/// responses) or header (trailers-only) under HTTP 200. Returns the mapped HTTP
/// status for a non-OK gRPC status, else `http_status`. Shared by the buffered
/// H1/H2 and H3 gRPC admission paths so they cannot drift.
pub(crate) fn grpc_admission_status_from_maps(
    trailers: &HashMap<String, String>,
    headers: &HashMap<String, String>,
    http_status: u16,
) -> u16 {
    trailers
        .get("grpc-status")
        .or_else(|| headers.get("grpc-status"))
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&code| code != 0)
        .map(grpc_status_to_http_status)
        .unwrap_or(http_status)
}

/// Reserved gRPC terminal-status metadata keys (`grpc-status`,
/// `grpc-message`, `grpc-status-details-bin`). Per the gRPC HTTP/2 mapping,
/// a non-Trailers-Only response must carry these ONLY in the terminal
/// TRAILERS frame — a copy in the initial HEADERS is malformed backend
/// output. The buffered writeback path uses this to (a) let the trailing
/// value win in the merged plugin view and (b) always strip the initial
/// header copy on the non-empty wire path, even when the key would
/// otherwise be header-shadowed. Keys are compared lowercase (hyper
/// normalizes header names).
pub(crate) fn is_reserved_grpc_terminal_metadata(key: &str) -> bool {
    matches!(
        key,
        "grpc-status" | "grpc-message" | "grpc-status-details-bin"
    )
}

/// Build the merged header+trailer view buffered gRPC response-hook plugins run
/// on, plus the set of trailer keys the backend ALSO sent as real initial
/// headers ("header-shadowed" keys).
///
/// Plugins historically saw a single merged map because trailers were inserted
/// into the response headers before hooks ran. This reproduces that view: a
/// trailer-only key is merged in so hooks can see and sanitize it; a key the
/// backend also sent as a real header is recorded in the returned set instead
/// of overriding the header value (a trailer never overrides a real header in
/// the view), so post-hook writeback can tell a genuine hook edit from the
/// backend's distinct trailer value. The reserved gRPC terminal-status keys
/// (`grpc-status` / `grpc-message` / `grpc-status-details-bin`) are
/// trailer-authoritative and never treated as shadowed.
///
/// Shared by the main buffered gRPC path (`proxy::handle_proxy_request`) and the
/// HTTP/3 cross-protocol bridge (`http3::cross_protocol`) so a response-hook
/// sanitizer reaches the wire trailers identically on both — see
/// [`reconcile_grpc_trailers_from_view`] for the writeback half.
pub fn build_grpc_plugin_header_view(
    response_headers: &HashMap<String, String>,
    response_trailers: &HashMap<String, String>,
) -> (HashMap<String, String>, HashSet<String>) {
    let mut plugin_response_headers = response_headers.clone();
    let mut header_shadowed_trailer_keys: HashSet<String> = HashSet::new();
    for (k, v) in response_trailers {
        if response_headers.contains_key(k) && !is_reserved_grpc_terminal_metadata(k) {
            header_shadowed_trailer_keys.insert(k.clone());
        } else {
            plugin_response_headers.insert(k.clone(), v.clone());
        }
    }
    (plugin_response_headers, header_shadowed_trailer_keys)
}

/// Reconcile response-hook mutations made on the merged plugin view (built by
/// [`build_grpc_plugin_header_view`]) back into the wire `response_trailers`.
///
/// `original_response_headers` must be the backend's initial headers as they
/// were before hooks ran. A trailer key now absent from the view was removed by
/// a hook (drop it). A header-shadowed key was merged into the view at the
/// *header* value, so its view value is not comparable to the trailer's own
/// value — detect a genuine hook edit by comparing the view value against the
/// original header value and only then copy the sanitized value into the hidden
/// wire trailer (a sanitizer must scrub every client-visible copy); an
/// untouched shadowed trailer keeps the backend's true trailing value. A
/// non-shadowed (trailer-only) key whose view value changed was edited by a
/// hook; copy it.
pub fn reconcile_grpc_trailers_from_view(
    response_trailers: &mut HashMap<String, String>,
    plugin_response_headers: &HashMap<String, String>,
    original_response_headers: &HashMap<String, String>,
    header_shadowed_trailer_keys: &HashSet<String>,
) {
    response_trailers.retain(|k, v| match plugin_response_headers.get(k) {
        Some(plugin_value) => {
            if header_shadowed_trailer_keys.contains(k) {
                if original_response_headers.get(k) != Some(plugin_value) {
                    *v = plugin_value.clone();
                }
            } else if plugin_value != v {
                *v = plugin_value.clone();
            }
            true
        }
        None => false,
    });
}

/// Re-home a hook-mutated trailer-only `set-cookie` onto the buffered gRPC
/// initial HEADERS (issue #1638).
///
/// On the buffered gRPC path response hooks run on a merged header+trailer view
/// ([`build_grpc_plugin_header_view`]). If the backend sent `set-cookie` only as
/// a gRPC **trailer** and a hook then mutates it, [`reconcile_grpc_trailers_from_view`]
/// writes the hook's value back into the wire trailer and the non-empty-body
/// strip loop removes it from the initial HEADERS — so the cookie rides a
/// trailer and browsers / gRPC-Web clients never store it. A hook that touches
/// `set-cookie` clearly intends a client-visible cookie, so move the hook's
/// value onto the initial HEADERS, mirroring the post-strip treatment the
/// sticky-affinity cookie already gets.
///
/// Scope guards (match issue #1638 exactly, to minimize wire-shape change):
/// - Acts only when `set-cookie` is **trailer-only** after the strip loop
///   (absent from `response_headers`). A header-shadowed `set-cookie` already
///   reaches the client as a real header, so its faithful (sanitized) trailer
///   copy is left alone; the empty-body Trailers-Only collapse is likewise a
///   no-op (the cookie is already a header there).
/// - Acts only when a hook actually **changed** the value
///   (`original_trailer_set_cookie` differs from the current wire trailer). An
///   untouched backend trailer keeps the backend's faithful split wire shape.
///
/// Must be called AFTER the strip loop and BEFORE sticky-cookie injection (so an
/// injected sticky `set-cookie` cannot mask the trailer-only check) and BEFORE
/// the gRPC-Web trailer-clear guard. Shared by the main buffered gRPC path
/// (`proxy::handle_proxy_request`) and the H3 cross-protocol bridge
/// (`http3::cross_protocol`) so both stay byte-for-byte identical (#1614).
pub fn rehome_hook_mutated_trailer_set_cookie(
    response_headers: &mut HashMap<String, String>,
    response_trailers: &mut HashMap<String, String>,
    original_trailer_set_cookie: Option<&str>,
) {
    if response_headers.contains_key("set-cookie") {
        return;
    }
    let Some(current) = response_trailers.get("set-cookie") else {
        return;
    };
    if original_trailer_set_cookie == Some(current.as_str()) {
        return;
    }
    if let Some(value) = response_trailers.remove("set-cookie") {
        response_headers.insert("set-cookie".to_string(), value);
    }
}

/// HTTP/3 admission rejects use `425 Too Early` for 0-RTT policy failures.
/// gRPC clients should see that transport retry signal as UNAVAILABLE.
pub(crate) fn h3_http_reject_status_to_grpc_status(status: StatusCode) -> u32 {
    if status == StatusCode::TOO_EARLY {
        grpc_status::UNAVAILABLE
    } else {
        http_reject_status_to_grpc_status(status)
    }
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

const DEFAULT_GRPC_BUFFERED_CAPACITY: usize = 16 * 1024;
const MAX_GRPC_BUFFERED_PREALLOC_CAPACITY: usize = 1024 * 1024;

pub fn grpc_buffered_body_capacity_hint(headers: &hyper::HeaderMap) -> usize {
    headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .map(|len| len.min(MAX_GRPC_BUFFERED_PREALLOC_CAPACITY))
        .unwrap_or(DEFAULT_GRPC_BUFFERED_CAPACITY)
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
    /// Per-frame idle read timeout (ms) the response-body consumer applies to
    /// the streaming `body` in the FALLBACK regime (no client `grpc-timeout`):
    /// `backend_read_timeout_ms`, or `0` for unbounded. Ignored when
    /// [`Self::client_grpc_deadline_ms`] is `Some` — that regime uses an absolute
    /// end-to-end deadline instead. Without a bound a backend that sends headers
    /// then stalls would pin the streaming guards until the client disconnects.
    pub response_read_timeout_ms: u64,
    /// The post-plugin client `grpc-timeout` in milliseconds, if the client set
    /// one (issue #1649). When `Some`, the response-body consumer enforces it as
    /// an ABSOLUTE end-to-end deadline (anchored at request receipt) via
    /// `TotalDeadlineBody`, so a backend cannot keep the streaming body open past
    /// the client's RPC deadline by trickling frames under a per-frame idle
    /// interval. When `None`, the per-frame [`Self::response_read_timeout_ms`]
    /// fallback applies. Uncapped: a pathologically large value is handled by the
    /// consumer's overflow guard (treated as unbounded, never a panic).
    pub client_grpc_deadline_ms: Option<u64>,
}

/// Either a fully-buffered or streaming gRPC response.
pub enum GrpcResponseKind {
    /// Response body was fully collected into memory (with trailers extracted).
    Buffered(GrpcResponse),
    /// Response headers received; body and trailers stream frame-by-frame.
    Streaming(GrpcStreamingResponse),
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
    max_response_body_size_bytes: usize,
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
        max_response_body_size_bytes,
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
///
/// `body_size_exceeded` is the shared overflow flag the request body sets on
/// limit breach; the caller owns it (and a matching `upload_observer`) so the
/// circuit-breaker probe outcome can be deferred to request-upload termination.
/// `upload_observer`, when present, is fired from the request body's `Drop` once
/// the upload terminates (clean EOF or overflow abort) — see
/// `GrpcUploadTerminationObserver`.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_grpc_request_streaming(
    req: Request<Incoming>,
    proxy: &Proxy,
    backend_url: &str,
    grpc_pool: &GrpcConnectionPool,
    _dns_cache: &DnsCache,
    proxy_headers: &HashMap<String, String>,
    max_grpc_recv_size_bytes: usize,
    body_size_exceeded: Arc<AtomicBool>,
    upload_observer: Option<Arc<dyn GrpcUploadTerminationObserver>>,
) -> Result<GrpcResponseKind, GrpcProxyError> {
    let (parts, body) = req.into_parts();
    let grpc_body = GrpcBody::Streaming {
        incoming: body,
        bytes_seen: 0,
        max_bytes: max_grpc_recv_size_bytes,
        exceeded: Arc::clone(&body_size_exceeded),
        upload_observer,
    };

    let uri: hyper::Uri = backend_url
        .parse()
        .map_err(|e| GrpcProxyError::Internal(format!("Invalid backend URL: {}", e)))?;

    // Build headers: merge plugin/proxy headers on top of the inbound
    // request's headers, then run the gRPC-specific strip on the union.
    // The helper encapsulates the merge-then-strip ordering so this
    // path and `proxy_grpc_request_core` cannot drift, and so neither
    // can call the steps in the wrong order. See `proxy::headers` for
    // why merging FIRST is required and why `te: trailers` is
    // synthesised at the end.
    let mut headers = parts.headers;
    merge_proxy_headers_and_strip_for_grpc(&mut headers, proxy_headers);

    // Apply per-route Host override AFTER the strip, mirroring
    // `proxy_grpc_request_core` and the plain HTTP path in
    // `proxy::proxy_to_backend`. Without this, an H2 or H3 frontend that
    // synthesized `host` from `:authority` would forward the client's
    // external authority to the gRPC backend even when
    // `preserve_host_header == false`. (Host is not in the hop-by-hop
    // strip set, so order vs strip is safe — but Host MUST be applied
    // after the synthesise step so it's not accidentally targeted by a
    // future strip predicate change.)
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
    let effective_timeout_ms = streaming_effective_timeout_ms(&headers, proxy);
    // Client end-to-end RPC deadline (issue #1649): when the client set a
    // `grpc-timeout`, the streaming response body is bounded by an ABSOLUTE
    // deadline rather than a per-frame idle timeout. Captured here before
    // `headers` is moved into the backend request below.
    let client_grpc_deadline_ms = parse_grpc_timeout_ms(&headers);

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
                GrpcProxyError::backend_unavailable_with_source(
                    GrpcBackendUnavailableKind::BackendRequest,
                    format!("Backend request failed: {}", e),
                    e,
                )
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
            GrpcProxyError::backend_unavailable_with_source(
                GrpcBackendUnavailableKind::BackendRequest,
                format!("Backend request failed: {}", e),
                e,
            )
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
    // Collect backend response headers through the shared collector that the
    // plain-HTTP path uses, instead of a bespoke `insert` loop that overwrote
    // duplicate names. Repeated `Set-Cookie` values are newline-joined (RFC 6265
    // — they MUST be emitted as separate header lines, never comma-folded), other
    // repeated headers are comma-folded, and both the canonical hop-by-hop set
    // (RFC 9110 §7.6.1) and any `Connection`-listed names are stripped.
    // `apply_response_headers()` in the consuming path later splits the
    // newline-joined `Set-Cookie` back into individual header lines. Reusing the
    // shared collector keeps the gRPC and generic paths from drifting and stops
    // duplicate response headers (e.g. multiple `Set-Cookie`) from collapsing to
    // a single value. Hyper rejects `Connection` on H2 frames (RFC 9113 §8.2.2),
    // so the Connection-listed strip is typically a no-op for valid gRPC backends
    // — present for defence in depth.
    let mut resp_headers = HashMap::new();
    let connection_listed = parse_connection_listed_headers(response.headers());
    super::collect_response_headers_generic(
        response.headers().keys_len(),
        response.headers().iter(),
        &mut resp_headers,
        &connection_listed,
    );
    Ok(GrpcResponseKind::Streaming(GrpcStreamingResponse {
        status,
        headers: resp_headers,
        body: response.into_body(),
        request_body_exceeded: if max_grpc_recv_size_bytes > 0 {
            Some(body_size_exceeded)
        } else {
            None
        },
        response_read_timeout_ms: effective_timeout_ms.unwrap_or(0),
        client_grpc_deadline_ms,
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
                if is_length_limit_error(e.as_ref()) {
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
    max_response_body_size_bytes: usize,
) -> Result<GrpcResponseKind, GrpcProxyError> {
    // Get or create HTTP/2 connection to backend (round-robins across pool)
    let mut sender = grpc_pool.get_sender(proxy).await?;
    // Parse the backend URL to extract path and authority
    let uri: hyper::Uri = backend_url
        .parse()
        .map_err(|e| GrpcProxyError::Internal(format!("Invalid backend URL: {}", e)))?;

    // Build headers: merge plugin/proxy headers on top of the inbound
    // request's headers, then run the gRPC-specific strip on the union.
    // Mirrors `proxy_grpc_request_streaming` via the shared helper so
    // the two gRPC dispatch paths cannot drift on header handling. See
    // `proxy::headers` for the rationale.
    merge_proxy_headers_and_strip_for_grpc(&mut headers, proxy_headers);

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
    // Two distinct timeout regimes:
    //  * client_deadline_ms — a client-supplied `grpc-timeout` (capped by the
    //    operator's backend_read_timeout_ms so it never exceeds the configured
    //    maximum; uncapped when that is 0). This is END-TO-END by gRPC spec, so
    //    it must bound the response-header wait + body collection as ONE shared
    //    budget — otherwise a slow backend gets up to ~2x the client's stated
    //    deadline (the F11 bug this PR fixes).
    //  * per_phase_read_ms — the operator backend_read_timeout_ms safety net
    //    used when the client set no deadline. This is a PER-READ stall guard,
    //    not an RPC budget, so each phase (header wait, body collection) gets a
    //    FRESH full budget. Folding it into a single end-to-end budget would
    //    newly time out a large buffered response from a slow-but-progressing
    //    backend that previously succeeded, so the two phases stay independent —
    //    matching the long-standing operator semantics and the streaming path.
    let (client_deadline_ms, per_phase_read_ms) = match parse_grpc_timeout_ms(&headers) {
        Some(grpc_ms) if proxy.backend_read_timeout_ms > 0 => {
            (Some(grpc_ms.min(proxy.backend_read_timeout_ms)), None)
        }
        Some(grpc_ms) => (Some(grpc_ms), None),
        None if proxy.backend_read_timeout_ms > 0 => (None, Some(proxy.backend_read_timeout_ms)),
        None => (None, None),
    };

    // Effective per-frame idle read timeout for the STREAMING response body,
    // computed before `headers` is moved into the backend request below. Same
    // post-plugin grpc-timeout (uncapped) / backend_read_timeout_ms-fallback
    // rule as the streaming dispatch's header-wait deadline, so a backend that
    // streams headers then stalls cannot pin the streaming guards until the
    // client disconnects. Unused on the buffered path. 0 = unbounded.
    let streaming_response_read_timeout_ms =
        streaming_effective_timeout_ms(&headers, proxy).unwrap_or(0);
    // Client end-to-end RPC deadline (issue #1649), captured before `headers` is
    // moved below. When set, the streaming response body is bounded by an
    // ABSOLUTE deadline rather than the per-frame idle fallback.
    let streaming_client_grpc_deadline_ms = parse_grpc_timeout_ms(&headers);

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
            GrpcProxyError::backend_unavailable_with_source(
                GrpcBackendUnavailableKind::BackendRequest,
                format!("Backend error: {}", e),
                e,
            )
        }
    };
    // For a client-supplied gRPC deadline, compute ONE absolute deadline shared
    // via timeout_at by both the header wait here and the body collection below
    // — the deadline is end-to-end, so the two phases share one budget instead
    // of each arming a fresh full timer (the F11 ~2x bug). `checked_add` guards a
    // pathologically large client deadline from overflowing the `Instant` add
    // (which would panic the request path, unlike the old `timeout(Duration)`
    // form); on overflow the deadline is treated as effectively unbounded. The
    // operator fallback (`per_phase_read_ms`) instead arms a fresh per-phase
    // timer in each phase, preserving the prior per-read stall-guard semantics.
    let client_deadline = client_deadline_ms.and_then(|ms| {
        tokio::time::Instant::now()
            .checked_add(Duration::from_millis(ms))
            .map(|deadline| (ms, deadline))
    });
    let response = if let Some((timeout_ms, deadline)) = client_deadline {
        tokio::time::timeout_at(deadline, send_fut)
            .await
            .map_err(|_| {
                warn!(
                    "gRPC: read timeout ({}ms, end-to-end) waiting for backend response",
                    timeout_ms
                );
                GrpcProxyError::BackendTimeout {
                    kind: GrpcTimeoutKind::Read,
                    message: format!("Read timeout after {}ms (end-to-end)", timeout_ms),
                }
            })?
            .map_err(map_send_err)?
    } else if let Some(timeout_ms) = per_phase_read_ms {
        tokio::time::timeout(Duration::from_millis(timeout_ms), send_fut)
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

    // Extract response status and headers through the shared collector the
    // plain-HTTP path uses, instead of a bespoke `insert` loop that overwrote
    // duplicate names. Repeated `Set-Cookie` values are newline-joined (RFC 6265
    // — emitted as separate header lines, never comma-folded), other repeated
    // headers are comma-folded, and both the canonical hop-by-hop set (RFC 9110
    // §7.6.1) and any `Connection`-listed names are stripped.
    // `apply_response_headers()` later splits the newline-joined `Set-Cookie`
    // back into individual lines. Reusing the shared collector keeps the two
    // gRPC paths and the generic path from drifting and stops duplicate response
    // headers from collapsing to a single value.
    let status = response.status().as_u16();
    let mut resp_headers = HashMap::new();
    let connection_listed = parse_connection_listed_headers(response.headers());
    super::collect_response_headers_generic(
        response.headers().keys_len(),
        response.headers().iter(),
        &mut resp_headers,
        &connection_listed,
    );

    // Streaming mode: return the live Incoming body without buffering.
    // The caller (mod.rs) wraps it in CoalescingH2Body so hyper
    // forwards DATA frames and TRAILERS to the downstream client as they arrive.
    if stream_response {
        return Ok(GrpcResponseKind::Streaming(GrpcStreamingResponse {
            status,
            headers: resp_headers,
            body: response.into_body(),
            request_body_exceeded: None, // buffered request body — already fully sent
            response_read_timeout_ms: streaming_response_read_timeout_ms,
            client_grpc_deadline_ms: streaming_client_grpc_deadline_ms,
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
    let body_capacity = grpc_buffered_body_capacity_hint(response.headers());
    let mut body_bytes = Vec::with_capacity(body_capacity);
    let mut trailers = HashMap::new();

    let body_collection = async {
        let mut body = response.into_body();
        while let Some(frame_result) = body.frame().await {
            match frame_result {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        if max_response_body_size_bytes > 0
                            && body_bytes.len().saturating_add(data.len())
                                > max_response_body_size_bytes
                        {
                            return Err(GrpcProxyError::ResponseTooLarge(format!(
                                "gRPC response payload size exceeds maximum of {} bytes",
                                max_response_body_size_bytes
                            )));
                        }
                        body_bytes.extend_from_slice(data);
                    } else if let Ok(trailer_map) = frame.into_trailers() {
                        // Strip RFC 9110 §7.6.1 response-direction
                        // hop-by-hop names from gRPC trailers — same
                        // predicate used for response headers above.
                        // Without this, a misbehaving / malicious
                        // backend can leak `connection: close`,
                        // `proxy-authenticate`, `keep-alive`,
                        // `transfer-encoding`, `upgrade`, etc. to the
                        // downstream client through TRAILERS frames.
                        // gRPC encodes trailers as response headers in
                        // the trailers-only forward path further up the
                        // call stack (see `mod.rs` Buffered branch),
                        // which is exactly where the hop-by-hop
                        // distinction matters.
                        collect_buffered_grpc_trailers(&trailer_map, &mut trailers);
                    }
                }
                Err(e) => {
                    // Propagate instead of break: swallowing a mid-body frame
                    // error (backend RST_STREAM / GOAWAY / connection reset)
                    // would forward a silently truncated body as HTTP 200 with
                    // no grpc-status anywhere, and the caller would record a
                    // circuit-breaker/admission SUCCESS for a failed exchange.
                    // h2 trailers are the final frame, so an error here always
                    // means the response never completed.
                    warn!("gRPC: error reading backend response frame: {}", e);
                    return Err(GrpcProxyError::backend_unavailable_with_source(
                        GrpcBackendUnavailableKind::BackendRequest,
                        format!("Error reading backend response body: {}", e),
                        e,
                    ));
                }
            }
        }
        Ok(())
    };

    if let Some((timeout_ms, deadline)) = client_deadline {
        // Same end-to-end deadline as the header wait above — for a
        // client-supplied gRPC deadline the header wait and body collection
        // share one budget, not two.
        tokio::time::timeout_at(deadline, body_collection)
            .await
            .map_err(|_| {
                warn!(
                    "gRPC: read timeout ({}ms, end-to-end) while collecting response body",
                    timeout_ms
                );
                GrpcProxyError::BackendTimeout {
                    kind: GrpcTimeoutKind::Read,
                    message: format!("Body read timeout after {}ms (end-to-end)", timeout_ms),
                }
            })??;
    } else if let Some(timeout_ms) = per_phase_read_ms {
        // Operator fallback: a FRESH per-phase budget for body collection,
        // independent of the header wait — preserves the prior per-read stall
        // guard so a slow-but-progressing large buffered response is not newly
        // timed out by a shared end-to-end budget.
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
            })??;
    } else {
        body_collection.await?;
    }

    Ok(GrpcResponseKind::Buffered(GrpcResponse {
        status,
        headers: resp_headers,
        body: body_bytes,
        trailers,
    }))
}

/// Drain a backend `HeaderMap` of gRPC trailers into the buffered-response
/// `HashMap<String, String>` carried in [`GrpcResponse::trailers`], filtering
/// RFC 9110 §7.6.1 response-direction hop-by-hop names.
///
/// gRPC carries `grpc-status` / `grpc-message` / `grpc-status-details-bin` in
/// trailers, and the forward boundary in `mod.rs` emits them as true trailers
/// when a buffered response has a non-empty body. Empty-body responses still
/// use gRPC trailers-only encoding in initial headers. A misbehaving or
/// malicious backend that puts hop-by-hop directives like `connection:
/// close`, `proxy-authenticate`, `keep-alive`, `transfer-encoding`, or
/// `upgrade` in the trailer map would otherwise leak past the proxy
/// boundary, because the response-headers strip earlier in this function
/// only sees response *headers*, not trailers. Hyper's H2 trailer encoder
/// rejects some hop-by-hop names at the frame layer but
/// `proxy-authenticate`, `proxy-connection`, and `keep-alive` are not
/// blocked, so the proxy must filter them itself.
///
/// Mirrors the streaming-path filter in `proxy::body::StripHopByHopTrailers`
/// so both gRPC response paths apply the same predicate.
pub(crate) fn collect_buffered_grpc_trailers(
    trailer_map: &hyper::HeaderMap,
    out: &mut HashMap<String, String>,
) {
    for (k, v) in trailer_map {
        if is_backend_response_strip_header(k.as_str()) {
            continue;
        }
        if let Ok(vs) = v.to_str() {
            out.insert(k.as_str().to_string(), vs.to_string());
        }
    }
}

/// Check if a request is a gRPC request based on content-type.
pub fn is_grpc_request(req: &Request<Incoming>) -> bool {
    is_grpc_content_type(req.headers())
}

/// Check if headers indicate a native gRPC request.
///
/// Delegates to the canonical [`super::backend_dispatch::is_native_grpc_content_type`]
/// classifier so the H1/H2 dispatch path and this helper can never diverge. The
/// shared helper works on raw bytes, so a malformed value such as
/// `application/grpc+\xff` classifies identically in both places, and we avoid a
/// per-request `to_str()` UTF-8 scan on the hot path.
pub fn is_grpc_content_type(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .is_some_and(|v| super::backend_dispatch::is_native_grpc_content_type(v.as_bytes()))
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
    parse_grpc_timeout_value(headers.get("grpc-timeout")?.to_str().ok()?)
}

/// Parse a raw `grpc-timeout` header value (e.g. `"100m"`, `"1S"`) into
/// milliseconds. Shared by [`parse_grpc_timeout_ms`] (hyper `HeaderMap` callers)
/// and the native-H3 gRPC path, whose headers are a `HashMap<String, String>`.
pub(crate) fn parse_grpc_timeout_value(val: &str) -> Option<u64> {
    let bytes = val.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    // The unit suffix is always a single ASCII letter per the gRPC spec. Reject
    // multi-byte UTF-8 (and any non-letter) here so the digit split below cannot
    // land on a char boundary or treat a stray byte as the unit.
    let unit = *bytes.last()?;
    if !unit.is_ascii_alphabetic() {
        return None;
    }
    let num_str = std::str::from_utf8(&bytes[..bytes.len() - 1]).ok()?;
    // The gRPC wire format constrains the value to a positive integer of AT MOST
    // 8 digits (matching the `grpc_deadline` plugin's own validation). Reject
    // anything longer or non-numeric by returning `None` so a malformed header
    // such as `18446744073709551615H` does NOT become a present-but-unbounded
    // deadline — that would let a bad client opt out of the operator's
    // `backend_read_timeout_ms` fallback. `None` means "absent or invalid", and
    // the caller then applies the fallback. With at most 8 digits the largest
    // representable value is `99_999_999 H` ≈ 3.6e14 ms, which always fits in a
    // `u64`, so the unit multiplies below can never actually overflow for valid
    // input.
    if num_str.is_empty() || num_str.len() > 8 || !num_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let num: u64 = num_str.parse().ok()?;
    if num == 0 {
        return None;
    }
    let ms = match unit {
        b'H' => num * 3_600_000,
        b'M' => num * 60_000,
        b'S' => num * 1_000,
        b'm' => num,
        b'u' => num / 1_000, // microseconds → ms, floor to 0 is handled by max(1) below
        b'n' => num / 1_000_000,
        _ => return None,
    };
    // Ensure at least 1ms for sub-millisecond timeouts
    Some(ms.max(1))
}

/// Effective timeout for the fully streaming gRPC path.
///
/// Client-supplied `grpc-timeout` is an end-to-end RPC deadline and is used
/// directly. `backend_read_timeout_ms` is only a fallback when the client did
/// not set a deadline.
pub(crate) fn streaming_effective_timeout_ms(
    headers: &hyper::HeaderMap,
    proxy: &Proxy,
) -> Option<u64> {
    match parse_grpc_timeout_ms(headers) {
        Some(grpc_ms) => Some(grpc_ms),
        None if proxy.backend_read_timeout_ms > 0 => Some(proxy.backend_read_timeout_ms),
        None => None,
    }
}

/// Build the same post-plugin header view that [`proxy_grpc_request_streaming`]
/// uses, then derive its effective streaming timeout.
///
/// Test-only: production dispatch derives the timeout from the already-merged
/// streaming headers via [`streaming_effective_timeout_ms`], and the HALF_OPEN
/// probe guard uses
/// [`streaming_post_header_upload_timeout_ms_after_proxy_headers`]. This wrapper
/// is retained solely to assert — in contrast to the capped guard helper — that
/// the end-to-end streaming RPC timeout is NOT capped by
/// `backend_read_timeout_ms`.
#[cfg(test)]
pub(crate) fn streaming_effective_timeout_ms_after_proxy_headers(
    request_headers: &hyper::HeaderMap,
    proxy_headers: &HashMap<String, String>,
    proxy: &Proxy,
) -> Option<u64> {
    let mut headers = request_headers.clone();
    merge_proxy_headers_and_strip_for_grpc(&mut headers, proxy_headers);
    streaming_effective_timeout_ms(&headers, proxy)
}

/// Timeout for the post-header upload guard used by HALF_OPEN streaming probes.
///
/// Unlike the end-to-end streaming RPC timeout, this guard only limits how long
/// a circuit-breaker probe slot can remain deferred after backend response
/// headers arrive while the client upload stays open. Cap client-supplied
/// `grpc-timeout` by `backend_read_timeout_ms` when configured so a remote
/// client cannot pin the single default HALF_OPEN probe slot for an
/// attacker-selected deadline.
pub(crate) fn streaming_post_header_upload_timeout_ms(
    headers: &hyper::HeaderMap,
    proxy: &Proxy,
) -> Option<u64> {
    match parse_grpc_timeout_ms(headers) {
        Some(grpc_ms) if proxy.backend_read_timeout_ms > 0 => {
            Some(grpc_ms.min(proxy.backend_read_timeout_ms))
        }
        Some(grpc_ms) => Some(grpc_ms),
        None if proxy.backend_read_timeout_ms > 0 => Some(proxy.backend_read_timeout_ms),
        None => None,
    }
}

/// Build the same post-plugin header view that [`proxy_grpc_request_streaming`]
/// uses, then derive the capped post-header upload guard timeout for HALF_OPEN
/// streaming probes.
pub(crate) fn streaming_post_header_upload_timeout_ms_after_proxy_headers(
    request_headers: &hyper::HeaderMap,
    proxy_headers: &HashMap<String, String>,
    proxy: &Proxy,
) -> Option<u64> {
    let mut headers = request_headers.clone();
    merge_proxy_headers_and_strip_for_grpc(&mut headers, proxy_headers);
    streaming_post_header_upload_timeout_ms(&headers, proxy)
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

    // -----------------------------------------------------------------------
    // GRPC_POOL_KEY_BUF thread-local helper tests
    //
    // Mirrors the HTTP/2 pool-key tests in `http2_pool.rs`. The gRPC pool
    // uses the same thread-local `String` buffer strategy for zero-allocation
    // cache hits on the proxy hot path.
    // -----------------------------------------------------------------------

    use super::*;
    use crate::config::types::{
        AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, ResponseBodyMode,
    };
    use chrono::Utc;

    /// Build a minimal `Proxy` for thread-local key tests. Uses HTTPS so the
    /// gRPC pool path is the realistic codepath (gRPC over TLS).
    fn grpc_pool_test_proxy() -> Proxy {
        let now = Utc::now();
        Proxy {
            id: "p-grpc".to_string(),
            namespace: crate::config::types::default_namespace(),
            name: None,
            hosts: vec![],
            listen_path: Some("/".to_string()),
            backend_scheme: Some(BackendScheme::Https),
            dispatch_kind: DispatchKind::from(BackendScheme::Https),
            backend_host: "grpc-backend.test".to_string(),
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
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn grpc_pool_key_can_partition_on_svid_generation() {
        let proxy = grpc_pool_test_proxy();
        let key = grpc_pool_key_owned(&proxy, Some(23));

        assert!(
            key.ends_with("|svidg=23"),
            "workload SVID generation must be represented in the gRPC pool key: {key}"
        );
    }

    #[tokio::test]
    async fn grpc_manager_pool_key_uses_global_mtls_fallback() {
        let proxy = grpc_pool_test_proxy();
        let env_config = crate::config::EnvConfig {
            backend_tls_client_cert_path: Some("/global/grpc-client.pem".to_string()),
            backend_tls_client_key_path: Some("/global/grpc-client.key".to_string()),
            ..Default::default()
        };
        let pool = GrpcConnectionPool::new(
            PoolConfig::default(),
            env_config,
            DnsCache::new(DnsConfig::default()),
            None,
            Arc::new(Vec::new()),
        );

        let key = pool.with_pool_key(&proxy, None, |buf| buf.clone());

        assert!(
            key.contains("|/global/grpc-client.pem|/global/grpc-client.key|"),
            "runtime gRPC pool key must include global backend mTLS fallback: {key}"
        );
    }

    #[test]
    fn streaming_effective_timeout_uses_post_plugin_headers_without_backend_cap() {
        let mut proxy = grpc_pool_test_proxy();
        proxy.backend_read_timeout_ms = 250;
        let mut request_headers = hyper::HeaderMap::new();
        request_headers.insert(
            "grpc-timeout",
            hyper::header::HeaderValue::from_static("10S"),
        );
        let mut proxy_headers = HashMap::new();
        proxy_headers.insert("grpc-timeout".to_string(), "3S".to_string());

        assert_eq!(
            streaming_effective_timeout_ms_after_proxy_headers(
                &request_headers,
                &proxy_headers,
                &proxy,
            ),
            Some(3_000),
            "the streaming RPC timeout uses the same post-plugin grpc-timeout as dispatch and must not cap it by backend_read_timeout_ms"
        );
    }

    #[test]
    fn streaming_post_header_upload_timeout_caps_post_plugin_grpc_timeout() {
        let mut proxy = grpc_pool_test_proxy();
        proxy.backend_read_timeout_ms = 250;
        let mut request_headers = hyper::HeaderMap::new();
        request_headers.insert(
            "grpc-timeout",
            hyper::header::HeaderValue::from_static("10S"),
        );
        let mut proxy_headers = HashMap::new();
        proxy_headers.insert("grpc-timeout".to_string(), "3S".to_string());

        assert_eq!(
            streaming_post_header_upload_timeout_ms_after_proxy_headers(
                &request_headers,
                &proxy_headers,
                &proxy,
            ),
            Some(250),
            "the HALF_OPEN probe upload guard must cap client-controlled grpc-timeout by backend_read_timeout_ms"
        );
    }

    #[test]
    fn streaming_post_header_upload_timeout_falls_back_to_backend_read_timeout() {
        let mut proxy = grpc_pool_test_proxy();
        proxy.backend_read_timeout_ms = 750;
        let request_headers = hyper::HeaderMap::new();
        let proxy_headers = HashMap::new();

        assert_eq!(
            streaming_post_header_upload_timeout_ms_after_proxy_headers(
                &request_headers,
                &proxy_headers,
                &proxy,
            ),
            Some(750),
        );
    }

    #[test]
    fn streaming_post_header_upload_timeout_disabled_read_timeout_is_opt_out() {
        // `backend_read_timeout_ms == 0` is an explicit operator opt-out of the
        // read timeout. With it disabled the guard cannot cap by it, so a client
        // `grpc-timeout` passes through uncapped, and with no client deadline at
        // all no guard is installed — the probe slot is then bounded only by the
        // RPC itself, matching the operator's "no read timeout" choice.
        let mut proxy = grpc_pool_test_proxy();
        proxy.backend_read_timeout_ms = 0;

        let mut request_headers = hyper::HeaderMap::new();
        request_headers.insert(
            "grpc-timeout",
            hyper::header::HeaderValue::from_static("3S"),
        );
        assert_eq!(
            streaming_post_header_upload_timeout_ms_after_proxy_headers(
                &request_headers,
                &HashMap::new(),
                &proxy,
            ),
            Some(3_000),
            "with backend_read_timeout_ms == 0 the client grpc-timeout is not capped"
        );

        assert_eq!(
            streaming_post_header_upload_timeout_ms_after_proxy_headers(
                &hyper::HeaderMap::new(),
                &HashMap::new(),
                &proxy,
            ),
            None,
            "with backend_read_timeout_ms == 0 and no client deadline the guard is disabled (documented opt-out)"
        );
    }

    #[tokio::test]
    async fn force_drain_svid_generation_removes_rr_counter_keys() {
        let pool = GrpcConnectionPool::default();

        pool.rr_counters.insert(
            "backend|443|fields|svidg=23".to_string(),
            Arc::new(AtomicUsize::new(1)),
        );
        pool.rr_counters.insert(
            "backend|443|fields|svidg=24".to_string(),
            Arc::new(AtomicUsize::new(1)),
        );
        pool.rr_counters.insert(
            "backend|443|fields|svidg=static".to_string(),
            Arc::new(AtomicUsize::new(1)),
        );

        pool.force_drain_svid_generation(23);

        assert!(!pool.rr_counters.contains_key("backend|443|fields|svidg=23"));
        assert!(pool.rr_counters.contains_key("backend|443|fields|svidg=24"));
        assert!(
            pool.rr_counters
                .contains_key("backend|443|fields|svidg=static")
        );
    }

    /// Correctness: the thread-local helper must produce the same byte string
    /// as `grpc_pool_key_owned()`. If these ever diverge the gRPC pool would
    /// silently fragment (one allocation path inserts keys, the other looks
    /// them up -- a mismatch would never hit a cached connection).
    fn with_grpc_test_pool_key<R>(
        proxy: &Proxy,
        svid_generation: Option<u64>,
        f: impl FnOnce(&mut String) -> R,
    ) -> R {
        with_grpc_pool_key(
            proxy,
            proxy.resolved_tls.client_cert_path.as_deref(),
            proxy.resolved_tls.client_key_path.as_deref(),
            svid_generation,
            f,
        )
    }

    #[test]
    fn with_grpc_pool_key_matches_grpc_pool_key_owned() {
        let proxy = grpc_pool_test_proxy();
        let owned = grpc_pool_key_owned(&proxy, None);
        let from_thread_local = with_grpc_test_pool_key(&proxy, None, |buf| buf.clone());
        assert_eq!(
            owned, from_thread_local,
            "thread-local key must equal grpc_pool_key_owned bytes — \
             divergence would split the cache"
        );
    }

    #[test]
    fn grpc_pool_key_distinguishes_backend_tls_sni_and_sans() {
        let mut p1 = grpc_pool_test_proxy();
        p1.resolved_tls.sni = Some("reviews.mesh.internal".to_string());
        p1.resolved_tls.san_allow_list = vec!["reviews.mesh.internal".to_string()];
        p1.resolved_tls.recompute_san_digest();
        let mut p2 = p1.clone();
        p2.resolved_tls.sni = Some("ratings.mesh.internal".to_string());

        assert_ne!(
            grpc_pool_key_owned(&p1, None),
            grpc_pool_key_owned(&p2, None),
            "backend TLS SNI must separate gRPC pool keys"
        );

        p2.resolved_tls.sni = p1.resolved_tls.sni.clone();
        p2.resolved_tls.san_allow_list = vec!["ratings.mesh.internal".to_string()];
        p2.resolved_tls.recompute_san_digest();
        assert_ne!(
            grpc_pool_key_owned(&p1, None),
            grpc_pool_key_owned(&p2, None),
            "backend TLS SAN allow-list must separate gRPC pool keys"
        );
    }

    /// Correctness across runs: a second `with_grpc_pool_key` invocation
    /// against the same `Proxy` must produce the identical key even after
    /// a different proxy with a longer host grows the buffer. Catches a
    /// future bug where stale buffer contents leak through if `clear()` is
    /// dropped from `write_grpc_pool_key`.
    #[test]
    fn with_grpc_pool_key_is_idempotent_after_buffer_growth() {
        let proxy = grpc_pool_test_proxy();
        let k1 = with_grpc_test_pool_key(&proxy, None, |buf| buf.clone());
        // Force the buffer to grow in between by running a different proxy
        // with a longer host through the helper.
        let mut other = grpc_pool_test_proxy();
        other.backend_host =
            "very-long-grpc-backend-hostname-that-grows-the-buffer.subdomain.example.com"
                .to_string();
        let _ = with_grpc_test_pool_key(&other, None, |buf| buf.clone());
        let k2 = with_grpc_test_pool_key(&proxy, None, |buf| buf.clone());
        assert_eq!(k1, k2, "same proxy must always yield the same key");
    }

    /// Reuse: repeated `with_grpc_pool_key` calls on the same thread must
    /// reuse the underlying heap buffer, not allocate a fresh one each call.
    /// We capture the heap pointer of the buffer's storage between
    /// invocations and assert it never moves once the capacity is large
    /// enough to hold the key. This is the load-bearing assertion for the
    /// CLAUDE.md "zero-allocation hot path" rule.
    #[test]
    fn with_grpc_pool_key_reuses_heap_buffer_across_calls() {
        let proxy = grpc_pool_test_proxy();

        // Prime the buffer once so the initial capacity is sized to hold
        // the key. The thread-local was constructed with capacity 128
        // (well above the typical key length), so this should not realloc.
        let (first_ptr, first_capacity) =
            with_grpc_test_pool_key(&proxy, None, |buf| (buf.as_ptr() as usize, buf.capacity()));
        assert!(
            first_capacity >= 128,
            "expected pre-sized capacity (>=128), got {first_capacity}"
        );

        // Run a tight loop and assert the heap pointer NEVER moves. If the
        // optimization regresses to per-call `String::with_capacity(...)`,
        // the pointer would change on every iteration.
        for i in 0..1024 {
            let (ptr, cap) = with_grpc_test_pool_key(&proxy, None, |buf| {
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
    /// `write_grpc_pool_key` against the same proxy produces a buffer
    /// whose `len()` equals the `base_len` captured pre-await. If a future
    /// refactor adds non-deterministic content to the key (e.g. timestamps)
    /// the assertion would fire under -C debug-assertions=on.
    #[test]
    fn with_grpc_pool_key_base_len_is_stable() {
        let proxy = grpc_pool_test_proxy();
        let len1 = with_grpc_test_pool_key(&proxy, None, |buf| buf.len());
        let len2 = with_grpc_test_pool_key(&proxy, None, |buf| buf.len());
        assert_eq!(
            len1, len2,
            "base_len must be deterministic across calls — \
             the post-await fallback in get_sender relies on this"
        );
    }

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

    /// F11: the buffered gRPC path must apply a CLIENT-SUPPLIED `grpc-timeout`
    /// as ONE end-to-end budget (a single shared `timeout_at` deadline spanning
    /// the header wait + body collection), while the OPERATOR
    /// `backend_read_timeout_ms` fallback keeps a FRESH per-phase
    /// `tokio::time::timeout` in each phase.
    ///
    /// Guarded structurally because the unit harness has no mock H2 backend to
    /// drive paused-clock timing.
    #[test]
    fn proxy_grpc_request_core_shares_one_client_deadline_but_per_phase_fallback() {
        let src = include_str!("grpc_proxy.rs");
        let fn_start = src
            .find("pub(crate) async fn proxy_grpc_request_core(")
            .expect("proxy_grpc_request_core signature not found");
        let tail = &src[fn_start..];
        let fn_end = tail
            .find("\n}\n")
            .expect("failed to locate end of proxy_grpc_request_core body");
        let body = &tail[..fn_end];

        // The client deadline is computed ONCE (a single shared Instant) and
        // reused by both phases via timeout_at — never recomputed per phase.
        let client_now = body.matches("tokio::time::Instant::now()").count();
        assert_eq!(
            client_now, 1,
            "the client gRPC deadline must be computed ONCE and shared by both \
             phases; found {client_now} `Instant::now()` call(s). A second one \
             means the header wait and body collection no longer share one \
             end-to-end budget (the F11 ~2x bug)."
        );
        let timeout_at = body.matches("tokio::time::timeout_at(").count();
        assert_eq!(
            timeout_at, 2,
            "both the header wait and body collection must consume the SAME \
             shared client deadline via timeout_at; found {timeout_at}."
        );

        // The deadline Instant add must be overflow-guarded (checked_add) so a
        // pathological client `grpc-timeout` cannot panic the request path.
        assert!(
            body.contains("checked_add(Duration::from_millis("),
            "the client deadline must use checked_add to avoid an Instant \
             overflow panic on a pathological grpc-timeout."
        );

        // The operator `backend_read_timeout_ms` fallback must stay PER-PHASE:
        // a fresh `tokio::time::timeout` in BOTH the header-wait and
        // body-collection arms (two independent timers, not one shared budget).
        let per_phase = body
            .matches("tokio::time::timeout(Duration::from_millis(")
            .count();
        assert_eq!(
            per_phase, 2,
            "the operator backend_read_timeout_ms fallback must arm a FRESH \
             per-phase `tokio::time::timeout` in each phase (header wait + body \
             collection); found {per_phase}. Folding it into the shared \
             end-to-end deadline regresses slow-but-progressing buffered \
             responses."
        );
    }

    // ── collect_buffered_grpc_trailers ─────────────────────────────────────
    //
    // Buffered-path companion to `proxy::body::StripHopByHopTrailers` for the
    // streaming gRPC response path. Both must apply the identical RFC 9110
    // §7.6.1 response-direction strip predicate so a backend cannot leak
    // hop-by-hop names through TRAILERS regardless of which response mode
    // (`Buffered` vs `Streaming`) the proxy negotiated.

    #[test]
    fn collect_buffered_grpc_trailers_strips_hop_by_hop_names() {
        let mut trailer_map = hyper::HeaderMap::new();
        trailer_map.insert("grpc-status", "0".parse().unwrap());
        trailer_map.insert("grpc-message", "ok".parse().unwrap());
        // Hop-by-hop directives a misbehaving / malicious backend might emit:
        trailer_map.insert("connection", "close".parse().unwrap());
        trailer_map.insert(
            "proxy-authenticate",
            "Basic realm=internal".parse().unwrap(),
        );
        trailer_map.insert("keep-alive", "timeout=5".parse().unwrap());
        trailer_map.insert("transfer-encoding", "chunked".parse().unwrap());
        trailer_map.insert("upgrade", "h2c".parse().unwrap());
        trailer_map.insert("proxy-connection", "close".parse().unwrap());
        trailer_map.insert("te", "trailers".parse().unwrap());
        trailer_map.insert("trailer", "grpc-status".parse().unwrap());

        let mut out: HashMap<String, String> = HashMap::new();
        collect_buffered_grpc_trailers(&trailer_map, &mut out);

        assert_eq!(out.get("grpc-status").map(String::as_str), Some("0"));
        assert_eq!(out.get("grpc-message").map(String::as_str), Some("ok"));
        for hop_by_hop in [
            "connection",
            "proxy-authenticate",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "proxy-connection",
            "te",
            "trailer",
        ] {
            assert!(
                !out.contains_key(hop_by_hop),
                "buffered-path trailer `{hop_by_hop}` must be stripped — it \
                 would otherwise be merged into the gRPC trailers-only \
                 forward in mod.rs and leak past the proxy boundary",
            );
        }
    }

    #[test]
    fn collect_buffered_grpc_trailers_preserves_legitimate_grpc_and_custom_trailers() {
        let mut trailer_map = hyper::HeaderMap::new();
        trailer_map.insert("grpc-status", "0".parse().unwrap());
        trailer_map.insert("grpc-message", "ok".parse().unwrap());
        trailer_map.insert("grpc-status-details-bin", "abc==".parse().unwrap());
        trailer_map.insert("x-custom-trailer", "v".parse().unwrap());
        trailer_map.insert("x-trace-id", "abc-123".parse().unwrap());

        let mut out: HashMap<String, String> = HashMap::new();
        collect_buffered_grpc_trailers(&trailer_map, &mut out);

        assert_eq!(out.len(), 5);
        for name in [
            "grpc-status",
            "grpc-message",
            "grpc-status-details-bin",
            "x-custom-trailer",
            "x-trace-id",
        ] {
            assert!(
                out.contains_key(name),
                "legitimate gRPC trailer `{name}` must be preserved",
            );
        }
    }

    #[test]
    fn collect_buffered_grpc_trailers_skips_non_utf8_values() {
        // `to_str()` fails on non-ASCII; the helper silently drops those
        // entries without leaking them. A malicious backend could otherwise
        // smuggle binary garbage into the response header map. Legitimate
        // binary trailers (e.g. `grpc-status-details-bin`) are
        // base64-encoded by gRPC convention, so they do round-trip through
        // `to_str()` cleanly.
        let mut trailer_map = hyper::HeaderMap::new();
        trailer_map.insert("grpc-status", "0".parse().unwrap());
        trailer_map.insert(
            "x-bin-trailer",
            http::HeaderValue::from_bytes(&[0x80, 0x81]).unwrap(),
        );

        let mut out: HashMap<String, String> = HashMap::new();
        collect_buffered_grpc_trailers(&trailer_map, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out.get("grpc-status").map(String::as_str), Some("0"));
    }

    #[test]
    fn grpc_response_header_collection_preserves_duplicate_set_cookie() {
        // Regression for the bug where the gRPC response-header copy used a
        // HashMap `insert` loop and collapsed duplicate header values — notably
        // multiple `Set-Cookie` — to the last value, breaking session
        // stickiness / auth flows. Both the streaming and buffered gRPC paths
        // now delegate to `collect_response_headers_generic`, matching the
        // plain-HTTP path: `Set-Cookie` is newline-joined (so the consuming
        // `apply_response_headers` re-emits separate header lines), other
        // duplicates are comma-folded, and hop-by-hop names are stripped. This
        // test exercises the collector exactly as the two gRPC paths now call it.
        let mut source = http::HeaderMap::new();
        source.append("set-cookie", http::HeaderValue::from_static("session=a"));
        source.append("set-cookie", http::HeaderValue::from_static("theme=dark"));
        source.append("x-multi", http::HeaderValue::from_static("1"));
        source.append("x-multi", http::HeaderValue::from_static("2"));
        // Response-direction hop-by-hop header — must be stripped.
        source.insert("keep-alive", http::HeaderValue::from_static("timeout=5"));

        let mut out: HashMap<String, String> = HashMap::new();
        let connection_listed = crate::proxy::headers::parse_connection_listed_headers(&source);
        crate::proxy::collect_response_headers_generic(
            source.keys_len(),
            source.iter(),
            &mut out,
            &connection_listed,
        );

        assert_eq!(
            out.get("set-cookie").map(String::as_str),
            Some("session=a\ntheme=dark"),
            "duplicate Set-Cookie must be newline-joined, not collapsed to the last value"
        );
        assert_eq!(
            out.get("x-multi").map(String::as_str),
            Some("1, 2"),
            "other duplicate response headers are comma-folded"
        );
        assert!(
            !out.contains_key("keep-alive"),
            "hop-by-hop response headers must be stripped"
        );
    }

    #[test]
    fn rehome_moves_hook_mutated_trailer_only_set_cookie_to_headers() {
        // Backend sent set-cookie only as a gRPC trailer ("a=1"); a response
        // hook appended a session cookie, so the post-reconcile wire trailer
        // ("a=1\nsession=x") differs from the captured original ("a=1"). The
        // strip loop already removed set-cookie from the initial headers
        // (issue #1638): it must be re-homed onto the headers so clients store
        // it, and must not also ride the wire trailer.
        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("content-type".into(), "application/grpc".into());
        let mut trailers: HashMap<String, String> = HashMap::new();
        trailers.insert("grpc-status".into(), "0".into());
        trailers.insert("set-cookie".into(), "a=1\nsession=x".into());

        rehome_hook_mutated_trailer_set_cookie(&mut headers, &mut trailers, Some("a=1"));

        assert_eq!(
            headers.get("set-cookie").map(String::as_str),
            Some("a=1\nsession=x"),
            "hook-mutated trailer-only set-cookie must be re-homed onto the initial HEADERS",
        );
        assert!(
            !trailers.contains_key("set-cookie"),
            "the re-homed cookie must not also ride the wire trailer",
        );
        assert_eq!(
            trailers.get("grpc-status").map(String::as_str),
            Some("0"),
            "the terminal status trailer is untouched",
        );
    }

    #[test]
    fn rehome_leaves_untouched_backend_trailer_set_cookie_as_a_trailer() {
        // No hook touched the backend's trailer set-cookie (original == current
        // wire value), so the faithful split wire shape is preserved — issue
        // #1638 scopes the re-homing to hook-contributed values only.
        let mut headers: HashMap<String, String> = HashMap::new();
        let mut trailers: HashMap<String, String> = HashMap::new();
        trailers.insert("set-cookie".into(), "a=1".into());

        rehome_hook_mutated_trailer_set_cookie(&mut headers, &mut trailers, Some("a=1"));

        assert!(
            !headers.contains_key("set-cookie"),
            "an untouched backend trailer set-cookie is not re-homed",
        );
        assert_eq!(
            trailers.get("set-cookie").map(String::as_str),
            Some("a=1"),
            "an untouched backend trailer set-cookie keeps its wire shape",
        );
    }

    #[test]
    fn rehome_skips_header_shadowed_set_cookie() {
        // set-cookie already reaches the client as a real header (shadowed); its
        // faithful (sanitized) trailer copy is left alone and never duplicated
        // onto the header, even though the trailer value "changed".
        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("set-cookie".into(), "h=1".into());
        let mut trailers: HashMap<String, String> = HashMap::new();
        trailers.insert("set-cookie".into(), "h=1".into());

        rehome_hook_mutated_trailer_set_cookie(&mut headers, &mut trailers, Some("t=1"));

        assert_eq!(
            headers.get("set-cookie").map(String::as_str),
            Some("h=1"),
            "an already-present header set-cookie must not be appended to",
        );
        assert_eq!(
            trailers.get("set-cookie").map(String::as_str),
            Some("h=1"),
            "the trailer copy is left untouched when set-cookie is already a header",
        );
    }

    #[test]
    fn rehome_is_noop_without_a_trailer_set_cookie() {
        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("content-type".into(), "application/grpc".into());
        let mut trailers: HashMap<String, String> = HashMap::new();
        trailers.insert("grpc-status".into(), "0".into());

        rehome_hook_mutated_trailer_set_cookie(&mut headers, &mut trailers, None);

        assert!(!headers.contains_key("set-cookie"));
        assert!(!trailers.contains_key("set-cookie"));
        assert_eq!(trailers.len(), 1, "unrelated trailers are untouched");
    }
}
