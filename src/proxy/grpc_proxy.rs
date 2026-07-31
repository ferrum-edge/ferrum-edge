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
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, error, warn};

use crate::config::PoolConfig;
use crate::config::types::{BackendScheme, Proxy};
use crate::dns::{DnsCache, DnsConfig};
use crate::plugins::{BufferedInitialResponseHeaderPolicyState, Plugin};
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

/// Observes the first server frame without interfering with hyper's parser.
/// HTTP/2 requires a structurally valid initial SETTINGS frame, so completing
/// one and giving Hyper a final validation poll proves the peer preface even
/// when MAX_CONCURRENT_STREAMS is zero.
struct H2cSettingsIo {
    inner: TcpStream,
    settings_received: Arc<AtomicBool>,
    first_frame_header: [u8; 9],
    header_len: usize,
    frame_remaining: Option<usize>,
}

impl H2cSettingsIo {
    fn new(inner: TcpStream, settings_received: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            settings_received,
            first_frame_header: [0; 9],
            header_len: 0,
            frame_remaining: None,
        }
    }

    fn observe(&mut self, mut bytes: &[u8]) {
        if self.settings_received.load(Ordering::Relaxed) {
            return;
        }
        if self.header_len < self.first_frame_header.len() {
            let copied = bytes
                .len()
                .min(self.first_frame_header.len() - self.header_len);
            self.first_frame_header[self.header_len..self.header_len + copied]
                .copy_from_slice(&bytes[..copied]);
            self.header_len += copied;
            bytes = &bytes[copied..];
            if self.header_len == self.first_frame_header.len() {
                let payload_len = (usize::from(self.first_frame_header[0]) << 16)
                    | (usize::from(self.first_frame_header[1]) << 8)
                    | usize::from(self.first_frame_header[2]);
                self.frame_remaining = Some(payload_len);
            }
        }
        if let Some(remaining) = self.frame_remaining.as_mut() {
            *remaining = remaining.saturating_sub(bytes.len());
            if *remaining == 0 && self.initial_settings_header_is_well_formed() {
                self.settings_received.store(true, Ordering::Release);
            }
        }
    }

    /// Validate the peer's initial SETTINGS frame header before treating the
    /// raw frame as establishment proof. Hyper remains the authoritative frame
    /// parser; these checks prevent a complete but obviously invalid SETTINGS
    /// frame from winning the readiness race before Hyper surfaces its protocol
    /// error.
    fn initial_settings_header_is_well_formed(&self) -> bool {
        const DEFAULT_MAX_FRAME_SIZE: usize = 16_384;

        let payload_len = (usize::from(self.first_frame_header[0]) << 16)
            | (usize::from(self.first_frame_header[1]) << 8)
            | usize::from(self.first_frame_header[2]);
        let stream_id = u32::from_be_bytes([
            self.first_frame_header[5],
            self.first_frame_header[6],
            self.first_frame_header[7],
            self.first_frame_header[8],
        ]) & 0x7fff_ffff;

        self.first_frame_header[3] == 0x4
            && self.first_frame_header[4] & 0x1 == 0
            && stream_id == 0
            && payload_len <= DEFAULT_MAX_FRAME_SIZE
            && payload_len % 6 == 0
    }
}

impl AsyncRead for H2cSettingsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled_before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                self.observe(&buf.filled()[filled_before..]);
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl AsyncWrite for H2cSettingsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Canonical terminal message for a gateway-owned client RPC deadline.
///
/// Response builders and the terminal-response ownership guard must share this
/// exact value; otherwise a wording change could let a later response replacer
/// overwrite `DEADLINE_EXCEEDED` after the gateway has selected it.
pub(crate) const GATEWAY_DEADLINE_EXCEEDED_MESSAGE: &str = "Deadline exceeded at gateway";
/// Canonical percent-encoded `grpc-message` header representation.
pub(crate) const GATEWAY_DEADLINE_EXCEEDED_MESSAGE_HEADER: &str =
    "Deadline%20exceeded%20at%20gateway";
/// Canonical serialized `grpc-status` paired with the gateway message above.
pub(crate) const GATEWAY_DEADLINE_EXCEEDED_STATUS_HEADER: &str = "4";

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
    /// Complete body in memory that terminates with an HTTP/2 TRAILERS frame.
    ///
    /// `Full<Bytes>` cannot emit a terminal trailers frame, so a request whose
    /// end-of-stream metadata arrived out-of-band — today, a gRPC-Web client
    /// that encoded its trailers as a `0x80` body frame the `grpc_web` plugin
    /// split off — uses this variant instead. The DATA is emitted first and the
    /// trailers exactly once, so the backend observes the native gRPC request
    /// representation rather than a body with framing bytes appended to it.
    BufferedWithTrailers {
        data: Option<Bytes>,
        trailers: Option<hyper::HeaderMap>,
    },
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
    /// Streaming body sourced from a channel rather than a hyper `Incoming`.
    ///
    /// Used by the HTTP/3 cross-protocol gRPC bridge: H3's
    /// `h3::server::RequestStream` cannot be expressed as a hyper `Incoming`,
    /// so a pump task reads `RequestStream::recv_data()` and pushes `Bytes`
    /// chunks — or `Err(())` on a frontend upload failure (so a truncated
    /// upload becomes a backend RST rather than a clean END_STREAM the backend
    /// would mistake for a completed stream) — into the bounded sender. This
    /// body polls the receiver. Inline size enforcement (`bytes_seen` /
    /// `max_bytes` / `exceeded`) and the upload observer match `Streaming`
    /// exactly; only the source differs. The same `Pin<&mut Self>` exclusivity
    /// argument as `Streaming` makes the plain `usize` counter safe.
    Channel {
        receiver: tokio::sync::mpsc::Receiver<Result<Bytes, ()>>,
        bytes_seen: usize,
        max_bytes: usize,
        exceeded: Arc<AtomicBool>,
        /// Fired from `Drop` when this request body terminates — same contract
        /// as [`GrpcBody::Streaming::upload_observer`]. `None` for the H3
        /// bridge, which records the circuit-breaker outcome at response time.
        upload_observer: Option<Arc<dyn GrpcUploadTerminationObserver>>,
    },
}

impl Drop for GrpcBody {
    fn drop(&mut self) {
        // Notify the upload-termination observer when the streaming request
        // body is dropped. hyper drops it once the upload finishes (END_STREAM)
        // or the stream is reset, so this is the canonical "request upload
        // terminated" signal — independent of the response body's lifetime.
        let upload_observer = match self {
            GrpcBody::Streaming {
                upload_observer, ..
            }
            | GrpcBody::Channel {
                upload_observer, ..
            } => upload_observer.as_ref(),
            GrpcBody::Buffered(_) | GrpcBody::BufferedWithTrailers { .. } => None,
        };
        if let Some(observer) = upload_observer {
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
            GrpcBody::BufferedWithTrailers { data, trailers } => {
                // Skip an empty DATA frame so hyper does not emit a zero-length
                // frame before the trailers block.
                if let Some(bytes) = data.take()
                    && !bytes.is_empty()
                {
                    return Poll::Ready(Some(Ok(Frame::data(bytes))));
                }
                match trailers.take() {
                    Some(trailers) => Poll::Ready(Some(Ok(Frame::trailers(trailers)))),
                    None => Poll::Ready(None),
                }
            }
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
            GrpcBody::Channel {
                receiver,
                bytes_seen,
                max_bytes,
                exceeded,
                ..
            } => match receiver.poll_recv(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    if *max_bytes > 0 {
                        *bytes_seen += data.len();
                        if *bytes_seen > *max_bytes {
                            exceeded.store(true, Ordering::Release);
                            // RST_STREAM the request so the backend cannot
                            // treat the truncated prefix as a complete stream —
                            // identical to the `Streaming` overflow branch.
                            return Poll::Ready(Some(Err(format!(
                                "gRPC request payload exceeds maximum of {} bytes",
                                max_bytes
                            )
                            .into())));
                        }
                    }
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                // The pump task signals a frontend upload failure with `Err(())`
                // so we RST the backend instead of sending a clean END_STREAM
                // that the backend would mistake for a completed request.
                Poll::Ready(Some(Err(()))) => Poll::Ready(Some(Err(
                    "gRPC request body upload failed (frontend stream error)".into(),
                ))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            GrpcBody::Buffered(full) => full.is_end_stream(),
            GrpcBody::BufferedWithTrailers { data, trailers } => {
                data.is_none() && trailers.is_none()
            }
            GrpcBody::Streaming {
                incoming, exceeded, ..
            } => incoming.is_end_stream() || exceeded.load(Ordering::Relaxed),
            // No cheap "channel closed" probe without polling; `false` is always
            // safe (hyper polls once more to observe `None`/overflow). The
            // `exceeded` short-circuit mirrors `Streaming`.
            GrpcBody::Channel { exceeded, .. } => exceeded.load(Ordering::Relaxed),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            GrpcBody::Buffered(full) => full.size_hint(),
            GrpcBody::BufferedWithTrailers { data, .. } => {
                // Exact DATA length only. The trailers block is header bytes,
                // not content, so it must not appear in the size hint hyper
                // uses to frame (and length-declare) the request body.
                let mut hint = http_body::SizeHint::new();
                hint.set_exact(data.as_ref().map_or(0, Bytes::len) as u64);
                hint
            }
            GrpcBody::Streaming { incoming, .. } => incoming.size_hint(),
            GrpcBody::Channel { .. } => http_body::SizeHint::default(),
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

    /// Drop every cached sender for `proxy` so the next acquisition dials fresh.
    ///
    /// Call after a pooled `send_request` fails with hyper `is_canceled`
    /// (request never left the client) while racing a backend GOAWAY /
    /// connection-age close. Waiting for `is_closed()` on the next
    /// `cached()` probe is racy — the dying sender can still look healthy
    /// for one more poll — so the whole host shard ring is cleared.
    /// Sibling shards reconnect lazily on the next miss.
    pub fn invalidate_shards_for_proxy(&self, proxy: &Proxy) {
        let pool_config = self.pool.manager().global_pool_config.for_proxy(proxy);
        let shard_count = pool_config.http2_connections_per_host.max(1);
        let svid_generation = self.pool.manager().svid_generation_for_proxy(proxy);
        self.with_pool_key(proxy, svid_generation, |key_buf| {
            let base_len = key_buf.len();
            for shard in 0..shard_count {
                Self::write_shard_key_inplace(key_buf, base_len, shard);
                self.pool.invalidate(key_buf);
            }
        });
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
                        // Shard exists but is mid-send. Skip — `now_or_never`
                        // only wins on an immediately-ready sender, so a
                        // busy-but-healthy shard falls through to phase 2.
                        // There `create_or_get_existing_owned` checks
                        // `cached()` first; the existing sender is still
                        // healthy (`!is_closed()`), so the create closure
                        // never runs and the pool does NOT grow beyond the
                        // shard ring. Callers queue on H2 readiness /
                        // stream-cap backpressure instead of spawning a fresh
                        // connection. The previous 1 ms `timeout(ready())`
                        // serialized under burst concurrency and was the
                        // largest contributor to gRPC p99 tail latency for
                        // 100-concurrent 500 KB / 1 MB payloads.
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
        let candidates = self
            .dns_cache
            .resolve_candidates(
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

        let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);
        let pool_config = self.global_pool_config.for_proxy(proxy);
        let keepalive_override = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&port))
            .and_then(|o| o.tcp_keepalive.as_ref());
        let use_tls = matches!(proxy.backend_scheme, Some(BackendScheme::Https));

        // The candidate attempt includes TCP socket setup, negotiated ALPN h2
        // when TLS is configured, and the Hyper H2 handshake. Cleartext h2c
        // additionally waits for the peer's initial SETTINGS, since it has no
        // ALPN proof. A peer that accepts TCP but cannot establish the
        // requested protocol must not pin this pool to that DNS address.
        let result = if use_tls {
            let tls_config = self.get_tls_config(proxy, svid_generation)?;
            let connector = tokio_rustls::TlsConnector::from(tls_config);
            let server_name =
                crate::tls::backend::backend_tls_server_name_owned(&proxy.resolved_tls, host)
                    .map_err(|e| {
                        GrpcProxyError::backend_unavailable(
                            GrpcBackendUnavailableKind::InvalidServerName,
                            format!("Invalid server name: {}", e),
                        )
                    })?;

            crate::dns::connect_candidates(&candidates, port, connect_timeout, |sock_addr| {
                let connector = connector.clone();
                let server_name = server_name.clone();
                let pool_config = &pool_config;
                async move {
                    let tcp = crate::socket_opts::connect_with_socket_opts(sock_addr)
                        .await
                        .map_err(|e| {
                            GrpcProxyError::backend_unavailable_with_source(
                                GrpcBackendUnavailableKind::Connect,
                                format!("Connection failed: {}", e),
                                e,
                            )
                        })?;
                    let _ = tcp.set_nodelay(true);
                    crate::socket_opts::apply_pooled_tcp_keepalive(
                        "grpc_proxy",
                        &tcp,
                        keepalive_override,
                        pool_config.enable_http_keep_alive,
                        pool_config.tcp_keepalive_seconds,
                    );
                    self.create_tls_connection(tcp, connector, server_name, pool_config)
                        .await
                }
            })
            .await
        } else {
            crate::dns::connect_candidates(&candidates, port, connect_timeout, |sock_addr| {
                let pool_config = &pool_config;
                async move {
                    let tcp = crate::socket_opts::connect_with_socket_opts(sock_addr)
                        .await
                        .map_err(|e| {
                            GrpcProxyError::backend_unavailable_with_source(
                                GrpcBackendUnavailableKind::Connect,
                                format!("Connection failed: {}", e),
                                e,
                            )
                        })?;
                    let _ = tcp.set_nodelay(true);
                    crate::socket_opts::apply_pooled_tcp_keepalive(
                        "grpc_proxy",
                        &tcp,
                        keepalive_override,
                        pool_config.enable_http_keep_alive,
                        pool_config.tcp_keepalive_seconds,
                    );
                    self.create_h2c_connection(tcp, pool_config).await
                }
            })
            .await
        };

        result
            .map(|(sender, _)| sender)
            .map_err(|error| match error {
                crate::dns::CandidateConnectError::TimedOut { last_addr } => {
                    warn!(
                        "gRPC: protocol establishment budget exhausted ({}ms) for backend {} \
                         (last={})",
                        proxy.backend_connect_timeout_ms, host, last_addr
                    );
                    GrpcProxyError::BackendTimeout {
                        kind: GrpcTimeoutKind::Connect,
                        message: format!(
                            "Connect timeout after {}ms establishing gRPC HTTP/2 to {}",
                            proxy.backend_connect_timeout_ms, last_addr
                        ),
                    }
                }
                crate::dns::CandidateConnectError::Failed { last_addr, source } => {
                    if crate::retry::is_port_exhaustion(&source) {
                        tracing::error!(
                            "gRPC: PORT EXHAUSTION connecting to backend {}: {} — \
                             reduce outbound connection rate or increase net.ipv4.ip_local_port_range",
                            last_addr,
                            source
                        );
                    } else {
                        warn!(
                            "gRPC: all DNS candidates failed protocol establishment for backend {} \
                             (last={}): {}",
                            host, last_addr, source
                        );
                    }
                    source
                }
            })
    }

    /// Build an HTTP/2 client builder with keepalive and flow-control settings.
    ///
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
            // Advertised to the peer as our own inbound stream cap.
            builder.max_concurrent_streams(max_streams);
        }

        if let Some(max_streams) = pool_config.http2_max_concurrent_streams {
            // Preserve the configured initial outbound bound until the peer's
            // SETTINGS frame replaces it.
            builder.initial_max_send_streams(max_streams as usize);
        }

        builder
    }

    /// Create an h2c (cleartext HTTP/2) connection using prior knowledge.
    async fn create_h2c_connection(
        &self,
        tcp: TcpStream,
        pool_config: &PoolConfig,
    ) -> Result<http2::SendRequest<GrpcBody>, GrpcProxyError> {
        let settings_received = Arc::new(AtomicBool::new(false));
        let io = TokioIo::new(H2cSettingsIo::new(tcp, Arc::clone(&settings_received)));
        let builder = Self::build_h2_builder(pool_config);

        let (sender, mut conn) = builder.handshake(io).await.map_err(|e| {
            GrpcProxyError::backend_unavailable_with_source(
                GrpcBackendUnavailableKind::H2cHandshake,
                format!("h2c handshake failed: {}", e),
                e,
            )
        })?;

        if let Err(message) = Self::await_h2c_peer_settings(&mut conn, &settings_received).await {
            return Err(GrpcProxyError::backend_unavailable_with_source(
                GrpcBackendUnavailableKind::H2cHandshake,
                message.clone(),
                std::io::Error::new(std::io::ErrorKind::InvalidData, message),
            ));
        }

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("gRPC h2c connection closed: {}", e);
            }
        });

        Ok(sender)
    }

    /// Wait for positive proof that an h2c peer completed the HTTP/2 preface.
    ///
    /// Unlike TLS-backed H2, h2c has no ALPN proof, so a peer that merely
    /// accepts TCP must not pin this pool to its DNS address. `handshake()`
    /// resolves once the *client* preface is written; readiness is the peer's
    /// complete, structurally valid initial SETTINGS frame having been observed
    /// by the transport and accepted by a subsequent Hyper connection poll.
    ///
    /// `conn` is hyper's connection-driver future. Polling it drives the peer's
    /// preface and SETTINGS processing and surfaces a protocol error or close,
    /// but the future does not resolve merely because SETTINGS arrived. The
    /// short timeout therefore supplies a bounded recheck cadence for the
    /// transport observation flag while also continuing to drive the connection.
    ///
    /// There is no timeout here by design: the caller runs inside
    /// `dns::connect_candidates`, whose per-candidate share of
    /// `backend_connect_timeout_ms` bounds this wait and moves on to the next
    /// address.
    async fn await_h2c_peer_settings(
        conn: &mut http2::Connection<TokioIo<H2cSettingsIo>, GrpcBody, TokioExecutor>,
        settings_received: &AtomicBool,
    ) -> Result<(), String> {
        // First re-read delay; the common case resolves on the first or second
        // pass over a loopback or same-datacenter RTT.
        const FIRST_RECHECK: Duration = Duration::from_millis(1);
        // Ceiling for the doubling backoff, so a peer that accepts TCP and
        // then stalls costs a bounded number of timer wakeups per candidate.
        const MAX_RECHECK: Duration = Duration::from_millis(20);

        let mut recheck = FIRST_RECHECK;
        loop {
            if settings_received.load(Ordering::Acquire) {
                // The transport observer fires while Hyper is consuming the
                // read. Poll the connection once more before accepting the peer
                // so a protocol error discovered from that same frame wins over
                // the raw readiness flag instead of leaving an invalid sender
                // cached and suppressing DNS-candidate failover.
                let post_observation = std::future::poll_fn(|cx| {
                    Poll::Ready(match Pin::new(&mut *conn).poll(cx) {
                        Poll::Ready(Ok(())) => {
                            Some(Err("h2c connection closed after peer SETTINGS".to_string()))
                        }
                        Poll::Ready(Err(error)) => {
                            Some(Err(format!("h2c handshake failed: {error}")))
                        }
                        Poll::Pending => None,
                    })
                })
                .await;
                if let Some(result) = post_observation {
                    return result;
                }
                return Ok(());
            }
            match tokio::time::timeout(recheck, &mut *conn).await {
                Ok(Ok(())) => {
                    return Err("h2c connection closed before peer SETTINGS".to_string());
                }
                Ok(Err(error)) => return Err(format!("h2c handshake failed: {error}")),
                Err(_elapsed) => recheck = (recheck * 2).min(MAX_RECHECK),
            }
        }
    }

    /// Create an h2 (TLS) connection with ALPN negotiation, mTLS, and custom CA bundles.
    async fn create_tls_connection(
        &self,
        tcp: TcpStream,
        connector: tokio_rustls::TlsConnector,
        server_name: rustls::pki_types::ServerName<'static>,
        pool_config: &PoolConfig,
    ) -> Result<http2::SendRequest<GrpcBody>, GrpcProxyError> {
        let tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
            GrpcProxyError::backend_unavailable_with_source(
                GrpcBackendUnavailableKind::TlsHandshake,
                format!("TLS handshake failed: {}", e),
                e,
            )
        })?;
        if !matches!(tls_stream.get_ref().1.alpn_protocol(), Some(b"h2")) {
            let message = "TLS peer did not negotiate ALPN h2".to_string();
            return Err(GrpcProxyError::backend_unavailable_with_source(
                GrpcBackendUnavailableKind::TlsHandshake,
                message.clone(),
                std::io::Error::new(std::io::ErrorKind::InvalidData, message),
            ));
        }

        let io = TokioIo::new(tls_stream);
        let builder = Self::build_h2_builder(pool_config);
        let (sender, conn) = builder.handshake(io).await.map_err(|e| {
            GrpcProxyError::backend_unavailable_with_source(
                GrpcBackendUnavailableKind::H2Handshake,
                format!("h2 handshake failed: {}", e),
                e,
            )
        })?;

        // TLS negotiation already proved H2 via ALPN.
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
    /// A pooled H2 `send_request` failed with hyper `is_canceled() == true`
    /// while the outbound body was still fully buffered and replayable.
    /// hyper's contract for that flag is that the request was **never
    /// dispatched onto the wire** (typical race: backend GOAWAY /
    /// `MaxConnectionAge` while the pool still handed out a sender that
    /// passed a single `ready()` probe). Pre-wire under the unified
    /// [`crate::retry::request_reached_wire`] boundary — maps to
    /// [`crate::retry::ErrorClass::ConnectionPoolError`] so
    /// `retry_on_connect_failure` can redial. Streaming / channel bodies
    /// keep [`Self::BackendRequest`] even on `is_canceled` because the
    /// upload may already be unreplayable.
    DispatchCanceled,
}

impl GrpcBackendUnavailableKind {
    /// Returns `true` for kinds that represent a pre-wire failure (DNS,
    /// connect, handshake, never-dispatched pooled send) — safe to replay
    /// regardless of HTTP method idempotency.
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
            | Self::InvalidServerName
            | Self::DispatchCanceled => true,
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
    /// The client RPC deadline expired before the current attempt acquired an
    /// HTTP/2 request stream (including connection acquisition and retry
    /// backoff). No request from that attempt reached the backend, so health,
    /// circuit-breaker, and adaptive-concurrency accounting must treat this as
    /// neutral while the client still receives DEADLINE_EXCEEDED.
    ClientDeadlineExceeded(String),
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

/// Failure while collecting a buffered client gRPC request before dispatch.
///
/// Upload failures are kept separate from [`GrpcProxyError`] because they occur
/// before backend dispatch. The typed timeout source preserves the distinct
/// operator stall-timeout and client RPC-deadline wire messages while both let
/// their pre-dispatch probe guard settle neutrally.
pub(crate) enum GrpcRequestBodyCollectError {
    Proxy(GrpcProxyError),
    TimedOut,
    DeadlineExceeded,
}

fn map_request_body_wait_error(error: super::RequestBodyWaitError) -> GrpcRequestBodyCollectError {
    match error {
        super::RequestBodyWaitError::TimedOut => GrpcRequestBodyCollectError::TimedOut,
        super::RequestBodyWaitError::DeadlineExceeded => {
            GrpcRequestBodyCollectError::DeadlineExceeded
        }
    }
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
            | Self::ClientDeadlineExceeded(message)
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

impl From<crate::pool::SharedPoolCreateError> for GrpcProxyError {
    fn from(err: crate::pool::SharedPoolCreateError) -> Self {
        use crate::pool::SharedPoolCreateKind;
        use crate::retry::ErrorClass;

        let message = err.message().to_string();
        match err.kind() {
            SharedPoolCreateKind::TimedOut => Self::BackendTimeout {
                // Pool create failures are connect-phase.
                kind: match err.error_class() {
                    ErrorClass::ReadWriteTimeout => GrpcTimeoutKind::Read,
                    _ => GrpcTimeoutKind::Connect,
                },
                message,
            },
            SharedPoolCreateKind::Internal => Self::Internal(message),
            // NegotiatedHttp1 is an H2-pool signal; gRPC create never emits it.
            // Fall through to unavailable reconstruction so waiters still fail.
            SharedPoolCreateKind::NegotiatedHttp1
            | SharedPoolCreateKind::Dns
            | SharedPoolCreateKind::Tls
            | SharedPoolCreateKind::ConnectionRefused
            | SharedPoolCreateKind::ConnectionClosed
            | SharedPoolCreateKind::Protocol
            | SharedPoolCreateKind::PortExhaustion
            | SharedPoolCreateKind::DispatchPolicyRejected
            | SharedPoolCreateKind::Unavailable
            | SharedPoolCreateKind::Other => {
                // Structural kind for logs / is_connect_class. The authoritative
                // ErrorClass lives on `err` and is restored via the source chain
                // in `classify_grpc_proxy_error`. DispatchPolicyRejected creators
                // use DnsResolution (egress denial before dial); preserve that
                // shape so `message.contains("egress policy")` retry/CB guards
                // stay aligned with the creator path.
                let kind = match err.error_class() {
                    ErrorClass::DnsLookupError | ErrorClass::DispatchPolicyRejected => {
                        GrpcBackendUnavailableKind::DnsResolution
                    }
                    ErrorClass::TlsError | ErrorClass::ProtocolError => {
                        GrpcBackendUnavailableKind::TlsHandshake
                    }
                    ErrorClass::ConnectionRefused
                    | ErrorClass::ConnectionClosed
                    | ErrorClass::ConnectionReset
                    | ErrorClass::PortExhaustion
                    | ErrorClass::ConnectionPoolError
                    | ErrorClass::ConnectionTimeout
                    | ErrorClass::ReadWriteTimeout
                    | ErrorClass::ClientDisconnect
                    | ErrorClass::ResponseBodyTooLarge
                    | ErrorClass::RequestBodyTooLarge
                    | ErrorClass::GracefulRemoteClose
                    | ErrorClass::RequestError => GrpcBackendUnavailableKind::Connect,
                };
                // Retain the shared classification payload as the typed source so
                // classifiers recover the creator's ErrorClass without substring
                // heuristics (port exhaustion, egress denial, ConnectionClosed, …).
                Self::backend_unavailable_with_source(kind, message, err)
            }
        }
    }
}

impl crate::pool::ShareablePoolCreateError for GrpcProxyError {
    fn to_shared(&self) -> crate::pool::SharedPoolCreateError {
        use crate::pool::{SharedPoolCreateError, SharedPoolCreateKind};
        use crate::retry::ErrorClass;

        // Canonical classifier — preserves DNS/TLS/timeout/refused/port-exhaustion
        // /egress without new substring heuristics on the shared path.
        let error_class = crate::retry::classify_grpc_proxy_error(self);
        match self {
            Self::BackendTimeout { message, .. } => SharedPoolCreateError::new(
                message.clone(),
                SharedPoolCreateKind::TimedOut,
                error_class,
                None,
            ),
            Self::Internal(message) => SharedPoolCreateError::new(
                message.clone(),
                SharedPoolCreateKind::Internal,
                error_class,
                None,
            ),
            Self::BackendUnavailable { message, .. }
            | Self::ClientDeadlineExceeded(message)
            | Self::ResourceExhausted(message)
            | Self::ResponseTooLarge(message) => {
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

/// gRPC status codes for gateway-generated errors.
pub mod grpc_status {
    pub const OK: u32 = 0;
    pub const UNKNOWN: u32 = 2;
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
    grpc_status_from_maps(trailers, headers)
        .filter(|&code| code != 0)
        .map(grpc_status_to_http_status)
        .unwrap_or(http_status)
}

/// Extract the terminal gRPC application status without mapping it onto HTTP.
/// Trailers take precedence over trailers-only initial headers, matching the
/// wire protocol. Callers use this for transaction metadata and metrics while
/// retaining HTTP 200 as the transport status.
///
/// Buffered collection joins duplicate `grpc-status` occurrences with LF (see
/// [`collect_buffered_grpc_trailers`]). Prefer the first valid numeric
/// occurrence — the same rule gRPC-Web trailer-frame emission uses — and reject
/// CR-bearing fields so a hostile value cannot inject an additional logical
/// status line into the parse of a single joined field.
pub(crate) fn grpc_status_from_maps(
    trailers: &HashMap<String, String>,
    headers: &HashMap<String, String>,
) -> Option<u32> {
    trailers
        .get("grpc-status")
        .or_else(|| headers.get("grpc-status"))
        .map(|status| parse_grpc_status_joined_value(status))
}

/// Parse a peer-supplied gRPC status without allowing malformed values to look
/// like success. `u32::MAX` is outside the standard 0..=16 range, maps to an
/// HTTP 500 health outcome, and is rendered in the bounded `OTHER` metric
/// bucket.
pub(crate) fn parse_grpc_status_value(status: &str) -> u32 {
    status.trim().parse::<u32>().unwrap_or(u32::MAX)
}

/// Parse a possibly LF-joined `grpc-status` field from the buffered string map.
fn parse_grpc_status_joined_value(status: &str) -> u32 {
    // Match gRPC-Web trailer-frame encoding: CR is never part of the LF-join
    // representation, so its presence means a hostile/malformed field.
    if status.contains('\r') {
        return u32::MAX;
    }
    for occurrence in status.split('\n') {
        if let Ok(code) = occurrence.trim().parse::<u32>() {
            return code;
        }
    }
    u32::MAX
}

/// Refresh transaction metadata from the final client-visible gRPC response.
///
/// Response hooks can rewrite or remove terminal metadata after the backend
/// status was captured for health accounting. Missing terminal status is
/// gRPC UNKNOWN for the client, so it must not leave a stale backend status in
/// Prometheus/log metadata.
pub(crate) fn refresh_grpc_status_metadata(
    metadata: &mut HashMap<String, String>,
    trailers: &HashMap<String, String>,
    headers: &HashMap<String, String>,
) {
    let status = grpc_status_from_maps(trailers, headers).unwrap_or(grpc_status::UNKNOWN);
    metadata.insert("grpc_status".to_string(), status.to_string());
}

/// [`refresh_grpc_status_metadata`] for a buffered response whose terminal
/// metadata may ride in the BODY rather than in either map.
///
/// gRPC-Web carries `grpc-status`/`grpc-message` in a body trailer frame, and
/// the gateway-authored terminal responses that use it — the representation
/// gate's `unparseable_document` refusal, the deadline replacement, and a
/// finalized body rejection — clear the wire trailers and strip the terminal
/// fields from the initial header block on purpose, because that is the shape
/// the client must see. Both maps are therefore legitimately silent, and the
/// plain refresh would read that silence as "the hooks removed the status" and
/// overwrite the status the replacement just recorded with the synthesized
/// `UNKNOWN(2)` — reporting `2` in logs, transaction summaries, and the
/// Prometheus status bucket for a fail-closed `INTERNAL(13)` error the client
/// actually received.
///
/// So when the terminal metadata is body-framed and neither map names a status,
/// an already-recorded status stands. A status present in either map is still
/// authoritative and still refreshes, so a genuine post-hook edit is never
/// ignored, and a request with no recorded status at all still falls back to
/// `UNKNOWN`.
pub(crate) fn refresh_grpc_status_metadata_with_body_framed_terminal(
    metadata: &mut HashMap<String, String>,
    trailers: &HashMap<String, String>,
    headers: &HashMap<String, String>,
    terminal_metadata_is_body_framed: bool,
) {
    if terminal_metadata_is_body_framed
        && grpc_status_from_maps(trailers, headers).is_none()
        && metadata.contains_key("grpc_status")
    {
        return;
    }
    refresh_grpc_status_metadata(metadata, trailers, headers);
}

/// Effective request-body cap for the sidecar mesh-mTLS dispatch path (issue
/// #2003 codex r1-3): gRPC-flavored uploads — native `application/grpc` or
/// gRPC-Web translated to it by the `grpc_web` plugin; both are wire-native
/// gRPC framing by dispatch time — are bounded by `max_grpc_recv_size_bytes`,
/// mirroring the direct gRPC pool's receive limit. Everything else keeps the
/// general `max_request_body_size_bytes`. `0` means unlimited for whichever
/// knob is selected (never cross-inherited).
pub fn mesh_request_body_limit(
    is_grpc: bool,
    max_request_body_size_bytes: usize,
    max_grpc_recv_size_bytes: usize,
) -> usize {
    if is_grpc {
        max_grpc_recv_size_bytes
    } else {
        max_request_body_size_bytes
    }
}

/// Trailers-Only `RESOURCE_EXHAUSTED` refusal for a gRPC request body that
/// exceeds `max_grpc_recv_size_bytes` on a mesh dispatch path, mirroring the
/// direct gRPC pool's oversize rejection (same gRPC status and message shape;
/// gRPC errors ride HTTP 200 with the outcome in `grpc-status`).
///
/// `ErrorClass::RequestBodyTooLarge` keeps backend-health accounting NEUTRAL:
/// a client-side upload overflow carries no signal about the backend, so the
/// circuit breaker and passive health skip it via
/// `client_side_no_backend_signal` and the adaptive-concurrency limiter
/// ignores it the same way — instead of banking the HTTP 200 as a phantom
/// success for a backend that was never dialed (or never finished the RPC).
pub fn grpc_request_body_too_large_backend_response(
    proxy_id: &str,
    resolved_ip: Option<String>,
    observed_size: Option<usize>,
    max_size: usize,
) -> crate::retry::BackendResponse {
    match observed_size {
        Some(size) => warn!(
            proxy_id = %proxy_id,
            request_body_bytes = size,
            max_grpc_recv_size_bytes = max_size,
            "gRPC request body exceeds configured receive limit on mesh dispatch"
        ),
        None => warn!(
            proxy_id = %proxy_id,
            max_grpc_recv_size_bytes = max_size,
            "gRPC streaming request body exceeded configured receive limit on mesh dispatch"
        ),
    }
    let mut headers = HashMap::with_capacity(3);
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(
        "grpc-status".to_string(),
        grpc_status::RESOURCE_EXHAUSTED.to_string(),
    );
    headers.insert(
        "grpc-message".to_string(),
        format!("gRPC request payload size exceeds maximum of {max_size} bytes"),
    );
    crate::retry::BackendResponse {
        status_code: 200, // gRPC errors ride HTTP 200 + grpc-status
        body: crate::retry::ResponseBody::buffered(Vec::new()),
        headers,
        connection_error: false,
        backend_resolved_ip: resolved_ip,
        error_class: Some(crate::retry::ErrorClass::RequestBodyTooLarge),
    }
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

/// Authoritative terminal metadata captured from a pristine gRPC header map.
///
/// A genuine Trailers-Only backend response carries these fields in its first
/// and only HEADERS block. Buffered response hooks operate later, so the
/// preserve path must restore this pre-hook snapshot instead of whatever a
/// policy left in the compatibility view.
#[derive(Debug, Default)]
pub struct GrpcTerminalMetadataSnapshot {
    grpc_status: Option<String>,
    grpc_message: Option<String>,
    grpc_status_details: Option<String>,
}

impl GrpcTerminalMetadataSnapshot {
    pub fn from_headers(headers: &HashMap<String, String>) -> Self {
        Self {
            grpc_status: headers.get("grpc-status").cloned(),
            grpc_message: headers.get("grpc-message").cloned(),
            grpc_status_details: headers.get("grpc-status-details-bin").cloned(),
        }
    }

    fn is_empty(&self) -> bool {
        self.grpc_status.is_none()
            && self.grpc_message.is_none()
            && self.grpc_status_details.is_none()
    }

    pub fn grpc_status(&self) -> Option<&str> {
        self.grpc_status.as_deref()
    }

    pub fn grpc_message(&self) -> Option<&str> {
        self.grpc_message.as_deref()
    }

    pub fn grpc_status_details(&self) -> Option<&str> {
        self.grpc_status_details.as_deref()
    }

    fn restore_into(&self, headers: &mut HashMap<String, String>) {
        for (name, value) in [
            ("grpc-status", self.grpc_status.as_ref()),
            ("grpc-message", self.grpc_message.as_ref()),
            ("grpc-status-details-bin", self.grpc_status_details.as_ref()),
        ] {
            if let Some(value) = value {
                headers.insert(name.to_string(), value.clone());
            }
        }
    }
}

/// Select gateway-authored terminal metadata after a buffered response is
/// replaced and retire every stale backend trailer in one transition.
///
/// Callers pass the replacement header view after it has been normalized into
/// the client's gRPC flavor. Capturing before split finalization is essential:
/// non-empty backend responses otherwise have no pristine Trailers-Only
/// snapshot, and finalization correctly strips an unsourced `grpc-status` from
/// initial HEADERS.
pub fn select_buffered_grpc_terminal_response(
    response_headers: &HashMap<String, String>,
    response_trailers: &mut HashMap<String, String>,
    authoritative_terminal_metadata: &mut Option<GrpcTerminalMetadataSnapshot>,
) {
    *authoritative_terminal_metadata =
        Some(GrpcTerminalMetadataSnapshot::from_headers(response_headers));
    response_trailers.clear();
}

/// Discard application trailers after buffered response bytes are rewritten,
/// while retaining the reserved gRPC terminal status on its wire channel.
///
/// Buffered hooks see a merged header/trailer compatibility map. Removing only
/// the wire trailer map would accidentally promote trailer-only application
/// metadata into initial HEADERS, so this also removes those compatibility
/// copies. A key that the backend supplied in both channels remains as its real
/// initial header; only its trailing copy is retired. `grpc-status`,
/// `grpc-message`, and status details survive because they describe RPC
/// completion, not the discarded byte representation.
pub fn discard_grpc_application_trailers_after_body_rewrite(
    response_headers: &mut HashMap<String, String>,
    response_trailers: &mut HashMap<String, String>,
    header_shadowed_trailer_keys: &HashSet<String>,
) {
    response_headers.retain(|name, _| {
        is_reserved_grpc_terminal_metadata(name)
            || !response_trailers.contains_key(name)
            || header_shadowed_trailer_keys.contains(name)
    });
    response_trailers.retain(|name, _| is_reserved_grpc_terminal_metadata(name));
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
/// hook; copy it. Initial-header policy provenance is handled separately: a
/// final set/override preserves the pre-policy application trailer, while a
/// final removal suppresses it. Reserved gRPC terminal metadata is the sole
/// removal exception and retains its authoritative pre-policy trailer value.
pub fn reconcile_grpc_trailers_from_view(
    response_trailers: &mut HashMap<String, String>,
    plugin_response_headers: &HashMap<String, String>,
    original_response_headers: &HashMap<String, String>,
    header_shadowed_trailer_keys: &HashSet<String>,
    policy_state: Option<&BufferedInitialResponseHeaderPolicyState>,
) {
    response_trailers.retain(|k, v| {
        if let Some((pre_policy_value, final_policy_value_present)) = policy_state
            .and_then(|state| state.application_trailer_initial_response_policy_outcome(k))
        {
            if !final_policy_value_present && !is_reserved_grpc_terminal_metadata(k) {
                return false;
            }
            if let Some(pre_policy_value) = pre_policy_value {
                if !header_shadowed_trailer_keys.contains(k)
                    || original_response_headers.get(k).map(String::as_str)
                        != Some(pre_policy_value)
                {
                    *v = pre_policy_value.to_string();
                }
                return true;
            }
            return false;
        }
        match plugin_response_headers.get(k) {
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
        }
    });
}

/// Remove compatibility-view trailer copies from buffered gRPC initial headers
/// before the ordered response-policy outcome is applied to the initial map.
///
/// Buffered response hooks historically receive one merged header+trailer map.
/// After trailer reconciliation, ordinary trailer-only fields must return to the
/// trailer channel. Callers then apply the policy provenance state so policy
/// values land in initial HEADERS without ever promoting an application
/// trailer value.
///
/// Header-shadowed trailers already have a genuine initial-header copy and are
/// left alone. Reserved gRPC terminal metadata is never considered shadowed by
/// the collector and therefore remains trailer-authoritative for non-empty
/// responses.
pub fn strip_non_initial_grpc_trailer_fields(
    response_headers: &mut HashMap<String, String>,
    response_trailers: &HashMap<String, String>,
    header_shadowed_trailer_keys: &HashSet<String>,
) {
    for name in response_trailers.keys() {
        if !header_shadowed_trailer_keys.contains(name) {
            response_headers.remove(name);
        }
    }
}

/// Keep gRPC terminal metadata out of initial HEADERS on non-empty responses.
///
/// Initial-response policy is reapplied after trailer provenance is restored.
/// An operator may deliberately name a gRPC metadata field in a generic header
/// policy, but the protocol boundary must still keep terminal status on the
/// trailer channel.
pub fn strip_grpc_terminal_metadata_from_initial(response_headers: &mut HashMap<String, String>) {
    response_headers.remove("grpc-status");
    response_headers.remove("grpc-message");
    response_headers.remove("grpc-status-details-bin");
}

/// Apply the buffered initial-header policy outcome while protecting gRPC terminal
/// metadata owned by a legitimate Trailers-Only initial HEADERS block.
///
/// Policy-supplied terminal fields are always discarded. A caller preserving
/// true Trailers-Only metadata supplies the snapshot captured from pristine
/// backend initial headers before hooks ran; otherwise terminal metadata
/// remains exclusive to the wire trailer channel. The transform-owned
/// `content-length` is preserved across the policy overlay.
pub fn apply_buffered_grpc_initial_response_policy(
    policy_state: Option<&BufferedInitialResponseHeaderPolicyState>,
    response_headers: &mut HashMap<String, String>,
    authoritative_terminal_metadata: Option<&GrpcTerminalMetadataSnapshot>,
) {
    let content_length = response_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.clone());
    // Drop every case variant before the policy overlay so a mixed-case leftover
    // cannot co-exist with the restored transform-owned length.
    crate::proxy::headers::remove_content_length_header(response_headers);
    strip_grpc_terminal_metadata_from_initial(response_headers);

    if let Some(policy_state) = policy_state {
        policy_state.apply_to_initial_headers(response_headers);
    }
    crate::proxy::headers::remove_content_length_header(response_headers);
    if let Some(value) = content_length {
        response_headers.insert("content-length".to_string(), value);
    }
    strip_grpc_terminal_metadata_from_initial(response_headers);

    if let Some(authoritative_terminal_metadata) = authoritative_terminal_metadata {
        authoritative_terminal_metadata.restore_into(response_headers);
    }
}

/// Restore the split gRPC wire channels and apply the final initial-header
/// policy outcome in one order-preserving boundary operation.
///
/// Trailer-derived compatibility fields are removed from initial HEADERS
/// first. A hook-mutated trailer-only `set-cookie` is then re-homed so the
/// ordered policy overlay gets the final decision: a later removal suppresses
/// it, while a later set/override wins without bypassing hook priority. Other
/// application trailers remain on the trailer channel unless the provenance
/// state records a final policy removal.
///
/// Shared by the H1/H2 buffered response path and the H3 cross-protocol bridge
/// so channel ownership and policy order cannot drift between frontends.
pub fn finalize_buffered_grpc_split_response(
    response_headers: &mut HashMap<String, String>,
    response_trailers: &mut HashMap<String, String>,
    header_shadowed_trailer_keys: &HashSet<String>,
    policy_state: Option<&BufferedInitialResponseHeaderPolicyState>,
    authoritative_terminal_metadata: Option<&GrpcTerminalMetadataSnapshot>,
    original_trailer_set_cookie: Option<&str>,
) {
    strip_non_initial_grpc_trailer_fields(
        response_headers,
        response_trailers,
        header_shadowed_trailer_keys,
    );
    rehome_hook_mutated_trailer_set_cookie(
        response_headers,
        response_trailers,
        original_trailer_set_cookie,
    );
    apply_buffered_grpc_initial_response_policy(
        policy_state,
        response_headers,
        authoritative_terminal_metadata,
    );
}

/// Collapse a buffered gRPC Trailers-Only response into its initial HEADERS
/// while keeping trailer provenance from defeating initial-header policy.
///
/// Trailer-only fields are removed before the first replay, so a policy using
/// `override_existing: false` evaluates against genuine initial headers. When
/// trailers are collapsed, policy-produced values retain precedence; a second
/// replay applies configured removals to application trailers. Reserved gRPC
/// terminal metadata is always restored from the authoritative trailer value.
/// A trailer-originated `content-length` is never promoted: framing remains
/// owned by the final buffered representation.
pub fn collapse_grpc_trailers_only_with_initial_response_policies(
    response_headers: &mut HashMap<String, String>,
    response_trailers: &mut HashMap<String, String>,
    header_shadowed_trailer_keys: &HashSet<String>,
    policy_state: Option<&BufferedInitialResponseHeaderPolicyState>,
    pristine_initial_terminal_metadata: Option<&GrpcTerminalMetadataSnapshot>,
) {
    let trailer_terminal_metadata = GrpcTerminalMetadataSnapshot::from_headers(response_trailers);
    let authoritative_terminal_metadata = if trailer_terminal_metadata.is_empty() {
        pristine_initial_terminal_metadata
    } else {
        Some(&trailer_terminal_metadata)
    };
    strip_non_initial_grpc_trailer_fields(
        response_headers,
        response_trailers,
        header_shadowed_trailer_keys,
    );
    apply_buffered_grpc_initial_response_policy(
        policy_state,
        response_headers,
        authoritative_terminal_metadata,
    );

    for (name, value) in response_trailers.drain() {
        if name == "content-length" {
            continue;
        }
        if is_reserved_grpc_terminal_metadata(&name) || header_shadowed_trailer_keys.contains(&name)
        {
            response_headers.insert(name, value);
        } else {
            response_headers.entry(name).or_insert(value);
        }
    }

    apply_buffered_grpc_initial_response_policy(
        policy_state,
        response_headers,
        authoritative_terminal_metadata,
    );
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
/// Must be called AFTER the strip loop and BEFORE the final initial-header
/// policy overlay, sticky-cookie injection (so an injected sticky `set-cookie`
/// cannot mask the trailer-only check), and the gRPC-Web trailer-clear guard.
/// [`finalize_buffered_grpc_split_response`] owns this ordering for both the
/// main buffered gRPC path and the H3 cross-protocol bridge (#1614).
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

/// How a gRPC-flavored request may dispatch for an LB-selected target with
/// respect to mesh transports (issue #2003).
///
/// The direct-dial gRPC pool (`GrpcConnectionPool`) speaks plaintext h2c /
/// plain TLS straight to `target.host:target.port`. For a mesh-tagged target
/// that dial BYPASSES the secured mesh transport: under STRICT
/// PeerAuthentication it fails confusingly at the destination's capture
/// listener, and under PERMISSIVE it succeeds **unauthenticated**, silently
/// skipping SVID-mTLS/HBONE, identity pinning, and mesh authz identity. Every
/// gRPC dispatch surface must therefore classify the selected target through
/// this helper and never direct-dial a non-[`Direct`](GrpcMeshDispatch::Direct)
/// target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcMeshDispatch {
    /// No mesh transport tag: the direct `GrpcConnectionPool` dial is correct.
    Direct,
    /// Same-cluster Sidecar `mesh.mtls=true` target: dispatch through the
    /// generic SVID-mTLS HTTP/2 path (`proxy_to_backend_mesh_mtls`), which is
    /// hyper h2 end-to-end and preserves gRPC trailers. Only the H1/H2
    /// frontend path can do this today; surfaces without a mesh-mTLS
    /// dispatch (the H3 cross-protocol bridge, the gRPC retry loop after a
    /// target rotation) must fail closed instead.
    MeshMtls,
    /// CROSS-CLUSTER Sidecar `mesh.mtls` east-west target that is WELL-FORMED
    /// (carries `mesh.cross_cluster=true`, a destination-FQDN SNI override
    /// `mesh.eastwest_sni`, and a remote trust domain `mesh.trust_domain`):
    /// dispatch through the SAME generic SVID-mTLS HTTP/2 path
    /// (`proxy_to_backend_mesh_mtls`) as [`MeshMtls`](Self::MeshMtls) — its
    /// cross-cluster branch dials the east-west gateway, overrides the
    /// ClientHello SNI to the destination service FQDN, and verifies the peer
    /// SVID trust-domain-only (no pinned pod SPIFFE). gRPC is HTTP/2 with
    /// trailers and rides that path natively, exactly like the HTTP family
    /// already does cross-cluster (issue #2010). Falls through only on the
    /// H1/H2 frontend path (like `MeshMtls`); the H3 bridge and the gRPC
    /// retry loop still fail closed.
    MeshMtlsCrossCluster,
    /// Cross-cluster Ambient `mesh.hbone` east-west target (or a corrupted
    /// target carrying BOTH transport tags): fail closed. The HBONE inner
    /// protocol is HTTP/1.1 over a byte tunnel and cannot carry the HTTP/2
    /// trailers gRPC requires — routing it cross-cluster does not change that,
    /// so native gRPC over cross-cluster HBONE stays out of scope, the same
    /// limitation as [`RefuseHbone`](Self::RefuseHbone) (declared out of scope
    /// in #2023; issue #2010).
    RefuseCrossCluster,
    /// Cross-cluster Sidecar `mesh.mtls` east-west target that is MALFORMED —
    /// missing the destination-FQDN SNI override (`mesh.eastwest_sni`) or the
    /// remote trust domain (`mesh.trust_domain`) the cross-cluster mesh-mTLS
    /// dial requires: fail closed. The transport tag is present but the target
    /// cannot be dialed safely (`proxy_to_backend_mesh_mtls`'s cross-cluster
    /// branch would itself fail closed on the missing metadata), so refuse
    /// here with a clean gRPC UNAVAILABLE rather than let it reach a 502
    /// (issue #2010).
    RefuseCrossClusterMalformed,
    /// Malformed cross-cluster target with no mesh transport tag: fail
    /// closed. It is not a valid pass-through gRPC-Web mesh transport either,
    /// so it must not use the plain HTTP-family fallback.
    RefuseCrossClusterNoTransport,
    /// Same-cluster Ambient `mesh.hbone=true` target: fail closed. The HBONE
    /// inner protocol is HTTP/1.1 over a byte tunnel (`hyper::client::conn::
    /// http1` inside the CONNECT stream; the destination relays raw bytes to
    /// the app), which cannot carry the HTTP/2 trailers gRPC requires for
    /// `grpc-status`.
    RefuseHbone,
}

/// Classify how a gRPC request may dispatch for `target`. See
/// [`GrpcMeshDispatch`]. A target that carries BOTH transport tags (should not
/// happen — topologies are mutually exclusive) is classified by the stricter
/// HBONE refusal so it can never fall through to a direct dial. The
/// cross-cluster check runs FIRST: an Ambient HBONE cross-cluster target (or a
/// transport-less one) stays fail-closed, but a WELL-FORMED Sidecar mesh-mTLS
/// cross-cluster target (SNI override + trust domain present) is now allowed to
/// ride the mesh-mTLS pool's cross-cluster branch (issue #2010) — the same
/// east-west transport the HTTP family already uses. A cross-cluster target
/// with no transport tag, or a Sidecar one missing its SNI/trust-domain
/// metadata, still fails closed.
pub fn classify_grpc_mesh_dispatch(
    target: &crate::config::types::UpstreamTarget,
) -> GrpcMeshDispatch {
    let hbone = crate::proxy::hbone_pool::target_hbone_enabled(target);
    let mesh_mtls = crate::proxy::mesh_mtls_pool::target_mesh_mtls_enabled(target);
    let cross_cluster = crate::proxy::hbone_pool::target_hbone_cross_cluster(target)
        || crate::proxy::mesh_mtls_pool::target_mesh_mtls_cross_cluster(target);
    if cross_cluster {
        // HBONE cross-cluster (or a corrupted BOTH-tags target) takes the
        // stricter refusal: gRPC over the HBONE HTTP/1.1 inner tunnel cannot
        // carry trailers, and a mixed-tag target must never fall through to the
        // mesh-mTLS pool. Checked FIRST so `hbone` wins over `mesh_mtls`.
        if hbone {
            return GrpcMeshDispatch::RefuseCrossCluster;
        }
        // Sidecar cross-cluster mesh-mTLS is allowed to ride the mesh-mTLS
        // pool's cross-cluster branch (east-west gateway dial + destination-FQDN
        // SNI override + trust-domain-only verification) ONLY when the target is
        // WELL-FORMED — it MUST carry the SNI override AND the remote trust
        // domain the dial scopes verification to. A missing/empty/unparseable
        // one fails closed here (the dispatch path would itself fail closed) so
        // the gRPC caller sees a clean UNAVAILABLE instead of a 502.
        if mesh_mtls {
            if crate::proxy::mesh_mtls_pool::target_mesh_mtls_eastwest_sni(target).is_some()
                && crate::proxy::mesh_mtls_pool::target_mesh_mtls_cross_cluster_trust_domain(target)
                    .is_some()
            {
                return GrpcMeshDispatch::MeshMtlsCrossCluster;
            }
            return GrpcMeshDispatch::RefuseCrossClusterMalformed;
        }
        return GrpcMeshDispatch::RefuseCrossClusterNoTransport;
    }
    if hbone {
        return GrpcMeshDispatch::RefuseHbone;
    }
    if mesh_mtls {
        return GrpcMeshDispatch::MeshMtls;
    }
    GrpcMeshDispatch::Direct
}

/// Whether a protocol-classified gRPC request may fall through the direct-dial
/// gRPC branch onto the generic HTTP-family dispatch path for a mesh-tagged
/// target (issue #2003).
///
/// * `Direct` never falls through — the direct `GrpcConnectionPool` serves it.
/// * `MeshMtls` / `MeshMtlsCrossCluster` fall through only when the generic
///   mesh-mTLS path can carry the request body without pre-buffering (the
///   cross-cluster variant rides the SAME pool, just its east-west branch).
///   Native streams and binary translated gRPC-Web are supported there;
///   text-mode translated gRPC-Web still needs request-body buffering for
///   base64 decode, which that path refuses today, so it fails closed before
///   falling through.
/// * `RefuseCrossClusterMalformed` never falls through: the cross-cluster
///   Sidecar mesh-mTLS transport tag is present but the target lacks the SNI
///   override / trust domain the dial needs, so even pass-through gRPC-Web
///   would fail closed at the mesh-mTLS dispatch — refuse cleanly in-branch.
/// * `RefuseCrossCluster` / `RefuseHbone` fall through ONLY for PASS-THROUGH
///   gRPC-Web (body-framed trailers, rides the HTTP-family transport like
///   plain HTTP). Native gRPC must be refused inside the branch, and so must
///   gRPC-Web the `grpc_web` plugin TRANSLATED (codex r2-1): by dispatch time
///   the outbound request is wire-native gRPC (`content-type:
///   application/grpc`), so letting it ride the HBONE HTTP/1.1 inner tunnel
///   or the cross-cluster paths would hit the exact no-trailer corruption the
///   refusal exists to prevent. The original request content-type
///   (`request_uses_grpc_content_type`) alone cannot see the translation —
///   pair it with the plugin's spoof-proof context marker
///   (`grpc_web::request_is_grpc_web_translated`).
/// * `RefuseCrossClusterNoTransport` never falls through because the target
///   is malformed: there is no HBONE or mesh-mTLS transport for the HTTP path
///   to use.
pub fn grpc_mesh_dispatch_falls_through(
    dispatch: GrpcMeshDispatch,
    request_uses_grpc_content_type: bool,
    grpc_web_translated: bool,
    mesh_mtls_supports_request_body: bool,
) -> bool {
    match dispatch {
        GrpcMeshDispatch::Direct => false,
        GrpcMeshDispatch::MeshMtls | GrpcMeshDispatch::MeshMtlsCrossCluster => {
            mesh_mtls_supports_request_body
        }
        GrpcMeshDispatch::RefuseCrossClusterNoTransport
        | GrpcMeshDispatch::RefuseCrossClusterMalformed => false,
        GrpcMeshDispatch::RefuseCrossCluster | GrpcMeshDispatch::RefuseHbone => {
            !request_uses_grpc_content_type && !grpc_web_translated
        }
    }
}

/// Timeout regime for a STREAMING gRPC response body:
/// `(per_frame_read_timeout_ms, absolute_total_deadline)`.
///
/// The typed absolute deadline was established once at request receipt, before
/// plugin work. Consumers must pass it through unchanged; reconstructing it
/// from the relative upstream header would deduct gateway elapsed time twice
/// and re-arm every retry. Without an RPC deadline, the operator fallback is a
/// per-frame idle timeout (`0` = unbounded).
pub fn grpc_streaming_response_deadline(
    request_deadline: Option<tokio::time::Instant>,
    fallback_read_timeout_ms: u64,
) -> (u64, Option<tokio::time::Instant>) {
    match request_deadline {
        Some(deadline) => (0, Some(deadline)),
        None => (fallback_read_timeout_ms, None),
    }
}

const GRPC_ERROR_TRANSPORT_MANAGED_HEADERS: [&str; 13] = [
    "connection",
    "content-length",
    "content-type",
    "grpc-message",
    "grpc-status",
    "grpc-status-details-bin",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Apply initial-response policy to a synthesized Trailers-Only gRPC response,
/// then restore the protocol-owned terminal metadata and framing fields.
///
/// Callers may seed `response_headers` with legitimate gateway metadata such
/// as `allow`; configured policy is applied to that initial-header surface.
/// A hostile policy cannot replace the authoritative gRPC outcome or add
/// Content-Length / transfer framing to the empty response.
pub fn finalize_grpc_error_response_headers(
    response_headers: &mut HashMap<String, String>,
    status: u32,
    message: &str,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) {
    crate::plugins::apply_initial_response_header_policies(
        initial_response_header_policy_plugins,
        response_headers,
    );
    response_headers.retain(|name, _| {
        !GRPC_ERROR_TRANSPORT_MANAGED_HEADERS
            .iter()
            .any(|managed| name.eq_ignore_ascii_case(managed))
    });
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    response_headers.insert("grpc-status".to_string(), status.to_string());
    if !message.is_empty() {
        response_headers.insert("grpc-message".to_string(), message.to_string());
    }
}

/// Build a gRPC error response with proper Trailers-Only encoding and the
/// precomputed initial-response policy for the resolved route.
pub fn build_grpc_error_response_with_policy(
    status: u32,
    message: &str,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) -> hyper::Response<super::ProxyBody> {
    let mut response_headers = HashMap::new();
    finalize_grpc_error_response_headers(
        &mut response_headers,
        status,
        message,
        initial_response_header_policy_plugins,
    );
    // Trailers-only gRPC error: no DATA frames, and gRPC never frames with
    // Content-Length. Remove the field outright so a policy-authored value can
    // neither survive nor be replaced by a misleading `0`.
    crate::proxy::headers::sanitize_client_response_headers_for_wire(
        &mut response_headers,
        crate::proxy::headers::ClientResponseFraming::TrailersOnly,
    );
    crate::proxy::headers::apply_response_headers(
        hyper::Response::builder().status(StatusCode::OK),
        &response_headers,
    )
    .body(super::ProxyBody::empty())
    .unwrap_or_else(|_| {
        let mut response = hyper::Response::new(super::ProxyBody::empty());
        *response.status_mut() = StatusCode::OK;
        response
    })
}

/// Attach an unread frontend gRPC upload to a synthesized Trailers-Only error
/// so its ownership follows the response-body lifecycle (#2057). This is
/// defense-in-depth on the pinned h2 0.4.x transport: h2 already writes the
/// response HEADERS before its permitted NO_ERROR request cancellation, and a
/// raw client can still observe that reset after the complete response.
///
/// #3422 re-confirmed the emitted shape is terminal: the synthesized error body
/// is `ProxyBody::empty()`, whose `is_end_stream()` makes hyper's h2 server take
/// the `send_response(res, end_of_stream = true)` branch, so `grpc-status` ships
/// in a single Trailers-Only HEADERS frame that precedes any reset. A client
/// must therefore treat the observed HEADERS END_STREAM bit — not h2 stream
/// state it can no longer trust after the reset — as the terminal-shape signal.
pub fn attach_held_frontend_grpc_upload(
    mut response: hyper::Response<super::ProxyBody>,
    held_frontend_upload: Option<GrpcBody>,
) -> hyper::Response<super::ProxyBody> {
    if let Some(upload) = held_frontend_upload {
        let body = std::mem::replace(response.body_mut(), super::ProxyBody::empty());
        *response.body_mut() = body.with_held_frontend_grpc_upload(upload);
    }
    response
}

/// Build a gRPC error response without route policy. Pre-routing callers use
/// this form because no resolved plugin configuration exists yet.
pub fn build_grpc_error_response(status: u32, message: &str) -> hyper::Response<super::ProxyBody> {
    build_grpc_error_response_with_policy(status, message, &[])
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
    /// [`Self::grpc_deadline_at`] is `Some` — that regime uses an absolute
    /// end-to-end deadline instead. Without a bound a backend that sends headers
    /// then stalls would pin the streaming guards until the client disconnects.
    pub response_read_timeout_ms: u64,
    /// The request-scoped absolute deadline established before plugin awaits.
    /// Every attempt and response-body wrapper shares this exact instant.
    pub grpc_deadline_at: Option<tokio::time::Instant>,
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
    request_trailers: Option<hyper::HeaderMap>,
    proxy: &Proxy,
    backend_url: &str,
    grpc_pool: &GrpcConnectionPool,
    dns_cache: &DnsCache,
    proxy_headers: &HashMap<String, String>,
    stream_response: bool,
    max_response_body_size_bytes: usize,
    grpc_deadline_at: Option<tokio::time::Instant>,
) -> Result<GrpcResponseKind, GrpcProxyError> {
    proxy_grpc_request_core(
        method,
        headers,
        body_bytes,
        request_trailers,
        proxy,
        backend_url,
        grpc_pool,
        dns_cache,
        proxy_headers,
        stream_response,
        max_response_body_size_bytes,
        grpc_deadline_at,
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
    grpc_deadline_at: Option<tokio::time::Instant>,
    held_frontend_upload: &mut Option<GrpcBody>,
) -> Result<GrpcResponseKind, GrpcProxyError> {
    let (parts, body) = req.into_parts();
    let grpc_body = GrpcBody::Streaming {
        incoming: body,
        bytes_seen: 0,
        max_bytes: max_grpc_recv_size_bytes,
        exceeded: Arc::clone(&body_size_exceeded),
        upload_observer,
    };
    proxy_grpc_streaming_dispatch(
        parts.method,
        parts.headers,
        proxy_headers,
        grpc_body,
        proxy,
        backend_url,
        grpc_pool,
        max_grpc_recv_size_bytes,
        body_size_exceeded,
        grpc_deadline_at,
        held_frontend_upload,
    )
    .await
}

/// Proxy a gRPC request whose body streams in from a channel rather than a
/// hyper `Incoming`.
///
/// Used by the HTTP/3 cross-protocol gRPC bridge: H3's `RequestStream` cannot be
/// expressed as a hyper `Incoming`, so a pump task feeds request DATA frames into
/// `receiver` and this entry wraps it in a [`GrpcBody::Channel`]. Behaviour is
/// otherwise identical to [`proxy_grpc_request_streaming`] — the response is
/// always streamed (the request body is consumed on the wire, so retries are
/// impossible), and request-size limits are enforced inline via the same byte
/// counting. `body_size_exceeded` is the shared overflow flag the channel body
/// sets on limit breach so the caller can surface `RESOURCE_EXHAUSTED`.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_grpc_request_streaming_channel(
    method: hyper::Method,
    headers: hyper::HeaderMap,
    receiver: tokio::sync::mpsc::Receiver<Result<Bytes, ()>>,
    proxy: &Proxy,
    backend_url: &str,
    grpc_pool: &GrpcConnectionPool,
    proxy_headers: &HashMap<String, String>,
    max_grpc_recv_size_bytes: usize,
    body_size_exceeded: Arc<AtomicBool>,
    upload_observer: Option<Arc<dyn GrpcUploadTerminationObserver>>,
    grpc_deadline_at: Option<tokio::time::Instant>,
    held_frontend_upload: &mut Option<GrpcBody>,
) -> Result<GrpcResponseKind, GrpcProxyError> {
    let grpc_body = GrpcBody::Channel {
        receiver,
        bytes_seen: 0,
        max_bytes: max_grpc_recv_size_bytes,
        exceeded: Arc::clone(&body_size_exceeded),
        upload_observer,
    };
    proxy_grpc_streaming_dispatch(
        method,
        headers,
        proxy_headers,
        grpc_body,
        proxy,
        backend_url,
        grpc_pool,
        max_grpc_recv_size_bytes,
        body_size_exceeded,
        grpc_deadline_at,
        held_frontend_upload,
    )
    .await
}

/// Shared dispatch for the streaming gRPC request entry points
/// ([`proxy_grpc_request_streaming`] over a hyper `Incoming`, and
/// [`proxy_grpc_request_streaming_channel`] over an mpsc channel). Takes a
/// pre-built `GrpcBody` — the only difference between the two paths is the body
/// source — plus the request `method`/`headers`, merges + strips headers,
/// applies the per-route Host override, sends to the gRPC pool with the
/// streaming-aware timeout, and returns the live streaming response. One core
/// keeps the two paths from drifting on header handling, timeout policy, or
/// size-overflow classification.
#[allow(clippy::too_many_arguments)]
async fn proxy_grpc_streaming_dispatch(
    method: hyper::Method,
    mut headers: hyper::HeaderMap,
    proxy_headers: &HashMap<String, String>,
    grpc_body: GrpcBody,
    proxy: &Proxy,
    backend_url: &str,
    grpc_pool: &GrpcConnectionPool,
    max_grpc_recv_size_bytes: usize,
    body_size_exceeded: Arc<AtomicBool>,
    grpc_deadline_at: Option<tokio::time::Instant>,
    held_frontend_upload: &mut Option<GrpcBody>,
) -> Result<GrpcResponseKind, GrpcProxyError> {
    let uri: hyper::Uri = match backend_url.parse() {
        Ok(uri) => uri,
        Err(e) => {
            // Preserve the unread frontend upload so the caller controls its
            // termination relative to the synthesized Trailers-Only response:
            // response-body ownership on H2 and post-HEADERS+FIN on H3 (#2057).
            *held_frontend_upload = Some(grpc_body);
            return Err(GrpcProxyError::Internal(format!(
                "Invalid backend URL: {}",
                e
            )));
        }
    };

    // Build headers: merge plugin/proxy headers on top of the inbound
    // request's headers, then run the gRPC-specific strip on the union.
    // The helper encapsulates the merge-then-strip ordering so this
    // path and `proxy_grpc_request_core` cannot drift, and so neither
    // can call the steps in the wrong order. See `proxy::headers` for
    // why merging FIRST is required and why `te: trailers` is
    // synthesised at the end.
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
    // The absolute client deadline is consumed directly by the first branch
    // below. Compute the relative operator fallback only when no client policy
    // exists; storing a remaining client duration here is dead because
    // `response_read_timeout_ms` is intentionally ignored whenever the
    // absolute deadline is present.
    let effective_timeout_ms = if grpc_deadline_at.is_none() {
        streaming_effective_timeout_ms(&headers, proxy)
    } else {
        None
    };

    // Acquire the backend sender BEFORE moving the frontend upload into the
    // outbound request. A connect/handshake failure (accept-then-RST) must
    // return the unread Incoming/Channel body so the caller owns termination:
    // H2 retains it with the response as defense-in-depth, while H3 must defer
    // channel drop/STOP_SENDING until after Trailers-Only HEADERS+FIN (#2057).
    let mut sender = if let Some(deadline) = grpc_deadline_at {
        match tokio::time::timeout_at(deadline, grpc_pool.get_sender(proxy)).await {
            Err(_) => {
                *held_frontend_upload = Some(grpc_body);
                return Err(GrpcProxyError::ClientDeadlineExceeded(
                    "gRPC deadline exceeded during backend connection acquisition".to_string(),
                ));
            }
            Ok(Err(e)) => {
                *held_frontend_upload = Some(grpc_body);
                return Err(e);
            }
            Ok(Ok(sender)) => sender,
        }
    } else {
        match grpc_pool.get_sender(proxy).await {
            Ok(sender) => sender,
            Err(e) => {
                *held_frontend_upload = Some(grpc_body);
                return Err(e);
            }
        }
    };

    // Remaining-budget rewrite AFTER acquisition, for the same reason as the
    // buffered path: a cold dial must not be re-added to the client's budget.
    if let Some(deadline) = grpc_deadline_at {
        apply_remaining_grpc_timeout_header(&mut headers, deadline);
    }

    let mut backend_req = Request::new(grpc_body);
    *backend_req.method_mut() = method;
    *backend_req.uri_mut() = uri;
    *backend_req.headers_mut() = headers;

    let response = if let Some(deadline) = grpc_deadline_at {
        tokio::time::timeout_at(deadline, sender.send_request(backend_req))
            .await
            .map_err(|_| {
                warn!("gRPC deadline exceeded waiting for streaming RPC response headers");
                GrpcProxyError::ClientDeadlineExceeded(
                    "gRPC deadline exceeded waiting for streaming RPC response headers".to_string(),
                )
            })?
            .map_err(|e| {
                if body_size_exceeded.load(Ordering::Acquire) {
                    return GrpcProxyError::ResourceExhausted(format!(
                        "gRPC request payload size exceeds maximum of {} bytes",
                        max_grpc_recv_size_bytes
                    ));
                }
                // Streaming / channel uploads are unreplayable — keep post-wire
                // classification even when hyper reports `is_canceled`, but still
                // drop the stale pooled sender so the next RPC dials fresh.
                if e.is_canceled() {
                    grpc_pool.invalidate_shards_for_proxy(proxy);
                }
                error!("gRPC backend request failed (streaming body): {}", e);
                GrpcProxyError::backend_unavailable_with_source(
                    GrpcBackendUnavailableKind::BackendRequest,
                    format!("Backend request failed: {}", e),
                    e,
                )
            })?
    } else if let Some(timeout_ms) = effective_timeout_ms {
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
                if e.is_canceled() {
                    grpc_pool.invalidate_shards_for_proxy(proxy);
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
            if e.is_canceled() {
                grpc_pool.invalidate_shards_for_proxy(proxy);
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
        grpc_deadline_at,
    }))
}

/// Collect the incoming gRPC request body and split the `Request<Incoming>` into
/// its constituent parts for separate validation and dispatch.
///
/// This is used when plugins or retry replay require request body buffering for
/// gRPC proxies. The body bytes, method, and headers are returned so the caller
/// can run plugin hooks before dispatching via `proxy_grpc_request_core`.
pub(crate) async fn collect_grpc_request_body(
    req: Request<Incoming>,
    max_grpc_recv_size_bytes: usize,
    request_body_read_timeout_ms: u64,
    grpc_deadline_at: Option<tokio::time::Instant>,
) -> Result<(hyper::Method, hyper::HeaderMap, Bytes), GrpcRequestBodyCollectError> {
    let (parts, body) = req.into_parts();
    let body_bytes = if max_grpc_recv_size_bytes > 0 {
        let limited = http_body_util::Limited::new(body, max_grpc_recv_size_bytes);
        let collected = super::collect_request_body_with_deadline(
            BodyExt::collect(limited),
            grpc_deadline_at,
            request_body_read_timeout_ms,
        )
        .await
        .map_err(map_request_body_wait_error)?;
        match collected {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                if is_length_limit_error(e.as_ref()) {
                    return Err(GrpcRequestBodyCollectError::Proxy(
                        GrpcProxyError::ResourceExhausted(format!(
                            "gRPC request payload size exceeds maximum of {} bytes",
                            max_grpc_recv_size_bytes
                        )),
                    ));
                }
                return Err(GrpcRequestBodyCollectError::Proxy(
                    GrpcProxyError::Internal(format!("Failed to read request body: {}", e)),
                ));
            }
        }
    } else {
        super::collect_request_body_with_deadline(
            BodyExt::collect(body),
            grpc_deadline_at,
            request_body_read_timeout_ms,
        )
        .await
        .map_err(map_request_body_wait_error)?
        .map_err(|e| {
            GrpcRequestBodyCollectError::Proxy(GrpcProxyError::Internal(format!(
                "Failed to read request body: {}",
                e
            )))
        })?
        .to_bytes()
    };
    Ok((parts.method, parts.headers, body_bytes))
}

/// Core gRPC proxy logic shared by initial requests and retries.
///
/// When `stream_response` is true, returns `GrpcResponseKind::Streaming` with
/// the live `Incoming` body instead of buffering the full response. The caller
/// is responsible for ensuring this is only used when retries are not needed.
///
/// `request_trailers` carries validated end-of-stream request metadata that did
/// not arrive as HTTP/2 trailers — today, a gRPC-Web body trailer frame. It is
/// sent as a real TRAILERS frame after the buffered DATA, and it is passed to
/// every attempt because a retry replays the same complete request.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_grpc_request_core(
    method: hyper::Method,
    mut headers: hyper::HeaderMap,
    body_bytes: Bytes,
    request_trailers: Option<hyper::HeaderMap>,
    proxy: &Proxy,
    backend_url: &str,
    grpc_pool: &GrpcConnectionPool,
    _dns_cache: &DnsCache,
    proxy_headers: &HashMap<String, String>,
    stream_response: bool,
    max_response_body_size_bytes: usize,
    grpc_deadline_at: Option<tokio::time::Instant>,
) -> Result<GrpcResponseKind, GrpcProxyError> {
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

    // Carry forward the receipt-anchored absolute deadline from
    // `prepare_request_deadline` (parsed before before_proxy plugins and
    // body awaits). Post-merge header mutations do not re-arm this budget;
    // before_proxy plugins cannot extend or re-anchor RPC time limits via
    // grpc-timeout. Two distinct timeout regimes:
    //  * client_grpc_deadline_at — a client-supplied absolute end-to-end
    //    deadline established once at request receipt (via
    //    `prepare_request_deadline`, independent of the `grpc_deadline`
    //    plugin). Pool acquisition consumes it together with the pool's own
    //    connect timeout. After acquisition, backend_read_timeout_ms may impose
    //    an earlier response ceiling, but it never acts as a connect timeout.
    //    The resulting response deadline bounds the header wait + body
    //    collection as ONE shared budget — otherwise a slow backend gets up to
    //    ~2x the client's stated deadline (the F11 bug this PR fixes).
    //    Retries and backoff consume the SAME Instant; the relative
    //    `grpc-timeout` header is rewritten to the remaining budget before
    //    each attempt and is never re-anchored from the original relative
    //    value at dispatch time.
    //  * per_phase_read_ms — the operator backend_read_timeout_ms safety net
    //    used when the client set no deadline. This is a PER-READ stall guard,
    //    not an RPC budget, so each phase (header wait, body collection) gets a
    //    FRESH full budget. Folding it into a single end-to-end budget would
    //    newly time out a large buffered response from a slow-but-progressing
    //    backend that previously succeeded, so the two phases stay independent —
    //    matching the long-standing operator semantics and the streaming path.
    let client_grpc_deadline_at = grpc_deadline_at;
    let per_phase_read_ms =
        if client_grpc_deadline_at.is_none() && proxy.backend_read_timeout_ms > 0 {
            Some(proxy.backend_read_timeout_ms)
        } else {
            None
        };

    // Effective per-frame idle read timeout for the STREAMING response body,
    // computed before `headers` is moved into the backend request below. Same
    // post-plugin grpc-timeout (uncapped) / backend_read_timeout_ms-fallback
    // rule as the streaming dispatch's header-wait deadline, so a backend that
    // streams headers then stalls cannot pin the streaming guards until the
    // client disconnects. Unused on the buffered path. 0 = unbounded.
    let streaming_response_read_timeout_ms = if client_grpc_deadline_at.is_some() {
        0
    } else {
        streaming_effective_timeout_ms(&headers, proxy).unwrap_or(0)
    };

    // A validated end-of-stream metadata block (today: a gRPC-Web request
    // trailer frame the `grpc_web` plugin split off the body) is re-emitted as
    // a native HTTP/2 TRAILERS frame after the DATA. An empty map is treated as
    // "no trailers" so a stray empty block cannot cost the backend a frame.
    let mut backend_req = Request::new(match request_trailers {
        Some(trailers) if !trailers.is_empty() => GrpcBody::BufferedWithTrailers {
            data: Some(body_bytes),
            trailers: Some(trailers),
        },
        _ => GrpcBody::Buffered(Full::new(body_bytes)),
    });
    *backend_req.method_mut() = method;
    *backend_req.uri_mut() = uri;
    *backend_req.headers_mut() = headers;
    // Pool acquisition is bounded by the end-to-end client deadline plus the
    // pool's own backend_connect_timeout_ms. backend_read_timeout_ms starts only
    // after a sender exists; applying it here would turn a read-stall policy
    // into an unintended shorter connect timeout.
    let mut sender = if let Some(client_deadline) = client_grpc_deadline_at {
        tokio::time::timeout_at(client_deadline, grpc_pool.get_sender(proxy))
            .await
            .map_err(|_| {
                GrpcProxyError::ClientDeadlineExceeded(
                    "gRPC deadline exceeded during backend connection acquisition".to_string(),
                )
            })??
    } else {
        grpc_pool.get_sender(proxy).await?
    };

    // Rewrite the outbound `grpc-timeout` to the remaining budget AFTER pool
    // acquisition. Computing it before the dial would forward a value that
    // over-states the budget by however long the connect/handshake took (up to
    // `backend_connect_timeout_ms` on a cold pool, or the whole retry backoff
    // on a redial), which is the same re-arming class of error #2933 fixes,
    // just at a smaller scale. Every attempt still gets exactly one rewrite.
    if let Some(deadline) = client_grpc_deadline_at {
        apply_remaining_grpc_timeout_header(backend_req.headers_mut(), deadline);
    }

    // A client deadline remains one absolute end-to-end ceiling. Layer the
    // operator read timeout over response processing only, after connection
    // acquisition, and keep the earlier source typed for accounting.
    let backend_read_deadline_at = if proxy.backend_read_timeout_ms > 0 {
        tokio::time::Instant::now()
            .checked_add(Duration::from_millis(proxy.backend_read_timeout_ms))
    } else {
        None
    };
    let response_deadline_at = match (client_grpc_deadline_at, backend_read_deadline_at) {
        (Some(client), Some(read)) => Some(client.min(read)),
        (Some(client), None) => Some(client),
        (None, _) => None,
    };
    let response_deadline_is_client = client_grpc_deadline_at
        .is_some_and(|client| response_deadline_at.is_some_and(|effective| client <= effective));
    let response_deadline_ms = response_deadline_at.map(|deadline| {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        crate::plugins::grpc_deadline::duration_millis_ceil_saturating(remaining).unwrap_or(1)
    });
    let send_fut = sender.send_request(backend_req);
    let map_send_err = |e: hyper::Error| {
        // Buffered unary/client bodies are fully held — hyper `is_canceled`
        // proves the request never hit the wire, so classify pre-wire and
        // drop the stale pooled sender for the next attempt / RPC.
        if e.is_canceled() {
            grpc_pool.invalidate_shards_for_proxy(proxy);
        }
        error!("gRPC: backend request failed: {}", e);
        if e.is_timeout() {
            GrpcProxyError::BackendTimeout {
                kind: GrpcTimeoutKind::Read,
                message: format!("Backend timeout: {}", e),
            }
        } else {
            let kind = if e.is_canceled() {
                GrpcBackendUnavailableKind::DispatchCanceled
            } else {
                GrpcBackendUnavailableKind::BackendRequest
            };
            GrpcProxyError::backend_unavailable_with_source(
                kind,
                format!("Backend error: {}", e),
                e,
            )
        }
    };
    // When a client deadline exists, compute ONE absolute effective response
    // deadline shared via timeout_at by both the header wait here and the body
    // collection below. The operator fallback (`per_phase_read_ms`) instead
    // arms a fresh per-phase timer in each phase when no client deadline exists,
    // preserving the prior per-read stall-guard semantics.
    let shared_response_deadline =
        response_deadline_at.map(|deadline| (response_deadline_ms.unwrap_or(1), deadline));
    let response = if let Some((timeout_ms, deadline)) = shared_response_deadline {
        tokio::time::timeout_at(deadline, send_fut)
            .await
            .map_err(|_| {
                if response_deadline_is_client {
                    warn!("gRPC client deadline exceeded waiting for backend response headers");
                    GrpcProxyError::ClientDeadlineExceeded(
                        "gRPC deadline exceeded waiting for backend response headers".to_string(),
                    )
                } else {
                    warn!(
                        "gRPC: read timeout ({}ms, end-to-end) waiting for backend response",
                        timeout_ms
                    );
                    GrpcProxyError::BackendTimeout {
                        kind: GrpcTimeoutKind::Read,
                        message: format!("Read timeout after {}ms (end-to-end)", timeout_ms),
                    }
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
            grpc_deadline_at: client_grpc_deadline_at,
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

    if let Some((timeout_ms, deadline)) = shared_response_deadline {
        // Same effective deadline as the header wait above — when a client
        // deadline exists the header wait and body collection share one budget,
        // not two.
        tokio::time::timeout_at(deadline, body_collection)
            .await
            .map_err(|_| {
                if response_deadline_is_client {
                    warn!("gRPC client deadline exceeded while collecting response body");
                    GrpcProxyError::ClientDeadlineExceeded(
                        "gRPC deadline exceeded while collecting response body".to_string(),
                    )
                } else {
                    warn!(
                        "gRPC: read timeout ({}ms, end-to-end) while collecting response body",
                        timeout_ms
                    );
                    GrpcProxyError::BackendTimeout {
                        kind: GrpcTimeoutKind::Read,
                        message: format!("Body read timeout after {}ms (end-to-end)", timeout_ms),
                    }
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
            // Preserve gRPC duplicate metadata semantics: HeaderMap yields each
            // value separately, and the string-map representation joins them
            // with newlines (same convention as multi-value Set-Cookie) so the
            // gRPC-Web trailer-frame encoder can emit one `key: value\r\n` line
            // per occurrence.
            out.entry(k.as_str().to_string())
                .and_modify(|existing| {
                    existing.push('\n');
                    existing.push_str(vs);
                })
                .or_insert_with(|| vs.to_string());
        }
    }
}

/// Append one buffered string-map trailer entry onto a native wire `HeaderMap`.
///
/// [`collect_buffered_grpc_trailers`] joins duplicate metadata with LF.
/// `HeaderValue::from_str` rejects embedded LF, so H2/H3 buffered emitters must
/// split and [`HeaderMap::append`] each occurrence. A CR-bearing field is
/// skipped entirely (matching gRPC-Web trailer-frame encoding) so injection
/// cannot create an additional logical trailer line from a single map value.
pub(crate) fn append_buffered_grpc_trailer_entry(
    trailers: &mut hyper::HeaderMap,
    name: &str,
    joined_value: &str,
) {
    let Ok(header_name) = hyper::header::HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    if joined_value.contains('\r') {
        return;
    }
    for occurrence in joined_value.split('\n') {
        if let Ok(value) = hyper::header::HeaderValue::from_str(occurrence) {
            trailers.append(header_name.clone(), value);
        }
    }
}

/// Build a native trailer `HeaderMap` from the buffered LF-joined string map.
pub(crate) fn buffered_grpc_trailers_to_header_map(
    map: &HashMap<String, String>,
) -> hyper::HeaderMap {
    let mut trailers = hyper::HeaderMap::new();
    for (name, value) in map {
        append_buffered_grpc_trailer_entry(&mut trailers, name, value);
    }
    trailers
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

/// Rewrite the outbound `grpc-timeout` header to the remaining budget of a
/// receipt-anchored absolute deadline.
///
/// Call once per backend attempt (including the first), as late as possible —
/// after the sender has been acquired — so the dial/handshake time is not
/// silently handed back to the backend. Retries must forward
/// the decremented remaining timeout rather than re-arming the client's
/// original relative value. Formatting (millisecond precision when it fits the
/// gRPC 8-digit wire limit, otherwise coarsened to seconds/minutes/hours) is
/// shared with the `grpc_deadline` plugin so the two cannot drift.
///
/// An already-expired deadline forwards the minimum legal value `1m` rather
/// than the invalid `0m`; the gateway's own `timeout_at` guards still terminate
/// the RPC, so this only avoids handing the backend a malformed header.
pub(crate) fn apply_remaining_grpc_timeout_header(
    headers: &mut hyper::HeaderMap,
    deadline: tokio::time::Instant,
) {
    let value = remaining_grpc_timeout_header_value(deadline);
    headers.insert("grpc-timeout", value);
}

/// Build the wire value for the remaining portion of a receipt-anchored gRPC
/// deadline. Shared by native gRPC (`HeaderMap`) and pass-through gRPC-Web
/// (`reqwest::RequestBuilder`) so neither transport can re-arm the original
/// relative header on a later attempt.
pub(crate) fn remaining_grpc_timeout_header_value(
    deadline: tokio::time::Instant,
) -> hyper::header::HeaderValue {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let ms = crate::plugins::grpc_deadline::duration_millis_ceil_saturating(remaining).unwrap_or(1);
    let timeout_val = crate::plugins::grpc_deadline::format_grpc_timeout_ms(ms.max(1));
    // The shared formatter only emits ASCII digits plus one unit letter, all
    // accepted by HeaderValue. Avoid unwrap/expect on the request path anyway;
    // the minimum legal gRPC timeout is a safe fail-closed fallback.
    hyper::header::HeaderValue::from_str(&timeout_val)
        .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("1m"))
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

    #[test]
    fn terminal_grpc_status_prefers_trailers_and_preserves_ok() {
        let headers = HashMap::from([("grpc-status".to_string(), "14".to_string())]);
        let trailers = HashMap::from([("grpc-status".to_string(), "0".to_string())]);
        assert_eq!(grpc_status_from_maps(&trailers, &headers), Some(0));
        assert_eq!(
            grpc_admission_status_from_maps(&trailers, &headers, 200),
            200
        );

        let malformed = HashMap::from([("grpc-status".to_string(), "hostile".to_string())]);
        assert_eq!(
            grpc_status_from_maps(&malformed, &HashMap::new()),
            Some(u32::MAX)
        );
        assert_eq!(
            grpc_admission_status_from_maps(&malformed, &HashMap::new(), 200),
            500
        );
    }

    #[test]
    fn grpc_status_from_maps_uses_first_valid_lf_joined_occurrence() {
        // collect_buffered_grpc_trailers joins duplicate grpc-status with LF.
        // Prefer the first valid occurrence (matching gRPC-Web frame emit).
        let trailers = HashMap::from([("grpc-status".to_string(), "0\n14".to_string())]);
        assert_eq!(grpc_status_from_maps(&trailers, &HashMap::new()), Some(0));

        let trailers = HashMap::from([("grpc-status".to_string(), "hostile\n7".to_string())]);
        assert_eq!(grpc_status_from_maps(&trailers, &HashMap::new()), Some(7));

        // CR injection must not yield a success parse of a smuggled suffix.
        let trailers = HashMap::from([("grpc-status".to_string(), "0\r\n14".to_string())]);
        assert_eq!(
            grpc_status_from_maps(&trailers, &HashMap::new()),
            Some(u32::MAX)
        );
    }

    #[test]
    fn final_grpc_status_metadata_tracks_rewrites_and_missing_status() {
        let mut metadata = HashMap::from([("grpc_status".to_string(), "14".to_string())]);
        let rewritten = HashMap::from([("grpc-status".to_string(), "7".to_string())]);
        refresh_grpc_status_metadata(&mut metadata, &rewritten, &HashMap::new());
        assert_eq!(metadata.get("grpc_status").map(String::as_str), Some("7"));

        refresh_grpc_status_metadata(&mut metadata, &HashMap::new(), &HashMap::new());
        assert_eq!(metadata.get("grpc_status").map(String::as_str), Some("2"));
    }

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

        // The caller-supplied typed deadline is the sole absolute budget.
        // Reconstructing from the relative header at dispatch would re-arm
        // a fresh full budget on every retry attempt.
        assert!(
            body.contains("let client_grpc_deadline_at = grpc_deadline_at;"),
            "the request-scoped typed deadline must be the sole absolute source"
        );
        assert!(
            body.contains(
                "apply_remaining_grpc_timeout_header(backend_req.headers_mut(), deadline)"
            ),
            "each attempt must forward a decremented remaining grpc-timeout, \
             measured after pool acquisition"
        );
        assert!(
            !body.contains("grpc_deadline_at.or_else(||"),
            "must not re-parse and re-anchor grpc-timeout at dispatch time"
        );
        assert!(
            body.contains("timeout_at(client_deadline, grpc_pool.get_sender(proxy))"),
            "pool acquisition must be bounded by only the client deadline"
        );
        let sender_acquisition = body
            .find("let mut sender =")
            .expect("sender acquisition not found");
        let backend_read_deadline = body
            .find("let backend_read_deadline_at =")
            .expect("backend read deadline not found");
        assert!(
            sender_acquisition < backend_read_deadline,
            "backend_read_timeout_ms must start after connection acquisition"
        );
        assert!(
            body.contains("let shared_response_deadline =")
                && body.contains("response_deadline_at.map(|deadline|"),
            "one effective response deadline must be shared by response phases"
        );
        let timeout_at = body.matches("tokio::time::timeout_at(").count();
        assert_eq!(
            timeout_at, 3,
            "pool acquisition must consume the client deadline while header wait \
             and body collection consume the same response deadline; found \
             {timeout_at} timeout_at calls."
        );

        // Operator backend_read_timeout Instant add must stay overflow-guarded.
        assert!(
            body.contains("checked_add(Duration::from_millis(proxy.backend_read_timeout_ms)"),
            "backend_read_timeout_ms must use checked_add to avoid an Instant overflow panic"
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
    fn collect_buffered_grpc_trailers_preserves_duplicate_metadata() {
        let mut trailer_map = hyper::HeaderMap::new();
        trailer_map.insert("grpc-status", "0".parse().unwrap());
        trailer_map.insert("request-id", "first".parse().unwrap());
        trailer_map.append("request-id", "second".parse().unwrap());

        let mut out: HashMap<String, String> = HashMap::new();
        collect_buffered_grpc_trailers(&trailer_map, &mut out);

        assert_eq!(
            out.get("request-id").map(String::as_str),
            Some("first\nsecond"),
            "duplicate gRPC metadata must be newline-joined for trailer-frame encoding"
        );
    }

    #[test]
    fn buffered_native_emit_splits_lf_joined_duplicates_including_grpc_status() {
        // Native H2/H3 buffered emit must append each LF-separated occurrence;
        // HeaderValue::from_str would otherwise drop the entire multi-value.
        let joined = HashMap::from([
            ("grpc-status".to_string(), "0\n14".to_string()),
            ("request-id".to_string(), "first\nsecond".to_string()),
        ]);
        let wire = buffered_grpc_trailers_to_header_map(&joined);

        let status: Vec<_> = wire
            .get_all("grpc-status")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(status, vec!["0", "14"]);

        let request_ids: Vec<_> = wire
            .get_all("request-id")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(request_ids, vec!["first", "second"]);

        // CR-bearing fields are skipped entirely (no partial injection).
        let hostile = HashMap::from([("x-meta".to_string(), "ok\r\ninjected".to_string())]);
        let wire = buffered_grpc_trailers_to_header_map(&hostile);
        assert!(wire.get("x-meta").is_none());
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
