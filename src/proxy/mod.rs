//! Core reverse proxy engine — the gateway's hot path.
//!
//! This module handles all HTTP/HTTPS/WebSocket proxy requests through a
//! multi-phase plugin pipeline:
//!
//! 1. **Route matching** — `RouterCache::find_proxy()` (O(1) cached, longest-prefix)
//! 2. **Plugin: on_request_received** — tracing, correlation ID, CORS preflight,
//!    early termination, IP restriction, bot detection
//! 3. **Plugin: authenticate** — mtls_auth, jwks_auth, jwt_auth, key_auth, basic_auth, hmac_auth
//! 4. **Plugin: authorize** — access_control, rate_limiting (consumer mode)
//! 5. **Plugin: before_proxy** — request/response policy before backend dispatch:
//!    request size limiting, GraphQL guardrails, AI plugins, request transformation,
//!    response caching preparation, gRPC deadline injection
//! 6. **Plugin: transform_request_body / on_final_request_body** — buffered request-body
//!    rewrites and final validation before backend dispatch
//! 7. **Backend dispatch** — protocol-specific: reqwest (HTTP), GrpcConnectionPool (gRPC),
//!    Http2ConnectionPool (H2 direct), Http3ConnectionPool (QUIC), WebSocket upgrade
//! 8. **Plugin: after_proxy** — CORS headers, response caching metadata, response transforms,
//!    response size limiting, AI rate limiter
//! 9. **Plugin: on_response_body** — raw backend body inspection before transforms:
//!    AI token metrics, AI rate limiter
//! 10. **Plugin: transform_response_body** — body rewrites (e.g., response_transformer)
//! 11. **Plugin: on_final_response_body** — final client-visible body validation/storage:
//!     body validation, response size limiting, response caching
//! 12. **Plugin: log** — stdout/HTTP logging, Prometheus, OpenTelemetry
//!
//! Key design principles:
//! - **Lock-free reads**: All config access uses `ArcSwap::load()` — no mutexes on the hot path
//! - **Pre-computed indexes**: Route table, plugin cache, consumer index rebuilt at config reload
//! - **Streaming by default**: Response bodies are streamed unless a plugin requires buffering
//! - **Atomic config reload**: `update_config()` and `apply_incremental()` swap config atomically

pub mod backend_dispatch;
pub mod body;
pub mod client_ip;
pub mod deferred_log;
pub mod grpc_proxy;
pub mod http2_pool;
pub mod sni;
pub mod stream_listener;
pub mod tcp_proxy;
pub mod udp_batch;
pub mod udp_proxy;

use arc_swap::ArcSwap;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, upgrade::OnUpgrade, upgrade::Upgraded};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};
use tokio_tungstenite::{
    WebSocketStream, connect_async_tls_with_config, tungstenite::handshake::derive_accept_key,
};
use tracing::{debug, error, info, trace, warn};

use crate::circuit_breaker::CircuitBreakerCache;
use crate::config::PoolConfig;
use crate::config::types::{
    AuthMode, BackendProtocol, GatewayConfig, Proxy, ResponseBodyMode, UpstreamTarget,
};
use crate::connection_pool::ConnectionPool;
use crate::consumer_index::ConsumerIndex;
use crate::dns::DnsCache;
use crate::health_check::HealthChecker;
use crate::http3::client::Http3ConnectionPool;
use crate::load_balancer::{HashOnStrategy, LoadBalancerCache};
use crate::plugin_cache::{PluginCache, PluginCapabilities};
use crate::plugins::{
    Plugin, PluginResult, ProxyProtocol, RequestContext, TransactionSummary,
    WebSocketFrameDirection,
};
use crate::retry;
use crate::retry::ResponseBody;
use crate::router_cache::RouterCache;
use crate::service_discovery::ServiceDiscoveryManager;
use crate::tls::{NoVerifier, TlsPolicy};

pub use self::body::ProxyBody;
use self::grpc_proxy::{GrpcConnectionPool, GrpcProxyError, GrpcResponseKind};
use self::http2_pool::Http2ConnectionPool;

/// Static empty HashMap used by rejection responses to avoid allocating a new
/// HashMap on every error path. ~20+ rejection sites in the proxy handler pass
/// `&HashMap::new()` — this eliminates those per-rejection allocations.
static EMPTY_HEADERS: std::sync::LazyLock<HashMap<String, String>> =
    std::sync::LazyLock::new(HashMap::new);

/// Boxed future type for pool warmup tasks.
/// Returns `Ok(description)` on success or `Err(message)` on failure.
type WarmupTask =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send>>;

/// Check if the request is a WebSocket upgrade request.
///
/// Uses ASCII case-insensitive comparisons to avoid per-request `to_lowercase()`
/// String allocations on the hot path.
///
/// Validates the `Sec-WebSocket-Key` header format: RFC 6455 §4.1 requires it to
/// be a base64-encoded 16-byte nonce (exactly 24 base64 characters). A malformed
/// key causes the handshake to be treated as a non-WebSocket request, which the
/// backend will handle as a regular HTTP request rather than proceeding with a
/// broken upgrade.
/// Check if the request is an HTTP/2 Extended CONNECT WebSocket request (RFC 8441).
///
/// In HTTP/2, WebSocket upgrades use the CONNECT method with a `:protocol = "websocket"`
/// pseudo-header instead of the HTTP/1.1 Upgrade mechanism. hyper exposes the pseudo-header
/// as a `hyper::ext::Protocol` extension on the request.
///
/// Generic over the body type so unit tests can use `Request<()>` without constructing
/// an `Incoming` body.
pub fn is_h2_websocket_connect<B>(req: &Request<B>) -> bool {
    req.method() == hyper::Method::CONNECT
        && req.version() == hyper::Version::HTTP_2
        && req
            .extensions()
            .get::<hyper::ext::Protocol>()
            .is_some_and(|p| p.as_ref().eq_ignore_ascii_case(b"websocket"))
}

fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    let headers = req.headers();
    let connection = headers.get("connection").and_then(|v| v.to_str().ok());
    let upgrade = headers.get("upgrade").and_then(|v| v.to_str().ok());
    let sec_key = headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok());
    let sec_version = headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok());

    connection.is_some_and(|conn| {
        // The Connection header can contain comma-separated values (e.g., "keep-alive, Upgrade").
        // Split on commas and check each token case-insensitively without allocating.
        conn.split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    }) && upgrade.is_some_and(|up| up.eq_ignore_ascii_case("websocket"))
        && sec_key.is_some_and(is_valid_websocket_key)
        && (sec_version == Some("13"))
}

/// Validate that a `Sec-WebSocket-Key` value is a base64-encoded 16-byte nonce.
///
/// RFC 6455 §4.1 requires the key to be exactly 16 bytes of random data,
/// base64-encoded to 24 characters (16 bytes → 22 base64 chars + 2 padding `=`).
pub fn is_valid_websocket_key(key: &str) -> bool {
    use base64::Engine;
    key.len() == 24
        && base64::engine::general_purpose::STANDARD
            .decode(key)
            .is_ok_and(|bytes| bytes.len() == 16)
}

/// Parse an HTTP method string into a `reqwest::Method`.
///
/// Common methods are matched as constants (zero-cost), with a fallback to
/// `from_bytes()` for non-standard methods. Extracted as a helper to avoid
/// duplicating this match block across `proxy_to_backend` and `proxy_to_backend_retry`
/// (code deduplication improves instruction cache utilization).
fn parse_reqwest_method(method: &str) -> Result<reqwest::Method, ()> {
    match method {
        "GET" => Ok(reqwest::Method::GET),
        "POST" => Ok(reqwest::Method::POST),
        "PUT" => Ok(reqwest::Method::PUT),
        "DELETE" => Ok(reqwest::Method::DELETE),
        "PATCH" => Ok(reqwest::Method::PATCH),
        "HEAD" => Ok(reqwest::Method::HEAD),
        "OPTIONS" => Ok(reqwest::Method::OPTIONS),
        other => reqwest::Method::from_bytes(other.as_bytes()).map_err(|_| ()),
    }
}

/// Whether HTTPS requests may use the direct hyper HTTP/2 backend pool.
///
/// Request-body plugins require buffering and transformation before forwarding,
/// which the direct H2 path does not implement. Those requests must stay on the
/// reqwest path so the final backend body matches the plugin output.
pub(crate) fn can_use_direct_http2_pool(
    enable_http2: bool,
    retain_request_body: bool,
    requires_request_body_buffering: bool,
) -> bool {
    enable_http2 && !retain_request_body && !requires_request_body_buffering
}

enum ClientRequestBody {
    Streaming(Box<Request<Incoming>>),
    Buffered(Vec<u8>),
}

enum RequestBodyBufferError {
    TooLarge,
    ClientDisconnected(String),
}

pub(crate) fn request_may_have_body(method: &str, headers: &HashMap<String, String>) -> bool {
    !matches!(method, "GET" | "HEAD" | "OPTIONS")
        || headers.contains_key("content-length")
        || headers.contains_key("transfer-encoding")
}

async fn buffer_request_body_for_before_proxy(
    request: Request<Incoming>,
    method: &str,
    headers: &HashMap<String, String>,
    max_request_body_size_bytes: usize,
) -> Result<ClientRequestBody, RequestBodyBufferError> {
    if !request_may_have_body(method, headers) {
        return Ok(ClientRequestBody::Streaming(Box::new(request)));
    }

    if max_request_body_size_bytes > 0
        && let Some(content_length) = headers.get("content-length")
        && let Ok(len) = content_length.parse::<usize>()
        && len > max_request_body_size_bytes
    {
        return Err(RequestBodyBufferError::TooLarge);
    }

    let (_parts, body) = request.into_parts();
    let body_bytes = if max_request_body_size_bytes > 0 {
        let limited = http_body_util::Limited::new(body, max_request_body_size_bytes);
        limited
            .collect()
            .await
            .map_err(|_| RequestBodyBufferError::TooLarge)?
            .to_bytes()
            .to_vec()
    } else {
        body.collect()
            .await
            .map_err(|e| RequestBodyBufferError::ClientDisconnected(e.to_string()))?
            .to_bytes()
            .to_vec()
    };

    Ok(ClientRequestBody::Buffered(body_bytes))
}

pub(crate) fn store_request_body_metadata(
    ctx: &mut RequestContext,
    body: &[u8],
    needs_body_bytes: bool,
) {
    ctx.metadata.insert(
        "request_body_size_bytes".to_string(),
        body.len().to_string(),
    );
    if let Ok(body_str) = std::str::from_utf8(body) {
        ctx.metadata
            .insert("request_body".to_string(), body_str.to_string());
    } else {
        ctx.metadata.remove("request_body");
    }
    // Only allocate a binary copy when a plugin explicitly needs raw bytes
    // (e.g., request_mirror with gRPC protobuf). This avoids a per-request
    // Bytes::copy_from_slice for the common case where plugins only read
    // the UTF-8 metadata string.
    if needs_body_bytes {
        ctx.request_body_bytes = Some(bytes::Bytes::copy_from_slice(body));
    }
}

/// Parse an HTTP method string into a `hyper::Method`.
fn parse_hyper_method(method: &str) -> Result<hyper::Method, ()> {
    match method {
        "GET" => Ok(hyper::Method::GET),
        "POST" => Ok(hyper::Method::POST),
        "PUT" => Ok(hyper::Method::PUT),
        "DELETE" => Ok(hyper::Method::DELETE),
        "PATCH" => Ok(hyper::Method::PATCH),
        "HEAD" => Ok(hyper::Method::HEAD),
        "OPTIONS" => Ok(hyper::Method::OPTIONS),
        other => hyper::Method::from_bytes(other.as_bytes()).map_err(|_| ()),
    }
}

/// Build X-Forwarded-For header value by appending the client IP to the existing value.
/// Uses pre-allocated buffer instead of `format!()` to avoid format machinery overhead.
fn build_xff_value(existing_xff: Option<&str>, client_ip: &str) -> String {
    match existing_xff {
        Some(xff) => {
            let mut val = String::with_capacity(xff.len() + 2 + client_ip.len());
            val.push_str(xff);
            val.push_str(", ");
            val.push_str(client_ip);
            val
        }
        None => client_ip.to_string(),
    }
}

/// RAII guard that decrements the per-IP concurrent request counter on drop.
/// Created after client IP resolution; guarantees decrement on every exit path
/// (including early returns and panics).
pub struct PerIpRequestGuard {
    pub ip: String,
    pub counts: Arc<dashmap::DashMap<String, AtomicU64>>,
}

impl Drop for PerIpRequestGuard {
    fn drop(&mut self) {
        if let Some(entry) = self.counts.get(&self.ip) {
            entry.value().fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Build RFC 7239 Forwarded header value.
/// IPv6 addresses are quoted per RFC 7239 §6.
/// Writes directly into a single pre-allocated buffer to avoid intermediate
/// `format!()` String allocations.
pub fn build_forwarded_value(client_ip: &str, proto: &str, host: Option<&str>) -> String {
    let mut val = String::with_capacity(64);
    // Quote IPv6 addresses: for="[2001:db8::1]"
    if client_ip.contains(':') {
        val.push_str("for=\"[");
        val.push_str(client_ip);
        val.push_str("]\"");
    } else {
        val.push_str("for=");
        val.push_str(client_ip);
    }
    val.push_str(";proto=");
    val.push_str(proto);
    if let Some(h) = host {
        val.push_str(";host=");
        val.push_str(h);
    }
    val
}

pub(crate) async fn apply_request_body_plugins(
    plugins: &[Arc<dyn Plugin>],
    headers: &HashMap<String, String>,
    body_bytes: Vec<u8>,
) -> Vec<u8> {
    if body_bytes.is_empty() || !plugins.iter().any(|plugin| plugin.modifies_request_body()) {
        return body_bytes;
    }

    let content_type = headers.get("content-type").map(|value| value.as_str());
    let mut current = body_bytes;
    for plugin in plugins {
        if plugin.modifies_request_body()
            && let Some(transformed) = plugin
                .transform_request_body(&current, content_type, headers)
                .await
        {
            current = transformed;
        }
    }
    current
}

pub(crate) async fn run_final_request_body_hooks(
    plugins: &[Arc<dyn Plugin>],
    headers: &HashMap<String, String>,
    body: &[u8],
) -> PluginResult {
    for plugin in plugins {
        match plugin.on_final_request_body(headers, body).await {
            PluginResult::Continue => {}
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                return reject;
            }
        }
    }
    PluginResult::Continue
}

pub(crate) struct RejectedResponseParts {
    pub status_code: u16,
    pub body: Vec<u8>,
    pub headers: HashMap<String, String>,
}

pub(crate) fn plugin_result_into_reject_parts(
    reject: PluginResult,
) -> Option<RejectedResponseParts> {
    match reject {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => Some(RejectedResponseParts {
            status_code,
            body: body.into_bytes(),
            headers,
        }),
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => Some(RejectedResponseParts {
            status_code,
            body: body.to_vec(),
            headers,
        }),
        PluginResult::Continue => None,
    }
}

fn reject_result_to_backend_response(
    reject: PluginResult,
    backend_resolved_ip: Option<String>,
) -> retry::BackendResponse {
    let reject = plugin_result_into_reject_parts(reject)
        .expect("continue result cannot be converted to a reject");
    retry::BackendResponse {
        status_code: reject.status_code,
        body: ResponseBody::Buffered(reject.body),
        headers: reject.headers,
        connection_error: false,
        backend_resolved_ip,
        error_class: (reject.status_code == 413).then_some(retry::ErrorClass::RequestBodyTooLarge),
    }
}

/// Shared state for the proxy engine.
#[derive(Clone)]
pub struct ProxyState {
    pub config: Arc<ArcSwap<GatewayConfig>>,
    pub dns_cache: DnsCache,
    pub connection_pool: Arc<ConnectionPool>,
    pub router_cache: Arc<RouterCache>,
    pub plugin_cache: Arc<PluginCache>,
    pub consumer_index: Arc<ConsumerIndex>,
    pub request_count: Arc<AtomicU64>,
    pub status_counts: Arc<dashmap::DashMap<u16, AtomicU64>>,
    /// gRPC-specific HTTP/2 connection pool (h2c + h2 with trailer support)
    pub grpc_pool: Arc<GrpcConnectionPool>,
    /// HTTP/2 connection pool for HTTPS backends (proper stream multiplexing)
    pub http2_pool: Arc<Http2ConnectionPool>,
    /// HTTP/3 connection pool for QUIC backends (reuses QUIC connections)
    pub h3_pool: Arc<Http3ConnectionPool>,
    /// Load balancer cache for upstream target selection.
    pub load_balancer_cache: Arc<LoadBalancerCache>,
    /// Health checker for upstream targets.
    pub health_checker: Arc<HealthChecker>,
    /// Circuit breaker cache for proxy-level circuit breaking.
    pub circuit_breaker_cache: Arc<CircuitBreakerCache>,
    /// Service discovery manager for dynamic upstream target resolution.
    pub service_discovery_manager: Arc<ServiceDiscoveryManager>,
    /// Pre-computed Alt-Svc header value for HTTP/3 advertisement.
    /// `None` when HTTP/3 is disabled; avoids a `format!()` allocation per response.
    pub alt_svc_header: Option<String>,
    /// Pre-computed Via header values per protocol version (RFC 9110 §7.6.3).
    /// `None` when `FERRUM_ADD_VIA_HEADER=false` (default). Keyed by protocol version string.
    pub via_header_http11: Option<String>,
    pub via_header_http2: Option<String>,
    pub via_header_http3: Option<String>,
    /// Whether to add Forwarded header (RFC 7239) alongside X-Forwarded-*.
    pub add_forwarded_header: bool,
    /// Environment config for backend TLS settings (WebSocket, etc.)
    pub env_config: Arc<crate::config::EnvConfig>,
    // Size limits
    pub max_header_size_bytes: usize,
    pub max_single_header_size_bytes: usize,
    pub max_header_count: usize,
    pub max_request_body_size_bytes: usize,
    pub max_response_body_size_bytes: usize,
    pub response_buffer_cutoff_bytes: usize,
    pub h2_coalesce_target_bytes: usize,
    pub max_url_length_bytes: usize,
    pub max_query_params: usize,
    pub max_grpc_recv_size_bytes: usize,
    pub max_websocket_frame_size_bytes: usize,
    pub websocket_write_buffer_size: usize,
    pub websocket_tunnel_mode: bool,
    /// Parsed trusted proxy CIDRs for X-Forwarded-For client IP resolution.
    /// Pre-parsed from `env_config.trusted_proxies` to avoid re-parsing on every request.
    pub trusted_proxies: Arc<client_ip::TrustedProxies>,
    /// Optional dedicated WebSocket admission control.
    /// Enforced only on the upgrade path, never on the frame-forwarding hot path.
    pub websocket_conn_limit: Option<Arc<tokio::sync::Semaphore>>,
    /// Per-IP concurrent request counters. Each IP gets an AtomicU64 tracking
    /// active requests. `None` when `FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP=0` (disabled).
    pub per_ip_request_counts: Option<Arc<dashmap::DashMap<String, AtomicU64>>>,
    /// Maximum concurrent requests per resolved client IP. 0 = disabled.
    pub max_concurrent_requests_per_ip: u64,
    /// Manages TCP/UDP stream proxy listeners (dedicated port per proxy).
    pub stream_listener_manager: Arc<stream_listener::StreamListenerManager>,
    /// Windowed per-second rate metrics computed by a background task.
    /// Read by the admin `/status` endpoint; written by `metrics::start_metrics_monitor`.
    pub windowed_metrics: Arc<crate::metrics::WindowedMetrics>,
    /// Monotonic instant captured at ProxyState creation for uptime calculation.
    pub started_at: Instant,
    /// Monotonic counter for generating unique WebSocket connection IDs.
    /// Used by frame-level plugins (e.g., ws_rate_limiting) for per-connection state.
    pub ws_connection_counter: Arc<AtomicU64>,
    /// TLS hardening policy for backend/outbound connections.
    /// When set, all backend TLS connections use the same cipher suites,
    /// protocol versions, and key exchange groups as inbound listeners.
    pub tls_policy: Option<Arc<TlsPolicy>>,
    /// Certificate Revocation Lists for backend TLS verification.
    /// Loaded once at startup from `FERRUM_TLS_CRL_FILE_PATH` and shared via Arc.
    pub crls: crate::tls::CrlList,
    /// Overload state for progressive load shedding and graceful drain tracking.
    /// Shared across all accept loops and the background monitor.
    pub overload: Arc<crate::overload::OverloadState>,
    /// Adaptive buffer size and batch limit tracker for TCP/WS tunnel/UDP.
    /// Tracks EWMA of bytes per connection and datagrams per batch cycle per proxy.
    pub adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    /// HTTP methods allowed as TLS 1.3 0-RTT early data (O(1) lookup).
    /// Empty = 0-RTT disabled (`max_early_data_size=0`). Non-empty = 0-RTT enabled
    /// and requests arriving via early data are rejected with 425 Too Early if
    /// their method is not in this set. Pre-computed at config load time.
    pub early_data_methods: Arc<std::collections::HashSet<String>>,
}

impl ProxyState {
    pub fn new(
        config: GatewayConfig,
        dns_cache: DnsCache,
        env_config: crate::config::EnvConfig,
        tls_policy: Option<TlsPolicy>,
    ) -> Result<Self, anyhow::Error> {
        let alt_svc_header = if env_config.enable_http3 {
            Some(format!("h3=\":{}\"; ma=86400", env_config.proxy_https_port))
        } else {
            None
        };
        let (via_header_http11, via_header_http2, via_header_http3) = if env_config.add_via_header {
            let p = &env_config.via_pseudonym;
            (
                Some(format!("1.1 {p}")),
                Some(format!("2.0 {p}")),
                Some(format!("3.0 {p}")),
            )
        } else {
            (None, None, None)
        };
        let add_forwarded_header = env_config.add_forwarded_header;
        let max_header_size_bytes = env_config.max_header_size_bytes;
        let max_single_header_size_bytes = env_config.max_single_header_size_bytes;
        let max_header_count = env_config.max_header_count;
        let max_request_body_size_bytes = env_config.max_request_body_size_bytes;
        let max_response_body_size_bytes = env_config.max_response_body_size_bytes;
        let response_buffer_cutoff_bytes = env_config.response_buffer_cutoff_bytes;
        let h2_coalesce_target_bytes = env_config.h2_coalesce_target_bytes;
        let max_url_length_bytes = env_config.max_url_length_bytes;
        let max_query_params = env_config.max_query_params;
        let max_grpc_recv_size_bytes = env_config.max_grpc_recv_size_bytes;
        let max_websocket_frame_size_bytes = env_config.max_websocket_frame_size_bytes;
        let websocket_write_buffer_size = env_config.websocket_write_buffer_size;
        let websocket_tunnel_mode = env_config.websocket_tunnel_mode;
        let max_concurrent_requests_per_ip = env_config.max_concurrent_requests_per_ip;
        let trusted_proxies = Arc::new(client_ip::TrustedProxies::parse(
            &env_config.trusted_proxies,
        ));
        let websocket_conn_limit = if env_config.websocket_max_connections > 0 {
            Some(Arc::new(tokio::sync::Semaphore::new(
                env_config.websocket_max_connections,
            )))
        } else {
            None
        };
        // Create connection pools with global configuration from environment
        let global_pool_config = PoolConfig::from_env();
        let tls_policy_arc = tls_policy.map(Arc::new);
        let crls = crate::tls::load_crls(env_config.tls_crl_file_path.as_deref())?;
        let grpc_pool = Arc::new(GrpcConnectionPool::new(
            global_pool_config.clone(),
            env_config.clone(),
            tls_policy_arc.clone(),
            crls.clone(),
        ));
        let http2_pool = Arc::new(Http2ConnectionPool::new(
            global_pool_config.clone(),
            env_config.clone(),
            tls_policy_arc.clone(),
            crls.clone(),
        ));
        let env_config_arc = Arc::new(env_config.clone());
        let h3_pool = Arc::new(Http3ConnectionPool::new(
            env_config_arc.clone(),
            dns_cache.clone(),
        ));
        let connection_pool = Arc::new(ConnectionPool::new(
            global_pool_config.clone(),
            env_config,
            dns_cache.clone(),
            tls_policy_arc.clone(),
            crls.clone(),
        ));
        // Build router cache with pre-sorted route table and HashMap prefix index.
        // Cache size: explicit env var if set (>0), otherwise auto-scales with proxy count.
        let max_cache_entries = if env_config_arc.router_cache_max_entries > 0 {
            env_config_arc
                .router_cache_max_entries
                .clamp(1_000, 10_000_000)
        } else {
            (config.proxies.len() * 3).clamp(10_000, 1_000_000)
        };
        let router_cache = Arc::new(RouterCache::new(&config, max_cache_entries));
        // Pre-resolve plugins per proxy (fixes rate_limiting state persistence bug).
        // All plugins that make outbound HTTP calls share a pooled client configured
        // with the gateway's connection pool settings (keepalive, idle timeout, etc.).
        let plugin_http_client = crate::plugins::PluginHttpClient::new(
            &global_pool_config,
            dns_cache.clone(),
            env_config_arc.plugin_http_slow_threshold_ms,
            env_config_arc.plugin_http_max_retries,
            env_config_arc.plugin_http_retry_delay_ms,
            env_config_arc.tls_no_verify,
            env_config_arc.tls_ca_bundle_path.as_deref(),
            &env_config_arc.namespace,
        );
        let plugin_cache = Arc::new(
            PluginCache::with_http_client(&config, plugin_http_client.clone())
                .map_err(|e| anyhow::anyhow!("{}", e))?,
        );
        // Build credential-indexed consumer lookup for O(1) auth
        let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
        // Build load balancer cache for upstream target selection
        let load_balancer_cache = Arc::new(LoadBalancerCache::new(&config));
        // Initialize health checker with the gateway's pool settings so active
        // probes share connection tuning (keep-alive, idle timeout, HTTP/2) with
        // regular proxy traffic.
        let mut health_checker =
            HealthChecker::with_pool_config(&global_pool_config, dns_cache.clone());
        health_checker.set_global_tls_config(
            env_config_arc.tls_ca_bundle_path.clone(),
            env_config_arc.backend_tls_client_cert_path.clone(),
            env_config_arc.backend_tls_client_key_path.clone(),
            env_config_arc.tls_no_verify,
        );
        health_checker.set_load_balancer_cache(load_balancer_cache.clone());
        health_checker.start(&config);
        let health_checker = Arc::new(health_checker);
        // Circuit breaker cache
        let circuit_breaker_cache = Arc::new(CircuitBreakerCache::with_max_entries(
            env_config_arc.circuit_breaker_cache_max_entries,
        ));
        // Service discovery manager (tasks started later via start_service_discovery)
        let service_discovery_manager = Arc::new(ServiceDiscoveryManager::new(
            load_balancer_cache.clone(),
            dns_cache.clone(),
            health_checker.clone(),
            plugin_http_client,
        ));

        let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));

        // Parse stream proxy bind address
        let stream_bind_addr: std::net::IpAddr = env_config_arc
            .stream_proxy_bind_address
            .parse()
            .unwrap_or_else(|_| {
                // Fall back to the proxy bind address, then to IPv4 unspecified
                env_config_arc
                    .proxy_bind_address
                    .parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
            });

        let adaptive_buffer = Arc::new(crate::adaptive_buffer::AdaptiveBufferTracker::new(
            env_config_arc.adaptive_buffer_enabled,
            env_config_arc.adaptive_batch_limit_enabled,
            env_config_arc.adaptive_buffer_ewma_alpha,
            env_config_arc.adaptive_buffer_min_size,
            env_config_arc.adaptive_buffer_max_size,
            env_config_arc.adaptive_buffer_default_size,
            env_config_arc.adaptive_batch_limit_default,
        ));

        let overload = Arc::new(crate::overload::OverloadState::new());

        let stream_listener_manager = Arc::new(stream_listener::StreamListenerManager::new(
            stream_bind_addr,
            config_arc.clone(),
            dns_cache.clone(),
            load_balancer_cache.clone(),
            consumer_index.clone(),
            plugin_cache.clone(),
            circuit_breaker_cache.clone(),
            None, // Frontend TLS for stream proxies is configured per-listener in reconcile()
            env_config_arc.tls_no_verify,
            env_config_arc.tls_ca_bundle_path.clone(),
            env_config_arc.tcp_idle_timeout_seconds,
            env_config_arc.udp_max_sessions,
            env_config_arc.udp_cleanup_interval_seconds,
            tls_policy_arc.clone(),
            crls.clone(),
            adaptive_buffer.clone(),
            env_config_arc.udp_recvmmsg_batch_size,
            {
                let v = env_config_arc
                    .tcp_fastopen_enabled
                    .resolve(crate::socket_opts::is_tcp_fastopen_available);
                tracing::info!(enabled = v, config = %env_config_arc.tcp_fastopen_enabled, "TCP_FASTOPEN auto-detection");
                v
            },
            overload.clone(),
            {
                let v = env_config_arc
                    .ktls_enabled
                    .resolve(crate::socket_opts::ktls::is_ktls_available);
                if v {
                    tracing::info!("kTLS auto-detection: enabled (full key install probe passed)");
                } else {
                    tracing::info!(config = %env_config_arc.ktls_enabled, "kTLS auto-detection: disabled");
                }
                v
            },
            {
                let v = env_config_arc
                    .io_uring_splice_enabled
                    .resolve(crate::socket_opts::io_uring_splice::check_io_uring_available);
                if v {
                    tracing::info!(
                        "io_uring splice auto-detection: enabled (IORING_OP_SPLICE probe passed)"
                    );
                    // Warn if the tokio blocking-thread pool is too small for the
                    // per-stream pattern: io_uring splice spawns 2 `spawn_blocking`
                    // tasks per TCP connection (one per direction). With the default
                    // cap of 512, thousands of concurrent streams will saturate the
                    // pool and new splices will queue, causing latency spikes. 1024
                    // is the rule-of-thumb floor; operators with very high connection
                    // counts should set FERRUM_BLOCKING_THREADS much higher or
                    // disable io_uring splice entirely.
                    let effective_blocking_threads = env_config_arc.blocking_threads.unwrap_or(512);
                    if effective_blocking_threads < 1024 {
                        tracing::warn!(
                            blocking_threads = effective_blocking_threads,
                            "FERRUM_IO_URING_SPLICE_ENABLED=true but FERRUM_BLOCKING_THREADS={} is low; \
                             each TCP stream consumes 2 blocking threads. \
                             Recommended: FERRUM_BLOCKING_THREADS >= 1024 for io_uring splice.",
                            effective_blocking_threads
                        );
                    }
                } else {
                    tracing::info!(config = %env_config_arc.io_uring_splice_enabled, "io_uring splice auto-detection: disabled");
                }
                v
            },
            env_config_arc.so_busy_poll_us,
            {
                let v = env_config_arc
                    .udp_gro_enabled
                    .resolve(crate::socket_opts::is_udp_gro_available);
                // GRO is probed but not active (recv_from lacks cmsg) — log for completeness.
                tracing::info!(enabled = v, config = %env_config_arc.udp_gro_enabled, "UDP GRO auto-detection (reserved, not active)");
                v
            },
            {
                let v = env_config_arc
                    .udp_gso_enabled
                    .resolve(crate::socket_opts::is_udp_gso_available);
                if v {
                    tracing::info!("UDP GSO auto-detection: enabled (setsockopt probe passed)");
                } else {
                    tracing::info!(config = %env_config_arc.udp_gso_enabled, "UDP GSO auto-detection: disabled");
                }
                v
            },
        ));

        Ok(Self {
            config: config_arc,
            dns_cache,
            connection_pool,
            router_cache,
            plugin_cache,
            consumer_index,
            load_balancer_cache,
            health_checker,
            circuit_breaker_cache,
            service_discovery_manager,
            request_count: Arc::new(AtomicU64::new(0)),
            status_counts: {
                // Pre-populate common HTTP status codes so the hot path uses
                // DashMap::get() (shared read lock) instead of entry() (write lock).
                // After warmup, virtually all requests hit the fast read path.
                let map = dashmap::DashMap::with_capacity(16);
                for code in [
                    200u16, 201, 204, 301, 302, 304, 400, 401, 403, 404, 405, 408, 429, 500, 502,
                    503, 504,
                ] {
                    map.insert(code, AtomicU64::new(0));
                }
                Arc::new(map)
            },
            grpc_pool,
            http2_pool,
            h3_pool,
            alt_svc_header,
            via_header_http11,
            via_header_http2,
            via_header_http3,
            add_forwarded_header,
            windowed_metrics: Arc::new(crate::metrics::WindowedMetrics::new(
                env_config_arc.status_metrics_window_seconds,
            )),
            early_data_methods: Arc::new(env_config_arc.tls_early_data_methods.clone()),
            env_config: env_config_arc,
            max_header_size_bytes,
            max_single_header_size_bytes,
            max_header_count,
            max_request_body_size_bytes,
            max_response_body_size_bytes,
            response_buffer_cutoff_bytes,
            h2_coalesce_target_bytes,
            max_url_length_bytes,
            max_query_params,
            max_grpc_recv_size_bytes,
            max_websocket_frame_size_bytes,
            websocket_write_buffer_size,
            websocket_tunnel_mode,
            trusted_proxies,
            websocket_conn_limit,
            per_ip_request_counts: if max_concurrent_requests_per_ip > 0 {
                Some(Arc::new(dashmap::DashMap::new()))
            } else {
                None
            },
            max_concurrent_requests_per_ip,
            stream_listener_manager,
            started_at: Instant::now(),
            ws_connection_counter: Arc::new(AtomicU64::new(0)),
            tls_policy: tls_policy_arc,
            crls,
            overload,
            adaptive_buffer,
        })
    }

    /// Start a background task that periodically removes stale zero-count
    /// entries from `per_ip_request_counts`. Normally entries are cleaned via
    /// the `PerIpRequestGuard` RAII drop, but this sweep catches edge cases
    /// (e.g., task cancellation without guard drop).
    pub fn start_per_ip_cleanup_task(&self) {
        if let Some(ref counts) = self.per_ip_request_counts {
            let counts = counts.clone();
            let interval_secs = self.env_config.per_ip_cleanup_interval_seconds.max(1);
            tokio::spawn(async move {
                let mut timer =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                loop {
                    timer.tick().await;
                    counts.retain(|_, count| count.load(Ordering::Relaxed) > 0);
                }
            });
        }
    }

    /// Reconcile stream proxy listeners at startup.
    ///
    /// This must be called after `ProxyState::new()` to start TCP/UDP listeners
    /// for any stream proxies in the initial config. Returns an error if any
    /// listener failed to bind its port (e.g., port already in use by another
    /// process). The caller should fail startup on error.
    pub async fn initial_reconcile_stream_listeners(&self) -> Result<(), anyhow::Error> {
        let failures = self.stream_listener_manager.reconcile().await;
        if failures.is_empty() {
            return Ok(());
        }
        let mut msg = String::from("Stream listener(s) failed to bind:\n");
        for (proxy_id, port, err) in &failures {
            msg.push_str(&format!(
                "  - proxy '{}' port {}: {}\n",
                proxy_id, port, err
            ));
        }
        Err(anyhow::anyhow!("{}", msg.trim_end()))
    }

    /// Pre-establish backend connections for all HTTP-family proxies.
    ///
    /// Warms four pool types (reqwest, gRPC, HTTP/2 direct, HTTP/3) after DNS
    /// warmup completes, so the first request to each backend does not pay
    /// TCP/TLS/QUIC handshake latency. Stream proxies (TCP/UDP) are skipped
    /// because they create per-session connections with no persistent pool.
    ///
    /// For upstream-backed proxies, every target in the upstream is warmed for
    /// pools that key by (host, port) — gRPC, HTTP/2 direct, HTTP/3. The
    /// reqwest pool keys by `upstream_id` so one `get_client()` call covers
    /// all targets (reqwest handles per-host pooling internally).
    pub async fn warmup_connection_pools(&self) {
        use futures_util::stream;
        use std::collections::HashSet;

        let config = self.config.load_full();
        let concurrency = self.env_config.pool_warmup_concurrency;

        // Build a deduplication set for per-host pools (gRPC, H2, H3) keyed by
        // the same pool key the pool itself uses, preventing redundant warmups.
        let mut seen_reqwest = HashSet::new();
        let mut seen_grpc = HashSet::new();
        let mut seen_h2 = HashSet::new();
        let mut seen_h3 = HashSet::new();

        // Collect all warmup tasks as boxed futures.
        let mut tasks: Vec<WarmupTask> = Vec::new();

        // Helper: build upstream target map for O(1) lookup
        let upstream_map: HashMap<&str, &crate::config::types::Upstream> = config
            .upstreams
            .iter()
            .map(|u| (u.id.as_str(), u))
            .collect();

        for proxy in &config.proxies {
            // Skip stream proxies — no persistent connection pools
            if proxy.backend_protocol.is_stream_proxy() {
                continue;
            }

            match proxy.backend_protocol {
                // ── reqwest pool (HTTP/1.1, HTTPS, WS, WSS) ──
                // Also covers HTTPS when H2 direct pool is not eligible.
                BackendProtocol::Http
                | BackendProtocol::Https
                | BackendProtocol::Ws
                | BackendProtocol::Wss => {
                    self.collect_reqwest_warmup_tasks(
                        proxy,
                        &upstream_map,
                        &mut seen_reqwest,
                        &mut tasks,
                    );

                    // If HTTPS with enable_http2, also warm the direct H2 pool
                    if matches!(proxy.backend_protocol, BackendProtocol::Https) {
                        let pool_config =
                            self.connection_pool.global_pool_config().for_proxy(proxy);
                        if pool_config.enable_http2 {
                            self.collect_h2_warmup_tasks(
                                proxy,
                                &upstream_map,
                                &mut seen_h2,
                                &mut tasks,
                            );
                        }
                    }
                }

                // ── gRPC pool (Grpc/Grpcs) ──
                BackendProtocol::Grpc | BackendProtocol::Grpcs => {
                    self.collect_grpc_warmup_tasks(
                        proxy,
                        &upstream_map,
                        &mut seen_grpc,
                        &mut tasks,
                    );
                }

                // ── HTTP/3 pool ──
                BackendProtocol::H3 => {
                    self.collect_h3_warmup_tasks(proxy, &upstream_map, &mut seen_h3, &mut tasks);
                }

                // Stream protocols already filtered above
                _ => {}
            }
        }

        if tasks.is_empty() {
            debug!("Pool warmup: no HTTP-family backends to warm");
            return;
        }

        let total = tasks.len();
        info!(
            "Pool warmup: establishing {} backend connections (concurrency={})",
            total, concurrency
        );

        let ok = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicU64::new(0));

        let ok_ref = ok.clone();
        let failed_ref = failed.clone();

        stream::iter(tasks)
            .for_each_concurrent(concurrency, |task| {
                let ok = ok_ref.clone();
                let failed = failed_ref.clone();
                async move {
                    match task.await {
                        Ok(desc) => {
                            debug!("Pool warmup: {} ok", desc);
                            ok.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(msg) => {
                            warn!("Pool warmup failed: {}", msg);
                            failed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
            .await;

        let ok_count = ok.load(Ordering::Relaxed);
        let failed_count = failed.load(Ordering::Relaxed);
        if failed_count > 0 {
            info!(
                "Pool warmup complete: {} ok, {} failed out of {} targets",
                ok_count, failed_count, total
            );
        } else {
            info!("Pool warmup complete: all {} targets ok", total);
        }
    }

    /// Collect reqwest pool warmup tasks for a proxy.
    ///
    /// Creates the `reqwest::Client` (TLS config, cert parsing) and then sends
    /// a lightweight HEAD request to each unique backend host:port to force
    /// TCP/TLS connection establishment. reqwest caches connections internally
    /// by host:port, so subsequent requests reuse the warmed connection.
    ///
    /// For upstream-backed proxies, every target is warmed individually because
    /// reqwest pools connections per URL host:port.
    fn collect_reqwest_warmup_tasks(
        &self,
        proxy: &Proxy,
        upstream_map: &HashMap<&str, &crate::config::types::Upstream>,
        seen: &mut std::collections::HashSet<String>,
        tasks: &mut Vec<WarmupTask>,
    ) {
        let scheme = match proxy.backend_protocol {
            BackendProtocol::Http | BackendProtocol::Ws => "http",
            _ => "https",
        };

        // Collect (host, port) targets to warm
        let mut targets: Vec<(String, u16)> = Vec::new();
        if let Some(ref upstream_id) = proxy.upstream_id
            && let Some(upstream) = upstream_map.get(upstream_id.as_str())
        {
            for target in &upstream.targets {
                targets.push((target.host.clone(), target.port));
            }
        }
        if targets.is_empty() {
            targets.push((proxy.backend_host.clone(), proxy.backend_port));
        }

        // First, ensure the reqwest::Client is created and cached (TLS config,
        // cert parsing, root store). This is shared across all targets.
        let pool_key = self.connection_pool.pool_key_for_warmup(proxy);
        let client_created = seen.contains(&pool_key);
        if !client_created {
            seen.insert(pool_key);
        }

        for (host, port) in targets {
            let dedup_key = format!("reqwest_conn|{}|{}|{}", scheme, host, port);
            if !seen.insert(dedup_key) {
                continue;
            }

            let pool = self.connection_pool.clone();
            let proxy = proxy.clone();
            let scheme = scheme.to_string();
            tasks.push(Box::pin(async move {
                let desc = format!("reqwest {}:{}", host, port);
                let client = pool
                    .get_client(&proxy)
                    .await
                    .map_err(|e| format!("{}: {}", desc, e))?;

                // Send a HEAD request to force TCP/TLS connection establishment.
                // The backend will likely return an error (404, 503, etc.) but
                // the underlying TCP/TLS connection is kept in reqwest's internal
                // pool for reuse. We ignore the HTTP response status entirely.
                let url = format!("{}://{}:{}/", scheme, host, port);
                let result = client
                    .head(&url)
                    .timeout(Duration::from_secs(5))
                    .send()
                    .await;

                match result {
                    Ok(_) => Ok(desc),
                    Err(e) if e.is_connect() || e.is_timeout() => Err(format!("{}: {}", desc, e)),
                    // Non-connect errors (4xx, 5xx, etc.) are fine — the TCP/TLS
                    // connection was established and is now pooled.
                    Err(_) => Ok(desc),
                }
            }));
        }
    }

    /// Collect gRPC pool warmup tasks for a proxy, expanding upstream targets.
    fn collect_grpc_warmup_tasks(
        &self,
        proxy: &Proxy,
        upstream_map: &HashMap<&str, &crate::config::types::Upstream>,
        seen: &mut std::collections::HashSet<String>,
        tasks: &mut Vec<WarmupTask>,
    ) {
        if let Some(ref upstream_id) = proxy.upstream_id {
            if let Some(upstream) = upstream_map.get(upstream_id.as_str()) {
                for target in &upstream.targets {
                    let mut target_proxy = proxy.clone();
                    target_proxy.backend_host = target.host.clone();
                    target_proxy.backend_port = target.port;
                    let key = grpc_proxy::GrpcConnectionPool::pool_key_for_warmup(&target_proxy);
                    if seen.insert(key) {
                        let pool = self.grpc_pool.clone();
                        let dns = self.dns_cache.clone();
                        tasks.push(Box::pin(async move {
                            let desc = format!(
                                "gRPC {}:{}",
                                target_proxy.backend_host, target_proxy.backend_port
                            );
                            pool.get_sender(&target_proxy, &dns)
                                .await
                                .map(|_| desc.clone())
                                .map_err(|e| format!("{}: {:?}", desc, e))
                        }));
                    }
                }
            }
        } else {
            let key = grpc_proxy::GrpcConnectionPool::pool_key_for_warmup(proxy);
            if seen.insert(key) {
                let pool = self.grpc_pool.clone();
                let dns = self.dns_cache.clone();
                let proxy = proxy.clone();
                tasks.push(Box::pin(async move {
                    let desc = format!("gRPC {}:{}", proxy.backend_host, proxy.backend_port);
                    pool.get_sender(&proxy, &dns)
                        .await
                        .map(|_| desc.clone())
                        .map_err(|e| format!("{}: {:?}", desc, e))
                }));
            }
        }
    }

    /// Collect HTTP/2 direct pool warmup tasks for a proxy, expanding upstream targets.
    fn collect_h2_warmup_tasks(
        &self,
        proxy: &Proxy,
        upstream_map: &HashMap<&str, &crate::config::types::Upstream>,
        seen: &mut std::collections::HashSet<String>,
        tasks: &mut Vec<WarmupTask>,
    ) {
        if let Some(ref upstream_id) = proxy.upstream_id {
            if let Some(upstream) = upstream_map.get(upstream_id.as_str()) {
                for target in &upstream.targets {
                    let mut target_proxy = proxy.clone();
                    target_proxy.backend_host = target.host.clone();
                    target_proxy.backend_port = target.port;
                    let key = Http2ConnectionPool::pool_key_for_warmup(&target_proxy);
                    if seen.insert(key) {
                        let pool = self.http2_pool.clone();
                        let dns = self.dns_cache.clone();
                        tasks.push(Box::pin(async move {
                            let desc = format!(
                                "H2 {}:{}",
                                target_proxy.backend_host, target_proxy.backend_port
                            );
                            pool.get_sender(&target_proxy, &dns)
                                .await
                                .map(|_| desc.clone())
                                .map_err(|e| format!("{}: {:?}", desc, e))
                        }));
                    }
                }
            }
        } else {
            let key = Http2ConnectionPool::pool_key_for_warmup(proxy);
            if seen.insert(key) {
                let pool = self.http2_pool.clone();
                let dns = self.dns_cache.clone();
                let proxy = proxy.clone();
                tasks.push(Box::pin(async move {
                    let desc = format!("H2 {}:{}", proxy.backend_host, proxy.backend_port);
                    pool.get_sender(&proxy, &dns)
                        .await
                        .map(|_| desc.clone())
                        .map_err(|e| format!("{}: {:?}", desc, e))
                }));
            }
        }
    }

    /// Collect HTTP/3 pool warmup tasks for a proxy, expanding upstream targets.
    fn collect_h3_warmup_tasks(
        &self,
        proxy: &Proxy,
        upstream_map: &HashMap<&str, &crate::config::types::Upstream>,
        seen: &mut std::collections::HashSet<String>,
        tasks: &mut Vec<WarmupTask>,
    ) {
        if let Some(ref upstream_id) = proxy.upstream_id {
            if let Some(upstream) = upstream_map.get(upstream_id.as_str()) {
                for target in &upstream.targets {
                    let key = format!(
                        "h3|{}|{}|{}|{}|{}",
                        target.host,
                        target.port,
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
                    if seen.insert(key) {
                        let pool = self.h3_pool.clone();
                        let conn_pool = self.connection_pool.clone();
                        let proxy = proxy.clone();
                        let host = target.host.clone();
                        let port = target.port;
                        tasks.push(Box::pin(async move {
                            let desc = format!("H3 {}:{}", host, port);
                            let tls_config = conn_pool
                                .get_tls_config_for_backend(&proxy)
                                .map_err(|e| format!("{}: TLS config: {}", desc, e))?;
                            pool.warmup_connection_to_target(&host, port, &tls_config)
                                .await
                                .map(|_| desc.clone())
                                .map_err(|e| format!("{}: {}", desc, e))
                        }));
                    }
                }
            }
        } else {
            let key = format!(
                "h3|{}|{}|{}|{}|{}",
                proxy.backend_host,
                proxy.backend_port,
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
            if seen.insert(key) {
                let pool = self.h3_pool.clone();
                let conn_pool = self.connection_pool.clone();
                let proxy = proxy.clone();
                tasks.push(Box::pin(async move {
                    let desc = format!("H3 {}:{}", proxy.backend_host, proxy.backend_port);
                    let tls_config = conn_pool
                        .get_tls_config_for_backend(&proxy)
                        .map_err(|e| format!("{}: TLS config: {}", desc, e))?;
                    pool.warmup_connection(&proxy, &tls_config)
                        .await
                        .map(|_| desc.clone())
                        .map_err(|e| format!("{}: {}", desc, e))
                }));
            }
        }
    }

    /// Apply a new configuration, using incremental (surgical) updates when
    /// possible to avoid disrupting the hot request path.
    ///
    /// The delta between the old and new config is computed first. If nothing
    /// changed, this is a no-op. For typical admin API edits (1-2 resources),
    /// only the affected cache entries are updated while the rest of the
    /// caches — including stateful plugin instances, warm path caches, and
    /// load balancer counters — remain completely untouched.
    ///
    /// Falls back to a full rebuild only on the very first config load (when
    /// there is no previous config to diff against).
    /// Update the proxy configuration. Returns `true` if changes were applied.
    pub fn update_config(&self, mut new_config: GatewayConfig) -> bool {
        use crate::config_delta::ConfigDelta;

        // Resolve upstream TLS into each proxy's resolved_tls before applying.
        new_config.resolve_upstream_tls();

        // Validate stream proxy port conflicts before applying any config.
        // In DP mode, warn but don't reject — the DP doesn't control its config
        // and one bad stream proxy port shouldn't block all other config updates.
        let reserved_ports = self.env_config.reserved_gateway_ports();
        if let Err(errors) = new_config.validate_stream_proxy_port_conflicts(&reserved_ports) {
            if matches!(
                self.env_config.mode,
                crate::config::env_config::OperatingMode::DataPlane
            ) {
                for msg in &errors {
                    warn!("Stream proxy port conflict (non-fatal in DP mode): {}", msg);
                }
            } else {
                for msg in &errors {
                    error!("Config reload rejected: {}", msg);
                }
                return false;
            }
        }

        let old_config = self.config.load_full();

        // If this is the initial load (old config empty, new config has data),
        // do a full rebuild of all caches instead of computing a delta.
        let old_is_empty = old_config.proxies.is_empty()
            && old_config.consumers.is_empty()
            && old_config.plugin_configs.is_empty()
            && old_config.upstreams.is_empty();
        let new_is_empty = new_config.proxies.is_empty()
            && new_config.consumers.is_empty()
            && new_config.plugin_configs.is_empty()
            && new_config.upstreams.is_empty();

        if old_is_empty && !new_is_empty {
            self.router_cache.rebuild(&new_config);
            if let Err(e) = self.plugin_cache.rebuild(&new_config) {
                error!(
                    "Config reload rejected — security plugin validation failed: {}",
                    e
                );
                return false;
            }
            self.consumer_index.rebuild(&new_config.consumers);
            self.load_balancer_cache.rebuild(&new_config);

            // DNS warmup for all hostnames in the new config
            let mut hostnames: Vec<(String, Option<String>, Option<u64>)> = new_config
                .proxies
                .iter()
                .map(|p| {
                    (
                        p.backend_host.clone(),
                        p.dns_override.clone(),
                        p.dns_cache_ttl_seconds,
                    )
                })
                .collect();
            for upstream in &new_config.upstreams {
                for target in &upstream.targets {
                    hostnames.push((target.host.clone(), None, None));
                }
            }
            if !hostnames.is_empty() {
                let dns = self.dns_cache.clone();
                tokio::spawn(async move {
                    dns.warmup(hostnames).await;
                });
            }

            // Prune adaptive buffer state for removed proxies.
            {
                let active_ids: Vec<&str> =
                    new_config.proxies.iter().map(|p| p.id.as_str()).collect();
                self.adaptive_buffer.prune_missing(&active_ids);
            }

            self.config.store(Arc::new(new_config));

            // Reconcile stream proxy listeners (TCP/UDP)
            let slm = self.stream_listener_manager.clone();
            tokio::spawn(async move {
                let failures = slm.reconcile().await;
                for (proxy_id, port, err) in &failures {
                    tracing::error!(
                        proxy_id = %proxy_id,
                        port = port,
                        "Stream listener failed to bind on config reload: {}",
                        err
                    );
                }
            });

            // Reconcile service discovery tasks
            let new_cfg = self.config.load_full();
            self.service_discovery_manager.reconcile(&new_cfg, None);

            info!(
                "Proxy configuration loaded (full build: router + plugins + consumers + load balancers)"
            );
            return true;
        }

        // Both empty — nothing to do
        if old_is_empty && new_is_empty {
            return false;
        }

        let delta = ConfigDelta::compute(&old_config, &new_config);

        if delta.is_empty() {
            debug!("Config poll: no changes detected, skipping update");
            // Still update loaded_at timestamp
            self.config.store(Arc::new(new_config));
            return false;
        }

        // --- RouterCache: rebuild route table, surgically invalidate path cache ---
        let affected_paths = delta.affected_listen_paths(&old_config);
        self.router_cache.apply_delta(&new_config, &affected_paths);

        // --- PluginCache: only rebuild plugins for affected proxies ---
        let proxy_ids_to_rebuild = delta.proxy_ids_needing_plugin_rebuild(&new_config);
        let rebuild_globals = delta
            .added_plugin_configs
            .iter()
            .chain(delta.modified_plugin_configs.iter())
            .any(|pc| pc.scope == crate::config::types::PluginScope::Global)
            || !delta.removed_plugin_config_ids.is_empty();
        if let Err(e) = self.plugin_cache.apply_delta(
            &new_config,
            &proxy_ids_to_rebuild,
            &delta.removed_proxy_ids,
            rebuild_globals,
        ) {
            error!(
                "Config reload rejected — security plugin validation failed: {}",
                e
            );
            return false;
        }

        // --- ConsumerIndex: surgical add/remove/update ---
        self.consumer_index.apply_delta(
            &delta.added_consumers,
            &delta.removed_consumer_ids,
            &delta.modified_consumers,
        );

        // --- LoadBalancerCache: only rebuild changed upstreams ---
        self.load_balancer_cache.apply_delta(
            &new_config,
            &delta.added_upstreams,
            &delta.removed_upstream_ids,
            &delta.modified_upstreams,
        );

        // --- CircuitBreakerCache: prune breakers for deleted proxies ---
        if !delta.removed_proxy_ids.is_empty() {
            self.circuit_breaker_cache.prune(&delta.removed_proxy_ids);
        }

        // --- CircuitBreakerCache: prune stale upstream targets ---
        // Removes breakers for host:port combos no longer in any upstream,
        // preventing unbounded growth from target churn (e.g., K8s pod cycling).
        {
            let mut active_keys = std::collections::HashSet::new();
            for proxy in &new_config.proxies {
                if let Some(ref upstream_id) = proxy.upstream_id
                    && let Some(upstream) =
                        new_config.upstreams.iter().find(|u| u.id == *upstream_id)
                {
                    for target in &upstream.targets {
                        active_keys
                            .insert(format!("{}::{}:{}", proxy.id, target.host, target.port));
                    }
                }
            }
            self.circuit_breaker_cache.prune_stale_targets(&active_keys);
        }

        // --- HealthChecker: prune passive health state for removed proxies ---
        if !delta.removed_proxy_ids.is_empty() {
            self.health_checker
                .prune_removed_proxies(&delta.removed_proxy_ids);
        }

        // --- DNS warmup for new/modified hostnames ---
        // Collect backend hostnames from added/modified proxies and upstreams
        // so the DNS cache is warm before the first request hits them.
        let mut new_hostnames: Vec<(String, Option<String>, Option<u64>)> = Vec::new();
        for proxy in delta
            .added_proxies
            .iter()
            .chain(delta.modified_proxies.iter())
        {
            new_hostnames.push((
                proxy.backend_host.clone(),
                proxy.dns_override.clone(),
                proxy.dns_cache_ttl_seconds,
            ));
        }
        for upstream in delta
            .added_upstreams
            .iter()
            .chain(delta.modified_upstreams.iter())
        {
            for target in &upstream.targets {
                new_hostnames.push((target.host.clone(), None, None));
            }
        }
        if !new_hostnames.is_empty() {
            let dns = self.dns_cache.clone();
            tokio::spawn(async move {
                dns.warmup(new_hostnames).await;
            });
        }

        // Clear cached pool keys when proxy settings change
        // Swap the canonical config last (readers may still be using old caches
        // via ArcSwap snapshots until they finish their current request)
        // Prune adaptive buffer state for removed proxies.
        {
            let active_ids: Vec<&str> = new_config.proxies.iter().map(|p| p.id.as_str()).collect();
            self.adaptive_buffer.prune_missing(&active_ids);
        }

        self.config.store(Arc::new(new_config));

        // Reconcile stream proxy listeners if any proxies changed
        let stream_proxies_changed = delta
            .added_proxies
            .iter()
            .chain(delta.modified_proxies.iter())
            .any(|p| p.backend_protocol.is_stream_proxy())
            || !delta.removed_proxy_ids.is_empty();
        if stream_proxies_changed {
            let slm = self.stream_listener_manager.clone();
            tokio::spawn(async move {
                let failures = slm.reconcile().await;
                for (proxy_id, port, err) in &failures {
                    tracing::error!(
                        proxy_id = %proxy_id,
                        port = port,
                        "Stream listener failed to bind on config update: {}",
                        err
                    );
                }
            });
        }

        // Log a concise summary of what changed
        let total_changes = delta.added_proxies.len()
            + delta.removed_proxy_ids.len()
            + delta.modified_proxies.len()
            + delta.added_consumers.len()
            + delta.removed_consumer_ids.len()
            + delta.modified_consumers.len()
            + delta.added_plugin_configs.len()
            + delta.removed_plugin_config_ids.len()
            + delta.modified_plugin_configs.len()
            + delta.added_upstreams.len()
            + delta.removed_upstream_ids.len()
            + delta.modified_upstreams.len();
        info!(
            "Config updated incrementally: {} changes (proxies: +{} -{} ~{}, consumers: +{} -{} ~{}, plugins: +{} -{} ~{}, upstreams: +{} -{} ~{}, {} proxy plugin lists rebuilt)",
            total_changes,
            delta.added_proxies.len(),
            delta.removed_proxy_ids.len(),
            delta.modified_proxies.len(),
            delta.added_consumers.len(),
            delta.removed_consumer_ids.len(),
            delta.modified_consumers.len(),
            delta.added_plugin_configs.len(),
            delta.removed_plugin_config_ids.len(),
            delta.modified_plugin_configs.len(),
            delta.added_upstreams.len(),
            delta.removed_upstream_ids.len(),
            delta.modified_upstreams.len(),
            proxy_ids_to_rebuild.len(),
        );

        // Reconcile service discovery tasks for changed upstreams
        if !delta.added_upstreams.is_empty()
            || !delta.removed_upstream_ids.is_empty()
            || !delta.modified_upstreams.is_empty()
        {
            let new_cfg = self.config.load_full();
            self.service_discovery_manager.reconcile(&new_cfg, None);
        }

        true
    }

    /// Start service discovery background tasks for all upstreams in the config.
    ///
    /// Should be called once after `ProxyState::new()` in each mode's startup,
    /// similar to `health_checker.start()`.
    pub fn start_service_discovery(&self, shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>) {
        let config = self.config.load_full();
        self.service_discovery_manager.start(&config, shutdown_rx);
    }

    /// Apply an incremental config update from the database polling loop.
    ///
    /// Unlike `update_config()` which takes a full `GatewayConfig` and diffs it
    /// against the current config, this method receives pre-computed changes
    /// directly from the DB layer's `load_incremental_config()`. This avoids
    /// loading and diffing the full config on every poll cycle.
    ///
    /// Returns `true` if changes were applied.
    pub async fn apply_incremental(
        &self,
        result: crate::config::db_loader::IncrementalResult,
    ) -> bool {
        if result.is_empty() {
            return false;
        }

        // Patch the stored GatewayConfig: clone current, apply mutations, store
        let mut new_config = (*self.config.load_full()).clone();

        // Remove deleted resources
        if !result.removed_proxy_ids.is_empty() {
            let removed: std::collections::HashSet<&str> = result
                .removed_proxy_ids
                .iter()
                .map(|s| s.as_str())
                .collect();
            new_config
                .proxies
                .retain(|p| !removed.contains(p.id.as_str()));
        }
        if !result.removed_consumer_ids.is_empty() {
            let removed: std::collections::HashSet<&str> = result
                .removed_consumer_ids
                .iter()
                .map(|s| s.as_str())
                .collect();
            new_config
                .consumers
                .retain(|c| !removed.contains(c.id.as_str()));
        }
        if !result.removed_plugin_config_ids.is_empty() {
            let removed: std::collections::HashSet<&str> = result
                .removed_plugin_config_ids
                .iter()
                .map(|s| s.as_str())
                .collect();
            new_config
                .plugin_configs
                .retain(|pc| !removed.contains(pc.id.as_str()));
        }
        if !result.removed_upstream_ids.is_empty() {
            let removed: std::collections::HashSet<&str> = result
                .removed_upstream_ids
                .iter()
                .map(|s| s.as_str())
                .collect();
            new_config
                .upstreams
                .retain(|u| !removed.contains(u.id.as_str()));
        }

        // Upsert added/modified resources using HashMap index for O(1) lookups
        // instead of O(n) linear scan per resource. Move values to avoid cloning.

        if !result.added_or_modified_proxies.is_empty() {
            let mut idx: std::collections::HashMap<String, usize> = new_config
                .proxies
                .iter()
                .enumerate()
                .map(|(i, p)| (p.id.clone(), i))
                .collect();
            for proxy in result.added_or_modified_proxies {
                if let Some(&pos) = idx.get(&proxy.id) {
                    new_config.proxies[pos] = proxy;
                } else {
                    idx.insert(proxy.id.clone(), new_config.proxies.len());
                    new_config.proxies.push(proxy);
                }
            }
        }

        if !result.added_or_modified_consumers.is_empty() {
            let mut idx: std::collections::HashMap<String, usize> = new_config
                .consumers
                .iter()
                .enumerate()
                .map(|(i, c)| (c.id.clone(), i))
                .collect();
            for consumer in result.added_or_modified_consumers {
                if let Some(&pos) = idx.get(&consumer.id) {
                    new_config.consumers[pos] = consumer;
                } else {
                    idx.insert(consumer.id.clone(), new_config.consumers.len());
                    new_config.consumers.push(consumer);
                }
            }
        }

        if !result.added_or_modified_plugin_configs.is_empty() {
            let mut idx: std::collections::HashMap<String, usize> = new_config
                .plugin_configs
                .iter()
                .enumerate()
                .map(|(i, pc)| (pc.id.clone(), i))
                .collect();
            for pc in result.added_or_modified_plugin_configs {
                if let Some(&pos) = idx.get(&pc.id) {
                    new_config.plugin_configs[pos] = pc;
                } else {
                    idx.insert(pc.id.clone(), new_config.plugin_configs.len());
                    new_config.plugin_configs.push(pc);
                }
            }
        }

        if !result.added_or_modified_upstreams.is_empty() {
            let mut idx: std::collections::HashMap<String, usize> = new_config
                .upstreams
                .iter()
                .enumerate()
                .map(|(i, u)| (u.id.clone(), i))
                .collect();
            for upstream in result.added_or_modified_upstreams {
                if let Some(&pos) = idx.get(&upstream.id) {
                    new_config.upstreams[pos] = upstream;
                } else {
                    idx.insert(upstream.id.clone(), new_config.upstreams.len());
                    new_config.upstreams.push(upstream);
                }
            }
        }

        new_config.loaded_at = result.poll_timestamp;

        // Validate the patched config before applying (same validations as load_full_config)
        new_config.normalize_fields();
        new_config.resolve_upstream_tls();
        if let Err(errors) = new_config.validate_all_fields_with_ip_policy(
            self.env_config.tls_cert_expiry_warning_days,
            &self.env_config.backend_allow_ips,
        ) {
            for msg in &errors {
                warn!("Incremental config field validation: {}", msg);
            }
        }
        if let Err(errors) = new_config.validate_hosts() {
            for msg in &errors {
                warn!("Incremental config validation: {}", msg);
            }
        }
        if let Err(errors) = new_config.validate_regex_listen_paths() {
            for msg in &errors {
                error!("Incremental config rejected: {}", msg);
            }
            return false;
        }
        if let Err(errors) = new_config.validate_unique_listen_paths() {
            for msg in &errors {
                error!("Incremental config rejected: {}", msg);
            }
            return false;
        }
        if let Err(errors) = new_config.validate_stream_proxies() {
            for msg in &errors {
                error!("Incremental config rejected: {}", msg);
            }
            return false;
        }
        if let Err(errors) = new_config.validate_upstream_references() {
            for msg in &errors {
                error!("Incremental config rejected: {}", msg);
            }
            return false;
        }
        if let Err(errors) = new_config.validate_plugin_references() {
            for msg in &errors {
                error!("Incremental config rejected: {}", msg);
            }
            return false;
        }
        let reserved_ports = self.env_config.reserved_gateway_ports();
        if let Err(errors) = new_config.validate_stream_proxy_port_conflicts(&reserved_ports) {
            if matches!(
                self.env_config.mode,
                crate::config::env_config::OperatingMode::DataPlane
            ) {
                for msg in &errors {
                    warn!(
                        "Incremental stream proxy port conflict (non-fatal in DP mode): {}",
                        msg
                    );
                }
            } else {
                for msg in &errors {
                    error!("Incremental config rejected: {}", msg);
                }
                return false;
            }
        }

        // Build a ConfigDelta to feed into existing cache apply_delta() methods.
        // For incremental results, we treat all changed resources as "modified"
        // since the DB layer doesn't distinguish adds from modifications.
        // The cache apply_delta methods handle both cases correctly.
        let old_config = self.config.load_full();

        // Use ConfigDelta::compute against old + new to get proper add/modify/remove classification
        let delta = crate::config_delta::ConfigDelta::compute(&old_config, &new_config);

        // --- RouterCache ---
        let affected_paths = delta.affected_listen_paths(&old_config);
        self.router_cache.apply_delta(&new_config, &affected_paths);

        // --- PluginCache ---
        let proxy_ids_to_rebuild = delta.proxy_ids_needing_plugin_rebuild(&new_config);
        let rebuild_globals = delta
            .added_plugin_configs
            .iter()
            .chain(delta.modified_plugin_configs.iter())
            .any(|pc| pc.scope == crate::config::types::PluginScope::Global)
            || !delta.removed_plugin_config_ids.is_empty();
        if let Err(e) = self.plugin_cache.apply_delta(
            &new_config,
            &proxy_ids_to_rebuild,
            &delta.removed_proxy_ids,
            rebuild_globals,
        ) {
            error!(
                "Config reload rejected — security plugin validation failed: {}",
                e
            );
            return false;
        }

        // --- ConsumerIndex ---
        self.consumer_index.apply_delta(
            &delta.added_consumers,
            &delta.removed_consumer_ids,
            &delta.modified_consumers,
        );

        // --- LoadBalancerCache ---
        self.load_balancer_cache.apply_delta(
            &new_config,
            &delta.added_upstreams,
            &delta.removed_upstream_ids,
            &delta.modified_upstreams,
        );

        // --- CircuitBreakerCache ---
        if !delta.removed_proxy_ids.is_empty() {
            self.circuit_breaker_cache.prune(&delta.removed_proxy_ids);
        }

        // Prune stale upstream targets from circuit breaker cache
        {
            let mut active_keys = std::collections::HashSet::new();
            for proxy in &new_config.proxies {
                if let Some(ref upstream_id) = proxy.upstream_id
                    && let Some(upstream) =
                        new_config.upstreams.iter().find(|u| u.id == *upstream_id)
                {
                    for target in &upstream.targets {
                        active_keys
                            .insert(format!("{}::{}:{}", proxy.id, target.host, target.port));
                    }
                }
            }
            self.circuit_breaker_cache.prune_stale_targets(&active_keys);
        }

        // --- HealthChecker: prune passive health state for removed proxies ---
        if !delta.removed_proxy_ids.is_empty() {
            self.health_checker
                .prune_removed_proxies(&delta.removed_proxy_ids);
        }

        // --- DNS warmup for new/modified hostnames ---
        let mut new_hostnames: Vec<(String, Option<String>, Option<u64>)> = Vec::new();
        for proxy in delta
            .added_proxies
            .iter()
            .chain(delta.modified_proxies.iter())
        {
            new_hostnames.push((
                proxy.backend_host.clone(),
                proxy.dns_override.clone(),
                proxy.dns_cache_ttl_seconds,
            ));
        }
        for upstream in delta
            .added_upstreams
            .iter()
            .chain(delta.modified_upstreams.iter())
        {
            for target in &upstream.targets {
                new_hostnames.push((target.host.clone(), None, None));
            }
        }
        if !new_hostnames.is_empty() {
            let dns = self.dns_cache.clone();
            tokio::spawn(async move {
                dns.warmup(new_hostnames).await;
            });
        }

        // Prune adaptive buffer state for removed proxies.
        {
            let active_ids: Vec<&str> = new_config.proxies.iter().map(|p| p.id.as_str()).collect();
            self.adaptive_buffer.prune_missing(&active_ids);
        }

        // Store updated config
        self.config.store(Arc::new(new_config));

        // Reconcile stream proxy listeners if any stream proxies changed
        let removed_had_stream = if !delta.removed_proxy_ids.is_empty() {
            let removed_set: std::collections::HashSet<&str> =
                delta.removed_proxy_ids.iter().map(|s| s.as_str()).collect();
            old_config.proxies.iter().any(|p| {
                removed_set.contains(p.id.as_str()) && p.backend_protocol.is_stream_proxy()
            })
        } else {
            false
        };
        let stream_proxies_changed = delta
            .added_proxies
            .iter()
            .chain(delta.modified_proxies.iter())
            .any(|p| p.backend_protocol.is_stream_proxy())
            || removed_had_stream;
        if stream_proxies_changed {
            let failures = self.stream_listener_manager.reconcile().await;
            for (proxy_id, port, err) in &failures {
                tracing::error!(
                    proxy_id = %proxy_id,
                    port = port,
                    "Stream listener failed to bind on incremental config update: {}",
                    err
                );
            }
        }

        info!(
            "Incremental config applied: proxies: +{} -{} ~{}, consumers: +{} -{} ~{}, plugins: +{} -{} ~{}, upstreams: +{} -{} ~{}",
            delta.added_proxies.len(),
            delta.removed_proxy_ids.len(),
            delta.modified_proxies.len(),
            delta.added_consumers.len(),
            delta.removed_consumer_ids.len(),
            delta.modified_consumers.len(),
            delta.added_plugin_configs.len(),
            delta.removed_plugin_config_ids.len(),
            delta.modified_plugin_configs.len(),
            delta.added_upstreams.len(),
            delta.removed_upstream_ids.len(),
            delta.modified_upstreams.len(),
        );

        // Reconcile service discovery tasks for changed upstreams
        if !delta.added_upstreams.is_empty()
            || !delta.removed_upstream_ids.is_empty()
            || !delta.modified_upstreams.is_empty()
        {
            let new_cfg = self.config.load_full();
            self.service_discovery_manager.reconcile(&new_cfg, None);
        }

        true
    }

    pub fn current_config(&self) -> Arc<GatewayConfig> {
        self.config.load_full()
    }
}

/// Handle a plain HTTP TCP connection (HTTP/1.1 and HTTP/2 cleartext via h2c).
///
/// Uses hyper-util's auto builder which accepts both HTTP/1.1 and HTTP/2
/// connections. h2c (cleartext HTTP/2) is required for gRPC clients that
/// connect without TLS.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    state: ProxyState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Set TCP keepalive on inbound connection to detect stale clients
    set_tcp_keepalive(&stream);

    // Use TokioIo to adapt the TCP stream for hyper
    let io = TokioIo::new(stream);

    // Use auto builder to support both HTTP/1.1 and HTTP/2 cleartext (h2c).
    // This is needed for gRPC clients that use h2c prior knowledge.
    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    {
        let mut http1 = builder.http1();
        http1.max_buf_size(state.max_header_size_bytes);
        // Slowloris protection: close connections that take too long to send headers.
        if state.env_config.http_header_read_timeout_seconds > 0 {
            http1.timer(hyper_util::rt::TokioTimer::new());
            http1.header_read_timeout(std::time::Duration::from_secs(
                state.env_config.http_header_read_timeout_seconds,
            ));
        }
    }
    let pool_cfg = state.connection_pool.global_pool_config();
    builder
        .http2()
        .max_header_list_size(state.max_header_size_bytes.min(u32::MAX as usize) as u32)
        .initial_stream_window_size(pool_cfg.http2_initial_stream_window_size)
        .initial_connection_window_size(pool_cfg.http2_initial_connection_window_size)
        .adaptive_window(pool_cfg.http2_adaptive_window)
        .max_frame_size(pool_cfg.http2_max_frame_size)
        .max_concurrent_streams(state.env_config.server_http2_max_concurrent_streams)
        .max_pending_accept_reset_streams(Some(
            state
                .env_config
                .server_http2_max_pending_accept_reset_streams,
        ))
        .max_local_error_reset_streams(Some(
            state.env_config.server_http2_max_local_error_reset_streams,
        ))
        // RFC 8441: Advertise SETTINGS_ENABLE_CONNECT_PROTOCOL so HTTP/2 clients
        // can initiate WebSocket connections via Extended CONNECT.
        .enable_connect_protocol();

    // WebSocket requests flow through handle_proxy_request so that authentication
    // and authorization plugins execute before the upgrade handshake.
    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let addr = remote_addr;
        async move { handle_proxy_request(req, state, addr, false, None, None).await }
    });
    if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
        let err_string = e.to_string();
        if is_client_disconnect_error(&err_string) {
            debug!(
                remote_addr = %remote_addr.ip(),
                error_kind = "client_disconnect",
                error = %e,
                "Client disconnected before response completed"
            );
        } else {
            debug!(error = %e, "Connection error");
        }
    }

    Ok(())
}

/// Check if a hyper connection error indicates a client disconnect.
fn is_client_disconnect_error(err: &str) -> bool {
    err.contains("connection reset")
        || err.contains("broken pipe")
        || err.contains("connection abort")
        || err.contains("not connected")
        || err.contains("early eof")
        || err.contains("incomplete message")
        || err.contains("connection closed before")
}

/// Set TCP keepalive on a stream to detect dead connections.
fn set_tcp_keepalive(stream: &tokio::net::TcpStream) {
    #[cfg(unix)]
    use std::os::fd::AsFd;
    #[cfg(windows)]
    use std::os::windows::io::AsSocket;

    // Disable Nagle's algorithm for lower latency on small responses
    let _ = stream.set_nodelay(true);
    #[cfg(unix)]
    let borrowed = stream.as_fd();
    #[cfg(windows)]
    let borrowed = stream.as_socket();
    let socket = socket2::SockRef::from(&borrowed);
    let keepalive = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(60));
    if let Err(e) = socket.set_tcp_keepalive(&keepalive) {
        debug!("Failed to set TCP keepalive: {}", e);
    }
}

pub fn try_acquire_websocket_connection_permit(
    limit: Option<&Arc<tokio::sync::Semaphore>>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, tokio::sync::TryAcquireError> {
    match limit {
        Some(limit) => limit.clone().try_acquire_owned().map(Some),
        None => Ok(None),
    }
}

/// Handle WebSocket requests AFTER authentication and authorization plugins have run.
///
/// Supports both HTTP/1.1 Upgrade (101 Switching Protocols) and HTTP/2 Extended CONNECT
/// (RFC 8441, 200 OK). The `is_h2_websocket` flag selects the response path; the backend
/// connection, bidirectional relay, and frame-level plugins are identical for both.
#[allow(clippy::too_many_arguments)]
async fn handle_websocket_request_authenticated(
    req: Request<Incoming>,
    state: ProxyState,
    remote_addr: SocketAddr,
    proxy: Arc<Proxy>,
    ctx: RequestContext,
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
    plugin_execution_ns: u64,
    upstream_target: Option<Arc<UpstreamTarget>>,
    lb_hash_key: Option<String>,
    sticky_cookie_needed: bool,
    start_time: Instant,
    is_h2_websocket: bool,
    is_tls: bool,
) -> Result<Response<ProxyBody>, hyper::Error> {
    info!(
        "WebSocket upgrade request authenticated for proxy: {} from: {}",
        proxy.id,
        remote_addr.ip()
    );

    // Build backend URL using upstream target if available
    let query_string = req.uri().query().unwrap_or("").to_string();
    let (effective_host, effective_port) = if let Some(ref target) = upstream_target {
        (target.host.as_str(), target.port)
    } else {
        (proxy.backend_host.as_str(), proxy.backend_port)
    };
    let backend_url = build_websocket_backend_url_with_target(
        &proxy,
        &ctx.path,
        &query_string,
        effective_host,
        effective_port,
        upstream_target.as_ref().and_then(|t| t.path.as_deref()),
    );

    // Get the upgrade parts from the request
    let (mut parts, _body) = req.into_parts();

    // Extract the OnUpgrade future
    let on_upgrade = match parts.extensions.remove::<OnUpgrade>() {
        Some(on_upgrade) => on_upgrade,
        None => {
            error!("Failed to extract OnUpgrade extension from WebSocket request");
            return Ok(build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"Internal server error during WebSocket upgrade"}"#,
            ));
        }
    };

    // Reject upgrades once the dedicated WebSocket pool is full.
    // This protects against idle upgraded-connection exhaustion without adding
    // any work to the per-frame forwarding path.
    let ws_connection_permit =
        match try_acquire_websocket_connection_permit(state.websocket_conn_limit.as_ref()) {
            Ok(permit) => permit,
            Err(_) => {
                warn!(
                    proxy_id = %proxy.id,
                    client_ip = %ctx.client_ip,
                    websocket_limit = state.env_config.websocket_max_connections,
                    "Rejecting WebSocket upgrade: connection limit reached"
                );
                log_rejected_request(
                    &plugins,
                    &ctx,
                    503,
                    start_time,
                    "websocket_connection_limit",
                    plugin_execution_ns,
                )
                .await;
                record_request(&state, 503);
                return Ok(build_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    r#"{"error":"WebSocket connection limit exceeded"}"#,
                ));
            }
        };

    // Collect client headers to forward to backend
    let mut client_headers = collect_forwardable_headers(&parts.headers);

    // Inject authenticated identity headers for WebSocket connections.
    if let Some(username) = ctx.backend_consumer_username() {
        client_headers.push(("x-consumer-username".to_string(), username.to_string()));
    }
    if let Some(custom_id) = ctx.backend_consumer_custom_id() {
        client_headers.push(("x-consumer-custom-id".to_string(), custom_id.to_string()));
    }

    // Connect to backend BEFORE sending 101 to client.
    // If the backend is unreachable, we return 502 instead of a premature 101.
    // Supports retry with upstream target rotation for connection failures.
    let env_config = state.env_config.clone();
    let mut current_backend_url = backend_url;
    let mut current_target = upstream_target;
    let mut ws_attempt = 0u32;

    let backend_ws_stream = loop {
        match connect_websocket_backend(
            &current_backend_url,
            &proxy,
            &env_config,
            &client_headers,
            state.tls_policy.as_deref(),
            &state.crls,
            state.max_websocket_frame_size_bytes,
            state.websocket_write_buffer_size,
        )
        .await
        {
            Ok(stream) => break stream,
            Err(e) => {
                let ws_error_class = retry::classify_boxed_error(e.as_ref());
                let is_ws_dns_error = ws_error_class == retry::ErrorClass::DnsLookupError;

                // Check if we should retry this connection failure
                let should_retry_ws = if let Some(retry_config) = &proxy.retry {
                    ws_attempt < retry_config.max_retries && retry_config.retry_on_connect_failure
                } else {
                    false
                };

                if should_retry_ws {
                    // Safety: should_retry_ws is only true when proxy.retry.is_some()
                    // (see condition above). Fall through to 502 if the invariant
                    // ever breaks due to a refactor, rather than panicking.
                    let retry_config = match proxy.retry.as_ref() {
                        Some(rc) => rc,
                        None => {
                            let ws_body = if is_ws_dns_error {
                                r#"{"error":"DNS resolution for backend failed"}"#
                            } else {
                                r#"{"error":"Backend WebSocket connection failed"}"#
                            };
                            return Ok(build_response(StatusCode::BAD_GATEWAY, ws_body));
                        }
                    };

                    // Record circuit breaker failure for current target
                    if let Some(cb_config) = &proxy.circuit_breaker {
                        let cb_key = current_target
                            .as_ref()
                            .map(|t| crate::circuit_breaker::target_key(&t.host, t.port));
                        let cb = state.circuit_breaker_cache.get_or_create(
                            &proxy.id,
                            cb_key.as_deref(),
                            cb_config,
                        );
                        cb.record_failure(502, true);
                    }

                    let delay = retry::retry_delay(retry_config, ws_attempt);
                    tokio::time::sleep(delay).await;
                    ws_attempt += 1;

                    // Try a different target on retry if load balancing is configured
                    if let (Some(upstream_id), Some(prev_target)) =
                        (&proxy.upstream_id, &current_target)
                        && let Some(ref hash_key) = lb_hash_key
                        && let Some(next) = state.load_balancer_cache.select_next_target(
                            upstream_id,
                            hash_key,
                            prev_target,
                            Some(&crate::load_balancer::HealthContext {
                                active_unhealthy: &state.health_checker.active_unhealthy_targets,
                                proxy_passive: state
                                    .health_checker
                                    .passive_health
                                    .get(&proxy.id)
                                    .map(|r| r.value().clone()),
                            }),
                        )
                    {
                        current_backend_url = build_websocket_backend_url_with_target(
                            &proxy,
                            &ctx.path,
                            &query_string,
                            &next.host,
                            next.port,
                            next.path.as_deref(),
                        );
                        current_target = Some(next);
                    }

                    warn!(
                        proxy_id = %proxy.id,
                        attempt = ws_attempt,
                        max_retries = retry_config.max_retries,
                        error_class = %ws_error_class,
                        "Retrying WebSocket backend connection"
                    );
                    continue;
                }

                // No retry — return error
                error!(
                    proxy_id = %proxy.id,
                    backend_url = %current_backend_url,
                    error_kind = "connect_failure",
                    error_class = %ws_error_class,
                    error = %e,
                    "WebSocket backend connection failed"
                );
                state.request_count.fetch_add(1, Ordering::Relaxed);
                record_status(&state, 502);

                // Log with error_class for WebSocket backend failures.
                // Dispatch to the full plugin chain — the default `.log()` impl
                // is a no-op, and plugins outside the logging priority band
                // (e.g., `otel_tracing` at priority 25) still need the hook so
                // rejected/error transactions reach tracing sinks.
                if !plugins.is_empty() {
                    {
                        // Use monotonic Instant rather than wall-clock to avoid NTP skew.
                        let ws_total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
                        let ws_plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
                        let ws_plugin_external_io_ms =
                            ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
                        let ws_gateway_overhead_ms =
                            (ws_total_ms - ws_plugin_execution_ms).max(0.0);
                        let mut metadata = ctx.metadata.clone();
                        metadata.insert(
                            "rejection_phase".to_string(),
                            "websocket_backend_error".to_string(),
                        );
                        let ws_err_method = if is_h2_websocket { "CONNECT" } else { "GET" };
                        let summary = TransactionSummary {
                            namespace: proxy.namespace.clone(),
                            timestamp_received: ctx.timestamp_received.to_rfc3339(),
                            client_ip: ctx.client_ip.clone(),
                            consumer_username: ctx.effective_identity().map(str::to_owned),
                            http_method: ws_err_method.to_string(),
                            request_path: ctx.path.clone(),
                            matched_proxy_id: Some(proxy.id.clone()),
                            matched_proxy_name: proxy.name.clone(),
                            backend_target_url: Some(
                                strip_query_params(&current_backend_url).to_string(),
                            ),
                            backend_resolved_ip: None,
                            response_status_code: 502,
                            latency_total_ms: ws_total_ms,
                            latency_gateway_processing_ms: ws_total_ms,
                            latency_backend_ttfb_ms: -1.0,
                            latency_backend_total_ms: -1.0,
                            latency_plugin_execution_ms: ws_plugin_execution_ms,
                            latency_plugin_external_io_ms: ws_plugin_external_io_ms,
                            latency_gateway_overhead_ms: ws_gateway_overhead_ms,
                            request_user_agent: ctx.headers.get("user-agent").cloned(),
                            response_streamed: false,
                            client_disconnected: false,
                            error_class: Some(ws_error_class),
                            body_error_class: None,
                            body_completed: false,
                            bytes_streamed_to_client: 0,
                            mirror: false,
                            metadata,
                        };
                        crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;
                    }
                }

                let ws_body = if is_ws_dns_error {
                    r#"{"error":"DNS resolution for backend failed"}"#
                } else {
                    r#"{"error":"Backend WebSocket connection failed"}"#
                };
                return Ok(build_response(StatusCode::BAD_GATEWAY, ws_body));
            }
        }
    };

    // Backend verified — record status and log.
    // HTTP/2 Extended CONNECT returns 200 OK; HTTP/1.1 returns 101 Switching Protocols.
    let ws_status_code: u16 = if is_h2_websocket { 200 } else { 101 };
    state.request_count.fetch_add(1, Ordering::Relaxed);
    record_status(&state, ws_status_code);

    // Measure total latency using monotonic Instant (NTP-safe).
    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;

    // Resolve backend IP from DNS cache for WebSocket tx log
    let ws_resolved_ip = state
        .dns_cache
        .resolve(
            &proxy.backend_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    let ws_plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
    let ws_plugin_external_io_ms =
        ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let ws_gateway_overhead_ms = (total_ms - ws_plugin_execution_ms).max(0.0);

    let ws_method = if is_h2_websocket { "CONNECT" } else { "GET" };
    let summary = TransactionSummary {
        namespace: proxy.namespace.clone(),
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.effective_identity().map(str::to_owned),
        http_method: ws_method.to_string(),
        request_path: ctx.path.clone(),
        matched_proxy_id: Some(proxy.id.clone()),
        matched_proxy_name: proxy.name.clone(),
        backend_target_url: Some(strip_query_params(&current_backend_url).to_string()),
        backend_resolved_ip: ws_resolved_ip,
        response_status_code: ws_status_code,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: total_ms,
        latency_backend_ttfb_ms: 0.0,
        latency_backend_total_ms: 0.0,
        latency_plugin_execution_ms: ws_plugin_execution_ms,
        latency_plugin_external_io_ms: ws_plugin_external_io_ms,
        latency_gateway_overhead_ms: ws_gateway_overhead_ms,
        request_user_agent: ctx.headers.get("user-agent").cloned(),
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: false,
        bytes_streamed_to_client: 0,
        mirror: false,
        metadata: ctx.metadata.clone(),
    };

    crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;

    // Build the upgrade response.
    // HTTP/2 Extended CONNECT (RFC 8441): 200 OK — the H2 stream becomes the WebSocket
    // transport. No Upgrade/Connection/Sec-WebSocket-Accept headers (those are HTTP/1.1).
    // HTTP/1.1: 101 Switching Protocols with standard WebSocket handshake headers.
    let mut ws_resp_builder = if is_h2_websocket {
        Response::builder().status(StatusCode::OK)
    } else {
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("upgrade", "websocket")
            .header("connection", "upgrade")
            .header(
                "sec-websocket-accept",
                derive_accept_key(
                    parts
                        .headers
                        .get("sec-websocket-key")
                        .and_then(|k| k.to_str().ok())
                        .unwrap_or("")
                        .as_bytes(),
                ),
            )
    };

    // Inject sticky session cookie on WebSocket upgrade responses
    if sticky_cookie_needed
        && let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, &current_target)
    {
        let strategy = state.load_balancer_cache.get_hash_on_strategy(upstream_id);
        if let HashOnStrategy::Cookie(ref cookie_name) = strategy {
            let upstream = state.load_balancer_cache.get_upstream(upstream_id);
            let default_cc = crate::config::types::HashOnCookieConfig::default();
            let cookie_config = upstream
                .as_ref()
                .and_then(|u| u.hash_on_cookie_config.as_ref())
                .unwrap_or(&default_cc);
            let cookie_val = build_sticky_cookie_header(cookie_name, target, cookie_config);
            ws_resp_builder = ws_resp_builder.header("set-cookie", cookie_val);
        }
    }

    let upgrade_response = ws_resp_builder
        .body(ProxyBody::empty())
        .unwrap_or_else(|_| Response::new(ProxyBody::empty()));

    // Collect plugins that opted into per-frame WebSocket hooks.
    // The pre-computed flag avoids iterating the plugin list when no plugin opted in.
    let all_ws_plugins = if state.plugin_cache.requires_ws_frame_hooks(&proxy.id) {
        state
            .plugin_cache
            .get_plugins_for_protocol(&proxy.id, ProxyProtocol::WebSocket)
    } else {
        // Even when no frame hooks are needed, we still need to check for
        // disconnect hooks — those live on the same WebSocket protocol list.
        state
            .plugin_cache
            .get_plugins_for_protocol(&proxy.id, ProxyProtocol::WebSocket)
    };
    let ws_frame_plugins: Vec<Arc<dyn Plugin>> = all_ws_plugins
        .iter()
        .filter(|p| p.requires_ws_frame_hooks())
        .cloned()
        .collect();
    // Collect disconnect-hook plugins separately. These fire exactly once at
    // session end instead of per-frame, so keeping them in their own list
    // avoids the per-frame filter cost paid by the frame-hook path.
    let ws_disconnect_plugins: Vec<Arc<dyn Plugin>> = all_ws_plugins
        .iter()
        .filter(|p| p.requires_ws_disconnect_hooks())
        .cloned()
        .collect();

    // Spawn bidirectional forwarding task (awaits client upgrade, then proxies)
    let proxy_id = proxy.id.clone();
    let ws_conn_id = state.ws_connection_counter.fetch_add(1, Ordering::Relaxed);
    let max_ws_frame = state.max_websocket_frame_size_bytes;
    let ws_write_buf = state.websocket_write_buffer_size;
    let ws_tunnel = state.websocket_tunnel_mode;
    let adaptive_buf = state.adaptive_buffer.clone();
    // Capture session metadata while the originating RequestContext + proxy are
    // still in scope. Passed to run_websocket_proxy so it can construct a
    // WsDisconnectContext at teardown for plugins that opted in to
    // on_ws_disconnect. Building this here (vs. inside run_websocket_proxy) is
    // effectively free when ws_disconnect_plugins is empty because the strings
    // are moved, not cloned, into an owned struct.
    // WebSocket upgrades arrive on either the plaintext HTTP proxy listener or
    // the TLS HTTPS/H2 listener. Choose the matching port so disconnect
    // metadata, logging plugins, and downstream alerts key on the port the
    // client actually connected to instead of always reporting the plaintext
    // port (which is misleading — or `0` — on TLS-only deployments).
    let listen_port = if is_tls {
        state.env_config.proxy_https_port
    } else {
        state.env_config.proxy_http_port
    };
    let session_meta = WsSessionMeta {
        namespace: proxy.namespace.clone(),
        proxy_name: proxy.name.clone(),
        client_ip: ctx.client_ip.clone(),
        backend_target: strip_query_params(&current_backend_url).to_string(),
        listen_port,
        consumer_username: ctx.effective_identity().map(str::to_owned),
        metadata: ctx.metadata.clone(),
        session_start: chrono::Utc::now(),
    };
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Err(e) = run_websocket_proxy(
                    upgraded,
                    backend_ws_stream,
                    &proxy_id,
                    ws_conn_id,
                    ws_frame_plugins,
                    ws_disconnect_plugins,
                    session_meta,
                    ws_connection_permit,
                    max_ws_frame,
                    ws_write_buf,
                    ws_tunnel,
                    &adaptive_buf,
                )
                .await
                {
                    error!("WebSocket proxying error for {}: {}", proxy_id, e);
                }
            }
            Err(e) => {
                error!(
                    "Failed to upgrade WebSocket connection for {}: {}",
                    proxy_id, e
                );
            }
        }
    });

    info!(
        "WebSocket upgrade response sent for authenticated connection: {} -> {}",
        proxy.id, current_backend_url
    );

    Ok(upgrade_response)
}

/// Collect headers from the client request that should be forwarded to the backend WebSocket.
/// Hop-by-hop headers and WebSocket handshake headers are excluded.
fn collect_forwardable_headers(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    /// Headers that must not be forwarded (hop-by-hop per RFC 9110 §7.6.1 + WS handshake).
    const SKIP_HEADERS: &[&str] = &[
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-accept",
        "host",
        "transfer-encoding",
        "te",
        "trailer",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
    ];

    headers
        .iter()
        .filter_map(|(name, value)| {
            // hyper already lowercases header names per HTTP/2 spec
            let name_str = name.as_str();
            if SKIP_HEADERS.contains(&name_str) {
                return None;
            }
            value
                .to_str()
                .ok()
                .map(|v| (name_str.to_string(), v.to_string()))
        })
        .collect()
}

/// Build a WebSocket backend URL using a specific target host/port,
/// respecting strip_listen_path, backend_path, and query string.
///
/// Uses a single pre-sized `String` buffer to avoid intermediate allocations
/// from multiple `format!()` calls (matches `build_backend_url_with_target`).
fn build_websocket_backend_url_with_target(
    proxy: &Proxy,
    incoming_path: &str,
    query_string: &str,
    host: &str,
    port: u16,
    target_path: Option<&str>,
) -> String {
    use std::fmt::Write;

    let scheme = match proxy.backend_protocol {
        BackendProtocol::Ws => "ws",
        BackendProtocol::Wss => "wss",
        _ => "ws", // fallback, should not happen
    };

    let remaining_path = if proxy.strip_listen_path {
        incoming_path.strip_prefix(&proxy.listen_path).unwrap_or("")
    } else {
        incoming_path
    };

    let backend_path = target_path.or(proxy.backend_path.as_deref()).unwrap_or("");

    // Both empty means path is just "/"
    let path_is_root = backend_path.is_empty() && remaining_path.is_empty();

    // Determine if we need to prepend a '/'. The first byte of the combined
    // path is determined by backend_path (if non-empty) or remaining_path.
    let combined_starts_with_slash = if !backend_path.is_empty() {
        backend_path.starts_with('/')
    } else {
        remaining_path.starts_with('/')
    };
    let needs_leading_slash = !path_is_root && !combined_starts_with_slash;

    // Pre-calculate capacity and build in a single buffer.
    let path_len = if path_is_root {
        1
    } else {
        (if needs_leading_slash { 1 } else { 0 }) + backend_path.len() + remaining_path.len()
    };
    let capacity = scheme.len()
        + 3 // "://"
        + host.len()
        + 6 // ":PORT" (max 5 digits + colon)
        + path_len
        + if query_string.is_empty() {
            0
        } else {
            1 + query_string.len()
        };

    let mut url = String::with_capacity(capacity);
    let _ = write!(url, "{}://{}:{}", scheme, host, port);

    if path_is_root {
        url.push('/');
    } else {
        if needs_leading_slash {
            url.push('/');
        }
        url.push_str(backend_path);
        url.push_str(remaining_path);
    }

    if !query_string.is_empty() {
        url.push('?');
        url.push_str(query_string);
    }

    url
}

/// Build a rustls TLS connector for WebSocket backends that respects
/// proxy-level and global TLS settings (CA bundles, client certs, cert verification).
/// When `tls_policy` is provided, outbound connections use the same cipher suites,
/// protocol versions, and key exchange groups as inbound listeners.
fn build_websocket_tls_connector(
    proxy: &Proxy,
    env_config: &crate::config::EnvConfig,
    tls_policy: Option<&TlsPolicy>,
    crls: &crate::tls::CrlList,
) -> Result<Option<tokio_tungstenite::Connector>, anyhow::Error> {
    // Only build a TLS connector for wss:// backends
    if proxy.backend_protocol != BackendProtocol::Wss {
        return Ok(None);
    }

    // Determine if we should skip server cert verification
    let skip_verify = env_config.tls_no_verify || !proxy.resolved_tls.verify_server_cert;

    // Build root certificate store:
    // - Custom CA configured → empty store + only that CA (no public roots)
    // - No CA configured → webpki/system roots as default fallback
    let ca_path = proxy
        .resolved_tls
        .server_ca_cert_path
        .as_ref()
        .or(env_config.tls_ca_bundle_path.as_ref());
    let mut root_store = if ca_path.is_some() {
        rustls::RootCertStore::empty()
    } else {
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
    };
    if let Some(ca_path) = ca_path {
        let ca_pem = std::fs::read(ca_path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to read CA bundle '{}' for WebSocket TLS: {}",
                ca_path,
                e
            )
        })?;
        let mut cursor = std::io::Cursor::new(ca_pem);
        let certs = rustls_pemfile::certs(&mut cursor);
        for cert in certs.flatten() {
            root_store.add(cert).map_err(|e| {
                anyhow::anyhow!("Failed to add CA certificate for WebSocket TLS: {}", e)
            })?;
        }
    }

    // Build client config with TLS policy (cipher suites, protocol versions)
    let builder = match crate::tls::backend_client_config_builder(tls_policy) {
        Ok(b) => {
            let verifier = crate::tls::build_server_verifier_with_crls(root_store, crls)?;
            b.with_webpki_verifier(verifier)
        }
        Err(e) => {
            warn!(
                "Failed to build WebSocket TLS config with policy: {}, using defaults",
                e
            );
            let fallback_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let verifier = crate::tls::build_server_verifier_with_crls(fallback_store, crls)?;
            rustls::ClientConfig::builder().with_webpki_verifier(verifier)
        }
    };

    // Add client certificate for mTLS (resolved_tls overrides take priority)
    let cert_path = proxy
        .resolved_tls
        .client_cert_path
        .as_ref()
        .or(env_config.backend_tls_client_cert_path.as_ref());
    let key_path = proxy
        .resolved_tls
        .client_key_path
        .as_ref()
        .or(env_config.backend_tls_client_key_path.as_ref());

    let mut client_config = if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
        let cert_pem = std::fs::read(cert_path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to read client cert '{}' for WebSocket mTLS: {}",
                cert_path,
                e
            )
        })?;
        let key_pem = std::fs::read(key_path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to read client key '{}' for WebSocket mTLS: {}",
                key_path,
                e
            )
        })?;
        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::Cursor::new(&cert_pem))
            .flatten()
            .collect();
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(&key_pem))
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to parse private key '{}' for WebSocket mTLS: {}",
                    key_path,
                    e
                )
            })?
            .ok_or_else(|| {
                anyhow::anyhow!("No private key found in '{}' for WebSocket mTLS", key_path)
            })?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("Failed to configure WebSocket mTLS client cert: {}", e))?
    } else {
        builder.with_no_client_auth()
    };

    // Disable server certificate verification only if explicitly opted out
    if skip_verify {
        warn!(
            "WebSocket backend TLS certificate verification DISABLED for proxy {}",
            proxy.id
        );
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }

    Ok(Some(tokio_tungstenite::Connector::Rustls(Arc::new(
        client_config,
    ))))
}

/// Connect to backend WebSocket server before sending 101 to client.
/// Returns the connected backend stream, or an error if the backend is unreachable.
#[allow(clippy::too_many_arguments)]
async fn connect_websocket_backend(
    backend_url: &str,
    proxy: &Proxy,
    env_config: &crate::config::EnvConfig,
    client_headers: &[(String, String)],
    tls_policy: Option<&TlsPolicy>,
    crls: &crate::tls::CrlList,
    max_websocket_frame_size_bytes: usize,
    websocket_write_buffer_size: usize,
) -> Result<
    WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let mut ws_config = WebSocketConfig::default();
    ws_config.max_frame_size = Some(max_websocket_frame_size_bytes);
    ws_config.max_message_size = Some(max_websocket_frame_size_bytes.saturating_mul(4));
    ws_config.write_buffer_size = websocket_write_buffer_size;

    let mut ws_request = backend_url.into_client_request()?;
    for (name, value) in client_headers {
        if let (Ok(header_name), Ok(header_value)) = (
            hyper::header::HeaderName::from_bytes(name.as_bytes()),
            hyper::header::HeaderValue::from_str(value),
        ) {
            ws_request.headers_mut().insert(header_name, header_value);
        }
    }

    let connector = build_websocket_tls_connector(proxy, env_config, tls_policy, crls)?;
    let connect_timeout = std::time::Duration::from_millis(proxy.backend_connect_timeout_ms);
    let connect_future =
        connect_async_tls_with_config(ws_request, Some(ws_config), false, connector);

    let (backend_ws_stream, backend_response) =
        match tokio::time::timeout(connect_timeout, connect_future).await {
            Ok(result) => result?,
            Err(_) => {
                error!(
                    proxy_id = %proxy.id,
                    backend_url = %backend_url,
                    timeout_ms = proxy.backend_connect_timeout_ms,
                    error_kind = "connect_timeout",
                    "WebSocket backend connect timeout"
                );
                return Err(format!(
                    "WebSocket backend connect timeout ({}ms) for proxy {}",
                    proxy.backend_connect_timeout_ms, proxy.id
                )
                .into());
            }
        };

    debug!("Connected to backend WebSocket server: {}", backend_url);
    debug!("Backend response status: {}", backend_response.status());

    Ok(backend_ws_stream)
}

/// Run bidirectional WebSocket proxying between upgraded client and connected backend.
///
/// Session-level metadata captured at WebSocket upgrade time and consumed at
/// teardown when firing `on_ws_disconnect`. Held as an owned struct (not
/// references) because the upgrade handler returns before the session ends,
/// so all fields must outlive the originating request context.
#[doc(hidden)]
pub struct WsSessionMeta {
    pub namespace: String,
    pub proxy_name: Option<String>,
    pub client_ip: String,
    pub backend_target: String,
    pub listen_port: u16,
    pub consumer_username: Option<String>,
    pub metadata: HashMap<String, String>,
    pub session_start: chrono::DateTime<chrono::Utc>,
}

/// Fire `on_ws_disconnect` for the tunnel-mode path, where raw
/// `copy_bidirectional` is used instead of frame-level parsing.
///
/// Tunnel mode does not track frame counts (all bytes flow as raw TCP), so
/// `frames_client_to_backend` / `frames_backend_to_client` are reported as
/// `0`. Direction attribution is best-effort: drain-phase write errors to
/// the client are attributed to `BackendToClient`; the `copy_bidirectional`
/// error path has no per-direction attribution and reports
/// `Direction::Unknown`. Observers that require direction/count fidelity
/// should disable tunnel mode for the proxy.
///
/// The helper takes `ws_disconnect_plugins` by slice and `session_meta` by
/// reference so the caller keeps ownership for the duration of the call.
#[doc(hidden)]
pub async fn fire_ws_tunnel_disconnect_hooks(
    ws_disconnect_plugins: &[Arc<dyn Plugin>],
    proxy_id: &str,
    session_meta: &WsSessionMeta,
    failure: Option<(crate::plugins::Direction, retry::ErrorClass)>,
) {
    if ws_disconnect_plugins.is_empty() {
        return;
    }
    let disconnect_duration_ms = (chrono::Utc::now() - session_meta.session_start)
        .num_milliseconds()
        .max(0) as f64;
    let disconnect_ctx = crate::plugins::WsDisconnectContext {
        namespace: session_meta.namespace.clone(),
        proxy_id: proxy_id.to_string(),
        proxy_name: session_meta.proxy_name.clone(),
        client_ip: session_meta.client_ip.clone(),
        backend_target: session_meta.backend_target.clone(),
        listen_port: session_meta.listen_port,
        duration_ms: disconnect_duration_ms,
        frames_client_to_backend: 0,
        frames_backend_to_client: 0,
        direction: failure.as_ref().map(|(d, _)| *d),
        error_class: failure.map(|(_, c)| c),
        consumer_username: session_meta.consumer_username.clone(),
        metadata: session_meta.metadata.clone(),
    };
    for plugin in ws_disconnect_plugins {
        plugin.on_ws_disconnect(&disconnect_ctx).await;
    }
}

/// `connection_id` — unique per-connection identifier for stateful frame plugins.
/// `ws_frame_plugins` — plugins that opted into per-frame hooks by returning `true`
/// from `requires_ws_frame_hooks()`. Pass an empty `Vec` for zero-overhead forwarding
/// when no plugin on this proxy needs frame inspection.
/// `ws_disconnect_plugins` — plugins that opted into end-of-session hooks by
/// returning `true` from `requires_ws_disconnect_hooks()`. Pass an empty `Vec`
/// to skip disconnect bookkeeping entirely.
/// `session_meta` — captured at upgrade time; used to populate `WsDisconnectContext`
/// when the session ends. Cost is paid regardless of whether disconnect plugins
/// are present (one small allocation per upgrade) because the struct is small
/// and moving it has zero additional cost.
/// `websocket_tunnel_mode` — when true and no frame plugins are configured, bypass
/// WebSocket frame parsing and use raw TCP bidirectional copy for maximum throughput.
///
/// Polite-close bound used when the cancel branch of each forward loop fires.
/// The opposite direction has already cancelled, so a plain `.await` on the
/// polite-Close send could hang indefinitely if the peer socket is dead or
/// backpressured. A Close control frame is small and completes in microseconds
/// on a healthy TCP connection, so 100ms is generous for the happy path while
/// still bounding teardown for pathological peers.
const WS_CANCEL_CLOSE_TIMEOUT_MS: u64 = 100;
#[allow(clippy::too_many_arguments)]
async fn run_websocket_proxy(
    upgraded: Upgraded,
    backend_ws_stream: WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    proxy_id: &str,
    connection_id: u64,
    ws_frame_plugins: Vec<Arc<dyn Plugin>>,
    ws_disconnect_plugins: Vec<Arc<dyn Plugin>>,
    session_meta: WsSessionMeta,
    _ws_connection_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    max_websocket_frame_size_bytes: usize,
    websocket_write_buffer_size: usize,
    websocket_tunnel_mode: bool,
    adaptive_buffer: &crate::adaptive_buffer::AdaptiveBufferTracker,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // When tunnel mode is enabled and no plugins need frame-level hooks, bypass
    // WebSocket frame parsing entirely and do raw TCP bidirectional copy. This
    // avoids per-frame header parsing, masking validation, and opcode dispatch —
    // critical for large frames (9 MB+). Trade-off: FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES
    // is not enforced, but data streams through a fixed-size copy buffer so there
    // is no large-allocation DoS risk.
    if websocket_tunnel_mode && ws_frame_plugins.is_empty() {
        debug!(
            proxy_id = %proxy_id,
            connection_id,
            "WebSocket tunnel mode: no frame plugins, using raw bidirectional copy"
        );
        // Drain any frames the backend sent piggybacked with the 101 response
        // before switching to raw mode. This prevents data loss for server-push
        // protocols that send immediately after the upgrade handshake.
        use futures_util::StreamExt;
        let (mut backend_write, mut backend_read) = backend_ws_stream.split();
        let mut client_io = TokioIo::new(upgraded);

        // Non-blocking drain: read any already-buffered frames and forward them
        // as raw WebSocket wire bytes via the tungstenite sink → client path.
        // In practice this is 0 frames for request-response protocols, 1-2 for
        // server-push protocols (e.g., stock tickers).
        while let std::task::Poll::Ready(Some(Ok(msg))) = futures_util::poll!(backend_read.next()) {
            // Re-serialize the frame and write to client via tungstenite's
            // framing layer so masking/headers are correct.
            if let Err(e) = backend_write.send(msg).await {
                warn!(
                    proxy_id = %proxy_id,
                    "WebSocket tunnel: failed to flush buffered frame: {e}"
                );
                // `backend_write` is the backend sink, so a failed send means
                // the backend-facing half broke — attribute to ClientToBackend.
                // Still run the disconnect hook before returning so observers
                // see the session teardown event.
                let drain_failure = Some((
                    crate::plugins::Direction::ClientToBackend,
                    retry::classify_boxed_error(&e),
                ));
                fire_ws_tunnel_disconnect_hooks(
                    &ws_disconnect_plugins,
                    proxy_id,
                    &session_meta,
                    drain_failure,
                )
                .await;
                return Ok(());
            }
        }
        // Reunite the backend stream and extract the raw transport
        let backend_ws = backend_read
            .reunite(backend_write)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
        let mut backend = backend_ws.into_inner();
        let buf_size = adaptive_buffer.get_buffer_size(proxy_id);
        let result = tokio::io::copy_bidirectional_with_sizes(
            &mut client_io,
            &mut backend,
            buf_size,
            buf_size,
        )
        .await;
        let tunnel_failure = match &result {
            Ok((c2b, b2c)) => {
                adaptive_buffer.record_connection(proxy_id, c2b.saturating_add(*b2c));
                None
            }
            Err(e) => {
                // `copy_bidirectional` doesn't report which half failed, so fall
                // back to `Direction::Unknown`. Observers that rely on direction
                // attribution should enable frame-level plugins instead of tunnel
                // mode.
                let anyhow_err: anyhow::Error =
                    anyhow::anyhow!("WebSocket tunnel copy error: {}", e);
                Some((
                    crate::plugins::Direction::Unknown,
                    crate::retry::classify_boxed_error(anyhow_err.as_ref()),
                ))
            }
        };
        // Fire on_ws_disconnect so plugins that opted into disconnect hooks see
        // the tunnel-mode session teardown. Frame counts are 0 because tunnel
        // mode does raw TCP bidirectional copy — no frames are parsed.
        fire_ws_tunnel_disconnect_hooks(
            &ws_disconnect_plugins,
            proxy_id,
            &session_meta,
            tunnel_failure,
        )
        .await;
        return Ok(());
    }

    let mut ws_config = WebSocketConfig::default();
    ws_config.max_frame_size = Some(max_websocket_frame_size_bytes);
    ws_config.max_message_size = Some(max_websocket_frame_size_bytes.saturating_mul(4));
    ws_config.write_buffer_size = websocket_write_buffer_size;

    let ws_stream = WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        Some(ws_config),
    )
    .await;

    // Split streams for bidirectional communication
    let (mut ws_sink, mut ws_stream) = ws_stream.split();
    let (mut backend_sink, mut backend_stream) = backend_ws_stream.split();

    // Clone Arc'd plugin list for each direction task.
    // When ws_frame_plugins is empty these clones are zero-cost (empty Vec).
    let ctb_plugins = ws_frame_plugins.clone();
    let btc_plugins = ws_frame_plugins;
    let proxy_id_ctb = proxy_id.to_string();
    let proxy_id_btc = proxy_id.to_string();

    // Per-direction frame counters for the on_ws_disconnect summary. Kept as
    // plain atomics (not protected by any lock) so the forward tasks can bump
    // them without coordination. Reads happen exactly once at teardown.
    let frames_c2b = Arc::new(AtomicU64::new(0));
    let frames_b2c = Arc::new(AtomicU64::new(0));
    let frames_c2b_task = frames_c2b.clone();
    let frames_b2c_task = frames_b2c.clone();

    // First-failure recorder. Whichever forward direction hits an error first
    // wins the (Direction, ErrorClass) slot via OnceLock::set(); later errors
    // from the other direction (or from the write-side of the same direction)
    // are dropped. Both directions still publish their clean-close outcome
    // through the counter, so "no error + clean close" is distinguishable
    // from "error observed on one half".
    let first_failure: Arc<std::sync::OnceLock<(crate::plugins::Direction, retry::ErrorClass)>> =
        Arc::new(std::sync::OnceLock::new());
    let first_failure_ctb = first_failure.clone();
    let first_failure_btc = first_failure.clone();

    // Cancellation token for clean bidirectional close when a plugin triggers Close.
    // Each direction checks this token to know if the other side initiated a close.
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_ctb = cancel.clone();
    let cancel_btc = cancel.clone();

    // Forward messages from client to backend
    let client_to_backend = async move {
        debug!("Starting client -> backend message forwarding");
        loop {
            tokio::select! {
                biased;
                _ = cancel_ctb.cancelled() => {
                    debug!("Client->backend: other direction triggered close");
                    // Bounded polite-close: the opposite direction has already
                    // cancelled us, so a plain `.await` on `backend_sink.send()`
                    // could hang forever if the backend socket is backpressured
                    // or dead. `lazy_timeout` pays zero cost when the send
                    // completes synchronously (common for small Close frames on
                    // healthy TCP) and only registers a timer on Pending.
                    // Cannot use select+cancel here — cancel is already signaled
                    // and would skip the Close entirely.
                    let _ = crate::lazy_timeout::lazy_timeout(
                        Duration::from_millis(WS_CANCEL_CLOSE_TIMEOUT_MS),
                        backend_sink.send(Message::Close(None)),
                    )
                    .await;
                    break;
                }
                msg = ws_stream.next() => {
                    let Some(msg) = msg else { break };
                    match msg {
                        Ok(raw @ (Message::Text(_) | Message::Binary(_) | Message::Ping(_))) => {
                            // Apply frame hooks when any plugin opted in (zero overhead when empty)
                            let outgoing = if ctb_plugins.is_empty() {
                                raw
                            } else {
                                let mut current = raw;
                                for plugin in &ctb_plugins {
                                    if let Some(transformed) = plugin
                                        .on_ws_frame(
                                            &proxy_id_ctb,
                                            connection_id,
                                            WebSocketFrameDirection::ClientToBackend,
                                            &current,
                                        )
                                        .await
                                    {
                                        current = transformed;
                                    }
                                }
                                current
                            };
                            // If a plugin transformed the frame into a Close, close both sides.
                            // Race cancel in case the opposite direction already exited while we
                            // were running plugin hooks — keeps teardown prompt without dropping
                            // the Close on the happy path.
                            if matches!(&outgoing, Message::Close(_)) {
                                debug!("Plugin triggered close on client->backend frame");
                                tokio::select! {
                                    biased;
                                    _ = cancel_ctb.cancelled() => {}
                                    _ = backend_sink.send(outgoing) => {}
                                }
                                cancel_ctb.cancel(); // signal other direction
                                break;
                            }
                            match &outgoing {
                                Message::Text(_) => trace!("Client -> Backend: Text message"),
                                Message::Binary(d) => {
                                    trace!(bytes = d.len(), "Client -> Backend: Binary message")
                                }
                                Message::Ping(_) => trace!("Client -> Backend: Ping"),
                                _ => {}
                            }
                            // Cancel-aware send: if the opposite direction has exited and
                            // cancelled us while this send is blocked on backend backpressure,
                            // `select!` breaks us out instead of hanging `tokio::join!` forever.
                            // Overhead is one atomic load per frame (CancellationToken state
                            // check); the send future is polled first on wakeup so successful
                            // sends pay no extra latency. No heap allocation, no timer wheel.
                            tokio::select! {
                                biased;
                                _ = cancel_ctb.cancelled() => {
                                    debug!("Client->backend: cancel fired mid-send");
                                    break;
                                }
                                res = backend_sink.send(outgoing) => {
                                    if let Err(e) = res {
                                        error!("Failed to send message to backend: {}", e);
                                        // Write-side failure on the c2b path means the
                                        // backend socket errored while we were pushing
                                        // into it — attribute to the c2b direction.
                                        let _ = first_failure_ctb.set((
                                            crate::plugins::Direction::ClientToBackend,
                                            retry::classify_boxed_error(&e),
                                        ));
                                        break;
                                    }
                                    // Count the frame that successfully reached the backend.
                                    frames_c2b_task.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        Ok(Message::Close(close_frame)) => {
                            debug!("Client sent close frame");
                            // Race cancel in case the opposite direction already exited while
                            // we were decoding this Close frame. The send future is polled
                            // first after the cancel check so the happy path does not block.
                            tokio::select! {
                                biased;
                                _ = cancel_ctb.cancelled() => {
                                    debug!("Client->backend: cancel fired during client-close forward");
                                }
                                res = backend_sink.send(Message::Close(close_frame)) => {
                                    if let Err(e) = res {
                                        error!("Failed to send close to backend: {}", e);
                                    }
                                }
                            }
                            break;
                        }
                        Ok(Message::Pong(_data)) => {
                            trace!("Client -> Backend: Pong");
                        }
                        Ok(Message::Frame(_)) => {
                            trace!("Client -> Backend: Frame");
                        }
                        Err(e) => {
                            error!("Error receiving from client: {}", e);
                            // Read-side failure on the c2b path means the client
                            // dropped / reset the socket.
                            let _ = first_failure_ctb.set((
                                crate::plugins::Direction::ClientToBackend,
                                retry::classify_boxed_error(&e),
                            ));
                            break;
                        }
                    }
                }
            }
        }
        debug!("Client -> backend forwarding completed");
        // Signal the opposite direction to wind down so we can finish the
        // session together. If the other direction already cancelled this
        // token (plugin-triggered Close path), `cancel()` is idempotent.
        // Without this, a natural EOF / error / Close-frame exit on c2b
        // would leave b2c running; the outer coordinator would then have
        // to drop b2c (old `tokio::select!`) or hang on it indefinitely.
        cancel_ctb.cancel();
    };

    // Forward messages from backend to client
    let backend_to_client = async move {
        debug!("Starting backend -> client message forwarding");
        loop {
            tokio::select! {
                biased;
                _ = cancel_btc.cancelled() => {
                    debug!("Backend->client: other direction triggered close");
                    // Mirror of the c2b cancel branch: bounded polite-close with
                    // `lazy_timeout` so the client sink cannot hang `tokio::join!`
                    // forever if the client socket is dead or not reading. See
                    // `WS_CANCEL_CLOSE_TIMEOUT_MS` for the rationale.
                    let _ = crate::lazy_timeout::lazy_timeout(
                        Duration::from_millis(WS_CANCEL_CLOSE_TIMEOUT_MS),
                        ws_sink.send(Message::Close(None)),
                    )
                    .await;
                    break;
                }
                msg = backend_stream.next() => {
                    let Some(msg) = msg else { break };
                    match msg {
                        Ok(raw @ (Message::Text(_) | Message::Binary(_) | Message::Ping(_))) => {
                            // Apply frame hooks when any plugin opted in (zero overhead when empty)
                            let outgoing = if btc_plugins.is_empty() {
                                raw
                            } else {
                                let mut current = raw;
                                for plugin in &btc_plugins {
                                    if let Some(transformed) = plugin
                                        .on_ws_frame(
                                            &proxy_id_btc,
                                            connection_id,
                                            WebSocketFrameDirection::BackendToClient,
                                            &current,
                                        )
                                        .await
                                    {
                                        current = transformed;
                                    }
                                }
                                current
                            };
                            // If a plugin transformed the frame into a Close, close both sides.
                            // Race cancel — the opposite direction may have already exited while
                            // we were running plugin hooks.
                            if matches!(&outgoing, Message::Close(_)) {
                                debug!("Plugin triggered close on backend->client frame");
                                tokio::select! {
                                    biased;
                                    _ = cancel_btc.cancelled() => {}
                                    _ = ws_sink.send(outgoing) => {}
                                }
                                cancel_btc.cancel(); // signal other direction
                                break;
                            }
                            match &outgoing {
                                Message::Text(_) => trace!("Backend -> Client: Text message"),
                                Message::Binary(d) => {
                                    trace!(bytes = d.len(), "Backend -> Client: Binary message")
                                }
                                Message::Ping(_) => trace!("Backend -> Client: Ping"),
                                _ => {}
                            }
                            // Cancel-aware send (mirror of c2b hot path): prevents
                            // `tokio::join!` from hanging when c2b has already exited and the
                            // client socket is backpressured so our `ws_sink.send()` would
                            // otherwise block indefinitely. One atomic load per frame; send
                            // polled first so successful frames pay no extra latency.
                            tokio::select! {
                                biased;
                                _ = cancel_btc.cancelled() => {
                                    debug!("Backend->client: cancel fired mid-send");
                                    break;
                                }
                                res = ws_sink.send(outgoing) => {
                                    if let Err(e) = res {
                                        error!("Failed to send message to client: {}", e);
                                        // Write-side failure on the b2c path means the
                                        // client dropped/reset while we were pushing
                                        // bytes to it — attribute to b2c direction.
                                        let _ = first_failure_btc.set((
                                            crate::plugins::Direction::BackendToClient,
                                            retry::classify_boxed_error(&e),
                                        ));
                                        break;
                                    }
                                    // Count the frame that successfully reached the client.
                                    frames_b2c_task.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        Ok(Message::Close(close_frame)) => {
                            debug!("Backend sent close frame");
                            // Race cancel in case c2b has already exited.
                            tokio::select! {
                                biased;
                                _ = cancel_btc.cancelled() => {
                                    debug!("Backend->client: cancel fired during backend-close forward");
                                }
                                res = ws_sink.send(Message::Close(close_frame)) => {
                                    if let Err(e) = res {
                                        error!("Failed to send close to client: {}", e);
                                    }
                                }
                            }
                            break;
                        }
                        Ok(Message::Pong(_data)) => {
                            trace!("Backend -> Client: Pong");
                        }
                        Ok(Message::Frame(_)) => {
                            trace!("Backend -> Client: Frame");
                        }
                        Err(e) => {
                            error!("Error receiving from backend: {}", e);
                            // Read-side failure on the b2c path means the
                            // backend closed / reset the socket.
                            let _ = first_failure_btc.set((
                                crate::plugins::Direction::BackendToClient,
                                retry::classify_boxed_error(&e),
                            ));
                            break;
                        }
                    }
                }
            }
        }
        debug!("Backend -> client forwarding completed");
        // Mirror of c2b: once b2c exits for any reason, signal c2b to finish
        // so the outer `tokio::join!` can complete promptly.
        cancel_btc.cancel();
    };

    // Wait for BOTH directions to complete before teardown — not just the
    // first one. Using `tokio::select!` here would drop whichever half is
    // still running (e.g., client half-closes while the backend is still
    // draining queued frames), truncating `frames_*` counts, shortening
    // `duration_ms`, and losing any terminal failure attribution the second
    // half would have produced. The end-of-future `cancel.cancel()` in each
    // branch above guarantees the second half winds down quickly after the
    // first exits, so `join!` cannot hang on a well-behaved peer.
    let _ = tokio::join!(client_to_backend, backend_to_client);

    // Fire the on_ws_disconnect hook exactly once, after both forward halves
    // have wound down. When no plugin opted in the list is empty and we skip
    // the whole block — zero overhead for deployments that don't observe
    // WebSocket sessions.
    if !ws_disconnect_plugins.is_empty() {
        let disconnect_duration_ms = (chrono::Utc::now() - session_meta.session_start)
            .num_milliseconds()
            .max(0) as f64;
        let failure = first_failure.get().cloned();
        let disconnect_ctx = crate::plugins::WsDisconnectContext {
            namespace: session_meta.namespace,
            proxy_id: proxy_id.to_string(),
            proxy_name: session_meta.proxy_name,
            client_ip: session_meta.client_ip,
            backend_target: session_meta.backend_target,
            listen_port: session_meta.listen_port,
            duration_ms: disconnect_duration_ms,
            frames_client_to_backend: frames_c2b.load(Ordering::Relaxed),
            frames_backend_to_client: frames_b2c.load(Ordering::Relaxed),
            direction: failure.as_ref().map(|(d, _)| *d),
            error_class: failure.map(|(_, c)| c),
            consumer_username: session_meta.consumer_username,
            metadata: session_meta.metadata,
        };
        for plugin in &ws_disconnect_plugins {
            plugin.on_ws_disconnect(&disconnect_ctx).await;
        }
    }

    debug!("WebSocket proxy connection closed for {}", proxy_id);
    Ok(())
}

/// Start the proxy HTTP listener with dual-path handling.
#[allow(dead_code)] // Used by library consumers and tests; binary startup uses the signaled variant.
pub async fn start_proxy_listener(
    addr: SocketAddr,
    state: ProxyState,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), anyhow::Error> {
    start_proxy_listener_with_tls(addr, state, shutdown, None).await
}

/// Start the proxy listener with optional TLS and client certificate verification.
#[allow(dead_code)] // Used by library consumers and tests; binary startup uses the signaled variant.
pub async fn start_proxy_listener_with_tls(
    addr: SocketAddr,
    state: ProxyState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), anyhow::Error> {
    start_proxy_listener_with_tls_and_signal(addr, state, shutdown, tls_config, None).await
}

/// Create a bound TCP socket with SO_REUSEADDR and SO_REUSEPORT enabled.
/// Used by the multi-listener accept architecture where N sockets are bound
/// to the same address, each with its own accept loop.
///
/// When `tcp_fastopen_queue_len` is `Some(n)`, enables TCP Fast Open on the
/// listening socket (Linux only), allowing repeat clients with a cached TFO
/// cookie to send data in the SYN packet (saves 1 RTT).
fn create_proxy_socket(
    addr: SocketAddr,
    backlog: i32,
    tcp_fastopen_queue_len: Option<u16>,
) -> Result<TcpListener, anyhow::Error> {
    let socket = socket2::Socket::new(
        if addr.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    // SO_REUSEADDR: allow rapid restart without TIME_WAIT blocking the port.
    socket.set_reuse_address(true)?;

    // SO_REUSEPORT: let the kernel distribute incoming connections across
    // multiple listener tasks (Linux 3.9+, macOS, BSDs). This eliminates
    // the single-thread accept() bottleneck at 50k+ connections/sec.
    #[cfg(unix)]
    socket.set_reuse_port(true)?;

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    // TCP_FASTOPEN: enable TFO on the server socket after bind, before listen.
    // This allows repeat clients to send data in the SYN packet, saving 1 RTT.
    if let Some(_queue_len) = tcp_fastopen_queue_len {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            if let Err(e) =
                crate::socket_opts::set_tcp_fastopen_server(socket.as_raw_fd(), _queue_len as i32)
            {
                tracing::warn!("Failed to enable TCP_FASTOPEN on {}: {}", addr, e);
            }
        }
    }

    socket.listen(backlog)?;

    Ok(TcpListener::from_std(socket.into())?)
}

/// Start the proxy listener with an optional startup signal sent after bind.
///
/// When `FERRUM_ACCEPT_THREADS > 1`, spawns N parallel accept loops each with
/// its own socket bound to the same address via SO_REUSEPORT. The kernel
/// distributes incoming connections across the N sockets, eliminating the
/// single-thread accept() bottleneck at high connection rates (50k+ conn/sec).
/// All N loops share the same connection semaphore for global limit enforcement.
pub async fn start_proxy_listener_with_tls_and_signal(
    addr: SocketAddr,
    state: ProxyState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    started_tx: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<(), anyhow::Error> {
    let backlog = state.env_config.tcp_listen_backlog as i32;
    let accept_threads = state.env_config.accept_threads.max(1);
    let tfo_enabled = state
        .env_config
        .tcp_fastopen_enabled
        .resolve(crate::socket_opts::is_tcp_fastopen_available);
    let tfo_queue = if tfo_enabled {
        Some(state.env_config.tcp_fastopen_queue_len)
    } else {
        None
    };

    // Create the first listener — this one validates that the port is available.
    let first_listener = create_proxy_socket(addr, backlog, tfo_queue)?;

    // Optional connection limit. Shared across all accept threads so the global
    // max_connections limit is enforced regardless of which thread accepted.
    let conn_semaphore: Option<Arc<tokio::sync::Semaphore>> =
        if state.env_config.max_connections > 0 {
            info!(
                "Connection limit: {} max concurrent connections",
                state.env_config.max_connections
            );
            Some(Arc::new(tokio::sync::Semaphore::new(
                state.env_config.max_connections,
            )))
        } else {
            None
        };

    if accept_threads > 1 {
        // Multi-listener mode: spawn N-1 additional accept loops, each with its
        // own socket bound to the same address via SO_REUSEPORT. The kernel
        // distributes connections across all N sockets.
        let mut handles = Vec::with_capacity(accept_threads);

        // Spawn additional listeners (threads 1..N-1)
        for i in 1..accept_threads {
            let listener = create_proxy_socket(addr, backlog, tfo_queue)?;
            let state = state.clone();
            let tls_config = tls_config.clone();
            let semaphore = conn_semaphore.clone();
            let shutdown_rx = shutdown.clone();

            handles.push(tokio::spawn(async move {
                run_accept_loop(listener, state, tls_config, semaphore, shutdown_rx, i).await;
            }));
        }

        info!(
            "Proxy listener started on {} (backlog={}, accept_threads={})",
            addr, backlog, accept_threads
        );
        if let Some(started_tx) = started_tx {
            let _ = started_tx.send(());
        }

        // Run thread 0 on the current task (avoids an extra spawn)
        run_accept_loop(
            first_listener,
            state,
            tls_config,
            conn_semaphore,
            shutdown,
            0,
        )
        .await;

        // When the first loop exits (shutdown), wait for others to finish
        for handle in handles {
            let _ = handle.await;
        }
    } else {
        // Single-listener mode (FERRUM_ACCEPT_THREADS=1) — no extra spawns
        info!("Proxy listener started on {} (backlog={})", addr, backlog);
        if let Some(started_tx) = started_tx {
            let _ = started_tx.send(());
        }

        run_accept_loop(
            first_listener,
            state,
            tls_config,
            conn_semaphore,
            shutdown,
            0,
        )
        .await;
    }

    Ok(())
}

/// Accept loop that runs on a single listener socket. Multiple instances can
/// run concurrently on the same address when SO_REUSEPORT is enabled.
async fn run_accept_loop(
    listener: TcpListener,
    state: ProxyState,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    conn_semaphore: Option<Arc<tokio::sync::Semaphore>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    _thread_id: usize,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, remote_addr)) => {
                        // Overload check: reject new connections under critical
                        // pressure. Checked after accept (inside the select!) so
                        // shutdown_rx is always observed even during sustained
                        // overload. Single atomic load (~1ns).
                        if state
                            .overload
                            .reject_new_connections
                            .load(std::sync::atomic::Ordering::Relaxed)
                        {
                            drop(stream); // TCP RST
                            continue;
                        }
                        // Acquire connection permit before spawning. This avoids
                        // creating tasks that queue on the semaphore under floods —
                        // over-limit connections are dropped immediately with zero
                        // task overhead (no spawn, no state.clone, no scheduler slot).
                        let conn_permit = if let Some(ref sem) = conn_semaphore {
                            match sem.clone().try_acquire_owned() {
                                Ok(permit) => Some(permit),
                                Err(_) => {
                                    drop(stream); // TCP RST — at capacity
                                    continue;
                                }
                            }
                        } else {
                            None
                        };

                        let state = state.clone();
                        let tls_config = tls_config.clone();

                        tokio::spawn(async move {
                            // Hold the permit for the connection lifetime.
                            // Released automatically when _conn_permit drops on any exit path.
                            let _conn_permit = conn_permit;

                            // Track this connection for graceful drain.
                            // The guard decrements the counter on drop (all exit paths).
                            let _conn_guard = crate::overload::ConnectionGuard::new(&state.overload);

                            let result = if let Some(tls_config) = tls_config {
                                handle_tls_connection(stream, remote_addr, state, tls_config).await
                            } else {
                                handle_connection(stream, remote_addr, state).await
                            };

                            if let Err(e) = result {
                                debug!("Connection handling error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("Proxy listener shutting down");
                return;
            }
        }
    }
}

/// Handle TLS connections with HTTP/1.1 and HTTP/2 auto-negotiation via ALPN.
async fn handle_tls_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    state: ProxyState,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio_rustls::TlsAcceptor;

    // Set TCP keepalive on inbound connection
    set_tcp_keepalive(&stream);

    let acceptor = TlsAcceptor::from(tls_config);
    let tls_stream = match acceptor.accept(stream).await {
        Ok(stream) => {
            info!("TLS connection established from {}", remote_addr.ip());
            stream
        }
        Err(e) => {
            warn!("TLS handshake failed from {}: {}", remote_addr.ip(), e);
            return Err(e.into());
        }
    };

    // Extract peer certificate and chain before wrapping the stream.
    // This is the only point where the ServerConnection is accessible — once
    // wrapped in TokioIo, the TLS metadata is encapsulated and inaccessible.
    // Arc-shared so HTTP/2 multiplexed requests avoid per-request cert cloning.
    let peer_certs = tls_stream.get_ref().1.peer_certificates();
    let client_cert_der: Option<Arc<Vec<u8>>> = peer_certs
        .and_then(|certs| certs.first())
        .map(|cert| Arc::new(cert.to_vec()));
    // Capture intermediate/CA certs (index 1+) for per-proxy CA filtering in mtls_auth.
    let client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>> = peer_certs
        .filter(|certs| certs.len() > 1)
        .map(|certs| Arc::new(certs[1..].iter().map(|c| c.to_vec()).collect()));

    // Convert TLS stream to TokioIo for hyper
    let io = hyper_util::rt::TokioIo::new(tls_stream);

    // Use hyper-util's auto builder which negotiates HTTP/1.1 or HTTP/2 via ALPN.
    // HTTP/2 clients get multiplexed streams; HTTP/1.1 clients get upgrade support.
    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    {
        let mut http1 = builder.http1();
        http1.max_buf_size(state.max_header_size_bytes);
        // Slowloris protection: close connections that take too long to send headers.
        if state.env_config.http_header_read_timeout_seconds > 0 {
            http1.timer(hyper_util::rt::TokioTimer::new());
            http1.header_read_timeout(std::time::Duration::from_secs(
                state.env_config.http_header_read_timeout_seconds,
            ));
        }
    }
    let pool_cfg = state.connection_pool.global_pool_config();
    builder
        .http2()
        .max_header_list_size(state.max_header_size_bytes.min(u32::MAX as usize) as u32)
        .initial_stream_window_size(pool_cfg.http2_initial_stream_window_size)
        .initial_connection_window_size(pool_cfg.http2_initial_connection_window_size)
        .adaptive_window(pool_cfg.http2_adaptive_window)
        .max_frame_size(pool_cfg.http2_max_frame_size)
        .max_concurrent_streams(state.env_config.server_http2_max_concurrent_streams)
        .max_pending_accept_reset_streams(Some(
            state
                .env_config
                .server_http2_max_pending_accept_reset_streams,
        ))
        .max_local_error_reset_streams(Some(
            state.env_config.server_http2_max_local_error_reset_streams,
        ))
        // RFC 8441: Advertise SETTINGS_ENABLE_CONNECT_PROTOCOL so HTTP/2 clients
        // can initiate WebSocket connections via Extended CONNECT.
        .enable_connect_protocol();

    // WebSocket requests flow through handle_proxy_request so that authentication
    // and authorization plugins execute before the upgrade handshake.
    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let state = state.clone();
        let addr = remote_addr;
        let cert = client_cert_der.clone();
        let chain = client_cert_chain_der.clone();
        async move { handle_proxy_request(req, state, addr, true, cert, chain).await }
    });
    if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
        let err_string = e.to_string();
        if is_client_disconnect_error(&err_string) {
            debug!(
                remote_addr = %remote_addr.ip(),
                error_kind = "client_disconnect",
                error = %e,
                "Client disconnected before response completed (TLS)"
            );
        } else {
            error!(
                remote_addr = %remote_addr.ip(),
                error = %e,
                "HTTP connection error over TLS"
            );
        }
    }

    Ok(())
}

/// Run logging plugins for a rejected request.
///
/// When a plugin (auth, access control, rate limiting, etc.) rejects a request,
/// logging plugins (stdout_logging, http_logging, transaction_debugger) must still
/// execute so that rejected traffic is visible in log sinks like Splunk, stdout, etc.
/// Plugins outside the logging priority band (e.g., `otel_tracing` at priority 25)
/// also implement `log()` and must receive rejected transactions — so we dispatch
/// to the full plugin chain. The default `.log()` impl is a no-op, so awaiting
/// plugins that don't override it is cheap.
pub async fn log_rejected_request(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    status_code: u16,
    start_time: Instant,
    rejection_phase: &str,
    plugin_execution_ns: u64,
) {
    if plugins.is_empty() {
        return;
    }

    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
    let plugin_external_io_ms =
        ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let gateway_overhead_ms = (total_ms - plugin_execution_ms).max(0.0);
    let proxy = ctx.matched_proxy.as_ref();

    let mut metadata = ctx.metadata.clone();
    metadata.insert("rejection_phase".to_string(), rejection_phase.to_string());

    let summary = TransactionSummary {
        namespace: proxy
            .map(|p| p.namespace.clone())
            .unwrap_or_else(crate::config::types::default_namespace),
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.effective_identity().map(str::to_owned),
        http_method: ctx.method.clone(),
        request_path: ctx.path.clone(),
        matched_proxy_id: proxy.map(|p| p.id.clone()),
        matched_proxy_name: proxy.and_then(|p| p.name.clone()),
        backend_target_url: proxy.map(|p| {
            let url = build_backend_url(p, &ctx.path, "", p.listen_path.len());
            strip_query_params(&url).to_string()
        }),
        backend_resolved_ip: None,
        response_status_code: status_code,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: total_ms,
        latency_backend_ttfb_ms: -1.0,
        latency_backend_total_ms: -1.0,
        latency_plugin_execution_ms: plugin_execution_ms,
        latency_plugin_external_io_ms: plugin_external_io_ms,
        latency_gateway_overhead_ms: gateway_overhead_ms,
        request_user_agent: ctx.headers.get("user-agent").cloned(),
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: false,
        bytes_streamed_to_client: 0,
        mirror: false,
        metadata,
    };

    crate::plugins::log_with_mirror(plugins, &summary, ctx).await;
}

pub(crate) async fn apply_after_proxy_hooks_to_rejection(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    status_code: u16,
    response_headers: &mut HashMap<String, String>,
) {
    for plugin in plugins.iter().filter(|p| p.applies_after_proxy_on_reject()) {
        match plugin.after_proxy(ctx, status_code, response_headers).await {
            PluginResult::Reject {
                status_code: reject_status,
                ..
            }
            | PluginResult::RejectBinary {
                status_code: reject_status,
                ..
            } => {
                warn!(
                    "after_proxy plugin '{}' returned Reject (status {}) during rejection handling; ignoring",
                    plugin.name(),
                    reject_status,
                );
            }
            PluginResult::Continue => {}
        }
    }
}

pub(crate) struct AfterProxyReject {
    pub status_code: u16,
    pub body: Vec<u8>,
    pub headers: HashMap<String, String>,
}

pub(crate) async fn run_after_proxy_hooks(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    response_status: u16,
    response_headers: &mut HashMap<String, String>,
) -> Option<AfterProxyReject> {
    for plugin in plugins.iter() {
        match plugin
            .after_proxy(ctx, response_status, response_headers)
            .await
        {
            PluginResult::Continue => {}
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                let RejectedResponseParts {
                    status_code,
                    body,
                    mut headers,
                } = plugin_result_into_reject_parts(reject)
                    .expect("reject result should convert to rejection parts");
                warn!(
                    "after_proxy plugin '{}' rejected response before downstream commit (status {})",
                    plugin.name(),
                    status_code,
                );
                apply_after_proxy_hooks_to_rejection(plugins, ctx, status_code, &mut headers).await;
                return Some(AfterProxyReject {
                    status_code,
                    body,
                    headers,
                });
            }
        }
    }

    None
}

pub(crate) struct NormalizedRejectResponse {
    pub(crate) http_status: StatusCode,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: Vec<u8>,
    pub(crate) grpc_status: Option<u32>,
    pub(crate) grpc_message: Option<String>,
}

fn grpc_status_reason(status: u32) -> &'static str {
    match status {
        grpc_proxy::grpc_status::INVALID_ARGUMENT => "Invalid argument",
        grpc_proxy::grpc_status::DEADLINE_EXCEEDED => "Deadline exceeded",
        grpc_proxy::grpc_status::NOT_FOUND => "Not found",
        grpc_proxy::grpc_status::PERMISSION_DENIED => "Permission denied",
        grpc_proxy::grpc_status::RESOURCE_EXHAUSTED => "Resource exhausted",
        grpc_proxy::grpc_status::FAILED_PRECONDITION => "Failed precondition",
        grpc_proxy::grpc_status::ABORTED => "Aborted",
        grpc_proxy::grpc_status::UNIMPLEMENTED => "Unimplemented",
        grpc_proxy::grpc_status::INTERNAL => "Internal error",
        grpc_proxy::grpc_status::UNAVAILABLE => "Service unavailable",
        grpc_proxy::grpc_status::UNAUTHENTICATED => "Unauthenticated",
        _ => "Gateway rejected request",
    }
}

fn sanitize_grpc_message(message: &str) -> String {
    message
        .chars()
        .map(|c| if matches!(c, '\r' | '\n') { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

pub(crate) fn extract_grpc_reject_message(body: &[u8]) -> Option<String> {
    let body = std::str::from_utf8(body).ok()?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
        for key in ["grpc_message", "message", "error", "details"] {
            if let Some(msg) = parsed.get(key).and_then(|v| v.as_str()) {
                let sanitized = sanitize_grpc_message(msg);
                if !sanitized.is_empty() {
                    return Some(sanitized);
                }
            }
        }
    }

    let sanitized = sanitize_grpc_message(trimmed);
    (!sanitized.is_empty()).then_some(sanitized)
}

pub(crate) fn map_http_reject_status_to_grpc_status(status: StatusCode) -> u32 {
    match status {
        StatusCode::BAD_REQUEST => grpc_proxy::grpc_status::INVALID_ARGUMENT,
        StatusCode::METHOD_NOT_ALLOWED => grpc_proxy::grpc_status::UNIMPLEMENTED,
        StatusCode::UNAUTHORIZED => grpc_proxy::grpc_status::UNAUTHENTICATED,
        StatusCode::FORBIDDEN => grpc_proxy::grpc_status::PERMISSION_DENIED,
        StatusCode::NOT_FOUND => grpc_proxy::grpc_status::NOT_FOUND,
        StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => {
            grpc_proxy::grpc_status::DEADLINE_EXCEEDED
        }
        StatusCode::CONFLICT => grpc_proxy::grpc_status::ABORTED,
        StatusCode::PRECONDITION_FAILED => grpc_proxy::grpc_status::FAILED_PRECONDITION,
        StatusCode::PAYLOAD_TOO_LARGE
        | StatusCode::URI_TOO_LONG
        | StatusCode::TOO_MANY_REQUESTS => grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
        StatusCode::NOT_IMPLEMENTED => grpc_proxy::grpc_status::UNIMPLEMENTED,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE => {
            grpc_proxy::grpc_status::UNAVAILABLE
        }
        _ => grpc_proxy::grpc_status::INTERNAL,
    }
}

pub(crate) fn normalize_reject_response(
    status: StatusCode,
    body: &[u8],
    headers: &HashMap<String, String>,
    is_grpc_request: bool,
) -> NormalizedRejectResponse {
    if !is_grpc_request {
        let mut normalized_headers = headers.clone();
        normalized_headers
            .entry("content-type".to_string())
            .or_insert_with(|| "application/json".to_string());
        return NormalizedRejectResponse {
            http_status: status,
            headers: normalized_headers,
            body: body.to_vec(),
            grpc_status: None,
            grpc_message: None,
        };
    }

    let grpc_status = headers
        .get("grpc-status")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_else(|| map_http_reject_status_to_grpc_status(status));
    let grpc_message = headers
        .get("grpc-message")
        .cloned()
        .or_else(|| extract_grpc_reject_message(body))
        .unwrap_or_else(|| grpc_status_reason(grpc_status).to_string());
    let grpc_message = sanitize_grpc_message(&grpc_message);

    let mut normalized_headers = HashMap::with_capacity(headers.len() + 3);
    for (key, value) in headers {
        if key.eq_ignore_ascii_case("content-type")
            || key.eq_ignore_ascii_case("grpc-status")
            || key.eq_ignore_ascii_case("grpc-message")
        {
            continue;
        }
        normalized_headers.insert(key.clone(), value.clone());
    }
    normalized_headers.insert("content-type".to_string(), "application/grpc".to_string());
    normalized_headers.insert("grpc-status".to_string(), grpc_status.to_string());
    if !grpc_message.is_empty() {
        normalized_headers.insert("grpc-message".to_string(), grpc_message.clone());
    }

    NormalizedRejectResponse {
        http_status: StatusCode::OK,
        headers: normalized_headers,
        body: Vec::new(),
        grpc_status: Some(grpc_status),
        grpc_message: Some(grpc_message),
    }
}

pub(crate) fn insert_grpc_error_metadata(
    metadata: &mut HashMap<String, String>,
    grpc_status: u32,
    grpc_message: &str,
) {
    metadata.insert("grpc_status".to_string(), grpc_status.to_string());
    let grpc_message = sanitize_grpc_message(grpc_message);
    if grpc_message.is_empty() {
        metadata.remove("grpc_message");
    } else {
        metadata.insert("grpc_message".to_string(), grpc_message);
    }
}

fn apply_grpc_reject_metadata(ctx: &mut RequestContext, reject: &NormalizedRejectResponse) {
    if let Some(grpc_status) = reject.grpc_status {
        insert_grpc_error_metadata(
            &mut ctx.metadata,
            grpc_status,
            reject.grpc_message.as_deref().unwrap_or(""),
        );
    }
}

fn build_response_from_normalized_reject(reject: NormalizedRejectResponse) -> Response<ProxyBody> {
    let is_grpc_error = reject.grpc_status.is_some();
    let mut builder = Response::builder().status(reject.http_status);
    for (key, value) in &reject.headers {
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(key.as_bytes()),
            hyper::header::HeaderValue::from_str(value),
        ) {
            builder = builder.header(name, val);
        }
    }

    let body = if reject.body.is_empty() {
        ProxyBody::empty()
    } else {
        ProxyBody::full(Bytes::from(reject.body))
    };

    builder.body(body).unwrap_or_else(|_| {
        if is_grpc_error {
            grpc_proxy::build_grpc_error_response(
                grpc_proxy::grpc_status::INTERNAL,
                "Internal gateway error",
            )
        } else {
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"Internal server error"}"#,
            )
        }
    })
}

async fn finalize_reject_response_with_after_proxy_hooks(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    status: StatusCode,
    body: &[u8],
    mut headers: HashMap<String, String>,
    is_grpc_request: bool,
) -> NormalizedRejectResponse {
    apply_after_proxy_hooks_to_rejection(plugins, ctx, status.as_u16(), &mut headers).await;
    normalize_reject_response(status, body, &headers, is_grpc_request)
}

pub fn request_is_authenticated(ctx: &RequestContext) -> bool {
    ctx.effective_identity().is_some()
}

pub async fn run_authentication_phase(
    auth_mode: AuthMode,
    auth_plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    consumer_index: &ConsumerIndex,
) -> Option<(u16, Vec<u8>, HashMap<String, String>)> {
    match auth_mode {
        AuthMode::Multi => {
            // Execute auth plugins; first success stops iteration.
            // Multi-auth success includes external identity auth (e.g. jwks_auth)
            // even when no gateway Consumer record exists.
            let mut last_reject: Option<(u16, Vec<u8>, HashMap<String, String>)> = None;
            for auth_plugin in auth_plugins {
                match auth_plugin.authenticate(ctx, consumer_index).await {
                    reject @ PluginResult::Reject { .. }
                    | reject @ PluginResult::RejectBinary { .. } => {
                        if let Some(reject) = plugin_result_into_reject_parts(reject) {
                            last_reject = Some((reject.status_code, reject.body, reject.headers));
                        }
                    }
                    PluginResult::Continue => {
                        if request_is_authenticated(ctx) {
                            last_reject = None;
                            break;
                        }
                    }
                }
            }
            last_reject.filter(|_| !auth_plugins.is_empty() && !request_is_authenticated(ctx))
        }
        AuthMode::Single => {
            for auth_plugin in auth_plugins {
                match auth_plugin.authenticate(ctx, consumer_index).await {
                    reject @ PluginResult::Reject { .. }
                    | reject @ PluginResult::RejectBinary { .. } => {
                        if let Some(reject) = plugin_result_into_reject_parts(reject) {
                            return Some((reject.status_code, reject.body, reject.headers));
                        }
                    }
                    PluginResult::Continue => {}
                }
            }
            None
        }
    }
}

/// Handle a single proxy request.
pub async fn handle_proxy_request(
    req: Request<Incoming>,
    state: ProxyState,
    remote_addr: SocketAddr,
    is_tls: bool,
    tls_client_cert_der: Option<Arc<Vec<u8>>>,
    tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    // Global request admission control. Single atomic load (~1ns) on the fast
    // path. Rejects with 503 when request pressure exceeds the critical
    // threshold (FERRUM_MAX_REQUESTS + FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD).
    if state
        .overload
        .reject_new_requests
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        let is_grpc = grpc_proxy::is_grpc_request(&req);
        record_request(&state, 503);
        if is_grpc {
            return Ok(grpc_proxy::build_grpc_error_response(
                grpc_proxy::grpc_status::UNAVAILABLE,
                "Service overloaded",
            ));
        }
        return Ok(build_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"Service overloaded"}"#,
        ));
    }

    // Track this request for overload monitoring and graceful drain.
    // The guard is attached to the response body so it lives as long as hyper
    // is sending the response — critical for H2/gRPC streaming where the body
    // outlives this function scope.
    let request_guard = crate::overload::RequestGuard::new(&state.overload);

    let response = handle_proxy_request_inner(
        req,
        state,
        remote_addr,
        is_tls,
        tls_client_cert_der,
        tls_client_cert_chain_der,
    )
    .await;

    // Attach the guard to the response body so active_requests stays incremented
    // for the full response lifetime (including streaming bodies).
    response.map(|mut resp| {
        let body = std::mem::replace(resp.body_mut(), ProxyBody::empty());
        *resp.body_mut() = body.with_request_guard(request_guard);
        resp
    })
}

/// Inner implementation of [`handle_proxy_request`] — separated so the outer
/// function can attach the [`RequestGuard`] to the response body.
async fn handle_proxy_request_inner(
    req: Request<Incoming>,
    state: ProxyState,
    remote_addr: SocketAddr,
    is_tls: bool,
    tls_client_cert_der: Option<Arc<Vec<u8>>>,
    tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    let start_time = Instant::now();

    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_string();
    let query_string = req.uri().query().unwrap_or("").to_string();

    let socket_ip = remote_addr.ip().to_string();

    // Build request context — pass cloned socket_ip to ctx (client_ip may be
    // overwritten by trusted-proxy resolution below). method and path keep
    // separate ownership for use in backend URL building and logging.
    let mut ctx = RequestContext::new(socket_ip.clone(), method.clone(), path.clone());
    ctx.tls_client_cert_der = tls_client_cert_der;
    ctx.tls_client_cert_chain_der = tls_client_cert_chain_der;
    // Store raw query string on ctx for lazy parsing. The local `query_string`
    // is kept for validation + URL building; the ctx copy is consumed by
    // materialize_query_params() when plugins need the parsed HashMap.
    ctx.set_raw_query_string(query_string.clone());
    // Validate header sizes without materializing headers into owned Strings.
    // The raw HeaderMap is stored on ctx for deferred materialization — the full
    // HashMap<String, String> is only built when a plugin phase or backend
    // dispatch actually needs it (saving ~20-60 String allocations per request
    // on early-reject paths and deferring them past routing on the happy path).
    let mut total_header_size: usize = 0;
    for (name, value) in req.headers() {
        let header_size = name.as_str().len() + value.len();
        if header_size > state.max_single_header_size_bytes {
            record_request(&state, 431);
            // Escape header name to prevent JSON injection from client-controlled data.
            // Use serde_json to produce a correctly escaped JSON string value,
            // which handles backslash, quotes, and all control characters.
            let escaped_name = serde_json::to_string(name.as_str())
                .unwrap_or_else(|_| "\"<invalid>\"".to_string());
            // escaped_name is a quoted JSON string like "\"foo\"", strip outer quotes for embedding
            let inner = &escaped_name[1..escaped_name.len() - 1];
            return Ok(build_response(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                &format!(
                    r#"{{"error":"Request header '{}' exceeds maximum size of {} bytes"}}"#,
                    inner, state.max_single_header_size_bytes
                ),
            ));
        }
        total_header_size += header_size;
    }
    if total_header_size > state.max_header_size_bytes {
        record_request(&state, 431);
        return Ok(build_response(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            r#"{"error":"Total request headers exceed maximum size"}"#,
        ));
    }
    if state.max_header_count > 0 && req.headers().len() > state.max_header_count {
        record_request(&state, 431);
        return Ok(build_response(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            &format!(
                r#"{{"error":"Request header count ({}) exceeds maximum of {}"}}"#,
                req.headers().len(),
                state.max_header_count
            ),
        ));
    }

    // Store raw headers for deferred materialization. The clone is a single
    // contiguous allocation (HeaderMap's internal Vec) — much cheaper than
    // N individual String allocations from the previous eager conversion.
    ctx.set_raw_headers(req.headers().clone());

    // Validate URL length (path + query string)
    if state.max_url_length_bytes > 0 {
        let url_len = path.len()
            + if query_string.is_empty() {
                0
            } else {
                1 + query_string.len()
            };
        if url_len > state.max_url_length_bytes {
            record_request(&state, 414);
            return Ok(build_response(
                StatusCode::URI_TOO_LONG,
                &format!(
                    r#"{{"error":"Request URL length ({} bytes) exceeds maximum of {} bytes"}}"#,
                    url_len, state.max_url_length_bytes
                ),
            ));
        }
    }

    // Validate query parameter count (skip empty segments from consecutive '&').
    // Uses split + filter instead of a raw byte-scan to correctly handle edge
    // cases like "&&" producing empty segments that shouldn't count as params.
    if state.max_query_params > 0 && !query_string.is_empty() {
        let param_count = query_string.split('&').filter(|s| !s.is_empty()).count();
        if param_count > state.max_query_params {
            record_request(&state, 400);
            return Ok(build_response(
                StatusCode::BAD_REQUEST,
                &format!(
                    r#"{{"error":"Query parameter count ({}) exceeds maximum of {}"}}"#,
                    param_count, state.max_query_params
                ),
            ));
        }
    }

    // Protocol-level header validation to prevent request smuggling and desync attacks.
    // Must run before routing because these are transport-level violations that apply
    // regardless of which backend the request would be forwarded to.
    if let Some(error_body) = check_protocol_headers(req.headers(), req.version()) {
        warn!("Rejected request: {}", error_body);
        record_request(&state, 400);
        return Ok(build_response(StatusCode::BAD_REQUEST, error_body));
    }

    // Block TRACE method to prevent Cross-Site Tracing (XST) attacks.
    // TRACE echoes request headers (including cookies and auth tokens) in the
    // response body, which can be exploited to steal credentials.
    if method == "TRACE" {
        warn!("Rejected TRACE request");
        record_request(&state, 405);
        return Ok(build_response(
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"TRACE method is not allowed"}"#,
        ));
    }

    // Block CONNECT method to prevent protocol confusion and tunneling attacks.
    // HTTP/1.1 CONNECT creates TCP tunnels (bypassing proxy controls).
    // HTTP/2 Extended CONNECT (RFC 8441) is only valid for WebSocket upgrades,
    // which are handled separately via is_h2_websocket_connect(). Non-WebSocket
    // CONNECT requests (e.g., :protocol = "h2c", "connect-udp") must be rejected
    // to prevent clients from using Extended CONNECT to bypass proxy routing.
    // Note: we enable_connect_protocol() on the h2 server to support WebSocket,
    // which means h2 will deliver Extended CONNECT requests to us — we must
    // filter non-WebSocket ones here before routing.
    if method == "CONNECT" && !is_h2_websocket_connect(&req) {
        warn!("Rejected non-WebSocket CONNECT request");
        record_request(&state, 405);
        return Ok(build_response(
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"CONNECT method is not allowed"}"#,
        ));
    }

    // TLS 1.3 0-RTT early data enforcement (RFC 8470).
    // On the HTTPS path, we detect early data via the `Early-Data: 1` header
    // that upstream proxies/CDNs add per RFC 8470. Direct-client 0-RTT detection
    // is not possible with the current rustls+tokio-rustls API (the early data
    // state is consumed during the handshake and not exposed afterwards).
    // HTTP/3 0-RTT is detected natively via quinn's into_0rtt() in the H3 path.
    if !state.early_data_methods.is_empty() {
        // Raw byte comparison avoids UTF-8 validation on the hot path.
        let is_early_data = req
            .headers()
            .get("early-data")
            .is_some_and(|v| v.as_bytes() == b"1");
        if is_early_data {
            ctx.is_early_data = true;
            if !state.early_data_methods.contains(&method) {
                let is_grpc = grpc_proxy::is_grpc_request(&req);
                warn!(
                    "Rejected 0-RTT request: method {} not in allowed early data methods",
                    method
                );
                record_request(&state, 425);
                if is_grpc {
                    return Ok(grpc_proxy::build_grpc_error_response(
                        grpc_proxy::grpc_status::UNAVAILABLE,
                        "Method not allowed in 0-RTT early data",
                    ));
                }
                return Ok(build_response(
                    StatusCode::TOO_EARLY,
                    r#"{"error":"Method not allowed in 0-RTT early data"}"#,
                ));
            }
        }
    }

    // Resolve real client IP using trusted proxy configuration.
    // Parse the socket IP once and reuse the parsed value to avoid redundant
    // parsing across the real-IP-header check and the XFF walk.
    // When no resolution changes the IP, we skip the allocation entirely —
    // ctx.client_ip was already set to socket_ip by RequestContext::new().
    // Uses raw_header_get() to read specific headers without materializing the
    // full HashMap — only 2-3 targeted lookups on the raw HeaderMap.
    if !state.trusted_proxies.is_empty() {
        let socket_addr: Option<std::net::IpAddr> = socket_ip.parse().ok();
        if let Some(ref real_ip_header) = state.env_config.real_ip_header {
            // real_ip_header is pre-lowercased at config load time — no allocation needed
            let header_val = ctx.raw_header_get(real_ip_header.as_str());
            if let Some(val) = header_val {
                // Validate the direct connection is from a trusted proxy before
                // trusting this header
                if socket_addr.is_some_and(|ip| state.trusted_proxies.contains(&ip)) {
                    let trimmed = val.trim();
                    // Only allocate if the resolved IP differs from socket_ip
                    if trimmed != socket_ip {
                        ctx.client_ip = trimmed.to_owned();
                    }
                }
                // else: untrusted proxy, keep socket_ip (already set in ctx)
            } else if let Some(ref addr) = socket_addr {
                ctx.client_ip = client_ip::resolve_client_ip_parsed(
                    &socket_ip,
                    addr,
                    ctx.raw_header_get("x-forwarded-for"),
                    &state.trusted_proxies,
                );
            }
            // else: no header + unparseable socket_ip, keep socket_ip (already set in ctx)
        } else if let Some(ref addr) = socket_addr {
            ctx.client_ip = client_ip::resolve_client_ip_parsed(
                &socket_ip,
                addr,
                ctx.raw_header_get("x-forwarded-for"),
                &state.trusted_proxies,
            );
        }
        // else: unparseable socket_ip with no real_ip_header, keep socket_ip (already set in ctx)
    }

    // Per-IP concurrent request limiting. The guard auto-decrements on drop,
    // covering all 30+ return paths without manual tracking.
    let _per_ip_guard = if let Some(ref counts) = state.per_ip_request_counts {
        let count = counts
            .entry(ctx.client_ip.clone())
            .or_insert_with(|| AtomicU64::new(0));
        let current = count.value().fetch_add(1, Ordering::Relaxed) + 1;
        let guard = Some(PerIpRequestGuard {
            ip: ctx.client_ip.clone(),
            counts: counts.clone(),
        });
        if current > state.max_concurrent_requests_per_ip {
            // Guard will be dropped immediately, decrementing the counter
            drop(guard);
            warn!(
                client_ip = %ctx.client_ip,
                concurrent = current,
                limit = state.max_concurrent_requests_per_ip,
                "Per-IP concurrent request limit exceeded"
            );
            record_request(&state, 429);
            return Ok(build_response(
                StatusCode::TOO_MANY_REQUESTS,
                r#"{"error":"Too many concurrent requests from this IP"}"#,
            ));
        }
        guard
    } else {
        None
    };

    // Extract request host for host-based routing.
    // HTTP/1.1 uses the Host header; HTTP/2 uses the :authority pseudo-header
    // (exposed via req.uri().authority()). Strip port if present and lowercase.
    // Uses raw_header_get() to avoid materializing the full HashMap.
    let request_host: Option<String> = ctx
        .raw_header_get("host")
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
        .map(|h| {
            let without_port = h.split(':').next().unwrap_or(h);
            // Strip trailing dot from FQDN (e.g., "example.com." → "example.com").
            // DNS treats "example.com." and "example.com" as identical, so routing
            // must normalize to prevent host-matching bypasses.
            let normalized = without_port.strip_suffix('.').unwrap_or(without_port);
            normalized.to_lowercase()
        });
    let request_uses_grpc_content_type = grpc_proxy::is_grpc_request(&req);

    // Route: host + longest prefix match via router cache (O(1) cache hit, pre-sorted fallback)
    let route_match = state
        .router_cache
        .find_proxy(request_host.as_deref(), &path);

    let (proxy, strip_len) = match route_match {
        Some(rm) => {
            // Materialize headers now — path param injection writes to ctx.headers,
            // and all subsequent code (plugins, backend dispatch) needs the HashMap.
            // Requests that fail routing (404) skip this entirely, saving ~20-60
            // String allocations.
            ctx.materialize_headers();
            // Inject regex path parameters into context metadata and headers
            for (name, value) in &rm.path_params {
                ctx.metadata
                    .insert(format!("path_param.{}", name), value.clone());
                ctx.headers
                    .insert(format!("x-path-param-{}", name), value.clone());
            }
            (rm.proxy, rm.matched_prefix_len)
        }
        None => {
            debug!(path = %path, client_ip = %ctx.client_ip, "No route matched for request path");
            state.request_count.fetch_add(1, Ordering::Relaxed);
            let reject = normalize_reject_response(
                StatusCode::NOT_FOUND,
                br#"{"error":"Not Found"}"#,
                &EMPTY_HEADERS,
                request_uses_grpc_content_type,
            );
            record_status(&state, reject.http_status.as_u16());
            return Ok(build_response_from_normalized_reject(reject));
        }
    };

    ctx.matched_proxy = Some(Arc::clone(&proxy));
    debug!(proxy_id = %proxy.id, method = %method, path = %path, client_ip = %ctx.client_ip, "Request routed to proxy");

    // Per-proxy HTTP method filtering (checked before plugins to save work)
    if let Some(ref allowed) = proxy.allowed_methods
        && !allowed.iter().any(|m| m.eq_ignore_ascii_case(&method))
    {
        state.request_count.fetch_add(1, Ordering::Relaxed);
        let allow_header = allowed.join(", ");
        let mut reject_headers = HashMap::new();
        reject_headers.insert("allow".to_string(), allow_header);
        let reject = normalize_reject_response(
            StatusCode::METHOD_NOT_ALLOWED,
            br#"{"error":"Method Not Allowed"}"#,
            &reject_headers,
            request_uses_grpc_content_type,
        );
        record_status(&state, reject.http_status.as_u16());
        return Ok(build_response_from_normalized_reject(reject));
    }

    // Detect request protocol early so we fetch only plugins that support it.
    // WebSocket and gRPC are detected from headers; everything else is plain HTTP.
    let is_h2_ws = is_h2_websocket_connect(&req);
    let request_protocol = if (is_websocket_upgrade(&req) || is_h2_ws)
        && matches!(
            proxy.backend_protocol,
            BackendProtocol::Ws | BackendProtocol::Wss
        ) {
        ProxyProtocol::WebSocket
    } else if request_uses_grpc_content_type
        && matches!(
            proxy.backend_protocol,
            BackendProtocol::Grpc | BackendProtocol::Grpcs
        )
    {
        ProxyProtocol::Grpc
    } else {
        ProxyProtocol::Http
    };
    let is_grpc_request = request_protocol == ProxyProtocol::Grpc;

    // gRPC spec mandates POST method. Reject non-POST gRPC requests with a proper
    // gRPC trailers-only error rather than forwarding an invalid request to the backend.
    if is_grpc_request && method != "POST" {
        state.request_count.fetch_add(1, Ordering::Relaxed);
        warn!(method = %method, path = %path, "Rejected gRPC request: method must be POST");
        let reject = normalize_reject_response(
            StatusCode::BAD_REQUEST,
            br#"{"error":"gRPC requires POST method"}"#,
            &EMPTY_HEADERS,
            true,
        );
        record_status(&state, reject.http_status.as_u16());
        return Ok(build_response_from_normalized_reject(reject));
    }

    // Get pre-resolved plugins filtered by protocol (O(1) lookup, no per-request filtering)
    let plugins = state
        .plugin_cache
        .get_plugins_for_protocol(&proxy.id, request_protocol);
    // Pre-computed capability bitset and phase-specific plugin lists — avoids
    // per-request `iter().filter().collect()` and `iter().any()` scans.
    let capabilities = state
        .plugin_cache
        .get_capabilities(&proxy.id, request_protocol);
    let mut client_request_body = ClientRequestBody::Streaming(Box::new(req));

    // Accumulator for total wall-clock time spent inside plugin phase callbacks.
    // Stored as nanoseconds in u64 to avoid floating-point precision loss across
    // many additions; converted to f64 milliseconds once when building the summary.
    let mut plugin_execution_ns: u64 = 0;

    // Execute on_request_received hooks (skip iteration when no plugins configured)
    if !plugins.is_empty() {
        let phase_start = Instant::now();
        for plugin in plugins.iter() {
            match plugin.on_request_received(&mut ctx).await {
                PluginResult::Continue => {}
                reject @ PluginResult::Reject { .. }
                | reject @ PluginResult::RejectBinary { .. } => {
                    let plugin_reject = plugin_result_into_reject_parts(reject)
                        .expect("reject result should convert to rejection parts");
                    let status_code = plugin_reject.status_code;
                    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                    let reject = finalize_reject_response_with_after_proxy_hooks(
                        &plugins,
                        &mut ctx,
                        StatusCode::from_u16(status_code)
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                        &plugin_reject.body,
                        plugin_reject.headers,
                        is_grpc_request,
                    )
                    .await;
                    apply_grpc_reject_metadata(&mut ctx, &reject);
                    log_rejected_request(
                        &plugins,
                        &ctx,
                        reject.http_status.as_u16(),
                        start_time,
                        "on_request_received",
                        plugin_execution_ns,
                    )
                    .await;
                    record_request(&state, reject.http_status.as_u16());
                    return Ok(build_response_from_normalized_reject(reject));
                }
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
    }

    // Materialize query params before authentication — key_auth and jwt_auth
    // may read query params for API key / token lookup. Deferred past routing
    // and on_request_received so plugin-less early rejects skip the work.
    ctx.materialize_query_params();

    // Authentication phase (pre-computed auth plugin list — zero allocation)
    let auth_plugins = state
        .plugin_cache
        .get_auth_plugins(&proxy.id, request_protocol);

    {
        let auth_phase_start = Instant::now();
        if let Some((status_code, body, headers)) = run_authentication_phase(
            proxy.auth_mode.clone(),
            &auth_plugins,
            &mut ctx,
            &state.consumer_index,
        )
        .await
        {
            plugin_execution_ns += auth_phase_start.elapsed().as_nanos() as u64;
            let reject = finalize_reject_response_with_after_proxy_hooks(
                &plugins,
                &mut ctx,
                StatusCode::from_u16(status_code).unwrap_or(StatusCode::UNAUTHORIZED),
                &body,
                headers,
                is_grpc_request,
            )
            .await;
            apply_grpc_reject_metadata(&mut ctx, &reject);
            log_rejected_request(
                &plugins,
                &ctx,
                reject.http_status.as_u16(),
                start_time,
                "authenticate",
                plugin_execution_ns,
            )
            .await;
            record_request(&state, reject.http_status.as_u16());
            return Ok(build_response_from_normalized_reject(reject));
        }
        plugin_execution_ns += auth_phase_start.elapsed().as_nanos() as u64;
    }

    // Authorization phase (access_control, rate_limiting by consumer, etc.)
    if !plugins.is_empty() {
        let phase_start = Instant::now();
        for plugin in plugins.iter() {
            match plugin.authorize(&mut ctx).await {
                PluginResult::Continue => {}
                reject @ PluginResult::Reject { .. }
                | reject @ PluginResult::RejectBinary { .. } => {
                    let plugin_reject = plugin_result_into_reject_parts(reject)
                        .expect("reject result should convert to rejection parts");
                    let status_code = plugin_reject.status_code;
                    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                    let reject = finalize_reject_response_with_after_proxy_hooks(
                        &plugins,
                        &mut ctx,
                        StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN),
                        &plugin_reject.body,
                        plugin_reject.headers,
                        is_grpc_request,
                    )
                    .await;
                    apply_grpc_reject_metadata(&mut ctx, &reject);
                    log_rejected_request(
                        &plugins,
                        &ctx,
                        reject.http_status.as_u16(),
                        start_time,
                        "authorize",
                        plugin_execution_ns,
                    )
                    .await;
                    record_request(&state, reject.http_status.as_u16());
                    return Ok(build_response_from_normalized_reject(reject));
                }
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
    }

    let maybe_requires_request_body_buffering = state
        .plugin_cache
        .requires_request_body_buffering(&proxy.id);
    // should_buffer_request_body is request-time (takes &RequestContext), so it
    // must still iterate. But the config-time capability checks use the bitset.
    let requires_request_body_buffering = maybe_requires_request_body_buffering
        && plugins
            .iter()
            .any(|plugin| plugin.should_buffer_request_body(&ctx));
    let requires_request_body_before_before_proxy = requires_request_body_buffering
        && capabilities.has(PluginCapabilities::HAS_BODY_BEFORE_BEFORE_PROXY)
        && plugins.iter().any(|plugin| {
            plugin.requires_request_body_before_before_proxy()
                && plugin.should_buffer_request_body(&ctx)
        });
    let needs_body_bytes = requires_request_body_before_before_proxy
        && capabilities.has(PluginCapabilities::NEEDS_REQUEST_BODY_BYTES);

    if requires_request_body_before_before_proxy {
        client_request_body = match client_request_body {
            ClientRequestBody::Streaming(request) => {
                match buffer_request_body_for_before_proxy(
                    *request,
                    &method,
                    &ctx.headers,
                    state.max_request_body_size_bytes,
                )
                .await
                {
                    Ok(buffered) => {
                        if let ClientRequestBody::Buffered(body) = &buffered {
                            store_request_body_metadata(&mut ctx, body, needs_body_bytes);
                        }
                        buffered
                    }
                    Err(RequestBodyBufferError::TooLarge) => {
                        record_request(&state, 413);
                        return Ok(build_response(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            r#"{"error":"Request body exceeds maximum size"}"#,
                        ));
                    }
                    Err(RequestBodyBufferError::ClientDisconnected(error_message)) => {
                        error!(
                            proxy_id = %proxy.id,
                            path = %ctx.path,
                            error_kind = "client_disconnect",
                            error = %error_message,
                            "Client disconnected while buffering request body before before_proxy"
                        );
                        record_request(&state, 499);
                        return Ok(build_response(
                            StatusCode::from_u16(499).unwrap_or(StatusCode::BAD_REQUEST),
                            r#"{"error":"Client disconnected"}"#,
                        ));
                    }
                }
            }
            already_buffered => already_buffered,
        };
    }

    // before_proxy hooks — only clone headers if at least one plugin modifies them.
    // When no plugin modifies headers, pass &mut ctx.headers directly to avoid
    // an expensive per-request HashMap clone on the hot path.
    let needs_header_clone = capabilities.has(PluginCapabilities::MODIFIES_REQUEST_HEADERS);
    let mut owned_proxy_headers: Option<HashMap<String, String>> = None;
    if needs_header_clone {
        let phase_start = Instant::now();
        let mut cloned = ctx.headers.clone();
        for plugin in plugins.iter() {
            match plugin.before_proxy(&mut ctx, &mut cloned).await {
                PluginResult::Continue => {}
                reject @ PluginResult::Reject { .. }
                | reject @ PluginResult::RejectBinary { .. } => {
                    let plugin_reject = plugin_result_into_reject_parts(reject)
                        .expect("reject result should convert to rejection parts");
                    let status_code = plugin_reject.status_code;
                    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                    let reject = finalize_reject_response_with_after_proxy_hooks(
                        &plugins,
                        &mut ctx,
                        StatusCode::from_u16(status_code)
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                        &plugin_reject.body,
                        plugin_reject.headers,
                        is_grpc_request,
                    )
                    .await;
                    apply_grpc_reject_metadata(&mut ctx, &reject);
                    log_rejected_request(
                        &plugins,
                        &ctx,
                        reject.http_status.as_u16(),
                        start_time,
                        "before_proxy",
                        plugin_execution_ns,
                    )
                    .await;
                    record_request(&state, reject.http_status.as_u16());
                    return Ok(build_response_from_normalized_reject(reject));
                }
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        owned_proxy_headers = Some(cloned);
    } else if !plugins.is_empty() {
        // Run before_proxy hooks that don't modify headers (e.g., body_validator).
        // No plugin modifies headers, so swap headers out of ctx temporarily to
        // satisfy the borrow checker without cloning — zero allocation hot path.
        let phase_start = Instant::now();
        let mut tmp_headers = std::mem::take(&mut ctx.headers);
        for plugin in plugins.iter() {
            match plugin.before_proxy(&mut ctx, &mut tmp_headers).await {
                PluginResult::Continue => {}
                reject @ PluginResult::Reject { .. }
                | reject @ PluginResult::RejectBinary { .. } => {
                    let plugin_reject = plugin_result_into_reject_parts(reject)
                        .expect("reject result should convert to rejection parts");
                    let status_code = plugin_reject.status_code;
                    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                    ctx.headers = tmp_headers;
                    let reject = finalize_reject_response_with_after_proxy_hooks(
                        &plugins,
                        &mut ctx,
                        StatusCode::from_u16(status_code)
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                        &plugin_reject.body,
                        plugin_reject.headers,
                        is_grpc_request,
                    )
                    .await;
                    apply_grpc_reject_metadata(&mut ctx, &reject);
                    log_rejected_request(
                        &plugins,
                        &ctx,
                        reject.http_status.as_u16(),
                        start_time,
                        "before_proxy",
                        plugin_execution_ns,
                    )
                    .await;
                    record_request(&state, reject.http_status.as_u16());
                    return Ok(build_response_from_normalized_reject(reject));
                }
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        ctx.headers = tmp_headers;
    }
    // Inject identity headers when authentication resolved a principal.
    if let Some(username) = ctx.backend_consumer_username() {
        let headers = owned_proxy_headers.get_or_insert_with(|| ctx.headers.clone());
        headers.insert("X-Consumer-Username".to_string(), username.to_string());
        if let Some(custom_id) = ctx.backend_consumer_custom_id() {
            headers.insert("X-Consumer-Custom-Id".to_string(), custom_id.to_string());
        }
    }
    let proxy_headers: &HashMap<String, String> =
        owned_proxy_headers.as_ref().unwrap_or(&ctx.headers);

    // Resolve upstream target and hash key with a single ArcSwap load.
    let selection =
        backend_dispatch::select_upstream_target(&proxy, &state, &ctx.client_ip, proxy_headers);
    let lb_hash_key = selection.lb_hash_key;
    let upstream_target = selection.target;
    let upstream_is_fallback = selection.is_fallback;
    let sticky_cookie_needed = selection.sticky_cookie_needed;

    // Circuit breaker check — per-target when upstream is configured, per-proxy otherwise
    let cb_target_key =
        match backend_dispatch::check_circuit_breaker(&proxy, &state, upstream_target.as_deref()) {
            Ok(key) => key,
            Err(()) => {
                let reject = finalize_reject_response_with_after_proxy_hooks(
                    &plugins,
                    &mut ctx,
                    StatusCode::SERVICE_UNAVAILABLE,
                    br#"{"error":"Service temporarily unavailable (circuit breaker open)"}"#,
                    HashMap::new(),
                    is_grpc_request,
                )
                .await;
                apply_grpc_reject_metadata(&mut ctx, &reject);
                log_rejected_request(
                    &plugins,
                    &ctx,
                    reject.http_status.as_u16(),
                    start_time,
                    "circuit_breaker_open",
                    plugin_execution_ns,
                )
                .await;
                record_request(&state, reject.http_status.as_u16());
                return Ok(build_response_from_normalized_reject(reject));
            }
        };

    // Check if this is a WebSocket upgrade request and the proxy supports WebSocket
    // This check happens AFTER authentication and authorization plugins have run
    if request_protocol == ProxyProtocol::WebSocket
        && matches!(
            proxy.backend_protocol,
            BackendProtocol::Ws | BackendProtocol::Wss
        )
    {
        // Cross-Site WebSocket Hijacking (CSWSH) protection per RFC 6455 §10.2.
        // When allowed_ws_origins is non-empty, reject upgrades from unlisted origins.
        if !proxy.allowed_ws_origins.is_empty() {
            let origin = ctx.headers.get("origin").map(|s| s.as_str()).unwrap_or("");
            if !proxy
                .allowed_ws_origins
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(origin))
            {
                warn!(
                    "WebSocket upgrade rejected: Origin '{}' not in allowed_ws_origins for proxy {}",
                    origin, proxy.id
                );
                record_request(&state, 403);
                return Ok(build_response(
                    StatusCode::FORBIDDEN,
                    r#"{"error":"WebSocket Origin not allowed"}"#,
                ));
            }
        }

        let request = match client_request_body {
            ClientRequestBody::Streaming(request) => *request,
            ClientRequestBody::Buffered(_) => {
                debug_assert!(
                    false,
                    "websocket requests should never be pre-buffered for before_proxy"
                );
                record_request(&state, 500);
                return Ok(build_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    r#"{"error":"WebSocket request buffering invariant violated"}"#,
                ));
            }
        };
        return handle_websocket_request_authenticated(
            request,
            state,
            remote_addr,
            proxy,
            ctx,
            plugins,
            plugin_execution_ns,
            upstream_target,
            lb_hash_key,
            sticky_cookie_needed,
            start_time,
            is_h2_ws,
            is_tls,
        )
        .await;
    }

    // Check if this is a gRPC request and the proxy supports gRPC
    if is_grpc_request
        && matches!(
            proxy.backend_protocol,
            BackendProtocol::Grpc | BackendProtocol::Grpcs
        )
    {
        let (grpc_effective_host, grpc_effective_port) = if let Some(ref target) = upstream_target {
            (target.host.as_str(), target.port)
        } else {
            (proxy.backend_host.as_str(), proxy.backend_port)
        };
        let mut grpc_backend_url = build_backend_url_with_target(
            &proxy,
            &path,
            &query_string,
            grpc_effective_host,
            grpc_effective_port,
            strip_len,
            upstream_target.as_ref().and_then(|t| t.path.as_deref()),
        );
        let backend_start = Instant::now();

        // Streaming is safe only when there are no retries and no plugins need
        // the response body buffered (e.g., ai_token_metrics, ai_rate_limiter).
        let grpc_has_retry = proxy.retry.is_some();
        let grpc_should_stream = !grpc_has_retry
            && !state
                .plugin_cache
                .requires_response_body_buffering(&proxy.id);

        // When plugins need request body access (e.g., protobuf validation),
        // collect the body first, run hooks, then dispatch to backend.
        // Otherwise, use the fast combined collect+dispatch path.
        let grpc_needs_request_body_hooks = requires_request_body_buffering;
        let (mut grpc_result, grpc_body_bytes) = if grpc_needs_request_body_hooks {
            // Split path: collect body → run plugin hooks → dispatch
            let request = match client_request_body {
                ClientRequestBody::Streaming(request) => *request,
                ClientRequestBody::Buffered(_) => {
                    record_request(&state, 500);
                    return Ok(build_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        r#"{"error":"Internal error"}"#,
                    ));
                }
            };
            let (grpc_method, grpc_headers, grpc_req_body) =
                match grpc_proxy::collect_grpc_request_body(request, state.max_grpc_recv_size_bytes)
                    .await
                {
                    Ok(parts) => parts,
                    Err(e) => {
                        record_request(&state, 500);
                        return Ok(grpc_proxy::build_grpc_error_response(
                            13, // INTERNAL
                            &format!("Failed to read gRPC request body: {:?}", e),
                        ));
                    }
                };

            // Store body metadata for plugins that read via ctx.metadata
            ctx.metadata.insert(
                "request_body_size_bytes".to_string(),
                grpc_req_body.len().to_string(),
            );

            // Transform request body via plugins (e.g., gRPC-Web base64 decoding)
            let mut hook_headers = proxy_headers.clone();
            hook_headers
                .entry(":path".to_string())
                .or_insert_with(|| path.clone());
            let grpc_req_body = bytes::Bytes::from(
                apply_request_body_plugins(&plugins, &hook_headers, grpc_req_body.to_vec()).await,
            );

            // Run on_final_request_body hooks (e.g., protobuf validation)
            match run_final_request_body_hooks(&plugins, &hook_headers, &grpc_req_body).await {
                PluginResult::Continue => {}
                reject @ PluginResult::Reject { .. }
                | reject @ PluginResult::RejectBinary { .. } => {
                    let (status, body, headers) = match reject {
                        PluginResult::Reject {
                            status_code,
                            body,
                            headers,
                        } => (status_code, body.into_bytes(), headers),
                        PluginResult::RejectBinary {
                            status_code,
                            body,
                            headers,
                        } => (status_code, body.to_vec(), headers),
                        _ => unreachable!(),
                    };
                    let normalized = normalize_reject_response(
                        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                        &body,
                        &headers,
                        true, // is_grpc_request
                    );
                    record_request(&state, normalized.http_status.as_u16());
                    return Ok(build_response_from_normalized_reject(normalized));
                }
            }

            // Dispatch to backend with pre-collected body bytes
            let result = grpc_proxy::proxy_grpc_request_core(
                grpc_method,
                grpc_headers,
                grpc_req_body.clone(),
                &proxy,
                &grpc_backend_url,
                &state.grpc_pool,
                &state.dns_cache,
                proxy_headers,
                grpc_should_stream,
            )
            .await;
            if grpc_should_stream {
                (result, Bytes::new())
            } else {
                (result, grpc_req_body)
            }
        } else {
            // Fast path: no plugin body hooks needed
            let request = match client_request_body {
                ClientRequestBody::Streaming(request) => *request,
                ClientRequestBody::Buffered(_) => {
                    record_request(&state, 500);
                    return Ok(build_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        r#"{"error":"Internal error"}"#,
                    ));
                }
            };
            if grpc_should_stream {
                // Streaming fast path: forward request body frame-by-frame
                // without collecting. No retries possible, no body plugins.
                let result = grpc_proxy::proxy_grpc_request_streaming(
                    request,
                    &proxy,
                    &grpc_backend_url,
                    &state.grpc_pool,
                    &state.dns_cache,
                    proxy_headers,
                    state.max_grpc_recv_size_bytes,
                )
                .await;
                (result, Bytes::new())
            } else {
                // Buffered path: collect body for potential retries
                grpc_proxy::proxy_grpc_request(
                    request,
                    &proxy,
                    &grpc_backend_url,
                    &state.grpc_pool,
                    &state.dns_cache,
                    proxy_headers,
                    grpc_should_stream,
                    state.max_grpc_recv_size_bytes,
                )
                .await
            }
        };

        // Only build retry parts when retries are configured
        let grpc_method = hyper::Method::POST; // gRPC always uses POST
        let grpc_req_headers: hyper::HeaderMap = if proxy.retry.is_some() {
            let mut hm = hyper::HeaderMap::new();
            for (k, v) in proxy_headers {
                if let (Ok(name), Ok(val)) = (
                    hyper::header::HeaderName::from_bytes(k.as_bytes()),
                    hyper::header::HeaderValue::from_str(v),
                ) {
                    hm.insert(name, val);
                }
            }
            hm
        } else {
            hyper::HeaderMap::new()
        };

        // gRPC retry loop — retries on connection failures
        if let Some(retry_config) = &proxy.retry {
            let mut grpc_attempt = 0u32;
            let mut grpc_current_target = upstream_target.clone();
            let mut grpc_current_cb_key = cb_target_key.clone();

            loop {
                // Classify the error and determine if retryable
                let is_connection_error = match &grpc_result {
                    Err(GrpcProxyError::BackendUnavailable(_)) => true,
                    Err(GrpcProxyError::BackendTimeout(msg)) if msg.contains("Connect timeout") => {
                        true
                    }
                    _ => false,
                };
                if grpc_attempt >= retry_config.max_retries
                    || !is_connection_error
                    || !retry_config.retry_on_connect_failure
                {
                    break;
                }

                // Record circuit breaker failure for current target
                if let Some(cb_config) = &proxy.circuit_breaker {
                    let cb = state.circuit_breaker_cache.get_or_create(
                        &proxy.id,
                        grpc_current_cb_key.as_deref(),
                        cb_config,
                    );
                    cb.record_failure(502, true);
                }

                let delay = retry::retry_delay(retry_config, grpc_attempt);
                tokio::time::sleep(delay).await;
                grpc_attempt += 1;

                // Try a different target on retry if load balancing is configured
                if let (Some(upstream_id), Some(prev_target)) =
                    (&proxy.upstream_id, &grpc_current_target)
                    && let Some(ref hash_key) = lb_hash_key
                    && let Some(next) = state.load_balancer_cache.select_next_target(
                        upstream_id,
                        hash_key,
                        prev_target,
                        Some(&crate::load_balancer::HealthContext {
                            active_unhealthy: &state.health_checker.active_unhealthy_targets,
                            proxy_passive: state
                                .health_checker
                                .passive_health
                                .get(&proxy.id)
                                .map(|r| r.value().clone()),
                        }),
                    )
                {
                    grpc_backend_url = build_backend_url_with_target(
                        &proxy,
                        &path,
                        &query_string,
                        &next.host,
                        next.port,
                        strip_len,
                        next.path.as_deref(),
                    );
                    grpc_current_cb_key =
                        Some(crate::circuit_breaker::target_key(&next.host, next.port));
                    grpc_current_target = Some(next);
                }

                warn!(
                    proxy_id = %proxy.id,
                    attempt = grpc_attempt,
                    max_retries = retry_config.max_retries,
                    "Retrying gRPC backend request"
                );

                grpc_result = grpc_proxy::proxy_grpc_request_from_bytes(
                    grpc_method.clone(),
                    grpc_req_headers.clone(),
                    grpc_body_bytes.clone(),
                    &proxy,
                    &grpc_backend_url,
                    &state.grpc_pool,
                    &state.dns_cache,
                    proxy_headers,
                )
                .await;
            }
        }

        let backend_total_ms = backend_start.elapsed().as_secs_f64() * 1000.0;

        match grpc_result {
            Ok(GrpcResponseKind::Streaming(grpc_streaming)) => {
                // Frame-by-frame streaming path: headers arrived, body not buffered.
                // after_proxy plugins run on headers only (body is not yet in memory).
                let mut response_headers: HashMap<String, String> = grpc_streaming.headers;
                {
                    let phase_start = Instant::now();
                    if let Some(reject) = run_after_proxy_hooks(
                        &plugins,
                        &mut ctx,
                        grpc_streaming.status,
                        &mut response_headers,
                    )
                    .await
                    {
                        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                        let normalized = normalize_reject_response(
                            StatusCode::from_u16(reject.status_code)
                                .unwrap_or(StatusCode::BAD_GATEWAY),
                            &reject.body,
                            &reject.headers,
                            true,
                        );
                        apply_grpc_reject_metadata(&mut ctx, &normalized);
                        log_rejected_request(
                            &plugins,
                            &ctx,
                            normalized.http_status.as_u16(),
                            start_time,
                            "after_proxy",
                            plugin_execution_ns,
                        )
                        .await;
                        record_request(&state, normalized.http_status.as_u16());
                        return Ok(build_response_from_normalized_reject(normalized));
                    }
                    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                }

                // Check if the streaming request body exceeded the size limit
                // BEFORE logging — otherwise the transaction summary captures a
                // success status while we're about to return RESOURCE_EXHAUSTED.
                let body_exceeded = grpc_streaming
                    .request_body_exceeded
                    .as_ref()
                    .is_some_and(|f| f.load(std::sync::atomic::Ordering::Acquire));

                // Determine the final status for logging and metrics.
                let final_status = if body_exceeded {
                    200_u16
                } else {
                    grpc_streaming.status
                };
                let final_error_class: Option<retry::ErrorClass> = if body_exceeded {
                    Some(retry::ErrorClass::RequestBodyTooLarge)
                } else {
                    None
                };

                let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
                let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
                let plugin_external_io_ms =
                    ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
                let gateway_processing_ms = total_ms - backend_total_ms;
                let gateway_overhead_ms =
                    (total_ms - backend_total_ms - plugin_execution_ms).max(0.0);
                // `backend_total_ms` for the gRPC streaming path is actually the time
                // through response headers (TTFB) — the body is forwarded frame-by-frame
                // by hyper after this point. When body_exceeded aborts streaming, backend
                // work is complete at the abort so total == TTFB. Otherwise the body is
                // still flowing at log time, so total_ms is unknown (-1.0 per schema).
                let streamed = !body_exceeded;
                let grpc_backend_total_ms = if streamed { -1.0 } else { backend_total_ms };

                // Build the summary up front so we can either log synchronously
                // (body_exceeded early-return path) or defer via the streaming
                // body wrapper (non-exceeded streaming path).
                let deferred_grpc_logger: Option<
                    Arc<crate::proxy::deferred_log::DeferredTransactionLogger>,
                > = if !plugins.is_empty() {
                    let grpc_resolved_ip = state
                        .dns_cache
                        .resolve(
                            &proxy.backend_host,
                            proxy.dns_override.as_deref(),
                            proxy.dns_cache_ttl_seconds,
                        )
                        .await
                        .ok()
                        .map(|ip| ip.to_string());

                    let summary = TransactionSummary {
                        namespace: proxy.namespace.clone(),
                        timestamp_received: ctx.timestamp_received.to_rfc3339(),
                        client_ip: ctx.client_ip.clone(),
                        consumer_username: ctx.effective_identity().map(str::to_owned),
                        http_method: method,
                        request_path: path,
                        matched_proxy_id: Some(proxy.id.clone()),
                        matched_proxy_name: proxy.name.clone(),
                        backend_target_url: Some(strip_query_params(&grpc_backend_url).to_string()),
                        backend_resolved_ip: grpc_resolved_ip,
                        response_status_code: final_status,
                        latency_total_ms: total_ms,
                        latency_gateway_processing_ms: gateway_processing_ms,
                        latency_backend_ttfb_ms: backend_total_ms,
                        latency_backend_total_ms: grpc_backend_total_ms,
                        latency_plugin_execution_ms: plugin_execution_ms,
                        latency_plugin_external_io_ms: plugin_external_io_ms,
                        latency_gateway_overhead_ms: gateway_overhead_ms,
                        request_user_agent: ctx.headers.get("user-agent").cloned(),
                        response_streamed: streamed,
                        client_disconnected: false,
                        error_class: final_error_class,
                        body_error_class: None,
                        body_completed: false,
                        bytes_streamed_to_client: 0,
                        mirror: false,
                        metadata: ctx.metadata.clone(),
                    };
                    if body_exceeded {
                        // Request body exceeded the size limit; we're about to
                        // return a trailers-only RESOURCE_EXHAUSTED error. The
                        // response body never streams, so log synchronously here.
                        crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;
                        None
                    } else {
                        // Streaming gRPC response: defer so the summary reflects
                        // mid-body RST, client cancellation, and partial bytes.
                        Some(crate::proxy::deferred_log::DeferredTransactionLogger::new(
                            summary,
                            Arc::clone(&plugins),
                            Arc::new(ctx.clone()),
                        ))
                    }
                } else {
                    None
                };

                if body_exceeded {
                    record_request(&state, 200);
                    return Ok(grpc_proxy::build_grpc_error_response(
                        grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                        "gRPC request payload size exceeds maximum",
                    ));
                }

                record_request(&state, grpc_streaming.status);

                // Build the response with the live Incoming body — hyper will forward
                // DATA frames and TRAILERS to the downstream client as they arrive.
                let mut resp_builder = Response::builder()
                    .status(StatusCode::from_u16(grpc_streaming.status).unwrap_or(StatusCode::OK));
                for (k, v) in &response_headers {
                    if let (Ok(name), Ok(val)) = (
                        hyper::header::HeaderName::from_bytes(k.as_bytes()),
                        hyper::header::HeaderValue::from_str(v),
                    ) {
                        resp_builder = resp_builder.header(name, val);
                    }
                }
                // For bidi/client-streaming RPCs where the request body is still
                // sending: GrpcBody::Streaming returns an error when exceeded,
                // which causes hyper to RST_STREAM the request. The backend then
                // resets the response stream, and the Incoming response body
                // naturally propagates the h2 error to the client.

                // Stream H2 DATA frames on the gRPC streaming path.
                let cl = response_headers
                    .get("content-length")
                    .and_then(|v| v.parse::<u64>().ok());
                let body = if state.response_buffer_cutoff_bytes == 0
                    && state.max_response_body_size_bytes == 0
                {
                    crate::proxy::body::direct_streaming_h2_body(grpc_streaming.body, cl)
                } else {
                    crate::proxy::body::coalescing_h2_body(
                        grpc_streaming.body,
                        cl,
                        state.h2_coalesce_target_bytes,
                    )
                };
                let body = if let Some(logger) = deferred_grpc_logger {
                    body.with_logger(logger)
                } else {
                    body
                };

                return Ok(resp_builder.body(body).unwrap_or_else(|_| {
                    grpc_proxy::build_grpc_error_response(
                        grpc_proxy::grpc_status::UNAVAILABLE,
                        "Internal gateway error",
                    )
                }));
            }
            Ok(GrpcResponseKind::Buffered(grpc_resp)) => {
                let mut response_status = grpc_resp.status;
                let mut response_headers: HashMap<String, String> = grpc_resp.headers;
                let mut response_body = grpc_resp.body;

                // Forward trailers as response headers (gRPC Trailers-Only encoding).
                // Drain instead of clone to avoid per-trailer String allocations.
                for (k, v) in grpc_resp.trailers {
                    response_headers.insert(k, v);
                }

                // after_proxy hooks
                let mut after_proxy_rejected = false;
                {
                    let phase_start = Instant::now();
                    if let Some(reject) = run_after_proxy_hooks(
                        &plugins,
                        &mut ctx,
                        response_status,
                        &mut response_headers,
                    )
                    .await
                    {
                        let normalized = normalize_reject_response(
                            StatusCode::from_u16(reject.status_code)
                                .unwrap_or(StatusCode::BAD_GATEWAY),
                            &reject.body,
                            &reject.headers,
                            true,
                        );
                        apply_grpc_reject_metadata(&mut ctx, &normalized);
                        response_status = normalized.http_status.as_u16();
                        response_headers = normalized.headers;
                        response_body = normalized.body;
                        after_proxy_rejected = true;
                    }
                    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                }

                if !after_proxy_rejected {
                    let phase_start = Instant::now();
                    for plugin in plugins.iter() {
                        let result = plugin
                            .on_response_body(
                                &mut ctx,
                                response_status,
                                &response_headers,
                                &response_body,
                            )
                            .await;
                        match result {
                            PluginResult::Continue => {}
                            reject @ PluginResult::Reject { .. }
                            | reject @ PluginResult::RejectBinary { .. } => {
                                let reject = plugin_result_into_reject_parts(reject)
                                    .expect("reject result should convert to rejection parts");
                                debug!(
                                    plugin = plugin.name(),
                                    status_code = reject.status_code,
                                    "Plugin rejected gRPC response body"
                                );
                                let normalized = normalize_reject_response(
                                    StatusCode::from_u16(reject.status_code)
                                        .unwrap_or(StatusCode::BAD_GATEWAY),
                                    &reject.body,
                                    &reject.headers,
                                    true,
                                );
                                apply_grpc_reject_metadata(&mut ctx, &normalized);
                                response_status = normalized.http_status.as_u16();
                                response_headers = normalized.headers;
                                response_body = normalized.body;
                                break;
                            }
                        }
                    }
                    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                }

                if !after_proxy_rejected {
                    let phase_start = Instant::now();
                    let content_type = response_headers.get("content-type").cloned();
                    let ct_ref = content_type.as_deref();
                    for plugin in plugins.iter() {
                        if let Some(transformed) = plugin
                            .transform_response_body(&response_body, ct_ref, &response_headers)
                            .await
                        {
                            response_headers.insert(
                                "content-length".to_string(),
                                transformed.len().to_string(),
                            );
                            response_body = transformed;
                        }
                    }
                    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                }

                if !after_proxy_rejected {
                    let phase_start = Instant::now();
                    for plugin in plugins.iter() {
                        let result = plugin
                            .on_final_response_body(
                                &mut ctx,
                                response_status,
                                &response_headers,
                                &response_body,
                            )
                            .await;
                        match result {
                            PluginResult::Continue => {}
                            reject @ PluginResult::Reject { .. }
                            | reject @ PluginResult::RejectBinary { .. } => {
                                let reject = plugin_result_into_reject_parts(reject)
                                    .expect("reject result should convert to rejection parts");
                                debug!(
                                    plugin = plugin.name(),
                                    status_code = reject.status_code,
                                    "Plugin rejected finalized gRPC response body"
                                );
                                let normalized = normalize_reject_response(
                                    StatusCode::from_u16(reject.status_code)
                                        .unwrap_or(StatusCode::BAD_GATEWAY),
                                    &reject.body,
                                    &reject.headers,
                                    true,
                                );
                                apply_grpc_reject_metadata(&mut ctx, &normalized);
                                response_status = normalized.http_status.as_u16();
                                response_headers = normalized.headers;
                                response_body = normalized.body;
                                break;
                            }
                        }
                    }
                    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                }

                let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
                let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
                let plugin_external_io_ms =
                    ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
                let gateway_processing_ms = total_ms - backend_total_ms;
                let gateway_overhead_ms =
                    (total_ms - backend_total_ms - plugin_execution_ms).max(0.0);

                // Log phase
                if !plugins.is_empty() {
                    // Resolve backend IP from DNS cache for gRPC tx log
                    let grpc_resolved_ip = state
                        .dns_cache
                        .resolve(
                            &proxy.backend_host,
                            proxy.dns_override.as_deref(),
                            proxy.dns_cache_ttl_seconds,
                        )
                        .await
                        .ok()
                        .map(|ip| ip.to_string());

                    let summary = TransactionSummary {
                        namespace: proxy.namespace.clone(),
                        timestamp_received: ctx.timestamp_received.to_rfc3339(),
                        client_ip: ctx.client_ip.clone(),
                        consumer_username: ctx.effective_identity().map(str::to_owned),
                        http_method: method,
                        request_path: path,
                        matched_proxy_id: Some(proxy.id.clone()),
                        matched_proxy_name: proxy.name.clone(),
                        backend_target_url: Some(strip_query_params(&grpc_backend_url).to_string()),
                        backend_resolved_ip: grpc_resolved_ip,
                        response_status_code: response_status,
                        latency_total_ms: total_ms,
                        latency_gateway_processing_ms: gateway_processing_ms,
                        latency_backend_ttfb_ms: backend_total_ms,
                        latency_backend_total_ms: backend_total_ms,
                        latency_plugin_execution_ms: plugin_execution_ms,
                        latency_plugin_external_io_ms: plugin_external_io_ms,
                        latency_gateway_overhead_ms: gateway_overhead_ms,
                        request_user_agent: ctx.headers.get("user-agent").cloned(),
                        response_streamed: false,
                        client_disconnected: false,
                        error_class: None,
                        body_error_class: None,
                        body_completed: false,
                        bytes_streamed_to_client: 0,
                        mirror: false,
                        metadata: ctx.metadata.clone(),
                    };
                    crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;
                }

                // Inject sticky session cookie for gRPC responses
                if sticky_cookie_needed
                    && let (Some(upstream_id), Some(target)) =
                        (&proxy.upstream_id, &upstream_target)
                {
                    let strategy = state.load_balancer_cache.get_hash_on_strategy(upstream_id);
                    if let HashOnStrategy::Cookie(ref cookie_name) = strategy {
                        let upstream = state.load_balancer_cache.get_upstream(upstream_id);
                        let default_cc = crate::config::types::HashOnCookieConfig::default();
                        let cookie_config = upstream
                            .as_ref()
                            .and_then(|u| u.hash_on_cookie_config.as_ref())
                            .unwrap_or(&default_cc);
                        let cookie_val =
                            build_sticky_cookie_header(cookie_name, target, cookie_config);
                        response_headers
                            .entry("set-cookie".to_string())
                            .and_modify(|v| {
                                v.push('\n');
                                v.push_str(&cookie_val);
                            })
                            .or_insert(cookie_val);
                    }
                }

                record_request(&state, response_status);

                // Build gRPC response with headers and trailers
                let mut resp_builder = Response::builder()
                    .status(StatusCode::from_u16(response_status).unwrap_or(StatusCode::OK));
                for (k, v) in &response_headers {
                    if let (Ok(name), Ok(val)) = (
                        hyper::header::HeaderName::from_bytes(k.as_bytes()),
                        hyper::header::HeaderValue::from_str(v),
                    ) {
                        resp_builder = resp_builder.header(name, val);
                    }
                }

                return Ok(resp_builder
                    .body(ProxyBody::full(Bytes::from(response_body)))
                    .unwrap_or_else(|_| {
                        grpc_proxy::build_grpc_error_response(
                            grpc_proxy::grpc_status::UNAVAILABLE,
                            "Internal gateway error",
                        )
                    }));
            }
            Err(e) => {
                let grpc_error_class = retry::classify_grpc_proxy_error(&e);
                if grpc_error_class == retry::ErrorClass::PortExhaustion {
                    state.overload.record_port_exhaustion();
                }
                let (grpc_code, original_msg) = match &e {
                    GrpcProxyError::BackendUnavailable(m) => {
                        (grpc_proxy::grpc_status::UNAVAILABLE, m.as_str())
                    }
                    GrpcProxyError::BackendTimeout(m) => {
                        (grpc_proxy::grpc_status::DEADLINE_EXCEEDED, m.as_str())
                    }
                    GrpcProxyError::ResourceExhausted(m) => {
                        (grpc_proxy::grpc_status::RESOURCE_EXHAUSTED, m.as_str())
                    }
                    GrpcProxyError::Internal(m) => {
                        (grpc_proxy::grpc_status::UNAVAILABLE, m.as_str())
                    }
                };
                let msg = if grpc_error_class == retry::ErrorClass::DnsLookupError {
                    "DNS resolution for backend failed"
                } else {
                    original_msg
                };

                // Log with error_class for gRPC backend failures
                let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
                let grpc_plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
                let grpc_plugin_external_io_ms =
                    ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
                let grpc_gateway_overhead_ms =
                    (total_ms - backend_total_ms - grpc_plugin_execution_ms).max(0.0);
                // Dispatch to the full plugin chain — plugins outside the
                // logging priority band (e.g., `otel_tracing` at priority 25)
                // still need the hook so rejected/error transactions reach
                // tracing sinks. The default `.log()` impl is a no-op.
                if !plugins.is_empty() {
                    {
                        let proxy_ref = ctx.matched_proxy.as_ref();
                        let mut metadata = ctx.metadata.clone();
                        metadata.insert(
                            "rejection_phase".to_string(),
                            "grpc_backend_error".to_string(),
                        );
                        insert_grpc_error_metadata(&mut metadata, grpc_code, msg);
                        let summary = TransactionSummary {
                            namespace: proxy_ref
                                .map(|p| p.namespace.clone())
                                .unwrap_or_else(crate::config::types::default_namespace),
                            timestamp_received: ctx.timestamp_received.to_rfc3339(),
                            client_ip: ctx.client_ip.clone(),
                            consumer_username: ctx.effective_identity().map(str::to_owned),
                            http_method: ctx.method.clone(),
                            request_path: ctx.path.clone(),
                            matched_proxy_id: proxy_ref.map(|p| p.id.clone()),
                            matched_proxy_name: proxy_ref.and_then(|p| p.name.clone()),
                            backend_target_url: proxy_ref.map(|p| {
                                let url = build_backend_url(p, &ctx.path, "", p.listen_path.len());
                                strip_query_params(&url).to_string()
                            }),
                            backend_resolved_ip: None,
                            response_status_code: 200, // gRPC errors use HTTP 200
                            latency_total_ms: total_ms,
                            latency_gateway_processing_ms: total_ms - backend_total_ms,
                            latency_backend_ttfb_ms: backend_total_ms,
                            latency_backend_total_ms: backend_total_ms,
                            latency_plugin_execution_ms: grpc_plugin_execution_ms,
                            latency_plugin_external_io_ms: grpc_plugin_external_io_ms,
                            latency_gateway_overhead_ms: grpc_gateway_overhead_ms,
                            request_user_agent: ctx.headers.get("user-agent").cloned(),
                            response_streamed: false,
                            client_disconnected: false,
                            error_class: Some(grpc_error_class),
                            body_error_class: None,
                            body_completed: false,
                            bytes_streamed_to_client: 0,
                            mirror: false,
                            metadata,
                        };
                        crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;
                    }
                }

                record_request(&state, 200); // gRPC errors use HTTP 200
                return Ok(grpc_proxy::build_grpc_error_response(grpc_code, msg));
            }
        }
    }

    // Build backend URL (using upstream target if available)
    let (effective_host, effective_port) = if let Some(ref target) = upstream_target {
        (target.host.as_str(), target.port)
    } else {
        (proxy.backend_host.as_str(), proxy.backend_port)
    };

    let backend_url = build_backend_url_with_target(
        &proxy,
        &path,
        &query_string,
        effective_host,
        effective_port,
        strip_len,
        upstream_target.as_ref().and_then(|t| t.path.as_deref()),
    );
    let backend_start = Instant::now();

    // Track connection for least-connections load balancing
    if let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, &upstream_target) {
        state
            .load_balancer_cache
            .record_connection_start(upstream_id, target);
    }

    // Determine response body mode: stream by default, buffer when required.
    // Two-tier check mirroring request body buffering:
    //   1. Config-time: does any plugin on this proxy potentially need buffering?
    //   2. Per-request: does any plugin need buffering for THIS specific request?
    // This lets plugins skip buffering when the request context makes it
    // irrelevant (e.g., compression when Accept-Encoding is absent).
    let should_stream = match proxy.response_body_mode {
        ResponseBodyMode::Buffer => false,
        ResponseBodyMode::Stream => {
            let maybe_requires = state
                .plugin_cache
                .requires_response_body_buffering(&proxy.id);
            if maybe_requires {
                // Per-request refinement: check if any plugin actually needs
                // buffering for this specific request.
                !plugins
                    .iter()
                    .any(|plugin| plugin.should_buffer_response_body(&ctx))
            } else {
                true
            }
        }
    };

    // Determine if we can stream the request body to the backend without
    // collecting it into memory. When retries are configured, we force
    // buffered mode so the collected body bytes can be replayed on connection
    // failures.
    let has_retry = proxy.retry.is_some();
    let stream_request_body = !has_retry && !requires_request_body_buffering;
    let request_client_ip = ctx.client_ip.clone();

    // Perform the backend request with retry logic.
    // Returns the response and the final CB target key (may differ from the
    // initial target when retries switch to a different upstream target).
    let (backend_resp, final_cb_target_key) = if let Some(retry_config) = &proxy.retry {
        let mut attempt = 0u32;
        let mut current_target = upstream_target.clone();
        let mut current_cb_target_key = cb_target_key.clone();
        let mut current_url = backend_url.clone();
        let (mut result, retained_body) = proxy_to_backend(
            &state,
            &proxy,
            &current_url,
            &method,
            proxy_headers,
            client_request_body,
            upstream_target.as_deref(),
            &plugins,
            should_stream,
            requires_request_body_buffering,
            stream_request_body,
            has_retry,
            &request_client_ip,
            is_tls,
        )
        .await;

        while retry::should_retry(retry_config, &method, &result, attempt) {
            // Record the failed attempt against the current target's circuit breaker
            // before potentially switching to a different target for the next retry.
            if let Some(cb_config) = &proxy.circuit_breaker {
                let cb = state.circuit_breaker_cache.get_or_create(
                    &proxy.id,
                    current_cb_target_key.as_deref(),
                    cb_config,
                );
                cb.record_failure(result.status_code, result.connection_error);
            }

            let delay = retry::retry_delay(retry_config, attempt);
            tokio::time::sleep(delay).await;
            attempt += 1;

            // Try a different target on retry if load balancing is configured
            if let (Some(upstream_id), Some(prev_target)) = (&proxy.upstream_id, &current_target)
                && let Some(ref hash_key) = lb_hash_key
                && let Some(next) = state.load_balancer_cache.select_next_target(
                    upstream_id,
                    hash_key,
                    prev_target,
                    Some(&crate::load_balancer::HealthContext {
                        active_unhealthy: &state.health_checker.active_unhealthy_targets,
                        proxy_passive: state
                            .health_checker
                            .passive_health
                            .get(&proxy.id)
                            .map(|r| r.value().clone()),
                    }),
                )
            {
                current_url = build_backend_url_with_target(
                    &proxy,
                    &path,
                    &query_string,
                    &next.host,
                    next.port,
                    strip_len,
                    next.path.as_deref(),
                );
                current_cb_target_key =
                    Some(crate::circuit_breaker::target_key(&next.host, next.port));
                current_target = Some(next);
            }

            warn!(
                proxy_id = %proxy.id,
                attempt = attempt,
                max_retries = retry_config.max_retries,
                connection_error = result.connection_error,
                "Retrying backend request"
            );

            // Replay the original request body on retry. On connection failures
            // the body was never sent, so replaying is correct and safe.
            // The final retry attempt uses streaming if configured.
            let is_last_attempt = attempt >= retry_config.max_retries;
            result = if matches!(proxy.backend_protocol, BackendProtocol::H3) {
                proxy_to_backend_http3_retry(
                    &state,
                    &proxy,
                    &current_url,
                    &method,
                    proxy_headers,
                    current_target.as_deref(),
                    retained_body.as_deref(),
                    &ctx.client_ip,
                    is_tls,
                )
                .await
            } else {
                proxy_to_backend_retry(
                    &state,
                    &proxy,
                    &current_url,
                    &method,
                    proxy_headers,
                    current_target.as_deref(),
                    retained_body.as_deref(),
                    should_stream && is_last_attempt,
                    &ctx.client_ip,
                    is_tls,
                )
                .await
            };
        }
        (result, current_cb_target_key)
    } else {
        let resp = proxy_to_backend(
            &state,
            &proxy,
            &backend_url,
            &method,
            proxy_headers,
            client_request_body,
            upstream_target.as_deref(),
            &plugins,
            should_stream,
            requires_request_body_buffering,
            stream_request_body,
            false, // no retry — don't retain body
            &request_client_ip,
            is_tls,
        )
        .await
        .0;
        (resp, cb_target_key.clone())
    };
    let mut response_status = backend_resp.status_code;
    let mut response_body = backend_resp.body;
    let mut response_headers = backend_resp.headers;
    let backend_resolved_ip = backend_resp.backend_resolved_ip;
    let backend_error_class = backend_resp.error_class.clone();

    debug!(
        proxy_id = %proxy.id,
        status = response_status,
        connection_error = backend_resp.connection_error,
        "Backend response received"
    );

    // Record outcome across CB, passive health, latency, and connection tracking.
    backend_dispatch::record_backend_outcome(
        &state,
        &proxy,
        upstream_target.as_deref(),
        final_cb_target_key.as_deref(),
        response_status,
        backend_resp.connection_error,
        backend_start.elapsed(),
    );

    let backend_elapsed = backend_start.elapsed().as_secs_f64() * 1000.0;
    let backend_ttfb_ms = backend_elapsed;
    // For buffered responses, backend_elapsed includes full body download (accurate total).
    // For streaming responses, the body is still being sent to the client at log time,
    // so we mark total as unknown (-1.0) to avoid silently reporting TTFB as total.
    let is_streaming_response = matches!(
        &response_body,
        ResponseBody::Streaming(_) | ResponseBody::StreamingH2(_) | ResponseBody::StreamingH3(_)
    );
    let backend_total_ms = if is_streaming_response {
        -1.0
    } else {
        backend_elapsed
    };

    // after_proxy hooks run before anything is sent downstream, so a plugin may
    // still replace the backend response here (for example, content-length fast-path
    // enforcement in response_size_limiting).
    let mut after_proxy_rejected = false;
    if !plugins.is_empty() {
        let phase_start = Instant::now();
        if let Some(reject) =
            run_after_proxy_hooks(&plugins, &mut ctx, response_status, &mut response_headers).await
        {
            response_status = reject.status_code;
            response_headers = reject.headers;
            response_headers
                .entry("content-type".to_string())
                .or_insert_with(|| "application/json".to_string());
            response_body = ResponseBody::Buffered(reject.body);
            after_proxy_rejected = true;
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
    }

    // on_response_body hooks — only for buffered responses, only when plugins exist.
    // This phase sees the raw backend body before any response transformations.
    // A Reject result replaces the response before it reaches the client.
    if !after_proxy_rejected
        && !plugins.is_empty()
        && let ResponseBody::Buffered(ref data) = response_body
    {
        let phase_start = Instant::now();
        for plugin in plugins.iter() {
            let result = plugin
                .on_response_body(&mut ctx, response_status, &response_headers, data)
                .await;
            match result {
                PluginResult::Continue => {}
                reject @ PluginResult::Reject { .. }
                | reject @ PluginResult::RejectBinary { .. } => {
                    let reject = plugin_result_into_reject_parts(reject)
                        .expect("reject result should convert to rejection parts");
                    debug!(
                        plugin = plugin.name(),
                        status_code = reject.status_code,
                        "Plugin rejected response body"
                    );
                    response_status = reject.status_code;
                    response_headers.clear();
                    response_headers
                        .insert("content-type".to_string(), "application/json".to_string());
                    for (k, v) in reject.headers {
                        response_headers.insert(k, v);
                    }
                    response_body = ResponseBody::Buffered(reject.body);
                    break;
                }
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
    }

    // transform_response_body hooks — only for buffered responses.
    // Allows plugins (e.g., response_transformer with body rules) to rewrite
    // JSON fields in the response body before it is sent to the client.
    if !after_proxy_rejected
        && !plugins.is_empty()
        && let ResponseBody::Buffered(ref mut data) = response_body
    {
        let phase_start = Instant::now();
        // Clone content-type to avoid borrowing response_headers across the loop.
        let content_type = response_headers.get("content-type").cloned();
        let ct_ref = content_type.as_deref();
        for plugin in plugins.iter() {
            if let Some(transformed) = plugin
                .transform_response_body(data, ct_ref, &response_headers)
                .await
            {
                // Update Content-Length to reflect the new body size
                response_headers
                    .insert("content-length".to_string(), transformed.len().to_string());
                *data = transformed;
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
    }

    // on_final_response_body hooks — buffered responses after all body transforms.
    // This lets plugins validate or persist the final client-visible payload.
    if !after_proxy_rejected
        && !plugins.is_empty()
        && let ResponseBody::Buffered(ref data) = response_body
    {
        let phase_start = Instant::now();
        for plugin in plugins.iter() {
            let result = plugin
                .on_final_response_body(&mut ctx, response_status, &response_headers, data)
                .await;
            match result {
                PluginResult::Continue => {}
                reject @ PluginResult::Reject { .. }
                | reject @ PluginResult::RejectBinary { .. } => {
                    let reject = plugin_result_into_reject_parts(reject)
                        .expect("reject result should convert to rejection parts");
                    debug!(
                        plugin = plugin.name(),
                        status_code = reject.status_code,
                        "Plugin rejected finalized response body"
                    );
                    response_status = reject.status_code;
                    response_headers.clear();
                    response_headers
                        .insert("content-type".to_string(), "application/json".to_string());
                    for (k, v) in reject.headers {
                        response_headers.insert(k, v);
                    }
                    response_body = ResponseBody::Buffered(reject.body);
                    break;
                }
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
    }

    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
    let plugin_external_io_ms =
        ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let effective_backend_ms = if backend_total_ms >= 0.0 {
        backend_total_ms
    } else {
        backend_ttfb_ms
    };
    let gateway_processing_ms = total_ms - effective_backend_ms;
    let gateway_overhead_ms = (total_ms - effective_backend_ms - plugin_execution_ms).max(0.0);

    // Log phase — skip TransactionSummary construction when no plugins need it.
    //
    // For streaming responses (Streaming / StreamingH2 / StreamingH3), defer
    // the log until the response body reaches a terminal state. At this point
    // only response headers have been flushed to hyper; the body is still being
    // polled out. Firing the log synchronously would record
    // `client_disconnected=false, body_completed=false` even if hyper then
    // cancels the connection mid-stream. The DeferredTransactionLogger attaches
    // to the ProxyBody wrapper and fires on success (Ready(None)), streaming
    // error (Ready(Some(Err))), or the Drop safety net (client disconnected
    // before completion). See `src/proxy/deferred_log.rs`.
    //
    // Note: a plugin reject during after_proxy/on_response_body/on_final_response_body
    // can replace the originally-streaming body with a Buffered one. We branch on
    // the *current* `response_body` rather than the captured `is_streaming_response`
    // (which tracks the original backend behavior for observability).
    let deferred_logger: Option<Arc<crate::proxy::deferred_log::DeferredTransactionLogger>> =
        if !plugins.is_empty() {
            let summary = TransactionSummary {
                namespace: proxy.namespace.clone(),
                timestamp_received: ctx.timestamp_received.to_rfc3339(),
                client_ip: ctx.client_ip.clone(),
                consumer_username: ctx.effective_identity().map(str::to_owned),
                http_method: method,
                request_path: path,
                matched_proxy_id: Some(proxy.id.clone()),
                matched_proxy_name: proxy.name.clone(),
                backend_target_url: Some(strip_query_params(&backend_url).to_string()),
                backend_resolved_ip,
                response_status_code: response_status,
                latency_total_ms: total_ms,
                latency_gateway_processing_ms: gateway_processing_ms,
                latency_backend_ttfb_ms: backend_ttfb_ms,
                latency_backend_total_ms: backend_total_ms,
                latency_plugin_execution_ms: plugin_execution_ms,
                latency_plugin_external_io_ms: plugin_external_io_ms,
                latency_gateway_overhead_ms: gateway_overhead_ms,
                request_user_agent: ctx.headers.get("user-agent").cloned(),
                response_streamed: is_streaming_response,
                client_disconnected: false,
                error_class: backend_error_class,
                body_error_class: None,
                body_completed: false,
                bytes_streamed_to_client: 0,
                mirror: false,
                metadata: ctx.metadata.clone(),
            };

            let body_will_stream = matches!(
                &response_body,
                ResponseBody::Streaming(_)
                    | ResponseBody::StreamingH2(_)
                    | ResponseBody::StreamingH3(_)
            );
            if body_will_stream {
                Some(crate::proxy::deferred_log::DeferredTransactionLogger::new(
                    summary,
                    Arc::clone(&plugins),
                    Arc::new(ctx.clone()),
                ))
            } else {
                crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;
                None
            }
        } else {
            None
        };

    // Inject sticky session cookie when cookie-based consistent hashing selected a new session
    if sticky_cookie_needed
        && let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, &upstream_target)
    {
        let strategy = state.load_balancer_cache.get_hash_on_strategy(upstream_id);
        if let HashOnStrategy::Cookie(ref cookie_name) = strategy {
            let upstream = state.load_balancer_cache.get_upstream(upstream_id);
            let default_cc = crate::config::types::HashOnCookieConfig::default();
            let cookie_config = upstream
                .as_ref()
                .and_then(|u| u.hash_on_cookie_config.as_ref())
                .unwrap_or(&default_cc);
            let cookie_val = build_sticky_cookie_header(cookie_name, target, cookie_config);
            // Append to existing set-cookie or create new entry (newline-separated)
            response_headers
                .entry("set-cookie".to_string())
                .and_modify(|v| {
                    v.push('\n');
                    v.push_str(&cookie_val);
                })
                .or_insert(cookie_val);
        }
    }

    record_request(&state, response_status);

    // Build final response
    let mut resp_builder = Response::builder()
        .status(StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY));

    for (k, v) in &response_headers {
        if k == "set-cookie" {
            // Set-Cookie values were stored newline-separated to avoid RFC-violating
            // comma folding. Emit each value as a separate header line.
            for cookie_val in v.split('\n') {
                if let Ok(val) = hyper::header::HeaderValue::from_str(cookie_val) {
                    resp_builder = resp_builder.header("set-cookie", val);
                }
            }
        } else if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) {
            resp_builder = resp_builder.header(name, val);
        }
    }

    // Add gateway error categorization headers so clients and ops teams
    // can distinguish different failure modes:
    //   X-Gateway-Error: connection_failure | backend_timeout | backend_error
    //   X-Gateway-Upstream-Status: degraded (when routing via all-unhealthy fallback)
    if backend_resp.connection_error {
        resp_builder = resp_builder.header("X-Gateway-Error", "connection_failure");
    } else if response_status == 504 {
        resp_builder = resp_builder.header("X-Gateway-Error", "backend_timeout");
    } else if response_status >= 500 {
        resp_builder = resp_builder.header("X-Gateway-Error", "backend_error");
    }

    if upstream_is_fallback {
        resp_builder = resp_builder.header("X-Gateway-Upstream-Status", "degraded");
    }

    // Advertise HTTP/3 availability via pre-computed Alt-Svc header
    if let Some(ref alt_svc) = state.alt_svc_header {
        resp_builder = resp_builder.header("alt-svc", alt_svc.as_str());
    }

    // During shutdown drain or overload pressure, tell HTTP/1.1 clients to
    // close after this response instead of reusing the connection. This
    // naturally frees connection slots for new clients (overload) or allows
    // the process to exit cleanly (drain).
    // RED adaptive shedding: between pressure and critical thresholds,
    // Connection: close is applied probabilistically (linear ramp from 0%
    // to 100%) rather than all-or-nothing. This smooths tail latency by
    // gradually shedding keepalive connections as load increases.
    // Cost: draining check is one AtomicBool::load(Relaxed) ~1ns;
    // RED check is one AtomicU32::load + one AtomicU64::load + one multiply ~3ns.
    if state
        .overload
        .draining
        .load(std::sync::atomic::Ordering::Relaxed)
        || state.overload.should_disable_keepalive_red()
    {
        resp_builder = resp_builder.header("connection", "close");
    }

    // Via header on response path (RFC 9110 §7.6.3)
    if let Some(ref via) = state.via_header_http11 {
        resp_builder = resp_builder.header("via", via.as_str());
    }

    // Build response body: either stream from backend or return buffered data.
    // When FERRUM_ENABLE_STREAMING_LATENCY_TRACKING=true, streaming responses are
    // wrapped with a TrackedBody that records the final transfer time via a shared
    // atomic. A deferred task reads it after read_timeout + 5s to emit a
    // supplementary log with accurate backend_total_ms.
    // Default (false): streaming responses pass through with zero tracking overhead.
    let body = match response_body {
        ResponseBody::Streaming(resp) if state.env_config.enable_streaming_latency_tracking => {
            let cl = response_headers
                .get("content-length")
                .and_then(|v| v.parse::<u64>().ok());
            // When size limits are configured and Content-Length is absent, apply
            // size-limited streaming before latency tracking to prevent unbounded
            // transfer for chunked/unknown-length responses.
            let (tracked_body, metrics) = if state.max_response_body_size_bytes > 0 && cl.is_none()
            {
                ProxyBody::streaming_tracked_with_size_limit(
                    resp,
                    backend_start,
                    state.max_response_body_size_bytes,
                )
            } else {
                ProxyBody::streaming_tracked(resp, backend_start)
            };

            // Spawn a lightweight deferred task to log the final streaming latency.
            // Wakes once after read_timeout + 5s buffer, reads one atomic, emits one log line.
            let deferred_proxy_id = proxy.id.clone();
            let deferred_backend_url = strip_query_params(&backend_url).to_string();
            let read_timeout_ms = proxy.backend_read_timeout_ms;
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(read_timeout_ms + 5_000)).await;
                let completed = metrics.completed();
                let total_ms = metrics.last_frame_elapsed_ms().unwrap_or(-1.0);
                if completed {
                    debug!(
                        proxy_id = %deferred_proxy_id,
                        backend_url = %deferred_backend_url,
                        backend_total_ms = total_ms,
                        "Streaming response completed"
                    );
                } else {
                    warn!(
                        proxy_id = %deferred_proxy_id,
                        backend_url = %deferred_backend_url,
                        backend_last_frame_ms = total_ms,
                        "Streaming response incomplete (client disconnect or timeout)"
                    );
                }
            });

            tracked_body
        }
        ResponseBody::Streaming(resp) => {
            let cl = response_headers
                .get("content-length")
                .and_then(|v| v.parse::<u64>().ok());
            // Fast path: skip coalescing when no plugins need body buffering,
            // no size limits apply, and response buffer cutoff is disabled.
            // This eliminates per-frame BytesMut buffering and branch overhead.
            if state.response_buffer_cutoff_bytes == 0 && state.max_response_body_size_bytes == 0 {
                crate::proxy::body::direct_streaming_body(resp, cl)
            } else if state.max_response_body_size_bytes > 0 && cl.is_none() {
                // No Content-Length — enforce size limit while streaming instead
                // of buffering the entire body into memory.
                crate::proxy::body::size_limited_streaming_body(
                    resp,
                    state.max_response_body_size_bytes,
                    cl,
                )
            } else {
                crate::proxy::body::coalescing_body(resp, cl)
            }
        }
        ResponseBody::StreamingH2(resp) => {
            let cl = response_headers
                .get("content-length")
                .and_then(|v| v.parse::<u64>().ok());
            if state.response_buffer_cutoff_bytes == 0 && state.max_response_body_size_bytes == 0 {
                crate::proxy::body::direct_streaming_h2_body(resp.into_body(), cl)
            } else {
                crate::proxy::body::coalescing_h2_body(
                    resp.into_body(),
                    cl,
                    state.h2_coalesce_target_bytes,
                )
            }
        }
        ResponseBody::StreamingH3(h3_resp) => {
            let cl = response_headers
                .get("content-length")
                .and_then(|v| v.parse::<u64>().ok());
            if state.response_buffer_cutoff_bytes == 0 && state.max_response_body_size_bytes == 0 {
                crate::proxy::body::direct_streaming_h3_body(h3_resp.recv_stream, cl)
            } else {
                crate::proxy::body::coalescing_h3_body(
                    h3_resp.recv_stream,
                    cl,
                    state.h2_coalesce_target_bytes,
                )
            }
        }
        ResponseBody::Buffered(data) => ProxyBody::full(Bytes::from(data)),
    };

    // Attach deferred logger to the body so `log_with_mirror` fires when the
    // body reaches a terminal state (completion, streaming error, or client
    // disconnect via the Drop safety net) rather than at header-flush time.
    // `deferred_logger` is `Some` only for streaming responses with plugins.
    let body = if let Some(logger) = deferred_logger {
        body.with_logger(logger)
    } else {
        body
    };

    Ok(resp_builder
        .body(body)
        .unwrap_or_else(|_| Response::new(ProxyBody::from_string("Internal Server Error"))))
}

/// Build the backend URL based on proxy config and path forwarding logic.
pub fn build_backend_url(
    proxy: &Proxy,
    incoming_path: &str,
    query_string: &str,
    strip_len: usize,
) -> String {
    build_backend_url_with_target(
        proxy,
        incoming_path,
        query_string,
        &proxy.backend_host,
        proxy.backend_port,
        strip_len,
        None,
    )
}

/// Build backend URL using a specific host and port (for load-balanced targets).
///
/// `strip_len` is the number of bytes to strip from the start of `incoming_path`
/// when `proxy.strip_listen_path` is true. For prefix routes this equals
/// `proxy.listen_path.len()`; for regex routes it is the regex match length
/// (from `RouteMatch::matched_prefix_len`).
///
/// Uses a single `String` buffer to avoid intermediate allocations from
/// multiple `format!` calls.
pub fn build_backend_url_with_target(
    proxy: &Proxy,
    incoming_path: &str,
    query_string: &str,
    host: &str,
    port: u16,
    strip_len: usize,
    target_path: Option<&str>,
) -> String {
    use std::fmt::Write;

    let scheme = match proxy.backend_protocol {
        BackendProtocol::Http | BackendProtocol::Ws | BackendProtocol::Grpc => "http",
        BackendProtocol::Https
        | BackendProtocol::Wss
        | BackendProtocol::H3
        | BackendProtocol::Grpcs => "https",
        // Stream proxies (TCP/UDP) don't use HTTP URL building, but provide a sensible default
        BackendProtocol::Tcp | BackendProtocol::Udp => "http",
        BackendProtocol::TcpTls | BackendProtocol::Dtls => "https",
    };

    let remaining_path = if proxy.strip_listen_path {
        &incoming_path[strip_len.min(incoming_path.len())..]
    } else {
        incoming_path
    };

    let backend_path = target_path.or(proxy.backend_path.as_deref()).unwrap_or("");

    // Both empty means path is just "/"
    let path_is_root = backend_path.is_empty() && remaining_path.is_empty();

    // Determine if we need to prepend a '/' (when neither segment starts with one)
    let needs_leading_slash =
        !path_is_root && !backend_path.starts_with('/') && !remaining_path.starts_with('/');

    // Build URL in a single buffer, writing the path segments directly to avoid
    // an intermediate `full_path` String allocation from format!().
    let path_len = if path_is_root {
        1
    } else {
        (if needs_leading_slash { 1 } else { 0 }) + backend_path.len() + remaining_path.len()
    };
    let capacity = scheme.len()
        + 3
        + host.len()
        + 6
        + path_len
        + if query_string.is_empty() {
            0
        } else {
            1 + query_string.len()
        };
    let mut url = String::with_capacity(capacity);
    let _ = write!(url, "{}://{}:{}", scheme, host, port);

    if path_is_root {
        url.push('/');
    } else {
        if needs_leading_slash {
            url.push('/');
        }
        url.push_str(backend_path);
        url.push_str(remaining_path);
    }

    if !query_string.is_empty() {
        url.push('?');
        url.push_str(query_string);
    }

    url
}

/// Retry a backend request, replaying the original request body if available.
/// The body bytes were collected and retained on the first attempt so they
/// can be replayed on connection-failure retries without data loss.
#[allow(clippy::too_many_arguments)]
async fn proxy_to_backend_retry(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    upstream_target: Option<&UpstreamTarget>,
    request_body: Option<&[u8]>,
    stream_response: bool,
    client_ip: &str,
    is_tls: bool,
) -> retry::BackendResponse {
    // All reqwest clients use our DnsCacheResolver, so DNS resolution is
    // always served from the warmed cache — never hitting DNS on the hot path.
    // For both single-backend and load-balanced proxies, the client transparently
    // resolves hostnames through the DNS cache.
    let effective_host = upstream_target
        .map(|t| t.host.as_str())
        .unwrap_or(&proxy.backend_host);

    // Resolve backend IP from DNS cache (O(1) cached lookup).
    let resolved_ip = state
        .dns_cache
        .resolve(
            effective_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    let client = match state.connection_pool.get_client(proxy).await {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to get client from pool for retry: {}", e);
            return retry::BackendResponse {
                status_code: 502,
                body: ResponseBody::Buffered(
                    format!(r#"{{"error":"Backend unavailable: {}"}}"#, e).into_bytes(),
                ),
                headers: HashMap::new(),
                connection_error: true,
                backend_resolved_ip: resolved_ip.clone(),
                error_class: Some(retry::ErrorClass::ConnectionPoolError),
            };
        }
    };

    let req_method = match parse_reqwest_method(method) {
        Ok(m) => m,
        Err(()) => {
            warn!("Invalid HTTP method on retry: {}", method);
            return retry::BackendResponse {
                status_code: 405,
                body: ResponseBody::Buffered(
                    r#"{"error":"Method Not Allowed"}"#.as_bytes().to_vec(),
                ),
                headers: HashMap::new(),
                connection_error: false,
                backend_resolved_ip: resolved_ip.clone(),
                error_class: None,
            };
        }
    };

    let mut req_builder = client.request(req_method, backend_url);

    // Forward headers, stripping hop-by-hop headers per RFC 7230 Section 6.1
    for (k, v) in headers {
        match k.as_str() {
            "host" => {
                if proxy.preserve_host_header {
                    req_builder = req_builder.header("Host", v.as_str());
                } else {
                    // Use upstream target host when load balancing, so SNI-based
                    // ingress routers see the correct Host header for the target.
                    req_builder = req_builder.header("Host", effective_host);
                }
            }
            // Hop-by-hop headers per RFC 7230 Section 6.1
            "connection"
            | "content-length"
            | "transfer-encoding"
            | "keep-alive"
            | "te"
            | "trailer"
            | "proxy-authorization"
            | "proxy-connection"
            | "upgrade" => continue,
            _ => {
                req_builder = req_builder.header(k.as_str(), v.as_str());
            }
        }
    }

    // Add proxy headers with real client IP
    let xff_val = build_xff_value(
        headers.get("x-forwarded-for").map(|s| s.as_str()),
        client_ip,
    );
    let proto_str = if is_tls { "https" } else { "http" };
    req_builder = req_builder.header("X-Forwarded-For", xff_val);
    req_builder = req_builder.header("X-Forwarded-Proto", proto_str);
    if let Some(host) = headers.get("host") {
        req_builder = req_builder.header("X-Forwarded-Host", host.as_str());
    }
    if let Some(ref via) = state.via_header_http11 {
        req_builder = req_builder.header("Via", via.as_str());
    }
    if state.add_forwarded_header {
        req_builder = req_builder.header(
            "Forwarded",
            build_forwarded_value(
                client_ip,
                proto_str,
                headers.get("host").map(|s| s.as_str()),
            ),
        );
    }

    // Replay the original request body on retry if available.
    // On connection failures the body was never sent, so replaying is safe.
    if let Some(body) = request_body
        && !body.is_empty()
    {
        req_builder = req_builder.body(body.to_vec());
    }

    match req_builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let mut resp_headers = HashMap::with_capacity(response.headers().keys_len());
            collect_response_headers(response.headers(), &mut resp_headers);
            if stream_response {
                // Buffer small responses eagerly: a single `bytes().await`
                // allocation is cheaper than the async coalescing adapter for
                // typical JSON API payloads. Skip buffering for SSE (unbounded
                // streams) and responses without Content-Length (unknown size).
                let content_length = response
                    .headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<usize>().ok());
                let cutoff = state.response_buffer_cutoff_bytes;
                if cutoff > 0
                    && content_length.is_some_and(|cl| cl <= cutoff)
                    && !is_streaming_content_type(&resp_headers)
                {
                    match response.bytes().await {
                        Ok(b) => retry::BackendResponse {
                            status_code: status,
                            body: ResponseBody::Buffered(b.to_vec()),
                            headers: resp_headers,
                            connection_error: false,
                            backend_resolved_ip: resolved_ip.clone(),
                            error_class: None,
                        },
                        Err(e) => {
                            warn!("Failed to read backend response body: {}", e);
                            retry::BackendResponse {
                                status_code: 502,
                                body: ResponseBody::Buffered(
                                    r#"{"error":"Backend response body read failed"}"#
                                        .as_bytes()
                                        .to_vec(),
                                ),
                                headers: HashMap::new(),
                                connection_error: true,
                                backend_resolved_ip: resolved_ip.clone(),
                                error_class: Some(retry::ErrorClass::ConnectionReset),
                            }
                        }
                    }
                } else {
                    retry::BackendResponse {
                        status_code: status,
                        body: ResponseBody::Streaming(response),
                        headers: resp_headers,
                        connection_error: false,
                        backend_resolved_ip: resolved_ip.clone(),
                        error_class: None,
                    }
                }
            } else {
                let body = match response.bytes().await {
                    Ok(b) => b.to_vec(),
                    Err(e) => {
                        warn!("Failed to read backend response body: {}", e);
                        Vec::new()
                    }
                };
                retry::BackendResponse {
                    status_code: status,
                    body: ResponseBody::Buffered(body),
                    headers: resp_headers,
                    connection_error: false,
                    backend_resolved_ip: resolved_ip.clone(),
                    error_class: None,
                }
            }
        }
        Err(e) => {
            let is_connect = e.is_connect();
            let is_timeout = e.is_timeout();
            let error_kind = if is_connect {
                "connect_failure"
            } else if is_timeout {
                "read_timeout"
            } else {
                "request_error"
            };
            error!(
                proxy_id = %proxy.id,
                backend_url = %backend_url,
                error_kind = error_kind,
                error = %e,
                "Backend retry request failed"
            );
            let error_class = retry::classify_reqwest_error(&e);
            if error_class == retry::ErrorClass::PortExhaustion {
                state.overload.record_port_exhaustion();
            }
            let error_body = if error_class == retry::ErrorClass::DnsLookupError {
                r#"{"error":"DNS resolution for backend failed"}"#
            } else {
                r#"{"error":"Backend unavailable"}"#
            };
            retry::BackendResponse {
                status_code: 502,
                body: ResponseBody::Buffered(error_body.as_bytes().to_vec()),
                headers: HashMap::new(),
                connection_error: is_connect || is_timeout,
                backend_resolved_ip: resolved_ip.clone(),
                error_class: Some(error_class),
            }
        }
    }
}

/// Proxy the request to the backend.
#[allow(clippy::too_many_arguments)]
async fn proxy_to_backend(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    client_request_body: ClientRequestBody,
    upstream_target: Option<&UpstreamTarget>,
    #[allow(unused_variables)] plugins: &[Arc<dyn crate::plugins::Plugin>],
    stream_response: bool,
    requires_request_body_buffering: bool,
    stream_request_body: bool,
    retain_request_body: bool,
    client_ip: &str,
    is_tls: bool,
) -> (retry::BackendResponse, Option<Vec<u8>>) {
    // When retain_request_body is true (retries configured), the collected
    // body bytes are cloned and returned alongside the response so the
    // caller can replay them on connection-failure retries.
    let mut retained_body: Option<Vec<u8>> = None;

    // All reqwest clients use our DnsCacheResolver, so DNS resolution is
    // always served from the warmed cache — never hitting DNS on the hot path.
    // For both single-backend and load-balanced proxies, the client transparently
    // resolves hostnames through the DNS cache.
    let effective_host = upstream_target
        .map(|t| t.host.as_str())
        .unwrap_or(&proxy.backend_host);

    // Resolve backend IP from DNS cache (O(1) cached lookup, <1μs).
    // This is the same cache reqwest will use internally via DnsCacheResolver,
    // so the IP will match the actual connection target.
    let resolved_ip = state
        .dns_cache
        .resolve(
            effective_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    // Handle HTTP/3 backend requests — streaming when possible, buffered for retries.
    if matches!(proxy.backend_protocol, BackendProtocol::H3) {
        let (mut backend_resp, body_bytes) = proxy_to_backend_http3(
            state,
            proxy,
            backend_url,
            method,
            headers,
            client_request_body,
            plugins,
            upstream_target,
            client_ip,
            retain_request_body,
            stream_response,
        )
        .await;
        // For streaming H3 responses, move headers from the H3StreamingResponse
        // into the BackendResponse headers map (avoids cloning all key/value strings).
        if let ResponseBody::StreamingH3(ref mut h3_resp) = backend_resp.body {
            backend_resp.headers = std::mem::take(&mut h3_resp.headers);
        }
        // Merge resolved_ip into the response (h3 function resolves its own IP
        // but the outer resolved_ip is already computed from DNS cache above)
        let resp = retry::BackendResponse {
            backend_resolved_ip: resolved_ip.clone().or(backend_resp.backend_resolved_ip),
            ..backend_resp
        };
        return (resp, body_bytes);
    }

    // Use HTTP/2 multiplexing pool for HTTPS backends with H2 enabled,
    // but only when body retention is NOT required (i.e., no retries configured).
    // When retries are configured, we fall through to the reqwest path which
    // auto-negotiates HTTP/2 via ALPN on TLS and supports body replay natively.
    if matches!(proxy.backend_protocol, BackendProtocol::Https) {
        let pool_config = state.connection_pool.global_pool_config().for_proxy(proxy);
        if can_use_direct_http2_pool(
            pool_config.enable_http2,
            retain_request_body,
            requires_request_body_buffering,
        ) {
            let request = match client_request_body {
                ClientRequestBody::Streaming(request) => *request,
                ClientRequestBody::Buffered(_) => {
                    debug_assert!(
                        false,
                        "direct HTTP/2 pool should not be used when request body is pre-buffered"
                    );
                    return (
                        retry::BackendResponse {
                            status_code: 500,
                            body: ResponseBody::Buffered(
                                r#"{"error":"Request buffering invariant violated"}"#
                                    .as_bytes()
                                    .to_vec(),
                            ),
                            headers: HashMap::new(),
                            connection_error: false,
                            backend_resolved_ip: resolved_ip,
                            error_class: None,
                        },
                        None,
                    );
                }
            };
            return (
                proxy_to_backend_http2(
                    state,
                    proxy,
                    backend_url,
                    method,
                    headers,
                    request,
                    stream_response,
                    client_ip,
                    is_tls,
                    resolved_ip,
                )
                .await,
                None,
            );
        }
        if pool_config.enable_http2 && (retain_request_body || requires_request_body_buffering) {
            debug!(
                proxy_id = %proxy.id,
                retain_request_body = retain_request_body,
                requires_request_body_buffering = requires_request_body_buffering,
                "H2 pool bypassed for request buffering support — using reqwest (ALPN HTTP/2)"
            );
        }
    }

    // Get client from connection pool for HTTP/1.1 and HTTP/2.
    // The client uses our DnsCacheResolver for transparent DNS cache lookups.
    // All upstream targets share one reqwest::Client since it handles
    // per-host pooling and SNI internally.
    let client = match state.connection_pool.get_client(proxy).await {
        Ok(client) => client,
        Err(e) => {
            error!(
                proxy_id = %proxy.id,
                listen_path = %proxy.listen_path,
                "Connection pool client creation failed — refusing to proxy without proper TLS configuration: {}",
                e
            );
            return (
                retry::BackendResponse {
                    status_code: 502,
                    body: ResponseBody::Buffered(r#"{"error":"Bad Gateway"}"#.as_bytes().to_vec()),
                    headers: HashMap::new(),
                    connection_error: true,
                    backend_resolved_ip: resolved_ip.clone(),
                    error_class: Some(retry::ErrorClass::ConnectionPoolError),
                },
                None,
            );
        }
    };

    let req_method = match parse_reqwest_method(method) {
        Ok(m) => m,
        Err(()) => {
            warn!("Invalid HTTP method: {}", method);
            return (
                retry::BackendResponse {
                    status_code: 405,
                    body: ResponseBody::Buffered(
                        r#"{"error":"Method Not Allowed"}"#.as_bytes().to_vec(),
                    ),
                    headers: HashMap::new(),
                    connection_error: false,
                    backend_resolved_ip: resolved_ip.clone(),
                    error_class: None,
                },
                None,
            );
        }
    };

    let mut req_builder = client.request(req_method, backend_url);

    // Forward headers, stripping hop-by-hop headers per RFC 7230 Section 6.1
    for (k, v) in headers {
        match k.as_str() {
            "host" => {
                if proxy.preserve_host_header {
                    req_builder = req_builder.header("Host", v.as_str());
                } else {
                    // Use upstream target host when load balancing, so SNI-based
                    // ingress routers see the correct Host header for the target.
                    req_builder = req_builder.header("Host", effective_host);
                }
            }
            // Hop-by-hop headers per RFC 7230 Section 6.1
            "connection"
            | "content-length"
            | "transfer-encoding"
            | "keep-alive"
            | "te"
            | "trailer"
            | "proxy-authorization"
            | "proxy-connection"
            | "upgrade" => continue,
            _ => {
                req_builder = req_builder.header(k.as_str(), v.as_str());
            }
        }
    }

    // Add proxy headers
    let xff_val = build_xff_value(
        headers.get("x-forwarded-for").map(|s| s.as_str()),
        client_ip,
    );
    let proto_str = if is_tls { "https" } else { "http" };
    req_builder = req_builder.header("X-Forwarded-For", xff_val);
    req_builder = req_builder.header("X-Forwarded-Proto", proto_str);
    if let Some(host) = headers.get("host") {
        req_builder = req_builder.header("X-Forwarded-Host", host.as_str());
    }
    if let Some(ref via) = state.via_header_http11 {
        req_builder = req_builder.header("Via", via.as_str());
    }
    if state.add_forwarded_header {
        req_builder = req_builder.header(
            "Forwarded",
            build_forwarded_value(
                client_ip,
                proto_str,
                headers.get("host").map(|s| s.as_str()),
            ),
        );
    }

    let has_body = request_may_have_body(method, headers);

    // Shared flag for detecting size-limit exceeded during streaming.
    // Only allocated when we actually stream a request body.
    let body_size_exceeded = Arc::new(std::sync::atomic::AtomicBool::new(false));

    if has_body {
        // Enforce request body size limit via Content-Length fast path
        if state.max_request_body_size_bytes > 0
            && let Some(content_length) = headers.get("content-length")
            && let Ok(len) = content_length.parse::<usize>()
            && len > state.max_request_body_size_bytes
        {
            return (
                retry::BackendResponse {
                    status_code: 413,
                    body: ResponseBody::Buffered(
                        r#"{"error":"Request body exceeds maximum size"}"#.as_bytes().to_vec(),
                    ),
                    headers: HashMap::new(),
                    connection_error: false,
                    backend_resolved_ip: resolved_ip.clone(),
                    error_class: Some(retry::ErrorClass::RequestBodyTooLarge),
                },
                None,
            );
        }

        match client_request_body {
            ClientRequestBody::Buffered(body_bytes) => {
                let body_bytes = apply_request_body_plugins(plugins, headers, body_bytes).await;
                match run_final_request_body_hooks(plugins, headers, &body_bytes).await {
                    PluginResult::Continue => {}
                    reject @ PluginResult::Reject { .. }
                    | reject @ PluginResult::RejectBinary { .. } => {
                        return (
                            reject_result_to_backend_response(reject, resolved_ip.clone()),
                            None,
                        );
                    }
                }
                if !body_bytes.is_empty() {
                    if retain_request_body {
                        retained_body = Some(body_bytes.clone());
                    }
                    req_builder = req_builder.body(body_bytes);
                }
            }
            ClientRequestBody::Streaming(original_req) if stream_request_body => {
                // Stream the request body directly to the backend without collecting
                // into memory. Size limit is enforced during streaming via
                // SizeLimitedIncoming which sets body_size_exceeded on overflow.
                let incoming = (*original_req).into_body();
                if state.max_request_body_size_bytes > 0 {
                    let limited = body::SizeLimitedIncoming::new(
                        incoming,
                        state.max_request_body_size_bytes,
                        Arc::clone(&body_size_exceeded),
                    );
                    req_builder = req_builder.body(limited.into_reqwest_body());
                } else {
                    // No size limit — stream body directly, preserving size_hint
                    // for Content-Length forwarding (avoids chunked encoding overhead)
                    req_builder =
                        req_builder.body(reqwest::Body::wrap(body::SyncBody::new(incoming)));
                }
            }
            ClientRequestBody::Streaming(original_req) => {
                // Buffered path: collect body into memory for plugin transformation.
                let body_bytes = if state.max_request_body_size_bytes > 0 {
                    let limited = http_body_util::Limited::new(
                        (*original_req).into_body(),
                        state.max_request_body_size_bytes,
                    );
                    match limited.collect().await {
                        Ok(collected) => collected.to_bytes().to_vec(),
                        Err(_) => {
                            return (
                                retry::BackendResponse {
                                    status_code: 413,
                                    body:
                                        ResponseBody::Buffered(
                                            r#"{"error":"Request body exceeds maximum size"}"#
                                                .as_bytes()
                                                .to_vec(),
                                        ),
                                    headers: HashMap::new(),
                                    connection_error: false,
                                    backend_resolved_ip: resolved_ip.clone(),
                                    error_class: Some(retry::ErrorClass::RequestBodyTooLarge),
                                },
                                None,
                            );
                        }
                    }
                } else {
                    match (*original_req).into_body().collect().await {
                        Ok(collected) => collected.to_bytes().to_vec(),
                        Err(e) => {
                            error!(
                                proxy_id = %proxy.id,
                                backend_url = %backend_url,
                                error_kind = "client_disconnect",
                                error = %e,
                                "Client disconnected while sending request body"
                            );
                            return (
                                retry::BackendResponse {
                                    status_code: 499,
                                    body: ResponseBody::Buffered(
                                        r#"{"error":"Client disconnected"}"#.as_bytes().to_vec(),
                                    ),
                                    headers: HashMap::new(),
                                    connection_error: true,
                                    backend_resolved_ip: resolved_ip.clone(),
                                    error_class: Some(retry::ErrorClass::ClientDisconnect),
                                },
                                None,
                            );
                        }
                    }
                };

                // Transform request body via plugins (JSON field rename, add, remove, etc.)
                let body_bytes = apply_request_body_plugins(plugins, headers, body_bytes).await;
                match run_final_request_body_hooks(plugins, headers, &body_bytes).await {
                    PluginResult::Continue => {}
                    reject @ PluginResult::Reject { .. }
                    | reject @ PluginResult::RejectBinary { .. } => {
                        return (
                            reject_result_to_backend_response(reject, resolved_ip.clone()),
                            None,
                        );
                    }
                }

                if !body_bytes.is_empty() {
                    if retain_request_body {
                        retained_body = Some(body_bytes.clone());
                    }
                    req_builder = req_builder.body(body_bytes);
                }
            }
        }
    }

    // Send
    let response = match req_builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let mut resp_headers = HashMap::with_capacity(response.headers().keys_len());
            collect_response_headers(response.headers(), &mut resp_headers);

            // Enforce response body size limit
            if state.max_response_body_size_bytes > 0 {
                // Fast path: check Content-Length header from backend
                let content_length = response
                    .headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<usize>().ok());

                if let Some(len) = content_length
                    && len > state.max_response_body_size_bytes
                {
                    warn!(
                        "Backend response body ({} bytes) exceeds limit ({} bytes)",
                        len, state.max_response_body_size_bytes
                    );
                    return (
                        retry::BackendResponse {
                            status_code: 502,
                            body: ResponseBody::Buffered(
                                r#"{"error":"Backend response body exceeds maximum size"}"#
                                    .as_bytes()
                                    .to_vec(),
                            ),
                            headers: HashMap::new(),
                            connection_error: false,
                            backend_resolved_ip: resolved_ip.clone(),
                            error_class: Some(retry::ErrorClass::ResponseBodyTooLarge),
                        },
                        retained_body,
                    );
                }

                // When streaming is requested and Content-Length is present and within
                // limits, we can stream. Buffer small bodies eagerly (cheaper than
                // async coalescing). Skip buffering for SSE (unbounded streams).
                if stream_response && content_length.is_some() {
                    let cutoff = state.response_buffer_cutoff_bytes;
                    if cutoff > 0
                        && content_length.is_some_and(|cl| cl <= cutoff)
                        && !is_streaming_content_type(&resp_headers)
                    {
                        let body = match response.bytes().await {
                            Ok(b) => b.to_vec(),
                            Err(e) => {
                                warn!("Failed to read backend response body: {}", e);
                                Vec::new()
                            }
                        };
                        return (
                            retry::BackendResponse {
                                status_code: status,
                                body: ResponseBody::Buffered(body),
                                headers: resp_headers,
                                connection_error: false,
                                backend_resolved_ip: resolved_ip.clone(),
                                error_class: None,
                            },
                            retained_body,
                        );
                    }
                    return (
                        retry::BackendResponse {
                            status_code: status,
                            body: ResponseBody::Streaming(response),
                            headers: resp_headers,
                            connection_error: false,
                            backend_resolved_ip: resolved_ip.clone(),
                            error_class: None,
                        },
                        retained_body,
                    );
                }

                // No Content-Length — stream with coalescing. The response size
                // limit is still enforced via the `SizeLimitedStreamingResponse`
                // adapter applied at the response body builder stage.
                if stream_response {
                    return (
                        retry::BackendResponse {
                            status_code: status,
                            body: ResponseBody::Streaming(response),
                            headers: resp_headers,
                            connection_error: false,
                            backend_resolved_ip: resolved_ip.clone(),
                            error_class: None,
                        },
                        retained_body,
                    );
                }

                // Buffered mode: stream-collect with size limit
                let max_size = state.max_response_body_size_bytes;
                match collect_response_with_limit(response, max_size).await {
                    Ok((resp_body, _)) => retry::BackendResponse {
                        status_code: status,
                        body: ResponseBody::Buffered(resp_body),
                        headers: resp_headers,
                        connection_error: false,
                        backend_resolved_ip: resolved_ip.clone(),
                        error_class: None,
                    },
                    Err(err_body) => retry::BackendResponse {
                        status_code: 502,
                        body: ResponseBody::Buffered(err_body),
                        headers: HashMap::new(),
                        connection_error: false,
                        backend_resolved_ip: resolved_ip.clone(),
                        error_class: Some(retry::ErrorClass::ResponseBodyTooLarge),
                    },
                }
            } else if stream_response {
                // No size limit — stream directly. Buffer small bodies eagerly
                // when Content-Length is known and below the cutoff (cheaper than
                // async coalescing). Skip buffering for SSE (unbounded streams).
                let content_length = response
                    .headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<usize>().ok());
                let cutoff = state.response_buffer_cutoff_bytes;
                if cutoff > 0
                    && content_length.is_some_and(|cl| cl <= cutoff)
                    && !is_streaming_content_type(&resp_headers)
                {
                    match response.bytes().await {
                        Ok(b) => retry::BackendResponse {
                            status_code: status,
                            body: ResponseBody::Buffered(b.to_vec()),
                            headers: resp_headers,
                            connection_error: false,
                            backend_resolved_ip: resolved_ip.clone(),
                            error_class: None,
                        },
                        Err(e) => {
                            warn!("Failed to read backend response body: {}", e);
                            retry::BackendResponse {
                                status_code: 502,
                                body: ResponseBody::Buffered(
                                    r#"{"error":"Backend response body read failed"}"#
                                        .as_bytes()
                                        .to_vec(),
                                ),
                                headers: HashMap::new(),
                                connection_error: true,
                                backend_resolved_ip: resolved_ip.clone(),
                                error_class: Some(retry::ErrorClass::ConnectionReset),
                            }
                        }
                    }
                } else {
                    retry::BackendResponse {
                        status_code: status,
                        body: ResponseBody::Streaming(response),
                        headers: resp_headers,
                        connection_error: false,
                        backend_resolved_ip: resolved_ip.clone(),
                        error_class: None,
                    }
                }
            } else {
                let body = match response.bytes().await {
                    Ok(b) => b.to_vec(),
                    Err(e) => {
                        warn!("Failed to read backend response body: {}", e);
                        Vec::new()
                    }
                };
                retry::BackendResponse {
                    status_code: status,
                    body: ResponseBody::Buffered(body),
                    headers: resp_headers,
                    connection_error: false,
                    backend_resolved_ip: resolved_ip.clone(),
                    error_class: None,
                }
            }
        }
        Err(e) => {
            // Check if the error was caused by the streaming body exceeding
            // the size limit. If so, return 413 instead of generic 502.
            if body_size_exceeded.load(Ordering::Acquire) {
                warn!(
                    proxy_id = %proxy.id,
                    backend_url = %backend_url,
                    max_body_size = state.max_request_body_size_bytes,
                    "Streaming request body exceeded maximum size"
                );
                return (
                    retry::BackendResponse {
                        status_code: 413,
                        body: ResponseBody::Buffered(
                            r#"{"error":"Request body exceeds maximum size"}"#.as_bytes().to_vec(),
                        ),
                        headers: HashMap::new(),
                        connection_error: false,
                        backend_resolved_ip: resolved_ip.clone(),
                        error_class: Some(retry::ErrorClass::RequestBodyTooLarge),
                    },
                    retained_body,
                );
            }

            let is_connect = e.is_connect();
            let is_timeout = e.is_timeout();
            let error_kind = if is_connect {
                "connect_failure"
            } else if is_timeout {
                "read_timeout"
            } else {
                "request_error"
            };
            error!(
                proxy_id = %proxy.id,
                backend_url = %backend_url,
                error_kind = error_kind,
                error = %e,
                "Backend request failed"
            );
            let error_class = retry::classify_reqwest_error(&e);
            if error_class == retry::ErrorClass::PortExhaustion {
                state.overload.record_port_exhaustion();
            }
            let error_body = if error_class == retry::ErrorClass::DnsLookupError {
                r#"{"error":"DNS resolution for backend failed"}"#
            } else {
                r#"{"error":"Backend unavailable"}"#
            };
            retry::BackendResponse {
                status_code: 502,
                body: ResponseBody::Buffered(error_body.as_bytes().to_vec()),
                headers: HashMap::new(),
                connection_error: is_connect || is_timeout,
                backend_resolved_ip: resolved_ip.clone(),
                error_class: Some(error_class),
            }
        }
    };

    (response, retained_body)
}

/// Returns `true` for response content types that represent inherently unbounded
/// or latency-sensitive streams and should never be eagerly buffered regardless
/// of Content-Length. Currently covers SSE (`text/event-stream`).
#[inline]
fn is_streaming_content_type(resp_headers: &HashMap<String, String>) -> bool {
    resp_headers.get("content-type").is_some_and(|ct| {
        ct.len() >= 17 && ct.as_bytes()[..17].eq_ignore_ascii_case(b"text/event-stream")
    })
}

/// Collect a response body with a size limit, returning Err with error body if exceeded.
async fn collect_response_with_limit(
    response: reqwest::Response,
    max_size: usize,
) -> Result<(Vec<u8>, usize), Vec<u8>> {
    use futures_util::StreamExt as _;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                if body.len() + chunk.len() > max_size {
                    warn!(
                        "Backend response truncated: exceeded {} byte limit",
                        max_size
                    );
                    return Err(r#"{"error":"Backend response body exceeds maximum size"}"#
                        .as_bytes()
                        .to_vec());
                }
                body.extend_from_slice(&chunk);
            }
            Err(e) => {
                error!("Error reading backend response: {}", e);
                return Err(r#"{"error":"Backend response read error"}"#.as_bytes().to_vec());
            }
        }
    }
    let len = body.len();
    Ok((body, len))
}

/// Build a `Set-Cookie` header value for sticky session cookie injection.
pub(crate) fn build_sticky_cookie_header(
    cookie_name: &str,
    target: &UpstreamTarget,
    config: &crate::config::types::HashOnCookieConfig,
) -> String {
    use crate::load_balancer::target_host_port_key;
    let value = target_host_port_key(target);
    let mut cookie = format!(
        "{}={}; Path={}; Max-Age={}",
        cookie_name, value, config.path, config.ttl_seconds
    );
    if config.http_only {
        cookie.push_str("; HttpOnly");
    }
    if config.secure {
        cookie.push_str("; Secure");
    }
    if let Some(ref domain) = config.domain {
        cookie.push_str("; Domain=");
        cookie.push_str(domain);
    }
    if let Some(ref same_site) = config.same_site {
        cookie.push_str("; SameSite=");
        cookie.push_str(same_site);
    }
    cookie
}

fn strip_query_params(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

fn record_status(state: &ProxyState, status: u16) {
    // Fast path: get() uses a read lock (shared), which is much cheaper than
    // entry() which always takes a write lock. Since status codes are a small
    // fixed set, the entry almost always exists after the first request.
    if let Some(counter) = state.status_counts.get(&status) {
        counter.fetch_add(1, Ordering::Relaxed);
    } else if state.status_counts.len() < state.env_config.status_counts_max_entries {
        // Only insert new status codes if under the cap. Prevents unbounded
        // growth from adversarial backends returning many distinct codes.
        state
            .status_counts
            .entry(status)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }
    // else: silently drop — rare status code and map is at capacity
}

fn record_request(state: &ProxyState, status: u16) {
    state.request_count.fetch_add(1, Ordering::Relaxed);
    record_status(state, status);
}

/// Collect backend response headers into a HashMap.
///
/// RFC 7230 Section 3.2.2 allows folding multi-valued headers with commas,
/// **except** `Set-Cookie` (RFC 6265) which must be emitted as separate header
/// lines. We store multiple Set-Cookie values separated by `\n` so they can be
/// split back into individual headers when building the downstream response.
fn collect_response_headers(
    source: &reqwest::header::HeaderMap,
    target: &mut HashMap<String, String>,
) {
    target.reserve(source.keys_len());
    for (k, v) in source {
        // Strip hop-by-hop headers from backend responses per RFC 9110 §7.6.1.
        // Uses match (compiler-optimized) instead of linear array scan.
        match k.as_str() {
            "connection" | "keep-alive" | "proxy-authenticate" | "proxy-connection" | "te"
            | "trailer" | "transfer-encoding" | "upgrade" => continue,
            _ => {}
        }
        if let Ok(vs) = v.to_str() {
            // Determine multi-value separator before allocating the key String.
            // HeaderName comparison is zero-cost (pointer/length check on
            // pre-interned names), saving a String allocation when the header
            // already exists in the target map.
            let sep = if k == "set-cookie" { "\n" } else { ", " };
            match target.get_mut(k.as_str()) {
                Some(existing) => {
                    existing.push_str(sep);
                    existing.push_str(vs);
                }
                None => {
                    target.insert(k.as_str().to_owned(), vs.to_owned());
                }
            }
        }
    }
}

/// Collect hyper response headers into a HashMap.
///
/// Same semantics as `collect_response_headers` (Set-Cookie newline separation,
/// comma folding for other headers) but for `hyper::HeaderMap` instead of
/// `reqwest::header::HeaderMap`. Used by the HTTP/2 multiplexing pool path.
fn collect_hyper_response_headers(source: &hyper::HeaderMap, target: &mut HashMap<String, String>) {
    target.reserve(source.keys_len());
    for (k, v) in source {
        // Strip hop-by-hop headers from backend responses per RFC 9110 §7.6.1.
        match k.as_str() {
            "connection" | "keep-alive" | "proxy-authenticate" | "proxy-connection" | "te"
            | "trailer" | "transfer-encoding" | "upgrade" => continue,
            _ => {}
        }
        if let Ok(vs) = v.to_str() {
            let sep = if k == "set-cookie" { "\n" } else { ", " };
            match target.get_mut(k.as_str()) {
                Some(existing) => {
                    existing.push_str(sep);
                    existing.push_str(vs);
                }
                None => {
                    target.insert(k.as_str().to_owned(), vs.to_owned());
                }
            }
        }
    }
}

/// Trim optional whitespace (OWS: SP / HTAB) from both ends of a byte slice.
/// Used for parsing comma-separated header field values per RFC 9110 §5.6.1.
fn trim_ows(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// Validate protocol-level header constraints to block smuggling and desync attacks.
///
/// Returns an error message string if the request violates protocol rules, `None` if valid.
///
/// Checks performed (all run before routing — these are transport-level violations):
///
/// 1. **Content-Length + Transfer-Encoding conflict** (HTTP/1.x only): RFC 9112 §6.1
///    mandates that a proxy MUST reject or fix messages with both headers. Attackers
///    exploit CL/TE or TE/CL parsing disagreements between proxies and backends to
///    smuggle requests across connection boundaries.
///
/// 2. **Multiple Content-Length with mismatched values** (all HTTP versions): RFC 9110 §8.6
///    — different CL values in the same message indicate tampering or a broken intermediary.
///
/// 3. **Multiple Host headers** (HTTP/1.1 only): RFC 9112 §3.2 — a request with
///    duplicate Host headers MUST be rejected with 400 to prevent host-header routing
///    confusion between the proxy and backend.
///
/// 4. **TE header validation** (HTTP/2 only): RFC 9113 §8.2.2 — the only permitted
///    value is "trailers"; any other value is a protocol violation that could be used
///    to confuse HTTP/2-unaware intermediaries.
pub fn check_protocol_headers(
    headers: &hyper::HeaderMap,
    version: hyper::Version,
) -> Option<&'static str> {
    let is_http1 = version == hyper::Version::HTTP_10 || version == hyper::Version::HTTP_11;

    // 1a. HTTP/1.0 must not use Transfer-Encoding (RFC 9112 §6.2 — HTTP/1.0 has no chunked encoding)
    if version == hyper::Version::HTTP_10 && headers.contains_key("transfer-encoding") {
        return Some(r#"{"error":"HTTP/1.0 does not support Transfer-Encoding"}"#);
    }

    // 1b. Content-Length + Transfer-Encoding conflict (HTTP/1.x request smuggling)
    // HTTP/2 and HTTP/3 don't use Transfer-Encoding (framing is at the protocol layer).
    if is_http1
        && headers.contains_key("transfer-encoding")
        && headers.contains_key("content-length")
    {
        return Some(
            r#"{"error":"Request contains both Content-Length and Transfer-Encoding headers"}"#,
        );
    }

    // 2. Content-Length validation (all HTTP versions)
    // a) Each token must be ASCII digits only (RFC 9110 §8.6 — non-negative integer).
    //    Rejecting signs, decimals, hex prefixes, and garbage prevents parsing
    //    disagreements between the proxy and backend about message boundaries.
    // b) An intermediary may coalesce duplicate CL headers into a single comma-separated
    //    field line (e.g. "Content-Length: 42, 0"). We must split on commas, trim OWS,
    //    and reject if any parsed value differs — otherwise a smuggling variant that
    //    relies on coalesced CL values can bypass the guard.
    {
        let mut canonical: Option<&[u8]> = None;
        for val in headers.get_all("content-length") {
            for token in val.as_bytes().split(|&b| b == b',') {
                let trimmed = trim_ows(token);
                if trimmed.is_empty() {
                    continue;
                }
                // 2a. Must be ASCII digits only (no signs, decimals, hex, or garbage)
                if !trimmed.iter().all(|&b| b.is_ascii_digit()) {
                    return Some(
                        r#"{"error":"Content-Length header contains invalid non-numeric value"}"#,
                    );
                }
                // 2b. All tokens must agree on the same value
                match canonical {
                    None => canonical = Some(trimmed),
                    Some(prev) if prev != trimmed => {
                        return Some(
                            r#"{"error":"Multiple Content-Length headers with conflicting values"}"#,
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    // 3. Multiple Host headers (HTTP/1.1 only)
    // HTTP/2 and HTTP/3 use the :authority pseudo-header (exposed via URI), not Host.
    if is_http1 {
        let mut host_iter = headers.get_all("host").iter();
        if host_iter.next().is_some() && host_iter.next().is_some() {
            return Some(r#"{"error":"Request contains multiple Host headers"}"#);
        }
    }

    // 4. TE header in HTTP/2 and HTTP/3 must be "trailers" only
    // (RFC 9113 §8.2.2 for HTTP/2, RFC 9114 §4.2 for HTTP/3).
    // Iterate all TE header entries and comma-separated tokens within each entry.
    // A request with `te: trailers` plus a second `te: gzip` entry (or a single
    // `te: trailers, gzip` field) must be rejected.
    if version == hyper::Version::HTTP_2 || version == hyper::Version::HTTP_3 {
        for te_val in headers.get_all("te") {
            if let Ok(te_str) = te_val.to_str() {
                for token in te_str.split(',') {
                    let trimmed = token.trim();
                    if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("trailers") {
                        return Some(r#"{"error":"TE header must be 'trailers' or absent"}"#);
                    }
                }
            }
        }
    }

    None
}

fn build_response(status: StatusCode, body: &str) -> Response<ProxyBody> {
    // Response::builder with a valid status and static header name cannot fail
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(ProxyBody::from_string(body))
        .unwrap_or_else(|_| {
            Response::new(ProxyBody::from_string(
                r#"{"error":"Internal server error"}"#,
            ))
        })
}

/// Proxy the request to an HTTPS backend using the HTTP/2 multiplexing pool.
///
/// Uses hyper's HTTP/2 client directly to multiplex concurrent requests over
/// a single persistent TLS connection, avoiding reqwest's connection-per-burst behavior.
#[allow(clippy::too_many_arguments)]
async fn proxy_to_backend_http2(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    original_req: Request<Incoming>,
    stream_response: bool,
    client_ip: &str,
    is_tls: bool,
    resolved_ip: Option<String>,
) -> retry::BackendResponse {
    debug!(proxy_id = %proxy.id, backend_url = %backend_url, "Proxying request via HTTP/2 pool");

    // Get or create HTTP/2 connection to backend.
    // The pool returns a ready() sender with stream capacity, evicting closed
    // connections and spreading load across shards automatically.
    let mut sender = match state.http2_pool.get_sender(proxy, &state.dns_cache).await {
        Ok(s) => s,
        Err(e) => {
            let msg = match &e {
                http2_pool::Http2PoolError::BackendTimeout(m) => m.clone(),
                http2_pool::Http2PoolError::BackendUnavailable(m) => m.clone(),
                http2_pool::Http2PoolError::Internal(m) => m.clone(),
            };
            // Classify the H2 pool error for accurate error_class reporting.
            // Uses the shared classifier so updates to the taxonomy apply uniformly
            // instead of scattering ad-hoc substring checks across call sites.
            let h2_error_class = http2_pool::classify_http2_pool_error(&e);
            if matches!(h2_error_class, retry::ErrorClass::PortExhaustion) {
                state.overload.record_port_exhaustion();
            }
            let error_body = if h2_error_class == retry::ErrorClass::DnsLookupError {
                r#"{"error":"DNS resolution for backend failed"}"#.to_string()
            } else {
                format!(r#"{{"error":"Backend unavailable: {}"}}"#, msg)
            };
            error!(proxy_id = %proxy.id, error = %msg, "HTTP/2 pool connection failed");
            return retry::BackendResponse {
                status_code: 502,
                body: ResponseBody::Buffered(error_body.into_bytes()),
                headers: HashMap::new(),
                connection_error: true,
                backend_resolved_ip: resolved_ip,
                error_class: Some(h2_error_class),
            };
        }
    };

    // Parse the backend URL
    let uri: hyper::Uri = match backend_url.parse() {
        Ok(u) => u,
        Err(e) => {
            error!(proxy_id = %proxy.id, error = %e, "Invalid backend URL");
            return retry::BackendResponse {
                status_code: 502,
                body: ResponseBody::Buffered(
                    r#"{"error":"Invalid backend URL"}"#.as_bytes().to_vec(),
                ),
                headers: HashMap::new(),
                connection_error: false,
                backend_resolved_ip: resolved_ip,
                error_class: None,
            };
        }
    };

    // Build hyper request
    let (mut parts, body) = original_req.into_parts();

    // Set the URI
    parts.uri = uri;

    // Set the method
    parts.method = match parse_hyper_method(method) {
        Ok(m) => m,
        Err(()) => {
            return retry::BackendResponse {
                status_code: 405,
                body: ResponseBody::Buffered(
                    r#"{"error":"Method Not Allowed"}"#.as_bytes().to_vec(),
                ),
                headers: HashMap::new(),
                connection_error: false,
                backend_resolved_ip: resolved_ip,
                error_class: None,
            };
        }
    };

    // Clear and rebuild headers from the plugin-processed headers map
    parts.headers.clear();
    let effective_host = &proxy.backend_host;
    for (k, v) in headers {
        match k.as_str() {
            "host" => {
                if proxy.preserve_host_header {
                    if let Ok(val) = hyper::header::HeaderValue::from_str(v) {
                        parts.headers.insert(hyper::header::HOST, val);
                    }
                } else if let Ok(val) = hyper::header::HeaderValue::from_str(effective_host) {
                    parts.headers.insert(hyper::header::HOST, val);
                }
            }
            // Hop-by-hop headers per RFC 7230 Section 6.1
            "connection"
            | "transfer-encoding"
            | "keep-alive"
            | "te"
            | "trailer"
            | "proxy-authorization"
            | "proxy-connection"
            | "upgrade" => continue,
            _ => {
                if let (Ok(name), Ok(val)) = (
                    hyper::header::HeaderName::from_bytes(k.as_bytes()),
                    hyper::header::HeaderValue::from_str(v),
                ) {
                    parts.headers.insert(name, val);
                }
            }
        }
    }

    // Add proxy headers
    let xff_val = build_xff_value(
        headers.get("x-forwarded-for").map(|s| s.as_str()),
        client_ip,
    );
    if let Ok(val) = hyper::header::HeaderValue::from_str(&xff_val) {
        parts.headers.insert("x-forwarded-for", val);
    }
    if let Ok(val) = hyper::header::HeaderValue::from_str(if is_tls { "https" } else { "http" }) {
        parts.headers.insert("x-forwarded-proto", val);
    }
    if let Some(host) = headers.get("host")
        && let Ok(val) = hyper::header::HeaderValue::from_str(host)
    {
        parts.headers.insert("x-forwarded-host", val);
    }
    if let Some(ref via) = state.via_header_http2
        && let Ok(val) = hyper::header::HeaderValue::from_str(via)
    {
        parts.headers.insert("via", val);
    }
    if state.add_forwarded_header {
        let proto_str = if is_tls { "https" } else { "http" };
        let fwd = build_forwarded_value(
            client_ip,
            proto_str,
            headers.get("host").map(|s| s.as_str()),
        );
        if let Ok(val) = hyper::header::HeaderValue::from_str(&fwd) {
            parts.headers.insert("forwarded", val);
        }
    }

    let backend_req = Request::from_parts(parts, body);

    // Send to backend with read timeout
    let read_timeout = Duration::from_millis(proxy.backend_read_timeout_ms);
    let response = match tokio::time::timeout(read_timeout, sender.send_request(backend_req)).await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            error!(proxy_id = %proxy.id, error = %e, "HTTP/2 backend request failed");
            return retry::BackendResponse {
                status_code: 502,
                body: ResponseBody::Buffered(
                    r#"{"error":"Backend unavailable"}"#.as_bytes().to_vec(),
                ),
                headers: HashMap::new(),
                connection_error: true,
                backend_resolved_ip: resolved_ip,
                error_class: Some(retry::ErrorClass::ProtocolError),
            };
        }
        Err(_) => {
            warn!(
                proxy_id = %proxy.id,
                "HTTP/2: read timeout ({}ms) waiting for backend response",
                proxy.backend_read_timeout_ms
            );
            return retry::BackendResponse {
                status_code: 504,
                body: ResponseBody::Buffered(r#"{"error":"Backend timeout"}"#.as_bytes().to_vec()),
                headers: HashMap::new(),
                connection_error: true,
                backend_resolved_ip: resolved_ip,
                error_class: Some(retry::ErrorClass::ReadWriteTimeout),
            };
        }
    };

    // Extract response status and headers
    let status = response.status().as_u16();
    let mut resp_headers = HashMap::with_capacity(response.headers().keys_len());
    collect_hyper_response_headers(response.headers(), &mut resp_headers);

    if stream_response {
        retry::BackendResponse {
            status_code: status,
            body: ResponseBody::StreamingH2(response),
            headers: resp_headers,
            connection_error: false,
            backend_resolved_ip: resolved_ip,
            error_class: None,
        }
    } else {
        // Buffer the full response body
        let body_bytes = match response.into_body().collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(e) => {
                error!(proxy_id = %proxy.id, error = %e, "Failed to read HTTP/2 response body");
                return retry::BackendResponse {
                    status_code: 502,
                    body: ResponseBody::Buffered(
                        r#"{"error":"Failed to read backend response"}"#.as_bytes().to_vec(),
                    ),
                    headers: HashMap::new(),
                    connection_error: false,
                    backend_resolved_ip: resolved_ip,
                    error_class: Some(retry::ErrorClass::ProtocolError),
                };
            }
        };
        retry::BackendResponse {
            status_code: status,
            body: ResponseBody::Buffered(body_bytes),
            headers: resp_headers,
            connection_error: false,
            backend_resolved_ip: resolved_ip,
            error_class: None,
        }
    }
}

/// Proxy the request to an HTTP/3 backend.
#[allow(clippy::too_many_arguments)]
async fn proxy_to_backend_http3(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    client_request_body: ClientRequestBody,
    plugins: &[Arc<dyn crate::plugins::Plugin>],
    upstream_target: Option<&UpstreamTarget>,
    client_ip: &str,
    retain_request_body: bool,
    stream_response: bool,
) -> (retry::BackendResponse, Option<Vec<u8>>) {
    debug!(proxy_id = %proxy.id, backend_url = %backend_url, "Proxying request to HTTP/3 backend");

    // Resolve backend IP from DNS cache for the effective host
    let effective_host = upstream_target
        .map(|t| t.host.as_str())
        .unwrap_or(&proxy.backend_host);
    let resolved_ip = state
        .dns_cache
        .resolve(
            effective_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    // Read request body with size limit. HTTP/3 is always buffered — the h3
    // crate requires the full body before sending the request.
    let request_body = match client_request_body {
        ClientRequestBody::Buffered(body) => body,
        ClientRequestBody::Streaming(original_req) => {
            let (_parts, body) = (*original_req).into_parts();
            if state.max_request_body_size_bytes > 0 {
                // Check Content-Length fast path
                if let Some(content_length) = headers.get("content-length")
                    && let Ok(len) = content_length.parse::<usize>()
                    && len > state.max_request_body_size_bytes
                {
                    return (
                        retry::BackendResponse {
                            status_code: 413,
                            body: ResponseBody::Buffered(
                                r#"{"error":"Request body exceeds maximum size"}"#
                                    .as_bytes()
                                    .to_vec(),
                            ),
                            headers: HashMap::new(),
                            connection_error: false,
                            backend_resolved_ip: resolved_ip,
                            error_class: Some(retry::ErrorClass::RequestBodyTooLarge),
                        },
                        None,
                    );
                }
                let limited = http_body_util::Limited::new(body, state.max_request_body_size_bytes);
                match limited.collect().await {
                    Ok(collected) => collected.to_bytes().to_vec(),
                    Err(_) => {
                        return (
                            retry::BackendResponse {
                                status_code: 413,
                                body: ResponseBody::Buffered(
                                    r#"{"error":"Request body exceeds maximum size"}"#
                                        .as_bytes()
                                        .to_vec(),
                                ),
                                headers: HashMap::new(),
                                connection_error: false,
                                backend_resolved_ip: resolved_ip,
                                error_class: Some(retry::ErrorClass::RequestBodyTooLarge),
                            },
                            None,
                        );
                    }
                }
            } else {
                match body.collect().await {
                    Ok(collected) => collected.to_bytes().to_vec(),
                    Err(e) => {
                        error!(
                            proxy_id = %proxy.id,
                            backend_url = %backend_url,
                            error_kind = "client_disconnect",
                            error = %e,
                            "Client disconnected while sending request body (HTTP/3)"
                        );
                        return (
                            retry::BackendResponse {
                                status_code: 499,
                                body: ResponseBody::Buffered(
                                    r#"{"error":"Client disconnected"}"#.as_bytes().to_vec(),
                                ),
                                headers: HashMap::new(),
                                connection_error: true,
                                backend_resolved_ip: resolved_ip,
                                error_class: Some(retry::ErrorClass::ClientDisconnect),
                            },
                            None,
                        );
                    }
                }
            }
        }
    };
    let request_body = apply_request_body_plugins(plugins, headers, request_body).await;
    match run_final_request_body_hooks(plugins, headers, &request_body).await {
        PluginResult::Continue => {}
        reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
            return (
                reject_result_to_backend_response(reject, resolved_ip.clone()),
                None,
            );
        }
    }

    // Retain the body for retries (always safe for H3 since we always buffer)
    let retained_body = if retain_request_body && !request_body.is_empty() {
        Some(request_body.clone())
    } else {
        None
    };

    // Convert headers to HTTP/3 format, stripping hop-by-hop headers per RFC 7230 §6.1
    let mut http3_headers: Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)> =
        Vec::new();
    for (name, value) in headers {
        match name.as_str() {
            "connection"
            | "content-length"
            | "transfer-encoding"
            | "keep-alive"
            | "te"
            | "trailer"
            | "proxy-authorization"
            | "proxy-connection"
            | "upgrade" => continue,
            _ => {
                if let (Ok(header_name), Ok(header_value)) = (name.parse(), value.parse()) {
                    http3_headers.push((header_name, header_value));
                } else {
                    debug!("Skipping invalid HTTP/3 header: {}={}", name, value);
                }
            }
        }
    }

    if !request_body.is_empty()
        && let Ok(content_length) = request_body.len().to_string().parse()
    {
        http3_headers.push((hyper::header::CONTENT_LENGTH, content_length));
    }

    // Add X-Forwarded-* headers (matching HTTP/1.1 and HTTP/2 paths)
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(v) = format!("{}, {}", xff, client_ip).parse() {
            http3_headers.push((hyper::header::HeaderName::from_static("x-forwarded-for"), v));
        }
    } else if let Ok(v) = client_ip.parse() {
        http3_headers.push((hyper::header::HeaderName::from_static("x-forwarded-for"), v));
    }
    if let Ok(v) = "https".parse() {
        http3_headers.push((
            hyper::header::HeaderName::from_static("x-forwarded-proto"),
            v,
        ));
    }
    if let Some(host) = headers.get("host")
        && let Ok(v) = host.parse()
    {
        http3_headers.push((
            hyper::header::HeaderName::from_static("x-forwarded-host"),
            v,
        ));
    }
    if let Some(ref via) = state.via_header_http3
        && let Ok(v) = via.parse()
    {
        http3_headers.push((hyper::header::HeaderName::from_static("via"), v));
    }
    if state.add_forwarded_header {
        let fwd =
            build_forwarded_value(client_ip, "https", headers.get("host").map(|s| s.as_str()));
        if let Ok(v) = fwd.parse() {
            http3_headers.push((hyper::header::HeaderName::from_static("forwarded"), v));
        }
    }

    // Make HTTP/3 request via connection pool (reuses QUIC connections).
    // When streaming is enabled, use request_streaming to avoid buffering
    // the entire response body in memory.
    let connection_pool = state.connection_pool.clone();
    let proxy_clone = proxy.clone();
    let body_bytes: bytes::Bytes = request_body.into();

    if stream_response {
        // Streaming path: return StreamingH3 with the recv_stream still open.
        // When an upstream target is specified, use target-aware pool keying.
        let h3_result = if let Some(target) = upstream_target {
            let target_host = target.host.clone();
            let target_port = target.port;
            state
                .h3_pool
                .request_with_target_streaming(
                    proxy,
                    &target_host,
                    target_port,
                    method,
                    backend_url,
                    &http3_headers,
                    body_bytes,
                    move || connection_pool.get_tls_config_for_backend(&proxy_clone),
                )
                .await
        } else {
            state
                .h3_pool
                .request_streaming(
                    proxy,
                    method,
                    backend_url,
                    &http3_headers,
                    body_bytes,
                    move || connection_pool.get_tls_config_for_backend(&proxy_clone),
                )
                .await
        };

        match h3_result {
            Ok(response) => {
                debug!(proxy_id = %proxy.id, status = response.status, "HTTP/3 backend streaming request successful");
                (
                    retry::BackendResponse {
                        status_code: response.status,
                        body: ResponseBody::StreamingH3(Box::new(response)),
                        headers: HashMap::new(), // headers extracted by caller from StreamingH3
                        connection_error: false,
                        backend_resolved_ip: resolved_ip,
                        error_class: None,
                    },
                    retained_body,
                )
            }
            Err(e) => {
                let error_str = e.to_string();
                let (error_kind, is_conn_error, error_class) = classify_h3_error(&error_str);
                error!(
                    proxy_id = %proxy.id,
                    backend_url = %backend_url,
                    error_kind = error_kind,
                    error = %e,
                    "HTTP/3 backend streaming request failed"
                );
                (
                    retry::BackendResponse {
                        status_code: 502,
                        body: ResponseBody::Buffered(
                            r#"{"error":"HTTP/3 backend request failed"}"#.as_bytes().to_vec(),
                        ),
                        headers: HashMap::new(),
                        connection_error: is_conn_error,
                        backend_resolved_ip: resolved_ip,
                        error_class: Some(error_class),
                    },
                    retained_body,
                )
            }
        }
    } else {
        // Buffered path: collect entire response body
        let h3_result = if let Some(target) = upstream_target {
            let target_host = target.host.clone();
            let target_port = target.port;
            state
                .h3_pool
                .request_with_target(
                    proxy,
                    &target_host,
                    target_port,
                    method,
                    backend_url,
                    &http3_headers,
                    body_bytes,
                    move || connection_pool.get_tls_config_for_backend(&proxy_clone),
                )
                .await
        } else {
            state
                .h3_pool
                .request(
                    proxy,
                    method,
                    backend_url,
                    &http3_headers,
                    body_bytes,
                    move || connection_pool.get_tls_config_for_backend(&proxy_clone),
                )
                .await
        };

        match h3_result {
            Ok(response) => {
                debug!(proxy_id = %proxy.id, status = response.0, "HTTP/3 backend request successful");
                (
                    retry::BackendResponse {
                        status_code: response.0,
                        body: ResponseBody::Buffered(response.1),
                        headers: response.2,
                        connection_error: false,
                        backend_resolved_ip: resolved_ip,
                        error_class: None,
                    },
                    retained_body,
                )
            }
            Err(e) => {
                let error_str = e.to_string();
                let (error_kind, is_conn_error, error_class) = classify_h3_error(&error_str);
                error!(
                    proxy_id = %proxy.id,
                    backend_url = %backend_url,
                    error_kind = error_kind,
                    error = %e,
                    "HTTP/3 backend request failed"
                );
                (
                    retry::BackendResponse {
                        status_code: 502,
                        body: ResponseBody::Buffered(
                            r#"{"error":"HTTP/3 backend request failed"}"#.as_bytes().to_vec(),
                        ),
                        headers: HashMap::new(),
                        connection_error: is_conn_error,
                        backend_resolved_ip: resolved_ip,
                        error_class: Some(error_class),
                    },
                    retained_body,
                )
            }
        }
    }
}

/// Classify an HTTP/3/QUIC error string into (error_kind, is_connection_error, ErrorClass).
///
/// Called only on the error path — not hot path.
fn classify_h3_error(error_str: &str) -> (&'static str, bool, retry::ErrorClass) {
    let lower = error_str.to_lowercase();
    if lower.contains("dns") || lower.contains("resolve") || lower.contains("no record found") {
        ("dns_failure", true, retry::ErrorClass::DnsLookupError)
    } else if lower.contains("tls")
        || lower.contains("certificate")
        || lower.contains("ssl")
        || lower.contains("handshake")
        || lower.contains("invalid server name")
    {
        ("tls_error", true, retry::ErrorClass::TlsError)
    } else if lower.contains("timeout") || lower.contains("timed out") {
        if lower.contains("connect") {
            (
                "connect_timeout",
                true,
                retry::ErrorClass::ConnectionTimeout,
            )
        } else {
            ("read_timeout", false, retry::ErrorClass::ReadWriteTimeout)
        }
    } else if lower.contains("refused") {
        (
            "connect_failure",
            true,
            retry::ErrorClass::ConnectionRefused,
        )
    } else if lower.contains("quic connection failed")
        || lower.contains("connection reset")
        || lower.contains("reset")
    {
        ("connect_failure", true, retry::ErrorClass::ConnectionReset)
    } else if lower.contains("protocol")
        || lower.contains("goaway")
        || lower.contains("h3")
        || lower.contains("stream")
    {
        ("protocol_error", false, retry::ErrorClass::ProtocolError)
    } else {
        ("request_error", false, retry::ErrorClass::RequestError)
    }
}

/// Replay a saved HTTP/3 request to an explicit target (used during retries).
///
/// Accepts pre-collected body bytes, method, URI, and headers so the original
/// `Request<Incoming>` body (already consumed) can be replayed. Mirrors the
/// pattern used by `proxy_to_backend_retry` for HTTP/1.1.
#[allow(clippy::too_many_arguments)]
async fn proxy_to_backend_http3_retry(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    upstream_target: Option<&UpstreamTarget>,
    request_body: Option<&[u8]>,
    client_ip: &str,
    is_tls: bool,
) -> retry::BackendResponse {
    let effective_host = upstream_target
        .map(|t| t.host.as_str())
        .unwrap_or(&proxy.backend_host);
    let effective_port = upstream_target
        .map(|t| t.port)
        .unwrap_or(proxy.backend_port);

    let resolved_ip = state
        .dns_cache
        .resolve(
            effective_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    // Build HTTP/3 headers from the saved headers map
    let mut http3_headers: Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)> =
        Vec::new();
    for (name, value) in headers {
        match name.as_str() {
            "connection"
            | "transfer-encoding"
            | "keep-alive"
            | "te"
            | "trailer"
            | "proxy-authorization"
            | "proxy-connection"
            | "upgrade" => continue,
            "host" => {
                // Use effective upstream host unless preserve_host_header is set
                let host_value = if proxy.preserve_host_header {
                    value.as_str()
                } else {
                    effective_host
                };
                if let (Ok(hn), Ok(hv)) = (
                    "host".parse::<hyper::header::HeaderName>(),
                    host_value.parse::<hyper::header::HeaderValue>(),
                ) {
                    http3_headers.push((hn, hv));
                }
            }
            _ => {
                if let (Ok(hn), Ok(hv)) = (name.parse(), value.parse()) {
                    http3_headers.push((hn, hv));
                }
            }
        }
    }

    // X-Forwarded-* headers
    let xff_val = build_xff_value(
        headers.get("x-forwarded-for").map(|s| s.as_str()),
        client_ip,
    );
    if let Ok(v) = xff_val.parse() {
        http3_headers.push((hyper::header::HeaderName::from_static("x-forwarded-for"), v));
    }
    let proto = if is_tls { "https" } else { "http" };
    if let Ok(v) = proto.parse() {
        http3_headers.push((
            hyper::header::HeaderName::from_static("x-forwarded-proto"),
            v,
        ));
    }
    if let Some(host) = headers.get("host")
        && let Ok(v) = host.parse()
    {
        http3_headers.push((
            hyper::header::HeaderName::from_static("x-forwarded-host"),
            v,
        ));
    }

    let body_bytes = bytes::Bytes::copy_from_slice(request_body.unwrap_or(&[]));

    let connection_pool = state.connection_pool.clone();
    let proxy_clone = proxy.clone();
    let h3_result = if let Some(target) = upstream_target {
        let target_host = target.host.clone();
        let target_port = target.port;
        state
            .h3_pool
            .request_with_target(
                proxy,
                &target_host,
                target_port,
                method,
                backend_url,
                &http3_headers,
                body_bytes,
                move || connection_pool.get_tls_config_for_backend(&proxy_clone),
            )
            .await
    } else {
        state
            .h3_pool
            .request(
                proxy,
                method,
                backend_url,
                &http3_headers,
                body_bytes,
                move || connection_pool.get_tls_config_for_backend(&proxy_clone),
            )
            .await
    };

    match h3_result {
        Ok(response) => {
            debug!(
                proxy_id = %proxy.id,
                status = response.0,
                "HTTP/3 backend retry request successful"
            );
            retry::BackendResponse {
                status_code: response.0,
                body: ResponseBody::Buffered(response.1),
                headers: response.2,
                connection_error: false,
                backend_resolved_ip: resolved_ip,
                error_class: None,
            }
        }
        Err(e) => {
            let error_str = e.to_string();
            let (error_kind, is_conn_error, error_class) = classify_h3_error(&error_str);
            error!(
                proxy_id = %proxy.id,
                backend_url = %backend_url,
                target = %format!("{}:{}", effective_host, effective_port),
                error_kind = error_kind,
                error = %e,
                "HTTP/3 backend retry request failed"
            );
            retry::BackendResponse {
                status_code: 502,
                body: ResponseBody::Buffered(
                    r#"{"error":"HTTP/3 backend request failed"}"#.as_bytes().to_vec(),
                ),
                headers: HashMap::new(),
                connection_error: is_conn_error,
                backend_resolved_ip: resolved_ip,
                error_class: Some(error_class),
            }
        }
    }
}
