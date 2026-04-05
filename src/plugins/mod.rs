//! Plugin system — 45 built-in plugins with a trait-based architecture.
//!
//! Plugins execute in priority order (lower number = runs first) through
//! lifecycle phases: `on_request_received` → `authenticate` → `authorize` →
//! `before_proxy` → `transform_request_body` → `on_final_request_body` →
//! `after_proxy` → `on_response_body` → `transform_response_body` →
//! `on_final_response_body` → `log` → `on_ws_frame`.
//!
//! Each plugin declares which protocols it supports via `supported_protocols()`.
//! The `PluginCache` pre-filters plugins per protocol at config reload time
//! so the hot path does zero filtering.
//!
//! Security plugins (auth, ACL, IP restriction) that fail config validation
//! cause the gateway to refuse startup — they never silently degrade.
//! Non-security plugins that fail validation are skipped with a warning.

pub mod access_control;
pub mod ai_prompt_shield;
pub mod ai_rate_limiter;
pub mod ai_request_guard;
pub mod ai_token_metrics;
pub mod basic_auth;
pub mod body_validator;
pub mod bot_detection;
pub mod compression;
pub mod correlation_id;
pub mod cors;
pub mod graphql;
pub mod grpc_deadline;
pub mod grpc_method_router;
pub mod grpc_web;
pub mod hmac_auth;
pub mod http_logging;
pub mod ip_restriction;
pub mod jwks_auth;
pub mod jwt_auth;
pub mod key_auth;
pub mod loki_logging;
pub mod mtls_auth;
pub mod otel_tracing;
pub mod prometheus_metrics;
pub mod rate_limiting;
pub mod request_mirror;
pub mod request_size_limiting;
pub mod request_termination;
pub mod request_transformer;
pub mod response_caching;
pub mod response_size_limiting;
pub mod response_transformer;
pub mod serverless_function;
pub mod sse;
pub mod statsd_logging;
pub mod stdout_logging;
pub mod tcp_connection_throttle;
pub mod tcp_logging;
pub mod transaction_debugger;
pub mod udp_rate_limiting;
pub mod utils;
pub mod ws_frame_logging;
pub mod ws_logging;
pub mod ws_message_size_limiting;
pub mod ws_rate_limiting;

pub use utils::PluginHttpClient;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::types::{BackendProtocol, Consumer, Proxy};
use crate::consumer_index::ConsumerIndex;

/// Protocol categories that plugins can declare support for.
///
/// TLS/DTLS are transport-layer concerns — a plugin that works on TCP also
/// works on TCP+TLS, and similarly for UDP+DTLS. So we use 5 variants, not 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyProtocol {
    /// HTTP/1.1, HTTP/2, HTTP/3 (includes HTTPS — TLS is transport-layer)
    Http,
    /// gRPC / gRPCs (HTTP/2-based RPC)
    Grpc,
    /// WebSocket / WSS
    WebSocket,
    /// Raw TCP stream proxy (includes TLS termination/origination)
    Tcp,
    /// Raw UDP datagram proxy (includes DTLS termination/origination)
    Udp,
}

/// All protocol variants, for plugins that support every protocol.
pub const ALL_PROTOCOLS: &[ProxyProtocol] = &[
    ProxyProtocol::Http,
    ProxyProtocol::Grpc,
    ProxyProtocol::WebSocket,
    ProxyProtocol::Tcp,
    ProxyProtocol::Udp,
];

/// HTTP-family protocols (HTTP, gRPC, WebSocket) — no raw stream support.
pub const HTTP_FAMILY_PROTOCOLS: &[ProxyProtocol] = &[
    ProxyProtocol::Http,
    ProxyProtocol::Grpc,
    ProxyProtocol::WebSocket,
];

/// HTTP + gRPC only (plugins that modify HTTP headers/body but not WebSocket frames).
pub const HTTP_GRPC_PROTOCOLS: &[ProxyProtocol] = &[ProxyProtocol::Http, ProxyProtocol::Grpc];

/// HTTP-family protocols plus raw TCP streams.
pub const HTTP_FAMILY_AND_TCP_PROTOCOLS: &[ProxyProtocol] = &[
    ProxyProtocol::Http,
    ProxyProtocol::Grpc,
    ProxyProtocol::WebSocket,
    ProxyProtocol::Tcp,
];

/// HTTP family + all stream protocols (TCP + UDP/DTLS). Used by plugins that
/// authenticate via TLS/DTLS client certificates across all transport types.
pub const HTTP_FAMILY_AND_STREAM_PROTOCOLS: &[ProxyProtocol] = &[
    ProxyProtocol::Http,
    ProxyProtocol::Grpc,
    ProxyProtocol::WebSocket,
    ProxyProtocol::Tcp,
    ProxyProtocol::Udp,
];

/// HTTP-only (single protocol).
pub const HTTP_ONLY_PROTOCOLS: &[ProxyProtocol] = &[ProxyProtocol::Http];

/// WebSocket-only (plugins that operate on WebSocket frames, not HTTP request/response).
pub const WS_ONLY_PROTOCOLS: &[ProxyProtocol] = &[ProxyProtocol::WebSocket];

/// gRPC-only (single protocol).
pub const GRPC_ONLY_PROTOCOLS: &[ProxyProtocol] = &[ProxyProtocol::Grpc];

/// TCP-only (raw stream plugins that do not apply to UDP/DTLS).
pub const TCP_ONLY_PROTOCOLS: &[ProxyProtocol] = &[ProxyProtocol::Tcp];

/// UDP-only (datagram-level plugins that do not apply to TCP or HTTP).
pub const UDP_ONLY_PROTOCOLS: &[ProxyProtocol] = &[ProxyProtocol::Udp];

/// Direction of a UDP datagram being proxied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDatagramDirection {
    ClientToBackend,
    BackendToClient,
}

/// Context for per-datagram UDP plugin hooks.
///
/// Passed to `on_udp_datagram` for every datagram when at least one plugin
/// on the proxy opts in via `requires_udp_datagram_hooks()`. Fired in both
/// directions: client→backend (before forwarding) and backend→client (before
/// relaying the response to the client).
#[allow(dead_code)]
pub struct UdpDatagramContext {
    pub client_ip: String,
    pub proxy_id: String,
    pub proxy_name: Option<String>,
    pub listen_port: u16,
    pub datagram_size: usize,
    pub direction: UdpDatagramDirection,
}

/// Verdict from a per-datagram UDP plugin hook.
///
/// Unlike HTTP plugins which return status codes and bodies, UDP datagrams
/// are silently dropped when rate limited — standard UDP behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDatagramVerdict {
    /// Forward the datagram to its destination.
    Forward,
    /// Silently drop the datagram (standard UDP flood mitigation).
    Drop,
}

/// Direction of a WebSocket frame being proxied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketFrameDirection {
    ClientToBackend,
    BackendToClient,
}

/// Context passed through the plugin pipeline for a single request.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub matched_proxy: Option<Arc<Proxy>>,
    pub identified_consumer: Option<Consumer>,
    /// Identity string set by external auth plugins (e.g., `jwks_auth`) when no
    /// matching `Consumer` exists in the gateway. Used as the rate-limit key and
    /// for `consumer_username` in transaction logs.
    pub authenticated_identity: Option<String>,
    /// Human-readable identity for the `X-Consumer-Username` header sent to the
    /// backend. Falls back to `authenticated_identity` when not set separately.
    pub authenticated_identity_header: Option<String>,
    pub timestamp_received: DateTime<Utc>,
    /// Extra metadata plugins can attach
    pub metadata: HashMap<String, String>,
    /// DER-encoded client certificate from mTLS handshake (first cert in chain).
    /// Populated when the connection used TLS with client certificate verification.
    /// Shared via Arc to avoid cloning cert bytes for each request on HTTP/2 connections.
    pub tls_client_cert_der: Option<Arc<Vec<u8>>>,
    /// DER-encoded CA/intermediate certificates from the client's TLS certificate chain.
    /// Contains all certificates after the peer cert (index 1+) sent during the handshake.
    /// Used by the mtls_auth plugin for per-proxy CA fingerprint verification.
    pub tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    /// Cumulative nanoseconds spent by plugins making external HTTP calls
    /// (via `PluginHttpClient::execute_tracked`). Shared across all plugin
    /// invocations for this request — clone-safe via Arc.
    pub plugin_http_call_ns: Arc<std::sync::atomic::AtomicU64>,
    /// Receiver for mirror response metadata from the `request_mirror` plugin.
    /// Set by the plugin in `before_proxy`; collected before building
    /// `TransactionSummary` so all logging plugins receive mirror results.
    pub mirror_result_rx: Option<tokio::sync::watch::Receiver<Option<MirrorResponseMeta>>>,
}

impl RequestContext {
    pub fn new(client_ip: String, method: String, path: String) -> Self {
        Self {
            client_ip,
            method,
            path,
            headers: HashMap::new(),
            query_params: HashMap::new(),
            matched_proxy: None,
            identified_consumer: None,
            authenticated_identity: None,
            authenticated_identity_header: None,
            timestamp_received: Utc::now(),
            metadata: HashMap::new(),
            tls_client_cert_der: None,
            tls_client_cert_chain_der: None,
            plugin_http_call_ns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            mirror_result_rx: None,
        }
    }

    /// Collect mirror response metadata from the `request_mirror` plugin.
    ///
    /// Returns `Some(meta)` if a mirror request was dispatched and completed
    /// before the timeout. The 5-second timeout is a safety net — the mirror
    /// task always completes within the proxy's `backend_read_timeout_ms`
    /// (set via `reqwest::RequestBuilder::timeout`). Since this runs after
    /// the response is sent to the client, the wait has zero impact on
    /// client-facing latency.
    pub async fn collect_mirror_result(&self) -> Option<MirrorResponseMeta> {
        let rx = self.mirror_result_rx.as_ref()?;
        let mut rx_clone = rx.clone();
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx_clone.changed()).await {
            Ok(Ok(())) => rx_clone.borrow().clone(),
            // Timeout or sender dropped — return whatever is currently available
            _ => rx.borrow().clone(),
        }
    }

    /// Return the stable authenticated identity for downstream policy and
    /// observability. Gateway-mapped Consumers take precedence over external
    /// identities emitted by plugins like `jwks_auth`.
    pub fn effective_identity(&self) -> Option<&str> {
        self.identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str())
            .or(self.authenticated_identity.as_deref())
    }

    /// Return the identity value to forward to the backend in
    /// `X-Consumer-Username`. This prefers the gateway Consumer username, then
    /// a plugin-provided display/header identity, then the raw external auth
    /// identity.
    pub fn backend_consumer_username(&self) -> Option<&str> {
        self.identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str())
            .or(self.authenticated_identity_header.as_deref())
            .or(self.authenticated_identity.as_deref())
    }

    /// Return the Consumer custom ID to forward to the backend, if a gateway
    /// Consumer was resolved.
    pub fn backend_consumer_custom_id(&self) -> Option<&str> {
        self.identified_consumer
            .as_ref()
            .and_then(|consumer| consumer.custom_id.as_deref())
    }
}

/// Strip an HTTP auth scheme prefix from a header value using ASCII
/// case-insensitive matching. Returns the remaining credentials/token when the
/// scheme matches and a non-empty payload follows.
pub(crate) fn strip_auth_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let boundary = value.find(|c: char| c.is_ascii_whitespace())?;
    let (prefix, remainder) = value.split_at(boundary);
    if !prefix.eq_ignore_ascii_case(scheme) {
        return None;
    }

    let payload = remainder.trim_start_matches(|c: char| c.is_ascii_whitespace());
    (!payload.is_empty()).then_some(payload)
}

/// Result of a plugin execution.
#[derive(Debug)]
pub enum PluginResult {
    /// Continue to the next plugin/phase.
    Continue,
    /// Short-circuit: immediately return this response to the client.
    Reject {
        status_code: u16,
        body: String,
        headers: HashMap<String, String>,
    },
    /// Short-circuit with an arbitrary byte body.
    RejectBinary {
        status_code: u16,
        body: bytes::Bytes,
        headers: HashMap<String, String>,
    },
}

/// Mirror response metadata from the `request_mirror` plugin's spawned task.
///
/// Communicated via `tokio::sync::watch` channel from the spawned mirror task
/// to the proxy handler, which builds a second `TransactionSummary` (with
/// `mirror: true`) and logs it through the normal plugin pipeline.
#[derive(Debug, Clone)]
pub struct MirrorResponseMeta {
    /// URL the mirror request was sent to.
    pub mirror_target_url: String,
    /// HTTP status code from the mirror target. `None` when the request failed
    /// before a response was received (DNS, connect, timeout errors).
    pub mirror_response_status_code: Option<u16>,
    /// Response body size in bytes from the mirror target. Derived from
    /// `content-length` header when present, otherwise from reading the body.
    pub mirror_response_size_bytes: Option<u64>,
    /// Wall-clock latency of the mirror request in milliseconds.
    pub mirror_latency_ms: f64,
    /// Human-readable error message when the mirror request failed.
    pub mirror_error: Option<String>,
}

/// Transaction summary for logging plugins.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TransactionSummary {
    pub timestamp_received: String,
    pub client_ip: String,
    pub consumer_username: Option<String>,
    pub http_method: String,
    pub request_path: String,
    pub matched_proxy_id: Option<String>,
    pub matched_proxy_name: Option<String>,
    pub backend_target_url: Option<String>,
    /// The DNS-resolved IP address of the backend that was connected to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_resolved_ip: Option<String>,
    pub response_status_code: u16,
    pub latency_total_ms: f64,
    pub latency_gateway_processing_ms: f64,
    pub latency_backend_ttfb_ms: f64,
    /// For buffered responses: actual total backend time (body fully received).
    /// For streaming responses: -1.0 (body still transferring at log time;
    /// use `latency_backend_ttfb_ms` for alerting).
    pub latency_backend_total_ms: f64,
    /// Wall-clock time spent executing all plugin hooks (on_request_received
    /// through after_proxy/on_response_body/transform_response_body/
    /// on_final_response_body).
    /// Includes any external I/O that plugins performed synchronously.
    pub latency_plugin_execution_ms: f64,
    /// Subset of plugin execution time spent on external HTTP calls
    /// (via `PluginHttpClient::execute_tracked`). 0.0 when no plugin
    /// makes tracked external calls during the request lifecycle.
    pub latency_plugin_external_io_ms: f64,
    /// Pure gateway overhead: routing, header parsing, URL building,
    /// connection pool checkout, response framing, etc.
    /// Computed as: total - max(backend, 0) - plugin_execution.
    /// For rejected requests (no backend call): total - plugin_execution.
    pub latency_gateway_overhead_ms: f64,
    pub request_user_agent: Option<String>,
    /// True when the response body was streamed (not buffered).
    /// When true, `latency_backend_total_ms` is -1.0 (unknown at log time).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub response_streamed: bool,
    /// True when the client disconnected before receiving the full response.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub client_disconnected: bool,
    /// Human-friendly classification of the error when the gateway itself
    /// failed to communicate with the backend. `None` for successful requests
    /// and normal HTTP error responses from the backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<crate::retry::ErrorClass>,
    /// True when this summary represents a mirror (shadow) request, not the
    /// actual client-facing proxy traffic. Logged as a separate entry with the
    /// same schema so existing log queries and dashboards work without changes.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub mirror: bool,
    pub metadata: HashMap<String, String>,
}

impl TransactionSummary {
    /// Build a mirror transaction summary from this summary and a mirror result.
    ///
    /// Clones the original request context fields (client_ip, method, path, proxy,
    /// consumer) and overlays the mirror response metadata (status, latency, target
    /// URL). Response size and error details go into metadata since there are no
    /// dedicated fields for them in the standard schema.
    pub fn as_mirror_entry(&self, result: MirrorResponseMeta) -> Self {
        let mut mirror = self.clone();
        mirror.mirror = true;
        mirror.backend_target_url = Some(result.mirror_target_url);
        mirror.response_status_code = result.mirror_response_status_code.unwrap_or(0);
        mirror.backend_resolved_ip = None;
        mirror.latency_total_ms = result.mirror_latency_ms;
        mirror.latency_backend_ttfb_ms = result.mirror_latency_ms;
        mirror.latency_backend_total_ms = result.mirror_latency_ms;
        mirror.latency_gateway_processing_ms = 0.0;
        mirror.latency_plugin_execution_ms = 0.0;
        mirror.latency_plugin_external_io_ms = 0.0;
        mirror.latency_gateway_overhead_ms = 0.0;
        mirror.response_streamed = false;
        mirror.client_disconnected = false;
        mirror.error_class = None;
        if let Some(size) = result.mirror_response_size_bytes {
            mirror
                .metadata
                .insert("response_size_bytes".to_string(), size.to_string());
        }
        if let Some(err) = result.mirror_error {
            mirror.metadata.insert("mirror_error".to_string(), err);
        }
        mirror
    }
}

/// Log a transaction summary through all logging plugins, then log a mirror
/// summary if a mirror request was dispatched.
///
/// Mirror results are collected after the main summary is logged, giving the
/// spawned mirror task maximum time to complete. The mirror entry uses the
/// same `TransactionSummary` schema with `mirror: true` so existing log
/// pipelines work without changes.
pub async fn log_with_mirror(
    plugins: &[Arc<dyn Plugin>],
    summary: &TransactionSummary,
    ctx: &RequestContext,
) {
    for plugin in plugins {
        plugin.log(summary).await;
    }
    if let Some(mirror_result) = ctx.collect_mirror_result().await {
        let mirror_summary = summary.as_mirror_entry(mirror_result);
        for plugin in plugins {
            plugin.log(&mirror_summary).await;
        }
    }
}

/// Context for stream proxy (TCP/UDP) plugin hooks.
///
/// Fields like `proxy_id`, `proxy_name`, `listen_port`, and `backend_protocol`
/// are available for custom plugins to use in their `on_stream_connect` logic.
#[derive(Clone)]
#[allow(dead_code)]
pub struct StreamConnectionContext {
    pub client_ip: String,
    pub proxy_id: String,
    pub proxy_name: Option<String>,
    pub listen_port: u16,
    pub backend_protocol: BackendProtocol,
    /// Pre-built consumer index shared across stream connections.
    pub consumer_index: Arc<ConsumerIndex>,
    /// Gateway Consumer identified for this stream connection, if any.
    pub identified_consumer: Option<Consumer>,
    /// Identity string set by external stream auth plugins when no gateway
    /// Consumer was mapped. Mirrors `RequestContext::authenticated_identity`.
    pub authenticated_identity: Option<String>,
    pub metadata: HashMap<String, String>,
    /// DER-encoded client certificate from frontend TLS handshake (first cert in chain).
    /// Populated for TCP/TLS proxies after the TLS handshake completes.
    /// Used by plugins like `tcp_connection_throttle` for consumer-based throttling.
    pub tls_client_cert_der: Option<Arc<Vec<u8>>>,
    /// DER-encoded CA/intermediate certificates from the client's certificate chain.
    /// Contains all certificates after the peer cert (index 1+) sent during the handshake.
    pub tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
}

impl StreamConnectionContext {
    /// Return the stable authenticated identity for stream policies. A mapped
    /// Consumer username takes precedence over any external authenticated identity.
    pub fn effective_identity(&self) -> Option<&str> {
        self.identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str())
            .or(self.authenticated_identity.as_deref())
    }
}

/// Transaction summary for stream proxy (TCP/UDP) logging plugins.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamTransactionSummary {
    pub proxy_id: String,
    pub proxy_name: Option<String>,
    pub client_ip: String,
    pub backend_target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_resolved_ip: Option<String>,
    pub protocol: String,
    pub listen_port: u16,
    pub duration_ms: f64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_error: Option<String>,
    /// Human-friendly classification of the connection error, if any.
    /// Mirrors the `ErrorClass` used for HTTP/gRPC transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<crate::retry::ErrorClass>,
    pub timestamp_connected: String,
    pub timestamp_disconnected: String,
    /// Plugin-injected metadata (e.g., correlation ID, trace ID) carried
    /// from `on_stream_connect` to `on_stream_disconnect`.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

/// Plugin execution priority bands.
///
/// Plugins are sorted by priority (lowest runs first) within each lifecycle
/// phase. Plugins at the same priority have no guaranteed relative order.
/// Gaps between bands leave room for future plugins to slot in.
///
/// | Band      | Range       | Purpose                                   | Plugins |
/// |-----------|-------------|-------------------------------------------|---------|
/// | Early     | 0–949       | Pre-routing, tracing, and preflight       | otel_tracing (25), correlation_id (50), cors (100), request_termination (125), ip_restriction (150), bot_detection (200), sse (250), grpc_web (260), grpc_method_router (275) |
/// | AuthN     | 950–1999    | Authentication / identity verification    | mtls_auth (950), jwks_auth (1000), jwt_auth (1100), key_auth (1200), basic_auth (1300), hmac_auth (1400) |
/// | AuthZ     | 2000–2999   | Authorization and admission control       | access_control (2000), tcp_connection_throttle (2050), request_size_limiting (2800), graphql (2850), rate_limiting (2900), ai_prompt_shield (2925), body_validator (2950), ai_request_guard (2975) |
/// | Transform | 3000–3999   | Request shaping and response buffering    | request_transformer (3000), grpc_deadline (3050), request_mirror (3075), response_size_limiting (3490), response_caching (3500) |
/// | Response  | 4000–4999   | Response transformation and AI accounting | response_transformer (4000), ai_token_metrics (4100), ai_rate_limiter (4200) |
/// | Logging   | 9000–9999   | Observability and frame logging           | stdout_logging (9000), ws_frame_logging (9050), statsd_logging (9075), http_logging (9100), loki_logging (9150), ws_logging (9175), transaction_debugger (9200), prometheus_metrics (9300) |
#[allow(dead_code)]
pub mod priority {
    pub const OTEL_TRACING: u16 = 25;
    pub const CORRELATION_ID: u16 = 50;
    pub const REQUEST_TERMINATION: u16 = 125;
    pub const CORS: u16 = 100;
    pub const IP_RESTRICTION: u16 = 150;
    pub const BOT_DETECTION: u16 = 200;
    pub const SSE: u16 = 250;
    pub const GRPC_WEB: u16 = 260;
    pub const GRPC_METHOD_ROUTER: u16 = 275;
    pub const MTLS_AUTH: u16 = 950;
    pub const JWKS_AUTH: u16 = 1000;
    pub const JWT_AUTH: u16 = 1100;
    pub const KEY_AUTH: u16 = 1200;
    pub const BASIC_AUTH: u16 = 1300;
    pub const HMAC_AUTH: u16 = 1400;
    pub const ACCESS_CONTROL: u16 = 2000;
    pub const TCP_CONNECTION_THROTTLE: u16 = 2050;
    pub const REQUEST_SIZE_LIMITING: u16 = 2800;
    pub const GRAPHQL: u16 = 2850;
    pub const RATE_LIMITING: u16 = 2900;
    pub const AI_PROMPT_SHIELD: u16 = 2925;
    pub const BODY_VALIDATOR: u16 = 2950;
    pub const AI_REQUEST_GUARD: u16 = 2975;
    pub const REQUEST_TRANSFORMER: u16 = 3000;
    pub const SERVERLESS_FUNCTION: u16 = 3025;
    pub const GRPC_DEADLINE: u16 = 3050;
    pub const REQUEST_MIRROR: u16 = 3075;
    pub const RESPONSE_SIZE_LIMITING: u16 = 3490;
    pub const RESPONSE_CACHING: u16 = 3500;
    pub const RESPONSE_TRANSFORMER: u16 = 4000;
    pub const COMPRESSION: u16 = 4050;
    pub const AI_TOKEN_METRICS: u16 = 4100;
    pub const AI_RATE_LIMITER: u16 = 4200;
    pub const STDOUT_LOGGING: u16 = 9000;
    pub const STATSD_LOGGING: u16 = 9075;
    pub const HTTP_LOGGING: u16 = 9100;
    pub const TCP_LOGGING: u16 = 9125;
    pub const LOKI_LOGGING: u16 = 9150;
    pub const TRANSACTION_DEBUGGER: u16 = 9200;
    pub const PROMETHEUS_METRICS: u16 = 9300;
    pub const WS_MESSAGE_SIZE_LIMITING: u16 = 2810;
    pub const WS_RATE_LIMITING: u16 = 2910;
    pub const WS_LOGGING: u16 = 9175;
    pub const WS_FRAME_LOGGING: u16 = 9050;
    pub const UDP_RATE_LIMITING: u16 = 2910;
    /// Default priority for unknown/custom plugins — runs after transforms, before logging.
    pub const DEFAULT: u16 = 5000;
}

/// Plugin lifecycle hooks.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Returns the plugin name.
    fn name(&self) -> &str;

    /// Returns the execution priority (lower = runs first).
    ///
    /// Plugins are sorted by priority within each lifecycle phase.
    /// See [`priority`] module for standard bands and assignments.
    fn priority(&self) -> u16 {
        priority::DEFAULT
    }

    /// Called when a request is first received (before routing).
    async fn on_request_received(&self, _ctx: &mut RequestContext) -> PluginResult {
        PluginResult::Continue
    }

    /// Authentication phase. Uses ConsumerIndex for O(1) credential lookups.
    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Authorization phase (after authentication).
    async fn authorize(&self, _ctx: &mut RequestContext) -> PluginResult {
        PluginResult::Continue
    }

    /// Returns `true` if this plugin may modify outgoing request headers
    /// during the `before_proxy` phase. The gateway uses this hint to skip
    /// cloning the header map when no plugin needs to modify it.
    ///
    /// Default is `false`. Override in plugins that insert, remove, or
    /// modify headers in `before_proxy`.
    fn modifies_request_headers(&self) -> bool {
        false
    }

    /// Returns `true` if this plugin may transform the request body before
    /// it is sent to the backend. The gateway uses this hint to call
    /// `transform_request_body` only when needed.
    ///
    /// Default is `false`. Override in plugins that rewrite JSON fields,
    /// rename body keys, etc.
    fn modifies_request_body(&self) -> bool {
        false
    }

    /// Returns `true` if this plugin needs the raw request body to be available
    /// during `before_proxy`.
    ///
    /// This is narrower than `requires_request_body_buffering()`: body
    /// transformers can buffer later, after `before_proxy` rejects have had a
    /// chance to short-circuit. Override this only for plugins that read
    /// `ctx.metadata["request_body"]` inside `before_proxy`.
    fn requires_request_body_before_before_proxy(&self) -> bool {
        false
    }

    /// Returns `true` if this plugin may require the request body to be
    /// buffered instead of streamed for at least some requests.
    ///
    /// The gateway uses this as a config-time upper bound in `PluginCache`.
    /// Request-time body buffering can still remain disabled when
    /// `should_buffer_request_body()` returns `false` for the current request.
    fn requires_request_body_buffering(&self) -> bool {
        self.modifies_request_body() || self.requires_request_body_before_before_proxy()
    }

    /// Called just before the request is proxied to the backend.
    async fn before_proxy(
        &self,
        _ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Returns `true` when the current request should buffer the request body
    /// for this plugin.
    ///
    /// Override this for config-sensitive or header-sensitive plugins so the
    /// gateway can keep streaming requests that clearly do not need body access
    /// (for example, non-JSON requests on an AI policy plugin).
    fn should_buffer_request_body(&self, _ctx: &RequestContext) -> bool {
        self.requires_request_body_buffering()
    }

    /// Called after the response is received from the backend.
    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Returns `true` if this plugin should also run its `after_proxy`
    /// header decoration logic for gateway-generated rejection responses.
    ///
    /// Intended for response-header plugins like CORS, tracing propagation,
    /// and correlation IDs. Plugins that rely on a real backend response
    /// should leave the default `false`.
    fn applies_after_proxy_on_reject(&self) -> bool {
        false
    }

    /// Returns `true` if this plugin needs the entire response body buffered
    /// in memory before forwarding to the client. When any active plugin
    /// returns `true`, the gateway forces buffered mode for that proxy
    /// regardless of the `response_body_mode` configuration.
    ///
    /// Default is `false` (compatible with streaming). Override this in
    /// plugins that inspect or transform the response body.
    fn requires_response_body_buffering(&self) -> bool {
        false
    }

    /// Called after the full response body has been received from the backend.
    ///
    /// Only invoked when `requires_response_body_buffering()` returns `true` for
    /// at least one active plugin on the proxy. Plugins that need to inspect,
    /// validate, or cache the response body should override this method.
    ///
    /// The body bytes are the raw backend response body (before any response
    /// transformation). The response_status and response_headers are the values
    /// after the `after_proxy` phase.
    ///
    /// Returning `PluginResult::Reject` replaces the buffered response with the
    /// rejection body/status before it reaches the client (useful for enforcing
    /// API response contracts).
    async fn on_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Transform the request body before it is sent to the backend.
    ///
    /// Called after `before_proxy` hooks, only when `modifies_request_body()`
    /// returns `true` for at least one active plugin. The body bytes are the
    /// raw request body collected from the client.
    ///
    /// Return `Some(new_body)` to replace the body, or `None` to leave it
    /// unchanged. The `content_type` parameter is extracted from the request
    /// headers so plugins can decide whether to parse the body. The full
    /// `request_headers` map is also available for plugins that need other
    /// headers (e.g., `content-encoding` for decompression).
    async fn transform_request_body(
        &self,
        _body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        None
    }

    /// Called after all `transform_request_body` hooks on buffered requests.
    ///
    /// Use this hook when the plugin must inspect or validate the final
    /// backend-visible request body after all request transformations have run.
    async fn on_final_request_body(
        &self,
        _headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Transform the response body before it is sent to the client.
    ///
    /// Called after `on_response_body` hooks, only for buffered responses
    /// when `requires_response_body_buffering()` returns `true`. The body
    /// bytes are the raw backend response body.
    ///
    /// Return `Some(new_body)` to replace the body, or `None` to leave it
    /// unchanged. The `content_type` parameter is extracted from the response
    /// headers so plugins can decide whether to parse the body. The full
    /// `response_headers` map is also available for plugins that need other
    /// headers (e.g., `content-encoding` for compression).
    async fn transform_response_body(
        &self,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        None
    }

    /// Called after all `transform_response_body` hooks on buffered responses.
    ///
    /// Use this hook when the plugin must inspect or act on the final
    /// client-visible response body, such as for outbound validation,
    /// post-transform size checks, or caching the transformed payload.
    async fn on_final_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Called for transaction logging.
    async fn log(&self, _summary: &TransactionSummary) {}

    /// Returns `true` if this plugin participates in the authentication phase.
    ///
    /// The gateway uses this to filter plugins for the authentication lifecycle
    /// phase, where auth mode (Single vs Multi) determines how failures are
    /// handled. Custom auth plugins should override this to return `true`.
    ///
    /// Default is `false`. Built-in auth plugins (jwks_auth, jwt_auth, key_auth,
    /// basic_auth, hmac_auth) override this to return `true`.
    fn is_auth_plugin(&self) -> bool {
        false
    }

    /// Returns hostnames that this plugin will send traffic to.
    ///
    /// Used during DNS warmup to pre-resolve plugin endpoint hostnames
    /// alongside proxy backend hostnames, avoiding cold-cache DNS lookups
    /// on the first request through the plugin.
    ///
    /// Default implementation returns an empty list (most plugins make no
    /// outbound network calls). Override this if your plugin has a configured
    /// endpoint URL (e.g., http_logging, jwks_auth JWKS endpoints).
    fn warmup_hostnames(&self) -> Vec<String> {
        Vec::new()
    }

    /// Returns the set of proxy protocols this plugin supports.
    ///
    /// The gateway uses this to filter plugins per proxy based on its protocol.
    /// For example, CORS only applies to HTTP, while ip_restriction works on all
    /// protocols. Plugins are skipped for protocols they don't support.
    ///
    /// Default is HTTP-only (backwards compatible for existing plugins).
    /// Use the protocol constants (`ALL_PROTOCOLS`, `HTTP_FAMILY_PROTOCOLS`, etc.)
    /// for common patterns.
    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        HTTP_ONLY_PROTOCOLS
    }

    /// Returns the number of tracked rate-limit keys, if applicable.
    ///
    /// Only meaningful for stateful plugins that track per-key counters
    /// (e.g., rate_limiting). Returns `None` by default.
    fn tracked_keys_count(&self) -> Option<usize> {
        None
    }

    /// Called when a new stream connection (TCP/UDP session) is established.
    ///
    /// Returning `PluginResult::Reject` closes the connection immediately.
    /// Plugins can insert metadata (e.g., correlation ID) into `ctx.metadata`
    /// which is carried through to `on_stream_disconnect`.
    async fn on_stream_connect(&self, _ctx: &mut StreamConnectionContext) -> PluginResult {
        PluginResult::Continue
    }

    /// Called when a stream connection (TCP/UDP session) is completed.
    async fn on_stream_disconnect(&self, _summary: &StreamTransactionSummary) {}

    /// Returns `true` if this plugin needs per-frame WebSocket inspection.
    /// Zero overhead when `false` (default) — the frame forwarding loop skips plugins entirely.
    fn requires_ws_frame_hooks(&self) -> bool {
        false
    }

    /// Called for each WebSocket frame when at least one plugin on the proxy opts in.
    ///
    /// `connection_id` is a unique per-connection identifier (monotonic counter) that
    /// stateful plugins (e.g., ws_rate_limiting) can use to track per-connection state.
    ///
    /// Return `Some(message)` to replace the frame, `None` to pass through unchanged.
    /// Returning `Some(Message::Close(...))` will close the WebSocket in both directions.
    async fn on_ws_frame(
        &self,
        _proxy_id: &str,
        _connection_id: u64,
        _direction: WebSocketFrameDirection,
        _message: &tokio_tungstenite::tungstenite::Message,
    ) -> Option<tokio_tungstenite::tungstenite::Message> {
        None
    }

    /// Returns `true` if this plugin needs per-datagram UDP inspection.
    /// Zero overhead when `false` (default) — the datagram forwarding path skips plugins entirely.
    fn requires_udp_datagram_hooks(&self) -> bool {
        false
    }

    /// Called for each UDP datagram in both directions (client→backend and backend→client).
    ///
    /// Only invoked when at least one plugin on the proxy opts in via
    /// `requires_udp_datagram_hooks()`. Return `UdpDatagramVerdict::Drop` to
    /// silently discard the datagram (standard UDP flood mitigation).
    /// Use `ctx.direction` to distinguish client→backend from backend→client.
    async fn on_udp_datagram(&self, _ctx: &UdpDatagramContext) -> UdpDatagramVerdict {
        UdpDatagramVerdict::Forward
    }
}

/// Create a plugin instance from its name and configuration.
///
/// Uses a default `PluginHttpClient` for plugins that make outbound HTTP calls.
/// Prefer [`create_plugin_with_http_client`] in production to share the gateway's
/// pooled client across all plugins for connection reuse and keepalive.
#[allow(dead_code)]
pub fn create_plugin(name: &str, config: &Value) -> Result<Option<Arc<dyn Plugin>>, String> {
    create_plugin_with_http_client(name, config, PluginHttpClient::default())
}

/// Create a plugin instance with a shared HTTP client for outbound calls.
///
/// Plugins that make network calls (http_logging, future OTel exporters, webhooks,
/// etc.) will use this shared client, which is configured with the gateway's
/// connection pool settings (keepalive, idle timeout, HTTP/2 multiplexing).
///
/// This ensures all plugin outbound traffic gets proper connection reuse instead
/// of opening a new TCP+TLS connection per call.
///
/// Returns:
/// - `Ok(Some(plugin))` — plugin created successfully
/// - `Ok(None)` — unknown plugin name
/// - `Err(msg)` — plugin config validation failed
pub fn create_plugin_with_http_client(
    name: &str,
    config: &Value,
    http_client: PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    match name {
        "stdout_logging" => Ok(Some(Arc::new(stdout_logging::StdoutLogging::new(config)))),
        "statsd_logging" => Ok(Some(Arc::new(statsd_logging::StatsdLogging::new(
            config,
            http_client.clone(),
        )?))),
        "http_logging" => Ok(Some(Arc::new(http_logging::HttpLogging::new(
            config,
            http_client.clone(),
        )?))),
        "tcp_logging" => Ok(Some(Arc::new(tcp_logging::TcpLogging::new(
            config,
            http_client,
        )?))),
        "ws_logging" => Ok(Some(Arc::new(ws_logging::WsLogging::new(
            config,
            http_client,
        )?))),
        "loki_logging" => Ok(Some(Arc::new(loki_logging::LokiLogging::new(
            config,
            http_client,
        )?))),
        "transaction_debugger" => Ok(Some(Arc::new(
            transaction_debugger::TransactionDebugger::new(config),
        ))),
        "jwks_auth" => Ok(Some(Arc::new(jwks_auth::JwksAuth::new(
            config,
            http_client.clone(),
        )?))),
        "jwt_auth" => Ok(Some(Arc::new(jwt_auth::JwtAuth::new(config)))),
        "key_auth" => Ok(Some(Arc::new(key_auth::KeyAuth::new(config)))),
        "basic_auth" => Ok(Some(Arc::new(basic_auth::BasicAuth::new(config)))),
        "hmac_auth" => Ok(Some(Arc::new(hmac_auth::HmacAuth::new(config)))),
        "mtls_auth" => Ok(Some(Arc::new(mtls_auth::MtlsAuth::new(config)))),
        "compression" => Ok(Some(Arc::new(compression::CompressionPlugin::new(config)))),
        "cors" => Ok(Some(Arc::new(cors::CorsPlugin::new(config)))),
        "access_control" => Ok(Some(Arc::new(access_control::AccessControl::new(config)?))),
        "tcp_connection_throttle" => Ok(Some(Arc::new(
            tcp_connection_throttle::TcpConnectionThrottle::new(config)?,
        ))),
        "ip_restriction" => Ok(Some(Arc::new(ip_restriction::IpRestriction::new(config)?))),
        "bot_detection" => Ok(Some(Arc::new(bot_detection::BotDetection::new(config)))),
        "correlation_id" => Ok(Some(Arc::new(correlation_id::CorrelationId::new(config)))),
        "request_transformer" => Ok(Some(Arc::new(
            request_transformer::RequestTransformer::new(config),
        ))),
        "response_transformer" => Ok(Some(Arc::new(
            response_transformer::ResponseTransformer::new(config),
        ))),
        "sse" => Ok(Some(Arc::new(sse::SsePlugin::new(config)))),
        "graphql" => Ok(Some(Arc::new(graphql::GraphqlPlugin::new(config)))),
        "grpc_method_router" => Ok(Some(Arc::new(grpc_method_router::GrpcMethodRouter::new(
            config,
        )))),
        "grpc_deadline" => Ok(Some(Arc::new(grpc_deadline::GrpcDeadline::new(config)))),
        "grpc_web" => Ok(Some(Arc::new(grpc_web::GrpcWebPlugin::new(config)))),
        "rate_limiting" => Ok(Some(Arc::new(rate_limiting::RateLimiting::new(
            config,
            http_client.clone(),
        )))),
        "request_mirror" => Ok(Some(Arc::new(request_mirror::RequestMirror::new(
            config,
            http_client.clone(),
        )?))),
        "request_size_limiting" => Ok(Some(Arc::new(
            request_size_limiting::RequestSizeLimiting::new(config),
        ))),
        "response_size_limiting" => Ok(Some(Arc::new(
            response_size_limiting::ResponseSizeLimiting::new(config),
        ))),
        "body_validator" => Ok(Some(Arc::new(body_validator::BodyValidator::new(config)))),
        "request_termination" => Ok(Some(Arc::new(
            request_termination::RequestTermination::new(config),
        ))),
        "response_caching" => Ok(Some(Arc::new(response_caching::ResponseCaching::new(
            config,
        )))),
        "serverless_function" => Ok(Some(Arc::new(
            serverless_function::ServerlessFunction::new(config, http_client)?,
        ))),
        "prometheus_metrics" => Ok(Some(Arc::new(prometheus_metrics::PrometheusMetrics::new(
            config,
        )))),
        "otel_tracing" => Ok(Some(Arc::new(
            otel_tracing::OtelTracing::new_with_http_client(config, http_client)?,
        ))),
        "ai_token_metrics" => Ok(Some(Arc::new(ai_token_metrics::AiTokenMetrics::new(
            config,
        )))),
        "ai_request_guard" => Ok(Some(Arc::new(ai_request_guard::AiRequestGuard::new(
            config,
        )))),
        "ai_rate_limiter" => Ok(Some(Arc::new(ai_rate_limiter::AiRateLimiter::new(
            config,
            http_client.clone(),
        )))),
        "ai_prompt_shield" => Ok(Some(Arc::new(ai_prompt_shield::AiPromptShield::new(
            config,
        )))),
        "ws_message_size_limiting" => Ok(Some(Arc::new(
            ws_message_size_limiting::WsMessageSizeLimiting::new(config),
        ))),
        "ws_frame_logging" => Ok(Some(Arc::new(ws_frame_logging::WsFrameLogging::new(
            config,
        )))),
        "ws_rate_limiting" => Ok(Some(Arc::new(ws_rate_limiting::WsRateLimiting::new(
            config,
            http_client.clone(),
        )))),
        "udp_rate_limiting" => Ok(Some(Arc::new(udp_rate_limiting::UdpRateLimiting::new(
            config,
        )?))),
        _ => {
            // Fall through to custom plugins registry
            let result = crate::custom_plugins::create_custom_plugin(name, config, http_client);
            if result.is_none() {
                tracing::warn!("Unknown plugin: {}", name);
            }
            Ok(result)
        }
    }
}

/// List of all available plugin names (built-in + custom).
/// Returns true if the named plugin is security-critical (auth or access control).
///
/// Validation failures for these plugins are fatal at startup — the gateway
/// refuses to start rather than serving traffic without the intended security.
pub fn is_security_plugin(name: &str) -> bool {
    matches!(
        name,
        "key_auth"
            | "basic_auth"
            | "jwt_auth"
            | "hmac_auth"
            | "jwks_auth"
            | "mtls_auth"
            | "access_control"
            | "tcp_connection_throttle"
            | "ip_restriction"
    )
}

pub fn available_plugins() -> Vec<&'static str> {
    let mut plugins = vec![
        "stdout_logging",
        "http_logging",
        "tcp_logging",
        "ws_logging",
        "transaction_debugger",
        "jwks_auth",
        "jwt_auth",
        "key_auth",
        "basic_auth",
        "hmac_auth",
        "mtls_auth",
        "cors",
        "access_control",
        "tcp_connection_throttle",
        "ip_restriction",
        "bot_detection",
        "correlation_id",
        "request_transformer",
        "response_transformer",
        "graphql",
        "grpc_method_router",
        "grpc_deadline",
        "grpc_web",
        "rate_limiting",
        "request_size_limiting",
        "response_size_limiting",
        "body_validator",
        "request_termination",
        "response_caching",
        "serverless_function",
        "prometheus_metrics",
        "otel_tracing",
        "ai_token_metrics",
        "ai_request_guard",
        "ai_rate_limiter",
        "ai_prompt_shield",
        "ws_message_size_limiting",
        "ws_frame_logging",
        "ws_rate_limiting",
        "udp_rate_limiting",
        "request_mirror",
    ];
    plugins.extend(crate::custom_plugins::custom_plugin_names());
    plugins
}
