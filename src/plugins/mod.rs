//! Plugin system — 61 built-in plugins with a trait-based architecture.
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
//! Security plugins (auth, ACL, IP restriction, WAF, and mesh policy gates)
//! that fail config validation cause the gateway to refuse startup — they
//! never silently degrade.
//! Non-security plugins that fail validation are skipped with a warning.

pub mod access_control;
pub mod access_log;
pub mod ai_federation;
pub mod ai_prompt_shield;
pub mod ai_rate_limiter;
pub mod ai_request_guard;
pub mod ai_response_guard;
pub mod ai_semantic_cache;
pub mod ai_token_metrics;
pub mod api_chargeback;
pub mod basic_auth;
pub mod body_validator;
pub mod bot_detection;
pub mod compression;
pub mod correlation_id;
pub mod cors;
pub mod fault_injection;
pub mod geo_restriction;
pub mod graphql;
pub mod grpc_deadline;
pub mod grpc_method_router;
pub mod grpc_web;
pub mod hmac_auth;
pub mod http_logging;
pub mod ip_restriction;
pub mod jwks_auth;
pub mod jwt_auth;
pub mod kafka_logging;
pub mod key_auth;
pub mod ldap_auth;
pub mod load_testing;
pub mod loki_logging;
pub mod mesh;
pub mod mesh_route_dispatch;
pub mod mtls_auth;
pub mod otel_tracing;
pub mod prometheus_metrics;
pub mod proxy_alerts;
pub mod rate_limiting;
pub mod request_deduplication;
pub mod request_mirror;
pub mod request_size_limiting;
pub mod request_termination;
pub mod request_transformer;
pub mod response_caching;
pub mod response_mock;
pub mod response_size_limiting;
pub mod response_transformer;
pub mod serverless_function;
pub mod soap_ws_security;
pub mod spec_expose;
pub mod sse;
pub mod statsd_logging;
pub mod stdout_logging;
pub mod tcp_connection_throttle;
pub mod tcp_logging;
pub mod transaction_debugger;
pub mod transaction_log_schema;
pub mod udp_logging;
pub mod udp_rate_limiting;
pub mod utils;
pub mod waf;
pub mod ws_frame_logging;
pub mod ws_logging;
pub mod ws_message_size_limiting;
pub mod ws_rate_limiting;

pub use utils::PluginHttpClient;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::HeaderMap;
use percent_encoding::percent_decode_str;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::types::{
    BackendScheme, BackendTlsConfig, Consumer, Proxy, ResolvedPortOverride, RetryConfig, Upstream,
};
use crate::consumer_index::ConsumerIndex;
use crate::modes::mesh::MeshTrafficDirection;

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
    pub client_ip: Arc<str>,
    pub proxy_id: Arc<str>,
    pub proxy_name: Option<Arc<str>>,
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

/// Context passed to `on_ws_disconnect` when a WebSocket session ends.
///
/// Mirrors the information made available on `StreamTransactionSummary`
/// for TCP/UDP streams so logging/metrics plugins have parity across all
/// three protocols. `direction` identifies which half of the frame relay
/// terminated first and `io_side` identifies whether that half failed while
/// reading from its source or writing to its destination. `None` for both
/// indicates a clean close initiated by either peer or an upgrade that never
/// established frame flow.
///
/// Populated once per accepted WebSocket upgrade, including H2 Extended
/// CONNECT (RFC 8441) sessions. The frame relay code should construct
/// this at session teardown and dispatch it to any plugin whose
/// `requires_ws_disconnect_hooks()` returns true.
#[derive(Debug, Clone)]
pub struct WsDisconnectContext {
    pub namespace: String,
    pub proxy_id: String,
    pub proxy_name: Option<String>,
    pub client_ip: String,
    /// Backend target URL (scheme://host:port/path) — matches the
    /// `backend_target` field from the original upgrade request.
    pub backend_target: String,
    /// Listener port on the gateway that accepted the upgrade.
    pub listen_port: u16,
    /// Total session lifetime in milliseconds (upgrade → close).
    pub duration_ms: f64,
    /// Number of frames proxied from client toward backend.
    pub frames_client_to_backend: u64,
    /// Number of frames proxied from backend toward client.
    pub frames_backend_to_client: u64,
    /// Total payload bytes proxied from client toward backend over the
    /// lifetime of this WebSocket session.
    pub bytes_client_to_backend: u64,
    /// Total payload bytes proxied from backend toward client over the
    /// lifetime of this WebSocket session.
    pub bytes_backend_to_client: u64,
    /// Which direction observed the first terminating error. `None` for
    /// clean close initiated by either peer.
    pub direction: Option<Direction>,
    /// Which I/O side inside the failing direction observed the error. This
    /// disambiguates `BackendToClient` reads from the backend versus writes to
    /// a disconnected client.
    pub io_side: Option<crate::proxy::tcp_proxy::StreamIoSide>,
    /// Classification of the terminating error, if any.
    pub error_class: Option<crate::retry::ErrorClass>,
    /// Consumer identity associated with the upgrade (copied from
    /// the originating `RequestContext`).
    pub consumer_username: Option<String>,
    /// Authentication mechanism that succeeded for the upgrade request.
    pub auth_method: Option<&'static str>,
    /// Correlation ID / tracing metadata inherited from the upgrade request.
    pub metadata: HashMap<String, String>,
}

/// Context passed through the plugin pipeline for a single request.
///
/// Headers and query parameters are lazily materialized to avoid per-request
/// allocations on the hot path. The raw `http::HeaderMap` and query string are
/// stored at request init time; the `HashMap<String, String>` representations
/// are only built when a plugin phase actually needs them (via
/// `materialize_headers()` / `materialize_query_params()`). Query
/// materialization preserves the raw query string so security plugins can still
/// inspect duplicate pairs that collapse in the parsed `HashMap`.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub client_ip: String,
    pub method: String,
    pub path: String,
    /// Frontend listener port that accepted this HTTP-family request.
    /// HTTP proxy resources do not carry `listen_port`, so mesh authorization
    /// uses this to evaluate Istio `to.ports` matches for HTTP traffic.
    pub frontend_listen_port: Option<u16>,
    /// Raw HTTP headers from the request. Stored at init time and consumed by
    /// `materialize_headers()`. Core proxy lookups (IP resolution, host
    /// extraction) read from this directly via `raw_header_get()` to avoid
    /// eagerly converting every header to an owned `String`.
    raw_headers: Option<HeaderMap>,
    /// Materialized headers HashMap. Empty until `materialize_headers()` is
    /// called. Plugin code and backend dispatch read from this field.
    pub headers: HashMap<String, String>,
    /// Raw query string stored for lazy parsing. `None` when empty. Preserved
    /// after query-param materialization so security plugins can inspect raw
    /// duplicate pairs.
    raw_query_string: Option<String>,
    /// Whether either decoded or raw query-param materialization has already
    /// populated `query_params`. Keeps materialization one-shot while preserving
    /// `raw_query_string` for inspection.
    query_params_materialized: bool,
    /// Parsed query parameters. Empty until `materialize_query_params()` or
    /// `materialize_query_params_raw()` is called.
    ///
    /// HTTP/1.1 and HTTP/2 materialize percent-decoded query params for
    /// historical compatibility. HTTP/3 materializes raw query params unless
    /// an active plugin explicitly requires the decoded representation.
    pub query_params: HashMap<String, String>,
    pub matched_proxy: Option<Arc<Proxy>>,
    pub identified_consumer: Option<Arc<Consumer>>,
    /// Identity string set by external auth plugins (e.g., `jwks_auth`) when no
    /// matching `Consumer` exists in the gateway. Used as the rate-limit key and
    /// for `consumer_username` in transaction logs.
    pub authenticated_identity: Option<String>,
    /// Human-readable identity for the `X-Consumer-Username` header sent to the
    /// backend. Falls back to `authenticated_identity` when not set separately.
    pub authenticated_identity_header: Option<String>,
    /// Authentication mechanism that succeeded (e.g., `"jwt_auth"`, `"key_auth"`).
    /// `&'static str` because every `AuthMechanism::mechanism_name()` returns a
    /// compiled-in literal — zero allocation on the hot path.
    pub auth_method: Option<&'static str>,
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
    /// Peer SPIFFE identity, populated by the `spiffe_identity` plugin when the
    /// client certificate carries a `spiffe://` URI SAN. `None` for non-mesh
    /// deployments and for clients that present a non-SPIFFE certificate.
    /// Plugins downstream of `spiffe_identity` may read this for identity-aware
    /// authorization (e.g. mesh policy evaluation in Phase C).
    pub peer_spiffe_id: Option<crate::identity::SpiffeId>,
    /// Cumulative nanoseconds spent by plugins making external HTTP calls
    /// (via `PluginHttpClient::execute_tracked`). Shared across all plugin
    /// invocations for this request — clone-safe via Arc.
    pub plugin_http_call_ns: Arc<std::sync::atomic::AtomicU64>,
    /// Receiver for mirror response metadata from the `request_mirror` plugin.
    /// Set by the plugin in `before_proxy`; collected before building
    /// `TransactionSummary` so all logging plugins receive mirror results.
    pub mirror_result_rx: Option<tokio::sync::watch::Receiver<Option<MirrorResponseMeta>>>,
    /// Binary-safe request body bytes, populated when a plugin requires the
    /// body before `before_proxy` (e.g., `request_mirror`). Unlike the
    /// `"request_body"` metadata key (UTF-8 only), this preserves non-UTF-8
    /// payloads such as gRPC protobuf.
    pub request_body_bytes: Option<bytes::Bytes>,
    /// Shared counter for request body bytes received from the client,
    /// populated by proxy body handlers and read by the summary builders.
    ///
    /// Populated at four points in the request path:
    /// 1. Buffered-collect sites (`Incoming::collect().await`): written once
    ///    with the final `body_bytes.len()` after collection completes.
    /// 2. Streaming forward with size limit (`SizeLimitedIncoming`): written
    ///    once after the backend request completes, from the cloned counter
    ///    handle obtained via `SizeLimitedIncoming::bytes_seen_handle()`.
    /// 3. Streaming forward without size limit (`CountingIncoming` wrapping
    ///    the `Incoming` body): same handle-capture pattern.
    /// 4. Prebuffered bodies (populated earlier by plugins like
    ///    `request_mirror`): copied from the buffered `Bytes::len()`.
    ///
    /// Summary builders read this via `load(Ordering::Acquire)` and populate
    /// `TransactionSummary.bytes_sent`. A zero value is skipped at
    /// serialization time, so empty/GET/HEAD requests do not inflate logs.
    ///
    /// Clone-safe via `Arc` — all proxy paths share one counter per request.
    pub bytes_sent_observed: Arc<std::sync::atomic::AtomicU64>,
    /// Whether this request arrived via TLS 1.3 0-RTT early data.
    /// Set on HTTP/3 via quinn's `into_0rtt()` detection, and on HTTPS via the
    /// `Early-Data: 1` header (RFC 8470) from upstream proxies/CDNs.
    pub is_early_data: bool,
    /// Plugin-set override for the proxy's `upstream_id`. When `Some`, the
    /// dispatch path uses this instead of `proxy.upstream_id`. Used by
    /// `mesh_route_dispatch` to implement Istio `VirtualService` header/method
    /// route matching without per-match `Proxy` materialization.
    ///
    /// **Pool-key invariant**: every connection-pool key that mentions
    /// upstream identity MUST derive from this override when set. See
    /// `RequestContext::effective_upstream_id`.
    pub route_override_upstream_id: Option<String>,
    /// Plugin-set override for the proxy's `backend_host`. Same contract as
    /// `route_override_upstream_id`; the dispatch path falls back to
    /// `proxy.backend_host` when this is `None`.
    pub route_override_backend_host: Option<String>,
    /// Plugin-set override for the proxy's `backend_port`. Same contract as
    /// `route_override_upstream_id`.
    pub route_override_backend_port: Option<u16>,
    /// Plugin-set override for the proxy's resolved backend TLS identity.
    ///
    /// When `route_override_upstream_id` points at another upstream, dispatch
    /// re-resolves this from the upstream snapshot automatically. Plugins that
    /// override a direct backend host/port can set this field explicitly when
    /// the destination uses different mTLS materials.
    pub route_override_resolved_tls: Option<BackendTlsConfig>,
    /// Plugin-set override for the proxy's backend response/read timeout.
    /// Used by mesh L7 route dispatch so route-local policy follows the
    /// matched predicate even when the hot router selected a later fallback
    /// proxy for the same public path.
    pub route_override_backend_read_timeout_ms: Option<u64>,
    /// Plugin-set override for the proxy's retry policy. Outer `None` means
    /// no override; `Some(None)` intentionally clears the selected proxy's
    /// retry policy for this route.
    pub route_override_retry: Option<Option<RetryConfig>>,
    /// Per-rule request header transforms published by `mesh_route_dispatch`
    /// when a matching rule carries `request_transform` rules (Istio
    /// `VirtualService.http[].headers.request.{set,add,remove}`). The
    /// `request_transformer` plugin applies these after its own static
    /// header rules. Shared via `Arc` so the dispatch hot path clones a
    /// pointer rather than the rule list.
    pub route_override_request_transform:
        Option<Arc<Vec<utils::route_header_transform::RouteHeaderTransformRule>>>,
    /// Per-rule response header transforms; counterpart to
    /// `route_override_request_transform`. Applied by `response_transformer`
    /// after its own static header rules.
    pub route_override_response_transform:
        Option<Arc<Vec<utils::route_header_transform::RouteHeaderTransformRule>>>,
    /// In node-waypoint mesh topology, the Kubernetes pod UID resolved from
    /// the eBPF socket-cookie record at accept time. Set by the connection
    /// admit path alongside `peer_spiffe_id`; `None` for non-mesh
    /// deployments and for mesh topologies other than `NodeWaypoint`.
    ///
    /// Plugins use this to disambiguate source-pod identity when one
    /// listener serves many pods. Pair with `node_waypoint_policy_scope`
    /// for the pre-resolved per-pod scope cache.
    pub node_waypoint_pod_uid: Option<[u8; 16]>,
    /// Pre-resolved per-pod policy scope for node-waypoint mode.
    ///
    /// Populated by the connection admit path by looking up the source
    /// pod's `PolicyScopeCache` from the `NodeWaypointIdentityResolver`.
    /// `mesh_authz` consults this when filtering policies whose
    /// `PolicyScope` is namespace- or workload-selector-bound, because
    /// the shared listener carries no single proxy identity that fits
    /// the slice-level filter that other topologies use.
    pub node_waypoint_policy_scope: Option<Arc<crate::modes::mesh::runtime::PolicyScopeCache>>,
    /// Mesh traffic direction stamped by the listener that accepted this
    /// request. `Some(Inbound)` for mesh inbound mTLS / HBONE termination
    /// listeners; `Some(Outbound)` for the outbound capture listener;
    /// `None` for non-mesh listeners (file/db/cp/dp HTTP entrypoints).
    ///
    /// Mesh-aware plugins (e.g., `workload_metrics`) gate span emission
    /// on this so a single plugin instance can serve both directions and
    /// CLIENT vs SERVER span kinds reflect which side of the hop the
    /// listener represents.
    pub mesh_direction: Option<MeshTrafficDirection>,
}

impl RequestContext {
    pub fn new(client_ip: String, method: String, path: String) -> Self {
        Self {
            client_ip,
            method,
            path,
            frontend_listen_port: None,
            raw_headers: None,
            headers: HashMap::new(),
            raw_query_string: None,
            query_params_materialized: false,
            query_params: HashMap::new(),
            matched_proxy: None,
            identified_consumer: None,
            authenticated_identity: None,
            authenticated_identity_header: None,
            auth_method: None,
            timestamp_received: Utc::now(),
            metadata: HashMap::new(),
            tls_client_cert_der: None,
            tls_client_cert_chain_der: None,
            peer_spiffe_id: None,
            plugin_http_call_ns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            mirror_result_rx: None,
            request_body_bytes: None,
            bytes_sent_observed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            is_early_data: false,
            route_override_upstream_id: None,
            route_override_backend_host: None,
            route_override_backend_port: None,
            route_override_resolved_tls: None,
            route_override_backend_read_timeout_ms: None,
            route_override_retry: None,
            route_override_request_transform: None,
            route_override_response_transform: None,
            node_waypoint_pod_uid: None,
            node_waypoint_policy_scope: None,
            mesh_direction: None,
        }
    }

    /// Build the lightweight compatibility context used by final request-body
    /// hooks when the active plugin needs request metadata after body
    /// transforms. Only `metadata` is copied back to the real context by the
    /// proxy caller, so this deliberately skips raw headers, raw query strings,
    /// parsed query maps, prebuffered body bytes, and mirror receivers.
    pub(crate) fn clone_for_final_request_body_hooks(&self) -> Self {
        Self {
            client_ip: self.client_ip.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            frontend_listen_port: self.frontend_listen_port,
            raw_headers: None,
            headers: self.headers.clone(),
            raw_query_string: None,
            query_params_materialized: false,
            query_params: HashMap::new(),
            matched_proxy: self.matched_proxy.clone(),
            identified_consumer: self.identified_consumer.clone(),
            authenticated_identity: self.authenticated_identity.clone(),
            authenticated_identity_header: self.authenticated_identity_header.clone(),
            auth_method: self.auth_method,
            timestamp_received: self.timestamp_received,
            metadata: self.metadata.clone(),
            tls_client_cert_der: self.tls_client_cert_der.clone(),
            tls_client_cert_chain_der: self.tls_client_cert_chain_der.clone(),
            peer_spiffe_id: self.peer_spiffe_id.clone(),
            plugin_http_call_ns: Arc::clone(&self.plugin_http_call_ns),
            mirror_result_rx: None,
            request_body_bytes: None,
            bytes_sent_observed: Arc::clone(&self.bytes_sent_observed),
            is_early_data: self.is_early_data,
            route_override_upstream_id: self.route_override_upstream_id.clone(),
            route_override_backend_host: self.route_override_backend_host.clone(),
            route_override_backend_port: self.route_override_backend_port,
            route_override_resolved_tls: self.route_override_resolved_tls.clone(),
            route_override_backend_read_timeout_ms: self.route_override_backend_read_timeout_ms,
            route_override_retry: self.route_override_retry.clone(),
            route_override_request_transform: self.route_override_request_transform.clone(),
            route_override_response_transform: self.route_override_response_transform.clone(),
            node_waypoint_pod_uid: self.node_waypoint_pod_uid,
            node_waypoint_policy_scope: self.node_waypoint_policy_scope.clone(),
            mesh_direction: self.mesh_direction,
        }
    }

    /// Effective upstream id for routing: plugin upstream override >
    /// direct-backend override (clears upstream) > proxy.upstream_id.
    /// Pool keys mentioning upstream identity must derive from this.
    #[inline]
    pub fn effective_upstream_id<'a>(&'a self, proxy: &'a Proxy) -> Option<&'a str> {
        if let Some(upstream_id) = self.route_override_upstream_id.as_deref() {
            return Some(upstream_id);
        }
        if self.route_override_backend_host.is_some() || self.route_override_backend_port.is_some()
        {
            return None;
        }
        proxy.upstream_id.as_deref()
    }

    /// Effective backend host for routing: plugin override > proxy.backend_host.
    #[inline]
    pub fn effective_backend_host<'a>(&'a self, proxy: &'a Proxy) -> &'a str {
        self.route_override_backend_host
            .as_deref()
            .unwrap_or(proxy.backend_host.as_str())
    }

    /// Effective backend port for routing: plugin override > proxy.backend_port.
    #[inline]
    pub fn effective_backend_port(&self, proxy: &Proxy) -> u16 {
        self.route_override_backend_port
            .unwrap_or(proxy.backend_port)
    }

    /// True when any of the route-override fields are set by a plugin.
    /// Used at dispatch entry to decide whether to clone the matched
    /// `Proxy` and bake in the overrides.
    #[inline]
    pub fn has_route_overrides(&self) -> bool {
        self.route_override_upstream_id.is_some()
            || self.route_override_backend_host.is_some()
            || self.route_override_backend_port.is_some()
            || self.route_override_resolved_tls.is_some()
            || self.route_override_backend_read_timeout_ms.is_some()
            || self.route_override_retry.is_some()
    }

    /// Build a `Proxy` Arc with any plugin-set route overrides applied. If no
    /// effective override is set, returns the original `Arc` (no struct alloc).
    /// When overrides change the proxy, allocates one `Proxy` struct + `Arc`.
    ///
    /// Downstream dispatch reads `proxy.upstream_id` / `proxy.backend_host` /
    /// `proxy.backend_port` / `proxy.resolved_tls` directly; using the
    /// returned `Arc<Proxy>` makes direct-backend overrides transparent to
    /// dispatch sites that already accept `&Proxy` (pool keys, capability
    /// registry, URL construction, backend TLS, etc.).
    ///
    /// Upstream-id overrides still need a later load-balancer target
    /// selection before `backend_host` / `backend_port` can be rebased. Any
    /// backend pool that keys or dials from those proxy fields must bake the
    /// selected target into its per-dispatch proxy after LB selection.
    ///
    /// This convenience helper cannot re-resolve `resolved_tls` when
    /// `route_override_upstream_id` points at a different upstream because it
    /// has no upstream snapshot. Custom dispatch paths that allow upstream
    /// overrides should call [`RequestContext::apply_route_overrides_with_upstreams`]
    /// instead, or they can silently keep the original proxy's backend TLS
    /// client certificate / CA / verify policy.
    pub fn apply_route_overrides(&self, proxy: Arc<Proxy>) -> Arc<Proxy> {
        self.apply_route_overrides_inner(proxy, None)
    }

    /// Build a `Proxy` Arc with plugin-set route overrides applied, re-resolving
    /// backend TLS from the supplied upstream snapshot when
    /// `route_override_upstream_id` changes the effective upstream.
    ///
    /// Use this variant for dispatch paths that might honor upstream-id
    /// overrides. It preserves the upstream-id / TLS / per-port-policy
    /// portion of the effective routing target. Pool-backed transports that
    /// read `proxy.backend_host` / `proxy.backend_port` directly must still
    /// rebase those fields after load-balancer target selection.
    pub fn apply_route_overrides_with_upstreams(
        &self,
        proxy: Arc<Proxy>,
        upstreams: &HashMap<String, Arc<Upstream>>,
    ) -> Arc<Proxy> {
        self.apply_route_overrides_inner(proxy, Some(upstreams))
    }

    fn apply_route_overrides_inner(
        &self,
        proxy: Arc<Proxy>,
        upstreams: Option<&HashMap<String, Arc<Upstream>>>,
    ) -> Arc<Proxy> {
        let direct_backend_override = self.route_override_upstream_id.is_none()
            && (self.route_override_backend_host.is_some()
                || self.route_override_backend_port.is_some());
        let upstream_id_changed = if direct_backend_override {
            proxy.upstream_id.is_some()
        } else {
            self.route_override_upstream_id
                .as_deref()
                .is_some_and(|id| proxy.upstream_id.as_deref() != Some(id))
        };
        let backend_host_changed = self
            .route_override_backend_host
            .as_deref()
            .is_some_and(|host| proxy.backend_host != host);
        let backend_port_changed = self
            .route_override_backend_port
            .is_some_and(|port| proxy.backend_port != port);

        let upstream_tls_override = if upstream_id_changed {
            self.route_override_upstream_id
                .as_deref()
                .and_then(|id| upstreams.and_then(|map| map.get(id)))
                .map(|upstream| BackendTlsConfig::from_upstream(upstream))
        } else {
            None
        };
        let direct_backend_tls_override = if direct_backend_override && proxy.upstream_id.is_some()
        {
            Some(BackendTlsConfig::from_proxy(&proxy))
        } else {
            None
        };
        let resolved_tls_override = self
            .route_override_resolved_tls
            .clone()
            .or(upstream_tls_override)
            .or(direct_backend_tls_override);
        let resolved_tls_changed = resolved_tls_override
            .as_ref()
            .is_some_and(|tls| *tls != proxy.resolved_tls);
        let dispatch_port_overrides_override = if upstream_id_changed {
            if direct_backend_override {
                Some(None)
            } else {
                Some(
                    self.route_override_upstream_id
                        .as_deref()
                        .and_then(|id| upstreams.and_then(|map| map.get(id)))
                        .and_then(|upstream| dispatch_port_overrides_from_upstream(upstream)),
                )
            }
        } else {
            None
        };
        let dispatch_port_overrides_changed = dispatch_port_overrides_override
            .as_ref()
            .is_some_and(|overrides| *overrides != proxy.dispatch_port_overrides);
        let backend_read_timeout_changed = self
            .route_override_backend_read_timeout_ms
            .is_some_and(|timeout| timeout != proxy.backend_read_timeout_ms);
        let retry_changed = self
            .route_override_retry
            .as_ref()
            .is_some_and(|retry| proxy.retry != *retry);

        if !upstream_id_changed
            && !backend_host_changed
            && !backend_port_changed
            && !resolved_tls_changed
            && !dispatch_port_overrides_changed
            && !backend_read_timeout_changed
            && !retry_changed
        {
            return proxy;
        }

        let mut overridden = (*proxy).clone();
        if let Some(id) = &self.route_override_upstream_id {
            overridden.upstream_id = Some(id.clone());
            if upstream_id_changed {
                overridden.upstream_subset = None;
            }
        } else if direct_backend_override {
            overridden.upstream_id = None;
            overridden.upstream_subset = None;
        }
        if let Some(host) = &self.route_override_backend_host {
            overridden.backend_host = host.clone();
        }
        if let Some(port) = self.route_override_backend_port {
            overridden.backend_port = port;
        }
        if let Some(resolved_tls) = resolved_tls_override {
            overridden.resolved_tls = resolved_tls;
        }
        if let Some(dispatch_port_overrides) = dispatch_port_overrides_override {
            overridden.dispatch_port_overrides = dispatch_port_overrides;
        }
        if let Some(timeout) = self.route_override_backend_read_timeout_ms {
            overridden.backend_read_timeout_ms = timeout;
        }
        if let Some(retry) = &self.route_override_retry {
            overridden.retry = retry.clone();
        }
        Arc::new(overridden)
    }

    // -- Lazy header materialization -----------------------------------------

    /// Store the raw `http::HeaderMap` for deferred materialization. Call this
    /// once at request init time instead of eagerly converting every header to
    /// owned `String`s.
    #[inline]
    pub fn set_raw_headers(&mut self, headers: HeaderMap) {
        self.raw_headers = Some(headers);
    }

    /// Look up a single header from the raw `HeaderMap` without materializing
    /// the full `HashMap<String, String>`. Returns `None` if the raw headers
    /// have already been consumed by `materialize_headers()`.
    ///
    /// Single hash lookup for call sites that only need one field-line value.
    /// Multiple `Host` headers are rejected earlier by `check_protocol_headers()`.
    /// For list-style headers that may span multiple field-lines (for example
    /// `x-forwarded-for`), use `raw_header_values()` and fold them explicitly.
    #[inline]
    pub fn raw_header_get(&self, name: &str) -> Option<&str> {
        self.raw_headers
            .as_ref()
            .and_then(|h| h.get(name))
            .and_then(|v| v.to_str().ok())
    }

    /// Iterate all values for a raw header without materializing the full
    /// header map. Returns an empty iterator if raw headers were already
    /// consumed.
    #[inline]
    pub fn raw_header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.raw_headers
            .iter()
            .flat_map(move |headers| headers.get_all(name).iter())
            .filter_map(|value| value.to_str().ok())
    }

    /// Convert the raw `http::HeaderMap` into `self.headers` (`HashMap<String,
    /// String>`). This is a one-time operation — subsequent calls are no-ops.
    /// Non-UTF-8 header values are silently skipped (same as the previous eager
    /// path).
    pub fn materialize_headers(&mut self) {
        if let Some(raw) = self.raw_headers.take() {
            self.headers.reserve(raw.keys_len());
            for (name, value) in &raw {
                if let Ok(v) = value.to_str() {
                    // http::HeaderName stores names in lowercase already (HTTP/2+3
                    // spec), and hyper normalizes HTTP/1.1 header names to
                    // lowercase at parse time. No `to_lowercase()` needed.
                    let key = name.as_str();
                    // Reserved gateway-asserted identity headers are never
                    // trusted from clients. They are injected after
                    // authentication from `identified_consumer`.
                    if matches!(key, "x-consumer-username" | "x-consumer-custom-id") {
                        continue;
                    }
                    if is_comma_folded_list_header(key) {
                        // These are list headers, so multiple field lines are
                        // equivalent to one comma-separated value. Preserve that
                        // before raw headers are consumed by materialization.
                        self.headers
                            .entry(key.to_owned())
                            .and_modify(|existing| {
                                existing.push(',');
                                existing.push_str(v);
                            })
                            .or_insert_with(|| v.to_owned());
                    } else {
                        self.headers.insert(key.to_owned(), v.to_owned());
                    }
                }
            }
        }
    }

    // -- Lazy query param materialization ------------------------------------

    /// Store the raw query string for deferred parsing. Call this once at
    /// request init time instead of eagerly percent-decoding every param.
    #[inline]
    pub fn set_raw_query_string(&mut self, qs: String) {
        self.query_params.clear();
        self.query_params_materialized = false;
        self.raw_query_string = (!qs.is_empty()).then_some(qs);
    }

    /// Borrow the raw query string without materializing it.
    ///
    /// Inspection plugins use this to detect duplicate/conflicting parameter
    /// keys that would be collapsed by the parsed `HashMap`.
    #[inline]
    pub fn raw_query_string(&self) -> Option<&str> {
        self.raw_query_string.as_deref()
    }

    /// Parse the raw query string into `self.query_params`. Keys and values are
    /// percent-decoded so plugins see human-readable strings. Parameters without
    /// `=` (e.g., `?flag`) are stored with an empty-string value.
    ///
    /// This is a one-time operation — subsequent calls are no-ops. The raw
    /// query string is intentionally retained for later security inspection.
    pub fn materialize_query_params(&mut self) {
        if self.query_params_materialized {
            return;
        }
        if let Some(raw) = self.raw_query_string.as_deref() {
            for pair in raw.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = if let Some((k, v)) = pair.split_once('=') {
                    (k, v)
                } else {
                    (pair, "")
                };
                let decoded_k = percent_decode_str(k).decode_utf8_lossy();
                let decoded_v = percent_decode_str(v).decode_utf8_lossy();
                self.query_params
                    .insert(decoded_k.into_owned(), decoded_v.into_owned());
            }
        }
        self.query_params_materialized = true;
    }

    /// Materialize the raw query string into `self.query_params` without
    /// percent-decoding.
    ///
    /// HTTP/3 uses this by default to preserve its legacy plugin-visible query
    /// representation unless an active plugin explicitly opts into decoded
    /// query params.
    pub fn materialize_query_params_raw(&mut self) {
        if self.query_params_materialized {
            return;
        }
        if let Some(raw) = self.raw_query_string.as_deref() {
            for pair in raw.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    self.query_params.insert(k.to_string(), v.to_string());
                }
            }
        }
        self.query_params_materialized = true;
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

/// Headers that are materialized by comma-folding repeated request values.
///
/// This is used both when `RequestContext` is built and when the WebSocket
/// proxy path reconstructs the materialized form to decide whether raw
/// repeated headers can be preserved for the backend handshake.
pub(crate) fn is_comma_folded_list_header(name: &str) -> bool {
    matches!(name, "baggage" | "sec-websocket-protocol")
}

fn dispatch_port_overrides_from_upstream(
    upstream: &Upstream,
) -> Option<HashMap<u16, ResolvedPortOverride>> {
    let overrides: HashMap<u16, ResolvedPortOverride> = upstream
        .port_overrides
        .iter()
        .filter_map(|(port, ovr)| {
            ResolvedPortOverride::from_upstream_override(ovr).map(|resolved| (*port, resolved))
        })
        .collect();
    if overrides.is_empty() {
        None
    } else {
        Some(overrides)
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

/// Serde skip predicate: true when the value is zero. Used to keep logs tidy
/// when new u64 counters are unset for a given transaction.
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Which direction of a bidirectional stream experienced a failure first.
///
/// Used by TCP/UDP/WebSocket disconnect logging so operators can tell whether
/// the client or the backend initiated the disconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Error originated on the client→backend half of the stream.
    ClientToBackend,
    /// Error originated on the backend→client half of the stream.
    BackendToClient,
    /// Direction could not be determined (both halves failed simultaneously,
    /// or the error occurred outside the copy loop).
    Unknown,
}

/// Cause of a stream (TCP/UDP) disconnect.
///
/// Disambiguates idle-timeout expiry from read/write errors so log consumers
/// don't have to rely on `error_class: None` as an implicit timeout signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectCause {
    /// Session exceeded the configured idle timeout without traffic.
    IdleTimeout,
    /// Frontend (client-side) recv/read returned an error.
    RecvError,
    /// Backend recv/read returned an error (e.g., backend closed the socket).
    BackendError,
    /// Clean shutdown initiated by either peer (e.g., FIN, graceful close frame).
    GracefulShutdown,
}

/// Transaction summary for logging plugins.
///
/// Implements [`Default`] so call sites that build partial summaries
/// (early-return error paths, rejected requests, etc.) can use struct
/// update syntax — `..TransactionSummary::default()` — instead of
/// hardcoding every field. Future additions to this struct get an
/// automatic default value at all update-syntax call sites; old call
/// sites that enumerate every field still require a manual edit, which
/// is also fine because it flags the deliberate choice.
///
/// Prefer the update syntax when adding new log sites:
/// ```ignore
/// TransactionSummary {
///     namespace: proxy.namespace.clone(),
///     timestamp_received: ctx.timestamp_received.to_rfc3339(),
///     client_ip: ctx.client_ip.clone(),
///     http_method: method,
///     request_path: path,
///     response_status_code: status,
///     error_class: Some(class),
///     ..TransactionSummary::default()
/// }
/// ```
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TransactionSummary {
    /// Namespace of the matched proxy.
    pub namespace: String,
    pub timestamp_received: String,
    pub client_ip: String,
    pub consumer_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<&'static str>,
    pub http_method: String,
    pub request_path: String,
    /// ID of the proxy that matched this request, or `None` when the request
    /// was rejected before routing (no proxy matched the host/path). Same
    /// JSON key as `StreamTransactionSummary.proxy_id` so log consumers see
    /// a single `proxy_id` field across HTTP, gRPC, WebSocket, TCP, UDP, and
    /// DTLS transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    /// Human-friendly proxy name; same JSON key as
    /// `StreamTransactionSummary.proxy_name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_name: Option<String>,
    /// Backend the request was forwarded to. For HTTP this is the full URL
    /// (`scheme://host:port/path`); `None` when the request was rejected
    /// before backend selection. Same JSON key as
    /// `StreamTransactionSummary.backend_target` (which is always set and
    /// uses `host:port` form, since stream proxies have no path).
    pub backend_target: Option<String>,
    /// The DNS-resolved IP address of the backend that was connected to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_resolved_ip: Option<String>,
    pub response_status_code: u16,
    pub latency_total_ms: f64,
    pub latency_gateway_processing_ms: f64,
    pub latency_backend_ttfb_ms: f64,
    /// Total backend time from connection start to the final response frame.
    ///
    /// Semantics by response type:
    /// * **Buffered responses**: exact — set synchronously when the body has
    ///   been fully received, before the summary is logged.
    /// * **Streaming responses**: re-derived at deferred-log fire time from
    ///   the real body-completion timestamp. Replaces the `-1.0` sentinel
    ///   that was written at header-flush time. If the body never completes
    ///   (client disconnect before the first frame, drop without any poll),
    ///   the field may remain at the original `-1.0` sentinel — prefer
    ///   `latency_backend_ttfb_ms` for alerting on streaming outcomes when
    ///   you need a guaranteed non-sentinel value.
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
    /// When true, `latency_backend_total_ms` is populated at deferred-log
    /// fire time from the real body-completion timestamp (see that field).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub response_streamed: bool,
    /// True when the client disconnected before receiving the full response.
    ///
    /// Semantics by response type:
    /// * **Streaming responses**: accurate — set by the deferred-logging path
    ///   when the response body wrapper (`ProxyBody`) observes a disconnect
    ///   error frame, or when the wrapper is dropped before reaching
    ///   end-of-stream (see `deferred_log::DeferredTransactionLogger`).
    /// * **Buffered responses**: best-effort. Hyper only signals client
    ///   send failures at the connection-error handler, which fires after
    ///   the handler function has already constructed and emitted the
    ///   summary. Consumers should treat `false` on a buffered response
    ///   as "not known to have disconnected," not as a positive assertion.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub client_disconnected: bool,
    /// Human-friendly classification of the error when the gateway itself
    /// failed to communicate with the backend. `None` for successful requests
    /// and normal HTTP error responses from the backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<crate::retry::ErrorClass>,
    /// Classification of an error that occurred while streaming the response
    /// body to the client (e.g., client RST after headers were sent). `None`
    /// when the body streamed successfully or when no streaming occurred.
    ///
    /// Distinct from `error_class`, which covers errors reaching the backend.
    /// Populated by the deferred-logging path when the response body wrapper
    /// returns an error frame or is dropped before completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_error_class: Option<crate::retry::ErrorClass>,
    /// True when the response body finished streaming all frames successfully.
    /// False when streaming was interrupted (client disconnect, backend RST,
    /// body size limit exceeded) or when no streaming occurred.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub body_completed: bool,
    /// Bytes of the request body relayed from the client to the backend
    /// (gateway-perspective: bytes it sent onward on the client's behalf).
    /// Same JSON key as `StreamTransactionSummary.bytes_sent`.
    ///
    /// Accuracy by request type:
    /// * **Buffered requests** (plugins required the body, or retries were
    ///   configured): exact — populated from the collected body length after
    ///   `Incoming::collect().await` (optionally via `SizeLimitedIncoming::bytes_seen()`
    ///   when a size limit is in force).
    /// * **Streaming requests** (body forwarded frame-by-frame without
    ///   collection): exact — populated via `CountingIncoming`, which shares
    ///   an `Arc<AtomicU64>` between the forwarded body and the summary
    ///   builder so the final byte count is visible once hyper has consumed
    ///   the body.
    /// * **Empty / GET / HEAD / size-zero requests**: zero (skipped during
    ///   serialization via `skip_serializing_if = "is_zero_u64"`).
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub bytes_sent: u64,
    /// Bytes of the response body relayed from the backend to the client
    /// (gateway-perspective: bytes it received and forwarded back). Unified
    /// streaming + buffered counter. Same JSON key as
    /// `StreamTransactionSummary.bytes_received`.
    ///
    /// Population sites:
    /// * **Buffered responses** (`ResponseBody::Buffered`, plugin rejects,
    ///   gRPC trailers-only error, gRPC buffered-success, H3 buffered path,
    ///   WS error path): populated synchronously from the final `Bytes::len()`
    ///   before the summary is logged.
    /// * **Streaming responses**: populated at deferred-log fire time from
    ///   the body counter. On a client disconnect mid-stream this reflects
    ///   bytes actually flushed before the disconnect.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub bytes_received: u64,
    /// True when this summary represents a mirror (shadow) request, not the
    /// actual client-facing proxy traffic. Logged as a separate entry with the
    /// same schema so existing log queries and dashboards work without changes.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub mirror: bool,
    /// Plugin-injected metadata. Sensitive keys (authorization, cookie,
    /// credential/session tokens, secrets — see
    /// `plugins::utils::metadata_redaction::DEFAULT_SENSITIVE_METADATA_KEYS`
    /// plus operator extras from `FERRUM_LOG_REDACT_METADATA_KEYS`) are
    /// replaced with `[REDACTED]` at serialize time. The in-memory value is
    /// untouched so other plugin phases can still read the original.
    #[serde(
        serialize_with = "crate::plugins::utils::metadata_redaction::serialize_redacted_metadata"
    )]
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
        mirror.backend_target = Some(result.mirror_target_url);
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
        mirror.body_error_class = None;
        mirror.body_completed = false;
        // Mirror traffic is fire-and-forget from the client's perspective — body
        // byte counters from the primary transaction are not meaningful on the
        // mirror summary. Mirror response size goes into metadata instead.
        mirror.bytes_sent = 0;
        mirror.bytes_received = 0;
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
///
/// Some proxy paths call this with an empty plugin slice so runtime transaction
/// metrics still see no-plugin error and streaming-disconnect outcomes.
pub async fn log_with_mirror(
    plugins: &[Arc<dyn Plugin>],
    summary: &TransactionSummary,
    ctx: &RequestContext,
) {
    for plugin in plugins {
        plugin.log(summary).await;
    }
    crate::runtime_metrics::global_ref().record_transaction(summary);
    if let Some(mirror_result) = ctx.collect_mirror_result().await {
        let mirror_summary = summary.as_mirror_entry(mirror_result);
        for plugin in plugins {
            plugin.log(&mirror_summary).await;
        }
    }
}

/// Context for stream proxy (TCP/UDP) plugin hooks.
///
/// Fields like `proxy_id`, `proxy_name`, `listen_port`, and `backend_scheme`
/// are available for custom plugins to use in their `on_stream_connect` logic.
#[derive(Clone)]
#[allow(dead_code)]
pub struct StreamConnectionContext {
    pub client_ip: String,
    pub proxy_id: String,
    pub proxy_name: Option<String>,
    pub listen_port: u16,
    /// Wire-level scheme the proxy uses to talk to its backend.
    /// Always one of the stream variants (`Tcp`, `Tcps`, `Udp`, `Dtls`) —
    /// validation guarantees stream proxies have a scheme set before any
    /// listener is bound, so this is non-optional.
    pub backend_scheme: BackendScheme,
    /// Pre-built consumer index shared across stream connections.
    pub consumer_index: Arc<ConsumerIndex>,
    /// Gateway Consumer identified for this stream connection, if any.
    pub identified_consumer: Option<Arc<Consumer>>,
    /// Identity string set by external stream auth plugins when no gateway
    /// Consumer was mapped. Mirrors `RequestContext::authenticated_identity`.
    pub authenticated_identity: Option<String>,
    /// Authentication mechanism that succeeded for this stream connection.
    /// Mirrors `RequestContext::auth_method`.
    pub auth_method: Option<&'static str>,
    /// Plugin metadata. Lazily allocated on first write to avoid a HashMap allocation
    /// for stream connections that have no metadata-writing plugins configured.
    pub metadata: Option<HashMap<String, String>>,
    /// DER-encoded client certificate from frontend TLS handshake (first cert in chain).
    /// Populated for TCP/TLS proxies after the TLS handshake completes.
    /// Used by plugins like `tcp_connection_throttle` for consumer-based throttling.
    pub tls_client_cert_der: Option<Arc<Vec<u8>>>,
    /// DER-encoded CA/intermediate certificates from the client's certificate chain.
    /// Contains all certificates after the peer cert (index 1+) sent during the handshake.
    pub tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    /// SNI hostname extracted from the TLS/DTLS ClientHello during passthrough mode.
    /// Populated only for proxies with `passthrough: true`. Available to plugins for
    /// logging, routing, or access control without requiring TLS termination.
    pub sni_hostname: Option<String>,
    /// Mesh traffic direction stamped by the stream listener that accepted this
    /// connection. Mirrors `RequestContext::mesh_direction`; `None` for stream
    /// proxies that are not part of a mesh listener.
    pub mesh_direction: Option<MeshTrafficDirection>,
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

    /// Insert a metadata value, lazily allocating the map on first write.
    pub fn insert_metadata(&mut self, key: String, value: String) {
        self.metadata
            .get_or_insert_with(HashMap::new)
            .insert(key, value);
    }

    /// Take the metadata map, returning an empty map if never allocated.
    pub fn take_metadata(&mut self) -> HashMap<String, String> {
        self.metadata.take().unwrap_or_default()
    }
}

/// Transaction summary for stream proxy (TCP/UDP) logging plugins.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamTransactionSummary {
    /// Namespace of the matched proxy.
    pub namespace: String,
    pub proxy_id: String,
    pub proxy_name: Option<String>,
    pub client_ip: String,
    /// Identified consumer username (from gateway Consumer mapping) or external
    /// authenticated identity (e.g., JWKS subject) set by stream auth plugins.
    /// `None` when no authentication plugin identified the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer_username: Option<String>,
    /// Authentication mechanism that succeeded for this stream connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<&'static str>,
    pub backend_target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_resolved_ip: Option<String>,
    pub protocol: String,
    pub listen_port: u16,
    pub duration_ms: f64,
    /// Bytes relayed from the client to the backend
    /// (gateway-perspective: bytes it sent onward on the client's behalf).
    pub bytes_sent: u64,
    /// Bytes relayed from the backend to the client
    /// (gateway-perspective: bytes it received and forwarded back).
    pub bytes_received: u64,
    pub connection_error: Option<String>,
    /// Human-friendly classification of the connection error, if any.
    /// Mirrors the `ErrorClass` used for HTTP/gRPC transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<crate::retry::ErrorClass>,
    /// Which direction of the bidirectional stream failed first.
    /// `None` for clean shutdowns or timeouts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnect_direction: Option<Direction>,
    /// Cause of the disconnect (idle timeout vs. recv error vs. graceful shutdown).
    /// Disambiguates the implicit `error_class: None` timeout convention.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnect_cause: Option<DisconnectCause>,
    pub timestamp_connected: String,
    pub timestamp_disconnected: String,
    /// SNI hostname extracted from the TLS/DTLS ClientHello during passthrough mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni_hostname: Option<String>,
    /// Plugin-injected metadata (e.g., correlation ID, trace ID) carried
    /// from `on_stream_connect` to `on_stream_disconnect`. Sensitive keys
    /// (authorization, cookie, credential/session tokens, secrets — see
    /// `plugins::utils::metadata_redaction::DEFAULT_SENSITIVE_METADATA_KEYS`
    /// plus operator extras from `FERRUM_LOG_REDACT_METADATA_KEYS`) are
    /// replaced with `[REDACTED]` at serialize time.
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "crate::plugins::utils::metadata_redaction::serialize_redacted_metadata"
    )]
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
/// | Early     | 0–949       | Pre-routing, tracing, and preflight       | otel_tracing (25), correlation_id (50), cors (100), request_termination (125), mesh_outbound_registry (130), ip_restriction (150), bot_detection (200), sse (250), grpc_web (260), grpc_method_router (275), spiffe_identity (940) |
/// | AuthN     | 950–1999    | Authentication / identity verification    | mtls_auth (950), jwks_auth (1000), jwt_auth (1100), key_auth (1200), ldap_auth (1250), basic_auth (1300), hmac_auth (1400), soap_ws_security (1500) |
/// | AuthZ     | 2000–2999   | Authorization and admission control       | access_control (2000), tcp_connection_throttle (2050), mesh_authz (2075), request_size_limiting (2800), graphql (2850), rate_limiting (2900), ai_prompt_shield (2925), waf (2930), body_validator (2950), ai_request_guard (2975), ai_federation (2985) |
/// | Transform | 3000–3999   | Request shaping and response buffering    | request_transformer (3000), serverless_function (3025), response_mock (3030), grpc_deadline (3050), request_mirror (3075), response_size_limiting (3490), response_caching (3500) |
/// | Response  | 4000–4999   | Response transformation and AI accounting | response_transformer (4000), ai_token_metrics (4100), ai_rate_limiter (4200) |
/// | Logging   | 9000–9999   | Observability and frame logging           | stdout_logging (9000), ws_frame_logging (9050), statsd_logging (9075), http_logging (9100), tcp_logging (9125), kafka_logging (9150), loki_logging (9155), udp_logging (9160), ws_logging (9175), transaction_debugger (9200), prometheus_metrics (9300), api_chargeback (9350), workload_metrics (9360), __mesh_bpf_metrics (9365), access_log (9375) |
#[allow(dead_code)]
pub mod priority {
    pub const OTEL_TRACING: u16 = 25;
    pub const CORRELATION_ID: u16 = 50;
    pub const CORS: u16 = 100;
    pub const REQUEST_TERMINATION: u16 = 125;
    /// `mesh_outbound_registry`: rejects outbound requests whose
    /// destination is not in the mesh registry. Auto-injected only when
    /// `MeshConfig.outbound_traffic_policy == RegistryOnly`. Runs in the
    /// `on_request_received` band so the rejection is visible to all
    /// downstream observability without engaging the auth pipeline.
    pub const MESH_OUTBOUND_REGISTRY: u16 = 130;
    pub const IP_RESTRICTION: u16 = 150;
    pub const GEO_RESTRICTION: u16 = 175;
    pub const BOT_DETECTION: u16 = 200;
    pub const SPEC_EXPOSE: u16 = 210;
    pub const SSE: u16 = 250;
    pub const GRPC_WEB: u16 = 260;
    pub const GRPC_METHOD_ROUTER: u16 = 275;
    pub const SPIFFE_IDENTITY: u16 = 940;
    pub const MTLS_AUTH: u16 = 950;
    pub const JWKS_AUTH: u16 = 1000;
    pub const JWT_AUTH: u16 = 1100;
    pub const KEY_AUTH: u16 = 1200;
    pub const LDAP_AUTH: u16 = 1250;
    pub const BASIC_AUTH: u16 = 1300;
    pub const HMAC_AUTH: u16 = 1400;
    pub const SOAP_WS_SECURITY: u16 = 1500;
    pub const ACCESS_CONTROL: u16 = 2000;
    pub const TCP_CONNECTION_THROTTLE: u16 = 2050;
    pub const MESH_AUTHZ: u16 = 2075;
    pub const AI_SEMANTIC_CACHE: u16 = 2700;
    pub const REQUEST_DEDUPLICATION: u16 = 2750;
    pub const REQUEST_SIZE_LIMITING: u16 = 2800;
    pub const GRAPHQL: u16 = 2850;
    pub const RATE_LIMITING: u16 = 2900;
    pub const AI_PROMPT_SHIELD: u16 = 2925;
    pub const WAF: u16 = 2930;
    pub const FAULT_INJECTION: u16 = 2940;
    pub const BODY_VALIDATOR: u16 = 2950;
    pub const AI_REQUEST_GUARD: u16 = 2975;
    pub const AI_FEDERATION: u16 = 2985;
    /// `mesh_route_dispatch`: rewrites `route_override_*` on `RequestContext`
    /// based on Istio VirtualService method/header/query-param predicates.
    /// Runs after admission plugins and immediately before request-transform
    /// plugins; backend dispatch applies the override after `before_proxy`.
    pub const MESH_ROUTE_DISPATCH: u16 = 2995;
    pub const REQUEST_TRANSFORMER: u16 = 3000;
    pub const SERVERLESS_FUNCTION: u16 = 3025;
    pub const RESPONSE_MOCK: u16 = 3030;
    pub const GRPC_DEADLINE: u16 = 3050;
    pub const REQUEST_MIRROR: u16 = 3075;
    pub const LOAD_TESTING: u16 = 3080;
    pub const RESPONSE_SIZE_LIMITING: u16 = 3490;
    pub const RESPONSE_CACHING: u16 = 3500;
    pub const RESPONSE_TRANSFORMER: u16 = 4000;
    pub const COMPRESSION: u16 = 4050;
    pub const AI_RESPONSE_GUARD: u16 = 4075;
    pub const AI_TOKEN_METRICS: u16 = 4100;
    pub const AI_RATE_LIMITER: u16 = 4200;
    pub const STDOUT_LOGGING: u16 = 9000;
    pub const STATSD_LOGGING: u16 = 9075;
    pub const HTTP_LOGGING: u16 = 9100;
    pub const TCP_LOGGING: u16 = 9125;
    pub const KAFKA_LOGGING: u16 = 9150;
    pub const LOKI_LOGGING: u16 = 9155;
    pub const UDP_LOGGING: u16 = 9160;
    pub const TRANSACTION_DEBUGGER: u16 = 9200;
    pub const PROXY_ALERTS: u16 = 9250;
    pub const PROMETHEUS_METRICS: u16 = 9300;
    pub const API_CHARGEBACK: u16 = 9350;
    pub const WORKLOAD_METRICS: u16 = 9360;
    /// `__mesh_bpf_metrics`: exposes TCP-layer counters (Connect, Accept,
    /// Rst, Fin, SRTT, BPF drop reasons, ringbuf overrun) from the
    /// SOCK_OPS event consumer. Auto-injected only when topology is
    /// `NodeWaypoint`. Lives in the observability band alongside other
    /// metric-emitter plugins so its `log` hook runs after all
    /// transaction-summary serialization.
    pub const MESH_BPF_METRICS: u16 = 9365;
    pub const ACCESS_LOG: u16 = 9375;
    /// `transaction_log_schema` is a config-only plugin with no lifecycle
    /// hooks; its priority is irrelevant in practice but is kept at the
    /// top of the logging band so any future hook would run after all
    /// observability sinks.
    pub const TRANSACTION_LOG_SCHEMA: u16 = 9999;
    pub const WS_MESSAGE_SIZE_LIMITING: u16 = 2810;
    pub const WS_RATE_LIMITING: u16 = 2910;
    pub const WS_LOGGING: u16 = 9175;
    pub const WS_FRAME_LOGGING: u16 = 9050;
    pub const UDP_RATE_LIMITING: u16 = 2915;
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

    /// Returns `true` if this plugin needs the raw request body to be available
    /// during the `authenticate` phase.
    ///
    /// This is even narrower than `requires_request_body_before_before_proxy()`:
    /// it forces request body buffering BEFORE the authenticate phase runs, so
    /// auth plugins can verify body integrity (e.g., HMAC signing string that
    /// covers a `Digest:` header per RFC 9421 / RFC 3230).
    ///
    /// Override this only for auth plugins that perform body integrity checks
    /// at authentication time (e.g., `hmac_auth`).
    fn requires_request_body_before_authenticate(&self) -> bool {
        false
    }

    /// Returns `true` if this plugin needs binary-safe access to the raw
    /// request body bytes via `ctx.request_body_bytes`.
    ///
    /// Most plugins read the body from `ctx.metadata["request_body"]` which
    /// is UTF-8 only. This flag gates a `Bytes::copy_from_slice` allocation
    /// that would otherwise run on every buffered request. Only override
    /// this for plugins that handle non-UTF-8 payloads (e.g., gRPC protobuf).
    fn needs_request_body_bytes(&self) -> bool {
        false
    }

    /// Returns `true` if this plugin may require the request body to be
    /// buffered instead of streamed for at least some requests.
    ///
    /// The gateway uses this as a config-time upper bound in `PluginCache`.
    /// Request-time body buffering can still remain disabled when
    /// `should_buffer_request_body()` returns `false` for the current request.
    fn requires_request_body_buffering(&self) -> bool {
        self.modifies_request_body()
            || self.requires_request_body_before_before_proxy()
            || self.requires_request_body_before_authenticate()
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

    /// Returns `true` when the current request's response should be buffered
    /// for this plugin.
    ///
    /// This is the response-side equivalent of `should_buffer_request_body()`:
    /// a per-request refinement that lets plugins skip buffering when the
    /// response is clearly irrelevant (e.g., `compression` skipping when
    /// `Accept-Encoding` is absent, `ai_token_metrics` skipping for non-AI
    /// content-types).
    ///
    /// Only called when `requires_response_body_buffering()` returns `true`
    /// (the config-time upper bound). Override this for content-type-sensitive
    /// or header-sensitive response plugins.
    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        self.requires_response_body_buffering()
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

    /// Context-aware variant of `on_final_request_body`.
    ///
    /// Existing plugins can keep overriding `on_final_request_body`. Plugins
    /// that need to annotate request metadata after request body transforms
    /// can override this hook and the proxy will call it instead.
    ///
    /// **Contract on the H1/H2 path**: `ctx` is a lightweight clone built by
    /// [`RequestContext::clone_for_final_request_body_hooks`]; only
    /// `ctx.metadata` is copied back to the real request context after the
    /// hook returns. Mutations to other fields (`ctx.headers`,
    /// `ctx.query_params`, `ctx.route_override_*`, …) on H1/H2 are dropped.
    /// On the H3 path the hook receives the real `&mut RequestContext`, so
    /// implementations MUST limit observable side effects to `ctx.metadata`
    /// if they want consistent behavior across protocols.
    async fn on_final_request_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.on_final_request_body(headers, body).await
    }

    /// Returns true when `on_final_request_body_with_context` needs the real
    /// mutable request context rather than the compatibility wrapper.
    fn needs_final_request_body_context(&self) -> bool {
        false
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

    /// Returns `true` if this plugin participates in the authorization phase.
    ///
    /// The gateway uses this to pre-filter authorize callbacks at config
    /// reload time when a plugin can safely declare it has no authorization
    /// work. The default stays `true` so existing custom plugins that already
    /// override `authorize()` keep running after upgrade.
    fn is_authorize_plugin(&self) -> bool {
        true
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
    /// Default is HTTP-only.
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

    /// Returns `true` if this plugin needs notification when a WebSocket
    /// session ends. Zero overhead when `false` (default) — the relay teardown
    /// path skips constructing the context and iterating plugins.
    ///
    /// Mirrors the opt-in pattern used by `requires_ws_frame_hooks()` and
    /// `requires_udp_datagram_hooks()` so most deployments pay no cost.
    fn requires_ws_disconnect_hooks(&self) -> bool {
        false
    }

    /// Called when a WebSocket session (H1 upgrade or H2 Extended CONNECT)
    /// terminates. Receives a summary of the session including directional
    /// failure classification and per-direction frame counts.
    ///
    /// Default no-op. Plugins wanting end-of-session observability should
    /// override this and set `requires_ws_disconnect_hooks()` to `true`.
    async fn on_ws_disconnect(&self, _ctx: &WsDisconnectContext) {}

    /// Returns `true` when this plugin requires HTTP/3 query params to use the
    /// percent-decoded representation. HTTP/3 historically exposed raw query
    /// params to plugins, so this opt-in is intentionally narrow: enabling it
    /// affects the shared `ctx.query_params` map for all plugins on the proxy.
    fn requires_decoded_query_params(&self) -> bool {
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

    /// Returns the JWKS URIs this plugin is actively using.
    ///
    /// Only meaningful for `jwks_auth` — returns the JWKS endpoint URIs from
    /// its configured providers. Used by the plugin cache to clean up stale
    /// JWKS cache entries (and their background refresh tasks) when plugins
    /// are removed from config.
    fn active_jwks_uris(&self) -> Vec<String> {
        Vec::new()
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
        "stdout_logging" => Ok(Some(Arc::new(stdout_logging::StdoutLogging::new(config)?))),
        "transaction_log_schema" => Ok(Some(Arc::new(
            transaction_log_schema::TransactionLogSchema::new(config)?,
        ))),
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
        "udp_logging" => Ok(Some(Arc::new(udp_logging::UdpLogging::new(
            config,
            http_client,
        )?))),
        "kafka_logging" => Ok(Some(Arc::new(kafka_logging::KafkaLogging::new(
            config,
            &http_client,
        )?))),
        "transaction_debugger" => Ok(Some(Arc::new(
            transaction_debugger::TransactionDebugger::new(config)?,
        ))),
        "jwks_auth" => Ok(Some(Arc::new(jwks_auth::JwksAuth::new(
            config,
            http_client.clone(),
        )?))),
        "jwt_auth" => Ok(Some(Arc::new(jwt_auth::JwtAuth::new(config)?))),
        "key_auth" => Ok(Some(Arc::new(key_auth::KeyAuth::new(config)?))),
        "basic_auth" => Ok(Some(Arc::new(basic_auth::BasicAuth::new(config)?))),
        "ldap_auth" => Ok(Some(Arc::new(ldap_auth::LdapAuth::new(
            config,
            http_client,
        )?))),
        "hmac_auth" => Ok(Some(Arc::new(hmac_auth::HmacAuth::new(config)?))),
        "mtls_auth" => Ok(Some(Arc::new(mtls_auth::MtlsAuth::new(config)?))),
        "spiffe_identity" => Ok(Some(Arc::new(mesh::spiffe_identity::SpiffeIdentity::new(
            config,
        )?))),
        "compression" => Ok(Some(Arc::new(compression::CompressionPlugin::new(config)?))),
        "cors" => Ok(Some(Arc::new(cors::CorsPlugin::new(config)?))),
        "access_control" => Ok(Some(Arc::new(access_control::AccessControl::new(config)?))),
        "tcp_connection_throttle" => Ok(Some(Arc::new(
            tcp_connection_throttle::TcpConnectionThrottle::new(config)?,
        ))),
        "mesh_authz" => Ok(Some(Arc::new(mesh::authz::MeshAuthz::new(config)?))),
        "mesh_outbound_registry" => Ok(Some(Arc::new(
            mesh::outbound_registry::OutboundRegistry::new(config)?,
        ))),
        "ip_restriction" => Ok(Some(Arc::new(ip_restriction::IpRestriction::new(config)?))),
        "geo_restriction" => Ok(Some(Arc::new(geo_restriction::GeoRestriction::new(
            config,
        )?))),
        "bot_detection" => Ok(Some(Arc::new(bot_detection::BotDetection::new(config)?))),
        "correlation_id" => Ok(Some(Arc::new(correlation_id::CorrelationId::new(config)?))),
        "request_transformer" => Ok(Some(Arc::new(
            request_transformer::RequestTransformer::new(config)?,
        ))),
        "mesh_route_dispatch" => Ok(Some(Arc::new(mesh_route_dispatch::MeshRouteDispatch::new(
            config,
        )?))),
        "response_transformer" => Ok(Some(Arc::new(
            response_transformer::ResponseTransformer::new(config)?,
        ))),
        "sse" => Ok(Some(Arc::new(sse::SsePlugin::new(config)?))),
        "graphql" => Ok(Some(Arc::new(graphql::GraphqlPlugin::new(
            config,
            http_client.clone(),
        )?))),
        "grpc_method_router" => Ok(Some(Arc::new(grpc_method_router::GrpcMethodRouter::new(
            config,
            http_client.clone(),
        )?))),
        "grpc_deadline" => Ok(Some(Arc::new(grpc_deadline::GrpcDeadline::new(config)?))),
        "grpc_web" => Ok(Some(Arc::new(grpc_web::GrpcWebPlugin::new(config)?))),
        "rate_limiting" => Ok(Some(Arc::new(rate_limiting::RateLimiting::new(
            config,
            http_client.clone(),
        )?))),
        "request_mirror" => Ok(Some(Arc::new(request_mirror::RequestMirror::new(
            config,
            http_client.clone(),
        )?))),
        "load_testing" => Ok(Some(Arc::new(load_testing::LoadTesting::new(
            config,
            http_client.clone(),
        )?))),
        "request_deduplication" => Ok(Some(Arc::new(
            request_deduplication::RequestDeduplication::new(config, http_client.clone())?,
        ))),
        "request_size_limiting" => Ok(Some(Arc::new(
            request_size_limiting::RequestSizeLimiting::new(config)?,
        ))),
        "waf" => Ok(Some(Arc::new(waf::Waf::new(config)?))),
        "response_size_limiting" => Ok(Some(Arc::new(
            response_size_limiting::ResponseSizeLimiting::new(config)?,
        ))),
        "body_validator" => Ok(Some(Arc::new(body_validator::BodyValidator::new(config)?))),
        "soap_ws_security" => Ok(Some(Arc::new(soap_ws_security::SoapWsSecurity::new(
            config,
        )?))),
        "request_termination" => Ok(Some(Arc::new(
            request_termination::RequestTermination::new(config)?,
        ))),
        "response_caching" => Ok(Some(Arc::new(response_caching::ResponseCaching::new(
            config,
        )?))),
        "fault_injection" => Ok(Some(Arc::new(fault_injection::FaultInjectionPlugin::new(
            config,
        )?))),
        "response_mock" => Ok(Some(Arc::new(response_mock::ResponseMock::new(config)?))),
        "serverless_function" => Ok(Some(Arc::new(
            serverless_function::ServerlessFunction::new(config, http_client)?,
        ))),
        "prometheus_metrics" => Ok(Some(Arc::new(prometheus_metrics::PrometheusMetrics::new(
            config,
            http_client.namespace(),
        )?))),
        "proxy_alerts" => Ok(Some(Arc::new(proxy_alerts::ProxyAlerts::new(
            config,
            http_client.clone(),
        )?))),
        "api_chargeback" => Ok(Some(Arc::new(api_chargeback::ApiChargeback::new(
            config,
            http_client.namespace(),
        )?))),
        "otel_tracing" => Ok(Some(Arc::new(
            otel_tracing::OtelTracing::new_with_http_client(config, http_client)?,
        ))),
        "ai_token_metrics" => Ok(Some(Arc::new(ai_token_metrics::AiTokenMetrics::new(
            config,
        )?))),
        "ai_request_guard" => Ok(Some(Arc::new(ai_request_guard::AiRequestGuard::new(
            config,
        )?))),
        "ai_rate_limiter" => Ok(Some(Arc::new(ai_rate_limiter::AiRateLimiter::new(
            config,
            http_client.clone(),
        )?))),
        "ai_prompt_shield" => Ok(Some(Arc::new(ai_prompt_shield::AiPromptShield::new(
            config,
        )?))),
        "ai_semantic_cache" => Ok(Some(Arc::new(ai_semantic_cache::AiSemanticCache::new(
            config,
            http_client.clone(),
        )?))),
        "ai_response_guard" => Ok(Some(Arc::new(ai_response_guard::AiResponseGuard::new(
            config,
        )?))),
        "ai_federation" => Ok(Some(Arc::new(ai_federation::AiFederation::new(
            config,
            http_client.clone(),
        )?))),
        "ws_message_size_limiting" => Ok(Some(Arc::new(
            ws_message_size_limiting::WsMessageSizeLimiting::new(config)?,
        ))),
        "ws_frame_logging" => Ok(Some(Arc::new(ws_frame_logging::WsFrameLogging::new(
            config,
        )?))),
        "ws_rate_limiting" => Ok(Some(Arc::new(ws_rate_limiting::WsRateLimiting::new(
            config,
            http_client.clone(),
        )?))),
        "udp_rate_limiting" => Ok(Some(Arc::new(
            udp_rate_limiting::UdpRateLimiting::new_with_http_client(config, http_client.clone())?,
        ))),
        "spec_expose" => Ok(Some(Arc::new(spec_expose::SpecExpose::new(
            config,
            http_client,
        )?))),
        "workload_metrics" => Ok(Some(Arc::new(
            mesh::workload_metrics::WorkloadMetrics::new_with_http_client(config, http_client)?,
        ))),
        // GAP-SC3 / GAP-3D: `__mesh_bpf_metrics` is auto-injected on
        // `NodeWaypoint` topology. When the gateway is mesh-mode +
        // node-waypoint, `ProxyState::new` attaches the shared
        // `Arc<BpfMetricsState>` to the `PluginHttpClient`, and the
        // SOCK_OPS ringbuf consumer updates the same Arc. When the slot
        // is empty (every other mode/topology, or a dev build that
        // doesn't run the kernel program), fall back to a fresh
        // unattached state — the plugin still emits a stable Prometheus
        // surface populated by zeros.
        "__mesh_bpf_metrics" => {
            let plugin = match http_client.bpf_metrics_state() {
                Some(state) => mesh::bpf_metrics::MeshBpfMetrics::with_state(config, state)?,
                None => mesh::bpf_metrics::MeshBpfMetrics::new(config)?,
            };
            Ok(Some(Arc::new(plugin)))
        }
        "access_log" => Ok(Some(Arc::new(access_log::AccessLog::new(config)?))),
        _ => {
            // Fall through to custom plugins registry
            let result = crate::custom_plugins::create_custom_plugin(name, config, http_client)?;
            if result.is_none() {
                tracing::warn!("Unknown plugin: {}", name);
            }
            Ok(result)
        }
    }
}

/// Validate a plugin configuration by attempting to instantiate the plugin.
///
/// This is a lightweight validation entry point for use by file_loader and db_loader.
/// The plugin instance is created and immediately dropped — only the config validation
/// side effects of the plugin's `new()` constructor matter.
///
/// Returns `Ok(())` if the config is valid, `Err(msg)` if validation fails.
pub fn validate_plugin_config(name: &str, config: &Value) -> Result<(), String> {
    match create_plugin(name, config)? {
        Some(_) => Ok(()),
        None => Err(format!("Unknown plugin name '{}'", name)),
    }
}

/// List of all available plugin names (built-in + custom).
/// Returns true if the named plugin is security-critical.
///
/// Validation failures for these plugins are fatal at startup — the gateway
/// refuses to start rather than serving traffic without the intended security.
pub fn is_security_plugin(name: &str) -> bool {
    matches!(
        name,
        "key_auth"
            | "basic_auth"
            | "ldap_auth"
            | "jwt_auth"
            | "hmac_auth"
            | "jwks_auth"
            | "mtls_auth"
            | "mesh_authz"
            | "mesh_outbound_registry"
            | "access_control"
            | "tcp_connection_throttle"
            | "rate_limiting"
            | "ip_restriction"
            | "waf"
            | "soap_ws_security"
    )
}

/// Removed built-in plugins that were historically security-sensitive.
///
/// These names are intentionally fail-closed during config load so upgrades
/// cannot silently drop authentication/authorization protections.
pub fn is_removed_security_plugin(name: &str) -> bool {
    matches!(name, "oauth2_auth")
}

pub fn available_plugins() -> Vec<&'static str> {
    let mut plugins = vec![
        "transaction_log_schema",
        "stdout_logging",
        "http_logging",
        "tcp_logging",
        "kafka_logging",
        "ws_logging",
        "transaction_debugger",
        "jwks_auth",
        "jwt_auth",
        "key_auth",
        "basic_auth",
        "ldap_auth",
        "hmac_auth",
        "mtls_auth",
        "spiffe_identity",
        "mesh_authz",
        "mesh_outbound_registry",
        "compression",
        "cors",
        "access_control",
        "tcp_connection_throttle",
        "ip_restriction",
        "bot_detection",
        "correlation_id",
        "request_transformer",
        "response_transformer",
        "mesh_route_dispatch",
        "graphql",
        "grpc_method_router",
        "grpc_deadline",
        "grpc_web",
        "rate_limiting",
        "request_size_limiting",
        "waf",
        "response_size_limiting",
        "body_validator",
        "request_termination",
        "response_caching",
        "response_mock",
        "serverless_function",
        "prometheus_metrics",
        "proxy_alerts",
        "otel_tracing",
        "ai_token_metrics",
        "ai_request_guard",
        "ai_rate_limiter",
        "ai_prompt_shield",
        "ai_response_guard",
        "ai_semantic_cache",
        "ai_federation",
        "ws_message_size_limiting",
        "ws_frame_logging",
        "ws_rate_limiting",
        "udp_rate_limiting",
        "udp_logging",
        "statsd_logging",
        "loki_logging",
        "sse",
        "request_mirror",
        "load_testing",
        "geo_restriction",
        "request_deduplication",
        "soap_ws_security",
        "spec_expose",
        "api_chargeback",
        "workload_metrics",
        "__mesh_bpf_metrics",
        "fault_injection",
        "access_log",
    ];
    plugins.extend(crate::custom_plugins::custom_plugin_names());
    plugins
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn upstream_override_reprojects_resolved_tls_from_snapshot() {
        let mut proxy: Proxy = serde_json::from_value(json!({
            "backend_host": "stable.svc",
            "backend_port": 8080,
            "upstream_id": "stable",
        }))
        .expect("minimal proxy should deserialize");
        proxy.resolved_tls = BackendTlsConfig {
            client_cert_path: Some("/certs/stable.pem".to_string()),
            client_key_path: Some("/certs/stable.key".to_string()),
            server_ca_cert_path: Some("/certs/stable-ca.pem".to_string()),
            verify_server_cert: true,
            sni: None,
            san_allow_list: Vec::new(),
            san_allow_list_key_digest: None,
        };

        let canary: Upstream = serde_json::from_value(json!({
            "id": "canary",
            "targets": [{"host": "canary.svc", "port": 9090}],
            "backend_tls_client_cert_path": "/certs/canary.pem",
            "backend_tls_client_key_path": "/certs/canary.key",
            "backend_tls_server_ca_cert_path": "/certs/canary-ca.pem",
            "backend_tls_verify_server_cert": false,
        }))
        .expect("minimal upstream should deserialize");
        let mut upstreams = HashMap::new();
        upstreams.insert("canary".to_string(), Arc::new(canary));

        let mut ctx =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
        ctx.route_override_upstream_id = Some("canary".to_string());

        let result = ctx.apply_route_overrides_with_upstreams(Arc::new(proxy), &upstreams);
        assert_eq!(result.upstream_id.as_deref(), Some("canary"));
        assert_eq!(
            result.resolved_tls.client_cert_path.as_deref(),
            Some("/certs/canary.pem")
        );
        assert_eq!(
            result.resolved_tls.client_key_path.as_deref(),
            Some("/certs/canary.key")
        );
        assert_eq!(
            result.resolved_tls.server_ca_cert_path.as_deref(),
            Some("/certs/canary-ca.pem")
        );
        assert!(!result.resolved_tls.verify_server_cert);
    }
}
