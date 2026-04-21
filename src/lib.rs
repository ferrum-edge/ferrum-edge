//! Ferrum Edge — A high-performance edge proxy built in Rust.
//!
//! This crate re-exports the public API surface used by integration tests,
//! functional tests, and custom plugins. The binary entry point is in `main.rs`;
//! this `lib.rs` simply makes internal modules accessible to external test crates
//! without duplicating module declarations.

/// The Ferrum Edge binary/crate version (sourced from Cargo.toml at compile time).
pub const FERRUM_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod adaptive_buffer;
pub mod admin;
pub mod circuit_breaker;
pub mod cli;
pub mod config;
pub mod config_delta;
pub mod connection_pool;
pub mod consumer_index;
#[path = "../custom_plugins/mod.rs"]
pub mod custom_plugins;
pub mod date_cache;
pub mod dns;
pub mod dtls;
pub mod grpc;
pub mod health_check;
pub mod http3;
pub mod lazy_timeout;
pub mod load_balancer;
pub mod metrics;
pub mod modes;
pub mod overload;
pub mod plugin_cache;
pub mod plugins;
pub mod pool;
pub mod proxy;
pub mod retry;
pub mod router_cache;
pub mod secrets;
pub mod service_discovery;
pub mod socket_opts;
pub mod startup;
pub mod tls;
pub mod tls_offload;

pub use config::types::{
    AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, GatewayConfig, HttpFlavor, Proxy,
};
pub use consumer_index::ConsumerIndex;
pub use load_balancer::LoadBalancerCache;
pub use plugin_cache::{PluginCache, PluginCapabilities};
pub use proxy::{build_backend_url, build_backend_url_with_target};
pub use router_cache::{RouteMatch, RouterCache};

/// Test-only re-exports of crate-private items.
///
/// External test crates (`tests/unit/`) access implementation-internal helpers
/// through this module rather than requiring those helpers to be fully `pub`.
/// The leading underscore signals that this module is not part of the public API.
#[doc(hidden)]
pub mod _test_support {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use hyper::StatusCode;

    use crate::config::types::{AuthMode, BackendScheme};
    use crate::plugins::Plugin;

    // ── proxy/tcp_proxy ──────────────────────────────────────────────────────
    pub fn classify_stream_error(error: &anyhow::Error) -> crate::retry::ErrorClass {
        crate::proxy::tcp_proxy::classify_stream_error(error)
    }

    pub use crate::proxy::tcp_proxy::{StreamCopyResult, StreamIoSide};

    /// Reach into `tcp_proxy` to exercise the `Direction` + IO-side →
    /// `DisconnectCause` mapping that the TCP accept loop uses when
    /// populating stream disconnect metrics.
    pub fn disconnect_cause_for_failure(
        direction: crate::plugins::Direction,
        class: &crate::retry::ErrorClass,
        side: Option<StreamIoSide>,
    ) -> crate::plugins::DisconnectCause {
        crate::proxy::tcp_proxy::disconnect_cause_for_failure(direction, class, side)
    }

    /// Invoke the internal `bidirectional_copy` for unit tests. Generic over
    /// any streams implementing `AsyncRead + AsyncWrite + Unpin`.
    pub async fn bidirectional_copy_for_test<C, B>(
        client: C,
        backend: B,
        idle_timeout: Option<std::time::Duration>,
        half_close_cap: Option<std::time::Duration>,
        buf_size: usize,
    ) -> StreamCopyResult
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        crate::proxy::tcp_proxy::bidirectional_copy_for_test(
            client,
            backend,
            idle_timeout,
            half_close_cap,
            buf_size,
        )
        .await
    }

    /// Test-only entry point that exposes `backend_read_timeout` and
    /// `backend_write_timeout` so per-direction timeout enforcement can be
    /// exercised directly.
    #[allow(clippy::too_many_arguments)]
    pub async fn bidirectional_copy_for_test_with_timeouts<C, B>(
        client: C,
        backend: B,
        idle_timeout: Option<std::time::Duration>,
        half_close_cap: Option<std::time::Duration>,
        backend_read_timeout: Option<std::time::Duration>,
        backend_write_timeout: Option<std::time::Duration>,
        buf_size: usize,
    ) -> StreamCopyResult
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        crate::proxy::tcp_proxy::bidirectional_copy_for_test_with_timeouts(
            client,
            backend,
            idle_timeout,
            half_close_cap,
            backend_read_timeout,
            backend_write_timeout,
            buf_size,
        )
        .await
    }

    /// Invoke the internal `bidirectional_splice` (Linux zero-copy relay) for
    /// unit tests. Only available on Linux — on other platforms there is no
    /// splice path to exercise.
    #[cfg(target_os = "linux")]
    pub async fn bidirectional_splice_for_test(
        client: tokio::net::TcpStream,
        backend: tokio::net::TcpStream,
        idle_timeout: Option<std::time::Duration>,
        half_close_cap: Option<std::time::Duration>,
        pipe_size: usize,
    ) -> StreamCopyResult {
        crate::proxy::tcp_proxy::bidirectional_splice_for_test(
            client,
            backend,
            idle_timeout,
            half_close_cap,
            pipe_size,
        )
        .await
    }

    // ── plugins/ws_rate_limiting ─────────────────────────────────────────────
    /// Create a fresh `WsRateLimiting` instance and return its Redis scope key.
    /// Each call returns a key from a new instance (unique UUID prefix), so two
    /// consecutive calls with the same arguments will return different keys.
    pub fn ws_rate_limiter_scope_key(proxy_id: &str, connection_id: u64) -> String {
        use crate::plugins::utils::http_client::PluginHttpClient;
        use crate::plugins::ws_rate_limiting::WsRateLimiting;
        WsRateLimiting::new(&serde_json::json!({}), PluginHttpClient::default())
            .expect("WsRateLimiting::new with empty config must succeed")
            .redis_connection_scope_key(proxy_id, connection_id)
    }

    // ── plugins/utils/redis_rate_limiter ─────────────────────────────────────
    pub use crate::plugins::utils::redis_rate_limiter::RedisConfig;

    pub fn redis_config_url_with_ip(config: &RedisConfig, ip: std::net::IpAddr) -> String {
        config.url_with_resolved_ip(ip)
    }

    // ── config/db_loader ─────────────────────────────────────────────────────
    pub use crate::config::db_loader::DbPoolConfig;

    pub fn db_append_connect_timeout(url: &str, db_type: &str, timeout: u64) -> String {
        crate::config::db_loader::DatabaseStore::append_connect_timeout(url, db_type, timeout)
    }

    pub fn db_diff_removed(known: &HashSet<String>, current: &HashSet<String>) -> Vec<String> {
        crate::config::db_loader::diff_removed(known, current)
    }

    pub fn parse_scheme(s: &str) -> BackendScheme {
        crate::config::db_loader::parse_scheme(s)
    }

    pub fn parse_auth_mode(s: &str) -> AuthMode {
        crate::config::db_loader::parse_auth_mode(s)
    }

    // ── plugins/grpc_web ─────────────────────────────────────────────────────
    pub const GRPC_FRAME_DATA: u8 = crate::plugins::grpc_web::GRPC_FRAME_DATA;
    pub const GRPC_FRAME_TRAILER: u8 = crate::plugins::grpc_web::GRPC_FRAME_TRAILER;

    pub fn is_grpc_web_content_type(ct: &str) -> bool {
        crate::plugins::grpc_web::is_grpc_web_content_type(ct)
    }

    pub fn is_grpc_web_text(ct: &str) -> bool {
        crate::plugins::grpc_web::is_grpc_web_text(ct)
    }

    pub fn build_trailer_frame(response_headers: &HashMap<String, String>) -> Vec<u8> {
        crate::plugins::grpc_web::build_trailer_frame(response_headers)
    }

    pub fn parse_grpc_frames(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        crate::plugins::grpc_web::parse_grpc_frames(data)
    }

    pub fn response_content_type(original_ct: &str) -> &'static str {
        crate::plugins::grpc_web::response_content_type(original_ct)
    }

    // ── proxy/mod ────────────────────────────────────────────────────────────
    pub struct NormalizedRejectResponse {
        pub http_status: StatusCode,
        pub headers: HashMap<String, String>,
        pub body: Vec<u8>,
        pub grpc_status: Option<u32>,
        pub grpc_message: Option<String>,
    }

    pub fn can_use_direct_http2_pool(
        enable_http2: bool,
        retain_request_body: bool,
        requires_request_body_buffering: bool,
    ) -> bool {
        crate::proxy::can_use_direct_http2_pool(
            enable_http2,
            retain_request_body,
            requires_request_body_buffering,
        )
    }

    pub fn request_may_have_body(method: &str, headers: &HashMap<String, String>) -> bool {
        crate::proxy::request_may_have_body(method, headers)
    }

    pub async fn apply_request_body_plugins(
        plugins: &[Arc<dyn Plugin>],
        headers: &HashMap<String, String>,
        body_bytes: Vec<u8>,
    ) -> Vec<u8> {
        crate::proxy::apply_request_body_plugins(plugins, headers, body_bytes).await
    }

    pub fn extract_grpc_reject_message(body: &[u8]) -> Option<String> {
        crate::proxy::extract_grpc_reject_message(body)
    }

    pub fn map_http_reject_status_to_grpc_status(status: StatusCode) -> u32 {
        crate::proxy::map_http_reject_status_to_grpc_status(status)
    }

    pub fn normalize_reject_response(
        status: StatusCode,
        body: &[u8],
        headers: &HashMap<String, String>,
        is_grpc_request: bool,
    ) -> NormalizedRejectResponse {
        let normalized =
            crate::proxy::normalize_reject_response(status, body, headers, is_grpc_request);
        NormalizedRejectResponse {
            http_status: normalized.http_status,
            headers: normalized.headers,
            body: normalized.body,
            grpc_status: normalized.grpc_status,
            grpc_message: normalized.grpc_message,
        }
    }

    pub fn insert_grpc_error_metadata(
        metadata: &mut HashMap<String, String>,
        grpc_status: u32,
        grpc_message: &str,
    ) {
        crate::proxy::insert_grpc_error_metadata(metadata, grpc_status, grpc_message)
    }

    // ── WebSocket tunnel-mode disconnect hook ────────────────────────────────
    //
    // Tunnel mode bypasses WebSocket frame parsing and does raw TCP bidirectional
    // copy. The test-support helpers below expose the internal `WsSessionMeta`
    // constructor and the `fire_ws_tunnel_disconnect_hooks` entry point so unit
    // tests can verify that `on_ws_disconnect` still fires in tunnel mode (the
    // disconnect-observability contract used by ws_frame_logging and
    // prometheus_metrics).
    #[allow(clippy::too_many_arguments)]
    pub fn make_ws_session_meta(
        namespace: String,
        proxy_name: Option<String>,
        client_ip: String,
        backend_target: String,
        listen_port: u16,
        consumer_username: Option<String>,
        metadata: HashMap<String, String>,
        session_start: chrono::DateTime<chrono::Utc>,
    ) -> crate::proxy::WsSessionMeta {
        crate::proxy::WsSessionMeta {
            namespace,
            proxy_name,
            client_ip,
            backend_target,
            listen_port,
            consumer_username,
            metadata,
            session_start,
        }
    }

    pub async fn fire_ws_tunnel_disconnect_hooks(
        ws_disconnect_plugins: &[Arc<dyn Plugin>],
        proxy_id: &str,
        session_meta: &crate::proxy::WsSessionMeta,
        failure: Option<(crate::plugins::Direction, crate::retry::ErrorClass)>,
    ) {
        crate::proxy::fire_ws_tunnel_disconnect_hooks(
            ws_disconnect_plugins,
            proxy_id,
            session_meta,
            failure,
        )
        .await
    }

    /// Construct a streaming `ProxyBody` for use in unit/integration tests.
    /// Delegates to the crate-private `ProxyBody::streaming` constructor,
    /// keeping that constructor internal while still letting tests exercise
    /// the streaming-variant `Drop` / `poll_frame` paths.
    pub fn proxy_body_streaming_for_test(
        body: std::pin::Pin<
            Box<
                dyn http_body::Body<Data = bytes::Bytes, Error = crate::proxy::body::ProxyBodyError>
                    + Send
                    + 'static,
            >,
        >,
    ) -> crate::proxy::ProxyBody {
        crate::proxy::body::ProxyBody::streaming(body)
    }
}
