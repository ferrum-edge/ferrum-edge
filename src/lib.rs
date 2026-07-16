//! Ferrum Edge — A high-performance edge proxy built in Rust.
//!
//! This crate re-exports the public API surface used by integration tests,
//! functional tests, and custom plugins. The binary entry point is in `main.rs`;
//! this `lib.rs` simply makes internal modules accessible to external test crates
//! without duplicating module declarations.

/// The Ferrum Edge binary/crate version (sourced from Cargo.toml at compile time).
pub const FERRUM_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod adaptive_buffer;
pub mod adaptive_concurrency;
pub mod admin;
pub mod backend_conn_limit;
pub mod backend_pending_limit;
pub mod capture;
pub mod circuit_breaker;
pub mod cli;
pub mod cni;
pub mod config;
pub mod config_delta;
pub mod config_sources;
pub mod connection_pool;
pub mod consumer_index;
#[path = "../custom_plugins/mod.rs"]
pub mod custom_plugins;
pub mod date_cache;
pub mod dns;
pub mod dtls;
pub mod ebpf;
pub mod grpc;
pub mod health_check;
pub mod http3;
pub mod identity;
pub mod k8s_controller;
pub mod lazy_timeout;
pub mod load_balancer;
pub mod logging;
pub mod metrics;
pub mod modes;
pub mod notifications;
pub mod overload;
pub mod plugin_cache;
pub mod plugins;
pub mod pool;
pub mod proxy;
pub mod request_epoch;
pub mod retry;
pub mod router_cache;
pub mod runtime_metrics;
pub mod runtime_metrics_tracing_layer;
pub mod secrets;
pub mod service_discovery;
pub mod socket_opts;
pub mod startup;
pub mod system_metrics;
pub mod tls;
pub mod tls_offload;
pub mod util;
pub mod xds;

pub use admin::api_specs::ExtractedBundle;
pub use admin::spec_codec::{compress_gzip, decompress_gzip_capped, sha256_hex};
pub use config::types::{
    ApiSpec, AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, GatewayConfig, HttpFlavor,
    Proxy, SpecFormat,
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use hyper::StatusCode;

    use crate::config::types::{AuthMode, BackendScheme};
    use crate::plugins::Plugin;

    pub fn bind_authorized_backend_path_for_test(
        ctx: &mut crate::plugins::RequestContext,
        path: &str,
    ) {
        ctx.bind_authorized_backend_path(path.to_string());
    }

    // ── adaptive_concurrency lifecycle ──────────────────────────────────────
    pub struct AdaptiveConcurrencyDecreaseHarness {
        limit: AtomicU64,
        config: crate::adaptive_concurrency::AdaptiveConcurrencyConfig,
    }

    impl AdaptiveConcurrencyDecreaseHarness {
        pub fn new(
            initial_limit: u64,
            min_limit: u64,
            max_limit: u64,
            decrease_ratio: f64,
        ) -> Self {
            Self {
                limit: AtomicU64::new(initial_limit),
                config: crate::adaptive_concurrency::AdaptiveConcurrencyConfig {
                    key_by: crate::adaptive_concurrency::AdaptiveConcurrencyKeyBy::Proxy,
                    max_tracked_keys: 1,
                    min_limit,
                    initial_limit,
                    max_limit,
                    min_samples: 1,
                    target_latency_multiplier: 1.5,
                    decrease_ratio,
                    increase_step: 1,
                    shadow_mode: false,
                    expose_headers: false,
                },
            }
        }

        pub fn limit(&self) -> u64 {
            self.limit.load(Ordering::Acquire)
        }

        pub fn decrease_from_observed_limit(&self, observed_limit: u64) {
            crate::adaptive_concurrency::decrease_limit(&self.limit, &self.config, observed_limit);
        }
    }

    pub struct AdaptiveConcurrencyTransitionHarness {
        transition: crate::adaptive_concurrency::AdaptiveConcurrencyPolicyTransition,
    }

    #[derive(Clone, Copy)]
    pub struct AdaptiveConcurrencyResetToken {
        reset: crate::adaptive_concurrency::AdaptiveConcurrencyResetEpoch,
    }

    impl AdaptiveConcurrencyTransitionHarness {
        pub fn new() -> Self {
            Self {
                transition: crate::adaptive_concurrency::AdaptiveConcurrencyPolicyTransition::new(),
            }
        }

        pub fn begin_structural_reset(&self) -> AdaptiveConcurrencyResetToken {
            AdaptiveConcurrencyResetToken {
                reset: self.transition.begin_structural_reset(),
            }
        }

        pub fn try_begin_structural_reset(&self) -> Option<AdaptiveConcurrencyResetToken> {
            self.transition
                .try_begin_structural_reset()
                .map(|reset| AdaptiveConcurrencyResetToken { reset })
        }

        pub fn finish_reset(&self, reset: AdaptiveConcurrencyResetToken) -> bool {
            self.transition.finish_reset(reset.reset)
        }

        pub fn is_active(&self) -> bool {
            self.transition.is_active()
        }
    }

    impl Default for AdaptiveConcurrencyTransitionHarness {
        fn default() -> Self {
            Self::new()
        }
    }

    #[allow(dead_code)] // owning the guard is the behavior exercised by cancellation tests
    pub struct JwksDiscoveryCandidateForTest(
        crate::plugins::utils::jwks_cache::DiscoveryStoreCandidate,
    );

    pub fn jwks_discovery_candidate_for_test(
        jwks_uri: &str,
        http_client: crate::plugins::PluginHttpClient,
        refresh_interval: Duration,
    ) -> JwksDiscoveryCandidateForTest {
        JwksDiscoveryCandidateForTest(
            crate::plugins::utils::jwks_cache::DiscoveryStoreCandidate::acquire(
                jwks_uri,
                &http_client,
                refresh_interval,
            ),
        )
    }

    pub fn oidc_sealed_refresh_session_cookie_for_test(
        plugin: &crate::plugins::oidc_relying_party::OidcRelyingParty,
        claims: serde_json::Value,
        refresh_token: Option<String>,
        refresh_due: bool,
        rolling_due: bool,
    ) -> Result<String, String> {
        plugin.sealed_refresh_session_cookie_for_tests(
            claims,
            refresh_token,
            refresh_due,
            rolling_due,
        )
    }

    pub fn oidc_open_session_cookie_for_test(
        plugin: &crate::plugins::oidc_relying_party::OidcRelyingParty,
        cookie: &str,
    ) -> Option<serde_json::Value> {
        plugin.open_session_cookie_for_tests(cookie)
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct OidcSessionStateForTest {
        pub access_token: String,
        pub refresh_token: Option<String>,
        pub refresh_after_unix: i64,
    }

    pub fn oidc_sealed_session_cookie_for_test(
        plugin: &crate::plugins::oidc_relying_party::OidcRelyingParty,
        claims: serde_json::Value,
        require_rolling_update: bool,
    ) -> Result<String, String> {
        plugin.sealed_session_cookie_for_tests(claims, require_rolling_update)
    }

    pub fn oidc_sealed_due_refresh_session_cookie_for_test(
        plugin: &crate::plugins::oidc_relying_party::OidcRelyingParty,
        claims: serde_json::Value,
        refresh_token: &str,
    ) -> Result<String, String> {
        plugin.sealed_due_refresh_session_cookie_for_tests(claims, refresh_token)
    }

    pub fn oidc_session_state_from_set_cookie_for_test(
        plugin: &crate::plugins::oidc_relying_party::OidcRelyingParty,
        set_cookie: &str,
    ) -> Option<OidcSessionStateForTest> {
        let (access_token, refresh_token, refresh_after_unix) =
            plugin.session_state_from_set_cookie_for_tests(set_cookie)?;
        Some(OidcSessionStateForTest {
            access_token,
            refresh_token,
            refresh_after_unix,
        })
    }

    pub fn prepare_basic_auth_credential_for_test(
        credential: &mut serde_json::Value,
    ) -> Result<(), StatusCode> {
        crate::admin::hash_credential_if_needed("basicauth", credential)
            .map_err(|response| response.status())
    }

    pub fn basic_auth_server_configuration_status_for_test(
        secret: Option<&str>,
    ) -> Option<StatusCode> {
        crate::config::types::hash_basic_auth_password_with_secret("test-password", secret)
            .err()
            .map(|error| crate::admin::basic_auth_credential_error_status(&error))
    }

    pub fn basic_auth_verify_with_test_material_for_test(
        dummy_password_hash: String,
        verification_rounds: usize,
        username: &str,
        password: &str,
        consumer_index: &crate::ConsumerIndex,
    ) -> (crate::plugins::utils::auth_flow::VerifyOutcome, usize) {
        crate::plugins::basic_auth::BasicAuth::verify_with_test_material(
            dummy_password_hash,
            verification_rounds,
            username,
            password,
            consumer_index,
        )
    }

    pub fn basic_auth_bounded_verification_rounds_for_test(configured_limit: usize) -> usize {
        crate::plugins::basic_auth::bounded_verification_rounds(configured_limit)
    }

    pub fn basic_auth_construction_with_secret_for_test(
        config: &serde_json::Value,
        secret: Option<&str>,
    ) -> Result<(), String> {
        crate::plugins::basic_auth::BasicAuth::new_with_hmac_secret(config, secret).map(|_| ())
    }

    pub fn validate_admin_plugin_config_for_test(
        plugin_config: &crate::config::types::PluginConfig,
    ) -> Result<(), String> {
        crate::admin::validate_plugin_config_definition(
            plugin_config,
            crate::plugins::PluginHttpClient::default(),
        )
    }

    pub fn validate_transaction_log_schema_graph_for_test(
        config: &crate::config::types::GatewayConfig,
    ) -> Result<(), Vec<String>> {
        crate::plugins::transaction_log_schema::validate_config_graph(
            config,
            &crate::plugins::PluginHttpClient::default(),
            true,
        )
    }

    pub fn collect_rejecting_runtime_config_errors_for_test(
        config: &crate::config::types::GatewayConfig,
    ) -> Vec<String> {
        crate::config::validation_pipeline::collect_rejecting_runtime_config_errors(config)
    }

    pub async fn lock_namespace_config_admission_for_test(
        namespace: &str,
    ) -> tokio::sync::MutexGuard<'static, ()> {
        crate::admin::crud::lock_local_namespace_config_admission(namespace).await
    }

    pub struct NamespaceConfigAdmissionLeaseStateForTest {
        state: crate::admin::crud::NamespaceConfigAdmissionLeaseState,
        started_at: Instant,
    }

    impl NamespaceConfigAdmissionLeaseStateForTest {
        pub fn new(lease_duration: Duration) -> Self {
            let started_at = Instant::now();
            Self {
                state: crate::admin::crud::NamespaceConfigAdmissionLeaseState::new(
                    started_at,
                    lease_duration,
                ),
                started_at,
            }
        }

        pub fn ensure_held_at(&self, elapsed: Duration) -> bool {
            self.state
                .ensure_held_at(self.started_at + elapsed)
                .is_ok()
        }

        pub fn record_renewal_result(
            &self,
            renewal_started_after: Duration,
            confirmed_after: Duration,
            owner_confirmed: bool,
        ) -> bool {
            if !owner_confirmed {
                self.state.lose_ownership();
                return false;
            }
            self.state.confirm_renewal(
                self.started_at + renewal_started_after,
                self.started_at + confirmed_after,
            )
        }

        pub fn lose_ownership(&self) {
            self.state.lose_ownership();
        }

        pub fn valid_until_millis(&self) -> u64 {
            self.state.valid_until_millis()
        }
    }

    pub fn validate_plugin_configs_fatal_for_test(
        config: &mut crate::config::types::GatewayConfig,
        backend_allow_ips: &crate::config::BackendEgressPolicy,
    ) -> Result<(), String> {
        crate::config::validation_pipeline::ValidationPipeline::new(config)
            .validate_plugin_configs(
                backend_allow_ips,
                crate::config::validation_pipeline::ValidationAction::FatalCount(
                    "Validation failed with {} errors",
                ),
            )
            .run()
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn collect_plugin_config_errors_for_test(
        config: &mut crate::config::types::GatewayConfig,
        backend_allow_ips: &crate::config::BackendEgressPolicy,
    ) -> Result<Vec<String>, String> {
        crate::config::validation_pipeline::ValidationPipeline::new(config)
            .validate_plugin_configs(
                backend_allow_ips,
                crate::config::validation_pipeline::ValidationAction::Collect,
            )
            .run()
            .map_err(|error| error.to_string())
    }

    // ── plugins/request_deduplication ─────────────────────────────────────────
    pub fn request_deduplication_redis_cached_response_payload_is_valid(data: &[u8]) -> bool {
        crate::plugins::request_deduplication::redis_cached_response_payload_is_valid_for_test(data)
    }

    pub fn request_deduplication_completed_size_snapshot_for_test(
        plugin: &crate::plugins::request_deduplication::RequestDeduplication,
    ) -> (usize, usize) {
        plugin.completed_size_snapshot_for_tests()
    }

    pub fn request_deduplication_expire_completed_entries_for_test(
        plugin: &crate::plugins::request_deduplication::RequestDeduplication,
    ) {
        plugin.expire_completed_entries_for_tests();
    }

    pub fn request_deduplication_expire_inflight_entries_for_test(
        plugin: &crate::plugins::request_deduplication::RequestDeduplication,
    ) {
        plugin.expire_inflight_entries_for_tests();
    }

    pub fn request_deduplication_redis_payload_for_test(
        plugin: &crate::plugins::request_deduplication::RequestDeduplication,
        status_code: u16,
        headers: HashMap<String, String>,
        body: &[u8],
    ) -> Option<Vec<u8>> {
        plugin.redis_payload_for_tests(status_code, headers, body)
    }

    // ── plugins/soap_ws_security ────────────────────────────────────────────
    pub fn soap_count_wsu_id_occurrences_for_test(xml: &str, id: &str) -> Result<usize, String> {
        crate::plugins::soap_ws_security::count_wsu_id_occurrences(xml, id)
    }

    pub fn soap_exclusive_canonicalize_element_for_test(
        xml: &str,
        local_name: &str,
        prefix_list: &str,
    ) -> Result<String, String> {
        crate::plugins::soap_ws_security::exclusive_canonicalize_element_for_test(
            xml,
            local_name,
            prefix_list,
        )
    }

    // ── proxy/tcp_proxy ──────────────────────────────────────────────────────
    pub fn classify_stream_error(error: &anyhow::Error) -> crate::retry::ErrorClass {
        crate::proxy::tcp_proxy::classify_stream_error(error)
    }

    /// Resolve the DestinationRule `connectionPool.tcp.maxConnections` cap a
    /// backend dial to `dispatch_port` would enforce. Exposes the
    /// `pub(crate)` hot-path helper the WebSocket dispatch path reads so
    /// integration tests can assert the DR → `dispatch_port_overrides`
    /// projection that feeds `ProxyState.backend_conn_limit`.
    pub fn resolve_backend_max_connections(
        proxy: &crate::config::types::Proxy,
        dispatch_port: u16,
    ) -> Option<u32> {
        crate::proxy::resolve_backend_max_connections(proxy, dispatch_port)
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

    /// Connect to a WebSocket backend using production dialer settings that
    /// are relevant to unit tests.
    pub async fn connect_websocket_backend_for_test(
        backend_url: &str,
        proxy: &crate::config::types::Proxy,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<crate::proxy::WsActivityIo<tokio::net::TcpStream>>,
        >,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let env_config = crate::config::EnvConfig::default();
        let crls: crate::tls::CrlList = Arc::new(Vec::new());
        let handshake = crate::proxy::connect_websocket_backend(
            backend_url,
            proxy,
            &env_config,
            &[],
            None,
            &crls,
            65_536,
            4_096,
            None,
            None,
        )
        .await?;
        Ok(handshake.stream)
    }

    /// Variant of `connect_websocket_backend_for_test` that returns the
    /// negotiated `Sec-WebSocket-Protocol` value alongside the stream so
    /// tests can assert that the backend's chosen subprotocol survives the
    /// gateway-side handshake.
    pub async fn connect_websocket_backend_with_subprotocol_for_test(
        backend_url: &str,
        proxy: &crate::config::types::Proxy,
        client_subprotocols: &[&str],
    ) -> Result<
        (
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<
                    crate::proxy::WsActivityIo<tokio::net::TcpStream>,
                >,
            >,
            Option<String>,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let env_config = crate::config::EnvConfig::default();
        let crls: crate::tls::CrlList = Arc::new(Vec::new());
        let client_headers: Vec<(String, String)> = if client_subprotocols.is_empty() {
            Vec::new()
        } else {
            vec![(
                "sec-websocket-protocol".to_string(),
                client_subprotocols.join(", "),
            )]
        };
        let handshake = crate::proxy::connect_websocket_backend(
            backend_url,
            proxy,
            &env_config,
            &client_headers,
            None,
            &crls,
            65_536,
            4_096,
            None,
            None,
        )
        .await?;
        let proto = handshake
            .negotiated_subprotocol
            .as_ref()
            .and_then(|hv| hv.to_str().ok())
            .map(|s| s.to_string());
        Ok((handshake.stream, proto))
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

    /// Invoke the internal `bidirectional_splice` with backend directional
    /// timeouts exposed. Only available on Linux.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub async fn bidirectional_splice_for_test_with_timeouts(
        client: tokio::net::TcpStream,
        backend: tokio::net::TcpStream,
        idle_timeout: Option<std::time::Duration>,
        half_close_cap: Option<std::time::Duration>,
        backend_read_timeout: Option<std::time::Duration>,
        backend_write_timeout: Option<std::time::Duration>,
        pipe_size: usize,
    ) -> StreamCopyResult {
        crate::proxy::tcp_proxy::bidirectional_splice_for_test_with_timeouts(
            client,
            backend,
            idle_timeout,
            half_close_cap,
            backend_read_timeout,
            backend_write_timeout,
            pipe_size,
        )
        .await
    }

    /// Invoke the internal `bidirectional_splice_io_uring` with backend
    /// directional timeouts exposed. Only available on Linux.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub async fn bidirectional_splice_io_uring_for_test_with_timeouts(
        client: tokio::net::TcpStream,
        backend: tokio::net::TcpStream,
        idle_timeout: Option<std::time::Duration>,
        half_close_cap: Option<std::time::Duration>,
        backend_read_timeout: Option<std::time::Duration>,
        backend_write_timeout: Option<std::time::Duration>,
        pipe_size: usize,
    ) -> StreamCopyResult {
        crate::proxy::tcp_proxy::bidirectional_splice_io_uring_for_test_with_timeouts(
            client,
            backend,
            idle_timeout,
            half_close_cap,
            backend_read_timeout,
            backend_write_timeout,
            pipe_size,
        )
        .await
    }

    // ── plugins/ai_semantic_cache ────────────────────────────────────────────
    pub async fn rebuild_ai_semantic_cache_vector_index(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) {
        plugin.rebuild_vector_index_for_tests().await;
    }

    // ── plugins/response_caching ─────────────────────────────────────────────
    /// Parse an HTTP-date the way `response_caching` does for conditional
    /// requests. Exposes the crate-private helper so tests can assert all
    /// three RFC 9110 §5.6.7 date formats are accepted.
    pub fn response_caching_parse_http_date(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        crate::plugins::response_caching::parse_http_date(value)
    }

    pub fn advance_response_caching_clock_for_test(
        plugin: &crate::plugins::response_caching::ResponseCaching,
        duration: std::time::Duration,
    ) {
        plugin.advance_clock_for_tests(duration);
    }

    pub fn response_caching_current_total_size_for_test(
        plugin: &crate::plugins::response_caching::ResponseCaching,
    ) -> usize {
        plugin.current_total_size_for_tests()
    }

    pub fn response_caching_size_accounting_snapshot_for_test(
        plugin: &crate::plugins::response_caching::ResponseCaching,
    ) -> (usize, usize) {
        plugin.size_accounting_snapshot_for_tests()
    }

    /// Apply `response_caching`'s underflow-safe cache-size subtraction to a
    /// standalone counter so tests can prove a drift larger than the current
    /// total saturates at `0` instead of wrapping to `usize::MAX`.
    pub fn response_caching_sub_total_size(total: &std::sync::atomic::AtomicUsize, n: usize) {
        use std::sync::atomic::Ordering;

        if n == 0 {
            return;
        }
        let _ = total.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(n))
        });
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

    /// Username/password observed on the [`redis::Client`] built from `config + url`.
    ///
    /// Returns `(username, password)` as parsed/injected by `build_client`. Tests
    /// use this to assert that explicit `username`/`password` fields override the
    /// userinfo encoded in `RedisConfig::url`, and that URL-embedded creds flow
    /// through when the explicit fields are `None`.
    pub fn redis_client_credentials(
        config: RedisConfig,
        url: &str,
    ) -> Result<(Option<String>, Option<String>), String> {
        use crate::plugins::utils::redis_rate_limiter::RedisRateLimitClient;
        let client = RedisRateLimitClient::new(config, None, false, None);
        let redis_client = client.build_client(url).map_err(|e| e.to_string())?;
        let info = redis_client.get_connection_info();
        Ok((
            info.redis_settings().username().map(|s| s.to_string()),
            info.redis_settings().password().map(|s| s.to_string()),
        ))
    }

    // ── config/db_loader ─────────────────────────────────────────────────────
    pub use crate::config::db_loader::DbPoolConfig;

    pub fn db_append_connect_timeout(url: &str, db_type: &str, timeout: u64) -> String {
        crate::config::db_loader::DatabaseStore::append_connect_timeout(url, db_type, timeout)
    }

    pub fn db_diff_removed(known: &HashSet<String>, current: &HashSet<String>) -> Vec<String> {
        known.difference(current).cloned().collect()
    }

    pub fn db_code_is_transient(code: &str, is_sqlite: bool) -> bool {
        crate::config::db_loader::is_transient_database_code(code, is_sqlite)
    }

    pub fn db_mongo_error_is_transient(error: &mongodb::error::Error) -> bool {
        crate::config::db_loader::is_transient_mongo_load_error(error)
    }

    pub fn db_mysql_error_number_is_transient(number: u16) -> bool {
        crate::config::db_loader::is_transient_mysql_error_number(number)
    }

    /// Build the exact error shape `mysql_transaction_isolation` returns when
    /// both the `@@transaction_isolation` and `@@tx_isolation` reads fail, so a
    /// test can pin that a transient MySQL disconnect during that read stays
    /// backup-eligible. `mysql_transaction_isolation` itself needs a live
    /// transaction, so this reuses the production wrapper to avoid drift.
    pub fn db_wrap_mysql_isolation_read_error(
        primary_error: &sqlx::Error,
        fallback_error: sqlx::Error,
    ) -> anyhow::Error {
        crate::config::db_loader::wrap_mysql_isolation_read_error(primary_error, fallback_error)
    }

    pub fn parse_scheme(s: &str) -> Result<BackendScheme, String> {
        crate::config::db_loader::parse_scheme(s)
    }

    pub fn parse_auth_mode(s: &str) -> AuthMode {
        crate::config::db_loader::parse_auth_mode(s)
    }

    pub fn statement_timeout_sql(
        timeout_seconds: u64,
        is_postgres: bool,
        is_mysql: bool,
    ) -> Option<String> {
        crate::config::db_loader::statement_timeout_sql(timeout_seconds, is_postgres, is_mysql)
    }

    pub fn is_config_validation_rejection(error: &anyhow::Error) -> bool {
        crate::config::validation_pipeline::is_config_validation_rejection(error)
    }

    // ── config/mongo_store: classic (DocumentDB) migration-lease builders ─────
    // The `$$NOW` aggregation pipeline is the primary skew-immune lease mode for
    // real MongoDB; DocumentDB does not support pipeline-form updates, so the
    // lease falls back to these classic client-time operator updates. These
    // re-exports pin the pure builder shapes without a live backend. Millis are
    // taken as `i64` so tests stay deterministic (no `DateTime::now()`).
    pub fn mongo_migration_lease_duration_millis() -> i64 {
        crate::config::mongo_store::MongoStore::migration_lease_duration_millis()
    }

    pub fn mongo_migration_lease_acquire_filter_classic(
        owner: &str,
        client_now_millis: i64,
    ) -> mongodb::bson::Document {
        crate::config::mongo_store::MongoStore::migration_lease_acquire_filter_classic(
            owner,
            mongodb::bson::DateTime::from_millis(client_now_millis),
        )
    }

    pub fn mongo_migration_lease_acquire_update_classic(
        owner: &str,
        client_now_millis: i64,
    ) -> mongodb::bson::Document {
        crate::config::mongo_store::MongoStore::migration_lease_acquire_update_classic(
            owner,
            mongodb::bson::DateTime::from_millis(client_now_millis),
        )
    }

    pub fn mongo_migration_lease_renew_update_classic(
        client_now_millis: i64,
    ) -> mongodb::bson::Document {
        crate::config::mongo_store::MongoStore::migration_lease_renew_update_classic(
            mongodb::bson::DateTime::from_millis(client_now_millis),
        )
    }

    pub fn mongo_pipeline_update_unsupported(error: &mongodb::error::Error) -> bool {
        crate::config::mongo_store::MongoStore::pipeline_update_unsupported_for_test(error)
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

    pub fn finalize_grpc_web_error_response_headers(
        response: &mut crate::plugins::grpc_web::GrpcWebErrorResponse,
        initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
        finalized_reject_headers: Option<&HashMap<String, String>>,
    ) {
        crate::proxy::finalize_grpc_web_error_response_headers(
            response,
            initial_response_header_policy_plugins,
            finalized_reject_headers,
        );
    }

    pub async fn run_h3_reject_response_committed_hooks(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        flavor: crate::config::types::HttpFlavor,
        grpc_web_response_content_type: Option<&str>,
        http_status: StatusCode,
        body: &[u8],
        headers: &HashMap<String, String>,
    ) {
        crate::http3::server::run_h3_reject_response_committed_hooks(
            plugins,
            ctx,
            flavor,
            grpc_web_response_content_type,
            http_status,
            body,
            headers,
        )
        .await;
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

    pub fn can_dispatch_direct_http2_pool(
        enable_http2: bool,
        retain_request_body: bool,
        requires_request_body_buffering: bool,
        max_request_body_size_bytes: usize,
        max_response_body_size_bytes: usize,
    ) -> bool {
        crate::proxy::can_dispatch_direct_http2_pool(
            enable_http2,
            retain_request_body,
            requires_request_body_buffering,
            max_request_body_size_bytes,
            max_response_body_size_bytes,
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

    pub fn set_websocket_response_boundary_for_test(
        ctx: &mut crate::plugins::RequestContext,
        enabled: bool,
    ) {
        ctx.set_websocket_response_boundary(enabled);
    }

    pub fn set_request_http_flavor_for_test(
        ctx: &mut crate::plugins::RequestContext,
        flavor: crate::config::types::HttpFlavor,
    ) {
        ctx.set_request_http_flavor(flavor);
    }

    pub async fn wait_for_tcp_peer_reset_for_test(stream: &tokio::net::TcpStream) {
        crate::proxy::tcp_proxy::wait_for_tcp_peer_reset(stream).await;
    }

    pub fn tcp_fault_admission_retry_delays_for_test(polls: usize) -> Vec<Duration> {
        let mut backoff = crate::proxy::tcp_proxy::TcpFaultAdmissionRetryBackoff::new();
        (0..polls).map(|_| backoff.next_delay()).collect()
    }

    pub fn tcp_fault_admission_should_cancel_for_test(
        readiness: std::io::Result<tokio::io::Ready>,
        socket_error: std::io::Result<Option<std::io::Error>>,
    ) -> bool {
        crate::proxy::tcp_proxy::tcp_fault_admission_should_cancel(&readiness, &socket_error)
    }

    pub fn insert_grpc_error_metadata(
        metadata: &mut HashMap<String, String>,
        grpc_status: u32,
        grpc_message: &str,
    ) {
        crate::proxy::insert_grpc_error_metadata(metadata, grpc_status, grpc_message)
    }

    pub fn clone_log_metadata(ctx: &crate::plugins::RequestContext) -> HashMap<String, String> {
        crate::proxy::clone_log_metadata(ctx)
    }

    // ── plugins/ai_semantic_cache staging fields ─────────────────────────────
    //
    // `RequestContext::ai_semantic_cache_embedding` / `..._scope_key` are
    // `pub(crate)` so the high-dimensional embedding vector and scope key cannot
    // leak into transaction logs. The read-only accessors below let external
    // unit tests assert that `exact_only` mode never stages either field for
    // multimodal requests, without widening the fields to `pub`.
    pub fn ai_semantic_cache_embedding(ctx: &crate::plugins::RequestContext) -> Option<&Vec<f32>> {
        ctx.ai_semantic_cache_embedding.as_ref()
    }

    pub fn ai_semantic_cache_scope_key(ctx: &crate::plugins::RequestContext) -> Option<&str> {
        ctx.ai_semantic_cache_scope_key.as_deref()
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
            auth_method: None,
            metadata,
            session_start,
        }
    }

    pub async fn fire_ws_tunnel_disconnect_hooks(
        ws_disconnect_plugins: &[Arc<dyn Plugin>],
        proxy_id: &str,
        session_meta: &crate::proxy::WsSessionMeta,
        bytes_client_to_backend: u64,
        bytes_backend_to_client: u64,
        failure: Option<(
            crate::plugins::Direction,
            crate::retry::ErrorClass,
            Option<StreamIoSide>,
        )>,
    ) {
        crate::proxy::fire_ws_tunnel_disconnect_hooks(
            ws_disconnect_plugins,
            proxy_id,
            session_meta,
            bytes_client_to_backend,
            bytes_backend_to_client,
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
