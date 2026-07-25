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
pub mod observability_delivery;
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
    use std::time::Duration;

    use futures_util::Sink;
    use hyper::StatusCode;
    use tokio_tungstenite::tungstenite::Error as WsError;
    use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message};

    use crate::config::types::{AuthMode, BackendScheme};
    use crate::plugins::Plugin;

    /// Exercise DP's crate-private concurrent listener supervisor without
    /// expanding the production API solely for external regression tests.
    pub async fn await_dp_listener_handles(
        listener_handles: Vec<tokio::task::JoinHandle<()>>,
        shutdown_tx: tokio::sync::watch::Sender<bool>,
    ) -> Result<(), tokio::task::JoinError> {
        crate::modes::data_plane::await_dp_listener_handles(listener_handles, shutdown_tx).await
    }

    /// Report private compression ownership without exposing it through public
    /// transaction metadata in production.
    pub fn compression_ownership_for_test(
        ctx: &crate::plugins::RequestContext,
    ) -> (Option<u64>, Option<u64>) {
        ctx.compression_ownership_for_test()
    }

    pub fn take_compression_response_codec_permit_for_test(
        ctx: &mut crate::plugins::RequestContext,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        ctx.take_compression_response_codec_permit()
    }

    /// Whether a compression instance reserved response codec admission for this
    /// request in `before_proxy` (the early bound on the buffered population).
    pub fn compression_response_admission_reserved_for_test(
        ctx: &crate::plugins::RequestContext,
    ) -> bool {
        ctx.has_compression_response_admission_owner()
    }

    /// Whether `before_proxy` negotiated a compressible coding but could not
    /// obtain bounded codec admission (so the response streams identity).
    pub fn compression_response_admission_declined_for_test(
        ctx: &crate::plugins::RequestContext,
    ) -> bool {
        ctx.compression_response_admission_declined()
    }

    /// Build the request-body-hook compatibility context. Used to prove the
    /// reserved response codec permit stays on the donor (live) context rather
    /// than being moved into this short-lived clone.
    pub fn clone_for_final_request_body_hooks_for_test(
        ctx: &mut crate::plugins::RequestContext,
    ) -> crate::plugins::RequestContext {
        ctx.clone_for_final_request_body_hooks()
    }

    pub fn gateway_response_compression_algorithm_for_test(
        ctx: &crate::plugins::RequestContext,
    ) -> Option<&'static str> {
        ctx.gateway_response_compression_algorithm()
    }

    pub fn reconcile_aborted_gateway_response_encoding_for_test(
        ctx: &mut crate::plugins::RequestContext,
        response_headers: &mut std::collections::HashMap<String, String>,
        body_len: usize,
    ) {
        crate::plugins::compression::reconcile_aborted_gateway_response_encoding(
            ctx,
            response_headers,
            body_len,
        );
    }

    pub fn validate_correlation_id_composition_for_test(
        plugins: &[Arc<dyn Plugin>],
    ) -> Result<(), String> {
        crate::plugin_cache::validate_correlation_id_composition(plugins, None)
    }

    pub fn validate_correlation_id_composition_with_real_ip_header_for_test(
        plugins: &[Arc<dyn Plugin>],
        real_ip_header: Option<&str>,
    ) -> Result<(), String> {
        crate::plugin_cache::validate_correlation_id_composition(plugins, real_ip_header)
    }

    pub fn correlation_id_with_real_ip_header_for_test(
        config: &serde_json::Value,
        real_ip_header: Option<&str>,
    ) -> Result<crate::plugins::correlation_id::CorrelationId, String> {
        crate::plugins::correlation_id::CorrelationId::new_with_real_ip_header(
            config,
            real_ip_header,
        )
    }

    pub fn udp_dtls_disconnect_metadata_after_datagram_metadata_for_test(
        ctx: &mut crate::plugins::StreamConnectionContext,
        datagram_metadata: HashMap<String, String>,
    ) -> (HashMap<String, String>, HashMap<String, String>) {
        let (connect_metadata, correlation_ids) = ctx.take_metadata_with_correlation_ids();

        let udp_metadata = std::sync::Mutex::new(connect_metadata.clone());
        crate::plugins::UdpMetadataSink::new(&udp_metadata).update(|metadata| {
            metadata.extend(datagram_metadata.clone());
        });
        let udp_metadata = crate::proxy::udp_proxy::finalize_stream_summary_metadata(
            udp_metadata
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            &correlation_ids,
        );

        let mut dtls_metadata = connect_metadata;
        dtls_metadata.extend(datagram_metadata);
        let dtls_metadata = crate::proxy::udp_proxy::finalize_stream_summary_metadata(
            dtls_metadata,
            &correlation_ids,
        );

        (udp_metadata, dtls_metadata)
    }

    pub fn plugin_cache_with_real_ip_header_for_test(
        config: &crate::config::types::GatewayConfig,
        real_ip_header: Option<&str>,
    ) -> Result<crate::PluginCache, String> {
        let http_client = crate::plugins::PluginHttpClient::default()
            .with_real_ip_header(real_ip_header.map(str::to_string));
        crate::PluginCache::with_http_client(config, http_client)
    }

    /// Deterministic allocator helper for proxy lifecycle ownership generations.
    pub fn build_proxy_lifecycle_generations_for_test(
        previous: &HashMap<String, u64>,
        previous_high_water: u64,
        config: &crate::config::types::GatewayConfig,
    ) -> Result<(HashMap<String, u64>, u64), String> {
        crate::plugin_cache::build_proxy_lifecycle_generations(
            previous,
            previous_high_water,
            config,
        )
    }

    pub fn validate_plugin_composition_candidate_with_real_ip_header_for_test(
        config: &crate::config::types::GatewayConfig,
        real_ip_header: Option<&str>,
    ) -> Result<(), String> {
        let http_client = crate::plugins::PluginHttpClient::default()
            .with_real_ip_header(real_ip_header.map(str::to_string));
        crate::plugin_cache::validate_plugin_composition_candidate(config, &http_client)
    }

    /// Exercise the mesh RTDS generation reconciliation boundary without
    /// widening its runtime API beyond the crate.
    pub fn reconcile_fault_plugin_generations_for_test(
        candidate: &mut crate::config::types::GatewayConfig,
        previous: &crate::config::types::GatewayConfig,
    ) {
        crate::modes::mesh::reconcile_fault_plugin_generations(candidate, previous);
    }

    /// Return the exact proxy targets used by incremental plugin-cache staging.
    pub fn incremental_plugin_rebuild_targets_for_test(
        current: &crate::config::types::GatewayConfig,
        candidate: &crate::config::types::GatewayConfig,
    ) -> HashSet<String> {
        let delta = crate::config_delta::ConfigDelta::compute(current, candidate);
        crate::proxy::plugin_rebuild_targets_for_incremental_stage(current, candidate, &delta)
    }

    // ── plugins/grpc_deadline + proxy rejection finalization ────────────────
    pub fn grpc_deadline_duration_millis_ceil_saturating_for_test(
        duration: std::time::Duration,
    ) -> Option<u64> {
        crate::plugins::grpc_deadline::duration_millis_ceil_saturating(duration)
    }

    pub fn set_grpc_deadline_budget_for_test(
        ctx: &mut crate::plugins::RequestContext,
        budget_ms: Option<u64>,
    ) {
        ctx.set_grpc_deadline_budget(budget_ms);
    }

    pub async fn await_request_plugin_deadline_for_test<F>(
        deadline: Option<tokio::time::Instant>,
        future: F,
    ) -> crate::plugins::PluginResult
    where
        F: std::future::Future<Output = crate::plugins::PluginResult>,
    {
        match crate::plugins::await_request_plugin_deadline_with_provenance(deadline, future).await
        {
            crate::plugins::RequestPluginDeadlineResult::Completed(result) => result,
            crate::plugins::RequestPluginDeadlineResult::DeadlineExceeded => {
                crate::plugins::grpc_deadline_exceeded_plugin_result()
            }
        }
    }

    pub async fn finalize_plugin_rejection_parts_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        status_code: u16,
        body: Vec<u8>,
        headers: HashMap<String, String>,
    ) -> (u16, Vec<u8>, HashMap<String, String>) {
        let mut response_status = status_code;
        let mut response_headers = headers.clone();
        let response_body = crate::proxy::apply_plugin_rejection_response(
            plugins,
            ctx,
            &mut response_status,
            &mut response_headers,
            crate::proxy::RejectedResponseParts {
                status_code,
                body,
                headers,
            },
        )
        .await;
        (response_status, response_body, response_headers)
    }

    pub fn gateway_deadline_response_selected_for_test(
        ctx: &crate::plugins::RequestContext,
    ) -> bool {
        ctx.gateway_deadline_response_selected()
    }

    pub fn mark_gateway_deadline_response_selected_for_test(
        ctx: &mut crate::plugins::RequestContext,
    ) {
        ctx.mark_gateway_deadline_response_selected();
    }

    pub async fn run_context_free_final_request_body_hooks_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> crate::plugins::PluginResult {
        let deadline = ctx.grpc_deadline_at();
        let transformed = crate::proxy::apply_request_body_plugins_with_context(
            plugins,
            None,
            deadline,
            headers,
            body.to_vec(),
        )
        .await;
        crate::proxy::run_final_request_body_hooks_with_provenance(
            plugins,
            None,
            deadline,
            headers,
            &transformed,
        )
        .await
        .into_plugin_result(ctx)
    }

    pub struct GrpcWebPluginViewForTest {
        pub plugins: Vec<String>,
        pub grpc_deadline_plugins: Vec<String>,
        pub backend_path_plugins: Vec<String>,
    }

    pub fn grpc_web_request_view_for_test(
        cache: &crate::PluginCache,
        proxy_id: &str,
    ) -> GrpcWebPluginViewForTest {
        let inner = cache.load_inner();
        let view = inner.grpc_web_request_view(proxy_id);
        GrpcWebPluginViewForTest {
            plugins: view
                .plugins()
                .iter()
                .map(|plugin| plugin.name().to_string())
                .collect(),
            grpc_deadline_plugins: view
                .grpc_deadline_plugins()
                .iter()
                .map(|plugin| plugin.name().to_string())
                .collect(),
            backend_path_plugins: view
                .backend_path_plugins()
                .iter()
                .map(|plugin| plugin.name().to_string())
                .collect(),
        }
    }

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

    pub fn intervening_clear_recovery_candidate_for_test(
        snapshot: crate::config::types::GatewayConfig,
        current: crate::config::types::GatewayConfig,
    ) -> crate::config::types::GatewayConfig {
        crate::admin::intervening_clear_recovery_candidate_for_test(snapshot, current)
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

    // ── plugins/request_mirror ───────────────────────────────────────────────
    pub fn request_mirror_should_mirror_for_test(
        plugin: &crate::plugins::request_mirror::RequestMirror,
    ) -> bool {
        plugin.should_mirror_for_test()
    }

    pub fn request_mirror_sample_threshold_for_test(
        plugin: &crate::plugins::request_mirror::RequestMirror,
    ) -> u64 {
        plugin.sample_threshold_for_test()
    }

    pub fn request_mirror_sample_phase_for_test(
        plugin: &crate::plugins::request_mirror::RequestMirror,
    ) -> u64 {
        plugin.sample_phase_for_test()
    }

    pub fn request_mirror_append_shadow_host_suffix_for_test(authority: &str) -> String {
        crate::plugins::request_mirror::append_shadow_host_suffix(authority)
    }

    pub fn request_mirror_resolve_timeout_ms_for_test(
        configured_mirror_timeout_ms: Option<u64>,
        backend_read_timeout_ms: Option<u64>,
    ) -> u64 {
        crate::plugins::request_mirror::resolve_mirror_timeout_ms(
            configured_mirror_timeout_ms,
            backend_read_timeout_ms,
        )
    }

    pub fn request_mirror_retained_request_body_bytes_for_test(
        plugin: &crate::plugins::request_mirror::RequestMirror,
    ) -> u64 {
        plugin.retained_request_body_bytes_for_test()
    }

    pub fn request_mirror_max_retained_request_body_bytes_for_test(
        plugin: &crate::plugins::request_mirror::RequestMirror,
    ) -> u64 {
        plugin.max_retained_request_body_bytes_for_test()
    }

    pub fn request_mirror_mirror_timeout_ms_for_test(
        plugin: &crate::plugins::request_mirror::RequestMirror,
    ) -> Option<u64> {
        plugin.mirror_timeout_ms_for_test()
    }

    pub fn request_mirror_metrics_snapshot_for_test(
        plugin: &crate::plugins::request_mirror::RequestMirror,
    ) -> crate::plugins::request_mirror::MirrorMetricsSnapshot {
        plugin.mirror_metrics_snapshot_for_test()
    }

    // ── plugins/api_chargeback_sink ──────────────────────────────────────────
    pub fn api_chargeback_sink_snapshot_accumulator_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
    ) -> Option<Arc<crate::plugins::api_chargeback_sink::SnapshotAccumulator>> {
        plugin.snapshot_accumulator_for_tests()
    }

    pub async fn api_chargeback_sink_finalize_snapshot_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
    ) -> Option<bool> {
        plugin.finalize_snapshot_for_tests().await
    }

    pub async fn api_chargeback_sink_finalize_with_held_admission_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
        timeout: std::time::Duration,
    ) -> Option<bool> {
        plugin
            .finalize_snapshot_with_held_admission_for_tests(timeout)
            .await
    }

    pub fn api_chargeback_sink_snapshot_finalized_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
    ) -> Option<bool> {
        plugin.snapshot_finalized_for_tests()
    }

    pub fn api_chargeback_sink_snapshot_generation_registered_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
    ) -> Option<bool> {
        plugin.snapshot_generation_registered_for_tests()
    }

    pub fn api_chargeback_sink_force_compact_snapshot_finalization_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
    ) -> bool {
        plugin.force_compact_snapshot_finalization_for_tests()
    }

    pub fn api_chargeback_sink_snapshot_compact_recovery_registered_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
    ) -> Option<bool> {
        plugin.snapshot_compact_recovery_registered_for_tests()
    }

    pub fn api_chargeback_sink_emit_snapshot_tick_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
    ) -> Option<Result<usize, String>> {
        plugin.emit_snapshot_tick_for_tests()
    }

    pub fn api_chargeback_sink_spool_snapshot_overflow_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
        event: crate::plugins::api_chargeback_sink::ChargeEvent,
    ) -> bool {
        plugin.spool_snapshot_overflow_for_tests(event)
    }

    pub fn api_chargeback_sink_abort_spool_delivery_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
    ) -> bool {
        plugin.abort_spool_delivery_for_tests()
    }

    pub fn api_chargeback_sink_snapshot_overflow_counters_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
    ) -> Option<(u64, u64, u64)> {
        plugin.snapshot_overflow_counters_for_tests()
    }

    pub fn api_chargeback_sink_compact_refuses_while_overflow_delivery_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
    ) -> Option<(bool, bool)> {
        plugin.compact_refuses_while_overflow_delivery_then_succeeds_for_tests()
    }

    pub fn api_chargeback_sink_compact_refuses_while_admitted_then_succeeds_for_test(
        plugin: &crate::plugins::api_chargeback_sink::ApiChargebackSink,
    ) -> Option<(bool, bool)> {
        plugin.compact_refuses_while_admitted_then_succeeds_for_tests()
    }

    // ── plugins/request_deduplication ─────────────────────────────────────────
    pub fn request_deduplication_with_instance_id_for_test(
        config: &serde_json::Value,
        http_client: crate::plugins::PluginHttpClient,
        instance_id: &str,
    ) -> Result<crate::plugins::request_deduplication::RequestDeduplication, String> {
        crate::plugins::request_deduplication::RequestDeduplication::new_with_instance_id(
            config,
            http_client,
            instance_id,
        )
    }

    pub fn request_deduplication_logical_keys_from_context_for_test(
        ctx: &crate::plugins::RequestContext,
    ) -> Vec<String> {
        crate::plugins::request_deduplication::logical_keys_from_request_context_for_test(ctx)
    }

    pub async fn finalize_plugin_rejection_without_committed_hooks_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        rejection: crate::plugins::PluginResult,
    ) -> crate::plugins::PluginResult {
        let Some(parts) = crate::proxy::plugin_result_into_reject_parts(rejection) else {
            return crate::plugins::PluginResult::Continue;
        };
        let mut status = parts.status_code;
        let mut headers = parts.headers;
        let mut body = parts.body;
        crate::proxy::apply_reject_after_proxy_and_synthetic_body_hooks(
            plugins,
            ctx,
            &mut status,
            &mut headers,
            &mut body,
            false,
            false,
        )
        .await;
        crate::plugins::PluginResult::RejectBinary {
            status_code: status,
            body: bytes::Bytes::from(body),
            headers,
        }
    }
    pub async fn finalize_plugin_rejection_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        rejection: crate::plugins::PluginResult,
    ) -> crate::plugins::PluginResult {
        let Some(parts) = crate::proxy::plugin_result_into_reject_parts(rejection) else {
            return crate::plugins::PluginResult::Continue;
        };
        let mut status = parts.status_code;
        let mut headers = parts.headers;
        let mut body = parts.body;
        crate::proxy::apply_reject_after_proxy_and_synthetic_body_hooks(
            plugins,
            ctx,
            &mut status,
            &mut headers,
            &mut body,
            false,
            true,
        )
        .await;
        crate::plugins::PluginResult::RejectBinary {
            status_code: status,
            body: bytes::Bytes::from(body),
            headers,
        }
    }

    pub fn request_deduplication_redis_cached_response_payload_is_valid(data: &[u8]) -> bool {
        crate::plugins::request_deduplication::redis_cached_response_payload_is_valid_for_test(data)
    }

    pub fn request_deduplication_completed_size_snapshot_for_test(
        plugin: &crate::plugins::request_deduplication::RequestDeduplication,
    ) -> (usize, usize) {
        plugin.completed_size_snapshot_for_tests()
    }

    pub fn request_deduplication_request_identity_for_test(
        plugin: &crate::plugins::request_deduplication::RequestDeduplication,
        ctx: &crate::plugins::RequestContext,
    ) -> Option<(String, String)> {
        plugin.request_identity_for_tests(ctx)
    }

    pub fn request_deduplication_set_request_state_for_test(
        plugin: &crate::plugins::request_deduplication::RequestDeduplication,
        ctx: &mut crate::plugins::RequestContext,
        key: &str,
        fingerprint: &str,
        local_inflight_owner_token: &str,
        redis_lock_token: Option<&str>,
    ) {
        crate::plugins::request_deduplication::set_request_state_for_test(
            plugin,
            ctx,
            key,
            fingerprint,
            local_inflight_owner_token,
            redis_lock_token,
        );
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

    // ── plugins/kafka_logging ───────────────────────────────────────────────
    /// Pure producer-configuration / CRL admission boundary. External unit
    /// tests use this so TLS-policy coverage does not require constructing a
    /// librdkafka producer (OpenSSL may be unavailable in CI builds).
    pub fn kafka_logging_validate_producer_admission_for_test(
        config: &serde_json::Value,
        http_client: &crate::plugins::PluginHttpClient,
    ) -> Result<(), String> {
        crate::plugins::kafka_logging::validate_producer_admission(config, http_client)
    }

    pub fn kafka_logging_serialize_http_with_config_for_test(
        config: &serde_json::Value,
        summary: &crate::plugins::TransactionSummary,
    ) -> Result<serde_json::Value, String> {
        crate::plugins::kafka_logging::serialize_http_with_config_for_test(config, summary)
    }

    pub fn kafka_logging_serialize_stream_with_config_for_test(
        config: &serde_json::Value,
        summary: &crate::plugins::StreamTransactionSummary,
    ) -> Result<serde_json::Value, String> {
        crate::plugins::kafka_logging::serialize_stream_with_config_for_test(config, summary)
    }

    /// Deterministic probe: channel reservation must precede serialization so
    /// an oversized summary rejected by a full Ferrum channel never increments
    /// the oversize counter.
    pub async fn kafka_logging_probe_reserve_before_serialize_for_test(
        oversized: &crate::plugins::TransactionSummary,
    ) -> (u64, u64) {
        crate::plugins::kafka_logging::probe_reserve_before_serialize_for_test(oversized).await
    }

    /// Deterministic probe: aggregate byte-budget reservation must precede
    /// serialization so budget denial cannot allocate an attacker-sized entry.
    pub async fn kafka_logging_probe_byte_budget_before_serialize_for_test(
        oversized: &crate::plugins::TransactionSummary,
    ) -> (u64, u64) {
        crate::plugins::kafka_logging::probe_byte_budget_before_serialize_for_test(oversized).await
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

    pub fn soap_decode_xml_body_for_test(
        bytes: &[u8],
        content_type: &str,
    ) -> Result<String, String> {
        crate::plugins::soap_ws_security::decode_soap_xml_body_for_test(bytes, content_type)
    }

    /// Schema type-cache stats for an openapi_validator instance: `(cached nodes,
    /// request-time fallback computes)`. Cached nodes are filled once per
    /// registered schema during ConversionPlan compile (#3024).
    pub fn openapi_validator_schema_type_cache_stats_for_test(
        plugin: &crate::plugins::openapi_validator::OpenapiValidator,
    ) -> (usize, usize) {
        plugin.schema_type_cache_stats_for_test()
    }

    // ── proxy/tcp_proxy ──────────────────────────────────────────────────────
    pub fn classify_stream_error(error: &anyhow::Error) -> crate::retry::ErrorClass {
        crate::proxy::tcp_proxy::classify_stream_error(error)
    }

    /// Mirror the TCP accept-loop disconnect summary contract: `duration_ms`
    /// from process-monotonic `Instant`, RFC3339 connect/disconnect stamps
    /// from civil/UTC wall clocks only. Used by parity regression tests for
    /// issue #2624 (WebSocket/UDP/DTLS must match this split).
    pub fn tcp_stream_summary_from_clocks_for_test(
        connected_mono: std::time::Instant,
        connected_wall_at: chrono::DateTime<chrono::Utc>,
        disconnected_wall_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::plugins::StreamTransactionSummary {
        crate::plugins::StreamTransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: "tcp-proxy".to_string(),
            proxy_lifecycle_generation: None,
            proxy_name: Some("TCP Proxy".to_string()),
            client_ip: "10.0.0.1".to_string(),
            consumer_username: None,
            auth_method: None,
            backend_target: "10.0.0.2:9000".to_string(),
            backend_resolved_ip: Some("10.0.0.2".to_string()),
            protocol: "tcp".to_string(),
            listen_port: 9000,
            // Production: `connected_at.elapsed().as_millis() as f64`
            duration_ms: connected_mono.elapsed().as_millis() as f64,
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: None,
            error_class: None,
            disconnect_direction: None,
            disconnect_cause: Some(crate::plugins::DisconnectCause::GracefulShutdown),
            timestamp_connected: connected_wall_at.to_rfc3339(),
            timestamp_disconnected: disconnected_wall_at.to_rfc3339(),
            sni_hostname: None,
            metadata: Default::default(),
        }
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
            262_144,
            4_096,
            None,
            None,
        )
        .await?;
        Ok(handshake.stream)
    }

    /// Exercise the production bounded WebSocket close/queued-echo path.
    pub async fn send_bounded_ws_close_for_test<S>(sink: &mut S, close: Option<CloseFrame>)
    where
        S: Sink<Message, Error = WsError> + Unpin,
    {
        crate::proxy::send_bounded_ws_close(sink, close).await;
    }

    /// Exercise synchronous policy-close publication and cancellation.
    pub fn publish_ws_policy_close_for_test(
        policy_close: &std::sync::OnceLock<CloseFrame>,
        cancel: &tokio_util::sync::CancellationToken,
        close: Option<CloseFrame>,
    ) -> Option<CloseFrame> {
        crate::proxy::publish_ws_policy_close(policy_close, cancel, close)
    }

    /// Exercise the shared H1/H2/H3 WebSocket frame-plugin composition path.
    pub async fn apply_ws_frame_plugins_for_test(
        plugins: &[Arc<dyn crate::plugins::Plugin>],
        proxy_id: &str,
        connection_id: u64,
        direction: crate::plugins::WebSocketFrameDirection,
        raw: Message,
    ) -> Message {
        crate::proxy::apply_ws_frame_plugins(plugins, proxy_id, connection_id, direction, raw).await
    }

    /// Prepare deferred delivery observations for the final post-plugin message.
    pub fn prepare_ws_frame_deliveries_for_test(
        plugins: &[Arc<dyn crate::plugins::Plugin>],
        message: &Message,
    ) -> Vec<(usize, crate::plugins::WsFrameDeliveryObservation)> {
        match crate::proxy::prepare_ws_frame_deliveries(plugins, message) {
            crate::proxy::WsFrameDeliveryBatch::None => Vec::new(),
            crate::proxy::WsFrameDeliveryBatch::One(index, observation) => {
                vec![(index, observation)]
            }
            crate::proxy::WsFrameDeliveryBatch::Many(entries) => entries,
        }
    }

    /// Emit previously prepared delivery observations after a successful sink accept.
    pub fn emit_ws_frame_deliveries_for_test(
        plugins: &[Arc<dyn crate::plugins::Plugin>],
        proxy_id: &str,
        connection_id: u64,
        direction: crate::plugins::WebSocketFrameDirection,
        prepared: Vec<(usize, crate::plugins::WsFrameDeliveryObservation)>,
    ) {
        let prepared = match prepared.len() {
            0 => crate::proxy::WsFrameDeliveryBatch::None,
            1 => {
                let mut prepared = prepared;
                if let Some((index, observation)) = prepared.pop() {
                    crate::proxy::WsFrameDeliveryBatch::One(index, observation)
                } else {
                    crate::proxy::WsFrameDeliveryBatch::None
                }
            }
            _ => crate::proxy::WsFrameDeliveryBatch::Many(prepared),
        };
        crate::proxy::emit_ws_frame_deliveries(
            plugins,
            proxy_id,
            connection_id,
            direction,
            prepared,
        )
    }

    /// Apply the shared Ping/Pong control-frame guard used after frame plugins.
    pub fn guard_ws_control_transform_for_test(
        original: &Message,
        transformed: Message,
        direction: crate::plugins::WebSocketFrameDirection,
    ) -> Message {
        crate::proxy::guard_ws_control_transform(original, transformed, direction)
    }

    /// Simulate the shared relay's post-plugin success boundary: run plugins,
    /// apply the control guard, prepare delivery observations from the final
    /// message, then emit them (as if the destination sink accepted the write).
    pub async fn apply_ws_frame_plugins_and_emit_delivery_for_test(
        plugins: &[Arc<dyn crate::plugins::Plugin>],
        proxy_id: &str,
        connection_id: u64,
        direction: crate::plugins::WebSocketFrameDirection,
        raw: Message,
    ) -> Message {
        let outgoing =
            crate::proxy::apply_ws_frame_plugins(plugins, proxy_id, connection_id, direction, raw)
                .await;
        if matches!(&outgoing, Message::Close(_)) {
            // Policy Close is already recorded by observational `on_ws_frame`
            // hooks inside the applicator; the production relay does not also
            // emit a delivered observation for that rejection path.
            return outgoing;
        }
        let prepared = crate::proxy::prepare_ws_frame_deliveries(plugins, &outgoing);
        crate::proxy::emit_ws_frame_deliveries(
            plugins,
            proxy_id,
            connection_id,
            direction,
            prepared,
        );
        outgoing
    }

    /// Report the production parser-policy and post-reassembly hook lists.
    pub fn websocket_relay_plugin_names_for_test(
        plugins: &[Arc<dyn crate::plugins::Plugin>],
        requires_websocket_framing: bool,
    ) -> (Vec<String>, Vec<String>) {
        let (framing_plugins, frame_plugins) =
            crate::proxy::collect_websocket_relay_plugins(plugins, requires_websocket_framing);
        (
            framing_plugins
                .iter()
                .map(|plugin| plugin.name().to_string())
                .collect(),
            frame_plugins
                .iter()
                .map(|plugin| plugin.name().to_string())
                .collect(),
        )
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
            262_144,
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

    /// Inspect whether a buffered rustls `ServerConnection` may be abandoned
    /// for kTLS. Always returns `false`: the public buffered API cannot prove
    /// that the inbound deframer is empty and record-aligned (issue #2955).
    /// The shared borrow is part of the contract — external tests use it to
    /// pin that the refusal leaves every staged application byte readable.
    pub fn ktls_rustls_buffers_safe_for_kernel_handoff(
        server_conn: &rustls::ServerConnection,
    ) -> bool {
        crate::proxy::tcp_proxy::ktls_rustls_buffers_safe_for_kernel_handoff(server_conn)
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
    ) -> usize {
        plugin.rebuild_vector_index_for_tests().await
    }

    pub fn ai_semantic_cache_size_accounting_snapshot_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) -> (usize, usize) {
        plugin.size_accounting_snapshot_for_tests()
    }

    pub fn ai_semantic_cache_vector_snapshot_accounted_bytes_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) -> usize {
        plugin.vector_snapshot_accounted_bytes_for_tests()
    }

    pub fn ai_semantic_cache_cache_budget_used_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) -> usize {
        plugin.cache_budget_used_for_tests()
    }

    pub async fn ai_semantic_cache_force_vector_rebuild_budget_failure_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) -> bool {
        plugin.force_vector_rebuild_budget_failure_for_tests().await
    }

    pub fn ai_semantic_cache_vector_index_dirty_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) -> bool {
        plugin.vector_index_dirty_for_tests()
    }

    pub fn ai_semantic_cache_clear_vector_index_dirty_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) {
        plugin.clear_vector_index_dirty_for_tests();
    }

    pub fn ai_semantic_cache_set_vector_index_rebuild_blocked_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
        blocked: bool,
    ) {
        plugin.set_vector_index_rebuild_blocked_for_tests(blocked);
    }

    pub fn ai_semantic_cache_expire_all_entries_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) {
        plugin.expire_all_entries_for_tests();
    }

    pub fn ai_semantic_cache_force_cleanup_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) {
        plugin.force_cleanup_for_tests();
    }

    pub fn ai_semantic_cache_maintenance_staged_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) -> bool {
        plugin.maintenance_staged_for_tests()
    }

    pub fn ai_semantic_cache_maintenance_committed_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) -> bool {
        plugin.maintenance_committed_for_tests()
    }

    pub fn ai_semantic_cache_maintenance_handle_count_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) -> usize {
        plugin.maintenance_handle_count_for_tests()
    }

    pub fn ai_semantic_cache_notify_cleanup_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) {
        plugin.notify_cleanup_for_tests();
    }

    pub fn ai_semantic_cache_notify_rebuild_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) {
        plugin.notify_rebuild_for_tests();
    }

    pub fn ai_semantic_cache_set_singleflight_wait_override_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
        wait: Option<std::time::Duration>,
    ) {
        plugin.set_singleflight_wait_override_for_tests(wait);
    }

    pub fn ai_semantic_cache_set_store_post_admit_hook_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
        hook: Option<std::sync::Arc<dyn Fn() + Send + Sync + 'static>>,
    ) {
        plugin.set_store_post_admit_hook_for_tests(hook);
    }

    pub fn ai_semantic_cache_instance_id_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
    ) -> u64 {
        plugin.instance_id_for_tests()
    }

    pub fn ai_semantic_cache_staging_metadata_key_for_test(
        plugin: &crate::plugins::ai_semantic_cache::AiSemanticCache,
        suffix: &str,
    ) -> String {
        plugin.staging_metadata_key_for_tests(suffix)
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

    pub fn response_caching_staging_metadata_key_for_test(
        plugin: &crate::plugins::response_caching::ResponseCaching,
        suffix: &str,
    ) -> String {
        plugin.staging_metadata_key_for_tests(suffix)
    }

    pub fn response_caching_instance_id_for_test(
        plugin: &crate::plugins::response_caching::ResponseCaching,
    ) -> u64 {
        plugin.instance_id_for_tests()
    }

    pub fn response_cache_hit_for_test(ctx: &crate::plugins::RequestContext) -> bool {
        ctx.response_cache_hit()
    }

    pub fn finalized_response_replay_for_test(ctx: &crate::plugins::RequestContext) -> bool {
        ctx.finalized_response_replay
    }

    pub fn response_caching_current_total_size_for_test(
        plugin: &crate::plugins::response_caching::ResponseCaching,
    ) -> usize {
        plugin.current_total_size_for_tests()
    }

    /// Effective DashMap shard count the plugin's hot-path maps
    /// (`cache`, `vary_index`, uncacheable predictor) were constructed with.
    pub fn response_caching_shard_amount_for_test(
        plugin: &crate::plugins::response_caching::ResponseCaching,
    ) -> usize {
        plugin.shard_amount_for_tests()
    }

    pub fn response_caching_size_accounting_snapshot_for_test(
        plugin: &crate::plugins::response_caching::ResponseCaching,
    ) -> (usize, usize) {
        plugin.size_accounting_snapshot_for_tests()
    }

    pub fn response_caching_vary_index_snapshot_for_test(
        plugin: &crate::plugins::response_caching::ResponseCaching,
    ) -> Vec<(String, Vec<String>)> {
        plugin.vary_index_snapshot_for_tests()
    }

    pub fn response_caching_cache_keys_for_test(
        plugin: &crate::plugins::response_caching::ResponseCaching,
    ) -> Vec<String> {
        plugin.cache_keys_for_tests()
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

    // ── plugins/rate-limit cleanup wrappers (#2316) ──────────────────────────
    /// Controllable-time harness for consumer cleanup wrappers. External tests
    /// exercise sampled/cooldown routing through these hooks rather than calling
    /// `LocalLimiter::prune_stale_at` directly.
    pub struct RateLimitCleanupHarness {
        udp: crate::plugins::udp_rate_limiting::UdpRateLimiting,
        rate_limiting: crate::plugins::rate_limiting::RateLimiting,
        ai: crate::plugins::ai_rate_limiter::AiRateLimiter,
        graphql: crate::plugins::graphql::GraphqlPlugin,
        grpc: crate::plugins::grpc_method_router::GrpcMethodRouter,
        ws: crate::plugins::ws_rate_limiting::WsRateLimiting,
    }

    impl Default for RateLimitCleanupHarness {
        fn default() -> Self {
            Self::new()
        }
    }

    impl RateLimitCleanupHarness {
        pub fn new() -> Self {
            use crate::plugins::PluginHttpClient;
            use serde_json::json;

            let http = PluginHttpClient::default();
            Self {
                udp: crate::plugins::udp_rate_limiting::UdpRateLimiting::new_with_http_client(
                    &json!({"datagrams_per_second": 1_000, "window_seconds": 1}),
                    http.clone(),
                )
                .expect("udp_rate_limiting"),
                rate_limiting: crate::plugins::rate_limiting::RateLimiting::new(
                    &json!({
                        "limits": [{"scope": "default", "requests_per_second": 100}]
                    }),
                    http.clone(),
                )
                .expect("rate_limiting"),
                ai: crate::plugins::ai_rate_limiter::AiRateLimiter::new(
                    &json!({"token_limit": 1_000, "window_seconds": 1}),
                    http.clone(),
                )
                .expect("ai_rate_limiter"),
                graphql: crate::plugins::graphql::GraphqlPlugin::new(
                    &json!({
                        "type_rate_limits": {
                            "query": {"max_requests": 100, "window_seconds": 1}
                        }
                    }),
                    http.clone(),
                )
                .expect("graphql"),
                grpc: crate::plugins::grpc_method_router::GrpcMethodRouter::new(
                    &json!({
                        "method_rate_limits": {
                            "/pkg.Svc/Method": {"max_requests": 100, "window_seconds": 1}
                        }
                    }),
                    http.clone(),
                )
                .expect("grpc_method_router"),
                ws: crate::plugins::ws_rate_limiting::WsRateLimiting::new(
                    &json!({"frames_per_second": 100, "burst_size": 100}),
                    http,
                )
                .expect("ws_rate_limiting"),
            }
        }

        pub fn udp_epoch_base(&self) -> std::time::Instant {
            self.udp.epoch_base_for_test()
        }

        pub fn seed_udp(&self, ip: &str, now: std::time::Instant) {
            self.udp
                .seed_client_at_for_test(std::sync::Arc::<str>::from(ip), 1, now);
        }

        pub fn seed_udp_with_cap(
            &self,
            ip: &str,
            now: std::time::Instant,
            max_entries: usize,
        ) -> bool {
            self.udp.seed_client_at_with_cap_for_test(
                std::sync::Arc::<str>::from(ip),
                1,
                now,
                max_entries,
            )
        }

        pub fn arm_udp_periodic(&self) {
            self.udp.arm_periodic_eviction_for_test();
        }

        pub fn block_udp_cooldown_at(&self, now: std::time::Instant) {
            self.udp.block_eviction_cooldown_at_for_test(now);
        }

        pub fn maybe_evict_udp_at(&self, now: std::time::Instant) -> bool {
            self.udp.maybe_evict_at_for_test(now)
        }

        pub fn udp_contains(&self, ip: &str) -> bool {
            self.udp
                .contains_client_for_test(&std::sync::Arc::<str>::from(ip))
        }

        pub fn udp_tracked(&self) -> Option<usize> {
            use crate::plugins::Plugin;
            self.udp.tracked_keys_count()
        }

        pub fn maybe_evict_udp_at_with_cap(
            &self,
            now: std::time::Instant,
            max_entries: usize,
        ) -> bool {
            self.udp.maybe_evict_at_with_cap_for_test(now, max_entries)
        }

        pub fn udp_all_shard_len_calls(&self) -> usize {
            self.udp.all_shard_len_calls_for_test()
        }

        pub fn udp_map_len(&self) -> usize {
            self.udp.map_len_for_test()
        }

        pub fn seed_rate_limiting(&self, key: &str, now: std::time::Instant) {
            self.rate_limiting
                .seed_key_at_for_test(key.to_string(), now);
        }

        pub fn arm_rate_limiting_periodic(&self) {
            self.rate_limiting.arm_periodic_eviction_for_test();
        }

        pub fn block_rate_limiting_cooldown_at(&self, now: std::time::Instant) {
            self.rate_limiting.block_periodic_cooldown_at_for_test(now);
        }

        pub fn maybe_evict_rate_limiting_at(&self, now: std::time::Instant) {
            self.rate_limiting
                .maybe_evict_stale_entries_at_for_test(now);
        }

        pub fn rate_limiting_contains(&self, key: &str) -> bool {
            self.rate_limiting.contains_key_for_test(key)
        }

        pub fn rate_limiting_tracked(&self) -> Option<usize> {
            use crate::plugins::Plugin;
            self.rate_limiting.tracked_keys_count()
        }

        pub fn rate_limiting_apply_branch(
            &self,
            now: std::time::Instant,
            over_capacity: bool,
            max_entries: usize,
        ) {
            self.rate_limiting
                .apply_cleanup_branch_for_test(now, over_capacity, max_entries);
        }

        pub fn seed_ai(&self, key: &str, now: std::time::Instant) {
            self.ai.seed_key_at_for_test(key.to_string(), now);
        }

        pub fn arm_ai_periodic(&self) {
            self.ai.arm_periodic_eviction_for_test();
        }

        pub fn maybe_evict_ai_at(&self, now: std::time::Instant) {
            self.ai.evict_stale_entries_at_for_test(now);
        }

        pub fn ai_contains(&self, key: &str) -> bool {
            self.ai.contains_key_for_test(key)
        }

        pub fn ai_tracked(&self) -> Option<usize> {
            use crate::plugins::Plugin;
            self.ai.tracked_keys_count()
        }

        pub fn ai_apply_branch(
            &self,
            now: std::time::Instant,
            over_capacity: bool,
            max_entries: usize,
        ) {
            self.ai
                .apply_cleanup_branch_for_test(now, over_capacity, max_entries);
        }

        pub fn seed_graphql(&self, key: &str, now: std::time::Instant) {
            self.graphql.seed_key_at_for_test(key.to_string(), now);
        }

        pub fn arm_graphql_periodic(&self) {
            self.graphql.arm_periodic_eviction_for_test();
        }

        pub fn maybe_evict_graphql_at(&self, now: std::time::Instant) {
            self.graphql.evict_stale_entries_at_for_test(now);
        }

        pub fn graphql_contains(&self, key: &str) -> bool {
            self.graphql.contains_key_for_test(key)
        }

        pub fn graphql_tracked(&self) -> Option<usize> {
            use crate::plugins::Plugin;
            self.graphql.tracked_keys_count()
        }

        pub fn graphql_apply_branch(
            &self,
            now: std::time::Instant,
            over_capacity: bool,
            max_entries: usize,
        ) {
            self.graphql
                .apply_cleanup_branch_for_test(now, over_capacity, max_entries);
        }

        pub fn seed_grpc(&self, key: &str, now: std::time::Instant) {
            self.grpc.seed_key_at_for_test(key.to_string(), now);
        }

        pub fn arm_grpc_periodic(&self) {
            self.grpc.arm_periodic_eviction_for_test();
        }

        pub fn maybe_evict_grpc_at(&self, now: std::time::Instant) {
            self.grpc.evict_stale_entries_at_for_test(now);
        }

        pub fn grpc_contains(&self, key: &str) -> bool {
            self.grpc.contains_key_for_test(key)
        }

        pub fn grpc_tracked(&self) -> Option<usize> {
            use crate::plugins::Plugin;
            self.grpc.tracked_keys_count()
        }

        pub fn grpc_apply_branch(
            &self,
            now: std::time::Instant,
            over_capacity: bool,
            max_entries: usize,
        ) {
            self.grpc
                .apply_cleanup_branch_for_test(now, over_capacity, max_entries);
        }

        pub fn seed_ws(&self, connection_id: u64, now: std::time::Instant) {
            self.ws.seed_connection_at_for_test(connection_id, now);
        }

        pub fn arm_ws_periodic(&self) {
            self.ws.arm_periodic_eviction_for_test();
        }

        pub fn block_ws_cooldown_at(&self, now: std::time::Instant) {
            self.ws.block_periodic_cooldown_at_for_test(now);
        }

        pub fn maybe_evict_ws_at(&self, now: std::time::Instant) -> bool {
            self.ws.maybe_evict_at_for_test(now)
        }

        pub fn ws_contains(&self, connection_id: u64) -> bool {
            self.ws.contains_connection_for_test(connection_id)
        }

        pub fn ws_tracked(&self) -> Option<usize> {
            use crate::plugins::Plugin;
            self.ws.tracked_keys_count()
        }

        pub fn ws_apply_branch(
            &self,
            now: std::time::Instant,
            over_capacity: bool,
            max_entries: usize,
        ) {
            self.ws
                .apply_cleanup_branch_for_test(now, over_capacity, max_entries);
        }
    }

    /// Build `udp_rate_limiting` with an explicit pool-shard override for
    /// hot-path shard-scaling regressions (#2314).
    pub fn udp_rate_limiting_with_shards_for_test(
        config: &serde_json::Value,
        pool_shard_amount: usize,
    ) -> crate::plugins::udp_rate_limiting::UdpRateLimiting {
        use crate::config::PoolConfig;
        use crate::dns::{DnsCache, DnsConfig};
        use crate::plugins::PluginHttpClient;

        let http = PluginHttpClient::new(
            &PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            1000,
            0,
            100,
            false,
            None,
            std::sync::Arc::new(Vec::new()),
            "ferrum",
            crate::config::BackendEgressPolicy::unrestricted(),
            std::sync::Arc::new(Vec::new()),
            pool_shard_amount,
        );
        crate::plugins::udp_rate_limiting::UdpRateLimiting::new_with_http_client(config, http)
            .expect("udp_rate_limiting constructs")
    }

    pub fn udp_rate_limiting_all_shard_len_calls_for_test(
        plugin: &crate::plugins::udp_rate_limiting::UdpRateLimiting,
    ) -> usize {
        plugin.all_shard_len_calls_for_test()
    }

    pub fn udp_rate_limiting_map_len_for_test(
        plugin: &crate::plugins::udp_rate_limiting::UdpRateLimiting,
    ) -> usize {
        plugin.map_len_for_test()
    }

    pub fn udp_rate_limiting_seed_client_at_for_test(
        plugin: &crate::plugins::udp_rate_limiting::UdpRateLimiting,
        client_ip: &str,
        datagram_size: u64,
        now: std::time::Instant,
    ) {
        plugin.seed_client_at_for_test(std::sync::Arc::<str>::from(client_ip), datagram_size, now);
    }

    pub fn udp_rate_limiting_maybe_evict_at_for_test(
        plugin: &crate::plugins::udp_rate_limiting::UdpRateLimiting,
        now: std::time::Instant,
    ) -> bool {
        plugin.maybe_evict_at_for_test(now)
    }

    pub fn udp_rate_limiting_epoch_base_for_test(
        plugin: &crate::plugins::udp_rate_limiting::UdpRateLimiting,
    ) -> std::time::Instant {
        plugin.epoch_base_for_test()
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
    pub use crate::plugins::utils::redis_rate_limiter::MAX_REDIS_POOL_SIZE;
    pub use crate::plugins::utils::redis_rate_limiter::RedisConfig;
    pub use crate::plugins::utils::redis_rate_limiter::RedisRateLimitClient;
    pub use crate::plugins::utils::redis_rate_limiter::RedisWindowProgress;

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
        let client = RedisRateLimitClient::new(config, None, false, None);
        let redis_client = client.build_client(url).map_err(|e| e.to_string())?;
        let info = redis_client.get_connection_info();
        Ok((
            info.redis_settings().username().map(|s| s.to_string()),
            info.redis_settings().password().map(|s| s.to_string()),
        ))
    }

    pub fn redis_rate_limit_client_for_test(config: RedisConfig) -> RedisRateLimitClient {
        RedisRateLimitClient::new(config, None, false, None)
    }

    /// Deterministic Redis sliding-window index + elapsed fraction for tests.
    pub fn redis_window_progress_at(
        now: std::time::Duration,
        window_seconds: u64,
    ) -> RedisWindowProgress {
        RedisRateLimitClient::window_progress_at(now, window_seconds)
    }

    /// Live-clock Redis sliding-window progress (single timestamp sample).
    pub fn redis_window_progress(window_seconds: u64) -> RedisWindowProgress {
        RedisRateLimitClient::window_progress(window_seconds)
    }

    // ── config/db_loader ─────────────────────────────────────────────────────
    pub use crate::config::db_loader::DbPoolConfig;

    pub async fn await_pool_connect_with_timeout<F, T>(
        timeout_seconds: u64,
        connect: F,
    ) -> Result<T, sqlx::Error>
    where
        F: std::future::Future<Output = Result<T, sqlx::Error>>,
    {
        crate::config::db_loader::await_pool_connect_with_timeout(timeout_seconds, connect).await
    }

    pub fn effective_pool_connect_timeout_seconds(db_type: &str, configured_seconds: u64) -> u64 {
        crate::config::db_loader::effective_pool_connect_timeout_seconds(
            db_type,
            configured_seconds,
        )
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

    pub fn mongo_mtls_dns_admission_lock_filter(
        namespace: &str,
        owner: &str,
    ) -> mongodb::bson::Document {
        crate::config::mongo_store::MongoStore::mtls_dns_admission_lock_filter(namespace, owner)
    }

    pub fn mongo_mtls_dns_admission_lock_update(
        owner: &str,
        client_now_millis: i64,
    ) -> mongodb::bson::Document {
        crate::config::mongo_store::MongoStore::mtls_dns_admission_lock_update(
            owner,
            mongodb::bson::DateTime::from_millis(client_now_millis),
        )
    }

    pub fn mongo_mtls_dns_admission_drop_must_retain(
        mutation_started: bool,
        outcome_settled: bool,
    ) -> bool {
        crate::config::mongo_store::MongoStore::mtls_dns_admission_drop_must_retain_for_test(
            mutation_started,
            outcome_settled,
        )
    }

    pub fn admin_mtls_dns_admission_drop_should_release(
        mutation_started: bool,
        outcome_settled: bool,
    ) -> bool {
        crate::admin::mtls_dns_admission_drop_should_release_for_test(
            mutation_started,
            outcome_settled,
        )
    }

    pub fn admin_mtls_dns_admission_contention_response(
        raw_backend_detail: &str,
    ) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
        let error = crate::config::db_backend::mark_mtls_dns_admission_unavailable(
            anyhow::anyhow!(raw_backend_detail.to_string()),
        );
        crate::admin::crud::consumer_persist_error_response(&error)
    }

    pub fn admin_consumer_persistence_response_for_test(
        raw_backend_detail: &str,
    ) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
        let error = anyhow::anyhow!(raw_backend_detail.to_string());
        crate::admin::crud::consumer_persist_error_response(&error)
    }

    pub fn admin_batch_persistence_message_for_test(raw_backend_detail: &str) -> String {
        let error = anyhow::anyhow!(raw_backend_detail.to_string());
        crate::admin::payload_persist_error_message(&error)
    }

    pub fn admin_recovery_persistence_message_for_test(raw_backend_detail: &str) -> String {
        let error = anyhow::anyhow!(raw_backend_detail.to_string());
        crate::admin::redacted_recovery_error_message(
            "external_recovery_regression",
            "failed to clear existing config",
            &error,
        )
    }

    pub fn admin_database_error_body_for_test(raw_backend_detail: &str) -> serde_json::Value {
        crate::admin::db_error_response(&raw_backend_detail)
    }

    pub fn admin_wrapped_mtls_conflict_message_for_test(raw_backend_detail: &str) -> String {
        let conflict = crate::config::db_backend::MtlsDnsIdentityConflict::new(vec![
            "consumers edge-a and edge-b share mTLS DNS identity svc.internal".to_string(),
        ]);
        let error = anyhow::Error::new(conflict).context(raw_backend_detail.to_string());
        crate::admin::payload_persist_error_message(&error)
    }

    pub fn admin_wrapped_mtls_conflict_response_for_test(
        raw_backend_detail: &str,
    ) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
        let conflict = crate::config::db_backend::MtlsDnsIdentityConflict::new(vec![
            "consumers edge-a and edge-b share mTLS DNS identity svc.internal".to_string(),
        ]);
        let error = anyhow::Error::new(conflict).context(raw_backend_detail.to_string());
        crate::admin::crud::consumer_persist_error_response(&error)
    }

    pub fn admin_throttle_conflict_message_for_test(raw_backend_detail: &str) -> String {
        let conflict =
            crate::config::db_backend::TcpConnectionThrottleAttachmentConflict::new(vec![
                "PluginConfig 'throttle-a' cannot attach to UDP proxy 'edge-a'".to_string(),
            ]);
        let error = anyhow::Error::new(conflict).context(raw_backend_detail.to_string());
        crate::admin::payload_persist_error_message(&error)
    }

    pub fn admin_proxy_route_conflict_message_for_test(raw_backend_detail: &str) -> String {
        let error = anyhow::anyhow!(
            "{}: {}",
            crate::config::db_backend::PROXY_ROUTE_CONFLICT_ERROR,
            raw_backend_detail
        );
        crate::admin::payload_persist_error_message(&error)
    }

    pub fn mysql_mtls_dns_admission_lock_insert_sql() -> &'static str {
        crate::config::db_loader::MYSQL_MTLS_DNS_ADMISSION_LOCK_INSERT_SQL
    }

    pub fn mysql_config_change_lock_insert_sql() -> &'static str {
        crate::config::db_loader::MYSQL_CONFIG_CHANGE_LOCK_INSERT_SQL
    }

    pub fn mysql_proxy_route_lock_insert_sql() -> &'static str {
        crate::config::db_loader::MYSQL_PROXY_ROUTE_LOCK_INSERT_SQL
    }

    pub fn mtls_dns_policy_requires_consumer_load(
        config: &crate::config::types::GatewayConfig,
    ) -> bool {
        config.has_effective_mtls_dns_identity_policy()
    }

    pub fn validate_tcp_connection_throttle_attachments(
        config: &crate::config::types::GatewayConfig,
    ) -> Result<(), Vec<String>> {
        crate::plugin_cache::validate_tcp_connection_throttle_attachments(config)
    }

    pub fn mongo_pipeline_update_unsupported(error: &mongodb::error::Error) -> bool {
        crate::config::mongo_store::MongoStore::pipeline_update_unsupported_for_test(error)
    }

    /// MongoDB timeout precedence (issue #2988): URI-parsed
    /// `serverSelectionTimeoutMS`/`connectTimeoutMS` survive when the env
    /// override is `None`, and are replaced only when explicitly set.
    pub fn apply_mongo_timeout_overrides(
        client_options: &mut mongodb::options::ClientOptions,
        server_selection_timeout_secs: Option<u64>,
        connect_timeout_secs: Option<u64>,
    ) {
        crate::config::mongo_store::apply_mongo_timeout_overrides(
            client_options,
            server_selection_timeout_secs,
            connect_timeout_secs,
        )
    }

    /// Consumer-identity ordered-insert prefix attribution (issue #2987): only
    /// the prefix before the E11000 write-error index was inserted by this
    /// attempt; `None` means attribution is unknown (retain everything).
    pub fn ordered_insert_newly_inserted_prefix<T>(
        values: &[T],
        first_error_index: Option<usize>,
    ) -> &[T] {
        crate::config::mongo_store::ordered_insert_newly_inserted_prefix(values, first_error_index)
    }

    /// Consumer-identity adoption-failure release set (issue #2987): the
    /// verifiable ordered-insert prefix plus vacant reservations this adoption
    /// attempt inserted before failing — never pre-existing same-owner docs.
    pub fn consumer_identity_adoption_failure_release_values(
        ordered_values: &[String],
        ordered_first_error_index: Option<usize>,
        adoption_newly_inserted: &[String],
    ) -> Vec<String> {
        crate::config::mongo_store::consumer_identity_adoption_failure_release_values(
            ordered_values,
            ordered_first_error_index,
            adoption_newly_inserted,
        )
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
        crate::plugins::grpc_web::build_trailer_frame(response_headers, None)
    }

    pub fn build_trailer_frame_with_http_status(
        response_headers: &HashMap<String, String>,
        http_status: Option<u16>,
    ) -> Vec<u8> {
        crate::plugins::grpc_web::build_trailer_frame(response_headers, http_status)
    }

    pub fn sync_translated_body_trailer_frame_from_trailers(
        body: &mut Vec<u8>,
        content_type: Option<&str>,
        reconciled_trailers: &HashMap<String, String>,
        http_status: Option<u16>,
    ) -> bool {
        crate::plugins::grpc_web::sync_translated_body_trailer_frame_from_trailers(
            body,
            content_type,
            reconciled_trailers,
            http_status,
        )
    }

    pub fn truncate_trailing_trailer_frames_for_test(data: &mut Vec<u8>) -> bool {
        crate::plugins::grpc_web::truncate_trailing_trailer_frames(data)
    }

    pub fn begin_buffered_initial_response_header_policy_for_test(
        ctx: &mut crate::plugins::RequestContext,
        header_names: std::sync::Arc<Vec<String>>,
        initial_headers: &HashMap<String, String>,
        merged_headers: &HashMap<String, String>,
    ) {
        ctx.begin_buffered_initial_response_header_policy(
            header_names,
            initial_headers,
            merged_headers,
        );
    }

    pub fn record_buffered_initial_response_header_plugin_for_test(
        ctx: &mut crate::plugins::RequestContext,
        plugin: &dyn crate::plugins::Plugin,
        response_headers: &mut HashMap<String, String>,
    ) {
        ctx.record_buffered_initial_response_header_plugin(plugin, response_headers);
    }

    pub fn http_response_status_to_grpc_status(http_status: u16) -> u32 {
        crate::plugins::grpc_web::http_response_status_to_grpc_status(http_status)
    }

    pub fn parse_grpc_frames(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        crate::plugins::grpc_web::parse_grpc_frames(data)
    }

    pub fn response_content_type(original_ct: &str) -> String {
        crate::plugins::grpc_web::response_content_type(original_ct)
    }

    pub fn negotiate_grpc_web_response_media_type(
        request_content_type: &str,
        accept: Option<&str>,
    ) -> Result<String, crate::plugins::grpc_web::GrpcWebAcceptError> {
        crate::plugins::grpc_web::negotiate_response_media_type(request_content_type, accept)
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
    ) -> bool {
        // No provenance seeding here: the production delegate seeds it, so this
        // shim stays a pure pass-through and tests observe the real behavior of
        // direct H3 reject callers rather than a test-only head start.
        crate::http3::server::run_h3_reject_response_committed_hooks(
            plugins,
            ctx,
            flavor,
            grpc_web_response_content_type,
            http_status,
            body,
            headers,
        )
        .await
    }

    // ── proxy/mod ────────────────────────────────────────────────────────────
    pub fn apply_effective_backend_scheme_headers_for_test(
        headers: &mut HashMap<String, String>,
        client_ip: &str,
        request_is_secure: bool,
        add_forwarded_header: bool,
    ) {
        crate::proxy::apply_effective_backend_scheme_headers(
            headers,
            client_ip,
            request_is_secure,
            add_forwarded_header,
        );
    }

    pub fn collect_forwardable_websocket_headers_for_test(
        raw_headers: &hyper::HeaderMap,
        proxy_headers: &HashMap<String, String>,
    ) -> Vec<(String, String)> {
        crate::proxy::collect_forwardable_websocket_headers(raw_headers, proxy_headers)
    }

    pub struct NormalizedRejectResponse {
        pub http_status: StatusCode,
        pub headers: HashMap<String, String>,
        pub body: Vec<u8>,
        pub grpc_status: Option<u32>,
        pub grpc_message: Option<String>,
    }

    pub struct DeadlineBackendResponse {
        pub status_code: u16,
        pub headers: HashMap<String, String>,
        pub body: Vec<u8>,
        pub connection_error: bool,
        pub error_class: Option<crate::retry::ErrorClass>,
    }

    pub struct PreacquiredBackendAdmissionForTest {
        inner: crate::proxy::PreacquiredBackendAdmission,
    }

    impl PreacquiredBackendAdmissionForTest {
        pub fn acquired(permits: Option<crate::plugins::BackendAdmissionPermitSet>) -> Self {
            Self {
                inner: crate::proxy::PreacquiredBackendAdmission::acquired(permits),
            }
        }

        pub fn take_if_acquired(
            &mut self,
        ) -> Option<Option<crate::plugins::BackendAdmissionPermitSet>> {
            self.inner.take_if_acquired()
        }
    }

    /// The production buffered-H3 sticky-affinity injector: writes the cookie
    /// and, on injection, records `set-cookie` as gRPC-deadline gateway-owned.
    /// This is the exact function the buffered H3 call sites invoke, so a test
    /// through it covers the inject-then-record ordering itself rather than
    /// re-implementing it.
    pub fn h3_inject_sticky_cookie_for_test(
        ctx: &mut crate::plugins::RequestContext,
        epoch: &crate::request_epoch::RequestEpoch,
        proxy: &crate::config::types::Proxy,
        upstream_target: Option<&crate::config::types::UpstreamTarget>,
        sticky_cookie_needed: bool,
        response_headers: &mut HashMap<String, String>,
    ) -> bool {
        crate::http3::server::inject_sticky_cookie_with_deadline_provenance(
            ctx,
            epoch,
            proxy,
            upstream_target,
            sticky_cookie_needed,
            response_headers,
        )
    }

    pub fn h3_buffered_grpc_deadline_replacement_for_test(
        grpc_web_response_content_type: Option<&str>,
    ) -> NormalizedRejectResponse {
        let mut ctx = crate::plugins::RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/test.Service/Call".to_string(),
        );
        ctx.set_grpc_deadline_budget(Some(1_000));
        let mut headers = HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("tracestate".to_string(), "backend=spoof".to_string()),
            ("x-backend-secret".to_string(), "secret".to_string()),
            ("set-cookie".to_string(), "session=secret".to_string()),
            ("vary".to_string(), "Accept-Encoding, Origin".to_string()),
        ]);
        ctx.begin_buffered_deadline_response_header_provenance(&headers);
        headers.insert("x-correlation-id".to_string(), "request-123".to_string());
        ctx.record_deadline_response_header_mutations(&headers);
        let mut body = b"backend response".to_vec();
        let http_status = crate::http3::server::replace_buffered_h3_response_with_grpc_deadline(
            &mut ctx,
            grpc_web_response_content_type,
            &mut headers,
            &mut body,
            &[],
        );
        NormalizedRejectResponse {
            http_status,
            headers,
            body,
            grpc_status: ctx
                .metadata
                .get("grpc_status")
                .and_then(|value| value.parse().ok()),
            grpc_message: ctx.metadata.get("grpc_message").cloned(),
        }
    }

    pub fn buffered_grpc_deadline_replacement_for_test(
        grpc_web_response_content_type: Option<&str>,
        mut backend_headers: HashMap<String, String>,
        gateway_headers: HashMap<String, String>,
        mut body: Vec<u8>,
    ) -> NormalizedRejectResponse {
        let mut ctx = crate::plugins::RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/test.Service/Call".to_string(),
        );
        ctx.set_grpc_deadline_budget(Some(1_000));
        ctx.begin_buffered_deadline_response_header_provenance(&backend_headers);
        backend_headers.extend(gateway_headers);
        ctx.record_deadline_response_header_mutations(&backend_headers);
        let http_status = crate::proxy::replace_buffered_grpc_response_with_deadline(
            &mut ctx,
            grpc_web_response_content_type,
            &mut backend_headers,
            &mut body,
            &[],
        );
        NormalizedRejectResponse {
            http_status,
            headers: backend_headers,
            body,
            grpc_status: ctx
                .metadata
                .get("grpc_status")
                .and_then(|value| value.parse().ok()),
            grpc_message: ctx.metadata.get("grpc_message").cloned(),
        }
    }

    pub async fn run_deadline_bounded_response_committed_hooks_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        response_status: &mut u16,
        response_headers: &mut HashMap<String, String>,
        response_body: &mut Vec<u8>,
    ) -> bool {
        crate::proxy::run_deadline_bounded_response_committed_hooks(
            plugins,
            ctx,
            response_status,
            response_headers,
            response_body,
            &[],
        )
        .await
    }

    /// Like [`transform_buffered_response_body_with_deadline_for_test`] but
    /// returns the full `(response_replaced, representation_rewritten)` pair,
    /// so a test can distinguish "the gate rejected and replaced the response"
    /// from "the gate decoded or a transform rewrote the body" from "nothing
    /// happened".
    ///
    /// `response_body_rejected` is the production flag every buffered path
    /// maintains: `false` while the bytes are still the backend's, `true` once an
    /// `on_response_body` hook replaced them with a gateway-authored rejection.
    pub async fn transform_buffered_response_body_with_deadline_full_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        response_status: &mut u16,
        response_headers: &mut HashMap<String, String>,
        response_body: &mut Vec<u8>,
        grpc_web_response_content_type: Option<&str>,
        response_body_rejected: bool,
    ) -> (bool, bool) {
        crate::proxy::transform_buffered_response_body_with_deadline(
            plugins,
            ctx,
            crate::proxy::buffered_response_representation_origin(response_body_rejected),
            response_status,
            response_headers,
            response_body,
            grpc_web_response_content_type,
            &[],
        )
        .await
    }

    /// Take the pre-`after_proxy` snapshot of a backend response exactly as the
    /// H1/H2, native H3, and H3 bridge paths do before running response hooks.
    ///
    /// Tests that drive the buffered body phase need this because the shared
    /// representation gate treats an unstamped backend response as unprovable
    /// (and therefore rejects it): the snapshot *is* the production precondition,
    /// so exercising the gate without it would test a state the proxy never
    /// produces.
    pub fn stamp_original_response_metadata_for_test(
        ctx: &mut crate::plugins::RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) {
        crate::proxy::stamp_original_response_metadata(ctx, response_status, response_headers);
    }

    /// Force the representation gate's pristine origin-encoding marker so a
    /// defensive identity-only decoder branch can be exercised independently of
    /// the production snapshotter, which intentionally stamps only non-identity
    /// codings.
    pub fn set_original_response_content_encoding_for_test(
        ctx: &mut crate::plugins::RequestContext,
        content_encoding: &str,
    ) {
        ctx.metadata.insert(
            crate::proxy::ORIGIN_ENCODED_RESPONSE_METADATA_KEY.to_string(),
            content_encoding.to_string(),
        );
    }

    /// Run the proxy's real request-init stamp over a context whose raw wire
    /// headers are already set, exactly as the H1/H2 and H3 handlers do
    /// immediately after `set_raw_headers` and before any `before_proxy` hook.
    ///
    /// Tests drive the production snapshotter rather than a setter so the
    /// pristine `Accept-Encoding` a test asserts on is the one the gateway would
    /// actually have captured.
    pub fn stamp_original_request_metadata_for_test(ctx: &mut crate::plugins::RequestContext) {
        crate::proxy::stamp_original_request_metadata(ctx);
    }

    pub fn retain_grpc_web_client_content_type_for_test(
        ctx: &mut crate::plugins::RequestContext,
        content_type: &str,
    ) {
        crate::plugins::grpc_web::retain_client_content_type_for_errors(ctx, content_type);
    }

    /// Drive the governed synthetic short-circuit body phase — the publication
    /// path for gateway-generated bytes (plugin short-circuit, mock,
    /// semantic-cache hit, serverless terminate, dedup replay).
    ///
    /// This is the only way to exercise the shared representation gate under
    /// `RepresentationOrigin::GatewayGenerated`. Those bytes have no
    /// pre-`after_proxy` snapshot, so the gate reads live headers instead, and
    /// its provenance rules there are not reachable through
    /// [`transform_buffered_response_body_with_deadline_full_for_test`].
    pub async fn apply_synthetic_response_body_hooks_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        response_status: &mut u16,
        response_headers: &mut HashMap<String, String>,
        response_body: &mut Vec<u8>,
    ) {
        crate::proxy::apply_synthetic_response_body_hooks(
            plugins,
            ctx,
            response_status,
            response_headers,
            response_body,
        )
        .await
    }

    /// Build the log metadata a transaction summary is rendered from, exactly as
    /// every logger sink does.
    ///
    /// This is the production projection (`clone_log_metadata`), not a
    /// re-implementation, so a test asserting that an internal lifecycle marker
    /// is absent is asserting on the same redaction pass the operator's
    /// transaction logs go through.
    pub fn clone_log_metadata_for_test(
        ctx: &crate::plugins::RequestContext,
    ) -> HashMap<String, String> {
        crate::proxy::clone_log_metadata(ctx)
    }

    /// The stamped `Content-Length` a LATER buffered body transform will read
    /// for this response.
    ///
    /// This is `mcp_gateway`'s own precheck expression, character for character
    /// (`get(ORIGINAL_RESPONSE_CONTENT_LENGTH_METADATA_KEY).and_then(parse)`), so
    /// a test asserting on it is asserting on what the MCP reverse-mapping
    /// transform actually sees. The key is deliberately stripped from transaction
    /// metadata, so `clone_log_metadata_for_test` cannot answer this.
    pub fn stamped_response_content_length_for_test(
        ctx: &crate::plugins::RequestContext,
    ) -> Option<usize> {
        ctx.metadata
            .get(crate::proxy::ORIGINAL_RESPONSE_CONTENT_LENGTH_METADATA_KEY)
            .and_then(|value| value.parse::<usize>().ok())
    }

    /// The low-cardinality reason the shared representation gate rejected this
    /// response, or `None` when it was never rejected.
    pub fn representation_rejection_reason_for_test(
        ctx: &crate::plugins::RequestContext,
    ) -> Option<&str> {
        ctx.metadata
            .get(crate::proxy::REPRESENTATION_REJECTED_METADATA_KEY)
            .map(String::as_str)
    }

    /// Exercise the buffered gRPC trailer-disposition boundary used after a
    /// client-visible body rewrite.
    pub fn discard_grpc_application_trailers_after_body_rewrite_for_test(
        response_headers: &mut HashMap<String, String>,
        response_trailers: &mut HashMap<String, String>,
        header_shadowed_trailer_keys: &[&str],
    ) {
        let header_shadowed_trailer_keys: std::collections::HashSet<String> =
            header_shadowed_trailer_keys
                .iter()
                .map(|name| (*name).to_string())
                .collect();
        crate::proxy::grpc_proxy::discard_grpc_application_trailers_after_body_rewrite(
            response_headers,
            response_trailers,
            &header_shadowed_trailer_keys,
        );
    }

    /// Model the H3 bridge transition from a non-empty backend response to a
    /// synthesized Trailers-Only gateway response, including split-response
    /// finalization.
    pub fn finalize_selected_buffered_grpc_terminal_response_for_test(
        mut response_headers: HashMap<String, String>,
        mut stale_backend_trailers: HashMap<String, String>,
    ) -> (HashMap<String, String>, HashMap<String, String>) {
        let mut authoritative_terminal_metadata = None;
        crate::proxy::grpc_proxy::select_buffered_grpc_terminal_response(
            &response_headers,
            &mut stale_backend_trailers,
            &mut authoritative_terminal_metadata,
        );
        crate::proxy::grpc_proxy::finalize_buffered_grpc_split_response(
            &mut response_headers,
            &mut stale_backend_trailers,
            &std::collections::HashSet::new(),
            None,
            authoritative_terminal_metadata.as_ref(),
            None,
        );
        (response_headers, stale_backend_trailers)
    }

    /// Drive the transaction-metadata status refresh the buffered gRPC paths run
    /// after trailer reconciliation, including the body-framed gRPC-Web case
    /// where the terminal status is deliberately absent from both maps.
    pub fn refresh_grpc_status_metadata_for_test(
        metadata: &mut HashMap<String, String>,
        trailers: &HashMap<String, String>,
        headers: &HashMap<String, String>,
        terminal_metadata_is_body_framed: bool,
    ) {
        crate::proxy::grpc_proxy::refresh_grpc_status_metadata_with_body_framed_terminal(
            metadata,
            trailers,
            headers,
            terminal_metadata_is_body_framed,
        );
    }

    pub async fn run_after_proxy_hooks_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> bool {
        crate::proxy::run_after_proxy_hooks(plugins, ctx, response_status, response_headers)
            .await
            .is_some()
    }

    /// Like [`run_after_proxy_hooks_for_test`] but surfaces the terminal
    /// rejection parts (status, body, headers) when an `after_proxy` hook
    /// rejects or exhausts the RPC deadline, so tests can assert which gateway
    /// decorations survive onto the synthesized DEADLINE_EXCEEDED response.
    pub async fn run_after_proxy_hooks_reject_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> Option<(u16, Vec<u8>, HashMap<String, String>)> {
        crate::proxy::run_after_proxy_hooks(plugins, ctx, response_status, response_headers)
            .await
            .map(|reject| (reject.status_code, reject.body, reject.headers))
    }

    /// Declare response-header keys a trusted hook wrote as a WHOLE-VALUE
    /// REPLACEMENT (a `response_transformer` `update`/`rename` destination, or
    /// an `add` into a slot a `remove` cleared), mirroring the declaration
    /// `response_transformer` makes. Lets tests exercise the
    /// owned-replacement-then-deadline path without a full proxy request.
    ///
    /// This is NOT the sticky-affinity cookie path — that is an APPEND and uses
    /// [`record_deadline_response_header_mutations_for_test`].
    pub fn record_deadline_owned_response_headers_for_test(
        ctx: &mut crate::plugins::RequestContext,
        owned_header_names: &[&str],
        response_headers: &HashMap<String, String>,
    ) {
        ctx.record_deadline_owned_response_headers(owned_header_names, response_headers);
    }

    /// Record a gateway-authored response-header APPEND into deadline
    /// provenance without claiming ownership, mirroring what proxy core does
    /// after injecting the sticky-session affinity `Set-Cookie` outside any
    /// plugin mutation. Lets tests exercise the sticky-cookie-then-deadline
    /// path without a full proxy request.
    pub fn record_deadline_response_header_mutations_for_test(
        ctx: &mut crate::plugins::RequestContext,
        response_headers: &HashMap<String, String>,
    ) {
        ctx.record_deadline_response_header_mutations(response_headers);
    }

    pub async fn transform_buffered_response_body_with_deadline_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        response_status: &mut u16,
        response_headers: &mut HashMap<String, String>,
        response_body: &mut Vec<u8>,
        grpc_web_response_content_type: Option<&str>,
    ) -> bool {
        transform_buffered_response_body_with_deadline_and_policy_for_test(
            plugins,
            ctx,
            response_status,
            response_headers,
            response_body,
            grpc_web_response_content_type,
            &[],
        )
        .await
    }

    pub async fn transform_buffered_response_body_with_deadline_and_policy_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        response_status: &mut u16,
        response_headers: &mut HashMap<String, String>,
        response_body: &mut Vec<u8>,
        grpc_web_response_content_type: Option<&str>,
        initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
    ) -> bool {
        crate::proxy::transform_buffered_response_body_with_deadline(
            plugins,
            ctx,
            // These helpers publish a real backend response, matching every
            // production caller that has not seen an `on_response_body` reject.
            crate::proxy::buffered_response_representation_origin(false),
            response_status,
            response_headers,
            response_body,
            grpc_web_response_content_type,
            initial_response_header_policy_plugins,
        )
        .await
        .0
    }

    pub fn strip_content_length_for_streaming_grpc_deadline_for_test(
        response_headers: &mut HashMap<String, String>,
        deadline_enabled: bool,
    ) {
        let deadline = deadline_enabled.then(tokio::time::Instant::now);
        crate::proxy::strip_content_length_for_streaming_grpc_deadline(response_headers, deadline);
    }

    /// Return true when an indefinitely stalled downstream H3 write is
    /// cancelled by the supplied absolute deadline.
    pub async fn stalled_h3_response_write_expires_for_test(
        deadline: tokio::time::Instant,
    ) -> bool {
        let write = std::future::pending::<Result<(), ()>>();
        matches!(
            crate::http3::stream_util::await_response_write_before_deadline(Some(deadline), write,)
                .await,
            Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded)
        )
    }

    /// Return true when a terminal H3 status that is immediately writable can
    /// still complete after the timer selected the zero-DATA deadline path.
    pub async fn ready_h3_terminal_write_wins_expired_deadline_for_test(
        deadline: tokio::time::Instant,
    ) -> bool {
        matches!(
            crate::http3::stream_util::await_terminal_response_write_before_deadline(
                Some(deadline),
                std::future::ready(Ok::<(), ()>(())),
            )
            .await,
            Ok(())
        )
    }

    /// Return true when an immediately-ready post-deadline terminal rejection
    /// write completes under the shared gateway grace.
    pub async fn ready_h3_post_deadline_terminal_write_completes_for_test() -> bool {
        matches!(
            crate::http3::stream_util::await_post_deadline_terminal_response_write(
                std::future::ready(Ok::<(), ()>(())),
            )
            .await,
            Ok(())
        )
    }

    /// Spawn a stalled post-deadline terminal rejection write under the shared
    /// gateway grace. Callers in paused-time tests must advance simulated time
    /// by [`h3_post_deadline_terminal_write_grace_for_test`] before awaiting the
    /// handle — this helper intentionally never calls Tokio `test-util` APIs.
    pub fn spawn_stalled_h3_post_deadline_terminal_write_for_test() -> tokio::task::JoinHandle<bool>
    {
        let write = std::future::pending::<Result<(), ()>>();
        tokio::spawn(async move {
            matches!(
                crate::http3::stream_util::await_post_deadline_terminal_response_write(write).await,
                Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded)
            )
        })
    }

    pub fn h3_post_deadline_terminal_write_grace_for_test() -> std::time::Duration {
        crate::http3::stream_util::H3_POST_DEADLINE_TERMINAL_WRITE_GRACE
    }

    pub fn grpc_deadline_can_send_terminal_status_for_test(bytes_streamed: u64) -> bool {
        crate::http3::stream_util::grpc_deadline_can_send_terminal_status(bytes_streamed)
    }

    pub fn client_grpc_deadline_response_for_request_for_test(
        content_type: &str,
    ) -> DeadlineBackendResponse {
        let ctx = crate::plugins::RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/test.Service/Call".to_string(),
        );
        let request_headers =
            HashMap::from([("content-type".to_string(), content_type.to_string())]);
        let response = crate::proxy::client_grpc_deadline_exceeded_response_for_request(
            &ctx,
            &request_headers,
            None,
        );
        let body = match response.body {
            crate::retry::ResponseBody::Buffered(body) => body,
            crate::retry::ResponseBody::Streaming { .. }
            | crate::retry::ResponseBody::StreamingH2(_)
            | crate::retry::ResponseBody::StreamingH3(_) => Vec::new(),
        };
        DeadlineBackendResponse {
            status_code: response.status_code,
            headers: response.headers,
            body,
            connection_error: response.connection_error,
            error_class: response.error_class,
        }
    }

    pub fn response_header_deadline_for_test(
        client_deadline_after_ms: Option<u64>,
        backend_read_timeout_ms: u64,
    ) -> Option<(bool, u128)> {
        let read_started_at = tokio::time::Instant::now();
        let client_deadline = client_deadline_after_ms.and_then(|millis| {
            read_started_at.checked_add(std::time::Duration::from_millis(millis))
        });
        crate::proxy::response_header_deadline(
            client_deadline,
            backend_read_timeout_ms,
            read_started_at,
        )
        .map(|(deadline, source)| {
            (
                matches!(source, crate::proxy::ResponseHeaderDeadlineSource::Client),
                deadline
                    .saturating_duration_since(read_started_at)
                    .as_millis(),
            )
        })
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
        crate::proxy::apply_request_body_plugins_with_context(
            plugins, None, None, headers, body_bytes,
        )
        .await
    }

    pub async fn apply_buffered_request_body_normalization_before_before_proxy_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        headers: &mut HashMap<String, String>,
        body: &mut Vec<u8>,
    ) -> crate::plugins::PluginResult {
        crate::proxy::apply_buffered_request_body_normalization_before_before_proxy(
            plugins, ctx, headers, body, true, true,
        )
        .await
    }

    pub async fn apply_buffered_request_body_normalization_with_requirements_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        headers: &mut HashMap<String, String>,
        body: &mut Vec<u8>,
        needs_body_text: bool,
        needs_body_bytes: bool,
    ) -> crate::plugins::PluginResult {
        crate::proxy::apply_buffered_request_body_normalization_before_before_proxy(
            plugins,
            ctx,
            headers,
            body,
            needs_body_text,
            needs_body_bytes,
        )
        .await
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

    pub fn ai_prompt_compressor_marker_scan_work_for_test(
        body: &[u8],
        tag: &str,
    ) -> Option<(Vec<u8>, usize, usize)> {
        let tags = (format!("<{tag}>"), format!("</{tag}>"));
        crate::plugins::ai_prompt_compressor::preserve_marker_sanitizer_work_for_test(body, &tags)
    }

    // ── plugins/ai_semantic_cache staging fields ─────────────────────────────
    //
    // `RequestContext::ai_semantic_cache_embeddings` / `..._scope_keys` are
    // `pub(crate)` so the high-dimensional embedding vector and scope key cannot
    // leak into transaction logs. The accessors below let external unit tests
    // assert per-instance staging (including `exact_only` multimodal skips)
    // without widening the maps to `pub`.
    pub fn ai_semantic_cache_embedding(
        ctx: &crate::plugins::RequestContext,
        instance_id: u64,
    ) -> Option<&Vec<f32>> {
        ctx.ai_semantic_cache_embeddings.get(&instance_id)
    }

    pub fn ai_semantic_cache_scope_key(
        ctx: &crate::plugins::RequestContext,
        instance_id: u64,
    ) -> Option<&str> {
        ctx.ai_semantic_cache_scope_keys
            .get(&instance_id)
            .map(String::as_str)
    }

    pub fn set_ai_semantic_cache_embedding(
        ctx: &mut crate::plugins::RequestContext,
        instance_id: u64,
        embedding: Option<Vec<f32>>,
    ) {
        match embedding {
            Some(values) => {
                ctx.ai_semantic_cache_embeddings.insert(instance_id, values);
            }
            None => {
                ctx.ai_semantic_cache_embeddings.remove(&instance_id);
            }
        }
    }

    pub fn set_ai_semantic_cache_scope_key(
        ctx: &mut crate::plugins::RequestContext,
        instance_id: u64,
        scope_key: Option<String>,
    ) {
        match scope_key {
            Some(key) => {
                ctx.ai_semantic_cache_scope_keys.insert(instance_id, key);
            }
            None => {
                ctx.ai_semantic_cache_scope_keys.remove(&instance_id);
            }
        }
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
            connection_id: 0,
            consumer_username,
            auth_method: None,
            metadata,
            proxy_lifecycle_generation: None,
            session_start,
            // Duration is Instant-based; wall `session_start` is rendering-only.
            session_start_mono: std::time::Instant::now(),
        }
    }

    /// Test helper that pins both wall and monotonic WebSocket session starts.
    #[allow(clippy::too_many_arguments)]
    pub fn make_ws_session_meta_with_mono(
        namespace: String,
        proxy_name: Option<String>,
        client_ip: String,
        backend_target: String,
        listen_port: u16,
        consumer_username: Option<String>,
        metadata: HashMap<String, String>,
        session_start: chrono::DateTime<chrono::Utc>,
        session_start_mono: std::time::Instant,
    ) -> crate::proxy::WsSessionMeta {
        crate::proxy::WsSessionMeta {
            namespace,
            proxy_name,
            client_ip,
            backend_target,
            listen_port,
            connection_id: 0,
            consumer_username,
            auth_method: None,
            metadata,
            proxy_lifecycle_generation: None,
            session_start,
            session_start_mono,
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

    /// Framed (parsed) WebSocket disconnect entry point — mirrors production
    /// teardown in `run_websocket_proxy` so unit tests can assert Instant-based
    /// `duration_ms` with non-zero frame counters.
    #[allow(clippy::too_many_arguments)]
    pub async fn fire_ws_framed_disconnect_hooks(
        ws_disconnect_plugins: &[Arc<dyn Plugin>],
        proxy_id: &str,
        session_meta: crate::proxy::WsSessionMeta,
        frames_client_to_backend: u64,
        frames_backend_to_client: u64,
        bytes_client_to_backend: u64,
        bytes_backend_to_client: u64,
        failure: Option<(
            crate::plugins::Direction,
            crate::retry::ErrorClass,
            Option<StreamIoSide>,
        )>,
    ) {
        crate::proxy::fire_ws_framed_disconnect_hooks(
            ws_disconnect_plugins,
            proxy_id,
            session_meta,
            frames_client_to_backend,
            frames_backend_to_client,
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

    pub fn proxy_body_with_client_grpc_deadline_for_test(
        body: crate::proxy::ProxyBody,
        deadline: tokio::time::Instant,
        grpc_web_response_content_type: Option<&str>,
    ) -> crate::proxy::ProxyBody {
        body.with_client_grpc_deadline(deadline, grpc_web_response_content_type)
    }

    pub fn proxy_body_into_grpc_web_streaming_for_test(
        body: crate::proxy::ProxyBody,
        content_type: &str,
        http_status: u16,
        initial_terminal_metadata: Option<HashMap<String, String>>,
    ) -> crate::proxy::ProxyBody {
        body.into_grpc_web_streaming(content_type, http_status, initial_terminal_metadata)
    }

    pub fn take_streaming_initial_terminal_metadata_for_test(
        response_headers: &mut HashMap<String, String>,
        body_ended: bool,
        pristine_terminal_names: &HashSet<String>,
    ) -> HashMap<String, String> {
        crate::plugins::grpc_web::take_streaming_initial_terminal_metadata(
            response_headers,
            body_ended,
            Some(pristine_terminal_names),
        )
    }

    pub async fn finalized_upload_deadline_response_for_test(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut crate::plugins::RequestContext,
        grpc_web_response_content_type: Option<&str>,
    ) -> http::Response<crate::proxy::ProxyBody> {
        crate::proxy::build_finalized_upload_deadline_response(
            plugins,
            ctx,
            grpc_web_response_content_type,
        )
        .await
        .0
    }

    pub fn inspected_proxy_body_for_test(
        body: crate::proxy::ProxyBody,
        inspector: Box<dyn crate::plugins::ResponseStreamInspector>,
    ) -> crate::proxy::ProxyBody {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(crate::proxy::body::run_proxy_body_response_inspection(
            body,
            inspector,
            tx,
            0,
            crate::proxy::LoadBalancerConnectionGuard::new(None, None),
        ));
        crate::proxy::body::inspected_streaming_body(rx)
    }

    pub fn h3_plugin_protocol_for_request_for_test(
        flavor: crate::config::types::HttpFlavor,
        grpc_web_request: bool,
    ) -> crate::plugins::ProxyProtocol {
        crate::http3::server::h3_plugin_protocol_for_request(flavor, grpc_web_request)
    }

    pub fn udp_logging_should_replace_sender_on_resolve_for_test(
        elapsed: Duration,
        current_addr: Option<std::net::SocketAddr>,
        new_addr: std::net::SocketAddr,
        interval: Duration,
    ) -> bool {
        crate::plugins::udp_logging::should_replace_sender_on_resolve(
            elapsed,
            current_addr,
            new_addr,
            interval,
        )
    }

    pub fn udp_logging_classify_dtls_batch_size_for_test(
        dtls_enabled: bool,
        payload_len: usize,
        batch_len: usize,
        max_plaintext: usize,
    ) -> &'static str {
        use crate::plugins::udp_logging::DtlsBatchSizeDecision;
        match crate::plugins::udp_logging::classify_dtls_batch_size(
            dtls_enabled,
            payload_len,
            batch_len,
            max_plaintext,
        ) {
            DtlsBatchSizeDecision::SendAsIs => "send_as_is",
            DtlsBatchSizeDecision::RejectOversizedSingle => "reject_oversized_single",
            DtlsBatchSizeDecision::SplitPerEntry => "split_per_entry",
        }
    }

    pub fn udp_logging_classify_serialized_summaries_for_test(
        summaries: &[crate::plugins::TransactionSummary],
        max_plaintext: usize,
    ) -> Result<(&'static str, usize), String> {
        use crate::plugins::udp_logging::DtlsBatchSizeDecision;
        use crate::plugins::utils::ByteBudget;
        use crate::plugins::utils::byte_budget::accounted_summary_bytes;
        use crate::plugins::utils::summary_log_budget::serialize_under_byte_budget;
        const HARD_MAX: usize = 16 * 1024 * 1024;
        let aggregate_budget =
            accounted_summary_bytes(HARD_MAX).saturating_mul(summaries.len().max(1));
        let budget = ByteBudget::new("udp_logging_test", aggregate_budget);
        let mut entries = Vec::with_capacity(summaries.len());
        for summary in summaries {
            let Some(payload) = serialize_under_byte_budget(&budget, HARD_MAX, summary) else {
                return Err("udp_logging test helper failed to serialize summary".to_string());
            };
            entries.push(payload);
        }
        let (decision, payload_len) =
            crate::plugins::udp_logging::classify_serialized_dtls_batch_for_test(
                &entries,
                max_plaintext,
            )?;
        let label = match decision {
            DtlsBatchSizeDecision::SendAsIs => "send_as_is",
            DtlsBatchSizeDecision::RejectOversizedSingle => "reject_oversized_single",
            DtlsBatchSizeDecision::SplitPerEntry => "split_per_entry",
        };
        Ok((label, payload_len))
    }

    pub fn udp_logging_validate_dtls_file_dependencies_for_test(
        config: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), String> {
        crate::plugins::udp_logging::validate_dtls_file_dependencies(config)
    }

    pub fn udp_logging_duplicate_dtls_materialization_probe_for_test(
        config: &serde_json::Map<String, serde_json::Value>,
    ) -> (Result<(), String>, Result<(), String>, usize, usize) {
        crate::plugins::udp_logging::duplicate_dtls_materialization_probe_for_test(config)
    }

    pub fn dtls_client_send_output_drain_needs_another_round_for_test(
        has_pending_completion: bool,
        wrote_ciphertext_datagram: bool,
        socket_send_failed: bool,
        fatal_send_failed: bool,
        drain_round_exhausted: bool,
    ) -> bool {
        crate::dtls::client_send_output_drain_needs_another_round_for_test(
            has_pending_completion,
            wrote_ciphertext_datagram,
            socket_send_failed,
            fatal_send_failed,
            drain_round_exhausted,
        )
    }

    /// External regression coverage for issue #2959 (DTLS demux identity-aware
    /// session removal). See
    /// [`crate::dtls::dtls_stale_session_removal_preserves_newer_generation_for_test`].
    pub fn dtls_stale_session_removal_preserves_newer_generation_for_test() -> Result<(), String> {
        crate::dtls::dtls_stale_session_removal_preserves_newer_generation_for_test()
    }

    pub fn udp_logging_dtls_send_timeout_requires_sender_reset_for_test() -> bool {
        crate::plugins::udp_logging::dtls_send_timeout_requires_sender_reset_for_test()
    }

    pub fn udp_logging_local_dtls_size_rejection_preserves_sender_for_test() -> bool {
        crate::plugins::udp_logging::local_dtls_size_rejection_preserves_sender_for_test()
    }

    pub fn udp_logging_transport_dtls_failure_requires_sender_reset_for_test() -> bool {
        crate::plugins::udp_logging::transport_dtls_failure_requires_sender_reset_for_test()
    }

    pub fn udp_logging_dtls_send_timeout_secs_for_test() -> u64 {
        crate::plugins::udp_logging::UDP_LOGGING_DTLS_SEND_TIMEOUT.as_secs()
    }

    #[derive(Debug, PartialEq, Eq)]
    pub enum EarlyUploadWaitError {
        TimedOut,
        DeadlineExceeded,
        Read,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EarlyUploadBoundKind {
        OperatorTimeout,
        RpcDeadline,
    }

    pub fn compose_early_upload_bound_for_test(
        absolute_deadline: Option<tokio::time::Instant>,
        operator_timeout_ms: u64,
    ) -> Option<(tokio::time::Instant, EarlyUploadBoundKind)> {
        crate::proxy::compose_early_upload_bound(absolute_deadline, operator_timeout_ms).map(
            |(deadline, kind)| {
                let kind = match kind {
                    crate::proxy::EarlyUploadBoundKind::OperatorTimeout => {
                        EarlyUploadBoundKind::OperatorTimeout
                    }
                    crate::proxy::EarlyUploadBoundKind::RpcDeadline => {
                        EarlyUploadBoundKind::RpcDeadline
                    }
                };
                (deadline, kind)
            },
        )
    }

    pub fn early_upload_phase_needs_fresh_drain_for_test(
        prebuffered_body: &Option<Vec<u8>>,
    ) -> bool {
        crate::proxy::early_upload_phase_needs_fresh_drain(prebuffered_body)
    }

    pub fn effective_request_body_limit_for_protocol_for_test(
        is_grpc_request: bool,
        http_limit: usize,
        grpc_limit: usize,
        plugin_limit: Option<usize>,
    ) -> usize {
        crate::proxy::effective_request_body_limit_for_protocol(
            is_grpc_request,
            http_limit,
            grpc_limit,
            plugin_limit,
        )
    }

    pub async fn collect_h1h2_request_body_with_deadline_for_test<F, T, E>(
        collect: F,
        deadline: Option<tokio::time::Instant>,
        request_body_read_timeout_ms: u64,
    ) -> Result<Result<T, E>, EarlyUploadWaitError>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        match crate::proxy::collect_request_body_with_deadline(
            collect,
            deadline,
            request_body_read_timeout_ms,
        )
        .await
        {
            Ok(result) => Ok(result),
            Err(crate::proxy::RequestBodyWaitError::TimedOut) => {
                Err(EarlyUploadWaitError::TimedOut)
            }
            Err(crate::proxy::RequestBodyWaitError::DeadlineExceeded) => {
                Err(EarlyUploadWaitError::DeadlineExceeded)
            }
        }
    }

    pub async fn collect_h3_request_body_with_deadline_for_test<F, T, E>(
        collect: F,
        deadline: Option<tokio::time::Instant>,
        request_body_read_timeout_ms: u64,
    ) -> Result<T, EarlyUploadWaitError>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        match crate::http3::server::collect_h3_request_body_with_deadline(
            collect,
            deadline,
            request_body_read_timeout_ms,
        )
        .await
        {
            Ok(value) => Ok(value),
            Err(crate::http3::server::H3RequestBodyReadError::TimedOut) => {
                Err(EarlyUploadWaitError::TimedOut)
            }
            Err(crate::http3::server::H3RequestBodyReadError::DeadlineExceeded) => {
                Err(EarlyUploadWaitError::DeadlineExceeded)
            }
            Err(crate::http3::server::H3RequestBodyReadError::Read(_)) => {
                Err(EarlyUploadWaitError::Read)
            }
        }
    }

    /// Drive CP listener supervision the same way `control_plane::run` does,
    /// so external tests can assert Ok/Err without constructing a full CP.
    pub async fn wait_for_cp_listeners_until_shutdown_or_exit_for_test(
        listener_handles: Vec<(String, tokio::task::JoinHandle<Result<(), anyhow::Error>>)>,
        shutdown_tx: tokio::sync::watch::Sender<bool>,
        drain_timeout: std::time::Duration,
    ) -> Result<(), anyhow::Error> {
        crate::modes::control_plane::wait_for_cp_listeners_until_shutdown_or_exit(
            listener_handles,
            shutdown_tx,
            drain_timeout,
        )
        .await
    }
}
