//! Unit Tests: plugins (test files k–z)
//!
//! One of the two plugin test targets. The former monolithic `unit_tests`
//! binary compiled 642k lines in a single rustc frontend; the plugin tests
//! alone are half of that, so they are split alphabetically by test-file
//! name (`a`–`j` in `unit_plugins_a_tests`, `k`–`z` in
//! `unit_plugins_b_tests`) and compiled in parallel by the Unit Tests matrix.
//! Shared helper modules the other half depends on are declared here too;
//! the few helper modules that also carry tests run in both halves.
//!
//! Run with: cargo test --test unit_plugins_b_tests [filter]

mod unit {
    pub mod env_lock;

    pub mod plugins {
        #[allow(dead_code)]
        pub(crate) mod plugin_utils;

        #[allow(dead_code, unused_imports)]
        mod jwks_auth_support; // shared helper, also compiled by the other half
        #[allow(dead_code, unused_imports)]
        mod jwks_auth_tests; // shared helper, also compiled by the other half
        #[allow(dead_code, unused_imports)]
        mod jwks_cache_tests; // shared helper, also compiled by the other half
        mod kafka_logging_tests;
        mod key_auth_tests;
        mod ldap_auth_tests;
        mod load_testing_tests;
        mod log_sampling_tests;
        mod logging_sink_lifecycle_tests;
        mod loki_logging_tests;
        mod mcp_aggregate_sse_tests;
        mod mcp_gateway_tests;
        mod mesh_plugins_tests;
        mod mesh_route_dispatch_tests;
        mod mesh_telemetry_metric_families_tests;
        mod mesh_telemetry_tag_cel_tests;
        mod metadata_redaction_contract_tests;
        mod mtls_auth_certificate_lifetime_tests;
        mod mtls_auth_tests;
        mod oauth2_introspection_tests;
        mod oidc_refresh_flight_tests;
        mod oidc_relying_party_tests;
        mod opa_tests;
        mod openapi_validator_tests;
        mod otel_tracing_tests;
        mod plugin_cache_tests;
        mod plugin_doc_parity_tests;
        mod plugin_http_client_tests;
        mod plugin_integration_tests;
        mod plugin_trigger_carrier_tests;
        mod plugin_trigger_gate_tests;
        mod plugin_unknown_key_registry_tests;
        mod plugin_utils_core_tests;
        mod prometheus_metric_contract_tests;
        mod prometheus_metrics_tests;
        mod proxy_alerts_tests;
        mod rate_limit_capacity_tests;
        mod rate_limit_cleanup_tests;
        mod rate_limit_policy_hardening_tests;
        mod rate_limit_state_lifecycle_tests;
        mod rate_limiting_tests;
        mod redis_rate_limiter_tests;
        mod rejection_logging_tests;
        mod replay_authority_tests;
        mod request_deduplication_tests;
        mod request_mirror_tests;
        mod request_size_limiting_tests;
        mod request_termination_tests;
        mod request_transformer_tests;
        mod response_body_bounded_tests;
        mod response_caching_tests;
        mod response_mock_tests;
        mod response_size_limiting_tests;
        mod response_transformer_tests;
        mod route_header_finalization_tests;
        mod security_headers_tests;
        mod serverless_function_tests;
        mod sink_loss_metric_tests;
        mod soap_ws_security_tests;
        mod spec_expose_tests;
        mod spiffe_identity_tests;
        mod sse_tests;
        mod stateful_plugin_generation_tests;
        mod statsd_logging_tests;
        mod stdout_logging_tests;
        mod stream_plugin_tests;
        mod synthetic_response_tests;
        mod tcp_connection_throttle_tests;
        mod tcp_endpoint_tests;
        mod tcp_logging_tests;
        mod transaction_debugger_tests;
        mod transaction_log_schema_tests;
        mod transaction_summary_tests;
        mod udp_endpoint_tests;
        mod udp_logging_tests;
        mod udp_rate_limiting_tests;
        mod validator_diagnostic_redaction_tests;
        mod waf_body_charset_parity_tests;
        mod waf_tests;
        mod workload_metrics_custom_env_tags_tests;
        mod workload_metrics_tests;
        mod ws_frame_logging_tests;
        mod ws_logging_tests;
        mod ws_message_size_limiting_tests;
        mod ws_rate_limiting_tests;
        mod xml_bounds_tests;

        #[allow(unused_imports)]
        pub(crate) use plugin_utils::{
            make_plugin_config, make_plugin_config_with_json, make_proxy, minimal_plugin_config,
        };
    }
}
