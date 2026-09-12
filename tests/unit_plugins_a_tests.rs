//! Unit Tests: plugins (test files a–j)
//!
//! One of the two plugin test targets. The former monolithic `unit_tests`
//! binary compiled 642k lines in a single rustc frontend; the plugin tests
//! alone are half of that, so they are split alphabetically by test-file
//! name (`a`–`j` in `unit_plugins_a_tests`, `k`–`z` in
//! `unit_plugins_b_tests`) and compiled in parallel by the Unit Tests matrix.
//! Shared helper modules the other half depends on are declared here too;
//! the few helper modules that also carry tests run in both halves.
//!
//! Run with: cargo test --test unit_plugins_a_tests [filter]

mod unit {
    pub mod env_lock;

    pub mod plugins {
        #[allow(dead_code)]
        pub(crate) mod plugin_utils;

        mod a2a_gateway_tests;
        mod access_control_tests;
        mod adaptive_concurrency_tests;
        mod ai_auth_error_envelope_tests;
        mod ai_federation_tests;
        mod ai_prompt_compressor_tests;
        mod ai_prompt_shield_tests;
        mod ai_provider_response_shape_parity_tests;
        mod ai_provider_shape_parity_tests;
        mod ai_rate_limiter_tests;
        mod ai_request_guard_tests;
        mod ai_response_guard_tests;
        mod ai_semantic_cache_tests;
        mod ai_semantic_firewall_tests;
        mod ai_stream_router_adapter_tests;
        mod ai_stream_router_tests;
        mod ai_token_metrics_tests;
        mod ai_tool_governor_tests;
        mod ai_transcript_audit_tests;
        mod ai_usage_stream_tests;
        mod api_chargeback_sink_tests;
        mod api_chargeback_tests;
        mod auth_flow_credential_deadline_tests;
        mod authenticated_identity_bounds_tests;
        mod basic_auth_tests;
        mod batching_logger_tests;
        mod body_transform_tests;
        mod body_validator_tests;
        mod bodyless_sse_refusal_tests;
        mod bot_detection_tests;
        mod byte_budget_tests;
        mod chargeback_mirror_billing_tests;
        mod claim_header_ownership_tests;
        mod compression_tests;
        mod correlation_id_tests;
        mod cors_tests;
        mod custom_plugin_guide_tests;
        mod dp_config_metrics_tests;
        mod dpop_tests;
        mod example_audit_plugin_tests;
        mod example_plugin_tests;
        mod fault_delay_tests;
        mod fault_injection_tests;
        mod geo_restriction_tests;
        mod graphql_tests;
        mod grpc_deadline_tests;
        mod grpc_method_router_tests;
        mod grpc_web_tests;
        mod hmac_auth_tests;
        mod http_batch_response_drain_tests;
        mod http_logging_tests;
        mod ip_restriction_tests;
        mod jwks_auth_custom_token_location_tests;
        mod jwks_auth_inline_keys_tests;
        mod jwks_auth_multi_audience_tests;
        mod jwks_auth_output_claim_header_tests;
        #[allow(dead_code, unused_imports)] // consumed by the k–z half
        mod jwks_auth_support;
        mod jwks_auth_tests;
        mod jwks_cache_tests;
        mod jwks_store_tests;
        mod jwt_auth_plugin_tests;

        #[allow(unused_imports)]
        pub(crate) use plugin_utils::{
            make_plugin_config, make_plugin_config_with_json, make_proxy, minimal_plugin_config,
        };
    }
}
