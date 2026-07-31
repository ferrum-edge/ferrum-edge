//! Shared utilities for plugins.
//!
//! This module contains infrastructure that plugins share, keeping plugin
//! implementation files focused on their core logic.

pub mod ai_pii;
pub mod ai_providers;
pub mod auth_attempt;
pub mod auth_flow;
pub mod aws_sigv4;
pub mod batching_logger;
pub mod body_transform;
pub mod byte_budget;
pub mod cache_headers;
pub mod cert_hash;
pub mod claim_header_fanout;
pub mod claim_resolver;
pub mod content_encoding;
pub mod dpop;
pub mod fault_delay;
pub mod fault_roll;
pub mod http_client;
pub mod introspection_cache;
pub mod json_escape;
pub mod jwks_cache;
pub mod jwks_store;
pub mod jwt_verifier;
pub mod log_helpers;
pub mod log_schema;
pub mod metadata_redaction;
pub mod policy_digest;
pub mod query;
pub mod rate_limit;
pub mod redis_rate_limiter;
pub mod replay_partition;
pub mod response_body;
pub mod route_header_transform;
pub mod runtime_bool_gate;
pub mod scope_role_check;
pub mod session_cookie;
pub mod size_limit;
pub mod socket_host;
pub mod sse;
pub mod summary_log_budget;
pub mod synthetic_response;
pub mod tcp_endpoint;
pub mod token_extract;
pub mod transformer_gate;
pub mod udp_endpoint;
pub mod validation_diagnostics;

pub use batching_logger::{
    BatchConfig, BatchingLogger, BatchingLoggerHandle, BatchingLoggerPermit,
    DeferredBatchingLogger, LoggerHooks, MAX_BATCH_FLUSH_INTERVAL_MS, MAX_BATCH_RETRIES,
    MAX_BATCH_RETRY_DELAY_MS, MAX_BATCH_SIZE, MAX_BUFFER_CAPACITY, RetryPolicy, TrySendOutcome,
    wait_until_committed, wait_until_committed_or_closed,
};
pub use byte_budget::{
    ByteBudget, ByteLease, DEFAULT_BUFFER_MAX_BYTES, HARD_MAX_BUFFER_MAX_BYTES, admit_byte_limits,
};
pub use http_client::PluginHttpClient;
pub use log_helpers::{
    BatchConfigDefaults, HttpBatchDrainOutcome, build_batch_config, drain_http_batch_response_body,
    handle_http_batch_response_redacted, parse_custom_headers, parse_http_endpoint,
    redacted_endpoint_url, redacted_endpoint_url_str, validate_batch_config,
};
pub use summary_log_budget::{
    QueuedSummaryPayload, admit_http_summary, admit_stream_summary, assemble_json_array,
    assemble_ndjson,
};
// Re-exported for external unit tests; unused inside the binary target.
#[allow(unused_imports)]
pub use log_helpers::{
    HTTP_BATCH_RESPONSE_BODY_LIMIT_BYTES, HTTP_BATCH_RESPONSE_DRAIN_TIMEOUT,
    handle_http_batch_response,
};
pub use socket_host::{parse_socket_host, socket_addr_lookup_input};
pub use tcp_endpoint::resolve_tcp_endpoint;
pub use udp_endpoint::{UDP_RE_RESOLVE_INTERVAL, bind_connected_udp_socket, resolve_udp_endpoint};
