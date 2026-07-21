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
pub mod cache_headers;
pub mod cert_hash;
pub mod claim_header_fanout;
pub mod claim_resolver;
pub mod content_encoding;
pub mod dpop;
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
pub mod query;
pub mod rate_limit;
pub mod redis_rate_limiter;
pub mod response_body;
pub mod route_header_transform;
pub mod runtime_bool_gate;
pub mod scope_role_check;
pub mod session_cookie;
pub mod size_limit;
pub mod socket_host;
pub mod sse;
pub mod synthetic_response;
pub mod tcp_endpoint;
pub mod token_extract;
pub mod transformer_gate;
pub mod udp_endpoint;

pub use batching_logger::{
    BatchConfig, BatchingLogger, BatchingLoggerHandle, BatchingLoggerPermit,
    DeferredBatchingLogger, LoggerHooks, MAX_BATCH_SIZE, MAX_BUFFER_CAPACITY, RetryPolicy,
};
pub use http_client::PluginHttpClient;
pub use log_helpers::{
    BatchConfigDefaults, HttpBatchDrainOutcome, SummaryLogEntry, build_batch_config,
    drain_http_batch_response_body, handle_http_batch_response, parse_custom_headers,
    parse_http_endpoint, validate_batch_config,
};
// Re-exported for external unit tests; unused inside the binary target.
#[allow(unused_imports)]
pub use log_helpers::{HTTP_BATCH_RESPONSE_BODY_LIMIT_BYTES, HTTP_BATCH_RESPONSE_DRAIN_TIMEOUT};
pub use socket_host::{parse_socket_host, socket_addr_lookup_input};
pub use tcp_endpoint::resolve_tcp_endpoint;
pub use udp_endpoint::{UDP_RE_RESOLVE_INTERVAL, bind_connected_udp_socket, resolve_udp_endpoint};
