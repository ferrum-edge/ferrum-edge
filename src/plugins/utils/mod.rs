//! Shared utilities for plugins.
//!
//! This module contains infrastructure that plugins share, keeping plugin
//! implementation files focused on their core logic.

pub mod aws_sigv4;
pub mod batching_logger;
pub mod body_transform;
pub mod http_client;
pub mod json_escape;
pub mod jwks_cache;
pub mod jwks_store;
pub mod log_helpers;
pub mod redis_rate_limiter;
pub mod udp_endpoint;

pub use batching_logger::{BatchConfig, BatchingLogger, RetryPolicy};
pub use http_client::PluginHttpClient;
pub use log_helpers::{
    BatchConfigDefaults, SummaryLogEntry, build_batch_config, handle_http_batch_response,
    parse_http_endpoint,
};
pub use udp_endpoint::{UDP_RE_RESOLVE_INTERVAL, bind_connected_udp_socket, resolve_udp_endpoint};
