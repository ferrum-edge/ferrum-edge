//! Shared utilities for plugins.
//!
//! This module contains infrastructure that plugins share, keeping plugin
//! implementation files focused on their core logic.

pub mod aws_sigv4;
pub mod body_transform;
pub mod http_client;
pub mod jwks_cache;
pub mod jwks_store;
pub mod redis_rate_limiter;

pub use http_client::PluginHttpClient;
