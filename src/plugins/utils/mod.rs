//! Shared utilities for plugins.
//!
//! This module contains infrastructure that plugins share, keeping plugin
//! implementation files focused on their core logic.

pub mod http_client;
pub mod redis_rate_limiter;

pub use http_client::PluginHttpClient;
