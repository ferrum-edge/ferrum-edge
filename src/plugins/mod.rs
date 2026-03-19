pub mod access_control;
pub mod basic_auth;
pub mod http_logging;
pub mod jwt_auth;
pub mod key_auth;
pub mod oauth2_auth;
pub mod rate_limiting;
pub mod request_transformer;
pub mod response_transformer;
pub mod stdout_logging;
pub mod transaction_debugger;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::types::{Consumer, Proxy};
use crate::consumer_index::ConsumerIndex;

/// Context passed through the plugin pipeline for a single request.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub matched_proxy: Option<Proxy>,
    pub identified_consumer: Option<Consumer>,
    pub timestamp_received: DateTime<Utc>,
    /// Extra metadata plugins can attach
    pub metadata: HashMap<String, String>,
}

impl RequestContext {
    pub fn new(client_ip: String, method: String, path: String) -> Self {
        Self {
            client_ip,
            method,
            path,
            headers: HashMap::new(),
            query_params: HashMap::new(),
            matched_proxy: None,
            identified_consumer: None,
            timestamp_received: Utc::now(),
            metadata: HashMap::new(),
        }
    }
}

/// Result of a plugin execution.
#[derive(Debug)]
pub enum PluginResult {
    /// Continue to the next plugin/phase.
    Continue,
    /// Short-circuit: immediately return this response to the client.
    Reject { status_code: u16, body: String },
}

/// Transaction summary for logging plugins.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TransactionSummary {
    pub timestamp_received: String,
    pub client_ip: String,
    pub consumer_username: Option<String>,
    pub http_method: String,
    pub request_path: String,
    pub matched_proxy_id: Option<String>,
    pub matched_proxy_name: Option<String>,
    pub backend_target_url: Option<String>,
    pub response_status_code: u16,
    pub latency_total_ms: f64,
    pub latency_gateway_processing_ms: f64,
    pub latency_backend_ttfb_ms: f64,
    pub latency_backend_total_ms: f64,
    pub request_user_agent: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Plugin lifecycle hooks.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Returns the plugin name.
    fn name(&self) -> &str;

    /// Called when a request is first received (before routing).
    async fn on_request_received(&self, _ctx: &mut RequestContext) -> PluginResult {
        PluginResult::Continue
    }

    /// Authentication phase. Uses ConsumerIndex for O(1) credential lookups.
    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Authorization phase (after authentication).
    async fn authorize(&self, _ctx: &mut RequestContext) -> PluginResult {
        PluginResult::Continue
    }

    /// Called just before the request is proxied to the backend.
    async fn before_proxy(
        &self,
        _ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Called after the response is received from the backend.
    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Called for transaction logging.
    async fn log(&self, _summary: &TransactionSummary) {}
}

/// Create a plugin instance from its name and configuration.
pub fn create_plugin(name: &str, config: &Value) -> Option<Arc<dyn Plugin>> {
    match name {
        "stdout_logging" => Some(Arc::new(stdout_logging::StdoutLogging::new(config))),
        "http_logging" => Some(Arc::new(http_logging::HttpLogging::new(config))),
        "transaction_debugger" => Some(Arc::new(transaction_debugger::TransactionDebugger::new(
            config,
        ))),
        "oauth2_auth" => Some(Arc::new(oauth2_auth::OAuth2Auth::new(config))),
        "jwt_auth" => Some(Arc::new(jwt_auth::JwtAuth::new(config))),
        "key_auth" => Some(Arc::new(key_auth::KeyAuth::new(config))),
        "basic_auth" => Some(Arc::new(basic_auth::BasicAuth::new(config))),
        "access_control" => Some(Arc::new(access_control::AccessControl::new(config))),
        "request_transformer" => Some(Arc::new(request_transformer::RequestTransformer::new(
            config,
        ))),
        "response_transformer" => Some(Arc::new(response_transformer::ResponseTransformer::new(
            config,
        ))),
        "rate_limiting" => Some(Arc::new(rate_limiting::RateLimiting::new(config))),
        _ => {
            tracing::warn!("Unknown plugin: {}", name);
            None
        }
    }
}

/// List of all available plugin names.
pub fn available_plugins() -> Vec<&'static str> {
    vec![
        "stdout_logging",
        "http_logging",
        "transaction_debugger",
        "oauth2_auth",
        "jwt_auth",
        "key_auth",
        "basic_auth",
        "access_control",
        "request_transformer",
        "response_transformer",
        "rate_limiting",
    ]
}
