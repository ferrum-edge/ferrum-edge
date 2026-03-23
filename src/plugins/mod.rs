pub mod access_control;
pub mod basic_auth;
pub mod body_validator;
pub mod bot_detection;
pub mod correlation_id;
pub mod cors;
pub mod hmac_auth;
pub mod http_logging;
pub mod ip_restriction;
pub mod jwt_auth;
pub mod key_auth;
pub mod oauth2_auth;
pub mod otel_tracing;
pub mod prometheus_metrics;
pub mod rate_limiting;
pub mod request_termination;
pub mod request_transformer;
pub mod response_transformer;
pub mod stdout_logging;
pub mod transaction_debugger;
pub mod utils;

pub use utils::PluginHttpClient;

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
    pub matched_proxy: Option<Arc<Proxy>>,
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
    Reject {
        status_code: u16,
        body: String,
        headers: HashMap<String, String>,
    },
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
    /// For buffered responses: actual total backend time (body fully received).
    /// For streaming responses: -1.0 (body still transferring at log time;
    /// use `latency_backend_ttfb_ms` for alerting).
    pub latency_backend_total_ms: f64,
    pub request_user_agent: Option<String>,
    /// True when the response body was streamed (not buffered).
    /// When true, `latency_backend_total_ms` is -1.0 (unknown at log time).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub response_streamed: bool,
    /// True when the client disconnected before receiving the full response.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub client_disconnected: bool,
    pub metadata: HashMap<String, String>,
}

/// Plugin execution priority bands.
///
/// Plugins are sorted by priority (lowest runs first) within each lifecycle
/// phase. Plugins at the same priority have no guaranteed relative order.
/// Gaps between bands leave room for future plugins to slot in.
///
/// | Band    | Range       | Purpose                                      | Plugins                          |
/// |---------|-------------|----------------------------------------------|----------------------------------|
/// | Early   | 0–999       | Pre-processing: CORS preflight               | cors (100)                       |
/// | AuthN   | 1000–1999   | Authentication: identity verification         | oauth2 (1000), jwt (1100), key (1200), basic (1300) |
/// | AuthZ   | 2000–2999   | Authorization & post-auth enforcement         | access_control (2000), rate_limiting (2900) |
/// | Transform | 3000–3999 | Request transformation before backend         | request_transformer (3000)       |
/// | Response | 4000–4999  | Response transformation after backend         | response_transformer (4000)      |
/// | Logging | 9000–9999   | Logging & observability (fire-and-forget)     | stdout (9000), http (9100), debugger (9200) |
#[allow(dead_code)]
pub mod priority {
    pub const OTEL_TRACING: u16 = 25;
    pub const CORRELATION_ID: u16 = 50;
    pub const REQUEST_TERMINATION: u16 = 75;
    pub const CORS: u16 = 100;
    pub const IP_RESTRICTION: u16 = 150;
    pub const BOT_DETECTION: u16 = 200;
    pub const OAUTH2_AUTH: u16 = 1000;
    pub const JWT_AUTH: u16 = 1100;
    pub const KEY_AUTH: u16 = 1200;
    pub const BASIC_AUTH: u16 = 1300;
    pub const HMAC_AUTH: u16 = 1400;
    pub const ACCESS_CONTROL: u16 = 2000;
    pub const RATE_LIMITING: u16 = 2900;
    pub const BODY_VALIDATOR: u16 = 2950;
    pub const REQUEST_TRANSFORMER: u16 = 3000;
    pub const RESPONSE_TRANSFORMER: u16 = 4000;
    pub const STDOUT_LOGGING: u16 = 9000;
    pub const HTTP_LOGGING: u16 = 9100;
    pub const TRANSACTION_DEBUGGER: u16 = 9200;
    pub const PROMETHEUS_METRICS: u16 = 9300;
    /// Default priority for unknown/custom plugins — runs after transforms, before logging.
    pub const DEFAULT: u16 = 5000;
}

/// Plugin lifecycle hooks.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Returns the plugin name.
    fn name(&self) -> &str;

    /// Returns the execution priority (lower = runs first).
    ///
    /// Plugins are sorted by priority within each lifecycle phase.
    /// See [`priority`] module for standard bands and assignments.
    fn priority(&self) -> u16 {
        priority::DEFAULT
    }

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

    /// Returns `true` if this plugin may modify outgoing request headers
    /// during the `before_proxy` phase. The gateway uses this hint to skip
    /// cloning the header map when no plugin needs to modify it.
    ///
    /// Default is `false`. Override in plugins that insert, remove, or
    /// modify headers in `before_proxy`.
    fn modifies_request_headers(&self) -> bool {
        false
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

    /// Returns `true` if this plugin needs the entire response body buffered
    /// in memory before forwarding to the client. When any active plugin
    /// returns `true`, the gateway forces buffered mode for that proxy
    /// regardless of the `response_body_mode` configuration.
    ///
    /// Default is `false` (compatible with streaming). Override this in
    /// plugins that inspect or transform the response body.
    fn requires_response_body_buffering(&self) -> bool {
        false
    }

    /// Called for transaction logging.
    async fn log(&self, _summary: &TransactionSummary) {}

    /// Returns `true` if this plugin participates in the authentication phase.
    ///
    /// The gateway uses this to filter plugins for the authentication lifecycle
    /// phase, where auth mode (Single vs Multi) determines how failures are
    /// handled. Custom auth plugins should override this to return `true`.
    ///
    /// Default is `false`. Built-in auth plugins (jwt_auth, key_auth,
    /// basic_auth, oauth2_auth, hmac_auth) override this to return `true`.
    fn is_auth_plugin(&self) -> bool {
        false
    }

    /// Returns hostnames that this plugin will send traffic to.
    ///
    /// Used during DNS warmup to pre-resolve plugin endpoint hostnames
    /// alongside proxy backend hostnames, avoiding cold-cache DNS lookups
    /// on the first request through the plugin.
    ///
    /// Default implementation returns an empty list (most plugins make no
    /// outbound network calls). Override this if your plugin has a configured
    /// endpoint URL (e.g., http_logging, oauth2_auth introspection).
    fn warmup_hostnames(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Create a plugin instance from its name and configuration.
///
/// Uses a default `PluginHttpClient` for plugins that make outbound HTTP calls.
/// Prefer [`create_plugin_with_http_client`] in production to share the gateway's
/// pooled client across all plugins for connection reuse and keepalive.
#[allow(dead_code)]
pub fn create_plugin(name: &str, config: &Value) -> Option<Arc<dyn Plugin>> {
    create_plugin_with_http_client(name, config, PluginHttpClient::default())
}

/// Create a plugin instance with a shared HTTP client for outbound calls.
///
/// Plugins that make network calls (http_logging, future OTel exporters, webhooks,
/// etc.) will use this shared client, which is configured with the gateway's
/// connection pool settings (keepalive, idle timeout, HTTP/2 multiplexing).
///
/// This ensures all plugin outbound traffic gets proper connection reuse instead
/// of opening a new TCP+TLS connection per call.
pub fn create_plugin_with_http_client(
    name: &str,
    config: &Value,
    http_client: PluginHttpClient,
) -> Option<Arc<dyn Plugin>> {
    match name {
        "stdout_logging" => Some(Arc::new(stdout_logging::StdoutLogging::new(config))),
        "http_logging" => Some(Arc::new(http_logging::HttpLogging::new(
            config,
            http_client,
        ))),
        "transaction_debugger" => Some(Arc::new(transaction_debugger::TransactionDebugger::new(
            config,
        ))),
        "oauth2_auth" => Some(Arc::new(oauth2_auth::OAuth2Auth::new(
            config,
            http_client.clone(),
        ))),
        "jwt_auth" => Some(Arc::new(jwt_auth::JwtAuth::new(config))),
        "key_auth" => Some(Arc::new(key_auth::KeyAuth::new(config))),
        "basic_auth" => Some(Arc::new(basic_auth::BasicAuth::new(config))),
        "hmac_auth" => Some(Arc::new(hmac_auth::HmacAuth::new(config))),
        "cors" => Some(Arc::new(cors::CorsPlugin::new(config))),
        "access_control" => Some(Arc::new(access_control::AccessControl::new(config))),
        "ip_restriction" => Some(Arc::new(ip_restriction::IpRestriction::new(config))),
        "bot_detection" => Some(Arc::new(bot_detection::BotDetection::new(config))),
        "correlation_id" => Some(Arc::new(correlation_id::CorrelationId::new(config))),
        "request_transformer" => Some(Arc::new(request_transformer::RequestTransformer::new(
            config,
        ))),
        "response_transformer" => Some(Arc::new(response_transformer::ResponseTransformer::new(
            config,
        ))),
        "rate_limiting" => Some(Arc::new(rate_limiting::RateLimiting::new(config))),
        "body_validator" => Some(Arc::new(body_validator::BodyValidator::new(config))),
        "request_termination" => Some(Arc::new(request_termination::RequestTermination::new(
            config,
        ))),
        "prometheus_metrics" => Some(Arc::new(prometheus_metrics::PrometheusMetrics::new(config))),
        "otel_tracing" => Some(Arc::new(otel_tracing::OtelTracing::new(config))),
        _ => {
            // Fall through to custom plugins registry
            let result = crate::custom_plugins::create_custom_plugin(name, config, http_client);
            if result.is_none() {
                tracing::warn!("Unknown plugin: {}", name);
            }
            result
        }
    }
}

/// List of all available plugin names (built-in + custom).
pub fn available_plugins() -> Vec<&'static str> {
    let mut plugins = vec![
        "stdout_logging",
        "http_logging",
        "transaction_debugger",
        "oauth2_auth",
        "jwt_auth",
        "key_auth",
        "basic_auth",
        "hmac_auth",
        "cors",
        "access_control",
        "ip_restriction",
        "bot_detection",
        "correlation_id",
        "request_transformer",
        "response_transformer",
        "rate_limiting",
        "body_validator",
        "request_termination",
        "prometheus_metrics",
        "otel_tracing",
    ];
    plugins.extend(crate::custom_plugins::custom_plugin_names());
    plugins
}
