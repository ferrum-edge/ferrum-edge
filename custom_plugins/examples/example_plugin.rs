//! Example Custom Plugin
//!
//! This is a complete, working example of a custom Ferrum Edge plugin.
//! Copy this file as a starting point for your own plugins.
//!
//! This plugin adds a custom `X-Custom-Gateway` header to every request
//! before it is proxied to the backend, and echoes it back in the response.
//! Optional `request_body_prefix`, `correlation_header_name`, and `protocol`
//! fields demonstrate capability metadata used by core composition validation.
//!
//! The `create_plugin` function at the bottom is the only required entry
//! point. This file lives under `custom_plugins/examples/` and is compiled
//! only when listed in `FERRUM_CUSTOM_PLUGINS` (or copied into
//! `custom_plugins/`).

use async_trait::async_trait;
use http::{HeaderName, HeaderValue};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, ProxyProtocol, RequestContext,
    StreamConnectionContext, TCP_ONLY_PROTOCOLS, TransactionSummary,
};

pub struct ExamplePlugin {
    header_value: String,
    request_body_prefix: Option<Vec<u8>>,
    correlation_header_name: Option<String>,
    correlation_header_claim: Option<String>,
    supported_protocols: &'static [ProxyProtocol],
}

const DEFAULT_HEADER_VALUE: &str = "ferrum-custom";
const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;

impl ExamplePlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config = config
            .as_object()
            .ok_or_else(|| "example_plugin config must be a JSON object".to_string())?;

        for key in config.keys() {
            if !matches!(
                key.as_str(),
                "header_value" | "request_body_prefix" | "correlation_header_name" | "protocol"
            ) {
                return Err(format!(
                    "example_plugin config contains unknown key '{key}'; expected only 'header_value', 'request_body_prefix', 'correlation_header_name', and 'protocol'"
                ));
            }
        }

        let header_value = match config.get("header_value") {
            None => DEFAULT_HEADER_VALUE.to_string(),
            Some(Value::String(value)) => value.clone(),
            Some(_) => {
                return Err(
                    "example_plugin.header_value must be a string when present".to_string(),
                );
            }
        };
        if header_value.len() > MAX_HEADER_VALUE_BYTES {
            return Err(format!(
                "example_plugin.header_value must be at most {MAX_HEADER_VALUE_BYTES} bytes"
            ));
        }
        HeaderValue::from_str(&header_value).map_err(|error| {
            format!("example_plugin.header_value must be a valid HTTP header value: {error}")
        })?;

        let request_body_prefix = match config.get("request_body_prefix") {
            None => None,
            Some(Value::String(prefix)) if prefix.is_empty() => {
                return Err("example_plugin.request_body_prefix must not be empty".to_string());
            }
            Some(Value::String(prefix)) => Some(prefix.as_bytes().to_vec()),
            Some(_) => {
                return Err(
                    "example_plugin.request_body_prefix must be a string when present".to_string(),
                );
            }
        };
        let (correlation_header_name, correlation_header_claim) = match config
            .get("correlation_header_name")
        {
            None => (None, None),
            Some(Value::String(value)) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return Err(
                        "example_plugin.correlation_header_name must not be empty".to_string(),
                    );
                }
                let normalized = trimmed.to_ascii_lowercase();
                let header_name = HeaderName::from_bytes(normalized.as_bytes()).map_err(|error| {
                    format!(
                        "example_plugin.correlation_header_name must be a valid HTTP header name: {error}"
                    )
                })?;
                (
                    Some(header_name.as_str().to_string()),
                    Some(value.clone()),
                )
            }
            Some(_) => {
                return Err(
                    "example_plugin.correlation_header_name must be a string when present"
                        .to_string(),
                );
            }
        };
        let supported_protocols = match config.get("protocol") {
            None => HTTP_ONLY_PROTOCOLS,
            Some(Value::String(value)) if value == "http" => HTTP_ONLY_PROTOCOLS,
            Some(Value::String(value)) if value == "tcp" => TCP_ONLY_PROTOCOLS,
            Some(Value::String(value)) => {
                return Err(format!(
                    "example_plugin.protocol must be 'http' or 'tcp', got '{value}'"
                ));
            }
            Some(_) => {
                return Err("example_plugin.protocol must be a string when present".to_string());
            }
        };
        Ok(Self {
            // Read configuration from the plugin's JSON config.
            // In the gateway config, this would look like:
            //   { "plugin_name": "example_plugin", "config": { "header_value": "my-gateway" } }
            header_value,
            request_body_prefix,
            correlation_header_name,
            correlation_header_claim,
            supported_protocols,
        })
    }
}

#[async_trait]
impl Plugin for ExamplePlugin {
    /// Unique name for this plugin. Must match the file name (without .rs).
    fn name(&self) -> &str {
        "example_plugin"
    }

    fn correlation_id_header_name(&self) -> Option<&str> {
        // Keep the configured whitespace and spelling at this capability
        // boundary so the core validator remains defensive against third-party
        // plugins that do not pre-normalize. Runtime header writes still use
        // the validated, lowercase `correlation_header_name` above.
        self.correlation_header_claim.as_deref()
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        self.supported_protocols
    }

    /// Execution priority. See `src/plugins/mod.rs` for the priority band guide:
    ///   - 0–949:    Matched-request preflight (CORS, IP filtering, correlation IDs)
    ///   - 950–1999: Authentication (identity verification)
    ///   - 2000–2999: Authorization (access control, rate limiting)
    ///   - 3000–3999: Request transformation
    ///   - 4000–4999: Response transformation
    ///   - 5000:      Default (custom plugins land here if not overridden)
    ///   - 9000–9999: Logging & observability
    fn priority(&self) -> u16 {
        // Default band — runs after transforms, before logging.
        // Override this to control when your plugin executes relative to others.
        super::super::plugins::priority::DEFAULT
    }

    /// Return `true` if your plugin modifies outgoing request headers in
    /// `before_proxy`. This allows the gateway to skip cloning the header
    /// map when no plugin needs to modify it.
    fn modifies_request_headers(&self) -> bool {
        true
    }

    fn modifies_request_body(&self) -> bool {
        self.request_body_prefix.is_some()
    }

    /// Called after a route matches and its allowed-method check succeeds.
    /// Native gRPC requests must also use `POST` before this hook runs.
    /// On H1, H2, and H3, unmatched 404 and matched-proxy 405 responses invoke
    /// neither global nor scoped instances of this hook. Matched-proxy 405
    /// responses still emit terminal transaction logging separately.
    /// Return `PluginResult::Reject` to short-circuit with an error response.
    async fn on_request_received(&self, _ctx: &mut RequestContext) -> PluginResult {
        // Example: you could reject requests here based on custom logic.
        PluginResult::Continue
    }

    /// Called just before the request is forwarded to the backend.
    /// Use this to add/modify headers sent to the backend.
    async fn before_proxy(
        &self,
        _ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        headers.insert("x-custom-gateway".to_string(), self.header_value.clone());
        if let Some(header_name) = &self.correlation_header_name {
            headers.insert(header_name.clone(), self.header_value.clone());
        }
        PluginResult::Continue
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        let prefix = self.request_body_prefix.as_ref()?;
        let mut transformed = Vec::with_capacity(prefix.len() + body.len());
        transformed.extend_from_slice(prefix);
        transformed.extend_from_slice(body);
        Some(transformed)
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        if let Some(header_name) = &self.correlation_header_name {
            ctx.insert_metadata(header_name.clone(), self.header_value.clone());
        }
        PluginResult::Continue
    }

    /// Called after the backend response is received.
    /// Use this to add/modify response headers sent to the client.
    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        response_headers.insert("x-custom-gateway".to_string(), self.header_value.clone());
        if let Some(header_name) = &self.correlation_header_name {
            response_headers.insert(header_name.clone(), self.header_value.clone());
        }
        PluginResult::Continue
    }

    /// Called for transaction logging. Buffered handlers normally await log
    /// hooks sequentially before returning; deadline-bearing H1/H2 handlers
    /// detach that cleanup under a finite bound. Native H3 awaits after body
    /// completion. Hyper-owned streamed bodies spawn logging after terminal
    /// body completion. Hand potentially slow I/O to a bounded, plugin-owned
    /// worker instead of performing it directly here.
    async fn log(&self, _summary: &TransactionSummary) {
        // Example: enqueue a bounded record for a lifecycle-owned worker.
    }

    // ── Optional overrides ──────────────────────────────────────────────────
    //
    // fn is_auth_plugin(&self) -> bool {
    //     // Return `true` if this plugin participates in the authentication phase.
    //     // This lets the gateway include it in auth mode (Single/Multi) logic.
    //     false
    // }
    //
    // fn requires_response_body_buffering(&self) -> bool {
    //     // Return `true` if your plugin needs to inspect or transform the
    //     // response body. This disables streaming for proxies using this plugin.
    //     false
    // }
    //
    // fn warmup_hostnames(&self) -> Vec<String> {
    //     // Return hostnames your plugin will connect to, so the gateway can
    //     // pre-resolve DNS at startup.
    //     vec![]
    // }
}

/// Factory function — called automatically by the build-script-generated registry.
/// The function name `create_plugin` and signature are the convention that every
/// custom plugin file must follow. Must return `Result` so invalid configs are
/// rejected at admission time (admin API, file mode startup, DB mode warnings).
pub fn create_plugin(
    config: &Value,
    _http_client: PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    Ok(Some(Arc::new(ExamplePlugin::new(config)?)))
}

pub fn failure_policy() -> crate::plugins::PluginFailurePolicy {
    crate::plugins::PluginFailurePolicy::KeepLastKnownGood
}
