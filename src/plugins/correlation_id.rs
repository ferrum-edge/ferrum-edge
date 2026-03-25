//! Correlation ID / Request ID Plugin
//!
//! Generates a unique request ID for every request and propagates it
//! through the proxy chain. If the client sends one, it is preserved.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

use super::{Plugin, PluginResult, RequestContext};

pub struct CorrelationId {
    header_name: String,
    echo_downstream: bool,
}

impl CorrelationId {
    pub fn new(config: &Value) -> Self {
        let header_name = config["header_name"]
            .as_str()
            .unwrap_or("x-request-id")
            .to_lowercase();

        let echo_downstream = config["echo_downstream"].as_bool().unwrap_or(true);

        Self {
            header_name,
            echo_downstream,
        }
    }
}

/// Plugin priority: very early, before everything else.
pub const CORRELATION_ID_PRIORITY: u16 = 50;

#[async_trait]
impl Plugin for CorrelationId {
    fn name(&self) -> &str {
        "correlation_id"
    }

    fn priority(&self) -> u16 {
        CORRELATION_ID_PRIORITY
    }

    fn supports_stream_proxy(&self) -> bool {
        true
    }

    fn modifies_request_headers(&self) -> bool {
        true
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let request_id = if let Some(existing) = ctx.headers.get(&self.header_name) {
            if existing.len() <= 256 {
                existing.clone()
            } else {
                let id = Uuid::new_v4().to_string();
                ctx.headers.insert(self.header_name.clone(), id.clone());
                id
            }
        } else {
            let id = Uuid::new_v4().to_string();
            ctx.headers.insert(self.header_name.clone(), id.clone());
            id
        };

        // Store in metadata for logging plugins
        ctx.metadata.insert("request_id".to_string(), request_id);

        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Ensure the correlation ID header is in the outgoing request
        if let Some(request_id) = ctx.metadata.get("request_id") {
            headers.insert(self.header_name.clone(), request_id.clone());
        }
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if self.echo_downstream
            && let Some(request_id) = ctx.metadata.get("request_id")
        {
            response_headers.insert(self.header_name.clone(), request_id.clone());
        }
        PluginResult::Continue
    }
}
