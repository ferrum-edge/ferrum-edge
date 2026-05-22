//! Stdout access logging plugin.
//!
//! Serializes the `TransactionSummary` to JSON and writes one JSON line to
//! stdout for each transaction, matching the plugin's documented behavior.
//! Supports all proxy protocols (HTTP, gRPC, WebSocket, TCP, UDP).

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tracing::{info, warn};

use super::utils::log_schema::{SchemaView, SummarySchema, resolve_schema};
use super::{Plugin, TransactionSummary};

pub struct StdoutLogging {
    schema: Option<Arc<SummarySchema>>,
}

impl StdoutLogging {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !(config.is_object() || config.is_null()) {
            return Err("stdout_logging: config must be an object".to_string());
        }
        let schema = resolve_schema(config, "stdout_logging")?;
        Ok(Self { schema })
    }
}

#[async_trait]
impl Plugin for StdoutLogging {
    fn name(&self) -> &str {
        "stdout_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::STDOUT_LOGGING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn log(&self, summary: &TransactionSummary) {
        let result = match self.schema.as_ref().filter(|s| s.applies_to_http()) {
            Some(schema) => serde_json::to_string(&SchemaView { summary, schema }),
            None => serde_json::to_string(summary),
        };
        match result {
            Ok(json) => info!(target: "access_log", "{}", json),
            Err(e) => warn!("stdout_logging: failed to serialize transaction summary: {e}"),
        }
    }

    async fn on_stream_disconnect(&self, summary: &super::StreamTransactionSummary) {
        let result = match self.schema.as_ref().filter(|s| s.applies_to_stream()) {
            Some(schema) => serde_json::to_string(&SchemaView { summary, schema }),
            None => serde_json::to_string(summary),
        };
        match result {
            Ok(json) => info!(target: "access_log", "{}", json),
            Err(e) => warn!("stdout_logging: failed to serialize stream summary: {e}"),
        }
    }
}
