//! Stdout access logging plugin.
//!
//! Serializes the `TransactionSummary` to JSON and emits it via `tracing::info!`
//! on the `access_log` target. This allows structured log collectors (Fluentd,
//! Vector, etc.) to capture per-request access logs without additional I/O.
//! Supports all proxy protocols (HTTP, gRPC, WebSocket, TCP, UDP).

use async_trait::async_trait;
use serde_json::Value;
use tracing::warn;

use super::{Plugin, TransactionSummary};

pub struct StdoutLogging;

impl StdoutLogging {
    pub fn new(_config: &Value) -> Result<Self, String> {
        Ok(Self)
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
        match serde_json::to_string(summary) {
            Ok(json) => tracing::info!(target: "access_log", "{}", json),
            Err(e) => warn!("stdout_logging: failed to serialize transaction summary: {e}"),
        }
    }

    async fn on_stream_disconnect(&self, summary: &super::StreamTransactionSummary) {
        match serde_json::to_string(summary) {
            Ok(json) => tracing::info!(target: "access_log", "{}", json),
            Err(e) => warn!("stdout_logging: failed to serialize stream summary: {e}"),
        }
    }
}
