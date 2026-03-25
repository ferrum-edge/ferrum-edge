use async_trait::async_trait;
use serde_json::Value;

use super::{Plugin, TransactionSummary};

pub struct StdoutLogging;

impl StdoutLogging {
    pub fn new(_config: &Value) -> Self {
        Self
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

    fn supports_stream_proxy(&self) -> bool {
        true
    }

    async fn log(&self, summary: &TransactionSummary) {
        if let Ok(json) = serde_json::to_string(summary) {
            tracing::info!(target: "access_log", "{}", json);
        }
    }

    async fn on_stream_disconnect(&self, summary: &super::StreamTransactionSummary) {
        if let Ok(json) = serde_json::to_string(summary) {
            tracing::info!(target: "access_log", "{}", json);
        }
    }
}
