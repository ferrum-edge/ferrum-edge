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

    async fn log(&self, summary: &TransactionSummary) {
        // Create a mutable copy we can enhance
        let enhanced_summary = summary.clone();

        // Add metadata to the log if present
        if !enhanced_summary.metadata.is_empty() {
            // Add metadata as a separate field for better visibility
            if let Ok(mut json_value) = serde_json::to_value(&enhanced_summary) {
                if let Some(obj) = json_value.as_object_mut() {
                    obj.insert(
                        "plugin_metadata".to_string(),
                        serde_json::Value::Object(
                            enhanced_summary
                                .metadata
                                .clone()
                                .into_iter()
                                .map(|(k, v)| (k, serde_json::Value::String(v)))
                                .collect(),
                        ),
                    );
                }
                if let Ok(json) = serde_json::to_string(&json_value) {
                    println!("{}", json);
                    return;
                }
            }
        }

        // Fallback to original logging
        if let Ok(json) = serde_json::to_string(&enhanced_summary) {
            println!("{}", json);
        }
    }
}
