use async_trait::async_trait;
use serde_json::Value;
use tracing::warn;

use super::{Plugin, TransactionSummary};

pub struct HttpLogging {
    endpoint_url: String,
    authorization_header: Option<String>,
}

impl HttpLogging {
    pub fn new(config: &Value) -> Self {
        Self {
            endpoint_url: config["endpoint_url"].as_str().unwrap_or("").to_string(),
            authorization_header: config["authorization_header"]
                .as_str()
                .map(|s| s.to_string()),
        }
    }
}

#[async_trait]
impl Plugin for HttpLogging {
    fn name(&self) -> &str {
        "http_logging"
    }

    async fn log(&self, summary: &TransactionSummary) {
        if self.endpoint_url.is_empty() {
            return;
        }
        let client = reqwest::Client::new();
        let mut req = client.post(&self.endpoint_url).json(summary);
        if let Some(ref auth) = self.authorization_header {
            req = req.header("Authorization", auth);
        }
        if let Err(e) = req.send().await {
            warn!(
                "HTTP logging plugin failed to send to {}: {}",
                self.endpoint_url, e
            );
        }
    }
}
