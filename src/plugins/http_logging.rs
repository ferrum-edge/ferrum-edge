use async_trait::async_trait;
use serde_json::Value;
use tracing::warn;
use url::Url;

use super::utils::PluginHttpClient;
use super::{Plugin, TransactionSummary};

pub struct HttpLogging {
    endpoint_url: String,
    authorization_header: Option<String>,
    http_client: PluginHttpClient,
}

impl HttpLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Self {
        Self {
            endpoint_url: config["endpoint_url"].as_str().unwrap_or("").to_string(),
            authorization_header: config["authorization_header"]
                .as_str()
                .map(|s| s.to_string()),
            http_client,
        }
    }
}

#[async_trait]
impl Plugin for HttpLogging {
    fn name(&self) -> &str {
        "http_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::HTTP_LOGGING
    }

    async fn log(&self, summary: &TransactionSummary) {
        if self.endpoint_url.is_empty() {
            return;
        }
        let mut req = self
            .http_client
            .get()
            .post(&self.endpoint_url)
            .json(summary);
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

    fn warmup_hostnames(&self) -> Vec<String> {
        if self.endpoint_url.is_empty() {
            return Vec::new();
        }
        Url::parse(&self.endpoint_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| vec![h.to_string()]))
            .unwrap_or_default()
    }
}
