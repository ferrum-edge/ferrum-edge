use std::time::Duration;

use serde_json::Value;
use url::Url;

use crate::plugins::{StreamTransactionSummary, TransactionSummary};

use super::{BatchConfig, RetryPolicy};

#[derive(Clone, Copy)]
pub struct BatchConfigDefaults {
    pub batch_size_key: &'static str,
    pub batch_size: u64,
    pub flush_interval_ms: u64,
    pub min_flush_interval_ms: u64,
    pub buffer_capacity: u64,
    pub max_retries: u64,
    pub retry_delay_ms: u64,
}

#[derive(Clone, serde::Serialize)]
#[serde(untagged)]
pub enum SummaryLogEntry {
    Http(TransactionSummary),
    Stream(StreamTransactionSummary),
}

impl SummaryLogEntry {
    pub fn client_ip(&self) -> &str {
        match self {
            Self::Http(summary) => &summary.client_ip,
            Self::Stream(summary) => &summary.client_ip,
        }
    }

    pub fn proxy_id(&self) -> Option<&str> {
        match self {
            Self::Http(summary) => summary.matched_proxy_id.as_deref(),
            Self::Stream(summary) => Some(&summary.proxy_id),
        }
    }
}

impl From<&TransactionSummary> for SummaryLogEntry {
    fn from(summary: &TransactionSummary) -> Self {
        Self::Http(summary.clone())
    }
}

impl From<&StreamTransactionSummary> for SummaryLogEntry {
    fn from(summary: &StreamTransactionSummary) -> Self {
        Self::Stream(summary.clone())
    }
}

pub fn build_batch_config(
    config: &Value,
    plugin_name: &'static str,
    defaults: BatchConfigDefaults,
) -> BatchConfig {
    BatchConfig {
        batch_size: config[defaults.batch_size_key]
            .as_u64()
            .unwrap_or(defaults.batch_size)
            .max(1) as usize,
        flush_interval: Duration::from_millis(
            config["flush_interval_ms"]
                .as_u64()
                .unwrap_or(defaults.flush_interval_ms)
                .max(defaults.min_flush_interval_ms),
        ),
        buffer_capacity: config["buffer_capacity"]
            .as_u64()
            .unwrap_or(defaults.buffer_capacity)
            .max(1) as usize,
        retry: RetryPolicy {
            // Plugin config remains `max_retries`; RetryPolicy stores total
            // attempts, so add the initial try here.
            max_attempts: config["max_retries"]
                .as_u64()
                .unwrap_or(defaults.max_retries) as u32
                + 1,
            delay: Duration::from_millis(
                config["retry_delay_ms"]
                    .as_u64()
                    .unwrap_or(defaults.retry_delay_ms),
            ),
        },
        plugin_name,
    }
}

pub fn parse_http_endpoint(
    config: &Value,
    plugin_name: &'static str,
) -> Result<(String, String), String> {
    let endpoint_url = config["endpoint_url"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!("{plugin_name}: 'endpoint_url' is required — logs will have nowhere to send")
        })?
        .to_string();
    let parsed_url = Url::parse(&endpoint_url)
        .map_err(|error| format!("{plugin_name}: invalid 'endpoint_url': {error}"))?;

    match parsed_url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "{plugin_name}: 'endpoint_url' must use http:// or https:// (got '{scheme}')"
            ));
        }
    }

    let hostname = parsed_url.host_str().ok_or_else(|| {
        format!("{plugin_name}: 'endpoint_url' must include a hostname or IP address")
    })?;

    Ok((endpoint_url, hostname.to_string()))
}

pub fn handle_http_batch_response(
    plugin_label: &str,
    entry_count: usize,
    result: Result<reqwest::Response, reqwest::Error>,
) -> Result<(), String> {
    match result {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => {
            let status = response.status();
            if status.is_client_error()
                && status != reqwest::StatusCode::REQUEST_TIMEOUT
                && status != reqwest::StatusCode::TOO_MANY_REQUESTS
            {
                tracing::warn!(
                    "{plugin_label} batch discarded due to {} response ({} entries lost)",
                    status,
                    entry_count,
                );
                Ok(())
            } else {
                Err(format!("{plugin_label} batch failed with status {status}"))
            }
        }
        Err(error) => Err(format!("{plugin_label} batch failed: {error}")),
    }
}
