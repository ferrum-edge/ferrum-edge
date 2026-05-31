use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use url::{Host, Url};

use crate::plugins::{StreamTransactionSummary, TransactionSummary};

use super::{BatchConfig, MAX_BATCH_SIZE, MAX_BUFFER_CAPACITY, RetryPolicy};

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
            Self::Http(summary) => summary.proxy_id.as_deref(),
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
    let batch_size = config[defaults.batch_size_key]
        .as_u64()
        .unwrap_or(defaults.batch_size)
        .max(1)
        .min(MAX_BATCH_SIZE as u64)
        .min(usize::MAX as u64) as usize;
    let buffer_capacity = config["buffer_capacity"]
        .as_u64()
        .unwrap_or(defaults.buffer_capacity)
        .max(1)
        .min(MAX_BUFFER_CAPACITY as u64)
        .min(usize::MAX as u64) as usize;
    let max_retries = config["max_retries"]
        .as_u64()
        .unwrap_or(defaults.max_retries);

    BatchConfig {
        batch_size,
        flush_interval: Duration::from_millis(
            config["flush_interval_ms"]
                .as_u64()
                .unwrap_or(defaults.flush_interval_ms)
                .max(defaults.min_flush_interval_ms),
        ),
        buffer_capacity,
        retry: RetryPolicy {
            // Plugin config remains `max_retries`; RetryPolicy stores total
            // attempts, so add the initial try here.
            max_attempts: max_retries.saturating_add(1).min(u64::from(u32::MAX)) as u32,
            delay: Duration::from_millis(
                config["retry_delay_ms"]
                    .as_u64()
                    .unwrap_or(defaults.retry_delay_ms),
            ),
        },
        plugin_name,
    }
}

pub fn validate_batch_config(
    config: &Value,
    plugin_name: &'static str,
    defaults: BatchConfigDefaults,
) -> Result<(), String> {
    for key in [
        defaults.batch_size_key,
        "flush_interval_ms",
        "buffer_capacity",
        "max_retries",
        "retry_delay_ms",
    ] {
        if let Some(value) = config.get(key)
            && value.as_u64().is_none()
        {
            return Err(format!(
                "{plugin_name}: '{key}' must be an unsigned integer"
            ));
        }
    }
    Ok(())
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

    if !has_non_empty_authority(&endpoint_url) {
        return Err(format!(
            "{plugin_name}: 'endpoint_url' must include a hostname or IP address"
        ));
    }

    let host = parsed_url.host().ok_or_else(|| {
        format!("{plugin_name}: 'endpoint_url' must include a hostname or IP address")
    })?;
    let hostname = match host {
        Host::Domain(hostname) => hostname.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };

    Ok((endpoint_url, hostname))
}

pub fn parse_custom_headers(
    config: &Value,
    plugin_name: &'static str,
) -> Result<Vec<(HeaderName, HeaderValue)>, String> {
    let mut custom_headers = Vec::new();
    let Some(custom_headers_value) = config.get("custom_headers") else {
        return Ok(custom_headers);
    };

    let map = custom_headers_value
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: 'custom_headers' must be an object"))?;
    for (key, value) in map {
        let value = value
            .as_str()
            .ok_or_else(|| format!("{plugin_name}: custom_headers['{key}'] must be a string"))?;
        let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|error| {
            format!("{plugin_name}: invalid custom_headers name '{key}': {error}")
        })?;
        let header_value = HeaderValue::from_str(value).map_err(|error| {
            format!("{plugin_name}: invalid custom_headers value for '{key}': {error}")
        })?;
        custom_headers.retain(|(existing, _)| *existing != header_name);
        custom_headers.push((header_name, header_value));
    }

    Ok(custom_headers)
}

fn has_non_empty_authority(endpoint_url: &str) -> bool {
    let Some((_, after_scheme)) = endpoint_url.split_once(':') else {
        return false;
    };
    let Some(authority_and_path) = after_scheme.strip_prefix("//") else {
        return false;
    };
    let authority_end = authority_and_path
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_path.len());

    authority_end > 0
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
