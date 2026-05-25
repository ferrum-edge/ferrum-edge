//! Mesh access log plugin.
//!
//! Emits identity-aware access logs through tracing. It is additive to the
//! existing logging plugins and reads the standard transaction summaries.
//!
//! Optional filter support (from Telemetry CRD): status code ranges,
//! latency threshold, errors-only mode.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value};
use tracing::warn;

use super::utils::log_schema::{SchemaView, SummarySchema, resolve_schema};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

pub struct AccessLog {
    /// When set, only log transactions matching all filter predicates.
    filter: Option<Filter>,
    schema: Option<Arc<SummarySchema>>,
}

struct Filter {
    status_code_min: Option<u16>,
    status_code_max: Option<u16>,
    min_latency_ms: Option<u64>,
    errors_only: bool,
}

impl AccessLog {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !(config.is_object() || config.is_null()) {
            return Err("access_log: config must be an object".to_string());
        }

        let filter = match config.get("filter") {
            Some(Value::Null) | None => None,
            Some(Value::Object(filter_config)) => {
                let status_code_min = parse_optional_u16(filter_config, "status_code_min")?;
                let status_code_max = parse_optional_u16(filter_config, "status_code_max")?;
                if let (Some(min), Some(max)) = (status_code_min, status_code_max)
                    && min > max
                {
                    return Err(
                        "access_log: filter.status_code_min must be less than or equal to filter.status_code_max"
                            .to_string(),
                    );
                }

                Some(Filter {
                    status_code_min,
                    status_code_max,
                    min_latency_ms: parse_optional_u64(filter_config, "min_latency_ms")?,
                    errors_only: parse_optional_bool(filter_config, "errors_only")?
                        .unwrap_or(false),
                })
            }
            Some(_) => return Err("access_log: filter must be an object".to_string()),
        };
        let schema = resolve_schema(config, "access_log")?;
        Ok(Self { filter, schema })
    }

    fn should_log_http(&self, summary: &TransactionSummary) -> bool {
        let Some(filter) = &self.filter else {
            return true;
        };
        if let Some(min) = filter.status_code_min
            && summary.response_status_code < min
        {
            return false;
        }
        if let Some(max) = filter.status_code_max
            && summary.response_status_code > max
        {
            return false;
        }
        if let Some(min_ms) = filter.min_latency_ms
            && summary.latency_total_ms < (min_ms as f64)
        {
            return false;
        }
        if filter.errors_only && summary.error_class.is_none() {
            return false;
        }
        true
    }

    fn should_log_stream(&self, summary: &StreamTransactionSummary) -> bool {
        let Some(filter) = &self.filter else {
            return true;
        };
        if filter.status_code_min.is_some() || filter.status_code_max.is_some() {
            return false;
        }
        if let Some(min_ms) = filter.min_latency_ms
            && summary.duration_ms < (min_ms as f64)
        {
            return false;
        }
        if filter.errors_only && summary.error_class.is_none() && summary.connection_error.is_none()
        {
            return false;
        }
        true
    }
}

fn parse_optional_u16(config: &Map<String, Value>, key: &str) -> Result<Option<u16>, String> {
    let Some(value) = config.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_u64() else {
        return Err(format!("access_log: filter.{key} must be an integer"));
    };
    u16::try_from(raw)
        .map(Some)
        .map_err(|_| format!("access_log: filter.{key} must be between 0 and 65535"))
}

fn parse_optional_u64(config: &Map<String, Value>, key: &str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(key) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| format!("access_log: filter.{key} must be an integer"))
}

fn parse_optional_bool(config: &Map<String, Value>, key: &str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(key) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("access_log: filter.{key} must be a boolean"))
}

#[async_trait]
impl Plugin for AccessLog {
    fn name(&self) -> &str {
        "access_log"
    }

    fn priority(&self) -> u16 {
        super::priority::ACCESS_LOG
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn log(&self, summary: &TransactionSummary) {
        if !self.should_log_http(summary) {
            return;
        }
        let result = match self.schema.as_ref().filter(|s| s.applies_to_http()) {
            Some(schema) => serde_json::to_string(&SchemaView { summary, schema }),
            None => serde_json::to_string(summary),
        };
        match result {
            Ok(json) => tracing::info!(target: "mesh_access_log", "{}", json),
            Err(e) => warn!("access_log: failed to serialize transaction summary: {e}"),
        }
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if !self.should_log_stream(summary) {
            return;
        }
        let result = match self.schema.as_ref().filter(|s| s.applies_to_stream()) {
            Some(schema) => serde_json::to_string(&SchemaView { summary, schema }),
            None => serde_json::to_string(summary),
        };
        match result {
            Ok(json) => tracing::info!(target: "mesh_access_log", "{}", json),
            Err(e) => warn!("access_log: failed to serialize stream summary: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use crate::retry::ErrorClass;

    use super::*;

    fn http_summary(
        status: u16,
        latency_total_ms: f64,
        error_class: Option<ErrorClass>,
    ) -> TransactionSummary {
        TransactionSummary {
            response_status_code: status,
            latency_total_ms,
            error_class,
            ..TransactionSummary::default()
        }
    }

    fn stream_summary() -> StreamTransactionSummary {
        StreamTransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: "proxy-1".to_string(),
            proxy_name: None,
            client_ip: "127.0.0.1".to_string(),
            consumer_username: None,
            auth_method: None,
            backend_target: "127.0.0.1:8080".to_string(),
            backend_resolved_ip: None,
            protocol: "tcp".to_string(),
            listen_port: 15432,
            duration_ms: 250.0,
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: None,
            error_class: None,
            disconnect_direction: None,
            disconnect_cause: None,
            timestamp_connected: "2026-05-10T00:00:00Z".to_string(),
            timestamp_disconnected: "2026-05-10T00:00:01Z".to_string(),
            sni_hostname: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn constructor_accepts_null_and_empty_object_config() {
        assert!(AccessLog::new(&serde_json::Value::Null).is_ok());
        assert!(AccessLog::new(&json!({})).is_ok());
    }

    #[test]
    fn constructor_rejects_malformed_filter_config() {
        for (config, expected) in [
            (json!("bad"), "config must be an object"),
            (json!({ "filter": "bad" }), "filter must be an object"),
            (
                json!({ "filter": { "status_code_min": "500" } }),
                "filter.status_code_min must be an integer",
            ),
            (
                json!({ "filter": { "status_code_max": 70000 } }),
                "filter.status_code_max must be between 0 and 65535",
            ),
            (
                json!({ "filter": { "min_latency_ms": "250" } }),
                "filter.min_latency_ms must be an integer",
            ),
            (
                json!({ "filter": { "errors_only": "true" } }),
                "filter.errors_only must be a boolean",
            ),
            (
                json!({ "filter": { "status_code_min": 500, "status_code_max": 499 } }),
                "filter.status_code_min must be less than or equal to filter.status_code_max",
            ),
        ] {
            let err = match AccessLog::new(&config) {
                Ok(_) => panic!("invalid config should fail"),
                Err(err) => err,
            };
            assert!(
                err.contains(expected),
                "expected error containing {expected:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn http_filter_matches_status_latency_and_error_predicates() {
        let plugin = AccessLog::new(&json!({
            "filter": {
                "status_code_min": 500,
                "status_code_max": 599,
                "min_latency_ms": 250,
                "errors_only": true
            }
        }))
        .expect("plugin config");

        assert!(plugin.should_log_http(&http_summary(
            503,
            250.0,
            Some(ErrorClass::ConnectionTimeout)
        )));
        assert!(!plugin.should_log_http(&http_summary(
            499,
            250.0,
            Some(ErrorClass::ConnectionTimeout)
        )));
        assert!(!plugin.should_log_http(&http_summary(
            600,
            250.0,
            Some(ErrorClass::ConnectionTimeout)
        )));
        assert!(!plugin.should_log_http(&http_summary(
            503,
            249.0,
            Some(ErrorClass::ConnectionTimeout)
        )));
        assert!(!plugin.should_log_http(&http_summary(503, 250.0, None)));
    }

    #[test]
    fn stream_status_code_filter_does_not_match_without_status() {
        let plugin = AccessLog::new(&json!({
            "filter": {
                "status_code_min": 500
            }
        }))
        .expect("plugin config");

        assert!(!plugin.should_log_stream(&stream_summary()));
    }

    #[test]
    fn stream_filter_matches_latency_and_error_predicates() {
        let plugin = AccessLog::new(&json!({
            "filter": {
                "min_latency_ms": 250,
                "errors_only": true
            }
        }))
        .expect("plugin config");

        let mut summary = stream_summary();
        assert!(!plugin.should_log_stream(&summary));

        summary.error_class = Some(ErrorClass::ConnectionReset);
        assert!(plugin.should_log_stream(&summary));

        summary.duration_ms = 249.0;
        assert!(!plugin.should_log_stream(&summary));

        summary.duration_ms = 250.0;
        summary.error_class = None;
        summary.connection_error = Some("backend closed".to_string());
        assert!(plugin.should_log_stream(&summary));
    }
}
