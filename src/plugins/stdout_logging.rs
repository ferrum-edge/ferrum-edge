//! Stdout access logging plugin.
//!
//! Serializes the `TransactionSummary` / `StreamTransactionSummary` to JSON
//! and writes one JSON line to stdout for each transaction or stream
//! disconnect. Supports all proxy protocols (HTTP, gRPC, WebSocket, TCP, UDP).
//!
//! Writes go through the process-global non-blocking stdout writer installed
//! by `init_logging` (see [`crate::logging::access_log_writer`]). That keeps
//! the proxy hot path free of synchronous `stdout().lock()` writes — each log
//! line is a bounded-channel send handled off-thread — and decouples access
//! logging from `FERRUM_LOG_LEVEL`: enabling this plugin is the only on/off
//! switch, and lowering runtime verbosity never silences it. When no global
//! writer is installed (validate-only mode, unit tests) it falls back to a
//! direct synchronous write so output is still produced.
//!
//! An optional `filter` (status-code range, minimum latency, errors-only)
//! gates which transactions are logged; it runs before schema application.
//! This is also the sink mesh mode injects to honor a Telemetry CRD's
//! `accessLogging` configuration.

use std::io::Write;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tracing::warn;

use super::utils::log_schema::{SchemaView, SummarySchema, resolve_schema};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

pub struct StdoutLogging {
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

impl StdoutLogging {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !(config.is_object() || config.is_null()) {
            return Err("stdout_logging: config must be an object".to_string());
        }
        let filter = match config.get("filter") {
            Some(f) if !f.is_null() => Some(Filter {
                status_code_min: parse_optional_u16(f, "status_code_min")?,
                status_code_max: parse_optional_u16(f, "status_code_max")?,
                min_latency_ms: f.get("min_latency_ms").and_then(Value::as_u64),
                errors_only: f
                    .get("errors_only")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }),
            _ => None,
        };
        let schema = resolve_schema(config, "stdout_logging")?;
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

fn parse_optional_u16(config: &Value, key: &str) -> Result<Option<u16>, String> {
    let Some(value) = config.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_u64() else {
        return Err(format!("stdout_logging: filter.{key} must be an integer"));
    };
    u16::try_from(raw)
        .map(Some)
        .map_err(|_| format!("stdout_logging: filter.{key} must be between 0 and 65535"))
}

/// Write one access-log line to the non-blocking stdout sink.
///
/// The full line (JSON + trailing newline) is built once and emitted with a
/// single `write_all`, so it reaches the non-blocking writer's worker thread
/// as one channel message and never interleaves with concurrent log output.
fn write_access_log_line(mut json: String) {
    json.push('\n');
    match crate::logging::access_log_writer() {
        Some(writer) => {
            let mut writer = writer.clone();
            let _ = writer.write_all(json.as_bytes());
        }
        // No global writer installed yet (validate-only mode, unit tests):
        // fall back to a direct synchronous write so output still appears.
        None => {
            let _ = std::io::stdout().write_all(json.as_bytes());
        }
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
        if !self.should_log_http(summary) {
            return;
        }
        let result = match self.schema.as_ref().filter(|s| s.applies_to_http()) {
            Some(schema) => serde_json::to_string(&SchemaView { summary, schema }),
            None => serde_json::to_string(summary),
        };
        match result {
            Ok(json) => write_access_log_line(json),
            Err(e) => warn!("stdout_logging: failed to serialize transaction summary: {e}"),
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
            Ok(json) => write_access_log_line(json),
            Err(e) => warn!("stdout_logging: failed to serialize stream summary: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

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
    fn no_filter_logs_everything() {
        let plugin = StdoutLogging::new(&json!({})).expect("plugin config");
        assert!(plugin.should_log_stream(&stream_summary()));
    }

    #[test]
    fn stream_status_code_filter_does_not_match_without_status() {
        let plugin = StdoutLogging::new(&json!({
            "filter": { "status_code_min": 500 }
        }))
        .expect("plugin config");

        assert!(!plugin.should_log_stream(&stream_summary()));
    }

    #[test]
    fn stream_min_latency_filter_excludes_fast_streams() {
        let plugin = StdoutLogging::new(&json!({
            "filter": { "min_latency_ms": 1000 }
        }))
        .expect("plugin config");

        assert!(!plugin.should_log_stream(&stream_summary()));
    }

    #[test]
    fn errors_only_filter_excludes_clean_streams() {
        let plugin = StdoutLogging::new(&json!({
            "filter": { "errors_only": true }
        }))
        .expect("plugin config");

        assert!(!plugin.should_log_stream(&stream_summary()));
    }

    #[test]
    fn rejects_out_of_range_status_filter() {
        let err = match StdoutLogging::new(&json!({
            "filter": { "status_code_min": 70000 }
        })) {
            Ok(_) => panic!("status code above u16 range must be rejected"),
            Err(e) => e,
        };
        assert!(err.contains("between 0 and 65535"), "got: {err}");
    }
}
