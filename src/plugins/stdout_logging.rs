//! Stdout access logging plugin.
//!
//! Serializes the `TransactionSummary` / `StreamTransactionSummary` to JSON
//! and writes one JSON line to stdout for each transaction or stream
//! disconnect. Supports all proxy protocols (HTTP, gRPC, WebSocket, TCP, UDP).
//!
//! Writes go through the process-global non-blocking stdout writer installed
//! by `init_logging` (see [`crate::logging::access_log_writer`]). That keeps
//! the proxy hot path free of synchronous `stdout().lock()` writes — each log
//! line is admitted to bounded record and byte budgets before serialization,
//! then handled off-thread — and decouples access logging from
//! `FERRUM_LOG_LEVEL`: enabling this plugin is the only on/off switch. When no
//! global writer is installed (in-process unit tests that never call
//! `init_logging`) it returns without performing blocking I/O.
//!
//! An optional `filter` (status-code range, minimum latency, errors-only)
//! gates which transactions are logged; it runs before schema application.
//! This is also the sink mesh mode injects to honor a Telemetry CRD's
//! `accessLogging` configuration.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use serde_json::{Map, Value};
use tracing::warn;

use crate::modes::mesh::access_log_filter::AccessLogFilterExpr;
use crate::modes::mesh::access_log_filter::{
    AccessLogFilterContext, StreamAccessLogFilterContext, evaluate_access_log_filter_expr,
    evaluate_access_log_filter_expr_for_stream, validate_access_log_filter_expr,
};

use super::utils::log_schema::{SchemaCapabilities, SchemaView, SummarySchema, resolve_schema};
use super::{Plugin, StreamTransactionSummary, TransactionSummary, WsDisconnectContext};

pub struct StdoutLogging {
    /// When set, only log transactions matching all filter predicates.
    filter: Option<Filter>,
    schema: Option<Arc<SummarySchema>>,
}

struct Filter {
    flat: FlatFilter,
    expression: Option<AccessLogFilterExpr>,
}

#[derive(Default)]
struct FlatFilter {
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
        if let Some(config) = config.as_object() {
            reject_unknown_keys(
                config,
                "stdout_logging",
                &["filter", "schema", "schema_ref"],
            )?;
        }
        let filter = match config.get("filter") {
            Some(Value::Null) | None => None,
            Some(Value::Object(filter_config)) => {
                reject_unknown_keys(
                    filter_config,
                    "stdout_logging.filter",
                    &[
                        "status_code_min",
                        "status_code_max",
                        "min_latency_ms",
                        "errors_only",
                        "expression",
                    ],
                )?;
                let status_code_min = parse_optional_u16(filter_config, "status_code_min")?;
                let status_code_max = parse_optional_u16(filter_config, "status_code_max")?;
                if let (Some(min), Some(max)) = (status_code_min, status_code_max)
                    && min > max
                {
                    return Err(
                        "stdout_logging: filter.status_code_min must be less than or equal to filter.status_code_max"
                            .to_string(),
                    );
                }
                let min_latency_ms = parse_optional_u64(filter_config, "min_latency_ms")?;
                let errors_only =
                    parse_optional_bool(filter_config, "errors_only")?.unwrap_or(false);
                let expression = match filter_config.get("expression") {
                    None => None,
                    Some(value) => {
                        reject_unknown_errors_only_fields(
                            value,
                            "stdout_logging.filter.expression",
                        )?;
                        let expression = serde_json::from_value(value.clone()).map_err(|err| {
                            format!("stdout_logging: filter.expression is invalid: {err}")
                        })?;
                        validate_access_log_filter_expr(&expression).map_err(|err| {
                            format!("stdout_logging: filter.expression is invalid: {err}")
                        })?;
                        Some(expression)
                    }
                };
                let has_flat_predicate_key = [
                    "status_code_min",
                    "status_code_max",
                    "min_latency_ms",
                    "errors_only",
                ]
                .iter()
                .any(|key| filter_config.contains_key(*key));
                if expression.is_some() && has_flat_predicate_key {
                    return Err(
                        "stdout_logging: filter.expression cannot be combined with flat filter predicates"
                            .to_string(),
                    );
                }
                Some(Filter {
                    flat: FlatFilter {
                        status_code_min,
                        status_code_max,
                        min_latency_ms,
                        errors_only,
                    },
                    expression,
                })
            }
            Some(_) => return Err("stdout_logging: filter must be an object".to_string()),
        };
        let schema = resolve_schema(config, "stdout_logging", SchemaCapabilities::BASE)?;
        Ok(Self { filter, schema })
    }

    /// Project a WebSocket disconnect into the HTTP access-log schema.
    ///
    /// Hidden test helper so external unit tests can assert handshake
    /// method/status/original-path without going through stdout.
    #[doc(hidden)]
    #[allow(dead_code)] // exercised by external unit tests; dead in the binary target
    pub fn project_ws_disconnect(ctx: &WsDisconnectContext) -> TransactionSummary {
        transaction_summary_from_ws_disconnect(ctx)
    }

    /// Apply the configured HTTP-family predicates to a finalized summary.
    pub fn should_log_transaction(&self, summary: &TransactionSummary) -> bool {
        let Some(filter) = &self.filter else {
            return true;
        };
        if let Some(expr) = &filter.expression {
            return evaluate_access_log_filter_expr(
                expr,
                AccessLogFilterContext {
                    response_status_code: summary.response_status_code,
                    latency_total_ms: summary.latency_total_ms,
                    is_terminal_failure: summary.is_terminal_failure(),
                },
            );
        }
        Self::flat_filter_matches_transaction(&filter.flat, summary)
    }

    /// Apply the configured stream-family predicates to a finalized summary.
    pub fn should_log_stream_transaction(&self, summary: &StreamTransactionSummary) -> bool {
        let Some(filter) = &self.filter else {
            return true;
        };
        if let Some(expr) = &filter.expression {
            return evaluate_access_log_filter_expr_for_stream(
                expr,
                StreamAccessLogFilterContext {
                    duration_ms: summary.duration_ms,
                    has_error: summary.error_class.is_some() || summary.connection_error.is_some(),
                },
            );
        }
        Self::flat_filter_matches_stream(&filter.flat, summary)
    }

    fn flat_filter_matches_transaction(filter: &FlatFilter, summary: &TransactionSummary) -> bool {
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
        if filter.errors_only && !summary.is_terminal_failure() {
            return false;
        }
        true
    }

    fn flat_filter_matches_stream(filter: &FlatFilter, summary: &StreamTransactionSummary) -> bool {
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

/// Project a WebSocket session-end into the HTTP-family access-log schema.
///
/// Handshake `log()` already emitted the upgrade row (usually without
/// `error_class`). In-session faults live on `WsDisconnectContext`; this
/// conversion lets operators grep the same `error_class` key. Method, path,
/// and status are the values captured at upgrade admission (`GET`/`101` for
/// HTTP/1.1, `CONNECT`/`200` for RFC 8441/9220 Extended CONNECT) so a
/// rewritten backend target cannot corrupt those fields. BASE schema only —
/// this is not the `websocket_disconnect` capability family.
fn transaction_summary_from_ws_disconnect(ctx: &WsDisconnectContext) -> TransactionSummary {
    TransactionSummary {
        namespace: ctx.namespace.clone(),
        timestamp_received: ctx.timestamp_connected.clone(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.consumer_username.clone(),
        auth_method: ctx.auth_method,
        http_method: ctx.http_method.clone(),
        request_path: ctx.request_path.clone(),
        proxy_id: Some(ctx.proxy_id.clone()),
        proxy_name: ctx.proxy_name.clone(),
        backend_target: Some(ctx.backend_target.clone()),
        response_status_code: ctx.handshake_status_code,
        latency_total_ms: ctx.duration_ms,
        latency_gateway_processing_ms: ctx.duration_ms,
        bytes_sent: ctx.bytes_client_to_backend,
        bytes_received: ctx.bytes_backend_to_client,
        error_class: ctx.error_class,
        metadata: ctx.metadata.clone(),
        proxy_lifecycle_generation: ctx.proxy_lifecycle_generation,
        ..TransactionSummary::default()
    }
}

fn reject_unknown_keys(
    config: &Map<String, Value>,
    path: &str,
    allowed: &[&str],
) -> Result<(), String> {
    let mut unknown: Vec<String> = config
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .map(|key| format!("{path}.{key}"))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort_unstable();
    Err(format!(
        "stdout_logging: unknown configuration key(s): {}",
        unknown.join(", ")
    ))
}

/// `errors_only` is a serde unit-like node (`{"op":"errors_only"}`). Internally
/// tagged unit variants ignore `deny_unknown_fields`, so extra keys such as
/// `value: false` would otherwise be dropped before tree validation. Walk the
/// JSON and reject them with the same full-path diagnostic as other keys.
fn reject_unknown_errors_only_fields(value: &Value, path: &str) -> Result<(), String> {
    let Some(obj) = value.as_object() else {
        return Ok(());
    };
    match obj.get("op").and_then(Value::as_str) {
        Some("errors_only") => {
            let mut unknown: Vec<String> = obj
                .keys()
                .filter(|key| key.as_str() != "op")
                .map(|key| format!("{path}.{key}"))
                .collect();
            if unknown.is_empty() {
                return Ok(());
            }
            unknown.sort_unstable();
            Err(format!(
                "stdout_logging: unknown configuration key(s): {}",
                unknown.join(", ")
            ))
        }
        Some("and") | Some("or") => {
            if let Some(left) = obj.get("left") {
                reject_unknown_errors_only_fields(left, &format!("{path}.left"))?;
            }
            if let Some(right) = obj.get("right") {
                reject_unknown_errors_only_fields(right, &format!("{path}.right"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn parse_optional_u16(config: &Map<String, Value>, key: &str) -> Result<Option<u16>, String> {
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

fn parse_optional_u64(config: &Map<String, Value>, key: &str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(key) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| format!("stdout_logging: filter.{key} must be an integer"))
}

fn parse_optional_bool(config: &Map<String, Value>, key: &str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(key) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("stdout_logging: filter.{key} must be a boolean"))
}

/// Serialize and enqueue one access-log line after capacity reservation.
fn write_access_log_line<T: Serialize + ?Sized>(value: &T) -> Result<(), serde_json::Error> {
    if let Some(writer) = crate::logging::access_log_writer() {
        // Saturation and oversize outcomes are accounted by the sink and
        // intentionally do not log into either potentially degraded sink.
        let _ = writer.try_write_json(value)?;
    }
    // The gateway treats process-sink initialization failure as fatal. A
    // missing writer therefore only occurs in library/unit contexts; never
    // add a synchronous stdout fallback here because plugin hooks are hot paths.
    Ok(())
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
        if !self.should_log_transaction(summary) {
            return;
        }
        let result = match self.schema.as_ref().filter(|s| s.applies_to_http()) {
            Some(schema) => write_access_log_line(&SchemaView { summary, schema }),
            None => write_access_log_line(summary),
        };
        if let Err(error) = result {
            warn!("stdout_logging: failed to serialize transaction summary: {error}");
        }
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if !self.should_log_stream_transaction(summary) {
            return;
        }
        let result = match self.schema.as_ref().filter(|s| s.applies_to_stream()) {
            Some(schema) => write_access_log_line(&SchemaView { summary, schema }),
            None => write_access_log_line(summary),
        };
        if let Err(error) = result {
            warn!("stdout_logging: failed to serialize stream summary: {error}");
        }
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        let summary = transaction_summary_from_ws_disconnect(ctx);
        self.log(&summary).await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;
    use crate::retry::ErrorClass;

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
            plugin_trigger_decisions: Default::default(),
            namespace: "ferrum".to_string(),
            proxy_id: "proxy-1".to_string(),
            proxy_lifecycle_generation: None,
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
        assert!(plugin.should_log_stream_transaction(&stream_summary()));
    }

    #[test]
    fn stream_status_code_filter_does_not_match_without_status() {
        let plugin = StdoutLogging::new(&json!({
            "filter": { "status_code_min": 500 }
        }))
        .expect("plugin config");

        assert!(!plugin.should_log_stream_transaction(&stream_summary()));
    }

    #[test]
    fn stream_expression_treats_status_as_false_and_duration_normally() {
        let plugin = StdoutLogging::new(&json!({
            "filter": {
                "expression": {
                    "op": "or",
                    "left": { "op": "status_code_min", "value": 500 },
                    "right": { "op": "min_latency_ms", "value": 200 }
                }
            }
        }))
        .expect("plugin config");

        assert!(plugin.should_log_stream_transaction(&stream_summary()));

        let status_only = StdoutLogging::new(&json!({
            "filter": {
                "expression": { "op": "status_code_min", "value": 500 }
            }
        }))
        .expect("plugin config");
        assert!(!status_only.should_log_stream_transaction(&stream_summary()));
    }

    #[test]
    fn stream_min_latency_filter_excludes_fast_streams() {
        let plugin = StdoutLogging::new(&json!({
            "filter": { "min_latency_ms": 1000 }
        }))
        .expect("plugin config");

        assert!(!plugin.should_log_stream_transaction(&stream_summary()));
    }

    #[test]
    fn errors_only_filter_excludes_clean_streams() {
        let plugin = StdoutLogging::new(&json!({
            "filter": { "errors_only": true }
        }))
        .expect("plugin config");

        assert!(!plugin.should_log_stream_transaction(&stream_summary()));
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

    #[test]
    fn constructor_accepts_null_and_empty_object_config() {
        assert!(StdoutLogging::new(&Value::Null).is_ok());
        assert!(StdoutLogging::new(&json!({})).is_ok());
        assert!(StdoutLogging::new(&json!({ "filter": null })).is_ok());
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
            (
                json!({ "filter": { "expression": null } }),
                "filter.expression is invalid",
            ),
            (
                json!({
                    "filter": {
                        "expression": {
                            "op": "or",
                            "left": {
                                "op": "status_code_min",
                                "value": 500,
                                "ignored": true
                            },
                            "right": { "op": "errors_only" }
                        }
                    }
                }),
                "unknown field",
            ),
        ] {
            let err = match StdoutLogging::new(&config) {
                Ok(_) => panic!("invalid config should fail: {config}"),
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
        let plugin = StdoutLogging::new(&json!({
            "filter": {
                "status_code_min": 500,
                "status_code_max": 599,
                "min_latency_ms": 250,
                "errors_only": true
            }
        }))
        .expect("plugin config");

        assert!(plugin.should_log_transaction(&http_summary(
            503,
            250.0,
            Some(ErrorClass::ConnectionTimeout)
        )));
        // Below the status floor, above the ceiling, under the latency floor, and
        // without an error class are each individually excluded.
        assert!(!plugin.should_log_transaction(&http_summary(
            499,
            250.0,
            Some(ErrorClass::ConnectionTimeout)
        )));
        assert!(!plugin.should_log_transaction(&http_summary(
            600,
            250.0,
            Some(ErrorClass::ConnectionTimeout)
        )));
        assert!(!plugin.should_log_transaction(&http_summary(
            503,
            249.0,
            Some(ErrorClass::ConnectionTimeout)
        )));
        assert!(!plugin.should_log_transaction(&http_summary(503, 250.0, None)));
    }

    #[test]
    fn expression_filter_logs_errors_or_slow_requests() {
        let plugin = StdoutLogging::new(&json!({
            "filter": {
                "expression": {
                    "op": "or",
                    "left": { "op": "status_code_min", "value": 500 },
                    "right": { "op": "min_latency_ms", "value": 1000 }
                }
            }
        }))
        .expect("plugin config");

        assert!(plugin.should_log_transaction(&http_summary(503, 10.0, None)));
        assert!(plugin.should_log_transaction(&http_summary(200, 1500.0, None)));
        assert!(!plugin.should_log_transaction(&http_summary(200, 10.0, None)));
    }

    #[test]
    fn expression_filter_short_circuits_or_branches() {
        let plugin = StdoutLogging::new(&json!({
            "filter": {
                "expression": {
                    "op": "or",
                    "left": { "op": "status_code_min", "value": 500 },
                    "right": { "op": "min_latency_ms", "value": 999_999 }
                }
            }
        }))
        .expect("plugin config");

        assert!(plugin.should_log_transaction(&http_summary(503, 1.0, None)));
        assert!(!plugin.should_log_transaction(&http_summary(200, 1.0, None)));
    }

    fn ws_disconnect(error_class: Option<ErrorClass>, backend_target: &str) -> WsDisconnectContext {
        WsDisconnectContext {
            namespace: "ferrum".to_string(),
            proxy_id: "proxy-ws".to_string(),
            proxy_lifecycle_generation: None,
            proxy_name: Some("websocket-proxy".to_string()),
            client_ip: "10.0.0.1".to_string(),
            backend_target: backend_target.to_string(),
            http_method: "GET".to_string(),
            request_path: "/chat".to_string(),
            handshake_status_code: 101,
            listen_port: 8080,
            duration_ms: 42.0,
            frames_client_to_backend: 1,
            frames_backend_to_client: 0,
            bytes_client_to_backend: 16,
            bytes_backend_to_client: 0,
            timestamp_connected: "2026-01-01T00:00:00Z".to_string(),
            timestamp_disconnected: "2026-01-01T00:00:01Z".to_string(),
            direction: Some(crate::plugins::Direction::ClientToBackend),
            io_side: None,
            error_class,
            consumer_username: None,
            auth_method: None,
            connection_id: 7,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn ws_disconnect_summary_carries_error_class_and_path() {
        let summary = transaction_summary_from_ws_disconnect(&ws_disconnect(
            Some(ErrorClass::ProtocolError),
            "ws://backend.local:9000/chat",
        ));
        assert_eq!(summary.response_status_code, 101);
        assert_eq!(summary.http_method, "GET");
        assert_eq!(summary.request_path, "/chat");
        assert_eq!(summary.error_class, Some(ErrorClass::ProtocolError));
        assert_eq!(summary.bytes_sent, 16);
        assert_eq!(
            summary.backend_target.as_deref(),
            Some("ws://backend.local:9000/chat")
        );
        assert!(summary.is_terminal_failure());
    }

    #[test]
    fn errors_only_filter_logs_ws_session_end_with_error_class() {
        let plugin = StdoutLogging::new(&json!({
            "filter": { "errors_only": true }
        }))
        .expect("plugin config");
        let failed = transaction_summary_from_ws_disconnect(&ws_disconnect(
            Some(ErrorClass::ConnectionReset),
            "http://127.0.0.1:9/",
        ));
        let clean =
            transaction_summary_from_ws_disconnect(&ws_disconnect(None, "http://127.0.0.1:9/"));
        assert!(plugin.should_log_transaction(&failed));
        assert!(!plugin.should_log_transaction(&clean));
    }
}
