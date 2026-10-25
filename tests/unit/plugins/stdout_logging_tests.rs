//! Tests for stdout_logging plugin

use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, StreamTransactionSummary, stdout_logging,
    stdout_logging::StdoutLogging, validate_plugin_config,
};
use serde_json::json;

use super::plugin_utils::{create_test_context, create_test_transaction_summary};

#[tokio::test]
async fn test_stdout_logging_plugin_creation() {
    let config = json!({});
    let plugin = StdoutLogging::new(&config).unwrap();
    assert_eq!(plugin.name(), "stdout_logging");
    assert_eq!(plugin.priority(), 9000);
    assert_eq!(
        plugin.supported_protocols(),
        &[
            ProxyProtocol::Http,
            ProxyProtocol::Grpc,
            ProxyProtocol::WebSocket,
            ProxyProtocol::Tcp,
            ProxyProtocol::Udp,
        ]
    );
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(plugin.requires_ws_disconnect_hooks());
}

#[tokio::test]
async fn test_stdout_logging_plugin_lifecycle() {
    let config = json!({});
    let plugin = StdoutLogging::new(&config).unwrap();
    let mut ctx = create_test_context();

    // Test all lifecycle phases
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_stdout_logging_plugin_logging() {
    let config = json!({});
    let plugin = StdoutLogging::new(&config).unwrap();

    let summary = create_test_transaction_summary();

    // Should not panic when logging
    plugin.log(&summary).await;
}

#[test]
fn test_stdout_logging_rejects_unknown_outer_and_nested_keys() {
    for (config, path) in [
        (
            json!({"filters": {"errors_only": true}}),
            "stdout_logging.filters",
        ),
        (json!({"log_level": "info"}), "stdout_logging.log_level"),
        (
            json!({"filter": {"error_only": true}}),
            "stdout_logging.filter.error_only",
        ),
        (
            json!({"filter": {"min_latency_msec": 10}}),
            "stdout_logging.filter.min_latency_msec",
        ),
    ] {
        let error = StdoutLogging::new(&config)
            .err()
            .expect("unknown key must fail");
        assert!(error.contains(path), "expected {path} in {error}");
    }
}

#[test]
fn test_stdout_logging_accepts_null_config_as_defaults() {
    let plugin =
        StdoutLogging::new(&serde_json::Value::Null).expect("null config should use defaults");
    assert_eq!(plugin.name(), "stdout_logging");
    assert_eq!(plugin.priority(), 9000);
}

#[test]
fn test_stdout_logging_rejects_non_object_config() {
    let err = StdoutLogging::new(&json!("bad")).err().unwrap();
    assert!(err.contains("config must be an object"), "got: {err}");
}

#[test]
fn test_shared_validation_rejects_invalid_stdout_logging_config() {
    let err = validate_plugin_config("stdout_logging", &json!({"filter": "errors"}))
        .expect_err("shared plugin validation must reject a non-object filter");
    assert_eq!(err, "stdout_logging: `filter` must be an object");
}

#[test]
fn test_shared_validation_preserves_null_defaults() {
    for config in [serde_json::Value::Null, json!({"filter": null})] {
        validate_plugin_config("stdout_logging", &config)
            .expect("shared validation must preserve null defaults");
    }
}

#[test]
fn test_shared_validation_rejects_unknown_stdout_logging_keys() {
    for (config, path) in [
        (
            json!({"include_metadata": false}),
            "stdout_logging.include_metadata",
        ),
        (
            json!({"filter": {"error_only": true}}),
            "stdout_logging.filter.error_only",
        ),
    ] {
        let error = validate_plugin_config("stdout_logging", &config)
            .expect_err("shared validation must reject unknown keys");
        assert!(error.contains(path), "expected {path} in {error}");
    }
}

#[test]
fn test_stdout_logging_rejects_mixed_flat_and_expression_filters() {
    let error = StdoutLogging::new(&json!({
        "filter": {
            "errors_only": true,
            "expression": {"op": "status_code_min", "value": 500}
        }
    }))
    .err()
    .expect("flat predicates must not be silently ignored");
    assert!(error.contains("cannot be combined"), "{error}");
}

#[test]
fn test_stdout_logging_bounds_direct_expression_trees() {
    let mut expression = json!({"op": "errors_only"});
    for _ in 0..32 {
        expression = json!({
            "op": "or",
            "left": expression,
            "right": {"op": "errors_only"}
        });
    }
    let error = StdoutLogging::new(&json!({"filter": {"expression": expression}}))
        .err()
        .expect("direct expression tree must honor the parser node ceiling");
    assert!(error.contains("maximum AST node count"), "{error}");
}

#[test]
fn test_errors_only_uses_authoritative_terminal_failure_predicate() {
    let plugin = StdoutLogging::new(&json!({"filter": {"errors_only": true}})).unwrap();
    let mut summary = create_test_transaction_summary();
    summary.body_completed = true;
    assert!(!plugin.should_log_transaction(&summary));

    summary.body_error_class = Some(ferrum_edge::retry::ErrorClass::ConnectionReset);
    assert!(plugin.should_log_transaction(&summary));
    summary.body_error_class = None;

    summary.response_streamed = true;
    summary.body_completed = false;
    assert!(plugin.should_log_transaction(&summary));
    summary.response_streamed = false;
    summary.body_completed = true;

    summary.client_disconnected = true;
    assert!(plugin.should_log_transaction(&summary));
    summary.client_disconnected = false;

    summary
        .metadata
        .insert("grpc_status".to_string(), "0".to_string());
    assert!(!plugin.should_log_transaction(&summary));
    summary
        .metadata
        .insert("grpc_status".to_string(), "14".to_string());
    assert!(plugin.should_log_transaction(&summary));

    summary.metadata.remove("grpc_status");
    summary
        .metadata
        .insert("mirror_error".to_string(), "connection refused".to_string());
    assert!(plugin.should_log_transaction(&summary));
}

#[test]
fn test_terminal_grpc_status_is_stable_across_buffered_streamed_h2_h3_and_rejection_shapes() {
    let plugin = StdoutLogging::new(&json!({"filter": {"errors_only": true}})).unwrap();
    for (case, streamed, body_completed, status, rejection, expected_failure) in [
        ("buffered_h2_ok", false, true, Some("0"), false, false),
        ("buffered_h2_error", false, true, Some("7"), false, true),
        ("streamed_h2_ok", true, true, Some("0"), false, false),
        ("streamed_h2_error", true, true, Some("14"), false, true),
        ("native_h3_ok", true, true, Some("0"), false, false),
        ("native_h3_error", true, true, Some("13"), false, true),
        ("missing_terminal", true, true, None, false, true),
        ("malformed_terminal", true, true, Some("bad"), false, true),
        ("gateway_rejection", false, true, Some("16"), true, true),
    ] {
        let mut summary = create_test_transaction_summary();
        summary.response_status_code = 200;
        summary.response_streamed = streamed;
        summary.body_completed = body_completed;
        summary
            .metadata
            .insert("request_protocol".to_string(), "grpc".to_string());
        if let Some(status) = status {
            summary
                .metadata
                .insert("grpc_status".to_string(), status.to_string());
        }
        if rejection {
            summary
                .metadata
                .insert("rejection_phase".to_string(), "authorize".to_string());
        }

        assert_eq!(
            plugin.should_log_transaction(&summary),
            expected_failure,
            "{case}"
        );
        let json = serde_json::to_value(&summary).unwrap();
        let expected_status = status.map_or(2, |value| value.parse::<u32>().unwrap_or(u32::MAX));
        assert_eq!(json["grpc_status"], expected_status, "{case}");
        assert_eq!(json["response_status_code"], 200, "{case}");
    }
}

#[tokio::test]
async fn test_stdout_logging_stream_disconnect() {
    let plugin = StdoutLogging::new(&json!({})).unwrap();
    let summary = StreamTransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-proxy-1".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("TCP Test".to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: "tcp".to_string(),
        listen_port: 8080,
        duration_ms: 15.0,
        bytes_sent: 128,
        bytes_received: 256,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: ferrum_edge::plugins::MetadataMap::default(),
    };

    plugin.on_stream_disconnect(&summary).await;
}

fn ws_disconnect_ctx(
    http_method: &str,
    request_path: &str,
    handshake_status_code: u16,
    backend_target: &str,
) -> ferrum_edge::plugins::WsDisconnectContext {
    ferrum_edge::plugins::WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "proxy-ws".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("websocket-proxy".to_string()),
        client_ip: "10.0.0.1".to_string(),
        backend_target: backend_target.to_string(),
        http_method: http_method.to_string(),
        request_path: request_path.to_string(),
        handshake_status_code,
        listen_port: 8080,
        duration_ms: 42.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 0,
        bytes_client_to_backend: 16,
        bytes_backend_to_client: 0,
        timestamp_connected: "2026-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01Z".to_string(),
        direction: Some(ferrum_edge::plugins::Direction::ClientToBackend),
        io_side: None,
        error_class: Some(ferrum_edge::retry::ErrorClass::ProtocolError),
        consumer_username: None,
        auth_method: None,
        connection_id: 7,
        metadata: ferrum_edge::plugins::MetadataMap::default(),
    }
}

#[test]
fn ws_disconnect_projection_keeps_h1_handshake_when_backend_path_differs() {
    let ctx = ws_disconnect_ctx(
        "GET",
        "/client/ws",
        101,
        "ws://backend.local:9000/v1/rewritten",
    );
    let summary = StdoutLogging::project_ws_disconnect(&ctx);
    assert_eq!(summary.http_method, "GET");
    assert_eq!(summary.response_status_code, 101);
    assert_eq!(summary.request_path, "/client/ws");
    assert_eq!(
        summary.backend_target.as_deref(),
        Some("ws://backend.local:9000/v1/rewritten")
    );
    assert_eq!(
        summary.error_class,
        Some(ferrum_edge::retry::ErrorClass::ProtocolError)
    );
    assert_eq!(summary.bytes_sent, 16);
    assert!(summary.is_terminal_failure());
}

#[test]
fn ws_disconnect_projection_keeps_extended_connect_handshake_when_backend_path_differs() {
    let ctx = ws_disconnect_ctx(
        "CONNECT",
        "/h2/original",
        200,
        "https://backend.local:9443/internal/socket",
    );
    let summary = StdoutLogging::project_ws_disconnect(&ctx);
    assert_eq!(summary.http_method, "CONNECT");
    assert_eq!(summary.response_status_code, 200);
    assert_eq!(summary.request_path, "/h2/original");
    assert_eq!(
        summary.backend_target.as_deref(),
        Some("https://backend.local:9443/internal/socket")
    );
    assert_ne!(summary.request_path, "/internal/socket");
}

#[test]
fn ws_disconnect_projection_does_not_infer_path_from_backend_query() {
    let ctx = ws_disconnect_ctx(
        "GET",
        "/client/ws",
        101,
        "ws://backend.local:9000/v1/rewritten",
    );
    let summary = StdoutLogging::project_ws_disconnect(&ctx);
    assert_eq!(summary.request_path, "/client/ws");
    assert!(
        !summary.request_path.contains("secret="),
        "request_path must not inherit backend query material"
    );
    assert_eq!(
        summary.backend_target.as_deref(),
        Some("ws://backend.local:9000/v1/rewritten"),
        "backend_target remains the already-stripped upgrade target"
    );
}

#[test]
fn test_stdout_logging_rejects_unknown_errors_only_expression_fields() {
    for (config, path) in [
        (
            json!({"filter": {"expression": {"op": "errors_only", "extra": 1}}}),
            "stdout_logging.filter.expression.extra",
        ),
        (
            json!({"filter": {"expression": {"op": "errors_only", "value": false}}}),
            "stdout_logging.filter.expression.value",
        ),
        (
            json!({
                "filter": {
                    "expression": {
                        "op": "and",
                        "left": {"op": "errors_only", "extra": 1},
                        "right": {"op": "errors_only"}
                    }
                }
            }),
            "stdout_logging.filter.expression.left.extra",
        ),
        (
            json!({
                "filter": {
                    "expression": {
                        "op": "or",
                        "left": {"op": "min_latency_ms", "value": 10},
                        "right": {"op": "errors_only", "value": false}
                    }
                }
            }),
            "stdout_logging.filter.expression.right.value",
        ),
    ] {
        let error = StdoutLogging::new(&config)
            .err()
            .expect("unknown errors_only fields must fail admission");
        assert!(
            error.contains("unknown configuration key"),
            "expected unknown-key diagnostic, got {error}"
        );
        assert!(error.contains(path), "expected {path} in {error}");
    }

    let plugin = StdoutLogging::new(&json!({
        "filter": {"expression": {"op": "errors_only"}}
    }))
    .expect("bare errors_only expression must remain valid");
    let mut failed = create_test_transaction_summary();
    failed.error_class = Some(ferrum_edge::retry::ErrorClass::ConnectionReset);
    assert!(plugin.should_log_transaction(&failed));
    assert!(!plugin.should_log_transaction(&create_test_transaction_summary()));
}

#[test]
fn startup_diagnostics_withhold_expression_scalars_and_unknown_keys() {
    let secret = "'diagnostic-secret-5594`\"\\\n";
    for (config, path) in [
        (json!({(secret): true}), "`stdout_logging`"),
        (
            json!({"filter": {(secret): false}}),
            "`stdout_logging.filter`",
        ),
    ] {
        let error = StdoutLogging::new(&config)
            .err()
            .expect("unknown key rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        assert!(rendered.contains(path), "{rendered}");
        assert!(rendered.contains("unknown configuration key"), "{rendered}");
        assert!(!rendered.contains("diagnostic-secret-5594"), "{rendered}");
    }
    for expression in [
        json!({"op": secret}),
        json!({"op": "status_code_min", "value": 987654321}),
        json!({"op": "status_code_min", "value": true}),
        json!({"op": "errors_only", secret: false}),
        json!({"op": "and", "left": {"op": "errors_only", secret: 1}, "right": {"op": "errors_only"}}),
    ] {
        let error = StdoutLogging::new(&json!({"filter": {"expression": expression}}))
            .err()
            .expect("invalid expression must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        assert!(rendered.contains("filter.expression"), "{rendered}");
        assert!(!rendered.contains("diagnostic-secret-5594"), "{rendered}");
        assert!(!rendered.contains("987654321"), "{rendered}");
        assert!(!rendered.contains("true"), "{rendered}");
        assert!(!rendered.contains("false"), "{rendered}");
    }
}

#[test]
fn nested_expression_diagnostics_distinguish_missing_fields_and_integer_types() {
    for (leaf, expected) in [
        (json!({"op": "status_code_min"}), "missing field `value`"),
        (
            json!({"op": "status_code_min", "value": true}),
            "expected an unsigned integer between 0 and 999",
        ),
    ] {
        let error = StdoutLogging::new(&json!({"filter": {"expression": {
            "op": "and", "left": {"op": "errors_only"},
            "right": {"op": "or", "left": leaf, "right": {"op": "errors_only"}}
        }}}))
        .err()
        .expect("invalid nested expression must still fail admission");
        assert!(error.contains(expected), "{error}");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        for fragment in ["stdout_logging", "filter.expression.right.left", expected] {
            assert!(rendered.contains(fragment), "{rendered}");
        }
        assert!(!rendered.contains("true"), "{rendered}");
    }
}

// ── WebSocket session-end projection field semantics ──────────────────────

#[test]
fn ws_session_end_row_marks_unobserved_latencies_and_records_the_end_time() {
    let ctx = ws_disconnect_ctx("GET", "/client/ws", 101, "ws://backend.local:9000/ws");
    let summary = StdoutLogging::project_ws_disconnect(&ctx);
    let json = serde_json::to_value(&summary).expect("summary serializes");

    assert_eq!(json["latency_total_ms"], 42.0, "session duration");
    for field in [
        "latency_gateway_processing_ms",
        "latency_backend_ttfb_ms",
        "latency_backend_total_ms",
        "latency_plugin_execution_ms",
        "latency_plugin_external_io_ms",
        "latency_gateway_overhead_ms",
    ] {
        assert_eq!(
            json[field],
            ferrum_edge::plugins::LATENCY_UNKNOWN_MS,
            "{field} is not observed for a session and must carry the sentinel"
        );
    }
    assert_eq!(
        json["timestamp_received"], "2026-01-01T00:00:00Z",
        "timestamp_received stays the upgrade admission time"
    );
    assert_eq!(
        json["metadata"][stdout_logging::WS_SESSION_END_TIMESTAMP_METADATA_KEY],
        "2026-01-01T00:00:01Z",
        "the session end is locatable in time and not redacted"
    );
    // The handshake identity fields are unchanged.
    assert_eq!(json["http_method"], "GET");
    assert_eq!(json["response_status_code"], 101);
    assert_eq!(json["request_path"], "/client/ws");
}

// ── Sampling ──────────────────────────────────────────────────────────────

fn clean_summary() -> ferrum_edge::plugins::TransactionSummary {
    let mut summary = create_test_transaction_summary();
    summary.body_completed = true;
    summary
}

fn failed_summary() -> ferrum_edge::plugins::TransactionSummary {
    let mut summary = clean_summary();
    summary.error_class = Some(ferrum_edge::retry::ErrorClass::ConnectionReset);
    summary
}

fn clean_stream_summary() -> StreamTransactionSummary {
    StreamTransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-proxy-1".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: None,
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: "tcp".to_string(),
        listen_port: 8080,
        duration_ms: 15.0,
        bytes_sent: 0,
        bytes_received: 0,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: ferrum_edge::plugins::MetadataMap::default(),
    }
}

#[test]
fn sampling_keeps_exactly_the_configured_fraction_evenly_spaced() {
    let plugin = StdoutLogging::new(&json!({"sampling": {"rate": 0.25}})).unwrap();
    let summary = clean_summary();
    let admitted: Vec<bool> = (0..1000)
        .map(|_| plugin.should_log_transaction(&summary))
        .collect();
    assert_eq!(admitted.iter().filter(|kept| **kept).count(), 250);
    // Evenly spaced: never two kept records in a row at a quarter rate, and
    // every window of four consecutive candidates keeps exactly one.
    for window in admitted.windows(4) {
        assert_eq!(window.iter().filter(|kept| **kept).count(), 1, "{window:?}");
    }

    let streams = StdoutLogging::new(&json!({"sampling": {"rate": 0.5}})).unwrap();
    let stream = clean_stream_summary();
    let kept = (0..1000)
        .filter(|_| streams.should_log_stream_transaction(&stream))
        .count();
    assert_eq!(kept, 500, "stream records share the deterministic sampler");
}

#[test]
fn sampling_rate_one_and_null_keep_every_record() {
    for config in [
        json!({"sampling": {"rate": 1}}),
        json!({"sampling": {"rate": 1.0, "always_log_errors": true}}),
        json!({"sampling": null}),
    ] {
        let plugin = StdoutLogging::new(&config).unwrap();
        let summary = clean_summary();
        assert!(
            (0..100).all(|_| plugin.should_log_transaction(&summary)),
            "{config} must keep every record"
        );
    }
}

#[test]
fn sampling_always_log_errors_keeps_failures_without_consuming_samples() {
    let plugin = StdoutLogging::new(&json!({
        "sampling": {"rate": 0.001, "always_log_errors": true}
    }))
    .unwrap();
    let failed = failed_summary();
    assert!(
        (0..1000).all(|_| plugin.should_log_transaction(&failed)),
        "every terminal failure is kept"
    );
    // Failures did not advance the sequence: the first 999 clean records are
    // all skipped and exactly the 1000th is kept.
    let clean = clean_summary();
    let kept: Vec<usize> = (0..1000)
        .filter(|_| plugin.should_log_transaction(&clean))
        .collect();
    assert_eq!(kept, vec![999]);

    let mut failed_stream = clean_stream_summary();
    failed_stream.connection_error = Some("connection reset".to_string());
    assert!((0..100).all(|_| plugin.should_log_stream_transaction(&failed_stream)));

    let without = StdoutLogging::new(&json!({"sampling": {"rate": 0.001}})).unwrap();
    let kept = (0..1000)
        .filter(|_| without.should_log_transaction(&failed))
        .count();
    assert_eq!(
        kept, 1,
        "without always_log_errors failures are sampled too"
    );
}

#[test]
fn sampling_applies_only_to_records_the_filter_admits() {
    let plugin = StdoutLogging::new(&json!({
        "filter": {"status_code_min": 500},
        "sampling": {"rate": 0.5}
    }))
    .unwrap();
    let ok = clean_summary();
    let mut server_error = clean_summary();
    server_error.response_status_code = 503;
    let mut kept = 0;
    for _ in 0..100 {
        assert!(!plugin.should_log_transaction(&ok), "filtered out first");
        if plugin.should_log_transaction(&server_error) {
            kept += 1;
        }
    }
    assert_eq!(kept, 50, "filtered-out records never consume a sample");
}

#[test]
fn sampling_config_is_validated_without_echoing_values() {
    for (config, expected) in [
        (json!({"sampling": "1%"}), "`sampling` must be an object"),
        (json!({"sampling": {}}), "`sampling.rate` is required"),
        (
            json!({"sampling": {"rate": "0.5"}}),
            "`sampling.rate` must be a number",
        ),
        (
            json!({"sampling": {"rate": 0}}),
            "`sampling.rate` must be greater than 0 and at most 1",
        ),
        (
            json!({"sampling": {"rate": 1.5}}),
            "`sampling.rate` must be greater than 0 and at most 1",
        ),
        (
            json!({"sampling": {"rate": -0.25}}),
            "`sampling.rate` must be greater than 0 and at most 1",
        ),
        (
            json!({"sampling": {"rate": 0.0000001}}),
            "`sampling.rate` must be at least 0.000001",
        ),
        (
            json!({"sampling": {"rate": 0.5, "always_log_errors": "yes"}}),
            "`sampling.always_log_errors` must be a boolean",
        ),
        (
            json!({"sampling": {"rate": 0.5, "percent": 50}}),
            "stdout_logging.sampling.percent",
        ),
    ] {
        let error = StdoutLogging::new(&config)
            .err()
            .unwrap_or_else(|| panic!("{config} must be rejected"));
        assert!(
            error.contains(expected),
            "expected {expected:?} in {error:?}"
        );
        let validated = validate_plugin_config("stdout_logging", &config)
            .expect_err("shared validation reaches the same constructor");
        assert!(validated.contains(expected), "{validated}");
    }
}

// ── Unsatisfiable filters ─────────────────────────────────────────────────

#[test]
fn unreachable_and_contradictory_status_filters_are_rejected() {
    for (config, expected) in [
        (
            json!({"filter": {"status_code_min": 5000}}),
            "`filter.status_code_min` must be between 0 and 999",
        ),
        (
            json!({"filter": {"status_code_max": 1000}}),
            "`filter.status_code_max` must be between 0 and 999",
        ),
        (
            json!({"filter": {"expression": {"op": "status_code_min", "value": 5000}}}),
            "status-code bound must be between 0 and 999",
        ),
        (
            json!({"filter": {"expression": {
                "op": "and",
                "left": {"op": "status_code_min", "value": 500},
                "right": {"op": "status_code_max", "value": 400}
            }}}),
            "conjunction can never match",
        ),
        (
            // Dead conjunction nested under `or`, with the status atoms split
            // across a nested `and` chain.
            json!({"filter": {"expression": {
                "op": "or",
                "left": {"op": "errors_only"},
                "right": {
                    "op": "and",
                    "left": {"op": "status_code_min", "value": 500},
                    "right": {
                        "op": "and",
                        "left": {"op": "min_latency_ms", "value": 10},
                        "right": {"op": "status_code_max", "value": 499}
                    }
                }
            }}}),
            "conjunction can never match",
        ),
    ] {
        let error = StdoutLogging::new(&config)
            .err()
            .unwrap_or_else(|| panic!("{config} must be rejected"));
        assert!(
            error.contains(expected),
            "expected {expected:?} in {error:?}"
        );
    }

    // Satisfiable shapes stay valid: an exact status (min == max), bounds that
    // live in different `or` branches, and the edge values 0 and 999.
    for config in [
        json!({"filter": {"status_code_min": 0, "status_code_max": 999}}),
        json!({"filter": {"expression": {
            "op": "and",
            "left": {"op": "status_code_min", "value": 503},
            "right": {"op": "status_code_max", "value": 503}
        }}}),
        json!({"filter": {"expression": {
            "op": "or",
            "left": {"op": "status_code_min", "value": 500},
            "right": {"op": "status_code_max", "value": 399}
        }}}),
        json!({"filter": {"expression": {
            "op": "and",
            "left": {"op": "status_code_min", "value": 500},
            "right": {
                "op": "or",
                "left": {"op": "status_code_max", "value": 400},
                "right": {"op": "errors_only"}
            }
        }}}),
    ] {
        if let Err(error) = StdoutLogging::new(&config) {
            panic!("{config} must stay valid: {error}");
        }
    }
}

// ── Failure policy and loss attribution ───────────────────────────────────

#[test]
fn stdout_logging_is_keep_last_known_good() {
    assert_eq!(
        ferrum_edge::plugins::plugin_failure_policy("stdout_logging"),
        Some(ferrum_edge::plugins::PluginFailurePolicy::KeepLastKnownGood),
        "the access log must not be silently omitted on a bad config"
    );
}

#[test]
fn access_record_outcomes_are_attributed_to_the_stdout_logging_series() {
    use ferrum_edge::logging::non_blocking::EnqueueResult;
    use ferrum_edge::plugins::utils::sink_loss::{
        SINK_PLUGINS, SinkLossReason, accepted_total, dropped_total, render_prometheus,
    };

    assert!(SINK_PLUGINS.contains(&"stdout_logging"));
    let plugin = StdoutLogging::new(&json!({})).unwrap();
    let accepted_before = accepted_total("stdout_logging");
    let drops_before: Vec<u64> = [
        SinkLossReason::QueueFull,
        SinkLossReason::RecordTooLarge,
        SinkLossReason::Shutdown,
    ]
    .iter()
    .map(|reason| dropped_total("stdout_logging", *reason))
    .collect();

    plugin.record_enqueue_outcome(EnqueueResult::Queued);
    plugin.record_enqueue_outcome(EnqueueResult::Saturated);
    plugin.record_enqueue_outcome(EnqueueResult::RecordTooLarge);
    plugin.record_enqueue_outcome(EnqueueResult::Closed);

    // Counters are process-global, so assert growth rather than exact values.
    assert!(accepted_total("stdout_logging") > accepted_before);
    for (reason, before) in [
        SinkLossReason::QueueFull,
        SinkLossReason::RecordTooLarge,
        SinkLossReason::Shutdown,
    ]
    .iter()
    .zip(drops_before)
    {
        assert!(
            dropped_total("stdout_logging", *reason) > before,
            "{} must be attributed to stdout_logging",
            reason.as_str()
        );
    }
    let exposition = render_prometheus();
    assert!(exposition.contains(
        "ferrum_plugin_log_sink_records_dropped_total{plugin=\"stdout_logging\",reason=\"queue_full\"}"
    ));
}
