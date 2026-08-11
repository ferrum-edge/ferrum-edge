//! Drift detection between `HTTP_FIELDS` / `STREAM_FIELDS` /
//! `WS_DISCONNECT_FIELDS` registries and the actual `TransactionSummary` /
//! `StreamTransactionSummary` / `WsDisconnectLogEntry` serializers.
//!
//! If you add a field to either summary struct and forget to add it to the
//! corresponding registry, this test fails with the missing field name.
//! If you remove a field, this test fails with the stale registry entry.
//!
//! Without this guard, the schema compiler would silently accept omits /
//! renames against non-existent fields (or reject valid ones), and
//! operators would get confusing errors.

use std::collections::{HashMap, HashSet};

use ferrum_edge::plugins::api_chargeback_sink::{
    ChargeEvent, compile_charge_event_projection, serialize_json_each_row,
    serialize_json_each_row_projected,
};
use ferrum_edge::plugins::utils::log_schema::{
    CHARGE_EVENT_FIELDS, CHARGEBACK_REPORT_FIELDS, DEBUG_HTTP_FIELDS, DEBUG_STREAM_FIELDS,
    DEBUG_WS_FIELDS, HTTP_FIELDS, STREAM_FIELDS, WS_DISCONNECT_FIELDS,
};
use ferrum_edge::plugins::{
    Direction, DisconnectCause, StreamTransactionSummary, TransactionSummary,
};
use ferrum_edge::retry::ErrorClass;

/// Populate every field of `TransactionSummary` so all serde
/// `skip_serializing_if` guards are bypassed and every key appears in the
/// serialized output.
fn fully_populated_http() -> TransactionSummary {
    TransactionSummary {
        // Terminal-log trigger carrier: stamped centrally by
        // `log_with_mirror` from the authoritative RequestContext.
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".into(),
        timestamp_received: "2026-05-11T12:00:00Z".into(),
        client_ip: "10.0.0.1".into(),
        consumer_username: Some("alice".into()),
        auth_method: Some("jwt_auth"),
        http_method: "GET".into(),
        request_path: "/things".into(),
        proxy_id: Some("p1".into()),
        proxy_name: Some("things-api".into()),
        backend_target: Some("https://backend:8443/things".into()),
        backend_resolved_ip: Some("10.5.0.10".into()),
        response_status_code: 200,
        latency_total_ms: 12.5,
        latency_gateway_processing_ms: 1.0,
        latency_backend_ttfb_ms: 3.0,
        latency_backend_total_ms: 8.0,
        latency_plugin_execution_ms: 0.5,
        latency_plugin_external_io_ms: 0.1,
        latency_gateway_overhead_ms: 0.4,
        request_user_agent: Some("curl/8.0".into()),
        response_streamed: true,
        client_disconnected: true,
        error_class: Some(ErrorClass::ConnectionTimeout),
        body_error_class: Some(ErrorClass::ConnectionReset),
        body_completed: true,
        bytes_sent: 100,
        bytes_received: 200,
        grpc_request_messages: 0,
        grpc_response_messages: 0,
        mirror: true,
        metadata: HashMap::from([
            ("trace_id".to_string(), "abc".to_string()),
            ("request_protocol".to_string(), "grpc".to_string()),
            ("grpc_status".to_string(), "14".to_string()),
        ]),
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

fn fully_populated_stream() -> StreamTransactionSummary {
    StreamTransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".into(),
        proxy_id: "p2".into(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("db-front".into()),
        client_ip: "10.0.0.2".into(),
        consumer_username: Some("svc-account".into()),
        auth_method: Some("mtls_auth"),
        backend_target: "10.5.0.20:5432".into(),
        backend_resolved_ip: Some("10.5.0.20".into()),
        protocol: "tcp".into(),
        listen_port: 5432,
        duration_ms: 100.0,
        bytes_sent: 200,
        bytes_received: 400,
        connection_error: Some("ECONNRESET".into()),
        error_class: Some(ErrorClass::ConnectionReset),
        disconnect_direction: Some(Direction::BackendToClient),
        disconnect_cause: Some(DisconnectCause::GracefulShutdown),
        timestamp_connected: "2026-05-11T12:00:00Z".into(),
        timestamp_disconnected: "2026-05-11T12:01:40Z".into(),
        sni_hostname: Some("db.internal".into()),
        metadata: HashMap::from([("session_id".to_string(), "xyz".to_string())]),
    }
}

#[test]
fn http_fields_registry_matches_struct() {
    let summary = fully_populated_http();
    let value = serde_json::to_value(&summary).expect("serialize");
    let emitted: HashSet<String> = value.as_object().expect("object").keys().cloned().collect();

    let registered: HashSet<String> = HTTP_FIELDS.iter().map(|f| f.name.to_string()).collect();

    let missing_from_registry: Vec<&String> = emitted.difference(&registered).collect();
    let missing_from_struct: Vec<&String> = registered.difference(&emitted).collect();

    assert!(
        missing_from_registry.is_empty() && missing_from_struct.is_empty(),
        "TransactionSummary <-> HTTP_FIELDS drift detected.\n  In struct but missing from registry: {:?}\n  In registry but missing from struct: {:?}",
        missing_from_registry,
        missing_from_struct,
    );
}

#[test]
fn stream_fields_registry_matches_struct() {
    let summary = fully_populated_stream();
    let value = serde_json::to_value(&summary).expect("serialize");
    let emitted: HashSet<String> = value.as_object().expect("object").keys().cloned().collect();

    let registered: HashSet<String> = STREAM_FIELDS.iter().map(|f| f.name.to_string()).collect();

    let missing_from_registry: Vec<&String> = emitted.difference(&registered).collect();
    let missing_from_struct: Vec<&String> = registered.difference(&emitted).collect();

    assert!(
        missing_from_registry.is_empty() && missing_from_struct.is_empty(),
        "StreamTransactionSummary <-> STREAM_FIELDS drift detected.\n  In struct but missing from registry: {:?}\n  In registry but missing from struct: {:?}",
        missing_from_registry,
        missing_from_struct,
    );
}

#[test]
fn http_fields_declaration_order_matches_struct() {
    let summary = fully_populated_http();
    let value = serde_json::to_value(&summary).expect("serialize");
    let obj = value.as_object().expect("object");

    // serde_json::Map preserves insertion order (which matches struct field
    // declaration order). Build a parallel vec of emitted keys and check
    // each one shows up in HTTP_FIELDS in the same relative order.
    let emitted_order: Vec<&str> = obj.keys().map(String::as_str).collect();
    let registry_order: Vec<&str> = HTTP_FIELDS.iter().map(|f| f.name).collect();

    // Quick check: same length (the other tests would have caught mismatches).
    assert_eq!(emitted_order.len(), registry_order.len());
    for (i, name) in emitted_order.iter().enumerate() {
        assert_eq!(
            registry_order[i], *name,
            "HTTP_FIELDS order mismatch at index {i}: expected '{}', got '{name}'",
            registry_order[i]
        );
    }
}

#[test]
fn stream_fields_declaration_order_matches_struct() {
    let summary = fully_populated_stream();
    let value = serde_json::to_value(&summary).expect("serialize");
    let obj = value.as_object().expect("object");

    let emitted_order: Vec<&str> = obj.keys().map(String::as_str).collect();
    let registry_order: Vec<&str> = STREAM_FIELDS.iter().map(|f| f.name).collect();

    assert_eq!(emitted_order.len(), registry_order.len());
    for (i, name) in emitted_order.iter().enumerate() {
        assert_eq!(
            registry_order[i], *name,
            "STREAM_FIELDS order mismatch at index {i}: expected '{}', got '{name}'",
            registry_order[i]
        );
    }
}

/// Drift guard for the WebSocket-disconnect field registry.
///
/// Unlike `TransactionSummary` / `StreamTransactionSummary`, the backing
/// `WsDisconnectLogEntry` in `src/plugins/ws_logging.rs` is a private struct
/// with a hand-written `SchemaSerializable::serialize_native` (and matching
/// `owns_native`), so it cannot be serialized from an integration test to diff
/// its keys. Instead we pin the exact ordered `WS_DISCONNECT_FIELDS` name list.
///
/// If you add, remove, or reorder a `serialize_native` arm (or the struct
/// fields feeding it) in `WsDisconnectLogEntry`, update both the registry and
/// this expected list. Keeping them in lockstep is what stops the schema
/// compiler from accepting stale or missing WebSocket-disconnect field names in
/// `omit` / `rename` / `order`.
#[test]
fn ws_disconnect_fields_registry_matches_expected() {
    // Declaration order mirrors `WsDisconnectLogEntry::serialize_native`.
    let expected: &[&str] = &[
        "event",
        "namespace",
        "proxy_id",
        "proxy_name",
        "client_ip",
        "consumer_username",
        "auth_method",
        "backend_target",
        "protocol",
        "listen_port",
        "duration_ms",
        "frames_client_to_backend",
        "frames_backend_to_client",
        "bytes_client_to_backend",
        "bytes_backend_to_client",
        "timestamp_connected",
        "timestamp_disconnected",
        "direction",
        "io_side",
        "error_class",
        "metadata",
    ];

    let registered: Vec<&str> = WS_DISCONNECT_FIELDS.iter().map(|f| f.name).collect();

    assert_eq!(
        registered, expected,
        "WS_DISCONNECT_FIELDS <-> WsDisconnectLogEntry drift detected.\n  \
         Registry: {registered:?}\n  Expected: {expected:?}\n  \
         Update WS_DISCONNECT_FIELDS and WsDisconnectLogEntry::serialize_native \
         together (see src/plugins/ws_logging.rs)."
    );

    // No duplicate output keys — mirrors the uniqueness the compiler relies on.
    let unique: HashSet<&str> = registered.iter().copied().collect();
    assert_eq!(
        unique.len(),
        registered.len(),
        "WS_DISCONNECT_FIELDS contains duplicate field names"
    );
}

// ---------------------------------------------------------------------------
// Non-summary record families (issues #3312, #3313, #3314)
// ---------------------------------------------------------------------------

/// Assert a family registry against its expected declaration order and check
/// that its output keys are unique — the uniqueness the compiler relies on.
fn assert_family(registered: Vec<&str>, expected: &[&str], label: &str, owner: &str) {
    assert_eq!(
        registered, expected,
        "{label} drift detected.\n  Registry: {registered:?}\n  Expected: {expected:?}\n  \
         Update {label} and {owner} together."
    );
    let unique: HashSet<&str> = registered.iter().copied().collect();
    assert_eq!(
        unique.len(),
        registered.len(),
        "{label} contains duplicate field names"
    );
}

#[test]
fn chargeback_report_fields_registry_matches_rendered_row() {
    assert_family(
        CHARGEBACK_REPORT_FIELDS.iter().map(|f| f.name).collect(),
        &[
            "proxy_id",
            "namespace",
            "proxy_name",
            "currency",
            "protocol_family",
            "total_calls",
            "total_charges",
            "by_status",
            "bandwidth",
            "stream",
        ],
        "CHARGEBACK_REPORT_FIELDS",
        "ChargebackProxyRow::to_native_json / serialize_native (src/plugins/api_chargeback.rs)",
    );
    // A billing row carries no timestamp: `timestamp_format` is rejected for
    // this family, so a timestamp field here would be unreachable.
    assert!(CHARGEBACK_REPORT_FIELDS.iter().all(|f| !f.is_timestamp));
}

#[test]
fn charge_event_fields_registry_matches_struct() {
    assert_family(
        CHARGE_EVENT_FIELDS.iter().map(|f| f.name).collect(),
        &[
            "event_id",
            "received_at",
            "node_id",
            "namespace",
            "consumer_id",
            "consumer_name",
            "proxy_id",
            "proxy_name",
            "route_id",
            "status_code",
            "http_status_code",
            "grpc_status",
            "protocol",
            "call_count",
            "charge_call",
            "bytes_sent",
            "bytes_received",
            "charge_bytes_sent",
            "charge_bytes_received",
            "charge_total",
            "currency",
            "pricing_version",
            "request_id",
            "trace_id",
            "snapshot_id",
        ],
        "CHARGE_EVENT_FIELDS",
        "ChargeEvent + its serialize_native (src/plugins/api_chargeback_sink.rs)",
    );
    // `received_at` is an epoch-nanosecond integer, not an RFC3339 string.
    assert!(CHARGE_EVENT_FIELDS.iter().all(|f| !f.is_timestamp));

    // Struct-derived drift guard, mirroring `http_fields_registry_matches_struct`.
    // The declaration-order assertion above only re-states the constant; it
    // cannot see a field ADDED to `ChargeEvent`. Without this comparison a new
    // charge-event column would keep flowing on the native path while every
    // deployment running a `schema:` / `schema_ref:` projection silently
    // dropped it from the ClickHouse INSERT body and the durable spool
    // artifact alike.
    let value = serde_json::to_value(fully_populated_charge_event()).expect("serialize");
    let emitted: HashSet<String> = value.as_object().expect("object").keys().cloned().collect();
    let names: HashSet<String> = CHARGE_EVENT_FIELDS
        .iter()
        .map(|f| f.name.to_string())
        .collect();
    let missing_from_registry: Vec<&String> = emitted.difference(&names).collect();
    let missing_from_struct: Vec<&String> = names.difference(&emitted).collect();
    assert!(
        missing_from_registry.is_empty() && missing_from_struct.is_empty(),
        "ChargeEvent <-> CHARGE_EVENT_FIELDS drift detected.\n  In struct but missing from registry: {:?}\n  In registry but missing from struct: {:?}",
        missing_from_registry,
        missing_from_struct,
    );
}

/// Populate every `ChargeEvent` member, including each `Option`, so no
/// `skip_serializing_if` guard hides a key.
///
/// Deliberately written without a struct-update base: a new member on
/// `ChargeEvent` must be added here too, which is the compile-time half of the
/// drift guard above.
fn fully_populated_charge_event() -> ChargeEvent {
    ChargeEvent {
        event_id: "01JQ0000000000000000000000".to_string(),
        received_at: 1_778_500_800_000_000_000,
        node_id: "node-a".to_string(),
        namespace: "ferrum".to_string(),
        consumer_id: "alice".to_string(),
        consumer_name: Some("Alice".to_string()),
        proxy_id: "proxy-a".to_string(),
        proxy_name: "My API".to_string(),
        route_id: Some("route-1".to_string()),
        status_code: 200,
        http_status_code: Some(200),
        grpc_status: Some(0),
        protocol: "http".to_string(),
        call_count: 3,
        charge_call: 0.5,
        bytes_sent: 100,
        bytes_received: 200,
        charge_bytes_sent: 0.001,
        charge_bytes_received: 0.002,
        charge_total: 0.503,
        currency: "USD".to_string(),
        pricing_version: "test-v1".to_string(),
        request_id: Some("req-1".to_string()),
        trace_id: Some("trace-1".to_string()),
        snapshot_id: Some("snap-1".to_string()),
    }
}

/// The same event with every optional member absent, so the projected row's
/// `skip_serializing_if` parity is exercised in both directions.
fn charge_event_without_optionals() -> ChargeEvent {
    ChargeEvent {
        consumer_name: None,
        route_id: None,
        http_status_code: None,
        grpc_status: None,
        request_id: None,
        trace_id: None,
        snapshot_id: None,
        ..fully_populated_charge_event()
    }
}

#[test]
fn charge_event_identity_projection_matches_the_native_row() {
    // `ChargeEvent` has two independent emitters: the serde derive (no schema
    // configured) and the hand-written `SchemaSerializable::serialize_native`
    // arms driven by `CHARGE_EVENT_FIELDS`. An identity projection must
    // reproduce the native row exactly — same members, same presence, same
    // values — otherwise a member covered by only one of the two silently
    // changes the exported billing record for projected deployments only.
    let projection = compile_charge_event_projection(&serde_json::json!({ "schema": {} }))
        .expect("identity schema compiles")
        .expect("schema present");

    for (label, event) in [
        (
            "all optional members present",
            fully_populated_charge_event(),
        ),
        (
            "all optional members absent",
            charge_event_without_optionals(),
        ),
    ] {
        let rows = std::slice::from_ref(&event);
        let native = serialize_json_each_row(rows).expect("native");
        let shaped = serialize_json_each_row_projected(rows, Some(&projection)).expect("shaped");
        let native_value: serde_json::Value = serde_json::from_str(&native).expect("native JSON");
        let shaped_value: serde_json::Value = serde_json::from_str(&shaped).expect("shaped JSON");
        assert_eq!(
            shaped_value, native_value,
            "{label}: identity projection drifted"
        );
    }
}

#[test]
fn debug_diagnostic_fields_registries_match_default_records() {
    assert_family(
        DEBUG_HTTP_FIELDS.iter().map(|f| f.name).collect(),
        &[
            "outcome",
            "namespace",
            "timestamp_received",
            "client_ip",
            "method",
            "path",
            "status",
            "proxy_id",
            "proxy_name",
            "backend_target",
            "backend_resolved_ip",
            "consumer_username",
            "auth_method",
            "error_class",
            "body_error_class",
            "response_streamed",
            "body_completed",
            "client_disconnected",
            "bytes_sent",
            "bytes_received",
            "rejection_phase",
            "grpc_status",
            "request_id",
            "trace_id",
            "latency_total_ms",
            "latency_backend_ttfb_ms",
            "latency_backend_total_ms",
            "latency_plugin_ms",
            "latency_gw_overhead_ms",
            "metadata",
        ],
        "DEBUG_HTTP_FIELDS",
        "TransactionDebugger::log (src/plugins/transaction_debugger.rs)",
    );
    assert_family(
        DEBUG_STREAM_FIELDS.iter().map(|f| f.name).collect(),
        &[
            "outcome",
            "namespace",
            "protocol",
            "proxy_id",
            "proxy_name",
            "client_ip",
            "listen_port",
            "backend_target",
            "backend_resolved_ip",
            "consumer_username",
            "auth_method",
            "connection_error",
            "error_class",
            "disconnect_direction",
            "disconnect_cause",
            "duration_ms",
            "bytes_sent",
            "bytes_received",
            "timestamp_connected",
            "timestamp_disconnected",
            "sni_hostname",
            "request_id",
            "trace_id",
            "metadata",
        ],
        "DEBUG_STREAM_FIELDS",
        "TransactionDebugger::on_stream_disconnect (src/plugins/transaction_debugger.rs)",
    );
    assert_family(
        DEBUG_WS_FIELDS.iter().map(|f| f.name).collect(),
        &[
            "outcome",
            "namespace",
            "proxy_id",
            "proxy_name",
            "client_ip",
            "listen_port",
            "backend_target",
            "consumer_username",
            "auth_method",
            "duration_ms",
            "frames_client_to_backend",
            "frames_backend_to_client",
            "bytes_client_to_backend",
            "bytes_backend_to_client",
            "disconnect_direction",
            "io_side",
            "error_class",
            "request_id",
            "trace_id",
            "metadata",
        ],
        "DEBUG_WS_FIELDS",
        "TransactionDebugger::on_ws_disconnect (src/plugins/transaction_debugger.rs)",
    );

    // The RFC3339 timestamp fields are the ones `timestamp_format` converts.
    let http_ts: Vec<&str> = DEBUG_HTTP_FIELDS
        .iter()
        .filter(|f| f.is_timestamp)
        .map(|f| f.name)
        .collect();
    assert_eq!(http_ts, vec!["timestamp_received"]);
    let stream_ts: Vec<&str> = DEBUG_STREAM_FIELDS
        .iter()
        .filter(|f| f.is_timestamp)
        .map(|f| f.name)
        .collect();
    assert_eq!(
        stream_ts,
        vec!["timestamp_connected", "timestamp_disconnected"]
    );
}
