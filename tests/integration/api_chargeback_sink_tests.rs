use std::collections::HashMap;
use std::time::Duration;

use ferrum_edge::plugins::api_chargeback_sink::{
    ApiChargebackSink, ChargeEvent, compile_charge_event_projection, serialize_json_each_row,
    serialize_json_each_row_projected,
};
use ferrum_edge::plugins::{Plugin, PluginHttpClient, TransactionSummary};
use serde_json::{Map, Value, json};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn wait_for_post_requests(server: &MockServer, at_least: usize) -> Vec<wiremock::Request> {
    for _ in 0..40 {
        if let Some(requests) = server.received_requests().await
            && requests.len() >= at_least
        {
            return requests;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("mock ClickHouse did not receive {at_least} POST request(s)");
}

fn per_event_summary(request_id: &str) -> TransactionSummary {
    let mut metadata = HashMap::new();
    metadata.insert("request_id".to_string(), request_id.to_string());
    TransactionSummary {
        // Terminal-log trigger carrier: stamped centrally by
        // `log_with_mirror` from the authoritative RequestContext.
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        timestamp_received: "2026-05-23T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: Some("it-consumer".to_string()),
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/it".to_string(),
        proxy_id: Some("it-proxy".to_string()),
        proxy_name: Some("Integration Proxy".to_string()),
        backend_target: Some("http://127.0.0.1:8080".to_string()),
        backend_resolved_ip: None,
        response_status_code: 200,
        latency_total_ms: 1.0,
        latency_gateway_processing_ms: 1.0,
        latency_backend_ttfb_ms: 1.0,
        latency_backend_total_ms: 1.0,
        latency_plugin_execution_ms: 0.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 0.0,
        request_user_agent: None,
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: true,
        bytes_sent: 0,
        bytes_received: 0,
        grpc_request_messages: 0,
        grpc_response_messages: 0,
        mirror: false,
        metadata,
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

fn clickhouse_url_with_query(base: &str, params: &[(&str, &str)]) -> String {
    let mut url = url::Url::parse(base).expect("FERRUM_CLICKHOUSE_TEST_URL must be a URL");
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            pairs.append_pair(key, value);
        }
    }
    url.to_string()
}

/// Split `0001_charges.sql` into ClickHouse statements.
///
/// Line comments are stripped first so the `--` block before
/// `charges_hourly` is not a statement of its own. The file's only
/// string literal is `DateTime64(9, 'UTC')`, which has no semicolon,
/// so splitting the comment-stripped copy on `;` is safe.
fn split_clickhouse_statements(sql: &str) -> Vec<String> {
    let mut without_comments = String::new();
    for line in sql.lines() {
        let code = match line.find("--") {
            Some(idx) => &line[..idx],
            None => line,
        };
        without_comments.push_str(code);
        without_comments.push('\n');
    }
    without_comments
        .split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .map(str::to_string)
        .collect()
}

/// Durable export must pin `wait_for_async_insert=1` on the on-wire INSERT URL
/// even when Ferrum omits both async settings, so a ClickHouse user/profile
/// default cannot enable fire-and-forget async inserts. Exercises the plugin's
/// real outbound POST (not URL-builder helpers) against an in-process fixture.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn durable_insert_pins_wait_on_wire_when_async_settings_omitted() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let config = json!({
        "clickhouse": {
            "url": server.uri(),
            "database": "ferrum",
            "table": "charges_raw",
            "timeout_ms": 2000
        },
        "batch": {"size": 1, "flush_interval_ms": 10, "buffer_capacity": 10},
        "retry": {"max_attempts": 1, "initial_delay_ms": 1, "max_delay_ms": 1, "jitter": false},
        "spool": {"enabled": false, "dir": temp.path().to_string_lossy().to_string()},
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.25}],
        "pricing_version": "it-chargeback-sink",
        "currency": "USD"
    });
    let plugin = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
    plugin
        .start_background_tasks()
        .expect("chargeback integration requires start_background_tasks");
    plugin.commit_background_tasks();
    plugin.log(&per_event_summary("it-request")).await;

    let requests = wait_for_post_requests(&server, 1).await;
    assert_eq!(
        requests.len(),
        1,
        "expected exactly one durable INSERT POST"
    );
    let request = &requests[0];

    let wait_values: Vec<_> = request
        .url
        .query_pairs()
        .filter(|(key, _)| key == "wait_for_async_insert")
        .map(|(_, value)| value.into_owned())
        .collect();
    assert_eq!(
        wait_values,
        vec!["1"],
        "durable INSERT must pin exactly one wait_for_async_insert=1 on the wire"
    );
    assert!(
        !request
            .url
            .query_pairs()
            .any(|(key, _)| key == "async_insert"),
        "fixture must omit async_insert so profile defaults are the only source"
    );
}

#[tokio::test]
#[ignore = "requires FERRUM_CLICKHOUSE_TEST_URL pointing at a ClickHouse HTTP endpoint"]
async fn clickhouse_insert_round_trip_when_configured() {
    // Hosted CI round-trips the same DDL + INSERT path via testcontainers in
    // tests/service_integration/clickhouse.rs (Service Integration job). This
    // ignored test remains the opt-in against an operator-supplied endpoint.
    let Ok(clickhouse_url) = std::env::var("FERRUM_CLICKHOUSE_TEST_URL") else {
        eprintln!("skipping: FERRUM_CLICKHOUSE_TEST_URL is not set");
        return;
    };
    let client = reqwest::Client::new();
    let statements = split_clickhouse_statements(CHARGES_RAW_DDL);
    for (index, statement) in statements.iter().enumerate() {
        let ddl_response = client
            .post(&clickhouse_url)
            .body(statement.clone())
            .send()
            .await
            .expect("ClickHouse DDL request should send");
        let status = ddl_response.status();
        let body = ddl_response.text().await.unwrap_or_default();
        assert!(
            status.is_success(),
            "DDL statement {} of {} failed: {status}: {body}",
            index + 1,
            statements.len()
        );
    }

    let temp = tempfile::tempdir().unwrap();
    let config = json!({
        "clickhouse": {
            "url": clickhouse_url,
            "database": "ferrum",
            "table": "charges_raw",
            "timeout_ms": 2000
        },
        "batch": {"size": 1, "flush_interval_ms": 10, "buffer_capacity": 10},
        "retry": {"max_attempts": 1, "initial_delay_ms": 1, "max_delay_ms": 1, "jitter": false},
        "spool": {"enabled": false, "dir": temp.path().to_string_lossy().to_string()},
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.25}],
        "pricing_version": "it-chargeback-sink",
        "currency": "USD"
    });
    let plugin = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
    plugin
        .start_background_tasks()
        .expect("chargeback live integration requires start_background_tasks");
    plugin.commit_background_tasks();
    let mut metadata = HashMap::new();
    metadata.insert("request_id".to_string(), "it-request".to_string());
    let summary = TransactionSummary {
        // Terminal-log trigger carrier: stamped centrally by
        // `log_with_mirror` from the authoritative RequestContext.
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        timestamp_received: "2026-05-23T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: Some("it-consumer".to_string()),
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/it".to_string(),
        proxy_id: Some("it-proxy".to_string()),
        proxy_name: Some("Integration Proxy".to_string()),
        backend_target: Some("http://127.0.0.1:8080".to_string()),
        backend_resolved_ip: None,
        response_status_code: 200,
        latency_total_ms: 1.0,
        latency_gateway_processing_ms: 1.0,
        latency_backend_ttfb_ms: 1.0,
        latency_backend_total_ms: 1.0,
        latency_plugin_execution_ms: 0.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 0.0,
        request_user_agent: None,
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: true,
        bytes_sent: 0,
        bytes_received: 0,
        grpc_request_messages: 0,
        grpc_response_messages: 0,
        mirror: false,
        metadata,
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    };
    plugin.log(&summary).await;

    let query = "SELECT count() FROM ferrum.charges_raw FINAL WHERE pricing_version='it-chargeback-sink' AND consumer_id='it-consumer'";
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let response = client
            .post(clickhouse_url_with_query(
                &std::env::var("FERRUM_CLICKHOUSE_TEST_URL").unwrap(),
                &[("query", query)],
            ))
            .send()
            .await
            .expect("ClickHouse SELECT request should send");
        assert!(
            response.status().is_success(),
            "SELECT failed: {}",
            response.text().await.unwrap_or_default()
        );
        let count = response.text().await.unwrap_or_default();
        if count.trim().parse::<u64>().unwrap_or_default() >= 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "expected at least one inserted charge event, got {count:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

// ---------------------------------------------------------------------------
// ClickHouse DDL / JSONEachRow wire contract (issue #4441)
//
// The sink inserts with `INSERT INTO <table> FORMAT JSONEachRow` and no
// column list, so ClickHouse maps JSON keys by name and silently defaults any
// physical column the serializer omits. This always-on parse of the baseline
// DDL is the CI gate that a live ClickHouse is not required to catch that
// drift. Hosted ClickHouse round-trips live in
// `tests/service_integration/clickhouse.rs`.
// ---------------------------------------------------------------------------

const CHARGES_RAW_DDL: &str = include_str!("../../migrations/clickhouse/0001_charges.sql");

const CHARGES_RAW_COLUMN_COUNT: usize = 25;

const OPTIONAL_NATIVE_KEYS: &[&str] = &[
    "consumer_name",
    "route_id",
    "http_status_code",
    "grpc_status",
    "request_id",
    "trace_id",
    "snapshot_id",
];

const NATIVE_FIELD_ORDER: &[&str] = &[
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
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonValueKind {
    String,
    Integer,
    Float,
    Bool,
    Null,
    Nested,
}

fn fully_populated_event() -> ChargeEvent {
    ChargeEvent {
        event_id: "evt-full".to_string(),
        received_at: 1_774_000_000_000_000_000,
        node_id: "node-a".to_string(),
        namespace: "ferrum".to_string(),
        consumer_id: "alice".to_string(),
        consumer_name: Some("Alice".to_string()),
        proxy_id: "proxy-a".to_string(),
        proxy_name: "Payments".to_string(),
        route_id: Some("route-1".to_string()),
        status_code: 200,
        http_status_code: Some(200),
        grpc_status: Some(0),
        protocol: "http".to_string(),
        call_count: 1,
        charge_call: 0.01,
        bytes_sent: 100,
        bytes_received: 200,
        charge_bytes_sent: 0.0001,
        charge_bytes_received: 0.0004,
        charge_total: 0.0105,
        currency: "USD".to_string(),
        pricing_version: "test-v1".to_string(),
        request_id: Some("req-1".to_string()),
        trace_id: Some("trace-1".to_string()),
        snapshot_id: Some("snap-1".to_string()),
    }
}

fn sparse_native_event() -> ChargeEvent {
    let mut event = fully_populated_event();
    event.event_id = "evt-sparse".to_string();
    event.consumer_name = None;
    event.route_id = None;
    event.http_status_code = None;
    event.grpc_status = None;
    event.request_id = None;
    event.trace_id = None;
    event.snapshot_id = None;
    event
}

fn parse_charges_raw_columns(ddl: &str) -> Vec<(String, String)> {
    const MARKER: &str = "CREATE TABLE IF NOT EXISTS ferrum.charges_raw";
    let table = ddl
        .split(MARKER)
        .nth(1)
        .expect("migrations/clickhouse/0001_charges.sql must create ferrum.charges_raw");
    let open = table
        .find('(')
        .expect("ferrum.charges_raw DDL must open a column list");
    let close = table
        .find(") ENGINE")
        .expect("ferrum.charges_raw DDL must close before ENGINE");
    let body = &table[open + 1..close];
    let mut columns = Vec::new();
    for raw_line in body.lines() {
        let line = raw_line.trim().trim_end_matches(',').trim();
        if line.is_empty() || line.starts_with("--") {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let name = parts
            .next()
            .expect("column line must start with a name")
            .trim();
        let declared = parts.next().unwrap_or("").trim();
        assert!(
            !name.is_empty() && !declared.is_empty(),
            "ferrum.charges_raw column line must be `<name> <type>`, got {line:?}"
        );
        columns.push((name.to_string(), declared.to_string()));
    }
    columns
}

fn strip_clickhouse_wrapper<'a>(declared: &'a str, wrapper: &str) -> Option<&'a str> {
    let prefix = format!("{wrapper}(");
    if declared.starts_with(&prefix) && declared.ends_with(')') {
        Some(&declared[prefix.len()..declared.len() - 1])
    } else {
        None
    }
}

fn unwrap_clickhouse_type(declared: &str) -> (String, bool) {
    let mut current = declared.trim().to_string();
    let mut nullable = false;
    loop {
        if let Some(inner) = strip_clickhouse_wrapper(&current, "LowCardinality") {
            current = inner.trim().to_string();
            continue;
        }
        if let Some(inner) = strip_clickhouse_wrapper(&current, "Nullable") {
            current = inner.trim().to_string();
            nullable = true;
            continue;
        }
        break;
    }
    (current, nullable)
}

fn json_value_kind(value: &Value) -> JsonValueKind {
    match value {
        Value::Null => JsonValueKind::Null,
        Value::Bool(_) => JsonValueKind::Bool,
        Value::Number(number) if number.is_f64() => JsonValueKind::Float,
        Value::Number(_) => JsonValueKind::Integer,
        Value::String(_) => JsonValueKind::String,
        Value::Array(_) | Value::Object(_) => JsonValueKind::Nested,
    }
}

fn json_kind_name(kind: JsonValueKind) -> &'static str {
    match kind {
        JsonValueKind::String => "string",
        JsonValueKind::Integer => "integer",
        JsonValueKind::Float => "float",
        JsonValueKind::Bool => "bool",
        JsonValueKind::Null => "null",
        JsonValueKind::Nested => "nested",
    }
}

fn clickhouse_family(base: &str) -> &'static str {
    if base == "String"
        || base.starts_with("FixedString")
        || base == "UUID"
        || base.starts_with("Enum")
    {
        "string"
    } else if base.starts_with("DateTime") || base.starts_with("Date") {
        "datetime"
    } else if base.starts_with("UInt") || base.starts_with("Int") {
        "integer"
    } else if base.starts_with("Float") || base.starts_with("Decimal") {
        "float"
    } else if base == "Bool" {
        "bool"
    } else {
        "other"
    }
}

fn integer_fits_clickhouse(value: i128, base: &str) -> bool {
    match base {
        "UInt8" => (0..=u8::MAX as i128).contains(&value),
        "UInt16" => (0..=u16::MAX as i128).contains(&value),
        "UInt32" => (0..=u32::MAX as i128).contains(&value),
        "UInt64" => (0..=u64::MAX as i128).contains(&value),
        "Int8" => (i8::MIN as i128..=i8::MAX as i128).contains(&value),
        "Int16" => (i16::MIN as i128..=i16::MAX as i128).contains(&value),
        "Int32" => (i32::MIN as i128..=i32::MAX as i128).contains(&value),
        "Int64" => (i64::MIN as i128..=i64::MAX as i128).contains(&value),
        _ => true,
    }
}

fn json_integer(value: &Value) -> Option<i128> {
    value
        .as_u64()
        .map(|n| n as i128)
        .or_else(|| value.as_i64().map(|n| n as i128))
}

fn type_mismatch(key: &str, kind: JsonValueKind, declared: &str, value: &Value) -> Option<String> {
    let (base, nullable) = unwrap_clickhouse_type(declared);
    let family = clickhouse_family(&base);
    let compatible = match kind {
        JsonValueKind::Null => nullable,
        JsonValueKind::String => family == "string" || family == "datetime",
        JsonValueKind::Integer => family == "integer" || family == "datetime" || family == "float",
        JsonValueKind::Float => family == "float",
        JsonValueKind::Bool => family == "bool",
        JsonValueKind::Nested => false,
    };
    if !compatible {
        return Some(format!(
            "emitted JSON key `{key}` has kind {} which contradicts \
             ClickHouse column `{key}` {declared}",
            json_kind_name(kind)
        ));
    }
    if kind == JsonValueKind::Integer
        && family == "integer"
        && let Some(number) = json_integer(value)
        && !integer_fits_clickhouse(number, &base)
    {
        return Some(format!(
            "emitted JSON key `{key}` integer {number} does not fit \
             ClickHouse column `{key}` {declared}"
        ));
    }
    None
}

fn wire_contract_errors(row: &Map<String, Value>, columns: &[(String, String)]) -> Vec<String> {
    let mut errors = Vec::new();
    for (key, value) in row {
        match columns.iter().find(|(name, _)| name == key) {
            None => errors.push(format!(
                "emitted JSON key `{key}` has no ClickHouse column in ferrum.charges_raw"
            )),
            Some((_, declared)) => {
                let kind = json_value_kind(value);
                if let Some(error) = type_mismatch(key, kind, declared, value) {
                    errors.push(error);
                }
            }
        }
    }
    for (name, _) in columns {
        if !row.contains_key(name) {
            errors.push(format!(
                "ClickHouse column `{name}` has no emitted JSONEachRow key"
            ));
        }
    }
    errors
}

fn assert_wire_contract(row: &Value, context: &str) {
    let Some(object) = row.as_object() else {
        panic!("{context}: JSONEachRow body must be a JSON object");
    };
    let columns = parse_charges_raw_columns(CHARGES_RAW_DDL);
    let errors = wire_contract_errors(object, &columns);
    assert!(
        errors.is_empty(),
        "{context}: ClickHouse JSONEachRow wire contract failed:\n  {}",
        errors.join("\n  ")
    );
}

fn serialize_row(event: &ChargeEvent) -> Value {
    let body = serialize_json_each_row(std::slice::from_ref(event))
        .expect("ChargeEvent must serialize as JSONEachRow");
    serde_json::from_str(&body).expect("JSONEachRow body must be JSON")
}

fn projected_row(schema: Value, event: &ChargeEvent) -> Value {
    let config = json!({
        "clickhouse": { "url": "http://127.0.0.1:8123" },
        "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.01 }],
        "schema": schema
    });
    let projection = compile_charge_event_projection(&config)
        .expect("charge-event schema must compile")
        .expect("schema present");
    let body = serialize_json_each_row_projected(std::slice::from_ref(event), Some(&projection))
        .expect("projected ChargeEvent must serialize");
    serde_json::from_str(&body).expect("projected JSONEachRow body must be JSON")
}

fn identity_schema() -> Value {
    json!({ "order": NATIVE_FIELD_ORDER })
}

#[test]
fn charges_raw_ddl_matches_native_field_order() {
    assert_eq!(
        NATIVE_FIELD_ORDER.len(),
        CHARGES_RAW_COLUMN_COUNT,
        "NATIVE_FIELD_ORDER must list exactly {CHARGES_RAW_COLUMN_COUNT} keys"
    );
    let columns = parse_charges_raw_columns(CHARGES_RAW_DDL);
    assert_eq!(
        columns.len(),
        CHARGES_RAW_COLUMN_COUNT,
        "ferrum.charges_raw must declare {CHARGES_RAW_COLUMN_COUNT} physical columns"
    );
    let names: Vec<&str> = columns.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, NATIVE_FIELD_ORDER);
}

#[test]
fn baseline_charges_ddl_splits_into_five_statements() {
    let statements = split_clickhouse_statements(CHARGES_RAW_DDL);
    assert_eq!(statements.len(), 5);
    assert!(statements[0].starts_with("CREATE DATABASE"));
    assert!(statements[1].contains("CREATE TABLE"));
    assert!(statements[1].contains("ferrum.charges_raw"));
    assert!(statements[2].contains("charges_hourly"));
    assert!(statements[3].contains("charges_daily"));
    assert!(statements[4].contains("charges_monthly"));
    for statement in &statements {
        assert!(
            !statement.contains("--"),
            "statement must not retain line comments: {statement}"
        );
        assert!(
            !statement.contains(';'),
            "statement must not retain the terminator: {statement}"
        );
    }
}

#[test]
fn fully_populated_native_jsoneachrow_matches_charges_raw_columns() {
    let row = serialize_row(&fully_populated_event());
    assert_wire_contract(&row, "fully populated native ChargeEvent");
}

#[test]
fn identity_projection_jsoneachrow_matches_charges_raw_columns() {
    let row = projected_row(identity_schema(), &fully_populated_event());
    assert_wire_contract(&row, "identity (order-only) charge-event projection");
}

#[test]
fn sparse_native_jsoneachrow_only_omits_optional_columns() {
    let row = serialize_row(&sparse_native_event());
    let object = row
        .as_object()
        .expect("sparse native JSONEachRow body must be a JSON object");
    let columns = parse_charges_raw_columns(CHARGES_RAW_DDL);
    let present_errors: Vec<String> = object
        .iter()
        .filter_map(|(key, value)| {
            let declared = columns.iter().find(|(name, _)| name == key);
            match declared {
                None => Some(format!(
                    "emitted JSON key `{key}` has no ClickHouse column in ferrum.charges_raw"
                )),
                Some((_, ty)) => type_mismatch(key, json_value_kind(value), ty, value),
            }
        })
        .collect();
    assert!(
        present_errors.is_empty(),
        "sparse native ChargeEvent: {}",
        present_errors.join("; ")
    );
    let omitted: Vec<&str> = columns
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| !object.contains_key(*name))
        .collect();
    assert_eq!(
        omitted, OPTIONAL_NATIVE_KEYS,
        "sparse native ChargeEvent must omit only optional columns"
    );
}

#[test]
fn wire_contract_names_emitted_key_without_column() {
    let row = projected_row(
        json!({ "rename": { "event_id": "billing_event_id" } }),
        &fully_populated_event(),
    );
    let object = row.as_object().expect("projected row must be an object");
    let columns = parse_charges_raw_columns(CHARGES_RAW_DDL);
    let errors = wire_contract_errors(object, &columns);
    assert!(
        errors.iter().any(|error| {
            error.contains("emitted JSON key `billing_event_id`")
                && error.contains("has no ClickHouse column")
        }),
        "rename projection must name the extra key, got {errors:?}"
    );
    assert!(
        errors.iter().any(|error| {
            error.contains("ClickHouse column `event_id`")
                && error.contains("has no emitted JSONEachRow key")
        }),
        "rename projection must name the missing column, got {errors:?}"
    );
}

#[test]
fn wire_contract_names_column_without_emitted_key() {
    let row = projected_row(json!({ "omit": ["node_id"] }), &fully_populated_event());
    let object = row.as_object().expect("projected row must be an object");
    let columns = parse_charges_raw_columns(CHARGES_RAW_DDL);
    let errors = wire_contract_errors(object, &columns);
    assert!(
        errors.iter().any(|error| {
            error.contains("ClickHouse column `node_id`")
                && error.contains("has no emitted JSONEachRow key")
        }),
        "omit projection must name column `node_id`, got {errors:?}"
    );
}

#[test]
fn wire_contract_names_derived_and_static_keys_without_columns() {
    let row = projected_row(
        json!({
            "static_fields": { "ledger": "prod" },
            "derived_fields": [
                { "name": "status_group", "kind": "status_class" },
                { "name": "record_kind", "kind": "summary_kind" },
                { "name": "call_outcome", "kind": "outcome" }
            ]
        }),
        &fully_populated_event(),
    );
    let object = row.as_object().expect("projected row must be an object");
    let columns = parse_charges_raw_columns(CHARGES_RAW_DDL);
    let errors = wire_contract_errors(object, &columns);
    for key in ["ledger", "status_group", "record_kind", "call_outcome"] {
        assert!(
            errors.iter().any(|error| {
                error.contains(&format!("emitted JSON key `{key}`"))
                    && error.contains("has no ClickHouse column")
            }),
            "static/derived key `{key}` must be named, got {errors:?}"
        );
    }
}

#[test]
fn wire_contract_rejects_string_against_uint64() {
    let columns = parse_charges_raw_columns(CHARGES_RAW_DDL);
    let call_count = columns
        .iter()
        .find(|(name, _)| name == "call_count")
        .map(|(_, declared)| declared.as_str())
        .expect("call_count column");
    let error = type_mismatch("call_count", JsonValueKind::String, call_count, &json!("1"))
        .expect("string vs UInt64 must be a contradiction");
    assert!(
        error.contains("call_count") && error.contains("string") && error.contains("UInt64"),
        "type mismatch must name field and column type, got {error}"
    );
}

fn lifecycle_sink_config(server: &MockServer) -> Value {
    json!({
        "clickhouse": {"url": server.uri(), "timeout_ms": 1000},
        "batch": {"size": 100, "flush_interval_ms": 600000, "buffer_capacity": 100},
        "retry": {"max_attempts": 1, "initial_delay_ms": 1, "max_delay_ms": 1, "jitter": false},
        "spool": {"enabled": false},
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.25}]
    })
}

fn sink_metric(name: &str) -> u64 {
    let prefix = format!("chargeback_sink_{name} ");
    ferrum_edge::plugins::api_chargeback_sink::render_prometheus()
        .lines()
        .find_map(|line| line.strip_prefix(&prefix)?.parse().ok())
        .unwrap_or(0)
}

async fn wait_for_sink_metric(name: &str, expected: u64) {
    for _ in 0..200 {
        if sink_metric(name) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(sink_metric(name), expected, "metric {name}");
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn pending_rows_remain_visible_across_replacement_and_graceful_retirement() {
    wait_for_sink_metric("per_event_pending", 0).await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let config = lifecycle_sink_config(&server);
    let received = sink_metric("per_event_received_total");
    let persisted = sink_metric("per_event_persisted_total");
    let dropped = sink_metric("per_event_dropped_total");
    let pending = sink_metric("per_event_pending");
    let old = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
    old.start_background_tasks().unwrap();
    old.commit_background_tasks();
    old.log(&per_event_summary("retired-pending")).await;
    wait_for_sink_metric("queue_depth", 0).await;
    assert_eq!(sink_metric("queue_outstanding"), 1);
    assert_eq!(sink_metric("per_event_pending"), pending + 1);
    assert!(server.received_requests().await.unwrap().is_empty());

    let replacement =
        ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
    replacement.start_background_tasks().unwrap();
    replacement.commit_background_tasks();
    assert_ne!(old.active_generation(), replacement.active_generation());
    assert_eq!(sink_metric("queue_outstanding"), 0);
    assert_eq!(sink_metric("per_event_pending"), pending + 1);
    // An in-flight old-generation hook can finish after replacement publication.
    old.log(&per_event_summary("late-retired-hook")).await;
    replacement.log(&per_event_summary("new-pending")).await;
    assert_eq!(sink_metric("per_event_received_total"), received + 3);
    assert_eq!(sink_metric("per_event_pending"), pending + 3);
    drop(old);
    drop(replacement);
    wait_for_sink_metric("per_event_persisted_total", persisted + 3).await;
    assert_eq!(sink_metric("per_event_dropped_total"), dropped);
    assert_eq!(sink_metric("per_event_pending"), pending);
    let requests = server.received_requests().await.unwrap();
    let rows: Vec<Value> = requests
        .iter()
        .flat_map(|request| std::str::from_utf8(&request.body).unwrap().lines())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        rows.len(),
        3,
        "retirement must actually deliver pending rows"
    );
    let identities: std::collections::HashSet<_> = rows
        .iter()
        .map(|row| row["event_id"].as_str().unwrap())
        .collect();
    assert_eq!(identities.len(), 3);
    assert!(rows.iter().all(|row| row["charge_call"] == 0.25));
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn failed_unspooled_delivery_is_counted_after_retirement_and_reload() {
    wait_for_sink_metric("per_event_pending", 0).await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let config = lifecycle_sink_config(&server);
    let received = sink_metric("per_event_received_total");
    let persisted = sink_metric("per_event_persisted_total");
    let dropped = sink_metric("per_event_dropped_total");
    let pending = sink_metric("per_event_pending");
    let old = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
    old.start_background_tasks().unwrap();
    old.commit_background_tasks();
    old.log(&per_event_summary("will-fail-on-retirement")).await;
    let replacement =
        ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
    replacement.start_background_tasks().unwrap();
    replacement.commit_background_tasks();
    drop(old);
    wait_for_sink_metric("per_event_dropped_total", dropped + 1).await;
    assert_eq!(sink_metric("per_event_received_total"), received + 1);
    assert_eq!(sink_metric("per_event_persisted_total"), persisted);
    assert_eq!(sink_metric("per_event_pending"), pending);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    let status: Value =
        serde_json::from_str(&ferrum_edge::plugins::api_chargeback_sink::render_status_json())
            .unwrap();
    assert_eq!(status["totals"]["per_event"]["dropped_total"], dropped + 1);
    assert_eq!(status["instances"][0]["per_event"]["dropped_total"], 0);
    drop(replacement);
    assert_eq!(sink_metric("per_event_dropped_total"), dropped + 1);
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn free_tiers_emit_counted_zero_charge_rows_with_and_without_bandwidth() {
    wait_for_sink_metric("per_event_pending", 0).await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let emitted_after = chrono::Utc::now().timestamp_nanos_opt().unwrap();
    for bandwidth in [false, true] {
        let mut config = lifecycle_sink_config(&server);
        config["batch"]["size"] = json!(1);
        config["pricing_tiers"] = json!([{"status_codes": [200], "price_per_call": 0}]);
        if bandwidth {
            config["bandwidth_pricing"] = json!({"price_per_byte_sent": 0.5});
        }
        let plugin =
            ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
        plugin.start_background_tasks().unwrap();
        plugin.commit_background_tasks();
        let mut summary = per_event_summary("free-tier");
        summary.bytes_sent = 2;
        plugin.log(&summary).await;
        if !bandwidth {
            summary.response_status_code = 404;
            plugin.log(&summary).await;
        }
        drop(plugin);
    }
    wait_for_sink_metric("per_event_pending", 0).await;
    let requests = wait_for_post_requests(&server, 2).await;
    assert_eq!(requests.len(), 2, "unconfigured status must not emit a row");
    let mut rows: Vec<Value> = requests
        .iter()
        .map(|request| request.body_json().unwrap())
        .collect();
    rows.sort_by(|a, b| {
        a["charge_total"]
            .as_f64()
            .partial_cmp(&b["charge_total"].as_f64())
            .unwrap()
    });
    let emitted_before = chrono::Utc::now().timestamp_nanos_opt().unwrap();
    for row in &rows {
        assert_eq!(row["call_count"], 1);
        assert_eq!(row["charge_call"], 0.0);
        assert!(row["consumer_name"].is_null());
        assert!(row["route_id"].is_null());
        let received_at = row["received_at"].as_i64().unwrap();
        assert!((emitted_after..=emitted_before).contains(&received_at));
    }
    assert_eq!(rows[0]["charge_total"], 0.0);
    assert_eq!(rows[1]["charge_total"], 1.0);
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn detected_websocket_flavor_prices_h1_h2_h3_handshakes_equally() {
    wait_for_sink_metric("per_event_pending", 0).await;
    use std::sync::Arc;

    use ferrum_edge::_test_support::set_request_http_flavor_for_test;
    use ferrum_edge::config::types::HttpFlavor;
    use ferrum_edge::plugins::{RequestContext, log_with_mirror};
    use ferrum_edge::proxy::backend_dispatch::detect_http_flavor;
    use http::{Request, Version};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let mut config = lifecycle_sink_config(&server);
    config["batch"]["size"] = json!(1);
    config["pricing_tiers"] = json!([
        {"status_codes": [101], "price_per_call": 0.25},
        {"status_codes": [200], "price_per_call": 0.75},
        {"status_codes": [403, 503], "price_per_call": 0.5}
    ]);
    let sink =
        Arc::new(ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap());
    sink.start_background_tasks().unwrap();
    sink.commit_background_tasks();
    let plugins: Vec<Arc<dyn Plugin>> = vec![sink];
    for (name, version, status, expected_flavor) in [
        ("h1", Version::HTTP_11, 101, HttpFlavor::WebSocket),
        ("h2", Version::HTTP_2, 200, HttpFlavor::WebSocket),
        ("h3", Version::HTTP_3, 200, HttpFlavor::WebSocket),
        ("plain", Version::HTTP_2, 200, HttpFlavor::Plain),
        ("rejected", Version::HTTP_3, 403, HttpFlavor::WebSocket),
        ("grpc", Version::HTTP_2, 200, HttpFlavor::Grpc),
    ] {
        let mut request = Request::builder()
            .method(
                if expected_flavor == HttpFlavor::WebSocket && version != Version::HTTP_11 {
                    "CONNECT"
                } else {
                    "GET"
                },
            )
            .uri("https://billing.example/socket")
            .version(version)
            .body(())
            .unwrap();
        if expected_flavor == HttpFlavor::WebSocket {
            if version == Version::HTTP_11 {
                request
                    .headers_mut()
                    .insert("upgrade", "websocket".parse().unwrap());
                request
                    .headers_mut()
                    .insert("connection", "upgrade".parse().unwrap());
                request
                    .headers_mut()
                    .insert("sec-websocket-version", "13".parse().unwrap());
                request.headers_mut().insert(
                    "sec-websocket-key",
                    "dGhlIHNhbXBsZSBub25jZQ==".parse().unwrap(),
                );
            } else if version == Version::HTTP_3 {
                request
                    .extensions_mut()
                    .insert(h3::ext::Protocol::WEB_SOCKET);
            } else {
                request
                    .extensions_mut()
                    .insert(hyper::ext::Protocol::from_static("websocket"));
            }
        } else if expected_flavor == HttpFlavor::Grpc {
            request
                .headers_mut()
                .insert("content-type", "application/grpc".parse().unwrap());
        }
        let flavor = detect_http_flavor(&request);
        assert_eq!(flavor, expected_flavor);
        let mut ctx = RequestContext::new(
            "127.0.0.1".into(),
            request.method().to_string(),
            "/socket".into(),
        );
        set_request_http_flavor_for_test(&mut ctx, flavor);
        let mut summary = per_event_summary(name);
        summary.proxy_id = Some(name.to_string());
        summary.response_status_code = status;
        summary.http_method = request.method().to_string();
        if flavor == HttpFlavor::Grpc {
            summary
                .metadata
                .insert("request_protocol".into(), "grpc".into());
            summary.metadata.insert("grpc_status".into(), "14".into());
        }
        log_with_mirror(&plugins, &summary, &ctx).await;
    }
    let requests = wait_for_post_requests(&server, 6).await;
    let rows: HashMap<String, Value> = requests
        .iter()
        .map(|request| {
            let row: Value = request.body_json().unwrap();
            (row["proxy_id"].as_str().unwrap().to_string(), row)
        })
        .collect();
    assert_eq!(rows.len(), 6);
    for name in ["h1", "h2", "h3"] {
        assert_eq!(rows[name]["protocol"], "ws");
        assert_eq!(rows[name]["status_code"], 101);
        assert_eq!(rows[name]["charge_call"], 0.25);
        assert_eq!(rows[name]["call_count"], 1);
    }
    assert_eq!(rows["h1"]["http_status_code"], 101);
    assert_eq!(rows["h2"]["http_status_code"], 200);
    assert_eq!(rows["h3"]["http_status_code"], 200);
    assert_eq!(rows["plain"]["protocol"], "http");
    assert_eq!(rows["plain"]["charge_call"], 0.75);
    assert_eq!(rows["rejected"]["status_code"], 403);
    assert_eq!(rows["rejected"]["charge_call"], 0.5);
    assert_eq!(rows["grpc"]["status_code"], 503);
    assert_eq!(rows["grpc"]["grpc_status"], 14);
    assert_eq!(rows["grpc"]["charge_call"], 0.5);
    drop(plugins);
    wait_for_sink_metric("per_event_pending", 0).await;
}

#[test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
fn runtime_cancellation_counts_memory_loss_without_claiming_a_process_crash_flush() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(wait_for_sink_metric("per_event_pending", 0));
    let received = sink_metric("per_event_received_total");
    let persisted = sink_metric("per_event_persisted_total");
    let dropped = sink_metric("per_event_dropped_total");
    let pending = sink_metric("per_event_pending");
    let (plugin, server) = runtime.block_on(async {
        let server = MockServer::start().await;
        let config = lifecycle_sink_config(&server);
        let plugin =
            ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
        plugin.start_background_tasks().unwrap();
        plugin.commit_background_tasks();
        plugin.log(&per_event_summary("cancel-pending")).await;
        wait_for_sink_metric("queue_depth", 0).await;
        assert_eq!(sink_metric("queue_outstanding"), 1);
        assert_eq!(sink_metric("per_event_pending"), pending + 1);
        assert!(server.received_requests().await.unwrap().is_empty());
        (plugin, server)
    });
    // Tokio cancellation executes Rust destructors. SIGKILL/power loss does not.
    drop(runtime);
    assert_eq!(sink_metric("per_event_received_total"), received + 1);
    assert_eq!(sink_metric("per_event_persisted_total"), persisted);
    assert_eq!(sink_metric("per_event_dropped_total"), dropped + 1);
    assert_eq!(sink_metric("per_event_pending"), pending);
    drop(plugin);
    drop(server);
}

#[test]
fn chargeback_process_counters_start_fresh_only_in_a_new_process() {
    const CHILD: &str = "FERRUM_TEST_CHARGEBACK_COUNTER_CHILD";
    if std::env::var_os(CHILD).is_some() {
        assert_eq!(sink_metric("per_event_received_total"), 0);
        assert_eq!(sink_metric("per_event_dropped_total"), 0);
        assert_eq!(sink_metric("queue_full_drops_total"), 0);
        let status: Value =
            serde_json::from_str(&ferrum_edge::plugins::api_chargeback_sink::render_status_json())
                .unwrap();
        assert_eq!(status["totals"]["export"]["events_enqueued_total"], 0);
        assert_eq!(status["totals"]["per_event"]["pending"], 0);
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "integration::api_chargeback_sink_tests::chargeback_process_counters_start_fresh_only_in_a_new_process",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn failed_export_settles_once_only_after_spool_write_with_unchanged_identity() {
    wait_for_sink_metric("per_event_pending", 0).await;
    use ferrum_edge::plugins::api_chargeback_sink::decode_spool_file_for_tests;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let temp = tempfile::tempdir().unwrap();
    let mut config = lifecycle_sink_config(&server);
    config["batch"]["size"] = json!(1);
    config["spool"] = json!({
        "enabled": true,
        "dir": temp.path().to_string_lossy(),
        "compression": "none",
        "replay_interval_secs": 3600
    });
    let persisted = sink_metric("per_event_persisted_total");
    let dropped = sink_metric("per_event_dropped_total");
    let pending = sink_metric("per_event_pending");
    let plugin = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
    plugin.start_background_tasks().unwrap();
    plugin.commit_background_tasks();
    plugin.log(&per_event_summary("spool-settlement")).await;
    // Retire before yielding so the replayer cannot claim this new row while
    // the test inspects it; the flush and spool delivery owners must still drain.
    drop(plugin);
    wait_for_sink_metric("per_event_persisted_total", persisted + 1).await;
    assert_eq!(sink_metric("per_event_pending"), pending);
    assert_eq!(sink_metric("per_event_dropped_total"), dropped);
    let requests = server.received_requests().await.unwrap();
    assert!(
        !requests.is_empty(),
        "must actually attempt ClickHouse delivery"
    );
    let posted: Value = requests[0].body_json().unwrap();
    let mut dirs = vec![temp.path().to_path_buf()];
    let mut rows = Vec::new();
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "ndjson") {
                let body = decode_spool_file_for_tests(&path).unwrap();
                rows.extend(
                    body.lines()
                        .map(|line| serde_json::from_str::<Value>(line).unwrap()),
                );
            }
        }
    }
    assert_eq!(rows.len(), 1, "failed export must leave one durable row");
    assert_eq!(rows[0]["event_id"], posted["event_id"]);
    assert_eq!(rows[0]["charge_total"], posted["charge_total"]);
    assert_eq!(rows[0]["call_count"], 1);
    assert_eq!(sink_metric("per_event_persisted_total"), persisted + 1);
}
