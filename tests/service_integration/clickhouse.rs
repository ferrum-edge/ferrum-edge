//! Live ClickHouse contracts for `api_chargeback_sink` JSONEachRow inserts.
//!
//! The always-on static gate lives in
//! `tests/integration/api_chargeback_sink_tests.rs` (issue #4441). This module
//! boots a pinned ClickHouse HTTP endpoint, applies
//! `migrations/clickhouse/0001_charges.sql`, and round-trips representative
//! events through the plugin's real INSERT path.

use std::collections::HashMap;
use std::time::Duration;

use ferrum_edge::plugins::api_chargeback_sink::{
    ApiChargebackSink, ChargeEvent, compile_charge_event_projection, serialize_json_each_row,
    serialize_json_each_row_projected,
};
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, StreamTransactionSummary, TransactionSummary,
};
use serde_json::{Value, json};
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use super::common::containers::{BoxError, fail_in_ci_else_skip};
use super::common::host_ports::{
    allocate_host_port, is_host_port_collision, retry_on_host_port_collision,
};

const CLICKHOUSE_IMAGE: &str = "clickhouse/clickhouse-server";
const CLICKHOUSE_TAG: &str = "24.8";
const CLICKHOUSE_HTTP_PORT: u16 = 8123;
const CHARGES_DDL: &str = include_str!("../../migrations/clickhouse/0001_charges.sql");
const PRICING_VERSION: &str = "it-clickhouse-wire-4441";

struct ClickHouseFixture {
    _container: ContainerAsync<GenericImage>,
    url: String,
    client: reqwest::Client,
}

async fn start_clickhouse_container(
    host_port: u16,
) -> Result<ContainerAsync<GenericImage>, BoxError> {
    const START_ATTEMPTS: u32 = 3;

    for attempt in 1..=START_ATTEMPTS {
        match GenericImage::new(CLICKHOUSE_IMAGE, CLICKHOUSE_TAG)
            .with_exposed_port(CLICKHOUSE_HTTP_PORT.tcp())
            .with_mapped_port(host_port, CLICKHOUSE_HTTP_PORT.tcp())
            .with_env_var("CLICKHOUSE_SKIP_USER_SETUP", "1")
            .start()
            .await
        {
            Ok(container) => return Ok(container),
            Err(error) => {
                if is_host_port_collision(&error.to_string()) {
                    return Err(format!("ClickHouse container start failed: {error}").into());
                }
                if attempt == START_ATTEMPTS {
                    return Err(format!(
                        "ClickHouse container failed to start after \
                         {START_ATTEMPTS} attempts: {error}"
                    )
                    .into());
                }
                eprintln!(
                    "ClickHouse container start attempt {attempt}/{START_ATTEMPTS} \
                     failed; retrying: {error}"
                );
                tokio::time::sleep(Duration::from_secs(u64::from(attempt))).await;
            }
        }
    }

    Err("ClickHouse container start retry loop did not execute".into())
}

async fn wait_clickhouse_ready(client: &reqwest::Client, url: &str) -> Result<(), BoxError> {
    let ping = format!("{url}/ping");
    let mut last_error = String::new();
    for _ in 0..90 {
        match client.get(&ping).send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await.unwrap_or_default();
                if body.trim().eq_ignore_ascii_case("ok.") || body.trim().eq_ignore_ascii_case("ok")
                {
                    return Ok(());
                }
                last_error = format!("unexpected /ping body ({})", body.len());
            }
            Ok(response) => {
                last_error = format!("HTTP {}", response.status());
            }
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!("ClickHouse /ping not ready within 45s: {last_error}").into())
}

async fn start_clickhouse() -> Result<ClickHouseFixture, BoxError> {
    let (container, port) = retry_on_host_port_collision(|| async {
        let host_port = allocate_host_port()?;
        let container = start_clickhouse_container(host_port).await?;
        Ok((container, host_port))
    })
    .await?;
    let url = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    wait_clickhouse_ready(&client, &url).await?;
    Ok(ClickHouseFixture {
        _container: container,
        url,
        client,
    })
}

fn clickhouse_url_with_query(base: &str, params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return base.to_string();
    }
    let mut url = url::Url::parse(base).expect("ClickHouse fixture URL");
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            pairs.append_pair(key, value);
        }
    }
    url.to_string()
}

/// First ~2000 chars of a ClickHouse HTTP body for fixture errors.
/// The `Code: NNN. DB::Exception: …` line must survive into the message.
fn clickhouse_error_body(text: &str) -> String {
    const LIMIT: usize = 2000;
    let trimmed = text.trim();
    let mut chars = trimmed.chars();
    let bounded: String = chars.by_ref().take(LIMIT).collect();
    if chars.next().is_some() {
        format!("{bounded}...")
    } else {
        bounded
    }
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

async fn clickhouse_post(
    fixture: &ClickHouseFixture,
    params: &[(&str, &str)],
    body: String,
) -> Result<String, String> {
    // ClickHouse 24.8 rejects a POST that carries neither `Content-Length` nor
    // chunked `Transfer-Encoding` with `411 Length Required` (`Code: 381`).
    // Read-only helpers pass an empty body, so set the length explicitly
    // instead of relying on reqwest to frame a zero-length body.
    let content_length = body.len();
    let response = fixture
        .client
        .post(clickhouse_url_with_query(&fixture.url, params))
        .header(reqwest::header::CONTENT_LENGTH, content_length)
        .body(body)
        .send()
        .await
        .map_err(|error| format!("ClickHouse request failed to send: {error}"))?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!(
            "ClickHouse HTTP {status}: {}",
            clickhouse_error_body(&text)
        ));
    }
    if text.contains("Code:") || text.contains("Exception") {
        return Err(format!(
            "ClickHouse exception in success body: {}",
            clickhouse_error_body(&text)
        ));
    }
    Ok(text)
}

async fn apply_ddl(fixture: &ClickHouseFixture) -> Result<(), String> {
    let statements = split_clickhouse_statements(CHARGES_DDL);
    for (index, statement) in statements.iter().enumerate() {
        let ordinal = index + 1;
        let total = statements.len();
        match clickhouse_post(fixture, &[], statement.clone()).await {
            Ok(_) => {}
            Err(error) => {
                return Err(format!(
                    "DDL statement {ordinal} of {total} failed: {error}"
                ));
            }
        }
    }
    Ok(())
}

fn insert_query() -> String {
    "INSERT INTO charges_raw FORMAT JSONEachRow".to_string()
}

async fn insert_json_each_row(fixture: &ClickHouseFixture, body: String) -> Result<(), String> {
    clickhouse_post(
        fixture,
        &[("database", "ferrum"), ("query", &insert_query())],
        body,
    )
    .await
    .map(|_| ())
}

fn http_summary(request_id: &str, consumer: &str) -> TransactionSummary {
    let mut metadata = HashMap::new();
    metadata.insert("request_id".to_string(), request_id.to_string());
    metadata.insert("trace_id".to_string(), format!("trace-{request_id}"));
    metadata.insert("consumer_name".to_string(), "Integration Consumer".into());
    metadata.insert("route_id".to_string(), "it-route".to_string());
    TransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        timestamp_received: "2026-05-23T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: Some(consumer.to_string()),
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
        bytes_sent: 32,
        bytes_received: 64,
        grpc_request_messages: 0,
        grpc_response_messages: 0,
        mirror: false,
        metadata,
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

fn grpc_summary(request_id: &str, consumer: &str) -> TransactionSummary {
    let mut summary = http_summary(request_id, consumer);
    summary
        .metadata
        .insert("request_protocol".to_string(), "grpc".to_string());
    summary
        .metadata
        .insert("grpc_status".to_string(), "0".to_string());
    summary.response_status_code = 200;
    summary.grpc_request_messages = 1;
    summary.grpc_response_messages = 1;
    summary
}

fn unicode_summary(request_id: &str, consumer: &str) -> TransactionSummary {
    let mut summary = http_summary(request_id, consumer);
    summary
        .metadata
        .insert("consumer_name".to_string(), "消费者-münchen".to_string());
    summary
}

fn stream_summary(consumer: &str) -> StreamTransactionSummary {
    let mut metadata = HashMap::new();
    metadata.insert("request_id".to_string(), "it-stream".to_string());
    StreamTransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        proxy_id: "it-proxy".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("Integration Proxy".to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: Some(consumer.to_string()),
        auth_method: None,
        backend_target: "10.0.0.50:5432".to_string(),
        backend_resolved_ip: Some("10.0.0.50".to_string()),
        protocol: "tcp".to_string(),
        listen_port: 5432,
        duration_ms: 12.0,
        bytes_sent: 8,
        bytes_received: 16,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-05-23T00:00:00Z".to_string(),
        timestamp_disconnected: "2026-05-23T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata,
    }
}

fn sink_config(clickhouse_url: &str, spool_dir: &str) -> Value {
    json!({
        "clickhouse": {
            "url": clickhouse_url,
            "database": "ferrum",
            "table": "charges_raw",
            "timeout_ms": 5000
        },
        "batch": {
            "size": 1,
            "flush_interval_ms": 10,
            "buffer_capacity": 16
        },
        "retry": {
            "max_attempts": 1,
            "initial_delay_ms": 1,
            "max_delay_ms": 1,
            "jitter": false
        },
        "spool": {
            "enabled": true,
            "dir": spool_dir,
            "max_bytes": 1048576,
            "replay_interval_secs": 1
        },
        "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.25 }],
        "stream_connection_pricing": { "price_per_connection": 0.0001 },
        "pricing_version": PRICING_VERSION,
        "currency": "USD"
    })
}

fn extreme_event() -> ChargeEvent {
    ChargeEvent {
        event_id: "evt-extreme-max".to_string(),
        received_at: 1_774_000_000_000_000_000,
        node_id: "node-a".to_string(),
        namespace: "ferrum".to_string(),
        consumer_id: "it-extreme".to_string(),
        consumer_name: Some("消费者-münchen".to_string()),
        proxy_id: "it-proxy".to_string(),
        proxy_name: "Integration Proxy".to_string(),
        route_id: Some("it-route".to_string()),
        status_code: u16::MAX,
        http_status_code: None,
        grpc_status: Some(u32::MAX),
        protocol: "tcp".to_string(),
        call_count: u64::MAX,
        charge_call: 1.25,
        bytes_sent: u64::MAX,
        bytes_received: 0,
        charge_bytes_sent: 0.5,
        charge_bytes_received: 0.0,
        charge_total: 1.75,
        currency: "EUR".to_string(),
        pricing_version: PRICING_VERSION.to_string(),
        request_id: Some("req-extreme".to_string()),
        trace_id: Some("trace-extreme".to_string()),
        snapshot_id: Some("snap-extreme".to_string()),
    }
}

fn identity_schema() -> Value {
    json!({
        "order": [
            "event_id", "received_at", "node_id", "namespace", "consumer_id",
            "consumer_name", "proxy_id", "proxy_name", "route_id", "status_code",
            "http_status_code", "grpc_status", "protocol", "call_count",
            "charge_call", "bytes_sent", "bytes_received", "charge_bytes_sent",
            "charge_bytes_received", "charge_total", "currency",
            "pricing_version", "request_id", "trace_id", "snapshot_id"
        ]
    })
}

async fn wait_for_count(
    fixture: &ClickHouseFixture,
    where_clause: &str,
    at_least: u64,
) -> Result<u64, String> {
    let query = format!("SELECT count() FROM ferrum.charges_raw FINAL WHERE {where_clause}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let body = clickhouse_post(fixture, &[("query", query.as_str())], String::new()).await?;
        let count = body.trim().parse::<u64>().unwrap_or(0);
        if count >= at_least {
            return Ok(count);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "expected at least {at_least} row(s) for {where_clause}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn json_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

fn json_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok()))
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

async fn select_row(fixture: &ClickHouseFixture, where_clause: &str) -> Result<Value, String> {
    let query = format!(
        "SELECT event_id, toUnixTimestamp64Nano(received_at) AS received_at, \
         node_id, namespace, consumer_id, consumer_name, proxy_id, proxy_name, \
         route_id, status_code, http_status_code, grpc_status, protocol, \
         call_count, charge_call, bytes_sent, bytes_received, \
         charge_bytes_sent, charge_bytes_received, charge_total, currency, \
         pricing_version, request_id, trace_id, snapshot_id \
         FROM ferrum.charges_raw FINAL WHERE {where_clause} \
         FORMAT JSONEachRow"
    );
    let body = clickhouse_post(fixture, &[("query", query.as_str())], String::new()).await?;
    let line = body
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| format!("no JSONEachRow for {where_clause}"))?;
    serde_json::from_str(line)
        .map_err(|error| format!("ClickHouse JSONEachRow parse failed: {error}"))
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn clickhouse_ddl_jsoneachrow_round_trip() {
    let fixture = match start_clickhouse().await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip(
                "clickhouse_ddl_jsoneachrow_round_trip",
                "ClickHouse 24.8",
                &error,
            );
            return;
        }
    };

    apply_ddl(&fixture)
        .await
        .expect("baseline charges DDL must apply");

    let temp = tempfile::tempdir().expect("spool dir");
    let spool_dir = temp.path().to_string_lossy().to_string();
    let plugin = ApiChargebackSink::new(
        &sink_config(&fixture.url, &spool_dir),
        PluginHttpClient::default(),
        "ferrum",
    )
    .expect("chargeback sink must construct");
    plugin
        .start_background_tasks()
        .expect("chargeback live integration requires start_background_tasks");
    plugin.commit_background_tasks();

    plugin
        .log(&http_summary("it-http", "it-http-consumer"))
        .await;
    plugin
        .log(&grpc_summary("it-grpc", "it-grpc-consumer"))
        .await;
    plugin
        .log(&unicode_summary("it-unicode", "it-unicode-consumer"))
        .await;
    plugin
        .on_stream_disconnect(&stream_summary("it-stream-consumer"))
        .await;

    wait_for_count(
        &fixture,
        "pricing_version='it-clickhouse-wire-4441' \
         AND consumer_id='it-http-consumer'",
        1,
    )
    .await
    .expect("HTTP plugin insert must land");
    wait_for_count(
        &fixture,
        "pricing_version='it-clickhouse-wire-4441' \
         AND consumer_id='it-grpc-consumer'",
        1,
    )
    .await
    .expect("gRPC plugin insert must land");
    wait_for_count(
        &fixture,
        "pricing_version='it-clickhouse-wire-4441' \
         AND consumer_id='it-unicode-consumer'",
        1,
    )
    .await
    .expect("Unicode plugin insert must land");
    wait_for_count(
        &fixture,
        "pricing_version='it-clickhouse-wire-4441' \
         AND consumer_id='it-stream-consumer'",
        1,
    )
    .await
    .expect("stream plugin insert must land");

    let http_row = select_row(
        &fixture,
        "pricing_version='it-clickhouse-wire-4441' \
         AND consumer_id='it-http-consumer'",
    )
    .await
    .expect("HTTP row");
    assert_eq!(http_row["currency"], json!("USD"));
    assert_eq!(http_row["pricing_version"], json!(PRICING_VERSION));
    assert_eq!(http_row["protocol"], json!("http"));
    assert_eq!(http_row["status_code"], json!(200));
    assert_eq!(http_row["http_status_code"], json!(200));
    assert!(http_row.get("grpc_status").is_none_or(|v| v.is_null()));
    assert_eq!(http_row["request_id"], json!("it-http"));
    assert_eq!(http_row["trace_id"], json!("trace-it-http"));
    assert!(json_i64(&http_row["received_at"]).unwrap_or(0) > 0);
    assert_eq!(http_row["charge_call"].as_f64(), Some(0.25));

    let grpc_row = select_row(
        &fixture,
        "pricing_version='it-clickhouse-wire-4441' \
         AND consumer_id='it-grpc-consumer'",
    )
    .await
    .expect("gRPC row");
    assert_eq!(grpc_row["protocol"], json!("grpc"));
    assert!(grpc_row.get("grpc_status").is_some_and(|v| !v.is_null()));

    let unicode_row = select_row(
        &fixture,
        "pricing_version='it-clickhouse-wire-4441' \
         AND consumer_id='it-unicode-consumer'",
    )
    .await
    .expect("Unicode row");
    assert_eq!(unicode_row["consumer_name"], json!("消费者-münchen"));

    let stream_row = select_row(
        &fixture,
        "pricing_version='it-clickhouse-wire-4441' \
         AND consumer_id='it-stream-consumer'",
    )
    .await
    .expect("stream row");
    assert_eq!(stream_row["protocol"], json!("tcp"));
    assert!(
        stream_row
            .get("http_status_code")
            .is_none_or(|v| v.is_null())
    );
    assert!(stream_row.get("grpc_status").is_none_or(|v| v.is_null()));

    let extreme = extreme_event();
    let extreme_body = serialize_json_each_row(std::slice::from_ref(&extreme))
        .expect("extreme ChargeEvent must serialize");
    insert_json_each_row(&fixture, extreme_body)
        .await
        .expect("extreme JSONEachRow insert must succeed");

    apply_ddl(&fixture)
        .await
        .expect("re-applying baseline DDL must stay compatible");

    wait_for_count(&fixture, "event_id='evt-extreme-max'", 1)
        .await
        .expect("extreme row must land");
    let extreme_row = select_row(&fixture, "event_id='evt-extreme-max'")
        .await
        .expect("extreme row");
    assert_eq!(json_u64(&extreme_row["call_count"]), Some(u64::MAX));
    assert_eq!(json_u64(&extreme_row["bytes_sent"]), Some(u64::MAX));
    assert_eq!(extreme_row["status_code"], json!(u16::MAX));
    assert_eq!(json_u64(&extreme_row["grpc_status"]), Some(u32::MAX as u64));
    assert!(
        extreme_row
            .get("http_status_code")
            .is_none_or(|v| v.is_null())
    );
    assert_eq!(extreme_row["currency"], json!("EUR"));
    assert_eq!(
        json_i64(&extreme_row["received_at"]),
        Some(1_774_000_000_000_000_000i64)
    );
    assert_eq!(extreme_row["snapshot_id"], json!("snap-extreme"));

    let replay_event = ChargeEvent {
        event_id: "evt-replay-artifact".to_string(),
        consumer_id: "it-replay".to_string(),
        ..extreme_event()
    };
    let artifact = serialize_json_each_row(std::slice::from_ref(&replay_event))
        .expect("spool artifact must serialize");
    insert_json_each_row(&fixture, artifact)
        .await
        .expect("durable JSONEachRow artifact replay must succeed");
    wait_for_count(&fixture, "event_id='evt-replay-artifact'", 1)
        .await
        .expect("replayed artifact must land");

    let projection = compile_charge_event_projection(&json!({
        "clickhouse": { "url": fixture.url },
        "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.01 }],
        "schema": identity_schema()
    }))
    .expect("identity schema compiles")
    .expect("schema present");
    let mut projected = extreme_event();
    projected.event_id = "evt-identity-projection".to_string();
    projected.consumer_id = "it-identity".to_string();
    let projected_body =
        serialize_json_each_row_projected(std::slice::from_ref(&projected), Some(&projection))
            .expect("identity projection must serialize");
    insert_json_each_row(&fixture, projected_body)
        .await
        .expect("identity-projected JSONEachRow must insert");
    wait_for_count(&fixture, "event_id='evt-identity-projection'", 1)
        .await
        .expect("identity projection row must land");
}
