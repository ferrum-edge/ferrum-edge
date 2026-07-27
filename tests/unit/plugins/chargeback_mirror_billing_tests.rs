//! Prove request_mirror shadow summaries never inflate consumer chargeback.
//!
//! These tests drive the real [`ferrum_edge::plugins::log_with_mirror`]
//! composition used by proxy paths: primary summary first, then a detached
//! mirror summary with `mirror: true`. Both `api_chargeback` and
//! `api_chargeback_sink` must record exactly one client charge.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ferrum_edge::_test_support::{
    api_chargeback_sink_snapshot_accumulator_for_test, request_mirror_should_mirror_for_test,
};
use ferrum_edge::plugins::api_chargeback::{
    ApiChargeback, InstanceScope, ProtocolFamily, global_registry,
};
use ferrum_edge::plugins::api_chargeback_sink::{ApiChargebackSink, ApiChargebackSinkConfig};
use ferrum_edge::plugins::request_mirror::RequestMirror;
use ferrum_edge::plugins::{
    MirrorResponseMeta, Plugin, PluginHttpClient, RequestContext, TransactionSummary,
    log_with_mirror, priority,
};
use serde_json::{Value, json};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

struct CapturingLogger {
    summaries: Mutex<Vec<TransactionSummary>>,
}

#[async_trait::async_trait]
impl Plugin for CapturingLogger {
    fn name(&self) -> &str {
        "capturing_chargeback_mirror_logger"
    }

    fn priority(&self) -> u16 {
        priority::STDOUT_LOGGING
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.summaries.lock().unwrap().push(summary.clone());
    }
}

fn primary_summary(consumer: &str, proxy_id: &str, status: u16) -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".to_string(),
        timestamp_received: "2025-01-01T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: Some(consumer.to_string()),
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/chargeback-mirror".to_string(),
        proxy_id: Some(proxy_id.to_string()),
        proxy_name: Some("Mirror Billing".to_string()),
        backend_target: Some("http://primary.local/chargeback-mirror".to_string()),
        backend_resolved_ip: None,
        response_status_code: status,
        latency_total_ms: 12.0,
        latency_gateway_processing_ms: 1.0,
        latency_backend_ttfb_ms: 10.0,
        latency_backend_total_ms: 11.0,
        latency_plugin_execution_ms: 0.5,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 0.5,
        request_user_agent: Some("chargeback-mirror-test".to_string()),
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: true,
        bytes_sent: 32,
        bytes_received: 64,
        mirror: false,
        metadata: HashMap::new(),
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

fn chargeback_key(
    consumer: &str,
    proxy_id: &str,
    status_code: u16,
    call_price: f64,
    bw_price_sent: f64,
    bw_price_received: f64,
) -> String {
    let scope = InstanceScope::new("USD", "ferrum");
    format!(
        "{}|{}|{}|{}|http|{}|{:016x}|{:016x}|{:016x}",
        consumer,
        scope.namespace,
        proxy_id,
        status_code,
        scope.currency,
        call_price.to_bits(),
        bw_price_sent.to_bits(),
        bw_price_received.to_bits()
    )
}

fn total_http_calls(consumer: &str, proxy_id: &str) -> u64 {
    let registry = global_registry();
    registry
        .entries
        .iter()
        .filter(|entry| {
            entry.consumer.as_ref() == consumer
                && entry.proxy_id.as_ref() == proxy_id
                && entry.protocol_family == ProtocolFamily::Http
        })
        .map(|entry| entry.call_count.load(Ordering::Relaxed))
        .sum()
}

fn total_http_bytes(consumer: &str, proxy_id: &str) -> (u64, u64) {
    let registry = global_registry();
    let mut sent = 0u64;
    let mut received = 0u64;
    for entry in registry.entries.iter().filter(|entry| {
        entry.consumer.as_ref() == consumer
            && entry.proxy_id.as_ref() == proxy_id
            && entry.protocol_family == ProtocolFamily::Http
    }) {
        sent = sent.saturating_add(entry.bytes_sent_total.load(Ordering::Relaxed));
        received = received.saturating_add(entry.bytes_received_total.load(Ordering::Relaxed));
    }
    (sent, received)
}

async fn wait_until_logged(logger: &CapturingLogger, expect_summaries: usize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if logger.summaries.lock().unwrap().len() >= expect_summaries {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached mirror logging did not complete");
}

async fn drive_log_with_mirror(
    plugins: &[Arc<dyn Plugin>],
    summary: &TransactionSummary,
    mirror: Option<MirrorResponseMeta>,
) {
    let logger = Arc::new(CapturingLogger {
        summaries: Mutex::new(Vec::new()),
    });
    // Capture after chargeback plugins so waiting for N summaries means the
    // billable hooks have already observed the same primary/mirror entries.
    let mut all_plugins: Vec<Arc<dyn Plugin>> = plugins.to_vec();
    all_plugins.push(logger.clone());

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/chargeback-mirror".to_string(),
    );
    let publisher = mirror.map(|meta| {
        let (tx, rx) = tokio::sync::watch::channel(None);
        ctx.push_mirror_result_rx(rx);
        (tx, meta)
    });
    let expect_summaries = if publisher.is_some() { 2 } else { 1 };

    log_with_mirror(&all_plugins, summary, &ctx).await;

    if let Some((tx, meta)) = publisher {
        tx.send(Some(meta))
            .expect("detached mirror collector must retain its receiver");
    }
    wait_until_logged(&logger, expect_summaries).await;
    // Extra yields so a buggy second charge would have time to land after the
    // mirror summary reaches every logging plugin.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

fn mirror_success(status: u16) -> MirrorResponseMeta {
    MirrorResponseMeta {
        mirror_plugin_id: Some("mirror-billing".to_string()),
        mirror_target_url: "http://shadow.local/chargeback-mirror".to_string(),
        mirror_response_status_code: Some(status),
        mirror_response_size_bytes: Some(128),
        mirror_response_advertised_size_bytes: None,
        mirror_latency_ms: 5.0,
        mirror_error: None,
    }
}

fn mirror_error() -> MirrorResponseMeta {
    MirrorResponseMeta {
        mirror_plugin_id: Some("mirror-billing".to_string()),
        mirror_target_url: "http://shadow.local/chargeback-mirror".to_string(),
        // Keep a valid, billable status alongside the transport error so this
        // fixture would create a duplicate charge without the mirror guard.
        mirror_response_status_code: Some(500),
        mirror_response_size_bytes: None,
        mirror_response_advertised_size_bytes: None,
        mirror_latency_ms: 1.0,
        mirror_error: Some("connection refused".to_string()),
    }
}

fn sink_pricing_config(spool_dir: &std::path::Path, mode: &str, clickhouse_url: &str) -> Value {
    let mut config = json!({
        "mode": mode,
        "clickhouse": {
            "url": clickhouse_url,
            "database": "ferrum",
            "table": "charges_raw",
            "timeout_ms": 1000
        },
        "batch": {"size": 1, "flush_interval_ms": 60000, "buffer_capacity": 10},
        "retry": {"max_attempts": 1, "initial_delay_ms": 1, "max_delay_ms": 1, "jitter": false},
        "spool": {
            "enabled": true,
            "dir": spool_dir.to_string_lossy().to_string(),
            "max_bytes": 1048576,
            "replay_interval_secs": 3600,
            "compression": "none"
        },
        "pricing_tiers": [
            {"status_codes": [200], "price_per_call": 0.01},
            {"status_codes": [500], "price_per_call": 0.05}
        ],
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.000001,
            "price_per_byte_received": 0.000002
        },
        "pricing_version": "mirror-billing-v1",
        "currency": "USD"
    });
    if mode == "snapshot" {
        config["snapshot"] = json!({
            "interval_secs": 3600,
            "cleanup_interval_secs": 3600,
            "emit_zero_deltas": false
        });
    }
    config
}

async fn wait_for_requests(server: &MockServer, at_least: usize) -> Vec<wiremock::Request> {
    for _ in 0..40 {
        if let Some(requests) = server.received_requests().await
            && requests.len() >= at_least
        {
            return requests;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("mock server did not receive {at_least} request(s)");
}

#[tokio::test]
async fn in_memory_chargeback_bills_primary_once_for_mirror_success_and_error() {
    let config = json!({
        "pricing_tiers": [
            {"status_codes": [200], "price_per_call": 0.01},
            {"status_codes": [500], "price_per_call": 0.05}
        ],
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.000001,
            "price_per_byte_received": 0.000002
        }
    });
    let plugin = Arc::new(ApiChargeback::new(&config, "ferrum").unwrap());
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin];

    // Differing primary/mirror statuses: primary 200, mirror 500.
    let success_consumer = "mirror-billing-success";
    let success_proxy = "proxy-mirror-success";
    let success_summary = primary_summary(success_consumer, success_proxy, 200);
    drive_log_with_mirror(&plugins, &success_summary, Some(mirror_success(500))).await;
    assert_eq!(total_http_calls(success_consumer, success_proxy), 1);
    assert_eq!(total_http_bytes(success_consumer, success_proxy), (32, 64));
    let registry = global_registry();
    assert!(registry.entries.contains_key(&chargeback_key(
        success_consumer,
        success_proxy,
        200,
        0.01,
        0.000001,
        0.000002
    )));
    assert!(
        !registry.entries.contains_key(&chargeback_key(
            success_consumer,
            success_proxy,
            500,
            0.05,
            0.000001,
            0.000002
        )),
        "mirror 500 must not create a second billable status bucket"
    );

    // Mirror error path with a valid, otherwise billable 500 status.
    let error_consumer = "mirror-billing-error";
    let error_proxy = "proxy-mirror-error";
    let error_summary = primary_summary(error_consumer, error_proxy, 200);
    drive_log_with_mirror(&plugins, &error_summary, Some(mirror_error())).await;
    assert_eq!(total_http_calls(error_consumer, error_proxy), 1);
    assert!(
        !registry.entries.contains_key(&chargeback_key(
            error_consumer,
            error_proxy,
            500,
            0.05,
            0.000001,
            0.000002
        )),
        "failed mirror summary must not bill its status 500"
    );
}

#[tokio::test]
async fn in_memory_chargeback_bills_each_primary_once_below_100_percent() {
    let config = json!({
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
    });
    let plugin = Arc::new(ApiChargeback::new(&config, "ferrum").unwrap());
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin];
    let sampler = RequestMirror::new(
        &json!({
            "mirror_host": "shadow.local",
            "percentage": 50.0,
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
    )
    .expect("valid below-100 request_mirror sampler");
    let consumer = "mirror-pct-billing";
    let proxy = "proxy-mirror-pct-billing";
    let summary = primary_summary(consumer, proxy, 200);

    // The real 50% sampler starts with a miss and then a selection. Translate
    // those decisions into the receiver presence that log_with_mirror sees.
    let missed = request_mirror_should_mirror_for_test(&sampler);
    let selected = request_mirror_should_mirror_for_test(&sampler);
    assert!(!missed, "first 50% sample must be the deterministic miss");
    assert!(selected, "second 50% sample must be selected");
    drive_log_with_mirror(&plugins, &summary, missed.then(|| mirror_success(200))).await;
    drive_log_with_mirror(&plugins, &summary, selected.then(|| mirror_success(200))).await;

    assert_eq!(total_http_calls(consumer, proxy), 2);
    assert_eq!(total_http_bytes(consumer, proxy), (64, 128));
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn sink_per_event_exports_exactly_one_charge_across_mirror_outcomes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let config = sink_pricing_config(temp.path(), "per_event", &server.uri());
    let plugin = Arc::new(
        ApiChargebackSink::new_with_config_id(
            &config,
            PluginHttpClient::default(),
            "ferrum",
            Some("mirror-billing-per-event"),
        )
        .unwrap(),
    );
    plugin.start_background_tasks().expect("stage sink");
    plugin.commit_background_tasks();
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];

    // Success with differing statuses.
    drive_log_with_mirror(
        &plugins,
        &primary_summary("sink-per-event-success", "proxy-sink-per-event", 200),
        Some(mirror_success(500)),
    )
    .await;
    let first = wait_for_requests(&server, 1).await;
    assert_eq!(first.len(), 1);
    let body: Value = first[0].body_json().unwrap();
    assert_eq!(body["consumer_id"], "sink-per-event-success");
    assert_eq!(body["status_code"], 200);
    assert_eq!(body["call_count"], 1);

    // Error mirror must not enqueue a second event for a new primary.
    drive_log_with_mirror(
        &plugins,
        &primary_summary("sink-per-event-error", "proxy-sink-per-event", 200),
        Some(mirror_error()),
    )
    .await;
    let both = wait_for_requests(&server, 2).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let final_requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(
        final_requests.len(),
        2,
        "mirror summaries must not enqueue additional charge events; got {}",
        final_requests.len()
    );
    let second: Value = both[1].body_json().unwrap();
    assert_eq!(second["consumer_id"], "sink-per-event-error");
    assert_eq!(second["status_code"], 200);
    assert_eq!(second["call_count"], 1);

    // percentage < 100%: unselected request (no mirror rx) still one event.
    drive_log_with_mirror(
        &plugins,
        &primary_summary("sink-per-event-pct-miss", "proxy-sink-per-event", 200),
        None,
    )
    .await;
    let three = wait_for_requests(&server, 3).await;
    assert_eq!(three.len(), 3);
    drop(plugin);
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn sink_snapshot_records_exactly_one_charge_across_mirror_outcomes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let config = sink_pricing_config(temp.path(), "snapshot", &server.uri());
    let plugin = Arc::new(
        ApiChargebackSink::new_with_config_id(
            &config,
            PluginHttpClient::default(),
            "ferrum",
            Some("mirror-billing-snapshot"),
        )
        .unwrap(),
    );
    plugin.start_background_tasks().expect("stage sink");
    plugin.commit_background_tasks();
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let accumulator = api_chargeback_sink_snapshot_accumulator_for_test(&plugin)
        .expect("snapshot mode must activate an accumulator");

    drive_log_with_mirror(
        &plugins,
        &primary_summary("sink-snap-success", "proxy-sink-snap", 200),
        Some(mirror_success(500)),
    )
    .await;

    drive_log_with_mirror(
        &plugins,
        &primary_summary("sink-snap-error", "proxy-sink-snap", 200),
        Some(mirror_error()),
    )
    .await;

    // percentage miss: primary only.
    drive_log_with_mirror(
        &plugins,
        &primary_summary("sink-snap-pct-miss", "proxy-sink-snap", 200),
        None,
    )
    .await;

    let mut export_config = ApiChargebackSinkConfig {
        mode: ferrum_edge::plugins::api_chargeback_sink::SinkMode::Snapshot,
        ..Default::default()
    };
    export_config.currency = "USD".to_string();
    export_config.pricing_version = "mirror-billing-v1".to_string();

    let mut events = accumulator
        .compute_deltas(&export_config, "node-a", 100, "snap-mirror-billing")
        .expect("snapshot deltas");
    events.sort_by(|left, right| left.consumer_id.cmp(&right.consumer_id));
    assert_eq!(
        events.len(),
        3,
        "exactly one snapshot row per primary client request"
    );
    assert!(events.iter().all(|event| {
        event.call_count == 1
            && event.status_code == 200
            && event.bytes_sent == 32
            && event.bytes_received == 64
    }));
    assert_eq!(events[0].consumer_id, "sink-snap-error");
    assert_eq!(events[1].consumer_id, "sink-snap-pct-miss");
    assert_eq!(events[2].consumer_id, "sink-snap-success");

    // A second delta emit must not invent mirror-inflated charges.
    let second = accumulator
        .compute_deltas(&export_config, "node-a", 200, "snap-mirror-billing-2")
        .expect("second snapshot deltas");
    assert!(
        second.is_empty(),
        "mirror traffic must not create further snapshot charge deltas"
    );

    drop(plugin);
}
