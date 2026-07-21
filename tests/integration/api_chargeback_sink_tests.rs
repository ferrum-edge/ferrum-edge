use std::collections::HashMap;

use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, TransactionSummary, api_chargeback_sink::ApiChargebackSink,
};
use serde_json::json;

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

#[tokio::test]
#[ignore = "requires FERRUM_CLICKHOUSE_TEST_URL pointing at a ClickHouse HTTP endpoint"]
async fn clickhouse_insert_round_trip_when_configured() {
    let Ok(clickhouse_url) = std::env::var("FERRUM_CLICKHOUSE_TEST_URL") else {
        eprintln!("skipping: FERRUM_CLICKHOUSE_TEST_URL is not set");
        return;
    };
    let client = reqwest::Client::new();
    let ddl = include_str!("../../migrations/clickhouse/0001_charges.sql");
    let ddl_response = client
        .post(clickhouse_url_with_query(
            &clickhouse_url,
            &[("multiquery", "1")],
        ))
        .body(ddl)
        .send()
        .await
        .expect("ClickHouse DDL request should send");
    assert!(
        ddl_response.status().is_success(),
        "DDL failed: {}",
        ddl_response.text().await.unwrap_or_default()
    );

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
    let mut metadata = HashMap::new();
    metadata.insert("request_id".to_string(), "it-request".to_string());
    let summary = TransactionSummary {
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
        mirror: false,
        metadata,
        ai_usage_export: None,
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
