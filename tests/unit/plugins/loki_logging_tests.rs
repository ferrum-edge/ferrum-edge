//! Tests for loki_logging plugin

use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Plugin, PluginHttpClient,
    loki_logging::{
        LOKI_DEFAULT_BUFFER_MAX_BYTES, LOKI_DEFAULT_MAX_ENTRY_BYTES, LOKI_LOGGING_CONFIG_KEYS,
        LOKI_MAX_CUSTOM_HEADER_NAME_BYTES, LokiLogging,
    },
};
use serde_json::json;
use std::io::{self, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing_subscriber::fmt::MakeWriter;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::plugin_utils::{
    create_test_stream_transaction_summary, create_test_transaction_summary,
    read_http11_request_headers,
};

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

#[derive(Clone, Default)]
struct SharedWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl SharedWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap_or_default()
    }
}

struct SharedGuard {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for SharedGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedWriter {
    type Writer = SharedGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedGuard {
            buffer: Arc::clone(&self.buffer),
        }
    }
}

fn delivery_config(endpoint_url: String) -> serde_json::Value {
    json!({
        "endpoint_url": endpoint_url,
        "batch_size": 1,
        "flush_interval_ms": 100,
        "max_retries": 0,
        "retry_delay_ms": 1,
        "gzip": false
    })
}

async fn wait_for_requests(server: &MockServer, expected: usize) -> Vec<wiremock::Request> {
    for _ in 0..100 {
        if let Some(requests) = server.received_requests().await
            && requests.len() >= expected
        {
            return requests;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("Loki mock did not receive {expected} requests in time");
}

#[tokio::test]
async fn test_loki_logging_plugin_creation() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://localhost:3100/loki/api/v1/push"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "loki_logging");
    assert_eq!(plugin.priority(), 9155);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    assert_eq!(plugin.warmup_hostnames(), vec!["localhost".to_string()]);
}

#[tokio::test]
async fn test_loki_logging_plugin_creation_empty_config() {
    let result = LokiLogging::new(&json!({}), default_client());
    match result {
        Err(e) => assert!(
            e.contains("endpoint_url"),
            "Expected error about endpoint_url, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err when creating loki_logging without endpoint_url"),
    }
}

#[tokio::test]
async fn test_loki_logging_rejects_malformed_endpoint_url() {
    let result = LokiLogging::new(
        &json!({
            "endpoint_url": "not a valid url"
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("invalid 'endpoint_url'")),
        Ok(_) => panic!("Expected malformed endpoint_url to be rejected"),
    }
}

#[tokio::test]
async fn test_loki_logging_rejects_non_http_scheme() {
    let result = LokiLogging::new(
        &json!({
            "endpoint_url": "tcp://127.0.0.1:3100/loki"
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("http:// or https://")),
        Ok(_) => panic!("Expected non-http endpoint_url to be rejected"),
    }
}

#[tokio::test]
async fn test_loki_logging_rejects_invalid_config_shapes() {
    let cases = [
        json!(null),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "gzip": "true"}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "labels": []}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "labels": {"bad-label": "value"}}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "labels": {"env": 1}}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "include_proxy_id_label": "false"}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "include_listen_path_label": []}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "include_status_class_label": 1}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "custom_headers": []}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "custom_headers": {"X-Scope-OrgID": 1}}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "custom_headers": {"Bad Header": "value"}}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "custom_headers": {"X-Bad": "bad\u{0001}value"}}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "authorization_header": ""}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "authorization_header": " Bearer token"}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "authorization_header": "Bearer token\t"}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "authorization_header": 123}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "authorization_header": "bad\u{0001}value"}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "batch_size": "100"}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "flush_interval_ms": false}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "buffer_capacity": -1}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "max_retries": []}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "retry_delay_ms": {}}),
    ];

    for config in cases {
        assert!(
            LokiLogging::new(&config, default_client()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_loki_logging_strict_config_admission_and_bounds() {
    let endpoint = "http://127.0.0.1:1/loki/api/v1/push";
    for key in LOKI_LOGGING_CONFIG_KEYS {
        let mut config = json!({"endpoint_url": endpoint});
        config
            .as_object_mut()
            .unwrap()
            .insert((*key).to_string(), serde_json::Value::Null);
        assert!(
            LokiLogging::new(&config, default_client()).is_err(),
            "explicit null must be rejected for {key}"
        );
    }

    for config in [
        json!({"endpoint_url": endpoint, "endpont_url": endpoint}),
        json!({"endpoint_url": endpoint, "batch_size": 0}),
        json!({"endpoint_url": endpoint, "batch_size": 10001}),
        json!({"endpoint_url": endpoint, "buffer_capacity": 1000001}),
        json!({"endpoint_url": endpoint, "flush_interval_ms": 99}),
        json!({"endpoint_url": endpoint, "max_retries": 11}),
        json!({"endpoint_url": endpoint, "retry_delay_ms": 0}),
        json!({"endpoint_url": endpoint, "max_entry_bytes": 1023}),
        json!({"endpoint_url": endpoint, "buffer_max_bytes": 1023}),
        json!({
            "endpoint_url": endpoint,
            "max_entry_bytes": 2048,
            "buffer_max_bytes": 1024
        }),
        json!({"endpoint_url": endpoint, "labels": {"__tenant": "x"}}),
        json!({"endpoint_url": endpoint, "labels": {"ferrum_emitter": "x"}}),
    ] {
        assert!(
            LokiLogging::new(&config, default_client()).is_err(),
            "strict config must be rejected: {config}"
        );
    }

    let oversized_header_name = "x".repeat(LOKI_MAX_CUSTOM_HEADER_NAME_BYTES + 1);
    let mut oversized_headers = serde_json::Map::new();
    oversized_headers.insert(oversized_header_name, json!("value"));
    let oversized_header_config = json!({
        "endpoint_url": endpoint,
        "custom_headers": oversized_headers
    });
    assert!(LokiLogging::new(&oversized_header_config, default_client()).is_err());

    let valid = json!({
        "endpoint_url": "HTTP://127.0.0.1:1/loki/api/v1/push",
        "max_entry_bytes": LOKI_DEFAULT_MAX_ENTRY_BYTES,
        "buffer_max_bytes": LOKI_DEFAULT_BUFFER_MAX_BYTES,
        "labels": {"tenant_name": "dynamic-value"},
        "custom_headers": {"X-Scope-OrgID": "dynamic-tenant"}
    });
    assert!(LokiLogging::new(&valid, default_client()).is_ok());
}

#[tokio::test]
async fn test_loki_logging_rejects_static_labels_that_exhaust_entry_budget() {
    let labels = (0..40)
        .map(|index| (format!("label_{index}"), json!("x".repeat(2048))))
        .collect::<serde_json::Map<_, _>>();
    let result = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/loki/api/v1/push",
            "labels": labels,
        }),
        default_client(),
    );

    let error = result
        .err()
        .expect("labels that leave no entry budget must be rejected");
    assert!(error.contains("minimum serialized HTTP and stream entry"));
}

fn entry_budget_config(
    max_entry_bytes: usize,
    include_proxy_id_label: bool,
    include_status_class_label: bool,
) -> serde_json::Value {
    entry_budget_config_for(
        "http://127.0.0.1:1/loki/api/v1/push",
        max_entry_bytes,
        include_proxy_id_label,
        include_status_class_label,
    )
}

fn entry_budget_config_for(
    endpoint_url: &str,
    max_entry_bytes: usize,
    include_proxy_id_label: bool,
    include_status_class_label: bool,
) -> serde_json::Value {
    json!({
        "endpoint_url": endpoint_url,
        "labels": {"service": "x".repeat(2048)},
        "include_proxy_id_label": include_proxy_id_label,
        "include_status_class_label": include_status_class_label,
        "max_entry_bytes": max_entry_bytes,
        "buffer_max_bytes": 8192,
        "gzip": false,
    })
}

fn minimum_accepted_entry_budget(
    include_proxy_id_label: bool,
    include_status_class_label: bool,
) -> usize {
    let mut rejected = 1023_usize;
    let mut accepted = 4096_usize;
    assert!(
        LokiLogging::new(
            &entry_budget_config(accepted, include_proxy_id_label, include_status_class_label,),
            default_client(),
        )
        .is_ok(),
        "upper test boundary must fit the minimum entry"
    );

    while accepted - rejected > 1 {
        let candidate = rejected + (accepted - rejected) / 2;
        if LokiLogging::new(
            &entry_budget_config(
                candidate,
                include_proxy_id_label,
                include_status_class_label,
            ),
            default_client(),
        )
        .is_ok()
        {
            accepted = candidate;
        } else {
            rejected = candidate;
        }
    }
    accepted
}

#[tokio::test]
async fn test_loki_logging_entry_budget_exact_boundary_includes_dynamic_labels() {
    let without_optional_labels = minimum_accepted_entry_budget(false, false);
    let with_status_class = minimum_accepted_entry_budget(false, true);
    let with_default_labels = minimum_accepted_entry_budget(true, true);

    // service key/value plus the fixed-width ferrum_emitter key/value. The
    // accepted boundary must reserve more than the static-label-only check.
    const STATIC_LABEL_BYTES: usize =
        "service".len() + 2048 + "ferrum_emitter".len() + (32 + 1 + 16);
    assert!(without_optional_labels > STATIC_LABEL_BYTES + 1);
    assert!(
        with_status_class > without_optional_labels,
        "enabled status_class must consume minimum entry budget"
    );
    assert!(
        with_default_labels > with_status_class,
        "enabled proxy_id must consume minimum entry budget"
    );

    for (minimum, include_proxy_id, include_status_class) in [
        (without_optional_labels, false, false),
        (with_status_class, false, true),
        (with_default_labels, true, true),
    ] {
        let error = LokiLogging::new(
            &entry_budget_config(minimum - 1, include_proxy_id, include_status_class),
            default_client(),
        )
        .err()
        .expect("one byte below the minimum retained size must be rejected");
        assert!(error.contains("minimum serialized HTTP and stream entry"));
        assert!(
            LokiLogging::new(
                &entry_budget_config(minimum, include_proxy_id, include_status_class),
                default_client(),
            )
            .is_ok(),
            "the exact minimum retained size must be accepted"
        );
    }

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/loki/api/v1/push"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let plugin = LokiLogging::new(
        &entry_budget_config_for(
            &format!("{}/loki/api/v1/push", server.uri()),
            with_default_labels,
            true,
            true,
        ),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let proxy_id = "123e4567-e89b-12d3-a456-426614174000";
    let summary = ferrum_edge::plugins::TransactionSummary {
        namespace: "0".to_string(),
        timestamp_received: "1970-01-01T00:00:00+00:00".to_string(),
        client_ip: "::".to_string(),
        http_method: "A".to_string(),
        request_path: "/".to_string(),
        proxy_id: Some(proxy_id.to_string()),
        response_status_code: u16::MAX,
        ..Default::default()
    };
    plugin.log(&summary).await;

    let requests = wait_for_requests(&server, 1).await;
    let payload: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(payload["streams"][0]["stream"]["proxy_id"], proxy_id);
    assert_eq!(payload["streams"][0]["stream"]["status_class"], "other");
}

#[tokio::test]
async fn test_loki_logging_rejects_url_userinfo_without_echoing_credentials() {
    let secret = "userinfo-secret-canary";
    let result = LokiLogging::new(
        &json!({
            "endpoint_url": format!("https://operator:{secret}@logs.example.com/loki/api/v1/push")
        }),
        default_client(),
    );
    let error = result.err().expect("URL user information must be rejected");
    assert!(error.contains("must not contain user information"));
    assert!(
        !error.contains(secret),
        "config error leaked URL credential: {error}"
    );
}

#[tokio::test]
async fn test_loki_timestamps_are_strictly_monotonic_within_and_across_batches() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/loki/api/v1/push"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": format!("{}/loki/api/v1/push", server.uri()),
            "batch_size": 2,
            "flush_interval_ms": 10000,
            "max_retries": 0,
            "retry_delay_ms": 1,
            "gzip": false
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let source_timestamps = [
        "2026-07-15T12:00:04Z",
        "2026-07-15T12:00:03Z",
        "2026-07-15T12:00:02Z",
        "2026-07-15T12:00:01Z",
    ];
    for timestamp in source_timestamps {
        let mut summary = create_test_transaction_summary();
        summary.timestamp_received = timestamp.to_string();
        plugin.log(&summary).await;
    }

    let requests = wait_for_requests(&server, 2).await;
    let mut outer = Vec::new();
    let mut inner = Vec::new();
    let mut emitter = None;
    for request in requests.iter().take(2) {
        let payload: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let streams = payload["streams"].as_array().unwrap();
        assert_eq!(streams.len(), 1);
        let stream_emitter = streams[0]["stream"]["ferrum_emitter"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            emitter.get_or_insert(stream_emitter.clone()),
            &stream_emitter
        );
        for value in streams[0]["values"].as_array().unwrap() {
            outer.push(value[0].as_str().unwrap().parse::<u64>().unwrap());
            let line: serde_json::Value = serde_json::from_str(value[1].as_str().unwrap()).unwrap();
            inner.push(line["timestamp_received"].as_str().unwrap().to_string());
        }
    }
    assert!(outer.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        inner,
        source_timestamps
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_loki_overlapping_plugin_generations_use_distinct_emitter_stream_labels() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/loki/api/v1/push"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let config = delivery_config(format!("{}/loki/api/v1/push", server.uri()));
    // Cache swaps can leave the prior generation alive for in-flight requests
    // while the replacement starts flushing. They must not share a timestamp
    // domain or a Loki stream even when their operator config is identical.
    let first = LokiLogging::new(&config, default_client()).unwrap();
    let second = LokiLogging::new(&config, default_client()).unwrap();
    first.log(&create_test_transaction_summary()).await;
    second.log(&create_test_transaction_summary()).await;

    let requests = wait_for_requests(&server, 2).await;
    let emitters = requests
        .iter()
        .take(2)
        .map(|request| {
            let payload: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            payload["streams"][0]["stream"]["ferrum_emitter"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(emitters.len(), 2);
}

#[tokio::test]
async fn test_loki_stream_disconnects_keep_source_time_in_line_and_emit_in_queue_order() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/loki/api/v1/push"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": format!("{}/loki/api/v1/push", server.uri()),
            "batch_size": 2,
            "flush_interval_ms": 10000,
            "max_retries": 0,
            "retry_delay_ms": 1,
            "gzip": false
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut first = create_test_stream_transaction_summary();
    first.timestamp_disconnected = "2026-07-15T12:00:02Z".to_string();
    let mut second = first.clone();
    second.timestamp_disconnected = "2026-07-15T12:00:01Z".to_string();
    plugin.on_stream_disconnect(&first).await;
    plugin.on_stream_disconnect(&second).await;

    let requests = wait_for_requests(&server, 1).await;
    let payload: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let values = payload["streams"][0]["values"].as_array().unwrap();
    assert_eq!(values.len(), 2);
    let outer = values
        .iter()
        .map(|value| value[0].as_str().unwrap().parse::<u64>().unwrap())
        .collect::<Vec<_>>();
    assert!(outer[0] < outer[1]);
    let inner = values
        .iter()
        .map(|value| {
            let line: serde_json::Value = serde_json::from_str(value[1].as_str().unwrap()).unwrap();
            line["timestamp_disconnected"].as_str().unwrap().to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        inner,
        vec![
            "2026-07-15T12:00:02Z".to_string(),
            "2026-07-15T12:00:01Z".to_string()
        ]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_loki_status_260_is_terminal_and_diagnostics_are_redacted() {
    let writer = SharedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);

    let server = MockServer::start().await;
    let response_secret = "blocked-body-secret-canary";
    let mut oversized_response = response_secret.as_bytes().to_vec();
    oversized_response.resize(1024 * 1024 + 1, b'x');
    Mock::given(method("POST"))
        .and(path("/private-path-secret/loki/api/v1/push"))
        .respond_with(ResponseTemplate::new(260).set_body_bytes(oversized_response))
        .mount(&server)
        .await;
    let query_secret = "query-secret-canary";
    let header_secret = "header-secret-canary";
    let auth_secret = "auth-secret-canary";
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": format!(
                "{}/private-path-secret/loki/api/v1/push?tenant={query_secret}",
                server.uri()
            ),
            "authorization_header": format!("Bearer {auth_secret}"),
            "custom_headers": {"X-Scope-OrgID": header_secret},
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 2,
            "retry_delay_ms": 1,
            "gzip": false
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    plugin.log(&create_test_transaction_summary()).await;
    wait_for_requests(&server, 1).await;
    for _ in 0..100 {
        if writer.contents().contains("status 260") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        1,
        "status 260 must not retry"
    );
    drop(plugin);
    drop(guard);

    let logs = writer.contents();
    assert!(logs.contains("status 260"));
    for secret in [
        response_secret,
        "private-path-secret",
        query_secret,
        header_secret,
        auth_secret,
    ] {
        assert!(
            !logs.contains(secret),
            "Loki diagnostic leaked {secret}: {logs}"
        );
    }
}

#[tokio::test]
async fn test_loki_retries_408_429_and_5xx() {
    for first_status in [408_u16, 429_u16, 503_u16] {
        let server = MockServer::start().await;
        let calls = Arc::new(AtomicUsize::new(0));
        Mock::given(method("POST"))
            .and(path("/loki/api/v1/push"))
            .respond_with({
                let calls = Arc::clone(&calls);
                move |_: &wiremock::Request| {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        ResponseTemplate::new(first_status)
                    } else {
                        ResponseTemplate::new(204)
                    }
                }
            })
            .mount(&server)
            .await;
        let mut config = delivery_config(format!("{}/loki/api/v1/push", server.uri()));
        config["max_retries"] = json!(1);
        let plugin = LokiLogging::new(&config, default_client()).unwrap();
        plugin.start_background_tasks().expect("live start");
        plugin.commit_background_tasks();
        plugin.log(&create_test_transaction_summary()).await;
        wait_for_requests(&server, 2).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_loki_accepts_empty_200_but_rejects_nonempty_200_without_retry() {
    let writer = SharedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);

    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/loki/api/v1/push"))
        .respond_with({
            let calls = Arc::clone(&calls);
            move |_: &wiremock::Request| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(200)
                } else {
                    ResponseTemplate::new(200).set_body_string("not accepted")
                }
            }
        })
        .mount(&server)
        .await;
    let mut config = delivery_config(format!("{}/loki/api/v1/push", server.uri()));
    config["max_retries"] = json!(2);
    let plugin = LokiLogging::new(&config, default_client()).unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    plugin.log(&create_test_transaction_summary()).await;
    wait_for_requests(&server, 1).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    plugin.log(&create_test_transaction_summary()).await;
    wait_for_requests(&server, 2).await;
    for _ in 0..100 {
        if writer.contents().contains("unexpected non-empty response") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        2,
        "neither successful 200 response should retry"
    );
    drop(plugin);
    drop(guard);

    let logs = writer.contents();
    assert!(logs.contains("unexpected non-empty response"));
    assert_eq!(
        logs.matches("returned status 200").count(),
        1,
        "the empty 200 must be delivered while the non-empty 200 is terminal: {logs}"
    );
}

#[tokio::test]
async fn test_loki_committed_204_drain_anomaly_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/loki/api/v1/push"))
        .respond_with(ResponseTemplate::new(204).set_body_bytes(vec![b'x'; 1024 * 1024 + 1]))
        .mount(&server)
        .await;
    let mut config = delivery_config(format!("{}/loki/api/v1/push", server.uri()));
    config["max_retries"] = json!(2);
    let plugin = LokiLogging::new(&config, default_client()).unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    plugin.log(&create_test_transaction_summary()).await;
    wait_for_requests(&server, 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        1,
        "a received 204 is committed even when its bounded drain is anomalous"
    );
}

#[tokio::test]
async fn test_loki_gzip_body_and_header_are_reused_across_retry() {
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/loki/api/v1/push"))
        .respond_with({
            let calls = Arc::clone(&calls);
            move |_: &wiremock::Request| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(503)
                } else {
                    ResponseTemplate::new(204)
                }
            }
        })
        .mount(&server)
        .await;
    let mut config = delivery_config(format!("{}/loki/api/v1/push", server.uri()));
    config["gzip"] = json!(true);
    config["max_retries"] = json!(1);
    let plugin = LokiLogging::new(&config, default_client()).unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut summary = create_test_transaction_summary();
    summary.request_path = "/gzip-retry-canary".to_string();
    plugin.log(&summary).await;

    let requests = wait_for_requests(&server, 2).await;
    for request in requests.iter().take(2) {
        assert_eq!(
            request
                .headers
                .get("content-encoding")
                .and_then(|value| value.to_str().ok()),
            Some("gzip")
        );
    }
    assert_eq!(
        requests[0].body.as_slice(),
        requests[1].body.as_slice(),
        "retry must reuse the exact serialized and compressed bytes"
    );

    let mut decoder = flate2::read::GzDecoder::new(requests[0].body.as_slice());
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
    let line: serde_json::Value =
        serde_json::from_str(payload["streams"][0]["values"][0][1].as_str().unwrap()).unwrap();
    assert_eq!(line["request_path"], "/gzip-retry-canary");
}

#[tokio::test]
async fn test_loki_oversized_entry_is_dropped_before_a_small_entry_is_sent() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/loki/api/v1/push"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let mut config = delivery_config(format!("{}/loki/api/v1/push", server.uri()));
    config["max_entry_bytes"] = json!(16384);
    config["buffer_max_bytes"] = json!(32768);
    let plugin = LokiLogging::new(&config, default_client()).unwrap();
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let canary = "oversized-entry-secret-canary";
    let mut oversized = create_test_transaction_summary();
    oversized.request_path = format!("/{canary}/{}", "x".repeat(32768));
    plugin.log(&oversized).await;
    plugin.log(&create_test_transaction_summary()).await;

    let requests = wait_for_requests(&server, 1).await;
    assert_eq!(requests.len(), 1);
    let body = String::from_utf8(requests[0].body.to_vec()).unwrap();
    assert!(!body.contains(canary));
}

#[tokio::test]
async fn test_loki_retained_content_budget_bounds_buffered_entries() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/loki/api/v1/push"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": format!("{}/loki/api/v1/push", server.uri()),
            "batch_size": 1000,
            "flush_interval_ms": 60000,
            "buffer_capacity": 1000,
            "max_entry_bytes": 16384,
            "buffer_max_bytes": 16384,
            "max_retries": 0,
            "retry_delay_ms": 1,
            "gzip": false
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    for _ in 0..100 {
        plugin.log(&create_test_transaction_summary()).await;
    }
    drop(plugin);

    let requests = wait_for_requests(&server, 1).await;
    let payload: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let retained_entries = payload["streams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|stream| stream["values"].as_array().unwrap().len())
        .sum::<usize>();
    assert!(retained_entries > 0);
    assert!(
        retained_entries < 100,
        "byte budget must cap retained content independently of channel count"
    );
}

#[tokio::test]
async fn test_loki_retained_content_budget_is_released_after_delivery() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/loki/api/v1/push"))
        .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_millis(200)))
        .mount(&server)
        .await;
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": format!("{}/loki/api/v1/push", server.uri()),
            "batch_size": 1,
            "flush_interval_ms": 100,
            "buffer_capacity": 10,
            "max_entry_bytes": 4096,
            "buffer_max_bytes": 4096,
            "max_retries": 0,
            "retry_delay_ms": 1,
            "gzip": false
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let large_path = "x".repeat(1800);
    let mut first = create_test_transaction_summary();
    first.request_path = format!("/first-budget-canary/{large_path}");
    plugin.log(&first).await;
    wait_for_requests(&server, 1).await;

    let mut rejected_while_reserved = first.clone();
    rejected_while_reserved.request_path = format!("/rejected-budget-canary/{large_path}");
    plugin.log(&rejected_while_reserved).await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut admitted_after_release = first;
    admitted_after_release.request_path = format!("/released-budget-canary/{large_path}");
    plugin.log(&admitted_after_release).await;

    let requests = wait_for_requests(&server, 2).await;
    assert_eq!(requests.len(), 2);
    let lines = requests
        .iter()
        .take(2)
        .map(|request| {
            let payload: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            serde_json::from_str::<serde_json::Value>(
                payload["streams"][0]["values"][0][1].as_str().unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(lines.iter().any(|line| {
        line["request_path"]
            .as_str()
            .unwrap()
            .contains("first-budget-canary")
    }));
    assert!(lines.iter().any(|line| {
        line["request_path"]
            .as_str()
            .unwrap()
            .contains("released-budget-canary")
    }));
    assert!(lines.iter().all(|line| {
        !line["request_path"]
            .as_str()
            .unwrap()
            .contains("rejected-budget-canary")
    }));
}

#[tokio::test]
async fn test_loki_logging_with_authorization_header() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "authorization_header": "Bearer my-loki-token",
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    assert_eq!(plugin.name(), "loki_logging");

    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_loki_logging_with_custom_headers() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "custom_headers": {
                "X-Scope-OrgID": "tenant-1"
            },
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "loki_logging");
}

#[tokio::test]
async fn test_loki_logging_with_custom_labels() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "labels": {
                "service": "my-gateway",
                "env": "staging",
                "region": "us-east-1"
            },
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "loki_logging");

    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_loki_logging_gzip_disabled() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "gzip": false,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "loki_logging");
}

#[tokio::test]
async fn test_loki_logging_default_lifecycle_phases() {
    let plugin = LokiLogging::new(
        &json!({"endpoint_url": "http://127.0.0.1:1/unreachable"}),
        default_client(),
    )
    .unwrap();

    let mut ctx = ferrum_edge::plugins::RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_loki_logging_batch_config_defaults() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://localhost:3100/loki/api/v1/push"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "loki_logging");
}

#[tokio::test]
async fn test_loki_logging_custom_batch_config() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://localhost:3100/loki/api/v1/push",
            "batch_size": 200,
            "flush_interval_ms": 5000,
            "max_retries": 5,
            "retry_delay_ms": 2000,
            "buffer_capacity": 50000,
            "gzip": true
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    assert_eq!(plugin.name(), "loki_logging");
}

#[tokio::test]
async fn test_loki_logging_buffer_accepts_multiple_entries() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "batch_size": 50,
            "flush_interval_ms": 10000,
            "max_retries": 0,
            "buffer_capacity": 1000
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let summary = create_test_transaction_summary();
    for _ in 0..100 {
        plugin.log(&summary).await;
    }
}

#[tokio::test]
async fn test_loki_logging_buffer_full_drops_gracefully() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "batch_size": 1000,
            "flush_interval_ms": 60000,
            "max_retries": 0,
            "buffer_capacity": 5
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let summary = create_test_transaction_summary();
    for _ in 0..20 {
        plugin.log(&summary).await;
    }
}

#[tokio::test]
async fn test_loki_logging_unreachable_endpoint_graceful() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_loki_logging_stream_disconnect_does_not_panic() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let summary = create_test_stream_transaction_summary();

    plugin.on_stream_disconnect(&summary).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_loki_logging_label_options_disabled() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "include_proxy_id_label": false,
            "include_status_class_label": false,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();

    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_loki_logging_include_proxy_id_label_new_key() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "include_proxy_id_label": false,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
    // No panic, and the plugin accepts the new key. Full label-output
    // coverage lives in the build_http_labels tests below.
}

#[tokio::test]
async fn test_loki_logging_removed_listen_path_key_rejected() {
    let result = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "include_listen_path_label": false,
            "max_retries": 0
        }),
        default_client(),
    );
    let err = result.err().expect("removed key should be rejected");
    assert!(err.contains("include_listen_path_label"), "got: {err}");
}

async fn spawn_loki_keepalive_server(
    responses: Vec<(u16, &'static [u8])>,
) -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let connections_task = Arc::clone(&connections);
    let requests_task = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            connections_task.fetch_add(1, Ordering::SeqCst);
            let responses = responses.clone();
            let requests = Arc::clone(&requests_task);
            tokio::spawn(async move {
                let mut index = 0usize;
                loop {
                    if !read_http11_request_headers(&mut socket).await {
                        break;
                    }
                    requests.fetch_add(1, Ordering::SeqCst);
                    let (status, body) = responses[index % responses.len()];
                    index = index.saturating_add(1);
                    // 204 must not carry a body; advertise Content-Length: 0 only.
                    let headers = if status == 204 {
                        format!(
                            "HTTP/1.1 {status} No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                        )
                    } else {
                        format!(
                            "HTTP/1.1 {status} Status\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                            body.len()
                        )
                    };
                    if socket.write_all(headers.as_bytes()).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(15)).await;
                    if status != 204 && socket.write_all(body).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (
        format!("http://{addr}/loki/api/v1/push"),
        connections,
        requests,
    )
}

async fn wait_for_loki_count(counter: &AtomicUsize, expected: usize) {
    for _ in 0..100 {
        if counter.load(Ordering::SeqCst) >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "timed out waiting for {expected} Loki requests; saw {}",
        counter.load(Ordering::SeqCst)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_loki_reuses_http11_connection_across_successful_batches() {
    // Valid Loki success is 204 with an empty body; a 204+body fixture is
    // protocol-invalid and can poison keep-alive framing in hyper.
    let (endpoint, connections, requests) = spawn_loki_keepalive_server(vec![(204, b"")]).await;
    let mut config = delivery_config(endpoint);
    config["max_retries"] = json!(0);
    let plugin = LokiLogging::new(&config, default_client()).unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    plugin.log(&create_test_transaction_summary()).await;
    plugin.log(&create_test_transaction_summary()).await;
    wait_for_loki_count(&requests, 2).await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "loki_logging must drain ACK bodies through the shared helper and reuse HTTP/1.1"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_loki_reuses_http11_connection_across_retry() {
    let (endpoint, connections, requests) =
        spawn_loki_keepalive_server(vec![(503, b"no"), (204, b"")]).await;
    let mut config = delivery_config(endpoint);
    config["max_retries"] = json!(1);
    config["retry_delay_ms"] = json!(1);
    let plugin = LokiLogging::new(&config, default_client()).unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    plugin.log(&create_test_transaction_summary()).await;
    wait_for_loki_count(&requests, 2).await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "loki_logging must drain retryable bodies before reusing the pooled connection"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_loki_stalled_ack_drain_timeout_does_not_block_indefinitely() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    // Use 200 (not 204): hyper ignores bodies on 204, so a stalled 204 never
    // enters the shared drain timeout. A 200 + Content-Length body does.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let requests_task = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let requests = Arc::clone(&requests_task);
            tokio::spawn(async move {
                if !read_http11_request_headers(&mut socket).await {
                    return;
                }
                let n = requests.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    // Stall forever — drain timeout must free the flush worker.
                    tokio::time::sleep(Duration::from_secs(30)).await;
                } else {
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                }
            });
        }
    });
    let mut config = delivery_config(format!("http://{addr}/loki/api/v1/push"));
    config["max_retries"] = json!(0);
    let plugin = LokiLogging::new(&config, default_client()).unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    // Second request only arrives if the drain timeout unblocks the worker
    // instead of waiting out the peer's 30s stall.
    plugin.log(&create_test_transaction_summary()).await;
    plugin.log(&create_test_transaction_summary()).await;
    for _ in 0..250 {
        if requests.load(Ordering::SeqCst) >= 2 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "stalled Loki ACK must free the flush worker via the shared drain timeout; saw {} requests",
        requests.load(Ordering::SeqCst)
    );
}
