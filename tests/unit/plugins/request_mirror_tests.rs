use ferrum_edge::_test_support::{
    request_mirror_append_shadow_host_suffix_for_test,
    request_mirror_max_retained_request_body_bytes_for_test,
    request_mirror_metrics_snapshot_for_test, request_mirror_resolve_timeout_ms_for_test,
    request_mirror_retained_request_body_bytes_for_test, request_mirror_sample_phase_for_test,
    request_mirror_sample_threshold_for_test, request_mirror_should_mirror_for_test,
};
use ferrum_edge::plugins::request_mirror::RequestMirror;
use ferrum_edge::plugins::{
    HTTP_GRPC_PROTOCOLS, MirrorResponseMeta, Plugin, PluginHttpClient, PluginResult,
    RequestContext, TransactionSummary, create_plugin,
    create_plugin_with_http_client_and_config_id, log_with_mirror, priority,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use super::plugin_utils;

fn make_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/users".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.query_params.insert("page".to_string(), "1".to_string());
    ctx
}

fn make_ctx_with_proxy() -> RequestContext {
    make_ctx_with_proxy_timeout(30_000)
}

fn make_ctx_with_proxy_timeout(backend_read_timeout_ms: u64) -> RequestContext {
    let mut ctx = make_ctx();
    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(json!({
        "id": "proxy-123",
        "name": "test-proxy",
        "listen_path": "/api",
        "backend_host": "backend.local",
        "backend_port": 8080,
        "backend_scheme": "http",
        "backend_read_timeout_ms": backend_read_timeout_ms
    }))
    .unwrap();
    ctx.matched_proxy = Some(Arc::new(proxy));
    ctx
}

struct CapturingMirrorLogger {
    summaries: Mutex<Vec<TransactionSummary>>,
}

#[async_trait::async_trait]
impl Plugin for CapturingMirrorLogger {
    fn name(&self) -> &str {
        "capturing_mirror_logger"
    }

    fn priority(&self) -> u16 {
        priority::STDOUT_LOGGING
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.summaries.lock().unwrap().push(summary.clone());
    }
}

#[tokio::test]
async fn test_mirror_result_logging_is_detached_from_primary_path() {
    let logger = Arc::new(CapturingMirrorLogger {
        summaries: Mutex::new(Vec::new()),
    });
    let plugins: Vec<Arc<dyn Plugin>> = vec![logger.clone()];
    let mut ctx = make_ctx();
    let (tx, rx) = tokio::sync::watch::channel(None);
    ctx.push_mirror_result_rx(rx);
    let summary = TransactionSummary {
        response_status_code: 200,
        ..TransactionSummary::default()
    };

    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        log_with_mirror(&plugins, &summary, &ctx),
    )
    .await
    .expect("primary logging must not wait for the mirror result");
    assert_eq!(logger.summaries.lock().unwrap().len(), 1);

    tx.send(Some(MirrorResponseMeta {
        mirror_plugin_id: Some("mirror-a".to_string()),
        mirror_target_url: "http://mirror.local:8080/api/users".to_string(),
        mirror_response_status_code: Some(204),
        mirror_response_size_bytes: Some(0),
        mirror_response_advertised_size_bytes: None,
        mirror_latency_ms: 250.0,
        mirror_error: None,
    }))
    .expect("detached mirror logger should retain its receiver");

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if logger.summaries.lock().unwrap().len() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached mirror summary was not logged");

    let summaries = logger.summaries.lock().unwrap();
    assert!(!summaries[0].mirror);
    assert!(summaries[1].mirror);
    assert_eq!(summaries[1].response_status_code, 204);
}

#[tokio::test]
async fn multiple_mirror_results_log_independently_in_completion_order() {
    let logger = Arc::new(CapturingMirrorLogger {
        summaries: Mutex::new(Vec::new()),
    });
    let plugins: Vec<Arc<dyn Plugin>> = vec![logger.clone()];
    let mut ctx = make_ctx();
    let mut publishers = Vec::new();
    for id in ["mirror-a", "mirror-b", "mirror-c"] {
        let (tx, rx) = tokio::sync::watch::channel(None);
        ctx.push_mirror_result_rx(rx);
        publishers.push((id, tx));
    }
    assert_eq!(ctx.mirror_result_rxs.len(), 3);
    assert_eq!(
        ctx.clone().mirror_result_rxs.len(),
        3,
        "detached deadline logging clones must preserve mirror receivers"
    );

    let summary = TransactionSummary {
        response_status_code: 200,
        ..TransactionSummary::default()
    };
    log_with_mirror(&plugins, &summary, &ctx).await;
    assert_eq!(logger.summaries.lock().unwrap().len(), 1);

    for (index, status, error) in [
        (2usize, None, Some("connection refused")),
        (0usize, Some(204u16), None),
        (1usize, Some(201u16), None),
    ] {
        let (id, tx) = &publishers[index];
        tx.send(Some(MirrorResponseMeta {
            mirror_plugin_id: Some((*id).to_string()),
            mirror_target_url: format!("http://{id}.example/shadow"),
            mirror_response_status_code: status,
            mirror_response_size_bytes: status.map(|_| 0),
            mirror_response_advertised_size_bytes: None,
            mirror_latency_ms: 1.0,
            mirror_error: error.map(str::to_string),
        }))
        .expect("detached collector must retain every receiver");
        tokio::task::yield_now().await;
    }

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if logger.summaries.lock().unwrap().len() == 4 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all three mirror summaries must be logged");

    let summaries = logger.summaries.lock().unwrap();
    let mut outcomes = summaries
        .iter()
        .filter(|entry| entry.mirror)
        .map(|entry| {
            (
                entry
                    .metadata
                    .get("mirror_plugin_id")
                    .cloned()
                    .expect("mirror instance id"),
                entry.response_status_code,
                entry.metadata.get("mirror_error").cloned(),
            )
        })
        .collect::<Vec<_>>();
    outcomes.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        outcomes,
        vec![
            ("mirror-a".to_string(), 204, None),
            ("mirror-b".to_string(), 201, None),
            (
                "mirror-c".to_string(),
                0,
                Some("connection refused".to_string())
            ),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn mirror_results_before_at_and_after_five_seconds_remain_observable() {
    let logger = Arc::new(CapturingMirrorLogger {
        summaries: Mutex::new(Vec::new()),
    });
    let plugins: Vec<Arc<dyn Plugin>> = vec![logger.clone()];
    let summary = TransactionSummary {
        response_status_code: 200,
        ..TransactionSummary::default()
    };

    let mut publishers = Vec::new();
    for (delay_seconds, proxy_timeout_ms, status) in
        [(4u64, 4_500u64, 204u16), (5, 5_500, 205), (6, 7_000, 206)]
    {
        let mut ctx = make_ctx_with_proxy_timeout(proxy_timeout_ms);
        let (tx, rx) = tokio::sync::watch::channel(None);
        ctx.push_mirror_result_rx(rx);
        log_with_mirror(&plugins, &summary, &ctx).await;
        publishers.push(tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(delay_seconds)).await;
            tx.send(Some(MirrorResponseMeta {
                mirror_plugin_id: Some(format!("mirror-{status}")),
                mirror_target_url: format!("http://mirror.local/result-{status}"),
                mirror_response_status_code: Some(status),
                mirror_response_size_bytes: Some(0),
                mirror_response_advertised_size_bytes: None,
                mirror_latency_ms: delay_seconds as f64 * 1000.0,
                mirror_error: None,
            }))
            .expect("detached result collector must remain subscribed");
        }));
    }

    let mirrored_statuses = || {
        logger
            .summaries
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| entry.mirror)
            .map(|entry| entry.response_status_code)
            .collect::<Vec<_>>()
    };

    // Let every publisher and detached result collector register its paused-
    // clock wait before advancing virtual time. Otherwise the first task may
    // not be polled until after the clock has already moved four seconds.
    tokio::task::yield_now().await;

    tokio::time::advance(std::time::Duration::from_secs(4)).await;
    for _ in 0..100 {
        if !mirrored_statuses().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(mirrored_statuses(), vec![204]);

    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    for _ in 0..100 {
        if mirrored_statuses().len() >= 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(mirrored_statuses(), vec![204, 205]);

    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    for publisher in publishers {
        publisher.await.expect("mirror result publisher");
    }
    for _ in 0..100 {
        if mirrored_statuses().len() >= 3 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(mirrored_statuses(), vec![204, 205, 206]);
}

#[tokio::test]
async fn max_in_flight_drop_emits_explicit_mirror_result() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(204).set_delay(std::time::Duration::from_secs(30)))
        .mount(&server)
        .await;
    let server_url = url::Url::parse(&server.uri()).unwrap();
    let plugin = RequestMirror::new_with_config_id(
        &json!({
            "mirror_host": server_url.host_str().unwrap(),
            "mirror_port": server_url.port().unwrap(),
            "percentage": 100,
            "max_in_flight": 1,
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
        Some("saturated-mirror"),
    )
    .unwrap();

    let mut first = make_ctx_with_proxy_timeout(30_000);
    let mut first_headers = HashMap::new();
    plugin_utils::assert_continue(plugin.before_proxy(&mut first, &mut first_headers).await);

    let mut dropped = make_ctx_with_proxy_timeout(30_000);
    let mut dropped_headers = HashMap::new();
    plugin_utils::assert_continue(
        plugin
            .before_proxy(&mut dropped, &mut dropped_headers)
            .await,
    );
    let meta = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        dropped.collect_mirror_result(),
    )
    .await
    .expect("concurrency drop result must be immediately available")
    .expect("selected mirror drop must emit metadata");
    assert!(
        meta.mirror_error
            .as_deref()
            .is_some_and(|error| error.contains("max_in_flight")),
        "unexpected drop metadata: {meta:?}"
    );
    assert_eq!(
        meta.mirror_plugin_id.as_deref(),
        Some("saturated-mirror"),
        "saturation outcomes must remain attributable to the selected instance"
    );
}

#[tokio::test]
async fn configured_instances_append_results_while_sampled_out_instance_adds_none() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let server_url = url::Url::parse(&server.uri()).unwrap();
    let make_plugin = |id: &'static str, percentage: u64| {
        create_plugin_with_http_client_and_config_id(
            "request_mirror",
            &json!({
                "mirror_host": server_url.host_str().unwrap(),
                "mirror_port": server_url.port().unwrap(),
                "percentage": percentage,
                "mirror_request_body": false
            }),
            PluginHttpClient::default(),
            Some(id),
        )
        .unwrap()
        .expect("request_mirror plugin")
    };
    let mirror_a = make_plugin("mirror-a", 100);
    let sampled_out = make_plugin("mirror-sampled-out", 0);
    let mirror_b = make_plugin("mirror-b", 100);
    let mut ctx = make_ctx_with_proxy();
    let mut headers = HashMap::new();

    plugin_utils::assert_continue(mirror_a.before_proxy(&mut ctx, &mut headers).await);
    plugin_utils::assert_continue(sampled_out.before_proxy(&mut ctx, &mut headers).await);
    plugin_utils::assert_continue(mirror_b.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.mirror_result_rxs.len(),
        2,
        "only the two dispatched instances should allocate result slots"
    );

    let mut ids = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ctx.collect_mirror_results(),
    )
    .await
    .expect("both mirror requests must complete")
    .into_iter()
    .map(|result| result.mirror_plugin_id.expect("plugin config id"))
    .collect::<Vec<_>>();
    ids.sort();
    assert_eq!(ids, vec!["mirror-a".to_string(), "mirror-b".to_string()]);
}

#[tokio::test]
async fn closed_task_channel_returns_seeded_failure_result() {
    // Issue #2472 acceptance: mirror task cancellation / incomplete publish
    // stays observable through the seeded watch-channel fallback.
    let mut ctx = make_ctx_with_proxy();
    let fallback = MirrorResponseMeta {
        mirror_plugin_id: Some("cancelled-mirror".to_string()),
        mirror_target_url: "http://mirror.local/cancelled".to_string(),
        mirror_response_status_code: None,
        mirror_response_size_bytes: None,
        mirror_response_advertised_size_bytes: None,
        mirror_latency_ms: 0.0,
        mirror_error: Some("mirror task ended before publishing a result".to_string()),
    };
    let (tx, rx) = tokio::sync::watch::channel(Some(fallback));
    ctx.push_mirror_result_rx(rx);
    drop(tx);

    let meta = ctx
        .collect_mirror_result()
        .await
        .expect("seeded task failure must remain observable after sender closure");
    assert!(
        meta.mirror_error
            .as_deref()
            .is_some_and(|error| error.contains("ended before publishing"))
    );
}

#[tokio::test]
async fn backend_read_timeout_emits_explicit_mirror_error() {
    // Issue #2472 acceptance: mirror timeout remains observable via
    // `mirror_error` for the fire-and-forget task. Generic HTTP sink is
    // sufficient — the timeout is applied on the reqwest builder before
    // transport selection, so h2c/TLS companions inherit the same budget.
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(204).set_delay(std::time::Duration::from_secs(1)))
        .mount(&server)
        .await;
    let server_url = url::Url::parse(&server.uri()).unwrap();
    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": server_url.host_str().unwrap(),
            "mirror_port": server_url.port().unwrap(),
            "percentage": 100,
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = make_ctx_with_proxy_timeout(50);
    let mut headers = HashMap::new();
    plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let meta = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        ctx.collect_mirror_result(),
    )
    .await
    .expect("mirror request timeout outcome must be bounded")
    .expect("timed-out mirror must emit metadata");
    assert!(meta.mirror_response_status_code.is_none());
    assert!(
        meta.mirror_error.is_some(),
        "timeout must be explicit: {meta:?}"
    );
}

#[test]
fn test_mirror_summary_uses_its_own_terminal_outcome() {
    let mut primary = TransactionSummary {
        response_status_code: 200,
        body_completed: true,
        ..TransactionSummary::default()
    };
    primary
        .metadata
        .insert("request_protocol".to_string(), "grpc".to_string());
    primary
        .metadata
        .insert("grpc_status".to_string(), "14".to_string());
    primary
        .metadata
        .insert("grpc_message".to_string(), "primary failed".to_string());
    primary
        .metadata
        .insert("rejection_phase".to_string(), "primary".to_string());

    let successful_mirror = primary.as_mirror_entry(MirrorResponseMeta {
        mirror_plugin_id: Some("mirror-success".to_string()),
        mirror_target_url: "http://mirror.local:8080/api/users".to_string(),
        mirror_response_status_code: Some(204),
        mirror_response_size_bytes: Some(0),
        mirror_response_advertised_size_bytes: None,
        mirror_latency_ms: 10.0,
        mirror_error: None,
    });
    assert!(successful_mirror.grpc_status().is_none());
    assert!(!successful_mirror.is_terminal_failure());
    assert!(!successful_mirror.metadata.contains_key("grpc_message"));
    assert!(!successful_mirror.metadata.contains_key("rejection_phase"));
    assert_eq!(
        successful_mirror
            .metadata
            .get("mirror_plugin_id")
            .map(String::as_str),
        Some("mirror-success")
    );
    let successful_json = serde_json::to_value(&successful_mirror).unwrap();
    assert!(successful_json.get("grpc_status").is_none());

    primary
        .metadata
        .insert("grpc_status".to_string(), "0".to_string());
    primary.metadata.remove("rejection_phase");
    let failed_mirror = primary.as_mirror_entry(MirrorResponseMeta {
        mirror_plugin_id: Some("mirror-failure".to_string()),
        mirror_target_url: "http://mirror.local:8080/api/users".to_string(),
        mirror_response_status_code: None,
        mirror_response_size_bytes: None,
        mirror_response_advertised_size_bytes: None,
        mirror_latency_ms: 10.0,
        mirror_error: Some("connection refused".to_string()),
    });
    assert!(failed_mirror.grpc_status().is_none());
    assert!(failed_mirror.is_terminal_failure());
    assert_eq!(
        failed_mirror
            .metadata
            .get("mirror_error")
            .map(String::as_str),
        Some("connection refused")
    );
}

#[tokio::test]
async fn expired_grpc_deadline_does_not_suppress_transaction_logging() {
    let deadline_plugin = create_plugin("grpc_deadline", &json!({ "default_deadline_ms": 1 }))
        .unwrap()
        .unwrap();
    let logger = Arc::new(CapturingMirrorLogger {
        summaries: Mutex::new(Vec::new()),
    });
    let plugins: Vec<Arc<dyn Plugin>> = vec![deadline_plugin, logger.clone()];
    let mut ctx = make_ctx();
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    assert!(matches!(
        ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(&plugins, &mut ctx),
        PluginResult::Continue
    ));
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    log_with_mirror(&plugins, &TransactionSummary::default(), &ctx).await;

    assert_eq!(
        logger.summaries.lock().unwrap().len(),
        1,
        "client-visible deadline expiry must not suppress the gateway audit record"
    );
}

// ---------------------------------------------------------------------------
// Plugin metadata
// ---------------------------------------------------------------------------

#[test]
fn test_plugin_name() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "request_mirror");
}

#[test]
fn test_plugin_priority() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(plugin.priority(), priority::REQUEST_MIRROR);
}

#[test]
fn test_supported_protocols() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

#[test]
fn test_non_object_config_is_error() {
    let result = RequestMirror::new(&json!("bad"), PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("config must be an object"));
}

#[test]
fn test_missing_mirror_host_is_error() {
    let result = RequestMirror::new(&json!({}), PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("mirror_host"));
}

#[test]
fn test_blank_plugin_config_id_is_error() {
    let error = RequestMirror::new_with_config_id(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
        Some("  "),
    )
    .err()
    .expect("supplied plugin identity must fail closed when blank");
    assert!(
        error.contains("plugin_config_id"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_invalid_field_types_are_error() {
    for (config, expected) in [
        (
            json!({ "mirror_host": "mirror.local", "mirror_protocol": true }),
            "'mirror_protocol' must be a string",
        ),
        (
            json!({ "mirror_host": "mirror.local", "mirror_port": "8080" }),
            "'mirror_port' must be an unsigned integer",
        ),
        (
            json!({ "mirror_host": "mirror.local", "mirror_path": 42 }),
            "'mirror_path' must be a string",
        ),
        (
            json!({ "mirror_host": "mirror.local", "percentage": "50" }),
            "'percentage' must be a number",
        ),
        (
            json!({ "mirror_host": "mirror.local", "mirror_request_body": "true" }),
            "'mirror_request_body' must be a boolean",
        ),
        (
            json!({ "mirror_host": "mirror.local", "max_in_flight": "10" }),
            "'max_in_flight' must be an unsigned integer",
        ),
    ] {
        let err = RequestMirror::new(&config, PluginHttpClient::default())
            .err()
            .unwrap();
        assert!(err.contains(expected), "expected {expected}, got: {err}");
    }
}

#[test]
fn test_mirror_path_must_start_with_slash() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_path": "shadow" }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("must start with '/'"));
}

#[test]
fn test_mirror_path_rejects_query_and_fragment_syntax() {
    for mirror_path in ["/shadow?src=config", "/shadow#fragment"] {
        let error = RequestMirror::new(
            &json!({ "mirror_host": "mirror.local", "mirror_path": mirror_path }),
            PluginHttpClient::default(),
        )
        .err()
        .expect("query and fragment syntax must be rejected");
        assert!(
            error.contains("'mirror_path' must not contain a query or fragment"),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn test_empty_mirror_host_is_error() {
    let result = RequestMirror::new(&json!({ "mirror_host": "" }), PluginHttpClient::default());
    assert!(result.is_err());
}

#[test]
fn test_mirror_host_rejects_url_authority_and_path_material() {
    for mirror_host in [
        "http://mirror.local",
        "user@mirror.local",
        "mirror.local/path",
        "mirror.local?token=secret",
        "mirror.local#fragment",
        "mirror.local:8080",
        "bad host",
    ] {
        let result = RequestMirror::new(
            &json!({ "mirror_host": mirror_host }),
            PluginHttpClient::default(),
        );
        assert!(
            result.is_err(),
            "mirror_host should fail validation: {mirror_host}"
        );
    }
}

#[test]
fn test_invalid_protocol_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_protocol": "ftp" }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("mirror_protocol"));
}

#[test]
fn test_port_zero_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_port": 0 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("mirror_port"));
}

#[test]
fn test_port_too_large_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_port": 70000 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
}

#[test]
fn test_percentage_below_zero_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "percentage": -1.0 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("percentage"));
}

#[test]
fn test_percentage_above_100_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "percentage": 101.0 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
}

#[test]
fn test_max_in_flight_zero_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "max_in_flight": 0 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("max_in_flight"));
}

/// #3070: `max_in_flight` must be range-checked against a deployment-safe hard
/// cap before it reaches `tokio::sync::Semaphore::new`. Values between the cap
/// and Tokio's `MAX_PERMITS` (`usize::MAX >> 3`) still fit `usize` and pass the
/// nonzero check, but panic inside `Semaphore::new`. They must fail as ordinary
/// config errors instead, and the exact cap boundary must be accepted.
#[test]
fn max_in_flight_hard_cap_rejects_unsafe_values_without_panicking() {
    // Exactly at the documented cap (2^20) is accepted.
    let at_cap = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "max_in_flight": 1_048_576u64 }),
        PluginHttpClient::default(),
    );
    assert!(
        at_cap.is_ok(),
        "cap value must be accepted: {:?}",
        at_cap.err()
    );

    // One above the cap is rejected as a config error.
    let above_cap = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "max_in_flight": 1_048_577u64 }),
        PluginHttpClient::default(),
    );
    assert!(
        above_cap
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("max_in_flight")),
        "above-cap value must be rejected, got {:?}",
        above_cap.as_ref().err()
    );

    // A value past Tokio's MAX_PERMITS (usize::MAX >> 3 on 64-bit) would panic
    // Semaphore::new; it must be a config error, never a panic.
    let tokio_max_permits: u64 = (usize::MAX >> 3) as u64;
    let past_tokio_cap = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "max_in_flight": tokio_max_permits }),
        PluginHttpClient::default(),
    );
    assert!(
        past_tokio_cap
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("max_in_flight")),
        "value at/above Tokio MAX_PERMITS must be rejected, got {:?}",
        past_tokio_cap.as_ref().err()
    );

    // A value that overflows u64's usable range but still parses as u64.
    let huge = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "max_in_flight": u64::MAX }),
        PluginHttpClient::default(),
    );
    assert!(
        huge.as_ref()
            .err()
            .is_some_and(|e| e.contains("max_in_flight")),
        "u64::MAX must be rejected without panic, got {:?}",
        huge.as_ref().err()
    );
}

#[test]
fn max_in_flight_is_documented_across_source_guide_and_example() {
    // Regression for #2476: the runtime has accepted `max_in_flight`
    // (default 256, minimum 1) as the per-instance mirror concurrency bound
    // since it was introduced, and OpenAPI models it, but the source
    // configuration table, the public plugin guide, and the YAML example
    // omitted it. Keep every operator-facing surface aligned so the setting
    // cannot drift undocumented again.
    let source = include_str!("../../../src/plugins/request_mirror.rs");
    let guide = include_str!("../../../docs/plugins.md");
    let section = guide
        .split("### `request_mirror`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("request_mirror docs section");

    // The runtime default both tables document.
    assert!(source.contains("DEFAULT_MAX_IN_FLIGHT_MIRRORS: usize = 256"));
    assert!(
        source.contains("`max_in_flight` | u64 | `256`"),
        "source configuration table must document max_in_flight"
    );
    assert!(
        section.contains("`max_in_flight` | Integer | `256`"),
        "public parameter table must document max_in_flight"
    );
    // The guide's YAML example shows the field, and the guide records the
    // saturation contract: dropping a mirror attempt never affects the
    // primary request.
    assert!(
        section.contains("max_in_flight: 64"),
        "request_mirror YAML example must include max_in_flight"
    );
    assert!(section.contains("without affecting the primary request"));
    assert!(
        section.contains("h2c prior knowledge") && section.contains("ALPN `h2`"),
        "public guide must document gRPC mirror HTTP/2 transport selection"
    );
    assert!(
        source.contains("get_http2") && source.contains("is_native_grpc"),
        "source must select the HTTP/2 companion for native gRPC mirrors"
    );
    assert!(
        source.contains("`max_retained_request_body_bytes`")
            && section.contains("`max_retained_request_body_bytes`"),
        "retained-body budget must be documented in source and guide"
    );
    assert!(
        source.contains("`mirror_timeout_ms`") && section.contains("`mirror_timeout_ms`"),
        "finite mirror timeout must be documented in source and guide"
    );
    assert!(
        source.contains("`forward_sensitive_headers`")
            && section.contains("`forward_sensitive_headers`")
            && section.contains("forward_sensitive_header_allowlist"),
        "credential forwarding opt-in must be documented fail-closed"
    );
}

// ---------------------------------------------------------------------------
// Config defaults
// ---------------------------------------------------------------------------

#[test]
fn test_default_protocol_is_http() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    // Default port for http is 80 — verify via warmup hostname
    assert_eq!(plugin.warmup_hostnames(), vec!["mirror.local".to_string()]);
}

#[test]
fn test_default_port_for_https_is_443() {
    // If protocol is https and no port specified, default should be 443
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_protocol": "https" }),
        PluginHttpClient::default(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_default_percentage_is_100() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    // Default percentage = 100%, so requires_request_body_before_before_proxy follows mirror_request_body
    assert!(plugin.requires_request_body_before_before_proxy());
}

#[test]
fn test_mirror_request_body_default_true() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert!(plugin.requires_request_body_before_before_proxy());
}

#[test]
fn test_mirror_request_body_false_disables_buffering() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_request_body": false }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert!(!plugin.requires_request_body_before_before_proxy());
}

// ---------------------------------------------------------------------------
// DNS warmup
// ---------------------------------------------------------------------------

#[test]
fn test_warmup_hostnames() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "shadow.example.com" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["shadow.example.com".to_string()]
    );
}

#[test]
fn test_hostname_normalized_to_lowercase() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "MIRROR.Example.COM" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["mirror.example.com".to_string()]
    );
}

#[test]
fn test_warmup_hostnames_skips_ip_literals() {
    for host in ["127.0.0.1", "2001:db8::10", "[2001:db8::10]"] {
        let plugin =
            RequestMirror::new(&json!({ "mirror_host": host }), PluginHttpClient::default())
                .unwrap();
        assert!(
            plugin.warmup_hostnames().is_empty(),
            "IP literal {host} should not be DNS-warmed"
        );
    }
}

// ---------------------------------------------------------------------------
// before_proxy always returns Continue (fire-and-forget)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_before_proxy_returns_continue() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_port": 9999 }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-custom".to_string(), "value".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_mirror_never_forwards_load_testing_trigger_even_if_it_runs_first() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (captured_tx, captured_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 2048];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0, "mirror closed before completing request headers");
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let _ = captured_tx.send(String::from_utf8_lossy(&request).to_ascii_lowercase());
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "percentage": 100,
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = make_ctx_with_proxy();
    let mut headers = HashMap::new();
    headers.insert(
        "X-Loadtesting-Key".to_string(),
        "test-load-key-0123456789abcdef!!".to_string(),
    );
    headers.insert("X-Loadtesting-Fanout".to_string(), "1".to_string());
    headers.insert("x-keep".to_string(), "preserved".to_string());

    plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let _ = ctx.collect_mirror_result().await;
    let captured = tokio::time::timeout(std::time::Duration::from_secs(2), captured_rx)
        .await
        .expect("mirror request timeout")
        .expect("mirror capture task");
    assert!(
        !captured.contains("\r\nx-loadtesting-key:"),
        "the load-testing control secret reached the mirror: {captured}"
    );
    assert!(
        !captured.contains("\r\nx-loadtesting-fanout:"),
        "the load-testing one-hop marker reached the mirror: {captured}"
    );
    assert!(captured.contains("\r\nx-keep: preserved"));
}

#[tokio::test]
async fn test_before_proxy_with_zero_percentage_returns_continue() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "percentage": 0.0 }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_before_proxy_with_body_metadata() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_request_body": true }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.metadata
        .insert("request_body".to_string(), r#"{"name":"test"}"#.to_string());
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_before_proxy_with_matched_proxy_uses_proxy_timeout() {
    // Verify that before_proxy doesn't panic when a matched_proxy is present.
    // The actual timeout is applied inside the spawned task (fire-and-forget),
    // so we can only verify the plugin reads proxy config without errors.
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_before_proxy_without_matched_proxy_uses_default_timeout() {
    // When no proxy is matched (shouldn't happen in practice), the plugin
    // falls back to a 60s default timeout.
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx(); // No matched_proxy
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
}

// ---------------------------------------------------------------------------
// Percentage sampling (issue #2466)
// ---------------------------------------------------------------------------
//
// Selection is a deterministic Bresenham phase accumulator at 0.1% granularity.
// Tests below observe actual selection decisions via `should_mirror()` and via
// `ctx.mirror_result_rxs` (dispatch), never merely `PluginResult::Continue`.

const SAMPLE_PERIOD: u64 = 1000;

fn mirror_plugin(percentage: f64) -> RequestMirror {
    RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "percentage": percentage,
            "mirror_request_body": false,
            // Keep saturation from masking selection observations if a test
            // path does dispatch mirrors.
            "max_in_flight": 10_000u64,
        }),
        PluginHttpClient::default(),
    )
    .unwrap_or_else(|e| panic!("valid request_mirror config: {e}"))
}

fn collect_selections(plugin: &RequestMirror, n: usize) -> Vec<bool> {
    (0..n)
        .map(|_| request_mirror_should_mirror_for_test(plugin))
        .collect()
}

fn selection_count(selections: &[bool]) -> usize {
    selections.iter().filter(|selected| **selected).count()
}

fn selection_gaps(selections: &[bool]) -> Vec<usize> {
    let indices: Vec<usize> = selections
        .iter()
        .enumerate()
        .filter_map(|(i, selected)| selected.then_some(i))
        .collect();
    if indices.len() < 2 {
        return Vec::new();
    }
    indices.windows(2).map(|w| w[1] - w[0]).collect()
}

fn assert_exact_cycle_count(percentage: f64, expected_threshold: u64) {
    let plugin = mirror_plugin(percentage);
    assert_eq!(
        request_mirror_sample_threshold_for_test(&plugin),
        expected_threshold
    );
    assert_eq!(
        request_mirror_sample_phase_for_test(&plugin),
        0,
        "construction must start at phase 0"
    );
    let selections = collect_selections(&plugin, SAMPLE_PERIOD as usize);
    assert_eq!(
        selection_count(&selections) as u64,
        expected_threshold,
        "percentage {percentage}: expected exactly {expected_threshold} selections per {SAMPLE_PERIOD}-request cycle"
    );
    // A second cycle must match exactly as well (phase remains bounded).
    let selections2 = collect_selections(&plugin, SAMPLE_PERIOD as usize);
    assert_eq!(selection_count(&selections2) as u64, expected_threshold);
}

fn assert_gap_bounds(percentage: f64, expected_threshold: u64) {
    let plugin = mirror_plugin(percentage);
    // Two cycles so thresholds like 0.1% (one hit/cycle) still yield measurable gaps.
    let selections = collect_selections(&plugin, (SAMPLE_PERIOD * 2) as usize);
    assert_eq!(
        selection_count(&selections) as u64,
        expected_threshold * 2,
        "percentage {percentage}: expected exact long-run count over two cycles"
    );
    if expected_threshold == 0 || expected_threshold >= SAMPLE_PERIOD {
        return;
    }
    let gaps = selection_gaps(&selections);
    assert!(
        !gaps.is_empty(),
        "percentage {percentage}: need at least two selections to measure gaps"
    );
    let min_gap = (SAMPLE_PERIOD / expected_threshold) as usize;
    let max_gap = SAMPLE_PERIOD.div_ceil(expected_threshold) as usize;
    for gap in &gaps {
        assert!(
            *gap >= min_gap && *gap <= max_gap,
            "percentage {percentage}: gap {gap} outside [{min_gap}, {max_gap}]"
        );
    }
    // Must not be a contiguous prefix: the first selection is deferred until
    // the accumulator crosses SAMPLE_PERIOD (phase starts at 0).
    assert!(
        !selections[0],
        "percentage {percentage}: construction must not mirror the first request (no mirrored prefix)"
    );
}

#[test]
fn test_sampling_exact_counts_for_required_percentages() {
    assert_exact_cycle_count(0.0, 0);
    assert_exact_cycle_count(0.1, 1);
    assert_exact_cycle_count(1.0, 10);
    assert_exact_cycle_count(33.3, 333);
    assert_exact_cycle_count(50.0, 500);
    assert_exact_cycle_count(99.9, 999);
    assert_exact_cycle_count(100.0, 1000);
}

#[test]
fn test_sampling_gap_bounds_for_required_percentages() {
    for (percentage, threshold) in [
        (0.1, 1u64),
        (1.0, 10),
        (33.3, 333),
        (50.0, 500),
        (99.9, 999),
    ] {
        assert_gap_bounds(percentage, threshold);
    }
}

#[test]
fn test_sampling_zero_percent_never_selects() {
    let plugin = mirror_plugin(0.0);
    assert_eq!(request_mirror_sample_threshold_for_test(&plugin), 0);
    for _ in 0..(SAMPLE_PERIOD * 3) {
        assert!(!request_mirror_should_mirror_for_test(&plugin));
    }
    assert_eq!(
        request_mirror_sample_phase_for_test(&plugin),
        0,
        "0% must not advance the phase accumulator"
    );
}

#[test]
fn test_sampling_hundred_percent_always_selects() {
    let plugin = mirror_plugin(100.0);
    assert_eq!(
        request_mirror_sample_threshold_for_test(&plugin),
        SAMPLE_PERIOD
    );
    for _ in 0..(SAMPLE_PERIOD * 3) {
        assert!(request_mirror_should_mirror_for_test(&plugin));
    }
    assert_eq!(
        request_mirror_sample_phase_for_test(&plugin),
        0,
        "100% must not advance the phase accumulator"
    );
}

#[test]
fn test_sampling_is_evenly_spaced_not_contiguous_prefix() {
    // Regression for #2466: the old `(counter % 1000) < threshold` predicate
    // mirrored a contiguous prefix (e.g. first 10 of every 1000 at 1%).
    let plugin = mirror_plugin(1.0);
    let selections = collect_selections(&plugin, SAMPLE_PERIOD as usize);
    assert_eq!(selection_count(&selections), 10);
    let prefix_mirrors = selections[..10].iter().filter(|s| **s).count();
    assert!(
        prefix_mirrors < 10,
        "1% must not mirror a contiguous 10-request prefix; got {prefix_mirrors} mirrors in the first 10"
    );
    // Even spacing: every selection gap is exactly 100 for threshold 10.
    let gaps = selection_gaps(&selections);
    assert!(
        gaps.iter().all(|g| *g == 100),
        "1% gaps must be exactly 100, got {gaps:?}"
    );
}

#[test]
fn test_sampling_construction_and_reload_reset_phase_without_prefix_burst() {
    let first = mirror_plugin(50.0);
    assert_eq!(request_mirror_sample_phase_for_test(&first), 0);
    let first_cycle = collect_selections(&first, SAMPLE_PERIOD as usize);
    assert!(
        !first_cycle[0],
        "fresh instance must not open with a mirror"
    );
    assert_eq!(selection_count(&first_cycle), 500);

    // Simulate config reload: a new instance resets phase independently.
    let reloaded = mirror_plugin(50.0);
    assert_eq!(request_mirror_sample_phase_for_test(&reloaded), 0);
    let reload_cycle = collect_selections(&reloaded, SAMPLE_PERIOD as usize);
    assert_eq!(
        first_cycle, reload_cycle,
        "reload must reproduce the same evenly spaced sequence from phase 0"
    );
    assert!(
        !reload_cycle[0],
        "reload must not reopen with a mirrored prefix burst"
    );
    // Old contiguous-prefix behavior mirrored the first 500 requests at 50%.
    let prefix = reload_cycle[..500].iter().filter(|s| **s).count();
    assert!(
        prefix < 500,
        "reload must not mirror a contiguous 50% prefix; got {prefix}/500"
    );
}

#[test]
fn test_sampling_phase_stays_bounded_across_many_cycles() {
    let plugin = mirror_plugin(33.3);
    for _ in 0..(SAMPLE_PERIOD * 5) {
        let _ = request_mirror_should_mirror_for_test(&plugin);
        let phase = request_mirror_sample_phase_for_test(&plugin);
        assert!(
            phase < SAMPLE_PERIOD,
            "phase must remain in 0..{SAMPLE_PERIOD}, got {phase}"
        );
    }
}

#[test]
fn test_sampling_concurrent_calls_preserve_exact_cycle_count() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    let plugin = std::sync::Arc::new(mirror_plugin(50.0));
    let selected = std::sync::Arc::new(AtomicUsize::new(0));
    let total = SAMPLE_PERIOD as usize * 4;
    let threads = 8usize;
    assert_eq!(total % threads, 0);
    let per_thread = total / threads;

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let plugin = plugin.clone();
        let selected = selected.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..per_thread {
                if request_mirror_should_mirror_for_test(&plugin) {
                    selected.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for handle in handles {
        handle.join().expect("sampler thread");
    }

    assert_eq!(
        selected.load(Ordering::Relaxed) as u64,
        (total as u64 / SAMPLE_PERIOD) * request_mirror_sample_threshold_for_test(&plugin),
        "concurrent selection must preserve exact long-run counts"
    );
    assert!(request_mirror_sample_phase_for_test(&plugin) < SAMPLE_PERIOD);
}

#[tokio::test]
async fn test_sampling_dispatch_observes_selection_not_just_continue() {
    // 0%: before_proxy always Continues and must NOT arm a mirror result slot.
    let zero = mirror_plugin(0.0);
    for _ in 0..32 {
        let mut ctx = make_ctx();
        let mut headers = HashMap::new();
        plugin_utils::assert_continue(zero.before_proxy(&mut ctx, &mut headers).await);
        assert!(
            ctx.mirror_result_rxs.is_empty(),
            "0% must not dispatch a mirror"
        );
    }

    // 100%: every Continuance must arm the dispatch channel.
    let full = mirror_plugin(100.0);
    for _ in 0..8 {
        let mut ctx = make_ctx();
        let mut headers = HashMap::new();
        plugin_utils::assert_continue(full.before_proxy(&mut ctx, &mut headers).await);
        assert!(
            ctx.mirror_result_rxs.len() == 1,
            "100% must dispatch a mirror"
        );
    }

    // Sequence agreement: before_proxy dispatch must match should_mirror() for
    // the same fresh phase, observed via mirror_result_rxs (not merely Continue).
    // Use 1% over one cycle (10 dispatches) so the test stays light.
    let expected = collect_selections(&mirror_plugin(1.0), SAMPLE_PERIOD as usize);
    assert_eq!(selection_count(&expected), 10);
    assert!(
        expected[..10].iter().filter(|s| **s).count() < 10,
        "expected sequence must not be a contiguous prefix"
    );

    let plugin = mirror_plugin(1.0);
    let mut dispatched = 0usize;
    for (i, expect) in expected.iter().enumerate() {
        let mut ctx = make_ctx();
        let mut headers = HashMap::new();
        plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        let did_dispatch = !ctx.mirror_result_rxs.is_empty();
        assert_eq!(
            did_dispatch, *expect,
            "before_proxy dispatch diverged from should_mirror at index {i}"
        );
        if did_dispatch {
            dispatched += 1;
        }
    }
    assert_eq!(
        dispatched, 10,
        "dispatch path must preserve the exact 1% cycle count"
    );
}

// ---------------------------------------------------------------------------
// should_buffer_request_body
// ---------------------------------------------------------------------------

#[test]
fn test_should_buffer_request_body_when_body_mirroring_enabled() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_request_body": true }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let ctx = make_ctx();
    assert!(plugin.should_buffer_request_body(&ctx));
}

#[test]
fn test_should_not_buffer_request_body_when_body_mirroring_disabled() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_request_body": false }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let ctx = make_ctx();
    assert!(!plugin.should_buffer_request_body(&ctx));
}

// ---------------------------------------------------------------------------
// Valid configs with various options
// ---------------------------------------------------------------------------

#[test]
fn test_valid_config_with_all_options() {
    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": "shadow.internal",
            "mirror_port": 8443,
            "mirror_protocol": "https",
            "mirror_path": "/shadow/v2",
            "percentage": 25.5,
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_valid_config_minimal() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_percentage_boundary_zero() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "percentage": 0.0 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_percentage_boundary_100() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "percentage": 100.0 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_mirror_path_override() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_path": "/shadow" }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
}

#[tokio::test]
async fn test_backend_path_policy_mirror_uses_authorized_effective_path() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request_line = String::from_utf8_lossy(&request)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string();
        let _ = tx.send(request_line);
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "percentage": 100
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = make_ctx_with_proxy();
    ferrum_edge::_test_support::bind_authorized_backend_path_for_test(
        &mut ctx,
        "/allowed.Service/Rewritten",
    );
    let mut headers = HashMap::new();

    plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let _ = ctx.collect_mirror_result().await;

    let request_line = rx.await.expect("mirror request line");
    assert!(
        request_line.starts_with("POST /allowed.Service/Rewritten?"),
        "mirror must use the backend-effective authorized path, got {request_line:?}"
    );
    assert!(
        !request_line.contains("/api/users"),
        "mirror must not replay the unauthorized original path"
    );
}

#[tokio::test]
async fn mesh_shadow_uses_rewritten_authority_and_explicit_mirror_path_wins() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel::<String>(3);
    tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 2048];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            tx.send(String::from_utf8_lossy(&request).into_owned())
                .await
                .unwrap();
            let _ = stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        }
    });

    let route = create_plugin(
        "mesh_route_dispatch",
        &json!({
            "rules": [
                {
                    "match": {
                        "uri": {"exact": "/legacy"},
                        "methods": ["POST"]
                    },
                    "destination": {
                        "backend_host": "primary.internal",
                        "backend_port": 8080
                    },
                    "rewrite": {
                        "uri": "/exact-shadow",
                        "authority": "exact.internal"
                    }
                },
                {
                    "match": {
                        "uri": {"prefix": "/api"},
                        "methods": ["POST"]
                    },
                    "destination": {
                        "backend_host": "primary.internal",
                        "backend_port": 8080
                    },
                    "rewrite": {
                        "uri": "/mesh-rewritten",
                        "match_prefix": "/api",
                        "authority": "internal.example.com:8443"
                    }
                }
            ]
        }),
    )
    .unwrap()
    .unwrap();
    let route_mirror = RequestMirror::new_with_config_id(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "percentage": 100,
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
        Some("mesh-route-shadow"),
    )
    .unwrap();
    let explicit_mirror = RequestMirror::new_with_config_id(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_path": "/operator-shadow",
            "percentage": 100,
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
        Some("explicit-path-shadow"),
    )
    .unwrap();
    let mut ctx = make_ctx_with_proxy();
    let mut headers = HashMap::from([
        ("host".to_string(), "public.example.com".to_string()),
        ("content-type".to_string(), "application/json".to_string()),
    ]);

    plugin_utils::assert_continue(route.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/mesh-rewritten/users")
    );
    assert_eq!(
        ctx.route_override_authority.as_deref(),
        Some("internal.example.com:8443")
    );
    plugin_utils::assert_continue(route_mirror.before_proxy(&mut ctx, &mut headers).await);
    plugin_utils::assert_continue(explicit_mirror.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(ctx.mirror_result_rxs.len(), 2);

    let mut exact_ctx = make_ctx_with_proxy();
    exact_ctx.path = "/legacy".to_string();
    let mut exact_headers = HashMap::from([("host".to_string(), "public.example.com".to_string())]);
    plugin_utils::assert_continue(route.before_proxy(&mut exact_ctx, &mut exact_headers).await);
    assert_eq!(
        exact_ctx.route_override_path.as_deref(),
        Some("/exact-shadow")
    );
    assert_eq!(
        exact_ctx.route_override_authority.as_deref(),
        Some("exact.internal")
    );
    plugin_utils::assert_continue(
        route_mirror
            .before_proxy(&mut exact_ctx, &mut exact_headers)
            .await,
    );
    assert_eq!(exact_ctx.mirror_result_rxs.len(), 1);

    let requests = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let mut requests = Vec::new();
        while let Some(request) = rx.recv().await {
            requests.push(request);
            if requests.len() == 3 {
                break;
            }
        }
        requests
    })
    .await
    .expect("all three mirror requests must arrive");
    assert!(
        requests.iter().any(|request| {
            request.starts_with("POST /mesh-rewritten/users?page=1 HTTP/1.1\r\n")
        }),
        "an unset mirror_path must use the selected mesh route URI: {requests:?}"
    );
    assert!(
        requests
            .iter()
            .any(|request| request.starts_with("POST /operator-shadow?page=1 HTTP/1.1\r\n")),
        "explicit mirror_path must win over the mesh route rewrite: {requests:?}"
    );
    assert!(
        requests.iter().any(|request| {
            request.starts_with("POST /exact-shadow?page=1 HTTP/1.1\r\n")
                && request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("host: exact.internal-shadow"))
        }),
        "exact route rewrite must replace the whole path and shadow its bare authority: \
         {requests:?}"
    );
    assert!(
        requests
            .iter()
            .filter(|request| !request.starts_with("POST /exact-shadow"))
            .all(|request| {
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("host: internal.example.com-shadow:8443"))
            }),
        "each prefix-route mirror must carry the rewritten shadow authority: {requests:?}"
    );

    let mut ids = ctx
        .collect_mirror_results()
        .await
        .into_iter()
        .map(|meta| meta.mirror_plugin_id.expect("mirror plugin id"))
        .collect::<Vec<_>>();
    ids.sort();
    assert_eq!(
        ids,
        vec![
            "explicit-path-shadow".to_string(),
            "mesh-route-shadow".to_string()
        ]
    );
    let exact_ids = exact_ctx
        .collect_mirror_results()
        .await
        .into_iter()
        .map(|meta| meta.mirror_plugin_id.expect("mirror plugin id"))
        .collect::<Vec<_>>();
    assert_eq!(exact_ids, vec!["mesh-route-shadow".to_string()]);
}

// ---------------------------------------------------------------------------
// Mirror transaction summary serialization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mirror_captures_proxy_context() {
    // Verify that the plugin captures proxy context (proxy_id, proxy_name,
    // consumer_username) from the request context for mirror logging.
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_request_body": false }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    ctx.identified_consumer = Some(
        serde_json::from_value(json!({
            "id": "consumer-1",
            "username": "test-user"
        }))
        .unwrap(),
    );

    let mut headers: HashMap<String, String> = HashMap::new();

    // This fires the mirror task — we can't inspect the spawned task's output
    // directly, but we verify the plugin reads all context fields without panicking.
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
}

// === Binary body preservation ===

#[tokio::test]
async fn test_mirror_uses_binary_body_bytes_over_metadata() {
    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "mirror_request_body": true,
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();

    // Simulate non-UTF-8 body (e.g., gRPC protobuf):
    // request_body metadata is absent (not valid UTF-8), but request_body_bytes is set
    let binary_body: Vec<u8> = vec![0x00, 0x01, 0xFF, 0xFE, 0x80, 0x90];
    ctx.request_body_bytes = Some(bytes::Bytes::from(binary_body.clone()));
    // Ensure the UTF-8 metadata key is NOT set (simulates store_request_body_metadata
    // with non-UTF-8 data)
    ctx.metadata.remove("request_body");

    let mut headers: HashMap<String, String> = HashMap::new();

    // The plugin should read from request_body_bytes (binary-safe) rather than
    // the missing metadata key. This fires the mirror task — we verify it doesn't
    // panic and completes without error.
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);

    // Mirror result receiver should be set (mirror was dispatched)
    assert!(
        ctx.mirror_result_rxs.len() == 1,
        "Mirror should be dispatched even with binary body"
    );
}

#[tokio::test]
async fn test_mirror_falls_back_to_metadata_when_no_body_bytes() {
    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "mirror_request_body": true,
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();

    // Only the UTF-8 metadata key is set.
    ctx.metadata.insert(
        "request_body".to_string(),
        r#"{"hello":"world"}"#.to_string(),
    );
    ctx.request_body_bytes = None;

    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);

    assert!(
        ctx.mirror_result_rxs.len() == 1,
        "Mirror should be dispatched using metadata fallback"
    );
}

// === max_response_body_bytes config validation ===

#[test]
fn test_max_response_body_bytes_default() {
    // No config field set → defaults to 1 MiB. Plugin construction should
    // succeed.
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_max_response_body_bytes_zero_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "max_response_body_bytes": 0 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    assert!(
        result.err().unwrap().contains("max_response_body_bytes"),
        "error must mention the field"
    );
}

#[test]
fn test_max_response_body_bytes_negative_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "max_response_body_bytes": -1 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
}

#[test]
fn test_max_response_body_bytes_string_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "max_response_body_bytes": "1024" }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
}

#[test]
fn test_max_response_body_bytes_valid_value() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "max_response_body_bytes": 4096 }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
}

// === Bounded mirror response-body reads ===
//
// When the mirror response has no `content-length` header, the size is
// derived by streaming and counting bytes — bounded by
// `max_response_body_bytes`. A misbehaving sink returning a body larger than
// the cap must NOT exhaust gateway memory in a fire-and-forget mirror task.

/// Mirror endpoint returns a 10 KiB body without Content-Length, plugin caps
/// at 1 KiB. The mirror task aborts early; the reported size is just over the
/// cap (one chunk past), NOT the full 10 KiB.
#[tokio::test]
async fn test_mirror_response_body_bounded_when_oversized_no_content_length() {
    use tokio::net::TcpListener;

    // Spawn a minimal HTTP/1.1 server that responds with chunked 10 KiB. We
    // hand-write the response so we don't have to fight a higher-level
    // framework into omitting Content-Length.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // Read and discard the request (read until \r\n\r\n).
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;

            // Write a chunked response with no Content-Length.
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Transfer-Encoding: chunked\r\n\
                      Connection: close\r\n\r\n",
                )
                .await;

            // Send 10 chunks of 1024 bytes each = 10 KiB total.
            for _ in 0..10 {
                let chunk = "400\r\n".to_string() + &"A".repeat(1024) + "\r\n";
                let _ = stream.write_all(chunk.as_bytes()).await;
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
            let _ = stream.shutdown().await;
        }
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": false,
            "max_response_body_bytes": 1024
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);

    // Wait for the mirror task to finish and surface its meta via the watch
    // channel. The truncated size should be just over the limit, NOT the full
    // 10 KiB — proving the bounded reader aborted the stream.
    let meta = ctx
        .collect_mirror_result()
        .await
        .expect("mirror should report metadata");
    assert!(meta.mirror_error.is_none());
    let size = meta
        .mirror_response_size_bytes
        .expect("size should be reported");
    assert!(
        size > 1024,
        "reported size should reflect at-least one byte past the limit, got {}",
        size
    );
    assert!(
        size <= 2048,
        "bounded read must NOT consume the full 10 KiB body — got {}",
        size
    );
}

/// When the mirror response carries Content-Length, the body is still drained
/// under `max_response_body_bytes` so keep-alive pools can reclaim the socket.
/// Advertised and observed sizes are recorded independently.
#[tokio::test]
async fn test_mirror_response_body_drains_content_length_and_reports_both_sizes() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = vec![b'C'; 2048];
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let server_addr = server.uri();
    let server_url = url::Url::parse(&server_addr).unwrap();
    let host = server_url.host_str().unwrap().to_string();
    let port = server_url.port().unwrap();

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": host,
            "mirror_port": port,
            // Cap above the body so drain completes fully.
            "max_response_body_bytes": 4096,
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);

    let meta = ctx
        .collect_mirror_result()
        .await
        .expect("mirror metadata should arrive");
    let size = meta
        .mirror_response_size_bytes
        .expect("observed size should be reported");
    assert_eq!(
        size, 2048,
        "bounded drain should report the observed body size"
    );
    assert_eq!(
        meta.mirror_response_advertised_size_bytes,
        Some(2048),
        "advertised Content-Length must be retained independently"
    );
}

// === Finding #13: query-string secrets must not leak into mirror_error ===
//
// The mirror URL is built from the original request's query params and can
// carry credentials (`?access_token=...`, `?api_key=...`, `?sig=...`). A raw
// `reqwest::Error` renders the full request URL — including the query string —
// in its Display output. On a mirror failure (DNS error, connection refused,
// TLS error, timeout — all routine, attacker-influenceable conditions) the
// error string is stored verbatim in `MirrorResponseMeta.mirror_error`, which
// is serialized into every logging sink. Routing the call through
// `execute_redacted` reduces the transport error to an `ErrorClass` plus the
// query-stripped URL, so the secret never reaches the logs.

/// A mirror failure (connection refused) must produce a `mirror_error` that
/// contains neither the query string nor any secret value carried in it.
#[tokio::test]
async fn test_mirror_error_does_not_leak_query_string_secret() {
    use tokio::net::TcpListener;

    // Bind to an ephemeral port, capture it, then drop the listener so that a
    // connection to that port is refused immediately (deterministic, fast — no
    // dependence on the proxy timeout budget).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // Use a short backend_read_timeout so that, if the platform does not
    // produce an immediate connection-refused, the test still finishes quickly.
    let mut ctx = make_ctx_with_proxy();
    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(json!({
        "id": "proxy-123",
        "name": "test-proxy",
        "listen_path": "/api",
        "backend_host": "backend.local",
        "backend_port": 8080,
        "backend_scheme": "http",
        "backend_read_timeout_ms": 1000
    }))
    .unwrap();
    ctx.matched_proxy = Some(Arc::new(proxy));

    // Secrets in the query string. `make_ctx` already inserts `page=1`; add a
    // bearer-style token and an api key that MUST NOT appear in any log field.
    ctx.query_params.insert(
        "access_token".to_string(),
        "super-secret-token-value".to_string(),
    );
    ctx.query_params
        .insert("sig".to_string(), "deadbeefsignature".to_string());

    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);

    let meta = ctx
        .collect_mirror_result()
        .await
        .expect("mirror should report metadata for a failed request");

    let error = meta
        .mirror_error
        .expect("a refused/timed-out mirror must record an error");

    // The error must describe the failure but must NOT embed the credentials.
    assert!(
        !error.contains("super-secret-token-value"),
        "mirror_error leaked the access_token value: {error}"
    );
    assert!(
        !error.contains("deadbeefsignature"),
        "mirror_error leaked the sig value: {error}"
    );
    assert!(
        !error.contains("access_token"),
        "mirror_error leaked the access_token query key: {error}"
    );
    assert!(
        !error.contains("sig="),
        "mirror_error leaked a query parameter: {error}"
    );
    // No query string at all (the '?' separator) should survive.
    assert!(
        !error.contains('?'),
        "mirror_error must not contain a query string: {error}"
    );

    // The redacted-but-informative target URL should still be carried in the
    // dedicated field, query-stripped.
    assert!(
        !meta.mirror_target_url.contains('?'),
        "mirror_target_url must be query-stripped: {}",
        meta.mirror_target_url
    );
}

// === Finding #14: stale content-length must not be forwarded to the mirror ===
//
// When `mirror_request_body` is false (or the body is otherwise unavailable),
// no body is attached to the mirror request. Forwarding the original request's
// `content-length: N` header would then declare N body bytes with a zero-length
// body — a malformed request that makes many mirror servers block awaiting the
// bytes until timeout or reject it. Dropping `content-length` from the forwarded
// header set lets reqwest set the correct Content-Length from the actual body.

/// With `mirror_request_body = false` and a request carrying
/// `content-length: 99`, the outgoing mirror request must NOT declare 99 body
/// bytes. reqwest sets Content-Length to 0 (or omits it) for the empty body.
#[tokio::test]
async fn test_stale_content_length_not_forwarded_when_body_not_mirrored() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // The server captures the raw request head and reports the parsed
    // content-length (if any) back over a oneshot channel.
    let (tx, rx) = oneshot::channel::<Option<u64>>();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Read the request head. A bodyless request (or CL: 0) means the
            // headers terminate at the first \r\n\r\n with nothing after.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            // Read until we see the header terminator or the peer closes.
            loop {
                match stream.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            let head = String::from_utf8_lossy(&buf);
            // Find the content-length header value, if present (case-insensitive).
            let content_length = head.lines().find_map(|line| {
                let lower = line.to_ascii_lowercase();
                lower
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().parse::<u64>().unwrap_or(u64::MAX))
            });

            // Reply with a tiny valid response so the client side completes
            // cleanly (no error path), then close.
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;

            let _ = tx.send(content_length);
        } else {
            let _ = tx.send(None);
        }
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            // Body is NOT mirrored — this is the broken path.
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    let mut headers: HashMap<String, String> = HashMap::new();
    // A POST that arrived with a body declares content-length. This is the
    // stale header that must NOT be forwarded since no body is mirrored.
    headers.insert("content-length".to_string(), "99".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);

    // Drain the mirror task so the request is actually sent.
    let _ = ctx.collect_mirror_result().await;

    let observed = rx.await.expect("server should report content-length");
    // The mirror request must NOT declare the stale 99 bytes. reqwest sets
    // Content-Length: 0 for an empty body (or omits it entirely).
    match observed {
        None => { /* no content-length declared — acceptable */ }
        Some(0) => { /* reqwest set the correct zero length — acceptable */ }
        Some(other) => panic!(
            "mirror request forwarded a stale/incorrect content-length: {other} (expected 0 or absent)"
        ),
    }
}

// === Issue #2606: canonical secondary-request header sanitization on the wire ===

async fn capture_mirror_request_headers(
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
) -> HashMap<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<HashMap<String, String>>();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match stream.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let head = String::from_utf8_lossy(&buf);
            let mut captured = HashMap::new();
            for line in head.lines().skip(1) {
                if line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    captured.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
            let _ = tx.send(captured);
        }
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": false,
            "percentage": 100.0
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let _ = plugin.before_proxy(ctx, headers).await;
    let _ = ctx.collect_mirror_result().await;
    rx.await.expect("mirror sink should capture headers")
}

#[tokio::test]
async fn test_mirror_strips_hostile_h1_connection_trailer_and_internal_markers() {
    let mut ctx = make_ctx_with_proxy();
    let mut headers = HashMap::new();
    headers.insert(
        "Connection".to_string(),
        "X-Hop , , bad:token, Keep-Alive".to_string(),
    );
    headers.insert("X-Hop".to_string(), "per-connection".to_string());
    headers.insert("Trailer".to_string(), "X-Foo".to_string());
    headers.insert(
        "x-ferrum-original-content-encoding".to_string(),
        "gzip".to_string(),
    );
    headers.insert("x-grpc-web-mode".to_string(), "1".to_string());
    headers.insert("proxy-authorization".to_string(), "Basic leak".to_string());
    headers.insert("x-forwarded-for".to_string(), "198.51.100.7".to_string());
    headers.insert("x-forwarded-proto".to_string(), "https".to_string());
    headers.insert("x-forwarded-host".to_string(), "evil.example".to_string());
    headers.insert("content-length".to_string(), "99".to_string());
    headers.insert("host".to_string(), "client.example".to_string());
    headers.insert(
        "x-loadtesting-key".to_string(),
        "should-not-mirror".to_string(),
    );
    headers.insert("x-custom".to_string(), "keep-me".to_string());
    headers.insert("authorization".to_string(), "Bearer keep".to_string());

    let observed = capture_mirror_request_headers(&mut ctx, &mut headers).await;
    for stripped in [
        "connection",
        "x-hop",
        "trailer",
        "x-ferrum-original-content-encoding",
        "x-grpc-web-mode",
        "proxy-authorization",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-loadtesting-key",
        "authorization",
    ] {
        assert!(
            !observed.contains_key(stripped),
            "mirror leaked `{stripped}`: {observed:?}"
        );
    }
    // Host comes from the mirror URL, not the client header.
    assert_ne!(
        observed.get("host").map(String::as_str),
        Some("client.example")
    );
    assert_eq!(
        observed.get("x-custom").map(String::as_str),
        Some("keep-me")
    );
    match observed.get("content-length").map(String::as_str) {
        None | Some("0") => {}
        Some(other) => panic!("stale content-length survived mirror sanitization: {other}"),
    }
}

#[tokio::test]
async fn test_mirror_h2_h3_parity_and_grpc_te_resynthesis() {
    let mut ctx = make_ctx_with_proxy();
    // No Connection header (H2/H3 inbound shape).
    let mut headers = HashMap::new();
    headers.insert("trailer".to_string(), "grpc-status".to_string());
    headers.insert("te".to_string(), "gzip".to_string());
    headers.insert("transfer-encoding".to_string(), "chunked".to_string());
    headers.insert(
        "x-ferrum-original-content-encoding".to_string(),
        "br".to_string(),
    );
    headers.insert("x-grpc-web-mode".to_string(), "1".to_string());
    headers.insert(
        "content-type".to_string(),
        "application/grpc+proto".to_string(),
    );
    headers.insert("x-keep".to_string(), "ok".to_string());

    let observed = capture_mirror_request_headers_h2c(&mut ctx, &mut headers).await;
    for stripped in [
        "trailer",
        "transfer-encoding",
        "x-ferrum-original-content-encoding",
        "x-grpc-web-mode",
    ] {
        assert!(
            !observed.contains_key(stripped),
            "H2/H3 mirror parity leaked `{stripped}`: {observed:?}"
        );
    }
    assert_eq!(
        observed.get("te").map(String::as_str),
        Some("trailers"),
        "gRPC mirror must re-synthesise te: trailers after generic strip: {observed:?}"
    );
    assert_eq!(observed.get("x-keep").map(String::as_str), Some("ok"));
}

/// Capture outbound mirror request headers on an h2c (prior-knowledge) sink.
///
/// Native gRPC mirrors dial the HTTP/2 companion client, so an HTTP/1.1
/// capture server cannot observe them.
async fn capture_mirror_request_headers_h2c(
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
) -> HashMap<String, String> {
    use h2::server as h2_server;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<HashMap<String, String>>();
    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut h2) = h2_server::handshake(tcp).await else {
            return;
        };
        let mut tx = Some(tx);
        while let Some(result) = h2.accept().await {
            let Ok((request, mut respond)) = result else {
                break;
            };
            let Some(tx) = tx.take() else {
                continue;
            };
            tokio::spawn(async move {
                let mut captured = HashMap::new();
                for (name, value) in request.headers().iter() {
                    if let Ok(v) = value.to_str() {
                        captured.insert(name.as_str().to_ascii_lowercase(), v.to_string());
                    }
                }
                let mut body = request.into_body();
                while let Some(chunk) = body.data().await {
                    if let Ok(bytes) = chunk {
                        let _ = body.flow_control().release_capacity(bytes.len());
                    }
                }
                let response = http::Response::builder()
                    .status(200)
                    .body(())
                    .expect("empty response");
                let _ = respond.send_response(response, true);
                let _ = tx.send(captured);
            });
        }
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": false,
            "percentage": 100.0
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let _ = plugin.before_proxy(ctx, headers).await;
    let _ = ctx.collect_mirror_result().await;
    rx.await.expect("h2c mirror sink should capture headers")
}

#[tokio::test]
async fn test_native_grpc_mirror_uses_h2c_prior_knowledge() {
    // Issue #2472: cleartext gRPC mirrors must speak h2c, not HTTP/1.1.
    let mut ctx = make_ctx_with_proxy();
    ctx.path = "/pkg.Service/Method".to_string();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert("te".to_string(), "trailers".to_string());
    headers.insert("grpc-timeout".to_string(), "1S".to_string());

    let observed = capture_mirror_request_headers_h2c(&mut ctx, &mut headers).await;
    assert_eq!(
        observed.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(
        observed.get("te").map(String::as_str),
        Some("trailers"),
        "h2c gRPC mirror must carry synthesised te: trailers: {observed:?}"
    );
    assert_eq!(
        observed.get("grpc-timeout").map(String::as_str),
        Some("1S"),
        "gRPC metadata must survive the mirror path: {observed:?}"
    );
}

#[tokio::test]
async fn test_native_grpc_mirror_synthesises_te_when_client_omits_it() {
    // Issue #2472: missing inbound TE must still yield synthesised trailers
    // after the canonical secondary-request strip.
    let mut ctx = make_ctx_with_proxy();
    ctx.path = "/pkg.Service/Method".to_string();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    let observed = capture_mirror_request_headers_h2c(&mut ctx, &mut headers).await;
    assert_eq!(
        observed.get("te").map(String::as_str),
        Some("trailers"),
        "gRPC mirror must synthesise te: trailers when the client omitted TE: {observed:?}"
    );
}

#[tokio::test]
async fn test_ordinary_http_mirror_still_uses_http1() {
    // Non-gRPC mirrors must remain HTTP/1.1-capable against plain H1 sinks.
    let mut ctx = make_ctx_with_proxy();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("x-custom".to_string(), "keep".to_string());

    let observed = capture_mirror_request_headers(&mut ctx, &mut headers).await;
    assert_eq!(
        observed.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(observed.get("x-custom").map(String::as_str), Some("keep"));
    assert!(
        !observed.contains_key("te"),
        "ordinary HTTP mirrors must not inject te: trailers: {observed:?}"
    );
}

async fn capture_mirror_request_line(ctx: &mut RequestContext) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<String>();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match stream.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let head = String::from_utf8_lossy(&buf);
            let request_line = head.lines().next().unwrap_or("").to_string();
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
            let _ = tx.send(request_line);
        }
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": false,
            "percentage": 100.0
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
    let _ = ctx.collect_mirror_result().await;
    rx.await.expect("mirror request line")
}

#[tokio::test]
async fn test_mirror_preserves_supported_and_extension_methods() {
    for method in ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
        let mut ctx = make_ctx_with_proxy();
        ctx.method = method.to_string();

        let request_line = capture_mirror_request_line(&mut ctx).await;
        assert!(
            request_line.starts_with(&format!("{method} ")),
            "mirror changed request method: {request_line}"
        );
    }
}

#[tokio::test]
async fn test_mirror_preserves_raw_query_edge_cases() {
    // Issue #2444: repeated pairs, order, flags, empty values, `+`, encoded
    // delimiters, percent escapes, and non-ASCII encoded bytes must survive.
    const RAW: &str =
        "tag=red&tag=blue&b=1&a=2&flag&empty=&q=a+b&path=%2Froot&k=a%26b&key=a%2Fb&name=%E2%9C%93";

    let mut ctx = make_ctx_with_proxy();
    ctx.set_raw_query_string(RAW.to_string());
    // Materialised map would collapse duplicates and re-encode; raw query must win.
    ctx.query_params
        .insert("tag".to_string(), "only-one".to_string());

    let request_line = capture_mirror_request_line(&mut ctx).await;
    assert!(
        request_line.contains(RAW),
        "mirror must preserve raw query edge cases: {request_line}"
    );
    assert!(
        !request_line.contains("only-one"),
        "materialised query map must not replace raw query: {request_line}"
    );
}

#[tokio::test]
async fn test_mirror_applies_auth_query_strips_like_primary() {
    // Intentional query mutation parity with primary:
    // `query_string_after_plugin_strips` removes auth-marked credential params.
    let mut ctx = make_ctx_with_proxy();
    ctx.set_raw_query_string("api_key=secret&tag=red&tag=blue&keep=1".to_string());
    ctx.metadata.insert(
        "auth.strip_query_param.api_key".to_string(),
        "true".to_string(),
    );

    let request_line = capture_mirror_request_line(&mut ctx).await;
    assert!(
        request_line.contains("tag=red&tag=blue&keep=1"),
        "mirror must keep non-credential raw pairs: {request_line}"
    );
    assert!(
        !request_line.contains("api_key="),
        "mirror must strip auth-marked query credentials like primary: {request_line}"
    );
}

#[tokio::test]
async fn test_mirror_does_not_reintroduce_fully_stripped_query_credential() {
    let mut ctx = make_ctx_with_proxy();
    ctx.set_raw_query_string("api_key=secret".to_string());
    // Model the already-materialised map retained for later plugins. An empty
    // effective raw query must remain authoritative over this stale value.
    ctx.query_params
        .insert("api_key".to_string(), "secret".to_string());
    ctx.metadata.insert(
        "auth.strip_query_param.api_key".to_string(),
        "true".to_string(),
    );

    let request_line = capture_mirror_request_line(&mut ctx).await;
    assert!(
        !request_line.contains("api_key") && !request_line.contains('?'),
        "mirror must not restore a fully stripped credential query: {request_line}"
    );
}

#[tokio::test]
async fn test_mirror_ignores_query_map_transform_when_client_had_no_query() {
    let mut ctx = make_ctx_with_proxy();
    ctx.query_params
        .insert("injected".to_string(), "value".to_string());
    ctx.metadata.insert(
        "ferrum:query_params_transformed".to_string(),
        "true".to_string(),
    );

    let request_line = capture_mirror_request_line(&mut ctx).await;
    assert!(
        !request_line.contains("injected") && !request_line.contains('?'),
        "mirror must match primary raw-query construction: {request_line}"
    );
}

#[tokio::test]
async fn test_mirror_rejects_grpc_prefix_smuggling_for_te_resynthesis() {
    let mut ctx = make_ctx_with_proxy();
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpcfoo".to_string(),
    );
    headers.insert("te".to_string(), "gzip".to_string());

    // Prefix-smuggled types are not native gRPC, so the mirror stays on the
    // default HTTP client and an H1 capture sink observes the strip.
    let observed = capture_mirror_request_headers(&mut ctx, &mut headers).await;
    assert!(
        !observed.contains_key("te"),
        "prefix-smuggled content-type must not re-synthesise te: {observed:?}"
    );
}

#[tokio::test]
async fn test_grpc_mirror_preserves_binary_body_over_h2c() {
    use h2::server as h2_server;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut h2) = h2_server::handshake(tcp).await else {
            return;
        };
        let mut tx = Some(tx);
        while let Some(result) = h2.accept().await {
            let Ok((request, mut respond)) = result else {
                break;
            };
            let Some(tx) = tx.take() else {
                continue;
            };
            tokio::spawn(async move {
                let mut body = request.into_body();
                let mut buf = Vec::new();
                while let Some(chunk) = body.data().await {
                    if let Ok(bytes) = chunk {
                        let _ = body.flow_control().release_capacity(bytes.len());
                        buf.extend_from_slice(&bytes);
                    }
                }
                let response = http::Response::builder()
                    .status(200)
                    .body(())
                    .expect("empty response");
                let _ = respond.send_response(response, true);
                let _ = tx.send(buf);
            });
        }
    });

    let mut ctx = make_ctx_with_proxy();
    ctx.path = "/pkg.Service/Echo".to_string();
    // Length-prefixed gRPC frame: flag=0, length=4, payload=deadbeef
    let grpc_frame = vec![0, 0, 0, 0, 4, 0xde, 0xad, 0xbe, 0xef];
    ctx.request_body_bytes = Some(bytes::Bytes::from(grpc_frame.clone()));
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": true,
            "percentage": 100.0
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    let meta = ctx.collect_mirror_result().await.expect("mirror result");
    assert!(
        meta.mirror_error.is_none(),
        "h2c gRPC mirror with binary body failed: {meta:?}"
    );
    let body = rx.await.expect("h2c sink should capture body");
    assert_eq!(
        body, grpc_frame,
        "binary gRPC frame must be preserved byte-for-byte"
    );
}

#[tokio::test]
async fn test_grpc_mirror_preserves_multiframe_client_stream_body_over_h2c() {
    // Client-streaming body shape: multiple length-prefixed gRPC messages in
    // one buffered request body must survive the h2c companion path.
    use h2::server as h2_server;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut h2) = h2_server::handshake(tcp).await else {
            return;
        };
        let mut tx = Some(tx);
        while let Some(result) = h2.accept().await {
            let Ok((request, mut respond)) = result else {
                break;
            };
            let Some(tx) = tx.take() else {
                continue;
            };
            tokio::spawn(async move {
                let mut body = request.into_body();
                let mut buf = Vec::new();
                while let Some(chunk) = body.data().await {
                    if let Ok(bytes) = chunk {
                        let _ = body.flow_control().release_capacity(bytes.len());
                        buf.extend_from_slice(&bytes);
                    }
                }
                let response = http::Response::builder()
                    .status(200)
                    .body(())
                    .expect("empty response");
                let _ = respond.send_response(response, true);
                let _ = tx.send(buf);
            });
        }
    });

    let mut ctx = make_ctx_with_proxy();
    ctx.path = "/pkg.Service/ClientStream".to_string();
    // Two frames: "ab" (len=2) and "cdef" (len=4).
    let multi_frame = vec![
        0, 0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0, 4, b'c', b'd', b'e', b'f',
    ];
    ctx.request_body_bytes = Some(bytes::Bytes::from(multi_frame.clone()));
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": true,
            "percentage": 100.0
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    let meta = ctx.collect_mirror_result().await.expect("mirror result");
    assert!(
        meta.mirror_error.is_none(),
        "h2c gRPC mirror with multi-frame body failed: {meta:?}"
    );
    let body = rx.await.expect("h2c sink should capture multi-frame body");
    assert_eq!(
        body, multi_frame,
        "client-streaming multi-frame body must be preserved byte-for-byte"
    );
}

// === Audit workstream #3054–#3058 ============================================

#[test]
fn shadow_host_suffix_preserves_ipv6_and_ipv4_literals() {
    assert_eq!(
        request_mirror_append_shadow_host_suffix_for_test("[2001:db8::1]:8080"),
        "[2001:db8::1]:8080",
        "bracketed IPv6 with port must stay protocol-valid"
    );
    assert_eq!(
        request_mirror_append_shadow_host_suffix_for_test("[2001:db8::1]"),
        "[2001:db8::1]",
        "bracketed IPv6 without port must stay protocol-valid"
    );
    assert_eq!(
        request_mirror_append_shadow_host_suffix_for_test("192.0.2.10:8443"),
        "192.0.2.10:8443",
        "IPv4 literal with port must not receive a DNS suffix"
    );
    assert_eq!(
        request_mirror_append_shadow_host_suffix_for_test("192.0.2.10"),
        "192.0.2.10"
    );
    assert_eq!(
        request_mirror_append_shadow_host_suffix_for_test("internal.example.com:8443"),
        "internal.example.com-shadow:8443"
    );
    assert_eq!(
        request_mirror_append_shadow_host_suffix_for_test("exact.internal"),
        "exact.internal-shadow"
    );
    assert_eq!(
        request_mirror_append_shadow_host_suffix_for_test("2001:db8::1"),
        "2001:db8::1",
        "unbracketed IPv6 must not be rewritten into an invalid Host"
    );
}

#[test]
fn mirror_timeout_remains_finite_when_backend_read_timeout_is_zero() {
    assert_eq!(
        request_mirror_resolve_timeout_ms_for_test(None, Some(0)),
        60_000,
        "zero primary timeout must fall back to the finite mirror default"
    );
    assert_eq!(
        request_mirror_resolve_timeout_ms_for_test(None, None),
        60_000
    );
    assert_eq!(
        request_mirror_resolve_timeout_ms_for_test(None, Some(5_000)),
        5_000
    );
    assert_eq!(
        request_mirror_resolve_timeout_ms_for_test(Some(1_500), Some(0)),
        1_500,
        "explicit mirror_timeout_ms wins even when primary timeout is zero"
    );
    assert_eq!(
        request_mirror_resolve_timeout_ms_for_test(Some(999_999), Some(5_000)),
        300_000,
        "hard maximum must clamp oversized deadlines"
    );
}

#[test]
fn forward_sensitive_headers_opt_in_is_fail_closed() {
    let missing_allowlist = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "forward_sensitive_headers": true
        }),
        PluginHttpClient::default(),
    );
    assert!(
        missing_allowlist
            .err()
            .unwrap()
            .contains("forward_sensitive_header_allowlist"),
        "true without allowlist must fail closed"
    );

    let allowlist_without_flag = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "forward_sensitive_header_allowlist": ["authorization"]
        }),
        PluginHttpClient::default(),
    );
    assert!(
        allowlist_without_flag
            .err()
            .unwrap()
            .contains("forward_sensitive_headers=true"),
        "allowlist without opt-in flag must fail closed"
    );

    // A non-sensitive header name cannot be allowlisted: the allowlist only
    // re-permits headers the deny-by-default policy actually strips, so a name
    // that would never be stripped is a config error (catches typos).
    let non_sensitive = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "forward_sensitive_headers": true,
            "forward_sensitive_header_allowlist": ["x-trace-id"]
        }),
        PluginHttpClient::default(),
    );
    assert!(
        non_sensitive
            .err()
            .unwrap()
            .contains("not a recognized sensitive header"),
        "non-sensitive allowlist names must be rejected"
    );

    // An entry that is not a valid HTTP header name is rejected.
    let invalid_name = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "forward_sensitive_headers": true,
            "forward_sensitive_header_allowlist": ["bad header name"]
        }),
        PluginHttpClient::default(),
    );
    assert!(
        invalid_name
            .err()
            .unwrap()
            .contains("is not a valid HTTP header name"),
        "invalid header names must be rejected"
    );

    // A vendor credential caught only by a configured pattern can be
    // allowlisted (patterns are parsed before the allowlist is validated).
    assert!(
        RequestMirror::new(
            &json!({
                "mirror_host": "mirror.local",
                "sensitive_header_patterns": ["x-vendor-"],
                "forward_sensitive_headers": true,
                "forward_sensitive_header_allowlist": ["x-vendor-token"]
            }),
            PluginHttpClient::default(),
        )
        .is_ok(),
        "a header denied only by a configured pattern must be allowlistable"
    );

    assert!(
        RequestMirror::new(
            &json!({
                "mirror_host": "mirror.local",
                "forward_sensitive_headers": true,
                "forward_sensitive_header_allowlist": ["authorization", "cookie"]
            }),
            PluginHttpClient::default(),
        )
        .is_ok()
    );
}

#[test]
fn sensitive_header_config_bounds_reject_unbounded_lists_and_items() {
    let patterns_overflow = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "sensitive_header_patterns": (0..65).map(|i| format!("pat{i}")).collect::<Vec<_>>()
        }),
        PluginHttpClient::default(),
    )
    .err()
    .unwrap();
    assert!(
        patterns_overflow.contains("sensitive_header_patterns")
            && patterns_overflow.contains("at most 64"),
        "expected pattern count bound, got {patterns_overflow}"
    );

    let pattern_len = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "sensitive_header_patterns": ["x".repeat(129)]
        }),
        PluginHttpClient::default(),
    )
    .err()
    .unwrap();
    assert!(
        pattern_len.contains("maximum length of 128"),
        "expected pattern length bound, got {pattern_len}"
    );

    let allow_count = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "sensitive_header_patterns": (0..64).map(|i| format!("vendorkey{i}")).collect::<Vec<_>>(),
            "forward_sensitive_headers": true,
            "forward_sensitive_header_allowlist": (0..65)
                .map(|i| format!("x-vendorkey{i}"))
                .collect::<Vec<_>>()
        }),
        PluginHttpClient::default(),
    )
    .err()
    .unwrap();
    assert!(
        allow_count.contains("forward_sensitive_header_allowlist")
            && allow_count.contains("at most 64"),
        "expected allowlist count bound, got {allow_count}"
    );

    let long_allow = format!("x-{}", "a".repeat(255));
    assert!(long_allow.len() > 256);
    let allow_len = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "sensitive_header_patterns": ["x-aaaa"],
            "forward_sensitive_headers": true,
            "forward_sensitive_header_allowlist": [long_allow]
        }),
        PluginHttpClient::default(),
    )
    .err()
    .unwrap();
    assert!(
        allow_len.contains("maximum length of 256"),
        "expected allowlist item length bound, got {allow_len}"
    );

    // Exact maxima must still be accepted (fail-closed only above the bounds).
    let patterns: Vec<String> = (0..64)
        .map(|i| {
            let mut pattern = format!("p{i}-");
            while pattern.len() < 128 {
                pattern.push('z');
            }
            pattern.truncate(128);
            pattern
        })
        .collect();
    let allowlist: Vec<String> = patterns
        .iter()
        .map(|pattern| format!("x-{pattern}"))
        .collect();
    let ok = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "sensitive_header_patterns": patterns,
            "forward_sensitive_headers": true,
            "forward_sensitive_header_allowlist": allowlist
        }),
        PluginHttpClient::default(),
    );
    assert!(
        ok.is_ok(),
        "exact max bounds must be accepted: {:?}",
        ok.as_ref().err()
    );
}

#[tokio::test]
async fn content_length_responses_are_drained_for_http1_connection_reuse() {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = accepts.clone();
    tokio::spawn(async move {
        // One accepted TCP connection should serve both mirrored requests when
        // the body is drained and keep-alive is honored.
        let (mut stream, _) = listener.accept().await.unwrap();
        accepts_task.fetch_add(1, AtomicOrdering::SeqCst);
        for _ in 0..2 {
            let mut buf = [0u8; 4096];
            let mut total = 0usize;
            loop {
                let n = stream.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    return;
                }
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\nping",
                )
                .await;
        }
        // Leave the socket open briefly so the client can reuse it.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": false,
            "max_in_flight": 2,
            "mirror_timeout_ms": 2000
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    for _ in 0..2 {
        let mut ctx = make_ctx_with_proxy();
        let mut headers = HashMap::new();
        plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        let meta = ctx.collect_mirror_result().await.expect("mirror meta");
        assert!(
            meta.mirror_error.is_none(),
            "unexpected mirror error: {meta:?}"
        );
        assert_eq!(meta.mirror_response_size_bytes, Some(4));
        assert_eq!(meta.mirror_response_advertised_size_bytes, Some(4));
    }

    assert_eq!(
        accepts.load(AtomicOrdering::SeqCst),
        1,
        "drained Content-Length responses must reuse one HTTP/1.1 connection"
    );
}

#[tokio::test]
async fn mesh_shadow_ipv6_authority_stays_valid_on_outbound_host() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 2048];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&request).into_owned());
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });

    let route = create_plugin(
        "mesh_route_dispatch",
        &json!({
            "rules": [{
                "match": { "uri": {"prefix": "/api"}, "methods": ["POST"] },
                "destination": { "backend_host": "primary.internal", "backend_port": 8080 },
                "rewrite": {
                    "uri": "/mesh-rewritten",
                    "authority": "[2001:db8::10]:8080"
                }
            }]
        }),
    )
    .unwrap()
    .unwrap();
    let mirror = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "percentage": 100,
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    let mut headers = HashMap::new();
    headers.insert("host".to_string(), "client.example".to_string());
    plugin_utils::assert_continue(route.before_proxy(&mut ctx, &mut headers).await);
    plugin_utils::assert_continue(mirror.before_proxy(&mut ctx, &mut headers).await);
    let _ = ctx.collect_mirror_result().await;

    let request = tokio::time::timeout(std::time::Duration::from_secs(1), rx)
        .await
        .expect("mirror request timeout")
        .expect("mirror request body");
    assert!(
        request
            .lines()
            .any(|line| line.eq_ignore_ascii_case("host: [2001:db8::10]:8080")),
        "IPv6 shadow Host must remain bracketed with port: {request}"
    );
    assert!(
        !request.to_ascii_lowercase().contains("]-shadow"),
        "must not emit invalid bracketed-IPv6-shadow Host: {request}"
    );
}

#[tokio::test]
async fn retained_body_budget_drops_when_exhausted_and_releases_on_completion() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (gate_tx, mut gate_rx) = mpsc::channel::<oneshot::Sender<()>>(1);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 8192];
        let mut total = 0usize;
        loop {
            let n = stream.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                return;
            }
            total += n;
            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        // Hold the first mirror open until the second attempt is evaluated.
        let (release_tx, release_rx) = oneshot::channel();
        let _ = gate_tx.send(release_tx).await;
        let _ = release_rx.await;
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });

    let body = bytes::Bytes::from(vec![b'B'; 1024]);
    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": true,
            "max_in_flight": 4,
            "max_retained_request_body_bytes": 1024,
            "mirror_timeout_ms": 2000
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(
        request_mirror_max_retained_request_body_bytes_for_test(&plugin),
        1024
    );

    let mut first = make_ctx_with_proxy();
    first.request_body_bytes = Some(body.clone());
    let mut first_headers = HashMap::new();
    plugin_utils::assert_continue(plugin.before_proxy(&mut first, &mut first_headers).await);

    // Wait until the first mirror is in-flight and holding the body lease.
    let release = tokio::time::timeout(std::time::Duration::from_secs(1), gate_rx.recv())
        .await
        .expect("first mirror should reach the sink")
        .expect("gate sender");
    assert_eq!(
        request_mirror_retained_request_body_bytes_for_test(&plugin),
        1024
    );

    let mut second = make_ctx_with_proxy();
    second.request_body_bytes = Some(body);
    let mut second_headers = HashMap::new();
    plugin_utils::assert_continue(plugin.before_proxy(&mut second, &mut second_headers).await);
    let dropped = second
        .collect_mirror_result()
        .await
        .expect("budget drop must publish an explicit result");
    assert!(
        dropped
            .mirror_error
            .as_deref()
            .is_some_and(|e| e.contains("max_retained_request_body_bytes")),
        "expected body-budget drop, got {dropped:?}"
    );
    assert_eq!(
        request_mirror_metrics_snapshot_for_test(&plugin).budget_drops,
        1,
        "the exhausted second attempt is a byte-budget drop"
    );

    let _ = release.send(());
    let _ = first.collect_mirror_result().await;
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if request_mirror_retained_request_body_bytes_for_test(&plugin) == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("body lease must release when the mirror task ends");
}

#[tokio::test]
async fn zero_backend_read_timeout_still_cancels_never_responding_mirror() {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        // Accept the connection but never respond — exercises the finite
        // mirror deadline that must remain even when primary timeout is 0.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": false,
            "mirror_timeout_ms": 100
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy_timeout(0);
    let mut headers = HashMap::new();
    plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let meta = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ctx.collect_mirror_result(),
    )
    .await
    .expect("mirror outcome must be bounded by the finite mirror deadline")
    .expect("mirror meta");
    assert!(
        meta.mirror_error.is_some(),
        "never-responding target must surface an explicit mirror_error: {meta:?}"
    );
}

#[tokio::test]
async fn sensitive_headers_stripped_by_default_including_grpc_metadata() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&request).into_owned());
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "authorization".to_string(),
        "Bearer live-secret".to_string(),
    );
    headers.insert("cookie".to_string(), "session=abc".to_string());
    headers.insert(
        "proxy-authorization".to_string(),
        "Basic proxied".to_string(),
    );
    headers.insert(
        "proxy-authenticate".to_string(),
        "Basic realm=\"shadow\"".to_string(),
    );
    headers.insert("www-authenticate".to_string(), "Bearer".to_string());
    headers.insert("x-api-key".to_string(), "sk-live".to_string());
    headers.insert("x-custom".to_string(), "keep-me".to_string());

    plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let _ = ctx.collect_mirror_result().await;
    let request = tokio::time::timeout(std::time::Duration::from_secs(1), rx)
        .await
        .expect("timeout")
        .expect("request");
    let lower = request.to_ascii_lowercase();
    for forbidden in [
        "authorization:",
        "cookie:",
        "proxy-authorization:",
        "proxy-authenticate:",
        "www-authenticate:",
        "x-api-key:",
        "live-secret",
        "session=abc",
        "sk-live",
        "realm=\"shadow\"",
    ] {
        assert!(
            !lower.contains(forbidden),
            "default mirror must not forward credential material `{forbidden}`: {request}"
        );
    }
    assert!(
        lower.contains("x-custom: keep-me"),
        "non-sensitive headers must still forward: {request}"
    );
}

#[tokio::test]
async fn sensitive_header_allowlist_forwards_only_listed_names() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&request).into_owned());
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": false,
            "forward_sensitive_headers": true,
            "forward_sensitive_header_allowlist": ["authorization"]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        "Bearer allowlisted".to_string(),
    );
    headers.insert("cookie".to_string(), "session=nope".to_string());
    headers.insert("x-api-key".to_string(), "sk-nope".to_string());

    plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let _ = ctx.collect_mirror_result().await;
    let request = tokio::time::timeout(std::time::Duration::from_secs(1), rx)
        .await
        .expect("timeout")
        .expect("request");
    let lower = request.to_ascii_lowercase();
    assert!(
        lower.contains("authorization: bearer allowlisted"),
        "allowlisted Authorization must forward: {request}"
    );
    assert!(
        !lower.contains("cookie:"),
        "Cookie must stay stripped: {request}"
    );
    assert!(
        !lower.contains("x-api-key:"),
        "X-Api-Key must stay stripped: {request}"
    );
}

#[tokio::test]
async fn grpc_metadata_credentials_stripped_by_default_on_h2c_mirror() {
    use h2::server as h2_server;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<Vec<(String, String)>>();
    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut h2) = h2_server::handshake(tcp).await else {
            return;
        };
        let mut tx = Some(tx);
        while let Some(result) = h2.accept().await {
            let Ok((request, mut respond)) = result else {
                break;
            };
            let Some(tx) = tx.take() else {
                continue;
            };
            tokio::spawn(async move {
                let headers = request
                    .headers()
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_str().to_string(),
                            String::from_utf8_lossy(v.as_bytes()).into_owned(),
                        )
                    })
                    .collect::<Vec<_>>();
                let mut body = request.into_body();
                while let Some(chunk) = body.data().await {
                    if let Ok(bytes) = chunk {
                        let _ = body.flow_control().release_capacity(bytes.len());
                    }
                }
                let response = http::Response::builder()
                    .status(200)
                    .body(())
                    .expect("empty response");
                let _ = respond.send_response(response, true);
                let _ = tx.send(headers);
            });
        }
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": true,
            "percentage": 100.0
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    ctx.path = "/pkg.Service/Method".to_string();
    ctx.request_body_bytes = Some(bytes::Bytes::from(vec![0, 0, 0, 0, 1, b'x']));
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(
        "authorization".to_string(),
        "Bearer grpc-secret".to_string(),
    );
    headers.insert("cookie".to_string(), "sid=1".to_string());
    headers.insert("x-api-key".to_string(), "grpc-key".to_string());
    headers.insert(
        "proxy-authenticate".to_string(),
        "Basic realm=\"grpc\"".to_string(),
    );
    headers.insert("grpc-timeout".to_string(), "1S".to_string());

    plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let meta = ctx.collect_mirror_result().await.expect("mirror result");
    assert!(
        meta.mirror_error.is_none(),
        "gRPC mirror should succeed: {meta:?}"
    );
    let observed = tokio::time::timeout(std::time::Duration::from_secs(1), rx)
        .await
        .expect("timeout")
        .expect("headers");
    let lower = observed
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_ascii_lowercase()))
        .collect::<Vec<_>>();
    assert!(
        !lower.iter().any(|(k, _)| k == "authorization"),
        "gRPC Authorization metadata must be stripped by default: {observed:?}"
    );
    assert!(
        !lower.iter().any(|(k, _)| k == "cookie"),
        "gRPC Cookie metadata must be stripped by default: {observed:?}"
    );
    assert!(
        !lower.iter().any(|(k, _)| k == "x-api-key"),
        "gRPC x-api-key metadata must be stripped by default: {observed:?}"
    );
    assert!(
        !lower.iter().any(|(k, _)| k == "proxy-authenticate"),
        "gRPC Proxy-Authenticate metadata must be stripped by default: {observed:?}"
    );
    assert!(
        lower.iter().any(|(k, v)| k == "grpc-timeout" && v == "1s"),
        "non-sensitive gRPC metadata must still forward: {observed:?}"
    );
}

/// #3054: a mirror response advertising a `Content-Length` larger than
/// `max_response_body_bytes` must still be drained under the byte + time bounds
/// (never dropped unread with a fabricated `observed = max_bytes`). The observed
/// size reflects bytes actually read, and the advertised length is recorded
/// independently.
#[tokio::test]
async fn oversized_content_length_response_is_drained_under_bounds() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let mut total = 0usize;
        loop {
            let n = stream.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                return;
            }
            total += n;
            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        // Advertise and actually send 4096 bytes — larger than the 1024 cap —
        // so the drain must bound the read rather than drop the response on the
        // advertised length alone (the old Content-Length fast path).
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n")
            .await;
        let _ = stream.write_all(&vec![b'D'; 4096]).await;
        let _ = stream.shutdown().await;
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": false,
            "max_response_body_bytes": 1024
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    let mut headers = HashMap::new();
    plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let meta = ctx.collect_mirror_result().await.expect("mirror meta");
    assert!(
        meta.mirror_error.is_none(),
        "truncation is not an error: {meta:?}"
    );
    assert_eq!(
        meta.mirror_response_advertised_size_bytes,
        Some(4096),
        "advertised Content-Length must be recorded independently of observed"
    );
    let observed = meta
        .mirror_response_size_bytes
        .expect("observed size should be reported");
    assert!(
        observed > 1024,
        "observed size must reflect a real bounded read, not a fabricated cap value: got {observed}"
    );
    assert!(
        observed <= 4096,
        "observed size must not exceed the actual body: got {observed}"
    );
    let m = request_mirror_metrics_snapshot_for_test(&plugin);
    assert_eq!(
        m.drain_truncations, 1,
        "byte-cap truncation is its own terminal drain outcome: {m:?}"
    );
    assert_eq!(m.completed, 0, "truncation is not a full completion: {m:?}");
    assert_eq!(m.dispatched, 1, "{m:?}");
}

/// #3058: deny-by-default credential stripping covers vendor-prefixed headers
/// via built-in credential substrings AND operator-configured
/// `sensitive_header_patterns`, without over-stripping benign headers that only
/// contain the deliberately-excluded bare `token` substring.
#[tokio::test]
async fn sensitive_header_patterns_and_substrings_strip_vendor_credentials() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&request).into_owned());
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": false,
            "sensitive_header_patterns": ["x-vault-"]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    let mut headers = HashMap::new();
    // Caught by the built-in `api-key` substring:
    headers.insert("x-openai-api-key".to_string(), "sk-openai".to_string());
    headers.insert("x-datadog-api-key".to_string(), "dd-key".to_string());
    // Caught by the built-in `security-token` substring:
    headers.insert("x-amz-security-token".to_string(), "amz-tok".to_string());
    // Caught only by the operator pattern `x-vault-`:
    headers.insert("x-vault-token".to_string(), "vault-tok".to_string());
    // Benign: contains only the excluded bare `token` substring — must survive.
    headers.insert("x-continuation-token".to_string(), "page2".to_string());
    headers.insert("x-custom".to_string(), "keep-me".to_string());

    plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let _ = ctx.collect_mirror_result().await;
    let request = tokio::time::timeout(std::time::Duration::from_secs(1), rx)
        .await
        .expect("timeout")
        .expect("request");
    let lower = request.to_ascii_lowercase();
    for forbidden in [
        "x-openai-api-key:",
        "x-datadog-api-key:",
        "x-amz-security-token:",
        "x-vault-token:",
        "sk-openai",
        "dd-key",
        "amz-tok",
        "vault-tok",
    ] {
        assert!(
            !lower.contains(forbidden),
            "vendor credential `{forbidden}` must be stripped: {request}"
        );
    }
    assert!(
        lower.contains("x-continuation-token: page2"),
        "benign pagination cursor must survive: {request}"
    );
    assert!(
        lower.contains("x-custom: keep-me"),
        "non-sensitive header must survive: {request}"
    );
}

/// #3057: per-instance bounded-lifetime counters track the mirror lifecycle —
/// dispatch, completion, and request-phase timeout — with a settled task never
/// counted as a cancellation.
#[tokio::test]
async fn mirror_metrics_track_dispatch_completion_and_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // (1) Success path → dispatched + completed, no cancellations/timeouts.
    let ok_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ok_addr = ok_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = ok_listener.accept().await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });
    let ok_plugin = RequestMirror::new(
        &json!({
            "mirror_host": ok_addr.ip().to_string(),
            "mirror_port": ok_addr.port(),
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = make_ctx_with_proxy();
    let mut headers = HashMap::new();
    plugin_utils::assert_continue(ok_plugin.before_proxy(&mut ctx, &mut headers).await);
    let _ = ctx.collect_mirror_result().await;
    let m = request_mirror_metrics_snapshot_for_test(&ok_plugin);
    assert_eq!(m.dispatched, 1, "one task dispatched: {m:?}");
    assert_eq!(
        m.completed, 1,
        "successful response counts as completed: {m:?}"
    );
    assert_eq!(
        m.cancellations, 0,
        "a settled task is not a cancellation: {m:?}"
    );
    assert_eq!(m.request_timeouts, 0, "{m:?}");
    assert_eq!(m.request_failures, 0, "{m:?}");

    // (2) Never-responding target under a short mirror deadline → request timeout.
    let stuck_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stuck_addr = stuck_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = stuck_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    });
    let stuck_plugin = RequestMirror::new(
        &json!({
            "mirror_host": stuck_addr.ip().to_string(),
            "mirror_port": stuck_addr.port(),
            "mirror_request_body": false,
            "mirror_timeout_ms": 100
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx2 = make_ctx_with_proxy_timeout(0);
    let mut headers2 = HashMap::new();
    plugin_utils::assert_continue(stuck_plugin.before_proxy(&mut ctx2, &mut headers2).await);
    let meta = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ctx2.collect_mirror_result(),
    )
    .await
    .expect("mirror outcome must be bounded by the finite deadline")
    .expect("mirror meta");
    assert!(
        meta.mirror_error.is_some(),
        "never-responding target must error: {meta:?}"
    );
    let m2 = request_mirror_metrics_snapshot_for_test(&stuck_plugin);
    assert_eq!(m2.dispatched, 1, "{m2:?}");
    assert_eq!(
        m2.request_timeouts, 1,
        "reqwest read timeout must be counted as a request timeout: {m2:?}"
    );
    assert_eq!(m2.completed, 0, "{m2:?}");
    assert_eq!(m2.cancellations, 0, "{m2:?}");
}

/// #3057: the concurrency-drop admission path increments the drop counter while
/// leaving the primary request unaffected.
#[tokio::test]
async fn mirror_metrics_count_concurrency_drops() {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    // Accept connections but never respond, so the first permit stays held for
    // the duration of the test.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            });
        }
    });

    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": addr.ip().to_string(),
            "mirror_port": addr.port(),
            "mirror_request_body": false,
            "max_in_flight": 1,
            "mirror_timeout_ms": 5000
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // First dispatch holds the only permit for the whole test.
    let mut first = make_ctx_with_proxy();
    let mut h1 = HashMap::new();
    plugin_utils::assert_continue(plugin.before_proxy(&mut first, &mut h1).await);

    // Second dispatch cannot acquire a permit → explicit concurrency drop.
    let mut second = make_ctx_with_proxy();
    let mut h2 = HashMap::new();
    plugin_utils::assert_continue(plugin.before_proxy(&mut second, &mut h2).await);
    let dropped = second
        .collect_mirror_result()
        .await
        .expect("concurrency drop must publish an explicit result");
    assert!(
        dropped
            .mirror_error
            .as_deref()
            .is_some_and(|e| e.contains("max_in_flight")),
        "expected concurrency drop, got {dropped:?}"
    );

    let m = request_mirror_metrics_snapshot_for_test(&plugin);
    assert_eq!(
        m.dispatched, 1,
        "only the first attempt was dispatched: {m:?}"
    );
    assert_eq!(
        m.concurrency_drops, 1,
        "the saturated second attempt is a concurrency drop: {m:?}"
    );
}
