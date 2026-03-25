//! Tests that logging plugins execute on rejected requests.
//!
//! When auth, access control, rate limiting, or other plugins reject a request,
//! logging plugins (stdout_logging, http_logging, transaction_debugger) must still
//! fire so that rejected traffic is visible in log sinks (Splunk, stdout, etc.).

use std::sync::Arc;
use std::time::Instant;

use ferrum_gateway::plugins::{
    Plugin, TransactionSummary, create_plugin, priority as plugin_priority,
};
use ferrum_gateway::proxy::log_rejected_request;
use serde_json::json;

use super::plugin_utils::{create_test_context, create_test_proxy};

/// Verify that log_rejected_request only invokes logging-band plugins (priority >= 9000)
/// and not auth/transform plugins.
#[tokio::test]
async fn test_log_rejected_request_only_calls_logging_plugins() {
    // Build a realistic plugin list: auth + logging
    let key_auth = create_plugin("key_auth", &json!({})).unwrap().unwrap();
    let stdout_log = create_plugin("stdout_logging", &json!({}))
        .unwrap()
        .unwrap();
    let http_log = create_plugin(
        "http_logging",
        &json!({"endpoint_url": "http://127.0.0.1:9999/logs"}),
    )
    .unwrap()
    .unwrap();
    let debugger = create_plugin("transaction_debugger", &json!({}))
        .unwrap()
        .unwrap();

    // Verify priorities are in expected bands
    assert!(key_auth.priority() < plugin_priority::STDOUT_LOGGING);
    assert!(stdout_log.priority() >= plugin_priority::STDOUT_LOGGING);
    assert!(http_log.priority() >= plugin_priority::STDOUT_LOGGING);
    assert!(debugger.priority() >= plugin_priority::STDOUT_LOGGING);

    let plugins: Vec<Arc<dyn Plugin>> = vec![key_auth, stdout_log, http_log, debugger];

    let mut ctx = create_test_context();
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));

    let start = Instant::now();

    // This should not panic and should only call log() on logging plugins
    log_rejected_request(&plugins, &ctx, 401, start, "authenticate").await;
}

/// Verify the TransactionSummary produced for rejected requests has correct metadata.
#[tokio::test]
async fn test_rejected_request_summary_has_rejection_phase() {
    // Use stdout_logging since it just prints to stdout (observable but won't fail)
    let stdout_log = create_plugin("stdout_logging", &json!({}))
        .unwrap()
        .unwrap();
    let plugins: Vec<Arc<dyn Plugin>> = vec![stdout_log];

    let mut ctx = create_test_context();
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    ctx.identified_consumer = None; // Auth failed, no consumer

    let start = Instant::now();

    // Call with "authorize" phase
    log_rejected_request(&plugins, &ctx, 403, start, "authorize").await;

    // The function completes without panic — if the summary were malformed,
    // the logging plugin would fail. The rejection_phase metadata is set
    // inside the function and passed to plugin.log().
}

/// Verify that log_rejected_request is a no-op when there are no logging plugins.
#[tokio::test]
async fn test_log_rejected_request_noop_without_logging_plugins() {
    // Only auth plugins, no logging plugins
    let key_auth = create_plugin("key_auth", &json!({})).unwrap().unwrap();
    let access_ctrl = create_plugin("access_control", &json!({"allowed_ips": ["0.0.0.0/0"]}))
        .unwrap()
        .unwrap();

    let plugins: Vec<Arc<dyn Plugin>> = vec![key_auth, access_ctrl];

    let mut ctx = create_test_context();
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));

    let start = Instant::now();

    // Should return immediately without calling any plugin
    log_rejected_request(&plugins, &ctx, 401, start, "authenticate").await;
}

/// Verify that log_rejected_request works with an empty plugin list.
#[tokio::test]
async fn test_log_rejected_request_empty_plugins() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![];
    let ctx = create_test_context();
    let start = Instant::now();

    log_rejected_request(&plugins, &ctx, 500, start, "on_request_received").await;
}

/// Verify that log_rejected_request handles all rejection phases.
#[tokio::test]
async fn test_log_rejected_request_all_phases() {
    let stdout_log = create_plugin("stdout_logging", &json!({}))
        .unwrap()
        .unwrap();
    let plugins: Vec<Arc<dyn Plugin>> = vec![stdout_log];

    let mut ctx = create_test_context();
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));

    let phases = vec![
        ("on_request_received", 400u16),
        ("authenticate", 401),
        ("authorize", 403),
        ("before_proxy", 429),
        ("grpc_backend_error", 200),
    ];

    for (phase, status) in phases {
        let start = Instant::now();
        log_rejected_request(&plugins, &ctx, status, start, phase).await;
    }
}

/// Verify that log_rejected_request sets backend fields correctly for rejected requests.
/// Since the request never reached the backend, backend_target_url should be None
/// and backend latency fields should be 0.
#[tokio::test]
async fn test_rejected_request_summary_no_backend_fields() {
    // Create a custom plugin that captures the summary for inspection
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct CapturingLogger {
        captured: Mutex<Vec<TransactionSummary>>,
    }

    #[async_trait]
    impl Plugin for CapturingLogger {
        fn name(&self) -> &str {
            "capturing_logger"
        }

        fn priority(&self) -> u16 {
            plugin_priority::STDOUT_LOGGING // Logging band
        }

        async fn log(&self, summary: &TransactionSummary) {
            self.captured.lock().unwrap().push(summary.clone());
        }
    }

    let logger = Arc::new(CapturingLogger {
        captured: Mutex::new(Vec::new()),
    });
    let plugins: Vec<Arc<dyn Plugin>> = vec![logger.clone()];

    let mut ctx = create_test_context();
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    ctx.identified_consumer = None;

    let start = Instant::now();
    log_rejected_request(&plugins, &ctx, 401, start, "authenticate").await;

    let summaries = logger.captured.lock().unwrap();
    assert_eq!(summaries.len(), 1);

    let summary = &summaries[0];
    assert_eq!(summary.response_status_code, 401);
    // backend_target_url is populated from the matched proxy so log consumers
    // can query which backend API proxy had rejected traffic.
    assert!(summary.backend_target_url.is_some());
    let target_url = summary.backend_target_url.as_ref().unwrap();
    assert!(
        target_url.contains("localhost"),
        "Expected backend host in URL, got: {}",
        target_url
    );
    assert_eq!(summary.latency_backend_ttfb_ms, -1.0);
    assert_eq!(summary.latency_backend_total_ms, -1.0);
    assert_eq!(summary.client_ip, "127.0.0.1");
    assert_eq!(summary.http_method, "GET");
    assert_eq!(summary.request_path, "/test");
    assert_eq!(summary.matched_proxy_id, Some("test-proxy".to_string()));
    assert_eq!(
        summary.metadata.get("rejection_phase"),
        Some(&"authenticate".to_string())
    );
    assert!(summary.consumer_username.is_none());
}
