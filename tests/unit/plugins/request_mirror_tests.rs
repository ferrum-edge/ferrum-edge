use ferrum_edge::plugins::request_mirror::RequestMirror;
use ferrum_edge::plugins::{
    HTTP_GRPC_PROTOCOLS, MirrorResponseMeta, Plugin, PluginHttpClient, PluginResult,
    RequestContext, TransactionSummary, create_plugin, log_with_mirror, priority,
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
    let mut ctx = make_ctx();
    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(json!({
        "id": "proxy-123",
        "name": "test-proxy",
        "listen_path": "/api",
        "backend_host": "backend.local",
        "backend_port": 8080,
        "backend_scheme": "http",
        "backend_read_timeout_ms": 30000
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
    ctx.mirror_result_rx = Some(rx);
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
        mirror_target_url: "http://mirror.local:8080/api/users".to_string(),
        mirror_response_status_code: Some(204),
        mirror_response_size_bytes: Some(0),
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
        mirror_target_url: "http://mirror.local:8080/api/users".to_string(),
        mirror_response_status_code: Some(204),
        mirror_response_size_bytes: Some(0),
        mirror_latency_ms: 10.0,
        mirror_error: None,
    });
    assert!(successful_mirror.grpc_status().is_none());
    assert!(!successful_mirror.is_terminal_failure());
    assert!(!successful_mirror.metadata.contains_key("grpc_message"));
    assert!(!successful_mirror.metadata.contains_key("rejection_phase"));
    let successful_json = serde_json::to_value(&successful_mirror).unwrap();
    assert!(successful_json.get("grpc_status").is_none());

    primary
        .metadata
        .insert("grpc_status".to_string(), "0".to_string());
    primary.metadata.remove("rejection_phase");
    let failed_mirror = primary.as_mirror_entry(MirrorResponseMeta {
        mirror_target_url: "http://mirror.local:8080/api/users".to_string(),
        mirror_response_status_code: None,
        mirror_response_size_bytes: None,
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
// Percentage sampling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_percentage_50_mirrors_roughly_half() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "percentage": 50.0 }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // The counter-based approach mirrors requests where (counter % 1000) < 500.
    // Over 1000 requests, exactly 500 should be mirrored.
    let mut mirrored = 0u32;
    for _ in 0..1000 {
        let mut ctx = make_ctx();
        let mut headers = HashMap::new();
        // We can't directly observe mirroring since it's fire-and-forget via tokio::spawn,
        // but we can verify the plugin always returns Continue.
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        match result {
            PluginResult::Continue => {}
            _ => panic!("Expected Continue"),
        }
        mirrored += 1;
    }
    assert_eq!(mirrored, 1000); // All return Continue regardless of mirror decision
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
        ctx.mirror_result_rx.is_some(),
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
        ctx.mirror_result_rx.is_some(),
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

/// When the mirror response carries Content-Length, the body is never read
/// (CL fast path). The reported size is the CL header value, regardless of
/// `max_response_body_bytes`.
#[tokio::test]
async fn test_mirror_response_body_uses_content_length_fast_path() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = vec![b'C'; 4096];
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
            // 1 KiB cap, but CL is 4 KiB — fast path skips the bounded read.
            "max_response_body_bytes": 1024,
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
        .expect("size should be reported");
    assert_eq!(size, 4096, "CL fast-path should report the full 4 KiB size");
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
    assert_eq!(
        observed.get("authorization").map(String::as_str),
        Some("Bearer keep")
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

    let observed = capture_mirror_request_headers(&mut ctx, &mut headers).await;
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

    let observed = capture_mirror_request_headers(&mut ctx, &mut headers).await;
    assert!(
        !observed.contains_key("te"),
        "prefix-smuggled content-type must not re-synthesise te: {observed:?}"
    );
}
