use async_trait::async_trait;
use bytes::Bytes;
use ferrum_edge::_test_support::{
    finalize_plugin_rejection_for_test, finalize_plugin_rejection_without_committed_hooks_for_test,
    request_deduplication_completed_size_snapshot_for_test,
    request_deduplication_expire_completed_entries_for_test,
    request_deduplication_expire_inflight_entries_for_test,
    request_deduplication_logical_keys_from_context_for_test,
    request_deduplication_redis_cached_response_payload_is_valid,
    request_deduplication_redis_payload_for_test, request_deduplication_request_identity_for_test,
    request_deduplication_set_request_state_for_test,
    request_deduplication_with_instance_id_for_test,
};
use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
use ferrum_edge::plugins::ai_response_guard::AiResponseGuard;
use ferrum_edge::plugins::ai_tool_governor::AiToolGovernor;
use ferrum_edge::plugins::request_deduplication::RequestDeduplication;
use ferrum_edge::plugins::serverless_function::ServerlessFunction;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext,
    create_plugin_with_http_client, create_plugin_with_http_client_and_config_id, priority,
};
use ferrum_edge::proxy::deferred_log::BodyOutcome;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Barrier;

struct AppendingResponseTransform;

struct FailingMandatoryReplayTransform;

#[async_trait]
impl Plugin for FailingMandatoryReplayTransform {
    fn name(&self) -> &str {
        "failing_mandatory_replay_transform"
    }

    fn requires_replay_response_body_transform(&self, _ctx: &RequestContext) -> bool {
        true
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    async fn transform_response_body(
        &self,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        None
    }
}

#[async_trait]
impl Plugin for AppendingResponseTransform {
    fn name(&self) -> &str {
        "appending_response_transform"
    }

    fn priority(&self) -> u16 {
        4000
    }

    fn supported_protocols(&self) -> &'static [ferrum_edge::plugins::ProxyProtocol] {
        HTTP_ONLY_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        ctx.metadata
            .insert("test:replay-inspected".to_string(), "true".to_string());
        PluginResult::Continue
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        let mut transformed = body.to_vec();
        transformed.extend_from_slice(b"|transformed");
        Some(transformed)
    }
}

fn make_plugin(config: serde_json::Value) -> RequestDeduplication {
    RequestDeduplication::new(&config, PluginHttpClient::default()).unwrap()
}

fn request_identity(
    plugin: &RequestDeduplication,
    ctx: &RequestContext,
) -> Option<(String, String)> {
    request_deduplication_request_identity_for_test(plugin, ctx)
}

#[tokio::test]
async fn request_context_debug_redacts_request_deduplication_state() {
    let plugin = make_plugin(json!({}));
    let mut ctx = body_ctx("POST", "/payments", br#"{"amount":100}"#);
    let mut upstream_headers = keyed_headers("ordinary-idempotency-key", "api.example.test", 14);

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut upstream_headers).await,
        PluginResult::Continue
    ));
    assert!(request_identity(&plugin, &ctx).is_some());

    let protected_values = [
        ("key", "dedup-debug-key-sentinel-9f21"),
        ("fingerprint", "dedup-debug-fingerprint-sentinel-6c38"),
        (
            "local_inflight_owner_token",
            "dedup-debug-local-owner-sentinel-4a57",
        ),
        ("redis_lock_token", "dedup-debug-redis-lock-sentinel-2d84"),
    ];
    request_deduplication_set_request_state_for_test(
        &plugin,
        &mut ctx,
        protected_values[0].1,
        protected_values[1].1,
        protected_values[2].1,
        Some(protected_values[3].1),
    );

    let debug_output = format!("{ctx:?}");
    assert!(debug_output.contains("RequestDeduplicationRequestState"));
    for (field, sentinel) in protected_values {
        assert!(
            debug_output.contains(&format!(r#"{field}: "<redacted>""#)),
            "missing redacted {field} structure: {debug_output}"
        );
        assert!(
            !debug_output.contains(sentinel),
            "{field} leaked through RequestContext Debug"
        );
    }
}

fn keyed_headers(key: &str, host: &str, body_len: usize) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), key.to_string());
    headers.insert("host".to_string(), host.to_string());
    headers.insert("content-length".to_string(), body_len.to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers
}

/// Two distinct-header instances on one request (issue #2378 reproduction shape).
fn dual_keyed_headers(
    idempotency_key: &str,
    operation_key: &str,
    host: &str,
    body_len: usize,
) -> HashMap<String, String> {
    let mut headers = keyed_headers(idempotency_key, host, body_len);
    headers.insert("x-operation-key".to_string(), operation_key.to_string());
    headers
}

fn make_local_sibling(header_name: &str, config_id: &str) -> RequestDeduplication {
    request_deduplication_with_instance_id_for_test(
        &json!({
            "header_name": header_name,
            "scope_by_consumer": false,
        }),
        PluginHttpClient::default(),
        config_id,
    )
    .unwrap()
}

fn make_redis_sibling(header_name: &str, config_id: &str, prefix: &str) -> RequestDeduplication {
    // Unreachable Redis forces local fallback while still constructing Redis-mode
    // instances with distinct explicit prefixes — the #2378 lifecycle shape that
    // is independent of shared-prefix self-conflict (#2379).
    request_deduplication_with_instance_id_for_test(
        &json!({
            "header_name": header_name,
            "scope_by_consumer": false,
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:1/0",
            "redis_connect_timeout_seconds": 1,
            "redis_key_prefix": prefix,
        }),
        PluginHttpClient::default(),
        config_id,
    )
    .unwrap()
}

async fn mark_both_fresh(
    first: &RequestDeduplication,
    second: &RequestDeduplication,
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
) {
    assert!(matches!(
        first.before_proxy(ctx, headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        second.before_proxy(ctx, headers).await,
        PluginResult::Continue
    ));
    let keys = request_deduplication_logical_keys_from_context_for_test(ctx);
    assert_eq!(
        keys.len(),
        2,
        "each instance must own an independent request-private completion slot"
    );
    let first_id = request_identity(first, ctx).expect("first instance ownership");
    let second_id = request_identity(second, ctx).expect("second instance ownership");
    assert_ne!(
        first_id.0, second_id.0,
        "distinct headers must produce distinct logical keys per instance"
    );
}

fn body_ctx(method: &str, path: &str, body: &'static [u8]) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    ctx.request_body_bytes = Some(Bytes::from_static(body));
    ctx
}

fn gzip_body(body: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).expect("gzip write failed");
    encoder.finish().expect("gzip finish failed")
}

async fn complete_response(plugin: &RequestDeduplication, ctx: &mut RequestContext) {
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let result = plugin
        .on_final_response_body(ctx, 201, &response_headers, b"{\"ok\":true}")
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

async fn complete_response_with_body(
    plugin: &RequestDeduplication,
    ctx: &mut RequestContext,
    body: &[u8],
) {
    let response_headers = HashMap::new();
    let result = plugin
        .on_final_response_body(ctx, 200, &response_headers, body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

fn assert_completed_size_exact(plugin: &RequestDeduplication) -> usize {
    let (tracked, actual) = request_deduplication_completed_size_snapshot_for_test(plugin);
    assert_eq!(
        tracked, actual,
        "tracked completed-response bytes must match retained completed entries"
    );
    tracked
}

fn assert_fingerprint_conflict(result: PluginResult) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 409);
            assert!(body.contains("different request"), "body was {body}");
        }
        other => panic!("Expected fingerprint mismatch conflict, got {other:?}"),
    }
}

async fn assert_reused_key_for_different_request_conflicts(
    first_ctx: &mut RequestContext,
    first_headers: &mut HashMap<String, String>,
    second_ctx: &mut RequestContext,
    second_headers: &mut HashMap<String, String>,
) {
    let plugin = make_plugin(json!({
        "applicable_methods": ["POST", "PUT", "PATCH"]
    }));

    let result = plugin.before_proxy(first_ctx, first_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response(&plugin, first_ctx).await;

    let result = plugin.before_proxy(second_ctx, second_headers).await;
    assert_fingerprint_conflict(result);
}

#[test]
fn test_new_default_config() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "request_deduplication");
    assert_eq!(plugin.priority(), priority::REQUEST_DEDUPLICATION);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(plugin.requires_response_body_buffering());
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.needs_request_body_bytes());
}

#[test]
fn test_new_custom_header() {
    let config = json!({
        "header_name": "X-Request-Id",
        "ttl_seconds": 60,
        "max_entries": 5000
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "request_deduplication");
}

#[test]
fn test_new_rejects_non_object_config() {
    let result = RequestDeduplication::new(&json!("bad"), PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("config must be an object"));
}

#[test]
fn new_with_instance_id_rejects_blank_stable_identity() {
    for blank in ["", "   ", "\t\n"] {
        let result = request_deduplication_with_instance_id_for_test(
            &json!({}),
            PluginHttpClient::default(),
            blank,
        );
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("blank plugin config id must fail closed"),
        };
        assert!(
            err.contains("plugin config id must be a non-empty stable identity"),
            "unexpected error for {blank:?}: {err}"
        );
    }
}

#[test]
fn production_factory_rejects_blank_plugin_config_id() {
    for blank in ["", "   ", "\t\n"] {
        let result = create_plugin_with_http_client_and_config_id(
            "request_deduplication",
            &json!({}),
            PluginHttpClient::default(),
            Some(blank),
        );
        let err = match result {
            Err(err) => err,
            Ok(_) => {
                panic!("blank plugin config id must fail closed through the production factory")
            }
        };
        assert!(
            err.contains("plugin config id must be a non-empty stable identity"),
            "unexpected error for {blank:?}: {err}"
        );
    }
}

#[test]
fn production_factory_without_config_id_keeps_direct_construction_coherent() {
    let via_default_factory = create_plugin_with_http_client(
        "request_deduplication",
        &json!({}),
        PluginHttpClient::default(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(via_default_factory.name(), "request_deduplication");
}

#[tokio::test]
async fn production_factory_partitions_logical_keys_by_plugin_config_id() {
    let config = json!({});
    let first = create_plugin_with_http_client_and_config_id(
        "request_deduplication",
        &config,
        PluginHttpClient::default(),
        Some("dedup-short"),
    )
    .unwrap()
    .unwrap();
    let sibling = create_plugin_with_http_client_and_config_id(
        "request_deduplication",
        &config,
        PluginHttpClient::default(),
        Some("dedup-long"),
    )
    .unwrap()
    .unwrap();
    let same_config_peer = create_plugin_with_http_client_and_config_id(
        "request_deduplication",
        &config,
        PluginHttpClient::default(),
        Some("dedup-short"),
    )
    .unwrap()
    .unwrap();
    let whitespace_distinct = create_plugin_with_http_client_and_config_id(
        "request_deduplication",
        &config,
        PluginHttpClient::default(),
        Some(" dedup-short "),
    )
    .unwrap()
    .unwrap();

    async fn logical_key(plugin: &Arc<dyn Plugin>) -> String {
        let mut ctx = body_ctx("POST", "/api/orders", b"{}");
        let mut headers = keyed_headers("shared-key", "api.example", 2);
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        let keys = request_deduplication_logical_keys_from_context_for_test(&ctx);
        assert_eq!(keys.len(), 1, "expected one acquired logical key");
        keys.into_iter().next().unwrap()
    }

    let first_key = logical_key(&first).await;
    let sibling_key = logical_key(&sibling).await;
    let peer_key = logical_key(&same_config_peer).await;
    let whitespace_distinct_key = logical_key(&whitespace_distinct).await;
    assert_ne!(
        first_key, sibling_key,
        "production factory must partition sibling plugin_config_id values"
    );
    assert_eq!(
        first_key, peer_key,
        "corresponding copies of one plugin_config_id must share Redis identity"
    );
    assert_ne!(
        first_key, whitespace_distinct_key,
        "distinct nonblank plugin_config_id bytes must not collapse after validation"
    );
}

#[test]
fn test_new_rejects_invalid_header_name() {
    let config = json!({
        "header_name": "not a header"
    });
    let result = RequestDeduplication::new(&config, PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("header_name"));
}

#[test]
fn test_new_rejects_invalid_numeric_and_bool_types() {
    for config in [
        json!({"ttl_seconds": "300"}),
        json!({"inflight_ttl_seconds": "300"}),
        json!({"max_entries": "100"}),
        json!({"max_entries": 0}),
        json!({"max_entry_size_bytes": "1024"}),
        json!({"max_entry_size_bytes": 0}),
        json!({"max_total_size_bytes": "1048576"}),
        json!({"max_total_size_bytes": 0}),
        json!({"scope_by_consumer": "true"}),
        json!({"enforce_required": "false"}),
    ] {
        let result = RequestDeduplication::new(&config, PluginHttpClient::default());
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
}

#[test]
fn test_new_rejects_invalid_applicable_methods() {
    for config in [
        json!({"applicable_methods": "POST"}),
        json!({"applicable_methods": ["POST", 123]}),
        json!({"applicable_methods": [""]}),
        json!({"applicable_methods": ["bad method"]}),
    ] {
        let result = RequestDeduplication::new(&config, PluginHttpClient::default());
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
}

#[test]
fn test_new_zero_ttl_fails() {
    let config = json!({
        "ttl_seconds": 0
    });
    let result = RequestDeduplication::new(&config, PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("ttl_seconds"));
}

#[test]
fn test_new_zero_inflight_ttl_fails() {
    let config = json!({
        "inflight_ttl_seconds": 0
    });
    let result = RequestDeduplication::new(&config, PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("inflight_ttl_seconds"));
}

#[test]
fn test_new_custom_inflight_ttl() {
    let config = json!({
        "ttl_seconds": 300,
        "inflight_ttl_seconds": 1800
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "request_deduplication");
}

#[test]
fn test_new_empty_methods_fails() {
    let config = json!({
        "applicable_methods": []
    });
    let result = RequestDeduplication::new(&config, PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("applicable_methods"));
}

#[test]
fn test_new_with_redis_config() {
    let config = json!({
        "sync_mode": "redis",
        "redis_url": "redis://dedup-redis.internal:6379/0",
        "redis_key_prefix": "dedup"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "request_deduplication");
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["dedup-redis.internal".to_string()]
    );
}

#[tokio::test]
async fn test_get_request_passes_through() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "abc-123".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_post_without_key_passes_through() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_enforce_required_rejects_missing_key() {
    let config = json!({
        "enforce_required": true
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert!(body.contains("idempotency"));
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                parsed["error"],
                "Missing required idempotency header: idempotency-key"
            );
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_first_request_passes_then_replay() {
    let config = json!({});
    let plugin = make_plugin(config);

    // First request with idempotency key — should pass through
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "key-1".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_identity(&plugin, &ctx1).is_some());

    // Simulate response caching
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let body = b"{\"id\": 123}";

    let _ = plugin
        .on_final_response_body(&mut ctx1, 201, &response_headers, body)
        .await;

    // Second request with same key — should replay
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "key-1".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
            ..
        } => {
            assert_eq!(status_code, 201);
            assert_eq!(headers.get("x-idempotent-replayed").unwrap(), "true");
            assert_eq!(&body[..], b"{\"id\": 123}");
            assert_eq!(
                ctx2.metadata
                    .get("request_deduplication.replayed")
                    .map(String::as_str),
                Some("true"),
                "replays must publish the bounded marker consumed by transcript audit"
            );
        }
        _ => panic!("Expected RejectBinary replay, got {:?}", result),
    }
}

#[tokio::test]
async fn committed_replay_skips_second_response_body_transform() {
    let dedup = make_plugin(json!({}));
    let mut first_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut first_headers =
        HashMap::from([("idempotency-key".to_string(), "finalized".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        dedup
            .on_final_response_body(
                &mut first_ctx,
                200,
                &HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
                b"presented-once",
            )
            .await,
        PluginResult::Continue
    ));

    let mut replay_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut replay_headers =
        HashMap::from([("idempotency-key".to_string(), "finalized".to_string())]);
    let replay = dedup
        .before_proxy(&mut replay_ctx, &mut replay_headers)
        .await;
    let transforms: Vec<Arc<dyn Plugin>> = vec![Arc::new(AppendingResponseTransform)];
    match finalize_plugin_rejection_for_test(&transforms, &mut replay_ctx, replay).await {
        PluginResult::RejectBinary { body, .. } => assert_eq!(&body[..], b"presented-once"),
        other => panic!("expected finalized replay, got {other:?}"),
    }
    assert_eq!(
        replay_ctx
            .metadata
            .get("test:replay-inspected")
            .map(String::as_str),
        Some("true"),
        "finalized replays must still run response inspection"
    );

    let mut ordinary_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let ordinary = PluginResult::RejectBinary {
        status_code: 200,
        body: Bytes::from_static(b"presented-once"),
        headers: HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
    };
    match finalize_plugin_rejection_for_test(&transforms, &mut ordinary_ctx, ordinary).await {
        PluginResult::RejectBinary { body, .. } => {
            assert_eq!(&body[..], b"presented-once|transformed")
        }
        other => panic!("expected ordinary transformed response, got {other:?}"),
    }
}

#[tokio::test]
async fn committed_replay_runs_current_ai_response_redaction() {
    let dedup = make_plugin(json!({}));
    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let stale_body = br#"{"choices":[{"message":{"content":"Contact user@example.com"}}]}"#;

    let mut first_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let mut first_headers =
        HashMap::from([("idempotency-key".to_string(), "guard-replay".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        dedup
            .on_final_response_body(&mut first_ctx, 200, &response_headers, stale_body)
            .await,
        PluginResult::Continue
    ));

    let guard = AiResponseGuard::new(&json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }))
    .unwrap();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(guard)];
    let mut replay_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let mut replay_headers =
        HashMap::from([("idempotency-key".to_string(), "guard-replay".to_string())]);
    let replay = dedup
        .before_proxy(&mut replay_ctx, &mut replay_headers)
        .await;

    match finalize_plugin_rejection_for_test(&plugins, &mut replay_ctx, replay).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert!(
                !body.contains("user@example.com"),
                "stale PII replayed: {body}"
            );
            assert!(body.contains("[REDACTED:pii:email]"), "{body}");
        }
        other => panic!("expected redacted finalized replay, got {other:?}"),
    }
}

#[tokio::test]
async fn committed_replay_runs_current_tool_argument_redaction() {
    let dedup = make_plugin(json!({}));
    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let stale_body = json!({
        "id": "chatcmpl-replay",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "filesystem.write",
                        "arguments": "{\"token\":\"sk-STALESECRET123\"}"
                    }
                }]
            }
        }]
    })
    .to_string()
    .into_bytes();

    let mut first_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let mut first_headers =
        HashMap::from([("idempotency-key".to_string(), "governor-replay".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        dedup
            .on_final_response_body(&mut first_ctx, 200, &response_headers, &stale_body)
            .await,
        PluginResult::Continue
    ));

    let governor = AiToolGovernor::new(
        &json!({
            "default_action": "allow",
            "tools": {
                "filesystem.write": {
                    "action": "redact_args",
                    "blocked_arg_patterns": [{
                        "name": "secret",
                        "regex": "sk-[A-Za-z0-9]+"
                    }]
                }
            }
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(governor)];
    let mut replay_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let mut replay_headers =
        HashMap::from([("idempotency-key".to_string(), "governor-replay".to_string())]);
    let replay = dedup
        .before_proxy(&mut replay_ctx, &mut replay_headers)
        .await;

    match finalize_plugin_rejection_for_test(&plugins, &mut replay_ctx, replay).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert!(
                !body.contains("sk-STALESECRET123"),
                "stale tool secret replayed: {body}"
            );
            assert!(body.contains("[REDACTED_TOOL_ARG:secret]"), "{body}");
        }
        other => panic!("expected governed finalized replay, got {other:?}"),
    }
}

#[tokio::test]
async fn committed_replay_fails_closed_when_required_transform_cannot_rewrite() {
    let dedup = make_plugin(json!({}));
    let mut first_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut first_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "failed-redaction".to_string(),
    )]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        dedup
            .on_final_response_body(
                &mut first_ctx,
                200,
                &HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
                b"sensitive replay",
            )
            .await,
        PluginResult::Continue
    ));

    let mut replay_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut replay_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "failed-redaction".to_string(),
    )]);
    let replay = dedup
        .before_proxy(&mut replay_ctx, &mut replay_headers)
        .await;
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(FailingMandatoryReplayTransform)];

    match finalize_plugin_rejection_for_test(&plugins, &mut replay_ctx, replay).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert_eq!(&body[..], br#"{"error":"response redaction failed"}"#);
        }
        other => panic!("required replay rewrite must fail closed, got {other:?}"),
    }
}

// Marker set by the proxy on `ctx.metadata` while the response-body hooks run
// over a synthetic 2xx plugin short-circuit body (mirrors
// `crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY`, which is `pub(crate)` and
// therefore not reachable from this external test crate).
const SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY: &str = "ferrum:synthetic_short_circuit";

// Marker set by an ownership producer (e.g. `ai_federation`) on `ctx.metadata`
// once a billable/side-effecting external operation has a committed or ambiguous
// outcome behind a synthetic short-circuit (mirrors the `pub(crate)`
// `crate::plugins::EXTERNAL_OPERATION_COMPLETED_METADATA_KEY`, which is not
// reachable from this external test crate).
const EXTERNAL_OPERATION_COMPLETED_METADATA_KEY: &str = "ferrum:external_operation_completed";

// A FRESH request that this plugin marked in-flight, then short-circuited by a
// LATER `before_proxy` plugin (e.g. a 2xx `fault_injection` abort / synthetic AI
// response), must NOT have its synthetic body stored under the idempotency key.
// A subsequent request with the same key must be treated as a brand-new request
// (Continue), not replayed from a poisoned cache entry.
#[tokio::test]
async fn synthetic_short_circuit_2xx_is_not_stored_under_dedup_key() {
    let plugin = make_plugin(json!({}));

    // First request acquires the in-flight marker and a dedup key.
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "key-1".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_identity(&plugin, &ctx1).is_some());

    // A later before_proxy plugin short-circuits with a synthetic 2xx body. The
    // proxy marks the context before running the response-body hooks; emulate it.
    ctx1.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let result = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"{\"synthetic\": true}")
        .await;
    assert!(matches!(result, PluginResult::Continue));

    // Nothing was cached: no completed-response bytes are retained, and the
    // in-flight marker was released (not left dangling until TTL).
    assert_eq!(
        assert_completed_size_exact(&plugin),
        0,
        "synthetic short-circuit body must not be stored as a completed response"
    );

    // A second request with the SAME key is treated as Fresh — it passes
    // through to the backend rather than replaying the synthetic body.
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "key-1".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "second request with same key must pass through, not replay a synthetic body; got {result:?}"
    );
    assert!(request_identity(&plugin, &ctx2).is_some());
}

// Marker set by the shared H1/H2/H3 reject finalizer for every finalized
// successful HTTP 2xx synthetic short-circuit (including empty 200 and 204), independent
// of whether synthetic response-body hooks ran. Mirrors
// `crate::proxy::FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY`.
const FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY: &str = "ferrum:finalized_synthetic_response";

async fn finalize_empty_synthetic_and_assert_second_request_continues(
    status_code: u16,
    idempotency_key: &str,
) {
    let dedup = Arc::new(make_plugin(json!({})));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&dedup) as Arc<dyn Plugin>];

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), idempotency_key.to_string());
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(request_identity(&dedup, &ctx).is_some());

    let finalized = finalize_plugin_rejection_for_test(
        &plugins,
        &mut ctx,
        PluginResult::Reject {
            status_code,
            body: String::new(),
            headers: HashMap::new(),
        },
    )
    .await;
    match finalized {
        PluginResult::RejectBinary {
            status_code: final_status,
            ..
        } => assert_eq!(final_status, status_code),
        other => panic!("expected finalized RejectBinary, got {other:?}"),
    }
    assert!(
        !ctx.metadata
            .contains_key(FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY),
        "internal finalized-synthetic signal must be consumed before transaction logging"
    );
    assert_eq!(
        assert_completed_size_exact(&dedup),
        0,
        "empty/204 synthetic successes must not be stored as completed responses"
    );

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut retry_headers = HashMap::new();
    retry_headers.insert("idempotency-key".to_string(), idempotency_key.to_string());
    let retry = dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await;
    assert!(
        matches!(retry, PluginResult::Continue),
        "identical request after finalized empty/204 synthetic success must not see a stale 409; got {retry:?}"
    );
}

#[tokio::test]
async fn empty_synthetic_200_releases_dedup_inflight_via_finalized_signal() {
    finalize_empty_synthetic_and_assert_second_request_continues(200, "empty-200-key").await;
}

#[tokio::test]
async fn synthetic_204_releases_dedup_inflight_via_finalized_signal() {
    finalize_empty_synthetic_and_assert_second_request_continues(204, "empty-204-key").await;
}

#[tokio::test]
async fn h3_deferred_committed_hooks_keep_finalized_signal_for_empty_synthetic_success() {
    let dedup = Arc::new(make_plugin(json!({})));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&dedup) as Arc<dyn Plugin>];

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert(
        "idempotency-key".to_string(),
        "h3-empty-204-key".to_string(),
    );
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let finalized = finalize_plugin_rejection_without_committed_hooks_for_test(
        &plugins,
        &mut ctx,
        PluginResult::Reject {
            status_code: 204,
            body: String::new(),
            headers: HashMap::new(),
        },
    )
    .await;
    assert!(matches!(
        finalized,
        PluginResult::RejectBinary {
            status_code: 204,
            ..
        }
    ));
    assert!(
        ctx.metadata
            .contains_key(FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY),
        "H3 finalizer mode must preserve the marker for its later committed-hook phase"
    );

    dedup
        .on_response_committed(&mut ctx, 204, &HashMap::new(), &[])
        .await;
    ctx.metadata
        .remove(FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY);

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut retry_headers = HashMap::new();
    retry_headers.insert(
        "idempotency-key".to_string(),
        "h3-empty-204-key".to_string(),
    );
    let retry = dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await;
    assert!(
        matches!(retry, PluginResult::Continue),
        "later H3 committed hook must release in-flight ownership; got {retry:?}"
    );
}

#[tokio::test]
async fn non_2xx_plugin_reject_retains_dedup_inflight_until_ttl() {
    let dedup = Arc::new(make_plugin(json!({
        "inflight_ttl_seconds": 60,
        "ttl_seconds": 60
    })));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&dedup) as Arc<dyn Plugin>];

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert(
        "idempotency-key".to_string(),
        "non-2xx-retain-key".to_string(),
    );
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let finalized = finalize_plugin_rejection_for_test(
        &plugins,
        &mut ctx,
        PluginResult::Reject {
            status_code: 503,
            body: r#"{"error":"upstream unavailable"}"#.to_string(),
            headers: HashMap::new(),
        },
    )
    .await;
    assert!(matches!(
        finalized,
        PluginResult::RejectBinary {
            status_code: 503,
            ..
        }
    ));
    assert!(
        !ctx.metadata
            .contains_key(FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY),
        "non-2xx rejects must not set the finalized-synthetic success signal"
    );

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut retry_headers = HashMap::new();
    retry_headers.insert(
        "idempotency-key".to_string(),
        "non-2xx-retain-key".to_string(),
    );
    assert!(
        matches!(
            dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "non-2xx downstream rejection must intentionally retain in-flight ownership until TTL"
    );

    request_deduplication_expire_inflight_entries_for_test(&dedup);
    let mut after_ttl_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut after_ttl_headers = HashMap::new();
    after_ttl_headers.insert(
        "idempotency-key".to_string(),
        "non-2xx-retain-key".to_string(),
    );
    assert!(matches!(
        dedup
            .before_proxy(&mut after_ttl_ctx, &mut after_ttl_headers)
            .await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn late_finalized_synthetic_release_does_not_clear_successor_marker() {
    let dedup = Arc::new(make_plugin(json!({
        "inflight_ttl_seconds": 1,
        "ttl_seconds": 60
    })));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&dedup) as Arc<dyn Plugin>];

    let mut first_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut first_headers = HashMap::new();
    first_headers.insert(
        "idempotency-key".to_string(),
        "successor-safe-key".to_string(),
    );
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));

    // Simulate the original request dying without committing; TTL cleanup makes
    // the key available for a successor with a new owner token.
    request_deduplication_expire_inflight_entries_for_test(&dedup);

    let mut successor_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut successor_headers = HashMap::new();
    successor_headers.insert(
        "idempotency-key".to_string(),
        "successor-safe-key".to_string(),
    );
    assert!(matches!(
        dedup
            .before_proxy(&mut successor_ctx, &mut successor_headers)
            .await,
        PluginResult::Continue
    ));

    // A late finalizer for the original request still carries that request's
    // ownership state. Token matching must leave the successor's marker intact.
    let _ = finalize_plugin_rejection_for_test(
        &plugins,
        &mut first_ctx,
        PluginResult::Reject {
            status_code: 200,
            body: String::new(),
            headers: HashMap::new(),
        },
    )
    .await;

    let mut conflict_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut conflict_headers = HashMap::new();
    conflict_headers.insert(
        "idempotency-key".to_string(),
        "successor-safe-key".to_string(),
    );
    assert!(
        matches!(
            dedup
                .before_proxy(&mut conflict_ctx, &mut conflict_headers)
                .await,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "late finalized-synthetic release must not clear a successor's in-flight marker"
    );
}

// A FRESH request marked in-flight by this plugin, then short-circuited by a
// synthetic response AFTER a committed/ambiguous external operation (the
// `ai_federation` provider-call lifecycle), must not release the in-flight
// marker on the early final-body pass and must not cache the synthetic body.
// Instead the observe-only committed hook publishes a non-replayable 409
// tombstone so an identical retry is rejected deterministically for the cache
// TTL rather than either re-running the side effect (fresh) or eating a bare
// "already in progress" in-flight conflict. This isolates the shared dedup
// lifecycle exercised end-to-end by the `ai_federation` suite, without the
// federation plugin, so a future dedup refactor cannot silently drop it again.
#[tokio::test]
async fn external_operation_completed_publishes_non_replayable_tombstone_at_commit() {
    let plugin = make_plugin(json!({}));

    // First request acquires the in-flight marker and a dedup key.
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "ext-op-key".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx1, &mut headers1).await,
        PluginResult::Continue
    ));
    assert!(request_identity(&plugin, &ctx1).is_some());

    // The proxy marks the synthetic short-circuit before running the response
    // body hooks; the external-operation marker is what a committed provider
    // call sets. The early final-body pass must retain ownership: it neither
    // stores the synthetic body nor releases the in-flight marker.
    ctx1.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    ctx1.metadata.insert(
        EXTERNAL_OPERATION_COMPLETED_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    assert!(matches!(
        plugin
            .on_final_response_body(&mut ctx1, 200, &response_headers, b"{\"synthetic\": true}")
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        assert_completed_size_exact(&plugin),
        0,
        "synthetic external-operation body must not be stored as a replayable response"
    );

    // The proxy clears the synthetic marker before the committed hook. The
    // observe-only committed hook then publishes the non-replayable tombstone.
    ctx1.metadata.remove(SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY);
    plugin
        .on_response_committed(&mut ctx1, 200, &response_headers, b"{\"synthetic\": true}")
        .await;

    // A retry with the SAME key must be rejected as a completed non-replayable
    // operation (409 "cannot be replayed safely"), NOT treated as fresh (which
    // would re-run the side effect) and NOT returned as a bare in-flight 409.
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "ext-op-key".to_string());
    match plugin.before_proxy(&mut ctx2, &mut headers2).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 409);
            assert!(
                String::from_utf8_lossy(&body).contains("cannot be replayed safely"),
                "retry after a committed external operation must return the non-replayable tombstone, got {}",
                String::from_utf8_lossy(&body)
            );
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
        }
        other => panic!("expected non-replayable completed tombstone, got {other:?}"),
    }
}

#[tokio::test]
async fn terminal_serverless_remote_502_is_stored_at_response_commit() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(502).set_body_string("executed-once"))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut first_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut first_headers = HashMap::new();
    first_headers.insert("idempotency-key".to_string(), "side-effect-key".to_string());
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) = match serverless
        .before_proxy(&mut first_ctx, &mut first_headers)
        .await
    {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
        } => (status_code, headers, body),
        other => panic!("expected terminal serverless response, got {other:?}"),
    };
    assert_eq!(status, 502);
    assert!(dedup.requires_response_committed_hook());
    dedup
        .on_response_committed(&mut first_ctx, status, &response_headers, &body)
        .await;

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut retry_headers = HashMap::new();
    retry_headers.insert("idempotency-key".to_string(), "side-effect-key".to_string());
    match dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 502);
            assert_eq!(&body[..], b"executed-once");
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
        }
        other => panic!("retry must replay without invoking again, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn terminal_serverless_completion_is_owned_by_every_dedup_instance() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503).set_body_string("one-side-effect"))
        .mount(&server)
        .await;

    let first = make_plugin(json!({"header_name": "idempotency-key-a"}));
    let second = make_plugin(json!({"header_name": "idempotency-key-b"}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::from([
        ("idempotency-key-a".to_string(), "owner-a".to_string()),
        ("idempotency-key-b".to_string(), "owner-b".to_string()),
    ]);
    for plugin in [&first, &second] {
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
    }

    let (status, response_headers, body) =
        match serverless.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::RejectBinary {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("expected terminal serverless response, got {other:?}"),
        };
    assert_eq!(status, 503);

    // The ordinary final-body phase must leave both owners pending until the
    // settled committed terminal response is available.
    for plugin in [&first, &second] {
        assert!(matches!(
            plugin
                .on_final_response_body(&mut ctx, status, &response_headers, &body)
                .await,
            PluginResult::Continue
        ));
        assert_eq!(plugin.tracked_keys_count(), Some(1));
    }

    // Each committed hook consumes only its own provenance and publishes into
    // its own cache. The first hook must not clear the second owner's marker.
    first
        .on_response_committed(&mut ctx, status, &response_headers, &body)
        .await;
    second
        .on_response_committed(&mut ctx, status, &response_headers, &body)
        .await;

    for (plugin, header_name, key) in [
        (&first, "idempotency-key-a", "owner-a"),
        (&second, "idempotency-key-b", "owner-b"),
    ] {
        let mut retry_ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/api".to_string(),
        );
        let mut retry_headers = HashMap::from([
            ("idempotency-key-a".to_string(), "owner-a".to_string()),
            ("idempotency-key-b".to_string(), "owner-b".to_string()),
        ]);
        assert_eq!(
            retry_headers.get(header_name).map(String::as_str),
            Some(key)
        );
        match plugin
            .before_proxy(&mut retry_ctx, &mut retry_headers)
            .await
        {
            PluginResult::RejectBinary {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 503);
                assert_eq!(&body[..], b"one-side-effect");
            }
            other => panic!("instance {header_name} did not retain its replay: {other:?}"),
        }
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn terminal_serverless_ambiguous_query_releases_every_dedup_owner() {
    let first = make_plugin(json!({}));
    let second = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://function.example/invoke",
            "mode": "terminate",
            "forward_query_params": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.set_raw_query_string("role=user&role=admin".to_string());
    let mut headers = HashMap::from([("idempotency-key".to_string(), "correctable".to_string())]);
    for dedup in [&first, &second] {
        assert!(matches!(
            dedup.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
    }
    let (status, response_headers, body) =
        match serverless.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("ambiguous query must reject before invocation, got {other:?}"),
        };
    assert!(body.contains("duplicate_query_parameter"));
    for dedup in [&first, &second] {
        dedup
            .on_response_committed(&mut ctx, status, &response_headers, body.as_bytes())
            .await;
    }

    for dedup in [&first, &second] {
        let mut retry_ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/api".to_string(),
        );
        retry_ctx.set_raw_query_string("role=user&role=admin".to_string());
        let mut retry_headers =
            HashMap::from([("idempotency-key".to_string(), "correctable".to_string())]);
        assert!(matches!(
            dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
            PluginResult::Continue
        ));
    }
}

#[tokio::test]
async fn terminal_serverless_encoded_body_releases_dedup_owner() {
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://function.example/invoke",
            "mode": "terminate",
            "forward_body": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let compressed = gzip_body(b"opaque");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.request_body_bytes = Some(Bytes::copy_from_slice(&compressed));
    let mut headers = HashMap::from([
        ("idempotency-key".to_string(), "encoded".to_string()),
        ("content-encoding".to_string(), "gzip".to_string()),
        ("content-length".to_string(), compressed.len().to_string()),
    ]);
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match serverless.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("encoded body must reject before invocation, got {other:?}"),
        };
    assert!(body.contains("encoded_request_body_unsupported"));
    dedup
        .on_response_committed(&mut ctx, status, &response_headers, body.as_bytes())
        .await;

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    retry_ctx.request_body_bytes = Some(Bytes::from(compressed.clone()));
    let mut retry_headers = HashMap::from([
        ("idempotency-key".to_string(), "encoded".to_string()),
        ("content-encoding".to_string(), "gzip".to_string()),
        ("content-length".to_string(), compressed.len().to_string()),
    ]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn terminal_serverless_origin_encoded_marker_releases_dedup_owner() {
    // A header-only request_transformer that stripped Content-Encoding leaves
    // the live header map identity-clean, but the init-time marker preserves the
    // original non-identity coding, so the serverless egress still fails closed —
    // and because nothing external ran, the dedup in-flight lock is released.
    const ORIGIN_ENCODED_REQUEST_METADATA_KEY: &str = "ferrum:origin_encoded_request";

    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://function.example/invoke",
            "mode": "terminate",
            "forward_body": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.request_body_bytes = Some(Bytes::from_static(b"opaque-compressed"));
    ctx.metadata.insert(
        ORIGIN_ENCODED_REQUEST_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    // No content-encoding on the live map — the transformer removed it.
    let mut headers = HashMap::from([("idempotency-key".to_string(), "stripped".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match serverless.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("stripped-but-original encoding must reject, got {other:?}"),
        };
    assert!(body.contains("encoded_request_body_unsupported"));
    dedup
        .on_response_committed(&mut ctx, status, &response_headers, body.as_bytes())
        .await;

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    retry_ctx.request_body_bytes = Some(Bytes::from_static(b"opaque-compressed"));
    let mut retry_headers =
        HashMap::from([("idempotency-key".to_string(), "stripped".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn terminal_serverless_query_transform_releases_dedup_owner() {
    // A request_transformer query rule recorded a decoded-query transform that
    // the raw-query payload cannot faithfully honor. The serverless egress fails
    // closed before any external call, so the dedup in-flight lock is released.
    const QUERY_PARAMS_TRANSFORMED_METADATA_KEY: &str = "ferrum:query_params_transformed";

    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://function.example/invoke",
            "mode": "terminate",
            "forward_query_params": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    // Raw query is otherwise valid; the transform marker alone drives the reject.
    ctx.set_raw_query_string("page=1&sort=asc".to_string());
    ctx.metadata.insert(
        QUERY_PARAMS_TRANSFORMED_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::from([("idempotency-key".to_string(), "transformed".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match serverless.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("transformed-query composition must reject, got {other:?}"),
        };
    assert!(body.contains("query_params_transformed"));
    dedup
        .on_response_committed(&mut ctx, status, &response_headers, body.as_bytes())
        .await;

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    retry_ctx.set_raw_query_string("page=1&sort=asc".to_string());
    retry_ctx.metadata.insert(
        QUERY_PARAMS_TRANSFORMED_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    let mut retry_headers =
        HashMap::from([("idempotency-key".to_string(), "transformed".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn terminal_serverless_pre_wire_invocation_failure_releases_dedup_owner() {
    // A proven pre-wire transport failure (connection refused: nothing reached
    // the function) must release the dedup in-flight lock rather than retain the
    // anticipatory side-effect marker, so an identical retry is not blocked/
    // replayed until inflight_ttl for an operation that never ran.
    let closed_addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    // Listener dropped above — the port is now refused.

    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("http://{closed_addr}/invoke"),
            "mode": "terminate",
            "timeout_ms": 2000
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::from([("idempotency-key".to_string(), "pre-wire".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match serverless.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("pre-wire failure must reject, got {other:?}"),
        };
    assert!(body.contains("invocation_failed"));
    dedup
        .on_response_committed(&mut ctx, status, &response_headers, body.as_bytes())
        .await;

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut retry_headers =
        HashMap::from([("idempotency-key".to_string(), "pre-wire".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn terminal_serverless_literal_ip_egress_denial_releases_dedup_owner() {
    let policy = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).unwrap();
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "http://169.254.169.254/invoke",
            "mode": "terminate"
        }),
        PluginHttpClient::default_with_backend_allow_ips(policy),
    )
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers =
        HashMap::from([("idempotency-key".to_string(), "literal-denial".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match serverless.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("literal-IP denial must reject pre-wire, got {other:?}"),
        };
    assert!(body.contains("invocation_failed"));
    dedup
        .on_response_committed(&mut ctx, status, &response_headers, body.as_bytes())
        .await;

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut retry_headers =
        HashMap::from([("idempotency-key".to_string(), "literal-denial".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn terminal_replay_survives_active_capacity_then_becomes_tombstone() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("side-effect-result"))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({
        "max_entries": 1,
        "ttl_seconds": 300,
        "inflight_ttl_seconds": 300
    }));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut first_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut first_headers =
        HashMap::from([("idempotency-key".to_string(), "terminal-a".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) = match serverless
        .before_proxy(&mut first_ctx, &mut first_headers)
        .await
    {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
        } => (status_code, headers, body),
        other => panic!("expected terminal serverless response, got {other:?}"),
    };

    // A distinct active request saturates max_entries before the terminal
    // response publishes. The owned completion must remain replayable instead
    // of being selected as the only capacity-eviction candidate.
    let mut second_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/other".to_string(),
    );
    let mut second_headers =
        HashMap::from([("idempotency-key".to_string(), "ordinary-b".to_string())]);
    assert!(matches!(
        dedup
            .before_proxy(&mut second_ctx, &mut second_headers)
            .await,
        PluginResult::Continue
    ));
    assert!(matches!(
        dedup
            .on_final_response_body(&mut first_ctx, status, &response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    dedup
        .on_response_committed(&mut first_ctx, status, &response_headers, &body)
        .await;

    let mut replay_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut replay_headers =
        HashMap::from([("idempotency-key".to_string(), "terminal-a".to_string())]);
    match dedup
        .before_proxy(&mut replay_ctx, &mut replay_headers)
        .await
    {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(&body[..], b"side-effect-result");
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
        }
        other => panic!("owned completion was not replayable under active pressure: {other:?}"),
    }

    // Once the other request completes, strict capacity can no longer retain
    // both responses. Evicting the protected terminal replay must leave an
    // in-flight tombstone, so a later Redis outage/lock expiry cannot allow the
    // external side effect to execute again.
    complete_response(&dedup, &mut second_ctx).await;
    let mut tombstone_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut tombstone_headers =
        HashMap::from([("idempotency-key".to_string(), "terminal-a".to_string())]);
    assert!(matches!(
        dedup
            .before_proxy(&mut tombstone_ctx, &mut tombstone_headers)
            .await,
        PluginResult::Reject {
            status_code: 409,
            ..
        }
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn oversized_terminal_serverless_response_retains_inflight_protection() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 128]))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({"max_entry_size_bytes": 32}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut first_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut first_headers =
        HashMap::from([("idempotency-key".to_string(), "oversized-key".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) = match serverless
        .before_proxy(&mut first_ctx, &mut first_headers)
        .await
    {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
        } => (status_code, headers, body),
        other => panic!("expected oversized terminal response, got {other:?}"),
    };
    dedup
        .on_response_committed(&mut first_ctx, status, &response_headers, &body)
        .await;
    assert_eq!(dedup.tracked_keys_count(), Some(1));

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut retry_headers =
        HashMap::from([("idempotency-key".to_string(), "oversized-key".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Reject {
            status_code: 409,
            ..
        }
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn oversized_buffered_fallback_retains_uncertain_serverless_protection() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(600).set_body_string("invalid status"))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({"max_entry_size_bytes": 32}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate",
            "on_error": "continue"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut first_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut first_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "oversized-fallback-key".to_string(),
    )]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        serverless
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));

    let backend_body = vec![b'y'; 128];
    assert!(matches!(
        dedup
            .on_final_response_body(&mut first_ctx, 200, &HashMap::new(), &backend_body)
            .await,
        PluginResult::Continue
    ));
    dedup
        .on_response_committed(&mut first_ctx, 200, &HashMap::new(), &backend_body)
        .await;
    assert_eq!(dedup.tracked_keys_count(), Some(1));

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut retry_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "oversized-fallback-key".to_string(),
    )]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Reject {
            status_code: 409,
            ..
        }
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn multiple_instances_release_only_their_own_inflight_ownership() {
    let first = make_plugin(json!({"header_name": "Idempotency-Key"}));
    let second = make_plugin(json!({"header_name": "Idempotency-Key"}));
    let mut ctx = body_ctx("POST", "/api", br#"{"value":1}"#);
    let mut headers = keyed_headers("shared-key", "example.test", 11);

    assert!(matches!(
        first.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        second.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    ctx.metadata.insert(
        "ferrum:release_dedup_inflight_on_commit".to_string(),
        "true".to_string(),
    );
    first
        .on_response_committed(&mut ctx, 503, &HashMap::new(), b"rejected")
        .await;

    let mut first_retry_ctx = body_ctx("POST", "/api", br#"{"value":1}"#);
    let mut first_retry_headers = keyed_headers("shared-key", "example.test", 11);
    assert!(matches!(
        first
            .before_proxy(&mut first_retry_ctx, &mut first_retry_headers)
            .await,
        PluginResult::Continue
    ));

    let mut second_retry_ctx = body_ctx("POST", "/api", br#"{"value":1}"#);
    let mut second_retry_headers = keyed_headers("shared-key", "example.test", 11);
    assert!(matches!(
        second
            .before_proxy(&mut second_retry_ctx, &mut second_retry_headers)
            .await,
        PluginResult::Reject {
            status_code: 409,
            ..
        }
    ));

    second
        .on_response_committed(&mut ctx, 503, &HashMap::new(), b"rejected")
        .await;
}

/// Two proxy-scoped instances with distinct headers must each complete and
/// release their own ownership. Before #2378, shared request-metadata slots
/// meant the earlier instance retained a stale in-flight marker after a
/// successful response.
async fn two_instances_buffered_completion_releases_independently(
    first: RequestDeduplication,
    second: RequestDeduplication,
) {
    let body = br#"{"order":1}"#;
    let mut ctx = body_ctx("POST", "/orders", body);
    let mut headers = dual_keyed_headers("key-a", "key-b", "orders.example", body.len());
    mark_both_fresh(&first, &second, &mut ctx, &mut headers).await;
    assert_eq!(first.tracked_keys_count(), Some(1));
    assert_eq!(second.tracked_keys_count(), Some(1));

    complete_response(&first, &mut ctx).await;
    assert!(
        request_identity(&first, &ctx).is_none(),
        "first instance must consume only its own completion state"
    );
    assert!(
        request_identity(&second, &ctx).is_some(),
        "second instance must retain its ownership after the first completes"
    );
    complete_response(&second, &mut ctx).await;
    assert!(request_identity(&second, &ctx).is_none());
    assert_eq!(first.tracked_keys_count(), Some(1));
    assert_eq!(second.tracked_keys_count(), Some(1));

    let mut retry_a = body_ctx("POST", "/orders", body);
    let mut retry_a_headers = dual_keyed_headers("key-a", "key-b", "orders.example", body.len());
    match first.before_proxy(&mut retry_a, &mut retry_a_headers).await {
        PluginResult::RejectBinary {
            status_code,
            headers: response_headers,
            ..
        } => {
            assert_eq!(status_code, 201);
            assert_eq!(
                response_headers
                    .get("x-idempotent-replayed")
                    .map(String::as_str),
                Some("true"),
                "repeated key A must observe completed replay, not a stale 409"
            );
        }
        other => panic!("expected completed replay for key A, got {other:?}"),
    }

    let mut retry_b = body_ctx("POST", "/orders", body);
    let mut retry_b_headers = dual_keyed_headers("key-a", "key-b", "orders.example", body.len());
    match second
        .before_proxy(&mut retry_b, &mut retry_b_headers)
        .await
    {
        PluginResult::RejectBinary {
            status_code,
            headers: response_headers,
            ..
        } => {
            assert_eq!(status_code, 201);
            assert_eq!(
                response_headers
                    .get("x-idempotent-replayed")
                    .map(String::as_str),
                Some("true"),
                "repeated key B must observe completed replay, not a stale 409"
            );
        }
        other => panic!("expected completed replay for key B, got {other:?}"),
    }
}

#[tokio::test]
async fn two_instances_distinct_headers_local_buffered_completion_releases_independently() {
    two_instances_buffered_completion_releases_independently(
        make_local_sibling("Idempotency-Key", "dedup-a"),
        make_local_sibling("X-Operation-Key", "dedup-b"),
    )
    .await;
}

#[tokio::test]
async fn two_instances_distinct_headers_redis_prefixed_buffered_completion_releases_independently()
{
    two_instances_buffered_completion_releases_independently(
        make_redis_sibling("Idempotency-Key", "dedup-a", "orders:dedup:a"),
        make_redis_sibling("X-Operation-Key", "dedup-b", "orders:dedup:b"),
    )
    .await;
}

async fn two_instances_streamed_completion_releases_independently(
    first: RequestDeduplication,
    second: RequestDeduplication,
) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut headers = dual_keyed_headers("stream-a", "stream-b", "orders.example", 0);
    mark_both_fresh(&first, &second, &mut ctx, &mut headers).await;
    assert!(first.should_buffer_response_body(&ctx));
    assert!(second.should_buffer_response_body(&ctx));
    assert!(!first.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));
    assert!(!second.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));

    first
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(16))
        .await;
    assert!(
        request_identity(&first, &ctx).is_none(),
        "clean stream end must release only the first instance's ownership"
    );
    assert!(request_identity(&second, &ctx).is_some());
    assert_eq!(first.tracked_keys_count(), Some(0));
    assert_eq!(second.tracked_keys_count(), Some(1));

    second
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(16))
        .await;
    assert!(request_identity(&second, &ctx).is_none());
    assert_eq!(second.tracked_keys_count(), Some(0));

    let mut retry_a = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut retry_a_headers = dual_keyed_headers("stream-a", "stream-b", "orders.example", 0);
    assert!(
        matches!(
            first.before_proxy(&mut retry_a, &mut retry_a_headers).await,
            PluginResult::Continue
        ),
        "clean streamed completion must not leave a stale in-flight conflict for key A"
    );

    let mut retry_b = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut retry_b_headers = dual_keyed_headers("stream-a", "stream-b", "orders.example", 0);
    assert!(
        matches!(
            second
                .before_proxy(&mut retry_b, &mut retry_b_headers)
                .await,
            PluginResult::Continue
        ),
        "clean streamed completion must not leave a stale in-flight conflict for key B"
    );
}

#[tokio::test]
async fn two_instances_distinct_headers_local_streamed_completion_releases_independently() {
    two_instances_streamed_completion_releases_independently(
        make_local_sibling("Idempotency-Key", "dedup-a"),
        make_local_sibling("X-Operation-Key", "dedup-b"),
    )
    .await;
}

#[tokio::test]
async fn two_instances_distinct_headers_redis_prefixed_streamed_completion_releases_independently()
{
    two_instances_streamed_completion_releases_independently(
        make_redis_sibling("Idempotency-Key", "dedup-a", "orders:dedup:a"),
        make_redis_sibling("X-Operation-Key", "dedup-b", "orders:dedup:b"),
    )
    .await;
}

async fn two_instances_interrupted_stream_retains_independently(
    first: RequestDeduplication,
    second: RequestDeduplication,
) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut headers = dual_keyed_headers("hold-a", "hold-b", "orders.example", 0);
    mark_both_fresh(&first, &second, &mut ctx, &mut headers).await;

    first
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::client_disconnect(8))
        .await;
    assert!(
        request_identity(&first, &ctx).is_some(),
        "interrupted stream must retain first-instance ownership until TTL"
    );
    assert!(
        request_identity(&second, &ctx).is_some(),
        "first instance's interrupted stream must not consume the second instance's state"
    );
    assert_eq!(first.tracked_keys_count(), Some(1));
    assert_eq!(second.tracked_keys_count(), Some(1));

    second
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::client_disconnect(8))
        .await;
    assert!(request_identity(&second, &ctx).is_some());
    assert_eq!(second.tracked_keys_count(), Some(1));

    let mut retry_a = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut retry_a_headers = dual_keyed_headers("hold-a", "hold-b", "orders.example", 0);
    assert!(
        matches!(
            first.before_proxy(&mut retry_a, &mut retry_a_headers).await,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "interrupted stream for key A must keep blocking retries until TTL"
    );

    let mut retry_b = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    let mut retry_b_headers = dual_keyed_headers("hold-a", "hold-b", "orders.example", 0);
    assert!(
        matches!(
            second
                .before_proxy(&mut retry_b, &mut retry_b_headers)
                .await,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "interrupted stream for key B must keep blocking retries until TTL"
    );
}

#[tokio::test]
async fn two_instances_distinct_headers_local_interrupted_stream_retains_independently() {
    two_instances_interrupted_stream_retains_independently(
        make_local_sibling("Idempotency-Key", "dedup-a"),
        make_local_sibling("X-Operation-Key", "dedup-b"),
    )
    .await;
}

#[tokio::test]
async fn two_instances_distinct_headers_redis_prefixed_interrupted_stream_retains_independently() {
    two_instances_interrupted_stream_retains_independently(
        make_redis_sibling("Idempotency-Key", "dedup-a", "orders:dedup:a"),
        make_redis_sibling("X-Operation-Key", "dedup-b", "orders:dedup:b"),
    )
    .await;
}

#[tokio::test]
async fn test_concurrent_duplicate_returns_conflict() {
    let config = json!({});
    let plugin = make_plugin(config);

    // First request marks key as in-flight
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "inflight-key".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));

    // Second request with same key while first is still in-flight
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "inflight-key".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 409);
            assert!(body.contains("already in progress"));
        }
        _ => panic!("Expected 409 Conflict"),
    }
}

#[tokio::test]
async fn test_concurrent_first_requests_only_one_reaches_backend() {
    let plugin = Arc::new(make_plugin(json!({})));
    let barrier = Arc::new(Barrier::new(16));
    let mut handles = Vec::new();

    for _ in 0..16 {
        let plugin = Arc::clone(&plugin);
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            let mut ctx = RequestContext::new(
                "127.0.0.1".to_string(),
                "POST".to_string(),
                "/api".to_string(),
            );
            let mut headers = HashMap::new();
            headers.insert("idempotency-key".to_string(), "race-key".to_string());

            barrier.wait().await;
            plugin.before_proxy(&mut ctx, &mut headers).await
        }));
    }

    let mut continues = 0;
    let mut conflicts = 0;
    for handle in handles {
        match handle.await.unwrap() {
            PluginResult::Continue => continues += 1,
            PluginResult::Reject {
                status_code: 409, ..
            } => conflicts += 1,
            other => panic!("unexpected result: {other:?}"),
        }
    }

    assert_eq!(continues, 1);
    assert_eq!(conflicts, 15);
}

#[tokio::test]
async fn test_different_keys_independent() {
    let config = json!({});
    let plugin = make_plugin(config);

    // First request
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "key-a".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));

    // Different key — should also pass
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "key-b".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_put_method_deduplicates() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "PUT".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "put-key".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_identity(&plugin, &ctx).is_some());
}

#[tokio::test]
async fn test_custom_applicable_methods() {
    let config = json!({
        "applicable_methods": ["DELETE"]
    });
    let plugin = make_plugin(config);

    // POST should pass through (not in applicable_methods)
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "key-1".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_identity(&plugin, &ctx).is_none());

    // DELETE should be deduplication-eligible
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "DELETE".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "key-2".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_identity(&plugin, &ctx2).is_some());
}

#[test]
fn test_requires_response_body_buffering() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert!(plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_response_buffering_only_for_fresh_dedup_keys() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut get_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    let mut get_headers = HashMap::new();
    get_headers.insert("idempotency-key".to_string(), "get-key".to_string());
    let result = plugin.before_proxy(&mut get_ctx, &mut get_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!plugin.should_buffer_response_body(&get_ctx));

    let mut keyless_post_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut keyless_post_headers = HashMap::new();
    let result = plugin
        .before_proxy(&mut keyless_post_ctx, &mut keyless_post_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!plugin.should_buffer_response_body(&keyless_post_ctx));

    let mut keyed_post_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut keyed_post_headers = HashMap::new();
    keyed_post_headers.insert("idempotency-key".to_string(), "post-key".to_string());
    let result = plugin
        .before_proxy(&mut keyed_post_ctx, &mut keyed_post_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.should_buffer_response_body(&keyed_post_ctx));
}

#[tokio::test]
async fn test_response_buffering_releases_event_stream_content_type() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "stream-key".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &HashMap::new()
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));
}

/// A keyed request whose response is streamed as `text/event-stream` is handed
/// to the client incrementally, so `on_final_response_body` (which transitions
/// the `InFlight` marker to a cached `Completed` entry) never runs. On a clean
/// stream completion the marker stays in-flight for the lifetime of the stream,
/// then `on_response_stream_terminated` releases it without storing a replay
/// body — so the next matching key re-executes instead of eating a stale 409
/// for the rest of `inflight_ttl_seconds`.
#[tokio::test]
async fn test_streamed_event_stream_releases_inflight_marker_on_clean_completion() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    // The fresh key is marked in-flight and stays that way for the stream.
    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert!(request_identity(&plugin, &ctx).is_some());

    // The SSE response is streamed (not buffered), confirmed by the content-type
    // refinement declining to buffer it.
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));

    // A duplicate request arriving while the stream is still active must be
    // rejected with 409 — the in-flight lock is exactly the protection this
    // plugin promises for the still-running request.
    let mut dup_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut dup_headers = HashMap::new();
    dup_headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin.before_proxy(&mut dup_ctx, &mut dup_headers).await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "duplicate during an active streamed SSE response must 409, got {result:?}"
    );

    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(32))
        .await;
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(0),
        "a cleanly completed streamed SSE response must release the in-flight marker instead of waiting for TTL"
    );

    let mut after_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut after_headers = HashMap::new();
    after_headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin
        .before_proxy(&mut after_ctx, &mut after_headers)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "duplicate after a cleanly completed streamed SSE response should re-execute, not get stale 409 or cached replay; got {result:?}"
    );
}

/// A terminate-mode function can execute externally and then fail before a
/// usable response is available. With `on_error: continue`, a streamed backend
/// response has no replay body to publish, so even clean stream completion must
/// retain the in-flight marker until TTL rather than re-executing the uncertain
/// function side effect on an immediate retry.
#[tokio::test]
async fn test_streamed_fallback_retains_marker_after_uncertain_serverless_side_effect() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(600).set_body_string("invalid status"))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate",
            "on_error": "continue"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert(
        "idempotency-key".to_string(),
        "serverless-stream-key".to_string(),
    );
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        serverless.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    dedup
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(32))
        .await;
    assert_eq!(
        dedup.tracked_keys_count(),
        Some(1),
        "an uncertain serverless side effect must retain the streamed fallback marker until TTL"
    );

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut retry_headers = HashMap::new();
    retry_headers.insert(
        "idempotency-key".to_string(),
        "serverless-stream-key".to_string(),
    );
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Reject {
            status_code: 409,
            ..
        }
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// An interrupted streamed SSE response — client disconnect or mid-stream error,
/// i.e. `!body_completed` — delivered no full response to the client and is the
/// case most likely to be retried with the same idempotency key. Releasing the
/// marker there would let that retry re-execute a side-effecting backend
/// operation with no replay/tombstone protection, so the marker is retained
/// until `inflight_ttl_seconds` and duplicates keep receiving 409.
#[tokio::test]
async fn test_streamed_event_stream_retains_inflight_marker_on_client_disconnect() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(plugin.tracked_keys_count(), Some(1));

    // The client stopped consuming mid-stream (Drop safety net): the body never
    // completed, so the marker must survive to block an immediate retry.
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::client_disconnect(32))
        .await;
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(1),
        "an interrupted streamed SSE response must keep the in-flight marker until TTL so a same-key retry cannot re-execute"
    );

    let mut after_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut after_headers = HashMap::new();
    after_headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin
        .before_proxy(&mut after_ctx, &mut after_headers)
        .await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "duplicate after an interrupted streamed SSE response must stay blocked until TTL, got {result:?}"
    );
}

#[tokio::test]
async fn test_stale_stream_end_does_not_clear_successor_inflight_marker() {
    let plugin = make_plugin(json!({
        "inflight_ttl_seconds": 1
    }));

    let mut original_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut original_headers = HashMap::new();
    original_headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin
        .before_proxy(&mut original_ctx, &mut original_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));

    request_deduplication_expire_inflight_entries_for_test(&plugin);

    let mut successor_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut successor_headers = HashMap::new();
    successor_headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin
        .before_proxy(&mut successor_ctx, &mut successor_headers)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "successor should replace the stale in-flight marker, got {result:?}"
    );
    assert_eq!(plugin.tracked_keys_count(), Some(1));

    plugin
        .on_response_stream_terminated(&mut original_ctx, 200, &BodyOutcome::success(32))
        .await;

    let mut duplicate_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut duplicate_headers = HashMap::new();
    duplicate_headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin
        .before_proxy(&mut duplicate_ctx, &mut duplicate_headers)
        .await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "late stream-end from the stale owner must not clear the successor marker; got {result:?}"
    );

    plugin
        .on_response_stream_terminated(&mut successor_ctx, 200, &BodyOutcome::success(32))
        .await;
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(0),
        "the successor's own clean completion releases its marker via token-matched removal"
    );
}

/// A buffered (non-SSE) keyed response keeps the marker in-flight through the
/// header phase and transitions it to a cached `Completed` entry via
/// `on_final_response_body`, which only runs on the buffered path.
#[tokio::test]
async fn test_buffered_response_transitions_inflight_to_completed() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "json-key".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert!(request_identity(&plugin, &ctx).is_some());

    // A JSON response is buffered (the content-type refinement still votes to
    // buffer), so `on_final_response_body` runs and caches it.
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &HashMap::new()
    ));
    let response_headers = HashMap::new();
    let result = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, b"{}")
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

#[test]
fn test_tracked_keys_count() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[tokio::test]
async fn test_completion_clears_inflight_then_replays() {
    // Verify normal lifecycle: in-flight → completed → replay works correctly
    // and does not return 409 Conflict after the response is captured.
    let config = json!({});
    let plugin = make_plugin(config);

    // First request marks key as in-flight
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "lifecycle-key".to_string());
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));

    // Capture response — converts InFlight → Completed
    let response_headers = HashMap::new();
    let body = b"completion body";
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, body)
        .await;

    // Now duplicate request should REPLAY, not get 409 Conflict
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "lifecycle-key".to_string());
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(&body[..], b"completion body");
        }
        _ => panic!(
            "Expected RejectBinary replay after completion, got {:?}",
            result
        ),
    }
}

#[tokio::test]
async fn test_response_below_entry_limit_is_retained() {
    let plugin = make_plugin(json!({
        "max_entry_size_bytes": 2048,
        "max_total_size_bytes": 8192
    }));

    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert(
        "idempotency-key".to_string(),
        "below-entry-limit".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx1, b"small retained response").await;
    assert!(assert_completed_size_exact(&plugin) > 0);

    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert(
        "idempotency-key".to_string(),
        "below-entry-limit".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(
        result,
        PluginResult::RejectBinary {
            status_code: 200,
            ..
        }
    ));
}

#[tokio::test]
async fn test_oversized_response_is_not_retained_and_clears_inflight() {
    let plugin = make_plugin(json!({
        "max_entry_size_bytes": 1,
        "max_total_size_bytes": 8192
    }));

    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "oversized-entry".to_string());
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx1, b"too large").await;

    assert_eq!(plugin.tracked_keys_count(), Some(0));
    assert_eq!(assert_completed_size_exact(&plugin), 0);

    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "oversized-entry".to_string());
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "oversized completion must clear in-flight state so the next request can execute"
    );
}

#[tokio::test]
async fn test_total_retained_bytes_cap_skips_new_completion() {
    let plugin = make_plugin(json!({
        "max_entry_size_bytes": 2048,
        "max_total_size_bytes": 768
    }));
    let body = vec![b'a'; 500];

    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "total-cap-a".to_string());
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx1, &body).await;
    let first_size = assert_completed_size_exact(&plugin);
    assert!(
        first_size <= 768,
        "first entry should fit under the configured total cap, got {first_size}"
    );

    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "total-cap-b".to_string());
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx2, &body).await;

    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert_eq!(assert_completed_size_exact(&plugin), first_size);

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut retry_headers = HashMap::new();
    retry_headers.insert("idempotency-key".to_string(), "total-cap-b".to_string());
    let result = plugin
        .before_proxy(&mut retry_ctx, &mut retry_headers)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "total-cap skip must clear the skipped key's in-flight marker"
    );

    assert!(
        request_deduplication_redis_payload_for_test(&plugin, 200, HashMap::new(), &body).is_some(),
        "a local total-cap skip must still be small enough for Redis publication"
    );
}

#[tokio::test]
async fn test_redis_total_cap_publish_failure_keeps_local_inflight() {
    let plugin = make_plugin(json!({
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1/0",
        "redis_connect_timeout_seconds": 1,
        "max_entry_size_bytes": 2048,
        "max_total_size_bytes": 768
    }));
    let body = vec![b'a'; 500];

    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert(
        "idempotency-key".to_string(),
        "redis-total-cap-a".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx1, &body).await;
    let first_size = assert_completed_size_exact(&plugin);
    assert!(
        first_size <= 768,
        "first entry should fit under the configured total cap, got {first_size}"
    );

    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert(
        "idempotency-key".to_string(),
        "redis-total-cap-b".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx2, &body).await;

    assert_eq!(assert_completed_size_exact(&plugin), first_size);
    assert_eq!(plugin.tracked_keys_count(), Some(2));

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut retry_headers = HashMap::new();
    retry_headers.insert(
        "idempotency-key".to_string(),
        "redis-total-cap-b".to_string(),
    );
    let result = plugin
        .before_proxy(&mut retry_ctx, &mut retry_headers)
        .await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 409),
        other => {
            panic!("Expected Redis publish failure to preserve local in-flight lock, got {other:?}")
        }
    }
}

#[tokio::test]
async fn test_inflight_marker_carries_timestamp() {
    // Smoke test: confirm InFlight marker can be inserted multiple times for
    // distinct keys without panic and tracked_keys_count reflects the inserts.
    // Stale-marker eviction uses `inflight_ttl_seconds` (defaults to
    // `ttl_seconds`); a full timing test would slow CI.
    let config = json!({});
    let plugin = make_plugin(config);

    for i in 0..5 {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/api".to_string(),
        );
        let mut headers = HashMap::new();
        headers.insert(
            "idempotency-key".to_string(),
            format!("inflight-marker-{i}"),
        );
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
    }

    // All 5 distinct keys should be tracked
    assert_eq!(plugin.tracked_keys_count(), Some(5));
}

#[tokio::test]
async fn test_completed_entries_evict_over_capacity_on_insert() {
    let config = json!({
        "ttl_seconds": 300,
        "max_entries": 2
    });
    let plugin = make_plugin(config);

    for i in 0..3 {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/api".to_string(),
        );
        let mut headers = HashMap::new();
        headers.insert("idempotency-key".to_string(), format!("completed-{i}"));
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));

        let response_headers = HashMap::new();
        let result = plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, b"cached")
            .await;
        assert!(matches!(result, PluginResult::Continue));
    }

    assert_eq!(plugin.tracked_keys_count(), Some(2));
    assert!(assert_completed_size_exact(&plugin) > 0);
}

#[tokio::test]
async fn test_expired_completed_entries_release_retained_bytes() {
    let plugin = make_plugin(json!({
        "ttl_seconds": 300,
        "max_entry_size_bytes": 2048,
        "max_total_size_bytes": 8192
    }));

    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "expires-size".to_string());
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx1, b"expires").await;
    assert!(assert_completed_size_exact(&plugin) > 0);

    request_deduplication_expire_completed_entries_for_test(&plugin);

    let mut cleanup_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut cleanup_headers = HashMap::new();
    cleanup_headers.insert("idempotency-key".to_string(), "cleanup-trigger".to_string());
    let result = plugin
        .before_proxy(&mut cleanup_ctx, &mut cleanup_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(assert_completed_size_exact(&plugin), 0);
}

#[tokio::test]
async fn test_active_inflight_entries_survive_capacity_pressure() {
    let config = json!({
        "ttl_seconds": 300,
        "max_entries": 2
    });
    let plugin = make_plugin(config);

    for i in 0..3 {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/api".to_string(),
        );
        let mut headers = HashMap::new();
        headers.insert("idempotency-key".to_string(), format!("inflight-{i}"));
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
    }

    assert_eq!(plugin.tracked_keys_count(), Some(3));

    let mut duplicate_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut duplicate_headers = HashMap::new();
    duplicate_headers.insert("idempotency-key".to_string(), "inflight-0".to_string());
    let result = plugin
        .before_proxy(&mut duplicate_ctx, &mut duplicate_headers)
        .await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 409),
        other => panic!("Expected duplicate in-flight request to be rejected, got {other:?}"),
    }
}

/// A cached response with `Set-Cookie: session=A` from the first client must
/// NOT be replayed verbatim to a second client sharing the same idempotency
/// key. Without sanitization, the second client would receive the first
/// client's session cookie — a direct session-hijack vector when
/// `scope_by_consumer=false` or for anonymous traffic. Replay must still
/// surface the `x-idempotent-replayed: true` marker so operators can tell a
/// replay apart from a fresh response.
#[tokio::test]
async fn test_replay_strips_set_cookie_session_hijack_protection() {
    let config = json!({});
    let plugin = make_plugin(config);

    // First client: cache a response carrying a session cookie.
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/checkout".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "shared-key".to_string());
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    response_headers.insert(
        "Set-Cookie".to_string(),
        "session=USER_A_SESSION_TOKEN; HttpOnly; Secure".to_string(),
    );
    response_headers.insert("set-cookie2".to_string(), "legacy=USER_A".to_string());
    let body = b"{\"order_id\": 42}";
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, body)
        .await;

    // Second client (anonymous, same idempotency key): must NOT receive
    // user A's Set-Cookie even though replay returns user A's body.
    let mut ctx2 = RequestContext::new(
        "10.0.0.99".to_string(),
        "POST".to_string(),
        "/api/checkout".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "shared-key".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
            ..
        } => {
            assert_eq!(status_code, 200);
            // Critical: session-bearing headers must be stripped on replay.
            assert!(
                !headers.contains_key("Set-Cookie"),
                "Set-Cookie must be stripped from replayed response (session hijack vector)"
            );
            assert!(
                !headers.contains_key("set-cookie2"),
                "set-cookie2 must be stripped from replayed response"
            );
            // Replay marker still added so operators / clients can detect a replay.
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
            // Body and safe headers still flow through.
            assert_eq!(&body[..], b"{\"order_id\": 42}");
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
        }
        other => panic!("Expected RejectBinary replay, got {:?}", other),
    }
}

/// Authorization, www-authenticate, and per-request trace IDs must be
/// stripped on replay. The original request's `Authorization: Bearer <leaked>`
/// being echoed back to a different consumer is an information-disclosure
/// vector, and replaying the original `traceparent` would splice every cache
/// hit into the original transaction's trace.
#[tokio::test]
async fn test_replay_strips_authorization_and_trace_headers() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "auth-key".to_string());
    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;

    let mut response_headers = HashMap::new();
    response_headers.insert(
        "Authorization".to_string(),
        "Bearer leaked-token".to_string(),
    );
    response_headers.insert(
        "WWW-Authenticate".to_string(),
        "Bearer realm=\"api\"".to_string(),
    );
    response_headers.insert("X-Request-Id".to_string(), "req-original-12345".to_string());
    response_headers.insert(
        "traceparent".to_string(),
        "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
    );
    response_headers.insert("X-RateLimit-Remaining".to_string(), "42".to_string());
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"{}")
        .await;

    let mut ctx2 = RequestContext::new(
        "10.0.0.99".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "auth-key".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary { headers, .. } => {
            // Sensitive headers stripped (case-insensitive check).
            assert!(
                !headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("Authorization")),
                "Authorization must be stripped (info-disclosure vector)"
            );
            assert!(
                !headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("WWW-Authenticate"))
            );
            assert!(
                !headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("X-Request-Id")),
                "Per-request trace IDs must be stripped"
            );
            assert!(
                !headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("traceparent"))
            );
            assert!(
                !headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("X-RateLimit-Remaining")),
                "Rate-limit counters must be stripped"
            );
            // Replay marker still present.
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
            // Safe headers retained.
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
        }
        other => panic!("Expected RejectBinary replay, got {:?}", other),
    }
}

/// `Set-Cookie` set on a different case (case-insensitive HTTP header
/// matching) must still be stripped on replay. Backends emit cookies under
/// many casings (`Set-Cookie`, `set-cookie`, `SET-COOKIE`); a case-sensitive
/// strip would silently leak sessions.
#[tokio::test]
async fn test_replay_strips_set_cookie_case_insensitively() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "case-key".to_string());
    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;

    let mut response_headers = HashMap::new();
    // Mixed casings — all must be stripped.
    response_headers.insert("set-cookie".to_string(), "session=A".to_string());
    response_headers.insert("Set-Cookie".to_string(), "session=B".to_string());
    response_headers.insert("SET-COOKIE".to_string(), "session=C".to_string());
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"{}")
        .await;

    let mut ctx2 = RequestContext::new(
        "10.0.0.99".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "case-key".to_string());
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary { headers, .. } => {
            assert!(
                !headers.keys().any(|k| k.eq_ignore_ascii_case("set-cookie")),
                "All casings of Set-Cookie must be stripped"
            );
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
        }
        other => panic!("Expected RejectBinary replay, got {:?}", other),
    }
}

#[tokio::test]
async fn test_keyed_applicable_methods_buffer_request_body_for_fingerprint() {
    let plugin = make_plugin(json!({}));

    let mut keyed_post = body_ctx("POST", "/api", b"{\"a\":1}");
    keyed_post.headers = keyed_headers("body-key", "api.example", 7);
    assert!(plugin.should_buffer_request_body(&keyed_post));

    let keyless_without_declared_body = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    assert!(
        !plugin.should_buffer_request_body(&keyless_without_declared_body),
        "keyless optional requests must not lose streaming semantics"
    );

    let mut keyless_declared_body = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    keyless_declared_body
        .headers
        .insert("content-length".to_string(), "7".to_string());
    assert!(
        !plugin.should_buffer_request_body(&keyless_declared_body),
        "keyless optional requests must not be rejected by body buffering limits before this plugin ignores them"
    );

    let required_keyless = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let required_plugin = make_plugin(json!({
        "enforce_required": true
    }));
    assert!(required_plugin.should_buffer_request_body(&required_keyless));

    let mut keyed_get = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    keyed_get.headers = keyed_headers("body-key", "api.example", 0);
    assert!(!plugin.should_buffer_request_body(&keyed_get));
}

#[tokio::test]
async fn test_keyed_idempotency_header_can_fingerprint_prebuffered_body() {
    let plugin = make_plugin(json!({}));

    let mut ctx = body_ctx("POST", "/api", b"{\"a\":1}");
    ctx.headers
        .insert("content-length".to_string(), "7".to_string());
    ctx.headers
        .insert("idempotency-key".to_string(), "transformed-key".to_string());
    assert!(
        plugin.should_buffer_request_body(&ctx),
        "declared-body applicable requests must prebuffer before earlier plugins can add the key"
    );

    let mut headers = keyed_headers("transformed-key", "api.example", 7);
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_identity(&plugin, &ctx).is_some());
}

#[tokio::test]
async fn test_keyed_idempotency_header_buffers_implicit_http2_body() {
    let plugin = make_plugin(json!({}));

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers.insert(
        "idempotency-key".to_string(),
        "implicit-body-key".to_string(),
    );
    assert!(
        plugin.should_buffer_request_body(&ctx),
        "keyed HTTP/2 and HTTP/3 POST bodies may arrive without length or transfer headers"
    );
}

#[tokio::test]
async fn test_identical_request_bodies_replay_cached_response() {
    let plugin = make_plugin(json!({}));

    let mut ctx1 = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut headers1 = keyed_headers("same-body", "api.example", 11);
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response(&plugin, &mut ctx1).await;

    let mut ctx2 = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut headers2 = keyed_headers("same-body", "api.example", 11);
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 201);
            assert_eq!(&body[..], b"{\"ok\":true}");
        }
        other => panic!("Expected replay for identical body, got {other:?}"),
    }
}

#[tokio::test]
async fn test_reused_key_different_method_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("method-key", "api.example", 11);
    let mut second_ctx = body_ctx("PUT", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("method-key", "api.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_authority_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("authority-key", "api.example", 11);
    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("authority-key", "other.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_authority_case_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("authority-case-key", "API.example", 11);
    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("authority-case-key", "api.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_raw_path_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders/1", b"{\"order\":1}");
    let mut first_headers = keyed_headers("path-key", "api.example", 11);
    let mut second_ctx = body_ctx("POST", "/api/orders/2", b"{\"order\":1}");
    let mut second_headers = keyed_headers("path-key", "api.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_raw_query_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    first_ctx.set_raw_query_string("a=1&a=2".to_string());
    let mut first_headers = keyed_headers("query-key", "api.example", 11);
    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    second_ctx.set_raw_query_string("a=2&a=1".to_string());
    let mut second_headers = keyed_headers("query-key", "api.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_route_affecting_header_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("route-header-key", "api.example", 11);
    first_headers.insert("x-canary".to_string(), "blue".to_string());
    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("route-header-key", "api.example", 11);
    second_headers.insert("x-canary".to_string(), "green".to_string());

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_client_trace_headers_replays() {
    let plugin = make_plugin(json!({}));

    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("synthetic-key", "api.example", 11);
    first_headers.insert(
        "traceparent".to_string(),
        "00-11111111111111111111111111111111-2222222222222222-01".to_string(),
    );
    first_headers.insert("x-request-id".to_string(), "request-a".to_string());
    first_headers.insert("tracestate".to_string(), "vendor=trace-a".to_string());
    first_headers.insert("X-Correlation-ID".to_string(), "correlation-a".to_string());
    first_headers.insert("correlation-id".to_string(), "legacy-a".to_string());
    first_headers.insert("X-Trace-ID".to_string(), "generic-a".to_string());
    first_headers.insert(
        "X-Amzn-Trace-Id".to_string(),
        "Root=1-11111111-111111111111111111111111".to_string(),
    );
    first_headers.insert(
        "B3".to_string(),
        "1111111111111111-2222222222222222-1".to_string(),
    );
    first_headers.insert("X-B3-TraceId".to_string(), "1111111111111111".to_string());
    first_headers.insert("x-b3-spanid".to_string(), "2222222222222222".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("synthetic-key", "api.example", 11);
    second_headers.insert(
        "traceparent".to_string(),
        "00-33333333333333333333333333333333-4444444444444444-01".to_string(),
    );
    second_headers.insert("x-request-id".to_string(), "request-b".to_string());
    second_headers.insert("TraceState".to_string(), "vendor=trace-b".to_string());
    second_headers.insert("x-correlation-id".to_string(), "correlation-b".to_string());
    second_headers.insert("Correlation-Id".to_string(), "legacy-b".to_string());
    second_headers.insert("x-trace-id".to_string(), "generic-b".to_string());
    second_headers.insert(
        "x-amzn-trace-id".to_string(),
        "Root=1-33333333-333333333333333333333333".to_string(),
    );
    second_headers.insert(
        "b3".to_string(),
        "3333333333333333-4444444444444444-0".to_string(),
    );
    second_headers.insert("x-b3-traceid".to_string(), "3333333333333333".to_string());
    second_headers.insert("X-B3-SpanId".to_string(), "4444444444444444".to_string());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(matches!(result, PluginResult::RejectBinary { .. }));
}

#[tokio::test]
async fn test_scoped_credential_rotation_replays_cached_response() {
    let plugin = make_plugin(json!({}));

    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    first_ctx.authenticated_identity = Some("consumer-1".to_string());
    let mut first_headers = keyed_headers("credential-rotation-key", "api.example", 11);
    first_headers.insert("authorization".to_string(), "Bearer old-token".to_string());
    first_headers.insert("cookie".to_string(), "session=old".to_string());
    first_headers.insert("x-api-key".to_string(), "old-api-key".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    second_ctx.authenticated_identity = Some("consumer-1".to_string());
    let mut second_headers = keyed_headers("credential-rotation-key", "api.example", 11);
    second_headers.insert("authorization".to_string(), "Bearer new-token".to_string());
    second_headers.insert("cookie".to_string(), "session=new".to_string());
    second_headers.insert("x-api-key".to_string(), "new-api-key".to_string());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(matches!(result, PluginResult::RejectBinary { .. }));
}

#[tokio::test]
async fn test_unscoped_credentials_remain_in_fingerprint() {
    let plugin = make_plugin(json!({
        "scope_by_consumer": false
    }));

    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    first_ctx.authenticated_identity = Some("consumer-1".to_string());
    let mut first_headers = keyed_headers("unscoped-credential-key", "api.example", 11);
    first_headers.insert("authorization".to_string(), "Bearer old-token".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    second_ctx.authenticated_identity = Some("consumer-1".to_string());
    let mut second_headers = keyed_headers("unscoped-credential-key", "api.example", 11);
    second_headers.insert("authorization".to_string(), "Bearer new-token".to_string());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert_fingerprint_conflict(result);
}

#[tokio::test]
async fn test_anonymous_credentials_remain_in_fingerprint() {
    let plugin = make_plugin(json!({}));

    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("anonymous-credential-key", "api.example", 11);
    first_headers.insert("authorization".to_string(), "Bearer old-token".to_string());
    first_headers.insert("cookie".to_string(), "session=old".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("anonymous-credential-key", "api.example", 11);
    second_headers.insert("authorization".to_string(), "Bearer new-token".to_string());
    second_headers.insert("cookie".to_string(), "session=new".to_string());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert_fingerprint_conflict(result);
}

#[tokio::test]
async fn test_reused_key_different_connection_listed_header_returns_409() {
    let plugin = make_plugin(json!({}));

    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("connection-key", "api.example", 11);
    first_headers.insert("connection".to_string(), "x-debug-route".to_string());
    first_headers.insert("x-debug-route".to_string(), "blue".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("connection-key", "api.example", 11);
    second_headers.insert("connection".to_string(), "x-debug-route".to_string());
    second_headers.insert("x-debug-route".to_string(), "green".to_string());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert_fingerprint_conflict(result);
}

#[tokio::test]
async fn test_reused_key_different_content_length_replays() {
    let plugin = make_plugin(json!({}));

    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("content-length-key", "api.example", 11);
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("content-length-key", "api.example", 11);
    second_headers.insert("content-length".to_string(), "999".to_string());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(matches!(result, PluginResult::RejectBinary { .. }));
}

#[tokio::test]
async fn test_reused_key_equivalent_gzip_body_replays() {
    let plugin = make_plugin(json!({}));
    let logical_body = br#"{"order":1}"#;
    let compressed_body = gzip_body(logical_body);

    let mut first_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/orders".to_string(),
    );
    first_ctx.request_body_bytes = Some(Bytes::from(compressed_body.clone()));
    let mut first_headers = keyed_headers("gzip-body-key", "api.example", compressed_body.len());
    first_headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", logical_body);
    let mut second_headers = keyed_headers("gzip-body-key", "api.example", logical_body.len());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(matches!(result, PluginResult::RejectBinary { .. }));
}

#[tokio::test]
async fn test_large_gzip_body_uses_wire_fingerprint_fallback() {
    let plugin = make_plugin(json!({}));
    let logical_body = vec![b'a'; 1024 * 1024 + 1];
    let compressed_body = gzip_body(&logical_body);

    let mut first_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/orders".to_string(),
    );
    first_ctx.request_body_bytes = Some(Bytes::from(compressed_body.clone()));
    let mut first_headers =
        keyed_headers("large-gzip-body-key", "api.example", compressed_body.len());
    first_headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/orders".to_string(),
    );
    second_ctx.request_body_bytes = Some(Bytes::from(logical_body));
    let mut second_headers = keyed_headers("large-gzip-body-key", "api.example", 1024 * 1024 + 1);

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert_fingerprint_conflict(result);
}

#[tokio::test]
async fn test_unsupported_content_encoding_stays_in_fingerprint() {
    let plugin = make_plugin(json!({}));
    let body = b"same wire bytes";

    let mut first_ctx = body_ctx("POST", "/api/orders", body);
    let mut first_headers = keyed_headers("unsupported-encoding-key", "api.example", body.len());
    first_headers.insert("content-encoding".to_string(), "deflate".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", body);
    let mut second_headers = keyed_headers("unsupported-encoding-key", "api.example", body.len());
    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert_fingerprint_conflict(result);
}

#[tokio::test]
async fn test_malformed_supported_content_encoding_stays_in_fingerprint() {
    let plugin = make_plugin(json!({}));
    let body = b"not actually gzip";

    let mut first_ctx = body_ctx("POST", "/api/orders", body);
    let mut first_headers = keyed_headers("malformed-encoding-key", "api.example", body.len());
    first_headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", body);
    let mut second_headers = keyed_headers("malformed-encoding-key", "api.example", body.len());
    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert_fingerprint_conflict(result);
}

#[tokio::test]
async fn test_reused_key_different_body_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("body-key", "api.example", 11);
    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":2}");
    let mut second_headers = keyed_headers("body-key", "api.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_declared_body_unavailable_rejects_fingerprinting() {
    let plugin = make_plugin(json!({}));
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/orders".to_string(),
    );
    let mut headers = keyed_headers("missing-body", "api.example", 12);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert!(body.contains("Request body unavailable"));
        }
        other => panic!("Expected body-unavailable reject, got {other:?}"),
    }
}

#[test]
fn test_legacy_redis_cached_response_without_fingerprint_is_rejected() {
    let legacy = br#"{"status_code":201,"headers":{},"body":[]}"#;

    assert!(!request_deduplication_redis_cached_response_payload_is_valid(legacy));
}

#[test]
fn test_legacy_redis_cached_response_byte_array_body_is_accepted() {
    let legacy = br#"{"fingerprint":"sha256-test","status_code":201,"headers":{},"body":[123,34,111,107,34,58,116,114,117,101,125]}"#;

    assert!(request_deduplication_redis_cached_response_payload_is_valid(legacy));
}

#[test]
fn test_redis_payload_admission_respects_entry_size_limit() {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let plugin = make_plugin(json!({
        "max_entry_size_bytes": 2048
    }));
    let payload = request_deduplication_redis_payload_for_test(
        &plugin,
        201,
        headers.clone(),
        b"{\"ok\":true}",
    )
    .expect("small Redis payload should be admitted");
    assert!(request_deduplication_redis_cached_response_payload_is_valid(&payload));

    let plugin = make_plugin(json!({
        "max_entry_size_bytes": 1
    }));
    assert!(
        request_deduplication_redis_payload_for_test(&plugin, 201, headers, b"{\"ok\":true}")
            .is_none(),
        "oversized responses must not be serialized for Redis storage"
    );
}

#[test]
fn test_redis_payload_uses_compact_body_encoding_before_size_check() {
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    );

    let max_entry_size_bytes = 256 * 1024;
    let plugin = make_plugin(json!({
        "max_entry_size_bytes": max_entry_size_bytes
    }));
    let body = vec![0xab; 160 * 1024];
    let payload = request_deduplication_redis_payload_for_test(&plugin, 201, headers, &body)
        .expect("compact Redis payload should be admitted under the entry limit");
    let payload_json: serde_json::Value =
        serde_json::from_slice(&payload).expect("payload should be JSON");

    assert!(
        payload_json
            .get("body")
            .is_some_and(serde_json::Value::is_string),
        "Redis response bodies must serialize as compact base64 strings"
    );
    assert!(
        payload.len() <= max_entry_size_bytes,
        "compact Redis payload should remain under the configured entry cap"
    );
    assert!(request_deduplication_redis_cached_response_payload_is_valid(&payload));
}

#[test]
fn test_redis_payload_admission_rejects_serialized_payload_over_entry_limit() {
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    );

    let plugin = make_plugin(json!({
        "max_entry_size_bytes": 1024 * 1024
    }));
    let body = vec![0xab; 800 * 1024];
    assert!(
        request_deduplication_redis_payload_for_test(&plugin, 201, headers, &body).is_none(),
        "Redis payloads must be rejected when serialized storage exceeds the entry cap"
    );
}

#[tokio::test]
async fn test_delimiter_containing_identities_and_keys_do_not_collide() {
    let plugin = make_plugin(json!({
        "scope_by_consumer": true
    }));

    let mut ctx1 = body_ctx("POST", "/api/orders", b"{}");
    ctx1.authenticated_identity = Some("alice:tenant".to_string());
    let mut headers1 = keyed_headers("key", "api.example", 2);
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut ctx2 = body_ctx("POST", "/api/orders", b"{}");
    ctx2.authenticated_identity = Some("alice".to_string());
    let mut headers2 = keyed_headers("tenant:key", "api.example", 2);
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));

    let (key1, _) = request_identity(&plugin, &ctx1).unwrap();
    let (key2, _) = request_identity(&plugin, &ctx2).unwrap();
    assert_ne!(key1, key2);
    assert!(!key1.contains("alice"));
    assert!(!key1.contains("key"));
    assert!(!key2.contains("tenant"));
}

#[tokio::test]
async fn test_peer_spiffe_id_scopes_logical_key() {
    let plugin = make_plugin(json!({}));

    let mut ctx1 = body_ctx("POST", "/api/orders", b"{}");
    ctx1.peer_spiffe_id = Some(
        ferrum_edge::identity::SpiffeId::new("spiffe://mesh.local/ns/blue/sa/default")
            .expect("valid SPIFFE ID"),
    );
    let mut headers1 = keyed_headers("mesh-key", "api.example", 2);
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut ctx2 = body_ctx("POST", "/api/orders", b"{}");
    ctx2.peer_spiffe_id = Some(
        ferrum_edge::identity::SpiffeId::new("spiffe://mesh.local/ns/green/sa/default")
            .expect("valid SPIFFE ID"),
    );
    let mut headers2 = keyed_headers("mesh-key", "api.example", 2);
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));

    let (key1, _) = request_identity(&plugin, &ctx1).unwrap();
    let (key2, _) = request_identity(&plugin, &ctx2).unwrap();
    assert_ne!(key1, key2);
    assert!(!key1.contains("blue"));
    assert!(!key2.contains("green"));
}

#[tokio::test]
async fn test_fingerprints_and_logical_keys_do_not_expose_secrets() {
    let plugin = make_plugin(json!({}));
    let mut ctx = body_ctx("POST", "/api/orders", b"super-secret-body");
    ctx.authenticated_identity = Some("identity-secret".to_string());
    let mut headers = keyed_headers("secret-idempotency-key", "api.example", 17);
    headers.insert(
        "authorization".to_string(),
        "Bearer request-secret-token".to_string(),
    );
    headers.insert("cookie".to_string(), "session=request-secret".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let (logical_key, fingerprint) = request_identity(&plugin, &ctx).unwrap();
    assert!(logical_key.starts_with("v3:"));
    assert!(fingerprint.starts_with("sha256-"));
    for secret in [
        "super-secret-body",
        "secret-idempotency-key",
        "identity-secret",
        "request-secret-token",
        "request-secret",
    ] {
        assert!(!logical_key.contains(secret));
        assert!(!fingerprint.contains(secret));
    }
}

#[tokio::test]
async fn stable_plugin_config_identity_partitions_distributed_logical_keys() {
    let config = json!({});
    // Same stable plugin-config id on two gateways must share Redis identity
    // (cross-gateway companion contract). Distinct ids — including across
    // scopes that happen to share a proxy association — must stay partitioned.
    let first_gateway = request_deduplication_with_instance_id_for_test(
        &config,
        PluginHttpClient::default(),
        "dedup-primary",
    )
    .unwrap();
    let second_gateway = request_deduplication_with_instance_id_for_test(
        &config,
        PluginHttpClient::default(),
        "dedup-primary",
    )
    .unwrap();
    let sibling_instance = request_deduplication_with_instance_id_for_test(
        &config,
        PluginHttpClient::default(),
        "dedup-secondary",
    )
    .unwrap();
    let proxy_group_sibling = request_deduplication_with_instance_id_for_test(
        &config,
        PluginHttpClient::default(),
        "dedup-proxy-group",
    )
    .unwrap();
    let global_sibling = request_deduplication_with_instance_id_for_test(
        &config,
        PluginHttpClient::default(),
        "dedup-global",
    )
    .unwrap();

    let mut identities = Vec::new();
    for plugin in [
        &first_gateway,
        &second_gateway,
        &sibling_instance,
        &proxy_group_sibling,
        &global_sibling,
    ] {
        let mut ctx = body_ctx("POST", "/api/orders", b"{}");
        let mut headers = keyed_headers("shared-key", "api.example", 2);
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        identities.push(request_identity(plugin, &ctx).unwrap());
    }

    assert_eq!(
        identities[0], identities[1],
        "the same plugin_config_id must share Redis identity across gateways"
    );
    assert_ne!(
        identities[0].0, identities[2].0,
        "sibling plugin instances must not share completed or in-flight Redis keys"
    );
    assert_ne!(
        identities[0].0, identities[3].0,
        "proxy_group-scoped config identity must remain isolated from peer instances"
    );
    assert_ne!(
        identities[0].0, identities[4].0,
        "global-scoped config identity must remain isolated from peer instances"
    );
    assert_eq!(
        identities[0].1, identities[2].1,
        "plugin instance partitioning must not alter request fingerprints"
    );
}

#[tokio::test]
async fn test_local_and_redis_modes_compute_identical_request_identity() {
    let local_plugin = make_plugin(json!({}));
    let redis_plugin = make_plugin(json!({
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1/0",
        "redis_connect_timeout_seconds": 1
    }));

    let mut local_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    local_ctx.set_raw_query_string("expand=items".to_string());
    let mut local_headers = keyed_headers("shared-key", "api.example", 11);
    let local_result = local_plugin
        .before_proxy(&mut local_ctx, &mut local_headers)
        .await;
    assert!(matches!(local_result, PluginResult::Continue));

    let mut redis_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    redis_ctx.set_raw_query_string("expand=items".to_string());
    let mut redis_headers = keyed_headers("shared-key", "api.example", 11);
    let redis_result = redis_plugin
        .before_proxy(&mut redis_ctx, &mut redis_headers)
        .await;
    assert!(matches!(redis_result, PluginResult::Continue));

    assert_eq!(
        request_identity(&local_plugin, &local_ctx).map(|identity| identity.0),
        request_identity(&redis_plugin, &redis_ctx).map(|identity| identity.0)
    );
    assert_eq!(
        request_identity(&local_plugin, &local_ctx).map(|identity| identity.1),
        request_identity(&redis_plugin, &redis_ctx).map(|identity| identity.1)
    );
}
