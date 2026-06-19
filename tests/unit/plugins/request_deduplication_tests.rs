use bytes::Bytes;
use ferrum_edge::plugins::request_deduplication::RequestDeduplication;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext, priority,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Barrier;

const DEDUP_KEY_METADATA: &str = "_dedup_key";
const DEDUP_FINGERPRINT_METADATA: &str = "_dedup_fingerprint";

fn make_plugin(config: serde_json::Value) -> RequestDeduplication {
    RequestDeduplication::new(&config, PluginHttpClient::default()).unwrap()
}

fn keyed_headers(key: &str, host: &str, body_len: usize) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), key.to_string());
    headers.insert("host".to_string(), host.to_string());
    headers.insert("content-length".to_string(), body_len.to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers
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

async fn complete_response(plugin: &RequestDeduplication, ctx: &mut RequestContext) {
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let result = plugin
        .on_final_response_body(ctx, 201, &response_headers, b"{\"ok\":true}")
        .await;
    assert!(matches!(result, PluginResult::Continue));
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
    assert!(ctx1.metadata.contains_key("_dedup_key"));

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
        }
        _ => panic!("Expected RejectBinary replay, got {:?}", result),
    }
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
    assert!(ctx.metadata.contains_key("_dedup_key"));
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
    assert!(!ctx.metadata.contains_key("_dedup_key"));

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
    assert!(ctx2.metadata.contains_key("_dedup_key"));
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
/// the `InFlight` marker to a cached `Completed` entry) never runs. The marker
/// is intentionally kept in-flight for the lifetime of the stream — there is no
/// plugin hook for streamed-body completion, and releasing it at response-headers
/// time would let a concurrent duplicate mutating request reach the backend while
/// the original stream is still running. While the stream is active a duplicate
/// key must therefore still 409.
#[tokio::test]
async fn test_streamed_event_stream_keeps_inflight_marker_for_stream_lifetime() {
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
    assert!(ctx.metadata.contains_key("_dedup_key"));

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
}

// Note: after a streamed SSE response ends, the `InFlight` marker self-heals
// once it exceeds `inflight_ttl` (documented to cover the longest protected
// request, including a long-lived stream) via the staleness branch in
// `local_lookup_or_mark_inflight`. That path is exercised by the staleness logic
// generally; a dedicated test here would require either a real >=1s sleep
// (`inflight_ttl_seconds` is rejected at 0) or injectable time, which this suite
// deliberately avoids to keep CI fast (see `test_inflight_marker_carries_timestamp`).

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
    assert!(ctx.metadata.contains_key("_dedup_key"));

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

    let keyless_post = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    assert!(!plugin.should_buffer_request_body(&keyless_post));

    let mut keyed_get = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    keyed_get.headers = keyed_headers("body-key", "api.example", 0);
    assert!(!plugin.should_buffer_request_body(&keyed_get));
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

    let key1 = ctx1.metadata.get(DEDUP_KEY_METADATA).unwrap();
    let key2 = ctx2.metadata.get(DEDUP_KEY_METADATA).unwrap();
    assert_ne!(key1, key2);
    assert!(!key1.contains("alice"));
    assert!(!key1.contains("key"));
    assert!(!key2.contains("tenant"));
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

    let logical_key = ctx.metadata.get(DEDUP_KEY_METADATA).unwrap();
    let fingerprint = ctx.metadata.get(DEDUP_FINGERPRINT_METADATA).unwrap();
    assert!(logical_key.starts_with("v2:"));
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
        local_ctx.metadata.get(DEDUP_KEY_METADATA),
        redis_ctx.metadata.get(DEDUP_KEY_METADATA)
    );
    assert_eq!(
        local_ctx.metadata.get(DEDUP_FINGERPRINT_METADATA),
        redis_ctx.metadata.get(DEDUP_FINGERPRINT_METADATA)
    );
}
