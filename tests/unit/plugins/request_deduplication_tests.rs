use ferrum_edge::plugins::request_deduplication::RequestDeduplication;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_plugin(config: serde_json::Value) -> RequestDeduplication {
    RequestDeduplication::new(&config, PluginHttpClient::default()).unwrap()
}

#[test]
fn test_new_default_config() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "request_deduplication");
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
        "redis_url": "redis://localhost:6379/0",
        "redis_key_prefix": "dedup"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "request_deduplication");
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
