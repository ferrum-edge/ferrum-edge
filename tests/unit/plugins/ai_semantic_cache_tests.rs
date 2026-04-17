use ferrum_edge::plugins::ai_semantic_cache::AiSemanticCache;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_plugin(config: serde_json::Value) -> AiSemanticCache {
    AiSemanticCache::new(&config, PluginHttpClient::default()).unwrap()
}

#[test]
fn test_new_default_config() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_semantic_cache");
}

#[test]
fn test_new_custom_config() {
    let config = json!({
        "ttl_seconds": 600,
        "max_entries": 5000,
        "max_entry_size_bytes": 524288,
        "max_total_size_bytes": 52428800,
        "include_model_in_key": true,
        "include_params_in_key": true,
        "scope_by_consumer": true
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_semantic_cache");
}

#[test]
fn test_new_zero_ttl_fails() {
    let config = json!({"ttl_seconds": 0});
    let result = AiSemanticCache::new(&config, PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("ttl_seconds"));
}

#[test]
fn test_new_with_redis_config() {
    let config = json!({
        "sync_mode": "redis",
        "redis_url": "redis://localhost:6379/0"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_semantic_cache");
}

#[test]
fn test_requires_response_body_buffering() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_requires_request_body() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert!(plugin.requires_request_body_before_before_proxy());
}

#[tokio::test]
async fn test_cache_miss_then_hit() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    let body_json = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "What is the capital of France?"}
        ]
    });
    let body_str = serde_json::to_string(&body_json).unwrap();

    // First request — cache MISS
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx1.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx1.metadata.get("ai_cache_status").unwrap(), "MISS");
    assert!(ctx1.metadata.contains_key("_ai_cache_key"));

    // Simulate caching the response
    let response_body = br#"{"choices":[{"message":{"content":"Paris"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, response_body)
        .await;

    // Second request with same prompt — cache HIT
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx2.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
            ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(headers.get("x-ai-cache-status").unwrap(), "HIT");
            assert_eq!(&body[..], response_body);
        }
        _ => panic!("Expected cache HIT (RejectBinary), got {:?}", result),
    }
}

#[tokio::test]
async fn test_different_prompts_no_cache_hit() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    // First request
    let body1 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is the capital of France?"}]
    });
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx1.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body1).unwrap(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    let response_headers = HashMap::new();
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"cached")
        .await;

    // Different prompt — should MISS
    let body2 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is the capital of Germany?"}]
    });
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx2.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body2).unwrap(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx2.metadata.get("ai_cache_status").unwrap(), "MISS");
}

#[tokio::test]
async fn test_whitespace_normalization_cache_hit() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    // First request with normal spacing
    let body1 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is the capital of France?"}]
    });
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx1.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body1).unwrap(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    let response_headers = HashMap::new();
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"Paris")
        .await;

    // Same prompt with extra whitespace and case differences — should HIT
    let body2 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "  What  is  the  Capital  of  France?  "}]
    });
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx2.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body2).unwrap(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary { status_code, .. } => {
            assert_eq!(status_code, 200);
        }
        _ => panic!("Expected cache HIT after whitespace normalization"),
    }
}

#[tokio::test]
async fn test_different_model_no_cache_hit() {
    let config = json!({"ttl_seconds": 300, "include_model_in_key": true});
    let plugin = make_plugin(config);

    // Cache with gpt-4o
    let body1 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx1.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body1).unwrap(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    let response_headers = HashMap::new();
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"hi")
        .await;

    // Same prompt but different model — should MISS
    let body2 = json!({
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx2.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body2).unwrap(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_get_request_skipped() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/chat".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("ai_cache_status"));
}

#[tokio::test]
async fn test_non_json_skipped() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_error_response_not_cached() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body).unwrap(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    // 500 response should not be cached
    let response_headers = HashMap::new();
    let _ = plugin
        .on_final_response_body(&mut ctx, 500, &response_headers, b"error")
        .await;

    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[test]
fn test_tracked_keys_count() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[tokio::test]
async fn test_sensitive_response_headers_not_replayed_on_cache_hit() {
    // SECURITY: Cached responses must not replay per-response identity
    // (cookies, auth tokens) or per-request rate-limit/trace headers to a
    // different consumer. Without this, a cache hit would leak the original
    // user's session cookie to the next user that asks the same question.
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    let body_json = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}]
    });
    let body_str = serde_json::to_string(&body_json).unwrap();

    // First request — cache MISS, store response with a Set-Cookie / Auth header.
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx1.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    response_headers.insert(
        "Set-Cookie".to_string(),
        "session=user-A-secret".to_string(),
    );
    response_headers.insert(
        "authorization".to_string(),
        "Bearer user-A-token".to_string(),
    );
    response_headers.insert(
        "X-Request-Id".to_string(),
        "request-id-from-user-A".to_string(),
    );
    response_headers.insert("x-ai-ratelimit-remaining".to_string(), "999".to_string());

    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"Hello back")
        .await;

    // Second request from a different consumer (different IP) hits the cache.
    let mut ctx2 = RequestContext::new(
        "203.0.113.99".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx2.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary { headers, .. } => {
            assert!(
                !headers.contains_key("Set-Cookie"),
                "cache MUST NOT replay Set-Cookie to a different consumer"
            );
            assert!(
                !headers.contains_key("authorization"),
                "cache MUST NOT replay Authorization to a different consumer"
            );
            assert!(
                !headers.contains_key("X-Request-Id"),
                "cache MUST NOT replay X-Request-Id to a different consumer"
            );
            assert!(
                !headers.contains_key("x-ai-ratelimit-remaining"),
                "cache MUST NOT replay rate-limit counters from the original request"
            );
            // The cache-status indicator and content-type must still be present.
            assert_eq!(headers.get("x-ai-cache-status").unwrap(), "HIT");
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
        }
        _ => panic!("Expected cache HIT (RejectBinary), got {:?}", result),
    }
}
