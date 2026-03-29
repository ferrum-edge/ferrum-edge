//! Tests for response_caching plugin

use super::plugin_utils::create_test_proxy;
use chrono::Utc;
use ferrum_gateway::config::types::Consumer;
use ferrum_gateway::plugins::response_caching::ResponseCaching;
use ferrum_gateway::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        id: id.to_string(),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_ctx(method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    ctx.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    ctx
}

fn make_ctx_with_query(method: &str, path: &str, query: &[(&str, &str)]) -> RequestContext {
    let mut ctx = make_ctx(method, path);
    for (k, v) in query {
        ctx.query_params.insert(k.to_string(), v.to_string());
    }
    ctx
}

fn default_plugin() -> ResponseCaching {
    ResponseCaching::new(&json!({}))
}

fn plugin_with_config(config: serde_json::Value) -> ResponseCaching {
    ResponseCaching::new(&config)
}

// Helper to simulate a full cache flow: before_proxy (miss) -> after_proxy -> on_response_body
async fn cache_response(
    plugin: &ResponseCaching,
    method: &str,
    path: &str,
    status: u16,
    response_headers: &HashMap<String, String>,
    body: &[u8],
) {
    let mut ctx = make_ctx(method, path);
    let mut headers = HashMap::new();

    // before_proxy (should be MISS)
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // after_proxy
    let mut resp_headers = response_headers.clone();
    plugin
        .after_proxy(&mut ctx, status, &mut resp_headers)
        .await;

    // on_response_body
    plugin
        .on_response_body(&mut ctx, status, &resp_headers, body)
        .await;
}

// === Plugin creation ===

#[tokio::test]
async fn test_creation_defaults() {
    let plugin = default_plugin();
    assert_eq!(plugin.name(), "response_caching");
    assert_eq!(plugin.priority(), 3500);
    assert!(plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_supported_protocols() {
    let plugin = default_plugin();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols.len(), 1);
    assert_eq!(protocols[0], ferrum_gateway::plugins::ProxyProtocol::Http);
}

// === Cache miss on first request ===

#[tokio::test]
async fn test_cache_miss_first_request() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("cache_status").unwrap(), "MISS");
    assert!(ctx.metadata.contains_key("cache_key"));
}

// === Cache hit on second request ===

#[tokio::test]
async fn test_cache_hit_second_request() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &resp_headers,
        b"{\"key\":\"value\"}",
    )
    .await;

    // Second request should be a HIT
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(body, "{\"key\":\"value\"}");
            assert_eq!(headers.get("content-type").unwrap(), "application/json");
            assert_eq!(headers.get("x-cache-status").unwrap(), "HIT");
        }
        _ => panic!("Expected Reject (cache HIT)"),
    }
}

// === TTL expiry ===

#[tokio::test]
async fn test_ttl_expiry() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 0  // Immediate expiry
    }));

    cache_response(&plugin, "GET", "/api/data", 200, &HashMap::new(), b"cached").await;

    // Wait a tiny bit to ensure expiry
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("cache_status").unwrap(), "MISS");
}

// === Cache-Control: no-store ===

#[tokio::test]
async fn test_cache_control_no_store_response() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "no-store".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/secret",
        200,
        &resp_headers,
        b"secret data",
    )
    .await;

    // Should not be cached
    let mut ctx = make_ctx("GET", "/api/secret");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Cache-Control: private ===

#[tokio::test]
async fn test_cache_control_private_response() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "private".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/private",
        200,
        &resp_headers,
        b"private data",
    )
    .await;

    // Should not be cached
    let mut ctx = make_ctx("GET", "/api/private");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Cache-Control: max-age ===

#[tokio::test]
async fn test_cache_control_max_age() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 1  // Short default
    }));

    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=3600".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &resp_headers,
        b"long-lived",
    )
    .await;

    // Should still be cached (max-age=3600 overrides ttl_seconds=1)
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

// === Cache-Control: s-maxage takes precedence ===

#[tokio::test]
async fn test_cache_control_s_maxage_precedence() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 0  // Would expire immediately
    }));

    let mut resp_headers = HashMap::new();
    resp_headers.insert(
        "cache-control".to_string(),
        "max-age=0, s-maxage=3600".to_string(),
    );

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &resp_headers,
        b"s-maxage wins",
    )
    .await;

    // s-maxage=3600 should override max-age=0
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

// === Client Cache-Control: no-cache bypasses cache ===

#[tokio::test]
async fn test_client_no_cache_bypasses() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &HashMap::new(),
        b"cached data",
    )
    .await;

    // Request with Cache-Control: no-cache should bypass
    let mut ctx = make_ctx("GET", "/api/data");
    ctx.headers
        .insert("cache-control".to_string(), "no-cache".to_string());
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("cache_status").unwrap(), "BYPASS");
}

// === Non-cacheable methods ===

#[tokio::test]
async fn test_post_not_cached() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("POST", "/api/data");
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("cache_status").unwrap(), "BYPASS");
}

#[tokio::test]
async fn test_delete_not_cached() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("DELETE", "/api/data");
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("cache_status").unwrap(), "BYPASS");
}

// === Non-cacheable status codes ===

#[tokio::test]
async fn test_500_not_cached() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/error",
        500,
        &HashMap::new(),
        b"server error",
    )
    .await;

    // Should not be cached
    let mut ctx = make_ctx("GET", "/api/error");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Cache invalidation on unsafe methods ===

#[tokio::test]
async fn test_post_invalidates_cached_get() {
    let plugin = default_plugin();

    // Cache a GET response
    cache_response(
        &plugin,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"[\"item1\"]",
    )
    .await;

    // Verify it's cached
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Reject { .. }));

    // POST to the same path should invalidate
    let mut ctx = make_ctx("POST", "/api/items");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // GET should now be a MISS
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Max entry size ===

#[tokio::test]
async fn test_max_entry_size_exceeded() {
    let plugin = plugin_with_config(json!({
        "max_entry_size_bytes": 10  // Very small
    }));

    cache_response(
        &plugin,
        "GET",
        "/api/large",
        200,
        &HashMap::new(),
        b"this response is way too large for the cache",
    )
    .await;

    // Should not be cached
    let mut ctx = make_ctx("GET", "/api/large");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Max entries eviction ===

#[tokio::test]
async fn test_max_entries_eviction() {
    let plugin = plugin_with_config(json!({
        "max_entries": 2,
        "ttl_seconds": 3600
    }));

    // Cache 3 entries (max is 2, so oldest should be evicted)
    for i in 0..3 {
        let path = format!("/api/item/{}", i);
        cache_response(
            &plugin,
            "GET",
            &path,
            200,
            &HashMap::new(),
            format!("data-{}", i).as_bytes(),
        )
        .await;
    }

    // The third entry should be cached
    let mut ctx = make_ctx("GET", "/api/item/2");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

// === Vary header ===

#[tokio::test]
async fn test_vary_by_headers() {
    let plugin = plugin_with_config(json!({
        "vary_by_headers": ["accept"]
    }));

    // Cache JSON response
    let mut ctx = make_ctx("GET", "/api/data");
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());
    ctx.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, b"{\"json\":true}")
        .await;

    // Cache XML response (different Accept header = different cache key)
    let mut ctx2 = make_ctx("GET", "/api/data");
    ctx2.headers
        .insert("accept".to_string(), "application/xml".to_string());
    ctx2.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut headers2 = HashMap::new();
    plugin.before_proxy(&mut ctx2, &mut headers2).await;
    let mut resp_headers2 = HashMap::new();
    resp_headers2.insert("content-type".to_string(), "application/xml".to_string());
    plugin.after_proxy(&mut ctx2, 200, &mut resp_headers2).await;
    plugin
        .on_response_body(&mut ctx2, 200, &resp_headers2, b"<xml/>")
        .await;

    // JSON accept should get JSON response
    let mut ctx_json = make_ctx("GET", "/api/data");
    ctx_json
        .headers
        .insert("accept".to_string(), "application/json".to_string());
    let mut h = HashMap::new();
    match plugin.before_proxy(&mut ctx_json, &mut h).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "{\"json\":true}");
        }
        _ => panic!("Expected cache HIT for JSON"),
    }

    // XML accept should get XML response
    let mut ctx_xml = make_ctx("GET", "/api/data");
    ctx_xml
        .headers
        .insert("accept".to_string(), "application/xml".to_string());
    let mut h2 = HashMap::new();
    match plugin.before_proxy(&mut ctx_xml, &mut h2).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "<xml/>");
        }
        _ => panic!("Expected cache HIT for XML"),
    }
}

// === X-Cache-Status header ===

#[tokio::test]
async fn test_x_cache_status_miss_header() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert_eq!(resp_headers.get("x-cache-status").unwrap(), "MISS");
}

#[tokio::test]
async fn test_x_cache_status_disabled() {
    let plugin = plugin_with_config(json!({
        "add_cache_status_header": false
    }));

    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!resp_headers.contains_key("x-cache-status"));
}

// === Consumer-keyed caching ===

#[tokio::test]
async fn test_consumer_keyed_caching() {
    let plugin = plugin_with_config(json!({
        "cache_key_include_consumer": true
    }));

    // Cache response for user A
    let mut ctx_a = make_ctx("GET", "/api/data");
    ctx_a.identified_consumer = Some(make_consumer("a", "alice"));
    let mut h = HashMap::new();
    plugin.before_proxy(&mut ctx_a, &mut h).await;
    let mut rh = HashMap::new();
    plugin.after_proxy(&mut ctx_a, 200, &mut rh).await;
    plugin
        .on_response_body(&mut ctx_a, 200, &rh, b"alice-data")
        .await;

    // User B should get a MISS (different consumer = different cache key)
    let mut ctx_b = make_ctx("GET", "/api/data");
    ctx_b.identified_consumer = Some(make_consumer("b", "bob"));
    let mut h2 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx_b, &mut h2).await;
    assert!(matches!(result, PluginResult::Continue));

    // User A should get a HIT
    let mut ctx_a2 = make_ctx("GET", "/api/data");
    ctx_a2.identified_consumer = Some(make_consumer("a", "alice"));
    let mut h3 = HashMap::new();
    match plugin.before_proxy(&mut ctx_a2, &mut h3).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "alice-data");
        }
        _ => panic!("Expected cache HIT for alice"),
    }
}

// === Query string caching ===

#[tokio::test]
async fn test_different_query_params_different_cache() {
    let plugin = default_plugin();

    // Cache response for ?page=1
    let mut ctx1 = make_ctx_with_query("GET", "/api/items", &[("page", "1")]);
    ctx1.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h = HashMap::new();
    plugin.before_proxy(&mut ctx1, &mut h).await;
    let mut rh = HashMap::new();
    plugin.after_proxy(&mut ctx1, 200, &mut rh).await;
    plugin
        .on_response_body(&mut ctx1, 200, &rh, b"page-1-data")
        .await;

    // ?page=2 should be a MISS
    let mut ctx2 = make_ctx_with_query("GET", "/api/items", &[("page", "2")]);
    ctx2.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h2 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx2, &mut h2).await;
    assert!(matches!(result, PluginResult::Continue));

    // ?page=1 should be a HIT
    let mut ctx3 = make_ctx_with_query("GET", "/api/items", &[("page", "1")]);
    ctx3.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h3 = HashMap::new();
    match plugin.before_proxy(&mut ctx3, &mut h3).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "page-1-data");
        }
        _ => panic!("Expected cache HIT"),
    }
}

// === Query-insensitive caching ===

#[tokio::test]
async fn test_query_excluded_from_cache_key() {
    let plugin = plugin_with_config(json!({
        "cache_key_include_query": false
    }));

    // Cache with ?page=1
    let mut ctx1 = make_ctx_with_query("GET", "/api/items", &[("page", "1")]);
    ctx1.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h = HashMap::new();
    plugin.before_proxy(&mut ctx1, &mut h).await;
    let mut rh = HashMap::new();
    plugin.after_proxy(&mut ctx1, 200, &mut rh).await;
    plugin
        .on_response_body(&mut ctx1, 200, &rh, b"same-data")
        .await;

    // ?page=2 should be a HIT (query excluded from key)
    let mut ctx2 = make_ctx_with_query("GET", "/api/items", &[("page", "2")]);
    ctx2.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h2 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx2, &mut h2).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

// === HEAD method cacheable ===

#[tokio::test]
async fn test_head_method_cacheable() {
    let plugin = default_plugin();

    cache_response(&plugin, "HEAD", "/api/data", 200, &HashMap::new(), b"").await;

    let mut ctx = make_ctx("HEAD", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

// === respect_cache_control disabled ===

#[tokio::test]
async fn test_respect_cache_control_disabled() {
    let plugin = plugin_with_config(json!({
        "respect_cache_control": false,
        "ttl_seconds": 3600
    }));

    // Even with no-store, response should be cached when respect_cache_control=false
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "no-store".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &resp_headers,
        b"should be cached",
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

// === Cache-Control: no-cache response not cached ===

#[tokio::test]
async fn test_cache_control_no_cache_response() {
    let plugin = default_plugin();

    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "no-cache".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/volatile",
        200,
        &resp_headers,
        b"volatile data",
    )
    .await;

    // Should not be cached (no-cache means always revalidate)
    let mut ctx = make_ctx("GET", "/api/volatile");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === 301 and 404 cacheable by default ===

#[tokio::test]
async fn test_301_cacheable() {
    let plugin = default_plugin();

    cache_response(&plugin, "GET", "/old-path", 301, &HashMap::new(), b"").await;

    let mut ctx = make_ctx("GET", "/old-path");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 301,
            ..
        }
    ));
}

#[tokio::test]
async fn test_404_cacheable() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/not-found",
        404,
        &HashMap::new(),
        b"not found",
    )
    .await;

    let mut ctx = make_ctx("GET", "/not-found");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

// === Invalidation disabled ===

#[tokio::test]
async fn test_invalidation_disabled() {
    let plugin = plugin_with_config(json!({
        "invalidate_on_unsafe_methods": false
    }));

    cache_response(&plugin, "GET", "/api/items", 200, &HashMap::new(), b"items").await;

    // POST should NOT invalidate when disabled
    let mut ctx = make_ctx("POST", "/api/items");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // GET should still be a HIT
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

// === Max total size ===

#[tokio::test]
async fn test_max_total_size_exceeded() {
    let plugin = plugin_with_config(json!({
        "max_total_size_bytes": 300,
        "max_entry_size_bytes": 1048576
    }));

    // Cache a response that takes up most of the total size
    // Each entry is ~200 bytes body + ~64 bytes overhead = ~264 bytes
    cache_response(&plugin, "GET", "/api/a", 200, &HashMap::new(), &[b'x'; 200]).await;

    // This should fail to cache (would exceed 300-byte total size)
    cache_response(&plugin, "GET", "/api/b", 200, &HashMap::new(), &[b'y'; 200]).await;

    // First should be cached
    let mut ctx = make_ctx("GET", "/api/a");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Reject { .. }));

    // Second should NOT be cached (total size exceeded)
    let mut ctx = make_ctx("GET", "/api/b");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}
