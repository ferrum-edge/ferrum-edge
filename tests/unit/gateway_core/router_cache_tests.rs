use chrono::Utc;
use ferrum_gateway::RouterCache;
use ferrum_gateway::config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
use ferrum_gateway::proxy::build_backend_url;

/// Helper to create a test proxy with sensible defaults.
fn test_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.into(),
        name: Some(format!("Test {}", id)),
        listen_path: listen_path.into(),
        backend_protocol: BackendProtocol::Http,
        backend_host: "backend.example.com".into(),
        backend_port: 3000,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],
        pool_max_idle_per_host: None,
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn test_config(proxies: Vec<Proxy>) -> GatewayConfig {
    GatewayConfig {
        proxies,
        consumers: vec![],
        plugin_configs: vec![],
        loaded_at: Utc::now(),
    }
}

// ============================================================
// Route matching correctness
// ============================================================

#[test]
fn test_longest_prefix_match_two_routes() {
    let config = test_config(vec![
        test_proxy("short", "/api"),
        test_proxy("long", "/api/v1"),
    ]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy("/api/v1/users");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().id, "long");
}

#[test]
fn test_longest_prefix_match_three_routes() {
    let config = test_config(vec![
        test_proxy("short", "/api"),
        test_proxy("medium", "/api/v1"),
        test_proxy("long", "/api/v1/users"),
    ]);
    let cache = RouterCache::new(&config, 100);

    // Should match /api/v1/users (longest)
    let matched = cache.find_proxy("/api/v1/users/123");
    assert_eq!(matched.unwrap().id, "long");

    // Should match /api/v1 (not /api or /api/v1/users)
    let matched = cache.find_proxy("/api/v1/products");
    assert_eq!(matched.unwrap().id, "medium");

    // Should match /api
    let matched = cache.find_proxy("/api/v2/other");
    assert_eq!(matched.unwrap().id, "short");
}

#[test]
fn test_root_path_catch_all() {
    let config = test_config(vec![test_proxy("root", "/"), test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    // /api path should match the specific /api proxy
    let matched = cache.find_proxy("/api/anything");
    assert_eq!(matched.unwrap().id, "api");

    // /other should fall through to root catch-all
    let matched = cache.find_proxy("/other/path");
    assert_eq!(matched.unwrap().id, "root");

    // Bare / should match root
    let matched = cache.find_proxy("/");
    assert_eq!(matched.unwrap().id, "root");
}

#[test]
fn test_exact_match_path_equals_listen_path() {
    let config = test_config(vec![test_proxy("exact", "/api/v1")]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy("/api/v1");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().id, "exact");
}

#[test]
fn test_no_match_returns_none() {
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy("/other/path");
    assert!(matched.is_none());
}

#[test]
fn test_empty_proxy_list() {
    let config = test_config(vec![]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy("/anything");
    assert!(matched.is_none());
    assert_eq!(cache.route_count(), 0);
}

#[test]
fn test_single_proxy() {
    let config = test_config(vec![test_proxy("only", "/service")]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy("/service/endpoint");
    assert_eq!(matched.unwrap().id, "only");
}

#[test]
fn test_proxy_order_independence() {
    // Routes should match by longest prefix regardless of insertion order
    let config1 = test_config(vec![
        test_proxy("short", "/api"),
        test_proxy("long", "/api/v1"),
    ]);
    let config2 = test_config(vec![
        test_proxy("long", "/api/v1"),
        test_proxy("short", "/api"),
    ]);

    let cache1 = RouterCache::new(&config1, 100);
    let cache2 = RouterCache::new(&config2, 100);

    let m1 = cache1.find_proxy("/api/v1/users");
    let m2 = cache2.find_proxy("/api/v1/users");
    assert_eq!(m1.unwrap().id, "long");
    assert_eq!(m2.unwrap().id, "long");
}

// ============================================================
// End-to-end URL mapping: client → gateway → backend
// ============================================================

#[test]
fn test_e2e_strip_listen_path_basic() {
    // Client: GET /api/v1/users/123
    // Proxy: listen_path=/api/v1, strip=true, backend=backend:3000
    // Expected backend URL: http://backend.example.com:3000/users/123
    let config = test_config(vec![test_proxy("api", "/api/v1")]);
    let cache = RouterCache::new(&config, 100);

    let proxy = cache.find_proxy("/api/v1/users/123").unwrap();
    let url = build_backend_url(&proxy, "/api/v1/users/123", "");
    assert_eq!(url, "http://backend.example.com:3000/users/123");
}

#[test]
fn test_e2e_no_strip_listen_path() {
    let mut proxy = test_proxy("api", "/api/v1");
    proxy.strip_listen_path = false;
    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let proxy = cache.find_proxy("/api/v1/users/123").unwrap();
    let url = build_backend_url(&proxy, "/api/v1/users/123", "");
    assert_eq!(url, "http://backend.example.com:3000/api/v1/users/123");
}

#[test]
fn test_e2e_with_backend_path() {
    // Client: GET /api/v1/users/123
    // Proxy: listen_path=/api/v1, strip=true, backend_path=/internal
    // Expected: http://backend.example.com:3000/internal/users/123
    let mut proxy = test_proxy("api", "/api/v1");
    proxy.backend_path = Some("/internal".into());
    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let proxy = cache.find_proxy("/api/v1/users/123").unwrap();
    let url = build_backend_url(&proxy, "/api/v1/users/123", "");
    assert_eq!(url, "http://backend.example.com:3000/internal/users/123");
}

#[test]
fn test_e2e_backend_path_with_nested_listen_path() {
    // Client: GET /api/v1/users/123
    // Proxy: listen_path=/api, strip=true, backend_path=/v2
    // Expected: http://backend.example.com:3000/v2/v1/users/123
    let mut proxy = test_proxy("api", "/api");
    proxy.backend_path = Some("/v2".into());
    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let proxy = cache.find_proxy("/api/v1/users/123").unwrap();
    let url = build_backend_url(&proxy, "/api/v1/users/123", "");
    assert_eq!(url, "http://backend.example.com:3000/v2/v1/users/123");
}

#[test]
fn test_e2e_query_string_preserved() {
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let proxy = cache.find_proxy("/api/search").unwrap();
    let url = build_backend_url(&proxy, "/api/search", "q=hello&page=1");
    assert_eq!(url, "http://backend.example.com:3000/search?q=hello&page=1");
}

#[test]
fn test_e2e_trailing_slash_on_listen_path() {
    // listen_path "/api/v1" should match "/api/v1/" (with trailing slash)
    let config = test_config(vec![test_proxy("api", "/api/v1")]);
    let cache = RouterCache::new(&config, 100);

    let proxy = cache.find_proxy("/api/v1/").unwrap();
    let url = build_backend_url(&proxy, "/api/v1/", "");
    assert_eq!(url, "http://backend.example.com:3000/");
}

#[test]
fn test_e2e_multiple_proxies_different_backends() {
    let mut users_proxy = test_proxy("users", "/api/users");
    users_proxy.backend_host = "users-service.internal".into();
    users_proxy.backend_port = 8001;

    let mut products_proxy = test_proxy("products", "/api/products");
    products_proxy.backend_host = "products-service.internal".into();
    products_proxy.backend_port = 8002;
    products_proxy.backend_path = Some("/v2".into());

    let config = test_config(vec![users_proxy, products_proxy]);
    let cache = RouterCache::new(&config, 100);

    // Users API
    let proxy = cache.find_proxy("/api/users/123").unwrap();
    let url = build_backend_url(&proxy, "/api/users/123", "");
    assert_eq!(url, "http://users-service.internal:8001/123");

    // Products API with backend_path
    let proxy = cache.find_proxy("/api/products/456").unwrap();
    let url = build_backend_url(&proxy, "/api/products/456", "");
    assert_eq!(url, "http://products-service.internal:8002/v2/456");
}

#[test]
fn test_e2e_https_backend_protocol() {
    let mut proxy = test_proxy("secure", "/api");
    proxy.backend_protocol = BackendProtocol::Https;
    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let proxy = cache.find_proxy("/api/data").unwrap();
    let url = build_backend_url(&proxy, "/api/data", "");
    assert_eq!(url, "https://backend.example.com:3000/data");
}

#[test]
fn test_e2e_websocket_protocol() {
    let mut proxy = test_proxy("ws", "/ws");
    proxy.backend_protocol = BackendProtocol::Ws;
    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let proxy = cache.find_proxy("/ws/chat").unwrap();
    let url = build_backend_url(&proxy, "/ws/chat", "");
    assert_eq!(url, "http://backend.example.com:3000/chat");
}

#[test]
fn test_e2e_grpc_protocol() {
    let mut proxy = test_proxy("grpc", "/grpc");
    proxy.backend_protocol = BackendProtocol::Grpc;
    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let proxy = cache.find_proxy("/grpc/service.Method").unwrap();
    let url = build_backend_url(&proxy, "/grpc/service.Method", "");
    assert_eq!(url, "http://backend.example.com:3000/service.Method");
}

// ============================================================
// Cache behavior
// ============================================================

#[test]
fn test_cache_hit_returns_same_result_as_scan() {
    let config = test_config(vec![
        test_proxy("short", "/api"),
        test_proxy("long", "/api/v1"),
    ]);
    let cache = RouterCache::new(&config, 100);

    // First call: cache miss → scan
    let first = cache.find_proxy("/api/v1/users");
    assert_eq!(cache.cache_len(), 1);

    // Second call: cache hit
    let second = cache.find_proxy("/api/v1/users");
    assert_eq!(cache.cache_len(), 1);

    assert_eq!(first.unwrap().id, second.unwrap().id);
}

#[test]
fn test_cache_stores_different_paths() {
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    cache.find_proxy("/api/users");
    cache.find_proxy("/api/products");
    cache.find_proxy("/api/orders");

    assert_eq!(cache.cache_len(), 3);
}

#[test]
fn test_cache_miss_not_cached() {
    // Misses (None) should NOT be cached to avoid unbounded growth from scanners
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let result = cache.find_proxy("/other/path");
    assert!(result.is_none());
    assert_eq!(cache.cache_len(), 0);
}

#[test]
fn test_rebuild_clears_cache_and_uses_new_routes() {
    let config1 = test_config(vec![test_proxy("v1", "/api/v1")]);
    let cache = RouterCache::new(&config1, 100);

    // Populate cache
    let matched = cache.find_proxy("/api/v1/users");
    assert_eq!(matched.unwrap().id, "v1");
    assert_eq!(cache.cache_len(), 1);

    // Rebuild with different config
    let config2 = test_config(vec![test_proxy("v2", "/api/v2")]);
    cache.rebuild(&config2);

    // Cache should be cleared
    assert_eq!(cache.cache_len(), 0);

    // Old route should no longer match
    let matched = cache.find_proxy("/api/v1/users");
    assert!(matched.is_none());

    // New route should match
    let matched = cache.find_proxy("/api/v2/users");
    assert_eq!(matched.unwrap().id, "v2");
}

#[test]
fn test_rebuild_updates_route_count() {
    let config1 = test_config(vec![test_proxy("a", "/a"), test_proxy("b", "/b")]);
    let cache = RouterCache::new(&config1, 100);
    assert_eq!(cache.route_count(), 2);

    let config2 = test_config(vec![
        test_proxy("x", "/x"),
        test_proxy("y", "/y"),
        test_proxy("z", "/z"),
    ]);
    cache.rebuild(&config2);
    assert_eq!(cache.route_count(), 3);
}

#[test]
fn test_bounded_capacity_clears_on_overflow() {
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 5); // Very low capacity

    // Fill beyond capacity
    for i in 0..10 {
        cache.find_proxy(&format!("/api/path/{}", i));
    }

    // Cache should have been cleared and refilled, not grown unbounded
    assert!(cache.cache_len() <= 5);
}

#[tokio::test]
async fn test_concurrent_find_proxy() {
    let config = test_config(vec![test_proxy("api", "/api"), test_proxy("web", "/web")]);
    let cache = std::sync::Arc::new(RouterCache::new(&config, 1000));

    let mut handles = vec![];
    for i in 0..50 {
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            let path = if i % 2 == 0 {
                "/api/resource"
            } else {
                "/web/page"
            };
            let result = cache.find_proxy(path);
            assert!(result.is_some());
            if i % 2 == 0 {
                assert_eq!(result.unwrap().id, "api");
            } else {
                assert_eq!(result.unwrap().id, "web");
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

// ============================================================
// Edge cases
// ============================================================

#[test]
fn test_double_slashes_in_path() {
    // Double slashes are passed through as-is (no normalization)
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy("/api//v1//users");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().id, "api");
}

#[test]
fn test_very_long_path() {
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let long_suffix = "a".repeat(10_000);
    let path = format!("/api/{}", long_suffix);
    let matched = cache.find_proxy(&path);
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().id, "api");
}

#[test]
fn test_listen_path_must_be_prefix_not_substring() {
    // /api should NOT match /my-api (it's not a prefix)
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy("/my-api/endpoint");
    assert!(matched.is_none());
}

#[test]
fn test_e2e_exact_listen_path_no_remaining() {
    // When request path exactly equals listen_path and strip=true,
    // remaining path is empty → backend should get "/"
    let config = test_config(vec![test_proxy("api", "/api/v1")]);
    let cache = RouterCache::new(&config, 100);

    let proxy = cache.find_proxy("/api/v1").unwrap();
    let url = build_backend_url(&proxy, "/api/v1", "");
    assert_eq!(url, "http://backend.example.com:3000/");
}
