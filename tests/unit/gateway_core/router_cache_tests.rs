use chrono::Utc;
use ferrum_gateway::RouterCache;
use ferrum_gateway::config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
use ferrum_gateway::proxy::build_backend_url;

/// Helper to create a test proxy with sensible defaults.
fn test_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.into(),
        name: Some(format!("Test {}", id)),
        hosts: vec![],
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
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        udp_idle_timeout_seconds: 60,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn test_config(proxies: Vec<Proxy>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
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

    let matched = cache.find_proxy(None, "/api/v1/users");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().proxy.id, "long");
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
    let matched = cache.find_proxy(None, "/api/v1/users/123");
    assert_eq!(matched.unwrap().proxy.id, "long");

    // Should match /api/v1 (not /api or /api/v1/users)
    let matched = cache.find_proxy(None, "/api/v1/products");
    assert_eq!(matched.unwrap().proxy.id, "medium");

    // Should match /api
    let matched = cache.find_proxy(None, "/api/v2/other");
    assert_eq!(matched.unwrap().proxy.id, "short");
}

#[test]
fn test_root_path_catch_all() {
    let config = test_config(vec![test_proxy("root", "/"), test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    // /api path should match the specific /api proxy
    let matched = cache.find_proxy(None, "/api/anything");
    assert_eq!(matched.unwrap().proxy.id, "api");

    // /other should fall through to root catch-all
    let matched = cache.find_proxy(None, "/other/path");
    assert_eq!(matched.unwrap().proxy.id, "root");

    // Bare / should match root
    let matched = cache.find_proxy(None, "/");
    assert_eq!(matched.unwrap().proxy.id, "root");
}

#[test]
fn test_exact_match_path_equals_listen_path() {
    let config = test_config(vec![test_proxy("exact", "/api/v1")]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(None, "/api/v1");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().proxy.id, "exact");
}

#[test]
fn test_no_match_returns_none() {
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(None, "/other/path");
    assert!(matched.is_none());
}

#[test]
fn test_empty_proxy_list() {
    let config = test_config(vec![]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(None, "/anything");
    assert!(matched.is_none());
    assert_eq!(cache.route_count(), 0);
}

#[test]
fn test_single_proxy() {
    let config = test_config(vec![test_proxy("only", "/service")]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(None, "/service/endpoint");
    assert_eq!(matched.unwrap().proxy.id, "only");
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

    let m1 = cache1.find_proxy(None, "/api/v1/users");
    let m2 = cache2.find_proxy(None, "/api/v1/users");
    assert_eq!(m1.unwrap().proxy.id, "long");
    assert_eq!(m2.unwrap().proxy.id, "long");
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

    let rm = cache.find_proxy(None, "/api/v1/users/123").unwrap();
    let url = build_backend_url(&rm.proxy, "/api/v1/users/123", "", rm.matched_prefix_len);
    assert_eq!(url, "http://backend.example.com:3000/users/123");
}

#[test]
fn test_e2e_no_strip_listen_path() {
    let mut proxy = test_proxy("api", "/api/v1");
    proxy.strip_listen_path = false;
    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/api/v1/users/123").unwrap();
    let url = build_backend_url(&rm.proxy, "/api/v1/users/123", "", rm.matched_prefix_len);
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

    let rm = cache.find_proxy(None, "/api/v1/users/123").unwrap();
    let url = build_backend_url(&rm.proxy, "/api/v1/users/123", "", rm.matched_prefix_len);
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

    let rm = cache.find_proxy(None, "/api/v1/users/123").unwrap();
    let url = build_backend_url(&rm.proxy, "/api/v1/users/123", "", rm.matched_prefix_len);
    assert_eq!(url, "http://backend.example.com:3000/v2/v1/users/123");
}

#[test]
fn test_e2e_query_string_preserved() {
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/api/search").unwrap();
    let url = build_backend_url(
        &rm.proxy,
        "/api/search",
        "q=hello&page=1",
        rm.matched_prefix_len,
    );
    assert_eq!(url, "http://backend.example.com:3000/search?q=hello&page=1");
}

#[test]
fn test_e2e_trailing_slash_on_listen_path() {
    // listen_path "/api/v1" should match "/api/v1/" (with trailing slash)
    let config = test_config(vec![test_proxy("api", "/api/v1")]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/api/v1/").unwrap();
    let url = build_backend_url(&rm.proxy, "/api/v1/", "", rm.matched_prefix_len);
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
    let rm = cache.find_proxy(None, "/api/users/123").unwrap();
    let url = build_backend_url(&rm.proxy, "/api/users/123", "", rm.matched_prefix_len);
    assert_eq!(url, "http://users-service.internal:8001/123");

    // Products API with backend_path
    let rm = cache.find_proxy(None, "/api/products/456").unwrap();
    let url = build_backend_url(&rm.proxy, "/api/products/456", "", rm.matched_prefix_len);
    assert_eq!(url, "http://products-service.internal:8002/v2/456");
}

#[test]
fn test_e2e_https_backend_protocol() {
    let mut proxy = test_proxy("secure", "/api");
    proxy.backend_protocol = BackendProtocol::Https;
    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/api/data").unwrap();
    let url = build_backend_url(&rm.proxy, "/api/data", "", rm.matched_prefix_len);
    assert_eq!(url, "https://backend.example.com:3000/data");
}

#[test]
fn test_e2e_websocket_protocol() {
    let mut proxy = test_proxy("ws", "/ws");
    proxy.backend_protocol = BackendProtocol::Ws;
    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/ws/chat").unwrap();
    let url = build_backend_url(&rm.proxy, "/ws/chat", "", rm.matched_prefix_len);
    assert_eq!(url, "http://backend.example.com:3000/chat");
}

#[test]
fn test_e2e_grpc_protocol() {
    let mut proxy = test_proxy("grpc", "/grpc");
    proxy.backend_protocol = BackendProtocol::Grpc;
    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/grpc/service.Method").unwrap();
    let url = build_backend_url(&rm.proxy, "/grpc/service.Method", "", rm.matched_prefix_len);
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
    let first = cache.find_proxy(None, "/api/v1/users");
    assert_eq!(cache.cache_len(), 1);

    // Second call: cache hit
    let second = cache.find_proxy(None, "/api/v1/users");
    assert_eq!(cache.cache_len(), 1);

    assert_eq!(first.unwrap().proxy.id, second.unwrap().proxy.id);
}

#[test]
fn test_cache_stores_different_paths() {
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    cache.find_proxy(None, "/api/users");
    cache.find_proxy(None, "/api/products");
    cache.find_proxy(None, "/api/orders");

    assert_eq!(cache.cache_len(), 3);
}

#[test]
fn test_cache_miss_not_cached() {
    // Misses (None) ARE cached as negative entries to prevent O(n) rescans
    // from scanner/bot traffic. The cache is bounded by max_cache_entries.
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let result = cache.find_proxy(None, "/other/path");
    assert!(result.is_none());
    // Negative entry is cached
    assert_eq!(cache.cache_len(), 1);

    // Second lookup hits the negative cache (O(1) instead of O(n) rescan)
    let result2 = cache.find_proxy(None, "/other/path");
    assert!(result2.is_none());
    assert_eq!(cache.cache_len(), 1);
}

#[test]
fn test_rebuild_clears_cache_and_uses_new_routes() {
    let config1 = test_config(vec![test_proxy("v1", "/api/v1")]);
    let cache = RouterCache::new(&config1, 100);

    // Populate cache
    let matched = cache.find_proxy(None, "/api/v1/users");
    assert_eq!(matched.unwrap().proxy.id, "v1");
    assert_eq!(cache.cache_len(), 1);

    // Rebuild with different config
    let config2 = test_config(vec![test_proxy("v2", "/api/v2")]);
    cache.rebuild(&config2);

    // Cache should be cleared
    assert_eq!(cache.cache_len(), 0);

    // Old route should no longer match
    let matched = cache.find_proxy(None, "/api/v1/users");
    assert!(matched.is_none());

    // New route should match
    let matched = cache.find_proxy(None, "/api/v2/users");
    assert_eq!(matched.unwrap().proxy.id, "v2");
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
        cache.find_proxy(None, &format!("/api/path/{}", i));
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
            let result = cache.find_proxy(None, path);
            assert!(result.is_some());
            if i % 2 == 0 {
                assert_eq!(result.unwrap().proxy.id, "api");
            } else {
                assert_eq!(result.unwrap().proxy.id, "web");
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

    let matched = cache.find_proxy(None, "/api//v1//users");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().proxy.id, "api");
}

#[test]
fn test_very_long_path() {
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let long_suffix = "a".repeat(10_000);
    let path = format!("/api/{}", long_suffix);
    let matched = cache.find_proxy(None, &path);
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().proxy.id, "api");
}

#[test]
fn test_listen_path_must_be_prefix_not_substring() {
    // /api should NOT match /my-api (it's not a prefix)
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(None, "/my-api/endpoint");
    assert!(matched.is_none());
}

#[test]
fn test_e2e_exact_listen_path_no_remaining() {
    // When request path exactly equals listen_path and strip=true,
    // remaining path is empty → backend should get "/"
    let config = test_config(vec![test_proxy("api", "/api/v1")]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/api/v1").unwrap();
    let url = build_backend_url(&rm.proxy, "/api/v1", "", rm.matched_prefix_len);
    assert_eq!(url, "http://backend.example.com:3000/");
}

// ============================================================
// Host-based routing
// ============================================================

/// Helper to create a test proxy with hosts.
fn test_proxy_with_hosts(id: &str, listen_path: &str, hosts: Vec<&str>) -> Proxy {
    let mut p = test_proxy(id, listen_path);
    p.hosts = hosts.into_iter().map(String::from).collect();
    p
}

#[test]
fn test_host_exact_match_with_path() {
    let config = test_config(vec![
        test_proxy_with_hosts("api", "/", vec!["api.example.com"]),
        test_proxy_with_hosts("admin", "/", vec!["admin.example.com"]),
    ]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(Some("api.example.com"), "/users");
    assert_eq!(matched.unwrap().proxy.id, "api");

    let matched = cache.find_proxy(Some("admin.example.com"), "/users");
    assert_eq!(matched.unwrap().proxy.id, "admin");
}

#[test]
fn test_host_wildcard_match() {
    let config = test_config(vec![test_proxy_with_hosts(
        "wildcard",
        "/",
        vec!["*.example.com"],
    )]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(Some("api.example.com"), "/");
    assert_eq!(matched.unwrap().proxy.id, "wildcard");

    let matched = cache.find_proxy(Some("admin.example.com"), "/path");
    assert_eq!(matched.unwrap().proxy.id, "wildcard");
}

#[test]
fn test_wildcard_does_not_match_base_domain() {
    let config = test_config(vec![test_proxy_with_hosts(
        "wildcard",
        "/",
        vec!["*.example.com"],
    )]);
    let cache = RouterCache::new(&config, 100);

    // *.example.com should NOT match example.com itself
    let matched = cache.find_proxy(Some("example.com"), "/");
    assert!(matched.is_none());
}

#[test]
fn test_wildcard_does_not_match_multi_level() {
    let config = test_config(vec![test_proxy_with_hosts(
        "wildcard",
        "/",
        vec!["*.example.com"],
    )]);
    let cache = RouterCache::new(&config, 100);

    // *.example.com should NOT match a.b.example.com (multi-level)
    let matched = cache.find_proxy(Some("a.b.example.com"), "/");
    assert!(matched.is_none());
}

#[test]
fn test_host_priority_exact_over_wildcard() {
    let mut exact = test_proxy_with_hosts("exact", "/", vec!["api.example.com"]);
    exact.backend_host = "exact-backend".into();

    let mut wildcard = test_proxy_with_hosts("wildcard", "/", vec!["*.example.com"]);
    wildcard.backend_host = "wildcard-backend".into();

    let config = test_config(vec![exact, wildcard]);
    let cache = RouterCache::new(&config, 100);

    // Exact host should take priority over wildcard
    let matched = cache.find_proxy(Some("api.example.com"), "/");
    assert_eq!(matched.unwrap().proxy.id, "exact");

    // Non-exact should fall through to wildcard
    let matched = cache.find_proxy(Some("other.example.com"), "/");
    assert_eq!(matched.unwrap().proxy.id, "wildcard");
}

#[test]
fn test_host_priority_wildcard_over_catchall() {
    let mut wildcard = test_proxy_with_hosts("wildcard", "/", vec!["*.example.com"]);
    wildcard.backend_host = "wildcard-backend".into();

    let mut catchall = test_proxy("catchall", "/");
    catchall.backend_host = "catchall-backend".into();

    let config = test_config(vec![wildcard, catchall]);
    let cache = RouterCache::new(&config, 100);

    // Wildcard should take priority over catch-all
    let matched = cache.find_proxy(Some("api.example.com"), "/");
    assert_eq!(matched.unwrap().proxy.id, "wildcard");

    // Unmatched host should fall through to catch-all
    let matched = cache.find_proxy(Some("other.org"), "/");
    assert_eq!(matched.unwrap().proxy.id, "catchall");
}

#[test]
fn test_no_host_proxy_matches_all_hosts() {
    // Backward compatibility: proxies with empty hosts match all hosts
    let config = test_config(vec![test_proxy("catchall", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(Some("api.example.com"), "/api/users");
    assert_eq!(matched.unwrap().proxy.id, "catchall");

    let matched = cache.find_proxy(Some("anything.org"), "/api/users");
    assert_eq!(matched.unwrap().proxy.id, "catchall");

    let matched = cache.find_proxy(None, "/api/users");
    assert_eq!(matched.unwrap().proxy.id, "catchall");
}

#[test]
fn test_host_with_port_stripped() {
    // Port stripping happens in the proxy handler before calling find_proxy,
    // so we simulate by passing the host without port
    let config = test_config(vec![test_proxy_with_hosts(
        "api",
        "/",
        vec!["api.example.com"],
    )]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(Some("api.example.com"), "/");
    assert_eq!(matched.unwrap().proxy.id, "api");
}

#[test]
fn test_host_case_insensitive() {
    // Host normalization happens before calling find_proxy (to_lowercase),
    // so we test with lowercase host against lowercase config
    let config = test_config(vec![test_proxy_with_hosts(
        "api",
        "/",
        vec!["api.example.com"],
    )]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(Some("api.example.com"), "/");
    assert_eq!(matched.unwrap().proxy.id, "api");
}

#[test]
fn test_same_path_different_hosts() {
    // Two proxies can share the same listen_path if they have different hosts
    let mut api = test_proxy_with_hosts("api", "/", vec!["api.example.com"]);
    api.backend_host = "api-backend".into();

    let mut admin = test_proxy_with_hosts("admin", "/", vec!["admin.example.com"]);
    admin.backend_host = "admin-backend".into();

    let config = test_config(vec![api, admin]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(Some("api.example.com"), "/users");
    assert_eq!(matched.unwrap().proxy.id, "api");

    let matched = cache.find_proxy(Some("admin.example.com"), "/users");
    assert_eq!(matched.unwrap().proxy.id, "admin");
}

#[test]
fn test_cache_key_includes_host() {
    // Same path, different hosts should produce different cache entries
    let config = test_config(vec![
        test_proxy_with_hosts("api", "/", vec!["api.example.com"]),
        test_proxy_with_hosts("admin", "/", vec!["admin.example.com"]),
    ]);
    let cache = RouterCache::new(&config, 100);

    cache.find_proxy(Some("api.example.com"), "/users");
    cache.find_proxy(Some("admin.example.com"), "/users");

    // Two different cache entries (one per host+path)
    assert_eq!(cache.cache_len(), 2);
}

#[test]
fn test_rebuild_clears_host_path_cache() {
    let config1 = test_config(vec![test_proxy_with_hosts(
        "api",
        "/",
        vec!["api.example.com"],
    )]);
    let cache = RouterCache::new(&config1, 100);

    cache.find_proxy(Some("api.example.com"), "/users");
    assert_eq!(cache.cache_len(), 1);

    let config2 = test_config(vec![test_proxy_with_hosts(
        "new-api",
        "/",
        vec!["new.example.com"],
    )]);
    cache.rebuild(&config2);
    assert_eq!(cache.cache_len(), 0);

    // Old host should no longer match
    let matched = cache.find_proxy(Some("api.example.com"), "/users");
    assert!(matched.is_none());

    // New host should match
    let matched = cache.find_proxy(Some("new.example.com"), "/users");
    assert_eq!(matched.unwrap().proxy.id, "new-api");
}

#[test]
fn test_host_with_path_matching_combined() {
    // Host-based routing combined with path-based routing
    let config = test_config(vec![
        test_proxy_with_hosts("api-v1", "/api/v1", vec!["api.example.com"]),
        test_proxy_with_hosts("api-v2", "/api/v2", vec!["api.example.com"]),
        test_proxy_with_hosts("admin-root", "/", vec!["admin.example.com"]),
    ]);
    let cache = RouterCache::new(&config, 100);

    // api.example.com + /api/v1 → api-v1
    let matched = cache.find_proxy(Some("api.example.com"), "/api/v1/users");
    assert_eq!(matched.unwrap().proxy.id, "api-v1");

    // api.example.com + /api/v2 → api-v2
    let matched = cache.find_proxy(Some("api.example.com"), "/api/v2/users");
    assert_eq!(matched.unwrap().proxy.id, "api-v2");

    // admin.example.com + any path → admin-root
    let matched = cache.find_proxy(Some("admin.example.com"), "/dashboard");
    assert_eq!(matched.unwrap().proxy.id, "admin-root");

    // api.example.com + unmatched path → no match (no catch-all for this host)
    let matched = cache.find_proxy(Some("api.example.com"), "/other");
    assert!(matched.is_none());
}

#[test]
fn test_multiple_hosts_on_single_proxy() {
    // A single proxy can match multiple exact hosts
    let config = test_config(vec![test_proxy_with_hosts(
        "multi",
        "/",
        vec!["api.example.com", "api.example.org"],
    )]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(Some("api.example.com"), "/");
    assert_eq!(matched.unwrap().proxy.id, "multi");

    let matched = cache.find_proxy(Some("api.example.org"), "/");
    assert_eq!(matched.unwrap().proxy.id, "multi");

    let matched = cache.find_proxy(Some("other.com"), "/");
    assert!(matched.is_none());
}

#[test]
fn test_no_host_header_falls_to_catchall() {
    let config = test_config(vec![
        test_proxy_with_hosts("specific", "/", vec!["api.example.com"]),
        test_proxy("catchall", "/"),
    ]);
    let cache = RouterCache::new(&config, 100);

    // No Host header → skip exact/wildcard tiers, match catch-all
    let matched = cache.find_proxy(None, "/users");
    assert_eq!(matched.unwrap().proxy.id, "catchall");
}

#[test]
fn test_full_priority_chain() {
    // exact host > wildcard host > catch-all, all with same path
    let config = test_config(vec![
        test_proxy_with_hosts("exact", "/api", vec!["api.example.com"]),
        test_proxy_with_hosts("wildcard", "/api", vec!["*.example.com"]),
        test_proxy("catchall", "/api"),
    ]);
    let cache = RouterCache::new(&config, 100);

    // Exact match wins
    let matched = cache.find_proxy(Some("api.example.com"), "/api/users");
    assert_eq!(matched.unwrap().proxy.id, "exact");

    // Wildcard match (not exact)
    let matched = cache.find_proxy(Some("other.example.com"), "/api/users");
    assert_eq!(matched.unwrap().proxy.id, "wildcard");

    // No match in exact or wildcard → catch-all
    let matched = cache.find_proxy(Some("other.org"), "/api/users");
    assert_eq!(matched.unwrap().proxy.id, "catchall");

    // No host → catch-all
    let matched = cache.find_proxy(None, "/api/users");
    assert_eq!(matched.unwrap().proxy.id, "catchall");
}

// ============================================================
// Regex path routing
// ============================================================

/// Helper to create a test proxy with a regex listen_path.
fn test_regex_proxy(id: &str, regex_path: &str) -> Proxy {
    let mut p = test_proxy(id, &format!("~{}", regex_path));
    p.backend_host = "regex-backend".into();
    p
}

#[test]
fn test_regex_basic_match() {
    let config = test_config(vec![test_regex_proxy(
        "user-orders",
        r"/users/[^/]+/orders",
    )]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(None, "/users/42/orders");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().proxy.id, "user-orders");
}

#[test]
fn test_regex_no_match() {
    let config = test_config(vec![test_regex_proxy(
        "user-orders",
        r"/users/[^/]+/orders",
    )]);
    let cache = RouterCache::new(&config, 100);

    // Path doesn't match the regex
    let matched = cache.find_proxy(None, "/products/42/orders");
    assert!(matched.is_none());
}

#[test]
fn test_regex_named_captures() {
    let config = test_config(vec![test_regex_proxy(
        "user-orders",
        r"/users/(?P<user_id>[^/]+)/orders/(?P<order_id>[^/]+)",
    )]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(None, "/users/42/orders/99/details");
    assert!(matched.is_some());
    let rm = matched.unwrap();
    assert_eq!(rm.proxy.id, "user-orders");
    assert_eq!(rm.path_params.len(), 2);
    assert!(
        rm.path_params
            .contains(&("user_id".to_string(), "42".to_string()))
    );
    assert!(
        rm.path_params
            .contains(&("order_id".to_string(), "99".to_string()))
    );
}

#[test]
fn test_regex_matched_prefix_len() {
    let config = test_config(vec![test_regex_proxy(
        "user-orders",
        r"/users/[^/]+/orders",
    )]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(None, "/users/42/orders/pending");
    let rm = matched.unwrap();
    // The regex matches "/users/42/orders" (19 chars)
    assert_eq!(rm.matched_prefix_len, "/users/42/orders".len());
}

#[test]
fn test_prefix_beats_regex() {
    // Prefix routes always take priority over regex routes
    let config = test_config(vec![
        test_proxy("prefix", "/users"),
        test_regex_proxy("regex", r"/users/[^/]+/orders"),
    ]);
    let cache = RouterCache::new(&config, 100);

    // This matches both the prefix /users and the regex pattern
    let matched = cache.find_proxy(None, "/users/42/orders");
    assert_eq!(matched.unwrap().proxy.id, "prefix");
}

#[test]
fn test_regex_fallback_when_no_prefix() {
    // Regex routes are checked when no prefix route matches
    let config = test_config(vec![
        test_proxy("api", "/api"),
        test_regex_proxy("user-orders", r"/users/[^/]+/orders"),
    ]);
    let cache = RouterCache::new(&config, 100);

    // /api matches the prefix route
    let matched = cache.find_proxy(None, "/api/test");
    assert_eq!(matched.unwrap().proxy.id, "api");

    // /users/42/orders doesn't match /api, falls through to regex
    let matched = cache.find_proxy(None, "/users/42/orders");
    assert_eq!(matched.unwrap().proxy.id, "user-orders");
}

#[test]
fn test_regex_with_remaining_path() {
    // Regex match with additional path segments after the matched portion
    let config = test_config(vec![test_regex_proxy(
        "user-orders",
        r"/users/[^/]+/orders",
    )]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(None, "/users/42/orders/99/items");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().proxy.id, "user-orders");
}

#[test]
fn test_regex_cache_separation() {
    // Regex matches use the regex cache, prefix matches use the prefix cache
    let config = test_config(vec![
        test_proxy("api", "/api"),
        test_regex_proxy("user-orders", r"/users/[^/]+/orders"),
    ]);
    let cache = RouterCache::new(&config, 100);

    // Prefix match → prefix cache
    cache.find_proxy(None, "/api/test");
    assert_eq!(cache.cache_len(), 1);
    assert_eq!(cache.regex_cache_len(), 0);

    // Regex match → regex cache
    cache.find_proxy(None, "/users/42/orders");
    assert_eq!(cache.cache_len(), 1); // prefix cache unchanged
    assert_eq!(cache.regex_cache_len(), 1);

    // Different regex path → another regex cache entry
    cache.find_proxy(None, "/users/99/orders");
    assert_eq!(cache.cache_len(), 1);
    assert_eq!(cache.regex_cache_len(), 2);
}

#[test]
fn test_regex_cache_hit() {
    let config = test_config(vec![test_regex_proxy(
        "user-orders",
        r"/users/(?P<user_id>[^/]+)/orders",
    )]);
    let cache = RouterCache::new(&config, 100);

    // First call: cache miss → regex scan
    let first = cache.find_proxy(None, "/users/42/orders");
    assert_eq!(cache.regex_cache_len(), 1);

    // Second call: cache hit (same path)
    let second = cache.find_proxy(None, "/users/42/orders");
    assert_eq!(cache.regex_cache_len(), 1); // no new entry

    assert_eq!(first.unwrap().proxy.id, second.unwrap().proxy.id);
}

#[test]
fn test_regex_negative_cache() {
    // When neither prefix nor regex matches, a negative entry goes in the prefix cache
    let config = test_config(vec![
        test_proxy("api", "/api"),
        test_regex_proxy("user-orders", r"/users/[^/]+/orders"),
    ]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(None, "/unknown/path");
    assert!(matched.is_none());
    // Negative entry is in the prefix cache
    assert_eq!(cache.cache_len(), 1);
    assert_eq!(cache.regex_cache_len(), 0);
}

#[test]
fn test_regex_auto_anchor() {
    // Regex should only match from the start of the path (auto-anchored with ^)
    let config = test_config(vec![test_regex_proxy("users", r"/users/[^/]+")]);
    let cache = RouterCache::new(&config, 100);

    // Should match — starts with /users/
    let matched = cache.find_proxy(None, "/users/42");
    assert!(matched.is_some());

    // Should NOT match — /users is not at the start
    let matched = cache.find_proxy(None, "/api/users/42");
    assert!(matched.is_none());
}

#[test]
fn test_regex_with_host_routing() {
    // Regex routes work with host-based routing tiers
    let mut regex_proxy = test_regex_proxy("user-api", r"/users/[^/]+");
    regex_proxy.hosts = vec!["api.example.com".to_string()];

    let config = test_config(vec![regex_proxy]);
    let cache = RouterCache::new(&config, 100);

    // Matches exact host + regex path
    let matched = cache.find_proxy(Some("api.example.com"), "/users/42");
    assert_eq!(matched.unwrap().proxy.id, "user-api");

    // Wrong host → no match
    let matched = cache.find_proxy(Some("other.com"), "/users/42");
    assert!(matched.is_none());
}

#[test]
fn test_regex_with_wildcard_host() {
    let mut regex_proxy = test_regex_proxy("user-api", r"/users/[^/]+");
    regex_proxy.hosts = vec!["*.example.com".to_string()];

    let config = test_config(vec![regex_proxy]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(Some("api.example.com"), "/users/42");
    assert_eq!(matched.unwrap().proxy.id, "user-api");

    let matched = cache.find_proxy(Some("admin.example.com"), "/users/42");
    assert_eq!(matched.unwrap().proxy.id, "user-api");
}

#[test]
fn test_regex_host_priority_prefix_over_regex() {
    // Within exact host tier: prefix route beats regex route
    let mut prefix_proxy = test_proxy_with_hosts("prefix", "/users", vec!["api.example.com"]);
    prefix_proxy.backend_host = "prefix-backend".into();

    let mut regex_proxy = test_regex_proxy("regex", r"/users/[^/]+/orders");
    regex_proxy.hosts = vec!["api.example.com".to_string()];

    let config = test_config(vec![prefix_proxy, regex_proxy]);
    let cache = RouterCache::new(&config, 100);

    // Prefix wins for the same host
    let matched = cache.find_proxy(Some("api.example.com"), "/users/42/orders");
    assert_eq!(matched.unwrap().proxy.id, "prefix");
}

#[test]
fn test_regex_multiple_patterns() {
    let config = test_config(vec![
        test_regex_proxy("user-orders", r"/users/[^/]+/orders"),
        test_regex_proxy("product-reviews", r"/products/[^/]+/reviews"),
    ]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(None, "/users/42/orders/1");
    assert_eq!(matched.unwrap().proxy.id, "user-orders");

    let matched = cache.find_proxy(None, "/products/widget/reviews/5");
    assert_eq!(matched.unwrap().proxy.id, "product-reviews");
}

#[test]
fn test_regex_route_count() {
    let config = test_config(vec![
        test_proxy("api", "/api"),
        test_regex_proxy("user-orders", r"/users/[^/]+/orders"),
        test_regex_proxy("product-reviews", r"/products/[^/]+/reviews"),
    ]);
    let cache = RouterCache::new(&config, 100);

    // 1 prefix + 2 regex = 3 total routes
    assert_eq!(cache.route_count(), 3);
}

#[test]
fn test_regex_rebuild_clears_caches() {
    let config1 = test_config(vec![test_regex_proxy("v1", r"/users/[^/]+")]);
    let cache = RouterCache::new(&config1, 100);

    cache.find_proxy(None, "/users/42");
    assert_eq!(cache.regex_cache_len(), 1);

    // Rebuild with different config
    let config2 = test_config(vec![test_regex_proxy("v2", r"/products/[^/]+")]);
    cache.rebuild(&config2);

    assert_eq!(cache.regex_cache_len(), 0);
    assert_eq!(cache.cache_len(), 0);

    // Old regex should no longer match
    let matched = cache.find_proxy(None, "/users/42");
    assert!(matched.is_none());

    // New regex should match
    let matched = cache.find_proxy(None, "/products/widget");
    assert_eq!(matched.unwrap().proxy.id, "v2");
}

#[test]
fn test_regex_e2e_strip_listen_path() {
    // Regex route with strip_listen_path: strip the matched portion
    let mut proxy = test_regex_proxy("user-orders", r"/users/[^/]+/orders");
    proxy.strip_listen_path = true;
    proxy.backend_host = "orders-service".into();
    proxy.backend_port = 8080;

    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/users/42/orders/pending").unwrap();
    let url = build_backend_url(
        &rm.proxy,
        "/users/42/orders/pending",
        "",
        rm.matched_prefix_len,
    );
    // Matched portion is "/users/42/orders" (16 chars), remaining is "/pending"
    assert_eq!(url, "http://orders-service:8080/pending");
}

#[test]
fn test_regex_e2e_no_strip() {
    let mut proxy = test_regex_proxy("user-orders", r"/users/[^/]+/orders");
    proxy.strip_listen_path = false;
    proxy.backend_host = "orders-service".into();
    proxy.backend_port = 8080;

    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/users/42/orders/pending").unwrap();
    let url = build_backend_url(
        &rm.proxy,
        "/users/42/orders/pending",
        "",
        rm.matched_prefix_len,
    );
    // No stripping — full path is forwarded
    assert_eq!(url, "http://orders-service:8080/users/42/orders/pending");
}

#[test]
fn test_regex_e2e_with_query_string() {
    let mut proxy = test_regex_proxy("search", r"/search/[^/]+");
    proxy.backend_host = "search-service".into();
    proxy.backend_port = 8080;

    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/search/products").unwrap();
    let url = build_backend_url(
        &rm.proxy,
        "/search/products",
        "q=hello&page=1",
        rm.matched_prefix_len,
    );
    assert_eq!(url, "http://search-service:8080/?q=hello&page=1");
}

#[test]
fn test_regex_e2e_with_backend_path() {
    let mut proxy = test_regex_proxy("user-orders", r"/users/[^/]+/orders");
    proxy.strip_listen_path = true;
    proxy.backend_path = Some("/internal".into());
    proxy.backend_host = "orders-service".into();
    proxy.backend_port = 8080;

    let config = test_config(vec![proxy]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/users/42/orders/pending").unwrap();
    let url = build_backend_url(
        &rm.proxy,
        "/users/42/orders/pending",
        "",
        rm.matched_prefix_len,
    );
    assert_eq!(url, "http://orders-service:8080/internal/pending");
}

#[test]
fn test_regex_path_params_cached_correctly() {
    let config = test_config(vec![test_regex_proxy(
        "users",
        r"/users/(?P<id>[^/]+)/profile",
    )]);
    let cache = RouterCache::new(&config, 100);

    // First request: cache miss
    let rm1 = cache.find_proxy(None, "/users/42/profile").unwrap();
    assert_eq!(rm1.path_params, vec![("id".to_string(), "42".to_string())]);

    // Same path: cache hit — same params
    let rm2 = cache.find_proxy(None, "/users/42/profile").unwrap();
    assert_eq!(rm2.path_params, vec![("id".to_string(), "42".to_string())]);

    // Different path: different params
    let rm3 = cache.find_proxy(None, "/users/99/profile").unwrap();
    assert_eq!(rm3.path_params, vec![("id".to_string(), "99".to_string())]);
}

#[test]
fn test_regex_prefix_no_path_params() {
    // Prefix routes should always have empty path_params
    let config = test_config(vec![test_proxy("api", "/api")]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/api/test").unwrap();
    assert!(rm.path_params.is_empty());
    assert_eq!(rm.matched_prefix_len, "/api".len());
}

#[test]
fn test_regex_invalid_pattern_skipped() {
    // Invalid regex should be skipped (logged as warning), not crash
    let config = test_config(vec![
        test_proxy("fallback", "/"),
        test_regex_proxy("bad", r"/users/[invalid"),
    ]);
    let cache = RouterCache::new(&config, 100);

    // The invalid regex route is skipped, fallback catches everything
    let matched = cache.find_proxy(None, "/users/42");
    assert_eq!(matched.unwrap().proxy.id, "fallback");
    // Only the prefix route should be counted (invalid regex skipped)
    assert_eq!(cache.route_count(), 1);
}

#[tokio::test]
async fn test_regex_concurrent_find_proxy() {
    let config = test_config(vec![
        test_proxy("api", "/api"),
        test_regex_proxy("users", r"/users/(?P<id>[^/]+)"),
    ]);
    let cache = std::sync::Arc::new(RouterCache::new(&config, 1000));

    let mut handles = vec![];
    for i in 0..50 {
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            if i % 2 == 0 {
                let result = cache.find_proxy(None, "/api/resource");
                assert_eq!(result.unwrap().proxy.id, "api");
            } else {
                let result = cache.find_proxy(None, &format!("/users/{}", i));
                let rm = result.unwrap();
                assert_eq!(rm.proxy.id, "users");
                assert_eq!(rm.path_params[0].0, "id");
                assert_eq!(rm.path_params[0].1, i.to_string());
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[test]
fn test_regex_explicit_anchor() {
    // Users can provide their own ^ anchor — should work fine
    let config = test_config(vec![test_regex_proxy("anchored", r"^/users/[^/]+")]);
    let cache = RouterCache::new(&config, 100);

    let matched = cache.find_proxy(None, "/users/42");
    assert_eq!(matched.unwrap().proxy.id, "anchored");
}

#[test]
fn test_regex_exact_path_no_remaining() {
    // When the regex matches the entire path exactly
    let config = test_config(vec![test_regex_proxy("exact", r"/status")]);
    let cache = RouterCache::new(&config, 100);

    let rm = cache.find_proxy(None, "/status").unwrap();
    assert_eq!(rm.matched_prefix_len, "/status".len());

    let url = build_backend_url(&rm.proxy, "/status", "", rm.matched_prefix_len);
    assert_eq!(url, "http://regex-backend:3000/");
}
