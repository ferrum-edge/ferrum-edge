//! Tests for PluginCache — pre-resolved plugin instances per proxy

use chrono::Utc;
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{
    AuthMode, BackendProtocol, GatewayConfig, PluginAssociation, PluginConfig, PluginScope, Proxy,
};
use ferrum_edge::plugins::ProxyProtocol;
use serde_json::json;

fn make_proxy(id: &str, listen_path: &str, plugin_ids: Vec<&str>) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: Some(format!("Proxy {}", id)),
        hosts: vec![],
        listen_path: listen_path.to_string(),
        backend_protocol: BackendProtocol::Http,
        backend_host: "localhost".to_string(),
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
        plugins: plugin_ids
            .into_iter()
            .map(|id| PluginAssociation {
                plugin_config_id: id.to_string(),
            })
            .collect(),

        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_plugin_config(
    id: &str,
    plugin_name: &str,
    scope: PluginScope,
    proxy_id: Option<&str>,
    enabled: bool,
) -> PluginConfig {
    // Some plugins now require non-empty config to be created successfully.
    let config = match plugin_name {
        "access_control" => json!({"allowed_ips": ["0.0.0.0/0"]}),
        "ip_restriction" => json!({"allow": ["0.0.0.0/0"]}),
        _ => json!({}),
    };
    PluginConfig {
        id: id.to_string(),
        plugin_name: plugin_name.to_string(),
        config,
        scope,
        proxy_id: proxy_id.map(|s| s.to_string()),
        enabled,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_config(proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs,
        upstreams: vec![],
        loaded_at: Utc::now(),
    }
}

// ---- Plugin caching correctness ----

#[test]
fn test_global_plugins_returned_for_all_proxies() {
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/web", vec![]),
        ],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let p1_plugins = cache.get_plugins("p1");
    let p2_plugins = cache.get_plugins("p2");

    assert_eq!(p1_plugins.len(), 1);
    assert_eq!(p1_plugins[0].name(), "stdout_logging");
    assert_eq!(p2_plugins.len(), 1);
    assert_eq!(p2_plugins[0].name(), "stdout_logging");
}

#[test]
fn test_proxy_scoped_plugins_override_globals_of_same_name() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config(
                "ps1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let plugins = cache.get_plugins("p1");
    // Should have 1 plugin (proxy-scoped replaces global of same name)
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "stdout_logging");
}

#[test]
fn test_disabled_plugins_excluded() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            false, // disabled
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let plugins = cache.get_plugins("p1");
    assert_eq!(plugins.len(), 0);
}

#[test]
fn test_rebuild_produces_updated_plugin_set() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    assert_eq!(cache.get_plugins("p1").len(), 1);
    assert_eq!(cache.get_plugins("p1")[0].name(), "stdout_logging");

    // Rebuild with different plugin
    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g2",
            "transaction_debugger",
            PluginScope::Global,
            None,
            true,
        )],
    );
    cache.rebuild(&config2).unwrap();

    assert_eq!(cache.get_plugins("p1").len(), 1);
    assert_eq!(cache.get_plugins("p1")[0].name(), "transaction_debugger");
}

#[test]
fn test_plugins_persist_across_get_calls() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "rate_limiting",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let call1 = cache.get_plugins("p1");
    let call2 = cache.get_plugins("p1");

    // Same Arc pointer — same plugin instance, not a copy
    assert!(std::sync::Arc::ptr_eq(&call1[0], &call2[0]));
}

#[test]
fn test_unknown_proxy_falls_back_to_globals() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    // "unknown" proxy not in config — should get global plugins
    let plugins = cache.get_plugins("unknown");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "stdout_logging");
}

#[test]
fn test_multiple_global_and_proxy_plugins() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config(
                "g2",
                "transaction_debugger",
                PluginScope::Global,
                None,
                true,
            ),
            make_plugin_config("ps1", "key_auth", PluginScope::Proxy, Some("p1"), true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let plugins = cache.get_plugins("p1");
    // 2 global + 1 proxy-scoped = 3
    assert_eq!(plugins.len(), 3);

    let names: Vec<&str> = plugins.iter().map(|p| p.name()).collect();
    assert!(names.contains(&"stdout_logging"));
    assert!(names.contains(&"transaction_debugger"));
    assert!(names.contains(&"key_auth"));
}

#[test]
fn test_proxy_count() {
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/web", vec![]),
            make_proxy("p3", "/admin", vec![]),
        ],
        vec![],
    );
    let cache = PluginCache::new(&config).unwrap();

    assert_eq!(cache.proxy_count(), 3);
}

// ---- Plugin priority ordering ----

#[test]
fn test_plugins_sorted_by_priority() {
    // Add plugins in reverse priority order — cache should sort them
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config("ps1", "key_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps2", "cors", PluginScope::Proxy, Some("p1"), true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 3);
    // CORS (100) < key_auth (1200) < stdout_logging (9000)
    assert_eq!(plugins[0].name(), "cors");
    assert_eq!(plugins[1].name(), "key_auth");
    assert_eq!(plugins[2].name(), "stdout_logging");
}

#[test]
fn test_full_plugin_priority_chain() {
    // All major plugin types — verify the complete ordering
    let config = make_config(
        vec![make_proxy(
            "p1",
            "/api",
            vec!["ps1", "ps2", "ps3", "ps4", "ps5", "ps6"],
        )],
        vec![
            // Global: logging
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            // Proxy-scoped: add in scrambled order
            make_plugin_config(
                "ps1",
                "access_control",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config(
                "ps2",
                "request_transformer",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config("ps3", "cors", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps4", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps5", "key_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "ps6",
                "response_transformer",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    let names: Vec<&str> = plugins.iter().map(|p| p.name()).collect();
    assert_eq!(
        names,
        vec![
            "cors",                 // 100  — Early
            "key_auth",             // 1200 — AuthN
            "access_control",       // 2000 — AuthZ
            "rate_limiting",        // 2900 — AuthZ (tail)
            "request_transformer",  // 3000 — Transform
            "response_transformer", // 4000 — Response
            "stdout_logging",       // 9000 — Logging
        ]
    );
}

#[test]
fn test_global_plugins_also_sorted() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config("g2", "cors", PluginScope::Global, None, true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    // Even for unknown proxy (global fallback), should be sorted
    let plugins = cache.get_plugins("unknown");
    assert_eq!(plugins.len(), 2);
    assert_eq!(plugins[0].name(), "cors"); // 100
    assert_eq!(plugins[1].name(), "stdout_logging"); // 9000
}

// ---- Rate limiting state persistence ----

#[tokio::test]
async fn test_rate_limiter_state_persists_across_calls() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![PluginConfig {
            id: "g1".to_string(),
            plugin_name: "rate_limiting".to_string(),
            config: json!({
                "window_seconds": 60,
                "max_requests": 2,
                "limit_by": "ip"
            }),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
    );
    let cache = PluginCache::new(&config).unwrap();

    let plugins = cache.get_plugins("p1");
    let rate_limiter = &plugins[0];
    assert_eq!(rate_limiter.name(), "rate_limiting");

    // Simulate 3 requests from the same IP
    for i in 0..3 {
        let mut ctx = ferrum_edge::plugins::RequestContext::new(
            "10.0.0.1".to_string(),
            "GET".to_string(),
            "/api/test".to_string(),
        );
        let result = rate_limiter.on_request_received(&mut ctx).await;

        if i < 2 {
            // First 2 should pass
            assert!(
                matches!(result, ferrum_edge::plugins::PluginResult::Continue),
                "Request {} should have been allowed",
                i
            );
        } else {
            // 3rd should be rate limited
            assert!(
                matches!(
                    result,
                    ferrum_edge::plugins::PluginResult::Reject {
                        status_code: 429,
                        ..
                    }
                ),
                "Request {} should have been rate limited",
                i
            );
        }
    }
}

// ---- Concurrency ----

#[tokio::test]
async fn test_concurrent_get_plugins() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = std::sync::Arc::new(PluginCache::new(&config).unwrap());

    let mut handles = vec![];
    for _ in 0..10 {
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            let plugins = cache.get_plugins("p1");
            assert_eq!(plugins.len(), 1);
            assert_eq!(plugins[0].name(), "stdout_logging");
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_rebuild_during_reads() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = std::sync::Arc::new(PluginCache::new(&config1).unwrap());

    // Snapshot before rebuild
    let pre_rebuild = cache.get_plugins("p1");
    assert_eq!(pre_rebuild[0].name(), "stdout_logging");

    // Rebuild with different plugin
    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g2",
            "transaction_debugger",
            PluginScope::Global,
            None,
            true,
        )],
    );
    cache.rebuild(&config2).unwrap();

    // Post-rebuild should see new plugin
    let post_rebuild = cache.get_plugins("p1");
    assert_eq!(post_rebuild[0].name(), "transaction_debugger");

    // Pre-rebuild snapshot still valid (Arc keeps it alive)
    assert_eq!(pre_rebuild[0].name(), "stdout_logging");
}

// ---- apply_delta security error propagation ----

#[test]
fn test_apply_delta_rejects_invalid_security_plugin() {
    // Start with a valid config
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1"])],
        vec![make_plugin_config(
            "pc1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    // Delta with an invalid security plugin (ip_restriction with empty config
    // fails validation because it requires at least one allow/deny rule)
    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1", "pc2"])],
        vec![
            make_plugin_config(
                "pc1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            PluginConfig {
                id: "pc2".to_string(),
                plugin_name: "ip_restriction".to_string(),
                config: json!({}), // empty — ip_restriction requires allow/deny
                scope: PluginScope::Proxy,
                proxy_id: Some("p1".to_string()),
                enabled: true,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ],
    );

    let mut proxy_ids = std::collections::HashSet::new();
    proxy_ids.insert("p1".to_string());

    let result = cache.apply_delta(&config2, &proxy_ids, &[], false);
    assert!(
        result.is_err(),
        "apply_delta should reject invalid security plugin config"
    );
}

#[test]
fn test_apply_delta_accepts_valid_config() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1"])],
        vec![make_plugin_config(
            "pc1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    // Delta adding a non-security plugin
    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1", "pc2"])],
        vec![
            make_plugin_config(
                "pc1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config("pc2", "cors", PluginScope::Proxy, Some("p1"), true),
        ],
    );

    let mut proxy_ids = std::collections::HashSet::new();
    proxy_ids.insert("p1".to_string());

    let result = cache.apply_delta(&config2, &proxy_ids, &[], false);
    assert!(result.is_ok(), "apply_delta should accept valid config");
}

// ---- Protocol-filtered plugin lookup tests ----

fn make_plugin_config_with_json(
    id: &str,
    plugin_name: &str,
    config: serde_json::Value,
    scope: PluginScope,
    proxy_id: Option<&str>,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        plugin_name: plugin_name.to_string(),
        config,
        scope,
        proxy_id: proxy_id.map(|s| s.to_string()),
        enabled: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_get_plugins_for_protocol_filters_by_protocol() {
    // ip_restriction = ALL_PROTOCOLS, cors = HTTP_ONLY
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config(
                "ps1",
                "ip_restriction",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config_with_json(
                "ps2",
                "cors",
                json!({"origins": ["*"]}),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    // HTTP — both present
    let http_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let http_names: Vec<&str> = http_plugins.iter().map(|p| p.name()).collect();
    assert!(http_names.contains(&"ip_restriction"));
    assert!(http_names.contains(&"cors"));
    assert_eq!(http_names.len(), 2);

    // TCP — only ip_restriction (cors is HTTP_ONLY)
    let tcp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let tcp_names: Vec<&str> = tcp_plugins.iter().map(|p| p.name()).collect();
    assert!(tcp_names.contains(&"ip_restriction"));
    assert!(!tcp_names.contains(&"cors"));
    assert_eq!(tcp_names.len(), 1);

    // UDP — only ip_restriction
    let udp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Udp);
    assert_eq!(udp_plugins.len(), 1);
    assert_eq!(udp_plugins[0].name(), "ip_restriction");

    // WebSocket — only ip_restriction (cors is HTTP_ONLY, not HTTP_FAMILY)
    let ws_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::WebSocket);
    assert_eq!(ws_plugins.len(), 1);
    assert_eq!(ws_plugins[0].name(), "ip_restriction");
}

#[test]
fn test_get_plugins_for_protocol_tcp_excludes_http_family() {
    // cors = HTTP_ONLY, key_auth = HTTP_FAMILY, rate_limiting = ALL, stdout_logging = ALL
    let config = make_config(
        vec![make_proxy(
            "p1",
            "/tcp-svc",
            vec!["ps1", "ps2", "ps3", "ps4"],
        )],
        vec![
            make_plugin_config_with_json(
                "ps1",
                "cors",
                json!({"origins": ["*"]}),
                PluginScope::Proxy,
                Some("p1"),
            ),
            make_plugin_config("ps2", "key_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps3", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "ps4",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let tcp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let tcp_names: Vec<&str> = tcp_plugins.iter().map(|p| p.name()).collect();
    assert!(tcp_names.contains(&"rate_limiting"));
    assert!(tcp_names.contains(&"stdout_logging"));
    assert!(
        !tcp_names.contains(&"cors"),
        "cors should be excluded for TCP"
    );
    assert!(
        !tcp_names.contains(&"key_auth"),
        "key_auth should be excluded for TCP"
    );
    assert_eq!(tcp_names.len(), 2);
}

#[test]
fn test_get_plugins_for_protocol_falls_back_to_globals() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    // Proxy with no associations — should get global stdout_logging for TCP
    let tcp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    assert_eq!(tcp_plugins.len(), 1);
    assert_eq!(tcp_plugins[0].name(), "stdout_logging");

    // Nonexistent proxy — falls back to global plugins
    let fallback = cache.get_plugins_for_protocol("nonexistent", ProxyProtocol::Http);
    assert_eq!(fallback.len(), 1);
    assert_eq!(fallback[0].name(), "stdout_logging");
}

#[test]
fn test_get_plugins_for_protocol_rebuild_updates_maps() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    let tcp_before = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    assert_eq!(tcp_before.len(), 1);

    // Rebuild with an additional plugin
    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config("ps1", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "ps2",
                "ip_restriction",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    cache.rebuild(&config2).unwrap();

    let tcp_after = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let names: Vec<&str> = tcp_after.iter().map(|p| p.name()).collect();
    assert!(names.contains(&"rate_limiting"));
    assert!(names.contains(&"ip_restriction"));
    assert_eq!(names.len(), 2);
}

#[test]
fn test_get_plugins_for_protocol_websocket_includes_auth_excludes_cors() {
    let config = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1", "ps2", "ps3"])],
        vec![
            make_plugin_config("ps1", "key_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps2", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config_with_json(
                "ps3",
                "cors",
                json!({"origins": ["*"]}),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let ws_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::WebSocket);
    let names: Vec<&str> = ws_plugins.iter().map(|p| p.name()).collect();
    assert!(names.contains(&"key_auth"), "WebSocket should include auth");
    assert!(
        names.contains(&"rate_limiting"),
        "WebSocket should include rate_limiting"
    );
    assert!(!names.contains(&"cors"), "WebSocket should exclude CORS");
    assert_eq!(names.len(), 2);
}

#[test]
fn test_get_plugins_for_protocol_grpc_excludes_http_only() {
    let config = make_config(
        vec![make_proxy("p1", "/grpc", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config_with_json(
                "ps1",
                "response_caching",
                json!({"ttl_seconds": 60}),
                PluginScope::Proxy,
                Some("p1"),
            ),
            make_plugin_config("ps2", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let grpc_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Grpc);
    let names: Vec<&str> = grpc_plugins.iter().map(|p| p.name()).collect();
    assert!(names.contains(&"rate_limiting"));
    assert!(
        !names.contains(&"response_caching"),
        "gRPC should exclude response_caching (HTTP_ONLY)"
    );
    assert_eq!(names.len(), 1);
}

// ---- WebSocket per-frame plugin hook infrastructure ----

#[tokio::test]
async fn test_requires_ws_frame_hooks_defaults_false_for_all_plugins() {
    use ferrum_edge::plugins::available_plugins;
    use ferrum_edge::plugins::create_plugin;

    // Every non-WS-frame built-in plugin must return false for requires_ws_frame_hooks().
    // This is the zero-overhead guarantee — only explicit WS frame plugins opt in.
    const WS_FRAME_PLUGINS: &[&str] = &[
        "ws_message_size_limiting",
        "ws_frame_logging",
        "ws_rate_limiting",
    ];

    for name in available_plugins() {
        if WS_FRAME_PLUGINS.contains(&name) {
            continue; // These intentionally return true
        }
        let config = match name {
            "access_control" => serde_json::json!({"allowed_ips": ["0.0.0.0/0"]}),
            "ip_restriction" => serde_json::json!({"allow": ["0.0.0.0/0"]}),
            "cors" => serde_json::json!({"origins": ["*"]}),
            "response_caching" => serde_json::json!({"ttl_seconds": 60}),
            "http_logging" => serde_json::json!({"endpoint": "http://localhost:9999/log"}),
            "jwks_auth" => {
                serde_json::json!({"providers": [{"issuer": "https://example.com", "jwks_uri": "https://example.com/.well-known/jwks.json"}]})
            }
            "otel_tracing" => serde_json::json!({"endpoint": "http://localhost:4317"}),
            _ => serde_json::json!({}),
        };
        if let Ok(Some(plugin)) = create_plugin(name, &config) {
            assert!(
                !plugin.requires_ws_frame_hooks(),
                "Plugin '{}' should default requires_ws_frame_hooks() to false",
                name
            );
        }
    }
}

#[tokio::test]
async fn test_on_ws_frame_default_returns_none() {
    use ferrum_edge::plugins::{WebSocketFrameDirection, create_plugin};
    use tokio_tungstenite::tungstenite::Message;

    // The default on_ws_frame() implementation must return None (passthrough).
    let plugin = create_plugin("stdout_logging", &serde_json::json!({}))
        .unwrap()
        .unwrap();

    let msg = Message::Text("hello".to_string().into());
    let result = plugin
        .on_ws_frame("proxy-1", 1, WebSocketFrameDirection::ClientToBackend, &msg)
        .await;
    assert!(
        result.is_none(),
        "Default on_ws_frame() must return None (passthrough)"
    );

    let result = plugin
        .on_ws_frame("proxy-1", 1, WebSocketFrameDirection::BackendToClient, &msg)
        .await;
    assert!(
        result.is_none(),
        "Default on_ws_frame() must return None (passthrough) for BackendToClient"
    );
}

#[test]
fn test_plugin_cache_requires_ws_frame_hooks_false_when_no_plugins_opt_in() {
    // When no plugins opt in, requires_ws_frame_hooks() must return false for any proxy.
    let config = make_config(
        vec![
            make_proxy("p1", "/ws", vec!["ps1"]),
            make_proxy("p2", "/api", vec![]),
        ],
        vec![
            make_plugin_config("ps1", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    // Known proxy — no plugin opts in
    assert!(
        !cache.requires_ws_frame_hooks("p1"),
        "requires_ws_frame_hooks should be false when no plugin opts in"
    );
    // Another proxy — no plugin opts in
    assert!(
        !cache.requires_ws_frame_hooks("p2"),
        "requires_ws_frame_hooks should be false for proxy with no plugins"
    );
    // Unknown proxy — falls back to global, still false
    assert!(
        !cache.requires_ws_frame_hooks("unknown"),
        "requires_ws_frame_hooks should be false for unknown proxy (global fallback)"
    );
}

#[test]
fn test_plugin_cache_requires_ws_frame_hooks_rebuild_updates_flag() {
    let config1 = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();
    assert!(!cache.requires_ws_frame_hooks("p1"));

    // Rebuild with different config — flag should still be false (no plugin opts in)
    let config2 = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    cache.rebuild(&config2).unwrap();
    assert!(!cache.requires_ws_frame_hooks("p1"));
}

#[test]
fn test_plugin_cache_requires_ws_frame_hooks_apply_delta_preserves_false() {
    let config = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    assert!(!cache.requires_ws_frame_hooks("p1"));

    // Delta adding a non-ws-frame plugin
    let config2 = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config("ps1", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps2", "key_auth", PluginScope::Proxy, Some("p1"), true),
        ],
    );
    let mut proxy_ids = std::collections::HashSet::new();
    proxy_ids.insert("p1".to_string());
    cache.apply_delta(&config2, &proxy_ids, &[], false).unwrap();

    // Still false — neither rate_limiting nor key_auth opt into ws_frame hooks
    assert!(
        !cache.requires_ws_frame_hooks("p1"),
        "requires_ws_frame_hooks should remain false after delta with non-frame plugins"
    );
}

#[test]
fn test_ws_frame_direction_debug_and_equality() {
    use ferrum_edge::plugins::WebSocketFrameDirection;

    let ctb = WebSocketFrameDirection::ClientToBackend;
    let btc = WebSocketFrameDirection::BackendToClient;

    assert_eq!(ctb, WebSocketFrameDirection::ClientToBackend);
    assert_eq!(btc, WebSocketFrameDirection::BackendToClient);
    assert_ne!(ctb, btc);

    // Debug formatting should not panic
    let _ = format!("{:?}", ctb);
    let _ = format!("{:?}", btc);
}

#[test]
fn test_plugin_cache_requires_ws_frame_hooks_true_with_ws_size_plugin() {
    // When a WS frame plugin is assigned to a proxy, requires_ws_frame_hooks must be TRUE.
    let config = make_config(
        vec![make_proxy("p1", "/ws", vec!["ws1"])],
        vec![make_plugin_config(
            "ws1",
            "ws_message_size_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    assert!(
        cache.requires_ws_frame_hooks("p1"),
        "requires_ws_frame_hooks must be TRUE when ws_message_size_limiting is attached"
    );
}

#[test]
fn test_plugin_cache_requires_ws_frame_hooks_true_with_ws_rate_plugin() {
    let config = make_config(
        vec![make_proxy("p1", "/ws", vec!["ws1"])],
        vec![make_plugin_config(
            "ws1",
            "ws_rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    assert!(
        cache.requires_ws_frame_hooks("p1"),
        "requires_ws_frame_hooks must be TRUE when ws_rate_limiting is attached"
    );
}

#[test]
fn test_plugin_cache_requires_ws_frame_hooks_true_with_ws_logging_plugin() {
    let config = make_config(
        vec![make_proxy("p1", "/ws", vec!["ws1"])],
        vec![make_plugin_config(
            "ws1",
            "ws_frame_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    assert!(
        cache.requires_ws_frame_hooks("p1"),
        "requires_ws_frame_hooks must be TRUE when ws_frame_logging is attached"
    );
}

#[test]
fn test_plugin_cache_ws_plugins_filtered_to_websocket_protocol_only() {
    // WS-only plugins should NOT appear in the HTTP plugin list for a proxy.
    let config = make_config(
        vec![make_proxy("p1", "/ws", vec!["ws1", "http1"])],
        vec![
            make_plugin_config(
                "ws1",
                "ws_message_size_limiting",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config(
                "http1",
                "rate_limiting",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    // HTTP protocol should only include rate_limiting, not ws_message_size_limiting
    let http_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    assert_eq!(
        http_plugins.len(),
        1,
        "HTTP should have only rate_limiting, not WS plugins"
    );
    assert_eq!(http_plugins[0].name(), "rate_limiting");

    // WebSocket protocol should include both
    let ws_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::WebSocket);
    let ws_names: Vec<&str> = ws_plugins.iter().map(|p| p.name()).collect();
    assert!(
        ws_names.contains(&"ws_message_size_limiting"),
        "WebSocket protocol should include ws_message_size_limiting"
    );
    assert!(
        ws_names.contains(&"rate_limiting"),
        "WebSocket protocol should include rate_limiting (ALL_PROTOCOLS)"
    );
}

#[test]
fn test_plugin_cache_rebuild_adds_ws_frame_hooks_flag() {
    // Start with no WS plugins → flag is false
    let config1 = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();
    assert!(!cache.requires_ws_frame_hooks("p1"));

    // Rebuild with WS plugin → flag must become true
    let config2 = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1", "ws1"])],
        vec![
            make_plugin_config("ps1", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "ws1",
                "ws_frame_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    cache.rebuild(&config2).unwrap();
    assert!(
        cache.requires_ws_frame_hooks("p1"),
        "requires_ws_frame_hooks must be TRUE after rebuild adds ws_frame_logging"
    );
}
