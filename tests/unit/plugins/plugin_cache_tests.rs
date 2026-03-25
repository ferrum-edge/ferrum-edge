//! Tests for PluginCache — pre-resolved plugin instances per proxy

use chrono::Utc;
use ferrum_gateway::PluginCache;
use ferrum_gateway::config::types::{
    AuthMode, BackendProtocol, GatewayConfig, PluginAssociation, PluginConfig, PluginScope, Proxy,
};
use serde_json::json;

fn make_proxy(id: &str, listen_path: &str, plugin_ids: Vec<&str>) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: Some(format!("Proxy {}", id)),
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
        let mut ctx = ferrum_gateway::plugins::RequestContext::new(
            "10.0.0.1".to_string(),
            "GET".to_string(),
            "/api/test".to_string(),
        );
        let result = rate_limiter.on_request_received(&mut ctx).await;

        if i < 2 {
            // First 2 should pass
            assert!(
                matches!(result, ferrum_gateway::plugins::PluginResult::Continue),
                "Request {} should have been allowed",
                i
            );
        } else {
            // 3rd should be rate limited
            assert!(
                matches!(
                    result,
                    ferrum_gateway::plugins::PluginResult::Reject {
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
