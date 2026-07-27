//! Tests for config delta module

use chrono::{DateTime, Utc};
use ferrum_edge::config::db_backend::NamespacedResourceId;
use ferrum_edge::config::types::*;
use ferrum_edge::config_delta::ConfigDelta;
use std::collections::HashMap;

fn make_proxy(id: &str, listen_path: &str, updated_at: DateTime<Utc>) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".to_string(),
        backend_port: 8080,
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
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],

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
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        created_at: updated_at,
        updated_at,
    }
}

fn make_upstream(id: &str, targets: Vec<UpstreamTarget>, updated_at: DateTime<Utc>) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: default_namespace(),
        name: None,
        targets,
        algorithm: LoadBalancerAlgorithm::default(),
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: updated_at,
        updated_at,
    }
}

fn make_target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 100,
        tags: HashMap::new(),
        locality: None,
        path: None,
    }
}

fn make_plugin_config(
    id: &str,
    name: &str,
    scope: PluginScope,
    proxy_id: Option<&str>,
    updated_at: DateTime<Utc>,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: default_namespace(),
        plugin_name: name.to_string(),
        config: serde_json::Value::Object(serde_json::Map::new()),
        scope,
        proxy_id: proxy_id.map(|s| s.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: updated_at,
        updated_at,
    }
}

fn make_consumer(id: &str, username: &str, updated_at: DateTime<Utc>) -> Consumer {
    Consumer {
        id: id.to_string(),
        namespace: default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: updated_at,
        updated_at,
    }
}

#[test]
fn test_empty_delta_when_configs_identical() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![make_proxy("p1", "/api", Utc::now())],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&config, &config);
    assert!(delta.is_empty());
}

#[test]
fn test_detects_added_proxy() {
    let t = Utc::now();
    let old = GatewayConfig::default();
    let new = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", t)],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    assert_eq!(delta.added_proxies.len(), 1);
    assert_eq!(delta.added_proxies[0].id, "p1");
    assert!(delta.removed_proxy_ids.is_empty());
    assert!(delta.modified_proxies.is_empty());
}

#[test]
fn test_detects_removed_proxy() {
    let t = Utc::now();
    let old = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", t)],
        ..Default::default()
    };
    let new = GatewayConfig::default();
    let delta = ConfigDelta::compute(&old, &new);
    assert!(delta.added_proxies.is_empty());
    assert_eq!(
        delta.removed_proxy_ids,
        vec![NamespacedResourceId::new(default_namespace(), "p1")]
    );
    assert!(delta.modified_proxies.is_empty());
}

#[test]
fn test_detects_modified_proxy() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(10);
    let old = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", t1)],
        ..Default::default()
    };
    let new = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api/v2", t2)],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    assert!(delta.added_proxies.is_empty());
    assert!(delta.removed_proxy_ids.is_empty());
    assert_eq!(delta.modified_proxies.len(), 1);
    assert_eq!(
        delta.modified_proxies[0].listen_path.as_deref(),
        Some("/api/v2")
    );
}

#[test]
fn test_unchanged_proxy_not_in_delta() {
    let t = Utc::now();
    let config = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", t)],
        ..Default::default()
    };
    // Same id, same updated_at
    let delta = ConfigDelta::compute(&config, &config);
    assert!(delta.modified_proxies.is_empty());
}

#[test]
fn test_detects_consumer_changes() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(5);
    let old = GatewayConfig {
        consumers: vec![
            make_consumer("c1", "alice", t1),
            make_consumer("c2", "bob", t1),
        ],
        ..Default::default()
    };
    let new = GatewayConfig {
        consumers: vec![
            make_consumer("c1", "alice_updated", t2), // modified
            make_consumer("c3", "charlie", t2),       // added
                                                      // c2 removed
        ],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    assert_eq!(delta.added_consumers.len(), 1);
    assert_eq!(delta.added_consumers[0].id, "c3");
    assert_eq!(
        delta.removed_consumer_ids,
        vec![NamespacedResourceId::new(default_namespace(), "c2")],
    );
    assert_eq!(delta.modified_consumers.len(), 1);
    assert_eq!(delta.modified_consumers[0].id, "c1");
}

// --- Upstream delta tests ---

#[test]
fn test_detects_added_upstream() {
    let t = Utc::now();
    let old = GatewayConfig::default();
    let new = GatewayConfig {
        upstreams: vec![make_upstream("u1", vec![make_target("backend1", 8080)], t)],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    assert_eq!(delta.added_upstreams.len(), 1);
    assert_eq!(delta.added_upstreams[0].id, "u1");
    assert!(delta.removed_upstream_ids.is_empty());
    assert!(delta.modified_upstreams.is_empty());
}

#[test]
fn test_detects_removed_upstream() {
    let t = Utc::now();
    let old = GatewayConfig {
        upstreams: vec![make_upstream("u1", vec![make_target("backend1", 8080)], t)],
        ..Default::default()
    };
    let new = GatewayConfig::default();
    let delta = ConfigDelta::compute(&old, &new);
    assert!(delta.added_upstreams.is_empty());
    assert_eq!(
        delta.removed_upstream_ids,
        vec![NamespacedResourceId::new(default_namespace(), "u1")],
    );
    assert!(delta.modified_upstreams.is_empty());
}

#[test]
fn test_detects_modified_upstream() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(10);
    let old = GatewayConfig {
        upstreams: vec![make_upstream("u1", vec![make_target("backend1", 8080)], t1)],
        ..Default::default()
    };
    let new = GatewayConfig {
        upstreams: vec![make_upstream("u1", vec![make_target("backend2", 9090)], t2)],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    assert!(delta.added_upstreams.is_empty());
    assert!(delta.removed_upstream_ids.is_empty());
    assert_eq!(delta.modified_upstreams.len(), 1);
    assert_eq!(delta.modified_upstreams[0].targets[0].host, "backend2");
}

#[test]
fn test_unchanged_upstream_not_in_delta() {
    let t = Utc::now();
    let config = GatewayConfig {
        upstreams: vec![make_upstream("u1", vec![make_target("backend1", 8080)], t)],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&config, &config);
    assert!(delta.added_upstreams.is_empty());
    assert!(delta.removed_upstream_ids.is_empty());
    assert!(delta.modified_upstreams.is_empty());
}

#[test]
fn test_upstream_mixed_add_remove_modify() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(5);
    let old = GatewayConfig {
        upstreams: vec![
            make_upstream("u1", vec![make_target("a", 80)], t1),
            make_upstream("u2", vec![make_target("b", 80)], t1),
        ],
        ..Default::default()
    };
    let new = GatewayConfig {
        upstreams: vec![
            make_upstream("u1", vec![make_target("a-new", 8080)], t2), // modified
            make_upstream("u3", vec![make_target("c", 80)], t2),       // added
                                                                       // u2 removed
        ],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    assert_eq!(delta.added_upstreams.len(), 1);
    assert_eq!(delta.added_upstreams[0].id, "u3");
    assert_eq!(
        delta.removed_upstream_ids,
        vec![NamespacedResourceId::new(default_namespace(), "u2")],
    );
    assert_eq!(delta.modified_upstreams.len(), 1);
    assert_eq!(delta.modified_upstreams[0].id, "u1");
}

// --- PluginConfig delta tests ---

#[test]
fn test_detects_added_plugin_config() {
    let t = Utc::now();
    let old = GatewayConfig::default();
    let new = GatewayConfig {
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Global,
            None,
            t,
        )],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    assert_eq!(delta.added_plugin_configs.len(), 1);
    assert_eq!(delta.added_plugin_configs[0].id, "pc1");
    assert!(delta.removed_plugin_config_ids.is_empty());
    assert!(delta.modified_plugin_configs.is_empty());
    assert!(delta.global_plugin_configs_changed);
}

#[test]
fn test_detects_removed_plugin_config() {
    let t = Utc::now();
    let old = GatewayConfig {
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Global,
            None,
            t,
        )],
        ..Default::default()
    };
    let new = GatewayConfig::default();
    let delta = ConfigDelta::compute(&old, &new);
    assert!(delta.added_plugin_configs.is_empty());
    assert_eq!(
        delta.removed_plugin_config_ids,
        vec![NamespacedResourceId::new(default_namespace(), "pc1")],
    );
    assert!(delta.modified_plugin_configs.is_empty());
    assert!(delta.global_plugin_configs_changed);
}

#[test]
fn test_detects_modified_plugin_config() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(5);
    let old = GatewayConfig {
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Global,
            None,
            t1,
        )],
        ..Default::default()
    };
    let new = GatewayConfig {
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Global,
            None,
            t2,
        )],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    assert!(delta.added_plugin_configs.is_empty());
    assert!(delta.removed_plugin_config_ids.is_empty());
    assert_eq!(delta.modified_plugin_configs.len(), 1);
    assert_eq!(delta.modified_plugin_configs[0].id, "pc1");
    assert!(delta.global_plugin_configs_changed);
}

// --- proxy_ids_needing_plugin_rebuild tests ---

#[test]
fn test_proxy_ids_needing_plugin_rebuild_from_proxy_change() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(5);
    let old = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", t1)],
        ..Default::default()
    };
    let new = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api/v2", t2)],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    let ids = delta.proxy_ids_needing_plugin_rebuild(&old, &new);
    assert!(ids.contains(&NamespacedResourceId::new(default_namespace(), "p1")));
}

#[test]
fn test_proxy_ids_needing_plugin_rebuild_from_global_plugin_change() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(5);
    let proxy = make_proxy("p1", "/api", t1);
    let old = GatewayConfig {
        proxies: vec![proxy.clone()],
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Global,
            None,
            t1,
        )],
        ..Default::default()
    };
    let new = GatewayConfig {
        proxies: vec![proxy],
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Global,
            None,
            t2,
        )],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    let ids = delta.proxy_ids_needing_plugin_rebuild(&old, &new);
    // Global plugin change should trigger rebuild for ALL proxies
    assert!(ids.contains(&NamespacedResourceId::new(default_namespace(), "p1")));
}

#[test]
fn test_proxy_ids_needing_plugin_rebuild_when_global_plugin_changes_scope() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(5);
    let proxy1 = make_proxy("p1", "/api", t1);
    let proxy2 = make_proxy("p2", "/other", t1);
    let old = GatewayConfig {
        proxies: vec![proxy1.clone(), proxy2.clone()],
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Global,
            None,
            t1,
        )],
        ..Default::default()
    };
    let new = GatewayConfig {
        proxies: vec![proxy1, proxy2],
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            t2,
        )],
        ..Default::default()
    };

    let delta = ConfigDelta::compute(&old, &new);
    let ids = delta.proxy_ids_needing_plugin_rebuild(&old, &new);

    assert!(delta.global_plugin_configs_changed);
    assert!(ids.contains(&NamespacedResourceId::new(default_namespace(), "p1")));
    assert!(
        ids.contains(&NamespacedResourceId::new(default_namespace(), "p2")),
        "a plugin moving away from global scope must rebuild proxies that only saw it via globals"
    );
}

#[test]
fn test_proxy_ids_needing_plugin_rebuild_from_removed_proxy_plugin_config() {
    let t = Utc::now();
    let proxy1 = make_proxy("p1", "/api", t);
    let proxy2 = make_proxy("p2", "/other", t);
    let old = GatewayConfig {
        proxies: vec![proxy1.clone(), proxy2.clone()],
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            t,
        )],
        ..Default::default()
    };
    let new = GatewayConfig {
        proxies: vec![proxy1, proxy2],
        plugin_configs: vec![],
        ..Default::default()
    };

    let delta = ConfigDelta::compute(&old, &new);
    let ids = delta.proxy_ids_needing_plugin_rebuild(&old, &new);

    assert!(!delta.global_plugin_configs_changed);
    assert!(ids.contains(&NamespacedResourceId::new(default_namespace(), "p1")));
    assert!(
        ids.contains(&NamespacedResourceId::new(default_namespace(), "p2")),
        "plugin config deletion conservatively rebuilds all proxies because associations may cascade without proxy timestamps"
    );
}

// --- Full mixed delta across all entity types ---

#[test]
fn test_full_mixed_delta_all_entity_types() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(5);
    let old = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", t1)],
        consumers: vec![make_consumer("c1", "alice", t1)],
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "key_auth",
            PluginScope::Global,
            None,
            t1,
        )],
        upstreams: vec![make_upstream("u1", vec![make_target("host", 80)], t1)],
        ..Default::default()
    };
    let new = GatewayConfig {
        proxies: vec![make_proxy("p2", "/new", t2)], // p1 removed, p2 added
        consumers: vec![make_consumer("c1", "bob", t2)], // c1 modified
        plugin_configs: vec![],                      // pc1 removed
        upstreams: vec![
            make_upstream("u1", vec![make_target("host2", 8080)], t2), // u1 modified
            make_upstream("u2", vec![make_target("host3", 80)], t2),   // u2 added
        ],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);

    assert_eq!(delta.added_proxies.len(), 1);
    assert_eq!(
        delta.removed_proxy_ids,
        vec![NamespacedResourceId::new(default_namespace(), "p1")]
    );
    assert!(delta.added_consumers.is_empty());
    assert_eq!(delta.modified_consumers.len(), 1);
    assert_eq!(
        delta.removed_plugin_config_ids,
        vec![NamespacedResourceId::new(default_namespace(), "pc1")],
    );
    assert_eq!(delta.added_upstreams.len(), 1);
    assert_eq!(delta.modified_upstreams.len(), 1);
    assert!(!delta.is_empty());
}

// --- AffectedRoutes::is_empty tests ---

#[test]
fn test_affected_routes_is_empty_default() {
    use ferrum_edge::config_delta::AffectedRoutes;
    let routes = AffectedRoutes::default();
    assert!(routes.is_empty());
}

#[test]
fn test_affected_routes_not_empty_with_listen_paths() {
    use ferrum_edge::config_delta::AffectedRoutes;
    let routes = AffectedRoutes {
        listen_paths: vec!["/api".to_string()],
        host_only_hosts: vec![],
    };
    assert!(!routes.is_empty());
}

#[test]
fn test_affected_routes_not_empty_with_hosts() {
    use ferrum_edge::config_delta::AffectedRoutes;
    let routes = AffectedRoutes {
        listen_paths: vec![],
        host_only_hosts: vec!["example.com".to_string()],
    };
    assert!(!routes.is_empty());
}

// --- Host-only proxy routing tests ---

#[test]
fn test_affected_routes_host_only_proxy_added() {
    let t = Utc::now();
    let mut host_proxy = make_proxy("h1", "/unused", t);
    host_proxy.listen_path = None;
    host_proxy.hosts = vec![
        "api.example.com".to_string(),
        "api2.example.com".to_string(),
    ];

    let old = GatewayConfig::default();
    let new = GatewayConfig {
        proxies: vec![host_proxy],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    let affected = delta.affected_routes(&old);
    assert!(affected.listen_paths.is_empty());
    assert!(
        affected
            .host_only_hosts
            .contains(&"api.example.com".to_string())
    );
    assert!(
        affected
            .host_only_hosts
            .contains(&"api2.example.com".to_string())
    );
}

#[test]
fn test_affected_routes_host_only_proxy_removed() {
    let t = Utc::now();
    let mut host_proxy = make_proxy("h1", "/unused", t);
    host_proxy.listen_path = None;
    host_proxy.hosts = vec!["removed.example.com".to_string()];

    let old = GatewayConfig {
        proxies: vec![host_proxy],
        ..Default::default()
    };
    let new = GatewayConfig::default();
    let delta = ConfigDelta::compute(&old, &new);
    let affected = delta.affected_routes(&old);
    assert!(affected.listen_paths.is_empty());
    assert!(
        affected
            .host_only_hosts
            .contains(&"removed.example.com".to_string())
    );
}

#[test]
fn test_affected_routes_host_only_proxy_modified() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(5);

    let mut old_proxy = make_proxy("h1", "/unused", t1);
    old_proxy.listen_path = None;
    old_proxy.hosts = vec!["old.example.com".to_string()];

    let mut new_proxy = make_proxy("h1", "/unused", t2);
    new_proxy.listen_path = None;
    new_proxy.hosts = vec!["new.example.com".to_string()];

    let old = GatewayConfig {
        proxies: vec![old_proxy],
        ..Default::default()
    };
    let new = GatewayConfig {
        proxies: vec![new_proxy],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    let affected = delta.affected_routes(&old);
    assert!(affected.listen_paths.is_empty());
    // Both old and new hosts should be recorded
    assert!(
        affected
            .host_only_hosts
            .contains(&"new.example.com".to_string())
    );
    assert!(
        affected
            .host_only_hosts
            .contains(&"old.example.com".to_string())
    );
}

// --- Stream proxy skipping ---

#[test]
fn test_affected_routes_skips_stream_proxies() {
    let t = Utc::now();
    let mut stream_proxy = make_proxy("tcp1", "/unused", t);
    stream_proxy.listen_path = None;
    stream_proxy.dispatch_kind = DispatchKind::TcpRaw;
    stream_proxy.listen_port = Some(9999);

    let old = GatewayConfig::default();
    let new = GatewayConfig {
        proxies: vec![stream_proxy],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    let affected = delta.affected_routes(&old);
    assert!(affected.is_empty());
}

#[test]
fn test_affected_routes_mixed_http_and_stream() {
    let t = Utc::now();
    let http_proxy = make_proxy("http1", "/api", t);

    let mut stream_proxy = make_proxy("tcp1", "/unused", t);
    stream_proxy.listen_path = None;
    stream_proxy.dispatch_kind = DispatchKind::TcpRaw;
    stream_proxy.listen_port = Some(9999);

    let old = GatewayConfig::default();
    let new = GatewayConfig {
        proxies: vec![http_proxy, stream_proxy],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    let affected = delta.affected_routes(&old);
    // Only the HTTP proxy path should appear
    assert_eq!(affected.listen_paths.len(), 1);
    assert!(affected.listen_paths.contains(&"/api".to_string()));
    assert!(affected.host_only_hosts.is_empty());
}

// --- Proxy-scoped plugin rebuild ---

#[test]
fn test_plugin_rebuild_proxy_scoped_plugin_change() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(5);

    let proxy = make_proxy("p1", "/api", t1);
    let old = GatewayConfig {
        proxies: vec![proxy.clone()],
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            t1,
        )],
        ..Default::default()
    };
    let new = GatewayConfig {
        proxies: vec![proxy],
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            t2,
        )],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    let ids = delta.proxy_ids_needing_plugin_rebuild(&old, &new);
    assert!(ids.contains(&NamespacedResourceId::new(default_namespace(), "p1")));
}

#[test]
fn test_plugin_rebuild_unrelated_proxy_not_affected() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(5);

    let proxy1 = make_proxy("p1", "/api", t1);
    let proxy2 = make_proxy("p2", "/other", t1);
    let old = GatewayConfig {
        proxies: vec![proxy1.clone(), proxy2.clone()],
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            t1,
        )],
        ..Default::default()
    };
    let new = GatewayConfig {
        proxies: vec![proxy1, proxy2],
        plugin_configs: vec![make_plugin_config(
            "pc1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            t2,
        )],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    let ids = delta.proxy_ids_needing_plugin_rebuild(&old, &new);
    assert!(ids.contains(&NamespacedResourceId::new(default_namespace(), "p1")));
    // p2 should NOT need rebuild since its plugin didn't change
    assert!(!ids.contains(&NamespacedResourceId::new(default_namespace(), "p2")));
}

// --- Same timestamp not treated as modification ---

#[test]
fn test_same_timestamp_is_not_modification() {
    let t = Utc::now();
    let old = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", t)],
        ..Default::default()
    };
    let new = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api/v2", t)], // different path, same timestamp
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    // Same updated_at = no modification detected (by design)
    assert!(delta.modified_proxies.is_empty());
}

// --- Both configs empty ---

#[test]
fn test_both_configs_empty() {
    let delta = ConfigDelta::compute(&GatewayConfig::default(), &GatewayConfig::default());
    assert!(delta.is_empty());
}
