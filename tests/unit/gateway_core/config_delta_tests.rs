//! Tests for config delta module

use chrono::{DateTime, Utc};
use ferrum_gateway::config::types::*;
use ferrum_gateway::config_delta::ConfigDelta;
use std::collections::HashMap;

fn make_proxy(id: &str, listen_path: &str, updated_at: DateTime<Utc>) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: None,
        hosts: vec![],
        listen_path: listen_path.to_string(),
        backend_protocol: BackendProtocol::Http,
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
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::default(),
        listen_port: None,
        frontend_tls: false,
        udp_idle_timeout_seconds: 60,
        created_at: updated_at,
        updated_at,
    }
}

fn make_consumer(id: &str, username: &str, updated_at: DateTime<Utc>) -> Consumer {
    Consumer {
        id: id.to_string(),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
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
    assert_eq!(delta.removed_proxy_ids, vec!["p1"]);
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
    assert_eq!(delta.modified_proxies[0].listen_path, "/api/v2");
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
    assert_eq!(delta.removed_consumer_ids, vec!["c2"]);
    assert_eq!(delta.modified_consumers.len(), 1);
    assert_eq!(delta.modified_consumers[0].id, "c1");
}

#[test]
fn test_affected_listen_paths() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(5);
    let old = GatewayConfig {
        proxies: vec![
            make_proxy("p1", "/api", t1),
            make_proxy("p2", "/old-path", t1),
        ],
        ..Default::default()
    };
    let new = GatewayConfig {
        proxies: vec![
            make_proxy("p2", "/new-path", t2), // modified, listen_path changed
            make_proxy("p3", "/added", t2),    // added
                                               // p1 removed
        ],
        ..Default::default()
    };
    let delta = ConfigDelta::compute(&old, &new);
    let paths = delta.affected_listen_paths(&old);
    assert!(paths.contains(&"/api".to_string())); // removed proxy's path
    assert!(paths.contains(&"/new-path".to_string())); // modified proxy's new path
    assert!(paths.contains(&"/old-path".to_string())); // modified proxy's old path
    assert!(paths.contains(&"/added".to_string())); // added proxy's path
}
