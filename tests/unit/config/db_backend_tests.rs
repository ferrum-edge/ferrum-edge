use chrono::Utc;
use ferrum_edge::config::db_backend::{
    IncrementalResult, extract_db_hostname, extract_known_ids, redact_url,
};
use ferrum_edge::config::types::GatewayConfig;

// ---------------------------------------------------------------------------
// extract_db_hostname — tests for MongoDB URLs
// ---------------------------------------------------------------------------

#[test]
fn extract_hostname_mongodb_url() {
    let url = "mongodb://user:pass@mongo.example.com:27017/ferrum";
    assert_eq!(
        extract_db_hostname(url),
        Some("mongo.example.com".to_string())
    );
}

#[test]
fn extract_hostname_mongodb_srv_url() {
    let url = "mongodb+srv://user:pass@cluster0.abc123.mongodb.net/ferrum";
    assert_eq!(
        extract_db_hostname(url),
        Some("cluster0.abc123.mongodb.net".to_string())
    );
}

#[test]
fn extract_hostname_mongodb_ip_literal() {
    let url = "mongodb://user:pass@192.168.1.100:27017/ferrum";
    assert_eq!(extract_db_hostname(url), None);
}

#[test]
fn extract_hostname_mongodb_localhost() {
    let url = "mongodb://localhost:27017/ferrum";
    assert_eq!(extract_db_hostname(url), Some("localhost".to_string()));
}

#[test]
fn extract_hostname_mongodb_with_options() {
    let url = "mongodb://user:pass@mongo.internal:27017/ferrum?authSource=admin&tls=true";
    assert_eq!(extract_db_hostname(url), Some("mongo.internal".to_string()));
}

// ---------------------------------------------------------------------------
// redact_url — tests for MongoDB URLs
// ---------------------------------------------------------------------------

#[test]
fn redact_mongodb_url_hides_credentials() {
    let url = "mongodb://myuser:supersecret@mongo.example.com:27017/ferrum?authSource=admin";
    let redacted = redact_url(url);
    assert!(!redacted.contains("supersecret"));
    assert!(!redacted.contains("myuser"));
    assert!(redacted.contains("mongo.example.com"));
    assert!(redacted.contains("27017"));
}

#[test]
fn redact_mongodb_srv_url() {
    let url = "mongodb+srv://user:pass@cluster0.abc123.mongodb.net/ferrum";
    let redacted = redact_url(url);
    assert!(!redacted.contains("pass"));
    assert!(redacted.contains("cluster0.abc123.mongodb.net"));
}

// ---------------------------------------------------------------------------
// extract_known_ids — tests
// ---------------------------------------------------------------------------

#[test]
fn extract_known_ids_empty_config() {
    let config = GatewayConfig::default();
    let (proxy_ids, consumer_ids, plugin_config_ids, upstream_ids) = extract_known_ids(&config);
    assert!(proxy_ids.is_empty());
    assert!(consumer_ids.is_empty());
    assert!(plugin_config_ids.is_empty());
    assert!(upstream_ids.is_empty());
}

#[test]
fn extract_known_ids_with_data() {
    // Use serde to construct test objects without needing Default
    let mut config = GatewayConfig::default();
    let proxy1: ferrum_edge::config::types::Proxy = serde_json::from_value(serde_json::json!({
        "id": "proxy-1",
        "name": "test-1",
        "listen_path": "/test1",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": 8080
    }))
    .unwrap();
    let proxy2: ferrum_edge::config::types::Proxy = serde_json::from_value(serde_json::json!({
        "id": "proxy-2",
        "name": "test-2",
        "listen_path": "/test2",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": 8081
    }))
    .unwrap();
    let consumer: ferrum_edge::config::types::Consumer =
        serde_json::from_value(serde_json::json!({
            "id": "consumer-1",
            "username": "test-user",
            "credentials": {}
        }))
        .unwrap();

    config.proxies.push(proxy1);
    config.proxies.push(proxy2);
    config.consumers.push(consumer);

    let (proxy_ids, consumer_ids, plugin_config_ids, upstream_ids) = extract_known_ids(&config);
    assert_eq!(proxy_ids.len(), 2);
    assert!(proxy_ids.contains("proxy-1"));
    assert!(proxy_ids.contains("proxy-2"));
    assert_eq!(consumer_ids.len(), 1);
    assert!(consumer_ids.contains("consumer-1"));
    assert!(plugin_config_ids.is_empty());
    assert!(upstream_ids.is_empty());
}

// ---------------------------------------------------------------------------
// extract_db_hostname — existing SQL URL patterns still work
// ---------------------------------------------------------------------------

#[test]
fn extract_hostname_postgres_url_via_free_fn() {
    let url = "postgres://user:pass@db.example.com:5432/ferrum";
    assert_eq!(extract_db_hostname(url), Some("db.example.com".to_string()));
}

#[test]
fn extract_hostname_sqlite_returns_none_via_free_fn() {
    assert_eq!(extract_db_hostname("sqlite://ferrum.db"), None);
}

// ---------------------------------------------------------------------------
// IncrementalResult::is_empty — incremental polling empty detection
// ---------------------------------------------------------------------------

#[test]
fn incremental_result_is_empty_when_default() {
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        poll_timestamp: Utc::now(),
    };
    assert!(result.is_empty());
}

#[test]
fn incremental_result_not_empty_with_added_proxy() {
    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(serde_json::json!({
        "id": "p1",
        "listen_path": "/api",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": 8080
    }))
    .unwrap();
    let result = IncrementalResult {
        added_or_modified_proxies: vec![proxy],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        poll_timestamp: Utc::now(),
    };
    assert!(!result.is_empty());
}

#[test]
fn incremental_result_not_empty_with_removed_proxy_id() {
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec!["p1".to_string()],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        poll_timestamp: Utc::now(),
    };
    assert!(!result.is_empty());
}

#[test]
fn incremental_result_not_empty_with_removed_consumer() {
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec!["c1".to_string()],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        poll_timestamp: Utc::now(),
    };
    assert!(!result.is_empty());
}

#[test]
fn incremental_result_not_empty_with_removed_plugin_config() {
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec!["pc1".to_string()],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        poll_timestamp: Utc::now(),
    };
    assert!(!result.is_empty());
}

#[test]
fn incremental_result_not_empty_with_removed_upstream() {
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec!["u1".to_string()],
        poll_timestamp: Utc::now(),
    };
    assert!(!result.is_empty());
}

#[test]
fn incremental_result_not_empty_with_added_consumer() {
    let consumer: ferrum_edge::config::types::Consumer =
        serde_json::from_value(serde_json::json!({
            "id": "c1",
            "username": "alice",
            "credentials": {}
        }))
        .unwrap();
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![consumer],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        poll_timestamp: Utc::now(),
    };
    assert!(!result.is_empty());
}
