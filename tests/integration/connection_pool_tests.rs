//! Tests for connection pool manager

use chrono::Utc;
use ferrum_gateway::config::PoolConfig;
use ferrum_gateway::config::types::{AuthMode, BackendProtocol, Proxy};
use ferrum_gateway::connection_pool::ConnectionPool;
use ferrum_gateway::dns::{DnsCache, DnsConfig};

fn create_test_proxy() -> Proxy {
    Proxy {
        id: "test".to_string(),
        name: None,
        listen_path: "/test".to_string(),
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

fn create_test_env_config() -> ferrum_gateway::config::EnvConfig {
    ferrum_gateway::config::EnvConfig {
        mode: ferrum_gateway::config::OperatingMode::File,
        log_level: "info".to_string(),
        enable_streaming_latency_tracking: false,
        proxy_http_port: 8000,
        proxy_https_port: 8443,
        proxy_tls_cert_path: None,
        proxy_tls_key_path: None,
        admin_http_port: 9000,
        admin_https_port: 9443,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_read_only: false,
        admin_jwt_secret: None,
        db_type: None,
        db_url: None,
        db_poll_interval: 30,
        db_ssl_mode: None,
        db_ssl_root_cert: None,
        db_ssl_client_cert: None,
        db_ssl_client_key: None,
        file_config_path: None,
        db_config_backup_path: None,
        cp_grpc_listen_addr: None,
        cp_grpc_jwt_secret: None,
        dp_cp_grpc_url: None,
        dp_grpc_auth_token: None,
        max_header_size_bytes: 32768,
        max_single_header_size_bytes: 16384,
        max_body_size_bytes: 10485760,
        max_response_body_size_bytes: 10485760,
        dns_cache_ttl_seconds: 300,
        dns_overrides: std::collections::HashMap::new(),
        dns_resolver_address: None,
        dns_resolver_hosts_file: None,
        dns_order: None,
        dns_valid_ttl: None,
        dns_stale_ttl: 3600,
        dns_error_ttl: 1,
        backend_tls_ca_bundle_path: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        frontend_tls_client_ca_bundle_path: None,
        backend_tls_no_verify: false,
        admin_tls_client_ca_bundle_path: None,
        admin_tls_no_verify: false,
        enable_http3: false,
        http3_idle_timeout: 30,
        http3_max_streams: 100,
        db_tls_enabled: false,
        db_tls_ca_cert_path: None,
        db_tls_client_cert_path: None,
        db_tls_client_key_path: None,
        db_tls_insecure: false,
        tls_min_version: "1.2".into(),
        tls_max_version: "1.3".into(),
        tls_cipher_suites: None,
        tls_prefer_server_cipher_order: true,
        tls_curves: None,
        dns_cache_max_size: 10_000,
        dns_slow_threshold_ms: None,
        stream_proxy_bind_address: "0.0.0.0".into(),
        trusted_proxies: String::new(),
        real_ip_header: None,
        dtls_cert_path: None,
        dtls_key_path: None,
        dtls_client_ca_cert_path: None,
        plugin_http_slow_threshold_ms: 1000,
    }
}

fn create_test_dns_cache() -> DnsCache {
    DnsCache::new(DnsConfig::default())
}

#[tokio::test]
async fn test_connection_pool_creation() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );
    let proxy = create_test_proxy();

    let _client1 = pool.get_client(&proxy).await.unwrap();
    let _client2 = pool.get_client(&proxy).await.unwrap();

    // Should reuse the same client
    let stats = pool.get_stats();
    assert_eq!(stats.total_pools, 1);
}

#[tokio::test]
async fn test_pool_stats() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );
    let proxy = create_test_proxy();

    let _client = pool.get_client(&proxy).await.unwrap();
    let stats = pool.get_stats();

    assert!(stats.total_pools > 0);
    assert_eq!(stats.max_idle_per_host, 64);
    assert_eq!(stats.idle_timeout_seconds, 90);
}

#[tokio::test]
async fn test_different_proxy_configs_produce_different_pool_keys() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );

    let mut proxy1 = create_test_proxy();
    proxy1.backend_port = 3000;

    let mut proxy2 = create_test_proxy();
    proxy2.backend_port = 4000;

    let _client1 = pool.get_client(&proxy1).await.unwrap();
    let _client2 = pool.get_client(&proxy2).await.unwrap();

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 2,
        "Different ports should create separate pool entries"
    );
}

#[tokio::test]
async fn test_different_protocols_produce_different_pool_keys() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );

    let mut proxy_http = create_test_proxy();
    proxy_http.backend_protocol = BackendProtocol::Http;

    let mut proxy_https = create_test_proxy();
    proxy_https.backend_protocol = BackendProtocol::Https;

    let _client1 = pool.get_client(&proxy_http).await.unwrap();
    let _client2 = pool.get_client(&proxy_https).await.unwrap();

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 2,
        "Different protocols should create separate pool entries"
    );
}

#[tokio::test]
async fn test_same_proxy_reuses_cached_client() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );
    let proxy = create_test_proxy();

    let _client1 = pool.get_client(&proxy).await.unwrap();
    let _client2 = pool.get_client(&proxy).await.unwrap();
    let _client3 = pool.get_client(&proxy).await.unwrap();

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 1,
        "Same proxy config should reuse cached client"
    );
}

#[tokio::test]
async fn test_dns_override_affects_pool_key() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );

    let mut proxy1 = create_test_proxy();
    proxy1.dns_override = Some("127.0.0.1".to_string());

    let mut proxy2 = create_test_proxy();
    proxy2.dns_override = Some("192.168.1.1".to_string());

    let _client1 = pool.get_client(&proxy1).await.unwrap();
    let _client2 = pool.get_client(&proxy2).await.unwrap();

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 2,
        "Different DNS overrides should create separate pool entries"
    );
}

#[tokio::test]
async fn test_pool_clear() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );
    let proxy = create_test_proxy();

    let _client = pool.get_client(&proxy).await.unwrap();
    assert_eq!(pool.get_stats().total_pools, 1);

    pool.clear();
    assert_eq!(pool.get_stats().total_pools, 0);
}

#[tokio::test]
async fn test_pool_with_proxy_config_overrides() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );

    let mut proxy = create_test_proxy();
    proxy.pool_max_idle_per_host = Some(25);
    proxy.pool_idle_timeout_seconds = Some(120);
    proxy.pool_tcp_keepalive_seconds = Some(30);

    // Should create a client successfully with proxy overrides
    let client = pool.get_client(&proxy).await;
    assert!(
        client.is_ok(),
        "Pool should create client with proxy config overrides"
    );
}

#[tokio::test]
async fn test_pool_websocket_protocol_creates_client() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );

    let mut proxy = create_test_proxy();
    proxy.backend_protocol = BackendProtocol::Ws;

    let client = pool.get_client(&proxy).await;
    assert!(
        client.is_ok(),
        "Pool should create client for WebSocket protocol"
    );
}

#[tokio::test]
async fn test_upstream_id_pools_separately_from_backend_host() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );

    // Proxy with direct backend
    let proxy_direct = create_test_proxy();

    // Proxy with same host/port but through an upstream
    let mut proxy_upstream = create_test_proxy();
    proxy_upstream.upstream_id = Some("upstream-1".to_string());

    let _client1 = pool.get_client(&proxy_direct).await.unwrap();
    let _client2 = pool.get_client(&proxy_upstream).await.unwrap();

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 2,
        "Upstream-backed proxy should have a different pool key than direct backend"
    );
}

#[tokio::test]
async fn test_different_upstream_ids_pool_separately() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );

    let mut proxy1 = create_test_proxy();
    proxy1.upstream_id = Some("upstream-a".to_string());

    let mut proxy2 = create_test_proxy();
    proxy2.upstream_id = Some("upstream-b".to_string());

    let _client1 = pool.get_client(&proxy1).await.unwrap();
    let _client2 = pool.get_client(&proxy2).await.unwrap();

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 2,
        "Different upstream IDs should create separate pool entries"
    );
}

#[tokio::test]
async fn test_concurrent_pool_access() {
    use std::sync::Arc;

    let pool = Arc::new(ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    ));

    let mut handles = Vec::new();
    for i in 0..10 {
        let pool_clone = pool.clone();
        handles.push(tokio::spawn(async move {
            let mut proxy = create_test_proxy();
            proxy.backend_port = 3000 + (i % 3); // 3 distinct keys
            pool_clone.get_client(&proxy).await.unwrap();
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 3,
        "Concurrent access should produce exactly 3 pool entries for 3 distinct ports"
    );
}

#[tokio::test]
async fn test_idle_timeout_does_not_fragment_pool() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );

    // Two proxies with same host/port/protocol but different idle timeouts
    // should share the same pool entry (idle_timeout is excluded from pool key)
    let mut proxy1 = create_test_proxy();
    proxy1.pool_idle_timeout_seconds = Some(30);

    let mut proxy2 = create_test_proxy();
    proxy2.pool_idle_timeout_seconds = Some(120);

    let _client1 = pool.get_client(&proxy1).await.unwrap();
    let _client2 = pool.get_client(&proxy2).await.unwrap();

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 1,
        "Different idle_timeout_seconds should NOT fragment the pool"
    );
}

#[tokio::test]
async fn test_max_idle_per_host_does_fragment_pool() {
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        create_test_env_config(),
        create_test_dns_cache(),
    );

    // Different max_idle_per_host IS in the pool key (affects connection behavior)
    let mut proxy1 = create_test_proxy();
    proxy1.pool_max_idle_per_host = Some(10);

    let mut proxy2 = create_test_proxy();
    proxy2.pool_max_idle_per_host = Some(50);

    let _client1 = pool.get_client(&proxy1).await.unwrap();
    let _client2 = pool.get_client(&proxy2).await.unwrap();

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 2,
        "Different max_idle_per_host should create separate pool entries"
    );
}
