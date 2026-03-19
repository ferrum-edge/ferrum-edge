//! Tests for connection pool manager

use chrono::Utc;
use ferrum_gateway::config::PoolConfig;
use ferrum_gateway::config::types::{AuthMode, BackendProtocol, Proxy};
use ferrum_gateway::connection_pool::ConnectionPool;

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
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn create_test_env_config() -> ferrum_gateway::config::EnvConfig {
    ferrum_gateway::config::EnvConfig {
        mode: ferrum_gateway::config::OperatingMode::File,
        log_level: "info".to_string(),
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
        db_poll_check_interval: 5,
        db_incremental_polling: true,
        db_ssl_mode: None,
        db_ssl_root_cert: None,
        db_ssl_client_cert: None,
        db_ssl_client_key: None,
        file_config_path: None,
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
    }
}

#[tokio::test]
async fn test_connection_pool_creation() {
    let pool = ConnectionPool::new(PoolConfig::default(), create_test_env_config());
    let proxy = create_test_proxy();

    let _client1 = pool.get_client(&proxy, None).await.unwrap();
    let _client2 = pool.get_client(&proxy, None).await.unwrap();

    // Should reuse the same client
    let stats = pool.get_stats();
    assert_eq!(stats.total_pools, 1);
}

#[tokio::test]
async fn test_pool_stats() {
    let pool = ConnectionPool::new(PoolConfig::default(), create_test_env_config());
    let proxy = create_test_proxy();

    let _client = pool.get_client(&proxy, None).await.unwrap();
    let stats = pool.get_stats();

    assert!(stats.total_pools > 0);
    assert_eq!(stats.max_idle_per_host, 10);
    assert_eq!(stats.idle_timeout_seconds, 90);
}

#[tokio::test]
async fn test_different_proxy_configs_produce_different_pool_keys() {
    let pool = ConnectionPool::new(PoolConfig::default(), create_test_env_config());

    let mut proxy1 = create_test_proxy();
    proxy1.backend_port = 3000;

    let mut proxy2 = create_test_proxy();
    proxy2.backend_port = 4000;

    let _client1 = pool.get_client(&proxy1, None).await.unwrap();
    let _client2 = pool.get_client(&proxy2, None).await.unwrap();

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 2,
        "Different ports should create separate pool entries"
    );
}

#[tokio::test]
async fn test_different_protocols_produce_different_pool_keys() {
    let pool = ConnectionPool::new(PoolConfig::default(), create_test_env_config());

    let mut proxy_http = create_test_proxy();
    proxy_http.backend_protocol = BackendProtocol::Http;

    let mut proxy_https = create_test_proxy();
    proxy_https.backend_protocol = BackendProtocol::Https;

    let _client1 = pool.get_client(&proxy_http, None).await.unwrap();
    let _client2 = pool.get_client(&proxy_https, None).await.unwrap();

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 2,
        "Different protocols should create separate pool entries"
    );
}

#[tokio::test]
async fn test_same_proxy_reuses_cached_client() {
    let pool = ConnectionPool::new(PoolConfig::default(), create_test_env_config());
    let proxy = create_test_proxy();

    let _client1 = pool.get_client(&proxy, None).await.unwrap();
    let _client2 = pool.get_client(&proxy, None).await.unwrap();
    let _client3 = pool.get_client(&proxy, None).await.unwrap();

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 1,
        "Same proxy config should reuse cached client"
    );
}

#[tokio::test]
async fn test_resolved_ip_affects_pool_key() {
    let pool = ConnectionPool::new(PoolConfig::default(), create_test_env_config());
    let proxy = create_test_proxy();

    let ip1: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let ip2: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    let _client1 = pool.get_client(&proxy, Some(ip1)).await.unwrap();
    let _client2 = pool.get_client(&proxy, Some(ip2)).await.unwrap();

    let stats = pool.get_stats();
    assert_eq!(
        stats.total_pools, 2,
        "Different resolved IPs should create separate pool entries"
    );
}

#[tokio::test]
async fn test_pool_clear() {
    let pool = ConnectionPool::new(PoolConfig::default(), create_test_env_config());
    let proxy = create_test_proxy();

    let _client = pool.get_client(&proxy, None).await.unwrap();
    assert_eq!(pool.get_stats().total_pools, 1);

    pool.clear();
    assert_eq!(pool.get_stats().total_pools, 0);
}

#[tokio::test]
async fn test_pool_with_proxy_config_overrides() {
    let pool = ConnectionPool::new(PoolConfig::default(), create_test_env_config());

    let mut proxy = create_test_proxy();
    proxy.pool_max_idle_per_host = Some(25);
    proxy.pool_idle_timeout_seconds = Some(120);
    proxy.pool_tcp_keepalive_seconds = Some(30);

    // Should create a client successfully with proxy overrides
    let client = pool.get_client(&proxy, None).await;
    assert!(
        client.is_ok(),
        "Pool should create client with proxy config overrides"
    );
}

#[tokio::test]
async fn test_pool_websocket_protocol_creates_client() {
    let pool = ConnectionPool::new(PoolConfig::default(), create_test_env_config());

    let mut proxy = create_test_proxy();
    proxy.backend_protocol = BackendProtocol::Ws;

    let client = pool.get_client(&proxy, None).await;
    assert!(
        client.is_ok(),
        "Pool should create client for WebSocket protocol"
    );
}
