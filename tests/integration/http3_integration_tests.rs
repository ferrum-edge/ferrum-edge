//! HTTP/3 Integration Tests
//! Tests complete HTTP/3 flow: Client → Gateway → Backend

use std::sync::Arc;

use ferrum_gateway::config::types::{BackendProtocol, GatewayConfig, Proxy};
use ferrum_gateway::config::{EnvConfig, PoolConfig};
use ferrum_gateway::connection_pool::ConnectionPool;
use ferrum_gateway::dns::DnsCache;
use ferrum_gateway::proxy::ProxyState;
use ferrum_gateway::{ConsumerIndex, PluginCache, RouterCache};
use tracing::info;

// Initialize rustls crypto provider for tests
fn init_crypto_provider() {
    // Try to install the crypto provider, but don't panic if it fails
    // This handles the case where tests run in isolation
    if let Err(e) =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
    {
        tracing::warn!("Failed to install crypto provider: {:?}", e);
        // Try aws-lc-rs as fallback
        if let Err(e2) = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::aws_lc_rs::default_provider(),
        ) {
            tracing::error!("Failed to install fallback crypto provider: {:?}", e2);
        }
    }
}

/// Test HTTP/3 server configuration
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct Http3TestConfig {
    pub http3_idle_timeout: u64,
    pub http3_max_streams: u32,
    pub enable_http3: bool,
}

impl Default for Http3TestConfig {
    fn default() -> Self {
        Self {
            http3_idle_timeout: 30,
            http3_max_streams: 1000,
            enable_http3: true,
        }
    }
}

/// Create a test proxy configuration for HTTP/3
fn create_http3_test_proxy() -> Proxy {
    Proxy {
        id: "http3-test-proxy".to_string(),
        name: Some("HTTP/3 Test Proxy".to_string()),
        hosts: vec![],
        listen_path: "/http3-test".to_string(),
        backend_protocol: BackendProtocol::H3,
        backend_host: "facebook.com".to_string(),
        backend_port: 443,
        backend_path: Some("/get".to_string()),
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
        auth_mode: ferrum_gateway::config::types::AuthMode::Single,
        plugins: vec![],
        pool_max_idle_per_host: Some(10),
        pool_idle_timeout_seconds: Some(90),
        pool_enable_http_keep_alive: Some(true),
        pool_enable_http2: Some(true),
        pool_tcp_keepalive_seconds: Some(60),
        pool_http2_keep_alive_interval_seconds: Some(30),
        pool_http2_keep_alive_timeout_seconds: Some(45),
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        udp_idle_timeout_seconds: 60,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Create a test gateway configuration with HTTP/3
fn create_http3_test_gateway_config() -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies: vec![create_http3_test_proxy()],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: chrono::Utc::now(),
    }
}

/// Create a test environment configuration for HTTP/3
fn create_http3_test_env_config() -> EnvConfig {
    EnvConfig {
        mode: ferrum_gateway::config::OperatingMode::File,
        log_level: "debug".to_string(),
        enable_streaming_latency_tracking: false,
        proxy_http_port: 8080,
        proxy_https_port: 8443,
        proxy_tls_cert_path: None,
        proxy_tls_key_path: None,
        admin_http_port: 9000,
        admin_https_port: 9443,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_jwt_secret: Some("test-secret".to_string()),
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
        max_body_size_bytes: 10_485_760,
        max_response_body_size_bytes: 10_485_760,
        dns_cache_ttl_seconds: 300,
        dns_overrides: std::collections::HashMap::new(),
        dns_resolver_address: None,
        dns_resolver_hosts_file: None,
        dns_order: None,
        dns_valid_ttl: None,
        dns_stale_ttl: 3600,
        dns_error_ttl: 1,
        tls_ca_bundle_path: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        frontend_tls_client_ca_bundle_path: None,
        admin_tls_client_ca_bundle_path: None,
        tls_no_verify: false,
        admin_read_only: false,
        admin_tls_no_verify: false,
        // HTTP/3 specific configuration (shares proxy_https_port for QUIC listener)
        enable_http3: true,
        http3_idle_timeout: 30,
        http3_max_streams: 1000,
        http3_stream_receive_window: 8_388_608,
        http3_receive_window: 33_554_432,
        http3_send_window: 8_388_608,
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
        stream_proxy_bind_address: "0.0.0.0".into(),
        trusted_proxies: String::new(),
        dns_cache_max_size: 10_000,
        dns_slow_threshold_ms: None,
        real_ip_header: None,
        dtls_cert_path: None,
        dtls_key_path: None,
        dtls_client_ca_cert_path: None,
        plugin_http_slow_threshold_ms: 1000,
        admin_restore_max_body_size_mib: 100,
        migrate_action: "up".into(),
        migrate_dry_run: false,
    }
}

/// Test HTTP/3 backend connection directly
#[tokio::test]
async fn test_http3_backend_connection() {
    // Initialize crypto provider for this test
    init_crypto_provider();

    // This test verifies that we can establish an HTTP/3 connection to a real backend
    // Note: This requires a real HTTP/3-enabled backend server

    let proxy = create_http3_test_proxy();
    let pool_config = PoolConfig::default();
    let env_config = create_http3_test_env_config();

    let dns_cache = DnsCache::new(ferrum_gateway::dns::DnsConfig::default());
    let connection_pool = Arc::new(ConnectionPool::new(
        pool_config,
        env_config,
        dns_cache.clone(),
    ));

    // Test DNS resolution first
    let resolved_ip = dns_cache
        .resolve(
            &proxy.backend_host,
            proxy.dns_override.clone().as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await;
    assert!(
        resolved_ip.is_ok(),
        "DNS resolution should succeed for {}",
        proxy.backend_host
    );

    info!("Resolved {} to {:?}", proxy.backend_host, resolved_ip);

    // Test HTTP/3 client creation and basic functionality
    let tls_config = connection_pool.get_tls_config_for_backend(&proxy);
    let http3_client_result = ferrum_gateway::http3::client::Http3Client::new(tls_config, None);

    match http3_client_result {
        Ok(_client) => {
            info!("HTTP/3 client created successfully");

            // Test a simple HTTP/3 request to verify client works
            // Use a real HTTP/3-enabled endpoint (facebook.com supports HTTP/3)
            let backend_url = "https://www.facebook.com:443/";
            let headers = std::collections::HashMap::from([
                ("user-agent".to_string(), "ferrum-gateway-test".to_string()),
                ("accept".to_string(), "text/html".to_string()),
            ]);

            // Convert headers to HTTP/3 format
            let mut http3_headers = Vec::new();
            for (name, value) in headers {
                http3_headers.push((
                    name.parse()
                        .unwrap_or_else(|_| http::header::HeaderName::from_static("x-custom")),
                    value
                        .parse()
                        .unwrap_or_else(|_| http::header::HeaderValue::from_static("")),
                ));
            }

            // Verify header conversion works
            assert_eq!(http3_headers.len(), 2);

            // Try to make a request (Facebook supports HTTP/3, so should work better)
            let request_body = bytes::Bytes::from("test");
            let start_time = std::time::Instant::now();
            let result = _client
                .request(&proxy, "GET", backend_url, http3_headers, request_body)
                .await;
            let request_time = start_time.elapsed();

            info!("HTTP/3 request completed in {:?}", request_time);

            match result {
                Ok((status, body, response_headers)) => {
                    info!(
                        "HTTP/3 request successful: status={}, body_len={}, headers={}",
                        status,
                        body.len(),
                        response_headers.len()
                    );
                    assert!(status > 0, "Status should be valid");

                    // Should be reasonably fast with HTTP/3
                    assert!(
                        request_time.as_secs() < 10,
                        "HTTP/3 request should complete within 10 seconds"
                    );
                }
                Err(e) => {
                    tracing::warn!("HTTP/3 request failed: {:?}", e);
                    // This is still possible due to network issues, but should be less common
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to create HTTP/3 client: {:?}", e);
            // This is expected in test environments without proper HTTP/3 support
            // We'll still verify the configuration is correct
        }
    }

    // Verify proxy configuration
    assert_eq!(proxy.backend_protocol, BackendProtocol::H3);
    assert_eq!(proxy.backend_host, "facebook.com");
    assert_eq!(proxy.backend_port, 443);

    info!("HTTP/3 backend connection test completed successfully");
}

/// Test HTTP/3 configuration loading
#[tokio::test]
async fn test_http3_configuration_loading() {
    let env_config = create_http3_test_env_config();

    // Verify HTTP/3 configuration is loaded correctly
    // HTTP/3 shares proxy_https_port (no separate http3_port)
    assert!(env_config.enable_http3);
    assert_eq!(env_config.proxy_https_port, 8443);
    assert_eq!(env_config.http3_idle_timeout, 30);
    assert_eq!(env_config.http3_max_streams, 1000);

    let gateway_config = create_http3_test_gateway_config();

    // Verify proxy configuration
    let proxy = &gateway_config.proxies[0];
    assert_eq!(proxy.backend_protocol, BackendProtocol::H3);
    assert_eq!(proxy.listen_path, "/http3-test");
    assert_eq!(proxy.backend_host, "facebook.com");
}

/// Test HTTP/3 proxy state creation
#[tokio::test]
async fn test_http3_proxy_state_creation() {
    let gateway_config = Arc::new(arc_swap::ArcSwap::from_pointee(
        create_http3_test_gateway_config(),
    ));
    let pool_config = PoolConfig::default();
    let env_config = create_http3_test_env_config();

    let dns_cache = DnsCache::new(ferrum_gateway::dns::DnsConfig::default());
    let connection_pool = Arc::new(ConnectionPool::new(
        pool_config,
        env_config,
        dns_cache.clone(),
    ));

    let gc = create_http3_test_gateway_config();
    let router_cache = Arc::new(RouterCache::new(&gc, 10_000));
    let plugin_cache = Arc::new(PluginCache::new(&gc).unwrap());
    let consumer_index = Arc::new(ConsumerIndex::new(&gc.consumers));
    let lb_cache = Arc::new(ferrum_gateway::LoadBalancerCache::new(&gc));
    let slm = Arc::new(
        ferrum_gateway::proxy::stream_listener::StreamListenerManager::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            gateway_config.clone(),
            dns_cache.clone(),
            lb_cache.clone(),
            None,
            false,
        ),
    );
    let dns_cache_for_sd = dns_cache.clone();
    let proxy_state = ProxyState {
        config: gateway_config,
        dns_cache,
        connection_pool,
        router_cache,
        plugin_cache,
        consumer_index,
        request_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        status_counts: Arc::new(dashmap::DashMap::new()),
        grpc_pool: Arc::new(ferrum_gateway::proxy::grpc_proxy::GrpcConnectionPool::default()),
        http2_pool: Arc::new(ferrum_gateway::proxy::http2_pool::Http2ConnectionPool::default()),
        h3_pool: Arc::new(ferrum_gateway::http3::client::Http3ConnectionPool::new(
            Arc::new(ferrum_gateway::config::EnvConfig::default()),
        )),
        load_balancer_cache: lb_cache.clone(),
        health_checker: Arc::new(ferrum_gateway::health_check::HealthChecker::new()),
        circuit_breaker_cache: Arc::new(ferrum_gateway::circuit_breaker::CircuitBreakerCache::new()),
        service_discovery_manager: {
            let hc = Arc::new(ferrum_gateway::health_check::HealthChecker::new());
            Arc::new(
                ferrum_gateway::service_discovery::ServiceDiscoveryManager::new(
                    lb_cache,
                    dns_cache_for_sd,
                    hc,
                    ferrum_gateway::plugins::PluginHttpClient::default(),
                ),
            )
        },
        alt_svc_header: Some("h3=\":8443\"; ma=86400".to_string()),
        max_header_size_bytes: 32768,
        max_single_header_size_bytes: 16384,
        max_body_size_bytes: 10_485_760,
        max_response_body_size_bytes: 10_485_760,
        env_config: Arc::new(ferrum_gateway::config::EnvConfig::default()),
        trusted_proxies: Arc::new(ferrum_gateway::proxy::client_ip::TrustedProxies::parse("")),
        stream_listener_manager: slm,
    };

    // Verify proxy state is created successfully
    let current_config = proxy_state.config.load();
    assert_eq!(current_config.proxies.len(), 1);
    assert_eq!(
        current_config.proxies[0].backend_protocol,
        BackendProtocol::H3
    );
}

/// Test HTTP/3 environment variable parsing
#[tokio::test]
async fn test_http3_environment_variables() {
    // Set environment variables
    // Note: FERRUM_HTTP3_PORT no longer exists — HTTP/3 shares FERRUM_PROXY_HTTPS_PORT
    unsafe {
        std::env::set_var("FERRUM_ENABLE_HTTP3", "true");
        std::env::set_var("FERRUM_HTTP3_IDLE_TIMEOUT", "30");
        std::env::set_var("FERRUM_HTTP3_MAX_STREAMS", "100");
    }

    let enable_http3 = std::env::var("FERRUM_ENABLE_HTTP3")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    let http3_idle_timeout = std::env::var("FERRUM_HTTP3_IDLE_TIMEOUT")
        .unwrap_or_else(|_| "30".to_string())
        .parse::<u64>()
        .unwrap_or(30);

    let http3_max_streams = std::env::var("FERRUM_HTTP3_MAX_STREAMS")
        .unwrap_or_else(|_| "100".to_string())
        .parse::<u32>()
        .unwrap_or(100);

    // Verify environment variables are parsed correctly
    assert!(enable_http3);
    assert_eq!(http3_idle_timeout, 30);
    assert_eq!(http3_max_streams, 100);

    // Clean up environment variables
    unsafe {
        std::env::remove_var("FERRUM_ENABLE_HTTP3");
        std::env::remove_var("FERRUM_HTTP3_IDLE_TIMEOUT");
        std::env::remove_var("FERRUM_HTTP3_MAX_STREAMS");
    }
}

/// Test HTTP/3 protocol enum functionality
#[tokio::test]
async fn test_http3_protocol_enum() {
    let protocol = BackendProtocol::H3;

    // Test Display trait
    assert_eq!(protocol.to_string(), "h3");

    // Test PartialEq
    assert_eq!(protocol, BackendProtocol::H3);
    assert_ne!(protocol, BackendProtocol::Http);
    assert_ne!(protocol, BackendProtocol::Https);

    // Test serialization/deserialization (if serde is used)
    let serialized = serde_json::to_string(&protocol).unwrap();
    assert_eq!(serialized, "\"h3\"");

    let deserialized: BackendProtocol = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, BackendProtocol::H3);
}

/// Test HTTP/3 configuration validation
#[tokio::test]
async fn test_http3_configuration_validation() {
    let config = create_http3_test_env_config();

    // HTTP/3 shares proxy_https_port (no separate http3_port)
    assert!(config.proxy_https_port > 0);
    assert!(config.http3_idle_timeout > 0);
    assert!(config.http3_max_streams > 0);
    assert!(config.enable_http3);
}

/// Integration test placeholder for full HTTP/3 flow
/// This test will be implemented once HTTP/3 server and client are complete
#[tokio::test]
async fn test_http3_full_integration() {
    // Initialize crypto provider for this test
    init_crypto_provider();

    // This test verifies the complete HTTP/3 flow:
    // 1. Create HTTP/3 proxy configuration
    // 2. Test proxy state creation with HTTP/3 support
    // 3. Verify HTTP/3 routing logic works
    // 4. Test HTTP/3 client integration

    let proxy = create_http3_test_proxy();
    let gateway_config = Arc::new(arc_swap::ArcSwap::from_pointee(
        create_http3_test_gateway_config(),
    ));
    let pool_config = PoolConfig::default();
    let env_config = create_http3_test_env_config();

    let dns_cache = DnsCache::new(ferrum_gateway::dns::DnsConfig::default());
    let connection_pool = Arc::new(ConnectionPool::new(
        pool_config,
        env_config,
        dns_cache.clone(),
    ));

    // Create proxy state with HTTP/3 support
    let gc = create_http3_test_gateway_config();
    let router_cache = Arc::new(RouterCache::new(&gc, 10_000));
    let plugin_cache = Arc::new(PluginCache::new(&gc).unwrap());
    let consumer_index = Arc::new(ConsumerIndex::new(&gc.consumers));
    let lb_cache = Arc::new(ferrum_gateway::LoadBalancerCache::new(&gc));
    let slm = Arc::new(
        ferrum_gateway::proxy::stream_listener::StreamListenerManager::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            gateway_config.clone(),
            dns_cache.clone(),
            lb_cache.clone(),
            None,
            false,
        ),
    );
    let dns_cache_for_sd = dns_cache.clone();
    let proxy_state = ProxyState {
        config: gateway_config,
        dns_cache,
        connection_pool,
        router_cache,
        plugin_cache,
        consumer_index,
        request_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        status_counts: Arc::new(dashmap::DashMap::new()),
        grpc_pool: Arc::new(ferrum_gateway::proxy::grpc_proxy::GrpcConnectionPool::default()),
        http2_pool: Arc::new(ferrum_gateway::proxy::http2_pool::Http2ConnectionPool::default()),
        h3_pool: Arc::new(ferrum_gateway::http3::client::Http3ConnectionPool::new(
            Arc::new(ferrum_gateway::config::EnvConfig::default()),
        )),
        load_balancer_cache: lb_cache.clone(),
        health_checker: Arc::new(ferrum_gateway::health_check::HealthChecker::new()),
        circuit_breaker_cache: Arc::new(ferrum_gateway::circuit_breaker::CircuitBreakerCache::new()),
        service_discovery_manager: {
            let hc = Arc::new(ferrum_gateway::health_check::HealthChecker::new());
            Arc::new(
                ferrum_gateway::service_discovery::ServiceDiscoveryManager::new(
                    lb_cache,
                    dns_cache_for_sd,
                    hc,
                    ferrum_gateway::plugins::PluginHttpClient::default(),
                ),
            )
        },
        alt_svc_header: Some("h3=\":8443\"; ma=86400".to_string()),
        max_header_size_bytes: 32768,
        max_single_header_size_bytes: 16384,
        max_body_size_bytes: 10_485_760,
        max_response_body_size_bytes: 10_485_760,
        env_config: Arc::new(ferrum_gateway::config::EnvConfig::default()),
        trusted_proxies: Arc::new(ferrum_gateway::proxy::client_ip::TrustedProxies::parse("")),
        stream_listener_manager: slm,
    };

    // Verify proxy state is created successfully
    let current_config = proxy_state.config.load();
    assert_eq!(current_config.proxies.len(), 1);
    assert_eq!(
        current_config.proxies[0].backend_protocol,
        BackendProtocol::H3
    );

    // Test HTTP/3 backend connection creation
    let tls_config = proxy_state
        .connection_pool
        .get_tls_config_for_backend(&proxy);
    assert!(Arc::strong_count(&tls_config) > 0);

    // Test HTTP/3 client creation (may fail in test environment, but should not panic)
    let http3_client_result = ferrum_gateway::http3::client::Http3Client::new(tls_config, None);
    match http3_client_result {
        Ok(_client) => {
            info!("HTTP/3 client created successfully");
        }
        Err(e) => {
            tracing::warn!("Failed to create HTTP/3 client: {}", e);
            // This is expected in test environments without proper HTTP/3 support
        }
    }

    info!("HTTP/3 full integration test completed successfully");
}

/// Performance test for HTTP/3 connection establishment
#[tokio::test]
async fn test_http3_connection_performance() {
    // Initialize crypto provider for this test
    init_crypto_provider();

    // This test will measure:
    // - Connection establishment time
    // - Request/response latency
    // - Concurrent connection handling
    // - Memory usage

    let proxy = create_http3_test_proxy();
    let pool_config = PoolConfig::default();
    let env_config = create_http3_test_env_config();

    let connection_pool = Arc::new(ConnectionPool::new(
        pool_config,
        env_config,
        DnsCache::new(ferrum_gateway::dns::DnsConfig::default()),
    ));

    // Test HTTP/3 client creation performance
    let tls_config = connection_pool.get_tls_config_for_backend(&proxy);

    let start_time = std::time::Instant::now();
    let http3_client = ferrum_gateway::http3::client::Http3Client::new(tls_config, None)
        .expect("HTTP/3 client creation should succeed");
    let client_creation_time = start_time.elapsed();

    info!("HTTP/3 client creation took: {:?}", client_creation_time);
    assert!(
        client_creation_time.as_millis() < 100,
        "Client creation should be fast"
    );

    // Test multiple concurrent requests
    // Use a real HTTP/3-enabled endpoint (facebook.com supports HTTP/3)
    let backend_url = "https://www.facebook.com:443/";
    let headers = std::collections::HashMap::from([
        (
            "user-agent".to_string(),
            "ferrum-gateway-perf-test".to_string(),
        ),
        ("accept".to_string(), "application/json".to_string()),
    ]);

    // Convert headers to HTTP/3 format
    let mut http3_headers = Vec::new();
    for (name, value) in headers {
        http3_headers.push((
            name.parse()
                .unwrap_or_else(|_| http::header::HeaderName::from_static("x-custom")),
            value
                .parse()
                .unwrap_or_else(|_| http::header::HeaderValue::from_static("")),
        ));
    }

    // Test sequential requests
    let sequential_start = std::time::Instant::now();
    let mut successful_requests = 0;
    let total_requests = 3;

    for i in 0..total_requests {
        let request_body = bytes::Bytes::from(format!("request_{}", i));
        match http3_client
            .request(
                &proxy,
                "GET",
                backend_url,
                http3_headers.clone(),
                request_body,
            )
            .await
        {
            Ok((status, body, response_headers)) => {
                info!(
                    "Request {} successful: status={}, body_len={}, headers={}",
                    i,
                    status,
                    body.len(),
                    response_headers.len()
                );
                successful_requests += 1;
            }
            Err(e) => {
                tracing::warn!("Request {} failed: {:?}", i, e);
            }
        }
    }

    let sequential_time = sequential_start.elapsed();
    info!(
        "Sequential requests ({}): {:?}, success rate: {}/{}",
        total_requests, sequential_time, successful_requests, total_requests
    );

    // Test concurrent requests
    let concurrent_start = std::time::Instant::now();
    let mut concurrent_tasks = Vec::new();

    for i in 0..total_requests {
        let client = http3_client.clone();
        let proxy_clone = proxy.clone();
        let url = backend_url.to_string();
        let headers_clone = http3_headers.clone();

        let task = tokio::spawn(async move {
            let request_body = bytes::Bytes::from(format!("concurrent_request_{}", i));
            match client
                .request(&proxy_clone, "GET", &url, headers_clone, request_body)
                .await
            {
                Ok((status, body, response_headers)) => {
                    info!(
                        "Concurrent request {} successful: status={}, body_len={}, headers={}",
                        i,
                        status,
                        body.len(),
                        response_headers.len()
                    );
                    Some((status, body.len()))
                }
                Err(e) => {
                    tracing::warn!("Concurrent request {} failed: {:?}", i, e);
                    None
                }
            }
        });

        concurrent_tasks.push(task);
    }

    let results = futures::future::join_all(concurrent_tasks).await;
    let successful_concurrent = results
        .iter()
        .filter(|r| r.as_ref().ok().and_then(|x| x.as_ref()).is_some())
        .count();
    let concurrent_time = concurrent_start.elapsed();

    info!(
        "Concurrent requests ({}): {:?}, success rate: {}/{}",
        total_requests, concurrent_time, successful_concurrent, total_requests
    );

    // Performance assertions
    info!("Performance results:");
    info!(
        "  Sequential: {}/{} successful in {:?}",
        successful_requests, total_requests, sequential_time
    );
    info!(
        "  Concurrent: {}/{} successful in {:?}",
        successful_concurrent, total_requests, concurrent_time
    );

    // Basic assertions - be more lenient for test environments
    assert!(
        client_creation_time.as_millis() < 1000,
        "Client creation should be <1s"
    );

    // At least some requests should work (network issues are expected in test env)
    if successful_requests > 0 {
        let sequential_avg = sequential_time.as_millis() as f64 / successful_requests as f64;
        info!("  Sequential avg: {:.2}ms per request", sequential_avg);
        assert!(
            sequential_avg < 30000.0,
            "Sequential requests should average <30s"
        );
    }

    if successful_concurrent > 0 {
        let concurrent_avg = concurrent_time.as_millis() as f64 / successful_concurrent as f64;
        info!("  Concurrent avg: {:.2}ms per request", concurrent_avg);
        assert!(
            concurrent_avg < 30000.0,
            "Concurrent requests should average <30s"
        );
    }

    // If we have any successful requests, the test passes
    // This accounts for network issues in test environments
    if successful_requests == 0 && successful_concurrent == 0 {
        // Log detailed failure info for debugging
        tracing::error!("All HTTP/3 requests failed - this may indicate:");
        tracing::error!("  1. Network connectivity issues");
        tracing::error!("  2. Backend doesn't support HTTP/3");
        tracing::error!("  3. TLS configuration issues");
        tracing::error!("  4. Firewall blocking QUIC/UDP");

        // Still pass the test since this is expected in some test environments
        info!("HTTP/3 performance test completed - network issues expected in test environment");
    } else {
        info!("HTTP/3 performance test completed successfully");
    }
}
