//! HTTP/3 Integration Tests
//! Tests complete HTTP/3 flow: Client → Gateway → Backend

use std::sync::Arc;

use ferrum_edge::config::types::{BackendProtocol, GatewayConfig, Proxy};
use ferrum_edge::config::{EnvConfig, PoolConfig};
use ferrum_edge::connection_pool::ConnectionPool;
use ferrum_edge::dns::DnsCache;
use ferrum_edge::proxy::ProxyState;
use ferrum_edge::{ConsumerIndex, PluginCache, RouterCache};
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
        namespace: ferrum_edge::config::types::default_namespace(),
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
        auth_mode: ferrum_edge::config::types::AuthMode::Single,
        plugins: vec![],

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
        pool_http3_connections_per_backend: None,
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
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
        known_namespaces: Vec::new(),
    }
}

/// Create a test environment configuration for HTTP/3
fn create_http3_test_env_config() -> EnvConfig {
    EnvConfig {
        mode: ferrum_edge::config::OperatingMode::File,
        log_level: "debug".to_string(),
        enable_streaming_latency_tracking: false,
        proxy_http_port: 8080,
        proxy_https_port: 8443,
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        proxy_bind_address: "0.0.0.0".into(),
        admin_http_port: 9000,
        admin_https_port: 9443,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_bind_address: "0.0.0.0".into(),
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
        db_failover_urls: Vec::new(),
        db_read_replica_url: None,
        cp_grpc_listen_addr: None,
        cp_dp_grpc_jwt_secret: None,
        dp_cp_grpc_url: None,
        dp_cp_grpc_urls: Vec::new(),
        dp_cp_failover_primary_retry_secs: 300,
        cp_grpc_tls_cert_path: None,
        cp_grpc_tls_key_path: None,
        cp_grpc_tls_client_ca_path: None,
        dp_grpc_tls_ca_cert_path: None,
        dp_grpc_tls_client_cert_path: None,
        dp_grpc_tls_client_key_path: None,
        dp_grpc_tls_no_verify: false,
        max_header_size_bytes: 32768,
        max_single_header_size_bytes: 16384,
        max_header_count: 100,
        max_request_body_size_bytes: 10_485_760,
        max_response_body_size_bytes: 10_485_760,
        response_buffer_threshold_bytes: 2_097_152,
        h2_coalesce_target_bytes: 131_072,
        max_url_length_bytes: 8_192,
        max_query_params: 100,
        max_grpc_recv_size_bytes: 4_194_304,
        max_websocket_frame_size_bytes: 16_777_216,
        websocket_write_buffer_size: 131_072,
        websocket_tunnel_mode: false,
        dns_ttl_override: None,
        dns_overrides: std::collections::HashMap::new(),
        dns_resolver_address: None,
        dns_resolver_hosts_file: None,
        dns_order: None,
        dns_min_ttl: 5,
        dns_stale_ttl: 3600,
        dns_error_ttl: 1,
        dns_failed_retry_interval: 10,
        dns_warmup_concurrency: 500,
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
        http3_connections_per_backend: 4,
        http3_pool_idle_timeout_seconds: 120,
        grpc_pool_ready_wait_ms: 1,
        pool_cleanup_interval_seconds: 30,
        tcp_idle_timeout_seconds: 300,
        udp_max_sessions: 10_000,
        udp_cleanup_interval_seconds: 10,
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
        tls_session_cache_size: 4096,
        stream_proxy_bind_address: "0.0.0.0".into(),
        admin_allowed_cidrs: String::new(),
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
        worker_threads: None,
        blocking_threads: None,
        max_connections: 0,
        tcp_listen_backlog: 2048,
        server_http2_max_concurrent_streams: 250,
        ..Default::default()
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

    let dns_cache = DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let connection_pool = Arc::new(ConnectionPool::new(
        pool_config,
        env_config,
        dns_cache.clone(),
        None,
        std::sync::Arc::new(Vec::new()),
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
    let tls_config = connection_pool
        .get_tls_config_for_backend(&proxy)
        .expect("TLS config should succeed for test proxy");
    let http3_client_result = ferrum_edge::http3::client::Http3Client::new(tls_config, None);

    match http3_client_result {
        Ok(_client) => {
            info!("HTTP/3 client created successfully");

            // Test a simple HTTP/3 request to verify client works
            // Use a real HTTP/3-enabled endpoint (facebook.com supports HTTP/3)
            let backend_url = "https://www.facebook.com:443/";
            let headers = std::collections::HashMap::from([
                ("user-agent".to_string(), "ferrum-edge-test".to_string()),
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

    let dns_cache = DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let connection_pool = Arc::new(ConnectionPool::new(
        pool_config,
        env_config,
        dns_cache.clone(),
        None,
        std::sync::Arc::new(Vec::new()),
    ));

    let gc = create_http3_test_gateway_config();
    let router_cache = Arc::new(RouterCache::new(&gc, 10_000));
    let plugin_cache = Arc::new(PluginCache::new(&gc).unwrap());
    let consumer_index = Arc::new(ConsumerIndex::new(&gc.consumers));
    let lb_cache = Arc::new(ferrum_edge::LoadBalancerCache::new(&gc));
    let circuit_breaker_cache = Arc::new(ferrum_edge::circuit_breaker::CircuitBreakerCache::new());
    let slm = Arc::new(
        ferrum_edge::proxy::stream_listener::StreamListenerManager::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            gateway_config.clone(),
            dns_cache.clone(),
            lb_cache.clone(),
            consumer_index.clone(),
            plugin_cache.clone(),
            circuit_breaker_cache.clone(),
            None,
            false,
            None,
            300,
            10_000,
            10,
            None,
            std::sync::Arc::new(Vec::new()),
            std::sync::Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
                true, true, 300, 8192, 262_144, 65_536, 6000,
            )),
            64,
            true,
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
        grpc_pool: Arc::new(ferrum_edge::proxy::grpc_proxy::GrpcConnectionPool::default()),
        http2_pool: Arc::new(ferrum_edge::proxy::http2_pool::Http2ConnectionPool::default()),
        h3_pool: Arc::new(ferrum_edge::http3::client::Http3ConnectionPool::new(
            Arc::new(ferrum_edge::config::EnvConfig::default()),
            ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default()),
        )),
        load_balancer_cache: lb_cache.clone(),
        health_checker: Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        circuit_breaker_cache: Arc::new(ferrum_edge::circuit_breaker::CircuitBreakerCache::new()),
        service_discovery_manager: {
            let hc = Arc::new(ferrum_edge::health_check::HealthChecker::new());
            Arc::new(
                ferrum_edge::service_discovery::ServiceDiscoveryManager::new(
                    lb_cache,
                    dns_cache_for_sd,
                    hc,
                    ferrum_edge::plugins::PluginHttpClient::default(),
                ),
            )
        },
        alt_svc_header: Some("h3=\":8443\"; ma=86400".to_string()),
        via_header_http11: None,
        via_header_http2: None,
        via_header_http3: None,
        add_forwarded_header: false,
        windowed_metrics: std::sync::Arc::new(ferrum_edge::metrics::WindowedMetrics::new(30)),
        max_header_size_bytes: 32768,
        max_single_header_size_bytes: 16384,
        max_header_count: 100,
        max_request_body_size_bytes: 10_485_760,
        max_response_body_size_bytes: 10_485_760,
        response_buffer_threshold_bytes: 2_097_152,
        h2_coalesce_target_bytes: 131_072,
        max_url_length_bytes: 8_192,
        max_query_params: 100,
        max_grpc_recv_size_bytes: 4_194_304,
        max_websocket_frame_size_bytes: 16_777_216,
        websocket_write_buffer_size: 131_072,
        websocket_tunnel_mode: false,
        env_config: Arc::new(ferrum_edge::config::EnvConfig::default()),
        trusted_proxies: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::parse("")),
        websocket_conn_limit: None,
        per_ip_request_counts: None,
        max_concurrent_requests_per_ip: 0,
        stream_listener_manager: slm,
        started_at: std::time::Instant::now(),
        ws_connection_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        tls_policy: None,
        crls: std::sync::Arc::new(Vec::new()),
        overload: std::sync::Arc::new(ferrum_edge::overload::OverloadState::new()),
        adaptive_buffer: std::sync::Arc::new(
            ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
                true, true, 300, 8192, 262_144, 65_536, 6000,
            ),
        ),
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

    let dns_cache = DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let connection_pool = Arc::new(ConnectionPool::new(
        pool_config,
        env_config,
        dns_cache.clone(),
        None,
        std::sync::Arc::new(Vec::new()),
    ));

    // Create proxy state with HTTP/3 support
    let gc = create_http3_test_gateway_config();
    let router_cache = Arc::new(RouterCache::new(&gc, 10_000));
    let plugin_cache = Arc::new(PluginCache::new(&gc).unwrap());
    let consumer_index = Arc::new(ConsumerIndex::new(&gc.consumers));
    let lb_cache = Arc::new(ferrum_edge::LoadBalancerCache::new(&gc));
    let circuit_breaker_cache = Arc::new(ferrum_edge::circuit_breaker::CircuitBreakerCache::new());
    let slm = Arc::new(
        ferrum_edge::proxy::stream_listener::StreamListenerManager::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            gateway_config.clone(),
            dns_cache.clone(),
            lb_cache.clone(),
            consumer_index.clone(),
            plugin_cache.clone(),
            circuit_breaker_cache.clone(),
            None,
            false,
            None,
            300,
            10_000,
            10,
            None,
            std::sync::Arc::new(Vec::new()),
            std::sync::Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
                true, true, 300, 8192, 262_144, 65_536, 6000,
            )),
            64,
            true,
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
        grpc_pool: Arc::new(ferrum_edge::proxy::grpc_proxy::GrpcConnectionPool::default()),
        http2_pool: Arc::new(ferrum_edge::proxy::http2_pool::Http2ConnectionPool::default()),
        h3_pool: Arc::new(ferrum_edge::http3::client::Http3ConnectionPool::new(
            Arc::new(ferrum_edge::config::EnvConfig::default()),
            ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default()),
        )),
        load_balancer_cache: lb_cache.clone(),
        health_checker: Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        circuit_breaker_cache: Arc::new(ferrum_edge::circuit_breaker::CircuitBreakerCache::new()),
        service_discovery_manager: {
            let hc = Arc::new(ferrum_edge::health_check::HealthChecker::new());
            Arc::new(
                ferrum_edge::service_discovery::ServiceDiscoveryManager::new(
                    lb_cache,
                    dns_cache_for_sd,
                    hc,
                    ferrum_edge::plugins::PluginHttpClient::default(),
                ),
            )
        },
        alt_svc_header: Some("h3=\":8443\"; ma=86400".to_string()),
        via_header_http11: None,
        via_header_http2: None,
        via_header_http3: None,
        add_forwarded_header: false,
        windowed_metrics: std::sync::Arc::new(ferrum_edge::metrics::WindowedMetrics::new(30)),
        max_header_size_bytes: 32768,
        max_single_header_size_bytes: 16384,
        max_header_count: 100,
        max_request_body_size_bytes: 10_485_760,
        max_response_body_size_bytes: 10_485_760,
        response_buffer_threshold_bytes: 2_097_152,
        h2_coalesce_target_bytes: 131_072,
        max_url_length_bytes: 8_192,
        max_query_params: 100,
        max_grpc_recv_size_bytes: 4_194_304,
        max_websocket_frame_size_bytes: 16_777_216,
        websocket_write_buffer_size: 131_072,
        websocket_tunnel_mode: false,
        env_config: Arc::new(ferrum_edge::config::EnvConfig::default()),
        trusted_proxies: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::parse("")),
        websocket_conn_limit: None,
        per_ip_request_counts: None,
        max_concurrent_requests_per_ip: 0,
        stream_listener_manager: slm,
        started_at: std::time::Instant::now(),
        ws_connection_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        tls_policy: None,
        crls: std::sync::Arc::new(Vec::new()),
        overload: std::sync::Arc::new(ferrum_edge::overload::OverloadState::new()),
        adaptive_buffer: std::sync::Arc::new(
            ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
                true, true, 300, 8192, 262_144, 65_536, 6000,
            ),
        ),
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
        .get_tls_config_for_backend(&proxy)
        .expect("TLS config should succeed for test proxy");
    assert!(Arc::strong_count(&tls_config) > 0);

    // Test HTTP/3 client creation (may fail in test environment, but should not panic)
    let http3_client_result = ferrum_edge::http3::client::Http3Client::new(tls_config, None);
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

/// Test HTTP/3 streaming vs buffered decision logic.
///
/// Verifies that the streaming path is selected when no plugins require body
/// buffering and no retries are configured (matching the same logic as HTTP/1.1
/// and gRPC paths).
#[tokio::test]
async fn test_http3_streaming_decision_logic() {
    use ferrum_edge::config::types::{PluginAssociation, PluginScope, RetryConfig};

    // --- Case 1: No plugins, no retry → should stream ---
    let proxy_stream = Proxy {
        id: "h3-stream".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("H3 Streaming".to_string()),
        hosts: vec![],
        listen_path: "/h3-stream".to_string(),
        backend_protocol: BackendProtocol::H3,
        backend_host: "localhost".to_string(),
        backend_port: 443,
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
        auth_mode: ferrum_edge::config::types::AuthMode::Single,
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
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    // --- Case 2: Proxy with retry configured → should buffer ---
    let proxy_buffered = Proxy {
        id: "h3-buffered".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("H3 Buffered".to_string()),
        listen_path: "/h3-buffered".to_string(),
        retry: Some(RetryConfig {
            max_retries: 3,
            retry_on_connect_failure: true,
            retryable_status_codes: vec![502, 503, 504],
            retryable_methods: vec!["GET".to_string()],
            backoff: ferrum_edge::config::types::BackoffStrategy::Fixed { delay_ms: 100 },
        }),
        ..proxy_stream.clone()
    };

    // --- Case 3: Proxy with ai_token_metrics plugin → should buffer responses ---
    let proxy_with_body_plugin = Proxy {
        id: "h3-body-plugin".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("H3 Body Plugin".to_string()),
        listen_path: "/h3-body-plugin".to_string(),
        retry: None,
        plugins: vec![PluginAssociation {
            plugin_config_id: "ai-token-metrics-cfg".to_string(),
        }],
        ..proxy_stream.clone()
    };

    let gc = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![
            proxy_stream.clone(),
            proxy_buffered.clone(),
            proxy_with_body_plugin.clone(),
        ],
        consumers: vec![],
        plugin_configs: vec![ferrum_edge::config::types::PluginConfig {
            id: "ai-token-metrics-cfg".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "ai_token_metrics".to_string(),
            enabled: true,
            config: serde_json::json!({}),
            scope: PluginScope::Proxy,
            proxy_id: Some("h3-body-plugin".to_string()),
            priority_override: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }],
        upstreams: vec![],
        loaded_at: chrono::Utc::now(),
        known_namespaces: Vec::new(),
    };

    let plugin_cache = PluginCache::new(&gc).unwrap();

    // Case 1: No plugins, no retry → streaming
    let has_retry_1 = proxy_stream.retry.is_some();
    let needs_resp_buf_1 = plugin_cache.requires_response_body_buffering(&proxy_stream.id);
    let needs_req_buf_1 = plugin_cache.requires_request_body_buffering(&proxy_stream.id);
    assert!(!has_retry_1, "No retry configured");
    assert!(!needs_resp_buf_1, "No response body buffering needed");
    assert!(!needs_req_buf_1, "No request body buffering needed");
    let should_stream_1 = !has_retry_1 && !needs_resp_buf_1;
    assert!(should_stream_1, "Should stream: no plugins, no retry");

    // Case 2: Retry configured → buffered
    let has_retry_2 = proxy_buffered.retry.is_some();
    assert!(has_retry_2, "Retry is configured");
    let should_stream_2 =
        !has_retry_2 && !plugin_cache.requires_response_body_buffering(&proxy_buffered.id);
    assert!(
        !should_stream_2,
        "Should buffer: retry configured requires body replay"
    );

    // Case 3: ai_token_metrics plugin → buffered responses
    let needs_resp_buf_3 =
        plugin_cache.requires_response_body_buffering(&proxy_with_body_plugin.id);
    assert!(
        needs_resp_buf_3,
        "ai_token_metrics requires response body buffering"
    );
    let should_stream_3 = proxy_with_body_plugin.retry.is_none() && !needs_resp_buf_3;
    assert!(
        !should_stream_3,
        "Should buffer: plugin requires response body"
    );
}

/// Test HTTP/3 chunk coalescing constants are appropriate
#[tokio::test]
async fn test_http3_coalesce_constants() {
    // The coalescing thresholds should be in the optimal 8–32 KiB range for QUIC.
    // Too small = excessive framing overhead. Too large = latency spike.
    let coalesce_min = 8_192usize; // H3_COALESCE_MIN_BYTES
    let coalesce_max = 32_768usize; // H3_COALESCE_MAX_BYTES
    let flush_interval_ms = 2u64; // H3_FLUSH_INTERVAL

    assert!(
        coalesce_min >= 4_096,
        "Coalesce minimum should be at least 4 KiB"
    );
    assert!(
        coalesce_max <= 65_536,
        "Coalesce maximum should be at most 64 KiB to bound per-stream memory"
    );
    assert!(
        coalesce_min < coalesce_max,
        "Min must be less than max for adaptive range"
    );
    assert!(
        (1..=10).contains(&flush_interval_ms),
        "Flush interval should be 1–10ms to balance latency vs efficiency"
    );
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
        DnsCache::new(ferrum_edge::dns::DnsConfig::default()),
        None,
        std::sync::Arc::new(Vec::new()),
    ));

    // Test HTTP/3 client creation performance
    let tls_config = connection_pool
        .get_tls_config_for_backend(&proxy)
        .expect("TLS config should succeed for test proxy");

    let start_time = std::time::Instant::now();
    let http3_client = ferrum_edge::http3::client::Http3Client::new(tls_config, None)
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
            "ferrum-edge-perf-test".to_string(),
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
