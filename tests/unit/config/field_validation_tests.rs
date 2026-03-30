use chrono::Utc;
use ferrum_edge::config::types::{
    ActiveHealthCheck, AuthMode, BackendProtocol, BackoffStrategy, CircuitBreakerConfig,
    ConsulConfig, Consumer, GatewayConfig, HealthCheckConfig, KubernetesConfig,
    LoadBalancerAlgorithm, MAX_BACKEND_HOST_LENGTH, MAX_BACKEND_PATH_LENGTH,
    MAX_CREDENTIAL_VALUE_LENGTH, MAX_CREDENTIALS_SIZE, MAX_FILE_PATH_LENGTH, MAX_HOSTS_PER_PROXY,
    MAX_HTTP2_MAX_FRAME_SIZE, MAX_HTTP3_CONNECTIONS_PER_BACKEND, MAX_LISTEN_PATH_LENGTH,
    MAX_NAME_LENGTH, MAX_PLUGIN_CONFIG_SIZE, MAX_SD_STRING_LENGTH, MAX_TARGETS_PER_UPSTREAM,
    MAX_TIMEOUT_MS, MAX_USERNAME_LENGTH, MIN_HTTP2_MAX_FRAME_SIZE, MIN_HTTP2_WINDOW_SIZE,
    PassiveHealthCheck, PluginConfig, PluginScope, Proxy, RetryConfig, SdProvider,
    ServiceDiscoveryConfig, Upstream, UpstreamTarget,
};
use std::collections::HashMap;

/// Helper to create a minimal valid proxy.
fn make_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.into(),
        name: None,
        hosts: vec![],
        listen_path: listen_path.into(),
        backend_protocol: BackendProtocol::Http,
        backend_host: "localhost".into(),
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
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_tcp_keepalive_seconds: None,
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        udp_idle_timeout_seconds: 60,
        allowed_methods: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        id: id.into(),
        username: username.into(),
        custom_id: None,
        credentials: HashMap::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_upstream(id: &str) -> Upstream {
    Upstream {
        id: id.into(),
        name: None,
        targets: vec![UpstreamTarget {
            host: "localhost".into(),
            port: 3000,
            weight: 1,
            tags: HashMap::new(),
            path: None,
        }],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_plugin_config(id: &str) -> PluginConfig {
    PluginConfig {
        id: id.into(),
        plugin_name: "cors".into(),
        config: serde_json::json!({}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// ---- Proxy field validation tests ----

#[test]
fn test_proxy_valid_fields_passes() {
    let proxy = make_proxy("test", "/api");
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_name_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.name = Some("a".repeat(MAX_NAME_LENGTH + 1));
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("name") && e.contains("exceed"))
    );
}

#[test]
fn test_proxy_backend_host_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_host = "a".repeat(MAX_BACKEND_HOST_LENGTH + 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_host") && e.contains("exceed"))
    );
}

#[test]
fn test_proxy_backend_host_contains_scheme() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_host = "http://example.com".into();
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("scheme")));
}

#[test]
fn test_proxy_backend_path_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_path = Some("a".repeat(MAX_BACKEND_PATH_LENGTH + 1));
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_path") && e.contains("exceed"))
    );
}

#[test]
fn test_proxy_listen_path_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.listen_path = format!("/{}", "a".repeat(MAX_LISTEN_PATH_LENGTH));
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("listen_path") && e.contains("exceed"))
    );
}

#[test]
fn test_proxy_listen_path_control_chars() {
    let mut proxy = make_proxy("test", "/api");
    proxy.listen_path = "/api\x00test".into();
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("listen_path") && e.contains("control"))
    );
}

#[test]
fn test_proxy_backend_host_control_chars() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_host = "localhost\x00evil".into();
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_host") && e.contains("control"))
    );
}

#[test]
fn test_proxy_too_many_hosts() {
    let mut proxy = make_proxy("test", "/api");
    proxy.hosts = (0..MAX_HOSTS_PER_PROXY + 1)
        .map(|i| format!("host{}.example.com", i))
        .collect();
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("hosts")));
}

#[test]
fn test_proxy_timeout_zero_rejected() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_connect_timeout_ms = 0;
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_connect_timeout_ms"))
    );
}

#[test]
fn test_proxy_timeout_too_large_rejected() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_read_timeout_ms = MAX_TIMEOUT_MS + 1;
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("backend_read_timeout_ms")));
}

#[test]
fn test_proxy_pool_timeout_validated() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_idle_timeout_seconds = Some(0);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("pool_idle_timeout_seconds")));
}

#[test]
fn test_proxy_circuit_breaker_validated() {
    let mut proxy = make_proxy("test", "/api");
    proxy.circuit_breaker = Some(CircuitBreakerConfig {
        failure_threshold: 0, // Invalid: must be >= 1
        success_threshold: 3,
        timeout_seconds: 30,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
    });
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("circuit_breaker.failure_threshold"))
    );
}

#[test]
fn test_proxy_retry_validated() {
    let mut proxy = make_proxy("test", "/api");
    proxy.retry = Some(RetryConfig {
        max_retries: 200, // Invalid: exceeds MAX_RETRIES (100)
        retryable_status_codes: vec![502],
        retryable_methods: vec!["GET".into()],
        backoff: BackoffStrategy::Fixed { delay_ms: 100 },
        retry_on_connect_failure: true,
    });
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("retry.max_retries")));
}

#[test]
fn test_proxy_retry_backoff_base_exceeds_max() {
    let mut proxy = make_proxy("test", "/api");
    proxy.retry = Some(RetryConfig {
        max_retries: 3,
        retryable_status_codes: vec![502],
        retryable_methods: vec!["GET".into()],
        backoff: BackoffStrategy::Exponential {
            base_ms: 5000,
            max_ms: 1000, // Invalid: base > max
        },
        retry_on_connect_failure: true,
    });
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("base_ms") && e.contains("must not exceed"))
    );
}

#[test]
fn test_proxy_circuit_breaker_invalid_status_codes() {
    let mut proxy = make_proxy("test", "/api");
    proxy.circuit_breaker = Some(CircuitBreakerConfig {
        failure_threshold: 5,
        success_threshold: 3,
        timeout_seconds: 30,
        failure_status_codes: vec![999], // Invalid HTTP status code
        half_open_max_requests: 1,
    });
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("failure_status_codes") && e.contains("999"))
    );
}

// ---- Consumer field validation tests ----

#[test]
fn test_consumer_valid_fields_passes() {
    let consumer = make_consumer("test", "alice");
    assert!(consumer.validate_fields().is_ok());
}

#[test]
fn test_consumer_username_too_long() {
    let consumer = make_consumer("test", &"a".repeat(MAX_USERNAME_LENGTH + 1));
    let errs = consumer.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("username")));
}

#[test]
fn test_consumer_username_control_chars() {
    let consumer = make_consumer("test", "alice\x00evil");
    let errs = consumer.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("username") && e.contains("control"))
    );
}

#[test]
fn test_consumer_custom_id_too_long() {
    let mut consumer = make_consumer("test", "alice");
    consumer.custom_id = Some("a".repeat(256));
    let errs = consumer.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("custom_id")));
}

#[test]
fn test_consumer_credential_value_too_long() {
    let mut consumer = make_consumer("test", "alice");
    consumer.credentials.insert(
        "keyauth".into(),
        serde_json::json!({"key": "a".repeat(MAX_CREDENTIAL_VALUE_LENGTH + 1)}),
    );
    let errs = consumer.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("credentials.keyauth.key") && e.contains("exceed"))
    );
}

#[test]
fn test_consumer_credential_control_chars() {
    let mut consumer = make_consumer("test", "alice");
    consumer
        .credentials
        .insert("keyauth".into(), serde_json::json!({"key": "abc\x00def"}));
    let errs = consumer.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("credentials.keyauth.key") && e.contains("control"))
    );
}

#[test]
fn test_consumer_credentials_total_size_limit() {
    let mut consumer = make_consumer("test", "alice");
    // Create a single credential value that exceeds 64KB
    let big_value = "a".repeat(MAX_CREDENTIALS_SIZE + 1);
    consumer
        .credentials
        .insert("keyauth".into(), serde_json::json!({"key": big_value}));
    let errs = consumer.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("credentials JSON") && e.contains("exceed"))
    );
}

// ---- Upstream field validation tests ----

#[test]
fn test_upstream_valid_fields_passes() {
    let upstream = make_upstream("test");
    assert!(upstream.validate_fields().is_ok());
}

#[test]
fn test_upstream_name_too_long() {
    let mut upstream = make_upstream("test");
    upstream.name = Some("a".repeat(MAX_NAME_LENGTH + 1));
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("name") && e.contains("exceed"))
    );
}

#[test]
fn test_upstream_too_many_targets() {
    let mut upstream = make_upstream("test");
    upstream.targets = (0..MAX_TARGETS_PER_UPSTREAM + 1)
        .map(|i| UpstreamTarget {
            host: format!("host{}.example.com", i),
            port: 3000,
            weight: 1,
            tags: HashMap::new(),
            path: None,
        })
        .collect();
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("targets")));
}

#[test]
fn test_upstream_target_empty_host() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].host = "".into();
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("targets[0].host") && e.contains("empty"))
    );
}

#[test]
fn test_upstream_target_host_too_long() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].host = "a".repeat(MAX_BACKEND_HOST_LENGTH + 1);
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("targets[0].host") && e.contains("exceed"))
    );
}

#[test]
fn test_upstream_target_port_zero() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].port = 0;
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("targets[0].port")));
}

#[test]
fn test_upstream_target_weight_zero() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].weight = 0;
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("targets[0].weight")));
}

#[test]
fn test_upstream_target_weight_too_large() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].weight = 70000;
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("targets[0].weight")));
}

#[test]
fn test_upstream_target_path_too_long() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].path = Some("a".repeat(MAX_BACKEND_PATH_LENGTH + 1));
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("targets[0].path") && e.contains("exceed"))
    );
}

#[test]
fn test_upstream_target_path_control_chars() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].path = Some("/api\x00evil".into());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("targets[0].path") && e.contains("control"))
    );
}

#[test]
fn test_upstream_target_path_valid() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].path = Some("/api/v1/service".into());
    assert!(upstream.validate_fields().is_ok());
}

#[test]
fn test_upstream_health_check_validated() {
    let mut upstream = make_upstream("test");
    upstream.health_checks = Some(HealthCheckConfig {
        active: Some(ActiveHealthCheck {
            interval_seconds: 0, // Invalid: must be >= 1
            ..Default::default()
        }),
        passive: None,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("health_checks.active.interval_seconds"))
    );
}

#[test]
fn test_upstream_passive_health_check_validated() {
    let mut upstream = make_upstream("test");
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            unhealthy_threshold: 0, // Invalid: must be >= 1
            ..Default::default()
        }),
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("health_checks.passive.unhealthy_threshold"))
    );
}

#[test]
fn test_upstream_service_discovery_dns_sd_validated() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: ferrum_edge::config::types::SdProvider::DnsSd,
        dns_sd: None, // Missing required config
        kubernetes: None,
        consul: None,
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("dns_sd config is required")));
}

// ---- PluginConfig field validation tests ----

#[test]
fn test_plugin_config_valid_fields_passes() {
    let pc = make_plugin_config("test");
    assert!(pc.validate_fields().is_ok());
}

#[test]
fn test_plugin_config_json_too_large() {
    let mut pc = make_plugin_config("test");
    // Create a large JSON config
    let big_value = "a".repeat(MAX_PLUGIN_CONFIG_SIZE);
    pc.config = serde_json::json!({"data": big_value});
    let errs = pc.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("config JSON") && e.contains("exceed"))
    );
}

#[test]
fn test_plugin_config_deeply_nested_json() {
    let mut pc = make_plugin_config("test");
    // Build a deeply nested JSON value (depth > 10)
    let mut val = serde_json::json!("leaf");
    for _ in 0..15 {
        val = serde_json::json!({"nested": val});
    }
    pc.config = val;
    let errs = pc.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("nesting depth")));
}

// ---- GatewayConfig.validate_all_fields() tests ----

#[test]
fn test_validate_all_fields_catches_proxy_errors() {
    let config = GatewayConfig {
        proxies: vec![{
            let mut p = make_proxy("test", "/api");
            p.backend_connect_timeout_ms = 0; // Invalid
            p
        }],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        ..Default::default()
    };
    let errs = config.validate_all_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("Proxy 'test'") && e.contains("backend_connect_timeout_ms"))
    );
}

#[test]
fn test_validate_all_fields_catches_consumer_errors() {
    let config = GatewayConfig {
        proxies: vec![],
        consumers: vec![make_consumer("test", &"a".repeat(MAX_USERNAME_LENGTH + 1))],
        plugin_configs: vec![],
        upstreams: vec![],
        ..Default::default()
    };
    let errs = config.validate_all_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("Consumer 'test'") && e.contains("username"))
    );
}

#[test]
fn test_validate_all_fields_catches_upstream_errors() {
    let config = GatewayConfig {
        proxies: vec![],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![{
            let mut u = make_upstream("test");
            u.targets[0].port = 0; // Invalid
            u
        }],
        ..Default::default()
    };
    let errs = config.validate_all_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("Upstream 'test'") && e.contains("targets[0].port"))
    );
}

#[test]
fn test_validate_all_fields_valid_config_passes() {
    let config = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api")],
        consumers: vec![make_consumer("c1", "alice")],
        plugin_configs: vec![make_plugin_config("pc1")],
        upstreams: vec![make_upstream("u1")],
        ..Default::default()
    };
    assert!(config.validate_all_fields().is_ok());
}

// ---- CircuitBreakerConfig validation tests ----

#[test]
fn test_circuit_breaker_valid() {
    let cb = CircuitBreakerConfig::default();
    assert!(cb.validate_fields().is_ok());
}

#[test]
fn test_circuit_breaker_timeout_zero() {
    let cb = CircuitBreakerConfig {
        timeout_seconds: 0,
        ..Default::default()
    };
    let errs = cb.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("timeout_seconds")));
}

// ---- RetryConfig validation tests ----

#[test]
fn test_retry_config_valid() {
    let retry = RetryConfig::default();
    assert!(retry.validate_fields().is_ok());
}

#[test]
fn test_retry_backoff_too_large() {
    let retry = RetryConfig {
        max_retries: 3,
        retryable_status_codes: vec![502],
        retryable_methods: vec!["GET".into()],
        backoff: BackoffStrategy::Fixed { delay_ms: 999_999 },
        retry_on_connect_failure: true,
    };
    let errs = retry.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("delay_ms")));
}

// ---- HTTP/2 flow control validation tests ----

#[test]
fn test_proxy_http2_stream_window_too_small() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_initial_stream_window_size = Some(MIN_HTTP2_WINDOW_SIZE - 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("pool_http2_initial_stream_window_size"))
    );
}

#[test]
fn test_proxy_http2_stream_window_valid_min() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_initial_stream_window_size = Some(MIN_HTTP2_WINDOW_SIZE);
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_http2_connection_window_too_small() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_initial_connection_window_size = Some(1000);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("pool_http2_initial_connection_window_size"))
    );
}

#[test]
fn test_proxy_http2_max_frame_size_too_small() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_max_frame_size = Some(MIN_HTTP2_MAX_FRAME_SIZE - 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("pool_http2_max_frame_size")));
}

#[test]
fn test_proxy_http2_max_frame_size_too_large() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_max_frame_size = Some(MAX_HTTP2_MAX_FRAME_SIZE + 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("pool_http2_max_frame_size")));
}

#[test]
fn test_proxy_http2_max_frame_size_valid_range() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_max_frame_size = Some(MIN_HTTP2_MAX_FRAME_SIZE);
    assert!(proxy.validate_fields().is_ok());
    proxy.pool_http2_max_frame_size = Some(MAX_HTTP2_MAX_FRAME_SIZE);
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_http2_max_concurrent_streams_zero() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_max_concurrent_streams = Some(0);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("pool_http2_max_concurrent_streams"))
    );
}

#[test]
fn test_proxy_http2_max_concurrent_streams_valid() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_max_concurrent_streams = Some(1000);
    assert!(proxy.validate_fields().is_ok());
}

// ---- HTTP/3 connections per backend tests ----

#[test]
fn test_proxy_http3_connections_zero() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http3_connections_per_backend = Some(0);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("pool_http3_connections_per_backend"))
    );
}

#[test]
fn test_proxy_http3_connections_too_large() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http3_connections_per_backend = Some(MAX_HTTP3_CONNECTIONS_PER_BACKEND + 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("pool_http3_connections_per_backend"))
    );
}

#[test]
fn test_proxy_http3_connections_valid() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http3_connections_per_backend = Some(4);
    assert!(proxy.validate_fields().is_ok());
}

// ---- TLS file path validation tests ----

#[test]
fn test_proxy_tls_cert_path_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_client_cert_path = Some("a".repeat(MAX_FILE_PATH_LENGTH + 1));
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_cert_path"))
    );
}

#[test]
fn test_proxy_tls_key_path_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_client_key_path = Some("a".repeat(MAX_FILE_PATH_LENGTH + 1));
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_key_path"))
    );
}

#[test]
fn test_proxy_tls_ca_path_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_server_ca_cert_path = Some("a".repeat(MAX_FILE_PATH_LENGTH + 1));
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_server_ca_cert_path"))
    );
}

#[test]
fn test_proxy_tls_paths_control_chars() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_client_cert_path = Some("/certs/\x00evil.pem".into());
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_cert_path") && e.contains("control"))
    );
}

// ---- Allowed methods validation tests ----

#[test]
fn test_proxy_allowed_methods_invalid() {
    let mut proxy = make_proxy("test", "/api");
    proxy.allowed_methods = Some(vec!["GET".into(), "GETT".into()]);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("allowed_methods") && e.contains("GETT"))
    );
}

#[test]
fn test_proxy_allowed_methods_valid() {
    let mut proxy = make_proxy("test", "/api");
    proxy.allowed_methods = Some(vec!["GET".into(), "POST".into(), "put".into()]);
    assert!(proxy.validate_fields().is_ok());
}

// ---- Retryable methods validation tests ----

#[test]
fn test_retry_invalid_method_name() {
    let retry = RetryConfig {
        max_retries: 3,
        retryable_status_codes: vec![502],
        retryable_methods: vec!["GET".into(), "FAKE".into()],
        backoff: BackoffStrategy::Fixed { delay_ms: 100 },
        retry_on_connect_failure: true,
    };
    let errs = retry.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("retryable_methods") && e.contains("FAKE"))
    );
}

#[test]
fn test_retry_valid_methods() {
    let retry = RetryConfig {
        max_retries: 3,
        retryable_status_codes: vec![502],
        retryable_methods: vec!["GET".into(), "post".into(), "HEAD".into()],
        backoff: BackoffStrategy::Fixed { delay_ms: 100 },
        retry_on_connect_failure: true,
    };
    assert!(retry.validate_fields().is_ok());
}

// ---- Service discovery optional field validation tests ----

#[test]
fn test_k8s_port_name_too_long() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Kubernetes,
        dns_sd: None,
        kubernetes: Some(KubernetesConfig {
            namespace: "default".into(),
            service_name: "my-svc".into(),
            port_name: Some("a".repeat(MAX_SD_STRING_LENGTH + 1)),
            label_selector: None,
            poll_interval_seconds: 30,
        }),
        consul: None,
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("kubernetes.port_name") && e.contains("exceed"))
    );
}

#[test]
fn test_k8s_label_selector_too_long() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Kubernetes,
        dns_sd: None,
        kubernetes: Some(KubernetesConfig {
            namespace: "default".into(),
            service_name: "my-svc".into(),
            port_name: None,
            label_selector: Some("a".repeat(1025)),
            poll_interval_seconds: 30,
        }),
        consul: None,
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("kubernetes.label_selector") && e.contains("exceed"))
    );
}

#[test]
fn test_consul_datacenter_too_long() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Consul,
        dns_sd: None,
        kubernetes: None,
        consul: Some(ConsulConfig {
            address: "http://consul:8500".into(),
            service_name: "my-svc".into(),
            datacenter: Some("a".repeat(MAX_SD_STRING_LENGTH + 1)),
            tag: None,
            healthy_only: true,
            token: None,
            poll_interval_seconds: 30,
        }),
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("consul.datacenter") && e.contains("exceed"))
    );
}

#[test]
fn test_consul_tag_too_long() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Consul,
        dns_sd: None,
        kubernetes: None,
        consul: Some(ConsulConfig {
            address: "http://consul:8500".into(),
            service_name: "my-svc".into(),
            datacenter: None,
            tag: Some("a".repeat(MAX_SD_STRING_LENGTH + 1)),
            healthy_only: true,
            token: None,
            poll_interval_seconds: 30,
        }),
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("consul.tag") && e.contains("exceed"))
    );
}

#[test]
fn test_consul_token_control_chars() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Consul,
        dns_sd: None,
        kubernetes: None,
        consul: Some(ConsulConfig {
            address: "http://consul:8500".into(),
            service_name: "my-svc".into(),
            datacenter: None,
            tag: None,
            healthy_only: true,
            token: Some("secret\x00token".into()),
            poll_interval_seconds: 30,
        }),
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("consul.token") && e.contains("control"))
    );
}

#[test]
fn test_consul_valid_optional_fields() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Consul,
        dns_sd: None,
        kubernetes: None,
        consul: Some(ConsulConfig {
            address: "http://consul:8500".into(),
            service_name: "my-svc".into(),
            datacenter: Some("us-east-1".into()),
            tag: Some("production".into()),
            healthy_only: true,
            token: Some("my-acl-token-abc123".into()),
            poll_interval_seconds: 30,
        }),
        default_weight: 1,
    });
    assert!(upstream.validate_fields().is_ok());
}

#[test]
fn test_k8s_valid_optional_fields() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Kubernetes,
        dns_sd: None,
        kubernetes: Some(KubernetesConfig {
            namespace: "production".into(),
            service_name: "my-svc".into(),
            port_name: Some("http".into()),
            label_selector: Some("app=my-svc,env=prod".into()),
            poll_interval_seconds: 30,
        }),
        consul: None,
        default_weight: 1,
    });
    assert!(upstream.validate_fields().is_ok());
}

// ─── hash_on format validation tests ────────────────────────────────────────

#[test]
fn test_upstream_hash_on_valid_formats() {
    for hash_on in &["ip", "header:x-user-id", "cookie:session"] {
        let mut upstream = make_upstream("u1");
        upstream.hash_on = Some(hash_on.to_string());
        assert!(
            upstream.validate_fields().is_ok(),
            "hash_on '{}' should be valid",
            hash_on
        );
    }
}

#[test]
fn test_upstream_hash_on_invalid_format() {
    let mut upstream = make_upstream("u1");
    upstream.hash_on = Some("random_string".to_string());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("hash_on must be")));
}

#[test]
fn test_upstream_hash_on_empty_header_name() {
    let mut upstream = make_upstream("u1");
    upstream.hash_on = Some("header:".to_string());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("non-empty header name")));
}

#[test]
fn test_upstream_hash_on_empty_cookie_name() {
    let mut upstream = make_upstream("u1");
    upstream.hash_on = Some("cookie:".to_string());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("non-empty cookie name")));
}

#[test]
fn test_upstream_hash_on_cookie_config_validation() {
    use ferrum_edge::config::types::HashOnCookieConfig;

    let mut upstream = make_upstream("u1");
    upstream.hash_on = Some("cookie:session".to_string());
    upstream.hash_on_cookie_config = Some(HashOnCookieConfig {
        path: "/".to_string(),
        ttl_seconds: 3600,
        domain: None,
        http_only: true,
        secure: false,
        same_site: Some("Invalid".to_string()),
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("same_site must be 'Strict', 'Lax', or 'None'"))
    );
}

#[test]
fn test_upstream_hash_on_cookie_config_valid() {
    use ferrum_edge::config::types::HashOnCookieConfig;

    let mut upstream = make_upstream("u1");
    upstream.hash_on = Some("cookie:session".to_string());
    upstream.hash_on_cookie_config = Some(HashOnCookieConfig {
        path: "/api".to_string(),
        ttl_seconds: 7200,
        domain: Some("example.com".to_string()),
        http_only: true,
        secure: true,
        same_site: Some("Lax".to_string()),
    });
    assert!(upstream.validate_fields().is_ok());
}
