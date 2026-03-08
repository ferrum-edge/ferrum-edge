//! Common test utilities for plugin tests

use ferrum_gateway::config::types::{AuthMode, BackendProtocol, Consumer, Proxy};
use ferrum_gateway::plugins::{RequestContext, PluginResult};
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;

/// Create a test consumer with all credential types
pub fn create_test_consumer() -> Consumer {
    Consumer {
        id: "test-consumer".to_string(),
        username: "testuser".to_string(),
        custom_id: Some("custom-123".to_string()),
        credentials: {
            let mut creds = HashMap::new();
            creds.insert("keyauth".to_string(), json!({"key": "test-api-key"}));
            creds.insert("basicauth".to_string(), json!({"password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBdXwtGtrmuPq6"}));
            creds.insert("jwt".to_string(), json!({"secret": "test-jwt-secret"}));
            creds
        },
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Create a test request context with common headers
pub fn create_test_context() -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/test".to_string());
    ctx.headers.insert("Authorization".to_string(), "Bearer test-token".to_string());
    ctx.headers.insert("X-API-Key".to_string(), "test-api-key".to_string());
    ctx.headers.insert("User-Agent".to_string(), "test-agent".to_string());
    ctx
}

/// Create a test proxy with default configuration
pub fn create_test_proxy() -> Proxy {
    Proxy {
        id: "test-proxy".to_string(),
        name: Some("Test Proxy".to_string()),
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Create a test transaction summary for logging plugins
pub fn create_test_transaction_summary() -> ferrum_gateway::plugins::TransactionSummary {
    ferrum_gateway::plugins::TransactionSummary {
        timestamp_received: Utc::now().to_rfc3339(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: Some("testuser".to_string()),
        http_method: "GET".to_string(),
        request_path: "/test".to_string(),
        matched_proxy_id: Some("test-proxy".to_string()),
        matched_proxy_name: Some("Test Proxy".to_string()),
        backend_target_url: Some("http://localhost:3000/test".to_string()),
        response_status_code: 200,
        latency_total_ms: 100.0,
        latency_gateway_processing_ms: 10.0,
        latency_backend_ttfb_ms: 80.0,
        latency_backend_total_ms: 90.0,
        request_user_agent: Some("test-agent".to_string()),
        metadata: HashMap::new(),
    }
}

/// Assert that a plugin result is Continue
pub fn assert_continue(result: PluginResult) {
    assert!(matches!(result, PluginResult::Continue), "Expected Continue, got {:?}", result);
}

/// Assert that a plugin result is Reject with optional status code check
pub fn assert_reject(result: PluginResult, expected_status: Option<u16>) {
    match result {
        PluginResult::Reject { status_code, .. } => {
            if let Some(expected) = expected_status {
                assert_eq!(status_code, expected, "Expected status {}, got {}", expected, status_code);
            }
        }
        PluginResult::Continue => {
            panic!("Expected Reject, got Continue");
        }
    }
}
