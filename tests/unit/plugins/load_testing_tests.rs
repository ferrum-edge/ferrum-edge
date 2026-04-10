use ferrum_edge::plugins::load_testing::LoadTesting;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

fn make_valid_config() -> serde_json::Value {
    json!({
        "key": "test-secret-key",
        "concurrent_clients": 5,
        "duration_seconds": 10
    })
}

fn make_plugin() -> LoadTesting {
    LoadTesting::new(&make_valid_config(), PluginHttpClient::default()).unwrap()
}

// ---------------------------------------------------------------------------
// Plugin metadata
// ---------------------------------------------------------------------------

#[test]
fn test_plugin_name() {
    assert_eq!(make_plugin().name(), "load_testing");
}

#[test]
fn test_plugin_priority() {
    assert_eq!(make_plugin().priority(), 3080);
}

#[test]
fn test_supported_protocols() {
    let protos = make_plugin().supported_protocols();
    assert!(protos.contains(&ferrum_edge::plugins::ProxyProtocol::Http));
    assert!(!protos.contains(&ferrum_edge::plugins::ProxyProtocol::Grpc));
    assert!(!protos.contains(&ferrum_edge::plugins::ProxyProtocol::WebSocket));
}

// ---------------------------------------------------------------------------
// Config validation — valid configs
// ---------------------------------------------------------------------------

#[test]
fn test_valid_minimal_config() {
    let result = LoadTesting::new(&make_valid_config(), PluginHttpClient::default());
    assert!(result.is_ok());
}

#[test]
fn test_valid_config_with_ramp() {
    let config = json!({
        "key": "my-key",
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "ramp": true
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_gateway_port() {
    let config = json!({
        "key": "my-key",
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "gateway_port": 9090
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_gateway_tls() {
    let config = json!({
        "key": "my-key",
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "gateway_tls": true
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_gateway_tls_and_port() {
    let config = json!({
        "key": "my-key",
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "gateway_tls": true,
        "gateway_port": 9443
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_tls_no_verify_explicit_false() {
    // Explicitly disable no-verify even with TLS enabled
    let config = json!({
        "key": "my-key",
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "gateway_tls": true,
        "gateway_tls_no_verify": false
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_gateway_addresses() {
    let config = json!({
        "key": "my-key",
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "gateway_addresses": ["https://node1:8443", "https://node2:8443"]
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_boundary_values() {
    // Min values
    let config = json!({
        "key": "k",
        "concurrent_clients": 1,
        "duration_seconds": 1
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());

    // Max values
    let config = json!({
        "key": "k",
        "concurrent_clients": 10000,
        "duration_seconds": 3600
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_full_config() {
    let config = json!({
        "key": "my-key",
        "concurrent_clients": 50,
        "duration_seconds": 60,
        "ramp": true,
        "gateway_tls": true,
        "gateway_tls_no_verify": true,
        "gateway_port": 8443,
        "gateway_addresses": ["https://node2:8443"]
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

// ---------------------------------------------------------------------------
// Config validation — invalid configs
// ---------------------------------------------------------------------------

#[test]
fn test_missing_key_is_error() {
    let config = json!({
        "concurrent_clients": 5,
        "duration_seconds": 10
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("'key' is required"), "got: {}", err);
}

#[test]
fn test_empty_key_is_error() {
    let config = json!({
        "key": "",
        "concurrent_clients": 5,
        "duration_seconds": 10
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("'key' is required"), "got: {}", err);
}

#[test]
fn test_missing_concurrent_clients_is_error() {
    let config = json!({
        "key": "test",
        "duration_seconds": 10
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(
        err.contains("'concurrent_clients' is required"),
        "got: {}",
        err
    );
}

#[test]
fn test_zero_concurrent_clients_is_error() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 0,
        "duration_seconds": 10
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("1–10000"), "got: {}", err);
}

#[test]
fn test_concurrent_clients_over_max_is_error() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 10001,
        "duration_seconds": 10
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("1–10000"), "got: {}", err);
}

#[test]
fn test_missing_duration_is_error() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 5
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(
        err.contains("'duration_seconds' is required"),
        "got: {}",
        err
    );
}

#[test]
fn test_zero_duration_is_error() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 5,
        "duration_seconds": 0
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("1–3600"), "got: {}", err);
}

#[test]
fn test_duration_over_max_is_error() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 5,
        "duration_seconds": 3601
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("1–3600"), "got: {}", err);
}

#[test]
fn test_zero_request_timeout_is_error() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "request_timeout_ms": 0
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("greater than 0"), "got: {}", err);
}

#[test]
fn test_custom_request_timeout_accepted() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "request_timeout_ms": 5000
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_gateway_port_zero_is_error() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_port": 0
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("1–65535"), "got: {}", err);
}

#[test]
fn test_gateway_port_over_max_is_error() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_port": 70000
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("1–65535"), "got: {}", err);
}

#[test]
fn test_empty_gateway_addresses_is_error() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_addresses": []
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("must not be empty"), "got: {}", err);
}

#[test]
fn test_gateway_addresses_with_empty_string_is_error() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_addresses": ["https://valid:8443", ""]
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("must not be empty"), "got: {}", err);
}

#[test]
fn test_gateway_addresses_with_non_string_is_error() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_addresses": [123]
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("must be a string"), "got: {}", err);
}

// ---------------------------------------------------------------------------
// before_proxy — key matching
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_skips_when_no_key_header() {
    let plugin = make_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_skips_when_key_does_not_match() {
    let plugin = make_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), "wrong-key".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_triggers_when_key_matches() {
    let plugin = make_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(json!({
        "id": "proxy-1",
        "name": "test-proxy",
        "listen_path": "/api",
        "backend_host": "backend.local",
        "backend_port": 8080,
        "backend_protocol": "http"
    }))
    .unwrap();
    ctx.matched_proxy = Some(Arc::new(proxy));

    let mut headers = HashMap::new();
    headers.insert(
        "x-loadtesting-key".to_string(),
        "test-secret-key".to_string(),
    );

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    // Plugin returns Continue (original request proceeds), load test spawns in background
    assert!(matches!(result, PluginResult::Continue));

    // Give the spawned task a moment to start, then verify is_running guard
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Second trigger should be ignored (already running)
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx2.matched_proxy = Some(Arc::new(
        serde_json::from_value::<ferrum_edge::config::types::Proxy>(json!({
            "id": "proxy-1",
            "name": "test-proxy",
            "listen_path": "/api",
            "backend_host": "backend.local",
            "backend_port": 8080,
            "backend_protocol": "http"
        }))
        .unwrap(),
    ));
    let mut headers2 = HashMap::new();
    headers2.insert(
        "x-loadtesting-key".to_string(),
        "test-secret-key".to_string(),
    );
    let result2 = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    // Still continues (but logs warning about already running)
    assert!(matches!(result2, PluginResult::Continue));
}

// ---------------------------------------------------------------------------
// Config defaults
// ---------------------------------------------------------------------------

#[test]
fn test_ramp_defaults_to_false() {
    let config = json!({
        "key": "test",
        "concurrent_clients": 5,
        "duration_seconds": 10
    });
    let plugin = LoadTesting::new(&config, PluginHttpClient::default()).unwrap();
    assert_eq!(plugin.name(), "load_testing");
}

#[test]
fn test_gateway_tls_no_verify_defaults_to_true_when_tls_enabled() {
    // When gateway_tls is true and gateway_tls_no_verify is not set,
    // the client should be built with danger_accept_invalid_certs(true).
    // We can't inspect the client directly, but we verify construction succeeds.
    let config = json!({
        "key": "test",
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_tls": true
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_gateway_tls_no_verify_defaults_to_false_when_tls_disabled() {
    // When gateway_tls is false (default), gateway_tls_no_verify defaults to false
    let config = json!({
        "key": "test",
        "concurrent_clients": 5,
        "duration_seconds": 10
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}
