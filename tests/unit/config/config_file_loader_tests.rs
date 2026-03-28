use ferrum_gateway::config::file_loader::{load_config_from_file, reload_config_from_file};
use ferrum_gateway::config::types::{AuthMode, BackendProtocol, PluginScope};
use std::io::Write;
use tempfile::NamedTempFile;

// ============================================================================
// Basic Loading Tests
// ============================================================================

#[test]
fn test_load_yaml_config() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3000
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();
    assert_eq!(config.proxies.len(), 1);
    assert_eq!(config.proxies[0].listen_path, "/api/v1");
}

#[test]
fn test_load_json_config() {
    let json = r#"{
  "proxies": [{
    "id": "proxy-1",
    "listen_path": "/api/v1",
    "backend_protocol": "http",
    "backend_host": "localhost",
    "backend_port": 3000
  }],
  "consumers": [],
  "plugin_configs": []
}"#;
    let mut file = NamedTempFile::with_suffix(".json").unwrap();
    write!(file, "{}", json).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();
    assert_eq!(config.proxies.len(), 1);
}

#[test]
fn test_duplicate_listen_path_rejected() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3000
  - id: "proxy-2"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3001
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let result = load_config_from_file(file.path().to_str().unwrap());
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("duplicate") || error_msg.contains("Duplicate"));
}

// ============================================================================
// Full Configuration with All Components
// ============================================================================

#[test]
fn test_load_full_config_yaml() {
    let yaml = r#"
proxies:
  - id: "proxy-httpbin"
    name: "HTTPBin Proxy"
    listen_path: "/httpbin"
    backend_protocol: https
    backend_host: "httpbin.org"
    backend_port: 443
    strip_listen_path: true
    preserve_host_header: false
    backend_connect_timeout_ms: 5000
    backend_read_timeout_ms: 30000
    backend_write_timeout_ms: 30000
    backend_tls_verify_server_cert: true
    pool_idle_timeout_seconds: 120
    pool_tcp_keepalive_seconds: 45
    pool_http2_keep_alive_interval_seconds: 20
    pool_http2_keep_alive_timeout_seconds: 30
    auth_mode: single
    plugins:
      - plugin_config_id: "plugin-stdout"

  - id: "proxy-multi-auth"
    listen_path: "/multi-auth"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3002
    auth_mode: multi
    plugins: []

consumers:
  - id: "consumer-alice"
    username: "alice"
    custom_id: "alice-001"
    credentials:
      keyauth:
        key: "alice-secret-api-key-12345"
      jwt:
        secret: "alice-jwt-secret-key"
      basicauth:
        password_hash: "$2b$12$LJ3m4ys3Lk0TSwHjOHRHOeUK/6Nh1GUz8QLXfYcR8x0e3kYzLhWS"

  - id: "consumer-bob"
    username: "bob"
    custom_id: "bob-002"
    credentials:
      keyauth:
        key: "bob-secret-api-key-67890"

plugin_configs:
  - id: "plugin-stdout"
    plugin_name: "stdout_logging"
    config: {}
    scope: global
    enabled: true

  - id: "plugin-keyauth"
    plugin_name: "key_auth"
    config:
      key_location: "header:X-API-Key"
    scope: proxy
    proxy_id: "proxy-protected"
    enabled: true
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();

    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    // Verify proxies
    assert_eq!(config.proxies.len(), 2);
    assert_eq!(config.proxies[0].id, "proxy-httpbin");
    assert_eq!(config.proxies[0].name, Some("HTTPBin Proxy".to_string()));
    assert_eq!(config.proxies[0].backend_protocol, BackendProtocol::Https);
    assert_eq!(config.proxies[0].backend_port, 443);
    assert!(config.proxies[0].strip_listen_path);
    assert!(!config.proxies[0].preserve_host_header);
    assert_eq!(config.proxies[0].backend_connect_timeout_ms, 5000);
    assert_eq!(config.proxies[0].auth_mode, AuthMode::Single);
    assert_eq!(config.proxies[0].pool_idle_timeout_seconds, Some(120));
    assert_eq!(config.proxies[0].pool_tcp_keepalive_seconds, Some(45));
    assert_eq!(config.proxies[1].auth_mode, AuthMode::Multi);

    // Verify consumers
    assert_eq!(config.consumers.len(), 2);
    assert_eq!(config.consumers[0].id, "consumer-alice");
    assert_eq!(config.consumers[0].username, "alice");
    assert_eq!(config.consumers[0].custom_id, Some("alice-001".to_string()));
    assert!(config.consumers[0].credentials.contains_key("keyauth"));
    assert!(config.consumers[0].credentials.contains_key("jwt"));
    assert!(config.consumers[0].credentials.contains_key("basicauth"));

    // Verify consumers have credentials
    assert_eq!(config.consumers[1].username, "bob");
    assert!(config.consumers[1].credentials.contains_key("keyauth"));

    // Verify plugin configs
    assert_eq!(config.plugin_configs.len(), 2);
    assert_eq!(config.plugin_configs[0].id, "plugin-stdout");
    assert_eq!(config.plugin_configs[0].plugin_name, "stdout_logging");
    assert_eq!(config.plugin_configs[0].scope, PluginScope::Global);
    assert!(config.plugin_configs[0].enabled);
    assert_eq!(config.plugin_configs[1].scope, PluginScope::Proxy);
    assert_eq!(
        config.plugin_configs[1].proxy_id,
        Some("proxy-protected".to_string())
    );
}

// ============================================================================
// Backend Protocol Tests
// ============================================================================

#[test]
fn test_all_backend_protocols() {
    let protocols = vec![
        ("http", BackendProtocol::Http),
        ("https", BackendProtocol::Https),
        ("ws", BackendProtocol::Ws),
        ("wss", BackendProtocol::Wss),
        ("grpc", BackendProtocol::Grpc),
        ("grpcs", BackendProtocol::Grpcs),
        ("h3", BackendProtocol::H3),
    ];

    for (protocol_str, expected) in protocols {
        let yaml = format!(
            r#"
proxies:
  - id: "test-proxy"
    listen_path: "/test"
    backend_protocol: {}
    backend_host: "localhost"
    backend_port: 8080
consumers: []
plugin_configs: []
"#,
            protocol_str
        );

        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        write!(file, "{}", yaml).unwrap();
        let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

        assert_eq!(
            config.proxies[0].backend_protocol, expected,
            "Failed to parse backend_protocol: {}",
            protocol_str
        );
    }
}

// ============================================================================
// Auth Mode Tests
// ============================================================================

#[test]
fn test_auth_mode_single() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3000
    auth_mode: single
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();
    assert_eq!(config.proxies[0].auth_mode, AuthMode::Single);
}

#[test]
fn test_auth_mode_multi() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3000
    auth_mode: multi
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();
    assert_eq!(config.proxies[0].auth_mode, AuthMode::Multi);
}

#[test]
fn test_auth_mode_defaults_to_single() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3000
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();
    assert_eq!(config.proxies[0].auth_mode, AuthMode::Single);
}

// ============================================================================
// Consumer Credential Parsing Tests
// ============================================================================

#[test]
fn test_consumer_keyauth_credential() {
    let yaml = r#"
proxies: []
consumers:
  - id: "consumer-1"
    username: "user1"
    credentials:
      keyauth:
        key: "my-api-key-12345"
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    assert_eq!(config.consumers.len(), 1);
    assert!(config.consumers[0].credentials.contains_key("keyauth"));
    let keyauth = &config.consumers[0].credentials["keyauth"];
    assert_eq!(keyauth["key"].as_str(), Some("my-api-key-12345"));
}

#[test]
fn test_consumer_jwt_credential() {
    let yaml = r#"
proxies: []
consumers:
  - id: "consumer-1"
    username: "user1"
    credentials:
      jwt:
        secret: "jwt-secret-key"
        algorithm: "HS256"
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    assert_eq!(config.consumers.len(), 1);
    assert!(config.consumers[0].credentials.contains_key("jwt"));
    let jwt = &config.consumers[0].credentials["jwt"];
    assert_eq!(jwt["secret"].as_str(), Some("jwt-secret-key"));
}

#[test]
fn test_consumer_basicauth_credential() {
    let yaml = r#"
proxies: []
consumers:
  - id: "consumer-1"
    username: "user1"
    credentials:
      basicauth:
        password_hash: "$2b$12$hashed_password_here"
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    assert_eq!(config.consumers.len(), 1);
    assert!(config.consumers[0].credentials.contains_key("basicauth"));
    let basicauth = &config.consumers[0].credentials["basicauth"];
    assert_eq!(
        basicauth["password_hash"].as_str(),
        Some("$2b$12$hashed_password_here")
    );
}

#[test]
fn test_consumer_multiple_credentials() {
    let yaml = r#"
proxies: []
consumers:
  - id: "consumer-1"
    username: "user1"
    credentials:
      keyauth:
        key: "api-key-123"
      jwt:
        secret: "jwt-secret"
      basicauth:
        password_hash: "$2b$12$hash"
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    assert_eq!(config.consumers.len(), 1);
    let creds = &config.consumers[0].credentials;
    assert_eq!(creds.len(), 3);
    assert!(creds.contains_key("keyauth"));
    assert!(creds.contains_key("jwt"));
    assert!(creds.contains_key("basicauth"));
}

// ============================================================================
// Plugin Config Scope Tests
// ============================================================================

#[test]
fn test_plugin_config_global_scope() {
    let yaml = r#"
proxies: []
consumers: []
plugin_configs:
  - id: "plugin-1"
    plugin_name: "stdout_logging"
    config: {}
    scope: global
    enabled: true
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    assert_eq!(config.plugin_configs.len(), 1);
    assert_eq!(config.plugin_configs[0].scope, PluginScope::Global);
    assert_eq!(config.plugin_configs[0].proxy_id, None);
}

#[test]
fn test_plugin_config_proxy_scope() {
    let yaml = r#"
proxies: []
consumers: []
plugin_configs:
  - id: "plugin-1"
    plugin_name: "key_auth"
    config:
      key_location: "header:X-API-Key"
    scope: proxy
    proxy_id: "proxy-protected"
    enabled: true
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    assert_eq!(config.plugin_configs.len(), 1);
    assert_eq!(config.plugin_configs[0].scope, PluginScope::Proxy);
    assert_eq!(
        config.plugin_configs[0].proxy_id,
        Some("proxy-protected".to_string())
    );
}

#[test]
fn test_plugin_config_with_complex_config() {
    let yaml = r#"
proxies: []
consumers: []
plugin_configs:
  - id: "plugin-rate-limit"
    plugin_name: "rate_limiting"
    config:
      limit_by: "consumer"
      requests_per_second: 10
      requests_per_minute: 100
      burst_size: 20
    scope: global
    enabled: true
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    assert_eq!(config.plugin_configs.len(), 1);
    let plugin_cfg = &config.plugin_configs[0];
    assert_eq!(plugin_cfg.config["limit_by"].as_str(), Some("consumer"));
    assert_eq!(plugin_cfg.config["requests_per_second"].as_i64(), Some(10));
    assert_eq!(plugin_cfg.config["requests_per_minute"].as_i64(), Some(100));
}

// ============================================================================
// Proxy Optional Fields Tests
// ============================================================================

#[test]
fn test_proxy_with_all_optional_fields() {
    let yaml = r#"
proxies:
  - id: "proxy-full"
    listen_path: "/api"
    backend_protocol: https
    backend_host: "example.com"
    backend_port: 443
    name: "Full Featured Proxy"
    backend_path: "/v1/gateway"
    strip_listen_path: true
    preserve_host_header: true
    backend_connect_timeout_ms: 8000
    backend_read_timeout_ms: 45000
    backend_write_timeout_ms: 45000
    backend_tls_client_cert_path: "/etc/certs/client.pem"
    backend_tls_client_key_path: "/etc/certs/client-key.pem"
    backend_tls_verify_server_cert: false
    backend_tls_server_ca_cert_path: "/etc/certs/ca.pem"
    dns_override: "192.168.1.1"
    dns_cache_ttl_seconds: 300
    pool_idle_timeout_seconds: 180
    pool_enable_http_keep_alive: true
    pool_enable_http2: true
    pool_tcp_keepalive_seconds: 60
    pool_http2_keep_alive_interval_seconds: 30
    pool_http2_keep_alive_timeout_seconds: 45
    auth_mode: multi
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    let proxy = &config.proxies[0];
    assert_eq!(proxy.backend_path, Some("/v1/gateway".to_string()));
    assert_eq!(
        proxy.backend_tls_client_cert_path,
        Some("/etc/certs/client.pem".to_string())
    );
    assert_eq!(
        proxy.backend_tls_client_key_path,
        Some("/etc/certs/client-key.pem".to_string())
    );
    assert!(!proxy.backend_tls_verify_server_cert);
    assert_eq!(
        proxy.backend_tls_server_ca_cert_path,
        Some("/etc/certs/ca.pem".to_string())
    );
    assert_eq!(proxy.dns_override, Some("192.168.1.1".to_string()));
    assert_eq!(proxy.dns_cache_ttl_seconds, Some(300));

    assert_eq!(proxy.pool_idle_timeout_seconds, Some(180));
    assert_eq!(proxy.pool_enable_http_keep_alive, Some(true));
    assert_eq!(proxy.pool_enable_http2, Some(true));
    assert_eq!(proxy.pool_tcp_keepalive_seconds, Some(60));
    assert_eq!(proxy.pool_http2_keep_alive_interval_seconds, Some(30));
    assert_eq!(proxy.pool_http2_keep_alive_timeout_seconds, Some(45));
}

#[test]
fn test_proxy_minimal_optional_fields() {
    let yaml = r#"
proxies:
  - id: "proxy-minimal"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 8080
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    let proxy = &config.proxies[0];
    assert_eq!(proxy.name, None);
    assert_eq!(proxy.backend_path, None);
    assert_eq!(proxy.dns_override, None);
    assert_eq!(proxy.dns_cache_ttl_seconds, None);

    assert_eq!(proxy.pool_idle_timeout_seconds, None);
}

// ============================================================================
// Reload Configuration Tests
// ============================================================================

#[test]
fn test_reload_config_from_file() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3000
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let file_path = file.path().to_str().unwrap();

    // Initial load
    let config1 = reload_config_from_file(file_path).unwrap();
    assert_eq!(config1.proxies.len(), 1);

    // Modify file and reload
    let yaml_updated = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3000
  - id: "proxy-2"
    listen_path: "/api/v2"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3001
consumers: []
plugin_configs: []
"#;
    write!(file.reopen().unwrap(), "{}", yaml_updated).unwrap();

    // Reload should get new config
    let config2 = reload_config_from_file(file_path).unwrap();
    assert_eq!(config2.proxies.len(), 2);
}

// ============================================================================
// Error Cases
// ============================================================================

#[test]
fn test_missing_config_file() {
    let result = load_config_from_file("/nonexistent/path/config.yaml");
    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("Configuration file not found") || error.contains("not found"));
}

#[test]
fn test_malformed_yaml() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: invalid_port_number
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let result = load_config_from_file(file.path().to_str().unwrap());
    assert!(result.is_err());
}

#[test]
fn test_malformed_json() {
    let json = r#"{
  "proxies": [{
    "id": "proxy-1",
    "listen_path": "/api/v1",
    invalid json here
  }],
}"#;
    let mut file = NamedTempFile::with_suffix(".json").unwrap();
    write!(file, "{}", json).unwrap();
    let result = load_config_from_file(file.path().to_str().unwrap());
    assert!(result.is_err());
}

#[test]
fn test_empty_config() {
    let yaml = r#"
proxies: []
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    assert_eq!(config.proxies.len(), 0);
    assert_eq!(config.consumers.len(), 0);
    assert_eq!(config.plugin_configs.len(), 0);
}

// ============================================================================
// Unknown Extension Fallback Test
// ============================================================================

#[test]
fn test_unknown_extension_fallback_to_yaml() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3000
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".conf").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();
    assert_eq!(config.proxies.len(), 1);
}

#[test]
fn test_unknown_extension_fallback_to_json() {
    let json = r#"{
  "proxies": [{
    "id": "proxy-1",
    "listen_path": "/api/v1",
    "backend_protocol": "http",
    "backend_host": "localhost",
    "backend_port": 3000
  }],
  "consumers": [],
  "plugin_configs": []
}"#;
    let mut file = NamedTempFile::with_suffix(".config").unwrap();
    write!(file, "{}", json).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();
    assert_eq!(config.proxies.len(), 1);
}

// ============================================================================
// Proxy Plugin Association Tests
// ============================================================================

#[test]
fn test_proxy_with_multiple_plugins() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 8080
    plugins:
      - plugin_config_id: "plugin-auth"
      - plugin_config_id: "plugin-ratelimit"
      - plugin_config_id: "plugin-logging"
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    assert_eq!(config.proxies[0].plugins.len(), 3);
    assert_eq!(config.proxies[0].plugins[0].plugin_config_id, "plugin-auth");
    assert_eq!(
        config.proxies[0].plugins[1].plugin_config_id,
        "plugin-ratelimit"
    );
    assert_eq!(
        config.proxies[0].plugins[2].plugin_config_id,
        "plugin-logging"
    );
}

#[test]
fn test_proxy_with_no_plugins() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 8080
    plugins: []
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    assert_eq!(config.proxies[0].plugins.len(), 0);
}
