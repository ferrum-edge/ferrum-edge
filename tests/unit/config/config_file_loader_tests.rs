use ferrum_edge::config::file_loader::{load_config_from_file, reload_config_from_file};
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, PluginScope};
use std::io::Write;
use tempfile::NamedTempFile;

// ============================================================================
// Basic Loading Tests
// ============================================================================

#[test]
fn test_load_yaml_config() {
    let yaml = r#"
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3000
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();
    assert_eq!(config.proxies.len(), 1);
    assert_eq!(config.proxies[0].listen_path.as_deref(), Some("/api/v1"));
}

#[test]
fn test_load_json_config() {
    let json = r#"{
  "version": "1",
  "proxies": [{
    "id": "proxy-1",
    "listen_path": "/api/v1",
    "backend_scheme": "http",
    "backend_host": "localhost",
    "backend_port": 3000
  }],
  "consumers": [],
  "plugin_configs": []
}"#;
    let mut file = NamedTempFile::with_suffix(".json").unwrap();
    write!(file, "{}", json).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();
    assert_eq!(config.proxies.len(), 1);
}

#[test]
fn test_load_config_rejects_invalid_host_label_shapes() {
    let yaml = r#"
version: "1"
proxies:
  - id: "bad-host-proxy"
    hosts:
      - "api..example.com"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3000
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();

    let err = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .expect_err("file-mode config loading must reject invalid host labels");
    let msg = err.to_string();
    assert!(
        msg.contains("invalid host"),
        "error should mention host validation, got: {msg}"
    );
}

#[test]
fn test_duplicate_listen_path_rejected() {
    let yaml = r#"
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3000
  - id: "proxy-2"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3001
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let result = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    );
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
version: "1"
proxies:
  - id: "proxy-httpbin"
    name: "HTTPBin Proxy"
    listen_path: "/httpbin"
    backend_scheme: https
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
    plugins: []

  - id: "proxy-multi-auth"
    listen_path: "/multi-auth"
    backend_scheme: http
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
        - key: "alice-secret-api-key-12345"
      jwt:
        - secret: "alice-jwt-secret-key-1234567890ab"
      basicauth:
        - password_hash: "hmac_sha256:0000000000000000000000000000000000000000000000000000000000000000"

  - id: "consumer-bob"
    username: "bob"
    custom_id: "bob-002"
    credentials:
      keyauth:
        - key: "bob-secret-api-key-67890"

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
    proxy_id: "proxy-multi-auth"
    enabled: true
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();

    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

    // Verify proxies
    assert_eq!(config.proxies.len(), 2);
    assert_eq!(config.proxies[0].id, "proxy-httpbin");
    assert_eq!(config.proxies[0].name, Some("HTTPBin Proxy".to_string()));
    assert_eq!(config.proxies[0].backend_scheme, Some(BackendScheme::Https));
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
        Some("proxy-multi-auth".to_string())
    );
}

#[test]
fn test_load_shared_example_config_fixture() {
    let config = load_config_from_file(
        "tests/config.yaml",
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

    assert!(!config.proxies.is_empty());
    assert!(
        config
            .plugin_configs
            .iter()
            .any(|plugin| plugin.scope == PluginScope::Global)
    );
    assert!(
        config
            .plugin_configs
            .iter()
            .any(|plugin| plugin.scope == PluginScope::Proxy)
    );
}

// ============================================================================
// Backend Scheme Tests
// ============================================================================
//
// After the BackendProtocol -> BackendScheme refactor, the wire format only
// accepts canonical schemes (http, https, tcp, tcps, udp, dtls). Former
// protocol values (ws, wss, grpc, grpcs) are detected per-request from the
// incoming traffic (`HttpFlavor`). Backend H3 selection is runtime capability-
// driven for HTTPS backends. Serde rejects unknown enum values, so old
// protocol spellings are not accepted via file loading.

#[test]
fn test_all_backend_schemes() {
    let schemes = vec![
        ("http", BackendScheme::Http),
        ("https", BackendScheme::Https),
    ];

    for (scheme_str, expected) in schemes {
        let yaml = format!(
            r#"
version: "1"
proxies:
  - id: "test-proxy"
    listen_path: "/test"
    backend_scheme: {}
    backend_host: "localhost"
    backend_port: 8080
consumers: []
plugin_configs: []
"#,
            scheme_str
        );

        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        write!(file, "{}", yaml).unwrap();
        let config = load_config_from_file(
            file.path().to_str().unwrap(),
            30,
            &ferrum_edge::config::BackendAllowIps::Both,
            "ferrum",
        )
        .unwrap();

        assert_eq!(
            config.proxies[0].backend_scheme,
            Some(expected),
            "Failed to parse backend_scheme: {}",
            scheme_str
        );
    }
}

#[test]
fn test_backend_scheme_defaults_to_https_for_http_family_proxy() {
    let yaml = r#"
version: "1"
proxies:
  - id: "test-proxy"
    listen_path: "/test"
    backend_host: "localhost"
    backend_port: 8443
consumers: []
plugin_configs: []
"#;

    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

    assert_eq!(config.proxies[0].backend_scheme, Some(BackendScheme::Https));
    assert_eq!(config.proxies[0].dispatch_kind, DispatchKind::HttpsPool);
}

#[test]
fn test_h3_scheme_rejected_by_file_loader() {
    let yaml = r#"
version: "1"
proxies:
  - id: "h3-scheme"
    listen_path: "/v1"
    backend_scheme: h3
    backend_host: "localhost"
    backend_port: 8443
consumers: []
plugin_configs: []
"#;

    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    );
    let err = config.expect_err("h3 scheme should be rejected by serde file loading");
    assert!(
        err.to_string().contains("unknown variant") || err.to_string().contains("h3"),
        "error should mention the unsupported scheme: {}",
        err
    );
}

#[test]
fn test_unknown_fields_rejected_on_each_resource_type() {
    // `Proxy`, `Consumer`, `Upstream`, `PluginConfig`, and `GatewayConfig` all
    // carry `#[serde(deny_unknown_fields)]`. A typo or removed field anywhere
    // in the tree must surface as a clear deserialize error rather than being
    // silently dropped.
    let cases: &[(&str, &str, &str)] = &[
        (
            "GatewayConfig top-level",
            r#"
version: "1"
extra_top_level_key: 1
proxies: []
consumers: []
plugin_configs: []
"#,
            "extra_top_level_key",
        ),
        (
            "Proxy entry",
            r#"
version: "1"
proxies:
  - id: "p1"
    listen_path: "/v1"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 8080
    backend_protocol: http
consumers: []
plugin_configs: []
"#,
            "backend_protocol",
        ),
        (
            "Consumer entry",
            r#"
version: "1"
proxies: []
consumers:
  - id: "c1"
    username: "alice"
    not_a_consumer_field: "x"
plugin_configs: []
"#,
            "not_a_consumer_field",
        ),
        (
            "PluginConfig entry",
            r#"
version: "1"
proxies: []
consumers: []
plugin_configs:
  - id: "pc1"
    plugin_name: "key_auth"
    config: {}
    scope: global
    bogus_plugin_field: true
"#,
            "bogus_plugin_field",
        ),
        (
            "Upstream entry",
            r#"
version: "1"
proxies: []
consumers: []
plugin_configs: []
upstreams:
  - id: "u1"
    targets:
      - host: "localhost"
        port: 8080
    bogus_upstream_field: "x"
"#,
            "bogus_upstream_field",
        ),
    ];

    for (label, yaml, expected_field) in cases {
        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        write!(file, "{}", yaml).unwrap();
        let result = load_config_from_file(
            file.path().to_str().unwrap(),
            30,
            &ferrum_edge::config::BackendAllowIps::Both,
            "ferrum",
        );
        let err = result.expect_err(&format!(
            "{label}: unknown field {expected_field:?} should be rejected"
        ));
        let msg = err.to_string();
        assert!(
            msg.contains(expected_field) || msg.contains("unknown field"),
            "{label}: error should mention the unknown field {expected_field:?}: {msg}"
        );
    }
}

// ============================================================================
// Mesh-projected upstream fields rejected on operator-provided file loads
// ============================================================================

/// Regression for codex F7.3 round-3 (Finding A): file mode runs
/// `validate_all_fields_with_ip_policy` but NOT the projected-field rejection, so
/// before the fix an operator-authored file could enable strict locality LB by
/// setting `locality_lb_strict` directly. The rejection must apply to ALL
/// operator-provided loads (admin API AND file mode). The mesh slice-apply path
/// still projects these fields (covered by `validate_fields().is_ok()` in
/// field_validation_tests.rs), so it must keep applying cleanly.
#[test]
fn test_file_load_rejects_mesh_projected_locality_lb_strict() {
    let yaml = r#"
version: "1"
proxies: []
consumers: []
plugin_configs: []
upstreams:
  - id: "u1"
    targets:
      - host: "localhost"
        port: 8080
    locality_lb_strict: true
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let err = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .expect_err("file mode must reject an operator-set locality_lb_strict");
    let msg = err.to_string();
    assert!(
        msg.contains("locality_lb_strict") && msg.contains("FERRUM_MESH_LOCALITY_LB_STRICT"),
        "error should name the projected field + its canonical env surface: {msg}"
    );
}

/// Companion to the above: a file-mode upstream that sets `source_locality`
/// (another mesh-projected field) is also rejected.
#[test]
fn test_file_load_rejects_mesh_projected_source_locality() {
    let yaml = r#"
version: "1"
proxies: []
consumers: []
plugin_configs: []
upstreams:
  - id: "u1"
    targets:
      - host: "localhost"
        port: 8080
    source_locality: "us-west/us-west-1/a"
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let err = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .expect_err("file mode must reject an operator-set source_locality");
    assert!(
        err.to_string().contains("source_locality"),
        "error should name the projected field: {err}"
    );
}

/// A clean operator file (no mesh-projected fields) still loads — the rejection
/// must not be over-broad.
#[test]
fn test_file_load_accepts_upstream_without_projected_fields() {
    let yaml = r#"
version: "1"
proxies: []
consumers: []
plugin_configs: []
upstreams:
  - id: "u1"
    targets:
      - host: "localhost"
        port: 8080
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .expect("a clean operator upstream must still load");
    assert_eq!(config.upstreams.len(), 1);
}

// ============================================================================
// Auth Mode Tests
// ============================================================================

#[test]
fn test_auth_mode_single() {
    let yaml = r#"
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3000
    auth_mode: single
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();
    assert_eq!(config.proxies[0].auth_mode, AuthMode::Single);
}

#[test]
fn test_auth_mode_multi() {
    let yaml = r#"
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3000
    auth_mode: multi
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();
    assert_eq!(config.proxies[0].auth_mode, AuthMode::Multi);
}

#[test]
fn test_auth_mode_defaults_to_single() {
    let yaml = r#"
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3000
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();
    assert_eq!(config.proxies[0].auth_mode, AuthMode::Single);
}

// ============================================================================
// Consumer Credential Parsing Tests
// ============================================================================

#[test]
fn test_consumer_keyauth_credential() {
    let yaml = r#"
version: "1"
proxies: []
consumers:
  - id: "consumer-1"
    username: "user1"
    credentials:
      keyauth:
        - key: "my-api-key-12345"
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

    assert_eq!(config.consumers.len(), 1);
    assert!(config.consumers[0].credentials.contains_key("keyauth"));
    let keyauth = &config.consumers[0].credentials["keyauth"][0];
    assert_eq!(keyauth["key"].as_str(), Some("my-api-key-12345"));
}

#[test]
fn test_consumer_jwt_credential() {
    let yaml = r#"
version: "1"
proxies: []
consumers:
  - id: "consumer-1"
    username: "user1"
    credentials:
      jwt:
        - secret: "jwt-secret-key-padding-1234567890"
          algorithm: "HS256"
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

    assert_eq!(config.consumers.len(), 1);
    assert!(config.consumers[0].credentials.contains_key("jwt"));
    let jwt = &config.consumers[0].credentials["jwt"][0];
    assert_eq!(
        jwt["secret"].as_str(),
        Some("jwt-secret-key-padding-1234567890")
    );
}

#[test]
fn test_consumer_basicauth_credential() {
    let yaml = r#"
version: "1"
proxies: []
consumers:
  - id: "consumer-1"
    username: "user1"
    credentials:
      basicauth:
        - password_hash: "hmac_sha256:0000000000000000000000000000000000000000000000000000000000000000"
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

    assert_eq!(config.consumers.len(), 1);
    assert!(config.consumers[0].credentials.contains_key("basicauth"));
    let basicauth = &config.consumers[0].credentials["basicauth"][0];
    assert_eq!(
        basicauth["password_hash"].as_str(),
        Some("hmac_sha256:0000000000000000000000000000000000000000000000000000000000000000")
    );
}

#[test]
fn test_consumer_multiple_credentials() {
    let yaml = r#"
version: "1"
proxies: []
consumers:
  - id: "consumer-1"
    username: "user1"
    credentials:
      keyauth:
        - key: "api-key-123"
      jwt:
        - secret: "jwt-secret-padding-12345678901234"
      basicauth:
        - password_hash: "hmac_sha256:0000000000000000000000000000000000000000000000000000000000000000"
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

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
version: "1"
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
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

    assert_eq!(config.plugin_configs.len(), 1);
    assert_eq!(config.plugin_configs[0].scope, PluginScope::Global);
    assert_eq!(config.plugin_configs[0].proxy_id, None);
}

#[test]
fn test_optional_fail_open_plugin_validation_is_non_fatal_in_file_mode() {
    let yaml = r#"
version: "1"
proxies: []
consumers: []
plugin_configs:
  - id: "plugin-optional-bad-config"
    plugin_name: "stdout_logging"
    config: "not-an-object"
    scope: global
    enabled: true
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .expect("optional fail-open plugin config errors must not reject file-mode config load");

    assert_eq!(config.plugin_configs.len(), 1);
    assert_eq!(
        config.plugin_configs[0].id,
        "plugin-optional-bad-config"
    );
    assert_eq!(config.plugin_configs[0].plugin_name, "stdout_logging");
}

#[test]
fn test_plugin_config_proxy_scope() {
    let yaml = r#"
version: "1"
proxies:
  - id: "proxy-protected"
    listen_path: "/protected"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3000
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
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

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
version: "1"
proxies: []
consumers: []
plugin_configs:
  - id: "plugin-rate-limit"
    plugin_name: "rate_limiting"
    config:
      limit_by: "consumer"
      limits:
        - scope: "default"
          requests_per_second: 10
          requests_per_minute: 100
    scope: global
    enabled: true
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

    assert_eq!(config.plugin_configs.len(), 1);
    let plugin_cfg = &config.plugin_configs[0];
    assert_eq!(plugin_cfg.config["limit_by"].as_str(), Some("consumer"));
    let default_limit = &plugin_cfg.config["limits"][0];
    assert_eq!(default_limit["scope"].as_str(), Some("default"));
    assert_eq!(default_limit["requests_per_second"].as_i64(), Some(10));
    assert_eq!(default_limit["requests_per_minute"].as_i64(), Some(100));
}

// ============================================================================
// Proxy Optional Fields Tests
// ============================================================================

#[test]
fn test_proxy_with_all_optional_fields() {
    // Use real test cert files so TLS file validation passes
    let cert_path = std::fs::canonicalize("tests/certs/server.crt")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let key_path = std::fs::canonicalize("tests/certs/server.key")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let yaml = format!(
        r#"
version: "1"
proxies:
  - id: "proxy-full"
    listen_path: "/api"
    backend_scheme: https
    backend_host: "example.com"
    backend_port: 443
    name: "Full Featured Proxy"
    backend_path: "/v1/gateway"
    strip_listen_path: true
    preserve_host_header: true
    backend_connect_timeout_ms: 8000
    backend_read_timeout_ms: 45000
    backend_write_timeout_ms: 45000
    backend_tls_client_cert_path: "{cert_path}"
    backend_tls_client_key_path: "{key_path}"
    backend_tls_verify_server_cert: false
    backend_tls_server_ca_cert_path: "{cert_path}"
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
"#
    );
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

    let proxy = &config.proxies[0];
    assert_eq!(proxy.backend_path, Some("/v1/gateway".to_string()));
    assert_eq!(proxy.backend_tls_client_cert_path, Some(cert_path.clone()));
    assert_eq!(proxy.backend_tls_client_key_path, Some(key_path.clone()));
    assert!(!proxy.backend_tls_verify_server_cert);
    assert_eq!(
        proxy.backend_tls_server_ca_cert_path,
        Some(cert_path.clone())
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
version: "1"
proxies:
  - id: "proxy-minimal"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 8080
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

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
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3000
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let file_path = file.path().to_str().unwrap();

    // Initial load
    let config1 = reload_config_from_file(
        file_path,
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();
    assert_eq!(config1.proxies.len(), 1);

    // Modify file and reload
    let yaml_updated = r#"
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3000
  - id: "proxy-2"
    listen_path: "/api/v2"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3001
consumers: []
plugin_configs: []
"#;
    write!(file.reopen().unwrap(), "{}", yaml_updated).unwrap();

    // Reload should get new config
    let config2 = reload_config_from_file(
        file_path,
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();
    assert_eq!(config2.proxies.len(), 2);
}

// ============================================================================
// Error Cases
// ============================================================================

#[test]
fn test_missing_config_file() {
    let result = load_config_from_file(
        "/nonexistent/path/config.yaml",
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    );
    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("Configuration file not found") || error.contains("not found"));
}

#[test]
fn test_malformed_yaml() {
    let yaml = r#"
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: invalid_port_number
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let result = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    );
    assert!(result.is_err());
}

#[test]
fn test_malformed_json() {
    let json = r#"{
  "version": "1",
  "proxies": [{
    "id": "proxy-1",
    "listen_path": "/api/v1",
    invalid json here
  }],
}"#;
    let mut file = NamedTempFile::with_suffix(".json").unwrap();
    write!(file, "{}", json).unwrap();
    let result = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    );
    assert!(result.is_err());
}

#[test]
fn test_empty_config() {
    let yaml = r#"
version: "1"
proxies: []
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

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
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3000
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".conf").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();
    assert_eq!(config.proxies.len(), 1);
}

#[test]
fn test_unknown_extension_fallback_to_json() {
    let json = r#"{
  "version": "1",
  "proxies": [{
    "id": "proxy-1",
    "listen_path": "/api/v1",
    "backend_scheme": "http",
    "backend_host": "localhost",
    "backend_port": 3000
  }],
  "consumers": [],
  "plugin_configs": []
}"#;
    let mut file = NamedTempFile::with_suffix(".config").unwrap();
    write!(file, "{}", json).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();
    assert_eq!(config.proxies.len(), 1);
}

// ============================================================================
// Proxy Plugin Association Tests
// ============================================================================

#[test]
fn test_proxy_with_multiple_plugins() {
    let yaml = r#"
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 8080
    plugins:
      - plugin_config_id: "plugin-auth"
      - plugin_config_id: "plugin-ratelimit"
      - plugin_config_id: "plugin-logging"
consumers: []
plugin_configs:
  - id: "plugin-auth"
    plugin_name: "key_auth"
    config:
      key_location: "header:X-API-Key"
    scope: proxy
    proxy_id: "proxy-1"
    enabled: true
  - id: "plugin-ratelimit"
    plugin_name: "rate_limiting"
    config:
      limits:
        - scope: "default"
          requests_per_second: 10
    scope: proxy
    proxy_id: "proxy-1"
    enabled: true
  - id: "plugin-logging"
    plugin_name: "stdout_logging"
    config: {}
    scope: proxy
    proxy_id: "proxy-1"
    enabled: true
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

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
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 8080
    plugins: []
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "ferrum",
    )
    .unwrap();

    assert_eq!(config.proxies[0].plugins.len(), 0);
}

// ============================================================================
// Namespace filtering happens before cross-resource uniqueness checks
// ============================================================================

/// Two proxies in different namespaces that share a `listen_path` must load
/// cleanly — only the active namespace's proxies participate in
/// `validate_unique_listen_paths`. Prior to moving the namespace filter above
/// the cross-resource validators in `load_config_from_file`, this would fail
/// with "Duplicate listen_path" even though both the admin API and the SQL
/// unique index allow it.
#[test]
fn test_load_config_multi_namespace_shared_listen_path() {
    let yaml = r#"
version: "1"
proxies:
  - id: "prod-proxy"
    namespace: "prod"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3001
  - id: "staging-proxy"
    namespace: "staging"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3002
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();

    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "prod",
    )
    .expect("multi-namespace config with shared listen_path must load");
    assert_eq!(config.proxies.len(), 1);
    assert_eq!(config.proxies[0].namespace, "prod");
    // `known_namespaces` is captured before filtering so /namespaces can
    // report the full set.
    assert!(config.known_namespaces.iter().any(|n| n == "prod"));
    assert!(config.known_namespaces.iter().any(|n| n == "staging"));
}

/// Same listen_path within a single namespace must still be rejected.
#[test]
fn test_load_config_same_namespace_duplicate_listen_path_rejected() {
    let yaml = r#"
version: "1"
proxies:
  - id: "prod-a"
    namespace: "prod"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3001
  - id: "prod-b"
    namespace: "prod"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3002
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();

    let err = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "prod",
    )
    .expect_err("duplicate listen_path within same namespace must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("listen_path") || msg.contains("Duplicate"),
        "expected listen_path uniqueness error, got: {msg}"
    );
}

/// Stream proxy `listen_port` collision across namespaces must also load
/// cleanly (same rationale as listen_path). Stream proxies must NOT set
/// listen_path — omit the field entirely.
#[test]
fn test_load_config_multi_namespace_shared_listen_port() {
    let yaml = r#"
version: "1"
proxies:
  - id: "prod-tcp"
    namespace: "prod"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: 3001
    listen_port: 15000
  - id: "staging-tcp"
    namespace: "staging"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: 3002
    listen_port: 15000
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();

    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "staging",
    )
    .expect("multi-namespace stream proxies sharing listen_port must load");
    assert_eq!(config.proxies.len(), 1);
    assert_eq!(config.proxies[0].namespace, "staging");
    assert_eq!(config.proxies[0].listen_port, Some(15000));
}

/// Consumer username collision is per-namespace.
#[test]
fn test_load_config_multi_namespace_shared_consumer_username() {
    let yaml = r#"
version: "1"
proxies: []
consumers:
  - id: "prod-alice"
    namespace: "prod"
    username: "alice"
  - id: "staging-alice"
    namespace: "staging"
    username: "alice"
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();

    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendAllowIps::Both,
        "prod",
    )
    .expect("multi-namespace consumers sharing username must load");
    assert_eq!(config.consumers.len(), 1);
    assert_eq!(config.consumers[0].username, "alice");
    assert_eq!(config.consumers[0].namespace, "prod");
}
