//! Tests for tcp_logging plugin

use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Plugin, PluginFailurePolicy, PluginHttpClient, plugin_failure_policy,
    tcp_logging::TcpLogging,
};
use serde_json::json;

use super::plugin_utils::{
    create_test_stream_transaction_summary, create_test_transaction_summary,
};

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

#[test]
fn test_tcp_logging_keeps_last_known_good_on_invalid_candidates() {
    assert_eq!(
        plugin_failure_policy("tcp_logging"),
        Some(PluginFailurePolicy::KeepLastKnownGood)
    );
}

/// `tls: true` now builds a rustls `ClientConfig` in `TcpLogging::new` (finding
/// #74), which requires an installed crypto provider — normally done in
/// `main.rs` at startup.
fn ensure_crypto_provider() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

/// Build a `PluginHttpClient` that advertises `ca_path` as its TLS CA bundle.
/// `PluginHttpClient::new` only `warn!`s (does not error) on a bad bundle, so
/// the path flows through to `TcpLogging::new`.
fn client_with_ca(ca_path: &str) -> PluginHttpClient {
    use ferrum_edge::config::BackendEgressPolicy;
    use ferrum_edge::config::PoolConfig;
    use ferrum_edge::config::types::DEFAULT_NAMESPACE;
    use ferrum_edge::dns::{DnsCache, DnsConfig};

    PluginHttpClient::new(
        &PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        1000,
        0,
        100,
        false,
        Some(ca_path),
        std::sync::Arc::new(Vec::new()),
        DEFAULT_NAMESPACE,
        BackendEgressPolicy::unrestricted(),
        std::sync::Arc::new(Vec::new()),
        0,
    )
}

/// Finding #74: the CA bundle is now parsed once in `TcpLogging::new` (off the
/// async flush task) instead of synchronously on every TLS reconnect. A bad CA
/// bundle therefore fails at construction/admission time rather than silently
/// inside the background batching task on first connect.
#[tokio::test]
async fn test_tcp_logging_tls_rejects_invalid_ca_bundle_at_construction() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = dir.path().join("not-a-cert.pem");
    std::fs::write(&ca_path, b"this is not a PEM certificate").expect("write garbage CA");

    let result = TcpLogging::new(
        &json!({
            "host": "logstash.example.com",
            "port": 5141,
            "tls": true,
        }),
        client_with_ca(ca_path.to_str().expect("utf8 path")),
    );
    assert!(
        result.is_err(),
        "an unparseable CA bundle must be rejected when the plugin is constructed"
    );
}

/// Counterpart to the above: TLS with no custom CA (system/webpki roots) still
/// constructs successfully — the connector is prebuilt without touching the
/// filesystem.
#[tokio::test]
async fn test_tcp_logging_tls_without_ca_bundle_constructs() {
    ensure_crypto_provider();
    let plugin = TcpLogging::new(
        &json!({
            "host": "logstash.example.com",
            "port": 5141,
            "tls": true,
        }),
        default_client(),
    );
    assert!(plugin.is_ok(), "TLS with default roots should construct");
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "localhost",
            "port": 5140
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "tcp_logging");
    assert_eq!(plugin.priority(), 9125);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation_with_tls() {
    ensure_crypto_provider();
    let plugin = TcpLogging::new(
        &json!({
            "host": "logstash.example.com",
            "port": 5141,
            "tls": true,
            "tls_server_name": "logstash.example.com"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "tcp_logging");
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation_missing_host() {
    let result = TcpLogging::new(&json!({"port": 5140}), default_client());
    match result {
        Err(e) => assert!(e.contains("host"), "Expected error about host, got: {}", e),
        Ok(_) => panic!("Expected Err when creating tcp_logging without host"),
    }
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation_missing_port() {
    let result = TcpLogging::new(&json!({"host": "localhost"}), default_client());
    match result {
        Err(e) => assert!(e.contains("port"), "Expected error about port, got: {}", e),
        Ok(_) => panic!("Expected Err when creating tcp_logging without port"),
    }
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation_invalid_port_zero() {
    let result = TcpLogging::new(&json!({"host": "localhost", "port": 0}), default_client());
    match result {
        Err(e) => assert!(e.contains("port"), "Expected error about port, got: {}", e),
        Ok(_) => panic!("Expected Err when creating tcp_logging with port 0"),
    }
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation_invalid_port_too_large() {
    let result = TcpLogging::new(
        &json!({"host": "localhost", "port": 70000}),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("port"), "Expected error about port, got: {}", e),
        Ok(_) => panic!("Expected Err when creating tcp_logging with port > 65535"),
    }
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation_empty_host() {
    let result = TcpLogging::new(&json!({"host": "", "port": 5140}), default_client());
    assert!(result.is_err());
}

#[tokio::test]
async fn test_tcp_logging_rejects_host_with_url_or_port_material() {
    for host in [
        "tcp://logs.example.com",
        "user@logs.example.com",
        "logs.example.com/path",
        "logs.example.com?token=secret",
        "logs.example.com#fragment",
        "logs.example.com:5140",
        "bad host",
    ] {
        let result = TcpLogging::new(&json!({"host": host, "port": 5140}), default_client());
        assert!(result.is_err(), "host should fail validation: {host}");
    }
}

#[tokio::test]
async fn test_tcp_logging_rejects_invalid_config_shapes() {
    let cases = [
        json!(null),
        json!({"host": 123, "port": 5140}),
        json!({"host": "localhost", "port": "5140"}),
        json!({"host": "localhost", "port": 5140, "tls": "true"}),
        json!({"host": "localhost", "port": 5140, "tls_server_name": ""}),
        json!({"host": "localhost", "port": 5140, "connect_timeout_ms": false}),
        json!({"host": "localhost", "port": 5140, "batch_size": []}),
        json!({"host": "localhost", "port": 5140, "max_retries": -1}),
    ];

    for config in cases {
        assert!(
            TcpLogging::new(&config, default_client()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_tcp_logging_log_does_not_panic() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    let summary = create_test_transaction_summary();

    // Should not panic — entry is queued and background task handles the failure
    plugin.log(&summary).await;

    // Give the background flush task time to attempt delivery
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_tcp_logging_stream_disconnect_does_not_panic() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    let summary = create_test_stream_transaction_summary();

    plugin.on_stream_disconnect(&summary).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_tcp_logging_default_lifecycle_phases() {
    let plugin =
        TcpLogging::new(&json!({"host": "127.0.0.1", "port": 1}), default_client()).unwrap();

    let mut ctx = ferrum_edge::plugins::RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_tcp_logging_batch_config_defaults() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "localhost",
            "port": 5140
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "tcp_logging");
}

#[tokio::test]
async fn test_tcp_logging_custom_batch_config() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "localhost",
            "port": 5140,
            "batch_size": 100,
            "flush_interval_ms": 5000,
            "max_retries": 5,
            "retry_delay_ms": 2000,
            "buffer_capacity": 50000,
            "connect_timeout_ms": 10000
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    assert_eq!(plugin.name(), "tcp_logging");
}

#[tokio::test]
async fn test_tcp_logging_buffer_accepts_multiple_entries() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 50,
            "flush_interval_ms": 10000,
            "max_retries": 0,
            "buffer_capacity": 1000
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");

    let summary = create_test_transaction_summary();
    for _ in 0..100 {
        plugin.log(&summary).await;
    }
    // Should not panic or block — entries are queued in the channel
}

#[tokio::test]
async fn test_tcp_logging_buffer_full_drops_gracefully() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 1000,
            "flush_interval_ms": 60000,
            "max_retries": 0,
            "buffer_capacity": 5
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");

    let summary = create_test_transaction_summary();
    // Send more entries than buffer_capacity — excess should be dropped
    for _ in 0..20 {
        plugin.log(&summary).await;
    }
    // Should not panic — overflow entries are dropped with a warning
}

#[tokio::test]
async fn test_tcp_logging_warmup_hostnames() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "logstash.example.com",
            "port": 5140
        }),
        default_client(),
    )
    .unwrap();

    let hostnames = plugin.warmup_hostnames();
    assert_eq!(hostnames, vec!["logstash.example.com"]);
}

#[tokio::test]
async fn test_tcp_logging_warmup_skips_ip_literals() {
    for host in ["127.0.0.1", "2001:db8::10", "[2001:db8::10]"] {
        let plugin =
            TcpLogging::new(&json!({"host": host, "port": 5140}), default_client()).unwrap();
        assert!(
            plugin.warmup_hostnames().is_empty(),
            "IP literal {host} should not be DNS-warmed"
        );
    }
}

#[tokio::test]
async fn test_tcp_logging_rejects_metadata_host_under_default_policy() {
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
    // A socket log sink dials its `host` directly (not via the policy-screened
    // HTTP client), so the default dangerous-range baseline must reject a
    // metadata host at config-load time.
    let client = PluginHttpClient::default_with_backend_allow_ips(
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid policy"),
    );
    let err = match TcpLogging::new(&json!({"host": "169.254.169.254", "port": 9000}), client) {
        Ok(_) => panic!("metadata host must be rejected"),
        Err(e) => e,
    };
    assert!(
        err.contains("169.254.169.254") && err.contains("backend egress policy"),
        "got: {err}"
    );

    // A loopback sink (local agent) still constructs under the default policy.
    let client = PluginHttpClient::default_with_backend_allow_ips(
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid policy"),
    );
    assert!(TcpLogging::new(&json!({"host": "127.0.0.1", "port": 9000}), client).is_ok());
}

#[tokio::test]
async fn test_tcp_logging_rejects_unknown_keys_with_suggestion() {
    let err = match TcpLogging::new(
        &json!({
            "host": "logs.example.com",
            "port": 6514,
            "tlls": true
        }),
        default_client(),
    ) {
        Ok(_) => panic!("misspelled tls key must fail admission"),
        Err(e) => e,
    };
    assert!(
        err.contains("unknown configuration key")
            && err.contains("tlls")
            && err.contains("did you mean 'tls'?"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_tcp_logging_rejects_multiple_unknown_keys_sorted() {
    let err = match TcpLogging::new(
        &json!({
            "host": "logs.example.com",
            "port": 6514,
            "zzz_extra": 1,
            "aaa_extra": 2
        }),
        default_client(),
    ) {
        Ok(_) => panic!("unknown keys must fail admission"),
        Err(e) => e,
    };
    let aaa = err.find("aaa_extra").expect("aaa_extra in error");
    let zzz = err.find("zzz_extra").expect("zzz_extra in error");
    assert!(aaa < zzz, "unknown keys must be reported sorted: {err}");
}

#[tokio::test]
async fn test_tcp_logging_rejects_invalid_tls_server_names_at_admission() {
    ensure_crypto_provider();
    for tls_server_name in [
        "https://logs.example.com",
        "logs.example.com/path",
        "logs example.com",
        "logs.example.com:6514",
        " logs.example.com",
        "logs.example.com ",
    ] {
        let err = match TcpLogging::new(
            &json!({
                "host": "logs.example.com",
                "port": 6514,
                "tls": true,
                "tls_server_name": tls_server_name
            }),
            default_client(),
        ) {
            Ok(_) => panic!("invalid tls_server_name must fail admission: {tls_server_name}"),
            Err(e) => e,
        };
        assert!(
            err.contains("invalid TLS server name") || err.contains("tls_server_name"),
            "name={tls_server_name} err={err}"
        );
    }
}

#[tokio::test]
async fn test_tcp_logging_accepts_valid_dns_and_ip_tls_server_names() {
    ensure_crypto_provider();
    for tls_server_name in ["logs.example.com", "localhost", "127.0.0.1"] {
        let result = TcpLogging::new(
            &json!({
                "host": "127.0.0.1",
                "port": 6514,
                "tls": true,
                "tls_server_name": tls_server_name
            }),
            default_client(),
        );
        assert!(
            result.is_ok(),
            "valid tls_server_name {tls_server_name} should admit: {:?}",
            result.as_ref().err()
        );
    }
}

#[tokio::test]
async fn test_tcp_logging_rejects_tls_server_name_without_tls() {
    let err = match TcpLogging::new(
        &json!({
            "host": "logs.example.com",
            "port": 6514,
            "tls": false,
            "tls_server_name": "logs.example.com"
        }),
        default_client(),
    ) {
        Ok(_) => panic!("tls_server_name without tls must fail admission"),
        Err(e) => e,
    };
    assert!(
        err.contains("tls_server_name") && err.contains("tls: true"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_tcp_logging_accepts_write_timeout_ms() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "localhost",
            "port": 5140,
            "write_timeout_ms": 1500,
            "connect_timeout_ms": 1200
        }),
        default_client(),
    );
    assert!(plugin.is_ok(), "write_timeout_ms should be admitted");
}

#[tokio::test]
async fn test_tcp_logging_rejects_invalid_write_timeout_shape() {
    let result = TcpLogging::new(
        &json!({
            "host": "localhost",
            "port": 5140,
            "write_timeout_ms": false
        }),
        default_client(),
    );
    assert!(result.is_err(), "non-integer write_timeout_ms must fail");
}

#[tokio::test]
async fn test_tcp_logging_rejects_timeouts_above_recovery_bound() {
    for key in ["connect_timeout_ms", "write_timeout_ms"] {
        let mut config = json!({"host": "localhost", "port": 5140});
        config
            .as_object_mut()
            .expect("object config")
            .insert(key.to_string(), json!(60_001));
        let error = TcpLogging::new(&config, default_client())
            .err()
            .expect("excessive timeout must fail admission");
        assert!(
            error.contains(key) && error.contains("60000"),
            "unexpected {key} error: {error}"
        );
    }
}
