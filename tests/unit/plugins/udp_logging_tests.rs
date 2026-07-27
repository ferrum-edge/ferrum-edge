//! Tests for udp_logging plugin

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::udp_logging::{UDP_LOGGING_CONFIG_KEYS, UdpLogging};
use ferrum_edge::plugins::{ALL_PROTOCOLS, Plugin, PluginHttpClient, validate_plugin_config};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256,
};
use serde_json::{Value, json};
use tokio::net::UdpSocket;

use super::plugin_utils::{
    create_test_stream_transaction_summary, create_test_transaction_summary,
};

fn test_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

async fn poll_until<F>(mut condition: F, timeout: Duration, label: &str)
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{label}: condition not met within {timeout:?}");
}

async fn spawn_dtls_server() -> (Arc<ferrum_edge::dtls::DtlsServer>, SocketAddr) {
    ensure_crypto_provider();
    let server_cert = dimpl::certificate::generate_self_signed_certificate().expect("server cert");
    let server_config = dimpl::Config::builder()
        .build()
        .expect("build server config");
    let frontend = ferrum_edge::dtls::FrontendDtlsConfig {
        dimpl_config: Arc::new(server_config),
        certificate: server_cert.into(),
        client_cert_verifier: None,
    };
    let server = Arc::new(
        ferrum_edge::dtls::DtlsServer::bind("127.0.0.1:0".parse().unwrap(), frontend)
            .await
            .expect("dtls server"),
    );
    let addr = server.local_addr();
    let runner = server.clone();
    tokio::spawn(async move {
        let _ = runner.run().await;
    });
    let acceptor = server.clone();
    tokio::spawn(async move {
        loop {
            let Ok((connection, _peer)) = acceptor.accept().await else {
                break;
            };
            // Retain and drain each accepted association. Dropping the handle
            // here would close the server side immediately after handshake and
            // turn DNS-rollover coverage into a race against teardown.
            tokio::spawn(async move { while connection.recv().await.is_ok() {} });
        }
    });
    (server, addr)
}

fn ensure_crypto_provider() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

fn mint_cert_key_pair(
    alg: &'static rcgen::SignatureAlgorithm,
) -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    let key_pair = KeyPair::generate_for(alg).expect("key");
    let mut params = CertificateParams::new(vec!["udp-logging-test".to_string()]).expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "udp-logging-test");
    params.distinguished_name = dn;
    let cert = params.self_signed(&key_pair).expect("self-sign");

    let mut cert_file = tempfile::NamedTempFile::with_suffix(".pem").expect("cert file");
    cert_file
        .write_all(cert.pem().as_bytes())
        .expect("write cert");
    cert_file.flush().expect("flush cert");

    let mut key_file = tempfile::NamedTempFile::with_suffix(".pem").expect("key file");
    key_file
        .write_all(key_pair.serialize_pem().as_bytes())
        .expect("write key");
    key_file.flush().expect("flush key");
    (cert_file, key_file)
}

fn mint_ecdsa_p256_pair() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    mint_cert_key_pair(&PKCS_ECDSA_P256_SHA256)
}

fn mint_rsa_pair() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    mint_cert_key_pair(&PKCS_RSA_SHA256)
}

fn write_temp_pem(contents: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::with_suffix(".pem").expect("temp pem");
    file.write_all(contents.as_bytes()).expect("write pem");
    file.flush().expect("flush pem");
    file
}

#[tokio::test]
async fn test_udp_logging_plugin_creation() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
    assert_eq!(plugin.priority(), 9160);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[tokio::test]
async fn test_udp_logging_missing_host() {
    let result = UdpLogging::new(
        &json!({
            "port": 9514
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(e.contains("host"), "Expected error about host, got: {}", e),
        Ok(_) => panic!("Expected Err when creating udp_logging without host"),
    }
}

#[tokio::test]
async fn test_udp_logging_missing_port() {
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1"
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(e.contains("port"), "Expected error about port, got: {}", e),
        Ok(_) => panic!("Expected Err when creating udp_logging without port"),
    }
}

#[tokio::test]
async fn test_udp_logging_empty_host() {
    let result = UdpLogging::new(
        &json!({
            "host": "",
            "port": 9514
        }),
        test_client(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_udp_logging_rejects_host_with_url_or_port_material() {
    for host in [
        "udp://logs.example.com",
        "user@logs.example.com",
        "logs.example.com/path",
        "logs.example.com?token=secret",
        "logs.example.com#fragment",
        "logs.example.com:9514",
        "bad host",
    ] {
        let result = UdpLogging::new(&json!({"host": host, "port": 9514}), test_client());
        assert!(result.is_err(), "host should fail validation: {host}");
    }
}

#[tokio::test]
async fn test_udp_logging_invalid_port_zero() {
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 0
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("between 1 and 65535"),
            "Expected port range error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err for port 0"),
    }
}

#[tokio::test]
async fn test_udp_logging_invalid_port_too_large() {
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 70000
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("between 1 and 65535"),
            "Expected port range error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err for port 70000"),
    }
}

#[tokio::test]
async fn test_udp_logging_rejects_invalid_config_shapes() {
    let cases = [
        json!(null),
        json!({"host": 123, "port": 9514}),
        json!({"host": "127.0.0.1", "port": "9514"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls": "true"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_no_verify": 1}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_cert_path": ""}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_key_path": false}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_ca_cert_path": []}),
        json!({"host": "127.0.0.1", "port": 9514, "batch_size": {}}),
        json!({"host": "127.0.0.1", "port": 9514, "retry_delay_ms": "500"}),
    ];

    for config in cases {
        assert!(
            UdpLogging::new(&config, test_client()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_udp_logging_rejects_malformed_and_out_of_range_batching() {
    for config in [
        json!({"host": "127.0.0.1", "port": 9514, "batch_size": null}),
        json!({"host": "127.0.0.1", "port": 9514, "batch_size": false}),
        json!({"host": "127.0.0.1", "port": 9514, "batch_size": []}),
        json!({"host": "127.0.0.1", "port": 9514, "batch_size": 0}),
        json!({"host": "127.0.0.1", "port": 9514, "batch_size": 10_001}),
        json!({"host": "127.0.0.1", "port": 9514, "buffer_capacity": null}),
        json!({"host": "127.0.0.1", "port": 9514, "buffer_capacity": 0}),
        json!({"host": "127.0.0.1", "port": 9514, "buffer_capacity": 1_000_001}),
        json!({"host": "127.0.0.1", "port": 9514, "flush_interval_ms": 99}),
        json!({"host": "127.0.0.1", "port": 9514, "flush_interval_ms": 600_001}),
        json!({"host": "127.0.0.1", "port": 9514, "max_retries": 11}),
        json!({"host": "127.0.0.1", "port": 9514, "retry_delay_ms": 60_001}),
    ] {
        assert!(
            UdpLogging::new(&config, test_client()).is_err(),
            "expected batching rejection for {config}"
        );
    }

    assert!(
        UdpLogging::new(
            &json!({
                "host": "127.0.0.1",
                "port": 9514,
                "batch_size": 1,
                "buffer_capacity": 1,
                "flush_interval_ms": 600_000,
                "max_retries": 10,
                "retry_delay_ms": 0
            }),
            test_client(),
        )
        .is_ok(),
        "valid batching boundaries must be admitted"
    );
}

#[tokio::test]
async fn test_udp_logging_log_does_not_panic() {
    // When the endpoint is unreachable, log() should still accept entries
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "max_retries": 0
        }),
        test_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();

    // Should not panic — entry is queued in the channel
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_udp_logging_stream_disconnect_does_not_panic() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        test_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let summary = create_test_stream_transaction_summary();

    plugin.on_stream_disconnect(&summary).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_udp_logging_buffer_accepts_multiple_entries() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 50,
            "flush_interval_ms": 10000,
            "max_retries": 0,
            "buffer_capacity": 1000
        }),
        test_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let summary = create_test_transaction_summary();
    for _ in 0..100 {
        plugin.log(&summary).await;
    }
    // Should not panic or block — entries are queued in the channel
}

#[tokio::test]
async fn test_udp_logging_buffer_full_drops_gracefully() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 1000,
            "flush_interval_ms": 60000,
            "max_retries": 0,
            "buffer_capacity": 5
        }),
        test_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let summary = create_test_transaction_summary();
    // Send more entries than buffer_capacity — excess should be dropped
    for _ in 0..20 {
        plugin.log(&summary).await;
    }
    // Should not panic — overflow entries are dropped with a warning
}

#[tokio::test]
async fn test_udp_logging_default_lifecycle_phases() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();

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
async fn test_udp_logging_batch_config_defaults() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_custom_batch_config() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "batch_size": 5,
            "flush_interval_ms": 2000,
            "max_retries": 3,
            "retry_delay_ms": 1000,
            "buffer_capacity": 50000
        }),
        test_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_dtls_cert_key_pairing_required() {
    // cert without key should fail
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": "/some/cert.pem"
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("together"),
            "Expected cert/key pairing error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err when cert is provided without key"),
    }

    // key without cert should fail
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_key_path": "/some/key.pem"
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("together"),
            "Expected cert/key pairing error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err when key is provided without cert"),
    }
}

#[tokio::test]
async fn test_udp_logging_rejects_dtls_only_fields_unless_dtls_true() {
    let dtls_only_cases = [
        json!({"host": "127.0.0.1", "port": 9514, "dtls_cert_path": "/c.pem", "dtls_key_path": "/k.pem"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls": false, "dtls_cert_path": "/c.pem", "dtls_key_path": "/k.pem"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_ca_cert_path": "/ca.pem"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls": false, "dtls_ca_cert_path": "/ca.pem"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_no_verify": true}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls": false, "dtls_no_verify": false}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls": false, "dtls_no_verify": true}),
    ];
    for config in dtls_only_cases {
        let err = UdpLogging::new(&config, test_client())
            .err()
            .unwrap_or_else(|| panic!("expected DTLS-only rejection for {config}"));
        assert!(
            err.contains("requires dtls: true"),
            "config {config} got: {err}"
        );
        let err = validate_plugin_config("udp_logging", &config)
            .err()
            .unwrap_or_else(|| panic!("shared validation must reject {config}"));
        assert!(
            err.contains("requires dtls: true"),
            "shared validation {config} got: {err}"
        );
        if let Some(object) = config.as_object() {
            let err =
                ferrum_edge::_test_support::udp_logging_validate_dtls_file_dependencies_for_test(
                    object,
                )
                .err()
                .unwrap_or_else(|| panic!("file-deps validation must reject {config}"));
            assert!(
                err.contains("requires dtls: true"),
                "file-deps {config} got: {err}"
            );
        }
    }
}

#[tokio::test]
async fn test_udp_logging_dtls_config_accepted() {
    // DTLS config without certs (ephemeral cert will be used) should be accepted
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_no_verify": true
        }),
        test_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_warmup_hostnames() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "syslog.example.com",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();
    let hostnames = plugin.warmup_hostnames();
    assert_eq!(hostnames, vec!["syslog.example.com".to_string()]);
}

#[tokio::test]
async fn test_udp_logging_warmup_skips_ip_literals() {
    for host in ["127.0.0.1", "2001:db8::10", "[2001:db8::10]"] {
        let plugin = UdpLogging::new(&json!({"host": host, "port": 9514}), test_client()).unwrap();
        assert!(
            plugin.warmup_hostnames().is_empty(),
            "IP literal {host} should not be DNS-warmed"
        );
    }
}

#[tokio::test]
async fn test_udp_logging_supported_protocols() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols, ALL_PROTOCOLS);
}

#[tokio::test]
async fn test_udp_logging_rejects_unknown_keys_including_dtls_typos() {
    for (canonical, typo) in [("dtls", "dtsl"), ("port", "prot"), ("host", "hst")] {
        assert!(
            UDP_LOGGING_CONFIG_KEYS.contains(&canonical),
            "fixture must target a recognized key: {canonical}"
        );
        let mut config = json!({"host": "127.0.0.1", "port": 9514});
        config
            .as_object_mut()
            .expect("object")
            .insert(typo.to_string(), json!(true));
        let err = UdpLogging::new(&config, test_client())
            .err()
            .unwrap_or_else(|| panic!("expected unknown-key rejection for {typo}"));
        assert!(err.contains("unknown configuration key"), "got: {err}");
        assert!(err.contains(typo), "error must name the typo: {err}");
        let shared = validate_plugin_config("udp_logging", &config)
            .expect_err("shared validation must reject the same typo");
        assert!(shared.contains(typo), "got: {shared}");
    }
}

#[tokio::test]
async fn test_udp_logging_rejects_multiple_unknown_keys_sorted() {
    let err = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "zzz_extra": true,
            "aaa_extra": false
        }),
        test_client(),
    )
    .err()
    .expect("multiple unknown keys must be rejected");
    let aaa = err.find("aaa_extra").expect("aaa_extra");
    let zzz = err.find("zzz_extra").expect("zzz_extra");
    assert!(aaa < zzz, "unknown keys should be sorted: {err}");
}

#[test]
fn test_udp_logging_disabled_skips_construction_validation() {
    let mut gateway = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            id: "udp-disabled".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "udp_logging".to_string(),
            config: json!({"dtsl": true}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: false,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        ..GatewayConfig::default()
    };
    let policy = ferrum_edge::config::BackendEgressPolicy::unrestricted();
    ferrum_edge::_test_support::validate_plugin_configs_fatal_for_test(&mut gateway, &policy)
        .expect("disabled udp_logging must skip unknown-key validation");
}

#[tokio::test]
async fn test_udp_logging_optional_fail_open_omits_unknown_key_instance() {
    use ferrum_edge::config::types::Proxy;

    let policy = ferrum_edge::config::BackendEgressPolicy::unrestricted();
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "p1",
        "listen_path": "/api",
        "backend_host": "localhost",
        "backend_port": 3000,
        "backend_scheme": "http"
    }))
    .expect("proxy");

    let bad_plugin = PluginConfig {
        id: "udp-typo".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "udp_logging".to_string(),
        config: json!({"host": "127.0.0.1", "port": 9514, "dtsl": true}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let mut bad_gateway = GatewayConfig {
        proxies: vec![proxy.clone()],
        plugin_configs: vec![bad_plugin.clone()],
        ..GatewayConfig::default()
    };
    ferrum_edge::_test_support::validate_plugin_configs_fatal_for_test(&mut bad_gateway, &policy)
        .expect("OptionalFailOpen udp typos warn but do not abort file-mode load");

    let omitted = PluginCache::new(&bad_gateway).expect("cache omits failed optional plugin");
    assert!(
        omitted.get_plugins("ferrum", "p1").is_empty(),
        "unknown-key udp_logging must be omitted, not silently defaulted to plaintext"
    );

    let valid_gateway = GatewayConfig {
        proxies: vec![proxy],
        plugin_configs: vec![PluginConfig {
            config: json!({"host": "127.0.0.1", "port": 9514, "dtls": true, "dtls_no_verify": true}),
            ..bad_plugin
        }],
        ..GatewayConfig::default()
    };
    let cache = PluginCache::new(&valid_gateway).expect("valid dtls config constructs");
    assert_eq!(cache.get_plugins("ferrum", "p1").len(), 1);

    cache
        .rebuild(&bad_gateway)
        .expect("OptionalFailOpen reload omits bad udp rather than rejecting the generation");
    assert!(
        cache.get_plugins("ferrum", "p1").is_empty(),
        "reload with unknown keys must drop the previously published udp instance"
    );
}

#[tokio::test]
async fn test_udp_logging_dtls_rejects_missing_cert_source_at_admission() {
    let err = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": "/definitely/missing/udp-logging-cert.pem",
            "dtls_key_path": "/definitely/missing/udp-logging-key.pem",
            "dtls_no_verify": true
        }),
        test_client(),
    )
    .err()
    .expect("missing DTLS sources must fail admission");
    assert!(
        err.contains("DTLS cert/key materialization failed") || err.contains("failed to load"),
        "got: {err}"
    );
}

#[test]
fn test_udp_logging_shared_validation_skips_node_local_dtls_sources() {
    validate_plugin_config(
        "udp_logging",
        &json!({
            "host": "logs.example.com",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": "/definitely/missing/dp-local-udp-cert.pem",
            "dtls_key_path": "/definitely/missing/dp-local-udp-key.pem",
            "dtls_ca_cert_path": "/definitely/missing/dp-local-udp-ca.pem"
        }),
    )
    .expect("shared Admin / CP validation must check shape without opening DP-local paths");
}

#[tokio::test]
async fn test_udp_logging_dtls_rejects_malformed_pem_at_admission() {
    let cert = write_temp_pem("not-a-certificate");
    let key = write_temp_pem("not-a-key");
    let err = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": cert.path().to_str().unwrap(),
            "dtls_key_path": key.path().to_str().unwrap(),
            "dtls_no_verify": true
        }),
        test_client(),
    )
    .err()
    .expect("malformed PEM must fail admission");
    assert!(
        err.contains("DTLS cert/key materialization failed")
            || err.contains("No certificate")
            || err.contains("parse"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_udp_logging_dtls_rejects_mismatched_certificate_and_key_at_admission() {
    ensure_crypto_provider();
    let (cert, _matching_key) = mint_ecdsa_p256_pair();
    let (_other_cert, other_key) = mint_ecdsa_p256_pair();
    let err = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": cert.path().to_str().unwrap(),
            "dtls_key_path": other_key.path().to_str().unwrap(),
            "dtls_no_verify": true
        }),
        test_client(),
    )
    .err()
    .expect("mismatched DTLS certificate/key must fail admission");
    assert!(
        err.contains("do not form a valid pair") || err.contains("key does not match"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_udp_logging_dtls_rejects_rsa_key_at_admission() {
    let (cert, key) = mint_rsa_pair();
    let err = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": cert.path().to_str().unwrap(),
            "dtls_key_path": key.path().to_str().unwrap(),
            "dtls_no_verify": true
        }),
        test_client(),
    )
    .err()
    .expect("RSA keys are unsupported for DTLS");
    assert!(
        err.contains("Unsupported DTLS private key") || err.contains("ECDSA"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_udp_logging_dtls_accepts_valid_ecdsa_material_and_caches() {
    ensure_crypto_provider();
    let (cert, key) = mint_ecdsa_p256_pair();
    let ca = write_temp_pem(&std::fs::read_to_string(cert.path()).expect("read cert as ca"));
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": cert.path().to_str().unwrap(),
            "dtls_key_path": key.path().to_str().unwrap(),
            "dtls_ca_cert_path": ca.path().to_str().unwrap(),
            "dtls_no_verify": false
        }),
        test_client(),
    )
    .expect("valid ECDSA DTLS material must construct");
    assert_eq!(plugin.name(), "udp_logging");
    validate_plugin_config(
        "udp_logging",
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": cert.path().to_str().unwrap(),
            "dtls_key_path": key.path().to_str().unwrap(),
            "dtls_ca_cert_path": ca.path().to_str().unwrap()
        }),
    )
    .expect("validate_config must accept the same material without spawning issues");
}

#[tokio::test]
async fn test_udp_logging_dtls_accepts_leaf_first_certificate_bundle() {
    ensure_crypto_provider();
    let (leaf, key) = mint_ecdsa_p256_pair();
    let (additional, _additional_key) = mint_ecdsa_p256_pair();
    let bundle = write_temp_pem(&format!(
        "{}{}",
        std::fs::read_to_string(leaf.path()).expect("read leaf"),
        std::fs::read_to_string(additional.path()).expect("read additional certificate")
    ));

    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": bundle.path().to_str().unwrap(),
            "dtls_key_path": key.path().to_str().unwrap(),
            "dtls_no_verify": true
        }),
        test_client(),
    )
    .expect("UDP logging must materialize the shared leaf-first DTLS loader");
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_dtls_rejects_malformed_ca_at_admission() {
    let (cert, key) = mint_ecdsa_p256_pair();
    let ca = write_temp_pem("not-a-ca");
    let err = UdpLogging::new(
        &json!({
            "host": "logs.example.com",
            "port": 9515,
            "dtls": true,
            "dtls_cert_path": cert.path().to_str().unwrap(),
            "dtls_key_path": key.path().to_str().unwrap(),
            "dtls_ca_cert_path": ca.path().to_str().unwrap()
        }),
        test_client(),
    )
    .err()
    .expect("malformed CA must fail admission");
    assert!(
        err.contains("DTLS CA materialization failed") || err.contains("No valid certificates"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_udp_logging_dtls_validates_configured_ca_when_no_verify_is_true() {
    let ca = write_temp_pem("not-a-ca");
    let err = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9515,
            "dtls": true,
            "dtls_ca_cert_path": ca.path().to_str().unwrap(),
            "dtls_no_verify": true
        }),
        test_client(),
    )
    .err()
    .expect("a declared malformed CA must fail even when verification is disabled");
    assert!(
        err.contains("DTLS CA materialization failed") || err.contains("No valid certificates"),
        "got: {err}"
    );
}

#[test]
fn test_udp_logging_file_dependency_phase_reports_bad_dtls_material() {
    let config = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            id: "udp-deps".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "udp_logging".to_string(),
            config: json!({
                "host": "127.0.0.1",
                "port": 9514,
                "dtls": true,
                "dtls_cert_path": "/missing/udp-cert.pem",
                "dtls_key_path": "/missing/udp-key.pem",
                "dtls_no_verify": true
            }),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        ..GatewayConfig::default()
    };
    let errors = config.validate_plugin_file_dependencies();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("udp-deps") && e.contains("DTLS")),
        "file-dependency phase must surface DTLS material errors: {errors:?}"
    );

    let disabled = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            enabled: false,
            ..config.plugin_configs[0].clone()
        }],
        ..GatewayConfig::default()
    };
    assert!(
        disabled.validate_plugin_file_dependencies().is_empty(),
        "disabled udp_logging must skip DTLS file dependencies"
    );

    let plaintext = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            config: json!({"host": "127.0.0.1", "port": 9514, "dtls": false}),
            ..config.plugin_configs[0].clone()
        }],
        ..GatewayConfig::default()
    };
    assert!(
        plaintext.validate_plugin_file_dependencies().is_empty(),
        "plaintext udp_logging must not require DTLS sources"
    );
}

#[test]
fn test_udp_logging_file_dependency_phase_normalizes_bracketed_ipv6() {
    ensure_crypto_provider();
    let config = json!({
        "host": "[::1]",
        "port": 9514,
        "dtls": true
    });
    ferrum_edge::_test_support::udp_logging_validate_dtls_file_dependencies_for_test(
        config.as_object().expect("udp config object"),
    )
    .expect("bracketed IPv6 must use the same canonical host as runtime admission");
}

#[test]
fn test_udp_logging_file_dependency_duplicate_sources_materialize_once() {
    let shared = json!({
        "host": "127.0.0.1",
        "port": 9514,
        "dtls": true,
        "dtls_cert_path": "/missing/shared-udp-cert.pem",
        "dtls_key_path": "/missing/shared-udp-key.pem",
        "dtls_no_verify": true
    });
    let (first, second, materialize_calls, cache_entries) =
        ferrum_edge::_test_support::udp_logging_duplicate_dtls_materialization_probe_for_test(
            shared.as_object().expect("shared config object"),
        );
    assert!(first.is_err(), "first missing-source validation must fail");
    assert_eq!(second, first, "cached failure must be replayed exactly");
    assert_eq!(materialize_calls, 1, "identical inputs materialize once");
    assert_eq!(cache_entries, 1, "identical inputs occupy one cache entry");

    let config = GatewayConfig {
        plugin_configs: vec![
            PluginConfig {
                id: "udp-deps-a".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "udp_logging".to_string(),
                config: shared.clone(),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            PluginConfig {
                id: "udp-deps-b".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "udp_logging".to_string(),
                config: shared,
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ],
        ..GatewayConfig::default()
    };
    let errors = config.validate_plugin_file_dependencies();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("udp-deps-a") && e.contains("DTLS")),
        "cached error must attach to first plugin id: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("udp-deps-b") && e.contains("DTLS")),
        "cached error must attach to second plugin id: {errors:?}"
    );
    // Never log source path contents in assertions beyond the stable error class.
    assert!(
        errors.iter().all(|e| e.contains("DTLS")),
        "duplicate-source errors must stay on the DTLS failure class"
    );
}

#[test]
fn test_udp_logging_dns_lifecycle_predicate() {
    let addr_a: SocketAddr = "127.0.0.1:9514".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:9515".parse().unwrap();
    let interval = Duration::from_secs(60);

    assert!(
        !ferrum_edge::_test_support::udp_logging_should_replace_sender_on_resolve_for_test(
            Duration::from_secs(30),
            Some(addr_a),
            addr_b,
            interval,
        ),
        "interval not elapsed"
    );
    assert!(
        !ferrum_edge::_test_support::udp_logging_should_replace_sender_on_resolve_for_test(
            interval,
            Some(addr_a),
            addr_a,
            interval,
        ),
        "unchanged address keeps association"
    );
    assert!(
        ferrum_edge::_test_support::udp_logging_should_replace_sender_on_resolve_for_test(
            interval,
            Some(addr_a),
            addr_b,
            interval,
        ),
        "changed address after interval replaces sender"
    );
}

#[tokio::test]
async fn test_udp_logging_plain_udp_dns_address_change_rebuilds_sender() {
    let listener_a = UdpSocket::bind("127.0.0.1:0").await.expect("bind a");
    let listener_b = UdpSocket::bind("127.0.0.1:0").await.expect("bind b");
    let addr_a = listener_a.local_addr().expect("addr a");
    let addr_b = listener_b.local_addr().expect("addr b");

    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": addr_a.port(),
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "buffer_capacity": 16
        }),
        test_client(),
    )
    .expect("construct");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
    poll_until(
        || plugin.current_addr_for_test() == Some(addr_a),
        Duration::from_secs(2),
        "plain UDP pin to addr_a",
    )
    .await;
    let generation_a = plugin.sender_generation_for_test();
    assert!(generation_a >= 1);

    plugin.set_next_resolve_addr_for_test(addr_b);
    plugin.age_last_resolve_for_test(Duration::from_secs(61));
    plugin.log(&summary).await;
    poll_until(
        || {
            plugin.current_addr_for_test() == Some(addr_b)
                && plugin.sender_generation_for_test() > generation_a
        },
        Duration::from_secs(2),
        "plain UDP rebuild to addr_b",
    )
    .await;
}

#[tokio::test]
async fn test_udp_logging_dtls_dns_address_change_rebuilds_association() {
    let (_server_a, addr_a) = spawn_dtls_server().await;
    let (_server_b, addr_b) = spawn_dtls_server().await;

    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": addr_a.port(),
            "dtls": true,
            "dtls_no_verify": true,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "buffer_capacity": 16
        }),
        test_client(),
    )
    .expect("construct dtls logger");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    // Force the first resolve through the one-shot hook so the bind port in
    // config cannot race with the DTLS server's ephemeral port.
    plugin.set_next_resolve_addr_for_test(addr_a);
    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
    poll_until(
        || plugin.current_addr_for_test() == Some(addr_a),
        Duration::from_secs(3),
        "DTLS pin to addr_a",
    )
    .await;
    let generation_a = plugin.sender_generation_for_test();
    assert!(
        generation_a >= 1,
        "initial DTLS association must install a sender"
    );

    plugin.set_next_resolve_addr_for_test(addr_b);
    plugin.age_last_resolve_for_test(Duration::from_secs(61));
    plugin.log(&summary).await;
    poll_until(
        || {
            plugin.current_addr_for_test() == Some(addr_b)
                && plugin.sender_generation_for_test() > generation_a
        },
        Duration::from_secs(3),
        "DTLS rebuild to addr_b with fresh association",
    )
    .await;
}

#[tokio::test]
async fn test_udp_logging_dtls_retains_association_when_replacement_handshake_fails() {
    let (_server_a, addr_a) = spawn_dtls_server().await;
    // Plain UDP listener: DTLS handshake cannot complete here.
    let plain_b = UdpSocket::bind("127.0.0.1:0").await.expect("plain b");
    let addr_b = plain_b.local_addr().expect("addr b");

    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": addr_a.port(),
            "dtls": true,
            "dtls_no_verify": true,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "buffer_capacity": 16
        }),
        test_client(),
    )
    .expect("construct dtls logger");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    plugin.set_next_resolve_addr_for_test(addr_a);
    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
    poll_until(
        || plugin.current_addr_for_test() == Some(addr_a),
        Duration::from_secs(3),
        "DTLS pin before failed rebuild",
    )
    .await;
    let generation_a = plugin.sender_generation_for_test();

    // Shorten only the replacement handshake so a non-DTLS peer fails quickly
    // without waiting on the production 10s connect budget.
    plugin.set_dtls_connect_timeout_ms_for_test(200);
    plugin.set_next_resolve_addr_for_test(addr_b);
    plugin.age_last_resolve_for_test(Duration::from_secs(61));
    plugin.log(&summary).await;

    // Bounded observation window covering the shortened handshake budget:
    // the pinned address must never move to B, and generation must stay put.
    let observe_deadline = Instant::now() + Duration::from_millis(800);
    while Instant::now() < observe_deadline {
        assert_ne!(
            plugin.current_addr_for_test(),
            Some(addr_b),
            "failed replacement must not publish the new address"
        );
        assert_eq!(
            plugin.sender_generation_for_test(),
            generation_a,
            "failed replacement must not install a new sender"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        plugin.current_addr_for_test(),
        Some(addr_a),
        "existing DTLS association must remain pinned"
    );
}

#[test]
fn test_udp_logging_dtls_docs_retain_association_when_rebuild_fails() {
    let addr: SocketAddr = "127.0.0.1:9514".parse().unwrap();
    assert!(
        !ferrum_edge::_test_support::udp_logging_should_replace_sender_on_resolve_for_test(
            Duration::from_secs(60),
            Some(addr),
            addr,
            Duration::from_secs(60),
        )
    );
    let docs = include_str!("../../../docs/plugins.md");
    assert!(docs.contains(
        "If re-resolution or the replacement handshake fails, the current sender is retained"
    ));
}

#[test]
fn test_udp_logging_dtls_batch_size_gate_classifies_send_reject_and_split() {
    let max = 16_384usize;
    assert_eq!(
        ferrum_edge::_test_support::udp_logging_classify_dtls_batch_size_for_test(
            false,
            max + 1,
            8,
            max
        ),
        "send_as_is",
        "plain UDP must not apply the DTLS plaintext ceiling"
    );
    assert_eq!(
        ferrum_edge::_test_support::udp_logging_classify_dtls_batch_size_for_test(
            true, max, 8, max
        ),
        "send_as_is",
        "in-limit DTLS batches send as one datagram"
    );
    assert_eq!(
        ferrum_edge::_test_support::udp_logging_classify_dtls_batch_size_for_test(
            true,
            max + 1,
            1,
            max
        ),
        "reject_oversized_single",
        "oversized singles fail closed into retry/final-loss"
    );
    assert_eq!(
        ferrum_edge::_test_support::udp_logging_classify_dtls_batch_size_for_test(
            true,
            max + 1,
            2,
            max
        ),
        "split_per_entry",
        "oversized multi-entry batches fan out per entry without async recursion"
    );
}

#[test]
fn test_dtls_client_send_drain_continues_past_a_full_application_data_round() {
    assert!(
        ferrum_edge::_test_support::dtls_client_send_output_drain_needs_another_round_for_test(
            true, false, false, false, true,
        ),
        "a pending send hidden behind a full inbound-data round must keep draining"
    );
    for terminal in [
        (false, false, false, false, true),
        (true, true, false, false, true),
        (true, false, true, false, true),
        (true, false, false, true, true),
        (true, false, false, false, false),
    ] {
        assert!(
            !ferrum_edge::_test_support::dtls_client_send_output_drain_needs_another_round_for_test(
                terminal.0, terminal.1, terminal.2, terminal.3, terminal.4,
            ),
            "terminal or completed state must not spin another drain round: {terminal:?}"
        );
    }
}

#[test]
fn test_udp_logging_default_summary_remote_trigger_and_cobatch_split() {
    let max = 16_384usize;
    let mut oversized = create_test_transaction_summary();
    oversized.request_user_agent = Some("x".repeat(max));

    let (single_decision, single_len) =
        ferrum_edge::_test_support::udp_logging_classify_serialized_summaries_for_test(
            std::slice::from_ref(&oversized),
            max,
        )
        .expect("serialize default summary with admitted long User-Agent");
    assert!(single_len > max, "JSON framing must cross the DTLS ceiling");
    assert_eq!(single_decision, "reject_oversized_single");

    let ordinary = create_test_transaction_summary();
    let (batch_decision, batch_len) =
        ferrum_edge::_test_support::udp_logging_classify_serialized_summaries_for_test(
            &[oversized, ordinary],
            max,
        )
        .expect("serialize co-batched summaries");
    assert!(batch_len > max);
    assert_eq!(
        batch_decision, "split_per_entry",
        "one remotely oversized summary must not erase its ordinary sibling"
    );
}

#[tokio::test]
async fn test_dtls_connection_send_rejects_oversized_plaintext() {
    ensure_crypto_provider();
    let server_cert = dimpl::certificate::generate_self_signed_certificate().expect("server cert");
    let server_config = dimpl::Config::builder()
        .build()
        .expect("build server config");
    let frontend = ferrum_edge::dtls::FrontendDtlsConfig {
        dimpl_config: Arc::new(server_config),
        certificate: server_cert.into(),
        client_cert_verifier: None,
    };
    let server = Arc::new(
        ferrum_edge::dtls::DtlsServer::bind("127.0.0.1:0".parse().unwrap(), frontend)
            .await
            .expect("dtls server"),
    );
    let server_addr = server.local_addr();
    let runner = server.clone();
    tokio::spawn(async move {
        let _ = runner.run().await;
    });
    let acceptor = server.clone();
    let accept = tokio::spawn(async move {
        let (conn, _) = acceptor.accept().await.expect("accept");
        conn
    });

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    client_socket.connect(server_addr).await.expect("connect");
    let client_cert = dimpl::certificate::generate_self_signed_certificate().expect("client cert");
    let params = ferrum_edge::dtls::BackendDtlsParams {
        config: Arc::new(dimpl::Config::default()),
        certificate: client_cert.into(),
        server_name: None,
        server_cert_verifier: None,
        connect_timeout_ms: 10_000,
    };
    let client = ferrum_edge::dtls::DtlsConnection::connect(client_socket, params)
        .await
        .expect("handshake");
    let server_conn = accept.await.expect("join accept");

    let max = ferrum_edge::dtls::max_plaintext_bytes();
    let oversized = vec![b'x'; max.saturating_add(1)];
    let err = client
        .send(&oversized)
        .await
        .expect_err("oversized plaintext must fail");
    assert!(err.to_string().contains("max_plaintext"), "got: {err}");

    // Exact in-limit boundary must complete successfully.
    let exact = vec![b'y'; max];
    client
        .send(&exact)
        .await
        .expect("exact max_plaintext send must succeed");

    // Connection close must propagate as a send failure (not hang).
    server_conn.close().await;
    client.close().await;
    let close_deadline = Instant::now() + Duration::from_secs(1);
    let closed_err = loop {
        match tokio::time::timeout(Duration::from_millis(100), client.send(b"after-close")).await {
            Ok(Err(error)) => break error,
            Ok(Ok(())) | Err(_) if Instant::now() < close_deadline => {
                tokio::task::yield_now().await;
            }
            Ok(Ok(())) => panic!("send kept succeeding after local close"),
            Err(_) => panic!("send did not observe local close within 1s"),
        }
    };
    assert!(
        closed_err.to_string().contains("closed") || closed_err.to_string().contains("DTLS"),
        "close/cancel failure must propagate: {closed_err}"
    );

    // Hosted CI cannot safely force a specific OS UDP socket-send errno
    // (ENETUNREACH / EMSGSIZE / etc.) without flaky routing tricks; those
    // paths remain covered by the driver's socket-error branch mapping into
    // the same completion Err used above.
}

#[test]
fn test_udp_logging_dtls_loss_and_reset_classification() {
    assert_eq!(
        ferrum_edge::_test_support::udp_logging_dtls_send_timeout_secs_for_test(),
        10,
        "udp_logging DTLS send budget must stay aligned with the 10s connect budget"
    );
    assert!(
        ferrum_edge::_test_support::udp_logging_dtls_send_timeout_requires_sender_reset_for_test(),
        "DTLS send timeout is a transport failure and must reset the sender"
    );
    assert!(
        ferrum_edge::_test_support::udp_logging_local_dtls_size_rejection_preserves_sender_for_test(
        ),
        "deterministic local size rejection must preserve the sender"
    );
    assert!(
        ferrum_edge::_test_support::udp_logging_transport_dtls_failure_requires_sender_reset_for_test(),
        "transport/driver failure must reset the sender"
    );
}

#[test]
fn test_udp_logging_openapi_dtls_policy_contract() {
    let spec: Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/UdpLoggingConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("UdpLoggingConfig compiles");

    assert!(
        validator.is_valid(&json!({"host": "127.0.0.1", "port": 9514})),
        "plaintext without DTLS fields must validate"
    );
    assert!(
        validator.is_valid(&json!({
            "host": "logs.example.com",
            "port": 9514,
            "dtls": true,
            "dtls_no_verify": true
        })),
        "dtls true with no_verify must validate"
    );
    assert!(
        validator.is_valid(&json!({
            "host": "logs.example.com",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": "/c.pem",
            "dtls_key_path": "/k.pem"
        })),
        "paired cert/key with dtls true must validate"
    );
    assert!(
        validator.is_valid(&json!({"host": "2001:db8::10", "port": 9514})),
        "unbracketed IPv6 accepted by parse_socket_host must validate"
    );

    for invalid in [
        json!({"host": "127.0.0.1", "port": 9514, "dtls_no_verify": true}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls": false, "dtls_cert_path": "/c.pem", "dtls_key_path": "/k.pem"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls": true, "dtls_cert_path": "/c.pem"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls": true, "dtls_key_path": "/k.pem"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls": true, "dtls_cert_path": ""}),
        json!({"host": "udp://logs.example.com", "port": 9514}),
        json!({"host": "logs.example.com:9514", "port": 9514}),
        json!({"host": "", "port": 9514}),
    ] {
        assert!(
            !validator.is_valid(&invalid),
            "OpenAPI must reject {invalid}"
        );
    }
}

#[test]
fn test_udp_logging_docs_dns_and_delivery_contract() {
    let docs = include_str!("../../../docs/plugins.md");
    let section = docs
        .split("### `udp_logging`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("udp_logging section present");

    for needle in [
        "Both plain UDP and DTLS re-resolve",
        "fresh handshake",
        "current sender is retained",
        "local UDP socket",
        "FERRUM_DTLS_MAX_PLAINTEXT_BYTES",
        "split per entry",
        "co-batched siblings",
        "at-least-once",
        "OptionalFailOpen",
        "shape-only",
        "immutable for that plugin generation",
        "10-second completion budget",
        "requires `dtls: true`",
        "File mode",
        "Database mode",
        "DP mode",
    ] {
        assert!(
            section.contains(needle),
            "docs/plugins.md udp_logging section missing `{needle}`"
        );
    }
    assert!(
        !section.contains("DTLS sessions are not re-handshaken mid-session"),
        "stale DTLS non-rehandshake wording must be removed"
    );
}
