//! Tests for statsd_logging plugin

use chrono::Utc;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::utils::ByteBudget;
use ferrum_edge::plugins::utils::byte_budget::{
    DEFAULT_MAX_ENTRY_BYTES, HARD_MAX_BUFFER_MAX_BYTES, HARD_MAX_ENTRY_BYTES, MIN_MAX_ENTRY_BYTES,
    accounted_summary_bytes,
};
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Direction, Plugin, PluginFailurePolicy, PluginHttpClient, PluginResult,
    StreamTransactionSummary, WsDisconnectContext, plugin_failure_policy,
    statsd_logging::{
        MAX_UDP_PAYLOAD, STATSD_LOGGING_CONFIG_KEYS, StatsdLogging, bounded_grpc_status_tag,
        for_each_udp_datagram, format_http_metrics, format_ws_metrics, http_body_outcome,
        http_grpc_status_tag, is_valid_timer_sample, pack_udp_datagrams,
        render_http_under_budget_for_test, sanitize_namespace_tag_value, sanitize_tag_value,
        validate_tag_key,
    },
    validate_plugin_config,
};
use ferrum_edge::retry::ErrorClass;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::plugin_utils::{create_test_context, create_test_transaction_summary};

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn make_stream_summary() -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-proxy-1".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("TCP Test".to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: "tcp".to_string(),
        listen_port: 8080,
        duration_ms: 15.0,
        bytes_sent: 128,
        bytes_received: 256,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    }
}

#[tokio::test]
async fn test_statsd_logging_plugin_creation() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 8125
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
    assert_eq!(plugin.priority(), 9075);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[tokio::test]
async fn test_statsd_logging_missing_host() {
    let result = StatsdLogging::new(&json!({}), default_client());
    match result {
        Err(e) => assert!(e.contains("host"), "Expected error about host, got: {e}"),
        Ok(_) => panic!("Expected Err when creating statsd_logging without host"),
    }
}

#[tokio::test]
async fn test_statsd_logging_empty_host() {
    let result = StatsdLogging::new(&json!({"host": ""}), default_client());
    match result {
        Err(e) => assert!(e.contains("host")),
        Ok(_) => panic!("Expected Err for empty host"),
    }
}

#[tokio::test]
async fn test_statsd_logging_rejects_host_with_url_or_port_material() {
    for host in [
        "udp://statsd.example.com",
        "user@statsd.example.com",
        "statsd.example.com/path",
        "statsd.example.com?token=secret",
        "statsd.example.com#fragment",
        "statsd.example.com:8125",
        "bad host",
    ] {
        let result = StatsdLogging::new(&json!({"host": host}), default_client());
        assert!(result.is_err(), "host should fail validation: {host}");
    }
}

#[tokio::test]
async fn test_statsd_logging_invalid_port_zero() {
    let result = StatsdLogging::new(&json!({"host": "127.0.0.1", "port": 0}), default_client());
    match result {
        Err(e) => assert!(e.contains("port")),
        Ok(_) => panic!("Expected Err for port 0"),
    }
}

#[tokio::test]
async fn test_statsd_logging_invalid_port_too_high() {
    let result = StatsdLogging::new(
        &json!({"host": "127.0.0.1", "port": 99999}),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("port")),
        Ok(_) => panic!("Expected Err for port > 65535"),
    }
}

#[tokio::test]
async fn test_statsd_logging_invalid_scalar_types() {
    let cases = [
        json!(null),
        json!({"host": 127}),
        json!({"host": "127.0.0.1", "port": "8125"}),
        json!({"host": "127.0.0.1", "prefix": 42}),
        json!({"host": "127.0.0.1", "global_tags": []}),
        json!({"host": "127.0.0.1", "global_tags": {"env": true}}),
    ];

    for config in cases {
        assert!(
            StatsdLogging::new(&config, default_client()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_statsd_logging_rejects_malformed_and_out_of_range_batching() {
    let host = "127.0.0.1";
    for config in [
        json!({"host": host, "flush_interval_ms": null}),
        json!({"host": host, "flush_interval_ms": "60000"}),
        json!({"host": host, "flush_interval_ms": false}),
        json!({"host": host, "flush_interval_ms": []}),
        json!({"host": host, "flush_interval_ms": {}}),
        json!({"host": host, "flush_interval_ms": 49}),
        json!({"host": host, "flush_interval_ms": 600_001}),
        json!({"host": host, "buffer_capacity": null}),
        json!({"host": host, "buffer_capacity": false}),
        json!({"host": host, "buffer_capacity": 0}),
        json!({"host": host, "buffer_capacity": 1_000_001}),
        json!({"host": host, "max_batch_lines": null}),
        json!({"host": host, "max_batch_lines": []}),
        json!({"host": host, "max_batch_lines": 0}),
        json!({"host": host, "max_batch_lines": 10_001}),
        json!({"host": host, "max_retries": "1"}),
        json!({"host": host, "max_retries": -1}),
        json!({"host": host, "max_retries": 11}),
        json!({"host": host, "retry_delay_ms": true}),
        json!({"host": host, "retry_delay_ms": 60_001}),
    ] {
        let err = StatsdLogging::new(&config, default_client())
            .err()
            .unwrap_or_else(|| panic!("expected batching rejection for {config}"));
        assert!(
            err.contains("statsd_logging:"),
            "expected field-specific statsd error for {config}, got {err}"
        );
    }

    let valid_bounds = StatsdLogging::new(
        &json!({
            "host": host,
            "max_batch_lines": 1,
            "buffer_capacity": 1,
            "flush_interval_ms": 600_000,
            "max_retries": 10,
            "retry_delay_ms": 60_000
        }),
        default_client(),
    );
    if let Err(err) = valid_bounds {
        panic!("valid batching boundaries must be admitted: {err}");
    }
}

#[tokio::test]
async fn test_statsd_logging_empty_prefix_rejected() {
    let result = StatsdLogging::new(
        &json!({"host": "127.0.0.1", "prefix": "   "}),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("prefix")),
        Ok(_) => panic!("Expected Err for empty prefix"),
    }
}

#[tokio::test]
async fn test_statsd_logging_default_port() {
    // port defaults to 8125 when not specified
    let plugin = StatsdLogging::new(&json!({"host": "127.0.0.1"}), default_client()).unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_custom_prefix() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "prefix": "myapp.gateway"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_with_global_tags() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "global_tags": {
                "env": "prod",
                "region": "us-east-1"
            }
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_log_does_not_panic() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1
        }),
        default_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();

    // Should not panic — entry is queued and background task handles UDP send
    plugin.log(&summary).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_statsd_logging_stream_disconnect_does_not_panic() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1
        }),
        default_client(),
    )
    .unwrap();
    let summary = make_stream_summary();

    // Should not panic
    plugin.on_stream_disconnect(&summary).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_statsd_logging_default_lifecycle_phases() {
    let plugin = StatsdLogging::new(&json!({"host": "127.0.0.1"}), default_client()).unwrap();

    let mut ctx = create_test_context();
    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_statsd_logging_buffer_full_drops_gracefully() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "buffer_capacity": 5,
            "max_batch_lines": 1000,
            "flush_interval_ms": 60000
        }),
        default_client(),
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
async fn test_statsd_logging_accepts_all_config_options() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9125,
            "prefix": "gateway.edge",
            "global_tags": {"env": "staging", "dc": "us-west-2"},
            "flush_interval_ms": 1000,
            "buffer_capacity": 50000,
            "max_batch_lines": 100,
            "max_retries": 2,
            "retry_delay_ms": 25,
            "max_entry_bytes": 65536,
            "buffer_max_bytes": 16_777_216,
            "schema": {
                "summary_type": "both",
                "rename": { "proxy_id": "route_id" }
            }
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_warmup_hostnames() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "statsd.internal.example.com"
        }),
        default_client(),
    )
    .unwrap();
    let hosts = plugin.warmup_hostnames();
    assert_eq!(hosts, vec!["statsd.internal.example.com".to_string()]);
}

#[tokio::test]
async fn test_statsd_logging_warmup_skips_ip_literals() {
    for host in ["127.0.0.1", "2001:db8::10", "[2001:db8::10]"] {
        let plugin = StatsdLogging::new(&json!({"host": host}), default_client()).unwrap();
        assert!(
            plugin.warmup_hostnames().is_empty(),
            "IP literal {host} should not be DNS-warmed"
        );
    }
}

#[tokio::test]
async fn test_statsd_logging_accepts_rename_and_omit_schema() {
    // rename + omit are supported; construction succeeds without warnings.
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "schema": {
                "summary_type": "http",
                "rename": { "proxy_id": "route_id" },
                "omit": ["response_status_code"]
            }
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_accepts_unsupported_schema_keys_with_warning() {
    // static_fields / metadata / timestamp_format / order / derived_fields
    // are no-ops for statsd, but construction still succeeds — the plugin
    // just emits a `warn!` for visibility. Verify here that they do not
    // hard-error.
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "schema": {
                "summary_type": "http",
                "static_fields": { "env": "prod" },
                "derived_fields": [{ "name": "outcome", "kind": "outcome" }],
                "order": ["*"],
                "timestamp_format": "epoch_ms",
                "metadata": { "mode": "omit" }
            }
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_rejects_one_character_misspellings_of_every_key() {
    assert_eq!(
        plugin_failure_policy("statsd_logging"),
        Some(PluginFailurePolicy::OptionalFailOpen)
    );

    let typos = [
        ("host", "hos"),
        ("port", "prot"),
        ("prefix", "prefx"),
        ("global_tags", "global_tgas"),
        ("flush_interval_ms", "flush_interval_m"),
        ("buffer_capacity", "buffer_capacit"),
        ("buffer_max_bytes", "buffer_max_byte"),
        ("max_batch_lines", "max_batch_line"),
        ("max_entry_bytes", "max_entry_byte"),
        ("max_retries", "max_retrie"),
        ("retry_delay_ms", "retry_delay_m"),
        ("schema", "schemaa"),
        ("schema_ref", "schema_reff"),
    ];
    assert_eq!(
        typos.len(),
        STATSD_LOGGING_CONFIG_KEYS.len(),
        "every recognized key needs a one-character misspelling case"
    );

    for (canonical, typo) in typos {
        assert!(
            STATSD_LOGGING_CONFIG_KEYS.contains(&canonical),
            "typo fixture must target a recognized key: {canonical}"
        );
        let mut config = json!({"host": "statsd.example.test"});
        config
            .as_object_mut()
            .unwrap()
            .insert(typo.to_string(), json!(1));
        let err = StatsdLogging::new(&config, default_client())
            .err()
            .unwrap_or_else(|| panic!("expected unknown-key rejection for {typo}"));
        assert!(err.contains("unknown configuration key"), "got: {err}");
        assert!(err.contains(typo), "error must name the typo key: {err}");
        assert!(
            err.contains("allowed keys"),
            "error must list the allowed-key contract: {err}"
        );
        for key in STATSD_LOGGING_CONFIG_KEYS {
            assert!(err.contains(key), "missing allowed key {key} in: {err}");
        }

        let shared = validate_plugin_config("statsd_logging", &config)
            .expect_err("shared admission must reject the same typo");
        assert!(shared.contains(typo), "got: {shared}");
    }
}

#[tokio::test]
async fn test_statsd_logging_rejects_multiple_unknown_keys_with_sorted_names() {
    let err = StatsdLogging::new(
        &json!({
            "host": "statsd.example.test",
            "zzz_extra": true,
            "aaa_extra": false
        }),
        default_client(),
    )
    .err()
    .expect("multiple unknown keys must be rejected");
    assert!(err.contains("aaa_extra"), "got: {err}");
    assert!(err.contains("zzz_extra"), "got: {err}");
    let aaa = err.find("aaa_extra").expect("aaa_extra present");
    let zzz = err.find("zzz_extra").expect("zzz_extra present");
    assert!(
        aaa < zzz,
        "unknown keys should be sorted in the error: {err}"
    );
}

#[tokio::test]
async fn test_statsd_logging_valid_complete_config_and_open_global_tags_map() {
    let config = json!({
        "host": "statsd.example.test",
        "port": 9125,
        "prefix": "edge.prod",
        "global_tags": {
            "env": "prod",
            "region": "us-east-1",
            "custom_dimension": "ok"
        },
        "flush_interval_ms": 250,
        "buffer_capacity": 2048,
        "max_batch_lines": 10,
        "max_retries": 1,
        "retry_delay_ms": 5,
        "max_entry_bytes": 8192,
        "buffer_max_bytes": 65536,
        "schema": {
            "summary_type": "stream",
            "omit": ["disconnect_cause"]
        }
    });
    assert!(StatsdLogging::new(&config, default_client()).is_ok());
    assert!(validate_plugin_config("statsd_logging", &config).is_ok());
}

#[test]
fn test_statsd_logging_disabled_config_skips_construction_validation() {
    let mut gateway = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            id: "statsd-disabled".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "statsd_logging".to_string(),
            config: json!({"prot": 9125}),
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
        .expect("disabled statsd_logging must skip unknown-key validation");
}

#[tokio::test]
async fn test_statsd_logging_optional_fail_open_on_file_mode_load_and_cache_rebuild() {
    use ferrum_edge::config::types::Proxy;

    let policy = ferrum_edge::config::BackendEgressPolicy::unrestricted();
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "p1",
        "listen_path": "/api",
        "backend_host": "localhost",
        "backend_port": 3000,
        "backend_scheme": "http"
    }))
    .expect("minimal proxy deserializes");

    let bad_plugin = PluginConfig {
        id: "statsd-typo".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "statsd_logging".to_string(),
        config: json!({"host": "statsd.example.test", "prot": 9125}),
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
        .expect("OptionalFailOpen statsd typos warn but do not abort file-mode load");

    let omitted = PluginCache::new(&bad_gateway)
        .expect("cache construction must omit the failed optional statsd plugin");
    assert!(
        omitted.get_plugins("p1").is_empty(),
        "unknown-key statsd_logging must be omitted, not silently defaulted"
    );

    let valid_gateway = GatewayConfig {
        proxies: vec![proxy],
        plugin_configs: vec![PluginConfig {
            config: json!({"host": "statsd.example.test", "port": 9125}),
            ..bad_plugin
        }],
        ..GatewayConfig::default()
    };
    let cache = PluginCache::new(&valid_gateway).expect("valid statsd config constructs");
    assert_eq!(cache.get_plugins("p1").len(), 1);
    assert_eq!(cache.get_plugins("p1")[0].name(), "statsd_logging");

    cache
        .rebuild(&bad_gateway)
        .expect("OptionalFailOpen reload omits bad statsd rather than rejecting the generation");
    assert!(
        cache.get_plugins("p1").is_empty(),
        "reload with unknown keys must drop the previously published statsd instance"
    );
}

#[test]
fn test_statsd_metric_docs_inventory_and_byte_directions() {
    let docs = include_str!("../../../docs/plugins.md");
    let statsd_section = docs
        .split("### `statsd_logging`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("statsd_logging section present in docs/plugins.md");

    for needle in [
        "request.client_disconnect",
        "request.body_incomplete",
        "request.grpc_status.{code}",
        "body_outcome",
        "`grpc_status` composition",
        "websocket.session.count",
        "websocket.session.duration_ms",
        "Mirror accounting",
        "1452-byte",
        "no-backend sentinel",
        "stream.disconnect",
        "client→backend",
        "backend→client",
        "last-observation",
        "idle_timeout",
        "recv_error",
        "backend_error",
        "graceful_shutdown",
        "client_to_backend",
        "backend_to_client",
        "max_retries",
        "retry_delay_ms",
        "OptionalFailOpen",
        "reserved runtime tags",
    ] {
        assert!(
            statsd_section.contains(needle),
            "statsd docs missing `{needle}`"
        );
    }
    assert!(
        !statsd_section.contains("Bytes sent to client"),
        "reversed byte direction must not remain in the StatsD reference"
    );
    assert!(
        !statsd_section.contains("Bytes received from client"),
        "reversed byte direction must not remain in the StatsD reference"
    );
}

#[test]
fn test_statsd_mirror_summaries_excluded_from_request_metrics() {
    let mut primary = create_test_transaction_summary();
    primary.mirror = false;
    primary.response_status_code = 200;
    primary.body_completed = true;
    primary.latency_backend_ttfb_ms = 15.0;

    let mut mirror = primary.clone();
    mirror.mirror = true;
    mirror.response_status_code = 0;

    let mut buf = String::new();
    format_http_metrics(&primary, "ferrum", "", None, &mut buf);
    format_http_metrics(&mirror, "ferrum", "", None, &mut buf);

    assert_eq!(
        buf.matches("ferrum.request.count:1|c").count(),
        1,
        "mirror must not double client request.count: {buf}"
    );
    assert!(
        !buf.contains("status:0"),
        "mirror transport failure must not export status:0: {buf}"
    );
}

#[test]
fn test_statsd_backend_ttfb_sentinel_and_timer_validity() {
    assert!(!is_valid_timer_sample(-1.0));
    assert!(!is_valid_timer_sample(f64::NAN));
    assert!(!is_valid_timer_sample(f64::INFINITY));
    assert!(is_valid_timer_sample(0.0));
    assert!(is_valid_timer_sample(1.25));

    let mut summary = create_test_transaction_summary();
    summary.latency_backend_ttfb_ms = -1.0;
    summary.latency_total_ms = 8.0;
    summary.body_completed = true;
    let mut buf = String::new();
    format_http_metrics(&summary, "edge", "", None, &mut buf);
    assert!(buf.contains("edge.request.count:1|c"), "{buf}");
    assert!(buf.contains("edge.request.status."), "{buf}");
    assert!(
        !buf.contains("latency_backend_ttfb_ms"),
        "no-backend sentinel must be omitted: {buf}"
    );
    assert!(buf.contains("latency_total_ms:8.00|ms"), "{buf}");
}

#[test]
fn test_statsd_terminal_body_failure_keeps_header_status() {
    let mut summary = create_test_transaction_summary();
    summary.response_status_code = 200;
    summary.response_streamed = true;
    summary.body_completed = false;
    summary.body_error_class = Some(ErrorClass::ResponseBodyTooLarge);
    summary.latency_backend_ttfb_ms = 5.0;
    assert_eq!(http_body_outcome(&summary), "incomplete");

    let mut buf = String::new();
    format_http_metrics(&summary, "ferrum", "", None, &mut buf);
    assert!(buf.contains("status:200"), "{buf}");
    assert!(buf.contains("status_class:2xx"), "{buf}");
    assert!(buf.contains("body_outcome:incomplete"), "{buf}");
    assert!(buf.contains("body_error:response_body_too_large"), "{buf}");
    assert!(buf.contains("request.body_incomplete:1|c"), "{buf}");
}

#[test]
fn test_statsd_bounded_grpc_status_tag_contract() {
    for (status, expected) in [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(bounded_grpc_status_tag(status as u32), expected);
    }
    assert_eq!(bounded_grpc_status_tag(17), "OTHER");
    assert_eq!(bounded_grpc_status_tag(u32::MAX), "OTHER");

    let mut plain = create_test_transaction_summary();
    plain.response_status_code = 200;
    assert_eq!(http_grpc_status_tag(&plain), None);

    let mut grpc = plain.clone();
    grpc.metadata
        .insert("request_protocol".to_string(), "grpc".to_string());
    // Missing terminal status on a known gRPC transaction → UNKNOWN (2).
    assert_eq!(http_grpc_status_tag(&grpc), Some("2"));
    grpc.metadata
        .insert("grpc_status".to_string(), "bad".to_string());
    assert_eq!(http_grpc_status_tag(&grpc), Some("OTHER"));
}

#[test]
fn test_statsd_terminal_grpc_status_across_buffered_streamed_h2_h3_and_rejection() {
    // Summary shapes mirror the upstream terminal grpc_status propagation
    // contract (buffered H2, trailers-only/streamed H2, native H3, gateway
    // rejection). StatsD consumes the authoritative summary value only.
    for (case, streamed, body_completed, status, rejection, expected) in [
        ("buffered_h2_ok", false, true, Some("0"), false, "0"),
        (
            "buffered_h2_unavailable",
            false,
            true,
            Some("14"),
            false,
            "14",
        ),
        ("trailers_only_h2_ok", true, true, Some("0"), false, "0"),
        ("streamed_h2_error", true, true, Some("14"), false, "14"),
        ("native_h3_ok", true, true, Some("0"), false, "0"),
        ("native_h3_internal", true, true, Some("13"), false, "13"),
        ("gateway_rejection", false, true, Some("16"), true, "16"),
        ("missing_terminal_unknown", true, true, None, false, "2"),
        (
            "malformed_terminal_other",
            true,
            true,
            Some("bad"),
            false,
            "OTHER",
        ),
    ] {
        let mut summary = create_test_transaction_summary();
        summary.http_method = "POST".to_string();
        summary.response_status_code = 200;
        summary.response_streamed = streamed;
        summary.body_completed = body_completed;
        summary.latency_backend_ttfb_ms = 5.0;
        summary
            .metadata
            .insert("request_protocol".to_string(), "grpc".to_string());
        if let Some(status) = status {
            summary
                .metadata
                .insert("grpc_status".to_string(), status.to_string());
        }
        if rejection {
            summary
                .metadata
                .insert("rejection_phase".to_string(), "authorize".to_string());
        }

        let mut buf = String::new();
        format_http_metrics(&summary, "ferrum", "", None, &mut buf);
        assert!(
            buf.contains("status:200") && buf.contains("status_class:2xx"),
            "{case}: HTTP status must stay distinct: {buf}"
        );
        assert!(
            buf.contains(&format!("grpc_status:{expected}")),
            "{case}: missing bounded grpc_status tag: {buf}"
        );
        assert!(
            buf.contains(&format!("ferrum.request.grpc_status.{expected}:1|c")),
            "{case}: missing grpc_status counter: {buf}"
        );
        assert!(
            buf.contains("ferrum.request.status.2xx:1|c"),
            "{case}: HTTP status-class counter must remain: {buf}"
        );
    }

    let mut plain = create_test_transaction_summary();
    plain.response_status_code = 200;
    plain.body_completed = true;
    let mut buf = String::new();
    format_http_metrics(&plain, "ferrum", "", None, &mut buf);
    assert!(
        !buf.contains("grpc_status"),
        "plain HTTP must omit grpc_status tag/counter: {buf}"
    );
}

#[tokio::test]
async fn test_statsd_websocket_session_metrics_and_opt_in() {
    let plugin = StatsdLogging::new(&json!({"host": "127.0.0.1"}), default_client()).unwrap();
    assert!(plugin.requires_ws_disconnect_hooks());

    let ctx = WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "ws-proxy".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("WS Proxy".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "http://127.0.0.1:9000/".to_string(),
        listen_port: 8080,
        duration_ms: 2500.0,
        frames_client_to_backend: 2,
        frames_backend_to_client: 3,
        bytes_client_to_backend: 20,
        bytes_backend_to_client: 30,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: Some(Direction::BackendToClient),
        io_side: Some(ferrum_edge::proxy::tcp_proxy::StreamIoSide::Read),
        error_class: Some(ErrorClass::ReadWriteTimeout),
        consumer_username: None,
        auth_method: None,
        connection_id: 0,
        metadata: HashMap::new(),
    };
    let mut buf = String::new();
    format_ws_metrics(&ctx, "ferrum", "", None, &mut buf);
    assert!(buf.contains("websocket.session.count:1|c"), "{buf}");
    assert!(buf.contains("result:error"), "{buf}");
    assert!(buf.contains("error_class:read_write_timeout"), "{buf}");
    assert!(buf.contains("direction:backend_to_client"), "{buf}");
    assert!(buf.contains("io_side:read"), "{buf}");
    assert!(
        !buf.contains("request.latency_total_ms"),
        "WS session metrics must not mix into HTTP latency families: {buf}"
    );
}

#[test]
fn test_statsd_namespace_tag_collision_resistance_and_reserved_keys() {
    let a = format!("{}tenant-a", "n".repeat(64));
    let b = format!("{}tenant-b", "n".repeat(64));
    assert_ne!(
        sanitize_namespace_tag_value(&a),
        sanitize_namespace_tag_value(&b)
    );
    assert!(sanitize_namespace_tag_value(&a).contains("tenant-a"));

    assert!(validate_tag_key("env").is_ok());
    assert!(validate_tag_key("method\nrogue").is_err());
    assert!(validate_tag_key("bad:key").is_err());
    assert_eq!(sanitize_tag_value("x\0y\x1bz"), "x_y_z");
    // Representative ASCII + Unicode control values (NUL / ESC / BEL / NEL).
    assert_eq!(sanitize_tag_value("a\0b\x1bc\x07d\u{0085}e"), "a_b_c_d_e");
}

#[tokio::test]
async fn test_statsd_rejects_reserved_and_injecting_global_tags() {
    for (config, needle) in [
        (
            json!({"host": "127.0.0.1", "global_tags": {"namespace": "victim"}}),
            "reserved",
        ),
        (
            json!({"host": "127.0.0.1", "global_tags": {"status": "spoof"}}),
            "reserved",
        ),
        (
            json!({"host": "127.0.0.1", "global_tags": {"grpc_status": "spoof"}}),
            "reserved",
        ),
        // Case-insensitive reserved-key collision.
        (
            json!({"host": "127.0.0.1", "global_tags": {"Status": "spoof"}}),
            "reserved",
        ),
        (
            json!({"host": "127.0.0.1", "global_tags": {"Grpc_Status": "spoof"}}),
            "reserved",
        ),
        (
            json!({"host": "127.0.0.1", "global_tags": {"NAMESPACE": "victim"}}),
            "reserved",
        ),
        // Post-normalization duplicate keys (Env / env).
        (
            json!({"host": "127.0.0.1", "global_tags": {"Env": "a", "env": "b"}}),
            "duplicate",
        ),
        (
            json!({"host": "127.0.0.1", "global_tags": {"evil\nkey": "x"}}),
            "tag key",
        ),
        (
            json!({"host": "127.0.0.1", "global_tags": {" env ": "prod"}}),
            "whitespace",
        ),
        (
            json!({
                "host": "127.0.0.1",
                "schema": {
                    "summary_type": "http",
                    "rename": {"http_method": "method\nrogue.metric:1|c\nx"}
                }
            }),
            "tag key",
        ),
        (
            json!({
                "host": "127.0.0.1",
                "schema": {
                    "summary_type": "http",
                    "rename": {"http_method": " method "}
                }
            }),
            "whitespace",
        ),
        // Native-field collision is fail-closed by the shared schema compiler.
        (
            json!({
                "host": "127.0.0.1",
                "schema": {
                    "summary_type": "http",
                    "rename": {"proxy_id": "namespace"}
                }
            }),
            "duplicate",
        ),
        // StatsD-reserved tag that is not a native summary out_key.
        (
            json!({
                "host": "127.0.0.1",
                "schema": {
                    "summary_type": "http",
                    "rename": {"proxy_id": "status_class"}
                }
            }),
            "reserved",
        ),
        // Case-insensitive reserved rename target.
        (
            json!({
                "host": "127.0.0.1",
                "schema": {
                    "summary_type": "http",
                    "rename": {"proxy_id": "Status_Class"}
                }
            }),
            "reserved",
        ),
        // A custom rename becomes runtime-owned for this sink and must not be
        // duplicated by a collector-global tag with ambiguous precedence.
        (
            json!({
                "host": "127.0.0.1",
                "global_tags": {"route_id": "spoof"},
                "schema": {
                    "summary_type": "http",
                    "rename": {"proxy_id": "route_id"}
                }
            }),
            "runtime tag",
        ),
    ] {
        let err = StatsdLogging::new(&config, default_client())
            .err()
            .unwrap_or_else(|| panic!("expected rejection for {config}"));
        assert!(
            err.to_lowercase().contains(needle) || err.contains("characters"),
            "expected '{needle}' in: {err}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_statsd_grpc_status_collector_visible_for_h2_h3_shapes() {
    // Collector-visible evidence that OK vs non-OK gRPC outcomes remain
    // distinguishable under HTTP 200 for the summary shapes produced by
    // buffered H2, trailers-only/streamed H2, and native H3 paths.
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind collector");
    let port = socket.local_addr().expect("local addr").port();

    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": port,
            "prefix": "ferrum",
            "flush_interval_ms": 50,
            "max_batch_lines": 1
        }),
        default_client(),
    )
    .expect("construct statsd");
    plugin.start_background_tasks().expect("start statsd");
    plugin.commit_background_tasks();

    let cases = [
        ("buffered_h2", false, true, "0"),
        ("buffered_h2", false, true, "14"),
        ("trailers_only_h2", true, true, "0"),
        ("streamed_h2", true, true, "14"),
        ("native_h3", true, true, "0"),
        ("native_h3", true, true, "13"),
    ];

    for (case, streamed, body_completed, status) in cases {
        let mut summary = create_test_transaction_summary();
        summary.http_method = "POST".to_string();
        summary.response_status_code = 200;
        summary.response_streamed = streamed;
        summary.body_completed = body_completed;
        summary.latency_backend_ttfb_ms = 7.0;
        summary
            .metadata
            .insert("request_protocol".to_string(), "grpc".to_string());
        summary
            .metadata
            .insert("grpc_status".to_string(), status.to_string());
        plugin.log(&summary).await;

        let mut buf = [0u8; 2048];
        let (n, _) = timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {case} grpc_status={status}"))
            .expect("receive statsd datagram");
        assert!(n <= MAX_UDP_PAYLOAD, "datagram exceeded ceiling: {n}");
        let payload = std::str::from_utf8(&buf[..n]).expect("utf8");
        assert!(
            payload.contains("status:200") && payload.contains("status_class:2xx"),
            "{case}/{status}: HTTP tags must remain: {payload}"
        );
        assert!(
            payload.contains(&format!("grpc_status:{status}")),
            "{case}/{status}: collector must see grpc_status tag: {payload}"
        );
        assert!(
            payload.contains(&format!("ferrum.request.grpc_status.{status}:1|c")),
            "{case}/{status}: collector must see grpc_status counter: {payload}"
        );
    }
}

#[tokio::test]
async fn test_statsd_udp_payload_ceiling_and_collector_capture() {
    // Use Tokio UDP + bounded timeouts so the default single-thread test
    // runtime cannot starve the batching task behind a blocking recv_from.
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind collector");
    let port = socket.local_addr().expect("local addr").port();

    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": port,
            "prefix": "ferrum",
            "flush_interval_ms": 50,
            "max_batch_lines": 1
        }),
        default_client(),
    )
    .expect("construct statsd");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let mut summary = create_test_transaction_summary();
    summary.body_completed = true;
    summary.latency_backend_ttfb_ms = 11.0;
    plugin.log(&summary).await;

    let mut mirror = summary.clone();
    mirror.mirror = true;
    plugin.log(&mirror).await;

    let mut buf = [0u8; 2048];
    let (n, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("timed out waiting for statsd datagram")
        .expect("receive statsd datagram");
    assert!(n <= MAX_UDP_PAYLOAD, "datagram exceeded ceiling: {n}");
    let payload = std::str::from_utf8(&buf[..n]).expect("utf8");
    assert!(payload.contains("ferrum.request.count:1|c"), "{payload}");
    assert!(
        payload.contains("namespace:ferrum"),
        "authoritative namespace tag must be present: {payload}"
    );
    // Mirror must not produce a second client datagram with ordinary request metrics.
    // Bounded absence window; timeout (no datagram) is success.
    let second = timeout(Duration::from_millis(200), socket.recv_from(&mut buf)).await;
    if let Ok(Ok((n2, _))) = second {
        let extra = std::str::from_utf8(&buf[..n2]).unwrap_or("");
        panic!("unexpected second datagram after mirror skip: {extra}");
    }

    let over = "m".repeat(MAX_UDP_PAYLOAD + 1);
    let (dgrams, dropped) = pack_udp_datagrams(&over, MAX_UDP_PAYLOAD);
    assert_eq!(dropped, 1);
    assert!(dgrams.is_empty());
    let exact = "e".repeat(MAX_UDP_PAYLOAD);
    let (dgrams, dropped) = pack_udp_datagrams(&exact, MAX_UDP_PAYLOAD);
    assert_eq!(dropped, 0);
    assert_eq!(dgrams[0].len(), MAX_UDP_PAYLOAD);
}

#[tokio::test]
async fn test_statsd_ws_disconnect_collector_emits_session_once() {
    // #2555 composition evidence: core H1 Upgrade, H2 Extended CONNECT, and
    // native H3 paths already dispatch `on_ws_disconnect` exactly once to
    // plugins that return `requires_ws_disconnect_hooks()` (gateway_core
    // websocket tunnel / relay / http3 websocket coverage). This test proves
    // statsd_logging opts in and formats the terminal websocket.* set into
    // one collector-visible datagram — without duplicating those harnesses.
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind collector");
    let port = socket.local_addr().expect("local addr").port();

    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": port,
            "prefix": "ferrum",
            "flush_interval_ms": 50,
            "max_batch_lines": 16
        }),
        default_client(),
    )
    .expect("construct statsd");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    assert!(
        plugin.requires_ws_disconnect_hooks(),
        "statsd_logging must opt into terminal WS disconnect dispatch"
    );

    let ctx = WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "ws-1".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("WS".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "http://127.0.0.1:9/".to_string(),
        listen_port: 8080,
        duration_ms: 42.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 2,
        bytes_client_to_backend: 10,
        bytes_backend_to_client: 20,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        connection_id: 0,
        metadata: HashMap::new(),
    };
    plugin.on_ws_disconnect(&ctx).await;

    let mut buf = [0u8; 2048];
    let (n, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("timed out waiting for websocket statsd datagram")
        .expect("receive websocket statsd datagram");
    assert!(n <= MAX_UDP_PAYLOAD, "datagram exceeded ceiling: {n}");
    let payload = std::str::from_utf8(&buf[..n]).expect("utf8");
    assert_eq!(
        payload
            .matches("ferrum.websocket.session.count:1|c")
            .count(),
        1,
        "terminal WS session count must appear exactly once: {payload}"
    );
    assert!(
        payload.contains("ferrum.websocket.session.duration_ms:42.00|ms"),
        "{payload}"
    );
    assert!(
        !payload.contains("request.latency_total_ms"),
        "WS session metrics must not mix into HTTP latency families: {payload}"
    );

    let second = timeout(Duration::from_millis(200), socket.recv_from(&mut buf)).await;
    if let Ok(Ok((n2, _))) = second {
        let extra = std::str::from_utf8(&buf[..n2]).unwrap_or("");
        panic!("unexpected second datagram after single WS disconnect: {extra}");
    }
}

#[tokio::test]
async fn test_statsd_logging_byte_budget_config_validation_fail_closed() {
    let host = "127.0.0.1";
    let below_min = StatsdLogging::new(
        &json!({
            "host": host,
            "max_entry_bytes": MIN_MAX_ENTRY_BYTES - 1
        }),
        default_client(),
    )
    .expect_err("max_entry_bytes below minimum");
    assert!(below_min.contains("max_entry_bytes"), "got: {below_min}");

    let above_hard = StatsdLogging::new(
        &json!({
            "host": host,
            "max_entry_bytes": HARD_MAX_ENTRY_BYTES + 1
        }),
        default_client(),
    )
    .expect_err("max_entry_bytes above hard max");
    assert!(above_hard.contains("max_entry_bytes"), "got: {above_hard}");

    let buffer_too_small = StatsdLogging::new(
        &json!({
            "host": host,
            "max_entry_bytes": 2048,
            "buffer_max_bytes": 1024
        }),
        default_client(),
    )
    .expect_err("buffer_max_bytes below accounted minimum");
    assert!(
        buffer_too_small.contains("buffer_max_bytes"),
        "got: {buffer_too_small}"
    );

    let buffer_above_hard = StatsdLogging::new(
        &json!({
            "host": host,
            "buffer_max_bytes": HARD_MAX_BUFFER_MAX_BYTES + 1
        }),
        default_client(),
    )
    .expect_err("buffer_max_bytes above hard max");
    assert!(
        buffer_above_hard.contains("buffer_max_bytes"),
        "got: {buffer_above_hard}"
    );

    let defaults = StatsdLogging::new(&json!({ "host": host }), default_client()).unwrap();
    assert_eq!(defaults.max_entry_bytes_for_test(), DEFAULT_MAX_ENTRY_BYTES);
}

#[tokio::test]
async fn test_statsd_logging_saturation_rejects_before_retention() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "buffer_capacity": 16,
            "max_batch_lines": 1000,
            "flush_interval_ms": 60_000,
            "max_entry_bytes": 1024,
            "buffer_max_bytes": accounted_summary_bytes(1024)
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let held = plugin
        .hold_byte_budget_for_test(accounted_summary_bytes(1024))
        .expect("fill aggregate budget");
    let drops_before = plugin.byte_budget_drops_for_test();
    let used_before = plugin.byte_budget_used_for_test();

    plugin.log(&create_test_transaction_summary()).await;

    assert_eq!(
        plugin.byte_budget_used_for_test(),
        used_before,
        "saturated admission must not retain additional content"
    );
    assert!(
        plugin.byte_budget_drops_for_test() > drops_before,
        "saturation must record a fail-closed drop"
    );
    drop(held);
    assert_eq!(plugin.byte_budget_used_for_test(), 0);
}

#[test]
fn test_statsd_logging_oversized_render_releases_lease() {
    let budget = ByteBudget::new("statsd_logging_test", accounted_summary_bytes(1024));
    let mut summary = create_test_transaction_summary();
    summary.proxy_name = Some("proxy".to_string());
    let prefix = "a".repeat(256);
    let mut global = String::from("|#");
    // Build a global_tags suffix that forces rendered lines over 1024 bytes.
    while global.len() < 380 {
        global.push_str("env:production,");
    }
    global.push_str("namespace:ferrum");

    let drops_before = budget.drops_total();
    let rejected =
        render_http_under_budget_for_test(&budget, 1024, &summary, &prefix, &global, None);
    assert!(
        rejected.is_none(),
        "oversized render must fail closed before retention"
    );
    assert_eq!(budget.used(), 0, "oversized render must release its lease");
    assert!(budget.drops_total() > drops_before);
}

#[test]
fn test_statsd_logging_admitted_payload_releases_on_drop() {
    let budget = ByteBudget::new("statsd_logging_test", 1_048_576);
    let summary = create_test_transaction_summary();
    let admitted = render_http_under_budget_for_test(
        &budget,
        DEFAULT_MAX_ENTRY_BYTES,
        &summary,
        "ferrum",
        "",
        None,
    )
    .expect("normal summary must admit");
    assert!(!admitted.as_str().is_empty());
    assert!(!admitted.as_bytes().is_empty());
    let expected = accounted_summary_bytes(admitted.retained_len());
    assert_eq!(budget.used(), expected);
    drop(admitted);
    assert_eq!(
        budget.used(),
        0,
        "drop must release the retained-byte lease"
    );
}

#[tokio::test]
async fn test_statsd_logging_failed_reserve_does_not_take_lease() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "buffer_capacity": 2,
            "max_batch_lines": 1000,
            "flush_interval_ms": 60_000
        }),
        default_client(),
    )
    .unwrap();
    // Stage the worker without committing so it never drains; the channel
    // fills and further admits fail on reserve before taking a byte lease.
    plugin.start_background_tasks().expect("live start");

    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
    plugin.log(&summary).await;
    let used_when_full = plugin.byte_budget_used_for_test();
    assert!(used_when_full > 0, "queued admits must hold leases");

    let drops_before = plugin.byte_budget_drops_for_test();
    plugin.log(&summary).await;
    assert!(
        plugin.byte_budget_drops_for_test() > drops_before,
        "queue saturation must record a drop"
    );
    assert_eq!(
        plugin.byte_budget_used_for_test(),
        used_when_full,
        "failed reserve must not retain additional content"
    );
}

#[test]
fn test_statsd_logging_for_each_udp_datagram_stays_mtu_safe() {
    let line_a = "a".repeat(700);
    let line_b = "b".repeat(700);
    let payload = format!("{line_a}\n{line_b}");
    let mut seen = Vec::new();
    let dropped = for_each_udp_datagram(&payload, MAX_UDP_PAYLOAD, |datagram| {
        assert!(datagram.len() <= MAX_UDP_PAYLOAD);
        seen.push(datagram.to_string());
    });
    assert_eq!(dropped, 0);
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], line_a);
    assert_eq!(seen[1], line_b);

    let over = "x".repeat(MAX_UDP_PAYLOAD + 8);
    let mixed = format!("short:1|c\n{over}\nother:1|c");
    let mut kept = Vec::new();
    let dropped = for_each_udp_datagram(&mixed, MAX_UDP_PAYLOAD, |datagram| {
        assert!(datagram.len() <= MAX_UDP_PAYLOAD);
        kept.push(datagram.to_string());
    });
    assert_eq!(dropped, 1);
    let joined = kept.join("\n");
    assert!(joined.contains("short:1|c"));
    assert!(joined.contains("other:1|c"));
    assert!(!joined.contains(&over));
}
