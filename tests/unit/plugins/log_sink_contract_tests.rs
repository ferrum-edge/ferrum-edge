//! One contract for every log sink (issue #7144).
//!
//! Every log sink emits WebSocket session-end records through
//! `on_ws_disconnect` and is registered `KeepLastKnownGood`, so an invalid
//! log-sink config never silently drops the sink: it fails file-mode load and
//! the initial cache, and a reload keeps the previous generation. The
//! per-sink delivery of the session-end record is pinned in each sink's own
//! test file (`*_logging_tests.rs`); this file is the parity table that fails
//! when a new log sink joins without the contract.

use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope, Proxy};
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::builtin_parity::builtin_plugin_parity_meta;
use ferrum_edge::plugins::{
    BUILTIN_PLUGIN_REGISTRATIONS, PluginFailurePolicy, plugin_failure_policy,
};
use ferrum_edge::time_compat::UtcTimestamp;
use serde_json::{Value, json};

/// Every built-in log sink. A registered plugin named `*_logging` that is
/// missing here fails `the_log_sink_table_is_complete`.
const LOG_SINKS: &[&str] = &[
    "stdout_logging",
    "http_logging",
    "tcp_logging",
    "udp_logging",
    "kafka_logging",
    "loki_logging",
    "statsd_logging",
    "ws_logging",
    "ws_frame_logging",
];

/// A minimal constructible config for each sink. None of them dials anything
/// at construction.
fn valid_config(name: &str) -> Value {
    match name {
        "stdout_logging" | "ws_frame_logging" => json!({}),
        "http_logging" => json!({"endpoint_url": "http://127.0.0.1:9/logs"}),
        "tcp_logging" | "udp_logging" => json!({"host": "127.0.0.1", "port": 9}),
        "kafka_logging" => json!({"broker_list": "127.0.0.1:9092", "topic": "ferrum-logs"}),
        "loki_logging" => json!({"endpoint_url": "http://127.0.0.1:9/loki/api/v1/push"}),
        "statsd_logging" => json!({"host": "127.0.0.1", "port": 8125}),
        "ws_logging" => json!({"endpoint_url": "ws://127.0.0.1:9/logs"}),
        other => panic!("no valid config for log sink {other}"),
    }
}

/// The same config with an unknown root key: every plugin config is closed
/// (issue #6616), so this is a construction failure for every sink.
fn invalid_config(name: &str) -> Value {
    let mut config = valid_config(name);
    config
        .as_object_mut()
        .expect("log sink config is an object")
        .insert("not_a_config_key".to_string(), json!(true));
    config
}

fn proxy() -> Proxy {
    serde_json::from_value(json!({
        "id": "p1",
        "listen_path": "/api",
        "backend_host": "localhost",
        "backend_port": 3000,
        "backend_scheme": "http"
    }))
    .expect("minimal proxy deserializes")
}

fn gateway_with(name: &str, config: Value) -> GatewayConfig {
    GatewayConfig {
        proxies: vec![proxy()],
        plugin_configs: vec![PluginConfig {
            labels: Default::default(),
            id: format!("{name}-instance"),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: name.to_string(),
            config,
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: UtcTimestamp::now(),
            updated_at: UtcTimestamp::now(),
        }],
        ..GatewayConfig::default()
    }
}

fn published_names(cache: &PluginCache) -> Vec<String> {
    cache
        .get_plugins("ferrum", "p1")
        .iter()
        .map(|plugin| plugin.name().to_string())
        .collect()
}

#[test]
fn the_log_sink_table_is_complete() {
    let registered: Vec<&str> = BUILTIN_PLUGIN_REGISTRATIONS
        .iter()
        .map(|registration| registration.name)
        .filter(|name| name.ends_with("_logging"))
        .collect();
    for name in &registered {
        assert!(
            LOG_SINKS.contains(name),
            "{name} is a log sink; add it to LOG_SINKS so it carries the #7144 contract"
        );
    }
    for name in LOG_SINKS {
        assert!(
            registered.contains(name),
            "{name} is not a registered plugin"
        );
    }
}

#[test]
fn every_log_sink_is_keep_last_known_good() {
    for name in LOG_SINKS {
        assert_eq!(
            plugin_failure_policy(name),
            Some(PluginFailurePolicy::KeepLastKnownGood),
            "{name}: a log sink must be KeepLastKnownGood (issue #7144)"
        );
    }
}

#[tokio::test]
async fn every_log_sink_runs_the_ws_session_end_hook() {
    for name in LOG_SINKS {
        let phases = builtin_plugin_parity_meta(name)
            .unwrap_or_else(|| panic!("{name}: parity metadata"))
            .active_phases;
        assert!(
            phases.contains("on_ws_disconnect"),
            "{name}: documented phases must include on_ws_disconnect, got {phases:?}"
        );

        let cache = PluginCache::new(&gateway_with(name, valid_config(name)))
            .unwrap_or_else(|error| panic!("{name}: valid config must construct: {error}"));
        let plugins = cache.get_plugins("ferrum", "p1");
        assert_eq!(plugins.len(), 1, "{name}");
        assert!(
            plugins[0].requires_ws_disconnect_hooks(),
            "{name}: must receive on_ws_disconnect for every WebSocket session"
        );
    }
}

#[tokio::test]
async fn every_log_sink_rejects_an_invalid_config_and_keeps_the_previous_generation() {
    let policy = ferrum_edge::config::BackendEgressPolicy::unrestricted();
    for name in LOG_SINKS {
        let mut bad = gateway_with(name, invalid_config(name));

        // `ferrum-edge validate` / file-mode load.
        assert!(
            ferrum_edge::_test_support::validate_plugin_configs_fatal_for_test(&mut bad, &policy)
                .is_err(),
            "{name}: an invalid log sink must fail file-mode load"
        );

        // Startup: there is no previous cache to keep.
        assert!(
            PluginCache::new(&bad).is_err(),
            "{name}: an invalid log sink must reject the initial cache, not omit the sink"
        );

        // Reload: the candidate is refused and the published sink survives.
        let cache = PluginCache::new(&gateway_with(name, valid_config(name)))
            .unwrap_or_else(|error| panic!("{name}: valid config must construct: {error}"));
        assert_eq!(published_names(&cache), vec![name.to_string()]);
        assert!(
            cache.rebuild(&bad).is_err(),
            "{name}: a reload with an invalid log sink must be rejected"
        );
        assert_eq!(
            published_names(&cache),
            vec![name.to_string()],
            "{name}: the rejected reload keeps the previous generation's sink"
        );
    }
}
