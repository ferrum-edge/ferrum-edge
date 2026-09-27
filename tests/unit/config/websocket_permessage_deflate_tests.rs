//! `websocket_permessage_deflate` proxy field: serde shape, per-proxy field
//! validation, and the plugin-graph admission gate that refuses `passthrough`
//! whenever a plugin requiring the parsed WebSocket relay is effective on the
//! proxy, while `terminate` keeps every plugin (issue #5769).

use ferrum_edge::_test_support::{
    collect_rejecting_runtime_config_errors_for_test,
    websocket_permessage_deflate_passthrough_errors_for_test,
};
use ferrum_edge::config::types::{
    BackendScheme, GatewayConfig, PluginConfig, Proxy, WebSocketPermessageDeflate,
};
use serde_json::{Value, json};

const PROXY_ID: &str = "chat";

fn proxy_json(mode: &str, plugin_ids: &[&str]) -> Value {
    let plugins: Vec<Value> = plugin_ids
        .iter()
        .map(|id| json!({ "plugin_config_id": id }))
        .collect();
    json!({
        "id": PROXY_ID,
        "listen_path": "/chat",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
        "websocket_permessage_deflate": mode,
        "plugins": plugins,
    })
}

fn proxy(mode: &str, plugin_ids: &[&str]) -> Proxy {
    serde_json::from_value(proxy_json(mode, plugin_ids)).expect("proxy JSON")
}

/// Minimal valid config for each plugin these tests attach.
fn plugin_body(name: &str) -> Value {
    match name {
        "waf" => json!({ "mode": "monitor" }),
        "ws_rate_limiting" => json!({ "frames_per_second": 100 }),
        "ws_message_size_limiting" => json!({ "max_frame_bytes": 65536 }),
        "key_auth" => json!({ "key_location": "header:x-api-key" }),
        _ => json!({}),
    }
}

fn plugin(id: &str, name: &str, scope: &str, enabled: bool) -> PluginConfig {
    let mut body = json!({
        "id": id,
        "plugin_name": name,
        "config": plugin_body(name),
        "scope": scope,
        "enabled": enabled,
    });
    if scope == "proxy" {
        body["proxy_id"] = json!(PROXY_ID);
    }
    serde_json::from_value(body).expect("plugin config JSON")
}

fn graph(proxy: Proxy, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        proxies: vec![proxy],
        plugin_configs,
        ..Default::default()
    }
}

fn assert_refused(config: &GatewayConfig, plugin_name: &str) {
    let errors = websocket_permessage_deflate_passthrough_errors_for_test(config);
    assert!(
        errors.iter().any(|error| {
            error.contains(PROXY_ID)
                && error.contains("websocket_permessage_deflate: passthrough")
                && error.contains(plugin_name)
        }),
        "passthrough with an effective {plugin_name} must be refused, got: {errors:?}"
    );
}

fn assert_admitted(config: &GatewayConfig) {
    let errors = websocket_permessage_deflate_passthrough_errors_for_test(config);
    assert!(errors.is_empty(), "unexpected refusal: {errors:?}");
}

fn mentions_field(errors: &[String]) -> bool {
    errors
        .iter()
        .any(|error| error.contains("websocket_permessage_deflate"))
}

#[test]
fn default_is_strip_and_is_not_serialized() {
    let mut body = proxy_json("strip", &[]);
    body.as_object_mut()
        .expect("proxy object")
        .remove("websocket_permessage_deflate");
    let proxy: Proxy = serde_json::from_value(body).expect("proxy JSON");
    assert!(proxy.websocket_permessage_deflate.is_strip());

    let rendered = serde_json::to_value(&proxy).expect("serialize proxy");
    assert!(
        rendered.get("websocket_permessage_deflate").is_none(),
        "the default must be omitted from serialized proxies: {rendered}"
    );
}

#[test]
fn passthrough_round_trips_and_unknown_values_are_rejected() {
    let proxy = proxy("passthrough", &[]);
    assert!(proxy.websocket_permessage_deflate.is_passthrough());
    let rendered = serde_json::to_value(&proxy).expect("serialize proxy");
    let mode = rendered["websocket_permessage_deflate"].as_str();
    assert_eq!(mode, Some("passthrough"));

    for bad in ["Terminate", "Passthrough", "deflate", ""] {
        let parsed = serde_json::from_value::<Proxy>(proxy_json(bad, &[]));
        assert!(parsed.is_err(), "{bad:?} must not deserialize");
    }

    let passthrough = WebSocketPermessageDeflate::Passthrough;
    let strip = WebSocketPermessageDeflate::Strip;
    assert_eq!(
        WebSocketPermessageDeflate::parse("passthrough"),
        Some(passthrough)
    );
    assert_eq!(WebSocketPermessageDeflate::parse("strip"), Some(strip));
    assert_eq!(WebSocketPermessageDeflate::parse("deflate"), None);
    assert_eq!(passthrough.as_str(), "passthrough");
    assert_eq!(strip.as_str(), "strip");
}

#[test]
fn terminate_round_trips_through_serde_and_the_sql_form() {
    let proxy = proxy("terminate", &[]);
    assert!(proxy.websocket_permessage_deflate.is_terminate());
    assert!(!proxy.websocket_permessage_deflate.is_passthrough());
    let rendered = serde_json::to_value(&proxy).expect("serialize proxy");
    let mode = rendered["websocket_permessage_deflate"].as_str();
    assert_eq!(mode, Some("terminate"));

    let terminate = WebSocketPermessageDeflate::Terminate;
    assert_eq!(terminate.as_str(), "terminate");
    assert_eq!(
        WebSocketPermessageDeflate::parse("terminate"),
        Some(terminate)
    );
    assert_eq!(WebSocketPermessageDeflate::parse("Terminate"), None);
}

#[test]
fn terminate_is_valid_on_http_proxies() {
    let result = proxy("terminate", &[]).validate_fields();
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn terminate_is_rejected_on_stream_proxies() {
    for scheme in [BackendScheme::Tcp, BackendScheme::Udp] {
        let mut proxy = proxy("terminate", &[]);
        proxy.listen_path = None;
        proxy.backend_scheme = Some(scheme);
        proxy.listen_port = Some(5432);
        let errors = proxy.validate_fields().unwrap_err();
        assert!(
            mentions_field(&errors),
            "{scheme:?} stream proxy must refuse terminate, got: {errors:?}"
        );
    }
}

#[test]
fn terminate_keeps_every_frame_plugin() {
    // Terminate inflates messages before the relay, so frame-parsing plugins
    // (the WAF included) keep working and are never refused.
    for name in [
        "waf",
        "ws_rate_limiting",
        "ws_frame_logging",
        "ws_message_size_limiting",
    ] {
        let global = plugin("global-1", name, "global", true);
        let config = graph(proxy("terminate", &[]), vec![global]);
        assert_admitted(&config);
        let errors = collect_rejecting_runtime_config_errors_for_test(&config);
        assert!(
            !mentions_field(&errors),
            "terminate next to {name} must load: {errors:?}"
        );
    }
    let waf = plugin("waf-1", "waf", "proxy", true);
    assert_admitted(&graph(proxy("terminate", &["waf-1"]), vec![waf]));
}

#[test]
fn passthrough_is_valid_on_http_proxies() {
    let result = proxy("passthrough", &[]).validate_fields();
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn passthrough_is_rejected_on_stream_proxies() {
    let schemes = [
        BackendScheme::Tcp,
        BackendScheme::Tcps,
        BackendScheme::Udp,
        BackendScheme::Dtls,
    ];
    for scheme in schemes {
        let mut proxy = proxy("passthrough", &[]);
        proxy.listen_path = None;
        proxy.backend_scheme = Some(scheme);
        proxy.listen_port = Some(5432);
        let errors = proxy.validate_fields().unwrap_err();
        assert!(
            mentions_field(&errors),
            "{scheme:?} stream proxy must refuse passthrough, got: {errors:?}"
        );

        proxy.websocket_permessage_deflate = WebSocketPermessageDeflate::Strip;
        let errors = proxy.validate_fields().err().unwrap_or_default();
        assert!(
            !mentions_field(&errors),
            "strip must stay valid on {scheme:?}: {errors:?}"
        );
    }
}

#[test]
fn passthrough_without_plugins_is_admitted() {
    assert_admitted(&graph(proxy("passthrough", &[]), vec![]));
}

#[test]
fn passthrough_refuses_directly_attached_waf() {
    let waf = plugin("waf-1", "waf", "proxy", true);
    let config = graph(proxy("passthrough", &["waf-1"]), vec![waf]);
    assert_refused(&config, "waf");
}

#[test]
fn passthrough_refuses_inherited_global_frame_plugins() {
    let names = [
        "waf",
        "ws_rate_limiting",
        "ws_frame_logging",
        "ws_message_size_limiting",
    ];
    for name in names {
        let global = plugin("global-1", name, "global", true);
        let config = graph(proxy("passthrough", &[]), vec![global]);
        assert_refused(&config, name);
    }
}

#[test]
fn passthrough_refuses_proxy_group_frame_plugin() {
    let group = plugin("group-1", "ws_message_size_limiting", "proxy_group", true);
    let config = graph(proxy("passthrough", &["group-1"]), vec![group]);
    assert_refused(&config, "ws_message_size_limiting");
}

#[test]
fn passthrough_ignores_plugins_that_do_not_apply() {
    // Disabled plugin configs never run.
    let disabled = plugin("global-off", "waf", "global", false);
    assert_admitted(&graph(proxy("passthrough", &[]), vec![disabled]));

    // A proxy-group instance the proxy does not associate with is not effective.
    let unassociated = plugin("group-2", "ws_rate_limiting", "proxy_group", true);
    assert_admitted(&graph(proxy("passthrough", &[]), vec![unassociated]));

    // Plugins that never parse WebSocket frames are compatible.
    let key_auth = plugin("auth-1", "key_auth", "proxy", true);
    assert_admitted(&graph(proxy("passthrough", &["auth-1"]), vec![key_auth]));
}

#[test]
fn strip_proxies_keep_every_plugin() {
    let global_waf = plugin("global-waf", "waf", "global", true);
    assert_admitted(&graph(proxy("strip", &[]), vec![global_waf]));
}

#[test]
fn passthrough_fails_closed_for_unevaluable_plugins() {
    let mystery = plugin("mystery", "__not_a_registered_plugin__", "proxy", true);
    let config = graph(proxy("passthrough", &["mystery"]), vec![mystery]);
    let errors = websocket_permessage_deflate_passthrough_errors_for_test(&config);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("could not be evaluated")),
        "an unknown plugin must refuse passthrough, got: {errors:?}"
    );
}

#[test]
fn runtime_config_validation_rejects_passthrough_with_frame_plugin() {
    let limiter = plugin("global-size", "ws_message_size_limiting", "global", true);
    let refused = graph(proxy("passthrough", &[]), vec![limiter.clone()]);
    let errors = collect_rejecting_runtime_config_errors_for_test(&refused);
    assert!(
        mentions_field(&errors),
        "file/database/CP validation must refuse the graph, got: {errors:?}"
    );

    let admitted = graph(proxy("strip", &[]), vec![limiter]);
    let errors = collect_rejecting_runtime_config_errors_for_test(&admitted);
    assert!(
        !mentions_field(&errors),
        "strip must not be refused: {errors:?}"
    );
}
