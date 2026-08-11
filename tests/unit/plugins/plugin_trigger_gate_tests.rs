//! Runtime behavior of the declarative per-instance execution trigger, through
//! the real `PluginCache` publication path.
//!
//! Covers: absent-trigger parity, request/stream gating, decide-once
//! memoization, phase safety at the authentication boundary, no-work and
//! no-buffering on skip, global/proxy/proxy-group scopes, multiple instances,
//! priority and ordering preservation, reload/publication, and the fail-closed
//! composition refusals.
//!
//! The pure schema/compilation layer lives in
//! `tests/unit/config/plugin_trigger_tests.rs`.

use chrono::Utc;
use ferrum_edge::_test_support::{
    attach_stream_trigger_decisions_for_test, final_request_body_requirements_for_test,
    set_request_http_flavor_for_test, set_request_wire_protocol_for_test,
    validate_plugin_composition_candidate_with_real_ip_header_for_test,
};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, HttpFlavor, HttpWireTransport,
    PluginConfig, PluginScope, Proxy,
};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, RequestContext, StreamConnectionContext,
    StreamFrontendTransport, StreamTransactionSummary,
};
use ferrum_edge::proxy::run_authentication_phase;
use ferrum_edge::{PluginCache, PluginCapabilities};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::{make_plugin_config_with_json, make_proxy, minimal_plugin_config};

const NS: &str = "ferrum";

/// A `request_transformer` instance whose only observable effect is adding one
/// request header in `before_proxy` — a precise probe for "did this instance
/// run at all".
fn header_stamper(
    id: &str,
    scope: PluginScope,
    proxy_id: Option<&str>,
    header: &str,
) -> PluginConfig {
    make_plugin_config_with_json(
        id,
        "request_transformer",
        json!({"rules": [{
            "operation": "add", "target": "header", "key": header, "value": "1"
        }]}),
        scope,
        proxy_id,
    )
}

fn builtin(id: &str, plugin_name: &str, proxy_id: &str) -> PluginConfig {
    make_plugin_config_with_json(
        id,
        plugin_name,
        minimal_plugin_config(plugin_name),
        PluginScope::Proxy,
        Some(proxy_id),
    )
}

fn with_trigger(mut pc: PluginConfig, trigger: serde_json::Value) -> PluginConfig {
    pc.trigger = Some(serde_json::from_value(trigger).expect("trigger parses"));
    pc
}

fn stream_proxy(id: &str, scheme: BackendScheme, port: u16, plugin_ids: Vec<&str>) -> Proxy {
    let mut proxy = make_proxy(id, "/unused", plugin_ids);
    proxy.listen_path = None;
    proxy.listen_port = Some(port);
    proxy.backend_scheme = Some(scheme);
    proxy.dispatch_kind = DispatchKind::from(scheme);
    proxy
}

fn config(proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        plugin_configs,
        loaded_at: Utc::now(),
        ..Default::default()
    }
}

fn request(method: &str, path: &str) -> RequestContext {
    request_from(method, path, "10.1.2.3", HttpWireTransport::Http2)
}

/// A request carrying the representation a JSON body policy actually governs,
/// so "would this instance buffer" is a real question rather than a vacuous no.
fn json_request(method: &str, path: &str) -> RequestContext {
    let mut ctx = request(method, path);
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx
}

fn request_from(
    method: &str,
    path: &str,
    client_ip: &str,
    transport: HttpWireTransport,
) -> RequestContext {
    let mut ctx = RequestContext::new(client_ip.to_string(), method.to_string(), path.to_string());
    set_request_wire_protocol_for_test(&mut ctx, transport, false);
    ctx
}

/// Run the whole published chain's `on_request_received` then `before_proxy`,
/// exactly as the dispatchers do, and return the resulting header map.
async fn run_request(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
) -> HashMap<String, String> {
    for plugin in plugins {
        plugin.on_request_received(ctx).await;
    }
    let mut headers = HashMap::new();
    for plugin in plugins {
        plugin.before_proxy(ctx, &mut headers).await;
    }
    headers
}

fn published(config: &GatewayConfig, proxy_id: &str) -> Vec<Arc<dyn Plugin>> {
    let cache = PluginCache::new(config).expect("plugin cache builds");
    cache.get_plugins(NS, proxy_id).as_ref().clone()
}

// ---------------------------------------------------------------------------
// Absent trigger preserves existing behavior
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_absent_trigger_leaves_the_instance_running_for_every_request() {
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![header_stamper(
                "stamp",
                PluginScope::Proxy,
                Some("api"),
                "x-stamp",
            )],
        ),
        "api",
    );

    for (method, path) in [("GET", "/api/health"), ("POST", "/api/orders")] {
        let mut ctx = request(method, path);
        let headers = run_request(&plugins, &mut ctx).await;
        assert_eq!(headers.get("x-stamp").map(String::as_str), Some("1"));
        assert!(
            !ctx.metadata
                .keys()
                .any(|key| key.starts_with("plugin_trigger.")),
            "an untriggered instance must not record trigger metadata"
        );
    }
}

// ---------------------------------------------------------------------------
// Request gating
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_matching_trigger_runs_the_instance_and_a_non_matching_one_skips_it() {
    let gated = with_trigger(
        header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
        json!({"when": {"all": [
            {"match": {"method": ["POST", "PUT"]}},
            {"match": {"path": {"prefix": ["/api/orders"]}}}
        ]}}),
    );
    let plugins = published(
        &config(vec![make_proxy("api", "/api", vec!["stamp"])], vec![gated]),
        "api",
    );

    let mut hit = request("POST", "/api/orders/42");
    assert_eq!(
        run_request(&plugins, &mut hit)
            .await
            .get("x-stamp")
            .map(String::as_str),
        Some("1")
    );
    assert!(!hit.metadata.contains_key("plugin_trigger.stamp.skipped"));

    let mut method_miss = request("GET", "/api/orders/42");
    assert!(run_request(&plugins, &mut method_miss).await.is_empty());
    assert_eq!(
        method_miss
            .metadata
            .get("plugin_trigger.stamp.skipped")
            .map(String::as_str),
        Some("true"),
        "a skip records exactly one bounded, redacted metadata pair"
    );

    let mut path_miss = request("POST", "/api/health");
    assert!(run_request(&plugins, &mut path_miss).await.is_empty());
}

#[tokio::test]
async fn header_query_and_cookie_predicates_read_the_live_request() {
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"any": [
                    {"match": {"header": {"name": "X-Debug", "value": {"exact": ["on"]}}}},
                    {"match": {"query": {"name": "debug"}}},
                    {"match": {"cookie": {"name": "debug", "value": {"exact": ["1"]}}}}
                ]}}),
            )],
        ),
        "api",
    );

    let mut header_hit = request("GET", "/api");
    header_hit
        .headers
        .insert("x-debug".to_string(), "on".to_string());
    assert!(!run_request(&plugins, &mut header_hit).await.is_empty());

    let mut query_hit = request("GET", "/api");
    query_hit.set_raw_query_string("debug=&other=1".to_string());
    assert!(!run_request(&plugins, &mut query_hit).await.is_empty());

    let mut cookie_hit = request("GET", "/api");
    cookie_hit
        .headers
        .insert("cookie".to_string(), "a=b; debug=1".to_string());
    assert!(!run_request(&plugins, &mut cookie_hit).await.is_empty());

    let mut miss = request("GET", "/api");
    miss.headers
        .insert("x-debug".to_string(), "off".to_string());
    assert!(run_request(&plugins, &mut miss).await.is_empty());
}

#[tokio::test]
async fn protocol_predicates_read_frontend_transport_and_http_flavor() {
    let trigger_specs = [
        ("h1", "http1", "x-h1"),
        ("h2", "http2", "x-h2"),
        ("h3", "http3", "x-h3"),
        ("grpc", "grpc", "x-grpc"),
        ("grpc-web", "grpc_web", "x-grpc-web"),
        ("websocket", "websocket", "x-websocket"),
    ];
    let plugins = published(
        &config(
            vec![make_proxy(
                "api",
                "/api",
                trigger_specs.iter().map(|(id, _, _)| *id).collect(),
            )],
            trigger_specs
                .iter()
                .map(|(id, protocol, header)| {
                    with_trigger(
                        header_stamper(id, PluginScope::Proxy, Some("api"), header),
                        json!({"when": {"match": {"protocol": [protocol]}}}),
                    )
                })
                .collect(),
        ),
        "api",
    );

    let h1 = request_from("GET", "/api", "10.1.2.3", HttpWireTransport::Http1);

    let mut native_grpc = request_from("POST", "/api", "10.1.2.3", HttpWireTransport::Http2);
    set_request_http_flavor_for_test(&mut native_grpc, HttpFlavor::Grpc);

    let mut grpc_web = request_from("POST", "/api", "10.1.2.3", HttpWireTransport::Http3);
    set_request_wire_protocol_for_test(&mut grpc_web, HttpWireTransport::Http3, true);

    let mut websocket = request_from("GET", "/api", "10.1.2.3", HttpWireTransport::Http1);
    set_request_http_flavor_for_test(&mut websocket, HttpFlavor::WebSocket);

    for (mut ctx, expected) in [
        (h1, &["x-h1"][..]),
        (native_grpc, &["x-h2", "x-grpc"][..]),
        (grpc_web, &["x-h3", "x-grpc-web"][..]),
        (websocket, &["x-h1", "x-websocket"][..]),
    ] {
        let headers = run_request(&plugins, &mut ctx).await;
        for (_, _, header) in trigger_specs {
            assert_eq!(
                headers.contains_key(header),
                expected.contains(&header),
                "unexpected protocol-trigger result for {header}: {headers:?}"
            );
        }
    }
}

#[tokio::test]
async fn source_cidr_predicates_read_the_gateway_resolved_client_ip() {
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"not": {"match": {"source_cidr": ["10.0.0.0/8"]}}}}),
            )],
        ),
        "api",
    );

    let mut internal = request_from("GET", "/api", "10.7.7.7", HttpWireTransport::Http2);
    assert!(run_request(&plugins, &mut internal).await.is_empty());

    let mut external = request_from("GET", "/api", "203.0.113.9", HttpWireTransport::Http2);
    assert!(!run_request(&plugins, &mut external).await.is_empty());
}

#[tokio::test]
async fn an_unrepresentable_query_pair_can_never_match_a_replacement_character() {
    // A lossy percent-decoder turns `%FF` into U+FFFD, so this trigger would
    // MATCH a hostile byte sequence the client never spelled that way.
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"match": {"query": {
                    "name": "q", "value": {"exact": ["\u{FFFD}"]}
                }}}}),
            )],
        ),
        "api",
    );

    let mut invalid = request("GET", "/api");
    invalid.set_raw_query_string("q=%FF".to_string());
    assert!(
        run_request(&plugins, &mut invalid).await.is_empty(),
        "invalid percent-decoded UTF-8 must not be coerced into a replacement character"
    );

    // A client that genuinely sends U+FFFD (properly percent-encoded) still
    // matches, so the rule is about representability, not about the character.
    let mut genuine = request("GET", "/api");
    genuine.set_raw_query_string("q=%EF%BF%BD".to_string());
    assert!(!run_request(&plugins, &mut genuine).await.is_empty());
}

#[tokio::test]
async fn an_unrepresentable_query_pair_fails_closed_to_running_under_not() {
    // "run unless the client sent q=<U+FFFD>". Under a lossy decoder `q=%FF`
    // satisfies the inner leaf, the `not` inverts it, and the instance is
    // SKIPPED — a hostile byte sequence switching a policy instance off.
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"not": {"match": {"query": {
                    "name": "q", "value": {"exact": ["\u{FFFD}"]}
                }}}}}),
            )],
        ),
        "api",
    );

    let mut invalid = request("GET", "/api");
    invalid.set_raw_query_string("q=%FF".to_string());
    assert!(
        !run_request(&plugins, &mut invalid).await.is_empty(),
        "an unrepresentable pair must not be able to switch an instance off"
    );
    assert!(
        !invalid
            .metadata
            .contains_key("plugin_trigger.stamp.skipped")
    );
}

#[tokio::test]
async fn unrepresentable_query_components_preserve_safe_scan_and_presence_semantics() {
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"match": {"query": {
                    "name": "q", "value": {"exact": ["ok"]}
                }}}}),
            )],
        ),
        "api",
    );

    // The malformed pair comes FIRST; the scan must step over it and still see
    // the representable `q=ok` behind it.
    let mut mixed = request("GET", "/api");
    mixed.set_raw_query_string("%FF=zzz&q=ok".to_string());
    assert!(!run_request(&plugins, &mut mixed).await.is_empty());

    // Once the name is decoded, occurrence is authoritative even when the value
    // is not text. It satisfies bare presence but no value comparison.
    let presence = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"match": {"query": {"name": "q"}}}}),
            )],
        ),
        "api",
    );
    let mut invalid = request("GET", "/api");
    invalid.set_raw_query_string("q=%FF".to_string());
    assert!(!run_request(&presence, &mut invalid).await.is_empty());

    let absent = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"match": {"query": {
                    "name": "q", "presence": "absent"
                }}}}),
            )],
        ),
        "api",
    );
    let mut invalid = request("GET", "/api");
    invalid.set_raw_query_string("q=%FF".to_string());
    assert!(run_request(&absent, &mut invalid).await.is_empty());
}

#[tokio::test]
async fn a_non_utf8_header_value_remains_present_but_matches_no_text() {
    let plugins = published(
        &config(
            vec![make_proxy(
                "api",
                "/api",
                vec!["present", "value", "absent"],
            )],
            vec![
                with_trigger(
                    header_stamper("present", PluginScope::Proxy, Some("api"), "x-present"),
                    json!({"when": {"match": {"header": {"name": "authorization"}}}}),
                ),
                with_trigger(
                    header_stamper("value", PluginScope::Proxy, Some("api"), "x-value"),
                    json!({"when": {"match": {"header": {
                        "name": "authorization", "value": {"regex": ".*"}
                    }}}}),
                ),
                with_trigger(
                    header_stamper("absent", PluginScope::Proxy, Some("api"), "x-absent"),
                    json!({"when": {"match": {"header": {
                        "name": "authorization", "presence": "absent"
                    }}}}),
                ),
            ],
        ),
        "api",
    );
    let mut raw = hyper::HeaderMap::new();
    raw.insert(
        hyper::header::AUTHORIZATION,
        hyper::header::HeaderValue::from_bytes(&[0xff]).expect("obs-text header value"),
    );
    let mut ctx = request("GET", "/api");
    ctx.set_raw_headers(raw);

    let headers = run_request(&plugins, &mut ctx).await;
    assert_eq!(headers.get("x-present").map(String::as_str), Some("1"));
    assert!(!headers.contains_key("x-value"));
    assert!(!headers.contains_key("x-absent"));
}

#[tokio::test]
async fn a_cookie_with_a_non_utf8_value_remains_present_but_matches_no_text() {
    let plugins = published(
        &config(
            vec![make_proxy(
                "api",
                "/api",
                vec!["present", "value", "absent"],
            )],
            vec![
                with_trigger(
                    header_stamper("present", PluginScope::Proxy, Some("api"), "x-present"),
                    json!({"when": {"match": {"cookie": {"name": "session"}}}}),
                ),
                with_trigger(
                    header_stamper("value", PluginScope::Proxy, Some("api"), "x-value"),
                    json!({"when": {"match": {"cookie": {
                        "name": "session", "value": {"regex": ".*"}
                    }}}}),
                ),
                with_trigger(
                    header_stamper("absent", PluginScope::Proxy, Some("api"), "x-absent"),
                    json!({"when": {"match": {"cookie": {
                        "name": "session", "presence": "absent"
                    }}}}),
                ),
            ],
        ),
        "api",
    );
    let mut raw = hyper::HeaderMap::new();
    raw.insert(
        hyper::header::COOKIE,
        hyper::header::HeaderValue::from_bytes(b"other=ok; session=\xff")
            .expect("obs-text cookie value"),
    );
    let mut ctx = request("GET", "/api");
    ctx.set_raw_headers(raw);

    let headers = run_request(&plugins, &mut ctx).await;
    assert_eq!(headers.get("x-present").map(String::as_str), Some("1"));
    assert!(!headers.contains_key("x-value"));
    assert!(!headers.contains_key("x-absent"));
}

// ---------------------------------------------------------------------------
// Decide-once
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_trigger_decision_is_memoized_so_a_later_rewrite_cannot_flip_it() {
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"match": {"path": {"prefix": ["/api/orders"]}}}}),
            )],
        ),
        "api",
    );

    // Decided TRUE at `on_request_received`; a route override then rewrites the
    // path to something the predicate would reject. The instance must still run.
    let mut ctx = request("GET", "/api/orders/42");
    for plugin in &plugins {
        plugin.on_request_received(&mut ctx).await;
    }
    ctx.path = "/internal/rewritten".to_string();
    let mut headers = HashMap::new();
    for plugin in &plugins {
        plugin.before_proxy(&mut ctx, &mut headers).await;
    }
    assert_eq!(headers.get("x-stamp").map(String::as_str), Some("1"));

    // Decided FALSE first; a rewrite into the matching prefix must not resurrect
    // the instance for a later phase.
    let mut ctx = request("GET", "/api/health");
    for plugin in &plugins {
        plugin.on_request_received(&mut ctx).await;
    }
    ctx.path = "/api/orders/42".to_string();
    let mut headers = HashMap::new();
    for plugin in &plugins {
        plugin.before_proxy(&mut ctx, &mut headers).await;
    }
    assert!(headers.is_empty(), "a memoized skip must stay a skip");
}

// ---------------------------------------------------------------------------
// Phase safety at the authentication boundary
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_identity_predicate_does_not_gate_hooks_before_authentication() {
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"match": {"consumer": {"value": {"exact": ["alice"]}}}}}),
            )],
        ),
        "api",
    );

    // No identity has been established when `on_request_received` runs, so the
    // pre-auth phase must NOT memoize a skip — that would be a fail-open gate.
    let mut ctx = request("GET", "/api");
    for plugin in &plugins {
        plugin.on_request_received(&mut ctx).await;
    }
    assert!(
        !ctx.metadata.contains_key("plugin_trigger.stamp.skipped"),
        "pre-auth evaluation of an identity predicate must not record a decision"
    );

    // The `before_proxy` (post-auth) phase is where the real decision is taken.
    ctx.authenticated_identity = Some("alice".to_string());
    let mut headers = HashMap::new();
    for plugin in &plugins {
        plugin.before_proxy(&mut ctx, &mut headers).await;
    }
    assert_eq!(headers.get("x-stamp").map(String::as_str), Some("1"));

    let mut other = request("GET", "/api");
    other.authenticated_identity = Some("mallory".to_string());
    let mut headers = HashMap::new();
    for plugin in &plugins {
        plugin.before_proxy(&mut other, &mut headers).await;
    }
    assert!(headers.is_empty());
}

// ---------------------------------------------------------------------------
// No work / no buffering on skip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_skipped_instance_does_not_request_request_body_buffering() {
    let gated = with_trigger(
        builtin("validate", "body_validator", "api"),
        json!({"when": {"match": {"path": {"prefix": ["/api/orders"]}}}}),
    );
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["validate"])],
            vec![gated],
        ),
        "api",
    );
    let plugin = plugins.first().expect("one published instance");

    let mut hit = json_request("POST", "/api/orders");
    plugin.on_request_received(&mut hit).await;
    assert!(
        plugin.should_buffer_request_body(&hit),
        "a running body policy still buffers its configured representation"
    );

    let mut miss = json_request("POST", "/api/health");
    plugin.on_request_received(&mut miss).await;
    assert!(
        !plugin.should_buffer_request_body(&miss),
        "a skipped instance must not force trigger-only body buffering"
    );
}

#[tokio::test]
async fn a_capability_predicate_fails_closed_to_running_before_any_decision_exists() {
    let gated = with_trigger(
        builtin("validate", "body_validator", "api"),
        json!({"when": {"match": {"path": {"prefix": ["/never"]}}}}),
    );
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["validate"])],
            vec![gated],
        ),
        "api",
    );
    let plugin = plugins.first().expect("one published instance");

    // No hook has run, so no decision is memoized. The read-only predicate must
    // report "runs" rather than silently suppressing a guard.
    let unresolved = json_request("POST", "/api/orders");
    assert!(plugin.should_buffer_request_body(&unresolved));
}

#[tokio::test]
async fn a_trigger_forces_context_aware_dispatch_for_contextless_request_body_hooks() {
    let rewrite = with_trigger(
        make_plugin_config_with_json(
            "rewrite",
            "request_transformer",
            json!({"rules": [{
                "operation": "add", "target": "body", "key": "gated", "value": "yes"
            }]}),
            PluginScope::Proxy,
            Some("api"),
        ),
        json!({"when": {"match": {"path": {"prefix": ["/api/orders"]}}}}),
    );
    let cache = PluginCache::new(&config(
        vec![make_proxy("api", "/api", vec!["rewrite"])],
        vec![rewrite],
    ))
    .expect("triggered request transformer publishes");
    let capabilities = cache.get_capabilities(NS, "api", ProxyProtocol::Http);
    assert!(
        capabilities.has(PluginCapabilities::NEEDS_FINAL_REQUEST_BODY_CONTEXT),
        "a trigger needs RequestContext even when the inner body hook uses the compatibility API"
    );
    let plugins = cache.get_plugins_for_protocol(NS, "api", ProxyProtocol::Http);
    let plugin = plugins.first().expect("one published instance");
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    let mut running = request("POST", "/api/orders/42");
    plugin.on_request_received(&mut running).await;
    let transformed = plugin
        .transform_request_body_with_context(
            &mut running,
            br#"{}"#,
            Some("application/json"),
            &headers,
        )
        .await
        .expect("matching trigger runs the inner contextless transform");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&transformed).expect("transformed JSON"),
        json!({"gated": "yes"})
    );

    let mut skipped = request("POST", "/api/health");
    plugin.on_request_received(&mut skipped).await;
    assert!(
        plugin
            .transform_request_body_with_context(
                &mut skipped,
                br#"{}"#,
                Some("application/json"),
                &headers,
            )
            .await
            .is_none(),
        "the context-aware wrapper must suppress a contextless inner body transform on skip"
    );
}

#[tokio::test]
async fn another_body_plugin_cannot_strand_a_skipped_trigger_on_contextless_dispatch() {
    let decompress = make_plugin_config_with_json(
        "decompress",
        "compression",
        json!({"decompress_request": true}),
        PluginScope::Proxy,
        Some("api"),
    );
    let rewrite = with_trigger(
        make_plugin_config_with_json(
            "rewrite",
            "request_transformer",
            json!({"rules": [{
                "operation": "add", "target": "body", "key": "gated", "value": "yes"
            }]}),
            PluginScope::Proxy,
            Some("api"),
        ),
        json!({"when": {"match": {"path": {"prefix": ["/api/orders"]}}}}),
    );
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["decompress", "rewrite"])],
        vec![decompress, rewrite],
    );
    let cache = PluginCache::new(&cfg).expect("mixed body chain publishes");
    let plugins = cache.get_plugins_for_protocol(NS, "api", ProxyProtocol::Http);
    let mut skipped = request("POST", "/api/public");
    skipped
        .headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    for plugin in plugins.iter() {
        plugin.on_request_received(&mut skipped).await;
    }

    let capabilities = cache.get_capabilities(NS, "api", ProxyProtocol::Http);
    let requirements = final_request_body_requirements_for_test(
        plugins.as_ref(),
        &skipped,
        true,
        false,
        capabilities.has(PluginCapabilities::NEEDS_FINAL_REQUEST_BODY_CONTEXT),
        false,
    );
    assert!(requirements.0, "compression must still require buffering");
    assert!(
        requirements.2,
        "a buffered mixed chain must keep RequestContext so the skipped transform remains gated"
    );
}

#[test]
fn a_triggered_response_presentation_policy_disables_finalized_replay() {
    let a2a = make_plugin_config_with_json(
        "a2a",
        "a2a_gateway",
        json!({"discovery": {"public_base_url": "https://agents.example.com"}}),
        PluginScope::Proxy,
        Some("api"),
    );
    let plain = config(
        vec![make_proxy("api", "/api", vec!["a2a"])],
        vec![a2a.clone()],
    );
    assert!(
        PluginCache::new(&plain)
            .expect("static presentation policy publishes")
            .request_view(NS, "api", ProxyProtocol::Http)
            .response_presentation_policy_digest()
            .is_some(),
        "a configured public base is normally a provable static presentation policy"
    );

    let triggered = config(
        vec![make_proxy("api", "/api", vec!["a2a"])],
        vec![with_trigger(
            a2a,
            json!({"when": {"match": {"sni": {"exact": ["agents.example.com"]}}}}),
        )],
    );
    assert!(
        PluginCache::new(&triggered)
            .expect("triggered presentation plugin publishes fail closed")
            .request_view(NS, "api", ProxyProtocol::Http)
            .response_presentation_policy_digest()
            .is_none(),
        "a finalized replay key does not prove the per-request trigger decision"
    );
}

fn html_response_headers() -> HashMap<String, String> {
    HashMap::from([("content-type".to_string(), "text/html".to_string())])
}

/// The five `should_release_response_body_*` votes, in declaration order:
/// under_retries, before_content_type_rewrite, for_later_no_transform,
/// for_simulated_final_headers, for_later_strong_etag.
fn release_votes(
    plugin: &Arc<dyn Plugin>,
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
) -> [bool; 5] {
    [
        plugin.should_release_response_body_under_retries(ctx, 200, headers),
        plugin.should_release_response_body_before_content_type_rewrite(ctx, 200, headers),
        plugin.should_release_response_body_for_later_no_transform(ctx, 200, headers),
        plugin.should_release_response_body_for_simulated_final_headers(ctx, 200, headers),
        plugin.should_release_response_body_for_later_strong_etag(ctx, 200, headers),
    ]
}

/// The five `should_release_response_body_*` predicates. The proxy folds them
/// with `all(...)` and only consults an instance that answered
/// `should_buffer_response_body == true`, so `true` — not `false` — is the
/// no-contribution answer for a skipped instance: it must neither need the body
/// retained nor pin the response to the buffered path.
#[tokio::test]
async fn a_skipped_instance_contributes_no_response_body_release_decision() {
    let gated = with_trigger(
        make_plugin_config_with_json(
            "validate",
            "body_validator",
            json!({"response_required_fields": ["approved"]}),
            PluginScope::Proxy,
            Some("api"),
        ),
        json!({"when": {"match": {"path": {"prefix": ["/api/orders"]}}}}),
    );
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["validate"])],
            vec![gated],
        ),
        "api",
    );
    let plugin = plugins.first().expect("one published instance");
    let headers = html_response_headers();

    let mut running = request("GET", "/api/orders/42");
    plugin.on_request_received(&mut running).await;
    assert!(
        !running
            .metadata
            .contains_key("plugin_trigger.validate.skipped")
    );
    assert!(
        plugin.should_buffer_response_body(&running),
        "an admitted response validator still requests its configured body"
    );
    assert_ne!(
        release_votes(plugin, &running, &headers),
        [true; 5],
        "an admitted instance contributes its own release decisions"
    );

    let mut skipped = request("GET", "/api/health");
    plugin.on_request_received(&mut skipped).await;
    assert_eq!(
        skipped
            .metadata
            .get("plugin_trigger.validate.skipped")
            .map(String::as_str),
        Some("true")
    );
    assert!(
        !plugin.should_buffer_response_body(&skipped),
        "a skipped instance never buffers"
    );
    assert_eq!(
        release_votes(plugin, &skipped, &headers),
        [true; 5],
        "a skipped instance withholds no release decision"
    );
}

/// The header-only half of the response phase. Its trait default is a silent
/// no-op, so a wrapper that forgets to forward it drops `response_caching`'s
/// RFC 9111 invalidation and cacheability marking for any instance carrying a
/// `priority_override` or a trigger.
fn final_header_decision_recorded(ctx: &RequestContext) -> bool {
    ctx.metadata
        .keys()
        .any(|key| key.ends_with("cache_final_header_decision"))
}

#[tokio::test]
async fn the_final_response_header_phase_is_forwarded_and_gated() {
    // Keep this instance trigger-compatible: the default cache config owns the
    // contextless `x-cache-status` trailer name and is correctly refused by
    // publication. Disabling that optional header leaves the per-request final
    // response-header hook intact, which is the phase this test exercises.
    let gated = with_trigger(
        make_plugin_config_with_json(
            "cache",
            "response_caching",
            json!({"ttl_seconds": 60, "add_cache_status_header": false}),
            PluginScope::Proxy,
            Some("api"),
        ),
        json!({"when": {"match": {"path": {"prefix": ["/api/orders"]}}}}),
    );
    let plugins = published(
        &config(vec![make_proxy("api", "/api", vec!["cache"])], vec![gated]),
        "api",
    );
    let plugin = plugins.first().expect("one published instance");
    let headers = html_response_headers();

    let mut running = request("GET", "/api/orders/42");
    plugin.on_request_received(&mut running).await;
    plugin.on_final_response_headers(&mut running, 200, &headers);
    assert!(
        final_header_decision_recorded(&running),
        "an admitted instance must still complete its header-only response work"
    );

    let mut skipped = request("GET", "/api/health");
    plugin.on_request_received(&mut skipped).await;
    plugin.on_final_response_headers(&mut skipped, 200, &headers);
    assert!(
        !final_header_decision_recorded(&skipped),
        "a skipped instance must take no final-response-header effect"
    );
}

#[tokio::test]
async fn a_priority_only_wrapper_still_runs_the_final_response_header_phase() {
    let mut reordered = builtin("cache", "response_caching", "api");
    reordered.priority_override = Some(3501);
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["cache"])],
            vec![reordered],
        ),
        "api",
    );
    let plugin = plugins.first().expect("one published instance");
    assert_eq!(
        plugin.priority(),
        3501,
        "the wrapper is the priority-only one"
    );

    let headers = html_response_headers();
    let mut ctx = request("GET", "/api/orders/42");
    plugin.on_request_received(&mut ctx).await;
    plugin.on_final_response_headers(&mut ctx, 200, &headers);
    assert!(
        final_header_decision_recorded(&ctx),
        "a priority override must not silently drop the header-only response phase"
    );
}

// ---------------------------------------------------------------------------
// Scope, multiplicity, ordering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn triggers_are_independent_per_instance_and_preserve_priority_order() {
    let mut first = with_trigger(
        header_stamper("first", PluginScope::Proxy, Some("api"), "x-first"),
        json!({"when": {"match": {"method": ["POST"]}}}),
    );
    first.priority_override = Some(3001);
    let mut second = with_trigger(
        header_stamper("second", PluginScope::Proxy, Some("api"), "x-second"),
        json!({"when": {"match": {"method": ["GET"]}}}),
    );
    second.priority_override = Some(3002);
    let mut third = header_stamper("third", PluginScope::Proxy, Some("api"), "x-third");
    third.priority_override = Some(3000);

    let cfg = config(
        vec![make_proxy("api", "/api", vec!["first", "second", "third"])],
        vec![first, second, third],
    );
    let plugins = published(&cfg, "api");
    assert_eq!(
        plugins.len(),
        3,
        "every instance stays on the published chain"
    );
    let priorities: Vec<_> = plugins.iter().map(|plugin| plugin.priority()).collect();
    assert_eq!(
        priorities,
        vec![3000, 3001, 3002],
        "trigger wrapping must not disturb effective priority ordering"
    );

    let mut post = request("POST", "/api");
    let headers = run_request(&plugins, &mut post).await;
    assert!(headers.contains_key("x-first"));
    assert!(!headers.contains_key("x-second"));
    assert!(
        headers.contains_key("x-third"),
        "an untriggered instance always runs"
    );

    let mut get = request("GET", "/api");
    let headers = run_request(&plugins, &mut get).await;
    assert!(!headers.contains_key("x-first"));
    assert!(headers.contains_key("x-second"));
    assert!(headers.contains_key("x-third"));
}

#[tokio::test]
async fn a_global_scoped_trigger_applies_per_proxy_without_changing_scope_merge() {
    let global = with_trigger(
        header_stamper("global", PluginScope::Global, None, "x-global"),
        json!({"when": {"match": {"proxy_id": ["alpha"]}}}),
    );
    let cfg = config(
        vec![
            make_proxy("alpha", "/alpha", vec![]),
            make_proxy("beta", "/beta", vec![]),
        ],
        vec![global],
    );

    for (proxy_id, expected) in [("alpha", true), ("beta", false)] {
        let plugins = published(&cfg, proxy_id);
        assert_eq!(plugins.len(), 1, "the global instance is on every chain");
        let mut ctx = request("GET", &format!("/{proxy_id}"));
        ctx.matched_proxy = Some(Arc::new(make_proxy(proxy_id, "/x", vec![])));
        let headers = run_request(&plugins, &mut ctx).await;
        assert_eq!(
            headers.contains_key("x-global"),
            expected,
            "proxy {proxy_id}"
        );
    }
}

#[tokio::test]
async fn a_proxy_group_trigger_is_shared_only_by_associated_proxies() {
    let group = with_trigger(
        header_stamper("group", PluginScope::ProxyGroup, None, "x-group"),
        json!({"when": {"match": {"proxy_id": ["alpha"]}}}),
    );
    let cfg = config(
        vec![
            make_proxy("alpha", "/alpha", vec!["group"]),
            make_proxy("beta", "/beta", vec!["group"]),
            make_proxy("unassociated", "/unassociated", vec![]),
        ],
        vec![group],
    );
    let cache = PluginCache::new(&cfg).expect("proxy-group trigger publishes");
    let alpha_plugins = cache.get_plugins(NS, "alpha").as_ref().clone();
    let beta_plugins = cache.get_plugins(NS, "beta").as_ref().clone();
    assert_eq!(alpha_plugins.len(), 1);
    assert_eq!(beta_plugins.len(), 1);
    assert!(
        Arc::ptr_eq(&alpha_plugins[0], &beta_plugins[0]),
        "one proxy-group instance must remain shared across its associations"
    );
    assert!(cache.get_plugins(NS, "unassociated").is_empty());

    for (proxy_id, plugins, expected) in [
        ("alpha", &alpha_plugins, true),
        ("beta", &beta_plugins, false),
    ] {
        let mut ctx = request("GET", &format!("/{proxy_id}"));
        ctx.matched_proxy = Some(Arc::new(make_proxy(proxy_id, "/x", vec!["group"])));
        let headers = run_request(plugins, &mut ctx).await;
        assert_eq!(
            headers.contains_key("x-group"),
            expected,
            "proxy-group trigger result for {proxy_id}"
        );
    }
}

#[tokio::test]
async fn a_reload_republishes_the_updated_trigger() {
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["stamp"])],
        vec![with_trigger(
            header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
            json!({"when": {"match": {"method": ["POST"]}}}),
        )],
    );
    let cache = PluginCache::new(&cfg).expect("initial cache builds");

    let mut get = request("GET", "/api");
    let plugins = cache.get_plugins(NS, "api").as_ref().clone();
    assert!(run_request(&plugins, &mut get).await.is_empty());

    let reloaded = config(
        vec![make_proxy("api", "/api", vec!["stamp"])],
        vec![with_trigger(
            header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
            json!({"when": {"match": {"method": ["GET"]}}}),
        )],
    );
    cache.rebuild(&reloaded).expect("reload republishes");

    let mut get = request("GET", "/api");
    let plugins = cache.get_plugins(NS, "api").as_ref().clone();
    assert!(!run_request(&plugins, &mut get).await.is_empty());
}

// ---------------------------------------------------------------------------
// Stream connections
// ---------------------------------------------------------------------------

fn stream_ctx(ip: &str) -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext::new(
        ip.to_string(),
        ip.to_string(),
        "tcp".to_string(),
        Some("tcp".to_string()),
        19_311,
        BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&[])),
    );
    ctx.proxy_namespace = NS.to_string();
    ctx
}

#[tokio::test]
async fn stream_triggers_gate_on_network_facts() {
    let gated = with_trigger(
        make_plugin_config_with_json(
            "throttle",
            "tcp_connection_throttle",
            json!({"max_connections_per_key": 1}),
            PluginScope::Proxy,
            Some("tcp"),
        ),
        json!({"when": {"match": {"source_cidr": ["10.0.0.0/8"]}}}),
    );
    let plugins = published(
        &config(
            vec![stream_proxy(
                "tcp",
                BackendScheme::Tcp,
                19_311,
                vec!["throttle"],
            )],
            vec![gated],
        ),
        "tcp",
    );
    let plugin = plugins.first().expect("one published instance");

    // Outside the CIDR the instance never runs, so its one-connection budget is
    // never consumed no matter how many connections arrive.
    for _ in 0..3 {
        let mut skipped = stream_ctx("203.0.113.5");
        assert!(matches!(
            plugin.on_stream_connect(&mut skipped).await,
            PluginResult::Continue
        ));
        assert_eq!(
            skipped
                .metadata
                .as_ref()
                .and_then(|meta| meta.get("plugin_trigger.throttle.skipped"))
                .map(String::as_str),
            Some("true")
        );
    }

    // Inside the CIDR the instance runs and the budget applies.
    let mut first = stream_ctx("10.9.9.9");
    assert!(matches!(
        plugin.on_stream_connect(&mut first).await,
        PluginResult::Continue
    ));
    let mut second = stream_ctx("10.9.9.9");
    assert!(
        !matches!(
            plugin.on_stream_connect(&mut second).await,
            PluginResult::Continue
        ),
        "a running throttle must refuse the over-budget connection"
    );
}

#[tokio::test]
async fn stream_protocol_triggers_use_the_frontend_transport_not_the_backend_scheme() {
    let gated = with_trigger(
        builtin("protocol-gate", "ip_restriction", "udp"),
        json!({"when": {"match": {"protocol": ["dtls"]}}}),
    );
    let plugins = published(
        &config(
            vec![stream_proxy(
                "udp",
                BackendScheme::Udp,
                19_316,
                vec!["protocol-gate"],
            )],
            vec![gated],
        ),
        "udp",
    );
    let plugin = plugins.first().expect("one published instance");

    let mut dtls_frontend = stream_ctx("203.0.113.5");
    dtls_frontend.backend_scheme = BackendScheme::Udp;
    dtls_frontend.frontend_transport = StreamFrontendTransport::Dtls;
    assert!(matches!(
        plugin.on_stream_connect(&mut dtls_frontend).await,
        PluginResult::Continue
    ));
    assert!(
        dtls_frontend
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("plugin_trigger.protocol-gate.skipped"))
            .is_none(),
        "DTLS accepted at the frontend must match even when the backend is plain UDP"
    );

    let mut udp_frontend = stream_ctx("203.0.113.6");
    udp_frontend.backend_scheme = BackendScheme::Dtls;
    udp_frontend.frontend_transport = StreamFrontendTransport::Udp;
    assert!(matches!(
        plugin.on_stream_connect(&mut udp_frontend).await,
        PluginResult::Continue
    ));
    assert_eq!(
        udp_frontend
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("plugin_trigger.protocol-gate.skipped"))
            .map(String::as_str),
        Some("true"),
        "plain UDP must not be mislabeled DTLS by its encrypted backend"
    );
}

fn stream_summary(client_ip: &str) -> StreamTransactionSummary {
    StreamTransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: NS.to_string(),
        proxy_id: "tcp".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("tcp".to_string()),
        client_ip: client_ip.to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: "tcp".to_string(),
        listen_port: 19_312,
        duration_ms: 1.0,
        bytes_sent: 0,
        bytes_received: 0,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    }
}

/// `on_stream_disconnect` receives only a summary, so the connect decision has
/// to travel with it. If it did not, a skipped instance would still emit its
/// disconnect record — an asymmetric skip.
#[tokio::test]
async fn a_false_stream_trigger_suppresses_connect_and_disconnect_together() {
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind record sink");
    let sink_port = sink.local_addr().expect("sink addr").port();

    let gated = with_trigger(
        make_plugin_config_with_json(
            "auditlog",
            "udp_logging",
            json!({
                "host": "127.0.0.1",
                "port": sink_port,
                "batch_size": 1,
                "flush_interval_ms": 100,
                "max_retries": 0
            }),
            PluginScope::Proxy,
            Some("tcp"),
        ),
        json!({"when": {"match": {"source_cidr": ["10.0.0.0/8"]}}}),
    );
    let plugins = published(
        &config(
            vec![stream_proxy(
                "tcp",
                BackendScheme::Tcp,
                19_312,
                vec!["auditlog"],
            )],
            vec![gated],
        ),
        "tcp",
    );
    let plugin = plugins.first().expect("one published instance");

    // Outside the CIDR the instance is skipped at connect. Its disconnect is
    // emitted FIRST, so a leaked record would be the first datagram to arrive
    // and the assertion below would fail deterministically rather than on a
    // timeout.
    let mut skipped = stream_ctx("203.0.113.5");
    assert!(matches!(
        plugin.on_stream_connect(&mut skipped).await,
        PluginResult::Continue
    ));
    assert_eq!(
        skipped
            .metadata
            .as_ref()
            .and_then(|meta| meta.get("plugin_trigger.auditlog.skipped"))
            .map(String::as_str),
        Some("true")
    );
    let mut skipped_summary = stream_summary("203.0.113.5");
    attach_stream_trigger_decisions_for_test(&mut skipped_summary, &skipped);
    plugin.on_stream_disconnect(&skipped_summary).await;

    // Inside the CIDR both halves run.
    let mut admitted = stream_ctx("10.9.9.9");
    assert!(matches!(
        plugin.on_stream_connect(&mut admitted).await,
        PluginResult::Continue
    ));
    assert!(
        admitted
            .metadata
            .as_ref()
            .and_then(|meta| meta.get("plugin_trigger.auditlog.skipped"))
            .is_none()
    );
    let mut admitted_summary = stream_summary("10.9.9.9");
    attach_stream_trigger_decisions_for_test(&mut admitted_summary, &admitted);
    plugin.on_stream_disconnect(&admitted_summary).await;

    let mut buffer = vec![0u8; 64 * 1024];
    let len = tokio::time::timeout(Duration::from_secs(10), sink.recv(&mut buffer))
        .await
        .expect("an admitted disconnect record reaches the sink")
        .expect("receive record");
    let payload = String::from_utf8_lossy(&buffer[..len]).to_string();
    assert!(
        payload.contains("10.9.9.9"),
        "the admitted connection must still be logged: {payload}"
    );
    assert!(
        !payload.contains("203.0.113.5"),
        "a skipped instance must emit no disconnect record: {payload}"
    );
}

/// A summary carrying no decision (a connection whose chain never reached this
/// instance's `on_stream_connect`) fails closed to "runs", so a trigger can only
/// ever remove work.
#[tokio::test]
async fn a_disconnect_without_a_recorded_decision_fails_closed_to_running() {
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind record sink");
    let sink_port = sink.local_addr().expect("sink addr").port();

    let gated = with_trigger(
        make_plugin_config_with_json(
            "auditlog",
            "udp_logging",
            json!({
                "host": "127.0.0.1",
                "port": sink_port,
                "batch_size": 1,
                "flush_interval_ms": 100,
                "max_retries": 0
            }),
            PluginScope::Proxy,
            Some("tcp"),
        ),
        // A predicate this connection would NOT satisfy, so only the missing
        // decision can admit the hook.
        json!({"when": {"match": {"source_cidr": ["10.0.0.0/8"]}}}),
    );
    let plugins = published(
        &config(
            vec![stream_proxy(
                "tcp",
                BackendScheme::Tcp,
                19_312,
                vec!["auditlog"],
            )],
            vec![gated],
        ),
        "tcp",
    );
    let plugin = plugins.first().expect("one published instance");

    plugin
        .on_stream_disconnect(&stream_summary("203.0.113.5"))
        .await;

    let mut buffer = vec![0u8; 64 * 1024];
    let len = tokio::time::timeout(Duration::from_secs(10), sink.recv(&mut buffer))
        .await
        .expect("an undecided disconnect still emits its record")
        .expect("receive record");
    assert!(String::from_utf8_lossy(&buffer[..len]).contains("203.0.113.5"));
}

// ---------------------------------------------------------------------------
// Fail-closed publication refusals
// ---------------------------------------------------------------------------

fn publication_error(cfg: &GatewayConfig) -> String {
    match PluginCache::new(cfg) {
        Ok(_) => panic!("plugin cache should have refused this trigger"),
        Err(error) => error,
    }
}

fn candidate_error(cfg: &GatewayConfig) -> String {
    validate_plugin_composition_candidate_with_real_ip_header_for_test(cfg, None)
        .expect_err("candidate admission should have refused this trigger")
}

#[test]
fn an_invalid_trigger_is_refused_at_plugin_cache_publication() {
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["stamp"])],
        vec![with_trigger(
            header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
            json!({"when": {"match": {"source_cidr": ["10.0.0.0/33"]}}}),
        )],
    );
    let error = publication_error(&cfg);
    assert!(error.contains("execution trigger is invalid"), "{error}");
    assert!(error.contains("source_cidr"), "{error}");
}

#[test]
fn a_websocket_frame_plugin_may_now_carry_a_trigger() {
    // Issue #3734: the frame/framing/disconnect surfaces are bound to the
    // decision taken at upgrade admission, so publication no longer refuses
    // them. `ws_message_size_limiting` publishes size limits AND frame hooks.
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["ws"])],
        vec![with_trigger(
            builtin("ws", "ws_message_size_limiting", "api"),
            json!({"when": {"match": {"method": ["GET"]}}}),
        )],
    );
    PluginCache::new(&cfg).expect("a triggered WebSocket frame plugin publishes");
    assert!(
        validate_plugin_composition_candidate_with_real_ip_header_for_test(&cfg, None).is_ok(),
        "candidate admission must accept a triggered WebSocket frame plugin"
    );
}

#[test]
fn a_udp_datagram_plugin_may_now_carry_a_network_fact_trigger() {
    // Issue #3734: the decision is taken once by the `on_stream_connect`
    // admission chain and consumed when the flow's datagram-hook list is built.
    let cfg = config(
        vec![stream_proxy(
            "udp",
            BackendScheme::Udp,
            19_411,
            vec!["udp-rl"],
        )],
        vec![with_trigger(
            builtin("udp-rl", "udp_rate_limiting", "udp"),
            json!({"when": {"match": {"source_cidr": ["10.0.0.0/8"]}}}),
        )],
    );
    PluginCache::new(&cfg).expect("a triggered UDP datagram plugin publishes");
    assert!(
        validate_plugin_composition_candidate_with_real_ip_header_for_test(&cfg, None).is_ok(),
        "candidate admission must accept a triggered UDP datagram plugin"
    );
}

#[test]
fn an_http_only_predicate_on_a_stream_only_plugin_is_refused_by_field() {
    // A datagram flow has no request line, header block, query string, or
    // cookie jar. Refuse by NAME rather than reinterpreting the absent concept
    // as an empty string (which would silently disable the instance) or, under
    // `not`, as a broad match (which would silently always enable it).
    for (field, predicate) in [
        ("method", json!({"method": ["GET"]})),
        ("path", json!({"path": {"prefix": ["/api"]}})),
        ("host", json!({"host": {"exact": ["api.example.com"]}})),
        ("header", json!({"header": {"name": "x-tenant"}})),
        ("query", json!({"query": {"name": "tenant"}})),
        ("cookie", json!({"cookie": {"name": "session"}})),
    ] {
        let cfg = config(
            vec![stream_proxy(
                "udp",
                BackendScheme::Udp,
                19_412,
                vec!["udp-rl"],
            )],
            vec![with_trigger(
                builtin("udp-rl", "udp_rate_limiting", "udp"),
                json!({"when": {"match": predicate}}),
            )],
        );
        let error = publication_error(&cfg);
        assert!(
            error.contains("cannot carry an execution trigger"),
            "{field}: {error}"
        );
        assert!(
            error.contains(&format!("`{field}`")),
            "the diagnostic must name the offending field ({field}): {error}"
        );
        let candidate = candidate_error(&cfg);
        assert!(candidate.contains(&format!("`{field}`")), "{candidate}");
    }
}

#[test]
fn an_http_only_predicate_is_still_supported_on_a_dual_protocol_plugin() {
    // `ip_restriction` serves every protocol, so a `path` predicate remains a
    // real condition for its HTTP requests and is not refused.
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["ipr"])],
        vec![with_trigger(
            builtin("ipr", "ip_restriction", "api"),
            json!({"when": {"match": {"path": {"prefix": ["/api/admin"]}}}}),
        )],
    );
    PluginCache::new(&cfg).expect("a dual-protocol plugin keeps HTTP-only predicates");
}

#[test]
fn an_identity_predicate_on_an_authentication_plugin_is_refused() {
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["auth"])],
        vec![with_trigger(
            builtin("auth", "key_auth", "api"),
            json!({"when": {"match": {"consumer": {"presence": "absent"}}}}),
        )],
    );
    let error = publication_error(&cfg);
    assert!(
        error.contains("cannot carry an execution trigger"),
        "{error}"
    );
    assert!(error.contains("authentication plugin"), "{error}");
}

/// `security_headers` re-asserts its header set through a CONTEXTLESS hook and
/// publishes its declared names per generation, so no coherent per-request gate
/// exists. Refuse rather than half-apply.
#[test]
fn a_trigger_on_an_initial_response_header_policy_plugin_is_refused() {
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["sec"])],
        vec![with_trigger(
            builtin("sec", "security_headers", "api"),
            json!({"when": {"match": {"method": ["GET"]}}}),
        )],
    );
    let error = publication_error(&cfg);
    assert!(
        error.contains("cannot carry an execution trigger"),
        "{error}"
    );
    assert!(error.contains("initial response-header policy"), "{error}");
    let candidate = candidate_error(&cfg);
    assert!(
        candidate.contains("initial response-header policy"),
        "admin candidate admission must match runtime publication: {candidate}"
    );
}

#[test]
fn a_trigger_on_a_fixed_core_body_ceiling_is_refused() {
    for plugin_name in ["request_size_limiting", "response_size_limiting"] {
        let cfg = config(
            vec![make_proxy("api", "/api", vec!["limit"])],
            vec![with_trigger(
                builtin("limit", plugin_name, "api"),
                json!({"when": {"match": {"path": {"prefix": ["/api/uploads"]}}}}),
            )],
        );
        let error = publication_error(&cfg);
        assert!(
            error.contains("cannot carry an execution trigger"),
            "{plugin_name}: {error}"
        );
        assert!(
            error.contains("fixed per-proxy") && error.contains("body ceiling"),
            "{plugin_name}: {error}"
        );
        let candidate = candidate_error(&cfg);
        assert!(
            candidate.contains("fixed per-proxy") && candidate.contains("body ceiling"),
            "admin candidate admission must match runtime for {plugin_name}: {candidate}"
        );
    }
}

#[test]
fn a_trigger_on_a_contextless_response_trailer_policy_is_refused() {
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["rewrite"])],
        vec![with_trigger(
            builtin("rewrite", "response_transformer", "api"),
            json!({"when": {"match": {"path": {"prefix": ["/api/public"]}}}}),
        )],
    );
    let error = publication_error(&cfg);
    assert!(
        error.contains("cannot carry an execution trigger"),
        "{error}"
    );
    assert!(error.contains("response-trailer ownership"), "{error}");
    let candidate = candidate_error(&cfg);
    assert!(
        candidate.contains("response-trailer ownership"),
        "{candidate}"
    );
}

/// A stream-only plugin can never reach the HTTP pipeline, and an identity
/// predicate never gates a stream connection, so such a trigger could gate
/// nothing at all. Refuse it rather than accept an inert predicate.
#[test]
fn an_identity_predicate_on_a_stream_only_plugin_is_refused() {
    for predicate in [
        json!({"consumer": {"presence": "present"}}),
        json!({"auth_method": ["mtls_auth"]}),
        json!({"spiffe_id": {"presence": "present"}}),
    ] {
        let cfg = config(
            vec![stream_proxy(
                "tcp",
                BackendScheme::Tcp,
                19_313,
                vec!["throttle"],
            )],
            vec![with_trigger(
                make_plugin_config_with_json(
                    "throttle",
                    "tcp_connection_throttle",
                    json!({"max_connections_per_key": 1}),
                    PluginScope::Proxy,
                    Some("tcp"),
                ),
                json!({"when": {"match": predicate}}),
            )],
        );
        let error = publication_error(&cfg);
        assert!(
            error.contains("cannot carry an execution trigger"),
            "{error}"
        );
        assert!(error.contains("stream-only plugin"), "{error}");
    }
}

/// The same instance keeps working on network facts, so the refusal is scoped to
/// identity rather than to stream plugins in general.
#[test]
fn a_network_predicate_on_a_stream_only_plugin_is_accepted() {
    let cfg = config(
        vec![stream_proxy(
            "tcp",
            BackendScheme::Tcp,
            19_314,
            vec!["throttle"],
        )],
        vec![with_trigger(
            make_plugin_config_with_json(
                "throttle",
                "tcp_connection_throttle",
                json!({"max_connections_per_key": 1}),
                PluginScope::Proxy,
                Some("tcp"),
            ),
            json!({"when": {"match": {"source_cidr": ["10.0.0.0/8"]}}}),
        )],
    );
    PluginCache::new(&cfg).expect("a network-scoped stream trigger is supported");
}

/// On a plugin that serves BOTH families the trigger is accepted, and the
/// identity predicate simply does not gate the stream half: every gated stream
/// phase is at or before the stream authentication boundary, so the instance
/// runs and no decision is memoized — which means the disconnect hook runs too.
#[tokio::test]
async fn an_identity_predicate_never_gates_a_stream_connection() {
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind record sink");
    let sink_port = sink.local_addr().expect("sink addr").port();

    let cfg = config(
        vec![stream_proxy(
            "tcp",
            BackendScheme::Tcp,
            19_315,
            vec!["auditlog"],
        )],
        vec![with_trigger(
            make_plugin_config_with_json(
                "auditlog",
                "udp_logging",
                json!({
                    "host": "127.0.0.1",
                    "port": sink_port,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "max_retries": 0
                }),
                PluginScope::Proxy,
                Some("tcp"),
            ),
            // No stream connection can satisfy this, yet the instance must run.
            json!({"when": {"match": {"consumer": {"value": {"exact": ["alice"]}}}}}),
        )],
    );
    let plugins = published(&cfg, "tcp");
    let plugin = plugins.first().expect("one published instance");

    let mut ctx = stream_ctx("203.0.113.5");
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx).await,
        PluginResult::Continue
    ));
    assert!(
        ctx.metadata
            .as_ref()
            .and_then(|meta| meta.get("plugin_trigger.auditlog.skipped"))
            .is_none(),
        "an identity predicate must not record a stream skip"
    );

    let mut summary = stream_summary("203.0.113.5");
    attach_stream_trigger_decisions_for_test(&mut summary, &ctx);
    plugin.on_stream_disconnect(&summary).await;

    let mut buffer = vec![0u8; 64 * 1024];
    let len = tokio::time::timeout(Duration::from_secs(10), sink.recv(&mut buffer))
        .await
        .expect("the ungated disconnect still emits its record")
        .expect("receive record");
    assert!(String::from_utf8_lossy(&buffer[..len]).contains("203.0.113.5"));
}

#[tokio::test]
async fn a_non_identity_trigger_removes_an_auth_plugin_from_the_effective_request_chain() {
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["auth"])],
        vec![with_trigger(
            builtin("auth", "key_auth", "api"),
            json!({"when": {"not": {"match": {"path": {"prefix": ["/api/public"]}}}}}),
        )],
    );
    let plugins = published(&cfg, "api");
    let consumer_index = ConsumerIndex::new(&[]);

    let mut public = request("GET", "/api/public");
    for plugin in &plugins {
        plugin.on_request_received(&mut public).await;
    }
    assert!(
        run_authentication_phase(AuthMode::Single, &plugins, &mut public, &consumer_index)
            .await
            .is_none(),
        "when every auth instance is trigger-skipped, the excluded path is intentionally public"
    );

    let mut private = request("GET", "/api/private");
    for plugin in &plugins {
        plugin.on_request_received(&mut private).await;
    }
    let rejection =
        run_authentication_phase(AuthMode::Single, &plugins, &mut private, &consumer_index)
            .await
            .expect("the same auth instance still governs its matching path");
    assert_eq!(rejection.0, 401);
}

#[tokio::test]
async fn a_skipped_auth_instance_cannot_supply_an_inapplicable_challenge() {
    let mut skipped_basic = with_trigger(
        builtin("basic", "basic_auth", "api"),
        json!({"when": {"match": {"path": {"prefix": ["/api/private"]}}}}),
    );
    skipped_basic.priority_override = Some(1_000);
    let mut bearer = builtin("bearer", "oauth2_introspection", "api");
    bearer.priority_override = Some(1_100);
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["basic", "bearer"])],
        vec![skipped_basic, bearer],
    );
    let plugins = published(&cfg, "api");
    let mut public = request("GET", "/api/public");
    for plugin in &plugins {
        plugin.on_request_received(&mut public).await;
    }
    let rejection = run_authentication_phase(
        AuthMode::Single,
        &plugins,
        &mut public,
        &ConsumerIndex::new(&[]),
    )
    .await
    .expect("the applicable bearer mechanism still requires authentication");
    assert_eq!(rejection.0, 401);
    assert_eq!(
        rejection.2.get("WWW-Authenticate").map(String::as_str),
        Some("Bearer"),
        "challenge selection must ignore the trigger-skipped Basic mechanism"
    );
}
