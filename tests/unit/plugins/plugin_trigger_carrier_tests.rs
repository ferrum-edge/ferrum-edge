//! Per-instance trigger decisions carried into the CONTEXTLESS phases:
//! terminal transaction logging (issue #3733), WebSocket sessions and UDP/DTLS
//! flows (issue #3734).
//!
//! Every test drives the real published `PluginCache` chain — the same wrapper,
//! the same summary/session carriers, and the same collection helpers the
//! H1/H2/H3 and UDP/DTLS data paths use. Nothing here reimplements the gate.
//!
//! The pure schema/compilation layer lives in
//! `tests/unit/config/plugin_trigger_tests.rs`; request/stream-phase gating
//! lives in `plugin_trigger_gate_tests.rs`.

use chrono::Utc;
use ferrum_edge::_test_support::{
    admitted_datagram_plugins_for_test, attach_transaction_trigger_decisions_for_test,
    collect_websocket_disconnect_plugins_for_test,
    collect_websocket_relay_plugins_decided_for_test,
    collect_websocket_size_limit_plugins_for_test, plugin_trigger_carrier_counters_for_test,
};
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{
    BackendScheme, DispatchKind, GatewayConfig, PluginConfig, PluginScope, Proxy,
};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::api_chargeback::{ProtocolFamily, global_registry};
use ferrum_edge::plugins::{
    MirrorResponseMeta, Plugin, RequestContext, StreamConnectionContext, StreamFrontendTransport,
    TransactionSummary, log_with_mirror,
};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{make_plugin_config_with_json, make_proxy, minimal_plugin_config};

const NS: &str = "ferrum";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

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

fn config(proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        plugin_configs,
        loaded_at: Utc::now(),
        ..Default::default()
    }
}

fn stream_proxy(id: &str, scheme: BackendScheme, port: u16, plugin_ids: Vec<&str>) -> Proxy {
    let mut proxy = make_proxy(id, "/unused", plugin_ids);
    proxy.listen_path = None;
    proxy.listen_port = Some(port);
    proxy.backend_scheme = Some(scheme);
    proxy.dispatch_kind = DispatchKind::from(scheme);
    proxy
}

fn published(config: &GatewayConfig, proxy_id: &str) -> Vec<Arc<dyn Plugin>> {
    let cache = PluginCache::new(config).expect("plugin cache builds");
    cache.get_plugins(NS, proxy_id).as_ref().clone()
}

fn request(path: &str) -> RequestContext {
    RequestContext::new("10.1.2.3".to_string(), "GET".to_string(), path.to_string())
}

/// Run the published chain's request-phase hooks, exactly as the dispatchers
/// do, so every triggered instance has memoized its decision before the
/// terminal summary is built.
async fn run_request_phase(plugins: &[Arc<dyn Plugin>], ctx: &mut RequestContext) {
    for plugin in plugins {
        plugin.on_request_received(ctx).await;
    }
    let mut headers = std::collections::HashMap::new();
    for plugin in plugins {
        plugin.before_proxy(ctx, &mut headers).await;
    }
}

// ---------------------------------------------------------------------------
// #3733 — terminal transaction logging
// ---------------------------------------------------------------------------

/// `api_chargeback` bills exactly once per terminal `log` call and its rows are
/// readable from the process registry, which makes it a precise probe for "did
/// the terminal hook actually run for this instance".
fn chargeback_config() -> serde_json::Value {
    json!({
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.000001,
            "price_per_byte_received": 0.000002
        }
    })
}

fn billed_calls(consumer: &str, proxy_id: &str) -> u64 {
    global_registry()
        .entries
        .iter()
        .filter(|entry| {
            entry.consumer.as_ref() == consumer
                && entry.proxy_id.as_ref() == proxy_id
                && entry.protocol_family == ProtocolFamily::Http
        })
        .map(|entry| entry.call_count.load(Ordering::Relaxed))
        .sum()
}

fn summary_for(consumer: &str, proxy_id: &str, path: &str) -> TransactionSummary {
    TransactionSummary {
        namespace: NS.to_string(),
        timestamp_received: "2026-01-01T00:00:00Z".to_string(),
        client_ip: "10.1.2.3".to_string(),
        consumer_username: Some(consumer.to_string()),
        http_method: "GET".to_string(),
        request_path: path.to_string(),
        proxy_id: Some(proxy_id.to_string()),
        response_status_code: 200,
        ..TransactionSummary::default()
    }
}

fn triggered_chargeback(proxy_id: &str, id: &str, predicate: serde_json::Value) -> PluginConfig {
    with_trigger(
        make_plugin_config_with_json(
            id,
            "api_chargeback",
            chargeback_config(),
            PluginScope::Proxy,
            Some(proxy_id),
        ),
        predicate,
    )
}

#[tokio::test]
async fn a_false_trigger_suppresses_the_terminal_transaction_hook() {
    let proxy_id = "carrier-terminal-false";
    let consumer = "carrier-terminal-false-consumer";
    let cfg = config(
        vec![make_proxy(proxy_id, "/billing-false", vec!["bill"])],
        vec![triggered_chargeback(
            proxy_id,
            "bill",
            json!({"when": {"match": {"path": {"prefix": ["/billing-false/billed"]}}}}),
        )],
    );
    let plugins = published(&cfg, proxy_id);

    let mut ctx = request("/billing-false/free");
    run_request_phase(&plugins, &mut ctx).await;
    let summary = summary_for(consumer, proxy_id, "/billing-false/free");

    let before = plugin_trigger_carrier_counters_for_test().skipped_terminal_log_hooks;
    log_with_mirror(&plugins, &summary, &ctx).await;

    assert_eq!(
        billed_calls(consumer, proxy_id),
        0,
        "a false trigger must suppress the terminal transaction hook entirely"
    );
    assert!(
        plugin_trigger_carrier_counters_for_test().skipped_terminal_log_hooks > before,
        "the skip must be visible in the bounded, unlabeled skip counter"
    );
}

#[tokio::test]
async fn a_true_trigger_runs_the_terminal_transaction_hook_exactly_once() {
    let proxy_id = "carrier-terminal-true";
    let consumer = "carrier-terminal-true-consumer";
    let cfg = config(
        vec![make_proxy(proxy_id, "/billing-true", vec!["bill"])],
        vec![triggered_chargeback(
            proxy_id,
            "bill",
            json!({"when": {"match": {"path": {"prefix": ["/billing-true/billed"]}}}}),
        )],
    );
    let plugins = published(&cfg, proxy_id);

    let mut ctx = request("/billing-true/billed/orders");
    run_request_phase(&plugins, &mut ctx).await;
    let summary = summary_for(consumer, proxy_id, "/billing-true/billed/orders");
    log_with_mirror(&plugins, &summary, &ctx).await;

    assert_eq!(
        billed_calls(consumer, proxy_id),
        1,
        "a true trigger must run the terminal hook exactly once"
    );
}

#[tokio::test]
async fn a_missing_carrier_runs_the_terminal_hook_and_records_the_invariant() {
    // A summary path that predates trigger evaluation (an internal/legacy relay
    // context that never ran the request chain) must keep the historical "log
    // it" behavior, never a silent suppression, and must be counted.
    let proxy_id = "carrier-terminal-missing";
    let consumer = "carrier-terminal-missing-consumer";
    let cfg = config(
        vec![make_proxy(proxy_id, "/billing-missing", vec!["bill"])],
        vec![triggered_chargeback(
            proxy_id,
            "bill",
            json!({"when": {"match": {"path": {"prefix": ["/never"]}}}}),
        )],
    );
    let plugins = published(&cfg, proxy_id);

    // Deliberately do NOT run the request phase: no decision is memoized, so
    // the funnel stamps nothing and the hook sees a missing carrier.
    let ctx = request("/billing-missing/anything");
    let summary = summary_for(consumer, proxy_id, "/billing-missing/anything");

    let before = plugin_trigger_carrier_counters_for_test().missing_decision_carriers;
    log_with_mirror(&plugins, &summary, &ctx).await;

    assert_eq!(
        billed_calls(consumer, proxy_id),
        1,
        "a missing decision carrier must never suppress a terminal audit record"
    );
    assert!(
        plugin_trigger_carrier_counters_for_test().missing_decision_carriers > before,
        "a missing carrier must record the bounded invariant signal"
    );
}

#[tokio::test]
async fn a_plugin_cannot_re_admit_a_skipped_instance_through_summary_metadata() {
    let proxy_id = "carrier-terminal-metadata";
    let consumer = "carrier-terminal-metadata-consumer";
    let cfg = config(
        vec![make_proxy(proxy_id, "/billing-meta", vec!["bill"])],
        vec![triggered_chargeback(
            proxy_id,
            "bill",
            json!({"when": {"match": {"path": {"prefix": ["/never"]}}}}),
        )],
    );
    let plugins = published(&cfg, proxy_id);

    let mut ctx = request("/billing-meta/free");
    run_request_phase(&plugins, &mut ctx).await;

    let mut summary = summary_for(consumer, proxy_id, "/billing-meta/free");
    // Everything a hostile or merely confused plugin can write: the public
    // metadata map, including a forged "not skipped" claim under the very key
    // the trigger layer publishes.
    summary.metadata.insert(
        "plugin_trigger.bill.skipped".to_string(),
        "false".to_string(),
    );
    summary
        .metadata
        .insert("mirror".to_string(), "true".to_string());
    log_with_mirror(&plugins, &summary, &ctx).await;

    assert_eq!(
        billed_calls(consumer, proxy_id),
        0,
        "the decision carrier is opaque: metadata must not re-admit a skipped instance"
    );
}

#[tokio::test]
async fn a_mirror_entry_inherits_the_decision_of_its_request() {
    // The mirror entry is derived from the already-stamped primary summary, so
    // a skipped instance is skipped for the mirror record too — whatever the
    // mirror metadata or completion ordering says. Both terminal calls must
    // therefore be suppressed, which the bounded skip counter shows (a mirror
    // that had been re-admitted would RUN instead of counting a second skip).
    let proxy_id = "carrier-terminal-mirror";
    let consumer = "carrier-terminal-mirror-consumer";
    let cfg = config(
        vec![make_proxy(proxy_id, "/billing-mirror", vec!["bill"])],
        vec![triggered_chargeback(
            proxy_id,
            "bill",
            json!({"when": {"match": {"path": {"prefix": ["/never"]}}}}),
        )],
    );
    let plugins = published(&cfg, proxy_id);

    let mut ctx = request("/billing-mirror/free");
    run_request_phase(&plugins, &mut ctx).await;
    let summary = summary_for(consumer, proxy_id, "/billing-mirror/free");

    let (tx, rx) = tokio::sync::watch::channel(None);
    ctx.push_mirror_result_rx(rx);
    let before = plugin_trigger_carrier_counters_for_test().skipped_terminal_log_hooks;
    log_with_mirror(&plugins, &summary, &ctx).await;
    tx.send(Some(MirrorResponseMeta {
        mirror_plugin_id: Some("mirror-carrier".to_string()),
        mirror_target_url: "http://shadow.local/billing-mirror/free".to_string(),
        mirror_response_status_code: Some(200),
        mirror_response_size_bytes: Some(64),
        mirror_response_advertised_size_bytes: None,
        mirror_latency_ms: 5.0,
        mirror_error: None,
    }))
    .expect("the detached mirror collector retains its receiver");

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if plugin_trigger_carrier_counters_for_test().skipped_terminal_log_hooks >= before + 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the mirror entry must reach the terminal hook and inherit the skip");

    assert_eq!(
        billed_calls(consumer, proxy_id),
        0,
        "neither the primary nor the mirror record may bill a skipped instance"
    );
}

#[tokio::test]
async fn the_carrier_projection_is_the_production_one_and_is_not_serialized() {
    let proxy_id = "carrier-terminal-projection";
    let cfg = config(
        vec![make_proxy(proxy_id, "/billing-proj", vec!["bill"])],
        vec![triggered_chargeback(
            proxy_id,
            "bill",
            json!({"when": {"match": {"path": {"prefix": ["/never"]}}}}),
        )],
    );
    let plugins = published(&cfg, proxy_id);
    let mut ctx = request("/billing-proj/free");
    run_request_phase(&plugins, &mut ctx).await;

    let mut summary = summary_for("proj-consumer", proxy_id, "/billing-proj/free");
    attach_transaction_trigger_decisions_for_test(&mut summary, &ctx);
    let rendered = serde_json::to_string(&summary).expect("summary serializes");
    assert!(
        !rendered.contains("plugin_trigger_decisions"),
        "the carrier must never reach the log representation: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// #3734 — WebSocket session binding
// ---------------------------------------------------------------------------

fn ws_names(plugins: &[Arc<dyn Plugin>]) -> Vec<&str> {
    plugins.iter().map(|plugin| plugin.name()).collect()
}

/// A WebSocket proxy carrying one frame-hook instance, one parser-ceiling
/// instance, and one disconnect-hook instance, each triggered on the request
/// path so one upgrade can admit them and another can skip them.
fn ws_config(proxy_id: &str, prefix: &str) -> GatewayConfig {
    let admit = json!({"when": {"match": {"path": {"prefix": [prefix]}}}});
    config(
        vec![make_proxy(proxy_id, "/ws", vec!["rl", "size", "log"])],
        vec![
            with_trigger(builtin("rl", "ws_rate_limiting", proxy_id), admit.clone()),
            with_trigger(
                builtin("size", "ws_message_size_limiting", proxy_id),
                admit.clone(),
            ),
            with_trigger(builtin("log", "ws_logging", proxy_id), admit),
        ],
    )
}

#[tokio::test]
async fn a_false_websocket_trigger_removes_the_instance_from_every_session_list() {
    let proxy_id = "carrier-ws-false";
    let plugins = published(&ws_config(proxy_id, "/ws/admit"), proxy_id);
    let mut ctx = request("/ws/other");

    let ceilings = collect_websocket_size_limit_plugins_for_test(&plugins, &mut ctx);
    let (framing, frame) =
        collect_websocket_relay_plugins_decided_for_test(&plugins, true, &mut ctx);
    let disconnect = collect_websocket_disconnect_plugins_for_test(&plugins, &mut ctx);

    assert!(
        ceilings.is_empty(),
        "a skipped instance must not constrain either framer: {:?}",
        ws_names(&ceilings)
    );
    assert!(
        framing.is_empty(),
        "a skipped instance must not force framing: {:?}",
        ws_names(&framing)
    );
    assert!(
        frame.is_empty(),
        "a skipped instance must observe no frame: {:?}",
        ws_names(&frame)
    );
    assert!(
        disconnect.is_empty(),
        "a skipped instance must run no disconnect hook: {:?}",
        ws_names(&disconnect)
    );
}

#[tokio::test]
async fn a_skipped_frame_plugin_leaves_the_session_on_the_raw_tunnel_path() {
    // Tunnel mode is chosen from the resulting parser-policy list, so an empty
    // list after admission is exactly "the relay stays a raw tunnel".
    let proxy_id = "carrier-ws-tunnel";
    let plugins = published(&ws_config(proxy_id, "/ws/admit"), proxy_id);
    let mut ctx = request("/ws/other");
    let (framing, _frame) =
        collect_websocket_relay_plugins_decided_for_test(&plugins, true, &mut ctx);
    assert!(
        framing.is_empty(),
        "a skipped frame plugin must not pull the session into framed mode"
    );
}

#[tokio::test]
async fn a_true_websocket_trigger_preserves_membership_and_priority_order() {
    let proxy_id = "carrier-ws-true";
    let plugins = published(&ws_config(proxy_id, "/ws/admit"), proxy_id);
    let mut ctx = request("/ws/admit/session");

    let ceilings = collect_websocket_size_limit_plugins_for_test(&plugins, &mut ctx);
    let (framing, frame) =
        collect_websocket_relay_plugins_decided_for_test(&plugins, true, &mut ctx);
    let disconnect = collect_websocket_disconnect_plugins_for_test(&plugins, &mut ctx);

    assert_eq!(ws_names(&ceilings), vec!["ws_message_size_limiting"]);
    assert!(
        ws_names(&frame).contains(&"ws_rate_limiting"),
        "an admitted frame plugin keeps its frame-hook membership: {:?}",
        ws_names(&frame)
    );
    assert!(
        ws_names(&disconnect).contains(&"ws_logging"),
        "an admitted disconnect plugin keeps its hook: {:?}",
        ws_names(&disconnect)
    );
    // The relay derives the frame list from the already-bound framing list, so
    // configured priority order is preserved as a subsequence.
    let framing_names = ws_names(&framing);
    let frame_names = ws_names(&frame);
    let mut framing_iter = framing_names.iter();
    for name in &frame_names {
        assert!(
            framing_iter.any(|candidate| candidate == name),
            "frame-hook order must follow the parser-policy order: {frame_names:?} vs {framing_names:?}"
        );
    }
}

#[tokio::test]
async fn two_websocket_instances_of_one_plugin_are_decided_independently() {
    let proxy_id = "carrier-ws-multi";
    let cfg = config(
        vec![make_proxy(proxy_id, "/ws", vec!["rl-a", "rl-b"])],
        vec![
            with_trigger(
                make_plugin_config_with_json(
                    "rl-a",
                    "ws_rate_limiting",
                    json!({"frames_per_second": 100}),
                    PluginScope::Proxy,
                    Some(proxy_id),
                ),
                json!({"when": {"match": {"path": {"prefix": ["/ws/a"]}}}}),
            ),
            with_trigger(
                make_plugin_config_with_json(
                    "rl-b",
                    "ws_rate_limiting",
                    json!({"frames_per_second": 200}),
                    PluginScope::Proxy,
                    Some(proxy_id),
                ),
                json!({"when": {"match": {"path": {"prefix": ["/ws/b"]}}}}),
            ),
        ],
    );
    let plugins = published(&cfg, proxy_id);
    assert_eq!(plugins.len(), 2, "both instances must be published");

    let mut only_a = request("/ws/a/session");
    let (_framing, frame_a) =
        collect_websocket_relay_plugins_decided_for_test(&plugins, true, &mut only_a);
    assert_eq!(
        frame_a.len(),
        1,
        "exactly one of two same-plugin instances may be admitted"
    );

    let mut neither = request("/ws/c/session");
    let (_framing, frame_none) =
        collect_websocket_relay_plugins_decided_for_test(&plugins, true, &mut neither);
    assert!(
        frame_none.is_empty(),
        "instances are decided independently, not as a group"
    );
}

#[tokio::test]
async fn an_untriggered_websocket_instance_is_unaffected() {
    let proxy_id = "carrier-ws-untriggered";
    let cfg = config(
        vec![make_proxy(proxy_id, "/ws", vec!["rl"])],
        vec![builtin("rl", "ws_rate_limiting", proxy_id)],
    );
    let plugins = published(&cfg, proxy_id);
    let mut ctx = request("/ws/anything");
    let (framing, frame) =
        collect_websocket_relay_plugins_decided_for_test(&plugins, true, &mut ctx);
    assert_eq!(framing.len(), 1, "an untriggered instance always binds");
    assert_eq!(frame.len(), 1);
}

// ---------------------------------------------------------------------------
// #3734 — UDP / DTLS flow binding
// ---------------------------------------------------------------------------

fn udp_stream_ctx(
    ip: &str,
    transport: StreamFrontendTransport,
    port: u16,
) -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext::new(
        ip.to_string(),
        ip.to_string(),
        "udp".to_string(),
        Some("udp".to_string()),
        port,
        BackendScheme::Udp,
        Arc::new(ConsumerIndex::new(&[])),
    );
    ctx.frontend_transport = transport;
    ctx.proxy_namespace = NS.to_string();
    ctx
}

fn udp_config(proxy_id: &str, port: u16, cidr: &str) -> GatewayConfig {
    config(
        vec![stream_proxy(proxy_id, BackendScheme::Udp, port, vec!["rl"])],
        vec![with_trigger(
            builtin("rl", "udp_rate_limiting", proxy_id),
            json!({"when": {"match": {"source_cidr": [cidr]}}}),
        )],
    )
}

/// Admit a flow through the real `on_stream_connect` chain, then bind the
/// session's datagram-hook list exactly as first-datagram admission does.
async fn admitted_flow_hooks(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut StreamConnectionContext,
) -> Arc<[Arc<dyn Plugin>]> {
    for plugin in plugins {
        let _ = plugin.on_stream_connect(ctx).await;
    }
    let datagram_plugins: Arc<[Arc<dyn Plugin>]> = plugins
        .iter()
        .filter(|plugin| plugin.requires_udp_datagram_hooks())
        .cloned()
        .collect();
    admitted_datagram_plugins_for_test(&datagram_plugins, ctx)
}

#[tokio::test]
async fn a_false_udp_trigger_removes_the_instance_from_the_flow_datagram_hooks() {
    let proxy_id = "carrier-udp-false";
    let plugins = published(&udp_config(proxy_id, 19_611, "10.0.0.0/8"), proxy_id);

    let mut outside = udp_stream_ctx("203.0.113.7", StreamFrontendTransport::Udp, 19_611);
    let hooks = admitted_flow_hooks(&plugins, &mut outside).await;
    assert!(
        hooks.is_empty(),
        "a false decision must mean zero datagram-hook work for the whole flow"
    );
}

#[tokio::test]
async fn a_true_udp_trigger_keeps_the_flow_datagram_hooks() {
    let proxy_id = "carrier-udp-true";
    let plugins = published(&udp_config(proxy_id, 19_612, "10.0.0.0/8"), proxy_id);

    let mut inside = udp_stream_ctx("10.4.4.4", StreamFrontendTransport::Udp, 19_612);
    for plugin in &plugins {
        let _ = plugin.on_stream_connect(&mut inside).await;
    }
    let datagram_plugins: Arc<[Arc<dyn Plugin>]> = plugins
        .iter()
        .filter(|plugin| plugin.requires_udp_datagram_hooks())
        .cloned()
        .collect();
    let hooks = admitted_datagram_plugins_for_test(&datagram_plugins, &inside);
    assert_eq!(hooks.len(), 1, "an admitted instance keeps its hooks");
    assert_eq!(hooks[0].name(), "udp_rate_limiting");
    assert!(
        Arc::ptr_eq(&hooks, &datagram_plugins),
        "an all-admitted flow must reuse the generation-owned hook list without allocating"
    );
}

#[tokio::test]
async fn a_dtls_flow_is_decided_the_same_way_as_plain_udp() {
    let proxy_id = "carrier-dtls";
    let plugins = published(&udp_config(proxy_id, 19_613, "10.0.0.0/8"), proxy_id);

    let mut skipped = udp_stream_ctx("198.51.100.9", StreamFrontendTransport::Dtls, 19_613);
    assert!(admitted_flow_hooks(&plugins, &mut skipped).await.is_empty());

    let mut admitted = udp_stream_ctx("10.5.5.5", StreamFrontendTransport::Dtls, 19_613);
    assert_eq!(admitted_flow_hooks(&plugins, &mut admitted).await.len(), 1);
}

#[tokio::test]
async fn a_decision_does_not_leak_across_flows_or_reused_client_tuples() {
    let proxy_id = "carrier-udp-tuple";
    let plugins = published(&udp_config(proxy_id, 19_614, "10.0.0.0/8"), proxy_id);

    // A skipped flow, then a NEW session from a different source on the same
    // listener: each session runs its own admission chain and owns its own
    // decisions, so nothing carries over.
    let mut skipped = udp_stream_ctx("203.0.113.8", StreamFrontendTransport::Udp, 19_614);
    assert!(admitted_flow_hooks(&plugins, &mut skipped).await.is_empty());

    let mut admitted = udp_stream_ctx("10.6.6.6", StreamFrontendTransport::Udp, 19_614);
    assert_eq!(admitted_flow_hooks(&plugins, &mut admitted).await.len(), 1);

    // Reusing the skipped tuple on a fresh session re-decides from scratch.
    let mut reused = udp_stream_ctx("203.0.113.8", StreamFrontendTransport::Udp, 19_614);
    assert!(admitted_flow_hooks(&plugins, &mut reused).await.is_empty());
}

#[tokio::test]
async fn a_generation_replacement_never_binds_an_old_decision_to_a_new_instance() {
    let proxy_id = "carrier-udp-generation";
    // Generation A skips this source.
    let old = published(&udp_config(proxy_id, 19_615, "10.0.0.0/8"), proxy_id);
    let mut ctx = udp_stream_ctx("192.0.2.10", StreamFrontendTransport::Udp, 19_615);
    assert!(admitted_flow_hooks(&old, &mut ctx).await.is_empty());

    // Generation B is a different published cache: its gate carries a fresh
    // token, so the retired generation's decision cannot be found — and the
    // missing-carrier rule runs the instance rather than inheriting a skip.
    let new = published(&udp_config(proxy_id, 19_615, "192.0.2.0/24"), proxy_id);
    let datagram_plugins: Arc<[Arc<dyn Plugin>]> = new
        .iter()
        .filter(|plugin| plugin.requires_udp_datagram_hooks())
        .cloned()
        .collect();
    let inherited = admitted_datagram_plugins_for_test(&datagram_plugins, &ctx);
    assert_eq!(
        inherited.len(),
        1,
        "a new generation must never inherit a retired generation's decision"
    );

    // Re-admitted through the new generation's own chain, the new predicate
    // decides for itself.
    let mut fresh = udp_stream_ctx("192.0.2.10", StreamFrontendTransport::Udp, 19_615);
    assert_eq!(admitted_flow_hooks(&new, &mut fresh).await.len(), 1);
}

#[tokio::test]
async fn an_untriggered_udp_instance_is_unaffected() {
    let proxy_id = "carrier-udp-untriggered";
    let cfg = config(
        vec![stream_proxy(
            proxy_id,
            BackendScheme::Udp,
            19_616,
            vec!["rl"],
        )],
        vec![builtin("rl", "udp_rate_limiting", proxy_id)],
    );
    let plugins = published(&cfg, proxy_id);
    let mut ctx = udp_stream_ctx("203.0.113.9", StreamFrontendTransport::Udp, 19_616);
    assert_eq!(
        admitted_flow_hooks(&plugins, &mut ctx).await.len(),
        1,
        "an untriggered instance keeps every datagram hook"
    );
}

// ---------------------------------------------------------------------------
// Hot-path structure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_flow_hook_list_is_bound_once_and_is_bounded_by_the_instance_count() {
    // The per-packet path traverses this list; binding it repeatedly must be
    // idempotent and must never grow it. This is the structural contract the
    // datagram benchmark asserts against.
    let proxy_id = "carrier-udp-bounded";
    let plugins = published(&udp_config(proxy_id, 19_617, "10.0.0.0/8"), proxy_id);
    let mut ctx = udp_stream_ctx("10.7.7.7", StreamFrontendTransport::Udp, 19_617);
    let first = admitted_flow_hooks(&plugins, &mut ctx).await;
    let second = admitted_datagram_plugins_for_test(&first, &ctx);
    assert_eq!(first.len(), second.len());
    assert!(
        first.len() <= plugins.len(),
        "the bound is the configured instance count"
    );
}

#[tokio::test]
async fn a_skipped_flow_costs_nothing_once_bound() {
    // The per-datagram path is a traversal of the bound list, so a skipped
    // instance is charged exactly once — at admission — and never again, no
    // matter how many datagrams the flow carries. The skip counter is the
    // observable proxy for "the gate was consulted".
    let proxy_id = "carrier-udp-once";
    let plugins = published(&udp_config(proxy_id, 19_618, "10.0.0.0/8"), proxy_id);
    let mut ctx = udp_stream_ctx("203.0.113.11", StreamFrontendTransport::Udp, 19_618);
    let hooks = admitted_flow_hooks(&plugins, &mut ctx).await;
    assert!(hooks.is_empty());

    // Every subsequent datagram of this flow traverses `hooks` — which is
    // exactly what `udp_datagram_allowed` receives — so re-binding must be a
    // pure, allocation-free identity and must never resurrect the instance.
    let mut bound = hooks;
    for _ in 0..1_000 {
        let next = admitted_datagram_plugins_for_test(&bound, &ctx);
        assert!(
            next.is_empty(),
            "a bound flow must never re-admit a skipped instance"
        );
        bound = next;
    }
}
