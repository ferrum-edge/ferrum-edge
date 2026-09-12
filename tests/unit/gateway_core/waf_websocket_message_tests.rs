//! WAF inspection of complete WebSocket application messages.
//!
//! Private advisory `GHSA-6j3m-vf5h-pgcx`: the WAF advertised WebSocket support
//! but stopped at the upgrade handshake, so an enforcing body rule that rejects
//! a payload on the HTTP path forwarded the same payload verbatim once it was
//! moved into a WebSocket message.
//!
//! Everything here drives the PRODUCTION composition path — the per-session
//! plugin collection (`Plugin::bind_ws_session` substitution) followed by the
//! shared `on_ws_frame` applicator. H1 Upgrade, H2 Extended CONNECT (RFC 8441)
//! and H3 Extended CONNECT (RFC 9220) all use those helpers inside
//! `run_websocket_proxy`; transport-entry tests separately pin the request
//! context each frontend supplies to the shared session binder.

use std::sync::Arc;

use ferrum_edge::_test_support::{
    apply_ws_frame_plugins_for_test, collect_websocket_relay_plugins_for_test,
};
use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, RequestContext, WebSocketFrameDirection};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

const PROXY_ID: &str = "ws-proxy";
const CONNECTION_ID: u64 = 7;

/// Payload token no built-in rule matches, so a block can only come from the
/// configured custom rule under test.
const PROHIBITED: &str = "ferrum-prohibited-token";

fn upgrade_ctx(path: &str) -> RequestContext {
    RequestContext::new(
        "203.0.113.10".to_string(),
        "GET".to_string(),
        path.to_string(),
    )
}

fn waf(config: Value) -> Arc<dyn Plugin> {
    Arc::new(Waf::new(&config).expect("valid waf config"))
}

/// Run the production per-session collection step and return the frame-hook
/// list the relay would use for this upgrade.
fn frame_plugins(plugins: &[Arc<dyn Plugin>], ctx: &RequestContext) -> Vec<Arc<dyn Plugin>> {
    let requires_websocket_framing = plugins.iter().any(|p| p.requires_websocket_framing());
    let (_framing, frame) =
        collect_websocket_relay_plugins_for_test(plugins, requires_websocket_framing, ctx);
    frame
}

async fn relay(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    direction: WebSocketFrameDirection,
    message: Message,
) -> Message {
    let frame = frame_plugins(plugins, ctx);
    apply_ws_frame_plugins_for_test(&frame, PROXY_ID, CONNECTION_ID, direction, message).await
}

async fn relay_to_backend(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    message: Message,
) -> Message {
    let direction = WebSocketFrameDirection::ClientToBackend;
    relay(plugins, ctx, direction, message).await
}

fn assert_policy_close(message: &Message) -> String {
    match message {
        Message::Close(Some(frame)) => {
            assert_eq!(
                frame.code,
                CloseCode::Policy,
                "WAF message rejection must use RFC 6455 code 1008"
            );
            frame.reason.as_str().to_string()
        }
        other => panic!("expected a policy Close, got {other:?}"),
    }
}

/// Enforcing client→backend (request-side) body rule.
fn enforcing_request_rule() -> Value {
    json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-WS-REQ",
            "name": "prohibited request token",
            "category": "custom",
            "target": "body_text",
            "match_kind": "contains",
            "pattern": PROHIBITED,
            "action": "enforce"
        }]
    })
}

/// Enforcing backend→client (response-side) body rule.
fn enforcing_response_rule() -> Value {
    json!({
        "include_default_rules": false,
        "response_inspection": true,
        "response_body_inspection": true,
        "custom_rules": [{
            "id": "CUSTOM-WS-RESP",
            "name": "prohibited response token",
            "category": "custom",
            "target": "response_body",
            "match_kind": "contains",
            "pattern": PROHIBITED,
            "action": "enforce"
        }]
    })
}

// ---------------------------------------------------------------------------
// The advisory itself: application messages are inspected, in both directions.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn text_message_matching_enforcing_rule_closes_client_to_backend() {
    let plugins = vec![waf(enforcing_request_rule())];
    let ctx = upgrade_ctx("/ws");
    let message = Message::Text(format!("query {PROHIBITED}").into());

    let outgoing = relay_to_backend(&plugins, &ctx, message).await;

    let reason = assert_policy_close(&outgoing);
    assert!(
        !reason.contains(PROHIBITED),
        "a close reason must never echo message bytes: {reason}"
    );
}

#[tokio::test]
async fn binary_message_is_inspected_like_text() {
    // A Binary opcode must not be a bypass: WebSocket messages carry no
    // Content-Type, so the HTTP `inspect_binary_body` selector deliberately
    // does not gate them (it is left at its restrictive default here).
    let plugins = vec![waf(enforcing_request_rule())];
    let ctx = upgrade_ctx("/ws");
    let message = Message::Binary(PROHIBITED.as_bytes().to_vec().into());

    let outgoing = relay_to_backend(&plugins, &ctx, message).await;

    assert_policy_close(&outgoing);
}

#[tokio::test]
async fn backend_to_client_message_uses_response_body_rules() {
    let plugins = vec![waf(enforcing_response_rule())];
    let ctx = upgrade_ctx("/ws");
    let direction = WebSocketFrameDirection::BackendToClient;
    let message = Message::Text(PROHIBITED.into());

    let outgoing = relay(&plugins, &ctx, direction, message).await;

    assert_policy_close(&outgoing);
}

#[tokio::test]
async fn request_rules_do_not_govern_backend_to_client_messages() {
    // Direction mapping must be exact: a request-body rule is not a response
    // control, exactly as on the HTTP path.
    let plugins = vec![waf(enforcing_request_rule())];
    let ctx = upgrade_ctx("/ws");
    let direction = WebSocketFrameDirection::BackendToClient;
    let original = Message::Text(PROHIBITED.into());

    let outgoing = relay(&plugins, &ctx, direction, original.clone()).await;

    assert_eq!(outgoing, original);
}

#[tokio::test]
async fn clean_message_is_forwarded_unchanged() {
    let plugins = vec![waf(enforcing_request_rule())];
    let ctx = upgrade_ctx("/ws");
    let original = Message::Text("an ordinary lookup".into());

    let outgoing = relay_to_backend(&plugins, &ctx, original.clone()).await;

    assert_eq!(outgoing, original);
}

#[tokio::test]
async fn builtin_rule_pack_applies_to_websocket_messages() {
    // Not just custom rules: the built-in pack is the same rule engine.
    // FE-PROTO-001 (`__proto__`) is a body_text rule, promoted to enforce.
    let config = json!({ "rule_modes": { "FE-PROTO-001": "enforce" } });
    let plugins = vec![waf(config)];
    let ctx = upgrade_ctx("/ws");
    let message = Message::Text("{\"__proto__\":{\"admin\":true}}".into());

    let outgoing = relay_to_backend(&plugins, &ctx, message).await;

    assert_policy_close(&outgoing);
}

// ---------------------------------------------------------------------------
// Protocol correctness: control frames, monitor mode, exemptions, conditions.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn control_frames_are_never_scanned_as_application_payload() {
    let plugins = vec![waf(enforcing_request_rule())];
    let ctx = upgrade_ctx("/ws");
    let payload = PROHIBITED.as_bytes().to_vec();
    let controls = [
        Message::Ping(payload.clone().into()),
        Message::Pong(payload.into()),
    ];
    let directions = [
        WebSocketFrameDirection::ClientToBackend,
        WebSocketFrameDirection::BackendToClient,
    ];

    for control in controls {
        for direction in directions {
            let outgoing = relay(&plugins, &ctx, direction, control.clone()).await;
            assert_eq!(
                outgoing, control,
                "control frames must keep ping/pong semantics untouched"
            );
        }
    }
}

#[tokio::test]
async fn peer_close_is_never_replaced() {
    let plugins = vec![waf(enforcing_request_rule())];
    let ctx = upgrade_ctx("/ws");
    let peer_close = Message::Close(None);

    let outgoing = relay_to_backend(&plugins, &ctx, peer_close.clone()).await;

    assert_eq!(outgoing, peer_close);
}

#[tokio::test]
async fn monitor_mode_never_closes_a_session() {
    let mut config = enforcing_request_rule();
    config["mode"] = json!("monitor");
    let plugins = vec![waf(config)];
    let ctx = upgrade_ctx("/ws");
    let original = Message::Text(PROHIBITED.into());

    let outgoing = relay_to_backend(&plugins, &ctx, original.clone()).await;

    assert_eq!(outgoing, original);
}

#[tokio::test]
async fn log_to_stdout_monitor_mode_logs_monitored_effective_action() {
    let (logs, guard) = crate::unit::plugins::plugin_utils::capture_debug_logs();
    let mut config = enforcing_request_rule();
    config["mode"] = json!("monitor");
    config["log_to_stdout"] = json!(true);
    let plugins = vec![waf(config)];
    let ctx = upgrade_ctx("/ws");
    let original = Message::Text(PROHIBITED.into());

    let outgoing = relay_to_backend(&plugins, &ctx, original.clone()).await;
    drop(guard);

    assert_eq!(outgoing, original);
    let captured = logs.contents();
    let hit = captured
        .lines()
        .find(|line| {
            line.contains("DEBUG") && line.contains("WAF rule matched on a WebSocket message")
        })
        .expect("each WebSocket rule hit retains its debug diagnostic");
    assert!(
        hit.contains("action=monitored"),
        "monitor-mode hit must log monitored effective action: {captured}"
    );
    assert!(
        hit.contains("rule_action=enforce"),
        "configured enforce action must remain visible: {captured}"
    );
    assert!(
        !hit.split_whitespace()
            .any(|field| field.trim_end_matches(',') == "action=block"),
        "must not log the legacy exact action=block field: {captured}"
    );
}

#[tokio::test]
async fn log_to_stdout_enforce_mode_logs_blocked_effective_action() {
    let (logs, guard) = crate::unit::plugins::plugin_utils::capture_debug_logs();
    let mut config = enforcing_request_rule();
    config["log_to_stdout"] = json!(true);
    let plugins = vec![waf(config)];
    let ctx = upgrade_ctx("/ws");
    let message = Message::Text(PROHIBITED.into());

    let outgoing = relay_to_backend(&plugins, &ctx, message).await;
    drop(guard);

    assert_policy_close(&outgoing);
    let captured = logs.contents();
    let hit = captured
        .lines()
        .find(|line| {
            line.contains("DEBUG") && line.contains("WAF rule matched on a WebSocket message")
        })
        .expect("each WebSocket rule hit retains its debug diagnostic");
    assert!(
        hit.contains("action=blocked"),
        "enforce-mode hit must log blocked effective action: {captured}"
    );
    assert!(
        hit.contains("rule_action=enforce"),
        "configured enforce action must remain visible: {captured}"
    );
}

#[tokio::test]
async fn upgrade_request_exemption_applies_to_the_whole_session() {
    let mut config = enforcing_request_rule();
    config["global_exemptions"] = json!({ "paths": ["/exempt-ws"] });
    let plugins = vec![waf(config)];
    let original = Message::Text(PROHIBITED.into());

    let exempt_ctx = upgrade_ctx("/exempt-ws");
    let exempt = relay_to_backend(&plugins, &exempt_ctx, original.clone()).await;
    assert_eq!(exempt, original, "an exempt upgrade must not block");

    let governed_ctx = upgrade_ctx("/ws");
    let governed = relay_to_backend(&plugins, &governed_ctx, original).await;
    assert_policy_close(&governed);
}

#[tokio::test]
async fn rule_conditions_are_resolved_from_the_upgrade_request() {
    let plugins = vec![waf(json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-WS-COND",
            "name": "conditional token",
            "category": "custom",
            "target": "body_text",
            "match_kind": "contains",
            "pattern": PROHIBITED,
            "action": "enforce",
            "conditions": { "paths": ["/governed-ws"] }
        }]
    }))];
    let original = Message::Text(PROHIBITED.into());

    let governed_ctx = upgrade_ctx("/governed-ws");
    let governed = relay_to_backend(&plugins, &governed_ctx, original.clone()).await;
    assert_policy_close(&governed);

    let other_ctx = upgrade_ctx("/other-ws");
    let other = relay_to_backend(&plugins, &other_ctx, original.clone()).await;
    assert_eq!(
        other, original,
        "a rule whose upgrade-time conditions did not match cannot block"
    );
}

#[tokio::test]
async fn header_conditions_are_resolved_from_the_upgrade_request() {
    let plugins = vec![waf(json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-WS-HEADER-COND",
            "name": "tenant-conditioned token",
            "category": "custom",
            "target": "body_text",
            "match_kind": "contains",
            "pattern": PROHIBITED,
            "action": "enforce",
            "conditions": { "headers": { "x-tenant": "acme" } }
        }]
    }))];
    let original = Message::Text(PROHIBITED.into());

    let mut governed_ctx = upgrade_ctx("/ws");
    governed_ctx
        .headers
        .insert("x-tenant".to_string(), "acme".to_string());
    let governed = relay_to_backend(&plugins, &governed_ctx, original.clone()).await;
    assert_policy_close(&governed);

    let mut other_ctx = upgrade_ctx("/ws");
    other_ctx
        .headers
        .insert("x-tenant".to_string(), "other".to_string());
    let other = relay_to_backend(&plugins, &other_ctx, original.clone()).await;
    assert_eq!(
        other, original,
        "a header-conditioned rule must not govern a different tenant"
    );
}

#[tokio::test]
async fn header_present_exemption_is_bound_for_the_whole_session() {
    let mut config = enforcing_request_rule();
    config["global_exemptions"] = json!({
        "header_present": { "x-skip-waf": null }
    });
    let plugins = vec![waf(config)];
    let original = Message::Text(PROHIBITED.into());

    let mut exempt_ctx = upgrade_ctx("/ws");
    exempt_ctx
        .headers
        .insert("x-skip-waf".to_string(), "1".to_string());
    let exempt = relay_to_backend(&plugins, &exempt_ctx, original.clone()).await;
    assert_eq!(
        exempt, original,
        "a header-exempt upgrade must suppress message rules for the session"
    );

    let governed_ctx = upgrade_ctx("/ws");
    let governed = relay_to_backend(&plugins, &governed_ctx, original).await;
    assert_policy_close(&governed);
}

// ---------------------------------------------------------------------------
// Size and uninspectable policy.
// ---------------------------------------------------------------------------

/// 64 bytes of benign padding, well past the 16-byte scan cap used below, with
/// the prohibited token hidden in the unscannable suffix.
fn oversize_message() -> Message {
    let padding = "a".repeat(64);
    Message::Text(format!("{padding}{PROHIBITED}").into())
}

#[tokio::test]
async fn oversize_message_fails_closed_by_default() {
    let mut config = enforcing_request_rule();
    config["max_scan_bytes"] = json!(16);
    let plugins = vec![waf(config)];
    let ctx = upgrade_ctx("/ws");

    let outgoing = relay_to_backend(&plugins, &ctx, oversize_message()).await;

    let reason = assert_policy_close(&outgoing);
    assert!(
        !reason.contains(PROHIBITED),
        "a close reason must never echo message bytes: {reason}"
    );
}

#[tokio::test]
async fn oversize_message_without_enforcing_policy_is_forwarded() {
    // Monitor-only policy: an unscannable message is a lost observation, not a
    // protection failure, exactly as on the HTTP body path.
    let mut config = enforcing_request_rule();
    config["max_scan_bytes"] = json!(16);
    config["mode"] = json!("monitor");
    let plugins = vec![waf(config)];
    let ctx = upgrade_ctx("/ws");
    let original = oversize_message();

    let outgoing = relay_to_backend(&plugins, &ctx, original.clone()).await;

    assert_eq!(outgoing, original);
}

#[tokio::test]
async fn oversize_message_scan_truncated_opt_out_forwards() {
    let mut config = enforcing_request_rule();
    config["max_scan_bytes"] = json!(16);
    config["on_body_too_large"] = json!("scan_truncated");
    let plugins = vec![waf(config)];
    let ctx = upgrade_ctx("/ws");
    let original = oversize_message();

    let outgoing = relay_to_backend(&plugins, &ctx, original.clone()).await;

    assert_eq!(
        outgoing, original,
        "the documented prefix-only opt-out still forwards the suffix"
    );
}

#[tokio::test]
async fn oversize_message_skip_forwards_uninspected() {
    let mut config = enforcing_request_rule();
    config["max_scan_bytes"] = json!(16);
    config["on_body_too_large"] = json!("skip");
    let plugins = vec![waf(config)];
    let ctx = upgrade_ctx("/ws");
    let original = oversize_message();

    let outgoing = relay_to_backend(&plugins, &ctx, original.clone()).await;

    assert_eq!(outgoing, original);
}

#[tokio::test]
async fn oversize_message_block_action_closes_without_enforcing_rule() {
    // `on_body_too_large: block` is itself the enforcement path: a monitor-only
    // body rule is enough to bind the session, and the oversize close comes
    // from `block` under `mode: enforce`, not from any rule hit.
    let plugins = vec![waf(json!({
        "include_default_rules": false,
        "max_scan_bytes": 16,
        "on_body_too_large": "block",
        "custom_rules": [
            {
                "id": "CUSTOM-WS-MONITOR",
                "name": "monitored token",
                "category": "custom",
                "target": "body_text",
                "match_kind": "contains",
                "pattern": PROHIBITED,
                "action": "monitor"
            }
        ]
    }))];
    let ctx = upgrade_ctx("/ws");

    let outgoing = relay_to_backend(&plugins, &ctx, oversize_message()).await;

    assert_policy_close(&outgoing);
}

#[tokio::test]
async fn a_message_at_the_scan_ceiling_is_still_fully_inspected() {
    let mut config = enforcing_request_rule();
    config["max_scan_bytes"] = json!(PROHIBITED.len());
    let plugins = vec![waf(config)];
    let ctx = upgrade_ctx("/ws");
    let message = Message::Text(PROHIBITED.into());

    let outgoing = relay_to_backend(&plugins, &ctx, message).await;

    assert_policy_close(&outgoing);
}

#[tokio::test]
async fn scan_timeout_block_closes_the_session() {
    let mut config = enforcing_request_rule();
    config["scan_budget_ms"] = json!(1);
    config["on_scan_timeout"] = json!("block");
    let plugins = vec![waf(config)];
    let ctx = upgrade_ctx("/ws");

    // A large clean message under a 1 ms budget: the scan runs to completion
    // but over budget, so `on_scan_timeout` decides. `block` must close.
    let message = Message::Text("a".repeat(1_000_000).into());
    let outgoing = relay_to_backend(&plugins, &ctx, message).await;

    assert_policy_close(&outgoing);
}

// ---------------------------------------------------------------------------
// Session binding and multi-instance behavior.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn body_rule_free_waf_keeps_handshake_only_behavior() {
    // Only response-header rules: nothing governs messages, so the proxy must
    // not be pulled into the parsed relay on this plugin's account.
    let plugin = waf(json!({
        "include_default_rules": false,
        "request_body_inspection": false,
        "response_inspection": true,
        "custom_rules": [{
            "id": "CUSTOM-RESP-HEADER",
            "name": "header rule",
            "category": "custom",
            "target": "response_headers",
            "match_kind": "contains",
            "pattern": "x-leak",
            "action": "enforce"
        }]
    }));

    assert!(
        !plugin.requires_ws_frame_hooks(),
        "a WAF with no message policy must not force the parsed relay"
    );
    assert!(!plugin.requires_websocket_framing());

    let frame = frame_plugins(&[plugin], &upgrade_ctx("/ws"));
    assert!(frame.is_empty(), "no message policy, no per-message hook");
}

#[tokio::test]
async fn message_governing_waf_opts_into_the_parsed_relay() {
    let plugin = waf(enforcing_request_rule());
    assert!(plugin.requires_ws_frame_hooks());
    assert!(plugin.requires_websocket_framing());

    let frame = frame_plugins(&[plugin], &upgrade_ctx("/ws"));

    assert_eq!(frame.len(), 1, "one bound instance per config");
    assert_eq!(frame[0].name(), "waf");
    assert!(frame[0].requires_ws_frame_hooks());
}

#[tokio::test]
async fn unbound_instance_fails_closed_on_application_messages() {
    // The bound substitute is what the relay uses. If a relay path ever
    // collected frame hooks WITHOUT binding, the shared instance has no
    // admission-time policy snapshot and must not forward unscanned bytes.
    let plugin = waf(enforcing_request_rule());
    let direction = WebSocketFrameDirection::ClientToBackend;
    let benign = Message::Text("entirely benign".into());

    let closed = plugin
        .on_ws_frame(PROXY_ID, CONNECTION_ID, direction, &benign)
        .await
        .expect("an unbound WAF must fail closed on a message");
    assert_policy_close(&closed);

    let ping = Message::Ping(Vec::new().into());
    let forwarded = plugin
        .on_ws_frame(PROXY_ID, CONNECTION_ID, direction, &ping)
        .await;
    assert!(forwarded.is_none(), "control frames still pass through");
}

#[tokio::test]
async fn multiple_waf_instances_bind_and_scan_independently() {
    // Two configured instances with disjoint rules: each participates, and a
    // message either one governs is blocked. No shared state, no collisions.
    let first = waf(json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-WS-ONE",
            "name": "token one",
            "category": "custom",
            "target": "body_text",
            "match_kind": "contains",
            "pattern": "token-one",
            "action": "enforce"
        }]
    }));
    let second = waf(json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-WS-TWO",
            "name": "token two",
            "category": "custom",
            "target": "body_text",
            "match_kind": "contains",
            "pattern": "token-two",
            "action": "enforce"
        }]
    }));
    let plugins = vec![first, second];
    let ctx = upgrade_ctx("/ws");

    assert_eq!(
        frame_plugins(&plugins, &ctx).len(),
        2,
        "every configured instance binds its own session policy"
    );

    for token in ["token-one", "token-two"] {
        let message = Message::Text(token.into());
        let outgoing = relay_to_backend(&plugins, &ctx, message).await;
        assert_policy_close(&outgoing);
    }

    let clean = Message::Text("token-three".into());
    let outgoing = relay_to_backend(&plugins, &ctx, clean.clone()).await;
    assert_eq!(outgoing, clean);
}

#[tokio::test]
async fn anomaly_scoring_is_evaluated_per_message() {
    // Two monitor-action hits on ONE message cross the threshold. A session
    // accumulator would instead let two separate under-threshold messages
    // combine, which is exactly what a long-lived connection must not do.
    let plugins = vec![waf(json!({
        "include_default_rules": false,
        "scoring": { "block_threshold": 6, "weights": { "high": 5 } },
        "custom_rules": [
            {
                "id": "CUSTOM-SCORE-A",
                "name": "score a",
                "category": "custom",
                "severity": "high",
                "target": "body_text",
                "match_kind": "contains",
                "pattern": "alpha",
                "action": "monitor"
            },
            {
                "id": "CUSTOM-SCORE-B",
                "name": "score b",
                "category": "custom",
                "severity": "high",
                "target": "body_text",
                "match_kind": "contains",
                "pattern": "beta",
                "action": "monitor"
            }
        ]
    }))];
    let ctx = upgrade_ctx("/ws");

    let single = Message::Text("alpha".into());
    let outgoing = relay_to_backend(&plugins, &ctx, single.clone()).await;
    assert_eq!(
        outgoing, single,
        "one high hit (5) stays under the threshold (6)"
    );

    // Same session, second message: still under the threshold on its own.
    let second = Message::Text("beta".into());
    let outgoing = relay_to_backend(&plugins, &ctx, second.clone()).await;
    assert_eq!(
        outgoing, second,
        "scores must not accumulate across a long-lived session"
    );

    let both = Message::Text("alpha and beta".into());
    let outgoing = relay_to_backend(&plugins, &ctx, both).await;
    assert_policy_close(&outgoing);
}

// ── Issue #5118: fp filters govern non-UTF-8 binary messages too ────────────

/// A binary message carrying non-UTF-8 bytes went down the byte-match path,
/// which recorded the hit without consulting per-rule `fp_filters` or global
/// `fp_capture_filters`. WebSocket messages carry no Content-Type, so this is
/// the ordinary shape of binary WebSocket traffic, not an edge case.
fn fp_filtered_request_rule(global: bool) -> Value {
    let mut rule = json!({
        "id": "CUSTOM-WS-FP",
        "name": "prohibited request token",
        "category": "custom",
        "target": "body_text",
        "match_kind": "contains",
        "pattern": PROHIBITED,
        "action": "enforce"
    });
    let mut config = json!({ "include_default_rules": false });
    if global {
        config["global_exemptions"] = json!({ "fp_capture_filters": ["allow-note"] });
    } else {
        rule["fp_filters"] = json!(["allow-note"]);
    }
    config["custom_rules"] = json!([rule]);
    config
}

fn non_utf8_message(payload: &str) -> Message {
    let mut bytes = payload.as_bytes().to_vec();
    bytes.push(0xff);
    Message::Binary(bytes.into())
}

#[tokio::test]
async fn non_utf8_binary_message_honours_per_rule_fp_filters() {
    let plugins = vec![waf(fp_filtered_request_rule(false))];
    let ctx = upgrade_ctx("/ws");
    let filtered = format!("{PROHIBITED} allow-note");

    let outgoing = relay_to_backend(&plugins, &ctx, non_utf8_message(&filtered)).await;

    assert_eq!(
        outgoing,
        non_utf8_message(&filtered),
        "a filtered binary message must be forwarded verbatim"
    );
}

#[tokio::test]
async fn non_utf8_binary_message_honours_global_fp_capture_filters() {
    let plugins = vec![waf(fp_filtered_request_rule(true))];
    let ctx = upgrade_ctx("/ws");
    let filtered = format!("{PROHIBITED} allow-note");

    let outgoing = relay_to_backend(&plugins, &ctx, non_utf8_message(&filtered)).await;

    assert_eq!(outgoing, non_utf8_message(&filtered));
}

#[tokio::test]
async fn a_non_utf8_binary_filter_miss_is_still_blocked() {
    for global in [false, true] {
        let plugins = vec![waf(fp_filtered_request_rule(global))];
        let ctx = upgrade_ctx("/ws");

        let outgoing = relay_to_backend(&plugins, &ctx, non_utf8_message(PROHIBITED)).await;

        assert_policy_close(&outgoing);
    }
}
