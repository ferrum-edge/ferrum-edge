//! `on_unlisted_content_type`: request bodies the WAF will not inspect because
//! their `Content-Type` falls outside `body_content_types` /
//! `inspect_multipart` / `inspect_binary_body`.
//!
//! The declared media type is attacker-controlled and many backends parse the
//! body without consulting it, so relabelling a JSON injection payload as
//! `application/octet-stream` (or dropping the header) used to skip every body
//! rule. `allow` keeps that behavior; `fail_closed` (the default) refuses a
//! non-empty unlisted body when an enforcing request-body policy applies;
//! `block` refuses every non-empty unlisted body while globally enforcing.
//!
//! `on_unlisted_response_content_type` is the response-side counterpart
//! (default `fail_closed`).

use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::{Value, json};
use std::collections::HashMap;

const SQLI_JSON: &[u8] = br#"{"id":"1 UNION SELECT password FROM users"}"#;

fn waf(mut config: Value) -> Result<Waf, String> {
    if let Some(object) = config.as_object_mut()
        && !object.contains_key("scan_budget_ms")
    {
        object.insert("scan_budget_ms".to_string(), json!(0));
    }
    Waf::new(&config)
}

fn recommended(on_unlisted_content_type: &str) -> Waf {
    waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "on_unlisted_content_type": on_unlisted_content_type
    }))
    .unwrap()
}

fn request(method: &str, path: &str, content_type: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::new("203.0.113.10".into(), method.into(), path.into());
    if let Some(content_type) = content_type {
        ctx.headers
            .insert("content-type".into(), content_type.into());
    }
    ctx
}

/// Drive the finalized-body decision the proxy runs after buffering.
async fn final_body(
    plugin: &Waf,
    ctx: &mut RequestContext,
    headers: &HashMap<String, String>,
    body: &[u8],
) -> PluginResult {
    plugin
        .on_final_request_body_with_context(ctx, headers, body)
        .await
}

async fn post(
    plugin: &Waf,
    content_type: Option<&str>,
    body: &[u8],
) -> (bool, PluginResult, RequestContext) {
    let mut ctx = request("POST", "/api/items", content_type);
    let buffers = plugin.should_buffer_request_body(&ctx);
    let headers = ctx.headers.clone();
    let result = final_body(plugin, &mut ctx, &headers, body).await;
    (buffers, result, ctx)
}

fn meta<'a>(ctx: &'a RequestContext, key: &str) -> Option<&'a str> {
    ctx.metadata.get(key).map(String::as_str)
}

fn is_reject(result: &PluginResult) -> bool {
    matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    )
}

#[tokio::test]
async fn allow_leaves_unlisted_bodies_uninspected() {
    let plugin = recommended("allow");
    for content_type in [
        Some("application/octet-stream"),
        Some("text/csv"),
        Some("multipart/form-data; boundary=x"),
        None,
    ] {
        let (buffers, result, ctx) = post(&plugin, content_type, SQLI_JSON).await;
        assert!(!buffers, "{content_type:?} must keep the streaming path");
        assert!(matches!(result, PluginResult::Continue), "{content_type:?}");
        assert_eq!(meta(&ctx, "waf.body_uninspected"), None);
        assert_eq!(meta(&ctx, "waf.rule_hits"), None);
    }
    // The same payload under a scanned type is blocked by the body rules.
    let (_, result, _) = post(&plugin, Some("application/json"), SQLI_JSON).await;
    assert!(is_reject(&result));
}

#[tokio::test]
async fn block_refuses_every_non_empty_unlisted_body() {
    let plugin = recommended("block");
    for content_type in [
        Some("application/octet-stream"),
        Some("text/csv"),
        Some("multipart/form-data; boundary=x"),
        Some("application/grpc"),
        None,
    ] {
        let (buffers, result, ctx) = post(&plugin, content_type, b"anything at all").await;
        assert!(
            buffers,
            "{content_type:?} must be buffered so the exact body decides"
        );
        assert!(is_reject(&result), "{content_type:?}");
        assert_eq!(meta(&ctx, "waf.block_reason"), Some("content_type"));
        assert_eq!(meta(&ctx, "waf.body_uninspected"), Some("content_type"));
        assert_eq!(meta(&ctx, "waf.action"), Some("blocked"));
    }

    // An empty upload carries nothing to inspect.
    let (_, result, ctx) = post(&plugin, Some("application/octet-stream"), b"").await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&ctx, "waf.body_uninspected"), None);

    // Listed types are scanned as before, not refused for their type.
    let (_, result, ctx) = post(&plugin, Some("application/json"), br#"{"ok":true}"#).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&ctx, "waf.body_uninspected"), None);
}

#[tokio::test]
async fn scan_scope_toggles_move_a_type_out_of_the_unlisted_set() {
    let plugin = waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "on_unlisted_content_type": "block",
        "inspect_multipart": true,
        "body_content_types": ["application/json", "text/csv"]
    }))
    .unwrap();
    for content_type in ["multipart/form-data; boundary=x", "text/csv"] {
        let (_, result, ctx) = post(&plugin, Some(content_type), b"name,qty\nwidget,2\n").await;
        assert!(matches!(result, PluginResult::Continue), "{content_type}");
        assert_eq!(meta(&ctx, "waf.body_uninspected"), None);
    }
    // ...and a now-inspected type is subject to the rules instead.
    let (_, result, ctx) = post(&plugin, Some("text/csv"), b"1 UNION SELECT password").await;
    assert!(is_reject(&result));
    assert_eq!(meta(&ctx, "waf.block_reason"), Some("rule"));
}

#[tokio::test]
async fn non_body_methods_and_exempt_requests_are_not_governed() {
    let plugin = waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "on_unlisted_content_type": "block",
        "global_exemptions": { "paths": ["/uploads*"] }
    }))
    .unwrap();

    let mut get = request("GET", "/api/items", Some("application/octet-stream"));
    assert!(!plugin.should_buffer_request_body(&get));
    let headers = get.headers.clone();
    let result = final_body(&plugin, &mut get, &headers, b"payload").await;
    assert!(matches!(result, PluginResult::Continue));

    let mut exempt = request("POST", "/uploads/avatar", Some("image/png"));
    assert!(!plugin.should_buffer_request_body(&exempt));
    let headers = exempt.headers.clone();
    let result = final_body(&plugin, &mut exempt, &headers, b"\x89PNG....").await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn fail_closed_refuses_only_where_an_enforcing_body_rule_applies() {
    // The enforcing body rule is scoped to `/api/*`; elsewhere the only body
    // rule is monitor-only, so an unlisted body there is observed, not refused.
    let plugin = waf(json!({
        "mode": "enforce",
        "include_default_rules": false,
        "on_unlisted_content_type": "fail_closed",
        "custom_rules": [
            {
                "id": "API-BODY",
                "category": "custom",
                "target": "body_text",
                "match_kind": "contains",
                "pattern": "forbidden",
                "action": "enforce",
                "conditions": { "paths": ["/api/*"] }
            },
            {
                "id": "ANY-BODY",
                "category": "custom",
                "target": "body_text",
                "match_kind": "contains",
                "pattern": "noted",
                "action": "monitor"
            }
        ]
    }))
    .unwrap();

    let mut scoped = request("POST", "/api/items", Some("application/octet-stream"));
    assert!(plugin.should_buffer_request_body(&scoped));
    let headers = scoped.headers.clone();
    let result = final_body(&plugin, &mut scoped, &headers, b"payload").await;
    assert!(is_reject(&result));
    assert_eq!(meta(&scoped, "waf.block_reason"), Some("content_type"));

    let mut unscoped = request("POST", "/public/items", Some("application/octet-stream"));
    assert!(
        !plugin.should_buffer_request_body(&unscoped),
        "a body that cannot be refused keeps the streaming path"
    );
    let headers = unscoped.headers.clone();
    let result = final_body(&plugin, &mut unscoped, &headers, b"payload").await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        meta(&unscoped, "waf.body_uninspected"),
        Some("content_type")
    );
    assert_eq!(meta(&unscoped, "waf.block_reason"), None);
}

#[tokio::test]
async fn monitor_mode_observes_declared_unlisted_bodies_without_buffering() {
    let plugin = waf(json!({
        "mode": "monitor",
        "on_unlisted_content_type": "block"
    }))
    .unwrap();

    let mut declared = request("POST", "/api/items", Some("application/octet-stream"));
    declared
        .headers
        .insert("content-length".into(), "15".into());
    assert!(!plugin.should_buffer_request_body(&declared));
    let result = plugin.authorize(&mut declared).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        meta(&declared, "waf.body_uninspected"),
        Some("content_type")
    );

    let mut chunked = request("PUT", "/api/items", None);
    chunked
        .headers
        .insert("transfer-encoding".into(), "chunked".into());
    let _ = plugin.authorize(&mut chunked).await;
    assert_eq!(meta(&chunked, "waf.body_uninspected"), Some("content_type"));

    let mut empty = request("POST", "/api/items", Some("application/octet-stream"));
    empty.headers.insert("content-length".into(), "0".into());
    let _ = plugin.authorize(&mut empty).await;
    assert_eq!(meta(&empty, "waf.body_uninspected"), None);

    let mut listed = request("POST", "/api/items", Some("application/json"));
    listed.headers.insert("content-length".into(), "2".into());
    let _ = plugin.authorize(&mut listed).await;
    assert_eq!(meta(&listed, "waf.body_uninspected"), None);
}

#[tokio::test]
async fn the_finalized_headers_decide() {
    // A request transformer can rewrite `Content-Type` before the body is
    // finalized; the decision follows the backend-visible map.
    let plugin = recommended("block");
    let mut ctx = request("POST", "/api/items", Some("application/octet-stream"));
    let mut finalized = ctx.headers.clone();
    finalized.insert("content-type".into(), "application/json".into());

    let result = final_body(&plugin, &mut ctx, &finalized, SQLI_JSON).await;
    assert!(is_reject(&result));
    assert_eq!(
        meta(&ctx, "waf.block_reason"),
        Some("rule"),
        "a finalized JSON body is scanned, not refused for its type"
    );
}

#[tokio::test]
async fn a_transformer_that_relabels_a_scanned_body_as_unlisted_is_refused() {
    // The inbound type is scanned, so the body is buffered for the rules; a
    // request transformer then rewrites it to a type the rules skip. The
    // finalized map decides, so the relabelled body is refused for its type.
    let plugin = recommended("block");
    let mut ctx = request("POST", "/api/items", Some("application/json"));
    assert!(plugin.should_buffer_request_body(&ctx));
    let mut finalized = ctx.headers.clone();
    finalized.insert("content-type".into(), "application/octet-stream".into());

    let result = final_body(&plugin, &mut ctx, &finalized, SQLI_JSON).await;
    assert!(is_reject(&result));
    assert_eq!(meta(&ctx, "waf.block_reason"), Some("content_type"));

    // Benign twin: the same rewrite of an empty body carries nothing to refuse.
    let mut empty = request("POST", "/api/items", Some("application/json"));
    let result = final_body(&plugin, &mut empty, &finalized, b"").await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&empty, "waf.body_uninspected"), None);
}

#[tokio::test]
async fn log_to_metadata_false_still_refuses_but_records_nothing() {
    let plugin = waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "on_unlisted_content_type": "block",
        "log_to_metadata": false
    }))
    .unwrap();
    let (buffers, result, ctx) = post(&plugin, Some("application/octet-stream"), SQLI_JSON).await;
    assert!(buffers);
    assert!(is_reject(&result));
    assert_eq!(meta(&ctx, "waf.body_uninspected"), None);
    assert_eq!(meta(&ctx, "waf.block_reason"), None);

    // Observe-only path: monitor mode with metadata off writes nothing.
    let plugin = waf(json!({
        "mode": "monitor",
        "on_unlisted_content_type": "block",
        "log_to_metadata": false
    }))
    .unwrap();
    let mut declared = request("POST", "/api/items", Some("application/octet-stream"));
    declared
        .headers
        .insert("content-length".into(), "15".into());
    let result = plugin.authorize(&mut declared).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&declared, "waf.body_uninspected"), None);
}

#[tokio::test]
async fn fail_closed_in_monitor_mode_observes_and_never_refuses() {
    let plugin = waf(json!({
        "mode": "monitor",
        "default_rule_action": "enforce",
        "on_unlisted_content_type": "fail_closed"
    }))
    .unwrap();

    let mut declared = request("POST", "/api/items", Some("application/octet-stream"));
    declared
        .headers
        .insert("content-length".into(), "43".into());
    assert!(
        !plugin.should_buffer_request_body(&declared),
        "monitor mode never buffers an unlisted body"
    );
    let result = plugin.authorize(&mut declared).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        meta(&declared, "waf.body_uninspected"),
        Some("content_type")
    );

    let (_, result, ctx) = post(&plugin, Some("application/octet-stream"), SQLI_JSON).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&ctx, "waf.block_reason"), None);
    assert_eq!(meta(&ctx, "waf.action"), None);
}

#[test]
fn block_is_not_an_admission_enforcement_path_when_every_type_is_scanned() {
    // With both scope toggles on, no body is ever unlisted, so `block` cannot
    // fire and the monitor-only default pack leaves nothing that can block.
    let error = waf(json!({
        "mode": "enforce",
        "inspect_binary_body": true,
        "inspect_multipart": true,
        "on_unlisted_content_type": "block"
    }))
    .unwrap_err();
    assert!(error.contains("no enabled enforcement path"), "{error}");

    // Either toggle alone leaves some type unlisted, so `block` is reachable.
    for toggle in ["inspect_binary_body", "inspect_multipart"] {
        let mut config = json!({ "mode": "enforce", "on_unlisted_content_type": "block" });
        config[toggle] = json!(true);
        assert!(waf(config).is_ok(), "{toggle}");
    }
}

#[tokio::test]
async fn block_with_every_type_scanned_is_admitted_beside_an_enforcing_rule() {
    // Accepted twin of the rejection above: `block` is still dead
    // configuration, but an enforcing body rule is a reachable path of its
    // own. Every type, a missing one included, is scanned rather than refused.
    let plugin = waf(json!({
        "mode": "enforce",
        "inspect_binary_body": true,
        "inspect_multipart": true,
        "on_unlisted_content_type": "block",
        "rule_modes": { "FE-SQLI-001-B": "enforce" }
    }))
    .unwrap();
    for ct in [Some("application/octet-stream"), Some("text/csv"), None] {
        let (_, result, ctx) = post(&plugin, ct, br#"{"name":"widget"}"#).await;
        assert!(matches!(result, PluginResult::Continue), "{ct:?}");
        assert_eq!(meta(&ctx, "waf.body_uninspected"), None, "{ct:?}");

        let (_, result, ctx) = post(&plugin, ct, SQLI_JSON).await;
        assert!(is_reject(&result), "{ct:?}");
        assert_eq!(meta(&ctx, "waf.block_reason"), Some("rule"), "{ct:?}");
    }
}

#[tokio::test]
async fn block_is_not_an_admission_enforcement_path_without_body_methods() {
    // `body_methods: []` governs no HTTP request body, so `block` can never
    // fire and the monitor-only default pack leaves nothing that can block.
    let error = waf(json!({
        "mode": "enforce",
        "body_methods": [],
        "on_unlisted_content_type": "block"
    }))
    .unwrap_err();
    assert!(error.contains("no enabled enforcement path"), "{error}");
    assert!(
        error.contains("at least one `body_methods` entry"),
        "{error}"
    );

    // Any listed method makes it reachable again.
    waf(json!({
        "mode": "enforce",
        "body_methods": ["POST"],
        "on_unlisted_content_type": "block"
    }))
    .unwrap();

    // Accepted beside another enforcement path, where `block` stays inert.
    let plugin = waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "body_methods": [],
        "on_unlisted_content_type": "block"
    }))
    .unwrap();
    let (buffers, result, ctx) = post(&plugin, Some("application/octet-stream"), SQLI_JSON).await;
    assert!(!buffers);
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&ctx, "waf.body_uninspected"), None);
}

#[test]
fn an_oversize_block_stays_an_admission_path_without_body_methods() {
    // `body_methods` does not govern WebSocket messages, which still apply the
    // strict size cap, so an empty list does not make it unreachable.
    waf(json!({
        "mode": "enforce",
        "body_methods": [],
        "on_body_too_large": "block"
    }))
    .unwrap();
}

#[tokio::test]
async fn grpc_json_codecs_are_scanned_and_other_grpc_types_are_unlisted() {
    let plugin = recommended("block");
    for ct in ["application/grpc+json", "application/grpc-web+json"] {
        let (_, result, ctx) = post(&plugin, Some(ct), br#"{"name":"widget"}"#).await;
        assert!(matches!(result, PluginResult::Continue), "{ct}");
        assert_eq!(meta(&ctx, "waf.body_uninspected"), None, "{ct}");

        let (_, result, ctx) = post(&plugin, Some(ct), SQLI_JSON).await;
        assert!(is_reject(&result), "{ct}");
        assert_eq!(meta(&ctx, "waf.block_reason"), Some("rule"), "{ct}");
    }
    for ct in [
        "application/grpc",
        "application/grpc+proto",
        "application/grpc-web",
        "application/grpc-web+proto",
        "application/grpc-web-text",
        "application/protobuf",
    ] {
        let (buffers, result, ctx) = post(&plugin, Some(ct), b"\0\0\0\0\x02hi").await;
        assert!(buffers, "{ct}");
        assert!(is_reject(&result), "{ct}");
        assert_eq!(
            meta(&ctx, "waf.block_reason"),
            Some("content_type"),
            "{ct:?}"
        );
    }
}

#[tokio::test]
async fn block_while_enforcing_records_nothing_before_the_body_decision() {
    // `block` in enforce mode always refuses, so the header-time observation
    // never records; the exact decision over the finalized body does.
    let plugin = recommended("block");
    let mut declared = request("POST", "/api/items", Some("application/octet-stream"));
    declared
        .headers
        .insert("content-length".into(), "15".into());
    let result = plugin.authorize(&mut declared).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&declared, "waf.body_uninspected"), None);

    let headers = declared.headers.clone();
    let result = final_body(&plugin, &mut declared, &headers, b"fifteen bytes!!").await;
    assert!(is_reject(&result));
    assert_eq!(
        meta(&declared, "waf.body_uninspected"),
        Some("content_type")
    );
}

#[test]
fn block_is_an_admission_enforcement_path_only_with_body_inspection() {
    // The built-in pack is monitor-only; `block` alone makes enforce reachable.
    assert!(waf(json!({ "mode": "enforce", "on_unlisted_content_type": "block" })).is_ok());
    // `fail_closed` cannot refuse without an enforcing body policy.
    let error =
        waf(json!({ "mode": "enforce", "on_unlisted_content_type": "fail_closed" })).unwrap_err();
    assert!(error.contains("no enabled enforcement path"), "{error}");
    // No request-body hook, no reachable path.
    let error = waf(json!({
        "mode": "enforce",
        "request_body_inspection": false,
        "on_unlisted_content_type": "block"
    }))
    .unwrap_err();
    assert!(error.contains("no enabled enforcement path"), "{error}");
}

#[test]
fn invalid_values_are_rejected() {
    let error = waf(json!({ "mode": "monitor", "on_unlisted_content_type": "deny" })).unwrap_err();
    assert!(
        error.contains("`on_unlisted_content_type` must be allow, fail_closed, or block"),
        "{error}"
    );
}

// ── Defaults ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn request_default_is_fail_closed_under_an_enforcing_body_policy() {
    let plugin = waf(json!({ "mode": "enforce", "default_rule_action": "enforce" })).unwrap();
    for content_type in [Some("application/octet-stream"), Some("text/csv"), None] {
        let (buffers, result, ctx) = post(&plugin, content_type, SQLI_JSON).await;
        assert!(buffers, "{content_type:?}");
        assert!(is_reject(&result), "{content_type:?}");
        assert_eq!(meta(&ctx, "waf.block_reason"), Some("content_type"));
        assert_eq!(
            meta(&ctx, "waf.body_uninspected_target"),
            Some("request_body")
        );
    }
    // An empty unlisted body still passes.
    let (_, result, _) = post(&plugin, Some("application/octet-stream"), b"").await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn request_default_never_blocks_a_monitor_only_deployment() {
    let plugin = waf(json!({ "mode": "monitor", "default_rule_action": "enforce" })).unwrap();
    let (buffers, result, ctx) = post(&plugin, Some("application/octet-stream"), SQLI_JSON).await;
    assert!(!buffers);
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&ctx, "waf.block_reason"), None);
}

#[tokio::test]
async fn delete_bodies_are_scanned_by_default() {
    let plugin = recommended("fail_closed");
    let mut ctx = request("DELETE", "/api/items", Some("application/json"));
    assert!(plugin.should_buffer_request_body(&ctx));
    let headers = ctx.headers.clone();
    let result = final_body(&plugin, &mut ctx, &headers, SQLI_JSON).await;
    assert!(is_reject(&result));
    assert_eq!(meta(&ctx, "waf.block_reason"), Some("rule"));

    // An explicit list still replaces the default.
    let plugin = waf(json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "body_methods": ["POST"]
    }))
    .unwrap();
    let ctx = request("DELETE", "/api/items", Some("application/json"));
    assert!(!plugin.should_buffer_request_body(&ctx));
}

// ── Responses: on_unlisted_response_content_type ───────────────────────────

/// An enforce-mode WAF whose only response-body rule is `response_action`.
/// An enforcing query rule keeps `mode: enforce` admissible either way.
fn response_waf(response_action: &str, on_unlisted: Option<&str>) -> Waf {
    let mut config = json!({
        "mode": "enforce",
        "include_default_rules": false,
        "response_inspection": true,
        "response_body_inspection": true,
        "custom_rules": [
            {
                "id": "LEAK", "category": "custom", "target": "response_body",
                "match_kind": "contains", "pattern": "leak-marker",
                "action": response_action
            },
            {
                "id": "QUERY", "category": "custom", "target": "query_values",
                "match_kind": "contains", "pattern": "query-marker",
                "action": "enforce"
            }
        ]
    });
    if let Some(value) = on_unlisted {
        config["on_unlisted_response_content_type"] = json!(value);
    }
    waf(config).unwrap()
}

async fn respond(
    plugin: &Waf,
    content_type: Option<&str>,
    body: &[u8],
) -> (bool, PluginResult, RequestContext) {
    let mut ctx = request("GET", "/api/items", None);
    let mut headers = HashMap::new();
    if let Some(content_type) = content_type {
        headers.insert("content-type".to_string(), content_type.to_string());
    }
    let buffers =
        plugin.should_buffer_response_body_for_content_type(&ctx, content_type, 200, &headers);
    let result = plugin
        .finalize_client_visible_response_body(&mut ctx, 200, &headers, body)
        .await;
    (buffers, result, ctx)
}

#[tokio::test]
async fn response_allow_streams_and_records_unlisted_bodies() {
    let plugin = response_waf("enforce", Some("allow"));
    let (buffers, result, ctx) =
        respond(&plugin, Some("application/octet-stream"), b"leak-marker").await;
    assert!(!buffers, "allow keeps the streaming path");
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&ctx, "waf.body_uninspected"), Some("content_type"));
    assert_eq!(
        meta(&ctx, "waf.body_uninspected_target"),
        Some("response_body")
    );
    assert_eq!(meta(&ctx, "waf.block_reason"), None);
}

#[tokio::test]
async fn response_default_is_fail_closed_under_an_enforcing_rule() {
    let plugin = response_waf("enforce", None);
    let (buffers, result, ctx) = respond(
        &plugin,
        Some("application/octet-stream"),
        b"<?php echo 1; ?>",
    )
    .await;
    assert!(buffers);
    assert!(is_reject(&result));
    assert_eq!(meta(&ctx, "waf.block_reason"), Some("content_type"));
    // The refusing disposition is part of the pre-content-type capability, so
    // gateway-header provenance is retained for the rejection.
    let ctx = request("GET", "/api/items", None);
    assert!(plugin.may_enforce_response_body_policy(&ctx));
}

#[tokio::test]
async fn response_fail_closed_refuses_unlisted_bodies_under_an_enforcing_rule() {
    let plugin = response_waf("enforce", Some("fail_closed"));
    for content_type in [Some("application/octet-stream"), Some("image/png"), None] {
        let (buffers, result, ctx) = respond(&plugin, content_type, b"anything").await;
        assert!(
            buffers,
            "{content_type:?} must be buffered so the bytes decide"
        );
        assert!(is_reject(&result), "{content_type:?}");
        assert_eq!(meta(&ctx, "waf.block_reason"), Some("content_type"));
        assert_eq!(meta(&ctx, "waf.action"), Some("blocked"));
        assert_eq!(
            meta(&ctx, "waf.body_uninspected_target"),
            Some("response_body")
        );
    }

    // Empty bodies pass, listed types are scanned rather than refused, and
    // event streams are never buffered.
    let (_, result, ctx) = respond(&plugin, Some("application/octet-stream"), b"").await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&ctx, "waf.body_uninspected"), None);
    let (_, result, ctx) = respond(&plugin, Some("application/json"), br#"{"ok":1}"#).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&ctx, "waf.body_uninspected"), None);
    let (_, result, ctx) = respond(&plugin, Some("text/plain"), b"leak-marker").await;
    assert!(is_reject(&result));
    assert_eq!(meta(&ctx, "waf.block_reason"), Some("rule"));
    let (buffers, _, _) = respond(&plugin, Some("text/event-stream"), b"data: x\n\n").await;
    assert!(!buffers);
}

#[tokio::test]
async fn response_fail_closed_needs_an_enforcing_response_rule_but_block_does_not() {
    let fail_closed = response_waf("monitor", Some("fail_closed"));
    let (buffers, result, ctx) =
        respond(&fail_closed, Some("application/octet-stream"), b"anything").await;
    assert!(!buffers);
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&ctx, "waf.block_reason"), None);

    let ctx = request("GET", "/api/items", None);
    assert!(!fail_closed.may_enforce_response_body_policy(&ctx));

    let block = response_waf("monitor", Some("block"));
    assert!(
        block.may_enforce_response_body_policy(&ctx),
        "a refusing unlisted disposition must be reported as a capability"
    );
    let (buffers, result, ctx) =
        respond(&block, Some("application/octet-stream"), b"anything").await;
    assert!(buffers);
    assert!(is_reject(&result));
    assert_eq!(meta(&ctx, "waf.block_reason"), Some("content_type"));
}

#[tokio::test]
async fn response_policy_does_not_govern_exempt_or_bodiless_responses() {
    let plugin = waf(json!({
        "mode": "enforce",
        "include_default_rules": false,
        "response_inspection": true,
        "response_body_inspection": true,
        "on_unlisted_response_content_type": "block",
        "global_exemptions": { "paths": ["/downloads/*"] },
        "custom_rules": [{
            "id": "LEAK", "category": "custom", "target": "response_body",
            "match_kind": "contains", "pattern": "leak-marker", "action": "enforce"
        }]
    }))
    .unwrap();
    let headers = HashMap::from([(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    )]);

    let mut exempt = request("GET", "/downloads/file.bin", None);
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &exempt,
        Some("application/octet-stream"),
        200,
        &headers
    ));
    let result = plugin
        .finalize_client_visible_response_body(&mut exempt, 200, &headers, b"bytes")
        .await;
    assert!(matches!(result, PluginResult::Continue));

    let head = request("HEAD", "/api/items", None);
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &head,
        Some("application/octet-stream"),
        200,
        &headers
    ));
    let no_content = request("GET", "/api/items", None);
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &no_content,
        Some("application/octet-stream"),
        204,
        &headers
    ));
}

#[test]
fn invalid_response_values_are_rejected() {
    let error = waf(json!({
        "mode": "monitor",
        "on_unlisted_response_content_type": "deny"
    }))
    .unwrap_err();
    assert!(
        error.contains("`on_unlisted_response_content_type` must be allow, fail_closed, or block"),
        "{error}"
    );
}

// ── Zero-contribution scoring does not make a body policy enforcing ────────

#[tokio::test]
async fn a_zero_score_monitor_body_rule_does_not_make_unlisted_bodies_refusable() {
    let plugin = waf(json!({
        "mode": "enforce",
        "include_default_rules": false,
        "response_inspection": true,
        "response_body_inspection": true,
        "scoring": { "enabled": true, "block_threshold": 5 },
        "custom_rules": [
            {
                "id": "QUERY", "category": "custom", "target": "query_values",
                "match_kind": "contains", "pattern": "query-marker", "action": "enforce"
            },
            {
                "id": "BODY-ZERO", "category": "custom", "target": "body_text",
                "match_kind": "contains", "pattern": "noted", "action": "monitor", "score": 0
            },
            {
                "id": "RESP-ZERO", "category": "custom", "target": "response_body",
                "match_kind": "contains", "pattern": "noted", "action": "monitor", "score": 0
            }
        ]
    }))
    .unwrap();

    let (buffers, result, ctx) = post(&plugin, Some("application/octet-stream"), b"x").await;
    assert!(!buffers);
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&ctx, "waf.block_reason"), None);

    let (buffers, result, ctx) = respond(&plugin, Some("application/octet-stream"), b"x").await;
    assert!(!buffers);
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&ctx, "waf.block_reason"), None);
}

#[tokio::test]
async fn a_scoring_body_rule_with_a_positive_score_still_makes_them_refusable() {
    let plugin = waf(json!({
        "mode": "enforce",
        "include_default_rules": false,
        "scoring": { "enabled": true, "block_threshold": 5 },
        "custom_rules": [{
            "id": "BODY-SCORED", "category": "custom", "target": "body_text",
            "match_kind": "contains", "pattern": "noted", "action": "monitor", "score": 5
        }]
    }))
    .unwrap();
    let (buffers, result, ctx) = post(&plugin, Some("application/octet-stream"), b"x").await;
    assert!(buffers);
    assert!(is_reject(&result));
    assert_eq!(meta(&ctx, "waf.block_reason"), Some("content_type"));
}

// ── header_present secrets stay out of diagnostics ─────────────────────────

#[test]
fn header_present_names_are_redacted_from_diagnostics() {
    let plugin = waf(json!({
        "mode": "monitor",
        "global_exemptions": {
            "header_present": {
                "X-Waf-Bypass": "trusted-hop-shared-secret",
                "x-scanner": "another-shared-secret-value"
            }
        }
    }))
    .unwrap();
    let mut names = plugin.request_headers_to_redact().to_vec();
    names.sort();
    assert_eq!(
        names,
        vec!["x-scanner".to_string(), "x-waf-bypass".to_string()]
    );

    let plain = waf(json!({ "mode": "monitor" })).unwrap();
    assert!(plain.request_headers_to_redact().is_empty());
}

/// On responses `inspect_binary_body` brings every type, multipart included,
/// into the scan scope, so such a body is scanned by the rules rather than
/// being unlisted: a hit still blocks for the rule.
#[tokio::test]
async fn binary_response_inspection_scans_multipart_instead_of_refusing_it() {
    let plugin = waf(json!({
        "mode": "enforce",
        "include_default_rules": false,
        "response_inspection": true,
        "response_body_inspection": true,
        "inspect_binary_body": true,
        "on_unlisted_response_content_type": "block",
        "custom_rules": [{
            "id": "LEAK", "category": "custom", "target": "response_body",
            "match_kind": "contains", "pattern": "leak-marker", "action": "enforce"
        }]
    }))
    .unwrap();
    let multipart = Some("multipart/mixed; boundary=b");
    let (buffers, result, ctx) = respond(&plugin, multipart, b"--b\r\nclean\r\n--b--").await;
    assert!(buffers);
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&ctx, "waf.body_uninspected"), None);
    let (_, result, ctx) = respond(&plugin, multipart, b"--b\r\nleak-marker\r\n--b--").await;
    assert!(is_reject(&result));
    assert_eq!(meta(&ctx, "waf.block_reason"), Some("rule"));
}
