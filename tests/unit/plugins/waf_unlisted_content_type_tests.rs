//! `on_unlisted_content_type`: request bodies the WAF will not inspect because
//! their `Content-Type` falls outside `body_content_types` /
//! `inspect_multipart` / `inspect_binary_body`.
//!
//! The declared media type is attacker-controlled and many backends parse the
//! body without consulting it, so relabelling a JSON injection payload as
//! `application/octet-stream` (or dropping the header) used to skip every body
//! rule. `allow` keeps that behavior; `fail_closed` refuses a non-empty
//! unlisted body when an enforcing request-body policy applies; `block` refuses
//! every non-empty unlisted body while globally enforcing.

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
async fn default_allow_leaves_unlisted_bodies_uninspected() {
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
