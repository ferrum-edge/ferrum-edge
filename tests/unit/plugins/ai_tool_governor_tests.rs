//! Tests for the ai_tool_governor plugin.

use ferrum_edge::{
    _test_support::clone_log_metadata,
    config::{BackendAllowIps, BackendEgressPolicy},
    plugins::{
        Plugin, PluginFailurePolicy, PluginHttpClient, PluginResult, RequestContext,
        ResponseStreamAction, ResponseStreamInspector, ai_tool_governor::AiToolGovernor,
        available_plugins, correlation_id::CorrelationId, create_plugin_with_http_client,
        create_response_stream_inspector, plugin_failure_policy, priority, validate_plugin_config,
    },
    proxy::deferred_log::BodyOutcome,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

fn make(config: Value) -> AiToolGovernor {
    AiToolGovernor::new(&config, PluginHttpClient::default()).expect("valid config")
}

fn try_make(config: Value) -> Result<AiToolGovernor, String> {
    AiToolGovernor::new(&config, PluginHttpClient::default())
}

fn json_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers
}

/// A request context shaped like the JSON POSTs this plugin governs.
fn json_post_ctx() -> RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx
}

/// A buffered OpenAI chat-completion response carrying a single tool call.
/// `arguments` is the JSON-encoded arguments *string*, as OpenAI emits.
fn response_with_tool_call(name: &str, arguments: &str) -> Vec<u8> {
    json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": Value::Null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": { "name": name, "arguments": arguments }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": { "prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2 }
    })
    .to_string()
    .into_bytes()
}

/// Assert that no metadata value contains `needle` (raw-secret leak guard).
fn assert_no_metadata_contains(ctx: &RequestContext, needle: &str) {
    for (key, value) in &ctx.metadata {
        assert!(
            !value.contains(needle),
            "metadata key {key:?} leaked {needle:?}: {value:?}"
        );
    }
}

/// Assert that metadata owned by this plugin contains no raw governed value.
///
/// Request tests deliberately retain the proxy's `request_body` buffer in
/// context metadata; that transport-owned copy is not emitted by the governor
/// and must not make a governor-metadata leak assertion fail vacuously.
fn assert_no_governor_metadata_contains(ctx: &RequestContext, needle: &str) {
    for (key, value) in &ctx.metadata {
        if !key.starts_with("ai_tool_governor.") {
            continue;
        }
        assert!(
            !value.contains(needle),
            "governor metadata key {key:?} leaked {needle:?}: {value:?}"
        );
    }
}

/// Drive a full SSE body through an inspector, returning all forwarded bytes and
/// whether the stream was terminated.
async fn drive_stream(
    inspector: &mut Box<dyn ResponseStreamInspector>,
    chunks: &[&[u8]],
) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut terminated = false;
    for chunk in chunks {
        match inspector.on_chunk(chunk).await {
            ResponseStreamAction::Forward(bytes) => out.extend_from_slice(&bytes),
            ResponseStreamAction::Terminate(bytes) => {
                if let Some(bytes) = bytes {
                    out.extend_from_slice(&bytes);
                }
                terminated = true;
                break;
            }
        }
    }
    if !terminated {
        match inspector.on_end().await {
            ResponseStreamAction::Forward(bytes) => out.extend_from_slice(&bytes),
            ResponseStreamAction::Terminate(bytes) => {
                if let Some(bytes) = bytes {
                    out.extend_from_slice(&bytes);
                }
                terminated = true;
            }
        }
    }
    (out, terminated)
}

// ---------------------------------------------------------------------------
// Registration / metadata
// ---------------------------------------------------------------------------

#[test]
fn plugin_is_registered_and_priority_is_correct() {
    assert!(available_plugins().contains(&"ai_tool_governor"));
    assert_eq!(priority::AI_TOOL_GOVERNOR, 2978);

    let config = json!({ "tools": { "x": { "action": "allow" } } });
    let plugin =
        create_plugin_with_http_client("ai_tool_governor", &config, PluginHttpClient::default())
            .expect("construction succeeds")
            .expect("plugin exists");
    assert_eq!(plugin.name(), "ai_tool_governor");
    assert_eq!(plugin.priority(), 2978);
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

#[test]
fn rejects_non_object_config() {
    assert!(try_make(json!("nope")).is_err());
}

#[test]
fn rejects_invalid_mode() {
    let err = try_make(json!({ "mode": "audit", "tools": { "x": { "action": "allow" } } }))
        .err()
        .unwrap();
    assert!(err.contains("mode"), "{err}");
}

#[test]
fn rejects_invalid_default_action() {
    let err =
        try_make(json!({ "default_action": "maybe", "tools": { "x": { "action": "allow" } } }))
            .err()
            .unwrap();
    assert!(err.contains("default_action"), "{err}");
}

#[test]
fn rejects_invalid_tool_action() {
    let err = try_make(json!({ "tools": { "x": { "action": "explode" } } }))
        .err()
        .unwrap();
    assert!(err.contains("invalid action"), "{err}");
}

#[test]
fn rejects_bad_regex() {
    let err = try_make(json!({
        "tools": { "x": { "action": "deny", "blocked_arg_patterns": [{ "name": "n", "regex": "(" }] } }
    }))
    .err().unwrap();
    assert!(err.contains("invalid regex"), "{err}");
}

#[test]
fn rejects_non_object_json_schema() {
    let err = try_make(json!({
        "tools": { "x": { "action": "allow", "json_schema": "not-a-schema" } }
    }))
    .err()
    .unwrap();
    assert!(err.contains("json_schema"), "{err}");
}

#[test]
fn rejects_require_approval_without_endpoint() {
    let err = try_make(json!({ "tools": { "x": { "action": "require_approval" } } }))
        .err()
        .unwrap();
    assert!(err.contains("approval.endpoint_url"), "{err}");
}

#[test]
fn rejects_non_http_approval_endpoint() {
    let err = try_make(json!({
        "tools": { "x": { "action": "require_approval" } },
        "approval": { "endpoint_url": "ftp://approve.example.com/x" }
    }))
    .err()
    .unwrap();
    assert!(err.contains("http/https"), "{err}");
}

#[test]
fn rejects_excessive_approval_cache_ttl() {
    let err = try_make(json!({
        "tools": { "x": { "action": "require_approval" } },
        "approval": {
            "endpoint_url": "https://approve.example.com/x",
            "cache_ttl_seconds": u64::MAX
        }
    }))
    .err()
    .unwrap();
    assert!(err.contains("approval.cache_ttl_seconds"), "{err}");
}

#[test]
fn rejects_non_error_deny_status_codes() {
    for status in [100, 200, 302, 399, 600] {
        let err = try_make(json!({
            "tools": { "x": { "action": "deny" } },
            "response": { "deny_status_code": status }
        }))
        .err()
        .unwrap();
        assert!(err.contains("error status"), "status {status}: {err}");
    }

    for status in [400, 599] {
        assert!(
            try_make(json!({
                "tools": { "x": { "action": "deny" } },
                "response": { "deny_status_code": status }
            }))
            .is_ok(),
            "HTTP error status {status} should be accepted"
        );
    }
}

#[test]
fn rejects_no_inspection_surface() {
    let err = try_make(json!({
        "tools": { "x": { "action": "deny" } },
        "inspect": {
            "request_tool_definitions": false,
            "response_tool_calls": false,
            "streaming_response_tool_calls": false,
            "mcp_tool_calls": false,
            "a2a_methods": false
        }
    }))
    .err()
    .unwrap();
    assert!(err.contains("inspect"), "{err}");
}

#[test]
fn rejects_noop_empty_tools_with_default_allow() {
    let err = try_make(json!({ "default_action": "allow", "tools": {} }))
        .err()
        .unwrap();
    assert!(err.contains("no effect"), "{err}");
}

#[test]
fn accepts_empty_tools_when_default_action_denies() {
    // default_action=deny governs everything, so no explicit tool policies is fine.
    assert!(try_make(json!({ "default_action": "deny", "tools": {} })).is_ok());
}

#[test]
fn disabled_config_skips_policy_validation() {
    // Known keys with invalid *values* remain ignored when disabled. Unknown
    // key names are still rejected (see unknown-key tests below).
    assert!(
        try_make(json!({
            "enabled": false,
            "mode": "invalid",
            "tools": { "": { "action": "invalid" } },
            "inspect": {
                "request_tool_definitions": false,
                "response_tool_calls": false,
                "streaming_response_tool_calls": false,
                "mcp_tool_calls": false,
                "a2a_methods": false
            }
        }))
        .is_ok()
    );
}

// ---------------------------------------------------------------------------
// Unknown-key admission (GHSA-hf5h-425j-58v5)
// ---------------------------------------------------------------------------

fn baseline_allow_policy() -> Value {
    json!({
        "default_action": "deny",
        "tools": {
            "github.create_pr": {
                "action": "allow",
                "required_args": ["ticket_id"],
                "max_arg_bytes": 1024,
                "blocked_arg_patterns": [{ "name": "secret", "regex": "(?i)token" }],
                "json_schema": {
                    "type": "object",
                    "required": ["ticket_id"],
                    "properties": {
                        "ticket_id": { "type": "string" },
                        "x-custom-keyword": { "type": "string" }
                    },
                    "additionalProperties": false
                }
            }
        },
        "inspect": {
            "response_tool_calls": true,
            "request_tool_definitions": true
        },
        "approval": {
            "endpoint_url": "https://approval.example/decide",
            "timeout_ms": 1500
        },
        "response": { "deny_status_code": 403 },
        "observability": { "emit_metadata": true, "hash_arguments": true }
    })
}

fn assert_unknown_key_error(err: &str, path_fragment: &str, typo: &str) {
    assert!(
        err.contains("unknown configuration key"),
        "missing unknown-key wording: {err}"
    );
    assert!(
        err.contains(typo),
        "error must name the typo {typo:?}: {err}"
    );
    assert!(
        err.contains(path_fragment),
        "error must be path-qualified with {path_fragment:?}: {err}"
    );
}

type UnknownKeyCase = (
    &'static str,
    fn() -> Value,
    &'static str,
    Option<&'static str>,
);

#[test]
fn rejects_enforcement_relevant_unknown_keys_with_path_and_suggestion() {
    let cases: &[UnknownKeyCase] = &[
        (
            "modde",
            || {
                let mut cfg = baseline_allow_policy();
                cfg.as_object_mut()
                    .unwrap()
                    .insert("modde".into(), json!("enforce"));
                cfg
            },
            "config.modde",
            Some("mode"),
        ),
        (
            "default_acton",
            || {
                let mut cfg = baseline_allow_policy();
                cfg.as_object_mut()
                    .unwrap()
                    .insert("default_acton".into(), json!("deny"));
                cfg
            },
            "config.default_acton",
            Some("default_action"),
        ),
        (
            "inspect.response_tool_call",
            || {
                let mut cfg = baseline_allow_policy();
                cfg["inspect"]
                    .as_object_mut()
                    .unwrap()
                    .insert("response_tool_call".into(), json!(true));
                cfg
            },
            "config.inspect.response_tool_call",
            Some("response_tool_calls"),
        ),
        (
            "tools.required_arg",
            || {
                let mut cfg = baseline_allow_policy();
                cfg["tools"]["github.create_pr"]
                    .as_object_mut()
                    .unwrap()
                    .insert("required_arg".into(), json!(["ticket_id"]));
                cfg
            },
            "config.tools.github.create_pr.required_arg",
            Some("required_args"),
        ),
        (
            "tools.max_arg_byte",
            || {
                let mut cfg = baseline_allow_policy();
                cfg["tools"]["github.create_pr"]
                    .as_object_mut()
                    .unwrap()
                    .insert("max_arg_byte".into(), json!(1024));
                cfg
            },
            "config.tools.github.create_pr.max_arg_byte",
            Some("max_arg_bytes"),
        ),
        (
            "tools.blocked_arg_pattern",
            || {
                let mut cfg = baseline_allow_policy();
                cfg["tools"]["github.create_pr"]
                    .as_object_mut()
                    .unwrap()
                    .insert(
                        "blocked_arg_pattern".into(),
                        json!([{ "name": "secret", "regex": "x" }]),
                    );
                cfg
            },
            "config.tools.github.create_pr.blocked_arg_pattern",
            Some("blocked_arg_patterns"),
        ),
        (
            "tools.json_shema",
            || {
                let mut cfg = baseline_allow_policy();
                cfg["tools"]["github.create_pr"]
                    .as_object_mut()
                    .unwrap()
                    .insert("json_shema".into(), json!({"type": "object"}));
                cfg
            },
            "config.tools.github.create_pr.json_shema",
            Some("json_schema"),
        ),
        (
            "blocked_arg_patterns[0].regexx",
            || {
                let mut cfg = baseline_allow_policy();
                cfg["tools"]["github.create_pr"]["blocked_arg_patterns"][0]
                    .as_object_mut()
                    .unwrap()
                    .insert("regexx".into(), json!("token"));
                cfg
            },
            "config.tools.github.create_pr.blocked_arg_patterns[0].regexx",
            Some("regex"),
        ),
        (
            "approval.endpoint_urll",
            || {
                let mut cfg = baseline_allow_policy();
                cfg["approval"]
                    .as_object_mut()
                    .unwrap()
                    .insert("endpoint_urll".into(), json!("https://x.example/y"));
                cfg
            },
            "config.approval.endpoint_urll",
            Some("endpoint_url"),
        ),
        (
            "response.deny_status_cod",
            || {
                let mut cfg = baseline_allow_policy();
                cfg["response"]
                    .as_object_mut()
                    .unwrap()
                    .insert("deny_status_cod".into(), json!(403));
                cfg
            },
            "config.response.deny_status_cod",
            Some("deny_status_code"),
        ),
        (
            "observability.emit_metdata",
            || {
                let mut cfg = baseline_allow_policy();
                cfg["observability"]
                    .as_object_mut()
                    .unwrap()
                    .insert("emit_metdata".into(), json!(true));
                cfg
            },
            "config.observability.emit_metdata",
            Some("emit_metadata"),
        ),
    ];

    for (label, build, path_fragment, suggestion) in cases {
        let config = build();
        let err = try_make(config.clone())
            .err()
            .unwrap_or_else(|| panic!("expected unknown-key rejection for {label}"));
        assert_unknown_key_error(
            &err,
            path_fragment,
            path_fragment.rsplit('.').next().unwrap(),
        );
        if let Some(expected) = suggestion {
            assert!(
                err.contains(&format!("did you mean '{expected}'")),
                "{label}: missing suggestion for {expected}: {err}"
            );
        }

        let shared = validate_plugin_config("ai_tool_governor", &config)
            .expect_err("shared admission must reject the same typo");
        assert!(
            shared.contains("unknown configuration key"),
            "{label}: shared admission wording: {shared}"
        );
        assert!(
            shared.contains(path_fragment),
            "{label}: shared admission path: {shared}"
        );
    }
}

#[test]
fn disabled_config_still_rejects_unknown_keys() {
    let err = try_make(json!({
        "enabled": false,
        "required_arg": ["ticket_id"],
        "modde": "enforce"
    }))
    .err()
    .expect("unknown keys must fail even when disabled");
    assert!(err.contains("unknown configuration key"), "{err}");
    assert!(
        err.contains("config.modde") || err.contains("config.required_arg"),
        "{err}"
    );
}

#[test]
fn accepts_free_form_tool_names_and_open_json_schema_keywords() {
    assert!(
        try_make(baseline_allow_policy()).is_ok(),
        "arbitrary tool names and JSON Schema keywords must remain accepted"
    );
    assert!(
        try_make(json!({
            "default_action": "deny",
            "tools": {
                "org.custom/tool-name.v2": {
                    "action": "allow",
                    "json_schema": {
                        "type": "object",
                        "$comment": "operator note",
                        "unevaluatedProperties": false,
                        "properties": { "q": { "type": "string" } }
                    }
                }
            }
        }))
        .is_ok()
    );
}

#[test]
fn null_optional_fields_keep_existing_type_errors() {
    // Present-but-null is not treated as absent for typed optional fields.
    let err = try_make(json!({
        "default_action": "deny",
        "tools": { "x": { "action": "allow" } },
        "mode": null
    }))
    .err()
    .expect("null mode must type-error");
    assert!(err.contains("mode"), "{err}");
    assert!(!err.contains("unknown configuration key"), "{err}");
}

#[test]
fn shared_admission_and_failure_policy_for_unknown_keys() {
    let config = json!({
        "default_action": "deny",
        "tools": {
            "search": {
                "action": "allow",
                "required_arg": ["q"]
            }
        }
    });
    let err = validate_plugin_config("ai_tool_governor", &config)
        .expect_err("shared admission must use the strict constructor");
    assert!(err.contains("config.tools.search.required_arg"), "{err}");
    assert!(err.contains("did you mean 'required_args'"), "{err}");
    assert_eq!(
        plugin_failure_policy("ai_tool_governor"),
        Some(PluginFailurePolicy::FailClosed)
    );
}

#[tokio::test]
async fn multiple_instances_admit_independently_for_unknown_keys() {
    let good = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let bad = try_make(json!({
        "default_action": "deny",
        "tools": {
            "report.read": {
                "action": "allow",
                "required_arg": ["id"]
            }
        }
    }));
    assert!(
        bad.err()
            .map(|e| e.contains("config.tools.report.read.required_arg"))
            .unwrap_or(false),
        "second instance typo must fail on its own config"
    );
    // The good instance remains usable after a sibling config fails admission.
    let mut ctx = create_test_context();
    assert_continue(
        good.on_response_body(
            &mut ctx,
            200,
            &mut json_headers(),
            &response_with_tool_call("report.read", "{}"),
        )
        .await,
    );
}

#[test]
fn dry_run_require_approval_does_not_require_endpoint() {
    assert!(
        try_make(json!({
            "mode": "dry_run",
            "tools": { "deploy": { "action": "require_approval" } }
        }))
        .is_ok()
    );
}

#[test]
fn approval_endpoint_literal_ip_is_screened_by_egress_policy() {
    let client = PluginHttpClient::default_with_backend_allow_ips(
        BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
    );
    let err = AiToolGovernor::new(
        &json!({
            "tools": { "deploy": { "action": "require_approval" } },
            "approval": { "endpoint_url": "http://10.0.0.5/approve" }
        }),
        client,
    )
    .err()
    .unwrap();
    assert!(err.contains("backend egress policy"), "{err}");
}

// ---------------------------------------------------------------------------
// Buffered response tool-call inspection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn allows_tool_in_allowlist() {
    let plugin = make(json!({ "tools": { "github.create_pr": { "action": "allow" } } }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("github.create_pr", "{\"repo\":\"acme/app\"}");
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
        .await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("allow")
    );
}

#[tokio::test]
async fn denies_unknown_tool_via_default_deny() {
    let plugin =
        make(json!({ "default_action": "deny", "tools": { "safe": { "action": "allow" } } }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("kubectl.apply", "{}");
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
        .await;
    assert_reject(result, Some(403));
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("deny")
    );
}

#[tokio::test]
async fn denies_explicit_deny_tool() {
    let plugin = make(json!({ "tools": { "kubectl.apply": { "action": "deny" } } }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("kubectl.apply", "{}");
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(403),
    );
}

#[tokio::test]
async fn denies_on_max_arg_bytes() {
    let plugin = make(json!({
        "tools": { "github.create_pr": { "action": "allow", "max_arg_bytes": 8 } }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call(
        "github.create_pr",
        "{\"repo\":\"acme/app\",\"title\":\"big\"}",
    );
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(403),
    );
}

#[tokio::test]
async fn denies_on_missing_required_args() {
    let plugin = make(json!({
        "tools": { "github.create_pr": { "action": "allow", "required_args": ["repo", "title", "body"] } }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("github.create_pr", "{\"repo\":\"acme/app\"}");
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(403),
    );
}

#[tokio::test]
async fn json_schema_allows_and_denies() {
    let schema = json!({
        "type": "object",
        "required": ["path", "content"],
        "properties": {
            "path": { "type": "string", "pattern": "^/workspace/" },
            "content": { "type": "string" }
        }
    });
    let plugin = make(json!({
        "tools": { "filesystem.write": { "action": "allow", "json_schema": schema } }
    }));

    // Conforming arguments pass.
    let mut ctx = create_test_context();
    let ok = response_with_tool_call(
        "filesystem.write",
        "{\"path\":\"/workspace/a\",\"content\":\"x\"}",
    );
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &ok)
            .await,
    );

    // A path outside /workspace/ violates the pattern → deny.
    let mut ctx = create_test_context();
    let bad = response_with_tool_call(
        "filesystem.write",
        "{\"path\":\"/etc/passwd\",\"content\":\"x\"}",
    );
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &bad)
            .await,
        Some(403),
    );
}

#[tokio::test]
async fn regex_blocked_arg_denies() {
    let plugin = make(json!({
        "tools": {
            "github.create_pr": {
                "action": "allow",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "(?i)(api[_-]?key|password|token)" }]
            }
        }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call(
        "github.create_pr",
        "{\"repo\":\"acme/app\",\"body\":\"my api_key is x\"}",
    );
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(403),
    );
}

#[tokio::test]
async fn dry_run_emits_metadata_but_does_not_reject() {
    let plugin = make(json!({
        "mode": "dry_run",
        "tools": { "kubectl.apply": { "action": "deny" } }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("kubectl.apply", "{}");
    // Dry-run never rejects...
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    // ...but records what would have happened.
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.mode")
            .map(String::as_str),
        Some("dry_run")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("deny")
    );
}

#[tokio::test]
async fn non_json_and_non_2xx_are_ignored() {
    let plugin = make(json!({ "tools": { "kubectl.apply": { "action": "deny" } } }));
    let body = response_with_tool_call("kubectl.apply", "{}");

    // Non-2xx status: not inspected.
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 500, &mut json_headers(), &body)
            .await,
    );

    // Non-JSON content-type with a genuinely non-JSON body: not inspected.
    let mut html = HashMap::new();
    html.insert("content-type".to_string(), "text/html".to_string());
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut html, b"<html>hi</html>")
            .await,
    );

    // A non-JSON content-type does NOT skip a JSON-shaped body: a header rule
    // that strips/relabels `Content-Type` must not disable governance of the
    // intact Chat Completions JSON underneath.
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut html, &body)
            .await,
        Some(403),
    );
}

// ---------------------------------------------------------------------------
// Redaction + hashing (no raw-secret leaks)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redacts_matched_args_and_never_leaks_secret_in_metadata() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "sk-[A-Za-z0-9]+" }]
            }
        }
    }));

    let body = response_with_tool_call(
        "filesystem.write",
        "{\"path\":\"/workspace/a\",\"token\":\"sk-SUPERSECRET123\"}",
    );
    let mut ctx = create_test_context();

    // redact_args forwards (does not block)...
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    // ...records the redaction...
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.redacted_tools")
            .map(String::as_str),
        Some("filesystem.write")
    );
    // ...and never puts the raw secret in metadata (only hashes).
    assert_no_metadata_contains(&ctx, "SUPERSECRET");
    assert!(
        ctx.metadata
            .contains_key("ai_tool_governor.arguments_hashes")
    );

    // The transform rewrites the secret out of the delivered body. Preflight
    // already computed the rewrite once; the transform must reuse that result
    // (or an equivalent fresh compute on memo miss) without changing output.
    let transformed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await.replaced_bytes()
        .expect("body is rewritten");
    let text = String::from_utf8(transformed).unwrap();
    assert!(!text.contains("SUPERSECRET"), "secret leaked: {text}");
    assert!(
        text.contains("[REDACTED_TOOL_ARG:secret]"),
        "placeholder missing: {text}"
    );
}

/// Tool names and raw argument strings are arbitrary JSON strings, so the
/// request-scoped redaction memo key must not rely on a delimiter that either
/// input can contain. These two distinct pairs collided under `name + NUL +
/// args`; each call must receive only its own preflighted rewrite.
#[tokio::test]
async fn redaction_memos_distinguish_embedded_nul_boundaries() {
    let plugin = make(json!({
        "tools": {
            "a": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "first", "regex": "b" }]
            },
            "a\u{0}": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "second", "regex": "b" }]
            }
        }
    }));
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "tool_calls": [
                    {
                        "id": "call_first",
                        "type": "function",
                        "function": { "name": "a", "arguments": "\u{0}b" }
                    },
                    {
                        "id": "call_second",
                        "type": "function",
                        "function": { "name": "a\u{0}", "arguments": "b" }
                    }
                ]
            }
        }]
    }))
    .expect("serialize NUL-boundary redaction response");
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    let transformed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await.replaced_bytes()
        .expect("both tool calls require redaction");
    let json: Value = serde_json::from_slice(&transformed).expect("transformed response JSON");
    let calls = json["choices"][0]["message"]["tool_calls"]
        .as_array()
        .expect("tool call array");
    assert_eq!(
        calls[0]["function"]["arguments"],
        json!("\u{0}[REDACTED_TOOL_ARG:first]")
    );
    assert_eq!(
        calls[1]["function"]["arguments"],
        json!("[REDACTED_TOOL_ARG:second]")
    );
}

#[tokio::test]
async fn redacts_non_string_response_arguments_before_forwarding() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "sk-[A-Za-z0-9]+" }]
            }
        }
    }));

    let body = json!({
        "choices": [{
            "message": {
                "tool_calls": [{
                    "function": {
                        "name": "filesystem.write",
                        "arguments": { "path": "/tmp/a", "token": "sk-STRUCTUREDSECRET123" }
                    }
                }]
            }
        }]
    })
    .to_string()
    .into_bytes();
    let mut ctx = create_test_context();

    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    let transformed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await.replaced_bytes()
        .expect("structured arguments are redacted");
    let text = String::from_utf8(transformed).unwrap();
    assert!(!text.contains("STRUCTUREDSECRET"), "secret leaked: {text}");
    assert!(text.contains("[REDACTED_TOOL_ARG:secret]"), "{text}");
}

/// A header transform that strips/relabels `Content-Type` away from JSON must
/// not skip the redaction transform for a body this plugin already governed as
/// JSON-shaped — otherwise the matched argument is forwarded unredacted while
/// the final re-check skips the unchanged governed hash.
#[tokio::test]
async fn relabeled_json_shaped_response_is_still_redacted_by_transform() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "sk-[A-Za-z0-9]+" }]
            }
        }
    }));

    let body = response_with_tool_call(
        "filesystem.write",
        "{\"path\":\"/workspace/a\",\"token\":\"sk-RELABELEDSECRET123\"}",
    );
    let mut html = HashMap::new();
    html.insert("content-type".to_string(), "text/html".to_string());
    let mut ctx = create_test_context();

    // The relabeled body is still governed via the JSON-shaped fallback and
    // records the redact decision.
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut html, &body)
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.redacted_tools")
            .map(String::as_str),
        Some("filesystem.write")
    );

    // The redaction transform must also apply despite the non-JSON label.
    let transformed = plugin
        .transform_response_body_with_context(&mut ctx, &body, Some("text/html"), &html)
        .await.replaced_bytes()
        .expect("relabeled governed body is rewritten");
    let text = String::from_utf8(transformed.clone()).unwrap();
    assert!(!text.contains("RELABELEDSECRET"), "secret leaked: {text}");
    assert!(text.contains("[REDACTED_TOOL_ARG:secret]"), "{text}");

    // The governed hash (recorded off `ctx.metadata`, on a non-serialized
    // request field so an arg-derived hash cannot leak to logs) now tracks the
    // redacted body, so the final re-check treats the plugin's own redaction as
    // already governed and forwards it untouched — observed here as a `Continue`
    // that does NOT re-run redaction/approval. The internal marker is no longer
    // observable from an external test, so this asserts the behavior it drives.
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &html, &transformed)
            .await,
    );
    // Defense in depth: the raw secret must never appear in transaction
    // metadata (the governed-hash / call-identity markers moved off metadata).
    assert_no_metadata_contains(&ctx, "RELABELEDSECRET");

    // A non-JSON body that was never governed as JSON-shaped stays untouched:
    // the fallback keys off this plugin's own governed-response marker.
    let mut fresh = create_test_context();
    assert!(
        plugin
            .transform_response_body_with_context(&mut fresh, &body, Some("text/html"), &html)
            .await.replaced_bytes()
            .is_none()
    );
}

#[tokio::test]
async fn dry_run_does_not_mutate_response_arguments() {
    let plugin = make(json!({
        "mode": "dry_run",
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "sk-[A-Za-z0-9]+" }]
            }
        }
    }));

    let body = response_with_tool_call("filesystem.write", "{\"token\":\"sk-DRYRUNSECRET123\"}");
    let mut ctx = create_test_context();
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/json"),
                &json_headers()
            )
            .await.replaced_bytes()
            .is_none(),
        "dry-run must not mutate the delivered response body"
    );
}

#[tokio::test]
async fn response_transform_respects_response_tool_calls_toggle() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "sk-[A-Za-z0-9]+" }]
            }
        },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));

    let body = response_with_tool_call("filesystem.write", "{\"token\":\"sk-TOGGLESECRET123\"}");
    let mut ctx = create_test_context();
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/json"),
                &json_headers()
            )
            .await.replaced_bytes()
            .is_none(),
        "response transform must be disabled when response_tool_calls=false"
    );
}

#[tokio::test]
async fn arguments_hashes_do_not_contain_raw_arguments() {
    let plugin = make(json!({ "tools": { "github.create_pr": { "action": "allow" } } }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("github.create_pr", "{\"repo\":\"acme/SENSITIVE\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    let hashes = ctx
        .metadata
        .get("ai_tool_governor.arguments_hashes")
        .expect("hashes present");
    assert!(
        !hashes.contains("SENSITIVE"),
        "raw args leaked into hash metadata"
    );
    // A SHA-256 hex is 64 chars.
    assert_eq!(hashes.len(), 64);
}

// ---------------------------------------------------------------------------
// Request tool-definition inspection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn denies_request_exposing_disallowed_tool_definition() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "github.create_pr": { "action": "allow" } },
        "inspect": { "request_tool_definitions": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "model": "gpt-4o",
            "messages": [],
            "tools": [
                { "type": "function", "function": { "name": "github.create_pr" } },
                { "type": "function", "function": { "name": "kubectl.apply" } }
            ]
        })
        .to_string(),
    );
    let mut headers = json_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn blocks_request_exposing_approval_required_tool_definition() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(0)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()) },
        "inspect": { "request_tool_definitions": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "model": "gpt-4o",
            "messages": [],
            "tools": [
                { "type": "function", "function": { "name": "deploy" } }
            ]
        })
        .to_string(),
    );
    let mut headers = json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(403));
    server.verify().await;
}

#[tokio::test]
async fn allows_request_exposing_only_permitted_tools() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "github.create_pr": { "action": "allow" } },
        "inspect": { "request_tool_definitions": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({ "tools": [{ "type": "function", "function": { "name": "github.create_pr" } }] })
            .to_string(),
    );
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn request_definition_dry_run_records_distinct_decision() {
    let plugin = make(json!({
        "default_action": "allow",
        "tools": {
            "report.read": { "action": "dry_run", "risk": "high" },
            "status.read": { "action": "allow" }
        },
        "inspect": { "request_tool_definitions": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "tools": [
                { "type": "function", "function": { "name": "report.read" } },
                { "type": "function", "function": { "name": "status.read" } }
            ]
        })
        .to_string(),
    );
    let mut headers = json_headers();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("dry_run")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.tool_names")
            .map(String::as_str),
        Some("report.read")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.risk")
            .map(String::as_str),
        Some("high")
    );
}

// ---------------------------------------------------------------------------
// MCP tools/call inspection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn denies_mcp_tools_call_for_denied_tool() {
    let plugin = make(json!({
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "kubectl.apply", "arguments": { "manifest": "kind: Pod" } }
        })
        .to_string(),
    );
    let mut headers = json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(403));
}

// ---------------------------------------------------------------------------
// Approval webhook
// ---------------------------------------------------------------------------

fn approval_config(endpoint: &str) -> Value {
    json!({
        "tools": { "deploy": { "action": "require_approval", "risk": "high" } },
        "approval": { "endpoint_url": endpoint, "cache_ttl_seconds": 300 }
    })
}

#[tokio::test]
async fn approval_allow_forwards() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "decision": "allow", "approval_id": "appr-1" })),
        )
        .mount(&server)
        .await;

    let plugin = make(approval_config(&format!("{}/approve", server.uri())));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("approved")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.approval_id")
            .map(String::as_str),
        Some("appr-1")
    );
}

#[tokio::test]
async fn correlation_id_composition_populates_generated_and_preserved_approval_request_ids() {
    let server = MockServer::start().await;
    let correlation = CorrelationId::new(&json!({})).expect("valid correlation config");
    let external_correlation = CorrelationId::new(&json!({
        "header_name": "x-external-correlation-id"
    }))
    .expect("valid external correlation config");

    let mut generated_ctx = create_test_context();
    generated_ctx.headers.insert(
        "x-external-correlation-id".to_string(),
        "attacker-controlled-alias".to_string(),
    );
    assert_continue(correlation.on_request_received(&mut generated_ctx).await);
    assert_continue(
        external_correlation
            .on_request_received(&mut generated_ctx)
            .await,
    );
    let generated_id = generated_ctx
        .metadata
        .get(ferrum_edge::plugins::REQUEST_ID_METADATA_KEY)
        .expect("generated canonical request ID")
        .clone();
    assert!(uuid::Uuid::parse_str(&generated_id).is_ok());
    assert_ne!(generated_id, "attacker-controlled-alias");

    let mut preserved_ctx = create_test_context();
    preserved_ctx.headers.insert(
        "x-request-id".to_string(),
        "approval-preserved-id".to_string(),
    );
    assert_continue(correlation.on_request_received(&mut preserved_ctx).await);

    for request_id in [&generated_id, "approval-preserved-id"] {
        Mock::given(method("POST"))
            .and(path("/approve"))
            .and(body_string_contains(format!(
                r#""request_id":"{request_id}""#
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "decision": "allow"
            })))
            .expect(1)
            .mount(&server)
            .await;
    }

    // Exercise both request IDs at the webhook boundary. Approval caching is
    // covered separately and would intentionally collapse these otherwise
    // identical tool calls before the second request reaches the mock server.
    let mut governor_config = approval_config(&format!("{}/approve", server.uri()));
    governor_config["approval"]["cache_ttl_seconds"] = json!(0);
    let governor = make(governor_config);
    let body = response_with_tool_call("deploy", r#"{"env":"prod"}"#);
    assert_continue(
        governor
            .on_response_body(&mut generated_ctx, 200, &mut json_headers(), &body)
            .await,
    );
    assert_continue(
        governor
            .on_response_body(&mut preserved_ctx, 200, &mut json_headers(), &body)
            .await,
    );
    server.verify().await;
}

#[tokio::test]
async fn approval_request_ids_prefer_canonical_then_legacy_custom_metadata() {
    let server = MockServer::start().await;
    for request_id in [
        "canonical-approval-id",
        "custom-request-id",
        "custom-correlation-id",
    ] {
        Mock::given(method("POST"))
            .and(path("/approve"))
            .and(body_string_contains(format!(
                r#""request_id":"{request_id}""#
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "decision": "allow"
            })))
            .expect(1)
            .mount(&server)
            .await;
    }

    let correlation = CorrelationId::new(&json!({})).expect("valid correlation config");
    let mut canonical_ctx = create_test_context();
    canonical_ctx.headers.insert(
        "x-request-id".to_string(),
        "canonical-approval-id".to_string(),
    );
    assert_continue(correlation.on_request_received(&mut canonical_ctx).await);
    canonical_ctx.metadata.insert(
        ferrum_edge::plugins::REQUEST_ID_METADATA_KEY.to_string(),
        "spoofed-legacy-request-id".to_string(),
    );
    canonical_ctx.metadata.insert(
        "correlation_id".to_string(),
        "spoofed-legacy-correlation-id".to_string(),
    );

    let mut request_id_ctx = create_test_context();
    request_id_ctx.metadata.insert(
        ferrum_edge::plugins::REQUEST_ID_METADATA_KEY.to_string(),
        "custom-request-id".to_string(),
    );
    request_id_ctx.metadata.insert(
        "correlation_id".to_string(),
        "lower-priority-custom-correlation-id".to_string(),
    );

    let mut correlation_id_ctx = create_test_context();
    correlation_id_ctx.metadata.insert(
        "correlation_id".to_string(),
        "custom-correlation-id".to_string(),
    );

    let mut governor_config = approval_config(&format!("{}/approve", server.uri()));
    governor_config["approval"]["cache_ttl_seconds"] = json!(0);
    let governor = make(governor_config);
    let body = response_with_tool_call("deploy", r#"{"env":"prod"}"#);
    for ctx in [
        &mut canonical_ctx,
        &mut request_id_ctx,
        &mut correlation_id_ctx,
    ] {
        assert_continue(
            governor
                .on_response_body(ctx, 200, &mut json_headers(), &body)
                .await,
        );
    }
    server.verify().await;
}

#[tokio::test]
async fn approval_include_arguments_opt_in_sends_raw_tool_arguments() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .and(body_string_contains("sensitive-approval-value"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": {
            "endpoint_url": format!("{}/approve", server.uri()),
            "include_arguments": true
        }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"value\":\"sensitive-approval-value\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    server.verify().await;
}

#[tokio::test]
async fn approval_deny_rejects() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "deny" })))
        .mount(&server)
        .await;

    let plugin = make(approval_config(&format!("{}/approve", server.uri())));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(403),
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("approval_denied")
    );
}

#[tokio::test]
async fn approval_cache_avoids_second_webhook() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1) // verified on server drop: the cache must prevent a 2nd call
        .mount(&server)
        .await;

    let plugin = make(approval_config(&format!("{}/approve", server.uri())));
    let body = response_with_tool_call("deploy", "{\"env\":\"prod\"}");

    // Two identical requests → one webhook call (second served from cache).
    for _ in 0..2 {
        let mut ctx = create_test_context();
        assert_continue(
            plugin
                .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
                .await,
        );
    }
    // Explicit verification (also runs on drop).
    server.verify().await;
}

#[tokio::test]
async fn batch_denial_skips_approval_webhook() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(0)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": {
            "deploy": { "action": "require_approval" },
            "kubectl.apply": { "action": "deny" }
        },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()) },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!([
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "deploy", "arguments": { "env": "prod" } }
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "kubectl.apply", "arguments": { "manifest": "kind: Pod" } }
            }
        ])
        .to_string(),
    );
    let mut headers = json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(403));
    server.verify().await;
}

#[tokio::test]
async fn approval_endpoint_error_fails_closed_by_default() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let plugin = make(approval_config(&format!("{}/approve", server.uri())));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    // fail_on_error defaults to reject → a 5xx from the endpoint blocks the call.
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn approval_endpoint_error_fails_open_when_configured() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "fail_on_error": "allow" }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
}

#[tokio::test]
async fn approval_endpoint_error_warns_and_fails_open_when_configured() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "fail_on_error": "warn" }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("approved")
    );
}

#[tokio::test]
async fn oversized_approval_response_fails_closed_without_unbounded_buffering() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "decision": "allow",
            "padding": "x".repeat(128 * 1024)
        })))
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()) }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn approval_endpoint_with_credentials_and_query_still_calls_webhook() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .mount(&server)
        .await;

    let endpoint = server.uri().replacen("http://", "http://user:secret@", 1);
    let plugin = make(approval_config(&format!("{endpoint}/approve?token=secret")));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
}

// ---------------------------------------------------------------------------
// Streaming SSE tool-call inspection
// ---------------------------------------------------------------------------

fn streaming_config(tools: Value, default_action: &str) -> Value {
    json!({
        "default_action": default_action,
        "tools": tools,
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    })
}

#[tokio::test]
async fn streaming_allows_and_releases_held_frames() {
    let plugin = make(streaming_config(
        json!({ "get_weather": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\":\\\"NYC\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let bytes = body.as_bytes();
    // Split the byte stream mid-way to exercise cross-chunk event reassembly.
    let (first, second) = bytes.split_at(bytes.len() / 2);
    let (out, terminated) = drive_stream(&mut inspector, &[first, second]).await;
    assert!(!terminated, "an allowed tool call must not cut the stream");
    // Every original frame is delivered (held frames were released).
    assert_eq!(out, bytes);
}

#[tokio::test]
async fn streaming_reconstructs_split_arguments_and_denies_without_leaking() {
    // A blocked pattern that only matches once the argument fragments are
    // reassembled across frames — proves the accumulator stitches deltas.
    let plugin = make(streaming_config(
        json!({
            "run": {
                "action": "allow",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "(?i)sk-secret-[0-9]+" }]
            }
        }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"run\",\"arguments\":\"{\\\"k\\\":\\\"sk-sec\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ret-123\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let bytes = body.as_bytes();
    let (first, second) = bytes.split_at(bytes.len() / 2);
    let (out, terminated) = drive_stream(&mut inspector, &[first, second]).await;

    assert!(
        terminated,
        "a reassembled blocked secret must cut the stream"
    );
    let text = String::from_utf8_lossy(&out);
    // The held tool-call frames (and the reassembled secret) must NOT leak.
    assert!(
        !text.contains("sk-sec"),
        "held tool-call fragment leaked: {text}"
    );
    assert!(
        !text.contains("secret-123"),
        "reassembled secret leaked: {text}"
    );
    // The terminal SSE error event is emitted.
    assert!(
        text.contains("ai_tool_governor_tool_blocked"),
        "no terminal error event: {text}"
    );
    // The pre-tool content frame (role) streamed through before the cut.
    assert!(
        text.contains("assistant"),
        "clean content should have streamed: {text}"
    );
}

#[tokio::test]
async fn streaming_denies_at_end_when_no_finish_reason() {
    let plugin = make(streaming_config(
        json!({ "safe": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    // A denied tool call with no finish_reason and no [DONE]: on_end must decide.
    let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"danger\",\"arguments\":\"{}\"}}]}}]}\n\n";
    let (out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(terminated, "unfinished denied stream must terminate at end");
    let text = String::from_utf8_lossy(&out);
    assert!(!text.contains("danger"), "held frame leaked: {text}");
}

#[tokio::test]
async fn streaming_inspector_only_for_event_stream_2xx() {
    let plugin = make(streaming_config(
        json!({ "x": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("application/json"))
            .is_none(),
        "JSON responses go through the buffered path, not the stream inspector"
    );
    assert!(
        plugin
            .response_stream_inspector(&ctx, 500, Some("text/event-stream"))
            .is_none(),
        "non-2xx responses are not inspected"
    );
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .is_some()
    );
}

#[tokio::test]
async fn streaming_approval_cache_key_includes_streamed_model() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(2)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 300 },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));

    for model in ["gpt-4o", "gpt-5"] {
        let ctx = create_test_context();
        let mut inspector = plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .expect("inspector");
        let tool_frame = json!({
            "model": model,
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": { "name": "deploy", "arguments": "{\"env\":\"prod\"}" }
                    }]
                }
            }]
        });
        let finish_frame = json!({
            "model": model,
            "choices": [{ "index": 0, "delta": {}, "finish_reason": "tool_calls" }]
        });
        let body = format!("data: {tool_frame}\n\ndata: {finish_frame}\n\ndata: [DONE]\n\n");
        let (_out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
        assert!(!terminated);
    }

    server.verify().await;
}

#[tokio::test]
async fn streaming_approval_cache_key_includes_sse_provider() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(2)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 300 },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));

    for provider_prelude in [
        json!({ "type": "message_start", "message": { "id": "msg_1" }, "model": "same-model" }),
        json!({ "object": "chat.completion.chunk", "model": "same-model" }),
    ] {
        let ctx = create_test_context();
        let mut inspector = plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .expect("inspector");
        let tool_frame = json!({
            "model": "same-model",
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": { "name": "deploy", "arguments": "{\"env\":\"prod\"}" }
                    }]
                }
            }]
        });
        let finish_frame = json!({
            "model": "same-model",
            "choices": [{ "index": 0, "delta": {}, "finish_reason": "tool_calls" }]
        });
        let body = format!(
            "data: {provider_prelude}\n\ndata: {tool_frame}\n\ndata: {finish_frame}\n\ndata: [DONE]\n\n"
        );
        let (_out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
        assert!(!terminated);
    }

    server.verify().await;
}

// ---------------------------------------------------------------------------
// Fail-closed request-body inspection (encoded / oversized / unparseable)
// ---------------------------------------------------------------------------

fn mcp_config(mode: &str) -> Value {
    json!({
        "mode": mode,
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    })
}

#[tokio::test]
async fn enforce_rejects_content_encoded_request_body() {
    // Request decompression runs in later body-transform hooks, so an encoded
    // body is opaque here: enforce mode must not forward it ungoverned.
    let plugin = make(mcp_config("enforce"));
    let mut ctx = json_post_ctx();
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "64".to_string());
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("deny")
    );
}

#[tokio::test]
async fn before_proxy_uses_live_header_argument_for_request_inspection() {
    let plugin = make(mcp_config("enforce"));
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "kubectl.apply", "arguments": { "manifest": "kind: Pod" } }
        })
        .to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(403));
}

#[tokio::test]
async fn before_proxy_ignores_stale_ctx_headers_content_type() {
    // Per `.claude/rules/plugins.md`: `before_proxy` must read the live `headers`
    // argument, never `ctx.headers`. The handler may have moved headers out of
    // `ctx.headers` (leaving it empty), or an earlier hook may have rewritten
    // Content-Type. Here the live `headers` carries a NON-JSON content-type while
    // the stale `ctx.headers` still claims `application/json` over a body that
    // WOULD be denied if parsed. The plugin must treat the request as out of
    // scope (Continue) and never parse/reject it from the stale header.
    let plugin = make(mcp_config("enforce"));
    let mut ctx = json_post_ctx();
    // `json_post_ctx()` leaves `application/json` in `ctx.headers`; a denied
    // tools/call body sits behind it.
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "kubectl.apply", "arguments": { "manifest": "kind: Pod" } }
        })
        .to_string(),
    );
    // The live header argument reflects what the request actually is: not JSON.
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        !ctx.metadata.contains_key("ai_tool_governor.decision"),
        "out-of-scope request must not be governed from the stale ctx.headers"
    );

    // An empty live `headers` is now deliberately in scope for MCP/A2A because
    // their gateways accept an absent Content-Type as JSON-RPC. The decision
    // still comes from the live absence, not the stale application/json value.
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "kubectl.apply", "arguments": { "manifest": "kind: Pod" } }
        })
        .to_string(),
    );
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(403));
}

#[tokio::test]
async fn dry_run_forwards_content_encoded_request_body() {
    let plugin = make(mcp_config("dry_run"));
    let mut ctx = json_post_ctx();
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "64".to_string());
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn enforce_rejects_oversized_request_body() {
    let plugin = make(mcp_config("enforce"));
    let mut ctx = json_post_ctx();
    // A syntactically valid JSON body padded past the 4 MiB parse limit.
    let body = format!("{{\"pad\":\"{}\"}}", "x".repeat(4 * 1024 * 1024));
    ctx.metadata.insert(
        "request_body_size_bytes".to_string(),
        body.len().to_string(),
    );
    ctx.metadata.insert("request_body".to_string(), body);
    let mut headers = json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
}

#[tokio::test]
async fn enforce_rejects_unparseable_json_request_body() {
    let plugin = make(mcp_config("enforce"));
    let mut ctx = json_post_ctx();
    ctx.metadata
        .insert("request_body".to_string(), "not-json{{{".to_string());
    let mut headers = json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
}

#[tokio::test]
async fn enforce_rejects_non_utf8_request_body() {
    // A non-UTF-8 (binary) body never reaches the `request_body` metadata slot;
    // only its size does. JSON must be UTF-8, so this is uninspectable.
    let plugin = make(mcp_config("enforce"));
    let mut ctx = json_post_ctx();
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "12".to_string());
    let mut headers = json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
}

#[tokio::test]
async fn non_json_posts_are_not_rejected() {
    // The fail-closed rules are scoped to the JSON POSTs this plugin governs.
    let plugin = make(mcp_config("enforce"));
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "64".to_string());
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

// ---------------------------------------------------------------------------
// JSON-RPC batch envelopes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn denies_mcp_tools_call_inside_json_rpc_batch() {
    let plugin = make(mcp_config("enforce"));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!([
            { "jsonrpc": "2.0", "id": 1, "method": "tools/list" },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "kubectl.apply", "arguments": { "manifest": "kind: Pod" } }
            }
        ])
        .to_string(),
    );
    let mut headers = json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(403));
}

#[tokio::test]
async fn allows_json_rpc_batch_without_governed_calls() {
    let plugin = make(mcp_config("enforce"));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!([{ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }]).to_string(),
    );
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

// ---------------------------------------------------------------------------
// Streaming dispatch + JSON-fallback buffering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stream_true_request_forces_reqwest_dispatch() {
    let plugin = make(streaming_config(
        json!({ "x": { "action": "allow" } }),
        "deny",
    ));
    let mut headers = json_headers();

    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({ "model": "gpt-4o", "stream": true, "messages": [] }).to_string(),
    );
    assert!(
        !plugin.forces_reqwest_dispatch(&ctx),
        "no marker before before_proxy runs"
    );
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        plugin.forces_reqwest_dispatch(&ctx),
        "a detected stream:true body must pin the reqwest dispatch path"
    );

    // A non-streaming body never leaves the fast path.
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({ "model": "gpt-4o", "messages": [] }).to_string(),
    );
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(!plugin.forces_reqwest_dispatch(&ctx));
}

#[tokio::test]
async fn stream_markers_are_excluded_from_transaction_log_metadata() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "x": { "action": "allow" } },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true },
        "observability": { "emit_metadata": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({ "model": "private-model", "stream": true, "messages": [] }).to_string(),
    );
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // The live lifecycle still needs these markers for dispatch/correlation.
    assert!(
        ctx.metadata
            .contains_key("ai_tool_governor.stream_requested")
    );
    assert!(ctx.metadata.contains_key("ai_tool_governor.stream_model"));

    // But disabling governor metadata must keep both out of every transaction
    // summary built through the shared logging boundary.
    let logged = clone_log_metadata(&ctx);
    assert!(!logged.contains_key("ai_tool_governor.stream_requested"));
    assert!(!logged.contains_key("ai_tool_governor.stream_model"));
    assert!(!logged.values().any(|value| value == "private-model"));
}

#[tokio::test]
async fn uninspectable_body_conservatively_forces_reqwest_when_streaming_only() {
    // Streaming-only configs never reject, but an uninspectable body may hide
    // `stream: true`, so the request must stay on the inspectable path.
    let plugin = make(streaming_config(
        json!({ "x": { "action": "allow" } }),
        "deny",
    ));
    let mut ctx = json_post_ctx();
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "64".to_string());
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "br".to_string());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(plugin.forces_reqwest_dispatch(&ctx));
}

#[tokio::test]
async fn enforce_streaming_only_ambiguity_does_not_claim_a_dry_run_decision() {
    // This plugin governs only streaming responses. It tentatively scans the
    // request to choose the inspectable dispatch path, but global mode is still
    // enforce and request calls are outside its governance surface. Ambiguity
    // must therefore preserve conservative dispatch without emitting the
    // dry-run-only observation label.
    let plugin = make(streaming_config(
        json!({ "x": { "action": "allow" } }),
        "deny",
    ));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        r#"{"stream":true,"stream":false}"#.to_string(),
    );
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(plugin.forces_reqwest_dispatch(&ctx));
    assert!(
        !ctx.metadata.contains_key(AMBIGUITY_METADATA_KEY),
        "enforce-mode request triage must not claim a dry-run decision"
    );
    assert!(
        !ctx.metadata.contains_key(AMBIGUITY_REASON_KEY),
        "out-of-scope request triage must not emit an ambiguity policy reason"
    );
}

#[test]
fn streaming_marked_requests_still_buffer_json_fallbacks() {
    // An earlier plugin's `ai_request_streaming` marker (or an SSE Accept
    // header) must not opt the response out of buffering pre-header: the
    // backend may answer with plain JSON tool_calls. Content-type refinement
    // releases only genuine event streams — and only when streaming inspection
    // is enabled so a live inspector will govern them — back to the stream
    // path.
    let plugin = make(json!({
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "response_tool_calls": true, "streaming_response_tool_calls": true }
    }));

    let mut ctx = create_test_context();
    ctx.metadata
        .insert("ai_request_streaming".to_string(), "true".to_string());
    assert!(plugin.should_buffer_response_body(&ctx));

    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());
    assert!(plugin.should_buffer_response_body(&ctx));

    let response_headers = HashMap::new();
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &response_headers
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &response_headers
    ));
}

// ---------------------------------------------------------------------------
// Oversized buffered responses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn enforce_rejects_oversized_json_response() {
    let plugin = make(json!({ "tools": { "kubectl.apply": { "action": "deny" } } }));
    let mut ctx = create_test_context();
    let body = vec![b'x'; 4 * 1024 * 1024 + 1];
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn dry_run_forwards_oversized_json_response() {
    let plugin = make(json!({
        "mode": "dry_run",
        "tools": { "kubectl.apply": { "action": "deny" } }
    }));
    let mut ctx = create_test_context();
    let body = vec![b'x'; 4 * 1024 * 1024 + 1];
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
}

#[tokio::test]
async fn gateway_added_content_encoding_header_does_not_make_plain_json_uninspectable() {
    let plugin = make(json!({ "tools": { "kubectl.apply": { "action": "allow" } } }));
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    let body = response_with_tool_call("kubectl.apply", "{}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
    );
}

#[tokio::test]
async fn enforce_rejects_opaque_content_encoded_json_response() {
    let plugin = make(json!({ "tools": { "kubectl.apply": { "action": "deny" } } }));
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, b"not-json-gzip-bytes")
            .await,
        Some(502),
    );
}

// ---------------------------------------------------------------------------
// Multi-choice streaming (per-choice finish tracking)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn streaming_governs_second_choice_tool_calls_after_first_choice_finishes() {
    // n=2 streaming: choice 0 finishes an ALLOWED call first; choice 1 then
    // streams a DENIED call. Finalizing on the first finish_reason would let
    // choice 1's deltas vanish ungoverned — they must still be evaluated.
    let plugin = make(streaming_config(
        json!({ "safe_tool": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"safe_tool\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: {\"choices\":[{\"index\":1,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c2\",\"function\":{\"name\":\"danger\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":1,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let (out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;

    assert!(terminated, "choice 1's denied call must cut the stream");
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("safe_tool"),
        "choice 0's allowed call should have been released: {text}"
    );
    assert!(!text.contains("danger"), "denied call leaked: {text}");
    assert!(
        text.contains("ai_tool_governor_tool_blocked"),
        "no terminal error event: {text}"
    );
}

#[tokio::test]
async fn streaming_multi_choice_releases_when_all_choices_allowed() {
    let plugin = make(streaming_config(
        json!({ "safe_tool": { "action": "allow" }, "other_tool": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    // Interleaved n=2 deltas; choice 0 finishes before choice 1's call arrives.
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"safe_tool\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: {\"choices\":[{\"index\":1,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c2\",\"function\":{\"name\":\"other_tool\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":1,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let bytes = body.as_bytes();
    let (out, terminated) = drive_stream(&mut inspector, &[bytes]).await;
    assert!(
        !terminated,
        "all-allowed multi-choice stream must not be cut"
    );
    assert_eq!(out, bytes, "every frame must be delivered");
}

// ---------------------------------------------------------------------------
// Streaming hold cap
// ---------------------------------------------------------------------------

/// One ~1MiB SSE tool-call delta frame (arguments fragment only, no finish).
fn huge_tool_call_frame() -> Vec<u8> {
    let args = "A".repeat(1024 * 1024);
    let frame = json!({
        "choices": [{
            "index": 0,
            "delta": { "tool_calls": [{ "index": 0, "function": { "name": "held_tool", "arguments": args } }] }
        }]
    });
    let mut event = b"data: ".to_vec();
    event.extend_from_slice(frame.to_string().as_bytes());
    event.extend_from_slice(b"\n\n");
    event
}

#[tokio::test]
async fn streaming_hold_cap_terminates_in_enforce_mode() {
    let plugin = make(streaming_config(
        json!({ "held_tool": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    // Never-finishing tool-call deltas: held bytes must not grow unboundedly.
    let frame = huge_tool_call_frame();
    let mut out = Vec::new();
    let mut terminated = false;
    for _ in 0..6 {
        match inspector.on_chunk(&frame).await {
            ResponseStreamAction::Forward(bytes) => out.extend_from_slice(&bytes),
            ResponseStreamAction::Terminate(bytes) => {
                if let Some(bytes) = bytes {
                    out.extend_from_slice(&bytes);
                }
                terminated = true;
                break;
            }
        }
    }
    assert!(terminated, "exceeding the hold cap must cut the stream");
    let text = String::from_utf8_lossy(&out);
    assert!(!text.contains("AAAA"), "held frames leaked: {text}");
    assert!(
        text.contains("ai_tool_governor_tool_blocked"),
        "no terminal error event: {text}"
    );
}

#[tokio::test]
async fn streaming_hold_cap_releases_uninspected_in_dry_run() {
    let plugin = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "held_tool": { "action": "allow" } },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    let frame = huge_tool_call_frame();
    let mut out = Vec::new();
    let mut terminated = false;
    for _ in 0..6 {
        match inspector.on_chunk(&frame).await {
            ResponseStreamAction::Forward(bytes) => out.extend_from_slice(&bytes),
            ResponseStreamAction::Terminate(bytes) => {
                if let Some(bytes) = bytes {
                    out.extend_from_slice(&bytes);
                }
                terminated = true;
                break;
            }
        }
    }
    assert!(!terminated, "dry-run must never disrupt traffic");
    assert_eq!(
        out.len(),
        frame.len() * 6,
        "dry-run must release all bytes once the cap is exceeded"
    );
}

// ---------------------------------------------------------------------------
// Approval cache keying
// ---------------------------------------------------------------------------

/// Like `response_with_tool_call` but with an Anthropic-shaped `usage`, so
/// `detect_response_provider` reports a different provider.
fn anthropic_shaped_response_with_tool_call(name: &str, arguments: &str) -> Vec<u8> {
    json!({
        "id": "chatcmpl-2",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": Value::Null,
                "tool_calls": [{
                    "id": "call_2",
                    "type": "function",
                    "function": { "name": name, "arguments": arguments }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": { "input_tokens": 1, "output_tokens": 1 }
    })
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn approval_cache_key_includes_provider() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(2) // same tool+args from two providers → two webhook calls
        .mount(&server)
        .await;

    let plugin = make(approval_config(&format!("{}/approve", server.uri())));

    let mut ctx = create_test_context();
    let openai = response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &openai)
            .await,
    );

    let mut ctx = create_test_context();
    let anthropic = anthropic_shaped_response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &anthropic)
            .await,
    );

    server.verify().await;
}

// ---------------------------------------------------------------------------
// Post-transform re-checks (on_final_request_body / on_final_response_body)
// ---------------------------------------------------------------------------

/// A `request_transformer`-style body rewrite after `before_proxy` that exposes
/// a denied tool definition must be caught on the final backend-visible body.
#[tokio::test]
async fn final_request_body_recheck_denies_transform_injected_definition() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "github.create_pr": { "action": "allow" } },
        "inspect": { "request_tool_definitions": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    let allowed =
        json!({ "tools": [{ "type": "function", "function": { "name": "github.create_pr" } }] })
            .to_string();
    ctx.metadata.insert("request_body".to_string(), allowed);
    let mut headers = json_headers();
    // before_proxy clears the allowed body and records its hash.
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // A later transform rewrites the body to expose a denied tool.
    let injected =
        json!({ "tools": [{ "type": "function", "function": { "name": "kubectl.apply" } }] })
            .to_string();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, injected.as_bytes())
            .await,
        Some(403),
    );
}

/// The final request-body re-check catches a transform that rewrites an allowed
/// MCP `tools/call` into a denied one.
#[tokio::test]
async fn final_request_body_recheck_denies_transform_injected_mcp_call() {
    let plugin = make(json!({
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    let headers = json_headers();
    let injected = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "kubectl.apply", "arguments": { "manifest": "kind: Pod" } }
    })
    .to_string();
    // before_proxy never governed this body (no recorded hash); the final hook
    // still fails closed on the denied call.
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, injected.as_bytes())
            .await,
        Some(403),
    );
}

/// When the final body is byte-identical to what `before_proxy` governed, the
/// re-check must NOT invoke the approval webhook a second time, even with the
/// approval cache disabled (the skip is hash-based, not cache-based).
#[tokio::test]
async fn final_request_body_recheck_skips_unchanged_body_no_second_webhook() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "deploy", "arguments": { "env": "prod" } }
    })
    .to_string();
    ctx.metadata
        .insert("request_body".to_string(), body.clone());
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await); // webhook #1

    // Same final body → hash matches → no second webhook.
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
    );
    server.verify().await;
}

/// A `response_transformer`-style injection after `on_response_body` must be
/// caught on the final client-visible body.
#[tokio::test]
async fn final_response_body_recheck_denies_transform_injected_tool_call() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    // Clean backend response with no tool calls: governed, hash recorded.
    let clean = json!({
        "id": "chatcmpl-1", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" }]
    })
    .to_string()
    .into_bytes();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &clean)
            .await,
    );

    // A later transform injects a denied tool call.
    let injected = response_with_tool_call("kubectl.apply", "{\"manifest\":\"kind: Pod\"}");
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &injected)
            .await,
        Some(403),
    );
}

/// The final response-body re-check must not re-invoke the approval webhook when
/// the client-visible body is unchanged from what `on_response_body` governed.
#[tokio::test]
async fn final_response_body_recheck_skips_unchanged_body_no_second_webhook() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    ); // webhook #1
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    ); // hash match → skip
    server.verify().await;
}

/// A response a later transform (e.g. the compression plugin) made opaque must
/// be skipped, not falsely rejected: the plaintext backend body was already
/// governed in `on_response_body`.
#[tokio::test]
async fn final_response_body_recheck_skips_opaque_transformed_body() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    let clean = json!({
        "id": "x", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" }]
    })
    .to_string()
    .into_bytes();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &clean)
            .await,
    );
    // A gzip-compressed (non-JSON) final body: opaque, must not fail closed.
    let opaque = vec![0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04];
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &opaque)
            .await,
    );
}

/// Approval cache keys must be unambiguous: two distinct (name, args) pairs that
/// differ only by where a `U+0001` byte falls must NOT share a cached decision.
#[tokio::test]
async fn approval_cache_key_is_unambiguous_across_delimiter_collisions() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(2) // distinct inputs → two webhook calls, never one cached hit
        .mount(&server)
        .await;

    let plugin = make(json!({
        "default_action": "require_approval",
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 300 }
    }));

    // (name="report", args="b\u{1}c") and (name="report\u{1}b", args="c") collide
    // under a flat `name\u{1}args` join but are genuinely different calls.
    let a = response_with_tool_call("report", "b\u{1}c");
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &a)
            .await,
    );

    let b = response_with_tool_call("report\u{1}b", "c");
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &b)
            .await,
    );

    server.verify().await;
}

/// Enforce mode fails closed when a later transform leaves the final request
/// body encoded (opaque), oversized, or unparseable.
#[tokio::test]
async fn final_request_body_recheck_enforce_rejects_uninspectable_bodies() {
    let plugin = make(json!({
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));

    // Content-encoding the governor cannot decode.
    let mut ctx = json_post_ctx();
    let mut encoded_headers = json_headers();
    encoded_headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &encoded_headers, b"\x1f\x8b\x08rest")
            .await,
        Some(502),
    );

    // Oversized body over the parse limit.
    let mut ctx = json_post_ctx();
    let oversized = vec![b'x'; 4 * 1024 * 1024 + 1];
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), &oversized)
            .await,
        Some(502),
    );

    // Non-JSON despite a JSON content-type.
    let mut ctx = json_post_ctx();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), b"not json at all")
            .await,
        Some(502),
    );
}

/// Dry-run mode forwards an uninspectable final body instead of rejecting.
#[tokio::test]
async fn final_request_body_recheck_dry_run_forwards_uninspectable() {
    let plugin = make(json!({
        "mode": "dry_run",
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    let mut encoded_headers = json_headers();
    encoded_headers.insert("content-encoding".to_string(), "br".to_string());
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &encoded_headers, b"opaque")
            .await,
    );
}

/// The request re-check ignores requests it does not govern: no request
/// inspection surface, a non-POST method, a non-JSON content type, or an empty
/// body all forward untouched.
#[tokio::test]
async fn final_request_body_recheck_ignores_out_of_scope_requests() {
    // No request inspection surface configured.
    let response_only = make(json!({
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "request_tool_definitions": false, "response_tool_calls": true }
    }));
    let mut ctx = json_post_ctx();
    assert_continue(
        response_only
            .on_final_request_body_with_context(&mut ctx, &json_headers(), b"{}")
            .await,
    );

    let plugin = make(json!({
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));

    // Non-POST method.
    let mut ctx = json_post_ctx();
    ctx.method = "GET".to_string();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), b"{}")
            .await,
    );

    // Non-JSON content type.
    let mut ctx = json_post_ctx();
    let mut text_headers = HashMap::new();
    text_headers.insert("content-type".to_string(), "text/plain".to_string());
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &text_headers, b"hello")
            .await,
    );

    // Empty body.
    let mut ctx = json_post_ctx();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), b"")
            .await,
    );
}

/// A transform that rewrites the response but leaves the tool call permitted is
/// forwarded by the final response-body re-check.
#[tokio::test]
async fn final_response_body_recheck_allows_permitted_transformed_call() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    let clean = json!({
        "id": "x", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" }]
    })
    .to_string()
    .into_bytes();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &clean)
            .await,
    );
    // Transform injects a PERMITTED tool call: still forwarded.
    let permitted = response_with_tool_call("report.read", "{\"id\":1}");
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &permitted)
            .await,
    );
}

/// The response re-check ignores responses out of scope: disabled response
/// inspection, non-2xx status, non-JSON content type, empty bodies, and
/// oversized bodies all forward untouched.
#[tokio::test]
async fn final_response_body_recheck_ignores_out_of_scope_responses() {
    // Response inspection disabled.
    let req_only = make(json!({
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = create_test_context();
    let denied = response_with_tool_call("kubectl.apply", "{}");
    assert_continue(
        req_only
            .on_final_response_body(&mut ctx, 200, &json_headers(), &denied)
            .await,
    );

    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));

    // Non-2xx status.
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 500, &json_headers(), &denied)
            .await,
    );

    // Non-JSON content type with a genuinely non-JSON body.
    let mut ctx = create_test_context();
    let mut html = HashMap::new();
    html.insert("content-type".to_string(), "text/html".to_string());
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &html, b"<html>hi</html>")
            .await,
    );

    // A relabeled content type does NOT skip a JSON-shaped final body: a header
    // transform must not disable the re-check of an injected denied call.
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &html, &denied)
            .await,
        Some(403),
    );

    // Empty body.
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), b"")
            .await,
    );

    // Oversized final body (a transform grew it past the parse limit): fail
    // closed in enforce mode so padding cannot smuggle a denied call.
    let mut ctx = create_test_context();
    let oversized = vec![b'x'; 4 * 1024 * 1024 + 1];
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &oversized)
            .await,
        Some(502),
    );
}

/// Capability flags gate the buffering and post-transform hooks by inspection
/// surface.
#[test]
fn post_transform_capability_flags_track_inspection_surfaces() {
    let req = make(json!({
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    assert!(req.requires_request_body_buffering());
    assert!(req.needs_final_request_body_context());

    let resp_only = make(json!({
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "request_tool_definitions": false, "response_tool_calls": true }
    }));
    assert!(!resp_only.requires_request_body_buffering());
    assert!(!resp_only.needs_final_request_body_context());
    assert!(resp_only.requires_response_body_buffering());
}

/// Protocol support and approval-endpoint warmup surfaces.
#[test]
fn capabilities_and_warmup_hostnames() {
    let plain = make(json!({
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    assert!(!plain.supported_protocols().is_empty());
    assert!(plain.warmup_hostnames().is_empty());

    let with_approval = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": "https://approvals.example.com/approve" },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    assert!(
        with_approval
            .warmup_hostnames()
            .iter()
            .any(|h| h.contains("approvals.example.com"))
    );
}

/// Canonical A2A JSON-RPC methods and gateway-supported PascalCase aliases use
/// the same policy key, so an alias cannot bypass a canonical deny rule.
#[tokio::test]
async fn a2a_method_deny_rejects() {
    let plugin = make(json!({
        "tools": { "message/send": { "action": "deny" } },
        "inspect": { "a2a_methods": true, "response_tool_calls": false }
    }));
    for method in ["message/send", "SendMessage"] {
        let mut ctx = json_post_ctx();
        ctx.metadata.insert(
            "request_body".to_string(),
            json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": { "foo": "bar" } })
                .to_string(),
        );
        let mut headers = json_headers();
        assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(403));
    }

    // The inverse spelling must work too: an operator-provided alias policy is
    // mirrored under the canonical method used by request extraction.
    let alias_policy = make(json!({
        "default_action": "allow",
        "tools": { "SendMessage": { "action": "deny" } },
        "inspect": { "a2a_methods": true, "response_tool_calls": false }
    }));
    for method in ["message/send", "SendMessage"] {
        let mut ctx = json_post_ctx();
        ctx.metadata.insert(
            "request_body".to_string(),
            json!({ "jsonrpc": "2.0", "id": 2, "method": method, "params": {} }).to_string(),
        );
        let mut headers = json_headers();
        assert_reject(
            alias_policy.before_proxy(&mut ctx, &mut headers).await,
            Some(403),
        );
    }
}

#[test]
fn rejects_conflicting_a2a_alias_and_canonical_policies() {
    let err = try_make(json!({
        "default_action": "allow",
        "tools": {
            "SendMessage": { "action": "deny" },
            "message/send": { "action": "allow" }
        },
        "inspect": { "a2a_methods": true, "response_tool_calls": false }
    }))
    .err()
    .unwrap();
    assert!(err.contains("conflicts with canonical method"), "{err}");
}

/// A per-tool `dry_run` action forwards the call while recording a distinct
/// observational decision even when the plugin mode is `enforce`. A sibling
/// allow in the same batch must not erase that rollout signal.
#[tokio::test]
async fn per_tool_dry_run_action_allows_and_labels() {
    let plugin = make(json!({
        "default_action": "allow",
        "tools": {
            "report.read": { "action": "dry_run" },
            "status.read": { "action": "allow" }
        }
    }));
    let mut ctx = create_test_context();
    let body = json!({
        "choices": [{
            "message": {
                "tool_calls": [
                    { "function": { "name": "report.read", "arguments": "{}" } },
                    { "function": { "name": "status.read", "arguments": "{}" } }
                ]
            }
        }]
    })
    .to_string()
    .into_bytes();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("dry_run")
    );
}

/// Per-tool risk levels surface in aggregate decision metadata.
#[tokio::test]
async fn tool_risk_levels_surface_in_metadata() {
    for (risk, tool) in [("critical", "danger"), ("medium", "warn")] {
        let plugin = make(json!({
            "default_action": "deny",
            "tools": { tool: { "action": "deny", "risk": risk } }
        }));
        let mut ctx = create_test_context();
        let body = response_with_tool_call(tool, "{}");
        assert_reject(
            plugin
                .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
                .await,
            Some(403),
        );
        assert_eq!(
            ctx.metadata
                .get("ai_tool_governor.risk")
                .map(String::as_str),
            Some(risk)
        );
    }
}

// ---------------------------------------------------------------------------
// Round 2 review fixes: buffering, redaction fail-closed, opaque decompress
// ---------------------------------------------------------------------------

fn gzip(data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn brotli(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut compressed = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
        writer.write_all(data).expect("brotli write");
    }
    compressed
}

fn gzip_headers() -> HashMap<String, String> {
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers
}

fn response_tool_call_model(name: &str, arguments: &str, model: Option<&str>) -> Vec<u8> {
    let mut obj = json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": Value::Null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": { "name": name, "arguments": arguments }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": { "prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2 }
    });
    if let Some(m) = model {
        obj["model"] = json!(m);
    }
    obj.to_string().into_bytes()
}

/// An absent correlation field (`null`) and an explicit empty string must hash
/// to different approval cache keys — the webhook may decide differently.
#[tokio::test]
async fn approval_cache_key_distinguishes_absent_vs_empty_fields() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(2) // absent model vs empty-string model = distinct approvals
        .mount(&server)
        .await;

    let plugin = make(json!({
        "default_action": "require_approval",
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 300 }
    }));

    // Same tool + args, but model absent (None) then explicitly empty ("").
    let absent = response_tool_call_model("deploy", "{}", None);
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &absent)
            .await,
    );

    let empty = response_tool_call_model("deploy", "{}", Some(""));
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &empty)
            .await,
    );

    server.verify().await;
}

/// A streaming-only config must still advertise request AND response body
/// buffering so the proxy buffers the JSON body for `before_proxy` streaming
/// detection and for governing an SSE JSON fallback.
#[test]
fn streaming_only_config_advertises_buffering() {
    let plugin = make(json!({
        "default_action": "deny",
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_response_body_buffering());
    // Per-request pre-header gate stays enabled even for an unmarked request:
    // response headers are needed to distinguish raw SSE (release to the live
    // inspector) from encoded SSE (keep buffered for decode-and-govern).
    let mut streaming = create_test_context();
    streaming
        .metadata
        .insert("ai_request_streaming".to_string(), "true".to_string());
    assert!(plugin.should_buffer_response_body(&streaming));
    assert!(plugin.should_buffer_response_body(&create_test_context()));
}

/// When a `stream: true` request's backend returns a plain JSON Chat Completions
/// body instead of SSE, the streaming-only config governs that fallback and
/// denies a disallowed tool call.
#[tokio::test]
async fn streaming_only_governs_json_fallback_response() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let denied = response_with_tool_call("kubectl.apply", "{}");

    // Streaming request (SSE fallback to JSON): the fallback is governed.
    let mut ctx = create_test_context();
    ctx.metadata
        .insert("ai_request_streaming".to_string(), "true".to_string());
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &denied)
            .await,
        Some(403),
    );

    // Non-streaming request: buffered response inspection is disabled, so the
    // ordinary JSON response is not governed.
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &denied)
            .await,
    );
}

/// An MCP/A2A request whose arguments match a `redact_args` policy fails closed
/// in enforce mode — there is no request-body transform to redact them.
#[tokio::test]
async fn request_redact_args_match_fails_closed() {
    let plugin = make(json!({
        "tools": { "search": { "action": "redact_args", "blocked_arg_patterns": [{ "name": "sk", "regex": "sk-[a-z0-9]+" }] } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "search", "arguments": { "q": "token sk-abc123" } }
        })
        .to_string(),
    );
    let mut headers = json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
    // The plugin's own metadata must not echo the raw secret (the seeded
    // `request_body` legitimately still holds it — that is the test's input).
    for (key, value) in &ctx.metadata {
        if key.starts_with("ai_tool_governor.") {
            assert!(
                !value.contains("sk-abc123"),
                "governor metadata {key:?} leaked secret"
            );
        }
    }
}

/// A `redact_args` match introduced into the FINAL response body (after the
/// redaction transform already ran) fails closed — it cannot be redacted here.
#[tokio::test]
async fn final_response_redact_args_match_fails_closed() {
    let plugin = make(json!({
        "tools": { "search": { "action": "redact_args", "blocked_arg_patterns": [{ "name": "sk", "regex": "sk-[a-z0-9]+" }] } }
    }));
    let mut ctx = create_test_context();
    // Clean backend body governed first (records hash).
    let clean = json!({
        "id": "x", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" }]
    })
    .to_string()
    .into_bytes();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &clean)
            .await,
    );

    // A transform injects a redact_args call carrying an unredacted secret.
    let injected = response_with_tool_call("search", "{\"q\":\"sk-deadbeef\"}");
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &injected)
            .await,
        Some(502),
    );
    assert_no_metadata_contains(&ctx, "sk-deadbeef");
}

/// A denied tool call injected by a transform and then gzip-compressed by the
/// compression plugin must be decompressed and fail closed in the final re-check.
#[tokio::test]
async fn final_response_decompresses_and_denies_injected_compressed_call() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    let clean = json!({
        "id": "x", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" }]
    })
    .to_string()
    .into_bytes();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &clean)
            .await,
    );

    let injected = response_with_tool_call("kubectl.apply", "{\"manifest\":\"kind: Pod\"}");
    let compressed = gzip(&injected);
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &gzip_headers(), &compressed)
            .await,
        Some(403),
    );
}

/// The same final-response decode path supports valid Brotli payloads emitted
/// by the gateway compression plugin, not only gzip.
#[tokio::test]
async fn final_response_decompresses_brotli_and_denies_injected_call() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    let clean = json!({
        "id": "x", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" }]
    })
    .to_string()
    .into_bytes();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &clean)
            .await,
    );

    let injected = response_with_tool_call("kubectl.apply", "{\"manifest\":\"kind: Pod\"}");
    let compressed = brotli(&injected);
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "br".to_string());
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &compressed)
            .await,
        Some(403),
    );
}

/// A legitimately gzip-compressed final body with only permitted tool calls is
/// decompressed, found clean, and forwarded — no false rejection.
#[tokio::test]
async fn final_response_allows_legit_compressed_body() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    let clean = json!({
        "id": "x", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" }]
    })
    .to_string()
    .into_bytes();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &clean)
            .await,
    );

    let permitted = response_with_tool_call("report.read", "{\"id\":1}");
    let compressed = gzip(&permitted);
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &gzip_headers(), &compressed)
            .await,
    );
}

// ---------------------------------------------------------------------------
// Round 18 fix (finding 1): the final re-check decodes an encoded body and runs
// the `looks_like_sse` check on the DECODED bytes BEFORE the JSON-fallback
// streaming-request gate, so a transform that injects an SSE `data:` frame AND
// compresses it (e.g. under a compressible `text/plain` relabel) is governed
// even under a streaming-ONLY config on a NON-streaming request.
// ---------------------------------------------------------------------------

/// A denied tool call injected as an SSE `data:` frame and then gzip-compressed
/// under a streaming-ONLY config (`response_tool_calls: false`) on a
/// NON-streaming request: the final re-check must DECODE and route the decoded
/// SSE bytes through buffered-SSE governance BEFORE the `governs_buffered_json`
/// gate (which is false here), so enforce mode fails closed. Without the fix the
/// gate returned `Continue` before the decoded `looks_like_sse` check ran and
/// the injected-then-compressed call escaped governance.
#[tokio::test]
async fn final_response_streaming_only_governs_encoded_injected_sse_enforce() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));
    // A plain, non-streaming request (no SSE Accept, no streaming marker):
    // `governs_buffered_json` is false for this request.
    let mut ctx = create_test_context();

    // A later transform injects a denied SSE frame and compresses it, relabeling
    // to a compressible `text/plain` (so `on_response_body` never governed it).
    let injected_sse = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"kubectl.apply\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let compressed = gzip(injected_sse.as_bytes());
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &compressed)
            .await,
        Some(403),
    );
}

/// Dry-run counterpart: the same encoded injected-SSE denied call under a
/// streaming-only config on a non-streaming request is FORWARDED (observation
/// never disrupts traffic), and the raw call name is not leaked to metadata.
#[tokio::test]
async fn final_response_streaming_only_encoded_injected_sse_dry_run_forwards() {
    let plugin = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));
    let mut ctx = create_test_context();
    let injected_sse = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"kubectl.apply\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let compressed = gzip(injected_sse.as_bytes());
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &compressed)
            .await,
    );
}

/// The narrow decode-before-gate must not re-govern (or re-call an approval
/// webhook for) an UNCHANGED already-governed encoded SSE body: the decoded
/// hash matches the recorded governed marker, so the final re-check hash-skips.
#[tokio::test]
async fn final_response_streaming_only_encoded_sse_unchanged_hash_skips() {
    let server = MockServer::start().await;
    // Exactly ONE approval call: the buffered-SSE governance in `on_response_body`.
    // The final re-check must hash-skip and not call it a second time.
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));
    // Streaming request so the buffered-SSE fallback is governed by
    // `on_response_body` (records the governed marker on the decoded bytes is
    // handled by `govern_buffered_sse`).
    let mut ctx = create_test_context();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    let sse = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"report.read\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    // `on_response_body` sees an SSE-labeled (encoded) body and governs the
    // decoded SSE — one approval call — recording the decoded-body marker.
    let compressed = gzip(sse.as_bytes());
    let mut sse_headers = HashMap::new();
    sse_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    sse_headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers, &compressed)
            .await,
    );
    // The client-visible body is the SAME compressed bytes: the final re-check
    // decodes, matches the recorded hash, and skips — no second approval call.
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &sse_headers, &compressed)
            .await,
    );
    server.verify().await;
}

// ---------------------------------------------------------------------------
// Round 3 review fixes: dry_run, federation provider, decompress skip, SSE
// ---------------------------------------------------------------------------

/// A per-tool `dry_run` action forwards (observes) even when an argument check
/// like `max_arg_bytes` would otherwise deny, in enforce mode.
#[tokio::test]
async fn per_tool_dry_run_forwards_despite_failing_arg_checks() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "big": { "action": "dry_run", "max_arg_bytes": 4 } }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("big", "{\"x\":\"way past the four byte limit\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("dry_run")
    );
}

#[test]
fn rejects_redact_args_without_blocked_patterns() {
    for blocked_arg_patterns in [None, Some(json!([]))] {
        let mut policy = json!({ "action": "redact_args" });
        if let Some(patterns) = blocked_arg_patterns {
            policy
                .as_object_mut()
                .expect("policy should be an object")
                .insert("blocked_arg_patterns".to_string(), patterns);
        }
        let err = try_make(json!({ "tools": { "search": policy } }))
            .err()
            .expect("empty redact_args policy must be rejected");
        assert!(err.contains("requires at least one"), "{err}");
        assert!(err.contains("blocked_arg_patterns"), "{err}");
    }
}

/// Approval uses the real serving provider recorded by `ai_federation` in
/// metadata, not the OpenAI shape of the normalized body.
#[tokio::test]
async fn approval_prefers_federation_provider_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .and(body_string_contains("\"provider\":\"anthropic\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = make(json!({
        "default_action": "require_approval",
        "approval": { "endpoint_url": format!("{}/approve", server.uri()) }
    }));
    let mut ctx = create_test_context();
    // ai_federation normalized an Anthropic response to OpenAI shape.
    ctx.metadata
        .insert("ai_provider".to_string(), "anthropic".to_string());
    let body = response_with_tool_call("deploy", "{}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    server.verify().await;
}

/// A compression-only rewrite of an already-governed body decodes to identical
/// bytes, so the final re-check skips it and does not fire a second approval.
#[tokio::test]
async fn compression_only_final_body_skips_duplicate_approval() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    ); // webhook #1
    // compression compressed the SAME governed body → decode matches hash → skip.
    let compressed = gzip(&body);
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &gzip_headers(), &compressed)
            .await,
    );
    server.verify().await;
}

/// A denied final body grown past the parse limit by a transform fails closed.
#[tokio::test]
async fn oversized_final_response_after_transform_fails_closed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    let clean = json!({
        "id": "x", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" }]
    })
    .to_string()
    .into_bytes();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &clean)
            .await,
    );
    let oversized = vec![b'x'; 4 * 1024 * 1024 + 1];
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &oversized)
            .await,
        Some(502),
    );
}

/// A `text/event-stream` response kept on the buffered path (stream inspector
/// did not attach) is still governed: a denied tool call is rejected, an
/// allowed one forwards.
#[tokio::test]
async fn buffered_sse_response_is_governed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut sse_headers = HashMap::new();
    sse_headers.insert("content-type".to_string(), "text/event-stream".to_string());

    let denied = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"kubectl.apply\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers, denied.as_bytes())
            .await,
        Some(403),
    );

    let allowed = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"report.read\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers, allowed.as_bytes())
            .await,
    );
}

// ---------------------------------------------------------------------------
// Round 4 review fixes: provider name, streaming unnamed frames
// ---------------------------------------------------------------------------

/// Approval prefers the unique `ai_federation_provider` name over the coarse
/// `ai_provider` type, so two providers of the same type do not share a
/// decision.
#[tokio::test]
async fn approval_uses_unique_federation_provider_name() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .and(body_string_contains("\"provider\":\"anthropic-secondary\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = make(json!({
        "default_action": "require_approval",
        "approval": { "endpoint_url": format!("{}/approve", server.uri()) }
    }));
    let mut ctx = create_test_context();
    ctx.metadata
        .insert("ai_provider".to_string(), "anthropic".to_string());
    ctx.metadata.insert(
        "ai_federation_provider".to_string(),
        "anthropic-secondary".to_string(),
    );
    let body = response_with_tool_call("deploy", "{}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    server.verify().await;
}

const SSE_UNNAMED_TOOL_FRAMES: &str = concat!(
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,",
    "\"function\":{\"arguments\":\"{}\"}}]}}]}\n\n",
    "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
    "data: [DONE]\n\n"
);

/// Streamed tool-call frames that never carry a `function.name` cannot be
/// governed; enforce mode cuts the stream rather than forwarding them.
#[tokio::test]
async fn streaming_unnamed_tool_frames_fail_closed_in_enforce() {
    let plugin = Arc::new(make(streaming_config(json!({}), "deny")));
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let mut ctx = create_test_context();
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("inspector");
    let (_out, terminated) =
        drive_stream(&mut inspector, &[SSE_UNNAMED_TOOL_FRAMES.as_bytes()]).await;
    assert!(
        terminated,
        "ungovernable tool-call frames must cut the stream in enforce mode"
    );
    drop(inspector);
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(0))
        .await;
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("deny"),
        "the fail-closed stream cut must be visible in transaction metadata"
    );
}

/// In dry-run the same ungovernable frames are released unchanged — dry-run
/// never disrupts traffic.
#[tokio::test]
async fn streaming_unnamed_tool_frames_released_in_dry_run() {
    let plugin = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let bytes = SSE_UNNAMED_TOOL_FRAMES.as_bytes();
    let (out, terminated) = drive_stream(&mut inspector, &[bytes]).await;
    assert!(!terminated, "dry-run must not cut the stream");
    assert_eq!(out, bytes, "dry-run must release the held frames unchanged");
}

// ---------------------------------------------------------------------------
// Round 5 review fixes: ungovernable streamed calls, redaction re-check, stream
// ---------------------------------------------------------------------------

/// A `request_transformer` that adds `stream: true` after `before_proxy` must be
/// re-detected on the final request body so the reqwest streaming path is pinned.
#[tokio::test]
async fn final_request_body_redetects_transform_added_stream() {
    let plugin = make(json!({
        "default_action": "deny",
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    // No streaming marker before this hook (the transform just added it).
    assert!(!plugin.forces_reqwest_dispatch(&ctx));
    let body = json!({ "stream": true, "model": "gpt-4o", "messages": [] }).to_string();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), body.as_bytes())
            .await,
    );
    assert!(
        plugin.forces_reqwest_dispatch(&ctx),
        "final-body stream:true must pin reqwest dispatch"
    );
}

/// A batch with one named allowed call AND one unnamed tool-call delta must fail
/// closed in enforce — the ungovernable sibling cannot ride out with the allowed
/// call.
#[tokio::test]
async fn streaming_mixed_named_and_unnamed_fails_closed() {
    let plugin = make(streaming_config(
        json!({ "get_weather": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
        "{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"{}\"}},",
        "{\"index\":1,\"function\":{\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let (_out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(
        terminated,
        "an ungovernable sibling call must cut the stream even alongside a named allowed call"
    );
}

/// A streamed tool call whose `function.arguments` arrive as a non-string JSON
/// value is ungovernable and fails closed in enforce.
#[tokio::test]
async fn streaming_non_string_arguments_fail_closed() {
    let plugin = make(streaming_config(
        json!({ "get_weather": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
        "{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"get_weather\",\"arguments\":{\"city\":\"NYC\"}}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let (_out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(
        terminated,
        "non-string streamed arguments are ungovernable and must fail closed"
    );
}

/// Redacting one call must not re-invoke the approval webhook for a separate
/// already-approved call in the final re-check (the redaction updates the
/// governed hash so the final body is treated as already governed).
#[tokio::test]
async fn redaction_does_not_trigger_duplicate_approval_on_final() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = make(json!({
        "tools": {
            "deploy": { "action": "require_approval" },
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "sk-[A-Za-z0-9]+" }]
            }
        },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 }
    }));
    let body = json!({
        "id": "1", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": Value::Null, "tool_calls": [
            { "id": "c1", "type": "function", "function": { "name": "deploy", "arguments": "{}" } },
            { "id": "c2", "type": "function", "function": { "name": "filesystem.write", "arguments": "{\"token\":\"sk-SECRET123\"}" } }
        ] }, "finish_reason": "tool_calls" }]
    })
    .to_string()
    .into_bytes();
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    ); // webhook #1 + marks redaction
    let transformed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await.replaced_bytes()
        .expect("redacted body");
    assert!(!String::from_utf8_lossy(&transformed).contains("sk-SECRET123"));
    // Final re-check sees the redacted body → matches updated hash → skip.
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &transformed)
            .await,
    );
    server.verify().await; // still exactly 1
}

/// A redaction placeholder that contains the pattern name must not be re-flagged
/// as a blocked-pattern match by the final re-check.
#[tokio::test]
async fn redaction_placeholder_not_reflagged_on_final() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "token", "regex": "token" }]
            }
        }
    }));
    let body = response_with_tool_call("filesystem.write", "{\"data\":\"my token here\"}");
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    let transformed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await.replaced_bytes()
        .expect("redacted body");
    // The placeholder embeds "token" but the final re-check must forward, not 502.
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &transformed)
            .await,
    );
}

#[tokio::test]
async fn redact_args_findings_on_range_and_delta_responses_fail_closed() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "sk-[A-Za-z0-9]+" }]
            }
        }
    }));
    let governed = response_with_tool_call("filesystem.write", "{\"token\":\"sk-SECRET123\"}");
    let clean = response_with_tool_call("filesystem.write", "{\"path\":\"/safe\"}");

    for status in [206, 226] {
        let mut governed_ctx = create_test_context();
        assert_reject(
            plugin
                .on_response_body(&mut governed_ctx, status, &mut json_headers(), &governed)
                .await,
            Some(502),
        );
        assert_eq!(
            governed_ctx
                .metadata
                .get("ai_tool_governor.decision")
                .map(String::as_str),
            Some("deny")
        );

        let mut clean_ctx = create_test_context();
        assert_continue(
            plugin
                .on_response_body(&mut clean_ctx, status, &mut json_headers(), &clean)
                .await,
        );
    }
}

// ---------------------------------------------------------------------------
// Round 6 review fixes: buffered-SSE ungovernable, header relabeling, placeholder
// ---------------------------------------------------------------------------

/// A buffered SSE tool call that cannot be policy-checked (missing name) fails
/// closed, like the live streaming path.
#[tokio::test]
async fn buffered_sse_ungovernable_call_fails_closed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut sse_headers = HashMap::new();
    sse_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,",
        "\"function\":{\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers, body.as_bytes())
            .await,
        Some(502),
    );
}

/// An ungovernable buffered SSE body must not stage a skip hash: otherwise a
/// later `on_final_response_body` of the same bytes would hash-skip and
/// Continue past the uninspectable screen (even after the initial Reject).
#[tokio::test]
async fn buffered_sse_ungovernable_never_stages_final_skip_hash() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut sse_headers = HashMap::new();
    sse_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,",
        "\"function\":{\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers, body.as_bytes())
            .await,
        Some(502),
    );
    // Same context + same body: must still fail closed. Staging a hash before
    // the ungovernable screen would let this final re-check hash-skip.
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &sse_headers, body.as_bytes())
            .await,
        Some(502),
    );
}

/// Governable buffered SSE still stages a skip hash so an unchanged final body
/// does not re-fire a `require_approval` webhook.
#[tokio::test]
async fn buffered_sse_governable_still_hash_skips_unchanged_final() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut sse_headers = HashMap::new();
    sse_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"report.read\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers, body.as_bytes())
            .await,
    );
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &sse_headers, body.as_bytes())
            .await,
    );
    server.verify().await;
}

/// A request whose `Content-Type` was stripped by a transform is still governed
/// when the body is JSON-shaped.
#[tokio::test]
async fn final_request_governs_json_body_despite_removed_content_type() {
    let plugin = make(json!({
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    let headers = HashMap::new(); // Content-Type removed by a transform.
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "kubectl.apply", "arguments": { "manifest": "kind: Pod" } }
    })
    .to_string();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
        Some(403),
    );
}

/// A response whose `Content-Type` was relabeled to non-JSON is still governed
/// when the body is JSON-shaped Chat Completions.
#[tokio::test]
async fn response_governs_json_body_despite_relabeled_content_type() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    let body = response_with_tool_call("kubectl.apply", "{}");
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        Some(403),
    );
}

/// A later transform that only adds an unrelated field (changing the body hash)
/// must not re-flag an already-redacted call as a blocked-pattern match.
#[tokio::test]
async fn later_transform_does_not_reflag_redacted_call() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "token", "regex": "token" }]
            }
        }
    }));
    let body = response_with_tool_call("filesystem.write", "{\"data\":\"my token here\"}");
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    let redacted = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await.replaced_bytes()
        .expect("redacted body");
    // A later response_transformer adds an unrelated field, changing the body
    // hash but leaving the redacted call unchanged.
    let mut val: Value = serde_json::from_slice(&redacted).unwrap();
    val["ferrum_extra"] = json!("added-by-response-transformer");
    let later = serde_json::to_vec(&val).unwrap();
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &later)
            .await,
    );
}

/// A model-only rewrite is approval-relevant for `require_approval`, but not
/// for deterministic `redact_args`. The already-redacted placeholder must not
/// be re-evaluated and rejected merely because the top-level model changed.
#[tokio::test]
async fn model_only_transform_does_not_reflag_redacted_call() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "token", "regex": "token" }]
            }
        }
    }));
    let body = response_with_tool_call("filesystem.write", "{\"data\":\"my token here\"}");
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    let redacted = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await.replaced_bytes()
        .expect("redacted body");

    let mut val: Value = serde_json::from_slice(&redacted).unwrap();
    val["model"] = json!("gpt-4o-mini");
    let model_rewritten = serde_json::to_vec(&val).unwrap();
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &model_rewritten)
            .await,
    );
}

// ---------------------------------------------------------------------------
// Round 8 review fixes: decode-before-gate, keep-buffered posture, identity
// counts/correlation fields, marker-gated redaction transform
// ---------------------------------------------------------------------------

/// A denied tool call injected by a transform, relabeled away from JSON
/// (`text/html` is compressible), and THEN gzip-compressed must still be
/// decoded and fail closed: the compressed bytes do not look like JSON and the
/// header no longer says JSON, so the content gates must run against the
/// DECODED bytes, not the encoded ones.
#[tokio::test]
async fn final_response_decodes_before_content_gates_and_denies_relabeled_compressed_call() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    let clean = json!({
        "id": "x", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" }]
    })
    .to_string()
    .into_bytes();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &clean)
            .await,
    );

    // A response_transformer injects a denied call and relabels Content-Type;
    // the compression plugin then gzips the (text/*, compressible) body.
    let injected = response_with_tool_call("kubectl.apply", "{\"manifest\":\"kind: Pod\"}");
    let compressed = gzip(&injected);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/html".to_string());
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &compressed)
            .await,
        Some(403),
    );
}

/// A compression-only rewrite of an already-governed body is still skipped
/// when the content type was ALSO relabeled: the decoded bytes match the
/// governed hash, so no duplicate approval webhook and no false rejection.
#[tokio::test]
async fn relabeled_compressed_unchanged_body_still_skips_final_recheck() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    ); // webhook #1
    let compressed = gzip(&body);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &compressed)
            .await,
    );
    server.verify().await; // still exactly 1
}

/// Keep-buffered matrix for the proxy's header-time content-type refinement:
/// on a governed request, ambiguous labels stay buffered (FailClosed posture);
/// only genuine SSE and framed gRPC/gRPC-Web are released back to the
/// streaming path; instances/requests without response governance never force
/// buffering.
#[test]
fn content_type_hook_keeps_ambiguous_labels_buffered() {
    let plugin = make(json!({ "tools": { "kubectl.apply": { "action": "deny" } } }));
    let ctx = create_test_context();
    let response_headers = HashMap::new();
    let buffered = |ct: Option<&str>| {
        plugin.should_buffer_response_body_for_content_type(&ctx, ct, 200, &response_headers)
    };
    assert!(buffered(Some("application/json")));
    // Mislabeled/unlabeled 2xx bodies could still be Chat Completions JSON
    // carrying a denied call: keep them buffered for `on_response_body`.
    assert!(buffered(Some("text/html")));
    assert!(buffered(Some("text/plain")));
    assert!(buffered(None));
    // With streaming inspection DISABLED no live SSE inspector exists, so an
    // SSE label stays buffered too: buffered-SSE governance handles real SSE
    // and the JSON-shape fallback catches Chat Completions JSON a transform
    // relabeled `text/event-stream`.
    assert!(buffered(Some("text/event-stream")));
    // Framed gRPC / gRPC-Web wire frames are owned by other machinery.
    assert!(!buffered(Some("application/grpc")));
    assert!(!buffered(Some("application/grpc+proto")));
    assert!(!buffered(Some("application/grpc-web+json")));
    // Non-2xx never buffers.
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/html"),
        500,
        &response_headers
    ));

    // An instance that does not govern responses never forces buffering.
    let request_only = make(json!({
        "tools": { "kubectl.apply": { "action": "deny" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    assert!(!request_only.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/html"),
        200,
        &response_headers
    ));
    assert!(!request_only.should_buffer_response_body_for_content_type(
        &ctx,
        None,
        200,
        &response_headers
    ));

    // A streaming-only config keeps the pre-header buffering candidate enabled
    // even for an unmarked/bodyless request. Header-time refinement releases
    // unencoded SSE to the live inspector, but keeps encoded or ambiguous
    // labels buffered so an unmarked `GET /events` cannot send gzip bytes into
    // the raw SSE parser.
    let streaming_only = make(json!({
        "default_action": "deny",
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    assert!(streaming_only.should_buffer_response_body(&ctx));
    assert!(streaming_only.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/html"),
        200,
        &response_headers
    ));
    assert!(
        !streaming_only.should_buffer_response_body_for_content_type(
            &ctx,
            Some("text/event-stream"),
            200,
            &response_headers
        )
    );
    let mut encoded_sse_headers = sse_headers();
    encoded_sse_headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert!(streaming_only.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &encoded_sse_headers
    ));
    let mut streaming_ctx = create_test_context();
    streaming_ctx
        .metadata
        .insert("ai_request_streaming".to_string(), "true".to_string());
    assert!(streaming_only.should_buffer_response_body_for_content_type(
        &streaming_ctx,
        Some("text/html"),
        200,
        &response_headers
    ));
    // With streaming inspection ENABLED, a genuine SSE label is released to
    // the streaming path where the live inspector attaches and governs it.
    assert!(
        !streaming_only.should_buffer_response_body_for_content_type(
            &streaming_ctx,
            Some("text/event-stream"),
            200,
            &response_headers
        )
    );
}

/// A transform that changes only the top-level `model` while leaving an
/// approved `require_approval` call unchanged must RE-approve: approval
/// decisions are keyed per model/provider, so the recorded call identity
/// (which includes those fields) no longer matches.
#[tokio::test]
async fn model_change_forces_reapproval_of_unchanged_call() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .and(body_string_contains("\"model\":\"gpt-4o\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .and(body_string_contains("\"model\":\"gpt-4o-mini\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 }
    }));
    let mut ctx = create_test_context();
    let body = response_tool_call_model("deploy", "{\"env\":\"prod\"}", Some("gpt-4o"));
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    ); // webhook #1, approved for model gpt-4o

    // A later transform rewrites ONLY the model; the call itself is unchanged.
    let relabeled = response_tool_call_model("deploy", "{\"env\":\"prod\"}", Some("gpt-4o-mini"));
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &relabeled)
            .await,
    ); // webhook #2, re-approved under the new model
    server.verify().await;
}

/// A transform that DUPLICATES an already-approved call (same name + args) must
/// have the copy re-evaluated: recorded identities are consumed as a multiset,
/// so with `cache_ttl_seconds: 0` one approval cannot cover two executions.
#[tokio::test]
async fn duplicated_approved_call_is_reevaluated() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(2) // one per execution, never one approval for two copies
        .mount(&server)
        .await;
    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    ); // webhook #1 (records deploy with count 1)

    // A later transform duplicates the approved call verbatim.
    let duplicated = json!({
        "id": "chatcmpl-1", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": Value::Null, "tool_calls": [
            { "id": "call_1", "type": "function", "function": { "name": "deploy", "arguments": "{\"env\":\"prod\"}" } },
            { "id": "call_2", "type": "function", "function": { "name": "deploy", "arguments": "{\"env\":\"prod\"}" } }
        ] }, "finish_reason": "tool_calls" }],
        "usage": { "prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2 }
    })
    .to_string()
    .into_bytes();
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &duplicated)
            .await,
    ); // first copy consumes the recorded count; second copy → webhook #2
    server.verify().await;
}

/// A backend 4xx/5xx JSON error body whose shape happens to contain
/// `choices[].message.tool_calls[]` is out of scope (non-2xx) and must NOT be
/// rewritten by the redaction transform: redaction is gated on the
/// governed-response marker, which is only recorded for 2xx governed bodies.
#[tokio::test]
async fn non_2xx_json_error_body_is_not_rewritten_by_transform() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "sk-[A-Za-z0-9]+" }]
            }
        }
    }));
    let body = response_with_tool_call("filesystem.write", "{\"token\":\"sk-ERRORSECRET123\"}");
    let mut ctx = create_test_context();
    // Backend error: `on_response_body` skips non-2xx and records no marker.
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 500, &mut json_headers(), &body)
            .await,
    );
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/json"),
                &json_headers()
            )
            .await.replaced_bytes()
            .is_none(),
        "non-2xx error body must not be silently modified"
    );
}

// ---------------------------------------------------------------------------
// Round 9 review fixes: legacy streaming function_call, framed gRPC requests,
// stream-router provider correlation
// ---------------------------------------------------------------------------

/// Frames for a legacy `functions`-API stream: one implicit call per choice as
/// `choices[].delta.function_call` `{name, arguments}` string deltas, with the
/// arguments split across frames.
fn legacy_function_call_stream(name_frames: &[&str], arg_frames: &[&str]) -> String {
    let mut body = String::from(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"}}]}\n\n",
    );
    for name in name_frames {
        body.push_str(&format!(
            "data: {}\n\n",
            json!({ "choices": [{ "index": 0, "delta": { "function_call": { "name": name, "arguments": "" } } }] })
        ));
    }
    for args in arg_frames {
        body.push_str(&format!(
            "data: {}\n\n",
            json!({ "choices": [{ "index": 0, "delta": { "function_call": { "arguments": args } } }] })
        ));
    }
    body.push_str(
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"function_call\"}]}\n\n",
    );
    body.push_str("data: [DONE]\n\n");
    body
}

/// A denied legacy `delta.function_call` stream is HELD and terminated in
/// enforce mode: the accumulated implicit call rides the same machinery as
/// `delta.tool_calls`, and none of the held frames leak.
#[tokio::test]
async fn streaming_legacy_function_call_deltas_are_held_and_denied() {
    let plugin = make(streaming_config(
        json!({ "rm_rf": { "action": "deny" } }),
        "allow",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    // Name and arguments split across frames: only the reassembled call matches.
    let body = legacy_function_call_stream(&["rm_", "rf"], &["{\"path\":\"/e", "tc\"}"]);
    let bytes = body.as_bytes();
    let (first, second) = bytes.split_at(bytes.len() / 2);
    let (out, terminated) = drive_stream(&mut inspector, &[first, second]).await;
    assert!(
        terminated,
        "denied legacy function call must cut the stream"
    );
    let text = String::from_utf8_lossy(&out);
    assert!(
        !text.contains("rm_"),
        "held function_call frame leaked: {text}"
    );
    assert!(!text.contains("/etc"), "held arguments leaked: {text}");
    // Clean content deltas released before the block still stream through.
    assert!(
        text.contains("\"content\":\"hi\""),
        "clean frame lost: {text}"
    );
    assert!(
        text.contains("ai_tool_governor_tool_blocked"),
        "terminal SSE error event missing: {text}"
    );
}

/// Dry-run releases the held legacy function-call frames unchanged.
#[tokio::test]
async fn streaming_legacy_function_call_released_in_dry_run() {
    let plugin = make(json!({
        "mode": "dry_run",
        "tools": { "rm_rf": { "action": "deny" } },
        "default_action": "allow",
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    let body = legacy_function_call_stream(&["rm_rf"], &["{\"path\":\"/etc\"}"]);
    let (out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(!terminated, "dry-run must never cut the stream");
    assert_eq!(
        out,
        body.as_bytes(),
        "dry-run must release every held frame"
    );
}

#[tokio::test]
async fn streamed_dry_run_decision_writes_transaction_metadata_at_termination() {
    let plugin = Arc::new(make(json!({
        "mode": "dry_run",
        "tools": { "rm_rf": { "action": "deny" } },
        "default_action": "allow",
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true },
        "observability": { "emit_metadata": true, "hash_arguments": true }
    })));
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let mut ctx = create_test_context();
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("stream inspector");
    assert_eq!(plugin.pending_stream_metadata_len(), 1);

    let body = legacy_function_call_stream(&["rm_rf"], &["{\"path\":\"/etc\"}"]);
    let (out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(!terminated, "dry-run must forward the stream");
    assert_eq!(out, body.as_bytes());
    drop(inspector);

    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(out.len() as u64))
        .await;
    assert_eq!(plugin.pending_stream_metadata_len(), 0);
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("deny")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.tool_names")
            .map(String::as_str),
        Some("rm_rf")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.arguments_hashes")
            .map(String::len),
        Some(64)
    );
    assert_no_metadata_contains(&ctx, "/etc");
}

#[tokio::test]
async fn streamed_metadata_honors_hash_arguments_false() {
    let plugin = Arc::new(make(json!({
        "mode": "dry_run",
        "tools": { "rm_rf": { "action": "deny" } },
        "default_action": "allow",
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true },
        "observability": { "emit_metadata": true, "hash_arguments": false }
    })));
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let mut ctx = create_test_context();
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("stream inspector");
    let body = legacy_function_call_stream(&["rm_rf"], &["{\"path\":\"/etc\"}"]);
    let (out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(!terminated);
    drop(inspector);

    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(out.len() as u64))
        .await;
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("deny")
    );
    assert!(
        !ctx.metadata
            .contains_key("ai_tool_governor.arguments_hashes")
    );
    assert_no_metadata_contains(&ctx, "/etc");
}

#[test]
fn ineligible_stream_creates_no_governor_writeback_slot() {
    let plugin = Arc::new(make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    })));
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let mut ctx = create_test_context();

    let inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 500, Some("text/event-stream"));
    assert!(inspector.is_none());
    assert_eq!(
        plugin.pending_stream_metadata_len(),
        0,
        "no inspector must mean no per-request write-back allocation"
    );
}

/// A legacy function call that never receives a `name` cannot be
/// policy-checked: enforce fails closed exactly like an unnamed
/// `delta.tool_calls` entry.
#[tokio::test]
async fn streaming_legacy_function_call_never_named_fails_closed() {
    let plugin = make(streaming_config(
        json!({ "safe": { "action": "allow" } }),
        "allow",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    let body = legacy_function_call_stream(&[], &["{\"path\":\"/etc\"}"]);
    let (out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(
        terminated,
        "a never-named legacy function call is ungovernable and must fail closed"
    );
    let text = String::from_utf8_lossy(&out);
    assert!(!text.contains("/etc"), "held arguments leaked: {text}");
}

/// Streaming `redact_args` cannot rewrite held frames in place, so a matched
/// pattern on a legacy function call fails closed like everywhere else.
#[tokio::test]
async fn streaming_legacy_function_call_redact_args_fails_closed() {
    let plugin = make(streaming_config(
        json!({
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "sk-[A-Za-z0-9]+" }]
            }
        }),
        "allow",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    let body = legacy_function_call_stream(
        &["filesystem.write"],
        &["{\"token\":\"sk-STREAM", "SECRET1\"}"],
    );
    let (out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(terminated, "streaming redact_args must fail closed");
    let text = String::from_utf8_lossy(&out);
    assert!(!text.contains("sk-STREAM"), "held secret leaked: {text}");
}

/// The buffered-SSE path shares the streaming accumulator, so a fully-buffered
/// `text/event-stream` body carrying legacy `delta.function_call` deltas is
/// governed too: denied calls reject, allowed calls forward.
#[tokio::test]
async fn buffered_sse_legacy_function_call_is_governed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut sse_headers = HashMap::new();
    sse_headers.insert("content-type".to_string(), "text/event-stream".to_string());

    let denied = legacy_function_call_stream(&["kubectl.apply"], &["{}"]);
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers, denied.as_bytes())
            .await,
        Some(403),
    );

    let allowed = legacy_function_call_stream(&["report.read"], &["{}"]);
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers, allowed.as_bytes())
            .await,
    );

    // A never-named buffered legacy call is ungovernable: fail closed.
    let unnamed = legacy_function_call_stream(&[], &["{}"]);
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers, unnamed.as_bytes())
            .await,
        Some(502),
    );
}

/// Framed gRPC / gRPC-Web request bodies (`application/grpc+json`,
/// `application/grpc-web+json`) are length-prefixed wire frames, not bare JSON:
/// they must be out of scope on every request-side gate — never buffered, never
/// fail-closed as unparseable — while genuine `+json` types stay governed.
#[tokio::test]
async fn framed_grpc_request_content_types_are_out_of_scope() {
    let plugin = make(mcp_config("enforce"));
    for ct in [
        "application/grpc",
        "application/grpc+json",
        "application/grpc-web+json",
        "application/grpc-web-text+proto",
    ] {
        // Buffering opt-in declines framed gRPC.
        let mut ctx = create_test_context();
        ctx.method = "POST".to_string();
        ctx.headers
            .insert("content-type".to_string(), ct.to_string());
        assert!(
            !plugin.should_buffer_request_body(&ctx),
            "framed gRPC request must not be buffered: {ct}"
        );

        // `before_proxy` treats it as out of scope even with an opaque body
        // another plugin buffered (previously: fail-closed as unparseable).
        ctx.metadata
            .insert("request_body_size_bytes".to_string(), "12".to_string());
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), ct.to_string());
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

        // The final-body re-check does not reject framed wire bytes either.
        let mut final_headers = HashMap::new();
        final_headers.insert("content-type".to_string(), ct.to_string());
        let framed: &[u8] = &[0, 0, 0, 0, 5, 1, 2, 3, 4, 5];
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &final_headers, framed)
                .await,
        );
    }

    // A genuine non-gRPC `+json` type is still in scope (buffered + governed).
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers.insert(
        "content-type".to_string(),
        "application/vnd.api+json".to_string(),
    );
    assert!(plugin.should_buffer_request_body(&ctx));
}

/// With `ai_stream_router`, the uniquely-configured provider name lives in
/// `ai_stream_router.provider`: two router providers of the same coarse type
/// must get DISTINCT approval decisions (and cache entries), keyed by that name.
#[tokio::test]
async fn streaming_approval_uses_stream_router_provider_name() {
    let server = MockServer::start().await;
    for provider in ["openai-primary", "openai-secondary"] {
        Mock::given(method("POST"))
            .and(path("/approve"))
            .and(body_string_contains(format!("\"provider\":\"{provider}\"")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
            .expect(1)
            .mount(&server)
            .await;
    }

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 300 },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));

    for provider in ["openai-primary", "openai-secondary"] {
        let mut ctx = create_test_context();
        // Same coarse type for both: without the router-provider precedence the
        // second call would reuse the first's cached decision.
        ctx.metadata
            .insert("ai_provider".to_string(), "openai".to_string());
        ctx.metadata.insert(
            "ai_stream_router.provider".to_string(),
            provider.to_string(),
        );
        let mut inspector = plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .expect("inspector");
        let tool_frame = json!({
            "model": "same-model",
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": { "name": "deploy", "arguments": "{\"env\":\"prod\"}" }
                    }]
                }
            }]
        });
        let finish_frame = json!({
            "model": "same-model",
            "choices": [{ "index": 0, "delta": {}, "finish_reason": "tool_calls" }]
        });
        let body = format!("data: {tool_frame}\n\ndata: {finish_frame}\n\ndata: [DONE]\n\n");
        let (_out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
        assert!(!terminated);
    }

    server.verify().await;
}

// ---------------------------------------------------------------------------
// Round 10 review fixes: SSE shape fallback, held-batch ordering, cache cap
// race, unnamed buffered calls, final-body model refresh
// ---------------------------------------------------------------------------

const SSE_DENIED_TOOL_BODY: &str = concat!(
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
    "\"function\":{\"name\":\"kubectl.apply\",\"arguments\":\"{}\"}}]}}]}\n\n",
    "data: [DONE]\n\n"
);

const SSE_ALLOWED_TOOL_BODY: &str = concat!(
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
    "\"function\":{\"name\":\"report.read\",\"arguments\":\"{}\"}}]}}]}\n\n",
    "data: [DONE]\n\n"
);

/// A buffered SSE body whose `Content-Type: text/event-stream` was OMITTED by
/// the upstream must still be governed: the body is SSE-shaped (`data:` first
/// line), not JSON-shaped, so without the shape fallback it would forward a
/// denied tool call uninspected.
#[tokio::test]
async fn buffered_sse_without_content_type_is_governed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));

    let mut no_ct: HashMap<String, String> = HashMap::new();
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut no_ct, SSE_DENIED_TOOL_BODY.as_bytes())
            .await,
        Some(403),
    );

    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut no_ct, SSE_ALLOWED_TOOL_BODY.as_bytes())
            .await,
    );
}

/// A `response_transformer` header rule that RELABELS `text/event-stream`
/// (e.g. to `text/plain`) must not skip buffered-SSE governance; the same
/// shape fallback applies on the final re-check.
#[tokio::test]
async fn buffered_sse_with_relabeled_content_type_is_governed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": true }
    }));
    let mut plain_headers = HashMap::new();
    plain_headers.insert("content-type".to_string(), "text/plain".to_string());

    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut plain_headers,
                SSE_DENIED_TOOL_BODY.as_bytes(),
            )
            .await,
        Some(403),
    );

    // Final re-check parity: a transform that rewrote the body into SSE (or
    // relabeled a governed SSE body) is re-governed on the final path too.
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &plain_headers,
                SSE_DENIED_TOOL_BODY.as_bytes(),
            )
            .await,
        Some(403),
    );
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &plain_headers,
                SSE_ALLOWED_TOOL_BODY.as_bytes(),
            )
            .await,
    );

    // A BOM/whitespace prefix must not defeat the shape detection.
    let mut bom_body = b"\xEF\xBB\xBF\n".to_vec();
    bom_body.extend_from_slice(SSE_DENIED_TOOL_BODY.as_bytes());
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut plain_headers, &bom_body)
            .await,
        Some(403),
    );
}

/// While a governed tool-call batch is HELD, later non-tool frames (another
/// choice's content) must be held too: an allowed multi-choice stream is
/// delivered in original arrival order, never reordered around the released
/// tool frames.
#[tokio::test]
async fn streaming_holds_non_tool_frames_behind_pending_batch_and_releases_in_order() {
    let plugin = make(streaming_config(
        json!({ "get_weather": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    let tool_frame = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"get_weather\",\"arguments\":\"{}\"}}]}}]}\n\n"
    );
    let content_after =
        "data: {\"choices\":[{\"index\":1,\"delta\":{\"content\":\"OTHER-CHOICE-TEXT\"}}]}\n\n";
    let finish_frame =
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n";
    let done = "data: [DONE]\n\n";

    // First chunk: tool frame + trailing content frame. Nothing may be
    // forwarded yet — the content frame arrived while the batch was pending.
    let first = format!("{tool_frame}{content_after}");
    let forwarded = match inspector.on_chunk(first.as_bytes()).await {
        ResponseStreamAction::Forward(bytes) => bytes,
        ResponseStreamAction::Terminate(_) => panic!("allowed batch must not terminate"),
    };
    assert!(
        forwarded.is_empty(),
        "content after a pending tool-call batch must be held, got: {}",
        String::from_utf8_lossy(&forwarded)
    );

    // Finish frame completes the batch: everything releases in arrival order.
    let rest = format!("{finish_frame}{done}");
    let (out, terminated) = drive_stream(&mut inspector, &[rest.as_bytes()]).await;
    assert!(!terminated);
    let mut full = forwarded.to_vec();
    full.extend_from_slice(&out);
    let expected = format!("{tool_frame}{content_after}{finish_frame}{done}");
    assert_eq!(
        String::from_utf8_lossy(&full),
        expected,
        "release must restore original arrival order"
    );
}

/// On a DENY, content frames that arrived after the held tool-call batch must
/// not leak ahead of (or after) the terminal error event.
#[tokio::test]
async fn streaming_denied_batch_does_not_leak_held_after_content() {
    let plugin = make(streaming_config(json!({}), "deny"));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"BEFORE-TOOLS\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"danger\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":1,\"delta\":{\"content\":\"AFTER-TOOLS-LEAK\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let (out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(terminated, "denied batch must cut the stream");
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("BEFORE-TOOLS"),
        "pre-batch content should have streamed: {text}"
    );
    assert!(
        !text.contains("AFTER-TOOLS-LEAK"),
        "content held behind a denied batch leaked: {text}"
    );
    assert!(!text.contains("danger"), "held tool frame leaked: {text}");
    assert!(
        text.contains("ai_tool_governor_tool_blocked"),
        "no terminal error event: {text}"
    );
}

/// The approval-cache entry cap must hold under CONCURRENT inserts: the
/// capacity check + eviction + insert path is serialized, so racing approval
/// resolutions cannot push the map past `MAX_APPROVAL_CACHE_ENTRIES`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn approval_cache_cap_holds_under_concurrent_inserts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .mount(&server)
        .await;

    let plugin = std::sync::Arc::new(make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": {
            "endpoint_url": format!("{}/approve", server.uri()),
            "cache_ttl_seconds": 300
        },
        "inspect": { "response_tool_calls": true }
    })));

    let max = AiToolGovernor::approval_cache_max_entries();
    let tasks = 16usize;
    // Enough distinct argument sets across all tasks to overshoot the cap.
    let per_task = max / tasks + 8;
    let mut handles = Vec::new();
    for task in 0..tasks {
        let plugin = std::sync::Arc::clone(&plugin);
        handles.push(tokio::spawn(async move {
            for i in 0..per_task {
                let args = format!("{{\"n\":{}}}", task * per_task + i);
                let body = response_with_tool_call("deploy", &args);
                let mut ctx = create_test_context();
                assert_continue(
                    plugin
                        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
                        .await,
                );
            }
        }));
    }
    for handle in handles {
        handle.await.expect("insert task");
    }

    let len = plugin.approval_cache_len();
    assert!(
        len <= max,
        "approval cache exceeded its cap under concurrent inserts: {len} > {max}"
    );
    assert_eq!(
        len, max,
        "cache should be exactly full after overshooting the cap with live entries"
    );
}

/// A buffered `tool_calls[]` whose entries ALL lack `function.name` must not
/// slide past policy as "no calls": enforce mode fails closed even under
/// `default_action: deny` with an empty extract.
#[tokio::test]
async fn buffered_all_unnamed_tool_calls_fail_closed_in_enforce() {
    let plugin = make(json!({
        "default_action": "deny",
        "inspect": { "response_tool_calls": true }
    }));
    let body = json!({
        "choices": [{
            "message": {
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": { "arguments": "{\"cmd\":\"rm -rf /\"}" }
                }]
            }
        }]
    })
    .to_string()
    .into_bytes();

    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(502),
    );

    // Final re-check parity: a transform that injects the unnamed call after
    // `on_response_body` cleared the original body fails closed too.
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
        Some(502),
    );
}

/// The same all-unnamed shape is forwarded in dry-run — observation must not
/// disrupt traffic (streaming parity).
#[tokio::test]
async fn buffered_all_unnamed_tool_calls_forward_in_dry_run() {
    let plugin = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "inspect": { "response_tool_calls": true }
    }));
    let body = json!({
        "choices": [{
            "message": {
                "tool_calls": [{
                    "id": "call_1",
                    "function": { "arguments": "{}" }
                }]
            }
        }]
    })
    .to_string()
    .into_bytes();

    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    );
}

/// A `null` `tool_calls` / `function_call` is OpenAI's documented content-only
/// shape and must NOT trip the ungovernable fail-closed path.
#[tokio::test]
async fn buffered_null_tool_calls_are_not_ungovernable() {
    let plugin = make(json!({
        "default_action": "deny",
        "inspect": { "response_tool_calls": true }
    }));
    let body = json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "hello",
                "tool_calls": Value::Null,
                "function_call": Value::Null
            }
        }]
    })
    .to_string()
    .into_bytes();
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
}

/// A `request_transformer` that changes `model` after `before_proxy` marked the
/// request streaming must refresh the recorded stream model: the stream
/// inspector seeds correlation from it, and the approval webhook must key on
/// the BACKEND-VISIBLE model, not the stale pre-transform one.
#[tokio::test]
async fn final_request_body_refreshes_stream_model_for_approval() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .and(body_string_contains("\"model\":\"model-b\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()) },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));

    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({ "stream": true, "model": "model-a", "messages": [] }).to_string(),
    );
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.stream_model")
            .map(String::as_str),
        Some("model-a"),
        "before_proxy records the original model"
    );

    // The transformer changed the model; the request is ALREADY marked
    // streaming, and the final-body re-check must still refresh the model.
    let final_body = json!({ "stream": true, "model": "model-b", "messages": [] }).to_string();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), final_body.as_bytes())
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.stream_model")
            .map(String::as_str),
        Some("model-b"),
        "final request body must refresh the stream model"
    );

    // The stream inspector's approval call keys on the refreshed model even
    // though the SSE frames carry no model of their own.
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"deploy\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let (_out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(!terminated, "approved call must not cut the stream");
    server.verify().await;
}

// ---------------------------------------------------------------------------
// Round 11 review fixes: encoded buffered SSE, undecodable relabeled encoded
// bodies, mislabeled JSON under an SSE label, keepalive-prefixed SSE, buffered
// SSE approval identity/correlation
// ---------------------------------------------------------------------------

fn sse_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/event-stream".to_string());
    headers
}

/// An SSE-labeled buffered body carrying `Content-Encoding: gzip` must be
/// DECODED before buffered-SSE governance: feeding compressed bytes into the
/// extractor would find zero calls and record the compressed hash, letting the
/// final re-check hash-skip denied deltas.
#[tokio::test]
async fn buffered_sse_gzip_encoded_denied_call_is_caught() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut headers = sse_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut headers,
                &gzip(SSE_DENIED_TOOL_BODY.as_bytes()),
            )
            .await,
        Some(403),
    );

    // Allowed calls decode and forward.
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut headers,
                &gzip(SSE_ALLOWED_TOOL_BODY.as_bytes()),
            )
            .await,
    );
}

/// An SSE-labeled buffered body with an encoding the governor cannot decode
/// fails closed in enforce mode and forwards in dry-run (round-8 undecodable
/// semantics).
#[tokio::test]
async fn buffered_sse_undecodable_encoding_fails_closed_enforce_only() {
    let mut headers = sse_headers();
    headers.insert("content-encoding".to_string(), "zstd".to_string());
    let opaque = b"\x28\xb5\x2f\xfdopaque-zstd-bytes";

    let enforce = make(json!({
        "default_action": "deny",
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = create_test_context();
    assert_reject(
        enforce
            .on_response_body(&mut ctx, 200, &mut headers, opaque)
            .await,
        Some(502),
    );

    let dry_run = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = create_test_context();
    assert_continue(
        dry_run
            .on_response_body(&mut ctx, 200, &mut headers, opaque)
            .await,
    );
}

/// Final re-check: an encoded governed 2xx that cannot be decoded for
/// inspection fails closed in enforce mode even when its `Content-Type` was
/// relabeled away from JSON (header-time buffering already treated that label
/// as governable) — and forwards in dry-run. Framed gRPC stays out of scope,
/// and a successfully-decoded non-JSON-shaped body still forwards.
#[tokio::test]
async fn final_response_undecodable_encoded_relabeled_body_fails_closed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));

    // Unsupported encoding + relabeled content type.
    let mut zstd_headers = HashMap::new();
    zstd_headers.insert("content-type".to_string(), "text/plain".to_string());
    zstd_headers.insert("content-encoding".to_string(), "zstd".to_string());
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &zstd_headers, b"\x28\xb5\x2f\xfdopaque")
            .await,
        Some(502),
    );

    // Corrupt gzip with a MISSING content type.
    let mut gz_headers = HashMap::new();
    gz_headers.insert("content-encoding".to_string(), "gzip".to_string());
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &gz_headers, b"\x1f\x8b\x08corrupt")
            .await,
        Some(502),
    );

    // Framed gRPC wire frames are out of this plugin's scope even when encoded.
    let mut grpc_headers = HashMap::new();
    grpc_headers.insert("content-type".to_string(), "application/grpc".to_string());
    grpc_headers.insert("content-encoding".to_string(), "zstd".to_string());
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &grpc_headers, b"\x28\xb5\x2f\xfdframe")
            .await,
    );

    // A successfully-decoded non-JSON-shaped body still forwards.
    let mut html_headers = HashMap::new();
    html_headers.insert("content-type".to_string(), "text/html".to_string());
    html_headers.insert("content-encoding".to_string(), "gzip".to_string());
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &html_headers, &gzip(b"<html>ok</html>"))
            .await,
    );

    // Dry-run forwards the undecodable body instead of rejecting.
    let dry_run = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    assert_continue(
        dry_run
            .on_final_response_body(&mut ctx, 200, &zstd_headers, b"\x28\xb5\x2f\xfdopaque")
            .await,
    );
}

/// With streaming inspection DISABLED (no inspector will attach), an SSE label
/// stays buffered and a Chat Completions JSON body relabeled
/// `text/event-stream` is caught by the JSON-shape fallback instead of
/// streaming past `on_response_body` ungoverned.
#[tokio::test]
async fn sse_labeled_json_body_with_streaming_disabled_is_buffered_and_governed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));

    // Fix: the SSE label is no longer released when no inspector exists.
    let ctx = create_test_context();
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));

    let denied = response_with_tool_call("kubectl.apply", "{}");
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers(), &denied)
            .await,
        Some(403),
    );

    let allowed = response_with_tool_call("report.read", "{}");
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers(), &allowed)
            .await,
    );
}

/// With streaming inspection ENABLED and the inspector attached, a JSON-shaped
/// stream (mislabeled Chat Completions JSON under an SSE label) is held and
/// governed at end-of-stream: a denied call is never leaked, an allowed body
/// is released byte-for-byte.
#[tokio::test]
async fn streaming_inspector_governs_json_shaped_stream() {
    let plugin = make(streaming_config(
        json!({ "report.read": { "action": "allow" } }),
        "deny",
    ));

    // Denied: split the JSON body across chunks; nothing may be forwarded.
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let denied = response_with_tool_call("kubectl.apply", "{\"target\":\"prod\"}");
    let (first, rest) = denied.split_at(denied.len() / 2);
    let (out, terminated) = drive_stream(&mut inspector, &[first, rest]).await;
    assert!(terminated, "denied JSON-shaped stream must be cut");
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        !out_str.contains("kubectl.apply"),
        "denied call leaked: {out_str}"
    );

    // Allowed: the held body is released unchanged at end-of-stream.
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let allowed = response_with_tool_call("report.read", "{}");
    let (first, rest) = allowed.split_at(allowed.len() / 2);
    let (out, terminated) = drive_stream(&mut inspector, &[first, rest]).await;
    assert!(!terminated, "allowed JSON-shaped stream must not be cut");
    assert_eq!(out, allowed, "allowed body must be released unchanged");
}

/// A `: ping` keepalive/comment prefix is a standard SSE prelude: the shape
/// fallback must still classify the body as SSE and govern its tool calls.
#[tokio::test]
async fn keepalive_prefixed_sse_body_is_governed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut no_ct: HashMap<String, String> = HashMap::new();

    let denied = format!(": ping\n\n{SSE_DENIED_TOOL_BODY}");
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut no_ct, denied.as_bytes())
            .await,
        Some(403),
    );

    let allowed = format!(": ping\n\n{SSE_ALLOWED_TOOL_BODY}");
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut no_ct, allowed.as_bytes())
            .await,
    );
}

/// A benign post-approval transform of a buffered SSE body (an appended
/// keepalive comment: hash changes, call identities do not) must NOT re-fire
/// the approval webhook for the unchanged approved call — with
/// `cache_ttl_seconds: 0` a re-fire could deny a one-shot approval.
#[tokio::test]
async fn buffered_sse_benign_transform_does_not_refire_approval() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));

    let body = concat!(
        "data: {\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"deploy\",\"arguments\":\"{\\\"env\\\":\\\"prod\\\"}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
            .await,
    ); // webhook #1 (approved)

    // A later transform appends only a keepalive comment; the governed call
    // identities are unchanged, so the final re-check must skip one-for-one.
    let transformed = format!("{body}: keepalive\n\n");
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &sse_headers(), transformed.as_bytes())
            .await,
    );
    server.verify().await;
}

/// Buffered-SSE approval correlation extracts the model the SSE FRAMES report
/// when request metadata is absent (parity with the live inspector), so a
/// decision for one model is never reused for another and the webhook payload
/// carries the served model.
#[tokio::test]
async fn buffered_sse_frame_model_keys_distinct_approvals() {
    let server = MockServer::start().await;
    for model in ["gpt-4o", "gpt-5"] {
        Mock::given(method("POST"))
            .and(path("/approve"))
            .and(body_string_contains(format!("\"model\":\"{model}\"")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
            .expect(1)
            .mount(&server)
            .await;
    }
    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 300 },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));

    for model in ["gpt-4o", "gpt-5"] {
        let frame = json!({
            "model": model,
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": { "name": "deploy", "arguments": "{\"env\":\"prod\"}" }
                    }]
                }
            }]
        });
        let body = format!("data: {frame}\n\ndata: [DONE]\n\n");
        // No stream-model metadata: the frame-reported model must be used.
        let mut ctx = create_test_context();
        assert_continue(
            plugin
                .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
                .await,
        );
    }
    server.verify().await;
}

// ---------------------------------------------------------------------------
// Round 12 review fixes: encoded SSE stays buffered under streaming configs,
// opaque stream shape fails closed, buffered multi-batch reset, BOM-prefixed
// SSE parsing
// ---------------------------------------------------------------------------

/// With streaming inspection ENABLED, an SSE label that carries a
/// `Content-Encoding` must stay BUFFERED: the live inspector reads the raw
/// (still-encoded) byte stream where compressed bytes parse as zero SSE
/// events, so releasing it would forward denied tool calls ungoverned. The
/// buffered path then decodes and governs (round-11 semantics), end to end.
#[tokio::test]
async fn encoded_sse_with_streaming_enabled_stays_buffered_and_is_governed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut streaming_ctx = create_test_context();
    streaming_ctx
        .metadata
        .insert("ai_request_streaming".to_string(), "true".to_string());

    // Plain SSE label: released to the live inspector.
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &streaming_ctx,
        Some("text/event-stream"),
        200,
        &sse_headers()
    ));
    // Encoded SSE label: kept buffered so decode-then-govern runs.
    let mut encoded_headers = sse_headers();
    encoded_headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert!(plugin.should_buffer_response_body_for_content_type(
        &streaming_ctx,
        Some("text/event-stream"),
        200,
        &encoded_headers
    ));
    // `identity` is not an encoding: still released.
    let mut identity_headers = sse_headers();
    identity_headers.insert("content-encoding".to_string(), "identity".to_string());
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &streaming_ctx,
        Some("text/event-stream"),
        200,
        &identity_headers
    ));

    // End to end on the buffered path the hook now selects: denied call in a
    // gzip'd SSE body rejects; allowed call forwards.
    let mut ctx = create_test_context();
    ctx.metadata
        .insert("ai_request_streaming".to_string(), "true".to_string());
    assert_reject(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut encoded_headers,
                &gzip(SSE_DENIED_TOOL_BODY.as_bytes()),
            )
            .await,
        Some(403),
    );
    let mut ctx = create_test_context();
    ctx.metadata
        .insert("ai_request_streaming".to_string(), "true".to_string());
    assert_continue(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut encoded_headers,
                &gzip(SSE_ALLOWED_TOOL_BODY.as_bytes()),
            )
            .await,
    );
}

/// Defense in depth for the live inspector: a stream whose leading bytes are
/// neither SSE-shaped nor JSON-shaped (e.g. gzip bytes whose
/// `Content-Encoding` header a transform stripped) is opaque — it must be
/// held in full and cut at end-of-stream in enforce mode rather than parsed
/// as zero SSE events and forwarded ungoverned. Dry-run releases it
/// unchanged.
#[tokio::test]
async fn opaque_stream_is_held_and_fails_closed_in_enforce() {
    let compressed = gzip(SSE_DENIED_TOOL_BODY.as_bytes());
    let (first, second) = compressed.split_at(2); // gzip magic alone resolves the sniff

    let enforce = make(streaming_config(
        json!({ "report.read": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = enforce
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[first, second]).await;
    assert!(terminated, "opaque stream must be cut in enforce mode");
    assert!(
        !out.windows(2).any(|w| w == [0x1f, 0x8b]),
        "held opaque bytes leaked"
    );
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("ai_tool_governor_tool_blocked"),
        "no terminal error event: {text}"
    );

    // Dry-run: held until end-of-stream, then released byte-for-byte.
    let dry_run = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let ctx = create_test_context();
    let mut inspector = dry_run
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[first, second]).await;
    assert!(!terminated, "dry-run must not cut an opaque stream");
    assert_eq!(out, compressed, "dry-run must release the bytes unchanged");
}

/// Two sequential tool-call batches in a buffered SSE body (same choice and
/// tool indices, separated by a `finish_reason` boundary) must be governed as
/// SEPARATE batches under their true names — without the batch reset the
/// accumulator concatenates them (`safe` + `danger` -> `safedanger`) and a
/// denied second call slides past `default_action: allow`.
#[tokio::test]
async fn buffered_multi_batch_sse_governs_second_batch_under_true_name() {
    let plugin = make(json!({
        "default_action": "allow",
        "tools": { "danger": { "action": "deny" } }
    }));
    let two_batches = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"safe\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c2\",",
        "\"function\":{\"name\":\"danger\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers(), two_batches.as_bytes())
            .await,
        Some(403),
    );

    // Both batches allowed: forwarded, and each batch's call kept its true
    // name (a concatenated `safesafe2` would be denied by an exact-name-only
    // allowlist under default deny).
    let strict = make(json!({
        "default_action": "deny",
        "tools": { "safe": { "action": "allow" }, "safe2": { "action": "allow" } }
    }));
    let allowed_batches = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"safe\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c2\",",
        "\"function\":{\"name\":\"safe2\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut ctx = create_test_context();
    assert_continue(
        strict
            .on_response_body(
                &mut ctx,
                200,
                &mut sse_headers(),
                allowed_batches.as_bytes(),
            )
            .await,
    );

    // `[DONE]` alone (no finish_reason) is also a batch boundary.
    let done_separated = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"safe\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: [DONE]\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c2\",",
        "\"function\":{\"name\":\"danger\",\"arguments\":\"{}\"}}]}}]}\n\n"
    );
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers(), done_separated.as_bytes())
            .await,
        Some(403),
    );
}

/// A UTF-8 BOM at the very start of an SSE body makes the first line
/// `\u{feff}data: ...`; the parser must strip it so the FIRST event's denied
/// call is not classified NoData and forwarded — on both the live streaming
/// path and the buffered fallback.
#[tokio::test]
async fn bom_prefixed_sse_denied_call_is_caught_on_both_paths() {
    let mut bom_body = b"\xEF\xBB\xBF".to_vec();
    bom_body.extend_from_slice(SSE_DENIED_TOOL_BODY.as_bytes());

    // Live streaming path.
    let plugin = make(streaming_config(
        json!({ "report.read": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[&bom_body]).await;
    assert!(terminated, "BOM-prefixed denied call must cut the stream");
    let text = String::from_utf8_lossy(&out);
    assert!(!text.contains("kubectl.apply"), "held frame leaked: {text}");

    // Live path, allowed call: the BOM must not break release either.
    let mut bom_allowed = b"\xEF\xBB\xBF".to_vec();
    bom_allowed.extend_from_slice(SSE_ALLOWED_TOOL_BODY.as_bytes());
    let allow_plugin = make(streaming_config(
        json!({ "report.read": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = allow_plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[&bom_allowed]).await;
    assert!(!terminated, "allowed BOM-prefixed stream must not be cut");
    assert_eq!(out, bom_allowed, "released bytes must be unchanged");

    // Buffered fallback (streaming inspection disabled: SSE label buffered).
    let buffered = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    assert_reject(
        buffered
            .on_response_body(&mut ctx, 200, &mut sse_headers(), &bom_body)
            .await,
        Some(403),
    );
    let mut ctx = create_test_context();
    assert_continue(
        buffered
            .on_response_body(&mut ctx, 200, &mut sse_headers(), &bom_allowed)
            .await,
    );
}

// ---------------------------------------------------------------------------
// Round 13 review fixes: decode-first for encoded buffered JSON, buffered
// invalid-UTF-8 SSE fails closed, unknown-field SSE preludes are not opaque
// ---------------------------------------------------------------------------

/// A perfectly valid upstream-compressed `application/json` Chat Completions
/// response must be DECODED and governed, not rejected as uninspectable
/// before the decode is even tried: allowed calls forward, denied calls
/// reject, dry-run forwards.
#[tokio::test]
async fn buffered_json_gzip_encoded_body_is_decoded_and_governed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    // Allowed call: decoded, governed, forwarded — no false 502.
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut headers,
                &gzip(&response_with_tool_call("report.read", "{}")),
            )
            .await,
    );

    // Denied call inside the compressed body still rejects.
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut headers,
                &gzip(&response_with_tool_call("kubectl.apply", "{}")),
            )
            .await,
        Some(403),
    );

    // Dry-run is unaffected either way.
    let dry_run = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    assert_continue(
        dry_run
            .on_response_body(
                &mut ctx,
                200,
                &mut headers,
                &gzip(&response_with_tool_call("kubectl.apply", "{}")),
            )
            .await,
    );
}

/// The decoded-governed encoded JSON body records the DECODED hash, so the
/// final re-check's own decode hash-skips the unchanged body instead of
/// re-firing the approval webhook (a one-shot approval service could deny the
/// duplicate and turn an approved response into a 502).
#[tokio::test]
async fn buffered_json_gzip_encoded_governed_hash_skips_final_recheck() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 }
    }));
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    let compressed = gzip(&response_with_tool_call("deploy", "{\"env\":\"prod\"}"));

    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &compressed)
            .await,
    ); // webhook #1 (approved)

    // Unchanged compressed body at the final re-check: decoded hash matches
    // the one recorded by the decode-first governance pass — skipped.
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &compressed)
            .await,
    );
    server.verify().await;
}

/// An encoded body cannot be rewritten by the in-place redaction transform
/// (it sees the still-encoded bytes), so a `redact_args` match inside a
/// decoded-governed gzip'd JSON body keeps the redaction-unavailable
/// fail-closed semantics rather than forwarding the matched secret.
#[tokio::test]
async fn buffered_json_gzip_encoded_redact_args_match_fails_closed() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "sk-[A-Za-z0-9]+" }]
            }
        }
    }));
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    let body = response_with_tool_call("filesystem.write", "{\"token\":\"sk-GZSECRET1\"}");

    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &gzip(&body))
            .await,
        Some(502),
    );
    assert_no_metadata_contains(&ctx, "sk-GZSECRET1");
}

/// An SSE-labeled buffered body WITHOUT a `Content-Encoding` whose bytes are
/// invalid UTF-8 (opaque/binary — e.g. a transform stripped the encoding
/// header) is ungovernable: zero extractable frames must not slide past
/// `default_action: deny` as `calls.is_empty()`. Fail closed in enforce,
/// forward in dry-run (opaque parity with the live inspector).
#[tokio::test]
async fn buffered_sse_labeled_invalid_utf8_fails_closed_enforce_only() {
    // Compressed-looking bytes with no encoding header: not valid UTF-8.
    let opaque = b"\x1f\x8b\x08\x00binary-without-encoding-header\xff\xfe";

    let enforce = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    assert_reject(
        enforce
            .on_response_body(&mut ctx, 200, &mut sse_headers(), opaque)
            .await,
        Some(502),
    );

    let dry_run = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    assert_continue(
        dry_run
            .on_response_body(&mut ctx, 200, &mut sse_headers(), opaque)
            .await,
    );
}

/// A legit SSE stream opening with an extension/heartbeat field line
/// (`ping: 1`) is valid SSE per spec (unknown field names are ignored) and
/// must be governed as SSE — not misclassified opaque, held in full, and
/// terminated at EOF: denied tool calls are still cut (with the live prelude
/// already forwarded), allowed streams pass through byte-for-byte.
#[tokio::test]
async fn ping_field_prefixed_sse_stream_is_governed_not_opaque() {
    let plugin = make(streaming_config(
        json!({ "report.read": { "action": "allow" } }),
        "deny",
    ));

    // Denied call after the ping prelude: governed (cut at the batch, prelude
    // forwarded live — an opaque hold would have swallowed it).
    let denied = format!("ping: 1\n\n{SSE_DENIED_TOOL_BODY}");
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[denied.as_bytes()]).await;
    assert!(terminated, "denied call must still cut the stream");
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("ping: 1"),
        "SSE prelude must be forwarded live, not opaque-held: {text}"
    );
    assert!(
        !text.contains("kubectl.apply"),
        "denied call leaked: {text}"
    );

    // Allowed call: the whole stream (prelude included) passes through.
    let allowed = format!("ping: 1\n\n{SSE_ALLOWED_TOOL_BODY}");
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[allowed.as_bytes()]).await;
    assert!(!terminated, "allowed ping-prefixed stream must not be cut");
    assert_eq!(
        out,
        allowed.as_bytes(),
        "stream must pass through unchanged"
    );
}

/// The widened SSE-shape check still treats genuinely binary starts (control
/// bytes) as opaque: held in full and cut at end-of-stream in enforce mode.
#[tokio::test]
async fn binary_starts_remain_opaque_cut() {
    let body = format!("\x01\x02binary{SSE_DENIED_TOOL_BODY}").into_bytes();
    let plugin = make(streaming_config(
        json!({ "report.read": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[&body]).await;
    assert!(terminated, "opaque stream must be cut in enforce mode");
    let text = String::from_utf8_lossy(&out);
    assert!(!text.contains("kubectl.apply"), "held bytes leaked: {text}");
}

/// `looks_like_sse` (the buffered fallback) agrees with the widened live
/// sniff: an unlabeled buffered SSE body opening with a `ping: 1` extension
/// field is still routed through buffered-SSE governance.
#[tokio::test]
async fn ping_field_prefixed_unlabeled_buffered_sse_is_governed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut no_ct: HashMap<String, String> = HashMap::new();

    let denied = format!("ping: 1\n\n{SSE_DENIED_TOOL_BODY}");
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut no_ct, denied.as_bytes())
            .await,
        Some(403),
    );

    let allowed = format!("ping: 1\n\n{SSE_ALLOWED_TOOL_BODY}");
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut no_ct, allowed.as_bytes())
            .await,
    );
}

/// A colonless line is a valid SSE field with an empty value. An unknown
/// colonless extension field must therefore be skipped while sniffing rather
/// than making a missing/relabelled Content-Type bypass buffered governance.
#[tokio::test]
async fn colonless_prefixed_unlabeled_buffered_sse_is_governed() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let denied = format!("x\n\n{SSE_DENIED_TOOL_BODY}");
    let allowed = format!("x\n\n{SSE_ALLOWED_TOOL_BODY}");

    // The live classifier shares the same shape detector. An allowed call
    // distinguishes SSE classification from the enforce-mode opaque cutoff.
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[allowed.as_bytes()]).await;
    assert!(!terminated, "valid colonless-prefixed SSE must not be cut");
    assert_eq!(out, allowed.as_bytes());

    for mut headers in [
        HashMap::new(),
        HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
    ] {
        let mut ctx = create_test_context();
        assert_reject(
            plugin
                .on_response_body(&mut ctx, 200, &mut headers, denied.as_bytes())
                .await,
            Some(403),
        );

        let mut ctx = create_test_context();
        assert_continue(
            plugin
                .on_response_body(&mut ctx, 200, &mut headers, allowed.as_bytes())
                .await,
        );
    }
}

// ---------------------------------------------------------------------------
// Round 18 fix (finding 2): the SSE-shape acceptance (live sniff + buffered
// fallback) requires the prefix line UP TO the first `:` to be ASCII. A
// first line with a HIGH-BIT (invalid-UTF-8/binary) byte BEFORE a colon is now
// OPAQUE, not SSE — a `Content-Encoding`-stripped compressed/binary stream that
// happens to carry a `:` early no longer passes uninspected in enforce.
// ---------------------------------------------------------------------------

/// Live inspector: a first line with a high-bit non-ASCII byte before a colon
/// (invalid UTF-8) must be classified opaque and held/cut in enforce, NOT
/// forwarded as an `Sse`-shaped stream whose "events" parse as `NoData`. Before
/// the fix, `sniff_stream_shape` let bytes >=0x80 fall through as "text" and
/// returned `Sse` on the first colon, so the denied call rode the stream
/// uninspected.
#[tokio::test]
async fn high_bit_colon_prefix_stream_is_opaque_cut_in_enforce() {
    // Leading high-bit bytes (0xFF/0xFE — the UTF-16 BOM / gzip-adjacent binary)
    // then a colon before any newline: NOT valid SSE, must be opaque.
    let mut body: Vec<u8> = vec![0xFF, 0xFE, b'x', b':', b' ', b'1', b'\n', b'\n'];
    body.extend_from_slice(SSE_DENIED_TOOL_BODY.as_bytes());

    let enforce = make(streaming_config(
        json!({ "report.read": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = enforce
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[&body]).await;
    assert!(
        terminated,
        "high-bit colon-prefix stream must be cut (opaque) in enforce mode"
    );
    let text = String::from_utf8_lossy(&out);
    assert!(!text.contains("kubectl.apply"), "held bytes leaked: {text}");

    // Dry-run releases the same bytes unchanged (observation never disrupts).
    let dry_run = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let ctx = create_test_context();
    let mut inspector = dry_run
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[&body]).await;
    assert!(!terminated, "dry-run must not cut an opaque stream");
    assert_eq!(out, body, "dry-run must release the bytes unchanged");
}

/// Buffered fallback: `looks_like_sse` must agree with the live sniff — an
/// SSE-labeled buffered body whose first line carries a high-bit byte before a
/// colon is NOT SSE-shaped, so it is treated as ungovernable (not valid UTF-8)
/// and fails closed in enforce / forwards in dry-run rather than routing through
/// the SSE extractor as zero frames.
#[tokio::test]
async fn high_bit_colon_prefix_buffered_body_fails_closed_enforce_only() {
    let mut body: Vec<u8> = vec![0xC0, 0x80, b'a', b':', b' ', b'1', b'\n', b'\n'];
    body.extend_from_slice(SSE_DENIED_TOOL_BODY.as_bytes());

    let enforce = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    assert_reject(
        enforce
            .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
            .await,
        Some(502),
    );
    assert_no_metadata_contains(&ctx, "kubectl.apply");

    let dry_run = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    assert_continue(
        dry_run
            .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
            .await,
    );
}

/// Regression guard: the tightening must NOT reject legitimate ASCII SSE
/// preludes. A `: ka` comment keepalive and a `ping: 1` extension field (both
/// pure ASCII before the colon) still classify as SSE and govern their tool
/// calls, live and buffered.
#[tokio::test]
async fn ascii_keepalive_and_ping_prefixes_still_sse_after_high_bit_tightening() {
    let plugin = make(streaming_config(
        json!({ "report.read": { "action": "allow" } }),
        "deny",
    ));
    let mut no_ct: HashMap<String, String> = HashMap::new();

    for prelude in [": ka", "ping: 1"] {
        // Live inspector: an allowed call after the ASCII prelude passes through
        // (opaque would have cut/held it).
        let allowed = format!("{prelude}\n\n{SSE_ALLOWED_TOOL_BODY}");
        let ctx = create_test_context();
        let mut inspector = plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .expect("inspector");
        let (out, terminated) = drive_stream(&mut inspector, &[allowed.as_bytes()]).await;
        assert!(!terminated, "ASCII `{prelude}` stream must not be cut");
        assert_eq!(out, allowed.as_bytes(), "`{prelude}` stream altered");

        // Live inspector: a denied call after the ASCII prelude IS governed.
        let denied = format!("{prelude}\n\n{SSE_DENIED_TOOL_BODY}");
        let ctx = create_test_context();
        let mut inspector = plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .expect("inspector");
        let (out, terminated) = drive_stream(&mut inspector, &[denied.as_bytes()]).await;
        assert!(terminated, "denied call after `{prelude}` must cut");
        let text = String::from_utf8_lossy(&out);
        assert!(
            !text.contains("kubectl.apply"),
            "`{prelude}` leaked: {text}"
        );

        // Buffered fallback: same denied body under no content type is governed.
        let mut ctx = create_test_context();
        assert_reject(
            plugin
                .on_response_body(&mut ctx, 200, &mut no_ct, denied.as_bytes())
                .await,
            Some(403),
        );
    }
}

// ---------------------------------------------------------------------------
// Round 18 fix (finding 4): the plugin's internal correlation markers (the
// governed-body hashes and the per-call identity multiset, both derived from
// raw tool arguments) live on non-serialized `RequestContext` fields, NOT in
// `ctx.metadata`, so they never reach transaction logs — even with
// `hash_arguments: false` — while the plugin's own re-check dedup still works.
// ---------------------------------------------------------------------------

/// With `observability.hash_arguments: false`, a governed response with tool
/// calls must NOT put `governed_call_hashes` / `governed_response_hash` (or any
/// raw-argument-derived value) into logged metadata — and the plugin's own
/// final re-check must still hash-skip the unchanged body (no duplicate
/// approval webhook).
#[tokio::test]
async fn governed_markers_absent_from_metadata_when_hash_arguments_disabled() {
    let server = MockServer::start().await;
    // Exactly ONE approval call: the re-check must dedup the unchanged body.
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 },
        "observability": { "emit_metadata": true, "hash_arguments": false }
    }));
    let mut ctx = create_test_context();
    // A distinctive raw-argument secret whose hash would be correlatable.
    let body = response_with_tool_call("deploy", "{\"token\":\"sk-CORRELATABLE-SECRET-123\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );

    // No internal correlation markers in metadata (they moved to non-serialized
    // request fields), and no raw-argument-derived value of any kind.
    assert!(
        !ctx.metadata
            .contains_key("ai_tool_governor.governed_call_hashes"),
        "governed_call_hashes leaked into metadata: {:?}",
        ctx.metadata
    );
    assert!(
        !ctx.metadata
            .contains_key("ai_tool_governor.governed_response_hash"),
        "governed_response_hash leaked into metadata: {:?}",
        ctx.metadata
    );
    // Any key whose name mentions a governed-hash marker is a leak.
    for key in ctx.metadata.keys() {
        assert!(
            !(key.contains("governed_response_hash") || key.contains("governed_call_hashes")),
            "internal marker key leaked into metadata: {key}"
        );
    }
    // `hash_arguments: false` also means no per-call argument hashes are emitted.
    assert!(
        !ctx.metadata
            .contains_key("ai_tool_governor.arguments_hashes"),
        "arguments_hashes emitted despite hash_arguments: false"
    );
    // The raw secret must never appear anywhere in metadata.
    assert_no_metadata_contains(&ctx, "sk-CORRELATABLE-SECRET-123");

    // Dedup still works: the unchanged final body must NOT re-fire the webhook.
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    );
    server.verify().await;
}

/// The governed-request marker (a hash over the raw request body) is likewise
/// off metadata, so a governed request never leaks it — and the final-request
/// re-check still dedups the unchanged body.
#[tokio::test]
async fn governed_request_marker_absent_from_metadata_and_dedups() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = make(json!({
        "default_action": "require_approval",
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false },
        "observability": { "emit_metadata": true, "hash_arguments": false }
    }));
    let mut ctx = json_post_ctx();
    let call = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "deploy", "arguments": { "token": "sk-REQSECRET-456" } }
    })
    .to_string();
    ctx.metadata
        .insert("request_body".to_string(), call.clone());
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    for key in ctx.metadata.keys() {
        assert!(
            !key.contains("governed_request_hash"),
            "governed_request_hash leaked into metadata: {key}"
        );
    }
    // No raw-argument-derived value in any key this plugin WROTE. (`request_body`
    // is the test's own input, not a plugin-written key, and the proxy strips it
    // from log metadata before serialization — so it is excluded here.)
    for (key, value) in &ctx.metadata {
        if key == "request_body" {
            continue;
        }
        assert!(
            !value.contains("sk-REQSECRET-456"),
            "raw request-arg secret leaked in metadata key {key}: {value}"
        );
    }

    // Unchanged final request body: the re-check must hash-skip (no 2nd webhook).
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), call.as_bytes())
            .await,
    );
    server.verify().await;
}

// ---------------------------------------------------------------------------
// Round 14 review fixes: stream-marked JSON-fallback inspector attach,
// EOF-unresolved non-UTF-8 opaque semantics, CR/CRLF SSE line terminators,
// encoded wire-size cap, framed-gRPC buffered-hook exclusion
// ---------------------------------------------------------------------------

/// A `request_transformer` can add `"stream": true` AFTER the proxy's
/// buffer/dispatch decisions, so the backend's plain `application/json` SSE
/// fallback rides the STREAMING path where the buffered hooks never run. The
/// inspector must therefore attach for a stream-marked governed request
/// regardless of the response content type: the shape sniff holds a
/// JSON-shaped stream and governs it at EOF (denied cut, allowed released),
/// and a real SSE body still gets normal streaming governance. Non-marked
/// requests and framed gRPC labels never get an inspector.
#[tokio::test]
async fn stream_marked_json_fallback_is_governed_via_inspector() {
    let plugin = make(streaming_config(
        json!({ "report.read": { "action": "allow" } }),
        "deny",
    ));
    let mut ctx = create_test_context();
    ctx.metadata.insert(
        "ai_tool_governor.stream_requested".to_string(),
        "true".to_string(),
    );

    // Denied JSON fallback: held in full, cut at EOF, nothing leaked.
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("application/json"))
        .expect("inspector must attach for a stream-marked request");
    let denied = response_with_tool_call("kubectl.apply", "{}");
    let (first, rest) = denied.split_at(denied.len() / 2);
    let (out, terminated) = drive_stream(&mut inspector, &[first, rest]).await;
    assert!(terminated, "denied JSON fallback must be cut");
    assert!(
        !String::from_utf8_lossy(&out).contains("kubectl.apply"),
        "denied call leaked"
    );

    // Allowed JSON fallback: released unchanged at EOF.
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("application/json"))
        .expect("inspector");
    let allowed = response_with_tool_call("report.read", "{}");
    let (first, rest) = allowed.split_at(allowed.len() / 2);
    let (out, terminated) = drive_stream(&mut inspector, &[first, rest]).await;
    assert!(!terminated, "allowed JSON fallback must not be cut");
    assert_eq!(out, allowed, "allowed body must be released unchanged");

    // A real SSE body under a stripped/absent content type on the same
    // stream-marked request: normal streaming governance still applies.
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, None)
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[SSE_ALLOWED_TOOL_BODY.as_bytes()]).await;
    assert!(!terminated, "allowed SSE stream must not be cut");
    assert_eq!(out, SSE_ALLOWED_TOOL_BODY.as_bytes());

    // No stream marker: ordinary non-streaming traffic gets no inspector.
    let plain = create_test_context();
    assert!(
        plugin
            .response_stream_inspector(&plain, 200, Some("application/json"))
            .is_none(),
        "non-stream-marked JSON responses stay on the buffered path"
    );

    // Framed gRPC stays out of scope even for a stream-marked request.
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("application/grpc+json"))
            .is_none(),
        "framed gRPC must never get an inspector"
    );
}

/// A stream whose shape never resolves before EOF (no colon, line terminator,
/// or control byte) is resolved conservatively at end-of-stream: bytes that
/// are NOT valid UTF-8 can never be classified as SSE/JSON and get Opaque
/// semantics (cut in enforce, released in dry-run) instead of the SSE flush
/// (where they would classify `NoData` and forward). A colon-less printable
/// UTF-8 fragment provably contains no `data:` frame and is still released.
#[tokio::test]
async fn eof_unresolved_non_utf8_stream_gets_opaque_semantics() {
    // High-bit bytes: no colon/terminator/control byte (sniff stays
    // inconclusive), and not valid UTF-8.
    let opaque: &[u8] = b"\x80\x81\x82\x83\xfe\xff";

    let enforce = make(streaming_config(
        json!({ "report.read": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = enforce
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[opaque]).await;
    assert!(
        terminated,
        "unresolved non-UTF-8 stream must be cut at EOF in enforce"
    );
    assert!(
        !out.windows(2).any(|w| w == [0x80, 0x81]),
        "held bytes leaked"
    );

    let dry_run = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let ctx = create_test_context();
    let mut inspector = dry_run
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[opaque]).await;
    assert!(!terminated, "dry-run must not cut an unresolved stream");
    assert_eq!(out, opaque, "dry-run must release the bytes unchanged");

    // Colon-less printable UTF-8 with no terminator: provably no `data:`
    // frame inside — released unchanged even in enforce.
    let printable: &[u8] = b"printable fragment with no colon or terminator";
    let ctx = create_test_context();
    let mut inspector = enforce
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[printable]).await;
    assert!(
        !terminated,
        "printable colon-less fragment must be released"
    );
    assert_eq!(out, printable);
}

/// The SSE spec allows `\r`, `\n`, or `\r\n` line terminators. A CR-only
/// stream must parse into events (an LF-only splitter sees one unparsed line
/// and forwards denied deltas) on BOTH the live and buffered paths.
#[tokio::test]
async fn cr_only_sse_denied_call_is_caught_live_and_buffered() {
    let denied_cr = SSE_DENIED_TOOL_BODY.replace('\n', "\r");
    let allowed_cr = SSE_ALLOWED_TOOL_BODY.replace('\n', "\r");

    // Live path: denied call cut, nothing leaked.
    let plugin = make(streaming_config(
        json!({ "report.read": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[denied_cr.as_bytes()]).await;
    assert!(terminated, "CR-only denied deltas must cut the stream");
    assert!(
        !String::from_utf8_lossy(&out).contains("kubectl.apply"),
        "denied call leaked"
    );

    // Live path: allowed CR-only stream released byte-for-byte.
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[allowed_cr.as_bytes()]).await;
    assert!(!terminated, "allowed CR-only stream must not be cut");
    assert_eq!(out, allowed_cr.as_bytes());

    // Buffered path (streaming inspection disabled: SSE label buffered).
    let buffered = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    assert_reject(
        buffered
            .on_response_body(&mut ctx, 200, &mut sse_headers(), denied_cr.as_bytes())
            .await,
        Some(403),
    );
    let mut ctx = create_test_context();
    assert_continue(
        buffered
            .on_response_body(&mut ctx, 200, &mut sse_headers(), allowed_cr.as_bytes())
            .await,
    );
}

/// A `\r\n` (or `\r\n\r\n` event boundary) can straddle a chunk boundary. A
/// chunk ending in `\r` is ambiguous — lone-CR terminator or half of `\r\n` —
/// so the live inspector must hold it until the next chunk disambiguates
/// rather than splitting an event inside one terminator.
#[tokio::test]
async fn crlf_terminator_straddling_chunks_is_not_mis_split() {
    let plugin = make(streaming_config(
        json!({ "report.read": { "action": "allow" } }),
        "deny",
    ));

    // Allowed CRLF stream split right after the FIRST `\r` of the boundary:
    // passes through byte-for-byte.
    let allowed = SSE_ALLOWED_TOOL_BODY.replace("\n\n", "\r\n\r\n");
    let split = allowed.find("\r\n\r\n").expect("boundary") + 1;
    let (first, rest) = allowed.as_bytes().split_at(split);
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[first, rest]).await;
    assert!(!terminated, "allowed straddled stream must not be cut");
    assert_eq!(out, allowed.as_bytes());

    // Denied CRLF stream split between `\r` and `\n` of the SECOND
    // terminator: still parsed as one event and caught.
    let denied = SSE_DENIED_TOOL_BODY.replace("\n\n", "\r\n\r\n");
    let split = denied.find("\r\n\r\n").expect("boundary") + 3;
    let (first, rest) = denied.as_bytes().split_at(split);
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[first, rest]).await;
    assert!(
        terminated,
        "straddled denied deltas must still cut the stream"
    );
    assert!(
        !String::from_utf8_lossy(&out).contains("kubectl.apply"),
        "denied call leaked"
    );
}

/// Wrap `data` in a gzip stream with STORED (uncompressed) deflate blocks so
/// the wire size slightly EXCEEDS the payload — models an incompressible
/// upstream payload whose wire bytes exceed the parse cap while the decoded
/// JSON is within it.
fn gzip_stored(data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::none());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

/// A JSON tool-call response padded with a `padding` field to exactly
/// `target_len` bytes.
fn padded_tool_call_json(name: &str, target_len: usize) -> Vec<u8> {
    let mut body = json!({
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": { "name": name, "arguments": "{}" }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "padding": ""
    });
    let overhead = body.to_string().len();
    body["padding"] = Value::String("x".repeat(target_len - overhead));
    let bytes = body.to_string().into_bytes();
    assert_eq!(bytes.len(), target_len, "padding math");
    bytes
}

/// The 4 MiB parse cap must bound the DECODED size for an encoded body, not
/// the compressed wire bytes: an incompressible >4 MiB-wire payload whose
/// decoded JSON is within the cap is decoded and governed normally (allowed
/// forwards, denied rejects), while a decoded-over-cap body still fails
/// closed. The wire cap continues to apply to identity/plaintext bodies.
#[tokio::test]
async fn oversized_wire_encoded_json_within_decoded_cap_is_governed() {
    let cap = 4 * 1024 * 1024;
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));

    // Decoded exactly at the cap; stored-gzip wire is slightly larger.
    let denied = padded_tool_call_json("kubectl.apply", cap);
    let wire = gzip_stored(&denied);
    assert!(wire.len() > cap, "test premise: wire must exceed the cap");
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut gzip_headers(), &wire)
            .await,
        Some(403),
    );

    let allowed = padded_tool_call_json("report.read", cap);
    let wire = gzip_stored(&allowed);
    assert!(wire.len() > cap, "test premise: wire must exceed the cap");
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut gzip_headers(), &wire)
            .await,
    );

    // Decoded past the cap: the decoded-size bound still fails closed.
    let too_big = padded_tool_call_json("report.read", cap + 1);
    let wire = gzip_stored(&too_big);
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut gzip_headers(), &wire)
            .await,
        Some(502),
    );
}

/// Framed gRPC / gRPC-Web (`+json` variants included) is out of scope on the
/// buffered response hooks: when a response is buffered for reasons outside
/// this plugin, an oversized framed body must NOT trip the fail-closed size
/// check via its `+json` suffix, and the redaction transform must never
/// rewrite framed wire bytes.
#[tokio::test]
async fn oversized_framed_grpc_buffered_response_is_untouched() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    for ct in ["application/grpc+json", "application/grpc-web+json"] {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), ct.to_string());
        let oversized = vec![0u8; 4 * 1024 * 1024 + 1];
        let mut ctx = create_test_context();
        assert_continue(
            plugin
                .on_response_body(&mut ctx, 200, &mut headers, &oversized)
                .await,
        );
        assert_continue(
            plugin
                .on_final_response_body(&mut ctx, 200, &headers, &oversized)
                .await,
        );
    }

    // Redaction transform: even with the governed-hash marker present, a
    // framed gRPC label is never rewritten. The marker now lives on a
    // non-serialized request field, so establish it the real way — govern a
    // genuine JSON body first (which records the marker) — instead of poking it
    // into metadata.
    let redact = make(json!({
        "default_action": "allow",
        "tools": {
            "deploy": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "s", "regex": "secret" }]
            }
        }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", "{\"k\":\"secret\"}");
    // Govern the body as JSON: records the governed-response marker on the
    // request so the marker gate in the transform is satisfied.
    assert_continue(
        redact
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    // With the marker present, the framed-gRPC gate (which precedes the marker
    // gate) is what declines the rewrite.
    let rewritten = redact
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc+json"),
            &HashMap::new(),
        )
        .await.replaced_bytes();
    assert!(rewritten.is_none(), "framed gRPC must never be rewritten");
}

// ---------------------------------------------------------------------------
// Round 15 review fixes:
//   1. final-body stream re-detection CLEARS a stale stream marker when a
//      transformer reverts `stream: true` -> `false` (round-14 regression).
//   2. an SSE frame with a MALFORMED (non-array) `delta.tool_calls` fails
//      closed like the buffered non-array case, not forwarded.
//   3. a UTF-8 BOM before a buffered JSON body no longer bypasses governance.
// ---------------------------------------------------------------------------

/// Fix 1: a `request_transformer` that rewrites an initially-`stream: true`
/// request back to `stream: false` on the FINAL backend-visible body must CLEAR
/// the stale `stream_requested` marker `before_proxy` set. Otherwise the
/// response mode stays "streaming", so a plain non-streaming JSON response is
/// misrouted through the SSE inspector (held-in-full, governed as an SSE
/// fallback) instead of the buffered JSON path. After clearing, the SSE
/// inspector no longer attaches to a plain-JSON response and the buffered path
/// governs it — a denied call is still rejected. The round-14 case (transformer
/// ADDS `stream: true`) must still pin streaming.
#[tokio::test]
async fn final_request_body_clears_stale_stream_marker_when_transform_disables_stream() {
    // Both response and streaming inspection enabled so the buffered path
    // governs regardless of the marker; the marker only decides SSE-vs-buffered
    // routing of the response.
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "response_tool_calls": true, "streaming_response_tool_calls": true }
    }));

    let mut ctx = json_post_ctx();
    // before_proxy sees the ORIGINAL streaming request and marks it.
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({ "stream": true, "model": "gpt-4o", "messages": [] }).to_string(),
    );
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.stream_requested")
            .map(String::as_str),
        Some("true"),
        "before_proxy marks the streaming request"
    );
    // With the stale marker, a plain-JSON response would get the SSE inspector.
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("application/json"))
            .is_some(),
        "test premise: stale marker misroutes plain JSON to the SSE inspector"
    );

    // The transformer rewrote `stream: true` -> `false` on the final body.
    let final_body = json!({ "stream": false, "model": "gpt-4o", "messages": [] }).to_string();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), final_body.as_bytes())
            .await,
    );
    assert_eq!(
        ctx.metadata.get("ai_tool_governor.stream_requested"),
        None,
        "a parsed non-streaming final body must CLEAR the stale stream marker"
    );
    assert_eq!(
        ctx.metadata.get("ai_tool_governor.stream_model"),
        None,
        "the dependent stream model must be cleared too"
    );
    assert!(
        !plugin.forces_reqwest_dispatch(&ctx),
        "cleared marker must no longer force reqwest dispatch"
    );
    // The plain-JSON response now stays on the buffered path (no SSE inspector).
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("application/json"))
            .is_none(),
        "cleared marker: plain JSON response governed as buffered JSON, not SSE"
    );
    // A denied call in that non-streaming JSON response is still rejected via
    // the buffered path.
    let denied = response_with_tool_call("kubectl.apply", "{}");
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &denied)
            .await,
        Some(403),
    );
}

/// Fix 1 (round-14 regression guard): a transformer that ADDS `stream: true` on
/// the final body still pins streaming — clearing must be strictly one-way
/// (only a parsed non-streaming body clears).
#[tokio::test]
async fn final_request_body_still_pins_stream_when_transform_adds_stream() {
    let plugin = make(json!({
        "default_action": "deny",
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));
    let mut ctx = json_post_ctx();
    assert!(!plugin.forces_reqwest_dispatch(&ctx));
    let body = json!({ "stream": true, "model": "gpt-4o", "messages": [] }).to_string();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), body.as_bytes())
            .await,
    );
    assert!(
        plugin.forces_reqwest_dispatch(&ctx),
        "transform-added stream:true must still pin reqwest dispatch"
    );

    // An UNPARSEABLE final body must NOT clear a marker either (conservative):
    // seed the marker, then feed a non-JSON body.
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "ai_tool_governor.stream_requested".to_string(),
        "true".to_string(),
    );
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), b"not json at all")
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.stream_requested")
            .map(String::as_str),
        Some("true"),
        "an unparseable final body must not clear the conservative stream marker"
    );
}

/// Fix 2: an SSE frame whose `choices[].delta.tool_calls` is present but NOT a
/// JSON array is ungovernable (its entries cannot be accumulated) — the live
/// inspector must fail closed in enforce (cut the stream, no leak) and release
/// unchanged in dry-run, mirroring the buffered non-array case.
#[tokio::test]
async fn streaming_non_array_tool_calls_frame_fails_closed_in_enforce() {
    let plugin = make(streaming_config(json!({}), "deny"));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    // `tool_calls` is an OBJECT, not an array.
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":",
        "{\"name\":\"kubectl.apply\"}}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let (out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(
        terminated,
        "a malformed non-array tool_calls frame must cut the stream in enforce"
    );
    assert!(
        !String::from_utf8_lossy(&out).contains("kubectl.apply"),
        "malformed frame must not be forwarded before the cut: {}",
        String::from_utf8_lossy(&out)
    );
}

/// Fix 2 (dry-run): the same malformed non-array `tool_calls` frame is released
/// unchanged — dry-run never disrupts traffic.
#[tokio::test]
async fn streaming_non_array_tool_calls_frame_released_in_dry_run() {
    let plugin = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":",
        "{\"name\":\"kubectl.apply\"}}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let bytes = body.as_bytes();
    let (out, terminated) = drive_stream(&mut inspector, &[bytes]).await;
    assert!(!terminated, "dry-run must not cut the stream");
    assert_eq!(
        out, bytes,
        "dry-run must release the malformed frame unchanged"
    );
}

/// Fix 2 (buffered-SSE parity): the buffered-SSE extractor must also treat a
/// non-array `delta.tool_calls` frame as ungovernable — enforce reject,
/// dry-run forward — so the two SSE paths agree with the buffered JSON path.
#[tokio::test]
async fn buffered_sse_non_array_tool_calls_frame_fails_closed() {
    let malformed = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":",
        "{\"name\":\"kubectl.apply\"}}}]}\n\n",
        "data: [DONE]\n\n"
    );
    // Enforce (streaming disabled -> SSE label buffered): reject.
    let enforce = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    assert_reject(
        enforce
            .on_response_body(&mut ctx, 200, &mut sse_headers(), malformed.as_bytes())
            .await,
        Some(502),
    );
    // Dry-run: forward unchanged.
    let dry = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    assert_continue(
        dry.on_response_body(&mut ctx, 200, &mut sse_headers(), malformed.as_bytes())
            .await,
    );
}

/// Fix 3: a UTF-8 BOM before an `application/json` Chat Completions body must
/// not let a denied `choices[].message.tool_calls[]` bypass policy —
/// `serde_json` rejects a BOM-prefixed body, so the un-stripped path forwarded
/// it ungoverned. A denied call is now rejected, an allowed call forwarded, on
/// both `on_response_body` and `on_final_response_body`.
#[tokio::test]
async fn bom_prefixed_json_response_denied_call_is_caught() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));

    let mut denied = b"\xEF\xBB\xBF".to_vec();
    denied.extend_from_slice(&response_with_tool_call("kubectl.apply", "{}"));
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &denied)
            .await,
        Some(403),
    );
    // Final re-check path also strips the BOM.
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &denied)
            .await,
        Some(403),
    );

    // An allowed call with a BOM still forwards on both paths.
    let mut allowed = b"\xEF\xBB\xBF".to_vec();
    allowed.extend_from_slice(&response_with_tool_call("report.read", "{}"));
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &allowed)
            .await,
    );
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &allowed)
            .await,
    );
}

/// Fix 3 (hash consistency): the governed-response hash is recorded over the
/// RAW (BOM-included) bytes on BOTH `on_response_body` and the final re-check,
/// so an unchanged BOM-prefixed body governed once is hash-skipped on the final
/// pass — no duplicate approval webhook.
#[tokio::test]
async fn bom_prefixed_json_governed_hash_skips_final_recheck() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 }
    }));
    let mut ctx = create_test_context();
    let mut body = b"\xEF\xBB\xBF".to_vec();
    body.extend_from_slice(&response_with_tool_call("deploy", "{\"env\":\"prod\"}"));
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    ); // webhook #1
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    ); // unchanged raw bytes -> hash match -> skip, no webhook #2
    server.verify().await;
}

// ---------------------------------------------------------------------------
// Round 17 review fixes
// ---------------------------------------------------------------------------

/// P2 (:2326): a streaming-only config (`response_tool_calls: false`,
/// `streaming_response_tool_calls: true`) with a NON-streaming request buffers
/// an SSE body OUTSIDE this plugin. `on_response_body` governs it via the
/// SSE-shape branch regardless of `request_is_streaming`; the final re-check
/// must agree. Previously the `governs_buffered_json` gate ran BEFORE the SSE
/// branch and early-returned, so a later transform that injected/rewrote an SSE
/// `data:` frame with a denied tool call escaped the final re-check. It is now
/// re-governed: enforce rejects, dry-run forwards, and an UNCHANGED SSE body
/// still hash-skips (no duplicate webhook).
#[tokio::test]
async fn final_recheck_governs_externally_buffered_sse_for_streaming_only_config() {
    // Enforce: the raw backend SSE body is allowed (governed by
    // `on_response_body`), then a transform rewrites its frame into a DENIED
    // call. The final re-check must reject instead of early-returning.
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = create_test_context(); // non-streaming request (no stream markers)
    assert_continue(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut sse_headers(),
                SSE_ALLOWED_TOOL_BODY.as_bytes(),
            )
            .await,
    );
    // A later `response_transformer` body rule rewrote the SSE frame to a denied
    // tool call (hash changed): the final re-check re-governs and fails closed.
    assert_reject(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &sse_headers(),
                SSE_DENIED_TOOL_BODY.as_bytes(),
            )
            .await,
        Some(403),
    );

    // Dry-run: the same injection is recorded but forwarded, never rejected.
    let dry = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": { "streaming_response_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = create_test_context();
    assert_continue(
        dry.on_response_body(
            &mut ctx,
            200,
            &mut sse_headers(),
            SSE_ALLOWED_TOOL_BODY.as_bytes(),
        )
        .await,
    );
    assert_continue(
        dry.on_final_response_body(
            &mut ctx,
            200,
            &sse_headers(),
            SSE_DENIED_TOOL_BODY.as_bytes(),
        )
        .await,
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("deny"),
        "dry-run must record the would-be denial from the final SSE re-check"
    );
}

/// P2 (:2326): an UNCHANGED externally-buffered SSE body — a streaming-only
/// config, non-streaming request, `require_approval` tool — is governed once in
/// `on_response_body` and hash-skipped by the final re-check, so the approval
/// webhook fires exactly once even though the final re-check now runs (it did
/// not before the gate reorder). Guards against a duplicate webhook regression.
#[tokio::test]
async fn final_recheck_unchanged_buffered_sse_skips_second_webhook() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": { "endpoint_url": format!("{}/approve", server.uri()), "cache_ttl_seconds": 0 },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));
    let body = concat!(
        "data: {\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"deploy\",\"arguments\":\"{\\\"env\\\":\\\"prod\\\"}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut ctx = create_test_context(); // non-streaming request
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
            .await,
    ); // webhook #1 (approved)
    // Identical bytes: the recorded SSE hash matches, so the final re-check
    // hash-skips before re-governing — no webhook #2.
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &sse_headers(), body.as_bytes())
            .await,
    );
    server.verify().await;
}

/// P3 (:1272): in `dry_run` with request tool-definition inspection AND MCP/A2A
/// request inspection, a request JSON exposing a DISALLOWED `tools[]` definition
/// records `decision=deny`, then execution continues and a later ALLOWED MCP
/// (or A2A) method in the same object must NOT clobber the metadata back to
/// `allow`. The recorded aggregate decision is sticky-deny so dry-run rollout
/// logs do not under-report would-be-rejected requests.
#[tokio::test]
async fn dry_run_request_decision_is_sticky_deny_across_surfaces() {
    // Disallowed tool DEFINITION (default deny) + allowed MCP `tools/call` in
    // one JSON object.
    let plugin = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "safe_mcp_tool": { "action": "allow" } },
        "inspect": {
            "request_tool_definitions": true,
            "mcp_tool_calls": true,
            "response_tool_calls": false
        }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "model": "gpt-4o",
            "tools": [
                { "type": "function", "function": { "name": "dangerous_tool" } }
            ],
            "method": "tools/call",
            "params": { "name": "safe_mcp_tool", "arguments": {} }
        })
        .to_string(),
    );
    let mut headers = json_headers();
    // Dry-run never rejects, but the definition deny is recorded first...
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    // ...and the later allowed MCP call must not downgrade it.
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("deny"),
        "an allowed MCP call must not clobber an earlier definition deny in dry-run"
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.tool_names")
            .map(String::as_str),
        Some("dangerous_tool"),
        "the allowed MCP call must not hide the denied definition name"
    );

    // Same guarantee for an allowed A2A method after a denied definition.
    let plugin = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "safe.a2a": { "action": "allow" } },
        "inspect": {
            "request_tool_definitions": true,
            "a2a_methods": true,
            "response_tool_calls": false
        }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "tools": [
                { "type": "function", "function": { "name": "dangerous_tool" } }
            ],
            "method": "safe.a2a",
            "params": {}
        })
        .to_string(),
    );
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("deny"),
        "an allowed A2A method must not clobber an earlier definition deny in dry-run"
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.tool_names")
            .map(String::as_str),
        Some("dangerous_tool"),
        "the allowed A2A call must not hide the denied definition name"
    );
}

// ---------------------------------------------------------------------------
// Round 19 review fixes
// ---------------------------------------------------------------------------

/// P3 (:1032): definition-only policies never invoke the approval webhook — a
/// bare tool definition has no arguments to approve, so `require_approval` is
/// deliberately treated as a blocked definition. Both an explicit tool action
/// and the default action must therefore be valid without an endpoint when no
/// concrete-call inspection surface is enabled.
#[tokio::test]
async fn definition_only_approval_policies_do_not_require_webhook() {
    let configs = [
        json!({
            "default_action": "allow",
            "tools": { "deploy": { "action": "require_approval" } },
            "inspect": {
                "request_tool_definitions": true,
                "response_tool_calls": false
            }
        }),
        json!({
            "default_action": "require_approval",
            "tools": {},
            "inspect": {
                "request_tool_definitions": true,
                "response_tool_calls": false
            }
        }),
    ];

    for config in configs {
        let plugin = try_make(config).expect("definition-only policy must not need a webhook");
        let mut ctx = json_post_ctx();
        ctx.metadata.insert(
            "request_body".to_string(),
            json!({
                "model": "gpt-4o",
                "tools": [{ "type": "function", "function": { "name": "deploy" } }]
            })
            .to_string(),
        );
        let mut headers = json_headers();
        assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(403));
    }
}

/// P2 (:2406, round 21 follow-up): an externally-buffered final encoded body
/// remains governed even for a non-streaming request under a streaming-only
/// config. If its encoding is unsupported/corrupt, enforce must fail closed
/// before the later JSON-only request gate even after an SSE body was relabeled;
/// dry-run continues without disrupting traffic.
#[tokio::test]
async fn final_undecodable_encoded_sse_fails_closed_for_streaming_only_config() {
    let opaque = b"\x28\xb5\x2f\xfdopaque-zstd-sse";

    let enforce = make(json!({
        "default_action": "deny",
        "inspect": {
            "response_tool_calls": false,
            "streaming_response_tool_calls": true
        }
    }));
    let dry_run = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "inspect": {
            "response_tool_calls": false,
            "streaming_response_tool_calls": true
        }
    }));

    for content_type in ["text/event-stream", "text/plain"] {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), content_type.to_string());
        headers.insert("content-encoding".to_string(), "zstd".to_string());

        let mut ctx = create_test_context(); // deliberately non-streaming request
        assert_reject(
            enforce
                .on_final_response_body(&mut ctx, 200, &headers, opaque)
                .await,
            Some(502),
        );

        let mut ctx = create_test_context();
        assert_continue(
            dry_run
                .on_final_response_body(&mut ctx, 200, &headers, opaque)
                .await,
        );
    }
}

/// One complete SSE event larger than the retained-byte cap must be handled
/// before `classify_event` can copy/parse it. A non-JSON `data:` payload makes
/// the behavioral regression observable: the old classify-first path forwarded
/// it and emptied `carry`, so the post-loop retained-byte check never fired.
#[tokio::test]
async fn complete_oversized_sse_event_is_capped_before_parsing() {
    let mut event = b"data: ".to_vec();
    event.extend(std::iter::repeat_n(b'A', 4 * 1024 * 1024 + 1));
    event.extend_from_slice(b"\n\n");

    let enforce = make(streaming_config(json!({}), "deny"));
    let ctx = create_test_context();
    let mut inspector = enforce
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[event.as_slice()]).await;
    assert!(
        terminated,
        "one over-cap complete event must cut enforce mode"
    );
    assert!(
        out.len() < 1024,
        "oversized event bytes must not be forwarded before termination"
    );

    let dry_run = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "inspect": {
            "response_tool_calls": false,
            "streaming_response_tool_calls": true
        }
    }));
    let ctx = create_test_context();
    let mut inspector = dry_run
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[event.as_slice()]).await;
    assert!(!terminated, "dry-run must not disrupt an over-cap event");
    assert_eq!(out, event, "dry-run must forward the event unchanged");
}

// ---------------------------------------------------------------------------
// Round 20 review fixes
// ---------------------------------------------------------------------------

/// P2 (:1462): private body/call dedup ledgers are scoped to one governor
/// instance. A permissive instance that clears a transform-injected call must
/// not let a stricter later instance consume that identity and skip policy.
#[tokio::test]
async fn multiple_governor_instances_do_not_share_final_recheck_ledgers() {
    let permissive = make(json!({
        "default_action": "allow",
        "tools": { "kubectl.apply": { "action": "allow" } }
    }));
    let strict = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } }
    }));
    let original = json!({
        "model": "gpt-4o",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": "ok" } }]
    })
    .to_string()
    .into_bytes();
    let injected = response_with_tool_call("kubectl.apply", "{}");
    let mut ctx = create_test_context();

    // Both instances see and clear the original call-free backend body.
    assert_continue(
        permissive
            .on_response_body(&mut ctx, 200, &mut json_headers(), &original)
            .await,
    );
    assert_continue(
        strict
            .on_response_body(&mut ctx, 200, &mut json_headers(), &original)
            .await,
    );

    // A later transform injects a call. The first instance allows and records
    // it, but that record belongs only to the first instance; the strict one
    // must still evaluate and reject it.
    assert_continue(
        permissive
            .on_final_response_body(&mut ctx, 200, &json_headers(), &injected)
            .await,
    );
    assert_reject(
        strict
            .on_final_response_body(&mut ctx, 200, &json_headers(), &injected)
            .await,
        Some(403),
    );
}

// ---------------------------------------------------------------------------
// Round 21 review fixes
// ---------------------------------------------------------------------------

/// P2 (:2107): gateway compression commits `Content-Encoding` in `after_proxy`
/// before body transforms run. The governor therefore still receives plaintext
/// here and must parse a JSON-shaped SSE fallback before attempting to decode
/// bytes that compression has not transformed yet.
#[tokio::test]
async fn pre_transform_gateway_compression_keeps_plaintext_json_inspectable() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "allow" } },
        "inspect": {
            "response_tool_calls": false,
            "streaming_response_tool_calls": true
        }
    }));
    let mut headers = sse_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let mut ctx = create_test_context();
    ctx.metadata.insert(
        "ai_tool_governor.stream_requested".to_string(),
        "true".to_string(),
    );
    ctx.metadata
        .insert("compression:algorithm".to_string(), "gzip".to_string());
    assert_continue(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut headers,
                &response_with_tool_call("report.read", "{}"),
            )
            .await,
    );

    let mut ctx = create_test_context();
    ctx.metadata.insert(
        "ai_tool_governor.stream_requested".to_string(),
        "true".to_string(),
    );
    ctx.metadata
        .insert("compression:algorithm".to_string(), "gzip".to_string());
    assert_reject(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut headers,
                &response_with_tool_call("kubectl.apply", "{}"),
            )
            .await,
        Some(403),
    );
}

/// P3 (:1208): later lower-risk inspection cannot downgrade the maximum risk
/// associated with a sticky dry-run denial.
#[tokio::test]
async fn dry_run_metadata_preserves_max_risk_across_governor_instances() {
    let high_risk = make(json!({
        "mode": "dry_run",
        "default_action": "allow",
        "tools": { "danger": { "action": "deny", "risk": "critical" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    let low_risk = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "safe.a2a": { "action": "allow", "risk": "low" } },
        "inspect": { "a2a_methods": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "danger", "arguments": { "scope": "denied" } }
        })
        .to_string(),
    );
    let mut headers = json_headers();
    assert_continue(high_risk.before_proxy(&mut ctx, &mut headers).await);
    let denied_hashes = ctx
        .metadata
        .get("ai_tool_governor.arguments_hashes")
        .cloned()
        .expect("denied call hash");

    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "safe.a2a",
            "params": { "scope": "allowed" }
        })
        .to_string(),
    );
    assert_continue(low_risk.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("deny")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.risk")
            .map(String::as_str),
        Some("critical")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.policy_ids")
            .map(String::as_str),
        Some("danger"),
        "the later allowed policy must not replace the sticky denial's policy ID"
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.arguments_hashes")
            .map(String::as_str),
        Some(denied_hashes.as_str()),
        "the later allowed call must not replace the sticky denial's argument hash"
    );
}

/// P3 (:1419): equal-severity definition denials from separate governor
/// instances merge their names rather than replacing the earlier finding.
#[tokio::test]
async fn dry_run_definition_denials_merge_across_governor_instances() {
    let first = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "inspect": { "request_tool_definitions": true, "response_tool_calls": false }
    }));
    let second = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "inspect": { "request_tool_definitions": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    let mut headers = json_headers();

    ctx.metadata.insert(
        "request_body".to_string(),
        json!({ "tools": [{ "type": "function", "function": { "name": "first_denied" } }] })
            .to_string(),
    );
    assert_continue(first.before_proxy(&mut ctx, &mut headers).await);

    ctx.metadata.insert(
        "request_body".to_string(),
        json!({ "tools": [{ "type": "function", "function": { "name": "second_denied" } }] })
            .to_string(),
    );
    assert_continue(second.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.tool_names")
            .map(String::as_str),
        Some("first_denied,second_denied")
    );
}

/// A definition-only denial that upgrades an earlier allowed concrete call
/// replaces every decision-aligned metadata field rather than retaining hashes
/// or correlation details from the weaker call.
#[tokio::test]
async fn definition_denial_clears_lower_rank_concrete_call_metadata() {
    let earlier_call = make(json!({
        "mode": "dry_run",
        "default_action": "allow",
        "tools": { "safe": { "action": "allow", "risk": "critical" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    let definition_guard = make(json!({
        "mode": "dry_run",
        "default_action": "allow",
        "tools": { "blocked_definition": { "action": "deny", "risk": "high" } },
        "inspect": { "request_tool_definitions": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    let mut headers = json_headers();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "safe", "arguments": { "scope": "earlier" } }
        })
        .to_string(),
    );
    assert_continue(earlier_call.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        ctx.metadata
            .contains_key("ai_tool_governor.arguments_hashes")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.risk")
            .map(String::as_str),
        Some("critical")
    );
    // Seed the other decision-aligned shapes an approval/redaction surface can
    // add; the stronger definition denial must clear all of them consistently.
    ctx.metadata.insert(
        "ai_tool_governor.approval_id".to_string(),
        "stale-approval".to_string(),
    );
    ctx.metadata.insert(
        "ai_tool_governor.redacted_tools".to_string(),
        "stale-redaction".to_string(),
    );

    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "tools": [{
                "type": "function",
                "function": { "name": "blocked_definition" }
            }]
        })
        .to_string(),
    );
    assert_continue(definition_guard.before_proxy(&mut ctx, &mut headers).await);

    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("deny")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.tool_names")
            .map(String::as_str),
        Some("blocked_definition")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.risk")
            .map(String::as_str),
        Some("high"),
        "the stronger definition decision replaces the earlier call risk"
    );
    for key in [
        "ai_tool_governor.policy_ids",
        "ai_tool_governor.approval_id",
        "ai_tool_governor.arguments_hashes",
        "ai_tool_governor.redacted_tools",
    ] {
        assert!(!ctx.metadata.contains_key(key), "stale metadata: {key}");
    }
}

// ---------------------------------------------------------------------------
// Round 22 review fixes
// ---------------------------------------------------------------------------

/// P2 (:3974): a JSON-RPC `tools/call` with no checkable `params.name` is a
/// malformed governed call, not an absent call. Enforce fails closed for both
/// direct and batch envelopes; dry-run remains non-disruptive.
#[tokio::test]
async fn malformed_mcp_tool_call_names_fail_closed_in_enforce() {
    let enforce = make(mcp_config("enforce"));
    let malformed = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {}
        }),
        json!([{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": 42, "arguments": {} }
        }]),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "", "arguments": {} }
        }),
    ];

    for body in &malformed {
        let mut ctx = json_post_ctx();
        ctx.metadata
            .insert("request_body".to_string(), body.to_string());
        let mut headers = json_headers();
        assert_reject(
            enforce.before_proxy(&mut ctx, &mut headers).await,
            Some(502),
        );
    }

    let dry_run = make(mcp_config("dry_run"));
    let mut ctx = json_post_ctx();
    ctx.metadata
        .insert("request_body".to_string(), malformed[0].to_string());
    let mut headers = json_headers();
    assert_continue(dry_run.before_proxy(&mut ctx, &mut headers).await);
}

/// P2 (:1999): JSON shape, not only a trusted Content-Type or an earlier hash,
/// keeps an oversized relabeled final request in fail-closed scope.
#[tokio::test]
async fn oversized_relabeled_json_request_fails_closed() {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "kubectl.apply", "arguments": {} },
        "padding": "x".repeat(4 * 1024 * 1024)
    })
    .to_string();
    assert!(body.len() > 4 * 1024 * 1024);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());

    let enforce = make(mcp_config("enforce"));
    let mut ctx = json_post_ctx();
    assert_reject(
        enforce
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
        Some(502),
    );

    let dry_run = make(mcp_config("dry_run"));
    let mut ctx = json_post_ctx();
    assert_continue(
        dry_run
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
    );
}

// ---------------------------------------------------------------------------
// Round 23 review fixes
// ---------------------------------------------------------------------------

/// P2 (:3980): empty names are not matchable because configuration rejects
/// empty policy keys. Buffered modern and legacy calls therefore fail closed
/// as ungovernable even under a default-allow denylist.
#[tokio::test]
async fn empty_buffered_tool_call_names_fail_closed() {
    let plugin = make(json!({
        "default_action": "allow",
        "tools": { "blocked": { "action": "deny" } }
    }));
    let bodies = [
        response_with_tool_call("", "{}"),
        json!({
            "choices": [{
                "message": { "function_call": { "name": "", "arguments": "{}" } }
            }]
        })
        .to_string()
        .into_bytes(),
    ];

    for body in &bodies {
        let mut ctx = create_test_context();
        assert_reject(
            plugin
                .on_response_body(&mut ctx, 200, &mut json_headers(), body)
                .await,
            Some(502),
        );
    }
}

/// P1 (:1835): match the MCP/A2A gateways' JSON-RPC media-type handling so a
/// denied call cannot bypass `before_proxy` via `application/json-rpc` or an
/// absent Content-Type.
#[tokio::test]
async fn json_rpc_media_types_are_governed_for_mcp_and_a2a() {
    let cases = [
        (
            make(mcp_config("enforce")),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "kubectl.apply", "arguments": {} }
            }),
        ),
        (
            make(json!({
                "default_action": "allow",
                "tools": { "danger.a2a": { "action": "deny" } },
                "inspect": { "a2a_methods": true, "response_tool_calls": false }
            })),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "danger.a2a",
                "params": {}
            }),
        ),
    ];

    for (plugin, body) in cases {
        for (content_type, method) in [
            (Some("application/json-rpc; charset=utf-8"), "post"),
            (None, "PoSt"),
        ] {
            let mut ctx = create_test_context();
            ctx.method = method.to_string();
            ctx.headers.remove("content-type");
            if let Some(content_type) = content_type {
                ctx.headers
                    .insert("content-type".to_string(), content_type.to_string());
            }
            ctx.metadata
                .insert("request_body".to_string(), body.to_string());
            assert!(plugin.should_buffer_request_body(&ctx));

            let mut headers = ctx.headers.clone();
            assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(403));
        }

        let mut final_ctx = create_test_context();
        final_ctx.method = "pOsT".to_string();
        let final_headers = HashMap::new();
        let final_body = body.to_string();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut final_ctx,
                    &final_headers,
                    final_body.as_bytes(),
                )
                .await,
            Some(403),
        );
    }
}

/// Missing Content-Type is only a tentative JSON-RPC buffering signal. Once
/// the body is available, unrelated no-type form/binary POSTs remain out of
/// scope instead of failing closed as malformed JSON.
#[tokio::test]
async fn absent_content_type_non_json_posts_are_out_of_scope() {
    let plugin = make(mcp_config("enforce"));
    let mut ctx = create_test_context();
    ctx.method = "post".to_string();
    ctx.headers.remove("content-type");
    ctx.metadata.insert(
        "request_body".to_string(),
        "file=not-json&mode=upload".to_string(),
    );
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "25".to_string());

    // The pre-body hook must buffer to classify absent-type traffic.
    assert!(plugin.should_buffer_request_body(&ctx));
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let mut final_ctx = create_test_context();
    final_ctx.method = "PoSt".to_string();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut final_ctx, &headers, b"\x00\x01binary upload")
            .await,
    );
}

// ---------------------------------------------------------------------------
// Audit residuals: #2258, #2260, GHSA-5j2p / GHSA-pcv8 / GHSA-6h6w
// ---------------------------------------------------------------------------

/// `redact_args` rewrite must invalidate origin representation validators so
/// clients never validate against pre-redaction bytes (#2258).
#[tokio::test]
async fn redact_args_transform_invalidates_stale_response_validators() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "token", "regex": "sk-[A-Za-z0-9]+" }]
            }
        }
    }));
    let validators = [
        "etag",
        "ETag",
        "last-modified",
        "content-digest",
        "repr-digest",
        "RePr-DiGeSt",
        "digest",
        "content-md5",
        "x-amz-checksum-sha256",
    ];
    let mut original_headers = HashMap::from([
        ("cache-control".to_string(), "private".to_string()),
        ("content-length".to_string(), "999".to_string()),
    ]);
    for validator in validators {
        original_headers.insert(validator.to_string(), "upstream-value".to_string());
    }

    let clean = response_with_tool_call("filesystem.write", r#"{"path":"/ok"}"#);
    let clean_headers = original_headers.clone();
    let mut clean_ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut clean_ctx, 200, &mut json_headers(), &clean)
            .await,
    );
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut clean_ctx,
                &clean,
                Some("application/json"),
                &clean_headers,
            )
            .await.replaced_bytes()
            .is_none()
    );
    assert_eq!(clean_headers, original_headers);

    let secret_body = response_with_tool_call(
        "filesystem.write",
        r#"{"token":"sk-secret123","path":"/tmp/a"}"#,
    );
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &secret_body)
            .await,
    );
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &secret_body,
            Some("application/json"),
            &original_headers,
        )
        .await.replaced_bytes()
        .expect("redact_args must rewrite the body");
    assert!(
        !String::from_utf8_lossy(&rewritten).contains("sk-secret123"),
        "secret must be redacted from the rewritten body"
    );

    let mut rewritten_headers = original_headers.clone();
    plugin.on_response_body_transformed(&mut ctx, &mut rewritten_headers);
    for validator in validators {
        assert!(
            rewritten_headers
                .keys()
                .all(|key| !key.eq_ignore_ascii_case(validator)),
            "mixed-case {validator} survived a redact_args rewrite"
        );
    }
    assert_eq!(
        rewritten_headers.get("cache-control").map(String::as_str),
        Some("private")
    );
}

/// MCP omitted `params.arguments` normalizes to `{}` for schema evaluation
/// (#2260). Provider response omissions keep distinct semantics.
#[tokio::test]
async fn mcp_omitted_arguments_normalize_to_empty_object_for_schema() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": {
            "github.ping_tool": {
                "action": "allow",
                "json_schema": {
                    "type": "object",
                    "additionalProperties": false
                }
            }
        },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 29,
            "method": "tools/call",
            "params": { "name": "github.ping_tool" }
        })
        .to_string(),
    );
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // Explicit {} is equivalent.
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": { "name": "github.ping_tool", "arguments": {} }
        })
        .to_string(),
    );
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // Required properties still fail after normalization to {}.
    let required = make(json!({
        "default_action": "deny",
        "tools": {
            "github.ping_tool": {
                "action": "allow",
                "json_schema": {
                    "type": "object",
                    "required": ["repo"],
                    "additionalProperties": false,
                    "properties": { "repo": { "type": "string" } }
                }
            }
        },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": { "name": "github.ping_tool" }
        })
        .to_string(),
    );
    assert_reject(
        required.before_proxy(&mut ctx, &mut headers).await,
        Some(403),
    );

    // Provider response shapes must NOT coerce a missing function.arguments
    // into {} — an allowlisted tool with a required object schema still fails
    // when the response omits arguments entirely.
    let response_plugin = make(json!({
        "default_action": "deny",
        "tools": {
            "github.ping_tool": {
                "action": "allow",
                "json_schema": {
                    "type": "object",
                    "additionalProperties": false
                }
            }
        }
    }));
    let body = serde_json::to_vec(&json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": { "name": "github.ping_tool" }
                }]
            },
            "finish_reason": "tool_calls"
        }]
    }))
    .unwrap();
    let mut ctx = create_test_context();
    assert_reject(
        response_plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(403),
    );
}

#[test]
fn rejects_zero_width_redaction_regex_and_oversized_placeholder() {
    // Use `.err().expect(...)` (not `Result::expect_err`) so these negative
    // construction checks do not require `AiToolGovernor: Debug`.
    let err = try_make(json!({
        "tools": {
            "search": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "any", "regex": ".*" }]
            }
        }
    }))
    .err()
    .expect("zero-width regex must be rejected");
    assert!(
        err.contains("must not match the empty string"),
        "unexpected error: {err}"
    );

    let err = try_make(json!({
        "tools": {
            "search": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "any", "regex": "a*" }]
            }
        }
    }))
    .err()
    .expect("a* is zero-width");
    assert!(err.contains("must not match the empty string"));

    let err = try_make(json!({
        "tools": {
            "search": {
                "action": "allow",
                "blocked_arg_patterns": [{ "name": "any", "regex": ".*?" }]
            }
        }
    }))
    .err()
    .expect("zero-width deny patterns are also rejected");
    assert!(err.contains("must not match the empty string"));

    let long = "X".repeat(257);
    let err = try_make(json!({
        "tools": {
            "search": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "token", "regex": "sk-[a-z0-9]+" }]
            }
        },
        "response": { "redaction_placeholder": long }
    }))
    .err()
    .expect("placeholder length must be bounded");
    assert!(err.contains("redaction_placeholder"));

    // OpenAPI maxLength counts Unicode characters; runtime counts UTF-8 bytes.
    let multibyte_placeholder = "é".repeat(129); // 258 bytes, 129 chars
    assert_eq!(multibyte_placeholder.chars().count(), 129);
    assert!(multibyte_placeholder.len() > 256);
    let err = try_make(json!({
        "tools": {
            "search": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "token", "regex": "sk-[a-z0-9]+" }]
            }
        },
        "response": { "redaction_placeholder": multibyte_placeholder }
    }))
    .err()
    .expect("multibyte placeholder over 256 UTF-8 bytes must be rejected");
    assert!(err.contains("redaction_placeholder") && err.contains("UTF-8 bytes"));

    assert!(
        try_make(json!({
            "tools": {
                "search": {
                    "action": "redact_args",
                    "blocked_arg_patterns": [{ "name": "X".repeat(256), "regex": "tok" }]
                }
            }
        }))
        .is_ok(),
        "256 ASCII-byte pattern names are admitted"
    );
    let err = try_make(json!({
        "tools": {
            "search": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "X".repeat(257), "regex": "tok" }]
            }
        }
    }))
    .err()
    .expect("257 ASCII-byte pattern names must be rejected");
    assert!(err.contains("blocked_arg_patterns") && err.contains("name"));

    let multibyte_name = "é".repeat(129); // 258 bytes, 129 chars
    let err = try_make(json!({
        "tools": {
            "search": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": multibyte_name, "regex": "tok" }]
            }
        }
    }))
    .err()
    .expect("multibyte pattern names over 256 UTF-8 bytes must be rejected");
    assert!(err.contains("blocked_arg_patterns") && err.contains("UTF-8 bytes"));

    let too_many: Vec<Value> = (0..33)
        .map(|i| json!({ "name": format!("p{i}"), "regex": format!("token{i}") }))
        .collect();
    let err = try_make(json!({
        "tools": {
            "search": {
                "action": "redact_args",
                "blocked_arg_patterns": too_many
            }
        }
    }))
    .err()
    .expect("pattern count must be bounded");
    assert!(err.contains("at most 32"));
}

#[tokio::test]
async fn contextual_zero_length_redaction_match_fails_closed() {
    // A word boundary does not match empty input, but it does yield empty spans
    // beside words. Runtime construction must reject the span before appending
    // any placeholder bytes rather than amplifying the response.
    let plugin = make(json!({
        "tools": {
            "search": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "boundary", "regex": "\\b" }]
            }
        }
    }));
    let body = response_with_tool_call("search", r#"{"query":"secret"}"#);
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(502),
    );
}

#[test]
fn rejects_oversized_approval_timeout() {
    let err = try_make(json!({
        "tools": { "deploy": { "action": "require_approval" } },
        "approval": {
            "endpoint_url": "https://approval.example/decide",
            "timeout_ms": 30001
        }
    }))
    .err()
    .expect("timeout_ms must be capped");
    assert!(err.contains("timeout_ms"));
}

/// More than 64 concrete calls in one batch fail closed before approval fan-out.
#[tokio::test]
async fn governable_call_limit_fails_closed_before_approvals() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(0)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "default_action": "require_approval",
        "tools": {},
        "approval": {
            "endpoint_url": format!("{}/approve", server.uri()),
            "cache_ttl_seconds": 0,
            "timeout_ms": 500
        }
    }));

    let tool_calls: Vec<Value> = (0..65)
        .map(|i| {
            json!({
                "id": format!("call_{i}"),
                "type": "function",
                "function": {
                    "name": "deploy",
                    "arguments": format!(r#"{{"n":{i}}}"#)
                }
            })
        })
        .collect();
    let body = serde_json::to_vec(&json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": tool_calls
            },
            "finish_reason": "tool_calls"
        }]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(502),
    );
}

/// After an enforce-mode approval denial, remaining unique calls must not each
/// wait out another webhook timeout (GHSA-pcv8).
#[tokio::test]
async fn approval_stops_fanout_after_enforce_block() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "decision": "deny" }))
                .set_delay(std::time::Duration::from_millis(50)),
        )
        .expect(1)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "default_action": "require_approval",
        "tools": {},
        "approval": {
            "endpoint_url": format!("{}/approve", server.uri()),
            "cache_ttl_seconds": 0,
            "timeout_ms": 1500
        }
    }));

    let tool_calls: Vec<Value> = (0..5)
        .map(|i| {
            json!({
                "id": format!("call_{i}"),
                "type": "function",
                "function": {
                    "name": "deploy",
                    "arguments": format!(r#"{{"n":{i}}}"#)
                }
            })
        })
        .collect();
    let body = serde_json::to_vec(&json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": tool_calls
            },
            "finish_reason": "tool_calls"
        }]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(403),
    );
}

/// Sequential unique approvals share one cumulative 30s batch budget
/// (GHSA-pcv8-f48c-mppw). Later webhook calls must not dispatch after the
/// budget is exhausted. The test-only approval clock advances by the
/// production ceiling on the first webhook response so hosted CI never sleeps
/// 30 seconds; public config / OpenAPI stay unchanged.
#[tokio::test]
async fn approval_batch_deadline_stops_later_webhook_fanout() {
    let server = MockServer::start().await;
    let plugin = std::sync::Arc::new(make(json!({
        "default_action": "require_approval",
        "tools": {},
        "approval": {
            "endpoint_url": format!("{}/approve", server.uri()),
            "cache_ttl_seconds": 0,
            "timeout_ms": 5000
        }
    })));
    assert_eq!(
        AiToolGovernor::max_approval_batch_deadline(),
        std::time::Duration::from_secs(30),
        "production approval batch ceiling must remain exactly 30s"
    );

    let clock = std::sync::Arc::clone(&plugin);
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(move |_req: &wiremock::Request| {
            // Simulate the first unique approval consuming the whole batch
            // budget. Subsequent unique calls must fail closed without another
            // webhook dispatch.
            clock.advance_approval_clock_for_tests(AiToolGovernor::max_approval_batch_deadline());
            ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let tool_calls: Vec<Value> = (0..3)
        .map(|i| {
            json!({
                "id": format!("call_{i}"),
                "type": "function",
                "function": {
                    "name": "deploy",
                    "arguments": format!(r#"{{"n":{i}}}"#)
                }
            })
        })
        .collect();
    let body = serde_json::to_vec(&json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": tool_calls
            },
            "finish_reason": "tool_calls"
        }]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    match plugin
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
        .await
    {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502, "deadline exhaustion is fail-closed");
            assert!(
                body.contains("approval batch deadline exceeded"),
                "unexpected reject body: {body}"
            );
            assert!(
                body.contains("approval_denied"),
                "unexpected reject body: {body}"
            );
        }
        other => panic!("expected reject after batch deadline, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("approval_denied")
    );
    server.verify().await;
}

/// Duplicate streamed indexes with distinct ids must fail closed instead of
/// merging a denied call into an allowed synthetic name (GHSA-6h6w).
#[tokio::test]
async fn duplicate_stream_index_with_conflicting_ids_fails_closed() {
    let plugin = make(streaming_config(
        json!({ "danger": { "action": "deny" } }),
        "allow",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    // One held frame carries two same-index entries with distinct ids/names.
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
        "{\"index\":0,\"id\":\"c_safe\",\"function\":{\"name\":\"safe\",\"arguments\":\"{}\"}},",
        "{\"index\":0,\"id\":\"c_danger\",\"function\":{\"name\":\"danger\",\"arguments\":\"{}\"}}",
        "]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let (out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(terminated, "ambiguous streamed identity must fail closed");
    assert!(
        !String::from_utf8_lossy(&out).contains("danger"),
        "denied call must not be released"
    );

    // Buffered SSE path shares the accumulator and must fail closed too.
    let buffered = make(json!({
        "default_action": "allow",
        "tools": { "danger": { "action": "deny" } }
    }));
    let mut ctx = create_test_context();
    assert_reject(
        buffered
            .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
            .await,
        Some(502),
    );
}

/// Conflicting ids across split frames for the same slot are ungovernable.
#[tokio::test]
async fn stream_id_change_within_slot_fails_closed() {
    let plugin = make(streaming_config(
        json!({ "danger": { "action": "deny" } }),
        "allow",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    let chunks: &[&[u8]] = &[
        br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"safe","arguments":""}}]}}]}"#,
        b"\n\n",
        br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c2","function":{"name":"danger","arguments":"{}"}}]}}]}"#,
        b"\n\n",
        br#"data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        b"\n\n",
        b"data: [DONE]\n\n",
    ];
    let (out, terminated) = drive_stream(&mut inspector, chunks).await;
    assert!(terminated, "id change within a slot must fail closed");
    assert!(!String::from_utf8_lossy(&out).contains("danger"));
}

/// Introducing an id only after an untagged fragment is ambiguous: the first
/// bytes may belong to an independently addressed call rather than a
/// continuation. Both live and buffered-SSE paths must fail closed, while an
/// omitted id after a stable initial id remains a valid continuation.
#[tokio::test]
async fn stream_late_id_introduction_fails_closed_but_missing_continuation_id_is_valid() {
    let plugin = make(streaming_config(
        json!({ "danger": { "action": "deny" } }),
        "allow",
    ));
    let ctx = create_test_context();
    let ambiguous = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
        "{\"index\":0,\"function\":{\"name\":\"safe\",\"arguments\":\"\"}}",
        "]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
        "{\"index\":0,\"id\":\"late-id\",\"function\":{\"name\":\"danger\",\"arguments\":\"{}\"}}",
        "]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[ambiguous.as_bytes()]).await;
    assert!(terminated, "late id introduction must fail closed");
    assert!(!String::from_utf8_lossy(&out).contains("danger"));

    let buffered = make(json!({
        "default_action": "allow",
        "tools": { "danger": { "action": "deny" } }
    }));
    let mut buffered_ctx = create_test_context();
    assert_reject(
        buffered
            .on_response_body(
                &mut buffered_ctx,
                200,
                &mut sse_headers(),
                ambiguous.as_bytes(),
            )
            .await,
        Some(502),
    );

    let valid_chunks: &[&[u8]] = &[
        br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"stable-id","function":{"name":"safe","arguments":"{"}}]}}]}"#,
        b"\n\n",
        br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"}"}}]}}]}"#,
        b"\n\n",
        br#"data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        b"\n\n",
        b"data: [DONE]\n\n",
    ];
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (_out, terminated) = drive_stream(&mut inspector, valid_chunks).await;
    assert!(
        !terminated,
        "missing id on a continuation after a stable id must remain valid"
    );
}

#[tokio::test]
async fn duplicate_choice_index_and_malformed_call_id_fail_closed() {
    let plugin = make(streaming_config(
        json!({ "danger": { "action": "deny" } }),
        "allow",
    ));
    let ctx = create_test_context();

    let duplicate_choice = concat!(
        "data: {\"choices\":[",
        "{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"same\",\"function\":{\"name\":\"safe\",\"arguments\":\"{}\"}}]}},",
        "{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"same\",\"function\":{\"name\":\"danger\",\"arguments\":\"{}\"}}]},\"finish_reason\":\"tool_calls\"}",
        "]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[duplicate_choice.as_bytes()]).await;
    assert!(terminated, "duplicate choice identity must fail closed");
    assert!(!String::from_utf8_lossy(&out).contains("danger"));

    let malformed_id = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
        "{\"index\":0,\"id\":42,\"function\":{\"name\":\"danger\",\"arguments\":\"{}\"}}",
        "]},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[malformed_id.as_bytes()]).await;
    assert!(terminated, "non-string call id must fail closed");
    assert!(!String::from_utf8_lossy(&out).contains("danger"));
}

/// JSON `null` for `tool_calls[].id` is omission (like a missing field), while
/// empty-string and non-string ids remain malformed. Live stream and buffered
/// SSE must agree.
#[tokio::test]
async fn stream_null_call_id_is_omission_but_empty_string_fails_closed() {
    let plugin = make(streaming_config(
        json!({ "danger": { "action": "deny" } }),
        "allow",
    ));
    let ctx = create_test_context();

    let null_id = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
        "{\"index\":0,\"id\":null,\"function\":{\"name\":\"safe\",\"arguments\":\"{\"}}",
        "]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
        "{\"index\":0,\"function\":{\"arguments\":\"}\"}}",
        "]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (_out, terminated) = drive_stream(&mut inspector, &[null_id.as_bytes()]).await;
    assert!(
        !terminated,
        "null call id must be treated as omitted continuation, not malformed"
    );

    let buffered = make(json!({
        "default_action": "allow",
        "tools": { "danger": { "action": "deny" } }
    }));
    let mut buffered_ctx = create_test_context();
    assert_continue(
        buffered
            .on_response_body(
                &mut buffered_ctx,
                200,
                &mut sse_headers(),
                null_id.as_bytes(),
            )
            .await,
    );

    let empty_id = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
        "{\"index\":0,\"id\":\"\",\"function\":{\"name\":\"danger\",\"arguments\":\"{}\"}}",
        "]},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (out, terminated) = drive_stream(&mut inspector, &[empty_id.as_bytes()]).await;
    assert!(terminated, "empty-string call id must fail closed");
    assert!(!String::from_utf8_lossy(&out).contains("danger"));

    let mut buffered_ctx = create_test_context();
    assert_reject(
        buffered
            .on_response_body(
                &mut buffered_ctx,
                200,
                &mut sse_headers(),
                empty_id.as_bytes(),
            )
            .await,
        Some(502),
    );
}

/// Dry-run still evaluates ambiguous stream identity without cutting traffic
/// when mode is dry_run — but the held bytes of an enforce cut must not leak.
#[tokio::test]
async fn duplicate_stream_index_dry_run_releases_without_cut() {
    let plugin = make(json!({
        "mode": "dry_run",
        "default_action": "allow",
        "tools": { "danger": { "action": "deny" } },
        "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
    }));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
        "{\"index\":0,\"id\":\"c_safe\",\"function\":{\"name\":\"safe\",\"arguments\":\"{}\"}},",
        "{\"index\":0,\"id\":\"c_danger\",\"function\":{\"name\":\"danger\",\"arguments\":\"{}\"}}",
        "]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let (_out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(!terminated, "dry-run must not cut on ungovernable identity");
}

// ---------------------------------------------------------------------------
// Coverage residuals: amplification fail-closed + admission edge cases
// (hosted Coverage run 29753983615: 142/172 = 82.56% < 84.98%)
// ---------------------------------------------------------------------------

/// Long placeholder × many matches must fail closed in enforce before the
/// redaction transform can emit an amplified body.
fn amplifying_redact_config(mode: &str) -> Value {
    json!({
        "mode": mode,
        "tools": {
            "search": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "a", "regex": "a" }]
            }
        },
        "response": { "redaction_placeholder": "X".repeat(256) }
    })
}

fn amplifying_argument_blob() -> String {
    // 17_000 × 256-byte placeholder exceeds MAX_PARSE_BYTES (4 MiB).
    "a".repeat(17_000)
}

/// A deterministic amplification failure anywhere in an enforce-mode batch
/// must suppress all approval fan-out, including require_approval calls that
/// appear earlier in the response array.
#[tokio::test]
async fn redaction_amplification_block_skips_earlier_approval_webhook() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "decision": "allow" })))
        .expect(0)
        .mount(&server)
        .await;

    let plugin = make(json!({
        "tools": {
            "deploy": { "action": "require_approval" },
            "search": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "a", "regex": "a" }]
            }
        },
        "approval": {
            "endpoint_url": format!("{}/approve", server.uri()),
            "cache_ttl_seconds": 0
        },
        "response": { "redaction_placeholder": "X".repeat(256) }
    }));
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "tool_calls": [
                    {
                        "id": "approval-first",
                        "type": "function",
                        "function": { "name": "deploy", "arguments": "{}" }
                    },
                    {
                        "id": "amplification-second",
                        "type": "function",
                        "function": {
                            "name": "search",
                            "arguments": amplifying_argument_blob()
                        }
                    }
                ]
            },
            "finish_reason": "tool_calls"
        }]
    }))
    .expect("serialize response");
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(502),
    );
    server.verify().await;
}

fn response_with_function_call(name: &str, arguments: &str) -> Vec<u8> {
    json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": Value::Null,
                "function_call": { "name": name, "arguments": arguments }
            },
            "finish_reason": "function_call"
        }],
        "usage": { "prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2 }
    })
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn redact_args_amplification_fails_closed_in_enforce() {
    let plugin = make(amplifying_redact_config("enforce"));
    let body = response_with_tool_call("search", &amplifying_argument_blob());
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(502),
    );
}

/// Amplifying redaction must clear the governed-response hash so the final
/// re-check cannot hash-skip an unredacted secret.
#[tokio::test]
async fn redact_args_amplification_clears_hash_on_transform() {
    let plugin = make(amplifying_redact_config("enforce"));
    let body = response_with_tool_call("search", &amplifying_argument_blob());
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(502),
    );
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/json"),
                &json_headers(),
            )
            .await.replaced_bytes()
            .is_none(),
        "amplifying redact must decline the rewrite"
    );

    // Hash cleared: the final re-check cannot hash-skip the raw body and fails
    // closed because redaction is no longer available on that lifecycle hook.
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
        Some(502),
    );
}

/// Context-bearing response transform screens ambiguity through the shared
/// per-request memo (exact BOM-stripped bytes), clears skip ledgers, and lets
/// the final re-check fail closed — the same recovery as amplification failure.
#[tokio::test]
async fn transform_response_ambiguous_body_clears_hash_via_memo_screen() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "token", "regex": "token" }]
            }
        }
    }));
    let clean = response_with_tool_call("filesystem.write", "{\"data\":\"my token here\"}");
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &clean)
            .await,
    );

    // Large enough for the digest-keyed memo path; leading BOM is stripped
    // before the screen (same bytes-as-key semantics as other context sites).
    let padding = "x".repeat(8192);
    let ambiguous = format!(
        "\u{feff}{{\"pad\":\"{padding}\",\"choices\":[{{\"message\":{{\"tool_calls\":[\
{{\"id\":\"c1\",\"type\":\"function\",\"function\":{{\
\"name\":\"filesystem.write\",\"name\":\"other\",\"arguments\":\"{{}}\"}}}}]}}}}]}}"
    );
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                ambiguous.as_bytes(),
                Some("application/json"),
                &json_headers(),
            )
            .await.replaced_bytes()
            .is_none(),
        "ambiguous transform body must decline rewrite"
    );

    // Skip ledgers cleared: final re-check must not hash-skip the ambiguous
    // client-visible bytes. A second screen of the same BOM-stripped payload on
    // this context reuses the memo entry rather than inheriting a stale pass.
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), ambiguous.as_bytes())
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn aggregate_redacted_arguments_cannot_exceed_response_limit() {
    let plugin = make(amplifying_redact_config("enforce"));
    // Each call expands to ~2.3 MiB and therefore passes the per-call preflight;
    // their aggregate must still be rejected before both strings are retained.
    let arguments = "a".repeat(9_000);
    let body = serde_json::to_vec(&json!({
        "id": "chatcmpl-aggregate",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "search", "arguments": arguments.clone()}},
                    {"id": "call_2", "type": "function", "function": {"name": "search", "arguments": arguments}}
                ]
            },
            "finish_reason": "tool_calls"
        }]
    }))
    .unwrap();
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(502),
    );
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/json"),
                &json_headers(),
            )
            .await.replaced_bytes()
            .is_none(),
        "aggregate redaction past 4 MiB must not be emitted"
    );
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn serialized_redaction_overhead_cannot_exceed_response_limit() {
    let plugin = make(amplifying_redact_config("enforce"));
    // 16,384 replacements produce exactly 4 MiB of argument text. JSON framing
    // necessarily exceeds the cap, so the bounded serializer must fail closed
    // without allocating the complete oversized representation.
    let body = response_with_tool_call("search", &"a".repeat(16_384));
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/json"),
                &json_headers(),
            )
            .await.replaced_bytes()
            .is_none(),
        "serialized body past 4 MiB must not be emitted"
    );
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
        Some(502),
    );
}

/// Legacy `function_call` redaction must rewrite arguments in place (not only
/// modern `tool_calls[]`).
#[tokio::test]
async fn buffered_legacy_function_call_redact_args_rewrites() {
    let plugin = make(json!({
        "tools": {
            "filesystem.write": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "secret", "regex": "sk-[A-Za-z0-9]+" }]
            }
        }
    }));
    let body = response_with_function_call(
        "filesystem.write",
        r#"{"token":"sk-legacysecret99","path":"/tmp"}"#,
    );
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await.replaced_bytes()
        .expect("legacy function_call redact must rewrite");
    let text = String::from_utf8(rewritten).unwrap();
    assert!(!text.contains("sk-legacysecret99"), "secret leaked: {text}");
    assert!(text.contains("[REDACTED_TOOL_ARG:secret]"), "{text}");
}

/// Amplifying redaction on a legacy `function_call` also fails closed.
#[tokio::test]
async fn buffered_legacy_function_call_redact_amplification_fails_closed() {
    let plugin = make(amplifying_redact_config("enforce"));
    let body = response_with_function_call("search", &amplifying_argument_blob());
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(502),
    );
    // Transform after a reject still hits AmplificationFailed and clears the
    // governed hash recorded before the deny.
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/json"),
                &json_headers(),
            )
            .await.replaced_bytes()
            .is_none()
    );
}

/// Pattern names used in `{name}` expansion are admission-capped at 256 UTF-8
/// bytes so a hostile config cannot stage multi-MiB substitutions.
#[test]
fn blocked_arg_pattern_name_admission_rejects_oversized_names() {
    let err = try_make(json!({
        "tools": {
            "search": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "N".repeat(4 * 1024 * 1024 + 1), "regex": "tok" }]
            }
        },
        "response": { "redaction_placeholder": "{name}" }
    }))
    .err()
    .expect("multi-MiB pattern names must fail at admission");
    assert!(
        err.contains("blocked_arg_patterns") && err.contains("UTF-8 bytes"),
        "unexpected admission error: {err}"
    );
}

#[test]
fn rejects_non_positive_approval_timeout() {
    for timeout_ms in [json!(0), json!(-1), json!("fast"), json!(1.5)] {
        let result = try_make(json!({
            "tools": { "deploy": { "action": "require_approval" } },
            "approval": {
                "endpoint_url": "https://approval.example/decide",
                "timeout_ms": timeout_ms.clone()
            }
        }));
        let err = match result {
            Ok(_) => panic!("non-positive timeout_ms must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.contains("timeout_ms") && err.contains("positive"),
            "unexpected error for {timeout_ms}: {err}"
        );
    }
}

/// Transform no-ops for shapes that are not redactable in place, without
/// clearing a previously recorded governed hash.
#[tokio::test]
async fn redact_transform_leaves_non_redactable_shapes_unchanged() {
    let plugin = make(json!({
        "tools": {
            "search": {
                "action": "redact_args",
                "blocked_arg_patterns": [{ "name": "token", "regex": "sk-[A-Za-z0-9]+" }]
            },
            "other": { "action": "allow" }
        }
    }));
    // Record a governed hash via an allowlisted sibling call.
    let seed = response_with_tool_call("other", r#"{"ok":true}"#);
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &seed)
            .await,
    );

    let probes: &[Value] = &[
        // No choices array.
        json!({ "id": "x" }),
        // Function object present but name missing.
        json!({
            "choices": [{
                "message": {
                    "tool_calls": [{ "function": { "arguments": "{}" } }]
                }
            }]
        }),
        // Name not in the redact_args tool set.
        json!({
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "function": { "name": "other", "arguments": r#"{"token":"sk-abc"}"# }
                    }]
                }
            }]
        }),
        // redact_args tool but arguments omitted.
        json!({
            "choices": [{
                "message": {
                    "tool_calls": [{ "function": { "name": "search" } }]
                }
            }]
        }),
    ];
    for probe in probes {
        let body = serde_json::to_vec(probe).unwrap();
        assert!(
            plugin
                .transform_response_body_with_context(
                    &mut ctx,
                    &body,
                    Some("application/json"),
                    &json_headers(),
                )
                .await.replaced_bytes()
                .is_none(),
            "probe should be a no-op: {probe}"
        );
    }
}

// ---------------------------------------------------------------------------
// GHSA-c78j-5w9p-cpq6 — duplicate JSON object member names
//
// `serde_json` collapses duplicate members to the LAST value; many parsers keep
// the FIRST. This plugin governs the collapsed view and forwards the ORIGINAL
// bytes, so a duplicated tool name or argument member lets a first-key-wins
// consumer execute something policy never saw. Governed JSON is therefore
// screened for duplicate members on every surface, and ambiguity joins the
// uninspectable class: fail closed in enforce, observe in dry-run.
// ---------------------------------------------------------------------------

const AMBIGUITY_METADATA_KEY: &str = "ai_tool_governor.decision";
const AMBIGUITY_REASON_KEY: &str = "ai_tool_governor.uninspectable_reason";
const AMBIGUITY_REASON_VALUE: &str = "ambiguous_json";

/// Positive dry-run ambiguity contract: forward unchanged, record
/// `decision=dry_run` + fixed `uninspectable_reason`, never claim deny.
fn assert_dry_run_ambiguity_observation(ctx: &RequestContext) {
    assert_eq!(
        ctx.metadata.get(AMBIGUITY_METADATA_KEY).map(String::as_str),
        Some("dry_run"),
        "dry-run ambiguity must record decision=dry_run, got {:?}",
        ctx.metadata.get(AMBIGUITY_METADATA_KEY)
    );
    assert_eq!(
        ctx.metadata.get(AMBIGUITY_REASON_KEY).map(String::as_str),
        Some(AMBIGUITY_REASON_VALUE),
        "dry-run ambiguity must record the fixed reason, got {:?}",
        ctx.metadata.get(AMBIGUITY_REASON_KEY)
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.mode")
            .map(String::as_str),
        Some("dry_run")
    );
}

/// A raw JSON-RPC `tools/call` body whose `params` carries an earlier `danger`
/// name and a later `safe` one. Built as raw text because `serde_json::json!`
/// cannot express a duplicated member.
const MCP_DUPLICATE_TOOL_NAME: &str = concat!(
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"#,
    r#"{"name":"danger","name":"safe","arguments":{}}}"#
);

fn mcp_governor(mode: &str) -> AiToolGovernor {
    make(json!({
        "mode": mode,
        "default_action": "allow",
        "tools": { "danger": { "action": "deny" }, "safe": { "action": "allow" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }))
}

/// Advisory reproduction 3: the governor evaluates `safe` and would forward the
/// original bytes, which a first-key-wins consumer reads as `danger`.
#[tokio::test]
async fn mcp_duplicate_tool_name_fails_closed_in_enforce() {
    // The differential is real: serde only ever sees the safe name.
    let parsed: Value = serde_json::from_str(MCP_DUPLICATE_TOOL_NAME).expect("valid JSON");
    assert_eq!(parsed["params"]["name"], "safe");

    let plugin = mcp_governor("enforce");
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        MCP_DUPLICATE_TOOL_NAME.to_string(),
    );
    let mut headers = json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
}

/// Dry-run observes without disrupting traffic and without claiming
/// enforcement.
#[tokio::test]
async fn mcp_duplicate_tool_name_is_observed_in_dry_run() {
    let plugin = mcp_governor("dry_run");
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        MCP_DUPLICATE_TOOL_NAME.to_string(),
    );
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_dry_run_ambiguity_observation(&ctx);
    assert_no_governor_metadata_contains(&ctx, "danger");
    assert_no_governor_metadata_contains(&ctx, "safe");
}

/// The rejection detail is a fixed reason that never echoes the governed body.
#[tokio::test]
async fn mcp_duplicate_rejection_detail_echoes_no_body_bytes() {
    let plugin = mcp_governor("enforce");
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        r#"{"method":"tools/call","params":{"name":"danger","name":"safe","secret":"SHIBBOLETH"}}"#
            .to_string(),
    );
    let mut headers = json_headers();
    let body = match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { body, .. } => body,
        other => panic!("expected Reject, got {other:?}"),
    };
    assert!(
        body.contains("duplicate JSON object member names"),
        "detail should name the cause: {body}"
    );
    assert!(
        !body.contains("SHIBBOLETH"),
        "detail leaked body bytes: {body}"
    );
    // The plugin's own metadata must not echo the body either. `request_body`
    // is the proxy's own buffered copy, not something this plugin wrote.
    for (key, value) in &ctx.metadata {
        if key == "request_body" {
            continue;
        }
        assert!(
            !value.contains("SHIBBOLETH"),
            "metadata key {key:?} leaked body bytes: {value:?}"
        );
    }
}

/// A duplicate ANYWHERE in the governed request document is caught, including
/// inside nested `arguments` objects and JSON-RPC batch array entries.
#[tokio::test]
async fn duplicate_members_nested_in_request_are_rejected() {
    let plugin = make(json!({
        "mode": "enforce",
        "default_action": "allow",
        "tools": { "danger": { "action": "deny" } },
        "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
    }));
    for body in [
        r#"{"method":"tools/call","params":{"name":"safe","arguments":{"cmd":"rm","cmd":"ls"}}}"#,
        r#"[{"method":"tools/call","params":{"name":"safe","arguments":{}}},{"method":"tools/call","params":{"name":"danger","name":"safe","arguments":{}}}]"#,
        r#"{"method":"tools/call","params":{"name":"safe","arguments":{"a":[[{"k":1,"k":2}]]}}}"#,
    ] {
        let mut ctx = json_post_ctx();
        ctx.metadata
            .insert("request_body".to_string(), body.to_string());
        let mut headers = json_headers();
        assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
    }
}

/// Unambiguous governed requests still flow — including a document that reuses
/// the same member name in sibling objects.
#[tokio::test]
async fn unambiguous_governed_requests_still_flow() {
    let plugin = mcp_governor("enforce");
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        r#"{"method":"tools/call","params":{"name":"safe","arguments":{"items":[{"k":1},{"k":2}]}}}"#
            .to_string(),
    );
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

/// The FINAL backend-visible request body is screened too, so a request
/// transform cannot re-introduce ambiguity after `before_proxy` cleared it.
#[tokio::test]
async fn duplicate_members_in_final_request_body_fail_closed() {
    let plugin = mcp_governor("enforce");
    let mut ctx = json_post_ctx();
    let result = plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &json_headers(),
            MCP_DUPLICATE_TOOL_NAME.as_bytes(),
        )
        .await;
    assert_reject(result, Some(502));
}

/// A tool call whose `arguments` arrive as a JSON STRING is a second document
/// the enclosing screen cannot see into. An ambiguous one makes the call
/// ungovernable rather than being evaluated on a last-wins collapse.
#[tokio::test]
async fn ambiguous_tool_argument_string_makes_a_request_call_ungovernable() {
    let plugin = make(json!({
        "mode": "enforce",
        "default_action": "allow",
        "tools": { "run": { "action": "allow", "required_args": ["cmd"] } },
        "inspect": { "a2a_methods": true, "mcp_tool_calls": false, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "run",
            "params": r#"{"cmd":"rm -rf /","cmd":"ls"}"#
        })
        .to_string(),
    );
    let mut headers = json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
}

/// A response body whose objects carry duplicate members cannot be governed:
/// the CLIENT is the first-key-wins parser here.
#[tokio::test]
async fn duplicate_members_in_buffered_response_fail_closed() {
    let plugin = make(json!({
        "mode": "enforce",
        "default_action": "allow",
        "tools": { "danger": { "action": "deny" } }
    }));
    let body = concat!(
        r#"{"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","#,
        r#""tool_calls":[{"id":"c1","type":"function","function":"#,
        r#"{"name":"danger","name":"safe","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#
    );
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), body.as_bytes())
            .await,
        Some(502),
    );
}

/// The duplicate-key verdict cannot depend on `serde_json::Value` accepting the
/// entire body. A valid document can exceed serde's recursive materialization
/// limit while remaining acceptable to a downstream parser; extra nesting must
/// not turn a root duplicate tool name into an unparseable-response bypass.
#[tokio::test]
async fn duplicate_response_stays_fail_closed_past_serde_value_depth_limit() {
    let plugin = make(json!({
        "mode": "enforce",
        "default_action": "allow",
        "tools": { "danger": { "action": "deny" }, "safe": { "action": "allow" } }
    }));
    let depth = 200usize;
    let mut body = String::from(concat!(
        r#"{"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","#,
        r#""tool_calls":[{"id":"c1","type":"function","function":"#,
        r#"{"name":"danger","name":"safe","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"padding":"#
    ));
    for _ in 0..depth {
        body.push('[');
    }
    for _ in 0..depth {
        body.push(']');
    }
    body.push('}');

    assert!(
        serde_json::from_str::<Value>(&body).is_err(),
        "fixture must exceed serde_json::Value's recursive depth limit"
    );
    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), body.as_bytes())
            .await,
        Some(502),
    );
}

/// Dry-run forwards the same body untouched.
#[tokio::test]
async fn duplicate_members_in_buffered_response_are_forwarded_in_dry_run() {
    let plugin = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "danger": { "action": "deny" } }
    }));
    let body = concat!(
        r#"{"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","#,
        r#""tool_calls":[{"id":"c1","type":"function","function":"#,
        r#"{"name":"danger","name":"safe","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#
    );
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), body.as_bytes())
            .await,
    );
    assert_dry_run_ambiguity_observation(&ctx);
    assert_no_metadata_contains(&ctx, "danger");
    assert_no_metadata_contains(&ctx, "safe");
}

/// A response tool call whose `arguments` STRING is ambiguous joins the
/// ungovernable class, exactly like a missing `function.name`.
#[tokio::test]
async fn ambiguous_response_tool_argument_string_fails_closed() {
    let plugin = make(json!({
        "mode": "enforce",
        "default_action": "allow",
        "tools": { "deploy": { "action": "allow", "required_args": ["env"] } }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("deploy", r#"{"env":"prod","env":"dev"}"#);
    assert_reject(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
        Some(502),
    );

    // The unambiguous equivalent still passes.
    let mut clean_ctx = create_test_context();
    let clean = response_with_tool_call("deploy", r#"{"env":"prod"}"#);
    assert_continue(
        plugin
            .on_response_body(&mut clean_ctx, 200, &mut json_headers(), &clean)
            .await,
    );
}

const SSE_DUPLICATE_MEMBER_FRAMES: &str = concat!(
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
    "\"function\":{\"name\":\"danger\",\"name\":\"get_weather\",\"arguments\":\"{}\"}}]}}]}\n\n",
    "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
    "data: [DONE]\n\n"
);

/// A LIVE SSE `data:` payload with duplicate members cuts the stream in enforce
/// mode, and no held frame reaches the client.
#[tokio::test]
async fn live_sse_duplicate_member_frame_cuts_the_stream_in_enforce() {
    let plugin = make(streaming_config(
        json!({ "get_weather": { "action": "allow" }, "danger": { "action": "deny" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let bytes = SSE_DUPLICATE_MEMBER_FRAMES.as_bytes();
    let (first, second) = bytes.split_at(bytes.len() / 2);
    let (out, terminated) = drive_stream(&mut inspector, &[first, second]).await;

    assert!(
        terminated,
        "an ambiguous SSE data payload must cut the stream in enforce mode"
    );
    let text = String::from_utf8_lossy(&out);
    assert!(
        !text.contains("danger"),
        "the ambiguous frame must not be released: {text}"
    );
    assert!(
        !text.contains("get_weather"),
        "held tool-call bytes must not be released: {text}"
    );
}

/// Dry-run releases the same stream unchanged.
#[tokio::test]
async fn live_sse_duplicate_member_frame_is_released_in_dry_run() {
    let mut config = streaming_config(
        json!({ "get_weather": { "action": "allow" }, "danger": { "action": "deny" } }),
        "deny",
    );
    config["mode"] = json!("dry_run");
    let plugin = Arc::new(make(config));
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let mut ctx = create_test_context();
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("stream inspector");
    let bytes = SSE_DUPLICATE_MEMBER_FRAMES.as_bytes();
    let (out, terminated) = drive_stream(&mut inspector, &[bytes]).await;
    assert!(!terminated, "dry-run must not disrupt the stream");
    assert_eq!(out, bytes, "dry-run must forward the body unchanged");
    drop(inspector);
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(out.len() as u64))
        .await;
    assert_dry_run_ambiguity_observation(&ctx);
    assert_no_metadata_contains(&ctx, "danger");
    assert_no_metadata_contains(&ctx, "get_weather");
}

/// The BUFFERED SSE path mirrors the live inspector: the same body delivered
/// buffered is equally ungovernable.
#[tokio::test]
async fn buffered_sse_duplicate_member_frame_fails_closed() {
    let plugin = make(json!({
        "mode": "enforce",
        "default_action": "deny",
        "tools": { "get_weather": { "action": "allow" }, "danger": { "action": "deny" } },
        "inspect": { "response_tool_calls": true, "streaming_response_tool_calls": true }
    }));
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/event-stream".to_string());
    assert_reject(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut headers,
                SSE_DUPLICATE_MEMBER_FRAMES.as_bytes(),
            )
            .await,
        Some(502),
    );
}

/// A JSON-shaped body under an SSE label AND a `Content-Encoding` takes the
/// decode-then-govern branch of `on_response_body`. The DECODED bytes must be
/// screened for duplicate members before they are governed (and before their
/// hash is staged for the terminal re-check): otherwise the plugin evaluates
/// the `serde_json` last-wins view, forwards bytes a first-key-wins client
/// reads as the denied call, and the terminal hook hash-skips them.
#[tokio::test]
async fn encoded_sse_labeled_json_with_duplicate_members_fails_closed() {
    let plugin = make(json!({
        "mode": "enforce",
        "default_action": "allow",
        "tools": { "danger": { "action": "deny" }, "safe": { "action": "allow" } }
    }));
    // The differential is real: serde only ever sees the ALLOWED name.
    let parsed: Value = serde_json::from_str(ENCODED_SSE_AMBIGUOUS_JSON).expect("valid JSON");
    assert_eq!(
        parsed["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
        "safe"
    );

    let mut ctx = create_test_context();
    assert_reject(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut encoded_sse_headers(),
                &gzip(ENCODED_SSE_AMBIGUOUS_JSON.as_bytes()),
            )
            .await,
        Some(502),
    );

    // Control: the same branch still governs normally — the unambiguous
    // equivalent with the allowed call is forwarded, so the rejection above is
    // the duplicate-member screen and not a blanket refusal of this route.
    let clean = ENCODED_SSE_AMBIGUOUS_JSON.replace(r#""name":"danger","#, "");
    let mut clean_ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(
                &mut clean_ctx,
                200,
                &mut encoded_sse_headers(),
                &gzip(clean.as_bytes()),
            )
            .await,
    );
}

/// Dry-run parity on the same encoded, SSE-labeled, JSON-shaped branch: observe
/// without disrupting the response.
#[tokio::test]
async fn encoded_sse_labeled_json_with_duplicate_members_forwards_in_dry_run() {
    let plugin = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "danger": { "action": "deny" }, "safe": { "action": "allow" } }
    }));
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut encoded_sse_headers(),
                &gzip(ENCODED_SSE_AMBIGUOUS_JSON.as_bytes()),
            )
            .await,
    );
    assert_dry_run_ambiguity_observation(&ctx);
}

/// Chat Completions JSON carrying a duplicated `function.name`, mislabeled
/// `text/event-stream` and compressed.
const ENCODED_SSE_AMBIGUOUS_JSON: &str = concat!(
    r#"{"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","#,
    r#""tool_calls":[{"id":"c1","type":"function","function":"#,
    r#"{"name":"danger","name":"safe","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#
);

fn encoded_sse_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/event-stream".to_string());
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers
}

/// Streaming argument deltas reassemble into an ambiguous arguments document:
/// the accumulated string is screened, so the batch is ungovernable and the
/// stream is cut before the held frames are released.
#[tokio::test]
async fn streaming_reassembled_ambiguous_arguments_cut_the_stream() {
    let plugin = make(streaming_config(
        json!({ "run": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"run\",\"arguments\":\"{\\\"cmd\\\":\\\"rm\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,",
        "\"function\":{\"arguments\":\"\\\",\\\"cmd\\\":\\\"ls\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let bytes = body.as_bytes();
    let (out, terminated) = drive_stream(&mut inspector, &[bytes]).await;
    assert!(
        terminated,
        "reassembled ambiguous arguments must cut the stream"
    );
    let text = String::from_utf8_lossy(&out);
    assert!(
        !text.contains("rm"),
        "held ambiguous argument bytes leaked: {text}"
    );
}

/// A JSON-shaped body delivered under an SSE label is held in full and governed
/// at end-of-stream; ambiguity there also cuts the stream rather than releasing
/// the held bytes.
#[tokio::test]
async fn json_shaped_stream_with_duplicate_members_cuts_the_stream() {
    let plugin = make(streaming_config(
        json!({ "danger": { "action": "deny" }, "get_weather": { "action": "allow" } }),
        "deny",
    ));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let body = concat!(
        r#"{"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","#,
        r#""tool_calls":[{"id":"c1","type":"function","function":"#,
        r#"{"name":"danger","name":"get_weather","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#
    );
    let (out, terminated) = drive_stream(&mut inspector, &[body.as_bytes()]).await;
    assert!(
        terminated,
        "an ambiguous JSON-shaped stream must cut the stream in enforce mode"
    );
    assert!(
        !String::from_utf8_lossy(&out).contains("danger"),
        "held JSON body must not be released"
    );
}

/// Two governor instances inspecting the SAME body in the same phase both fail
/// closed. The shared per-request screen memo is a cache, never a decision: it
/// must not let a second plugin inherit a pass.
#[tokio::test]
async fn shared_screen_memo_does_not_let_a_second_plugin_inherit_a_pass() {
    let first = mcp_governor("enforce");
    let second = mcp_governor("enforce");

    // A body large enough to engage the digest-keyed memo path.
    let padding = "x".repeat(8192);
    let clean = format!(
        r#"{{"pad":"{padding}","method":"tools/call","params":{{"name":"safe","arguments":{{}}}}}}"#
    );
    let ambiguous = format!(
        r#"{{"pad":"{padding}","method":"tools/call","params":{{"name":"danger","name":"safe","arguments":{{}}}}}}"#
    );

    // First: a clean body passes both plugins and seeds the memo.
    let mut ctx = json_post_ctx();
    let headers = json_headers();
    assert_continue(
        first
            .on_final_request_body_with_context(&mut ctx, &headers, clean.as_bytes())
            .await,
    );
    assert_continue(
        second
            .on_final_request_body_with_context(&mut ctx, &headers, clean.as_bytes())
            .await,
    );

    // Then a rewritten (ambiguous) body on the SAME context: the memo is keyed
    // on the body digest, so neither plugin inherits the earlier pass.
    let mut ctx = json_post_ctx();
    assert_reject(
        first
            .on_final_request_body_with_context(&mut ctx, &headers, ambiguous.as_bytes())
            .await,
        Some(502),
    );
    let mut ctx = json_post_ctx();
    assert_continue(
        first
            .on_final_request_body_with_context(&mut ctx, &headers, clean.as_bytes())
            .await,
    );
    assert_reject(
        second
            .on_final_request_body_with_context(&mut ctx, &headers, ambiguous.as_bytes())
            .await,
        Some(502),
    );
}

/// Malformed governed JSON keeps its existing handling and never panics; the
/// screen must not reclassify parse failures as ambiguity.
#[tokio::test]
async fn malformed_governed_bodies_do_not_panic() {
    let plugin = mcp_governor("enforce");
    for body in [
        "{",
        "{\"method\":}",
        "{\"method\":\"tools/call\"} trailing",
        "\u{feff}{\"method\":\"tools/call\",\"params\":{\"name\":\"safe\"}}",
    ] {
        let mut ctx = json_post_ctx();
        ctx.metadata
            .insert("request_body".to_string(), body.to_string());
        let mut headers = json_headers();
        // Enforce mode fails closed on ANY uninspectable governed body, so the
        // assertion here is only that it is a controlled rejection.
        assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
    }
}

/// The screen is non-recursive: a pathologically deep governed body is refused
/// on a budget rather than overflowing the stack.
#[tokio::test]
async fn pathologically_deep_governed_body_is_refused_without_stack_overflow() {
    let plugin = mcp_governor("enforce");
    let depth = 50_000usize;
    let mut body = String::with_capacity(depth * 2 + 64);
    body.push_str(r#"{"method":"tools/call","params":{"name":"safe","arguments":"#);
    for _ in 0..depth {
        body.push('[');
    }
    for _ in 0..depth {
        body.push(']');
    }
    body.push_str("}}");
    let mut ctx = json_post_ctx();
    ctx.metadata.insert("request_body".to_string(), body);
    let mut headers = json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
}

/// Final backend-visible request ambiguity: dry-run forwards and records the
/// fixed observation; enforce still rejects.
#[tokio::test]
async fn final_request_duplicate_members_are_observed_in_dry_run() {
    let enforce = mcp_governor("enforce");
    let mut enforce_ctx = json_post_ctx();
    assert_reject(
        enforce
            .on_final_request_body_with_context(
                &mut enforce_ctx,
                &json_headers(),
                MCP_DUPLICATE_TOOL_NAME.as_bytes(),
            )
            .await,
        Some(502),
    );

    let plugin = mcp_governor("dry_run");
    let mut ctx = json_post_ctx();
    let body = MCP_DUPLICATE_TOOL_NAME.as_bytes();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), body)
            .await,
    );
    assert_dry_run_ambiguity_observation(&ctx);
    assert_no_metadata_contains(&ctx, "danger");
}

/// Trailing-event Ambiguous arm: an incomplete final `data:` event with
/// duplicate members is classified only at `on_end`. Dry-run forwards it and
/// records the observation; enforce cuts.
#[tokio::test]
async fn trailing_sse_duplicate_member_frame_is_observed_in_dry_run() {
    // Complete stop event, then an ambiguous payload left in the carry (no
    // trailing blank line) so classification happens in `on_end`.
    let trailing = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"danger\",\"name\":\"safe\",\"arguments\":\"{}\"}}]}}]}"
    );

    let enforce = make(streaming_config(
        json!({ "safe": { "action": "allow" }, "danger": { "action": "deny" } }),
        "deny",
    ));
    let enforce_ctx = create_test_context();
    let mut enforce_inspector = enforce
        .response_stream_inspector(&enforce_ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (enforce_out, enforce_terminated) =
        drive_stream(&mut enforce_inspector, &[trailing.as_bytes()]).await;
    assert!(
        enforce_terminated,
        "trailing ambiguous event must cut the stream in enforce"
    );
    assert!(
        !String::from_utf8_lossy(&enforce_out).contains("danger"),
        "enforce must not release the ambiguous trailing frame"
    );

    let mut config = streaming_config(
        json!({ "safe": { "action": "allow" }, "danger": { "action": "deny" } }),
        "deny",
    );
    config["mode"] = json!("dry_run");
    let plugin = Arc::new(make(config));
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let mut ctx = create_test_context();
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("stream inspector");
    let bytes = trailing.as_bytes();
    let (out, terminated) = drive_stream(&mut inspector, &[bytes]).await;
    assert!(!terminated, "dry-run must not cut on trailing ambiguity");
    assert_eq!(out, bytes, "dry-run must forward trailing bytes unchanged");
    drop(inspector);
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(out.len() as u64))
        .await;
    assert_dry_run_ambiguity_observation(&ctx);
    assert_no_metadata_contains(&ctx, "danger");
}

/// Fully-held JSON-shaped stream with duplicate members: dry-run forwards
/// byte-for-byte and records the fixed observation; enforce cuts.
#[tokio::test]
async fn json_shaped_stream_duplicate_members_are_observed_in_dry_run() {
    let body = concat!(
        r#"{"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","#,
        r#""tool_calls":[{"id":"c1","type":"function","function":"#,
        r#"{"name":"danger","name":"get_weather","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#
    );

    let enforce = make(streaming_config(
        json!({ "danger": { "action": "deny" }, "get_weather": { "action": "allow" } }),
        "deny",
    ));
    let enforce_ctx = create_test_context();
    let mut enforce_inspector = enforce
        .response_stream_inspector(&enforce_ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (enforce_out, enforce_terminated) =
        drive_stream(&mut enforce_inspector, &[body.as_bytes()]).await;
    assert!(enforce_terminated);
    assert!(!String::from_utf8_lossy(&enforce_out).contains("danger"));

    let mut config = streaming_config(
        json!({ "danger": { "action": "deny" }, "get_weather": { "action": "allow" } }),
        "deny",
    );
    config["mode"] = json!("dry_run");
    let plugin = Arc::new(make(config));
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let mut ctx = create_test_context();
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("stream inspector");
    let bytes = body.as_bytes();
    let (out, terminated) = drive_stream(&mut inspector, &[bytes]).await;
    assert!(
        !terminated,
        "dry-run must not cut a JSON-shaped ambiguous body"
    );
    assert_eq!(out, bytes, "dry-run must forward the held JSON unchanged");
    drop(inspector);
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(out.len() as u64))
        .await;
    assert_dry_run_ambiguity_observation(&ctx);
    assert_no_metadata_contains(&ctx, "danger");
}

/// String-form tool argument ambiguity on the request path: dry-run forwards
/// and records the observation; enforce rejects.
#[tokio::test]
async fn ambiguous_tool_argument_string_is_observed_in_dry_run() {
    let config = json!({
        "mode": "dry_run",
        "default_action": "allow",
        "tools": { "run": { "action": "allow", "required_args": ["cmd"] } },
        "inspect": { "a2a_methods": true, "mcp_tool_calls": false, "response_tool_calls": false }
    });
    let plugin = make(config);
    let mut ctx = json_post_ctx();
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "run",
        "params": r#"{"cmd":"rm -rf /","cmd":"ls"}"#
    })
    .to_string();
    ctx.metadata
        .insert("request_body".to_string(), body.clone());
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_dry_run_ambiguity_observation(&ctx);
    assert_no_governor_metadata_contains(&ctx, "rm -rf");
    assert_no_governor_metadata_contains(&ctx, "SHIBBOLETH");

    let enforce = make(json!({
        "mode": "enforce",
        "default_action": "allow",
        "tools": { "run": { "action": "allow", "required_args": ["cmd"] } },
        "inspect": { "a2a_methods": true, "mcp_tool_calls": false, "response_tool_calls": false }
    }));
    let mut enforce_ctx = json_post_ctx();
    enforce_ctx
        .metadata
        .insert("request_body".to_string(), body);
    let mut enforce_headers = json_headers();
    assert_reject(
        enforce
            .before_proxy(&mut enforce_ctx, &mut enforce_headers)
            .await,
        Some(502),
    );
}

/// Streaming reassembled argument string with duplicate members: dry-run
/// releases held frames and records the observation; enforce cuts.
#[tokio::test]
async fn streaming_reassembled_ambiguous_arguments_are_observed_in_dry_run() {
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"run\",\"arguments\":\"{\\\"cmd\\\":\\\"rm\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,",
        "\"function\":{\"arguments\":\"\\\",\\\"cmd\\\":\\\"ls\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );

    let enforce = make(streaming_config(
        json!({ "run": { "action": "allow" } }),
        "deny",
    ));
    let enforce_ctx = create_test_context();
    let mut enforce_inspector = enforce
        .response_stream_inspector(&enforce_ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (enforce_out, enforce_terminated) =
        drive_stream(&mut enforce_inspector, &[body.as_bytes()]).await;
    assert!(enforce_terminated);
    assert!(!String::from_utf8_lossy(&enforce_out).contains("rm"));

    let mut config = streaming_config(json!({ "run": { "action": "allow" } }), "deny");
    config["mode"] = json!("dry_run");
    let plugin = Arc::new(make(config));
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let mut ctx = create_test_context();
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("stream inspector");
    let bytes = body.as_bytes();
    let (out, terminated) = drive_stream(&mut inspector, &[bytes]).await;
    assert!(
        !terminated,
        "dry-run must release reassembled ambiguous args"
    );
    assert_eq!(out, bytes, "dry-run must forward held frames unchanged");
    drop(inspector);
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(out.len() as u64))
        .await;
    assert_dry_run_ambiguity_observation(&ctx);
    assert_no_metadata_contains(&ctx, "rm");
    assert_no_metadata_contains(&ctx, "ls");
}

/// Multiple mid-stream ambiguous frames must not grow metadata cardinality.
#[tokio::test]
async fn multiple_sse_ambiguous_frames_keep_fixed_observation_cardinality() {
    let frames = concat!(
        "data: {\"a\":1,\"a\":2}\n\n",
        "data: {\"b\":1,\"b\":2}\n\n",
        "data: {\"c\":1,\"c\":2}\n\n",
        "data: [DONE]\n\n"
    );
    let mut config = streaming_config(json!({}), "deny");
    config["mode"] = json!("dry_run");
    let plugin = Arc::new(make(config));
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let mut ctx = create_test_context();
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("stream inspector");
    let bytes = frames.as_bytes();
    let (out, terminated) = drive_stream(&mut inspector, &[bytes]).await;
    assert!(!terminated);
    assert_eq!(out, bytes);
    drop(inspector);
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(out.len() as u64))
        .await;
    assert_dry_run_ambiguity_observation(&ctx);
    let reason = ctx
        .metadata
        .get(AMBIGUITY_REASON_KEY)
        .expect("reason present");
    assert_eq!(reason, AMBIGUITY_REASON_VALUE);
    assert!(
        !reason.contains(','),
        "repeated ambiguous frames must not grow reason cardinality: {reason}"
    );
}

/// Buffered SSE duplicate-member frame: dry-run forwards and records the
/// fixed observation (parity with the live inspector).
#[tokio::test]
async fn buffered_sse_duplicate_member_frame_is_observed_in_dry_run() {
    let plugin = make(json!({
        "mode": "dry_run",
        "default_action": "deny",
        "tools": { "get_weather": { "action": "allow" }, "danger": { "action": "deny" } },
        "inspect": { "response_tool_calls": true, "streaming_response_tool_calls": true }
    }));
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/event-stream".to_string());
    assert_continue(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut headers,
                SSE_DUPLICATE_MEMBER_FRAMES.as_bytes(),
            )
            .await,
    );
    assert_dry_run_ambiguity_observation(&ctx);
    assert_no_metadata_contains(&ctx, "danger");
}
