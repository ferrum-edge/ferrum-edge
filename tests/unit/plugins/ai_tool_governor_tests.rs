//! Tests for the ai_tool_governor plugin.

use ferrum_edge::{
    config::{BackendAllowIps, BackendEgressPolicy},
    plugins::{
        Plugin, PluginHttpClient, RequestContext, ResponseStreamAction, ResponseStreamInspector,
        ai_tool_governor::AiToolGovernor, available_plugins, create_plugin_with_http_client,
        priority,
    },
};
use serde_json::{Value, json};
use std::collections::HashMap;
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
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_reject(result, Some(502));
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
        Some(502),
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
        Some(502),
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
        Some(502),
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
            .on_response_body(&mut ctx, 200, &json_headers(), &ok)
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
            .on_response_body(&mut ctx, 200, &json_headers(), &bad)
            .await,
        Some(502),
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
        Some(502),
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
            .on_response_body(&mut ctx, 500, &json_headers(), &body)
            .await,
    );

    // Non-JSON content-type: not inspected.
    let mut html = HashMap::new();
    html.insert("content-type".to_string(), "text/html".to_string());
    let mut ctx = create_test_context();
    assert_continue(plugin.on_response_body(&mut ctx, 200, &html, &body).await);
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
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

    // The transform rewrites the secret out of the delivered body.
    let transformed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await
        .expect("body is rewritten");
    let text = String::from_utf8(transformed).unwrap();
    assert!(!text.contains("SUPERSECRET"), "secret leaked: {text}");
    assert!(
        text.contains("[REDACTED_TOOL_ARG:secret]"),
        "placeholder missing: {text}"
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    );
    let transformed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await
        .expect("structured arguments are redacted");
    let text = String::from_utf8(transformed).unwrap();
    assert!(!text.contains("STRUCTUREDSECRET"), "secret leaked: {text}");
    assert!(text.contains("[REDACTED_TOOL_ARG:secret]"), "{text}");
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
            .await
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
            .await
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(502));
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
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
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
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
        Some(502),
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
                .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
    ctx.headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "64".to_string());
    let mut headers = HashMap::new();
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

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
}

#[tokio::test]
async fn dry_run_forwards_content_encoded_request_body() {
    let plugin = make(mcp_config("dry_run"));
    let mut ctx = json_post_ctx();
    ctx.headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "64".to_string());
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
}

#[tokio::test]
async fn enforce_rejects_unparseable_json_request_body() {
    let plugin = make(mcp_config("enforce"));
    let mut ctx = json_post_ctx();
    ctx.metadata
        .insert("request_body".to_string(), "not-json{{{".to_string());
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
}

#[tokio::test]
async fn non_json_posts_are_not_rejected() {
    // The fail-closed rules are scoped to the JSON POSTs this plugin governs.
    let plugin = make(mcp_config("enforce"));
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "text/plain".to_string());
    ctx.headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "64".to_string());
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
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
    let mut headers = HashMap::new();

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
async fn uninspectable_body_conservatively_forces_reqwest_when_streaming_only() {
    // Streaming-only configs never reject, but an uninspectable body may hide
    // `stream: true`, so the request must stay on the inspectable path.
    let plugin = make(streaming_config(
        json!({ "x": { "action": "allow" } }),
        "deny",
    ));
    let mut ctx = json_post_ctx();
    ctx.headers
        .insert("content-encoding".to_string(), "br".to_string());
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "64".to_string());
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(plugin.forces_reqwest_dispatch(&ctx));
}

#[test]
fn streaming_marked_requests_still_buffer_json_fallbacks() {
    // An earlier plugin's `ai_request_streaming` marker (or an SSE Accept
    // header) must not opt the response out of buffering pre-header: the
    // backend may answer with plain JSON tool_calls. Content-type refinement
    // releases only genuine event streams back to the stream path.
    let plugin = make(json!({ "tools": { "kubectl.apply": { "action": "deny" } } }));

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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &headers, &body)
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
            .on_response_body(&mut ctx, 200, &headers, b"not-json-gzip-bytes")
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
            .on_response_body(&mut ctx, 200, &json_headers(), &openai)
            .await,
    );

    let mut ctx = create_test_context();
    let anthropic = anthropic_shaped_response_with_tool_call("deploy", "{\"env\":\"prod\"}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &json_headers(), &anthropic)
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
        Some(502),
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
        Some(502),
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
            .on_response_body(&mut ctx, 200, &json_headers(), &clean)
            .await,
    );

    // A later transform injects a denied tool call.
    let injected = response_with_tool_call("kubectl.apply", "{\"manifest\":\"kind: Pod\"}");
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &injected)
            .await,
        Some(502),
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &json_headers(), &clean)
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
            .on_response_body(&mut ctx, 200, &json_headers(), &a)
            .await,
    );

    let b = response_with_tool_call("report\u{1}b", "c");
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &json_headers(), &b)
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
            .on_response_body(&mut ctx, 200, &json_headers(), &clean)
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

    // Non-JSON content type.
    let mut ctx = create_test_context();
    let mut html = HashMap::new();
    html.insert("content-type".to_string(), "text/html".to_string());
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &html, &denied)
            .await,
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

/// An A2A JSON-RPC method governed by a `deny` policy is rejected on the request.
#[tokio::test]
async fn a2a_method_deny_rejects() {
    let plugin = make(json!({
        "tools": { "message/send": { "action": "deny" } },
        "inspect": { "a2a_methods": true, "response_tool_calls": false }
    }));
    let mut ctx = json_post_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": { "foo": "bar" } })
            .to_string(),
    );
    let mut headers = json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(502));
}

/// A per-tool `dry_run` action forwards the call while recording an `allow`
/// observational decision even when the plugin mode is `enforce`.
#[tokio::test]
async fn per_tool_dry_run_action_allows_and_labels() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "report.read": { "action": "dry_run" } }
    }));
    let mut ctx = create_test_context();
    let body = response_with_tool_call("report.read", "{}");
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("allow")
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
                .on_response_body(&mut ctx, 200, &json_headers(), &body)
                .await,
            Some(502),
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
            .on_response_body(&mut ctx, 200, &json_headers(), &absent)
            .await,
    );

    let empty = response_tool_call_model("deploy", "{}", Some(""));
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &json_headers(), &empty)
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
    // Per-request: buffer only a streaming request's response (its SSE-JSON
    // fallback), not an ordinary non-streaming response.
    let mut streaming = create_test_context();
    streaming
        .metadata
        .insert("ai_request_streaming".to_string(), "true".to_string());
    assert!(plugin.should_buffer_response_body(&streaming));
    assert!(!plugin.should_buffer_response_body(&create_test_context()));
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
            .on_response_body(&mut ctx, 200, &json_headers(), &denied)
            .await,
        Some(502),
    );

    // Non-streaming request: buffered response inspection is disabled, so the
    // ordinary JSON response is not governed.
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &json_headers(), &denied)
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
            .on_response_body(&mut ctx, 200, &json_headers(), &clean)
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
            .on_response_body(&mut ctx, 200, &json_headers(), &clean)
            .await,
    );

    let injected = response_with_tool_call("kubectl.apply", "{\"manifest\":\"kind: Pod\"}");
    let compressed = gzip(&injected);
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &gzip_headers(), &compressed)
            .await,
        Some(502),
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
            .on_response_body(&mut ctx, 200, &json_headers(), &clean)
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("ai_tool_governor.decision")
            .map(String::as_str),
        Some("allow")
    );
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &json_headers(), &clean)
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
            .on_response_body(&mut ctx, 200, &sse_headers, denied.as_bytes())
            .await,
        Some(502),
    );

    let allowed = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
        "\"function\":{\"name\":\"report.read\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let mut ctx = create_test_context();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &sse_headers, allowed.as_bytes())
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
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
    let plugin = make(streaming_config(json!({}), "deny"));
    let ctx = create_test_context();
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let (_out, terminated) =
        drive_stream(&mut inspector, &[SSE_UNNAMED_TOOL_FRAMES.as_bytes()]).await;
    assert!(
        terminated,
        "ungovernable tool-call frames must cut the stream in enforce mode"
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    ); // webhook #1 + marks redaction
    let transformed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    );
    let transformed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await
        .expect("redacted body");
    // The placeholder embeds "token" but the final re-check must forward, not 502.
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), &transformed)
            .await,
    );
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
            .on_response_body(&mut ctx, 200, &sse_headers, body.as_bytes())
            .await,
        Some(502),
    );
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
        Some(502),
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
            .on_response_body(&mut ctx, 200, &headers, &body)
            .await,
        Some(502),
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
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    );
    let redacted = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/json"),
            &json_headers(),
        )
        .await
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
