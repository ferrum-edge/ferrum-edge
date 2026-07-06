//! Tests for the ai_tool_governor plugin.

use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, RequestContext, ResponseStreamAction, ResponseStreamInspector,
    ai_tool_governor::AiToolGovernor, available_plugins, create_plugin_with_http_client, priority,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use wiremock::matchers::{method, path};
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
        .transform_response_body(&body, Some("application/json"), &json_headers())
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
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
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
async fn allows_request_exposing_only_permitted_tools() {
    let plugin = make(json!({
        "default_action": "deny",
        "tools": { "github.create_pr": { "action": "allow" } },
        "inspect": { "request_tool_definitions": true, "response_tool_calls": false }
    }));
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
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
