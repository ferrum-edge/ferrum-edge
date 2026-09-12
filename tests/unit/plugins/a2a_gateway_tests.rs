use bytes::Bytes;
use ferrum_edge::plugins::{
    HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, RequestContext, ResponsePresentationPolicy,
    ResponseStreamAction, create_plugin, create_response_stream_inspector,
    utils::metadata_redaction::is_sensitive_metadata_key_with_extras,
};
use ferrum_edge::proxy::deferred_log::BodyOutcome;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

fn plugin(mut config: Value) -> std::sync::Arc<dyn ferrum_edge::plugins::Plugin> {
    // Ordinary fixtures explicitly publish this front door. Admission failures
    // are tested through create_plugin directly, without fixture defaults.
    if config.get("discovery").is_none() {
        config["discovery"] = json!({"public_base_url": "https://gateway.example.com"});
    }
    create_plugin("a2a_gateway", &config)
        .expect("a2a_gateway config should be valid")
        .expect("a2a_gateway should be registered")
}

/// Run the HTTP JSON Agent Card lifecycle the proxy runs: admission in
/// `on_response_body`, then bounded production in the response transform phase.
///
/// The rewrite deliberately does not happen inside `on_response_body` any more:
/// the replacement is built through the retained-response sink inside the
/// producer window (`GHSA-r423-f5mr-83x2`). `Err` carries a terminal the
/// admission phase selected; `Ok(None)` means the card needed no rewrite.
async fn http_card_rewrite(
    plugin: &Arc<dyn Plugin>,
    ctx: &mut RequestContext,
    response_headers: &mut HashMap<String, String>,
    body: &str,
) -> Result<Option<Value>, PluginResult> {
    let admitted = plugin
        .on_response_body(ctx, 200, response_headers, body.as_bytes())
        .await;
    if !matches!(admitted, PluginResult::Continue) {
        return Err(admitted);
    }
    let content_type = response_headers.get("content-type").cloned();
    let transformed = plugin
        .transform_response_body_with_context(
            ctx,
            body.as_bytes(),
            content_type.as_deref(),
            response_headers,
        )
        .await;
    Ok(transformed.map(|bytes| {
        serde_json::from_slice(&bytes).expect("rewritten agent card should be valid JSON")
    }))
}

/// The rewritten card, or a panic naming what went wrong instead.
async fn expect_http_card_rewrite(
    plugin: &Arc<dyn Plugin>,
    ctx: &mut RequestContext,
    response_headers: &mut HashMap<String, String>,
    body: &str,
) -> Value {
    match http_card_rewrite(plugin, ctx, response_headers, body).await {
        Ok(Some(rewritten)) => rewritten,
        Ok(None) => panic!("agent card rewrite should replace the response body"),
        Err(_) => panic!("agent card rewrite should not have been refused"),
    }
}

fn jsonrpc_ctx(body: Value) -> (RequestContext, HashMap<String, String>) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/a2a".to_string(),
    );
    ctx.request_body_bytes = Some(Bytes::from(body.to_string()));
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    let headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("accept-encoding".to_string(), "gzip".to_string()),
    ]);
    (ctx, headers)
}

fn jsonrpc_ctx_with_raw_body(body: String) -> (RequestContext, HashMap<String, String>) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/a2a".to_string(),
    );
    ctx.request_body_bytes = Some(Bytes::from(body));
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    (ctx, headers)
}

fn rest_ctx(method: &str, path: &str) -> (RequestContext, HashMap<String, String>) {
    (
        RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            path.to_string(),
        ),
        HashMap::new(),
    )
}

fn grpc_ctx(rpc: &str, content_type: &str) -> (RequestContext, HashMap<String, String>) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        format!("/a2a.v1.A2AService/{rpc}"),
    );
    ctx.headers
        .insert("content-type".to_string(), content_type.to_string());
    let headers = ctx.headers.clone();
    (ctx, headers)
}

#[test]
fn a2a_gateway_registers_with_http_and_grpc_protocols() {
    let plugin = plugin(json!({}));
    assert_eq!(plugin.name(), "a2a_gateway");
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
    assert!(ferrum_edge::plugins::available_plugins().contains(&"a2a_gateway"));
}

#[test]
fn a2a_gateway_valid_transparent_config_constructs() {
    let plugin = create_plugin(
        "a2a_gateway",
        &json!({ "mode": "transparent_proxy", "discovery": {"rewrite_agent_card_urls": false} }),
    )
    .expect("valid a2a_gateway config should construct")
    .expect("a2a_gateway should be registered");
    assert_eq!(plugin.name(), "a2a_gateway");
}

#[test]
fn a2a_gateway_rejects_unknown_root_key() {
    let error = create_plugin(
        "a2a_gateway",
        &json!({
            "mode": "transparent_proxy",
            "not_a_real_a2a_key": true
        }),
    )
    .err()
    .expect("unknown root key must fail closed");
    assert!(error.contains("unknown configuration key"), "{error}");
    assert!(error.contains("not_a_real_a2a_key"), "{error}");
}

#[tokio::test]
async fn jsonrpc_request_emits_metadata_and_strips_accept_encoding() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "message/send",
        "params": {
            "taskId": "task-1"
        }
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("a2a.binding").map(String::as_str),
        Some("jsonrpc")
    );
    assert_eq!(
        ctx.metadata.get("a2a.method").map(String::as_str),
        Some("message/send")
    );
    assert_eq!(
        ctx.metadata.get("a2a.task_id").map(String::as_str),
        Some("task-1")
    );
    assert!(!headers.contains_key("accept-encoding"));
}

#[tokio::test]
async fn jsonrpc_policy_deny_preserves_request_id() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-2",
        "method": "message/send"
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!("policy deny should reject");
    };
    assert_eq!(status_code, 200);
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(body["id"], "req-2");
    assert_eq!(body["error"]["data"]["gateway"], "a2a_gateway");
}

#[tokio::test]
async fn jsonrpc_batch_policy_deny_rejects_denied_member() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!([
        {
            "jsonrpc": "2.0",
            "id": "req-allowed",
            "method": "tasks/get"
        },
        {
            "jsonrpc": "2.0",
            "id": "req-denied",
            "method": "message/send"
        }
    ]));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!("batch containing a denied JSON-RPC method should reject");
    };
    assert_eq!(status_code, 200);
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    let responses = body
        .as_array()
        .expect("batch denial should be wrapped in a JSON-RPC batch response");
    // The refusal dispatches no member, so every non-notification member needs a
    // Response object it can be correlated against — not only the denied one.
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], "req-allowed");
    assert_eq!(responses[0]["error"]["code"], -32001);
    assert!(responses[0]["error"]["data"]["method"].is_null());
    assert_eq!(responses[1]["id"], "req-denied");
    assert_eq!(responses[1]["error"]["data"]["method"], "message/send");
    assert_eq!(
        ctx.metadata.get("a2a.policy_decision").map(String::as_str),
        Some("deny")
    );
}

#[tokio::test]
async fn jsonrpc_batch_policy_deny_rejects_uninspectable_member() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!([
        {
            "jsonrpc": "2.0",
            "id": "req-allowed",
            "method": "tasks/get"
        },
        "not-an-envelope"
    ]));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!("uninspectable batch with method policy should reject");
    };
    assert_eq!(status_code, 200);
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    let responses = body
        .as_array()
        .expect("uninspectable batch should be wrapped in a JSON-RPC batch response");
    // The valid member is still a request the gateway refused without
    // dispatching, so it gets its own Response object. The bare string member
    // carries no id and is not answerable.
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["id"], "req-allowed");
    assert_eq!(responses[0]["error"]["data"]["method"], "unknown");
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("request_body_uninspectable")
    );
}

#[tokio::test]
async fn jsonrpc_single_method_without_version_fails_closed_when_policy_denies() {
    // A single (non-batch) body that carries a JSON-RPC `method` but omits a
    // valid `jsonrpc: "2.0"` envelope must not slip past a deny policy by being
    // treated as "not A2A". It fails closed exactly as a batch member would.
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "id": "req-malformed",
        "method": "message/send"
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!(
            "single method-bearing body with a malformed envelope should reject under a deny policy"
        );
    };
    assert_eq!(status_code, 200);
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    // A single (non-batch) denial is a bare object, not a batch array.
    assert!(!body.is_array());
    assert_eq!(body["error"]["data"]["method"], "unknown");
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("request_body_uninspectable")
    );
}

#[tokio::test]
async fn jsonrpc_single_body_without_method_is_denied_under_deny_policy() {
    // The endpoint belongs to A2A. An unclassified body cannot establish
    // compliance with its operation policy.
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({ "foo": "bar" }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "a method-less body cannot prove compliance with an operation deny rule"
    );
}

#[tokio::test]
async fn jsonrpc_pascalcase_method_is_detected_and_policy_normalized() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "SendMessage": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-pascal",
        "method": "SendMessage",
        "params": {
            "id": "task-1"
        }
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject { body, .. } = result else {
        panic!("PascalCase JSON-RPC method should be denied by normalized policy");
    };
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(body["error"]["data"]["method"], "message/send");
    assert_eq!(
        ctx.metadata.get("a2a.method").map(String::as_str),
        Some("message/send")
    );
}

#[tokio::test]
async fn jsonrpc_detection_accepts_case_insensitive_json_suffix() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-json-suffix",
        "method": "SendMessage"
    }));
    ctx.headers.insert(
        "content-type".to_string(),
        "application/A2A+JSON".to_string(),
    );
    headers.insert(
        "content-type".to_string(),
        "application/A2A+JSON".to_string(),
    );

    assert!(plugin.should_buffer_request_body(&ctx));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("a2a.method").map(String::as_str),
        Some("message/send")
    );
}

#[tokio::test]
async fn rest_agent_card_response_rewrites_gateway_urls() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/agents/planner/.well-known/agent-card.json".to_string(),
    );
    let mut request_headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "description": "planning agent",
        "preferredTransport": "GRPC",
        "url": "https://planner.internal/grpc",
        "agentCardUrl": "https://planner.internal/.well-known/agent-card.json",
        "signatures": [{"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "stale"}],
        "additionalInterfaces": [
            {"transport": "JSONRPC", "url": "https://planner.internal/a2a"},
            {"transport": "GRPC", "url": "https://planner.internal/grpc"}
        ]
    })
    .to_string();

    let body = expect_http_card_rewrite(&plugin, &mut ctx, &mut response_headers, &body).await;
    assert_eq!(body["url"], "https://planner.internal/grpc");
    assert_eq!(
        body["additionalInterfaces"][0]["url"],
        "https://gateway.example.com/a2a"
    );
    assert_eq!(
        body["additionalInterfaces"][1]["url"],
        "https://planner.internal/grpc"
    );
    assert_eq!(
        body["agentCardUrl"],
        "https://gateway.example.com/agents/planner/.well-known/agent-card.json"
    );
    assert!(body.get("signatures").is_none());
}

#[tokio::test]
async fn grpc_a2a_method_is_detected_without_request_buffering() {
    let plugin = plugin(json!({}));
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/a2a.v1.A2AService/SendStreamingMessage".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    let mut headers = ctx.headers.clone();

    assert!(!plugin.should_buffer_request_body(&ctx));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("a2a.binding").map(String::as_str),
        Some("grpc")
    );
    assert_eq!(
        ctx.metadata.get("a2a.method").map(String::as_str),
        Some("message/stream")
    );
    assert_eq!(
        ctx.metadata.get("a2a.streaming").map(String::as_str),
        Some("true")
    );
    assert!(!plugin.should_buffer_response_body(&ctx));
    assert!(!plugin.forces_reqwest_dispatch(&ctx));
}

#[tokio::test]
async fn jsonrpc_agent_card_response_rewrites_gateway_urls() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-card",
        "method": "GetExtendedAgentCard",
        "params": {}
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.should_buffer_response_body(&ctx));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "jsonrpc": "2.0",
        "id": "req-card",
        "result": {
            "name": "planner",
            "description": "planning agent",
            "signatures": [{"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "stale"}],
            "supported_interfaces": [
                {
                    "protocol_binding": "JSONRPC",
                    "protocol_version": "0.3",
                    "url": "https://planner.internal/a2a"
                },
                {
                    "protocol_binding": "GRPC",
                    "protocol_version": "0.3",
                    "url": "https://planner.internal/grpc"
                }
            ]
        }
    })
    .to_string();

    let body = expect_http_card_rewrite(&plugin, &mut ctx, &mut response_headers, &body).await;
    let result = &body["result"];
    assert!(result.get("url").is_none());
    assert_eq!(
        result["supported_interfaces"][0]["url"],
        "https://gateway.example.com/a2a"
    );
    assert_eq!(
        result["supported_interfaces"][1]["url"],
        "https://planner.internal/grpc"
    );
    assert!(result.get("signatures").is_none());
}

#[tokio::test]
async fn agent_card_rewrite_still_runs_when_metadata_is_disabled() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        },
        "observability": {
            "emit_metadata": false
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.is_empty());
    assert!(plugin.should_buffer_response_body(&ctx));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let body = expect_http_card_rewrite(&plugin, &mut ctx, &mut response_headers, &body).await;
    assert_eq!(body["url"], "https://gateway.example.com/a2a");
    assert!(ctx.metadata.is_empty());
}

#[tokio::test]
async fn non_agent_card_response_shape_is_not_rewritten() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut request_headers) = rest_ctx("GET", "/a2a/v1/tasks/task-1");

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "task-shaped-custom-payload",
        "url": "https://backend.example.com/not-an-agent-card",
        "id": "task-1"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn invalid_forwarded_origin_does_not_rewrite_agent_card() {
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true,
            "allowed_public_origins": ["https://gateway.example.com"]
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");
    // The request hook's own header map is what the origin is resolved from —
    // the core moves headers off the context when nothing mutates them.
    request_headers.insert("x-forwarded-proto".to_string(), "javascript".to_string());
    request_headers.insert("host".to_string(), "gateway.example.com".to_string());
    ctx.headers.clone_from(&request_headers);

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 502,
            ..
        }
    ));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 502,
            ..
        }
    ));
}

#[tokio::test]
async fn response_host_is_not_used_for_agent_card_public_rewrite() {
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true,
            "allowed_public_origins": ["https://gateway.example.com"]
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 502,
            ..
        }
    ));

    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("host".to_string(), "backend.example.com".to_string()),
    ]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 502,
            ..
        }
    ));
}

#[tokio::test]
async fn trusted_forwarded_origin_rewrites_agent_card_url() {
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true,
            "allowed_public_origins": ["https://gateway.example.com"]
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");
    request_headers.insert("x-forwarded-proto".to_string(), "https".to_string());
    request_headers.insert(
        "x-forwarded-host".to_string(),
        "gateway.example.com".to_string(),
    );

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.should_buffer_response_body(&ctx));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let body = expect_http_card_rewrite(&plugin, &mut ctx, &mut response_headers, &body).await;
    assert_eq!(body["url"], "https://gateway.example.com/a2a");
}

#[tokio::test]
async fn trusted_host_header_rewrites_agent_card_url_without_forwarded_host() {
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true,
            "allowed_public_origins": ["https://gateway.example.com"]
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");
    request_headers.insert("x-forwarded-proto".to_string(), "https".to_string());
    request_headers.insert("host".to_string(), "gateway.example.com".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let body = expect_http_card_rewrite(&plugin, &mut ctx, &mut response_headers, &body).await;
    assert_eq!(body["url"], "https://gateway.example.com/a2a");
}

#[tokio::test]
async fn agent_card_rewrite_strips_stale_body_coupled_headers() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    // Mixed-case header names exercise the case-insensitive strip.
    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("Content-Length".to_string(), "128".to_string()),
        ("Content-Encoding".to_string(), "gzip".to_string()),
        ("ETag".to_string(), "\"abc123\"".to_string()),
        (
            "Last-Modified".to_string(),
            "Wed, 21 Oct 2026 07:28:00 GMT".to_string(),
        ),
        (
            "Content-Digest".to_string(),
            "sha-256=:deadbeef:".to_string(),
        ),
        ("Cache-Control".to_string(), "max-age=300".to_string()),
    ]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let rewritten = expect_http_card_rewrite(&plugin, &mut ctx, &mut response_headers, &body).await;
    assert_eq!(rewritten["url"], "https://gateway.example.com/a2a");
    // The core runs this immediately after installing a transform's output.
    plugin.on_response_body_transformed(&mut ctx, &mut response_headers);

    // Validators, integrity digests, and the content encoding describe the
    // backend body and no longer match the re-serialized (uncompressed) card,
    // so they must be dropped on rewrite.
    for stale in [
        "content-length",
        "content-encoding",
        "etag",
        "last-modified",
        "content-digest",
    ] {
        assert!(
            !response_headers
                .keys()
                .any(|key| key.eq_ignore_ascii_case(stale)),
            "expected {stale} to be stripped after rewrite, got {response_headers:?}"
        );
    }
    // Headers unrelated to the body are preserved, as is the backend's own JSON
    // content type: the rewrite changes the document, not its media type.
    assert!(
        response_headers
            .keys()
            .any(|key| key.eq_ignore_ascii_case("cache-control"))
    );
    assert_eq!(
        response_headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
}

#[tokio::test]
async fn oversized_jsonrpc_body_fails_closed_when_policy_can_deny() {
    let plugin = plugin(json!({
        "detection": {
            "max_request_body_size": 16
        },
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let body = json!({
        "jsonrpc": "2.0",
        "id": "req-oversized",
        "method": "message/send",
        "params": {"padding": "this body is intentionally too large"}
    })
    .to_string();
    let (mut ctx, mut headers) = jsonrpc_ctx_with_raw_body(body);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!("oversized policy candidate should reject");
    };
    assert_eq!(status_code, 413);
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(body["error"]["data"]["method"], "unknown");
    assert_eq!(
        ctx.metadata.get("a2a.policy_decision").map(String::as_str),
        Some("deny")
    );
}

#[tokio::test]
async fn oversized_jsonrpc_body_continues_when_policy_cannot_deny() {
    let plugin = plugin(json!({
        "detection": {
            "max_request_body_size": 16
        }
    }));
    let body = json!({
        "jsonrpc": "2.0",
        "id": "req-oversized",
        "method": "message/send",
        "params": {"padding": "this body is intentionally too large"}
    })
    .to_string();
    let (mut ctx, mut headers) = jsonrpc_ctx_with_raw_body(body);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("a2a.enabled"));
}

#[tokio::test]
async fn unknown_jsonrpc_method_is_denied_when_unknown_policy_denies() {
    let cases = [
        (
            json!({"policy": {"default_action": "deny"}}),
            "default deny should reject unknown JSON-RPC methods",
        ),
        (
            json!({"policy": {"methods": {"unknown": {"action": "deny"}}}}),
            "explicit unknown deny should reject unknown JSON-RPC methods",
        ),
    ];

    for (config, label) in cases {
        let plugin = plugin(config);
        let (mut ctx, mut headers) = jsonrpc_ctx(json!({
            "jsonrpc": "2.0",
            "id": "req-custom-method",
            "method": "FutureCustomMethod"
        }));

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        let PluginResult::Reject {
            status_code, body, ..
        } = result
        else {
            panic!("{label}");
        };
        assert_eq!(status_code, 200, "{label}");
        let body: Value = serde_json::from_str(&body).expect("body should be JSON");
        assert_eq!(body["error"]["data"]["method"], "unknown", "{label}");
        assert_eq!(
            ctx.metadata.get("a2a.policy_decision").map(String::as_str),
            Some("deny"),
            "{label}"
        );
    }
}

#[tokio::test]
async fn rest_detection_is_scoped_to_configured_endpoint_path() {
    let plugin = plugin(json!({
        "policy": {
            "default_action": "deny"
        }
    }));
    let (mut unrelated_ctx, mut unrelated_headers) = rest_ctx("GET", "/api/v1/tasks/task-1");
    let result = plugin
        .before_proxy(&mut unrelated_ctx, &mut unrelated_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!unrelated_ctx.metadata.contains_key("a2a.enabled"));

    let (mut a2a_ctx, mut a2a_headers) = rest_ctx("GET", "/a2a/tasks/task-1");
    let result = plugin.before_proxy(&mut a2a_ctx, &mut a2a_headers).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
}

#[tokio::test]
async fn rest_post_tasks_is_not_classified_as_list_tasks() {
    // A2A 0.3 section 3.5.6 maps send/create to POST /v1/message:send and
    // list to GET /v1/tasks. POST /v1/tasks is not a supported operation.
    let gateway = plugin(json!({}));
    for path in ["/a2a/tasks", "/a2a/v1/tasks"] {
        let (mut ctx, mut headers) = rest_ctx("POST", path);

        let result = gateway.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
        assert!(!ctx.metadata.contains_key("a2a.enabled"));
        assert!(!ctx.metadata.contains_key("a2a.method"));
    }

    // Allowing both plausible misclassifications must not admit an unknown
    // operation in a protected scope, even with an explicit unknown allow.
    for policy in [
        json!({"default_action": "deny", "methods": {
            "tasks/list": {"action": "allow"},
            "message/send": {"action": "allow"},
            "unknown": {"action": "allow"}
        }}),
        json!({"methods": {"tasks/cancel": {"action": "deny"}}}),
    ] {
        let gateway = plugin(json!({"policy": policy}));
        for path in ["/a2a/tasks", "/a2a/v1/tasks"] {
            let (mut ctx, mut headers) = rest_ctx("POST", path);
            let result = gateway.before_proxy(&mut ctx, &mut headers).await;
            assert!(matches!(
                result,
                PluginResult::Reject {
                    status_code: 403,
                    ..
                }
            ));
            assert_eq!(ctx.metadata["a2a.method"], "unknown");
            assert_eq!(ctx.metadata["a2a.error"], "request_body_uninspectable");
        }
        for (method, path, expected) in [
            ("GET", "/a2a/v1/tasks", "tasks/list"),
            ("POST", "/a2a/v1/message:send", "message/send"),
        ] {
            let (mut ctx, mut headers) = rest_ctx(method, path);
            let result = gateway.before_proxy(&mut ctx, &mut headers).await;
            assert!(matches!(result, PluginResult::Continue));
            assert_eq!(ctx.metadata["a2a.method"], expected);
        }
    }
}

#[tokio::test]
async fn rest_operation_table_emits_expected_metadata() {
    let cases = [
        ("POST", "/a2a/message:send", "message/send", None, "false"),
        (
            "POST",
            "/a2a/acme/message:stream",
            "message/stream",
            None,
            "true",
        ),
        ("GET", "/a2a/tasks", "tasks/list", None, "false"),
        (
            "GET",
            "/a2a/acme/tasks/task-1",
            "tasks/get",
            Some("task-1"),
            "false",
        ),
        (
            "POST",
            "/a2a/v1/message:send",
            "message/send",
            None,
            "false",
        ),
        (
            "POST",
            "/a2a/v1/message:stream",
            "message/stream",
            None,
            "true",
        ),
        ("GET", "/a2a/v1/tasks", "tasks/list", None, "false"),
        (
            "GET",
            "/a2a/v1/tasks/task-1",
            "tasks/get",
            Some("task-1"),
            "false",
        ),
        (
            "POST",
            "/a2a/v1/tasks/task-1:cancel",
            "tasks/cancel",
            Some("task-1"),
            "false",
        ),
        (
            "GET",
            "/a2a/v1/tasks/task-1:subscribe",
            "tasks/resubscribe",
            Some("task-1"),
            "true",
        ),
        (
            "POST",
            "/a2a/v1/tasks/task-1:subscribe",
            "tasks/resubscribe",
            Some("task-1"),
            "true",
        ),
        (
            "GET",
            "/a2a/v1/tasks/task-1/pushNotificationConfigs",
            "tasks/pushNotificationConfig/list",
            Some("task-1"),
            "false",
        ),
        (
            "POST",
            "/a2a/v1/tasks/task-1/pushNotificationConfigs",
            "tasks/pushNotificationConfig/set",
            Some("task-1"),
            "false",
        ),
        (
            "GET",
            "/a2a/v1/tasks/task-1/pushNotificationConfigs/config-1",
            "tasks/pushNotificationConfig/get",
            Some("task-1"),
            "false",
        ),
        (
            "DELETE",
            "/a2a/v1/tasks/task-1/pushNotificationConfigs/config-1",
            "tasks/pushNotificationConfig/delete",
            Some("task-1"),
            "false",
        ),
    ];

    for (method, path, expected_method, expected_task_id, expected_streaming) in cases {
        let plugin = plugin(json!({}));
        let (mut ctx, mut headers) = rest_ctx(method, path);
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{method} {path} should continue"
        );
        assert_eq!(
            ctx.metadata.get("a2a.method").map(String::as_str),
            Some(expected_method),
            "{method} {path}"
        );
        assert_eq!(
            ctx.metadata.get("a2a.task_id").map(String::as_str),
            expected_task_id,
            "{method} {path}"
        );
        assert_eq!(
            ctx.metadata.get("a2a.streaming").map(String::as_str),
            Some(expected_streaming),
            "{method} {path}"
        );
    }

    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = rest_ctx("GET", "/a2a/tasks/task-1/child");
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("a2a.enabled"));
}

#[tokio::test]
async fn grpc_standard_push_rpc_names_are_detected() {
    let cases = [
        (
            "CreateTaskPushNotification",
            "tasks/pushNotificationConfig/set",
        ),
        (
            "GetTaskPushNotification",
            "tasks/pushNotificationConfig/get",
        ),
        (
            "ListTaskPushNotification",
            "tasks/pushNotificationConfig/list",
        ),
        (
            "ListTaskPushNotificationConfigs",
            "tasks/pushNotificationConfig/list",
        ),
        (
            "DeleteTaskPushNotification",
            "tasks/pushNotificationConfig/delete",
        ),
    ];

    for (rpc, expected_method) in cases {
        let plugin = plugin(json!({}));
        let (mut ctx, mut headers) = grpc_ctx(rpc, "application/grpc");
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue), "{rpc}");
        assert_eq!(
            ctx.metadata.get("a2a.method").map(String::as_str),
            Some(expected_method),
            "{rpc}"
        );
    }
}

#[tokio::test]
async fn grpc_get_agent_card_maps_to_authenticated_card() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "agent/getAuthenticatedExtendedCard": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetAgentCard", "application/grpc");

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata.get("a2a.method").map(String::as_str),
        Some("agent/getAuthenticatedExtendedCard")
    );
}

#[tokio::test]
async fn grpc_get_agent_card_denied_via_pascalcase_policy_alias() {
    // The PascalCase `GetAgentCard` policy key must normalize to the same method
    // the gRPC binding detects (agent/getAuthenticatedExtendedCard); otherwise a
    // `GetAgentCard: deny` rule silently fails to block the gRPC card RPC.
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "GetAgentCard": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetAgentCard", "application/grpc");

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata.get("a2a.method").map(String::as_str),
        Some("agent/getAuthenticatedExtendedCard")
    );
}

fn encode_proto_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn encode_proto_string(field: u32, value: &str, out: &mut Vec<u8>) {
    encode_proto_varint(u64::from(field) << 3 | 2, out);
    encode_proto_varint(value.len() as u64, out);
    out.extend_from_slice(value.as_bytes());
}

fn encode_proto_bytes(field: u32, value: &[u8], out: &mut Vec<u8>) {
    encode_proto_varint(u64::from(field) << 3 | 2, out);
    encode_proto_varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn encode_proto_varint_field(field: u32, value: u64, out: &mut Vec<u8>) {
    encode_proto_varint(u64::from(field) << 3, out);
    encode_proto_varint(value, out);
}

fn encode_proto_fixed64_field(field: u32, value: u64, out: &mut Vec<u8>) {
    encode_proto_varint(u64::from(field) << 3 | 1, out);
    out.extend_from_slice(&value.to_le_bytes());
}

fn encode_proto_fixed32_field(field: u32, value: u32, out: &mut Vec<u8>) {
    encode_proto_varint(u64::from(field) << 3 | 5, out);
    out.extend_from_slice(&value.to_le_bytes());
}

/// Minimal Agent Card with identity + endpoint fields; optional extras appended.
fn encode_minimal_agent_card(
    name: &str,
    description: &str,
    url: &str,
    extras: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let mut out = Vec::new();
    encode_proto_string(1, name, &mut out);
    encode_proto_string(2, description, &mut out);
    encode_proto_string(3, url, &mut out);
    extras(&mut out);
    out
}

async fn detect_grpc_agent_card(
    plugin: &std::sync::Arc<dyn ferrum_edge::plugins::Plugin>,
    rpc: &str,
) -> RequestContext {
    let (mut ctx, mut headers) = grpc_ctx(rpc, "application/grpc");
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    ctx
}

fn assert_grpc_rewrite_reject(result: PluginResult, diagnostic: &str, metadata: Option<&str>) {
    let PluginResult::Reject {
        status_code,
        body,
        headers,
    } = result
    else {
        panic!("expected gRPC Agent Card rewrite reject for {diagnostic}");
    };
    // A gRPC failure rides HTTP 200 + a `grpc-status` trailer. An HTTP 5xx here
    // would publish a synthetic backend-shaped fault for a gateway-side policy
    // refusal; the deadline terminal (`grpc_deadline_exceeded_plugin_result`)
    // uses the same 200 shape.
    assert_eq!(status_code, 200);
    assert!(
        body.is_empty(),
        "a gRPC rewrite refusal must be trailers-only, never an HTTP body"
    );
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("13"));
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some(diagnostic)
    );
    if let Some(metadata) = metadata {
        assert_eq!(metadata, diagnostic);
    }
}

fn encode_agent_interface(url: &str, transport: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_proto_string(1, url, &mut out);
    encode_proto_string(2, transport, &mut out);
    out
}

fn encode_agent_card_signature(protected: &str, signature: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_proto_string(1, protected, &mut out);
    encode_proto_string(2, signature, &mut out);
    out
}

fn encode_a2a_03_agent_card(
    name: &str,
    description: &str,
    url: &str,
    preferred_transport: &str,
    interfaces: &[(&str, &str)],
    protocol_version: &str,
    with_signature: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    encode_proto_string(1, name, &mut out);
    encode_proto_string(2, description, &mut out);
    encode_proto_string(3, url, &mut out);
    encode_proto_string(14, preferred_transport, &mut out);
    for (interface_url, transport) in interfaces {
        encode_proto_bytes(
            15,
            &encode_agent_interface(interface_url, transport),
            &mut out,
        );
    }
    encode_proto_string(16, protocol_version, &mut out);
    if with_signature {
        encode_proto_bytes(
            17,
            &encode_agent_card_signature("eyJhbGciOiJFUzI1NiJ9", "stale"),
            &mut out,
        );
    }
    out
}

/// A2A renumbered `AgentCard` for 1.0: field 3 is
/// `repeated AgentInterface supported_interfaces` (it was `string url` in
/// 0.3.x), `signatures` moved from field 17 to field 13, field 14 is
/// `optional string icon_url` (it was `preferred_transport`), and
/// `protocol_version` (field 16) was removed from the message entirely.
///
/// Every byte of a serialized `AgentInterface` stays below 0x80, so the
/// submessage on field 3 decodes as valid UTF-8 — `from_utf8` alone cannot
/// tell this layout apart from a 0.3 card.
fn encode_a2a_10_agent_card(
    name: &str,
    description: &str,
    interfaces: &[(&str, &str)],
    icon_url: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::new();
    encode_proto_string(1, name, &mut out);
    encode_proto_string(2, description, &mut out);
    for (interface_url, protocol_binding) in interfaces {
        encode_proto_bytes(
            3,
            &encode_agent_interface(interface_url, protocol_binding),
            &mut out,
        );
    }
    encode_proto_bytes(
        13,
        &encode_agent_card_signature("eyJhbGciOiJFUzI1NiJ9", "v1-signature"),
        &mut out,
    );
    if let Some(icon_url) = icon_url {
        encode_proto_string(14, icon_url, &mut out);
    }
    out
}

/// The buffered native-gRPC response view a plugin sees for a SUCCESSFUL unary
/// reply: `application/grpc` plus the terminal `grpc-status: 0` the proxy merges
/// out of the backend's TRAILERS frame
/// (`grpc_proxy::build_grpc_plugin_header_view`). Both are required before
/// `a2a_gateway` will treat a body as a candidate Agent Card, so a helper keeps
/// every rewrite test honest about the shape it is actually asserting on.
fn grpc_ok_response_headers() -> HashMap<String, String> {
    HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("grpc-status".to_string(), "0".to_string()),
    ])
}

fn frame_grpc_message(message: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + message.len());
    frame.push(0);
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(message);
    frame
}

fn proto_string_field(message: &[u8], target: u32) -> Option<String> {
    let mut buf = message;
    while !buf.is_empty() {
        let mut key = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *buf.first()?;
            buf = &buf[1..];
            key |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match wire {
            0 => {
                for shift in (0..64).step_by(7) {
                    let byte = *buf.first()?;
                    buf = &buf[1..];
                    if byte & 0x80 == 0 {
                        let _ = shift;
                        break;
                    }
                }
            }
            1 => {
                if buf.len() < 8 {
                    return None;
                }
                buf = &buf[8..];
            }
            2 => {
                let mut len = 0usize;
                for shift in (0..64).step_by(7) {
                    let byte = *buf.first()?;
                    buf = &buf[1..];
                    len |= usize::from(byte & 0x7f) << shift;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                if buf.len() < len {
                    return None;
                }
                let (value, rest) = buf.split_at(len);
                buf = rest;
                if field == target {
                    return std::str::from_utf8(value).ok().map(str::to_owned);
                }
            }
            5 => {
                if buf.len() < 4 {
                    return None;
                }
                buf = &buf[4..];
            }
            _ => return None,
        }
    }
    None
}

fn proto_has_field(message: &[u8], target: u32) -> bool {
    let mut buf = message;
    while !buf.is_empty() {
        let mut key = 0u64;
        for shift in (0..64).step_by(7) {
            let Some(&byte) = buf.first() else {
                return false;
            };
            buf = &buf[1..];
            key |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                let _ = shift;
                break;
            }
        }
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        let len = match wire {
            0 => {
                for _ in 0..10 {
                    let Some(&byte) = buf.first() else {
                        return false;
                    };
                    buf = &buf[1..];
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                0
            }
            1 => 8,
            2 => {
                let mut len = 0usize;
                for shift in (0..64).step_by(7) {
                    let Some(&byte) = buf.first() else {
                        return false;
                    };
                    buf = &buf[1..];
                    len |= usize::from(byte & 0x7f) << shift;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                len
            }
            5 => 4,
            _ => return false,
        };
        if wire != 0 {
            if buf.len() < len {
                return false;
            }
            buf = &buf[len..];
        }
        if field == target {
            return true;
        }
    }
    false
}

fn proto_repeated_messages(message: &[u8], target: u32) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    let mut buf = message;
    while !buf.is_empty() {
        let mut key = 0u64;
        for shift in (0..64).step_by(7) {
            let Some(&byte) = buf.first() else {
                return found;
            };
            buf = &buf[1..];
            key |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match wire {
            0 => {
                for _ in 0..10 {
                    let Some(&byte) = buf.first() else {
                        return found;
                    };
                    buf = &buf[1..];
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
            }
            1 => {
                if buf.len() < 8 {
                    return found;
                }
                buf = &buf[8..];
            }
            2 => {
                let mut len = 0usize;
                for shift in (0..64).step_by(7) {
                    let Some(&byte) = buf.first() else {
                        return found;
                    };
                    buf = &buf[1..];
                    len |= usize::from(byte & 0x7f) << shift;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                if buf.len() < len {
                    return found;
                }
                let (value, rest) = buf.split_at(len);
                buf = rest;
                if field == target {
                    found.push(value.to_vec());
                }
            }
            5 => {
                if buf.len() < 4 {
                    return found;
                }
                buf = &buf[4..];
            }
            _ => return found,
        }
    }
    found
}

#[tokio::test]
async fn grpc_agent_card_response_rewrites_jsonrpc_urls() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetExtendedAgentCard", "application/grpc");
    headers.insert("grpc-accept-encoding".to_string(), "gzip".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.should_buffer_response_body(&ctx));
    assert!(!headers.contains_key("grpc-accept-encoding"));

    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/grpc",
        "GRPC",
        &[
            ("https://planner.internal/a2a", "JSONRPC"),
            ("https://planner.internal/grpc", "GRPC"),
        ],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("rewritten grpc agent card frame");
    assert_eq!(rewritten[0], 0);
    let msg_len =
        u32::from_be_bytes([rewritten[1], rewritten[2], rewritten[3], rewritten[4]]) as usize;
    assert_eq!(rewritten.len(), 5 + msg_len);
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://planner.internal/grpc")
    );
    let interfaces = proto_repeated_messages(message, 15);
    assert_eq!(interfaces.len(), 2);
    assert_eq!(
        proto_string_field(&interfaces[0], 1).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    assert_eq!(
        proto_string_field(&interfaces[1], 1).as_deref(),
        Some("https://planner.internal/grpc")
    );
    assert!(!proto_has_field(message, 17));
    plugin.on_response_body_transformed(&mut ctx, &mut response_headers);
    assert!(!response_headers.contains_key("content-length"));
    assert!(!response_headers.contains_key("grpc-encoding"));
}

#[tokio::test]
async fn grpc_agent_card_unsupported_version_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetAgentCard", "application/grpc");
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "1.0.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    let PluginResult::Reject {
        status_code,
        headers: reject_headers,
        ..
    } = result
    else {
        panic!("unsupported protobuf version must fail closed");
    };
    assert_eq!(status_code, 200);
    assert_eq!(
        reject_headers.get("grpc-status").map(String::as_str),
        Some("13")
    );
    assert_eq!(
        reject_headers.get("grpc-message").map(String::as_str),
        Some("unsupported_agent_card_protobuf_version")
    );
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("unsupported_agent_card_protobuf_version")
    );
}

#[tokio::test]
async fn grpc_agent_card_malformed_frame_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetExtendedAgentCard", "application/grpc");
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &[0x00, 0x00, 0x00])
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_grpc_frame_malformed",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[test]
fn agent_card_rewrite_requires_an_admitted_public_origin() {
    for config in [
        json!({}),
        json!({"discovery": {"rewrite_agent_card_urls": true}}),
        json!({"discovery": {"trust_forwarded_headers": true}}),
    ] {
        let error = create_plugin("a2a_gateway", &config)
            .err()
            .expect("must reject");
        assert!(error.contains("discovery.public_base_url"), "{error}");
        assert!(
            error.contains("discovery.rewrite_agent_card_urls"),
            "{error}"
        );
    }
    assert!(
        create_plugin(
            "a2a_gateway",
            &json!({"discovery": {"rewrite_agent_card_urls": false}}),
        )
        .is_ok()
    );
}

#[tokio::test]
async fn grpc_agent_card_preferred_jsonrpc_url_is_rewritten() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetExtendedAgentCard", "application/grpc");
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("preferred jsonrpc url should rewrite");
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    assert!(!proto_has_field(message, 17));
}

#[tokio::test]
async fn grpc_agent_card_empty_body_is_trailers_only_passthrough() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &[])
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &[],
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none()
    );
}

#[tokio::test]
async fn grpc_agent_card_non_ok_status_skips_rewrite() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("grpc-status".to_string(), "14".to_string()),
    ]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none(),
        "non-OK grpc-status must not rewrite an Agent Card frame"
    );
}

#[tokio::test]
async fn grpc_agent_card_compressed_frame_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let mut compressed = frame_grpc_message(b"not-a-card");
    compressed[0] = 1; // gRPC compression flag
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &compressed)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_grpc_encoding_unsupported",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_grpc_encoding_header_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        false,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("grpc-status".to_string(), "0".to_string()),
        ("grpc-encoding".to_string(), "gzip".to_string()),
    ]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_grpc_encoding_unsupported",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_length_prefix_mismatch_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Claims 10 payload bytes but only carries 3.
    let body = vec![0, 0, 0, 0, 10, 1, 2, 3];
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_grpc_frame_malformed",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_unrecognized_protobuf_shape_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Valid unary frame, but missing Agent Card identity/endpoint fields.
    let mut message = Vec::new();
    encode_proto_string(99, "not-an-agent-card", &mut message);
    let body = frame_grpc_message(&message);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_shape_unrecognized",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_truncated_protobuf_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Length-delimited field claiming more bytes than remain.
    let message = vec![0x0a, 0x05, 0x61, 0x62]; // field 1, len 5, only 2 bytes
    let body = frame_grpc_message(&message);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_truncated",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_invalid_field_number_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Protobuf key with field number 0 is illegal.
    let message = vec![0x02, 0x01, 0x61]; // field 0, wire LEN, one byte
    let body = frame_grpc_message(&message);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_field_invalid",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_unsupported_wire_type_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Wire type 3 (start-group) is unsupported.
    let message = vec![0x0b]; // field 1, wire 3
    let body = frame_grpc_message(&message);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_wire_type_unsupported",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_protocol_version_wire_mismatch_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let card = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |out| {
            encode_proto_string(14, "JSONRPC", out);
            // Field 16 must be LEN-wire string; force a varint mismatch.
            encode_proto_varint_field(16, 1, out);
        },
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_field_wire_mismatch",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_missing_protocol_version_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    // Omit field 16. This card really is A2A 0.3.x shaped, but proto3 cannot
    // distinguish an unset protocol_version from "", and A2A 1.0 dropped the
    // field entirely, so the wire carries no evidence of the layout. The gate
    // is positive: without proof, the card fails closed instead of being
    // rewritten with 0.3 field numbers that may not apply.
    let card = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |out| {
            encode_proto_string(14, "JSONRPC", out);
        },
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "unsupported_agent_card_protobuf_version",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none(),
        "an unprovable layout must never produce a rewritten frame"
    );
}

/// Assert that a v1.0-shaped card is refused, and report the exact corruption
/// if the rewriter ever accepts one again.
async fn assert_a2a_10_card_fails_closed(icon_url: Option<&str>) {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_10_agent_card(
        "planner",
        "planning agent",
        &[
            ("https://planner.internal/a2a", "JSONRPC"),
            ("https://planner.internal/grpc", "GRPC"),
        ],
        icon_url,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "unsupported_agent_card_protobuf_version",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await;
    if let Some(rewritten) = rewritten {
        // Applying 0.3 field numbers here flattens each AgentInterface
        // submessage on field 3 into a bare URL string and leaves the real
        // field-13 signatures in place: a mutated card under a stale signature.
        let message = &rewritten[5..];
        panic!(
            "A2A 1.0 card was rewritten: field 3 as string = {:?}, field 13 present = {}",
            proto_string_field(message, 3),
            proto_has_field(message, 13)
        );
    }
}

#[tokio::test]
async fn grpc_a2a_10_agent_card_fails_closed_instead_of_being_corrupted() {
    assert_a2a_10_card_fails_closed(None).await;
}

#[tokio::test]
async fn grpc_a2a_10_agent_card_outcome_is_independent_of_icon_url() {
    // Field 14 is `preferred_transport` in 0.3 but `icon_url` in 1.0. The
    // outcome must not hinge on whether that unrelated optional field happens
    // to be set, so this takes exactly the same path as the fixture without it.
    assert_a2a_10_card_fails_closed(Some("https://cdn.example.com/planner.png")).await;
}

// ── gRPC service identity ↔ Agent Card schema ────────────────────────────────
//
// A gRPC service NAME and an `AgentCard` wire LAYOUT are two different facts.
// A2A 0.3 publishes `package a2a.v1` (service `a2a.v1.A2AService`) with
// `AgentCard` fields 1..17; A2A 1.0 publishes `package lf.a2a.v1` with a
// renumbered card. This gateway implements the 0.3 layout, so the 0.3 identity
// is what it defaults to, and the 1.0 identity may never reach the 0.3 decoder
// no matter what the bytes look like.

/// Build a detected gRPC Agent Card context on an arbitrary service.
async fn detect_grpc_card_on_service(
    plugin: &std::sync::Arc<dyn ferrum_edge::plugins::Plugin>,
    service: &str,
    rpc: &str,
) -> (RequestContext, bool) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        format!("/{service}/{rpc}"),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    let mut headers = ctx.headers.clone();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let detected = ctx.metadata.get("a2a.binding").map(String::as_str) == Some("grpc");
    (ctx, detected)
}

fn a2a_03_card_fixture() -> Vec<u8> {
    encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        true,
    )
}

/// The default `endpoint.grpc_services` is the canonical A2A 0.3 identity, and
/// it is the one that actually gets rewritten. Before this pairing was made
/// explicit, the default named A2A 1.0's service while the rewriter implemented
/// 0.3's payload, so genuine canonical 0.3 traffic was missed by defaults.
#[tokio::test]
async fn grpc_default_service_is_the_canonical_a2a_03_identity() {
    let plugin = plugin(json!({
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let (mut ctx, detected) =
        detect_grpc_card_on_service(&plugin, "a2a.v1.A2AService", "GetAgentCard").await;
    assert!(detected, "a2a.v1.A2AService must be detected by default");

    let body = frame_grpc_message(&a2a_03_card_fixture());
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("canonical 0.3 card must be rewritten");
    assert_eq!(
        proto_string_field(&rewritten[5..], 3).as_deref(),
        Some("https://gateway.example.com/a2a"),
    );
}

/// A2A 1.0 remains detected by default so upgrades cannot bypass existing
/// method policy. Its declared schema still prevents 0.3 card decoding.
#[tokio::test]
async fn grpc_a2a_10_service_is_detected_by_default() {
    let plugin = plugin(json!({
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let (ctx, detected) =
        detect_grpc_card_on_service(&plugin, "lf.a2a.v1.A2AService", "GetAgentCard").await;
    assert!(detected, "A2A 1.0 traffic must remain subject to policy");
    assert!(plugin.should_buffer_response_body(&ctx));
}

/// **The load-bearing regression.** Even when an operator explicitly configures
/// the A2A 1.0 service, a reply on it can never be decoded or rewritten with 0.3
/// field numbers — not even one whose bytes happen to be 0.3-shaped and carry a
/// configured `protocol_version`. The decoder follows the declared service
/// schema, never the bytes.
#[tokio::test]
async fn grpc_a2a_10_service_never_decodes_a_0_3_shaped_card() {
    let plugin = plugin(json!({
        "endpoint": {"grpc_services": ["lf.a2a.v1.A2AService"]},
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let (mut ctx, detected) =
        detect_grpc_card_on_service(&plugin, "lf.a2a.v1.A2AService", "GetAgentCard").await;
    assert!(detected, "a configured 1.0 service is still detected");

    let body = frame_grpc_message(&a2a_03_card_fixture());
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_grpc_schema_unsupported",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await;
    assert!(
        rewritten.is_none(),
        "a 1.0 service's reply must never be re-encoded with 0.3 field numbers"
    );
}

/// A genuine 1.0 card on the 1.0 service is refused for the SCHEMA reason, not
/// with a complaint about a `protocol_version` the 1.0 layout does not even
/// carry. The disposition a client sees has to name what is actually wrong.
#[tokio::test]
async fn grpc_a2a_10_service_refuses_with_a_schema_disposition() {
    let plugin = plugin(json!({
        "endpoint": {"grpc_services": ["lf.a2a.v1.A2AService"]},
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let (mut ctx, _) =
        detect_grpc_card_on_service(&plugin, "lf.a2a.v1.A2AService", "GetExtendedAgentCard").await;
    let body = frame_grpc_message(&encode_a2a_10_agent_card(
        "planner",
        "planning agent",
        &[("https://planner.internal/a2a", "JSONRPC")],
        None,
    ));
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_grpc_schema_unsupported",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

/// A custom service name has no published Agent Card layout, so an undeclared
/// one is detected and policed but never decoded. Serving the card un-rewritten
/// would publish the backend's internal URLs, so it fails closed.
#[tokio::test]
async fn grpc_undeclared_custom_service_refuses_card_rewrite() {
    let plugin = plugin(json!({
        "endpoint": {"grpc_services": ["acme.agents.v1.AgentService"]},
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let (mut ctx, detected) =
        detect_grpc_card_on_service(&plugin, "acme.agents.v1.AgentService", "GetAgentCard").await;
    assert!(detected, "a custom service is still detected and policed");

    let body = frame_grpc_message(&a2a_03_card_fixture());
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_grpc_schema_undeclared",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

/// The documented custom-deployment path: declare the published layout the
/// service actually serves, and rewriting works exactly as on the canonical
/// identity.
#[tokio::test]
async fn grpc_custom_service_declaring_a2a_03_is_rewritten() {
    let plugin = plugin(json!({
        "endpoint": {"grpc_services": [
            {"service": "acme.agents.v1.AgentService", "card_schema": "a2a-0.3"}
        ]},
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let (mut ctx, _) =
        detect_grpc_card_on_service(&plugin, "acme.agents.v1.AgentService", "GetAgentCard").await;
    let body = frame_grpc_message(&a2a_03_card_fixture());
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("a declared 0.3 custom service must be rewritten");
    assert_eq!(
        proto_string_field(&rewritten[5..], 3).as_deref(),
        Some("https://gateway.example.com/a2a"),
    );
}

/// The documented escape for fronting a service this gateway cannot rewrite:
/// withdraw rewriting and the card passes through untouched instead of being
/// refused.
#[tokio::test]
async fn grpc_unrewritable_service_passes_through_with_rewriting_withdrawn() {
    let cases = [
        ("lf.a2a.v1.A2AService", json!(["lf.a2a.v1.A2AService"])),
        ("acme.v1.Agents", json!(["acme.v1.Agents"])),
        (
            "acme.v1.Agents",
            json!([{"service": "acme.v1.Agents", "card_schema": "none"}]),
        ),
    ];
    for (service, services) in cases {
        let plugin = plugin(json!({
            "endpoint": {"grpc_services": services},
            "discovery": {
                "public_base_url": "https://gateway.example.com",
                "rewrite_agent_card_urls": false
            }
        }));
        let (mut ctx, _) = detect_grpc_card_on_service(&plugin, service, "GetAgentCard").await;
        let body = frame_grpc_message(&a2a_03_card_fixture());
        let mut response_headers = grpc_ok_response_headers();
        let staged = plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await;
        assert!(
            matches!(staged, PluginResult::Continue),
            "{service}: withdrawing the rewrite must stop the refusal too"
        );
        let rewritten = plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await;
        assert!(
            rewritten.is_none(),
            "{service}: nothing may be rewritten with the rewrite withdrawn"
        );
    }
}

/// Restating a published service's own layout is a no-op; contradicting it is a
/// configuration error, because the layout belongs to the protocol rather than
/// to the deployment.
#[test]
fn grpc_service_card_schema_declarations_are_validated() {
    let accepted = [
        json!([{"service": "a2a.v1.A2AService", "card_schema": "a2a-0.3"}]),
        json!([{"service": "lf.a2a.v1.A2AService", "card_schema": "a2a-1.0"}]),
        json!([{"service": "acme.v1.Agents", "card_schema": "a2a-1.0"}]),
        json!([{"service": "acme.v1.Agents", "card_schema": "none"}]),
        json!([{"service": "acme.v1.Agents"}]),
        json!(["a2a.v1.A2AService", {"service": "acme.v1.Agents"}]),
    ];
    for services in accepted {
        let config = json!({
            "endpoint": {"grpc_services": services},
            "discovery": {"rewrite_agent_card_urls": false}
        });
        assert!(
            create_plugin("a2a_gateway", &config).is_ok(),
            "{services} must be accepted"
        );
    }

    let rejected = [
        (
            json!([{"service": "a2a.v1.A2AService", "card_schema": "a2a-1.0"}]),
            "published A2A service",
        ),
        (
            json!([{"service": "lf.a2a.v1.A2AService", "card_schema": "a2a-0.3"}]),
            "published A2A service",
        ),
        (
            json!([{"service": "a2a.v1.A2AService", "card_schema": "none"}]),
            "published A2A service",
        ),
        (
            json!([{"service": "acme.v1.Agents", "card_schema": "a2a-2.0"}]),
            "card_schema",
        ),
        (json!([{"card_schema": "a2a-0.3"}]), "require 'service'"),
        (json!([42]), "service name string"),
    ];
    for (services, expected) in rejected {
        let config = json!({
            "endpoint": {"grpc_services": services},
            "discovery": {"rewrite_agent_card_urls": false}
        });
        let error = match create_plugin("a2a_gateway", &config) {
            Ok(_) => panic!("{services} must be rejected"),
            Err(error) => error,
        };
        assert!(
            error.contains(expected),
            "{services}: expected an error naming {expected:?}, got {error}"
        );
    }
}

#[tokio::test]
async fn grpc_agent_card_submessage_on_url_field_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    // A card that claims 0.3.0 but carries a 1.0-shaped serialized
    // AgentInterface on field 3. The submessage is valid UTF-8, so only the
    // absolute-http(s)-URL guard separates it from a real 0.3 `url` string.
    let mut card = Vec::new();
    encode_proto_string(1, "planner", &mut card);
    encode_proto_string(2, "planning agent", &mut card);
    encode_proto_bytes(
        3,
        &encode_agent_interface("https://planner.internal/a2a", "JSONRPC"),
        &mut card,
    );
    encode_proto_string(14, "JSONRPC", &mut card);
    encode_proto_string(16, "0.3.0", &mut card);
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    // Admission schema-validates every known field the 0.3 layout gate relies
    // on, so the field-3 mismatch is caught before a rewrite is ever staged.
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_url_layout_mismatch",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none(),
        "a submessage on the url field must not be rewritten in place"
    );
}

#[tokio::test]
async fn grpc_agent_card_non_absolute_interface_url_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    // preferred_transport GRPC leaves field 3 alone; the JSONRPC interface is
    // the only rewrite target, and its url is not an absolute http(s) URL.
    let mut card = Vec::new();
    encode_proto_string(1, "planner", &mut card);
    encode_proto_string(2, "planning agent", &mut card);
    encode_proto_string(3, "https://planner.internal/grpc", &mut card);
    encode_proto_string(14, "GRPC", &mut card);
    encode_proto_bytes(
        15,
        &encode_agent_interface("planner.internal/a2a", "JSONRPC"),
        &mut card,
    );
    encode_proto_string(16, "0.3.0", &mut card);
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_url_layout_mismatch",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none()
    );
}

#[tokio::test]
async fn grpc_agent_card_grpc_only_urls_need_no_mutation() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/grpc",
        "GRPC",
        &[("https://planner.internal/grpc", "GRPC")],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none(),
        "GRPC-only cards must leave the upstream frame untouched"
    );
}

#[tokio::test]
async fn grpc_agent_card_preserves_matching_jsonrpc_url_when_interface_changes() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    // Preferred URL already public; only the additional interface needs rewrite.
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://gateway.example.com/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("interface rewrite should still produce a frame");
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    let interfaces = proto_repeated_messages(message, 15);
    assert_eq!(interfaces.len(), 1);
    assert_eq!(
        proto_string_field(&interfaces[0], 1).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    assert!(!proto_has_field(message, 17));
}

#[tokio::test]
async fn grpc_agent_card_preserves_matching_interface_url_when_card_url_changes() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://gateway.example.com/a2a", "JSONRPC")],
        "0.3.0",
        false,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("card url rewrite should still produce a frame");
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    let interfaces = proto_repeated_messages(message, 15);
    assert_eq!(
        proto_string_field(&interfaces[0], 1).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
}

#[tokio::test]
async fn grpc_agent_card_empty_preferred_transport_rewrites_url() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |out| {
            // No preferred_transport field => treat as rewritable.
            encode_proto_bytes(
                15,
                &encode_agent_interface("https://planner.internal/a2a", ""),
                out,
            );
            encode_proto_string(16, "0.3.0", out);
        },
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("empty preferred transport should rewrite");
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    let interfaces = proto_repeated_messages(message, 15);
    assert_eq!(
        proto_string_field(&interfaces[0], 1).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
}

#[tokio::test]
async fn grpc_agent_card_rewrite_preserves_unknown_scalar_wire_types() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |out| {
            encode_proto_string(14, "JSONRPC", out);
            encode_proto_string(16, "0.3.0", out);
            // Unknown fields across varint / 64-bit / 32-bit wires must round-trip.
            encode_proto_varint_field(50, 42, out);
            encode_proto_fixed64_field(51, 0x1122_3344_5566_7788, out);
            encode_proto_fixed32_field(52, 0xaabb_ccdd, out);
        },
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("scalar unknown fields must not block rewrite");
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    assert!(proto_has_field(message, 50));
    assert!(proto_has_field(message, 51));
    assert!(proto_has_field(message, 52));
}

#[tokio::test]
async fn grpc_agent_card_unlimited_response_ceiling_still_rewrites() {
    use ferrum_edge::_test_support::take_buffered_response_capacity_refusal_pending_for_test;

    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    // 0 means unlimited on the effective limit; the rewriter must fold via
    // retained_response_body_ceiling or BoundedResponseBodySink refuses writes.
    ctx.max_response_body_size_bytes = 0;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("unlimited effective limit must still permit Agent Card rewrite");
    assert_eq!(
        proto_string_field(&rewritten[5..], 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    assert!(
        !take_buffered_response_capacity_refusal_pending_for_test(&mut ctx),
        "successful unlimited-ceiling rewrite must not mark capacity refusal"
    );
}

#[tokio::test]
async fn grpc_agent_card_tight_response_ceiling_refuses_rewrite() {
    use ferrum_edge::_test_support::take_buffered_response_capacity_refusal_pending_for_test;

    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    // Far below any rewritten frame size.
    ctx.max_response_body_size_bytes = 8;
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none(),
        "over-ceiling Agent Card rewrite must return None"
    );
    assert!(
        take_buffered_response_capacity_refusal_pending_for_test(&mut ctx),
        "over-ceiling rewrite must mark the pending capacity refusal"
    );
}

#[tokio::test]
async fn grpc_agent_card_transform_failure_rejects_on_final_body() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        false,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    // Staging validated an uncompressed card; transform later sees compression.
    response_headers.insert("grpc-encoding".to_string(), "gzip".to_string());
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none()
    );
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("agent_card_grpc_encoding_unsupported")
    );
    let final_result = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(final_result, "agent_card_grpc_encoding_unsupported", None);
}

#[tokio::test]
async fn grpc_agent_card_truncated_fixed64_field_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let mut message = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |_| {},
    );
    // 64-bit wire value truncated to 3 bytes.
    encode_proto_varint(u64::from(51u32) << 3 | 1, &mut message);
    message.extend_from_slice(&[1, 2, 3]);
    let body = frame_grpc_message(&message);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_truncated",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_truncated_fixed32_field_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let mut message = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |_| {},
    );
    encode_proto_varint(u64::from(52u32) << 3 | 5, &mut message);
    message.extend_from_slice(&[1, 2]); // need 4
    let body = frame_grpc_message(&message);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_truncated",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_varint_overflow_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Ten continuation bytes overflow the varint decoder.
    let message = vec![0xff; 10];
    let body = frame_grpc_message(&message);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_varint_overflow",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_truncated_varint_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Continuation bit set with no following byte.
    let message = vec![0x80];
    let body = frame_grpc_message(&message);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_truncated",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_identity_grpc_encoding_is_accepted() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[],
        "0.3.0",
        false,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("grpc-status".to_string(), "0".to_string()),
        ("grpc-encoding".to_string(), "identity".to_string()),
    ]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("identity grpc-encoding must still rewrite");
    assert_eq!(
        proto_string_field(&rewritten[5..], 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
}

#[tokio::test]
async fn grpc_agent_card_transform_sees_late_shape_and_version_failures() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let valid = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[],
        "0.3.0",
        false,
    );
    let valid_body = frame_grpc_message(&valid);
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &valid_body)
            .await,
        PluginResult::Continue
    ));

    let mut unrecognized = Vec::new();
    encode_proto_string(99, "not-a-card", &mut unrecognized);
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &frame_grpc_message(&unrecognized),
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none()
    );
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("agent_card_protobuf_shape_unrecognized")
    );
    // Consume the pending transform diagnostic, then re-admit the valid card so
    // the version case is isolated: `on_final_response_body` clears the staged
    // state, and the transform phase only acts on a card it admitted.
    let _ = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, &valid_body)
        .await;
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &valid_body)
            .await,
        PluginResult::Continue
    ));

    let unsupported = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[],
        "1.0.0",
        false,
    );
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &frame_grpc_message(&unsupported),
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none()
    );
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("unsupported_agent_card_protobuf_version")
    );
    let final_result = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, &valid_body)
        .await;
    assert_grpc_rewrite_reject(
        final_result,
        "unsupported_agent_card_protobuf_version",
        None,
    );
}

/// Build the standard rewritable 0.3 card at an arbitrary wire version.
fn versioned_agent_card_body(protocol_version: &str) -> Vec<u8> {
    frame_grpc_message(&encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[],
        protocol_version,
        false,
    ))
}

/// Drive admission for one `endpoint.protocol_versions` list against one wire
/// `protocol_version`, returning the `on_response_body` outcome.
async fn admit_versioned_card(configured: &[&str], wire_version: &str) -> PluginResult {
    let plugin = plugin(json!({
        "endpoint": { "protocol_versions": configured },
        "discovery": { "public_base_url": "https://gateway.example.com" }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let body = versioned_agent_card_body(wire_version);
    let mut response_headers = grpc_ok_response_headers();
    plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await
}

/// `endpoint.protocol_versions` is a list of EXACT version strings — the schema
/// documents no family, range, or wildcard syntax — so listing `0.3.0` must not
/// silently vouch for every other `0.3.x` a backend cares to claim.
#[tokio::test]
async fn grpc_agent_card_version_gate_requires_an_exact_configured_version() {
    assert!(matches!(
        admit_versioned_card(&["0.3.0"], "0.3.0").await,
        PluginResult::Continue
    ));
    assert_grpc_rewrite_reject(
        admit_versioned_card(&["0.3.0"], "0.3.99").await,
        "unsupported_agent_card_protobuf_version",
        None,
    );
    // Configuring the other version is what admits it.
    assert!(matches!(
        admit_versioned_card(&["0.3.0", "0.3.99"], "0.3.99").await,
        PluginResult::Continue
    ));
    // Trailing/leading whitespace in configuration is normalized, not a
    // different version.
    assert!(matches!(
        admit_versioned_card(&[" 0.3.0 "], "0.3.0").await,
        PluginResult::Continue
    ));
}

/// The exact-match rule is necessary but not sufficient: the selected version
/// must ALSO map to the 0.3 wire layout this rewriter implements. An operator
/// who configures a 1.0 backend cannot thereby authorize 0.3 field surgery on
/// it.
#[tokio::test]
async fn grpc_agent_card_version_gate_requires_the_implemented_wire_layout() {
    assert_grpc_rewrite_reject(
        admit_versioned_card(&["1.0.0"], "1.0.0").await,
        "unsupported_agent_card_protobuf_version",
        None,
    );
    assert_grpc_rewrite_reject(
        admit_versioned_card(&["0.2.9"], "0.2.9").await,
        "unsupported_agent_card_protobuf_version",
        None,
    );
    // `0.30.0` starts with the characters `0.3` but is not the 0.3 family.
    assert_grpc_rewrite_reject(
        admit_versioned_card(&["0.30.0"], "0.30.0").await,
        "unsupported_agent_card_protobuf_version",
        None,
    );
}

/// A non-OK upstream gRPC reply is not an Agent Card, even when it decodes.
/// Both halves of the proof are required, and a missing one is passthrough — not
/// a rewrite, and not a gateway-authored failure that would blame the rewriter
/// for the backend's own outcome.
#[tokio::test]
async fn grpc_agent_card_requires_positive_proof_of_a_successful_reply() {
    let plugin = plugin(json!({
        "discovery": { "public_base_url": "https://gateway.example.com" }
    }));
    let body = versioned_agent_card_body("0.3.0");

    // No terminal grpc-status at all: not a proven-OK reply.
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let mut headers = HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Continue
    ));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &headers,
            )
            .await
            .is_none(),
        "an unproven reply must be forwarded, not rewritten"
    );
    assert!(matches!(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &body)
            .await,
        PluginResult::Continue
    ));

    // grpc-status arriving in the merged trailer view as a failure.
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let mut headers = grpc_ok_response_headers();
    headers.insert("grpc-status".to_string(), "13".to_string());
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Continue
    ));
    assert!(!ctx.metadata.contains_key("a2a.error"));

    // A non-200 HTTP status is a transport-level failure, not a card.
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let mut headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 502, &mut headers, &body)
            .await,
        PluginResult::Continue
    ));
    assert!(!ctx.metadata.contains_key("a2a.error"));
}

/// A card this plugin ADMITTED whose transform phase never reported an outcome
/// must not be served. "The rewrite silently did not run" and "no rewrite was
/// needed" must not be indistinguishable.
#[tokio::test]
async fn grpc_agent_card_admitted_but_never_transformed_fails_closed() {
    let plugin = plugin(json!({
        "discovery": { "public_base_url": "https://gateway.example.com" }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let body = versioned_agent_card_body("0.3.0");
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    // Transform phase deliberately skipped.
    let final_result = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        final_result,
        "agent_card_grpc_rewrite_not_applied",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

/// A retained-ceiling refusal is owned by the shared capacity terminal. This
/// plugin must not additionally publish an `INTERNAL` over it, which would
/// relabel a health-neutral gateway capacity `503` as a gateway defect.
#[tokio::test]
async fn grpc_agent_card_capacity_refusal_does_not_also_publish_internal() {
    use ferrum_edge::_test_support::take_buffered_response_capacity_refusal_pending_for_test;

    let plugin = plugin(json!({
        "discovery": { "public_base_url": "https://gateway.example.com" }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let body = versioned_agent_card_body("0.3.0");
    ctx.max_response_body_size_bytes = 8;
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none()
    );
    assert!(take_buffered_response_capacity_refusal_pending_for_test(
        &mut ctx
    ));
    // The proxy has by now installed the shared capacity terminal (503).
    assert!(matches!(
        plugin
            .on_final_response_body(&mut ctx, 503, &response_headers, &[])
            .await,
        PluginResult::Continue
    ));
}

/// Drive admission over a hand-built message and return the outcome.
async fn admit_raw_card_message(message: Vec<u8>) -> (RequestContext, PluginResult) {
    let plugin = plugin(json!({
        "discovery": { "public_base_url": "https://gateway.example.com" }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let body = frame_grpc_message(&message);
    let mut response_headers = grpc_ok_response_headers();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    (ctx, result)
}

/// A known field carrying an unexpected wire type used to fall through the
/// rewriter's catch-all and be PRESERVED verbatim while its siblings were
/// rewritten and the signature block was dropped — a half-rewritten card served
/// under no signature at all.
#[tokio::test]
async fn grpc_agent_card_known_field_with_wrong_wire_type_fails_closed() {
    let mut card = Vec::new();
    encode_proto_string(1, "planner", &mut card);
    encode_proto_string(2, "planning agent", &mut card);
    // Field 3 (`url`) declared as a varint rather than a length-delimited
    // string. `has_endpoint` is satisfied by field number, so the card is still
    // Agent-Card shaped and reaches schema validation.
    encode_proto_varint_field(3, 7, &mut card);
    encode_proto_string(14, "JSONRPC", &mut card);
    encode_proto_string(16, "0.3.0", &mut card);
    let (ctx, result) = admit_raw_card_message(card).await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_field_wire_mismatch",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

/// `additional_interfaces` submessages are schema-validated too, so a wrong wire
/// type inside one cannot ride along.
#[tokio::test]
async fn grpc_agent_card_interface_field_with_wrong_wire_type_fails_closed() {
    let mut interface = Vec::new();
    encode_proto_varint_field(1, 7, &mut interface); // url as a varint
    encode_proto_string(2, "JSONRPC", &mut interface);
    let mut card = Vec::new();
    encode_proto_string(1, "planner", &mut card);
    encode_proto_string(2, "planning agent", &mut card);
    encode_proto_string(3, "https://planner.internal/grpc", &mut card);
    encode_proto_string(14, "GRPC", &mut card);
    encode_proto_bytes(15, &interface, &mut card);
    encode_proto_string(16, "0.3.0", &mut card);
    let (ctx, result) = admit_raw_card_message(card).await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_field_wire_mismatch",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

/// proto3 last-wins would let a backend hide the URL that actually gets served
/// behind a decoy earlier in the message, so a duplicated singular field is
/// ambiguous and fails closed.
#[tokio::test]
async fn grpc_agent_card_duplicated_singular_field_fails_closed() {
    let mut card = Vec::new();
    encode_proto_string(1, "planner", &mut card);
    encode_proto_string(2, "planning agent", &mut card);
    encode_proto_string(3, "https://decoy.internal/a2a", &mut card);
    encode_proto_string(3, "https://planner.internal/a2a", &mut card);
    encode_proto_string(14, "JSONRPC", &mut card);
    encode_proto_string(16, "0.3.0", &mut card);
    let (ctx, result) = admit_raw_card_message(card).await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_field_duplicated",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

/// A duplicated `protocol_version` is ambiguous about which version admitted the
/// card, so it is refused before the layout gate can pick one.
#[tokio::test]
async fn grpc_agent_card_duplicated_protocol_version_fails_closed() {
    let mut card = Vec::new();
    encode_proto_string(1, "planner", &mut card);
    encode_proto_string(2, "planning agent", &mut card);
    encode_proto_string(3, "https://planner.internal/a2a", &mut card);
    encode_proto_string(14, "JSONRPC", &mut card);
    encode_proto_string(16, "1.0.0", &mut card);
    encode_proto_string(16, "0.3.0", &mut card);
    let (ctx, result) = admit_raw_card_message(card).await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_field_duplicated",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

/// A ten-byte varint's final byte contributes bits 63..69, so only `0x00` and
/// `0x01` are representable. A permissive decoder truncates the rest with the
/// shift and reads a DIFFERENT tag than any conforming parser would.
#[tokio::test]
async fn grpc_agent_card_ten_byte_varint_overflow_fails_closed() {
    let mut message = vec![0x80u8; 9];
    message.push(0x02); // final group > 1
    let (ctx, result) = admit_raw_card_message(message).await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_varint_overflow",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

/// A continuation chain ending in a zero group encodes a value that already fit
/// in fewer bytes. Every conforming encoder emits the minimal form, so the
/// redundant one is refused rather than accepted as an alias for the same tag.
#[tokio::test]
async fn grpc_agent_card_noncanonical_varint_fails_closed() {
    // `0x8a 0x00` is a non-minimal encoding of the field-1 LEN tag `0x0a`.
    let message = vec![0x8a, 0x00, 0x01, 0x61];
    let (ctx, result) = admit_raw_card_message(message).await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_varint_noncanonical",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

/// The protobuf maximum field number is `2^29 - 1`. A larger key is not a valid
/// tag; casting it to `u32` truncates it into one that IS valid, which is how a
/// hostile message gets a field to mean two things at once.
#[tokio::test]
async fn grpc_agent_card_out_of_range_field_number_fails_closed() {
    let mut message = Vec::new();
    // Field number 2^29, wire LEN.
    encode_proto_varint((1u64 << 29) << 3 | 2, &mut message);
    encode_proto_varint(1, &mut message);
    message.push(b'a');
    let (ctx, result) = admit_raw_card_message(message).await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_field_invalid",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_web_content_type_is_not_detected_as_native_grpc() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = grpc_ctx("SendMessage", "application/grpc-web+proto");

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("a2a.enabled"));
}

#[tokio::test]
async fn grpc_policy_deny_returns_reject_for_proxy_normalization() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("SendMessage", "application/grpc");

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!("expected gRPC policy denial");
    };
    assert_eq!(status_code, 403);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"error": "A2A method denied by gateway policy"})
    );
}

#[tokio::test]
async fn grpc_policy_deny_applies_to_legacy_default_a2a_10_service() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("SendMessage", "application/grpc");
    ctx.path = "/lf.a2a.v1.A2AService/SendMessage".to_string();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
}

#[tokio::test]
async fn task_id_metadata_uses_known_a2a_locations_only() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-4",
        "method": "message/send",
        "params": {
            "message": {
                "parts": [
                    {"id": "part-id", "name": "part-name"}
                ]
            }
        }
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("a2a.task_id"));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "jsonrpc": "2.0",
        "id": "req-4",
        "result": [
            {"id": "task-from-list"}
        ]
    })
    .to_string();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("a2a.task_id"));
}

#[tokio::test]
async fn task_id_metadata_uses_nested_message_task_id() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-nested-task",
        "method": "message/send",
        "params": {
            "message": {
                "taskId": "task-1",
                "parts": [
                    {"id": "part-id"}
                ]
            }
        }
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("a2a.task_id").map(String::as_str),
        Some("task-1")
    );
}

#[tokio::test]
async fn response_metadata_normalizes_task_state() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-5",
        "method": "tasks/get",
        "params": {"id": "task-1"}
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "jsonrpc": "2.0",
        "id": "req-5",
        "result": {
            "id": "task-1",
            "status": {
                "state": "TASK_STATE_CANCELLED"
            }
        }
    })
    .to_string();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("a2a.task_state").map(String::as_str),
        Some("canceled")
    );
}

#[tokio::test]
async fn streaming_jsonrpc_does_not_force_response_buffering() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-3",
        "method": "message/stream"
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!plugin.should_buffer_response_body(&ctx));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &headers
    ));
}

#[tokio::test]
async fn retry_marked_sse_response_is_released_while_json_stays_buffered() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-retry",
        "method": "message/send",
        "params": {}
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    // Classified non-streaming: the pre-flight decision buffers, and the
    // plugin must advertise the retry release so retry-enabled dispatch
    // keeps a header-first transport instead of committing to collection.
    assert!(plugin.should_buffer_response_body(&ctx));
    assert!(plugin.may_release_response_body_under_retries(&ctx));

    // Backend unexpectedly answers with SSE: released under retries, exactly
    // matching the non-retry content-type escape hatch.
    let sse_headers = HashMap::from([(
        "content-type".to_string(),
        "text/event-stream; charset=utf-8".to_string(),
    )]);
    assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &sse_headers));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream; charset=utf-8"),
        200,
        &sse_headers,
    ));

    // JSON responses stay buffered on both paths so metadata extraction,
    // agent-card rewriting, and retry replay keep working.
    let json_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &json_headers));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &json_headers,
    ));

    // Non-JSON, non-SSE responses also stay buffered under retries: the
    // non-retry path buffers them for `a2a.response_body_size` and payload
    // metadata, and the retry release must never be broader than that.
    let text_headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &text_headers));
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &HashMap::new()));
}

#[tokio::test]
async fn retry_release_is_not_advertised_without_an_active_buffering_decision() {
    let plugin = plugin(json!({}));
    let sse_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    // Streaming-classified request: the plugin is not an active buffering
    // plugin, so it must not advertise the retry release either.
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-stream",
        "method": "message/stream"
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!plugin.should_buffer_response_body(&ctx));
    assert!(!plugin.may_release_response_body_under_retries(&ctx));
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &sse_headers));

    // Undetected request: same.
    let undetected_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/unrelated".to_string(),
    );
    assert!(!plugin.may_release_response_body_under_retries(&undetected_ctx));
    assert!(!plugin.should_release_response_body_under_retries(&undetected_ctx, 200, &sse_headers));

    // Native gRPC A2A request: capture is HTTP-only, so no retry release.
    let (mut grpc_ctx, mut grpc_headers) = grpc_ctx("SendMessage", "application/grpc");
    let result = plugin.before_proxy(&mut grpc_ctx, &mut grpc_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!plugin.should_buffer_response_body(&grpc_ctx));
    assert!(!plugin.may_release_response_body_under_retries(&grpc_ctx));
}

#[tokio::test]
async fn streaming_jsonrpc_inspector_extracts_multichunk_sse_terminal_metadata() {
    let plugin = plugin(json!({}));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&plugin)];
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-stream",
        "method": "message/stream"
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.requires_response_stream_hooks());
    assert!(plugin.forces_reqwest_dispatch(&ctx));

    let mut inspector = create_response_stream_inspector(
        &plugins,
        &mut ctx,
        200,
        Some("text/event-stream; charset=utf-8"),
    )
    .expect("detected 2xx A2A SSE response should attach an inspector");
    let chunks: &[&[u8]] = &[
        b"data: {\"jsonrpc\":\"2.0\",\"result\":{\"taskId\":\"task-9\",\"contextId\":\"ctx-4\",\"status\":{\"state\":\"working\"}}}\n\nda",
        b"ta: {\"jsonrpc\":\"2.0\",\"result\":{\"taskId\":\"task-9\",\"contextId\":\"ctx-4\",\"status\":{\"state\":\"TASK_STATE_",
        b"COMPLETED\"},\"final\":true}}\r",
        b"\n\r\n",
    ];
    for chunk in chunks {
        let action = inspector.on_chunk(chunk).await;
        let ResponseStreamAction::Forward(forwarded) = action else {
            panic!("observe-only A2A inspector must never terminate a stream");
        };
        assert_eq!(forwarded.as_ref(), *chunk);
    }
    let end = inspector.on_end().await;
    assert!(matches!(end, ResponseStreamAction::Forward(ref bytes) if bytes.is_empty()));
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(0))
        .await;

    assert_eq!(
        ctx.metadata.get("a2a.stream_events").map(String::as_str),
        Some("2")
    );
    assert_eq!(
        ctx.metadata.get("a2a.task_id").map(String::as_str),
        Some("task-9")
    );
    assert_eq!(
        ctx.metadata.get("a2a.context_id").map(String::as_str),
        Some("ctx-4")
    );
    assert_eq!(
        ctx.metadata.get("a2a.task_state").map(String::as_str),
        Some("completed")
    );

    let extras = vec![
        "a2a.task_id".to_string(),
        "a2a.context_id".to_string(),
        "a2a.task_state".to_string(),
    ];
    for key in ["a2a.task_id", "a2a.context_id", "a2a.task_state"] {
        assert!(
            is_sensitive_metadata_key_with_extras(key, &extras),
            "central metadata serialization must redact {key}"
        );
    }
}

#[tokio::test]
async fn streaming_jsonrpc_termination_before_inspector_end_does_not_emit_metadata() {
    let plugin = plugin(json!({}));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&plugin)];
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-stream",
        "method": "message/stream"
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("detected 2xx A2A SSE response should attach an inspector");
    let chunk = b"data: {\"result\":{\"taskId\":\"task-9\"}}\n\n";
    assert!(matches!(
        inspector.on_chunk(chunk).await,
        ResponseStreamAction::Forward(_)
    ));

    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::client_disconnect(0))
        .await;
    assert!(!ctx.metadata.contains_key("a2a.stream_events"));
    assert!(!ctx.metadata.contains_key("a2a.task_id"));

    let end = inspector.on_end().await;
    assert!(matches!(end, ResponseStreamAction::Forward(ref bytes) if bytes.is_empty()));
}

#[tokio::test]
async fn streaming_jsonrpc_observation_omits_absent_optional_metadata() {
    let plugin = plugin(json!({}));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&plugin)];
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-stream",
        "method": "message/stream"
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("detected 2xx A2A SSE response should attach an inspector");
    let chunk = b"data: {\"jsonrpc\":\"2.0\",\"result\":{}}\n\n";
    assert!(matches!(
        inspector.on_chunk(chunk).await,
        ResponseStreamAction::Forward(_)
    ));
    let end = inspector.on_end().await;
    assert!(matches!(end, ResponseStreamAction::Forward(ref bytes) if bytes.is_empty()));

    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(chunk.len() as u64))
        .await;
    assert_eq!(
        ctx.metadata.get("a2a.stream_events").map(String::as_str),
        Some("1")
    );
    for key in ["a2a.task_id", "a2a.context_id", "a2a.task_state"] {
        assert!(!ctx.metadata.contains_key(key));
    }
}

#[tokio::test]
async fn streaming_termination_is_a_noop_when_metadata_is_disabled() {
    let plugin = plugin(json!({
        "observability": {"emit_metadata": false}
    }));
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/a2a".to_string(),
    );

    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(0))
        .await;
    assert!(ctx.metadata.is_empty());
}

#[tokio::test]
async fn streaming_jsonrpc_inspector_forwards_incomplete_event_without_holding() {
    let plugin = plugin(json!({}));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&plugin)];
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-stream",
        "method": "message/stream"
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 206, Some("TEXT/EVENT-STREAM"))
            .expect("detected 2xx A2A SSE response should attach an inspector");
    let partial = b"data: {\"result\":{\"status\":{\"state\":\"work";
    let action = inspector.on_chunk(partial).await;
    let ResponseStreamAction::Forward(forwarded) = action else {
        panic!("observe-only A2A inspector must never terminate a stream");
    };
    assert_eq!(forwarded.as_ref(), partial);
    let end = inspector.on_end().await;
    assert!(matches!(end, ResponseStreamAction::Forward(ref bytes) if bytes.is_empty()));

    assert!(
        plugin
            .response_stream_inspector(&ctx, 500, Some("text/event-stream"))
            .is_none()
    );
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("application/json"))
            .is_none()
    );
}

#[test]
fn invalid_grpc_service_is_rejected() {
    let result = create_plugin(
        "a2a_gateway",
        &json!({
            "endpoint": {
                "grpc_services": ["not valid"]
            }
        }),
    );
    let err = match result {
        Ok(_) => panic!("invalid service should reject config"),
        Err(err) => err,
    };
    assert!(err.contains("endpoint.grpc_services"));
}

#[test]
fn invalid_a2a_gateway_configs_are_rejected() {
    let cases = [
        (
            json!({"mode": "active_gateway"}),
            "mode",
            "non-transparent mode should reject",
        ),
        (
            json!({"endpoint": {"path": "a2a"}}),
            "endpoint.path",
            "endpoint path must be absolute",
        ),
        (
            json!({"endpoint": {"protocol_versions": []}}),
            "endpoint.protocol_versions",
            "protocol versions cannot be empty",
        ),
        (
            json!({"endpoint": {"grpc_services": ["a2a.v1.A2AService", "a2a.v1.A2AService"]}}),
            "duplicate endpoint.grpc_services",
            "duplicate gRPC services should reject",
        ),
        (
            json!({"detection": {"bindings": []}}),
            "detection.bindings",
            "bindings cannot be empty",
        ),
        (
            json!({"detection": {"version_header": "not a header"}}),
            "detection.version_header",
            "version header must be a valid header name",
        ),
        (
            json!({"discovery": {"public_base_url": "ftp://agents.example.com"}}),
            "discovery.public_base_url scheme",
            "public base scheme must be HTTP-family",
        ),
        (
            json!({"discovery": {"public_base_url": "https://agents.example.com?a=b"}}),
            "discovery.public_base_url must not contain query",
            "public base cannot carry query",
        ),
        (
            json!({"discovery": {"public_base_url": "https://user:pass@agents.example.com"}}),
            "discovery.public_base_url must not contain credentials",
            "public base cannot carry credentials",
        ),
        (
            json!({"observability": {"max_payload_size": 0}}),
            "observability.max_payload_size",
            "payload size must be positive",
        ),
    ];

    for (config, expected, label) in cases {
        let result = create_plugin("a2a_gateway", &config);
        let err = match result {
            Ok(_) => panic!("{label}"),
            Err(err) => err,
        };
        assert!(
            err.contains(expected),
            "{label}: expected {expected:?} in {err:?}"
        );
    }
}

const A2A_GATEWAY_SOURCE: &str = include_str!("../../../src/plugins/a2a_gateway.rs");

/// Every fixed gRPC Agent Card diagnostic string literal the plugin source
/// carries.
///
/// Scanned from the opening quote of each known prefix rather than by splitting
/// on `"`, so an escaped quote elsewhere in the file cannot desynchronize the
/// parity and silently shrink the set this test compares against.
fn agent_card_diagnostic_literals(source: &str) -> Vec<&str> {
    let mut found = Vec::new();
    for prefix in [
        "\"agent_card_protobuf_",
        "\"agent_card_grpc_",
        "\"agent_card_public_",
        "\"unsupported_agent_card_",
    ] {
        let mut rest = source;
        while let Some(index) = rest.find(prefix) {
            let tail = &rest[index + 1..];
            let end = tail
                .find('"')
                .expect("a string literal must have a closing quote");
            found.push(&tail[..end]);
            rest = &tail[end..];
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

/// The gRPC Agent Card diagnostic enumeration in `docs/plugins.md` is a
/// *complete* list of client-visible codes, not a sample.
///
/// It is published as an operator-facing contract, so an omission is worse than
/// no list at all: an operator who cannot find an observed `a2a.error` in the
/// table concludes their gateway produced something undocumented. This pins both
/// directions — every client-visible diagnostic in the source is in the table,
/// and every diagnostic in the table exists in the source.
#[test]
fn grpc_agent_card_diagnostics_are_completely_documented() {
    const GUIDE: &str = include_str!("../../../docs/plugins.md");
    // Internal sentinel for "the output pass refused a write". Callers translate
    // it into `agent_card_grpc_frame_too_large` or the shared capacity terminal,
    // so it must never be documented as a client-visible diagnostic.
    const INTERNAL_ONLY: &str = "agent_card_protobuf_emit_refused";

    let section = GUIDE
        .split("### `a2a_gateway`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("a2a_gateway docs section");
    let literals = agent_card_diagnostic_literals(A2A_GATEWAY_SOURCE);
    assert!(
        literals.len() > 1,
        "diagnostic extraction found {} literals — the scan is broken",
        literals.len()
    );

    let mut documented = 0usize;
    for diagnostic in &literals {
        if *diagnostic == INTERNAL_ONLY {
            assert!(
                !section.contains(diagnostic),
                "{INTERNAL_ONLY} never reaches a client and must not be documented as a diagnostic"
            );
            continue;
        }
        assert!(
            section.contains(&format!("| `{diagnostic}` |")),
            "docs/plugins.md must list the client-visible diagnostic {diagnostic} \
             in the a2a_gateway gRPC Agent Card table"
        );
        documented += 1;
    }
    assert!(
        documented > 0,
        "no client-visible diagnostics were checked against the guide"
    );

    // Reverse direction, restricted to the diagnostic table's own rows so an
    // unrelated parameter table in this section cannot be misread as one.
    const STAGES: [&str; 6] = [
        "Service schema",
        "Framing",
        "Version/layout",
        "Schema",
        "Decoding",
        "Emission",
    ];
    for line in section.lines() {
        let Some(row) = line.strip_prefix("| ") else {
            continue;
        };
        let mut columns = row.split('|');
        let stage = columns.next().unwrap_or_default().trim();
        if !STAGES.contains(&stage) {
            continue;
        }
        let Some(name) = columns.next() else {
            continue;
        };
        let name = name.trim().trim_matches('`');
        assert!(
            literals.contains(&name),
            "docs/plugins.md documents {name}, which the plugin source cannot produce"
        );
    }
}

/// The OpenAPI `endpoint.grpc_services` description must describe what the gRPC
/// binding actually does. It used to say the payloads are never decoded, which
/// stopped being true when unary Agent Card decode/rewrite landed.
#[test]
fn openapi_grpc_services_describes_agent_card_decoding() {
    const SPEC: &str = include_str!("../../../openapi.yaml");

    assert!(
        !SPEC.contains("without decoding protobuf payloads"),
        "openapi.yaml must not claim the A2A gRPC binding never decodes protobuf payloads"
    );
    let scoped = "The one decoded payload is the unary Agent Card reply \
                  (GetAgentCard / GetExtendedAgentCard)";
    assert!(
        SPEC.contains(scoped),
        "openapi.yaml endpoint.grpc_services must scope protobuf decoding \
         to unary Agent Card replies"
    );
}

/// The published `endpoint.grpc_services` default must be the gRPC service
/// identity whose Agent Card layout this plugin actually implements.
///
/// The whole point of the repair is that a service NAME and a card LAYOUT are
/// separate facts: the spec previously advertised A2A 1.0's
/// `lf.a2a.v1.A2AService` as the default of a gateway that decodes A2A 0.3
/// cards, so an operator reading the spec was told the wrong pairing. Pinning it
/// here keeps the documented default, the runtime default, and the implemented
/// wire layout from drifting apart again.
#[test]
fn openapi_grpc_services_default_is_the_canonical_a2a_03_service() {
    const SPEC: &str = include_str!("../../../openapi.yaml");

    // The schema body is every line indented deeper than the 4-space key line,
    // so the section ends at the next sibling schema key rather than at the
    // first nested mapping (which a naive prefix split would truncate on).
    let mut section = String::new();
    let mut inside = false;
    for line in SPEC.lines() {
        if line == "    A2aGatewayConfig:" {
            inside = true;
            continue;
        }
        if inside {
            let is_sibling_key =
                line.starts_with("    ") && !line.starts_with("     ") && !line.trim().is_empty();
            if is_sibling_key {
                break;
            }
            section.push_str(line);
            section.push('\n');
        }
    }
    assert!(inside, "A2aGatewayConfig schema section not found");
    let section = section.as_str();
    // Both published identities are recognized by default so a deployment that
    // relied on the former 1.0 default keeps method-policy enforcement, but the
    // 0.3 service stays FIRST: it is the primary identity, and the only one
    // eligible for Agent Card rewriting.
    assert!(
        section.contains(r#"default: ["a2a.v1.A2AService", "lf.a2a.v1.A2AService"]"#),
        "endpoint.grpc_services must default to the canonical A2A 0.3 service first, \
         with A2A 1.0 recognized for policy"
    );
    assert!(
        !section.contains(r#"default: ["lf.a2a.v1.A2AService"]"#),
        "A2A 1.0's service must not be the default of a 0.3 Agent Card rewriter"
    );
    assert!(
        section.contains(r#"default: ["0.3.0"]"#),
        "the default protocol version must stay the one a2a.v1.A2AService carries"
    );
    for enumerated in ["a2a-0.3", "a2a-1.0", "none"] {
        assert!(
            section.contains(enumerated),
            "the card_schema enumeration must publish {enumerated}"
        );
    }
    for diagnostic in [
        "agent_card_grpc_schema_unsupported",
        "agent_card_grpc_schema_undeclared",
    ] {
        assert!(
            section.contains(diagnostic),
            "openapi.yaml must document the fail-closed disposition {diagnostic}"
        );
    }
}

/// The runtime default and the published default are the same service, proven
/// through detection rather than by reading a constant.
#[tokio::test]
async fn default_grpc_service_detection_matches_the_published_default() {
    let plugin = plugin(json!({}));
    for (service, expected) in [
        ("a2a.v1.A2AService", true),
        ("lf.a2a.v1.A2AService", true),
        ("acme.agents.v1.AgentService", false),
    ] {
        let (_, detected) = detect_grpc_card_on_service(&plugin, service, "GetTask").await;
        assert_eq!(
            detected, expected,
            "{service}: default gRPC service detection disagrees with openapi.yaml"
        );
    }
}

// ── Replay presentation provenance (issue #3297 root review) ────────────────
//
// `transform_response_body_with_context` is a client-facing presentation
// transform, and `request_deduplication` deliberately skips such transforms
// when it replays a finalized representation. Without enrollment here, a
// retained Agent Card could be replayed under a public base, endpoint path,
// admitted protocol version, or rewrite switch that has since changed.

fn presentation_policy(config: Value) -> ResponsePresentationPolicy {
    plugin(config)
        .response_presentation_policy()
        .expect("a2a_gateway must always enroll in replay presentation provenance")
}

fn static_presentation_digest(config: Value) -> [u8; 32] {
    match presentation_policy(config) {
        ResponsePresentationPolicy::Static(digest) => digest,
        ResponsePresentationPolicy::Dynamic => {
            panic!("expected a provable static presentation policy")
        }
    }
}

fn configured_base_config() -> Value {
    json!({
        "endpoint": {
            "path": "/a2a",
            "agent_card_path": "/.well-known/agent-card.json",
            "protocol_versions": ["0.3.0"]
        },
        "discovery": {
            "rewrite_agent_card_urls": true,
            "public_base_url": "https://agents.example.com"
        }
    })
}

/// A digest that depended on map iteration order, or on which process computed
/// it, could not prove anything about a representation persisted to Redis and
/// read back by a different gateway.
#[test]
fn a2a_static_presentation_digest_is_stable_for_equivalent_configs() {
    let one_order = r#"{"discovery":{"public_base_url":"https://a.example.com",
        "rewrite_agent_card_urls":true},"endpoint":{"path":"/a2a"}}"#;
    let other_order = r#"{"endpoint":{"path":"/a2a"},"discovery":{
        "rewrite_agent_card_urls":true,"public_base_url":"https://a.example.com"}}"#;
    let one: Value = serde_json::from_str(one_order).expect("fixture must parse");
    let other: Value = serde_json::from_str(other_order).expect("fixture must parse");

    assert_eq!(
        static_presentation_digest(one.clone()),
        static_presentation_digest(other),
        "equivalent configuration must digest identically regardless of key order"
    );
    assert_eq!(
        static_presentation_digest(one.clone()),
        static_presentation_digest(one),
        "two instances of one configuration must digest identically"
    );
}

/// Every knob that shapes a client-visible Agent Card must move the digest, or
/// a representation retained under the old value would keep replaying.
#[test]
fn a2a_static_presentation_digest_moves_when_card_shaping_config_changes() {
    let mut changed_public_base = configured_base_config();
    changed_public_base["discovery"]["public_base_url"] = json!("https://other.example.com");

    let mut changed_endpoint_path = configured_base_config();
    changed_endpoint_path["endpoint"]["path"] = json!("/agents");

    let mut changed_card_path = configured_base_config();
    changed_card_path["endpoint"]["agent_card_path"] = json!("/.well-known/agent.json");

    let mut changed_versions = configured_base_config();
    changed_versions["endpoint"]["protocol_versions"] = json!(["0.3.0", "0.3.1"]);

    let mut rewrite_disabled = configured_base_config();
    rewrite_disabled["discovery"]["rewrite_agent_card_urls"] = json!(false);

    let mut plugin_disabled = configured_base_config();
    plugin_disabled["enabled"] = json!(false);

    let labels = [
        "base",
        "public base",
        "endpoint path",
        "agent card path",
        "admitted protocol versions",
        "rewrite switch",
        "enabled switch",
    ];
    let digests = [
        static_presentation_digest(configured_base_config()),
        static_presentation_digest(changed_public_base),
        static_presentation_digest(changed_endpoint_path),
        static_presentation_digest(changed_card_path),
        static_presentation_digest(changed_versions),
        static_presentation_digest(rewrite_disabled),
        static_presentation_digest(plugin_disabled),
    ];

    for (index, digest) in digests.iter().enumerate() {
        for (other_index, other) in digests.iter().enumerate() {
            if index == other_index {
                continue;
            }
            assert_ne!(
                digest, other,
                "the {} and {} configurations must not share replay provenance",
                labels[index], labels[other_index]
            );
        }
    }
}

/// The forwarded-derived public base is not static configuration: absent an
/// `X-Forwarded-Proto`, the scheme comes from whether the connection carried a
/// TLS SNI hostname, which no replay fingerprint binds.
#[test]
fn a2a_request_derived_public_base_reports_dynamic_presentation_policy() {
    let config = json!({"discovery": {
        "trust_forwarded_headers": true,
        "allowed_public_origins": ["https://gateway.example.com"]
    }});
    assert_eq!(
        presentation_policy(config),
        ResponsePresentationPolicy::Dynamic,
        "a forwarded/SNI-derived public base cannot be described by a static digest"
    );
}

/// A configured public base is the provable mode and must keep composing with
/// deduplication, even when forwarded headers are also trusted — the configured
/// value wins inside `public_base_url`.
#[test]
fn a2a_configured_public_base_stays_static_even_with_forwarded_trust() {
    let mut trusting = configured_base_config();
    trusting["discovery"]["trust_forwarded_headers"] = json!(true);

    assert_ne!(
        static_presentation_digest(trusting),
        static_presentation_digest(configured_base_config()),
        "the accepted configuration differs, so the digest must differ too"
    );
}

/// Enrollment is unconditional. An instance that rewrites nothing still binds a
/// stored representation to "nothing was rewritten", so turning the rewrite back
/// on cannot be skipped by a retained replay.
#[test]
fn a2a_inert_instances_still_enroll_a_static_presentation_policy() {
    let internally_disabled = json!({
        "enabled": false,
        "discovery": {
            "trust_forwarded_headers": true,
            "allowed_public_origins": ["https://gateway.example.com"]
        }
    });
    let rewriting_disabled = json!({
        "discovery": {
            "rewrite_agent_card_urls": false,
            "trust_forwarded_headers": true,
            "allowed_public_origins": ["https://gateway.example.com"]
        }
    });

    for config in [
        internally_disabled,
        rewriting_disabled,
        json!({"discovery": {"rewrite_agent_card_urls": false}}),
    ] {
        assert!(
            matches!(
                presentation_policy(config.clone()),
                ResponsePresentationPolicy::Static(_)
            ),
            "an inert a2a_gateway ({config}) applies no request-derived rewrite \
             and must stay provable"
        );
    }
}

// ── Absolute-URL proof (issue #3297 root review) ────────────────────────────

/// A `http://` / `https://` prefix is not a URL. Each of these begins with one
/// and is still not an absolute http(s) URL with a real host and no embedded
/// credentials, so the rewriter must treat it as a layout mismatch rather than
/// mutating around it.
#[tokio::test]
async fn grpc_agent_card_absolute_looking_urls_fail_closed() {
    let over_length = format!("https://planner.internal/{}", "a".repeat(5000));
    let cases = [
        // No authority at all — not an explicit canonical spelling.
        "https://",
        "https:///",
        "https://:8080/a2a",
        "http:///a2a",
        "https:////planner.internal/a2a",
        "http://\\planner.internal/a2a",
        "https:\\planner.internal/a2a",
        "https://user:pass@planner.internal/a2a",
        "http://token@planner.internal/a2a",
        "http://[::1/a2a",
        "https://plan ner.internal/a2a",
        // Begins with neither scheme, so it is not absolute.
        "//planner.internal/a2a",
        // An absolute URL, but not an http-family one.
        "file:///a2a",
        over_length.as_str(),
    ];

    for url in cases {
        let card = encode_minimal_agent_card("planner", "planning agent", url, |out| {
            encode_proto_string(14, "JSONRPC", out);
            encode_proto_string(16, "0.3.0", out);
        });
        let (ctx, result) = admit_raw_card_message(card).await;
        assert_grpc_rewrite_reject(
            result,
            "agent_card_protobuf_url_layout_mismatch",
            ctx.metadata.get("a2a.error").map(String::as_str),
        );
    }
}

/// Ambiguous absolute-URL spellings whose authority exists only after parser
/// recovery must fail closed at the Agent Card boundary.
#[tokio::test]
async fn grpc_agent_card_ambiguous_absolute_url_spellings_fail_closed() {
    let cases = [
        "http:///a2a",
        "https:////planner.internal/a2a",
        "http://\\planner.internal/a2a",
        "https:\\planner.internal/a2a",
    ];

    for url in cases {
        let card = encode_minimal_agent_card("planner", "planning agent", url, |out| {
            encode_proto_string(14, "JSONRPC", out);
            encode_proto_string(16, "0.3.0", out);
        });
        let (ctx, result) = admit_raw_card_message(card).await;
        assert_grpc_rewrite_reject(
            result,
            "agent_card_protobuf_url_layout_mismatch",
            ctx.metadata.get("a2a.error").map(String::as_str),
        );
    }
}

/// Ordinary absolute URLs with an explicit authority remain admitted.
#[tokio::test]
async fn grpc_agent_card_preserves_explicit_absolute_url_bytes() {
    let plugin = plugin(json!({
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let card = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "http://planner.internal/a2a",
        |out| {
            encode_proto_string(14, "GRPC", out);
            encode_proto_bytes(
                15,
                &encode_agent_interface("https://planner.internal/a2a", "JSONRPC"),
                out,
            );
            encode_proto_string(16, "0.3.0", out);
        },
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    let staged = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert!(
        matches!(staged, PluginResult::Continue),
        "an explicit-authority http URL must be admitted"
    );
    assert_eq!(ctx.metadata.get("a2a.error"), None);

    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("the JSONRPC interface still needs rewriting");
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("http://planner.internal/a2a"),
        "a preserved URL must be the backend's own bytes, never a normalized form"
    );
    assert_eq!(
        proto_string_field(&proto_repeated_messages(message, 15)[0], 1).as_deref(),
        Some("https://gateway.example.com/a2a"),
    );
}

/// The same proof applies inside every advertised interface, which is where a
/// serialized submessage most plausibly masquerades as a URL string.
#[tokio::test]
async fn grpc_agent_card_absolute_looking_interface_url_fails_closed() {
    let interface = encode_agent_interface("https://user:pass@planner.internal/grpc", "GRPC");
    let mut card = Vec::new();
    encode_proto_string(1, "planner", &mut card);
    encode_proto_string(2, "planning agent", &mut card);
    encode_proto_string(3, "https://planner.internal/a2a", &mut card);
    encode_proto_string(14, "JSONRPC", &mut card);
    encode_proto_bytes(15, &interface, &mut card);
    encode_proto_string(16, "0.3.0", &mut card);
    let (ctx, result) = admit_raw_card_message(card).await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_url_layout_mismatch",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

/// An interface with no URL is not a usable endpoint: nothing would rewrite it,
/// yet it would be preserved verbatim inside a card published as rewritten with
/// its signatures removed — and it would be the only evidence the card
/// advertised an endpoint at all.
#[tokio::test]
async fn grpc_agent_card_interface_without_url_fails_closed() {
    let mut interface = Vec::new();
    encode_proto_string(2, "JSONRPC", &mut interface);
    let mut card = Vec::new();
    encode_proto_string(1, "planner", &mut card);
    encode_proto_string(2, "planning agent", &mut card);
    encode_proto_bytes(15, &interface, &mut card);
    encode_proto_string(16, "0.3.0", &mut card);
    let (ctx, result) = admit_raw_card_message(card).await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_interface_url_missing",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

// ── Complete A2A 0.3 field-table validation (issue #3297 root review) ───────

/// Base card carrying every known 0.3 top-level field, so the validation table
/// is exercised as a whole rather than field by field.
fn encode_complete_a2a_03_agent_card(url: &str, extras: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut card = Vec::new();
    encode_proto_string(1, "planner", &mut card);
    encode_proto_string(2, "planning agent", &mut card);
    encode_proto_string(3, url, &mut card);
    // Opaque submessages the rewriter preserves without decoding.
    encode_proto_bytes(4, b"\x0a\x07acme.io", &mut card);
    encode_proto_string(5, "1.4.2", &mut card);
    encode_proto_string(6, "https://docs.example.com/planner", &mut card);
    encode_proto_bytes(7, b"\x08\x01", &mut card);
    encode_proto_bytes(8, b"\x0a\x05oauth", &mut card);
    encode_proto_bytes(9, b"\x0a\x03key", &mut card);
    encode_proto_string(10, "text/plain", &mut card);
    encode_proto_string(10, "application/json", &mut card);
    encode_proto_string(11, "application/json", &mut card);
    encode_proto_bytes(12, b"\x0a\x04plan", &mut card);
    encode_proto_varint_field(13, 1, &mut card);
    encode_proto_string(14, "JSONRPC", &mut card);
    encode_proto_bytes(
        15,
        &encode_agent_interface("https://planner.internal/grpc", "GRPC"),
        &mut card,
    );
    encode_proto_string(16, "0.3.0", &mut card);
    extras(&mut card);
    card
}

/// The complete card round-trips: the JSON-RPC endpoint is rewritten, every
/// opaque submessage and repeated string is preserved, and only the signature
/// block is dropped.
#[tokio::test]
async fn grpc_agent_card_complete_0_3_card_preserves_every_untouched_field() {
    let plugin = plugin(json!({
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let card = encode_complete_a2a_03_agent_card("https://planner.internal/a2a", |out| {
        let signature = encode_agent_card_signature("eyJhbGciOiJFUzI1NiJ9", "stale");
        encode_proto_bytes(17, &signature, out);
    });
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("a complete 0.3 card must rewrite");
    let message = &rewritten[5..];

    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    for preserved in [4u32, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
        assert!(
            proto_has_field(message, preserved),
            "field {preserved} must be preserved verbatim"
        );
    }
    assert!(
        !proto_has_field(message, 17),
        "signatures must be dropped once a URL mutation is published"
    );
    let interfaces = proto_repeated_messages(message, 15);
    assert_eq!(interfaces.len(), 1);
    assert_eq!(
        proto_string_field(&interfaces[0], 1).as_deref(),
        Some("https://planner.internal/grpc"),
        "a non-JSONRPC interface must be preserved verbatim"
    );
}

/// Every known top-level field must carry the wire type the 0.3 schema
/// declares. Before this, a known field with an unexpected wire type fell
/// through the rewriter's catch-all and was preserved beside rewritten siblings
/// after the signature block was dropped.
#[tokio::test]
async fn grpc_agent_card_known_fields_with_wrong_wire_types_fail_closed() {
    // Every length-delimited known field, declared as a varint instead.
    for field in [4u32, 5, 6, 7, 8, 9, 10, 11, 12] {
        let card = encode_minimal_agent_card(
            "planner",
            "planning agent",
            "https://planner.internal/a2a",
            |out| {
                encode_proto_varint_field(field, 7, out);
                encode_proto_string(14, "JSONRPC", out);
                encode_proto_string(16, "0.3.0", out);
            },
        );
        let (ctx, result) = admit_raw_card_message(card).await;
        assert_grpc_rewrite_reject(
            result,
            "agent_card_protobuf_field_wire_mismatch",
            ctx.metadata.get("a2a.error").map(String::as_str),
        );
    }

    // The one varint field, declared as a length-delimited string instead.
    let card = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |out| {
            encode_proto_string(13, "true", out);
            encode_proto_string(14, "JSONRPC", out);
            encode_proto_string(16, "0.3.0", out);
        },
    );
    let (ctx, result) = admit_raw_card_message(card).await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_field_wire_mismatch",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

/// proto3 last-wins would make a duplicated singular field ambiguous, so each
/// of them is claimed exactly once.
#[tokio::test]
async fn grpc_agent_card_duplicated_singular_fields_fail_closed() {
    for field in [4u32, 5, 6, 7] {
        let card = encode_minimal_agent_card(
            "planner",
            "planning agent",
            "https://planner.internal/a2a",
            |out| {
                encode_proto_bytes(field, b"\x0a\x01a", out);
                encode_proto_bytes(field, b"\x0a\x01b", out);
                encode_proto_string(14, "JSONRPC", out);
                encode_proto_string(16, "0.3.0", out);
            },
        );
        let (ctx, result) = admit_raw_card_message(card).await;
        assert_grpc_rewrite_reject(
            result,
            "agent_card_protobuf_field_duplicated",
            ctx.metadata.get("a2a.error").map(String::as_str),
        );
    }

    let card = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |out| {
            encode_proto_varint_field(13, 1, out);
            encode_proto_varint_field(13, 0, out);
            encode_proto_string(14, "JSONRPC", out);
            encode_proto_string(16, "0.3.0", out);
        },
    );
    let (ctx, result) = admit_raw_card_message(card).await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_field_duplicated",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

/// The genuinely repeated fields must still be allowed to repeat.
#[tokio::test]
async fn grpc_agent_card_repeated_fields_may_repeat() {
    let plugin = plugin(json!({
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let card = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |out| {
            encode_proto_bytes(8, b"\x0a\x05oauth", out);
            encode_proto_bytes(8, b"\x0a\x04mtls", out);
            encode_proto_bytes(9, b"\x0a\x03key", out);
            encode_proto_bytes(9, b"\x0a\x03alt", out);
            encode_proto_string(10, "text/plain", out);
            encode_proto_string(10, "application/json", out);
            encode_proto_string(11, "text/plain", out);
            encode_proto_string(11, "application/json", out);
            encode_proto_bytes(12, b"\x0a\x04plan", out);
            encode_proto_bytes(12, b"\x0a\x04cook", out);
            encode_proto_string(14, "JSONRPC", out);
            encode_proto_string(16, "0.3.0", out);
        },
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("repeated 0.3 fields must not block the rewrite");
    let message = &rewritten[5..];
    for repeated in [8u32, 9, 10, 11, 12] {
        assert_eq!(
            proto_repeated_messages(message, repeated).len(),
            2,
            "both {repeated} entries must be preserved"
        );
    }
}

/// A protobuf `bool` a conforming encoder never emits is refused rather than
/// preserved verbatim beside rewritten siblings.
#[tokio::test]
async fn grpc_agent_card_non_boolean_extended_card_flag_fails_closed() {
    for raw in [2u64, 255] {
        let card = encode_minimal_agent_card(
            "planner",
            "planning agent",
            "https://planner.internal/a2a",
            |out| {
                encode_proto_varint_field(13, raw, out);
                encode_proto_string(14, "JSONRPC", out);
                encode_proto_string(16, "0.3.0", out);
            },
        );
        let (ctx, result) = admit_raw_card_message(card).await;
        assert_grpc_rewrite_reject(
            result,
            "agent_card_protobuf_bool_invalid",
            ctx.metadata.get("a2a.error").map(String::as_str),
        );
    }
}

/// Known strings that get copied into the rebuilt card must be valid UTF-8, so
/// a value the gateway cannot even represent is never republished as though it
/// had been inspected.
#[tokio::test]
async fn grpc_agent_card_non_utf8_known_strings_fail_closed() {
    for field in [1u32, 2, 5, 6, 10, 11, 14] {
        let mut card = Vec::new();
        if field != 1 {
            encode_proto_string(1, "planner", &mut card);
        }
        encode_proto_string(3, "https://planner.internal/a2a", &mut card);
        encode_proto_bytes(field, &[0xff, 0xfe], &mut card);
        if field != 14 {
            encode_proto_string(14, "JSONRPC", &mut card);
        }
        encode_proto_string(16, "0.3.0", &mut card);
        let (ctx, result) = admit_raw_card_message(card).await;
        assert_grpc_rewrite_reject(
            result,
            "agent_card_protobuf_string_invalid",
            ctx.metadata.get("a2a.error").map(String::as_str),
        );
    }
}

#[tokio::test]
async fn policy_covers_unrecognized_shapes_and_disabled_bindings() {
    for policy in [
        json!({"default_action": "deny", "methods": {"tasks/get": {"action": "allow"}}}),
        json!({"methods": {"message/send": {"action": "deny"}}}),
    ] {
        let gateway = plugin(json!({"policy": policy}));
        for (method, path, content_type, body) in [
            ("POST", "/a2a/", "application/json", "{}"),
            ("POST", "/a2a", "application/json", "not-json"),
            ("POST", "/a2a", "application/json", "null"),
            ("POST", "/a2a", "application/json", "[]"),
            ("POST", "/a2a", "text/plain", "{}"),
            ("GET", "/a2a", "application/json", "{}"),
            ("PATCH", "/a2a/tasks/task-1", "application/json", "{}"),
            ("POST", "/a2a/message:send/", "application/json", "{}"),
            (
                "POST",
                "/a2a/tasks/t1//pushNotificationConfigs",
                "application/json",
                "{}",
            ),
            (
                "POST",
                "/a2a/tasks/t1/pushNotificationConfigs/",
                "application/json",
                "{}",
            ),
            (
                "POST",
                "/a2a.v1.A2AService/FutureCall",
                "application/grpc",
                "",
            ),
            ("GET", "/a2a.v1.A2AService/GetTask", "application/grpc", ""),
            (
                "POST",
                "/lf.a2a.v1.A2AService/FutureCall",
                "application/grpc",
                "",
            ),
            ("POST", "/a2a.v1.A2AService/GetTask", "text/plain", ""),
        ] {
            let (mut ctx, _) = rest_ctx(method, path);
            ctx.request_body_bytes = Some(Bytes::copy_from_slice(body.as_bytes()));
            ctx.headers
                .insert("content-type".to_string(), content_type.to_string());
            let mut headers = ctx.headers.clone();
            assert!(
                matches!(
                    gateway.before_proxy(&mut ctx, &mut headers).await,
                    PluginResult::Reject { .. }
                ),
                "{method} {path} {content_type} {body}"
            );
        }
        for path in [
            "/other",
            "/a2a-sibling",
            "/a2a.v1.A2AServiceSibling/FutureCall",
        ] {
            let (mut ctx, mut headers) = rest_ctx("POST", path);
            assert!(matches!(
                gateway.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ));
        }
        let (mut ctx, mut headers) = rest_ctx("GET", "/a2a/tasks/task-1");
        assert!(matches!(
            gateway.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
    }
    let gateway = plugin(json!({
        "detection": {"bindings": ["rest"]},
        "policy": {"default_action": "deny"}
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({"jsonrpc": "2.0", "method": "message/send"}));
    assert!(matches!(
        gateway.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn forwarded_card_origins_require_exact_allowlist_membership() {
    let gateway = plugin(json!({"discovery": {
        "trust_forwarded_headers": true,
        "allowed_public_origins": ["https://gateway.example.com"]
    }}));
    for (proto, host) in [
        ("https", "unapproved.example.com"),
        ("http", "gateway.example.com"),
        ("https", "gateway.example.com:444"),
        ("https", "gateway.example.com, unapproved.example.com"),
        ("https, http", "gateway.example.com"),
        ("https", "user@gateway.example.com"),
    ] {
        let (mut ctx, mut headers) = rest_ctx("GET", "/.well-known/agent-card.json");
        headers.insert("x-forwarded-proto".to_string(), proto.to_string());
        headers.insert("x-forwarded-host".to_string(), host.to_string());
        assert!(matches!(
            gateway.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Reject {
                status_code: 502,
                ..
            }
        ));
    }
}

#[tokio::test]
async fn task_metadata_is_bounded_utf8_and_state_is_semantic() {
    for limit in [1, 2, 7, 16, 1024, 4096] {
        let gateway = plugin(json!({"observability": {"max_payload_size": limit}}));
        let (mut ctx, mut headers) = jsonrpc_ctx(json!({
            "jsonrpc": "2.0", "method": "tasks/get", "params": {"id": "界".repeat(2000)}
        }));
        assert!(matches!(
            gateway.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        let cap = limit.min(1024);
        assert!(ctx.metadata["a2a.task_id"].len() <= cap);
        let mut response_headers = HashMap::new();
        let response = json!({"jsonrpc": "2.0", "id": 1, "result": {
            "id": "界".repeat(2000), "contextId": "é".repeat(3000),
            "status": {"state": "backend-controlled-".repeat(1000)}
        }})
        .to_string();
        assert!(matches!(
            gateway
                .on_response_body(&mut ctx, 200, &mut response_headers, response.as_bytes())
                .await,
            PluginResult::Continue
        ));
        for key in ["a2a.task_id", "a2a.context_id", "a2a.task_state"] {
            if let Some(value) = ctx.metadata.get(key) {
                assert!(value.len() <= cap);
            }
            assert_eq!(ctx.metadata[&format!("{key}.truncated")], "true");
        }
        assert!(ctx.metadata["a2a.task_id"].ends_with('~'));
        assert!(ctx.metadata["a2a.context_id"].ends_with('~'));
        assert_eq!(ctx.metadata["a2a.task_state.unrecognized"], "true");
        if limit >= 7 {
            assert_eq!(ctx.metadata["a2a.task_state"], "unknown");
        }
        let serialized = serde_json::to_vec(&ctx.metadata).expect("serialize metadata");
        assert!(
            serialized.len() <= 3 * cap + 1200,
            "retained metadata exceeded fixed envelope"
        );
    }
}

#[tokio::test]
async fn ordinary_task_metadata_preserves_identifiers_and_normalizes_states() {
    let gateway = plugin(json!({"observability": {"max_payload_size": 32}}));
    let (mut ctx, mut headers) = rest_ctx("GET", "/a2a/tasks/task-1");
    assert!(matches!(
        gateway.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    for (raw, expected) in [
        ("TASK_STATE_INPUT_REQUIRED", "input-required"),
        ("cancelled", "canceled"),
        ("completed", "completed"),
    ] {
        let response =
            json!({"id": "task-1", "contextId": "context-1", "status": {"state": raw}}).to_string();
        gateway
            .on_response_body(&mut ctx, 200, &mut HashMap::new(), response.as_bytes())
            .await;
        assert_eq!(ctx.metadata["a2a.task_id"], "task-1");
        assert_eq!(ctx.metadata["a2a.context_id"], "context-1");
        assert_eq!(ctx.metadata["a2a.task_state"], expected);
        assert!(!ctx.metadata.contains_key("a2a.task_id.truncated"));
        assert!(!ctx.metadata.contains_key("a2a.task_state.unrecognized"));
    }
}

#[tokio::test]
async fn streamed_task_metadata_uses_the_same_bounds_without_changing_bytes() {
    let gateway = plugin(json!({"observability": {"max_payload_size": 16}}));
    let plugins = vec![Arc::clone(&gateway)];
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({"jsonrpc": "2.0", "method": "message/stream"}));
    assert!(matches!(
        gateway.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("SSE inspector");
    let event = format!(
        "data: {}\n\n",
        json!({"result": {
            "taskId": "界".repeat(100), "contextId": "é".repeat(100),
            "status": {"state": "invalid".repeat(100)}
        }})
    );
    let mut forwarded = Vec::new();
    for chunk in event.as_bytes().chunks(5) {
        let ResponseStreamAction::Forward(bytes) = inspector.on_chunk(chunk).await else {
            panic!("must forward");
        };
        forwarded.extend_from_slice(&bytes);
    }
    inspector.on_end().await;
    gateway
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(0))
        .await;
    assert_eq!(forwarded, event.as_bytes());
    assert!(ctx.metadata["a2a.task_id"].len() <= 16);
    assert!(ctx.metadata["a2a.context_id"].len() <= 16);
    assert_eq!(ctx.metadata["a2a.task_state"], "unknown");
    assert_eq!(ctx.metadata["a2a.task_state.unrecognized"], "true");
}

#[tokio::test]
async fn already_public_json_card_retains_signatures_and_body() {
    let gateway = plugin(json!({"discovery": {
        "public_base_url": "https://gateway.example.com"
    }}));
    let (mut ctx, mut headers) = rest_ctx("GET", "/.well-known/agent-card.json");
    assert!(matches!(
        gateway.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let body = json!({
        "name": "fixture", "protocolVersion": "0.3.0",
        "url": "https://gateway.example.com/a2a",
        "agentCardUrl": "https://gateway.example.com/.well-known/agent-card.json",
        "signatures": [{"signature": "fixture"}]
    })
    .to_string();
    let mut response_headers = HashMap::new();
    // Every advertised URL already names the public origin, so the producing
    // phase forwards the backend's original, still-signed bytes untouched.
    assert!(
        http_card_rewrite(&gateway, &mut ctx, &mut response_headers, &body)
            .await
            .expect("an already-public card must not select a terminal")
            .is_none()
    );
    assert!(matches!(
        gateway
            .on_final_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
            .await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn malformed_envelopes_cannot_use_an_unknown_method_allow_rule() {
    let gateway = plugin(json!({"policy": {
        "default_action": "deny", "methods": {"unknown": {"action": "allow"}}
    }}));
    for body in [
        json!({"jsonrpc": "2.0", "method": 42}),
        json!({"jsonrpc": "2.0", "method": "FutureCall", "params": true}),
        json!({"jsonrpc": "2.0", "method": "FutureCall", "id": {"key": 1}}),
        json!({"jsonrpc": "2.0", "method": "FutureCall", "result": {}}),
    ] {
        let (mut ctx, mut headers) = jsonrpc_ctx(body);
        headers.insert("a2a-version".to_string(), "0.3.0".to_string());
        assert!(matches!(
            gateway.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Reject { .. }
        ));
    }
}

#[tokio::test]
async fn grpc_card_schema_gate_precedes_missing_origin_response_backstop() {
    let gateway = plugin(json!({"discovery": {
        "trust_forwarded_headers": true,
        "allowed_public_origins": ["https://gateway.example.com"]
    }}));
    let (mut ctx, mut headers) = grpc_ctx("GetAgentCard", "application/grpc");
    ctx.path = "/lf.a2a.v1.A2AService/GetAgentCard".to_string();
    headers.insert("x-forwarded-proto".to_string(), "https".to_string());
    headers.insert(
        "x-forwarded-host".to_string(),
        "gateway.example.com".to_string(),
    );
    assert!(matches!(
        gateway.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    // The admitted origin is retained on the request claim, so the response
    // phase cannot lose it; the service-schema gate is what refuses this card,
    // and it does so before the origin is ever consulted.
    let frame = frame_grpc_message(&a2a_03_card_fixture());
    let result = gateway
        .on_response_body(&mut ctx, 200, &mut grpc_ok_response_headers(), &frame)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_grpc_schema_unsupported",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

// ---------------------------------------------------------------------------
// Issue #5352 — Agent Card discovery must not depend on request-header mutability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn forwarded_origin_card_rewrite_survives_disabled_accept_encoding_strip() {
    // With `strip_accept_encoding: false` the plugin declares no request-header
    // mutation, so the core moves the request headers out of the context. The
    // admitted public origin has to come from the hook's own header map and be
    // retained for the response phase, or a perfectly valid allowlisted card
    // request fails with `agent_card_public_origin_unavailable`.
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true,
            "allowed_public_origins": ["https://agents.example.com"]
        },
        "detection": {"strip_accept_encoding": false}
    }));
    assert!(!plugin.modifies_request_headers());

    let (mut ctx, mut request_headers) = rest_ctx("GET", "/.well-known/agent-card.json");
    request_headers.insert(
        "x-forwarded-host".to_string(),
        "agents.example.com".to_string(),
    );
    request_headers.insert("x-forwarded-proto".to_string(), "https".to_string());
    // Exactly what the core does when nothing on the proxy mutates headers.
    ctx.headers.clear();

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut request_headers).await,
        PluginResult::Continue
    ));
    assert!(plugin.should_buffer_response_body(&ctx));
    // Accept-Encoding is left alone: the option controls compression
    // negotiation, not whether the card can be rewritten.
    assert!(request_headers.contains_key("x-forwarded-host"));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();
    let rewritten = expect_http_card_rewrite(&plugin, &mut ctx, &mut response_headers, &body).await;
    assert_eq!(rewritten["url"], "https://agents.example.com/a2a");
}

#[tokio::test]
async fn unadmitted_forwarded_origin_still_fails_closed_before_dispatch() {
    // The companion half of the fix: relaxing where the origin is READ must not
    // relax which origins are ADMITTED.
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true,
            "allowed_public_origins": ["https://agents.example.com"]
        },
        "detection": {"strip_accept_encoding": false}
    }));
    let (mut ctx, mut request_headers) = rest_ctx("GET", "/.well-known/agent-card.json");
    request_headers.insert(
        "x-forwarded-host".to_string(),
        "attacker.example.com".to_string(),
    );
    request_headers.insert("x-forwarded-proto".to_string(), "https".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut request_headers).await,
        PluginResult::Reject {
            status_code: 502,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("agent_card_public_origin_unavailable")
    );
}

// ---------------------------------------------------------------------------
// Issue #5353 — gRPC-Web framing must not run before the card rewrite
// ---------------------------------------------------------------------------

/// Mark the request the way `grpc_web` marks one it translated to native gRPC.
fn mark_grpc_web_translated(ctx: &mut RequestContext) {
    ctx.metadata
        .insert("grpc_web_mode".to_string(), "binary".to_string());
}

#[tokio::test]
async fn grpc_web_translated_agent_card_is_rewritten_before_framing() {
    let plugin = plugin(json!({
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    mark_grpc_web_translated(&mut ctx);

    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = grpc_ok_response_headers();

    // The normalize phase runs before `on_response_body` and before every
    // transform, so this is the last point at which the body is still one
    // native unary frame.
    let normalized = plugin
        .normalize_response_body_with_context(
            &mut ctx,
            200,
            &body,
            Some("application/grpc-web+proto"),
            &response_headers,
        )
        .await
        .expect("gRPC-Web translated Agent Card must be rewritten before framing");
    let message = &normalized[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    assert!(!proto_has_field(message, 17), "signatures must be dropped");

    // The staged route must not run a second time over the same response.
    response_headers.insert("content-length".to_string(), "128".to_string());
    response_headers.insert("etag".to_string(), "\"abc123\"".to_string());
    response_headers.insert("grpc-encoding".to_string(), "identity".to_string());
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &normalized)
            .await,
        PluginResult::Continue
    ));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &normalized,
                Some("application/grpc-web+proto"),
                &response_headers,
            )
            .await
            .is_none(),
        "the card was already produced; the transform phase must not re-run it"
    );
    // Validators describing the backend's original frame are invalidated.
    for stale in ["content-length", "etag", "grpc-encoding"] {
        assert!(!response_headers.contains_key(stale));
    }
    assert!(matches!(
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, &normalized)
            .await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn native_grpc_agent_card_keeps_the_staged_transform_route() {
    // Without the translator the normalize phase must stay inert, so the
    // existing two-phase contract is unchanged.
    let plugin = plugin(json!({
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let body = frame_grpc_message(&a2a_03_card_fixture());
    let mut response_headers = grpc_ok_response_headers();
    assert!(
        plugin
            .normalize_response_body_with_context(
                &mut ctx,
                200,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none(),
        "native gRPC must not be rewritten in the normalize phase"
    );
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_some(),
        "the native route still produces the rewritten frame in the transform phase"
    );
}

#[tokio::test]
async fn grpc_web_translated_unrewritable_card_still_fails_closed() {
    let plugin = plugin(json!({
        "endpoint": {"grpc_services": ["lf.a2a.v1.A2AService"]},
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetAgentCard", "application/grpc");
    ctx.path = "/lf.a2a.v1.A2AService/GetAgentCard".to_string();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    mark_grpc_web_translated(&mut ctx);

    let body = frame_grpc_message(&a2a_03_card_fixture());
    let response_headers = grpc_ok_response_headers();
    assert!(
        plugin
            .normalize_response_body_with_context(
                &mut ctx,
                200,
                &body,
                Some("application/grpc-web+proto"),
                &response_headers,
            )
            .await
            .is_none()
    );
    let final_result = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(final_result, "agent_card_grpc_schema_unsupported", None);
}

// ---------------------------------------------------------------------------
// Issue #5354 — a refused batch answers every request member
// ---------------------------------------------------------------------------

async fn deny_batch(plugin: &Arc<dyn Plugin>, batch: Value) -> Vec<Value> {
    let (mut ctx, mut headers) = jsonrpc_ctx(batch);
    let PluginResult::Reject { body, .. } = plugin.before_proxy(&mut ctx, &mut headers).await
    else {
        panic!("a batch containing a denied member must be refused");
    };
    let body: Value = serde_json::from_str(&body).expect("batch refusal should be JSON");
    body.as_array()
        .expect("a batch refusal must answer with an array")
        .clone()
}

fn deny_message_send_plugin() -> Arc<dyn Plugin> {
    plugin(json!({
        "policy": {"methods": {"message/send": {"action": "deny"}}}
    }))
}

#[tokio::test]
async fn batch_refusal_answers_every_request_id_in_wire_order() {
    let plugin = deny_message_send_plugin();
    let responses = deny_batch(
        &plugin,
        json!([
            {"jsonrpc": "2.0", "id": 1, "method": "tasks/get"},
            {"jsonrpc": "2.0", "id": "deny-me", "method": "message/send"},
            {"jsonrpc": "2.0", "id": 3, "method": "tasks/list"}
        ]),
    )
    .await;
    let ids: Vec<Value> = responses
        .iter()
        .map(|response| response["id"].clone())
        .collect();
    assert_eq!(ids, vec![json!(1), json!("deny-me"), json!(3)]);
    for response in &responses {
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["error"]["code"], -32001);
        assert_eq!(response["error"]["data"]["gateway"], "a2a_gateway");
    }
    // Only the member the policy named carries the operation it named.
    assert_eq!(responses[1]["error"]["data"]["method"], "message/send");
    assert!(responses[0]["error"]["data"]["method"].is_null());
    assert!(responses[2]["error"]["data"]["method"].is_null());
}

#[tokio::test]
async fn batch_refusal_preserves_id_types_and_omits_notifications() {
    let plugin = deny_message_send_plugin();
    let responses = deny_batch(
        &plugin,
        json!([
            {"jsonrpc": "2.0", "method": "tasks/get"},
            {"jsonrpc": "2.0", "id": null, "method": "tasks/list"},
            {"jsonrpc": "2.0", "id": 7, "method": "message/send"},
            {"jsonrpc": "2.0", "id": "seven", "method": "message/send"}
        ]),
    )
    .await;
    // The notification (no `id` member) is correctly unanswered; an explicit
    // null id is a request and keeps its exact JSON type, as do the number and
    // the string.
    assert_eq!(responses.len(), 3);
    assert!(responses[0]["id"].is_null());
    assert_eq!(responses[1]["id"], json!(7));
    assert!(responses[1]["id"].is_number());
    assert_eq!(responses[2]["id"], json!("seven"));
    assert!(responses[2]["id"].is_string());
}

#[tokio::test]
async fn batch_refusal_covers_multiple_denied_members() {
    let plugin = plugin(json!({
        "policy": {
            "default_action": "deny",
            "methods": {"tasks/get": {"action": "allow"}}
        }
    }));
    let responses = deny_batch(
        &plugin,
        json!([
            {"jsonrpc": "2.0", "id": "a", "method": "message/send"},
            {"jsonrpc": "2.0", "id": "b", "method": "tasks/cancel"},
            {"jsonrpc": "2.0", "id": "c", "method": "tasks/get"}
        ]),
    )
    .await;
    let ids: Vec<Value> = responses
        .iter()
        .map(|response| response["id"].clone())
        .collect();
    assert_eq!(ids, vec![json!("a"), json!("b"), json!("c")]);
}

// ---------------------------------------------------------------------------
// Issue #5355 — the published base URL is the canonicalized, validated one
// ---------------------------------------------------------------------------

#[test]
fn ambiguous_public_base_url_spellings_are_refused() {
    for base in [
        "https://agents.example.com ",
        " https://agents.example.com",
        "https:agents.example.com",
        "https:/agents.example.com",
        "https://agents.example\t.com",
        "https://agents.example.com\n",
        "http:///a2a",
    ] {
        let error = create_plugin(
            "a2a_gateway",
            &json!({"discovery": {"public_base_url": base}}),
        )
        .err()
        .unwrap_or_else(|| panic!("{base:?} must be refused"));
        assert!(error.contains("discovery.public_base_url"), "{error}");
    }
}

#[test]
fn ambiguous_allowed_public_origin_spellings_are_refused() {
    let error = create_plugin(
        "a2a_gateway",
        &json!({"discovery": {
            "trust_forwarded_headers": true,
            "allowed_public_origins": ["https://agents.example.com "]
        }}),
    )
    .err()
    .expect("a whitespace-bearing origin must be refused");
    assert!(error.contains("allowed_public_origins"), "{error}");
}

#[tokio::test]
async fn configured_public_base_is_published_in_canonical_form() {
    // Case, default port, and a trailing slash are normalized once at admission
    // so the published card URL cannot inherit the operator's raw spelling.
    let plugin = plugin(json!({
        "discovery": {"public_base_url": "HTTPS://Agents.Example.COM:443/"}
    }));
    let (mut ctx, mut request_headers) = rest_ctx("GET", "/.well-known/agent-card.json");
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut request_headers).await,
        PluginResult::Continue
    ));
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();
    let rewritten = expect_http_card_rewrite(&plugin, &mut ctx, &mut response_headers, &body).await;
    assert_eq!(rewritten["url"], "https://agents.example.com/a2a");
}

#[tokio::test]
async fn configured_public_base_preserves_an_intended_base_path() {
    let plugin = plugin(json!({
        "discovery": {"public_base_url": "https://agents.example.com/tenant-a/"}
    }));
    let (mut ctx, mut request_headers) = rest_ctx("GET", "/.well-known/agent-card.json");
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut request_headers).await,
        PluginResult::Continue
    ));
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();
    let rewritten = expect_http_card_rewrite(&plugin, &mut ctx, &mut response_headers, &body).await;
    assert_eq!(rewritten["url"], "https://agents.example.com/tenant-a/a2a");
}

// ---------------------------------------------------------------------------
// Per-instance detection ownership
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_second_instance_does_not_inherit_another_instances_detection() {
    // Two instances with disjoint endpoint scopes on one proxy. Only the one
    // whose scope matches may treat the response as A2A; the other must not
    // apply ITS observability settings — here verbatim payload capture — to a
    // response it never claimed.
    let matching = plugin(json!({
        "endpoint": {"path": "/a2a"},
        "discovery": {"public_base_url": "https://gateway.example.com"},
        "observability": {"log_payloads": false}
    }));
    let disjoint = plugin(json!({
        "endpoint": {"path": "/other", "agent_card_path": "/.well-known/other-card.json"},
        "discovery": {"public_base_url": "https://elsewhere.example.com"},
        "observability": {"log_payloads": true, "max_payload_size": 65536}
    }));

    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tasks/get"
    }));
    assert!(matches!(
        matching.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        disjoint.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    assert!(matching.should_buffer_response_body(&ctx));
    assert!(
        !disjoint.should_buffer_response_body(&ctx),
        "an instance whose scope did not match must not pin the response"
    );

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body =
        json!({"jsonrpc": "2.0", "id": "req-1", "result": {"id": "task-secret"}}).to_string();
    assert!(matches!(
        disjoint
            .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
            .await,
        PluginResult::Continue
    ));
    assert!(
        !ctx.metadata.contains_key("a2a.payload.response"),
        "an unmatched instance must not copy response bytes into metadata"
    );
    assert!(!ctx.metadata.contains_key("a2a.response_body_size"));
}

#[tokio::test]
async fn a_second_instance_does_not_rewrite_another_instances_agent_card() {
    let matching = plugin(json!({
        "endpoint": {"agent_card_path": "/.well-known/agent-card.json"},
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let disjoint = plugin(json!({
        "endpoint": {"path": "/other", "agent_card_path": "/.well-known/other-card.json"},
        "discovery": {"public_base_url": "https://elsewhere.example.com"}
    }));

    let (mut ctx, mut request_headers) = rest_ctx("GET", "/.well-known/agent-card.json");
    assert!(matches!(
        matching.before_proxy(&mut ctx, &mut request_headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        disjoint.before_proxy(&mut ctx, &mut request_headers).await,
        PluginResult::Continue
    ));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();
    // The unmatched instance neither stages nor produces anything.
    assert!(
        http_card_rewrite(&disjoint, &mut ctx, &mut response_headers, &body)
            .await
            .expect("unmatched instance must not select a terminal")
            .is_none()
    );
    // The owner still rewrites, and to ITS configured origin.
    let rewritten =
        expect_http_card_rewrite(&matching, &mut ctx, &mut response_headers, &body).await;
    assert_eq!(rewritten["url"], "https://gateway.example.com/a2a");
    // A fail-closed terminal belongs only to the owner, so the unmatched
    // instance leaves the final phase alone.
    assert!(matches!(
        disjoint
            .on_final_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
            .await,
        PluginResult::Continue
    ));
}

// ---------------------------------------------------------------------------
// Bounded HTTP JSON Agent Card production
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_agent_card_rewrite_is_refused_by_the_retained_response_ceiling() {
    use ferrum_edge::_test_support::take_buffered_response_capacity_refusal_pending_for_test;

    let plugin = plugin(json!({
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let (mut ctx, mut request_headers) = rest_ctx("GET", "/.well-known/agent-card.json");
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut request_headers).await,
        PluginResult::Continue
    ));
    // Far below any rewritten card.
    ctx.max_response_body_size_bytes = 8;

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();
    // Admission alone produces no bytes, so nothing over-budget was allocated
    // before the window admitted the producer.
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
            .await,
        PluginResult::Continue
    ));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                body.as_bytes(),
                Some("application/json"),
                &response_headers,
            )
            .await
            .is_none(),
        "an over-ceiling HTTP card rewrite must return None, not an oversized body"
    );
    assert!(
        take_buffered_response_capacity_refusal_pending_for_test(&mut ctx),
        "the shared health-neutral capacity terminal owns this outcome"
    );
    // The capacity refusal is not additionally published as a gateway fault.
    assert!(matches!(
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
            .await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn admitted_http_agent_card_that_is_never_produced_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {"public_base_url": "https://gateway.example.com"}
    }));
    let (mut ctx, mut request_headers) = rest_ctx("GET", "/.well-known/agent-card.json");
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut request_headers).await,
        PluginResult::Continue
    ));
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
            .await,
        PluginResult::Continue
    ));
    // The producer window never invoked the transform. "Silently did not run"
    // must not be indistinguishable from "no rewrite was needed".
    let PluginResult::Reject {
        status_code, body, ..
    } = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
        .await
    else {
        panic!("an admitted HTTP card that was never rewritten must fail closed");
    };
    assert_eq!(status_code, 502);
    let body: Value = serde_json::from_str(&body).expect("terminal body should be JSON");
    assert_eq!(body["error"], "agent_card_grpc_rewrite_not_applied");
}

// ---------------------------------------------------------------------------
// Final backend-visible request-body policy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn method_policy_is_re_decided_on_the_final_request_body() {
    // A later request-body transformer can rewrite the JSON-RPC `method` after
    // `before_proxy` admitted the request. The backend-visible representation is
    // what the policy has to govern.
    let plugin = deny_message_send_plugin();
    assert!(plugin.needs_final_request_body_context());
    assert!(plugin.enforces_finalized_request_policy());

    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tasks/get"
    }));
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata.get("a2a.policy_decision").map(String::as_str),
        Some("allow")
    );

    let dispatched = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "message/send"
    })
    .to_string();
    let PluginResult::Reject {
        status_code, body, ..
    } = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, dispatched.as_bytes())
        .await
    else {
        panic!("a method the policy denies must be refused on the dispatched body");
    };
    assert_eq!(status_code, 200);
    let body: Value = serde_json::from_str(&body).expect("refusal should be JSON");
    assert_eq!(body["id"], "req-1");
    assert_eq!(body["error"]["data"]["method"], "message/send");
    assert_eq!(
        ctx.metadata.get("a2a.policy_decision").map(String::as_str),
        Some("deny")
    );
}

#[tokio::test]
async fn final_request_body_recheck_admits_an_unchanged_allowed_body() {
    let plugin = deny_message_send_plugin();
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tasks/get"
    }));
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let dispatched = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tasks/get"
    })
    .to_string();
    assert!(matches!(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, dispatched.as_bytes())
            .await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn final_request_body_recheck_covers_batch_members() {
    let plugin = deny_message_send_plugin();
    let (mut ctx, mut headers) = jsonrpc_ctx(json!([
        {"jsonrpc": "2.0", "id": "a", "method": "tasks/get"}
    ]));
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let dispatched = json!([
        {"jsonrpc": "2.0", "id": "a", "method": "tasks/get"},
        {"jsonrpc": "2.0", "id": "b", "method": "message/send"}
    ])
    .to_string();
    let PluginResult::Reject { body, .. } = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, dispatched.as_bytes())
        .await
    else {
        panic!("a denied member injected after admission must be refused");
    };
    let body: Value = serde_json::from_str(&body).expect("refusal should be JSON");
    let responses = body
        .as_array()
        .expect("batch refusal answers with an array");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], "a");
    assert_eq!(responses[1]["id"], "b");
}

#[tokio::test]
async fn observability_only_configs_do_not_claim_the_final_request_representation() {
    // No deny rule means no enforcement decision, so the composition gate must
    // not refuse chains this plugin does not actually govern.
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tasks/get"
    }));
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(!plugin.enforces_finalized_request_policy());
    let claims_representation = plugin.enforces_final_request_body_policy(&ctx, &headers, b"{}");
    assert!(!claims_representation);

    // A deny policy claims the representation, but only inside this instance's
    // own JSON-RPC endpoint scope.
    let enforcing = deny_message_send_plugin();
    assert!(enforcing.enforces_final_request_body_policy(&ctx, &headers, b"{}"));
    let (other_scope, other_headers) = rest_ctx("GET", "/somewhere-else");
    let out_of_scope =
        enforcing.enforces_final_request_body_policy(&other_scope, &other_headers, b"{}");
    assert!(!out_of_scope);
}
