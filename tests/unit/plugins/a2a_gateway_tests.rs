use bytes::Bytes;
use ferrum_edge::plugins::{HTTP_GRPC_PROTOCOLS, PluginResult, RequestContext, create_plugin};
use serde_json::{Value, json};
use std::collections::HashMap;

fn plugin(config: Value) -> std::sync::Arc<dyn ferrum_edge::plugins::Plugin> {
    create_plugin("a2a_gateway", &config)
        .expect("a2a_gateway config should be valid")
        .expect("a2a_gateway should be registered")
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
        format!("/lf.a2a.v1.A2AService/{rpc}"),
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

    let response_headers =
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

    let result = plugin
        .on_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
        .await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!("agent card rewrite should replace response body");
    };
    assert_eq!(status_code, 200);
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
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
        "/lf.a2a.v1.A2AService/SendStreamingMessage".to_string(),
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

    let response_headers =
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

    let result = plugin
        .on_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
        .await;
    let PluginResult::Reject { body, .. } = result else {
        panic!("JSON-RPC agent card rewrite should replace response body");
    };
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
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

    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
        .await;
    let PluginResult::Reject { body, .. } = result else {
        panic!("agent card rewrite should replace response body");
    };
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
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

    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "task-shaped-custom-payload",
        "url": "https://backend.example.com/not-an-agent-card",
        "id": "task-1"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn invalid_forwarded_origin_does_not_rewrite_agent_card() {
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");
    ctx.headers
        .insert("x-forwarded-proto".to_string(), "javascript".to_string());
    ctx.headers
        .insert("host".to_string(), "gateway.example.com".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn response_host_is_not_used_for_agent_card_public_rewrite() {
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let response_headers = HashMap::from([
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
        .on_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn trusted_forwarded_origin_rewrites_agent_card_url() {
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");
    ctx.headers
        .insert("x-forwarded-proto".to_string(), "https".to_string());
    ctx.headers.insert(
        "x-forwarded-host".to_string(),
        "gateway.example.com".to_string(),
    );

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.should_buffer_response_body(&ctx));

    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
        .await;
    let PluginResult::Reject { body, .. } = result else {
        panic!("trusted forwarded origin should rewrite the agent card");
    };
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(body["url"], "https://gateway.example.com/a2a");
}

#[tokio::test]
async fn trusted_host_header_rewrites_agent_card_url_without_forwarded_host() {
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");
    ctx.headers
        .insert("x-forwarded-proto".to_string(), "https".to_string());
    ctx.headers
        .insert("host".to_string(), "gateway.example.com".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
        .await;
    let PluginResult::Reject { body, .. } = result else {
        panic!("trusted host header should rewrite the agent card");
    };
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
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
    let response_headers = HashMap::from([
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

    let result = plugin
        .on_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
        .await;
    let PluginResult::Reject { headers, body, .. } = result else {
        panic!("agent card rewrite should replace response body");
    };
    let rewritten: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(rewritten["url"], "https://gateway.example.com/a2a");

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
            !headers.keys().any(|key| key.eq_ignore_ascii_case(stale)),
            "expected {stale} to be stripped after rewrite, got {headers:?}"
        );
    }
    // Headers unrelated to the body are preserved, and content-type is normalized.
    assert!(
        headers
            .keys()
            .any(|key| key.eq_ignore_ascii_case("cache-control"))
    );
    assert_eq!(
        headers.get("content-type").map(String::as_str),
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
    let plugin = plugin(json!({
        "policy": {
            "default_action": "deny"
        }
    }));
    let (mut ctx, mut headers) = rest_ctx("POST", "/a2a/v1/tasks");

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("a2a.enabled"));
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

    let response_headers =
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
        .on_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
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

    let response_headers =
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
        .on_response_body(&mut ctx, 200, &response_headers, body.as_bytes())
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
    assert!(!plugin.should_buffer_response_body_for_content_type(&ctx, Some("text/event-stream")));
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
            json!({"endpoint": {"grpc_services": ["lf.a2a.v1.A2AService", "lf.a2a.v1.A2AService"]}}),
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
