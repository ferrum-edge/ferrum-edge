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
            "message": {
                "taskId": "task-1",
                "contextId": "ctx-1"
            }
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
        "url": "https://planner.internal/a2a",
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
    assert_eq!(body["url"], "https://gateway.example.com/a2a");
    assert_eq!(
        body["additionalInterfaces"][0]["url"],
        "https://gateway.example.com/a2a"
    );
    assert_eq!(
        body["additionalInterfaces"][1]["url"],
        "https://gateway.example.com/a2a"
    );
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
