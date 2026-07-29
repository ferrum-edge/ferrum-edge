//! Integration coverage for `ai_stream_router` Anthropic normalization.
//!
//! Exercises claim → Accept-Encoding strip → residual Content-Encoding repair →
//! buffered/streamed normalize as one lifecycle, without spawning the binary.

use ferrum_edge::plugins::ai_stream_router::AiStreamRouter;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, ResponseStreamAction,
};
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::json;
use std::collections::HashMap;
use std::io::Write;

fn plugin() -> AiStreamRouter {
    AiStreamRouter::new(
        &json!({
            "providers": [{
                "name": "anthropic",
                "provider_type": "anthropic",
                "endpoint": "https://api.anthropic.com/v1/messages",
                "api_key": "sk-ant-test",
                "model_patterns": ["claude-*"],
                "priority": 1
            }]
        }),
        PluginHttpClient::default(),
    )
    .expect("valid config")
}

async fn claim(plugin: &AiStreamRouter) -> (RequestContext, HashMap<String, String>) {
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{}"}
                }]
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "ok"}
        ]
    });
    let mut ctx = RequestContext::new(
        "127.0.0.1".into(),
        "POST".into(),
        "/v1/chat/completions".into(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body).unwrap(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("accept-encoding".to_string(), "gzip, br".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    (ctx, headers)
}

const SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_i\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"integrated\"}}\n\n",
    "event: message_delta\n",
    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n",
    "event: message_stop\n",
    "data: {\"type\":\"message_stop\"}\n\n",
);

#[tokio::test]
async fn claim_requests_identity_encoding_and_preserves_tool_history() {
    let plugin = plugin();
    let (mut ctx, headers) = claim(&plugin).await;
    assert_eq!(
        headers.get("accept-encoding").map(String::as_str),
        Some("identity")
    );

    let body = ctx.metadata.get("request_body").unwrap().clone();
    let translated = plugin
        .transform_request_body_with_context(
            &mut ctx,
            body.as_bytes(),
            Some("application/json"),
            &headers,
        )
        .await
        .expect("tool history must translate");
    let parsed: serde_json::Value = serde_json::from_slice(&translated).unwrap();
    assert_eq!(
        parsed["messages"][1]["content"][0]["type"],
        json!("tool_use")
    );
    assert_eq!(
        parsed["messages"][2]["content"][0]["type"],
        json!("tool_result")
    );
}

#[tokio::test]
async fn claim_preserves_legacy_function_call_history() {
    let plugin = plugin();
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": null,
                "function_call": {
                    "name": "lookup",
                    "arguments": "{\"q\":\"ok\"}"
                }
            },
            {"role": "function", "name": "lookup", "content": "ok"}
        ]
    });
    let mut ctx = RequestContext::new(
        "127.0.0.1".into(),
        "POST".into(),
        "/v1/chat/completions".into(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body).unwrap(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("accept-encoding".to_string(), "gzip, br".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let translated = plugin
        .transform_request_body_with_context(
            &mut ctx,
            serde_json::to_vec(&body).unwrap().as_slice(),
            Some("application/json"),
            &headers,
        )
        .await
        .expect("legacy function history must translate");
    let parsed: serde_json::Value = serde_json::from_slice(&translated).unwrap();
    assert_eq!(
        parsed["messages"][1]["content"][0]["type"],
        json!("tool_use")
    );
    assert_eq!(
        parsed["messages"][1]["content"][0]["id"],
        json!("call_legacy_1")
    );
    assert_eq!(parsed["messages"][1]["content"][0]["name"], json!("lookup"));
    assert_eq!(
        parsed["messages"][2]["content"][0]["type"],
        json!("tool_result")
    );
    assert_eq!(
        parsed["messages"][2]["content"][0]["tool_use_id"],
        json!("call_legacy_1")
    );
}

#[tokio::test]
async fn gzip_residual_encoding_repairs_headers_and_normalizes_stream() {
    let plugin = plugin();
    let (mut ctx, _) = claim(&plugin).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    response_headers.insert("content-encoding".to_string(), "gzip".to_string());
    response_headers.insert("etag".to_string(), "\"stale\"".to_string());
    response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());

    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert!(!response_headers.contains_key("content-encoding"));
    assert!(!response_headers.contains_key("etag"));
    assert!(!response_headers.contains_key("vary"));

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(SSE.as_bytes()).unwrap();
    let encoded = encoder.finish().unwrap();

    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let mut out = Vec::new();
    match inspector.on_chunk(&encoded).await {
        ResponseStreamAction::Forward(b) | ResponseStreamAction::Terminate(Some(b)) => {
            out.extend_from_slice(&b)
        }
        ResponseStreamAction::Terminate(None) => {}
    }
    if !String::from_utf8_lossy(&out).contains("[DONE]") {
        match inspector.on_end().await {
            ResponseStreamAction::Forward(b) | ResponseStreamAction::Terminate(Some(b)) => {
                out.extend_from_slice(&b)
            }
            ResponseStreamAction::Terminate(None) => {}
        }
    }
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("\"content\":\"integrated\""));
    assert!(text.trim_end().ends_with("data: [DONE]"));
}

#[tokio::test]
async fn premature_eof_buffered_path_surfaces_upstream_error() {
    let plugin = plugin();
    let (mut ctx, _) = claim(&plugin).await;
    let partial = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_p\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n",
    );
    let out = plugin
        .normalize_response_body_with_context(
            &mut ctx,
            200,
            partial.as_bytes(),
            Some("text/event-stream"),
            &HashMap::new(),
        )
        .await
        .expect("normalized error body");
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("upstream_error"));
    assert!(text.contains("before message_stop"));
    assert_eq!(text.matches("data: [DONE]").count(), 1);
}
