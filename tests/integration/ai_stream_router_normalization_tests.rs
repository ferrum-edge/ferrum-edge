//! Integration coverage for `ai_stream_router` Anthropic normalization.
//!
//! Exercises claim → Accept-Encoding strip → residual Content-Encoding repair →
//! buffered/streamed normalize as one lifecycle, without spawning the binary.

use ferrum_edge::plugins::ai_stream_router::AiStreamRouter;
use ferrum_edge::plugins::ai_tool_governor::AiToolGovernor;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, ResponseStreamAction,
    ResponseStreamInspector, ResponseStreamInspectorStage, chain_response_stream_inspectors,
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
    match inspector
        .on_chunk(&bytes::Bytes::copy_from_slice(&encoded))
        .await
    {
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
async fn gemini_sse_and_json_streams_normalize() {
    let plugin = AiStreamRouter::new(
        &json!({
            "providers": [{
                "name": "gemini",
                "provider_type": "google_gemini",
                "endpoint": "https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent",
                "api_key": "sk-gemini-test",
                "model_patterns": ["gemini-*"],
                "priority": 1
            }]
        }),
        PluginHttpClient::default(),
    )
    .expect("valid gemini config");

    let body = json!({
        "model": "gemini-1.5-flash",
        "stream": true,
        "messages": [{"role": "user", "content": "hi"}]
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
    headers.insert("accept-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        headers.get("accept-encoding").map(String::as_str),
        Some("identity")
    );
    assert_eq!(
        headers.get("x-goog-api-key").map(String::as_str),
        Some("sk-gemini-test")
    );

    let translated = plugin
        .transform_request_body_with_context(
            &mut ctx,
            serde_json::to_vec(&body).unwrap().as_slice(),
            Some("application/json"),
            &headers,
        )
        .await
        .expect("gemini translate");
    let parsed: serde_json::Value = serde_json::from_slice(&translated).unwrap();
    assert!(parsed.get("contents").is_some());

    let sse = "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"integrated\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":1,\"totalTokenCount\":2}}\n\n";
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("gemini inspector");
    let mut out = Vec::new();
    match inspector
        .on_chunk(&bytes::Bytes::copy_from_slice(sse.as_bytes()))
        .await
    {
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

    let json_stream = "[{ \"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"vertex\"}]},\"finishReason\":\"STOP\"}]}]";
    let buffered = plugin
        .normalize_response_body_with_context(
            &mut ctx,
            200,
            json_stream.as_bytes(),
            Some("application/json"),
            &HashMap::new(),
        )
        .await
        .expect("json stream normalize");
    let buffered = String::from_utf8(buffered).unwrap();
    assert!(buffered.contains("\"content\":\"vertex\""));
    assert!(buffered.trim_end().ends_with("data: [DONE]"));
}

#[tokio::test]
async fn layered_gzip_br_residual_encoding_normalizes_without_leaking_frames() {
    let plugin = plugin();
    let (mut ctx, _) = claim(&plugin).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    response_headers.insert("content-encoding".to_string(), "gzip, br".to_string());
    response_headers.insert("content-length".to_string(), "42".to_string());
    response_headers.insert("content-digest".to_string(), "sha-256=:dead:".to_string());

    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.provider_content_encoding")
            .map(String::as_str),
        Some("gzip, br")
    );
    assert!(!response_headers.contains_key("content-encoding"));
    assert!(!response_headers.contains_key("content-length"));
    assert!(!response_headers.contains_key("content-digest"));

    let mut gzipped = GzEncoder::new(Vec::new(), Compression::default());
    gzipped.write_all(SSE.as_bytes()).unwrap();
    let gzip_layer = gzipped.finish().unwrap();
    let mut layered = Vec::new();
    {
        let mut encoder = brotli::CompressorWriter::new(&mut layered, 4096, 5, 22);
        encoder.write_all(&gzip_layer).unwrap();
    }

    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("chain inspector");
    match inspector
        .on_chunk(&bytes::Bytes::copy_from_slice(&layered))
        .await
    {
        ResponseStreamAction::Forward(b) => {
            assert!(b.is_empty(), "must hold encoded chain frames until EOF")
        }
        other => panic!("unexpected mid-stream action: {other:?}"),
    }
    let mut out = Vec::new();
    match inspector.on_end().await {
        ResponseStreamAction::Forward(b) | ResponseStreamAction::Terminate(Some(b)) => {
            out.extend_from_slice(&b)
        }
        ResponseStreamAction::Terminate(None) => {}
    }
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("\"content\":\"integrated\""));
    assert!(text.trim_end().ends_with("data: [DONE]"));
    assert!(!text.contains("upstream_error"));
}

#[tokio::test]
async fn unsupported_layered_coding_rejects_before_stream_fallback() {
    let plugin = plugin();
    let (mut ctx, _) = claim(&plugin).await;
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    response_headers.insert("content-encoding".to_string(), "gzip, zstd".to_string());
    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(
                !body.contains("zstd"),
                "502 must not echo unsupported coding member: {body}"
            );
        }
        other => panic!("unsupported chain must reject before body fallback: {other:?}"),
    }
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .is_some(),
        "claim still owns normalization; forged residual encoding is absent"
    );
    assert!(
        !ctx.metadata
            .contains_key("ai_stream_router.provider_content_encoding")
    );
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

/// Anthropic tool-use SSE with the argument bytes split across
/// `input_json_delta` fragments.
const ANTHROPIC_TOOL_SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_t\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
    "event: content_block_start\n",
    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"kubectl.apply\",\"input\":{}}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"ns\\\":\"}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"prod\\\"}\"}}\n\n",
    "event: content_block_stop\n",
    "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
    "event: message_delta\n",
    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":1}}\n\n",
    "event: message_stop\n",
    "data: {\"type\":\"message_stop\"}\n\n",
);

fn tool_governor() -> AiToolGovernor {
    AiToolGovernor::new(
        &json!({
            "default_action": "deny",
            "tools": { "safe_tool": { "action": "allow" } },
            "inspect": { "response_tool_calls": false, "streaming_response_tool_calls": true }
        }),
        PluginHttpClient::default(),
    )
    .expect("valid config")
}

async fn drive(inspector: &mut Box<dyn ResponseStreamInspector>, body: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut terminated = false;
    match inspector
        .on_chunk(&bytes::Bytes::copy_from_slice(body))
        .await
    {
        ResponseStreamAction::Forward(bytes) => out.extend_from_slice(&bytes),
        ResponseStreamAction::Terminate(bytes) => {
            if let Some(bytes) = bytes {
                out.extend_from_slice(&bytes);
            }
            terminated = true;
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

/// Pins the stage-ordering guarantee the governor's scope comment relies on:
/// `ai_stream_router` normalizers declare `Normalize`, which sorts BEFORE the
/// governor's default `Inspect`, regardless of the two plugins' request-side
/// priorities (2984 vs 2978). If this ever inverts, the governor would inspect
/// raw provider frames while the client receives normalized ones.
#[tokio::test]
async fn stream_router_normalizer_sorts_before_the_tool_governor() {
    let router = plugin();
    let (ctx, _) = claim(&router).await;
    let router_inspector = router
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("router inspector");
    let governor = tool_governor();
    let governor_inspector = governor
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("governor inspector");

    assert_eq!(
        router_inspector.stage(),
        ResponseStreamInspectorStage::Normalize
    );
    assert_eq!(
        governor_inspector.stage(),
        ResponseStreamInspectorStage::Inspect
    );
    assert!(
        ResponseStreamInspectorStage::Normalize < ResponseStreamInspectorStage::Inspect,
        "normalizers must sort before policy inspectors"
    );
}

/// Composition case: with `ai_stream_router` present the governor inspects the
/// NORMALIZED OpenAI chunks, so a denied Anthropic `tool_use` is cut and never
/// reaches the client.
#[tokio::test]
async fn tool_governor_denies_normalized_anthropic_tool_use() {
    let router = plugin();
    let (ctx, _) = claim(&router).await;
    let governor = tool_governor();

    // Deliberately register the governor FIRST so the chain's own stage sort —
    // not the caller's ordering — is what puts the normalizer in front.
    let chained = chain_response_stream_inspectors(vec![
        governor
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .expect("governor inspector"),
        router
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .expect("router inspector"),
    ]);
    let mut chained = chained.expect("chained inspector");

    let (out, terminated) = drive(&mut chained, ANTHROPIC_TOOL_SSE.as_bytes()).await;
    assert!(
        terminated,
        "a denied tool call must cut the normalized stream"
    );
    let text = String::from_utf8_lossy(&out);
    assert!(
        !text.contains("kubectl.apply"),
        "the denied tool call leaked to the client: {text}"
    );
}

/// The same stream WITHOUT a normalizer: the governor reads Anthropic-native
/// frames directly, so the denied call is still cut. Before issue #4165 this
/// path forwarded every `tool_use` block with `decision: allow`.
#[tokio::test]
async fn tool_governor_denies_native_anthropic_tool_use_without_a_normalizer() {
    let router = plugin();
    let (ctx, _) = claim(&router).await;
    let governor = tool_governor();
    let mut inspector = governor
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("governor inspector");

    let (out, terminated) = drive(&mut inspector, ANTHROPIC_TOOL_SSE.as_bytes()).await;
    assert!(
        terminated,
        "a denied provider-native tool_use must cut the stream"
    );
    let text = String::from_utf8_lossy(&out);
    assert!(
        !text.contains("kubectl.apply"),
        "the denied tool call leaked to the client: {text}"
    );
}
