//! Provider adapter identity, lifecycle, and downstream policy contracts.

use ferrum_edge::plugins::ai_federation::test_helpers::normalize_response_test;
use ferrum_edge::plugins::ai_stream_router::AiStreamRouter;
use ferrum_edge::plugins::ai_tool_governor::AiToolGovernor;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, ResponseStreamAction,
    ResponseStreamInspector, chain_response_stream_inspectors,
};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

async fn claimed(provider: &str, tools_none: bool) -> (AiStreamRouter, RequestContext) {
    let (model, endpoint) = if provider == "anthropic" {
        ("claude-test", "https://provider.invalid/v1/messages")
    } else {
        (
            "gemini-test",
            "https://provider.invalid/v1beta/models/{model}:streamGenerateContent",
        )
    };
    let plugin = AiStreamRouter::new(
        &json!({"providers": [{
            "name": "fixture", "provider_type": provider, "endpoint": endpoint,
            "api_key": "fixture-key", "model_patterns": ["*"]
        }]}),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut body = json!({
        "model": model, "stream": true,
        "messages": [{"role": "user", "content": "hello"}]
    });
    if tools_none {
        body["tool_choice"] = json!("none");
    }
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), body.to_string());
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    // Commit the actual provider representation, including tool_choice none.
    plugin
        .transform_request_body_with_context(
            &mut ctx,
            body.to_string().as_bytes(),
            Some("application/json"),
            &headers,
        )
        .await
        .unwrap();
    (plugin, ctx)
}

fn bytes(action: ResponseStreamAction) -> Vec<u8> {
    match action {
        ResponseStreamAction::Forward(bytes) | ResponseStreamAction::Terminate(Some(bytes)) => {
            bytes.to_vec()
        }
        ResponseStreamAction::Terminate(None) => Vec::new(),
    }
}

fn frames(text: &str) -> Vec<Value> {
    text.lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter(|data| *data != "[DONE]")
        .map(|data| serde_json::from_str(data).unwrap())
        .collect()
}

fn reasons(text: &str) -> Vec<String> {
    frames(text)
        .iter()
        .filter_map(|frame| frame["choices"][0]["finish_reason"].as_str())
        .map(str::to_string)
        .collect()
}

fn sse(events: &[Value]) -> String {
    events
        .iter()
        .map(|event| format!("data: {event}\n\n"))
        .collect()
}

async fn drive(inspector: &mut dyn ResponseStreamInspector, body: &str, chunk: usize) -> String {
    let mut output = Vec::new();
    for part in body.as_bytes().chunks(chunk) {
        let action = inspector.on_chunk(part).await;
        let terminal = matches!(action, ResponseStreamAction::Terminate(_));
        output.extend(bytes(action));
        if terminal {
            break;
        }
    }
    output.extend(bytes(inspector.on_end().await));
    assert!(bytes(inspector.on_end().await).is_empty());
    assert!(bytes(inspector.on_chunk(b"data: {}\n\n").await).is_empty());
    String::from_utf8(output).unwrap()
}

fn stable_id(text: &str) -> String {
    let frames = frames(text);
    let ids: HashSet<_> = frames
        .iter()
        .filter_map(|frame| frame["id"].as_str())
        .collect();
    assert_eq!(ids.len(), 1, "{text}");
    ids.into_iter().next().unwrap().to_string()
}

fn without_created(text: &str) -> Vec<Value> {
    frames(text)
        .into_iter()
        .map(|mut frame| {
            frame.as_object_mut().unwrap().remove("created");
            frame
        })
        .collect()
}

fn start() -> Value {
    json!({"type": "message_start", "message": {
        "id": "msg_fixture", "model": "claude-test",
        "usage": {"input_tokens": 3, "output_tokens": 1}
    }})
}

fn text_delta(text: &str) -> Value {
    json!({"type": "content_block_delta", "index": 0,
        "delta": {"type": "text_delta", "text": text}})
}

fn argument(index: u64, partial: &str) -> Value {
    json!({"type": "content_block_delta", "index": index,
        "delta": {"type": "input_json_delta", "partial_json": partial}})
}

fn tool_start(index: u64, kind: &str, name: &str) -> Value {
    json!({"type": "content_block_start", "index": index, "content_block": {
        "type": kind, "id": format!("tool_{index}"), "name": name, "input": {}
    }})
}

#[tokio::test]
async fn synthetic_stream_and_tool_ids_are_random_and_distinct_without_clock_races() {
    // All inspectors coexist and progress interleaved. UUID shape/version proves
    // the entropy contract without requiring construction within a wall-clock second.
    let mut inspectors = Vec::new();
    for _ in 0..64 {
        let (plugin, ctx) = claimed("google_gemini", false).await;
        inspectors.push(
            plugin
                .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
                .unwrap(),
        );
    }
    let body = sse(&[json!({"candidates": [{"index": 0, "content": {"parts": [
        {"functionCall": {"name": "one", "args": {}}},
        {"functionCall": {"name": "two", "args": {}}}
    ]}, "finishReason": "STOP"}]})]);
    let mut outputs = vec![Vec::new(); inspectors.len()];
    for part in body.as_bytes().chunks(3) {
        for (inspector, output) in inspectors.iter_mut().zip(&mut outputs) {
            output.extend(bytes(inspector.on_chunk(part).await));
        }
    }
    let mut completion_ids = HashSet::new();
    let mut tool_ids = HashSet::new();
    for (inspector, output) in inspectors.iter_mut().zip(&mut outputs) {
        output.extend(bytes(inspector.on_end().await));
        let text = std::str::from_utf8(output).unwrap();
        assert!(!text.contains("upstream_error"), "{text}");
        assert_eq!(reasons(text), ["tool_calls"]);
        let id = stable_id(text);
        let suffix = id.strip_prefix("chatcmpl-stream-").unwrap();
        let uuid = uuid::Uuid::parse_str(suffix).unwrap();
        assert_eq!(uuid.get_version_num(), 4);
        assert!(completion_ids.insert(id));
        for frame in frames(text) {
            if let Some(calls) = frame["choices"][0]["delta"]["tool_calls"].as_array() {
                for call in calls {
                    if let Some(id) = call["id"].as_str() {
                        assert!(id.starts_with("call_gemini_"));
                        assert!(tool_ids.insert(id.to_string()), "duplicate {id}");
                    }
                }
            }
        }
    }
    assert_eq!(completion_ids.len(), 64);
    assert_eq!(tool_ids.len(), 128);

    let mut anthropic_ids = HashSet::new();
    for _ in 0..32 {
        let (plugin, ctx) = claimed("anthropic", false).await;
        let mut inspector = plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .unwrap();
        let mut missing_id = start();
        missing_id["message"].as_object_mut().unwrap().remove("id");
        let body = sse(&[missing_id, json!({"type": "message_stop"})]);
        let out = drive(&mut *inspector, &body, 1).await;
        let id = stable_id(&out);
        let uuid = uuid::Uuid::parse_str(id.strip_prefix("chatcmpl-stream-").unwrap()).unwrap();
        assert_eq!(uuid.get_version_num(), 4);
        assert!(anthropic_ids.insert(id));
    }
}

#[tokio::test]
async fn gemini_provider_identity_baseline_is_independent_of_emitted_identity() {
    for content_type in ["text/event-stream", "application/json"] {
        for chunk_size in [1, 7, 4096] {
            for early_output in [false, true] {
                for changed in [false, true] {
                    let (plugin, mut ctx) = claimed("google_gemini", false).await;
                    let mut inspector = plugin
                        .response_stream_inspector(&ctx, 200, Some(content_type))
                        .unwrap();
                    let first = if early_output {
                        json!({"candidates": [{"content": {"parts": [{"text": "first"}]}}]})
                    } else {
                        json!({})
                    };
                    let events = [
                        first,
                        json!({"responseId": "provider-a", "candidates": [{
                            "content": {"parts": [{"text": "second"}]}
                        }]}),
                        json!({"responseId": if changed { "provider-b" } else { "provider-a" },
                            "candidates": [{"finishReason": "STOP"}]}),
                    ];
                    let body = if content_type == "application/json" {
                        serde_json::to_string(&events).unwrap()
                    } else {
                        sse(&events)
                    };
                    let out = drive(&mut *inspector, &body, chunk_size).await;
                    let id = stable_id(&out);
                    if early_output {
                        assert!(id.starts_with("chatcmpl-stream-"), "{out}");
                    } else {
                        assert_eq!(id, "provider-a");
                    }
                    assert_eq!(out.contains("upstream_error"), changed, "{out}");
                    assert_eq!(out.matches("data: [DONE]").count(), 1, "{out}");
                    assert_eq!(reasons(&out).len(), usize::from(!changed), "{out}");
                    let buffered = plugin
                        .normalize_response_body_with_context(
                            &mut ctx,
                            200,
                            body.as_bytes(),
                            Some(content_type),
                            &HashMap::new(),
                        )
                        .await
                        .unwrap();
                    let buffered = std::str::from_utf8(&buffered).unwrap();
                    let buffered_id = stable_id(buffered);
                    if early_output {
                        assert!(buffered_id.starts_with("chatcmpl-stream-"));
                    } else {
                        assert_eq!(buffered_id, "provider-a");
                    }
                    // Independent normalizers intentionally mint independent IDs.
                    let mut buffered_frames = without_created(buffered);
                    for frame in &mut buffered_frames {
                        if frame.get("id").is_some() {
                            frame["id"] = json!(id);
                        }
                    }
                    assert_eq!(without_created(&out), buffered_frames);
                }
            }
        }
    }
}

#[tokio::test]
async fn anthropic_finish_waits_for_stop_and_matches_buffered_mapping() {
    for reason in [
        "end_turn",
        "stop_sequence",
        "pause_turn",
        "max_tokens",
        "tool_use",
        "refusal",
        "future_reason",
    ] {
        let content = if reason == "tool_use" {
            json!([{"type": "tool_use", "id": "tool_7", "name": "client_fn", "input": {}}])
        } else {
            json!([{"type": "text", "text": "hello"}])
        };
        let buffered = normalize_response_test(
            "anthropic",
            200,
            &serde_json::to_vec(&json!({
                "id": "msg_fixture", "type": "message", "role": "assistant",
                "model": "claude-test", "content": content, "stop_reason": reason,
                "usage": {"input_tokens": 3, "output_tokens": 4}
            }))
            .unwrap(),
            "claude-test",
        );
        for chunk_size in [1, 11, 4096] {
            let (plugin, mut ctx) = claimed("anthropic", false).await;
            let mut inspector = plugin
                .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
                .unwrap();
            let mut events = vec![start()];
            if reason == "tool_use" {
                events.push(tool_start(7, "tool_use", "client_fn"));
                events.push(argument(7, "{}"));
            } else {
                events.push(text_delta("hello"));
            }
            // Both absent and null intermediate reasons, followed by more output.
            events.push(json!({
                "type": "message_delta", "delta": {}, "usage": {"output_tokens": 2}
            }));
            events.push(json!({"type": "message_delta", "delta": {"stop_reason": null}}));
            events.push(text_delta("tail"));
            events.push(
                json!({"type": "message_delta", "delta": {"stop_reason": reason},
                "usage": {"output_tokens": 4}}),
            );
            // Repeated terminal metadata must still produce only one finish.
            events.push(events.last().unwrap().clone());
            let before_stop = sse(&events);
            let mut output = Vec::new();
            for part in before_stop.as_bytes().chunks(chunk_size) {
                output.extend(bytes(inspector.on_chunk(part).await));
            }
            let before_stop_out = std::str::from_utf8(&output).unwrap();
            assert!(reasons(before_stop_out).is_empty(), "{before_stop_out}");
            events.push(json!({"type": "message_stop"}));
            let stop = sse(&events[events.len() - 1..]);
            output.extend(bytes(inspector.on_chunk(stop.as_bytes()).await));
            output.extend(bytes(inspector.on_end().await));
            let out = String::from_utf8(output).unwrap();
            assert_eq!(out.matches("data: [DONE]").count(), 1, "{out}");
            match &buffered {
                Ok((normalized, _, _, _)) => {
                    let expected = normalized["choices"][0]["finish_reason"].as_str().unwrap();
                    assert_eq!(reasons(&out), [expected]);
                    assert!(!out.contains("upstream_error"), "{out}");
                    let usage = frames(&out)
                        .into_iter()
                        .find(|frame| frame.get("usage").is_some())
                        .unwrap();
                    assert_eq!(usage["usage"]["total_tokens"], 7);
                }
                Err(_) => {
                    assert!(out.contains("upstream_error"), "{out}");
                    assert!(reasons(&out).is_empty());
                }
            }
            let normalized = plugin
                .normalize_response_body_with_context(
                    &mut ctx,
                    200,
                    sse(&events).as_bytes(),
                    Some("text/event-stream"),
                    &HashMap::new(),
                )
                .await
                .unwrap();
            assert_eq!(
                without_created(&out),
                without_created(std::str::from_utf8(&normalized).unwrap())
            );
        }
    }
}

#[tokio::test]
async fn anthropic_missing_delta_retains_usage_and_errors_never_finish_successfully() {
    for partial_usage in [false, true] {
        let (plugin, ctx) = claimed("anthropic", false).await;
        let mut inspector = plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .unwrap();
        let mut first = start();
        if partial_usage {
            first["message"]["usage"]
                .as_object_mut()
                .unwrap()
                .remove("output_tokens");
        }
        let out = drive(
            &mut *inspector,
            &sse(&[first, text_delta("hello"), json!({"type": "message_stop"})]),
            1,
        )
        .await;
        assert_eq!(reasons(&out), ["stop"]);
        assert_eq!(out.matches("data: [DONE]").count(), 1);
        let usage = frames(&out)
            .into_iter()
            .find(|frame| frame.get("usage").is_some())
            .unwrap();
        assert_eq!(usage["usage"]["prompt_tokens"], 3);
        if partial_usage {
            assert!(usage["usage"]["completion_tokens"].is_null());
            assert!(usage["usage"]["total_tokens"].is_null());
        } else {
            assert_eq!(usage["usage"]["completion_tokens"], 1);
            assert_eq!(usage["usage"]["total_tokens"], 4);
        }
    }
    for terminal in [
        None,
        Some(json!({"type": "error", "error": {"message": "fixture failure"}})),
    ] {
        let (plugin, ctx) = claimed("anthropic", false).await;
        let mut inspector = plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .unwrap();
        let mut events = vec![
            start(),
            json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}}),
        ];
        if let Some(terminal) = terminal {
            events.push(terminal);
        }
        let out = drive(&mut *inspector, &sse(&events), 3).await;
        assert!(out.contains("upstream_error"), "{out}");
        assert!(reasons(&out).is_empty(), "{out}");
        assert_eq!(out.matches("data: [DONE]").count(), 1);
    }
    let (plugin, ctx) = claimed("anthropic", false).await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .unwrap();
    let mut overflow = start();
    overflow["message"]["usage"]["input_tokens"] = json!(u64::MAX);
    let out = drive(
        &mut *inspector,
        &sse(&[overflow, json!({"type": "message_stop"})]),
        7,
    )
    .await;
    assert!(out.contains("overflow"), "{out}");
    assert!(reasons(&out).is_empty(), "{out}");
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

fn tool_events(provider_tools: bool, client_tools: bool, valid: bool) -> Vec<Value> {
    let mut events = vec![start()];
    if client_tools {
        events.push(tool_start(7, "tool_use", "client_fn"));
        events.push(argument(7, "{\"x\":"));
        events.push(tool_start(2, "tool_use", "client_fn"));
        events.push(argument(2, "{\"x\":2"));
    }
    if provider_tools {
        events.push(tool_start(9, "server_tool_use", "provider_fn"));
        events.push(argument(9, "{\"q\":"));
        events.push(tool_start(4, "mcp_tool_use", "remote_fn"));
        events.push(argument(4, "{\"q\":\"remote\"}"));
    }
    if client_tools {
        events.push(argument(7, if valid { "1}" } else { "\"wrong-type\"}" }));
    }
    if provider_tools {
        events.push(argument(9, "\"search\"}"));
        events.push(json!({"type": "content_block_stop", "index": 9}));
        events.push(json!({"type": "content_block_stop", "index": 4}));
    }
    if client_tools {
        events.push(argument(2, "}"));
        events.push(json!({"type": "content_block_stop", "index": 7}));
        events.push(json!({"type": "content_block_stop", "index": 2}));
    }
    events.push(json!({"type": "message_delta", "delta": {
        "stop_reason": if client_tools { "tool_use" } else { "end_turn" }
    }}));
    events.push(json!({"type": "message_stop"}));
    events
}

fn client_calls(text: &str) -> HashMap<u64, (String, String, String)> {
    let mut calls: HashMap<u64, (String, String, String)> = HashMap::new();
    for frame in frames(text) {
        if let Some(deltas) = frame["choices"][0]["delta"]["tool_calls"].as_array() {
            for delta in deltas {
                let call = calls.entry(delta["index"].as_u64().unwrap()).or_default();
                if let Some(id) = delta["id"].as_str() {
                    call.0.push_str(id);
                }
                if let Some(name) = delta["function"]["name"].as_str() {
                    call.1.push_str(name);
                }
                if let Some(arguments) = delta["function"]["arguments"].as_str() {
                    call.2.push_str(arguments);
                }
            }
        }
    }
    calls
}

#[tokio::test]
async fn interleaved_provider_tools_preserve_client_calls_and_governor_decisions() {
    let governor = AiToolGovernor::new(
        &json!({
            "default_action": "deny",
            "tools": {"client_fn": {"action": "allow", "json_schema": {
                "type": "object", "properties": {"x": {"type": "integer"}},
                "required": ["x"], "additionalProperties": false
            }}},
            "inspect": {"response_tool_calls": true, "streaming_response_tool_calls": true}
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    for chunk_size in [1, 13, 4096] {
        for valid in [false, true] {
            for client_tools in [false, true] {
                let mut control = None;
                for provider_tools in [false, true] {
                    let body = sse(&tool_events(provider_tools, client_tools, valid));
                    let (plugin, mut ctx) = claimed("anthropic", !client_tools).await;
                    let mut normalizer = plugin
                        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
                        .unwrap();
                    let out = drive(&mut *normalizer, &body, chunk_size).await;
                    assert!(!out.contains("upstream_error"), "{out}");
                    assert_eq!(out.matches("data: [DONE]").count(), 1);
                    let calls = client_calls(&out);
                    assert_eq!(calls.len(), if client_tools { 2 } else { 0 }, "{out}");
                    if client_tools {
                        for (index, expected) in [(0, 1), (1, 2)] {
                            let (id, name, arguments) = &calls[&index];
                            assert_eq!(id, if index == 0 { "tool_7" } else { "tool_2" });
                            assert_eq!(name, "client_fn");
                            let parsed: Value = serde_json::from_str(arguments).unwrap();
                            if valid || index == 1 {
                                assert_eq!(parsed, json!({"x": expected}));
                            } else {
                                assert_eq!(parsed, json!({"x": "wrong-type"}));
                            }
                        }
                    }
                    let buffered = plugin
                        .normalize_response_body_with_context(
                            &mut ctx,
                            200,
                            body.as_bytes(),
                            Some("text/event-stream"),
                            &HashMap::new(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        without_created(&out),
                        without_created(std::str::from_utf8(&buffered).unwrap())
                    );
                    if let Some(control) = &control {
                        assert_eq!(&without_created(&out), control);
                    } else {
                        control = Some(without_created(&out));
                    }
                    let normalizer = plugin
                        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
                        .unwrap();
                    let policy = governor
                        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
                        .unwrap();
                    // Production stage sorting must put normalization first.
                    let mut chain =
                        chain_response_stream_inspectors(vec![policy, normalizer]).unwrap();
                    let governed = drive(&mut *chain, &body, chunk_size).await;
                    if valid || !client_tools {
                        assert_eq!(client_calls(&governed), calls, "{governed}");
                        assert_eq!(reasons(&governed), reasons(&out), "{governed}");
                    } else {
                        assert!(governed.contains("error"), "{governed}");
                        assert!(client_calls(&governed).is_empty(), "{governed}");
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn anthropic_unmapped_or_closed_tool_arguments_fail_without_fabricating_calls() {
    let cases = [
        vec![argument(9, "{}")],
        vec![
            tool_start(9, "server_tool_use", "provider_fn"),
            json!({"type": "content_block_stop", "index": 9}),
            argument(9, "{}"),
        ],
        vec![
            tool_start(9, "server_tool_use", "provider_fn"),
            tool_start(9, "tool_use", "client_fn"),
        ],
        vec![json!({"type": "content_block_start", "index": 9,
            "content_block": {"type": "tool_use", "name": "client_fn", "input": {}}})],
        vec![json!({"type": "content_block_delta",
            "delta": {"type": "input_json_delta", "partial_json": "{}"}})],
    ];
    for case in cases {
        let (plugin, ctx) = claimed("anthropic", false).await;
        let mut inspector = plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .unwrap();
        let mut events = vec![start()];
        events.extend(case);
        events.push(json!({"type": "message_stop"}));
        let out = drive(&mut *inspector, &sse(&events), 1).await;
        assert!(out.contains("upstream_error"), "{out}");
        assert!(client_calls(&out).is_empty(), "{out}");
        assert!(reasons(&out).is_empty(), "{out}");
        assert_eq!(out.matches("data: [DONE]").count(), 1);
    }
}
