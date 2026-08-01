//! Google Gemini / Vertex streaming adapter for `ai_stream_router`.
//!
//! Translates OpenAI Chat Completions streaming requests into Gemini
//! `streamGenerateContent` bodies and normalizes native / Vertex
//! `GenerateContentResponse` SSE (`alt=sse`) into OpenAI
//! `chat.completion.chunk` SSE without buffering the whole body.
//!
//! Security posture mirrors the Anthropic adapter: byte/depth/event bounds
//! before allocation/parse, fail closed on malformed or ambiguous
//! terminal/security-relevant events, and never log prompts, credentials,
//! tool arguments, raw payloads, or provider error bodies.

use super::{
    FrameOutcome, MAX_SSE_EVENT_BYTES, MAX_SSE_EVENT_JSON_DEPTH, MAX_SSE_EVENTS,
    MAX_SSE_NORMALIZED_BODY_BYTES, MAX_SSE_NORMALIZED_OUTPUT_BYTES, NormalizedSseOut,
    SSE_BUFFER_COMPACT_THRESHOLD, SSE_NORMALIZED_OUTPUT_LIMIT_MESSAGE,
    SSE_NORMALIZED_OUTPUT_TERMINAL_RESERVE_BYTES, StreamTerminal, extract_sse_event_result,
    flatten_content_text, is_system_role, json_nesting_depth, next_event_boundary,
    parse_openai_function_call, parse_openai_tool_calls, tool_result_text, valid_tool_name,
};
use crate::plugins::utils::gemini_generate::{
    gemini_function_args_to_openai_string, gemini_prompt_feedback_is_blocked,
    gemini_response_is_provider_error, gemini_usage_token_counts, map_gemini_finish_reason,
};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use serde_json::{Value, json};
use std::collections::HashMap;

use super::super::{
    ResponseStreamAction, ResponseStreamInspector, ResponseStreamInspectorStage,
};

/// Validate that a Gemini streaming endpoint is representable: `{model}` path
/// placeholder and a `streamGenerateContent` target. Auth / TLS policy stay
/// with the shared provider construction path.
pub(super) fn validate_gemini_endpoint(name: &str, path: &str, has_model_placeholder: bool) -> Result<(), String> {
    if !has_model_placeholder {
        return Err(format!(
            "ai_stream_router: provider '{name}' google_gemini endpoint must contain a '{{model}}' path placeholder"
        ));
    }
    if !path.contains("streamGenerateContent") {
        return Err(format!(
            "ai_stream_router: provider '{name}' google_gemini endpoint path must target streamGenerateContent"
        ));
    }
    Ok(())
}

/// Ensure the forwarded provider query requests SSE framing (`alt=sse`).
///
/// Native Gemini and Vertex both accept `alt=sse` on `streamGenerateContent`.
/// Without it, some deployments emit a JSON-array body that cannot be
/// progressively framed; fail closed by requiring / injecting SSE.
pub(super) fn ensure_gemini_alt_sse_query(query: &str) -> String {
    let has_alt_sse = query.split('&').any(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        name.eq_ignore_ascii_case("alt") && value.eq_ignore_ascii_case("sse")
    });
    if has_alt_sse {
        return query.to_string();
    }
    if query.is_empty() {
        "alt=sse".to_string()
    } else {
        format!("{query}&alt=sse")
    }
}

/// Fail-closed admission for Gemini-representable OpenAI request shapes.
pub(super) fn validate_gemini_translation(openai_body: &Value) -> Result<(), String> {
    let messages = openai_body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "request missing 'messages' array".to_string())?;
    super::validate_openai_tool_history(messages)?;
    resolve_gemini_tool_choice(openai_body)?;
    Ok(())
}

fn resolve_gemini_tool_choice(openai_body: &Value) -> Result<Option<Value>, String> {
    let Some(choice) = openai_body.get("tool_choice") else {
        return Ok(None);
    };
    if choice.is_null() {
        return Ok(None);
    }
    let translated = match choice {
        Value::String(value) if value == "none" => json!({ "mode": "NONE" }),
        Value::String(value) if value == "auto" => json!({ "mode": "AUTO" }),
        Value::String(value) if value == "required" => json!({ "mode": "ANY" }),
        Value::Object(object) => {
            if object.len() != 2 || object.get("type").and_then(Value::as_str) != Some("function") {
                return Err("unsupported or malformed tool_choice".to_string());
            }
            let function = object
                .get("function")
                .and_then(Value::as_object)
                .ok_or_else(|| "unsupported or malformed tool_choice".to_string())?;
            if function.len() != 1 {
                return Err("unsupported or malformed tool_choice".to_string());
            }
            let name = function
                .get("name")
                .and_then(Value::as_str)
                .filter(|value| valid_tool_name(value))
                .ok_or_else(|| "unsupported or malformed tool_choice".to_string())?;
            json!({
                "mode": "ANY",
                "allowedFunctionNames": [name],
            })
        }
        _ => return Err("unsupported or malformed tool_choice".to_string()),
    };

    let tools = openai_body.get("tools");
    let tools_present = tools.is_some_and(|value| {
        value
            .as_array()
            .is_some_and(|arr| !arr.is_empty())
    });
    if choice.as_str() != Some("none") && !tools_present {
        // Named / required / auto without tools is ambiguous for Gemini.
        if !matches!(choice.as_str(), Some("auto")) {
            return Err("tool_choice requires a non-empty tools array".to_string());
        }
    }
    Ok(Some(translated))
}

fn tool_names_by_id(messages: &[Value]) -> Result<HashMap<String, String>, String> {
    let mut names = HashMap::new();
    for (message_index, message) in messages.iter().enumerate() {
        for call in parse_openai_tool_calls(message, message_index)? {
            names.insert(call.id, call.name);
        }
        if let Some(call) = parse_openai_function_call(message, message_index)? {
            names.insert(call.id, call.name);
        }
    }
    Ok(names)
}

fn translate_gemini_tools(openai_body: &Value) -> Result<Option<Value>, String> {
    let Some(tools) = openai_body.get("tools") else {
        return Ok(None);
    };
    if tools.is_null() {
        return Ok(None);
    }
    let arr = tools
        .as_array()
        .ok_or_else(|| "unsupported or malformed tools".to_string())?;
    if arr.is_empty() {
        return Ok(None);
    }
    let mut declarations = Vec::with_capacity(arr.len());
    for tool in arr {
        let func = tool.get("function").unwrap_or(tool);
        let name = func
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| valid_tool_name(value))
            .ok_or_else(|| "unsupported or malformed tools".to_string())?;
        let mut declaration = serde_json::Map::new();
        declaration.insert("name".to_string(), Value::String(name.to_string()));
        if let Some(description) = func.get("description").and_then(Value::as_str) {
            declaration.insert(
                "description".to_string(),
                Value::String(description.to_string()),
            );
        }
        declaration.insert(
            "parameters".to_string(),
            func.get("parameters")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "object" })),
        );
        declarations.push(Value::Object(declaration));
    }
    Ok(Some(json!([{ "functionDeclarations": declarations }])))
}

/// Translate an OpenAI Chat Completions body to a Gemini streaming request.
///
/// The model stays in the URL path (`{model}` placeholder); the body carries
/// `contents` / `systemInstruction` / `generationConfig` / tools only.
/// Text-first for message content in this phase (non-text parts dropped),
/// matching the Anthropic stream-router MVP posture.
pub(super) fn translate_to_gemini_stream(openai_body: &Value, _model: &str) -> Result<Vec<u8>, String> {
    validate_gemini_translation(openai_body)?;
    let messages = openai_body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "request missing 'messages' array".to_string())?;

    let system_parts: Vec<Value> = messages
        .iter()
        .filter(|m| m["role"].as_str().is_some_and(is_system_role))
        .map(|m| flatten_content_text(&m["content"]))
        .filter(|s| !s.is_empty())
        .map(|text| json!({ "text": text }))
        .collect();

    let tool_names = tool_names_by_id(messages)?;
    let mut contents = Vec::with_capacity(messages.len());
    let mut message_index = 0;
    let mut pending_legacy_by_name: HashMap<String, String> = HashMap::new();

    while message_index < messages.len() {
        let message = &messages[message_index];
        let role = message["role"].as_str().unwrap_or("");
        if is_system_role(role) {
            message_index += 1;
            continue;
        }
        if role == "tool" {
            let mut parts = Vec::new();
            while message_index < messages.len()
                && messages[message_index]["role"].as_str() == Some("tool")
            {
                let tool_message = &messages[message_index];
                let tool_call_id = tool_message["tool_call_id"].as_str().ok_or_else(|| {
                    format!("messages[{message_index}] tool message missing tool_call_id")
                })?;
                let tool_name = tool_names.get(tool_call_id).ok_or_else(|| {
                    format!(
                        "messages[{message_index}] tool_call_id has no matching assistant tool call"
                    )
                })?;
                let text = tool_result_text(&tool_message["content"])
                    .map_err(|error| format!("messages[{message_index}] {error}"))?;
                let response = match serde_json::from_str::<Value>(&text) {
                    Ok(Value::Object(object)) => Value::Object(object),
                    Ok(value) => json!({ "output": value }),
                    Err(_) => json!({ "output": text }),
                };
                parts.push(json!({
                    "functionResponse": {
                        "name": tool_name,
                        "response": response,
                    }
                }));
                message_index += 1;
            }
            contents.push(json!({ "role": "user", "parts": parts }));
            continue;
        }
        if role == "function" {
            let mut parts = Vec::new();
            while message_index < messages.len()
                && messages[message_index]["role"].as_str() == Some("function")
            {
                let function_message = &messages[message_index];
                let name = function_message["name"]
                    .as_str()
                    .filter(|value| valid_tool_name(value))
                    .ok_or_else(|| {
                        format!("messages[{message_index}] function message has invalid name")
                    })?;
                let _tool_use_id = pending_legacy_by_name.remove(name).ok_or_else(|| {
                    format!(
                        "messages[{message_index}] function result has no unmatched preceding assistant function_call"
                    )
                })?;
                let text = tool_result_text(&function_message["content"])
                    .map_err(|error| format!("messages[{message_index}] {error}"))?;
                let response = match serde_json::from_str::<Value>(&text) {
                    Ok(Value::Object(object)) => Value::Object(object),
                    Ok(value) => json!({ "output": value }),
                    Err(_) => json!({ "output": text }),
                };
                parts.push(json!({
                    "functionResponse": {
                        "name": name,
                        "response": response,
                    }
                }));
                message_index += 1;
            }
            contents.push(json!({ "role": "user", "parts": parts }));
            continue;
        }
        if role != "user" && role != "assistant" {
            return Err(format!(
                "messages[{message_index}] has unsupported role '{role}'"
            ));
        }

        let text = flatten_content_text(&message["content"]);
        let tool_calls = if role == "assistant" {
            parse_openai_tool_calls(message, message_index)?
        } else {
            Vec::new()
        };
        let legacy_call = if role == "assistant" {
            parse_openai_function_call(message, message_index)?
        } else {
            None
        };
        let mut parts = Vec::new();
        if !text.is_empty() {
            parts.push(json!({ "text": text }));
        }
        for call in &tool_calls {
            parts.push(json!({
                "functionCall": {
                    "name": call.name,
                    "args": call.arguments,
                }
            }));
        }
        if let Some(call) = legacy_call {
            pending_legacy_by_name.insert(call.name.clone(), call.id.clone());
            parts.push(json!({
                "functionCall": {
                    "name": call.name,
                    "args": call.arguments,
                }
            }));
        }
        if parts.is_empty() {
            return Err(format!(
                "messages[{message_index}] has no Gemini-representable content"
            ));
        }
        let native_role = if role == "assistant" { "model" } else { role };
        contents.push(json!({ "role": native_role, "parts": parts }));
        message_index += 1;
    }

    if !pending_legacy_by_name.is_empty() {
        return Err("assistant function_call is missing its function result".to_string());
    }

    let mut body = json!({ "contents": contents });
    if !system_parts.is_empty() {
        body["systemInstruction"] = json!({ "parts": system_parts });
    }

    let mut gen_config = serde_json::Map::new();
    if let Some(max_tokens) = openai_body
        .get("max_tokens")
        .or_else(|| openai_body.get("max_completion_tokens"))
    {
        gen_config.insert("maxOutputTokens".to_string(), max_tokens.clone());
    }
    if let Some(temp) = openai_body.get("temperature") {
        gen_config.insert("temperature".to_string(), temp.clone());
    }
    if let Some(top_p) = openai_body.get("top_p") {
        gen_config.insert("topP".to_string(), top_p.clone());
    }
    if let Some(stop) = openai_body.get("stop") {
        let sequences = match stop {
            Value::String(s) => json!([s]),
            Value::Array(_) => stop.clone(),
            _ => Value::Array(Vec::new()),
        };
        gen_config.insert("stopSequences".to_string(), sequences);
    }
    if !gen_config.is_empty() {
        body["generationConfig"] = Value::Object(gen_config);
    }

    if let Some(tools) = translate_gemini_tools(openai_body)? {
        body["tools"] = tools;
    }
    if let Some(choice) = resolve_gemini_tool_choice(openai_body)? {
        body["toolConfig"] = json!({ "functionCallingConfig": choice });
    }

    serde_json::to_vec(&body)
        .map_err(|error| format!("failed to serialize Gemini body: {error}"))
}

/// Revalidate a translated Gemini body: model lives in the path, so require
/// `contents` and reject a conflicting body-level `model` when present.
pub(super) fn gemini_final_body_model_ok(
    final_body: &Value,
    committed_model: &str,
) -> Result<(), &'static str> {
    match final_body.get("contents") {
        Some(Value::Array(contents)) if !contents.is_empty() => {}
        _ => return Err("The final Gemini provider request body has no usable contents array"),
    }
    match final_body.get("model") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(model)) if model == committed_model => Ok(()),
        Some(_) => Err("The final AI provider request model does not match the routed model policy"),
    }
}

// ---------------------------------------------------------------------------
// Gemini SSE → OpenAI chat.completion.chunk SSE normalizer
// ---------------------------------------------------------------------------

pub(super) struct GeminiSseNormalizer {
    buf: Vec<u8>,
    cursor: usize,
    scan_cursor: usize,
    bytes_ingested: usize,
    events_seen: usize,
    normalized_out_bytes: usize,
    model: String,
    stream_id: Option<String>,
    created: i64,
    role_emitted: bool,
    done_emitted: bool,
    terminal: Option<StreamTerminal>,
    /// Saw at least one successful terminal finishReason / prompt block.
    saw_terminal_finish: bool,
    tools_forbidden: bool,
    next_tool_index: u32,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    call_id_nonce: String,
}

impl GeminiSseNormalizer {
    pub(super) fn new(model: String, tools_forbidden: bool) -> Self {
        let created = Utc::now().timestamp();
        Self {
            buf: Vec::new(),
            cursor: 0,
            scan_cursor: 0,
            bytes_ingested: 0,
            events_seen: 0,
            normalized_out_bytes: 0,
            model,
            stream_id: None,
            created,
            role_emitted: false,
            done_emitted: false,
            terminal: None,
            saw_terminal_finish: false,
            tools_forbidden,
            next_tool_index: 0,
            prompt_tokens: None,
            completion_tokens: None,
            call_id_nonce: format!("{created}"),
        }
    }

    fn unread_len(&self) -> usize {
        self.buf.len().saturating_sub(self.cursor)
    }

    fn clear_buffer(&mut self) {
        self.buf.clear();
        self.cursor = 0;
        self.scan_cursor = 0;
        if self.buf.capacity() > 64 * 1024 {
            self.buf.shrink_to(4096);
        }
    }

    fn maybe_compact(&mut self) {
        if self.cursor == 0 {
            return;
        }
        if self.cursor >= self.buf.len() {
            self.clear_buffer();
            return;
        }
        if self.cursor >= SSE_BUFFER_COMPACT_THRESHOLD && self.cursor * 2 >= self.buf.len() {
            let consumed = self.cursor;
            self.buf.drain(..consumed);
            self.scan_cursor = self.scan_cursor.saturating_sub(consumed);
            self.cursor = 0;
        }
    }

    fn id(&mut self) -> String {
        if let Some(id) = &self.stream_id {
            return id.clone();
        }
        let id = format!("chatcmpl-stream-{}", self.created);
        self.stream_id = Some(id.clone());
        id
    }

    fn write_chunk_line(
        &mut self,
        delta: Value,
        finish_reason: Option<&str>,
        choice_index: u64,
        out: &mut NormalizedSseOut,
    ) {
        let id = self.id();
        let payload = json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{
                "index": choice_index,
                "delta": delta,
                "finish_reason": finish_reason,
            }],
        });
        out.write_sse_data_line(&payload);
    }

    fn write_usage_line(&mut self, out: &mut NormalizedSseOut) {
        let (Some(p), Some(c)) = (self.prompt_tokens, self.completion_tokens) else {
            return;
        };
        let id = self.id();
        let payload = json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [],
            "usage": {
                "prompt_tokens": p,
                "completion_tokens": c,
                "total_tokens": p.saturating_add(c),
            },
        });
        out.write_sse_data_line(&payload);
    }

    fn emit_upstream_error(&mut self, message: &str, out: &mut NormalizedSseOut) {
        let err = json!({
            "error": {
                "message": message,
                "type": "upstream_error",
            }
        });
        out.write_sse_data_line(&err);
    }

    fn fail_bound(&mut self, message: &'static str, out: &mut NormalizedSseOut) {
        self.clear_buffer();
        self.emit_upstream_error(message, out);
        self.finish(StreamTerminal::ProviderError, out);
    }

    fn ensure_role(&mut self, choice_index: u64, out: &mut NormalizedSseOut) {
        if !self.role_emitted {
            self.role_emitted = true;
            self.write_chunk_line(json!({ "role": "assistant" }), None, choice_index, out);
        }
    }

    fn finish(&mut self, terminal: StreamTerminal, out: &mut NormalizedSseOut) {
        if self.done_emitted {
            return;
        }
        self.done_emitted = true;
        self.terminal = Some(terminal);
        if terminal == StreamTerminal::MessageStop {
            self.write_usage_line(out);
        }
        out.push_str("data: [DONE]\n\n");
    }

    fn record_usage(&mut self, event: &Value) -> Result<(), &'static str> {
        let (prompt, completion, _total) = gemini_usage_token_counts(event)?;
        if let Some(p) = prompt {
            self.prompt_tokens = Some(p);
        }
        if let Some(c) = completion {
            self.completion_tokens = Some(c);
        }
        if let Some(Value::String(version)) = event.get("modelVersion")
            && !version.is_empty()
            && version.len() <= 128
        {
            self.model = version.clone();
        }
        if let Some(Value::String(response_id)) = event.get("responseId")
            && !response_id.is_empty()
            && response_id.len() <= 128
        {
            self.stream_id = Some(response_id.clone());
        }
        Ok(())
    }

    /// Transcode one GenerateContentResponse (or provider error) JSON object.
    fn transcode_event(&mut self, event: &Value, out: &mut NormalizedSseOut) -> bool {
        if gemini_response_is_provider_error(event) {
            // Fixed-cardinality: never echo the provider error body.
            self.emit_upstream_error("upstream provider stream error", out);
            self.finish(StreamTerminal::ProviderError, out);
            return true;
        }

        if let Err(message) = self.record_usage(event) {
            self.emit_upstream_error(message, out);
            self.finish(StreamTerminal::UpstreamFailure, out);
            return true;
        }

        let prompt_blocked = match gemini_prompt_feedback_is_blocked(event) {
            Ok(blocked) => blocked,
            Err(message) => {
                self.emit_upstream_error(message, out);
                self.finish(StreamTerminal::UpstreamFailure, out);
                return true;
            }
        };

        let candidates = match event.get("candidates") {
            Some(Value::Array(candidates)) => candidates.as_slice(),
            None if prompt_blocked => &[],
            None => {
                // Usage-only / empty keepalive chunks are forward-compatible.
                return false;
            }
            Some(_) => {
                self.emit_upstream_error(
                    "upstream provider sent Gemini candidates that were not an array",
                    out,
                );
                self.finish(StreamTerminal::UpstreamFailure, out);
                return true;
            }
        };

        if candidates.is_empty() {
            if prompt_blocked {
                self.ensure_role(0, out);
                self.write_chunk_line(json!({}), Some("content_filter"), 0, out);
                self.saw_terminal_finish = true;
                self.finish(StreamTerminal::MessageStop, out);
                return true;
            }
            return false;
        }

        for (candidate_index, candidate) in candidates.iter().enumerate() {
            let Some(candidate) = candidate.as_object() else {
                self.emit_upstream_error(
                    "upstream provider sent a malformed Gemini candidate",
                    out,
                );
                self.finish(StreamTerminal::UpstreamFailure, out);
                return true;
            };
            let choice_index = candidate_index as u64;

            let finish_native = candidate
                .get("finishReason")
                .and_then(Value::as_str);
            let base_finish = match finish_native {
                None => None,
                Some(native) => match map_gemini_finish_reason(native) {
                    Ok(mapped) => Some((native, mapped)),
                    Err(message) => {
                        self.emit_upstream_error(message, out);
                        self.finish(StreamTerminal::UpstreamFailure, out);
                        return true;
                    }
                },
            };

            let parts: &[Value] = match candidate.get("content") {
                Some(Value::Object(content)) => {
                    match content.get("role") {
                        Some(Value::String(role)) if role == "model" => {}
                        None if base_finish
                            .as_ref()
                            .is_some_and(|(_, mapped)| *mapped == "content_filter") => {}
                        None => {}
                        Some(_) => {
                            self.emit_upstream_error(
                                "upstream provider sent a Gemini candidate with an invalid content role",
                                out,
                            );
                            self.finish(StreamTerminal::UpstreamFailure, out);
                            return true;
                        }
                    }
                    match content.get("parts") {
                        Some(Value::Array(parts)) => parts.as_slice(),
                        None | Some(Value::Null) => &[],
                        Some(_) => {
                            self.emit_upstream_error(
                                "upstream provider sent Gemini content.parts that were not an array",
                                out,
                            );
                            self.finish(StreamTerminal::UpstreamFailure, out);
                            return true;
                        }
                    }
                }
                None | Some(Value::Null) => &[],
                Some(_) => {
                    self.emit_upstream_error(
                        "upstream provider sent a malformed Gemini candidate content object",
                        out,
                    );
                    self.finish(StreamTerminal::UpstreamFailure, out);
                    return true;
                }
            };

            let mut emitted_tool = false;
            for (part_index, part) in parts.iter().enumerate() {
                match (
                    part.get("text").and_then(Value::as_str),
                    part.get("functionCall"),
                ) {
                    (Some(text), None) => {
                        if !text.is_empty() {
                            self.ensure_role(choice_index, out);
                            self.write_chunk_line(
                                json!({ "content": text }),
                                None,
                                choice_index,
                                out,
                            );
                        }
                    }
                    (None, Some(function_call)) => {
                        if self.tools_forbidden {
                            self.emit_upstream_error(
                                "upstream provider emitted tool use despite tool_choice none",
                                out,
                            );
                            self.finish(StreamTerminal::UpstreamFailure, out);
                            return true;
                        }
                        let name = function_call
                            .get("name")
                            .and_then(Value::as_str)
                            .filter(|value| valid_tool_name(value));
                        let Some(name) = name else {
                            self.emit_upstream_error(
                                "upstream provider sent a Gemini functionCall without a valid name",
                                out,
                            );
                            self.finish(StreamTerminal::UpstreamFailure, out);
                            return true;
                        };
                        let args = function_call.get("args").unwrap_or(&Value::Null);
                        let arguments = match gemini_function_args_to_openai_string(args) {
                            Ok(serialized) => serialized,
                            Err(message) => {
                                self.emit_upstream_error(message, out);
                                self.finish(StreamTerminal::UpstreamFailure, out);
                                return true;
                            }
                        };
                        let tool_index = self.next_tool_index;
                        self.next_tool_index = self.next_tool_index.saturating_add(1);
                        let call_id = format!(
                            "call_gem_{}_{choice_index}_{part_index}",
                            self.call_id_nonce
                        );
                        self.ensure_role(choice_index, out);
                        self.write_chunk_line(
                            json!({
                                "tool_calls": [{
                                    "index": tool_index,
                                    "id": call_id,
                                    "type": "function",
                                    "function": { "name": name, "arguments": arguments },
                                }]
                            }),
                            None,
                            choice_index,
                            out,
                        );
                        emitted_tool = true;
                    }
                    (None, None) => {
                        // thought / executableCode / unknown parts: ignore.
                    }
                    _ => {
                        self.emit_upstream_error(
                            "upstream provider sent an ambiguous Gemini content part",
                            out,
                        );
                        self.finish(StreamTerminal::UpstreamFailure, out);
                        return true;
                    }
                }
            }

            if let Some((native, mapped)) = base_finish {
                if self.tools_forbidden && emitted_tool {
                    self.emit_upstream_error(
                        "upstream provider emitted tool use despite tool_choice none",
                        out,
                    );
                    self.finish(StreamTerminal::UpstreamFailure, out);
                    return true;
                }
                let finish = if emitted_tool {
                    if native != "STOP" {
                        self.emit_upstream_error(
                            "upstream provider Gemini function calls and finishReason disagree",
                            out,
                        );
                        self.finish(StreamTerminal::UpstreamFailure, out);
                        return true;
                    }
                    "tool_calls"
                } else {
                    mapped
                };
                self.ensure_role(choice_index, out);
                self.write_chunk_line(json!({}), Some(finish), choice_index, out);
                self.saw_terminal_finish = true;
            }
        }

        if self.saw_terminal_finish {
            self.finish(StreamTerminal::MessageStop, out);
            return true;
        }
        false
    }

    fn interpret_sse_frame(raw: &[u8]) -> FrameOutcome {
        match extract_sse_event_result(raw) {
            Ok((_event_name, None)) => FrameOutcome::Ignore,
            Ok((_event_name, Some(data))) => {
                let trimmed = data.trim();
                if trimmed.is_empty() || trimmed == "[DONE]" {
                    return FrameOutcome::Ignore;
                }
                if json_nesting_depth(trimmed) > MAX_SSE_EVENT_JSON_DEPTH {
                    return FrameOutcome::Fail(
                        "upstream provider sent an SSE event with excessive JSON nesting; stream terminated",
                    );
                }
                match serde_json::from_str::<Value>(trimmed) {
                    Ok(event) => {
                        if !event.is_object() {
                            return FrameOutcome::Fail(
                                "upstream provider sent a Gemini SSE JSON event that was not an object; stream terminated",
                            );
                        }
                        // Security-relevant Gemini frames must look like a
                        // GenerateContentResponse or a provider error object.
                        let looks_gemini = event.get("candidates").is_some()
                            || event.get("promptFeedback").is_some()
                            || event.get("usageMetadata").is_some()
                            || gemini_response_is_provider_error(&event);
                        if !looks_gemini {
                            return FrameOutcome::Fail(
                                "upstream provider sent an unrecognized Gemini SSE JSON event; stream terminated",
                            );
                        }
                        FrameOutcome::Event(event)
                    }
                    Err(_) => FrameOutcome::Fail(
                        "upstream provider sent a malformed SSE JSON event; stream terminated",
                    ),
                }
            }
            Err(_) => FrameOutcome::Fail(
                "upstream provider sent a malformed SSE event; stream terminated",
            ),
        }
    }

    fn apply_frame_outcome(&mut self, outcome: FrameOutcome, out: &mut NormalizedSseOut) -> bool {
        match outcome {
            FrameOutcome::Ignore => false,
            FrameOutcome::Event(event) => self.transcode_event(&event, out),
            FrameOutcome::Fail(message) => {
                self.emit_upstream_error(message, out);
                self.finish(StreamTerminal::UpstreamFailure, out);
                true
            }
        }
    }

    fn drain_complete(&mut self, out: &mut NormalizedSseOut) -> bool {
        loop {
            let end = {
                let scan_start = self.scan_cursor.max(self.cursor).min(self.buf.len());
                match next_event_boundary(&self.buf[scan_start..]) {
                    Some(end_rel) => scan_start + end_rel,
                    None => {
                        self.scan_cursor = self.buf.len().saturating_sub(3).max(self.cursor);
                        break;
                    }
                }
            };
            let end_rel = end.saturating_sub(self.cursor);
            if end_rel > MAX_SSE_EVENT_BYTES {
                self.fail_bound(
                    "upstream provider sent an oversized SSE event; stream terminated",
                    out,
                );
                return true;
            }
            if self.events_seen >= MAX_SSE_EVENTS {
                self.fail_bound(
                    "upstream provider SSE stream exceeded the event count limit; stream terminated",
                    out,
                );
                return true;
            }

            let start = self.cursor;
            let outcome = Self::interpret_sse_frame(&self.buf[start..end]);
            self.cursor = end;
            self.scan_cursor = end;
            self.events_seen = self.events_seen.saturating_add(1);

            let terminate = self.apply_frame_outcome(outcome, out);
            self.maybe_compact();
            if self.normalized_output_exceeded(out, terminate) {
                return true;
            }
            if terminate {
                self.clear_buffer();
                return true;
            }
        }
        false
    }

    fn normalized_output_exceeded(&mut self, out: &mut NormalizedSseOut, terminal: bool) -> bool {
        let total = self.normalized_out_bytes.saturating_add(out.len());
        let allowed = if terminal {
            MAX_SSE_NORMALIZED_OUTPUT_BYTES
        } else {
            MAX_SSE_NORMALIZED_OUTPUT_BYTES
                .saturating_sub(SSE_NORMALIZED_OUTPUT_TERMINAL_RESERVE_BYTES)
        };
        if total <= allowed {
            return false;
        }
        out.reset_call();
        self.done_emitted = false;
        self.terminal = None;
        self.fail_bound(SSE_NORMALIZED_OUTPUT_LIMIT_MESSAGE, out);
        true
    }

    fn account_ingested(&mut self, chunk_len: usize) -> Result<(), &'static str> {
        let Some(next) = self.bytes_ingested.checked_add(chunk_len) else {
            return Err(
                "upstream provider SSE stream exceeded the cumulative size limit; stream terminated",
            );
        };
        if next > MAX_SSE_NORMALIZED_BODY_BYTES {
            return Err(
                "upstream provider SSE stream exceeded the cumulative size limit; stream terminated",
            );
        }
        self.bytes_ingested = next;
        Ok(())
    }

    fn push_chunk(&mut self, mut chunk: &[u8], out: &mut NormalizedSseOut) -> bool {
        if let Err(message) = self.account_ingested(chunk.len()) {
            self.fail_bound(message, out);
            return true;
        }

        while !chunk.is_empty() {
            let unread = self.unread_len();
            let room = (MAX_SSE_EVENT_BYTES.saturating_add(1)).saturating_sub(unread);
            let take = room.min(chunk.len());
            self.buf.extend_from_slice(&chunk[..take]);
            chunk = &chunk[take..];

            if self.drain_complete(out) {
                return true;
            }
            if self.unread_len() > MAX_SSE_EVENT_BYTES {
                self.fail_bound(
                    "upstream provider sent an oversized SSE event; stream terminated",
                    out,
                );
                return true;
            }
        }
        false
    }

    fn finish_stream(&mut self, out: &mut NormalizedSseOut) {
        if self.drain_complete(out) {
            return;
        }
        if self.unread_len() > 0 {
            if self.unread_len() > MAX_SSE_EVENT_BYTES {
                self.fail_bound(
                    "upstream provider sent an oversized SSE event; stream terminated",
                    out,
                );
                return;
            }
            if self.events_seen >= MAX_SSE_EVENTS {
                self.fail_bound(
                    "upstream provider SSE stream exceeded the event count limit; stream terminated",
                    out,
                );
                return;
            }
            let start = self.cursor;
            let end = self.buf.len();
            let raw_is_ws = self.buf[start..end].iter().all(u8::is_ascii_whitespace);
            let outcome = Self::interpret_sse_frame(&self.buf[start..end]);
            self.cursor = end;
            self.events_seen = self.events_seen.saturating_add(1);
            self.clear_buffer();

            match outcome {
                FrameOutcome::Fail(_) => {
                    self.emit_upstream_error(
                        "upstream provider ended the Gemini SSE stream with malformed trailing data",
                        out,
                    );
                    self.finish(StreamTerminal::UpstreamFailure, out);
                    let _ = self.normalized_output_exceeded(out, true);
                    return;
                }
                outcome => {
                    let terminate = self.apply_frame_outcome(outcome, out);
                    if self.normalized_output_exceeded(out, terminate) {
                        return;
                    }
                    if terminate {
                        return;
                    }
                    if !raw_is_ws {
                        self.emit_upstream_error(
                            "upstream provider ended the Gemini SSE stream with malformed trailing data",
                            out,
                        );
                        self.finish(StreamTerminal::UpstreamFailure, out);
                        let _ = self.normalized_output_exceeded(out, true);
                        return;
                    }
                }
            }
        }
        if self.saw_terminal_finish {
            self.finish(StreamTerminal::MessageStop, out);
            let _ = self.normalized_output_exceeded(out, true);
            return;
        }
        self.emit_upstream_error(
            "upstream provider closed the Gemini SSE stream before a terminal finishReason",
            out,
        );
        self.finish(StreamTerminal::UpstreamFailure, out);
        let _ = self.normalized_output_exceeded(out, true);
    }

    fn commit_forwarded(&mut self, out: &NormalizedSseOut) {
        self.normalized_out_bytes = self.normalized_out_bytes.saturating_add(out.len());
    }

    pub(super) fn drive_chunk(&mut self, chunk: &[u8], out: &mut NormalizedSseOut) -> bool {
        out.begin_call();
        if self.push_chunk(chunk, out) {
            return true;
        }
        self.commit_forwarded(out);
        false
    }

    pub(super) fn drive_end(&mut self, out: &mut NormalizedSseOut) {
        out.begin_call();
        self.finish_stream(out);
    }
}

#[async_trait]
impl ResponseStreamInspector for GeminiSseNormalizer {
    fn stage(&self) -> ResponseStreamInspectorStage {
        ResponseStreamInspectorStage::Normalize
    }

    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if self.done_emitted {
            return ResponseStreamAction::Terminate(None);
        }
        let mut out = NormalizedSseOut::unbounded();
        if self.drive_chunk(chunk, &mut out) {
            return ResponseStreamAction::Terminate(Some(Bytes::from(out.take_call_bytes())));
        }
        ResponseStreamAction::Forward(Bytes::from(out.take_call_bytes()))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.done_emitted {
            return ResponseStreamAction::Terminate(None);
        }
        let mut out = NormalizedSseOut::unbounded();
        self.drive_end(&mut out);
        ResponseStreamAction::Terminate(Some(Bytes::from(out.take_call_bytes())))
    }
}

/// Residual gzip/br decode then Gemini SSE normalize (same contract as Anthropic).
pub(super) struct GeminiContentDecodingNormalizer {
    encoding: &'static str,
    encoded: Vec<u8>,
    inner: GeminiSseNormalizer,
}

impl GeminiContentDecodingNormalizer {
    pub(super) fn gzip(inner: GeminiSseNormalizer) -> Self {
        Self {
            encoding: "gzip",
            encoded: Vec::new(),
            inner,
        }
    }

    pub(super) fn brotli(inner: GeminiSseNormalizer) -> Self {
        Self {
            encoding: "br",
            encoded: Vec::new(),
            inner,
        }
    }

    async fn fail_decode(&mut self, message: String) -> ResponseStreamAction {
        let mut out = NormalizedSseOut::unbounded();
        out.begin_call();
        self.inner.emit_upstream_error(&message, &mut out);
        self.inner
            .finish(StreamTerminal::UpstreamFailure, &mut out);
        ResponseStreamAction::Terminate(Some(Bytes::from(out.take_call_bytes())))
    }
}

#[async_trait]
impl ResponseStreamInspector for GeminiContentDecodingNormalizer {
    fn stage(&self) -> ResponseStreamInspectorStage {
        ResponseStreamInspectorStage::Normalize
    }

    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if self.inner.done_emitted {
            return ResponseStreamAction::Terminate(None);
        }
        let Some(next_len) = self.encoded.len().checked_add(chunk.len()) else {
            return self
                .fail_decode("encoded Gemini SSE size overflowed".to_string())
                .await;
        };
        if next_len > super::NORMALIZE_DECODE_LIMITS.max_cumulative_bytes {
            return self
                .fail_decode("encoded Gemini SSE exceeds the streaming size limit".to_string())
                .await;
        }
        self.encoded.extend_from_slice(chunk);
        ResponseStreamAction::Forward(Bytes::new())
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.inner.done_emitted {
            return ResponseStreamAction::Terminate(None);
        }
        let decoded = match super::prepare_sse_bytes_for_normalization(
            &self.encoded,
            Some(self.encoding),
        ) {
            Ok(bytes) => bytes.into_owned(),
            Err(message) => return self.fail_decode(message).await,
        };
        let mut out = Vec::new();
        if !decoded.is_empty() {
            match self.inner.on_chunk(&decoded).await {
                ResponseStreamAction::Forward(bytes) => out.extend_from_slice(&bytes),
                ResponseStreamAction::Terminate(bytes) => {
                    if let Some(bytes) = bytes {
                        out.extend_from_slice(&bytes);
                    }
                    return ResponseStreamAction::Terminate(Some(Bytes::from(out)));
                }
            }
        }
        match self.inner.on_end().await {
            ResponseStreamAction::Forward(bytes) => {
                out.extend_from_slice(&bytes);
                ResponseStreamAction::Terminate(Some(Bytes::from(out)))
            }
            ResponseStreamAction::Terminate(Some(bytes)) => {
                out.extend_from_slice(&bytes);
                ResponseStreamAction::Terminate(Some(Bytes::from(out)))
            }
            ResponseStreamAction::Terminate(None) => {
                if out.is_empty() {
                    ResponseStreamAction::Terminate(None)
                } else {
                    ResponseStreamAction::Terminate(Some(Bytes::from(out)))
                }
            }
        }
    }
}

pub(super) fn wrap_gemini_normalizer(
    model: String,
    encoding: Option<&str>,
    tools_forbidden: bool,
) -> Box<dyn ResponseStreamInspector> {
    let inner = GeminiSseNormalizer::new(model, tools_forbidden);
    match encoding {
        Some("gzip") => Box::new(GeminiContentDecodingNormalizer::gzip(inner)),
        Some("br") => Box::new(GeminiContentDecodingNormalizer::brotli(inner)),
        Some(other) => Box::new(super::ImmediateUpstreamErrorNormalizer::new(format!(
            "unsupported content-encoding '{other}' for Gemini SSE normalization"
        ))),
        None => Box::new(inner),
    }
}

pub(super) async fn normalize_gemini_sse_buffered(
    model: String,
    body: &[u8],
    tools_forbidden: bool,
    ceiling: usize,
) -> Option<Vec<u8>> {
    let mut normalizer = GeminiSseNormalizer::new(model, tools_forbidden);
    let mut out = NormalizedSseOut::with_ceiling(ceiling);
    for slice in body.chunks(super::BUFFERED_NORMALIZE_CHUNK_BYTES) {
        if normalizer.done_emitted {
            break;
        }
        let terminate = normalizer.drive_chunk(slice, &mut out);
        if out.refused() {
            return None;
        }
        if terminate {
            return out.finish();
        }
    }
    if !normalizer.done_emitted {
        normalizer.drive_end(&mut out);
    }
    out.finish()
}
