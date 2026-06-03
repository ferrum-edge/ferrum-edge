//! Shared helpers for detecting Server-Sent Events (SSE) requests.
//!
//! SSE responses (`text/event-stream`) are inherently unbounded streams. Plugins
//! that buffer the response body (e.g., `response_caching`, `body_validator`,
//! `response_transformer`, `response_size_limiting`) MUST skip buffering for
//! SSE — otherwise the buffer collects events forever and the gateway returns
//! 502 once `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` is hit, instead of streaming
//! events to the client.
//!
//! The proxy handler already has a response-side bypass via
//! `is_streaming_content_type()` (checks the backend's `Content-Type`), but
//! that bypass only applies when the matching plugin permits streaming. Once
//! a plugin pins the response into the buffered path, the response-side
//! escape hatch never runs.
//!
//! These helpers operate on the request-side `Accept` header (the canonical
//! SSE intent signal per the WHATWG EventSource spec). Plugins call
//! `is_sse_request(ctx)` from `should_buffer_response_body()` to opt out of
//! buffering before the response-side check happens.
//!
//! Backends may legitimately return `text/event-stream` for non-SSE-aware
//! clients — in those cases the proxy's response-side `is_streaming_content_type`
//! check still streams the body via the existing escape hatch. This helper
//! covers the request-side case.
use super::super::RequestContext;
use serde_json::Value;
use std::collections::HashMap;

/// Returns `true` when the request's `Accept` header indicates Server-Sent
/// Events (i.e., contains `text/event-stream`). Matches the WHATWG EventSource
/// contract used by browser SSE clients (`new EventSource(...)`).
///
/// Used by plugins that buffer response bodies to short-circuit buffering for
/// SSE — buffering an unbounded event stream would 502 the response once the
/// max-response-size limit is hit instead of streaming events.
#[inline]
pub fn is_sse_request(ctx: &RequestContext) -> bool {
    headers_accept_sse(&ctx.headers)
}

/// Returns `true` when the supplied request headers include
/// `Accept: text/event-stream`.
#[inline]
pub fn headers_accept_sse(headers: &HashMap<String, String>) -> bool {
    headers
        .get("accept")
        .is_some_and(|accept| accept_includes_event_stream(accept))
}

/// Parse SSE `data:` frames from a buffered SSE response body into JSON values.
///
/// Iterates lines, strips the `data: ` (or `data:`) prefix, skips empty data,
/// the `[DONE]` sentinel, and frames that are not valid JSON. Returns the
/// parsed frames in order. Returns an empty `Vec` if the body is not valid
/// UTF-8 — callers receive no JSON frames but no error either.
pub fn parse_sse_data_frames(body: &[u8]) -> Vec<Value> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut frames = Vec::new();
    let mut event_data = Vec::new();

    fn flush_event(event_data: &mut Vec<&str>, frames: &mut Vec<Value>) {
        if event_data.is_empty() {
            return;
        }
        let data = if event_data.len() == 1 {
            event_data[0].to_string()
        } else {
            event_data.join("\n")
        };
        event_data.clear();

        let trimmed = data.trim();
        if trimmed.is_empty() || trimmed == "[DONE]" {
            return;
        }
        if let Ok(json) = serde_json::from_str::<Value>(trimmed) {
            frames.push(json);
        }
    }

    for raw_line in body_str.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            flush_event(&mut event_data, &mut frames);
            continue;
        }

        let data = if let Some(rest) = line.strip_prefix("data: ") {
            rest
        } else if let Some(rest) = line.strip_prefix("data:") {
            rest
        } else {
            continue;
        };
        event_data.push(data);
    }
    flush_event(&mut event_data, &mut frames);

    frames
}

/// Logical role of a reassembled streaming-SSE text fragment, so callers can map
/// it onto their own segment taxonomy without re-deriving the JSON shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseTextKind {
    /// Chat-completions assistant text (`$.choices[*].delta.content`).
    ChatContent,
    /// Chat-completions streaming tool/function-call name
    /// (`$.choices[*].delta.tool_calls[*].function.name`).
    ChatToolName,
    /// Chat-completions streaming tool/function-call arguments
    /// (`$.choices[*].delta.tool_calls[*].function.arguments`).
    ChatToolArguments,
    /// Responses-API assistant text (`response.output_text.delta` events).
    ResponsesText,
    /// Responses-API function-call arguments
    /// (`response.function_call_arguments.delta` events).
    ResponsesArguments,
}

/// A coherent text fragment reassembled from many streaming-SSE delta frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseText {
    pub kind: SseTextKind,
    /// Synthetic JSON-path locator for audit attribution
    /// (e.g. `$.choices[0].delta.content`).
    pub json_path: String,
    pub text: String,
}

#[derive(Debug, Default)]
struct ToolCallAccumulator {
    name: String,
    arguments: String,
}

/// Reassembles OpenAI-style streaming chat-completion / Responses-API deltas
/// into coherent per-target text.
///
/// Streaming LLM responses emit many tiny frames
/// (`data: {"choices":[{"delta":{"content":"Hel"}}]}`), so inspecting each frame
/// in isolation is semantically meaningless — an embedding cannot score a single
/// token, and a violation phrase split across frames is invisible per-frame.
/// Feed parsed `data:` frames in arrival order via [`push_frame`](Self::push_frame);
/// concatenation is keyed by choice index and tool-call index so interleaved
/// choices / parallel tool-calls stay separate. Read the joined result with
/// [`into_texts`](Self::into_texts).
///
/// Insertion order is preserved across all accumulators so the output is
/// deterministic.
#[derive(Debug, Default)]
pub struct SseReassembler {
    /// `choice_index -> assistant content`.
    content: Vec<(usize, String)>,
    /// `(choice_index, tool_call_index) -> accumulated name + arguments`.
    tool_calls: Vec<((usize, usize), ToolCallAccumulator)>,
    /// Responses-API output text keyed by `(output_index, content_index)`.
    responses_text: Vec<((usize, usize), String)>,
    /// Responses-API function-call arguments keyed by `output_index`.
    responses_args: Vec<(usize, String)>,
}

impl SseReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accumulate one already-parsed SSE `data:` frame.
    pub fn push_frame(&mut self, frame: &Value) {
        self.push_chat_completion_deltas(frame);
        self.push_responses_deltas(frame);
    }

    /// Consume the accumulator and return the reassembled fragments, dropping any
    /// that reassembled to an empty string.
    pub fn into_texts(self) -> Vec<SseText> {
        let mut out = Vec::new();
        for (choice, text) in self.content {
            if !text.is_empty() {
                out.push(SseText {
                    kind: SseTextKind::ChatContent,
                    json_path: format!("$.choices[{choice}].delta.content"),
                    text,
                });
            }
        }
        for ((choice, tool), accum) in self.tool_calls {
            if !accum.name.is_empty() {
                out.push(SseText {
                    kind: SseTextKind::ChatToolName,
                    json_path: format!(
                        "$.choices[{choice}].delta.tool_calls[{tool}].function.name"
                    ),
                    text: accum.name,
                });
            }
            if !accum.arguments.is_empty() {
                out.push(SseText {
                    kind: SseTextKind::ChatToolArguments,
                    json_path: format!(
                        "$.choices[{choice}].delta.tool_calls[{tool}].function.arguments"
                    ),
                    text: accum.arguments,
                });
            }
        }
        for ((output, content), text) in self.responses_text {
            if !text.is_empty() {
                out.push(SseText {
                    kind: SseTextKind::ResponsesText,
                    json_path: format!("$.output[{output}].content[{content}].text"),
                    text,
                });
            }
        }
        for (output, text) in self.responses_args {
            if !text.is_empty() {
                out.push(SseText {
                    kind: SseTextKind::ResponsesArguments,
                    json_path: format!("$.output[{output}].arguments"),
                    text,
                });
            }
        }
        out
    }

    fn push_chat_completion_deltas(&mut self, frame: &Value) {
        let Some(choices) = frame.get("choices").and_then(Value::as_array) else {
            return;
        };
        for (positional, choice) in choices.iter().enumerate() {
            let choice_index = index_field(choice, "index").unwrap_or(positional);
            let Some(delta) = choice.get("delta") else {
                continue;
            };
            if let Some(content) = delta.get("content").and_then(Value::as_str) {
                self.content_mut(choice_index).push_str(content);
            }
            if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                for (tc_positional, tool_call) in tool_calls.iter().enumerate() {
                    // Streaming tool-call deltas carry an explicit `index` that ties
                    // later argument fragments back to the call announced earlier;
                    // fall back to position only when it is absent.
                    let tool_index = index_field(tool_call, "index").unwrap_or(tc_positional);
                    let function = tool_call.get("function");
                    if let Some(name) = function
                        .and_then(|function| function.get("name"))
                        .and_then(Value::as_str)
                    {
                        self.tool_call_mut(choice_index, tool_index)
                            .name
                            .push_str(name);
                    }
                    if let Some(arguments) = function
                        .and_then(|function| function.get("arguments"))
                        .and_then(Value::as_str)
                    {
                        self.tool_call_mut(choice_index, tool_index)
                            .arguments
                            .push_str(arguments);
                    }
                }
            }
        }
    }

    fn push_responses_deltas(&mut self, frame: &Value) {
        // Responses-API streaming carries the increment in a top-level `delta`
        // string discriminated by `type`; ignore the chat-completions shape, which
        // is handled separately and uses a nested object delta.
        let Some(delta) = frame.get("delta").and_then(Value::as_str) else {
            return;
        };
        let Some(event_type) = frame.get("type").and_then(Value::as_str) else {
            return;
        };
        if event_type.ends_with("output_text.delta") {
            let output = index_field(frame, "output_index").unwrap_or(0);
            let content = index_field(frame, "content_index").unwrap_or(0);
            self.responses_text_mut(output, content).push_str(delta);
        } else if event_type.ends_with("function_call_arguments.delta") {
            let output = index_field(frame, "output_index").unwrap_or(0);
            self.responses_args_mut(output).push_str(delta);
        }
    }

    fn content_mut(&mut self, choice: usize) -> &mut String {
        let pos = match self.content.iter().position(|(c, _)| *c == choice) {
            Some(pos) => pos,
            None => {
                self.content.push((choice, String::new()));
                self.content.len() - 1
            }
        };
        &mut self.content[pos].1
    }

    fn tool_call_mut(&mut self, choice: usize, tool: usize) -> &mut ToolCallAccumulator {
        let key = (choice, tool);
        let pos = match self.tool_calls.iter().position(|(k, _)| *k == key) {
            Some(pos) => pos,
            None => {
                self.tool_calls.push((key, ToolCallAccumulator::default()));
                self.tool_calls.len() - 1
            }
        };
        &mut self.tool_calls[pos].1
    }

    fn responses_text_mut(&mut self, output: usize, content: usize) -> &mut String {
        let key = (output, content);
        let pos = match self.responses_text.iter().position(|(k, _)| *k == key) {
            Some(pos) => pos,
            None => {
                self.responses_text.push((key, String::new()));
                self.responses_text.len() - 1
            }
        };
        &mut self.responses_text[pos].1
    }

    fn responses_args_mut(&mut self, output: usize) -> &mut String {
        let pos = match self.responses_args.iter().position(|(o, _)| *o == output) {
            Some(pos) => pos,
            None => {
                self.responses_args.push((output, String::new()));
                self.responses_args.len() - 1
            }
        };
        &mut self.responses_args[pos].1
    }
}

/// Read a non-negative integer index field (`index`, `output_index`, ...) as a
/// `usize`, returning `None` when the field is absent or out of range.
fn index_field(value: &Value, field: &str) -> Option<usize> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|raw| usize::try_from(raw).ok())
}

/// Returns `true` when an `Accept` header value (which may be a comma-separated
/// list of media-range entries) includes `text/event-stream`. The match is
/// exact on the media type itself: a candidate like `text/event-stream-like`
/// is rejected, but parameters (`text/event-stream; q=1.0`) are accepted.
#[inline]
fn accept_includes_event_stream(accept: &str) -> bool {
    accept.split(',').any(|part| {
        let trimmed = part.trim();
        // Strip optional media-type parameters (`; q=...`, `; charset=...`).
        let media_type = trimmed.split(';').next().unwrap_or(trimmed).trim_end();
        media_type.eq_ignore_ascii_case("text/event-stream")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_accept(accept: Option<&str>) -> RequestContext {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/events".to_string(),
        );
        if let Some(value) = accept {
            ctx.headers.insert("accept".to_string(), value.to_string());
        }
        ctx
    }

    #[test]
    fn detects_plain_event_stream() {
        assert!(is_sse_request(&ctx_with_accept(Some("text/event-stream"))));
    }

    #[test]
    fn detects_event_stream_in_list() {
        assert!(is_sse_request(&ctx_with_accept(Some(
            "text/html, text/event-stream, */*"
        ))));
    }

    #[test]
    fn detects_event_stream_with_quality() {
        assert!(is_sse_request(&ctx_with_accept(Some(
            "text/event-stream; q=1.0"
        ))));
    }

    #[test]
    fn detects_uppercase_event_stream() {
        assert!(is_sse_request(&ctx_with_accept(Some("TEXT/EVENT-STREAM"))));
    }

    #[test]
    fn rejects_non_sse_accept() {
        assert!(!is_sse_request(&ctx_with_accept(Some("application/json"))));
    }

    #[test]
    fn rejects_missing_accept() {
        assert!(!is_sse_request(&ctx_with_accept(None)));
    }

    #[test]
    fn rejects_substring_match() {
        // `text/event-stream-like` is a different media type and must NOT
        // match — the helper splits on `;` to isolate the media type and
        // compares case-insensitively for equality.
        assert!(!is_sse_request(&ctx_with_accept(Some(
            "text/event-stream-like"
        ))));
    }

    #[test]
    fn detects_event_stream_with_trailing_space_before_semicolon() {
        // RFC 9110 allows OWS around the `;` parameter delimiter. Accept the
        // common shape we see in the wild.
        assert!(is_sse_request(&ctx_with_accept(Some(
            "text/event-stream ; q=0.9"
        ))));
    }

    #[test]
    fn parse_sse_frames_basic() {
        let body = b"data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"id\":\"2\",\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\ndata: [DONE]\n\n";
        let frames = parse_sse_data_frames(body);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0]["id"], "1");
        assert_eq!(frames[1]["id"], "2");
    }

    #[test]
    fn parse_sse_frames_empty_body() {
        assert!(parse_sse_data_frames(b"").is_empty());
    }

    #[test]
    fn parse_sse_frames_skips_done_and_comments() {
        let body = b": comment\ndata: [DONE]\n\ndata: {\"ok\":true}\n";
        let frames = parse_sse_data_frames(body);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["ok"], true);
    }

    #[test]
    fn parse_sse_frames_no_space_after_colon() {
        let body = b"data:{\"v\":1}\n";
        let frames = parse_sse_data_frames(body);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["v"], 1);
    }

    #[test]
    fn parse_sse_frames_multiline_data_event() {
        let body = b"data: {\"id\":\"1\",\ndata: \"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"id\":\"2\"}\n\n";
        let frames = parse_sse_data_frames(body);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0]["id"], "1");
        assert_eq!(frames[0]["choices"][0]["delta"]["content"], "Hello");
        assert_eq!(frames[1]["id"], "2");
    }

    #[test]
    fn parse_sse_frames_skips_invalid_json() {
        let body = b"data: not-json\n\ndata: {\"ok\":true}\n";
        let frames = parse_sse_data_frames(body);
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn parse_sse_frames_invalid_utf8() {
        let body: &[u8] = &[0xff, 0xfe, 0xfd];
        assert!(parse_sse_data_frames(body).is_empty());
    }

    fn reassemble(body: &[u8]) -> Vec<SseText> {
        let mut reassembler = SseReassembler::new();
        for frame in parse_sse_data_frames(body) {
            reassembler.push_frame(&frame);
        }
        reassembler.into_texts()
    }

    #[test]
    fn reassembles_chat_completion_content_deltas() {
        let body = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo \"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"world\"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n\
data: [DONE]\n\n";
        let texts = reassemble(body);
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0].kind, SseTextKind::ChatContent);
        assert_eq!(texts[0].text, "Hello world");
        assert_eq!(texts[0].json_path, "$.choices[0].delta.content");
    }

    #[test]
    fn keeps_parallel_choices_separate() {
        let body = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"foo\"}},{\"index\":1,\"delta\":{\"content\":\"bar\"}}]}\n\n\
data: {\"choices\":[{\"index\":1,\"delta\":{\"content\":\"baz\"}}]}\n\n";
        let texts = reassemble(body);
        assert_eq!(texts.len(), 2);
        assert_eq!(texts[0].text, "foo");
        assert_eq!(texts[0].json_path, "$.choices[0].delta.content");
        assert_eq!(texts[1].text, "barbaz");
        assert_eq!(texts[1].json_path, "$.choices[1].delta.content");
    }

    #[test]
    fn reassembles_tool_call_name_and_arguments_by_index() {
        // The `id`/`name` arrive in the first fragment; later fragments carry only
        // `index` + argument chunks. Reassembly must stitch them by `index`.
        let body = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"transfer_funds\",\"arguments\":\"\"}}]}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"amount\\\":\"}}]}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"100}\"}}]}}]}\n\n";
        let texts = reassemble(body);
        assert_eq!(texts.len(), 2);
        let name = texts
            .iter()
            .find(|t| t.kind == SseTextKind::ChatToolName)
            .expect("tool name");
        assert_eq!(name.text, "transfer_funds");
        let args = texts
            .iter()
            .find(|t| t.kind == SseTextKind::ChatToolArguments)
            .expect("tool arguments");
        assert_eq!(args.text, "{\"amount\":100}");
        assert_eq!(
            args.json_path,
            "$.choices[0].delta.tool_calls[0].function.arguments"
        );
    }

    #[test]
    fn reassembles_responses_api_output_text_deltas() {
        let body = b"event: response.output_text.delta\n\
data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"Lea\"}\n\n\
event: response.output_text.delta\n\
data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"king\"}\n\n";
        let texts = reassemble(body);
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0].kind, SseTextKind::ResponsesText);
        assert_eq!(texts[0].text, "Leaking");
        assert_eq!(texts[0].json_path, "$.output[0].content[0].text");
    }

    #[test]
    fn reassembles_responses_api_function_call_arguments_deltas() {
        let body = b"data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":1,\"delta\":\"{\\\"q\\\":\"}\n\n\
data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":1,\"delta\":\"42}\"}\n\n";
        let texts = reassemble(body);
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0].kind, SseTextKind::ResponsesArguments);
        assert_eq!(texts[0].text, "{\"q\":42}");
        assert_eq!(texts[0].json_path, "$.output[1].arguments");
    }

    #[test]
    fn falls_back_to_positional_choice_index_when_absent() {
        let body = b"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n\
data: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n\n";
        let texts = reassemble(body);
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0].text, "ab");
    }

    #[test]
    fn ignores_frames_without_recognized_deltas() {
        // A buffered non-delta SSE body (full message object per frame) yields no
        // reassembled deltas — the caller falls back to per-frame extraction.
        let body = b"data: {\"choices\":[{\"message\":{\"content\":\"done\"}}]}\n\n";
        assert!(reassemble(body).is_empty());
    }

    #[test]
    fn reassembler_handles_empty_and_done_only_bodies() {
        assert!(reassemble(b"").is_empty());
        assert!(reassemble(b"data: [DONE]\n\n").is_empty());
    }
}
