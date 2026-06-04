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

/// Outcome of parsing a buffered SSE body, distinguishing "no data" from "data
/// we could not parse" so callers that promise inspection (e.g. the AI firewall
/// `buffer` mode) can fail closed on uninspectable input rather than deliver it.
pub struct SseParse {
    /// Successfully parsed JSON `data:` frames, in order.
    pub frames: Vec<Value>,
    /// `true` when the body was valid UTF-8 **and** every non-empty, non-`[DONE]`
    /// `data:` payload parsed as JSON. `false` if the body was not UTF-8 or any
    /// such payload failed to parse — i.e. it carried data we could not inspect
    /// (which may hide content a clean-looking frame would not reveal).
    pub fully_parsed: bool,
}

/// Parse SSE `data:` frames from a buffered SSE response body into JSON values.
///
/// Iterates lines, strips the `data: ` (or `data:`) prefix, skips empty data,
/// the `[DONE]` sentinel, and frames that are not valid JSON. Returns the
/// parsed frames in order. Returns an empty `Vec` if the body is not valid
/// UTF-8 — callers receive no JSON frames but no error either. Use
/// [`parse_sse_data_frames_checked`] when "had unparseable data" must be
/// distinguished from "had no data".
pub fn parse_sse_data_frames(body: &[u8]) -> Vec<Value> {
    parse_sse_data_frames_checked(body).frames
}

/// Like [`parse_sse_data_frames`], but also reports whether the entire body was
/// inspectable (see [`SseParse::fully_parsed`]).
pub fn parse_sse_data_frames_checked(body: &[u8]) -> SseParse {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        // Non-UTF-8 body: nothing inspectable, and we cannot rule out hidden data.
        Err(_) => {
            return SseParse {
                frames: Vec::new(),
                fully_parsed: false,
            };
        }
    };
    let mut frames = Vec::new();
    let mut fully_parsed = true;
    let mut event_data = Vec::new();

    fn flush_event(event_data: &mut Vec<&str>, frames: &mut Vec<Value>, fully_parsed: &mut bool) {
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
        match serde_json::from_str::<Value>(trimmed) {
            Ok(json) => frames.push(json),
            // A `data:` payload that is not JSON is content we cannot inspect.
            Err(_) => *fully_parsed = false,
        }
    }

    for raw_line in body_str.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            flush_event(&mut event_data, &mut frames, &mut fully_parsed);
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
    flush_event(&mut event_data, &mut frames, &mut fully_parsed);

    SseParse {
        frames,
        fully_parsed,
    }
}

/// Encode an OpenAI-compatible terminal SSE error event for mid-stream
/// termination: an `event: error` frame carrying `{"error":{"code","message"}}`
/// followed by the `[DONE]` sentinel. A streaming client surfaces the trailing
/// `error` data event and sees a clean end-of-stream rather than a silently
/// truncated body.
///
/// `code` and `message` are JSON-escaped via `serde_json`, so embedded quotes or
/// newlines cannot break out of the frame structure (control characters are
/// escaped, keeping the payload on a single `data:` line).
pub fn encode_sse_error_event(code: &str, message: &str) -> bytes::Bytes {
    let payload = serde_json::json!({
        "error": { "code": code, "message": message }
    });
    // serde_json's `Display` is compact and single-line, so the payload is a
    // valid one-line SSE `data:` value.
    bytes::Bytes::from(format!("event: error\ndata: {payload}\n\ndata: [DONE]\n\n"))
}

/// Floor `idx` down to the nearest UTF-8 char boundary at or below it in `s`.
/// Window release/overlap offsets are computed from byte lengths, so callers
/// snap them here before slicing to avoid panicking on multi-byte content.
pub fn floor_char_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Byte index just past the last sentence-terminating `.`/`!`/`?` that is
/// followed by whitespace (or end of text) in `s`, or `None` when `s` holds no
/// complete sentence. Lets streamed inspection release windows at sentence
/// granularity. Terminators are ASCII, so the returned index is always a char
/// boundary. Intentionally simple — an abbreviation or decimal just yields an
/// earlier (still safe) window boundary.
pub fn last_sentence_boundary(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut last = None;
    for i in 0..bytes.len() {
        if matches!(bytes[i], b'.' | b'!' | b'?')
            && bytes.get(i + 1).is_none_or(u8::is_ascii_whitespace)
        {
            last = Some(i + 1);
        }
    }
    last
}

/// Byte index just past the last paragraph break (blank line) in `s`, or `None`.
pub fn last_paragraph_boundary(s: &str) -> Option<usize> {
    s.rfind("\n\n").map(|i| i + 2)
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

#[derive(Debug, Default, Clone)]
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
#[derive(Debug, Default, Clone)]
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

    /// The assistant prose reassembled so far — chat-completion `delta.content`
    /// across choices (in choice-index order) followed by Responses-API output
    /// text. This is the stream that windowed inspection scans for sentence /
    /// paragraph boundaries; tool-call arguments are inspected separately. With
    /// parallel choices (`n > 1`) the texts are concatenated, which is an
    /// approximation — `n = 1` is the dominant streaming case.
    pub fn assistant_content(&self) -> String {
        let mut combined = String::new();
        for (_choice, text) in &self.content {
            combined.push_str(text);
        }
        for (_key, text) in &self.responses_text {
            combined.push_str(text);
        }
        combined
    }

    /// Byte length of [`assistant_content`](Self::assistant_content) without
    /// allocating the joined string. Streamed `inspect` mode queries this per
    /// event to track window/release offsets, so building the full string each
    /// time would be O(n²) in the completion length.
    pub fn assistant_content_len(&self) -> usize {
        let content: usize = self.content.iter().map(|(_, t)| t.len()).sum();
        let responses: usize = self.responses_text.iter().map(|(_, t)| t.len()).sum();
        content + responses
    }

    /// Reassembled fragments as of now, **without** consuming the accumulator —
    /// the streamed `inspect` path inspects the current window repeatedly as the
    /// stream grows, so it cannot move the strings out the way
    /// [`into_texts`](Self::into_texts) does for the one-shot buffered path.
    pub fn texts(&self) -> Vec<SseText> {
        self.clone().into_texts()
    }

    /// Drop the first `prefix_len` bytes of the logical
    /// [`assistant_content`](Self::assistant_content) (chat-completion content
    /// across choices, then Responses-API output text), keeping the tail.
    ///
    /// Streamed `inspect` mode calls this after releasing an inspected-clean
    /// window so retained prose stays bounded to roughly one window plus the
    /// re-inspection overlap, rather than growing with the whole completion.
    /// Tool-call accumulators are intentionally left intact — they are bounded
    /// by the size of the function-call payloads, not the prose length, and have
    /// no linear release offset. `prefix_len` is snapped down to a char boundary
    /// per entry, so a value landing mid-character simply retains a few extra
    /// bytes (always safe — never drops un-inspected content).
    pub fn drain_assistant_prefix(&mut self, prefix_len: usize) {
        let mut remaining = prefix_len;
        let drain_one = |text: &mut String, remaining: &mut usize| {
            if *remaining == 0 {
                return;
            }
            if *remaining >= text.len() {
                *remaining -= text.len();
                text.clear();
            } else {
                let cut = floor_char_boundary(text, *remaining);
                text.drain(..cut);
                *remaining = 0;
            }
        };
        for (_choice, text) in &mut self.content {
            drain_one(text, &mut remaining);
        }
        for (_key, text) in &mut self.responses_text {
            drain_one(text, &mut remaining);
        }
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

    #[test]
    fn checked_parse_reports_fully_parsed_for_valid_frames() {
        let body = b"data: {\"a\":1}\n\ndata: [DONE]\n\n";
        let parsed = parse_sse_data_frames_checked(body);
        assert_eq!(parsed.frames.len(), 1);
        assert!(parsed.fully_parsed);
    }

    #[test]
    fn checked_parse_flags_unparseable_data_event() {
        // A valid frame plus a non-JSON data event: the valid frame is recovered,
        // but fully_parsed is false because the garbage event is uninspectable.
        let body = b"data: {\"a\":1}\n\ndata: not-json\n\n";
        let parsed = parse_sse_data_frames_checked(body);
        assert_eq!(parsed.frames.len(), 1);
        assert!(!parsed.fully_parsed);
    }

    #[test]
    fn checked_parse_flags_non_utf8_body() {
        let parsed = parse_sse_data_frames_checked(&[0xff, 0xfe, 0xfd]);
        assert!(parsed.frames.is_empty());
        assert!(!parsed.fully_parsed);
    }

    #[test]
    fn checked_parse_fully_parsed_for_content_less_stream() {
        // Comment/keepalive lines and [DONE] only: no frames, nothing unparseable.
        let body = b": keepalive\n\ndata: [DONE]\n\n";
        let parsed = parse_sse_data_frames_checked(body);
        assert!(parsed.frames.is_empty());
        assert!(parsed.fully_parsed);
    }

    #[test]
    fn encodes_terminal_sse_error_event() {
        let bytes = encode_sse_error_event("ai_semantic_firewall_response_blocked", "blocked");
        let text = std::str::from_utf8(&bytes).expect("utf8");
        assert!(text.starts_with("event: error\ndata: {"));
        assert!(text.ends_with("\n\ndata: [DONE]\n\n"));
        // The data payload round-trips through the parser as one JSON frame.
        let frames = parse_sse_data_frames(&bytes);
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0]["error"]["code"],
            "ai_semantic_firewall_response_blocked"
        );
        assert_eq!(frames[0]["error"]["message"], "blocked");
    }

    #[test]
    fn encode_sse_error_event_escapes_payload() {
        // Embedded quotes / newlines must not break out of the single data line.
        let bytes = encode_sse_error_event("c", "line1\nline2 \"q\"");
        let frames = parse_sse_data_frames(&bytes);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["error"]["message"], "line1\nline2 \"q\"");
    }

    #[test]
    fn assistant_content_concatenates_choice_and_responses_text() {
        let mut r = SseReassembler::new();
        for frame in parse_sse_data_frames(
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello \"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"world.\"}}]}\n\n",
        ) {
            r.push_frame(&frame);
        }
        assert_eq!(r.assistant_content(), "Hello world.");
        // The no-alloc length tracks the joined string exactly.
        assert_eq!(r.assistant_content_len(), "Hello world.".len());
        // `texts()` is non-consuming and equals the consuming `into_texts()`.
        assert_eq!(r.texts(), r.clone().into_texts());
    }

    #[test]
    fn drain_assistant_prefix_keeps_tail_and_snaps_boundaries() {
        let mut r = SseReassembler::new();
        for frame in parse_sse_data_frames(
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello world.\"}}]}\n\n",
        ) {
            r.push_frame(&frame);
        }
        // Drop the first sentence, keep the tail.
        r.drain_assistant_prefix("Hello ".len());
        assert_eq!(r.assistant_content(), "world.");
        assert_eq!(r.assistant_content_len(), "world.".len());

        // A prefix landing mid-multibyte-char snaps down (retains a few extra
        // bytes) rather than panicking or dropping a partial char.
        let mut m = SseReassembler::new();
        for frame in parse_sse_data_frames(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"aé\"}}]}\n\n".as_bytes(),
        ) {
            m.push_frame(&frame);
        }
        m.drain_assistant_prefix(2); // index 2 is mid-'é' → floors to 1
        assert_eq!(m.assistant_content(), "é");

        // Tool-call accumulators are NOT drained by a prose-prefix drain.
        let mut t = SseReassembler::new();
        for frame in parse_sse_data_frames(
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"exec\",\"arguments\":\"{}\"}}]}}]}\n\n",
        ) {
            t.push_frame(&frame);
        }
        t.drain_assistant_prefix(100);
        assert!(t.texts().iter().any(|x| x.text == "exec"));
    }

    #[test]
    fn last_sentence_boundary_finds_terminator_before_whitespace() {
        assert_eq!(last_sentence_boundary("Hello world. More"), Some(12));
        // Last terminator+whitespace wins: '!' at index 8 → boundary 9.
        assert_eq!(last_sentence_boundary("One. Two! Three"), Some(9));
        assert_eq!(
            last_sentence_boundary("ends.").map(|i| &"ends."[..i]),
            Some("ends.")
        );
        // No terminator-then-space (or end): no complete sentence.
        assert_eq!(last_sentence_boundary("no boundary here"), None);
        assert_eq!(last_sentence_boundary("mid.dle"), None);
    }

    #[test]
    fn last_paragraph_boundary_finds_blank_line() {
        assert_eq!(last_paragraph_boundary("para one\n\npara two"), Some(10));
        assert_eq!(last_paragraph_boundary("single line"), None);
    }

    #[test]
    fn floor_char_boundary_snaps_into_multibyte_content() {
        let s = "aé"; // 'a' (1 byte) + 'é' (2 bytes) => len 3
        assert_eq!(floor_char_boundary(s, 2), 1); // index 2 is mid-'é' → floor to 1
        assert_eq!(floor_char_boundary(s, 1), 1);
        assert_eq!(floor_char_boundary(s, 3), 3);
        assert_eq!(floor_char_boundary(s, 99), 3); // clamps to len
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
