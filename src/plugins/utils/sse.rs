//! Shared helpers for detecting Server-Sent Events (SSE) requests.
//!
//! SSE responses (`text/event-stream`) are inherently unbounded streams. Plugins
//! that buffer the response body (e.g., `response_caching`, `body_validator`,
//! `response_size_limiting`) MUST skip buffering for SSE — otherwise the buffer
//! collects events forever and the gateway returns 502 once
//! `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` is hit, instead of streaming events to
//! the client. A policy plugin such as `response_transformer` cannot safely use
//! client intent for that decision: it buffers conservatively before headers,
//! then releases only when the backend response itself declares event-stream.
//!
//! The proxy handler already has a response-side bypass via
//! `is_streaming_content_type()` (checks the backend's `Content-Type`), but
//! that bypass only applies when the matching plugin permits streaming. Once
//! a plugin pins the response into the buffered path, the response-side
//! escape hatch never runs.
//!
//! These helpers operate on the request-side `Accept` header (the canonical
//! SSE intent signal per the WHATWG EventSource spec). Plugins whose scope is
//! inherently streaming may call `is_sse_request(ctx)` from
//! `should_buffer_response_body()`. Outbound body-policy plugins must instead
//! wait for the response-header refinement; request intent alone is not proof
//! that the backend selected an event stream.
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

/// Returns `true` when `value` has the exact `text/event-stream` media-type
/// essence. Optional parameters and surrounding whitespace are ignored, while
/// lookalike types such as `application/event-stream+json` are rejected.
#[inline]
pub fn is_text_event_stream_media_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .eq_ignore_ascii_case("text/event-stream")
}

/// Returns `true` only when the response selected by the backend is an SSE
/// representation. Once the proxy has stamped pristine response metadata, an
/// absent original `Content-Type` stays absent: a later response-header plugin
/// must not be able to manufacture or erase the evidence used by the
/// buffer/stream security decision. Synthetic responses, which have no backend
/// stamp, use their live header map.
#[inline]
pub fn original_response_is_event_stream(
    ctx: &RequestContext,
    response_headers: &HashMap<String, String>,
) -> bool {
    let content_type = if ctx
        .metadata
        .contains_key(crate::proxy::ORIGINAL_RESPONSE_METADATA_STAMPED_KEY)
    {
        ctx.metadata
            .get(crate::proxy::ORIGINAL_RESPONSE_CONTENT_TYPE_METADATA_KEY)
            .map(String::as_str)
    } else {
        response_headers.get("content-type").map(String::as_str)
    };
    content_type.is_some_and(is_text_event_stream_media_type)
}

/// Outcome of parsing a buffered SSE body, distinguishing "no data" from "data
/// we could not parse" so callers that promise inspection (e.g. the AI firewall
/// `buffer` mode) can fail closed on uninspectable input rather than deliver it.
pub struct SseParse {
    /// Successfully parsed JSON `data:` frames, in order.
    pub frames: Vec<Value>,
    /// The `event:` name that framed each entry of [`frames`](Self::frames),
    /// classified into [`SseEventName`] so no `String` is retained per event.
    /// Always the same length as `frames`; `None` where the event carried no
    /// `event:` line.
    pub events: Vec<Option<SseEventName>>,
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
                events: Vec::new(),
                fully_parsed: false,
            };
        }
    };
    let mut frames = Vec::new();
    let mut events: Vec<Option<SseEventName>> = Vec::new();
    let mut fully_parsed = true;
    let mut event_data = Vec::new();
    let mut event_name: Option<SseEventName> = None;

    fn flush_event(
        event_name: &mut Option<SseEventName>,
        event_data: &mut Vec<&str>,
        frames: &mut Vec<Value>,
        events: &mut Vec<Option<SseEventName>>,
        fully_parsed: &mut bool,
    ) {
        // The `event:` field is scoped to one event even when that event
        // carried no `data:` payload, so retire it before the early return.
        let name = event_name.take();
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
            Ok(json) => {
                frames.push(json);
                events.push(name);
            }
            // A `data:` payload that is not JSON is content we cannot inspect.
            Err(_) => *fully_parsed = false,
        }
    }

    for raw_line in body_str.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            flush_event(
                &mut event_name,
                &mut event_data,
                &mut frames,
                &mut events,
                &mut fully_parsed,
            );
            continue;
        }

        // Per the WHATWG spec the last `event:` field of an event wins.
        if let Some(rest) = line.strip_prefix("event:") {
            event_name = Some(SseEventName::from_name(rest.trim()));
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
    flush_event(
        &mut event_name,
        &mut event_data,
        &mut frames,
        &mut events,
        &mut fully_parsed,
    );

    SseParse {
        frames,
        events,
        fully_parsed,
    }
}

impl SseParse {
    /// Frames paired with the `event:` name that framed each one, in arrival
    /// order — exactly the input [`SseReassembler::push_event_frame`] takes.
    pub fn reassembly_frames(&self) -> impl Iterator<Item = (Option<SseEventName>, &Value)> {
        self.events.iter().copied().zip(self.frames.iter())
    }
}

/// One Anthropic Messages streaming event type.
///
/// The wire protocol carries the discriminator twice — on the SSE `event:` line
/// and in the JSON payload's `type` field — and intermediaries differ over which
/// they preserve, so the reassembler accepts either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnthropicEvent {
    /// Opens the response and carries the (still empty) message envelope.
    MessageStart,
    /// Opens one content block: its `index` and its `content_block` type.
    ContentBlockStart,
    /// Appends to one content block: `text_delta` prose or `input_json_delta`
    /// tool-input JSON.
    ContentBlockDelta,
    /// Closes one content block.
    ContentBlockStop,
    /// Terminal stop reason plus cumulative usage.
    MessageDelta,
    /// Ends the response.
    MessageStop,
    /// Keep-alive.
    Ping,
    /// Provider error delivered mid-stream.
    Error,
}

/// Classification of an SSE event discriminator, interned so reassembly never
/// retains a `String` per event. The OpenAI Responses API also names every
/// event, so an allocating representation would tax a stream shape that never
/// dispatches on the name at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseEventName {
    /// A recognized Anthropic Messages event.
    Anthropic(AnthropicEvent),
    /// Any other event name.
    Other,
}

impl SseEventName {
    /// Classify an event discriminator taken from an SSE `event:` line or from
    /// a frame's JSON `type` field.
    pub fn from_name(name: &str) -> Self {
        match name {
            "message_start" => Self::Anthropic(AnthropicEvent::MessageStart),
            "content_block_start" => Self::Anthropic(AnthropicEvent::ContentBlockStart),
            "content_block_delta" => Self::Anthropic(AnthropicEvent::ContentBlockDelta),
            "content_block_stop" => Self::Anthropic(AnthropicEvent::ContentBlockStop),
            "message_delta" => Self::Anthropic(AnthropicEvent::MessageDelta),
            "message_stop" => Self::Anthropic(AnthropicEvent::MessageStop),
            "ping" => Self::Anthropic(AnthropicEvent::Ping),
            "error" => Self::Anthropic(AnthropicEvent::Error),
            _ => Self::Other,
        }
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
    /// Legacy Completions assistant text (`$.choices[*].text`).
    CompletionText,
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
    /// Anthropic Messages assistant text, reassembled from the `text_delta`
    /// fragments of one content block (`$.content[*].text`).
    AnthropicText,
    /// Anthropic Messages tool-use block name, announced once by
    /// `content_block_start` (`$.content[*].name`).
    AnthropicToolName,
    /// Anthropic Messages tool-use input document, reassembled from the
    /// `input_json_delta` fragments of one content block (`$.content[*].input`).
    AnthropicToolInput,
    /// Google Gemini / Vertex assistant text, reassembled from the `text` parts
    /// of one candidate (`$.candidates[*].content.parts[*].text`).
    GeminiText,
    /// Google Gemini / Vertex function-call name
    /// (`$.candidates[*].content.parts[*].functionCall.name`).
    GeminiFunctionCallName,
    /// Google Gemini / Vertex function-call arguments, serialized compactly
    /// (`$.candidates[*].content.parts[*].functionCall.args`).
    GeminiFunctionCallArgs,
    /// Hugging Face TGI `/generate_stream` completion text, reassembled from
    /// the `token.text` fragments of one stream into the same field the
    /// buffered document carries (`$[*].generated_text`).
    TgiGeneratedText,
}

/// Ceiling on the number of distinct Anthropic content blocks one stream may
/// open.
///
/// The block `index` arrives on every `content_block_*` event as a provider-
/// supplied integer, so an unbounded keying map would let a stream of one-byte
/// deltas at ever-increasing indexes grow the reassembler's per-block overhead
/// without growing the text that the callers' byte budgets account for. Blocks
/// at or beyond this index are folded into a single shared overflow
/// accumulator, so their content is still reassembled and inspected — never
/// silently dropped — while the retained accumulator count stays bounded at
/// `MAX_ANTHROPIC_CONTENT_BLOCKS + 1`. Folding also marks the stream
/// uninspectable (see
/// [`provider_stream_uninspectable`](SseReassembler::provider_stream_uninspectable))
/// so a caller that promised inspection fails closed on a shape this far
/// outside the protocol rather than allowing on merged blocks. Real Anthropic
/// responses use a handful of blocks.
pub const MAX_ANTHROPIC_CONTENT_BLOCKS: usize = 64;

/// Ceiling on the number of distinct Gemini candidates one stream may open.
///
/// Every `streamGenerateContent?alt=sse` frame repeats the whole
/// `candidates` array, and a candidate's `index` is provider-supplied, so an
/// unbounded keying map would let a stream of one-byte text parts at
/// ever-increasing indexes grow the reassembler's per-candidate overhead
/// without growing the text the callers' byte budgets account for. Candidates
/// at or beyond this index are folded into a single shared overflow
/// accumulator, so their content is still reassembled and inspected — never
/// silently dropped — while the retained accumulator count stays bounded at
/// `MAX_GEMINI_CANDIDATES + 1`. Folding also marks the stream uninspectable
/// (see
/// [`provider_stream_uninspectable`](SseReassembler::provider_stream_uninspectable))
/// so a caller that promised inspection fails closed on a shape this far
/// outside the protocol rather than allowing on merged candidates. Real Gemini
/// responses cap `candidateCount` in the single digits.
pub const MAX_GEMINI_CANDIDATES: usize = 64;

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

/// One Anthropic Messages content block, reassembled across its
/// `content_block_start` / `content_block_delta` events.
#[derive(Debug, Default, Clone)]
struct AnthropicBlockAccumulator {
    /// `content_block_start.content_block.name` for a tool-use block.
    name: String,
    /// Concatenated `text_delta` fragments (plus any `content_block_start` seed).
    text: String,
    /// Concatenated `input_json_delta.partial_json` fragments.
    input_json: String,
}

impl AnthropicBlockAccumulator {
    fn is_empty(&self) -> bool {
        self.name.is_empty() && self.text.is_empty() && self.input_json.is_empty()
    }
}

/// One Google Gemini / Vertex candidate, reassembled across the
/// `streamGenerateContent` frames that carry its incremental parts.
///
/// A candidate's consecutive `text` parts are concatenated into one prose
/// string — the way a client renders them — and its `functionCall` parts
/// contribute the invoked name plus the compactly serialized `args` document,
/// the Gemini equivalent of an Anthropic `tool_use` name and input.
#[derive(Debug, Default, Clone)]
struct GeminiCandidateAccumulator {
    /// Concatenated `functionCall.name` values.
    name: String,
    /// Concatenated `parts[].text` fragments.
    text: String,
    /// Concatenated, compactly serialized `functionCall.args` documents.
    args_json: String,
}

impl GeminiCandidateAccumulator {
    fn is_empty(&self) -> bool {
        self.name.is_empty() && self.text.is_empty() && self.args_json.is_empty()
    }
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
    /// `choice_index -> legacy Completions text`.
    completion_text: Vec<(usize, String)>,
    /// Lookup table for `completion_text`, avoiding linear scans over untrusted indexes.
    completion_text_positions: HashMap<usize, usize>,
    /// `choice_index -> assistant content`.
    content: Vec<(usize, String)>,
    /// Lookup table for `content`, avoiding linear scans over untrusted indexes.
    content_positions: HashMap<usize, usize>,
    /// `(choice_index, tool_call_index) -> accumulated name + arguments`.
    tool_calls: Vec<((usize, usize), ToolCallAccumulator)>,
    /// Lookup table for `tool_calls`, avoiding linear scans over untrusted indexes.
    tool_call_positions: HashMap<(usize, usize), usize>,
    /// Responses-API output text keyed by `(output_index, content_index)`.
    responses_text: Vec<((usize, usize), String)>,
    /// Lookup table for `responses_text`, avoiding linear scans over untrusted indexes.
    responses_text_positions: HashMap<(usize, usize), usize>,
    /// Responses-API function-call arguments keyed by `output_index`.
    responses_args: Vec<(usize, String)>,
    /// Lookup table for `responses_args`, avoiding linear scans over untrusted indexes.
    responses_args_positions: HashMap<usize, usize>,
    /// Anthropic Messages content blocks keyed by their event `index`, bounded
    /// by [`MAX_ANTHROPIC_CONTENT_BLOCKS`].
    anthropic_blocks: Vec<(usize, AnthropicBlockAccumulator)>,
    /// Lookup table for `anthropic_blocks`, avoiding linear scans over untrusted indexes.
    anthropic_block_positions: HashMap<usize, usize>,
    /// Set once a content-bearing Anthropic event has been seen, so foreign or
    /// unnamed frames interleaved after it can be recognized as out-of-protocol.
    anthropic_stream: bool,
    /// Free text carried by an Anthropic `error` event's `error.message`. Kept
    /// out of the content-block accumulators so an error frame can never
    /// consume a block slot or trip the block ceiling, and so a foreign
    /// stream's terminal `event: error` frame stays neutral.
    anthropic_error_text: String,
    /// Gemini candidates keyed by their `candidates[]` index, bounded by
    /// [`MAX_GEMINI_CANDIDATES`].
    gemini_candidates: Vec<(usize, GeminiCandidateAccumulator)>,
    /// Lookup table for `gemini_candidates`, avoiding linear scans over untrusted indexes.
    gemini_candidate_positions: HashMap<usize, usize>,
    /// First content-bearing Gemini candidate observed in this stream.
    gemini_first_candidate: Option<usize>,
    /// Sticky marker for independently rendered Gemini candidate streams.
    gemini_multiple_candidates: bool,
    /// Hugging Face TGI `/generate_stream` completion text: the concatenated
    /// `token.text` fragments, plus a terminal `generated_text` that does not
    /// merely repeat them. TGI streams exactly one sequence per request, so
    /// this is a single accumulator with no provider-supplied index and no
    /// ceiling to enforce.
    tgi_text: String,
    /// Set once a TGI frame has been folded, so a later frame of the same
    /// stream that carries `token` / `generated_text` in a shape outside the
    /// protocol is recognized as out-of-protocol rather than passed over as an
    /// unrelated stream's field of the same name.
    tgi_stream: bool,
    /// Set when part of an identified provider stream (Anthropic Messages,
    /// Gemini `streamGenerateContent`, or Hugging Face TGI `/generate_stream`)
    /// could not be reassembled into the paths this type exposes. Sticky for
    /// the rest of the stream.
    provider_uninspectable: bool,
}

impl SseReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// The assistant prose reassembled so far — legacy Completions `text`,
    /// chat-completion `delta.content`, and Responses-API output text. This is
    /// the stream that windowed inspection scans for sentence / paragraph
    /// boundaries; tool-call arguments are inspected separately. With parallel
    /// choices (`n > 1`) the texts are concatenated, which is an approximation —
    /// `n = 1` is the dominant streaming case.
    pub fn assistant_content(&self) -> String {
        let mut combined = String::new();
        for (_choice, text) in &self.completion_text {
            combined.push_str(text);
        }
        for (_choice, text) in &self.content {
            combined.push_str(text);
        }
        for (_key, text) in &self.responses_text {
            combined.push_str(text);
        }
        for (_index, block) in &self.anthropic_blocks {
            combined.push_str(&block.text);
        }
        for (_index, candidate) in &self.gemini_candidates {
            combined.push_str(&candidate.text);
        }
        combined.push_str(&self.tgi_text);
        combined.push_str(&self.anthropic_error_text);
        combined
    }

    /// Byte length of [`assistant_content`](Self::assistant_content) without
    /// allocating the joined string. Streamed `inspect` mode queries this per
    /// event to track window/release offsets, so building the full string each
    /// time would be O(n²) in the completion length.
    pub fn assistant_content_len(&self) -> usize {
        let completion_text: usize = self.completion_text.iter().map(|(_, t)| t.len()).sum();
        let content: usize = self.content.iter().map(|(_, t)| t.len()).sum();
        let responses: usize = self.responses_text.iter().map(|(_, t)| t.len()).sum();
        let anthropic: usize = self
            .anthropic_blocks
            .iter()
            .map(|(_, block)| block.text.len())
            .sum();
        let gemini: usize = self
            .gemini_candidates
            .iter()
            .map(|(_, candidate)| candidate.text.len())
            .sum();
        completion_text
            .saturating_add(content)
            .saturating_add(responses)
            .saturating_add(anthropic)
            .saturating_add(gemini)
            .saturating_add(self.tgi_text.len())
            .saturating_add(self.anthropic_error_text.len())
    }

    /// Total bytes retained across every reassembled text accumulator (assistant
    /// prose, tool names/arguments, and Responses API text/arguments), without
    /// allocating a snapshot. Windowed policy inspectors use this for their
    /// aggregate retained-state budget.
    pub fn retained_text_len(&self) -> usize {
        let completion_text = self
            .completion_text
            .iter()
            .map(|(_, text)| text.len())
            .sum::<usize>();
        let content = self
            .content
            .iter()
            .map(|(_, text)| text.len())
            .sum::<usize>();
        let tool_calls = self
            .tool_calls
            .iter()
            .map(|(_, call)| call.name.len().saturating_add(call.arguments.len()))
            .sum::<usize>();
        let responses_text = self
            .responses_text
            .iter()
            .map(|(_, text)| text.len())
            .sum::<usize>();
        let responses_args = self
            .responses_args
            .iter()
            .map(|(_, text)| text.len())
            .sum::<usize>();
        let anthropic = self
            .anthropic_blocks
            .iter()
            .map(|(_, block)| {
                block
                    .name
                    .len()
                    .saturating_add(block.text.len())
                    .saturating_add(block.input_json.len())
            })
            .sum::<usize>();
        let gemini = self
            .gemini_candidates
            .iter()
            .map(|(_, candidate)| {
                candidate
                    .name
                    .len()
                    .saturating_add(candidate.text.len())
                    .saturating_add(candidate.args_json.len())
            })
            .sum::<usize>();
        completion_text
            .saturating_add(content)
            .saturating_add(tool_calls)
            .saturating_add(responses_text)
            .saturating_add(responses_args)
            .saturating_add(anthropic)
            .saturating_add(gemini)
            .saturating_add(self.tgi_text.len())
            .saturating_add(self.anthropic_error_text.len())
    }

    /// `true` when a stream identified as a provider protocol this reassembler
    /// models carried something it could not fold into its reassembled
    /// document.
    ///
    /// Anthropic Messages: an unknown event or `delta.type`, a
    /// `content_block_*` event missing its `index` / payload, a discriminator
    /// disagreement between the SSE `event:` line and the JSON `type` field
    /// where both name Anthropic events (or the stream had already identified
    /// itself as Anthropic), an interleaved foreign frame, or a block index
    /// past [`MAX_ANTHROPIC_CONTENT_BLOCKS`].
    ///
    /// Gemini `streamGenerateContent`: a non-array `candidates`, a candidate or
    /// part that is not an object, a non-array `content.parts`, a non-string
    /// `text`, a part kind this reassembler cannot fold (`inlineData`,
    /// `fileData`, `executableCode`, `codeExecutionResult`, a `thought`
    /// summary, or a kind added later), a malformed `functionCall`, or a
    /// candidate index past [`MAX_GEMINI_CANDIDATES`].
    ///
    /// Hugging Face TGI `/generate_stream`: a frame naming the shape whose
    /// `token` is not an object carrying a string `text`, a `generated_text`
    /// that is neither a string nor `null`, a non-empty `top_tokens`
    /// alternatives array, or a `details.best_of_sequences` list — the last two
    /// carry model-authored text that is NOT part of the completion the
    /// `token.text` deltas reconstruct, so folding them into that prose would
    /// corrupt it.
    ///
    /// Such a frame may carry client-visible text on a path nothing here reads,
    /// so a caller that promised inspection must treat the whole stream as
    /// uninspectable and fail closed rather than deliver a clean verdict over
    /// content it never scanned. Sticky once set.
    pub fn provider_stream_uninspectable(&self) -> bool {
        self.provider_uninspectable
    }

    /// Whether this is a Gemini stream with independently rendered candidates.
    ///
    /// Buffered inspection can safely inspect every fully reassembled candidate,
    /// but windowed inspection currently retains one aggregate prose overlap.
    /// Its caller must therefore fail closed instead of allowing one candidate's
    /// padding to evict another candidate's cross-frame continuity.
    pub fn has_multiple_gemini_candidates(&self) -> bool {
        self.gemini_multiple_candidates
    }

    /// Reassembled fragments as of now, **without** consuming the accumulator —
    /// the streamed `inspect` path inspects the current window repeatedly as the
    /// stream grows, so it cannot move the strings out the way
    /// [`into_texts`](Self::into_texts) does for the one-shot buffered path.
    pub fn texts(&self) -> Vec<SseText> {
        self.clone().into_texts()
    }

    /// Trim streamed tool-call names/arguments and Responses-API function-call
    /// arguments to a shared tail budget, dropping already-inspected prefixes.
    ///
    /// Counterpart to [`drain_assistant_prefix`](Self::drain_assistant_prefix)
    /// for the non-prose accumulators: streamed `inspect` mode inspects tool-call
    /// names/arguments alongside prose, so without trimming a large name, large
    /// arguments payload, or many parallel calls could be retained in full.
    /// The caller trims only AFTER a window inspected those bytes clean, so the
    /// dropped prefix was already evaluated; the bounded aggregate tail
    /// preserves cross-window context without multiplying `keep_total` by the
    /// attacker-controlled number of tool indexes. Empty accumulators are
    /// removed so their lookup tables cannot grow for the rest of the stream.
    pub fn truncate_streamed_tool_state(&mut self, keep_total: usize) {
        fn retain_tail_within_budget(text: &mut String, remaining: &mut usize) {
            if *remaining == 0 {
                text.clear();
                return;
            }
            if text.len() > *remaining {
                let mut drop = text.len() - *remaining;
                while drop < text.len() && !text.is_char_boundary(drop) {
                    drop += 1;
                }
                text.drain(..drop);
            }
            *remaining = (*remaining).saturating_sub(text.len());
        }

        let has_names = self
            .tool_calls
            .iter()
            .any(|(_key, accum)| !accum.name.is_empty());
        let has_names = has_names
            || self
                .anthropic_blocks
                .iter()
                .any(|(_index, block)| !block.name.is_empty())
            || self
                .gemini_candidates
                .iter()
                .any(|(_index, candidate)| !candidate.name.is_empty());
        let has_arguments = self
            .tool_calls
            .iter()
            .any(|(_key, accum)| !accum.arguments.is_empty())
            || self
                .responses_args
                .iter()
                .any(|(_output, text)| !text.is_empty())
            || self
                .anthropic_blocks
                .iter()
                .any(|(_index, block)| !block.input_json.is_empty())
            || self
                .gemini_candidates
                .iter()
                .any(|(_index, candidate)| !candidate.args_json.is_empty());
        let argument_budget = if has_names && has_arguments {
            keep_total.div_ceil(2)
        } else if has_arguments {
            keep_total
        } else {
            0
        };
        let name_budget = keep_total.saturating_sub(argument_budget);

        // Keep argument and name tails under separate shares when both exist.
        // A hostile long function name must not consume the entire tool budget
        // and erase the argument overlap needed for cross-window inspection.
        let mut argument_remaining = argument_budget;
        for (_key, accum) in self.tool_calls.iter_mut().rev() {
            retain_tail_within_budget(&mut accum.arguments, &mut argument_remaining);
        }
        for (_output, text) in self.responses_args.iter_mut().rev() {
            retain_tail_within_budget(text, &mut argument_remaining);
        }
        for (_index, block) in self.anthropic_blocks.iter_mut().rev() {
            retain_tail_within_budget(&mut block.input_json, &mut argument_remaining);
        }
        for (_index, candidate) in self.gemini_candidates.iter_mut().rev() {
            retain_tail_within_budget(&mut candidate.args_json, &mut argument_remaining);
        }
        let mut name_remaining = name_budget;
        for (_key, accum) in self.tool_calls.iter_mut().rev() {
            retain_tail_within_budget(&mut accum.name, &mut name_remaining);
        }
        for (_index, block) in self.anthropic_blocks.iter_mut().rev() {
            retain_tail_within_budget(&mut block.name, &mut name_remaining);
        }
        for (_index, candidate) in self.gemini_candidates.iter_mut().rev() {
            retain_tail_within_budget(&mut candidate.name, &mut name_remaining);
        }

        self.tool_calls
            .retain(|(_key, accum)| !accum.name.is_empty() || !accum.arguments.is_empty());
        self.tool_call_positions.clear();
        for (position, (key, _accum)) in self.tool_calls.iter().enumerate() {
            self.tool_call_positions.insert(*key, position);
        }
        self.responses_args
            .retain(|(_output, text)| !text.is_empty());
        self.responses_args_positions.clear();
        for (position, (output, _text)) in self.responses_args.iter().enumerate() {
            self.responses_args_positions.insert(*output, position);
        }
        self.compact_anthropic_blocks();
        self.compact_gemini_candidates();
    }

    /// Drop fully-drained Anthropic content blocks and rebuild their lookup
    /// table. A block is retained while ANY of its three accumulators still
    /// holds bytes, so trimming tool state cannot evict a block whose prose is
    /// still awaiting inspection (or vice versa).
    fn compact_anthropic_blocks(&mut self) {
        self.anthropic_blocks
            .retain(|(_index, block)| !block.is_empty());
        self.anthropic_block_positions.clear();
        for (position, (index, _block)) in self.anthropic_blocks.iter().enumerate() {
            self.anthropic_block_positions.insert(*index, position);
        }
    }

    /// Drop fully-drained Gemini candidates and rebuild their lookup table.
    /// A candidate is retained while ANY of its three accumulators still holds
    /// bytes, so trimming tool state cannot evict a candidate whose prose is
    /// still awaiting inspection (or vice versa).
    fn compact_gemini_candidates(&mut self) {
        self.gemini_candidates
            .retain(|(_index, candidate)| !candidate.is_empty());
        self.gemini_candidate_positions.clear();
        for (position, (index, _candidate)) in self.gemini_candidates.iter().enumerate() {
            self.gemini_candidate_positions.insert(*index, position);
        }
    }

    /// Drop the first `prefix_len` bytes of the logical
    /// [`assistant_content`](Self::assistant_content) (legacy Completions text,
    /// chat-completion content, then Responses-API output text), keeping the tail.
    ///
    /// Streamed `inspect` mode calls this after releasing an inspected-clean
    /// window so retained prose stays bounded to roughly one window plus the
    /// re-inspection overlap, rather than growing with the whole completion.
    /// Tool-call accumulators are intentionally left intact by this prose-only
    /// operation; the window engine bounds them separately with
    /// [`truncate_streamed_tool_state`](Self::truncate_streamed_tool_state).
    /// `prefix_len` is snapped down to a char boundary per entry, so a value
    /// landing mid-character simply retains a few extra bytes (always safe —
    /// never drops un-inspected content).
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
        for (_choice, text) in &mut self.completion_text {
            drain_one(text, &mut remaining);
        }
        for (_choice, text) in &mut self.content {
            drain_one(text, &mut remaining);
        }
        for (_key, text) in &mut self.responses_text {
            drain_one(text, &mut remaining);
        }
        for (_index, block) in &mut self.anthropic_blocks {
            drain_one(&mut block.text, &mut remaining);
        }
        for (_index, candidate) in &mut self.gemini_candidates {
            drain_one(&mut candidate.text, &mut remaining);
        }
        drain_one(&mut self.tgi_text, &mut remaining);
        drain_one(&mut self.anthropic_error_text, &mut remaining);

        self.completion_text
            .retain(|(_choice, text)| !text.is_empty());
        self.completion_text_positions.clear();
        for (position, (choice, _text)) in self.completion_text.iter().enumerate() {
            self.completion_text_positions.insert(*choice, position);
        }
        self.content.retain(|(_choice, text)| !text.is_empty());
        self.content_positions.clear();
        for (position, (choice, _text)) in self.content.iter().enumerate() {
            self.content_positions.insert(*choice, position);
        }
        self.responses_text.retain(|(_key, text)| !text.is_empty());
        self.responses_text_positions.clear();
        for (position, (key, _text)) in self.responses_text.iter().enumerate() {
            self.responses_text_positions.insert(*key, position);
        }
        self.compact_anthropic_blocks();
        self.compact_gemini_candidates();
    }

    /// Accumulate one already-parsed SSE `data:` frame whose `event:` name is
    /// unknown or absent. Anthropic events are still dispatched from the JSON
    /// `type` field, which the Messages protocol always carries.
    pub fn push_frame(&mut self, frame: &Value) {
        self.push_event_frame(None, frame);
    }

    /// Accumulate one already-parsed SSE `data:` frame together with the
    /// `event:` name that framed it (see [`SseParse::reassembly_frames`]).
    pub fn push_event_frame(&mut self, event: Option<SseEventName>, frame: &Value) {
        self.push_chat_completion_deltas(frame);
        self.push_responses_deltas(frame);
        self.push_anthropic_events(event, frame);
        self.push_gemini_frame(frame);
        self.push_tgi_frame(frame);
    }

    /// Consume the accumulator and return the reassembled fragments, dropping any
    /// that reassembled to an empty string.
    pub fn into_texts(self) -> Vec<SseText> {
        let mut out = Vec::new();
        for (choice, text) in self.completion_text {
            if !text.is_empty() {
                out.push(SseText {
                    kind: SseTextKind::CompletionText,
                    json_path: format!("$.choices[{choice}].text"),
                    text,
                });
            }
        }
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
        // Anthropic blocks reassemble into the same document shape the buffered
        // Messages response has, so `$.content[*].text` / `.name` / `.input`
        // read a streamed response with no provider branching at the caller.
        for (index, block) in self.anthropic_blocks {
            if !block.text.is_empty() {
                out.push(SseText {
                    kind: SseTextKind::AnthropicText,
                    json_path: format!("$.content[{index}].text"),
                    text: block.text,
                });
            }
            if !block.name.is_empty() {
                out.push(SseText {
                    kind: SseTextKind::AnthropicToolName,
                    json_path: format!("$.content[{index}].name"),
                    text: block.name,
                });
            }
            if !block.input_json.is_empty() {
                out.push(SseText {
                    kind: SseTextKind::AnthropicToolInput,
                    json_path: format!("$.content[{index}].input"),
                    text: block.input_json,
                });
            }
        }
        // Gemini candidates reassemble into the same document shape the
        // buffered `generateContent` response has, so
        // `$.candidates[*].content.parts[*].text` / `.functionCall.name` /
        // `.functionCall.args` read a streamed response with no provider
        // branching at the caller. The `parts[*]` locator is literal: a
        // candidate's consecutive text parts are joined into one prose string
        // (the way a client renders them), so the fragment spans the parts
        // rather than naming one of them.
        for (index, candidate) in self.gemini_candidates {
            if !candidate.text.is_empty() {
                out.push(SseText {
                    kind: SseTextKind::GeminiText,
                    json_path: format!("$.candidates[{index}].content.parts[*].text"),
                    text: candidate.text,
                });
            }
            if !candidate.name.is_empty() {
                out.push(SseText {
                    kind: SseTextKind::GeminiFunctionCallName,
                    json_path: format!("$.candidates[{index}].content.parts[*].functionCall.name"),
                    text: candidate.name,
                });
            }
            if !candidate.args_json.is_empty() {
                out.push(SseText {
                    kind: SseTextKind::GeminiFunctionCallArgs,
                    json_path: format!("$.candidates[{index}].content.parts[*].functionCall.args"),
                    text: candidate.args_json,
                });
            }
        }
        // TGI reassembles into the same document shape the buffered
        // `/generate` response has — a top-level ARRAY of
        // `{"generated_text": …}` objects — so `$[*].generated_text` reads a
        // streamed response with no provider branching at the caller. A
        // `/generate_stream` response carries exactly one sequence, so the
        // locator names element zero.
        if !self.tgi_text.is_empty() {
            out.push(SseText {
                kind: SseTextKind::TgiGeneratedText,
                json_path: "$[0].generated_text".to_string(),
                text: self.tgi_text,
            });
        }
        // A mid-stream `error` event's `error.message` is client-visible free
        // text, so it is reported as assistant prose (its taxonomy) located at
        // its own path (its true origin) rather than being attributed to a
        // content block that never existed.
        if !self.anthropic_error_text.is_empty() {
            out.push(SseText {
                kind: SseTextKind::AnthropicText,
                json_path: "$.error.message".to_string(),
                text: self.anthropic_error_text,
            });
        }
        out
    }

    fn push_chat_completion_deltas(&mut self, frame: &Value) {
        let Some(choices) = frame.get("choices").and_then(Value::as_array) else {
            return;
        };
        for (positional, choice) in choices.iter().enumerate() {
            let choice_index = index_field(choice, "index").unwrap_or(positional);
            if let Some(text) = choice.get("text").and_then(Value::as_str) {
                self.completion_text_mut(choice_index).push_str(text);
            }
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

    /// Accumulate one Anthropic Messages event.
    ///
    /// Coverage: `message_start` (including a populated `message.content`
    /// envelope), `content_block_start` (block index + `text` seed, or a
    /// `tool_use` name plus a non-empty `input` object), `content_block_delta`
    /// with `delta.type` of `text_delta` (prose) or `input_json_delta`
    /// (tool-input JSON), `error` (`error.message` free text), and the
    /// no-content terminals `content_block_stop`, `message_delta`,
    /// `message_stop`, and `ping`.
    ///
    /// Anything else inside an identified Anthropic stream — an unknown event,
    /// an unknown `delta.type` such as extended thinking's `thinking_delta`, a
    /// `content_block_*` event missing its `index` or payload, or an
    /// interleaved foreign frame — sets [`provider_uninspectable`] instead of
    /// being ignored: it may carry client-visible text on a path this
    /// reassembler does not read, and silently skipping it would let a caller
    /// stamp a clean verdict over content nothing scanned.
    fn push_anthropic_events(&mut self, event: Option<SseEventName>, frame: &Value) {
        let json_event = frame
            .get("type")
            .and_then(Value::as_str)
            .map(SseEventName::from_name);

        let resolved = match (event, json_event) {
            (Some(from_line), Some(from_json)) if from_line != from_json => {
                match (from_line, from_json) {
                    // Both discriminators name Anthropic events, or the stream
                    // already identified itself as Anthropic: at most one of
                    // them describes the payload and neither can be trusted to
                    // route it, so fail closed.
                    (SseEventName::Anthropic(_), SseEventName::Anthropic(_)) => {
                        self.provider_uninspectable = true;
                        return;
                    }
                    _ if self.anthropic_stream => {
                        self.provider_uninspectable = true;
                        return;
                    }
                    // Exactly one side names an Anthropic event on a stream
                    // that has not identified itself as Anthropic. This is the
                    // ordinary shape of a FOREIGN stream whose own event names
                    // happen to collide (`event: ping` beside
                    // `{"type":"heartbeat"}`, or the gateway's own terminal
                    // `event: error` frame), so route by the Anthropic side
                    // rather than failing a stream closed on a protocol it
                    // never claimed. A genuine Anthropic frame mislabeled on
                    // one discriminator is still folded in.
                    (name @ SseEventName::Anthropic(_), _) => Some(name),
                    (_, name) => Some(name),
                }
            }
            (Some(name), _) => Some(name),
            (None, Some(name)) => Some(name),
            (None, None) => None,
        };

        let Some(SseEventName::Anthropic(kind)) = resolved else {
            if self.anthropic_stream {
                self.provider_uninspectable = true;
            }
            return;
        };

        match kind {
            AnthropicEvent::MessageStart => {
                self.anthropic_stream = true;
                // The envelope's `content` array is normally empty here and the
                // blocks that fill it arrive as their own events — but the
                // field is client-visible (Anthropic's own SDK seeds its
                // response snapshot from `message_start.message`), so a
                // populated envelope is folded in rather than discarded.
                let Some(message) = frame.get("message") else {
                    return;
                };
                let Some(content) = message.get("content") else {
                    return;
                };
                let Some(blocks) = content.as_array() else {
                    // `content` present but not an array: outside the protocol
                    // and possibly carrying text on a path nothing reads.
                    self.provider_uninspectable = true;
                    return;
                };
                for (position, block) in blocks.iter().enumerate() {
                    if !self.absorb_anthropic_content_block(position, block) {
                        self.provider_uninspectable = true;
                    }
                }
            }
            AnthropicEvent::ContentBlockStart => {
                self.anthropic_stream = true;
                let Some(index) = index_field(frame, "index") else {
                    self.provider_uninspectable = true;
                    return;
                };
                let Some(block) = frame.get("content_block") else {
                    self.provider_uninspectable = true;
                    return;
                };
                if !self.absorb_anthropic_content_block(index, block) {
                    self.provider_uninspectable = true;
                }
            }
            AnthropicEvent::ContentBlockDelta => {
                self.anthropic_stream = true;
                let Some(index) = index_field(frame, "index") else {
                    self.provider_uninspectable = true;
                    return;
                };
                let Some(delta) = frame.get("delta") else {
                    self.provider_uninspectable = true;
                    return;
                };
                match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => {
                        if let Some(text) = delta.get("text").and_then(Value::as_str) {
                            self.anthropic_block_mut(index).text.push_str(text);
                        } else {
                            self.provider_uninspectable = true;
                        }
                    }
                    Some("input_json_delta") => {
                        if let Some(fragment) = delta.get("partial_json").and_then(Value::as_str) {
                            self.anthropic_block_mut(index)
                                .input_json
                                .push_str(fragment);
                        } else {
                            self.provider_uninspectable = true;
                        }
                    }
                    // `thinking_delta`, `signature_delta`, an absent
                    // discriminator, or a delta type added later. Absorb a
                    // plain `text` field when one is there so the fragment is
                    // still inspected rather than dropped, and mark the stream
                    // uninspectable either way — the event may carry more than
                    // the single field read here.
                    _ => {
                        if let Some(text) = delta.get("text").and_then(Value::as_str) {
                            self.anthropic_block_mut(index).text.push_str(text);
                        }
                        self.provider_uninspectable = true;
                    }
                }
            }
            // `error.message` is free text the client sees, so it is scanned
            // like any other client-visible fragment. This arm deliberately
            // does NOT set `anthropic_stream`: a foreign stream's terminal
            // `event: error` frame (including the gateway's own) must not
            // reclassify the rest of that stream as Anthropic.
            AnthropicEvent::Error => {
                if let Some(message) = frame
                    .get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Value::as_str)
                {
                    self.anthropic_error_text.push_str(message);
                }
            }
            // `message_delta.delta.stop_sequence` echoes a request-supplied
            // stop sequence rather than model output, and `usage` is numeric,
            // so these terminals carry no client-visible model text.
            AnthropicEvent::ContentBlockStop
            | AnthropicEvent::MessageDelta
            | AnthropicEvent::MessageStop
            | AnthropicEvent::Ping => {}
        }
    }

    /// Fold one Anthropic content block — from a `content_block_start` event or
    /// from the `message_start` envelope's `content` array — into the
    /// accumulator for `index`.
    ///
    /// `false` means the block is a type this reassembler cannot fold
    /// (`thinking`, `image`, `redacted_thinking`, or a block type added after
    /// this code was written), so the caller marks the stream uninspectable.
    /// Bounded exactly like the delta path: one level, this block's own fields,
    /// and the [`MAX_ANTHROPIC_CONTENT_BLOCKS`] ceiling applies through
    /// [`anthropic_block_mut`](Self::anthropic_block_mut).
    fn absorb_anthropic_content_block(&mut self, index: usize, block: &Value) -> bool {
        match block.get("type").and_then(Value::as_str) {
            // A text block may open with a seed string.
            Some("text") => {
                let seed = block.get("text").and_then(Value::as_str).unwrap_or("");
                self.anthropic_block_mut(index).text.push_str(seed);
                true
            }
            // Client tool calls and the provider-executed variants all announce
            // the invoked name here and stream their arguments as
            // `input_json_delta`.
            Some("tool_use" | "server_tool_use" | "mcp_tool_use") => {
                let name = block.get("name").and_then(Value::as_str).unwrap_or("");
                self.anthropic_block_mut(index).name.push_str(name);
                self.absorb_anthropic_tool_input(index, block.get("input"))
            }
            _ => false,
        }
    }

    /// Fold a tool-use block's `input` document into that block's tool-input
    /// accumulator.
    ///
    /// The protocol opens a tool-use block with an empty `input` object and
    /// streams the real arguments as `input_json_delta` fragments, so an absent
    /// or empty `input` contributes nothing. A NON-empty object is
    /// client-visible tool input that the buffered `$.content[*].input` path
    /// inspects, so it is serialized compactly into the same accumulator the
    /// deltas append to rather than being discarded. Any other JSON type is
    /// outside the protocol and returns `false`.
    fn absorb_anthropic_tool_input(&mut self, index: usize, input: Option<&Value>) -> bool {
        let Some(input) = input else {
            return true;
        };
        let Some(object) = input.as_object() else {
            return false;
        };
        if object.is_empty() {
            return true;
        }
        let Ok(serialized) = serde_json::to_string(input) else {
            return false;
        };
        self.anthropic_block_mut(index)
            .input_json
            .push_str(&serialized);
        true
    }

    /// Accumulator for one Anthropic content-block index, folding indexes at or
    /// beyond [`MAX_ANTHROPIC_CONTENT_BLOCKS`] into a single shared overflow
    /// bucket so the retained accumulator count cannot grow with an
    /// attacker-chosen index. Folded content is still reassembled and
    /// inspected; the stream is marked uninspectable so callers that promised
    /// inspection fail closed on it.
    fn anthropic_block_mut(&mut self, index: usize) -> &mut AnthropicBlockAccumulator {
        let key = if index >= MAX_ANTHROPIC_CONTENT_BLOCKS {
            self.provider_uninspectable = true;
            MAX_ANTHROPIC_CONTENT_BLOCKS
        } else {
            index
        };
        let pos = match self.anthropic_block_positions.get(&key).copied() {
            Some(pos) => pos,
            None => {
                let pos = self.anthropic_blocks.len();
                self.anthropic_blocks
                    .push((key, AnthropicBlockAccumulator::default()));
                self.anthropic_block_positions.insert(key, pos);
                pos
            }
        };
        &mut self.anthropic_blocks[pos].1
    }

    /// Accumulate one Google Gemini / Vertex `streamGenerateContent?alt=sse`
    /// frame.
    ///
    /// Every frame is a complete `GenerateContentResponse` whose
    /// `candidates[i].content.parts[j]` carry one incremental piece each, so
    /// reassembly concatenates them per candidate index into the same document
    /// shape a buffered `generateContent` response has. Sibling envelope fields
    /// (`usageMetadata`, `promptFeedback`, `modelVersion`, `finishReason`,
    /// `safetyRatings`) carry no free model text and are ignored.
    ///
    /// Gemini frames carry no event discriminator, so the shape itself selects
    /// the path (see [`is_gemini_stream_frame`]) and a frame that also carries
    /// `choices` or a `type` is left to the OpenAI / Anthropic paths rather
    /// than being read twice. A frame that names Gemini's shape but violates it
    /// — a non-array `candidates`, a non-object candidate or part, a non-array
    /// `content.parts`, a non-string `text`, an unfoldable part kind, or a
    /// candidate index past [`MAX_GEMINI_CANDIDATES`] — sets
    /// [`provider_uninspectable`]: it may carry client-visible text on a path
    /// this reassembler does not read.
    fn push_gemini_frame(&mut self, frame: &Value) {
        if !is_gemini_stream_frame(frame) {
            return;
        }
        let Some(candidates) = frame.get("candidates").and_then(Value::as_array) else {
            // `candidates` present but not an array: outside the protocol and
            // possibly carrying text on a path nothing reads.
            self.provider_uninspectable = true;
            return;
        };
        for (positional, candidate) in candidates.iter().enumerate() {
            let Some(object) = candidate.as_object() else {
                self.provider_uninspectable = true;
                continue;
            };
            // A candidate repeats its own `index` on every frame, which is what
            // ties a later fragment back to the prose it continues; fall back to
            // position only when the provider omits it.
            let index = index_field(candidate, "index").unwrap_or(positional);
            // A blocked or finished candidate legitimately carries no `content`
            // (or a `content` with no `parts`) and contributes nothing.
            let Some(content) = object.get("content") else {
                continue;
            };
            let Some(content) = content.as_object() else {
                self.provider_uninspectable = true;
                continue;
            };
            let Some(parts) = content.get("parts") else {
                continue;
            };
            let Some(parts) = parts.as_array() else {
                self.provider_uninspectable = true;
                continue;
            };
            if !parts.is_empty() {
                match self.gemini_first_candidate {
                    Some(first) if first != index => self.gemini_multiple_candidates = true,
                    None => self.gemini_first_candidate = Some(index),
                    Some(_) => {}
                }
            }
            for part in parts {
                if !self.absorb_gemini_part(index, part) {
                    self.provider_uninspectable = true;
                }
            }
        }
    }

    /// Fold one Gemini `content.parts[]` entry into the accumulator for
    /// `index`.
    ///
    /// `false` means the part is a kind this reassembler cannot fold —
    /// `inlineData`, `fileData`, `executableCode`, `codeExecutionResult`,
    /// `functionResponse`, a `thought` summary, or a part kind added after this
    /// code was written — so the caller marks the stream uninspectable, exactly
    /// as an Anthropic `thinking` block does. A thought part's prose is still
    /// absorbed where it exists, so nothing is dropped from what is scanned.
    fn absorb_gemini_part(&mut self, index: usize, part: &Value) -> bool {
        let Some(object) = part.as_object() else {
            return false;
        };
        // A `thought` part is the model's internal reasoning summary rather
        // than the client-visible answer; it is scanned but never treated as a
        // fully modelled part.
        if object.contains_key("thought") {
            if let Some(text) = object.get("text").and_then(Value::as_str) {
                self.gemini_candidate_mut(index).text.push_str(text);
            }
            return false;
        }
        if let Some(text) = object.get("text") {
            let Some(text) = text.as_str() else {
                return false;
            };
            self.gemini_candidate_mut(index).text.push_str(text);
            return true;
        }
        if let Some(call) = object.get("functionCall") {
            return self.absorb_gemini_function_call(index, call);
        }
        false
    }

    /// Fold a `functionCall` part's invoked name and `args` document into that
    /// candidate's tool accumulators — the Gemini equivalent of an Anthropic
    /// `tool_use` block's `name` and `input`.
    ///
    /// An absent or empty `args` object contributes nothing; a populated one is
    /// serialized compactly into the same accumulator so the buffered
    /// `functionCall.args` path reads the streamed form unchanged. Any other
    /// JSON type for `name` or `args` is outside the protocol and returns
    /// `false`.
    fn absorb_gemini_function_call(&mut self, index: usize, call: &Value) -> bool {
        let Some(object) = call.as_object() else {
            return false;
        };
        if let Some(name) = object.get("name") {
            let Some(name) = name.as_str() else {
                return false;
            };
            self.gemini_candidate_mut(index).name.push_str(name);
        }
        let Some(args) = object.get("args") else {
            return true;
        };
        let Some(map) = args.as_object() else {
            return false;
        };
        if map.is_empty() {
            return true;
        }
        let Ok(serialized) = serde_json::to_string(args) else {
            return false;
        };
        self.gemini_candidate_mut(index)
            .args_json
            .push_str(&serialized);
        true
    }

    /// Accumulator for one Gemini candidate index, folding indexes at or beyond
    /// [`MAX_GEMINI_CANDIDATES`] into a single shared overflow bucket so the
    /// retained accumulator count cannot grow with a provider-chosen index.
    /// Folded content is still reassembled and inspected; the stream is marked
    /// uninspectable so callers that promised inspection fail closed on it.
    fn gemini_candidate_mut(&mut self, index: usize) -> &mut GeminiCandidateAccumulator {
        let key = if index >= MAX_GEMINI_CANDIDATES {
            self.provider_uninspectable = true;
            MAX_GEMINI_CANDIDATES
        } else {
            index
        };
        let pos = match self.gemini_candidate_positions.get(&key).copied() {
            Some(pos) => pos,
            None => {
                let pos = self.gemini_candidates.len();
                self.gemini_candidates
                    .push((key, GeminiCandidateAccumulator::default()));
                self.gemini_candidate_positions.insert(key, pos);
                pos
            }
        };
        &mut self.gemini_candidates[pos].1
    }

    /// Accumulate one Hugging Face TGI `/generate_stream` frame.
    ///
    /// TGI streams one sequence per request as
    /// `{"index": n, "token": {"id": …, "text": "Hel", …}, "generated_text":
    /// null, "details": null}` frames, with the terminal frame carrying the
    /// completed `generated_text` string (and `details` when the request asked
    /// for them). The `token.text` fragments concatenate into exactly the text
    /// the client renders, which is the same string the buffered `/generate`
    /// document carries at `$[*].generated_text`.
    ///
    /// TGI frames carry no event discriminator, so the shape selects the path
    /// (see [`is_tgi_stream_frame`]) and a frame that also carries `choices`, a
    /// `type`, or `candidates` is left to the OpenAI / Anthropic / Gemini paths
    /// rather than being read twice. A frame that names TGI's shape but
    /// violates it sets [`provider_uninspectable`], as does one carrying
    /// alternative-token text this reassembler does not fold.
    ///
    /// Selection is structural on the FIRST frame and sticky afterwards: an
    /// unrelated event stream carrying a string `token` is not claimed, while a
    /// stream that has identified itself as TGI holds every later
    /// `token` / `generated_text` frame to the protocol.
    fn push_tgi_frame(&mut self, frame: &Value) {
        if !frame_carries_only_tgi_discriminators(frame) {
            return;
        }
        // The selector is structural (see [`is_tgi_stream_frame`]), so an
        // unrelated stream whose frames happen to carry a string `token` is not
        // claimed. Once a frame HAS identified the stream as TGI, every later
        // frame carrying those members is held to the protocol whatever its
        // type — otherwise an intermediary could hide a fragment by mistyping
        // the field the reassembler reads and the stream would still be
        // reported clean.
        if !is_tgi_stream_frame(frame) && !self.tgi_stream {
            return;
        }
        self.tgi_stream = true;
        let Some(object) = frame.as_object() else {
            // Named the shape (`Value::get` reads through no other type), yet
            // is not an object: outside the protocol.
            self.provider_uninspectable = true;
            return;
        };
        // `top_n_tokens` adds a `top_tokens` array of alternative tokens per
        // frame, and `best_of` adds `details.best_of_sequences`. Both are
        // model-authored text a client can render, but neither belongs to the
        // completion the `token.text` deltas reconstruct, so folding them into
        // that prose would corrupt it. Flag instead, exactly as an unfoldable
        // Gemini part kind does.
        let alternatives_present = match object.get("top_tokens") {
            None => false,
            Some(Value::Array(list)) => !list.is_empty(),
            // Present but not an array: outside the protocol either way.
            Some(_) => true,
        };
        let best_of_present = object
            .get("details")
            .and_then(|details| details.get("best_of_sequences"))
            .is_some();
        if alternatives_present || best_of_present {
            self.provider_uninspectable = true;
        }
        if let Some(token) = object.get("token") {
            match token.get("text").and_then(Value::as_str) {
                Some(text) => self.tgi_text.push_str(text),
                // A `token` that is not an object, or whose `text` is absent or
                // not a string, is outside the protocol and may carry the
                // fragment on a field nothing here reads.
                None => self.provider_uninspectable = true,
            }
        }
        match object.get("generated_text") {
            // Absent, or the `null` every non-terminal frame carries.
            None | Some(Value::Null) => {}
            Some(Value::String(full)) => self.absorb_tgi_generated_text(full),
            Some(_) => self.provider_uninspectable = true,
        }
    }

    /// Fold the terminal frame's completed `generated_text` into the TGI
    /// accumulator.
    ///
    /// By protocol this string is the concatenation of the `token.text`
    /// fragments already accumulated, so appending it unconditionally would
    /// scan the whole completion twice and let a match straddle the seam
    /// between the deltas and their own repetition. It is therefore skipped
    /// when the accumulated text already ends with it, and appended otherwise
    /// — a terminal full text that diverges from the deltas (or one whose
    /// accumulated prefix a windowed inspector has already released and
    /// drained) is client-visible text that must still be scanned at least
    /// once.
    fn absorb_tgi_generated_text(&mut self, full: &str) {
        if full.is_empty() || self.tgi_text.ends_with(full) {
            return;
        }
        self.tgi_text.push_str(full);
    }

    fn completion_text_mut(&mut self, choice: usize) -> &mut String {
        let pos = match self.completion_text_positions.get(&choice).copied() {
            Some(pos) => pos,
            None => {
                let pos = self.completion_text.len();
                self.completion_text.push((choice, String::new()));
                self.completion_text_positions.insert(choice, pos);
                pos
            }
        };
        &mut self.completion_text[pos].1
    }

    fn content_mut(&mut self, choice: usize) -> &mut String {
        let pos = match self.content_positions.get(&choice).copied() {
            Some(pos) => pos,
            None => {
                let pos = self.content.len();
                self.content.push((choice, String::new()));
                self.content_positions.insert(choice, pos);
                pos
            }
        };
        &mut self.content[pos].1
    }

    fn tool_call_mut(&mut self, choice: usize, tool: usize) -> &mut ToolCallAccumulator {
        let key = (choice, tool);
        let pos = match self.tool_call_positions.get(&key).copied() {
            Some(pos) => pos,
            None => {
                let pos = self.tool_calls.len();
                self.tool_calls.push((key, ToolCallAccumulator::default()));
                self.tool_call_positions.insert(key, pos);
                pos
            }
        };
        &mut self.tool_calls[pos].1
    }

    fn responses_text_mut(&mut self, output: usize, content: usize) -> &mut String {
        let key = (output, content);
        let pos = match self.responses_text_positions.get(&key).copied() {
            Some(pos) => pos,
            None => {
                let pos = self.responses_text.len();
                self.responses_text.push((key, String::new()));
                self.responses_text_positions.insert(key, pos);
                pos
            }
        };
        &mut self.responses_text[pos].1
    }

    fn responses_args_mut(&mut self, output: usize) -> &mut String {
        let pos = match self.responses_args_positions.get(&output).copied() {
            Some(pos) => pos,
            None => {
                let pos = self.responses_args.len();
                self.responses_args.push((output, String::new()));
                self.responses_args_positions.insert(output, pos);
                pos
            }
        };
        &mut self.responses_args[pos].1
    }
}

/// Whether one parsed SSE `data:` frame is a Google Gemini / Vertex
/// `streamGenerateContent?alt=sse` frame that [`SseReassembler`] reassembles.
///
/// Gemini streams carry no `event:` line and no JSON `type` discriminator —
/// every frame is a complete `GenerateContentResponse` — so the shape itself is
/// the signal: a `candidates` member with neither an OpenAI `choices` array nor
/// an event `type` beside it. Detection is by the MEMBER, not by its JSON type,
/// so a frame claiming the shape while violating it (a non-array `candidates`)
/// is still routed here and fails the stream closed rather than slipping past
/// every provider path unread.
///
/// Callers that decide whether an otherwise segment-less window is a governed
/// provider stream this build cannot map use this to exclude the frames that
/// ARE now mapped.
pub fn is_gemini_stream_frame(frame: &Value) -> bool {
    frame.get("candidates").is_some()
        && frame.get("choices").is_none()
        && frame.get("type").is_none()
}

/// Whether one parsed SSE `data:` frame is a Hugging Face TGI
/// `/generate_stream` frame that [`SseReassembler`] reassembles.
///
/// TGI streams carry no `event:` line and no JSON `type` discriminator, so the
/// shape is the signal: a `token` OBJECT fragment or a string `generated_text`
/// completion, with none of the three discriminators the other modelled
/// protocols use beside it (`choices` for OpenAI, `type` for Anthropic / the
/// Responses API, `candidates` for Gemini).
///
/// Unlike the Gemini selector this one is STRUCTURAL rather than by member
/// presence: `candidates` is distinctive, but `token` is an ordinary field name
/// on unrelated event streams, and claiming a session or progress stream would
/// fail it closed on every enforcing caller. A frame that violates the protocol
/// is not thereby unreachable — a stream one frame has identified as TGI holds
/// every later `token` / `generated_text` frame to the protocol whatever its
/// type, so a mistyped field fails the stream closed instead of slipping past
/// unread (see [`SseReassembler::push_tgi_frame`]).
///
/// Callers that decide whether an otherwise segment-less window is a governed
/// provider stream this build cannot map use this to exclude the frames that
/// ARE now mapped.
pub fn is_tgi_stream_frame(frame: &Value) -> bool {
    if !frame_carries_only_tgi_discriminators(frame) {
        return false;
    }
    frame.get("token").is_some_and(Value::is_object)
        || frame.get("generated_text").is_some_and(Value::is_string)
}

/// Whether `frame` carries a `token` / `generated_text` member and none of the
/// discriminators that route a frame to one of the other modelled protocols.
fn frame_carries_only_tgi_discriminators(frame: &Value) -> bool {
    (frame.get("token").is_some() || frame.get("generated_text").is_some())
        && frame.get("choices").is_none()
        && frame.get("type").is_none()
        && frame.get("candidates").is_none()
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
    accept.split(',').any(|media_range| {
        let mut parts = media_range.split(';');
        if !parts.next().is_some_and(is_text_event_stream_media_type) {
            return false;
        }

        let mut quality_seen = false;
        for parameter in parts {
            let Some((name, value)) = parameter.split_once('=') else {
                // A malformed bare quality parameter must not retain the
                // default affirmative qvalue. Unknown extension parameters
                // remain irrelevant to the request-side hint.
                if parameter.trim().eq_ignore_ascii_case("q") {
                    return false;
                }
                continue;
            };
            if !name.trim().eq_ignore_ascii_case("q") {
                continue;
            }
            if quality_seen {
                return false;
            }
            quality_seen = true;
            if !quality_value_is_positive(value.trim()) {
                return false;
            }
        }
        true
    })
}

/// Parse the RFC 9110 `qvalue` grammar without floating-point ambiguity. An
/// invalid value is not affirmative streaming intent, which is the safe side
/// of the request-side hint used by non-policy streaming plugins.
fn quality_value_is_positive(value: &str) -> bool {
    if value == "0" {
        return false;
    }
    if value == "1" {
        return true;
    }
    if let Some(fraction) = value.strip_prefix("0.") {
        return fraction.len() <= 3
            && fraction.bytes().all(|byte| byte.is_ascii_digit())
            && fraction.bytes().any(|byte| byte != b'0');
    }
    if let Some(fraction) = value.strip_prefix("1.") {
        return fraction.len() <= 3 && fraction.bytes().all(|byte| byte == b'0');
    }
    false
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
    fn rejects_event_stream_with_zero_quality() {
        for value in [
            "text/event-stream; q=0",
            "text/event-stream; q=0.0",
            "text/event-stream; q=0.000",
            "text/event-stream; Q=0",
        ] {
            assert!(!is_sse_request(&ctx_with_accept(Some(value))), "{value}");
        }
    }

    #[test]
    fn rejects_event_stream_with_invalid_quality() {
        for value in [
            "text/event-stream; q=",
            "text/event-stream; q=2",
            "text/event-stream; q=0.0001",
            "text/event-stream; q=1.1",
            "text/event-stream; q=1; q=0",
            "text/event-stream; q",
            "text/event-stream; Q ",
        ] {
            assert!(!is_sse_request(&ctx_with_accept(Some(value))), "{value}");
        }
    }

    #[test]
    fn pristine_response_content_type_wins_over_live_relabel() {
        let mut ctx = ctx_with_accept(None);
        ctx.metadata.insert(
            crate::proxy::ORIGINAL_RESPONSE_METADATA_STAMPED_KEY.to_string(),
            "true".to_string(),
        );
        ctx.metadata.insert(
            crate::proxy::ORIGINAL_RESPONSE_CONTENT_TYPE_METADATA_KEY.to_string(),
            "text/event-stream; charset=utf-8".to_string(),
        );
        let live_headers =
            HashMap::from([("content-type".to_string(), "application/json".to_string())]);
        assert!(original_response_is_event_stream(&ctx, &live_headers));
    }

    #[test]
    fn stamped_missing_content_type_does_not_trust_live_injection() {
        let mut ctx = ctx_with_accept(None);
        ctx.metadata.insert(
            crate::proxy::ORIGINAL_RESPONSE_METADATA_STAMPED_KEY.to_string(),
            "true".to_string(),
        );
        let live_headers =
            HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
        assert!(!original_response_is_event_stream(&ctx, &live_headers));
    }

    #[test]
    fn stamped_ambiguous_content_type_is_not_event_stream() {
        let mut ctx = ctx_with_accept(None);
        ctx.metadata.insert(
            crate::proxy::ORIGINAL_RESPONSE_METADATA_STAMPED_KEY.to_string(),
            "true".to_string(),
        );
        ctx.metadata.insert(
            crate::proxy::ORIGINAL_RESPONSE_CONTENT_TYPE_METADATA_KEY.to_string(),
            "application/event-stream+json".to_string(),
        );
        let live_headers =
            HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
        assert!(!original_response_is_event_stream(&ctx, &live_headers));
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
    fn drain_assistant_prefix_prunes_all_empty_prose_indexes() {
        let mut reassembler = SseReassembler::new();
        for index in 0..1024 {
            reassembler.push_frame(&serde_json::json!({
                "choices": [{
                    "index": index,
                    "text": "x",
                    "delta": {"content": "y"}
                }]
            }));
            reassembler.push_frame(&serde_json::json!({
                "type": "response.output_text.delta",
                "output_index": index,
                "content_index": 0,
                "delta": "z"
            }));
            reassembler.drain_assistant_prefix(3);
        }

        assert!(reassembler.completion_text.is_empty());
        assert!(reassembler.completion_text_positions.is_empty());
        assert!(reassembler.content.is_empty());
        assert!(reassembler.content_positions.is_empty());
        assert!(reassembler.responses_text.is_empty());
        assert!(reassembler.responses_text_positions.is_empty());

        reassembler.push_frame(&serde_json::json!({
            "choices": [{
                "index": 1024,
                "text": "legacy",
                "delta": {"content": "chat"}
            }]
        }));
        reassembler.push_frame(&serde_json::json!({
            "type": "response.output_text.delta",
            "output_index": 1024,
            "content_index": 0,
            "delta": "response"
        }));
        assert_eq!(reassembler.assistant_content(), "legacychatresponse");
    }

    #[test]
    fn truncate_streamed_tool_state_bounds_names_and_arguments_keeping_tail() {
        let mut r = SseReassembler::new();
        // A long tool-call argument stream (well past any small keep_tail).
        let big = "X".repeat(500);
        let frame = format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"name\":\"run\",\"arguments\":\"{big}\"}}}}]}}}}]}}\n\n"
        );
        for f in parse_sse_data_frames(frame.as_bytes()) {
            r.push_frame(&f);
        }
        r.truncate_streamed_tool_state(64);
        let args = r
            .texts()
            .into_iter()
            .find(|t| t.kind == SseTextKind::ChatToolArguments)
            .map(|t| t.text)
            .unwrap_or_default();
        assert!(
            args.len() <= 64,
            "args bounded to ~keep_tail, got {}",
            args.len()
        );
        assert!(!args.is_empty(), "argument overlap must be retained");
        assert!(args.chars().all(|c| c == 'X'), "kept the argument tail");
        // A normal-sized tool name remains while the hostile argument is bounded.
        assert!(r.texts().iter().any(|t| t.text == "run"));
    }

    #[test]
    fn truncate_streamed_tool_state_uses_one_budget_across_parallel_calls() {
        let mut r = SseReassembler::new();
        let name = "N".repeat(200);
        let arguments = "A".repeat(200);
        let frame = format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"name\":\"{name}\",\"arguments\":\"{arguments}\"}}}},{{\"index\":1,\"function\":{{\"name\":\"{name}\",\"arguments\":\"{arguments}\"}}}}]}}}}]}}\n\n"
        );
        for parsed in parse_sse_data_frames(frame.as_bytes()) {
            r.push_frame(&parsed);
        }
        assert!(r.retained_text_len() > 64);

        r.truncate_streamed_tool_state(64);

        assert!(
            r.retained_text_len() <= 64,
            "parallel tool state exceeded shared tail budget: {}",
            r.retained_text_len()
        );
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
    fn reassembles_legacy_completion_text_chunks() {
        let body = b"data: {\"choices\":[{\"index\":0,\"text\":\"My system \"}]}\n\n\
data: {\"choices\":[{\"index\":0,\"text\":\"prompt is secret.\"}]}\n\n\
data: [DONE]\n\n";
        let texts = reassemble(body);
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0].kind, SseTextKind::CompletionText);
        assert_eq!(texts[0].text, "My system prompt is secret.");
        assert_eq!(texts[0].json_path, "$.choices[0].text");
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
    fn reassembles_many_distinct_untrusted_indexes_without_linear_scans() {
        let mut reassembler = SseReassembler::new();
        for index in 0..4096 {
            reassembler.push_frame(&serde_json::json!({
                "choices": [{
                    "index": index,
                    "delta": { "content": "x" }
                }]
            }));
        }

        let texts = reassembler.into_texts();
        assert_eq!(texts.len(), 4096);
        assert_eq!(texts[0].json_path, "$.choices[0].delta.content");
        assert_eq!(texts[4095].json_path, "$.choices[4095].delta.content");
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
