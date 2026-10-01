//! Bounded recognition of MCP JSON-RPC `tools/call` requests (issue #5908).
//!
//! `mcp_gateway` owns MCP routing. The AI governance plugins only need to know
//! WHICH tools a request calls and with WHAT arguments: `rate_limiting`
//! (`mcp_tool_calls`) counts calls, `ai_prompt_shield`
//! (`scan_fields: mcp_arguments`) scans `params.arguments`, and
//! `ai_transcript_audit` records each call. They share this one recognizer so
//! a batch, an escaped member name, or a duplicated member means the same
//! thing to every one of them and to the gateway.
//!
//! Recognition follows the gateway's own admission rules:
//!
//! - a body is a JSON-RPC singleton (an object) or a batch (an array);
//! - member names are decoded before comparison, so `"m\u0065thod"` is
//!   `method`, and a body with duplicate member names is ambiguous (the
//!   gateway refuses it with `-32600`) rather than read one way here and
//!   another way downstream;
//! - a batch reuses `mcp_gateway`'s default batch bounds
//!   (`validation.max_batch_items` / `max_batch_bytes` /
//!   `max_batch_item_bytes`) and never funds a `Value` tree for a member past
//!   them.
//!
//! The byte scanner never materializes a `serde_json::Value` for the request:
//! it reads each member's top-level fields as borrowed raw slices and parses
//! only `method` and `params.name`. Bodies that cannot name `tools/call` at
//! all (no `tools/call` byte sequence and no JSON escape) are answered before
//! any parse, so ordinary JSON traffic pays one `memchr` pass.

use serde_json::Value;
use serde_json::value::RawValue;
use std::collections::BTreeMap;

/// The JSON-RPC method these helpers recognize.
pub const TOOLS_CALL_METHOD: &str = "tools/call";

/// Most members one recognized batch may carry: `mcp_gateway`'s default
/// `validation.max_batch_items`.
pub const MAX_BATCH_ITEMS: usize = 32;

/// Largest batch body the byte scanner reads: `mcp_gateway`'s default
/// `validation.max_batch_bytes`.
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;

/// Largest single batch member the byte scanner reads: `mcp_gateway`'s default
/// `validation.max_batch_item_bytes`.
pub const MAX_BATCH_ITEM_BYTES: usize = 256 * 1024;

/// Largest JSON-RPC id token a gateway-authored error may reflect verbatim,
/// matching `mcp_gateway`'s reflected-id bound. A longer id is answered with
/// `id: null`.
pub const MAX_REFLECTED_ID_BYTES: usize = 4096;

/// Whether a request `Content-Type` value names a JSON representation an MCP
/// endpoint accepts: `application/json`, `application/json-rpc`, or any
/// `+json` suffix, compared case-insensitively. `mcp_gateway` admits these and
/// a request with no `Content-Type` at all, so a governance plugin that wants
/// to see every `tools/call` the gateway routes must accept the same set.
pub fn content_type_is_json(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or(value).trim();
    media_type.eq_ignore_ascii_case("application/json")
        || media_type.eq_ignore_ascii_case("application/json-rpc")
        || media_type
            .rsplit_once('+')
            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
}

/// Whether a request `Content-Type` value declares no `charset` parameter, or
/// declares UTF-8 (`utf-8` / `utf8`, case-insensitive, optionally quoted, with
/// whitespace tolerated around `;` and `=`).
///
/// MCP JSON-RPC is read as UTF-8 by every governance plugin and by
/// `mcp_gateway`. A body under another charset — UTF-7 is plain ASCII and still
/// parses as JSON — would be inspected as one text here and decoded as another
/// by an upstream that honours the charset (GHSA-4f9m-cfqg-fhx9), so callers
/// refuse it. A parameter that cannot be read as one of those spellings
/// (an empty value, an unterminated quote) counts as non-UTF-8.
pub fn content_type_charset_is_utf8(value: &str) -> bool {
    value.split(';').skip(1).all(|parameter| {
        let Some((name, charset)) = parameter.split_once('=') else {
            return true;
        };
        if !name.trim().eq_ignore_ascii_case("charset") {
            return true;
        }
        let charset = charset.trim();
        let charset = charset
            .strip_prefix('"')
            .and_then(|quoted| quoted.strip_suffix('"'))
            .unwrap_or(charset)
            .trim();
        charset.eq_ignore_ascii_case("utf-8") || charset.eq_ignore_ascii_case("utf8")
    })
}

/// One `tools/call` request read from the wire bytes.
#[derive(Debug)]
pub struct ToolCallRef<'a> {
    /// `params.name` when it is a JSON string.
    pub name: Option<String>,
    /// `params.arguments` exactly as sent, when present.
    pub arguments: Option<&'a RawValue>,
}

/// One JSON-RPC batch member (or the singleton) read from the wire bytes.
#[derive(Debug)]
pub struct MemberRef<'a> {
    /// The member's `id` token exactly as sent. `None` when the member has no
    /// `id` (a notification) or is not an object.
    pub id: Option<&'a RawValue>,
    /// The call, when the member is a `tools/call`.
    pub tool_call: Option<ToolCallRef<'a>>,
}

impl MemberRef<'_> {
    /// Whether this member expects a JSON-RPC response.
    pub fn is_request(&self) -> bool {
        self.id.is_some()
    }
}

/// What a request body carries, as far as `tools/call` is concerned.
#[derive(Debug)]
pub enum RequestScan<'a> {
    /// No member is a `tools/call` (including bodies that are not JSON-RPC,
    /// are malformed, or are not UTF-8: `mcp_gateway` refuses the last two).
    NoToolCall,
    /// At least one member is a `tools/call`. `members` lists every member in
    /// wire order, including those that are not calls.
    ToolCalls {
        batch: bool,
        members: Vec<MemberRef<'a>>,
    },
    /// The body may carry a `tools/call` but cannot be read faithfully: its
    /// member names are ambiguous, or a batch exceeds the shared bounds. The
    /// reason is a fixed token.
    Uninspectable(&'static str),
}

impl<'a> RequestScan<'a> {
    /// The `tools/call` members, in wire order.
    pub fn tool_calls<'s>(&'s self) -> impl Iterator<Item = &'s ToolCallRef<'a>> + 's {
        let members: &'s [MemberRef<'a>] = match self {
            Self::ToolCalls { members, .. } => members.as_slice(),
            _ => &[],
        };
        members
            .iter()
            .filter_map(|member| member.tool_call.as_ref())
    }
}

/// Cheap pre-filter: a body that contains neither the literal `tools/call` nor
/// any JSON escape cannot spell the method, so it is not parsed at all.
fn may_name_tools_call(body: &[u8]) -> bool {
    memchr::memchr(b'\\', body).is_some()
        || memchr::memmem::find(body, TOOLS_CALL_METHOD.as_bytes()).is_some()
}

/// Whether `body` may carry a `tools/call` that some lenient JSON reader could
/// execute, so a policy that failed to parse it strictly must not forward it.
///
/// True when the body
///
/// - contains a NUL byte and its first byte that is neither NUL nor ASCII
///   whitespace is `{`, `[`, `/`, or `#` (UTF-16 / UTF-32 JSON in either byte
///   order interleaves `0x00` with ASCII, so a `tools/call` spelled in it hides
///   from a UTF-8 search; a binary upload that merely contains NULs is not
///   flagged);
/// - starts with a byte-order mark (UTF-8 `EF BB BF`, UTF-16 `FE FF` /
///   `FF FE`, UTF-32 `00 00 FE FF`), which strict JSON refuses but lenient
///   decoders strip;
/// - opens, after JSON and JSON5 ASCII whitespace (including `\v` and `\f`),
///   with `/` or `#` (a comment), or with a valid UTF-8 non-ASCII character (a
///   BOM after whitespace, a no-break space, U+2028, …); or
/// - opens with `{` or `[` and contains the literal method name or a JSON
///   escape that could spell it.
///
/// Strict UTF-8 JSON never legitimately contains a NUL byte, a BOM, or those
/// lead characters. A body this
/// returns false for is not proven call-free to every reader; it is simply not
/// recognizable as a JSON document that could carry one. This is
/// deliberately looser than [`scan_request_bytes`], which only reports what a
/// strict parser reads: a body strict parsing refuses — an encoding or BOM,
/// `NaN`, `Infinity`, comments, trailing commas — can still be accepted by a
/// lenient upstream (Python's `json`, JSON5), so a policy that must not forward
/// an uninspected call treats such a body as possibly carrying one. The cost is
/// a prefix check, a leading-whitespace scan, and `memchr` / `memmem` passes
/// over the body; nothing is parsed.
pub fn may_carry_tool_call(body: &[u8]) -> bool {
    const BYTE_ORDER_MARKS: [&[u8]; 4] = [
        b"\xEF\xBB\xBF",
        b"\xFE\xFF",
        b"\xFF\xFE",
        b"\x00\x00\xFE\xFF",
    ];
    if BYTE_ORDER_MARKS.iter().any(|bom| body.starts_with(bom)) {
        return true;
    }
    // UTF-16 / UTF-32 JSON: NUL bytes interleaved with an ASCII document whose
    // first real character opens a value or a comment, in either byte order.
    // A binary upload (PNG, JPEG, …) that merely contains NULs is not flagged.
    if memchr::memchr(0, body).is_some() {
        let lead = body
            .iter()
            .copied()
            .find(|byte| !matches!(byte, 0 | b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C));
        if matches!(lead, Some(b'{' | b'[' | b'/' | b'#')) {
            return true;
        }
    }
    let start = body
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C))
        .unwrap_or(body.len());
    let rest = &body[start..];
    match rest.first().copied() {
        Some(b'{' | b'[') => may_name_tools_call(body),
        Some(b'/' | b'#') => true,
        // A non-ASCII character a lenient reader may skip as whitespace (a
        // no-break space, U+2028, a BOM after whitespace). Only a valid UTF-8
        // character counts: UTF-16 / UTF-32 are caught above by their NUL
        // bytes, and a stray high byte opens a binary upload, not JSON.
        Some(0x80..=0xFF) => starts_with_utf8_char(rest),
        _ => false,
    }
}

/// Whether `bytes` opens with one complete, valid UTF-8 character.
fn starts_with_utf8_char(bytes: &[u8]) -> bool {
    let prefix = bytes.get(..4).unwrap_or(bytes);
    match std::str::from_utf8(prefix) {
        Ok(text) => !text.is_empty(),
        Err(error) => error.valid_up_to() > 0,
    }
}

/// Recognize the `tools/call` members of a request body.
pub fn scan_request_bytes(body: &[u8]) -> RequestScan<'_> {
    let Some(first) = body
        .iter()
        .copied()
        .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
    else {
        return RequestScan::NoToolCall;
    };
    if first != b'{' && first != b'[' {
        return RequestScan::NoToolCall;
    }
    if !may_name_tools_call(body) {
        return RequestScan::NoToolCall;
    }
    let batch = first == b'[';
    if batch && body.len() > MAX_BATCH_BYTES {
        return RequestScan::Uninspectable("batch_too_large");
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return RequestScan::NoToolCall;
    };
    if crate::util::json_dup_keys::slice_ambiguity(body).is_some() {
        return RequestScan::Uninspectable("ambiguous_body");
    }
    let members = if batch {
        let Ok(raw_members) = serde_json::from_str::<Vec<&RawValue>>(text) else {
            return RequestScan::NoToolCall;
        };
        if raw_members.len() > MAX_BATCH_ITEMS {
            return RequestScan::Uninspectable("batch_too_many_items");
        }
        let mut members = Vec::with_capacity(raw_members.len());
        for raw in raw_members {
            if raw.get().len() > MAX_BATCH_ITEM_BYTES {
                return RequestScan::Uninspectable("batch_item_too_large");
            }
            members.push(scan_member(raw.get()));
        }
        members
    } else {
        vec![scan_member(text)]
    };
    if members.iter().all(|member| member.tool_call.is_none()) {
        return RequestScan::NoToolCall;
    }
    RequestScan::ToolCalls { batch, members }
}

/// Read one JSON-RPC member from its raw text. A member that is not an object
/// yields no id and no call.
fn scan_member(text: &str) -> MemberRef<'_> {
    let Some(fields) = object_members(text) else {
        return MemberRef {
            id: None,
            tool_call: None,
        };
    };
    let id = fields.get("id").copied();
    let is_tool_call = fields
        .get("method")
        .and_then(|method| serde_json::from_str::<String>(method.get()).ok())
        .is_some_and(|method| method == TOOLS_CALL_METHOD);
    let tool_call = is_tool_call.then(|| {
        let params = fields
            .get("params")
            .and_then(|params| object_members(params.get()));
        let name = params
            .as_ref()
            .and_then(|params| params.get("name"))
            .and_then(|name| serde_json::from_str::<String>(name.get()).ok());
        let arguments = params
            .as_ref()
            .and_then(|params| params.get("arguments"))
            .copied();
        ToolCallRef { name, arguments }
    });
    MemberRef { id, tool_call }
}

/// The members of a JSON object, each as its exact raw text, or `None` when
/// `text` is not an object. Member names are decoded.
fn object_members(text: &str) -> Option<BTreeMap<String, &RawValue>> {
    serde_json::from_str(text).ok()
}

/// Whether a parsed JSON-RPC member is a `tools/call`.
pub fn is_tool_call(member: &Value) -> bool {
    member.get("method").and_then(Value::as_str) == Some(TOOLS_CALL_METHOD)
}

/// Whether a parsed JSON-RPC singleton or batch carries any `tools/call`.
pub fn has_tool_call(document: &Value) -> bool {
    match document {
        Value::Array(members) => members.iter().any(is_tool_call),
        Value::Object(_) => is_tool_call(document),
        _ => false,
    }
}

/// One `tools/call` in a parsed request document.
#[derive(Debug, Clone, Copy)]
pub struct ToolCallValue<'a> {
    /// The member's `id`, when present.
    pub id: Option<&'a Value>,
    /// `params.name` when it is a string.
    pub name: Option<&'a str>,
    /// `params.arguments`, when present.
    pub arguments: Option<&'a Value>,
}

/// Every `tools/call` in a parsed JSON-RPC singleton or batch, in order.
///
/// Parsed-document callers have already bounded the body they parsed, so a
/// batch is walked in full: skipping members past a count bound would let a
/// long batch hide a call from a scanning policy.
pub fn tool_calls_in_value(document: &Value) -> Vec<ToolCallValue<'_>> {
    let members: &[Value] = match document {
        Value::Array(members) => members,
        Value::Object(_) => std::slice::from_ref(document),
        _ => return Vec::new(),
    };
    members
        .iter()
        .filter(|member| is_tool_call(member))
        .map(|member| {
            let params = member.get("params");
            ToolCallValue {
                id: member.get("id"),
                name: params
                    .and_then(|params| params.get("name"))
                    .and_then(Value::as_str),
                arguments: params.and_then(|params| params.get("arguments")),
            }
        })
        .collect()
}

/// Apply `visit` to the `params.arguments` of every `tools/call` in a parsed
/// JSON-RPC singleton or batch, in order. Calls without arguments are skipped.
pub fn for_each_tool_call_arguments_mut(document: &mut Value, mut visit: impl FnMut(&mut Value)) {
    match document {
        Value::Array(members) => {
            for member in members.iter_mut() {
                visit_tool_call_arguments(member, &mut visit);
            }
        }
        Value::Object(_) => visit_tool_call_arguments(document, &mut visit),
        _ => {}
    }
}

fn visit_tool_call_arguments(member: &mut Value, visit: &mut impl FnMut(&mut Value)) {
    if !is_tool_call(member) {
        return;
    }
    if let Some(arguments) = member
        .get_mut("params")
        .and_then(|params| params.get_mut("arguments"))
    {
        visit(arguments);
    }
}
