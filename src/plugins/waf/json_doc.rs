//! Duplicate-preserving JSON document for `body_json_path` rules.
//!
//! `serde_json::Value` keeps only the LAST occurrence of a duplicated object
//! member, while many backends keep the FIRST (or expose every occurrence).
//! The WAF forwards the original bytes, so a rule evaluated on the collapsed
//! `Value` could clear a document whose other occurrence the backend acts on.
//! This tree keeps every member in source order, and [`select`] returns every
//! node a path reaches through any occurrence, so a rule fires when ANY reading
//! of the document carries the forbidden value.
//!
//! Parsing still goes through `serde_json`'s deserializer, so its grammar,
//! member-name unescaping (a `\u`-escaped name is the same member as its
//! literal spelling) and 128-level recursion limit are unchanged. Its string
//! validation is stricter than the parsers backends commonly use: it refuses
//! invalid UTF-8 inside a string and a `\u` escape naming an unpaired UTF-16
//! surrogate. JavaScript `JSON.parse`, Python `json.loads` and Jackson keep an
//! unpaired surrogate, and Go `encoding/json` substitutes `U+FFFD` for it and
//! for invalid UTF-8.
//! A view refused for only those reasons is re-read leniently (see [`parse`]),
//! so one such string cannot hide the rest of the document from inspection.
//! A view holding several whitespace-separated documents is read as all of
//! them, and what still cannot be read is graded by [`JsonView::refused`] so
//! the caller can fail closed instead of treating it as having nothing to
//! inspect.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_json::Value;

use super::rules::JsonPathSegment;

/// UTF-8 encoding of U+FEFF. JSON parsers that sniff encodings (and the
/// declaration-honouring reading of a wide body whose BOM disagrees with its
/// charset) start the document with it; `serde_json` rejects it.
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

pub(super) enum JsonNode {
    /// String, number, boolean, or null.
    Scalar(Value),
    Array(Vec<JsonNode>),
    /// Every member in source order, duplicates included.
    Object(Vec<(String, JsonNode)>),
}

/// How one inspection view reads as JSON.
pub(super) struct JsonView {
    documents: Documents,
    /// `None` when the whole view was read (or is blank). Otherwise how JSON-like
    /// the part that could not be read opens: the most JSON-like of the view's
    /// opening and every document the lenient reading stopped at.
    refused: Option<JsonOpening>,
}

enum Documents {
    Empty,
    /// The strict parse accepted the view: no copy, no vector.
    One(JsonNode),
    Many(Vec<JsonNode>),
}

/// Whether a refused view opens like a JSON object or array.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub(super) enum JsonOpening {
    /// It does not.
    #[default]
    No,
    /// Only when U+0000 is skipped between tokens, as Json.NET does. A NUL is
    /// also how every ASCII character of a UTF-16 / UTF-32 document looks in
    /// its raw bytes, and in some transcoded readings of one, so this alone
    /// does not mark a body as unreadable JSON when another reading of it was
    /// read completely.
    SkippingNul,
    /// It does, without skipping any NUL.
    Yes,
}

/// How far past a refused document the per-document opening check looks.
/// The view's own opening is judged without a bound (once per view); a
/// document the lenient reading stopped at part-way through the view is
/// judged within this window, so a body of many short refused lines costs
/// `O(lines × SNIFF_WINDOW)`, never `O(lines × bytes)`.
const SNIFF_WINDOW: usize = 64;

impl JsonOpening {
    fn of(bytes: &[u8]) -> Self {
        if opens_like_json_container(bytes, false) {
            JsonOpening::Yes
        } else if opens_like_json_container(bytes, true) {
            JsonOpening::SkippingNul
        } else {
            JsonOpening::No
        }
    }

    fn of_window(bytes: &[u8]) -> Self {
        Self::of(&bytes[..bytes.len().min(SNIFF_WINDOW)])
    }
}

impl JsonView {
    /// Every document read from the view, in source order — including the
    /// ones read before (or after) a part that could not be read.
    pub(super) fn documents(&self) -> &[JsonNode] {
        match &self.documents {
            Documents::Empty => &[],
            Documents::One(document) => std::slice::from_ref(document),
            Documents::Many(documents) => documents,
        }
    }

    /// `None` when the whole view was read or is blank; otherwise how
    /// JSON-like the part that could not be read opens.
    pub(super) fn refused(&self) -> Option<JsonOpening> {
        self.refused
    }
}

/// Parse one inspection view. A leading byte-order mark is skipped.
///
/// A view the strict parse accepts is parsed in place, with no copy and no
/// further work. A refused view is re-read the way lenient parsers read it:
/// invalid UTF-8 decodes to `U+FFFD`, every `\u` escape naming an unpaired
/// surrogate (`\uD800`–`\uDFFF` not forming a high-then-low pair) becomes
/// `\uFFFD`, every document of a whitespace-separated sequence is read, and a
/// document that still cannot be read is skipped up to the end of its line,
/// where reading resumes (as a line-by-line NDJSON consumer does). Every
/// document read is returned for inspection, whatever failed around it. Only
/// this failure path copies the view, and only when there is something to
/// repair. The view is refused when anything in it could not be read — for
/// example a number beyond the `f64` range, nesting deeper than
/// `serde_json`'s 128 levels, `NaN`, a comment, a trailing comma, a leading
/// form feed, or an unquoted member name.
pub(super) fn parse(bytes: &[u8]) -> JsonView {
    let bytes = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
    if let Ok(document) = serde_json::from_slice(bytes) {
        return JsonView {
            documents: Documents::One(document),
            refused: None,
        };
    }
    if bytes.iter().all(|byte| is_json_whitespace(*byte)) {
        return JsonView {
            documents: Documents::Empty,
            refused: None,
        };
    }
    let text = String::from_utf8_lossy(bytes);
    let repaired = replace_unpaired_surrogate_escapes(&text);
    let (documents, stopped_at) = parse_lenient_sequence(&repaired);
    let refused = match stopped_at {
        // Every document parsed: the view was read completely.
        None => None,
        Some(stopped_at) => Some(stopped_at.max(JsonOpening::of(bytes))),
    };
    JsonView {
        documents: if documents.is_empty() {
            Documents::Empty
        } else {
            Documents::Many(documents)
        },
        refused,
    }
}

/// Read every document of a whitespace-separated sequence, resuming after
/// the line that holds an error. Returns the documents read and, when
/// anything could not be read, the most JSON-like opening among the
/// documents the reading stopped at (judged within [`SNIFF_WINDOW`]).
///
/// Linear in the view: each attempt starts after the line holding the
/// previous attempt's error, and an error is never before anything that
/// attempt consumed, so no byte is parsed twice.
fn parse_lenient_sequence(text: &str) -> (Vec<JsonNode>, Option<JsonOpening>) {
    let bytes = text.as_bytes();
    let mut documents = Vec::new();
    let mut stopped_at: Option<JsonOpening> = None;
    let mut start = 0;
    while start < bytes.len() {
        // `text[start..]`: `start` is 0 or follows an ASCII `\n`.
        let segment = &text[start..];
        let mut stream = serde_json::Deserializer::from_str(segment).into_iter::<JsonNode>();
        // Not a `for` loop: the stream is read again on failure.
        let failure = loop {
            match stream.next() {
                None => break None,
                Some(Ok(document)) => documents.push(document),
                Some(Err(error)) => break Some((stream.byte_offset(), error)),
            }
        };
        let Some((failed_at, error)) = failure else {
            break;
        };
        let failed_at = start + failed_at.min(segment.len());
        stopped_at = stopped_at.max(Some(JsonOpening::of_window(&bytes[failed_at..])));
        let error_at = (start
            + offset_of_position(segment.as_bytes(), error.line(), error.column()))
        .max(failed_at);
        match memchr::memchr(b'\n', &bytes[error_at..]) {
            Some(newline) => start = error_at + newline + 1,
            None => break,
        }
    }
    (documents, stopped_at)
}

/// The byte offset of a 1-based `line` and byte `column` reported by
/// `serde_json`, clamped to `bytes`. Linear in the bytes before that line.
fn offset_of_position(bytes: &[u8], line: usize, column: usize) -> usize {
    let line_start = match line.checked_sub(2) {
        None => 0,
        Some(newlines) => memchr::memchr_iter(b'\n', bytes)
            .nth(newlines)
            .map_or(bytes.len(), |newline| newline + 1),
    };
    line_start.saturating_add(column).min(bytes.len())
}

fn is_json_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// The index of the first significant byte at or after `at`, skipping what
/// lenient parsers skip before and between tokens:
///
/// - whitespace: JSON whitespace, vertical tab, form feed, U+001C–U+001F
///   (Java `Character.isWhitespace`), and the UTF-8 forms of U+0085, U+00A0,
///   U+FEFF, U+2028 / U+2029 and the other Unicode space separators
///   (JSON5, .NET `char.IsWhiteSpace`); U+0000 when `nul_is_whitespace`
///   (Json.NET);
/// - comments: `//` and `#` to the end of the line (LF, CR, U+2028 or
///   U+2029 — JSON5, Gson lenient, Jackson YAML comments) and `/* */`;
/// - the `)]}'` (or `)]}',`) anti-XSSI prefix Gson's lenient reader strips.
///
/// `None` for an unterminated block comment, which no parser reads past. One
/// forward pass: the index only grows.
fn skip_insignificant(bytes: &[u8], mut at: usize, nul_is_whitespace: bool) -> Option<usize> {
    while let Some(rest) = bytes.get(at..) {
        let step = match rest {
            [b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C | 0x1C..=0x1F, ..] => 1,
            [0x00, ..] if nul_is_whitespace => 1,
            [0xC2, 0x85 | 0xA0, ..] => 2,
            [0xEF, 0xBB, 0xBF, ..]
            | [0xE2, 0x80, 0x80..=0x8A | 0xA8 | 0xA9 | 0xAF, ..]
            | [0xE2, 0x81, 0x9F, ..]
            | [0xE3, 0x80, 0x80, ..]
            | [0xE1, 0x9A, 0x80, ..] => 3,
            [b'/', b'/', ..] | [b'#', ..] => line_comment_length(rest),
            [b'/', b'*', tail @ ..] => memchr::memmem::find(tail, b"*/")? + 4,
            [b')', b']', b'}', b'\'', b',', ..] => 5,
            [b')', b']', b'}', b'\'', ..] => 4,
            _ => return Some(at),
        };
        at += step;
    }
    Some(bytes.len())
}

/// Length of a line comment at the start of `rest`, including the line
/// terminator that ends it (LF, CR, U+2028 or U+2029), or all of `rest`.
fn line_comment_length(rest: &[u8]) -> usize {
    let mut from = 0;
    while let Some(found) = memchr::memchr3(b'\n', b'\r', 0xE2, &rest[from..]) {
        let at = from + found;
        if rest[at] != 0xE2 {
            return at + 1;
        }
        if matches!(rest.get(at + 1..at + 3), Some([0x80, 0xA8 | 0xA9])) {
            return at + 3;
        }
        from = at + 1;
    }
    rest.len()
}

/// Bytes Gson's lenient reader takes as part of an unquoted name or value:
/// everything except structure, separators, comment starts, quotes and
/// whitespace.
fn is_unquoted_literal_byte(byte: u8) -> bool {
    !matches!(
        byte,
        b'{' | b'}'
            | b'['
            | b']'
            | b':'
            | b','
            | b'='
            | b';'
            | b'#'
            | b'/'
            | b'\\'
            | b'"'
            | b'\''
            | b' '
            | b'\t'
            | b'\n'
            | b'\r'
            | 0x0B
            | 0x0C
            | 0x00
    )
}

/// Whether a view opens like a JSON object or array as a parser — strict or
/// lenient — reads one. After whatever [`skip_insignificant`] skips, the view
/// must hold:
///
/// - `{` followed by a quoted member name, `}`, or an unquoted name (a run of
///   [`is_unquoted_literal_byte`], digits and `-` included: JSON5, Jackson
///   `ALLOW_UNQUOTED_FIELD_NAMES`, Gson lenient) and then `:` or `=`; or
/// - `[` followed by `]`, `{`, `[`, a quote, `-`, `+`, `.`, a digit, one of
///   `true` / `false` / `null` / `NaN` / `Infinity` ending at a delimiter or
///   at anything [`skip_insignificant`] skips, or an unquoted value followed
///   by `,` or `;` (Gson lenient).
///
/// This decides whether a view the WAF cannot parse is a document it failed
/// to inspect or simply not JSON. The second token is required so that text
/// which merely starts with a bracket (`[INFO] …`, `[true-story] …`,
/// `{{template}}`, `{amount}`), and the raw bytes of a UTF-16 / UTF-32
/// document (a NUL follows the bracket), are not taken for a JSON document;
/// their transcoded views are judged on their own.
fn opens_like_json_container(bytes: &[u8], nul_is_whitespace: bool) -> bool {
    let Some(open_at) = skip_insignificant(bytes, 0, nul_is_whitespace) else {
        return false;
    };
    let Some(&open) = bytes.get(open_at) else {
        return false;
    };
    if open != b'{' && open != b'[' {
        return false;
    }
    let Some(next_at) = skip_insignificant(bytes, open_at + 1, nul_is_whitespace) else {
        return false;
    };
    let rest = &bytes[next_at..];
    let Some(&next) = rest.first() else {
        return false;
    };
    if open == b'{' {
        return matches!(next, b'"' | b'\'' | b'}')
            || unquoted_literal_then(rest, nul_is_whitespace, b":=");
    }
    matches!(
        next,
        b'{' | b'[' | b']' | b'"' | b'\'' | b'-' | b'+' | b'.' | b'0'..=b'9'
    ) || opens_with_literal(rest, nul_is_whitespace)
        || unquoted_literal_then(rest, nul_is_whitespace, b",;")
}

/// `rest` starts with a non-empty unquoted literal followed, after anything
/// [`skip_insignificant`] skips, by one of `terminators`.
fn unquoted_literal_then(rest: &[u8], nul_is_whitespace: bool, terminators: &[u8]) -> bool {
    let length = rest
        .iter()
        .take_while(|byte| is_unquoted_literal_byte(**byte))
        .count();
    length > 0
        && skip_insignificant(rest, length, nul_is_whitespace)
            .and_then(|at| rest.get(at))
            .is_some_and(|byte| terminators.contains(byte))
}

/// `rest` starts with a JSON / JSON5 literal that ends at a delimiter or at
/// anything [`skip_insignificant`] skips, so `[true]`, `[NaN,…]` and
/// `[true<NBSP>,…]` count while `[true-story]` and `[nullify …]` do not.
fn opens_with_literal(rest: &[u8], nul_is_whitespace: bool) -> bool {
    [
        b"true".as_slice(),
        b"false".as_slice(),
        b"null".as_slice(),
        b"NaN".as_slice(),
        b"Infinity".as_slice(),
    ]
    .iter()
    .any(|literal| {
        rest.starts_with(literal)
            && match rest.get(literal.len()).copied() {
                None => true,
                Some(b',' | b']' | b'}' | b':' | b';') => true,
                Some(_) => skip_insignificant(rest, literal.len(), nul_is_whitespace)
                    .is_none_or(|at| at > literal.len()),
            }
    })
}

/// Whether a `Content-Type` declares a JSON document: base type `*/json` or
/// an RFC 6839 `+json` suffix, as the inspection gate maps them. Framed JSON
/// codecs (`application/grpc+json`, `application/connect+json`, …) match as
/// well; [`framed_json_messages`] takes a body that really is framed out of
/// this question before it is asked. Allocation-free.
pub(super) fn media_type_declares_json(content_type: Option<&str>) -> bool {
    let Some(subtype) = media_essence(content_type)
        .and_then(|essence| essence.split_once('/'))
        .map(|(_, subtype)| subtype.trim().as_bytes())
    else {
        return false;
    };
    subtype.eq_ignore_ascii_case(b"json") || ends_with_ignore_ascii_case(subtype, b"+json")
}

/// The base media type of a `Content-Type`, parameters and OWS stripped.
fn media_essence(content_type: Option<&str>) -> Option<&str> {
    Some(content_type?.split(';').next().unwrap_or("").trim())
}

fn ends_with_ignore_ascii_case(value: &[u8], suffix: &[u8]) -> bool {
    value
        .len()
        .checked_sub(suffix.len())
        .is_some_and(|at| value[at..].eq_ignore_ascii_case(suffix))
}

/// `application/connect+<codec>`: Connect streaming, whose body is
/// enveloped messages. (Connect unary uses the plain codec media type, such
/// as `application/json`, and an unframed body.)
fn is_connect_streaming_essence(essence: &str) -> bool {
    const PREFIX: &[u8] = b"application/connect+";
    let essence = essence.as_bytes();
    essence
        .get(..PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
        && essence.len() > PREFIX.len()
}

/// A body that genuinely is a framed RPC stream, identified by its exact
/// media type AND validated framing: the gRPC (`application/grpc[+codec]`),
/// gRPC-Web binary (`application/grpc-web[+codec]`) and Connect streaming
/// (`application/connect+codec`) envelopes of a flags byte and a 4-byte
/// big-endian length, covering the body exactly; or a gRPC-Web text body
/// (`application/grpc-web-text[+codec]`) that is entirely base64.
///
/// Returns the messages to inspect as JSON documents in place of the raw
/// body: each uncompressed message of a `+json` codec. A non-JSON codec,
/// a compressed message, or a gRPC-Web text body contributes none (those
/// bytes are not a JSON document under any reading). `None` when the body is
/// not such a stream — a look-alike media type, or framing that does not
/// validate — so it is judged as an ordinary body.
pub(super) fn framed_json_messages<'a>(
    content_type: Option<&str>,
    body: &'a [u8],
) -> Option<Vec<&'a [u8]>> {
    let content_type = content_type?;
    let essence = media_essence(Some(content_type))?;
    if crate::plugins::grpc_web::is_grpc_web_text(content_type) {
        let base64 = body
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/=\r\n".contains(byte));
        return base64.then(Vec::new);
    }
    let connect = is_connect_streaming_essence(essence);
    let framed = connect
        || crate::proxy::backend_dispatch::is_native_grpc_content_type(content_type.as_bytes())
        || crate::plugins::grpc_web::is_grpc_web_content_type(content_type);
    if !framed {
        return None;
    }
    // gRPC and gRPC-Web request frames: bit 0 is the compression flag.
    // Connect adds bit 1, end-of-stream.
    let allowed_flags: u8 = if connect { 0x03 } else { 0x01 };
    let json_codec = ends_with_ignore_ascii_case(essence.as_bytes(), b"+json");
    let mut messages = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let [flags, a, b, c, d, tail @ ..] = rest else {
            return None;
        };
        if flags & !allowed_flags != 0 {
            return None;
        }
        let length = usize::try_from(u32::from_be_bytes([*a, *b, *c, *d])).ok()?;
        let message = tail.get(..length)?;
        if json_codec && flags & 0x01 == 0 {
            messages.push(message);
        }
        rest = &tail[length..];
    }
    Some(messages)
}

/// Rewrite every `\u` escape that names an unpaired UTF-16 surrogate to
/// `\uFFFD`, leaving valid high-then-low pairs and every other byte as is.
/// Text with nothing to rewrite is borrowed.
///
/// Escapes are consumed left to right as whole units, so the `\\` in
/// `"\\ud800"` is one escape and the `ud800` after it stays literal text. A
/// backslash is only legal inside a string, so this walk sees exactly the
/// string escapes of any document that can parse.
fn replace_unpaired_surrogate_escapes(text: &str) -> Cow<'_, str> {
    const ESCAPE_LEN: usize = 6;
    let bytes = text.as_bytes();
    let mut repaired: Option<String> = None;
    let mut copied = 0;
    let mut at = 0;
    while let Some(offset) = bytes.get(at..).and_then(|rest| memchr::memchr(b'\\', rest)) {
        at += offset;
        let Some(unit) = unicode_escape(bytes, at) else {
            // Any other escape is the backslash and one character; skipping
            // both keeps `\\` from exposing a following `u`.
            at += 2;
            continue;
        };
        if (0xD800..=0xDBFF).contains(&unit)
            && unicode_escape(bytes, at + ESCAPE_LEN)
                .is_some_and(|low| (0xDC00..=0xDFFF).contains(&low))
        {
            at += 2 * ESCAPE_LEN;
            continue;
        }
        if (0xD800..=0xDFFF).contains(&unit) {
            let out = repaired.get_or_insert_with(|| String::with_capacity(text.len()));
            // `at` indexes an ASCII backslash and `copied` the byte after a
            // six-byte ASCII escape, so both are character boundaries.
            out.push_str(&text[copied..at]);
            out.push_str("\\uFFFD");
            copied = at + ESCAPE_LEN;
        }
        at += ESCAPE_LEN;
    }
    match repaired {
        Some(mut out) => {
            out.push_str(&text[copied..]);
            Cow::Owned(out)
        }
        None => Cow::Borrowed(text),
    }
}

/// The code unit of the `\uXXXX` escape starting at `at`, if one does.
fn unicode_escape(bytes: &[u8], at: usize) -> Option<u16> {
    let [b'\\', b'u', digits @ ..] = bytes.get(at..at + 6)? else {
        return None;
    };
    digits.iter().try_fold(0u16, |unit, &digit| {
        let value = (digit as char).to_digit(16)?;
        Some((unit << 4) | value as u16)
    })
}

/// Every node `path` reaches. A key segment follows every member with that
/// name, so duplicated members (at the leaf or on an enclosing object) all
/// contribute. Matched nodes at one depth are disjoint subtrees, so the result
/// never exceeds the document's node count.
pub(super) fn select<'a>(root: &'a JsonNode, path: &[JsonPathSegment]) -> Vec<&'a JsonNode> {
    let mut current = vec![root];
    for segment in path {
        let mut next = Vec::new();
        for node in current {
            match (segment, node) {
                (JsonPathSegment::Key(key), JsonNode::Object(members)) => next.extend(
                    members
                        .iter()
                        .filter(|(name, _)| name == key)
                        .map(|(_, value)| value),
                ),
                (JsonPathSegment::Index(index), JsonNode::Array(items)) => {
                    next.extend(items.get(*index));
                }
                _ => {}
            }
        }
        if next.is_empty() {
            return next;
        }
        current = next;
    }
    current
}

/// The strings a JSON-path matcher inspects for one selected node, each a
/// separate target (its own match and its own false-positive filtering).
///
/// A scalar yields one: a string's unescaped value or the canonical text of a
/// number / boolean / null. A container yields its compact JSON as a
/// last-wins parser reads it (the reading `serde_json::Value` gives, so a
/// rule that matched before still matches); when the subtree holds duplicated
/// members, also the first-wins reading and the duplicate-preserving text.
/// A rule hits if any reading matches, so a benign duplicate can neither break
/// an `equals` match nor let a filter suppress the reading that carries the
/// forbidden value.
pub(super) fn scan_texts(node: &JsonNode) -> Vec<Cow<'_, str>> {
    match node {
        JsonNode::Scalar(Value::String(value)) => vec![Cow::Borrowed(value.as_str())],
        JsonNode::Scalar(Value::Bool(value)) => {
            vec![Cow::Borrowed(if *value { "true" } else { "false" })]
        }
        JsonNode::Scalar(Value::Null) => vec![Cow::Borrowed("null")],
        JsonNode::Scalar(other) => vec![Cow::Owned(other.to_string())],
        JsonNode::Array(_) | JsonNode::Object(_) => {
            let render = |mode| serde_json::to_string(&Reading { node, mode }).ok();
            let Some(last) = render(Duplicates::Last) else {
                return Vec::new();
            };
            let Some(all) = render(Duplicates::All) else {
                return vec![Cow::Owned(last)];
            };
            // Equal only when the subtree has no duplicated member.
            if all == last {
                return vec![Cow::Owned(last)];
            }
            let mut texts = vec![Cow::Owned(last)];
            if let Some(first) = render(Duplicates::First)
                && !texts.iter().any(|text| *text == first)
            {
                texts.push(Cow::Owned(first));
            }
            texts.push(Cow::Owned(all));
            texts
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Duplicates {
    /// One member per name at its first position with its last value —
    /// `serde_json::Value` with `preserve_order`.
    Last,
    /// One member per name at its first position with its first value.
    First,
    /// Every member in source order.
    All,
}

/// Serializes `node` as one reading of its duplicated members, applied at
/// every depth (including objects nested inside arrays).
struct Reading<'a> {
    node: &'a JsonNode,
    mode: Duplicates,
}

impl Serialize for Reading<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.node {
            JsonNode::Scalar(value) => value.serialize(serializer),
            JsonNode::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for node in items {
                    seq.serialize_element(&Reading {
                        node,
                        mode: self.mode,
                    })?;
                }
                seq.end()
            }
            JsonNode::Object(members) if self.mode == Duplicates::All => {
                let mut map = serializer.serialize_map(Some(members.len()))?;
                for (name, node) in members {
                    map.serialize_entry(
                        name,
                        &Reading {
                            node,
                            mode: self.mode,
                        },
                    )?;
                }
                map.end()
            }
            JsonNode::Object(members) => {
                let mut kept: Vec<(&str, &JsonNode)> = Vec::with_capacity(members.len());
                let mut slots: HashMap<&str, usize> = HashMap::with_capacity(members.len());
                for (name, node) in members {
                    match slots.get(name.as_str()) {
                        Some(&slot) => {
                            if self.mode == Duplicates::Last {
                                kept[slot].1 = node;
                            }
                        }
                        None => {
                            slots.insert(name.as_str(), kept.len());
                            kept.push((name.as_str(), node));
                        }
                    }
                }
                let mut map = serializer.serialize_map(Some(kept.len()))?;
                for (name, node) in kept {
                    map.serialize_entry(
                        name,
                        &Reading {
                            node,
                            mode: self.mode,
                        },
                    )?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for JsonNode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NodeVisitor)
    }
}

struct NodeVisitor;

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = JsonNode;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<JsonNode, E> {
        Ok(JsonNode::Scalar(Value::Bool(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<JsonNode, E> {
        Ok(JsonNode::Scalar(Value::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<JsonNode, E> {
        Ok(JsonNode::Scalar(Value::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<JsonNode, E> {
        // Same mapping as `serde_json::Value`.
        Ok(JsonNode::Scalar(
            serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number),
        ))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<JsonNode, E> {
        Ok(JsonNode::Scalar(Value::String(value.to_owned())))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<JsonNode, E> {
        Ok(JsonNode::Scalar(Value::String(value)))
    }

    fn visit_unit<E: de::Error>(self) -> Result<JsonNode, E> {
        Ok(JsonNode::Scalar(Value::Null))
    }

    fn visit_none<E: de::Error>(self) -> Result<JsonNode, E> {
        Ok(JsonNode::Scalar(Value::Null))
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<JsonNode, D::Error> {
        JsonNode::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<JsonNode, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(JsonNode::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JsonNode, A::Error> {
        let mut members = Vec::new();
        while let Some((name, value)) = map.next_entry::<String, JsonNode>()? {
            members.push((name, value));
        }
        Ok(JsonNode::Object(members))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(body: &[u8], path: &[JsonPathSegment]) -> Vec<Vec<String>> {
        let view = parse(body);
        let [doc] = view.documents() else {
            panic!("expected exactly one JSON document");
        };
        select(doc, path)
            .into_iter()
            .map(|node| scan_texts(node).into_iter().map(Cow::into_owned).collect())
            .collect()
    }

    fn key(name: &str) -> JsonPathSegment {
        JsonPathSegment::Key(name.to_string())
    }

    #[test]
    fn duplicate_leaf_and_enclosing_members_are_all_selected() {
        let leaf = br#"{"user":{"bio":"first","bio":"last"}}"#;
        assert_eq!(
            texts(leaf, &[key("user"), key("bio")]),
            [["first"], ["last"]]
        );

        let enclosing = br#"{"user":{"bio":"first"},"user":{"bio":"last"}}"#;
        assert_eq!(
            texts(enclosing, &[key("user"), key("bio")]),
            [["first"], ["last"]]
        );

        // `b\u0069o` and `\u0075ser` are escaped spellings of `bio` / `user`.
        let escaped = br#"{"\u0075ser":{"b\u0069o":"first","bio":"last"}}"#;
        assert_eq!(
            texts(escaped, &[key("user"), key("bio")]),
            [["first"], ["last"]]
        );
    }

    #[test]
    fn container_without_duplicates_has_one_reading() {
        let body = br#"{"a":{"z":1,"y":[true,null,2.5]}}"#;
        assert_eq!(
            texts(body, &[key("a")]),
            [[r#"{"z":1,"y":[true,null,2.5]}"#]]
        );
    }

    #[test]
    fn container_with_duplicates_has_last_first_and_full_readings() {
        let body = br#"{"a":{"z":1,"y":[{"k":"p","k":"q"}],"z":"x"}}"#;
        assert_eq!(
            texts(body, &[key("a")]),
            [[
                r#"{"z":"x","y":[{"k":"q"}]}"#,
                r#"{"z":1,"y":[{"k":"p"}]}"#,
                r#"{"z":1,"y":[{"k":"p","k":"q"}],"z":"x"}"#,
            ]]
        );
    }

    #[test]
    fn index_segments_and_mismatched_shapes() {
        let body = br#"{"m":[{"c":"zero"},{"c":"one"}],"s":"text"}"#;
        assert_eq!(
            texts(body, &[key("m"), JsonPathSegment::Index(1), key("c")]),
            [["one"]]
        );
        assert!(texts(body, &[key("s"), key("x")]).is_empty());
        assert!(texts(body, &[key("m"), key("c")]).is_empty());
    }

    #[test]
    fn byte_order_mark_is_skipped_and_malformed_input_is_rejected() {
        assert_eq!(texts(b"\xEF\xBB\xBF{\"k\":\"v\"}", &[key("k")]), [["v"]]);
        assert_eq!(parse(b"{\"k\":").refused(), Some(JsonOpening::Yes));
        // The document before the trailing text is still read.
        let trailing = parse(b"{\"k\":1} trailing");
        assert_eq!(trailing.refused(), Some(JsonOpening::Yes));
        assert_eq!(trailing.documents().len(), 1);
        assert_eq!(parse(b"k=v").refused(), Some(JsonOpening::No));
        let blank = parse(b" \r\n");
        assert_eq!(blank.refused(), None);
        assert!(blank.documents().is_empty());
    }
}
