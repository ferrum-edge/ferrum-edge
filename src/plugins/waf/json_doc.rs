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
//! them, and a view that opens like a JSON object or array but still cannot
//! be read is reported as [`JsonView::Refused`] so the caller can fail closed
//! instead of treating it as having nothing to inspect.

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
pub(super) enum JsonView {
    /// One document: the strict parse accepted the view.
    Document(JsonNode),
    /// Every document of a view the strict parse refused but the lenient
    /// reading accepts: one, or several separated by whitespace (NDJSON, a
    /// leading scalar followed by an object, or a document followed by
    /// another that a first-value reader such as Jackson stops before).
    Documents(Vec<JsonNode>),
    /// Neither reading parses. `opening` says whether the view, or the
    /// document the lenient reading stopped at, opens like a JSON object or
    /// array (see [`opens_like_json_container`]).
    Refused { opening: JsonOpening },
    /// Empty, or JSON whitespace only.
    Blank,
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
    /// does not mark the body as unreadable JSON when another reading parsed.
    SkippingNul,
    /// It does, without skipping any NUL.
    Yes,
}

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
}

impl JsonView {
    /// The parsed documents, in source order; empty unless the view parsed.
    pub(super) fn documents(&self) -> &[JsonNode] {
        match self {
            JsonView::Document(document) => std::slice::from_ref(document),
            JsonView::Documents(documents) => documents,
            JsonView::Refused { .. } | JsonView::Blank => &[],
        }
    }
}

/// Parse one inspection view. A leading byte-order mark is skipped.
///
/// A view the strict parse accepts is parsed in place, with no copy and no
/// further work. When it is refused and its first byte can start a JSON value,
/// it is re-read the way lenient parsers read it: invalid UTF-8 decodes to
/// `U+FFFD`, every `\u` escape naming an unpaired surrogate (`\uD800`–`\uDFFF`
/// not forming a high-then-low pair) becomes `\uFFFD`, and every document of a
/// whitespace-separated sequence is read. Only that failure path copies the
/// view, and only when there is something to repair. A view that is still
/// refused — for example a number beyond the `f64` range, nesting deeper than
/// `serde_json`'s 128 levels, `NaN`, a comment, a trailing comma, a leading
/// form feed, or an unquoted member name — is [`JsonView::Refused`].
pub(super) fn parse(bytes: &[u8]) -> JsonView {
    let bytes = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
    if let Ok(document) = serde_json::from_slice(bytes) {
        return JsonView::Document(document);
    }
    let Some(&first) = bytes.iter().find(|byte| !is_json_whitespace(**byte)) else {
        return JsonView::Blank;
    };
    // `serde_json` only starts a document at one of these bytes; anything
    // else cannot be rescued by the lenient reading, so skip that pass.
    let mut stopped_at = JsonOpening::No;
    if matches!(
        first,
        b'{' | b'[' | b'"' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n'
    ) {
        let text = String::from_utf8_lossy(bytes);
        let repaired = replace_unpaired_surrogate_escapes(&text);
        match parse_document_sequence(&repaired) {
            Ok(documents) => return JsonView::Documents(documents),
            Err(offset) if offset > 0 => {
                stopped_at = JsonOpening::of(&repaired.as_bytes()[offset..]);
            }
            Err(_) => {}
        }
    }
    JsonView::Refused {
        opening: stopped_at.max(JsonOpening::of(bytes)),
    }
}

/// Every document of a whitespace-separated sequence. On failure, the
/// stream's byte offset when it failed — never past the start of the document
/// it stopped at, and `0` when no document parsed — so the caller can judge
/// that document. Each document is parsed once, so the cost stays linear in
/// the view.
fn parse_document_sequence(text: &str) -> Result<Vec<JsonNode>, usize> {
    let mut documents = Vec::new();
    let mut stream = serde_json::Deserializer::from_str(text).into_iter::<JsonNode>();
    // `while let`, not `for`: the stream is read again on failure.
    while let Some(document) = stream.next() {
        match document {
            Ok(document) => documents.push(document),
            Err(_) => return Err(stream.byte_offset()),
        }
    }
    if documents.is_empty() {
        return Err(0);
    }
    Ok(documents)
}

fn is_json_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// The index of the first significant byte at or after `at`, skipping what
/// lenient parsers skip between tokens: JSON whitespace, vertical tab and form
/// feed (JavaScript and JSON5 whitespace), the UTF-8 forms of U+00A0, U+FEFF,
/// U+2028 / U+2029 and the other Unicode space separators, U+0000 when
/// `nul_is_whitespace` (Json.NET), and `//` / `/* */` comments. `None` for an
/// unterminated block comment, which no parser reads past. One forward pass:
/// the index only grows.
fn skip_insignificant(bytes: &[u8], mut at: usize, nul_is_whitespace: bool) -> Option<usize> {
    while let Some(rest) = bytes.get(at..) {
        let step = match rest {
            [b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C, ..] => 1,
            [0x00, ..] if nul_is_whitespace => 1,
            [0xC2, 0xA0, ..] => 2,
            [0xEF, 0xBB, 0xBF, ..]
            | [0xE2, 0x80, 0x80..=0x8A | 0xA8 | 0xA9 | 0xAF, ..]
            | [0xE2, 0x81, 0x9F, ..]
            | [0xE3, 0x80, 0x80, ..]
            | [0xE1, 0x9A, 0x80, ..] => 3,
            [b'/', b'/', ..] => {
                memchr::memchr2(b'\n', b'\r', rest).map_or(rest.len(), |end| end + 1)
            }
            [b'/', b'*', tail @ ..] => memchr::memmem::find(tail, b"*/")? + 4,
            _ => return Some(at),
        };
        at += step;
    }
    Some(bytes.len())
}

/// Whether a view opens like a JSON object or array as a parser — strict or
/// lenient — reads one. After an optional `)]}'` (or `)]}',`) anti-XSSI
/// prefix and whatever [`skip_insignificant`] skips, the view must hold `{`
/// followed by a quoted member name, `}`, or an unquoted identifier and `:`
/// (JSON5, Jackson `ALLOW_UNQUOTED_FIELD_NAMES`, Gson lenient), or `[`
/// followed by `]`, a value start (`{ [ " ' - + .` or a digit), or one of
/// `true` / `false` / `null` / `NaN` / `Infinity` ending at a delimiter.
///
/// This decides whether a view the WAF cannot parse is a document it failed
/// to inspect or simply not JSON. The second token is required so that text
/// which merely starts with a bracket (`[INFO] …`, `[true-story] …`,
/// `{{template}}`), and the raw bytes of a UTF-16 / UTF-32 document (a NUL
/// follows the bracket), are not taken for a JSON document; their transcoded
/// views are judged on their own. One bounded forward pass over the opening.
fn opens_like_json_container(bytes: &[u8], nul_is_whitespace: bool) -> bool {
    let start = match bytes.strip_prefix(b")]}'") {
        Some([b',', ..]) => 5,
        Some(_) => 4,
        None => 0,
    };
    let Some(open_at) = skip_insignificant(bytes, start, nul_is_whitespace) else {
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
            || opens_with_unquoted_member_name(rest, nul_is_whitespace);
    }
    matches!(
        next,
        b'{' | b'[' | b']' | b'"' | b'\'' | b'-' | b'+' | b'.' | b'0'..=b'9'
    ) || opens_with_literal(rest)
}

/// `rest` starts with an identifier (not starting with a digit; ASCII
/// letters, digits, `_`, `$`, or any non-ASCII byte) followed by `:`.
fn opens_with_unquoted_member_name(rest: &[u8], nul_is_whitespace: bool) -> bool {
    let is_identifier_byte =
        |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80;
    let length = rest
        .iter()
        .take_while(|byte| is_identifier_byte(**byte))
        .count();
    if length == 0 || rest[0].is_ascii_digit() {
        return false;
    }
    skip_insignificant(rest, length, nul_is_whitespace)
        .is_some_and(|at| rest.get(at) == Some(&b':'))
}

/// `rest` starts with a JSON / JSON5 literal that ends at a delimiter, so
/// `[true]` and `[NaN,…]` count while `[true-story]` and `[nullify …]` do not.
fn opens_with_literal(rest: &[u8]) -> bool {
    [
        b"true".as_slice(),
        b"false".as_slice(),
        b"null".as_slice(),
        b"NaN".as_slice(),
        b"Infinity".as_slice(),
    ]
    .iter()
    .any(|literal| {
        rest.strip_prefix(*literal).is_some_and(|after| {
            after.first().is_none_or(|&byte| {
                matches!(
                    byte,
                    b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C | b',' | b']' | b'}' | b'/'
                )
            })
        })
    })
}

/// Whether a `Content-Type` declares a JSON document: base type `*/json` or
/// an RFC 6839 `+json` suffix, as the inspection gate maps them. The gRPC
/// JSON codecs (`application/grpc+json`, `application/grpc-web+json`) are
/// excluded: their bodies are length-prefixed frames, not a JSON document.
/// Allocation-free.
pub(super) fn media_type_declares_json(content_type: Option<&str>) -> bool {
    let Some(subtype) = media_subtype(content_type) else {
        return false;
    };
    if subtype_is_grpc(subtype) {
        return false;
    }
    subtype.eq_ignore_ascii_case(b"json")
        || subtype
            .len()
            .checked_sub(5)
            .is_some_and(|at| subtype[at..].eq_ignore_ascii_case(b"+json"))
}

/// Whether a `Content-Type` names a gRPC framing (`application/grpc`,
/// `application/grpc+json`, `application/grpc-web+json`, …), whose body is
/// length-prefixed frames. Allocation-free.
pub(super) fn media_type_is_grpc(content_type: Option<&str>) -> bool {
    media_subtype(content_type).is_some_and(subtype_is_grpc)
}

fn subtype_is_grpc(subtype: &[u8]) -> bool {
    subtype
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"grpc"))
}

/// The subtype of a `Content-Type`'s base media type, parameters stripped.
fn media_subtype(content_type: Option<&str>) -> Option<&[u8]> {
    let base = content_type?.split(';').next().unwrap_or("").trim();
    let (_, subtype) = base.split_once('/')?;
    Some(subtype.trim().as_bytes())
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
        assert!(matches!(
            parse(b"{\"k\":"),
            JsonView::Refused {
                opening: JsonOpening::Yes
            }
        ));
        assert!(matches!(
            parse(b"{\"k\":1} trailing"),
            JsonView::Refused {
                opening: JsonOpening::Yes
            }
        ));
        assert!(matches!(
            parse(b"k=v"),
            JsonView::Refused {
                opening: JsonOpening::No
            }
        ));
        assert!(matches!(parse(b" \r\n"), JsonView::Blank));
    }
}
