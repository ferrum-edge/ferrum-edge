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
//! UTF-8 / surrogate validation, member-name unescaping (a `\u`-escaped name
//! is the same member as its literal spelling) and 128-level recursion limit
//! are unchanged.

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

/// Parse one inspection view. A leading byte-order mark is skipped; anything
/// `serde_json` rejects yields `None`, exactly as the collapsed parse did.
pub(super) fn parse(bytes: &[u8]) -> Option<JsonNode> {
    let bytes = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
    serde_json::from_slice(bytes).ok()
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
        let doc = parse(body).expect("valid JSON");
        select(&doc, path)
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
        assert!(parse(b"{\"k\":").is_none());
        assert!(parse(b"{\"k\":1} trailing").is_none());
    }
}
