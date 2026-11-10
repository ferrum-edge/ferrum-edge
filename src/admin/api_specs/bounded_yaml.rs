//! Bounded YAML composition and alias expansion for API-spec ingestion.
//!
//! Parses YAML through libyaml events into an intermediate graph that preserves
//! alias edges, then materializes a `serde_json::Value` under strict
//! node / depth / alias-reference / expanded-byte / work budgets with cycle
//! and undefined-alias detection. Expansion never shares JSON subtrees across
//! alias sites, so exponential alias bombs fail closed before allocation grows
//! unboundedly.

use serde_json::map::Entry;
use serde_json::{Map, Number, Value};
use std::collections::{HashMap, HashSet};
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::slice;
// Keep the conventional `sys` spelling for the raw FFI surface; every call is
// still contained in an explicitly documented unsafe block.
#[allow(clippy::unsafe_removed_from_name)]
use unsafe_libyaml as sys;

/// Maximum nesting depth while composing and expanding YAML documents.
pub(crate) const MAX_YAML_DEPTH: usize = 128;

/// Maximum number of alias edges followed during expansion.
pub(crate) const MAX_YAML_ALIAS_REFERENCES: usize = 500_000;

/// Fail-closed upper bound on the compact JSON representation of the expanded
/// tree (`serde_json` encoding), including string/key escaping and structural
/// punctuation. Matches the public 32 MiB expanded-representation ceiling.
pub(crate) const MAX_YAML_EXPANDED_BYTES: usize = 32 * 1024 * 1024;

/// Maximum composition/expansion steps (event processing + node visits).
pub(crate) const MAX_YAML_EXPANSION_WORK: usize = 2_000_000;

/// Errors from bounded YAML parse/expand. Messages are field-oriented and must
/// never echo secret scalar payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BoundedYamlError {
    Parse(String),
    UndefinedAlias { name: String },
    DuplicateAnchor { name: String },
    Cycle { anchor: String },
    DepthExceeded,
    NodeLimitExceeded,
    AliasReferenceLimitExceeded,
    ExpandedByteLimitExceeded,
    WorkLimitExceeded,
    UnrepresentableMappingKey,
    DuplicateMappingKey,
    UnsupportedTag { tag: String },
    EmptyDocument,
    NonFiniteNumber,
}

impl BoundedYamlError {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::Parse(msg) => format!("YAML parse error: {msg}"),
            Self::UndefinedAlias { .. } => "undefined YAML alias".to_string(),
            Self::DuplicateAnchor { .. } => "duplicate YAML anchor".to_string(),
            Self::Cycle { .. } => "YAML alias cycle detected during expansion".to_string(),
            Self::DepthExceeded => "YAML document exceeds nesting depth limit".to_string(),
            Self::NodeLimitExceeded => {
                "YAML document exceeds expanded node limit; reduce nesting or alias reuse"
                    .to_string()
            }
            Self::AliasReferenceLimitExceeded => {
                "YAML document exceeds alias reference limit; reduce alias reuse".to_string()
            }
            Self::ExpandedByteLimitExceeded => {
                "YAML document exceeds expanded byte limit; reduce alias reuse or document size"
                    .to_string()
            }
            Self::WorkLimitExceeded => {
                "YAML document exceeds expansion work limit; reduce alias reuse or nesting"
                    .to_string()
            }
            Self::UnrepresentableMappingKey => {
                "YAML mapping keys must be scalars representable as JSON object keys".to_string()
            }
            Self::DuplicateMappingKey => "YAML mapping contains a duplicate key".to_string(),
            // Tags are supplied by the caller. Keep diagnostics actionable
            // without reflecting arbitrary tag text into an admin response.
            Self::UnsupportedTag { .. } => "unsupported YAML tag in API specs".to_string(),
            Self::EmptyDocument => "YAML document is empty".to_string(),
            Self::NonFiniteNumber => {
                "YAML non-finite numbers are not representable in JSON".to_string()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScalarStyle {
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Literal,
    Folded,
}

#[derive(Debug)]
enum NodeKind {
    Scalar {
        value: String,
        style: ScalarStyle,
        tag: Option<String>,
    },
    Sequence(Vec<usize>),
    Mapping(Vec<(usize, usize)>),
    /// Alias edge preserved until budgeted expansion.
    Alias {
        target: usize,
        name: String,
    },
}

struct Document {
    nodes: Vec<NodeKind>,
    /// Anchor name → node index (registered when the anchored node is allocated).
    anchors: HashMap<String, usize>,
    /// Node index → first anchor name that pointed at it (for cycle diagnostics).
    anchor_names: HashMap<usize, String>,
    root: Option<usize>,
    /// Event-processing work already charged while composing this graph.
    /// Expansion continues from the same counter so the documented work limit
    /// is cumulative rather than independently available to both phases.
    composition_work: usize,
}

struct Budgets {
    max_nodes: usize,
    nodes: usize,
    depth: usize,
    max_depth: usize,
    alias_refs: usize,
    max_alias_refs: usize,
    bytes: usize,
    max_bytes: usize,
    work: usize,
    max_work: usize,
}

impl Budgets {
    fn charge_work(&mut self) -> Result<(), BoundedYamlError> {
        self.work = self.work.saturating_add(1);
        if self.work > self.max_work {
            return Err(BoundedYamlError::WorkLimitExceeded);
        }
        Ok(())
    }

    fn enter_depth(&mut self) -> Result<(), BoundedYamlError> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > self.max_depth {
            return Err(BoundedYamlError::DepthExceeded);
        }
        Ok(())
    }

    fn leave_depth(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn charge_node(&mut self) -> Result<(), BoundedYamlError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.max_nodes {
            return Err(BoundedYamlError::NodeLimitExceeded);
        }
        Ok(())
    }

    fn charge_bytes(&mut self, n: usize) -> Result<(), BoundedYamlError> {
        self.bytes = self.bytes.saturating_add(n);
        if self.bytes > self.max_bytes {
            return Err(BoundedYamlError::ExpandedByteLimitExceeded);
        }
        Ok(())
    }

    fn charge_alias(&mut self) -> Result<(), BoundedYamlError> {
        self.alias_refs = self.alias_refs.saturating_add(1);
        if self.alias_refs > self.max_alias_refs {
            return Err(BoundedYamlError::AliasReferenceLimitExceeded);
        }
        Ok(())
    }
}

/// Parse `body` as a single YAML document and expand aliases into JSON under
/// the given node budget (and the module's depth/alias/byte/work caps).
pub(crate) fn parse_yaml_to_json(body: &[u8], max_nodes: usize) -> Result<Value, BoundedYamlError> {
    let document = compose_document(body, max_nodes)?;
    let root = document.root.ok_or(BoundedYamlError::EmptyDocument)?;
    let mut budgets = Budgets {
        max_nodes,
        nodes: 0,
        depth: 0,
        max_depth: MAX_YAML_DEPTH,
        alias_refs: 0,
        max_alias_refs: MAX_YAML_ALIAS_REFERENCES,
        bytes: 0,
        max_bytes: MAX_YAML_EXPANDED_BYTES,
        work: document.composition_work,
        max_work: MAX_YAML_EXPANSION_WORK,
    };
    let mut expanding = HashSet::new();
    expand_node(&document, root, &mut budgets, &mut expanding)
}

// ---------------------------------------------------------------------------
// Composition (event stream → alias-preserving graph)
// ---------------------------------------------------------------------------

enum Frame {
    Sequence {
        node: usize,
    },
    Mapping {
        node: usize,
        pending_key: Option<usize>,
    },
}

fn compose_document(body: &[u8], max_nodes: usize) -> Result<Document, BoundedYamlError> {
    let mut parser = Parser::new(body)?;
    let mut document = Document {
        nodes: Vec::new(),
        anchors: HashMap::new(),
        anchor_names: HashMap::new(),
        root: None,
        composition_work: 0,
    };
    let mut stack: Vec<Frame> = Vec::new();
    let mut work = 0usize;
    let mut seen_document = false;
    let mut finished_document = false;

    loop {
        work = work.saturating_add(1);
        if work > MAX_YAML_EXPANSION_WORK {
            return Err(BoundedYamlError::WorkLimitExceeded);
        }
        if stack.len() > MAX_YAML_DEPTH {
            return Err(BoundedYamlError::DepthExceeded);
        }

        let event = parser.next()?;
        match event {
            Event::StreamStart => {}
            Event::DocumentStart => {
                if seen_document {
                    return Err(BoundedYamlError::Parse(
                        "multi-document YAML streams are not supported in API specs".to_string(),
                    ));
                }
                seen_document = true;
            }
            Event::StreamEnd => {
                if !stack.is_empty() || (seen_document && !finished_document) {
                    return Err(BoundedYamlError::Parse(
                        "unexpected stream end inside YAML document".to_string(),
                    ));
                }
                break;
            }
            Event::DocumentEnd => {
                if !stack.is_empty() {
                    return Err(BoundedYamlError::Parse(
                        "unexpected document end inside collection".to_string(),
                    ));
                }
                finished_document = true;
            }
            Event::Alias { name } => {
                if finished_document {
                    return Err(BoundedYamlError::Parse(
                        "content after document end".to_string(),
                    ));
                }
                let target = document
                    .anchors
                    .get(&name)
                    .copied()
                    .ok_or_else(|| BoundedYamlError::UndefinedAlias { name: name.clone() })?;
                let id = alloc_node(
                    &mut document,
                    max_nodes,
                    NodeKind::Alias {
                        target,
                        name: name.clone(),
                    },
                )?;
                attach_child(&mut document, &mut stack, id)?;
            }
            Event::Scalar {
                anchor,
                tag,
                value,
                style,
            } => {
                if finished_document {
                    return Err(BoundedYamlError::Parse(
                        "content after document end".to_string(),
                    ));
                }
                let id = alloc_node(
                    &mut document,
                    max_nodes,
                    NodeKind::Scalar { value, style, tag },
                )?;
                register_anchor(&mut document, anchor, id)?;
                attach_child(&mut document, &mut stack, id)?;
            }
            Event::SequenceStart { anchor, tag } => {
                if finished_document {
                    return Err(BoundedYamlError::Parse(
                        "content after document end".to_string(),
                    ));
                }
                validate_collection_tag(tag.as_deref(), "tag:yaml.org,2002:seq")?;
                let id = alloc_node(&mut document, max_nodes, NodeKind::Sequence(Vec::new()))?;
                // Register before children so self-referential aliases resolve.
                register_anchor(&mut document, anchor, id)?;
                attach_child(&mut document, &mut stack, id)?;
                stack.push(Frame::Sequence { node: id });
            }
            Event::SequenceEnd => match stack.pop() {
                Some(Frame::Sequence { .. }) => {}
                _ => {
                    return Err(BoundedYamlError::Parse(
                        "unexpected sequence end".to_string(),
                    ));
                }
            },
            Event::MappingStart { anchor, tag } => {
                if finished_document {
                    return Err(BoundedYamlError::Parse(
                        "content after document end".to_string(),
                    ));
                }
                validate_collection_tag(tag.as_deref(), "tag:yaml.org,2002:map")?;
                let id = alloc_node(&mut document, max_nodes, NodeKind::Mapping(Vec::new()))?;
                register_anchor(&mut document, anchor, id)?;
                attach_child(&mut document, &mut stack, id)?;
                stack.push(Frame::Mapping {
                    node: id,
                    pending_key: None,
                });
            }
            Event::MappingEnd => match stack.pop() {
                Some(Frame::Mapping {
                    pending_key: None, ..
                }) => {}
                Some(Frame::Mapping {
                    pending_key: Some(_),
                    ..
                }) => {
                    return Err(BoundedYamlError::Parse(
                        "mapping ended with unpaired key".to_string(),
                    ));
                }
                _ => {
                    return Err(BoundedYamlError::Parse(
                        "unexpected mapping end".to_string(),
                    ));
                }
            },
        }
    }

    if document.root.is_none() {
        return Err(BoundedYamlError::EmptyDocument);
    }
    document.composition_work = work;
    Ok(document)
}

fn validate_collection_tag(
    tag: Option<&str>,
    expected_core_tag: &str,
) -> Result<(), BoundedYamlError> {
    match tag {
        None | Some("!") => Ok(()),
        Some(tag) if tag == expected_core_tag => Ok(()),
        Some(tag) => Err(BoundedYamlError::UnsupportedTag {
            tag: tag.to_owned(),
        }),
    }
}

fn alloc_node(
    document: &mut Document,
    max_nodes: usize,
    kind: NodeKind,
) -> Result<usize, BoundedYamlError> {
    if document.nodes.len() >= max_nodes {
        return Err(BoundedYamlError::NodeLimitExceeded);
    }
    let id = document.nodes.len();
    document.nodes.push(kind);
    Ok(id)
}

fn register_anchor(
    document: &mut Document,
    anchor: Option<String>,
    id: usize,
) -> Result<(), BoundedYamlError> {
    let Some(name) = anchor else {
        return Ok(());
    };
    if document.anchors.contains_key(&name) {
        return Err(BoundedYamlError::DuplicateAnchor { name });
    }
    document.anchors.insert(name.clone(), id);
    document.anchor_names.entry(id).or_insert(name);
    Ok(())
}

fn attach_child(
    document: &mut Document,
    stack: &mut [Frame],
    child: usize,
) -> Result<(), BoundedYamlError> {
    let Some(frame) = stack.last_mut() else {
        if document.root.is_some() {
            return Err(BoundedYamlError::Parse(
                "multiple top-level YAML values are not supported".to_string(),
            ));
        }
        document.root = Some(child);
        return Ok(());
    };
    match frame {
        Frame::Sequence { node } => {
            let node = *node;
            match document.nodes.get_mut(node) {
                Some(NodeKind::Sequence(items)) => {
                    items.push(child);
                    Ok(())
                }
                _ => Err(BoundedYamlError::Parse(
                    "internal sequence frame mismatch".to_string(),
                )),
            }
        }
        Frame::Mapping { node, pending_key } => {
            if let Some(key) = *pending_key {
                let node = *node;
                match document.nodes.get_mut(node) {
                    Some(NodeKind::Mapping(pairs)) => {
                        pairs.push((key, child));
                        *pending_key = None;
                        Ok(())
                    }
                    _ => Err(BoundedYamlError::Parse(
                        "internal mapping frame mismatch".to_string(),
                    )),
                }
            } else {
                *pending_key = Some(child);
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Expansion (alias graph → JSON) with budgets + cycle detection
// ---------------------------------------------------------------------------

fn expand_node(
    document: &Document,
    id: usize,
    budgets: &mut Budgets,
    expanding: &mut HashSet<usize>,
) -> Result<Value, BoundedYamlError> {
    budgets.charge_work()?;
    // Track every node on the expansion stack — including Alias edges — so
    // self-refs, collection cycles, and alias-only mutual cycles all fail
    // closed with Cycle rather than relying solely on the work budget.
    if !expanding.insert(id) {
        let anchor = document
            .anchor_names
            .get(&id)
            .cloned()
            .unwrap_or_else(|| id.to_string());
        return Err(BoundedYamlError::Cycle { anchor });
    }
    let result = expand_node_inner(document, id, budgets, expanding);
    expanding.remove(&id);
    result
}

fn expand_node_inner(
    document: &Document,
    id: usize,
    budgets: &mut Budgets,
    expanding: &mut HashSet<usize>,
) -> Result<Value, BoundedYamlError> {
    let kind = document
        .nodes
        .get(id)
        .ok_or_else(|| BoundedYamlError::Parse("internal node index out of range".to_string()))?;

    match kind {
        NodeKind::Alias { target, name } => {
            budgets.charge_alias()?;
            // Fast path: alias into a collection/alias already on the stack.
            if expanding.contains(target) {
                let anchor = document
                    .anchor_names
                    .get(target)
                    .cloned()
                    .unwrap_or_else(|| name.clone());
                return Err(BoundedYamlError::Cycle { anchor });
            }
            expand_node(document, *target, budgets, expanding)
        }
        NodeKind::Scalar { value, style, tag } => {
            budgets.charge_node()?;
            let json = scalar_to_json(value, *style, tag.as_deref())?;
            charge_value_bytes(budgets, &json)?;
            Ok(json)
        }
        NodeKind::Sequence(items) => {
            budgets.enter_depth()?;
            budgets.charge_node()?;
            // Compact JSON `[...]` framing. The per-element `+1` below is a
            // trailing-comma overestimate and therefore fail-closed.
            budgets.charge_bytes(2)?;
            let mut out = Vec::with_capacity(items.len());
            for child in items {
                budgets.charge_bytes(1)?;
                out.push(expand_node(document, *child, budgets, expanding)?);
            }
            budgets.leave_depth();
            Ok(Value::Array(out))
        }
        NodeKind::Mapping(pairs) => {
            budgets.enter_depth()?;
            budgets.charge_node()?;
            // Compact JSON `{...}` framing. Key string/escaping bytes are
            // charged when the key scalar expands; `:` / `,` are charged here
            // (trailing-comma overestimate, fail-closed).
            budgets.charge_bytes(2)?;
            let mut map = Map::new();
            let mut merges: Vec<Value> = Vec::new();
            let mut saw_merge_spelling = false;
            for (key_id, value_id) in pairs {
                let key_value = expand_node(document, *key_id, budgets, expanding)?;
                let key = json_object_key(key_value, budgets)?;
                if (key == "<<" && saw_merge_spelling) || (key != "<<" && map.contains_key(&key)) {
                    return Err(BoundedYamlError::DuplicateMappingKey);
                }
                saw_merge_spelling |= key == "<<";
                let value = expand_node(document, *value_id, budgets, expanding)?;
                if is_yaml_merge_key(document, *key_id) {
                    collect_merge_sources(value, &mut merges)?;
                } else {
                    budgets.charge_bytes(2)?;
                    map.insert(key, value);
                }
            }
            // YAML 1.1 merge keys: earlier sequence entries take precedence
            // over later ones, while explicit keys always take precedence over
            // every merged value.
            for merge in merges {
                let Value::Object(merge_map) = merge else {
                    return Err(BoundedYamlError::Parse(
                        "YAML merge key '<<' must expand to a mapping or sequence of mappings"
                            .to_string(),
                    ));
                };
                for (k, v) in merge_map {
                    // Charge the `:` / `,` framing only for a merged pair that
                    // actually lands in the output, so the byte budget stays a
                    // true upper bound on the compact JSON encoding.
                    if let Entry::Vacant(slot) = map.entry(k) {
                        budgets.charge_bytes(2)?;
                        slot.insert(v);
                    }
                }
            }
            budgets.leave_depth();
            Ok(Value::Object(map))
        }
    }
}

/// Render an expanded YAML mapping key as its JSON object-key text.
///
/// The pre-`bounded_yaml` ingestion path converted `serde_yaml::Value` through
/// `serde_json::to_value`, whose map-key serializer stringifies scalar numbers
/// and booleans. OpenAPI YAML routinely leaves those keys unquoted
/// (`responses:` / `200:` / `description: ok`), and specs admitted that way are
/// already stored, so backup restore re-parses them through this module —
/// rejecting them here would both break a common idiom and strand existing
/// rows. Null and collection keys stay rejected exactly as `to_value` rejected
/// them.
fn json_object_key(value: Value, budgets: &mut Budgets) -> Result<String, BoundedYamlError> {
    // A number/bool scalar was charged as its bare JSON text when it expanded;
    // as a key it also pays the two surrounding quotes. Neither spelling can
    // contain a character that JSON string escaping would widen.
    match value {
        Value::String(text) => Ok(text),
        Value::Number(number) => {
            budgets.charge_bytes(2)?;
            Ok(number.to_string())
        }
        Value::Bool(flag) => {
            budgets.charge_bytes(2)?;
            Ok(if flag { "true" } else { "false" }.to_string())
        }
        Value::Null | Value::Array(_) | Value::Object(_) => {
            Err(BoundedYamlError::UnrepresentableMappingKey)
        }
    }
}

fn is_yaml_merge_key(document: &Document, id: usize) -> bool {
    matches!(
        document.nodes.get(id),
        Some(NodeKind::Scalar {
            value,
            style: ScalarStyle::Plain,
            tag: None,
        }) if value == "<<"
    ) || matches!(
        document.nodes.get(id),
        Some(NodeKind::Scalar {
            value,
            tag: Some(tag),
            ..
        }) if value == "<<" && tag == "tag:yaml.org,2002:merge"
    )
}

fn collect_merge_sources(value: Value, out: &mut Vec<Value>) -> Result<(), BoundedYamlError> {
    match value {
        Value::Object(_) => {
            out.push(value);
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::Object(_) => out.push(item),
                    _ => {
                        return Err(BoundedYamlError::Parse(
                            "YAML merge key '<<' sequence entries must be mappings".to_string(),
                        ));
                    }
                }
            }
            Ok(())
        }
        _ => Err(BoundedYamlError::Parse(
            "YAML merge key '<<' must expand to a mapping or sequence of mappings".to_string(),
        )),
    }
}

fn charge_value_bytes(budgets: &mut Budgets, value: &Value) -> Result<(), BoundedYamlError> {
    match value {
        Value::Null => budgets.charge_bytes(4),
        Value::Bool(true) => budgets.charge_bytes(4),
        Value::Bool(false) => budgets.charge_bytes(5),
        Value::Number(n) => budgets.charge_bytes(n.to_string().len()),
        Value::String(s) => budgets.charge_bytes(json_string_serialized_len(s)),
        // Containers charge framing/separators while expanding children.
        Value::Array(_) | Value::Object(_) => Ok(()),
    }
}

/// Exact byte length of a string after `serde_json` quoting/escaping.
///
/// Expanded-byte accounting must bound the compact representation that
/// `serde_json::to_vec` will emit. Counting decoded UTF-8 alone underestimates
/// quotes, backslashes, and control characters by up to six bytes each, which
/// alias expansion can amplify past the public 32 MiB ceiling. Kept
/// allocation-free (no scratch buffer) to avoid admin-path memory spikes.
/// Logic mirrors `extractor::json_string_serialized_len`.
fn json_string_serialized_len(value: &str) -> usize {
    value.chars().fold(2usize, |bytes, character| {
        let encoded = match character {
            '"' | '\\' | '\u{0008}' | '\u{0009}' | '\u{000a}' | '\u{000c}' | '\u{000d}' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8(),
        };
        bytes.saturating_add(encoded)
    })
}

fn scalar_to_json(
    value: &str,
    style: ScalarStyle,
    tag: Option<&str>,
) -> Result<Value, BoundedYamlError> {
    if let Some(tag) = tag {
        if tag == "tag:yaml.org,2002:str"
            || tag == "!"
            || (tag == "tag:yaml.org,2002:merge" && value == "<<")
        {
            return Ok(Value::String(value.to_owned()));
        }
        if tag == "tag:yaml.org,2002:null" {
            return if parse_null(value.as_bytes()).is_some() {
                Ok(Value::Null)
            } else {
                Err(BoundedYamlError::Parse("invalid !!null scalar".to_string()))
            };
        }
        if tag == "tag:yaml.org,2002:bool" {
            return parse_bool(value)
                .map(Value::Bool)
                .ok_or_else(|| BoundedYamlError::Parse("invalid !!bool scalar".to_string()));
        }
        if tag == "tag:yaml.org,2002:int" {
            return int_to_json(value)
                .ok_or_else(|| BoundedYamlError::Parse("invalid !!int scalar".to_string()));
        }
        if tag == "tag:yaml.org,2002:float" {
            return float_to_json(value);
        }
        // Non-core / local tags are not representable in OpenAPI JSON.
        return Err(BoundedYamlError::UnsupportedTag {
            tag: tag.to_owned(),
        });
    }

    if style == ScalarStyle::Plain {
        return untagged_plain_scalar(value);
    }
    Ok(Value::String(value.to_owned()))
}

fn untagged_plain_scalar(value: &str) -> Result<Value, BoundedYamlError> {
    if value.is_empty() || parse_null(value.as_bytes()).is_some() {
        return Ok(Value::Null);
    }
    if let Some(b) = parse_bool(value) {
        return Ok(Value::Bool(b));
    }
    if let Some(n) = int_to_json(value) {
        return Ok(n);
    }
    // Do not silently round an integer that is syntactically valid YAML but
    // outside serde_json's exact i64/u64 representation. Falling through to
    // f64 would accept a different value from the one the operator supplied.
    if looks_like_yaml_integer(value) {
        return Err(BoundedYamlError::Parse(
            "YAML integer is outside the exact JSON numeric range".to_string(),
        ));
    }
    if !digits_but_not_number(value)
        && let Some(n) = parse_f64(value)
    {
        return number_from_f64(n);
    }
    // Rust's finite f64 parser returns infinity for a syntactically numeric
    // exponent outside its range (for example `1e400`). That is still a YAML
    // number, not a string. Reject it exactly like `.inf` rather than silently
    // changing the operator's scalar type at the JSON boundary.
    if yaml_float_overflows_finite_range(value) {
        return Err(BoundedYamlError::NonFiniteNumber);
    }
    Ok(Value::String(value.to_owned()))
}

fn int_to_json(value: &str) -> Option<Value> {
    if let Some(n) = parse_unsigned_int(value, u64::from_str_radix) {
        return Some(Value::Number(Number::from(n)));
    }
    if let Some(n) = parse_negative_int(value, i64::from_str_radix) {
        return Some(Value::Number(Number::from(n)));
    }
    None
}

fn float_to_json(value: &str) -> Result<Value, BoundedYamlError> {
    let Some(n) = parse_f64(value) else {
        return Err(BoundedYamlError::Parse(
            "invalid !!float scalar".to_string(),
        ));
    };
    number_from_f64(n)
}

fn number_from_f64(n: f64) -> Result<Value, BoundedYamlError> {
    Number::from_f64(n)
        .map(Value::Number)
        .ok_or(BoundedYamlError::NonFiniteNumber)
}

fn parse_null(scalar: &[u8]) -> Option<()> {
    match scalar {
        b"null" | b"Null" | b"NULL" | b"~" => Some(()),
        _ => None,
    }
}

fn parse_bool(scalar: &str) -> Option<bool> {
    match scalar {
        "true" | "True" | "TRUE" => Some(true),
        "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

fn parse_unsigned_int<T>(
    scalar: &str,
    from_str_radix: fn(&str, radix: u32) -> Result<T, std::num::ParseIntError>,
) -> Option<T> {
    let unpositive = scalar.strip_prefix('+').unwrap_or(scalar);
    if let Some(rest) = unpositive.strip_prefix("0x") {
        if rest.starts_with(['+', '-']) {
            return None;
        }
        return from_str_radix(rest, 16).ok();
    }
    if let Some(rest) = unpositive.strip_prefix("0o") {
        if rest.starts_with(['+', '-']) {
            return None;
        }
        return from_str_radix(rest, 8).ok();
    }
    if let Some(rest) = unpositive.strip_prefix("0b") {
        if rest.starts_with(['+', '-']) {
            return None;
        }
        return from_str_radix(rest, 2).ok();
    }
    if unpositive.starts_with(['+', '-']) {
        return None;
    }
    if digits_but_not_number(scalar) {
        return None;
    }
    from_str_radix(unpositive, 10).ok()
}

fn parse_negative_int<T>(
    scalar: &str,
    from_str_radix: fn(&str, radix: u32) -> Result<T, std::num::ParseIntError>,
) -> Option<T> {
    if let Some(rest) = scalar.strip_prefix("-0x") {
        let negative = format!("-{rest}");
        return from_str_radix(&negative, 16).ok();
    }
    if let Some(rest) = scalar.strip_prefix("-0o") {
        let negative = format!("-{rest}");
        return from_str_radix(&negative, 8).ok();
    }
    if let Some(rest) = scalar.strip_prefix("-0b") {
        let negative = format!("-{rest}");
        return from_str_radix(&negative, 2).ok();
    }
    if digits_but_not_number(scalar) {
        return None;
    }
    if !scalar.starts_with('-') {
        return None;
    }
    from_str_radix(scalar, 10).ok()
}

fn parse_f64(scalar: &str) -> Option<f64> {
    let unpositive = if let Some(unpositive) = scalar.strip_prefix('+') {
        if unpositive.starts_with(['+', '-']) {
            return None;
        }
        unpositive
    } else {
        scalar
    };
    if matches!(unpositive, ".inf" | ".Inf" | ".INF") {
        return Some(f64::INFINITY);
    }
    if matches!(scalar, "-.inf" | "-.Inf" | "-.INF") {
        return Some(f64::NEG_INFINITY);
    }
    if matches!(scalar, ".nan" | ".NaN" | ".NAN") {
        return Some(f64::NAN.copysign(1.0));
    }
    if let Ok(float) = unpositive.parse::<f64>()
        && float.is_finite()
    {
        return Some(float);
    }
    None
}

fn yaml_float_overflows_finite_range(scalar: &str) -> bool {
    let unpositive = if let Some(unpositive) = scalar.strip_prefix('+') {
        if unpositive.starts_with(['+', '-']) {
            return false;
        }
        unpositive
    } else {
        scalar
    };
    // Keep legacy word-like spellings (`NaN`, `inf`) as strings unless they
    // use the YAML core forms handled by `parse_f64`. An overflowing numeric
    // spelling necessarily contains a digit.
    unpositive.bytes().any(|byte| byte.is_ascii_digit())
        && unpositive
            .parse::<f64>()
            .is_ok_and(|float| !float.is_finite())
}

fn digits_but_not_number(scalar: &str) -> bool {
    let scalar = scalar.strip_prefix(['-', '+']).unwrap_or(scalar);
    scalar.len() > 1 && scalar.starts_with('0') && scalar[1..].bytes().all(|b| b.is_ascii_digit())
}

fn looks_like_yaml_integer(scalar: &str) -> bool {
    if digits_but_not_number(scalar) {
        return false;
    }
    let unsigned = scalar.strip_prefix(['-', '+']).unwrap_or(scalar);
    let (digits, radix) = if let Some(digits) = unsigned.strip_prefix("0x") {
        (digits, 16)
    } else if let Some(digits) = unsigned.strip_prefix("0o") {
        (digits, 8)
    } else if let Some(digits) = unsigned.strip_prefix("0b") {
        (digits, 2)
    } else {
        (unsigned, 10)
    };
    !digits.is_empty()
        && digits.bytes().all(|byte| match radix {
            2 => matches!(byte, b'0' | b'1'),
            8 => matches!(byte, b'0'..=b'7'),
            10 => byte.is_ascii_digit(),
            16 => byte.is_ascii_hexdigit(),
            _ => false,
        })
}

// ---------------------------------------------------------------------------
// libyaml event parser wrapper
// ---------------------------------------------------------------------------

enum Event {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Alias {
        name: String,
    },
    Scalar {
        anchor: Option<String>,
        tag: Option<String>,
        value: String,
        style: ScalarStyle,
    },
    SequenceStart {
        anchor: Option<String>,
        tag: Option<String>,
    },
    SequenceEnd,
    MappingStart {
        anchor: Option<String>,
        tag: Option<String>,
    },
    MappingEnd,
}

struct Parser {
    /// Heap-resident foreign parser.
    ///
    /// `yaml_parser_set_input_string` stores `read_handler_data = parser`, making
    /// the C object self-referential. Moving `yaml_parser_t` after input setup
    /// leaves a dangling self-pointer and aborts inside the string read handler
    /// (`ptr::copy_nonoverlapping` alignment/null precondition). Keeping the
    /// object inside a private `Box` gives it a stable address while the owning
    /// `Parser` moves freely.
    sys: Box<sys::yaml_parser_t>,
    /// Owned input bytes. The heap buffer must stay alive and unmoved for the
    /// parser lifetime (`set_input_string` retains raw pointers into it).
    _input: Vec<u8>,
}

impl Parser {
    fn new(input: &[u8]) -> Result<Self, BoundedYamlError> {
        // Own input first so its heap buffer address is stable before the
        // parser retains pointers into it.
        let input = input.to_vec();
        let mut sys = Box::<sys::yaml_parser_t>::new_uninit();
        unsafe {
            if sys::yaml_parser_initialize(sys.as_mut_ptr()).fail {
                // Initialize failed: do not assume_init and do not delete.
                return Err(BoundedYamlError::Parse(
                    "failed to initialize YAML parser".to_string(),
                ));
            }
            // Promote MaybeUninit -> T in place without relocating the
            // allocation. The private Box is never converted back into an
            // owned yaml_parser_t, so its address stays stable.
            let mut sys = sys.assume_init();
            let parser_ptr = &mut *sys as *mut sys::yaml_parser_t;

            sys::yaml_parser_set_encoding(parser_ptr, sys::YAML_UTF8_ENCODING);
            // After this call the parser is self-referential via
            // `read_handler_data`; only the Box handle may move from here on.
            sys::yaml_parser_set_input_string(parser_ptr, input.as_ptr(), input.len() as u64);
            Ok(Self { sys, _input: input })
        }
    }

    fn next(&mut self) -> Result<Event, BoundedYamlError> {
        let mut event = MaybeUninit::<sys::yaml_event_t>::uninit();
        unsafe {
            let parser = &mut *self.sys as *mut sys::yaml_parser_t;
            let event_ptr = event.as_mut_ptr();
            // `yaml_parser_parse` initializes `event` to zero before advancing
            // the state machine. Delete any partially populated event on
            // failure. Error detail fields are crate-private — fail closed.
            if sys::yaml_parser_parse(parser, event_ptr).fail {
                sys::yaml_event_delete(event_ptr);
                return Err(BoundedYamlError::Parse(
                    "malformed YAML document".to_string(),
                ));
            }
            let converted = convert_event(&*event_ptr);
            sys::yaml_event_delete(event_ptr);
            converted
        }
    }
}

impl Drop for Parser {
    fn drop(&mut self) {
        // Delete the foreign parser before `_input` drops so retained input
        // pointers are not used during teardown. Rust then frees the parser
        // allocation and the owned input buffer.
        unsafe {
            sys::yaml_parser_delete(&mut *self.sys);
        }
    }
}

unsafe fn convert_event(event: &sys::yaml_event_t) -> Result<Event, BoundedYamlError> {
    match event.type_ {
        sys::YAML_STREAM_START_EVENT => Ok(Event::StreamStart),
        sys::YAML_STREAM_END_EVENT => Ok(Event::StreamEnd),
        sys::YAML_DOCUMENT_START_EVENT => Ok(Event::DocumentStart),
        sys::YAML_DOCUMENT_END_EVENT => Ok(Event::DocumentEnd),
        sys::YAML_ALIAS_EVENT => {
            let name = unsafe { optional_cstr(event.data.alias.anchor) }?
                .ok_or_else(|| BoundedYamlError::Parse("alias event missing name".to_string()))?;
            Ok(Event::Alias { name })
        }
        sys::YAML_SCALAR_EVENT => {
            let anchor = unsafe { optional_cstr(event.data.scalar.anchor) }?;
            let tag = unsafe { optional_cstr(event.data.scalar.tag) }?;
            let value = unsafe {
                let ptr = event.data.scalar.value;
                let len = event.data.scalar.length as usize;
                if ptr.is_null() {
                    String::new()
                } else {
                    let bytes = slice::from_raw_parts(ptr, len);
                    String::from_utf8(bytes.to_vec()).map_err(|_| {
                        BoundedYamlError::Parse("YAML scalar is not valid UTF-8".to_string())
                    })?
                }
            };
            let style = match unsafe { event.data.scalar.style } {
                sys::YAML_PLAIN_SCALAR_STYLE => ScalarStyle::Plain,
                sys::YAML_SINGLE_QUOTED_SCALAR_STYLE => ScalarStyle::SingleQuoted,
                sys::YAML_DOUBLE_QUOTED_SCALAR_STYLE => ScalarStyle::DoubleQuoted,
                sys::YAML_LITERAL_SCALAR_STYLE => ScalarStyle::Literal,
                sys::YAML_FOLDED_SCALAR_STYLE => ScalarStyle::Folded,
                _ => {
                    return Err(BoundedYamlError::Parse(
                        "unsupported YAML scalar style".to_string(),
                    ));
                }
            };
            Ok(Event::Scalar {
                anchor,
                tag,
                value,
                style,
            })
        }
        sys::YAML_SEQUENCE_START_EVENT => {
            let anchor = unsafe { optional_cstr(event.data.sequence_start.anchor) }?;
            let tag = unsafe { optional_cstr(event.data.sequence_start.tag) }?;
            Ok(Event::SequenceStart { anchor, tag })
        }
        sys::YAML_SEQUENCE_END_EVENT => Ok(Event::SequenceEnd),
        sys::YAML_MAPPING_START_EVENT => {
            let anchor = unsafe { optional_cstr(event.data.mapping_start.anchor) }?;
            let tag = unsafe { optional_cstr(event.data.mapping_start.tag) }?;
            Ok(Event::MappingStart { anchor, tag })
        }
        sys::YAML_MAPPING_END_EVENT => Ok(Event::MappingEnd),
        _ => Err(BoundedYamlError::Parse(
            "unsupported YAML event type".to_string(),
        )),
    }
}

unsafe fn optional_cstr(ptr: *const u8) -> Result<Option<String>, BoundedYamlError> {
    let Some(nn) = NonNull::new(ptr as *mut i8) else {
        return Ok(None);
    };
    let s = unsafe { cstr_to_string(nn.as_ptr()) }
        .ok_or_else(|| BoundedYamlError::Parse("YAML identifier is not valid UTF-8".to_string()))?;
    if s.is_empty() { Ok(None) } else { Ok(Some(s)) }
}

unsafe fn cstr_to_string(ptr: *const i8) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len = len.saturating_add(1);
            if len > 1_048_576 {
                return None;
            }
        }
        let bytes = slice::from_raw_parts(ptr as *const u8, len);
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }
}
