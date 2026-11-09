//! OpenAI-to-provider request admission rules shared by `ai_federation`
//! (buffered) and `ai_stream_router` (streaming) (issue #7070).
//!
//! Both plugins translate the same OpenAI Chat Completions request into the
//! Gemini/Vertex and Anthropic request shapes. The rules that decide whether
//! that input is admissible live here once, so the same client request gets
//! the same answer on either route kind:
//!
//! - which strict `response_format` JSON schemas Gemini actually enforces
//!   ([`screen_gemini_strict_schema_document`]);
//! - what a tool-call id ([`valid_tool_call_id`]) and a function name
//!   ([`valid_tool_name`]) may be;
//! - how an assistant `tool_calls` array is read, with `"tool_calls": null`
//!   treated as absent ([`present_tool_calls`], [`parse_openai_tool_calls`]);
//! - how a tool-result `content` is flattened ([`tool_result_text`]).
//!
//! Buffered vs streaming protocol handling, error envelopes, and each plugin's
//! own error prefix stay in the plugins. Diagnostics here name the offending
//! field but never echo tool-argument bytes or schema values.

use serde_json::{Map, Value};

// ── Gemini strict `response_format` schema screen ─────────────────────────

/// JSON Schema keywords Gemini/Vertex `responseJsonSchema` documents as
/// enforced (Gemini API structured-output guide, "JSON Schema support"; Vertex
/// AI "Supported schema fields"). Deliberately conservative: a keyword that is
/// not listed here (`minLength`, `pattern`, `uniqueItems`, `oneOf`, `const`,
/// ...) is treated as unenforced, so a strict schema using it is refused rather
/// than silently weakened.
pub(crate) const GEMINI_STRICT_SCHEMA_KEYWORDS: &[&str] = &[
    "type",
    "title",
    "description",
    "enum",
    "format",
    "anyOf",
    "$ref",
    "$defs",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "prefixItems",
    "minItems",
    "maxItems",
    "minimum",
    "maximum",
];

/// String `format` values Gemini documents as enforced.
pub(crate) const GEMINI_STRICT_SCHEMA_FORMATS: &[&str] = &["date-time", "date", "time"];

/// Nesting bound for the strict-schema screen. Deeper schemas are refused
/// rather than walked, so hostile nesting cannot grow the stack.
pub(crate) const MAX_STRICT_SCHEMA_DEPTH: usize = 32;

/// Upper bound on `$defs` entries in a strict schema, so the reference-graph
/// walk is bounded.
pub(crate) const MAX_STRICT_SCHEMA_DEFS: usize = 256;

/// Why a strict JSON schema cannot be enforced by Gemini.
///
/// [`std::fmt::Display`] renders a fixed diagnostic that never echoes a schema
/// key or value. [`Self::unenforced_keyword`] exposes the offending keyword for
/// a caller that chooses to name it (bounded) in its own error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GeminiStrictSchemaRefusal<'a> {
    /// More than [`MAX_STRICT_SCHEMA_DEFS`] root `$defs` entries.
    TooManyDefs,
    /// `$defs` is not an object.
    DefsNotObject,
    /// Nesting deeper than [`MAX_STRICT_SCHEMA_DEPTH`].
    TooDeep,
    /// A subschema that is neither an object nor a boolean.
    NonObjectSubschema,
    /// `$ref` beside any keyword other than the root's own `$defs`.
    RefWithSiblings,
    /// A keyword outside [`GEMINI_STRICT_SCHEMA_KEYWORDS`].
    UnenforcedKeyword(&'a str),
    /// A `format` outside [`GEMINI_STRICT_SCHEMA_FORMATS`].
    UnenforcedFormat,
    /// A `$ref` that is not `#` or an existing root `#/$defs/<name>`.
    UnresolvedRef,
    /// `$defs` below the root schema.
    NestedDefs,
    /// `properties` (or `$defs`) is not an object.
    MembersNotObject(&'static str),
    /// `anyOf` / `prefixItems` is not an array.
    MembersNotArray(&'static str),
    /// The reference graph has a cycle.
    RecursiveRef,
}

impl<'a> GeminiStrictSchemaRefusal<'a> {
    /// The keyword Gemini does not enforce, when that is the refusal.
    pub(crate) fn unenforced_keyword(&self) -> Option<&'a str> {
        if let Self::UnenforcedKeyword(keyword) = *self {
            Some(keyword)
        } else {
            None
        }
    }
}

impl std::fmt::Display for GeminiStrictSchemaRefusal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyDefs => write!(
                f,
                "strict json_schema declares more than {MAX_STRICT_SCHEMA_DEFS} `$defs` entries"
            ),
            Self::DefsNotObject => f.write_str("strict json_schema `$defs` must be an object"),
            Self::TooDeep => write!(
                f,
                "strict json_schema nests deeper than {MAX_STRICT_SCHEMA_DEPTH} levels"
            ),
            Self::NonObjectSubschema => {
                f.write_str("strict json_schema contains a non-object subschema")
            }
            Self::RefWithSiblings => f.write_str(
                "strict json_schema combines `$ref` with sibling keywords, which Gemini does not support",
            ),
            Self::UnenforcedKeyword(_) => {
                f.write_str("strict json_schema uses a keyword Gemini does not enforce")
            }
            Self::UnenforcedFormat => f.write_str(
                "strict json_schema uses a `format` Gemini does not enforce (supported: date-time, date, time)",
            ),
            Self::UnresolvedRef => f.write_str(
                "strict json_schema `$ref` must be `#` or name an existing `#/$defs/<name>` entry",
            ),
            Self::NestedDefs => {
                f.write_str("strict json_schema declares `$defs` below the root schema")
            }
            Self::MembersNotObject(keyword) => {
                write!(f, "strict json_schema `{keyword}` must be an object")
            }
            Self::MembersNotArray(keyword) => {
                write!(f, "strict json_schema `{keyword}` must be an array")
            }
            Self::RecursiveRef => f.write_str(
                "strict json_schema uses a recursive `$ref`, which Gemini only honours through optional properties",
            ),
        }
    }
}

/// The reference-graph node a `$ref` names: `None` for the root (`#`), or the
/// root `$defs` entry.
type StrictSchemaRefTarget<'a> = Option<&'a str>;

/// Screen a complete strict JSON Schema against what Gemini/Vertex
/// `responseJsonSchema` enforces.
///
/// Beyond the keyword subset, references are held to the shapes Google
/// documents (GenerateContent `GenerationConfig` response JSON schema
/// restrictions): a `$ref` node carries no sibling keyword (other than the
/// root's own `$defs`), targets only `#` or an existing root
/// `#/$defs/<name>`, `$defs` appears only at the root, and the reference graph
/// is acyclic. Google admits recursion only through optional properties;
/// telling those apart reliably is not attempted here, so a strict schema with
/// ANY recursive reference is refused (conservative; send it with
/// `strict: false` to forward it as guidance).
pub(crate) fn screen_gemini_strict_schema_document(
    root: &Value,
) -> Result<(), GeminiStrictSchemaRefusal<'_>> {
    let defs = match root.get("$defs") {
        None => None,
        Some(Value::Object(defs)) if defs.len() <= MAX_STRICT_SCHEMA_DEFS => Some(defs),
        Some(Value::Object(_)) => return Err(GeminiStrictSchemaRefusal::TooManyDefs),
        Some(_) => return Err(GeminiStrictSchemaRefusal::DefsNotObject),
    };
    screen_gemini_strict_schema(root, defs, 0, true)?;

    // Reference graph: the root plus every `$defs` entry, each with the
    // targets its own subtree references (a definition's references are
    // collected without descending into the root `$defs`).
    let mut nodes: Vec<(StrictSchemaRefTarget<'_>, Vec<StrictSchemaRefTarget<'_>>)> = Vec::new();
    let mut root_refs = Vec::new();
    collect_strict_schema_refs(root, true, &mut root_refs);
    nodes.push((None, root_refs));
    if let Some(defs) = defs {
        for (name, definition) in defs {
            let mut refs = Vec::new();
            collect_strict_schema_refs(definition, false, &mut refs);
            nodes.push((Some(name.as_str()), refs));
        }
    }
    // Iterative three-colour DFS: 0 unvisited, 1 on the stack, 2 done.
    let index_of =
        |target: StrictSchemaRefTarget<'_>| nodes.iter().position(|(node, _)| *node == target);
    let mut colour = vec![0u8; nodes.len()];
    for start in 0..nodes.len() {
        if colour[start] != 0 {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
        colour[start] = 1;
        while let Some((node, next_edge)) = stack.last().copied() {
            let edges = &nodes[node].1;
            if next_edge == edges.len() {
                colour[node] = 2;
                stack.pop();
                continue;
            }
            if let Some(top) = stack.last_mut() {
                top.1 += 1;
            }
            let Some(target) = index_of(edges[next_edge]) else {
                // Unresolvable targets were already refused by the screen.
                continue;
            };
            match colour[target] {
                0 => {
                    colour[target] = 1;
                    stack.push((target, 0));
                }
                1 => return Err(GeminiStrictSchemaRefusal::RecursiveRef),
                _ => {}
            }
        }
    }
    Ok(())
}

/// Collect the `$ref` targets of one schema subtree. `at_root` skips the
/// root's own `$defs` (each definition is its own graph node).
fn collect_strict_schema_refs<'a>(
    schema: &'a Value,
    at_root: bool,
    out: &mut Vec<StrictSchemaRefTarget<'a>>,
) {
    let Value::Object(object) = schema else {
        return;
    };
    for (keyword, value) in object {
        match keyword.as_str() {
            "$ref" => {
                if let Some(reference) = value.as_str() {
                    out.push(reference.strip_prefix("#/$defs/"));
                }
            }
            "$defs" if at_root => {}
            "properties" | "$defs" => {
                if let Some(members) = value.as_object() {
                    for member in members.values() {
                        collect_strict_schema_refs(member, false, out);
                    }
                }
            }
            "anyOf" | "prefixItems" => {
                if let Some(members) = value.as_array() {
                    for member in members {
                        collect_strict_schema_refs(member, false, out);
                    }
                }
            }
            "items" | "additionalProperties" => {
                collect_strict_schema_refs(value, false, out);
            }
            _ => {}
        }
    }
}

/// Check one strict JSON Schema node (and every nested subschema) against the
/// Gemini-enforced subset. `defs` is the root `$defs` object every
/// `#/$defs/<name>` reference must resolve into.
fn screen_gemini_strict_schema<'a>(
    schema: &'a Value,
    defs: Option<&Map<String, Value>>,
    depth: usize,
    at_root: bool,
) -> Result<(), GeminiStrictSchemaRefusal<'a>> {
    if depth > MAX_STRICT_SCHEMA_DEPTH {
        return Err(GeminiStrictSchemaRefusal::TooDeep);
    }
    let object = match schema {
        // Boolean subschemas (`true` / `false`) carry no keywords.
        Value::Bool(_) => return Ok(()),
        Value::Object(object) => object,
        _ => return Err(GeminiStrictSchemaRefusal::NonObjectSubschema),
    };
    // Google forbids sibling keywords next to `$ref`; the root may still
    // declare the `$defs` its reference points into.
    if object.contains_key("$ref")
        && object
            .keys()
            .any(|keyword| keyword != "$ref" && !(at_root && keyword == "$defs"))
    {
        return Err(GeminiStrictSchemaRefusal::RefWithSiblings);
    }
    for (keyword, value) in object {
        if !GEMINI_STRICT_SCHEMA_KEYWORDS.contains(&keyword.as_str()) {
            return Err(GeminiStrictSchemaRefusal::UnenforcedKeyword(keyword));
        }
        match keyword.as_str() {
            "format" => {
                if !value
                    .as_str()
                    .is_some_and(|format| GEMINI_STRICT_SCHEMA_FORMATS.contains(&format))
                {
                    return Err(GeminiStrictSchemaRefusal::UnenforcedFormat);
                }
            }
            "$ref" => {
                // Only the root (`#`) or an existing root definition resolves
                // inside the schema the provider receives.
                let resolves = value.as_str().is_some_and(|reference| {
                    reference == "#"
                        || reference
                            .strip_prefix("#/$defs/")
                            .is_some_and(|name| defs.is_some_and(|defs| defs.contains_key(name)))
                });
                if !resolves {
                    return Err(GeminiStrictSchemaRefusal::UnresolvedRef);
                }
            }
            "$defs" => {
                if !at_root {
                    return Err(GeminiStrictSchemaRefusal::NestedDefs);
                }
                let members = value
                    .as_object()
                    .ok_or(GeminiStrictSchemaRefusal::DefsNotObject)?;
                for member in members.values() {
                    screen_gemini_strict_schema(member, defs, depth + 1, false)?;
                }
            }
            "properties" => {
                let members = value
                    .as_object()
                    .ok_or(GeminiStrictSchemaRefusal::MembersNotObject("properties"))?;
                for member in members.values() {
                    screen_gemini_strict_schema(member, defs, depth + 1, false)?;
                }
            }
            "anyOf" | "prefixItems" => {
                let label = if keyword == "anyOf" {
                    "anyOf"
                } else {
                    "prefixItems"
                };
                let members = value
                    .as_array()
                    .ok_or(GeminiStrictSchemaRefusal::MembersNotArray(label))?;
                for member in members {
                    screen_gemini_strict_schema(member, defs, depth + 1, false)?;
                }
            }
            "items" | "additionalProperties" => {
                screen_gemini_strict_schema(value, defs, depth + 1, false)?;
            }
            _ => {}
        }
    }
    Ok(())
}

// ── Tool calls and tool results ───────────────────────────────────────────

/// Upper bound on a tool-call or tool-result id (bytes).
pub(crate) const MAX_TOOL_CALL_ID_BYTES: usize = 128;

/// Upper bound on a function name (bytes), matching OpenAI's own limit.
pub(crate) const MAX_TOOL_NAME_BYTES: usize = 64;

/// Upper bound on one tool/function-call `arguments` JSON string (bytes).
pub(crate) const MAX_TOOL_ARGUMENTS_BYTES: usize = 256 * 1024;

/// A tool-call (`tool_calls[].id`) or tool-result (`tool_call_id`) id:
/// non-empty and at most [`MAX_TOOL_CALL_ID_BYTES`] bytes.
pub(crate) fn valid_tool_call_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_TOOL_CALL_ID_BYTES
}

/// A function name every translated provider accepts: 1 to
/// [`MAX_TOOL_NAME_BYTES`] ASCII alphanumerics, `_`, or `-`.
pub(crate) fn valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TOOL_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// A message's `tool_calls`, when present. JSON `null` is treated as absent,
/// the same as an omitted field.
pub(crate) fn present_tool_calls(message: &Value) -> Option<&Value> {
    message.get("tool_calls").filter(|value| !value.is_null())
}

/// One validated OpenAI assistant tool call.
#[derive(Debug, Clone)]
pub(crate) struct ParsedToolCall {
    pub(crate) id: String,
    pub(crate) name: String,
    /// The parsed `arguments` object.
    pub(crate) arguments: Value,
}

/// Which request field a tool-call `arguments` string came from, for
/// diagnostics.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ToolArgumentsField {
    /// `messages[i].tool_calls[j].function.arguments`.
    Modern {
        message_index: usize,
        tool_index: usize,
    },
    /// `messages[i].function_call.arguments` (legacy single function call).
    Legacy { message_index: usize },
}

impl ToolArgumentsField {
    fn error(self, detail: &str) -> String {
        match self {
            Self::Modern {
                message_index,
                tool_index,
            } => format!("messages[{message_index}].tool_calls[{tool_index}] {detail}"),
            Self::Legacy { message_index } => {
                format!("messages[{message_index}].function_call {detail}")
            }
        }
    }
}

/// Parse a tool-call `arguments` string into the JSON object it must encode,
/// bounded by [`MAX_TOOL_ARGUMENTS_BYTES`]. Errors name the field only and
/// never echo argument bytes (they may hold credentials).
pub(crate) fn parse_tool_arguments_object(
    arguments: &str,
    field: ToolArgumentsField,
) -> Result<Value, String> {
    if arguments.len() > MAX_TOOL_ARGUMENTS_BYTES {
        return Err(field.error("arguments exceed the maximum allowed size"));
    }
    let parsed: Value =
        serde_json::from_str(arguments).map_err(|_| field.error("arguments are not valid JSON"))?;
    if !parsed.is_object() {
        return Err(field.error("arguments must encode a JSON object"));
    }
    Ok(parsed)
}

/// The entries of an OpenAI assistant message's `tool_calls`.
///
/// Absent or JSON `null` yields no entries. Otherwise the value must be a
/// non-empty array. Errors carry no plugin prefix; callers add their own.
pub(crate) fn openai_tool_call_entries(
    message: &Value,
    message_index: usize,
) -> Result<&[Value], String> {
    let Some(tool_calls_value) = present_tool_calls(message) else {
        return Ok(&[]);
    };
    let tool_calls = tool_calls_value
        .as_array()
        .ok_or_else(|| format!("messages[{message_index}].tool_calls must be an array"))?;
    if tool_calls.is_empty() {
        return Err(format!(
            "messages[{message_index}].tool_calls must not be empty"
        ));
    }
    Ok(tool_calls)
}

/// Parse and validate one `tool_calls[tool_index]` entry:
/// `{"type":"function","id":..,"function":{"name":..,"arguments":"<JSON
/// object>"}}` with a [`valid_tool_call_id`] and a [`valid_tool_name`].
/// Errors carry no plugin prefix; callers add their own.
pub(crate) fn parse_openai_tool_call(
    call: &Value,
    message_index: usize,
    tool_index: usize,
) -> Result<ParsedToolCall, String> {
    let call_object = call.as_object().ok_or_else(|| {
        format!("messages[{message_index}].tool_calls[{tool_index}] must be an object")
    })?;
    if call_object.get("type").and_then(Value::as_str) != Some("function") {
        return Err(format!(
            "messages[{message_index}].tool_calls[{tool_index}] must have type 'function'"
        ));
    }
    let id = call_object
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| valid_tool_call_id(value))
        .ok_or_else(|| format!("messages[{message_index}].tool_calls[{tool_index}] missing id"))?;
    let function = call_object
        .get("function")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            format!("messages[{message_index}].tool_calls[{tool_index}] missing function")
        })?;
    let name = function
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| valid_tool_name(value))
        .ok_or_else(|| {
            format!("messages[{message_index}].tool_calls[{tool_index}] has invalid function name")
        })?;
    let arguments = function
        .get("arguments")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "messages[{message_index}].tool_calls[{tool_index}] arguments must be a JSON string"
            )
        })?;
    let arguments = parse_tool_arguments_object(
        arguments,
        ToolArgumentsField::Modern {
            message_index,
            tool_index,
        },
    )?;
    Ok(ParsedToolCall {
        id: id.to_string(),
        name: name.to_string(),
        arguments,
    })
}

/// Parse and validate an OpenAI assistant message's `tool_calls`: the
/// [`openai_tool_call_entries`] array, each entry through
/// [`parse_openai_tool_call`] in order.
pub(crate) fn parse_openai_tool_calls(
    message: &Value,
    message_index: usize,
) -> Result<Vec<ParsedToolCall>, String> {
    let entries = openai_tool_call_entries(message, message_index)?;
    let mut parsed = Vec::with_capacity(entries.len());
    for (tool_index, call) in entries.iter().enumerate() {
        parsed.push(parse_openai_tool_call(call, message_index, tool_index)?);
    }
    Ok(parsed)
}

/// Flatten a tool-result `content` into text: a string, a text-parts array, or
/// JSON `null` / absent (an empty result). Errors carry no plugin prefix.
pub(crate) fn tool_result_text(content: &Value) -> Result<String, String> {
    if let Some(text) = content.as_str() {
        return Ok(text.to_string());
    }
    if content.is_null() {
        return Ok(String::new());
    }
    let parts = content
        .as_array()
        .ok_or("tool message content must be a string or text-parts array")?;
    let mut text = String::new();
    for (index, part) in parts.iter().enumerate() {
        if part.get("type").and_then(Value::as_str) != Some("text") {
            return Err(format!("tool message content[{index}] must be a text part"));
        }
        text.push_str(
            part.get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("tool message content[{index}] missing text"))?,
        );
    }
    Ok(text)
}
