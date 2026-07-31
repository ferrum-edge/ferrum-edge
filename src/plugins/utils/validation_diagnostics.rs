//! Client-, metadata-, and log-safe diagnostics for body-validation plugins.
//!
//! Advisory `GHSA-5p2h-fq6q-gwh9`: `body_validator` and `openapi_validator`
//! used to format the rejected instance value — or a payload-derived JSON /
//! XML / form / multipart member name — into the string they hand back to
//! `PluginResult::Reject` and into `RequestContext.metadata`. Both surfaces
//! cross a confidentiality boundary: the reject body is returned to the
//! requesting client, and the metadata entry is exported verbatim by every
//! configured logging plugin. On the response side that re-publishes exactly
//! the upstream representation validation existed to withhold; on the request
//! side it copies caller credentials into gateway telemetry.
//!
//! The fix is a construction-time contract, not a post-hoc scrub. A production
//! diagnostic is assembled here from three ingredients only:
//!
//! * a fixed-cardinality **category** — a compiled-in `&'static str` chosen by
//!   the rejecting code path, never derived from payload bytes;
//! * an optional bounded **location** — a JSON Pointer whose segments are
//!   either a fixed numeric-shape marker or member names the *configured
//!   schema* itself declares as JSON object properties (see
//!   [`SafeFieldNames`]); every other segment collapses to
//!   [`REDACTED_SEGMENT`];
//! * an optional **keyword** — the failing JSON Schema keyword, accepted only
//!   when it is on the explicit allowlist of supported diagnostic vocabulary
//!   tokens ([`SAFE_KEYWORDS`]); anything else collapses to
//!   [`UNKNOWN_KEYWORD`].
//!
//! Nothing here accepts an instance value, so there is no code path that can
//! leak one and no "raw detail" escape hatch to misconfigure. Truncation is
//! applied on top as a size bound, never as the confidentiality mechanism:
//! [`bound_detail`] exists so a pathological schema (deeply nested `$defs`,
//! hundreds of declared properties) cannot produce an unbounded log line, and
//! its cap is compiled in rather than operator-tunable.

use std::collections::HashSet;

use serde_json::Value;

/// Hard ceiling on a rendered diagnostic, in characters.
///
/// This is a resource bound. Confidentiality comes from what is *never*
/// formatted, so this value is deliberately not configurable — an operator
/// cannot raise it into a leak.
pub const MAX_DIAGNOSTIC_CHARS: usize = 256;

/// Maximum number of JSON Pointer segments retained in a location.
pub const MAX_LOCATION_SEGMENTS: usize = 8;

/// Maximum characters retained in a rendered location.
pub const MAX_LOCATION_CHARS: usize = 96;

/// Maximum characters a single retained (unescaped) path segment may have.
pub const MAX_SEGMENT_CHARS: usize = 48;

/// Maximum bytes accepted from a raw JSON Pointer segment before unescape.
///
/// JSON Pointer `~0` / `~1` escapes shrink (two bytes → one char), so the
/// unescaped form is never longer than the raw form. Doubling
/// [`MAX_SEGMENT_CHARS`] therefore bounds both the allocation and the
/// worst-case escaped spelling of a declared name that still fits after
/// unescape.
pub const MAX_RAW_SEGMENT_CHARS: usize = MAX_SEGMENT_CHARS * 2;

/// Maximum characters retained from a schema-derived keyword token.
pub const MAX_KEYWORD_CHARS: usize = 32;

/// Placeholder for a path segment that could originate from payload bytes.
pub const REDACTED_SEGMENT: &str = "~";

/// Fixed marker for a JSON Pointer segment whose text is all ASCII digits.
///
/// JSON Pointer alone does not prove the container is an array: an
/// attacker-controlled object member named `"0"` is indistinguishable from a
/// true array index. Digits are therefore never echoed.
pub const NUMERIC_SEGMENT: &str = "#";

/// Marker appended when a location was cut short by the segment budget.
pub const TRUNCATED_LOCATION_MARKER: &str = "/...";

/// Rendered location for a failure at the document root.
pub const ROOT_LOCATION: &str = "(root)";

/// Keyword reported when the failing token is absent or not allowlisted.
pub const UNKNOWN_KEYWORD: &str = "UNKNOWN_KEYWORD";

/// Depth budget for the declared-name walk over a configured schema.
const MAX_SCHEMA_WALK_DEPTH: usize = 24;

/// Cap on how many declared names are retained per compiled schema.
const MAX_DECLARED_NAMES: usize = 2048;

/// Explicit allowlist of JSON Schema keywords that may appear in a diagnostic.
///
/// Drawn from the Draft 7 / Draft 2020-12 vocabularies Ferrum compiles. A short
/// all-alphanumeric custom keyword, `$defs` / `definitions` map key, or any
/// other schema-derived token is *not* in this set and collapses to
/// [`UNKNOWN_KEYWORD`].
pub const SAFE_KEYWORDS: &[&str] = &[
    "$anchor",
    "$dynamicAnchor",
    "$dynamicRef",
    "$id",
    "$recursiveAnchor",
    "$recursiveRef",
    "$ref",
    "$schema",
    "$vocabulary",
    "additionalItems",
    "additionalProperties",
    "allOf",
    "anyOf",
    "const",
    "contains",
    "contentEncoding",
    "contentMediaType",
    "contentSchema",
    "default",
    "definitions",
    "dependentRequired",
    "dependentSchemas",
    "deprecated",
    "description",
    "else",
    "enum",
    "examples",
    "exclusiveMaximum",
    "exclusiveMinimum",
    "format",
    "if",
    "items",
    "maxContains",
    "maximum",
    "maxItems",
    "maxLength",
    "maxProperties",
    "minContains",
    "minimum",
    "minItems",
    "minLength",
    "minProperties",
    "multipleOf",
    "not",
    "oneOf",
    "pattern",
    "patternProperties",
    "prefixItems",
    "properties",
    "propertyNames",
    "readOnly",
    "required",
    "then",
    "title",
    "type",
    "unevaluatedItems",
    "unevaluatedProperties",
    "uniqueItems",
    "writeOnly",
];

/// Subschema-bearing keywords whose value is itself a schema.
const SUBSCHEMA_KEYWORDS: &[&str] = &[
    "additionalItems",
    "additionalProperties",
    "contains",
    "contentSchema",
    "else",
    "if",
    "items",
    "not",
    "propertyNames",
    "then",
    "unevaluatedItems",
    "unevaluatedProperties",
];

/// Keywords whose value is an array of schemas.
const SCHEMA_ARRAY_KEYWORDS: &[&str] = &["allOf", "anyOf", "oneOf", "prefixItems"];

/// Keywords whose value is a map of name -> schema. Their keys are declared
/// member names for `properties` / `dependentSchemas` and opaque regexes for
/// `patternProperties`, so only the first two contribute names. `$defs` /
/// `definitions` keys are schema identifiers, not JSON instance member names,
/// and are never collected.
const SCHEMA_MAP_KEYWORDS: &[&str] = &[
    "$defs",
    "definitions",
    "dependentSchemas",
    "patternProperties",
    "properties",
];

/// Member names the configured schema declares, and which are therefore
/// operator-controlled rather than payload-derived.
///
/// A name in this set is safe to echo: it came from the plugin's own
/// configuration (or the imported OpenAPI document), so reporting it describes
/// the *policy* rather than the rejected instance. Everything else — an
/// arbitrary JSON member, an XML local name, a form or multipart field name —
/// is attacker- or backend-chosen and is replaced by [`REDACTED_SEGMENT`].
///
/// Only JSON object member names (`properties`, `required`,
/// `dependentRequired`, `dependentSchemas`) are collected. Configured
/// `xml.name` values are deliberately excluded: they are wire/payload names,
/// and echoing them contradicts the advisory's prohibition on raw XML names.
///
/// The walk is bounded in both depth and retained names so a large configured
/// schema cannot make construction expensive or the set unbounded.
#[derive(Debug, Default, Clone)]
pub struct SafeFieldNames {
    names: HashSet<String>,
}

impl SafeFieldNames {
    /// Collect every JSON member name the schema declares, bounded.
    pub fn from_schema(schema: &Value) -> Self {
        let mut names = HashSet::new();
        collect_declared_names(schema, &mut names, 0);
        Self { names }
    }

    /// True when `name` is declared by the configured schema and short enough
    /// to render.
    pub fn allows(&self, name: &str) -> bool {
        name.len() <= MAX_SEGMENT_CHARS && self.names.contains(name)
    }
}

fn collect_declared_names(schema: &Value, out: &mut HashSet<String>, depth: usize) {
    if depth > MAX_SCHEMA_WALK_DEPTH || out.len() >= MAX_DECLARED_NAMES {
        return;
    }
    let Some(object) = schema.as_object() else {
        return;
    };

    if let Some(Value::Array(required)) = object.get("required") {
        for entry in required {
            if let Some(name) = entry.as_str() {
                insert_name(out, name);
            }
        }
    }
    // `enum` / `const` members are instance values, never member names, and are
    // deliberately not collected here — see the module docs.
    // `xml.name` is a wire/payload name and is never collected.
    if let Some(Value::Object(dependent)) = object.get("dependentRequired") {
        for (name, values) in dependent {
            insert_name(out, name);
            if let Some(values) = values.as_array() {
                for entry in values {
                    if let Some(entry) = entry.as_str() {
                        insert_name(out, entry);
                    }
                }
            }
        }
    }

    for keyword in SCHEMA_MAP_KEYWORDS {
        let Some(Value::Object(members)) = object.get(*keyword) else {
            continue;
        };
        let names_are_members = *keyword == "properties" || *keyword == "dependentSchemas";
        for (name, subschema) in members {
            if names_are_members {
                insert_name(out, name);
            }
            collect_declared_names(subschema, out, depth + 1);
        }
    }
    for keyword in SCHEMA_ARRAY_KEYWORDS {
        let Some(Value::Array(entries)) = object.get(*keyword) else {
            continue;
        };
        for entry in entries {
            collect_declared_names(entry, out, depth + 1);
        }
    }
    for keyword in SUBSCHEMA_KEYWORDS {
        let Some(subschema) = object.get(*keyword) else {
            continue;
        };
        if let Value::Array(entries) = subschema {
            // Draft 7 tuple `items`.
            for entry in entries {
                collect_declared_names(entry, out, depth + 1);
            }
            continue;
        }
        collect_declared_names(subschema, out, depth + 1);
    }
}

fn insert_name(out: &mut HashSet<String>, name: &str) {
    if out.len() >= MAX_DECLARED_NAMES || name.len() > MAX_SEGMENT_CHARS {
        return;
    }
    out.insert(name.to_string());
}

/// Render a JSON Pointer as a bounded, payload-free location.
///
/// Digits render as [`NUMERIC_SEGMENT`] (JSON Pointer does not prove array
/// shape). Object member names survive only when `names` declares them. Raw
/// segments over [`MAX_RAW_SEGMENT_CHARS`] are redacted before unescape so a
/// hostile key cannot force an unbounded allocation on the error path. Depth,
/// segment count, and total length are all capped.
pub fn safe_location(pointer: &str, names: &SafeFieldNames) -> String {
    if pointer.is_empty() {
        return ROOT_LOCATION.to_string();
    }
    let mut out = String::new();
    let mut emitted = 0usize;
    let mut truncated = false;
    for raw in pointer.split('/').skip(1) {
        if emitted >= MAX_LOCATION_SEGMENTS {
            truncated = true;
            break;
        }
        let rendered = render_pointer_segment(raw, names);
        if out.len() + 1 + rendered.len() > MAX_LOCATION_CHARS {
            truncated = true;
            break;
        }
        out.push('/');
        out.push_str(&rendered);
        emitted += 1;
    }
    if out.is_empty() {
        return ROOT_LOCATION.to_string();
    }
    if truncated {
        out.push_str(TRUNCATED_LOCATION_MARKER);
    }
    out
}

fn render_pointer_segment(raw: &str, names: &SafeFieldNames) -> String {
    // Reject over-budget raw segments before allocating an unescaped copy.
    // Escapes only shrink, so this also bounds the post-unescape length.
    if raw.is_empty() || raw.len() > MAX_RAW_SEGMENT_CHARS {
        return REDACTED_SEGMENT.to_string();
    }
    let segment = unescape_pointer_segment(raw);
    if segment.len() > MAX_SEGMENT_CHARS {
        return REDACTED_SEGMENT.to_string();
    }
    if is_numeric_segment(&segment) {
        return NUMERIC_SEGMENT.to_string();
    }
    if names.allows(&segment) {
        return segment;
    }
    REDACTED_SEGMENT.to_string()
}

fn is_numeric_segment(segment: &str) -> bool {
    !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit())
}

fn unescape_pointer_segment(segment: &str) -> String {
    if !segment.contains('~') {
        return segment.to_string();
    }
    let mut out = String::with_capacity(segment.len());
    let mut chars = segment.chars();
    while let Some(ch) = chars.next() {
        if ch != '~' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            Some(other) => {
                out.push('~');
                out.push(other);
            }
            None => out.push('~'),
        }
    }
    out
}

/// Reduce a `jsonschema` schema path to the failing keyword token.
///
/// The schema path is operator-controlled, but it can carry `$defs` /
/// `definitions` names, `$ref` fragments, and other imported schema text. Only
/// a trailing token that matches the explicit [`SAFE_KEYWORDS`] allowlist is
/// retained.
pub fn safe_keyword(schema_path: &str) -> &'static str {
    let candidate = schema_path
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("");
    if candidate.is_empty() || candidate.len() > MAX_KEYWORD_CHARS {
        return UNKNOWN_KEYWORD;
    }
    for keyword in SAFE_KEYWORDS {
        if *keyword == candidate {
            return keyword;
        }
    }
    UNKNOWN_KEYWORD
}

/// Apply the compiled-in size ceiling to an assembled diagnostic.
///
/// Defense in depth only: every caller already builds from fixed categories
/// plus a bounded location, so this should never actually cut. It exists so a
/// pathological configuration cannot emit an unbounded metadata value.
pub fn bound_detail(detail: &str) -> String {
    if detail.chars().count() <= MAX_DIAGNOSTIC_CHARS {
        return detail.to_string();
    }
    detail.chars().take(MAX_DIAGNOSTIC_CHARS).collect()
}

/// Stable, value-free category for an XML parse failure.
///
/// Shared by every XML-inspecting validator so one audited mapping governs both
/// the request and response paths.
///
/// `roxmltree`'s own `Display` embeds parsed names and offsets; those are body
/// content, so the client only ever sees the class of well-formedness error.
pub fn xml_error_category(error: &roxmltree::Error) -> &'static str {
    use roxmltree::Error as XmlError;
    match error {
        XmlError::InvalidXmlPrefixUri(_)
        | XmlError::UnexpectedXmlUri(_)
        | XmlError::UnexpectedXmlnsUri(_)
        | XmlError::InvalidElementNamePrefix(_)
        | XmlError::DuplicatedNamespace(_, _)
        | XmlError::UnknownNamespace(_, _) => "namespace declaration is not well-formed",
        XmlError::UnexpectedCloseTag(_, _, _)
        | XmlError::UnexpectedEntityCloseTag(_)
        | XmlError::UnclosedRootNode => "element tags are not balanced",
        XmlError::UnknownEntityReference(_, _) | XmlError::MalformedEntityReference(_) => {
            "entity reference is undeclared or malformed"
        }
        XmlError::EntityReferenceLoop(_) => "entity references expand recursively",
        XmlError::InvalidAttributeValue(_) | XmlError::DuplicatedAttribute(_, _) => {
            "attribute is malformed or duplicated"
        }
        XmlError::NoRootNode => "document has no root element",
        XmlError::NodesLimitReached => "document exceeds the parser node budget",
        XmlError::AttributesLimitReached => "element has too many attributes",
        XmlError::NamespacesLimitReached => "document declares too many namespaces",
        XmlError::UnexpectedDeclaration(_) => "XML declaration is misplaced or duplicated",
        XmlError::DtdDetected => "document type declaration is not permitted",
        XmlError::InvalidName(_) => "element or attribute name is not a valid XML name",
        XmlError::NonXmlChar(_, _) => "document contains a character XML does not allow",
        XmlError::InvalidChar(_, _, _) | XmlError::InvalidChar2(_, _, _) => {
            "unexpected character in markup"
        }
        XmlError::InvalidString(_, _) => "unexpected token in markup",
        XmlError::InvalidExternalID(_) => "external identifier is malformed",
        XmlError::InvalidComment(_) => "comment is malformed",
        XmlError::InvalidCharacterData(_) => "character data is malformed",
        XmlError::UnknownToken(_) => "unrecognized markup",
        XmlError::UnexpectedEndOfStream => "document ended before markup was complete",
    }
}

/// Assemble the canonical schema-violation diagnostic.
///
/// `category` is a compiled-in `&'static str` message, `location` a
/// [`safe_location`] result, and `keyword` a [`safe_keyword`] result. No
/// argument may carry payload bytes.
pub fn schema_violation_detail(category: &'static str, location: &str, keyword: &str) -> String {
    bound_detail(&format!("{category} at {location} (keyword '{keyword}')"))
}
