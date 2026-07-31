//! OpenAPI contract validation plugin.
//!
//! Validates request and response bodies against operation schemas extracted
//! from an attached OpenAPI document. All regexes, JSON Schema validators, and
//! compact schema type/shape metadata are compiled at plugin construction time;
//! request-time work is limited to operation matching, optional decompression,
//! media-type parsing, O(1) conversion metadata lookups, and schema validation.
//!
//! # Diagnostic confidentiality
//!
//! Violation details are written to two places with different audiences: the
//! client-visible problem body, and the `openapi_validator.request_error` /
//! `openapi_validator.response_error` metadata entries that every configured
//! logging plugin exports. Both are therefore built under the contract in
//! [`super::utils::validation_diagnostics`]: a compiled-in category, an
//! allowlisted JSON Schema keyword, and — request side only — a bounded
//! instance location whose object-member segments survive only when the
//! configured schema declares them as JSON property names. Numeric pointer
//! segments render as a fixed marker; raw schema paths (including `$defs`
//! names), configured XML names/namespaces, and hostile content-coding tokens
//! are never emitted.
//!
//! No conversion helper below formats a rejected scalar, a payload-chosen JSON
//! / XML / form / multipart member name, an `roxmltree` parse token, or a
//! `jsonschema` `Display` rendering into its error string
//! (`GHSA-5p2h-fq6q-gwh9`). `error_truncate_chars` bounds the size of the
//! result; it is not what makes it safe, and it cannot be raised into a
//! disclosure.

use ahash::AHashMap;
use async_trait::async_trait;
use regex::{Regex, RegexSet};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::types::OPENAPI_VALIDATOR_DEFAULT_CONTENT_TYPES;
use crate::util::json_dup_keys::{self, JsonScanMemo};
use crate::util::media_type::is_concrete_http_media_type;
use crate::util::unknown_keys::reject_unknown_keys;

use super::utils::content_encoding::{DecodeLimits, decode_content_encoding};
use super::utils::sse::{is_text_event_stream_media_type, original_response_is_event_stream};
use super::utils::validation_diagnostics::{
    MAX_DIAGNOSTIC_CHARS, SafeFieldNames, bound_detail, safe_keyword, safe_location,
    schema_violation_detail, xml_error_category,
};
use super::{HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext};

const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_ERROR_TRUNCATE_CHARS: usize = 1024;
/// Upper bound on stacked `Content-Encoding` layers decoded for validation.
/// Matches the shared content-coding decoder used elsewhere in the gateway.
const MAX_CONTENT_CODINGS: usize = 4;
/// Public, stable metadata key carrying the bypass/skip reason for loggers and
/// observability. It is write-only output; control flow recomputes bypass
/// decisions per instance so sibling instances cannot cross-apply a bypass
/// decision (see finding #17).
const SKIP_REASON_KEY: &str = "openapi_validator.skip_reason";
/// Public, stable metadata key recording WHICH representation the request
/// contract was decided over. `client` is the documented pre-transform client
/// contract; `backend_final` is the post-transform fallback that only runs when
/// the request never reached the client-contract phase (`GHSA-896v-jx23-9g6p`).
const CONTRACT_PHASE_KEY: &str = "openapi_validator.request_contract_phase";
/// Config key for the media-refusal status. Named once so the parse site stays
/// inside the line budget.
const UNSUPPORTED_MEDIA_STATUS_KEY: &str = "unsupported_media_type_status_code";
/// Fixed-cardinality XML conversion diagnostics.
///
/// None of these echoes a document-derived element name, attribute name, or
/// namespace URI: those are payload bytes, and this string is copied into both
/// the client-visible problem body and the exported transaction metadata
/// (`GHSA-5p2h-fq6q-gwh9`).
const XML_ATTRIBUTE_COLLISION_DETAIL: &str =
    "XML attribute collides with a modeled property name but does not match its modeled XML construct or namespace";
const XML_ELEMENT_COLLISION_DETAIL: &str =
    "XML element collides with a modeled property name but does not match its modeled XML construct or namespace";
const XML_DUPLICATE_ATTRIBUTE_DETAIL: &str =
    "XML attributes sharing a local name cannot be represented unambiguously";
const XML_ATTRIBUTE_ELEMENT_CONFLICT_DETAIL: &str =
    "XML attribute and element sharing a local name cannot be represented unambiguously";
const XML_NAMESPACE_CONFLICT_DETAIL: &str =
    "XML elements sharing a local name across namespaces cannot be represented unambiguously";
/// Fixed-cardinality multipart / scalar conversion diagnostics. Neither the
/// rejected value nor the payload-chosen part name is interpolated.
const MULTIPART_DISPOSITION_TYPE_DETAIL: &str =
    "Malformed multipart part: Content-Disposition type must be form-data";
const MULTIPART_FIELD_NOT_UTF8_DETAIL: &str = "Multipart field is not UTF-8";
const COMPOSED_SCALAR_CONVERSION_DETAIL: &str =
    "No compatible composed-schema scalar conversion for the supplied value";
const SCALAR_CONVERSION_DETAIL: &str = "Unsupported scalar conversion for the supplied value";
/// Fixed-cardinality detail for the unknown-operation class.
///
/// The request method and target are deliberately not interpolated: the detail
/// is copied into `RequestContext.metadata` for every logging sink, and a
/// request target can carry a credential in a path segment
/// (`GHSA-5p2h-fq6q-gwh9`). Loggers already record the method and path in their
/// own dedicated summary fields.
const UNMATCHED_OPERATION_DETAIL: &str = "No OpenAPI operation matched this request";
/// Fixed-cardinality media-refusal diagnostics. Neither echoes the received
/// `Content-Type` nor any byte of the rejected body.
const UNDECLARED_MEDIA_DETAIL: &str = "Request Content-Type is not declared for this operation";
const MISSING_MEDIA_DETAIL: &str =
    "Request body has no Content-Type and no declared media type applies";
static INSTANCE_ID_COUNTER: AtomicUsize = AtomicUsize::new(1);

/// Error prefix shared by every construction diagnostic.
const ERROR_PREFIX: &str = "openapi_validator: ";

/// Exhaustive fixed-field key sets. Every object below is a *fixed-field*
/// object: an unrecognized key is a typo that would otherwise silently select a
/// weaker default (GHSA-692x-352q-6gm8). Intentionally free-form maps -- media
/// type maps, response status maps, `bypass.header_present`, encoding property
/// maps, and JSON Schema values -- are structurally distinguished instead of
/// key-enumerated: their keys are validated for shape (media type, status key,
/// header name) rather than membership.
const CONFIG_KEYS: &[&str] = &[
    "enforcement_mode",
    "validate_request",
    "validate_response",
    "fail_on_unknown_operation",
    "fail_on_missing_response_schema",
    "max_body_bytes",
    "request_content_types",
    "response_content_types",
    "schema_draft",
    "operations",
    "bypass",
    "error_response",
    "error_truncate_chars",
];
const OPERATION_KEYS: &[&str] = &[
    "method",
    "path_template",
    "path_regex",
    "operation_label",
    "request_required",
    "request_body",
    "responses",
];
const BYPASS_KEYS: &[&str] = &["paths", "methods", "consumers", "header_present"];
const ERROR_RESPONSE_KEYS: &[&str] = &[
    "request_status_code",
    "response_status_code",
    UNSUPPORTED_MEDIA_STATUS_KEY,
    "content_type",
];
/// Alternate single-schema request-body form.
const REQUEST_BODY_INLINE_KEYS: &[&str] = &["content_type", "schema", "encoding"];
/// Canonical request-body form.
const REQUEST_BODY_CONTENT_KEYS: &[&str] = &["content"];
/// Media Type Object wrapper inside a content map.
const MEDIA_TYPE_OBJECT_KEYS: &[&str] = &["schema", "encoding"];
/// Fixed fields retained on a generated response object that carries `content`.
const RESPONSE_OBJECT_KEYS: &[&str] = &["description", "content"];
/// Schema-form Header Object fields. `style`/`explode`/`example`/`examples`
/// apply only when `schema` is selected. Common fields (`description`,
/// `required`, `deprecated`) are included here and in the content-form set.
const ENCODING_HEADER_OBJECT_SCHEMA_KEYS: &[&str] = &[
    "description",
    "required",
    "deprecated",
    "style",
    "explode",
    "schema",
    "example",
    "examples",
];

/// Content-form Header Object fields. Examples belong on the Media Type Object
/// inside `content`, not on the Header Object itself.
const ENCODING_HEADER_OBJECT_CONTENT_KEYS: &[&str] =
    &["description", "required", "deprecated", "content"];

/// Parameter-location fields that OpenAPI forbids on Header Objects
/// (`allowEmptyValue` is query-only; `allowReserved` is query-only).
const ENCODING_HEADER_OBJECT_INVALID_KEYS: &[&str] = &["allowEmptyValue", "allowReserved"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnforcementMode {
    Block,
    LogOnly,
    Disabled,
}

impl EnforcementMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::LogOnly => "log_only",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemaDraft {
    Auto,
    Draft7,
    Draft202012,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationSide {
    Request,
    Response,
}

/// Which representation a request-contract decision was taken over.
///
/// The two are deliberately distinct lifecycle phases, not two spellings of one
/// check. `Client` is the documented contract: the original client bytes after
/// gateway-owned `Content-Encoding` decoding and before any transform. `Backend`
/// is the pre-existing final-body hook, retained as a fallback when this
/// validator did not select over the pristine client view but can select over
/// the effective backend-visible view — an operation match or bypass state that
/// only materializes after a `before_proxy` route override or request
/// header/target rewrite. Disabling that fallback would be a silent downgrade
/// for those post-rewrite selections. Unknown-operation admission
/// (`fail_on_unknown_operation`) is rejected in `before_proxy` so it is not
/// reordered ahead of unrelated `before_proxy` hooks; the client phase
/// deliberately leaves unmatched operations undecided for that reason.
///
/// An HBONE CONNECT tunnel is NOT one of those paths. This plugin governs plain
/// HTTP request bodies; a CONNECT tunnel's bytes are not a request body, the
/// proxy skips request-body buffering for HBONE entirely, and it short-circuits
/// into `handle_hbone_request` immediately after `before_proxy` — before any
/// final-request-body hook — so neither phase ever observes tunnel bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestContractPhase {
    Client,
    Backend,
}

impl RequestContractPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Backend => "backend_final",
        }
    }
}

struct OperationEntry {
    operation_label: String,
    literal_segments: u16,
    request_validators: AHashMap<String, MediaValidator>,
    request_required: bool,
    response_validators: ResponseValidators,
}

struct OperationBucket {
    path_regexes: RegexSet,
    entries: Vec<OperationEntry>,
}

struct MediaValidator {
    schema: Arc<Value>,
    validator: jsonschema::Validator,
    conversion: ConversionPlan,
    /// Per-property OpenAPI Encoding Objects for form-urlencoded / multipart.
    encoding: AHashMap<String, PropertyEncoding>,
    /// Member names declared by this media entry's schema. Only these may be
    /// rendered into a violation location; every other instance-path segment is
    /// payload-derived and is redacted (`GHSA-5p2h-fq6q-gwh9`).
    safe_names: SafeFieldNames,
}

#[derive(Default)]
struct ConversionPlan {
    /// Compact type/shape metadata keyed by schema pointer. Populated once per
    /// registered schema node during compile; request conversion uses O(1)
    /// lookups instead of re-walking `allOf`/`oneOf`/`anyOf` graphs.
    schema_types: AHashMap<usize, SchemaTypeSet>,
    object_schemas: AHashMap<usize, Arc<Value>>,
    array_item_schemas: AHashMap<usize, Arc<Value>>,
    composed_scalar_validators: AHashMap<usize, jsonschema::Validator>,
    pattern_property_schemas: AHashMap<usize, Vec<(Regex, Arc<Value>)>>,
    /// Cache-miss computes for synthetic/unregistered schemas. Registered
    /// request-path lookups must keep this at zero.
    fallback_type_computes: AtomicUsize,
}

impl ConversionPlan {
    fn compile(root: &Value, schema_draft: SchemaDraft) -> Result<Self, String> {
        let mut plan = Self::default();
        let mut visited = HashSet::new();
        plan.register_schema(root, schema_draft, &mut visited, 0)?;
        Ok(plan)
    }

    fn register_schema(
        &mut self,
        schema: &Value,
        schema_draft: SchemaDraft,
        visited: &mut HashSet<usize>,
        depth: usize,
    ) -> Result<(), String> {
        if depth > 64 {
            return Err("conversion schema nesting exceeds 64 levels".to_string());
        }
        let key = schema as *const Value as usize;
        if !visited.insert(key) {
            return Ok(());
        }

        let types = collect_schema_types(schema);
        self.schema_types.insert(key, types);

        if schema_is_composed(schema) {
            if types.has_scalar_primitive() {
                let validator = compile_schema(schema, schema_draft)
                    .map_err(|error| format!("invalid composed scalar schema: {error}"))?;
                self.composed_scalar_validators.insert(key, validator);
            }
            if types.contains(ScalarType::Object) {
                let merged = Arc::new(build_object_schema_for_conversion(schema));
                self.object_schemas.insert(key, Arc::clone(&merged));
                self.register_schema(merged.as_ref(), schema_draft, visited, depth + 1)?;
            }
            if types.contains(ScalarType::Array) {
                let items = Arc::new(build_array_item_schema_for_conversion(schema));
                self.array_item_schemas.insert(key, Arc::clone(&items));
                self.register_schema(items.as_ref(), schema_draft, visited, depth + 1)?;
            }
        }

        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for child in properties.values() {
                self.register_schema(child, schema_draft, visited, depth + 1)?;
            }
        }
        if let Some(patterns) = schema.get("patternProperties").and_then(Value::as_object) {
            let mut compiled = Vec::with_capacity(patterns.len());
            for (pattern, child) in patterns {
                let regex = Regex::new(pattern).map_err(|error| {
                    format!("invalid patternProperties regex '{pattern}': {error}")
                })?;
                let child = Arc::new(child.clone());
                self.register_schema(child.as_ref(), schema_draft, visited, depth + 1)?;
                compiled.push((regex, child));
            }
            self.pattern_property_schemas.insert(key, compiled);
        }
        for keyword in ["items", "additionalProperties"] {
            if let Some(child) = schema.get(keyword).filter(|child| child.is_object()) {
                self.register_schema(child, schema_draft, visited, depth + 1)?;
            }
        }
        for keyword in ["allOf", "oneOf", "anyOf"] {
            if let Some(children) = schema.get(keyword).and_then(Value::as_array) {
                for child in children {
                    self.register_schema(child, schema_draft, visited, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    fn schema_types(&self, schema: &Value) -> SchemaTypeSet {
        let key = schema as *const Value as usize;
        if let Some(types) = self.schema_types.get(&key) {
            return *types;
        }
        // Synthetic/unregistered schemas (for example temporary Null placeholders)
        // fall back to a one-shot compute; registered request-path schemas hit the
        // map above and never allocate or re-walk composition here.
        self.fallback_type_computes.fetch_add(1, Ordering::Relaxed);
        collect_schema_types(schema)
    }

    fn cached_schema_type_nodes(&self) -> usize {
        self.schema_types.len()
    }

    fn fallback_type_computes(&self) -> usize {
        self.fallback_type_computes.load(Ordering::Relaxed)
    }

    fn accepts_object(&self, schema: &Value) -> bool {
        self.schema_types(schema).contains(ScalarType::Object)
    }

    fn accepts_array(&self, schema: &Value) -> bool {
        self.schema_types(schema).contains(ScalarType::Array)
    }

    fn object_schema<'a>(&'a self, schema: &'a Value) -> &'a Value {
        self.object_schemas
            .get(&(schema as *const Value as usize))
            .map(Arc::as_ref)
            .unwrap_or(schema)
    }

    fn array_item_schema<'a>(&'a self, schema: &'a Value) -> &'a Value {
        self.array_item_schemas
            .get(&(schema as *const Value as usize))
            .map(Arc::as_ref)
            .or_else(|| schema.get("items"))
            .unwrap_or(&Value::Null)
    }

    fn composed_scalar_validator(&self, schema: &Value) -> Option<&jsonschema::Validator> {
        self.composed_scalar_validators
            .get(&(schema as *const Value as usize))
    }

    fn pattern_property_schema<'a>(
        &'a self,
        schema: &Value,
        property_name: &str,
    ) -> Option<&'a Value> {
        let mut first_match = None;
        for (pattern, child) in self
            .pattern_property_schemas
            .get(&(schema as *const Value as usize))?
        {
            if !pattern.is_match(property_name) {
                continue;
            }
            let child = child.as_ref();
            if first_match.is_none() {
                first_match = Some(child);
            }
            if !self.schema_types(child).is_empty() {
                return Some(child);
            }
        }
        first_match
    }
}

/// Supported OpenAPI Encoding Object `style` values for request bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodingStyle {
    Form,
    SpaceDelimited,
    PipeDelimited,
    DeepObject,
}

struct PropertyEncoding {
    style: EncodingStyle,
    explode: bool,
    /// Whether URI-reserved bytes may appear literally in an encoded form value.
    /// When false (the default), reserved bytes must be percent-encoded.
    allow_reserved: bool,
    content_type: Option<String>,
    /// Additional multipart part-header schemas (OpenAPI Header Objects / schemas).
    headers: AHashMap<String, EncodingHeaderValidator>,
}

struct EncodingHeaderValidator {
    required: bool,
    schema: Value,
    /// Precomputed at admission so header scalar conversion never re-walks.
    schema_types: SchemaTypeSet,
    validator: jsonschema::Validator,
    /// When set, the header value is decoded as this single Media Type Object
    /// media type before schema validation (OpenAPI Header Object `content`).
    content_media_type: Option<String>,
    /// Conversion plan for structured `content` decoding (JSON/XML/text/…).
    conversion: ConversionPlan,
    /// Declared member names for safe violation locations
    /// (`GHSA-5p2h-fq6q-gwh9`).
    safe_names: SafeFieldNames,
}

/// Hostile-input caps for multipart parsing (RFC 2046 / RFC 7578).
const MAX_MULTIPART_BOUNDARY_LEN: usize = 70;
const MAX_MULTIPART_PARTS: usize = 1024;
const MAX_MULTIPART_HEADER_BYTES: usize = 8 * 1024;
const MAX_MULTIPART_HEADER_LINES: usize = 64;
const MAX_MULTIPART_PARAM_BYTES: usize = 4 * 1024;

#[derive(Default)]
struct ResponseValidators {
    exact: AHashMap<u16, AHashMap<String, MediaValidator>>,
    ranges: Vec<ResponseRangeValidators>,
    default: Option<AHashMap<String, MediaValidator>>,
}

struct ResponseRangeValidators {
    start: u16,
    end: u16,
    validators: AHashMap<String, MediaValidator>,
}

struct ParsedOperation {
    method: String,
    path_regex: String,
    entry: OperationEntry,
}

struct OperationMatch<'a> {
    entry: &'a OperationEntry,
}

impl OperationEntry {
    fn has_request_schema(&self) -> bool {
        !self.request_validators.is_empty()
    }

    fn has_response_schema(&self) -> bool {
        !self.response_validators.is_empty()
    }

    fn select_response(&self, status: u16, content_type: Option<&str>) -> ResponseSelection<'_> {
        self.response_validators.select(status, content_type)
    }
}

/// Outcome of OpenAPI response-object selection.
///
/// Selection is status-first: an exact status declaration precludes range
/// (`4XX`) and `default` fallback, because `default` covers status codes that
/// are *not otherwise declared*. Media selection then happens only inside the
/// selected response object, so a media miss can never reach another response
/// object's schema (GHSA-cjqx-p554-5rx9).
enum ResponseSelection<'a> {
    /// A response object was selected and one of its media entries matched.
    Media(&'a MediaValidator),
    /// A response object was selected but none of its media entries matched.
    MediaMismatch,
    /// A response object was selected and declares no content at all.
    NoContentDeclared,
    /// No response object covers this status.
    NoResponseObject,
}

impl ResponseValidators {
    fn is_empty(&self) -> bool {
        self.exact.values().all(|validators| validators.is_empty())
            && self.ranges.iter().all(|range| range.validators.is_empty())
            && self
                .default
                .as_ref()
                .is_none_or(|validators| validators.is_empty())
    }

    /// Select the response object by status, then the media entry inside it.
    ///
    /// Precedence is exact status, then the narrowest declared range, then
    /// `default`. A miss on media type inside the selected object never falls
    /// through to a less specific response object.
    fn select(&self, status: u16, content_type: Option<&str>) -> ResponseSelection<'_> {
        let selected = self
            .exact
            .get(&status)
            .or_else(|| {
                self.ranges
                    .iter()
                    .filter(|range| (range.start..=range.end).contains(&status))
                    .min_by_key(|range| range.end.saturating_sub(range.start))
                    .map(|range| &range.validators)
            })
            .or(self.default.as_ref());
        let Some(validators) = selected else {
            return ResponseSelection::NoResponseObject;
        };
        if validators.is_empty() {
            return ResponseSelection::NoContentDeclared;
        }
        match validator_for_content_type(validators, content_type) {
            Some(validator) => ResponseSelection::Media(validator),
            None => ResponseSelection::MediaMismatch,
        }
    }
}

pub struct OpenapiValidator {
    instance_id: usize,
    mode: EnforcementMode,
    validate_request: bool,
    validate_response: bool,
    fail_on_unknown_operation: bool,
    fail_on_missing_response_schema: bool,
    max_body_bytes: usize,
    request_content_types: Vec<String>,
    response_content_types: Vec<String>,
    ops_by_method: AHashMap<String, OperationBucket>,
    has_any_request_schema: bool,
    /// At least one operation declares `request_required`. Presence enforcement
    /// is independent of any declared media type, so a document that declares a
    /// required body with an empty content map still has to buffer.
    has_any_required_request_body: bool,
    has_any_response_schema: bool,
    bypass_paths: Option<RegexSet>,
    bypass_methods: HashSet<String>,
    bypass_consumers: HashSet<String>,
    bypass_header_present: HashMap<String, Option<String>>,
    request_error_status: u16,
    response_error_status: u16,
    /// Status for a nonempty client representation that no declared media entry
    /// of the matched operation covers. Protocol-appropriate 415 by default,
    /// kept distinct from `request_error_status` so an operator who remapped
    /// schema failures does not also remap media-type refusals
    /// (`GHSA-6p78-6x8c-9g9x`).
    request_unsupported_media_status: u16,
    error_content_type: String,
    error_truncate_chars: usize,
}

impl OpenapiValidator {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "openapi_validator: config must be an object".to_string())?;
        // Fail closed on typos before any default is applied: a misspelled
        // enforcement control would otherwise construct successfully with the
        // weaker default still in force (GHSA-692x-352q-6gm8).
        reject_unknown_keys(object, "config", CONFIG_KEYS, ERROR_PREFIX)?;

        let mode = parse_mode(optional_string(object, "enforcement_mode")?.unwrap_or("block"))?;
        let validate_request = optional_bool(object, "validate_request")?.unwrap_or(true);
        let validate_response = optional_bool(object, "validate_response")?.unwrap_or(true);
        let fail_on_unknown_operation =
            optional_bool(object, "fail_on_unknown_operation")?.unwrap_or(true);
        let fail_on_missing_response_schema =
            optional_bool(object, "fail_on_missing_response_schema")?.unwrap_or(false);
        let max_body_bytes =
            optional_usize(object, "max_body_bytes")?.unwrap_or(DEFAULT_MAX_BODY_BYTES);
        if max_body_bytes == 0 {
            return Err(
                "openapi_validator: 'max_body_bytes' must be greater than zero".to_string(),
            );
        }
        let request_content_types = normalize_configured_media_types(
            optional_string_vec(object, "request_content_types")?
                .unwrap_or_else(default_content_types),
            "request_content_types",
        )?;
        let response_content_types = normalize_configured_media_types(
            optional_string_vec(object, "response_content_types")?
                .unwrap_or_else(default_content_types),
            "response_content_types",
        )?;
        let schema_draft =
            parse_schema_draft(optional_string(object, "schema_draft")?.unwrap_or("auto"))?;

        let operations_value = object
            .get("operations")
            .ok_or_else(|| "openapi_validator: 'operations' is required".to_string())?;
        let operations = operations_value
            .as_array()
            .ok_or_else(|| "openapi_validator: 'operations' must be an array".to_string())?;
        if operations.is_empty() {
            return Err("openapi_validator: 'operations' must not be empty".to_string());
        }

        let mut grouped_ops: AHashMap<String, Vec<(String, OperationEntry)>> = AHashMap::new();
        let mut has_any_request_schema = false;
        let mut has_any_required_request_body = false;
        let mut has_any_response_schema = false;
        for (index, operation) in operations.iter().enumerate() {
            let parsed = parse_operation(operation, index, schema_draft)?;
            has_any_request_schema |= parsed.entry.has_request_schema();
            has_any_required_request_body |= parsed.entry.request_required;
            has_any_response_schema |= parsed.entry.has_response_schema();
            grouped_ops
                .entry(parsed.method)
                .or_default()
                .push((parsed.path_regex, parsed.entry));
        }
        let mut ops_by_method: AHashMap<String, OperationBucket> = AHashMap::new();
        for (method, mut entries) in grouped_ops {
            entries.sort_by(|(_, left), (_, right)| {
                right
                    .literal_segments
                    .cmp(&left.literal_segments)
                    .then_with(|| right.operation_label.len().cmp(&left.operation_label.len()))
            });
            let patterns = entries.iter().map(|(pattern, _)| pattern.as_str());
            let path_regexes = RegexSet::new(patterns).map_err(|error| {
                format!("openapi_validator: failed to compile path regex set for {method}: {error}")
            })?;
            let entries = entries.into_iter().map(|(_, entry)| entry).collect();
            ops_by_method.insert(
                method,
                OperationBucket {
                    path_regexes,
                    entries,
                },
            );
        }
        if !has_any_request_schema
            && !has_any_required_request_body
            && !has_any_response_schema
            && !fail_on_unknown_operation
        {
            return Err(
                "openapi_validator: no validation rules configured -- provide request or response schemas"
                    .to_string(),
            );
        }

        let bypass = optional_object(object, "bypass")?;
        if let Some(bypass) = bypass {
            reject_unknown_keys(bypass, "config.bypass", BYPASS_KEYS, ERROR_PREFIX)?;
        }
        let bypass_paths = parse_regex_set(bypass.and_then(|b| b.get("paths")), "bypass.paths")?;
        let bypass_methods = optional_string_vec_from_object(bypass, "methods")?
            .unwrap_or_default()
            .into_iter()
            .map(|method| method.to_ascii_uppercase())
            .collect();
        let bypass_consumers = optional_string_vec_from_object(bypass, "consumers")?
            .unwrap_or_default()
            .into_iter()
            .collect();
        let bypass_header_present =
            parse_header_present(bypass.and_then(|b| b.get("header_present")))?;

        let error_response = optional_object(object, "error_response")?;
        if let Some(error_response) = error_response {
            reject_unknown_keys(
                error_response,
                "config.error_response",
                ERROR_RESPONSE_KEYS,
                ERROR_PREFIX,
            )?;
        }
        let request_error_status =
            optional_u16_from_object(error_response, "request_status_code")?.unwrap_or(400);
        let response_error_status =
            optional_u16_from_object(error_response, "response_status_code")?.unwrap_or(502);
        let request_unsupported_media_status =
            optional_u16_from_object(error_response, UNSUPPORTED_MEDIA_STATUS_KEY)?.unwrap_or(415);
        validate_status(request_error_status, "error_response.request_status_code")?;
        validate_status(response_error_status, "error_response.response_status_code")?;
        validate_status(
            request_unsupported_media_status,
            "error_response.unsupported_media_type_status_code",
        )?;
        let error_content_type = optional_string_from_object(error_response, "content_type")?
            .unwrap_or_else(|| "application/problem+json".to_string());
        validate_concrete_media_type(&error_content_type, "error_response.content_type")?;
        // Accepted for compatibility, but only ever narrows: the effective cap
        // is `min(configured, MAX_DIAGNOSTIC_CHARS)`. Raising it can no longer
        // widen a disclosure, because diagnostics carry no payload bytes to
        // reveal (`GHSA-5p2h-fq6q-gwh9`).
        let error_truncate_chars =
            optional_usize(object, "error_truncate_chars")?.unwrap_or(DEFAULT_ERROR_TRUNCATE_CHARS);

        Ok(Self {
            instance_id: INSTANCE_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            mode,
            validate_request,
            validate_response,
            fail_on_unknown_operation,
            fail_on_missing_response_schema,
            max_body_bytes,
            request_content_types,
            response_content_types,
            ops_by_method,
            has_any_request_schema,
            has_any_required_request_body,
            has_any_response_schema,
            bypass_paths,
            bypass_methods,
            bypass_consumers,
            bypass_header_present,
            request_error_status,
            response_error_status,
            request_unsupported_media_status,
            error_content_type,
            error_truncate_chars,
        })
    }

    /// External-test seam: `(cached schema-type nodes, request-time fallback computes)`.
    /// Cached nodes are populated once per registered schema during compile;
    /// fallback computes must stay zero for registered form/multipart conversion.
    #[allow(dead_code)] // reached via `_test_support` from the external test crate
    pub(crate) fn schema_type_cache_stats_for_test(&self) -> (usize, usize) {
        let mut cached_nodes = 0usize;
        let mut fallback_computes = 0usize;
        for bucket in self.ops_by_method.values() {
            for entry in &bucket.entries {
                for media in entry.request_validators.values() {
                    cached_nodes =
                        cached_nodes.saturating_add(media.conversion.cached_schema_type_nodes());
                    fallback_computes =
                        fallback_computes.saturating_add(media.conversion.fallback_type_computes());
                }
                for media in entry
                    .response_validators
                    .exact
                    .values()
                    .flat_map(|validators| validators.values())
                {
                    cached_nodes =
                        cached_nodes.saturating_add(media.conversion.cached_schema_type_nodes());
                    fallback_computes =
                        fallback_computes.saturating_add(media.conversion.fallback_type_computes());
                }
                for range in &entry.response_validators.ranges {
                    for media in range.validators.values() {
                        cached_nodes = cached_nodes
                            .saturating_add(media.conversion.cached_schema_type_nodes());
                        fallback_computes = fallback_computes
                            .saturating_add(media.conversion.fallback_type_computes());
                    }
                }
                if let Some(default) = &entry.response_validators.default {
                    for media in default.values() {
                        cached_nodes = cached_nodes
                            .saturating_add(media.conversion.cached_schema_type_nodes());
                        fallback_computes = fallback_computes
                            .saturating_add(media.conversion.fallback_type_computes());
                    }
                }
            }
        }
        (cached_nodes, fallback_computes)
    }

    fn active(&self) -> bool {
        self.mode != EnforcementMode::Disabled
    }

    fn match_operation(&self, method: &str, path: &str) -> Option<OperationMatch<'_>> {
        let (_, bucket) = self
            .ops_by_method
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(method))?;
        let index = bucket.path_regexes.matches(path).into_iter().next()?;
        bucket
            .entries
            .get(index)
            .map(|entry| OperationMatch { entry })
    }

    fn operation_for_context<'a>(&'a self, ctx: &RequestContext) -> Option<&'a OperationEntry> {
        if let Some((method, path)) = ctx.openapi_validator_matches.get(&self.instance_id) {
            return self
                .match_operation(method, path)
                .map(|matched| matched.entry);
        }
        self.match_operation(&ctx.method, &ctx.path)
            .map(|matched| matched.entry)
    }

    fn mark_operation(&self, ctx: &mut RequestContext, operation: OperationMatch<'_>) {
        self.mark_operation_entry(ctx, operation.entry);
    }

    fn mark_operation_entry(&self, ctx: &mut RequestContext, operation: &OperationEntry) {
        self.mark_mode(ctx);
        ctx.openapi_validator_matches
            .entry(self.instance_id)
            .or_insert_with(|| (ctx.method.clone(), ctx.path.clone()));
        ctx.metadata.insert(
            "openapi_validator.matched_operation".to_string(),
            operation.operation_label.clone(),
        );
    }

    fn bypass_reason_for_headers(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> Option<&'static str> {
        if self
            .bypass_paths
            .as_ref()
            .is_some_and(|paths| paths.is_match(&ctx.path))
        {
            return Some("bypass_path");
        }
        if self
            .bypass_methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(&ctx.method))
        {
            return Some("bypass_method");
        }
        if let Some(identity) = ctx.effective_identity()
            && self.bypass_consumers.contains(identity)
        {
            return Some("bypass_consumer");
        }
        if self.bypass_header_present.iter().any(|(name, expected)| {
            header_value(headers, name).is_some_and(|actual| {
                expected
                    .as_deref()
                    .is_none_or(|expected| actual == expected)
            })
        }) {
            return Some("bypass_header");
        }
        None
    }

    fn bypass_reason(&self, ctx: &RequestContext) -> Option<&'static str> {
        self.bypass_reason_for_headers(ctx, &ctx.headers)
    }

    fn mark_mode(&self, ctx: &mut RequestContext) {
        ctx.metadata.insert(
            "openapi_validator.mode".to_string(),
            self.mode.as_str().to_string(),
        );
    }

    fn mark_skip(&self, ctx: &mut RequestContext, reason: &'static str) {
        self.mark_mode(ctx);
        ctx.openapi_validator_matches.remove(&self.instance_id);
        // Public key for loggers/observability (last writer wins across
        // instances; this is output only).
        ctx.metadata
            .insert(SKIP_REASON_KEY.to_string(), reason.to_string());
    }

    fn handle_violation(
        &self,
        ctx: &mut RequestContext,
        side: ValidationSide,
        operation_label: Option<&str>,
        detail: String,
    ) -> PluginResult {
        self.handle_violation_with_status(ctx, side, operation_label, detail, None)
    }

    /// `status_override` selects a protocol-appropriate status for a violation
    /// class that is not a schema failure (currently only "no declared media
    /// type covers this representation" → 415). `None` keeps the configured
    /// per-side status.
    ///
    /// Every `detail` reaching this function is payload-free by construction
    /// (`GHSA-5p2h-fq6q-gwh9`): callers assemble it from compiled-in categories,
    /// allowlisted JSON Schema keywords, and [`safe_location`] output. That
    /// matters because the same string lands in two places with different
    /// audiences — the client-visible problem body and the
    /// `openapi_validator.request_error` / `.response_error` metadata entries,
    /// which every configured logging plugin exports. `truncate_chars` bounds
    /// the size; it is not what makes the value safe.
    fn handle_violation_with_status(
        &self,
        ctx: &mut RequestContext,
        side: ValidationSide,
        operation_label: Option<&str>,
        detail: String,
        status_override: Option<u16>,
    ) -> PluginResult {
        self.mark_mode(ctx);
        if let Some(label) = operation_label {
            ctx.metadata.insert(
                "openapi_validator.matched_operation".to_string(),
                label.to_string(),
            );
        }

        let detail = truncate_chars(&detail, self.error_truncate_chars);
        let error_key = match side {
            ValidationSide::Request => "openapi_validator.request_error",
            ValidationSide::Response => "openapi_validator.response_error",
        };
        ctx.metadata.insert(error_key.to_string(), detail.clone());

        match self.mode {
            EnforcementMode::Block => {
                let (status_code, action, title) = match side {
                    ValidationSide::Request => (
                        status_override.unwrap_or(self.request_error_status),
                        "rejected_request",
                        "Request body validation failed",
                    ),
                    ValidationSide::Response => (
                        status_override.unwrap_or(self.response_error_status),
                        "rejected_response",
                        "Response body validation failed",
                    ),
                };
                ctx.metadata
                    .insert("openapi_validator.action".to_string(), action.to_string());
                PluginResult::Reject {
                    status_code,
                    body: serde_json::json!({
                        "type": "about:blank",
                        "title": title,
                        "status": status_code,
                        "detail": detail,
                        "operation": operation_label,
                    })
                    .to_string(),
                    headers: HashMap::from([(
                        "content-type".to_string(),
                        self.error_content_type.clone(),
                    )]),
                }
            }
            EnforcementMode::LogOnly => {
                let action = match side {
                    ValidationSide::Request => "logged_request_mismatch",
                    ValidationSide::Response => "logged_response_mismatch",
                };
                ctx.metadata
                    .insert("openapi_validator.action".to_string(), action.to_string());
                PluginResult::Continue
            }
            EnforcementMode::Disabled => PluginResult::Continue,
        }
    }

    /// Strict-mode outcome when the response contract selected no schema.
    ///
    /// `fail_on_missing_response_schema` covers missing, out-of-scope, and
    /// unmatched content types after status selection; permissive mode records
    /// the skip reason and continues (GHSA-cjqx-p554-5rx9).
    fn missing_response_schema(
        &self,
        ctx: &mut RequestContext,
        operation: &OperationEntry,
        skip_reason: &'static str,
        detail: String,
    ) -> PluginResult {
        if self.fail_on_missing_response_schema {
            return self.handle_violation(
                ctx,
                ValidationSide::Response,
                Some(&operation.operation_label),
                detail,
            );
        }
        self.mark_skip(ctx, skip_reason);
        PluginResult::Continue
    }

    fn request_validator<'a>(
        &'a self,
        operation: &'a OperationEntry,
        content_type: Option<&str>,
    ) -> Option<&'a MediaValidator> {
        if !content_type_in_scope(&self.request_content_types, content_type) {
            return None;
        }
        validator_for_content_type(&operation.request_validators, content_type)
    }

    /// Whether this operation carries anything for the request contract to
    /// enforce: a declared media schema, or a declared presence requirement.
    fn operation_has_request_contract(operation: &OperationEntry) -> bool {
        operation.has_request_schema() || operation.request_required
    }

    /// Record that THIS instance took its request-contract decision in the
    /// client phase, so its backend-final fallback stays inert. Keyed by the
    /// process-unique instance ID: sibling instances never share the entry.
    fn mark_decided(&self, ctx: &mut RequestContext, phase: RequestContractPhase) {
        if phase == RequestContractPhase::Client {
            ctx.openapi_validator_client_contract_enforced
                .insert(self.instance_id);
        }
    }

    /// The single request-contract decision, shared by the client-contract phase
    /// and the backend-final fallback so the two can never diverge.
    ///
    /// Fail-closed rules, all independent of anything a client can simply omit:
    ///
    /// - an empty body for a `request_required` operation is a violation;
    /// - a NONEMPTY body that no declared media entry of the operation covers is
    ///   an unsupported-media violation (415 by default) rather than a silent
    ///   continue — including when the body was buffered because some *other*
    ///   plugin voted for it (`GHSA-6p78-6x8c-9g9x`);
    /// - a declared media entry that the operator excluded from
    ///   `request_content_types` is an explicit inspection opt-out and records
    ///   `content_type_out_of_scope` instead of failing closed.
    ///
    /// Diagnostics for the media-refusal class are fixed-cardinality: they never
    /// echo the received `Content-Type` or any byte of the rejected body.
    fn enforce_request_contract(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
        phase: RequestContractPhase,
    ) -> PluginResult {
        if !self.requires_request_body_buffering() {
            return PluginResult::Continue;
        }
        if let Some(reason) = self.bypass_reason_for_headers(ctx, headers) {
            self.mark_decided(ctx, phase);
            self.mark_skip(ctx, reason);
            return PluginResult::Continue;
        }
        let Some(operation) = self.operation_for_context(ctx) else {
            if phase == RequestContractPhase::Client {
                // Unknown-operation admission belongs to `before_proxy`, which
                // runs immediately after this phase. Deciding it here as well
                // would move that rejection ahead of unrelated `before_proxy`
                // hooks and leave the backend fallback with nothing to do.
                return PluginResult::Continue;
            }
            if self.fail_on_unknown_operation {
                return self.handle_violation(
                    ctx,
                    ValidationSide::Request,
                    None,
                    UNMATCHED_OPERATION_DETAIL.to_string(),
                );
            }
            self.mark_skip(ctx, "no_match");
            return PluginResult::Continue;
        };
        // The shared runner is activated when at least one effective plugin
        // instance selected the client-contract phase. A sibling instance can
        // still match a response-only operation on this request. That sibling
        // has taken no request-contract decision and must remain eligible for
        // the backend-final fallback if a later before_proxy rewrite selects
        // one of its request-contract operations.
        if !Self::operation_has_request_contract(operation) {
            return PluginResult::Continue;
        }
        self.mark_decided(ctx, phase);
        self.mark_operation_entry(ctx, operation);
        ctx.metadata
            .insert(CONTRACT_PHASE_KEY.to_string(), phase.as_str().to_string());
        if body.is_empty() {
            return if operation.request_required {
                self.handle_violation(
                    ctx,
                    ValidationSide::Request,
                    Some(&operation.operation_label),
                    "Required request body is missing".to_string(),
                )
            } else {
                PluginResult::Continue
            };
        }
        if !operation.has_request_schema() {
            // Presence-only declaration: a nonempty body satisfies it and the
            // document declares no media entry to select.
            return PluginResult::Continue;
        }
        let content_type = header_value(headers, "content-type");
        if validator_for_content_type(&operation.request_validators, content_type).is_none() {
            return self.handle_violation_with_status(
                ctx,
                ValidationSide::Request,
                Some(&operation.operation_label),
                if content_type.is_some() {
                    UNDECLARED_MEDIA_DETAIL.to_string()
                } else {
                    MISSING_MEDIA_DETAIL.to_string()
                },
                Some(self.request_unsupported_media_status),
            );
        }
        let Some(validator) = self.request_validator(operation, content_type) else {
            // Declared by the document but excluded from the configured
            // inspection scope: an explicit operator opt-out, not a bypass a
            // client can choose.
            self.mark_skip(ctx, "content_type_out_of_scope");
            return PluginResult::Continue;
        };
        let result = validate_media_body(
            headers,
            body,
            content_type,
            validator,
            self.max_body_bytes,
            ValidationSide::Request,
            Some(&mut ctx.json_scan_memo),
        );
        match result {
            Ok(()) => PluginResult::Continue,
            Err(error) => self.handle_violation(
                ctx,
                ValidationSide::Request,
                Some(&operation.operation_label),
                error,
            ),
        }
    }
}

#[async_trait]
impl Plugin for OpenapiValidator {
    fn name(&self) -> &str {
        "openapi_validator"
    }

    fn priority(&self) -> u16 {
        super::priority::OPENAPI_VALIDATOR
    }

    /// The request contract is normally decided in
    /// `validate_client_request_body_contract`, over the original client
    /// representation (`GHSA-896v-jx23-9g6p`). This declaration is about the
    /// phase that remains: `on_final_request_body` is still a backend-contract
    /// fallback that can reject the exact backend-visible representation when
    /// this instance did not decide in the client phase, and the response side
    /// always decides over the final body. Composition admission therefore
    /// still refuses to pair this plugin with one that egresses the request
    /// before finalization (GHSA-4vr5-4wm3-x5xv).
    fn enforces_finalized_request_policy(&self) -> bool {
        true
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        HTTP_ONLY_PROTOCOLS
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.active() {
            self.mark_mode(ctx);
            return PluginResult::Continue;
        }
        if let Some(reason) = self.bypass_reason_for_headers(ctx, headers) {
            self.mark_skip(ctx, reason);
            return PluginResult::Continue;
        }
        match self.match_operation(&ctx.method, &ctx.path) {
            Some(operation) => {
                self.mark_operation(ctx, operation);
                PluginResult::Continue
            }
            None if self.fail_on_unknown_operation => self.handle_violation(
                ctx,
                ValidationSide::Request,
                None,
                UNMATCHED_OPERATION_DETAIL.to_string(),
            ),
            None => {
                self.mark_skip(ctx, "no_match");
                PluginResult::Continue
            }
        }
    }

    fn requires_request_body_buffering(&self) -> bool {
        self.active()
            && self.validate_request
            && (self.has_any_request_schema || self.has_any_required_request_body)
    }

    /// The client contract is decided before `before_proxy`, so the buffer has
    /// to exist by then (`GHSA-896v-jx23-9g6p`).
    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.requires_request_body_buffering()
    }

    fn validates_client_request_body_contract(&self) -> bool {
        self.requires_request_body_buffering()
    }

    /// Every body hook here takes `&[u8]`; nothing reads
    /// `ctx.metadata["request_body"]`. Pulling the pre-`before_proxy` buffer
    /// forward must not start retaining a second full UTF-8 copy of every
    /// validated request body.
    fn needs_request_body_text(&self) -> bool {
        false
    }

    /// Buffering is selected from the matched operation alone.
    ///
    /// It deliberately does NOT consult the received `Content-Type` and does not
    /// exclude methods by name: a client that omits, misspells, or mismatches a
    /// representation hint would otherwise vote this validator out of the
    /// request and make every declared constraint inert
    /// (`GHSA-6p78-6x8c-9g9x`). Whatever the imported document declares for an
    /// operation is enforced for that operation, and the bytes retained stay
    /// bounded by Ferrum's global/route request-body ceilings.
    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if !self.requires_request_body_buffering() || self.bypass_reason(ctx).is_some() {
            return false;
        }
        self.operation_for_context(ctx)
            .is_some_and(Self::operation_has_request_contract)
    }

    async fn validate_client_request_body_contract(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.enforce_request_contract(ctx, headers, body, RequestContractPhase::Client)
    }

    fn needs_final_request_body_context(&self) -> bool {
        true
    }

    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if ctx
            .openapi_validator_client_contract_enforced
            .contains(&self.instance_id)
        {
            // This instance already decided the contract over the original
            // client representation. Deciding again here would validate
            // gateway-synthesized data and double-charge the rejection.
            return PluginResult::Continue;
        }
        self.enforce_request_contract(ctx, headers, body, RequestContractPhase::Backend)
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.active()
            && self.validate_response
            && (self.has_any_response_schema || self.fail_on_missing_response_schema)
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.requires_response_body_buffering()
            && self.bypass_reason(ctx).is_none()
            && self.operation_for_context(ctx).is_some_and(|operation| {
                operation.has_response_schema() || self.fail_on_missing_response_schema
            })
    }

    fn should_process_empty_synthetic_response_body(
        &self,
        ctx: &RequestContext,
        response_status: u16,
    ) -> bool {
        !response_has_no_body_semantics(&ctx.method, response_status)
    }

    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        self.should_buffer_response_body(ctx)
    }

    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && original_response_is_event_stream(ctx, response_headers)
    }

    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && original_response_is_event_stream(ctx, response_headers)
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && !content_type.is_some_and(is_text_event_stream_media_type)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if self.should_buffer_response_body(ctx)
            && original_response_is_event_stream(ctx, response_headers)
        {
            let operation_label = self
                .operation_for_context(ctx)
                .map(|operation| operation.operation_label.as_str());
            return self.handle_violation(
                ctx,
                ValidationSide::Response,
                operation_label,
                "event-stream responses require a bounded streaming validator".to_string(),
            );
        }
        PluginResult::Continue
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.requires_response_body_buffering() {
            return PluginResult::Continue;
        }
        if let Some(reason) = self.bypass_reason(ctx) {
            self.mark_skip(ctx, reason);
            return PluginResult::Continue;
        }
        let Some(operation) = self.operation_for_context(ctx) else {
            if self.fail_on_unknown_operation {
                return self.handle_violation(
                    ctx,
                    ValidationSide::Response,
                    None,
                    UNMATCHED_OPERATION_DETAIL.to_string(),
                );
            }
            self.mark_skip(ctx, "no_match");
            return PluginResult::Continue;
        };
        self.mark_operation_entry(ctx, operation);
        // Explicit body-absence semantics. RFC 9110 forbids a body for these,
        // so no representation is expected and none of the strict paths below
        // apply. Every other status reaches media selection even with an empty
        // body, so an empty payload under a schema-bearing content type is
        // parsed and rejected rather than silently continuing.
        if response_has_no_body_semantics(&ctx.method, response_status) {
            self.mark_skip(ctx, "no_body_expected");
            return PluginResult::Continue;
        }
        let content_type = header_value(response_headers, "content-type");
        let missing_schema_detail = |reason: &str| {
            // `Content-Type` is backend-controlled. Report only whether it was
            // present; never reflect its raw value into the client problem body
            // or transaction metadata.
            let content_type_state = if content_type.is_some() {
                "present"
            } else {
                "missing"
            };
            format!("{reason} for status {response_status} (Content-Type {content_type_state})")
        };
        // Status selection first, so an exact declared status can never fall
        // through to a range or `default` response object on a media miss.
        let validator = match operation.select_response(response_status, content_type) {
            ResponseSelection::Media(validator) => {
                // Scope is a deployment-side filter applied after the contract
                // selected a schema; strict mode still rejects out-of-scope
                // representations rather than skipping them.
                if !content_type_in_scope(&self.response_content_types, content_type) {
                    return self.missing_response_schema(
                        ctx,
                        operation,
                        "content_type",
                        missing_schema_detail(
                            "Response content type is outside the configured validation scope",
                        ),
                    );
                }
                validator
            }
            ResponseSelection::NoContentDeclared if body.is_empty() => {
                self.mark_skip(ctx, "no_response_content");
                return PluginResult::Continue;
            }
            ResponseSelection::NoContentDeclared => {
                return self.missing_response_schema(
                    ctx,
                    operation,
                    "no_schema",
                    missing_schema_detail(
                        "Response declares no content but the backend returned a body",
                    ),
                );
            }
            ResponseSelection::MediaMismatch => {
                return self.missing_response_schema(
                    ctx,
                    operation,
                    "content_type",
                    missing_schema_detail("No declared response media type matched"),
                );
            }
            ResponseSelection::NoResponseObject => {
                return self.missing_response_schema(
                    ctx,
                    operation,
                    "no_schema",
                    missing_schema_detail("No response schema matched"),
                );
            }
        };
        let result = validate_media_body(
            response_headers,
            body,
            content_type,
            validator,
            self.max_body_bytes,
            ValidationSide::Response,
            Some(&mut ctx.json_scan_memo),
        );
        match result {
            Ok(()) => PluginResult::Continue,
            Err(error) => self.handle_violation(
                ctx,
                ValidationSide::Response,
                Some(&operation.operation_label),
                error,
            ),
        }
    }
}

/// Wrap an operator-supplied `path_regex` so it matches the full path rather
/// than any substring. The non-capturing group keeps the anchors applied to the
/// whole alternation: `a|b` becomes `^(?:a|b)$` (both branches anchored), not
/// `^a|b$` (only the first branch anchored). Already-anchored patterns such as
/// the auto-generated `^/orders/[^/]+$` remain equivalent after wrapping. See
/// finding #89.
fn anchor_path_regex(raw: &str) -> String {
    format!("^(?:{raw})$")
}

/// Statuses and methods for which HTTP defines no response body.
///
/// A HEAD response, an informational status, `204 No Content`, `205 Reset
/// Content`, and `304 Not Modified` carry no representation, so response schema
/// selection is skipped instead of treating an absent body as a contract
/// violation.
fn response_has_no_body_semantics(method: &str, status: u16) -> bool {
    method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || matches!(status, 204 | 205 | 304)
}

fn parse_operation(
    value: &Value,
    index: usize,
    schema_draft: SchemaDraft,
) -> Result<ParsedOperation, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("openapi_validator: operations[{index}] must be an object"))?;
    reject_unknown_keys(
        object,
        &format!("config.operations[{index}]"),
        OPERATION_KEYS,
        ERROR_PREFIX,
    )?;
    let method = optional_string(object, "method")?
        .ok_or_else(|| format!("openapi_validator: operations[{index}].method is required"))?
        .to_ascii_uppercase();
    if method.is_empty() {
        return Err(format!(
            "openapi_validator: operations[{index}].method must not be empty"
        ));
    }
    let path_template = optional_string(object, "path_template")?
        .ok_or_else(|| format!("openapi_validator: operations[{index}].path_template is required"))?
        .to_string();
    let path_regex_raw = optional_string(object, "path_regex")?
        .ok_or_else(|| format!("openapi_validator: operations[{index}].path_regex is required"))?;
    // Anchor operator-supplied patterns so a loose regex like `/users/\d+`
    // cannot substring-match an unintended superstring path such as
    // `/admin/users/1/secret` and thus validate a request against the wrong
    // operation (finding #89). Ferrum's own generated specs already anchor via
    // extractor.rs. The non-capturing group is required so a top-level
    // alternation `a|b` becomes `^(?:a|b)$` (every branch anchored) rather than
    // `^a|b$` (only the first branch anchored).
    let path_regex_anchored = anchor_path_regex(path_regex_raw);
    Regex::new(&path_regex_anchored).map_err(|error| {
        format!("openapi_validator: operations[{index}].path_regex is invalid: {error}")
    })?;
    let operation_label = optional_string(object, "operation_label")?
        .map(str::to_string)
        .unwrap_or_else(|| format!("{method} {path_template}"));
    let request_required =
        optional_bool_from_object(Some(object), "request_required")?.unwrap_or(false);
    let request_validators =
        parse_request_validators(object.get("request_body"), index, schema_draft)?;
    if request_required && request_validators.is_empty() {
        return Err(format!(
            "openapi_validator: operations[{index}].request_required requires at least one request-body schema"
        ));
    }
    let response_validators =
        parse_response_validators(object.get("responses"), index, schema_draft)?;

    Ok(ParsedOperation {
        method,
        path_regex: path_regex_anchored,
        entry: OperationEntry {
            operation_label,
            literal_segments: literal_segment_count(&path_template),
            request_validators,
            request_required,
            response_validators,
        },
    })
}

fn parse_request_validators(
    value: Option<&Value>,
    operation_index: usize,
    schema_draft: SchemaDraft,
) -> Result<AHashMap<String, MediaValidator>, String> {
    let Some(value) = value else {
        return Ok(AHashMap::new());
    };
    if value.is_null() {
        return Err(format!(
            "openapi_validator: operations[{operation_index}].request_body must be an object"
        ));
    }
    let object = value.as_object().ok_or_else(|| {
        format!("openapi_validator: operations[{operation_index}].request_body must be an object")
    })?;
    let path = format!("config.operations[{operation_index}].request_body");
    let mut validators = AHashMap::new();
    // The two request-body forms are structurally disjoint so unknown keys are
    // detectable in both: the alternate single-schema form is keyed by
    // `content_type`/`schema`/`encoding`, the canonical form by `content`.
    // The old "the object *is* the media map" fallback made every typo look
    // like a media type and is no longer accepted (GHSA-692x-352q-6gm8).
    let is_inline_form = REQUEST_BODY_INLINE_KEYS
        .iter()
        .any(|key| object.contains_key(*key));
    if is_inline_form {
        reject_unknown_keys(object, &path, REQUEST_BODY_INLINE_KEYS, ERROR_PREFIX)?;
        let content_type = object
            .get("content_type")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("openapi_validator: {path}.content_type is required and must be a string")
            })?;
        let schema = object
            .get("schema")
            .ok_or_else(|| format!("openapi_validator: {path}.schema is required"))?;
        validate_media_type_key(content_type, &path)?;
        let media_type = normalize_media_type(content_type);
        let encoding = object.get("encoding");
        insert_media_validator(
            &mut validators,
            media_type.clone(),
            compile_media_validator(schema, encoding, &media_type, schema_draft).map_err(
                |error| {
                    format!(
                        "openapi_validator: operations[{operation_index}].request_body schema for {content_type} is invalid: {error}"
                    )
                },
            )?,
            &path,
        )?;
        return Ok(validators);
    }
    reject_unknown_keys(object, &path, REQUEST_BODY_CONTENT_KEYS, ERROR_PREFIX)?;
    let content = object
        .get("content")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("openapi_validator: {path}.content must be an object"))?;
    if content.is_empty() {
        return Err(format!(
            "openapi_validator: {path}.content must not be empty"
        ));
    }
    for (content_type, media_value) in content {
        validate_media_type_key(content_type, &format!("{path}.content"))?;
        let media_type = normalize_media_type(content_type);
        let (schema, encoding) = split_media_type_value(media_value).map_err(|error| {
            format!(
                "openapi_validator: operations[{operation_index}].request_body content['{content_type}'] is invalid: {error}"
            )
        })?;
        insert_media_validator(
            &mut validators,
            media_type.clone(),
            compile_media_validator(schema, encoding, &media_type, schema_draft).map_err(
                |error| {
                    format!(
                        "openapi_validator: operations[{operation_index}].request_body schema for {content_type} is invalid: {error}"
                    )
                },
            )?,
            &format!("{path}.content"),
        )?;
    }
    Ok(validators)
}

fn parse_response_validators(
    value: Option<&Value>,
    operation_index: usize,
    schema_draft: SchemaDraft,
) -> Result<ResponseValidators, String> {
    let Some(value) = value else {
        return Ok(ResponseValidators::default());
    };
    if value.is_null() {
        return Err(format!(
            "openapi_validator: operations[{operation_index}].responses must be an object"
        ));
    }
    let object = value.as_object().ok_or_else(|| {
        format!("openapi_validator: operations[{operation_index}].responses must be an object")
    })?;
    let mut statuses = ResponseValidators::default();
    for (status_raw, response_value) in object {
        let status = parse_response_status_key(status_raw, operation_index)?;
        let response_object = response_value.as_object().ok_or_else(|| {
            format!(
                "openapi_validator: operations[{operation_index}].responses['{status_raw}'] must be an object"
            )
        })?;
        let response_path =
            format!("config.operations[{operation_index}].responses['{status_raw}']");
        // Two structurally distinct shapes: a Response Object carrying `content`
        // (fixed fields, key-enumerated) or the canonical generated media map
        // (free-form media-type keys, shape-validated). `description` stays
        // accepted in the media map form and is skipped.
        let content = match response_object.get("content") {
            Some(content) => {
                reject_unknown_keys(
                    response_object,
                    &response_path,
                    RESPONSE_OBJECT_KEYS,
                    ERROR_PREFIX,
                )?;
                content.as_object().ok_or_else(|| {
                    format!("openapi_validator: {response_path}.content must be an object")
                })?
            }
            None => response_object,
        };
        if let Some(description) = response_object.get("description")
            && !description.is_null()
            && !description.is_string()
        {
            return Err(format!(
                "openapi_validator: {response_path}.description must be a string"
            ));
        }
        let mut validators = AHashMap::new();
        for (content_type, media_value) in content {
            if content_type == "description" {
                continue;
            }
            validate_media_type_key(content_type, &response_path)?;
            let (schema, encoding) = split_media_type_value(media_value).map_err(|error| {
                format!(
                    "openapi_validator: operations[{operation_index}].responses['{status_raw}'] content['{content_type}'] is invalid: {error}"
                )
            })?;
            if encoding.is_some() {
                return Err(format!(
                    "openapi_validator: operations[{operation_index}].responses['{status_raw}'] content['{content_type}'] must not contain an Encoding Object"
                ));
            }
            let media_type = normalize_media_type(content_type);
            insert_media_validator(
                &mut validators,
                media_type,
                compile_media_validator(schema, None, content_type, schema_draft).map_err(
                    |error| {
                        format!(
                            "openapi_validator: operations[{operation_index}].responses['{status_raw}'] schema for {content_type} is invalid: {error}"
                        )
                    },
                )?,
                &response_path,
            )?;
        }
        match status {
            ResponseStatusKey::Exact(status) => {
                if statuses.exact.contains_key(&status) {
                    return Err(format!(
                        "openapi_validator: operations[{operation_index}].responses contains duplicate status declarations for '{status}'"
                    ));
                }
                statuses.exact.insert(status, validators);
            }
            ResponseStatusKey::Range(start, end) => {
                if statuses
                    .ranges
                    .iter()
                    .any(|range| range.start == start && range.end == end)
                {
                    return Err(format!(
                        "openapi_validator: operations[{operation_index}].responses contains duplicate status-range declarations for '{status_raw}'"
                    ));
                }
                statuses.ranges.push(ResponseRangeValidators {
                    start,
                    end,
                    validators,
                });
            }
            ResponseStatusKey::Default => {
                if statuses.default.is_some() {
                    return Err(format!(
                        "openapi_validator: operations[{operation_index}].responses contains duplicate default declarations"
                    ));
                }
                statuses.default = Some(validators);
            }
        }
    }
    Ok(statuses)
}

enum ResponseStatusKey {
    Exact(u16),
    Range(u16, u16),
    Default,
}

fn parse_response_status_key(
    status_raw: &str,
    operation_index: usize,
) -> Result<ResponseStatusKey, String> {
    if status_raw.eq_ignore_ascii_case("default") {
        return Ok(ResponseStatusKey::Default);
    }
    let bytes = status_raw.as_bytes();
    if bytes.len() == 3
        && matches!(bytes[0], b'1'..=b'5')
        && bytes[1].eq_ignore_ascii_case(&b'X')
        && bytes[2].eq_ignore_ascii_case(&b'X')
    {
        let class = u16::from(bytes[0] - b'0');
        let start = class * 100;
        return Ok(ResponseStatusKey::Range(start, start + 99));
    }
    if bytes.len() == 3
        && matches!(bytes[0], b'1'..=b'5')
        && bytes[1..].iter().all(|byte| byte.is_ascii_digit())
    {
        return status_raw
            .parse::<u16>()
            .map(ResponseStatusKey::Exact)
            .map_err(|_| {
                format!(
                    "openapi_validator: operations[{operation_index}].responses contains invalid status '{status_raw}'"
                )
            });
    }
    Err(format!(
        "openapi_validator: operations[{operation_index}].responses contains invalid status '{status_raw}'"
    ))
}

fn insert_media_validator(
    validators: &mut AHashMap<String, MediaValidator>,
    media_type: String,
    validator: MediaValidator,
    path: &str,
) -> Result<(), String> {
    if validators.contains_key(&media_type) {
        return Err(format!(
            "{ERROR_PREFIX}'{path}' contains duplicate media type '{media_type}' after normalization"
        ));
    }
    validators.insert(media_type, validator);
    Ok(())
}

fn compile_schema(
    schema: &Value,
    schema_draft: SchemaDraft,
) -> Result<jsonschema::Validator, jsonschema::ValidationError<'static>> {
    match schema_draft {
        SchemaDraft::Auto => jsonschema::validator_for(schema),
        SchemaDraft::Draft7 => jsonschema::draft7::options().build(schema),
        SchemaDraft::Draft202012 => jsonschema::draft202012::options().build(schema),
    }
}

fn compile_media_validator(
    schema: &Value,
    encoding: Option<&Value>,
    media_type: &str,
    schema_draft: SchemaDraft,
) -> Result<MediaValidator, String> {
    let validator = compile_schema(schema, schema_draft).map_err(|error| error.to_string())?;
    let schema = Arc::new(schema.clone());
    let conversion = ConversionPlan::compile(schema.as_ref(), schema_draft)?;
    let encoding = parse_encoding_map(encoding, media_type, schema.as_ref(), schema_draft)?;
    let safe_names = SafeFieldNames::from_schema(schema.as_ref());
    Ok(MediaValidator {
        schema,
        validator,
        conversion,
        encoding,
        safe_names,
    })
}

/// Split a media-type content entry into schema + optional encoding.
///
/// A bare JSON Schema remains the canonical form when no Encoding Object is
/// present. The wrapper is recognized only when the explicit `encoding` field
/// is present, which keeps a schema containing an ordinary/custom `schema`
/// keyword from being misclassified as a Media Type Object.
fn split_media_type_value(value: &Value) -> Result<(&Value, Option<&Value>), String> {
    let Some(object) = value.as_object() else {
        return Ok((value, None));
    };
    if !object.contains_key("encoding") {
        return Ok((value, None));
    }
    let only_media_type_fields = object
        .keys()
        .all(|key| MEDIA_TYPE_OBJECT_KEYS.contains(&key.as_str()));
    if !only_media_type_fields {
        return Err(
            "media type object with encoding may contain only 'schema' and 'encoding'".to_string(),
        );
    }
    let schema = object
        .get("schema")
        .ok_or_else(|| "media type object is missing schema".to_string())?;
    Ok((schema, object.get("encoding")))
}

fn parse_encoding_map(
    encoding: Option<&Value>,
    media_type: &str,
    schema: &Value,
    schema_draft: SchemaDraft,
) -> Result<AHashMap<String, PropertyEncoding>, String> {
    let Some(encoding) = encoding else {
        return Ok(AHashMap::new());
    };
    let object = encoding
        .as_object()
        .ok_or_else(|| "encoding must be an object".to_string())?;
    let normalized = media_type.to_ascii_lowercase();
    let supports_style =
        normalized == "application/x-www-form-urlencoded" || normalized == "multipart/form-data";
    if !supports_style {
        return Err(format!(
            "encoding is only supported for application/x-www-form-urlencoded and multipart/form-data (got {media_type})"
        ));
    }
    let mut out = AHashMap::new();
    for (property, value) in object {
        let parsed = parse_property_encoding(property, value, &normalized, schema, schema_draft)?;
        out.insert(property.clone(), parsed);
    }
    let free_form_exploded_objects: Vec<&str> = out
        .iter()
        .filter_map(|(property, encoding)| {
            let property_schema = property_schema_from_object(schema, property)?;
            (encoding.style == EncodingStyle::Form
                && encoding.explode
                && schema_accepts_object(property_schema)
                && additional_property_schema_for_conversion(property_schema).is_some())
            .then_some(property.as_str())
        })
        .collect();
    if free_form_exploded_objects.len() > 1 {
        return Err(format!(
            "encoding contains multiple explode=true free-form object properties ({}) whose unprefixed child keys are ambiguous",
            free_form_exploded_objects.join(", ")
        ));
    }
    reject_exploded_object_key_collisions(schema, &out)?;
    Ok(out)
}

/// Fail closed when explode=true form objects would emit the same wire key into
/// more than one logical JSON property (root sibling, sibling exploded object,
/// or a free-form object whose unbounded child key space overlaps another).
fn reject_exploded_object_key_collisions(
    schema: &Value,
    encoding: &AHashMap<String, PropertyEncoding>,
) -> Result<(), String> {
    let root_names = declared_object_property_names(schema);
    let mut exploded_children: Vec<(&str, HashSet<String>)> = Vec::new();
    let mut free_form: Vec<&str> = Vec::new();
    for (property, property_encoding) in encoding {
        if property_encoding.style != EncodingStyle::Form || !property_encoding.explode {
            continue;
        }
        let Some(property_schema) = property_schema_from_object(schema, property) else {
            continue;
        };
        if !schema_accepts_object(property_schema) {
            continue;
        }
        // A free-form object (additionalProperties not false) absorbs any wire
        // key that is not a root sibling, so its emitted-key space is unbounded.
        if additional_property_schema_for_conversion(property_schema).is_some() {
            free_form.push(property.as_str());
        }
        let child_names = declared_object_property_names(property_schema);
        for child in &child_names {
            if child != property && root_names.contains(child) {
                return Err(format!(
                    "encoding['{property}'] explode=true object child '{child}' collides with a root request-body property"
                ));
            }
        }
        exploded_children.push((property.as_str(), child_names));
    }
    for (index, (left_property, left_children)) in exploded_children.iter().enumerate() {
        for (right_property, right_children) in exploded_children.iter().skip(index + 1) {
            let mut overlap: Vec<&str> = left_children
                .intersection(right_children)
                .map(String::as_str)
                .collect();
            if overlap.is_empty() {
                continue;
            }
            overlap.sort_unstable();
            return Err(format!(
                "encoding explode=true object properties '{left_property}' and '{right_property}' emit colliding child keys ({})",
                overlap.join(", ")
            ));
        }
    }
    // An unbounded free-form key space intersects the declared child keys of
    // every other exploded object (those keys are, by the root check above,
    // non-root wire keys the free-form object would also absorb). One wire
    // occurrence could then populate two logical properties depending on schema
    // declaration order, so reject the coexistence fail-closed. (Two free-form
    // objects are already rejected earlier as mutually ambiguous.)
    if let Some(free) = free_form.first().copied()
        && exploded_children.len() > 1
    {
        let mut others: Vec<&str> = exploded_children
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| *name != free)
            .collect();
        others.sort_unstable();
        return Err(format!(
            "encoding explode=true free-form object '{free}' cannot coexist with other explode=true object properties ({}); its unbounded child key space would populate more than one logical property",
            others.join(", ")
        ));
    }
    Ok(())
}

fn declared_object_property_names(schema: &Value) -> HashSet<String> {
    let mut names = HashSet::new();
    collect_declared_object_property_names(schema, &mut names, 0);
    names
}

fn collect_declared_object_property_names(schema: &Value, out: &mut HashSet<String>, depth: usize) {
    if depth > 32 {
        return;
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        out.extend(properties.keys().cloned());
    }
    for keyword in ["allOf", "oneOf", "anyOf"] {
        let Some(branches) = schema.get(keyword).and_then(Value::as_array) else {
            continue;
        };
        for branch in branches {
            collect_declared_object_property_names(branch, out, depth + 1);
        }
    }
}

fn parse_property_encoding(
    property: &str,
    value: &Value,
    media_type: &str,
    schema: &Value,
    schema_draft: SchemaDraft,
) -> Result<PropertyEncoding, String> {
    let property_schema = property_schema_from_object(schema, property).ok_or_else(|| {
        format!("encoding['{property}'] does not name a request-body schema property")
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| format!("encoding['{property}'] must be an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "style" | "explode" | "allowReserved" | "contentType" | "headers"
        ) {
            return Err(format!(
                "encoding['{property}'] contains unsupported field '{key}'"
            ));
        }
    }

    let style_raw = match object.get("style") {
        None => "form",
        Some(Value::String(value)) => value.as_str(),
        Some(_) => return Err(format!("encoding['{property}'].style must be a string")),
    };
    let style = match style_raw {
        "form" => EncodingStyle::Form,
        "spaceDelimited" => EncodingStyle::SpaceDelimited,
        "pipeDelimited" => EncodingStyle::PipeDelimited,
        "deepObject" => EncodingStyle::DeepObject,
        other => {
            return Err(format!(
                "encoding['{property}'].style '{other}' is unsupported for request bodies (supported: form, spaceDelimited, pipeDelimited, deepObject)"
            ));
        }
    };

    let explode = match object.get("explode") {
        None => style == EncodingStyle::Form,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(format!("encoding['{property}'].explode must be a boolean")),
    };
    let allow_reserved = match object.get("allowReserved") {
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => {
            return Err(format!(
                "encoding['{property}'].allowReserved must be a boolean"
            ));
        }
    };

    match (style, explode) {
        (EncodingStyle::Form, _) => {}
        (EncodingStyle::SpaceDelimited | EncodingStyle::PipeDelimited, false) => {}
        (EncodingStyle::DeepObject, true) => {}
        (EncodingStyle::SpaceDelimited | EncodingStyle::PipeDelimited, true) => {
            return Err(format!(
                "encoding['{property}']: style '{style_raw}' requires explode=false"
            ));
        }
        (EncodingStyle::DeepObject, false) => {
            return Err(format!(
                "encoding['{property}']: style 'deepObject' requires explode=true"
            ));
        }
    }

    if style == EncodingStyle::DeepObject && !schema_accepts_object(property_schema) {
        return Err(format!(
            "encoding['{property}']: style 'deepObject' requires an object schema property"
        ));
    }
    if matches!(
        style,
        EncodingStyle::SpaceDelimited | EncodingStyle::PipeDelimited
    ) && !(schema_accepts_array(property_schema) || schema_accepts_object(property_schema))
    {
        return Err(format!(
            "encoding['{property}']: style '{style_raw}' requires an array or object schema property"
        ));
    }

    let content_type = match object.get("contentType") {
        None => None,
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(format!(
                    "encoding['{property}'].contentType must not be empty"
                ));
            }
            if trimmed.len() > MAX_MULTIPART_PARAM_BYTES {
                return Err(format!(
                    "encoding['{property}'].contentType exceeds {MAX_MULTIPART_PARAM_BYTES} bytes"
                ));
            }
            Some(trimmed.to_string())
        }
        Some(_) => {
            return Err(format!(
                "encoding['{property}'].contentType must be a string"
            ));
        }
    };

    if content_type.is_some() && media_type != "multipart/form-data" {
        return Err(format!(
            "encoding['{property}'].contentType is only valid for multipart/form-data"
        ));
    }

    let mut headers = AHashMap::new();
    if let Some(headers_value) = object.get("headers") {
        if media_type != "multipart/form-data" {
            return Err(format!(
                "encoding['{property}'].headers is only valid for multipart/form-data"
            ));
        }
        let headers_object = headers_value
            .as_object()
            .ok_or_else(|| format!("encoding['{property}'].headers must be an object"))?;
        if headers_object.len() > 32 {
            return Err(format!(
                "encoding['{property}'].headers must not exceed 32 entries"
            ));
        }
        for (header_name, header_schema) in headers_object {
            let name = header_name.trim().to_ascii_lowercase();
            if name.is_empty()
                || name.len() > 256
                || http::header::HeaderName::from_bytes(name.as_bytes()).is_err()
            {
                return Err(format!(
                    "encoding['{property}'].headers contains an invalid header name"
                ));
            }
            if matches!(
                name.as_str(),
                "content-type" | "content-disposition" | "content-transfer-encoding"
            ) {
                return Err(format!(
                    "encoding['{property}'].headers must not redefine '{name}'"
                ));
            }
            if headers.contains_key(&name) {
                return Err(format!(
                    "encoding['{property}'].headers contains duplicate header name '{name}'"
                ));
            }
            // Header Object may wrap `schema`; accept either that public OAS
            // shape or the internal bare-schema representation. Header Object
            // `required` defaults to false (OAS 3.1 §4.8.21), while the
            // internal bare-schema representation preserves its historical
            // fail-closed presence requirement.
            let header_object = header_schema.as_object();
            // `required`, `description`, and `examples` are also valid JSON
            // Schema keywords, so they cannot distinguish the supported bare
            // schema form from a Header Object. The OAS wrapper is unambiguous
            // only when it carries `schema` or `content`.
            let is_header_object = header_object.is_some_and(|object| {
                object.contains_key("schema") || object.contains_key("content")
            });
            let (schema_value, content_media_type, required) = if is_header_object {
                let header_object = header_object.ok_or_else(|| {
                    format!(
                        "encoding['{property}'].headers['{header_name}'] must be a Header Object"
                    )
                })?;
                let header_path = format!("encoding['{property}'].headers['{header_name}']");
                let has_schema = header_object.contains_key("schema");
                let has_content = header_object.contains_key("content");
                if has_schema && has_content {
                    return Err(format!(
                        "{header_path} must not declare both schema and content"
                    ));
                }
                if !has_schema && !has_content {
                    return Err(format!("{header_path} must contain schema or content"));
                }
                for key in ENCODING_HEADER_OBJECT_INVALID_KEYS {
                    if header_object.contains_key(*key) {
                        return Err(format!(
                            "{header_path}.{key} is not valid for Header Objects"
                        ));
                    }
                }
                if has_content {
                    for key in ["style", "explode", "example", "examples", "schema"] {
                        if header_object.contains_key(key) {
                            return Err(format!(
                                "{header_path}.{key} is a schema-form Header Object field and is not valid with content"
                            ));
                        }
                    }
                }
                // Keep spelling suggestions for near-miss keys on the selected form.
                reject_unknown_keys(
                    header_object,
                    &header_path,
                    if has_content {
                        ENCODING_HEADER_OBJECT_CONTENT_KEYS
                    } else {
                        ENCODING_HEADER_OBJECT_SCHEMA_KEYS
                    },
                    ERROR_PREFIX,
                )?;
                if let Some(description) = header_object.get("description")
                    && !description.is_null()
                    && !description.is_string()
                {
                    return Err(format!("{header_path}.description must be a string"));
                }
                if let Some(deprecated) = header_object.get("deprecated")
                    && !deprecated.is_boolean()
                {
                    return Err(format!("{header_path}.deprecated must be a boolean"));
                }
                let required = match header_object.get("required") {
                    None => false,
                    Some(Value::Bool(value)) => *value,
                    Some(_) => {
                        return Err(format!("{header_path}.required must be a boolean"));
                    }
                };
                if has_content {
                    let content_object = header_object
                        .get("content")
                        .and_then(Value::as_object)
                        .ok_or_else(|| format!("{header_path}.content must be an object"))?;
                    if content_object.len() != 1 {
                        return Err(format!(
                            "{header_path}.content must contain exactly one media type"
                        ));
                    }
                    let (media_type, media_value) =
                        content_object.iter().next().ok_or_else(|| {
                            format!("{header_path}.content must contain exactly one media type")
                        })?;
                    let media_path = format!("{header_path}.content['{media_type}']");
                    validate_concrete_media_type(media_type, &media_path)?;
                    let media_base = normalize_media_type(media_type);
                    if media_base == "multipart/form-data" {
                        return Err(format!("{media_path} does not support multipart/form-data"));
                    }
                    let media_object = media_value
                        .as_object()
                        .ok_or_else(|| format!("{media_path} must be a Media Type Object"))?;
                    reject_unknown_keys(
                        media_object,
                        &media_path,
                        &["schema", "example", "examples"],
                        ERROR_PREFIX,
                    )?;
                    if let Some(examples) = media_object.get("examples")
                        && !examples.is_object()
                    {
                        return Err(format!("{media_path}.examples must be an object"));
                    }
                    if media_object.contains_key("example") && media_object.contains_key("examples")
                    {
                        return Err(format!(
                            "{media_path}.example and .examples are mutually exclusive"
                        ));
                    }
                    let schema = media_object
                        .get("schema")
                        .ok_or_else(|| format!("{media_path} must contain schema"))?;
                    (schema, Some(media_base), required)
                } else {
                    if let Some(style) = header_object.get("style")
                        && style.as_str() != Some("simple")
                    {
                        return Err(format!("{header_path}.style must be 'simple'"));
                    }
                    if let Some(explode) = header_object.get("explode")
                        && !explode.is_boolean()
                    {
                        return Err(format!("{header_path}.explode must be a boolean"));
                    }
                    if let Some(examples) = header_object.get("examples")
                        && !examples.is_object()
                    {
                        return Err(format!("{header_path}.examples must be an object"));
                    }
                    let schema = header_object
                        .get("schema")
                        .ok_or_else(|| format!("{header_path} must contain schema or content"))?;
                    (schema, None, required)
                }
            } else {
                (header_schema, None, true)
            };
            let validator = compile_schema(schema_value, schema_draft).map_err(|error| {
                format!(
                    "encoding['{property}'].headers['{header_name}'] schema is invalid: {error}"
                )
            })?;
            let schema_types = collect_schema_types(schema_value);
            let conversion =
                ConversionPlan::compile(schema_value, schema_draft).map_err(|error| {
                    format!(
                        "encoding['{property}'].headers['{header_name}'] schema is invalid: {error}"
                    )
                })?;
            headers.insert(
                name,
                EncodingHeaderValidator {
                    required,
                    schema: schema_value.clone(),
                    schema_types,
                    validator,
                    content_media_type,
                    conversion,
                    safe_names: SafeFieldNames::from_schema(schema_value),
                },
            );
        }
    }

    Ok(PropertyEncoding {
        style,
        explode,
        allow_reserved,
        content_type,
        headers,
    })
}

fn property_schema_from_object<'a>(schema: &'a Value, property: &str) -> Option<&'a Value> {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(property))
        .or_else(|| {
            // Walk every composition branch so Encoding Objects can target a
            // property declared in an allOf/oneOf/anyOf object branch.
            ["allOf", "oneOf", "anyOf"].into_iter().find_map(|keyword| {
                schema
                    .get(keyword)
                    .and_then(Value::as_array)
                    .and_then(|branches| {
                        branches
                            .iter()
                            .find_map(|branch| property_schema_from_object(branch, property))
                    })
            })
        })
}

fn decode_body<'a>(
    headers: &HashMap<String, String>,
    body: &'a [u8],
    max_body_bytes: usize,
) -> Result<Cow<'a, [u8]>, String> {
    if body.len() > max_body_bytes {
        return Err(format!(
            "Body exceeds max_body_bytes of {max_body_bytes} bytes"
        ));
    }
    // Enforce `max_body_bytes` on every decoded layer. Cumulative work is capped
    // at layers × max so a stacked chain cannot bypass the per-layer ceiling
    // while still failing closed on amplification across the full list.
    let max_cumulative_bytes = max_body_bytes.saturating_mul(MAX_CONTENT_CODINGS);
    // The shared decoder's errors can echo a hostile coding token. Collapse to
    // a fixed category at this plugin boundary so neither the request problem
    // body nor transaction metadata can reproduce it (`GHSA-5p2h-fq6q-gwh9`).
    // Response conversion already has a coarser outer collapse; request must
    // be safe here too. The shared utility stays detailed for other plugins.
    decode_content_encoding(
        header_value(headers, "content-encoding"),
        body,
        DecodeLimits {
            max_decoded_bytes: max_body_bytes,
            max_cumulative_bytes,
            max_codings: MAX_CONTENT_CODINGS,
            max_amplification_ratio: 0,
        },
    )
    .map_err(|_| "Content-Encoding could not be decoded".to_string())
}

enum SchemaInstance {
    Value(Value),
    BinaryLengthOnly,
}

/// Duplicate-object-member screen for a governed JSON document, reusing the
/// per-request memo when one is available so a multi-plugin chain scans one
/// buffered body once.
///
/// The returned reason is a fixed-cardinality `&'static str` that never echoes
/// any byte of the inspected body, so it is safe on both the request-side
/// (client-visible) and response-side error paths.
fn screen_json_ambiguity(body: &[u8], memo: Option<&mut JsonScanMemo>) -> Option<&'static str> {
    match memo {
        Some(memo) => memo.ambiguity(body),
        None => json_dup_keys::slice_ambiguity(body),
    }
}

fn validate_media_body(
    headers: &HashMap<String, String>,
    body: &[u8],
    content_type: Option<&str>,
    validator: &MediaValidator,
    max_body_bytes: usize,
    side: ValidationSide,
    json_scan_memo: Option<&mut JsonScanMemo>,
) -> Result<(), String> {
    let instance = body_to_schema_instance(
        headers,
        body,
        content_type,
        validator,
        max_body_bytes,
        json_scan_memo,
    )
    .map_err(|error| match side {
        ValidationSide::Request => error,
        ValidationSide::Response => {
            // Every conversion helper is now payload-free by construction
            // (`GHSA-5p2h-fq6q-gwh9`), so this collapse is no longer the
            // confidentiality mechanism. It is retained as a second, coarser
            // response-side boundary: the *class* of a decode failure still
            // describes the shape of an upstream representation the client was
            // never entitled to observe, and a future helper that regresses
            // cannot reach the client through this path.
            "Response body could not be safely decoded or converted for schema validation"
                .to_string()
        }
    })?;
    match instance {
        SchemaInstance::Value(instance) => validator
            .validator
            .validate(&instance)
            .map_err(|error| format_schema_error(&error, side, &validator.safe_names)),
        SchemaInstance::BinaryLengthOnly => Ok(()),
    }
}

fn body_to_schema_instance(
    headers: &HashMap<String, String>,
    body: &[u8],
    content_type: Option<&str>,
    validator: &MediaValidator,
    max_body_bytes: usize,
    json_scan_memo: Option<&mut JsonScanMemo>,
) -> Result<SchemaInstance, String> {
    let schema = validator.schema.as_ref();
    let encoding = &validator.encoding;
    let conversion = &validator.conversion;
    let decoded = decode_body(headers, body, max_body_bytes)?;
    let media_type = content_type_base(content_type)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if is_json_media_type(&media_type) {
        // Screen for duplicate object member names BEFORE the schema sees a
        // `serde_json`-collapsed view of the document (advisory
        // `GHSA-c78j-5w9p-cpq6`). Validating the last-wins value while
        // forwarding the original bytes lets a first-key-wins backend act on a
        // schema-forbidden earlier value, so ambiguity is rejected outright
        // rather than canonicalized.
        if let Some(reason) = screen_json_ambiguity(decoded.as_ref(), json_scan_memo) {
            return Err(reason.to_string());
        }
        return serde_json::from_slice(decoded.as_ref())
            .map(SchemaInstance::Value)
            .map_err(|error| format!("Invalid JSON body: {error}"));
    }
    if is_xml_media_type(&media_type) {
        let body = std::str::from_utf8(decoded.as_ref())
            .map_err(|error| format!("Invalid XML body encoding: {error}"))?;
        return xml_body_to_value(body, schema, conversion).map(SchemaInstance::Value);
    }
    if media_type == "application/x-www-form-urlencoded" {
        let body = std::str::from_utf8(decoded.as_ref())
            .map_err(|error| format!("Invalid form body encoding: {error}"))?;
        return form_urlencoded_to_value(body, schema, encoding, conversion)
            .map(SchemaInstance::Value);
    }
    if media_type == "multipart/form-data" {
        let boundary = multipart_boundary(content_type.unwrap_or(""))?
            .ok_or_else(|| "Multipart body is missing boundary parameter".to_string())?;
        return multipart_to_value(decoded.as_ref(), &boundary, schema, encoding, conversion)
            .map(SchemaInstance::Value);
    }
    if is_text_media_type(&media_type) {
        let body = std::str::from_utf8(decoded.as_ref())
            .map_err(|error| format!("Invalid text body encoding: {error}"))?;
        return scalar_to_schema_value(body, schema, conversion).map(SchemaInstance::Value);
    }
    binary_body_to_schema_instance(decoded.as_ref(), schema)
}

fn xml_body_to_value(
    body: &str,
    schema: &Value,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    // The `roxmltree` error rendering quotes the offending source token, so it
    // is reduced to a fixed well-formedness category before it can reach a
    // client body or transaction metadata (`GHSA-5p2h-fq6q-gwh9`).
    let doc = roxmltree::Document::parse(body)
        .map_err(|error| format!("Invalid XML body: {}", xml_error_category(&error)))?;
    let root = doc.root_element();
    let expected_root = xml_name(schema, None);
    let expected_namespace = xml_namespace(schema);
    let root_local_matches = expected_root.is_none_or(|local| root.tag_name().name() == local);
    let root_namespace_matches =
        expected_namespace.is_none_or(|namespace| root.tag_name().namespace() == Some(namespace));
    if !root_local_matches || !root_namespace_matches {
        // Disclose neither the document's actual root name/namespace nor the
        // configured xml.name / xml.namespace expectation
        // (`GHSA-5p2h-fq6q-gwh9`). Matching still uses the schema metadata.
        return Err("XML root element does not match the configured schema".to_string());
    }
    xml_node_to_value(root, schema, conversion)
}

fn xml_node_to_value(
    node: roxmltree::Node<'_, '_>,
    schema: &Value,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    if conversion.accepts_array(schema) {
        let item_schema = array_item_schema_for_conversion(schema, conversion);
        let values = node
            .children()
            .filter(roxmltree::Node::is_element)
            .map(|child| xml_node_to_value(child, item_schema, conversion))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Value::Array(values));
    }
    let object_schema = object_schema_for_conversion(schema, conversion);
    if conversion.accepts_object(object_schema) || object_schema.get("properties").is_some() {
        let empty_properties = serde_json::Map::new();
        let properties =
            merged_object_properties(object_schema, conversion).unwrap_or(&empty_properties);
        let mut out = serde_json::Map::new();
        let mut modeled_names = ModeledXmlNames::default();
        for (property_name, property_schema) in properties {
            if xml_attribute(property_schema) {
                let attr_local = xml_name(property_schema, Some(property_name.as_str()))
                    .unwrap_or(property_name.as_str());
                let attr_namespace = xml_namespace(property_schema);
                modeled_names.insert_attribute(attr_namespace, attr_local, property_name);
                if let Some(value) = xml_attribute_value(node, attr_namespace, attr_local) {
                    out.insert(
                        property_name.clone(),
                        scalar_to_schema_value(value, property_schema, conversion)?,
                    );
                }
                continue;
            }
            if conversion.accepts_array(property_schema) {
                mark_xml_array_modeled_names(
                    property_name,
                    property_schema,
                    conversion,
                    &mut modeled_names,
                );
                let values = xml_array_values(node, property_name, property_schema, conversion)?;
                if !values.is_empty() {
                    out.insert(property_name.clone(), Value::Array(values));
                }
                continue;
            }
            let child_local = xml_name(property_schema, Some(property_name.as_str()))
                .unwrap_or(property_name.as_str());
            let child_namespace = xml_namespace(property_schema);
            modeled_names.insert_element(child_namespace, child_local, property_name);
            let matches = child_elements_matching(node, child_namespace, child_local);
            match matches.as_slice() {
                [] => {}
                [child] => {
                    out.insert(
                        property_name.clone(),
                        xml_node_to_value(*child, property_schema, conversion)?,
                    );
                }
                _ => {
                    return Err(format!(
                        "XML property '{property_name}' must not repeat for a non-array schema"
                    ));
                }
            }
        }
        // Always materialize undeclared members so JSON Schema keywords such as
        // additionalProperties, maxProperties, patternProperties, and propertyNames
        // observe the full XML payload instead of a filtered projection.
        // Fail closed: a member that collides with a modeled JSON key / XML local
        // but not the property's modeled XML construct or namespace (a
        // wrong-namespace peer, or an attribute where an element is modeled and
        // vice versa) must not rebind that property or be silently dropped;
        // return a conversion error.
        let additional_schema = additional_property_schema_for_conversion(object_schema);
        let mut additional_attribute_locals = HashSet::new();
        let mut additional_element_names: HashMap<String, Option<String>> = HashMap::new();
        for attr in node.attributes() {
            if modeled_names.contains_attribute(attr) {
                continue;
            }
            if modeled_names.reserves_json_key(attr.name()) {
                return Err(XML_ATTRIBUTE_COLLISION_DETAIL.to_string());
            }
            let member_schema = conversion
                .pattern_property_schema(object_schema, attr.name())
                .or_else(|| additional_schema.flatten());
            let value = match member_schema {
                Some(schema) => scalar_to_schema_value(attr.value(), schema, conversion)?,
                _ => Value::String(attr.value().to_string()),
            };
            additional_attribute_locals.insert(attr.name().to_string());
            if out.insert(attr.name().to_string(), value).is_some() {
                return Err(XML_DUPLICATE_ATTRIBUTE_DETAIL.to_string());
            }
        }
        for child in node.children().filter(roxmltree::Node::is_element) {
            if modeled_names.contains_element(child) {
                continue;
            }
            let name = child.tag_name().name();
            if modeled_names.reserves_json_key(name) {
                return Err(XML_ELEMENT_COLLISION_DETAIL.to_string());
            }
            if additional_attribute_locals.contains(name) {
                return Err(XML_ATTRIBUTE_ELEMENT_CONFLICT_DETAIL.to_string());
            }
            let namespace = child.tag_name().namespace();
            if let Some(previous_namespace) = additional_element_names.get(name) {
                if previous_namespace.as_deref() != namespace {
                    return Err(XML_NAMESPACE_CONFLICT_DETAIL.to_string());
                }
            } else {
                additional_element_names.insert(name.to_string(), namespace.map(str::to_string));
            }
            let member_schema = conversion
                .pattern_property_schema(object_schema, name)
                .or_else(|| additional_schema.flatten());
            let value = match member_schema {
                Some(schema) => xml_node_to_value(child, schema, conversion)?,
                _ => generic_xml_node_to_value(child)?,
            };
            match out.get_mut(name) {
                Some(Value::Array(values)) => values.push(value),
                Some(existing) => {
                    let first = std::mem::take(existing);
                    *existing = Value::Array(vec![first, value]);
                }
                None => {
                    out.insert(name.to_string(), value);
                }
            }
        }
        if node.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        }) {
            return Err("XML object contains unmodeled text content".to_string());
        }
        return Ok(Value::Object(out));
    }
    let text = node.text().unwrap_or("").trim();
    scalar_to_schema_value(text, schema, conversion)
}

fn xml_array_values(
    node: roxmltree::Node<'_, '_>,
    property_name: &str,
    property_schema: &Value,
    conversion: &ConversionPlan,
) -> Result<Vec<Value>, String> {
    let item_schema = array_item_schema_for_conversion(property_schema, conversion);
    let (item_namespace, item_local) =
        xml_array_item_name(property_name, property_schema, item_schema);
    let mut values = Vec::new();
    if xml_wrapped(property_schema) {
        let wrapper_local = xml_name(property_schema, Some(property_name)).unwrap_or(property_name);
        let wrapper_namespace = xml_namespace(property_schema);
        let wrappers = child_elements_matching(node, wrapper_namespace, wrapper_local);
        if wrappers.len() > 1 {
            return Err(format!(
                "XML wrapped array '{property_name}' must not repeat its wrapper element"
            ));
        }
        for wrapper in wrappers {
            // Fail closed inside the wrapper: same-local wrong-namespace children
            // must not be filtered away (an optional wrapped array would otherwise
            // silently become empty and pass).
            for child in child_elements_matching_fail_closed(
                wrapper,
                item_namespace,
                item_local,
                "array item",
            )? {
                values.push(xml_node_to_value(child, item_schema, conversion)?);
            }
        }
    } else {
        for child in
            child_elements_matching_fail_closed(node, item_namespace, item_local, "array item")?
        {
            values.push(xml_node_to_value(child, item_schema, conversion)?);
        }
    }
    Ok(values)
}

fn mark_xml_array_modeled_names(
    property_name: &str,
    property_schema: &Value,
    conversion: &ConversionPlan,
    modeled_names: &mut ModeledXmlNames,
) {
    let item_schema = array_item_schema_for_conversion(property_schema, conversion);
    let (item_namespace, item_local) =
        xml_array_item_name(property_name, property_schema, item_schema);
    if xml_wrapped(property_schema) {
        let wrapper_local = xml_name(property_schema, Some(property_name)).unwrap_or(property_name);
        let wrapper_namespace = xml_namespace(property_schema);
        modeled_names.insert_element(wrapper_namespace, wrapper_local, property_name);
        // Reserve namespace-qualified item locals (and the array JSON key when the
        // wrapper itself omits xml.namespace) so a wrong-namespace peer cannot
        // rebind them via additional-member insertion or silent drop.
        if item_namespace.is_some() {
            if wrapper_namespace.is_none() {
                modeled_names.reserve_json_key(property_name);
            }
            if item_local != property_name && item_local != wrapper_local {
                modeled_names.reserve_json_key(item_local);
            }
        }
    } else {
        modeled_names.insert_element(item_namespace, item_local, property_name);
    }
}

fn xml_array_item_name<'a>(
    property_name: &'a str,
    property_schema: &'a Value,
    item_schema: &'a Value,
) -> (Option<&'a str>, &'a str) {
    if let Some(local) = xml_name(item_schema, None) {
        return (xml_namespace(item_schema), local);
    }
    if let Some(local) = xml_name(property_schema, Some(property_name)) {
        // Prefer item-level namespace when present; otherwise inherit the
        // property XML Object namespace used for unwrapped array items.
        let namespace = xml_namespace(item_schema).or_else(|| xml_namespace(property_schema));
        return (namespace, local);
    }
    (
        xml_namespace(item_schema).or_else(|| xml_namespace(property_schema)),
        property_name,
    )
}

fn generic_xml_node_to_value(node: roxmltree::Node<'_, '_>) -> Result<Value, String> {
    let mut out = serde_json::Map::new();
    let mut attribute_locals = HashSet::new();
    for attr in node.attributes() {
        attribute_locals.insert(attr.name().to_string());
        if out
            .insert(
                attr.name().to_string(),
                Value::String(attr.value().to_string()),
            )
            .is_some()
        {
            return Err(XML_DUPLICATE_ATTRIBUTE_DETAIL.to_string());
        }
    }
    let children: Vec<_> = node
        .children()
        .filter(roxmltree::Node::is_element)
        .collect();
    if children.is_empty() {
        let text = node.text().unwrap_or("").trim().to_string();
        if out.is_empty() {
            return Ok(Value::String(text));
        }
        if !text.is_empty() {
            out.insert("#text".to_string(), Value::String(text));
        }
        return Ok(Value::Object(out));
    }
    let mut element_names: HashMap<String, Option<String>> = HashMap::new();
    for child in children {
        let local = child.tag_name().name();
        if attribute_locals.contains(local) {
            return Err(XML_ATTRIBUTE_ELEMENT_CONFLICT_DETAIL.to_string());
        }
        let namespace = child.tag_name().namespace();
        if let Some(previous_namespace) = element_names.get(local) {
            if previous_namespace.as_deref() != namespace {
                return Err(XML_NAMESPACE_CONFLICT_DETAIL.to_string());
            }
        } else {
            element_names.insert(local.to_string(), namespace.map(str::to_string));
        }
        let value = generic_xml_node_to_value(child)?;
        match out.get_mut(local) {
            Some(Value::Array(values)) => values.push(value),
            Some(existing) => {
                let first = std::mem::take(existing);
                *existing = Value::Array(vec![first, value]);
            }
            None => {
                out.insert(local.to_string(), value);
            }
        }
    }
    if let Some(text) = node.text().map(str::trim)
        && !text.is_empty()
    {
        out.insert("#text".to_string(), Value::String(text.to_string()));
    }
    Ok(Value::Object(out))
}

fn form_urlencoded_to_value(
    body: &str,
    schema: &Value,
    encoding: &AHashMap<String, PropertyEncoding>,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    validate_form_serialization(body, schema, encoding)?;
    let mut fields: HashMap<String, Vec<String>> = HashMap::new();
    let mut raw_fields: HashMap<String, Vec<String>> = HashMap::new();
    for pair in body.split('&') {
        let (_raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let Some((key, value)) = url::form_urlencoded::parse(pair.as_bytes()).next() else {
            continue;
        };
        let key = key.into_owned();
        fields
            .entry(key.clone())
            .or_default()
            .push(value.into_owned());
        // Keep the encoded value so style delimiters can be split before
        // percent-decoding. Otherwise an item containing `%2C` would be
        // mistaken for an `explode=false` comma delimiter.
        raw_fields
            .entry(key)
            .or_default()
            .push(raw_value.to_string());
    }
    fields_to_schema_object(fields, &raw_fields, schema, encoding, conversion)
}

fn validate_form_serialization(
    body: &str,
    schema: &Value,
    encoding: &AHashMap<String, PropertyEncoding>,
) -> Result<(), String> {
    for pair in body.split('&') {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded_key = url::form_urlencoded::parse(pair.as_bytes())
            .next()
            .map(|(key, _)| key.into_owned())
            .unwrap_or_default();
        let property = decoded_key
            .split_once('[')
            .map(|(base, _)| base)
            .unwrap_or(decoded_key.as_str());
        let Some(property_encoding) = form_encoding_for_key(property, schema, encoding) else {
            // Preserve the historical lenient form decoder for properties with
            // no declared Encoding Object. Encoding-specific strictness starts
            // only when an operator explicitly opts that property into it.
            continue;
        };
        validate_percent_encoding(raw_key)?;
        validate_percent_encoding(raw_value)?;
        let allow_reserved = property_encoding.allow_reserved;
        let comma_is_style_delimiter =
            { property_encoding.style == EncodingStyle::Form && !property_encoding.explode };
        if !allow_reserved
            && raw_value.bytes().any(|byte| {
                is_unescaped_form_reserved_byte(byte) && !(comma_is_style_delimiter && byte == b',')
            })
        {
            return Err(format!(
                "Form field '{property}' contains an unescaped reserved character while allowReserved=false"
            ));
        }
    }
    Ok(())
}

fn form_encoding_for_key<'a>(
    key: &str,
    schema: &Value,
    encoding: &'a AHashMap<String, PropertyEncoding>,
) -> Option<&'a PropertyEncoding> {
    encoding.get(key).or_else(|| {
        encoding.iter().find_map(|(property, property_encoding)| {
            if property_encoding.style != EncodingStyle::Form || !property_encoding.explode {
                return None;
            }
            let property_schema = property_schema_from_object(schema, property)?;
            object_property_schema(property_schema, key).map(|_| property_encoding)
        })
    })
}

fn validate_percent_encoding(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err("Form body contains malformed percent-encoding".to_string());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn is_unescaped_form_reserved_byte(byte: u8) -> bool {
    // RFC 3986 gen-delims + sub-delims that can occur inside the raw value.
    // `&` is already the field delimiter and `+` is the form-space encoding.
    matches!(
        byte,
        b':' | b'/'
            | b'?'
            | b'#'
            | b'['
            | b']'
            | b'@'
            | b'!'
            | b'$'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b','
            | b';'
            | b'='
    )
}

#[derive(Debug)]
struct MultipartPart {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn multipart_to_value(
    body: &[u8],
    boundary: &str,
    schema: &Value,
    encoding: &AHashMap<String, PropertyEncoding>,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    let parts = parse_multipart_parts(body, boundary)?;
    let mut grouped: HashMap<String, Vec<MultipartPart>> = HashMap::new();
    for part in parts {
        grouped.entry(part.name.clone()).or_default().push(part);
    }
    multipart_parts_to_schema_object(grouped, schema, encoding, conversion)
}

fn parse_multipart_parts(body: &[u8], boundary: &str) -> Result<Vec<MultipartPart>, String> {
    validate_multipart_boundary(boundary)?;
    let delimiter = format!("--{boundary}");
    let close_marker = format!("--{boundary}--");
    let delim_bytes = delimiter.as_bytes();
    let close_bytes = close_marker.as_bytes();

    let mut parts = Vec::new();
    let mut saw_close = false;

    // Locate the opening boundary (optional preamble before it).
    let Some(opening) = find_mime_boundary(body, 0, delim_bytes, close_bytes)? else {
        return Err("Malformed multipart body: missing opening boundary".to_string());
    };
    if opening.is_close {
        return Err("Malformed multipart body: empty closed multipart".to_string());
    }
    let mut pos = opening.after;

    while !saw_close {
        let Some(end) = find_mime_boundary(body, pos, delim_bytes, close_bytes)? else {
            return Err("Malformed multipart body: missing closing boundary".to_string());
        };
        let mut segment = &body[pos..end.at];
        // Part body excludes the CRLF that precedes the next boundary.
        segment = trim_trailing_line_break(segment);

        if segment.is_empty() {
            return Err("Malformed multipart body: empty part".to_string());
        }
        if parts.len() >= MAX_MULTIPART_PARTS {
            return Err(format!(
                "Multipart body exceeds {MAX_MULTIPART_PARTS} parts"
            ));
        }
        // `find_mime_boundary` already consumes the delimiter line ending.
        // Another line ending here is therefore an empty header block. Reject
        // it before searching for a later separator, or a body line that looks
        // like Content-Disposition could be promoted into the header section.
        if segment.starts_with(b"\r\n") || segment.starts_with(b"\n") {
            return Err("Malformed multipart part: empty header block".to_string());
        }
        let Some((header_bytes, part_body)) = split_header_body(segment) else {
            return Err("Malformed multipart part: missing header/body separator".to_string());
        };
        if header_bytes.len() > MAX_MULTIPART_HEADER_BYTES {
            return Err(format!(
                "Multipart part headers exceed {MAX_MULTIPART_HEADER_BYTES} bytes"
            ));
        }
        let headers = parse_part_headers(header_bytes)?;
        let Some(disposition) = headers.get("content-disposition") else {
            return Err("Malformed multipart part: missing Content-Disposition".to_string());
        };
        let (disposition_type, params) = parse_header_type_and_params(disposition)?;
        if !disposition_type.eq_ignore_ascii_case("form-data") {
            return Err(MULTIPART_DISPOSITION_TYPE_DETAIL.to_string());
        }
        let Some(name) = params
            .get("name")
            .map(|value| value.value.as_str())
            .filter(|value| !value.is_empty())
        else {
            return Err("Malformed multipart part: missing form-data name".to_string());
        };
        if name.len() > MAX_MULTIPART_PARAM_BYTES {
            return Err("Multipart form-data name exceeds size limit".to_string());
        }
        // Resolve ordinary `filename` and RFC 5987/8187 `filename*` with
        // fail-closed conflict/continuation rules. Presence of either form
        // marks a file part so structured JSON/XML body spoofing stays closed.
        let filename = resolve_multipart_filename(&params)?;
        parts.push(MultipartPart {
            name: name.to_string(),
            filename,
            content_type: headers.get("content-type").cloned(),
            headers,
            body: part_body.to_vec(),
        });

        saw_close = end.is_close;
        pos = end.after;
    }

    // Trailing epilogue after the close boundary is ignored.
    Ok(parts)
}

#[derive(Debug, Clone, Copy)]
struct MimeBoundaryMatch {
    at: usize,
    after: usize,
    is_close: bool,
}

/// Find the next MIME multipart delimiter line starting at `from`.
///
/// Boundaries are only recognized as delimiter *lines*: either at byte 0 or
/// immediately after CRLF/LF, matching `--{boundary}` or `--{boundary}--`,
/// then optional transport-padding spaces/tabs, then CRLF/LF or end-of-body.
fn find_mime_boundary(
    body: &[u8],
    from: usize,
    delim: &[u8],
    close: &[u8],
) -> Result<Option<MimeBoundaryMatch>, String> {
    let finder = memchr::memmem::Finder::new(delim);
    let mut search_from = from;
    while search_from <= body.len() {
        let Some(rel) = finder.find(&body[search_from..]) else {
            return Ok(None);
        };
        let at = search_from + rel;
        if !is_mime_line_start(body, at, from) {
            search_from = at + 1;
            continue;
        }
        let after_delim = at + delim.len();
        let is_close = body[after_delim..].starts_with(b"--");
        let after_marker = if is_close {
            // Ensure close marker is exactly `--boundary--` (not a longer token).
            if !body[at..].starts_with(close) {
                search_from = at + 1;
                continue;
            }
            at + close.len()
        } else {
            after_delim
        };
        let after_padding = skip_transport_padding(&body[after_marker..]);
        let term_at = after_marker + after_padding;
        let after = match consume_line_terminator(body, term_at) {
            Some(next) => next,
            None if term_at == body.len() => term_at,
            None => {
                search_from = at + 1;
                continue;
            }
        };
        return Ok(Some(MimeBoundaryMatch {
            at,
            after,
            is_close,
        }));
    }
    Ok(None)
}

fn is_mime_line_start(body: &[u8], at: usize, floor: usize) -> bool {
    if at == 0 || at == floor {
        return true;
    }
    if at >= 2 && body[at - 2] == b'\r' && body[at - 1] == b'\n' {
        return true;
    }
    at >= 1 && body[at - 1] == b'\n'
}

fn skip_transport_padding(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count()
}

fn consume_line_terminator(body: &[u8], at: usize) -> Option<usize> {
    if body[at..].starts_with(b"\r\n") {
        Some(at + 2)
    } else if body[at..].starts_with(b"\n") {
        Some(at + 1)
    } else {
        None
    }
}

fn validate_multipart_boundary(boundary: &str) -> Result<(), String> {
    if boundary.is_empty() || boundary.len() > MAX_MULTIPART_BOUNDARY_LEN {
        return Err(format!(
            "Invalid multipart boundary: length must be 1..={MAX_MULTIPART_BOUNDARY_LEN}"
        ));
    }
    // RFC 2046 permits interior spaces in a quoted boundary, but the final
    // byte must use bcharsnospace.
    if boundary.ends_with(' ') {
        return Err("Invalid multipart boundary: trailing space".to_string());
    }
    if !boundary.bytes().all(|byte| {
        matches!(
            byte,
            b'0'..=b'9'
                | b'a'..=b'z'
                | b'A'..=b'Z'
                | b'\''
                | b'('
                | b')'
                | b'+'
                | b'_'
                | b','
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'='
                | b'?'
                | b' '
        )
    }) {
        return Err("Invalid multipart boundary characters".to_string());
    }
    Ok(())
}

fn fields_to_schema_object(
    fields: HashMap<String, Vec<String>>,
    raw_fields: &HashMap<String, Vec<String>>,
    schema: &Value,
    encoding: &AHashMap<String, PropertyEncoding>,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    let object_schema = object_schema_for_conversion(schema, conversion);
    if !(conversion.accepts_object(object_schema) || object_schema.get("properties").is_some()) {
        let Some(values) = fields.values().next() else {
            return Ok(Value::Null);
        };
        return values_to_schema_value(values, schema, None, conversion);
    }
    let mut out = serde_json::Map::new();
    let empty_properties = serde_json::Map::new();
    let properties =
        merged_object_properties(object_schema, conversion).unwrap_or(&empty_properties);
    let mut consumed_keys: HashSet<String> = HashSet::new();

    for (property, property_schema) in properties {
        let property_encoding = encoding.get(property.as_str());
        if property_encoding.is_some_and(|enc| enc.style == EncodingStyle::DeepObject) {
            let object_fields = take_deep_object_fields(&fields, property, &mut consumed_keys);
            if !object_fields.is_empty() {
                out.insert(
                    property.clone(),
                    deep_object_fields_to_value(&object_fields, property_schema, conversion)?,
                );
            }
            continue;
        }
        if conversion.accepts_object(property_schema)
            && let Some(property_encoding) = property_encoding
        {
            if property_encoding.style == EncodingStyle::Form && property_encoding.explode {
                let object = exploded_form_object_to_value(
                    &fields,
                    property_schema,
                    properties,
                    &mut consumed_keys,
                    conversion,
                )?;
                if object.as_object().is_some_and(|object| !object.is_empty()) {
                    out.insert(property.clone(), object);
                }
                continue;
            }
            if !property_encoding.explode {
                if let Some(values) = fields.get(property) {
                    consumed_keys.insert(property.clone());
                    out.insert(
                        property.clone(),
                        serialized_object_to_value(
                            values,
                            raw_fields.get(property).map(Vec::as_slice),
                            property_schema,
                            property_encoding.style,
                            conversion,
                        )?,
                    );
                }
                continue;
            }
        }
        if let Some(values) = fields.get(property) {
            consumed_keys.insert(property.clone());
            out.insert(
                property.clone(),
                form_values_to_schema_value(
                    values,
                    raw_fields.get(property).map(Vec::as_slice),
                    property_schema,
                    property_encoding,
                    conversion,
                )?,
            );
        }
    }
    for (key, values) in &fields {
        if consumed_keys.contains(key) || out.contains_key(key) {
            continue;
        }
        if let Some((parent, child)) = split_deep_object_key(key)
            && encoding
                .get(parent)
                .is_some_and(|enc| enc.style == EncodingStyle::DeepObject)
        {
            // The configured parent consumed all syntactically valid children
            // above. Do not leak an orphan back into the root object.
            let _ = child;
            continue;
        }
        out.insert(
            key.clone(),
            values_to_schema_value(values, &Value::Null, None, conversion)?,
        );
    }
    Ok(Value::Object(out))
}

fn exploded_form_object_to_value(
    fields: &HashMap<String, Vec<String>>,
    schema: &Value,
    root_properties: &serde_json::Map<String, Value>,
    consumed: &mut HashSet<String>,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    let empty_properties = serde_json::Map::new();
    let properties = merged_object_properties(schema, conversion).unwrap_or(&empty_properties);
    let mut out = serde_json::Map::new();
    for (child, child_schema) in properties {
        let Some(values) = fields.get(child) else {
            continue;
        };
        consumed.insert(child.clone());
        out.insert(
            child.clone(),
            values_to_schema_value(values, child_schema, None, conversion)?,
        );
    }
    if let Some(additional_schema) = additional_property_schema_for_conversion(schema) {
        for (child, values) in fields {
            if consumed.contains(child) || root_properties.contains_key(child) {
                continue;
            }
            consumed.insert(child.clone());
            let value = match additional_schema {
                Some(additional_schema) => {
                    values_to_schema_value(values, additional_schema, None, conversion)?
                }
                None => values_to_schema_value(values, &Value::Null, None, conversion)?,
            };
            out.insert(child.clone(), value);
        }
    }
    Ok(Value::Object(out))
}

fn serialized_object_to_value(
    values: &[String],
    raw_values: Option<&[String]>,
    schema: &Value,
    style: EncodingStyle,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    if values.len() != 1 {
        return Err(
            "Serialized object property must occur exactly once when explode=false".to_string(),
        );
    }
    let tokens = match raw_values {
        Some(raw_values) if raw_values.len() == 1 => split_raw_form_tokens(&raw_values[0], style)?
            .into_iter()
            .map(decode_raw_form_component)
            .collect::<Vec<_>>(),
        _ => split_decoded_style_value(&values[0], style),
    };
    object_tokens_to_value(tokens, schema, conversion)
}

fn object_tokens_to_value(
    tokens: Vec<String>,
    schema: &Value,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    if !tokens.len().is_multiple_of(2) {
        return Err(
            "Serialized object property must contain alternating key/value items".to_string(),
        );
    }
    let empty_properties = serde_json::Map::new();
    let properties = merged_object_properties(schema, conversion).unwrap_or(&empty_properties);
    let mut out = serde_json::Map::new();
    for pair in tokens.chunks_exact(2) {
        let key = pair[0].clone();
        if key.is_empty() {
            return Err("Serialized object property contains an empty key".to_string());
        }
        if out.contains_key(&key) {
            return Err("Serialized object property contains a duplicate key".to_string());
        }
        let child_schema = properties.get(&key).unwrap_or(&Value::Null);
        out.insert(
            key,
            scalar_to_schema_value(pair[1].as_str(), child_schema, conversion)?,
        );
    }
    Ok(Value::Object(out))
}

fn form_values_to_schema_value(
    values: &[String],
    raw_values: Option<&[String]>,
    schema: &Value,
    encoding: Option<&PropertyEncoding>,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    let Some(encoding) = encoding.filter(|encoding| !encoding.explode) else {
        return values_to_schema_value(values, schema, encoding, conversion);
    };
    if !conversion.accepts_array(schema) {
        return values_to_schema_value(values, schema, Some(encoding), conversion);
    }
    let Some(raw_values) = raw_values else {
        return values_to_schema_value(values, schema, Some(encoding), conversion);
    };
    if values.len() != 1 || raw_values.len() != 1 {
        return Err(
            "Serialized array property must occur exactly once when explode=false".to_string(),
        );
    }
    let item_schema = array_item_schema_for_conversion(schema, conversion);
    let mut converted = Vec::new();
    for raw in raw_values {
        for token in split_raw_form_tokens(raw, encoding.style)? {
            let value = decode_raw_form_component(token);
            converted.push(scalar_to_schema_value(&value, item_schema, conversion)?);
        }
    }
    Ok(Value::Array(converted))
}

fn split_decoded_style_value(value: &str, style: EncodingStyle) -> Vec<String> {
    let delimiter = match style {
        EncodingStyle::Form => ',',
        EncodingStyle::SpaceDelimited => ' ',
        EncodingStyle::PipeDelimited => '|',
        EncodingStyle::DeepObject => return vec![value.to_string()],
    };
    value
        .split(delimiter)
        .map(str::trim)
        .map(str::to_string)
        .collect()
}

fn split_raw_form_tokens(value: &str, style: EncodingStyle) -> Result<Vec<&str>, String> {
    if style == EncodingStyle::DeepObject {
        return Err("deepObject style does not use a delimited property value".to_string());
    }
    let bytes = value.as_bytes();
    let mut tokens = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        let delimiter_len = match style {
            EncodingStyle::Form if bytes[index] == b',' => 1,
            EncodingStyle::SpaceDelimited if matches!(bytes[index], b' ' | b'+') => 1,
            EncodingStyle::SpaceDelimited
                if bytes[index..].get(..3).is_some_and(|candidate| {
                    candidate[0] == b'%' && candidate[1] == b'2' && candidate[2] == b'0'
                }) =>
            {
                3
            }
            EncodingStyle::PipeDelimited
                if bytes[index] == b'|'
                    || bytes[index..].get(..3).is_some_and(|candidate| {
                        candidate[0] == b'%'
                            && candidate[1] == b'7'
                            && candidate[2].eq_ignore_ascii_case(&b'c')
                    }) =>
            {
                if bytes[index] == b'|' {
                    1
                } else {
                    3
                }
            }
            _ => 0,
        };
        if delimiter_len == 0 {
            index += 1;
            continue;
        }
        tokens.push(&value[start..index]);
        index += delimiter_len;
        start = index;
    }
    tokens.push(&value[start..]);
    Ok(tokens)
}

fn decode_raw_form_component(value: &str) -> String {
    let encoded = format!("value={value}");
    url::form_urlencoded::parse(encoded.as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

fn object_property_schema<'a>(schema: &'a Value, property: &str) -> Option<&'a Value> {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(property))
        .or_else(|| {
            ["allOf", "oneOf", "anyOf"].into_iter().find_map(|keyword| {
                schema
                    .get(keyword)
                    .and_then(Value::as_array)
                    .and_then(|branches| {
                        branches
                            .iter()
                            .find_map(|branch| object_property_schema(branch, property))
                    })
            })
        })
}

fn take_deep_object_fields(
    fields: &HashMap<String, Vec<String>>,
    property: &str,
    consumed: &mut HashSet<String>,
) -> HashMap<String, Vec<String>> {
    let prefix = format!("{property}[");
    let mut out = HashMap::new();
    for (key, values) in fields {
        if let Some(child) = key
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix(']'))
        {
            consumed.insert(key.clone());
            out.insert(child.to_string(), values.clone());
        }
    }
    out
}

fn split_deep_object_key(key: &str) -> Option<(&str, &str)> {
    let open = key.find('[')?;
    let close = key.rfind(']')?;
    if close + 1 != key.len() || open == 0 || close <= open + 1 {
        return None;
    }
    Some((&key[..open], &key[open + 1..close]))
}

fn deep_object_fields_to_value(
    fields: &HashMap<String, Vec<String>>,
    schema: &Value,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    let object_schema = object_schema_for_conversion(schema, conversion);
    let empty_properties = serde_json::Map::new();
    let properties =
        merged_object_properties(object_schema, conversion).unwrap_or(&empty_properties);
    let mut out = serde_json::Map::new();
    for (child, child_schema) in properties {
        if let Some(values) = fields.get(child) {
            out.insert(
                child.clone(),
                values_to_schema_value(values, child_schema, None, conversion)?,
            );
        }
    }
    for (key, values) in fields {
        if !out.contains_key(key) {
            out.insert(
                key.clone(),
                values_to_schema_value(values, &Value::Null, None, conversion)?,
            );
        }
    }
    Ok(Value::Object(out))
}

fn multipart_parts_to_schema_object(
    parts: HashMap<String, Vec<MultipartPart>>,
    schema: &Value,
    encoding: &AHashMap<String, PropertyEncoding>,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    let object_schema = object_schema_for_conversion(schema, conversion);
    if !(conversion.accepts_object(object_schema) || object_schema.get("properties").is_some()) {
        let Some(values) = parts.values().next() else {
            return Ok(Value::Null);
        };
        return multipart_values_to_schema_value(values, schema, None, conversion);
    }
    let mut out = serde_json::Map::new();
    let empty_properties = serde_json::Map::new();
    let properties =
        merged_object_properties(object_schema, conversion).unwrap_or(&empty_properties);
    let mut consumed_keys = HashSet::new();
    for (property, property_schema) in properties {
        let property_encoding = encoding.get(property.as_str());
        if conversion.accepts_object(property_schema)
            && let Some(values) = parts.get(property)
            && values.len() == 1
            && values[0].filename.is_none()
            && is_structured_multipart_object_part(&values[0])
        {
            consumed_keys.insert(property.clone());
            out.insert(
                property.clone(),
                multipart_part_to_schema_value(
                    &values[0],
                    property_schema,
                    property_encoding,
                    conversion,
                )?,
            );
            continue;
        }
        if conversion.accepts_object(property_schema)
            && let Some(property_encoding) = property_encoding
        {
            if property_encoding.style == EncodingStyle::DeepObject {
                let object = deep_object_parts_to_value(
                    &parts,
                    property,
                    property_schema,
                    property_encoding,
                    &mut consumed_keys,
                    conversion,
                )?;
                if object.as_object().is_some_and(|object| !object.is_empty()) {
                    out.insert(property.clone(), object);
                }
                continue;
            }
            if property_encoding.style == EncodingStyle::Form && property_encoding.explode {
                let object = exploded_multipart_object_to_value(
                    &parts,
                    property_schema,
                    properties,
                    property_encoding,
                    &mut consumed_keys,
                    conversion,
                )?;
                if object.as_object().is_some_and(|object| !object.is_empty()) {
                    out.insert(property.clone(), object);
                }
                continue;
            }
            if !property_encoding.explode {
                if let Some(values) = parts.get(property) {
                    consumed_keys.insert(property.clone());
                    out.insert(
                        property.clone(),
                        serialized_multipart_object_to_value(
                            values,
                            property_schema,
                            property_encoding.style,
                            conversion,
                        )?,
                    );
                }
                continue;
            }
        }
        let Some(values) = parts.get(property) else {
            continue;
        };
        consumed_keys.insert(property.clone());
        let explode = property_encoding.map(|enc| enc.explode).unwrap_or(true);
        if conversion.accepts_array(property_schema) && explode {
            let item_schema = array_item_schema_for_conversion(property_schema, conversion);
            let array = values
                .iter()
                .map(|part| {
                    multipart_part_to_schema_value(part, item_schema, property_encoding, conversion)
                })
                .collect::<Result<Vec<_>, _>>()?;
            out.insert(property.clone(), Value::Array(array));
            continue;
        }
        if conversion.accepts_array(property_schema) && !explode {
            if values.len() != 1 {
                return Err(
                    "Serialized multipart array property must occur exactly once when explode=false"
                        .to_string(),
                );
            }
            let joined = values
                .iter()
                .map(|part| {
                    std::str::from_utf8(&part.body)
                        .map_err(|_| MULTIPART_FIELD_NOT_UTF8_DETAIL.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?
                .join(match property_encoding.map(|enc| enc.style) {
                    Some(EncodingStyle::SpaceDelimited) => " ",
                    Some(EncodingStyle::PipeDelimited) => "|",
                    _ => ",",
                });
            out.insert(
                property.clone(),
                values_to_schema_value(&[joined], property_schema, property_encoding, conversion)?,
            );
            continue;
        }
        if values.len() != 1 {
            return Err(format!(
                "Multipart field '{property}' occurs {} times but the schema expects a scalar",
                values.len()
            ));
        }
        if let Some(first) = values.first() {
            out.insert(
                property.clone(),
                multipart_part_to_schema_value(
                    first,
                    property_schema,
                    property_encoding,
                    conversion,
                )?,
            );
        }
    }
    for (key, values) in parts {
        if consumed_keys.contains(&key) || out.contains_key(&key) {
            continue;
        }
        let value = if values.len() == 1 {
            multipart_part_to_schema_value(
                &values[0],
                &Value::Null,
                encoding.get(key.as_str()),
                conversion,
            )?
        } else {
            Value::Array(
                values
                    .iter()
                    .map(|part| {
                        multipart_part_to_schema_value(
                            part,
                            &Value::Null,
                            encoding.get(&key),
                            conversion,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
        };
        out.insert(key, value);
    }
    Ok(Value::Object(out))
}

fn exploded_multipart_object_to_value(
    parts: &HashMap<String, Vec<MultipartPart>>,
    schema: &Value,
    root_properties: &serde_json::Map<String, Value>,
    encoding: &PropertyEncoding,
    consumed: &mut HashSet<String>,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    let empty_properties = serde_json::Map::new();
    let properties = merged_object_properties(schema, conversion).unwrap_or(&empty_properties);
    let mut out = serde_json::Map::new();
    for (child, child_schema) in properties {
        let Some(values) = parts.get(child) else {
            continue;
        };
        consumed.insert(child.clone());
        out.insert(
            child.clone(),
            multipart_values_to_schema_value(values, child_schema, Some(encoding), conversion)?,
        );
    }
    if let Some(additional_schema) = additional_property_schema_for_conversion(schema) {
        for (child, values) in parts {
            if consumed.contains(child) || root_properties.contains_key(child) {
                continue;
            }
            consumed.insert(child.clone());
            let value = match additional_schema {
                Some(additional_schema) => multipart_values_to_schema_value(
                    values,
                    additional_schema,
                    Some(encoding),
                    conversion,
                )?,
                None => multipart_values_to_schema_value(
                    values,
                    &Value::Null,
                    Some(encoding),
                    conversion,
                )?,
            };
            out.insert(child.clone(), value);
        }
    }
    Ok(Value::Object(out))
}

fn deep_object_parts_to_value(
    parts: &HashMap<String, Vec<MultipartPart>>,
    property: &str,
    schema: &Value,
    encoding: &PropertyEncoding,
    consumed: &mut HashSet<String>,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    let empty_properties = serde_json::Map::new();
    let properties = merged_object_properties(schema, conversion).unwrap_or(&empty_properties);
    let mut out = serde_json::Map::new();
    for (key, values) in parts {
        let Some((parent, child)) = split_deep_object_key(key) else {
            continue;
        };
        if parent != property {
            continue;
        }
        consumed.insert(key.clone());
        let child_schema = properties.get(child).unwrap_or(&Value::Null);
        out.insert(
            child.to_string(),
            multipart_values_to_schema_value(values, child_schema, Some(encoding), conversion)?,
        );
    }
    Ok(Value::Object(out))
}

fn serialized_multipart_object_to_value(
    values: &[MultipartPart],
    schema: &Value,
    style: EncodingStyle,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    if values.len() != 1 {
        return Err(
            "Serialized multipart object property must occur exactly once when explode=false"
                .to_string(),
        );
    }
    let text = std::str::from_utf8(&values[0].body)
        .map_err(|_| MULTIPART_FIELD_NOT_UTF8_DETAIL.to_string())?;
    object_tokens_to_value(split_decoded_style_value(text, style), schema, conversion)
}

fn multipart_values_to_schema_value(
    values: &[MultipartPart],
    schema: &Value,
    encoding: Option<&PropertyEncoding>,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    let explode = encoding.map(|enc| enc.explode).unwrap_or(true);
    if conversion.accepts_array(schema) && explode {
        let item_schema = array_item_schema_for_conversion(schema, conversion);
        return values
            .iter()
            .map(|part| multipart_part_to_schema_value(part, item_schema, encoding, conversion))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    if conversion.accepts_array(schema) && !explode {
        if values.len() != 1 {
            return Err(
                "Serialized multipart array property must occur exactly once when explode=false"
                    .to_string(),
            );
        }
        let joined = values
            .iter()
            .map(|part| {
                std::str::from_utf8(&part.body)
                    .map_err(|_| MULTIPART_FIELD_NOT_UTF8_DETAIL.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?
            .join(match encoding.map(|enc| enc.style) {
                Some(EncodingStyle::SpaceDelimited) => " ",
                Some(EncodingStyle::PipeDelimited) => "|",
                _ => ",",
            });
        return values_to_schema_value(&[joined], schema, encoding, conversion);
    }
    if values.len() != 1 {
        // The multipart `name` parameter is payload-derived, so only the
        // repetition count is reported (`GHSA-5p2h-fq6q-gwh9`).
        return Err(format!(
            "Multipart field occurs {} times but the schema expects a scalar",
            values.len()
        ));
    }
    let Some(first) = values.first() else {
        return Ok(Value::Null);
    };
    multipart_part_to_schema_value(first, schema, encoding, conversion)
}

/// Decode an Encoding Object Header Object `content` value under the existing
/// multipart header-size ceiling, then materialize a JSON Schema instance.
fn header_content_to_schema_value(
    value: &str,
    media_type: &str,
    schema: &Value,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    if value.len() > MAX_MULTIPART_HEADER_BYTES {
        return Err(format!(
            "header content exceeds {MAX_MULTIPART_HEADER_BYTES} bytes"
        ));
    }
    let media_type = media_type.to_ascii_lowercase();
    if is_json_media_type(&media_type) {
        // Header Object `content` JSON is governed by its own schema and the
        // original header bytes are forwarded verbatim, so it gets the same
        // duplicate-member screen as a top-level JSON body
        // (`GHSA-c78j-5w9p-cpq6`). No memo: a header value is a bounded
        // fragment that no other plugin re-screens, so it could only evict
        // useful entries.
        if let Some(reason) = screen_json_ambiguity(value.as_bytes(), None) {
            return Err(reason.to_string());
        }
        return serde_json::from_str(value)
            .map_err(|error| format!("Invalid JSON header content: {error}"));
    }
    if is_xml_media_type(&media_type) {
        return xml_body_to_value(value, schema, conversion);
    }
    if media_type == "application/x-www-form-urlencoded" {
        return form_urlencoded_to_value(value, schema, &AHashMap::new(), conversion);
    }
    if is_text_media_type(&media_type) {
        return scalar_to_schema_value(value, schema, conversion);
    }
    match binary_body_to_schema_instance(value.as_bytes(), schema)? {
        SchemaInstance::Value(instance) => Ok(instance),
        SchemaInstance::BinaryLengthOnly => Ok(Value::String(value.to_string())),
    }
}

fn multipart_part_to_schema_value(
    part: &MultipartPart,
    schema: &Value,
    encoding: Option<&PropertyEncoding>,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    // Every diagnostic below names the *declared* encoding header, which is
    // operator-controlled, and never `part.name` — a multipart `name` parameter
    // is chosen by whoever produced the body (`GHSA-5p2h-fq6q-gwh9`). The
    // enclosing property is already reported by the caller's own location.
    if let Some(encoding) = encoding {
        if let Some(expected) = &encoding.content_type {
            let actual = part
                .content_type
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("text/plain");
            if !content_type_matches_encoding(actual, expected) {
                return Err(format!(
                    "Multipart field content type does not match encoding contentType '{expected}'"
                ));
            }
        }
        for (header_name, header_validator) in &encoding.headers {
            let Some(header_value) = part.headers.get(header_name) else {
                if header_validator.required {
                    return Err(format!(
                        "Multipart field is missing required encoding header '{header_name}'"
                    ));
                }
                continue;
            };
            if header_value.len() > MAX_MULTIPART_HEADER_BYTES {
                return Err(format!(
                    "Multipart field header '{header_name}' exceeds {MAX_MULTIPART_HEADER_BYTES} bytes"
                ));
            }
            let converted = if let Some(media_type) = &header_validator.content_media_type {
                header_content_to_schema_value(
                    header_value,
                    media_type,
                    &header_validator.schema,
                    &header_validator.conversion,
                )
                .map_err(|error| {
                    format!(
                        "Multipart field header '{header_name}' failed content decoding: {error}"
                    )
                })?
            } else {
                scalar_to_schema_value_with_types(
                    header_value,
                    &header_validator.schema,
                    header_validator.schema_types,
                    schema_is_composed(&header_validator.schema)
                        .then_some(&header_validator.validator),
                )?
            };
            header_validator
                .validator
                .validate(&converted)
                .map_err(|error| {
                    let schema_path = error.schema_path().to_string();
                    let keyword = safe_keyword(&schema_path);
                    let location = safe_location(
                        &error.instance_path().to_string(),
                        &header_validator.safe_names,
                    );
                    format!(
                        "Multipart field header '{header_name}' failed validation at {location} (keyword '{keyword}')"
                    )
                })?;
        }
    }

    if conversion.accepts_object(schema) || schema.get("properties").is_some() {
        if part.filename.is_none()
            && let Some(media_type) = part
                .content_type
                .as_deref()
                .and_then(|value| content_type_base(Some(value)).map(str::to_ascii_lowercase))
        {
            if is_json_media_type(&media_type) {
                // Form-derived embedded JSON is governed by the same schema, so
                // it gets the same duplicate-member screen as a top-level JSON
                // body — the enclosing multipart body is not itself JSON, so
                // nothing else screens these bytes. No memo: a part is a
                // bounded fragment that is never the whole body another plugin
                // re-screens, so it could only evict useful entries.
                if let Some(reason) = screen_json_ambiguity(&part.body, None) {
                    return Err(format!("Multipart field: {reason}"));
                }
                return serde_json::from_slice(&part.body)
                    .map_err(|error| format!("Multipart field contains invalid JSON: {error}"));
            }
            if is_xml_media_type(&media_type) {
                let text = std::str::from_utf8(&part.body)
                    .map_err(|_| "Multipart field is not UTF-8 XML".to_string())?;
                return xml_body_to_value(text, schema, conversion);
            }
        }
        let mut out = serde_json::Map::new();
        if let Some(filename) = &part.filename {
            out.insert("filename".to_string(), Value::String(filename.clone()));
        }
        if let Some(content_type) = &part.content_type {
            out.insert(
                "content_type".to_string(),
                Value::String(content_type.clone()),
            );
        }
        out.insert(
            "size".to_string(),
            Value::Number(serde_json::Number::from(part.body.len() as u64)),
        );
        // Materialize the part body as a `content` string so the schema can
        // validate it. (A finding-#88 micro-optimization that skipped this copy
        // when the schema "couldn't validate content" was reverted: it was NOT
        // outcome-preserving — for `maxProperties` / `minProperties` /
        // `propertyNames` / `patternProperties` / `dependentRequired` / `not` /
        // `oneOf`-`anyOf` part schemas the mere presence of `content` changes
        // validity. The body is already bounded, so the copy is cheap.)
        if let Ok(text) = std::str::from_utf8(&part.body) {
            out.insert("content".to_string(), Value::String(text.to_string()));
        }
        return Ok(Value::Object(out));
    }
    if schema_format(schema) == Some("binary") || part.filename.is_some() {
        return binary_to_schema_value(&part.body, schema);
    }
    let text = std::str::from_utf8(&part.body)
        .map_err(|_| MULTIPART_FIELD_NOT_UTF8_DETAIL.to_string())?;
    if let Some(encoding) = encoding.filter(|enc| conversion.accepts_array(schema) && !enc.explode)
    {
        return values_to_schema_value(&[text.to_string()], schema, Some(encoding), conversion);
    }
    scalar_to_schema_value(text, schema, conversion)
}

fn is_structured_multipart_object_part(part: &MultipartPart) -> bool {
    part.content_type
        .as_deref()
        .and_then(|value| content_type_base(Some(value)))
        .is_some_and(|media_type| {
            let media_type = media_type.to_ascii_lowercase();
            is_json_media_type(&media_type) || is_xml_media_type(&media_type)
        })
}

fn content_type_matches_encoding(actual: &str, expected: &str) -> bool {
    let actual_base = content_type_base(Some(actual))
        .unwrap_or(actual)
        .to_ascii_lowercase();
    for candidate in expected.split(',') {
        let candidate = candidate.trim();
        if candidate.is_empty() {
            continue;
        }
        let candidate_base = content_type_base(Some(candidate))
            .unwrap_or(candidate)
            .to_ascii_lowercase();
        if candidate_base == "*/*"
            || actual_base == candidate_base
            || (candidate_base.ends_with("/*")
                && actual_base.starts_with(candidate_base.trim_end_matches('*')))
        {
            return true;
        }
    }
    false
}

fn values_to_schema_value(
    values: &[String],
    schema: &Value,
    encoding: Option<&PropertyEncoding>,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    if conversion.accepts_array(schema) {
        let item_schema = array_item_schema_for_conversion(schema, conversion);
        let explode = encoding.map(|enc| enc.explode).unwrap_or(true);
        let style = encoding.map(|enc| enc.style).unwrap_or(EncodingStyle::Form);
        let items: Vec<String> = if !explode {
            let delimiter = match style {
                EncodingStyle::Form => ',',
                EncodingStyle::SpaceDelimited => ' ',
                EncodingStyle::PipeDelimited => '|',
                EncodingStyle::DeepObject => {
                    return Err("deepObject style is not valid for array properties".to_string());
                }
            };
            values
                .iter()
                .flat_map(|value| value.split(delimiter).map(str::trim).map(str::to_string))
                .collect()
        } else {
            values.to_vec()
        };
        return items
            .iter()
            .map(|value| scalar_to_schema_value(value, item_schema, conversion))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    if values.len() > 1 {
        return Err("Repeated form field values are not allowed for non-array schemas".to_string());
    }
    let value = values.first().map(String::as_str).unwrap_or("");
    scalar_to_schema_value(value, schema, conversion)
}

fn scalar_to_schema_value(
    value: &str,
    schema: &Value,
    conversion: &ConversionPlan,
) -> Result<Value, String> {
    scalar_to_schema_value_with_types(
        value,
        schema,
        conversion.schema_types(schema),
        conversion.composed_scalar_validator(schema),
    )
}

fn scalar_to_schema_value_with_types(
    value: &str,
    schema: &Value,
    types: SchemaTypeSet,
    composed_validator: Option<&jsonschema::Validator>,
) -> Result<Value, String> {
    if types.is_empty() {
        return Ok(Value::String(value.to_string()));
    }

    let composed = schema_is_composed(schema);
    if composed {
        let validator = composed_validator.ok_or_else(|| {
            "Composed scalar schema was not precompiled at plugin construction".to_string()
        })?;
        let mut parsed = Vec::with_capacity(4);

        // Serialized form fields do not carry a native JSON type. Try every
        // compatible primitive in a stable order, but accept a conversion only
        // when the complete composed property schema validates it. This avoids
        // both branch-order selection and the old failure where an integer
        // parse succeeded even though its branch constraints failed while a
        // string/boolean candidate would have satisfied another branch.
        if types.contains(ScalarType::Integer)
            && let Ok(candidate) = parse_integer_value(value)
        {
            parsed.push(candidate);
        }
        if types.contains(ScalarType::Number)
            && let Ok(candidate) = parse_number_value(value)
            && !parsed.contains(&candidate)
        {
            parsed.push(candidate);
        }
        if types.contains(ScalarType::Boolean)
            && let Ok(candidate) = parse_boolean_value(value)
        {
            parsed.push(candidate);
        }
        if types.contains(ScalarType::String) {
            parsed.push(Value::String(value.to_string()));
        }
        if let Some(candidate) = parsed
            .into_iter()
            .find(|candidate| validator.is_valid(candidate))
        {
            return Ok(candidate);
        }
        return Err(COMPOSED_SCALAR_CONVERSION_DETAIL.to_string());
    }

    let multi = types.len() > 1;
    let mut last_error = None;

    // Deterministic try order — never depends on oneOf/anyOf branch order.
    if types.contains(ScalarType::Integer) {
        match parse_integer_value(value) {
            Ok(parsed) => return Ok(parsed),
            Err(error) if !multi => return Err(error),
            Err(error) => last_error = Some(error),
        }
    }
    if types.contains(ScalarType::Number) {
        match parse_number_value(value) {
            Ok(parsed) => return Ok(parsed),
            Err(error) if !multi => return Err(error),
            Err(error) => last_error = Some(error),
        }
    }
    if types.contains(ScalarType::Boolean) {
        match parse_boolean_value(value) {
            Ok(parsed) => return Ok(parsed),
            Err(error) if !multi => return Err(error),
            Err(error) => last_error = Some(error),
        }
    }
    if types.contains(ScalarType::String) {
        return Ok(Value::String(value.to_string()));
    }
    Err(last_error.unwrap_or_else(|| SCALAR_CONVERSION_DETAIL.to_string()))
}

fn parse_integer_value(value: &str) -> Result<Value, String> {
    let parsed = value
        .parse::<i64>()
        .map_err(|_| "Invalid integer value".to_string())?;
    Ok(Value::Number(serde_json::Number::from(parsed)))
}

fn parse_number_value(value: &str) -> Result<Value, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| "Invalid number value".to_string())?;
    let number = serde_json::Number::from_f64(parsed)
        .ok_or_else(|| "Invalid finite number value".to_string())?;
    Ok(Value::Number(number))
}

fn parse_boolean_value(value: &str) -> Result<Value, String> {
    let value = value.trim();
    if value == "1"
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("on")
    {
        return Ok(Value::Bool(true));
    }
    if value == "0"
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("off")
    {
        return Ok(Value::Bool(false));
    }
    Err("Invalid boolean value".to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScalarType {
    Integer,
    Number,
    Boolean,
    String,
    Null,
    Object,
    Array,
}

/// Compact, allocation-free set of JSON Schema types/shapes discovered for a
/// schema node (including `allOf`/`oneOf`/`anyOf` contributions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct SchemaTypeSet(u8);

impl SchemaTypeSet {
    const INTEGER: u8 = 1 << 0;
    const NUMBER: u8 = 1 << 1;
    const BOOLEAN: u8 = 1 << 2;
    const STRING: u8 = 1 << 3;
    const NULL: u8 = 1 << 4;
    const OBJECT: u8 = 1 << 5;
    const ARRAY: u8 = 1 << 6;

    fn bit(kind: ScalarType) -> u8 {
        match kind {
            ScalarType::Integer => Self::INTEGER,
            ScalarType::Number => Self::NUMBER,
            ScalarType::Boolean => Self::BOOLEAN,
            ScalarType::String => Self::STRING,
            ScalarType::Null => Self::NULL,
            ScalarType::Object => Self::OBJECT,
            ScalarType::Array => Self::ARRAY,
        }
    }

    fn insert(&mut self, kind: ScalarType) {
        self.0 |= Self::bit(kind);
    }

    fn contains(self, kind: ScalarType) -> bool {
        self.0 & Self::bit(kind) != 0
    }

    fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn len(self) -> u32 {
        self.0.count_ones()
    }

    fn has_scalar_primitive(self) -> bool {
        self.contains(ScalarType::Integer)
            || self.contains(ScalarType::Number)
            || self.contains(ScalarType::Boolean)
            || self.contains(ScalarType::String)
    }
}

fn collect_schema_types(schema: &Value) -> SchemaTypeSet {
    let mut out = SchemaTypeSet::default();
    collect_types_into(schema, &mut out, 0);
    out
}

fn collect_types_into(schema: &Value, out: &mut SchemaTypeSet, depth: usize) {
    if depth > 32 {
        return;
    }
    push_declared_types(schema, out);
    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            collect_types_into(branch, out, depth + 1);
        }
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(branches) = schema.get(key).and_then(Value::as_array) {
            for branch in branches {
                collect_types_into(branch, out, depth + 1);
            }
        }
    }
}

fn push_declared_types(schema: &Value, out: &mut SchemaTypeSet) {
    match schema.get("type") {
        Some(Value::String(value)) => {
            if let Some(parsed) = parse_scalar_type(value) {
                out.insert(parsed);
            }
        }
        Some(Value::Array(values)) => {
            for value in values {
                if let Some(text) = value.as_str()
                    && let Some(parsed) = parse_scalar_type(text)
                {
                    out.insert(parsed);
                }
            }
        }
        _ => {}
    }
    if schema.get("properties").is_some() {
        out.insert(ScalarType::Object);
    }
    if schema.get("items").is_some() {
        out.insert(ScalarType::Array);
    }
}

fn parse_scalar_type(value: &str) -> Option<ScalarType> {
    match value {
        "integer" => Some(ScalarType::Integer),
        "number" => Some(ScalarType::Number),
        "boolean" => Some(ScalarType::Boolean),
        "string" => Some(ScalarType::String),
        "null" => Some(ScalarType::Null),
        "object" => Some(ScalarType::Object),
        "array" => Some(ScalarType::Array),
        _ => None,
    }
}

fn schema_is_composed(schema: &Value) -> bool {
    schema.get("allOf").is_some() || schema.get("oneOf").is_some() || schema.get("anyOf").is_some()
}

/// Admission-time helper for Encoding Object checks before a ConversionPlan exists.
fn schema_accepts_object(schema: &Value) -> bool {
    collect_schema_types(schema).contains(ScalarType::Object)
}

/// Admission-time helper for Encoding Object checks before a ConversionPlan exists.
fn schema_accepts_array(schema: &Value) -> bool {
    collect_schema_types(schema).contains(ScalarType::Array)
}

/// Resolve the item schema used to deserialize textual array members without
/// choosing a `oneOf`/`anyOf` branch by array order. The original parent schema
/// remains authoritative for final validation.
fn build_array_item_schema_for_conversion(schema: &Value) -> Value {
    if !schema_is_composed(schema) {
        return schema.get("items").cloned().unwrap_or(Value::Null);
    }
    composed_array_item_schema(schema, 0).unwrap_or(Value::Null)
}

fn array_item_schema_for_conversion<'a>(
    schema: &'a Value,
    conversion: &'a ConversionPlan,
) -> &'a Value {
    conversion.array_item_schema(schema)
}

fn composed_array_item_schema(schema: &Value, depth: usize) -> Option<Value> {
    if depth > 32 {
        return None;
    }
    let mut constraints = Vec::new();
    if let Some(items) = schema.get("items") {
        constraints.push(items.clone());
    }
    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            if let Some(items) = composed_array_item_schema(branch, depth + 1) {
                constraints.push(items);
            }
        }
    }
    for keyword in ["oneOf", "anyOf"] {
        let Some(branches) = schema.get(keyword).and_then(Value::as_array) else {
            continue;
        };
        let alternatives: Vec<Value> = branches
            .iter()
            .filter_map(|branch| composed_array_item_schema(branch, depth + 1))
            .collect();
        if !alternatives.is_empty() {
            let mut composition = serde_json::Map::new();
            composition.insert(keyword.to_string(), Value::Array(alternatives));
            constraints.push(Value::Object(composition));
        }
    }
    match constraints.len() {
        0 => None,
        1 => constraints.pop(),
        _ => Some(serde_json::json!({"allOf": constraints})),
    }
}

/// `None` means additional properties are forbidden. `Some(None)` means they
/// are allowed without a child schema; `Some(Some(schema))` carries the schema.
fn additional_property_schema_for_conversion(schema: &Value) -> Option<Option<&Value>> {
    match schema.get("additionalProperties") {
        Some(Value::Bool(false)) => None,
        Some(Value::Object(_)) => Some(schema.get("additionalProperties")),
        _ => Some(None),
    }
}

/// Build a conversion-time object schema that merges `allOf` property maps and
/// unions properties declared across `oneOf`/`anyOf` object branches.
fn build_object_schema_for_conversion(schema: &Value) -> Value {
    if !schema_is_composed(schema) {
        return schema.clone();
    }
    let mut merged = serde_json::Map::new();
    if let Some(object) = schema.as_object() {
        for (key, value) in object {
            if !matches!(key.as_str(), "allOf" | "oneOf" | "anyOf") {
                merged.insert(key.clone(), value.clone());
            }
        }
    }
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    merge_composition_object_fields(schema, &mut properties, &mut required, 0);
    if !properties.is_empty() {
        merged.insert("properties".to_string(), Value::Object(properties));
        merged.insert("type".to_string(), Value::String("object".to_string()));
    }
    if !required.is_empty() {
        required.sort();
        required.dedup();
        merged.insert(
            "required".to_string(),
            Value::Array(required.into_iter().map(Value::String).collect()),
        );
    }
    Value::Object(merged)
}

fn object_schema_for_conversion<'a>(
    schema: &'a Value,
    conversion: &'a ConversionPlan,
) -> &'a Value {
    conversion.object_schema(schema)
}

fn merge_composition_object_fields(
    schema: &Value,
    properties: &mut serde_json::Map<String, Value>,
    required: &mut Vec<String>,
    depth: usize,
) {
    if depth > 32 {
        return;
    }
    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        for (key, value) in props {
            match properties.entry(key.clone()) {
                serde_json::map::Entry::Vacant(entry) => {
                    entry.insert(value.clone());
                }
                serde_json::map::Entry::Occupied(mut entry) => {
                    // Conversion needs every branch's possible property type.
                    // Use an order-insensitive union here; the original root
                    // schema remains authoritative for final validation.
                    let existing = entry.get().clone();
                    entry.insert(serde_json::json!({"anyOf": [existing, value.clone()]}));
                }
            }
        }
    }
    if let Some(req) = schema.get("required").and_then(Value::as_array) {
        for item in req {
            if let Some(name) = item.as_str() {
                required.push(name.to_string());
            }
        }
    }
    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            merge_composition_object_fields(branch, properties, required, depth + 1);
        }
    }
    // For oneOf/anyOf, union property declarations so later branches are not
    // discarded during form/multipart field conversion.
    for key in ["oneOf", "anyOf"] {
        if let Some(branches) = schema.get(key).and_then(Value::as_array) {
            for branch in branches {
                merge_composition_object_fields(branch, properties, required, depth + 1);
            }
        }
    }
}

fn merged_object_properties<'a>(
    schema: &'a Value,
    conversion: &'a ConversionPlan,
) -> Option<&'a serde_json::Map<String, Value>> {
    object_schema_for_conversion(schema, conversion)
        .get("properties")
        .and_then(Value::as_object)
}

fn binary_body_to_schema_instance(body: &[u8], schema: &Value) -> Result<SchemaInstance, String> {
    match std::str::from_utf8(body) {
        Ok(value) => Ok(SchemaInstance::Value(Value::String(value.to_string()))),
        Err(_) => {
            validate_binary_length(body.len(), schema)?;
            Ok(SchemaInstance::BinaryLengthOnly)
        }
    }
}

fn binary_to_schema_value(body: &[u8], schema: &Value) -> Result<Value, String> {
    match std::str::from_utf8(body) {
        Ok(value) => Ok(Value::String(value.to_string())),
        Err(_) => {
            validate_binary_length(body.len(), schema)?;
            Err(
                "Non-UTF-8 multipart binary fields require an object schema to validate metadata"
                    .to_string(),
            )
        }
    }
}

fn validate_binary_length(len: usize, schema: &Value) -> Result<(), String> {
    let types = collect_schema_types(schema);
    if schema.get("type").is_some() && !types.contains(ScalarType::String) {
        return Err(
            "Non-UTF-8 binary bodies require a string schema with optional minLength/maxLength"
                .to_string(),
        );
    }
    if let Some(min_length) = schema_usize(schema, "minLength")
        && len < min_length
    {
        return Err(format!(
            "Binary body length {len} is shorter than minLength {min_length}"
        ));
    }
    if let Some(max_length) = schema_usize(schema, "maxLength")
        && len > max_length
    {
        return Err(format!(
            "Binary body length {len} exceeds maxLength {max_length}"
        ));
    }
    Ok(())
}

fn schema_usize(schema: &Value, key: &str) -> Option<usize> {
    schema
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
}

fn validator_for_content_type<'a>(
    validators: &'a AHashMap<String, MediaValidator>,
    content_type: Option<&str>,
) -> Option<&'a MediaValidator> {
    let base = content_type_base(content_type)?;
    // OpenAPI media-range specificity: the most specific declared entry wins.
    // Concrete media types (exact, then Ferrum's `+json` / `+xml` / `text/*`
    // family fallbacks) outrank `type/*`, which outranks `*/*`.
    validators
        .iter()
        .find(|(expected, _)| expected.eq_ignore_ascii_case(base))
        .map(|(_, validator)| validator)
        .or_else(|| fallback_validator_for_media_type(validators, base))
        .or_else(|| media_range_validator(validators, base))
}

/// Match a declared `type/*` range, then `*/*`.
fn media_range_validator<'a>(
    validators: &'a AHashMap<String, MediaValidator>,
    actual: &str,
) -> Option<&'a MediaValidator> {
    let (actual_type, _) = actual.split_once('/')?;
    for (expected, validator) in validators {
        let Some((expected_type, expected_subtype)) = expected.split_once('/') else {
            continue;
        };
        if expected_subtype != "*" || expected_type == "*" {
            continue;
        }
        if expected_type.eq_ignore_ascii_case(actual_type) {
            return Some(validator);
        }
    }
    validators.get("*/*")
}

fn content_type_in_scope(configured: &[String], content_type: Option<&str>) -> bool {
    let Some(base) = content_type_base(content_type) else {
        return false;
    };
    configured.is_empty()
        || configured
            .iter()
            .any(|expected| media_type_matches(expected, base))
}

fn normalize_configured_media_types(
    values: Vec<String>,
    field: &'static str,
) -> Result<Vec<String>, String> {
    let mut normalized = Vec::with_capacity(values.len());
    let mut seen = HashSet::with_capacity(values.len());
    for (index, value) in values.into_iter().enumerate() {
        validate_media_type_key(&value, &format!("config.{field}[{index}]"))?;
        let value = normalize_media_type(&value);
        if !seen.insert(value.clone()) {
            return Err(format!(
                "{ERROR_PREFIX}'{field}' contains duplicate media type '{value}' after normalization"
            ));
        }
        normalized.push(value);
    }
    Ok(normalized)
}

fn content_type_base(content_type: Option<&str>) -> Option<&str> {
    let base = content_type?.split(';').next().unwrap_or("").trim();
    (!base.is_empty()).then_some(base)
}

/// Structural gate for free-form media-type map keys.
///
/// Media-type maps cannot be key-enumerated, so a typo is caught by shape
/// instead: the key must be `type/subtype`, `type/*`, or `*/*` built from RFC
/// 9110 tokens. This is what keeps a misspelled fixed field from masquerading
/// as a media type once the "object is its own content map" fallback is gone.
fn validate_media_type_key(key: &str, path: &str) -> Result<(), String> {
    if key.chars().any(char::is_control) {
        return Err(format!(
            "{ERROR_PREFIX}'{path}' contains a media type with control characters"
        ));
    }
    let base = key.split(';').next().unwrap_or("").trim();
    if is_media_type_or_range(base) {
        Ok(())
    } else {
        Err(format!(
            "{ERROR_PREFIX}'{path}' contains '{key}', which is not a media type or media range"
        ))
    }
}

fn is_media_type_or_range(base: &str) -> bool {
    let Some((type_, subtype)) = base.split_once('/') else {
        return false;
    };
    if type_ == "*" {
        return subtype == "*";
    }
    is_mime_token(type_) && (subtype == "*" || is_mime_token(subtype))
}

fn validate_concrete_media_type(value: &str, path: &str) -> Result<(), String> {
    if value.parse::<http::HeaderValue>().is_err() {
        return Err(format!(
            "{ERROR_PREFIX}'{path}' must be a valid HTTP header value"
        ));
    }
    if !is_concrete_http_media_type(value) {
        return Err(format!(
            "{ERROR_PREFIX}'{path}' must be a concrete media type"
        ));
    }
    Ok(())
}

fn optional_object<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<&'a serde_json::Map<String, Value>>, String> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value)),
        Some(_) => Err(format!("{ERROR_PREFIX}'{key}' must be an object")),
    }
}

fn normalize_media_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn default_content_types() -> Vec<String> {
    OPENAPI_VALIDATOR_DEFAULT_CONTENT_TYPES
        .iter()
        .map(|value| value.to_string())
        .collect()
}

fn fallback_validator_for_media_type<'a>(
    validators: &'a AHashMap<String, MediaValidator>,
    actual: &str,
) -> Option<&'a MediaValidator> {
    if is_json_media_type(actual) {
        return validators.get("application/json");
    }
    if is_xml_media_type(actual) {
        return validators
            .get("application/xml")
            .or_else(|| validators.get("text/xml"));
    }
    if actual.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        return validators.get("application/x-www-form-urlencoded");
    }
    if actual.eq_ignore_ascii_case("multipart/form-data") {
        return validators.get("multipart/form-data");
    }
    if is_text_media_type(actual) {
        return validators.get("text/plain");
    }
    validators.get("application/octet-stream")
}

fn media_type_matches(expected: &str, actual: &str) -> bool {
    let range_matches = expected == "*/*"
        || expected.split_once('/').is_some_and(|(type_, subtype)| {
            subtype == "*"
                && type_ != "*"
                && actual
                    .split_once('/')
                    .is_some_and(|(actual_type, _)| type_.eq_ignore_ascii_case(actual_type))
        });
    expected.eq_ignore_ascii_case(actual)
        || range_matches
        || (expected == "application/json" && is_json_media_type(actual))
        || ((expected == "application/xml" || expected == "text/xml") && is_xml_media_type(actual))
        || (expected == "text/plain" && is_text_media_type(actual))
        || (expected == "application/octet-stream" && is_binary_media_type(actual))
}

fn is_json_media_type(media_type: &str) -> bool {
    media_type.eq_ignore_ascii_case("application/json")
        || ascii_ends_with_ignore_case(media_type, "+json")
}

fn is_xml_media_type(media_type: &str) -> bool {
    media_type.eq_ignore_ascii_case("application/xml")
        || media_type.eq_ignore_ascii_case("text/xml")
        || ascii_ends_with_ignore_case(media_type, "+xml")
}

fn is_text_media_type(media_type: &str) -> bool {
    media_type.eq_ignore_ascii_case("text/plain")
        || ascii_starts_with_ignore_case(media_type, "text/")
}

fn is_binary_media_type(media_type: &str) -> bool {
    media_type.eq_ignore_ascii_case("application/octet-stream")
        || ascii_starts_with_ignore_case(media_type, "image/")
        || ascii_starts_with_ignore_case(media_type, "audio/")
        || ascii_starts_with_ignore_case(media_type, "video/")
        || (ascii_starts_with_ignore_case(media_type, "application/")
            && !is_json_media_type(media_type)
            && !is_xml_media_type(media_type)
            && !media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
}

fn ascii_starts_with_ignore_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn ascii_ends_with_ignore_case(value: &str, suffix: &str) -> bool {
    value
        .as_bytes()
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(suffix.as_bytes()))
}

fn multipart_boundary(content_type: &str) -> Result<Option<String>, String> {
    let (_, mut params) = parse_header_type_and_params(content_type)?;
    let Some(param) = params.remove("boundary") else {
        return Ok(None);
    };
    // RFC 2045/2046: characters outside the MIME token grammar (spaces, `:`,
    // `/`, etc.) are only legal inside a quoted-string. Retain quote state so
    // unquoted `boundary=abc:def` cannot silently become a valid delimiter.
    if !param.was_quoted && !is_mime_token(&param.value) {
        return Err(
            "Unquoted multipart boundary must be a MIME token (quote values that require quoting)"
                .to_string(),
        );
    }
    Ok(Some(param.value))
}

#[derive(Debug, Clone)]
struct HeaderParamValue {
    value: String,
    was_quoted: bool,
}

/// Parse a MIME/HTTP header into its type token and parameters with
/// quoted-string / escape awareness.
///
/// Semicolons and escapes inside quoted values are preserved. The first
/// semicolon-delimited segment is the media type or disposition type.
fn parse_header_type_and_params(
    value: &str,
) -> Result<(String, HashMap<String, HeaderParamValue>), String> {
    if value.len() > MAX_MULTIPART_PARAM_BYTES * 4 {
        return Err("Header parameter list exceeds size limit".to_string());
    }
    let mut params = HashMap::new();
    let mut parts = split_header_param_segments(value)?;
    if parts.is_empty() {
        return Ok((String::new(), params));
    }
    let type_token = parts.remove(0).trim().to_string();
    for piece in parts {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        // MIME parameters are always `attribute=value`. Bare segments such as
        // `filename*` / `filename*0` must fail closed so extended filename
        // family markers cannot disappear before file-part resolution.
        let Some((key, raw_value)) = piece.split_once('=') else {
            return Err("Malformed header parameter: expected name=value".to_string());
        };
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() || key.len() > 256 || !is_mime_token(&key) {
            return Err("Invalid header parameter name".to_string());
        }
        let decoded = decode_header_param_value(raw_value.trim())?;
        if decoded.value.len() > MAX_MULTIPART_PARAM_BYTES {
            return Err("Header parameter exceeds size limit".to_string());
        }
        if params.insert(key, decoded).is_some() {
            return Err("Duplicate header parameter".to_string());
        }
    }
    Ok((type_token, params))
}

fn split_header_param_segments(value: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => {
                current.push(ch);
                escaped = true;
            }
            '"' => {
                current.push(ch);
                in_quotes = !in_quotes;
            }
            ';' if !in_quotes => {
                out.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
        if out.len() > 64 {
            return Err("Too many header parameters".to_string());
        }
    }
    if in_quotes {
        return Err("Unterminated quoted header parameter".to_string());
    }
    if escaped {
        return Err("Trailing escape in header parameter".to_string());
    }
    out.push(current);
    Ok(out)
}

fn decode_header_param_value(value: &str) -> Result<HeaderParamValue, String> {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        let inner = &value[1..value.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                let Some(next) = chars.next() else {
                    return Err("Trailing escape in quoted header parameter".to_string());
                };
                out.push(next);
            } else {
                out.push(ch);
            }
        }
        return Ok(HeaderParamValue {
            value: out,
            was_quoted: true,
        });
    }
    if value.contains(['"', '\\']) {
        return Err("Unquoted header parameter contains illegal characters".to_string());
    }
    Ok(HeaderParamValue {
        value: value.to_string(),
        was_quoted: false,
    })
}

/// Resolve the effective multipart filename from Content-Disposition params.
///
/// Supports ordinary RFC 7578 `filename` and a single RFC 5987/8187
/// `filename*` extended value (`charset'language'value-chars`). Continuations
/// (`filename*0*`, …), duplicates, ambiguous `filename`+`filename*`, quoted
/// `filename*` (RFC 8187 `ext-value` is not a quoted-string), unsupported
/// charsets, malformed percent-encoding, invalid UTF-8, CR/LF/NUL, and encoded
/// length overflow fail closed. A decoded-length cap is kept as defense in
/// depth even though percent-decoding cannot expand past the raw value-chars
/// budget. Either form marks a file part so structured body spoofing cannot
/// demote the part to a non-file field.
fn resolve_multipart_filename(
    params: &HashMap<String, HeaderParamValue>,
) -> Result<Option<String>, String> {
    let mut filename_star: Option<&HeaderParamValue> = None;
    for (key, value) in params {
        if key == "filename*" {
            filename_star = Some(value);
        } else if key.starts_with("filename*") {
            // RFC 2231 continuations / sectioned forms are unsupported.
            return Err(
                "Malformed multipart part: filename* continuations are unsupported".to_string(),
            );
        }
    }

    let ordinary = params.get("filename");
    match (ordinary, filename_star) {
        (Some(_), Some(_)) => {
            Err("Malformed multipart part: ambiguous filename and filename* parameters".to_string())
        }
        (Some(ordinary), None) => {
            if ordinary.value.len() > MAX_MULTIPART_PARAM_BYTES {
                return Err("Multipart filename exceeds size limit".to_string());
            }
            reject_filename_injection(&ordinary.value)?;
            Ok(Some(ordinary.value.clone()))
        }
        (None, Some(extended)) => {
            // RFC 8187 `ext-value` is not a quoted-string. Stripping quotes and
            // decoding would accept a non-conforming wire form.
            if extended.was_quoted {
                return Err(
                    "Malformed multipart part: filename* must not be a quoted-string".to_string(),
                );
            }
            let decoded = decode_rfc8187_filename_star(&extended.value)?;
            Ok(Some(decoded))
        }
        (None, None) => Ok(None),
    }
}

/// Decode RFC 8187 `ext-value` for `filename*`: `charset'language'value-chars`.
///
/// Supported charset is UTF-8 only (case-insensitive). Language tags, when
/// present, must be a conservative ASCII subset and are otherwise ignored for
/// decoding. `value-chars` may contain only `attr-char` and well-formed
/// percent-encoded octets; the decoded byte sequence must be valid UTF-8.
fn decode_rfc8187_filename_star(raw: &str) -> Result<String, String> {
    if raw.len() > MAX_MULTIPART_PARAM_BYTES {
        return Err("Multipart filename* exceeds size limit".to_string());
    }
    let Some((charset, rest)) = raw.split_once('\'') else {
        return Err(
            "Malformed multipart part: filename* must use charset'language'value form".to_string(),
        );
    };
    let Some((language, value_chars)) = rest.split_once('\'') else {
        return Err(
            "Malformed multipart part: filename* must use charset'language'value form".to_string(),
        );
    };
    if !charset.eq_ignore_ascii_case("utf-8") {
        return Err(
            "Malformed multipart part: unsupported filename* charset (only UTF-8 is supported)"
                .to_string(),
        );
    }
    if !is_supported_rfc8187_language(language) {
        return Err("Malformed multipart part: invalid filename* language tag".to_string());
    }
    if value_chars.len() > MAX_MULTIPART_PARAM_BYTES {
        return Err("Multipart filename* exceeds size limit".to_string());
    }
    // Percent-decoding maps 3 wire bytes to 1 output byte (or copies attr-char
    // 1:1), so decoded length cannot exceed the raw value-chars cap above. The
    // decoded-length checks below are defense in depth only.
    let decoded_bytes = decode_rfc8187_value_chars(value_chars)?;
    if decoded_bytes.len() > MAX_MULTIPART_PARAM_BYTES {
        return Err("Multipart filename* decoded value exceeds size limit".to_string());
    }
    let decoded = String::from_utf8(decoded_bytes).map_err(|_| {
        "Malformed multipart part: filename* decoded value is not valid UTF-8".to_string()
    })?;
    reject_filename_injection(&decoded)?;
    Ok(decoded)
}

fn is_supported_rfc8187_language(language: &str) -> bool {
    // Empty language is common (`UTF-8''file.txt`). Non-empty tags are limited
    // to a conservative Language-Tag subset: 1*8ALPHA *("-" 1*8alphanum).
    if language.is_empty() {
        return true;
    }
    let mut parts = language.split('-');
    let Some(primary) = parts.next() else {
        return false;
    };
    if !(1..=8).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    for subtag in parts {
        if !(1..=8).contains(&subtag.len()) || !subtag.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return false;
        }
    }
    true
}

fn decode_rfc8187_value_chars(value_chars: &str) -> Result<Vec<u8>, String> {
    let bytes = value_chars.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let Some(hi) = bytes
                    .get(index + 1)
                    .copied()
                    .and_then(|byte| char::from(byte).to_digit(16))
                else {
                    return Err(
                        "Malformed multipart part: filename* contains malformed percent-encoding"
                            .to_string(),
                    );
                };
                let Some(lo) = bytes
                    .get(index + 2)
                    .copied()
                    .and_then(|byte| char::from(byte).to_digit(16))
                else {
                    return Err(
                        "Malformed multipart part: filename* contains malformed percent-encoding"
                            .to_string(),
                    );
                };
                out.push(((hi << 4) | lo) as u8);
                index += 3;
            }
            byte if is_rfc8187_attr_char(byte) => {
                out.push(byte);
                index += 1;
            }
            _ => {
                return Err(
                    "Malformed multipart part: filename* value contains characters outside attr-char"
                        .to_string(),
                );
            }
        }
        // Defense in depth: unreachable while callers cap value_chars length
        // first, because decoding never expands past the wire length.
        if out.len() > MAX_MULTIPART_PARAM_BYTES {
            return Err("Multipart filename* decoded value exceeds size limit".to_string());
        }
    }
    Ok(out)
}

/// RFC 8187 `attr-char`.
fn is_rfc8187_attr_char(byte: u8) -> bool {
    matches!(
        byte,
        b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'!'
            | b'#'
            | b'$'
            | b'&'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}

fn reject_filename_injection(filename: &str) -> Result<(), String> {
    if filename
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err("Malformed multipart part: filename contains CR, LF, or NUL".to_string());
    }
    Ok(())
}

/// RFC 2045 `token`: 1* any CHAR except SPACE, CTLs, or tspecials.
/// Retained for multipart Content-Type parameter names/values (including
/// boundary) where the historical MIME token grammar still applies.
fn is_mime_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_mime_token_char)
}

fn is_mime_token_char(byte: u8) -> bool {
    // RFC 2045 token = 1*<any CHAR except SPACE, CTLs, or tspecials>
    matches!(
        byte,
        b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'{'
            | b'|'
            | b'}'
            | b'~'
    )
}

fn parse_part_headers(header_bytes: &[u8]) -> Result<HashMap<String, String>, String> {
    let headers = std::str::from_utf8(header_bytes)
        .map_err(|error| format!("Multipart headers are not UTF-8: {error}"))?;
    let mut out = HashMap::new();
    let mut lines = 0usize;
    for line in headers.split_inclusive(['\n']) {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            continue;
        }
        lines += 1;
        if lines > MAX_MULTIPART_HEADER_LINES {
            return Err(format!(
                "Multipart part exceeds {MAX_MULTIPART_HEADER_LINES} header lines"
            ));
        }
        // RFC 7230 folded headers are obsolete; reject rather than silently join.
        if line.starts_with([' ', '\t']) {
            return Err("Malformed multipart headers: obsolete line folding".to_string());
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("Malformed multipart header line".to_string());
        };
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || http::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
            return Err("Malformed multipart header name".to_string());
        }
        let value = value.trim();
        if http::HeaderValue::from_bytes(value.as_bytes()).is_err() {
            return Err("Malformed multipart header value".to_string());
        }
        if out.insert(name, value.to_string()).is_some() {
            return Err("Malformed multipart part: duplicate header".to_string());
        }
    }
    Ok(out)
}

/// Choose the earliest header/body separator: the first blank line, i.e. the
/// first CRLF/LF line terminator immediately followed by another CRLF/LF
/// terminator.
///
/// Matching only `\r\n\r\n` and `\n\n` (and taking the lower index) still misses
/// mixed `\n\r\n` / `\r\n\n` blank lines. A part whose header block ends with an
/// LF line but whose blank line is CRLF (`...name"\n\r\n...`) then has no early
/// match, so a later separator wins and the intervening body prefix is
/// reclassified as part headers. Scanning every terminator keeps the earliest
/// blank line winning regardless of CRLF/LF mixing, so body bytes before a later
/// separator can never be promoted into headers.
fn split_header_body(segment: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut search = 0;
    while let Some(rel) = memchr::memchr(b'\n', &segment[search..]) {
        let lf = search + rel;
        // The line terminator ending at `lf` starts at a preceding CR when present.
        let term_start = if lf > 0 && segment[lf - 1] == b'\r' {
            lf - 1
        } else {
            lf
        };
        // A blank line requires a second terminator immediately after the first.
        let after = lf + 1;
        let second_len = if segment[after..].starts_with(b"\r\n") {
            Some(2)
        } else if segment[after..].starts_with(b"\n") {
            Some(1)
        } else {
            None
        };
        if let Some(second_len) = second_len {
            return Some((&segment[..term_start], &segment[after + second_len..]));
        }
        search = lf + 1;
    }
    None
}

fn trim_trailing_line_break(mut value: &[u8]) -> &[u8] {
    if value.ends_with(b"\r\n") {
        value = &value[..value.len() - 2];
    } else if value.ends_with(b"\n") {
        value = &value[..value.len() - 1];
    }
    value
}

fn schema_format(schema: &Value) -> Option<&str> {
    schema.get("format").and_then(Value::as_str)
}

fn xml_name<'a>(schema: &'a Value, default: Option<&'a str>) -> Option<&'a str> {
    schema
        .get("xml")
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or(default)
}

fn xml_namespace(schema: &Value) -> Option<&str> {
    schema
        .get("xml")
        .and_then(|value| value.get("namespace"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn xml_attribute(schema: &Value) -> bool {
    schema
        .get("xml")
        .and_then(|value| value.get("attribute"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn xml_wrapped(schema: &Value) -> bool {
    schema
        .get("xml")
        .and_then(|value| value.get("wrapped"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[derive(Debug, Default)]
struct ModeledXmlNames {
    /// Exact expanded names when the schema declares `xml.namespace`.
    exact_elements: HashSet<(String, String)>,
    /// Local names that match any namespace when the schema omits `xml.namespace`.
    any_namespace_elements: HashSet<String>,
    exact_attributes: HashSet<(String, String)>,
    /// Unqualified attribute locals when the schema omits `xml.namespace`.
    unqualified_attributes: HashSet<String>,
    /// JSON property keys and modeled XML locals claimed by modeled properties.
    /// A member that shares one of these names but does not match the property's
    /// modeled XML construct or namespace is rejected fail-closed rather than
    /// dropped or rematerialized as an additional member.
    reserved_json_keys: HashSet<String>,
}

impl ModeledXmlNames {
    fn reserve_json_key(&mut self, json_key: &str) {
        self.reserved_json_keys.insert(json_key.to_string());
    }

    fn reserves_json_key(&self, json_key: &str) -> bool {
        self.reserved_json_keys.contains(json_key)
    }

    fn insert_element(&mut self, namespace: Option<&str>, local: &str, json_key: &str) {
        // Reserve the modeled JSON key unconditionally. Attributes and elements
        // share the intermediate object's keyspace, so an additional member of the
        // opposite XML construct (an attribute where this property is modeled as an
        // element, or vice versa) could otherwise fill an unfilled modeled slot and
        // pass validation the backend would reject: a validator/backend
        // differential. Correct-construct members are consumed before the
        // reserved-key check, so this only rejects cross-construct collisions.
        //
        // Also reserve a differing xml.name local unconditionally (with or without
        // xml.namespace). Otherwise a namespace-less rename such as JSON key `role`
        // / xml.name `wireRole` would leave `wireRole` free for an opposite-
        // construct additional member under additionalProperties omitted/true/
        // permissive.
        self.reserve_json_key(json_key);
        if local != json_key {
            self.reserve_json_key(local);
        }
        match namespace {
            Some(namespace) => {
                self.exact_elements
                    .insert((namespace.to_string(), local.to_string()));
            }
            None => {
                self.any_namespace_elements.insert(local.to_string());
            }
        }
    }

    fn insert_attribute(&mut self, namespace: Option<&str>, local: &str, json_key: &str) {
        // Reserve the modeled JSON key and a differing xml.name local
        // unconditionally (see insert_element).
        self.reserve_json_key(json_key);
        if local != json_key {
            self.reserve_json_key(local);
        }
        match namespace {
            Some(namespace) => {
                self.exact_attributes
                    .insert((namespace.to_string(), local.to_string()));
            }
            None => {
                self.unqualified_attributes.insert(local.to_string());
            }
        }
    }

    fn contains_element(&self, node: roxmltree::Node<'_, '_>) -> bool {
        let local = node.tag_name().name();
        if self.any_namespace_elements.contains(local) {
            return true;
        }
        let Some(namespace) = node.tag_name().namespace() else {
            return false;
        };
        self.exact_elements
            .iter()
            .any(|(ns, name)| ns == namespace && name == local)
    }

    fn contains_attribute(&self, attr: roxmltree::Attribute<'_, '_>) -> bool {
        let local = attr.name();
        match attr.namespace() {
            Some(namespace) => self
                .exact_attributes
                .iter()
                .any(|(ns, name)| ns == namespace && name == local),
            None => self.unqualified_attributes.contains(local),
        }
    }
}

fn xml_expanded_name_matches(
    actual: roxmltree::ExpandedName<'_, '_>,
    expected_namespace: Option<&str>,
    expected_local: &str,
) -> bool {
    if actual.name() != expected_local {
        return false;
    }
    match expected_namespace {
        // Fail closed: a declared namespace URI must match exactly. Prefix text is
        // ignored; only the expanded name (URI + local) participates.
        Some(namespace) => actual.namespace() == Some(namespace),
        // When the schema omits `xml.namespace`, preserve local-name matching.
        None => true,
    }
}

fn xml_attribute_value<'a>(
    node: roxmltree::Node<'a, 'a>,
    namespace: Option<&str>,
    local: &str,
) -> Option<&'a str> {
    match namespace {
        Some(namespace) => node.attribute((namespace, local)),
        // Attributes do not inherit default namespaces; omit => unqualified only.
        None => node.attribute(local),
    }
}

fn child_elements_matching<'a>(
    node: roxmltree::Node<'a, 'a>,
    namespace: Option<&str>,
    local_name: &str,
) -> Vec<roxmltree::Node<'a, 'a>> {
    node.children()
        .filter(roxmltree::Node::is_element)
        .filter(|child| xml_expanded_name_matches(child.tag_name(), namespace, local_name))
        .collect()
}

/// Like [`child_elements_matching`], but when the schema declares a namespace URI
/// and a child shares the modeled local name under a different URI, return a
/// conversion error instead of silently dropping the child.
fn child_elements_matching_fail_closed<'a>(
    node: roxmltree::Node<'a, 'a>,
    namespace: Option<&str>,
    local_name: &str,
    role: &str,
) -> Result<Vec<roxmltree::Node<'a, 'a>>, String> {
    let mut matched = Vec::new();
    for child in node.children().filter(roxmltree::Node::is_element) {
        let local = child.tag_name().name();
        if local != local_name {
            // Unrelated locals stay non-colliding (ignored here; object-level
            // additional-member materialization may still observe them).
            continue;
        }
        if xml_expanded_name_matches(child.tag_name(), namespace, local_name) {
            matched.push(child);
            continue;
        }
        // Reachable only when `namespace` is Some and the URI differs (or is
        // absent): local-name-only schemas accept any URI via the match above.
        return Err(format!(
            "XML element uses a local name reserved for a namespace-qualified modeled {role} but does not match the required expanded name"
        ));
    }
    Ok(matched)
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str).or_else(|| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
}

/// Render a schema violation for metadata and the problem body.
///
/// `jsonschema`'s own `Display` embeds the offending instance value, and JSON
/// Pointer object-key segments in the instance path are derived from payload
/// member names. Neither may cross the client boundary or land in transaction
/// logs, on *either* side: a response detail would republish the upstream
/// representation this validator exists to withhold, and a request detail would
/// copy the caller's own credentials into every configured logging sink
/// (`GHSA-5p2h-fq6q-gwh9`). The `ValidationError` is therefore never rendered.
///
/// Both sides emit a fixed category plus an allowlisted keyword. Raw
/// `schema_path()` text — including `$defs` names, `$ref` fragments, and other
/// imported schema identifiers — is never copied into the diagnostic. The
/// request side additionally carries a bounded instance location whose object
/// member segments survive only when the configured schema declares them as
/// JSON properties; numeric pointer segments render as a fixed marker. The
/// response side stays coarser because describing an upstream body's shape back
/// to the client is itself a disclosure.
fn format_schema_error(
    error: &jsonschema::ValidationError<'_>,
    side: ValidationSide,
    safe_names: &SafeFieldNames,
) -> String {
    let keyword = safe_keyword(&error.schema_path().to_string());
    match side {
        ValidationSide::Request => {
            let location = safe_location(&error.instance_path().to_string(), safe_names);
            schema_violation_detail(
                "request body does not satisfy the request schema",
                &location,
                keyword,
            )
        }
        ValidationSide::Response => bound_detail(&format!(
            "response body does not satisfy the response schema (keyword '{keyword}')"
        )),
    }
}

/// Apply the operator's diagnostic cap, itself clamped to the compiled-in
/// [`MAX_DIAGNOSTIC_CHARS`] ceiling.
///
/// This is a resource bound only. Confidentiality comes from the construction
/// contract above, so raising `error_truncate_chars` can no longer widen a
/// disclosure — there is nothing sensitive left for it to reveal.
fn truncate_chars(value: &str, max_chars: usize) -> String {
    let max_chars = max_chars.min(MAX_DIAGNOSTIC_CHARS);
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect()
}

fn literal_segment_count(path_template: &str) -> u16 {
    path_template
        .split('/')
        .filter(|segment| !segment.is_empty())
        .filter(|segment| !(segment.starts_with('{') && segment.ends_with('}')))
        .count()
        .min(u16::MAX as usize) as u16
}

fn parse_mode(raw: &str) -> Result<EnforcementMode, String> {
    match raw {
        "block" => Ok(EnforcementMode::Block),
        "log_only" => Ok(EnforcementMode::LogOnly),
        "disabled" => Ok(EnforcementMode::Disabled),
        other => Err(format!(
            "openapi_validator: 'enforcement_mode' must be one of block, log_only, disabled; got {other:?}"
        )),
    }
}

fn parse_schema_draft(raw: &str) -> Result<SchemaDraft, String> {
    match raw {
        "auto" => Ok(SchemaDraft::Auto),
        "draft7" => Ok(SchemaDraft::Draft7),
        "draft2020-12" => Ok(SchemaDraft::Draft202012),
        other => Err(format!(
            "openapi_validator: 'schema_draft' must be auto, draft7, or draft2020-12; got {other:?}"
        )),
    }
}

fn parse_regex_set(value: Option<&Value>, field: &'static str) -> Result<Option<RegexSet>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let values = value
        .as_array()
        .ok_or_else(|| format!("openapi_validator: '{field}' must be an array"))?;
    if values.is_empty() {
        return Ok(None);
    }
    let mut patterns = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(pattern) = value.as_str() else {
            return Err(format!(
                "openapi_validator: '{field}' entries must be strings (invalid entry at index {index})"
            ));
        };
        if pattern.is_empty() {
            return Err(format!(
                "openapi_validator: '{field}' entries must not be empty (invalid entry at index {index})"
            ));
        }
        patterns.push(pattern.to_string());
    }
    RegexSet::new(patterns)
        .map(Some)
        .map_err(|error| format!("openapi_validator: failed to compile '{field}': {error}"))
}

fn parse_header_present(value: Option<&Value>) -> Result<HashMap<String, Option<String>>, String> {
    match value {
        None => Ok(HashMap::new()),
        Some(Value::Object(map)) => {
            let mut parsed = HashMap::new();
            for (key, value) in map {
                if key.is_empty() {
                    return Err(
                        "openapi_validator: bypass.header_present keys must not be empty"
                            .to_string(),
                    );
                }
                if http::header::HeaderName::from_bytes(key.as_bytes()).is_err() {
                    return Err(format!(
                        "openapi_validator: bypass.header_present contains invalid header name '{key}'"
                    ));
                }
                let expected = if value.is_null() {
                    None
                } else {
                    Some(value.as_str().ok_or_else(|| {
                        "openapi_validator: bypass.header_present values must be strings or null"
                            .to_string()
                    })?)
                };
                let normalized = key.to_ascii_lowercase();
                if parsed.contains_key(&normalized) {
                    return Err(format!(
                        "openapi_validator: bypass.header_present contains duplicate header name '{normalized}'"
                    ));
                }
                parsed.insert(normalized, expected.map(str::to_string));
            }
            Ok(parsed)
        }
        Some(_) => Err("openapi_validator: bypass.header_present must be an object".to_string()),
    }
}

fn optional_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<&'a str>, String> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value)),
        Some(Value::String(_)) => Err(format!("openapi_validator: '{key}' must not be empty")),
        Some(_) => Err(format!("openapi_validator: '{key}' must be a string")),
    }
}

fn optional_bool(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<bool>, String> {
    optional_bool_from_object(Some(object), key)
}

fn optional_bool_from_object(
    object: Option<&serde_json::Map<String, Value>>,
    key: &'static str,
) -> Result<Option<bool>, String> {
    let Some(object) = object else {
        return Ok(None);
    };
    match object.get(key) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(format!("openapi_validator: '{key}' must be a boolean")),
    }
}

fn optional_usize(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<usize>, String> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("openapi_validator: '{key}' must be an unsigned integer"))
            .and_then(|value| {
                usize::try_from(value)
                    .map_err(|_| format!("openapi_validator: '{key}' is too large"))
            })
            .map(Some),
        Some(_) => Err(format!(
            "openapi_validator: '{key}' must be an unsigned integer"
        )),
    }
}

fn optional_u16_from_object(
    object: Option<&serde_json::Map<String, Value>>,
    key: &'static str,
) -> Result<Option<u16>, String> {
    let Some(object) = object else {
        return Ok(None);
    };
    match object.get(key) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("openapi_validator: '{key}' must be an unsigned integer"))
            .and_then(|value| {
                u16::try_from(value).map_err(|_| format!("openapi_validator: '{key}' is too large"))
            })
            .map(Some),
        Some(_) => Err(format!(
            "openapi_validator: '{key}' must be an unsigned integer"
        )),
    }
}

fn optional_string_from_object(
    object: Option<&serde_json::Map<String, Value>>,
    key: &'static str,
) -> Result<Option<String>, String> {
    let Some(object) = object else {
        return Ok(None);
    };
    optional_string(object, key).map(|value| value.map(str::to_string))
}

fn optional_string_vec(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<Vec<String>>, String> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::Array(values)) => parse_string_array(values, key),
        Some(_) => Err(format!("openapi_validator: '{key}' must be an array")),
    }
}

fn optional_string_vec_from_object(
    object: Option<&serde_json::Map<String, Value>>,
    key: &'static str,
) -> Result<Option<Vec<String>>, String> {
    let Some(object) = object else {
        return Ok(None);
    };
    optional_string_vec(object, key)
}

fn parse_string_array(values: &[Value], key: &'static str) -> Result<Option<Vec<String>>, String> {
    let mut out = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(value) = value.as_str() else {
            return Err(format!(
                "openapi_validator: '{key}' entries must be strings (invalid entry at index {index})"
            ));
        };
        if value.is_empty() {
            return Err(format!(
                "openapi_validator: '{key}' entries must not be empty (invalid entry at index {index})"
            ));
        }
        out.push(value.to_string());
    }
    Ok(Some(out))
}

fn validate_status(status: u16, field: &'static str) -> Result<(), String> {
    if (400..=599).contains(&status) {
        Ok(())
    } else {
        Err(format!(
            "openapi_validator: '{field}' must be from 400 to 599"
        ))
    }
}
