//! Body Validation Plugin
//!
//! Validates JSON, XML, and gRPC protobuf request and response bodies against schemas.
//! For JSON, configured schemas are compiled once at plugin construction with the
//! `jsonschema` crate under an explicit draft and evaluated per request. For XML, the
//! body is parsed with `roxmltree` and must be a well-formed XML document; required
//! elements are matched on parsed (namespace-expanded) element names. For gRPC
//! protobuf, the payload is decoded against a compiled `FileDescriptorSet` and every
//! proto2 `required` field must be present, recursively.
//!
//! Request validation for JSON/XML runs in `before_proxy` (rejects with 400).
//! Request validation for protobuf runs in `on_final_request_body` (rejects with 400).
//! Response validation runs in `on_final_response_body` (rejects with 502)
//! and requires response body buffering when configured.
//!
//! Every configuration surface is fail-closed: unknown top-level keys, unknown keys
//! inside a `protobuf_method_messages` entry, malformed schemas, unsupported drafts
//! or vocabularies, non-local `$ref`s, and schemas outside the compile budgets all
//! make `BodyValidator::new` return an error, which keeps the last known-good
//! plugin generation in place (`PluginFailurePolicy::FailClosed`).
//!
//! # Diagnostic confidentiality
//!
//! Rejection details reach the client in the `details` field of the 400 / 502
//! body and are re-emitted to internal tracing verbatim, so they are built
//! under the contract in [`super::utils::validation_diagnostics`]: a
//! compiled-in category, a bounded instance location whose object-member
//! segments survive only when the configured schema declares them, and a
//! keyword drawn from the JSON Schema vocabulary. No rejected instance value,
//! expected constant, `roxmltree` parse token, or `prost` decode rendering is
//! formatted into them (`GHSA-5p2h-fq6q-gwh9`). Response-side details stay
//! coarser still, since describing an upstream body's shape back to the client
//! is itself a disclosure.

use async_trait::async_trait;
use flate2::read::GzDecoder;
use prost_reflect::{
    Cardinality, DescriptorPool, DynamicMessage, MessageDescriptor, ReflectMessage, Syntax,
    Value as ProtobufValue,
};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io::Read as _;
use tracing::{debug, warn};

use crate::util::json_dup_keys::{self, JsonScanMemo};

use super::utils::sse::{is_text_event_stream_media_type, original_response_is_event_stream};
use super::utils::validation_diagnostics::{
    SafeFieldNames, bound_detail, safe_keyword, safe_location, schema_violation_detail,
    xml_error_category,
};
use super::{Plugin, PluginResult, RequestContext};

/// Per-method message type descriptors for protobuf validation.
struct ProtobufMethodEntry {
    request: Option<MessageDescriptor>,
    response: Option<MessageDescriptor>,
}

#[derive(Default)]
struct ProtobufTargets {
    default_request: bool,
    default_response: bool,
    method_requests: HashSet<String>,
    method_responses: HashSet<String>,
}

impl ProtobufTargets {
    fn has_request(&self) -> bool {
        self.default_request || !self.method_requests.is_empty()
    }

    fn has_response(&self) -> bool {
        self.default_response || !self.method_responses.is_empty()
    }

    fn request_applies(&self, grpc_path: &str) -> bool {
        self.default_request || self.method_requests.contains(grpc_path)
    }

    fn response_applies(&self, grpc_path: &str) -> bool {
        self.default_response || self.method_responses.contains(grpc_path)
    }
}

#[derive(Default)]
struct ProtobufMethodShape {
    request: Option<String>,
    response: Option<String>,
}

#[derive(Default)]
struct ProtobufShape {
    descriptor_path: Option<String>,
    request_type: Option<String>,
    response_type: Option<String>,
    methods: HashMap<String, ProtobufMethodShape>,
    targets: ProtobufTargets,
}

struct ProtobufConfig {
    pool: Option<DescriptorPool>,
    request_descriptor: Option<MessageDescriptor>,
    response_descriptor: Option<MessageDescriptor>,
    method_messages: HashMap<String, ProtobufMethodEntry>,
    targets: ProtobufTargets,
    dependency_unavailable: bool,
}

struct ResolvedProtobufShape {
    request_descriptor: Option<MessageDescriptor>,
    response_descriptor: Option<MessageDescriptor>,
    method_messages: HashMap<String, ProtobufMethodEntry>,
}

#[derive(Clone, Copy)]
enum DescriptorLoadMode {
    Runtime,
    ShapeOnly,
}

/// Every configuration key `body_validator` accepts at the top level.
///
/// Construction rejects anything outside this set so an operator, generated
/// client, or control-plane typo can never silently drop an intended rule
/// (GHSA-w7x7-ppx9-5v74). Keep in sync with
/// `openapi.yaml#/components/schemas/BodyValidatorConfig`; parity is pinned by
/// `tests/unit/openapi_yaml_tests.rs`.
pub const BODY_VALIDATOR_CONFIG_KEYS: &[&str] = &[
    "json_schema",
    "json_schema_draft",
    "required_fields",
    "validate_xml",
    "required_xml_elements",
    "xml_max_entities",
    "xml_reject_nested_entities",
    "content_types",
    "response_json_schema",
    "response_required_fields",
    "response_validate_xml",
    "response_required_xml_elements",
    "response_content_types",
    "protobuf_descriptor_path",
    "protobuf_request_type",
    "protobuf_response_type",
    "protobuf_method_messages",
    "protobuf_reject_unknown_fields",
    "grpc_max_decompressed_size_bytes",
];

/// Every key a single `protobuf_method_messages` entry accepts.
pub const BODY_VALIDATOR_PROTOBUF_METHOD_KEYS: &[&str] = &["request", "response"];

/// Which side of the exchange a validation failure belongs to. Response-side
/// messages stay coarse so an upstream body's shape is not described back to
/// the client.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Request,
    Response,
}

struct CompiledJsonSchema {
    validator: jsonschema::Validator,
    canonicalize_object_order: bool,
    /// Member names this configured schema declares. Only these may appear in
    /// a rendered violation location; every other instance-path segment is
    /// payload-derived and is redacted (`GHSA-5p2h-fq6q-gwh9`).
    safe_names: SafeFieldNames,
}

pub struct BodyValidator {
    // ── Request validation config ──
    /// Compiled JSON Schema for request body validation (if configured).
    json_validator: Option<CompiledJsonSchema>,
    /// Required JSON fields (simple validation without full JSON Schema).
    required_fields: Vec<String>,
    /// Required XML elements in request bodies, parsed into expanded names.
    required_xml_elements: Vec<RequiredXmlElement>,
    /// Max `<!ENTITY` declarations allowed in an XML DOCTYPE before the body is
    /// rejected as a possible entity-expansion (billion-laughs) attack. Applies
    /// to both request and response XML when well-formedness validation runs.
    xml_max_entities: usize,
    /// Reject XML whose entity definitions reference other general entities —
    /// the billion-laughs expansion signature.
    xml_reject_nested_entities: bool,
    /// Content types to validate for requests (empty = validate all).
    content_types: Vec<String>,

    // ── Response validation config ──
    /// Compiled JSON Schema for response body validation (if configured).
    response_json_validator: Option<CompiledJsonSchema>,
    /// Required JSON fields in response bodies.
    response_required_fields: Vec<String>,
    /// Required XML elements in response bodies, parsed into expanded names.
    response_required_xml_elements: Vec<RequiredXmlElement>,
    /// Content types to validate for responses.
    response_content_types: Vec<String>,

    // ── Protobuf validation config ──
    /// Descriptor pool loaded from the compiled `FileDescriptorSet` binary.
    /// Retained so message descriptors remain valid (they borrow from the pool).
    _protobuf_pool: Option<DescriptorPool>,
    /// Default request message descriptor (for methods not in `protobuf_method_messages`).
    protobuf_request_descriptor: Option<MessageDescriptor>,
    /// Default response message descriptor.
    protobuf_response_descriptor: Option<MessageDescriptor>,
    /// Per-method message type overrides keyed by gRPC path (e.g., `/pkg.Svc/Method`).
    protobuf_method_messages: HashMap<String, ProtobufMethodEntry>,
    /// Configured request/response targets, retained even when the node-local
    /// descriptor dependency is temporarily unavailable.
    protobuf_targets: ProtobufTargets,
    /// Missing or unreadable descriptor files fail closed for applicable gRPC
    /// traffic instead of silently disabling configured validation.
    protobuf_dependency_unavailable: bool,
    /// Whether the loaded descriptor pool contains any proto2 file. Only proto2
    /// has `required` fields, so proto3-only pools skip the initialization walk
    /// entirely and keep the gRPC hot path allocation-free.
    protobuf_pool_has_proto2: bool,
    /// Whether to reject messages with unknown field numbers.
    protobuf_reject_unknown_fields: bool,
    /// Maximum decompressed gRPC payload size; 0 disables the decompressed cap.
    grpc_max_decompressed_size_bytes: usize,

    // ── Cached flags ──
    /// Whether any request validation is configured (cached for O(1) checks).
    has_request_validation: bool,
    /// Whether any response validation is configured (cached for O(1) check).
    has_response_validation: bool,
    /// Whether protobuf request validation is configured.
    has_protobuf_request_validation: bool,
    /// Whether protobuf response validation is configured.
    has_protobuf_response_validation: bool,
    /// Whether request validation must run in before_proxy (JSON/XML only).
    has_pre_proxy_request_validation: bool,
    /// Whether XML request validation is active (validate_xml OR required_xml_elements non-empty).
    has_xml_request_validation: bool,
    /// Whether XML response validation is active (response_validate_xml OR response_required_xml_elements non-empty).
    has_xml_response_validation: bool,
}

impl BodyValidator {
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::new_inner(config, DescriptorLoadMode::Runtime)
    }

    /// Validate configuration shape without opening node-local descriptor files.
    ///
    /// Mode-aware file dependency validation is performed separately by
    /// `GatewayConfig::validate_plugin_file_dependencies`.
    pub fn validate_config(config: &Value) -> Result<(), String> {
        Self::new_shape_only(config).map(|_| ())
    }

    /// Build an instance from configuration shape alone, without opening
    /// node-local descriptor files.
    ///
    /// The returned instance derives the same `has_request_validation` /
    /// `has_pre_proxy_request_validation` flags as the runtime instance: the
    /// protobuf request/response *targets* come from the parsed config shape,
    /// not from the descriptor file, and only the resolved descriptors differ.
    /// `Plugin::requires_request_body_buffering()` on this instance is
    /// therefore the authoritative runtime answer, which is what the
    /// backend-TLS SNI buffering screen
    /// (`plugins::RequestBodyBufferingScreener`) needs.
    pub fn new_shape_only(config: &Value) -> Result<Self, String> {
        Self::new_inner(config, DescriptorLoadMode::ShapeOnly)
    }

    fn new_inner(config: &Value, descriptor_mode: DescriptorLoadMode) -> Result<Self, String> {
        let Some(object) = config.as_object() else {
            return Err("body_validator: config must be an object".to_string());
        };

        // Fail closed on unknown keys before any default is applied so a typo
        // can never replace a working policy with a weaker one.
        if object
            .keys()
            .any(|key| !BODY_VALIDATOR_CONFIG_KEYS.contains(&key.as_str()))
        {
            return Err(format!(
                "body_validator: unknown configuration key; allowed keys: {}",
                BODY_VALIDATOR_CONFIG_KEYS.join(", ")
            ));
        }

        let schema_draft = parse_schema_draft(optional_string(config, "json_schema_draft")?)?;
        let json_validator = optional_compiled_schema(config, "json_schema", schema_draft)?;
        let required_fields = optional_string_vec(config, "required_fields")?.unwrap_or_default();
        let validate_xml = optional_bool(config, "validate_xml")?.unwrap_or(false);
        let required_xml_elements = parse_required_xml_elements(
            optional_string_vec(config, "required_xml_elements")?.unwrap_or_default(),
            "required_xml_elements",
        )?;
        let xml_max_entities = optional_usize(config, "xml_max_entities")?.unwrap_or(100);
        let xml_reject_nested_entities =
            optional_bool(config, "xml_reject_nested_entities")?.unwrap_or(true);
        let content_types =
            optional_content_types(config, "content_types")?.unwrap_or_else(default_content_types);

        // ── Response validation config ──
        let response_json_validator =
            optional_compiled_schema(config, "response_json_schema", schema_draft)?;
        let response_required_fields =
            optional_string_vec(config, "response_required_fields")?.unwrap_or_default();
        let response_validate_xml =
            optional_bool(config, "response_validate_xml")?.unwrap_or(false);
        let response_required_xml_elements = parse_required_xml_elements(
            optional_string_vec(config, "response_required_xml_elements")?.unwrap_or_default(),
            "response_required_xml_elements",
        )?;
        let response_content_types = optional_content_types(config, "response_content_types")?
            .unwrap_or_else(default_content_types);

        // ── Protobuf validation config ──
        let protobuf_config = load_protobuf_config(config, descriptor_mode)?;
        let ProtobufConfig {
            pool: protobuf_pool,
            request_descriptor: protobuf_request_descriptor,
            response_descriptor: protobuf_response_descriptor,
            method_messages: protobuf_method_messages,
            targets: protobuf_targets,
            dependency_unavailable: protobuf_dependency_unavailable,
        } = protobuf_config;
        let protobuf_pool_has_proto2 = protobuf_pool
            .as_ref()
            .is_some_and(|pool| pool.files().any(|file| file.syntax() == Syntax::Proto2));
        let protobuf_reject_unknown_fields =
            optional_bool(config, "protobuf_reject_unknown_fields")?.unwrap_or(false);
        let grpc_max_decompressed_size_bytes =
            optional_usize(config, "grpc_max_decompressed_size_bytes")?
                .unwrap_or_else(default_grpc_max_decompressed_size_bytes);

        let has_protobuf_request_validation = protobuf_targets.has_request();
        let has_protobuf_response_validation = protobuf_targets.has_response();

        let has_xml_request_validation = validate_xml || !required_xml_elements.is_empty();
        let has_xml_response_validation =
            response_validate_xml || !response_required_xml_elements.is_empty();

        let has_json_xml_request =
            json_validator.is_some() || !required_fields.is_empty() || has_xml_request_validation;
        let has_json_xml_response = response_json_validator.is_some()
            || !response_required_fields.is_empty()
            || has_xml_response_validation;

        let has_request_validation = has_json_xml_request || has_protobuf_request_validation;
        let has_response_validation = has_json_xml_response || has_protobuf_response_validation;

        if !has_request_validation && !has_response_validation {
            return Err(
                "body_validator: no validation rules configured — set 'json_schema', 'required_fields', 'validate_xml', 'required_xml_elements' (request), their 'response_*' equivalents, or 'protobuf_descriptor_path' with message types"
                    .to_string(),
            );
        }

        Ok(Self {
            json_validator,
            required_fields,
            required_xml_elements,
            xml_max_entities,
            xml_reject_nested_entities,
            content_types,
            response_json_validator,
            response_required_fields,
            response_required_xml_elements,
            response_content_types,
            _protobuf_pool: protobuf_pool,
            protobuf_request_descriptor,
            protobuf_response_descriptor,
            protobuf_method_messages,
            protobuf_targets,
            protobuf_dependency_unavailable,
            protobuf_pool_has_proto2,
            protobuf_reject_unknown_fields,
            grpc_max_decompressed_size_bytes,
            has_request_validation,
            has_response_validation,
            has_protobuf_request_validation,
            has_protobuf_response_validation,
            has_pre_proxy_request_validation: has_json_xml_request,
            has_xml_request_validation,
            has_xml_response_validation,
        })
    }

    /// Shared implementation of the final backend-visible request-body hooks.
    ///
    /// `json_scan_memo` is `Some` on the context-aware hook so the duplicate
    /// object-member screen of this exact body is shared with the other
    /// governed plugins running in the same stage, and `None` on the
    /// context-free hook, where the screen runs standalone.
    async fn validate_final_request_body(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
        json_scan_memo: Option<&mut JsonScanMemo>,
    ) -> PluginResult {
        if !self.has_request_validation {
            return PluginResult::Continue;
        }

        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");

        if body.is_empty() {
            return PluginResult::Continue;
        }

        if !is_grpc_content_type(content_type) {
            // Only run the JSON/XML branch when JSON or XML validation is
            // actually configured. A protobuf-only plugin must Continue on
            // non-grpc content types (the gRPC branch below is the one that
            // applies to it). `has_request_validation` alone isn't enough —
            // it's also true for protobuf-only configs, which would otherwise
            // mis-treat a non-gRPC payload as malformed JSON.
            let has_json_validation =
                self.json_validator.is_some() || !self.required_fields.is_empty();
            if !has_json_validation && !self.has_xml_request_validation {
                return PluginResult::Continue;
            }

            if !content_type_matches(&self.content_types, content_type) {
                return PluginResult::Continue;
            }

            let body_str = match std::str::from_utf8(body) {
                Ok(value) => value,
                Err(_) => {
                    debug!("body_validator: request body is not valid UTF-8, skipping validation");
                    return PluginResult::Continue;
                }
            };

            // JSON branch matches `before_proxy`: any matching JSON-like body is
            // screened once request validation is active for this content type,
            // even when only XML rules (plus `content_types: ["application/json"]`)
            // activated the plugin — otherwise a request-body transform can
            // reintroduce duplicate members after the first screen and the final
            // backend-visible bytes are never checked. `has_json_validation` is
            // consulted only by the early Continue above so protobuf-only configs
            // still never treat arbitrary non-gRPC payloads as JSON.
            let result = if is_json_like_content_type(content_type) {
                Self::validate_json_body(
                    body_str,
                    &self.required_fields,
                    self.json_validator.as_ref(),
                    Direction::Request,
                    json_scan_memo,
                )
            } else if is_xml_like_content_type(content_type) && self.has_xml_request_validation {
                Self::validate_xml_body(
                    body_str,
                    &self.required_xml_elements,
                    self.xml_max_entities,
                    self.xml_reject_nested_entities,
                )
            } else {
                Ok(())
            };

            return match result {
                Ok(()) => PluginResult::Continue,
                // Every producer above already builds a payload-free
                // diagnostic; `bound_detail` is the compiled-in size ceiling on
                // top of that, never the confidentiality mechanism
                // (`GHSA-5p2h-fq6q-gwh9`).
                Err(msg) => PluginResult::Reject {
                    status_code: 400,
                    body: serde_json::json!({
                        "error": "Request body validation failed",
                        "details": bound_detail(&msg)
                    })
                    .to_string(),
                    headers: HashMap::new(),
                },
            };
        }

        if !self.has_protobuf_request_validation {
            return PluginResult::Continue;
        }

        // Resolve gRPC method path from headers (injected by the proxy handler)
        let grpc_path = headers.get(":path").map(|s| s.as_str()).unwrap_or("");
        if self.protobuf_dependency_unavailable && self.protobuf_targets.request_applies(grpc_path)
        {
            return protobuf_reject(
                400,
                "request",
                "configured protobuf descriptor dependency is unavailable",
            );
        }
        let descriptor = match self.get_request_descriptor(grpc_path) {
            Some(d) => d,
            None => {
                // No descriptor for this method — skip validation
                debug!(
                    "body_validator: no protobuf request descriptor for method '{}'",
                    grpc_path
                );
                return PluginResult::Continue;
            }
        };

        match self.validate_protobuf_body(body, descriptor) {
            Ok(()) => PluginResult::Continue,
            Err(msg) => protobuf_reject(400, "request", &msg),
        }
    }

    fn validate_json_body(
        body: &str,
        required_fields: &[String],
        json_schema: Option<&CompiledJsonSchema>,
        direction: Direction,
        json_scan_memo: Option<&mut JsonScanMemo>,
    ) -> Result<(), String> {
        // Duplicate object member names make the evaluated document and the
        // forwarded bytes two different documents: `serde_json` keeps the LAST
        // value while a first-key-wins consumer acts on the first, so a body
        // that passes required-field and JSON Schema checks here can still
        // deliver a forbidden value downstream (advisory
        // `GHSA-c78j-5w9p-cpq6`). Screen before evaluating, and reject rather
        // than canonicalize — this plugin forwards the original bytes.
        let ambiguity = match json_scan_memo {
            Some(memo) => memo.ambiguity_str(body),
            None => json_dup_keys::str_ambiguity(body),
        };
        if let Some(reason) = ambiguity {
            return Err(reason.to_string());
        }

        // Parse as JSON. `serde_json`'s own 128-level nesting limit bounds the
        // instance depth the compiled validator then walks, so a deeply nested
        // hostile body cannot drive unbounded recursion here.
        // `serde_json`'s error rendering for a `Value` target is a syntax
        // category plus line/column — it never reproduces the offending token
        // (the value-bearing `invalid type: ...` / `invalid value: ...` forms
        // are raised only by typed `Deserialize` impls, which this call does
        // not use). Keep the target as `Value` if this ever changes
        // (`GHSA-5p2h-fq6q-gwh9`).
        let mut parsed: Value =
            serde_json::from_str(body).map_err(|e| format!("Invalid JSON: {}", e))?;

        // Check required fields
        if let Value::Object(map) = &parsed {
            for field in required_fields {
                if !map.contains_key(field) {
                    return Err(format!("Missing required field: {}", field));
                }
            }
        } else if !required_fields.is_empty() {
            return Err("Body must be a JSON object".to_string());
        }

        // Validate against the schema compiled at plugin construction. Nothing
        // is compiled per request, and the reported message never echoes the
        // rejected value.
        if let Some(schema) = json_schema {
            // jsonschema 0.46.5 compares object members in insertion order for
            // `uniqueItems` when serde_json's workspace-wide `preserve_order`
            // feature is active. JSON object equality is order-insensitive, so
            // canonicalize only for schemas that actually use `uniqueItems`.
            // The flag is computed once by the schema-position audit; all other
            // validators retain the existing request-path cost.
            if schema.canonicalize_object_order {
                parsed.sort_all_objects();
            }
            if let Err(error) = schema.validator.validate(&parsed) {
                return Err(schema_violation_message(&error, direction, &schema.safe_names));
            }
        }

        Ok(())
    }

    /// Validate that a body is a well-formed XML document and contains every
    /// configured required element.
    ///
    /// Well-formedness is decided by `roxmltree`, a maintained, namespace-aware,
    /// non-fetching XML parser, rather than by a tag-balancing scan
    /// (GHSA-mg9q-6h9j-9mmv). That means exactly one document element, XML `Name`
    /// syntax, attribute grammar/quoting/uniqueness, character validity, entity
    /// reference validity, and text placement are all enforced by the parser's
    /// documented contract. The exact original string is parsed without Unicode
    /// whitespace normalization. External entities are never retrieved.
    ///
    /// Two bounded pre-parse guards still run first because they encode policy the
    /// parser has no opinion on: the configured `<!ENTITY` declaration cap /
    /// nested-entity rejection, and outright rejection of external
    /// (`SYSTEM`/`PUBLIC`) identifiers on both the DOCTYPE and entity
    /// declarations. The parser is then given a node budget so a pathologically
    /// wide document cannot allocate without bound.
    fn validate_xml_body(
        body: &str,
        required_xml_elements: &[RequiredXmlElement],
        max_entities: usize,
        reject_nested: bool,
    ) -> Result<(), String> {
        if body.is_empty() {
            return Err("Empty XML body".to_string());
        }

        // Reject entity-expansion bombs and external identifiers at the edge
        // (Ferrum does not expand entities, but backends may).
        check_xml_entity_expansion(body, max_entities, reject_nested)?;

        let document = roxmltree::Document::parse_with_options(
            body,
            roxmltree::ParsingOptions {
                // DTDs are permitted only so the configured entity policy above
                // stays the authority on declaration count and nesting; the
                // parser still applies its own billion-laughs limits (expansion
                // depth 10, 255 references per reference) and never resolves an
                // external entity.
                allow_dtd: true,
                nodes_limit: XML_MAX_NODES,
            },
        )
        .map_err(|e| format!("Invalid XML: {}", xml_error_category(&e)))?;

        if required_xml_elements.is_empty() {
            return Ok(());
        }

        let mut required_found = vec![false; required_xml_elements.len()];
        for node in document.descendants().filter(roxmltree::Node::is_element) {
            let name = node.tag_name();
            for (idx, required) in required_xml_elements.iter().enumerate() {
                if !required_found[idx] && required.matches(name.namespace(), name.name()) {
                    required_found[idx] = true;
                }
            }
        }

        for (idx, element) in required_xml_elements.iter().enumerate() {
            if !required_found[idx] {
                return Err(format!("Missing required XML element: {}", element.display));
            }
        }

        Ok(())
    }

    /// Validate a gRPC protobuf body (request or response) against a message descriptor.
    ///
    /// The body uses gRPC length-prefixed framing: 1 byte compressed flag + 4 bytes
    /// big-endian u32 message length + protobuf payload bytes.
    fn validate_protobuf_body(
        &self,
        body: &[u8],
        descriptor: &MessageDescriptor,
    ) -> Result<(), String> {
        let payload = parse_grpc_frame(body, self.grpc_max_decompressed_size_bytes)?;
        // The `prost` decode error is not reproduced: its rendering is not part
        // of a stability contract Ferrum controls, so it is not a surface this
        // gateway can promise stays free of payload bytes
        // (`GHSA-5p2h-fq6q-gwh9`). The failure class alone is what a caller or
        // operator can act on.
        let msg = DynamicMessage::decode(descriptor.clone(), payload.as_ref())
            .map_err(|_| "Protobuf decode failed".to_string())?;
        // Wire decoding does not enforce proto2 initialization, so a correctly
        // framed message that omits a `required` field decodes cleanly
        // (GHSA-qvrp-m3v9-345m). Walk the descriptor and reject any missing
        // required field, including inside nested/repeated/map/extension values.
        // This is independent of the unknown-field policy below.
        if self.protobuf_pool_has_proto2 {
            let mut budget = ProtobufWalkBudget::default();
            check_proto2_required_fields(&msg, &mut budget)?;
        }
        if self.protobuf_reject_unknown_fields {
            let unknown_count = msg.unknown_fields().count();
            if unknown_count > 0 {
                return Err(format!(
                    "Message contains {} unknown field(s)",
                    unknown_count
                ));
            }
        }
        Ok(())
    }

    /// Look up the request message descriptor for a given gRPC path.
    fn get_request_descriptor(&self, grpc_path: &str) -> Option<&MessageDescriptor> {
        self.protobuf_method_messages
            .get(grpc_path)
            .and_then(|e| e.request.as_ref())
            .or(self.protobuf_request_descriptor.as_ref())
    }

    /// Look up the response message descriptor for a given gRPC path.
    fn get_response_descriptor(&self, grpc_path: &str) -> Option<&MessageDescriptor> {
        self.protobuf_method_messages
            .get(grpc_path)
            .and_then(|e| e.response.as_ref())
            .or(self.protobuf_response_descriptor.as_ref())
    }

    /// Whether JSON response validation rules are configured.
    fn has_json_response_validation(&self) -> bool {
        self.response_json_validator.is_some() || !self.response_required_fields.is_empty()
    }

    /// Resolve the gRPC method path used for response descriptor lookup.
    ///
    /// Prefer `grpc_full_method` set by `grpc_method_router` when available;
    /// otherwise fall back to `ctx.path`.
    fn grpc_method_path_for_response(ctx: &RequestContext) -> String {
        ctx.metadata
            .get("grpc_full_method")
            .map(|method| {
                if method.starts_with('/') {
                    method.clone()
                } else {
                    let mut path = String::with_capacity(method.len() + 1);
                    path.push('/');
                    path.push_str(method);
                    path
                }
            })
            .unwrap_or_else(|| ctx.path.clone())
    }

    /// Whether protobuf response validation applies to this request/response.
    fn applicable_protobuf_response_validation(&self, ctx: &RequestContext) -> bool {
        self.has_protobuf_response_validation
            && self
                .protobuf_targets
                .response_applies(&Self::grpc_method_path_for_response(ctx))
    }

    /// Whether the final response-body hook would inspect this media type.
    ///
    /// Used by the post-header buffering refinement so irrelevant downloads
    /// (and other non-matching types) can stream instead of being collected
    /// only to be skipped. A missing type stays buffered conservatively;
    /// malformed or ambiguous values cannot match a configured JSON/XML rule
    /// and are released. Genuine `text/event-stream` is released so
    /// `after_proxy` can fail closed before header commit.
    fn response_body_requires_buffering_for_media_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
    ) -> bool {
        if !self.has_response_validation {
            return false;
        }
        let Some(content_type) = content_type else {
            return true;
        };
        if is_text_event_stream_media_type(content_type) {
            return false;
        }
        if is_grpc_content_type(content_type) {
            return self.applicable_protobuf_response_validation(ctx);
        }
        if !content_type_matches(&self.response_content_types, content_type) {
            return false;
        }
        // Claim only representations the configured JSON/XML rules can
        // actually inspect. A JSON-only config must not pin XML (or other
        // allowlisted neighbors) onto the buffered path when the final hook
        // would no-op.
        if is_json_like_content_type(content_type) && self.has_json_response_validation() {
            return true;
        }
        is_xml_like_content_type(content_type) && self.has_xml_response_validation
    }
}

/// Parse the first gRPC length-prefixed frame and return the protobuf payload bytes.
///
/// Frame format: [1 byte compressed flag] [4 bytes big-endian u32 length] [payload]
///
/// Supports unary RPCs only (single frame per message). For streaming RPCs the body
/// may contain multiple concatenated frames — this function validates only the first
/// frame and rejects trailing data via the length mismatch check.
///
/// When the compressed flag is set (byte 0 == 1), the payload is decompressed using
/// gzip (deflate), which is the standard gRPC compression algorithm. Other compression
/// algorithms (e.g., zstd, snappy) are not supported and will return an error.
/// Default maximum decompressed size for a gRPC frame (10 MB). Prevents compression-bomb
/// DoS — without a cap, a tiny compressed payload can inflate into gigabytes and OOM
/// the process.
const DEFAULT_MAX_GRPC_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;

fn parse_grpc_frame(
    body: &[u8],
    max_decompressed_size_bytes: usize,
) -> Result<Cow<'_, [u8]>, String> {
    if body.len() < 5 {
        return Err(format!(
            "gRPC frame too short: {} bytes (minimum 5)",
            body.len()
        ));
    }
    let compressed = body[0];
    let msg_len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    let payload = &body[5..];
    if payload.len() != msg_len {
        return Err(format!(
            "gRPC frame length mismatch: header says {} bytes but payload is {} bytes",
            msg_len,
            payload.len()
        ));
    }
    if compressed != 0 {
        // gRPC compression uses gzip (deflate) by default per the gRPC spec.
        // Bounded read to prevent compression-bomb DoS.
        let mut decoder = GzDecoder::new(payload);
        let initial_capacity = if max_decompressed_size_bytes > 0 {
            payload.len().min(max_decompressed_size_bytes)
        } else {
            payload.len()
        };
        let mut decompressed = Vec::with_capacity(initial_capacity);
        let mut buf = [0u8; 8192];
        loop {
            let n = decoder
                .read(&mut buf)
                .map_err(|e| format!("Failed to decompress gRPC frame (gzip): {e}"))?;
            if n == 0 {
                break;
            }
            if max_decompressed_size_bytes > 0
                && decompressed.len().saturating_add(n) > max_decompressed_size_bytes
            {
                return Err(format!(
                    "gRPC decompressed body exceeds max size of {max_decompressed_size_bytes} bytes"
                ));
            }
            decompressed.extend_from_slice(&buf[..n]);
        }
        Ok(Cow::Owned(decompressed))
    } else {
        Ok(Cow::Borrowed(payload))
    }
}

fn default_grpc_max_decompressed_size_bytes() -> usize {
    crate::config::conf_file::resolve_ferrum_var("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES")
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_GRPC_DECOMPRESSED_SIZE)
}

/// Supported JSON Schema dialects. There is no "whatever the library guesses"
/// mode: a configured schema is always compiled under one explicit draft so an
/// operator cannot end up with silently different keyword semantics.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SchemaDraft {
    Draft7,
    Draft202012,
}

impl SchemaDraft {
    fn config_value(self) -> &'static str {
        match self {
            Self::Draft7 => "draft7",
            Self::Draft202012 => "draft2020-12",
        }
    }

    /// `$schema` URIs that name this draft.
    fn schema_uris(self) -> &'static [&'static str] {
        match self {
            Self::Draft7 => &[
                "http://json-schema.org/draft-07/schema#",
                "https://json-schema.org/draft-07/schema#",
                "http://json-schema.org/draft-07/schema",
                "https://json-schema.org/draft-07/schema",
            ],
            Self::Draft202012 => &[
                "https://json-schema.org/draft/2020-12/schema",
                "http://json-schema.org/draft/2020-12/schema",
                "https://json-schema.org/draft/2020-12/schema#",
                "http://json-schema.org/draft/2020-12/schema#",
            ],
        }
    }
}

/// Maximum nesting depth of a configured JSON Schema document.
const MAX_SCHEMA_DEPTH: usize = 32;

/// Maximum number of JSON nodes inspected while auditing a configured schema.
const MAX_SCHEMA_NODES: usize = 20_000;

/// Node budget handed to the XML parser so a pathologically wide document
/// cannot allocate a tree without bound.
const XML_MAX_NODES: u32 = 100_000;

fn parse_schema_draft(raw: Option<&str>) -> Result<SchemaDraft, String> {
    match raw {
        None => Ok(SchemaDraft::Draft202012),
        Some("draft2020-12") => Ok(SchemaDraft::Draft202012),
        Some("draft7") => Ok(SchemaDraft::Draft7),
        Some(_) => Err(
            "body_validator: 'json_schema_draft' must be 'draft2020-12' or 'draft7'".to_string(),
        ),
    }
}

/// Read, audit, and compile an optional JSON Schema configuration field.
///
/// Compilation happens once, here, at plugin construction — never on the
/// request path (GHSA-5883-wg84-7rhm). Anything the audit or the compiler
/// rejects fails construction, which preserves the last known-good plugin
/// generation instead of admitting a policy whose decisive constraints would
/// silently never run.
fn optional_compiled_schema(
    config: &Value,
    field: &'static str,
    draft: SchemaDraft,
) -> Result<Option<CompiledJsonSchema>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(object) = value.as_object() else {
        return Err(format!(
            "body_validator: '{field}' must be a JSON Schema object"
        ));
    };
    if object.is_empty() {
        return Err(format!("body_validator: '{field}' must not be empty"));
    }

    let audit = audit_schema(value, field, draft)?;

    let options = match draft {
        SchemaDraft::Draft7 => jsonschema::draft7::options(),
        SchemaDraft::Draft202012 => jsonschema::draft202012::options(),
    };
    options
        // `format` stays an asserted constraint in both drafts so the documented
        // format vocabulary keeps rejecting bad values. Unknown format names
        // remain advisory per the specification.
        .should_validate_formats(true)
        .build(value)
        .map_err(|_| {
            format!(
                "body_validator: '{field}' is not a valid {} JSON Schema",
                draft.config_value()
            )
        })
        // A configured, non-empty, audited schema always yields a live
        // validator here; `Ok(None)` above is reserved for "the operator did
        // not configure this field at all", so an unconfigured surface stays
        // unvalidated while a configured one can never degrade to `None`.
        .map(|validator| {
            Some(CompiledJsonSchema {
                validator,
                canonicalize_object_order: audit.has_unique_items,
                safe_names: SafeFieldNames::from_schema(value),
            })
        })
}

#[derive(Default)]
struct SchemaAudit {
    has_unique_items: bool,
}

/// Bounded structural and semantic audit of a configured JSON Schema.
///
/// The compiler already rejects malformed keyword shapes, invalid type names,
/// and bad regexes. The structural pass charges every JSON value, including
/// literal instance data and annotations. The semantic pass applies keyword
/// policy only at actual schema positions and follows the subschema-bearing
/// keywords supported by Draft 7 and Draft 2020-12, plus any schema target
/// reached through a supported local URI-fragment JSON Pointer.
///
/// Together the passes add the policy the library cannot express:
///
/// * every `$ref` / `$dynamicRef` must be a local fragment (`#...`), so no
///   schema can cause a network or filesystem retrieval. The `jsonschema`
///   dependency is built with `default-features = false`, which also removes
///   the HTTP and file retrievers entirely — this is the explicit, message-
///   bearing half of that defence.
/// * `$id` / `id` must be fragment-only, so a base URI cannot re-point an
///   otherwise local `$ref` at an external resource.
/// * `$vocabulary` is refused outright: Ferrum cannot honour a custom
///   vocabulary, and silently ignoring one is exactly the failure mode this
///   advisory is about.
/// * `$schema`, when present, must name the configured draft.
/// * depth and node count stay inside fixed budgets across the complete value.
fn audit_schema(
    schema: &Value,
    field: &'static str,
    draft: SchemaDraft,
) -> Result<SchemaAudit, String> {
    let mut nodes = 0usize;
    audit_schema_structure(schema, field, 0, &mut nodes)?;

    let mut audit = SchemaAudit::default();
    let mut visited = HashSet::new();
    audit_schema_node(schema, schema, field, draft, &mut audit, &mut visited)?;
    Ok(audit)
}

fn audit_schema_structure(
    node: &Value,
    field: &'static str,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "body_validator: '{field}' nests deeper than the {MAX_SCHEMA_DEPTH}-level schema budget"
        ));
    }
    *nodes += 1;
    if *nodes > MAX_SCHEMA_NODES {
        return Err(format!(
            "body_validator: '{field}' exceeds the {MAX_SCHEMA_NODES}-node schema budget"
        ));
    }

    match node {
        Value::Array(items) => {
            for item in items {
                audit_schema_structure(item, field, depth + 1, nodes)?;
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                audit_schema_structure(value, field, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn audit_schema_node(
    node: &Value,
    document: &Value,
    field: &'static str,
    draft: SchemaDraft,
    audit: &mut SchemaAudit,
    visited: &mut HashSet<usize>,
) -> Result<(), String> {
    // A JSON value cannot contain an in-memory cycle, but local references can
    // revisit the same target indefinitely. Identity-based deduplication makes
    // the semantic walk no larger than the already-budgeted supplied value.
    let identity = std::ptr::from_ref(node) as usize;
    if !visited.insert(identity) {
        return Ok(());
    }

    // Both supported drafts allow boolean schemas. Scalars and arrays reached
    // through malformed keyword shapes are left to the compiler to reject.
    let Value::Object(map) = node else {
        return Ok(());
    };

    let reference_keywords: &[&str] = match draft {
        SchemaDraft::Draft7 => &["$ref"],
        SchemaDraft::Draft202012 => &["$ref", "$dynamicRef"],
    };
    for &key in reference_keywords {
        if let Some(value) = map.get(key) {
            let Some(reference) = value.as_str() else {
                return Err(format!(
                    "body_validator: '{field}' has a non-string '{key}'"
                ));
            };
            if !reference.starts_with('#') {
                return Err(format!(
                    "body_validator: '{field}' has a non-local '{key}'; \
                     only local references (starting with '#') \
                     are supported and no external reference is ever retrieved"
                ));
            }
            if let Some(target) = local_json_pointer_target(document, reference, field, key)? {
                audit_schema_node(target, document, field, draft, audit, visited)?;
            }
        }
    }

    for key in ["$id", "id"] {
        if let Some(value) = map.get(key) {
            let Some(id) = value.as_str() else {
                return Err(format!(
                    "body_validator: '{field}' has a non-string '{key}'"
                ));
            };
            if !id.starts_with('#') {
                return Err(format!(
                    "body_validator: '{field}' has a non-fragment '{key}'; \
                     a base URI would allow external reference resolution"
                ));
            }
        }
    }

    if map.contains_key("$vocabulary") {
        return Err(format!(
            "body_validator: '{field}' declares '$vocabulary'; custom \
             vocabularies are not supported and would not be enforced"
        ));
    }

    if let Some(value) = map.get("$schema") {
        let Some(uri) = value.as_str() else {
            return Err(format!(
                "body_validator: '{field}' has a non-string '$schema'"
            ));
        };
        if !draft.schema_uris().contains(&uri) {
            return Err(format!(
                "body_validator: '{field}' declares an unsupported '$schema'; \
                 configured draft is '{}'",
                draft.config_value()
            ));
        }
    }

    if map.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
        audit.has_unique_items = true;
    }

    // These object-valued keywords contain schemas as their map values. The
    // member names are instance-property/definition names, never keywords.
    for keyword in ["properties", "patternProperties"] {
        if let Some(subschemas) = map.get(keyword).and_then(Value::as_object) {
            for subschema in subschemas.values() {
                audit_schema_node(subschema, document, field, draft, audit, visited)?;
            }
        }
    }

    // Match referencing 0.46.5's configured-draft child maps. Draft 7 walks
    // `definitions` only. Draft 2020-12 walks `$defs` and keeps its legacy
    // `definitions` compatibility. A Draft 7 `$defs` value remains literal
    // unless a local JSON Pointer explicitly reaches it above.
    let definition_keywords: &[&str] = match draft {
        SchemaDraft::Draft7 => &["definitions"],
        SchemaDraft::Draft202012 => &["$defs", "definitions"],
    };
    for &keyword in definition_keywords {
        if let Some(subschemas) = map.get(keyword).and_then(Value::as_object) {
            for subschema in subschemas.values() {
                audit_schema_node(subschema, document, field, draft, audit, visited)?;
            }
        }
    }

    match draft {
        SchemaDraft::Draft7 => {
            // A Draft 7 dependency value is either a schema or an array of
            // property names. Arrays are literal names and are not traversed.
            if let Some(dependencies) = map.get("dependencies").and_then(Value::as_object) {
                for dependency in dependencies.values() {
                    if dependency.is_object() || dependency.is_boolean() {
                        audit_schema_node(dependency, document, field, draft, audit, visited)?;
                    }
                }
            }
        }
        SchemaDraft::Draft202012 => {
            if let Some(subschemas) = map.get("dependentSchemas").and_then(Value::as_object) {
                for subschema in subschemas.values() {
                    audit_schema_node(subschema, document, field, draft, audit, visited)?;
                }
            }
        }
    }

    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(subschemas) = map.get(keyword).and_then(Value::as_array) {
            for subschema in subschemas {
                audit_schema_node(subschema, document, field, draft, audit, visited)?;
            }
        }
    }

    match draft {
        SchemaDraft::Draft7 => {
            if let Some(items) = map.get("items").and_then(Value::as_array) {
                for subschema in items {
                    audit_schema_node(subschema, document, field, draft, audit, visited)?;
                }
            }
        }
        SchemaDraft::Draft202012 => {
            if let Some(subschemas) = map.get("prefixItems").and_then(Value::as_array) {
                for subschema in subschemas {
                    audit_schema_node(subschema, document, field, draft, audit, visited)?;
                }
            }
        }
    }

    for keyword in [
        "additionalProperties",
        "contains",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
    ] {
        if let Some(subschema) = map.get(keyword) {
            audit_schema_node(subschema, document, field, draft, audit, visited)?;
        }
    }

    match draft {
        SchemaDraft::Draft7 => {
            for keyword in ["items", "additionalItems"] {
                if let Some(subschema) = map.get(keyword)
                    && !subschema.is_array()
                {
                    audit_schema_node(subschema, document, field, draft, audit, visited)?;
                }
            }
        }
        SchemaDraft::Draft202012 => {
            for keyword in [
                "items",
                "unevaluatedProperties",
                "unevaluatedItems",
                "contentSchema",
            ] {
                if let Some(subschema) = map.get(keyword) {
                    audit_schema_node(subschema, document, field, draft, audit, visited)?;
                }
            }
        }
    }

    Ok(())
}

/// Resolve a supported local URI-fragment JSON Pointer exactly as
/// `referencing` 0.46.5 does for a single schema document.
///
/// The fragment kind is selected before percent-decoding: `#` is the root,
/// `#/...` is a pointer, and any other `#name` is an anchor. Pointer text after
/// the leading slash is percent-decoded as one UTF-8 string, then object keys
/// apply JSON Pointer `~1` / `~0` unescaping. Array segments use `usize::parse`
/// directly, matching the library's accepted index spellings and failures.
fn local_json_pointer_target<'a>(
    document: &'a Value,
    reference: &str,
    field: &'static str,
    keyword: &str,
) -> Result<Option<&'a Value>, String> {
    let fragment = reference
        .strip_prefix('#')
        .ok_or_else(|| format!("body_validator: '{field}' has a non-local '{keyword}'"))?;
    if fragment.is_empty() || !fragment.starts_with('/') {
        // The root was already visited. Anchor resources are indexed only while
        // the library walks actual draft-specific schema positions, which this
        // audit also visits, so there is no hidden anchor target to discover.
        return Ok(None);
    }

    let decoded = percent_encoding::percent_decode_str(&fragment[1..])
        .decode_utf8()
        .map_err(|_| {
            format!(
                "body_validator: '{field}' has invalid UTF-8 percent encoding \
                 in a local '{keyword}' JSON Pointer"
            )
        })?;
    let mut target = document;
    for raw_segment in decoded.split('/') {
        target = match target {
            Value::Array(items) => {
                let index = raw_segment.parse::<usize>().map_err(|_| {
                    format!(
                        "body_validator: '{field}' has invalid array index in \
                         a local '{keyword}' JSON Pointer"
                    )
                })?;
                items.get(index).ok_or_else(|| {
                    format!(
                        "body_validator: '{field}' has a local '{keyword}' JSON \
                         Pointer that resolves nowhere"
                    )
                })?
            }
            Value::Object(map) => {
                let segment = unescape_json_pointer_segment(raw_segment);
                map.get(segment.as_ref()).ok_or_else(|| {
                    format!(
                        "body_validator: '{field}' has a local '{keyword}' JSON \
                         Pointer that resolves nowhere"
                    )
                })?
            }
            _ => {
                return Err(format!(
                    "body_validator: '{field}' has a local '{keyword}' JSON \
                     Pointer that resolves nowhere"
                ));
            }
        };
    }
    Ok(Some(target))
}

fn unescape_json_pointer_segment(segment: &str) -> Cow<'_, str> {
    if !segment.contains('~') {
        return Cow::Borrowed(segment);
    }

    let mut output = String::with_capacity(segment.len());
    let mut chars = segment.chars();
    while let Some(ch) = chars.next() {
        if ch != '~' {
            output.push(ch);
            continue;
        }
        match chars.next() {
            Some('0') => output.push('~'),
            Some('1') => output.push('/'),
            Some(next) => {
                output.push('~');
                output.push(next);
            }
            None => output.push('~'),
        }
    }
    Cow::Owned(output)
}

/// Client-visible message for a compiled-schema violation.
///
/// The rejected instance value is never included, in either direction. Request
/// failures carry a bounded instance location plus the failing keyword so a
/// caller can fix its own payload; response failures stay coarse so an upstream
/// body's shape is not described back to the client.
///
/// The location is rendered by [`safe_location`]: array indices survive, and
/// object member names survive only when the *configured schema* declares them.
/// A hostile member name — which `jsonschema` places in the instance path for
/// `propertyNames`, `patternProperties`, `additionalProperties`, and nested
/// `required` failures — is replaced with a placeholder rather than echoed,
/// and depth, segment count, and total length are all capped
/// (`GHSA-5p2h-fq6q-gwh9`).
fn schema_violation_message(
    error: &jsonschema::ValidationError<'_>,
    direction: Direction,
    safe_names: &SafeFieldNames,
) -> String {
    let schema_path = error.schema_path().to_string();
    let keyword = safe_keyword(&schema_path);
    match direction {
        Direction::Request => {
            let location = safe_location(&error.instance_path().to_string(), safe_names);
            schema_violation_detail("JSON Schema validation failed", &location, keyword)
        }
        Direction::Response => bound_detail(&format!(
            "Response body does not satisfy the configured JSON Schema (keyword '{keyword}')"
        )),
    }
}

/// A configured required XML element name, matched against parsed element
/// names rather than raw source bytes.
///
/// Entries are either a bare local name (`item`), which matches that local name
/// in any namespace, or Clark notation (`{http://example.com/ns}item`), which
/// requires both the expanded namespace URI and the local name to match. A
/// literal `{}local` requires the element to be in no namespace.
struct RequiredXmlElement {
    display: String,
    namespace: Option<String>,
    local: String,
}

impl RequiredXmlElement {
    fn matches(&self, namespace: Option<&str>, local: &str) -> bool {
        if self.local != local {
            return false;
        }
        match self.namespace.as_deref() {
            None => true,
            Some("") => namespace.is_none(),
            Some(expected) => namespace == Some(expected),
        }
    }
}

fn parse_required_xml_elements(
    raw: Vec<String>,
    field: &'static str,
) -> Result<Vec<RequiredXmlElement>, String> {
    let mut parsed = Vec::with_capacity(raw.len());
    for (index, entry) in raw.into_iter().enumerate() {
        let (namespace, local) = match entry.strip_prefix('{') {
            Some(rest) => match rest.split_once('}') {
                Some((namespace, local)) => (Some(namespace.to_string()), local.to_string()),
                None => {
                    return Err(format!(
                        "body_validator: '{field}' entry at index {index} opens Clark notation \
                         with '{{' but never closes it with '}}'"
                    ));
                }
            },
            None => (None, entry.clone()),
        };
        if local.is_empty() {
            return Err(format!(
                "body_validator: '{field}' entry at index {index} has an empty local element name"
            ));
        }
        if local.contains('{') || local.contains('}') {
            return Err(format!(
                "body_validator: '{field}' entry at index {index} has an invalid local element name"
            ));
        }
        parsed.push(RequiredXmlElement {
            display: entry,
            namespace,
            local,
        });
    }
    Ok(parsed)
}

/// Bounded budget for the recursive proto2 initialization walk.
#[derive(Default)]
struct ProtobufWalkBudget {
    messages: usize,
}

/// Maximum message-nesting depth inspected while checking proto2 initialization.
const MAX_PROTOBUF_MESSAGE_DEPTH: usize = 32;

/// Maximum number of messages inspected while checking proto2 initialization.
const MAX_PROTOBUF_MESSAGES: usize = 50_000;

impl ProtobufWalkBudget {
    fn charge(&mut self) -> Result<(), String> {
        self.messages += 1;
        if self.messages > MAX_PROTOBUF_MESSAGES {
            return Err(
                "Protobuf message exceeds the initialization inspection budget".to_string(),
            );
        }
        Ok(())
    }
}

/// Recursively verify that every proto2 `required` field is present.
///
/// Presence, not value, is what is checked: a required scalar carrying its
/// type's default value is present because proto2 tracks it with a hasbit, and
/// prost-reflect's `has_field` reflects exactly that. proto3 descriptors have
/// no `Required` cardinality, so proto3 messages are unaffected. Extensions,
/// oneof members, repeated values, and map values are all walked. The error
/// names the offending field path (descriptor metadata, configured by the
/// operator) and never any payload value.
fn check_proto2_required_fields(
    message: &DynamicMessage,
    budget: &mut ProtobufWalkBudget,
) -> Result<(), String> {
    check_proto2_required_fields_at(message, budget, 0, &mut String::new())
}

fn check_proto2_required_fields_at(
    message: &DynamicMessage,
    budget: &mut ProtobufWalkBudget,
    depth: usize,
    path: &mut String,
) -> Result<(), String> {
    if depth > MAX_PROTOBUF_MESSAGE_DEPTH {
        return Err(
            "Protobuf message nests deeper than the initialization inspection budget".to_string(),
        );
    }
    budget.charge()?;

    let descriptor = message.descriptor();
    for field in descriptor.fields() {
        if field.cardinality() == Cardinality::Required && !message.has_field(&field) {
            let name = field.name();
            return Err(format!("Missing required protobuf field: {path}{name}"));
        }
    }

    // Only present values can be walked; an absent singular message field is
    // legal unless it is itself `required`, which the loop above already
    // rejected.
    for (field, value) in message.fields() {
        let restore = path.len();
        path.push_str(field.name());
        path.push('.');
        check_proto2_required_in_value(value, budget, depth + 1, path)?;
        path.truncate(restore);
    }
    // Only present extensions are iterable, and proto2 forbids `required`
    // extension fields, so there is no presence check to make here — but an
    // extension's message value can still carry required fields of its own.
    for (extension, value) in message.extensions() {
        let restore = path.len();
        path.push('[');
        path.push_str(extension.full_name());
        path.push_str("].");
        check_proto2_required_in_value(value, budget, depth + 1, path)?;
        path.truncate(restore);
    }
    Ok(())
}

fn check_proto2_required_in_value(
    value: &ProtobufValue,
    budget: &mut ProtobufWalkBudget,
    depth: usize,
    path: &mut String,
) -> Result<(), String> {
    match value {
        ProtobufValue::Message(nested) => {
            check_proto2_required_fields_at(nested, budget, depth, path)
        }
        ProtobufValue::List(items) => {
            for item in items {
                check_proto2_required_in_value(item, budget, depth, path)?;
            }
            Ok(())
        }
        ProtobufValue::Map(entries) => {
            for entry in entries.values() {
                check_proto2_required_in_value(entry, budget, depth, path)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("body_validator: '{field}' must be a boolean"))
}

fn optional_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "body_validator: '{field}' must be an unsigned integer"
        ));
    };
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("body_validator: '{field}' is too large for this platform"))
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        return Err(format!("body_validator: '{field}' must be a string"));
    };
    if value.is_empty() {
        return Err(format!("body_validator: '{field}' must not be empty"));
    }
    Ok(Some(value))
}

fn optional_object<'a>(
    config: &'a Value,
    field: &'static str,
) -> Result<Option<&'a serde_json::Map<String, Value>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_object()
        .map(Some)
        .ok_or_else(|| format!("body_validator: '{field}' must be an object"))
}

fn optional_string_vec(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("body_validator: '{field}' must be an array"));
    };

    let mut parsed = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(value) = value.as_str() else {
            return Err(format!(
                "body_validator: '{field}' entries must be strings (invalid entry at index {index})"
            ));
        };
        if value.is_empty() {
            return Err(format!(
                "body_validator: '{field}' entries must not be empty (invalid entry at index {index})"
            ));
        }
        parsed.push(value.to_string());
    }
    Ok(Some(parsed))
}

fn optional_content_types(
    config: &Value,
    field: &'static str,
) -> Result<Option<Vec<String>>, String> {
    let Some(values) = optional_string_vec(config, field)? else {
        return Ok(None);
    };
    let mut parsed = Vec::with_capacity(values.len());
    for (index, value) in values.into_iter().enumerate() {
        // Normalize configured media types the same way actual headers are
        // compared: type/subtype only, parameters stripped, ASCII-lowercased.
        let normalized = media_type_essence(&value)
            .ok_or_else(|| {
                format!(
                    "body_validator: '{field}' entries must be valid media types \
                     (type/subtype), not empty, parameter-only, or malformed \
                     (invalid entry at index {index})"
                )
            })?
            .to_ascii_lowercase();
        parsed.push(normalized);
    }
    Ok(Some(parsed))
}

fn default_content_types() -> Vec<String> {
    vec![
        "application/json".to_string(),
        "application/xml".to_string(),
        "text/xml".to_string(),
    ]
}

/// Media-type essence (`type`/`subtype`) from a `Content-Type` value: the token
/// before the first `;`, with surrounding OWS trimmed. Both components must be
/// non-empty RFC token values and exactly one slash must separate them.
fn media_type_essence(content_type: &str) -> Option<&str> {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim_matches(|ch| ch == ' ' || ch == '\t');
    let (type_name, subtype) = essence.split_once('/')?;
    if type_name.is_empty()
        || subtype.is_empty()
        || subtype.contains('/')
        || !type_name.bytes().all(is_media_type_token_byte)
        || !subtype.bytes().all(is_media_type_token_byte)
    {
        return None;
    }
    Some(essence)
}

fn is_media_type_token_byte(byte: u8) -> bool {
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
            | b'|'
            | b'~'
    )
}

/// Exact type/subtype match against configured media types.
///
/// Compares the normalized essence of `content_type` (parameters stripped,
/// OWS trimmed, ASCII case-insensitive) to each configured entry. Distinct
/// neighbors such as `application/json-seq` and parameter values that merely
/// contain a configured string do not match. An empty configured list means
/// "match all valid media types" (legacy). A malformed actual value never
/// matches, including when the configured list is empty.
fn content_type_matches(configured: &[String], content_type: &str) -> bool {
    let Some(actual) = media_type_essence(content_type) else {
        return false;
    };
    if configured.is_empty() {
        return true;
    }
    configured
        .iter()
        .any(|expected| actual.eq_ignore_ascii_case(expected))
}

fn is_grpc_content_type(content_type: &str) -> bool {
    // gRPC media types use application/grpc or a registered representation
    // suffix such as application/grpc+proto. Parameters never participate.
    let Some(media_type) = media_type_essence(content_type) else {
        return false;
    };
    media_type.eq_ignore_ascii_case("application/grpc")
        || ascii_starts_with_ignore_case(media_type, "application/grpc+")
}

/// Enforce bounded internal-entity policy and reject every external identifier.
///
/// Ferrum does not retrieve external resources or expand entities for business
/// logic, but downstream parsers may. `max_entities` caps `<!ENTITY`
/// declarations; when `reject_nested` is set, entity-expansion chains and
/// parameter entities that generate declarations are rejected outright.
fn check_xml_entity_expansion(
    body: &str,
    max_entities: usize,
    reject_nested: bool,
) -> Result<(), String> {
    let bytes = body.as_bytes();
    let needle = b"<!ENTITY";
    let mut count = 0usize;
    // Store the precomputed entity-declaration count per parameter entity, not
    // the raw value: a `%name;` reference may appear many times (bounded only by
    // body length), and recomputing `entity_declaration_count(value)` on each
    // reference is O(refs x |value|) — quadratic in body size, a DoS in the very
    // guard meant to prevent one. Compute the count once at declaration time so
    // each reference is O(1).
    let mut parameter_entities: Vec<(String, usize)> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some((name, end)) = parameter_entity_reference_at(body, i)
        {
            charge_parameter_entity_reference(
                name,
                &parameter_entities,
                &mut count,
                max_entities,
                reject_nested,
            )?;
            i = end;
            continue;
        }
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let remaining = &bytes[i..];
        if remaining.starts_with(b"<![CDATA[") {
            let Some(end) = find_subsequence(&bytes[i + 9..], b"]]>") else {
                return Ok(());
            };
            i = i + 9 + end + 3;
            continue;
        }
        if remaining.starts_with(b"<!--") {
            let Some(end) = find_subsequence(&bytes[i + 4..], b"-->") else {
                return Ok(());
            };
            i = i + 4 + end + 3;
            continue;
        }
        if remaining.len() >= 2 && remaining[1] == b'?' {
            let Some(end) = find_subsequence(&bytes[i + 2..], b"?>") else {
                return Ok(());
            };
            i = i + 2 + end + 2;
            continue;
        }
        if i + needle.len() <= bytes.len()
            && bytes[i..i + needle.len()].eq_ignore_ascii_case(needle)
        {
            count += 1;
            if count > max_entities {
                return Err(format!(
                    "XML declares more than {max_entities} entities (possible entity-expansion attack)"
                ));
            }
            let decl_end = find_xml_declaration_end(&bytes[i..])
                .map(|end| i + end)
                .unwrap_or(bytes.len());
            // External entity declarations are always refused: Ferrum never
            // resolves them, but a downstream parser that does turns this into
            // an XXE/SSRF primitive.
            if entity_declaration_is_external(&body[i..decl_end]) {
                return Err(
                    "XML declares an external entity (SYSTEM/PUBLIC identifiers are not permitted)"
                        .to_string(),
                );
            }
            if reject_nested && entity_value_references_nested_entity(&body[i..decl_end]) {
                return Err(
                    "XML entity definition references another entity (billion-laughs protection)"
                        .to_string(),
                );
            }
            if let Some((name, value)) = parameter_entity_declaration(&body[i..decl_end]) {
                // Count nested entity declarations once, at declaration time, so
                // each later `%name;` reference is an O(1) lookup.
                parameter_entities.push((name.to_string(), entity_declaration_count(value)));
            }
            i = decl_end.saturating_add(1);
        } else if remaining.starts_with(b"<!DOCTYPE") {
            if doctype_declaration_is_external(&body[i..]) {
                return Err(
                    "XML DOCTYPE has an external SYSTEM/PUBLIC identifier, which is not permitted"
                        .to_string(),
                );
            }
            // Do not skip the complete DOCTYPE: its internal subset may contain
            // entity declarations that the guards above must inspect.
            i += b"<!DOCTYPE".len();
        } else if remaining.starts_with(b"<!") {
            // Skip other markup declarations quote-aware. This prevents text
            // such as "<!DOCTYPE" or "<!ENTITY" inside a quoted ATTLIST value
            // from being misclassified as a declaration of its own. Parameter
            // entity references outside quotes still count toward policy.
            let decl_end = find_xml_declaration_end(remaining)
                .map(|end| i + end)
                .unwrap_or(bytes.len());
            charge_parameter_entity_references_in_markup(
                body,
                i,
                decl_end,
                &parameter_entities,
                &mut count,
                max_entities,
                reject_nested,
            )?;
            i = decl_end.saturating_add(1);
        } else {
            i += 1;
        }
    }
    Ok(())
}

fn charge_parameter_entity_reference(
    name: &str,
    parameter_entities: &[(String, usize)],
    count: &mut usize,
    max_entities: usize,
    reject_nested: bool,
) -> Result<(), String> {
    let Some((_, expanded_entities)) = parameter_entities
        .iter()
        .find(|(entity_name, _)| entity_name == name)
    else {
        return Ok(());
    };
    if *expanded_entities == 0 {
        return Ok(());
    }
    if reject_nested {
        return Err(
            "XML parameter entity expands to entity declarations (billion-laughs protection)"
                .to_string(),
        );
    }
    *count = count.saturating_add(*expanded_entities);
    if *count > max_entities {
        return Err(format!(
            "XML declares more than {max_entities} entities after parameter entity expansion (possible entity-expansion attack)"
        ));
    }
    Ok(())
}

fn charge_parameter_entity_references_in_markup(
    body: &str,
    start: usize,
    end: usize,
    parameter_entities: &[(String, usize)],
    count: &mut usize,
    max_entities: usize,
    reject_nested: bool,
) -> Result<(), String> {
    let bytes = body.as_bytes();
    let mut quote = None;
    let mut i = start;
    while i < end {
        match quote {
            Some(current) if bytes[i] == current => quote = None,
            Some(_) => {}
            None if matches!(bytes[i], b'"' | b'\'') => quote = Some(bytes[i]),
            None if bytes[i] == b'%' => {
                if let Some((name, reference_end)) = parameter_entity_reference_at(body, i)
                    && reference_end <= end
                {
                    charge_parameter_entity_reference(
                        name,
                        parameter_entities,
                        count,
                        max_entities,
                        reject_nested,
                    )?;
                    i = reference_end;
                    continue;
                }
            }
            None => {}
        }
        i += 1;
    }
    Ok(())
}

/// True when the document type declaration itself carries an external subset.
///
/// XML's grammar places `SYSTEM` / `PUBLIC` immediately after the document
/// name and before any internal subset, so this inspection never searches
/// quoted literals, comments, or CDATA for keyword-looking text.
fn doctype_declaration_is_external(decl: &str) -> bool {
    let bytes = decl.as_bytes();
    let needle = b"<!DOCTYPE";
    if !bytes.starts_with(needle) {
        return false;
    }

    let mut i = needle.len();
    let name_separator = skip_xml_space(bytes, i);
    if name_separator == i {
        return false;
    }
    i = name_separator;

    // The XML Name itself may be non-ASCII; its UTF-8 continuation bytes are
    // all non-whitespace, so a byte scan safely finds the grammar delimiter.
    while i < bytes.len() && !matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | b'[' | b'>') {
        i += 1;
    }
    let external_separator = skip_xml_space(bytes, i);
    if external_separator == i {
        return false;
    }
    i = external_separator;

    for keyword in [b"SYSTEM".as_slice(), b"PUBLIC".as_slice()] {
        if bytes
            .get(i..i + keyword.len())
            .is_some_and(|candidate| candidate == keyword)
            && bytes
                .get(i + keyword.len())
                .is_some_and(|next| matches!(next, b' ' | b'\t' | b'\r' | b'\n'))
        {
            return true;
        }
    }
    false
}

fn find_xml_declaration_end(bytes: &[u8]) -> Option<usize> {
    let mut quote = None;
    for (idx, byte) in bytes.iter().copied().enumerate() {
        match quote {
            Some(current) if byte == current => quote = None,
            Some(_) => {}
            None if matches!(byte, b'"' | b'\'') => quote = Some(byte),
            None if byte == b'>' => return Some(idx),
            None => {}
        }
    }
    None
}

/// True when an `<!ENTITY ...>` declaration names an external entity, i.e. its
/// definition is a `SYSTEM` or `PUBLIC` external identifier rather than a
/// quoted literal.
fn entity_declaration_is_external(decl: &str) -> bool {
    let bytes = decl.as_bytes();
    let needle = b"<!ENTITY";
    if bytes.len() < needle.len() || !bytes[..needle.len()].eq_ignore_ascii_case(needle) {
        return false;
    }
    let mut i = needle.len();
    i = skip_xml_space(bytes, i);
    if bytes.get(i) == Some(&b'%') {
        i += 1;
        i = skip_xml_space(bytes, i);
    }
    // Entity name.
    while i < bytes.len() && !matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i = skip_xml_space(bytes, i);
    // XML external identifier keywords are case-sensitive upper case.
    decl.get(i..)
        .is_some_and(|rest| rest.starts_with("SYSTEM") || rest.starts_with("PUBLIC"))
}

fn parameter_entity_declaration(decl: &str) -> Option<(&str, &str)> {
    let bytes = decl.as_bytes();
    let needle = b"<!ENTITY";
    if bytes.len() < needle.len() || !bytes[..needle.len()].eq_ignore_ascii_case(needle) {
        return None;
    }
    let mut i = needle.len();
    i = skip_xml_space(bytes, i);
    if bytes.get(i) != Some(&b'%') {
        return None;
    }
    i += 1;
    i = skip_xml_space(bytes, i);
    let name_start = i;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'-' | b'.'))
    {
        i += 1;
    }
    if i == name_start {
        return None;
    }
    let name_end = i;
    i = skip_xml_space(bytes, i);
    let quote = *bytes.get(i)?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    i += 1;
    let value_start = i;
    while i < bytes.len() && bytes[i] != quote {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    Some((&decl[name_start..name_end], &decl[value_start..i]))
}

fn parameter_entity_reference_at(body: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = body.as_bytes();
    if bytes.get(start) != Some(&b'%') {
        return None;
    }
    let mut i = start + 1;
    let name_start = i;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'-' | b'.'))
    {
        i += 1;
    }
    if i == name_start || bytes.get(i) != Some(&b';') {
        return None;
    }
    Some((&body[name_start..i], i + 1))
}

fn entity_declaration_count(text: &str) -> usize {
    let bytes = text.as_bytes();
    let needle = b"<!ENTITY";
    if bytes.len() < needle.len() {
        return 0;
    }
    bytes
        .windows(needle.len())
        .filter(|window| window.eq_ignore_ascii_case(needle))
        .count()
}

fn skip_xml_space(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

/// True if an `<!ENTITY ...>` declaration's value references another entity.
/// General entity refs (`&name;`) and parameter entity refs (`%name;`) can both
/// create expansion chains. Numeric character refs are normalized first because
/// XML resolves them inside entity replacement text before expansion.
fn entity_value_references_nested_entity(decl: &str) -> bool {
    let Some(value) = entity_declaration_value(decl) else {
        return false;
    };
    let decoded = decode_xml_numeric_char_refs(value);
    entity_replacement_text_references_entity(decoded.as_ref())
}

fn entity_declaration_value(decl: &str) -> Option<&str> {
    let bytes = decl.as_bytes();
    let needle = b"<!ENTITY";
    if bytes.len() < needle.len() || !bytes[..needle.len()].eq_ignore_ascii_case(needle) {
        return None;
    }
    let mut i = needle.len();
    i = skip_xml_space(bytes, i);
    if bytes.get(i) == Some(&b'%') {
        i += 1;
        i = skip_xml_space(bytes, i);
    }
    let name_start = i;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'-' | b'.'))
    {
        i += 1;
    }
    if i == name_start {
        return None;
    }
    i = skip_xml_space(bytes, i);
    let quote = *bytes.get(i)?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    i += 1;
    let value_start = i;
    while i < bytes.len() && bytes[i] != quote {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    Some(&decl[value_start..i])
}

fn decode_xml_numeric_char_refs(value: &str) -> std::borrow::Cow<'_, str> {
    let bytes = value.as_bytes();
    let mut i = 0usize;
    let mut out: Option<String> = None;
    while i < bytes.len() {
        if bytes[i] == b'&'
            && bytes.get(i + 1) == Some(&b'#')
            && let Some((cp, end)) = numeric_char_ref_at(bytes, i)
            && let Some(ch) = char::from_u32(cp)
        {
            let output = out.get_or_insert_with(|| value[..i].to_string());
            output.push(ch);
            i = end;
            continue;
        }
        let Some(ch) = value[i..].chars().next() else {
            break;
        };
        if let Some(output) = &mut out {
            output.push(ch);
        }
        i += ch.len_utf8();
    }
    match out {
        Some(decoded) => std::borrow::Cow::Owned(decoded),
        None => std::borrow::Cow::Borrowed(value),
    }
}

fn entity_replacement_text_references_entity(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if matches!(bytes[i], b'&' | b'%') {
            let marker = bytes[i];
            let mut j = i + 1;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || matches!(bytes[j], b'_' | b'-' | b'.'))
            {
                j += 1;
            }
            if j > i + 1 && bytes.get(j) == Some(&b';') {
                let name = &value[i + 1..j];
                if marker == b'%' || !matches!(name, "lt" | "gt" | "amp" | "quot" | "apos") {
                    return true;
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    false
}

fn numeric_char_ref_at(bytes: &[u8], start: usize) -> Option<(u32, usize)> {
    if bytes.get(start) != Some(&b'&') || bytes.get(start + 1) != Some(&b'#') {
        return None;
    }
    let mut i = start + 2;
    let radix = if matches!(bytes.get(i), Some(b'x' | b'X')) {
        i += 1;
        16
    } else {
        10
    };
    let digits_start = i;
    while i < bytes.len()
        && match radix {
            16 => bytes[i].is_ascii_hexdigit(),
            _ => bytes[i].is_ascii_digit(),
        }
    {
        i += 1;
    }
    if i == digits_start || bytes.get(i) != Some(&b';') {
        return None;
    }
    let digits = std::str::from_utf8(&bytes[digits_start..i]).ok()?;
    let cp = u32::from_str_radix(digits, radix).ok()?;
    Some((cp, i + 1))
}

/// JSON dispatch over a media-type essence: exact `application/json` or an
/// RFC 6838 structured suffix `+json`. Operates on type/subtype only so
/// parameter values and neighboring types such as `application/json-seq` are
/// not treated as single-document JSON.
fn is_json_like_content_type(content_type: &str) -> bool {
    let Some(media_type) = media_type_essence(content_type) else {
        return false;
    };
    media_type.eq_ignore_ascii_case("application/json")
        || ascii_ends_with_ignore_case(media_type, "+json")
}

/// XML dispatch over a media-type essence: exact `application/xml` /
/// `text/xml`, or an RFC 6838 structured suffix `+xml`.
fn is_xml_like_content_type(content_type: &str) -> bool {
    let Some(media_type) = media_type_essence(content_type) else {
        return false;
    };
    media_type.eq_ignore_ascii_case("application/xml")
        || media_type.eq_ignore_ascii_case("text/xml")
        || ascii_ends_with_ignore_case(media_type, "+xml")
}

fn ascii_starts_with_ignore_case(value: &str, prefix: &str) -> bool {
    let value = value.as_bytes();
    let prefix = prefix.as_bytes();
    value.len() >= prefix.len()
        && value[..prefix.len()]
            .iter()
            .zip(prefix)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn ascii_ends_with_ignore_case(value: &str, suffix: &str) -> bool {
    let value = value.as_bytes();
    let suffix = suffix.as_bytes();
    value.len() >= suffix.len()
        && value[value.len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

/// Parse protobuf configuration shape without touching the local filesystem.
fn parse_protobuf_shape(config: &Value) -> Result<ProtobufShape, String> {
    let descriptor_path = optional_string(config, "protobuf_descriptor_path")?.map(str::to_string);
    if descriptor_path.is_none()
        && (config.get("protobuf_request_type").is_some()
            || config.get("protobuf_response_type").is_some()
            || config.get("protobuf_method_messages").is_some())
    {
        return Err(
            "body_validator: 'protobuf_descriptor_path' is required when configuring protobuf validation"
                .to_string(),
        );
    }

    let request_type = optional_string(config, "protobuf_request_type")?.map(str::to_string);
    let response_type = optional_string(config, "protobuf_response_type")?.map(str::to_string);
    let mut targets = ProtobufTargets {
        default_request: request_type.is_some(),
        default_response: response_type.is_some(),
        ..Default::default()
    };
    let mut methods = HashMap::new();
    if let Some(method_configs) = optional_object(config, "protobuf_method_messages")? {
        for (method_path, method_config) in method_configs {
            if method_path.is_empty() {
                return Err(
                    "body_validator: protobuf_method_messages method paths must not be empty"
                        .to_string(),
                );
            }
            let Some(method_object) = method_config.as_object() else {
                return Err(
                    "body_validator: a 'protobuf_method_messages' entry must be an object"
                        .to_string(),
                );
            };
            // Reject unknown per-method keys before defaults so a misspelled
            // direction cannot leave that direction unvalidated while the other
            // direction keeps admission succeeding (GHSA-w7x7-ppx9-5v74).
            if method_object
                .keys()
                .any(|key| !BODY_VALIDATOR_PROTOBUF_METHOD_KEYS.contains(&key.as_str()))
            {
                return Err(format!(
                    "body_validator: a 'protobuf_method_messages' entry has an unknown key; \
                     allowed keys: {}",
                    BODY_VALIDATOR_PROTOBUF_METHOD_KEYS.join(", ")
                ));
            }
            let request = optional_string(method_config, "request")?.map(str::to_string);
            let response = optional_string(method_config, "response")?.map(str::to_string);
            if request.is_none() && response.is_none() {
                return Err(
                    "body_validator: a 'protobuf_method_messages' entry must configure 'request' \
                     or 'response'"
                        .to_string(),
                );
            }
            if request.is_some() {
                targets.method_requests.insert(method_path.clone());
            }
            if response.is_some() {
                targets.method_responses.insert(method_path.clone());
            }
            methods.insert(
                method_path.clone(),
                ProtobufMethodShape { request, response },
            );
        }
    }

    Ok(ProtobufShape {
        descriptor_path,
        request_type,
        response_type,
        methods,
        targets,
    })
}

pub(crate) fn protobuf_descriptor_path(config: &Value) -> Result<Option<&str>, String> {
    optional_string(config, "protobuf_descriptor_path")
}

enum ProtobufDescriptorLoadError {
    Unavailable(String),
    Invalid(String),
}

impl ProtobufDescriptorLoadError {
    fn into_message(self) -> String {
        match self {
            Self::Unavailable(message) | Self::Invalid(message) => message,
        }
    }
}

fn load_protobuf_descriptor_pool_inner(
    descriptor_path: &str,
) -> Result<DescriptorPool, ProtobufDescriptorLoadError> {
    let descriptor_bytes = std::fs::read(descriptor_path).map_err(|_| {
        ProtobufDescriptorLoadError::Unavailable(
            "body_validator: failed to read protobuf descriptor file".to_string(),
        )
    })?;
    DescriptorPool::decode(descriptor_bytes.as_slice()).map_err(|_| {
        ProtobufDescriptorLoadError::Invalid(
            "body_validator: failed to parse protobuf descriptor".to_string(),
        )
    })
}

fn resolve_protobuf_shape(
    shape: &ProtobufShape,
    pool: &DescriptorPool,
) -> Result<ResolvedProtobufShape, String> {
    let request_descriptor = shape
        .request_type
        .as_deref()
        .map(|name| {
            pool.get_message_by_name(name).ok_or_else(|| {
                "body_validator: configured 'protobuf_request_type' was not found in the descriptor"
                    .to_string()
            })
        })
        .transpose()?;
    let response_descriptor = shape
        .response_type
        .as_deref()
        .map(|name| {
            pool.get_message_by_name(name).ok_or_else(|| {
                "body_validator: configured 'protobuf_response_type' was not found in the descriptor"
                    .to_string()
            })
        })
        .transpose()?;
    let mut method_messages = HashMap::new();
    for (method_path, method) in &shape.methods {
        let request = method
            .request
            .as_deref()
            .map(|name| {
                pool.get_message_by_name(name).ok_or_else(|| {
                    "body_validator: a 'protobuf_method_messages' request type was not found in \
                     the descriptor"
                        .to_string()
                })
            })
            .transpose()?;
        let response = method
            .response
            .as_deref()
            .map(|name| {
                pool.get_message_by_name(name).ok_or_else(|| {
                    "body_validator: a 'protobuf_method_messages' response type was not found in \
                     the descriptor"
                        .to_string()
                })
            })
            .transpose()?;
        method_messages.insert(
            method_path.clone(),
            ProtobufMethodEntry { request, response },
        );
    }
    Ok(ResolvedProtobufShape {
        request_descriptor,
        response_descriptor,
        method_messages,
    })
}

pub(crate) fn validate_protobuf_descriptor_config(
    config: &Value,
    pool: &DescriptorPool,
) -> Result<(), String> {
    let shape = parse_protobuf_shape(config)?;
    resolve_protobuf_shape(&shape, pool).map(|_| ())
}

/// Load protobuf validation config for a runtime instance, or validate shape
/// only for CP/admin admission.
fn load_protobuf_config(
    config: &Value,
    mode: DescriptorLoadMode,
) -> Result<ProtobufConfig, String> {
    let shape = parse_protobuf_shape(config)?;
    let Some(descriptor_path) = shape.descriptor_path.as_deref() else {
        return Ok(ProtobufConfig {
            pool: None,
            request_descriptor: None,
            response_descriptor: None,
            method_messages: HashMap::new(),
            targets: shape.targets,
            dependency_unavailable: false,
        });
    };

    if matches!(mode, DescriptorLoadMode::ShapeOnly) {
        return Ok(ProtobufConfig {
            pool: None,
            request_descriptor: None,
            response_descriptor: None,
            method_messages: HashMap::new(),
            targets: shape.targets,
            dependency_unavailable: true,
        });
    }

    let pool = match load_protobuf_descriptor_pool_inner(descriptor_path) {
        Ok(pool) => pool,
        Err(ProtobufDescriptorLoadError::Unavailable(_)) => {
            warn!(
                plugin = "body_validator",
                "Protobuf descriptor dependency is unavailable; applicable gRPC validation will fail closed"
            );
            return Ok(ProtobufConfig {
                pool: None,
                request_descriptor: None,
                response_descriptor: None,
                method_messages: HashMap::new(),
                targets: shape.targets,
                dependency_unavailable: true,
            });
        }
        Err(error) => return Err(error.into_message()),
    };
    let ResolvedProtobufShape {
        request_descriptor,
        response_descriptor,
        method_messages,
    } = resolve_protobuf_shape(&shape, &pool)?;
    Ok(ProtobufConfig {
        pool: Some(pool),
        request_descriptor,
        response_descriptor,
        method_messages,
        targets: shape.targets,
        dependency_unavailable: false,
    })
}

/// Find the position of a byte subsequence within a slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Helper to build a rejection `PluginResult` for protobuf validation failures.
fn protobuf_reject(status_code: u16, direction: &str, msg: &str) -> PluginResult {
    let msg = bound_detail(msg);
    debug!(
        "body_validator: {} protobuf validation failed: {}",
        direction, msg
    );
    PluginResult::Reject {
        status_code,
        body: serde_json::json!({
            "error": if status_code == 400 {
                "Request body validation failed"
            } else {
                "Response body validation failed"
            },
            "details": msg
        })
        .to_string(),
        headers: HashMap::new(),
    }
}

#[async_trait]
impl Plugin for BodyValidator {
    fn name(&self) -> &str {
        "body_validator"
    }

    fn priority(&self) -> u16 {
        super::priority::BODY_VALIDATOR
    }

    /// This plugin's enforcement decision is taken in the final request-body
    /// phase, over the exact backend-visible representation. Composition
    /// admission refuses to pair it with a plugin that egresses the request
    /// before finalization (GHSA-4vr5-4wm3-x5xv).
    fn enforces_finalized_request_policy(&self) -> bool {
        true
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        // JSON/XML validation reads request_body from metadata in before_proxy.
        // Protobuf validation runs in on_final_request_body and should not force pre-before_proxy buffering.
        self.has_pre_proxy_request_validation
    }

    fn requires_request_body_buffering(&self) -> bool {
        self.has_request_validation
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if !self.has_request_validation
            || matches!(ctx.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "DELETE")
        {
            return false;
        }

        let content_type = ctx
            .headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");

        // For gRPC protobuf validation, buffer if content-type is application/grpc
        if self.has_protobuf_request_validation && is_grpc_content_type(content_type) {
            return true;
        }

        content_type_matches(&self.content_types, content_type)
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only validate methods that typically have a body
        if matches!(ctx.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "DELETE") {
            return PluginResult::Continue;
        }

        // Check content type
        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");

        // gRPC protobuf validation is handled in on_final_request_body, not here
        if is_grpc_content_type(content_type) {
            return PluginResult::Continue;
        }

        let should_validate = content_type_matches(&self.content_types, content_type);

        if !should_validate {
            return PluginResult::Continue;
        }

        // The request body lives in `ctx.metadata`, so the shared duplicate-key
        // memo is moved out for the duration of the borrow and moved back
        // before this hook returns. Taking it is not a reset: `JsonScanMemo` is
        // keyed on body digests, so restoring it preserves every verdict.
        let mut json_scan_memo = std::mem::take(&mut ctx.json_scan_memo);

        // Get body from metadata (set by proxy handler if body collection is early)
        let result = match ctx.metadata.get("request_body") {
            None => {
                // No body available — can't validate
                debug!("body_validator: no request body available for validation");
                Ok(())
            }
            Some(body) if body.is_empty() => Ok(()),
            // Determine validation type
            Some(body) if is_json_like_content_type(content_type) => Self::validate_json_body(
                body,
                &self.required_fields,
                self.json_validator.as_ref(),
                Direction::Request,
                Some(&mut json_scan_memo),
            ),
            Some(body)
                if is_xml_like_content_type(content_type) && self.has_xml_request_validation =>
            {
                Self::validate_xml_body(
                    body,
                    &self.required_xml_elements,
                    self.xml_max_entities,
                    self.xml_reject_nested_entities,
                )
            }
            Some(_) => Ok(()),
        };

        ctx.json_scan_memo = json_scan_memo;

        match result {
            Ok(()) => PluginResult::Continue,
            Err(msg) => {
                let detail = bound_detail(&msg);
                debug!("body_validator: request validation failed: {}", detail);
                PluginResult::Reject {
                    status_code: 400,
                    body: serde_json::json!({
                        "error": "Request body validation failed",
                        "details": detail
                    })
                    .to_string(),
                    headers: HashMap::new(),
                }
            }
        }
    }

    async fn on_final_request_body(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.validate_final_request_body(headers, body, None).await
    }

    /// Context-aware variant so the duplicate-key screen of the final
    /// backend-visible body is shared with every other governed plugin in this
    /// hook stage (they all receive the same context object).
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        let mut json_scan_memo = std::mem::take(&mut ctx.json_scan_memo);
        let result = self
            .validate_final_request_body(headers, body, Some(&mut json_scan_memo))
            .await;
        ctx.json_scan_memo = json_scan_memo;
        result
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.has_response_validation
    }

    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        // Request Accept is only client intent. Keep ordinary backend JSON/XML
        // and protobuf responses on the validator path until response headers
        // prove that the backend selected an event stream.
        self.has_response_validation
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
        // Once headers prove the representation is outside JSON/XML/gRPC
        // validation scope (or is an unbounded event stream), retries must not
        // keep pinning it on the buffered path. Matching types stay buffered.
        self.should_buffer_response_body(ctx)
            && !self.response_body_requires_buffering_for_media_type(
                ctx,
                response_headers.get("content-type").map(String::as_str),
            )
    }

    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        // Only genuine SSE is safe to release before the Content-Type relabel
        // guard: `after_proxy` fails closed on it. Non-matching downloads still
        // go through the ordinary content-type refinement, which refuses
        // release when a later hook may rewrite Content-Type.
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
        // Narrow the pre-flight vote after backend headers arrive: release
        // media types the final hook would skip (binary downloads, etc.) while
        // keeping matching JSON/XML and applicable gRPC protobuf responses
        // buffered for validation.
        self.should_buffer_response_body(ctx)
            && self.response_body_requires_buffering_for_media_type(ctx, content_type)
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
            return PluginResult::Reject {
                status_code: 502,
                body: serde_json::json!({
                    "error": "Response body validation failed",
                    "details": "event-stream responses require a bounded streaming validator"
                })
                .to_string(),
                headers: HashMap::new(),
            };
        }
        PluginResult::Continue
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.has_response_validation {
            return PluginResult::Continue;
        }

        // Determine content type from response headers
        let content_type = response_headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");

        // gRPC protobuf response validation
        if is_grpc_content_type(content_type) {
            if !self.has_protobuf_response_validation || body.is_empty() {
                return PluginResult::Continue;
            }
            // Resolve the gRPC method path from the request, NOT response headers.
            // Backends never echo `:path` in responses, so reading response_headers
            // would always miss per-method `protobuf_method_messages` overrides.
            let grpc_path = Self::grpc_method_path_for_response(ctx);
            if self.protobuf_dependency_unavailable
                && self.protobuf_targets.response_applies(&grpc_path)
            {
                return protobuf_reject(
                    502,
                    "response",
                    "configured protobuf descriptor dependency is unavailable",
                );
            }
            let descriptor = match self.get_response_descriptor(&grpc_path) {
                Some(d) => d,
                None => return PluginResult::Continue,
            };
            // 502 Bad Gateway: the backend returned a response whose protobuf
            // payload does not match the expected schema — i.e., the upstream
            // produced an invalid response, which is the definition of 502.
            return match self.validate_protobuf_body(body, descriptor) {
                Ok(()) => PluginResult::Continue,
                Err(msg) => protobuf_reject(502, "response", &msg),
            };
        }

        let should_validate = content_type_matches(&self.response_content_types, content_type);

        if !should_validate {
            return PluginResult::Continue;
        }

        if body.is_empty() {
            return PluginResult::Continue;
        }

        // Convert body bytes to string for validation
        let body_str = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => {
                debug!("body_validator: response body is not valid UTF-8, skipping validation");
                return PluginResult::Continue;
            }
        };

        // Determine validation type
        let result = if is_json_like_content_type(content_type) {
            Self::validate_json_body(
                body_str,
                &self.response_required_fields,
                self.response_json_validator.as_ref(),
                Direction::Response,
                Some(&mut ctx.json_scan_memo),
            )
        } else if is_xml_like_content_type(content_type) && self.has_xml_response_validation {
            Self::validate_xml_body(
                body_str,
                &self.response_required_xml_elements,
                self.xml_max_entities,
                self.xml_reject_nested_entities,
            )
        } else {
            Ok(())
        };

        match result {
            Ok(()) => PluginResult::Continue,
            Err(msg) => {
                // `msg` is already payload-free by construction, so the same
                // string is safe for the client body and for internal tracing;
                // there is no raw-detail development channel to fall back to
                // (`GHSA-5p2h-fq6q-gwh9`).
                let detail = bound_detail(&msg);
                debug!("body_validator: response validation failed: {}", detail);
                PluginResult::Reject {
                    status_code: 502,
                    body: serde_json::json!({
                        "error": "Response body validation failed",
                        "details": detail
                    })
                    .to_string(),
                    headers: HashMap::new(),
                }
            }
        }
    }
}
