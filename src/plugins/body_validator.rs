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
//! Request validation for JSON/XML runs in `before_proxy` (rejects with 400) —
//! except when the request declares a non-identity `Content-Encoding`, whose
//! plaintext only the shared backend-visible representation gate can produce;
//! that case is judged in the final request-body hook instead, still before
//! backend egress (`GHSA-3973-47g5-4mcx`).
//! Request validation for protobuf runs in `on_final_request_body` (rejects with 400).
//! Response validation runs in `finalize_client_visible_response_body` (rejects
//! with 502) and requires response body buffering when configured. That phase is
//! after every semantic body transform and before gateway transport encoding, so
//! the validator reads the exact client-visible plaintext rather than a
//! representation a later rewrite or a gzip encode produced
//! (`GHSA-62jg-v563-4q23`, `GHSA-4vqr-427g-5cg7`).
//!
//! Applicability is decided by the configured representation, never by the
//! request method (advisory `GHSA-2vmr-ww8r-mww3`). Once a configured rule
//! applies, an unusual method, an empty body, an uninspectable (non-UTF-8) body,
//! or a missing buffered representation is a rejection — never a silent
//! `Continue`. The only exemptions are the ones the protocol itself defines:
//! empty native-gRPC error replies (a single valid non-zero terminal
//! `grpc-status` in the hook-visible metadata), and HTTP responses that carry no
//! content by status/method semantics (1xx, 204, 205, 304, and responses to
//! `HEAD`).
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
//! segments survive only when the configured schema declares them as JSON
//! property names (numeric pointer segments render as a fixed marker; raw XML
//! names are never collected), and an allowlisted JSON Schema keyword. No
//! rejected instance value, expected constant, configured XML name, raw schema
//! path, `roxmltree` parse token, or `prost` decode rendering is formatted into
//! them (`GHSA-5p2h-fq6q-gwh9`). Response-side details stay coarser still, since
//! describing an upstream body's shape back to the client is itself a
//! disclosure.

use async_trait::async_trait;
use prost_reflect::{
    Cardinality, DescriptorPool, DynamicMessage, EnumDescriptor, Kind, MessageDescriptor,
    ReflectMessage, Syntax, Value as ProtobufValue,
};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, warn};

use crate::plugins::utils::log_sampling::warn_sampled;
use crate::proxy::response_buffer_budget::{
    self as response_budget, BudgetRef, ResponseBufferReservation,
};
use crate::util::json_dup_keys::{self, JsonScanMemo};

use super::utils::sse::{is_text_event_stream_media_type, original_response_is_event_stream};
use super::utils::synthetic_response::{
    request_method_omits_response_body, synthetic_response_omits_body,
};
use super::utils::validation_diagnostics::{
    SafeFieldNames, bound_detail, safe_keyword, safe_location, schema_violation_detail,
    xml_error_category,
};
use super::utils::xml_bounds::{XML_MAX_NESTING_DEPTH, xml_nesting_depth_within_limit};
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
    /// Every method path that has a `protobuf_method_messages` entry. An entry
    /// is direction-authoritative: a direction it omits is NOT validated
    /// against the default type, because a single-direction entry is how an
    /// operator says "do not validate this method's other direction".
    method_entries: HashSet<String>,
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
        if self.method_entries.contains(grpc_path) {
            self.method_requests.contains(grpc_path)
        } else {
            self.default_request
        }
    }

    fn response_applies(&self, grpc_path: &str) -> bool {
        if self.method_entries.contains(grpc_path) {
            self.method_responses.contains(grpc_path)
        } else {
            self.default_response
        }
    }
}

/// What a configured violation does to the exchange.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EnforcementMode {
    /// Reject the request (`400` / `415`) or the response (`502`).
    Block,
    /// Evaluate, record the would-be outcome in metadata, and always continue.
    LogOnly,
}

/// Which upstream response statuses response validation applies to.
///
/// A response schema describes the operation's SUCCESS document. Judging a
/// backend `404` / `422` / `500` error document against it used to replace the
/// real status and error body with a gateway `502`, so the default scope is
/// `2XX` only and operators opt other statuses in explicitly.
#[derive(Clone)]
struct ResponseStatusScope {
    /// `classes[n]` selects every `nXX` status, `n` in `1..=5`.
    classes: [bool; 6],
    codes: Vec<u16>,
}

impl ResponseStatusScope {
    fn success_only() -> Self {
        let mut classes = [false; 6];
        classes[2] = true;
        Self {
            classes,
            codes: Vec::new(),
        }
    }

    fn contains(&self, status: u16) -> bool {
        let class = usize::from(status / 100);
        self.classes.get(class).copied().unwrap_or(false) || self.codes.contains(&status)
    }
}

/// Source of [`BodyValidator::instance_id`]. Process-unique and never
/// persisted; it scopes this instance's private per-request state.
static NEXT_BODY_VALIDATOR_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

/// Why a protobuf representation did not validate.
enum ProtobufFailure {
    /// The bytes violate the descriptor, the framing, or an inspection bound.
    Invalid(String),
    /// The aggregate decode budget could not admit the working set. Nothing is
    /// wrong with the bytes; the gateway is out of inspection capacity.
    Capacity,
}

impl From<String> for ProtobufFailure {
    fn from(message: String) -> Self {
        Self::Invalid(message)
    }
}

/// The outcome of one request-side evaluation, before the enforcement mode
/// decides what it does to the exchange.
enum RequestVerdict {
    Pass,
    Violation {
        status: u16,
        detail: String,
    },
    Capacity,
    /// Log-only mode only: the representation carried a content coding no
    /// gate decoded for this instance, so it could not be observed.
    Uninspected,
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
    "enforcement_mode",
    "reject_unsupported_media_types",
    "response_status_codes",
];

/// Request/response metadata keys this plugin publishes when a configured rule
/// finds a violation (or, in `log_only` mode, would have rejected). Values are
/// fixed categories, a status code, and the same payload-free bounded
/// diagnostic the client-visible `details` field carries.
pub const BODY_VALIDATOR_REQUEST_OUTCOME_KEY: &str = "body_validator.request_outcome";
pub const BODY_VALIDATOR_REQUEST_STATUS_KEY: &str = "body_validator.request_status";
pub const BODY_VALIDATOR_REQUEST_DETAIL_KEY: &str = "body_validator.request_detail";
pub const BODY_VALIDATOR_RESPONSE_OUTCOME_KEY: &str = "body_validator.response_outcome";
pub const BODY_VALIDATOR_RESPONSE_STATUS_KEY: &str = "body_validator.response_status";
pub const BODY_VALIDATOR_RESPONSE_DETAIL_KEY: &str = "body_validator.response_detail";

/// Outcome value for a violation that rejected the exchange.
const OUTCOME_REJECTED: &str = "rejected";
/// Outcome value for a `log_only` violation that was allowed through.
const OUTCOME_WOULD_REJECT: &str = "would_reject";
/// Outcome value for a representation `log_only` mode could not observe (an
/// undecoded content coding, or no inspection capacity).
const OUTCOME_UNINSPECTED: &str = "uninspected";
/// Outcome value for an inspection-capacity refusal in `block` mode.
const OUTCOME_CAPACITY_REFUSED: &str = "capacity_refused";

/// Fixed diagnostic for `reject_unsupported_media_types`.
const UNSUPPORTED_MEDIA_TYPE_DETAIL: &str =
    "Request media type is not one this validator is configured to inspect";

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
    /// Content types to validate for requests. Never empty: an explicit empty
    /// list is rejected at construction. Entries are exact essences or
    /// `type/*+suffix` structured-suffix patterns.
    content_types: Vec<String>,
    /// Refuse (`415`) a request body this instance has no configured rule for.
    reject_unsupported_media_types: bool,

    // ── Response validation config ──
    /// Compiled JSON Schema for response body validation (if configured).
    response_json_validator: Option<CompiledJsonSchema>,
    /// Required JSON fields in response bodies.
    response_required_fields: Vec<String>,
    /// Required XML elements in response bodies, parsed into expanded names.
    response_required_xml_elements: Vec<RequiredXmlElement>,
    /// Content types to validate for responses.
    response_content_types: Vec<String>,
    /// Upstream statuses response validation applies to (default `2XX`).
    response_status_scope: ResponseStatusScope,

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
    /// has `required` fields, so a proto3-only pool skips the initialization
    /// check; it enters the shared message walk only when
    /// `protobuf_reject_unknown_fields` asks for one.
    protobuf_pool_has_proto2: bool,
    /// Whether to reject messages with unknown field numbers.
    protobuf_reject_unknown_fields: bool,
    /// Positive maximum decompressed gRPC payload size.
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

    // ── Enforcement ──
    /// `block` (default) or `log_only`.
    enforcement_mode: EnforcementMode,
    /// Process-unique id scoping this instance's private per-request state.
    instance_id: u64,
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
    /// therefore the authoritative runtime answer.
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
                "body_validator: unknown configuration key; allowed keys: `{}`",
                BODY_VALIDATOR_CONFIG_KEYS.join("`, `")
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
        let response_status_scope = optional_response_status_scope(config)?
            .unwrap_or_else(ResponseStatusScope::success_only);
        let enforcement_mode = match optional_string(config, "enforcement_mode")? {
            None | Some("block") => EnforcementMode::Block,
            Some("log_only") => EnforcementMode::LogOnly,
            Some(_) => {
                return Err(
                    "body_validator: `enforcement_mode` must be `block` or `log_only`".to_string(),
                );
            }
        };
        let reject_unsupported_media_types =
            optional_bool(config, "reject_unsupported_media_types")?.unwrap_or(false);

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
        let configured_grpc_limit = optional_usize(config, "grpc_max_decompressed_size_bytes")?;
        let grpc_max_decompressed_size_bytes = match configured_grpc_limit {
            Some(0) => {
                return Err(
                    "body_validator: `grpc_max_decompressed_size_bytes` must be greater than zero"
                        .to_string(),
                );
            }
            Some(limit) if limit > MAX_GRPC_DECOMPRESSED_SIZE_CEILING => {
                return Err(format!(
                    "body_validator: `grpc_max_decompressed_size_bytes` must be at most {MAX_GRPC_DECOMPRESSED_SIZE_CEILING}"
                ));
            }
            Some(limit) => limit,
            None => default_grpc_max_decompressed_size_bytes()?,
        };

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
                "body_validator: no validation rules configured — set `json_schema`, `required_fields`, `validate_xml`, `required_xml_elements` (request), their `response_*` equivalents, or `protobuf_descriptor_path` with message types"
                    .to_string(),
            );
        }
        if reject_unsupported_media_types && !has_request_validation {
            // Strict media-type admission refuses every body no request rule
            // inspects; without any request rule it would refuse every body.
            return Err(
                "body_validator: `reject_unsupported_media_types` requires at least one request \
                 validation rule"
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
            reject_unsupported_media_types,
            response_json_validator,
            response_required_fields,
            response_required_xml_elements,
            response_content_types,
            response_status_scope,
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
            enforcement_mode,
            instance_id: NEXT_BODY_VALIDATOR_INSTANCE_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    /// Evaluate the final backend-visible request body against the configured
    /// rules. Shared by both final request-body hooks.
    ///
    /// `ctx` is `Some` on the context-aware hook. It supplies the gRPC method
    /// path when the hook headers carry no `:path` — only the native H1/H2 gRPC
    /// ladder injects one; HTTP/3, the H3 bridge, and generic dispatch do not,
    /// and a per-method rule must not silently stop applying there.
    ///
    /// `json_scan_memo` is `Some` on the context-aware hook so the duplicate
    /// object-member screen of this exact body is shared with the other
    /// governed plugins running in the same stage, and `None` on the
    /// context-free hook, where the screen runs standalone.
    ///
    /// `undecoded_coding` is set only in `log_only` mode, which never claims the
    /// representation gate: a content-coded JSON/XML body then reaches this
    /// hook still encoded, and is recorded as uninspected rather than as a
    /// spurious UTF-8 violation.
    fn evaluate_final_request_body(
        &self,
        ctx: Option<&RequestContext>,
        headers: &HashMap<String, String>,
        body: &[u8],
        json_scan_memo: Option<&mut JsonScanMemo>,
        undecoded_coding: bool,
        budget: BudgetRef<'_>,
    ) -> RequestVerdict {
        if !self.has_request_validation {
            return RequestVerdict::Pass;
        }

        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");

        // An empty body is deliberately NOT a skip. Whether "no bytes at all"
        // satisfies the configured representation is a question only that
        // representation can answer: an empty JSON/XML document is invalid, and
        // a zero-length gRPC transport body is not a frame
        // (`GHSA-2vmr-ww8r-mww3`). The applicability checks below still pass
        // representations this instance does not govern (unless strict media
        // type admission refuses them).
        if let Some(representation) = grpc_representation(content_type) {
            if !self.has_protobuf_request_validation {
                return self.unsupported_request_body_verdict(body);
            }
            let grpc_path = request_grpc_method_path(headers, ctx);
            if self.protobuf_dependency_unavailable
                && self.protobuf_targets.request_applies(&grpc_path)
            {
                return RequestVerdict::Violation {
                    status: 400,
                    detail: "configured protobuf descriptor dependency is unavailable".to_string(),
                };
            }
            let Some(descriptor) = self.get_request_descriptor(&grpc_path) else {
                // No descriptor for this method — nothing configured to check.
                debug!(
                    "body_validator: no protobuf request descriptor for method '{}'",
                    grpc_path
                );
                return RequestVerdict::Pass;
            };
            return match self.validate_grpc_representation(
                body,
                representation,
                descriptor,
                Direction::Request,
                None,
                budget,
            ) {
                Ok(()) => RequestVerdict::Pass,
                Err(ProtobufFailure::Invalid(detail)) => RequestVerdict::Violation {
                    status: 400,
                    detail,
                },
                Err(ProtobufFailure::Capacity) => RequestVerdict::Capacity,
            };
        }

        // Only run the JSON/XML branch when JSON or XML validation is actually
        // configured. A protobuf-only plugin must not treat a non-gRPC payload
        // as malformed JSON. `has_request_validation` alone isn't enough — it's
        // also true for protobuf-only configs.
        let has_json_validation = self.json_validator.is_some() || !self.required_fields.is_empty();
        if !has_json_validation && !self.has_xml_request_validation {
            return self.unsupported_request_body_verdict(body);
        }

        if !content_type_matches(&self.content_types, content_type) {
            return self.unsupported_request_body_verdict(body);
        }

        // JSON branch matches `before_proxy`: any matching JSON-like body is
        // screened once request validation is active for this content type,
        // even when only XML rules (plus `content_types: ["application/json"]`)
        // activated the plugin — otherwise a request-body transform can
        // reintroduce duplicate members after the first screen and the final
        // backend-visible bytes are never checked. `has_json_validation` is
        // consulted only by the early return above so protobuf-only configs
        // still never treat arbitrary non-gRPC payloads as JSON.
        let validate_as_json = is_json_like_content_type(content_type);
        let validate_as_xml = !validate_as_json
            && is_xml_like_content_type(content_type)
            && self.has_xml_request_validation;
        if !validate_as_json && !validate_as_xml {
            // Allowlisted media type that no configured rule can inspect.
            return self.unsupported_request_body_verdict(body);
        }

        if undecoded_coding {
            return RequestVerdict::Uninspected;
        }

        // A body the configured JSON/XML rules cannot even decode is not
        // evidence that the policy passed. Reject with a fixed diagnostic
        // that never reproduces any of the offending bytes.
        let body_str = match std::str::from_utf8(body) {
            Ok(value) => value,
            Err(_) => {
                return RequestVerdict::Violation {
                    status: 400,
                    detail: NON_UTF8_REQUEST_BODY.to_string(),
                };
            }
        };

        let result = if validate_as_json {
            Self::validate_json_body(
                body_str,
                &self.required_fields,
                self.json_validator.as_ref(),
                Direction::Request,
                json_scan_memo,
            )
        } else {
            Self::validate_xml_body(
                body_str,
                &self.required_xml_elements,
                self.xml_max_entities,
                self.xml_reject_nested_entities,
            )
        };

        match result {
            Ok(()) => RequestVerdict::Pass,
            Err(detail) => RequestVerdict::Violation {
                status: 400,
                detail,
            },
        }
    }

    /// The verdict for a request body no configured rule inspects: a pass,
    /// unless `reject_unsupported_media_types` refuses a non-empty one.
    fn unsupported_request_body_verdict(&self, body: &[u8]) -> RequestVerdict {
        if self.reject_unsupported_media_types && !body.is_empty() {
            RequestVerdict::Violation {
                status: 415,
                detail: UNSUPPORTED_MEDIA_TYPE_DETAIL.to_string(),
            }
        } else {
            RequestVerdict::Pass
        }
    }

    /// Whether the configured JSON/XML request rules would inspect a body of
    /// this media type (the `before_proxy` / final-hook applicability ladder).
    fn json_xml_request_rule_inspects(&self, content_type: &str) -> bool {
        if !self.has_pre_proxy_request_validation
            || !content_type_matches(&self.content_types, content_type)
        {
            return false;
        }
        is_json_like_content_type(content_type)
            || (is_xml_like_content_type(content_type) && self.has_xml_request_validation)
    }

    /// Map a request-side verdict onto the exchange under the configured
    /// enforcement mode.
    fn finish_request_verdict(
        &self,
        ctx: Option<&mut RequestContext>,
        verdict: RequestVerdict,
    ) -> PluginResult {
        match verdict {
            RequestVerdict::Pass => PluginResult::Continue,
            RequestVerdict::Violation { status, detail } => {
                self.violation(ctx, Direction::Request, status, &detail)
            }
            RequestVerdict::Capacity => self.capacity_refusal(ctx, Direction::Request),
            RequestVerdict::Uninspected => {
                if let Some(ctx) = ctx {
                    record_outcome(ctx, Direction::Request, OUTCOME_UNINSPECTED, None, None);
                }
                PluginResult::Continue
            }
        }
    }

    /// Decide one configured violation: reject it in `block` mode, or record it
    /// and continue in `log_only` mode. Either way, when a request context is
    /// available the outcome is published under the fixed
    /// `body_validator.{request,response}_*` metadata keys.
    fn violation(
        &self,
        ctx: Option<&mut RequestContext>,
        direction: Direction,
        status_code: u16,
        msg: &str,
    ) -> PluginResult {
        // Every producer builds a payload-free diagnostic. `bound_detail` is
        // the compiled-in size ceiling on top of that, never the
        // confidentiality mechanism (`GHSA-5p2h-fq6q-gwh9`).
        let detail = bound_detail(msg);
        let enforced = self.enforcement_mode == EnforcementMode::Block;
        if let Some(ctx) = ctx {
            let outcome = if enforced {
                OUTCOME_REJECTED
            } else {
                OUTCOME_WOULD_REJECT
            };
            record_outcome(ctx, direction, outcome, Some(status_code), Some(&detail));
        }
        let side = match direction {
            Direction::Request => "request",
            Direction::Response => "response",
        };
        if !enforced {
            debug!(
                "body_validator: log_only {} validation would reject ({}): {}",
                side, status_code, detail
            );
            return PluginResult::Continue;
        }
        debug!("body_validator: {} validation failed: {}", side, detail);
        let error = match (status_code, direction) {
            (415, _) => "Unsupported request media type",
            (_, Direction::Request) => "Request body validation failed",
            (_, Direction::Response) => "Response body validation failed",
        };
        PluginResult::Reject {
            status_code,
            body: serde_json::json!({
                "error": error,
                "details": detail
            })
            .to_string(),
            headers: HashMap::new(),
        }
    }

    /// The gateway-local inspection-capacity terminal for a protobuf decode the
    /// aggregate budget could not admit: `503` / `RESOURCE_EXHAUSTED`, never a
    /// validation `400`/`502` (nothing is wrong with the bytes) and never a
    /// pass-through of uninspected bytes. `log_only` mode, which never refuses
    /// traffic, records the representation as uninspected instead.
    fn capacity_refusal(
        &self,
        ctx: Option<&mut RequestContext>,
        direction: Direction,
    ) -> PluginResult {
        if self.enforcement_mode == EnforcementMode::LogOnly {
            if let Some(ctx) = ctx {
                record_outcome(ctx, direction, OUTCOME_UNINSPECTED, None, None);
            }
            return PluginResult::Continue;
        }
        let (status_code, body, grpc_status, grpc_message) = match direction {
            Direction::Request => (
                response_budget::REQUEST_DECODE_OVERLOAD_STATUS,
                response_budget::REQUEST_DECODE_OVERLOAD_BODY,
                response_budget::REQUEST_DECODE_OVERLOAD_GRPC_STATUS,
                response_budget::REQUEST_DECODE_OVERLOAD_GRPC_MESSAGE,
            ),
            Direction::Response => (
                response_budget::RESPONSE_BUFFER_OVERLOAD_STATUS,
                response_budget::RESPONSE_BUFFER_OVERLOAD_BODY,
                response_budget::RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS,
                response_budget::RESPONSE_BUFFER_OVERLOAD_GRPC_MESSAGE,
            ),
        };
        warn_sampled!("body_validator: protobuf inspection refused: decode budget exhausted");
        if let Some(ctx) = ctx {
            record_outcome(
                ctx,
                direction,
                OUTCOME_CAPACITY_REFUSED,
                Some(status_code),
                None,
            );
            // Typed provenance so the response finalizer publishes this fixed
            // gateway terminal as written instead of re-deciding it.
            ctx.mark_gateway_capacity_response_selected();
        }
        let mut headers = HashMap::new();
        headers.insert("grpc-status".to_string(), grpc_status.to_string());
        headers.insert("grpc-message".to_string(), grpc_message.to_string());
        PluginResult::Reject {
            status_code,
            body: body.to_string(),
            headers,
        }
    }

    /// Whether the final request body is byte-identical (with the same
    /// `Content-Type`) to the representation this instance already validated
    /// and passed in `before_proxy`. Validation is a pure function of those two
    /// inputs, so re-running the parse and schema evaluation could only repeat
    /// the same answer. Any transform, relabel, or decode misses and is
    /// re-validated.
    fn final_request_body_matches_early_pass(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> bool {
        let Some(previous) = ctx
            .plugin_state()
            .and_then(|state| {
                state
                    .body_validator_early_request_digests
                    .get(&self.instance_id)
            })
            .copied()
        else {
            return false;
        };
        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");
        early_request_digest(content_type, body) == previous
    }

    /// Whether the configured final request-body rules would actually inspect
    /// this finalized representation.
    ///
    /// Mirrors the applicability ladder inside [`Self::evaluate_final_request_body`]
    /// exactly, so the shared request representation gate claims precisely the
    /// requests this plugin enforces on (`GHSA-3973-47g5-4mcx`).
    fn final_request_body_policy_applies(&self, headers: &HashMap<String, String>) -> bool {
        if !self.has_request_validation {
            return false;
        }
        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");
        if grpc_representation(content_type).is_some() {
            // gRPC carries its per-message compression in `grpc-encoding`, not
            // `Content-Encoding`, so this branch is never the one the gate
            // decodes for. Declining keeps framed bodies out of the gate.
            return false;
        }
        let has_json_validation = self.json_validator.is_some() || !self.required_fields.is_empty();
        if !has_json_validation && !self.has_xml_request_validation {
            return false;
        }
        if !content_type_matches(&self.content_types, content_type) {
            return false;
        }
        let validate_as_json = is_json_like_content_type(content_type);
        let validate_as_xml = !validate_as_json
            && is_xml_like_content_type(content_type)
            && self.has_xml_request_validation;
        validate_as_json || validate_as_xml
    }

    /// Whether the configured JSON/XML response rules would actually inspect this
    /// client-visible representation. The gRPC branch is excluded for the same
    /// reason as on the request side.
    fn final_response_body_policy_applies(&self, content_type: Option<&str>) -> bool {
        if !self.has_response_validation {
            return false;
        }
        let content_type = content_type.unwrap_or("");
        if grpc_representation(content_type).is_some() {
            return false;
        }
        if !self.has_json_response_validation() && !self.has_xml_response_validation {
            return false;
        }
        if !content_type_matches(&self.response_content_types, content_type) {
            return false;
        }
        let validate_as_json = is_json_like_content_type(content_type);
        let validate_as_xml = !validate_as_json
            && is_xml_like_content_type(content_type)
            && self.has_xml_response_validation;
        validate_as_json || validate_as_xml
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
            // jsonschema compares object members in insertion order for
            // `uniqueItems` when serde_json's workspace-wide `preserve_order`
            // feature is active. JSON object equality is order-insensitive, so
            // canonicalize only for schemas that actually use `uniqueItems`.
            // The flag is computed once by the schema-position audit; all other
            // validators retain the existing request-path cost.
            if schema.canonicalize_object_order {
                parsed.sort_all_objects();
            }
            if let Err(error) = schema.validator.validate(&parsed) {
                return Err(schema_violation_message(
                    &error,
                    direction,
                    &schema.safe_names,
                ));
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
    /// Three bounded pre-parse guards still run first because they encode policy
    /// the parser has no opinion on, or a limit it cannot enforce on itself: the
    /// configured `<!ENTITY` declaration cap / nested-entity rejection, outright
    /// rejection of external (`SYSTEM`/`PUBLIC`) identifiers on both the DOCTYPE
    /// and entity declarations, and the shared
    /// [`xml_nesting_depth_within_limit`] screen, a fixed nesting ceiling applied
    /// before any tree is allocated (`roxmltree` before 0.21.2 recursed once
    /// per nesting level inside the parser; see `xml_bounds`). The parser is
    /// then given a node budget so a pathologically wide document cannot
    /// allocate without bound.
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

        // Bound element nesting over the raw bytes before `roxmltree` sees
        // them. `roxmltree` 0.21.2+ parses element content iteratively, but
        // the screen stays the fixed depth ceiling for this path, so a parser
        // that recursed per level again could not overflow the worker stack
        // (a process kill under `panic = "abort"`). See `xml_bounds`.
        if !xml_nesting_depth_within_limit(body, XML_MAX_NESTING_DEPTH) {
            return Err(XML_DEPTH_DETAIL.to_string());
        }

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
                // No resolver: an external entity is never fetched or inlined.
                entity_resolver: None,
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

        for (idx, _) in required_xml_elements.iter().enumerate() {
            if !required_found[idx] {
                // Never echo a configured XML local name or Clark notation —
                // those are schema/payload constants (`GHSA-5p2h-fq6q-gwh9`).
                return Err("Missing required XML element".to_string());
            }
        }

        Ok(())
    }

    /// Validate a gRPC body in any supported framing against a message
    /// descriptor.
    ///
    /// Native gRPC is one length-prefixed frame. gRPC-Web (binary, or text-mode
    /// base64) is the same message frame optionally followed by one terminal
    /// trailer frame; a translated gRPC-Web response reaches the final
    /// client-visible phase in that representation, after `grpc_web` re-framed
    /// it, so it is validated here rather than being skipped as "not gRPC".
    ///
    /// Every byte of working set this decode allocates — the base64 output, the
    /// decompressed payload, the decoder's own heap, and the reflected message
    /// graph — is charged to `budget` before it is allocated and released when
    /// this returns (`plugins::charged_decode`).
    fn validate_grpc_representation(
        &self,
        body: &[u8],
        representation: GrpcRepresentation,
        descriptor: &MessageDescriptor,
        direction: Direction,
        response_headers: Option<&HashMap<String, String>>,
        budget: BudgetRef<'_>,
    ) -> Result<(), ProtobufFailure> {
        let mut reservation = ResponseBufferReservation::new();
        match representation {
            GrpcRepresentation::Native => {
                self.validate_protobuf_frame(body, descriptor, 0, &mut reservation, budget)
            }
            GrpcRepresentation::WebBinary => self.validate_grpc_web_frames(
                body,
                descriptor,
                direction,
                response_headers,
                0,
                &mut reservation,
                budget,
            ),
            GrpcRepresentation::WebText => {
                if body.is_empty() {
                    return self.validate_grpc_web_frames(
                        body,
                        descriptor,
                        direction,
                        response_headers,
                        0,
                        &mut reservation,
                        budget,
                    );
                }
                // Base64 output is at most three quarters of the input; charge it
                // before the decoder allocates it.
                let decoded_capacity = body.len() / 4 * 3;
                if !reservation.reserve_in(budget, decoded_capacity) {
                    return Err(ProtobufFailure::Capacity);
                }
                let decoded = super::grpc_web::decode_grpc_web_text_body(body)
                    .ok_or_else(|| "gRPC-Web text body is not valid base64".to_string())?;
                let resident = decoded.capacity();
                self.validate_grpc_web_frames(
                    &decoded,
                    descriptor,
                    direction,
                    response_headers,
                    resident,
                    &mut reservation,
                    budget,
                )
            }
        }
    }

    /// Validate a binary gRPC-Web frame sequence: at most one message frame
    /// (unary scope, as on native gRPC) followed by at most one terminal
    /// trailer frame.
    #[allow(clippy::too_many_arguments)]
    fn validate_grpc_web_frames(
        &self,
        data: &[u8],
        descriptor: &MessageDescriptor,
        direction: Direction,
        response_headers: Option<&HashMap<String, String>>,
        concurrent_bytes: usize,
        reservation: &mut ResponseBufferReservation,
        budget: BudgetRef<'_>,
    ) -> Result<(), ProtobufFailure> {
        let (message, trailer) = split_grpc_web_frames(data)?;
        match message {
            Some(frame) => self.validate_protobuf_frame(
                frame,
                descriptor,
                concurrent_bytes,
                reservation,
                budget,
            ),
            None => {
                // A gRPC-Web terminal ERROR legitimately carries only the
                // trailer frame (or, with no body at all, the merged header
                // view). Status OK, a missing status, and ambiguous statuses
                // still require a message frame — exactly the native rule.
                let terminal_error = match trailer {
                    Some(block) => grpc_web_trailer_is_terminal_error(block),
                    None => response_headers.is_some_and(grpc_empty_response_is_terminal_error),
                };
                if direction == Direction::Response && terminal_error {
                    Ok(())
                } else {
                    Err("gRPC-Web body carries no message frame".to_string().into())
                }
            }
        }
    }

    /// Validate one native gRPC length-prefixed frame against a message
    /// descriptor.
    ///
    /// The body uses gRPC length-prefixed framing: 1 byte compressed flag + 4
    /// bytes big-endian u32 message length + protobuf payload bytes.
    ///
    /// The decode is bounded BEFORE reflection: a descriptor-aware wire
    /// preflight charges every message and field value against the fixed
    /// inspection budgets and the 32-level depth bound, for every pool and
    /// policy, so a small (possibly compressed) frame cannot materialize an
    /// unbounded reflected graph before any limit is consulted. The reflected
    /// working set the preflight measured is then reserved against the
    /// aggregate decode budget, alongside the decompressed payload, before
    /// `DynamicMessage::decode` allocates it.
    fn validate_protobuf_frame(
        &self,
        frame: &[u8],
        descriptor: &MessageDescriptor,
        concurrent_bytes: usize,
        reservation: &mut ResponseBufferReservation,
        budget: BudgetRef<'_>,
    ) -> Result<(), ProtobufFailure> {
        let payload = parse_grpc_frame_charged(
            frame,
            self.grpc_max_decompressed_size_bytes,
            concurrent_bytes,
            reservation,
            budget,
        )?;

        let policy = ProtobufMessagePolicy {
            check_required: self.protobuf_pool_has_proto2,
            reject_unknown: self.protobuf_reject_unknown_fields,
        };
        let mut preflight = ProtobufDecodePreflight::default();
        if let Err(error) = preflight.charge_message() {
            return Err(error.into_failure());
        }
        if let Err(error) =
            preflight_protobuf_fields(&payload, Some(descriptor), None, 0, &mut preflight, policy)
        {
            return Err(error.into_failure());
        }

        let decompressed_resident = match &payload {
            Cow::Owned(buffer) => buffer.capacity(),
            Cow::Borrowed(_) => 0,
        };
        // An undeclared closed-enum occurrence (permitted: strict mode already
        // refused it above) is stripped from a separate inspection copy so the
        // decoded tree has conforming proto2 merge/oneof/initialization
        // semantics. That copy and its per-level buffers hold at most twice the
        // payload.
        let strip_closed_enums = preflight.undeclared_closed_enum;
        let inspection_copy_bound = if strip_closed_enums {
            payload.len().saturating_mul(2)
        } else {
            0
        };
        // String and bytes values are copied out of the payload, so the
        // payload length bounds them; messages and values are charged at a
        // conservative per-node cost.
        let working_set = concurrent_bytes
            .saturating_add(decompressed_resident)
            .saturating_add(payload.len())
            .saturating_add(inspection_copy_bound)
            .saturating_add(preflight.reflected_bytes());
        if !reservation.reserve_in(budget, working_set) {
            return Err(ProtobufFailure::Capacity);
        }
        let inspection_copy = if strip_closed_enums {
            let mut stripped = Vec::with_capacity(payload.len());
            if let Err(error) =
                strip_undeclared_closed_enums(&payload, Some(descriptor), None, &mut stripped)
            {
                return Err(error.into_failure());
            }
            Some(stripped)
        } else {
            None
        };
        let decode_input: &[u8] = inspection_copy.as_deref().unwrap_or(payload.as_ref());

        // The `prost` decode error is not reproduced: its rendering is not part
        // of a stability contract Ferrum controls, so it is not a surface this
        // gateway can promise stays free of payload bytes
        // (`GHSA-5p2h-fq6q-gwh9`). The failure class alone is what a caller or
        // operator can act on.
        let msg = DynamicMessage::decode(descriptor.clone(), decode_input)
            .map_err(|_| PROTOBUF_DECODE_FAILED_DETAIL.to_string())?;
        // Two independent message policies share one bounded descriptor walk.
        //
        // Wire decoding does not enforce proto2 initialization, so a correctly
        // framed message that omits a `required` field decodes cleanly
        // (GHSA-qvrp-m3v9-345m). A closed (proto2) enum field carrying an
        // undeclared number is, to a conforming reader, an UNKNOWN field: the
        // preflight refuses it in strict mode, and the inspection copy decoded
        // above leaves it out, so it can neither satisfy `required` nor
        // overwrite a declared value or a oneof selection.
        //
        // `DynamicMessage::unknown_fields()` is message-LOCAL, so checking only
        // the decoded outer message left unknown fields inside nested,
        // repeated, map-value, oneof, and extension messages unexamined even
        // though `protobuf_reject_unknown_fields` is documented as a strict
        // schema policy (`GHSA-cqmm-vj3c-g8w8`).
        if policy.is_active() {
            let mut walk_budget = ProtobufWalkBudget::default();
            check_protobuf_message(&msg, policy, &mut walk_budget)?;
        }
        Ok(())
    }

    /// Request-side gRPC protobuf validation of `body` in the framing named by
    /// `content_type`, against an explicitly bound aggregate budget, reduced to
    /// a fixed outcome label.
    #[allow(dead_code)] // reached via `_test_support` from the external test crate
    pub(crate) fn protobuf_request_outcome_in(
        &self,
        grpc_path: &str,
        content_type: &str,
        body: &[u8],
        budget: BudgetRef<'_>,
    ) -> &'static str {
        let Some(representation) = grpc_representation(content_type) else {
            return "unconfigured";
        };
        let Some(descriptor) = self.get_request_descriptor(canonical_grpc_method(grpc_path)) else {
            return "unconfigured";
        };
        match self.validate_grpc_representation(
            body,
            representation,
            descriptor,
            Direction::Request,
            None,
            budget,
        ) {
            Ok(()) => "pass",
            Err(ProtobufFailure::Invalid(_)) => "invalid",
            Err(ProtobufFailure::Capacity) => "capacity",
        }
    }

    /// Look up the request message descriptor for a given gRPC path.
    ///
    /// A `protobuf_method_messages` entry is direction-authoritative: when the
    /// method has an entry, a direction the entry omits is not validated,
    /// rather than falling back to the default type.
    fn get_request_descriptor(&self, grpc_path: &str) -> Option<&MessageDescriptor> {
        match self.protobuf_method_messages.get(grpc_path) {
            Some(entry) => entry.request.as_ref(),
            None => self.protobuf_request_descriptor.as_ref(),
        }
    }

    /// Look up the response message descriptor for a given gRPC path, with the
    /// same direction-authoritative entry rule as the request side.
    fn get_response_descriptor(&self, grpc_path: &str) -> Option<&MessageDescriptor> {
        match self.protobuf_method_messages.get(grpc_path) {
            Some(entry) => entry.response.as_ref(),
            None => self.protobuf_response_descriptor.as_ref(),
        }
    }

    /// Whether JSON response validation rules are configured.
    fn has_json_response_validation(&self) -> bool {
        self.response_json_validator.is_some() || !self.response_required_fields.is_empty()
    }

    /// Resolve the gRPC method a request/response belongs to from the request
    /// context, as the canonical `/Service/Method` key.
    ///
    /// The backend-effective path the gateway bound after route policy
    /// (`authorized_backend_path`, private and not plugin-writable) wins when
    /// present; then `grpc_full_method` set by `grpc_method_router`; then
    /// `ctx.path`, onto which a route-override rewrite is mirrored. Whatever the
    /// source, only the trailing `/Service/Method` is the method key, so a
    /// prefix that does not touch the service segment cannot change the entry.
    /// A prefix REPLACEMENT can (`/v1.Greeter` stripped, `/v2.Greeter`
    /// prepended), which is why method-scoped configurations opt into
    /// backend-path resolution and the bound path wins. Backends never echo
    /// `:path` in responses.
    fn grpc_method_path(ctx: &RequestContext) -> Cow<'_, str> {
        if let Some(path) = ctx.authorized_backend_path() {
            return Cow::Borrowed(canonical_grpc_method(path));
        }
        match ctx.metadata.get("grpc_full_method") {
            Some(method) if method.starts_with('/') => {
                Cow::Borrowed(canonical_grpc_method(method.as_str()))
            }
            Some(method) => {
                let mut path = String::with_capacity(method.len() + 1);
                path.push('/');
                path.push_str(method);
                if canonical_grpc_method(&path).len() == path.len() {
                    Cow::Owned(path)
                } else {
                    Cow::Owned(canonical_grpc_method(&path).to_string())
                }
            }
            None => Cow::Borrowed(canonical_grpc_method(ctx.path.as_str())),
        }
    }

    /// Whether protobuf response validation applies to this request/response.
    fn applicable_protobuf_response_validation(&self, ctx: &RequestContext) -> bool {
        self.has_protobuf_response_validation
            && self
                .protobuf_targets
                .response_applies(&Self::grpc_method_path(ctx))
    }

    /// Whether protobuf request validation may apply to this request.
    ///
    /// Used by the buffering vote, which runs before the route-override path
    /// rewrite is mirrored onto `ctx.path`, so the pending rewrite is
    /// considered too: the vote must never be narrower than the method the
    /// final hook will select, or an enrolled method would stream past it.
    fn protobuf_request_may_apply(&self, ctx: &RequestContext) -> bool {
        self.protobuf_targets
            .request_applies(&Self::grpc_method_path(ctx))
            || ctx.route_override_path.as_deref().is_some_and(|path| {
                self.protobuf_targets
                    .request_applies(canonical_grpc_method(path))
            })
    }

    /// Whether this exchange's upstream status selects response validation:
    /// inside `response_status_codes`, and not a partial (`206`) or delta
    /// (`226`) fragment, which is not a complete document a schema can judge.
    fn response_status_validated(&self, ctx: &RequestContext, response_status: u16) -> bool {
        self.response_status_scope.contains(response_status)
            && !response_is_fragment(ctx, response_status)
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
        if grpc_representation(content_type).is_some() {
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

/// Default maximum decompressed size for a gRPC frame (10 MB). Prevents compression-bomb
/// DoS — without a cap, a tiny compressed payload can inflate into gigabytes and OOM
/// the process.
const DEFAULT_MAX_GRPC_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;

/// Hard ceiling on the resolved gRPC decompression limit. Compressed frames
/// inflate into a growing buffer bounded only by this value, and the shared
/// request-representation decode gate does not cover native gRPC, so an
/// arbitrary 64-bit configuration (or environment-inherited default) would
/// leave a small compressed frame effectively unbounded.
const MAX_GRPC_DECOMPRESSED_SIZE_CEILING: usize = 64 * 1024 * 1024;

/// Parse one gRPC length-prefixed frame and return the protobuf payload bytes.
///
/// Frame format: [1 byte compressed flag] [4 bytes big-endian u32 length] [payload]
///
/// Supports unary RPCs only (single frame per message). For streaming RPCs the
/// body may contain multiple concatenated frames — the exact-length check
/// rejects the trailing data.
///
/// When the compressed flag is set (byte 0 == 1), the payload is decompressed
/// as gzip, the standard gRPC compression algorithm, through the shared strict,
/// budget-charged decoder ([`super::charged_decode::decode_one_coding`]): the
/// decoder's heap and every growth of the output are reserved against `budget`
/// BEFORE they are allocated, the output is capped at
/// `max_decompressed_size_bytes`, and the payload must be exactly one fully
/// consumed gzip member (a multistream peer would also decode a concatenated
/// member this validator never inspected, while the original frame is
/// forwarded unchanged). Other compression algorithms are not supported.
fn parse_grpc_frame_charged<'a>(
    body: &'a [u8],
    max_decompressed_size_bytes: usize,
    concurrent_bytes: usize,
    reservation: &mut ResponseBufferReservation,
    budget: BudgetRef<'_>,
) -> Result<Cow<'a, [u8]>, ProtobufFailure> {
    if max_decompressed_size_bytes == 0 {
        return Err("gRPC decompressed size limit must be greater than zero"
            .to_string()
            .into());
    }
    if body.len() < 5 {
        return Err(format!("gRPC frame too short: {} bytes (minimum 5)", body.len()).into());
    }
    let compressed = body[0];
    let msg_len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    let payload = &body[5..];
    if payload.len() != msg_len {
        return Err(format!(
            "gRPC frame length mismatch: header says {} bytes but payload is {} bytes",
            msg_len,
            payload.len()
        )
        .into());
    }
    if compressed > 1 {
        // The gRPC wire format defines only 0 (identity) and 1 (compressed
        // with the `grpc-encoding` codec); any other flag is malformed.
        return Err(format!("gRPC frame has invalid compressed flag {compressed}").into());
    }
    if compressed == 0 {
        return Ok(Cow::Borrowed(payload));
    }
    use super::charged_decode::{ChargedDecodeError, decode_one_coding};
    match decode_one_coding(
        "gzip",
        payload,
        max_decompressed_size_bytes,
        concurrent_bytes,
        reservation,
        budget,
    ) {
        Ok(decompressed) => Ok(Cow::Owned(decompressed)),
        Err(ChargedDecodeError::TooLarge) => Err(format!(
            "gRPC decompressed body exceeds max size of {max_decompressed_size_bytes} bytes"
        )
        .into()),
        Err(ChargedDecodeError::CapacityRefused) => Err(ProtobufFailure::Capacity),
        Err(ChargedDecodeError::Unsupported | ChargedDecodeError::Malformed) => Err(
            "Failed to decompress gRPC frame (gzip): malformed, truncated, trailing, or \
             concatenated gzip data"
                .to_string()
                .into(),
        ),
    }
}

/// gRPC framing of a body, decided by its media-type essence.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GrpcRepresentation {
    /// `application/grpc[+fmt]`: one length-prefixed message frame.
    Native,
    /// `application/grpc-web[+fmt]`: message frame, optional trailer frame.
    WebBinary,
    /// `application/grpc-web-text[+fmt]`: base64 of the binary framing.
    WebText,
}

fn grpc_representation(content_type: &str) -> Option<GrpcRepresentation> {
    let media_type = media_type_essence(content_type)?;
    let matches_family = |base: &str| {
        media_type.eq_ignore_ascii_case(base)
            || (media_type.len() > base.len() + 1
                && ascii_starts_with_ignore_case(media_type, base)
                && media_type.as_bytes()[base.len()] == b'+')
    };
    if matches_family("application/grpc") {
        Some(GrpcRepresentation::Native)
    } else if matches_family("application/grpc-web-text") {
        Some(GrpcRepresentation::WebText)
    } else if matches_family("application/grpc-web") {
        Some(GrpcRepresentation::WebBinary)
    } else {
        None
    }
}

/// The gRPC method path a final request body belongs to.
///
/// The native H1/H2 gRPC ladder injects a synthetic `:path` into the hook
/// headers; when it is absent (HTTP/3, the H3 bridge, generic dispatch) the
/// request context names the method instead, so a per-method rule cannot
/// silently stop applying on those dispatchers. Only the context-free
/// compatibility hook has neither, and it then matches only a default type.
fn request_grpc_method_path<'a>(
    headers: &'a HashMap<String, String>,
    ctx: Option<&'a RequestContext>,
) -> Cow<'a, str> {
    // The bound backend-effective path is authoritative; a synthetic `:path`
    // (the local, possibly unstripped request path) never outranks it.
    if let Some(path) = ctx.and_then(RequestContext::authorized_backend_path) {
        return Cow::Borrowed(canonical_grpc_method(path));
    }
    if let Some(path) = headers.get(":path") {
        return Cow::Borrowed(canonical_grpc_method(path.as_str()));
    }
    match ctx {
        Some(ctx) => BodyValidator::grpc_method_path(ctx),
        None => Cow::Borrowed(""),
    }
}

/// The canonical gRPC method key of a request path: its trailing
/// `/Service/Method` (query and fragment excluded). A gRPC method is always the
/// last two path segments, so a listen-path prefix, a stripped prefix, or a
/// backend base path cannot make the same method select a different
/// `protobuf_method_messages` entry.
fn canonical_grpc_method(path: &str) -> &str {
    let end = path.find(['?', '#']).unwrap_or(path.len());
    let path = &path[..end];
    let Some(last) = path.rfind('/') else {
        return path;
    };
    match path[..last].rfind('/') {
        Some(start) => &path[start..],
        None => path,
    }
}

/// Whether a response is a range slice (`206`) or a delta (`226`) of the
/// selected representation rather than a complete document. The pristine
/// fragment stamp recorded before `after_proxy` covers a status or
/// `Content-Range` an earlier hook rewrote.
fn response_is_fragment(ctx: &RequestContext, response_status: u16) -> bool {
    response_status == 206
        || response_status == 226
        || ctx
            .metadata
            .contains_key(crate::proxy::ORIGIN_FRAGMENT_RESPONSE_METADATA_KEY)
}

/// Publish one validation outcome under the fixed per-direction metadata keys.
fn record_outcome(
    ctx: &mut RequestContext,
    direction: Direction,
    outcome: &'static str,
    status: Option<u16>,
    detail: Option<&str>,
) {
    let (outcome_key, status_key, detail_key) = match direction {
        Direction::Request => (
            BODY_VALIDATOR_REQUEST_OUTCOME_KEY,
            BODY_VALIDATOR_REQUEST_STATUS_KEY,
            BODY_VALIDATOR_REQUEST_DETAIL_KEY,
        ),
        Direction::Response => (
            BODY_VALIDATOR_RESPONSE_OUTCOME_KEY,
            BODY_VALIDATOR_RESPONSE_STATUS_KEY,
            BODY_VALIDATOR_RESPONSE_DETAIL_KEY,
        ),
    };
    ctx.metadata
        .insert(outcome_key.to_string(), outcome.to_string());
    match status {
        Some(status) => {
            ctx.metadata
                .insert(status_key.to_string(), status.to_string());
        }
        None => {
            ctx.metadata.remove(status_key);
        }
    }
    match detail {
        Some(detail) => {
            ctx.metadata
                .insert(detail_key.to_string(), detail.to_string());
        }
        None => {
            ctx.metadata.remove(detail_key);
        }
    }
}

/// SHA-256 over the `Content-Type` and body a request-side verdict was reached
/// for. Used only to recognize the byte-identical representation again in the
/// final hook; never logged, exported, or compared against peer input. SHA-256
/// rather than a fast hash because a collision would let a transformed body
/// reuse the earlier pass.
fn early_request_digest(content_type: &str, body: &[u8]) -> [u8; 32] {
    let mut hasher = crate::fips::approved::Sha256::new();
    hasher.update(content_type.as_bytes());
    hasher.update([0u8]);
    hasher.update(body);
    hasher.finalize()
}

/// Whether the request headers alone already answer "is there a body?".
fn request_headers_declare_body_framing(headers: &HashMap<String, String>) -> bool {
    headers.contains_key("content-length") || headers.contains_key("transfer-encoding")
}

/// A `CONNECT` request (including HTTP/2 extended CONNECT and mesh HBONE) or a
/// transport-classified WebSocket handshake opens a tunnel; what follows is not
/// a request body this plugin governs, so strict media-type admission does not
/// apply to it. Decided from trusted request state (the request line and the
/// frontend's own flavor classification), never from a client-supplied
/// `Upgrade` header, which an ordinary upload can carry.
fn request_opens_tunnel(ctx: &RequestContext) -> bool {
    ctx.method.eq_ignore_ascii_case("CONNECT")
        || ctx.is_hbone_connect_relay()
        || matches!(
            ctx.request_http_flavor(),
            crate::config::types::HttpFlavor::WebSocket
        )
}

/// Whether a request ungoverned by any configured rule carries a body, for
/// `reject_unsupported_media_types`. Headers decide when they can
/// (`Content-Length`, `Transfer-Encoding`); otherwise the buffered
/// representation the strict vote requested, or the transport's empty proof,
/// does. A representation that cannot be shown empty counts as a body.
fn ungoverned_request_carries_body(
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
) -> bool {
    if request_opens_tunnel(ctx) {
        return false;
    }
    if let Some(length) = headers.get("content-length") {
        // Only a well-formed zero proves there is none; anything else,
        // including a malformed or comma-joined value, counts as a body.
        return !matches!(length.trim().parse::<u64>(), Ok(0));
    }
    if headers.contains_key("transfer-encoding") {
        return true;
    }
    if let Some(text) = ctx.metadata.get("request_body") {
        return !text.is_empty();
    }
    if let Some(bytes) = ctx.request_body_bytes.as_deref() {
        return !bytes.is_empty();
    }
    !ctx.replay_request_body_empty_proven()
}

/// The single message frame (header included) and the trailer-frame payload of
/// a binary gRPC-Web body.
type GrpcWebFrames<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);

/// Split a binary gRPC-Web frame sequence into its single message frame
/// (header included) and its terminal trailer-frame payload.
///
/// More than one message frame is the unary-scope rejection native gRPC
/// already applies; a trailer frame that is not last, a compressed trailer
/// frame, an unknown flag, and truncated framing are malformed.
fn split_grpc_web_frames(data: &[u8]) -> Result<GrpcWebFrames<'_>, String> {
    let mut message: Option<&[u8]> = None;
    let mut trailer: Option<&[u8]> = None;
    let mut pos = 0usize;
    while pos < data.len() {
        if trailer.is_some() {
            return Err("gRPC-Web frame follows the trailer frame".to_string());
        }
        if data.len() - pos < 5 {
            return Err(format!(
                "gRPC frame too short: {} bytes (minimum 5)",
                data.len() - pos
            ));
        }
        let flag = data[pos];
        let declared =
            u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]);
        let end = usize::try_from(declared)
            .ok()
            .and_then(|length| (pos + 5).checked_add(length))
            .filter(|end| *end <= data.len())
            .ok_or_else(|| "gRPC-Web frame length exceeds the body".to_string())?;
        match flag {
            0x00 | 0x01 => {
                if message.is_some() {
                    return Err(
                        "gRPC body carries more than one message frame (unary only)".to_string()
                    );
                }
                message = Some(&data[pos..end]);
            }
            0x80 => trailer = Some(&data[pos + 5..end]),
            _ => return Err("gRPC-Web frame has an invalid flag".to_string()),
        }
        pos = end;
    }
    Ok((message, trailer))
}

/// `true` when a gRPC-Web trailer block carries one unambiguous non-zero
/// terminal `grpc-status` (the same rule as
/// [`grpc_empty_response_is_terminal_error`]).
fn grpc_web_trailer_is_terminal_error(block: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(block) else {
        return false;
    };
    let mut status: Option<&str> = None;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        if name.trim().eq_ignore_ascii_case("grpc-status") {
            if status.is_some() {
                return false;
            }
            status = Some(value.trim());
        }
    }
    status
        .and_then(|value| value.parse::<u32>().ok())
        .is_some_and(|code| (1..=16).contains(&code))
}

/// Fixed diagnostic for a protobuf payload the wire preflight or the reflection
/// decoder rejected.
const PROTOBUF_DECODE_FAILED_DETAIL: &str = "Protobuf decode failed";

/// Maximum number of field values (scalar elements included) one decoded
/// message tree may carry. Every value becomes a reflected node, so this bounds
/// the graph `DynamicMessage::decode` materializes independently of the byte
/// size of the payload that encodes it.
const MAX_PROTOBUF_VALUES: usize = 1 << 20;

/// Conservative reflected-graph cost of one decoded message (descriptor handle
/// plus its field map), charged to the aggregate decode budget.
const PROTOBUF_REFLECTED_MESSAGE_BYTES: usize = 256;

/// Conservative reflected-graph cost of one decoded field value.
const PROTOBUF_REFLECTED_VALUE_BYTES: usize = 64;

/// Counts the descriptor-aware wire preflight charges before reflection.
#[derive(Default)]
struct ProtobufDecodePreflight {
    messages: usize,
    values: usize,
    /// Whether any closed (proto2) enum occurrence carried an undeclared
    /// number. The decoder would install it as an ordinary value; a conforming
    /// reader moves it to the unknown-field set instead.
    undeclared_closed_enum: bool,
}

/// Why the wire preflight refused a payload.
enum PreflightError {
    Malformed,
    Budget,
    Depth,
    /// A closed-enum occurrence outside the declared set under
    /// `protobuf_reject_unknown_fields`: an unknown field to a conforming
    /// proto2 reader.
    UnknownClosedEnum,
}

impl PreflightError {
    fn into_failure(self) -> ProtobufFailure {
        let detail = match self {
            Self::Malformed => PROTOBUF_DECODE_FAILED_DETAIL,
            Self::Budget => PROTOBUF_BUDGET_DETAIL,
            Self::Depth => PROTOBUF_DEPTH_DETAIL,
            Self::UnknownClosedEnum => "Message contains 1 unknown field(s)",
        };
        ProtobufFailure::Invalid(detail.to_string())
    }
}

impl ProtobufDecodePreflight {
    fn charge_message(&mut self) -> Result<(), PreflightError> {
        self.messages += 1;
        if self.messages > MAX_PROTOBUF_MESSAGES {
            return Err(PreflightError::Budget);
        }
        Ok(())
    }

    fn charge_values(&mut self, count: usize) -> Result<(), PreflightError> {
        self.values = self.values.saturating_add(count);
        if self.values > MAX_PROTOBUF_VALUES {
            return Err(PreflightError::Budget);
        }
        Ok(())
    }

    fn reflected_bytes(&self) -> usize {
        self.messages
            .saturating_mul(PROTOBUF_REFLECTED_MESSAGE_BYTES)
            .saturating_add(self.values.saturating_mul(PROTOBUF_REFLECTED_VALUE_BYTES))
    }
}

/// How a field number is shaped on the wire, from the descriptor.
enum WireFieldShape {
    /// A message (or group, or map entry) value: its payload is a nested
    /// message the decoder reflects.
    Message(MessageDescriptor),
    /// A repeated numeric field whose length-delimited form is packed.
    Packed(PackedWidth),
    /// A CLOSED (proto2) enum field. Each wire occurrence is judged on its own:
    /// a conforming reader puts an undeclared number in the unknown-field set
    /// and keeps any earlier declared value, while the reflection decoder simply
    /// overwrites the field with the last number it read.
    ClosedEnum {
        enum_type: EnumDescriptor,
        repeated: bool,
    },
    /// Anything else: one value per occurrence.
    Other,
}

#[derive(Clone, Copy)]
enum PackedWidth {
    Varint,
    Fixed32,
    Fixed64,
}

fn wire_field_shape(descriptor: &MessageDescriptor, number: u32) -> WireFieldShape {
    let (kind, is_list) = if let Some(field) = descriptor.get_field(number) {
        (field.kind(), field.is_list())
    } else if let Some(extension) = descriptor.get_extension(number) {
        (extension.kind(), extension.is_list())
    } else {
        return WireFieldShape::Other;
    };
    match kind {
        Kind::Message(message) => WireFieldShape::Message(message),
        Kind::Enum(enum_type) if enum_is_closed(&enum_type) => WireFieldShape::ClosedEnum {
            enum_type,
            repeated: is_list,
        },
        _ if !is_list => WireFieldShape::Other,
        Kind::Double | Kind::Fixed64 | Kind::Sfixed64 => {
            WireFieldShape::Packed(PackedWidth::Fixed64)
        }
        Kind::Float | Kind::Fixed32 | Kind::Sfixed32 => {
            WireFieldShape::Packed(PackedWidth::Fixed32)
        }
        Kind::Int32
        | Kind::Int64
        | Kind::Uint32
        | Kind::Uint64
        | Kind::Sint32
        | Kind::Sint64
        | Kind::Bool
        | Kind::Enum(_) => WireFieldShape::Packed(PackedWidth::Varint),
        Kind::String | Kind::Bytes => WireFieldShape::Other,
    }
}

fn read_wire_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for index in 0..10u32 {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        // The tenth byte may contribute only the 64th bit.
        if index == 9 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn take_wire_bytes<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = pos.checked_add(len)?;
    let bytes = buf.get(*pos..end)?;
    *pos = end;
    Some(bytes)
}

/// Descriptor-aware wire preflight: walk the encoded message without
/// allocating, charging every message and every field value (each packed
/// element included) against the inspection budgets and the nesting depth.
///
/// It runs for every pool and policy before `DynamicMessage::decode`, so the
/// reflected graph is bounded before it exists — a post-decode walk can only
/// observe allocations that already happened, and used to be skipped entirely
/// for a proto3-only pool with default unknown-field handling. It is never
/// stricter than the decoder about well-formed input: anything it calls
/// malformed the decoder rejects too.
///
/// `end_group` is `Some(field)` while scanning a group's contents. Returns the
/// number of bytes consumed (the whole buffer for a message body; through the
/// matching end-group tag for a group).
fn preflight_protobuf_fields(
    buf: &[u8],
    descriptor: Option<&MessageDescriptor>,
    end_group: Option<u32>,
    depth: usize,
    budget: &mut ProtobufDecodePreflight,
    policy: ProtobufMessagePolicy,
) -> Result<usize, PreflightError> {
    if depth > MAX_PROTOBUF_MESSAGE_DEPTH {
        return Err(PreflightError::Depth);
    }
    let mut pos = 0usize;
    while pos < buf.len() {
        let key = read_wire_varint(buf, &mut pos).ok_or(PreflightError::Malformed)?;
        let wire_type = key & 0x7;
        let number = u32::try_from(key >> 3).map_err(|_| PreflightError::Malformed)?;
        if number == 0 {
            return Err(PreflightError::Malformed);
        }
        if wire_type == 4 {
            return if end_group == Some(number) {
                Ok(pos)
            } else {
                Err(PreflightError::Malformed)
            };
        }
        budget.charge_values(1)?;
        let shape = match descriptor {
            Some(descriptor) => wire_field_shape(descriptor, number),
            None => WireFieldShape::Other,
        };
        match wire_type {
            0 => {
                let value = read_wire_varint(buf, &mut pos).ok_or(PreflightError::Malformed)?;
                if let WireFieldShape::ClosedEnum { enum_type, .. } = &shape
                    && !closed_enum_value_is_declared(enum_type, value)
                {
                    if policy.reject_unknown {
                        return Err(PreflightError::UnknownClosedEnum);
                    }
                    budget.undeclared_closed_enum = true;
                }
            }
            1 => {
                take_wire_bytes(buf, &mut pos, 8).ok_or(PreflightError::Malformed)?;
            }
            5 => {
                take_wire_bytes(buf, &mut pos, 4).ok_or(PreflightError::Malformed)?;
            }
            2 => {
                let len = read_wire_varint(buf, &mut pos)
                    .and_then(|len| usize::try_from(len).ok())
                    .ok_or(PreflightError::Malformed)?;
                let payload =
                    take_wire_bytes(buf, &mut pos, len).ok_or(PreflightError::Malformed)?;
                match shape {
                    WireFieldShape::Message(nested) if nested.is_map_entry() => {
                        // A map entry is not a reflected message of its own
                        // (its key and value land in the parent's map), so it
                        // adds no nesting level; its value message does. The
                        // decoder materializes a DEFAULT value message for every
                        // entry even when the value field is omitted on the
                        // wire, so that message is charged here, once per
                        // entry, and not again for an explicit value.
                        if matches!(nested.map_entry_value_field().kind(), Kind::Message(_)) {
                            budget.charge_message()?;
                        }
                        preflight_protobuf_fields(
                            payload,
                            Some(&nested),
                            None,
                            depth,
                            budget,
                            policy,
                        )?;
                    }
                    WireFieldShape::Message(nested) => {
                        let charged_by_map_entry = number == MAP_ENTRY_VALUE_FIELD
                            && descriptor.is_some_and(MessageDescriptor::is_map_entry);
                        if !charged_by_map_entry {
                            budget.charge_message()?;
                        }
                        preflight_protobuf_fields(
                            payload,
                            Some(&nested),
                            None,
                            depth + 1,
                            budget,
                            policy,
                        )?;
                    }
                    WireFieldShape::ClosedEnum {
                        enum_type,
                        repeated: true,
                        ..
                    } => {
                        // Packed closed-enum list: every element is its own
                        // occurrence.
                        let mut element = 0usize;
                        let mut elements = 0usize;
                        while element < payload.len() {
                            let value = read_wire_varint(payload, &mut element)
                                .ok_or(PreflightError::Malformed)?;
                            elements += 1;
                            if !closed_enum_value_is_declared(&enum_type, value) {
                                if policy.reject_unknown {
                                    return Err(PreflightError::UnknownClosedEnum);
                                }
                                budget.undeclared_closed_enum = true;
                            }
                        }
                        budget.charge_values(elements)?;
                    }
                    WireFieldShape::Packed(width) => {
                        let elements = match width {
                            PackedWidth::Varint => {
                                payload.iter().filter(|byte| **byte & 0x80 == 0).count()
                            }
                            PackedWidth::Fixed32 => payload.len() / 4,
                            PackedWidth::Fixed64 => payload.len() / 8,
                        };
                        budget.charge_values(elements)?;
                    }
                    WireFieldShape::ClosedEnum { .. } | WireFieldShape::Other => {}
                }
            }
            3 => {
                // A group: a declared group field's message, or an unknown
                // group whose nested fields the decoder retains as unknown
                // field sets. Both are charged as one nesting level.
                budget.charge_message()?;
                let nested = match shape {
                    WireFieldShape::Message(nested) => Some(nested),
                    _ => None,
                };
                let consumed = preflight_protobuf_fields(
                    &buf[pos..],
                    nested.as_ref(),
                    Some(number),
                    depth + 1,
                    budget,
                    policy,
                )?;
                pos += consumed;
            }
            _ => return Err(PreflightError::Malformed),
        }
    }
    if end_group.is_some() {
        // A group opened in this buffer never closed.
        return Err(PreflightError::Malformed);
    }
    Ok(pos)
}

/// A map entry's value field number (`MapEntry.value = 2`).
const MAP_ENTRY_VALUE_FIELD: u32 = 2;

/// Whether a wire varint is a declared number of a closed enum. Enum numbers
/// are `int32` on the wire (negative numbers are sign-extended to ten bytes),
/// so the truncation matches the decoder's own `int32` read.
fn closed_enum_value_is_declared(enum_type: &EnumDescriptor, value: u64) -> bool {
    enum_type.get_value(value as i32).is_some()
}

/// Re-encode an already preflighted message with every undeclared closed-enum
/// occurrence removed: the inspection representation a conforming proto2
/// reader would build, where such a number goes to the unknown-field set and
/// never becomes (or overwrites, or selects in a oneof) the field's value.
///
/// Decoding THAT with the reflection decoder makes ordinary merge, last-wins,
/// and oneof semantics — and therefore the post-decode `required` walk —
/// conform, including across merged submessage occurrences. Only the
/// inspection copy is rewritten; the backend still receives the original
/// bytes. Bytes are only ever removed, so the output is never larger than the
/// input, and every nested level's buffer holds a disjoint slice of it. The
/// preflight already validated the framing and bounded the depth, so the same
/// grammar errors are reported as malformed here.
fn strip_undeclared_closed_enums(
    buf: &[u8],
    descriptor: Option<&MessageDescriptor>,
    end_group: Option<u32>,
    out: &mut Vec<u8>,
) -> Result<usize, PreflightError> {
    let mut pos = 0usize;
    while pos < buf.len() {
        let field_start = pos;
        let key = read_wire_varint(buf, &mut pos).ok_or(PreflightError::Malformed)?;
        let wire_type = key & 0x7;
        let number = u32::try_from(key >> 3).map_err(|_| PreflightError::Malformed)?;
        if wire_type == 4 {
            return if end_group == Some(number) {
                out.extend_from_slice(&buf[field_start..pos]);
                Ok(pos)
            } else {
                Err(PreflightError::Malformed)
            };
        }
        let shape = match descriptor {
            Some(descriptor) => wire_field_shape(descriptor, number),
            None => WireFieldShape::Other,
        };
        match wire_type {
            0 => {
                let value = read_wire_varint(buf, &mut pos).ok_or(PreflightError::Malformed)?;
                let undeclared = matches!(
                    &shape,
                    WireFieldShape::ClosedEnum { enum_type, .. }
                        if !closed_enum_value_is_declared(enum_type, value)
                );
                if !undeclared {
                    out.extend_from_slice(&buf[field_start..pos]);
                }
            }
            1 => {
                take_wire_bytes(buf, &mut pos, 8).ok_or(PreflightError::Malformed)?;
                out.extend_from_slice(&buf[field_start..pos]);
            }
            5 => {
                take_wire_bytes(buf, &mut pos, 4).ok_or(PreflightError::Malformed)?;
                out.extend_from_slice(&buf[field_start..pos]);
            }
            2 => {
                let tag_end = pos;
                let len = read_wire_varint(buf, &mut pos)
                    .and_then(|len| usize::try_from(len).ok())
                    .ok_or(PreflightError::Malformed)?;
                let payload =
                    take_wire_bytes(buf, &mut pos, len).ok_or(PreflightError::Malformed)?;
                let rewritten = match shape {
                    WireFieldShape::Message(nested) => {
                        let mut inner = Vec::with_capacity(payload.len());
                        strip_undeclared_closed_enums(payload, Some(&nested), None, &mut inner)?;
                        Some(inner)
                    }
                    WireFieldShape::ClosedEnum {
                        enum_type,
                        repeated: true,
                    } => {
                        let mut inner = Vec::with_capacity(payload.len());
                        let mut element = 0usize;
                        while element < payload.len() {
                            let start = element;
                            let value = read_wire_varint(payload, &mut element)
                                .ok_or(PreflightError::Malformed)?;
                            if closed_enum_value_is_declared(&enum_type, value) {
                                inner.extend_from_slice(&payload[start..element]);
                            }
                        }
                        Some(inner)
                    }
                    _ => None,
                };
                match rewritten {
                    Some(inner) => {
                        out.extend_from_slice(&buf[field_start..tag_end]);
                        push_wire_varint(out, inner.len() as u64);
                        out.extend_from_slice(&inner);
                    }
                    None => out.extend_from_slice(&buf[field_start..pos]),
                }
            }
            3 => {
                out.extend_from_slice(&buf[field_start..pos]);
                let nested = match shape {
                    WireFieldShape::Message(nested) => Some(nested),
                    _ => None,
                };
                let consumed =
                    strip_undeclared_closed_enums(&buf[pos..], nested.as_ref(), Some(number), out)?;
                pos += consumed;
            }
            _ => return Err(PreflightError::Malformed),
        }
    }
    if end_group.is_some() {
        return Err(PreflightError::Malformed);
    }
    Ok(pos)
}

fn push_wire_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn default_grpc_max_decompressed_size_bytes() -> Result<usize, String> {
    // The inherited ceiling comes from the typed compression admission
    // policy (issue #6651 item 3): a typo'd
    // `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` refuses construction instead of
    // silently defaulting, including on library entry points that never
    // built an `EnvConfig`. Zero/default/ceiling handling is unchanged.
    let policy = crate::config::CompressionAdmissionPolicy::from_process_env()?;
    Ok(inherited_grpc_max_decompressed_size_bytes(Some(
        &policy.max_request_body_size_bytes.to_string(),
    )))
}

/// The omitted-field default resolved from a raw
/// `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` value. A node-wide request-body setting
/// above [`MAX_GRPC_DECOMPRESSED_SIZE_CEILING`] is clamped rather than refused,
/// so it cannot fail every body_validator config on that node, but it can never
/// lift the decompression bound. Pure, so the clamp is testable without
/// mutating process environment in a parallel test binary.
pub(crate) fn inherited_grpc_max_decompressed_size_bytes(raw: Option<&str>) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_MAX_GRPC_DECOMPRESSED_SIZE)
        .min(MAX_GRPC_DECOMPRESSED_SIZE_CEILING)
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

/// Fixed diagnostic for a body whose element nesting exceeds
/// [`XML_MAX_NESTING_DEPTH`]. Like every other XML diagnostic here it is a
/// compiled-in constant; no body byte is ever interpolated
/// (`GHSA-5p2h-fq6q-gwh9`).
const XML_DEPTH_DETAIL: &str = "Invalid XML: document nesting exceeds the supported depth";

/// Fixed diagnostic for an entity declaration whose replacement text references
/// another entity — the billion-laughs expansion signature.
const XML_NESTED_ENTITY_DETAIL: &str =
    "XML entity definition references another entity (billion-laughs protection)";

/// Fixed diagnostic for an `<!ENTITY ...>` declaration the nested-entity policy
/// could not read a replacement text out of.
///
/// Failing to extract a value is not evidence that the declaration is harmless:
/// the parser downstream still sees a declared, referenceable entity
/// (`GHSA-j965-6vq5-v44f`). With `xml_reject_nested_entities` on, an
/// unevaluable declaration is refused rather than silently counted as safe.
const XML_UNEVALUABLE_ENTITY_DETAIL: &str =
    "XML entity declaration could not be evaluated against the nested-entity policy";

fn parse_schema_draft(raw: Option<&str>) -> Result<SchemaDraft, String> {
    match raw {
        None => Ok(SchemaDraft::Draft202012),
        Some("draft2020-12") => Ok(SchemaDraft::Draft202012),
        Some("draft7") => Ok(SchemaDraft::Draft7),
        Some(_) => Err(
            "body_validator: `json_schema_draft` must be `draft2020-12` or `draft7`".to_string(),
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
            "body_validator: `{field}` must be a JSON Schema object"
        ));
    };
    if object.is_empty() {
        return Err(format!("body_validator: `{field}` must not be empty"));
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
                "body_validator: `{field}` is not a valid {} JSON Schema",
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
            "body_validator: `{field}` nests deeper than the {MAX_SCHEMA_DEPTH}-level schema budget"
        ));
    }
    *nodes += 1;
    if *nodes > MAX_SCHEMA_NODES {
        return Err(format!(
            "body_validator: `{field}` exceeds the {MAX_SCHEMA_NODES}-node schema budget"
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
                    "body_validator: `{field}` has a non-string `{key}`"
                ));
            };
            if !reference.starts_with('#') {
                return Err(format!(
                    "body_validator: `{field}` has a non-local `{key}`; \
                     only local references (starting with `#`) \
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
                    "body_validator: `{field}` has a non-string `{key}`"
                ));
            };
            if !id.starts_with('#') {
                return Err(format!(
                    "body_validator: `{field}` has a non-fragment `{key}`; \
                     a base URI would allow external reference resolution"
                ));
            }
        }
    }

    if map.contains_key("$vocabulary") {
        return Err(format!(
            "body_validator: `{field}` declares `$vocabulary`; custom \
             vocabularies are not supported and would not be enforced"
        ));
    }

    if let Some(value) = map.get("$schema") {
        let Some(uri) = value.as_str() else {
            return Err(format!(
                "body_validator: `{field}` has a non-string `$schema`"
            ));
        };
        if !draft.schema_uris().contains(&uri) {
            return Err(format!(
                "body_validator: `{field}` declares an unsupported `$schema`; \
                 configured draft is `{}`",
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
        .ok_or_else(|| format!("body_validator: `{field}` has a non-local `{keyword}`"))?;
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
                "body_validator: `{field}` has invalid UTF-8 percent encoding \
                 in a local `{keyword}` JSON Pointer"
            )
        })?;
    let mut target = document;
    for raw_segment in decoded.split('/') {
        target = match target {
            Value::Array(items) => {
                let index = raw_segment.parse::<usize>().map_err(|_| {
                    format!(
                        "body_validator: `{field}` has invalid array index in \
                         a local `{keyword}` JSON Pointer"
                    )
                })?;
                items.get(index).ok_or_else(|| {
                    format!(
                        "body_validator: `{field}` has a local `{keyword}` JSON \
                         Pointer that resolves nowhere"
                    )
                })?
            }
            Value::Object(map) => {
                let segment = unescape_json_pointer_segment(raw_segment);
                map.get(segment.as_ref()).ok_or_else(|| {
                    format!(
                        "body_validator: `{field}` has a local `{keyword}` JSON \
                         Pointer that resolves nowhere"
                    )
                })?
            }
            _ => {
                return Err(format!(
                    "body_validator: `{field}` has a local `{keyword}` JSON \
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
/// failures carry a bounded instance location plus an allowlisted keyword so a
/// caller can fix its own payload; response failures stay coarse so an upstream
/// body's shape is not described back to the client. Raw schema paths (including
/// `$defs` names and `$ref` fragments) are never emitted.
///
/// The location is rendered by [`safe_location`]: numeric pointer segments
/// become a fixed marker (JSON Pointer alone does not prove array shape), and
/// object member names survive only when the *configured schema* declares them
/// as JSON properties. A hostile member name — which `jsonschema` places in the
/// instance path for `propertyNames`, `patternProperties`,
/// `additionalProperties`, and nested `required` failures — is replaced with a
/// placeholder rather than echoed, and depth, segment count, and total length
/// are all capped (`GHSA-5p2h-fq6q-gwh9`).
fn schema_violation_message(
    error: &jsonschema::ValidationError<'_>,
    direction: Direction,
    safe_names: &SafeFieldNames,
) -> String {
    let keyword = safe_keyword(error.schema_path().as_str());
    match direction {
        Direction::Request => {
            let location = safe_location(error.instance_path().as_str(), safe_names);
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
///
/// The configured spelling is retained only for matching; diagnostics never
/// echo it (`GHSA-5p2h-fq6q-gwh9`).
struct RequiredXmlElement {
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
                        "body_validator: `{field}` entry at index {index} opens Clark notation \
                         with `{{` but never closes it with `}}`"
                    ));
                }
            },
            None => (None, entry.clone()),
        };
        if local.is_empty() {
            return Err(format!(
                "body_validator: `{field}` entry at index {index} has an empty local element name"
            ));
        }
        // The matcher compares against `roxmltree`'s parsed LOCAL name, so a
        // spelling outside the XML `NCName` grammar can never equal one. Such
        // an entry is admitted today and then rejects every governed request
        // (400) and every governed response (502) forever, so refuse it here
        // instead. The configured spelling is never echoed
        // (`GHSA-5p2h-fq6q-gwh9`).
        if !is_xml_ncname(&local) {
            return Err(format!(
                "body_validator: `{field}` entry at index {index} has an invalid local element \
                 name; it must be an XML NCName (no whitespace, markup, namespace prefix, or \
                 braces)"
            ));
        }
        parsed.push(RequiredXmlElement { namespace, local });
    }
    Ok(parsed)
}

/// Bounded budget for the recursive protobuf message walk.
#[derive(Default)]
struct ProtobufWalkBudget {
    messages: usize,
}

/// Maximum message-nesting depth inspected by the protobuf message walk.
const MAX_PROTOBUF_MESSAGE_DEPTH: usize = 32;

/// Maximum number of messages inspected by the protobuf message walk.
const MAX_PROTOBUF_MESSAGES: usize = 50_000;

/// Fixed diagnostic for exhausting the walk's message budget.
const PROTOBUF_BUDGET_DETAIL: &str = "Protobuf message exceeds the inspection budget";

/// Fixed diagnostic for exceeding the walk's message-nesting depth.
const PROTOBUF_DEPTH_DETAIL: &str = "Protobuf message nests deeper than the inspection budget";

impl ProtobufWalkBudget {
    fn charge(&mut self) -> Result<(), String> {
        self.messages += 1;
        if self.messages > MAX_PROTOBUF_MESSAGES {
            return Err(PROTOBUF_BUDGET_DETAIL.to_string());
        }
        Ok(())
    }
}

/// The per-message policies the bounded walk enforces.
#[derive(Clone, Copy)]
struct ProtobufMessagePolicy {
    /// Enforce proto2 `required` field presence. Set only for pools that
    /// actually contain a proto2 file, so a proto3-only deployment keeps the
    /// gRPC hot path free of the walk.
    check_required: bool,
    /// Enforce `protobuf_reject_unknown_fields` at every nesting level.
    reject_unknown: bool,
}

impl ProtobufMessagePolicy {
    fn is_active(&self) -> bool {
        self.check_required || self.reject_unknown
    }
}

/// Recursively apply the configured message policies to a decoded message.
///
/// **proto2 initialization.** Presence, not value, is what is checked: a
/// required scalar carrying its type's default value is present because proto2
/// tracks it with a hasbit, and prost-reflect's `has_field` reflects exactly
/// that. proto3 descriptors have no `Required` cardinality, so proto3 messages
/// are unaffected. The error names the offending field path (descriptor
/// metadata, configured by the operator) and never any payload value.
///
/// **Unknown fields.** `DynamicMessage::unknown_fields()` reports only the
/// fields the decoder could not place in THIS message; nested message values
/// carry their own. Applying the configured strict policy at every level is
/// what makes it mean what it is documented to mean (`GHSA-cqmm-vj3c-g8w8`).
/// The diagnostic carries a count, never a field number or payload byte.
///
/// Extensions, oneof members, repeated values, and map values are all walked,
/// under one shared depth and message budget.
fn check_protobuf_message(
    message: &DynamicMessage,
    policy: ProtobufMessagePolicy,
    budget: &mut ProtobufWalkBudget,
) -> Result<(), String> {
    check_protobuf_message_at(message, policy, budget, 0, &mut String::new())
}

fn check_protobuf_message_at(
    message: &DynamicMessage,
    policy: ProtobufMessagePolicy,
    budget: &mut ProtobufWalkBudget,
    depth: usize,
    path: &mut String,
) -> Result<(), String> {
    if depth > MAX_PROTOBUF_MESSAGE_DEPTH {
        return Err(PROTOBUF_DEPTH_DETAIL.to_string());
    }
    budget.charge()?;

    if policy.reject_unknown {
        let unknown_count = message.unknown_fields().count();
        if unknown_count > 0 {
            return Err(format!(
                "Message contains {} unknown field(s)",
                unknown_count
            ));
        }
    }

    if policy.check_required {
        let descriptor = message.descriptor();
        for field in descriptor.fields() {
            if field.cardinality() == Cardinality::Required && !message.has_field(&field) {
                let name = field.name();
                return Err(format!("Missing required protobuf field: {path}{name}"));
            }
        }
    }

    // Only present values can be walked; an absent singular message field is
    // legal unless it is itself `required`, which the loop above already
    // rejected.
    for (field, value) in message.fields() {
        let restore = path.len();
        path.push_str(field.name());
        path.push('.');
        check_protobuf_message_in_value(value, policy, budget, depth + 1, path)?;
        path.truncate(restore);
    }
    // Only present extensions are iterable, and proto2 forbids `required`
    // extension fields, so there is no presence check to make here — but an
    // extension's message value can still carry required fields, or unknown
    // fields, of its own.
    for (extension, value) in message.extensions() {
        let restore = path.len();
        path.push('[');
        path.push_str(extension.full_name());
        path.push_str("].");
        check_protobuf_message_in_value(value, policy, budget, depth + 1, path)?;
        path.truncate(restore);
    }
    Ok(())
}

/// Whether an enum type is CLOSED: declared in a proto2 file. A closed enum
/// admits only its declared numbers; a proto3 (open) enum keeps any number.
fn enum_is_closed(enum_type: &EnumDescriptor) -> bool {
    enum_type.parent_file().syntax() == Syntax::Proto2
}

fn check_protobuf_message_in_value(
    value: &ProtobufValue,
    policy: ProtobufMessagePolicy,
    budget: &mut ProtobufWalkBudget,
    depth: usize,
    path: &mut String,
) -> Result<(), String> {
    match value {
        ProtobufValue::Message(nested) => {
            check_protobuf_message_at(nested, policy, budget, depth, path)
        }
        ProtobufValue::List(items) => {
            for item in items {
                check_protobuf_message_in_value(item, policy, budget, depth, path)?;
            }
            Ok(())
        }
        ProtobufValue::Map(entries) => {
            for entry in entries.values() {
                check_protobuf_message_in_value(entry, policy, budget, depth, path)?;
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
        .ok_or_else(|| format!("body_validator: `{field}` must be a boolean"))
}

fn optional_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "body_validator: `{field}` must be an unsigned integer"
        ));
    };
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("body_validator: `{field}` is too large for this platform"))
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        return Err(format!("body_validator: `{field}` must be a string"));
    };
    if value.is_empty() {
        return Err(format!("body_validator: `{field}` must not be empty"));
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
        .ok_or_else(|| format!("body_validator: `{field}` must be an object"))
}

fn optional_string_vec(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("body_validator: `{field}` must be an array"));
    };

    let mut parsed = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(value) = value.as_str() else {
            return Err(format!(
                "body_validator: `{field}` entries must be strings (invalid entry at index {index})"
            ));
        };
        if value.is_empty() {
            return Err(format!(
                "body_validator: `{field}` entries must not be empty (invalid entry at index {index})"
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
    if values.is_empty() {
        // An empty list used to mean "every valid media type" — the opposite
        // of what it reads as. Omit the field for the defaults instead.
        return Err(format!(
            "body_validator: `{field}` must not be empty; omit it to use the defaults"
        ));
    }
    let mut parsed = Vec::with_capacity(values.len());
    for (index, value) in values.into_iter().enumerate() {
        // Normalize configured media types the same way actual headers are
        // compared: type/subtype only, parameters stripped, ASCII-lowercased.
        let normalized = media_type_essence(&value)
            .ok_or_else(|| {
                format!(
                    "body_validator: `{field}` entries must be valid media types \
                     (type/subtype), not empty, parameter-only, or malformed \
                     (invalid entry at index {index})"
                )
            })?
            .to_ascii_lowercase();
        parsed.push(normalized);
    }
    Ok(Some(parsed))
}

/// Default request/response media types: JSON and XML, including their RFC
/// 6838 structured-suffix types (`application/problem+json`,
/// `application/vnd.acme.v2+json`, `application/atom+xml`, ...), which the
/// JSON/XML dispatch already understands. gRPC-family types never match a
/// pattern entry.
fn default_content_types() -> Vec<String> {
    vec![
        "application/json".to_string(),
        "application/*+json".to_string(),
        "application/xml".to_string(),
        "application/*+xml".to_string(),
        "text/xml".to_string(),
    ]
}

/// Parse `response_status_codes`: a non-empty array of integer statuses
/// (`100..=599`) and/or status classes `"1XX"`..`"5XX"`.
fn optional_response_status_scope(config: &Value) -> Result<Option<ResponseStatusScope>, String> {
    const FIELD: &str = "response_status_codes";
    let Some(value) = config.get(FIELD) else {
        return Ok(None);
    };
    let Some(entries) = value.as_array() else {
        return Err(format!("body_validator: `{FIELD}` must be an array"));
    };
    if entries.is_empty() {
        return Err(format!(
            "body_validator: `{FIELD}` must not be empty; omit it to validate 2XX responses"
        ));
    }
    let mut scope = ResponseStatusScope {
        classes: [false; 6],
        codes: Vec::new(),
    };
    for (index, entry) in entries.iter().enumerate() {
        if let Some(code) = entry.as_u64() {
            let Some(code) = u16::try_from(code)
                .ok()
                .filter(|code| (100..=599).contains(code))
            else {
                return Err(format!(
                    "body_validator: `{FIELD}` integer entries must be HTTP statuses 100-599 \
                     (invalid entry at index {index})"
                ));
            };
            scope.codes.push(code);
            continue;
        }
        let class = entry.as_str().and_then(|text| match text.as_bytes() {
            [digit @ b'1'..=b'5', first, second]
                if first.eq_ignore_ascii_case(&b'x') && second.eq_ignore_ascii_case(&b'x') =>
            {
                Some(usize::from(*digit - b'0'))
            }
            _ => None,
        });
        let Some(class) = class else {
            return Err(format!(
                "body_validator: `{FIELD}` entries must be integer statuses or classes `1XX`-`5XX` \
                 (invalid entry at index {index})"
            ));
        };
        scope.classes[class] = true;
    }
    Ok(Some(scope))
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

/// Type/subtype match against configured media types.
///
/// Compares the normalized essence of `content_type` (parameters stripped,
/// OWS trimmed, ASCII case-insensitive) to each configured entry. Distinct
/// neighbors such as `application/json-seq` and parameter values that merely
/// contain a configured string do not match. A malformed actual value never
/// matches. The configured list is never empty (construction rejects it).
///
/// An entry of the form `type/*+suffix` is a structured-suffix pattern: it
/// matches any `type/<name>+suffix` with a non-empty `<name>`, except the
/// gRPC-family types (`application/grpc+json`, `application/grpc-web+json`),
/// whose bodies are length-prefixed frames rather than a document.
fn content_type_matches(configured: &[String], content_type: &str) -> bool {
    let Some(actual) = media_type_essence(content_type) else {
        return false;
    };
    configured.iter().any(|expected| {
        if let Some((type_name, suffix)) = expected
            .split_once("/*+")
            .filter(|(_, suffix)| !suffix.is_empty())
        {
            let Some((actual_type, actual_subtype)) = actual.split_once('/') else {
                return false;
            };
            actual_type.eq_ignore_ascii_case(type_name)
                && actual_subtype.len() > suffix.len() + 1
                && ascii_ends_with_ignore_case(actual_subtype, suffix)
                && actual_subtype.as_bytes()[actual_subtype.len() - suffix.len() - 1] == b'+'
                && grpc_representation(actual).is_none()
        } else {
            actual.eq_ignore_ascii_case(expected)
        }
    })
}

/// Whether the request declares a `Content-Encoding` the shared representation
/// gate must judge before a governed policy may claim to have inspected the
/// body.
///
/// The grammar is the gate's own, so one request cannot be "encoded" to this
/// hook and "identity" to the gate. A malformed or empty coding token counts as
/// requiring judgment, which routes it to the gate's fail-closed rejection
/// rather than to a scan of octets nobody proved were plaintext.
fn request_declares_content_coding(headers: &HashMap<String, String>) -> bool {
    headers
        .get("content-encoding")
        .is_some_and(|value| super::request_representation::requires_decode_judgment(value))
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
            if reject_nested {
                match scan_entity_declaration_nesting(&body[i..decl_end]) {
                    EntityNestingScan::NestedReference => {
                        return Err(XML_NESTED_ENTITY_DETAIL.to_string());
                    }
                    EntityNestingScan::Unevaluable => {
                        return Err(XML_UNEVALUABLE_ENTITY_DETAIL.to_string());
                    }
                    EntityNestingScan::NoNestedReference => {}
                }
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

/// XML 1.0 (fifth edition) `NameStartChar`, production [4].
///
/// The pre-parse entity policy must recognize exactly the names the parser
/// recognizes. `roxmltree` consumes entity declaration names and entity
/// references through the XML `Name` production, so the previous ASCII-only
/// scanners made an entity declared or referenced under a non-ASCII name
/// invisible to the nested-entity restriction while the parser still saw a
/// declared, referenced entity (`GHSA-j965-6vq5-v44f`).
fn is_xml_name_start_char(ch: char) -> bool {
    let cp = u32::from(ch);
    ch == ':'
        || ch == '_'
        || ch.is_ascii_alphabetic()
        || (0xC0..=0xD6).contains(&cp)
        || (0xD8..=0xF6).contains(&cp)
        || (0xF8..=0x2FF).contains(&cp)
        || (0x370..=0x37D).contains(&cp)
        || (0x37F..=0x1FFF).contains(&cp)
        || (0x200C..=0x200D).contains(&cp)
        || (0x2070..=0x218F).contains(&cp)
        || (0x2C00..=0x2FEF).contains(&cp)
        || (0x3001..=0xD7FF).contains(&cp)
        || (0xF900..=0xFDCF).contains(&cp)
        || (0xFDF0..=0xFFFD).contains(&cp)
        || (0x10000..=0xEFFFF).contains(&cp)
}

/// XML 1.0 (fifth edition) `NameChar`, production [4a].
fn is_xml_name_char(ch: char) -> bool {
    let cp = u32::from(ch);
    is_xml_name_start_char(ch)
        || ch == '-'
        || ch == '.'
        || ch.is_ascii_digit()
        || cp == 0xB7
        || (0x300..=0x36F).contains(&cp)
        || (0x203F..=0x2040).contains(&cp)
}

/// Byte offset one past the XML `Name` beginning at `start`, or `None` when no
/// `Name` begins there.
///
/// `start` is always reached by skipping ASCII delimiters (`<!ENTITY`, XML
/// whitespace, `%`, `&`), so it is a UTF-8 boundary; a non-boundary index is
/// still handled — `str::get` returns `None` and the caller treats the position
/// as "no name here".
fn xml_name_end(text: &str, start: usize) -> Option<usize> {
    let rest = text.get(start..)?;
    let mut chars = rest.char_indices();
    let (_, first) = chars.next()?;
    if !is_xml_name_start_char(first) {
        return None;
    }
    let mut end = start + first.len_utf8();
    for (offset, ch) in chars {
        if !is_xml_name_char(ch) {
            break;
        }
        end = start + offset + ch.len_utf8();
    }
    Some(end)
}

/// True when `name` is an XML `NCName`: the `Name` production without `:`.
///
/// `roxmltree` reports an element's LOCAL name, with any namespace prefix
/// already split off and resolved to an expanded URI, so a configured required
/// element name can only ever equal an `NCName`. Admitting a spelling outside
/// that grammar — `two words`, a leading digit, a `prefix:local` spelling —
/// creates a rule no well-formed document can satisfy, so every governed
/// request is rejected with 400 and every governed response with 502.
fn is_xml_ncname(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if first == ':' || !is_xml_name_start_char(first) {
        return false;
    }
    chars.all(|ch| ch != ':' && is_xml_name_char(ch))
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
    let name_end = xml_name_end(decl, name_start)?;
    i = skip_xml_space(bytes, name_end);
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
    let name_start = start + 1;
    let name_end = xml_name_end(body, name_start)?;
    if bytes.get(name_end) != Some(&b';') {
        return None;
    }
    Some((&body[name_start..name_end], name_end + 1))
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

/// What the nested-entity policy could establish about one `<!ENTITY ...>`
/// declaration.
enum EntityNestingScan {
    /// The declaration's replacement text references another entity. General
    /// entity refs (`&name;`) and parameter entity refs (`%name;`) both create
    /// expansion chains.
    NestedReference,
    /// The declaration parsed and its replacement text references nothing.
    NoNestedReference,
    /// No replacement text could be read out of the declaration, so the policy
    /// has no evidence either way. The parser downstream still sees a declared,
    /// referenceable entity, so absence of proof is not proof of absence
    /// (`GHSA-j965-6vq5-v44f`).
    Unevaluable,
}

/// Inspect one `<!ENTITY ...>` declaration for the nested-entity policy.
///
/// Numeric character refs are normalized first because XML resolves them
/// inside entity replacement text before expansion.
fn scan_entity_declaration_nesting(decl: &str) -> EntityNestingScan {
    let Some(value) = entity_declaration_value(decl) else {
        return EntityNestingScan::Unevaluable;
    };
    let decoded = decode_xml_numeric_char_refs(value);
    if entity_replacement_text_references_entity(decoded.as_ref()) {
        EntityNestingScan::NestedReference
    } else {
        EntityNestingScan::NoNestedReference
    }
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
    let name_end = xml_name_end(decl, i)?;
    i = skip_xml_space(bytes, name_end);
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

/// The five general entities XML predefines. A reference to one of them
/// resolves to a single character, never to another declaration, so it is not
/// an expansion chain.
fn is_predefined_general_entity(name: &str) -> bool {
    matches!(name, "lt" | "gt" | "amp" | "quot" | "apos")
}

fn entity_replacement_text_references_entity(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if matches!(bytes[i], b'&' | b'%') {
            let marker = bytes[i];
            match xml_name_end(value, i + 1) {
                Some(name_end) => {
                    if bytes.get(name_end) == Some(&b';') {
                        let name = &value[i + 1..name_end];
                        if marker == b'%' || !is_predefined_general_entity(name) {
                            return true;
                        }
                    }
                    // `name_end > i + 1` whenever a name was found, so the scan
                    // always advances and stays linear in the value length.
                    i = name_end;
                }
                None => i += 1,
            }
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

/// Whether a `protobuf_method_messages` key can equal the gRPC method path the
/// hooks look up.
///
/// Selection is an exact map lookup: the request hook keys on the `:path`
/// pseudo-header the proxy injects, and the response hook on
/// `grpc_full_method` (normalized to a leading `/`) or `ctx.path`. Both are
/// gRPC method paths, so a key spelled any other way can never be selected —
/// yet it still satisfies the constructor's rule-presence test, producing an
/// enabled policy whose intended rule is silently inert (issue #5139).
///
/// The shape check is deliberately structural rather than a protobuf
/// identifier grammar, so deployments that route custom service or method
/// spellings keep working: one leading `/`, exactly two non-empty segments,
/// and no character that could not appear in the looked-up path.
fn is_grpc_method_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    let Some((service, method)) = rest.split_once('/') else {
        return false;
    };
    if service.is_empty() || method.is_empty() || method.contains('/') {
        return false;
    }
    for ch in path.chars() {
        if ch.is_whitespace() || ch.is_control() || matches!(ch, '?' | '#') {
            return false;
        }
    }
    true
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
            "body_validator: `protobuf_descriptor_path` is required when configuring protobuf validation"
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
            if !is_grpc_method_path(method_path) {
                return Err(
                    "body_validator: `protobuf_method_messages` keys must be gRPC method paths \
                     of the form `/package.Service/Method`"
                        .to_string(),
                );
            }
            let Some(method_object) = method_config.as_object() else {
                return Err(
                    "body_validator: a `protobuf_method_messages` entry must be an object"
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
                    "body_validator: a `protobuf_method_messages` entry has an unknown key; \
                     allowed keys: `{}`",
                    BODY_VALIDATOR_PROTOBUF_METHOD_KEYS.join("`, `")
                ));
            }
            let request = optional_string(method_config, "request")?.map(str::to_string);
            let response = optional_string(method_config, "response")?.map(str::to_string);
            if request.is_none() && response.is_none() {
                return Err(
                    "body_validator: a `protobuf_method_messages` entry must configure `request` \
                     or `response`"
                        .to_string(),
                );
            }
            targets.method_entries.insert(method_path.clone());
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
                "body_validator: configured `protobuf_request_type` was not found in the descriptor"
                    .to_string()
            })
        })
        .transpose()?;
    let response_descriptor = shape
        .response_type
        .as_deref()
        .map(|name| {
            pool.get_message_by_name(name).ok_or_else(|| {
                "body_validator: configured `protobuf_response_type` was not found in the descriptor"
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
                    "body_validator: a `protobuf_method_messages` request type was not found in \
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
                    "body_validator: a `protobuf_method_messages` response type was not found in \
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

/// Fixed, value-free diagnostic for a request body the configured JSON/XML
/// rules cannot decode. Hostile bytes are never echoed or logged.
const NON_UTF8_REQUEST_BODY: &str = "Request body is not valid UTF-8";

/// Response counterpart of [`NON_UTF8_REQUEST_BODY`]. Deliberately coarse so an
/// upstream body is not described back to the client.
const NON_UTF8_RESPONSE_BODY: &str = "Response body is not valid UTF-8";

/// Fixed diagnostic for the case where this instance selected request-body
/// buffering but no buffered representation reached the hook. That is a gateway
/// inconsistency, not a validated request, so it fails closed.
const REQUEST_BODY_REPRESENTATION_UNAVAILABLE: &str =
    "Request body representation was unavailable for validation";

/// `true` when an empty gRPC reply is a legitimate terminal error response:
/// the hook-visible header map carries one unambiguous non-zero terminal status
/// and no message frame is sent.
///
/// A successful unary response (`grpc-status: 0`), including
/// `google.protobuf.Empty`, still requires a real five-byte gRPC frame, so OK
/// must not create an empty-body exemption. Malformed, CR/LF-joined duplicate,
/// or otherwise unparsable `grpc-status` values also must not — only one valid
/// non-zero standard gRPC status (`1..=16`) legitimizes an empty error body.
fn grpc_empty_response_is_terminal_error(response_headers: &HashMap<String, String>) -> bool {
    let Some(raw) = response_headers.get("grpc-status") else {
        return false;
    };
    // Buffered collection may LF-join duplicate occurrences. Preferring any
    // occurrence would let a hostile/ambiguous field look like a terminal
    // error; refuse the exemption unless the field is a single clean value.
    if raw.contains('\n') || raw.contains('\r') {
        return false;
    }
    let Ok(code) = raw.trim().parse::<u32>() else {
        return false;
    };
    (1..=16).contains(&code)
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
        // JSON/XML validation reads request_body from metadata in before_proxy,
        // and strict media-type admission needs to know whether an ungoverned
        // request carries a body. Protobuf validation runs in
        // on_final_request_body and should not force pre-before_proxy buffering.
        self.has_pre_proxy_request_validation || self.reject_unsupported_media_types
    }

    fn requires_request_body_buffering(&self) -> bool {
        self.has_request_validation
    }

    /// Keep the raw buffer available so a body-validator-only chain retains
    /// binary bytes when the proxy removes the UTF-8 metadata copy
    /// (`GHSA-2vmr-ww8r-mww3`). Early JSON/XML validation prefers a downstream
    /// metadata text view when one exists (composition with `ai_prompt_shield`)
    /// and falls back to these bytes only when that text view is absent.
    fn needs_request_body_bytes(&self) -> bool {
        self.has_pre_proxy_request_validation || self.reject_unsupported_media_types
    }

    fn needs_request_body_text(&self) -> bool {
        false
    }

    /// Buffering follows the configured representation, not the request method.
    ///
    /// A body-bearing `DELETE`, `PUT`, `PATCH`, `OPTIONS`, `GET`, or any other
    /// method carrying a governed media type must reach the validator; the old
    /// `GET`/`HEAD`/`OPTIONS`/`DELETE` exclusion made the policy bypassable by
    /// method alone (`GHSA-2vmr-ww8r-mww3`). Legitimate protocol semantics are
    /// preserved because the proxy still never materializes a body the transport
    /// proved absent, and the hooks validate that proven-empty representation
    /// directly.
    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if !self.has_request_validation {
            return false;
        }

        let content_type = ctx
            .headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");

        // gRPC is governed only by configured protobuf descriptors, and only
        // for the methods they enroll: buffering an unenrolled method would take
        // it off the streaming path (deadlocking bidi RPCs and collecting
        // unbounded server streams) only for the hooks to skip it.
        if grpc_representation(content_type).is_some() {
            return self.has_protobuf_request_validation && self.protobuf_request_may_apply(ctx);
        }

        // Everything else is governed only by the configured JSON/XML rules. A
        // protobuf-only instance must not pull unrelated media types onto the
        // buffered path: its final hook would no-op on them anyway.
        if self.has_pre_proxy_request_validation
            && content_type_matches(&self.content_types, content_type)
        {
            return true;
        }

        // Strict media-type admission must learn whether an ungoverned request
        // carries a body when its headers do not already say.
        self.reject_unsupported_media_types
            && !request_headers_declare_body_framing(&ctx.headers)
            && !request_opens_tunnel(ctx)
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only the configured JSON/XML rules (and strict media-type admission)
        // decide here; protobuf validation runs in `on_final_request_body`. The
        // request method is deliberately not consulted (`GHSA-2vmr-ww8r-mww3`).
        if !self.has_pre_proxy_request_validation && !self.reject_unsupported_media_types {
            return PluginResult::Continue;
        }

        // Check content type
        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");

        // gRPC protobuf validation is handled in on_final_request_body, not here.
        if grpc_representation(content_type).is_some() {
            if self.reject_unsupported_media_types && !self.has_protobuf_request_validation {
                // gRPC is a body-bearing protocol this instance has no rule for.
                return self.violation(
                    Some(ctx),
                    Direction::Request,
                    415,
                    UNSUPPORTED_MEDIA_TYPE_DETAIL,
                );
            }
            return PluginResult::Continue;
        }

        if !self.json_xml_request_rule_inspects(content_type) {
            // The media type is outside the configured allowlist, or inside it
            // but no configured rule can inspect it. Nothing to decide — unless
            // strict media-type admission refuses a body nothing inspects.
            if self.reject_unsupported_media_types && ungoverned_request_carries_body(ctx, headers)
            {
                return self.violation(
                    Some(ctx),
                    Direction::Request,
                    415,
                    UNSUPPORTED_MEDIA_TYPE_DETAIL,
                );
            }
            return PluginResult::Continue;
        }
        let validate_as_json = is_json_like_content_type(content_type);

        // A declared, non-identity `Content-Encoding` means the representation
        // this early hook can see is a COMPRESSED encoding of the document the
        // configured rules are about. `before_proxy` has no decoder — the
        // shared backend-visible representation gate does, and it stages
        // bounded, budget-charged plaintext for exactly the requests this
        // plugin claims (`GHSA-3973-47g5-4mcx`). Running the UTF-8 conversion
        // over the encoded octets here turned every legitimate gzip JSON/XML
        // upload into a fixed 400 while the authoritative check was still ahead
        // of it, so hand the decision to that check instead.
        //
        // The deferral is taken only when this instance's final request-body
        // policy claims the request — precisely the condition under which the
        // gate decodes it or fails it closed — and only for a representation
        // that actually reached this hook. A missing representation still fails
        // closed below, and an undecodable coding is still a rejection before
        // backend egress. (In `log_only` mode, which never claims, the final
        // hook records the encoded representation as uninspected.)
        let defer_encoded_representation = request_declares_content_coding(headers)
            && self.final_request_body_policy_applies(headers);

        // The body views live on `ctx`, so the shared duplicate-key memo is
        // moved out for the duration of the borrow and moved back before this
        // hook returns. Taking it is not a reset: `JsonScanMemo` is keyed on
        // body digests, so restoring it preserves every verdict.
        let mut json_scan_memo = std::mem::take(&mut ctx.json_scan_memo);

        // Resolve the early-hook request representation.
        //
        // Prefer `ctx.metadata["request_body"]` when present: earlier
        // `before_proxy` plugins such as `ai_prompt_shield` deliberately rewrite
        // that UTF-8 view so downstream admission evaluates the shielded /
        // redacted representation. Fall back to `ctx.request_body_bytes` when no
        // text view exists — this plugin declares `needs_request_body_bytes()`,
        // so the raw buffer is retained for non-UTF-8 bodies the proxy strips
        // from metadata. `replay_request_body_empty_proven()` is the transport's
        // own proof that the client sent nothing at all. Anything else is a
        // missing representation and fails closed. The final request-body hook
        // still validates the exact backend-visible bytes independently.
        const TRANSPORT_PROVEN_EMPTY: &[u8] = &[];
        let resolved: Option<&[u8]> = if let Some(text) = ctx.metadata.get("request_body") {
            Some(text.as_bytes())
        } else if let Some(bytes) = ctx.request_body_bytes.as_deref() {
            Some(bytes)
        } else if ctx.replay_request_body_empty_proven() {
            Some(TRANSPORT_PROVEN_EMPTY)
        } else {
            None
        };

        // `Ok(Some(digest))`: the body was validated and passed; the digest lets
        // the final hook recognize the byte-identical representation.
        let result: Result<Option<[u8; 32]>, String> = match resolved {
            None => Err(REQUEST_BODY_REPRESENTATION_UNAVAILABLE.to_string()),
            // Present but encoded: the governed decode and the authoritative
            // verdict both belong to the final hook.
            Some(_) if defer_encoded_representation => Ok(None),
            Some(body) => match std::str::from_utf8(body) {
                Err(_) => Err(NON_UTF8_REQUEST_BODY.to_string()),
                Ok(body_str) => {
                    let verdict = if validate_as_json {
                        Self::validate_json_body(
                            body_str,
                            &self.required_fields,
                            self.json_validator.as_ref(),
                            Direction::Request,
                            Some(&mut json_scan_memo),
                        )
                    } else {
                        Self::validate_xml_body(
                            body_str,
                            &self.required_xml_elements,
                            self.xml_max_entities,
                            self.xml_reject_nested_entities,
                        )
                    };
                    verdict.map(|()| Some(early_request_digest(content_type, body)))
                }
            },
        };

        ctx.json_scan_memo = json_scan_memo;

        match result {
            Ok(Some(digest)) => {
                ctx.plugin_state_mut()
                    .body_validator_early_request_digests
                    .insert(self.instance_id, digest);
                PluginResult::Continue
            }
            Ok(None) => PluginResult::Continue,
            Err(msg) => {
                if msg == REQUEST_BODY_REPRESENTATION_UNAVAILABLE {
                    // Fixed-cardinality operator signal: no request value, no
                    // header value, and no body byte is recorded.
                    warn!(
                        plugin = "body_validator",
                        "Request body representation unavailable; failing closed"
                    );
                }
                self.violation(Some(ctx), Direction::Request, 400, &msg)
            }
        }
    }

    async fn on_final_request_body(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        let undecoded_coding = self.enforcement_mode == EnforcementMode::LogOnly
            && request_declares_content_coding(headers);
        let verdict = self.evaluate_final_request_body(
            None,
            headers,
            body,
            None,
            undecoded_coding,
            BudgetRef::request_decode(),
        );
        self.finish_request_verdict(None, verdict)
    }

    /// Claim the finalized request representation whenever the configured
    /// JSON/XML rules would inspect it, so the shared request representation gate
    /// decodes a content coding into plaintext or fails the request closed
    /// (`GHSA-3973-47g5-4mcx`).
    ///
    /// Without this, a gzip-encoded `application/json` upload reached the UTF-8
    /// conversion below as compressed octets, failed it, and — before
    /// `GHSA-2vmr-ww8r-mww3` tightened it — was skipped; even after that fix it
    /// produced a confusing non-UTF-8 rejection rather than validating the
    /// document the backend actually parses. `log_only` mode cannot refuse, so
    /// it never claims (an undecodable coding must not become a `400` there).
    fn enforces_final_request_body_policy(
        &self,
        _ctx: &RequestContext,
        headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> bool {
        self.enforcement_mode == EnforcementMode::Block
            && self.final_request_body_policy_applies(headers)
    }

    /// The shared backend-visible representation gate stages decoded plaintext
    /// on the request context before this plugin's final hook runs. Opt in even
    /// when `body_validator` is the only contextual plugin in the chain; without
    /// this capability the proxy takes the compatibility hook path with no
    /// context, so a body-validator-only configuration can never reach either
    /// the charged decoder, the duplicate-key memo, or the context-derived gRPC
    /// method path below.
    fn needs_final_request_body_context(&self) -> bool {
        self.has_request_validation
    }

    /// A per-method protobuf rule is keyed on the BACKEND-effective method.
    /// Listen-path stripping plus a proxy or target base path can replace the
    /// service segment the client sent (`/v1.Greeter/Call` served as
    /// `/v2.Greeter/Call`), so opt into backend-path resolution: the gateway
    /// then binds the assembled path on every ladder before dispatch
    /// (`authorized_backend_path`), the per-method selectors read it, and the
    /// dispatchers re-ask the body-buffering votes against it. A default-type
    /// configuration applies to every method and needs no resolution.
    fn requires_backend_path_resolution(&self) -> bool {
        !self.protobuf_targets.method_entries.is_empty()
    }

    /// Context-aware variant: the duplicate-key screen of the final
    /// backend-visible body is shared with every other governed plugin in this
    /// hook stage (they all receive the same context object), the gRPC method
    /// path is recovered from the context when the dispatcher injected no
    /// `:path`, and the outcome is published to metadata.
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Validate the PLAINTEXT the backend will parse. This is `body` itself
        // unless the shared gate decoded a content coding; a claimed
        // representation it could not decode never reaches this hook.
        // An `O(1)` `Bytes` clone sharing the gate's one charged allocation
        // rather than a second uncharged copy of the decoded document; the owned
        // handle exists only to escape the borrow of `ctx` that the memo take
        // below needs.
        let decoded_view = ctx.inspectable_final_request_body_owned();
        let decoded = decoded_view.is_some();
        let body: &[u8] = decoded_view.as_deref().unwrap_or(body);
        if self.final_request_body_matches_early_pass(ctx, headers, body) {
            return PluginResult::Continue;
        }
        let undecoded_coding = self.enforcement_mode == EnforcementMode::LogOnly
            && !decoded
            && request_declares_content_coding(headers);
        let mut json_scan_memo = std::mem::take(&mut ctx.json_scan_memo);
        let verdict = self.evaluate_final_request_body(
            Some(&*ctx),
            headers,
            body,
            Some(&mut json_scan_memo),
            undecoded_coding,
            BudgetRef::request_decode(),
        );
        ctx.json_scan_memo = json_scan_memo;
        self.finish_request_verdict(Some(ctx), verdict)
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.has_response_validation
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        // Request Accept is only client intent. Keep ordinary backend JSON/XML
        // and protobuf responses on the validator path until response headers
        // prove that the backend selected an event stream.
        if !self.has_response_validation || request_method_omits_response_body(&ctx.method) {
            return false;
        }
        // A gRPC request (native, translated gRPC-Web, or pass-through
        // gRPC-Web) answers in gRPC framing, which only an applicable protobuf
        // descriptor inspects. Buffering an unenrolled method would take it off
        // the streaming path for nothing.
        if super::grpc_web::client_grpc_framing_representation(ctx).is_some() {
            return self.applicable_protobuf_response_validation(ctx);
        }
        self.has_json_response_validation()
            || self.has_xml_response_validation
            || self.applicable_protobuf_response_validation(ctx)
    }

    /// A zero-byte synthetic success (for example a `response_mock` rule with
    /// an empty body) is a representation the configured rules must judge — an
    /// empty JSON/XML document is invalid — so opt into the synthetic body
    /// pipeline for it. Protocol-defined no-body responses, out-of-scope
    /// statuses, and fragments stay exempt exactly as on the backend path.
    fn should_process_empty_synthetic_response_body(
        &self,
        ctx: &RequestContext,
        response_status: u16,
    ) -> bool {
        self.has_response_validation
            && self.response_status_validated(ctx, response_status)
            && !synthetic_response_omits_body(&ctx.method, response_status)
    }

    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        self.should_buffer_response_body(ctx)
    }

    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        // Once headers prove the representation is outside JSON/XML/gRPC
        // validation scope (or is an unbounded event stream, an out-of-scope
        // status, or a fragment), retries must not keep pinning it on the
        // buffered path. Matching types stay buffered.
        self.should_buffer_response_body(ctx)
            && (synthetic_response_omits_body(&ctx.method, response_status)
                || !self.response_status_validated(ctx, response_status)
                || !self.response_body_requires_buffering_for_media_type(
                    ctx,
                    response_headers.get("content-type").map(String::as_str),
                ))
    }

    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        // No-content responses cannot acquire a body through a Content-Type
        // rewrite. Genuine SSE is also safe to release here: `after_proxy`
        // fails closed on it. Non-matching downloads still go through ordinary
        // refinement, which refuses release when a later hook may relabel them.
        self.should_buffer_response_body(ctx)
            && (synthetic_response_omits_body(&ctx.method, response_status)
                || original_response_is_event_stream(ctx, response_headers))
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        // Narrow the pre-flight vote after backend headers arrive: release
        // media types the final hook would skip (binary downloads, etc.),
        // statuses outside `response_status_codes`, and range/delta fragments,
        // while keeping matching JSON/XML and applicable gRPC protobuf
        // responses buffered for validation.
        self.should_buffer_response_body(ctx)
            && !synthetic_response_omits_body(&ctx.method, response_status)
            && self.response_status_validated(ctx, response_status)
            && self.response_body_requires_buffering_for_media_type(ctx, content_type)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if self.should_buffer_response_body(ctx)
            && !synthetic_response_omits_body(&ctx.method, response_status)
            && self.response_status_validated(ctx, response_status)
            && original_response_is_event_stream(ctx, response_headers)
        {
            return self.violation(
                Some(ctx),
                Direction::Response,
                502,
                "event-stream responses require a bounded streaming validator",
            );
        }
        PluginResult::Continue
    }

    /// Claim an ORIGIN-ENCODED buffered response so the shared representation
    /// gate decodes it to plaintext — or fails it closed — before validation
    /// (`GHSA-4vqr-427g-5cg7`).
    ///
    /// Narrow on purpose: only in `block` mode, only when the configured
    /// JSON/XML rules would inspect this media type, only for a complete
    /// (non-fragment) representation, AND only when the pristine
    /// pre-`after_proxy` stamp says the origin declared a content coding. An
    /// identity-coded response is already the representation this plugin
    /// validates, so nothing changes for it. Gateway compression is not a
    /// reason to claim: it now runs in the deferred transport-encoding stage,
    /// after this plugin has decided.
    fn enforces_response_body_policy(
        &self,
        ctx: &RequestContext,
        response_content_type: Option<&str>,
        _response_body: &[u8],
    ) -> bool {
        self.enforcement_mode == EnforcementMode::Block
            && self.final_response_body_policy_applies(response_content_type)
            // A status outside `response_status_codes` is never validated, so
            // its encoded body must not be claimed (decoded, or refused for an
            // unsupported coding / exhausted budget) on this plugin's behalf.
            && ctx
                .origin_http_response_status()
                .is_none_or(|status| self.response_status_validated(ctx, status))
            && !ctx
                .metadata
                .contains_key(crate::proxy::ORIGIN_FRAGMENT_RESPONSE_METADATA_KEY)
            && ctx
                .metadata
                .contains_key(crate::proxy::ORIGIN_ENCODED_RESPONSE_METADATA_KEY)
    }

    /// Configuration- and request-only over-approximation, consulted before the
    /// response `Content-Type` is known.
    fn may_enforce_response_body_policy(&self, _ctx: &RequestContext) -> bool {
        self.has_response_validation
    }

    fn enforces_final_client_visible_response_body(&self, _ctx: &RequestContext) -> bool {
        self.has_response_validation
    }

    /// Validate the EXACT representation the client receives.
    ///
    /// This decision used to live in `on_final_response_body`, which runs after
    /// `compression` (priority 4050) has already encoded the body: the UTF-8
    /// conversion below then failed on gzip/Brotli octets and returned
    /// `Continue`, delivering a schema-invalid payload the client decompresses
    /// (`GHSA-4vqr-427g-5cg7`). This phase runs after every semantic transform —
    /// so a later `response_transformer` rule that removes a required field is
    /// caught too (`GHSA-62jg-v563-4q23`) — and before transport encoding.
    async fn finalize_client_visible_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.has_response_validation {
            return PluginResult::Continue;
        }

        // A response schema describes a complete success document. Statuses
        // outside `response_status_codes` (default `2XX`) keep the backend's
        // own status and body, and a `206`/`226` fragment is not a document.
        if !self.response_status_validated(ctx, response_status) {
            return PluginResult::Continue;
        }

        // The ONLY no-body exemptions are the ones HTTP itself defines. An
        // ordinary body-bearing success (200, 201, …) that arrives empty is a
        // validation failure, not an exemption (`GHSA-2vmr-ww8r-mww3`), and the
        // exemption covers an ABSENT body only: a no-content status that somehow
        // carries bytes is still validated.
        if body.is_empty() && synthetic_response_omits_body(&ctx.method, response_status) {
            return PluginResult::Continue;
        }

        // Determine content type from response headers
        let content_type = response_headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");

        // gRPC protobuf response validation, in native or gRPC-Web framing.
        if let Some(representation) = grpc_representation(content_type) {
            if !self.has_protobuf_response_validation {
                return PluginResult::Continue;
            }
            // An empty terminal *error* reply carries a single valid non-zero
            // `grpc-status` in the hook-visible merged header/trailer view and
            // legitimately sends no message. `grpc-status: 0` and
            // malformed/duplicate status values still require a five-byte frame
            // and fail validation below.
            if body.is_empty() && grpc_empty_response_is_terminal_error(response_headers) {
                return PluginResult::Continue;
            }
            // Resolve the gRPC method path from the request, NOT response headers.
            // Backends never echo `:path` in responses, so reading response_headers
            // would always miss per-method `protobuf_method_messages` overrides.
            let grpc_path = Self::grpc_method_path(ctx).into_owned();
            if self.protobuf_dependency_unavailable
                && self.protobuf_targets.response_applies(&grpc_path)
            {
                return self.violation(
                    Some(ctx),
                    Direction::Response,
                    502,
                    "configured protobuf descriptor dependency is unavailable",
                );
            }
            let Some(descriptor) = self.get_response_descriptor(&grpc_path) else {
                return PluginResult::Continue;
            };
            // 502 Bad Gateway: the backend returned a response whose protobuf
            // payload does not match the expected schema — i.e., the upstream
            // produced an invalid response, which is the definition of 502.
            return match self.validate_grpc_representation(
                body,
                representation,
                descriptor,
                Direction::Response,
                Some(response_headers),
                BudgetRef::global(),
            ) {
                Ok(()) => PluginResult::Continue,
                Err(ProtobufFailure::Invalid(msg)) => {
                    self.violation(Some(ctx), Direction::Response, 502, &msg)
                }
                Err(ProtobufFailure::Capacity) => {
                    self.capacity_refusal(Some(ctx), Direction::Response)
                }
            };
        }

        // Mirror of the request side: a protobuf-only instance must not treat an
        // ordinary HTTP response as a governed JSON/XML representation.
        if !self.has_json_response_validation() && !self.has_xml_response_validation {
            return PluginResult::Continue;
        }

        if !content_type_matches(&self.response_content_types, content_type) {
            return PluginResult::Continue;
        }

        let validate_as_json = is_json_like_content_type(content_type);
        let validate_as_xml = !validate_as_json
            && is_xml_like_content_type(content_type)
            && self.has_xml_response_validation;
        if !validate_as_json && !validate_as_xml {
            // Allowlisted media type that no configured rule can inspect.
            return PluginResult::Continue;
        }

        // `log_only` mode never claims the representation gate, so an
        // origin-encoded body it did not get decoded is not observable here.
        if self.enforcement_mode == EnforcementMode::LogOnly
            && response_headers
                .get("content-encoding")
                .is_some_and(|value| super::request_representation::requires_decode_judgment(value))
        {
            record_outcome(ctx, Direction::Response, OUTCOME_UNINSPECTED, None, None);
            return PluginResult::Continue;
        }

        // Convert body bytes to string for validation. A body the configured
        // rules cannot decode is not a passing response.
        let body_str = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => {
                return self.violation(Some(ctx), Direction::Response, 502, NON_UTF8_RESPONSE_BODY);
            }
        };

        // Determine validation type
        let result = if validate_as_json {
            Self::validate_json_body(
                body_str,
                &self.response_required_fields,
                self.response_json_validator.as_ref(),
                Direction::Response,
                Some(&mut ctx.json_scan_memo),
            )
        } else {
            Self::validate_xml_body(
                body_str,
                &self.response_required_xml_elements,
                self.xml_max_entities,
                self.xml_reject_nested_entities,
            )
        };

        match result {
            Ok(()) => PluginResult::Continue,
            // `msg` is already payload-free by construction, so the same string
            // is safe for the client body, for metadata, and for internal
            // tracing; there is no raw-detail development channel to fall back
            // to (`GHSA-5p2h-fq6q-gwh9`).
            Err(msg) => self.violation(Some(ctx), Direction::Response, 502, &msg),
        }
    }

    /// Preserve the established final-body hook contract for direct callers.
    /// The proxy skips this compatibility hook after it has invoked the
    /// authoritative client-visible phase, so production validates once.
    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.finalize_client_visible_response_body(ctx, response_status, response_headers, body)
            .await
    }
}
