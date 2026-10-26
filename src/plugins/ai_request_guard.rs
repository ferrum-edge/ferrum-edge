//! AI Request Guard Plugin
//!
//! Validates and constrains AI/LLM API requests before they reach the backend,
//! preventing expensive mistakes and enforcing organizational policy at the
//! gateway layer.
//!
//! Supports model blocking/allowlisting, max_tokens enforcement (reject or
//! clamp), message count limits, prompt character limits, temperature range
//! validation, system prompt blocking, and required field enforcement.
//!
//! ## Inspection scope
//!
//! The guard inspects plain HTTP JSON `POST` request bodies. The scope is not
//! selected from the client's `Content-Type` alone: a `POST` whose
//! `Content-Type` is missing, non-JSON, or a duplicated/joined value is still
//! buffered and *sniffed*, and a body that opens a JSON object (`{`) is
//! evaluated exactly like a declared JSON body, because many backends parse the
//! body as JSON regardless of the declared media type. Only opaque upload media
//! types (`multipart/*`, `application/octet-stream`, `audio/*`, `image/*`,
//! `video/*`) and framed gRPC are left unbuffered. Bodies are screened for
//! duplicate object members before evaluation (advisory `GHSA-c78j-5w9p-cpq6`),
//! and Anthropic Message Batches bodies (`{"requests": [{"params": ...}]}`) are
//! evaluated entry by entry.
//!
//! Bodies that are not bare
//! JSON wire formats — framed gRPC / gRPC-Web — are passed through unmodified
//! rather than rejected, because the JSON policies fundamentally do not apply to
//! length-prefixed (and possibly base64) wire frames:
//!
//! - **Native gRPC bodies** (`application/grpc`, `application/grpc+json`, …):
//!   these are length-prefixed gRPC wire frames, not bare JSON, so the JSON
//!   policies do not apply. The guard advertises `HTTP_GRPC_PROTOCOLS`, so it
//!   must not 400 valid framed gRPC requests on those routes.
//! - **gRPC-Web bodies** (`application/grpc-web`, `application/grpc-web+json`,
//!   `application/grpc-web-text+json`, …): these are also length-prefixed (and,
//!   for the `-text` variants, base64) gRPC frames, not a bare JSON document.
//!   Normally the `grpc_web` plugin rewrites the content-type to native
//!   `application/grpc` in `on_request_received` before this runs, so the guard
//!   sees native gRPC and skips it. On a proxy that has `ai_request_guard` but
//!   no `grpc_web` plugin the guard would otherwise try to parse the frame as
//!   JSON and reject valid gRPC-Web traffic; it is skipped for the same scope
//!   reason as native gRPC.
//!
//! ### Compressed request bodies — fail closed
//!
//! `ai_request_guard` runs reject-style policy in `before_proxy`, but a
//! `Content-Encoding: gzip|br|…` body is still the compressed (non-UTF-8) bytes
//! at that phase — request decompression (the `compression` plugin's
//! `decompress_request`) only happens in the later `transform_request_body`
//! phase. The guard therefore cannot evaluate JSON policy on a compressed body
//! in `before_proxy`, so it defers: it Continues there (without enforcing
//! policy) and re-runs inspection in `on_final_request_body`, which executes
//! *after* all `transform_request_body` hooks.
//!
//! By `on_final_request_body` time there are two cases:
//!
//! - A `compression` plugin with `decompress_request: true` is co-located: the
//!   body has been decompressed and `Content-Encoding` stripped, so the guard
//!   inspects the now-plaintext JSON and enforces every policy normally.
//! - No decompression happened (no `compression` plugin, or it could not decode
//!   the body): the body is still compressed and `Content-Encoding` is still
//!   present. The guard treats this as an **uninspectable** body and applies
//!   `fail_on_uninspectable_body` — rejecting by default (reason
//!   `compressed_body`). Operators who deliberately forward compressed AI
//!   uploads uninspected must opt out with `fail_on_uninspectable_body: false`.
//!
//! This closes the otherwise trivial bypass where a caller gzips the request
//! body to skip all reject-style policy (model allow/block, token/prompt limits,
//! temperature, system-prompt blocking, required fields). To make
//! `on_final_request_body` run, the guard buffers compressed bodies too (see
//! `should_buffer_request_body`).

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, error};

use super::utils::body_transform::is_json_content_type;
use super::utils::json_escape::escape_json_string;
use super::{Plugin, PluginResult, RequestContext};

/// Prefix for the per-instance metadata marker set in `before_proxy` for every
/// accepted in-scope JSON POST (and every compressed body whose inspection is
/// deferred). Its presence tells `on_final_request_body` to validate the final
/// backend-visible representation after all body transforms have run.
///
/// The full marker key is `{FINAL_INSPECTION_MARKER_PREFIX}{instance_id}` (see
/// [`AiRequestGuard::final_inspection_marker_key`]). It MUST be
/// instance-specific: multiple `ai_request_guard` instances can run on the same
/// proxy (e.g. two proxy/proxy-group configs with different policies, all on the
/// same request). With a single shared marker, the first instance's final hook
/// would consume it and later instances would silently skip their policy. The
/// marker also records the original request scope so a later header transform
/// cannot evade final validation by relabeling the body.
const FINAL_INSPECTION_MARKER_PREFIX: &str = "ai_request_guard.final_inspection.";

/// Process-wide source of unique per-instance ids for the final-inspection
/// marker. Mirrors the `openapi_validator` `INSTANCE_ID_COUNTER` pattern: a
/// monotonically increasing counter assigned once at construction guarantees two
/// `ai_request_guard` instances never collide on the same marker key, regardless
/// of how they are configured. Starts at 1 so a marker key is never the bare
/// prefix.
static FINAL_INSPECTION_MARKER_COUNTER: AtomicU64 = AtomicU64::new(1);

const CONFIG_FIELDS: &[&str] = &[
    "max_tokens_limit",
    "enforce_max_tokens",
    "default_max_tokens",
    "max_choices",
    "supported_schema",
    "strict_schema",
    "allowed_models",
    "blocked_models",
    "require_model_for_model_policy",
    "require_user_field",
    "max_messages",
    "max_prompt_characters",
    "temperature_range",
    "block_system_prompts",
    "system_prompt_aliases",
    "required_metadata_fields",
    "fail_on_uninspectable_body",
];

/// Fixed-cardinality decision metadata. `action` is `reject` (a policy or
/// uninspectable-body rejection) or `modify` (a clamp and/or default-cap
/// injection rewrote the request); `reason` is the matching fixed code (see
/// `docs/plugins.md`). Neither value ever echoes request content, and neither
/// key contains a redacted substring, so both reach transaction logs intact.
const ACTION_METADATA_KEY: &str = "ai_request_guard.action";
const REASON_METADATA_KEY: &str = "ai_request_guard.reason";

/// Anthropic Message Batches envelope: `{"requests": [{"custom_id", "params"}]}`,
/// where each `params` object is a complete Messages request.
const BATCH_REQUESTS_FIELD: &str = "requests";
const BATCH_PARAMS_FIELD: &str = "params";

/// True when `content-type` is a native gRPC media type (`application/grpc`,
/// optionally with a `+subtype`/`;param`/OWS suffix), excluding
/// `application/grpc-web` and bogus suffixes like `application/grpcfoo`.
///
/// Native gRPC bodies are length-prefixed wire frames (1-byte compression flag +
/// 4-byte big-endian length + message), NOT bare JSON documents — even when the
/// content-type is `application/grpc+json`, which `is_json_content_type` matches
/// via its `+json` suffix. Parsing that framing as plain JSON always fails, so
/// the guard must skip framed gRPC bodies rather than reject valid requests.
///
/// Delegates to the canonical, delimiter-aware
/// [`crate::proxy::backend_dispatch::is_native_grpc_content_type`] classifier so
/// this stays aligned with the H1/H2/H3 dispatch path. Allocation-free.
fn is_native_grpc_content_type(content_type: &str) -> bool {
    crate::proxy::backend_dispatch::is_native_grpc_content_type(content_type.as_bytes())
}

/// True when `content-type` is a gRPC-Web media type (`application/grpc-web`,
/// `application/grpc-web+json`, `application/grpc-web-text`,
/// `application/grpc-web-text+json`, optionally with a `;param`/OWS suffix).
///
/// gRPC-Web bodies are length-prefixed gRPC frames (and base64-encoded for the
/// `-text` variants), NOT bare JSON documents — even when the content-type ends
/// in `+json`, which `is_json_content_type` matches via its `+json` suffix.
/// Parsing that framing as plain JSON always fails. In a normal deployment the
/// `grpc_web` plugin rewrites the content-type to native `application/grpc`
/// (which `is_native_grpc_content_type` already skips) before this plugin runs;
/// this check covers the edge config where `ai_request_guard` is present without
/// `grpc_web`, so real gRPC-Web traffic is skipped rather than 400'd as
/// malformed JSON. Case-insensitive on the prefix; allocation-free.
fn is_grpc_web_content_type(content_type: &str) -> bool {
    const PREFIX: &[u8] = b"application/grpc-web";
    let bytes = content_type.as_bytes();
    let Some(prefix) = bytes.get(..PREFIX.len()) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case(PREFIX) {
        return false;
    }
    // Anything after the `application/grpc-web` prefix is an accepted suffix:
    // `-text`, `+json`, `-text+json`, `;charset=...`, OWS, or end-of-value.
    // `application/grpc-website` is the only realistic false positive shape, and
    // it is not a real media type, so the broad accept is safe here.
    true
}

/// True when a JSON-looking `content-type` actually carries framed gRPC or
/// gRPC-Web wire bytes rather than a bare JSON document. Such bodies are never
/// inspectable by the JSON policies and must be skipped (passed through), not
/// rejected. Allocation-free.
fn is_framed_grpc_content_type(content_type: &str) -> bool {
    is_native_grpc_content_type(content_type) || is_grpc_web_content_type(content_type)
}

/// True when a `content-encoding` header marks the request body as encoded with
/// anything other than `identity`.
///
/// Used in two phases. In `before_proxy` the buffered body is still the
/// compressed bytes (request-body decompression — the `compression` plugin's
/// `decompress_request` — only runs later in `transform_request_body`), so a
/// non-`identity` encoding means the guard must defer inspection rather than
/// parse the compressed bytes. In `on_final_request_body` the same check against
/// the final backend headers tells whether decompression actually happened: if
/// the encoding is still present, the body was never decoded and is
/// uninspectable (fail closed). Allocation-free; tolerant of comma-separated
/// encoding lists.
fn has_non_identity_content_encoding(headers: &HashMap<String, String>) -> bool {
    headers.get("content-encoding").is_some_and(|value| {
        value
            .split(',')
            .map(|token| token.trim())
            .any(|token| !token.is_empty() && !token.eq_ignore_ascii_case("identity"))
    })
}

/// How a `POST` body is brought into the guard's scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyScope {
    /// The client declared a JSON media type: the body must be inspectable JSON.
    DeclaredJson,
    /// The declared media type is missing, non-JSON, or a joined/duplicated
    /// value. The body is buffered and evaluated when it opens a JSON object, so
    /// a backend that parses JSON regardless of `Content-Type` cannot receive an
    /// unevaluated AI request.
    Sniffed,
    /// Framed gRPC / gRPC-Web, or an opaque upload media type: never buffered.
    OutOfScope,
}

/// Classifies a `POST` body's scope from its declared `Content-Type`. The
/// client controls that header, so only the media types that are never a bare
/// JSON document (framed gRPC) or are opaque uploads the guard deliberately
/// leaves streaming (`multipart/*`, `application/octet-stream`, `audio/*`,
/// `image/*`, `video/*`) are out of scope; everything else is either declared
/// JSON or sniffed.
fn request_body_scope(content_type: Option<&str>) -> BodyScope {
    let Some(content_type) = content_type else {
        return BodyScope::Sniffed;
    };
    if is_framed_grpc_content_type(content_type) {
        return BodyScope::OutOfScope;
    }
    if is_json_content_type(content_type) {
        return BodyScope::DeclaredJson;
    }
    if is_opaque_upload_content_type(content_type) {
        return BodyScope::OutOfScope;
    }
    BodyScope::Sniffed
}

/// True for opaque upload media types the guard leaves unbuffered. A value that
/// mentions `json` anywhere (for example a joined `multipart/form-data,
/// application/json`) is never treated as opaque. Allocation-free.
fn is_opaque_upload_content_type(content_type: &str) -> bool {
    if content_type
        .as_bytes()
        .windows(4)
        .any(|window| window.eq_ignore_ascii_case(b"json"))
    {
        return false;
    }
    let media_type = content_type
        .split([';', ','])
        .next()
        .unwrap_or_default()
        .trim();
    let starts_with = |prefix: &str| {
        media_type
            .as_bytes()
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
    };
    starts_with("multipart/")
        || starts_with("audio/")
        || starts_with("image/")
        || starts_with("video/")
        || media_type.eq_ignore_ascii_case("application/octet-stream")
}

/// True when a sniffed (non-JSON-labelled) body opens a JSON object, after an
/// optional UTF-8 BOM and JSON whitespace. Only objects are claimed: every AI
/// request schema the guard governs is an object, and a prose or form body
/// never starts with `{`.
fn looks_like_json_object(body: &str) -> bool {
    let body = body.strip_prefix('\u{feff}').unwrap_or(body);
    body.trim_start_matches([' ', '\t', '\n', '\r'])
        .starts_with('{')
}

const TOP_LEVEL_TOKEN_FIELDS: &[&str] = &[
    "max_tokens",
    "max_output_tokens",
    "max_completion_tokens",
    "max_new_tokens",
    "max_tokens_to_sample",
    "maxOutputTokens",
    "maxTokens",
];

/// Gemini's generation container, in both ProtoJSON spellings. ProtoJSON
/// accepts the lowerCamelCase JSON name and the original snake_case proto field
/// name for every field, so `generation_config.max_output_tokens` is exactly as
/// valid as `generationConfig.maxOutputTokens`.
const GEMINI_GENERATION_CONTAINERS: [&str; 2] = ["generationConfig", "generation_config"];
const GEMINI_MAX_OUTPUT_FIELDS: [&str; 2] = ["maxOutputTokens", "max_output_tokens"];
const GEMINI_CANDIDATE_COUNT_FIELDS: [&str; 2] = ["candidateCount", "candidate_count"];

/// Provider-native output-token caps nested in a generation container, as
/// `(container, field, label)`. Every spelling is read by reject, clamp, and the
/// final-body recheck alike.
const NESTED_TOKEN_FIELDS: &[(&str, &str, &str)] = &[
    (
        "generationConfig",
        "maxOutputTokens",
        "generationConfig.maxOutputTokens",
    ),
    (
        "generationConfig",
        "max_output_tokens",
        "generationConfig.max_output_tokens",
    ),
    (
        "generation_config",
        "maxOutputTokens",
        "generation_config.maxOutputTokens",
    ),
    (
        "generation_config",
        "max_output_tokens",
        "generation_config.max_output_tokens",
    ),
    ("inferenceConfig", "maxTokens", "inferenceConfig.maxTokens"),
    (
        "textGenerationConfig",
        "maxTokenCount",
        "textGenerationConfig.maxTokenCount",
    ),
    ("parameters", "max_new_tokens", "parameters.max_new_tokens"),
];

/// Completion-count multipliers bounded by `max_choices`: OpenAI `n` /
/// `best_of`, Cohere `num_generations`, Gemini `candidateCount`, and TGI
/// `parameters.best_of`. `max_tokens_limit` bounds tokens per completion, so
/// these are what bound the number of completions generated per request.
const TOP_LEVEL_CHOICE_FIELDS: &[&str] = &["n", "best_of", "num_generations"];
const NESTED_CHOICE_FIELDS: &[(&str, &str, &str)] = &[
    (
        "generationConfig",
        "candidateCount",
        "generationConfig.candidateCount",
    ),
    (
        "generationConfig",
        "candidate_count",
        "generationConfig.candidate_count",
    ),
    (
        "generation_config",
        "candidateCount",
        "generation_config.candidateCount",
    ),
    (
        "generation_config",
        "candidate_count",
        "generation_config.candidate_count",
    ),
    ("parameters", "best_of", "parameters.best_of"),
];

/// The reading of one request-supplied integer control (an output-token cap or
/// a completion count).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntegerControl {
    /// Absent or JSON `null` (the provider default applies).
    Absent,
    /// A non-negative integral value. Values above `u64::MAX` saturate, which
    /// only ever makes an over-limit request look larger.
    Value(u64),
    /// Present but not a non-negative integer the guard can evaluate.
    Invalid,
}

/// Parses an integer control the way the governed providers do, so a value a
/// backend honors can never be read as "no value" by the guard. JSON integers,
/// integral floats and exponents (`8192.0`, `5e5`), and quoted spellings of
/// those (ProtoJSON's quoted int64 form, which lax Python/pydantic servers also
/// coerce) are numeric; negative, fractional, non-finite, boolean, array,
/// object, and unparseable string values are `Invalid` so the caller fails
/// closed rather than treating them as absent.
fn parse_integer_control(value: Option<&Value>) -> IntegerControl {
    match value {
        None | Some(Value::Null) => IntegerControl::Absent,
        Some(Value::Number(number)) => {
            if let Some(value) = number.as_u64() {
                IntegerControl::Value(value)
            } else if number.is_i64() {
                // A negative integer is never a valid count.
                IntegerControl::Invalid
            } else {
                number
                    .as_f64()
                    .map_or(IntegerControl::Invalid, integral_float_control)
            }
        }
        Some(Value::String(text)) => match text.parse::<u64>() {
            Ok(value) => IntegerControl::Value(value),
            Err(_) => text
                .parse::<f64>()
                .map_or(IntegerControl::Invalid, integral_float_control),
        },
        Some(_) => IntegerControl::Invalid,
    }
}

fn integral_float_control(value: f64) -> IntegerControl {
    if value.is_finite() && value >= 0.0 && value.fract() == 0.0 {
        // `as` saturates finite out-of-range values at `u64::MAX`.
        IntegerControl::Value(value as u64)
    } else {
        IntegerControl::Invalid
    }
}

fn is_valid_integer_control(value: Option<&Value>) -> bool {
    matches!(parse_integer_control(value), IntegerControl::Value(_))
}

/// Present and not JSON `null`.
fn is_present_value(value: Option<&Value>) -> bool {
    value.is_some_and(|value| !value.is_null())
}

/// The largest value across every listed control location. `Err(label)` names
/// the first present location whose value is not a valid integer control.
fn max_integer_control(
    json: &Value,
    top_level: &[&'static str],
    nested: &[(&'static str, &'static str, &'static str)],
) -> Result<Option<u64>, &'static str> {
    let top = top_level.iter().map(|field| (*field, json.get(*field)));
    let nested = nested.iter().map(|(container, field, label)| {
        (
            *label,
            json.get(*container)
                .and_then(|container| container.get(*field)),
        )
    });
    let mut requested: Option<u64> = None;
    for (label, value) in top.chain(nested) {
        match parse_integer_control(value) {
            IntegerControl::Absent => {}
            IntegerControl::Value(value) => {
                requested = Some(requested.map_or(value, |current| current.max(value)));
            }
            IntegerControl::Invalid => return Err(label),
        }
    }
    Ok(requested)
}

/// Gemini ProtoJSON fields that are spelled more than once. ProtoJSON maps both
/// spellings onto one proto field, so a body that carries both is ambiguous: the
/// guard cannot know which one the backend applies, and it fails closed.
///
/// Presence is key existence, deliberately including JSON `null`: a ProtoJSON
/// parser that applies the spellings in order clears the field on a trailing
/// `null` (`{"maxOutputTokens": 128, "max_output_tokens": null}`), so a null
/// alias would silently remove the cap the guard evaluated or required. A
/// single `null` spelling on its own is not ambiguous and stays eligible for
/// ordinary default replacement.
fn gemini_spelling_conflict(json: &Value) -> Option<&'static str> {
    if GEMINI_GENERATION_CONTAINERS
        .iter()
        .all(|container| json.get(*container).is_some())
    {
        return Some("generationConfig / generation_config");
    }
    for container in GEMINI_GENERATION_CONTAINERS {
        let Some(config) = json.get(container) else {
            continue;
        };
        if GEMINI_MAX_OUTPUT_FIELDS
            .iter()
            .all(|field| config.get(*field).is_some())
        {
            return Some("maxOutputTokens / max_output_tokens");
        }
        if GEMINI_CANDIDATE_COUNT_FIELDS
            .iter()
            .all(|field| config.get(*field).is_some())
        {
            return Some("candidateCount / candidate_count");
        }
    }
    None
}

const BUILTIN_SYSTEM_PROMPT_ROLES: &[&str] = &["system", "developer"];

const BUILTIN_SYSTEM_PROMPT_FIELDS: &[&str] = &[
    "instructions",
    "system",
    "systemInstruction",
    "system_instruction",
    "developer",
    "preamble",
];

const TOP_LEVEL_PROMPT_FIELDS: &[&str] = &[
    "prompt",
    "input",
    // TGI / HuggingFace text-generation carries its prompt in the plural
    // `inputs` field. Strict-auto admits these bodies via
    // `looks_like_legacy_completions`, so the prompt-character cap must count
    // them too — otherwise `{"inputs": "<huge prompt>"}` bypasses the limit.
    "inputs",
    // Amazon Titan text-generation carries its prompt in top-level `inputText`
    // (alongside `textGenerationConfig`). Strict-auto admits these bodies via
    // `looks_like_legacy_completions`, so the prompt-character cap must count
    // `inputText` too — otherwise `{"inputText": "<huge prompt>"}` bypasses it.
    "inputText",
    "instructions",
    "system",
    "systemInstruction",
    "system_instruction",
    "message",
    "preamble",
    "context",
];

/// Action to take when max_tokens exceeds the limit.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MaxTokensAction {
    Reject,
    Clamp,
}

/// Request schema family the guard should accept when strict schema checking is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedSchema {
    ChatCompletions,
    Responses,
    ProviderNative,
    /// Operator-bound Amazon Bedrock Converse dialect. Unlike the broad
    /// `ProviderNative` family, it tells default-cap injection that the backend
    /// is Converse, so a body without `inferenceConfig` still receives
    /// `inferenceConfig.maxTokens` (and never an unsupported top-level cap).
    BedrockConverse,
    Auto,
}

pub struct AiRequestGuard {
    max_tokens_limit: Option<u64>,
    enforce_max_tokens: MaxTokensAction,
    default_max_tokens: Option<u64>,
    max_choices: Option<u64>,
    supported_schema: SupportedSchema,
    strict_schema: bool,
    allowed_models: HashSet<String>,
    blocked_models: HashSet<String>,
    require_model_for_model_policy: bool,
    require_user_field: bool,
    max_messages: Option<u64>,
    max_prompt_characters: Option<u64>,
    temperature_range: Option<(f64, f64)>,
    block_system_prompts: bool,
    system_prompt_aliases: HashSet<String>,
    required_metadata_fields: Vec<String>,
    fail_on_uninspectable_body: bool,
    /// True when the plugin needs to modify the request body (clamp or inject defaults).
    needs_body_transform: bool,
    /// True when any configured policy needs the request body to be inspected.
    requires_request_body: bool,
    /// Instance-specific metadata key recording that the request entered the
    /// guard's JSON POST scope. The final-body hook consumes it after validating
    /// the backend-visible representation.
    final_inspection_marker: String,
}

impl AiRequestGuard {
    pub fn new(config: &Value) -> Result<Self, String> {
        let Some(config_object) = config.as_object() else {
            return Err("ai_request_guard: config must be an object".to_string());
        };

        if let Some(unknown) = config_object
            .keys()
            .find(|field| !CONFIG_FIELDS.contains(&field.as_str()))
        {
            return Err(format!(
                "ai_request_guard: unknown config field {unknown:?}; allowed fields: `{}`",
                CONFIG_FIELDS.join("`, `")
            ));
        }

        let max_tokens_limit = optional_u64(config, "max_tokens_limit")?;
        let enforce_max_tokens = match optional_string(config, "enforce_max_tokens")?
            .unwrap_or("reject")
        {
            "reject" => MaxTokensAction::Reject,
            "clamp" => MaxTokensAction::Clamp,
            other => {
                return Err(format!(
                    "ai_request_guard: `enforce_max_tokens` must be one of `reject` or `clamp`, got: {other:?}"
                ));
            }
        };
        let default_max_tokens = optional_u64(config, "default_max_tokens")?;
        let max_choices = optional_u64(config, "max_choices")?;
        let supported_schema = match optional_string(config, "supported_schema")?.unwrap_or("auto")
        {
            "chat_completions" => SupportedSchema::ChatCompletions,
            "responses" => SupportedSchema::Responses,
            "provider_native" => SupportedSchema::ProviderNative,
            "bedrock_converse" => SupportedSchema::BedrockConverse,
            "auto" => SupportedSchema::Auto,
            other => {
                return Err(format!(
                    "ai_request_guard: `supported_schema` must be one of `chat_completions`, `responses`, `provider_native`, `bedrock_converse`, or `auto`, got: {other:?}"
                ));
            }
        };
        let strict_schema = optional_bool(config, "strict_schema")?.unwrap_or(false);

        // Reject a contradictory cost-control config: the injected default must
        // not exceed the configured cap. `default_max_tokens` is injected when a
        // request omits all token fields and is never clamped, so a default
        // above `max_tokens_limit` would make the gateway itself emit a
        // `max_tokens` value that violates the operator's own limit. Fail fast
        // at construction, consistent with the temperature_range validation.
        if let (Some(default), Some(limit)) = (default_max_tokens, max_tokens_limit)
            && default > limit
        {
            return Err(format!(
                "ai_request_guard: `default_max_tokens` (\"{default}\") must be <= `max_tokens_limit` (\"{limit}\")"
            ));
        }

        let allowed_models = optional_lowercase_set(config, "allowed_models")?.unwrap_or_default();
        let blocked_models = optional_lowercase_set(config, "blocked_models")?.unwrap_or_default();
        let require_model_for_model_policy =
            optional_bool(config, "require_model_for_model_policy")?.unwrap_or(true);

        let require_user_field = optional_bool(config, "require_user_field")?.unwrap_or(false);
        let max_messages = optional_u64(config, "max_messages")?;
        let max_prompt_characters = optional_u64(config, "max_prompt_characters")?;

        // Parse temperature_range with strict validation. A misconfigured
        // `[max, min]` or `[NaN, x]` would silently reject every request or
        // silently accept all of them (NaN comparisons always return false),
        // so reject these inputs at construction time rather than producing
        // a plugin that looks active but behaves incorrectly.
        let temperature_range = if let Some(arr) = config.get("temperature_range") {
            let Some(arr) = arr.as_array() else {
                return Err(
                    "ai_request_guard: `temperature_range` must be an array of two numbers"
                        .to_string(),
                );
            };
            if arr.len() != 2 {
                return Err(format!(
                    "ai_request_guard: `temperature_range` must have exactly 2 elements, got {}",
                    arr.len()
                ));
            }
            let Some(min) = arr[0].as_f64() else {
                return Err("ai_request_guard: `temperature_range[0]` must be a number".to_string());
            };
            let Some(max) = arr[1].as_f64() else {
                return Err("ai_request_guard: `temperature_range[1]` must be a number".to_string());
            };
            if !min.is_finite() || !max.is_finite() {
                return Err(format!(
                    "ai_request_guard: `temperature_range` bounds must be finite, got [\"{min}\", \"{max}\"]"
                ));
            }
            if min > max {
                return Err(format!(
                    "ai_request_guard: `temperature_range` min must be <= max, got [\"{min}\", \"{max}\"]"
                ));
            }
            Some((min, max))
        } else {
            None
        };

        let block_system_prompts = optional_bool(config, "block_system_prompts")?.unwrap_or(false);
        let system_prompt_aliases =
            optional_lowercase_set(config, "system_prompt_aliases")?.unwrap_or_default();

        let required_metadata_fields =
            optional_string_vec(config, "required_metadata_fields")?.unwrap_or_default();
        let fail_on_uninspectable_body =
            optional_bool(config, "fail_on_uninspectable_body")?.unwrap_or(true);

        let needs_body_transform = (max_tokens_limit.is_some()
            && enforce_max_tokens == MaxTokensAction::Clamp)
            || default_max_tokens.is_some();
        let requires_request_body = needs_body_transform
            || max_tokens_limit.is_some()
            || max_choices.is_some()
            || !allowed_models.is_empty()
            || !blocked_models.is_empty()
            || require_user_field
            || max_messages.is_some()
            || max_prompt_characters.is_some()
            || temperature_range.is_some()
            || block_system_prompts
            || strict_schema
            || !required_metadata_fields.is_empty();

        // Reject configs that would make the plugin a no-op: at least one
        // policy must be configured for the plugin to do anything useful.
        if !requires_request_body {
            return Err("ai_request_guard: at least one policy must be configured \
                 (max_tokens_limit, default_max_tokens, max_choices, allowed_models, blocked_models, \
                 require_user_field, max_messages, max_prompt_characters, \
                 temperature_range, block_system_prompts, strict_schema, or \
                 required_metadata_fields)"
                .to_string());
        }

        // Assign a unique per-instance final-inspection marker so multiple guard
        // instances on the same proxy cannot consume each other's scope marker.
        let instance_id = FINAL_INSPECTION_MARKER_COUNTER.fetch_add(1, Ordering::Relaxed);
        let final_inspection_marker = format!("{FINAL_INSPECTION_MARKER_PREFIX}{instance_id}");

        Ok(Self {
            max_tokens_limit,
            enforce_max_tokens,
            default_max_tokens,
            max_choices,
            supported_schema,
            strict_schema,
            allowed_models,
            blocked_models,
            require_model_for_model_policy,
            require_user_field,
            max_messages,
            max_prompt_characters,
            temperature_range,
            block_system_prompts,
            system_prompt_aliases,
            required_metadata_fields,
            fail_on_uninspectable_body,
            needs_body_transform,
            requires_request_body,
            final_inspection_marker,
        })
    }

    /// The instance-specific metadata key this guard uses to carry the original
    /// JSON POST scope into `on_final_request_body`. Exposed so tests can observe
    /// or simulate the final inspection for this exact instance; two instances
    /// always return distinct keys.
    ///
    /// Only the external test crate (`tests/unit/plugins/ai_request_guard_tests.rs`)
    /// calls this — production code reads `self.final_inspection_marker`
    /// directly in `before_proxy` / `on_final_request_body`. The binary crate
    /// only ever uses `AiRequestGuard` as a `dyn Plugin`, so its dead-code pass
    /// (which can't see the separate test crate) would otherwise flag this
    /// accessor. `#[allow(dead_code)]` mirrors the established pattern for
    /// test-only `pub(crate)` accessors elsewhere in `src/plugins/`.
    #[allow(dead_code)]
    pub fn final_inspection_marker_key(&self) -> &str {
        &self.final_inspection_marker
    }

    /// Validate the request body JSON. A Message Batches envelope is validated
    /// entry by entry (each `params` object is a complete request); every other
    /// body is validated as one request. `path_models` are the models the
    /// request path selects (see [`path_model_candidates`]).
    fn validate(&self, json: &Value, path_models: &[String]) -> Result<(), PolicyRejection> {
        for_each_request_document(json, |request| self.validate_request(request, path_models))
    }

    /// True when any configured policy reads generation controls, so Gemini
    /// ProtoJSON double spellings must be refused as ambiguous.
    fn inspects_generation_controls(&self) -> bool {
        self.max_tokens_limit.is_some()
            || self.default_max_tokens.is_some()
            || self.max_choices.is_some()
            || self.temperature_range.is_some()
    }

    fn has_model_policy(&self) -> bool {
        !self.allowed_models.is_empty() || !self.blocked_models.is_empty()
    }

    /// The models this request's path selects, when model policy is configured.
    fn path_models(&self, path: &str) -> Vec<String> {
        if !self.has_model_policy() {
            return Vec::new();
        }
        path_model_candidates(path)
    }

    fn check_model_name(&self, model: &str) -> Result<(), PolicyRejection> {
        let model_lower = model.to_lowercase();

        if !self.blocked_models.is_empty() && self.blocked_models.contains(model_lower.as_str()) {
            return Err(PolicyRejection::new(
                "model_blocked",
                "Model not allowed",
                format!(
                    "Model '{}' is blocked by gateway policy",
                    escape_json_string(model)
                ),
            ));
        }

        if !self.allowed_models.is_empty() && !self.allowed_models.contains(model_lower.as_str()) {
            return Err(PolicyRejection::new(
                "model_not_allowed",
                "Model not allowed",
                format!(
                    "Model '{}' is not in the allowed models list",
                    escape_json_string(model)
                ),
            ));
        }
        Ok(())
    }

    /// Validate one request document (the whole body, or one batch entry's
    /// `params`).
    fn validate_request(
        &self,
        json: &Value,
        path_models: &[String],
    ) -> Result<(), PolicyRejection> {
        // Optional schema admission. In non-strict mode, the guard still applies
        // every configured policy to any fields it recognizes, preserving the
        // historical pass-through behavior for unusual provider payloads.
        if self.strict_schema && !schema_matches(json, self.supported_schema) {
            return Err(PolicyRejection::new(
                "unsupported_schema",
                "Unsupported AI request schema",
                schema_rejection_details(self.supported_schema),
            ));
        }

        if self.inspects_generation_controls()
            && let Some(conflict) = gemini_spelling_conflict(json)
        {
            return Err(PolicyRejection::new(
                "conflicting_fields",
                "Conflicting field spellings",
                format!("'{conflict}' are both present; send a single spelling"),
            ));
        }

        // Model blocking/allowlisting. A model the request path selects
        // (Gemini/Vertex `models/{model}:generateContent`, Bedrock
        // `model/{modelId}/converse`, Azure `openai/deployments/{deployment}`)
        // is checked as well as the body `model`: both must satisfy policy, and
        // a path model satisfies the "model must be present" requirement for
        // bodies that legitimately omit `model`.
        if self.has_model_policy() {
            for path_model in path_models {
                self.check_model_name(path_model)?;
            }
            match json.get("model") {
                Some(Value::String(model)) => {
                    // A present-but-empty/whitespace string is supplied but
                    // unusable — same shape as a non-string value below, so it
                    // shares the "present but invalid" title rather than the
                    // "genuinely absent" one. The opt-out
                    // (`require_model_for_model_policy: false`) only tolerates a
                    // *genuinely absent* model; a present-but-invalid value is
                    // still rejected so the allowlist/blocklist can't be bypassed
                    // by sending a malformed `model`.
                    if model.trim().is_empty() {
                        return Err(model_field_rejection(
                            "invalid_model",
                            INVALID_MODEL_FIELD_TITLE,
                        ));
                    }
                    self.check_model_name(model)?;
                }
                // Present but wrong-typed (number/bool/array/object/null):
                // the field exists, so report it as invalid rather than
                // missing, sharing the title with the empty-string arm above.
                // This rejects regardless of `require_model_for_model_policy` —
                // the opt-out only relaxes the *missing-field* case, never a
                // present-but-malformed value that would otherwise skip the
                // allowlist/blocklist.
                Some(_) => {
                    return Err(model_field_rejection(
                        "invalid_model",
                        INVALID_MODEL_FIELD_TITLE,
                    ));
                }
                None if path_models.is_empty() && self.require_model_for_model_policy => {
                    return Err(model_field_rejection(
                        "missing_model",
                        MISSING_MODEL_FIELD_TITLE,
                    ));
                }
                None => {}
            }
        }

        // Output-token caps. A present cap the guard cannot read as a
        // non-negative integer fails closed in both reject and clamp modes (and
        // under `default_max_tokens`), so a spelling the backend honors can never
        // be mistaken for "no cap requested". Over-limit clamping is handled in
        // the transform pass.
        if self.max_tokens_limit.is_some() || self.default_max_tokens.is_some() {
            let requested = max_requested_tokens(json).map_err(|field| {
                PolicyRejection::new(
                    "invalid_max_tokens",
                    "Invalid max_tokens field",
                    format!("'{field}' must be a non-negative integer"),
                )
            })?;
            if self.enforce_max_tokens == MaxTokensAction::Reject
                && let Some(limit) = self.max_tokens_limit
                && let Some(req) = requested
                && req > limit
            {
                return Err(PolicyRejection::new(
                    "max_tokens_exceeded",
                    "max_tokens exceeds limit",
                    format!("Requested {} tokens, maximum allowed is {}", req, limit),
                ));
            }
        }

        // Completion-count multipliers (`n`, `best_of`, ...).
        if let Some(max_choices) = self.max_choices {
            let requested =
                max_integer_control(json, TOP_LEVEL_CHOICE_FIELDS, NESTED_CHOICE_FIELDS).map_err(
                    |field| {
                        PolicyRejection::new(
                            "invalid_choice_count",
                            "Invalid completion count field",
                            format!("'{field}' must be a non-negative integer"),
                        )
                    },
                )?;
            // Every request that generates output asks for at least one
            // completion: an omitted count is the provider default of one, and
            // an explicit `0` is not a valid "no output" request (providers
            // refuse or treat it as one). Counting both as one makes
            // `max_choices: 0` refuse every request rather than admit an
            // implicit single completion.
            let requested = requested.unwrap_or(1).max(1);
            if requested > max_choices {
                return Err(PolicyRejection::new(
                    "max_choices_exceeded",
                    "Too many completions requested",
                    format!(
                        "Request asks for {requested} completions, maximum allowed is {max_choices}"
                    ),
                ));
            }
        }

        // Message count
        if let Some(max_msgs) = self.max_messages {
            let count = count_message_entries(json);
            if count > max_msgs {
                return Err(PolicyRejection::new(
                    "too_many_messages",
                    "Too many messages",
                    format!(
                        "Request contains {} messages, maximum allowed is {}",
                        count, max_msgs
                    ),
                ));
            }
        }

        // Prompt character limit
        if let Some(max_chars) = self.max_prompt_characters {
            let total_chars = count_prompt_characters(json);
            if total_chars > max_chars {
                return Err(PolicyRejection::new(
                    "prompt_too_long",
                    "Prompt too long",
                    format!(
                        "Total prompt length is {} characters, maximum allowed is {}",
                        total_chars, max_chars
                    ),
                ));
            }
        }

        // Temperature range. Validate every supported alias rather than stopping
        // at the top level: Gemini and Bedrock place this setting in their native
        // generation containers. Present-but-numeric-invalid values and
        // conflicting aliases fail closed so a backend cannot select a value the
        // guard did not actually evaluate.
        if let Some((min_temp, max_temp)) = self.temperature_range {
            let mut observed: Option<(&'static str, f64)> = None;
            for (field, value) in [
                ("temperature", json.get("temperature")),
                (
                    "generationConfig.temperature",
                    json.get("generationConfig")
                        .and_then(|container| container.get("temperature")),
                ),
                (
                    "generation_config.temperature",
                    json.get("generation_config")
                        .and_then(|container| container.get("temperature")),
                ),
                (
                    "inferenceConfig.temperature",
                    json.get("inferenceConfig")
                        .and_then(|container| container.get("temperature")),
                ),
            ] {
                let Some(value) = value else {
                    continue;
                };
                let Some(temp) = value.as_f64().filter(|value| value.is_finite()) else {
                    return Err(PolicyRejection::new(
                        "invalid_temperature",
                        "Invalid temperature",
                        format!("'{field}' must be a finite number"),
                    ));
                };
                if let Some((previous_field, previous)) = observed
                    && previous != temp
                {
                    return Err(PolicyRejection::new(
                        "conflicting_temperature",
                        "Conflicting temperature fields",
                        format!(
                            "'{previous_field}' and '{field}' specify different temperature values"
                        ),
                    ));
                }
                observed = Some((field, temp));
                if temp < min_temp || temp > max_temp {
                    return Err(PolicyRejection::new(
                        "temperature_out_of_range",
                        "Temperature out of range",
                        format!(
                            "Temperature {temp} in '{field}' is outside allowed range [{min_temp}, {max_temp}]"
                        ),
                    ));
                }
            }
        }

        // System prompt blocking
        if self.block_system_prompts && contains_system_prompt(json, &self.system_prompt_aliases) {
            return Err(PolicyRejection::new(
                "system_prompt",
                "System prompts not allowed",
                "Requests with system, developer, instructions, aliased system-prompt fields, or Azure 'On Your Data' data_sources[].parameters.role_information are blocked by gateway policy",
            ));
        }

        // Require user field: a usable audit identity, so a present-but-null or
        // blank `user` cannot satisfy the requirement.
        if self.require_user_field
            && !matches!(json.get("user"), Some(Value::String(user)) if !user.trim().is_empty())
        {
            return Err(PolicyRejection::new(
                "missing_user",
                "Missing required field",
                "The 'user' field must be a non-empty string for audit trail purposes",
            ));
        }

        // Required metadata fields: present, not `null`, and not a blank string.
        for field in &self.required_metadata_fields {
            if !is_supplied_metadata_value(json.get(field.as_str())) {
                return Err(PolicyRejection::new(
                    "missing_metadata_field",
                    "Missing required field",
                    format!(
                        "Required field '{}' is missing, null, or empty in the request",
                        escape_json_string(field)
                    ),
                ));
            }
        }

        Ok(())
    }

    /// Validate the final backend-visible representation. Clamp/default policy
    /// normally mutates the body before this phase, but a later body transformer
    /// can overwrite or remove those caps. The final hook cannot replace bytes,
    /// so it fails closed if the final representation would require another
    /// clamp or default injection.
    fn validate_final_body(
        &self,
        json: &Value,
        path_models: &[String],
    ) -> Result<(), PolicyRejection> {
        self.validate(json, path_models)?;
        for_each_request_document(json, |request| self.validate_final_caps(request))
    }

    fn validate_final_caps(&self, json: &Value) -> Result<(), PolicyRejection> {
        if self.enforce_max_tokens == MaxTokensAction::Clamp
            && let Some(limit) = self.max_tokens_limit
            && let Ok(Some(requested)) = max_requested_tokens(json)
            && requested > limit
        {
            return Err(PolicyRejection::new(
                "max_tokens_exceeded",
                "max_tokens exceeds limit after request transforms",
                format!("Final request asks for {requested} tokens, maximum allowed is {limit}"),
            ));
        }

        if self.default_max_tokens.is_some()
            && !has_required_default_token_cap(json, self.supported_schema)
        {
            return Err(PolicyRejection::new(
                "missing_max_tokens",
                "Missing output token cap after request transforms",
                "A later request-body transform removed the output token cap required by gateway policy",
            ));
        }

        Ok(())
    }

    /// Apply clamp and default-cap injection to every request document,
    /// reporting which of the two changed anything.
    fn apply_token_mutations(&self, json: &mut Value) -> TokenMutation {
        let mut mutation = TokenMutation::default();
        for_each_request_document_mut(json, |request| {
            if let Some(limit) = self.max_tokens_limit
                && self.enforce_max_tokens == MaxTokensAction::Clamp
            {
                mutation.clamped |= clamp_max_token_fields(request, limit);
            }
            if let Some(default) = self.default_max_tokens {
                mutation.injected |=
                    inject_default_max_tokens(request, default, self.supported_schema);
            }
        });
        mutation
    }

    fn transform_scoped_json_body(&self, ctx: &mut RequestContext, body: &[u8]) -> Option<Vec<u8>> {
        let mut json: Value = serde_json::from_slice(body).ok()?;
        let mutation = self.apply_token_mutations(&mut json);
        if !mutation.modified() {
            return None;
        }
        let transformed = serde_json::to_vec(&json).ok()?;
        record_token_mutation(ctx, mutation);
        Some(transformed)
    }

    fn handle_uninspectable_body(
        &self,
        ctx: &mut RequestContext,
        reason: &'static str,
        status_code: u16,
        // Lazy so a per-request `format!` (e.g. the serde parse error on the
        // `malformed_json` path) is only built when a log line that consumes it
        // actually fires. The detail is for logs only — never returned to the
        // client (see `client_details` below) — so on a busy AI proxy a client
        // looping malformed JSON does not pay an allocation per request when the
        // relevant level is disabled. Honors this module's log-flood / cost
        // amplification rationale.
        details: impl FnOnce() -> String,
    ) -> PluginResult {
        let action = if self.fail_on_uninspectable_body {
            "reject"
        } else {
            "allow"
        };
        ctx.metadata.insert(
            "ai_request_guard.uninspectable_body".to_string(),
            "true".to_string(),
        );
        ctx.metadata.insert(
            "ai_request_guard.uninspectable_body_reason".to_string(),
            reason.to_string(),
        );
        ctx.metadata.insert(
            "ai_request_guard.uninspectable_body_action".to_string(),
            action.to_string(),
        );

        // `missing_buffered_body` is an internal plugin-runner inconsistency
        // (the body should always have been buffered before this hook), not a
        // client-controllable input. Always surface it at `error!` so a real
        // plumbing regression cannot hide — even when compatibility mode lets
        // the request pass through. All other reasons are attacker-influenceable
        // 400s, so they log at `debug!` to avoid a log-flood / cost amplification
        // vector.
        let is_internal_inconsistency = reason == "missing_buffered_body";

        // Materialize the detail string at most once, and only when a log line
        // will actually consume it: the internal-inconsistency path always logs
        // at `error!`; the client-caused paths log at `debug!`, so skip the
        // closure (and its `format!`) entirely when DEBUG is disabled.
        let detail_str = if is_internal_inconsistency || tracing::enabled!(tracing::Level::DEBUG) {
            Some(details())
        } else {
            None
        };
        let detail_display = detail_str.as_deref().unwrap_or("");

        if !self.fail_on_uninspectable_body {
            if is_internal_inconsistency {
                error!(
                    reason,
                    action,
                    status_code,
                    details = %detail_display,
                    "ai_request_guard: internal inconsistency - uninspectable request body allowed by compatibility mode"
                );
            } else {
                debug!(
                    reason,
                    action,
                    status_code,
                    details = %detail_display,
                    "ai_request_guard: uninspectable request body allowed by compatibility mode"
                );
            }
            return PluginResult::Continue;
        }

        if is_internal_inconsistency {
            error!(
                reason,
                action,
                status_code,
                details = %detail_display,
                "ai_request_guard: rejecting uninspectable request body due to internal inconsistency"
            );
        } else {
            debug!(
                reason,
                action,
                status_code,
                details = %detail_display,
                "ai_request_guard: rejecting uninspectable request body"
            );
        }
        let client_details = match reason {
            "empty_body" => "JSON request body is empty",
            "non_utf8_body" => "JSON request body is not valid UTF-8",
            "malformed_json" => "Malformed JSON request body",
            "ambiguous_json" => {
                "Ambiguous JSON request body (duplicate object member names or an over-budget document)"
            }
            "compressed_body" => "Compressed request body could not be inspected",
            _ => "Request body could not be inspected",
        };
        ctx.metadata
            .insert(ACTION_METADATA_KEY.to_string(), "reject".to_string());
        ctx.metadata.insert(
            REASON_METADATA_KEY.to_string(),
            "uninspectable_body".to_string(),
        );
        PluginResult::Reject {
            status_code,
            body: serde_json::json!({
                "error": "Request body uninspectable",
                "details": client_details,
            })
            .to_string(),
            headers: HashMap::new(),
        }
    }
}

/// Rejection title for a `model` field that is entirely absent from the body.
const MISSING_MODEL_FIELD_TITLE: &str = "Missing required model field";
/// Rejection title for a `model` field that is present but unusable — an empty/
/// whitespace string or a non-string value. Both arms share this title so the
/// "present but invalid" responses cannot drift apart.
const INVALID_MODEL_FIELD_TITLE: &str = "Invalid model field";

/// Build the rejection for a `model` field that violates the required model
/// policy. `error` is the title; the shared `details` string documents the
/// constraint for both the missing and present-but-invalid cases.
fn model_field_rejection(reason: &'static str, error: &'static str) -> PolicyRejection {
    PolicyRejection::new(
        reason,
        error,
        "The 'model' field must be a non-empty string when model policy is configured",
    )
}

/// One policy rejection: a fixed-cardinality `reason` code published as
/// decision metadata, plus the client-facing `error` title and `details`.
struct PolicyRejection {
    reason: &'static str,
    error: String,
    details: String,
}

impl PolicyRejection {
    fn new(reason: &'static str, error: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            reason,
            error: error.into(),
            details: details.into(),
        }
    }
}

/// Record a policy rejection as decision metadata and build the 400 response.
fn policy_reject(
    ctx: &mut RequestContext,
    rejection: PolicyRejection,
    stage: &'static str,
) -> PluginResult {
    debug!(
        reason = rejection.reason,
        stage, "ai_request_guard: validation failed: {} - {}", rejection.error, rejection.details
    );
    ctx.metadata
        .insert(ACTION_METADATA_KEY.to_string(), "reject".to_string());
    ctx.metadata.insert(
        REASON_METADATA_KEY.to_string(),
        rejection.reason.to_string(),
    );
    PluginResult::Reject {
        status_code: 400,
        body: serde_json::json!({
            "error": rejection.error,
            "details": rejection.details,
        })
        .to_string(),
        headers: HashMap::new(),
    }
}

/// Which token mutations one pass applied.
#[derive(Debug, Clone, Copy, Default)]
struct TokenMutation {
    clamped: bool,
    injected: bool,
}

impl TokenMutation {
    fn modified(self) -> bool {
        self.clamped || self.injected
    }

    fn reason(self) -> Option<&'static str> {
        match (self.clamped, self.injected) {
            (true, true) => Some("max_tokens_clamped_and_default_injected"),
            (true, false) => Some("max_tokens_clamped"),
            (false, true) => Some("default_max_tokens_injected"),
            (false, false) => None,
        }
    }
}

/// Record a clamp / default-cap rewrite as decision metadata.
fn record_token_mutation(ctx: &mut RequestContext, mutation: TokenMutation) {
    if let Some(reason) = mutation.reason() {
        ctx.metadata
            .insert(ACTION_METADATA_KEY.to_string(), "modify".to_string());
        ctx.metadata
            .insert(REASON_METADATA_KEY.to_string(), reason.to_string());
    }
}

/// Present, not `null`, and not a blank string. Other value types are accepted:
/// `required_metadata_fields` constrains presence, not type.
fn is_supplied_metadata_value(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::String(text)) => !text.trim().is_empty(),
        Some(_) => true,
    }
}

/// The request's `requests[]` entries when the body is an Anthropic Message
/// Batches envelope: a top-level `requests` array in which at least one entry
/// carries `params`. Any other body is one request.
fn batch_request_entries(json: &Value) -> Option<&[Value]> {
    let entries = json.get(BATCH_REQUESTS_FIELD)?.as_array()?;
    entries
        .iter()
        .any(|entry| entry.get(BATCH_PARAMS_FIELD).is_some())
        .then_some(entries.as_slice())
}

/// True when a batch envelope carries top-level members besides `requests`. A
/// canonical envelope has none; when present, the top level is also evaluated
/// as a request so a request field cannot sit beside the batch unevaluated.
fn batch_envelope_has_extra_members(json: &Value) -> bool {
    json.as_object().is_some_and(|object| object.len() > 1)
}

/// Run `check` over every request document: each batch entry's `params` (plus
/// the envelope itself when it carries other members), or the body itself. A
/// batch entry without a `params` object fails closed rather than being
/// skipped.
fn for_each_request_document(
    json: &Value,
    mut check: impl FnMut(&Value) -> Result<(), PolicyRejection>,
) -> Result<(), PolicyRejection> {
    let Some(entries) = batch_request_entries(json) else {
        return check(json);
    };
    if batch_envelope_has_extra_members(json) {
        check(json)?;
    }
    for entry in entries {
        let Some(params) = entry
            .get(BATCH_PARAMS_FIELD)
            .filter(|params| params.is_object())
        else {
            return Err(PolicyRejection::new(
                "invalid_batch_entry",
                "Invalid batch request entry",
                "Every Message Batches 'requests[]' entry must carry a 'params' object",
            ));
        };
        check(params)?;
    }
    Ok(())
}

/// Mutable counterpart of [`for_each_request_document`] for clamp/default
/// rewrites. Entries without a `params` object are left untouched; validation
/// rejects them.
fn for_each_request_document_mut(json: &mut Value, mut apply: impl FnMut(&mut Value)) {
    if batch_request_entries(json).is_none() {
        apply(json);
        return;
    }
    if batch_envelope_has_extra_members(json) {
        apply(json);
    }
    if let Some(entries) = json
        .get_mut(BATCH_REQUESTS_FIELD)
        .and_then(Value::as_array_mut)
    {
        for entry in entries {
            if let Some(params) = entry
                .get_mut(BATCH_PARAMS_FIELD)
                .filter(|params| params.is_object())
            {
                apply(params);
            }
        }
    }
}

/// Models selected by the request path, for providers that carry the model in
/// the URL rather than the body. `path` is the canonical policy path
/// (`RequestContext::path`), already percent-decoded once and free of encoded
/// separators. Recognized shapes, matched per segment (ASCII
/// case-insensitively) anywhere in the path so a route prefix does not hide
/// them:
///
/// - Gemini / Vertex: `.../models/{model}:{method}` and
///   `.../tunedModels/{model}:{method}`.
/// - Bedrock runtime: `.../model/{modelId}/{converse|converse-stream|invoke|
///   invoke-with-response-stream|count-tokens}`. A model id containing `/`
///   (an unencoded ARN) is rejoined.
/// - Azure OpenAI: `.../openai/deployments/{deployment}/...`; the deployment
///   name is what the operator lists in `allowed_models` / `blocked_models`.
///
/// Every match is returned, so a path that names several models must satisfy
/// policy for all of them.
fn path_model_candidates(path: &str) -> Vec<String> {
    let path = path.split_once('?').map_or(path, |(path, _query)| path);
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let mut models = Vec::new();
    for (index, segment) in segments.iter().enumerate() {
        if segment.eq_ignore_ascii_case("models") || segment.eq_ignore_ascii_case("tunedModels") {
            if let Some((model, _method)) = segments
                .get(index + 1)
                .and_then(|next| next.split_once(':'))
            {
                push_path_model(&mut models, model);
            }
        } else if segment.eq_ignore_ascii_case("model") {
            if let Some(rest) = segments.get(index + 1..)
                && let Some(action) = rest.iter().copied().rposition(is_bedrock_model_action)
                && let Some(model_segments) = rest.get(..action)
                && !model_segments.is_empty()
            {
                push_path_model(&mut models, &model_segments.join("/"));
            }
        } else if segment.eq_ignore_ascii_case("deployments")
            && index
                .checked_sub(1)
                .and_then(|previous| segments.get(previous))
                .is_some_and(|previous| previous.eq_ignore_ascii_case("openai"))
            && let Some(deployment) = segments.get(index + 1)
        {
            push_path_model(&mut models, deployment);
        }
    }
    models
}

fn push_path_model(models: &mut Vec<String>, model: &str) {
    let model = model.trim();
    if !model.is_empty() {
        models.push(model.to_string());
    }
}

fn is_bedrock_model_action(segment: &str) -> bool {
    [
        "converse",
        "converse-stream",
        "invoke",
        "invoke-with-response-stream",
        "count-tokens",
    ]
    .iter()
    .any(|action| segment.eq_ignore_ascii_case(action))
}

fn schema_matches(json: &Value, supported_schema: SupportedSchema) -> bool {
    match supported_schema {
        SupportedSchema::ChatCompletions => looks_like_chat_completions(json),
        SupportedSchema::Responses => looks_like_responses(json),
        SupportedSchema::ProviderNative => looks_like_provider_native(json),
        SupportedSchema::BedrockConverse => looks_like_bedrock_converse(json),
        SupportedSchema::Auto => {
            looks_like_chat_completions(json)
                || looks_like_responses(json)
                || looks_like_provider_native(json)
                || looks_like_legacy_completions(json)
        }
    }
}

fn schema_rejection_details(supported_schema: SupportedSchema) -> String {
    let expected = match supported_schema {
        SupportedSchema::ChatCompletions => "OpenAI Chat Completions",
        SupportedSchema::Responses => "OpenAI Responses API",
        SupportedSchema::ProviderNative => "provider-native AI",
        SupportedSchema::BedrockConverse => "Amazon Bedrock Converse",
        SupportedSchema::Auto => "a supported AI",
    };
    format!("Request body does not match {expected} schema coverage")
}

fn looks_like_chat_completions(json: &Value) -> bool {
    json.get("messages").and_then(Value::as_array).is_some()
        && json.get("input").is_none()
        && json.get("instructions").is_none()
        && json.get("contents").is_none()
        && json.get("systemInstruction").is_none()
        && json.get("system_instruction").is_none()
        && json.get("inferenceConfig").is_none()
        && json.get("generationConfig").is_none()
        && json.get("generation_config").is_none()
        // Provider-native top-level markers disqualify the body from the OpenAI
        // Chat Completions family even when it also carries a `messages` array
        // (e.g. Anthropic `{"system": ..., "messages": [...]}`, Cohere
        // `preamble`/`message`/`chat_history`, TGI `inputs`, RAG `documents`). In
        // strict `chat_completions` mode these must be rejected rather than
        // admitted as chat schema.
        && json.get("system").is_none()
        && json.get("preamble").is_none()
        && json.get("message").is_none()
        && json.get("chat_history").is_none()
        && json.get("inputs").is_none()
        && json.get("documents").is_none()
        && json.get("retrieved_context").is_none()
        && json.get("tool_results").is_none()
}

fn looks_like_responses(json: &Value) -> bool {
    json.get("input").is_some()
        || json.get("instructions").is_some()
        || json.get("previous_response_id").is_some()
}

fn looks_like_provider_native(json: &Value) -> bool {
    json.get("system").is_some()
        || json.get("systemInstruction").is_some()
        || json.get("system_instruction").is_some()
        || json.get("contents").is_some()
        || json.get("generationConfig").is_some()
        || json.get("generation_config").is_some()
        || json.get("inferenceConfig").is_some()
        || json.get("preamble").is_some()
        || json.get("message").is_some()
        || json.get("chat_history").is_some()
        || json.get("documents").is_some()
        || json.get("retrieved_context").is_some()
        || json.get("tool_results").is_some()
        // Amazon Titan text-generation is provider-native: the prompt lives in
        // `inputText` and the output cap in `textGenerationConfig.maxTokenCount`
        // (read by `max_requested_tokens` / `clamp_max_token_fields`). Without
        // these markers a strict `provider_native` config rejects Titan bodies
        // before the documented `textGenerationConfig` reject/clamp logic runs.
        || json.get("inputText").is_some()
        || json.get("textGenerationConfig").is_some()
        // Hugging Face TGI uses `inputs` with generation controls nested under
        // `parameters` (not the legacy top-level `max_new_tokens` alias).
        || json.get("inputs").is_some()
        // Anthropic Messages and Cohere v2 can be indistinguishable from
        // OpenAI-style chat when they carry only a `messages` array.
        || json.get("messages").and_then(Value::as_array).is_some()
        // Google Vertex legacy `predict`, whose prompt lives in
        // `instances[].prompt` and now counts toward `max_prompt_characters`.
        || looks_like_vertex_predict(json)
}

/// Amazon Bedrock Converse (`supported_schema: bedrock_converse`): a `messages`
/// array, with the optional `system`, `inferenceConfig`, `toolConfig`, and
/// `additionalModelRequestFields` members.
fn looks_like_bedrock_converse(json: &Value) -> bool {
    json.get("messages").and_then(Value::as_array).is_some()
}

/// Google Vertex legacy `predict`: `{"instances": [{"prompt": "..."}], ...}`.
///
/// Shape-qualified rather than a bare `instances` key, because this predicate
/// decides what a strict `supported_schema` config ADMITS: `instances` is an
/// ordinary word in unrelated JSON, so a bare key would admit non-AI bodies as
/// provider-native. Requiring an entry that actually carries a `prompt` binds
/// admission to the same field `count_prompt_characters` counts. This mirrors
/// the shape-qualification the sibling `ai_semantic_firewall` applies to
/// Anthropic batch `requests` for the same reason.
fn looks_like_vertex_predict(json: &Value) -> bool {
    let Some(instances) = json.get("instances").and_then(Value::as_array) else {
        return false;
    };
    let carries_prompt = |instance: &Value| instance.get("prompt").is_some();
    instances.iter().any(carries_prompt)
}

/// Recognizes legacy text-completion and text-generation bodies that carry a
/// single prompt string instead of a message array: OpenAI legacy completions
/// (`{"model", "prompt"}`), TGI/HuggingFace text-generation
/// (`{"inputs", "parameters":{"max_new_tokens":...}}`), and Amazon Titan
/// text-generation (`{"inputText", "textGenerationConfig"}`).
/// `prompt`/`inputs`/`inputText` are in `TOP_LEVEL_PROMPT_FIELDS`,
/// `max_new_tokens`/`max_tokens_to_sample` are honored as token fields, and
/// `textGenerationConfig.maxTokenCount` is read by `max_requested_tokens` /
/// `clamp_max_token_fields`, so strict mode must admit these shapes rather than
/// reject them as unsupported.
fn looks_like_legacy_completions(json: &Value) -> bool {
    json.get("prompt").is_some()
        || json.get("inputs").is_some()
        || json.get("inputText").is_some()
        || json.get("textGenerationConfig").is_some()
}

/// The largest output-token cap the request asks for, across every top-level
/// and provider-native spelling. `Err(label)` names a present cap that is not a
/// non-negative integer.
fn max_requested_tokens(json: &Value) -> Result<Option<u64>, &'static str> {
    max_integer_control(json, TOP_LEVEL_TOKEN_FIELDS, NESTED_TOKEN_FIELDS)
}

/// Whether the request already caps output tokens for the *specific* provider
/// that `default_max_tokens` would be injected into.
///
/// This is deliberately provider-aware rather than schema-agnostic. A previous
/// `has_any_max_token_field` check treated any token-looking top-level field as
/// an existing cap, so a Gemini- or TGI-native body carrying a stray OpenAI
/// `max_tokens` (which those backends ignore) suppressed injection into the
/// real field (`generationConfig.maxOutputTokens` /
/// `parameters.max_new_tokens`), silently dropping the documented default cap.
/// We only treat the *target* provider's
/// own output-token field as an existing cap so injection still lands in the
/// field the backend actually honors.
///
/// A JSON `null` cap is the provider default, not a cap, so it never suppresses
/// injection (the injected value replaces it).
fn target_already_caps_output(json: &Value, target: DefaultTokenTarget) -> bool {
    match target {
        DefaultTokenTarget::Gemini => GEMINI_GENERATION_CONTAINERS.iter().any(|container| {
            json.get(*container).is_some_and(|config| {
                GEMINI_MAX_OUTPUT_FIELDS
                    .iter()
                    .any(|field| is_present_value(config.get(*field)))
            })
        }),
        DefaultTokenTarget::Bedrock => {
            is_present_value(json.get("inferenceConfig").and_then(|v| v.get("maxTokens")))
        }
        DefaultTokenTarget::TextGeneration => {
            is_present_value(json.get("parameters").and_then(|v| v.get("max_new_tokens")))
        }
        // The `TopLevel` target only injects a top-level `max_tokens`, so any
        // top-level token-cap field the plugin recognizes (`TOP_LEVEL_TOKEN_FIELDS`)
        // is the real cap for this target. That covers OpenAI Chat Completions
        // (`max_tokens` / `max_completion_tokens`), the OpenAI Responses API
        // (`max_output_tokens`, reached for a bare `{"input", ...}` body), and the
        // legacy/provider aliases that route here without a marker container —
        // Anthropic legacy (`max_tokens_to_sample`), `maxTokens`, `maxOutputTokens`,
        // and `max_new_tokens`. Treating any of them as an existing cap matches
        // what the reject/clamp logic recognizes and keeps a redundant — and for
        // Responses, conflicting — `max_tokens` from being injected alongside an
        // existing cap. Unlike the container-scoped targets, there is no
        // cross-provider stray-field hazard here: every field checked is itself a
        // top-level field this plugin already honors.
        DefaultTokenTarget::TopLevel => TOP_LEVEL_TOKEN_FIELDS
            .iter()
            .any(|field| is_present_value(json.get(*field))),
    }
}

fn clamp_max_token_fields(json: &mut Value, limit: u64) -> bool {
    let mut modified = false;
    if let Some(obj) = json.as_object_mut() {
        for field in TOP_LEVEL_TOKEN_FIELDS {
            modified |= clamp_number_field(obj, field, limit);
        }
    }
    for (container, field, _label) in NESTED_TOKEN_FIELDS {
        if let Some(obj) = json.get_mut(*container).and_then(Value::as_object_mut) {
            modified |= clamp_number_field(obj, field, limit);
        }
    }
    modified
}

/// Replace an over-limit cap with the numeric limit. Every numeric spelling
/// [`parse_integer_control`] accepts (quoted, float, exponent) is clamped, so a
/// cap the backend honors cannot stay above the limit.
fn clamp_number_field(obj: &mut serde_json::Map<String, Value>, field: &str, limit: u64) -> bool {
    if let IntegerControl::Value(current) = parse_integer_control(obj.get(field))
        && current > limit
    {
        obj.insert(field.to_string(), Value::Number(limit.into()));
        return true;
    }
    false
}

#[derive(Clone, Copy)]
enum DefaultTokenTarget {
    TopLevel,
    Gemini,
    Bedrock,
    TextGeneration,
}

/// Picks the provider-native container that `default_max_tokens` should also be
/// injected into when the body is clearly using one of the provider-native
/// schemas the guard understands.
///
/// These markers are still request-controlled, so they must not be used to
/// suppress the top-level default cap on an OpenAI-shaped body.
/// `inject_default_max_tokens` keeps a top-level fallback whenever the body
/// carries a top-level OpenAI-family prompt field (see
/// [`has_top_level_prompt_marker`]) or no native container at all, then adds the
/// provider-native cap when a native target is detected. A body that is
/// unambiguously provider-native is left to its native cap only.
///
/// `supported_schema: bedrock_converse` is operator configuration, not a
/// request marker, so it binds the target to Bedrock unconditionally: a
/// Converse body that omits the optional `inferenceConfig` still receives
/// `inferenceConfig.maxTokens`.
fn default_token_target(json: &Value, schema: SupportedSchema) -> DefaultTokenTarget {
    if matches!(schema, SupportedSchema::BedrockConverse) {
        DefaultTokenTarget::Bedrock
    } else if json.get("generationConfig").is_some()
        || json.get("generation_config").is_some()
        || json.get("contents").is_some()
        || json.get("systemInstruction").is_some()
        || json.get("system_instruction").is_some()
    {
        DefaultTokenTarget::Gemini
    } else if json.get("inferenceConfig").is_some() {
        DefaultTokenTarget::Bedrock
    } else if json.get("inputs").is_some() {
        DefaultTokenTarget::TextGeneration
    } else {
        DefaultTokenTarget::TopLevel
    }
}

/// A Responses-shaped body uses `input` / `instructions` / `previous_response_id`
/// and NO chat `messages` array. A body that carries `messages` is a Chat /
/// Anthropic / Cohere request (it caps via top-level `max_tokens`) even if a
/// client also adds a Responses marker — routing such a body to
/// `max_output_tokens` would let `{messages, input}` divert `default_max_tokens`
/// into a field the chat upstream ignores, leaving it uncapped.
fn is_responses_shape(json: &Value) -> bool {
    looks_like_responses(json) && json.get("messages").is_none()
}

/// The top-level output-cap field for the body's OpenAI-family schema. A
/// Responses-shaped body (see [`is_responses_shape`]) caps output via
/// `max_output_tokens`; every other top-level-capped family (Chat Completions,
/// legacy completions, Anthropic Messages, Cohere) caps via `max_tokens`.
/// Provider-native families cap via their own container
/// (`inject_provider_default_max_tokens`), not this field.
fn top_level_cap_field(json: &Value) -> &'static str {
    if is_responses_shape(json) {
        "max_output_tokens"
    } else {
        "max_tokens"
    }
}

/// True when the body already declares the cap field its OWN top-level family
/// reads. Checks only that family's field(s) — not every recognized token alias:
/// a stray cross-provider alias an OpenAI-family upstream ignores (e.g. a TGI
/// `max_new_tokens`, a Gemini `maxOutputTokens`, or a Bedrock `maxTokens` sitting
/// at the top level of a Chat body) must NOT be mistaken for the real cap and
/// suppress the fallback. `max_completion_tokens` is the Chat-Completions alias
/// for `max_tokens` and counts.
fn top_level_cap_present(json: &Value) -> bool {
    if is_responses_shape(json) {
        is_present_value(json.get("max_output_tokens"))
    } else {
        is_present_value(json.get("max_tokens"))
            || is_present_value(json.get("max_completion_tokens"))
    }
}

/// True when the body carries a top-level prompt field that an OpenAI-compatible
/// (top-level-capped) upstream reads, so a top-level cap would actually bound its
/// output. Covers every top-level-capped family: `messages` (OpenAI Chat,
/// Anthropic Messages, Cohere v2, Bedrock Converse), `prompt` (legacy
/// completions), `input` / `instructions` / `previous_response_id` (Responses),
/// and `message` / `chat_history` (Cohere v1). The provider-native prompt fields
/// `contents` (Gemini), `inputs` (TGI), and `inputText` (Titan) are deliberately
/// excluded — those bodies cap via their native container, so a client-spoofed
/// provider-native marker on a top-level-shaped body must NOT divert the default
/// away from the top level (the #1950 bypass), while an unambiguously native body
/// (a native container and none of these prompts) is left to its native cap only
/// and a strict provider backend is not handed an unsupported top-level field.
/// Bedrock Converse is the irreducible exception: it shares `messages` with
/// OpenAI, so it is treated as top-level-capable and fail-closed-capped. See
/// [`inject_default_max_tokens`].
fn has_top_level_prompt_marker(json: &Value) -> bool {
    const TOP_LEVEL_PROMPT_MARKERS: &[&str] = &[
        "messages",
        "prompt",
        "input",
        "instructions",
        "previous_response_id",
        "message",
        "chat_history",
    ];
    TOP_LEVEL_PROMPT_MARKERS
        .iter()
        .any(|field| json.get(*field).is_some())
}

fn inject_provider_default_max_tokens(
    obj: &mut serde_json::Map<String, Value>,
    target: DefaultTokenTarget,
    default: u64,
) -> bool {
    match target {
        DefaultTokenTarget::Gemini => {
            // Keep the client's ProtoJSON spelling: injecting the other spelling
            // beside an existing container or `null` cap would make the body
            // carry one proto field twice.
            let container =
                if obj.contains_key("generation_config") && !obj.contains_key("generationConfig") {
                    "generation_config"
                } else {
                    "generationConfig"
                };
            let entry = obj
                .entry(container.to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            // A lone null container is unset too; replace it in place so the
            // default neither disappears nor creates a second proto spelling.
            if entry.is_null() {
                *entry = Value::Object(serde_json::Map::new());
            }
            if let Some(gen_config) = entry.as_object_mut() {
                let field = if gen_config.contains_key("max_output_tokens")
                    && !gen_config.contains_key("maxOutputTokens")
                {
                    "max_output_tokens"
                } else {
                    "maxOutputTokens"
                };
                gen_config.insert(field.to_string(), Value::Number(default.into()));
                true
            } else {
                false
            }
        }
        DefaultTokenTarget::Bedrock => {
            let entry = obj
                .entry("inferenceConfig".to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(inference_config) = entry.as_object_mut() {
                inference_config.insert("maxTokens".to_string(), Value::Number(default.into()));
                true
            } else {
                false
            }
        }
        DefaultTokenTarget::TextGeneration => {
            let entry = obj
                .entry("parameters".to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(parameters) = entry.as_object_mut() {
                parameters.insert("max_new_tokens".to_string(), Value::Number(default.into()));
                true
            } else {
                false
            }
        }
        DefaultTokenTarget::TopLevel => false,
    }
}

/// True when the operator-declared backend dialect makes a Bedrock target
/// authoritative, so no top-level fallback cap is added beside
/// `inferenceConfig.maxTokens`.
fn bedrock_native_target(target: DefaultTokenTarget, schema: SupportedSchema) -> bool {
    matches!(target, DefaultTokenTarget::Bedrock)
        && matches!(
            schema,
            SupportedSchema::ProviderNative | SupportedSchema::BedrockConverse
        )
}

fn inject_default_max_tokens(json: &mut Value, default: u64, schema: SupportedSchema) -> bool {
    let target = default_token_target(json, schema);
    // Use the body's OWN family cap field (`max_output_tokens` for Responses, else
    // `max_tokens`) both to test whether a real cap is present and as the field to
    // inject — so a Responses body gets the cap the Responses API actually reads,
    // and a stray cross-provider alias does not pass as an existing cap.
    let cap_field = top_level_cap_field(json);
    let top_level_already_capped = top_level_cap_present(json);
    let target_already_capped = target_already_caps_output(json, target);
    // The top-level fallback exists to defeat the #1950 spoof: a client appends a
    // provider-native marker (`generationConfig`/`inferenceConfig`/`contents`) to
    // an OpenAI-shaped body so the default routes only into a field the real
    // (top-level-capped) upstream ignores, leaving output uncapped. Inject the
    // top-level fallback only when the body actually carries a top-level-capped
    // prompt field — the spoof must keep one so the OpenAI/Anthropic/Cohere
    // upstream still processes the request — or when no provider-native container
    // is present at all. A body that is unambiguously provider-native (a native
    // container and NO top-level prompt field, e.g. Gemini `contents`, TGI
    // `inputs`) is left to its native cap only, so a strict provider backend is
    // not handed an unsupported top-level cap field.
    //
    // Bedrock Converse is the one provider-native shape that DOES carry a
    // top-level prompt marker (`messages`) — but it caps via
    // `inferenceConfig.maxTokens`, and the AWS Converse API rejects an unexpected
    // top-level `max_tokens`. A model-less `{messages, inferenceConfig}` body,
    // however, is ALSO what an OpenAI-compatible backend that derives the model
    // outside the JSON body receives (Azure OpenAI / deployment-in-URL routes),
    // so absence of `model` cannot prove Converse. Only suppress the top-level
    // fallback when the operator has explicitly declared a provider-native
    // backend (`supported_schema: provider_native` or `bedrock_converse`); in
    // `auto` or OpenAI-family modes, fail closed and keep the top-level cap so an
    // Azure/OpenAI upstream is not left uncapped. Native backends still get their
    // `inferenceConfig` cap below either way.
    let bedrock_converse_native = bedrock_native_target(target, schema);
    let wants_top_level_fallback = matches!(target, DefaultTokenTarget::TopLevel)
        || (has_top_level_prompt_marker(json) && !bedrock_converse_native);
    let Some(obj) = json.as_object_mut() else {
        return false;
    };

    let mut modified = false;

    if wants_top_level_fallback && !top_level_already_capped {
        obj.insert(cap_field.to_string(), Value::Number(default.into()));
        modified = true;
    }

    // Preserve provider-native functionality too: native backends that ignore
    // the top-level fallback still receive their own output-token cap. A
    // malformed provider container simply skips the native insertion; the
    // top-level fallback above remains in place for compatible upstreams.
    if !target_already_capped {
        modified |= inject_provider_default_max_tokens(obj, target, default);
    }

    modified
}

/// Whether the final request still carries every provider/family cap that
/// `inject_default_max_tokens` would require for this body shape. This mirrors
/// the injection routing without cloning or mutating the request JSON.
fn has_required_default_token_cap(json: &Value, schema: SupportedSchema) -> bool {
    let target = default_token_target(json, schema);
    let bedrock_converse_native = bedrock_native_target(target, schema);
    let wants_top_level_fallback = matches!(target, DefaultTokenTarget::TopLevel)
        || (has_top_level_prompt_marker(json) && !bedrock_converse_native);

    (!wants_top_level_fallback || top_level_numeric_cap_present(json))
        && (matches!(target, DefaultTokenTarget::TopLevel)
            || target_has_numeric_output_cap(json, target))
}

fn top_level_numeric_cap_present(json: &Value) -> bool {
    if is_responses_shape(json) {
        is_valid_integer_control(json.get("max_output_tokens"))
    } else {
        ["max_tokens", "max_completion_tokens"]
            .into_iter()
            .any(|field| is_valid_integer_control(json.get(field)))
    }
}

fn target_has_numeric_output_cap(json: &Value, target: DefaultTokenTarget) -> bool {
    match target {
        DefaultTokenTarget::Gemini => GEMINI_GENERATION_CONTAINERS.iter().any(|container| {
            json.get(*container).is_some_and(|config| {
                GEMINI_MAX_OUTPUT_FIELDS
                    .iter()
                    .any(|field| is_valid_integer_control(config.get(*field)))
            })
        }),
        DefaultTokenTarget::Bedrock => is_valid_integer_control(
            json.get("inferenceConfig")
                .and_then(|value| value.get("maxTokens")),
        ),
        DefaultTokenTarget::TextGeneration => is_valid_integer_control(
            json.get("parameters")
                .and_then(|value| value.get("max_new_tokens")),
        ),
        DefaultTokenTarget::TopLevel => top_level_numeric_cap_present(json),
    }
}

fn count_message_entries(json: &Value) -> u64 {
    let mut total = 0u64;
    total = total.saturating_add(count_message_array(json.get("messages")));
    total = total.saturating_add(count_message_array(json.get("input")));
    total = total.saturating_add(count_message_array(json.get("contents")));
    total = total.saturating_add(count_message_array(json.get("chat_history")));
    // Cohere-native requests carry the current user turn in a top-level
    // `message` string (the prior turns live in `chat_history`). Count it as one
    // entry so `max_messages` reflects the full conversation length; without it a
    // request with N `chat_history` entries plus a current `message` is counted
    // as N and slips one message past the cap.
    if json
        .get("message")
        .and_then(Value::as_str)
        .is_some_and(|message| !message.is_empty())
    {
        total = total.saturating_add(1);
    }
    total
}

fn count_message_array(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|item| match item {
                Value::String(_) => true,
                Value::Object(obj) => {
                    !is_typed_non_text_content_part(obj)
                        && (obj.contains_key("role")
                            || obj.contains_key("content")
                            || obj.contains_key("parts")
                            || obj.contains_key("message"))
                }
                _ => false,
            })
            .count() as u64,
        _ => 0,
    }
}

/// Counts Unicode scalar values in model-visible request text, not UTF-8 bytes.
///
/// The extraction mirrors `ai_prompt_shield`'s content-mode coverage for chat
/// messages, Responses `input`/`instructions`, Anthropic top-level `system`,
/// and multimodal text parts. It extends that baseline for policy fields that
/// affect prompt cost/risk: tool definitions, tool-call arguments, and common
/// RAG/document fields. Non-text multimodal parts are intentionally ignored.
fn count_prompt_characters(json: &Value) -> u64 {
    let mut total = 0u64;

    if let Some(messages) = json.get("messages").and_then(Value::as_array) {
        for message in messages {
            count_text_value(message.get("content"), &mut total);
        }
    }

    if let Some(contents) = json.get("contents") {
        count_text_value(Some(contents), &mut total);
    }
    if let Some(chat_history) = json.get("chat_history") {
        count_text_value(Some(chat_history), &mut total);
    }

    for field in TOP_LEVEL_PROMPT_FIELDS {
        count_text_value(json.get(field), &mut total);
    }

    // Cohere v1 `documents` entries are provider document *maps* whose eligible
    // string members are all serialized into the model-visible prompt, so they
    // are read member-wise rather than through the single-member content
    // selector that `count_text_value` applies to nested content objects (see
    // [`count_document_value`]).
    count_document_value(json.get("documents"), &mut total);

    for field in ["retrieved_context", "tool_results", "toolResults"] {
        count_text_value(json.get(field), &mut total);
    }

    // Azure OpenAI "On Your Data": the per-data-source instruction in
    // `data_sources[].parameters.role_information` is sent to the model and
    // billed as input, so it must count toward `max_prompt_characters`.
    // Scoped to that exact field (not the whole `parameters` object, which holds
    // non-prompt config such as endpoints/keys/index names) so the cap reflects
    // model-visible text, consistent with how other RAG fields are counted.
    count_data_source_role_information(json, &mut total);

    // Google Vertex legacy `predict`: the prompt lives in `instances[].prompt`
    // and no other counted field reaches it, so `{"instances": [{"prompt":
    // "<huge prompt>"}]}` bypassed the cap entirely. Scoped to `prompt` —
    // the surrounding instance fields are prediction inputs and identifiers,
    // not model-visible prose — matching the `$.instances[*].prompt` path the
    // sibling `ai_semantic_firewall` and `ai_prompt_shield` plugins read.
    if let Some(instances) = json.get("instances").and_then(Value::as_array) {
        for instance in instances {
            count_text_value(instance.get("prompt"), &mut total);
        }
    }

    count_tool_definition_text(json.get("tools"), &mut total);
    count_tool_definition_text(json.get("functions"), &mut total);
    // Amazon Bedrock Converse nests its tool definitions (`toolSpec` name,
    // description, and `inputSchema.json`) under `toolConfig.tools[]` rather
    // than a top-level `tools` array; they are model-visible all the same.
    count_tool_definition_text(
        json.get("toolConfig")
            .and_then(|config| config.get("tools")),
        &mut total,
    );
    count_tool_argument_fields(json, &mut total);

    total
}

fn count_text_value(value: Option<&Value>, total: &mut u64) {
    let Some(value) = value else {
        return;
    };
    match value {
        Value::String(text) => add_chars(total, text),
        Value::Array(items) => {
            for item in items {
                count_text_value(Some(item), total);
            }
        }
        Value::Object(obj) => {
            if let Some(part_type) = obj.get("type").and_then(Value::as_str) {
                if is_text_content_part_type(part_type) {
                    count_text_value(obj.get("text").or_else(|| obj.get("content")), total);
                    return;
                }
                // Responses API tool-result items carry model-visible text in
                // `output` (e.g. `{"type": "function_call_output", "output":
                // "..."}`). These are typed non-text parts as far as the content
                // matchers are concerned, so count `output` explicitly before the
                // non-text bailout — otherwise a large tool result re-fed to the
                // model dodges `max_prompt_characters` entirely.
                if part_type == "function_call_output"
                    && let Some(output) = obj.get("output")
                {
                    count_text_value(Some(output), total);
                    return;
                }
                // Anthropic text documents keep model-visible prose under
                // `source.data`. Count it before the typed non-text bailout;
                // binary/base64 image and PDF sources remain excluded.
                if part_type == "document"
                    && let Some(source) = obj.get("source")
                    && source_is_text_document(source)
                {
                    count_text_value(source.get("data"), total);
                    return;
                }
                if is_typed_non_text_content_part(obj) {
                    return;
                }
            }
            if let Some(parts) = obj.get("parts") {
                count_text_value(Some(parts), total);
            } else if let Some(content) = obj.get("content") {
                count_text_value(Some(content), total);
            } else if let Some(tool_result) = obj.get("toolResult") {
                // Amazon Bedrock Converse tool results:
                // `messages[].content[].toolResult.content[].text`. The block
                // carries no `type` and no `content` of its own, so without
                // this arm a tool result re-fed to the model — often the
                // largest text in the turn — counted zero characters and
                // dodged `max_prompt_characters` entirely. Scoped to
                // `content`: the sibling `toolUseId`/`status` fields are
                // plumbing, not model-visible prose.
                count_text_value(tool_result.get("content"), total);
            } else if let Some(guard_content) = obj.get("guardContent") {
                // Bedrock Converse guarded text, nested
                // (`{"text": {"text": "..."}}`) or flat
                // (`{"text": "..."}`); the recursive call counts either.
                count_text_value(guard_content.get("text"), total);
            } else if let Some(message) = obj.get("message") {
                count_text_value(Some(message), total);
            } else if let Some(text) = obj.get("text") {
                count_text_value(Some(text), total);
            }
        }
        _ => {}
    }
}

/// Cohere document-map member holding the citation identifier. It is bookkeeping
/// for citation retrieval rather than prompt prose, so it is not counted.
const DOCUMENT_ID_MEMBER: &str = "id";

/// Cohere document-map member naming the document members the provider keeps out
/// of the model-visible rendering. Neither the control list nor the members it
/// names reach the model, so neither is counted.
const DOCUMENT_EXCLUDES_MEMBER: &str = "_excludes";

/// Counts model-visible text in the top-level `documents` RAG array.
///
/// Cohere v1 document entries are arbitrary string-to-string maps and the
/// provider serializes their eligible members into the prompt the model reads,
/// so every eligible member counts toward `max_prompt_characters`. The generic
/// content selector in [`count_text_value`] picks at most one recognized
/// `text`/`content`-like member per object, which leaves a document's other
/// documented members (`title`, `snippet`, `url`, ...) outside the cap — and
/// contributes nothing at all for a document whose members are all
/// operator-chosen keys. Document objects are therefore read member-wise, minus
/// the two members Cohere itself excludes from the model-visible rendering:
/// [`DOCUMENT_ID_MEMBER`] and [`DOCUMENT_EXCLUDES_MEMBER`] (plus every member the
/// latter names, which stays available for citation retrieval only).
///
/// Each retained member value is still handed to [`count_text_value`], so a
/// document that nests provider content shapes keeps that accounting and is
/// counted exactly once. An entry carrying a `type` discriminator is a content
/// *part*, not a document map, and is delegated whole to [`count_text_value`] so
/// non-text multimodal parts and base64 document sources stay excluded from
/// prose accounting rather than being counted as sibling strings.
///
/// Member *names* are deliberately not counted: like the JSON-Schema boilerplate
/// keys excluded from tool definitions, they are structure rather than
/// operator-supplied prose.
fn count_document_value(value: Option<&Value>, total: &mut u64) {
    match value {
        Some(Value::Array(items)) => {
            for item in items {
                count_document_value(Some(item), total);
            }
        }
        Some(Value::Object(obj)) if !obj.contains_key("type") => {
            let excluded_members = document_excluded_members(obj.get(DOCUMENT_EXCLUDES_MEMBER));
            for (member, member_value) in obj {
                let member = member.as_str();
                if member == DOCUMENT_ID_MEMBER
                    || member == DOCUMENT_EXCLUDES_MEMBER
                    || excluded_members.contains(member)
                {
                    continue;
                }
                count_text_value(Some(member_value), total);
            }
        }
        other => count_text_value(other, total),
    }
}

/// Parse a document's exclusion control once before visiting its members. This
/// keeps processing linear when both collections are attacker-controlled.
fn document_excluded_members(excludes: Option<&Value>) -> HashSet<&str> {
    match excludes {
        Some(Value::Array(excludes)) => excludes.iter().filter_map(Value::as_str).collect(),
        // Tolerate the single-value spelling of the same control.
        Some(Value::String(excluded)) => HashSet::from([excluded.as_str()]),
        _ => HashSet::new(),
    }
}

fn is_text_content_part_type(part_type: &str) -> bool {
    matches!(part_type, "text" | "input_text" | "output_text")
}

fn source_is_text_document(source: &Value) -> bool {
    let Some(source) = source.as_object() else {
        return false;
    };
    match source.get("type").and_then(Value::as_str) {
        Some("text") => true,
        // Some provider adapters omit the redundant `type: text` but retain the
        // text media type. An explicit non-text type (especially `base64`) wins
        // so encoded bytes are never counted as prose.
        None => source
            .get("media_type")
            .and_then(Value::as_str)
            .is_some_and(|media_type| {
                media_type
                    .as_bytes()
                    .get(..5)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"text/"))
            }),
        Some(_) => false,
    }
}

fn is_typed_non_text_content_part(obj: &serde_json::Map<String, Value>) -> bool {
    obj.get("type")
        .and_then(Value::as_str)
        .is_some_and(|part_type| !is_text_content_part_type(part_type))
        && !obj.contains_key("role")
        && !obj.contains_key("content")
        && !obj.contains_key("parts")
        && !obj.contains_key("message")
}

/// Counts text in tool/function definitions. Only string *values* are counted,
/// mirroring `count_text_value`: JSON-Schema boilerplate keys (`type`,
/// `properties`, `description`, `parameters`, `enum`, ...) describe the tool's
/// structure rather than model-visible prompt text, so counting them would
/// inconsistently inflate `max_prompt_characters` and push otherwise small
/// requests over the limit.
fn count_tool_definition_text(value: Option<&Value>, total: &mut u64) {
    match value {
        Some(Value::String(text)) => add_chars(total, text),
        Some(Value::Array(items)) => {
            for item in items {
                count_tool_definition_text(Some(item), total);
            }
        }
        Some(Value::Object(obj)) => {
            for value in obj.values() {
                count_tool_definition_text(Some(value), total);
            }
        }
        _ => {}
    }
}

/// Counts assistant tool-call argument payloads, scoped to the *legitimate*
/// tool-call locations of the supported schemas rather than any `arguments` key
/// anywhere in the body. Walking the whole tree (the previous behavior) counted
/// unrelated nested `arguments` keys — e.g. `metadata.arguments` or an embedded
/// transcript under `documents` — which is the same arbitrary-nesting
/// false-positive class the system-role scoping (`array_item_has_system_role`)
/// deliberately avoids. Mirroring that structure, we only inspect items of the
/// known message arrays and pull arguments from:
///   * OpenAI Chat Completions: `messages[].tool_calls[].function.arguments`
///   * OpenAI Responses function-call items: `input[].arguments`
///   * Anthropic content blocks: `messages[].content[]` entries of
///     `type: "tool_use"` carrying an `input` arguments object
///   * Bedrock Converse content blocks: `messages[].content[].toolUse.input`,
///     the untyped union spelling of the same call
///   * Gemini: `contents[].parts[]` entries carrying `functionCall.args`, plus
///     the `functionResponse.response` tool results
fn count_tool_argument_fields(json: &Value, total: &mut u64) {
    for field in ["messages", "input", "contents", "chat_history"] {
        if let Some(Value::Array(items)) = json.get(field) {
            for item in items {
                count_item_tool_arguments(item, total);
            }
        }
    }
}

fn count_item_tool_arguments(item: &Value, total: &mut u64) {
    let Value::Object(obj) = item else {
        return;
    };

    // OpenAI Responses function-call item: the call lives at the array-item
    // level (`{"type": "function_call", "name": ..., "arguments": "..."}`).
    if let Some(arguments) = obj.get("arguments") {
        count_argument_value(arguments, total);
    }

    // OpenAI Chat Completions assistant message: tool calls are nested under
    // `tool_calls[].function.arguments`.
    if let Some(Value::Array(tool_calls)) = obj.get("tool_calls") {
        for call in tool_calls {
            if let Some(arguments) = call
                .get("function")
                .and_then(|function| function.get("arguments"))
            {
                count_argument_value(arguments, total);
            }
        }
    }

    // Anthropic and Bedrock Converse assistant messages both carry tool calls as
    // `content[]` blocks, but in two different spellings, and each needs its own
    // arm:
    //
    // * Anthropic Messages uses a typed block (`type: "tool_use"`) whose `input`
    //   object is the model-emitted arguments.
    // * The canonical Converse `ContentBlock` union instead carries an untyped
    //   `{"toolUse": {"toolUseId", "name", "input"}}` member, which never matches
    //   the typed arm. `count_text_value` does not reach it either — the block
    //   exposes no `text`/`content`/`parts` member of its own — so its arguments,
    //   often the largest text in the turn, are read here.
    //
    // Both are scoped to `input`: the sibling `type`/`toolUseId`/`name`/`id`
    // fields are call plumbing, not model-visible prose, and scoping to the block
    // keeps an unrelated `input` key elsewhere in the body out of the count.
    if let Some(Value::Array(blocks)) = obj.get("content") {
        for block in blocks {
            let Value::Object(block_obj) = block else {
                continue;
            };
            if block_obj.get("type").and_then(Value::as_str) == Some("tool_use")
                && let Some(input) = block_obj.get("input")
            {
                count_argument_value(input, total);
            }
            if let Some(input) = block_obj
                .get("toolUse")
                .and_then(|tool_use| tool_use.get("input"))
            {
                count_argument_value(input, total);
            }
        }
    }

    // Gemini: tool calls live in `contents[].parts[]` entries carrying a
    // `functionCall` object whose `args` is the arguments payload, and tool
    // results re-fed to the model live in `functionResponse.response` (the
    // structured result the model reads as context). Both ProtoJSON spellings
    // of each member are read.
    if let Some(Value::Array(parts)) = obj.get("parts") {
        for part in parts {
            for call_member in ["functionCall", "function_call"] {
                if let Some(args) = part
                    .get(call_member)
                    .and_then(|function_call| function_call.get("args"))
                {
                    count_argument_value(args, total);
                }
            }
            for response_member in ["functionResponse", "function_response"] {
                if let Some(response) = part
                    .get(response_member)
                    .and_then(|function_response| function_response.get("response"))
                {
                    count_argument_value(response, total);
                }
            }
        }
    }
}

fn count_argument_value(value: &Value, total: &mut u64) {
    match value {
        Value::String(text) => add_chars(total, text),
        Value::Array(items) => {
            for item in items {
                count_argument_value(item, total);
            }
        }
        Value::Object(obj) => {
            for value in obj.values() {
                count_argument_value(value, total);
            }
        }
        _ => {}
    }
}

/// All Azure "On Your Data" data-source items, across BOTH the GA snake_case
/// `data_sources` and the original extensions-API camelCase `dataSources` arrays.
/// Both keys are iterated rather than short-circuited on the first one present:
/// `Option::or_else` only falls through on `None`, so a body that pairs an
/// empty/`null` `data_sources` with a populated `dataSources` (or vice versa)
/// would otherwise slip the second array past the guard. Mirrors the file's
/// `tool_results` / `toolResults` both-keys handling.
fn azure_data_source_items(json: &Value) -> impl Iterator<Item = &Value> {
    ["data_sources", "dataSources"]
        .into_iter()
        .filter_map(|key| json.get(key))
        .filter_map(Value::as_array)
        .flatten()
}

/// Every per-data-source instruction string under `parameters.role_information`
/// (GA) and `parameters.roleInformation` (original extensions API). BOTH inner
/// keys are yielded — like [`azure_data_source_items`] does for the outer keys —
/// rather than short-circuiting on the first present one: `as_str` of an empty
/// string is `Some("")` (not `None`), so an `or_else` chain would let
/// `{role_information: "", roleInformation: "<jailbreak>"}` hide the populated
/// camelCase value from both `block_system_prompts` and `max_prompt_characters`.
/// Keeping a single accessor also keeps those two inspections in agreement.
fn azure_role_information_values(source: &Value) -> impl Iterator<Item = &str> {
    let parameters = source.get("parameters");
    ["role_information", "roleInformation"]
        .into_iter()
        .filter_map(move |key| parameters.and_then(|p| p.get(key)).and_then(Value::as_str))
}

/// Counts the model-visible instruction text under Azure "On Your Data"
/// `data_sources[].parameters.role_information` (and the camelCase
/// `dataSources[].parameters.roleInformation`). Only that string is counted —
/// the rest of `parameters` carries connection/config values (endpoints, keys,
/// index names, embedding settings) that are not sent to the model as prompt
/// text, so counting them would inconsistently inflate `max_prompt_characters`.
fn count_data_source_role_information(json: &Value, total: &mut u64) {
    for source in azure_data_source_items(json) {
        for role_information in azure_role_information_values(source) {
            add_chars(total, role_information);
        }
    }
}

fn add_chars(total: &mut u64, text: &str) {
    *total = total.saturating_add(text.chars().count() as u64);
}

fn contains_system_prompt(json: &Value, aliases: &HashSet<String>) -> bool {
    object_has_system_prompt_field(json, aliases)
        || value_has_system_role(json.get("messages"), aliases)
        || value_has_system_role(json.get("input"), aliases)
        || value_has_system_role(json.get("contents"), aliases)
        || value_has_system_role(json.get("chat_history"), aliases)
        || data_sources_have_role_information(json)
}

/// Azure OpenAI "On Your Data" requests carry a per-data-source instruction in
/// `data_sources[].parameters.role_information` (or the original extensions-API
/// camelCase `dataSources[].parameters.roleInformation`) — a free-text string
/// that tells the model how to behave. It is a de-facto system prompt: the
/// backend applies it even when the top-level `messages` carry only ordinary
/// `user` turns, so a caller could otherwise smuggle disallowed system/developer
/// instructions past `block_system_prompts`. Treat a NON-BLANK `role_information`
/// on any data source as a system prompt.
///
/// A blank value (empty or whitespace-only) is intentionally allowed — a
/// deliberate departure from the presence-based top-level
/// `object_has_system_prompt_field`: it carries no directive, and Azure clients
/// legitimately include data sources without one, so blocking those would be a
/// false positive. (Non-whitespace invisible characters are not trimmed, so they
/// still block — fail-closed.) Scoped to this exact nested field (both casings) to
/// avoid flagging arbitrary user-supplied text.
fn data_sources_have_role_information(json: &Value) -> bool {
    azure_data_source_items(json)
        .any(|source| azure_role_information_values(source).any(|ri| !ri.trim().is_empty()))
}

fn object_has_system_prompt_field(json: &Value, aliases: &HashSet<String>) -> bool {
    let Some(obj) = json.as_object() else {
        return false;
    };

    for field in BUILTIN_SYSTEM_PROMPT_FIELDS {
        if obj.get(*field).is_some_and(|value| !value.is_null()) {
            return true;
        }
    }

    // Default config carries no aliases: the fixed-field check above already
    // covered the work, so skip the per-key lowercase allocation entirely. Only
    // when an operator opts into aliases do we pay the case-insensitive scan.
    !aliases.is_empty()
        && obj
            .iter()
            .any(|(key, value)| !value.is_null() && aliases.contains(key.to_lowercase().as_str()))
}

/// Checks whether any entry of a message/content array carries a system-prompt
/// role. In every supported schema (OpenAI `messages[]`, Responses `input[]`,
/// Gemini `contents[]`, Cohere `chat_history[]`) the role lives at the top of
/// each array item (`role` for OpenAI/Anthropic/Cohere, `author` for some
/// provider shapes), so we inspect only the item level. Recursing into arbitrary
/// nested values would flag any user-supplied data that happens to contain a
/// `role`/`author` key (e.g. an embedded transcript under `metadata`),
/// producing false-positive system-prompt blocks.
fn value_has_system_role(value: Option<&Value>, aliases: &HashSet<String>) -> bool {
    let Some(Value::Array(items)) = value else {
        return false;
    };
    items
        .iter()
        .any(|item| array_item_has_system_role(item, aliases))
}

fn array_item_has_system_role(item: &Value, aliases: &HashSet<String>) -> bool {
    let Value::Object(obj) = item else {
        return false;
    };
    obj.get("role")
        .and_then(Value::as_str)
        .is_some_and(|role| is_system_prompt_role(role, aliases))
        || obj
            .get("author")
            .and_then(Value::as_str)
            .is_some_and(|role| is_system_prompt_role(role, aliases))
}

fn is_system_prompt_role(role: &str, aliases: &HashSet<String>) -> bool {
    let role_lower = role.to_lowercase();
    BUILTIN_SYSTEM_PROMPT_ROLES.contains(&role_lower.as_str())
        || aliases.contains(role_lower.as_str())
}

#[async_trait]
impl Plugin for AiRequestGuard {
    fn name(&self) -> &str {
        "ai_request_guard"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_REQUEST_GUARD
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn enforces_finalized_request_policy(&self) -> bool {
        true
    }

    fn modifies_request_body(&self) -> bool {
        self.needs_body_transform
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.requires_request_body
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if !self.requires_request_body || ctx.method != "POST" {
            return false;
        }
        // Buffer every POST body that could be an AI request, whatever its
        // declared `Content-Type`: a missing, non-JSON, or joined value is
        // sniffed in `before_proxy` (see [`BodyScope::Sniffed`]). Only framed
        // gRPC / gRPC-Web (length-prefixed, possibly base64, wire frames — never
        // bare JSON, even under `+json`) and opaque upload media types stay
        // unbuffered.
        //
        // Compressed bodies (`content-encoding: gzip|br|…`) ARE buffered: even
        // though they cannot be inspected in `before_proxy`, the guard re-runs
        // inspection in `on_final_request_body` (after any `compression`
        // decompression), and failing closed there requires the buffered body.
        request_body_scope(ctx.headers.get("content-type").map(String::as_str))
            != BodyScope::OutOfScope
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only validate POST requests (AI APIs are always POST)
        if ctx.method != "POST" {
            return PluginResult::Continue;
        }

        // Classify the scope from the content-type. Read from the `headers`
        // parameter, never `ctx.headers`: when no plugin modifies request
        // headers the handler `std::mem::take()`s them out of `ctx.headers` for
        // this phase.
        //
        // Framed gRPC / gRPC-Web bodies (`application/grpc+json`,
        // `application/grpc-web-text+json`, etc.) match `is_json_content_type`
        // via their `+json` suffix but carry length-prefixed (and, for `-text`,
        // base64) wire frames, not a bare JSON document. Parsing that framing as
        // JSON always fails; they are out of scope so valid framed requests
        // reach the backend instead of being 400'd as malformed.
        let declared_json =
            match request_body_scope(headers.get("content-type").map(String::as_str)) {
                BodyScope::OutOfScope => return PluginResult::Continue,
                BodyScope::DeclaredJson => true,
                BodyScope::Sniffed => false,
            };

        // Compressed request bodies cannot be inspected here unless a
        // `compression` plugin normalized them before this phase. Rather than
        // silently pass (which would let a caller gzip the body to bypass every
        // reject-style policy), DEFER: mark the request and re-inspect in
        // `on_final_request_body`, which runs after decompression. If no
        // decompression happened by then, that hook fails closed
        // (`compressed_body`). See the "Compressed request bodies" section in
        // this module's docs. A compressed body that is not even labelled JSON
        // cannot be sniffed, so it is passed through (documented residual: a
        // backend would have to both decompress and ignore the media type).
        if has_non_identity_content_encoding(headers) {
            if declared_json {
                ctx.metadata
                    .insert(self.final_inspection_marker.clone(), "true".to_string());
            }
            return PluginResult::Continue;
        }

        // Get request body from metadata. A sniffed body is only claimed when it
        // is UTF-8 text that opens a JSON object; prose, forms, and binary
        // uploads under a non-JSON media type pass through.
        let body = match ctx.metadata.get("request_body") {
            Some(body) if !declared_json && !looks_like_json_object(body) => {
                return PluginResult::Continue;
            }
            Some(b) if !b.is_empty() => b.as_str(),
            Some(_) => {
                return self.handle_uninspectable_body(ctx, "empty_body", 400, || {
                    "JSON request body is empty and cannot be inspected".to_string()
                });
            }
            None if !declared_json => return PluginResult::Continue,
            None => {
                // The `non_utf8_body` (400) vs `missing_buffered_body` (500)
                // discrimination relies on the exact contract of
                // `crate::proxy::store_request_body_metadata`: it always records
                // `request_body_size_bytes` for a buffered body but removes
                // `request_body` when the bytes are not valid UTF-8, and sets
                // both for a valid body. Keep this in sync if that helper changes
                // (e.g. lossy UTF-8 decoding) — otherwise a 400 could silently
                // flip to a 500 or vice versa.
                let (reason, status_code, details): (_, _, &'static str) =
                    if ctx.metadata.contains_key("request_body_size_bytes") {
                        (
                            "non_utf8_body",
                            400,
                            "Request body was buffered but is not valid UTF-8 JSON",
                        )
                    } else {
                        // For matching POST JSON requests, body buffering should
                        // always provide metadata before this hook. Missing metadata
                        // indicates an internal plugin runner inconsistency.
                        (
                            "missing_buffered_body",
                            500,
                            "Buffered request body metadata was unavailable for request inspection",
                        )
                    };
                return self
                    .handle_uninspectable_body(ctx, reason, status_code, || details.to_string());
            }
        };

        // Duplicate object member names make the evaluated document and the
        // forwarded bytes two different documents: `serde_json` keeps the LAST
        // value while a first-key-wins backend acts on the first, so a body that
        // passes model/token policy here could still deliver a forbidden value
        // (advisory `GHSA-c78j-5w9p-cpq6`). Screen before evaluating, and reject
        // rather than canonicalize — reject-mode forwards the original bytes.
        if let Some(reason) = ctx.json_scan_memo.ambiguity_str(body) {
            return self
                .handle_uninspectable_body(ctx, "ambiguous_json", 400, || reason.to_string());
        }

        // Parse JSON
        let mut json: Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(err) => {
                return self.handle_uninspectable_body(ctx, "malformed_json", 400, || {
                    format!("Malformed JSON request body cannot be inspected: {err}")
                });
            }
        };

        // Run all validation checks
        let path_models = self.path_models(&ctx.path);
        if let Err(rejection) = self.validate(&json, &path_models) {
            return policy_reject(ctx, rejection, "before_proxy");
        }

        // Eagerly apply max_tokens transformations so downstream plugins
        // (e.g. ai_federation) see the modified body if they short-circuit
        // before the transform_request_body phase runs.
        let mutation = self.apply_token_mutations(&mut json);
        if mutation.modified()
            && let Ok(new_body) = serde_json::to_string(&json)
        {
            ctx.metadata.insert("request_body".to_string(), new_body);
        }
        record_token_mutation(ctx, mutation);

        // This instance accepted the original JSON POST. Carry that scope into
        // the final hook so later body/header transforms cannot create a policy
        // violation after admission.
        ctx.metadata
            .insert(self.final_inspection_marker.clone(), "true".to_string());

        PluginResult::Continue
    }

    fn needs_final_request_body_context(&self) -> bool {
        // The final-body hook records uninspectable-body bookkeeping in
        // `ctx.metadata` and consumes the per-instance scope marker, so it needs
        // the real mutable context, not the no-op default wrapper.
        self.requires_request_body
    }

    /// Inspect the final backend-visible body after all `transform_request_body`
    /// hooks (including request transformers and decompression) have run.
    ///
    /// `before_proxy` records this instance's JSON POST scope before validating
    /// an ordinary body or deferring a compressed one. This hook then closes both
    /// post-transform gaps:
    ///
    /// - If the marker is absent, the request was outside this guard's scope.
    /// - If `Content-Encoding` is still non-identity, decompression did not
    ///   happen (no `compression` plugin, or it could not decode the body): the
    ///   body is still compressed and uninspectable — fail closed via
    ///   `fail_on_uninspectable_body` (reason `compressed_body`).
    /// - Otherwise the body is plaintext JSON: screen it for duplicate members,
    ///   then parse and validate the final representation, rejecting policy
    ///   violations introduced by later body transforms. Clamp/default controls
    ///   fail closed if a later transform undoes them because this hook cannot
    ///   replace body bytes.
    ///
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only act on requests THIS instance admitted into scope. The marker is
        // instance-specific, so co-located guard instances cannot consume each
        // other's final validation work.
        if ctx.metadata.remove(&self.final_inspection_marker).is_none() {
            return PluginResult::Continue;
        }

        // The marker can only be set by `before_proxy` on a POST. Keep the method
        // check defensive for direct hook callers and future runner changes.
        if ctx.method != "POST" {
            return PluginResult::Continue;
        }

        // If the body is still encoded, no `transform_request_body` decompressed
        // it. It cannot be inspected — fail closed (or pass through in
        // compatibility mode). This is the deliberate-bypass case: a caller that
        // gzipped the body to skip policy on a proxy without `compression`.
        if has_non_identity_content_encoding(headers) {
            return self.handle_uninspectable_body(ctx, "compressed_body", 400, || {
                "Request body is still compressed after request transforms and cannot be inspected"
                    .to_string()
            });
        }

        // A decompressed-to-empty (or never-populated) body cannot be inspected.
        if body.is_empty() {
            return self.handle_uninspectable_body(ctx, "empty_body", 400, || {
                "Request body is empty after request transforms and cannot be inspected".to_string()
            });
        }

        // The backend receives exactly these bytes, so they must be one
        // unambiguous document (see the matching screen in `before_proxy`).
        if let Some(reason) = ctx.json_scan_memo.ambiguity(body) {
            return self
                .handle_uninspectable_body(ctx, "ambiguous_json", 400, || reason.to_string());
        }

        // The body was decompressed (or was never really compressed). Parse and
        // run the full reject-style policy set.
        let json: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(err) => {
                return self.handle_uninspectable_body(ctx, "malformed_json", 400, || {
                    format!("Malformed JSON request body cannot be inspected: {err}")
                });
            }
        };

        let path_models = self.path_models(&ctx.path);
        if let Err(rejection) = self.validate_final_body(&json, &path_models) {
            return policy_reject(ctx, rejection, "final_request_body");
        }

        PluginResult::Continue
    }

    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        _request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if ctx.method != "POST" {
            return None;
        }
        // A request this instance admitted (its scope marker is set, including a
        // sniffed non-JSON-labelled body) is rewritten whatever its current
        // label; otherwise only a JSON-labelled, non-framed body is.
        let in_scope = ctx.metadata.contains_key(&self.final_inspection_marker)
            || content_type.is_some_and(|content_type| {
                is_json_content_type(content_type) && !is_framed_grpc_content_type(content_type)
            });
        if !in_scope {
            return None;
        }
        self.transform_scoped_json_body(ctx, body)
    }

    async fn transform_request_body(
        &self,
        _body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // Methodless runners cannot prove the documented JSON POST scope. The
        // normal H1/H2/H3 paths provide RequestContext and use the override above;
        // unsupported context-free paths must leave the body unchanged.
        None
    }
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ai_request_guard: `{field}` must be a string"))
}

fn optional_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| format!("ai_request_guard: `{field}` must be an unsigned integer"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("ai_request_guard: `{field}` must be a boolean"))
}

fn optional_string_vec(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("ai_request_guard: `{field}` must be an array"));
    };
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let Some(value) = value.as_str() else {
            return Err(format!(
                "ai_request_guard: `{field}` must contain only strings"
            ));
        };
        out.push(value.to_string());
    }
    Ok(Some(out))
}

fn optional_lowercase_set(
    config: &Value,
    field: &'static str,
) -> Result<Option<HashSet<String>>, String> {
    optional_string_vec(config, field)
        .map(|values| values.map(|values| values.into_iter().map(|s| s.to_lowercase()).collect()))
}
