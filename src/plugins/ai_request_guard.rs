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
//! The guard inspects plain HTTP JSON request bodies. Bodies that are not bare
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

/// Prefix for the per-instance metadata marker set in `before_proxy` when a
/// compressed request body was deferred to `on_final_request_body` (where the
/// body is inspected after any `compression` `transform_request_body`
/// decompression has run). Its presence tells the final-body hook that this
/// request still needs JSON-policy evaluation; its absence means `before_proxy`
/// already inspected the body, so the final-body hook must not re-validate
/// (avoids double work on the common, uncompressed path).
///
/// The full marker key is `{DEFERRED_COMPRESSED_MARKER_PREFIX}{instance_id}`
/// (see [`AiRequestGuard::deferred_compressed_marker_key`]). It MUST be
/// instance-specific: multiple `ai_request_guard` instances can run on the same
/// proxy (e.g. two proxy/proxy-group configs with different policies, all on the
/// same request). With a single shared marker the first instance's
/// `on_final_request_body` would `remove()` the marker and every later instance
/// would treat the decompressed body as already inspected — silently skipping
/// its reject-style policy on compressed uploads. Keying by a unique per-instance
/// id lets each instance defer, inspect, and clear its own marker independently.
const DEFERRED_COMPRESSED_MARKER_PREFIX: &str = "ai_request_guard.deferred_compressed_body.";

/// Process-wide source of unique per-instance ids for the deferred-compressed
/// marker. Mirrors the `openapi_validator` `INSTANCE_ID_COUNTER` pattern: a
/// monotonically increasing counter assigned once at construction guarantees two
/// `ai_request_guard` instances never collide on the same marker key, regardless
/// of how they are configured. Starts at 1 so a marker key is never the bare
/// prefix.
static DEFERRED_MARKER_COUNTER: AtomicU64 = AtomicU64::new(1);

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

const TOP_LEVEL_TOKEN_FIELDS: &[&str] = &[
    "max_tokens",
    "max_output_tokens",
    "max_completion_tokens",
    "max_new_tokens",
    "max_tokens_to_sample",
    "maxOutputTokens",
    "maxTokens",
];

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
    Auto,
}

pub struct AiRequestGuard {
    max_tokens_limit: Option<u64>,
    enforce_max_tokens: MaxTokensAction,
    default_max_tokens: Option<u64>,
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
    /// Instance-specific metadata key used to defer a compressed request body
    /// from `before_proxy` to `on_final_request_body`. Built once at
    /// construction as `{DEFERRED_COMPRESSED_MARKER_PREFIX}{unique_id}` so that
    /// co-located `ai_request_guard` instances never consume each other's
    /// deferral marker. See [`DEFERRED_COMPRESSED_MARKER_PREFIX`].
    deferred_compressed_marker: String,
}

impl AiRequestGuard {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_request_guard: config must be an object".to_string());
        }

        let max_tokens_limit = optional_u64(config, "max_tokens_limit")?;
        let enforce_max_tokens = match optional_string(config, "enforce_max_tokens")?
            .unwrap_or("reject")
        {
            "reject" => MaxTokensAction::Reject,
            "clamp" => MaxTokensAction::Clamp,
            other => {
                return Err(format!(
                    "ai_request_guard: 'enforce_max_tokens' must be one of 'reject' or 'clamp', got: {other:?}"
                ));
            }
        };
        let default_max_tokens = optional_u64(config, "default_max_tokens")?;
        let supported_schema = match optional_string(config, "supported_schema")?.unwrap_or("auto")
        {
            "chat_completions" => SupportedSchema::ChatCompletions,
            "responses" => SupportedSchema::Responses,
            "provider_native" => SupportedSchema::ProviderNative,
            "auto" => SupportedSchema::Auto,
            other => {
                return Err(format!(
                    "ai_request_guard: 'supported_schema' must be one of 'chat_completions', 'responses', 'provider_native', or 'auto', got: {other:?}"
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
                "ai_request_guard: 'default_max_tokens' ({default}) must be <= 'max_tokens_limit' ({limit})"
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
                    "ai_request_guard: 'temperature_range' must be an array of two numbers"
                        .to_string(),
                );
            };
            if arr.len() != 2 {
                return Err(format!(
                    "ai_request_guard: 'temperature_range' must have exactly 2 elements, got {}",
                    arr.len()
                ));
            }
            let Some(min) = arr[0].as_f64() else {
                return Err("ai_request_guard: 'temperature_range[0]' must be a number".to_string());
            };
            let Some(max) = arr[1].as_f64() else {
                return Err("ai_request_guard: 'temperature_range[1]' must be a number".to_string());
            };
            if !min.is_finite() || !max.is_finite() {
                return Err(format!(
                    "ai_request_guard: 'temperature_range' bounds must be finite, got [{min}, {max}]"
                ));
            }
            if min > max {
                return Err(format!(
                    "ai_request_guard: 'temperature_range' min must be <= max, got [{min}, {max}]"
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
                 (max_tokens_limit, default_max_tokens, allowed_models, blocked_models, \
                 require_user_field, max_messages, max_prompt_characters, \
                 temperature_range, block_system_prompts, strict_schema, or \
                 required_metadata_fields)"
                .to_string());
        }

        // Assign a unique per-instance deferral-marker key so multiple
        // `ai_request_guard` instances on the same proxy cannot consume each
        // other's compressed-body marker (each defers / inspects / clears its
        // own). See `DEFERRED_COMPRESSED_MARKER_PREFIX`.
        let instance_id = DEFERRED_MARKER_COUNTER.fetch_add(1, Ordering::Relaxed);
        let deferred_compressed_marker =
            format!("{DEFERRED_COMPRESSED_MARKER_PREFIX}{instance_id}");

        Ok(Self {
            max_tokens_limit,
            enforce_max_tokens,
            default_max_tokens,
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
            deferred_compressed_marker,
        })
    }

    /// The instance-specific metadata key this guard uses to defer a compressed
    /// request body from `before_proxy` to `on_final_request_body`. Exposed so
    /// callers (and tests) can observe or simulate the deferral for this exact
    /// instance; two instances always return distinct keys.
    ///
    /// Only the external test crate (`tests/unit/plugins/ai_request_guard_tests.rs`)
    /// calls this — production code reads `self.deferred_compressed_marker`
    /// directly in `before_proxy` / `on_final_request_body`. The binary crate
    /// only ever uses `AiRequestGuard` as a `dyn Plugin`, so its dead-code pass
    /// (which can't see the separate test crate) would otherwise flag this
    /// accessor. `#[allow(dead_code)]` mirrors the established pattern for
    /// test-only `pub(crate)` accessors elsewhere in `src/plugins/`.
    #[allow(dead_code)]
    pub fn deferred_compressed_marker_key(&self) -> &str {
        &self.deferred_compressed_marker
    }

    /// Validate the request body JSON. Returns Err with a rejection tuple on failure.
    fn validate(&self, json: &Value) -> Result<(), (String, String)> {
        // Optional schema admission. In non-strict mode, the guard still applies
        // every configured policy to any fields it recognizes, preserving the
        // historical pass-through behavior for unusual provider payloads.
        if self.strict_schema && !schema_matches(json, self.supported_schema) {
            return Err((
                "Unsupported AI request schema".to_string(),
                schema_rejection_details(self.supported_schema),
            ));
        }

        // Model blocking/allowlisting
        if !self.allowed_models.is_empty() || !self.blocked_models.is_empty() {
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
                        return Err(model_field_rejection(INVALID_MODEL_FIELD_TITLE));
                    }

                    let model_lower = model.to_lowercase();

                    if !self.blocked_models.is_empty()
                        && self.blocked_models.contains(model_lower.as_str())
                    {
                        return Err((
                            "Model not allowed".to_string(),
                            format!(
                                "Model '{}' is blocked by gateway policy",
                                escape_json_string(model)
                            ),
                        ));
                    }

                    if !self.allowed_models.is_empty()
                        && !self.allowed_models.contains(model_lower.as_str())
                    {
                        return Err((
                            "Model not allowed".to_string(),
                            format!(
                                "Model '{}' is not in the allowed models list",
                                escape_json_string(model)
                            ),
                        ));
                    }
                }
                // Present but wrong-typed (number/bool/array/object/null):
                // the field exists, so report it as invalid rather than
                // missing, sharing the title with the empty-string arm above.
                // This rejects regardless of `require_model_for_model_policy` —
                // the opt-out only relaxes the *missing-field* case, never a
                // present-but-malformed value that would otherwise skip the
                // allowlist/blocklist.
                Some(_) => {
                    return Err(model_field_rejection(INVALID_MODEL_FIELD_TITLE));
                }
                None if self.require_model_for_model_policy => {
                    return Err(model_field_rejection(MISSING_MODEL_FIELD_TITLE));
                }
                None => {}
            }
        }

        // Max tokens check (reject mode only — clamp is handled in transform_request_body)
        if self.enforce_max_tokens == MaxTokensAction::Reject
            && let Some(limit) = self.max_tokens_limit
        {
            let requested = max_requested_tokens(json);
            if let Some(req) = requested
                && req > limit
            {
                return Err((
                    "max_tokens exceeds limit".to_string(),
                    format!("Requested {} tokens, maximum allowed is {}", req, limit),
                ));
            }
        }

        // Message count
        if let Some(max_msgs) = self.max_messages {
            let count = count_message_entries(json);
            if count > max_msgs {
                return Err((
                    "Too many messages".to_string(),
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
                return Err((
                    "Prompt too long".to_string(),
                    format!(
                        "Total prompt length is {} characters, maximum allowed is {}",
                        total_chars, max_chars
                    ),
                ));
            }
        }

        // Temperature range
        if let Some((min_temp, max_temp)) = self.temperature_range
            && let Some(temp) = json.get("temperature").and_then(|v| v.as_f64())
            && (temp < min_temp || temp > max_temp)
        {
            return Err((
                "Temperature out of range".to_string(),
                format!(
                    "Temperature {} is outside allowed range [{}, {}]",
                    temp, min_temp, max_temp
                ),
            ));
        }

        // System prompt blocking
        if self.block_system_prompts && contains_system_prompt(json, &self.system_prompt_aliases) {
            return Err((
                "System prompts not allowed".to_string(),
                "Requests with system, developer, instructions, or aliased system-prompt fields are blocked by gateway policy"
                    .to_string(),
            ));
        }

        // Require user field
        if self.require_user_field && json.get("user").is_none() {
            return Err((
                "Missing required field".to_string(),
                "The 'user' field is required for audit trail purposes".to_string(),
            ));
        }

        // Required metadata fields
        for field in &self.required_metadata_fields {
            if json.get(field.as_str()).is_none() {
                return Err((
                    "Missing required field".to_string(),
                    format!(
                        "Required field '{}' is missing from the request",
                        escape_json_string(field)
                    ),
                ));
            }
        }

        Ok(())
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
            "compressed_body" => "Compressed request body could not be inspected",
            _ => "Request body could not be inspected",
        };
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

/// Build the rejection tuple for a `model` field that violates the required
/// model policy. `error` is the title; the shared `details` string documents
/// the constraint for both the missing and present-but-invalid cases.
fn model_field_rejection(error: &'static str) -> (String, String) {
    (
        error.to_string(),
        "The 'model' field must be a non-empty string when model policy is configured".to_string(),
    )
}

fn schema_matches(json: &Value, supported_schema: SupportedSchema) -> bool {
    match supported_schema {
        SupportedSchema::ChatCompletions => looks_like_chat_completions(json),
        SupportedSchema::Responses => looks_like_responses(json),
        SupportedSchema::ProviderNative => looks_like_provider_native(json),
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
        // Provider-native top-level markers disqualify the body from the OpenAI
        // Chat Completions family even when it also carries a `messages` array
        // (e.g. Anthropic `{"system": ..., "messages": [...]}`, Cohere
        // `preamble`/`message`/`chat_history`, RAG `documents`). In strict
        // `chat_completions` mode these must be rejected rather than admitted as
        // chat schema.
        && json.get("system").is_none()
        && json.get("preamble").is_none()
        && json.get("message").is_none()
        && json.get("chat_history").is_none()
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
        // Anthropic Messages and Cohere v2 can be indistinguishable from
        // OpenAI-style chat when they carry only a `messages` array.
        || json.get("messages").and_then(Value::as_array).is_some()
}

/// Recognizes legacy text-completion and text-generation bodies that carry a
/// single prompt string instead of a message array: OpenAI legacy completions
/// (`{"model", "prompt"}`), TGI/HuggingFace text-generation
/// (`{"inputs", "max_new_tokens"}`), and Amazon Titan text-generation
/// (`{"inputText", "textGenerationConfig"}`). `prompt`/`inputs`/`inputText` are
/// in `TOP_LEVEL_PROMPT_FIELDS`, `max_new_tokens`/`max_tokens_to_sample` are
/// honored as token fields, and `textGenerationConfig.maxTokenCount` is read by
/// `max_requested_tokens` / `clamp_max_token_fields`, so strict mode must admit
/// these shapes rather than reject them as unsupported.
fn looks_like_legacy_completions(json: &Value) -> bool {
    json.get("prompt").is_some()
        || json.get("inputs").is_some()
        || json.get("inputText").is_some()
        || json.get("textGenerationConfig").is_some()
}

fn max_requested_tokens(json: &Value) -> Option<u64> {
    let mut requested = None;
    for field in TOP_LEVEL_TOKEN_FIELDS {
        update_max_token(&mut requested, json.get(field).and_then(Value::as_u64));
    }
    update_max_token(
        &mut requested,
        json.get("generationConfig")
            .and_then(|v| v.get("maxOutputTokens"))
            .and_then(Value::as_u64),
    );
    update_max_token(
        &mut requested,
        json.get("inferenceConfig")
            .and_then(|v| v.get("maxTokens"))
            .and_then(Value::as_u64),
    );
    update_max_token(
        &mut requested,
        json.get("textGenerationConfig")
            .and_then(|v| v.get("maxTokenCount"))
            .and_then(Value::as_u64),
    );
    requested
}

fn update_max_token(current: &mut Option<u64>, candidate: Option<u64>) {
    if let Some(candidate) = candidate {
        *current = Some(current.map_or(candidate, |value| value.max(candidate)));
    }
}

/// Whether the request already caps output tokens for the *specific* provider
/// that `default_max_tokens` would be injected into.
///
/// This is deliberately provider-aware rather than schema-agnostic. A previous
/// `has_any_max_token_field` check treated any token-looking top-level field as
/// an existing cap, so a Gemini- or TGI-native body carrying a stray OpenAI
/// `max_tokens` (which those backends ignore) suppressed injection into the
/// real field (`generationConfig.maxOutputTokens` / `max_new_tokens`), silently
/// dropping the documented default cap. We only treat the *target* provider's
/// own output-token field as an existing cap so injection still lands in the
/// field the backend actually honors.
fn target_already_caps_output(json: &Value, target: DefaultTokenTarget) -> bool {
    match target {
        DefaultTokenTarget::Gemini => json
            .get("generationConfig")
            .is_some_and(|v| v.get("maxOutputTokens").is_some()),
        DefaultTokenTarget::Bedrock => json
            .get("inferenceConfig")
            .is_some_and(|v| v.get("maxTokens").is_some()),
        DefaultTokenTarget::TextGeneration => json.get("max_new_tokens").is_some(),
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
            .any(|field| json.get(*field).is_some()),
    }
}

fn clamp_max_token_fields(json: &mut Value, limit: u64) -> bool {
    let mut modified = false;
    if let Some(obj) = json.as_object_mut() {
        for field in TOP_LEVEL_TOKEN_FIELDS {
            modified |= clamp_number_field(obj, field, limit);
        }
    }
    for (container, field) in [
        ("generationConfig", "maxOutputTokens"),
        ("inferenceConfig", "maxTokens"),
        ("textGenerationConfig", "maxTokenCount"),
    ] {
        if let Some(obj) = json.get_mut(container).and_then(Value::as_object_mut) {
            modified |= clamp_number_field(obj, field, limit);
        }
    }
    modified
}

fn clamp_number_field(obj: &mut serde_json::Map<String, Value>, field: &str, limit: u64) -> bool {
    if let Some(current) = obj.get(field).and_then(Value::as_u64)
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
/// suppress the top-level default cap. `inject_default_max_tokens` always keeps
/// a top-level fallback for top-level-compatible upstreams, then adds the
/// provider-native cap when a native target is detected.
fn default_token_target(json: &Value) -> DefaultTokenTarget {
    if json.get("generationConfig").is_some()
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

fn top_level_already_caps_output(json: &Value) -> bool {
    TOP_LEVEL_TOKEN_FIELDS
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
            let entry = obj
                .entry("generationConfig".to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(gen_config) = entry.as_object_mut() {
                gen_config.insert("maxOutputTokens".to_string(), Value::Number(default.into()));
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
            obj.insert("max_new_tokens".to_string(), Value::Number(default.into()));
            true
        }
        DefaultTokenTarget::TopLevel => false,
    }
}

fn inject_default_max_tokens(json: &mut Value, default: u64) -> bool {
    let target = default_token_target(json);
    let top_level_already_capped = top_level_already_caps_output(json);
    let target_already_capped = target_already_caps_output(json, target);
    let Some(obj) = json.as_object_mut() else {
        return false;
    };

    let mut modified = false;

    // Request-body schema markers are client controlled and may not match the
    // configured upstream. Always inject the top-level fallback unless a
    // recognized top-level cap already exists, so an OpenAI-compatible backend
    // cannot be left uncapped by a stray provider-native marker.
    if !top_level_already_capped {
        obj.insert("max_tokens".to_string(), Value::Number(default.into()));
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

    for field in [
        "documents",
        "retrieved_context",
        "tool_results",
        "toolResults",
    ] {
        count_text_value(json.get(field), &mut total);
    }

    count_tool_definition_text(json.get("tools"), &mut total);
    count_tool_definition_text(json.get("functions"), &mut total);
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
                if is_typed_non_text_content_part(obj) {
                    return;
                }
            }
            if let Some(parts) = obj.get("parts") {
                count_text_value(Some(parts), total);
            } else if let Some(content) = obj.get("content") {
                count_text_value(Some(content), total);
            } else if let Some(message) = obj.get("message") {
                count_text_value(Some(message), total);
            } else if let Some(text) = obj.get("text") {
                count_text_value(Some(text), total);
            }
        }
        _ => {}
    }
}

fn is_text_content_part_type(part_type: &str) -> bool {
    matches!(part_type, "text" | "input_text" | "output_text")
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
///   * Anthropic / Bedrock content blocks: `messages[].content[]` entries of
///     `type: "tool_use"` carrying an `input` arguments object
///   * Gemini: `contents[].parts[]` entries carrying `functionCall.args`
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

    // Anthropic / Bedrock Converse assistant message: tool calls are typed
    // content blocks (`content[]` entries of `type: "tool_use"` whose `input`
    // object is the model-emitted arguments). Scope to the typed block so an
    // unrelated `input` key elsewhere is not counted.
    if let Some(Value::Array(blocks)) = obj.get("content") {
        for block in blocks {
            if let Value::Object(block_obj) = block
                && block_obj.get("type").and_then(Value::as_str) == Some("tool_use")
                && let Some(input) = block_obj.get("input")
            {
                count_argument_value(input, total);
            }
        }
    }

    // Gemini: tool calls live in `contents[].parts[]` entries carrying a
    // `functionCall` object whose `args` is the arguments payload.
    if let Some(Value::Array(parts)) = obj.get("parts") {
        for part in parts {
            if let Some(args) = part
                .get("functionCall")
                .and_then(|function_call| function_call.get("args"))
            {
                count_argument_value(args, total);
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

fn add_chars(total: &mut u64, text: &str) {
    *total = total.saturating_add(text.chars().count() as u64);
}

fn contains_system_prompt(json: &Value, aliases: &HashSet<String>) -> bool {
    object_has_system_prompt_field(json, aliases)
        || value_has_system_role(json.get("messages"), aliases)
        || value_has_system_role(json.get("input"), aliases)
        || value_has_system_role(json.get("contents"), aliases)
        || value_has_system_role(json.get("chat_history"), aliases)
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
        // Skip framed gRPC / gRPC-Web bodies: `application/grpc*` and
        // `application/grpc-web*` carry length-prefixed (and, for `-text`,
        // base64) wire frames, not bare JSON — even the `+json` variants, which
        // `is_json_content_type` matches on the `+json` suffix. They are never
        // JSON-inspectable, so buffering them would only burn memory for a
        // request the guard always passes through.
        //
        // Compressed bodies (`content-encoding: gzip|br|…`) ARE buffered: even
        // though they cannot be inspected in `before_proxy`, the guard re-runs
        // inspection in `on_final_request_body` (after any `compression`
        // decompression), and failing closed there requires the buffered body.
        ctx.headers
            .get("content-type")
            .is_some_and(|ct| is_json_content_type(ct) && !is_framed_grpc_content_type(ct))
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

        // Check content-type. Read from the `headers` parameter, never
        // `ctx.headers`: when no plugin modifies request headers the handler
        // `std::mem::take()`s them out of `ctx.headers` for this phase.
        let content_type = headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");
        if !is_json_content_type(content_type) {
            return PluginResult::Continue;
        }

        // Framed gRPC / gRPC-Web bodies (`application/grpc+json`,
        // `application/grpc-web-text+json`, etc.) match `is_json_content_type`
        // via their `+json` suffix but carry length-prefixed (and, for `-text`,
        // base64) wire frames, not a bare JSON document. Parsing that framing as
        // JSON always fails; skip inspection so valid framed requests reach the
        // backend instead of being 400'd as malformed. The guard's JSON policies
        // target plain HTTP AI APIs, so this is the correct scope, not a gap.
        if is_framed_grpc_content_type(content_type) {
            return PluginResult::Continue;
        }

        // Compressed request bodies cannot be inspected here: the `compression`
        // plugin's `decompress_request` runs in the later `transform_request_body`
        // phase, so at `before_proxy` time the buffered body is still the
        // compressed (non-UTF-8) bytes. Rather than silently pass (which would
        // let a caller gzip the body to bypass every reject-style policy), DEFER:
        // mark the request and re-inspect in `on_final_request_body`, which runs
        // after decompression. If no decompression happened by then, that hook
        // fails closed (`compressed_body`). See the "Compressed request bodies"
        // section in this module's docs.
        if has_non_identity_content_encoding(headers) {
            ctx.metadata
                .insert(self.deferred_compressed_marker.clone(), "true".to_string());
            return PluginResult::Continue;
        }

        // Get request body from metadata
        let body = match ctx.metadata.get("request_body") {
            Some(b) if !b.is_empty() => b.as_str(),
            Some(_) => {
                return self.handle_uninspectable_body(ctx, "empty_body", 400, || {
                    "JSON request body is empty and cannot be inspected".to_string()
                });
            }
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
        if let Err((error, details)) = self.validate(&json) {
            debug!(
                "ai_request_guard: validation failed: {} - {}",
                error, details
            );
            return PluginResult::Reject {
                status_code: 400,
                body: serde_json::json!({
                    "error": error,
                    "details": details,
                })
                .to_string(),
                headers: HashMap::new(),
            };
        }

        // Eagerly apply max_tokens transformations so downstream plugins
        // (e.g. ai_federation) see the modified body if they short-circuit
        // before the transform_request_body phase runs.
        let mut body_modified = false;

        // Clamp max_tokens if over limit
        if let Some(limit) = self.max_tokens_limit
            && self.enforce_max_tokens == MaxTokensAction::Clamp
        {
            body_modified |= clamp_max_token_fields(&mut json, limit);
        }

        // Inject default_max_tokens if not present
        if let Some(default) = self.default_max_tokens {
            body_modified |= inject_default_max_tokens(&mut json, default);
        }

        if body_modified && let Ok(new_body) = serde_json::to_string(&json) {
            ctx.metadata.insert("request_body".to_string(), new_body);
        }

        PluginResult::Continue
    }

    fn needs_final_request_body_context(&self) -> bool {
        // The final-body hook records uninspectable-body bookkeeping in
        // `ctx.metadata` (and reads the deferred-compressed marker), so it needs
        // the real mutable context, not the no-op default wrapper.
        self.requires_request_body
    }

    /// Re-inspect a deferred compressed request body after all
    /// `transform_request_body` hooks (including the `compression` plugin's
    /// `decompress_request`) have run.
    ///
    /// `before_proxy` cannot evaluate JSON policy on a still-compressed body, so
    /// it sets this instance's deferral marker
    /// ([`AiRequestGuard::deferred_compressed_marker_key`]) and Continues. This
    /// hook closes that deferral:
    ///
    /// - If the marker is absent, `before_proxy` already inspected the body
    ///   (plain, uncompressed path) — Continue without re-validating so the
    ///   common path pays no extra parse.
    /// - If `Content-Encoding` is still non-identity, decompression did not
    ///   happen (no `compression` plugin, or it could not decode the body): the
    ///   body is still compressed and uninspectable — fail closed via
    ///   `fail_on_uninspectable_body` (reason `compressed_body`).
    /// - Otherwise the body is now plaintext JSON: parse and run `validate()`,
    ///   rejecting on malformed JSON or any policy violation.
    ///
    /// Note: reject-style policy (model allow/block, token/prompt limits,
    /// temperature, system-prompt blocking, required fields) is enforced here.
    /// The `max_tokens` clamp / `default_max_tokens` injection is NOT re-applied
    /// to compressed bodies — those mutate the body, and the H1/H2 final-body
    /// hook contract only copies `ctx.metadata` back (body edits are dropped), so
    /// attempting them here would be inconsistent across protocols. Clamp/inject
    /// on compressed uploads remains a known limitation; the security-relevant
    /// reject policies are fully enforced.
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only act on bodies THIS instance deferred. The marker key is
        // instance-specific (see `DEFERRED_COMPRESSED_MARKER_PREFIX`), so a
        // sibling `ai_request_guard` instance on the same proxy cannot consume
        // it — each instance inspects and clears its own deferral. The marker is
        // set only for non-identity `Content-Encoding` requests, so the common
        // (uncompressed) path skips this hook entirely.
        if ctx
            .metadata
            .remove(&self.deferred_compressed_marker)
            .is_none()
        {
            return PluginResult::Continue;
        }

        // Defensive: a deferred request should still be JSON content-type and
        // not framed gRPC, but re-check against the final headers in case an
        // earlier-phase plugin relabeled the content-type. Skipping here matches
        // the `before_proxy` content-type scope.
        let content_type = headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");
        if !is_json_content_type(content_type) || is_framed_grpc_content_type(content_type) {
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

        if let Err((error, details)) = self.validate(&json) {
            debug!(
                "ai_request_guard: validation failed on decompressed body: {} - {}",
                error, details
            );
            return PluginResult::Reject {
                status_code: 400,
                body: serde_json::json!({
                    "error": error,
                    "details": details,
                })
                .to_string(),
                headers: HashMap::new(),
            };
        }

        PluginResult::Continue
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // Only transform JSON
        if let Some(ct) = content_type
            && !is_json_content_type(ct)
        {
            return None;
        }

        let mut json: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return None,
        };

        let mut modified = false;

        // Clamp max_tokens if over limit
        if let Some(limit) = self.max_tokens_limit
            && self.enforce_max_tokens == MaxTokensAction::Clamp
        {
            modified |= clamp_max_token_fields(&mut json, limit);
        }

        // Inject default_max_tokens if not present
        if let Some(default) = self.default_max_tokens {
            modified |= inject_default_max_tokens(&mut json, default);
        }

        if modified {
            serde_json::to_vec(&json).ok()
        } else {
            None
        }
    }
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ai_request_guard: '{field}' must be a string"))
}

fn optional_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| format!("ai_request_guard: '{field}' must be an unsigned integer"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("ai_request_guard: '{field}' must be a boolean"))
}

fn optional_string_vec(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("ai_request_guard: '{field}' must be an array"));
    };
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let Some(value) = value.as_str() else {
            return Err(format!(
                "ai_request_guard: '{field}' must contain only strings"
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
