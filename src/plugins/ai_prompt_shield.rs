//! AI Prompt Shield Plugin
//!
//! Scans AI/LLM request bodies for PII (personally identifiable information)
//! patterns and either rejects the request, redacts the PII, or logs a warning.
//!
//! Built-in patterns: SSN, credit card, email, US phone, API keys, AWS keys,
//! IPv4 addresses, and IBAN. Custom regex patterns can be added via config.
//!
//! ## Inspection scope
//!
//! The shield inspects bare JSON AI request bodies on the HTTP protocol view
//! only (`HTTP_ONLY_PROTOCOLS`). Native gRPC is intentionally unsupported:
//! there is no bounded, schema-aware frame/protobuf prompt contract, so the
//! plugin is not registered for `ProxyProtocol::Grpc` and must not be treated
//! as a fail-closed control for unary or streaming native gRPC traffic.
//!
//! gRPC-Web still rides the composed HTTP/gRPC-Web view. Its framed
//! `application/grpc-web*` bodies (including `+json` variants) remain outside
//! this bare-JSON policy: they are not buffered, decoded, or rewritten, so
//! message framing is never double-decoded or corrupted.
//!
//! ## The final backend-visible body is authoritative
//!
//! `before_proxy` is not the last word on the bytes a backend receives: every
//! `transform_request_body` hook — a `request_transformer` body rule, a
//! header-to-body overlay, a custom body plugin — runs afterwards and can put
//! content back that the shield already decided about. Every request this
//! shield admits into scope therefore carries an instance-private marker into
//! `on_final_request_body`, where the same detection runs again over the exact
//! dispatched representation. Reject and warn re-decide there; redact fails the
//! request closed, because that hook can refuse a request but cannot rewrite
//! wire bytes. A rejection there precedes backend dispatch and finalized-request
//! egress.
//!
//! Reject/redact instances additionally claim the finalized representation
//! (`Plugin::enforces_final_request_body_policy`), so the shared request
//! representation gate reduces a content coding to plaintext before this hook
//! reads it, or fails the request closed when it cannot.
//!
//! ## Compressed request bodies
//!
//! With the `compression` plugin's `decompress_request` enabled, request
//! decoding runs in the shared pre-`before_proxy` normalization phase: the
//! encoding header is gone by the time this plugin runs, so an ordinary
//! compressed request is scanned — and, in redact mode, rewritten — exactly
//! like a plaintext one. That is the configured path.
//!
//! A body that still carries a non-identity `Content-Encoding` when
//! `before_proxy` runs cannot be parsed there. The shield marks it for deferred
//! inspection and decides it in `on_final_request_body` instead, after request
//! transforms. Reject policy is enforced there, warn policy records its event
//! there, and redact policy fails closed when PII is present, because the
//! final-body hook cannot safely rewrite the wire body. If nothing reduced the
//! body to plaintext, enforcing actions reject the uninspectable request instead
//! of silently forwarding it.
//!
//! ## Bounded redaction output
//!
//! Redaction replaces each match with a configured placeholder, which can be
//! longer than the value it removes. Rewriting is therefore charged against an
//! aggregate per-request growth budget and stops before allocating past it;
//! `custom_patterns` that match the empty string are refused at construction so
//! a zero-width rule cannot amplify at every position.

use async_trait::async_trait;
use regex::{Regex, RegexSet};
use serde_json::Value;
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

use crate::plugins::utils::log_sampling::warn_sampled;

use super::utils::body_transform::is_json_content_type;
use super::{Plugin, PluginResult, RequestContext};

/// JSON object keys that are structural metadata (model names, IDs, roles,
/// etc.) and must never be redacted, even in `ScanMode::All`. Protects
/// values that may incidentally match PII regexes.
const STRUCTURAL_KEYS: &[&str] = &[
    "model",
    "id",
    "object",
    "role",
    "type",
    "created",
    "stream",
    "tool_call_id",
];

/// Top-level numeric/scalar LLM request parameters an operator legitimately
/// sends. Numeric values for these keys are tuning knobs, not user content, so
/// a number that incidentally matches a PII regex (for example a 9-digit
/// `seed`) is preserved. String values under these keys remain
/// attacker-controlled content and must still be redacted.
const NUMERIC_LLM_PARAMETER_KEYS: &[&str] = &[
    "temperature",
    "top_p",
    "top_k",
    "max_tokens",
    "max_output_tokens",
    "max_completion_tokens",
    "seed",
    "n",
    "best_of",
    "logprobs",
    "top_logprobs",
    "frequency_penalty",
    "presence_penalty",
    "repetition_penalty",
    "logit_bias",
];

/// Top-level request fields that carry prompt text in non-`messages` LLM
/// request shapes. Scanned in `ScanMode::Content` in addition to
/// `messages[].content`: OpenAI legacy completions use `prompt`, the
/// Responses API and embeddings use `input`, OpenAI Responses uses
/// `instructions`, Anthropic carries a top-level `system` string, Amazon
/// Bedrock Titan text-generation carries its entire prompt in `inputText`,
/// Cohere v1 `/chat` carries the current turn in `message` and the system
/// prompt in `preamble`, and Hugging Face TGI carries its prompt in `inputs`.
/// Each may be a string, an array of strings, or an array of
/// `{type:"text", text:"..."}` parts.
///
/// Mirrors the request-side field list the sibling `ai_semantic_firewall`
/// inspects, so a provider shape one plugin reads is not silently invisible to
/// the other (issue #4792).
const CONTENT_SCAN_FIELDS: &[&str] = &[
    "prompt",
    "input",
    "instructions",
    "system",
    "inputText",
    "message",
    "preamble",
    "inputs",
];

/// Whether a [`CONTENT_SCAN_FIELDS`] entry is applied by the provider as a
/// system prompt, and is therefore suppressed when `exclude_roles` excludes
/// `system`. Anthropic/Bedrock spell it `system`; Cohere v1 spells the same
/// thing `preamble`, so the long-standing `system` carve-out has to cover both
/// or `exclude_roles: [system]` would mean different things per provider.
fn is_system_prompt_scan_field(field: &str) -> bool {
    matches!(field, "system" | "preamble")
}

/// Every accepted top-level configuration property. Configuration is parsed
/// manually from `serde_json::Value`, so this allow-list is the fail-closed
/// equivalent of `#[serde(deny_unknown_fields)]`.
const ALLOWED_CONFIG_KEYS: &[&str] = &[
    "action",
    "patterns",
    "custom_patterns",
    "scan_fields",
    "exclude_roles",
    "redaction_placeholder",
    "max_scan_bytes",
];

/// Every accepted member of one `custom_patterns` entry. Entries are parsed
/// manually from `serde_json::Value`, so this allow-list is the nested
/// equivalent of the top-level [`ALLOWED_CONFIG_KEYS`] gate: without it an
/// unsupported nested option is read as `name`/`regex`, silently ignored, and
/// never diagnosed at admission.
const ALLOWED_CUSTOM_PATTERN_KEYS: &[&str] = &["name", "regex"];

/// Upper bound on one `custom_patterns[].name`. The name is operator-supplied,
/// is substituted into `redaction_placeholder`, and is echoed in construction
/// errors, so it has to be bounded before it can be multiplied by the number of
/// matches a request produces.
///
/// Counted in CHARACTERS, not bytes, so it means exactly what the published
/// `maxLength` on that property means — a byte bound here would reject names the
/// component accepts. The byte cost of a rendered replacement is bounded
/// separately and precisely by [`MAX_REDACTION_PLACEHOLDER_BYTES`].
const MAX_CUSTOM_PATTERN_NAME_CHARS: usize = 128;

/// Upper bound on the RENDERED per-pattern redaction placeholder — the
/// configured template with `{type}` already substituted. Bounding the rendered
/// form rather than the template is what actually caps amplification: a
/// template may repeat `{type}`, so a short template plus a long pattern name
/// can still render a large replacement that every match then re-emits.
const MAX_REDACTION_PLACEHOLDER_BYTES: usize = 512;

/// How much larger than its own input one redaction pass may make a request
/// body. The input is already bounded by `max_scan_bytes`, but the OUTPUT is
/// not a function of the input alone: a short pattern with a long placeholder
/// re-emits the replacement at every match, so an admitted expanding policy
/// could otherwise turn a bounded body into an unbounded allocation and an
/// unbounded synchronous rewrite. Only net growth is charged, so a redaction
/// that shrinks or preserves the body spends nothing.
const REDACTION_OUTPUT_EXPANSION_FACTOR: usize = 4;

/// Floor for the growth allowance so a deliberately tiny `max_scan_bytes` (or a
/// very small body) still admits ordinary placeholder expansion.
const MIN_REDACTION_OUTPUT_GROWTH_BYTES: usize = 64 * 1024;

/// Absolute ceiling on the growth allowance, independent of `max_scan_bytes`.
const MAX_REDACTION_OUTPUT_GROWTH_BYTES: usize = 64 * 1024 * 1024;

/// Prefix for the instance-specific marker recording that `before_proxy`
/// admitted a request into this shield instance's scope, so
/// `on_final_request_body` revalidates the exact backend-visible body it
/// decided about. Instance-scoped for the same reason the deferral marker is:
/// co-located shield instances must not consume each other's final check.
const FINAL_INSPECTION_MARKER_PREFIX: &str = "ai_prompt_shield.final_inspection.";

/// Prefix for the instance-specific marker used to defer compressed request
/// inspection until after all request-body transforms. Multiple shield
/// instances may coexist on a proxy, so each instance must own an independent
/// marker or one instance could consume another's deferred policy check.
const DEFERRED_COMPRESSED_MARKER_PREFIX: &str = "ai_prompt_shield.deferred_compressed_body.";

static DEFERRED_MARKER_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Adjacent text parts in one logical message are joined without inserting
/// model-visible content. Boundary byte offsets are retained separately, and a
/// detection is added only when a regex match actually crosses one of them.
const LOGICAL_TEXT_PART_SEPARATOR: &str = "";

/// Action to take when PII is detected.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ShieldAction {
    Reject,
    Redact,
    Warn,
}

/// How to scan the request body.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScanMode {
    /// Only scan `content` fields within the `messages` array.
    Content,
    /// Scan the entire request body as text.
    All,
}

/// Result of attempting redaction on a request body.
enum RedactionOutcome {
    /// No PII to redact, body not parseable, or over `max_scan_bytes` — the
    /// caller should forward the body unchanged without claiming redaction.
    NoChange,
    /// PII was detected and the rewritten body no longer contains any
    /// detectable PII — safe to forward and report as redacted.
    Redacted(Value),
    /// PII was detected but could not be fully removed (e.g. it was carried in
    /// an object key, or matched only a cross-token/contextual custom pattern
    /// that has no single rewritable token). The carried `Value` is the
    /// best-effort redaction (string values and numeric scalars already
    /// removed). `before_proxy` fails the request closed on this outcome rather
    /// than forwarding the residual value while falsely reporting redaction;
    /// the body-transform path, which cannot reject, still emits this
    /// best-effort body so it never forwards the *original* unredacted bytes.
    Incomplete(Value),
    /// Redaction could not be completed inside the per-request output/work
    /// budget (see [`REDACTION_OUTPUT_EXPANSION_FACTOR`]), or a configured
    /// pattern produced a zero-width match that would amplify at every
    /// position.
    ///
    /// Deliberately carries NO body: a partially rewritten document must never
    /// be forwarded. `before_proxy` fails the request closed, and the
    /// body-transform path leaves the wire bytes untouched so the final
    /// request-body hook — which sees the same unredacted PII — rejects before
    /// dispatch.
    BudgetExceeded,
}

/// Aggregate output/work allowance for one redaction pass over one request
/// body, shared by every string the pass rewrites.
///
/// Interior mutability because the redactors are handed to the JSON walkers as
/// `&impl Fn(&str) -> String`. The budget is created and dropped entirely
/// inside one synchronous call, so it never crosses an `.await`.
struct RedactionBudget {
    /// Remaining net growth, in bytes, that this pass may still produce.
    remaining: Cell<usize>,
    /// Set once the pass has provably failed. Every later rewrite is skipped
    /// and the caller discards the partially rewritten document.
    exhausted: Cell<bool>,
}

impl RedactionBudget {
    /// Allowance for a body of `body_len` bytes: growth is capped at a small
    /// multiple of the input, with a floor so tiny bodies still admit ordinary
    /// placeholder expansion and an absolute ceiling regardless of config.
    fn for_body(body_len: usize) -> Self {
        let limit = body_len
            .saturating_mul(REDACTION_OUTPUT_EXPANSION_FACTOR)
            .clamp(
                MIN_REDACTION_OUTPUT_GROWTH_BYTES,
                MAX_REDACTION_OUTPUT_GROWTH_BYTES,
            );
        Self {
            remaining: Cell::new(limit),
            exhausted: Cell::new(false),
        }
    }

    fn is_exhausted(&self) -> bool {
        self.exhausted.get()
    }

    fn remaining(&self) -> usize {
        self.remaining.get()
    }

    /// Mark the whole pass failed. Callers return the ORIGINAL text so no
    /// half-rewritten string is retained.
    fn fail(&self) {
        self.exhausted.set(true);
    }

    /// Charge `bytes` of net growth, failing the pass when it does not fit.
    fn charge_growth(&self, bytes: usize) -> bool {
        match self.remaining.get().checked_sub(bytes) {
            Some(left) => {
                self.remaining.set(left);
                true
            }
            None => {
                self.fail();
                false
            }
        }
    }
}

/// Append `value` to `output` only while the result stays within `ceiling`,
/// so an expanding rewrite is refused BEFORE it allocates rather than after.
fn push_within_ceiling(output: &mut String, value: &str, ceiling: usize) -> bool {
    match output.len().checked_add(value.len()) {
        Some(next) if next <= ceiling => {
            output.push_str(value);
            true
        }
        _ => false,
    }
}

/// Replace every configured pattern's matches in `text` with that pattern's
/// pre-rendered placeholder, under `budget`.
///
/// Replacement is literal — the placeholder is appended verbatim, so `$0`,
/// `$1`, `${name}`, and `$$` are never expanded as capture references (the
/// same contract `regex::NoExpand` provided before this became a bounded
/// sink). Each append is checked against a per-string ceiling derived from the
/// remaining allowance, so no intermediate pass can allocate past the budget,
/// and only the pass's NET growth is charged, so a non-expanding redaction
/// spends nothing.
///
/// On refusal the ORIGINAL `text` is returned and the budget is marked failed:
/// the caller discards the document rather than forwarding a partial rewrite.
fn redact_text_bounded(text: &str, patterns: &[PiiPattern], budget: &RedactionBudget) -> String {
    if budget.is_exhausted() {
        return text.to_string();
    }
    // Every intermediate pass over this one string is bounded by what the
    // aggregate allowance can still pay for.
    let ceiling = text.len().saturating_add(budget.remaining());
    let mut result = text.to_string();
    for pattern in patterns {
        let mut matches = pattern.regex.find_iter(&result);
        let Some(first_match) = matches.next() else {
            continue;
        };
        let mut replaced = String::with_capacity(result.len());
        let mut cursor = 0usize;
        for matched in std::iter::once(first_match).chain(matches) {
            // A zero-width match inserts the placeholder at every position and
            // amplifies a bounded body without bound. Config admission already
            // refuses patterns that match the empty string; a contextual
            // assertion can still produce an empty span beside non-empty input,
            // so refuse those here too.
            if matched.start() == matched.end() {
                budget.fail();
                return text.to_string();
            }
            if !push_within_ceiling(&mut replaced, &result[cursor..matched.start()], ceiling)
                || !push_within_ceiling(&mut replaced, &pattern.placeholder, ceiling)
            {
                budget.fail();
                return text.to_string();
            }
            cursor = matched.end();
        }
        if !push_within_ceiling(&mut replaced, &result[cursor..], ceiling) {
            budget.fail();
            return text.to_string();
        }
        result = replaced;
    }
    let growth = result.len().saturating_sub(text.len());
    if growth > 0 && !budget.charge_growth(growth) {
        return text.to_string();
    }
    result
}

/// A named regex pattern for PII detection.
#[derive(Debug)]
struct PiiPattern {
    name: String,
    regex: Regex,
    /// Pre-rendered redaction placeholder for this pattern, with `{type}`
    /// already substituted with `name`. Built once at config-load time so
    /// `redact_text` does not re-render the template per pattern per call.
    placeholder: String,
}

pub struct AiPromptShield {
    action: ShieldAction,
    patterns: Vec<PiiPattern>,
    /// All patterns compiled into a single DFA for O(text_len) detection
    /// regardless of pattern count. Indices align with `patterns`.
    detection_set: RegexSet,
    scan_mode: ScanMode,
    exclude_roles: HashSet<String>,
    max_scan_bytes: usize,
    /// True when action is Redact — enables transform_request_body.
    needs_body_transform: bool,
    /// True when the plugin has valid patterns and may need to inspect bodies.
    requires_request_body: bool,
    /// Instance-specific metadata marker for compressed-body deferral.
    deferred_compressed_marker: String,
    /// Instance-specific metadata marker recording that `before_proxy` admitted
    /// this request into scope, so `on_final_request_body` revalidates the
    /// backend-visible body this instance already decided about.
    final_inspection_marker: String,
}

/// Built-in PII pattern definitions.
///
/// Sourced from the shared [`crate::plugins::utils::ai_pii`] table so the
/// prompt shield, response guard, and transcript audit plugins stay in lockstep.
fn builtin_pattern(name: &str) -> Option<&'static str> {
    crate::plugins::utils::ai_pii::builtin_pii_pattern(name)
}

/// True when a JSON-looking media type actually carries framed native gRPC or
/// gRPC-Web bytes instead of a bare JSON document. This mirrors the explicit
/// scope guard in `ai_request_guard`.
fn is_framed_grpc_content_type(content_type: &str) -> bool {
    if crate::proxy::backend_dispatch::is_native_grpc_content_type(content_type.as_bytes()) {
        return true;
    }

    const GRPC_WEB_PREFIX: &[u8] = b"application/grpc-web";
    let bytes = content_type.as_bytes();
    bytes
        .get(..GRPC_WEB_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(GRPC_WEB_PREFIX))
}

/// True when any comma-separated content-encoding token is non-identity.
fn has_non_identity_content_encoding(headers: &HashMap<String, String>) -> bool {
    headers.get("content-encoding").is_some_and(|value| {
        value
            .split(',')
            .map(str::trim)
            .any(|token| !token.is_empty() && !token.eq_ignore_ascii_case("identity"))
    })
}

impl AiPromptShield {
    pub fn new(config: &Value) -> Result<Self, String> {
        let Some(config_object) = config.as_object() else {
            return Err("ai_prompt_shield: config must be an object".to_string());
        };

        if let Some(unknown) = config_object
            .keys()
            .find(|key| !ALLOWED_CONFIG_KEYS.contains(&key.as_str()))
        {
            return Err(format!(
                "ai_prompt_shield: unknown config field {unknown:?}; allowed fields: {}",
                ALLOWED_CONFIG_KEYS.join(", ")
            ));
        }

        let action = match optional_string(config, "action")?.unwrap_or("reject") {
            "reject" => ShieldAction::Reject,
            "redact" => ShieldAction::Redact,
            "warn" => ShieldAction::Warn,
            other => {
                return Err(format!(
                    "ai_prompt_shield: 'action' must be one of 'reject', 'redact', or 'warn', got: {other:?}"
                ));
            }
        };

        let scan_mode = match optional_string(config, "scan_fields")?.unwrap_or("content") {
            "content" => ScanMode::Content,
            "all" => ScanMode::All,
            other => {
                return Err(format!(
                    "ai_prompt_shield: 'scan_fields' must be one of 'content' or 'all', got: {other:?}"
                ));
            }
        };

        let exclude_roles: HashSet<String> =
            optional_string_array(config, "exclude_roles")?.unwrap_or_default();

        let redaction_template =
            optional_string(config, "redaction_placeholder")?.unwrap_or("[REDACTED:{type}]");

        let max_scan_bytes =
            optional_positive_usize(config, "max_scan_bytes")?.unwrap_or(1_048_576);

        // Build pattern list from config
        let pattern_names: Vec<String> =
            optional_string_vec(config, "patterns")?.unwrap_or_else(|| {
                vec![
                    "ssn".to_string(),
                    "credit_card".to_string(),
                    "api_key".to_string(),
                    "aws_key".to_string(),
                ]
            });

        let mut patterns: Vec<PiiPattern> = Vec::new();

        // Add built-in patterns. Compile failures and unknown names are
        // fatal so the operator gets a clear error instead of silently
        // losing PII coverage.
        for name in &pattern_names {
            if let Some(regex_str) = builtin_pattern(name) {
                match Regex::new(regex_str) {
                    Ok(regex) => {
                        let placeholder = render_placeholder(redaction_template, name)?;
                        patterns.push(PiiPattern {
                            name: name.clone(),
                            regex,
                            placeholder,
                        });
                    }
                    Err(e) => {
                        return Err(format!(
                            "ai_prompt_shield: failed to compile built-in pattern '{}': {}",
                            name, e,
                        ));
                    }
                }
            } else {
                return Err(format!(
                    "ai_prompt_shield: unknown built-in pattern '{}'",
                    name,
                ));
            }
        }

        // Add custom patterns
        if let Some(custom) = optional_array(config, "custom_patterns")? {
            for (index, entry) in custom.iter().enumerate() {
                // Closed member set, exactly like the top-level gate: an
                // unsupported nested option must be diagnosed at admission
                // instead of being read as `name`/`regex` and dropped.
                let Some(entry_object) = entry.as_object() else {
                    return Err(format!(
                        "ai_prompt_shield: 'custom_patterns[{index}]' must be an object"
                    ));
                };
                if let Some(unknown) = entry_object
                    .keys()
                    .find(|key| !ALLOWED_CUSTOM_PATTERN_KEYS.contains(&key.as_str()))
                {
                    return Err(format!(
                        "ai_prompt_shield: unknown config field 'custom_patterns[{index}].{unknown}'; allowed fields: {}",
                        ALLOWED_CUSTOM_PATTERN_KEYS.join(", ")
                    ));
                }
                let name = entry_object
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or("ai_prompt_shield: custom_patterns entries require string 'name'")?;
                if name.chars().count() > MAX_CUSTOM_PATTERN_NAME_CHARS {
                    return Err(format!(
                        "ai_prompt_shield: 'custom_patterns[{index}].name' must be at most {MAX_CUSTOM_PATTERN_NAME_CHARS} characters"
                    ));
                }
                let regex_str = entry_object
                    .get("regex")
                    .and_then(Value::as_str)
                    .ok_or("ai_prompt_shield: custom_patterns entries require string 'regex'")?;
                match Regex::new(regex_str) {
                    Ok(regex) => {
                        // A pattern that matches the empty string inserts its
                        // placeholder at every position, turning a bounded body
                        // into an unbounded rewrite. Refuse it at admission
                        // rather than discovering it per request.
                        if regex.is_match("") {
                            return Err(format!(
                                "ai_prompt_shield: 'custom_patterns[{index}].regex' must not match the empty string (zero-width redaction is rejected)"
                            ));
                        }
                        let placeholder = render_placeholder(redaction_template, name)?;
                        patterns.push(PiiPattern {
                            name: name.to_string(),
                            regex,
                            placeholder,
                        });
                    }
                    Err(e) => {
                        return Err(format!(
                            "ai_prompt_shield: failed to compile custom pattern '{}': {}",
                            name, e,
                        ));
                    }
                }
            }
        }

        if patterns.is_empty() {
            return Err(
                "ai_prompt_shield: no valid patterns configured — plugin will have no effect"
                    .to_string(),
            );
        }

        let needs_body_transform = action == ShieldAction::Redact;
        let requires_request_body = !patterns.is_empty();

        // Build a single combined RegexSet for O(text_len) detection.
        // Each pattern was already validated above (compiled as a Regex), so
        // RegexSet construction will not fail for pattern syntax — but we
        // propagate any error defensively.
        let detection_set =
            RegexSet::new(patterns.iter().map(|p| p.regex.as_str())).map_err(|e| {
                format!(
                    "ai_prompt_shield: failed to build detection RegexSet: {}",
                    e
                )
            })?;
        let marker_id = DEFERRED_MARKER_COUNTER.fetch_add(1, Ordering::Relaxed);
        let deferred_compressed_marker = format!("{DEFERRED_COMPRESSED_MARKER_PREFIX}{marker_id}");
        let final_inspection_marker = format!("{FINAL_INSPECTION_MARKER_PREFIX}{marker_id}");

        Ok(Self {
            action,
            patterns,
            detection_set,
            scan_mode,
            exclude_roles,
            max_scan_bytes,
            needs_body_transform,
            requires_request_body,
            deferred_compressed_marker,
            final_inspection_marker,
        })
    }

    /// Extract text segments to scan from the request body.
    fn extract_scan_text<'a>(&self, json: &'a Value) -> Vec<&'a str> {
        match self.scan_mode {
            ScanMode::All => {
                // We can't get &str from Value for the whole body easily,
                // so we'll handle this differently in the caller.
                vec![]
            }
            ScanMode::Content => {
                let mut texts = Vec::new();
                if let Some(messages) = json.get("messages").and_then(|v| v.as_array()) {
                    for msg in messages {
                        // Skip excluded roles (O(1) HashSet lookup)
                        if let Some(role) = msg.get("role").and_then(|r| r.as_str())
                            && self.exclude_roles.contains(role)
                        {
                            continue;
                        }
                        // String content
                        if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                            texts.push(content);
                        }
                        // Array content (multimodal, and Bedrock Converse
                        // content blocks, which carry no `type` at all). A
                        // block that is not itself a text part may still carry
                        // model-visible text one level down — a Converse
                        // `toolResult`/`guardContent`, or an Anthropic
                        // `tool_result` — so it falls through to
                        // `collect_content_block_nested_text`.
                        if let Some(parts) = msg.get("content").and_then(|c| c.as_array()) {
                            for part in parts {
                                match text_content_part_text(part) {
                                    Some(text) => texts.push(text),
                                    None => collect_content_block_nested_text(part, &mut texts),
                                }
                            }
                        }
                    }
                }
                // Many widely-used LLM request shapes do not use a `messages`
                // array: OpenAI legacy completions use `prompt`, the Responses
                // API and embeddings use `input`, and Anthropic carries a
                // top-level `system` string alongside `messages`. Without
                // scanning these, Content mode silently passes PII through on
                // those endpoints. Each field may be a string, an array of
                // strings, or an array of `{type:"text", text:"..."}` parts.
                for field in CONTENT_SCAN_FIELDS {
                    if is_system_prompt_scan_field(field) && self.exclude_roles.contains("system") {
                        continue;
                    }
                    if let Some(value) = json.get(field) {
                        collect_field_text(value, &self.exclude_roles, &mut texts);
                    }
                }
                // Google Gemini / Vertex carries no `messages` array at all:
                // turns live in `contents[].parts[].text` and the system prompt
                // in `systemInstruction.parts[].text`. Without this, Content
                // mode passed every Gemini prompt through unscanned. See
                // `collect_gemini_prompt_text`.
                collect_gemini_prompt_text(json, &self.exclude_roles, &mut texts);
                // Azure OpenAI "On Your Data" carries a per-data-source
                // instruction the backend applies as a de-facto system prompt;
                // scan it so a PII/jailbreak payload smuggled there does not slip
                // past Content mode. See `collect_azure_role_information_text`.
                collect_azure_role_information_text(json, &mut texts);
                // Cohere v1 `/chat` keeps the prior turns in
                // `chat_history[].message`, which no [`CONTENT_SCAN_FIELDS`]
                // entry reaches. See `collect_cohere_chat_history_text`.
                collect_cohere_chat_history_text(json, &self.exclude_roles, &mut texts);
                // Cohere v1 `/chat` RAG documents are arbitrary maps whose
                // eligible members all reach the model, so they are read
                // member-wise. See `collect_cohere_document_text`.
                collect_cohere_document_text(json, &mut texts);
                // Google Vertex legacy `predict` carries its prompt in
                // `instances[].prompt`. See
                // `collect_vertex_instance_prompts`.
                collect_vertex_instance_prompts(json, &self.exclude_roles, &mut texts);
                texts
            }
        }
    }

    /// Detect PII in the given text segments. Returns names of detected pattern types.
    /// Uses a single `RegexSet` DFA pass per text fragment, O(text_len)
    /// regardless of pattern count.
    ///
    /// Generic over `AsRef<str>` so callers can pass borrowed `&str` slices
    /// (`ScanMode::Content`) or owned/`Cow` text (`ScanMode::All`, which must
    /// collect stringified JSON numbers that have no backing `&str`).
    fn detect_pii<S: AsRef<str>>(&self, texts: &[S]) -> Vec<String> {
        if self.patterns.is_empty() {
            return Vec::new();
        }
        let mut hit = vec![false; self.patterns.len()];
        for text in texts {
            for idx in self.detection_set.matches(text.as_ref()).into_iter() {
                hit[idx] = true;
            }
        }
        hit.iter()
            .enumerate()
            .filter_map(|(idx, &h)| {
                if h {
                    self.patterns.get(idx).map(|p| p.name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Content-mode detection over both individual prompt fragments and a
    /// boundary-aware view of adjacent text parts in each logical message.
    ///
    /// Individual fragments preserve the established behavior. The additional
    /// pass joins only consecutive text-part objects and records their byte
    /// boundaries; a pattern is added only when one concrete regex occurrence
    /// crosses a recorded boundary. Different messages, independent embedding
    /// strings, and text runs separated by an image/non-text part are never
    /// joined.
    fn detect_pii_content_mode(&self, json: &Value) -> Vec<String> {
        if self.patterns.is_empty() {
            return Vec::new();
        }

        let mut hit = vec![false; self.patterns.len()];
        let texts = self.extract_scan_text(json);
        for text in texts {
            for idx in self.detection_set.matches(text).into_iter() {
                hit[idx] = true;
            }
        }

        self.mark_logical_message_boundary_hits(json, &mut hit, &self.exclude_roles);

        hit.iter()
            .enumerate()
            .filter_map(|(idx, &matched)| {
                if matched {
                    self.patterns.get(idx).map(|pattern| pattern.name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// The shared logical-message boundary traversal, used by BOTH scan modes.
    ///
    /// Providers concatenate the adjacent text parts of one logical message
    /// into a single prompt, so a value split across two parts reaches the model
    /// intact while every per-fragment scan sees only halves. This pass joins
    /// each run of consecutive text parts, records the byte offsets of the
    /// joins, and adds a detection only when a concrete regex occurrence
    /// actually crosses one — independent messages and runs separated by a
    /// non-text part are never joined.
    ///
    /// `exclude_roles` is a parameter rather than `self.exclude_roles` because
    /// the two modes scope role exclusions differently: Content mode honours
    /// them, while `ScanMode::All` deliberately scans every value in the body
    /// regardless of role and therefore passes an empty set, so this pass can
    /// never be narrower than the token pass it supplements.
    fn mark_logical_message_boundary_hits(
        &self,
        json: &Value,
        hit: &mut [bool],
        exclude_roles: &HashSet<String>,
    ) {
        if let Some(messages) = json.get("messages").and_then(Value::as_array) {
            for message in messages {
                if message
                    .get("role")
                    .and_then(Value::as_str)
                    .is_some_and(|role| exclude_roles.contains(role))
                {
                    continue;
                }
                if let Some(content) = message.get("content") {
                    self.mark_cross_part_hits_in_value(content, hit, exclude_roles);
                }
            }
        }

        for field in CONTENT_SCAN_FIELDS {
            if is_system_prompt_scan_field(field) && exclude_roles.contains("system") {
                continue;
            }
            if let Some(value) = json.get(field) {
                self.mark_cross_part_hits_in_value(value, hit, exclude_roles);
            }
        }

        // Gemini concatenates the `parts[]` of one turn into a single prompt
        // exactly as OpenAI concatenates adjacent text content parts, so give
        // them the same boundary-crossing pass — otherwise a value split across
        // two adjacent `parts` entries would evade the scan.
        for_each_gemini_parts(json, exclude_roles, &mut |parts| {
            self.mark_adjacent_text_part_hits(parts, hit);
        });
    }

    /// Find adjacent content-part runs recursively within one prompt field.
    fn mark_cross_part_hits_in_value(
        &self,
        value: &Value,
        hit: &mut [bool],
        exclude_roles: &HashSet<String>,
    ) {
        match value {
            Value::Array(items) => {
                self.mark_adjacent_text_part_hits(items, hit);
                for item in items {
                    let Value::Object(object) = item else {
                        continue;
                    };
                    if object
                        .get("role")
                        .and_then(Value::as_str)
                        .is_some_and(|role| exclude_roles.contains(role))
                    {
                        continue;
                    }
                    // An OpenAI Responses function-result item carries its
                    // model-visible text under `output`, not `content`, and that
                    // payload can be an array of adjacent text parts too.
                    if let Some(output) = function_call_output_payload(object) {
                        self.mark_cross_part_hits_in_value(output, hit, exclude_roles);
                        continue;
                    }
                    if let Some(content) = object.get("content") {
                        self.mark_cross_part_hits_in_value(content, hit, exclude_roles);
                    }
                }
            }
            Value::Object(object) => {
                if object
                    .get("role")
                    .and_then(Value::as_str)
                    .is_some_and(|role| exclude_roles.contains(role))
                {
                    return;
                }
                if let Some(output) = function_call_output_payload(object) {
                    self.mark_cross_part_hits_in_value(output, hit, exclude_roles);
                    return;
                }
                if let Some(content) = object.get("content") {
                    self.mark_cross_part_hits_in_value(content, hit, exclude_roles);
                }
            }
            _ => {}
        }
    }

    /// Scan each run of consecutive text content parts as one logical string,
    /// retaining byte offsets for every part boundary. Matches wholly contained
    /// in one part are already handled by the ordinary fragment scan; only
    /// boundary-crossing occurrences are added here.
    fn mark_adjacent_text_part_hits(&self, items: &[Value], hit: &mut [bool]) {
        let mut joined = String::new();
        let mut boundaries = Vec::new();
        let mut part_count = 0usize;

        for item in items {
            let Some(text) = text_content_part_text(item) else {
                if part_count > 1 {
                    self.mark_joined_boundary_hits(&joined, &boundaries, hit);
                }
                joined.clear();
                boundaries.clear();
                part_count = 0;
                continue;
            };

            if part_count > 0 {
                boundaries.push(joined.len());
                joined.push_str(LOGICAL_TEXT_PART_SEPARATOR);
            }
            joined.push_str(text);
            part_count += 1;
        }

        if part_count > 1 {
            self.mark_joined_boundary_hits(&joined, &boundaries, hit);
        }
    }

    /// Mark patterns with at least one occurrence crossing a retained part
    /// boundary. Regex matches and boundary offsets are both ordered, so the
    /// inner walk is monotonic rather than restarting for each match.
    fn mark_joined_boundary_hits(&self, joined: &str, boundaries: &[usize], hit: &mut [bool]) {
        for pattern_index in self.detection_set.matches(joined).into_iter() {
            let Some(pattern) = self.patterns.get(pattern_index) else {
                continue;
            };
            let mut boundary_index = 0usize;
            for matched in pattern.regex.find_iter(joined) {
                while boundaries
                    .get(boundary_index)
                    .is_some_and(|boundary| *boundary <= matched.start())
                {
                    boundary_index += 1;
                }
                if boundaries
                    .get(boundary_index)
                    .is_some_and(|boundary| *boundary < matched.end())
                {
                    if let Some(slot) = hit.get_mut(pattern_index) {
                        *slot = true;
                    }
                    break;
                }
            }
        }
    }

    /// Fallback PII scan for a `ScanMode::All` body that failed to parse as
    /// JSON. The decoded walker (`collect_json_strings`) needs a parsed
    /// `Value`; a malformed JSON body has none, so without this the request
    /// short-circuited to `Continue` and raw PII in a broken body failed open.
    ///
    /// For `Reject`/`Warn` the documented all-mode contract is "scans the
    /// entire body", so we scan the raw bytes as text — this is the same
    /// coverage the original raw-body scan provided and cannot decode JSON
    /// escapes, which is acceptable for an already-malformed body. For
    /// `Redact` we return no detections: an unparseable body cannot be
    /// re-serialized after redaction, so reporting PII we cannot remove would
    /// be misleading; the request is forwarded unchanged as before.
    fn detect_pii_raw_fallback(&self, body: &str) -> Vec<String> {
        if self.action == ShieldAction::Redact {
            return Vec::new();
        }
        self.detect_pii(std::slice::from_ref(&body))
    }

    /// `ScanMode::All` detection: the union of two passes over the parsed JSON.
    ///
    /// 1. Decoded walker (`collect_json_strings`): scans each JSON token after
    ///    serde has resolved `\uXXXX` and other escapes, so escaped PII in
    ///    string values, object keys, and numeric scalars is caught exactly as
    ///    the backend LLM will see it. This is the coverage issue #1714 added.
    /// 2. Raw-body pass: runs the `RegexSet` over `raw` (the serialized request
    ///    body). The original all-mode scan was raw-only, and some patterns —
    ///    notably operator-supplied `custom_patterns` — depend on JSON context
    ///    that spans tokens (e.g. `"password"\s*:`) or match scalar shapes the
    ///    decoded walker drops (booleans/null, e.g. `"allow_pii"\s*:\s*true`).
    ///    Testing the key and value as separate tokens never reconstructs that
    ///    context, so without this pass those patterns regress to no-match.
    ///
    /// 3. Logical-message boundary pass
    ///    (`mark_logical_message_boundary_hits`): the same traversal Content
    ///    mode uses, so a value split across two adjacent text parts of one
    ///    message is caught here too. Neither of the first two passes can see
    ///    it — the decoded walker visits each part as a separate token, and the
    ///    raw serialization carries JSON punctuation between them — yet the
    ///    provider concatenates the parts into one prompt. All-mode scans every
    ///    value regardless of role, so this pass runs with NO role exclusions;
    ///    it can only ever be broader than the token pass it supplements.
    ///
    /// Unioning the passes only ever *adds* detections, so this strictly hardens
    /// all-mode coverage: escaped-value PII (pass 1), cross-token/contextual
    /// patterns plus dropped scalars (pass 2), and cross-part values (pass 3)
    /// are all caught. Every pass feeds the reject/warn decision; the redact
    /// path additionally re-scans the rewritten body so any detection a token
    /// rewrite cannot remove fails closed rather than forwarding PII while
    /// claiming redaction succeeded.
    fn detect_pii_all_mode(&self, json: &Value, raw: &str) -> Vec<String> {
        if self.patterns.is_empty() {
            return Vec::new();
        }
        let mut hit = vec![false; self.patterns.len()];
        // Pass 1: decoded tokens.
        let mut texts: Vec<Cow<'_, str>> = Vec::new();
        collect_json_strings(json, &mut texts, true);
        for text in &texts {
            for idx in self.detection_set.matches(text.as_ref()).into_iter() {
                hit[idx] = true;
            }
        }
        // Pass 2: raw serialized body (cross-token / contextual patterns).
        // Matches wholly contained in an exempt top-level structural scalar are
        // ignored here too; otherwise the raw pass would re-introduce the exact
        // false positive the decoded walker excludes. Contextual matches that
        // span a key/colon remain enforceable because they are not contained by
        // the scalar's byte range.
        let preserved_spans = collect_preserved_top_level_scalar_spans(raw, json);
        for idx in self.detection_set.matches(raw).into_iter() {
            if preserved_spans.is_empty() {
                hit[idx] = true;
                continue;
            }
            let Some(pattern) = self.patterns.get(idx) else {
                continue;
            };
            let mut span_index = 0usize;
            if pattern.regex.find_iter(raw).any(|matched| {
                !match_is_inside_ordered_span(
                    matched.start()..matched.end(),
                    &preserved_spans,
                    &mut span_index,
                )
            }) {
                hit[idx] = true;
            }
        }
        // Pass 3: logical-message boundaries. All-mode applies no role
        // exclusions, so an empty set is passed rather than `self.exclude_roles`
        // (`HashSet::new()` does not allocate).
        let no_role_exclusions: HashSet<String> = HashSet::new();
        self.mark_logical_message_boundary_hits(json, &mut hit, &no_role_exclusions);
        hit.iter()
            .enumerate()
            .filter_map(|(idx, &h)| {
                if h {
                    self.patterns.get(idx).map(|p| p.name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Whether the ORIGINAL request contains a raw-body match that token
    /// rewriting cannot remove — i.e. an individual match in the serialized body
    /// whose matched byte span is not fully contained inside the serialized span
    /// of a single rewritable value (a string VALUE or numeric scalar). Such a
    /// match (e.g. a contextual `custom_pattern` like `"password"\s*:`, which
    /// spans a key name, the surrounding quotes, and the colon) covers structural
    /// bytes that lie outside any value, so `redact_json_strings` — which only
    /// rewrites string values and numbers — can never remove it. The request is
    /// therefore unredactable and must fail closed.
    ///
    /// Matching is done per individual occurrence (`Regex::find_iter`), NOT per
    /// pattern index. A single custom regex can alternate a removable value
    /// alternative with an unremovable structural-context alternative (for
    /// example `(?:"password"\s+:)|(?:\w+@\w+\.\w+)`); if the value alternative
    /// hits a token, an index-level "this pattern matched a token" flag would
    /// wrongly mark the structural-context occurrence removable too. Testing
    /// each matched occurrence by byte span avoids that suppression so the
    /// contextual occurrence is still caught.
    ///
    /// Removability is decided by BYTE-SPAN containment in the raw body, not by
    /// substring containment in decoded tokens. The substring test was unsound:
    /// a structural match (key + colon) could be wrongly judged removable merely
    /// because an unrelated string VALUE happened to contain the same decoded
    /// text — e.g. with pattern `"password"\s+:` and body
    /// `{"password" : "hunter2", "note": "\"password\" :"}`, the real
    /// `"password" :` field match would be "absorbed" by the `note` value while
    /// the key/colon it actually spans can never be rewritten. Tying each match
    /// to a concrete value span fixes that: a match overlapping any structural
    /// byte (a key, a `:`/`,`, container brackets, or inter-token whitespace)
    /// falls outside every value span and is correctly treated as unredactable.
    ///
    /// This is computed from the ORIGINAL body, independent of the rewritten
    /// body's serialization, precisely so a whitespace-sensitive contextual
    /// match cannot be "cleared" by the minification that `serde_json::to_string`
    /// applies to the rewritten body. Using minified output as proof of removal
    /// is unsound: minification can erase the formatting a raw regex depended on
    /// even though nothing was redacted.
    ///
    /// Object KEY spans are intentionally excluded from the rewritable-value set
    /// (`redact_json_strings` cannot rename keys), so a raw match that overlaps
    /// only a key is treated as non-removable here. PII carried purely in a key
    /// name is still caught — by `redacted_body_has_residual_pii`, whose key text
    /// survives minification unchanged — so it does not need to drive this
    /// contextual verdict as well.
    fn original_has_unredactable_contextual_match(&self, raw: &str) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        // Cheap DFA pre-check: nothing fired on the raw body at all.
        if !self.detection_set.is_match(raw) {
            return false;
        }
        // Byte spans of the rewritable values (string VALUES + numeric scalars;
        // NOT keys, NOT structural punctuation). Computed once over the raw body.
        let value_spans = collect_json_value_spans(raw);
        // A raw match is removable iff its byte span lies entirely within one
        // value span AND the same pattern can actually match the decoded value
        // representation that `redact_json_strings` rewrites. Span containment
        // keeps structural matches from being absorbed by unrelated values, but
        // it is not sufficient by itself: a raw-body regex can match JSON escape
        // syntax such as `\u0061` inside a string value, while the redactor only
        // sees serde's decoded `a`.
        for pattern in &self.patterns {
            let mut removable_by_value_span = vec![None; value_spans.len()];
            let mut span_index = 0usize;
            for m in pattern.regex.find_iter(raw) {
                while value_spans
                    .get(span_index)
                    .is_some_and(|span| span.end < m.start())
                {
                    span_index += 1;
                }
                let Some(span) = value_spans.get(span_index) else {
                    return true;
                };
                if span.start > m.start() || m.end() > span.end {
                    return true;
                }

                let removable = match removable_by_value_span.get(span_index).copied().flatten() {
                    Some(removable) => removable,
                    None => {
                        let removable =
                            raw_value_is_removable_by_value_redactor(raw, pattern, span);
                        let Some(slot) = removable_by_value_span.get_mut(span_index) else {
                            return true;
                        };
                        *slot = Some(removable);
                        removable
                    }
                };

                if !removable {
                    return true;
                }
            }
        }
        false
    }

    /// Parse the body as JSON, apply mode-appropriate redaction, and return a
    /// [`RedactionOutcome`]. Returns `NoChange` when the body isn't valid JSON,
    /// is over `max_scan_bytes`, or contains no PII to redact (so callers don't
    /// waste serialization on a no-op); `Redacted` when PII was detected and
    /// fully removed; `Incomplete` when PII was detected but some could not be
    /// rewritten in place; `BudgetExceeded` when rewriting could not complete
    /// inside this request's aggregate output/work allowance, in which case NO
    /// document is returned at all.
    ///
    /// Shared between `before_proxy` (which uses this to update
    /// `ctx.metadata["request_body"]` so downstream `before_proxy` plugins
    /// see redacted text) and `transform_request_body` (which uses the
    /// returned `Value` to rewrite the wire body on the backend dispatch
    /// path). Keeping the two paths in lockstep guarantees both see the
    /// same redacted bytes regardless of which path actually runs.
    fn apply_redaction_in_place(&self, body: &str) -> RedactionOutcome {
        if body.len() > self.max_scan_bytes {
            return RedactionOutcome::NoChange;
        }
        let Ok(mut json) = serde_json::from_str::<Value>(body) else {
            return RedactionOutcome::NoChange;
        };

        // One aggregate output/work allowance for this whole pass. Every
        // rewritten string is charged against it, so an expanding policy cannot
        // turn a bounded body into an unbounded rewrite (see
        // [`RedactionBudget::for_body`]).
        let budget = RedactionBudget::for_body(body.len());

        if self.scan_mode == ScanMode::All {
            // Gate on the same union detection used for reject/warn so the
            // redact path can't silently miss cross-token/contextual matches.
            let detected = self.detect_pii_all_mode(&json, body);
            if detected.is_empty() {
                return RedactionOutcome::NoChange;
            }
            // Decide UP FRONT, against the unmodified original, whether any hit
            // is a raw-only contextual match that token rewriting cannot remove.
            // Captured before mutation so the verdict can't depend on the
            // minified serialization of the rewritten body (see
            // `original_has_unredactable_contextual_match`).
            let unredactable_contextual = self.original_has_unredactable_contextual_match(body);
            // Run structured redaction first on known prompt-content
            // fields (messages[].content) so recognized chat-completion
            // shapes are handled with the correct template. Then run the
            // recursive walker to cover any PII in sibling fields
            // (metadata, tool arguments, custom top-level strings) that
            // the structured redactor doesn't touch. The recursive walker
            // preserves only TOP-LEVEL structural scalar values (model
            // names, IDs, request parameters) so they remain untouched
            // while PII hidden under nested structural keys is still
            // redacted. Running structured first is safe because its
            // [REDACTED:...] placeholders do not match any PII regex on the
            // subsequent recursive pass.
            let has_known_messages = json
                .get("messages")
                .and_then(|m| m.as_array())
                .is_some_and(|arr| !arr.is_empty());
            if has_known_messages {
                self.redact_body(&mut json, &budget);
            }
            redact_json_strings(&mut json, &self.patterns, true, &budget);

            // Redaction ran out of its output/work allowance (or hit a
            // zero-width match). The document in hand is partially rewritten,
            // so it is discarded rather than forwarded.
            if budget.is_exhausted() {
                return RedactionOutcome::BudgetExceeded;
            }

            // Fail closed when redaction provably could not remove the PII:
            //   1. A raw-only contextual match in the original (no rewritable
            //      token) — decided above against the unmodified body so
            //      minification can't erase the signal.
            //   2. The rewritten body still has residual PII in a decoded token
            //      (e.g. PII carried in an object key, which is never rewritten).
            // Either case means forwarding would leak the value while reporting
            // it redacted. `[REDACTED:...]` placeholders match no PII pattern, so
            // a fully-redacted token re-scans clean.
            if unredactable_contextual || self.redacted_body_has_residual_pii(&json) {
                return RedactionOutcome::Incomplete(json);
            }
            return RedactionOutcome::Redacted(json);
        }

        // Content mode: only redact within messages
        if self.detect_pii_content_mode(&json).is_empty() {
            return RedactionOutcome::NoChange;
        }
        self.redact_body(&mut json, &budget);
        if budget.is_exhausted() {
            return RedactionOutcome::BudgetExceeded;
        }
        // Adjacent text-part matches can span two independently rewritable JSON
        // strings. Redacting either fragment in isolation may be ambiguous or a
        // no-op, so re-run the boundary-aware detector and fail closed if any
        // configured pattern remains.
        if self.detect_pii_content_mode(&json).is_empty() {
            RedactionOutcome::Redacted(json)
        } else {
            RedactionOutcome::Incomplete(json)
        }
    }

    /// After `ScanMode::All` redaction, decide whether any *unredactable* PII
    /// still remains, so the caller can fail closed instead of forwarding it
    /// while reporting the body as redacted.
    ///
    /// This must mirror `redact_json_strings`' structural carve-out: top-level
    /// structural scalar values (`model`, `id`, request parameters, …) are
    /// deliberately preserved even when they incidentally match a PII regex, so
    /// they are NOT residual leaks and must not trigger a fail-closed. To run
    /// the same union detection (decoded tokens + a raw-body pass for
    /// cross-token/contextual custom patterns) without those preserved scalars
    /// re-triggering, we scan a copy of the body whose top-level structural
    /// scalars have been blanked to an empty string. Blanking only the scalar
    /// values keeps the surrounding JSON structure intact, so a contextual
    /// pattern such as `"password"\s*:` still matches while a preserved
    /// `"max_tokens": 123456789` no longer does.
    ///
    /// What this still catches: PII in an object key (`{"a@b.com": …}`), a
    /// string/number the walker failed to rewrite, and contextual custom
    /// patterns that have no single rewritable token — all genuine
    /// "detected but not removed" cases.
    fn redacted_body_has_residual_pii(&self, json: &Value) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        let mut check = json.clone();
        if let Value::Object(map) = &mut check {
            for (key, value) in map.iter_mut() {
                if should_preserve_top_level_scalar(key, value) {
                    *value = Value::String(String::new());
                }
            }
        }
        let serialized = check.to_string();
        !self.detect_pii_all_mode(&check, &serialized).is_empty()
    }

    /// Apply redaction to message content fields in the JSON body, charging
    /// every rewrite against the caller's aggregate output allowance.
    fn redact_body(&self, json: &mut Value, budget: &RedactionBudget) {
        if let Some(messages) = json.get_mut("messages").and_then(|v| v.as_array_mut()) {
            for msg in messages.iter_mut() {
                // Skip excluded roles (O(1) HashSet lookup)
                if let Some(role) = msg.get("role").and_then(|r| r.as_str())
                    && self.exclude_roles.contains(role)
                {
                    continue;
                }

                // String content
                if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                    let redacted = self.redact_text(content, budget);
                    if redacted != content {
                        msg["content"] = Value::String(redacted);
                    }
                }

                // Array content (multimodal, and Bedrock Converse content
                // blocks). Mirrors the `extract_scan_text` walk exactly, via
                // the shared `text_content_part_text` gate, then the same
                // fall-through to the nested tool-result / guarded text a
                // non-text block can still carry.
                if let Some(parts) = msg.get_mut("content").and_then(|c| c.as_array_mut()) {
                    let redact = |text: &str| self.redact_text(text, budget);
                    for part in parts.iter_mut() {
                        if !redact_content_part_text(part, &redact) {
                            redact_content_block_nested_text(part, &redact);
                        }
                    }
                }
            }
        }

        // Redact the same non-`messages` prompt fields scanned by
        // `extract_scan_text` so Content-mode detection and redaction stay
        // symmetric — otherwise PII in `prompt`/`input`/`system` would be
        // reported as redacted but forwarded unredacted (a fail-open bypass).
        for field in CONTENT_SCAN_FIELDS {
            if is_system_prompt_scan_field(field) && self.exclude_roles.contains("system") {
                continue;
            }
            if let Some(value) = json.get_mut(field) {
                redact_field_text(value, &self.exclude_roles, &|text| {
                    self.redact_text(text, budget)
                });
            }
        }
        // Same symmetry contract for the Gemini turns and system instruction
        // scanned by `collect_gemini_prompt_text`.
        redact_gemini_prompt_text(json, &self.exclude_roles, &|text| {
            self.redact_text(text, budget)
        });
        // Keep redaction symmetric with detection: `extract_scan_text` scans
        // Azure "On Your Data" `role_information`, so redact it here too —
        // otherwise Redact mode would report the PII removed while forwarding it
        // unredacted (a fail-open bypass).
        redact_azure_role_information(json, &|text| self.redact_text(text, budget));
        // Same symmetry contract for the Cohere history and Vertex legacy
        // `predict` instances scanned above.
        redact_cohere_chat_history_text(json, &self.exclude_roles, &|text| {
            self.redact_text(text, budget)
        });
        redact_cohere_document_text(json, &|text| self.redact_text(text, budget));
        redact_vertex_instance_prompts(json, &self.exclude_roles, &|text| {
            self.redact_text(text, budget)
        });
    }

    /// Replace all PII pattern matches in the text with the redaction
    /// placeholder, charged against `budget`.
    ///
    /// Placeholders are pre-rendered at construction time so each call does no
    /// template formatting on the hot path, and a pattern with no match in this
    /// string allocates nothing at all. See [`redact_text_bounded`] for the
    /// literal-replacement and budget contracts.
    fn redact_text(&self, text: &str, budget: &RedactionBudget) -> String {
        redact_text_bounded(text, &self.patterns, budget)
    }

    /// Enforce the configured scan ceiling without silently bypassing reject or
    /// redact policy. Warn mode remains observational but records a bounded
    /// metadata event instead of silently skipping the request.
    fn handle_oversize_body(&self, ctx: &mut RequestContext, body_size: usize) -> PluginResult {
        match self.action {
            ShieldAction::Warn => {
                warn_sampled!(
                    body_size,
                    max_scan_bytes = self.max_scan_bytes,
                    "ai_prompt_shield: request body exceeds scan ceiling (warn mode)"
                );
                ctx.metadata.insert(
                    "ai_shield_warnings".to_string(),
                    "body_too_large".to_string(),
                );
                PluginResult::Continue
            }
            ShieldAction::Reject | ShieldAction::Redact => {
                warn_sampled!(
                    body_size,
                    max_scan_bytes = self.max_scan_bytes,
                    "ai_prompt_shield: rejecting request body above scan ceiling"
                );
                ctx.metadata.insert(
                    "ai_shield_rejected".to_string(),
                    "body_too_large".to_string(),
                );
                PluginResult::Reject {
                    status_code: 413,
                    body: serde_json::json!({
                        "error": "Request body exceeds AI prompt shield scan limit",
                        "message": "Request blocked because the prompt body is too large to inspect safely."
                    })
                    .to_string(),
                    headers: HashMap::new(),
                }
            }
        }
    }

    /// Apply the configured action to detections taken over the FINAL
    /// backend-visible body.
    ///
    /// `redact` cannot rewrite wire bytes from the final hook, so PII that is
    /// still present at dispatch time is an unfulfilled redaction obligation and
    /// fails the request closed — whether it survived a compressed deferral or
    /// was reintroduced by a later body transform.
    fn decide_final_request_body(
        &self,
        ctx: &mut RequestContext,
        detected: Vec<String>,
    ) -> PluginResult {
        if detected.is_empty() {
            return PluginResult::Continue;
        }
        match self.action {
            ShieldAction::Reject => {
                debug!(
                    "ai_prompt_shield: PII detected in the final request body (types: {:?}), rejecting request",
                    detected
                );
                ctx.metadata
                    .insert("ai_shield_rejected".to_string(), detected.join(","));
                PluginResult::Reject {
                    status_code: 400,
                    body: serde_json::json!({
                        "error": "PII detected in request",
                        "detected_types": detected,
                        "message": "Request blocked: potential PII detected. Remove sensitive data before sending to AI provider."
                    })
                    .to_string(),
                    headers: HashMap::new(),
                }
            }
            ShieldAction::Warn => {
                warn_sampled!(
                    "ai_prompt_shield: PII detected in the final request body (types: {:?}), passing through (warn mode)",
                    detected
                );
                ctx.metadata
                    .insert("ai_shield_warnings".to_string(), detected.join(","));
                PluginResult::Continue
            }
            ShieldAction::Redact => {
                // This hook can reject but cannot replace the final wire bytes.
                // Forwarding would leak the plaintext body, so redaction policy
                // fails closed on any PII still present in the dispatched
                // representation.
                warn_sampled!(
                    "ai_prompt_shield: PII detected in the final request body (types: {:?}) but that body cannot be rewritten, rejecting request",
                    detected
                );
                ctx.metadata
                    .insert("ai_shield_rejected".to_string(), detected.join(","));
                PluginResult::Reject {
                    status_code: 400,
                    body: serde_json::json!({
                        "error": "PII detected in request",
                        "detected_types": detected,
                        "message": "Request blocked: sensitive data reached the backend-visible body and could not be redacted safely."
                    })
                    .to_string(),
                    headers: HashMap::new(),
                }
            }
        }
    }

    /// Handle a compressed body that remained encoded, or a deferred body that
    /// could not be decoded as UTF-8 JSON. Enforcing actions fail closed; warn
    /// mode records the uninspectable condition and continues by design.
    fn handle_uninspectable_deferred_body(
        &self,
        ctx: &mut RequestContext,
        reason: &'static str,
    ) -> PluginResult {
        match self.action {
            ShieldAction::Warn => {
                warn_sampled!(
                    reason,
                    "ai_prompt_shield: deferred request body could not be inspected (warn mode)"
                );
                ctx.metadata
                    .insert("ai_shield_warnings".to_string(), reason.to_string());
                PluginResult::Continue
            }
            ShieldAction::Reject | ShieldAction::Redact => {
                warn_sampled!(
                    reason,
                    "ai_prompt_shield: rejecting uninspectable deferred request body"
                );
                ctx.metadata
                    .insert("ai_shield_rejected".to_string(), reason.to_string());
                PluginResult::Reject {
                    status_code: 400,
                    body: serde_json::json!({
                        "error": "Request body could not be inspected",
                        "message": "Request blocked because the encoded prompt body could not be inspected safely."
                    })
                    .to_string(),
                    headers: HashMap::new(),
                }
            }
        }
    }
}

#[async_trait]
impl Plugin for AiPromptShield {
    fn name(&self) -> &str {
        "ai_prompt_shield"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_PROMPT_SHIELD
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        // Native gRPC protobuf/framed messages have no supported prompt-schema
        // contract here. Advertise HTTP only so operators cannot attach this
        // shield as an inert fail-closed control on ProxyProtocol::Grpc.
        // gRPC-Web continues through the HTTP/gRPC-Web composed view, where
        // framed bodies are explicitly skipped without decoding.
        super::HTTP_ONLY_PROTOCOLS
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
        self.requires_request_body
            && ctx.method == "POST"
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|ct| is_json_content_type(ct) && !is_framed_grpc_content_type(ct))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only process POST requests
        if ctx.method != "POST" {
            return PluginResult::Continue;
        }

        // Check content-type
        let content_type = headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");
        if !is_json_content_type(content_type) {
            return PluginResult::Continue;
        }

        // Framed native gRPC / gRPC-Web bodies (including `+json` variants) are
        // length-prefixed wire formats, not bare JSON. Skip without buffering
        // or decoding so gRPC-Web framing is preserved; native gRPC requests
        // should already be excluded via HTTP_ONLY_PROTOCOLS.
        if is_framed_grpc_content_type(content_type) {
            return PluginResult::Continue;
        }

        // This instance owns the request from here on. Carry that scope into
        // `on_final_request_body` so a later body transform cannot change
        // policy-relevant content after this hook decided (see the
        // "final backend-visible body is authoritative" note above). The marker
        // is instance-private, so co-located shield instances never consume each
        // other's final check.
        ctx.metadata
            .insert(self.final_inspection_marker.clone(), "true".to_string());

        // Decompression may occur later in request-body transforms. Mark this
        // instance for deferred inspection instead of parsing compressed bytes
        // and silently allowing the request.
        if has_non_identity_content_encoding(headers) {
            ctx.metadata
                .insert(self.deferred_compressed_marker.clone(), "true".to_string());
            return PluginResult::Continue;
        }

        // Get request body
        let body = match ctx.metadata.get("request_body") {
            Some(b) if !b.is_empty() => b.as_str(),
            _ => return PluginResult::Continue,
        };

        // Size limit check
        if body.len() > self.max_scan_bytes {
            let body_size = body.len();
            return self.handle_oversize_body(ctx, body_size);
        }

        // Detect PII and capture streaming intent from the same parsed JSON.
        // Scan-all mode walks decoded JSON string values instead of raw bytes
        // so JSON escapes cannot hide PII or prompt-injection payloads from the
        // detector while the backend sees the decoded text.
        //
        // The streaming flag is captured before mutating `ctx.metadata`
        // because `body` borrows from `ctx.metadata.get("request_body")`.
        let (detected, is_streaming_request) = if self.scan_mode == ScanMode::All {
            match serde_json::from_str::<Value>(body) {
                Ok(json) => {
                    let is_streaming = json.get("stream").and_then(|s| s.as_bool()) == Some(true);
                    (self.detect_pii_all_mode(&json, body), is_streaming)
                }
                // Malformed JSON in all-mode: handled below for non-redact
                // actions by falling back to a raw-body scan so PII in an
                // unparseable body cannot fail open.
                Err(_) => (self.detect_pii_raw_fallback(body), false),
            }
        } else {
            match serde_json::from_str::<Value>(body) {
                Ok(json) => {
                    let is_streaming = json.get("stream").and_then(|s| s.as_bool()) == Some(true);
                    (self.detect_pii_content_mode(&json), is_streaming)
                }
                Err(_) => return PluginResult::Continue,
            }
        };

        // `body` borrow released — safe to mutate ctx.metadata now.
        if is_streaming_request {
            ctx.metadata
                .insert("ai_request_streaming".to_string(), "true".to_string());
        }

        if detected.is_empty() {
            return PluginResult::Continue;
        }

        match self.action {
            ShieldAction::Reject => {
                debug!(
                    "ai_prompt_shield: PII detected (types: {:?}), rejecting request",
                    detected
                );
                ctx.metadata
                    .insert("ai_shield_rejected".to_string(), detected.join(","));
                PluginResult::Reject {
                    status_code: 400,
                    body: serde_json::json!({
                        "error": "PII detected in request",
                        "detected_types": detected,
                        "message": "Request blocked: potential PII detected. Remove sensitive data before sending to AI provider."
                    })
                    .to_string(),
                    headers: HashMap::new(),
                }
            }
            ShieldAction::Warn => {
                warn_sampled!(
                    "ai_prompt_shield: PII detected (types: {:?}), passing through (warn mode)",
                    detected
                );
                ctx.metadata
                    .insert("ai_shield_warnings".to_string(), detected.join(","));
                PluginResult::Continue
            }
            ShieldAction::Redact => {
                // Materialize the redacted body NOW (not just in
                // `transform_request_body`) so we can overwrite
                // `ctx.metadata["request_body"]`. Downstream `before_proxy`
                // plugins read the buffered body from that metadata key
                // and act on its contents — most importantly,
                // `ai_federation` (priority 4060) consumes the body as-is
                // to dispatch a direct provider request and then returns
                // `RejectBinary`. `RejectBinary` short-circuits the
                // backend dispatch path entirely, so
                // `transform_request_body` never runs and the un-redacted
                // bytes would otherwise be forwarded to the AI provider.
                // Updating the metadata here ensures every downstream
                // consumer — whether they reach the backend dispatch path
                // or terminate the request from another `before_proxy`
                // plugin — sees the redacted form.
                //
                // Re-fetch the body as an owned `String` rather than
                // reusing the earlier `&str` borrow on `ctx.metadata`:
                // the borrow checker can't see that the existing borrow
                // ends before the upcoming mutations, and cloning the
                // body once on this path is cheap relative to the JSON
                // parse + regex walk we're about to do.
                //
                // `transform_request_body` still runs on the normal
                // backend dispatch path and re-applies the same redaction
                // to the wire body. The double walk is cheap because
                // `[REDACTED:...]` placeholders don't match any PII
                // pattern, so the second pass is a no-op on already
                // redacted strings.
                let original_body = ctx
                    .metadata
                    .get("request_body")
                    .cloned()
                    .unwrap_or_default();
                match self.apply_redaction_in_place(&original_body) {
                    RedactionOutcome::Redacted(json) => {
                        // Only claim redaction once the rewritten body is
                        // verified free of detectable PII (see
                        // `apply_redaction_in_place`).
                        ctx.metadata
                            .insert("ai_shield_redacted".to_string(), detected.join(","));
                        if let Ok(serialized) = serde_json::to_string(&json) {
                            ctx.metadata.insert("request_body".to_string(), serialized);
                        }
                        PluginResult::Continue
                    }
                    RedactionOutcome::Incomplete(_) => {
                        // PII was detected but could not be fully removed from
                        // the body (e.g. carried in an object key, or matching
                        // only a cross-token custom pattern). Fail closed
                        // rather than forward the value while reporting it
                        // redacted.
                        warn_sampled!(
                            "ai_prompt_shield: PII detected (types: {:?}) could not be fully redacted, rejecting request",
                            detected
                        );
                        ctx.metadata
                            .insert("ai_shield_rejected".to_string(), detected.join(","));
                        PluginResult::Reject {
                            status_code: 400,
                            body: serde_json::json!({
                                "error": "PII detected in request",
                                "detected_types": detected,
                                "message": "Request blocked: sensitive data could not be redacted. Remove sensitive data before sending to AI provider."
                            })
                            .to_string(),
                            headers: HashMap::new(),
                        }
                    }
                    RedactionOutcome::BudgetExceeded => {
                        // The configured policy would expand this body past its
                        // aggregate redaction allowance (or produced a
                        // zero-width match). Nothing partially rewritten is
                        // forwarded; the request is refused as un-redactable at
                        // this size, matching the scan-ceiling disposition.
                        warn_sampled!(
                            body_size = original_body.len(),
                            "ai_prompt_shield: redaction exceeded the request output budget, rejecting request"
                        );
                        ctx.metadata.insert(
                            "ai_shield_rejected".to_string(),
                            "redaction_budget_exceeded".to_string(),
                        );
                        PluginResult::Reject {
                            status_code: 413,
                            body: serde_json::json!({
                                "error": "Request body exceeds AI prompt shield redaction limit",
                                "message": "Request blocked because redacting the prompt body would exceed the safe rewrite budget."
                            })
                            .to_string(),
                            headers: HashMap::new(),
                        }
                    }
                    RedactionOutcome::NoChange => {
                        // `detected` is non-empty (checked above) yet redaction
                        // found nothing to change. This should not happen for a
                        // parseable in-range body, but if it does, do not claim
                        // redaction and do not forward unredacted PII.
                        warn_sampled!(
                            "ai_prompt_shield: PII detected (types: {:?}) but redaction produced no change, rejecting request",
                            detected
                        );
                        ctx.metadata
                            .insert("ai_shield_rejected".to_string(), detected.join(","));
                        PluginResult::Reject {
                            status_code: 400,
                            body: serde_json::json!({
                                "error": "PII detected in request",
                                "detected_types": detected,
                                "message": "Request blocked: sensitive data could not be redacted. Remove sensitive data before sending to AI provider."
                            })
                            .to_string(),
                            headers: HashMap::new(),
                        }
                    }
                }
            }
        }
    }

    fn needs_final_request_body_context(&self) -> bool {
        self.requires_request_body
    }

    /// Claim the finalized backend-visible representation for an enforcing
    /// instance, so the shared request representation gate reduces a content
    /// coding to plaintext before the hook below reads it — or fails the request
    /// closed when it cannot (`GHSA-3973-47g5-4mcx`).
    ///
    /// The claim is decided from configuration and request state only, never by
    /// decoding `body`. `warn` never claims: it cannot refuse anything, so a
    /// body it merely fails to observe must not become a `400`. Requests outside
    /// the documented JSON `POST` scope are not claimed either, so an ordinary
    /// compressed upload on an unrelated route is unaffected.
    fn enforces_final_request_body_policy(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> bool {
        if !self.requires_request_body || self.action == ShieldAction::Warn {
            return false;
        }
        if ctx.method != "POST" {
            return false;
        }
        let Some(content_type) = headers.get("content-type") else {
            return false;
        };
        is_json_content_type(content_type) && !is_framed_grpc_content_type(content_type)
    }

    /// The authoritative policy decision over the exact backend-visible request
    /// body, after every `transform_request_body` hook has run.
    ///
    /// Two request classes reach substantive inspection here:
    ///
    /// * **Revalidation.** `before_proxy` already decided an ordinary plaintext
    ///   body, but later body transforms can put policy-relevant content back
    ///   into it. Re-running detection over the dispatched bytes is what keeps
    ///   the shield's verdict a statement about what the backend receives rather
    ///   than about a pre-transform approximation. `redact` fails closed here:
    ///   this hook can refuse a request but cannot rewrite wire bytes, so PII
    ///   surviving to this point is an unfulfilled redaction obligation.
    /// * **Deferred compressed bodies.** The body was still encoded during
    ///   `before_proxy` and was never inspected, so an unreadable representation
    ///   is itself a fail-closed condition for enforcing actions.
    ///
    /// The two classes differ only in how an UNREADABLE body is treated. A
    /// deferred body that cannot be reduced to plaintext JSON was never
    /// inspected at all and fails closed; a revalidated body reuses exactly the
    /// disposition `before_proxy` applied to the same condition, so this hook
    /// can never invent a rejection class the early hook would have waved
    /// through.
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Both markers are instance-private and are CONSUMED here: a
        // re-finalization that skips the transform pass must not re-decide a
        // body this instance already governed.
        let deferred = ctx
            .metadata
            .remove(&self.deferred_compressed_marker)
            .is_some();
        let in_scope = ctx.metadata.remove(&self.final_inspection_marker).is_some();
        if !deferred && !in_scope {
            return PluginResult::Continue;
        }

        // The markers can only be set by `before_proxy` on a POST. Keep the
        // method check defensive for direct hook callers and future runner
        // changes.
        if ctx.method != "POST" {
            return PluginResult::Continue;
        }

        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");
        if !is_json_content_type(content_type) || is_framed_grpc_content_type(content_type) {
            return PluginResult::Continue;
        }

        // Read through the shared gate: when a content coding is present on a
        // claimed request the gate has already staged the decoded plaintext, and
        // scanning the encoded octets instead would find nothing.
        let decoded_view = ctx.inspectable_final_request_body_owned();
        let body: &[u8] = match decoded_view.as_deref() {
            Some(plaintext) => plaintext,
            None => {
                if has_non_identity_content_encoding(headers) {
                    // Nothing reduced this body to plaintext — no `compression`
                    // instance decoded it and (for `warn`, which never claims)
                    // the gate did not either.
                    return self.handle_uninspectable_deferred_body(ctx, "compressed_body");
                }
                body
            }
        };

        if body.len() > self.max_scan_bytes {
            return self.handle_oversize_body(ctx, body.len());
        }

        let Ok(body_text) = std::str::from_utf8(body) else {
            if deferred {
                return self.handle_uninspectable_deferred_body(ctx, "non_utf8_body");
            }
            // `before_proxy` reads the UTF-8 `request_body` metadata view, which
            // the proxy does not publish for non-UTF-8 bytes, so it continued on
            // exactly this condition. Mirror it rather than inventing a new
            // rejection class on revalidation.
            return PluginResult::Continue;
        };
        let json = match serde_json::from_str::<Value>(body_text) {
            Ok(json) => json,
            Err(_) => {
                if deferred {
                    return self.handle_uninspectable_deferred_body(ctx, "malformed_json");
                }
                // Same mirroring: `ScanMode::All` falls back to a raw-body scan
                // for non-redact actions, and Content mode continues.
                let detected = match self.scan_mode {
                    ScanMode::All => self.detect_pii_raw_fallback(body_text),
                    ScanMode::Content => Vec::new(),
                };
                return self.decide_final_request_body(ctx, detected);
            }
        };

        if json.get("stream").and_then(Value::as_bool) == Some(true) {
            ctx.metadata
                .insert("ai_request_streaming".to_string(), "true".to_string());
        }

        let detected = match self.scan_mode {
            ScanMode::All => self.detect_pii_all_mode(&json, body_text),
            ScanMode::Content => self.detect_pii_content_mode(&json),
        };
        self.decide_final_request_body(ctx, detected)
    }

    /// Rewrite the wire body for a `redact` instance.
    ///
    /// Method scope is decided here, from `ctx.method`, and NOT from
    /// `should_buffer_request_body`: another body plugin can force a request
    /// onto the buffered path, and the shared transform loop then visits every
    /// `modifies_request_body` plugin regardless of which one asked for the
    /// buffer. Without this check, adding an unrelated body rule to a route
    /// would silently extend the shield's rewrites to methods the same
    /// configuration otherwise leaves untouched.
    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if ctx.method != "POST" {
            return None;
        }
        // A later compression plugin may already have stripped the encoding
        // header in `before_proxy` even though its body transform has not run
        // yet. The instance marker is therefore the authoritative signal that
        // these bytes are still the deferred encoded representation.
        if ctx.metadata.contains_key(&self.deferred_compressed_marker) {
            return None;
        }
        self.redact_wire_body(body, content_type, request_headers)
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // No `RequestContext` here. Require the explicit method marker the
        // context-free body-transform callers supply, so this compatibility
        // variant applies exactly the same JSON `POST` scope as the
        // context-aware one above rather than guessing it. Production HTTP
        // paths use the context-aware variant.
        if !request_headers
            .get(":method")
            .is_some_and(|method| method.eq_ignore_ascii_case("POST"))
        {
            return None;
        }
        self.redact_wire_body(body, content_type, request_headers)
    }
}

impl AiPromptShield {
    /// Shared body-rewrite path for both `transform_request_body` variants,
    /// entered only once the caller has proven the documented JSON `POST` scope.
    fn redact_wire_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if self.action != ShieldAction::Redact {
            return None;
        }

        // Only transform JSON
        if let Some(ct) = content_type
            && (!is_json_content_type(ct) || is_framed_grpc_content_type(ct))
        {
            return None;
        }

        if has_non_identity_content_encoding(request_headers) {
            return None;
        }

        if body.len() > self.max_scan_bytes {
            return None;
        }

        let body_str = std::str::from_utf8(body).ok()?;
        match self.apply_redaction_in_place(body_str) {
            // Fully redacted, or best-effort on a body whose residual PII lives
            // somewhere a token rewrite can't reach. `before_proxy` runs first
            // and already rejects the `Incomplete` case, so in normal flow this
            // path only sees fully-redacted bodies; emitting the best-effort
            // body here is a defensive backstop that still strips every PII the
            // walker *can* remove and never forwards the original bytes.
            RedactionOutcome::Redacted(json) | RedactionOutcome::Incomplete(json) => {
                serde_json::to_vec(&json).ok()
            }
            // Redaction could not complete inside its output/work allowance. The
            // partially rewritten document is discarded rather than forwarded;
            // the wire bytes are left alone so `on_final_request_body` sees the
            // same unredacted PII and rejects before dispatch. `before_proxy`
            // already refused this request in the ordinary flow.
            RedactionOutcome::BudgetExceeded => None,
            // No PII to redact (or body not parseable / over the size cap):
            // leave the wire body unchanged.
            RedactionOutcome::NoChange => None,
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
        .ok_or_else(|| format!("ai_prompt_shield: '{field}' must be a string"))
}

fn optional_array<'a>(
    config: &'a Value,
    field: &'static str,
) -> Result<Option<&'a Vec<Value>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_array()
        .map(Some)
        .ok_or_else(|| format!("ai_prompt_shield: '{field}' must be an array"))
}

fn optional_string_vec(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(values) = optional_array(config, field)? else {
        return Ok(None);
    };
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let Some(value) = value.as_str() else {
            return Err(format!(
                "ai_prompt_shield: '{field}' must contain only strings"
            ));
        };
        out.push(value.to_string());
    }
    Ok(Some(out))
}

fn optional_string_array(
    config: &Value,
    field: &'static str,
) -> Result<Option<HashSet<String>>, String> {
    optional_string_vec(config, field)
        .map(|values| values.map(|values| values.into_iter().collect()))
}

/// Render one pattern's redaction placeholder from the configured template and
/// bound the RESULT, not the template: a template may repeat `{type}`, so the
/// rendered replacement — the string every match re-emits — is what has to stay
/// bounded (`MAX_REDACTION_PLACEHOLDER_BYTES`).
fn render_placeholder(template: &str, name: &str) -> Result<String, String> {
    let placeholder = template.replace("{type}", name);
    if placeholder.len() > MAX_REDACTION_PLACEHOLDER_BYTES {
        return Err(format!(
            "ai_prompt_shield: 'redaction_placeholder' rendered for pattern '{name}' must be <= {MAX_REDACTION_PLACEHOLDER_BYTES} UTF-8 bytes"
        ));
    }
    Ok(placeholder)
}

/// Inclusive upper bound of the supported numeric domain for published
/// `integer` config fields: 2^53 − 1.
///
/// The bound is not `u64::MAX` on purpose. JSON Schema treats a mathematically
/// integral number as an integer however it is spelled, and a JSON number that
/// does not fit an unsigned 64-bit slot is carried as an `f64` — where
/// `u64::MAX` and 2^64 round to the SAME value. A `u64::MAX` ceiling would
/// therefore be a bound the published component cannot actually enforce, which
/// is the schema/runtime disagreement this domain exists to remove. Every
/// integer at or below 2^53 − 1 is exact in every JSON number representation,
/// so schema validation and admission reach the same verdict for every input.
/// As a body-scan ceiling it is ~8 PiB — far beyond any request.
const MAX_CONFIG_INTEGER: u64 = 9_007_199_254_740_991;

/// Parse a published `integer` config value that must be greater than zero and
/// within [`MAX_CONFIG_INTEGER`].
///
/// A mathematically integral number is the same published integer however it is
/// spelled, so `1024` and `1024.0` are both accepted. A fractional, negative,
/// non-finite, or out-of-range number is not an integer under that contract and
/// is rejected rather than silently truncated by a lossy cast.
fn optional_positive_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let type_error = format!(
        "ai_prompt_shield: '{field}' must be an integer between 1 and {MAX_CONFIG_INTEGER}"
    );
    let Value::Number(number) = value else {
        return Err(type_error);
    };
    let value = match number.as_u64() {
        Some(value) => value,
        None => {
            // Not held as an unsigned integer: accept only a mathematically
            // integral, in-range decimal spelling. `MAX_CONFIG_INTEGER as f64`
            // is exact, so this comparison — and the cast after it — lose
            // nothing.
            match number.as_f64() {
                Some(float)
                    if float.is_finite()
                        && float.fract() == 0.0
                        && float >= 0.0
                        && float <= MAX_CONFIG_INTEGER as f64 =>
                {
                    float as u64
                }
                _ => return Err(type_error),
            }
        }
    };
    if value == 0 {
        return Err(format!(
            "ai_prompt_shield: '{field}' must be greater than zero"
        ));
    }
    if value > MAX_CONFIG_INTEGER {
        return Err(type_error);
    }
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("ai_prompt_shield: '{field}' is too large for this platform"))
}

/// Collect every decoded JSON token for `ScanMode::All` detection so the
/// decoded walker matches the coverage of the original raw-body scan, except
/// for the same preserved top-level structural scalars the redactor exempts.
///
/// Serde has already resolved `\uXXXX` and other JSON string escapes here, so
/// detection sees the same text the backend LLM will receive after parsing.
///
/// Collected, mirroring the raw-body scan this replaced:
/// - String values (borrowed `&str`).
/// - Object keys (borrowed `&str`) — e.g. `{"a@b.com":"allowed"}`, whose key
///   the raw scan caught but a values-only walk would drop.
/// - Numeric scalars, stringified to owned `String` — e.g. a numeric SSN
///   `{"ssn":123456789}` or credit-card number, which a `&str`-only walk
///   cannot see. Numbers are the load-bearing scalar case for PII.
///
/// Booleans and null are intentionally skipped: their canonical forms
/// (`true`/`false`/`null`) carry no PII, so collecting them would only add
/// noise. The walker yields `Cow<str>` (`Borrowed` for strings/keys,
/// `Owned` for stringified numbers) so number text can be included without
/// allocating for the common string case.
fn collect_json_strings<'a>(value: &'a Value, texts: &mut Vec<Cow<'a, str>>, top_level: bool) {
    match value {
        Value::String(s) => texts.push(Cow::Borrowed(s.as_str())),
        Value::Number(n) => texts.push(Cow::Owned(n.to_string())),
        Value::Array(items) => {
            for item in items {
                collect_json_strings(item, texts, false);
            }
        }
        Value::Object(map) => {
            for (key, value) in map {
                texts.push(Cow::Borrowed(key.as_str()));
                if top_level && should_preserve_top_level_scalar(key, value) {
                    continue;
                }
                collect_json_strings(value, texts, false);
            }
        }
        // Bool / Null carry no PII; deliberately dropped.
        _ => {}
    }
}

/// Test whether an ordered match range lies wholly inside one of a sorted,
/// non-overlapping set of ranges. `span_index` only moves forward, so callers
/// can process ordered regex matches in O(matches + spans).
fn match_is_inside_ordered_span(
    matched: Range<usize>,
    spans: &[Range<usize>],
    span_index: &mut usize,
) -> bool {
    while spans
        .get(*span_index)
        .is_some_and(|span| span.end < matched.start)
    {
        *span_index += 1;
    }
    spans
        .get(*span_index)
        .is_some_and(|span| span.start <= matched.start && matched.end <= span.end)
}

fn skip_json_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
    {
        index += 1;
    }
    index
}

/// Return the byte offset immediately after a JSON string beginning at `start`.
fn json_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut index = start + 1;
    while let Some(byte) = bytes.get(index) {
        match byte {
            b'\\' => index = index.checked_add(2)?,
            b'"' => return index.checked_add(1),
            _ => index += 1,
        }
    }
    None
}

/// Return the byte offset immediately after one valid JSON value. The caller
/// invokes this only after `serde_json` parsed the complete body, so malformed
/// nesting conservatively returns `None` and disables the exclusion.
fn json_value_end(bytes: &[u8], start: usize) -> Option<usize> {
    match bytes.get(start)? {
        b'"' => json_string_end(bytes, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut index = start;
            while let Some(byte) = bytes.get(index) {
                match byte {
                    b'"' => index = json_string_end(bytes, index)?,
                    b'{' | b'[' => {
                        depth = depth.checked_add(1)?;
                        index += 1;
                    }
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        index += 1;
                        if depth == 0 {
                            return Some(index);
                        }
                    }
                    _ => index += 1,
                }
            }
            None
        }
        _ => {
            let mut index = start;
            while bytes.get(index).is_some_and(|byte| {
                !matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | b',' | b'}' | b']')
            }) {
                index += 1;
            }
            (index > start).then_some(index)
        }
    }
}

/// Locate the exact raw byte ranges of preserved scalar values held directly
/// by the root object. Keeping these offsets in the original serialization lets
/// all-mode detection retain whitespace-sensitive contextual custom patterns
/// while ignoring incidental built-in matches wholly inside exempt values.
fn collect_preserved_top_level_scalar_spans(raw: &str, json: &Value) -> Vec<Range<usize>> {
    if !json.is_object() {
        return Vec::new();
    }

    let bytes = raw.as_bytes();
    let mut index = skip_json_whitespace(bytes, 0);
    if bytes.get(index) != Some(&b'{') {
        return Vec::new();
    }
    index += 1;
    let mut spans = Vec::new();

    loop {
        index = skip_json_whitespace(bytes, index);
        if bytes.get(index) == Some(&b'}') {
            break;
        }

        let key_start = index;
        let Some(key_end) = json_string_end(bytes, key_start) else {
            return Vec::new();
        };
        let Some(raw_key) = raw.get(key_start..key_end) else {
            return Vec::new();
        };
        let key: Cow<'_, str> = if raw_key.as_bytes().contains(&b'\\') {
            let Ok(decoded) = serde_json::from_str::<String>(raw_key) else {
                return Vec::new();
            };
            Cow::Owned(decoded)
        } else {
            let Some(unquoted) = raw_key.get(1..raw_key.len().saturating_sub(1)) else {
                return Vec::new();
            };
            Cow::Borrowed(unquoted)
        };

        index = skip_json_whitespace(bytes, key_end);
        if bytes.get(index) != Some(&b':') {
            return Vec::new();
        }
        index = skip_json_whitespace(bytes, index + 1);
        let value_start = index;
        let Some(value_end) = json_value_end(bytes, value_start) else {
            return Vec::new();
        };

        if (STRUCTURAL_KEYS.contains(&key.as_ref())
            || NUMERIC_LLM_PARAMETER_KEYS.contains(&key.as_ref()))
            && let Some(raw_value) = raw.get(value_start..value_end)
            && let Ok(value) = serde_json::from_str::<Value>(raw_value)
            && should_preserve_top_level_scalar(key.as_ref(), &value)
        {
            spans.push(value_start..value_end);
        }

        index = skip_json_whitespace(bytes, value_end);
        match bytes.get(index) {
            Some(b',') => index += 1,
            Some(b'}') => break,
            _ => return Vec::new(),
        }
    }

    spans
}

/// Scan a raw JSON body and return the byte spans of every *rewritable* value —
/// string VALUES (quotes included) and number literals — while excluding object
/// KEY spans and all structural punctuation/whitespace.
///
/// `redact_json_strings` rewrites string values and numeric scalars in place but
/// cannot rewrite a key name (renaming keys risks collisions and reorders the
/// document; key-PII is instead caught by the post-redaction residual re-scan).
/// `original_has_unredactable_contextual_match` uses these spans to decide
/// removability by BYTE-SPAN containment rather than decoded-substring presence:
/// a raw regex match is rewritable only if it lies entirely inside one value
/// span. A match that overlaps a key, a `:`/`,` separator, container brackets,
/// or inter-token whitespace lands outside every span and is treated as
/// unredactable — which a decoded-substring test could not distinguish, since an
/// unrelated value may contain the same text as a structural match.
///
/// This is a forward single-pass scanner over the raw bytes (the body already
/// parsed as valid JSON upstream, so it is well-formed). Strings honor `\\`
/// escapes so an escaped quote does not end the span prematurely. In an object,
/// the string immediately after `{` or `,` is a KEY (its span is skipped); the
/// value after `:` — and every array element and the root token — is a VALUE.
fn collect_json_value_spans(raw: &str) -> Vec<std::ops::Range<usize>> {
    /// What the next encountered value token represents in the current context.
    #[derive(Clone, Copy, PartialEq)]
    enum Expect {
        /// Object key position (after `{` or `,` inside an object).
        Key,
        /// Value position (after `:`, an array element, or the root token).
        Value,
    }
    let bytes = raw.as_bytes();
    let mut spans: Vec<std::ops::Range<usize>> = Vec::new();
    // Stack of `true` for object contexts, `false` for array contexts. Drives
    // whether `,` returns us to a Key (object) or a Value (array) expectation.
    let mut in_object: Vec<bool> = Vec::new();
    // Root token is a value; inside an object the first token is a key.
    let mut expect = Expect::Value;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                in_object.push(true);
                expect = Expect::Key;
                i += 1;
            }
            b'[' => {
                in_object.push(false);
                expect = Expect::Value;
                i += 1;
            }
            b'}' | b']' => {
                in_object.pop();
                i += 1;
            }
            b':' => {
                // Object key/value separator: the next token is a VALUE.
                expect = Expect::Value;
                i += 1;
            }
            b',' => {
                // Next token: a key in an object, a value in an array.
                expect = match in_object.last() {
                    Some(true) => Expect::Key,
                    _ => Expect::Value,
                };
                i += 1;
            }
            b'"' => {
                // Scan to the closing quote, skipping `\\`-escaped bytes.
                let start = i;
                let mut j = i + 1;
                while j < bytes.len() {
                    match bytes[j] {
                        b'\\' => j += 2, // escape consumes the next byte
                        b'"' => {
                            j += 1;
                            break;
                        }
                        _ => j += 1,
                    }
                }
                // Only VALUE strings are rewritable; KEY strings are not.
                if expect == Expect::Value {
                    spans.push(start..j.min(bytes.len()));
                }
                i = j;
            }
            // Number literal (rewritable only in value position). serde accepts
            // a leading `-`; scan the contiguous numeric run.
            b'-' | b'0'..=b'9' if expect == Expect::Value => {
                let start = i;
                let mut j = i + 1;
                while j < bytes.len()
                    && matches!(bytes[j], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    j += 1;
                }
                spans.push(start..j);
                i = j;
            }
            // Whitespace and literal scalars (true/false/null) carry no
            // rewritable PII span; advance past them.
            _ => i += 1,
        }
    }
    spans
}

fn should_preserve_top_level_scalar(key: &str, value: &Value) -> bool {
    if STRUCTURAL_KEYS.contains(&key) {
        return value.is_string() || value.is_number();
    }
    NUMERIC_LLM_PARAMETER_KEYS.contains(&key) && value.is_number()
}

fn raw_value_is_removable_by_value_redactor(
    raw: &str,
    pattern: &PiiPattern,
    span: &std::ops::Range<usize>,
) -> bool {
    let Some(raw_value) = raw.get(span.clone()) else {
        return false;
    };

    match serde_json::from_str::<Value>(raw_value) {
        Ok(Value::String(decoded)) => pattern.regex.is_match(&decoded),
        Ok(Value::Number(number)) => pattern.regex.is_match(&number.to_string()),
        _ => false,
    }
}

/// Collect scannable prompt text from a top-level LLM field that may be a
/// string, an array of strings, or an array of `{type:"text", text:"..."}`
/// content parts (e.g. `prompt`, `input`, `system`). Pushes borrowed `&str`
/// slices onto `texts`. Non-text array entries are ignored.
/// Text content-part `type` values across the major LLM APIs. The OpenAI Chat
/// API and Anthropic Messages API use `text`; the OpenAI Responses API uses
/// `input_text` (request) and `output_text` (response).
fn is_text_content_part_type(part_type: &str) -> bool {
    matches!(part_type, "text" | "input_text" | "output_text")
}

/// The model-visible prompt text of one content part / content block, or `None`
/// when the part carries none.
///
/// A part that *declares* a string `type` must declare a text one
/// ([`is_text_content_part_type`]), which keeps `tool_use`, `image`,
/// `image_url`, `reasoning`, and `tool_result` blocks out of THIS gate exactly
/// as before. (A `tool_result` block carries no `text` of its own; its nested
/// `content` is picked up separately by
/// [`collect_content_block_nested_text`].) A part with **no** `type`
/// discriminator is accepted when it
/// carries a string `text`: Amazon Bedrock Converse sends
/// `messages[].content[]` as bare `{"text": "..."}` blocks and Google Gemini
/// sends `parts[]` as bare `{"text": "..."}` entries, so gating on a
/// discriminator those providers never emit left their entire prompt
/// unscanned. `text` must be a string — a non-string `text` is not prompt text
/// and is never scanned or rewritten.
///
/// A part whose `type` is present but not a string is treated as undeclared and
/// scanned: the fail-closed direction, so a malformed discriminator cannot be
/// used to hide prompt text from the shield.
///
/// Bounded to the part itself: nothing here recurses into nested arrays, so a
/// deeply nested body cannot drive unbounded work.
fn text_content_part_text(part: &Value) -> Option<&str> {
    match part.get("type") {
        // A declared, recognized non-text block type: skip, as before.
        Some(Value::String(part_type)) if !is_text_content_part_type(part_type) => None,
        _ => part.get("text").and_then(Value::as_str),
    }
}

/// Rewrite one content part's `text` through `redact`, returning whether the
/// value was a text-bearing content part at all.
///
/// The `true`/`false` verdict is exactly [`text_content_part_text`]'s
/// `Some`/`None`, so the redactor can never treat a part as non-text that the
/// detector scanned as text (which would be a fail-open bypass: PII reported
/// as redacted but forwarded). A part whose text needs no rewrite still
/// reports `true` — it was scanned, it just had nothing to change.
fn redact_content_part_text(part: &mut Value, redact: &impl Fn(&str) -> String) -> bool {
    let replacement = match text_content_part_text(part) {
        None => return false,
        Some(text) => {
            let redacted = redact(text);
            (redacted != text).then_some(redacted)
        }
    };
    if let Some(redacted) = replacement
        && let Some(object) = part.as_object_mut()
    {
        object.insert("text".to_string(), Value::String(redacted));
    }
    true
}

/// Model-visible text a content block carries somewhere other than its own
/// `text` — the shapes [`text_content_part_text`] deliberately answers `None`
/// for because the block is not itself a text part:
///
/// * Amazon Bedrock Converse `{"toolResult": {"content": [{"text": "..."}]}}`
/// * Anthropic `{"type": "tool_result", "content": <string | [parts]>}`
/// * Amazon Bedrock Converse `{"guardContent": {"text": {"text": "..."}}}`,
///   and the flat `{"guardContent": {"text": "..."}}` spelling — either
///   reaches the model, so reading only one leaves the other unscanned.
/// * Amazon Bedrock Converse `{"toolUse": {"toolUseId", "name", "input"}}` —
///   the untyped union spelling of a tool call, whose `input` arguments are
///   replayed to the model on the next turn and are often the largest text in
///   it. Only `input` is scanned: the sibling `toolUseId`/`name` fields are
///   call plumbing, not prose. The Anthropic `type: "tool_use"` spelling is
///   deliberately NOT read here — a declared non-text block type stays outside
///   Content-mode scanning, as `text_content_part_text` and its tests record.
///
/// Tool-result content is text the model reads verbatim from a third party,
/// which is exactly where a smuggled payload hides; the sibling
/// `ai_semantic_firewall` reads the same two spellings, so leaving them out
/// here made the shield the weaker of the pair on identical bodies. The block
/// inherits its enclosing message's `role`, so `exclude_roles` filters it
/// exactly like that message's own text — this is called only for a message
/// the role filter already admitted.
///
/// Bounded to one level below the block: an array element contributes its own
/// string or `text`, and nothing recurses, so a chained tool result cannot
/// drive unbounded work. Tool arguments are the one shape read deeper, because
/// an arguments object is arbitrary operator/model-shaped JSON with no fixed
/// member; that traversal is bounded by [`collect_tool_argument_text`]. The
/// mutating counterpart is [`redact_content_block_nested_text`].
fn collect_content_block_nested_text<'a>(block: &'a Value, texts: &mut Vec<&'a str>) {
    if let Some(tool_result) = block.get("toolResult") {
        collect_tool_result_content_text(tool_result.get("content"), texts);
    } else if block.get("type").and_then(Value::as_str) == Some("tool_result") {
        collect_tool_result_content_text(block.get("content"), texts);
    } else if let Some(text) = block.get("guardContent").and_then(guard_content_text) {
        texts.push(text);
    } else if let Some(input) = block
        .get("toolUse")
        .and_then(|tool_use| tool_use.get("input"))
    {
        collect_tool_argument_text(input, texts, 0);
    }
}

/// How deep [`collect_tool_argument_text`] descends into a tool-arguments
/// value. Arguments follow the tool's own JSON Schema, so unlike every other
/// block shape here they have no fixed member to read; a fixed ceiling keeps
/// the request-path cost bounded without letting a shallow nest hide prose.
/// Provider argument schemas are flat to a handful of levels, so 8 is well
/// clear of real traffic while a hostile body cannot drive unbounded work.
const MAX_TOOL_ARGUMENT_DEPTH: usize = 8;

/// Every string leaf of a tool-arguments value, down to
/// [`MAX_TOOL_ARGUMENT_DEPTH`].
///
/// Member *names* are not scanned: they are the tool's schema, not
/// operator-supplied prose, and the redactor cannot rewrite a key without
/// changing the arguments the provider receives. The mutating counterpart is
/// [`redact_tool_argument_text`], which walks the identical shape at the
/// identical depth so detection and redaction cannot drift.
fn collect_tool_argument_text<'a>(value: &'a Value, texts: &mut Vec<&'a str>, depth: usize) {
    match value {
        Value::String(text) => texts.push(text.as_str()),
        Value::Array(items) if depth < MAX_TOOL_ARGUMENT_DEPTH => {
            for item in items {
                collect_tool_argument_text(item, texts, depth + 1);
            }
        }
        Value::Object(object) if depth < MAX_TOOL_ARGUMENT_DEPTH => {
            for member in object.values() {
                collect_tool_argument_text(member, texts, depth + 1);
            }
        }
        _ => {}
    }
}

/// Mutable mirror of [`collect_tool_argument_text`], rewriting exactly the same
/// string leaves at the same depth.
fn redact_tool_argument_text(value: &mut Value, redact: &impl Fn(&str) -> String, depth: usize) {
    match value {
        Value::String(text) => redact_string_in_place(text, redact),
        Value::Array(items) if depth < MAX_TOOL_ARGUMENT_DEPTH => {
            for item in items.iter_mut() {
                redact_tool_argument_text(item, redact, depth + 1);
            }
        }
        Value::Object(object) if depth < MAX_TOOL_ARGUMENT_DEPTH => {
            for member in object.values_mut() {
                redact_tool_argument_text(member, redact, depth + 1);
            }
        }
        _ => {}
    }
}

/// Redact every string [`collect_content_block_nested_text`] scans, so
/// Content-mode detection and redaction cannot drift on tool-result, guarded,
/// or tool-argument text (an asymmetry there is a fail-open bypass: the PII
/// reported removed while the provider receives the original block).
fn redact_content_block_nested_text(block: &mut Value, redact: &impl Fn(&str) -> String) {
    if let Some(tool_result) = block.get_mut("toolResult") {
        redact_tool_result_content_text(tool_result.get_mut("content"), redact);
        return;
    }
    if block.get("type").and_then(Value::as_str) == Some("tool_result") {
        redact_tool_result_content_text(block.get_mut("content"), redact);
        return;
    }
    if let Some(guard_content) = block.get_mut("guardContent") {
        redact_guard_content_text(guard_content, redact);
        return;
    }
    if let Some(input) = block
        .get_mut("toolUse")
        .and_then(|tool_use| tool_use.get_mut("input"))
    {
        redact_tool_argument_text(input, redact, 0);
    }
}

/// The text payload of a tool-result block: a bare string, or an array whose
/// elements each contribute their own string or `text`. One level, never
/// recursive — matching the bound `ai_semantic_firewall`'s
/// `extract_tool_result_content` keeps.
fn collect_tool_result_content_text<'a>(content: Option<&'a Value>, texts: &mut Vec<&'a str>) {
    match content {
        Some(Value::String(text)) => texts.push(text.as_str()),
        Some(Value::Array(items)) => {
            for item in items {
                match item {
                    Value::String(text) => texts.push(text.as_str()),
                    Value::Object(object) => {
                        if let Some(text) = object.get("text").and_then(Value::as_str) {
                            texts.push(text);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// Mutable mirror of [`collect_tool_result_content_text`], visiting exactly the
/// same strings in the same order.
fn redact_tool_result_content_text(content: Option<&mut Value>, redact: &impl Fn(&str) -> String) {
    match content {
        Some(Value::String(text)) => redact_string_in_place(text, redact),
        Some(Value::Array(items)) => {
            for item in items.iter_mut() {
                match item {
                    Value::String(text) => redact_string_in_place(text, redact),
                    Value::Object(object) => redact_object_string_field(object, "text", redact),
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// The guarded text of a Bedrock Converse `guardContent` block, under both the
/// nested (`{"text": {"text": "..."}}`) and flat (`{"text": "..."}`)
/// spellings. Mirrors the sibling `ai_semantic_firewall`'s
/// `extract_guard_content_text`.
fn guard_content_text(guard_content: &Value) -> Option<&str> {
    match guard_content.get("text") {
        Some(Value::String(text)) => Some(text.as_str()),
        Some(Value::Object(object)) => object.get("text").and_then(Value::as_str),
        _ => None,
    }
}

/// Mutable mirror of [`guard_content_text`], rewriting whichever of the two
/// spellings the block used.
fn redact_guard_content_text(guard_content: &mut Value, redact: &impl Fn(&str) -> String) {
    match guard_content.get_mut("text") {
        Some(Value::String(text)) => redact_string_in_place(text, redact),
        Some(Value::Object(object)) => redact_object_string_field(object, "text", redact),
        _ => {}
    }
}

/// Rewrite a `String` held in place, leaving it untouched when redaction is a
/// no-op so an unchanged body is never needlessly reallocated.
fn redact_string_in_place(text: &mut String, redact: &impl Fn(&str) -> String) {
    let redacted = redact(text.as_str());
    if redacted != *text {
        *text = redacted;
    }
}

/// Rewrite one string-valued field of a JSON object. A missing or non-string
/// value is left alone, matching the read side, which never scans one.
fn redact_object_string_field(
    object: &mut serde_json::Map<String, Value>,
    key: &str,
    redact: &impl Fn(&str) -> String,
) {
    let Some(text) = object.get(key).and_then(Value::as_str) else {
        return;
    };
    let redacted = redact(text);
    if redacted != text {
        object.insert(key.to_string(), Value::String(redacted));
    }
}

/// The model-visible payload of an OpenAI Responses function-result input item,
/// or `None` for anything else.
///
/// The Responses API supplies a tool's result as a top-level `input` item of
/// type `function_call_output` whose text lives under `output`, not `content`:
/// no other branch of the walkers reaches it, so the model read that text
/// verbatim while the shield never saw it. `output` is a JSON-encoded string in
/// the documented shape and an array of content items in the structured
/// spelling; both are handled by the shared tool-result traversal, which is
/// bounded to one level. The item carries no `role`, so `exclude_roles` does not
/// suppress it — third-party tool output is exactly where a smuggled value
/// hides, and there is no operator-authored role to exempt.
///
/// Any other `output` shape (an object, a number) contributes no text and is
/// left untouched by both the detector and the redactor, keeping them
/// symmetric.
fn function_call_output_payload(object: &serde_json::Map<String, Value>) -> Option<&Value> {
    if !is_function_call_output_item(object) {
        return None;
    }
    object.get("output")
}

/// Whether this object is an OpenAI Responses function-result input item. The
/// mutating walkers test the discriminator and then take `output` separately,
/// so the redactor never holds a borrow across the branch its read decided.
fn is_function_call_output_item(object: &serde_json::Map<String, Value>) -> bool {
    object.get("type").and_then(Value::as_str) == Some("function_call_output")
}

/// Collect scannable text from a top-level LLM content field
/// (`prompt`/`input`/`instructions`/`system`/`inputText`). Handles a plain
/// string, an array of strings, an array of content parts (see
/// [`text_content_part_text`]), the structured OpenAI Responses `input`
/// shape — an array of message objects `{role, content: <string | array of
/// parts>}` — by recursing into each message's `content`, and the Responses
/// function-result item (see [`function_call_output_payload`]).
fn collect_field_text<'a>(
    value: &'a Value,
    exclude_roles: &HashSet<String>,
    texts: &mut Vec<&'a str>,
) {
    match value {
        Value::String(s) => texts.push(s.as_str()),
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::String(s) => texts.push(s.as_str()),
                    Value::Object(obj) => {
                        if let Some(text) = text_content_part_text(item) {
                            texts.push(text);
                        } else if let Some(output) = function_call_output_payload(obj) {
                            // Responses function-result item: model-visible text
                            // lives under `output`.
                            collect_tool_result_content_text(Some(output), texts);
                        } else if let Some(content) = obj.get("content") {
                            if obj
                                .get("role")
                                .and_then(|r| r.as_str())
                                .is_some_and(|role| exclude_roles.contains(role))
                            {
                                continue;
                            }
                            // Message object `{role, content}` (structured
                            // Responses `input`): scan its content.
                            collect_field_text(content, exclude_roles, texts);
                        }
                    }
                    _ => {}
                }
            }
        }
        // A field that is itself a single message object `{role, content}`, or
        // a single Responses function-result item.
        Value::Object(obj) => {
            if let Some(output) = function_call_output_payload(obj) {
                collect_tool_result_content_text(Some(output), texts);
                return;
            }
            if let Some(content) = obj.get("content") {
                if obj
                    .get("role")
                    .and_then(|r| r.as_str())
                    .is_some_and(|role| exclude_roles.contains(role))
                {
                    return;
                }
                collect_field_text(content, exclude_roles, texts);
            }
        }
        _ => {}
    }
}

/// Redact PII in a top-level LLM field that may be a string, an array of
/// strings, or an array of content parts (e.g. `prompt`, `input`,
/// `instructions`, `system`, `inputText`). Mirrors `collect_field_text` so
/// detection and redaction stay symmetric — anything scanned for PII is also
/// rewritten. Both sides gate content parts through
/// [`text_content_part_text`], so neither can drift from the other.
fn redact_field_text(
    value: &mut Value,
    exclude_roles: &HashSet<String>,
    redact: &impl Fn(&str) -> String,
) {
    match value {
        Value::String(s) => {
            let redacted = redact(s);
            if redacted != *s {
                *s = redacted;
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                if let Value::String(s) = item {
                    let redacted = redact(s);
                    if redacted != *s {
                        *s = redacted;
                    }
                    continue;
                }
                if !item.is_object() {
                    continue;
                }
                // A text-bearing content part (explicit `type`, or a Bedrock
                // Converse block that carries none) contributes its own `text`
                // and is never recursed into, matching `collect_field_text`.
                if redact_content_part_text(item, redact) {
                    continue;
                }
                let Some(obj) = item.as_object_mut() else {
                    continue;
                };
                // Mirrors `collect_field_text`: the Responses function-result
                // item is matched before the role filter, exactly as the
                // detector does, so the two cannot drift.
                if is_function_call_output_item(obj) {
                    redact_tool_result_content_text(obj.get_mut("output"), redact);
                    continue;
                }
                if obj
                    .get("role")
                    .and_then(|r| r.as_str())
                    .is_some_and(|role| exclude_roles.contains(role))
                {
                    continue;
                }
                if let Some(content) = obj.get_mut("content") {
                    redact_field_text(content, exclude_roles, redact);
                }
            }
        }
        Value::Object(obj) => {
            if is_function_call_output_item(obj) {
                redact_tool_result_content_text(obj.get_mut("output"), redact);
                return;
            }
            let excluded = obj
                .get("role")
                .and_then(|r| r.as_str())
                .is_some_and(|role| exclude_roles.contains(role));
            if !excluded && let Some(content) = obj.get_mut("content") {
                redact_field_text(content, exclude_roles, redact);
            }
        }
        _ => {}
    }
}

/// Visit every Google Gemini / Vertex `parts` array that carries model-visible
/// prompt text: each in-scope `contents[]` turn, plus the system instruction
/// under BOTH the JSON (`systemInstruction`) and proto (`system_instruction`)
/// casings — either reaches the model, so inspecting only one leaves the other
/// uninspected. Mirrors the dual-casing extraction the sibling
/// `ai_semantic_firewall` and `ai_request_guard` plugins already perform.
///
/// `exclude_roles` filters `contents[].role` the same way it filters
/// `messages[].role`, and suppresses the system instruction when `system` is
/// excluded — matching the `system` carve-out in [`CONTENT_SCAN_FIELDS`].
///
/// Read-only traversal shared by the fragment scan and the boundary-aware
/// cross-part scan; the mutating counterpart is [`redact_gemini_prompt_text`].
fn for_each_gemini_parts<'a>(
    json: &'a Value,
    exclude_roles: &HashSet<String>,
    visit: &mut impl FnMut(&'a [Value]),
) {
    if let Some(contents) = json.get("contents").and_then(Value::as_array) {
        for content in contents {
            if content
                .get("role")
                .and_then(Value::as_str)
                .is_some_and(|role| exclude_roles.contains(role))
            {
                continue;
            }
            if let Some(parts) = content.get("parts").and_then(Value::as_array) {
                visit(parts.as_slice());
            }
        }
    }
    if exclude_roles.contains("system") {
        return;
    }
    for key in ["systemInstruction", "system_instruction"] {
        if let Some(parts) = json
            .get(key)
            .and_then(|instruction| instruction.get("parts"))
            .and_then(Value::as_array)
        {
            visit(parts.as_slice());
        }
    }
}

/// Collect Gemini / Vertex prompt text for Content-mode scanning:
/// `contents[].parts[].text` (the provider's equivalent of
/// `messages[].content`) and `systemInstruction.parts[].text`. Gemini bodies
/// carry no `messages` array and none of the [`CONTENT_SCAN_FIELDS`], so
/// without this the whole prompt passed Content mode unscanned
/// (`ScanMode::All` already covered it via full-body recursion).
///
/// Bounded to one level per part, matching the sibling plugins' extraction: a
/// part contributes only its own `text` string and is never recursed into.
fn collect_gemini_prompt_text<'a>(
    json: &'a Value,
    exclude_roles: &HashSet<String>,
    texts: &mut Vec<&'a str>,
) {
    for_each_gemini_parts(json, exclude_roles, &mut |parts| {
        for part in parts {
            if let Some(text) = text_content_part_text(part) {
                texts.push(text);
            }
        }
    });
}

/// Redact PII in every Gemini / Vertex prompt part scanned by
/// [`collect_gemini_prompt_text`], keeping Content-mode detection and
/// redaction symmetric. Without this, Redact mode would report the PII removed
/// while forwarding the original `parts[].text` unchanged (a fail-open
/// bypass). The traversal — both casings, the same `exclude_roles` filtering,
/// one level per part — is the mutable mirror of [`for_each_gemini_parts`].
fn redact_gemini_prompt_text(
    json: &mut Value,
    exclude_roles: &HashSet<String>,
    redact: &impl Fn(&str) -> String,
) {
    if let Some(contents) = json.get_mut("contents").and_then(Value::as_array_mut) {
        for content in contents.iter_mut() {
            if content
                .get("role")
                .and_then(Value::as_str)
                .is_some_and(|role| exclude_roles.contains(role))
            {
                continue;
            }
            redact_parts_text(content.get_mut("parts"), redact);
        }
    }
    if exclude_roles.contains("system") {
        return;
    }
    for key in ["systemInstruction", "system_instruction"] {
        if let Some(instruction) = json.get_mut(key) {
            redact_parts_text(instruction.get_mut("parts"), redact);
        }
    }
}

/// Redact the `text` of each element of a Gemini-style `parts` array, gated by
/// the same [`text_content_part_text`] contract the scan uses.
fn redact_parts_text(parts: Option<&mut Value>, redact: &impl Fn(&str) -> String) {
    let Some(parts) = parts.and_then(Value::as_array_mut) else {
        return;
    };
    for part in parts.iter_mut() {
        redact_content_part_text(part, redact);
    }
}

/// All Azure OpenAI "On Your Data" data-source items, across BOTH the GA
/// snake_case `data_sources` and the original extensions-API camelCase
/// `dataSources` arrays. Both keys are iterated rather than short-circuited on
/// the first present one: `Option::or_else` only falls through on `None`, so a
/// body that pairs an empty/`null` `data_sources` with a populated `dataSources`
/// (or vice versa) would otherwise slip the second array past the scan. Mirrors
/// the dual-casing extraction in the sibling `ai_request_guard` plugin.
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
/// camelCase value from the scan.
fn azure_role_information_values(source: &Value) -> impl Iterator<Item = &str> {
    let parameters = source.get("parameters");
    ["role_information", "roleInformation"]
        .into_iter()
        .filter_map(move |key| parameters.and_then(|p| p.get(key)).and_then(Value::as_str))
}

/// Collect Azure OpenAI "On Your Data" per-data-source instruction text for
/// Content-mode scanning. The backend applies
/// `data_sources[].parameters.role_information` (and the camelCase
/// `dataSources[].parameters.roleInformation`) as a de-facto system prompt even
/// when the top-level `messages` carry only ordinary `user` turns, so PII or a
/// jailbreak smuggled there would otherwise pass Content mode unseen
/// (`ScanMode::All` already covers it via full-body recursion).
///
/// Not gated by `exclude_roles`: that set filters chat *message roles* (the
/// `role` field on a message/part), but `role_information` is a nested config
/// field with no `role` to match against — and it is exactly where a payload
/// would be hidden — so it is always scanned.
fn collect_azure_role_information_text<'a>(json: &'a Value, texts: &mut Vec<&'a str>) {
    for source in azure_data_source_items(json) {
        for role_information in azure_role_information_values(source) {
            texts.push(role_information);
        }
    }
}

/// Redact PII in every Azure "On Your Data" `role_information` instruction
/// (both `data_sources`/`dataSources` outer casings and
/// `role_information`/`roleInformation` inner casings), mirroring
/// `collect_azure_role_information_text` so Content-mode detection and redaction
/// stay symmetric. Without this, `Redact` mode would report the PII removed
/// while forwarding the original `role_information` unchanged (a fail-open
/// bypass). Both casings are iterated (no short-circuit) for the same reason the
/// scan helpers iterate both.
fn redact_azure_role_information(json: &mut Value, redact: &impl Fn(&str) -> String) {
    for outer_key in ["data_sources", "dataSources"] {
        let Some(sources) = json.get_mut(outer_key).and_then(Value::as_array_mut) else {
            continue;
        };
        for source in sources.iter_mut() {
            let Some(parameters) = source.get_mut("parameters").and_then(Value::as_object_mut)
            else {
                continue;
            };
            for inner_key in ["role_information", "roleInformation"] {
                if let Some(text) = parameters.get(inner_key).and_then(Value::as_str) {
                    let redacted = redact(text);
                    if redacted != text {
                        parameters.insert(inner_key.to_string(), Value::String(redacted));
                    }
                }
            }
        }
    }
}

/// Whether a Cohere `chat_history[].role` is excluded by `exclude_roles`.
///
/// Cohere spells its roles in upper case (`USER`, `CHATBOT`, `SYSTEM`,
/// `TOOL`) while `exclude_roles` is configured in the OpenAI lower-case
/// spelling, so an exact `HashSet` hit alone would silently ignore the
/// operator's filter on every Cohere body. The fallback compares
/// case-insensitively without allocating per turn; `exclude_roles` is an
/// operator-sized set (usually empty or one entry), so the linear scan is not
/// a hot-path cost.
fn cohere_role_excluded(role: Option<&str>, exclude_roles: &HashSet<String>) -> bool {
    let Some(role) = role else {
        return false;
    };
    if exclude_roles.contains(role) {
        return true;
    }
    let matches_role = |excluded: &str| excluded.eq_ignore_ascii_case(role);
    exclude_roles.iter().map(String::as_str).any(matches_role)
}

/// Collect Cohere v1 `/chat` history text for Content-mode scanning:
/// `chat_history[].message`, the prior turns of the conversation. The current
/// turn (`message`) and the system prompt (`preamble`) are ordinary
/// [`CONTENT_SCAN_FIELDS`] entries; the history is an array of
/// `{role, message}` objects that no top-level field reaches, so without this
/// every turn but the last passed Content mode unscanned.
///
/// Each turn's `role` is filtered through [`cohere_role_excluded`] exactly as
/// `messages[].role` is filtered, and the message value accepts the same
/// string / array-of-strings / content-part shapes as any other prompt field.
fn collect_cohere_chat_history_text<'a>(
    json: &'a Value,
    exclude_roles: &HashSet<String>,
    texts: &mut Vec<&'a str>,
) {
    let Some(history) = json.get("chat_history").and_then(Value::as_array) else {
        return;
    };
    for turn in history {
        if cohere_role_excluded(turn.get("role").and_then(Value::as_str), exclude_roles) {
            continue;
        }
        if let Some(message) = turn.get("message") {
            collect_field_text(message, exclude_roles, texts);
        }
    }
}

/// Redact every Cohere history turn scanned by
/// [`collect_cohere_chat_history_text`], keeping Content-mode detection and
/// redaction symmetric.
fn redact_cohere_chat_history_text(
    json: &mut Value,
    exclude_roles: &HashSet<String>,
    redact: &impl Fn(&str) -> String,
) {
    let Some(history) = json.get_mut("chat_history").and_then(Value::as_array_mut) else {
        return;
    };
    for turn in history.iter_mut() {
        if cohere_role_excluded(turn.get("role").and_then(Value::as_str), exclude_roles) {
            continue;
        }
        if let Some(message) = turn.get_mut("message") {
            redact_field_text(message, exclude_roles, redact);
        }
    }
}

/// Cohere document-map member holding the citation identifier. It is
/// bookkeeping for citation retrieval rather than prompt prose, so it is not
/// scanned or rewritten.
const DOCUMENT_ID_MEMBER: &str = "id";

/// Cohere document-map member naming the document members the provider keeps
/// out of the model-visible rendering. Neither the control list nor the members
/// it names reach the model, so neither is scanned or rewritten.
const DOCUMENT_EXCLUDES_MEMBER: &str = "_excludes";

/// Whether a Cohere document-map member is bookkeeping the provider keeps out
/// of what the model reads: the citation [`DOCUMENT_ID_MEMBER`], the
/// [`DOCUMENT_EXCLUDES_MEMBER`] control itself, or a member that control names.
///
/// Shared by the detector and the redactor — passing the control value in
/// rather than the whole map is what lets the redactor apply the identical
/// predicate while it holds the map borrowed mutably, so the two cannot drift.
///
/// The control list is scanned in place rather than collected into a set: both
/// it and a document's member list are a handful of entries, and this runs on
/// the request path.
fn document_member_is_hidden(member: &str, excludes: Option<&Value>) -> bool {
    if member == DOCUMENT_ID_MEMBER || member == DOCUMENT_EXCLUDES_MEMBER {
        return true;
    }
    match excludes {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .any(|excluded| excluded == member),
        // Tolerate the single-value spelling of the same control.
        Some(Value::String(excluded)) => excluded == member,
        _ => false,
    }
}

/// Collect Cohere v1 `/chat` RAG document text for Content-mode scanning:
/// every eligible member of each top-level `documents[]` entry.
///
/// A Cohere v1 document is an arbitrary string-to-string map and the provider
/// serializes its eligible members into the prompt the model reads, so a
/// reader that stops at a recognized `text` member leaves `title`, `snippet`,
/// `url`, and every operator-chosen key unscanned while the model still sees
/// them — and contributes nothing at all for a document with no recognized
/// member. Documents are therefore read member-wise, minus the members
/// [`document_member_is_hidden`] excludes. Member *names* are not scanned:
/// they are structure rather than operator-supplied prose, and the redactor
/// cannot rewrite a key without changing the document the provider receives.
///
/// Mirrors the member-wise reading the sibling `ai_request_guard` counts, so a
/// shape one plugin reads is not silently invisible to the other (issue
/// #4792).
///
/// An entry that carries a `type` discriminator is a content *part*, not a
/// document map, so it keeps the ordinary [`text_content_part_text`] gate and
/// non-text multimodal parts stay out. A bare-string entry contributes itself.
/// Each retained member value is read through the same bounded one-level
/// traversal a tool-result payload gets ([`collect_tool_result_content_text`]),
/// so a document that nests content parts is still read and nothing recurses.
fn collect_cohere_document_text<'a>(json: &'a Value, texts: &mut Vec<&'a str>) {
    let Some(documents) = json.get("documents").and_then(Value::as_array) else {
        return;
    };
    for document in documents {
        let Some(object) = document.as_object() else {
            collect_tool_result_content_text(Some(document), texts);
            continue;
        };
        if object.contains_key("type") {
            if let Some(text) = text_content_part_text(document) {
                texts.push(text);
            }
            continue;
        }
        let excludes = object.get(DOCUMENT_EXCLUDES_MEMBER);
        for (member, value) in object {
            if document_member_is_hidden(member, excludes) {
                continue;
            }
            collect_tool_result_content_text(Some(value), texts);
        }
    }
}

/// Redact every Cohere document member scanned by
/// [`collect_cohere_document_text`], keeping Content-mode detection and
/// redaction symmetric.
///
/// The `_excludes` control is cloned before the map is borrowed mutably, and
/// only for a document that actually carries one, so the redactor applies the
/// same [`document_member_is_hidden`] predicate the detector did.
fn redact_cohere_document_text(json: &mut Value, redact: &impl Fn(&str) -> String) {
    let Some(documents) = json.get_mut("documents").and_then(Value::as_array_mut) else {
        return;
    };
    for document in documents.iter_mut() {
        if !document.is_object() {
            redact_tool_result_content_text(Some(document), redact);
            continue;
        }
        if document.get("type").is_some() {
            redact_content_part_text(document, redact);
            continue;
        }
        let excludes = document.get(DOCUMENT_EXCLUDES_MEMBER).cloned();
        let Some(object) = document.as_object_mut() else {
            continue;
        };
        for (member, value) in object.iter_mut() {
            if document_member_is_hidden(member, excludes.as_ref()) {
                continue;
            }
            redact_tool_result_content_text(Some(value), redact);
        }
    }
}

/// Collect Google Vertex legacy `predict` prompt text for Content-mode
/// scanning: `instances[].prompt`. These bodies carry no `messages` array and
/// none of the [`CONTENT_SCAN_FIELDS`], so the whole prompt passed Content
/// mode unscanned (`ScanMode::All` already covered it via full-body
/// recursion).
///
/// Scoped to each instance's `prompt` rather than the whole instance object:
/// the surrounding instance fields are prediction inputs and identifiers, not
/// model-visible prose, which matches how the sibling `ai_semantic_firewall`
/// reads `$.instances[*].prompt`.
fn collect_vertex_instance_prompts<'a>(
    json: &'a Value,
    exclude_roles: &HashSet<String>,
    texts: &mut Vec<&'a str>,
) {
    let Some(instances) = json.get("instances").and_then(Value::as_array) else {
        return;
    };
    for instance in instances {
        if let Some(prompt) = instance.get("prompt") {
            collect_field_text(prompt, exclude_roles, texts);
        }
    }
}

/// Redact every Vertex instance prompt scanned by
/// [`collect_vertex_instance_prompts`], keeping Content-mode detection and
/// redaction symmetric.
fn redact_vertex_instance_prompts(
    json: &mut Value,
    exclude_roles: &HashSet<String>,
    redact: &impl Fn(&str) -> String,
) {
    let Some(instances) = json.get_mut("instances").and_then(Value::as_array_mut) else {
        return;
    };
    for instance in instances.iter_mut() {
        if let Some(prompt) = instance.get_mut("prompt") {
            redact_field_text(prompt, exclude_roles, redact);
        }
    }
}

/// Recursively redact PII in all string values within a JSON Value.
///
/// `STRUCTURAL_KEYS` (model name, IDs, roles, request parameters) exists to
/// protect *top-level* request fields whose scalar values may incidentally
/// match a PII regex (e.g. a `model` name or an `id`) from being corrupted.
/// That protection is applied ONLY to a scalar string held directly by a
/// structural key at the top level of the body. Below the top level, those
/// same key names are attacker-controllable hiding spots, so PII nested under
/// them — e.g. `{"metadata":{"type":"<PII>"}}` or `{"id":{"note":"<PII>"}}` —
/// is still redacted. The walker also always recurses into nested objects and
/// arrays even under a top-level structural key, so PII cannot be hidden by
/// wrapping it in a container. Without this, redaction was fail-open: PII was
/// reported as detected but forwarded to the provider unredacted purely
/// because of attacker-controlled JSON structure.
///
/// `top_level` is true only for the root object's direct fields.
fn redact_json_strings(
    value: &mut Value,
    patterns: &[PiiPattern],
    top_level: bool,
    budget: &RedactionBudget,
) {
    if budget.is_exhausted() {
        return;
    }
    match value {
        Value::String(s) => {
            let result = redact_text_bounded(s.as_str(), patterns, budget);
            if result != *s {
                *s = result;
            }
        }
        // Numeric scalar PII (e.g. a bare `{"ssn":123456789}` or a numeric
        // credit-card number). `ScanMode::All` detection collects stringified
        // numbers, so a number that matches a PII pattern must actually be
        // removed here — otherwise it is forwarded unchanged while the request
        // is reported as redacted. A number has no in-place string to rewrite,
        // so when it matches we replace the whole scalar with the placeholder
        // string. The type change (number -> string) is the safe direction for
        // a privacy control: the alternative is leaking the value. Only the
        // first matching pattern's placeholder is used; a number matches at
        // most one PII shape in practice. The top-level structural carve-out
        // below prevents legitimate top-level numerics (timestamps, token
        // limits) from being rewritten.
        Value::Number(n) => {
            let rendered = n.to_string();
            if let Some(pattern) = patterns.iter().find(|p| p.regex.is_match(&rendered)) {
                // Replacing a scalar can grow the document just like rewriting
                // a string, so charge the same aggregate allowance.
                let growth = pattern.placeholder.len().saturating_sub(rendered.len());
                if growth > 0 && !budget.charge_growth(growth) {
                    return;
                }
                *value = Value::String(pattern.placeholder.clone());
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_strings(item, patterns, false, budget);
            }
        }
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                // Preserve only top-level structural scalar values. LLM
                // request parameters are preserved only when they are numeric;
                // string values in fields such as `seed` or `n` are
                // attacker-controlled content and must be redacted. Always
                // recurse into nested objects/arrays, and never skip nested
                // occurrences of these key names, so PII cannot hide under a
                // structural key.
                if top_level && should_preserve_top_level_scalar(k, val) {
                    continue;
                }
                redact_json_strings(val, patterns, false, budget);
            }
        }
        // PII carried in an object KEY name (e.g. `{"a@b.com":"x"}`) cannot be
        // rewritten here without rebuilding the map, and renaming keys risks
        // collisions and reorders the document. Such PII is instead caught by
        // the post-redaction re-scan in `apply_redaction_in_place`, which fails
        // the request closed rather than forwarding key PII while reporting it
        // redacted. Bool / Null carry no PII.
        _ => {}
    }
}
