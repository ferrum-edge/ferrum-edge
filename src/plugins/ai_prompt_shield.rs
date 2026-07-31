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
//! ## Compressed request bodies
//!
//! Request decompression runs in the later `transform_request_body` phase, so a
//! body with a non-identity `Content-Encoding` cannot be inspected during
//! `before_proxy`. The shield marks that request for deferred inspection and
//! re-evaluates the final backend-visible body in `on_final_request_body`, after
//! request transforms have run. Reject policy is enforced there, warn policy
//! records its event there, and redact policy fails closed when PII is present
//! because the final-body hook cannot safely rewrite the wire body. If no
//! decompressor removed the encoding, enforcing actions reject the uninspectable
//! request instead of silently forwarding it.

use async_trait::async_trait;
use regex::{NoExpand, Regex, RegexSet};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, warn};

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
/// `instructions`, and Anthropic carries a top-level `system` string. Each may
/// be a string, an array of strings, or an array of `{type:"text", text:"..."}`
/// parts.
const CONTENT_SCAN_FIELDS: &[&str] = &["prompt", "input", "instructions", "system"];

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
                        let placeholder = redaction_template.replace("{type}", name);
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
            for entry in custom {
                let name = entry["name"]
                    .as_str()
                    .ok_or("ai_prompt_shield: custom_patterns entries require string 'name'")?;
                let regex_str = entry["regex"]
                    .as_str()
                    .ok_or("ai_prompt_shield: custom_patterns entries require string 'regex'")?;
                match Regex::new(regex_str) {
                    Ok(regex) => {
                        let placeholder = redaction_template.replace("{type}", name);
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
                        // Array content (multimodal)
                        if let Some(parts) = msg.get("content").and_then(|c| c.as_array()) {
                            for part in parts {
                                if part
                                    .get("type")
                                    .and_then(|t| t.as_str())
                                    .is_some_and(is_text_content_part_type)
                                    && let Some(text) = part.get("text").and_then(|t| t.as_str())
                                {
                                    texts.push(text);
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
                    if *field == "system" && self.exclude_roles.contains("system") {
                        continue;
                    }
                    if let Some(value) = json.get(field) {
                        collect_field_text(value, &self.exclude_roles, &mut texts);
                    }
                }
                // Azure OpenAI "On Your Data" carries a per-data-source
                // instruction the backend applies as a de-facto system prompt;
                // scan it so a PII/jailbreak payload smuggled there does not slip
                // past Content mode. See `collect_azure_role_information_text`.
                collect_azure_role_information_text(json, &mut texts);
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

        if let Some(messages) = json.get("messages").and_then(Value::as_array) {
            for message in messages {
                if message
                    .get("role")
                    .and_then(Value::as_str)
                    .is_some_and(|role| self.exclude_roles.contains(role))
                {
                    continue;
                }
                if let Some(content) = message.get("content") {
                    self.mark_cross_part_hits_in_value(content, &mut hit);
                }
            }
        }

        for field in CONTENT_SCAN_FIELDS {
            if *field == "system" && self.exclude_roles.contains("system") {
                continue;
            }
            if let Some(value) = json.get(field) {
                self.mark_cross_part_hits_in_value(value, &mut hit);
            }
        }

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

    /// Find adjacent content-part runs recursively within one prompt field.
    fn mark_cross_part_hits_in_value(&self, value: &Value, hit: &mut [bool]) {
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
                        .is_some_and(|role| self.exclude_roles.contains(role))
                    {
                        continue;
                    }
                    if let Some(content) = object.get("content") {
                        self.mark_cross_part_hits_in_value(content, hit);
                    }
                }
            }
            Value::Object(object) => {
                if object
                    .get("role")
                    .and_then(Value::as_str)
                    .is_some_and(|role| self.exclude_roles.contains(role))
                {
                    return;
                }
                if let Some(content) = object.get("content") {
                    self.mark_cross_part_hits_in_value(content, hit);
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
            let text = item
                .get("type")
                .and_then(Value::as_str)
                .filter(|part_type| is_text_content_part_type(part_type))
                .and_then(|_| item.get("text"))
                .and_then(Value::as_str);

            let Some(text) = text else {
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
    /// Unioning the two only ever *adds* detections, so this strictly hardens
    /// all-mode coverage: escaped-value PII (pass 1) and cross-token/contextual
    /// patterns plus dropped scalars (pass 2) are both caught. Both passes feed
    /// the reject/warn decision; the redact path additionally re-scans the
    /// rewritten body so any detection a token rewrite cannot remove fails
    /// closed rather than forwarding PII while claiming redaction succeeded.
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
    /// rewritten in place.
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
                self.redact_body(&mut json);
            }
            redact_json_strings(&mut json, &self.patterns, true);

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
        self.redact_body(&mut json);
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

    /// Apply redaction to message content fields in the JSON body.
    fn redact_body(&self, json: &mut Value) {
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
                    let redacted = self.redact_text(content);
                    if redacted != content {
                        msg["content"] = Value::String(redacted);
                    }
                }

                // Array content (multimodal)
                if let Some(parts) = msg.get_mut("content").and_then(|c| c.as_array_mut()) {
                    for part in parts.iter_mut() {
                        if part
                            .get("type")
                            .and_then(|t| t.as_str())
                            .is_some_and(is_text_content_part_type)
                            && let Some(text) = part.get("text").and_then(|t| t.as_str())
                        {
                            let redacted = self.redact_text(text);
                            if redacted != text {
                                part["text"] = Value::String(redacted);
                            }
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
            if *field == "system" && self.exclude_roles.contains("system") {
                continue;
            }
            if let Some(value) = json.get_mut(field) {
                redact_field_text(value, &self.exclude_roles, &|text| self.redact_text(text));
            }
        }
        // Keep redaction symmetric with detection: `extract_scan_text` scans
        // Azure "On Your Data" `role_information`, so redact it here too —
        // otherwise Redact mode would report the PII removed while forwarding it
        // unredacted (a fail-open bypass).
        redact_azure_role_information(json, &|text| self.redact_text(text));
    }

    /// Replace all PII pattern matches in the text with the redaction placeholder.
    /// Placeholders are pre-rendered at construction time so each call is one
    /// `replace_all` per pattern, with no template formatting on the hot path.
    fn redact_text(&self, text: &str) -> String {
        let mut result = text.to_string();
        for pattern in &self.patterns {
            result = pattern
                .regex
                .replace_all(&result, NoExpand(pattern.placeholder.as_str()))
                .to_string();
        }
        result
    }

    /// Enforce the configured scan ceiling without silently bypassing reject or
    /// redact policy. Warn mode remains observational but records a bounded
    /// metadata event instead of silently skipping the request.
    fn handle_oversize_body(&self, ctx: &mut RequestContext, body_size: usize) -> PluginResult {
        match self.action {
            ShieldAction::Warn => {
                warn!(
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
                warn!(
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
                warn!(
                    reason,
                    "ai_prompt_shield: deferred request body could not be inspected (warn mode)"
                );
                ctx.metadata
                    .insert("ai_shield_warnings".to_string(), reason.to_string());
                PluginResult::Continue
            }
            ShieldAction::Reject | ShieldAction::Redact => {
                warn!(
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

        // Decompression occurs later in request-body transforms. Mark this
        // instance for final-body inspection instead of parsing compressed bytes
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
                warn!(
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
                        warn!(
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
                    RedactionOutcome::NoChange => {
                        // `detected` is non-empty (checked above) yet redaction
                        // found nothing to change. This should not happen for a
                        // parseable in-range body, but if it does, do not claim
                        // redaction and do not forward unredacted PII.
                        warn!(
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

    /// Inspect a compressed request after all request-body transforms. This is
    /// the authoritative policy decision for the backend-visible plaintext body.
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if ctx
            .metadata
            .remove(&self.deferred_compressed_marker)
            .is_none()
        {
            return PluginResult::Continue;
        }

        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");
        if !is_json_content_type(content_type) || is_framed_grpc_content_type(content_type) {
            return PluginResult::Continue;
        }

        if has_non_identity_content_encoding(headers) {
            return self.handle_uninspectable_deferred_body(ctx, "compressed_body");
        }

        if body.len() > self.max_scan_bytes {
            return self.handle_oversize_body(ctx, body.len());
        }

        let Ok(body_text) = std::str::from_utf8(body) else {
            return self.handle_uninspectable_deferred_body(ctx, "non_utf8_body");
        };
        let Ok(json) = serde_json::from_str::<Value>(body_text) else {
            return self.handle_uninspectable_deferred_body(ctx, "malformed_json");
        };

        if json.get("stream").and_then(Value::as_bool) == Some(true) {
            ctx.metadata
                .insert("ai_request_streaming".to_string(), "true".to_string());
        }

        let detected = match self.scan_mode {
            ScanMode::All => self.detect_pii_all_mode(&json, body_text),
            ScanMode::Content => self.detect_pii_content_mode(&json),
        };
        if detected.is_empty() {
            return PluginResult::Continue;
        }

        match self.action {
            ShieldAction::Reject => {
                debug!(
                    "ai_prompt_shield: PII detected after request decompression (types: {:?}), rejecting request",
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
                warn!(
                    "ai_prompt_shield: PII detected after request decompression (types: {:?}), passing through (warn mode)",
                    detected
                );
                ctx.metadata
                    .insert("ai_shield_warnings".to_string(), detected.join(","));
                PluginResult::Continue
            }
            ShieldAction::Redact => {
                // This hook can reject but cannot replace the final wire bytes.
                // Forwarding would leak the plaintext body, so redaction policy
                // must fail closed on a compressed request containing PII.
                warn!(
                    "ai_prompt_shield: PII detected after request decompression (types: {:?}) but final body cannot be rewritten, rejecting request",
                    detected
                );
                ctx.metadata
                    .insert("ai_shield_rejected".to_string(), detected.join(","));
                PluginResult::Reject {
                    status_code: 400,
                    body: serde_json::json!({
                        "error": "PII detected in request",
                        "detected_types": detected,
                        "message": "Request blocked: compressed sensitive data could not be redacted safely."
                    })
                    .to_string(),
                    headers: HashMap::new(),
                }
            }
        }
    }

    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // A later compression plugin may already have stripped the encoding
        // header in `before_proxy` even though its body transform has not run
        // yet. The instance marker is therefore the authoritative signal that
        // these bytes are still the deferred encoded representation.
        if ctx.metadata.contains_key(&self.deferred_compressed_marker) {
            return None;
        }
        self.transform_request_body(body, content_type, request_headers)
            .await
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &std::collections::HashMap<String, String>,
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

fn optional_positive_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "ai_prompt_shield: '{field}' must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "ai_prompt_shield: '{field}' must be greater than zero"
        ));
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

/// Collect scannable text from a top-level LLM content field
/// (`prompt`/`input`/`instructions`/`system`). Handles a plain string, an array
/// of strings, an array of `{type: text|input_text|output_text, text}` content
/// parts, and the structured OpenAI Responses `input` shape — an array of
/// message objects `{role, content: <string | array of parts>}` — by recursing
/// into each message's `content`.
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
                        if obj
                            .get("type")
                            .and_then(|t| t.as_str())
                            .is_some_and(is_text_content_part_type)
                        {
                            if let Some(text) = obj.get("text").and_then(|t| t.as_str()) {
                                texts.push(text);
                            }
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
        // A field that is itself a single message object `{role, content}`.
        Value::Object(obj) => {
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
/// strings, or an array of `{type:"text", text:"..."}` content parts (e.g.
/// `prompt`, `input`, `instructions`, `system`). Mirrors `collect_field_text`
/// so detection and redaction stay symmetric — anything scanned for PII is
/// also rewritten.
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
                match item {
                    Value::String(s) => {
                        let redacted = redact(s);
                        if redacted != *s {
                            *s = redacted;
                        }
                    }
                    Value::Object(obj) => {
                        if obj
                            .get("type")
                            .and_then(|t| t.as_str())
                            .is_some_and(is_text_content_part_type)
                        {
                            if let Some(text) = obj.get("text").and_then(|t| t.as_str()) {
                                let redacted = redact(text);
                                if redacted != text {
                                    obj.insert("text".to_string(), Value::String(redacted));
                                }
                            }
                        } else if obj
                            .get("role")
                            .and_then(|r| r.as_str())
                            .is_some_and(|role| exclude_roles.contains(role))
                        {
                            continue;
                        } else if let Some(content) = obj.get_mut("content") {
                            redact_field_text(content, exclude_roles, redact);
                        }
                    }
                    _ => {}
                }
            }
        }
        Value::Object(obj) => {
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
fn redact_json_strings(value: &mut Value, patterns: &[PiiPattern], top_level: bool) {
    match value {
        Value::String(s) => {
            let mut result = s.clone();
            for pattern in patterns {
                result = pattern
                    .regex
                    .replace_all(&result, NoExpand(pattern.placeholder.as_str()))
                    .to_string();
            }
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
                *value = Value::String(pattern.placeholder.clone());
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_strings(item, patterns, false);
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
                redact_json_strings(val, patterns, false);
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
