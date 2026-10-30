//! AI Prompt Compressor Plugin
//!
//! Shortens the prompt text sent to an LLM backend to cut token usage (and
//! therefore cost and latency) while preserving meaning. It rewrites the
//! prompt-bearing fields of an admitted OpenAI Chat Completions or legacy Text
//! Completions request body — `messages[].content` (per configurable role) and
//! the legacy top-level `prompt` — replacing each long content string with a
//! shorter, statistically filtered version. Standard operation paths are
//! recognized by default; compatible custom paths require a fixed-family opt-in.
//! OpenAI Responses (`instructions` / `input`) and Anthropic Messages
//! (`system` / `messages[].content` text blocks) are fixed-family opt-ins only.
//!
//! An optional aggregate `target_max_tokens` budget compresses only requests
//! whose eligible text exceeds it, `mode: observe` records would-be savings
//! without rewriting prompts, and `sample_rate` limits statistical work to a
//! deterministic per-request fraction of traffic.
//!
//! # Why a model-free approach
//!
//! Model-based prompt compressors run a fine-tuned transformer (hundreds of
//! megabytes) to score token importance — accurate, but a poor fit for a
//! hot-path edge proxy that would have to load the model and run per-request
//! inference. Instead this plugin uses a compact, dependency-free **statistical
//! extractive** filter: it scores every word by a handful of cheap features —
//! stop-word membership, length, in-document rarity, and a proper-noun/entity
//! signal — protects structural spans (code, URLs, numbers, identifiers),
//! always keeps negations, then drops the lowest-scoring words until the target
//! ratio is met. Hard body/text/token/field/output and concurrent-work budgets
//! bound the algorithm; it uses no model files or network calls. When a
//! `preserve_tag` is configured, a separate bounded sanitation lane removes
//! markers from admitted JSON string values even when statistical work is over
//! budget or saturated. Object member names are never sanitized.
//!
//! The transformation is intentionally lossy (extractive compression removes
//! filler words), so it only runs on roles the operator opts into and only on
//! content long enough to be worth compressing (`min_content_tokens`). Code
//! blocks/inline spans with matching backtick runs, URLs, Unicode numbers, and
//! common identifier forms are preserved verbatim, and an optional
//! `preserve_tag` lets operators wrap nested must-keep spans that are copied
//! through with every marker removed.
//!
//! A normal admitted field change intentionally reserializes the complete JSON
//! value. Non-target decoded values are semantically retained, but lexical
//! whitespace, escapes, duplicate members, numeric spelling, and member-byte
//! order are not preserved. Marker-only bounded fallbacks instead preserve
//! every unrelated source byte, including member names.
//!
//! # Request flow
//!
//! Like `ai_prompt_shield`, the plugin composes multiple body phases so both the
//! normal backend-dispatch path and the `ai_federation` direct-dispatch path
//! forward the compressed body:
//!
//! * `before_proxy` compresses the buffered body and rewrites
//!   `ctx.metadata["request_body"]` so any later `before_proxy` consumer that
//!   dispatches directly from that metadata sends the compressed prompt. It also
//!   records `ai_prompt_compressor.*` observability metadata.
//! * The context-aware request-body transform reuses a staged result of at most
//!   65,536 bytes when the source digest matches, or recomputes against an
//!   earlier transform's final bytes. Larger direct-dispatch bodies retain only
//!   their metadata representation. This hook produces the bytes actually sent
//!   upstream and replaces provisional counters with authoritative wire
//!   counters. Auto-family classification always uses the original incoming
//!   path captured before routing can rewrite the backend path.
//! * `on_final_request_body_with_context` fails closed if a decoded body exceeds
//!   the immutable sanitation bound or the bounded sanitation worker cannot
//!   complete. With a configured `preserve_tag` it also re-verifies the exact
//!   final representation (through the shared decoded inspection view for a
//!   content-coded body) and refuses any admitted body whose string values
//!   still carry a marker — one a later transform reintroduced, or one that
//!   bounded removal could not resolve. This keeps configured preserve markers
//!   in string values off the provider wire without changing the request
//!   schema.
//!   Compression is gated to POST requests: the context-aware variant checks
//!   `ctx.method` (H1/H2 and the H3 cross-protocol bridge), and the no-context
//!   compatibility variant requires explicit `:method` and `:path` pseudo-
//!   headers. Compression is deterministic, so all paths agree.

use crate::fips::approved::Sha256;
use async_trait::async_trait;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use tokio::sync::Semaphore;
use tracing::debug;

use super::utils::body_transform::is_json_content_type;
use super::{Plugin, PluginResult, RequestContext};

/// Default per-content token floor below which a string is left untouched.
const DEFAULT_MIN_CONTENT_TOKENS: usize = 200;
/// Default fraction of word-tokens to keep (0.5 = target ~50% reduction).
const DEFAULT_TARGET_RATIO: f64 = 0.5;
/// Default maximum request-body size to attempt compression on (1 MiB).
const DEFAULT_MAX_SCAN_BYTES: usize = 1_048_576;
/// Absolute request-body ceiling, independent of operator configuration.
const HARD_MAX_SCAN_BYTES: usize = 1_048_576;
/// Maximum aggregate eligible prompt bytes considered in one body.
const MAX_TARGET_TEXT_BYTES: usize = 524_288;
/// Largest meaningful per-field token floor under the eligible-text ceiling.
const MAX_MIN_CONTENT_TOKENS: usize = MAX_TARGET_TEXT_BYTES.div_ceil(4);
/// Maximum aggregate whitespace-delimited units admitted before token allocation.
const MAX_TOKEN_UNITS: usize = 32_768;
/// Maximum independently rewritable text fields in one request body.
const MAX_TARGET_FIELDS: usize = 256;
/// Maximum preserve markers admitted across eligible text in one body.
const MAX_PRESERVE_MARKERS: usize = 1_024;
/// Maximum configured marker-name length. This also bounds lexical matching
/// work in the representation-preserving marker sanitizer.
const MAX_PRESERVE_TAG_NAME_BYTES: usize = 64;
/// Maximum transformed body retained beside request metadata for wire-path reuse.
const MAX_STAGED_OUTPUT_BYTES: usize = 65_536;
/// Maximum simultaneous statistical compression jobs across all plugin instances.
const MAX_CONCURRENT_COMPRESSIONS: usize = 8;
/// Maximum simultaneous parse/classify/sanitize jobs for configured preserve
/// markers. Saturation fails closed before cloning the buffered body rather
/// than retaining an unbounded queue of request contexts.
const MAX_CONCURRENT_MARKER_SANITIZATIONS: usize = 32;
/// Maximum configured `compress_roles` entries.
const MAX_COMPRESS_ROLES: usize = 32;
/// Maximum Unicode scalars in one configured role name.
const MAX_ROLE_NAME_CHARS: usize = 64;
/// Maximum representation-preserving marker-removal passes. Removing one
/// marker can join its neighbours into a new one (`<ke<keep>ep>`), so removal
/// repeats until a pass changes nothing. Each pass is linear in the bounded
/// body; anything still unresolved after this many passes is refused by the
/// final residual-marker check instead of being forwarded.
const MAX_MARKER_SANITATION_PASSES: usize = 8;
/// Largest integral float spelling accepted for an integer field. Every
/// integer up to 2^53 is exactly representable, so the cast loses nothing.
const MAX_INTEGRAL_FLOAT: f64 = 9_007_199_254_740_992.0;

const STAT_SUFFIXES: [&str; 4] = [
    "original_tokens",
    "compressed_tokens",
    "tokens_saved",
    "fields_compressed",
];
const AGGREGATE_STAT_KEYS: [&str; 4] = [
    "ai_prompt_compressor.original_tokens",
    "ai_prompt_compressor.compressed_tokens",
    "ai_prompt_compressor.tokens_saved",
    "ai_prompt_compressor.fields_compressed",
];
/// `mode: observe` counters: the savings a rewrite would have produced, kept
/// apart from enforced counters so dashboards never mistake them for savings.
const OBSERVED_STAT_SUFFIXES: [&str; 4] = [
    "observed_original_tokens",
    "observed_compressed_tokens",
    "observed_tokens_saved",
    "observed_fields_compressed",
];
const OBSERVED_AGGREGATE_STAT_KEYS: [&str; 4] = [
    "ai_prompt_compressor.observed_original_tokens",
    "ai_prompt_compressor.observed_compressed_tokens",
    "ai_prompt_compressor.observed_tokens_saved",
    "ai_prompt_compressor.observed_fields_compressed",
];

const CONFIG_FIELDS: &[&str] = &[
    "compress_roles",
    "target_ratio",
    "min_content_tokens",
    "max_scan_bytes",
    "preserve_tag",
    "request_family",
    "target_max_tokens",
    "mode",
    "sample_rate",
];

/// Top-level fields that identify a request family other than OpenAI Chat or
/// Text Completions. `auto` never admits a body carrying any of them.
const PROVIDER_NATIVE_MARKERS: &[&str] = &[
    "input",
    "instructions",
    "previous_response_id",
    "contents",
    "system",
    "systemInstruction",
    "system_instruction",
    "generationConfig",
    "inferenceConfig",
    "preamble",
    "message",
    "chat_history",
    "inputs",
    "inputText",
    "textGenerationConfig",
    "documents",
    "retrieved_context",
    "tool_results",
];
/// Provider markers that belong to the OpenAI Responses request shape.
const RESPONSES_NATIVE_FIELDS: &[&str] = &["input", "instructions", "previous_response_id"];
/// Provider markers that belong to the Anthropic Messages request shape.
const ANTHROPIC_NATIVE_FIELDS: &[&str] = &["system"];

/// Typed content-part `type` values that carry prompt text in `text`.
const CHAT_TEXT_PARTS: &[&str] = &["text"];
const ANTHROPIC_TEXT_BLOCKS: &[&str] = &["text"];
const RESPONSES_TEXT_PARTS: &[&str] = &["input_text", "output_text"];

/// Restrictive connectives: like negations, they and the word right after them
/// are kept, because dropping either widens an instruction's scope.
const RESTRICTIVE_CONNECTIVES: &[&str] = &["unless", "except", "only"];
/// Closed-class conditions, obligations, ordering words, quantifiers, and
/// spelled-out numbers. Dropping one silently turns a conditional, bounded, or
/// counted instruction into an unconditional one.
const SCOPE_QUALIFIERS: &[&str] = &[
    "if", "must", "before", "after", "until", "exactly", "all", "every", "each", "any", "zero",
    "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven",
    "twelve", "hundred", "thousand", "million", "billion",
];

static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);
static COMPRESSION_BUDGET: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_COMPRESSIONS)));
static MARKER_SANITIZATION_BUDGET: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_MARKER_SANITIZATIONS)));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestFamily {
    ChatCompletions,
    TextCompletions,
    Responses,
    AnthropicMessages,
}

impl RequestFamily {
    /// Typed part kinds carrying text inside a `messages[].content` array.
    fn message_text_parts(self) -> &'static [&'static str] {
        match self {
            RequestFamily::AnthropicMessages => ANTHROPIC_TEXT_BLOCKS,
            RequestFamily::ChatCompletions
            | RequestFamily::TextCompletions
            | RequestFamily::Responses => CHAT_TEXT_PARTS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestFamilyPolicy {
    Auto,
    ChatCompletions,
    TextCompletions,
    Responses,
    AnthropicMessages,
}

/// How one prompt-bearing value may be shaped.
#[derive(Clone, Copy)]
enum ContentShape {
    /// Legacy `prompt`: a string or an array of strings.
    PromptStrings,
    /// A string, `null`, or an array of typed parts. Parts whose `type` is
    /// listed carry their prompt text in `text`; every other part is left
    /// untouched.
    TypedParts(&'static [&'static str]),
}

/// Why statistical compression was skipped for an otherwise admitted body.
/// Recorded as low-cardinality metadata so a silent loss of savings is visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SkipReason {
    /// The process-wide statistical worker budget was saturated.
    Saturated,
    /// The body exceeded `max_scan_bytes` or a work/output limit.
    WorkLimit,
    /// The request fell outside `sample_rate`.
    NotSampled,
}

impl SkipReason {
    fn as_str(self) -> &'static str {
        match self {
            SkipReason::Saturated => "saturated",
            SkipReason::WorkLimit => "work_limit",
            SkipReason::NotSampled => "not_sampled",
        }
    }
}

/// Why work measurement refused an admitted family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkRejection {
    /// An inner role/content field has an unsupported shape.
    Malformed,
    /// An aggregate work bound was exceeded.
    OverBudget,
}

/// Whether a scored word is meaning-critical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CriticalWord {
    Ordinary,
    Kept,
    KeptWithComplement,
}

#[derive(Clone)]
pub struct AiPromptCompressor {
    /// Process-unique identity used for per-instance staging and counters.
    instance_id: u64,
    /// Lowercased message roles whose `content` is compressed.
    compress_roles: HashSet<String>,
    /// Whether the legacy top-level `prompt` field is compressed (true when
    /// `"user"` is an eligible role, since a completions `prompt` is user text).
    compress_prompt_field: bool,
    /// Fraction of word-tokens to keep, in `(0.0, 1.0)`.
    target_ratio: f64,
    /// Estimated-token floor: content below this is passed through unchanged.
    min_content_tokens: usize,
    /// Skip statistical compression when the body exceeds this many bytes.
    /// Configured preserve-marker sanitation continues to the hard ceiling.
    max_scan_bytes: usize,
    /// Optional `(open, close)` markers whose enclosed span is kept verbatim
    /// (the markers themselves are stripped from the outgoing content).
    preserve_tags: Option<(String, String)>,
    /// Request-family admission policy. `Auto` recognizes standard endpoint
    /// paths; fixed variants are an explicit opt-in for custom endpoints.
    request_family: RequestFamilyPolicy,
    /// Optional aggregate estimated-token budget for all eligible prompt text.
    /// Requests within it are not statistically compressed.
    target_max_tokens: Option<usize>,
    /// `mode: observe`: compute and record savings, forward the original
    /// prompt text. Marker sanitation is still enforced.
    observe: bool,
    /// Fraction of requests, in `(0.0, 1.0]`, eligible for statistical work.
    sample_rate: f64,
    /// Exact per-instance metadata keys, constructed once with the instance and
    /// shared by blocking-worker clones. Request paths never format key names.
    metadata_keys: Arc<CompressionMetadataKeys>,
}

#[derive(Debug)]
struct CompressionMetadataKeys {
    instance: [String; 4],
    aggregate: [&'static str; 4],
    skipped: String,
}

impl CompressionMetadataKeys {
    fn new(instance_id: u64, observe: bool) -> Self {
        let (suffixes, aggregate) = if observe {
            (OBSERVED_STAT_SUFFIXES, OBSERVED_AGGREGATE_STAT_KEYS)
        } else {
            (STAT_SUFFIXES, AGGREGATE_STAT_KEYS)
        };
        Self {
            instance: std::array::from_fn(|index| {
                format!(
                    "ai_prompt_compressor.instances.{instance_id}.{}",
                    suffixes[index]
                )
            }),
            aggregate,
            skipped: format!("ai_prompt_compressor.instances.{instance_id}.skipped"),
        }
    }
}

/// Running totals accumulated while compressing one request body.
#[derive(Clone, Debug, Default)]
struct CompressionStats {
    original_tokens: usize,
    compressed_tokens: usize,
    fields_compressed: usize,
}

/// Bounded compression staged in `before_proxy` for reuse by the authoritative
/// wire transform when no earlier transform changed the source representation.
#[derive(Clone, Debug)]
pub(crate) struct StagedCompression {
    source_len: usize,
    source_sha256: [u8; 32],
    /// `None` when the forwarded representation is unchanged (`mode: observe`
    /// without markers to remove); only the observed counters are reused.
    output: Option<Vec<u8>>,
    stats: Option<CompressionStats>,
    /// Why statistical work was skipped for the staged result, restored with
    /// the stage so wire-path reuse keeps the authoritative skip reason.
    skipped: Option<SkipReason>,
}

struct CompressionOutput {
    source_sha256: [u8; 32],
    /// Replacement body bytes, or `None` when the representation is unchanged
    /// and only `stats` are reported (`mode: observe`).
    body: Option<Vec<u8>>,
    stats: Option<CompressionStats>,
}

/// One compression attempt: an optional result plus why statistical work was
/// skipped, when it was.
#[derive(Default)]
struct CompressionAttempt {
    output: Option<CompressionOutput>,
    skipped: Option<SkipReason>,
}

impl CompressionAttempt {
    fn skipped(reason: SkipReason) -> Self {
        Self {
            output: None,
            skipped: Some(reason),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MarkerSanitizationError {
    BodyTooLarge,
    WorkerUnavailable,
    /// The final admitted representation still carries a configured marker in
    /// a string value, or a content-coded body offered no inspectable view.
    Unsanitizable,
}

#[derive(Default)]
struct WorkEstimate {
    target_fields: usize,
    target_text_bytes: usize,
    token_units: usize,
    emitted_tokens: usize,
    preserve_markers: usize,
    /// Whether `eligible_chars` is needed (a `target_max_tokens` budget).
    count_chars: bool,
    /// Unicode scalars across every eligible text field.
    eligible_chars: usize,
}

impl CompressionStats {
    fn changed(&self) -> bool {
        self.fields_compressed > 0
    }
}

impl AiPromptCompressor {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "ai_prompt_compressor: config must be an object".to_string())?;
        let mut unknown: Vec<&str> = object
            .keys()
            .map(String::as_str)
            .filter(|key| !CONFIG_FIELDS.contains(key))
            .collect();
        if !unknown.is_empty() {
            unknown.sort_unstable();
            return Err(format!(
                "ai_prompt_compressor: unknown config field(s): {:?} (allowed: `{}`)",
                unknown.join(", "),
                CONFIG_FIELDS.join("`, `")
            ));
        }

        let compress_roles: HashSet<String> = match optional_string_vec(config, "compress_roles")? {
            Some(roles) => {
                if roles.is_empty() {
                    return Err(
                        "ai_prompt_compressor: `compress_roles` must not be empty — the plugin \
                         would have no effect"
                            .to_string(),
                    );
                }
                if roles.len() > MAX_COMPRESS_ROLES {
                    return Err(format!(
                        "ai_prompt_compressor: `compress_roles` must contain at most \
                         {MAX_COMPRESS_ROLES} entries"
                    ));
                }
                if roles
                    .iter()
                    .any(|role| role.chars().count() > MAX_ROLE_NAME_CHARS)
                {
                    return Err(format!(
                        "ai_prompt_compressor: `compress_roles` entries must be at most \
                         {MAX_ROLE_NAME_CHARS} characters long"
                    ));
                }
                let normalized: HashSet<String> =
                    roles.into_iter().map(|r| r.trim().to_lowercase()).collect();
                if normalized.iter().any(String::is_empty) {
                    return Err(
                        "ai_prompt_compressor: `compress_roles` entries must not be blank"
                            .to_string(),
                    );
                }
                normalized
            }
            // Default: compress user prompts only. System messages usually carry
            // load-bearing instructions and are preserved unless opted in.
            None => HashSet::from(["user".to_string()]),
        };
        let compress_prompt_field = compress_roles.contains("user");

        let target_ratio = match config.get("target_ratio") {
            Some(value) => {
                let ratio = value.as_f64().ok_or_else(|| {
                    "ai_prompt_compressor: `target_ratio` must be a number".to_string()
                })?;
                if !(ratio > 0.0 && ratio < 1.0) {
                    return Err(format!(
                        "ai_prompt_compressor: `target_ratio` must be between 0 and 1 \
                         (exclusive), got \"{ratio}\""
                    ));
                }
                ratio
            }
            None => DEFAULT_TARGET_RATIO,
        };

        let min_content_tokens =
            optional_usize(config, "min_content_tokens")?.unwrap_or(DEFAULT_MIN_CONTENT_TOKENS);
        if min_content_tokens > MAX_MIN_CONTENT_TOKENS {
            return Err(format!(
                "ai_prompt_compressor: `min_content_tokens` must not exceed \
                 {MAX_MIN_CONTENT_TOKENS}"
            ));
        }

        let max_scan_bytes = match optional_usize(config, "max_scan_bytes")? {
            Some(0) => {
                return Err(
                    "ai_prompt_compressor: `max_scan_bytes` must be greater than zero".to_string(),
                );
            }
            Some(bytes) if bytes <= HARD_MAX_SCAN_BYTES => bytes,
            Some(bytes) => {
                return Err(format!(
                    "ai_prompt_compressor: `max_scan_bytes` must not exceed the hard limit of \
                     {HARD_MAX_SCAN_BYTES}, got \"{bytes}\""
                ));
            }
            None => DEFAULT_MAX_SCAN_BYTES,
        };

        let preserve_tags = match optional_string(config, "preserve_tag")? {
            Some(tag) => {
                if tag.trim() != tag {
                    return Err(
                        "ai_prompt_compressor: `preserve_tag` must not contain leading or \
                         trailing whitespace"
                            .to_string(),
                    );
                }
                if tag.is_empty()
                    || tag.len() > MAX_PRESERVE_TAG_NAME_BYTES
                    || !tag
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    return Err(
                        "ai_prompt_compressor: `preserve_tag` must be a non-empty name of ASCII \
                         letters, digits, `-`, or `_`, at most 64 bytes long"
                            .to_string(),
                    );
                }
                Some((format!("<{tag}>"), format!("</{tag}>")))
            }
            None => None,
        };

        let request_family = match optional_string(config, "request_family")? {
            Some("auto") | None => RequestFamilyPolicy::Auto,
            Some("chat_completions") => RequestFamilyPolicy::ChatCompletions,
            Some("text_completions") => RequestFamilyPolicy::TextCompletions,
            Some("responses") => RequestFamilyPolicy::Responses,
            Some("anthropic_messages") => RequestFamilyPolicy::AnthropicMessages,
            Some(other) => {
                return Err(format!(
                    "ai_prompt_compressor: `request_family` must be `auto`, \
                     `chat_completions`, `text_completions`, `responses`, or \
                     `anthropic_messages`, got {other:?}"
                ));
            }
        };
        if request_family == RequestFamilyPolicy::TextCompletions && !compress_prompt_field {
            return Err(
                "ai_prompt_compressor: `compress_roles` must include `user` when \
                 `request_family` is `text_completions`"
                    .to_string(),
            );
        }

        let target_max_tokens = match optional_usize(config, "target_max_tokens")? {
            Some(0) => {
                return Err(
                    "ai_prompt_compressor: `target_max_tokens` must be greater than zero"
                        .to_string(),
                );
            }
            Some(tokens) if tokens > MAX_MIN_CONTENT_TOKENS => {
                return Err(format!(
                    "ai_prompt_compressor: `target_max_tokens` must not exceed \
                     {MAX_MIN_CONTENT_TOKENS}"
                ));
            }
            other => other,
        };

        let observe = match optional_string(config, "mode")? {
            Some("enforce") | None => false,
            Some("observe") => true,
            Some(other) => {
                return Err(format!(
                    "ai_prompt_compressor: `mode` must be `enforce` or `observe`, got {other:?}"
                ));
            }
        };

        let sample_rate = match config.get("sample_rate") {
            Some(value) => {
                let rate = value.as_f64().ok_or_else(|| {
                    "ai_prompt_compressor: `sample_rate` must be a number".to_string()
                })?;
                if !(rate > 0.0 && rate <= 1.0) {
                    return Err(format!(
                        "ai_prompt_compressor: `sample_rate` must be greater than 0 and at \
                         most 1, got \"{rate}\""
                    ));
                }
                rate
            }
            None => 1.0,
        };

        let instance_id = NEXT_INSTANCE_ID.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            instance_id,
            compress_roles,
            compress_prompt_field,
            target_ratio,
            min_content_tokens,
            max_scan_bytes,
            preserve_tags,
            request_family,
            target_max_tokens,
            observe,
            sample_rate,
            metadata_keys: Arc::new(CompressionMetadataKeys::new(instance_id, observe)),
        })
    }

    /// Deterministic per-request sampling decision. It is derived from the
    /// request's receive timestamp and this instance's identity, so the
    /// metadata stage and the wire transform (including retries) agree without
    /// any per-request state.
    fn sampled(&self, ctx: &RequestContext) -> bool {
        if self.sample_rate >= 1.0 {
            return true;
        }
        let mut hasher = DefaultHasher::new();
        self.instance_id.hash(&mut hasher);
        ctx.timestamp_received.timestamp().hash(&mut hasher);
        ctx.timestamp_received
            .timestamp_subsec_nanos()
            .hash(&mut hasher);
        // The top 53 bits give a uniform draw in [0, 1).
        let draw = (hasher.finish() >> 11) as f64 / (1u64 << 53) as f64;
        draw < self.sample_rate
    }

    /// Estimated tokens are `ceil(chars / 4)` and no field holds more Unicode
    /// scalars than the body has bytes, so a body whose own estimate cannot
    /// reach the per-field floor (or, with a budget, cannot exceed it) has
    /// nothing to compress and needs no parse.
    fn body_len_may_compress(&self, len: usize) -> bool {
        let ceiling = len.div_ceil(4);
        ceiling >= self.min_content_tokens
            && self.target_max_tokens.is_none_or(|budget| ceiling > budget)
    }

    /// Keep ratio for this request, or `None` when its eligible text already
    /// fits the configured `target_max_tokens` budget. With a budget, the
    /// ratio removes only as much as needed, but never more aggressively than
    /// `target_ratio`.
    fn effective_ratio(&self, estimate: &WorkEstimate) -> Option<f64> {
        let Some(budget) = self.target_max_tokens else {
            return Some(self.target_ratio);
        };
        let tokens = estimate.eligible_chars.div_ceil(4);
        if tokens <= budget {
            return None;
        }
        Some((budget as f64 / tokens as f64).max(self.target_ratio))
    }

    /// `instructions` is a system/developer-level message in the Responses API.
    fn instructions_eligible(&self) -> bool {
        self.role_is_eligible("system") || self.role_is_eligible("developer")
    }

    /// Parse, compress in place, and re-serialize `body`. With no preserve tag,
    /// saturated, unsampled, or over-budget statistical work remains a
    /// passthrough. With a preserve tag, admitted bodies use a separate bounded
    /// lane and fall back to representation-preserving marker removal on every
    /// compression skip.
    async fn compress_body(
        &self,
        body: &[u8],
        request_path: Option<&str>,
        sampled: bool,
    ) -> Result<CompressionAttempt, MarkerSanitizationError> {
        if body.len() > HARD_MAX_SCAN_BYTES {
            return if self.preserve_tags.is_some() {
                Err(MarkerSanitizationError::BodyTooLarge)
            } else {
                Ok(CompressionAttempt::skipped(SkipReason::WorkLimit))
            };
        }

        let mut skipped = None;
        let mut statistical = true;
        if !sampled {
            statistical = false;
            skipped = Some(SkipReason::NotSampled);
        } else if body.len() > self.max_scan_bytes {
            statistical = false;
            skipped = Some(SkipReason::WorkLimit);
        } else if self.preserve_tags.is_none() && !self.body_len_may_compress(body.len()) {
            // Cheap negative shortcut: no field of this body can reach the
            // floor (or exceed the budget), so skip the clone, the blocking
            // hop, and the parse entirely.
            return Ok(CompressionAttempt::default());
        }
        if self.preserve_tags.is_none() && !statistical {
            return Ok(CompressionAttempt {
                output: None,
                skipped,
            });
        }

        // Marker sanitation is a correctness boundary, so configured instances
        // use a separate bounded worker lane instead of converting pressure
        // into marker-bearing passthrough. Both lanes use non-waiting admission;
        // sanitation saturation fails closed before the body clone.
        let marker_permit = if self.preserve_tags.is_some() {
            Some(
                Arc::clone(&MARKER_SANITIZATION_BUDGET)
                    .try_acquire_owned()
                    .map_err(|_| MarkerSanitizationError::WorkerUnavailable)?,
            )
        } else {
            None
        };
        let compression_permit = if statistical {
            Arc::clone(&COMPRESSION_BUDGET).try_acquire_owned().ok()
        } else {
            None
        };
        if statistical && compression_permit.is_none() {
            skipped = Some(SkipReason::Saturated);
        }
        if self.preserve_tags.is_none() && compression_permit.is_none() {
            return Ok(CompressionAttempt {
                output: None,
                skipped,
            });
        }

        let worker = self.clone();
        let body = body.to_vec();
        let request_path = request_path.map(str::to_owned);
        tokio::task::spawn_blocking(move || {
            let _marker_permit = marker_permit;
            let allow_compression = compression_permit.is_some();
            let _compression_permit = compression_permit;
            worker.compress_body_blocking(
                &body,
                request_path.as_deref(),
                allow_compression,
                skipped,
            )
        })
        .await
        .map_err(|_| MarkerSanitizationError::WorkerUnavailable)
    }

    fn compress_body_blocking(
        &self,
        body: &[u8],
        request_path: Option<&str>,
        allow_compression: bool,
        skipped: Option<SkipReason>,
    ) -> CompressionAttempt {
        let Ok(mut json) = serde_json::from_slice::<Value>(body) else {
            return CompressionAttempt::default();
        };
        let Some(family) = self.classify_request(&json, request_path) else {
            return CompressionAttempt::default();
        };
        let fallback = |skipped: Option<SkipReason>| CompressionAttempt {
            output: self
                .preserve_tags
                .as_ref()
                .and_then(|tags| strip_markers_from_json_strings(body, tags))
                .map(|output| CompressionOutput {
                    source_sha256: Sha256::digest(body),
                    body: Some(output),
                    stats: None,
                }),
            skipped,
        };

        if !allow_compression {
            return fallback(skipped);
        }
        let estimate = match self.measure_work(&json, family) {
            Ok(estimate) => estimate,
            Err(WorkRejection::OverBudget) => return fallback(Some(SkipReason::WorkLimit)),
            Err(WorkRejection::Malformed) => return fallback(None),
        };
        let Some(ratio) = self.effective_ratio(&estimate) else {
            // Within the aggregate `target_max_tokens` budget: nothing to save.
            return fallback(None);
        };
        let Some(stats) = self.compress_json(&mut json, family, ratio) else {
            return fallback(None);
        };
        if !stats.changed() {
            return fallback(None);
        }
        if self.observe {
            // Observe mode reports the would-be savings and forwards the
            // original representation; only configured markers are removed.
            return CompressionAttempt {
                output: Some(CompressionOutput {
                    source_sha256: Sha256::digest(body),
                    body: self
                        .preserve_tags
                        .as_ref()
                        .and_then(|tags| strip_markers_from_json_strings(body, tags)),
                    stats: Some(stats),
                }),
                skipped: None,
            };
        }
        // The input scan cap and output cap are deliberately distinct. Complete
        // JSON reserialization may expand short exponent spellings in untouched
        // fields; admit that growth up to the immutable 1 MiB body ceiling.
        let mut writer = BoundedWriter::new(body.len(), HARD_MAX_SCAN_BYTES);
        if serde_json::to_writer(&mut writer, &json).is_err() {
            return fallback(Some(SkipReason::WorkLimit));
        }
        let serialized = writer.into_inner();
        let output = self
            .preserve_tags
            .as_ref()
            .and_then(|tags| strip_markers_from_json_strings(&serialized, tags))
            .unwrap_or(serialized);
        CompressionAttempt {
            output: Some(CompressionOutput {
                source_sha256: Sha256::digest(body),
                body: Some(output),
                stats: Some(stats),
            }),
            skipped: None,
        }
    }

    async fn body_digest(&self, body: &[u8]) -> Option<[u8; 32]> {
        // Staged marker-only sanitation remains reusable above the statistical
        // scan threshold; only the immutable body ceiling limits digest work.
        if body.len() > HARD_MAX_SCAN_BYTES {
            return None;
        }
        let permit = Arc::clone(&COMPRESSION_BUDGET).try_acquire_owned().ok()?;
        let body = body.to_vec();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            Sha256::digest(&body)
        })
        .await
        .ok()
    }

    /// Shared wire-path compression used by both `transform_request_body` and
    /// its context-aware variant: skip non-JSON and transport-encoded bodies,
    /// otherwise return the compressed bytes (or `None` when unchanged).
    async fn compress_wire_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
        request_path: Option<&str>,
        sampled: bool,
    ) -> Result<CompressionAttempt, MarkerSanitizationError> {
        // Require an explicit JSON content type; a missing Content-Type is
        // treated as ineligible so a JSON-looking body without the header is
        // never rewritten (matches `should_buffer_request_body`'s JSON gate).
        if !content_type.is_some_and(is_json_content_type) {
            return Ok(CompressionAttempt::default());
        }
        // An encoded body is opaque here. With a configured preserve tag the
        // final hook inspects the gate's decoded view and refuses markers.
        if has_non_identity_content_encoding(request_headers) {
            return Ok(CompressionAttempt::default());
        }
        self.compress_body(body, request_path, sampled).await
    }

    /// Admit only an explicitly supported request family. In `auto`, the
    /// request path must name the standard OpenAI Chat Completions or Text
    /// Completions operation and the body shape must agree. Fixed policies are
    /// the explicit opt-in for compatible custom endpoint paths and the only
    /// way to admit OpenAI Responses or Anthropic Messages bodies.
    fn classify_request(&self, json: &Value, request_path: Option<&str>) -> Option<RequestFamily> {
        match self.request_family {
            RequestFamilyPolicy::ChatCompletions => (request_shape(json)?
                == RequestFamily::ChatCompletions)
                .then_some(RequestFamily::ChatCompletions),
            RequestFamilyPolicy::TextCompletions => (request_shape(json)?
                == RequestFamily::TextCompletions)
                .then_some(RequestFamily::TextCompletions),
            RequestFamilyPolicy::Responses => {
                responses_request_shape(json).then_some(RequestFamily::Responses)
            }
            RequestFamilyPolicy::AnthropicMessages => {
                anthropic_messages_request_shape(json).then_some(RequestFamily::AnthropicMessages)
            }
            RequestFamilyPolicy::Auto => {
                let shape = request_shape(json)?;
                let path_family = standard_path_family(request_path?)?;
                (shape == path_family).then_some(shape)
            }
        }
    }

    /// Validate every candidate field and establish aggregate work bounds before
    /// token allocation, lowercasing, scoring, or mutation begins.
    fn measure_work(
        &self,
        json: &Value,
        family: RequestFamily,
    ) -> Result<WorkEstimate, WorkRejection> {
        use WorkRejection::{Malformed, OverBudget};
        let mut estimate = WorkEstimate {
            count_chars: self.target_max_tokens.is_some(),
            ..WorkEstimate::default()
        };
        let tags = self.preserve_tags.as_ref();
        match family {
            RequestFamily::ChatCompletions | RequestFamily::AnthropicMessages => {
                let object = json.as_object().ok_or(Malformed)?;
                if family == RequestFamily::AnthropicMessages
                    && let Some(system) = object.get("system")
                {
                    measure_content(
                        system,
                        self.role_is_eligible("system"),
                        ContentShape::TypedParts(ANTHROPIC_TEXT_BLOCKS),
                        tags,
                        &mut estimate,
                    )?;
                }
                let messages = object
                    .get("messages")
                    .and_then(Value::as_array)
                    .ok_or(Malformed)?;
                let parts = ContentShape::TypedParts(family.message_text_parts());
                for message in messages {
                    let message = message.as_object().ok_or(Malformed)?;
                    let role = message
                        .get("role")
                        .and_then(Value::as_str)
                        .ok_or(Malformed)?;
                    let eligible = self.role_is_eligible(role);
                    if let Some(content) = message.get("content") {
                        measure_content(content, eligible, parts, tags, &mut estimate)?;
                    }
                }
            }
            RequestFamily::TextCompletions => {
                let prompt = json.get("prompt").ok_or(Malformed)?;
                measure_content(
                    prompt,
                    self.compress_prompt_field,
                    ContentShape::PromptStrings,
                    tags,
                    &mut estimate,
                )?;
            }
            RequestFamily::Responses => {
                let object = json.as_object().ok_or(Malformed)?;
                match object.get("instructions") {
                    None | Some(Value::Null) => {}
                    Some(Value::String(text)) => {
                        if self.instructions_eligible() {
                            account_text(text, tags, &mut estimate).ok_or(OverBudget)?;
                        }
                    }
                    Some(_) => return Err(Malformed),
                }
                match object.get("input") {
                    Some(Value::String(text)) => {
                        if self.compress_prompt_field {
                            account_text(text, tags, &mut estimate).ok_or(OverBudget)?;
                        }
                    }
                    Some(Value::Array(items)) => {
                        for item in items {
                            let item = item.as_object().ok_or(Malformed)?;
                            if !responses_item_is_message(item) {
                                continue;
                            }
                            let role = item.get("role").and_then(Value::as_str).ok_or(Malformed)?;
                            let content = item.get("content").ok_or(Malformed)?;
                            measure_content(
                                content,
                                self.role_is_eligible(role),
                                ContentShape::TypedParts(RESPONSES_TEXT_PARTS),
                                tags,
                                &mut estimate,
                            )?;
                        }
                    }
                    _ => return Err(Malformed),
                }
            }
        }
        Ok(estimate)
    }

    fn role_is_eligible(&self, role: &str) -> bool {
        self.compress_roles
            .iter()
            .any(|candidate| role.eq_ignore_ascii_case(candidate))
    }

    /// Keep auto-family admission tied to the client-visible operation even
    /// after a routing plugin rebases `ctx.path` for backend dispatch. The
    /// snapshot is typed private state, shared across every configured instance,
    /// and therefore neither attacker-spoofable nor proportional to instance
    /// count. Fixed families intentionally need no path classification.
    fn preserve_classification_path(&self, ctx: &mut RequestContext) {
        if self.request_family == RequestFamilyPolicy::Auto
            && ctx.ai_prompt_compressor_classification_path.is_none()
        {
            ctx.ai_prompt_compressor_classification_path = Some(ctx.path.clone());
        }
    }

    fn classification_path<'a>(&self, ctx: &'a RequestContext) -> Option<&'a str> {
        match self.request_family {
            RequestFamilyPolicy::Auto => Some(
                ctx.ai_prompt_compressor_classification_path
                    .as_deref()
                    .unwrap_or(ctx.path.as_str()),
            ),
            RequestFamilyPolicy::ChatCompletions
            | RequestFamilyPolicy::TextCompletions
            | RequestFamilyPolicy::Responses
            | RequestFamilyPolicy::AnthropicMessages => None,
        }
    }

    /// Whether this instance's preserve-marker guarantee covers the finalized
    /// request: a configured preserve tag, a JSON `POST`, and (in `auto`) a
    /// standard operation path. Decided from configuration and request state
    /// only — never by decoding the body — so it is also the representation
    /// claim.
    fn final_marker_policy_applies(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> bool {
        if self.preserve_tags.is_none() || ctx.method != "POST" {
            return false;
        }
        if !headers
            .get("content-type")
            .is_some_and(|content_type| is_json_content_type(content_type))
        {
            return false;
        }
        match self.request_family {
            RequestFamilyPolicy::Auto => self
                .classification_path(ctx)
                .and_then(standard_path_family)
                .is_some(),
            RequestFamilyPolicy::ChatCompletions
            | RequestFamilyPolicy::TextCompletions
            | RequestFamilyPolicy::Responses
            | RequestFamilyPolicy::AnthropicMessages => true,
        }
    }

    /// Verify that the exact final representation carries no configured marker
    /// in an admitted string value. Bounded like sanitation itself: the body
    /// ceiling and the non-waiting sanitation lane both fail closed.
    ///
    /// `decoded` is the representation gate's charged plaintext view of a
    /// content-coded body, and `body` the finalized bytes otherwise. The
    /// charged owner is MOVED into the worker (an `O(1)` share of the one
    /// charged allocation), so no uncharged duplicate of an amplified body is
    /// minted and the charge is held until the worker finishes, even if the
    /// awaiting request is dropped. Only an originally borrowed plaintext body
    /// is copied.
    async fn verify_final_markers(
        &self,
        decoded: Option<bytes::Bytes>,
        body: &[u8],
        request_path: Option<&str>,
    ) -> Result<(), MarkerSanitizationError> {
        if self.preserve_tags.is_none() {
            return Ok(());
        }
        let view: &[u8] = decoded.as_deref().unwrap_or(body);
        if view.len() > HARD_MAX_SCAN_BYTES {
            return Err(MarkerSanitizationError::BodyTooLarge);
        }
        // Every marker begins with `<`, which a JSON string can only spell as a
        // literal byte or a `\u003c` escape. Without either, no marker exists.
        if !may_contain_marker_start(view) {
            return Ok(());
        }
        let permit = Arc::clone(&MARKER_SANITIZATION_BUDGET)
            .try_acquire_owned()
            .map_err(|_| MarkerSanitizationError::WorkerUnavailable)?;
        let worker = self.clone();
        let body = match decoded {
            Some(charged) => charged,
            None => bytes::Bytes::copy_from_slice(body),
        };
        let request_path = request_path.map(str::to_owned);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            worker.verify_final_markers_blocking(&body, request_path.as_deref())
        })
        .await
        .map_err(|_| MarkerSanitizationError::WorkerUnavailable)?
    }

    fn verify_final_markers_blocking(
        &self,
        body: &[u8],
        request_path: Option<&str>,
    ) -> Result<(), MarkerSanitizationError> {
        let Some(tags) = self.preserve_tags.as_ref() else {
            return Ok(());
        };
        // Invalid JSON and unadmitted shapes are documented to retain their
        // bytes; only admitted families carry the marker guarantee.
        let Ok(json) = serde_json::from_slice::<Value>(body) else {
            return Ok(());
        };
        if self.classify_request(&json, request_path).is_none() {
            return Ok(());
        }
        // One removal pass changes the body exactly when some string value
        // (never a member name) still contains a configured marker.
        if strip_markers_from_json_strings_once(body, tags).is_some() {
            Err(MarkerSanitizationError::Unsanitizable)
        } else {
            Ok(())
        }
    }

    /// Walk the admitted request family, compressing eligible prompt text in
    /// place and accumulating token stats. `None` aborts the whole rewrite.
    /// Keep this walker structurally identical to `measure_work`, which has
    /// already validated every shape it visits.
    fn compress_json(
        &self,
        json: &mut Value,
        family: RequestFamily,
        ratio: f64,
    ) -> Option<CompressionStats> {
        let mut stats = CompressionStats::default();

        match family {
            RequestFamily::ChatCompletions | RequestFamily::AnthropicMessages => {
                let object = json.as_object_mut()?;
                if family == RequestFamily::AnthropicMessages
                    && self.role_is_eligible("system")
                    && let Some(system) = object.get_mut("system")
                {
                    self.compress_content(
                        system,
                        ContentShape::TypedParts(ANTHROPIC_TEXT_BLOCKS),
                        ratio,
                        &mut stats,
                    )
                    .ok()?;
                }
                let parts = ContentShape::TypedParts(family.message_text_parts());
                let messages = object.get_mut("messages")?.as_array_mut()?;
                for message in messages {
                    let message = message.as_object_mut()?;
                    let role_eligible = message
                        .get("role")
                        .and_then(Value::as_str)
                        .is_some_and(|role| self.role_is_eligible(role));
                    if role_eligible && let Some(content) = message.get_mut("content") {
                        self.compress_content(content, parts, ratio, &mut stats)
                            .ok()?;
                    }
                }
            }
            RequestFamily::TextCompletions if self.compress_prompt_field => {
                let prompt = json.get_mut("prompt")?;
                self.compress_content(prompt, ContentShape::PromptStrings, ratio, &mut stats)
                    .ok()?;
            }
            RequestFamily::TextCompletions => {}
            RequestFamily::Responses => {
                let object = json.as_object_mut()?;
                if self.instructions_eligible()
                    && let Some(Value::String(text)) = object.get_mut("instructions")
                {
                    self.compress_field(text, ratio, &mut stats).ok()?;
                }
                match object.get_mut("input")? {
                    Value::String(text) => {
                        if self.compress_prompt_field {
                            self.compress_field(text, ratio, &mut stats).ok()?;
                        }
                    }
                    Value::Array(items) => {
                        for item in items.iter_mut() {
                            let item = item.as_object_mut()?;
                            if !responses_item_is_message(item) {
                                continue;
                            }
                            let role_eligible = item
                                .get("role")
                                .and_then(Value::as_str)
                                .is_some_and(|role| self.role_is_eligible(role));
                            if role_eligible && let Some(content) = item.get_mut("content") {
                                self.compress_content(
                                    content,
                                    ContentShape::TypedParts(RESPONSES_TEXT_PARTS),
                                    ratio,
                                    &mut stats,
                                )
                                .ok()?;
                            }
                        }
                    }
                    _ => return None,
                }
            }
        }

        Some(stats)
    }

    /// Compress a prompt-bearing value: a string, `null`, an array of typed
    /// parts whose listed text kinds carry `text`, or (legacy `prompt`) an
    /// array of strings. Non-text parts are left untouched.
    fn compress_content(
        &self,
        content: &mut Value,
        shape: ContentShape,
        ratio: f64,
        stats: &mut CompressionStats,
    ) -> Result<(), ()> {
        match (content, shape) {
            (Value::String(text), _) => self.compress_field(text, ratio, stats)?,
            (Value::Array(parts), _) => {
                for part in parts.iter_mut() {
                    match (part, shape) {
                        (Value::Object(obj), ContentShape::TypedParts(text_types)) => {
                            // Keep this shape validation identical to
                            // `measure_content`: every typed part needs a
                            // string type, and text parts need a string payload.
                            let is_text = text_types
                                .contains(&obj.get("type").and_then(Value::as_str).ok_or(())?);
                            if is_text {
                                let Value::String(text) = obj.get_mut("text").ok_or(())? else {
                                    return Err(());
                                };
                                self.compress_field(text, ratio, stats)?;
                            }
                        }
                        // Plain string element (array-of-strings `prompt`).
                        // Typed-part arrays reject this shape during
                        // measurement, so keep the mutation walker identical.
                        (Value::String(text), ContentShape::PromptStrings) => {
                            self.compress_field(text, ratio, stats)?;
                        }
                        _ => return Err(()),
                    }
                }
            }
            (Value::Null, ContentShape::TypedParts(_)) => {}
            _ => return Err(()),
        }
        Ok(())
    }

    /// Compress one text field in place and fold its counters into `stats`.
    fn compress_field(
        &self,
        text: &mut String,
        ratio: f64,
        stats: &mut CompressionStats,
    ) -> Result<(), ()> {
        if let Some((compressed, orig, comp)) = self.compress_text(text, ratio)? {
            *text = compressed;
            stats.original_tokens += orig;
            stats.compressed_tokens += comp;
            stats.fields_compressed += 1;
        }
        Ok(())
    }

    /// Compress one text string. Returns `Some((compressed, original_tokens,
    /// compressed_tokens))` only when the content clears `min_content_tokens`
    /// and the result is a genuine token reduction; otherwise `None`.
    fn compress_text(&self, text: &str, ratio: f64) -> Result<Option<(String, usize, usize)>, ()> {
        let original_tokens = estimate_tokens(text);
        if original_tokens < self.min_content_tokens {
            // Too short to compress, but preserve-tag markers must still be
            // stripped — they are gateway-internal and never reach providers.
            return Ok(self.strip_markers_only(text, original_tokens));
        }
        let compressed = match &self.preserve_tags {
            Some(tags) => self.compress_with_preserve(text, tags, ratio)?,
            None => statistical_compress(text, ratio).ok_or(())?,
        };
        let compressed_tokens = estimate_tokens(&compressed);
        if compressed_tokens < original_tokens {
            Ok(Some((compressed, original_tokens, compressed_tokens)))
        } else {
            Ok(self.strip_markers_only(text, original_tokens))
        }
    }

    /// When `preserve_tag` is configured and the text contains markers but
    /// compression does not apply (too short, or no token reduction), the
    /// markers are still removed so they never leak upstream.
    fn strip_markers_only(
        &self,
        text: &str,
        original_tokens: usize,
    ) -> Option<(String, usize, usize)> {
        let (open, close) = self.preserve_tags.as_ref()?;
        if !text.contains(open.as_str()) && !text.contains(close.as_str()) {
            return None;
        }
        let out = strip_all_markers(text, open, close);
        let stripped_tokens = estimate_tokens(&out);
        Some((out, original_tokens, stripped_tokens))
    }

    /// Compress a string that may contain `preserve_tag` spans. Text outside the
    /// tags is compressed; the enclosed span is copied **verbatim** — its exact
    /// internal whitespace is retained, only the markers are stripped. A single
    /// separating space is inserted at a boundary only when needed to avoid
    /// gluing two adjacent non-whitespace characters.
    fn compress_with_preserve(
        &self,
        text: &str,
        tags: &(String, String),
        ratio: f64,
    ) -> Result<String, ()> {
        let (open, close) = tags;
        let mut out = String::with_capacity(text.len());
        let mut depth = 0usize;
        let mut cursor = 0usize;
        let mut segment_start = 0usize;
        let mut preserved_started = false;

        while let Some(relative) = text[cursor..].find('<') {
            let marker_start = cursor + relative;
            let (marker_len, opening) = if text[marker_start..].starts_with(open.as_str()) {
                (open.len(), true)
            } else if text[marker_start..].starts_with(close.as_str()) {
                (close.len(), false)
            } else {
                cursor = marker_start + 1;
                continue;
            };

            if opening {
                if depth == 0 {
                    let compressed =
                        statistical_compress(&text[segment_start..marker_start], ratio).ok_or(())?;
                    append_segment(&mut out, &compressed);
                    preserved_started = false;
                } else {
                    append_preserved_piece(
                        &mut out,
                        &text[segment_start..marker_start],
                        &mut preserved_started,
                    );
                }
                depth = depth.checked_add(1).ok_or(())?;
            } else if depth == 0 {
                let compressed =
                    statistical_compress(&text[segment_start..marker_start], ratio).ok_or(())?;
                append_segment(&mut out, &compressed);
            } else {
                append_preserved_piece(
                    &mut out,
                    &text[segment_start..marker_start],
                    &mut preserved_started,
                );
                depth -= 1;
            }

            cursor = marker_start + marker_len;
            segment_start = cursor;
        }

        if depth == 0 {
            let compressed = statistical_compress(&text[segment_start..], ratio).ok_or(())?;
            append_segment(&mut out, &compressed);
        } else {
            append_preserved_piece(&mut out, &text[segment_start..], &mut preserved_started);
        }

        Ok(out)
    }
}

/// Whether `object` carries a provider-native marker other than `allowed`.
fn has_conflicting_provider_marker(object: &Map<String, Value>, allowed: &[&str]) -> bool {
    PROVIDER_NATIVE_MARKERS
        .iter()
        .any(|field| !allowed.contains(field) && object.contains_key(*field))
}

fn request_shape(json: &Value) -> Option<RequestFamily> {
    let object = json.as_object()?;
    if has_conflicting_provider_marker(object, &[]) {
        return None;
    }

    match (object.get("messages"), object.get("prompt")) {
        (Some(messages), None) if messages.is_array() => Some(RequestFamily::ChatCompletions),
        (None, Some(_)) => Some(RequestFamily::TextCompletions),
        _ => None,
    }
}

/// OpenAI Responses: a string or array `input`, with no Chat/Text Completions
/// field and no other provider's marker.
fn responses_request_shape(json: &Value) -> bool {
    let Some(object) = json.as_object() else {
        return false;
    };
    matches!(
        object.get("input"),
        Some(Value::String(_) | Value::Array(_))
    ) && !object.contains_key("messages")
        && !object.contains_key("prompt")
        && !has_conflicting_provider_marker(object, RESPONSES_NATIVE_FIELDS)
}

/// Anthropic Messages: a `messages` array, optional top-level `system`, no
/// legacy `prompt`, and no other provider's marker.
fn anthropic_messages_request_shape(json: &Value) -> bool {
    let Some(object) = json.as_object() else {
        return false;
    };
    object.get("messages").is_some_and(Value::is_array)
        && !object.contains_key("prompt")
        && !has_conflicting_provider_marker(object, ANTHROPIC_NATIVE_FIELDS)
}

/// Whether a Responses `input` item is a message. Other item kinds
/// (`function_call`, `function_call_output`, `reasoning`, item references, …)
/// are never prompt text and stay untouched.
fn responses_item_is_message(item: &Map<String, Value>) -> bool {
    match item.get("type") {
        Some(Value::String(kind)) => kind == "message",
        Some(_) => false,
        None => item.contains_key("role"),
    }
}

fn standard_path_family(path: &str) -> Option<RequestFamily> {
    let path = path.split('?').next()?.trim_end_matches('/');
    if path.ends_with("/chat/completions") {
        Some(RequestFamily::ChatCompletions)
    } else if path.ends_with("/completions") {
        Some(RequestFamily::TextCompletions)
    } else {
        None
    }
}

fn measure_content(
    content: &Value,
    eligible: bool,
    shape: ContentShape,
    preserve_tags: Option<&(String, String)>,
    estimate: &mut WorkEstimate,
) -> Result<(), WorkRejection> {
    use WorkRejection::{Malformed, OverBudget};
    match (content, shape) {
        (Value::String(text), _) => {
            if eligible {
                account_text(text, preserve_tags, estimate).ok_or(OverBudget)?;
            }
        }
        (Value::Array(parts), _) => {
            for part in parts {
                match (part, shape) {
                    (Value::String(text), ContentShape::PromptStrings) => {
                        if eligible {
                            account_text(text, preserve_tags, estimate).ok_or(OverBudget)?;
                        }
                    }
                    (Value::Object(object), ContentShape::TypedParts(text_types)) => {
                        let part_type = object
                            .get("type")
                            .and_then(Value::as_str)
                            .ok_or(Malformed)?;
                        if text_types.contains(&part_type) {
                            let text = object
                                .get("text")
                                .and_then(Value::as_str)
                                .ok_or(Malformed)?;
                            if eligible {
                                account_text(text, preserve_tags, estimate).ok_or(OverBudget)?;
                            }
                        }
                    }
                    _ => return Err(Malformed),
                }
            }
        }
        (Value::Null, ContentShape::TypedParts(_)) => {}
        _ => return Err(Malformed),
    }
    Ok(())
}

fn account_text(
    text: &str,
    preserve_tags: Option<&(String, String)>,
    estimate: &mut WorkEstimate,
) -> Option<()> {
    estimate.target_fields = estimate.target_fields.checked_add(1)?;
    estimate.target_text_bytes = estimate.target_text_bytes.checked_add(text.len())?;
    if estimate.target_fields > MAX_TARGET_FIELDS
        || estimate.target_text_bytes > MAX_TARGET_TEXT_BYTES
    {
        return None;
    }
    if estimate.count_chars {
        estimate.eligible_chars = estimate.eligible_chars.checked_add(text.chars().count())?;
    }
    estimate.token_units = estimate
        .token_units
        .checked_add(count_token_units(text, MAX_TOKEN_UNITS)?)?;
    let remaining_tokens = MAX_TOKEN_UNITS.checked_sub(estimate.emitted_tokens)?;
    estimate.emitted_tokens = estimate
        .emitted_tokens
        .checked_add(count_emitted_tokens(text, remaining_tokens)?)?;
    if let Some(tags) = preserve_tags {
        let remaining = MAX_PRESERVE_MARKERS.checked_sub(estimate.preserve_markers)?;
        estimate.preserve_markers = estimate
            .preserve_markers
            .checked_add(count_preserve_markers(text, tags, remaining)?)?;
    }
    // Preserve markers can split what the whole-text lexer saw as one matched
    // backtick span. Bound the conservative sum so segment-local token vectors
    // cannot collectively exceed the advertised work ceiling even when each
    // individual counter remains below it.
    let segmented_tokens = estimate
        .token_units
        .checked_add(estimate.emitted_tokens)?
        .checked_add(estimate.preserve_markers)?;
    (estimate.token_units <= MAX_TOKEN_UNITS
        && segmented_tokens <= MAX_TOKEN_UNITS
        && estimate.preserve_markers <= MAX_PRESERVE_MARKERS)
        .then_some(())
}

fn count_preserve_markers(text: &str, tags: &(String, String), limit: usize) -> Option<usize> {
    let (open, close) = tags;
    let mut count = 0usize;
    let mut cursor = 0usize;
    while let Some(relative) = text[cursor..].find('<') {
        let marker_start = cursor + relative;
        let marker_len = if text[marker_start..].starts_with(open.as_str()) {
            open.len()
        } else if text[marker_start..].starts_with(close.as_str()) {
            close.len()
        } else {
            cursor = marker_start + 1;
            continue;
        };
        count = count.checked_add(1)?;
        if count > limit {
            return None;
        }
        cursor = marker_start + marker_len;
    }
    Some(count)
}

fn count_token_units(text: &str, limit: usize) -> Option<usize> {
    let mut units = 0usize;
    let mut in_unit = false;
    for byte in text.bytes() {
        if byte.is_ascii_whitespace() {
            in_unit = false;
        } else if !in_unit {
            units = units.checked_add(1)?;
            if units > limit {
                return None;
            }
            in_unit = true;
        }
    }
    Some(units)
}

fn count_emitted_tokens(text: &str, limit: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut count = 0usize;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            break;
        }

        let start = cursor;
        cursor = if bytes[start] == b'`' {
            scan_backtick_span(bytes, start)
        } else if starts_with_http_url(&text[start..]) {
            scan_to_whitespace(bytes, start)
        } else {
            scan_to_whitespace_or_backtick(bytes, start)
        };

        count = count.checked_add(1)?;
        if count > limit {
            return None;
        }
    }
    Some(count)
}

fn strip_all_markers(text: &str, open: &str, close: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    while let Some(relative) = text[cursor..].find('<') {
        let marker_start = cursor + relative;
        let marker_len = if text[marker_start..].starts_with(open) {
            open.len()
        } else if text[marker_start..].starts_with(close) {
            close.len()
        } else {
            out.push_str(&text[cursor..marker_start + 1]);
            cursor = marker_start + 1;
            continue;
        };
        out.push_str(&text[cursor..marker_start]);
        cursor = marker_start + marker_len;
    }
    out.push_str(&text[cursor..]);
    out
}

/// Remove configured markers from JSON string values without reserializing the
/// surrounding value. Object member names are deliberately left untouched. The
/// caller first validates and classifies the JSON,
/// so this lexical pass can preserve whitespace, duplicate members, numeric
/// spellings, and member order on sanitation-only fallbacks. Marker characters
/// are recognized through ordinary JSON escapes too (`\u003c`, `\/`, and mixed
/// literal/escaped spellings), matching the decoded strings a provider sees.
///
/// Removal is repeated until a pass changes nothing, because deleting one
/// marker can join its neighbours into a new one (`<ke<keep>ep>` becomes
/// `<keep>`). At most [`MAX_MARKER_SANITATION_PASSES`] linear passes run; a
/// marker still left after them is refused by the final residual check rather
/// than forwarded.
fn strip_markers_from_json_strings(body: &[u8], tags: &(String, String)) -> Option<Vec<u8>> {
    let mut current = strip_markers_from_json_strings_once(body, tags)?;
    for _ in 1..MAX_MARKER_SANITATION_PASSES {
        let Some(next) = strip_markers_from_json_strings_once(&current, tags) else {
            break;
        };
        current = next;
    }
    Some(current)
}

/// One linear representation-preserving removal pass. `Some` exactly when at
/// least one configured marker was removed from a string value.
fn strip_markers_from_json_strings_once(body: &[u8], tags: &(String, String)) -> Option<Vec<u8>> {
    // The zero-sized recorder is statically dispatched, so optimized runtime
    // builds retain no counters, allocations, atomics, or instrumentation
    // branches on the sanitation path.
    let mut ignore_work = |_: usize| {};
    strip_markers_from_json_strings_with_work(
        body,
        tags,
        |candidate| std::str::from_utf8(candidate).ok(),
        &mut ignore_work,
    )
}

/// Cheap linear pre-check: every configured marker starts with `<`, which a
/// JSON string can spell only as a literal byte or a `\u003c` escape.
fn may_contain_marker_start(body: &[u8]) -> bool {
    body.contains(&b'<')
        || body
            .windows(6)
            .any(|window| window.starts_with(b"\\u003") && window[5].eq_ignore_ascii_case(&b'c'))
}

// External tests reach this through the lib target's `_test_support` shim;
// the bin target recompiles this plugin module without that caller.
#[allow(dead_code)]
pub(crate) fn preserve_marker_sanitizer_work_for_test(
    body: &[u8],
    tags: &(String, String),
) -> Option<(Vec<u8>, usize, usize)> {
    let mut utf8_validation_bytes = 0usize;
    let mut scalar_scan_bytes = 0usize;
    let output = strip_markers_from_json_strings_with_work(
        body,
        tags,
        |candidate| {
            utf8_validation_bytes = utf8_validation_bytes.saturating_add(candidate.len());
            std::str::from_utf8(candidate).ok()
        },
        &mut |bytes| {
            scalar_scan_bytes = scalar_scan_bytes.saturating_add(bytes);
        },
    )?;
    Some((output, utf8_validation_bytes, scalar_scan_bytes))
}

fn strip_markers_from_json_strings_with_work<'a, V, W>(
    body: &'a [u8],
    tags: &(String, String),
    validate_utf8: V,
    work: &mut W,
) -> Option<Vec<u8>>
where
    V: FnOnce(&'a [u8]) -> Option<&'a str>,
    W: FnMut(usize),
{
    // Validate once before the lexical pass, then retain the validated `str`
    // type throughout the scanner. Scalar advancement below can use UTF-8
    // lead-byte widths without revalidating every remaining suffix. The body is
    // bounded by the caller, so this keeps the complete scan linear while
    // preserving the fail-closed behavior for invalid UTF-8.
    let body = validate_utf8(body)?;
    let bytes = body.as_bytes();

    let (open, close) = tags;
    let mut output = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    let mut in_string = false;
    let mut changed = false;

    while cursor < bytes.len() {
        if !in_string {
            let byte = bytes[cursor];
            output.push(byte);
            cursor += 1;
            if byte == b'"' {
                let string_start = cursor;
                let string_end = json_string_end(body, string_start, work)?;
                let mut next = string_end + 1;
                while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                    next += 1;
                }
                // Preserve object member names byte-for-byte. Preserve markers
                // are prompt annotations, never permission to manufacture a
                // backend-visible field name after request policy has run.
                if bytes.get(next) == Some(&b':') {
                    output.extend_from_slice(&bytes[string_start..=string_end]);
                    cursor = string_end + 1;
                } else {
                    in_string = true;
                }
            }
            continue;
        }

        if bytes[cursor] == b'"' {
            output.push(b'"');
            cursor += 1;
            in_string = false;
            continue;
        }

        let marker_end = match_json_string_ascii(body, cursor, open.as_bytes(), work);
        let marker_end =
            marker_end.or_else(|| match_json_string_ascii(body, cursor, close.as_bytes(), work));
        if let Some(end) = marker_end {
            cursor = end;
            changed = true;
            continue;
        }

        let end = json_string_scalar_end(body, cursor, work)?;
        output.extend_from_slice(&bytes[cursor..end]);
        cursor = end;
    }

    (changed && !in_string).then_some(output)
}

fn json_string_end<W: FnMut(usize)>(body: &str, mut cursor: usize, work: &mut W) -> Option<usize> {
    // Each call advances monotonically to one string boundary using the UTF-8
    // validation performed once at scanner entry, and the caller then advances
    // past that string. Value contents are scanned once more for marker matches
    // whose length is bounded by MAX_PRESERVE_TAG_NAME_BYTES plus fixed
    // delimiters, so the complete sanitation pass remains linear in the bounded
    // input size.
    let bytes = body.as_bytes();
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            return Some(cursor);
        }
        // Validate escapes while locating the boundary even though callers
        // already require a successfully parsed JSON representation. This
        // keeps the lexical helper fail-closed on malformed or truncated input
        // and prevents an invalid escape from being accepted as part of a key.
        let (_, end) = decode_json_string_ascii(body, cursor, work)?;
        cursor = end;
    }
    None
}

fn match_json_string_ascii<W: FnMut(usize)>(
    body: &str,
    start: usize,
    expected: &[u8],
    work: &mut W,
) -> Option<usize> {
    let mut cursor = start;
    for expected_byte in expected {
        let (decoded, end) = decode_json_string_ascii(body, cursor, work)?;
        if decoded != Some(*expected_byte) {
            return None;
        }
        cursor = end;
    }
    Some(cursor)
}

fn decode_json_string_ascii<W: FnMut(usize)>(
    body: &str,
    start: usize,
    work: &mut W,
) -> Option<(Option<u8>, usize)> {
    let bytes = body.as_bytes();
    let byte = *bytes.get(start)?;
    if byte != b'\\' {
        let end = json_string_scalar_end(body, start, work)?;
        return Some(((byte.is_ascii()).then_some(byte), end));
    }

    let escaped = *bytes.get(start + 1)?;
    let decoded = match escaped {
        b'"' => b'"',
        b'\\' => b'\\',
        b'/' => b'/',
        b'b' => 0x08,
        b'f' => 0x0c,
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        b'u' => {
            let digits = bytes.get(start + 2..start + 6)?;
            let scalar = digits.iter().try_fold(0u16, |value, byte| {
                value.checked_mul(16)?.checked_add(hex_digit(*byte)? as u16)
            })?;
            work(6);
            return Some((
                (scalar <= u8::MAX as u16).then_some(scalar as u8),
                start + 6,
            ));
        }
        _ => return None,
    };
    work(2);
    Some((Some(decoded), start + 2))
}

fn json_string_scalar_end<W: FnMut(usize)>(
    body: &str,
    start: usize,
    work: &mut W,
) -> Option<usize> {
    let bytes = body.as_bytes();
    let byte = *bytes.get(start)?;
    if byte == b'\\' {
        let end = match bytes.get(start + 1) {
            Some(b'u') if bytes.get(start + 2..start + 6).is_some() => Some(start + 6),
            Some(_) => Some(start + 2),
            None => None,
        }?;
        work(end.saturating_sub(start));
        return Some(end);
    }
    if byte < 0x20 || byte == b'"' {
        return None;
    }
    if byte.is_ascii() {
        work(1);
        return Some(start + 1);
    }

    // `strip_markers_from_json_strings` validates the complete body as UTF-8
    // once before reaching this helper. Reject continuation and out-of-range
    // lead bytes defensively, then advance in constant time without rescanning
    // the remaining suffix for every non-ASCII scalar.
    let width = match byte {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let end = start.checked_add(width)?;
    bytes.get(start..end)?;
    work(width);
    Some(end)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn append_preserved_piece(out: &mut String, piece: &str, started: &mut bool) {
    if piece.is_empty() {
        return;
    }
    if *started {
        out.push_str(piece);
    } else {
        append_segment(out, piece);
        *started = true;
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    fn new(capacity: usize, limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other(
                "ai_prompt_compressor JSON output exceeded its bound",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Plugin for AiPromptCompressor {
    fn name(&self) -> &str {
        "ai_prompt_compressor"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_PROMPT_COMPRESSOR
    }

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::BEFORE_PROXY
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        // JSON prompt bodies are an HTTP concern; native gRPC wire frames are
        // not compressed.
        super::HTTP_ONLY_PROTOCOLS
    }

    fn enforces_finalized_request_policy(&self) -> bool {
        true
    }

    /// Claim the finalized representation for a preserve-tag instance so the
    /// shared request representation gate decodes a content-coded body into
    /// the plaintext view the final hook verifies — or rejects it when it
    /// cannot. Without the claim an encoded body would carry configured
    /// markers to a provider that honours `Content-Encoding`. Decided from
    /// configuration and request state only, never by decoding `body`.
    fn enforces_final_request_body_policy(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> bool {
        self.final_marker_policy_applies(ctx, headers)
    }

    fn modifies_request_body(&self) -> bool {
        true
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        // `before_proxy` rewrites `ctx.metadata["request_body"]` so direct
        // dispatchers (ai_federation) forward the compressed prompt.
        true
    }

    fn request_body_buffer_limit(&self) -> Option<usize> {
        // Marker sanitation is fail-closed at the immutable body ceiling even
        // when the gateway-wide request limit is configured as unlimited.
        self.preserve_tags.is_some().then_some(HARD_MAX_SCAN_BYTES)
    }

    fn needs_final_request_body_context(&self) -> bool {
        // The context-aware transform owns method/path admission, staged-result
        // reuse, and final-wire statistics. Opt in even when no other active
        // body plugin needs a final-hook context.
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        ctx.method == "POST"
            && (self.request_family != RequestFamilyPolicy::Auto
                || standard_path_family(&ctx.path).is_some())
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|ct| is_json_content_type(ct))
            // A content-coded body is never compressed, but with a configured
            // preserve tag the final hook must still verify its decoded view,
            // so marker instances buffer it too.
            && (self.preserve_tags.is_some() || !has_non_identity_content_encoding(&ctx.headers))
            // Preserve-marker sanitation remains active above the operator's
            // statistical scan cap. Without a preserve tag, keep the existing
            // streaming/direct-backend fast path for declared oversized bodies.
            && (self.preserve_tags.is_some()
                || !content_length_exceeds(&ctx.headers, self.max_scan_bytes))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx.method != "POST" {
            return PluginResult::Continue;
        }
        self.preserve_classification_path(ctx);
        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");
        if !is_json_content_type(content_type) {
            return PluginResult::Continue;
        }
        // A transport-compressed body is opaque here (request-body decompression
        // runs later in the `compression` plugin's transform hook), so defer to
        // the wire-path `transform_request_body`, which sees decoded bytes.
        if has_non_identity_content_encoding(headers) {
            return PluginResult::Continue;
        }

        let sampled = self.sampled(ctx);
        if !ctx.metadata.contains_key("request_body") {
            // A declared oversized candidate deliberately bypasses buffering
            // without a preserve tag; record why it was not compressed.
            if self.preserve_tags.is_none()
                && content_length_exceeds(headers, self.max_scan_bytes)
                && (self.request_family != RequestFamilyPolicy::Auto
                    || self
                        .classification_path(ctx)
                        .and_then(standard_path_family)
                        .is_some())
            {
                record_skip_metadata(ctx, &self.metadata_keys, SkipReason::WorkLimit);
            }
            return PluginResult::Continue;
        }
        let Some(body) = ctx.metadata.get("request_body") else {
            return PluginResult::Continue;
        };
        if body.is_empty() {
            return PluginResult::Continue;
        }
        let source_len = body.len();

        let attempt = match self
            .compress_body(body.as_bytes(), self.classification_path(ctx), sampled)
            .await
        {
            Ok(attempt) => attempt,
            Err(error) => return marker_sanitization_reject(error),
        };
        let skipped = attempt.skipped;
        if let Some(reason) = skipped {
            record_skip_metadata(ctx, &self.metadata_keys, reason);
        }
        let Some(compression) = attempt.output else {
            return PluginResult::Continue;
        };

        match compression.body {
            Some(output) => {
                // Direct dispatchers consume the metadata representation and
                // can await a provider without ever running body transforms.
                // Retain a second representation only below a strict ceiling;
                // larger bodies are recomputed for normal wire dispatch under
                // the same work budget.
                let staged_output =
                    (output.len() <= MAX_STAGED_OUTPUT_BYTES).then(|| output.clone());
                let Ok(serialized) = String::from_utf8(output) else {
                    return PluginResult::Continue;
                };
                ctx.metadata.insert("request_body".to_string(), serialized);
                if let Some(output) = staged_output {
                    ctx.plugin_state_mut().ai_prompt_compressor_staged.insert(
                        self.instance_id,
                        StagedCompression {
                            source_len,
                            source_sha256: compression.source_sha256,
                            output: Some(output),
                            stats: compression.stats.clone(),
                            skipped,
                        },
                    );
                } else if let Some(state) = ctx.plugin_state_opt_mut() {
                    state.ai_prompt_compressor_staged.remove(&self.instance_id);
                }
            }
            None => {
                // Observe mode: the representation is unchanged, so only the
                // observed counters are staged for wire-path reuse.
                ctx.plugin_state_mut().ai_prompt_compressor_staged.insert(
                    self.instance_id,
                    StagedCompression {
                        source_len,
                        source_sha256: compression.source_sha256,
                        output: None,
                        stats: compression.stats.clone(),
                        skipped,
                    },
                );
            }
        }
        if let Some(stats) = compression.stats.as_ref() {
            record_stats_metadata(ctx, &self.metadata_keys, stats);
            debug!(
                original_tokens = stats.original_tokens,
                compressed_tokens = stats.compressed_tokens,
                fields = stats.fields_compressed,
                observe = self.observe,
                "ai_prompt_compressor: compressed request prompt"
            );
        }

        PluginResult::Continue
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // No `RequestContext` here. Require explicit method and path markers so
        // the transform cannot guess a request family. Production HTTP paths use
        // the context-aware variant below; this remains safe for compatibility
        // callers that provide the pseudo-headers. Without a request identity
        // there is no sampling decision, so every such request is sampled.
        if !request_headers
            .get(":method")
            .is_some_and(|method| method.eq_ignore_ascii_case("POST"))
        {
            return None;
        }
        match self
            .compress_wire_body(
                body,
                content_type,
                request_headers,
                request_headers.get(":path").map(String::as_str),
                true,
            )
            .await
        {
            Ok(attempt) => attempt.output.and_then(|compression| compression.body),
            // This compatibility API has no rejection channel. Production HTTP
            // paths use the context-aware transform and final hook (503); an
            // empty invalid provider request is the marker-safe fail-closed
            // result for a context-free caller.
            Err(_) => Some(Vec::new()),
        }
    }

    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // Only compress POST bodies, even when a retry or another body-buffering
        // plugin forced buffering that bypassed `should_buffer_request_body`.
        if ctx.method != "POST" {
            return None;
        }
        begin_wire_stats(ctx);
        clear_instance_stats(ctx, &self.metadata_keys);

        if content_type.is_some_and(is_json_content_type)
            && !has_non_identity_content_encoding(request_headers)
            && let Some(staged) = ctx
                .plugin_state_opt_mut()
                .and_then(|state| state.ai_prompt_compressor_staged.remove(&self.instance_id))
        {
            if body.len() == staged.source_len
                && self.body_digest(body).await == Some(staged.source_sha256)
            {
                if let Some(stats) = staged.stats.as_ref() {
                    record_stats_metadata(ctx, &self.metadata_keys, stats);
                }
                if let Some(reason) = staged.skipped {
                    record_skip_metadata(ctx, &self.metadata_keys, reason);
                }
                return staged.output;
            }
        } else if let Some(state) = ctx.plugin_state_opt_mut() {
            state.ai_prompt_compressor_staged.remove(&self.instance_id);
        }

        let sampled = self.sampled(ctx);
        let attempt = match self
            .compress_wire_body(
                body,
                content_type,
                request_headers,
                self.classification_path(ctx),
                sampled,
            )
            .await
        {
            Ok(attempt) => attempt,
            Err(error) => {
                ctx.ai_prompt_compressor_marker_reject_status =
                    Some(marker_sanitization_status(error));
                return None;
            }
        };
        if let Some(reason) = attempt.skipped {
            record_skip_metadata(ctx, &self.metadata_keys, reason);
        }
        let compression = attempt.output?;
        if let Some(stats) = compression.stats.as_ref() {
            record_stats_metadata(ctx, &self.metadata_keys, stats);
        }
        compression.body
    }

    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        let staged_status = ctx.ai_prompt_compressor_marker_reject_status.take();
        let status_code = match staged_status {
            Some(status_code) => status_code,
            None => {
                if !self.final_marker_policy_applies(ctx, headers) {
                    return PluginResult::Continue;
                }
                // Verify the exact final representation: a later transform
                // can write a marker after this plugin ran, and a content-coded
                // body is inspected through the gate's decoded view (which the
                // claim above guarantees exists or was already refused).
                let decoded = ctx.inspectable_final_request_body_owned();
                let result = if decoded.is_none() && has_non_identity_content_encoding(headers) {
                    Err(MarkerSanitizationError::Unsanitizable)
                } else {
                    self.verify_final_markers(decoded, body, self.classification_path(ctx))
                        .await
                };
                match result {
                    Ok(()) => return PluginResult::Continue,
                    Err(error) => marker_sanitization_status(error),
                }
            }
        };
        if let Some(state) = ctx.plugin_state_opt_mut() {
            state.ai_prompt_compressor_staged.clear();
        }
        marker_sanitization_reject_with_status(status_code)
    }
}

fn marker_sanitization_status(error: MarkerSanitizationError) -> u16 {
    match error {
        MarkerSanitizationError::BodyTooLarge => 413,
        MarkerSanitizationError::WorkerUnavailable => 503,
        MarkerSanitizationError::Unsanitizable => 400,
    }
}

fn marker_sanitization_reject(error: MarkerSanitizationError) -> PluginResult {
    marker_sanitization_reject_with_status(marker_sanitization_status(error))
}

/// Fixed, body-free rejection envelope for a marker-sanitation failure.
fn marker_sanitization_reject_with_status(status_code: u16) -> PluginResult {
    let body = match status_code {
        413 => r#"{"error":"Request body exceeds AI prompt marker sanitation limit"}"#,
        400 => {
            r#"{"error":"Request contains AI prompt preserve markers that could not be sanitized"}"#
        }
        _ => r#"{"error":"AI prompt marker sanitation unavailable"}"#,
    };
    PluginResult::Reject {
        status_code,
        body: body.to_string(),
        headers: HashMap::new(),
    }
}

/// Record small, log-safe compression counters on the request context so they
/// flow to transaction summaries. Per-instance keys prevent multiple configured
/// compressors from overwriting each other; the historical unsuffixed keys are
/// the sum across active instances and are replacement-safe on retries.
fn record_stats_metadata(
    ctx: &mut RequestContext,
    keys: &CompressionMetadataKeys,
    stats: &CompressionStats,
) {
    let values = [
        stats.original_tokens,
        stats.compressed_tokens,
        stats
            .original_tokens
            .saturating_sub(stats.compressed_tokens),
        stats.fields_compressed,
    ];
    for ((instance_key, aggregate_key), value) in
        keys.instance.iter().zip(keys.aggregate).zip(values)
    {
        let previous = metadata_usize(&ctx.metadata, instance_key);
        let aggregate = metadata_usize(&ctx.metadata, aggregate_key)
            .saturating_sub(previous)
            .saturating_add(value);
        ctx.metadata.insert(instance_key.clone(), value.to_string());
        ctx.metadata
            .insert(aggregate_key.to_string(), aggregate.to_string());
    }
}

fn begin_wire_stats(ctx: &mut RequestContext) {
    if ctx.ai_prompt_compressor_wire_stats_started {
        return;
    }
    ctx.metadata
        .retain(|key, _| !key.starts_with("ai_prompt_compressor."));
    ctx.ai_prompt_compressor_wire_stats_started = true;
}

fn clear_instance_stats(ctx: &mut RequestContext, keys: &CompressionMetadataKeys) {
    ctx.metadata.remove(&keys.skipped);
    for (instance_key, aggregate_key) in keys.instance.iter().zip(keys.aggregate) {
        let previous = metadata_usize(&ctx.metadata, instance_key);
        ctx.metadata.remove(instance_key);
        let aggregate = metadata_usize(&ctx.metadata, aggregate_key).saturating_sub(previous);
        if aggregate == 0 {
            ctx.metadata.remove(aggregate_key);
        } else {
            ctx.metadata
                .insert(aggregate_key.to_string(), aggregate.to_string());
        }
    }
}

/// Record why this instance skipped statistical compression (`saturated`,
/// `work_limit`, or `not_sampled`), so a silent loss of savings is visible.
fn record_skip_metadata(
    ctx: &mut RequestContext,
    keys: &CompressionMetadataKeys,
    reason: SkipReason,
) {
    ctx.metadata
        .insert(keys.skipped.clone(), reason.as_str().to_string());
}

fn metadata_usize<MS: std::hash::BuildHasher>(
    metadata: &HashMap<String, String, MS>,
    key: &str,
) -> usize {
    metadata
        .get(key)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
}

/// True when a declared `Content-Length` exceeds `cap`. A missing or
/// unparseable length returns `false` (buffer and let the byte gate decide).
fn content_length_exceeds(headers: &HashMap<String, String>, cap: usize) -> bool {
    headers
        .get("content-length")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .is_some_and(|len| len > cap as u64)
}

/// True when `content-encoding` marks the body as anything other than
/// `identity`. Allocation-free; tolerant of comma-separated encoding lists.
fn has_non_identity_content_encoding(headers: &HashMap<String, String>) -> bool {
    headers.get("content-encoding").is_some_and(|value| {
        value
            .split(',')
            .map(str::trim)
            .any(|token| !token.is_empty() && !token.eq_ignore_ascii_case("identity"))
    })
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    match config.get(field) {
        None => Ok(None),
        Some(Value::Null) => Err(format!("ai_prompt_compressor: `{field}` must not be null")),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("ai_prompt_compressor: `{field}` must be a string")),
    }
}

fn optional_string_vec(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    match config.get(field) {
        None => Ok(None),
        Some(Value::Null) => Err(format!("ai_prompt_compressor: `{field}` must not be null")),
        Some(value) => {
            let array = value
                .as_array()
                .ok_or_else(|| format!("ai_prompt_compressor: `{field}` must be an array"))?;
            let mut out = Vec::with_capacity(array.len());
            for entry in array {
                let text = entry.as_str().ok_or_else(|| {
                    format!("ai_prompt_compressor: `{field}` must contain only strings")
                })?;
                out.push(text.to_string());
            }
            Ok(Some(out))
        }
    }
}

fn optional_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    match config.get(field) {
        None => Ok(None),
        Some(Value::Null) => Err(format!("ai_prompt_compressor: `{field}` must not be null")),
        Some(value) => {
            // JSON Schema `integer` admits any mathematically integral number,
            // so `200` and `200.0` are the same value here too. Fractional,
            // negative, and non-finite spellings stay rejected.
            let number = match value.as_u64() {
                Some(number) => number,
                None => match value.as_f64() {
                    Some(float)
                        if float.is_finite()
                            && float.fract() == 0.0
                            && (0.0..=MAX_INTEGRAL_FLOAT).contains(&float) =>
                    {
                        float as u64
                    }
                    _ => {
                        return Err(format!(
                            "ai_prompt_compressor: `{field}` must be a non-negative integer"
                        ));
                    }
                },
            };
            usize::try_from(number).map(Some).map_err(|_| {
                format!("ai_prompt_compressor: `{field}` is too large for this platform")
            })
        }
    }
}

/// Estimate token count with the common ~4-characters-per-token heuristic for
/// English text. This is an approximation used for thresholds and reporting;
/// the plugin embeds no model tokenizer.
fn estimate_tokens(text: &str) -> usize {
    let chars = text.chars().count();
    if chars == 0 { 0 } else { chars.div_ceil(4) }
}

/// A tokenized unit of text.
struct Token<'a> {
    /// The exact source slice to emit when this token is kept.
    text: &'a str,
    /// Borrowed alphanumeric core (empty for `Verbatim` tokens). Keeping this
    /// borrowed avoids one lowercase heap allocation per request token.
    core: &'a str,
    /// `true` when this token is always kept (code, URL, number, identifier,
    /// pure punctuation, or a `preserve_tag` span).
    verbatim: bool,
    /// `true` when the whitespace immediately before this token contained a
    /// newline — used to keep paragraph breaks in the reconstructed text.
    leading_newline: bool,
}

#[derive(Clone, Copy)]
struct FoldedCore<'a>(&'a str);

impl PartialEq for FoldedCore<'_> {
    fn eq(&self, other: &Self) -> bool {
        folded_core_chars(self.0).eq(folded_core_chars(other.0))
    }
}

impl Eq for FoldedCore<'_> {}

impl Hash for FoldedCore<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for character in folded_core_chars(self.0) {
            character.hash(state);
        }
    }
}

fn folded_core_chars(text: &str) -> impl Iterator<Item = char> + '_ {
    text.chars().flat_map(char::to_lowercase).map(|character| {
        if matches!(character, '\u{2019}' | '\u{02bc}') {
            '\''
        } else {
            character
        }
    })
}

/// Append `seg` to `out`, inserting a single separating space only when needed
/// to avoid gluing two non-whitespace characters at the boundary. `seg`'s own
/// internal whitespace is preserved exactly, so this is safe for verbatim
/// `preserve_tag` spans.
fn append_segment(out: &mut String, seg: &str) {
    if seg.is_empty() {
        return;
    }
    if let (Some(last), Some(first)) = (out.chars().last(), seg.chars().next())
        && !last.is_whitespace()
        && !first.is_whitespace()
    {
        out.push(' ');
    }
    out.push_str(seg);
}

/// Compress a plain text chunk to roughly `ratio` of its word-tokens.
fn statistical_compress(text: &str, ratio: f64) -> Option<String> {
    let tokens = tokenize(text)?;
    if tokens.is_empty() {
        return Some(String::new());
    }

    // In-document frequency of each candidate word (rarer => more important).
    let mut freq: HashMap<FoldedCore<'_>, u32> = HashMap::new();
    for token in &tokens {
        if !token.verbatim {
            *freq.entry(FoldedCore(token.core)).or_insert(0) += 1;
        }
    }

    let word_count = tokens.iter().filter(|token| !token.verbatim).count();

    let mut keep = vec![false; tokens.len()];
    let mut scored: Vec<(usize, f32)> = Vec::with_capacity(word_count);
    let mut critical_count = 0usize;
    // A kept negation whose complement is dropped re-binds to the following
    // clause ("It is not urgent. Delete logs" => "not Delete logs"), so the
    // candidate word immediately after a negation (or a restrictive connective
    // such as `unless`/`only`) is critical too. Conditions, obligations,
    // quantifiers, and spelled-out numbers are kept on their own.
    let mut force_next = false;
    for (i, token) in tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| !token.verbatim)
    {
        let critical = critical_word(token.core);
        if critical != CriticalWord::Ordinary || force_next {
            keep[i] = true;
            critical_count += 1;
            force_next = critical == CriticalWord::KeptWithComplement;
            continue;
        }
        scored.push((i, word_score(token, &freq)));
    }

    // Every token is verbatim (all code/URLs/numbers/identifiers) — there is
    // nothing to score or drop. Return the original text so protected layouts
    // keep their exact whitespace.
    if word_count == 0 {
        return Some(text.to_string());
    }

    // Keep at least one word; criticals count toward the budget.
    let target_keep = ((ratio * word_count as f64).ceil() as usize).clamp(1, word_count);
    let remaining = target_keep.saturating_sub(critical_count);
    if remaining > 0 {
        // Linear-time partial selection avoids sorting every candidate. Ties
        // fall back to source order so the selected set stays deterministic.
        let compare = |a: &(usize, f32), b: &(usize, f32)| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.0.cmp(&b.0))
        };
        if remaining < scored.len() {
            scored.select_nth_unstable_by(remaining - 1, compare);
        }
        for &(i, _) in &scored[..remaining] {
            keep[i] = true;
        }
    }

    Some(reconstruct(&tokens, &keep))
}

/// Compute an importance score for a candidate word. Higher = more likely kept.
fn word_score(token: &Token<'_>, freq: &HashMap<FoldedCore<'_>, u32>) -> f32 {
    let mut score = if is_stopword(token.core) { 0.0 } else { 1.0 };
    // Longer words tend to carry more meaning (capped so one long word can't
    // dominate).
    let len = token.core.chars().count().min(12) as f32;
    score += len * 0.1;
    // Rarity: a word appearing once scores higher than a frequently repeated one.
    let count = freq.get(&FoldedCore(token.core)).copied().unwrap_or(1);
    score += 1.0 / count as f32;
    // Proper-noun / entity signal: an original-case leading capital.
    if token
        .text
        .trim_start_matches(|c: char| !c.is_alphanumeric())
        .chars()
        .next()
        .is_some_and(|c| c.is_uppercase())
    {
        score += 0.5;
    }
    score
}

/// Split `text` into [`Token`]s, marking code / URLs / numbers / identifiers /
/// punctuation as verbatim. Whitespace boundaries are ASCII-only, which is UTF-8
/// safe because multi-byte sequences never contain ASCII bytes.
fn tokenize(text: &str) -> Option<Vec<Token<'_>>> {
    let bytes = text.as_bytes();
    let capacity = count_emitted_tokens(text, MAX_TOKEN_UNITS)?;
    let mut tokens = Vec::with_capacity(capacity);
    let mut i = 0usize;
    while i < bytes.len() {
        // Skip the whitespace run preceding the next token.
        let mut had_newline = false;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            if bytes[i] == b'\n' {
                had_newline = true;
            }
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let start = i;
        let rest = &text[start..];

        // Inline/fenced code: match a closing backtick run of the exact opening
        // length. An unmatched run protects the remainder rather than exposing
        // code-like content to lossy prose scoring.
        if bytes[start] == b'`' {
            let end = scan_backtick_span(bytes, start);
            push_verbatim(&mut tokens, &text[start..end], had_newline)?;
            i = end;
            continue;
        }
        // URL: keep intact so paths/query strings are never mangled.
        if starts_with_http_url(rest) {
            let end = scan_to_whitespace(bytes, start);
            push_verbatim(&mut tokens, &text[start..end], had_newline)?;
            i = end;
            continue;
        }

        // Ordinary whitespace-delimited unit.
        let end = scan_to_whitespace_or_backtick(bytes, start);
        let unit = &text[start..end];
        i = end;

        let core: &str =
            unit.trim_matches(|c: char| !(c.is_alphanumeric() || c == '_' || c == '\''));
        // `contains_url` catches URLs wrapped in punctuation — Markdown
        // `(https://…)`, `<https://…>`, `[text](https://…)` — that the
        // leading-scheme fast path above misses; such a token stays verbatim so
        // links are never scored and dropped.
        // An uppercase negation or qualifier (`NOT`, `NEVER`, `DON'T`,
        // `UNLESS`) has acronym form, but it must stay a critical word so the
        // word after it is protected too; it is still always kept.
        if core.is_empty()
            || (is_protected_word(core) && critical_word(core) == CriticalWord::Ordinary)
            || contains_url(unit)
        {
            push_verbatim(&mut tokens, unit, had_newline)?;
        } else {
            push_token(
                &mut tokens,
                Token {
                    text: unit,
                    core,
                    verbatim: false,
                    leading_newline: had_newline,
                },
            )?;
        }
    }
    Some(tokens)
}

fn scan_backtick_span(bytes: &[u8], start: usize) -> usize {
    let opening_len = backtick_run_len(bytes, start);
    let mut cursor = start + opening_len;
    while cursor < bytes.len() {
        if bytes[cursor] != b'`' {
            cursor += 1;
            continue;
        }
        let run_len = backtick_run_len(bytes, cursor);
        if run_len == opening_len {
            return cursor + run_len;
        }
        cursor += run_len;
    }
    bytes.len()
}

fn backtick_run_len(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len() && bytes[end] == b'`' {
        end += 1;
    }
    end - start
}

fn scan_to_whitespace(bytes: &[u8], start: usize) -> usize {
    let mut j = start;
    while j < bytes.len() && !bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    j
}

fn scan_to_whitespace_or_backtick(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len() && !bytes[end].is_ascii_whitespace() && bytes[end] != b'`' {
        end += 1;
    }
    end
}

fn push_verbatim<'a>(
    tokens: &mut Vec<Token<'a>>,
    text: &'a str,
    leading_newline: bool,
) -> Option<()> {
    push_token(
        tokens,
        Token {
            text,
            core: "",
            verbatim: true,
            leading_newline,
        },
    )
}

fn push_token<'a>(tokens: &mut Vec<Token<'a>>, token: Token<'a>) -> Option<()> {
    if tokens.len() >= MAX_TOKEN_UNITS {
        return None;
    }
    tokens.push(token);
    Some(())
}

/// True when `s` embeds an `http(s)://` URL, including when it is wrapped in
/// punctuation such as `(https://…)` or `<https://…>`.
fn contains_url(s: &str) -> bool {
    s.as_bytes()
        .windows(b"http://".len())
        .any(|window| window.eq_ignore_ascii_case(b"http://"))
        || s.as_bytes()
            .windows(b"https://".len())
            .any(|window| window.eq_ignore_ascii_case(b"https://"))
}

fn starts_with_http_url(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes
        .get(..b"http://".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
        || bytes
            .get(..b"https://".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https://"))
}

/// A word whose form should never be split or dropped: contains a Unicode
/// number, is an acronym, or matches a common snake_case, lowerCamelCase,
/// PascalCase, or kebab-case identifier form.
fn is_protected_word(core: &str) -> bool {
    if core.contains('_') || core.chars().any(char::is_numeric) {
        return true;
    }
    if core.contains('-')
        && core
            .split('-')
            .all(|part| !part.is_empty() && part.chars().all(char::is_alphanumeric))
    {
        return true;
    }

    let mut letters = core.chars().filter(|c| c.is_alphabetic());
    let Some(first) = letters.next() else {
        return false;
    };
    let mut uppercase = usize::from(first.is_uppercase());
    let mut lowercase = usize::from(first.is_lowercase());
    let mut later_uppercase = false;
    for letter in letters {
        if letter.is_uppercase() {
            uppercase += 1;
            later_uppercase = true;
        }
        if letter.is_lowercase() {
            lowercase += 1;
        }
    }

    let acronym = uppercase >= 2 && lowercase == 0;
    let lower_camel = first.is_lowercase() && later_uppercase;
    let pascal_case = first.is_uppercase() && uppercase >= 2 && lowercase > 0;
    acronym || lower_camel || pascal_case
}

/// Rebuild text from the kept tokens, restoring single-space or newline breaks.
fn reconstruct(tokens: &[Token<'_>], keep: &[bool]) -> String {
    let mut out = String::new();
    let mut pending_newline = false;
    let mut first = true;
    for (i, token) in tokens.iter().enumerate() {
        if token.leading_newline {
            pending_newline = true;
        }
        let emit = token.verbatim || keep[i];
        if !emit {
            continue;
        }
        if !first {
            out.push(if pending_newline { '\n' } else { ' ' });
        }
        out.push_str(token.text);
        first = false;
        pending_newline = false;
    }
    out
}

/// Common English stop words — low base importance, dropped first.
fn is_stopword(word: &str) -> bool {
    const WORDS: &[&str] = &[
        "a", "an", "and", "are", "as", "at", "be", "been", "being", "but", "by", "can", "could",
        "did", "do", "does", "for", "from", "had", "has", "have", "he", "her", "here", "hers",
        "him", "his", "how", "i", "if", "in", "into", "is", "it", "its", "just", "may", "me",
        "might", "my", "of", "on", "or", "our", "out", "over", "own", "she", "should", "so",
        "some", "such", "than", "that", "the", "their", "them", "then", "there", "these", "they",
        "this", "those", "to", "too", "up", "very", "was", "we", "were", "what", "when", "where",
        "which", "while", "who", "will", "with", "would", "you", "your",
    ];
    WORDS
        .iter()
        .any(|candidate| word.eq_ignore_ascii_case(candidate))
}

/// Classify a candidate word as meaning-critical. Negations and restrictive
/// connectives also protect the word after them.
fn critical_word(word: &str) -> CriticalWord {
    if is_negation(word)
        || RESTRICTIVE_CONNECTIVES
            .iter()
            .any(|candidate| word.eq_ignore_ascii_case(candidate))
    {
        CriticalWord::KeptWithComplement
    } else if SCOPE_QUALIFIERS
        .iter()
        .any(|candidate| word.eq_ignore_ascii_case(candidate))
    {
        CriticalWord::Kept
    } else {
        CriticalWord::Ordinary
    }
}

/// Negations and their contractions — always kept to preserve meaning. The
/// `n't` suffix is matched case-insensitively with ASCII, right single
/// quotation mark, or modifier-letter apostrophes (`DON’T`, `won't`).
fn is_negation(word: &str) -> bool {
    let mut tail = word.chars().rev();
    if let (Some(t), Some(apostrophe), Some(n)) = (tail.next(), tail.next(), tail.next())
        && t.eq_ignore_ascii_case(&'t')
        && n.eq_ignore_ascii_case(&'n')
        && matches!(apostrophe, '\'' | '\u{2019}' | '\u{02bc}')
    {
        return true;
    }
    [
        "no", "not", "nor", "none", "never", "neither", "without", "cannot", "cant", "dont",
        "wont", "isnt", "arent",
    ]
    .iter()
    .any(|candidate| word.eq_ignore_ascii_case(candidate))
}
