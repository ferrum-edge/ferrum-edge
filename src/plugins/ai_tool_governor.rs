//! AI Tool Governor Plugin
//!
//! Deterministic allow/deny/approval policy for AI **tool / function calls** —
//! the concrete actions an agent asks a client runtime (or an upstream
//! agent/tool) to execute: file writes, ticket creation, deploys, DB queries,
//! code execution, account changes.
//!
//! This complements `ai_semantic_firewall` (which catches *intent* with
//! semantic policy) by enforcing deterministic policy on **tool names,
//! arguments, JSON Schema, regexes, caller identity, proxy, and model/provider
//! metadata**. It does not try to prove intent — every decision is a
//! deterministic function of the request/response bytes plus an optional
//! out-of-band approval webhook.
//!
//! Inspection surfaces (each independently toggled under `inspect`):
//! - **request tool definitions**: `tools[].function.name` / `functions[].name`
//!   the client exposes to the model (reject/dry-run disallowed tools).
//! - **buffered response tool calls**: `choices[].message.tool_calls[]` and the
//!   legacy `choices[].message.function_call` on non-streaming responses.
//! - **streaming response tool calls**: OpenAI SSE `choices[].delta.tool_calls`
//!   and legacy `choices[].delta.function_call` (the `functions` API's one
//!   implicit call per choice) deltas, accumulated across split frames;
//!   tool-call frames are HELD until
//!   the call is complete and policy/approval clears it, then released — or the
//!   stream is terminated with an SSE error event, never leaking the held call.
//!   Duplicate indexes in one frame or conflicting call ids for one slot are
//!   ungovernable (fail closed in enforce) on both live and buffered SSE paths.
//!   JSON null for a streamed `tool_calls[].id` is treated as omitted.
//! - **MCP `tools/call`** and **A2A JSON-RPC methods** (optional, off by
//!   default): direct JSON-RPC body parsing on the request path. Omitted MCP
//!   `params.arguments` normalize to `{}`; provider response argument omissions
//!   are not coerced.
//!
//! Actions per tool: `allow`, `deny`, `redact_args`, `require_approval`,
//! `dry_run`. In `mode: dry_run` the plugin evaluates and emits metadata but
//! never rejects. In `mode: enforce` it fails closed when a configured policy
//! or the approval endpoint cannot be evaluated, unless the approval
//! `fail_on_error` says `warn`/`allow`. Enforce mode also fails closed on
//! governed bodies it cannot inspect: `Content-Encoding`d, oversized
//! (> [`MAX_PARSE_BYTES`]), non-UTF-8, or unparseable JSON request bodies when
//! request inspection is on; oversized JSON response bodies; and streaming
//! holds past [`MAX_STREAM_HOLD_BYTES`].
//!
//! Request and response policy is evaluated in `before_proxy` / `on_response_body`
//! and then re-evaluated on the FINAL backend-/client-visible body in
//! `on_final_request_body` / `on_final_response_body`, because `request_transformer`
//! (3000) and `response_transformer` (4000) run body rules afterward. An unchanged
//! body (matched by hash) is not governed twice; a body a later transform rewrote
//! into a denied `tools/call`, a disallowed `tools[]` definition, or an injected
//! `choices[].message.tool_calls[]` is fail-closed before dispatch/delivery. When
//! a later transform (e.g. the `compression` plugin) encoded the final response,
//! the re-check decompresses the gateway's own `gzip`/`br` encoding FIRST and
//! applies the JSON-shape/content-type gates to the decoded bytes, so an
//! injected-then-compressed (and possibly `Content-Type`-relabeled) tool call
//! cannot slip through. Already-governed calls are skipped by a
//! correlation-aware identity (consumer/proxy/model/provider + name + args)
//! with multiset counts, so a transform that changes an approval-relevant
//! field or duplicates an approved call is re-evaluated while unchanged (and
//! this plugin's own redacted) calls are not re-approved. Redaction
//! is unavailable on these re-check paths (no request-body transform, and the
//! response redaction transform already ran), so a `redact_args` match there
//! fails closed instead of forwarding the secret. On a governed request,
//! ambiguously labeled 2xx responses (missing or non-JSON `Content-Type`,
//! except framed gRPC) stay buffered for inspection rather than being
//! released to the streaming path — deliberate FailClosed posture. A
//! `text/event-stream` label is released to the streaming path ONLY when
//! streaming inspection is enabled (a live SSE inspector will attach);
//! otherwise it stays buffered so buffered-SSE governance covers real SSE and
//! the JSON-shape fallback catches Chat Completions JSON a transform
//! relabeled as SSE. Buffered SSE bodies that carry a `Content-Encoding` are
//! DECODED first (the same gzip/br decode as the final re-check) so the
//! governed hash and extracted calls always reflect the plaintext frames; an
//! encoded governed 2xx that cannot be decoded for inspection (unsupported
//! encoding, corrupt bytes, or decoded output past the cap) fails closed in
//! enforce mode regardless of how its `Content-Type` was relabeled.
//!
//! Non-goals (MVP): it does not execute tools, manage MCP sessions, replace
//! `mcp_gateway`/A2A routing, or implement an approval UI. When composed with
//! `mcp_gateway` aggregate routing, policy keys remain the public namespaced
//! tool names: a gateway-authenticated public→upstream rewrite is remapped for
//! the final-body recheck only when the final wire name exactly matches that
//! trusted upstream alias; final arguments are still re-evaluated, and any
//! unrelated name change fails closed.

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use regex::Regex;
use serde_json::{Value, json};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, warn};
use url::Url;

use sha2::{Digest, Sha256};

use crate::util::json_dup_keys;
use crate::util::unknown_keys::reject_unknown_keys;

use super::utils::ai_providers::{detect_response_provider, detect_sse_provider};
use super::utils::body_transform::{is_event_stream_content_type, is_json_content_type};
use super::utils::json_escape::escape_json_string;
use super::utils::response_body::read_response_body_bounded;
use super::utils::sse::{encode_sse_error_event, is_sse_request};
use super::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, ResponseStreamAction,
    ResponseStreamInspector,
};

/// Accepted top-level configuration keys. Nested free-form maps (`tools` tool
/// names, `json_schema` contents) are intentionally open and are not listed
/// here — only the fixed-shape object that owns those maps is closed.
pub const AI_TOOL_GOVERNOR_CONFIG_KEYS: &[&str] = &[
    "enabled",
    "mode",
    "default_action",
    "inspect",
    "tools",
    "approval",
    "response",
    "observability",
];

/// Accepted `inspect` object keys.
pub const AI_TOOL_GOVERNOR_INSPECT_KEYS: &[&str] = &[
    "request_tool_definitions",
    "response_tool_calls",
    "streaming_response_tool_calls",
    "mcp_tool_calls",
    "a2a_methods",
];

/// Accepted per-tool policy object keys. Tool names themselves remain a
/// free-form map under `tools`.
pub const AI_TOOL_GOVERNOR_TOOL_POLICY_KEYS: &[&str] = &[
    "action",
    "risk",
    "max_arg_bytes",
    "required_args",
    "blocked_arg_patterns",
    "json_schema",
];

/// Accepted blocked-argument pattern entry keys.
pub const AI_TOOL_GOVERNOR_BLOCKED_PATTERN_KEYS: &[&str] = &["name", "regex"];

/// Accepted `approval` object keys.
pub const AI_TOOL_GOVERNOR_APPROVAL_KEYS: &[&str] = &[
    "endpoint_url",
    "timeout_ms",
    "cache_ttl_seconds",
    "fail_on_error",
    "include_arguments",
];

/// Accepted `response` object keys.
pub const AI_TOOL_GOVERNOR_RESPONSE_KEYS: &[&str] = &[
    "deny_status_code",
    "redaction_placeholder",
    "streaming_deny_event",
];

/// Accepted `observability` object keys.
pub const AI_TOOL_GOVERNOR_OBSERVABILITY_KEYS: &[&str] =
    &["emit_metadata", "hash_arguments", "max_argument_log_bytes"];

/// Default status for deterministic policy denials. Operational failures where
/// a governed body cannot be inspected remain `502 Bad Gateway`.
const DEFAULT_DENY_STATUS: u16 = 403;
const UNINSPECTABLE_STATUS: u16 = 502;
/// Default redaction placeholder template (`{name}` → matched-pattern name).
const DEFAULT_REDACTION_PLACEHOLDER: &str = "[REDACTED_TOOL_ARG:{name}]";
/// Default approval webhook timeout.
const DEFAULT_APPROVAL_TIMEOUT_MS: u64 = 1500;
/// Default approval cache TTL.
const DEFAULT_APPROVAL_CACHE_TTL_S: u64 = 300;
/// Approval responses contain only a decision and optional ID. Bound the
/// out-of-band response so a compromised service cannot exhaust gateway memory.
const MAX_APPROVAL_RESPONSE_BYTES: usize = 64 * 1024;
/// Maximum approval cache TTL. Larger values risk overflowing `Instant`
/// arithmetic on some platforms and keep stale approvals alive too long.
const MAX_APPROVAL_CACHE_TTL_S: u64 = 30 * 24 * 60 * 60;
/// Upper bound on a single approval webhook timeout. Without a ceiling,
/// `timeout_ms × call_count` can pin a proxy task for arbitrarily long.
const MAX_APPROVAL_TIMEOUT_MS: u64 = 30_000;
/// Hard ceiling on cumulative approval wait for one governed batch, including
/// sequential webhook calls. Client cancellation still drops the awaiting
/// future (and therefore the in-flight reqwest call) immediately.
const MAX_APPROVAL_BATCH_DEADLINE: Duration = Duration::from_secs(30);
/// Maximum concrete tool calls governed in one request, response, or SSE
/// batch. Attacker-selected unique argument sets cannot otherwise force an
/// unbounded approval fan-out within the 4 MiB parse window.
const MAX_GOVERNABLE_CALLS: usize = 64;
/// Maximum `blocked_arg_patterns` entries per tool. Each pattern runs
/// `replace_all` over the prior result during `redact_args`.
const MAX_BLOCKED_ARG_PATTERNS: usize = 32;
/// Maximum `response.redaction_placeholder` template length in UTF-8 bytes.
/// OpenAPI `maxLength: 256` counts Unicode scalar values; runtime admission is
/// intentionally stricter and counts encoded bytes.
const MAX_REDACTION_PLACEHOLDER_BYTES: usize = 256;
/// Maximum `blocked_arg_patterns[].name` length in UTF-8 bytes. Pattern names
/// are substituted into `redaction_placeholder` `{name}` and must stay bounded
/// independently of regex count/pattern constraints. OpenAPI `maxLength: 256`
/// counts Unicode characters; runtime admission counts UTF-8 bytes.
const MAX_BLOCKED_ARG_PATTERN_NAME_BYTES: usize = 256;
/// Upper bound on the body size this plugin will parse for tool calls, so an
/// oversized (already-buffered) body cannot spend unbounded CPU in serde. In
/// `enforce` mode a governed body past this limit is REJECTED (fail closed —
/// padding a request/response past the parse limit must not smuggle a governed
/// call past policy); in `dry_run` it is forwarded uninspected. The same cap
/// bounds redacted argument / response growth so zero-width patterns cannot
/// amplify past the inspectable window.
const MAX_PARSE_BYTES: usize = 4 * 1024 * 1024;

/// Fixed reason for a governed request body whose objects carry duplicate
/// member names (advisory `GHSA-c78j-5w9p-cpq6`). `serde_json` keeps the LAST
/// value while a first-key-wins backend acts on the first, so the tool name or
/// arguments this plugin evaluated need not be the ones the backend executes.
/// This plugin forwards the original bytes, so ambiguity is refused rather than
/// canonicalized.
const AMBIGUOUS_REQUEST_JSON: &str =
    "request body contains duplicate JSON object member names and cannot be governed unambiguously";
/// Response-side counterpart of [`AMBIGUOUS_REQUEST_JSON`].
const AMBIGUOUS_RESPONSE_JSON: &str = "response body contains duplicate JSON object member names and cannot be governed unambiguously";
/// A governed tool call whose `arguments` JSON STRING carries duplicate member
/// names. The enclosing document scan cannot see inside a JSON string, so the
/// string content gets its own screen and an ambiguous one makes the call
/// ungovernable — the same posture as a non-string `function.arguments`.
const AMBIGUOUS_TOOL_ARGUMENTS: &str =
    "tool call arguments contain duplicate JSON object member names and cannot be policy-checked";
/// Fixed-cardinality transaction-log label for duplicate-key ambiguity under
/// global `mode: dry_run`. Never echoes body, key, argument, tool, or
/// backend-controlled bytes; repeated ambiguous events reuse this same value.
const AMBIGUITY_OBSERVATION_REASON: &str = "ambiguous_json";
/// Metadata key for [`AMBIGUITY_OBSERVATION_REASON`]. Kept separate from
/// `decision` so dry-run can record the observation as `decision=dry_run`
/// without claiming enforcement via `decision=deny`.
const UNINSPECTABLE_REASON_KEY: &str = "ai_tool_governor.uninspectable_reason";
/// Upper bound on bytes the streaming inspector may retain (held tool-call
/// frames plus the partial-event carry buffer). A backend that streams
/// never-finishing tool-call deltas cannot grow gateway memory past this: on
/// overflow the stream is terminated in `enforce` mode (fail closed) or
/// released uninspected in `dry_run` (never disrupt traffic).
const MAX_STREAM_HOLD_BYTES: usize = MAX_PARSE_BYTES;
/// Upper bound on cached approval decisions. At capacity, expired entries are
/// purged; if the cache is still full of live decisions, new decisions are
/// simply not cached (costing an extra webhook call later, never memory).
const MAX_APPROVAL_CACHE_ENTRIES: usize = 4096;
/// Request-path metadata marker: this plugin detected `"stream": true` in the
/// request body (or could not rule it out for an uninspectable body), so the
/// response must stay on the reqwest dispatch path where the SSE stream
/// inspector is wired.
pub(crate) const STREAM_REQUESTED_KEY: &str = "ai_tool_governor.stream_requested";
pub(crate) const STREAM_MODEL_KEY: &str = "ai_tool_governor.stream_model";
// Internal correlation state (the governed-body hashes and the per-call
// identity multiset) lives on NON-SERIALIZED `RequestContext` fields
// (`ai_tool_governor_request_hashes` / `ai_tool_governor_response_hashes` /
// `ai_tool_governor_call_hashes` / `ai_tool_governor_redaction_memos`), NOT in
// `ctx.metadata`. The maps are keyed by a process-unique plugin-instance ID so
// multiple governors on one proxy never consume each other's dedup state. The
// `on_final_request_body` / `on_final_response_body` re-checks read them so an
// unchanged body is not governed twice (avoids duplicate approval webhooks)
// while a body a later `request_transformer` / `response_transformer` rewrote
// is re-evaluated against the same policy. They are DERIVED FROM RAW TOOL
// ARGUMENTS, so keeping them off `ctx.metadata` guarantees an operator who
// disabled `observability.hash_arguments` never gets an arg-derived hash
// leaked to transaction logs via a correlation marker (the identity hash is
// otherwise correlatable/dictionary-guessable). See `RequestContext` for the
// per-call identity/multiset semantics preserved by the accessors below.

/// Process-unique scope for private per-request dedup ledgers. Plugin instances
/// are immutable and shared through `Arc`, so one ID remains stable for the
/// lifetime of a cache snapshot; a rebuilt snapshot gets fresh IDs.
static NEXT_GOVERNOR_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Enforce,
    DryRun,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Enforce => "enforce",
            Mode::DryRun => "dry_run",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefaultAction {
    Allow,
    Deny,
    RequireApproval,
}

/// Per-tool action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolAction {
    Allow,
    Deny,
    RedactArgs,
    RequireApproval,
    DryRun,
}

/// Ordered risk band. Declaration order is the ordering (`Low < Critical`), so
/// `max` picks the most severe risk across a batch of tool calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "low" => Some(RiskLevel::Low),
            "medium" => Some(RiskLevel::Medium),
            "high" => Some(RiskLevel::High),
            "critical" => Some(RiskLevel::Critical),
            _ => None,
        }
    }
}

/// What to do when the approval endpoint cannot be evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailOnError {
    Reject,
    Warn,
    Allow,
}

// ---------------------------------------------------------------------------
// Config structs
// ---------------------------------------------------------------------------

/// Which surfaces to inspect. Each is independently toggled.
#[derive(Debug, Clone, Copy)]
struct InspectConfig {
    request_tool_definitions: bool,
    response_tool_calls: bool,
    streaming_response_tool_calls: bool,
    mcp_tool_calls: bool,
    a2a_methods: bool,
}

impl InspectConfig {
    fn any_request(self) -> bool {
        self.request_tool_definitions || self.mcp_tool_calls || self.a2a_methods
    }

    /// True when policy can reach a concrete call whose `require_approval`
    /// action is resolved through the approval webhook. Bare request tool
    /// definitions carry only a name and deliberately treat
    /// `require_approval` as blocked without calling the webhook.
    fn any_approval_capable_surface(self) -> bool {
        self.response_tool_calls
            || self.streaming_response_tool_calls
            || self.mcp_tool_calls
            || self.a2a_methods
    }

    /// True when a buffered (non-SSE) response body must be governed. This
    /// includes streaming inspection, because a `stream: true` request whose
    /// backend answers with a plain `application/json` Chat Completions body
    /// (an SSE fallback) is delivered on the buffered path, not the stream
    /// inspector, and must still be screened.
    fn any_buffered_response(self) -> bool {
        self.response_tool_calls || self.streaming_response_tool_calls
    }
}

/// A named blocked-argument regex.
#[derive(Debug)]
struct BlockedArgPattern {
    name: String,
    regex: Regex,
}

/// Deterministic policy for a single tool name (or namespaced name like
/// `github.create_pr`, or an MCP/A2A method name).
struct ToolPolicy {
    action: ToolAction,
    risk: RiskLevel,
    max_arg_bytes: Option<usize>,
    required_args: Vec<String>,
    blocked_arg_patterns: Vec<BlockedArgPattern>,
    json_schema: Option<jsonschema::Validator>,
}

/// Approval webhook configuration.
struct ApprovalConfig {
    endpoint_url: String,
    redacted_endpoint_url: String,
    hostname: String,
    timeout: Duration,
    cache_ttl: Duration,
    fail_on_error: FailOnError,
    include_arguments: bool,
}

/// Response-shaping configuration.
#[derive(Debug, Clone)]
struct ResponseConfig {
    deny_status_code: u16,
    redaction_placeholder: String,
    streaming_deny_event: bool,
}

/// Observability configuration.
#[derive(Debug, Clone, Copy)]
struct ObservabilityConfig {
    emit_metadata: bool,
    hash_arguments: bool,
    max_argument_log_bytes: usize,
}

// ---------------------------------------------------------------------------
// Engine (shared between buffered, request, and streaming paths)
// ---------------------------------------------------------------------------

/// The policy engine, shared behind an `Arc` so the streaming inspector (which
/// cannot borrow the request `ctx`) evaluates against exactly the same policy
/// as the buffered/request paths.
struct GovernorEngine {
    mode: Mode,
    default_action: DefaultAction,
    tools: HashMap<String, ToolPolicy>,
    approval: Option<ApprovalConfig>,
    response: ResponseConfig,
    observability: ObservabilityConfig,
    http_client: PluginHttpClient,
    /// Approval decisions keyed by SHA-256 of the canonical policy input
    /// (`consumer|proxy|model|provider|tool|raw_args` — every field the webhook
    /// receives that can change its decision), value is `(allowed, expiry)`.
    /// Bounded by [`MAX_APPROVAL_CACHE_ENTRIES`].
    approval_cache: DashMap<String, (bool, Instant)>,
    /// Serializes the approval-cache INSERT path (capacity check + eviction +
    /// insert) so concurrent approval resolutions cannot each observe
    /// `len() < MAX_APPROVAL_CACHE_ENTRIES` and race the map past the cap.
    /// Reads stay lock-free on the `DashMap`. A mutex is acceptable here: this
    /// guards the approval-webhook resolution path (an outbound HTTP call just
    /// completed), NOT the per-request proxy hot path, so the hot-path
    /// no-locks invariant does not apply.
    approval_cache_insert_lock: std::sync::Mutex<()>,
    /// Test-only monotonic offset applied to approval-batch deadline arithmetic.
    /// Production construction leaves this at zero so the ceiling stays exactly
    /// [`MAX_APPROVAL_BATCH_DEADLINE`]. Cache TTLs continue to use wall time.
    approval_clock_offset_ms: AtomicU64,
}

/// A concrete tool call to evaluate (name + arguments).
struct ToolCall {
    name: String,
    /// Raw arguments as received (the OpenAI `function.arguments` JSON *string*,
    /// or the stringified MCP/A2A `params`). Blocked-pattern and byte-size
    /// checks run on this.
    raw_args: String,
    /// The arguments parsed as JSON, if they parse. Required-arg and JSON Schema
    /// checks run on this.
    parsed_args: Option<Value>,
    /// The arguments arrived as a JSON STRING whose content parses but carries
    /// duplicate object member names. `parsed_args` then holds the last-wins
    /// collapse of a document a first-key-wins backend reads differently, so the
    /// call cannot be policy-checked (advisory `GHSA-c78j-5w9p-cpq6`). Treated
    /// exactly like a missing name or a non-string argument delta: fail closed
    /// in enforce mode, forward in dry-run.
    args_ambiguous: bool,
}

/// Deterministic per-call outcome, before any approval resolution.
enum PolicyOutcome {
    Allow,
    Deny(String),
    Redact(Vec<String>),
    RequireApproval,
    DryRun,
}

/// Outcome of a buffered `redact_args` body rewrite attempt.
enum RedactTransform {
    Unchanged,
    Changed,
    /// Redaction would exceed [`MAX_PARSE_BYTES`]; refuse to emit amplified
    /// bytes and force a fail-closed final re-check.
    AmplificationFailed,
}

/// Name-only policy outcome for a tool definition exposed to the model.
/// Approval cannot be resolved without concrete arguments, while a per-tool
/// dry-run remains observable without blocking the request.
enum DefinitionOutcome {
    Allow,
    DryRun(RiskLevel),
    Deny(RiskLevel),
}

/// Correlation metadata attached to approval requests and audit logs.
#[derive(Debug, Clone, Default)]
struct CorrelationMeta {
    request_id: String,
    consumer: Option<String>,
    proxy: Option<String>,
    model: Option<String>,
    provider: Option<String>,
}

/// Bundled inputs for one approval evaluation, keeping the resolve/call
/// signatures small.
struct ApprovalInput<'a> {
    corr: &'a CorrelationMeta,
    name: &'a str,
    raw_args: &'a str,
    arg_hash: &'a str,
    risk: RiskLevel,
    ns: &'a AtomicU64,
}

/// Per-call decision after resolution.
struct CallDecision {
    name: String,
    matched_policy: bool,
    risk: RiskLevel,
    label: &'static str,
    blocks: bool,
    /// Operational fail-closed rejection rather than a deterministic policy
    /// denial. These retain `502 Bad Gateway` semantics.
    fail_closed: bool,
    redact_patterns: Vec<String>,
    approval_id: Option<String>,
    arguments_hash: Option<String>,
    reason: Option<String>,
}

/// Aggregate decision across a batch of tool calls.
struct BatchDecision {
    per_call: Vec<CallDecision>,
    /// True when at least one call blocks *and* mode is enforce.
    enforce_blocks: bool,
    fail_closed: bool,
    overall_label: &'static str,
    max_risk: RiskLevel,
    deny_reason: Option<String>,
    /// Successful buffered `redact_args` rewrites computed during amplification
    /// preflight (keyed by [`redaction_memo_key`]). Aggregate value bytes are
    /// capped at [`MAX_PARSE_BYTES`] so the transform path can reuse them
    /// without retaining more than one inspectable window of hostile data.
    redaction_memos: HashMap<String, String>,
}

fn label_rank(label: &str) -> u8 {
    match label {
        "deny" => 6,
        "approval_denied" => 5,
        "require_approval" => 4,
        "approved" => 3,
        "dry_run" => 2,
        _ => 1, // allow / redact-forward
    }
}

/// Record the aggregate `ai_tool_governor.decision` metadata, keeping the
/// HIGHEST-severity label seen across every inspected surface of one request or
/// response. A single request JSON can carry several governable surfaces (a
/// `tools[]` definition, an MCP `tools/call`, an A2A method), each governed and
/// metadata-written in turn; in `dry_run` inspection CONTINUES past a blocking
/// surface so a later allowed surface would otherwise clobber an earlier
/// `deny` and under-report would-be-rejected requests in rollout logs. Ranking
/// by `label_rank` (mirroring the per-batch `overall_label` aggregation) makes a
/// recorded `deny`/`approval_denied` STICKY — an `allow` never downgrades it —
/// while a higher-severity label still upgrades a recorded `allow`. Enforce mode
/// is unaffected: it rejects at the first blocking surface, so no later write
/// runs to clobber the decision.
fn set_decision_metadata(m: &mut HashMap<String, String>, label: &str) {
    let keep_existing = m
        .get("ai_tool_governor.decision")
        .is_some_and(|existing| label_rank(existing) >= label_rank(label));
    if keep_existing {
        return;
    }
    m.insert("ai_tool_governor.decision".to_string(), label.to_string());
}

/// Keep comma-delimited decision metadata aligned with the highest-severity
/// decision. A higher-severity batch replaces values from a weaker decision,
/// while an equal-severity batch merges values so multiple inspected surfaces
/// or plugin instances cannot hide one another's findings.
fn set_ranked_csv_metadata(
    m: &mut HashMap<String, String>,
    key: &str,
    previous_rank: u8,
    batch_rank: u8,
    values: &[&str],
) {
    if batch_rank < previous_rank {
        return;
    }
    if batch_rank > previous_rank {
        if values.is_empty() {
            m.remove(key);
        } else {
            m.insert(key.to_string(), values.join(","));
        }
        return;
    }
    if values.is_empty() {
        return;
    }

    let existing = m.entry(key.to_string()).or_default();
    for value in values {
        if !existing.split(',').any(|existing| existing == *value) {
            if !existing.is_empty() {
                existing.push(',');
            }
            existing.push_str(value);
        }
    }
}

/// Keep risk aligned with the sticky decision while preserving the maximum
/// risk among batches at the SAME decision severity. A stronger decision
/// replaces a weaker decision's risk even when the weaker call happened to
/// carry a higher risk label; lower-severity later batches cannot downgrade or
/// overwrite the winning decision's risk.
fn set_ranked_risk_metadata(
    m: &mut HashMap<String, String>,
    previous_rank: u8,
    batch_rank: u8,
    risk: RiskLevel,
) {
    if batch_rank < previous_rank {
        return;
    }
    let risk = if batch_rank == previous_rank {
        m.get("ai_tool_governor.risk")
            .and_then(|value| RiskLevel::from_str(value))
            .map_or(risk, |existing| existing.max(risk))
    } else {
        risk
    };
    m.insert(
        "ai_tool_governor.risk".to_string(),
        risk.as_str().to_string(),
    );
}

impl GovernorEngine {
    /// Instant used for the whole-batch approval deadline. Production offset is
    /// zero; tests may advance it without sleeping the real 30s ceiling.
    fn approval_now(&self) -> Instant {
        let offset = Duration::from_millis(self.approval_clock_offset_ms.load(Ordering::Relaxed));
        Instant::now()
            .checked_add(offset)
            .unwrap_or_else(Instant::now)
    }

    /// Deterministic evaluation of one tool call. Returns the outcome, whether
    /// an explicit policy matched, and the call's risk.
    fn evaluate(
        &self,
        name: &str,
        raw_args: &str,
        parsed: Option<&Value>,
    ) -> (PolicyOutcome, bool, RiskLevel) {
        let Some(policy) = self.tools.get(name) else {
            let outcome = match self.default_action {
                DefaultAction::Allow => PolicyOutcome::Allow,
                DefaultAction::Deny => {
                    PolicyOutcome::Deny(format!("tool '{name}' is not in the allowlist"))
                }
                DefaultAction::RequireApproval => PolicyOutcome::RequireApproval,
            };
            return (outcome, false, RiskLevel::Low);
        };

        if policy.action == ToolAction::Deny {
            return (
                PolicyOutcome::Deny(format!("tool '{name}' is denied by policy")),
                true,
                policy.risk,
            );
        }

        // Per-tool dry-run forwards while only recording the observational
        // decision, so it must short-circuit BEFORE the enforcing argument
        // checks below — otherwise a dry-run tool with `max_arg_bytes` /
        // `required_args` / `json_schema` / `blocked_arg_patterns` would still
        // reject in enforce mode instead of letting operators observe safely.
        if policy.action == ToolAction::DryRun {
            return (PolicyOutcome::DryRun, true, policy.risk);
        }

        if let Some(max) = policy.max_arg_bytes
            && raw_args.len() > max
        {
            return (
                PolicyOutcome::Deny(format!(
                    "tool '{name}' arguments exceed max_arg_bytes ({} > {max})",
                    raw_args.len()
                )),
                true,
                policy.risk,
            );
        }

        if !policy.required_args.is_empty() {
            match parsed.and_then(Value::as_object) {
                Some(obj) => {
                    for req in &policy.required_args {
                        if !obj.contains_key(req) {
                            return (
                                PolicyOutcome::Deny(format!(
                                    "tool '{name}' missing required argument '{req}'"
                                )),
                                true,
                                policy.risk,
                            );
                        }
                    }
                }
                None => {
                    return (
                        PolicyOutcome::Deny(format!(
                            "tool '{name}' arguments are not a JSON object"
                        )),
                        true,
                        policy.risk,
                    );
                }
            }
        }

        if let Some(validator) = &policy.json_schema {
            let valid = matches!(parsed, Some(v) if validator.validate(v).is_ok());
            if !valid {
                return (
                    PolicyOutcome::Deny(format!(
                        "tool '{name}' arguments failed JSON Schema validation"
                    )),
                    true,
                    policy.risk,
                );
            }
        }

        let mut matched_patterns = Vec::new();
        for bp in &policy.blocked_arg_patterns {
            if bp.regex.is_match(raw_args) {
                matched_patterns.push(bp.name.clone());
            }
        }
        if !matched_patterns.is_empty() && policy.action != ToolAction::RedactArgs {
            return (
                PolicyOutcome::Deny(format!(
                    "tool '{name}' arguments matched blocked pattern(s): {}",
                    matched_patterns.join(", ")
                )),
                true,
                policy.risk,
            );
        }

        let outcome = match policy.action {
            ToolAction::Allow => PolicyOutcome::Allow,
            ToolAction::RedactArgs => PolicyOutcome::Redact(matched_patterns),
            ToolAction::RequireApproval => PolicyOutcome::RequireApproval,
            ToolAction::DryRun => PolicyOutcome::DryRun,
            ToolAction::Deny => unreachable!("deny handled above"),
        };
        (outcome, true, policy.risk)
    }

    /// Govern a tool *definition* (name only, no arguments).
    /// `require_approval` cannot be resolved for a bare definition because
    /// there are no concrete arguments to send to the approval webhook.
    fn definition_outcome(&self, name: &str) -> DefinitionOutcome {
        match self.tools.get(name) {
            Some(policy)
                if matches!(
                    policy.action,
                    ToolAction::Deny | ToolAction::RequireApproval
                ) =>
            {
                DefinitionOutcome::Deny(policy.risk)
            }
            Some(policy) if policy.action == ToolAction::DryRun => {
                DefinitionOutcome::DryRun(policy.risk)
            }
            Some(_) => DefinitionOutcome::Allow,
            None if matches!(
                self.default_action,
                DefaultAction::Deny | DefaultAction::RequireApproval
            ) =>
            {
                DefinitionOutcome::Deny(RiskLevel::Low)
            }
            None => DefinitionOutcome::Allow,
        }
    }

    /// Govern a batch of concrete tool calls. `redaction_unavailable` treats a
    /// matched `redact_args` pattern as a block (fail closed): on paths that
    /// cannot rewrite the arguments in place — mid-stream SSE deltas, the
    /// request body (no request-body transform), and the post-transform final
    /// response re-check — the safe behavior is to reject rather than forward an
    /// unredacted secret. Only a buffered response whose status permits the
    /// `transform_response_body` redaction hook passes `false`; range/delta
    /// representations preserve their bytes and therefore pass `true`.
    async fn govern_calls(
        &self,
        corr: &CorrelationMeta,
        calls: &[ToolCall],
        ns: &AtomicU64,
        redaction_unavailable: bool,
    ) -> BatchDecision {
        if calls.len() > MAX_GOVERNABLE_CALLS {
            // Fail closed before any approval fan-out: a 4 MiB body can encode
            // far more unique calls than a single request should resolve.
            let reason = format!(
                "tool call batch exceeds the governable call limit ({MAX_GOVERNABLE_CALLS})"
            );
            let per_call = calls
                .iter()
                .take(MAX_GOVERNABLE_CALLS.saturating_add(1))
                .map(|call| CallDecision {
                    name: call.name.clone(),
                    matched_policy: false,
                    risk: RiskLevel::High,
                    label: "deny",
                    blocks: true,
                    fail_closed: true,
                    redact_patterns: Vec::new(),
                    approval_id: None,
                    arguments_hash: self
                        .observability
                        .hash_arguments
                        .then(|| sha256_hex(&call.raw_args)),
                    reason: Some(reason.clone()),
                })
                .collect();
            return BatchDecision {
                per_call,
                enforce_blocks: self.mode == Mode::Enforce,
                fail_closed: true,
                overall_label: "deny",
                max_risk: RiskLevel::High,
                deny_reason: Some(reason),
                redaction_memos: HashMap::new(),
            };
        }

        let mut per_call = Vec::with_capacity(calls.len());
        // Evaluation can run JSON Schema validation and every configured
        // blocked-argument regex. Cache it for the deterministic-denial
        // pre-scan and the main loop instead of doing that work twice.
        let evaluations: Vec<_> = calls
            .iter()
            .map(|call| self.evaluate(&call.name, &call.raw_args, call.parsed_args.as_ref()))
            .collect();
        // Preflight every deterministic redaction once before resolving any
        // approval. Keep successful rewrites (aggregate-capped) so the
        // buffered transform reuses them instead of recomputing hostile
        // argument expansions. An earlier require_approval call must not fan
        // out when a later redaction already makes the batch unshippable.
        let mut redaction_memos = HashMap::new();
        let mut redacted_argument_bytes = 0usize;
        let mut redaction_amplification = vec![false; calls.len()];
        for (index, (call, (outcome, _, _))) in calls.iter().zip(evaluations.iter()).enumerate() {
            let PolicyOutcome::Redact(patterns) = outcome else {
                continue;
            };
            if redaction_unavailable || patterns.is_empty() {
                continue;
            }
            let Some(policy) = self.tools.get(&call.name) else {
                continue;
            };
            let Ok((redacted, changed)) = redact_arguments(
                &call.raw_args,
                &policy.blocked_arg_patterns,
                &self.response.redaction_placeholder,
            ) else {
                // The enforce-mode batch is already unshippable. Mark later
                // redactions unavailable and stop before hostile siblings can
                // each force another bounded-but-expensive expansion.
                redaction_amplification[index..].fill(true);
                break;
            };
            if !changed {
                continue;
            }
            let Some(next_total) = redacted_argument_bytes.checked_add(redacted.len()) else {
                redaction_amplification[index..].fill(true);
                break;
            };
            if next_total > MAX_PARSE_BYTES {
                redaction_amplification[index..].fill(true);
                break;
            }
            redacted_argument_bytes = next_total;
            redaction_memos.insert(redaction_memo_key(&call.name, &call.raw_args), redacted);
        }
        let mut skip_approvals = self.mode == Mode::Enforce
            && (evaluations.iter().any(|(outcome, _, _)| match outcome {
                PolicyOutcome::Deny(_) => true,
                PolicyOutcome::Redact(patterns) => redaction_unavailable && !patterns.is_empty(),
                _ => false,
            }) || redaction_amplification.iter().any(|failed| *failed));
        // Whole-batch approval deadline: sequential webhook waits cannot exceed
        // this ceiling even when every call misses the cache.
        let approval_deadline = self
            .approval_now()
            .checked_add(MAX_APPROVAL_BATCH_DEADLINE)
            .unwrap_or_else(|| self.approval_now());

        for ((call, (outcome, matched, risk)), amplification) in calls
            .iter()
            .zip(evaluations)
            .zip(redaction_amplification.iter().copied())
        {
            let arguments_hash = self
                .observability
                .hash_arguments
                .then(|| sha256_hex(&call.raw_args));

            let mut cd = CallDecision {
                name: call.name.clone(),
                matched_policy: matched,
                risk,
                label: "allow",
                blocks: false,
                fail_closed: false,
                redact_patterns: Vec::new(),
                approval_id: None,
                arguments_hash: arguments_hash.clone(),
                reason: None,
            };

            match outcome {
                PolicyOutcome::Allow => {}
                PolicyOutcome::DryRun => {
                    // Per-tool dry-run: forward, but record the observational label.
                    cd.label = "dry_run";
                }
                PolicyOutcome::Deny(reason) => {
                    cd.label = "deny";
                    cd.blocks = true;
                    cd.reason = Some(reason);
                }
                PolicyOutcome::Redact(patterns) => {
                    if redaction_unavailable && !patterns.is_empty() {
                        cd.label = "deny";
                        cd.blocks = true;
                        cd.fail_closed = true;
                        cd.reason = Some(format!(
                            "tool '{}' matched a redact_args policy on a path where arguments cannot be redacted in place (failing closed)",
                            call.name
                        ));
                    } else if !patterns.is_empty() {
                        if amplification {
                            cd.label = "deny";
                            cd.blocks = true;
                            cd.fail_closed = true;
                            cd.reason = Some(format!(
                                "tool '{}' redact_args output would exceed the inspectable size limit",
                                call.name
                            ));
                        } else {
                            cd.label = "allow";
                            cd.redact_patterns = patterns;
                        }
                    } else {
                        cd.label = "allow";
                    }
                }
                PolicyOutcome::RequireApproval => {
                    if skip_approvals {
                        cd.label = "require_approval";
                    } else {
                        self.resolve_require_approval(corr, call, ns, approval_deadline, &mut cd)
                            .await;
                        // Stop further webhook fan-out once enforce mode has a
                        // blocking decision; remaining calls keep an
                        // observational require_approval label.
                        if cd.blocks && self.mode == Mode::Enforce {
                            skip_approvals = true;
                        }
                    }
                }
            }

            // Raw arguments are logged only when the operator explicitly opts in
            // with a positive `max_argument_log_bytes`, and only for a blocked
            // call (audit trail). Default 0 keeps secrets out of logs entirely.
            if cd.blocks && self.observability.max_argument_log_bytes > 0 {
                debug!(
                    target: "ai_tool_governor",
                    tool = %call.name,
                    decision = cd.label,
                    "blocked tool call arguments excerpt: {}",
                    truncate_str(&call.raw_args, self.observability.max_argument_log_bytes)
                );
            }

            per_call.push(cd);
        }

        let enforce = self.mode == Mode::Enforce;
        let enforce_blocks = enforce && per_call.iter().any(|c| c.blocks);
        let fail_closed = per_call.iter().any(|c| c.blocks && c.fail_closed);
        let overall_label = per_call
            .iter()
            .map(|c| c.label)
            .max_by_key(|l| label_rank(l))
            .unwrap_or("allow");
        let max_risk = per_call
            .iter()
            .map(|c| c.risk)
            .max()
            .unwrap_or(RiskLevel::Low);
        let deny_reason = per_call
            .iter()
            .find(|c| c.blocks)
            .and_then(|c| c.reason.clone());
        // Drop preflight rewrites when the batch cannot ship them (deny) or
        // when dry-run will not run the transform: avoids retaining hostile
        // redacted argument bytes with no consumer.
        if self.mode == Mode::DryRun
            || enforce_blocks
            || redaction_amplification.iter().any(|failed| *failed)
        {
            redaction_memos.clear();
        }

        BatchDecision {
            per_call,
            enforce_blocks,
            fail_closed,
            overall_label,
            max_risk,
            deny_reason,
            redaction_memos,
        }
    }

    /// Resolve a `require_approval` outcome onto `cd`, honoring dry-run mode,
    /// the approval cache, the webhook, and `fail_on_error`.
    ///
    /// Risk and arguments hash are read from `cd` (already populated by the
    /// caller) so this helper stays under clippy's `too_many_arguments` limit.
    async fn resolve_require_approval(
        &self,
        corr: &CorrelationMeta,
        call: &ToolCall,
        ns: &AtomicU64,
        approval_deadline: Instant,
        cd: &mut CallDecision,
    ) {
        // Dry-run never calls the webhook (a rollout must have no side effects);
        // it records the observational "require_approval" label.
        if self.mode == Mode::DryRun {
            cd.label = "require_approval";
            return;
        }

        let Some(approval) = &self.approval else {
            // Config validation guarantees an endpoint when require_approval is
            // reachable; defensively fail closed.
            cd.label = "approval_denied";
            cd.blocks = true;
            cd.fail_closed = true;
            cd.reason = Some("approval endpoint not configured".to_string());
            return;
        };

        let remaining = approval_deadline.saturating_duration_since(self.approval_now());
        if remaining.is_zero() {
            cd.label = "approval_denied";
            cd.blocks = true;
            cd.fail_closed = true;
            cd.reason = Some("approval batch deadline exceeded".to_string());
            return;
        }

        // Copy fields needed for ApprovalInput before further &mut cd writes.
        let risk = cd.risk;
        let hash = cd
            .arguments_hash
            .clone()
            .unwrap_or_else(|| sha256_hex(&call.raw_args));
        let input = ApprovalInput {
            corr,
            name: &call.name,
            raw_args: &call.raw_args,
            arg_hash: &hash,
            risk,
            ns,
        };
        match self
            .resolve_approval(approval, &input, approval.timeout.min(remaining))
            .await
        {
            Ok((true, id)) => {
                cd.label = "approved";
                cd.approval_id = id;
            }
            Ok((false, id)) => {
                cd.label = "approval_denied";
                cd.blocks = true;
                cd.approval_id = id;
                cd.reason = Some("approval denied by endpoint".to_string());
            }
            Err(err) => match approval.fail_on_error {
                FailOnError::Reject => {
                    cd.label = "approval_denied";
                    cd.blocks = true;
                    cd.fail_closed = true;
                    cd.reason = Some(format!("approval endpoint error: {err}"));
                }
                FailOnError::Warn => {
                    warn!(
                        target: "ai_tool_governor",
                        tool = %call.name,
                        "approval endpoint error, failing open (warn): {err}"
                    );
                    cd.label = "approved";
                }
                FailOnError::Allow => {
                    cd.label = "approved";
                }
            },
        }
    }

    /// Check the approval cache, then the webhook. Caches the fresh decision for
    /// `cache_ttl`. Returns `(allowed, approval_id)`.
    ///
    /// `timeout` is the effective per-call wait (min of configured timeout and
    /// remaining batch deadline). Dropping this future — e.g. client cancel —
    /// cancels the in-flight reqwest call.
    async fn resolve_approval(
        &self,
        approval: &ApprovalConfig,
        input: &ApprovalInput<'_>,
        timeout: Duration,
    ) -> Result<(bool, Option<String>), String> {
        // Hash a JSON array rather than a delimiter-joined string: tool/method
        // names and A2A/MCP argument JSON are not restricted from containing the
        // delimiter, so a flat `a\u{1}b` join collides `(name="n", args="x\u{1}y")`
        // with `(name="n\u{1}x", args="y")`. serde escapes control characters
        // inside each element, so distinct inputs always serialize distinctly.
        // Provider is included because it is sent to the webhook and can change
        // its decision — an approval for one provider must never be reused for
        // another. `Value::to_string` is infallible, so no fallback key is needed.
        let cache_key = sha256_hex(
            &json!([
                // Serialize the Options directly so an absent field (`null`) and
                // an explicitly-empty one (`""`) hash distinctly — the webhook
                // omits absent fields and can decide differently for each, so a
                // cached decision must not be shared across the two.
                input.corr.consumer.as_deref(),
                input.corr.proxy.as_deref(),
                input.corr.model.as_deref(),
                input.corr.provider.as_deref(),
                input.name,
                input.raw_args,
            ])
            .to_string(),
        );

        if let Some(entry) = self.approval_cache.get(&cache_key) {
            let (allowed, expiry) = *entry.value();
            drop(entry);
            if expiry > Instant::now() {
                // Cached decision — no fresh approval id.
                return Ok((allowed, None));
            }
            // Expired: remove eagerly so stale keys do not accumulate.
            self.approval_cache.remove(&cache_key);
        }

        let (allowed, approval_id) = self.call_approval(approval, input, timeout).await?;

        if approval.cache_ttl > Duration::ZERO {
            // Serialize capacity check + eviction + insert behind a mutex:
            // check-then-insert on the bare DashMap is racy (N concurrent
            // resolutions can each observe `len() < MAX` and push the map past
            // the cap). This is the approval-webhook path — an outbound HTTP
            // call just completed — not the per-request proxy hot path, so a
            // mutex on the insert side is acceptable; cache READS above remain
            // lock-free. A poisoned lock (a panic while held) just falls
            // through to the same bounded insert logic.
            let _insert_guard = self
                .approval_cache_insert_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.approval_cache.len() >= MAX_APPROVAL_CACHE_ENTRIES {
                // At capacity: purge expired entries. Argument-varying clients
                // cannot grow this map for the process lifetime.
                let now = Instant::now();
                self.approval_cache.retain(|_, (_, expiry)| *expiry > now);
            }
            // Replacing an existing key never grows the map, so allow it even
            // at capacity; only NEW keys are capped.
            if (self.approval_cache.len() < MAX_APPROVAL_CACHE_ENTRIES
                || self.approval_cache.contains_key(&cache_key))
                && let Some(expiry) = Instant::now().checked_add(approval.cache_ttl)
            {
                self.approval_cache.insert(cache_key, (allowed, expiry));
            }
            // Still full of live decisions: skip caching (fail safe — only
            // costs an extra webhook call later) rather than grow unbounded.
        }
        Ok((allowed, approval_id))
    }

    /// POST the approval request and parse the decision.
    async fn call_approval(
        &self,
        approval: &ApprovalConfig,
        input: &ApprovalInput<'_>,
        timeout: Duration,
    ) -> Result<(bool, Option<String>), String> {
        let corr = input.corr;
        let mut body = json!({
            "request_id": corr.request_id,
            "tool_name": input.name,
            "arguments_hash": input.arg_hash,
            "risk": input.risk.as_str(),
        });
        if let Value::Object(map) = &mut body {
            if let Some(v) = &corr.consumer {
                map.insert("consumer".to_string(), json!(v));
            }
            if let Some(v) = &corr.proxy {
                map.insert("proxy".to_string(), json!(v));
            }
            if let Some(v) = &corr.model {
                map.insert("model".to_string(), json!(v));
            }
            if let Some(v) = &corr.provider {
                map.insert("provider".to_string(), json!(v));
            }
            // Raw arguments are sent only when explicitly opted in.
            if approval.include_arguments {
                map.insert("arguments".to_string(), json!(input.raw_args));
            }
        }

        let request = self
            .http_client
            .get()
            .post(&approval.endpoint_url)
            .timeout(timeout)
            .json(&body);

        let response = self
            .http_client
            .execute_redacted_tracked(
                request,
                "ai_tool_governor_approval",
                &approval.redacted_endpoint_url,
                input.ns,
            )
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !response.status().is_success() {
            return Err(format!("endpoint returned HTTP {}", response.status()));
        }

        let response_body = read_response_body_bounded(response, MAX_APPROVAL_RESPONSE_BYTES)
            .await
            .map_err(|e| format!("response read failed: {e}"))?;
        // The approval verdict is a security decision taken from this document,
        // so a duplicate `decision` / `allow` member makes it unusable rather
        // than resolved on `serde_json`'s last-wins collapse. Approval failures
        // are already fail-closed for the caller.
        if json_dup_keys::slice_ambiguity(&response_body).is_some() {
            return Err(
                "response contains duplicate JSON object member names and is ambiguous".to_string(),
            );
        }
        let value: Value = serde_json::from_slice(&response_body)
            .map_err(|e| format!("response parse failed: {e}"))?;

        let approval_id = value
            .get("approval_id")
            .or_else(|| value.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string);

        let allowed = if let Some(decision) = value.get("decision").and_then(Value::as_str) {
            decision.eq_ignore_ascii_case("allow")
                || decision.eq_ignore_ascii_case("allowed")
                || decision.eq_ignore_ascii_case("approved")
        } else if let Some(flag) = value
            .get("allow")
            .or_else(|| value.get("approved"))
            .and_then(Value::as_bool)
        {
            flag
        } else {
            return Err("response missing 'decision' / 'allow' field".to_string());
        };

        Ok((allowed, approval_id))
    }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct AiToolGovernor {
    instance_id: u64,
    enabled: bool,
    inspect: InspectConfig,
    engine: Arc<GovernorEngine>,
    /// True when any tool policy uses `redact_args` — enables the response body
    /// transform on the buffered path.
    needs_response_transform: bool,
    /// Cached copy of the redaction placeholder template for the transform path.
    redaction_placeholder: String,
    /// Inspector-completed observability batches waiting for the mutable
    /// response-stream terminal hook. Entries exist only for concrete streams
    /// that attached this plugin's inspector with metadata emission enabled.
    pending_stream_metadata: Arc<DashMap<u64, StreamMetadataSlot>>,
}

type StreamMetadataSlot = Arc<std::sync::Mutex<HashMap<String, String>>>;

impl AiToolGovernor {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let Some(config_object) = config.as_object() else {
            return Err("ai_tool_governor: config must be an object".to_string());
        };
        // Reject unknown keys before the enabled short-circuit so a disabled
        // draft cannot hide a misspelled enforcement field that becomes live
        // on the next reload that flips `enabled: true`.
        validate_config_keys(config_object)?;

        let instance_id =
            NEXT_GOVERNOR_INSTANCE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let approval_cache_shard_amount = http_client.pool_shard_amount();

        let enabled = optional_bool(config, "enabled")?.unwrap_or(true);
        if !enabled {
            let engine = GovernorEngine {
                mode: Mode::Enforce,
                default_action: DefaultAction::Allow,
                tools: HashMap::new(),
                approval: None,
                response: ResponseConfig {
                    deny_status_code: DEFAULT_DENY_STATUS,
                    redaction_placeholder: DEFAULT_REDACTION_PLACEHOLDER.to_string(),
                    streaming_deny_event: true,
                },
                observability: ObservabilityConfig {
                    emit_metadata: true,
                    hash_arguments: true,
                    max_argument_log_bytes: 0,
                },
                http_client,
                approval_cache: DashMap::with_shard_amount(approval_cache_shard_amount),
                approval_cache_insert_lock: std::sync::Mutex::new(()),
                approval_clock_offset_ms: AtomicU64::new(0),
            };
            return Ok(Self {
                instance_id,
                enabled: false,
                inspect: InspectConfig {
                    request_tool_definitions: false,
                    response_tool_calls: false,
                    streaming_response_tool_calls: false,
                    mcp_tool_calls: false,
                    a2a_methods: false,
                },
                engine: Arc::new(engine),
                needs_response_transform: false,
                redaction_placeholder: DEFAULT_REDACTION_PLACEHOLDER.to_string(),
                pending_stream_metadata: Arc::new(DashMap::with_shard_amount(
                    approval_cache_shard_amount,
                )),
            });
        }

        let mode = match optional_string(config, "mode")?.unwrap_or("enforce") {
            "enforce" => Mode::Enforce,
            "dry_run" => Mode::DryRun,
            other => {
                return Err(format!(
                    "ai_tool_governor: 'mode' must be one of 'enforce' or 'dry_run', got {other:?}"
                ));
            }
        };

        let default_action = match optional_string(config, "default_action")?.unwrap_or("deny") {
            "allow" => DefaultAction::Allow,
            "deny" => DefaultAction::Deny,
            "require_approval" => DefaultAction::RequireApproval,
            other => {
                return Err(format!(
                    "ai_tool_governor: 'default_action' must be one of 'allow', 'deny', or 'require_approval', got {other:?}"
                ));
            }
        };

        let inspect = parse_inspect(config)?;

        // Parse tool policies.
        let mut tools: HashMap<String, ToolPolicy> = HashMap::new();
        let mut any_require_approval = default_action == DefaultAction::RequireApproval;
        let mut needs_response_transform = false;
        if let Some(map) = optional_object(config, "tools")? {
            for (name, spec) in map {
                if name.is_empty() {
                    return Err("ai_tool_governor: tool names must not be empty".to_string());
                }
                // A2A request extraction uses the gateway's canonical method
                // names. Retain the raw key for ordinary AI/MCP tool calls, but
                // mirror a configured PascalCase A2A alias under its canonical
                // key so an explicit alias policy cannot become unreachable.
                // Reject ambiguous duplicate spellings rather than choosing a
                // policy based on JSON map iteration order.
                let canonical_a2a_alias = if inspect.a2a_methods {
                    super::a2a_gateway::canonical_a2a_method(name)
                } else {
                    None
                }
                .filter(|canonical| *canonical != name);
                if let Some(canonical) = canonical_a2a_alias
                    && (map.contains_key(canonical) || tools.contains_key(canonical))
                {
                    return Err(format!(
                        "ai_tool_governor: A2A tool policy alias {name:?} conflicts with canonical method {canonical:?}"
                    ));
                }
                let policy = parse_tool_policy(name, spec)?;
                if policy.action == ToolAction::RequireApproval {
                    any_require_approval = true;
                }
                if policy.action == ToolAction::RedactArgs {
                    needs_response_transform = true;
                }
                tools.insert(name.clone(), policy);
                if let Some(canonical) = canonical_a2a_alias {
                    tools.insert(canonical.to_string(), parse_tool_policy(name, spec)?);
                }
            }
        }

        // At least one inspection surface must be enabled.
        if !inspect.request_tool_definitions
            && !inspect.response_tool_calls
            && !inspect.streaming_response_tool_calls
            && !inspect.mcp_tool_calls
            && !inspect.a2a_methods
        {
            return Err(
                "ai_tool_governor: at least one 'inspect.*' surface must be enabled".to_string(),
            );
        }

        // A configuration that governs nothing is a no-op. `tools` may be empty
        // only when `default_action` itself governs (deny / require_approval).
        if tools.is_empty() && default_action == DefaultAction::Allow {
            return Err(
                "ai_tool_governor: no tool policies configured and default_action is 'allow' — plugin would have no effect"
                    .to_string(),
            );
        }

        // Approval endpoint is required only when a concrete-call inspection
        // surface can reach `require_approval`. Definition-only inspection
        // handles that action as a name-only block and never calls the webhook.
        let approval = parse_approval(config, http_client.backend_allow_ips())?;
        if mode == Mode::Enforce
            && any_require_approval
            && inspect.any_approval_capable_surface()
            && approval.is_none()
        {
            return Err(
                "ai_tool_governor: 'approval.endpoint_url' is required when any policy uses 'require_approval'"
                    .to_string(),
            );
        }

        let response = parse_response(config)?;
        let redaction_placeholder = response.redaction_placeholder.clone();
        let observability = parse_observability(config)?;

        let engine = GovernorEngine {
            mode,
            default_action,
            tools,
            approval,
            response,
            observability,
            http_client,
            approval_cache: DashMap::with_shard_amount(approval_cache_shard_amount),
            approval_cache_insert_lock: std::sync::Mutex::new(()),
            approval_clock_offset_ms: AtomicU64::new(0),
        };

        Ok(Self {
            instance_id,
            enabled,
            inspect,
            engine: Arc::new(engine),
            needs_response_transform,
            redaction_placeholder,
            pending_stream_metadata: Arc::new(DashMap::with_shard_amount(
                approval_cache_shard_amount,
            )),
        })
    }

    fn correlation(
        &self,
        ctx: &RequestContext,
        model: Option<String>,
        provider: Option<&str>,
    ) -> CorrelationMeta {
        let request_id = ctx
            .canonical_correlation_id()
            .or_else(|| {
                [super::REQUEST_ID_METADATA_KEY, "correlation_id"]
                    .into_iter()
                    .filter_map(|key| ctx.metadata.get(key).map(String::as_str))
                    .find(|value| !value.is_empty())
            })
            .unwrap_or_default();
        CorrelationMeta {
            request_id: request_id.to_string(),
            consumer: ctx.effective_identity().map(str::to_string),
            proxy: ctx
                .matched_proxy
                .as_ref()
                .map(|p| p.name.clone().unwrap_or_else(|| p.id.clone())),
            model,
            provider: provider.map(str::to_string),
        }
    }

    /// Resolve the serving provider for a buffered response. `ai_federation`
    /// normalizes provider-native responses to OpenAI shape while recording the
    /// real provider in metadata, so prefer that over body-shape detection —
    /// otherwise an Anthropic/Gemini response reports `openai` and a
    /// provider-specific approval decision (or cache entry) is made for the
    /// wrong provider. The unique configured provider name
    /// (`ai_federation_provider`, then `ai_stream_router.provider`) is
    /// preferred over `ai_provider` (the coarse provider type) so two
    /// providers of the same type do not share an approval decision.
    fn resolve_response_provider(&self, ctx: &RequestContext, json: &Value) -> Option<String> {
        federation_provider(ctx)
            .or_else(|| detect_response_provider(json).map(|p| p.as_str().to_string()))
    }

    /// Whether a buffered (non-SSE) JSON response body should be governed for
    /// this request. Explicit `response_tool_calls` always governs; a
    /// streaming-only config governs the JSON body ONLY when the request was
    /// itself streaming (the SSE fallback), so a normal non-streaming response
    /// is not inspected/rejected when buffered response inspection was disabled.
    fn governs_buffered_json(&self, ctx: &RequestContext) -> bool {
        self.inspect.response_tool_calls
            || (self.inspect.streaming_response_tool_calls && request_is_streaming(ctx))
    }

    fn response_hash<'a>(&self, ctx: &'a RequestContext) -> Option<&'a str> {
        ctx.ai_tool_governor_response_hashes
            .get(&self.instance_id)
            .map(String::as_str)
    }

    fn set_response_hash(&self, ctx: &mut RequestContext, hash: String) {
        ctx.ai_tool_governor_response_hashes
            .insert(self.instance_id, hash);
    }

    fn clear_response_hash(&self, ctx: &mut RequestContext) {
        ctx.ai_tool_governor_response_hashes
            .remove(&self.instance_id);
    }

    fn request_hash<'a>(&self, ctx: &'a RequestContext) -> Option<&'a str> {
        ctx.ai_tool_governor_request_hashes
            .get(&self.instance_id)
            .map(String::as_str)
    }

    fn set_request_hash(&self, ctx: &mut RequestContext, hash: String) {
        ctx.ai_tool_governor_request_hashes
            .insert(self.instance_id, hash);
    }

    /// Identity used by the post-transform response re-check. Approval-capable
    /// calls retain every approval-cache correlation field so a model/provider
    /// rewrite requires a fresh decision. `redact_args` is deterministic and
    /// does not consult those fields, so its already-redacted identity remains
    /// stable when a later transform changes only model/provider metadata.
    fn governed_call_identity_hash(&self, corr: &CorrelationMeta, call: &ToolCall) -> String {
        if self
            .engine
            .tools
            .get(&call.name)
            .is_some_and(|policy| policy.action == ToolAction::RedactArgs)
        {
            deterministic_call_identity_hash(call)
        } else {
            correlated_call_identity_hash(corr, call)
        }
    }

    /// Record governed response calls as a multiset for the final re-check.
    fn record_governed_calls(
        &self,
        ctx: &mut RequestContext,
        corr: &CorrelationMeta,
        calls: &[ToolCall],
    ) {
        let identities: Vec<String> = calls
            .iter()
            .map(|call| self.governed_call_identity_hash(corr, call))
            .collect();
        record_governed_identities(ctx, self.instance_id, &identities);
    }

    /// Request media types this instance can govern. MCP/A2A gateways accept
    /// JSON-RPC's registered-in-practice media type and absent Content-Type, so
    /// their policy surface must do the same or the gateway can consume a call
    /// before the governor ever sees it. An absent type is only a tentative
    /// buffering signal here; `before_proxy` additionally requires a
    /// JSON-shaped body before treating it as governed. Other request/streaming
    /// inspection remains scoped to ordinary JSON media types.
    fn governs_request_content_type(&self, content_type: Option<&str>) -> bool {
        let governs_json_rpc = self.inspect.mcp_tool_calls || self.inspect.a2a_methods;
        match content_type {
            Some(content_type) => {
                is_governable_json_request_content_type(content_type)
                    || (governs_json_rpc && is_json_rpc_content_type(content_type))
            }
            None => governs_json_rpc,
        }
    }

    /// Write aggregate decision metadata onto the request context.
    fn write_metadata(&self, ctx: &mut RequestContext, batch: &BatchDecision) {
        Self::write_metadata_into(&self.engine, &mut ctx.metadata, batch);
    }

    /// Shared buffered/streaming metadata formatter. Streaming inspectors write
    /// into an inspector-owned slot, then the terminal hook merges that slot
    /// into `ctx.metadata`; keeping the formatter shared prevents observability
    /// config or key-shape drift between the two paths.
    fn write_metadata_into(
        engine: &GovernorEngine,
        m: &mut HashMap<String, String>,
        batch: &BatchDecision,
    ) {
        let obs = engine.observability;
        if !obs.emit_metadata {
            return;
        }
        m.insert("ai_tool_governor.enabled".to_string(), "true".to_string());
        m.insert(
            "ai_tool_governor.mode".to_string(),
            engine.mode.as_str().to_string(),
        );
        // Sticky aggregate: an earlier surface's `deny` in one request/response
        // is never downgraded by this batch's `allow` (see `set_decision_metadata`).
        // Keep the tool-name list aligned with that highest-severity decision:
        // a later allowed MCP/A2A call must not replace the denied definition's
        // name and leave logs saying only `decision=deny` with an allowed tool.
        let previous_rank = m
            .get("ai_tool_governor.decision")
            .map(|value| label_rank(value))
            .unwrap_or(0);
        let batch_rank = label_rank(batch.overall_label);
        set_decision_metadata(m, batch.overall_label);

        let tool_names: Vec<&str> = batch.per_call.iter().map(|c| c.name.as_str()).collect();
        set_ranked_csv_metadata(
            m,
            "ai_tool_governor.tool_names",
            previous_rank,
            batch_rank,
            &tool_names,
        );

        set_ranked_risk_metadata(m, previous_rank, batch_rank, batch.max_risk);

        let policy_ids: Vec<&str> = batch
            .per_call
            .iter()
            .filter(|c| c.matched_policy)
            .map(|c| c.name.as_str())
            .collect();
        set_ranked_csv_metadata(
            m,
            "ai_tool_governor.policy_ids",
            previous_rank,
            batch_rank,
            &policy_ids,
        );

        let approval_ids: Vec<&str> = batch
            .per_call
            .iter()
            .filter_map(|c| c.approval_id.as_deref())
            .collect();
        set_ranked_csv_metadata(
            m,
            "ai_tool_governor.approval_id",
            previous_rank,
            batch_rank,
            &approval_ids,
        );

        let hashes: Vec<&str> = if obs.hash_arguments {
            batch
                .per_call
                .iter()
                .filter_map(|c| c.arguments_hash.as_deref())
                .collect()
        } else {
            Vec::new()
        };
        set_ranked_csv_metadata(
            m,
            "ai_tool_governor.arguments_hashes",
            previous_rank,
            batch_rank,
            &hashes,
        );

        let redacted: Vec<&str> = batch
            .per_call
            .iter()
            .filter(|c| !c.redact_patterns.is_empty())
            .map(|c| c.name.as_str())
            .collect();
        set_ranked_csv_metadata(
            m,
            "ai_tool_governor.redacted_tools",
            previous_rank,
            batch_rank,
            &redacted,
        );
    }

    fn write_uninspectable_metadata_into(
        engine: &GovernorEngine,
        metadata: &mut HashMap<String, String>,
    ) {
        if !engine.observability.emit_metadata {
            return;
        }
        metadata.insert("ai_tool_governor.enabled".to_string(), "true".to_string());
        metadata.insert(
            "ai_tool_governor.mode".to_string(),
            engine.mode.as_str().to_string(),
        );
        set_decision_metadata(metadata, "deny");
    }

    /// Dry-run observation for duplicate-key ambiguity: forward traffic, but
    /// positively record a sanitized fixed-cardinality finding. Uses
    /// `decision=dry_run` (never `deny`) so logs cannot claim the bytes were
    /// blocked, and reuses [`set_decision_metadata`] so a stronger earlier
    /// decision from another surface/instance is not erased.
    fn write_ambiguity_observation_into(
        engine: &GovernorEngine,
        metadata: &mut HashMap<String, String>,
    ) {
        // This label describes observation without enforcement and is valid
        // only for global dry-run mode. In particular, an enforce-mode plugin
        // configured for streaming-response inspection only may tentatively
        // scan an ambiguous request to choose a safe dispatch path, but that
        // request is outside its governance surface and must not be mislabeled
        // as a dry-run policy decision.
        if engine.mode != Mode::DryRun || !engine.observability.emit_metadata {
            return;
        }
        metadata.insert("ai_tool_governor.enabled".to_string(), "true".to_string());
        metadata.insert(
            "ai_tool_governor.mode".to_string(),
            engine.mode.as_str().to_string(),
        );
        set_decision_metadata(metadata, "dry_run");
        // Sticky single label: multiple ambiguous events must not grow
        // metadata cardinality or retain distinct reason strings.
        metadata
            .entry(UNINSPECTABLE_REASON_KEY.to_string())
            .or_insert_with(|| AMBIGUITY_OBSERVATION_REASON.to_string());
    }

    /// True when `reason` is one of the fixed duplicate-key ambiguity strings
    /// (not a generic uninspectable cause such as encoding or size).
    fn is_ambiguity_reason(reason: &str) -> bool {
        reason == AMBIGUOUS_REQUEST_JSON
            || reason == AMBIGUOUS_RESPONSE_JSON
            || reason == AMBIGUOUS_TOOL_ARGUMENTS
    }

    fn merge_stream_metadata(
        target: &mut HashMap<String, String>,
        source: &HashMap<String, String>,
    ) {
        let Some(label) = source.get("ai_tool_governor.decision") else {
            return;
        };
        if let Some(enabled) = source.get("ai_tool_governor.enabled") {
            target.insert("ai_tool_governor.enabled".to_string(), enabled.clone());
        }
        if let Some(mode) = source.get("ai_tool_governor.mode") {
            target.insert("ai_tool_governor.mode".to_string(), mode.clone());
        }
        // Preserve the fixed ambiguity observation even when a higher-rank
        // decision from another surface wins the sticky merge below.
        if let Some(reason) = source.get(UNINSPECTABLE_REASON_KEY) {
            target
                .entry(UNINSPECTABLE_REASON_KEY.to_string())
                .or_insert_with(|| reason.clone());
        }

        let previous_rank = target
            .get("ai_tool_governor.decision")
            .map(|value| label_rank(value))
            .unwrap_or(0);
        let batch_rank = label_rank(label);
        set_decision_metadata(target, label);
        for key in [
            "ai_tool_governor.tool_names",
            "ai_tool_governor.policy_ids",
            "ai_tool_governor.approval_id",
            "ai_tool_governor.arguments_hashes",
            "ai_tool_governor.redacted_tools",
        ] {
            let values: Vec<&str> = source
                .get(key)
                .map(|value| value.split(',').filter(|value| !value.is_empty()).collect())
                .unwrap_or_default();
            set_ranked_csv_metadata(target, key, previous_rank, batch_rank, &values);
        }
        if let Some(risk) = source
            .get("ai_tool_governor.risk")
            .and_then(|value| RiskLevel::from_str(value))
        {
            set_ranked_risk_metadata(target, previous_rank, batch_rank, risk);
        }
    }

    fn reject(&self, batch: &BatchDecision) -> PluginResult {
        let reason = batch
            .deny_reason
            .clone()
            .unwrap_or_else(|| "tool call blocked by policy".to_string());
        PluginResult::Reject {
            status_code: if batch.fail_closed {
                UNINSPECTABLE_STATUS
            } else {
                self.engine.response.deny_status_code
            },
            body: format!(
                r#"{{"error":"AI tool call blocked by ai_tool_governor policy","decision":"{}","detail":"{}"}}"#,
                batch.overall_label,
                escape_json_string(&reason),
            ),
            headers: HashMap::new(),
        }
    }

    /// Reject a request/response body this plugin is configured to govern but
    /// cannot inspect (encoded, oversized, non-UTF-8, or unparseable). Only
    /// called in `enforce` mode — forwarding an uninspectable governed body
    /// would let padding/encoding smuggle a denied call past policy.
    fn reject_uninspectable(
        &self,
        ctx: &mut RequestContext,
        surface: &str,
        reason: &str,
    ) -> PluginResult {
        Self::write_uninspectable_metadata_into(&self.engine, &mut ctx.metadata);
        PluginResult::Reject {
            status_code: UNINSPECTABLE_STATUS,
            body: format!(
                r#"{{"error":"ai_tool_governor: {} cannot be inspected","decision":"deny","detail":"{}"}}"#,
                escape_json_string(surface),
                escape_json_string(reason),
            ),
            headers: HashMap::new(),
        }
    }

    /// Fail closed when any governed request call's `arguments` arrived as a
    /// JSON string whose content carries duplicate object member names.
    ///
    /// The enclosing body screen cannot see inside a JSON string, so this is the
    /// request-side mirror of the ungovernable-call posture the response and
    /// streaming paths already apply: enforce rejects before the bytes reach the
    /// backend; dry-run forwards while recording a sanitized observation so
    /// audit mode never disrupts traffic and never claims enforcement.
    fn ambiguous_args_rejection(
        &self,
        ctx: &mut RequestContext,
        calls: &[ToolCall],
    ) -> Option<PluginResult> {
        if !calls.iter().any(|call| call.args_ambiguous) {
            return None;
        }
        if self.engine.mode == Mode::Enforce {
            return Some(self.reject_uninspectable(ctx, "request body", AMBIGUOUS_TOOL_ARGUMENTS));
        }
        Self::write_ambiguity_observation_into(&self.engine, &mut ctx.metadata);
        None
    }

    /// Governs a decoded request body's MCP/A2A tool calls and tool definitions.
    async fn govern_request(&self, ctx: &mut RequestContext, json: &Value) -> PluginResult {
        // JSON-RPC batch envelope (`[{"method":"tools/call",...}, ...]`): govern
        // every batched MCP/A2A call so batching cannot bypass the same policy
        // the backend will execute per entry.
        if let Some(entries) = json.as_array() {
            if !self.inspect.mcp_tool_calls && !self.inspect.a2a_methods {
                return PluginResult::Continue;
            }
            let mut calls = Vec::new();
            let mut malformed_mcp_call = false;
            for entry in entries {
                if self.inspect.mcp_tool_calls {
                    match extract_mcp_tool_call_for_policy(entry, ctx) {
                        McpToolCallExtraction::Call(call) => {
                            calls.push(call);
                            continue;
                        }
                        McpToolCallExtraction::Malformed => malformed_mcp_call = true,
                        McpToolCallExtraction::Absent => {}
                    }
                }
                if self.inspect.a2a_methods
                    && let Some(call) = extract_a2a_method(entry)
                {
                    calls.push(call);
                }
            }
            if malformed_mcp_call && self.engine.mode == Mode::Enforce {
                return self.reject_uninspectable(
                    ctx,
                    "request body",
                    "request contains an MCP tools/call whose name cannot be policy-checked",
                );
            }
            if calls.is_empty() {
                return PluginResult::Continue;
            }
            if let Some(rejection) = self.ambiguous_args_rejection(ctx, &calls) {
                return rejection;
            }
            let corr = self.correlation(ctx, None, None);
            // Request path: no `transform_request_body` hook exists to rewrite
            // arguments, so a `redact_args` match fails closed instead of
            // forwarding the secret to the backend.
            let batch = self
                .engine
                .govern_calls(&corr, &calls, &ctx.plugin_http_call_ns, true)
                .await;
            self.write_metadata(ctx, &batch);
            if batch.enforce_blocks {
                return self.reject(&batch);
            }
            return PluginResult::Continue;
        }

        let corr = self.correlation(ctx, request_model(json), None);

        // 1. Client tool definitions exposed to the model.
        if self.inspect.request_tool_definitions {
            let mut denied = Vec::new();
            let mut dry_run = Vec::new();
            for name in extract_request_tool_definitions(json) {
                match self.engine.definition_outcome(&name) {
                    DefinitionOutcome::Deny(risk) => denied.push((name, risk)),
                    DefinitionOutcome::DryRun(risk) => dry_run.push((name, risk)),
                    DefinitionOutcome::Allow => {}
                }
            }
            if !denied.is_empty() {
                self.write_definition_metadata(ctx, "deny", &denied);
                if self.engine.mode == Mode::Enforce {
                    return PluginResult::Reject {
                        status_code: self.engine.response.deny_status_code,
                        body: format!(
                            r#"{{"error":"ai_tool_governor: request exposes disallowed tool definitions","decision":"deny","tools":[{}]}}"#,
                            denied
                                .iter()
                                .map(|(name, _)| format!("\"{}\"", escape_json_string(name)))
                                .collect::<Vec<_>>()
                                .join(","),
                        ),
                        headers: HashMap::new(),
                    };
                }
            } else if !dry_run.is_empty() {
                self.write_definition_metadata(ctx, "dry_run", &dry_run);
            }
        }

        // 2. MCP tools/call (direct JSON-RPC body parsing).
        if self.inspect.mcp_tool_calls {
            match extract_mcp_tool_call_for_policy(json, ctx) {
                McpToolCallExtraction::Call(call) => {
                    if let Some(rejection) =
                        self.ambiguous_args_rejection(ctx, std::slice::from_ref(&call))
                    {
                        return rejection;
                    }
                    let batch = self
                        .engine
                        .govern_calls(&corr, &[call], &ctx.plugin_http_call_ns, true)
                        .await;
                    self.write_metadata(ctx, &batch);
                    if batch.enforce_blocks {
                        return self.reject(&batch);
                    }
                }
                McpToolCallExtraction::Malformed if self.engine.mode == Mode::Enforce => {
                    return self.reject_uninspectable(
                        ctx,
                        "request body",
                        "request contains an MCP tools/call whose name cannot be policy-checked",
                    );
                }
                McpToolCallExtraction::Malformed | McpToolCallExtraction::Absent => {}
            }
        }

        // 3. A2A JSON-RPC method policy.
        if self.inspect.a2a_methods
            && let Some(call) = extract_a2a_method(json)
        {
            if let Some(rejection) = self.ambiguous_args_rejection(ctx, std::slice::from_ref(&call))
            {
                return rejection;
            }
            let batch = self
                .engine
                .govern_calls(&corr, &[call], &ctx.plugin_http_call_ns, true)
                .await;
            self.write_metadata(ctx, &batch);
            if batch.enforce_blocks {
                return self.reject(&batch);
            }
        }

        PluginResult::Continue
    }

    fn write_definition_metadata(
        &self,
        ctx: &mut RequestContext,
        label: &'static str,
        definitions: &[(String, RiskLevel)],
    ) {
        if !self.engine.observability.emit_metadata {
            return;
        }
        let m = &mut ctx.metadata;
        m.insert("ai_tool_governor.enabled".to_string(), "true".to_string());
        m.insert(
            "ai_tool_governor.mode".to_string(),
            self.engine.mode.as_str().to_string(),
        );
        let previous_rank = m
            .get("ai_tool_governor.decision")
            .map(|value| label_rank(value))
            .unwrap_or(0);
        let decision_rank = label_rank(label);
        set_decision_metadata(m, label);
        let definition_names: Vec<&str> =
            definitions.iter().map(|(name, _)| name.as_str()).collect();
        set_ranked_csv_metadata(
            m,
            "ai_tool_governor.tool_names",
            previous_rank,
            decision_rank,
            &definition_names,
        );
        let max_risk = definitions
            .iter()
            .map(|(_, risk)| *risk)
            .max()
            .unwrap_or(RiskLevel::Low);
        set_ranked_risk_metadata(m, previous_rank, decision_rank, max_risk);

        // A definition decision has no concrete-call correlation metadata. If
        // it upgrades an earlier weaker decision, clear every decision-aligned
        // field from that weaker call; at equal severity, the ranked helper
        // preserves metadata emitted by sibling surfaces.
        for key in [
            "ai_tool_governor.policy_ids",
            "ai_tool_governor.approval_id",
            "ai_tool_governor.arguments_hashes",
            "ai_tool_governor.redacted_tools",
        ] {
            set_ranked_csv_metadata(m, key, previous_rank, decision_rank, &[]);
        }
    }

    /// Redact `redact_args` matches in a buffered response body. Deterministic
    /// (no approval), so it runs standalone on the transform path.
    ///
    /// `redaction_memos` carries successful rewrites already computed during
    /// governance preflight (aggregate-capped at [`MAX_PARSE_BYTES`]). Hits
    /// reuse that exact string; misses fall back to a fresh `redact_arguments`
    /// for shapes that were not preflighted.
    fn redact_response(
        &self,
        json: &mut Value,
        redaction_memos: Option<&HashMap<String, String>>,
    ) -> RedactTransform {
        let mut modified = false;
        // Cap the aggregate owned strings installed into the parsed response.
        // Per-call bounds alone would still allow 64 individually valid
        // redactions to retain hundreds of MiB before serialization.
        let mut redacted_argument_bytes = 0usize;
        let Some(choices) = json.get_mut("choices").and_then(Value::as_array_mut) else {
            return RedactTransform::Unchanged;
        };
        for choice in choices.iter_mut() {
            let Some(message) = choice.get_mut("message") else {
                continue;
            };
            if let Some(tool_calls) = message.get_mut("tool_calls").and_then(Value::as_array_mut) {
                for tc in tool_calls.iter_mut() {
                    match self.redact_tool_call_function(
                        tc.get_mut("function"),
                        &mut redacted_argument_bytes,
                        redaction_memos,
                    ) {
                        RedactTransform::Changed => modified = true,
                        RedactTransform::AmplificationFailed => {
                            return RedactTransform::AmplificationFailed;
                        }
                        RedactTransform::Unchanged => {}
                    }
                }
            }
            match self.redact_tool_call_function(
                message.get_mut("function_call"),
                &mut redacted_argument_bytes,
                redaction_memos,
            ) {
                RedactTransform::Changed => modified = true,
                RedactTransform::AmplificationFailed => {
                    return RedactTransform::AmplificationFailed;
                }
                RedactTransform::Unchanged => {}
            }
        }
        if modified {
            RedactTransform::Changed
        } else {
            RedactTransform::Unchanged
        }
    }

    /// Redact one `function`/`function_call` object's `arguments` string in place.
    fn redact_tool_call_function(
        &self,
        function: Option<&mut Value>,
        redacted_argument_bytes: &mut usize,
        redaction_memos: Option<&HashMap<String, String>>,
    ) -> RedactTransform {
        let Some(function) = function else {
            return RedactTransform::Unchanged;
        };
        let Some(name) = function.get("name").and_then(Value::as_str) else {
            return RedactTransform::Unchanged;
        };
        let Some(policy) = self.engine.tools.get(name) else {
            return RedactTransform::Unchanged;
        };
        if policy.action != ToolAction::RedactArgs || policy.blocked_arg_patterns.is_empty() {
            return RedactTransform::Unchanged;
        }
        let Some(args_value) = function.get("arguments") else {
            return RedactTransform::Unchanged;
        };
        let args = match args_value {
            Value::String(s) => Cow::Borrowed(s.as_str()),
            value => Cow::Owned(value.to_string()),
        };
        let memo_key = redaction_memo_key(name, &args);
        let (redacted, changed) =
            if let Some(redacted) = redaction_memos.and_then(|memos| memos.get(&memo_key)) {
                // Preflight already enforced per-call and aggregate bounds.
                (redacted.clone(), true)
            } else {
                let Ok(result) = redact_arguments(
                    &args,
                    &policy.blocked_arg_patterns,
                    &self.redaction_placeholder,
                ) else {
                    return RedactTransform::AmplificationFailed;
                };
                result
            };
        if changed {
            let Some(next_total) = redacted_argument_bytes.checked_add(redacted.len()) else {
                return RedactTransform::AmplificationFailed;
            };
            if next_total > MAX_PARSE_BYTES {
                return RedactTransform::AmplificationFailed;
            }
            *redacted_argument_bytes = next_total;
            function["arguments"] = Value::String(redacted);
            RedactTransform::Changed
        } else {
            RedactTransform::Unchanged
        }
    }

    /// Govern the tool calls in a FINAL (post-transform) response body. Redaction
    /// is not available here — the redaction transform already ran — so a
    /// `redact_args` match fails closed (`redaction_unavailable = true`).
    async fn govern_final_response(&self, ctx: &mut RequestContext, json: &Value) -> PluginResult {
        let (calls, ungovernable) = extract_response_tool_calls(json);
        // Parity with the streaming finalizer and the buffered-SSE path: an
        // entry the extractor cannot policy-check (a missing or non-string
        // name) fails closed in enforce mode and forwards in dry-run.
        if ungovernable {
            let reason = if calls.iter().any(|call| call.args_ambiguous) {
                AMBIGUOUS_TOOL_ARGUMENTS
            } else {
                "response contains a tool call that cannot be policy-checked (missing or non-string name, or ambiguous arguments)"
            };
            return self.uninspectable_governed_response(ctx, reason);
        }
        if calls.is_empty() {
            return PluginResult::Continue;
        }
        let provider = self.resolve_response_provider(ctx, json);
        let model = json
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string);
        let corr = self.correlation(ctx, model, provider.as_deref());
        // Skip calls this plugin already governed/redacted, consuming the
        // recorded identities as a MULTISET: each recorded identity admits at
        // most its recorded count of identical calls, so a transform that
        // DUPLICATES an approved call has the copy re-evaluated (with
        // `cache_ttl_seconds: 0`, re-approved) instead of two executions riding
        // one approval. Approval-capable identities include the correlation
        // fields (consumer/proxy/model/provider — the approval cache key
        // fields), so a top-level `model` rewrite forces re-approval. A
        // deterministic `redact_args` identity deliberately omits those fields:
        // a model/provider-only rewrite cannot make this plugin's own safe
        // `[REDACTED_TOOL_ARG:<name>]` form look new and re-match the placeholder
        // as a blocked pattern.
        let identities: Vec<String> = calls
            .iter()
            .map(|call| self.governed_call_identity_hash(&corr, call))
            .collect();
        let mut remaining = governed_call_counts(ctx, self.instance_id);
        let mut to_govern: Vec<ToolCall> = Vec::new();
        for (call, identity) in calls.into_iter().zip(identities.iter()) {
            match remaining.get_mut(identity) {
                Some(count) if *count > 0 => *count -= 1,
                _ => to_govern.push(call),
            }
        }
        if !to_govern.is_empty() {
            let batch = self
                .engine
                .govern_calls(&corr, &to_govern, &ctx.plugin_http_call_ns, true)
                .await;
            self.write_metadata(ctx, &batch);
            if batch.enforce_blocks {
                debug!(
                    target: "ai_tool_governor",
                    decision = batch.overall_label,
                    "rejecting response after transforms: {}",
                    batch.deny_reason.as_deref().unwrap_or("blocked")
                );
                return self.reject(&batch);
            }
        }
        // Re-record the full identity multiset (skipped + freshly cleared) so
        // a later re-check of this same call set — this path also runs from
        // `on_response_body` for a decoded mislabeled-JSON body — skips
        // one-for-one instead of re-firing approval webhooks.
        record_governed_identities(ctx, self.instance_id, &identities);
        PluginResult::Continue
    }

    /// Govern a fully-buffered `text/event-stream` response body. Reached when
    /// the stream inspector did not attach — streaming inspection is disabled
    /// (this plugin then keeps SSE labels buffered), or another buffering
    /// plugin / content-type-rewrite guard kept the SSE response on the
    /// buffered path — so its accumulated tool calls are governed rather than
    /// forwarded uninspected. Callers must pass DECODED bytes when the
    /// response carried a `Content-Encoding` (the recorded hash must match the
    /// decoded-hash comparison in the final re-check). Redaction is impossible
    /// on a buffered SSE body, so a `redact_args` match fails closed
    /// (`redaction_unavailable = true`).
    async fn govern_buffered_sse(&self, ctx: &mut RequestContext, body: &[u8]) -> PluginResult {
        if !self.inspect.any_buffered_response() || body.is_empty() {
            return PluginResult::Continue;
        }
        if body.len() > MAX_PARSE_BYTES {
            return self.uninspectable_governed_response(
                ctx,
                "streamed response body exceeds the inspectable size limit",
            );
        }
        // Opaque parity with the live inspector: SSE-labeled bytes that are
        // not valid UTF-8 (opaque/binary — e.g. compressed bytes whose
        // `Content-Encoding` header a transform stripped) cannot be parsed
        // for SSE frames at all. Extraction would find zero calls and
        // `calls.is_empty()` would forward a denied delta hiding inside even
        // under `default_action: deny`, so surface it as ungovernable
        // instead: fail closed in enforce, forward in dry-run.
        if std::str::from_utf8(body).is_err() {
            return self.uninspectable_governed_response(
                ctx,
                "streamed response body is not valid UTF-8 and cannot be inspected",
            );
        }
        let extracted = extract_sse_tool_calls(body);
        // Mirror the live streaming finalizer: a buffered SSE tool call that
        // cannot be policy-checked (missing `function.name` or non-string
        // `function.arguments`) is ungovernable. Fail closed in enforce, forward
        // in dry-run.
        //
        // Screen BEFORE staging the skip hash (same ordering as the decoded
        // JSON ambiguity screens): an ungovernable body was never governed, so
        // recording its hash would let dry-run Continue — or a later final
        // re-check after an enforce Reject — hash-skip bytes that must be
        // re-evaluated as uninspectable.
        if extracted.ungovernable {
            let reason = if extracted.ambiguous {
                AMBIGUOUS_RESPONSE_JSON
            } else {
                "streamed response body contains an ungovernable tool call"
            };
            return self.uninspectable_governed_response(ctx, reason);
        }
        // Record the hash of the SSE body governed here so the post-transform
        // `on_final_response_body` re-check (which routes SSE-labeled/shaped
        // bodies back through this path) can skip an unchanged body instead of
        // re-governing it — for `require_approval` policies that would mean a
        // duplicate approval webhook call. Stored on the non-serialized
        // per-instance `ai_tool_governor_response_hashes` map so this body-derived hash never
        // reaches transaction logs. Staged only after the ungovernable screen
        // so governable responses (including empty-call bodies) keep
        // no-duplicate-approval skip behavior.
        self.set_response_hash(ctx, sha256_hex_bytes(body));
        if extracted.calls.is_empty() {
            return PluginResult::Continue;
        }
        // Correlation precedence mirrors the live inspector: the model a
        // routing plugin / the request body recorded first, then the
        // model/provider the SSE frames themselves report — so approval
        // webhook and cache keys carry the served model/provider even when
        // request metadata is absent, and a decision made for one
        // model/provider is never reused for another.
        let provider = federation_provider(ctx).or(extracted.provider);
        let model = ctx
            .metadata
            .get(STREAM_MODEL_KEY)
            .or_else(|| ctx.metadata.get("ai_model"))
            .cloned()
            .or(extracted.model);
        let corr = self.correlation(ctx, model, provider.as_deref());
        // Skip calls a previous pass already governed, consuming the recorded
        // identities as a MULTISET (same semantics as the buffered-JSON final
        // re-check): a later benign transform — an appended keepalive comment,
        // a relabel, a reserialization — changes the body hash but not the
        // call identities, so an unchanged approved call is not re-sent to the
        // approval webhook (which a one-shot approval service or
        // `cache_ttl_seconds: 0` would deny).
        let identities: Vec<String> = extracted
            .calls
            .iter()
            .map(|call| self.governed_call_identity_hash(&corr, call))
            .collect();
        let mut remaining = governed_call_counts(ctx, self.instance_id);
        let mut to_govern: Vec<ToolCall> = Vec::new();
        for (call, identity) in extracted.calls.into_iter().zip(identities.iter()) {
            match remaining.get_mut(identity) {
                Some(count) if *count > 0 => *count -= 1,
                _ => to_govern.push(call),
            }
        }
        if !to_govern.is_empty() {
            let batch = self
                .engine
                .govern_calls(&corr, &to_govern, &ctx.plugin_http_call_ns, true)
                .await;
            self.write_metadata(ctx, &batch);
            if batch.enforce_blocks {
                return self.reject(&batch);
            }
        }
        // Record the full identity multiset (skipped + freshly cleared) so the
        // final re-check skips unchanged calls one-for-one while a transform
        // that injects, duplicates, or rewrites a call is still re-evaluated.
        record_governed_identities(ctx, self.instance_id, &identities);
        PluginResult::Continue
    }

    /// A governed response body that cannot be inspected (an unsupported or
    /// undecodable content-encoding, an ungovernable call, or an oversized
    /// body): fail closed in enforce mode, forward in dry-run. Duplicate-key
    /// ambiguity additionally records a sanitized dry-run observation so
    /// rollout logs positively witness the finding without claiming deny.
    fn uninspectable_governed_response(
        &self,
        ctx: &mut RequestContext,
        reason: &'static str,
    ) -> PluginResult {
        if self.engine.mode == Mode::Enforce {
            return self.reject_uninspectable(ctx, "response body", reason);
        }
        if Self::is_ambiguity_reason(reason) {
            Self::write_ambiguity_observation_into(&self.engine, &mut ctx.metadata);
        }
        PluginResult::Continue
    }
}

#[async_trait]
impl Plugin for AiToolGovernor {
    fn name(&self) -> &str {
        "ai_tool_governor"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_TOOL_GOVERNOR
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn enforces_finalized_request_policy(&self) -> bool {
        true
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.engine
            .approval
            .as_ref()
            .map(|a| vec![a.hostname.clone()])
            .unwrap_or_default()
    }

    // --- Request path -----------------------------------------------------

    fn requires_request_body_before_before_proxy(&self) -> bool {
        // Streaming inspection also needs the request body in `before_proxy`
        // to detect `"stream": true` and pin the response onto the reqwest
        // dispatch path where the SSE inspector is wired.
        self.enabled && (self.inspect.any_request() || self.inspect.streaming_response_tool_calls)
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if !self.enabled
            || !(self.inspect.any_request() || self.inspect.streaming_response_tool_calls)
            || !ctx.method.eq_ignore_ascii_case("POST")
        {
            return false;
        }
        self.governs_request_content_type(ctx.headers.get("content-type").map(String::as_str))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.enabled {
            return PluginResult::Continue;
        }
        let governs_request = self.inspect.any_request();
        let detects_streaming = self.inspect.streaming_response_tool_calls;
        if !governs_request && !detects_streaming {
            return PluginResult::Continue;
        }
        // Mirror `should_buffer_request_body`: ordinary JSON plus the
        // JSON-RPC/absent media types accepted by MCP/A2A gateways are in
        // scope. Framed gRPC/gRPC-Web `+json` variants are wire frames, not
        // bare JSON — out of scope, never fail-closed.
        let content_type = header_value(headers, "content-type");
        if !ctx.method.eq_ignore_ascii_case("POST")
            || !self.governs_request_content_type(content_type)
        {
            return PluginResult::Continue;
        }

        // Bodies this plugin is configured to govern but cannot inspect fail
        // CLOSED in enforce mode. Request decompression runs in later
        // body-transform hooks, so a `Content-Encoding`d body here is opaque; an
        // oversized or unparseable body is equally opaque. In dry-run (or a
        // streaming-only config) the request is forwarded, but conservatively
        // marked for the inspectable dispatch path since a `"stream": true`
        // flag inside it cannot be ruled out.
        let enforce_request = governs_request && self.engine.mode == Mode::Enforce;
        let mut uninspectable: Option<&'static str> = None;

        let body_size: usize = ctx
            .metadata
            .get("request_body_size_bytes")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        // Duplicate-object-member screen of the pre-transform request body,
        // computed before the `ctx.metadata` borrow below so it can use the
        // shared per-request memo (`body_validator` inspects this same body in
        // this same phase). The memo is moved out and straight back; it is keyed
        // on body digests, so moving it preserves every verdict. Bodies past the
        // inspection window are skipped here — they are already uninspectable
        // for size and must not pay for a scan.
        let mut json_scan_memo = std::mem::take(&mut ctx.json_scan_memo);
        let body_ambiguity = ctx
            .metadata
            .get("request_body")
            .filter(|body| body.len() <= MAX_PARSE_BYTES)
            .and_then(|body| json_scan_memo.ambiguity_str(body));
        ctx.json_scan_memo = json_scan_memo;

        let body = ctx.metadata.get("request_body");

        // A missing Content-Type is accepted by MCP/A2A gateways, but it is
        // not evidence that every POST on a mixed proxy is JSON-RPC. Body
        // buffering is necessarily tentative (the body is unavailable when
        // `should_buffer_request_body` runs); once available, only a JSON-shaped
        // body enters fail-closed governance. Unrelated form/binary uploads are
        // released instead of being rejected as malformed JSON.
        if content_type.is_none() && !body.is_some_and(|body| looks_like_json(body.as_bytes())) {
            return PluginResult::Continue;
        }

        if header_value(headers, "content-encoding")
            .map(str::trim)
            .is_some_and(|enc| !enc.is_empty() && !enc.eq_ignore_ascii_case("identity"))
        {
            uninspectable = Some("request body has a content-encoding that cannot be inspected");
        }

        if uninspectable.is_none() {
            if body_size == 0 && body.is_none_or(|b| b.is_empty()) {
                // Empty body: nothing to govern.
                return PluginResult::Continue;
            }
            if body_size > MAX_PARSE_BYTES || body.is_some_and(|b| b.len() > MAX_PARSE_BYTES) {
                uninspectable = Some("request body exceeds the inspectable size limit");
            }
        }

        // Duplicate object member names make the governed document and the
        // dispatched bytes disagree: `serde_json` keeps the LAST tool name or
        // argument while a first-key-wins backend executes the first. This
        // plugin has no request-body transform, so it cannot canonicalize —
        // the body joins the uninspectable class and fails closed in enforce
        // mode (advisory `GHSA-c78j-5w9p-cpq6`).
        if uninspectable.is_none() && body_ambiguity.is_some() {
            uninspectable = Some(AMBIGUOUS_REQUEST_JSON);
        }

        let json = match uninspectable {
            Some(_) => None,
            // `request_body` metadata is absent for a non-UTF-8 (binary) body:
            // JSON must be UTF-8, so that is uninspectable too.
            None => body.and_then(|b| serde_json::from_str::<Value>(b).ok()),
        };
        let Some(json) = json else {
            let reason = uninspectable
                .unwrap_or("request body is not parseable JSON despite a JSON content-type");
            if enforce_request {
                return self.reject_uninspectable(ctx, "request body", reason);
            }
            if Self::is_ambiguity_reason(reason) {
                Self::write_ambiguity_observation_into(&self.engine, &mut ctx.metadata);
            }
            if detects_streaming {
                ctx.metadata
                    .insert(STREAM_REQUESTED_KEY.to_string(), "true".to_string());
            }
            return PluginResult::Continue;
        };

        if detects_streaming && json.get("stream").and_then(Value::as_bool) == Some(true) {
            ctx.metadata
                .insert(STREAM_REQUESTED_KEY.to_string(), "true".to_string());
            if let Some(model) = request_model(&json) {
                ctx.metadata.insert(STREAM_MODEL_KEY.to_string(), model);
            }
        }
        if governs_request {
            // Record the hash of the exact body governed here so the
            // post-transform `on_final_request_body` re-check can skip an
            // unchanged backend-visible body instead of governing (and, for
            // `require_approval` policies, calling the webhook) a second time.
            // Stored on a non-serialized field so this arg-derived hash never
            // reaches transaction logs.
            if let Some(hash) = ctx.metadata.get("request_body").map(|b| sha256_hex(b)) {
                self.set_request_hash(ctx, hash);
            }
            return self.govern_request(ctx, &json).await;
        }
        PluginResult::Continue
    }

    // --- Final backend-visible request body (post-transform re-check) ------

    fn requires_request_body_buffering(&self) -> bool {
        // `requires_request_body_before_before_proxy` (used for streaming
        // detection) is gated by this flag in the proxy, so it must also be true
        // when only streaming inspection is enabled — otherwise a `stream: true`
        // JSON POST without an `Accept: text/event-stream` header is never
        // buffered, `before_proxy` cannot set the reqwest-pinning marker, and the
        // SSE tool-call inspector is bypassed.
        self.enabled && (self.inspect.any_request() || self.inspect.streaming_response_tool_calls)
    }

    fn needs_final_request_body_context(&self) -> bool {
        // `govern_request` needs the real request context (consumer/proxy
        // correlation, `plugin_http_call_ns` for approval webhooks, metadata
        // writes), and streaming-only configs need it too so the final-body
        // `stream: true` re-detection can set the reqwest-pinning marker back on
        // the live request.
        self.enabled && (self.inspect.any_request() || self.inspect.streaming_response_tool_calls)
    }

    /// Re-run the deterministic request policy on the FINAL backend-visible body.
    ///
    /// `before_proxy` governs the body as first buffered, but `request_transformer`
    /// (3000) and other `transform_request_body` hooks run afterward and can add
    /// or rewrite JSON fields — turning an allowed body into a denied `tools/call`
    /// or a disallowed `tools[]` definition before it reaches the backend. This
    /// hook closes that gap. Request decompression also runs in `transform_request_body`,
    /// so a body opaque to `before_proxy` may be plaintext here. A trusted
    /// `mcp_gateway` aggregate-router name rewrite is remapped back to the public
    /// policy identity only when the final wire name exactly matches the staged
    /// upstream alias; arguments and unrelated name changes are still governed.
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        let governs_request = self.enabled && self.inspect.any_request();
        let detects_streaming = self.enabled && self.inspect.streaming_response_tool_calls;
        if !governs_request && !detects_streaming {
            return PluginResult::Continue;
        }
        if !ctx.method.eq_ignore_ascii_case("POST") {
            return PluginResult::Continue;
        }
        // An empty body has nothing to detect or govern (it is not
        // "uninspectable" in the fail-closed sense).
        if body.is_empty() {
            return PluginResult::Continue;
        }
        // Only JSON bodies are in scope (mirror `should_buffer_request_body`). A
        // `request_transformer` can strip/relabel `Content-Type` while still
        // applying JSON body rules, so also inspect a JSON-shaped body — otherwise
        // a request initially governed as safe JSON could be transformed into a
        // denied MCP/A2A `tools/call` with the header removed and skip this
        // re-check. A framed gRPC/gRPC-Web `+json` label is NOT a JSON label
        // (the body is length-prefixed wire frames): such a request is out of
        // scope rather than fail-closed as unparseable, and its framed bytes
        // never look like JSON, so the shape fallback does not re-admit it —
        // while a transform that merely relabeled a still-JSON-shaped body is
        // still caught by `looks_like_json`.
        let json_ct = header_value(headers, "content-type")
            .is_some_and(|content_type| self.governs_request_content_type(Some(content_type)));
        let json_shaped = looks_like_json(body);
        if !json_ct && !json_shaped {
            return PluginResult::Continue;
        }

        let inspectable =
            !has_non_identity_content_encoding(headers) && body.len() <= MAX_PARSE_BYTES;
        // Screen the FINAL backend-visible bytes for duplicate object member
        // names, sharing the verdict with the other governed plugins running in
        // this stage. Ambiguity makes the body uninspectable: these are the
        // exact bytes the backend will parse, and this plugin cannot rewrite
        // them (advisory `GHSA-c78j-5w9p-cpq6`).
        let ambiguity = inspectable
            .then(|| ctx.json_scan_memo.ambiguity(body))
            .flatten();
        let json = (inspectable && ambiguity.is_none())
            .then(|| serde_json::from_slice::<Value>(body).ok())
            .flatten();

        // Re-detect the stream mode on the FINAL backend-visible body: a
        // `request_transformer` body rule may have added OR removed `stream:
        // true` after `before_proxy` ran. `forces_reqwest_dispatch` /
        // `request_is_streaming` (consulted after this hook) read the marker to
        // pin the reqwest path and — in a streaming-only config
        // (`response_tool_calls: false`) — to route the response as an SSE
        // fallback vs. ordinary buffered JSON. The backend-visible request
        // governs the response mode, so the marker must track it in BOTH
        // directions.
        if detects_streaming {
            let already_marked =
                ctx.metadata.get(STREAM_REQUESTED_KEY).map(String::as_str) == Some("true");
            // An uninspectable final body (encoded, oversized, non-JSON) cannot
            // rule out `stream: true`, so treat it as streaming — reqwest
            // dispatch is always valid, and this preserves the round-14
            // transformer-adds-stream fix.
            let is_stream = match &json {
                Some(json) => json.get("stream").and_then(Value::as_bool) == Some(true),
                None => true,
            };
            if is_stream && !already_marked {
                ctx.metadata
                    .insert(STREAM_REQUESTED_KEY.to_string(), "true".to_string());
            } else if !is_stream && json.is_some() {
                // A `request_transformer` rewrote an initially-streaming request
                // to `stream: false` (or removed the field): the backend now
                // sees a non-streaming request, so CLEAR the stale marker (and
                // the dependent stream model) or a normal non-streaming JSON
                // response would be mis-governed as an SSE fallback and denied
                // under a streaming-only config. Only clear when a final body
                // was actually parsed and is provably non-streaming — never on
                // an unparseable/absent body, which stays conservatively marked
                // (round-14).
                ctx.metadata.remove(STREAM_REQUESTED_KEY);
                ctx.metadata.remove(STREAM_MODEL_KEY);
            }
            // Refresh the recorded model from the FINAL backend-visible body —
            // a `request_transformer` can change `model` after the initial
            // detection, the stream inspector seeds its correlation from this
            // key (and ignores SSE-frame models once correlation is `Some`),
            // and approval webhooks/cache must key on the model the backend
            // actually serves. When an inspectable final body no longer
            // carries a model, drop the stale key so the inspector falls back
            // to the `model` reported in the SSE frames. Only runs on a parsed
            // STILL-streaming body; the non-streaming clear branch above
            // already removed both keys, and an uninspectable body leaves the
            // last-known value in place.
            if is_stream && json.is_some() {
                match json.as_ref().and_then(request_model) {
                    Some(model) => {
                        ctx.metadata.insert(STREAM_MODEL_KEY.to_string(), model);
                    }
                    None => {
                        ctx.metadata.remove(STREAM_MODEL_KEY);
                    }
                }
            }
        }

        if !governs_request {
            return PluginResult::Continue;
        }

        // Unchanged since `before_proxy` governed it: nothing new to check, and
        // re-governing would risk a duplicate approval webhook.
        let final_hash = sha256_hex_bytes(body);
        if self.request_hash(ctx) == Some(final_hash.as_str()) {
            return PluginResult::Continue;
        }

        // A still-encoded / oversized / unparseable final body cannot be
        // inspected: fail closed in enforce mode so a transform (or a body
        // `before_proxy` could not read) cannot smuggle a denied call past policy.
        // Only fail closed for a request this plugin actually governs — a JSON
        // content type or one `before_proxy` already governed — so a non-JSON
        // request another plugin merely buffered is not rejected here.
        let Some(json) = json else {
            let was_governed = self.request_hash(ctx).is_some();
            if self.engine.mode == Mode::Enforce && (json_ct || json_shaped || was_governed) {
                return self.reject_uninspectable(
                    ctx,
                    "request body",
                    if ambiguity.is_some() {
                        AMBIGUOUS_REQUEST_JSON
                    } else {
                        "final request body cannot be inspected (encoded, oversized, or not JSON)"
                    },
                );
            }
            if ambiguity.is_some() {
                Self::write_ambiguity_observation_into(&self.engine, &mut ctx.metadata);
            }
            return PluginResult::Continue;
        };
        self.set_request_hash(ctx, final_hash);
        self.govern_request(ctx, &json).await
    }

    // --- Buffered response path -------------------------------------------

    fn requires_response_body_buffering(&self) -> bool {
        self.enabled && self.inspect.any_buffered_response()
    }

    /// Buffer by default whenever a response inspection surface is enabled.
    /// The pre-header decision cannot see response `Content-Type` or
    /// `Content-Encoding`: even an unmarked/bodyless request such as
    /// `GET /events` can return encoded SSE, which the raw live inspector cannot
    /// decode. The header-time refinement below releases only unencoded SSE to
    /// that inspector (plus framed gRPC, which is out of scope) and keeps
    /// encoded/ambiguous bodies on the decode-and-govern path.
    /// `should_buffer_response_body_for_content_type` downgrades ONLY an event
    /// stream that the live SSE inspector will actually govern
    /// (`streaming_response_tool_calls` enabled) and framed gRPC/gRPC-Web back
    /// to the streaming path.
    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        self.enabled && self.inspect.any_buffered_response()
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        if !self.should_buffer_response_body(ctx) || !(200..300).contains(&response_status) {
            return false;
        }
        // Deliberate FailClosed posture: on a governed request, an ambiguously
        // labeled 2xx response stays BUFFERED so `on_response_body` (and its
        // `looks_like_json` fallback) can inspect it. The proxy's header-time
        // refinement downgrades plugin-forced buffering back to streaming when
        // every plugin declines the content type, so declining `text/html`,
        // `text/plain`, or a missing `Content-Type` here would let a mislabeled
        // Chat Completions JSON body containing a denied tool call stream to
        // the client uninspected. Framed gRPC/gRPC-Web (length-prefixed wire
        // frames owned by the gRPC machinery) is always released — out of this
        // plugin's scope. A `text/event-stream` label is released ONLY when
        // streaming inspection is enabled AND the response carries no
        // `Content-Encoding`, so a live SSE inspector will
        // actually attach and govern it; with streaming inspection disabled
        // there is no inspector, and releasing the label would let real SSE
        // tool-call deltas — or a Chat Completions JSON body a transform
        // relabeled `text/event-stream` — stream past governance entirely.
        // Kept buffered, buffered-SSE governance handles real SSE and the
        // JSON-shape fallback catches the mislabeled JSON.
        match content_type {
            Some(ct) => {
                if is_framed_grpc_content_type(ct) {
                    return false;
                }
                if is_event_stream_content_type(ct) {
                    // The live inspector reads the RAW byte stream, so an SSE
                    // label with a non-identity `Content-Encoding` must stay
                    // BUFFERED even when streaming inspection is enabled:
                    // compressed bytes parse as zero SSE events, and releasing
                    // them would forward denied tool-call deltas ungoverned.
                    // The buffered path decodes (`decompress_within_limit`)
                    // and governs the decoded frames, failing closed on an
                    // undecodable encoding in enforce mode.
                    if has_non_identity_content_encoding(response_headers) {
                        return true;
                    }
                    return !self.inspect.streaming_response_tool_calls;
                }
                true
            }
            None => true,
        }
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // `any_buffered_response()` also covers a streaming-only config whose
        // backend returned a plain JSON body instead of SSE (the SSE fallback):
        // that body is delivered on the buffered path and must still be governed.
        if !self.enabled || !self.inspect.any_buffered_response() {
            return PluginResult::Continue;
        }
        if !(200..300).contains(&response_status) {
            return PluginResult::Continue;
        }
        let content_type = header_value(response_headers, "content-type").unwrap_or("");
        // Framed gRPC/gRPC-Web (including the `+json` variants) is
        // length-prefixed wire frames owned by the gRPC machinery, not a bare
        // JSON document — explicitly OUT OF SCOPE, mirroring the request-side
        // exclusion. This plugin never buffers those labels itself, but when
        // the response is buffered for reasons outside this plugin
        // (`response_body_mode: Buffer`, another buffering plugin) this hook
        // still runs and `is_json_content_type` matches `+json` suffixes, so
        // without this gate an oversized framed-gRPC body would be
        // fail-closed rejected despite never being governable here.
        if is_framed_grpc_content_type(content_type) {
            return PluginResult::Continue;
        }
        // A buffered `text/event-stream` body means the stream inspector never
        // attached (streaming inspection disabled, or another plugin/guard
        // kept it buffered): govern the SSE tool calls here rather than
        // forwarding them uninspected. Routing is by SHAPE first, label
        // second — the label is not trustworthy: an upstream can omit
        // `text/event-stream`, and a `response_transformer` header rule can
        // relabel it (e.g. `text/plain`) while leaving the SSE frames intact.
        // An SSE-SHAPED body (see `looks_like_sse`) is routed through
        // buffered-SSE governance regardless of the header — even an
        // `application/json` relabel: an SSE-shaped body can never parse as
        // JSON, so the JSON path below could only forward it uninspected.
        if looks_like_sse(body) {
            return self.govern_buffered_sse(ctx, body).await;
        }
        if is_event_stream_content_type(content_type) {
            // SSE-labeled but not SSE-shaped plaintext.
            // Try the plaintext JSON-shape route first even when the header
            // already carries `Content-Encoding`: the gateway compression
            // plugin commits that header in `after_proxy`, but its body
            // transform runs after this hook, so the bytes are still plaintext
            // here. A real upstream-encoded body will not look like JSON and
            // continues to the bounded decode path below.
            if !looks_like_json(body)
                && let Some(encoding) = content_encoding_value(response_headers)
            {
                // An SSE label with a `Content-Encoding`: DECODE FIRST (the
                // same gzip/br decode the final re-check uses) and govern the
                // decoded bytes. Feeding compressed bytes into the SSE
                // extractor would find zero calls and record the COMPRESSED
                // hash, letting the final re-check hash-skip denied deltas.
                // An undecodable/unsupported encoding or decoded output past
                // the cap fails closed in enforce mode, forwards in dry-run
                // (round-8 undecodable semantics).
                let Some(decoded) = decompress_within_limit(encoding, body) else {
                    return self.uninspectable_governed_response(
                        ctx,
                        "response body has a content-encoding that cannot be inspected",
                    );
                };
                if looks_like_json(&decoded) {
                    // Mislabeled Chat Completions JSON under an SSE label,
                    // encoded: govern the decoded JSON. Redaction is
                    // impossible here (the redaction transform sees the
                    // still-encoded bytes), so this rides the
                    // redact-unavailable final-response path; the decoded hash
                    // is recorded so an unchanged final body is not
                    // re-governed.
                    if !self.governs_buffered_json(ctx) {
                        return PluginResult::Continue;
                    }
                    // Same duplicate-member screen the other decoded JSON paths
                    // run, and BEFORE the skip hash is staged: an ambiguous body
                    // governed from the `serde_json` last-wins view while the
                    // client reads a first-wins view is uninspectable, and
                    // recording its hash first would let the terminal re-check
                    // hash-skip the very bytes that were never governable
                    // (advisory `GHSA-c78j-5w9p-cpq6`).
                    if ctx
                        .json_scan_memo
                        .ambiguity(strip_json_bom(&decoded))
                        .is_some()
                    {
                        return self.uninspectable_governed_response(ctx, AMBIGUOUS_RESPONSE_JSON);
                    }
                    self.set_response_hash(ctx, sha256_hex_bytes(&decoded));
                    let Some(json) = parse_json_within_limit(&decoded) else {
                        return self.uninspectable_governed_response(
                            ctx,
                            "response body could not be inspected after decoding",
                        );
                    };
                    return self.govern_final_response(ctx, &json).await;
                }
                return self.govern_buffered_sse(ctx, &decoded).await;
            }
            if !looks_like_json(body) {
                return self.govern_buffered_sse(ctx, body).await;
            }
            // SSE-labeled but JSON-SHAPED: mislabeled Chat Completions JSON —
            // fall through to the JSON path below (the round-8 content-type
            // refinement keeps this label buffered when no live inspector
            // attaches, precisely so this body cannot bypass governance).
        }
        // A `response_transformer` header rule runs in `after_proxy` before this
        // hook and can remove/relabel `Content-Type: application/json` while
        // leaving the Chat Completions JSON intact, so also inspect a JSON-shaped
        // body even when the header no longer says JSON.
        if !is_json_content_type(content_type) && !looks_like_json(body) {
            return PluginResult::Continue;
        }
        // A streaming-only config governs a buffered JSON body only for a
        // streaming request's SSE fallback, never an ordinary JSON response.
        if !self.governs_buffered_json(ctx) {
            return PluginResult::Continue;
        }
        if body.is_empty() {
            return PluginResult::Continue;
        }
        let wire_encoding = content_encoding_value(response_headers);
        if body.len() > MAX_PARSE_BYTES && wire_encoding.is_none() {
            // A padded PLAINTEXT response must not smuggle governed tool
            // calls past the parse limit: fail closed in enforce mode. The
            // wire-size cap applies only to identity/plaintext bodies — for
            // a body with a `Content-Encoding` the real inspection bound is
            // the DECODED size (`decompress_within_limit`'s cap below): an
            // incompressible payload can exceed the cap on the wire while
            // its decoded JSON is comfortably inspectable, and rejecting it
            // before the decode attempt would 502 legitimate traffic.
            if self.engine.mode == Mode::Enforce {
                return self.reject_uninspectable(
                    ctx,
                    "response body",
                    "response body exceeds the inspectable size limit",
                );
            }
            return PluginResult::Continue;
        }
        // Duplicate-object-member screen of the raw backend body. A body whose
        // `choices[].message.tool_calls[]` this plugin would evaluate on a
        // last-wins collapse, while the client's parser reads a first-wins view
        // of the same bytes, is uninspectable — and these bytes are forwarded
        // unchanged, so ambiguity cannot be canonicalized away (advisory
        // `GHSA-c78j-5w9p-cpq6`). Screened on the BOM-stripped bytes the parse
        // below actually consumes.
        if body.len() <= MAX_PARSE_BYTES
            && ctx.json_scan_memo.ambiguity(strip_json_bom(body)).is_some()
        {
            return self.uninspectable_governed_response(ctx, AMBIGUOUS_RESPONSE_JSON);
        }
        // The plaintext parse is attempted only within the wire cap (the cap
        // bounds serde CPU); an encoded body past it goes straight to the
        // bounded decode branch. `parse_json_within_limit` strips a leading
        // UTF-8 BOM so a `\u{feff}`-prefixed Chat Completions body is governed
        // rather than forwarded as unparseable (the SSE path already strips it).
        let parsed = (body.len() <= MAX_PARSE_BYTES)
            .then(|| parse_json_within_limit(body))
            .flatten();
        let json = match parsed {
            Some(json) => json,
            None => {
                // A JSON-labeled body that does not parse as plaintext but
                // carries a `Content-Encoding` is usually a perfectly valid
                // compressed Chat Completions response (an upstream that
                // gzips its JSON): DECODE FIRST — the same gzip/br decode the
                // SSE branch above and the final re-check use — and govern
                // the DECODED bytes. Fail closed only when decoding actually
                // fails (unsupported/corrupt encoding, or output past the
                // cap); rejecting before the decode attempt would 502
                // legitimate compressed responses.
                let Some(encoding) = wire_encoding else {
                    // Unencoded but unparseable despite the JSON label/shape:
                    // no governable calls can be extracted from it and it was
                    // never encoded, so forward (long-standing plaintext
                    // semantics).
                    return PluginResult::Continue;
                };
                let Some(decoded) = decompress_within_limit(encoding, body) else {
                    return self.uninspectable_governed_response(
                        ctx,
                        "response body has a content-encoding that cannot be inspected",
                    );
                };
                // Decoded SSE frames under a JSON (or relabeled) header:
                // buffered-SSE governance on the decoded bytes, mirroring the
                // final re-check's decoded-shape routing (it records the
                // decoded hash itself).
                if looks_like_sse(&decoded) {
                    return self.govern_buffered_sse(ctx, &decoded).await;
                }
                // Same duplicate-member screen on the DECODED bytes: a
                // compressed governed body must not reach policy on a
                // last-wins collapse either. Screened BEFORE the hash is
                // staged, so an ambiguous body never gets a skip hash the
                // terminal re-check could honour.
                if ctx
                    .json_scan_memo
                    .ambiguity(strip_json_bom(&decoded))
                    .is_some()
                {
                    return self.uninspectable_governed_response(ctx, AMBIGUOUS_RESPONSE_JSON);
                }
                // Record the DECODED hash: the final re-check compares its
                // own decode against this, so a compression-only final body
                // is hash-skipped instead of re-governed (no duplicate
                // approval webhook).
                self.set_response_hash(ctx, sha256_hex_bytes(&decoded));
                let Some(json) = parse_json_within_limit(&decoded) else {
                    return self.uninspectable_governed_response(
                        ctx,
                        "response body could not be inspected after decoding",
                    );
                };
                // The in-place redaction transform sees the still-encoded
                // bytes and cannot rewrite them, so a decoded-governed
                // encoded body rides the redaction-unavailable final-response
                // path: a `redact_args` match fails closed (round-11
                // semantics) instead of forwarding the matched secret.
                return self.govern_final_response(ctx, &json).await;
            }
        };

        // Record the hash of the raw backend body governed here so the
        // post-transform `on_final_response_body` re-check can skip an unchanged
        // client-visible body (recorded even when there are no calls: a later
        // `response_transformer` that injects one changes the hash and forces a
        // fresh evaluation). Stored on the non-serialized
        // per-instance `ai_tool_governor_response_hashes` map, off `ctx.metadata`.
        self.set_response_hash(ctx, sha256_hex_bytes(body));

        let (calls, ungovernable) = extract_response_tool_calls(&json);
        // Streaming parity: an ungovernable `tool_calls[]` entry (a missing
        // or non-string `function.name`) must not slide past policy
        // because the extractor dropped it — with all entries unnamed,
        // `calls.is_empty()` would Continue even under `default_action: deny`.
        // Fail closed in enforce mode, forward in dry-run.
        if ungovernable {
            let reason = if calls.iter().any(|call| call.args_ambiguous) {
                AMBIGUOUS_TOOL_ARGUMENTS
            } else {
                "response contains a tool call that cannot be policy-checked (missing or non-string name, or ambiguous arguments)"
            };
            return self.uninspectable_governed_response(ctx, reason);
        }
        if calls.is_empty() {
            return PluginResult::Continue;
        }

        let provider = self.resolve_response_provider(ctx, &json);
        let model = json
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string);
        let corr = self.correlation(ctx, model, provider.as_deref());

        let batch = self
            .engine
            .govern_calls(
                &corr,
                &calls,
                &ctx.plugin_http_call_ns,
                !super::response_body_rewrite_allowed(response_status),
            )
            .await;
        self.write_metadata(ctx, &batch);

        if batch.enforce_blocks {
            debug!(
                target: "ai_tool_governor",
                decision = batch.overall_label,
                "rejecting response: {}",
                batch.deny_reason.as_deref().unwrap_or("blocked")
            );
            ctx.ai_tool_governor_redaction_memos
                .remove(&self.instance_id);
            return self.reject(&batch);
        }
        if ctx.finalized_response_replay
            && self.engine.mode == Mode::Enforce
            && batch
                .per_call
                .iter()
                .any(|decision| !decision.redact_patterns.is_empty())
        {
            ctx.ai_tool_governor_replay_redactions
                .insert(self.instance_id);
        }
        // Stage preflighted redaction rewrites for the transform hook. One
        // instance's aggregate value bytes are capped at MAX_PARSE_BYTES during
        // govern_calls, and the context retains at most ONE instance's memo set
        // at a time. Otherwise many configured governor instances could each
        // stage another inspectable window before any transform hook runs.
        // Instances that do not win this bounded slot safely recompute during
        // their transform instead of multiplying per-request memory.
        ctx.ai_tool_governor_redaction_memos
            .remove(&self.instance_id);
        if !batch.redaction_memos.is_empty() && ctx.ai_tool_governor_redaction_memos.is_empty() {
            ctx.ai_tool_governor_redaction_memos
                .insert(self.instance_id, batch.redaction_memos);
        }
        // Record the governed calls with multiset counts so the final re-check
        // skips them one-for-one. Approval-capable calls use correlation-aware
        // identities; deterministic `redact_args` calls use name/args only.
        // Redaction updates the latter record to the redacted args below.
        self.record_governed_calls(ctx, &corr, &calls);
        PluginResult::Continue
    }

    async fn transform_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // Context-aware so the redaction path is gated the same way as the
        // governance path: a streaming-only config redacts a JSON body only for
        // a streaming request's SSE fallback, not an ordinary JSON response.
        if !self.enabled
            || !self.needs_response_transform
            || self.engine.mode == Mode::DryRun
            || !self.governs_buffered_json(ctx)
        {
            return None;
        }
        // Framed gRPC/gRPC-Web is out of scope (same gate as the buffered
        // hooks): defense in depth — `on_response_body` no longer records the
        // governed-hash marker for those labels, so the marker gate below
        // already declines, but a rewrite of framed wire bytes must never be
        // possible even if that changes.
        if content_type.is_some_and(is_framed_grpc_content_type) {
            return None;
        }
        // Redaction rewrites only bodies this plugin actually governed in
        // `on_response_body` (the governed-response hash marker is recorded
        // only for 2xx in-scope bodies). Without the marker gate, a
        // content-type-only gate would silently rewrite out-of-scope bodies —
        // e.g. a backend 4xx/5xx JSON error whose shape happens to contain
        // `choices[].message.tool_calls[]`, which `on_response_body` skips as
        // non-2xx before recording the hash.
        self.response_hash(ctx)?;
        // Mirror the `looks_like_json` fallback in `on_response_body`: a header
        // rule can strip/relabel `Content-Type: application/json` before this
        // transform runs while leaving the governed JSON intact. Redaction must
        // still rewrite it — returning `None` here would forward the matched
        // argument unredacted, and the final re-check would skip the unchanged
        // governed hash.
        let json_ct = content_type.is_some_and(is_json_content_type);
        if !json_ct && !looks_like_json(body) {
            return None;
        }
        if body.is_empty() || body.len() > MAX_PARSE_BYTES {
            return None;
        }
        // Strip a leading BOM (same as the governance parse) so a BOM-prefixed
        // governed body — now inspected by `on_response_body` — is also
        // redactable rather than forwarded unredacted; the re-serialized output
        // is BOM-free valid JSON.
        //
        // Defence in depth: `on_response_body` already fails closed on an
        // ambiguous governed body, but a later transform could hand this hook
        // different bytes. Clearing the skip ledgers (rather than returning a
        // silent `None`, which would forward the body unredacted and let the
        // terminal re-check hash-skip it) routes the ambiguity to
        // `on_final_response_body`, which fails closed — the same recovery the
        // serialization-overflow branch below uses. Use the shared per-request
        // memo (exact BOM-stripped bytes as key) like every other
        // context-bearing screen on this plugin.
        if ctx.json_scan_memo.ambiguity(strip_json_bom(body)).is_some() {
            self.clear_response_hash(ctx);
            ctx.ai_tool_governor_call_hashes.remove(&self.instance_id);
            return None;
        }
        let mut json: Value = serde_json::from_slice(strip_json_bom(body)).ok()?;
        // Consume the preflight memo with the rewrite attempt so hostile
        // redacted arguments are not retained after the transform installs
        // them (or after AmplificationFailed clears skip state).
        let redaction_memos = ctx
            .ai_tool_governor_redaction_memos
            .remove(&self.instance_id);
        match self.redact_response(&mut json, redaction_memos.as_ref()) {
            RedactTransform::Changed => {
                let rewritten = match serialize_json_bounded(&json) {
                    Ok(rewritten) => rewritten,
                    Err(()) => {
                        // A JSON string may require escaping on serialization,
                        // so even an aggregate argument payload at the byte cap
                        // can exceed the final body limit. Clear the skip state
                        // and let the terminal re-check fail closed.
                        self.clear_response_hash(ctx);
                        ctx.ai_tool_governor_call_hashes.remove(&self.instance_id);
                        return None;
                    }
                };
                // Record the redacted body's hash so `on_final_response_body` treats
                // this plugin's own redaction as already-governed and skips it when
                // no later transform runs. Also re-record the redacted calls'
                // identity hashes (with the same per-policy identity rules and
                // counts as `on_response_body`) so that even if a later transform
                // changes the body hash or only the model/provider, the final
                // re-check skips these already-redacted calls. Approval-capable
                // siblings keep their correlation-aware identities and still
                // require re-approval when those fields change.
                self.set_response_hash(ctx, sha256_hex_bytes(&rewritten));
                let provider = self.resolve_response_provider(ctx, &json);
                let model = json
                    .get("model")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let corr = self.correlation(ctx, model, provider.as_deref());
                self.record_governed_calls(ctx, &corr, &extract_response_tool_calls(&json).0);
                Some(rewritten)
            }
            RedactTransform::AmplificationFailed => {
                // Do not forward unredacted secrets under a skipped final
                // re-check: clear the governed hash and call-identity ledger so
                // `on_final_response_body` re-evaluates with redaction
                // unavailable and fails closed.
                self.clear_response_hash(ctx);
                ctx.ai_tool_governor_call_hashes.remove(&self.instance_id);
                None
            }
            RedactTransform::Unchanged => None,
        }
    }

    fn on_response_body_transformed(
        &self,
        _ctx: &mut RequestContext,
        response_headers: &mut HashMap<String, String>,
    ) {
        // Lifecycle `finalize_response_body_transformation` already invalidates
        // content-bound validators before this hook. Re-run for defense in depth
        // and for direct unit-test callers that exercise the plugin hook alone:
        // a `redact_args` rewrite must never leave ETag / Content-Digest /
        // Repr-Digest / Last-Modified describing the pre-redaction bytes.
        super::invalidate_content_bound_response_headers(response_headers);
    }

    fn requires_replay_response_body_transform(&self, ctx: &RequestContext) -> bool {
        ctx.ai_tool_governor_replay_redactions
            .contains(&self.instance_id)
    }

    /// Re-run the deterministic response policy on the FINAL client-visible body.
    ///
    /// `on_response_body` governs the raw backend body, but `response_transformer`
    /// (4000) and other `transform_response_body` hooks run afterward and can add
    /// or rewrite JSON fields — injecting a denied `choices[].message.tool_calls[]`
    /// into a response the governor already cleared. This hook re-evaluates the
    /// final body so such an injection is fail-closed before delivery. When a
    /// later transform (e.g. the `compression` plugin) encoded the body, it is
    /// decompressed with the gateway's own encoding and re-checked, so an
    /// injected-then-compressed tool call cannot slip through. Redaction is no
    /// longer possible on this path (the redaction transform already ran), so a
    /// `redact_args` match here fails closed rather than forwarding the secret.
    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.enabled || !self.inspect.any_buffered_response() {
            return PluginResult::Continue;
        }
        if !(200..300).contains(&response_status) {
            return PluginResult::Continue;
        }
        if body.is_empty() {
            return PluginResult::Continue;
        }

        // Unchanged since `on_response_body` governed the raw backend body: no
        // transform rewrote it, so re-governing would only risk a duplicate
        // approval webhook. This hash-skip runs BEFORE the `governs_buffered_json`
        // gate so an unchanged SSE body — governed by `on_response_body` when the
        // buffering came from OUTSIDE this plugin, regardless of whether the
        // request was streaming — is not re-governed (no duplicate webhook).
        let final_hash = sha256_hex_bytes(body);
        if self.response_hash(ctx) == Some(final_hash.as_str()) {
            return PluginResult::Continue;
        }

        let content_type = header_value(response_headers, "content-type").unwrap_or("");
        // Framed gRPC/gRPC-Web wire frames are out of scope on the final
        // re-check too (same gate as `on_response_body`): a buffered framed
        // body must not be size- or shape-rejected by a governor that never
        // inspects it.
        if is_framed_grpc_content_type(content_type) {
            return PluginResult::Continue;
        }
        let json_ct = is_json_content_type(content_type);

        // Buffered-SSE parity for the final re-check (mirrors
        // `on_response_body`), shape first then label: a transform can rewrite
        // an SSE body (hash changed above) or strip/relabel its content type,
        // so an SSE-SHAPED unencoded final body — or an SSE-LABELED one that
        // is not JSON-shaped — is re-governed through the buffered-SSE path
        // with the same fail-closed semantics (ungovernable calls,
        // redact-unavailable). An SSE-labeled JSON-SHAPED body is mislabeled
        // Chat Completions JSON and falls through to the JSON re-check below
        // instead of bypassing it. Encoded bytes never look like SSE; the
        // content-encoding branch below applies the same checks to the
        // DECODED bytes.
        //
        // This SSE branch runs BEFORE the `governs_buffered_json` gate below,
        // exactly as `on_response_body` routes `looks_like_sse` bodies before
        // its own `governs_buffered_json` gate: an SSE body buffered OUTSIDE
        // this plugin (a `response_transformer` body rule, `response_body_mode:
        // Buffer`, or another plugin) is governed regardless of whether the
        // request was streaming, so a later transform that injects/relabels an
        // SSE `data:` frame with a denied tool call — even when only
        // `streaming_response_tool_calls` is enabled and the request is
        // non-streaming — is fail-closed re-checked here instead of escaping via
        // the JSON-fallback streaming gate.
        if content_encoding_value(response_headers).is_none()
            && (looks_like_sse(body)
                || (is_event_stream_content_type(content_type) && !looks_like_json(body)))
        {
            return self.govern_buffered_sse(ctx, body).await;
        }

        // Encoded-SSE parity for the final re-check, BEFORE the
        // `governs_buffered_json` gate — the encoded mirror of the unencoded
        // SSE branch above. Compressed bytes never look like SSE, so the
        // decoded-shape check must run on the DECODED bytes; but a blanket
        // decode-before-gate would add a decompress to every ordinary
        // non-streaming JSON response. Scope it to the ONLY case that needs it:
        // an encoded body under a config that governs STREAMING tool calls.
        // There a later transform can inject an SSE `data:` frame with a denied
        // call AND compress it (e.g. under a compressible `text/plain` relabel)
        // on a NON-streaming request, where `governs_buffered_json` is false —
        // so the decoded `looks_like_sse` check below would never be reached and
        // the injected-then-compressed call would escape governance. Ordinary
        // `response_tool_calls` JSON traffic keeps decoding on its own branch
        // (after the gate), so it is not decoded twice here.
        //
        // The single decode performed here is REUSED by the JSON re-check below
        // (threaded through `decoded_encoded`) so an encoded body is never
        // decompressed twice.
        //
        // Any encoded body on this streaming-governance path that cannot be
        // decoded is uninspectable regardless of its label. A relabel such as
        // `text/plain` cannot prove the opaque bytes do not contain denied SSE
        // frames, so reject before the JSON-only request gate below.
        let wire_encoding = content_encoding_value(response_headers);
        let mut decoded_encoded: Option<Vec<u8>> = None;
        if let Some(encoding) = wire_encoding
            && self.inspect.streaming_response_tool_calls
        {
            if let Some(decoded) = decompress_within_limit(encoding, body) {
                // Compression-only rewrite of an already-governed body: decoded
                // bytes match the recorded hash, so skip (no duplicate approval
                // webhook), regardless of the request-streaming gate.
                if self.response_hash(ctx) == Some(sha256_hex_bytes(&decoded).as_str()) {
                    return PluginResult::Continue;
                }
                // Encoded-SSE shape check on the DECODED bytes, ungated by
                // `governs_buffered_json` — matching the unencoded SSE branch. An
                // SSE-labeled body that decodes to JSON-shaped bytes is mislabeled
                // Chat Completions JSON and takes the gated JSON re-check instead.
                if looks_like_sse(&decoded)
                    || (is_event_stream_content_type(content_type) && !looks_like_json(&decoded))
                {
                    return self.govern_buffered_sse(ctx, &decoded).await;
                }
                // Not SSE-shaped: keep the decoded bytes for the JSON re-check below
                // (which is gated) so the body is not decompressed a second time.
                decoded_encoded = Some(decoded);
            } else {
                return self.uninspectable_governed_response(
                    ctx,
                    "SSE response body has a content-encoding that cannot be inspected",
                );
            }
        }

        // Mirror `on_response_body`'s post-SSE gate: a streaming-only config
        // re-checks a buffered JSON body (and the encoded-body decode below)
        // only for a streaming request's SSE fallback, never an ordinary
        // non-streaming JSON response. The SSE-shaped/labelled branches above are
        // deliberately NOT gated by this, matching `on_response_body`.
        if !self.governs_buffered_json(ctx) {
            return PluginResult::Continue;
        }

        // Plaintext parse first: covers unencoded bodies and a spurious
        // `Content-Encoding` header a header rule added without encoding the
        // bytes. Header relabeling must not disable the re-check, so a
        // JSON-shaped body is inspected even when a transform rewrote the
        // content type (mirrors `on_response_body`).
        if json_ct || looks_like_json(body) {
            // Duplicate-member screen of the client-visible bytes before the
            // terminal re-check evaluates them.
            if body.len() <= MAX_PARSE_BYTES
                && ctx.json_scan_memo.ambiguity(strip_json_bom(body)).is_some()
            {
                return self.uninspectable_governed_response(ctx, AMBIGUOUS_RESPONSE_JSON);
            }
            if let Some(json) = parse_json_within_limit(body) {
                return self.govern_final_response(ctx, &json).await;
            }
        }

        // When a later transform encoded the final body (e.g. the `compression`
        // plugin — which compresses `text/*` too), decode FIRST and gate on the
        // DECODED bytes: compressed bytes never look like JSON, so gating on
        // the encoded bytes plus a relabeled `Content-Type` would skip the
        // re-check entirely and forward an injected-then-compressed denied
        // call uninspected.
        if let Some(encoding) = wire_encoding {
            // Reuse the decode already performed for the encoded-SSE check when a
            // streaming-governing config took that path; otherwise (a
            // `response_tool_calls`-only config) decode now, here, on its own
            // branch — so ordinary non-streaming JSON traffic is not decoded
            // before the gate above.
            let decoded = match decoded_encoded {
                Some(decoded) => decoded,
                None => {
                    let Some(decoded) = decompress_within_limit(encoding, body) else {
                        // Unsupported/undecodable encoding (`deflate`/`zstd`,
                        // corrupt gzip/br), or decoded output past the parse
                        // limit: cannot verify a later transform did not inject a
                        // governed call. Header-time buffering already treated
                        // every non-framed-gRPC label (JSON, SSE, `text/plain`,
                        // missing, relabeled) as governable on this route, so the
                        // same posture applies here: fail closed in enforce mode,
                        // forward in dry-run — a relabel must not downgrade an
                        // uninspectable encoded body from fail-closed to forward.
                        // Framed gRPC/gRPC-Web wire frames already returned at the
                        // top of this hook and never reach this posture.
                        return self.uninspectable_governed_response(
                            ctx,
                            "response body has a content-encoding that cannot be inspected",
                        );
                    };
                    decoded
                }
            };
            // Compression-only rewrite of an already-governed body: the decoded
            // bytes match the hash `on_response_body` recorded, so skip to avoid
            // a duplicate approval webhook (which a one-shot approval service
            // could deny, turning an allowed response into a 502). (Already
            // checked for the streaming-config early-decode path above; repeated
            // here for the `response_tool_calls`-only decode-now path.)
            if self.response_hash(ctx) == Some(sha256_hex_bytes(&decoded).as_str()) {
                return PluginResult::Continue;
            }
            // Buffered-SSE parity on the DECODED bytes: a compressed SSE body
            // (the `compression` plugin compresses `text/*` too) must be
            // re-governed, not skipped by the JSON-shape gate below — while an
            // SSE-labeled body that decodes to JSON-shaped bytes is mislabeled
            // Chat Completions JSON and takes the JSON re-check instead. (A
            // streaming-governing config already handled the SSE shape above;
            // this covers the `response_tool_calls`-only decode-now path.)
            if looks_like_sse(&decoded)
                || (is_event_stream_content_type(content_type) && !looks_like_json(&decoded))
            {
                return self.govern_buffered_sse(ctx, &decoded).await;
            }
            // Content-type / JSON-shape gates against the DECODED bytes.
            if !json_ct && !looks_like_json(&decoded) {
                return PluginResult::Continue;
            }
            // Duplicate-member screen on the DECODED client-visible bytes.
            if ctx
                .json_scan_memo
                .ambiguity(strip_json_bom(&decoded))
                .is_some()
            {
                return self.uninspectable_governed_response(ctx, AMBIGUOUS_RESPONSE_JSON);
            }
            let Some(json) = parse_json_within_limit(&decoded) else {
                // Decoded but oversized or not parseable JSON: cannot verify a
                // transform did not inject a governed call.
                return self.uninspectable_governed_response(
                    ctx,
                    "response body could not be inspected after decoding",
                );
            };
            return self.govern_final_response(ctx, &json).await;
        }

        // Unencoded and not parseable plaintext JSON.
        if !json_ct && !looks_like_json(body) {
            // Plaintext but not JSON: `on_response_body` already governed the
            // original backend body.
            return PluginResult::Continue;
        }
        if body.len() > MAX_PARSE_BYTES {
            // A later transform grew the (hash-changed) plaintext body past the
            // inspectable limit: fail closed like the `on_response_body` path so
            // padding cannot smuggle a denied tool call past enforce policy.
            return self.uninspectable_governed_response(
                ctx,
                "response body exceeds the inspectable size limit after transforms",
            );
        }
        // JSON-labeled/shaped but unparseable plaintext within the limit:
        // forward, mirroring `on_response_body` (rejecting every unparseable
        // JSON-labeled response on a shared proxy would break unrelated routes).
        PluginResult::Continue
    }

    // --- Streaming response path ------------------------------------------

    fn requires_response_stream_hooks(&self) -> bool {
        self.enabled && self.inspect.streaming_response_tool_calls
    }

    fn forces_reqwest_dispatch(&self, ctx: &RequestContext) -> bool {
        // Prefer reqwest for requests already known to produce inspected SSE.
        // Inspector correctness no longer depends on this pin: direct-H2 and
        // native-H3 response arms drive the same inspector chain.
        self.enabled
            && self.inspect.streaming_response_tool_calls
            && (is_sse_request(ctx)
                || ctx.metadata.get("ai_request_streaming").map(String::as_str) == Some("true")
                || ctx.metadata.get(STREAM_REQUESTED_KEY).map(String::as_str) == Some("true"))
    }

    /// The streaming inspector accumulates OpenAI-shaped SSE
    /// `choices[].delta.tool_calls`. LIMITATION: `ai_stream_router` (2984)
    /// normalizes provider-native streaming (e.g. Anthropic `tool_use` /
    /// `input_json_delta`) into OpenAI chunks in a stream inspector that runs
    /// AFTER this one (2978 < 2984), so on those routes the governor sees only
    /// raw provider frames it does not recognize as tool calls. Deterministic
    /// mid-stream tool governance therefore covers OpenAI-native SSE; buffered
    /// (non-streaming) responses are governed for every provider, and
    /// provider-native streaming governance is tracked as a follow-up (it would
    /// require the governor to understand each provider's native tool events or
    /// to run after normalization). Reordering is not an option here: 2978 is
    /// deliberately before semantic cache/federation on the request path.
    ///
    /// The proxy drives this inspector on reqwest, direct-H2, and native-H3
    /// streaming responses. Request-body transforms are finalized before the
    /// response buffer/stream and transport decisions, so a transformed
    /// `stream` marker is visible to both policy checks.
    fn response_stream_inspector(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        if !self.enabled || !self.inspect.streaming_response_tool_calls {
            return None;
        }
        if !(200..300).contains(&response_status) {
            return None;
        }
        // Attach on an SSE label (the normal case) — and ALSO on a
        // STREAM-MARKED governed request regardless of the response content
        // type: a `request_transformer` can add `"stream": true` AFTER the
        // proxy's buffer/dispatch decisions, so the backend's plain
        // `application/json` SSE fallback (which can carry denied
        // `choices[].message.tool_calls[]`) is delivered on the STREAMING
        // path where the buffered hooks never run. The shape sniff then
        // routes a JSON-shaped stream into hold-in-full/govern-at-EOF, real
        // SSE into normal streaming governance, and opaque bytes fail closed
        // — so the widened attach never weakens inspection. The stream-marker
        // gate keeps ordinary non-streaming traffic inspector-free, and
        // framed gRPC/gRPC-Web wire frames stay out of scope (owned by the
        // gRPC machinery — attaching would opaque-cut them in enforce).
        if !content_type.is_some_and(is_event_stream_content_type) {
            if !request_is_streaming(ctx) {
                return None;
            }
            if content_type.is_some_and(is_framed_grpc_content_type) {
                return None;
            }
        }
        let model = ctx
            .metadata
            .get(STREAM_MODEL_KEY)
            .or_else(|| ctx.metadata.get("ai_model"))
            .cloned();
        let provider = federation_provider(ctx);
        let corr = self.correlation(ctx, model, provider.as_deref());
        let stream_metadata = if self.engine.observability.emit_metadata
            && let Some(stream_id) = ctx.response_stream_id()
        {
            let slot = Arc::new(std::sync::Mutex::new(HashMap::new()));
            self.pending_stream_metadata
                .insert(stream_id, Arc::clone(&slot));
            Some(slot)
        } else {
            None
        };
        Some(Box::new(ToolCallStreamInspector::new(
            Arc::clone(&self.engine),
            corr,
            Arc::clone(&ctx.plugin_http_call_ns),
            stream_metadata,
        )))
    }

    async fn on_response_stream_terminated(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        _outcome: &crate::proxy::deferred_log::BodyOutcome,
    ) {
        if !self.engine.observability.emit_metadata {
            return;
        }
        let Some(stream_id) = ctx.response_stream_id() else {
            return;
        };
        let Some((_, slot)) = self.pending_stream_metadata.remove(&stream_id) else {
            return;
        };
        let pending = match slot.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        Self::merge_stream_metadata(&mut ctx.metadata, &pending);
    }
}

/// Test-only observability — exposed for unit tests (the approval cache is
/// otherwise unobservable from outside the plugin).
#[doc(hidden)]
#[allow(dead_code)] // used only by tests/, dead code in the bin target
impl AiToolGovernor {
    pub fn approval_cache_len(&self) -> usize {
        self.engine.approval_cache.len()
    }

    pub fn approval_cache_max_entries() -> usize {
        MAX_APPROVAL_CACHE_ENTRIES
    }

    pub fn pending_stream_metadata_len(&self) -> usize {
        self.pending_stream_metadata.len()
    }

    /// Production whole-batch approval deadline ceiling (exactly 30s).
    pub fn max_approval_batch_deadline() -> Duration {
        MAX_APPROVAL_BATCH_DEADLINE
    }

    /// Advance the approval-batch deadline clock without sleeping. Used to
    /// prove cumulative budget exhaustion deterministically while the
    /// production ceiling remains [`MAX_APPROVAL_BATCH_DEADLINE`].
    pub fn advance_approval_clock_for_tests(&self, duration: Duration) {
        let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let _ = self.engine.approval_clock_offset_ms.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_add(millis)),
        );
    }
}

// ---------------------------------------------------------------------------
// Streaming inspector
// ---------------------------------------------------------------------------

/// Slot for one accumulating call within a choice: an indexed
/// `delta.tool_calls[]` entry, or the single implicit call the legacy
/// `functions` API streams as `delta.function_call`. A distinct variant (not a
/// sentinel tool index) so a hostile `tool_calls[].index` can never collide
/// with — and merge into — the legacy slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ToolSlot {
    Indexed(usize),
    LegacyFunctionCall,
}

/// Accumulates OpenAI streaming tool-call deltas — modern
/// `choices[].delta.tool_calls` and the legacy `choices[].delta.function_call`
/// (one implicit call per choice) — into complete tool calls, keyed by
/// `(choice_index, slot)` with a positional fallback when `index` is absent.
#[derive(Default)]
struct StreamingToolCallAccumulator {
    calls: Vec<((usize, ToolSlot), StreamingCall)>,
    positions: HashMap<(usize, ToolSlot), usize>,
    /// A frame carried a MALFORMED `tool_calls` container (present but not a
    /// JSON array): its entries cannot be accumulated, so the batch is
    /// ungovernable — the SSE mirror of the buffered `extract_response_tool_calls`
    /// non-array case (round 10). Enforce cuts the stream; dry-run releases.
    malformed: bool,
}

#[derive(Default)]
struct StreamingCall {
    name: String,
    arguments: String,
    /// Stable protocol call id observed for this slot, when present.
    call_id: Option<String>,
    /// Whether any fragment has already been accumulated for this slot. An ID
    /// introduced only after an untagged fragment is an identity change, not a
    /// stable initial identity; fail closed rather than merge the two shapes.
    saw_fragment: bool,
    /// A tool-call delta supplied `function.arguments` as a non-string JSON
    /// value (object/array/number). Those bytes are not accumulated, so the
    /// call cannot be policy-checked and must be treated as ungovernable.
    non_string_args: bool,
    /// True when this slot saw conflicting call ids, an id change, or a
    /// duplicate index in a single frame — fail closed rather than merging
    /// distinct calls into one synthetic policy identity.
    ambiguous_identity: bool,
}

impl StreamingToolCallAccumulator {
    fn push_frame(&mut self, frame: &Value) {
        let Some(choices) = frame.get("choices").and_then(Value::as_array) else {
            return;
        };
        // Length ≤ 1 cannot contain a duplicate index; skip the set entirely.
        let mut seen_choice_indexes =
            (choices.len() > 1).then(|| HashSet::with_capacity(choices.len()));
        for (cpos, choice) in choices.iter().enumerate() {
            let cidx = choice
                .get("index")
                .and_then(Value::as_u64)
                .and_then(|v| usize::try_from(v).ok())
                .unwrap_or(cpos);
            if let Some(seen) = seen_choice_indexes.as_mut()
                && !seen.insert(cidx)
            {
                self.malformed = true;
            }
            let delta = choice.get("delta");
            let tool_calls =
                match classify_tool_calls_container(delta.and_then(|d| d.get("tool_calls"))) {
                    ToolCallsContainer::Array(items) => items,
                    // Present but not an array: cannot be accumulated. Flag the
                    // batch ungovernable (mirrors the buffered non-array case) so
                    // `finalize_checked()` fails closed in enforce.
                    ToolCallsContainer::Malformed => {
                        self.malformed = true;
                        &[]
                    }
                    ToolCallsContainer::None => &[],
                };
            // Duplicate `(choice, tool_index)` entries inside one frame are
            // ambiguous: concatenating them would merge independently addressed
            // calls (often with distinct ids) into one synthetic identity.
            // Length ≤ 1 cannot duplicate; skip the set allocation.
            let mut seen_indexes =
                (tool_calls.len() > 1).then(|| HashSet::with_capacity(tool_calls.len()));
            for (tpos, tc) in tool_calls.iter().enumerate() {
                let tidx = tc
                    .get("index")
                    .and_then(Value::as_u64)
                    .and_then(|v| usize::try_from(v).ok())
                    .unwrap_or(tpos);
                if let Some(seen) = seen_indexes.as_mut()
                    && !seen.insert(tidx)
                {
                    self.malformed = true;
                }
                let function = tc.get("function");
                let call_id = match tc.get("id") {
                    // Omitted and JSON null are the same continuation shape.
                    None | Some(Value::Null) => None,
                    Some(Value::String(id)) if !id.is_empty() => Some(id.as_str()),
                    // A present but empty/non-string identity is not the same as
                    // an omitted continuation fragment. Treat it as malformed
                    // so a backend cannot hide an index reuse behind an id the
                    // downstream runtime may interpret differently.
                    Some(_) => {
                        self.malformed = true;
                        None
                    }
                };
                self.push_delta(
                    cidx,
                    ToolSlot::Indexed(tidx),
                    call_id,
                    function.and_then(|f| f.get("name")),
                    function.and_then(|f| f.get("arguments")),
                );
            }
            // Legacy `functions` API: a backend streams the single implicit
            // call per choice as `delta.function_call` `{name, arguments}`
            // string deltas instead of `delta.tool_calls`. Accumulate it as a
            // governed call in its own slot so a denied legacy function call
            // cannot stream past the hold/deny/approval path ungoverned.
            if let Some(fc) = delta
                .and_then(|d| d.get("function_call"))
                .filter(|fc| !fc.is_null())
            {
                self.push_delta(
                    cidx,
                    ToolSlot::LegacyFunctionCall,
                    None,
                    fc.get("name"),
                    fc.get("arguments"),
                );
            }
        }
    }

    /// Accumulate one name/arguments delta onto the `(choice, slot)` call.
    /// A non-string name is ignored (the call stays never-named and therefore
    /// ungovernable); arguments present but not a string mean the bytes are not
    /// accumulated, so the call is marked ungovernable rather than evaluated
    /// against empty args. Conflicting or changing call ids mark the slot
    /// ambiguous so enforce mode fails closed instead of merging identities.
    fn push_delta(
        &mut self,
        choice: usize,
        slot: ToolSlot,
        call_id: Option<&str>,
        name: Option<&Value>,
        args: Option<&Value>,
    ) {
        let name_str = name.and_then(Value::as_str);
        let args_str = args.and_then(Value::as_str);
        let non_string_args = args.is_some() && args_str.is_none();
        let entry = self.entry(choice, slot);
        if let Some(id) = call_id.filter(|id| !id.is_empty()) {
            match &entry.call_id {
                None => {
                    if entry.saw_fragment {
                        entry.ambiguous_identity = true;
                    }
                    entry.call_id = Some(id.to_string());
                }
                Some(existing) if existing == id => {}
                Some(_) => entry.ambiguous_identity = true,
            }
        }
        if let Some(name) = name_str {
            entry.name.push_str(name);
        }
        if let Some(args) = args_str {
            entry.arguments.push_str(args);
        }
        if non_string_args {
            entry.non_string_args = true;
        }
        entry.saw_fragment = true;
    }

    fn entry(&mut self, choice: usize, slot: ToolSlot) -> &mut StreamingCall {
        let key = (choice, slot);
        let pos = match self.positions.get(&key).copied() {
            Some(pos) => pos,
            None => {
                let pos = self.calls.len();
                self.calls.push((key, StreamingCall::default()));
                self.positions.insert(key, pos);
                pos
            }
        };
        &mut self.calls[pos].1
    }

    /// Whether any delta has been accumulated for this choice index.
    fn has_choice(&self, choice: usize) -> bool {
        self.calls.iter().any(|((c, _), _)| *c == choice)
    }

    /// Whether every choice that produced tool-call deltas is in `finished`.
    fn choices_finished(&self, finished: &std::collections::HashSet<usize>) -> bool {
        self.calls.iter().all(|((c, _), _)| finished.contains(c))
    }

    /// Authoritative checked finalization for a sealed batch: each accumulated
    /// call's `arguments` string is screened for duplicate-member ambiguity at
    /// most once. Returns `Err` (ungovernable) when any call cannot be
    /// policy-checked — malformed container, missing name, non-string args,
    /// ambiguous identity, or duplicate-member arguments — otherwise the built
    /// governable calls. Both the live streaming finalizer and the buffered-SSE
    /// batch sealer consult this single choke point so their ungovernable
    /// semantics and argument-scan cost cannot drift. Duplicate-key argument
    /// failures are distinguished so dry-run can record an ambiguity
    /// observation without claiming enforcement.
    fn finalize_checked(&self) -> Result<Vec<ToolCall>, CheckedFinalizeError> {
        if self.malformed {
            return Err(CheckedFinalizeError::Ungovernable);
        }
        let mut out = Vec::with_capacity(self.calls.len());
        for (_, c) in &self.calls {
            if c.name.is_empty() || c.non_string_args || c.ambiguous_identity {
                return Err(CheckedFinalizeError::Ungovernable);
            }
            // One ambiguity scan per call: an ambiguous arguments document
            // makes the whole batch ungovernable (same class as a missing name).
            if json_dup_keys::str_ambiguity(&c.arguments).is_some() {
                return Err(CheckedFinalizeError::AmbiguousArguments);
            }
            out.push(ToolCall {
                name: c.name.clone(),
                parsed_args: serde_json::from_str(&c.arguments).ok(),
                args_ambiguous: false,
                raw_args: c.arguments.clone(),
            });
        }
        Ok(out)
    }
}

/// Why a sealed streaming batch cannot be policy-checked.
enum CheckedFinalizeError {
    /// At least one call's `arguments` JSON string carries duplicate object
    /// member names (advisory `GHSA-c78j-5w9p-cpq6`).
    AmbiguousArguments,
    /// Missing name, non-string args, malformed container, or ambiguous
    /// identity — generic ungovernable, distinct from duplicate-key ambiguity.
    Ungovernable,
}

/// Result of finalizing accumulated tool calls at a completion boundary.
enum Finalize {
    /// Held tool-call bytes were appended to the output; keep streaming.
    Released,
    /// Policy blocked: held bytes dropped; the caller must terminate the stream.
    Blocked,
}

/// Body shape of an inspected stream, sniffed once from the leading bytes via
/// [`sniff_stream_shape`] (ordinary SSE latency is untouched — no per-chunk
/// re-scan). A `text/event-stream`-labeled response can actually be a Chat
/// Completions JSON body a `response_transformer` relabeled: forwarding those
/// bytes as ordinary non-SSE trailing data would deliver a denied
/// `tool_calls[]` ungoverned, so a JSON-shaped stream (`{`/`[`) is held in
/// full and governed at end-of-stream like a buffered JSON body. Leading
/// bytes that are neither SSE-shaped nor JSON-shaped (gzip magic, other
/// compressed/binary output) mean the stream can never be inspected as SSE
/// and is held in full: enforce mode fails closed at end-of-stream, dry-run
/// releases it unchanged.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamBodyShape {
    /// Too few bytes to classify yet (whitespace, a partial BOM, an incomplete
    /// field line, or only colonless extension fields so far): hold until the
    /// shape resolves.
    Unknown,
    /// SSE-shaped: the normal SSE framing path.
    Sse,
    /// JSON-shaped: hold the whole body, govern at end-of-stream.
    Json,
    /// Neither SSE- nor JSON-shaped (e.g. compressed bytes whose
    /// `Content-Encoding` a transform stripped, or arbitrary binary under an
    /// SSE label): uninspectable — hold the whole body, fail closed at
    /// end-of-stream in enforce mode, release unchanged in dry-run.
    Opaque,
}

/// Shape verdict from sniffing the leading bytes of an inspected stream.
enum StreamSniff {
    /// Not enough bytes to decide yet.
    Inconclusive,
    Json,
    Sse,
    Opaque,
}

/// Sniff the body shape from the leading bytes. Real SSE always begins with a
/// syntactically valid field or comment line after an optional UTF-8 BOM and
/// leading whitespace. A field may omit `:` (its value is then empty), so
/// printable ASCII extension fields such as `x` are skipped until a later
/// colon-bearing or standard colonless field proves the body is SSE. An SSE
/// field name (`data`/`event`/`id`/`retry`, or empty for a `:comment`) is pure
/// ASCII, so every scanned field-name prefix must be ASCII too. The SSE spec
/// ignores unknown field names, so legitimate providers may also open streams
/// with extension/heartbeat lines like `ping: 1`.
/// Leading bytes that are binary (gzip magic, control bytes, or a HIGH-BIT
/// non-ASCII byte before the first `:`) — and not opening a JSON object/array —
/// can never yield a governable SSE event. A high-bit byte before the colon is
/// REQUIRED to opaque-classify (not
/// fall through as "text"): otherwise a `Content-Encoding`-stripped compressed
/// stream whose first bytes happen to carry a `:` before any newline would
/// pass uninspected in enforce. (Accepted consequence: colon-containing ASCII
/// plaintext under an SSE label is parsed as SSE — no `data:` frames, forwarded
/// — the pre-round-12 behavior for that shape; fail-closed opaque treatment is
/// reserved for binary/non-ASCII starts.)
fn sniff_stream_shape(buf: &[u8]) -> StreamSniff {
    const BOM: &[u8] = b"\xEF\xBB\xBF";
    // The buffer so far is a (possibly empty) prefix of the BOM: wait.
    if BOM.starts_with(buf) {
        return StreamSniff::Inconclusive;
    }
    let buf = buf.strip_prefix(BOM).unwrap_or(buf);
    let Some(start) = buf.iter().position(|b| !b.is_ascii_whitespace()) else {
        return StreamSniff::Inconclusive;
    };
    if matches!(buf[start], b'{' | b'[') {
        return StreamSniff::Json;
    }

    let mut cursor = start;
    while cursor < buf.len() {
        let line_start = cursor;
        while cursor < buf.len() {
            match buf[cursor] {
                // A field separator before the line ends proves SSE framing,
                // including extension fields and comment lines.
                b':' => return StreamSniff::Sse,
                b'\r' | b'\n' => break,
                // Control/binary or high-bit bytes cannot be an ASCII field
                // name. `\t` (0x09) remains accepted for parity with the
                // existing conservative shape detector.
                0x00..=0x08 | 0x0B..=0x1F | 0x7F..=0xFF => {
                    return StreamSniff::Opaque;
                }
                _ => cursor += 1,
            }
        }

        if cursor == buf.len() {
            // Still inside a printable line with no separator. It may be an
            // unknown colonless prelude followed by an SSE field in a later
            // chunk, so keep holding until more bytes arrive.
            return StreamSniff::Inconclusive;
        }

        let field = &buf[line_start..cursor];
        if matches!(field, b"data" | b"event" | b"id" | b"retry") {
            return StreamSniff::Sse;
        }

        // Unknown colonless fields and blank event separators are valid SSE
        // syntax but do not alone distinguish SSE from arbitrary text. Skip
        // them and look for a later field that supplies positive evidence.
        while cursor < buf.len() && matches!(buf[cursor], b'\r' | b'\n') {
            cursor += 1;
        }
        if cursor < buf.len() && matches!(buf[cursor], b'{' | b'[') {
            return StreamSniff::Opaque;
        }
    }

    // Only colonless extension/blank lines have arrived so far. A later chunk
    // can still provide an SSE field; the retained-body cap bounds the wait.
    StreamSniff::Inconclusive
}

/// Per-response streaming inspector. Holds tool-call SSE frames until the call
/// is complete and cleared by policy/approval, then releases them — or cuts the
/// stream with an SSE error event, never leaking the held frames.
struct ToolCallStreamInspector {
    engine: Arc<GovernorEngine>,
    corr: CorrelationMeta,
    plugin_http_call_ns: Arc<AtomicU64>,
    /// Shared only with this plugin instance's terminal-hook entry. Written at
    /// completed policy-batch boundaries, never on the per-chunk path.
    stream_metadata: Option<StreamMetadataSlot>,
    /// Raw bytes received but not yet a complete SSE event.
    carry: Vec<u8>,
    /// Raw bytes of held (un-released) events, in arrival order. Contains the
    /// pending batch's tool-call frames AND every event received after the
    /// batch opened (content frames of other choices, keepalives, comments):
    /// releasing only tool frames would reorder an allowed multi-choice
    /// stream, and forwarding non-tool events live would leak content that
    /// arrived after a subsequently-denied tool call.
    held: Vec<u8>,
    accumulator: StreamingToolCallAccumulator,
    saw_tool_calls: bool,
    /// Choice indices that reported a non-null `finish_reason` while holding
    /// tool-call deltas. Only choices already present in the accumulator are
    /// tracked, so this set is bounded by the held-bytes cap.
    finished_choices: std::collections::HashSet<usize>,
    /// Set in dry-run mode when the hold cap overflowed: forward everything
    /// uninspected instead of disrupting traffic.
    bypassed: bool,
    terminated: bool,
    /// Sniffed body shape (see [`StreamBodyShape`]).
    shape: StreamBodyShape,
}

impl ToolCallStreamInspector {
    fn new(
        engine: Arc<GovernorEngine>,
        corr: CorrelationMeta,
        plugin_http_call_ns: Arc<AtomicU64>,
        stream_metadata: Option<StreamMetadataSlot>,
    ) -> Self {
        Self {
            engine,
            corr,
            plugin_http_call_ns,
            stream_metadata,
            carry: Vec::new(),
            held: Vec::new(),
            accumulator: StreamingToolCallAccumulator::default(),
            saw_tool_calls: false,
            finished_choices: std::collections::HashSet::new(),
            bypassed: false,
            terminated: false,
            shape: StreamBodyShape::Unknown,
        }
    }

    /// Record which choices this frame finishes. Only choices that actually
    /// hold tool-call deltas are tracked — a hostile stream of synthetic
    /// finish frames for unrelated choice indices cannot grow the set.
    fn record_finished_choices(&mut self, frame: &Value) {
        collect_finished_choices(frame, &self.accumulator, &mut self.finished_choices);
    }

    /// Whether the accumulated batch is complete: every choice that produced
    /// tool-call deltas has reported a `finish_reason`. With `n > 1` streamed
    /// choices, finalizing on the FIRST finish would drop (and leave
    /// ungoverned) tool-call deltas another choice streams afterwards.
    fn batch_complete(&self) -> bool {
        self.saw_tool_calls && self.accumulator.choices_finished(&self.finished_choices)
    }

    /// Reset per-batch state after a release so any later tool-call deltas
    /// form a new, independently governed batch instead of vanishing.
    fn reset_batch(&mut self) {
        self.accumulator = StreamingToolCallAccumulator::default();
        self.finished_choices.clear();
        self.saw_tool_calls = false;
    }

    fn record_frame_context(&mut self, frame: &Value) {
        if self.corr.model.is_none()
            && let Some(model) = frame.get("model").and_then(Value::as_str)
        {
            self.corr.model = Some(model.to_string());
        }
        if self.corr.provider.is_none()
            && let Some(provider) = detect_sse_provider(frame)
        {
            self.corr.provider = Some(provider.as_str().to_string());
        }
    }

    fn record_metadata(&self, batch: &BatchDecision) {
        let Some(slot) = &self.stream_metadata else {
            return;
        };
        match slot.lock() {
            Ok(mut metadata) => {
                AiToolGovernor::write_metadata_into(&self.engine, &mut metadata, batch);
            }
            Err(poisoned) => {
                let mut metadata = poisoned.into_inner();
                AiToolGovernor::write_metadata_into(&self.engine, &mut metadata, batch);
            }
        }
    }

    fn record_uninspectable_metadata(&self) {
        let Some(slot) = &self.stream_metadata else {
            return;
        };
        match slot.lock() {
            Ok(mut metadata) => {
                AiToolGovernor::write_uninspectable_metadata_into(&self.engine, &mut metadata);
            }
            Err(poisoned) => {
                let mut metadata = poisoned.into_inner();
                AiToolGovernor::write_uninspectable_metadata_into(&self.engine, &mut metadata);
            }
        }
    }

    fn record_ambiguity_observation(&self) {
        let Some(slot) = &self.stream_metadata else {
            return;
        };
        match slot.lock() {
            Ok(mut metadata) => {
                AiToolGovernor::write_ambiguity_observation_into(&self.engine, &mut metadata);
            }
            Err(poisoned) => {
                let mut metadata = poisoned.into_inner();
                AiToolGovernor::write_ambiguity_observation_into(&self.engine, &mut metadata);
            }
        }
    }

    /// Evaluate the accumulated tool calls at a completion boundary. On
    /// release, appends the held raw bytes to `out` and resets batch state.
    async fn finalize(&mut self, out: &mut Vec<u8>) -> Finalize {
        if !self.saw_tool_calls {
            return Finalize::Released;
        }
        // Any accumulated tool call that cannot be policy-checked — no
        // `function.name`, non-string `function.arguments`, malformed container,
        // ambiguous identity, or duplicate-member arguments — makes the whole
        // batch ungovernable: a governable named call in the same SSE batch
        // could otherwise carry an unchecked sibling to the client. Enforce mode
        // fails closed (cut the stream); dry-run releases the held frames
        // unchanged so observation never disrupts traffic. A single
        // `finalize_checked` pass both screens and builds so arguments are not
        // scanned twice. Duplicate-key argument ambiguity records a dry-run
        // observation; other ungovernable causes keep their prior forward-only
        // dry-run posture.
        let calls = match self.accumulator.finalize_checked() {
            Err(CheckedFinalizeError::AmbiguousArguments) => {
                if self.engine.mode == Mode::Enforce {
                    self.record_uninspectable_metadata();
                    self.held.clear();
                    return Finalize::Blocked;
                }
                self.record_ambiguity_observation();
                out.extend_from_slice(&self.held);
                self.held.clear();
                self.reset_batch();
                return Finalize::Released;
            }
            Err(CheckedFinalizeError::Ungovernable) => {
                if self.engine.mode == Mode::Enforce {
                    self.record_uninspectable_metadata();
                    self.held.clear();
                    return Finalize::Blocked;
                }
                out.extend_from_slice(&self.held);
                self.held.clear();
                self.reset_batch();
                return Finalize::Released;
            }
            Ok(calls) => calls,
        };
        if calls.is_empty() {
            // Saw a tool-call array but no governable calls (e.g. an empty
            // array): nothing to check, release the held frames unchanged.
            out.extend_from_slice(&self.held);
            self.held.clear();
            self.reset_batch();
            return Finalize::Released;
        }
        let batch = self
            .engine
            .govern_calls(&self.corr, &calls, &self.plugin_http_call_ns, true)
            .await;
        self.record_metadata(&batch);

        if batch.enforce_blocks {
            warn!(
                target: "ai_tool_governor",
                decision = batch.overall_label,
                risk = batch.max_risk.as_str(),
                "streaming tool call blocked; cutting stream: {}",
                batch.deny_reason.as_deref().unwrap_or("blocked")
            );
            self.held.clear();
            Finalize::Blocked
        } else {
            out.extend_from_slice(&self.held);
            self.held.clear();
            self.reset_batch();
            Finalize::Released
        }
    }

    /// Build the terminal action, prepending any already-cleared bytes in `out`
    /// so clean content released in the same chunk is not lost.
    fn terminate(&mut self, mut out: Vec<u8>) -> ResponseStreamAction {
        self.terminated = true;
        if self.engine.response.streaming_deny_event {
            out.extend_from_slice(&encode_sse_error_event(
                "ai_tool_governor_tool_blocked",
                "Tool call blocked by ai_tool_governor policy.",
            ));
        }
        if out.is_empty() {
            ResponseStreamAction::Terminate(None)
        } else {
            ResponseStreamAction::Terminate(Some(Bytes::from(out)))
        }
    }

    /// A stream held in full (JSON-shaped, opaque, or shape not yet resolved):
    /// hold the accumulating body (never forward a prefix — releasing bytes
    /// before the body can be classified/parsed would leak a denied call),
    /// bounded by the same hold cap as the SSE path.
    fn hold_entire_body(&mut self) -> ResponseStreamAction {
        if self.carry.len() > MAX_STREAM_HOLD_BYTES {
            warn!(
                target: "ai_tool_governor",
                held_bytes = self.carry.len(),
                mode = self.engine.mode.as_str(),
                "held stream exceeded cap"
            );
            if self.engine.mode == Mode::Enforce {
                self.record_uninspectable_metadata();
                self.carry.clear();
                return self.terminate(Vec::new());
            }
            self.bypassed = true;
            return ResponseStreamAction::Forward(Bytes::from(std::mem::take(&mut self.carry)));
        }
        ResponseStreamAction::Forward(Bytes::new())
    }

    /// Apply the retained-byte cap without parsing the bytes that crossed it.
    /// In enforce mode none of the over-cap event/carry is released; in dry-run
    /// all retained bytes are forwarded unchanged and later chunks bypass
    /// inspection so observation never disrupts traffic.
    fn handle_hold_overflow(&mut self, mut out: Vec<u8>) -> ResponseStreamAction {
        warn!(
            target: "ai_tool_governor",
            held_bytes = self.held.len(),
            carry_bytes = self.carry.len(),
            mode = self.engine.mode.as_str(),
            "streaming tool-call hold exceeded cap"
        );
        if self.engine.mode == Mode::Enforce {
            self.record_uninspectable_metadata();
            self.held.clear();
            self.carry.clear();
            return self.terminate(out);
        }
        out.append(&mut self.held);
        out.append(&mut self.carry);
        self.reset_batch();
        self.bypassed = true;
        ResponseStreamAction::Forward(Bytes::from(out))
    }

    /// Govern a fully-held JSON-shaped stream at end-of-stream, mirroring the
    /// buffered JSON path: extract `choices[].message.tool_calls[]` /
    /// `function_call`, fail closed on ungovernable entries and blocked calls
    /// (redaction is impossible on a stream), and release the body bytes
    /// unchanged when policy clears them. An unparseable JSON-shaped body is
    /// released, mirroring the buffered path's treatment of unparseable
    /// JSON-shaped plaintext within the size cap.
    async fn finalize_json_body(&mut self) -> ResponseStreamAction {
        let body = std::mem::take(&mut self.carry);
        // An UNPARSEABLE JSON-shaped body is released (documented above); an
        // AMBIGUOUS one is not. It parses — a denied `tool_calls[]` can be
        // hiding behind a duplicate member whose last-wins collapse this
        // gateway would clear but the client's parser would not read
        // (advisory `GHSA-c78j-5w9p-cpq6`). Enforce cuts the stream before any
        // held byte is released; dry-run forwards unchanged.
        if json_dup_keys::slice_ambiguity(strip_json_bom(&body)).is_some() {
            if self.engine.mode == Mode::Enforce {
                self.record_uninspectable_metadata();
                warn!(
                    target: "ai_tool_governor",
                    "JSON-shaped stream contains duplicate JSON object member names; cutting stream"
                );
                return self.terminate(Vec::new());
            }
            self.record_ambiguity_observation();
            return ResponseStreamAction::Forward(Bytes::from(body));
        }
        let Ok(json) = serde_json::from_slice::<Value>(strip_json_bom(&body)) else {
            return ResponseStreamAction::Forward(Bytes::from(body));
        };
        let (calls, ungovernable) = extract_response_tool_calls(&json);
        if ungovernable {
            if self.engine.mode == Mode::Enforce {
                self.record_uninspectable_metadata();
                warn!(
                    target: "ai_tool_governor",
                    "JSON-shaped stream contains an ungovernable tool call; cutting stream"
                );
                return self.terminate(Vec::new());
            }
            if calls.iter().any(|call| call.args_ambiguous) {
                self.record_ambiguity_observation();
            }
            return ResponseStreamAction::Forward(Bytes::from(body));
        }
        if calls.is_empty() {
            return ResponseStreamAction::Forward(Bytes::from(body));
        }
        // Same fill-if-absent correlation the SSE frame path uses, sourced
        // from the JSON body itself.
        if self.corr.model.is_none() {
            self.corr.model = json
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        if self.corr.provider.is_none() {
            self.corr.provider = detect_response_provider(&json).map(|p| p.as_str().to_string());
        }
        let batch = self
            .engine
            .govern_calls(&self.corr, &calls, &self.plugin_http_call_ns, true)
            .await;
        self.record_metadata(&batch);
        if batch.enforce_blocks {
            warn!(
                target: "ai_tool_governor",
                decision = batch.overall_label,
                "JSON-shaped stream tool call blocked; cutting stream: {}",
                batch.deny_reason.as_deref().unwrap_or("blocked")
            );
            return self.terminate(Vec::new());
        }
        ResponseStreamAction::Forward(Bytes::from(body))
    }
}

#[async_trait]
impl ResponseStreamInspector for ToolCallStreamInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if self.terminated {
            return ResponseStreamAction::Forward(Bytes::new());
        }
        if self.bypassed {
            return ResponseStreamAction::Forward(Bytes::copy_from_slice(chunk));
        }
        self.carry.extend_from_slice(chunk);
        // Sniff the body shape once, from the leading bytes: a JSON-shaped
        // stream (mislabeled Chat Completions JSON under an SSE label) must
        // not be forwarded as ordinary non-SSE trailing data — hold it and
        // govern at end-of-stream like a buffered JSON body — and an OPAQUE
        // stream (neither SSE- nor JSON-shaped, e.g. compressed bytes) must
        // not ride the SSE path where every "event" classifies as NoData and
        // forwards uninspected.
        if self.shape == StreamBodyShape::Unknown {
            self.shape = match sniff_stream_shape(&self.carry) {
                StreamSniff::Json => StreamBodyShape::Json,
                StreamSniff::Sse => StreamBodyShape::Sse,
                StreamSniff::Opaque => StreamBodyShape::Opaque,
                StreamSniff::Inconclusive => StreamBodyShape::Unknown,
            };
        }
        match self.shape {
            // Hold-in-full shapes. An unresolved shape holds too — never
            // forward bytes whose shape is unknown — bounded by the same cap.
            StreamBodyShape::Json | StreamBodyShape::Opaque | StreamBodyShape::Unknown => {
                return self.hold_entire_body();
            }
            StreamBodyShape::Sse => {}
        }
        let mut out: Vec<u8> = Vec::new();

        while let Some(end) = next_event_end(&self.carry) {
            // Enforce the retained-byte bound BEFORE draining and classifying
            // the event. Otherwise one complete >4 MiB `data:` frame is copied
            // and JSON-parsed before the cap below runs (and a non-JSON event
            // can be forwarded without ever tripping that retained-byte check).
            if self.held.len().saturating_add(end) > MAX_STREAM_HOLD_BYTES {
                return self.handle_hold_overflow(out);
            }
            let event: Vec<u8> = self.carry.drain(..end).collect();
            match classify_event(&event) {
                SseEvent::Frame(frame) => {
                    self.record_frame_context(&frame);
                    if frame_has_tool_calls(&frame) {
                        self.saw_tool_calls = true;
                        self.accumulator.push_frame(&frame);
                    }
                    // Once a governed batch is pending, hold EVERY subsequent
                    // event (not just tool-call frames) in arrival order: with
                    // multi-choice streams another choice can emit content
                    // frames before the tool-call choice's finish frame, and
                    // forwarding those live would deliver an allowed stream out
                    // of order — or leak post-tool-call content ahead of the
                    // terminal error on a deny. Release restores the original
                    // order; deny drops everything held. The added latency for
                    // the rare multi-choice-with-tools case is the accepted
                    // cost of ordering correctness and no-leak.
                    let batch_pending = self.saw_tool_calls;
                    if batch_pending {
                        self.held.extend_from_slice(&event);
                    }
                    self.record_finished_choices(&frame);
                    // Evaluate once every choice holding tool calls has
                    // finished, then release the held frames (this event
                    // included, in order). Later tool-call deltas start a new
                    // batch governed at its own completion boundary.
                    if self.batch_complete()
                        && let Finalize::Blocked = self.finalize(&mut out).await
                    {
                        return self.terminate(out);
                    }
                    if !batch_pending {
                        out.extend_from_slice(&event);
                    }
                }
                SseEvent::Done => {
                    if let Finalize::Blocked = self.finalize(&mut out).await {
                        return self.terminate(out);
                    }
                    out.extend_from_slice(&event);
                }
                SseEvent::Ambiguous => {
                    // The frame parses but its objects carry duplicate member
                    // names, so no tool-call extraction from it can be trusted:
                    // a `tool_calls` delta the client's parser reads may not be
                    // the one this gateway would evaluate. Cut the stream in
                    // enforce mode BEFORE any held bytes are released; dry-run
                    // records a sanitized observation and forwards, holding only
                    // to preserve arrival order behind a pending batch.
                    if self.engine.mode == Mode::Enforce {
                        self.record_uninspectable_metadata();
                        warn!(
                            target: "ai_tool_governor",
                            "SSE data payload contains duplicate JSON object member names; cutting stream"
                        );
                        self.held.clear();
                        return self.terminate(out);
                    }
                    self.record_ambiguity_observation();
                    if self.saw_tool_calls {
                        self.held.extend_from_slice(&event);
                    } else {
                        out.extend_from_slice(&event);
                    }
                }
                SseEvent::OtherData | SseEvent::NoData => {
                    if self.saw_tool_calls {
                        // A governed batch is pending: hold to preserve
                        // arrival order (and never leak past a deny).
                        self.held.extend_from_slice(&event);
                    } else {
                        // Comments, keepalives, non-JSON data: forward live.
                        out.extend_from_slice(&event);
                    }
                }
            }
        }

        // Cap retained bytes (held tool-call frames + partial-event carry): an
        // upstream streaming never-finishing tool-call deltas (or an
        // event-terminator-free byte stream) must not grow gateway memory
        // unboundedly. Enforce mode fails closed; dry-run releases everything
        // uninspected rather than disrupting traffic.
        if self.held.len().saturating_add(self.carry.len()) > MAX_STREAM_HOLD_BYTES {
            return self.handle_hold_overflow(out);
        }

        ResponseStreamAction::Forward(Bytes::from(out))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.terminated || self.bypassed {
            return ResponseStreamAction::Forward(Bytes::new());
        }
        match self.shape {
            StreamBodyShape::Json => return self.finalize_json_body().await,
            StreamBodyShape::Opaque => {
                // Neither SSE- nor JSON-shaped (e.g. a compressed body whose
                // `Content-Encoding` a transform stripped): nothing could be
                // inspected, so a denied tool call may be hiding inside.
                // Enforce fails closed; dry-run releases the held bytes
                // unchanged.
                if self.engine.mode == Mode::Enforce {
                    self.record_uninspectable_metadata();
                    warn!(
                        target: "ai_tool_governor",
                        held_bytes = self.carry.len(),
                        "opaque stream under governance cannot be inspected; cutting stream"
                    );
                    self.carry.clear();
                    return self.terminate(Vec::new());
                }
                return ResponseStreamAction::Forward(Bytes::from(std::mem::take(&mut self.carry)));
            }
            // An Unknown shape at end-of-stream is bytes that never resolved
            // before EOF. Two cases, resolved conservatively here:
            // - Valid UTF-8 (whitespace, a bare BOM, or a colon-less
            //   printable first-line fragment — no `:` and no line
            //   terminator, so provably no `data:` line and no governable
            //   call inside): the SSE flush below forwards it unchanged.
            // - NOT valid UTF-8 (e.g. high-bit binary with no colon, line
            //   terminator, or control byte before EOF): never classifiable
            //   as SSE or JSON. Flushing it through the SSE path would
            //   classify it `NoData` and forward it even in enforce mode, so
            //   apply Opaque semantics instead — cut in enforce, release
            //   unchanged in dry-run.
            StreamBodyShape::Unknown => {
                if std::str::from_utf8(&self.carry).is_err() {
                    if self.engine.mode == Mode::Enforce {
                        self.record_uninspectable_metadata();
                        warn!(
                            target: "ai_tool_governor",
                            held_bytes = self.carry.len(),
                            "unclassifiable non-UTF-8 stream under governance cannot be inspected; cutting stream"
                        );
                        self.carry.clear();
                        return self.terminate(Vec::new());
                    }
                    return ResponseStreamAction::Forward(Bytes::from(std::mem::take(
                        &mut self.carry,
                    )));
                }
            }
            StreamBodyShape::Sse => {}
        }
        let mut out: Vec<u8> = Vec::new();
        let mut trailing: Vec<u8> = Vec::new();

        // Flush a trailing partial/complete event, if any.
        if !self.carry.is_empty() {
            let event = std::mem::take(&mut self.carry);
            match classify_event(&event) {
                SseEvent::Frame(frame) if frame_has_tool_calls(&frame) => {
                    self.record_frame_context(&frame);
                    self.saw_tool_calls = true;
                    self.accumulator.push_frame(&frame);
                    self.held.extend_from_slice(&event);
                }
                // Same posture as the mid-stream ambiguous frame: an
                // uninspectable trailing event must not be flushed to the
                // client in enforce mode alongside a released batch. Dry-run
                // records the observation and still forwards the trailing bytes.
                SseEvent::Ambiguous if self.engine.mode == Mode::Enforce => {
                    self.record_uninspectable_metadata();
                    warn!(
                        target: "ai_tool_governor",
                        "trailing SSE data payload contains duplicate JSON object member names; cutting stream"
                    );
                    self.held.clear();
                    return self.terminate(Vec::new());
                }
                SseEvent::Ambiguous => {
                    self.record_ambiguity_observation();
                    trailing = event;
                }
                _ => trailing = event,
            }
        }

        match self.finalize(&mut out).await {
            Finalize::Blocked => return self.terminate(out),
            Finalize::Released => {}
        }
        out.extend_from_slice(&trailing);
        ResponseStreamAction::Forward(Bytes::from(out))
    }
}

// ---------------------------------------------------------------------------
// SSE framing helpers
// ---------------------------------------------------------------------------

/// Length of the SSE line terminator starting at `buf[i]`.
enum TermAt {
    /// `buf[i]` does not start a line terminator.
    None,
    /// A complete terminator of this byte length (`\n` or `\r` = 1, `\r\n` = 2).
    Len(usize),
    /// A `\r` as the FINAL buffer byte: it may be a lone-CR terminator or the
    /// first half of a `\r\n` straddling a chunk boundary — undecidable until
    /// the next byte arrives.
    Ambiguous,
}

fn terminator_at(buf: &[u8], i: usize) -> TermAt {
    match buf[i] {
        b'\n' => TermAt::Len(1),
        b'\r' => match buf.get(i + 1) {
            Some(b'\n') => TermAt::Len(2),
            Some(_) => TermAt::Len(1),
            None => TermAt::Ambiguous,
        },
        _ => TermAt::None,
    }
}

/// Byte index just past the end of the first complete SSE event (the first
/// blank line), or `None` if no event has fully arrived yet. The SSE spec
/// allows `\r\n`, `\r`, or `\n` as line terminators, so an event ends at any
/// TWO consecutive terminators — an LF-only scan would leave a CR-only stream
/// (`data: {...}\r\r`) as one never-complete "line" whose denied deltas flush
/// as unparsed trailing bytes. A trailing `\r` is held (return `None`) until
/// the next chunk disambiguates lone-CR from a straddled `\r\n`, so an event
/// is never split inside one terminator.
fn next_event_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < buf.len() {
        let first = match terminator_at(buf, i) {
            TermAt::None => {
                i += 1;
                continue;
            }
            TermAt::Ambiguous => return None,
            TermAt::Len(len) => len,
        };
        let after_first = i + first;
        if after_first >= buf.len() {
            // Line terminator at the buffer edge: the next byte decides
            // whether a blank line follows.
            return None;
        }
        match terminator_at(buf, after_first) {
            TermAt::None => i = after_first,
            TermAt::Ambiguous => return None,
            TermAt::Len(second) => return Some(after_first + second),
        }
    }
    None
}

/// Split SSE text into lines on any of the three spec terminators (`\r\n`,
/// `\r`, `\n`), terminators consumed. `str::lines` is LF-only, so a CR-only
/// event would collapse into one unparseable line and its `data:` frames
/// would bypass governance. Terminator bytes are ASCII, so the byte-index
/// slices always fall on char boundaries.
fn sse_lines(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                lines.push(&text[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                lines.push(&text[start..i]);
                i += 1;
                if bytes.get(i) == Some(&b'\n') {
                    i += 1;
                }
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < bytes.len() {
        lines.push(&text[start..]);
    }
    lines
}

enum SseEvent {
    Frame(Value),
    Done,
    /// The `data:` payload parses as JSON but carries duplicate object member
    /// names, so the frame this gateway would evaluate is not necessarily the
    /// frame the client's parser reads (advisory `GHSA-c78j-5w9p-cpq6`). The
    /// held bytes must not be released on the strength of a governed decision
    /// taken over a last-wins collapse.
    Ambiguous,
    OtherData,
    NoData,
}

/// Classify a raw SSE event by its concatenated `data:` payload.
fn classify_event(event: &[u8]) -> SseEvent {
    // A UTF-8 BOM at the very start of the body rides into the FIRST event's
    // bytes and would make its first line `\u{feff}data: ...`, which the
    // field matcher below cannot see — the first event's denied call would
    // classify as NoData and forward. `looks_like_sse` is already
    // BOM-tolerant; the parser must be too, on both the live streaming path
    // and the buffered extraction.
    let event = event
        .strip_prefix(b"\xEF\xBB\xBF".as_slice())
        .unwrap_or(event);
    let Ok(text) = std::str::from_utf8(event) else {
        return SseEvent::NoData;
    };
    let mut data_lines: Vec<&str> = Vec::new();
    for line in sse_lines(text) {
        if let Some(rest) = line
            .strip_prefix("data: ")
            .or_else(|| line.strip_prefix("data:"))
        {
            data_lines.push(rest);
        }
    }
    if data_lines.is_empty() {
        return SseEvent::NoData;
    }
    let data = data_lines.join("\n");
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return SseEvent::NoData;
    }
    if trimmed == "[DONE]" {
        return SseEvent::Done;
    }
    // Screen the concatenated `data:` payload before it becomes the frame
    // policy is evaluated against. `OtherData` (unparseable) stays a forwarding
    // outcome; ambiguity is a distinct, fail-closed one.
    if json_dup_keys::str_ambiguity(trimmed).is_some() {
        return SseEvent::Ambiguous;
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(value) => SseEvent::Frame(value),
        Err(_) => SseEvent::OtherData,
    }
}

/// Record the choices `frame` finishes into `finished`. Only choices that
/// actually hold tool-call deltas in `acc` are tracked — a hostile stream of
/// synthetic finish frames for unrelated choice indices cannot grow the set.
/// Shared by the live inspector and the buffered-SSE extraction so their
/// batch-boundary semantics cannot drift.
fn collect_finished_choices(
    frame: &Value,
    acc: &StreamingToolCallAccumulator,
    finished: &mut std::collections::HashSet<usize>,
) {
    let Some(choices) = frame.get("choices").and_then(Value::as_array) else {
        return;
    };
    for (cpos, choice) in choices.iter().enumerate() {
        if choice.get("finish_reason").is_none_or(|r| r.is_null()) {
            continue;
        }
        let cidx = choice
            .get("index")
            .and_then(Value::as_u64)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(cpos);
        if acc.has_choice(cidx) {
            finished.insert(cidx);
        }
    }
}

/// Classify a `tool_calls` container Value the ONE way this plugin decides
/// governability, shared by the buffered-JSON extractor and the SSE frame
/// paths so they cannot diverge (round 10 established the buffered posture;
/// this is the shared choke point):
///   - a JSON array is a governable container (its entries are checked);
///   - absent or explicit `null` means no tool calls;
///   - any OTHER JSON type (object, string, number, bool) is MALFORMED — an
///     unrecognized shape that could hide a call the extractor would silently
///     drop, so it is treated as ungovernable (enforce cut / dry-run release).
enum ToolCallsContainer<'a> {
    Array(&'a [Value]),
    None,
    Malformed,
}

fn classify_tool_calls_container(value: Option<&Value>) -> ToolCallsContainer<'_> {
    match value {
        Some(Value::Array(items)) => ToolCallsContainer::Array(items),
        None | Some(Value::Null) => ToolCallsContainer::None,
        Some(_) => ToolCallsContainer::Malformed,
    }
}

/// Whether a `choices[].delta` carries governed call deltas (a non-empty
/// `tool_calls` array, or a non-null legacy `function_call`) OR a MALFORMED
/// tool-call container (`tool_calls` present but not an array). A malformed
/// container must return `true` so the frame is HELD and pushed into the
/// accumulator (which flags it ungovernable): otherwise the live inspector and
/// the buffered-SSE extractor would treat it as ordinary data and forward it
/// even under enforce/default-deny — the SSE mirror of the round-10 buffered
/// non-array fix.
fn delta_has_tool_calls(delta: Option<&Value>) -> bool {
    let tool_calls = delta.and_then(|d| d.get("tool_calls"));
    match classify_tool_calls_container(tool_calls) {
        ToolCallsContainer::Array(items) => {
            if !items.is_empty() {
                return true;
            }
        }
        ToolCallsContainer::Malformed => return true,
        ToolCallsContainer::None => {}
    }
    delta
        .and_then(|d| d.get("function_call"))
        .is_some_and(|fc| !fc.is_null())
}

/// Whether a streaming frame carries governed call deltas (or a malformed
/// tool-call container that must be held and flagged ungovernable): modern
/// `choices[].delta.tool_calls`, or the legacy `functions`-API
/// `choices[].delta.function_call`. Frames matching this are HELD until the
/// accumulated call clears policy.
fn frame_has_tool_calls(frame: &Value) -> bool {
    frame
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| {
            choices
                .iter()
                .any(|choice| delta_has_tool_calls(choice.get("delta")))
        })
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

/// Tool calls (plus frame-derived correlation context) extracted from a
/// fully-buffered SSE body.
struct BufferedSseExtract {
    calls: Vec<ToolCall>,
    /// A call that cannot be policy-checked was present (missing
    /// `function.name` / non-string `function.arguments`) — the mirror of the
    /// live streaming finalizer's ungovernable state.
    ungovernable: bool,
    /// True when ungovernability came from duplicate-key ambiguity (an
    /// ambiguous `data:` frame or duplicate-member arguments string), so
    /// dry-run can record the fixed observation without treating generic
    /// ungovernable traffic the same way.
    ambiguous: bool,
    /// First `model` a data frame reported, mirroring the live inspector's
    /// `record_frame_context` — approval webhook/cache keys must carry the
    /// served model even when request metadata is absent.
    model: Option<String>,
    /// First provider detected from a frame's shape (same mirror).
    provider: Option<String>,
}

/// Per-batch accumulation state for [`extract_sse_tool_calls`], mirroring the
/// live inspector's batch lifecycle (`batch_complete` → `finalize` →
/// `reset_batch`): the accumulator RESETS at every completion boundary
/// (`finish_reason` for all tool-call choices, or `[DONE]`). Without the
/// reset, two sequential tool-call batches reusing the same
/// `(choice, tool_call)` indices would concatenate (`safe`+`danger` →
/// `safedanger`) and a denied second call would be evaluated under a mangled
/// name — a bypass under `default_action: allow`.
struct BufferedSseBatches {
    acc: StreamingToolCallAccumulator,
    finished: std::collections::HashSet<usize>,
    saw_tool_calls: bool,
    extract: BufferedSseExtract,
}

impl BufferedSseBatches {
    fn new() -> Self {
        Self {
            acc: StreamingToolCallAccumulator::default(),
            finished: std::collections::HashSet::new(),
            saw_tool_calls: false,
            extract: BufferedSseExtract {
                calls: Vec::new(),
                ungovernable: false,
                ambiguous: false,
                model: None,
                provider: None,
            },
        }
    }

    /// Seal the pending batch at a completion boundary: fold its calls (under
    /// their TRUE per-batch names) and its ungovernable state into the
    /// extract, then reset the accumulator for the next batch. Uses the same
    /// single checked-finalization pass as the live streaming finalizer so
    /// argument ambiguity is screened once per call.
    fn seal_batch(&mut self) {
        if !self.saw_tool_calls {
            return;
        }
        match self.acc.finalize_checked() {
            Err(CheckedFinalizeError::AmbiguousArguments) => {
                self.extract.ungovernable = true;
                self.extract.ambiguous = true;
            }
            Err(CheckedFinalizeError::Ungovernable) => self.extract.ungovernable = true,
            Ok(calls) => self.extract.calls.extend(calls),
        }
        self.acc = StreamingToolCallAccumulator::default();
        self.finished.clear();
        self.saw_tool_calls = false;
    }

    fn on_event(&mut self, event: &[u8]) {
        match classify_event(event) {
            SseEvent::Frame(frame) => {
                if self.extract.model.is_none()
                    && let Some(m) = frame.get("model").and_then(Value::as_str)
                {
                    self.extract.model = Some(m.to_string());
                }
                if self.extract.provider.is_none()
                    && let Some(p) = detect_sse_provider(&frame)
                {
                    self.extract.provider = Some(p.as_str().to_string());
                }
                if frame_has_tool_calls(&frame) {
                    self.saw_tool_calls = true;
                    self.acc.push_frame(&frame);
                }
                collect_finished_choices(&frame, &self.acc, &mut self.finished);
                // Every choice holding tool-call deltas has finished: the
                // batch is complete (the live inspector's `batch_complete`).
                if self.saw_tool_calls && self.acc.choices_finished(&self.finished) {
                    self.seal_batch();
                }
            }
            // `[DONE]` is a definitive batch boundary even when no
            // `finish_reason` frame arrived.
            SseEvent::Done => self.seal_batch(),
            // Buffered mirror of the live inspector's ambiguous-frame cut: a
            // `data:` payload whose objects carry duplicate member names cannot
            // be extracted from faithfully, so the whole body is ungovernable
            // and `govern_buffered_sse` fails closed in enforce mode.
            SseEvent::Ambiguous => {
                self.extract.ungovernable = true;
                self.extract.ambiguous = true;
            }
            SseEvent::OtherData | SseEvent::NoData => {}
        }
    }
}

/// Accumulate the complete OpenAI tool calls from a fully-buffered SSE body.
/// Used when a `text/event-stream` response is delivered on the buffered path
/// (streaming inspection disabled, an encoded SSE response decoded first,
/// another buffering plugin, or a content-type-rewrite guard kept it buffered)
/// instead of through the streaming inspector, so its tool calls are still
/// governed rather than forwarded uninspected. Batches are collected per
/// completion boundary (see [`BufferedSseBatches`]) so every batch's calls are
/// governed under their true names.
fn extract_sse_tool_calls(body: &[u8]) -> BufferedSseExtract {
    let mut batches = BufferedSseBatches::new();
    let Ok(text) = std::str::from_utf8(body) else {
        // Non-UTF-8 SSE bytes: nothing extractable. `govern_buffered_sse`
        // pre-screens these and fails closed BEFORE extraction (opaque
        // parity with the live inspector); this fallback only keeps
        // extraction itself total.
        return batches.extract;
    };
    let mut event: Vec<&str> = Vec::new();
    // Spec-terminator-aware line split (`\r\n` / `\r` / `\n` — see
    // [`sse_lines`]): a blank line of any terminator form separates events,
    // so a CR-only stream is parsed identically to the live inspector.
    for line in sse_lines(text) {
        if line.is_empty() {
            if !event.is_empty() {
                batches.on_event(event.join("\n").as_bytes());
                event.clear();
            }
        } else {
            event.push(line);
        }
    }
    if !event.is_empty() {
        batches.on_event(event.join("\n").as_bytes());
    }
    // A trailing batch with no completion boundary (stream cut early) is
    // still surfaced for governance — the mirror of the live inspector's
    // `on_end` finalize.
    batches.seal_batch();
    batches.extract
}

fn tool_call_from(name: &str, args: Option<&Value>) -> ToolCall {
    // A JSON STRING argument payload is a second, independently parsed document
    // that the enclosing body's duplicate-member screen could not see into, so
    // screen its content here. A non-string `Value` came from the enclosing
    // document and was already screened with it.
    let mut args_ambiguous = false;
    let (raw_args, parsed_args) = match args {
        Some(Value::String(s)) => {
            args_ambiguous = json_dup_keys::str_ambiguity(s).is_some();
            (s.clone(), serde_json::from_str::<Value>(s).ok())
        }
        Some(value) => (value.to_string(), Some(value.clone())),
        None => (String::new(), None),
    };
    ToolCall {
        name: name.to_string(),
        raw_args,
        parsed_args,
        args_ambiguous,
    }
}

/// Extract `choices[].message.tool_calls[]` and legacy
/// `choices[].message.function_call` from a buffered response.
///
/// Returns `(calls, ungovernable)`, bringing the buffered path to parity with
/// [`extract_sse_tool_calls`] / the streaming accumulator: an entry that
/// cannot be policy-checked — a missing or non-string `function.name` (or a
/// `tool_calls` container that is not an array) — must be SURFACED rather
/// than silently dropped, or an all-unnamed `tool_calls[]` would yield
/// `calls.is_empty()` and slide past even `default_action: deny`. Callers
/// fail closed in enforce mode and forward in dry-run, exactly like the
/// streaming finalizer. Two deliberate divergences from streaming:
/// - Non-string `function.arguments` are GOVERNABLE here: the buffered value
///   is fully available, so `tool_call_from` evaluates (and the redaction
///   transform rewrites) the concrete JSON — unlike streaming, where
///   non-string argument deltas are never accumulated and thus uncheckable.
/// - A `null` `tool_calls` / `function_call` is the documented "no calls"
///   shape (OpenAI emits it on content-only responses), NOT ungovernable.
fn extract_response_tool_calls(json: &Value) -> (Vec<ToolCall>, bool) {
    let mut out = Vec::new();
    let mut ungovernable = false;
    let Some(choices) = json.get("choices").and_then(Value::as_array) else {
        return (out, false);
    };
    for choice in choices {
        let Some(message) = choice.get("message") else {
            continue;
        };
        // Same container classification the SSE paths use (shared choke point).
        match classify_tool_calls_container(message.get("tool_calls")) {
            ToolCallsContainer::Array(tool_calls) => {
                for tc in tool_calls {
                    let function = tc.get("function");
                    match function.and_then(|f| f.get("name")).and_then(Value::as_str) {
                        Some(name) if !name.is_empty() => {
                            out.push(tool_call_from(
                                name,
                                function.and_then(|f| f.get("arguments")),
                            ));
                        }
                        // Arguments/id without a checkable `function.name`:
                        // policy is keyed by name, so this call cannot be
                        // evaluated and must not vanish from the batch.
                        Some(_) | None => ungovernable = true,
                    }
                }
            }
            // Absent or explicitly-null: no tool calls for this choice.
            ToolCallsContainer::None => {}
            // `tool_calls` present but not an array: not a checkable shape.
            ToolCallsContainer::Malformed => ungovernable = true,
        }
        match message.get("function_call") {
            Some(Value::Null) | None => {}
            Some(function_call) => match function_call.get("name").and_then(Value::as_str) {
                Some(name) if !name.is_empty() => {
                    out.push(tool_call_from(name, function_call.get("arguments")));
                }
                Some(_) | None => ungovernable = true,
            },
        }
    }
    // A `function.arguments` JSON STRING whose content carries duplicate object
    // member names is a second document the enclosing body screen could not see
    // into. It is checkable in form but not in meaning, so it joins the
    // ungovernable class rather than being evaluated on a last-wins collapse
    // the client's parser may not share (advisory `GHSA-c78j-5w9p-cpq6`).
    ungovernable |= out.iter().any(|call| call.args_ambiguous);
    (out, ungovernable)
}

/// Extract tool definition names from a request's `tools[]` / `functions[]`.
fn extract_request_tool_definitions(json: &Value) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(tools) = json.get("tools").and_then(Value::as_array) {
        for tool in tools {
            if let Some(name) = tool
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
            {
                names.push(name.to_string());
            }
        }
    }
    if let Some(functions) = json.get("functions").and_then(Value::as_array) {
        for function in functions {
            if let Some(name) = function.get("name").and_then(Value::as_str) {
                names.push(name.to_string());
            }
        }
    }
    names
}

enum McpToolCallExtraction {
    Absent,
    Call(ToolCall),
    Malformed,
}

/// Extract a single tool call from an MCP JSON-RPC `tools/call` request while
/// preserving the distinction between an unrelated JSON-RPC method and a
/// governed call whose name cannot be policy-checked.
///
/// MCP permits omitting `params.arguments` for zero-argument tools; that case
/// is normalized to an empty JSON object before required-arg / regex / hash /
/// approval / JSON Schema evaluation (matching `mcp_gateway`). Provider
/// response shapes that omit `function.arguments` keep their distinct
/// semantics via [`tool_call_from`] and are not normalized here.
fn extract_mcp_tool_call(json: &Value) -> McpToolCallExtraction {
    if json.get("method").and_then(Value::as_str) != Some("tools/call") {
        return McpToolCallExtraction::Absent;
    }
    let Some(params) = json.get("params") else {
        return McpToolCallExtraction::Malformed;
    };
    let Some(name) = params
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
    else {
        return McpToolCallExtraction::Malformed;
    };
    match params.get("arguments") {
        None => McpToolCallExtraction::Call(ToolCall {
            name: name.to_string(),
            raw_args: "{}".to_string(),
            parsed_args: Some(json!({})),
            args_ambiguous: false,
        }),
        Some(arguments) => McpToolCallExtraction::Call(tool_call_from(name, Some(arguments))),
    }
}

/// Like [`extract_mcp_tool_call`], but remaps a gateway-authenticated aggregate
/// upstream alias to its public policy name when — and only when — the final
/// wire name exactly matches the trusted rewrite staged by `mcp_gateway`.
///
/// Final arguments remain the backend-visible values. Unrelated name changes,
/// missing trust, or a wire name that does not equal the staged upstream alias
/// keep the wire identity and therefore fail closed under deny-by-default.
fn extract_mcp_tool_call_for_policy(json: &Value, ctx: &RequestContext) -> McpToolCallExtraction {
    match extract_mcp_tool_call(json) {
        McpToolCallExtraction::Call(mut call) => {
            if let Some((public_name, upstream_name)) = &ctx.mcp_trusted_tool_name_rewrite
                && call.name == *upstream_name
            {
                call.name = public_name.clone();
            }
            McpToolCallExtraction::Call(call)
        }
        other => other,
    }
}

/// Extract an A2A JSON-RPC method as a name-governed "tool" (params as args).
/// MCP `tools/call` is handled separately, so it is skipped here.
fn extract_a2a_method(json: &Value) -> Option<ToolCall> {
    let method = json.get("method").and_then(Value::as_str)?;
    if method == "tools/call" {
        return None;
    }
    let canonical_method = super::a2a_gateway::canonical_a2a_method(method).unwrap_or(method);
    Some(tool_call_from(canonical_method, json.get("params")))
}

fn request_model(json: &Value) -> Option<String> {
    json.get("model")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str).or_else(|| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
}

fn has_non_identity_content_encoding(headers: &HashMap<String, String>) -> bool {
    content_encoding_value(headers).is_some()
}

/// True for native gRPC (`application/grpc*`) and gRPC-Web
/// (`application/grpc-web*`) content types, including the `+json` variants.
/// Their bodies are length-prefixed wire frames owned by the gRPC/gRPC-Web
/// machinery, not a bare JSON document, so the governor releases them back to
/// the streaming path instead of buffering them for JSON inspection. Mirrors
/// `ai_request_guard`/`ai_rate_limiter`.
fn is_framed_grpc_content_type(content_type: &str) -> bool {
    crate::proxy::backend_dispatch::is_native_grpc_content_type(content_type.as_bytes())
        || crate::plugins::grpc_web::is_grpc_web_content_type(content_type)
}

/// Whether a request `Content-Type` labels a bare JSON document this plugin
/// governs. `application/grpc+json` / `application/grpc-web+json` carry a
/// `+json` suffix but their bodies are length-prefixed gRPC wire frames, not a
/// JSON document — on a mixed proxy those requests must be out of scope
/// (mirroring the response-side framed-gRPC release), not buffered and then
/// fail-closed as unparseable JSON.
fn is_governable_json_request_content_type(content_type: &str) -> bool {
    is_json_content_type(content_type) && !is_framed_grpc_content_type(content_type)
}

fn is_json_rpc_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .eq_ignore_ascii_case("application/json-rpc")
}

/// Whether the request was marked as streaming: an `Accept: text/event-stream`
/// header, a shared `ai_request_streaming` marker from an earlier plugin, or
/// this plugin's own `stream: true` request-body detection (set in
/// `before_proxy`). Used to scope streaming-only buffered inspection to the SSE
/// fallback of a streaming request rather than every JSON response.
fn request_is_streaming(ctx: &RequestContext) -> bool {
    is_sse_request(ctx)
        || ctx.metadata.get("ai_request_streaming").map(String::as_str) == Some("true")
        || ctx.metadata.get(STREAM_REQUESTED_KEY).map(String::as_str) == Some("true")
}

/// The serving-provider name an upstream AI routing plugin recorded, used for
/// approval webhook/cache correlation. Precedence: `ai_federation_provider`
/// (the unique `ai_federation` provider name) → `ai_stream_router.provider`
/// (the unique `ai_stream_router` provider name) → `ai_provider` (the coarse
/// provider type), so two configured providers of the same type/model/proxy
/// are never conflated into one approval decision or cache entry.
fn federation_provider(ctx: &RequestContext) -> Option<String> {
    [
        "ai_federation_provider",
        "ai_stream_router.provider",
        "ai_provider",
    ]
    .into_iter()
    .find_map(|key| ctx.metadata.get(key).filter(|p| !p.is_empty()).cloned())
}

/// The non-identity `Content-Encoding` header value, trimmed, or `None` when
/// absent/empty/`identity`.
fn content_encoding_value(headers: &HashMap<String, String>) -> Option<&str> {
    header_value(headers, "content-encoding")
        .map(str::trim)
        .filter(|enc| !enc.is_empty() && !enc.eq_ignore_ascii_case("identity"))
}

/// Parse `body` as JSON only when it is within the inspectable size limit. A
/// leading UTF-8 BOM is stripped before the parse (`serde_json` rejects a
/// BOM-prefixed document), so a `\u{feff}`-prefixed Chat Completions response
/// cannot slip a denied tool call past the governor by making the parse fail.
fn parse_json_within_limit(body: &[u8]) -> Option<Value> {
    if body.is_empty() || body.len() > MAX_PARSE_BYTES {
        return None;
    }
    serde_json::from_slice(strip_json_bom(body)).ok()
}

/// Decompress a gateway-encoded response body (the same `gzip`/`br` encodings
/// the `compression` plugin produces), bounded by [`MAX_PARSE_BYTES`] so a
/// decompression bomb cannot blow up memory. Returns `None` for unsupported
/// encodings, decode errors, or output past the limit.
fn decompress_within_limit(encoding: &str, data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    // A single encoding token only (the compression plugin emits exactly one).
    let mut out = Vec::new();
    let limit = MAX_PARSE_BYTES as u64;
    match encoding.trim().to_ascii_lowercase().as_str() {
        "gzip" | "x-gzip" => {
            let mut reader = flate2::read::MultiGzDecoder::new(data).take(limit + 1);
            reader.read_to_end(&mut out).ok()?;
        }
        "br" => {
            let mut reader = brotli::Decompressor::new(data, 4096).take(limit + 1);
            reader.read_to_end(&mut out).ok()?;
        }
        _ => return None,
    }
    if out.len() as u64 > limit {
        return None;
    }
    Some(out)
}

fn redacted_approval_url(parsed: &Url) -> String {
    let mut redacted = parsed.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.set_path("/...");
    redacted.set_query(None);
    redacted.set_fragment(None);
    redacted.to_string()
}

/// Stable key for staging a preflighted redaction rewrite between buffered
/// governance and the response-body transform. Uses a digest so the map does
/// not retain a second copy of raw hostile arguments as the key. A fixed-width
/// name-length prefix keeps arbitrary JSON strings unambiguous (tool names and
/// arguments may both contain NUL or any other delimiter candidate).
fn redaction_memo_key(name: &str, raw_args: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name.len().to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(raw_args.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Replace each blocked-pattern match in a raw arguments string with the
/// rendered redaction placeholder. Apply every blocked-argument pattern while
/// checking each append before allocation, failing closed when the redacted
/// output would exceed [`MAX_PARSE_BYTES`]. Patterns that match empty input are
/// rejected at config load; the per-match zero-width check also catches
/// contextual assertions (for example `\b`) that can match an empty span only
/// beside non-empty input.
fn redact_arguments(
    args: &str,
    patterns: &[BlockedArgPattern],
    placeholder: &str,
) -> Result<(String, bool), ()> {
    if args.len() > MAX_PARSE_BYTES {
        return Err(());
    }
    let mut result = args.to_string();
    for pattern in patterns {
        // Defense in depth: config admission rejects patterns that match empty
        // input. Contextual assertions can still produce a zero-length match
        // only beside non-empty input, so reject those spans below as well.
        if pattern.regex.is_match("") {
            return Err(());
        }
        let rendered = render_redaction_placeholder(placeholder, &pattern.name)?;
        let mut matches = pattern.regex.find_iter(&result);
        let Some(first_match) = matches.next() else {
            continue;
        };
        let mut replaced = String::with_capacity(result.len());
        let mut cursor = 0;
        for matched in std::iter::once(first_match).chain(matches) {
            if matched.start() == matched.end() {
                return Err(());
            }
            push_redaction_bytes(&mut replaced, &result[cursor..matched.start()])?;
            push_redaction_bytes(&mut replaced, &rendered)?;
            cursor = matched.end();
        }
        push_redaction_bytes(&mut replaced, &result[cursor..])?;
        result = replaced;
    }
    let changed = result != args;
    Ok((result, changed))
}

/// Render `{name}` without allowing an unbounded intermediate allocation from
/// an operator-supplied pattern name.
fn render_redaction_placeholder(placeholder: &str, name: &str) -> Result<String, ()> {
    let mut rendered = String::with_capacity(placeholder.len());
    let mut cursor = 0;
    for (start, token) in placeholder.match_indices("{name}") {
        push_redaction_bytes(&mut rendered, &placeholder[cursor..start])?;
        push_redaction_bytes(&mut rendered, name)?;
        cursor = start + token.len();
    }
    push_redaction_bytes(&mut rendered, &placeholder[cursor..])?;
    Ok(rendered)
}

fn push_redaction_bytes(output: &mut String, value: &str) -> Result<(), ()> {
    let next_len = output.len().checked_add(value.len()).ok_or(())?;
    if next_len > MAX_PARSE_BYTES {
        return Err(());
    }
    output.push_str(value);
    Ok(())
}

/// Serialize a transformed JSON response without ever retaining more than the
/// inspectable body limit. `serde_json::to_vec` would allocate the complete
/// escaped representation before the caller could reject an oversized result.
fn serialize_json_bounded(value: &Value) -> Result<Vec<u8>, ()> {
    struct BoundedWriter {
        output: Vec<u8>,
    }

    impl std::io::Write for BoundedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let next_len = self.output.len().checked_add(bytes.len()).ok_or_else(|| {
                std::io::Error::other("ai_tool_governor JSON output length overflow")
            })?;
            if next_len > MAX_PARSE_BYTES {
                return Err(std::io::Error::other(
                    "ai_tool_governor JSON output exceeds inspectable limit",
                ));
            }
            self.output.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut writer = BoundedWriter {
        output: Vec::with_capacity(64 * 1024),
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| ())?;
    Ok(writer.output)
}

/// Borrow the leading `max_bytes` bytes of `s`, snapped down to a char boundary
/// so the excerpt never splits a multi-byte character.
fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn sha256_hex(input: &str) -> String {
    sha256_hex_bytes(input.as_bytes())
}

/// Strip a single leading UTF-8 BOM (`EF BB BF`) so JSON parsing/shape checks
/// see the document itself. `serde_json` rejects a BOM-prefixed body, so a
/// backend (or a `response_transformer`) that emits `\u{feff}{...}` would make
/// `on_response_body`/`on_final_response_body` fail to parse and — with no
/// `Content-Encoding` — forward a denied `choices[].message.tool_calls[]`
/// ungoverned. The SSE parser already strips the BOM (`classify_event`,
/// `looks_like_sse`); this is the JSON-path counterpart, applied on every
/// JSON parse in this plugin so the two paths cannot diverge again. Only the
/// PARSE/SHAPE view is stripped — the governed-response hash still covers the
/// RAW bytes on both `on_response_body` and the final re-check, so the
/// hash-skip stays consistent.
fn strip_json_bom(body: &[u8]) -> &[u8] {
    body.strip_prefix(b"\xEF\xBB\xBF".as_slice())
        .unwrap_or(body)
}

/// Whether a body's first non-whitespace byte starts a JSON object/array. Used
/// so a `request_transformer`/`response_transformer` that removes or rewrites the
/// `Content-Type` header cannot disable governance while leaving the JSON body
/// intact — a JSON-shaped body is still inspected. Bounds the extra parse to
/// bodies that actually look like JSON. BOM-tolerant (mirrors `looks_like_sse`)
/// so a BOM-prefixed JSON body a header rule relabeled still routes into the
/// JSON parse rather than being skipped by the content-type/shape gate.
fn looks_like_json(body: &[u8]) -> bool {
    matches!(
        strip_json_bom(body)
            .iter()
            .copied()
            .find(|b| !b.is_ascii_whitespace()),
        Some(b'{') | Some(b'[')
    )
}

/// Whether a body is shaped like a Server-Sent Events stream: after an optional
/// UTF-8 BOM and leading whitespace/blank lines, the first non-empty line is a
/// syntactically valid SSE field or comment line. Printable ASCII colonless
/// extension fields are skipped until a later field provides positive SSE
/// evidence; standard `data`/`event`/`id`/`retry` fields are evidence even when
/// their value-separating `:` is omitted.
/// The same tightened check as [`sniff_stream_shape`], so live and buffered
/// classification agree: the SSE spec ignores unknown field names, and
/// legitimate extension/heartbeat preludes like `ping: 1` or the standard
/// `: ping` keepalive comment must not bypass the shape fallback.
/// The SSE-shape counterpart of [`looks_like_json`]: an upstream that omits
/// `Content-Type: text/event-stream` (or a `response_transformer` header rule
/// that relabels it, e.g. to `text/plain`) must not route a buffered SSE body
/// with governed tool-call deltas past `govern_buffered_sse` uninspected. A
/// JSON-opening body (`{`/`[`) is explicitly NOT SSE-shaped, so the two shape
/// checks stay disjoint; binary/control-byte starts are not SSE-shaped either.
fn looks_like_sse(body: &[u8]) -> bool {
    matches!(sniff_stream_shape(body), StreamSniff::Sse)
}

/// Unambiguous correlated identity hash of a governed tool call. It hashes the
/// same JSON array as the approval cache key — correlation fields plus name and
/// raw args — so an approval-relevant rewrite is evaluated under the new
/// context instead of riding the old decision.
fn correlated_call_identity_hash(corr: &CorrelationMeta, call: &ToolCall) -> String {
    sha256_hex(
        &json!([
            corr.consumer.as_deref(),
            corr.proxy.as_deref(),
            corr.model.as_deref(),
            corr.provider.as_deref(),
            call.name.as_str(),
            call.raw_args.as_str(),
        ])
        .to_string(),
    )
}

/// Identity for a deterministic `redact_args` result. The request-scoped
/// instance ledger already provides isolation, and name/args are the only
/// inputs to redaction policy; approval-only correlation fields must not make
/// an already-redacted call look new after a model/provider-only rewrite.
fn deterministic_call_identity_hash(call: &ToolCall) -> String {
    sha256_hex(&json!([call.name.as_str(), call.raw_args.as_str()]).to_string())
}

/// Record pre-computed governed-call identity hashes (multiset counts) onto the
/// request context, replacing any previous record. Stored on the non-serialized
/// `ai_tool_governor_call_hashes` field (NOT `ctx.metadata`) so this arg-derived
/// identity ledger never reaches transaction logs, while remaining readable to
/// this exact plugin instance's own later hooks (the `on_final_response_body`
/// re-check).
fn record_governed_identities(ctx: &mut RequestContext, instance_id: u64, identities: &[String]) {
    if identities.is_empty() {
        return;
    }
    let counts = ctx
        .ai_tool_governor_call_hashes
        .entry(instance_id)
        .or_default();
    counts.clear();
    for hash in identities {
        *counts.entry(hash.clone()).or_insert(0) += 1;
    }
}

/// Read the recorded governed-call identity counts from the request context.
fn governed_call_counts(ctx: &RequestContext, instance_id: u64) -> HashMap<String, usize> {
    ctx.ai_tool_governor_call_hashes
        .get(&instance_id)
        .cloned()
        .unwrap_or_default()
}

fn sha256_hex_bytes(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

/// Keep runtime admission as strict as the OpenAPI fixed-shape objects. Runs
/// before ordinary type/value parsing (and before the `enabled: false`
/// short-circuit) so a valid sibling field can never mask a misspelled
/// enforcement control. The free-form `tools` name map and arbitrary
/// `json_schema` document contents are intentionally not closed.
fn validate_config_keys(config: &serde_json::Map<String, Value>) -> Result<(), String> {
    reject_unknown_keys(
        config,
        "config",
        AI_TOOL_GOVERNOR_CONFIG_KEYS,
        "ai_tool_governor: ",
    )?;

    if let Some(object) = config.get("inspect").and_then(Value::as_object) {
        reject_unknown_keys(
            object,
            "config.inspect",
            AI_TOOL_GOVERNOR_INSPECT_KEYS,
            "ai_tool_governor: ",
        )?;
    }

    if let Some(tools) = config.get("tools").and_then(Value::as_object) {
        for (tool_name, spec) in tools {
            let Some(object) = spec.as_object() else {
                continue;
            };
            let tool_path = format!("config.tools.{tool_name}");
            reject_unknown_keys(
                object,
                &tool_path,
                AI_TOOL_GOVERNOR_TOOL_POLICY_KEYS,
                "ai_tool_governor: ",
            )?;
            if let Some(patterns) = object.get("blocked_arg_patterns").and_then(Value::as_array) {
                for (idx, entry) in patterns.iter().enumerate() {
                    if let Some(entry_obj) = entry.as_object() {
                        reject_unknown_keys(
                            entry_obj,
                            &format!("{tool_path}.blocked_arg_patterns[{idx}]"),
                            AI_TOOL_GOVERNOR_BLOCKED_PATTERN_KEYS,
                            "ai_tool_governor: ",
                        )?;
                    }
                }
            }
            // `json_schema` remains an intentionally open JSON Schema document.
        }
    }

    if let Some(object) = config.get("approval").and_then(Value::as_object) {
        reject_unknown_keys(
            object,
            "config.approval",
            AI_TOOL_GOVERNOR_APPROVAL_KEYS,
            "ai_tool_governor: ",
        )?;
    }
    if let Some(object) = config.get("response").and_then(Value::as_object) {
        reject_unknown_keys(
            object,
            "config.response",
            AI_TOOL_GOVERNOR_RESPONSE_KEYS,
            "ai_tool_governor: ",
        )?;
    }
    if let Some(object) = config.get("observability").and_then(Value::as_object) {
        reject_unknown_keys(
            object,
            "config.observability",
            AI_TOOL_GOVERNOR_OBSERVABILITY_KEYS,
            "ai_tool_governor: ",
        )?;
    }

    Ok(())
}

fn parse_inspect(config: &Value) -> Result<InspectConfig, String> {
    let inspect = config.get("inspect");
    if let Some(inspect) = inspect
        && !inspect.is_object()
    {
        return Err("ai_tool_governor: 'inspect' must be an object".to_string());
    }
    if let Some(object) = inspect.and_then(Value::as_object) {
        reject_unknown_keys(
            object,
            "config.inspect",
            AI_TOOL_GOVERNOR_INSPECT_KEYS,
            "ai_tool_governor: ",
        )?;
    }
    let get = |key: &'static str, default: bool| -> Result<bool, String> {
        match inspect.and_then(|i| i.get(key)) {
            None => Ok(default),
            Some(v) => v
                .as_bool()
                .ok_or_else(|| format!("ai_tool_governor: 'inspect.{key}' must be a boolean")),
        }
    };
    Ok(InspectConfig {
        request_tool_definitions: get("request_tool_definitions", false)?,
        response_tool_calls: get("response_tool_calls", true)?,
        streaming_response_tool_calls: get("streaming_response_tool_calls", false)?,
        mcp_tool_calls: get("mcp_tool_calls", false)?,
        a2a_methods: get("a2a_methods", false)?,
    })
}

fn parse_tool_policy(name: &str, spec: &Value) -> Result<ToolPolicy, String> {
    let obj = spec
        .as_object()
        .ok_or_else(|| format!("ai_tool_governor: tool '{name}' policy must be an object"))?;
    let tool_path = format!("config.tools.{name}");
    reject_unknown_keys(
        obj,
        &tool_path,
        AI_TOOL_GOVERNOR_TOOL_POLICY_KEYS,
        "ai_tool_governor: ",
    )?;

    let action = match obj.get("action").and_then(Value::as_str) {
        Some("allow") => ToolAction::Allow,
        Some("deny") => ToolAction::Deny,
        Some("redact_args") => ToolAction::RedactArgs,
        Some("require_approval") => ToolAction::RequireApproval,
        Some("dry_run") => ToolAction::DryRun,
        Some(other) => {
            return Err(format!(
                "ai_tool_governor: tool '{name}' has invalid action {other:?} (expected allow, deny, redact_args, require_approval, or dry_run)"
            ));
        }
        None => {
            return Err(format!(
                "ai_tool_governor: tool '{name}' is missing required 'action'"
            ));
        }
    };

    let risk = match obj.get("risk").and_then(Value::as_str) {
        None => RiskLevel::Low,
        Some("low") => RiskLevel::Low,
        Some("medium") => RiskLevel::Medium,
        Some("high") => RiskLevel::High,
        Some("critical") => RiskLevel::Critical,
        Some(other) => {
            return Err(format!(
                "ai_tool_governor: tool '{name}' has invalid risk {other:?} (expected low, medium, high, or critical)"
            ));
        }
    };

    let max_arg_bytes = match obj.get("max_arg_bytes") {
        None => None,
        Some(v) => {
            let n = v.as_u64().ok_or_else(|| {
                format!(
                    "ai_tool_governor: tool '{name}' 'max_arg_bytes' must be a non-negative integer"
                )
            })?;
            Some(usize::try_from(n).map_err(|_| {
                format!("ai_tool_governor: tool '{name}' 'max_arg_bytes' is too large")
            })?)
        }
    };

    let mut required_args = Vec::new();
    if let Some(v) = obj.get("required_args") {
        let arr = v.as_array().ok_or_else(|| {
            format!("ai_tool_governor: tool '{name}' 'required_args' must be an array of strings")
        })?;
        for (idx, entry) in arr.iter().enumerate() {
            let s = entry.as_str().ok_or_else(|| {
                format!("ai_tool_governor: tool '{name}' 'required_args[{idx}]' must be a string")
            })?;
            if s.is_empty() {
                return Err(format!(
                    "ai_tool_governor: tool '{name}' 'required_args[{idx}]' must not be empty"
                ));
            }
            required_args.push(s.to_string());
        }
    }

    let mut blocked_arg_patterns = Vec::new();
    if let Some(v) = obj.get("blocked_arg_patterns") {
        let arr = v.as_array().ok_or_else(|| {
            format!("ai_tool_governor: tool '{name}' 'blocked_arg_patterns' must be an array")
        })?;
        if arr.len() > MAX_BLOCKED_ARG_PATTERNS {
            return Err(format!(
                "ai_tool_governor: tool '{name}' 'blocked_arg_patterns' must have at most {MAX_BLOCKED_ARG_PATTERNS} entries"
            ));
        }
        for (idx, entry) in arr.iter().enumerate() {
            let entry_obj = entry.as_object().ok_or_else(|| {
                format!(
                    "ai_tool_governor: tool '{name}' 'blocked_arg_patterns[{idx}]' must be an object"
                )
            })?;
            reject_unknown_keys(
                entry_obj,
                &format!("{tool_path}.blocked_arg_patterns[{idx}]"),
                AI_TOOL_GOVERNOR_BLOCKED_PATTERN_KEYS,
                "ai_tool_governor: ",
            )?;
            let pattern_name = entry_obj
                .get("name")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    format!(
                        "ai_tool_governor: tool '{name}' 'blocked_arg_patterns[{idx}].name' is required"
                    )
                })?;
            if pattern_name.len() > MAX_BLOCKED_ARG_PATTERN_NAME_BYTES {
                return Err(format!(
                    "ai_tool_governor: tool '{name}' 'blocked_arg_patterns[{idx}].name' must be <= {MAX_BLOCKED_ARG_PATTERN_NAME_BYTES} UTF-8 bytes"
                ));
            }
            let regex_str = entry_obj
                .get("regex")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    format!(
                        "ai_tool_governor: tool '{name}' 'blocked_arg_patterns[{idx}].regex' is required"
                    )
                })?;
            let regex = Regex::new(regex_str).map_err(|e| {
                format!(
                    "ai_tool_governor: tool '{name}' 'blocked_arg_patterns[{idx}]' invalid regex: {e}"
                )
            })?;
            // Zero-width matches let `replace_all` insert the placeholder at
            // every position and amplify a bounded argument into gigabytes.
            if regex.is_match("") {
                return Err(format!(
                    "ai_tool_governor: tool '{name}' 'blocked_arg_patterns[{idx}].regex' must not match the empty string (zero-width redaction is rejected)"
                ));
            }
            blocked_arg_patterns.push(BlockedArgPattern {
                name: pattern_name.to_string(),
                regex,
            });
        }
    }
    if action == ToolAction::RedactArgs && blocked_arg_patterns.is_empty() {
        return Err(format!(
            "ai_tool_governor: tool '{name}' action 'redact_args' requires at least one 'blocked_arg_patterns' entry"
        ));
    }

    let json_schema = match obj.get("json_schema") {
        None => None,
        Some(schema) => {
            if !schema.is_object() {
                return Err(format!(
                    "ai_tool_governor: tool '{name}' 'json_schema' must be an object"
                ));
            }
            Some(jsonschema::validator_for(schema).map_err(|e| {
                format!(
                    "ai_tool_governor: tool '{name}' 'json_schema' is not a valid JSON Schema: {e}"
                )
            })?)
        }
    };

    Ok(ToolPolicy {
        action,
        risk,
        max_arg_bytes,
        required_args,
        blocked_arg_patterns,
        json_schema,
    })
}

fn parse_approval(
    config: &Value,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<Option<ApprovalConfig>, String> {
    let Some(approval) = config.get("approval") else {
        return Ok(None);
    };
    let obj = approval
        .as_object()
        .ok_or_else(|| "ai_tool_governor: 'approval' must be an object".to_string())?;
    reject_unknown_keys(
        obj,
        "config.approval",
        AI_TOOL_GOVERNOR_APPROVAL_KEYS,
        "ai_tool_governor: ",
    )?;

    let endpoint_url = obj
        .get("endpoint_url")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "ai_tool_governor: 'approval.endpoint_url' is required".to_string())?;

    let parsed = url::Url::parse(endpoint_url).map_err(|e| {
        format!("ai_tool_governor: 'approval.endpoint_url' is not a valid URL: {e}")
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(
            "ai_tool_governor: 'approval.endpoint_url' must be an http/https URL".to_string(),
        );
    }
    crate::plugins::utils::log_helpers::screen_url_host_egress(
        "ai_tool_governor",
        "approval.endpoint_url",
        &parsed,
        backend_allow_ips,
    )?;
    let hostname = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| {
            "ai_tool_governor: 'approval.endpoint_url' must have a hostname".to_string()
        })?
        .to_string();

    let timeout_ms = match obj.get("timeout_ms") {
        None => DEFAULT_APPROVAL_TIMEOUT_MS,
        Some(v) => {
            let n = v.as_u64().filter(|n| *n > 0).ok_or_else(|| {
                "ai_tool_governor: 'approval.timeout_ms' must be a positive integer".to_string()
            })?;
            if n > MAX_APPROVAL_TIMEOUT_MS {
                return Err(format!(
                    "ai_tool_governor: 'approval.timeout_ms' must be <= {MAX_APPROVAL_TIMEOUT_MS}"
                ));
            }
            n
        }
    };

    let cache_ttl_seconds = match obj.get("cache_ttl_seconds") {
        None => DEFAULT_APPROVAL_CACHE_TTL_S,
        Some(v) => v.as_u64().ok_or_else(|| {
            "ai_tool_governor: 'approval.cache_ttl_seconds' must be a non-negative integer"
                .to_string()
        })?,
    };
    if cache_ttl_seconds > MAX_APPROVAL_CACHE_TTL_S {
        return Err(format!(
            "ai_tool_governor: 'approval.cache_ttl_seconds' must be <= {MAX_APPROVAL_CACHE_TTL_S}"
        ));
    }

    let fail_on_error = match obj.get("fail_on_error").and_then(Value::as_str) {
        None | Some("reject") => FailOnError::Reject,
        Some("warn") => FailOnError::Warn,
        Some("allow") => FailOnError::Allow,
        Some(other) => {
            return Err(format!(
                "ai_tool_governor: 'approval.fail_on_error' must be one of 'reject', 'warn', or 'allow', got {other:?}"
            ));
        }
    };

    let include_arguments = match obj.get("include_arguments") {
        None => false,
        Some(v) => v.as_bool().ok_or_else(|| {
            "ai_tool_governor: 'approval.include_arguments' must be a boolean".to_string()
        })?,
    };

    Ok(Some(ApprovalConfig {
        endpoint_url: endpoint_url.to_string(),
        redacted_endpoint_url: redacted_approval_url(&parsed),
        hostname,
        timeout: Duration::from_millis(timeout_ms),
        cache_ttl: Duration::from_secs(cache_ttl_seconds),
        fail_on_error,
        include_arguments,
    }))
}

fn parse_response(config: &Value) -> Result<ResponseConfig, String> {
    let response = config.get("response");
    if let Some(response) = response
        && !response.is_object()
    {
        return Err("ai_tool_governor: 'response' must be an object".to_string());
    }
    if let Some(object) = response.and_then(Value::as_object) {
        reject_unknown_keys(
            object,
            "config.response",
            AI_TOOL_GOVERNOR_RESPONSE_KEYS,
            "ai_tool_governor: ",
        )?;
    }

    let deny_status_code = match response.and_then(|r| r.get("deny_status_code")) {
        None => DEFAULT_DENY_STATUS,
        Some(v) => {
            let n = v.as_u64().ok_or_else(|| {
                "ai_tool_governor: 'response.deny_status_code' must be an integer".to_string()
            })?;
            if !(400..=599).contains(&n) {
                return Err(
                    "ai_tool_governor: 'response.deny_status_code' must be an HTTP error status (400-599)"
                        .to_string(),
                );
            }
            n as u16
        }
    };

    let redaction_placeholder = response
        .and_then(|r| r.get("redaction_placeholder"))
        .map(|v| {
            v.as_str().map(str::to_string).ok_or_else(|| {
                "ai_tool_governor: 'response.redaction_placeholder' must be a string".to_string()
            })
        })
        .transpose()?
        .unwrap_or_else(|| DEFAULT_REDACTION_PLACEHOLDER.to_string());
    if redaction_placeholder.len() > MAX_REDACTION_PLACEHOLDER_BYTES {
        return Err(format!(
            "ai_tool_governor: 'response.redaction_placeholder' must be <= {MAX_REDACTION_PLACEHOLDER_BYTES} UTF-8 bytes"
        ));
    }

    let streaming_deny_event = match response.and_then(|r| r.get("streaming_deny_event")) {
        None => true,
        Some(v) => v.as_bool().ok_or_else(|| {
            "ai_tool_governor: 'response.streaming_deny_event' must be a boolean".to_string()
        })?,
    };

    Ok(ResponseConfig {
        deny_status_code,
        redaction_placeholder,
        streaming_deny_event,
    })
}

fn parse_observability(config: &Value) -> Result<ObservabilityConfig, String> {
    let obs = config.get("observability");
    if let Some(obs) = obs
        && !obs.is_object()
    {
        return Err("ai_tool_governor: 'observability' must be an object".to_string());
    }
    if let Some(object) = obs.and_then(Value::as_object) {
        reject_unknown_keys(
            object,
            "config.observability",
            AI_TOOL_GOVERNOR_OBSERVABILITY_KEYS,
            "ai_tool_governor: ",
        )?;
    }

    let emit_metadata = match obs.and_then(|o| o.get("emit_metadata")) {
        None => true,
        Some(v) => v.as_bool().ok_or_else(|| {
            "ai_tool_governor: 'observability.emit_metadata' must be a boolean".to_string()
        })?,
    };
    let hash_arguments = match obs.and_then(|o| o.get("hash_arguments")) {
        None => true,
        Some(v) => v.as_bool().ok_or_else(|| {
            "ai_tool_governor: 'observability.hash_arguments' must be a boolean".to_string()
        })?,
    };
    let max_argument_log_bytes = match obs.and_then(|o| o.get("max_argument_log_bytes")) {
        None => 0,
        Some(v) => {
            let n = v.as_u64().ok_or_else(|| {
                "ai_tool_governor: 'observability.max_argument_log_bytes' must be a non-negative integer"
                    .to_string()
            })?;
            usize::try_from(n).map_err(|_| {
                "ai_tool_governor: 'observability.max_argument_log_bytes' is too large".to_string()
            })?
        }
    };

    Ok(ObservabilityConfig {
        emit_metadata,
        hash_arguments,
        max_argument_log_bytes,
    })
}

// ---------------------------------------------------------------------------
// Small config accessors
// ---------------------------------------------------------------------------

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    match config.get(field) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("ai_tool_governor: '{field}' must be a string")),
    }
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    match config.get(field) {
        None => Ok(None),
        Some(v) => v
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("ai_tool_governor: '{field}' must be a boolean")),
    }
}

fn optional_object<'a>(
    config: &'a Value,
    field: &'static str,
) -> Result<Option<&'a serde_json::Map<String, Value>>, String> {
    match config.get(field) {
        None => Ok(None),
        Some(v) => v
            .as_object()
            .map(Some)
            .ok_or_else(|| format!("ai_tool_governor: '{field}' must be an object")),
    }
}
