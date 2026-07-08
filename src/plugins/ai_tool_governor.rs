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
//!   deltas, accumulated across split frames; tool-call frames are HELD until
//!   the call is complete and policy/approval clears it, then released — or the
//!   stream is terminated with an SSE error event, never leaking the held call.
//! - **MCP `tools/call`** and **A2A JSON-RPC methods** (optional, off by
//!   default): direct JSON-RPC body parsing on the request path.
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
//! the re-check decompresses the gateway's own `gzip`/`br` encoding and inspects
//! that, so an injected-then-compressed tool call cannot slip through. Redaction
//! is unavailable on these re-check paths (no request-body transform, and the
//! response redaction transform already ran), so a `redact_args` match there
//! fails closed instead of forwarding the secret.
//!
//! Non-goals (MVP): it does not execute tools, manage MCP sessions, replace
//! `mcp_gateway`/A2A routing, or implement an approval UI.

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use regex::Regex;
use serde_json::{Value, json};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};
use tracing::{debug, warn};
use url::Url;

use sha2::{Digest, Sha256};

use super::utils::ai_providers::{detect_response_provider, detect_sse_provider};
use super::utils::body_transform::{is_event_stream_content_type, is_json_content_type};
use super::utils::json_escape::escape_json_string;
use super::utils::sse::{encode_sse_error_event, is_sse_request};
use super::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, ResponseStreamAction,
    ResponseStreamInspector,
};

/// Default deny status code for blocked tool calls / definitions.
const DEFAULT_DENY_STATUS: u16 = 502;
/// Default redaction placeholder template (`{name}` → matched-pattern name).
const DEFAULT_REDACTION_PLACEHOLDER: &str = "[REDACTED_TOOL_ARG:{name}]";
/// Default approval webhook timeout.
const DEFAULT_APPROVAL_TIMEOUT_MS: u64 = 1500;
/// Default approval cache TTL.
const DEFAULT_APPROVAL_CACHE_TTL_S: u64 = 300;
/// Maximum approval cache TTL. Larger values risk overflowing `Instant`
/// arithmetic on some platforms and keep stale approvals alive too long.
const MAX_APPROVAL_CACHE_TTL_S: u64 = 30 * 24 * 60 * 60;
/// Upper bound on the body size this plugin will parse for tool calls, so an
/// oversized (already-buffered) body cannot spend unbounded CPU in serde. In
/// `enforce` mode a governed body past this limit is REJECTED (fail closed —
/// padding a request/response past the parse limit must not smuggle a governed
/// call past policy); in `dry_run` it is forwarded uninspected.
const MAX_PARSE_BYTES: usize = 4 * 1024 * 1024;
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
const STREAM_REQUESTED_KEY: &str = "ai_tool_governor.stream_requested";
const STREAM_MODEL_KEY: &str = "ai_tool_governor.stream_model";
/// SHA-256 (hex) of the request/response body the deterministic policy last ran
/// over, recorded in `before_proxy` / `on_response_body`. The post-transform
/// `on_final_request_body` / `on_final_response_body` re-checks compare against
/// it so an unchanged body is not governed twice (avoids duplicate approval
/// webhooks) while a body a later `request_transformer` / `response_transformer`
/// rewrote is re-evaluated against the same policy.
const GOVERNED_REQUEST_HASH_KEY: &str = "ai_tool_governor.governed_request_hash";
const GOVERNED_RESPONSE_HASH_KEY: &str = "ai_tool_governor.governed_response_hash";

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
    include_prompt_excerpt: bool,
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
}

/// Deterministic per-call outcome, before any approval resolution.
enum PolicyOutcome {
    Allow,
    Deny(String),
    Redact(Vec<String>),
    RequireApproval,
    DryRun,
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
    overall_label: &'static str,
    max_risk: RiskLevel,
    deny_reason: Option<String>,
}

fn label_rank(label: &str) -> u8 {
    match label {
        "deny" => 5,
        "approval_denied" => 4,
        "require_approval" => 3,
        "approved" => 2,
        _ => 1, // allow / dry_run / redact-forward
    }
}

impl GovernorEngine {
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

    /// Whether exposing a tool *definition* (name only, no arguments) is
    /// blocked. `require_approval` cannot be resolved for a bare definition
    /// because there are no concrete arguments to send to the approval webhook.
    fn definition_blocked(&self, name: &str) -> bool {
        match self.tools.get(name) {
            Some(policy) => matches!(
                policy.action,
                ToolAction::Deny | ToolAction::RequireApproval
            ),
            None => matches!(
                self.default_action,
                DefaultAction::Deny | DefaultAction::RequireApproval
            ),
        }
    }

    /// Govern a batch of concrete tool calls. `redaction_unavailable` treats a
    /// matched `redact_args` pattern as a block (fail closed): on paths that
    /// cannot rewrite the arguments in place — mid-stream SSE deltas, the
    /// request body (no request-body transform), and the post-transform final
    /// response re-check — the safe behavior is to reject rather than forward an
    /// unredacted secret. Only the buffered response path (which has a
    /// `transform_response_body` redaction hook) passes `false`.
    async fn govern_calls(
        &self,
        corr: &CorrelationMeta,
        calls: &[ToolCall],
        ns: &AtomicU64,
        redaction_unavailable: bool,
    ) -> BatchDecision {
        let mut per_call = Vec::with_capacity(calls.len());
        let skip_approvals = self.mode == Mode::Enforce
            && calls.iter().any(|call| {
                let (outcome, _, _) =
                    self.evaluate(&call.name, &call.raw_args, call.parsed_args.as_ref());
                match outcome {
                    PolicyOutcome::Deny(_) => true,
                    PolicyOutcome::Redact(patterns) => {
                        redaction_unavailable && !patterns.is_empty()
                    }
                    _ => false,
                }
            });

        for call in calls {
            let (outcome, matched, risk) =
                self.evaluate(&call.name, &call.raw_args, call.parsed_args.as_ref());
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
                redact_patterns: Vec::new(),
                approval_id: None,
                arguments_hash: arguments_hash.clone(),
                reason: None,
            };

            match outcome {
                PolicyOutcome::Allow => {}
                PolicyOutcome::DryRun => {
                    // Per-tool dry-run: forward, but record the observational label.
                    cd.label = "allow";
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
                        cd.reason = Some(format!(
                            "tool '{}' matched a redact_args policy on a path where arguments cannot be redacted in place (failing closed)",
                            call.name
                        ));
                    } else {
                        cd.label = "allow";
                        cd.redact_patterns = patterns;
                    }
                }
                PolicyOutcome::RequireApproval => {
                    if skip_approvals {
                        cd.label = "require_approval";
                    } else {
                        self.resolve_require_approval(
                            corr,
                            call,
                            &arguments_hash,
                            risk,
                            ns,
                            &mut cd,
                        )
                        .await;
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

        BatchDecision {
            per_call,
            enforce_blocks,
            overall_label,
            max_risk,
            deny_reason,
        }
    }

    /// Resolve a `require_approval` outcome onto `cd`, honoring dry-run mode,
    /// the approval cache, the webhook, and `fail_on_error`.
    async fn resolve_require_approval(
        &self,
        corr: &CorrelationMeta,
        call: &ToolCall,
        arguments_hash: &Option<String>,
        risk: RiskLevel,
        ns: &AtomicU64,
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
            cd.reason = Some("approval endpoint not configured".to_string());
            return;
        };

        let hash = arguments_hash
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
        match self.resolve_approval(approval, &input).await {
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
    async fn resolve_approval(
        &self,
        approval: &ApprovalConfig,
        input: &ApprovalInput<'_>,
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

        let (allowed, approval_id) = self.call_approval(approval, input).await?;

        if approval.cache_ttl > Duration::ZERO {
            if self.approval_cache.len() >= MAX_APPROVAL_CACHE_ENTRIES {
                // At capacity: purge expired entries. Argument-varying clients
                // cannot grow this map for the process lifetime.
                let now = Instant::now();
                self.approval_cache.retain(|_, (_, expiry)| *expiry > now);
            }
            if self.approval_cache.len() < MAX_APPROVAL_CACHE_ENTRIES
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
            if approval.include_prompt_excerpt {
                map.insert("arguments".to_string(), json!(input.raw_args));
            }
        }

        let request = self
            .http_client
            .get()
            .post(&approval.endpoint_url)
            .timeout(approval.timeout)
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

        let value: Value = response
            .json()
            .await
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
    enabled: bool,
    inspect: InspectConfig,
    engine: Arc<GovernorEngine>,
    /// True when any tool policy uses `redact_args` — enables the response body
    /// transform on the buffered path.
    needs_response_transform: bool,
    /// Cached copy of the redaction placeholder template for the transform path.
    redaction_placeholder: String,
}

impl AiToolGovernor {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_tool_governor: config must be an object".to_string());
        }

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
                approval_cache: DashMap::new(),
            };
            return Ok(Self {
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
                let policy = parse_tool_policy(name, spec)?;
                if policy.action == ToolAction::RequireApproval {
                    any_require_approval = true;
                }
                if policy.action == ToolAction::RedactArgs {
                    needs_response_transform = true;
                }
                tools.insert(name.clone(), policy);
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

        // Approval endpoint is required when any policy can reach require_approval.
        let approval = parse_approval(config, http_client.backend_allow_ips())?;
        if mode == Mode::Enforce && any_require_approval && approval.is_none() {
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
            approval_cache: DashMap::new(),
        };

        Ok(Self {
            enabled,
            inspect,
            engine: Arc::new(engine),
            needs_response_transform,
            redaction_placeholder,
        })
    }

    fn correlation(
        &self,
        ctx: &RequestContext,
        model: Option<String>,
        provider: Option<&str>,
    ) -> CorrelationMeta {
        CorrelationMeta {
            request_id: ctx
                .metadata
                .get("correlation_id")
                .cloned()
                .unwrap_or_default(),
            consumer: ctx.effective_identity().map(str::to_string),
            proxy: ctx
                .matched_proxy
                .as_ref()
                .map(|p| p.name.clone().unwrap_or_else(|| p.id.clone())),
            model,
            provider: provider.map(str::to_string),
        }
    }

    /// Write aggregate decision metadata onto the request context.
    fn write_metadata(&self, ctx: &mut RequestContext, batch: &BatchDecision) {
        let obs = self.engine.observability;
        if !obs.emit_metadata {
            return;
        }
        let m = &mut ctx.metadata;
        m.insert("ai_tool_governor.enabled".to_string(), "true".to_string());
        m.insert(
            "ai_tool_governor.mode".to_string(),
            self.engine.mode.as_str().to_string(),
        );
        m.insert(
            "ai_tool_governor.decision".to_string(),
            batch.overall_label.to_string(),
        );

        let tool_names: Vec<&str> = batch.per_call.iter().map(|c| c.name.as_str()).collect();
        if !tool_names.is_empty() {
            m.insert(
                "ai_tool_governor.tool_names".to_string(),
                tool_names.join(","),
            );
        }
        m.insert(
            "ai_tool_governor.risk".to_string(),
            batch.max_risk.as_str().to_string(),
        );

        let policy_ids: Vec<&str> = batch
            .per_call
            .iter()
            .filter(|c| c.matched_policy)
            .map(|c| c.name.as_str())
            .collect();
        if !policy_ids.is_empty() {
            m.insert(
                "ai_tool_governor.policy_ids".to_string(),
                policy_ids.join(","),
            );
        }

        let approval_ids: Vec<&str> = batch
            .per_call
            .iter()
            .filter_map(|c| c.approval_id.as_deref())
            .collect();
        if !approval_ids.is_empty() {
            m.insert(
                "ai_tool_governor.approval_id".to_string(),
                approval_ids.join(","),
            );
        }

        if obs.hash_arguments {
            let hashes: Vec<&str> = batch
                .per_call
                .iter()
                .filter_map(|c| c.arguments_hash.as_deref())
                .collect();
            if !hashes.is_empty() {
                m.insert(
                    "ai_tool_governor.arguments_hashes".to_string(),
                    hashes.join(","),
                );
            }
        }

        let redacted: Vec<&str> = batch
            .per_call
            .iter()
            .filter(|c| !c.redact_patterns.is_empty())
            .map(|c| c.name.as_str())
            .collect();
        if !redacted.is_empty() {
            m.insert(
                "ai_tool_governor.redacted_tools".to_string(),
                redacted.join(","),
            );
        }
    }

    fn reject(&self, batch: &BatchDecision) -> PluginResult {
        let reason = batch
            .deny_reason
            .clone()
            .unwrap_or_else(|| "tool call blocked by policy".to_string());
        PluginResult::Reject {
            status_code: self.engine.response.deny_status_code,
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
        if self.engine.observability.emit_metadata {
            let m = &mut ctx.metadata;
            m.insert("ai_tool_governor.enabled".to_string(), "true".to_string());
            m.insert(
                "ai_tool_governor.mode".to_string(),
                self.engine.mode.as_str().to_string(),
            );
            m.insert("ai_tool_governor.decision".to_string(), "deny".to_string());
        }
        PluginResult::Reject {
            status_code: self.engine.response.deny_status_code,
            body: format!(
                r#"{{"error":"ai_tool_governor: {} cannot be inspected","decision":"deny","detail":"{}"}}"#,
                escape_json_string(surface),
                escape_json_string(reason),
            ),
            headers: HashMap::new(),
        }
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
            for entry in entries {
                if self.inspect.mcp_tool_calls
                    && let Some(call) = extract_mcp_tool_call(entry)
                {
                    calls.push(call);
                    continue;
                }
                if self.inspect.a2a_methods
                    && let Some(call) = extract_a2a_method(entry)
                {
                    calls.push(call);
                }
            }
            if calls.is_empty() {
                return PluginResult::Continue;
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
            let denied: Vec<String> = extract_request_tool_definitions(json)
                .into_iter()
                .filter(|name| self.engine.definition_blocked(name))
                .collect();
            if !denied.is_empty() {
                self.write_definition_metadata(ctx, &denied);
                if self.engine.mode == Mode::Enforce {
                    return PluginResult::Reject {
                        status_code: self.engine.response.deny_status_code,
                        body: format!(
                            r#"{{"error":"ai_tool_governor: request exposes disallowed tool definitions","decision":"deny","tools":[{}]}}"#,
                            denied
                                .iter()
                                .map(|t| format!("\"{}\"", escape_json_string(t)))
                                .collect::<Vec<_>>()
                                .join(","),
                        ),
                        headers: HashMap::new(),
                    };
                }
            }
        }

        // 2. MCP tools/call (direct JSON-RPC body parsing).
        if self.inspect.mcp_tool_calls
            && let Some(call) = extract_mcp_tool_call(json)
        {
            let batch = self
                .engine
                .govern_calls(&corr, &[call], &ctx.plugin_http_call_ns, true)
                .await;
            self.write_metadata(ctx, &batch);
            if batch.enforce_blocks {
                return self.reject(&batch);
            }
        }

        // 3. A2A JSON-RPC method policy.
        if self.inspect.a2a_methods
            && let Some(call) = extract_a2a_method(json)
        {
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

    fn write_definition_metadata(&self, ctx: &mut RequestContext, denied: &[String]) {
        if !self.engine.observability.emit_metadata {
            return;
        }
        let m = &mut ctx.metadata;
        m.insert("ai_tool_governor.enabled".to_string(), "true".to_string());
        m.insert(
            "ai_tool_governor.mode".to_string(),
            self.engine.mode.as_str().to_string(),
        );
        m.insert("ai_tool_governor.decision".to_string(), "deny".to_string());
        m.insert("ai_tool_governor.tool_names".to_string(), denied.join(","));
    }

    /// Redact `redact_args` matches in a buffered response body. Deterministic
    /// (no approval), so it runs standalone on the transform path.
    fn redact_response(&self, json: &mut Value) -> bool {
        let mut modified = false;
        let Some(choices) = json.get_mut("choices").and_then(Value::as_array_mut) else {
            return false;
        };
        for choice in choices.iter_mut() {
            let Some(message) = choice.get_mut("message") else {
                continue;
            };
            if let Some(tool_calls) = message.get_mut("tool_calls").and_then(Value::as_array_mut) {
                for tc in tool_calls.iter_mut() {
                    if self.redact_tool_call_function(tc.get_mut("function")) {
                        modified = true;
                    }
                }
            }
            if self.redact_tool_call_function(message.get_mut("function_call")) {
                modified = true;
            }
        }
        modified
    }

    /// Redact one `function`/`function_call` object's `arguments` string in place.
    fn redact_tool_call_function(&self, function: Option<&mut Value>) -> bool {
        let Some(function) = function else {
            return false;
        };
        let Some(name) = function.get("name").and_then(Value::as_str) else {
            return false;
        };
        let Some(policy) = self.engine.tools.get(name) else {
            return false;
        };
        if policy.action != ToolAction::RedactArgs || policy.blocked_arg_patterns.is_empty() {
            return false;
        }
        let Some(args_value) = function.get("arguments") else {
            return false;
        };
        let args = match args_value {
            Value::String(s) => Cow::Borrowed(s.as_str()),
            value => Cow::Owned(value.to_string()),
        };
        let (redacted, changed) = redact_arguments(
            &args,
            &policy.blocked_arg_patterns,
            &self.redaction_placeholder,
        );
        if changed {
            function["arguments"] = Value::String(redacted);
        }
        changed
    }

    /// Govern the tool calls in a FINAL (post-transform) response body. Redaction
    /// is not available here — the redaction transform already ran — so a
    /// `redact_args` match fails closed (`redaction_unavailable = true`).
    async fn govern_final_response(&self, ctx: &mut RequestContext, json: &Value) -> PluginResult {
        let calls = extract_response_tool_calls(json);
        if calls.is_empty() {
            return PluginResult::Continue;
        }
        let provider = detect_response_provider(json).map(|p| p.as_str());
        let model = json
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string);
        let corr = self.correlation(ctx, model, provider);
        let batch = self
            .engine
            .govern_calls(&corr, &calls, &ctx.plugin_http_call_ns, true)
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
        PluginResult::Continue
    }

    /// A final response body that cannot be inspected (an unsupported or
    /// undecodable content-encoding after transforms): fail closed in enforce
    /// mode, forward in dry-run.
    fn uninspectable_final_response(&self, ctx: &mut RequestContext) -> PluginResult {
        if self.engine.mode == Mode::Enforce {
            return self.reject_uninspectable(
                ctx,
                "response body",
                "response body has a content-encoding that cannot be inspected",
            );
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
            || ctx.method != "POST"
        {
            return false;
        }
        ctx.headers
            .get("content-type")
            .is_some_and(|ct| is_json_content_type(ct))
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
        // Mirror `should_buffer_request_body`: only JSON POST bodies are in scope.
        if ctx.method != "POST"
            || !header_value(headers, "content-type")
                .or_else(|| header_value(&ctx.headers, "content-type"))
                .is_some_and(is_json_content_type)
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

        if header_value(headers, "content-encoding")
            .or_else(|| header_value(&ctx.headers, "content-encoding"))
            .map(str::trim)
            .is_some_and(|enc| !enc.is_empty() && !enc.eq_ignore_ascii_case("identity"))
        {
            uninspectable = Some("request body has a content-encoding that cannot be inspected");
        }

        let body_size: usize = ctx
            .metadata
            .get("request_body_size_bytes")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let body = ctx.metadata.get("request_body");

        if uninspectable.is_none() {
            if body_size == 0 && body.is_none_or(|b| b.is_empty()) {
                // Empty body: nothing to govern.
                return PluginResult::Continue;
            }
            if body_size > MAX_PARSE_BYTES || body.is_some_and(|b| b.len() > MAX_PARSE_BYTES) {
                uninspectable = Some("request body exceeds the inspectable size limit");
            }
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
            if let Some(hash) = ctx.metadata.get("request_body").map(|b| sha256_hex(b)) {
                ctx.metadata
                    .insert(GOVERNED_REQUEST_HASH_KEY.to_string(), hash);
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
        // `govern_request` needs the real request context: consumer/proxy
        // correlation, `plugin_http_call_ns` for approval webhooks, and metadata
        // writes must survive back to the live request.
        self.enabled && self.inspect.any_request()
    }

    /// Re-run the deterministic request policy on the FINAL backend-visible body.
    ///
    /// `before_proxy` governs the body as first buffered, but `request_transformer`
    /// (3000) and other `transform_request_body` hooks run afterward and can add
    /// or rewrite JSON fields — turning an allowed body into a denied `tools/call`
    /// or a disallowed `tools[]` definition before it reaches the backend. This
    /// hook closes that gap. Request decompression also runs in `transform_request_body`,
    /// so a body opaque to `before_proxy` may be plaintext here.
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.enabled || !self.inspect.any_request() {
            return PluginResult::Continue;
        }
        // Only JSON POST bodies are governed (mirror `should_buffer_request_body`).
        if ctx.method != "POST"
            || !header_value(headers, "content-type").is_some_and(is_json_content_type)
        {
            return PluginResult::Continue;
        }

        // Unchanged since `before_proxy` governed it: nothing new to check, and
        // re-governing would risk a duplicate approval webhook.
        let final_hash = sha256_hex_bytes(body);
        if ctx.metadata.get(GOVERNED_REQUEST_HASH_KEY) == Some(&final_hash) {
            return PluginResult::Continue;
        }

        let enforce_request = self.engine.mode == Mode::Enforce;

        // A still-encoded / oversized / unparseable final body cannot be
        // inspected: fail closed in enforce mode so a transform (or a body
        // `before_proxy` could not read) cannot smuggle a denied call past policy.
        if has_non_identity_content_encoding(headers) {
            if enforce_request {
                return self.reject_uninspectable(
                    ctx,
                    "request body",
                    "request body has a content-encoding that cannot be inspected",
                );
            }
            return PluginResult::Continue;
        }
        if body.is_empty() {
            return PluginResult::Continue;
        }
        if body.len() > MAX_PARSE_BYTES {
            if enforce_request {
                return self.reject_uninspectable(
                    ctx,
                    "request body",
                    "request body exceeds the inspectable size limit",
                );
            }
            return PluginResult::Continue;
        }
        let json = match serde_json::from_slice::<Value>(body) {
            Ok(json) => json,
            Err(_) => {
                if enforce_request {
                    return self.reject_uninspectable(
                        ctx,
                        "request body",
                        "request body is not parseable JSON despite a JSON content-type",
                    );
                }
                return PluginResult::Continue;
            }
        };
        ctx.metadata
            .insert(GOVERNED_REQUEST_HASH_KEY.to_string(), final_hash);
        self.govern_request(ctx, &json).await
    }

    // --- Buffered response path -------------------------------------------

    fn requires_response_body_buffering(&self) -> bool {
        self.enabled && self.inspect.any_buffered_response()
    }

    /// Buffer by default — even for requests marked streaming (`Accept:
    /// text/event-stream`, a shared `ai_request_streaming` marker set by an
    /// earlier plugin, or this plugin's own `stream: true` marker). The
    /// pre-header decision cannot see the response content-type, and a backend
    /// may answer a `stream: true` request with plain JSON
    /// `choices[].message.tool_calls[]`; opting out here would skip
    /// `on_response_body` entirely and bypass enforce-mode policy.
    /// `should_buffer_response_body_for_content_type` downgrades ONLY a genuine
    /// event stream back to the streaming path (where the SSE inspector
    /// attaches when `streaming_response_tool_calls` is enabled).
    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        self.enabled && self.inspect.any_buffered_response()
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        if !self.should_buffer_response_body(ctx) || !(200..300).contains(&response_status) {
            return false;
        }
        // Buffer only JSON responses; SSE tool calls go through the stream
        // inspector, never the buffered path.
        match content_type {
            Some(ct) => is_json_content_type(ct) && !is_event_stream_content_type(ct),
            None => false,
        }
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
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
        if !is_json_content_type(content_type) {
            return PluginResult::Continue;
        }
        if body.is_empty() {
            return PluginResult::Continue;
        }
        if body.len() > MAX_PARSE_BYTES {
            // A padded response must not smuggle governed tool calls past the
            // parse limit: fail closed in enforce mode.
            if self.engine.mode == Mode::Enforce {
                return self.reject_uninspectable(
                    ctx,
                    "response body",
                    "response body exceeds the inspectable size limit",
                );
            }
            return PluginResult::Continue;
        }
        let json = match serde_json::from_slice::<Value>(body) {
            Ok(json) => json,
            Err(_) => {
                if has_non_identity_content_encoding(response_headers)
                    && self.engine.mode == Mode::Enforce
                {
                    return self.reject_uninspectable(
                        ctx,
                        "response body",
                        "response body has a content-encoding that cannot be inspected",
                    );
                }
                return PluginResult::Continue;
            }
        };

        // Record the hash of the raw backend body governed here so the
        // post-transform `on_final_response_body` re-check can skip an unchanged
        // client-visible body (recorded even when there are no calls: a later
        // `response_transformer` that injects one changes the hash and forces a
        // fresh evaluation).
        ctx.metadata.insert(
            GOVERNED_RESPONSE_HASH_KEY.to_string(),
            sha256_hex_bytes(body),
        );

        let calls = extract_response_tool_calls(&json);
        if calls.is_empty() {
            return PluginResult::Continue;
        }

        let provider = detect_response_provider(&json).map(|p| p.as_str());
        let model = json
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string);
        let corr = self.correlation(ctx, model, provider);

        let batch = self
            .engine
            .govern_calls(&corr, &calls, &ctx.plugin_http_call_ns, false)
            .await;
        self.write_metadata(ctx, &batch);

        if batch.enforce_blocks {
            debug!(
                target: "ai_tool_governor",
                decision = batch.overall_label,
                "rejecting response: {}",
                batch.deny_reason.as_deref().unwrap_or("blocked")
            );
            return self.reject(&batch);
        }
        PluginResult::Continue
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.enabled
            || !self.needs_response_transform
            || self.engine.mode == Mode::DryRun
            || !self.inspect.any_buffered_response()
        {
            return None;
        }
        match content_type {
            Some(ct) if is_json_content_type(ct) => {}
            _ => return None,
        }
        if body.is_empty() || body.len() > MAX_PARSE_BYTES {
            return None;
        }
        let mut json: Value = serde_json::from_slice(body).ok()?;
        if self.redact_response(&mut json) {
            return serde_json::to_vec(&json).ok();
        }
        None
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
        let content_type = header_value(response_headers, "content-type").unwrap_or("");
        if !is_json_content_type(content_type) {
            return PluginResult::Continue;
        }
        if body.is_empty() {
            return PluginResult::Continue;
        }

        // Unchanged since `on_response_body` governed the raw backend body: no
        // transform rewrote it, so re-governing would only risk a duplicate
        // approval webhook.
        let final_hash = sha256_hex_bytes(body);
        if ctx.metadata.get(GOVERNED_RESPONSE_HASH_KEY) == Some(&final_hash) {
            return PluginResult::Continue;
        }

        // Parse the final body directly; if a later transform encoded it,
        // decompress with the gateway's own content-encoding and parse that.
        let json = if let Some(json) = parse_json_within_limit(body) {
            json
        } else if let Some(decoded) = content_encoding_value(response_headers)
            .and_then(|enc| decompress_within_limit(enc, body))
        {
            match parse_json_within_limit(&decoded) {
                Some(json) => json,
                None => return self.uninspectable_final_response(ctx),
            }
        } else if has_non_identity_content_encoding(response_headers) {
            // Encoded with an unsupported/undecodable content-encoding: cannot
            // verify a later transform did not inject a governed call.
            return self.uninspectable_final_response(ctx);
        } else {
            // Plaintext but unparseable / oversized: `on_response_body` already
            // fail-closed a genuinely uninspectable backend body before delivery.
            return PluginResult::Continue;
        };

        self.govern_final_response(ctx, &json).await
    }

    // --- Streaming response path ------------------------------------------

    fn requires_response_stream_hooks(&self) -> bool {
        self.enabled && self.inspect.streaming_response_tool_calls
    }

    fn forces_reqwest_dispatch(&self, ctx: &RequestContext) -> bool {
        // The stream inspector is only wired on the reqwest streaming path, so
        // any request that may produce an inspected SSE response must dispatch
        // via reqwest: an SSE `Accept` header, a shared streaming marker from
        // an earlier plugin, or this plugin's own request-body detection of
        // `"stream": true` (set in `before_proxy`) — the latter catches a
        // plain POST to a direct H2/H3 backend that answers with SSE.
        self.enabled
            && self.inspect.streaming_response_tool_calls
            && (is_sse_request(ctx)
                || ctx.metadata.get("ai_request_streaming").map(String::as_str) == Some("true")
                || ctx.metadata.get(STREAM_REQUESTED_KEY).map(String::as_str) == Some("true"))
    }

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
        if !content_type.is_some_and(is_event_stream_content_type) {
            return None;
        }
        let model = ctx
            .metadata
            .get(STREAM_MODEL_KEY)
            .or_else(|| ctx.metadata.get("ai_model"))
            .cloned();
        let provider = ctx
            .metadata
            .get("ai_provider")
            .or_else(|| ctx.metadata.get("ai_federation_provider"))
            .map(String::as_str);
        let corr = self.correlation(ctx, model, provider);
        Some(Box::new(ToolCallStreamInspector::new(
            Arc::clone(&self.engine),
            corr,
            Arc::clone(&ctx.plugin_http_call_ns),
        )))
    }
}

// ---------------------------------------------------------------------------
// Streaming inspector
// ---------------------------------------------------------------------------

/// Accumulates OpenAI streaming `choices[].delta.tool_calls` deltas into
/// complete tool calls, keyed by `(choice_index, tool_index)` with a positional
/// fallback when `index` is absent.
#[derive(Default)]
struct StreamingToolCallAccumulator {
    calls: Vec<((usize, usize), StreamingCall)>,
    positions: HashMap<(usize, usize), usize>,
}

#[derive(Default)]
struct StreamingCall {
    name: String,
    arguments: String,
}

impl StreamingToolCallAccumulator {
    fn push_frame(&mut self, frame: &Value) {
        let Some(choices) = frame.get("choices").and_then(Value::as_array) else {
            return;
        };
        for (cpos, choice) in choices.iter().enumerate() {
            let cidx = choice
                .get("index")
                .and_then(Value::as_u64)
                .and_then(|v| usize::try_from(v).ok())
                .unwrap_or(cpos);
            let Some(tool_calls) = choice
                .get("delta")
                .and_then(|d| d.get("tool_calls"))
                .and_then(Value::as_array)
            else {
                continue;
            };
            for (tpos, tc) in tool_calls.iter().enumerate() {
                let tidx = tc
                    .get("index")
                    .and_then(Value::as_u64)
                    .and_then(|v| usize::try_from(v).ok())
                    .unwrap_or(tpos);
                let function = tc.get("function");
                let entry = self.entry(cidx, tidx);
                if let Some(name) = function.and_then(|f| f.get("name")).and_then(Value::as_str) {
                    entry.name.push_str(name);
                }
                if let Some(args) = function
                    .and_then(|f| f.get("arguments"))
                    .and_then(Value::as_str)
                {
                    entry.arguments.push_str(args);
                }
            }
        }
    }

    fn entry(&mut self, choice: usize, tool: usize) -> &mut StreamingCall {
        let key = (choice, tool);
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

    fn build_calls(&self) -> Vec<ToolCall> {
        self.calls
            .iter()
            .filter(|(_, c)| !c.name.is_empty())
            .map(|(_, c)| ToolCall {
                name: c.name.clone(),
                parsed_args: serde_json::from_str(&c.arguments).ok(),
                raw_args: c.arguments.clone(),
            })
            .collect()
    }
}

/// Result of finalizing accumulated tool calls at a completion boundary.
enum Finalize {
    /// Held tool-call bytes were appended to the output; keep streaming.
    Released,
    /// Policy blocked: held bytes dropped; the caller must terminate the stream.
    Blocked,
}

/// Per-response streaming inspector. Holds tool-call SSE frames until the call
/// is complete and cleared by policy/approval, then releases them — or cuts the
/// stream with an SSE error event, never leaking the held frames.
struct ToolCallStreamInspector {
    engine: Arc<GovernorEngine>,
    corr: CorrelationMeta,
    plugin_http_call_ns: Arc<AtomicU64>,
    /// Raw bytes received but not yet a complete SSE event.
    carry: Vec<u8>,
    /// Raw bytes of held (un-released) tool-call events, in order.
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
}

impl ToolCallStreamInspector {
    fn new(
        engine: Arc<GovernorEngine>,
        corr: CorrelationMeta,
        plugin_http_call_ns: Arc<AtomicU64>,
    ) -> Self {
        Self {
            engine,
            corr,
            plugin_http_call_ns,
            carry: Vec::new(),
            held: Vec::new(),
            accumulator: StreamingToolCallAccumulator::default(),
            saw_tool_calls: false,
            finished_choices: std::collections::HashSet::new(),
            bypassed: false,
            terminated: false,
        }
    }

    /// Record which choices this frame finishes. Only choices that actually
    /// hold tool-call deltas are tracked — a hostile stream of synthetic
    /// finish frames for unrelated choice indices cannot grow the set.
    fn record_finished_choices(&mut self, frame: &Value) {
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
            if self.accumulator.has_choice(cidx) {
                self.finished_choices.insert(cidx);
            }
        }
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

    /// Evaluate the accumulated tool calls at a completion boundary. On
    /// release, appends the held raw bytes to `out` and resets batch state.
    async fn finalize(&mut self, out: &mut Vec<u8>) -> Finalize {
        if !self.saw_tool_calls {
            return Finalize::Released;
        }
        let calls = self.accumulator.build_calls();
        if calls.is_empty() {
            // Held frames whose deltas never produced a tool name cannot be
            // policy-checked: drop them (never release ungovernable bytes).
            self.held.clear();
            self.reset_batch();
            return Finalize::Released;
        }
        let batch = self
            .engine
            .govern_calls(&self.corr, &calls, &self.plugin_http_call_ns, true)
            .await;

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
        let mut out: Vec<u8> = Vec::new();

        while let Some(end) = next_event_end(&self.carry) {
            let event: Vec<u8> = self.carry.drain(..end).collect();
            match classify_event(&event) {
                SseEvent::Frame(frame) => {
                    self.record_frame_context(&frame);
                    let has_tool_calls = frame_has_tool_calls(&frame);
                    if has_tool_calls {
                        self.saw_tool_calls = true;
                        self.accumulator.push_frame(&frame);
                        self.held.extend_from_slice(&event);
                    }
                    self.record_finished_choices(&frame);
                    // Evaluate once every choice holding tool calls has
                    // finished, then release the held frames before forwarding
                    // this event. Later tool-call deltas start a new batch
                    // governed at its own completion boundary.
                    if self.batch_complete()
                        && let Finalize::Blocked = self.finalize(&mut out).await
                    {
                        return self.terminate(out);
                    }
                    if !has_tool_calls {
                        out.extend_from_slice(&event);
                    }
                }
                SseEvent::Done => {
                    if let Finalize::Blocked = self.finalize(&mut out).await {
                        return self.terminate(out);
                    }
                    out.extend_from_slice(&event);
                }
                SseEvent::OtherData | SseEvent::NoData => {
                    // Comments, keepalives, non-JSON data: no tool calls, forward live.
                    out.extend_from_slice(&event);
                }
            }
        }

        // Cap retained bytes (held tool-call frames + partial-event carry): an
        // upstream streaming never-finishing tool-call deltas (or an
        // event-terminator-free byte stream) must not grow gateway memory
        // unboundedly. Enforce mode fails closed; dry-run releases everything
        // uninspected rather than disrupting traffic.
        if self.held.len() + self.carry.len() > MAX_STREAM_HOLD_BYTES {
            warn!(
                target: "ai_tool_governor",
                held_bytes = self.held.len(),
                carry_bytes = self.carry.len(),
                mode = self.engine.mode.as_str(),
                "streaming tool-call hold exceeded cap"
            );
            if self.engine.mode == Mode::Enforce {
                self.held.clear();
                return self.terminate(out);
            }
            out.append(&mut self.held);
            out.append(&mut self.carry);
            self.reset_batch();
            self.bypassed = true;
        }

        ResponseStreamAction::Forward(Bytes::from(out))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.terminated || self.bypassed {
            return ResponseStreamAction::Forward(Bytes::new());
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

/// Byte index just past the end of the first complete SSE event (first blank
/// line), or `None` if no event has fully arrived yet.
fn next_event_end(buf: &[u8]) -> Option<usize> {
    for (i, &b) in buf.iter().enumerate() {
        if b != b'\n' {
            continue;
        }
        match buf.get(i + 1) {
            Some(b'\n') => return Some(i + 2),
            Some(b'\r') if buf.get(i + 2) == Some(&b'\n') => return Some(i + 3),
            _ => {}
        }
    }
    None
}

enum SseEvent {
    Frame(Value),
    Done,
    OtherData,
    NoData,
}

/// Classify a raw SSE event by its concatenated `data:` payload.
fn classify_event(event: &[u8]) -> SseEvent {
    let Ok(text) = std::str::from_utf8(event) else {
        return SseEvent::NoData;
    };
    let mut data_lines: Vec<&str> = Vec::new();
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
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
    match serde_json::from_str::<Value>(trimmed) {
        Ok(value) => SseEvent::Frame(value),
        Err(_) => SseEvent::OtherData,
    }
}

fn frame_has_tool_calls(frame: &Value) -> bool {
    frame
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| {
            choices.iter().any(|choice| {
                choice
                    .get("delta")
                    .and_then(|d| d.get("tool_calls"))
                    .and_then(Value::as_array)
                    .is_some_and(|tcs| !tcs.is_empty())
            })
        })
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

fn tool_call_from(name: &str, args: Option<&Value>) -> ToolCall {
    let (raw_args, parsed_args) = match args {
        Some(Value::String(s)) => (s.clone(), serde_json::from_str::<Value>(s).ok()),
        Some(value) => (value.to_string(), Some(value.clone())),
        None => (String::new(), None),
    };
    ToolCall {
        name: name.to_string(),
        raw_args,
        parsed_args,
    }
}

/// Extract `choices[].message.tool_calls[]` and legacy
/// `choices[].message.function_call` from a buffered response.
fn extract_response_tool_calls(json: &Value) -> Vec<ToolCall> {
    let mut out = Vec::new();
    let Some(choices) = json.get("choices").and_then(Value::as_array) else {
        return out;
    };
    for choice in choices {
        let Some(message) = choice.get("message") else {
            continue;
        };
        if let Some(tool_calls) = message.get("tool_calls").and_then(Value::as_array) {
            for tc in tool_calls {
                if let Some(function) = tc.get("function")
                    && let Some(name) = function.get("name").and_then(Value::as_str)
                {
                    out.push(tool_call_from(name, function.get("arguments")));
                }
            }
        }
        if let Some(function_call) = message.get("function_call")
            && let Some(name) = function_call.get("name").and_then(Value::as_str)
        {
            out.push(tool_call_from(name, function_call.get("arguments")));
        }
    }
    out
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

/// Extract a single tool call from an MCP JSON-RPC `tools/call` request.
fn extract_mcp_tool_call(json: &Value) -> Option<ToolCall> {
    if json.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let params = json.get("params")?;
    let name = params.get("name").and_then(Value::as_str)?;
    Some(tool_call_from(name, params.get("arguments")))
}

/// Extract an A2A JSON-RPC method as a name-governed "tool" (params as args).
/// MCP `tools/call` is handled separately, so it is skipped here.
fn extract_a2a_method(json: &Value) -> Option<ToolCall> {
    let method = json.get("method").and_then(Value::as_str)?;
    if method == "tools/call" {
        return None;
    }
    Some(tool_call_from(method, json.get("params")))
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

/// The non-identity `Content-Encoding` header value, trimmed, or `None` when
/// absent/empty/`identity`.
fn content_encoding_value(headers: &HashMap<String, String>) -> Option<&str> {
    header_value(headers, "content-encoding")
        .map(str::trim)
        .filter(|enc| !enc.is_empty() && !enc.eq_ignore_ascii_case("identity"))
}

/// Parse `body` as JSON only when it is within the inspectable size limit.
fn parse_json_within_limit(body: &[u8]) -> Option<Value> {
    if body.is_empty() || body.len() > MAX_PARSE_BYTES {
        return None;
    }
    serde_json::from_slice(body).ok()
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

/// Replace each blocked-pattern match in a raw arguments string with the
/// rendered redaction placeholder. `NoExpand` keeps `$`-sequences literal.
fn redact_arguments(
    args: &str,
    patterns: &[BlockedArgPattern],
    placeholder: &str,
) -> (String, bool) {
    let mut result = args.to_string();
    for pattern in patterns {
        let rendered = placeholder.replace("{name}", &pattern.name);
        result = pattern
            .regex
            .replace_all(&result, regex::NoExpand(rendered.as_str()))
            .into_owned();
    }
    let changed = result != args;
    (result, changed)
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

fn parse_inspect(config: &Value) -> Result<InspectConfig, String> {
    let inspect = config.get("inspect");
    if let Some(inspect) = inspect
        && !inspect.is_object()
    {
        return Err("ai_tool_governor: 'inspect' must be an object".to_string());
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
        for (idx, entry) in arr.iter().enumerate() {
            let entry_obj = entry.as_object().ok_or_else(|| {
                format!(
                    "ai_tool_governor: tool '{name}' 'blocked_arg_patterns[{idx}]' must be an object"
                )
            })?;
            let pattern_name = entry_obj
                .get("name")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    format!(
                        "ai_tool_governor: tool '{name}' 'blocked_arg_patterns[{idx}].name' is required"
                    )
                })?;
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
            blocked_arg_patterns.push(BlockedArgPattern {
                name: pattern_name.to_string(),
                regex,
            });
        }
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
        Some(v) => v.as_u64().filter(|n| *n > 0).ok_or_else(|| {
            "ai_tool_governor: 'approval.timeout_ms' must be a positive integer".to_string()
        })?,
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

    let include_prompt_excerpt = match obj.get("include_prompt_excerpt") {
        None => false,
        Some(v) => v.as_bool().ok_or_else(|| {
            "ai_tool_governor: 'approval.include_prompt_excerpt' must be a boolean".to_string()
        })?,
    };

    Ok(Some(ApprovalConfig {
        endpoint_url: endpoint_url.to_string(),
        redacted_endpoint_url: redacted_approval_url(&parsed),
        hostname,
        timeout: Duration::from_millis(timeout_ms),
        cache_ttl: Duration::from_secs(cache_ttl_seconds),
        fail_on_error,
        include_prompt_excerpt,
    }))
}

fn parse_response(config: &Value) -> Result<ResponseConfig, String> {
    let response = config.get("response");
    if let Some(response) = response
        && !response.is_object()
    {
        return Err("ai_tool_governor: 'response' must be an object".to_string());
    }

    let deny_status_code = match response.and_then(|r| r.get("deny_status_code")) {
        None => DEFAULT_DENY_STATUS,
        Some(v) => {
            let n = v.as_u64().ok_or_else(|| {
                "ai_tool_governor: 'response.deny_status_code' must be an integer".to_string()
            })?;
            if !(100..=599).contains(&n) {
                return Err(
                    "ai_tool_governor: 'response.deny_status_code' must be a valid HTTP status (100-599)"
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
