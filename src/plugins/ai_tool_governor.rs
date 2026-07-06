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
//! `fail_on_error` says `warn`/`allow`.
//!
//! Non-goals (MVP): it does not execute tools, manage MCP sessions, replace
//! `mcp_gateway`/A2A routing, or implement an approval UI.

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use regex::Regex;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use sha2::{Digest, Sha256};

use super::utils::ai_providers::detect_response_provider;
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
/// Upper bound on the body size this plugin will parse for tool calls, so an
/// oversized (already-buffered) body cannot spend unbounded CPU in serde. Bodies
/// past this are forwarded uninspected (buffered path) — the request/response
/// size-limiting plugins are the real backstop.
const MAX_PARSE_BYTES: usize = 4 * 1024 * 1024;

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
    /// (`consumer|proxy|model|tool|raw_args`), value is `(allowed, expiry)`.
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

    /// Whether exposing a tool *definition* (name only, no arguments) is denied.
    fn definition_denied(&self, name: &str) -> bool {
        match self.tools.get(name) {
            Some(policy) => policy.action == ToolAction::Deny,
            None => self.default_action == DefaultAction::Deny,
        }
    }

    /// Govern a batch of concrete tool calls. `streaming` treats a matched
    /// `redact_args` pattern as a block (fail closed): surgical redaction of
    /// split-JSON tool arguments mid-stream is out of MVP scope, so the safe
    /// behavior is to cut the stream rather than forward an unredacted secret.
    async fn govern_calls(
        &self,
        corr: &CorrelationMeta,
        calls: &[ToolCall],
        ns: &AtomicU64,
        streaming: bool,
    ) -> BatchDecision {
        let mut per_call = Vec::with_capacity(calls.len());

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
                    if streaming && !patterns.is_empty() {
                        cd.label = "deny";
                        cd.blocks = true;
                        cd.reason = Some(format!(
                            "tool '{}' redact_args is not supported for streaming tool calls (failing closed)",
                            call.name
                        ));
                    } else {
                        cd.label = "allow";
                        cd.redact_patterns = patterns;
                    }
                }
                PolicyOutcome::RequireApproval => {
                    self.resolve_require_approval(corr, call, &arguments_hash, risk, ns, &mut cd)
                        .await;
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
        let cache_key = sha256_hex(&format!(
            "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}",
            input.corr.consumer.as_deref().unwrap_or(""),
            input.corr.proxy.as_deref().unwrap_or(""),
            input.corr.model.as_deref().unwrap_or(""),
            input.name,
            input.raw_args,
        ));

        if let Some(entry) = self.approval_cache.get(&cache_key) {
            let (allowed, expiry) = *entry.value();
            if expiry > Instant::now() {
                // Cached decision — no fresh approval id.
                return Ok((allowed, None));
            }
        }

        let (allowed, approval_id) = self.call_approval(approval, input).await?;

        if approval.cache_ttl > Duration::ZERO {
            self.approval_cache
                .insert(cache_key, (allowed, Instant::now() + approval.cache_ttl));
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
            .execute_tracked(request, "ai_tool_governor_approval", input.ns)
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
        let approval = parse_approval(config)?;
        if any_require_approval && approval.is_none() {
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

    /// Governs a decoded request body's MCP/A2A tool calls and tool definitions.
    async fn govern_request(&self, ctx: &mut RequestContext, json: &Value) -> PluginResult {
        let corr = self.correlation(ctx, request_model(json), None);

        // 1. Client tool definitions exposed to the model.
        if self.inspect.request_tool_definitions {
            let denied: Vec<String> = extract_request_tool_definitions(json)
                .into_iter()
                .filter(|name| self.engine.definition_denied(name))
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
                .govern_calls(&corr, &[call], &ctx.plugin_http_call_ns, false)
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
                .govern_calls(&corr, &[call], &ctx.plugin_http_call_ns, false)
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
        let Some(args) = function.get("arguments").and_then(Value::as_str) else {
            return false;
        };
        let (redacted, changed) = redact_arguments(
            args,
            &policy.blocked_arg_patterns,
            &self.redaction_placeholder,
        );
        if changed {
            function["arguments"] = Value::String(redacted);
        }
        changed
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
        self.enabled && self.inspect.any_request()
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if !self.enabled || !self.inspect.any_request() || ctx.method != "POST" {
            return false;
        }
        ctx.headers
            .get("content-type")
            .is_some_and(|ct| is_json_content_type(ct))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.enabled || !self.inspect.any_request() {
            return PluginResult::Continue;
        }
        let Some(body) = ctx.metadata.get("request_body") else {
            return PluginResult::Continue;
        };
        if body.is_empty() || body.len() > MAX_PARSE_BYTES {
            return PluginResult::Continue;
        }
        let Ok(json) = serde_json::from_str::<Value>(body) else {
            return PluginResult::Continue;
        };
        self.govern_request(ctx, &json).await
    }

    // --- Buffered response path -------------------------------------------

    fn requires_response_body_buffering(&self) -> bool {
        self.enabled && self.inspect.response_tool_calls
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.enabled
            && self.inspect.response_tool_calls
            && !is_sse_request(ctx)
            && ctx.metadata.get("ai_request_streaming").map(String::as_str) != Some("true")
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
        if !self.enabled || !self.inspect.response_tool_calls {
            return PluginResult::Continue;
        }
        if !(200..300).contains(&response_status) {
            return PluginResult::Continue;
        }
        let content_type = response_headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");
        if !is_json_content_type(content_type) {
            return PluginResult::Continue;
        }
        if body.is_empty() || body.len() > MAX_PARSE_BYTES {
            return PluginResult::Continue;
        }
        let Ok(json) = serde_json::from_slice::<Value>(body) else {
            return PluginResult::Continue;
        };

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
        if !self.enabled || !self.needs_response_transform {
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

    // --- Streaming response path ------------------------------------------

    fn requires_response_stream_hooks(&self) -> bool {
        self.enabled && self.inspect.streaming_response_tool_calls
    }

    fn forces_reqwest_dispatch(&self, ctx: &RequestContext) -> bool {
        self.enabled
            && self.inspect.streaming_response_tool_calls
            && (is_sse_request(ctx)
                || ctx.metadata.get("ai_request_streaming").map(String::as_str) == Some("true"))
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
        let corr = self.correlation(ctx, None, None);
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

    fn is_empty(&self) -> bool {
        self.calls.iter().all(|(_, c)| c.name.is_empty())
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
    decided: bool,
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
            decided: false,
            terminated: false,
        }
    }

    /// Evaluate accumulated tool calls at a completion boundary. On release,
    /// appends the held raw bytes to `out`. Idempotent once decided.
    async fn finalize(&mut self, out: &mut Vec<u8>) -> Finalize {
        if self.decided || !self.saw_tool_calls || self.accumulator.is_empty() {
            self.decided = true;
            return Finalize::Released;
        }
        self.decided = true;
        let calls = self.accumulator.build_calls();
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
        self.carry.extend_from_slice(chunk);
        let mut out: Vec<u8> = Vec::new();

        while let Some(end) = next_event_end(&self.carry) {
            let event: Vec<u8> = self.carry.drain(..end).collect();
            match classify_event(&event) {
                SseEvent::Frame(frame) => {
                    let has_tool_calls = frame_has_tool_calls(&frame);
                    if has_tool_calls {
                        self.saw_tool_calls = true;
                        self.accumulator.push_frame(&frame);
                        self.held.extend_from_slice(&event);
                    }
                    // A `finish_reason` (or a combined tool-call+finish frame)
                    // signals the calls are complete: evaluate, then release the
                    // held frames before forwarding this event.
                    if frame_has_finish(&frame)
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

        ResponseStreamAction::Forward(Bytes::from(out))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.terminated {
            return ResponseStreamAction::Forward(Bytes::new());
        }
        let mut out: Vec<u8> = Vec::new();
        let mut trailing: Vec<u8> = Vec::new();

        // Flush a trailing partial/complete event, if any.
        if !self.carry.is_empty() {
            let event = std::mem::take(&mut self.carry);
            match classify_event(&event) {
                SseEvent::Frame(frame) if frame_has_tool_calls(&frame) => {
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

fn frame_has_finish(frame: &Value) -> bool {
    frame
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| {
            choices
                .iter()
                .any(|choice| choice.get("finish_reason").is_some_and(|r| !r.is_null()))
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
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
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

fn parse_approval(config: &Value) -> Result<Option<ApprovalConfig>, String> {
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
