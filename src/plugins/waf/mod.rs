//! Web Application Firewall (WAF) plugin.
//!
//! Content-pattern threat detection for HTTP-family traffic. The plugin is
//! intentionally scoped to payload and metadata inspection; authentication,
//! authorization, rate limiting, protocol smuggling defense, and structural
//! schema validation remain in their dedicated plugins/core layers.
//!
//! Query scanning uses the raw query string even after the proxy pipeline has
//! materialized the parsed query map, so duplicate raw pairs remain visible for
//! HPP checks instead of being collapsed by `HashMap` parsing. Synthetic
//! contexts without a raw query string fall back to the decoded
//! `RequestContext::query_params` map for key/value scans and best-effort
//! full-URL checks.

mod decode;
mod defaults;
mod exemptions;
mod normalize;
mod rules;
mod scan;
mod stream;

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::warn;

use self::defaults::default_rules;
use self::exemptions::CompiledExemptions;
use self::rules::{
    CompiledRules, RuleAction, RuleHit, Severity, WafRule, compile_rules, parse_custom_rule,
    parse_rule_action, parse_rule_overrides,
};
use self::scan::ScanOutcome;
use self::stream::{
    StreamWafConfig, TLS_CLIENT_HELLO_MIN_PREFIX, looks_like_tls_client_hello, parse_stream_config,
};
use super::utils::sse::{is_text_event_stream_media_type, original_response_is_event_stream};
use super::{
    ALL_PROTOCOLS, HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext,
    ResponseTrailerPolicy, StreamBytesKind, StreamConnectionContext, UdpDatagramContext,
    UdpDatagramDirection, UdpDatagramVerdict,
};
use crate::config::types::BackendScheme;
use crate::util::unknown_keys::reject_unknown_keys;

/// Exhaustive top-level WAF config keys. Unknown properties are rejected before
/// defaults apply so typos cannot silently weaken enforcement (for example
/// `default_rule_actoin` leaving built-ins monitor-only).
const WAF_CONFIG_KEYS: &[&str] = &[
    "mode",
    "default_rule_action",
    "paranoia_level",
    "request_inspection",
    "request_body_inspection",
    "response_inspection",
    "response_body_inspection",
    "log_to_metadata",
    "log_to_stdout",
    "scan_budget_ms",
    "max_scan_bytes",
    "on_scan_timeout",
    "on_body_too_large",
    "include_default_rules",
    "disabled_default_rules",
    "rule_modes",
    "rule_overrides",
    "custom_rules",
    "scoring",
    "global_exemptions",
    "body_methods",
    "body_content_types",
    "inspect_multipart",
    "inspect_binary_body",
    "disallowed_methods",
    "reject_status_code",
    "reject_content_type",
    "reject_body",
    "stream",
];

const SCORING_CONFIG_KEYS: &[&str] = &["enabled", "block_threshold", "weights"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GlobalMode {
    Enforce,
    Monitor,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeoutAction {
    Allow,
    Block,
    LogAndAllow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TooLargeAction {
    ScanTruncated,
    Skip,
    Block,
}

#[derive(Debug)]
struct WafConfig {
    mode: GlobalMode,
    paranoia_level: u8,
    request_inspection: bool,
    request_body_inspection: bool,
    response_inspection: bool,
    response_body_inspection: bool,
    log_to_metadata: bool,
    log_to_stdout: bool,
    scan_budget_ms: u64,
    max_scan_bytes: usize,
    on_scan_timeout: TimeoutAction,
    on_body_too_large: TooLargeAction,
    body_methods: Vec<String>,
    body_content_types: Vec<String>,
    inspect_multipart: bool,
    inspect_binary_body: bool,
    disallowed_methods: Vec<String>,
    reject_status_code: u16,
    reject_content_type: String,
    reject_body: String,
    scoring: Option<ScoringConfig>,
}

/// Anomaly-scoring configuration. Present only when scoring is enabled.
#[derive(Debug)]
struct ScoringConfig {
    block_threshold: u32,
    /// Per-severity weight, indexed by `Severity as usize`
    /// (info, low, medium, high, critical).
    weights: [u32; 5],
}

impl ScoringConfig {
    fn weight(&self, severity: Severity) -> u32 {
        self.weights[severity as usize]
    }
}

#[derive(Debug)]
struct SpecialRuleIndices {
    encoding: Option<usize>,
    overlong_utf8: Option<usize>,
    hpp: Option<usize>,
    method: Option<usize>,
    method_override: Option<usize>,
}

#[derive(Debug)]
pub struct Waf {
    config: WafConfig,
    compiled: CompiledRules,
    exemptions: CompiledExemptions,
    specials: SpecialRuleIndices,
    active: bool,
    /// Optional raw-stream (TCP/UDP) inspection. `None` keeps the plugin
    /// HTTP-only and untouched.
    stream: Option<StreamWafConfig>,
    /// Protocols this instance attaches to. Includes the stream protocols only
    /// when `stream` inspection is configured, so HTTP-only WAFs are unchanged.
    supported_protocols: &'static [ProxyProtocol],
    /// Process-unique runtime id used as the private request-score map key.
    instance_id: u64,
    /// Stable validated plugin-config identity for transaction-log ownership.
    identity: Arc<str>,
    /// Precomputed `waf.instances.<identity>.score` metadata key (cold path).
    score_metadata_key: Arc<str>,
}

static NEXT_WAF_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

impl Waf {
    fn body_encoding_specials_active(&self) -> bool {
        self.specials.encoding.is_some() || self.specials.overlong_utf8.is_some()
    }

    fn has_enforcing_response_header_policy(&self) -> bool {
        if self.config.mode != GlobalMode::Enforce || !self.compiled.response_header_rules_active {
            return false;
        }
        if self.config.scoring.is_some() {
            return true;
        }
        self.compiled.rules.iter().any(|rule| {
            rule.action == RuleAction::Enforce
                && matches!(&rule.target, self::rules::RuleTarget::ResponseHeaders)
        })
    }

    fn has_enforcing_response_body_policy(&self) -> bool {
        if self.config.mode != GlobalMode::Enforce {
            return false;
        }
        if self.config.scoring.is_some() {
            return true;
        }
        let encoding = self.specials.encoding;
        let overlong_utf8 = self.specials.overlong_utf8;
        self.compiled.rules.iter().enumerate().any(|(index, rule)| {
            rule.action == RuleAction::Enforce
                && (matches!(rule.target, self::rules::RuleTarget::ResponseBody)
                    || encoding == Some(index)
                    || overlong_utf8 == Some(index))
        })
    }

    fn handle_unbounded_response_stream(&self, ctx: &mut RequestContext) -> PluginResult {
        if self.config.log_to_metadata {
            ctx.set_waf_metadata("waf.response_stream_uninspectable", "true");
        }
        let should_block = match self.config.on_body_too_large {
            TooLargeAction::Skip => false,
            TooLargeAction::Block => self.config.mode == GlobalMode::Enforce,
            TooLargeAction::ScanTruncated => self.has_enforcing_response_body_policy(),
        };
        if should_block {
            if self.config.log_to_metadata {
                ctx.set_waf_metadata("waf.action", "blocked");
                ctx.set_waf_metadata_if_absent("waf.block_reason", "unbounded_response_stream");
            }
            return self.reject();
        }
        if self.config.log_to_metadata {
            ctx.set_waf_metadata("waf.action", "stream_uninspected");
        }
        PluginResult::Continue
    }

    // Kept for direct construction by the external integration-test suites;
    // the production plugin cache always supplies the stable config id below.
    #[allow(dead_code)]
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::new_with_config_id(config, None)
    }

    /// Construct a WAF instance with an optional stable plugin-config resource id.
    ///
    /// Production `PluginCache` passes `Some(&pc.id)` so request-private anomaly
    /// scores and transaction metadata are owned by that configured instance.
    /// Direct/test construction may pass `None` and receives a process-unique
    /// `standalone-<n>` identity so sibling `Waf::new` calls never share an
    /// accumulator.
    pub fn new_with_config_id(config: &Value, config_id: Option<&str>) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "waf: config must be an object".to_string())?;

        // Reject unknown keys before any defaults so a typo cannot admit a
        // weaker policy while construction reports success.
        reject_unknown_keys(object, "config", WAF_CONFIG_KEYS, "waf: ")?;

        let mode = parse_global_mode(
            optional_string(object, "mode")?
                .as_deref()
                .unwrap_or("enforce"),
        )?;
        let paranoia_level = optional_u8(object, "paranoia_level")?.unwrap_or(1);
        if !(1..=4).contains(&paranoia_level) {
            return Err("waf: 'paranoia_level' must be from 1 to 4".to_string());
        }

        let request_inspection = optional_bool(object, "request_inspection")?.unwrap_or(true);
        let request_body_inspection =
            optional_bool(object, "request_body_inspection")?.unwrap_or(true);
        let response_inspection = optional_bool(object, "response_inspection")?.unwrap_or(false);
        let response_body_inspection =
            optional_bool(object, "response_body_inspection")?.unwrap_or(false);
        let log_to_metadata = optional_bool(object, "log_to_metadata")?.unwrap_or(true);
        let log_to_stdout = optional_bool(object, "log_to_stdout")?.unwrap_or(false);
        let scan_budget_ms = optional_u64(object, "scan_budget_ms")?.unwrap_or(50);
        let max_scan_bytes = optional_usize(object, "max_scan_bytes")?.unwrap_or(1_048_576);
        if max_scan_bytes == 0 {
            return Err("waf: 'max_scan_bytes' must be greater than zero".to_string());
        }
        let on_scan_timeout = parse_timeout_action(
            optional_string(object, "on_scan_timeout")?
                .as_deref()
                .unwrap_or("log_and_allow"),
        )?;
        let on_body_too_large = parse_too_large_action(
            optional_string(object, "on_body_too_large")?
                .as_deref()
                .unwrap_or("scan_truncated"),
        )?;
        let include_default_rules = optional_bool(object, "include_default_rules")?.unwrap_or(true);
        let disabled_default_rules = optional_string_vec(object, "disabled_default_rules")?
            .unwrap_or_default()
            .into_iter()
            .collect::<HashSet<_>>();
        let rule_modes = parse_rule_modes(object.get("rule_modes"))?;
        // Bulk action for built-in rules. Unset preserves the safe monitor-only
        // default; `rule_modes` still overrides individual rules either way.
        let default_rule_action = optional_string(object, "default_rule_action")?
            .map(|raw| parse_rule_action(&raw, "default_rule_action"))
            .transpose()?;
        let rule_overrides = parse_rule_overrides(object.get("rule_overrides"))?;
        let default_action = match mode {
            GlobalMode::Enforce => RuleAction::Enforce,
            GlobalMode::Monitor | GlobalMode::Disabled => RuleAction::Monitor,
        };
        let custom_rules = parse_custom_rules(object.get("custom_rules"), default_action)?;
        let exemptions = CompiledExemptions::from_config(object.get("global_exemptions"))?;

        // Parse optional raw-stream (TCP/UDP) inspection up front so a
        // stream-only WAF (no HTTP rule pack) is still a valid configuration.
        let stream = parse_stream_config(object)?;

        let mut all_rules: Vec<(WafRule, bool)> = Vec::new();
        if include_default_rules {
            all_rules.extend(default_rules().into_iter().map(|rule| (rule, true)));
        }
        all_rules.extend(custom_rules.into_iter().map(|rule| (rule, false)));
        if all_rules.is_empty() && stream.is_none() {
            return Err(
                "waf: no rules configured — enable default rules, provide custom_rules, or configure stream inspection"
                    .to_string(),
            );
        }
        let compiled = compile_rules(
            all_rules,
            &disabled_default_rules,
            &rule_modes,
            default_rule_action,
            &rule_overrides,
            paranoia_level,
        )?;
        if compiled.is_empty() && stream.is_none() && mode != GlobalMode::Disabled {
            return Err(
                "waf: all configured rules are disabled or above paranoia_level".to_string(),
            );
        }

        let config = WafConfig {
            mode,
            paranoia_level,
            request_inspection,
            request_body_inspection,
            response_inspection,
            response_body_inspection,
            log_to_metadata,
            log_to_stdout,
            scan_budget_ms,
            max_scan_bytes,
            on_scan_timeout,
            on_body_too_large,
            body_methods: optional_string_vec(object, "body_methods")?
                .unwrap_or_else(default_body_methods)
                .into_iter()
                .map(|method| method.to_ascii_uppercase())
                .collect(),
            body_content_types: optional_string_vec(object, "body_content_types")?
                .unwrap_or_else(default_body_content_types)
                .into_iter()
                .map(|content_type| content_type.to_ascii_lowercase())
                .collect(),
            inspect_multipart: optional_bool(object, "inspect_multipart")?.unwrap_or(false),
            inspect_binary_body: optional_bool(object, "inspect_binary_body")?.unwrap_or(false),
            disallowed_methods: optional_string_vec(object, "disallowed_methods")?
                .unwrap_or_default()
                .into_iter()
                .map(|method| method.to_ascii_uppercase())
                .collect(),
            reject_status_code: optional_u16(object, "reject_status_code")?.unwrap_or(403),
            reject_content_type: optional_string(object, "reject_content_type")?
                .unwrap_or_else(|| "application/json".to_string()),
            reject_body: optional_string(object, "reject_body")?
                .unwrap_or_else(|| r#"{"error":"Forbidden"}"#.to_string()),
            scoring: parse_scoring(object.get("scoring"))?,
        };
        if !(400..=599).contains(&config.reject_status_code) {
            return Err("waf: 'reject_status_code' must be from 400 to 599".to_string());
        }

        let specials = SpecialRuleIndices {
            encoding: compiled.find_rule_index("FE-ENCODING-001"),
            overlong_utf8: compiled.find_rule_index("FE-ENCODING-002"),
            hpp: compiled.find_rule_index("FE-HPP-001"),
            method: compiled.find_rule_index("FE-METHOD-001"),
            method_override: compiled.find_rule_index("FE-HEADER-002"),
        };
        // A stream-only WAF (no HTTP rule pack, but stream signatures or the
        // TLS-shape guard) is still active for its stream proxies.
        let active =
            config.mode != GlobalMode::Disabled && (!compiled.is_empty() || stream.is_some());
        let supported_protocols = if active && stream.is_some() {
            ALL_PROTOCOLS
        } else {
            HTTP_FAMILY_PROTOCOLS
        };
        let instance_id = NEXT_WAF_INSTANCE_ID.fetch_add(1, Ordering::Relaxed);
        let identity: Arc<str> = match config_id {
            Some(id) => {
                crate::config::types::validate_resource_id(id)
                    .map_err(|error| format!("waf: invalid plugin config id: {error}"))?;
                Arc::from(id)
            }
            None => Arc::from(format!("standalone-{instance_id}")),
        };
        let score_metadata_key: Arc<str> = Arc::from(format!("waf.instances.{identity}.score"));
        Ok(Self {
            config,
            compiled,
            exemptions,
            specials,
            active,
            stream,
            supported_protocols,
            instance_id,
            identity,
            score_metadata_key,
        })
    }

    fn request_is_exempt(&self, ctx: &RequestContext) -> bool {
        self.exemptions.request_short_circuits(ctx)
    }

    fn should_inspect_body_content_type(&self, content_type: Option<&str>) -> bool {
        let Some(content_type) = content_type else {
            return self.config.inspect_binary_body;
        };
        let base = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if base.starts_with("multipart/") {
            return self.config.inspect_multipart;
        }
        if self
            .config
            .body_content_types
            .iter()
            .any(|allowed| allowed == &base)
        {
            return true;
        }
        self.config.inspect_binary_body
    }

    fn request_body_eligible_for_scan(&self, content_type: Option<&str>) -> bool {
        self.should_inspect_body_content_type(content_type)
    }

    async fn run_body_scan_with_budget<F>(&self, scan: F) -> ScanOutcome
    where
        F: FnOnce() -> ScanOutcome,
    {
        if self.config.scan_budget_ms == 0 {
            return scan();
        }
        let budget = Duration::from_millis(self.config.scan_budget_ms);
        let start = std::time::Instant::now();
        // Yield to the scheduler before the scan so a timer that has already
        // elapsed (e.g. due to scheduling congestion) can fire immediately.
        // The scan itself is synchronous — Rust's regex crate guarantees O(n)
        // matching, so execution time is bounded by
        // O(active_rules × max_scan_bytes) without pathological backtracking.
        tokio::task::yield_now().await;
        if start.elapsed() >= budget {
            return ScanOutcome {
                timed_out: true,
                ..ScanOutcome::default()
            };
        }
        let outcome = scan();
        if start.elapsed() >= budget {
            return ScanOutcome {
                timed_out: true,
                ..outcome
            };
        }
        outcome
    }

    /// Run a synchronous (header/query/path/response-header) scan under the
    /// scan budget. The `RegexSet` pass cannot be interrupted, so the budget is
    /// enforced post-hoc: an over-budget scan is flagged `timed_out` so
    /// `on_scan_timeout` decides the outcome, matching the body-scan path.
    fn run_cheap_with_budget<F>(&self, scan: F) -> ScanOutcome
    where
        F: FnOnce() -> ScanOutcome,
    {
        if self.config.scan_budget_ms == 0 {
            return scan();
        }
        let start = std::time::Instant::now();
        let mut outcome = scan();
        if start.elapsed() >= Duration::from_millis(self.config.scan_budget_ms) {
            outcome.timed_out = true;
        }
        outcome
    }

    fn finish_scan(&self, ctx: &mut RequestContext, outcome: ScanOutcome) -> PluginResult {
        if outcome.hits.is_empty() {
            if outcome.truncated && self.config.log_to_metadata {
                ctx.set_waf_metadata("waf.scan_truncated", "true");
            }
            if outcome.timed_out {
                return self.finish_timeout(ctx);
            }
            if self.config.log_to_metadata {
                ctx.set_waf_metadata_if_absent("waf.action", "clean");
            }
            return PluginResult::Continue;
        }

        let should_block = self.record_hits(ctx, &outcome, true);
        if should_block {
            // An over-budget cheap/body scan still ran to completion and
            // produced real matches, so a confirmed enforcing hit (or score
            // block) must reject regardless of `timed_out`. The block path
            // bypasses `finish_timeout`, so record the timeout flag here for
            // observability and to keep `on_scan_timeout` metadata intact.
            if outcome.timed_out && self.config.log_to_metadata {
                ctx.set_waf_metadata("waf.scan_timed_out", "true");
            }
            return self.reject();
        }
        if outcome.timed_out {
            return self.finish_timeout(ctx);
        }
        PluginResult::Continue
    }

    /// Build the configured rejection response (status, content-type, body).
    /// On TCP/UDP stream paths the proxy ignores the status/body and simply
    /// drops the connection or datagram; the `Reject` variant is what triggers
    /// that drop.
    fn reject(&self) -> PluginResult {
        PluginResult::Reject {
            status_code: self.config.reject_status_code,
            body: self.config.reject_body.clone(),
            headers: HashMap::from([(
                "content-type".to_string(),
                self.config.reject_content_type.clone(),
            )]),
        }
    }

    /// Aggregate matched stream signatures into a `(block, highest_severity,
    /// comma_joined_ids)` decision. Blocks only when enforcing globally and at
    /// least one matched signature is itself set to enforce.
    fn stream_decision(&self, hits: &[&stream::StreamSignatureMeta]) -> (bool, Severity, String) {
        let mut highest = Severity::Info;
        let mut any_enforce = false;
        let mut ids = Vec::with_capacity(hits.len());
        for hit in hits {
            highest = highest.max(hit.severity);
            any_enforce |= hit.action == RuleAction::Enforce;
            ids.push(hit.id.as_str());
        }
        let block = any_enforce && self.config.mode == GlobalMode::Enforce;
        (block, highest, ids.join(","))
    }

    /// Record stream WAF decision fields on a TCP `StreamConnectionContext` so
    /// they ride the stream transaction summary out to every logging sink.
    ///
    /// `blocked` is the decision in the *current* mode; `would_block` is whether
    /// the same condition blocks in `enforce` mode (always true for the transport
    /// guards, `any_enforce` for signatures). When blocked, the cause rides
    /// `waf.block_reason`. In `monitor` mode nothing is blocked, so an
    /// enforce-mode would-block is recorded as `waf.would_block_reason` instead —
    /// the transport guards carry no `rule_hits`, so without this an operator
    /// gauging rollout impact could not count missing-first-bytes would-blocks.
    fn record_stream_metadata(
        &self,
        ctx: &mut StreamConnectionContext,
        rule_hits: &str,
        severity: Severity,
        blocked: bool,
        would_block: bool,
        reason: &str,
    ) {
        if !self.config.log_to_metadata {
            return;
        }
        if !rule_hits.is_empty() {
            ctx.insert_metadata("waf.rule_hits".to_string(), rule_hits.to_string());
        }
        ctx.insert_metadata("waf.target".to_string(), "tcp_stream".to_string());
        ctx.insert_metadata("waf.severity".to_string(), severity.as_str().to_string());
        ctx.insert_metadata(
            "waf.action".to_string(),
            if blocked { "blocked" } else { "monitored" }.to_string(),
        );
        if blocked {
            ctx.insert_metadata("waf.block_reason".to_string(), reason.to_string());
        } else if would_block {
            ctx.insert_metadata("waf.would_block_reason".to_string(), reason.to_string());
        }
    }

    /// Emit one structured `warn!` per matched stream signature when
    /// `log_to_stdout` is configured.
    fn warn_stream_hits(
        &self,
        proxy_id: &str,
        client_ip: &str,
        transport: &str,
        hits: &[&stream::StreamSignatureMeta],
        blocked: bool,
    ) {
        if !self.config.log_to_stdout {
            return;
        }
        for hit in hits {
            warn!(
                target: "waf",
                proxy = %proxy_id,
                rule = %hit.id,
                severity = %hit.severity.as_str(),
                action = %hit.action.as_event_action(),
                transport = %transport,
                client_ip = %client_ip,
                blocked = blocked,
                "WAF stream signature matched"
            );
        }
    }

    /// Decide how to handle a body larger than `max_scan_bytes`. Returns the
    /// (possibly truncated) slice to scan and a `truncated` flag, or a
    /// short-circuit result: `Skip` → continue unscanned; `Block` → reject when
    /// enforcing (fail closed), else scan the prefix and flag it.
    fn clamp_body<'a>(
        &self,
        ctx: &mut RequestContext,
        body: &'a [u8],
    ) -> Result<(&'a [u8], bool), PluginResult> {
        if body.len() <= self.config.max_scan_bytes {
            return Ok((body, false));
        }
        match self.config.on_body_too_large {
            TooLargeAction::ScanTruncated => Ok((&body[..self.config.max_scan_bytes], true)),
            TooLargeAction::Skip => Err(PluginResult::Continue),
            TooLargeAction::Block => {
                if self.config.log_to_metadata {
                    ctx.set_waf_metadata("waf.body_too_large", "true");
                }
                if self.config.mode == GlobalMode::Enforce {
                    if self.config.log_to_metadata {
                        ctx.set_waf_metadata("waf.action", "blocked");
                        ctx.set_waf_metadata_if_absent("waf.block_reason", "body_too_large");
                    }
                    Err(self.reject())
                } else {
                    // Cannot block in monitor mode; scan the prefix instead so
                    // the oversize body still produces signal.
                    Ok((&body[..self.config.max_scan_bytes], true))
                }
            }
        }
    }

    fn record_hits(
        &self,
        ctx: &mut RequestContext,
        outcome: &ScanOutcome,
        enforce_actions: bool,
    ) -> bool {
        let mut first_blocking_rule = None;
        let mut highest = Severity::Info;
        let mut rule_ids = Vec::with_capacity(outcome.hits.len());
        let mut targets = Vec::with_capacity(outcome.hits.len());
        let mut phase_score: u32 = 0;
        for hit in &outcome.hits {
            let rule = &self.compiled.rules[hit.rule_index];
            highest = highest.max(rule.severity);
            rule_ids.push(rule.id.as_str());
            if !targets.contains(&hit.target_name) {
                targets.push(hit.target_name);
            }
            if let Some(scoring) = &self.config.scoring {
                let contribution = rule.score.unwrap_or_else(|| scoring.weight(rule.severity));
                phase_score = phase_score.saturating_add(contribution);
            }
            if enforce_actions
                && rule.action == RuleAction::Enforce
                && self.config.mode == GlobalMode::Enforce
                && first_blocking_rule.is_none()
            {
                first_blocking_rule = Some(rule.id.as_str());
            }
            self.warn_hit(ctx, hit);
        }

        // Accumulate across all scan phases of this instance (carried in
        // request-private per-instance state) so weak signals in the query,
        // body, and response add up to a single instance score that can cross
        // that instance's block threshold. Sibling WAF instances never share
        // this accumulator.
        let total_score = self.config.scoring.as_ref().and_then(|scoring| {
            ctx.ensure_waf_metadata_initialized();
            ctx.accumulate_waf_instance_score(self.instance_id, &self.identity, phase_score)
                .map(|total| (total, scoring.block_threshold))
        });
        let score_block = enforce_actions
            && self.config.mode == GlobalMode::Enforce
            && total_score.is_some_and(|(total, threshold)| total >= threshold);

        if self.config.log_to_metadata {
            ctx.ensure_waf_metadata_initialized();
            if let Some(previous_highest) = ctx
                .waf_metadata_value("waf.severity")
                .and_then(parse_severity)
            {
                highest = highest.max(previous_highest);
            }
            ctx.merge_waf_metadata("waf.rule_hits", &rule_ids.join(","));
            ctx.merge_waf_metadata("waf.target", &targets.join(","));
            ctx.set_waf_metadata("waf.severity", highest.as_str());
            ctx.set_waf_metadata("waf.paranoia", self.config.paranoia_level.to_string());
            if let Some((total, _)) = total_score {
                self.publish_instance_score_metadata(ctx, total);
            }
            if outcome.truncated {
                ctx.set_waf_metadata("waf.scan_truncated", "true");
            }
            if let Some(rule_id) = first_blocking_rule {
                ctx.set_waf_metadata_if_absent("waf.first_blocking_rule", rule_id);
                ctx.set_waf_metadata("waf.action", "blocked");
                ctx.set_waf_metadata_if_absent("waf.block_reason", "rule");
            } else if score_block {
                ctx.set_waf_metadata("waf.action", "blocked");
                ctx.set_waf_metadata_if_absent("waf.block_reason", "score");
                ctx.set_waf_metadata_if_absent("waf.scoring_instance", self.identity.as_ref());
            } else if ctx.waf_metadata_value("waf.action") != Some("blocked") {
                ctx.set_waf_metadata("waf.action", "monitored");
            }
        }

        first_blocking_rule.is_some() || score_block
    }

    /// Publish this instance's score and a deterministic multi-instance aggregate.
    ///
    /// - Always writes `waf.instances.<identity>.score` for the updating instance.
    /// - When exactly one instance has scored on this request, also writes
    ///   `waf.score` (single-policy compatibility).
    /// - When multiple instances have scored, writes sorted
    ///   `waf.instance_scores` as `id=score,...` and clears conflated `waf.score`.
    fn publish_instance_score_metadata(&self, ctx: &mut RequestContext, total: u32) {
        ctx.set_waf_metadata(self.score_metadata_key.as_ref(), total.to_string());
        if ctx.waf_instance_scores.len() <= 1 {
            ctx.set_waf_metadata("waf.score", total.to_string());
            ctx.clear_waf_metadata("waf.instance_scores");
            return;
        }
        let mut parts: Vec<(&str, u32)> = ctx
            .waf_instance_scores
            .values()
            .map(|state| (state.identity.as_ref(), state.score))
            .collect();
        parts.sort_unstable_by(|left, right| left.0.cmp(right.0));
        let mut aggregate = String::new();
        for (index, (identity, score)) in parts.iter().enumerate() {
            if index > 0 {
                aggregate.push(',');
            }
            aggregate.push_str(identity);
            aggregate.push('=');
            push_decimal_u32(&mut aggregate, *score);
        }
        ctx.set_waf_metadata("waf.instance_scores", aggregate);
        ctx.clear_waf_metadata("waf.score");
    }

    fn finish_timeout(&self, ctx: &mut RequestContext) -> PluginResult {
        if self.config.log_to_metadata {
            ctx.set_waf_metadata("waf.scan_timed_out", "true");
            match self.config.on_scan_timeout {
                TimeoutAction::Block => {
                    ctx.set_waf_metadata("waf.action", "blocked");
                }
                TimeoutAction::Allow | TimeoutAction::LogAndAllow => {
                    ctx.set_waf_metadata_if_absent("waf.action", "clean");
                }
            }
        }
        if !matches!(self.config.on_scan_timeout, TimeoutAction::Allow) {
            warn!(
                target: "waf",
                proxy = %proxy_id(ctx),
                client_ip = %ctx.client_ip,
                path = %ctx.path,
                method = %ctx.method,
                action = ?self.config.on_scan_timeout,
                "WAF scan timed out"
            );
        }
        match self.config.on_scan_timeout {
            TimeoutAction::Allow | TimeoutAction::LogAndAllow => PluginResult::Continue,
            TimeoutAction::Block => self.reject(),
        }
    }

    fn warn_hit(&self, ctx: &RequestContext, hit: &RuleHit) {
        if !self.config.log_to_stdout {
            return;
        }
        let rule = &self.compiled.rules[hit.rule_index];
        warn!(
            target: "waf",
            proxy = %proxy_id(ctx),
            rule = %rule.id,
            rule_name = %rule.name,
            severity = %rule.severity.as_str(),
            category = %rule.category,
            action = %rule.action.as_event_action(),
            target_field = %hit.target_name,
            client_ip = %ctx.client_ip,
            path = %ctx.path,
            method = %ctx.method,
            "WAF rule matched"
        );
    }

    fn response_body_eligible_for_scan(&self, content_type: Option<&str>) -> bool {
        // Response bodies with missing or malformed content-type are still
        // eligible when binary inspection is explicit; request bodies are
        // gated earlier by `should_buffer_request_body`.
        self.config.inspect_binary_body || self.should_inspect_body_content_type(content_type)
    }
}

#[async_trait]
impl Plugin for Waf {
    fn name(&self) -> &str {
        "waf"
    }

    fn priority(&self) -> u16 {
        super::priority::WAF
    }

    /// WAF body rules decide in the final request-body phase, over the exact
    /// backend-visible representation. Composition admission refuses to pair
    /// this with a plugin that egresses the request before finalization on an
    /// HTTP/gRPC request-body protocol (GHSA-4vr5-4wm3-x5xv). Stream inspection
    /// on TCP/UDP does not widen that body-policy collision.
    fn enforces_finalized_request_policy(&self) -> bool {
        true
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        self.supported_protocols
    }

    fn requires_stream_first_bytes(&self) -> bool {
        self.active
            && self
                .stream
                .as_ref()
                .is_some_and(|s| s.needs_tcp_first_bytes())
    }

    fn requires_stream_first_bytes_decrypted(&self) -> bool {
        self.active
            && self
                .stream
                .as_ref()
                .is_some_and(|s| s.needs_tcp_decrypted_first_bytes())
    }

    fn stream_first_bytes_min_len(&self) -> usize {
        // Only the TLS-shape guard needs a complete prefix: it inspects the
        // leading TLS record + handshake-type bytes, so a fragmented ClientHello
        // must be reassembled to at least that length before classification, or a
        // legitimately split hello would be rejected in enforce mode. Signature
        // scanning has no minimum (it matches whatever opening bytes arrive), so
        // a guard-less config keeps the cheap single-peek behavior.
        if self.active && self.stream.as_ref().is_some_and(|s| s.tcp_require_tls) {
            TLS_CLIENT_HELLO_MIN_PREFIX
        } else {
            0
        }
    }

    fn requires_udp_datagram_hooks(&self) -> bool {
        self.active
            && self
                .stream
                .as_ref()
                .is_some_and(|s| s.needs_udp_datagrams())
    }

    /// Inspect the opening bytes of a TCP stream. Runs before backend dispatch
    /// so a block never dials an upstream. The bytes were captured into
    /// `ctx.first_bytes` by the TCP proxy (raw peek for plaintext/passthrough,
    /// decrypted prefix for TLS-terminated frontends).
    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let Some(stream) = self.stream.as_ref() else {
            return PluginResult::Continue;
        };
        if !self.active {
            return PluginResult::Continue;
        }

        // Transport-shape guard (TCP only). A TLS-terminating frontend has
        // already proven the transport (the proxy marks it `DecryptedApp`), so
        // the guard is satisfied. On a raw TCP connection the opening bytes must
        // begin a TLS ClientHello — and missing bytes (idle peek timeout / EOF)
        // fail closed, so a client cannot stall the peek and then send plaintext.
        if stream.tcp_require_tls
            && matches!(ctx.backend_scheme, BackendScheme::Tcp | BackendScheme::Tcps)
        {
            let terminated = matches!(ctx.first_bytes_kind, Some(StreamBytesKind::DecryptedApp));
            let presents_tls = ctx
                .first_bytes
                .as_ref()
                .is_some_and(|b| looks_like_tls_client_hello(b));
            if !terminated && !presents_tls {
                let blocked = self.config.mode == GlobalMode::Enforce;
                // A transport-shape miss always blocks in enforce mode, so it is
                // unconditionally a would-block for monitor-mode accounting.
                self.record_stream_metadata(
                    ctx,
                    "",
                    Severity::High,
                    blocked,
                    true,
                    "tcp_require_tls",
                );
                if self.config.log_to_stdout {
                    warn!(
                        target: "waf",
                        proxy = %ctx.proxy_id,
                        client_ip = %ctx.client_ip,
                        transport = "tcp",
                        blocked = blocked,
                        "WAF: non-TLS traffic on tcp_require_tls port"
                    );
                }
                if blocked {
                    return self.reject();
                }
                return PluginResult::Continue;
            }
        }

        // L7 signature scan over plaintext / decrypted opening bytes only.
        // If an inspectable stream produced no bytes before the bounded capture
        // deadline (idle client / EOF / read timeout), fail closed in enforce
        // mode. Otherwise a client could wait out the peek/read window and send
        // malicious first bytes after the backend relay starts. Encrypted
        // passthrough remains fail-open for signatures because the gateway never
        // has L7 plaintext to scan there.
        if stream.inspect_tcp && !stream.signatures.is_empty() {
            let kind = ctx
                .first_bytes_kind
                .unwrap_or(StreamBytesKind::PlaintextWire);
            if kind.is_l7_inspectable() {
                let Some(bytes) = ctx.first_bytes.clone() else {
                    // Mirror the present-payload decision (`stream_decision`): a
                    // config with no enforce-action signature never rejects a
                    // match, so it must not fail closed on missing bytes either —
                    // that would block idle / server-first clients with no
                    // possible block to justify it. Only an enforce-action
                    // signature, whose hidden match we cannot rule out, fails
                    // closed.
                    if !stream.signatures.has_enforce_action() {
                        return PluginResult::Continue;
                    }
                    let blocked = self.config.mode == GlobalMode::Enforce;
                    // An enforce-action signature exists, so this is a would-block
                    // in enforce mode (recorded for monitor-mode accounting).
                    self.record_stream_metadata(
                        ctx,
                        "",
                        Severity::High,
                        blocked,
                        true,
                        "first_bytes_unavailable",
                    );
                    if self.config.log_to_stdout {
                        warn!(
                            target: "waf",
                            proxy = %ctx.proxy_id,
                            client_ip = %ctx.client_ip,
                            transport = "tcp",
                            blocked = blocked,
                            "WAF: TCP stream first bytes unavailable for signature inspection"
                        );
                    }
                    if blocked {
                        return self.reject();
                    }
                    return PluginResult::Continue;
                };
                let hits = stream.signatures.matches(&bytes);
                if !hits.is_empty() {
                    let (block, severity, ids) = self.stream_decision(&hits);
                    // `block` folds in the global mode; the monitor-mode
                    // would-block signal is whether any matched signature is
                    // enforce-action (i.e. would reject under `enforce`).
                    let would_block = hits.iter().any(|h| h.action == RuleAction::Enforce);
                    self.record_stream_metadata(
                        ctx,
                        &ids,
                        severity,
                        block,
                        would_block,
                        "signature",
                    );
                    self.warn_stream_hits(&ctx.proxy_id, &ctx.client_ip, "tcp", &hits, block);
                    if block {
                        return self.reject();
                    }
                }
            }
        }
        PluginResult::Continue
    }

    /// Inspect a UDP/DTLS datagram payload. Encrypted passthrough datagrams are
    /// skipped (not L7-inspectable). A block is a silent `Drop` (standard UDP
    /// behavior). Hits (blocked or monitored) ride the session transaction
    /// summary via `ctx.metadata_sink` (`waf.*`, default-on through
    /// `log_to_metadata`) and are additionally logged when `log_to_stdout` is set.
    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
        let Some(stream) = self.stream.as_ref() else {
            return UdpDatagramVerdict::Forward;
        };
        if !self.active || !stream.inspect_udp {
            return UdpDatagramVerdict::Forward;
        }
        if !ctx.payload_kind.is_l7_inspectable() {
            return UdpDatagramVerdict::Forward;
        }
        // Inspect client→backend by default; responses only when opted in.
        if ctx.direction == UdpDatagramDirection::BackendToClient && !stream.inspect_response {
            return UdpDatagramVerdict::Forward;
        }
        let hits = stream.signatures.matches(ctx.payload);
        if hits.is_empty() {
            return UdpDatagramVerdict::Forward;
        }
        let (block, severity, ids) = self.stream_decision(&hits);
        // `block` folds in the global mode; the monitor-mode would-block signal is
        // whether any matched signature is enforce-action (would reject under
        // `enforce`). Mirrors the TCP `record_stream_metadata` accounting.
        let would_block = hits.iter().any(|h| h.action == RuleAction::Enforce);
        // Record the hit on the session transaction summary so a UDP/DTLS match
        // is observable by default — parity with the TCP `on_stream_connect` path,
        // not only when `log_to_stdout` is enabled. The per-datagram context is
        // immutable, so this rides the proxy-provided session metadata sink. A
        // session sees many datagrams, so findings are *merged* across them rather
        // than overwritten (last-hit-wins): rule ids accumulate, severity keeps its
        // max, and a `blocked` action is never downgraded by a later `monitored`
        // hit. The whole merge runs under one lock so the bidirectional datagram
        // tasks cannot race.
        if self.config.log_to_metadata
            && let Some(sink) = ctx.metadata_sink
        {
            sink.update(|meta| {
                merge_csv_into(meta, "waf.rule_hits", &ids);
                meta.insert("waf.target".to_string(), "udp_stream".to_string());
                let raise = meta
                    .get("waf.severity")
                    .and_then(|current| parse_severity(current))
                    .is_none_or(|current| severity > current);
                if raise {
                    meta.insert("waf.severity".to_string(), severity.as_str().to_string());
                }
                if block {
                    meta.insert("waf.action".to_string(), "blocked".to_string());
                    meta.entry("waf.block_reason".to_string())
                        .or_insert_with(|| "signature".to_string());
                } else {
                    meta.entry("waf.action".to_string())
                        .or_insert_with(|| "monitored".to_string());
                    // Monitor mode: keep the enforce-mode would-block countable.
                    // `block`/`would_block` are mode-exclusive, so this never
                    // coexists with `waf.block_reason` in a session.
                    if would_block {
                        meta.entry("waf.would_block_reason".to_string())
                            .or_insert_with(|| "signature".to_string());
                    }
                }
            });
        }
        self.warn_stream_hits(&ctx.proxy_id, &ctx.client_ip, "udp", &hits, block);
        if block {
            UdpDatagramVerdict::Drop
        } else {
            UdpDatagramVerdict::Forward
        }
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        if self.active {
            ctx.ensure_waf_metadata_initialized();
        }
        if !self.active
            || !self.config.request_inspection
            || !self.compiled.request_cheap_rules_active
        {
            return PluginResult::Continue;
        }
        if self.request_is_exempt(ctx) {
            return PluginResult::Continue;
        }
        let outcome = self.run_cheap_with_budget(|| self.run_cheap_scan(ctx));
        self.finish_scan(ctx, outcome)
    }

    fn requires_request_body_buffering(&self) -> bool {
        self.active
            && self.config.request_inspection
            && self.config.request_body_inspection
            && (self.compiled.request_body_rules_active || self.body_encoding_specials_active())
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if !self.requires_request_body_buffering() || self.exemptions.request_short_circuits(ctx) {
            return false;
        }
        if !self
            .config
            .body_methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(&ctx.method))
        {
            return false;
        }
        if self.config.on_body_too_large == TooLargeAction::Skip
            && let Some(content_length) = ctx.headers.get("content-length")
            && let Ok(length) = content_length.parse::<usize>()
            && length > self.config.max_scan_bytes
        {
            return false;
        }
        self.request_body_eligible_for_scan(ctx.headers.get("content-type").map(String::as_str))
    }

    fn needs_request_body_bytes(&self) -> bool {
        self.requires_request_body_buffering()
    }

    fn needs_final_request_body_context(&self) -> bool {
        self.requires_request_body_buffering()
    }

    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if self.active {
            ctx.ensure_waf_metadata_initialized();
        }
        if !self.requires_request_body_buffering()
            || self.exemptions.request_short_circuits(ctx)
            || !self
                .config
                .body_methods
                .iter()
                .any(|method| method.eq_ignore_ascii_case(&ctx.method))
            || !self.request_body_eligible_for_scan(headers.get("content-type").map(String::as_str))
        {
            return PluginResult::Continue;
        }
        let (body, truncated) = match self.clamp_body(ctx, body) {
            Ok(value) => value,
            Err(result) => return result,
        };
        let mut outcome = self
            .run_body_scan_with_budget(|| self.run_request_body_scan(ctx, body))
            .await;
        outcome.truncated = truncated;
        self.finish_scan(ctx, outcome)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if self.active {
            ctx.ensure_waf_metadata_initialized();
        }
        if !self.active
            || !self.config.response_inspection
            || self.exemptions.request_short_circuits(ctx)
        {
            return PluginResult::Continue;
        }
        if self.compiled.response_header_rules_active {
            let outcome =
                self.run_cheap_with_budget(|| self.run_response_header_scan(ctx, response_headers));
            let result = self.finish_scan(ctx, outcome);
            if !matches!(&result, PluginResult::Continue) {
                return result;
            }
        }
        if self.should_buffer_response_body(ctx)
            && original_response_is_event_stream(ctx, response_headers)
        {
            return self.handle_unbounded_response_stream(ctx);
        }
        PluginResult::Continue
    }

    fn response_trailer_policy(&self) -> ResponseTrailerPolicy<'_> {
        if self.active
            && self.config.response_inspection
            && self.has_enforcing_response_header_policy()
        {
            // Response-header rules can match any field name or value. Since
            // `after_proxy` cannot inspect trailer-only fields, fail closed by
            // preventing trailer-forwarding paths from emitting that section.
            //
            // REQUEST-CONDITIONAL, not `Unbounded`: `after_proxy` returns early
            // for a `global_exemptions` match, so an exempt request never gets a
            // response-header scan and there is nothing to fail closed about —
            // it must keep its backend trailers exactly as it did before this
            // governance existed, matching
            // `requires_buffered_grpc_web_trailer_policy`. The per-request arm
            // is `request_applies_unbounded_response_trailer_policy` below.
            ResponseTrailerPolicy::RequestConditionalUnbounded
        } else {
            ResponseTrailerPolicy::None
        }
    }

    fn request_applies_unbounded_response_trailer_policy(&self, ctx: &RequestContext) -> bool {
        // Exactly the predicate that gates `after_proxy`'s response-header scan,
        // so the trailer fail-closed arm is active on precisely the requests the
        // WAF can actually enforce on. Consumer-keyed exemptions resolve only
        // after authentication, which is why the caller defers this to the
        // finalized request context.
        !self.request_is_exempt(ctx)
    }

    fn requires_buffered_grpc_web_trailer_policy(&self, ctx: &RequestContext) -> bool {
        self.active
            && self.config.response_inspection
            && self.compiled.response_header_rules_active
            && !self.exemptions.request_short_circuits(ctx)
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.active
            && self.config.response_inspection
            && self.config.response_body_inspection
            && (self.compiled.response_body_rules_active || self.body_encoding_specials_active())
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.requires_response_body_buffering() && !self.exemptions.request_short_circuits(ctx)
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
        self.should_buffer_response_body(ctx)
            && original_response_is_event_stream(ctx, response_headers)
    }

    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
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
        // Narrow the pre-flight buffering decision once the response
        // content-type is known: a body whose content-type is not eligible for
        // scanning (non-allowlisted / binary with `inspect_binary_body=false`)
        // would be buffered and then skipped by `on_final_response_body`, so let
        // the proxy stream it instead of collecting bytes nothing will inspect.
        self.should_buffer_response_body(ctx)
            && !content_type.is_some_and(is_text_event_stream_media_type)
            && self.response_body_eligible_for_scan(content_type)
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if self.active {
            ctx.ensure_waf_metadata_initialized();
        }
        if !self.should_buffer_response_body(ctx) {
            return PluginResult::Continue;
        }
        if !self.response_body_eligible_for_scan(
            response_headers.get("content-type").map(String::as_str),
        ) {
            return PluginResult::Continue;
        }
        let (body, truncated) = match self.clamp_body(ctx, body) {
            Ok(value) => value,
            Err(result) => return result,
        };
        let mut outcome = self
            .run_body_scan_with_budget(|| self.run_response_body_scan(ctx, body))
            .await;
        outcome.truncated = truncated;
        self.finish_scan(ctx, outcome)
    }
}

fn proxy_id(ctx: &RequestContext) -> &str {
    ctx.matched_proxy
        .as_ref()
        .map(|proxy| proxy.id.as_str())
        .unwrap_or("-")
}

fn default_body_methods() -> Vec<String> {
    vec!["POST".into(), "PUT".into(), "PATCH".into()]
}

fn default_body_content_types() -> Vec<String> {
    vec![
        "application/json".into(),
        "application/x-www-form-urlencoded".into(),
        "application/xml".into(),
        "text/xml".into(),
        "text/plain".into(),
        "text/html".into(),
    ]
}

fn parse_severity(value: &str) -> Option<Severity> {
    match value {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Union a comma-separated `value` into `map[key]`, preserving first-seen order
/// and dropping duplicates. Lets repeated stream WAF hits on one session
/// accumulate matched rule ids instead of overwriting them (last-hit-wins).
fn merge_csv_into(map: &mut HashMap<String, String>, key: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    let Some(existing) = map.get(key) else {
        map.insert(key.to_string(), value.to_string());
        return;
    };
    let existing = existing.clone();
    let mut ids: Vec<&str> = existing.split(',').filter(|s| !s.is_empty()).collect();
    for id in value.split(',').filter(|s| !s.is_empty()) {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    map.insert(key.to_string(), ids.join(","));
}

fn parse_global_mode(raw: &str) -> Result<GlobalMode, String> {
    match raw {
        "enforce" => Ok(GlobalMode::Enforce),
        "monitor" => Ok(GlobalMode::Monitor),
        "disabled" => Ok(GlobalMode::Disabled),
        other => Err(format!(
            "waf: 'mode' must be one of enforce, monitor, disabled; got {other:?}"
        )),
    }
}

fn parse_timeout_action(raw: &str) -> Result<TimeoutAction, String> {
    match raw {
        "allow" => Ok(TimeoutAction::Allow),
        "block" => Ok(TimeoutAction::Block),
        "log_and_allow" => Ok(TimeoutAction::LogAndAllow),
        other => Err(format!(
            "waf: 'on_scan_timeout' must be allow, block, or log_and_allow; got {other:?}"
        )),
    }
}

fn parse_too_large_action(raw: &str) -> Result<TooLargeAction, String> {
    match raw {
        "scan_truncated" => Ok(TooLargeAction::ScanTruncated),
        "skip" => Ok(TooLargeAction::Skip),
        "block" => Ok(TooLargeAction::Block),
        other => Err(format!(
            "waf: 'on_body_too_large' must be scan_truncated, skip, or block; got {other:?}"
        )),
    }
}

fn parse_scoring(value: Option<&Value>) -> Result<Option<ScoringConfig>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| "waf: 'scoring' must be an object".to_string())?;
    reject_unknown_keys(object, "config.scoring", SCORING_CONFIG_KEYS, "waf: ")?;
    if !optional_bool(object, "enabled")?.unwrap_or(true) {
        return Ok(None);
    }
    let block_threshold = optional_u64(object, "block_threshold")?
        .map(|v| {
            u32::try_from(v).map_err(|_| "waf: 'scoring.block_threshold' is too large".to_string())
        })
        .transpose()?
        .unwrap_or(7);
    if block_threshold == 0 {
        return Err("waf: 'scoring.block_threshold' must be greater than zero".to_string());
    }
    // Defaults: one critical, or one high plus one medium, crosses the default
    // threshold of 7; a lone medium does not.
    let mut weights = [0u32, 2, 3, 5, 10];
    match object.get("weights") {
        None | Some(Value::Null) => {}
        Some(Value::Object(map)) => {
            for (key, raw) in map {
                let index = match key.as_str() {
                    "info" => 0,
                    "low" => 1,
                    "medium" => 2,
                    "high" => 3,
                    "critical" => 4,
                    other => {
                        return Err(format!(
                            "waf: 'scoring.weights' has unknown severity '{other}'"
                        ));
                    }
                };
                weights[index] = raw
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| {
                        format!("waf: 'scoring.weights.{key}' must be a non-negative integer")
                    })?;
            }
        }
        Some(_) => return Err("waf: 'scoring.weights' must be an object".to_string()),
    }
    Ok(Some(ScoringConfig {
        block_threshold,
        weights,
    }))
}

fn parse_rule_modes(value: Option<&Value>) -> Result<HashMap<String, RuleAction>, String> {
    match value {
        None | Some(Value::Null) => Ok(HashMap::new()),
        Some(Value::Object(map)) => {
            let mut parsed = HashMap::new();
            for (rule_id, value) in map {
                let Some(raw) = value.as_str() else {
                    return Err("waf: rule_modes values must be strings".to_string());
                };
                parsed.insert(rule_id.clone(), parse_rule_action(raw, "rule_modes")?);
            }
            Ok(parsed)
        }
        Some(other) => Err(format!("waf: 'rule_modes' must be an object, got {other}")),
    }
}

fn parse_custom_rules(
    value: Option<&Value>,
    default_action: RuleAction,
) -> Result<Vec<WafRule>, String> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .enumerate()
            .map(|(idx, value)| {
                parse_custom_rule(
                    value,
                    default_action,
                    &format!("config.custom_rules[{idx}]"),
                )
            })
            .collect(),
        Some(other) => Err(format!("waf: 'custom_rules' must be an array, got {other}")),
    }
}

fn optional_bool(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<bool>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(other) => Err(format!("waf: '{key}' must be a boolean, got {other}")),
    }
}

fn optional_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(format!("waf: '{key}' must be non-empty")),
        Some(other) => Err(format!("waf: '{key}' must be a string, got {other}")),
    }
}

fn optional_string_vec(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<Vec<String>>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => {
            let mut parsed = Vec::with_capacity(values.len());
            for value in values {
                let Some(raw) = value.as_str() else {
                    return Err(format!("waf: '{key}' entries must be strings"));
                };
                if raw.is_empty() {
                    return Err(format!("waf: '{key}' entries must be non-empty"));
                }
                parsed.push(raw.to_string());
            }
            Ok(Some(parsed))
        }
        Some(other) => Err(format!("waf: '{key}' must be an array, got {other}")),
    }
}

fn optional_u8(object: &serde_json::Map<String, Value>, key: &str) -> Result<Option<u8>, String> {
    optional_u64(object, key)?
        .map(|value| u8::try_from(value).map_err(|_| format!("waf: '{key}' is too large")))
        .transpose()
}

fn optional_u16(object: &serde_json::Map<String, Value>, key: &str) -> Result<Option<u16>, String> {
    optional_u64(object, key)?
        .map(|value| u16::try_from(value).map_err(|_| format!("waf: '{key}' is too large")))
        .transpose()
}

fn optional_usize(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<usize>, String> {
    optional_u64(object, key)?
        .map(|value| usize::try_from(value).map_err(|_| format!("waf: '{key}' is too large")))
        .transpose()
}

fn optional_u64(object: &serde_json::Map<String, Value>, key: &str) -> Result<Option<u64>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("waf: '{key}' must be a non-negative integer")),
        Some(other) => Err(format!("waf: '{key}' must be an integer, got {other}")),
    }
}

/// Append a decimal `u32` without allocating an intermediate `String`.
fn push_decimal_u32(buf: &mut String, value: u32) {
    let mut digits = [0u8; 10];
    let mut remaining = value;
    let mut index = digits.len();
    loop {
        index -= 1;
        digits[index] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    // Digits are ASCII by construction.
    buf.push_str(std::str::from_utf8(&digits[index..]).unwrap_or("0"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body_ctx() -> RequestContext {
        let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/submit".into());
        ctx.headers
            .insert("content-type".into(), "application/json".into());
        ctx
    }

    #[test]
    fn scan_budget_timeout_enforced_hits_still_reject() {
        let plugin = Waf::new(&json!({
            "include_default_rules": false,
            "scan_budget_ms": 1,
            "on_scan_timeout": "log_and_allow",
            "custom_rules": [{
                "id": "CUSTOM-SLOW",
                "name": "slow",
                "category": "custom",
                "target": "body_text",
                "match_kind": "contains",
                "pattern": "needle",
                "action": "enforce"
            }]
        }))
        .unwrap();
        let mut ctx = body_ctx();

        let mut outcome = ScanOutcome {
            timed_out: true,
            ..ScanOutcome::default()
        };
        outcome.push(RuleHit {
            rule_index: 0,
            target_name: "request_body",
        });

        assert!(outcome.timed_out);
        let result = plugin.finish_scan(&mut ctx, outcome);

        assert!(matches!(result, PluginResult::Reject { .. }));
        assert_eq!(
            ctx.metadata.get("waf.rule_hits").map(String::as_str),
            Some("CUSTOM-SLOW")
        );
        assert_eq!(
            ctx.metadata.get("waf.scan_timed_out").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            ctx.metadata.get("waf.action").map(String::as_str),
            Some("blocked")
        );
    }

    #[tokio::test]
    async fn scan_budget_timeout_block_action_rejects() {
        let plugin = Waf::new(&json!({
            "include_default_rules": false,
            "scan_budget_ms": 1,
            "on_scan_timeout": "block",
            "custom_rules": [{
                "id": "CUSTOM-SLOW",
                "name": "slow",
                "category": "custom",
                "target": "body_text",
                "match_kind": "contains",
                "pattern": "needle",
                "action": "monitor"
            }]
        }))
        .unwrap();
        let mut ctx = body_ctx();

        let outcome = plugin
            .run_body_scan_with_budget(|| {
                std::thread::sleep(Duration::from_millis(5));
                ScanOutcome::default()
            })
            .await;
        let result = plugin.finish_scan(&mut ctx, outcome);

        assert!(matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ));
        assert_eq!(
            ctx.metadata.get("waf.scan_timed_out").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            ctx.metadata.get("waf.action").map(String::as_str),
            Some("blocked")
        );
    }

    #[test]
    fn cheap_scan_budget_flags_timeout() {
        let plugin = Waf::new(&json!({ "scan_budget_ms": 1 })).unwrap();
        let outcome = plugin.run_cheap_with_budget(|| {
            std::thread::sleep(Duration::from_millis(5));
            ScanOutcome::default()
        });
        assert!(outcome.timed_out);
    }

    #[test]
    fn cheap_scan_budget_zero_never_times_out() {
        let plugin = Waf::new(&json!({ "scan_budget_ms": 0 })).unwrap();
        let outcome = plugin.run_cheap_with_budget(|| {
            std::thread::sleep(Duration::from_millis(2));
            ScanOutcome::default()
        });
        assert!(!outcome.timed_out);
    }
}
