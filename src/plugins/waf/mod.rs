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
mod rules;
mod scan;

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tracing::warn;

use self::defaults::default_rules;
use self::exemptions::CompiledExemptions;
use self::rules::{
    CompiledRules, RuleAction, RuleHit, Severity, WafRule, compile_rules, parse_custom_rule,
    parse_rule_action,
};
use self::scan::ScanOutcome;
use super::utils::sse::is_sse_request;
use super::{HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext};

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
}

#[derive(Debug)]
struct SpecialRuleIndices {
    encoding: Option<usize>,
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
}

impl Waf {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "waf: config must be an object".to_string())?;

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
        let default_action = match mode {
            GlobalMode::Enforce => RuleAction::Enforce,
            GlobalMode::Monitor | GlobalMode::Disabled => RuleAction::Monitor,
        };
        let custom_rules = parse_custom_rules(object.get("custom_rules"), default_action)?;
        let exemptions = CompiledExemptions::from_config(object.get("global_exemptions"))?;

        let mut all_rules: Vec<(WafRule, bool)> = Vec::new();
        if include_default_rules {
            all_rules.extend(default_rules().into_iter().map(|rule| (rule, true)));
        }
        all_rules.extend(custom_rules.into_iter().map(|rule| (rule, false)));
        if all_rules.is_empty() {
            return Err(
                "waf: no rules configured — enable default rules or provide custom_rules"
                    .to_string(),
            );
        }
        let compiled = compile_rules(
            all_rules,
            &disabled_default_rules,
            &rule_modes,
            paranoia_level,
        )?;
        if compiled.is_empty() && mode != GlobalMode::Disabled {
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
        };
        if !(400..=599).contains(&config.reject_status_code) {
            return Err("waf: 'reject_status_code' must be from 400 to 599".to_string());
        }

        let specials = SpecialRuleIndices {
            encoding: compiled.find_rule_index("FE-ENCODING-001"),
            hpp: compiled.find_rule_index("FE-HPP-001"),
            method: compiled.find_rule_index("FE-METHOD-001"),
            method_override: compiled.find_rule_index("FE-HEADER-002"),
        };
        let active = config.mode != GlobalMode::Disabled && !compiled.is_empty();
        Ok(Self {
            config,
            compiled,
            exemptions,
            specials,
            active,
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

    fn finish_scan(&self, ctx: &mut RequestContext, outcome: ScanOutcome) -> PluginResult {
        if outcome.hits.is_empty() {
            if outcome.truncated && self.config.log_to_metadata {
                ctx.metadata
                    .insert("waf.scan_truncated".to_string(), "true".to_string());
            }
            if outcome.timed_out {
                return self.finish_timeout(ctx);
            }
            return PluginResult::Continue;
        }

        let has_blocking_rule = self.record_hits(ctx, &outcome, !outcome.timed_out);
        if outcome.timed_out {
            return self.finish_timeout(ctx);
        }

        if has_blocking_rule {
            let mut headers = HashMap::new();
            headers.insert(
                "content-type".to_string(),
                self.config.reject_content_type.clone(),
            );
            PluginResult::Reject {
                status_code: self.config.reject_status_code,
                body: self.config.reject_body.clone(),
                headers,
            }
        } else {
            PluginResult::Continue
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
        for hit in &outcome.hits {
            let rule = &self.compiled.rules[hit.rule_index];
            highest = highest.max(rule.severity);
            rule_ids.push(rule.id.as_str());
            if !targets.contains(&hit.target_name) {
                targets.push(hit.target_name);
            }
            if enforce_actions
                && rule.action == RuleAction::Enforce
                && first_blocking_rule.is_none()
            {
                first_blocking_rule = Some(rule.id.as_str());
            }
            self.warn_hit(ctx, hit);
        }

        if self.config.log_to_metadata {
            merge_metadata(&mut ctx.metadata, "waf.rule_hits", &rule_ids.join(","));
            merge_metadata(&mut ctx.metadata, "waf.target", &targets.join(","));
            ctx.metadata
                .insert("waf.severity".to_string(), highest.as_str().to_string());
            ctx.metadata.insert(
                "waf.paranoia".to_string(),
                self.config.paranoia_level.to_string(),
            );
            if outcome.truncated {
                ctx.metadata
                    .insert("waf.scan_truncated".to_string(), "true".to_string());
            }
            if let Some(rule_id) = first_blocking_rule {
                ctx.metadata
                    .entry("waf.first_blocking_rule".to_string())
                    .or_insert_with(|| rule_id.to_string());
                ctx.metadata
                    .insert("waf.action".to_string(), "blocked".to_string());
            } else if ctx.metadata.get("waf.action").map(String::as_str) != Some("blocked") {
                ctx.metadata
                    .insert("waf.action".to_string(), "monitored".to_string());
            }
        }

        first_blocking_rule.is_some()
    }

    fn finish_timeout(&self, ctx: &mut RequestContext) -> PluginResult {
        if self.config.log_to_metadata {
            ctx.metadata
                .insert("waf.scan_timed_out".to_string(), "true".to_string());
            match self.config.on_scan_timeout {
                TimeoutAction::Block => {
                    ctx.metadata
                        .insert("waf.action".to_string(), "blocked".to_string());
                }
                TimeoutAction::Allow | TimeoutAction::LogAndAllow => {
                    ctx.metadata
                        .entry("waf.action".to_string())
                        .or_insert_with(|| "clean".to_string());
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
            TimeoutAction::Block => PluginResult::Reject {
                status_code: self.config.reject_status_code,
                body: self.config.reject_body.clone(),
                headers: HashMap::from([(
                    "content-type".to_string(),
                    self.config.reject_content_type.clone(),
                )]),
            },
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

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        HTTP_FAMILY_PROTOCOLS
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        if !self.active
            || !self.config.request_inspection
            || !self.compiled.request_cheap_rules_active
        {
            return PluginResult::Continue;
        }
        if self.request_is_exempt(ctx) {
            return PluginResult::Continue;
        }
        let outcome = self.run_cheap_scan(ctx);
        self.finish_scan(ctx, outcome)
    }

    fn requires_request_body_buffering(&self) -> bool {
        self.active
            && self.config.request_inspection
            && self.config.request_body_inspection
            && self.compiled.request_body_rules_active
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
        self.should_inspect_body_content_type(ctx.headers.get("content-type").map(String::as_str))
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
        if !self.requires_request_body_buffering()
            || self.exemptions.request_short_circuits(ctx)
            || !self
                .config
                .body_methods
                .iter()
                .any(|method| method.eq_ignore_ascii_case(&ctx.method))
            || !self
                .should_inspect_body_content_type(headers.get("content-type").map(String::as_str))
        {
            return PluginResult::Continue;
        }
        let mut truncated = false;
        let body = if body.len() > self.config.max_scan_bytes {
            match self.config.on_body_too_large {
                TooLargeAction::Skip => return PluginResult::Continue,
                TooLargeAction::ScanTruncated => {
                    truncated = true;
                    &body[..self.config.max_scan_bytes]
                }
            }
        } else {
            body
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
        if !self.active
            || !self.config.response_inspection
            || !self.compiled.response_header_rules_active
            || self.exemptions.request_short_circuits(ctx)
        {
            return PluginResult::Continue;
        }
        let outcome = self.run_response_header_scan(ctx, response_headers);
        self.finish_scan(ctx, outcome)
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.active
            && self.config.response_inspection
            && self.config.response_body_inspection
            && self.compiled.response_body_rules_active
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.requires_response_body_buffering()
            && !is_sse_request(ctx)
            && !self.exemptions.request_short_circuits(ctx)
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.should_buffer_response_body(ctx) {
            return PluginResult::Continue;
        }
        if !self.response_body_eligible_for_scan(
            response_headers.get("content-type").map(String::as_str),
        ) {
            return PluginResult::Continue;
        }
        let mut truncated = false;
        let body = if body.len() > self.config.max_scan_bytes {
            match self.config.on_body_too_large {
                TooLargeAction::Skip => return PluginResult::Continue,
                TooLargeAction::ScanTruncated => {
                    truncated = true;
                    &body[..self.config.max_scan_bytes]
                }
            }
        } else {
            body
        };
        let mut outcome = self
            .run_body_scan_with_budget(|| self.run_response_body_scan(ctx, body))
            .await;
        outcome.truncated = truncated;
        self.finish_scan(ctx, outcome)
    }
}

fn merge_metadata(metadata: &mut HashMap<String, String>, key: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    metadata
        .entry(key.to_string())
        .and_modify(|existing| {
            if !existing.is_empty() {
                existing.push(',');
            }
            existing.push_str(value);
        })
        .or_insert_with(|| value.to_string());
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
        other => Err(format!(
            "waf: 'on_body_too_large' must be scan_truncated or skip; got {other:?}"
        )),
    }
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
            .map(|value| parse_custom_rule(value, default_action))
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

    #[tokio::test]
    async fn scan_budget_timeout_preserves_hits_for_metadata() {
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

        let outcome = plugin
            .run_body_scan_with_budget(|| {
                std::thread::sleep(Duration::from_millis(5));
                let mut outcome = ScanOutcome::default();
                outcome.push(RuleHit {
                    rule_index: 0,
                    target_name: "request_body",
                });
                outcome
            })
            .await;

        assert!(outcome.timed_out);
        let result = plugin.finish_scan(&mut ctx, outcome);

        assert!(matches!(result, PluginResult::Continue));
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
            Some("monitored")
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
}
