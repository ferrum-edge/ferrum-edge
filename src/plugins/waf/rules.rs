use regex::{Regex, RegexSet, RegexSetBuilder, bytes::RegexSet as BytesRegexSet};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::plugins::RequestContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuleAction {
    Enforce,
    Monitor,
    Disabled,
}

impl RuleAction {
    pub(super) fn as_event_action(self) -> &'static str {
        match self {
            RuleAction::Enforce => "block",
            RuleAction::Monitor => "monitor",
            RuleAction::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MatchKind {
    Regex,
    Literal,
    Contains,
    Equals,
    Luhn,
    Cidr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RuleTarget {
    HeaderNames,
    HeaderValues(Option<Vec<String>>),
    QueryKeys,
    QueryValues,
    Cookies,
    UrlPath,
    FullUrl,
    Method,
    BodyText,
    BodyJsonPath(String),
    ResponseHeaders,
    ResponseBody,
}

impl RuleTarget {
    pub(super) fn log_target(&self) -> &'static str {
        match self {
            RuleTarget::HeaderNames | RuleTarget::HeaderValues(_) => "request_headers",
            RuleTarget::QueryKeys | RuleTarget::QueryValues => "request_query",
            RuleTarget::Cookies => "cookies",
            RuleTarget::UrlPath => "request_path",
            RuleTarget::FullUrl => "request_url",
            RuleTarget::Method => "request_method",
            RuleTarget::BodyText | RuleTarget::BodyJsonPath(_) => "request_body",
            RuleTarget::ResponseHeaders => "response_headers",
            RuleTarget::ResponseBody => "response_body",
        }
    }

    fn is_request_body(&self) -> bool {
        matches!(self, RuleTarget::BodyText | RuleTarget::BodyJsonPath(_))
    }

    fn is_response_body(&self) -> bool {
        matches!(self, RuleTarget::ResponseBody)
    }

    fn is_response_header(&self) -> bool {
        matches!(self, RuleTarget::ResponseHeaders)
    }

    fn is_request_cheap(&self) -> bool {
        !self.is_request_body() && !self.is_response_body() && !self.is_response_header()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Conditions {
    paths: Vec<String>,
    methods: Vec<String>,
    headers: HashMap<String, Option<String>>,
    consumers: Vec<String>,
}

#[derive(Debug)]
struct CompiledConditions {
    path_matchers: Vec<PathMatcher>,
    methods: Vec<String>,
    headers: HashMap<String, Option<String>>,
    consumers: Vec<String>,
}

#[derive(Debug)]
enum PathMatcher {
    Regex(Regex),
    Prefix(String),
    Exact(String),
}

impl PathMatcher {
    fn matches(&self, path: &str) -> bool {
        match self {
            PathMatcher::Regex(re) => re.is_match(path),
            PathMatcher::Prefix(prefix) => path.starts_with(prefix.as_str()),
            PathMatcher::Exact(exact) => path == exact,
        }
    }
}

impl CompiledConditions {
    fn compile(raw: &Conditions) -> Result<Self, String> {
        let path_matchers = raw
            .paths
            .iter()
            .map(|pattern| {
                if let Some(regex) = pattern.strip_prefix('~') {
                    Regex::new(regex)
                        .map(PathMatcher::Regex)
                        .map_err(|e| format!("waf: invalid conditions.paths regex: {e}"))
                } else if let Some(prefix) = pattern.strip_suffix('*') {
                    Ok(PathMatcher::Prefix(prefix.to_string()))
                } else {
                    Ok(PathMatcher::Exact(pattern.clone()))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            path_matchers,
            methods: raw.methods.clone(),
            headers: raw.headers.clone(),
            consumers: raw.consumers.clone(),
        })
    }

    fn matches(&self, ctx: &RequestContext) -> bool {
        if !self.path_matchers.is_empty()
            && !self.path_matchers.iter().any(|m| m.matches(&ctx.path))
        {
            return false;
        }
        if !self.methods.is_empty()
            && !self
                .methods
                .iter()
                .any(|method| method.eq_ignore_ascii_case(&ctx.method))
        {
            return false;
        }
        if !self.consumers.is_empty() {
            let identity = ctx.effective_identity();
            if !self
                .consumers
                .iter()
                .any(|consumer| identity == Some(consumer.as_str()))
            {
                return false;
            }
        }
        for (name, expected) in &self.headers {
            let Some(actual) = ctx.headers.get(name) else {
                return false;
            };
            if let Some(expected) = expected
                && actual != expected
            {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WafRule {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) category: String,
    pub(super) severity: Severity,
    pub(super) target: RuleTarget,
    pub(super) match_kind: MatchKind,
    pub(super) pattern: String,
    pub(super) conditions: Option<Conditions>,
    pub(super) action: RuleAction,
    pub(super) fp_filters: Vec<String>,
    pub(super) paranoia_min: u8,
}

#[derive(Debug)]
pub(super) struct CompiledRule {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) category: String,
    pub(super) severity: Severity,
    pub(super) target: RuleTarget,
    pub(super) action: RuleAction,
    conditions: Option<CompiledConditions>,
    fp_filters: Option<RegexSet>,
    pub(super) cidr: Option<IpCidr>,
}

impl CompiledRule {
    pub(super) fn matches_conditions(&self, ctx: &RequestContext) -> bool {
        self.conditions
            .as_ref()
            .is_none_or(|conditions| conditions.matches(ctx))
    }

    pub(super) fn suppresses_text(&self, value: &str) -> bool {
        self.fp_filters
            .as_ref()
            .is_some_and(|filters| filters.is_match(value))
    }
}

#[derive(Debug, Clone)]
pub(super) struct RuleRef {
    pub(super) rule_index: usize,
    pub(super) target_name: &'static str,
    header_names: Option<Vec<String>>,
}

impl RuleRef {
    pub(super) fn matches_header(&self, header_name: Option<&str>) -> bool {
        match (&self.header_names, header_name) {
            (Some(names), Some(header_name)) => names.iter().any(|name| name == header_name),
            (Some(_), None) => false,
            (None, _) => true,
        }
    }
}

#[derive(Debug)]
pub(super) struct TextRuleSet {
    pub(super) set: RegexSet,
    pub(super) refs: Vec<RuleRef>,
}

#[derive(Debug)]
pub(super) struct BytesRuleSet {
    pub(super) set: BytesRegexSet,
    pub(super) refs: Vec<RuleRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum JsonPathSegment {
    Key(String),
    Index(usize),
}

#[derive(Debug)]
pub(super) enum JsonPathMatcher {
    Regex(Regex),
    Luhn,
    Cidr,
}

#[derive(Debug)]
pub(super) struct JsonPathRule {
    pub rule_index: usize,
    pub target_name: &'static str,
    pub path: Vec<JsonPathSegment>,
    pub matcher: JsonPathMatcher,
}

#[derive(Debug)]
pub(super) struct CompiledRules {
    pub(super) rules: Vec<CompiledRule>,
    pub(super) header_names: Option<TextRuleSet>,
    pub(super) header_values: Option<TextRuleSet>,
    pub(super) query_keys: Option<TextRuleSet>,
    pub(super) query_values: Option<TextRuleSet>,
    pub(super) cookies: Option<TextRuleSet>,
    pub(super) url_path: Option<TextRuleSet>,
    pub(super) full_url: Option<TextRuleSet>,
    pub(super) method: Option<TextRuleSet>,
    pub(super) body_bytes: Option<BytesRuleSet>,
    pub(super) body_json_paths: Vec<JsonPathRule>,
    pub(super) response_headers: Option<TextRuleSet>,
    pub(super) response_body_bytes: Option<BytesRuleSet>,
    pub(super) body_luhn_rules: Vec<usize>,
    pub(super) response_luhn_rules: Vec<usize>,
    pub(super) text_cidr_rules: Vec<usize>,
    pub(super) body_cidr_rules: Vec<usize>,
    pub(super) response_cidr_rules: Vec<usize>,
    pub(super) request_body_rules_active: bool,
    pub(super) request_cheap_rules_active: bool,
    pub(super) response_header_rules_active: bool,
    pub(super) response_body_rules_active: bool,
}

impl CompiledRules {
    pub(super) fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub(super) fn find_rule_index(&self, id: &str) -> Option<usize> {
        self.rules.iter().position(|rule| rule.id == id)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RuleHit {
    pub(super) rule_index: usize,
    pub(super) target_name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub(super) fn parse(raw: &str) -> Option<Self> {
        if let Some((addr, prefix)) = raw.split_once('/') {
            let network: IpAddr = addr.parse().ok()?;
            let prefix: u8 = prefix.parse().ok()?;
            match network {
                IpAddr::V4(_) if prefix <= 32 => Some(Self { network, prefix }),
                IpAddr::V6(_) if prefix <= 128 => Some(Self { network, prefix }),
                _ => None,
            }
        } else {
            let network: IpAddr = raw.parse().ok()?;
            let prefix = match network {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Some(Self { network, prefix })
        }
    }

    pub(super) fn matches(self, addr: IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(network), IpAddr::V4(addr)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) & mask == u32::from(addr) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(addr)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) & mask == u128::from(addr) & mask
            }
            _ => false,
        }
    }
}

pub(super) fn compile_rules(
    mut rules: Vec<(WafRule, bool)>,
    disabled_default_rules: &HashSet<String>,
    rule_modes: &HashMap<String, RuleAction>,
    paranoia_level: u8,
) -> Result<CompiledRules, String> {
    let mut seen = HashSet::new();
    let mut seen_default = HashSet::new();
    let mut compiled_rules = Vec::new();
    let mut builders = RuleSetBuilders::default();

    for (mut rule, is_default) in rules.drain(..) {
        validate_rule(&rule)?;
        if !seen.insert(rule.id.clone()) {
            return Err(format!("waf: duplicate rule id '{}'", rule.id));
        }
        if is_default {
            seen_default.insert(rule.id.clone());
        }
        if rule.paranoia_min > paranoia_level {
            continue;
        }
        if is_default && disabled_default_rules.contains(&rule.id) {
            continue;
        }
        if let Some(action) = rule_modes.get(&rule.id) {
            rule.action = *action;
        }
        if rule.action == RuleAction::Disabled {
            continue;
        }

        let fp_filters = compile_fp_filters(&rule)?;
        let cidr = if rule.match_kind == MatchKind::Cidr {
            Some(IpCidr::parse(&rule.pattern).ok_or_else(|| {
                format!(
                    "waf: rule '{}' has invalid CIDR '{}'",
                    rule.id, rule.pattern
                )
            })?)
        } else {
            None
        };

        let compiled_conditions = rule
            .conditions
            .as_ref()
            .map(CompiledConditions::compile)
            .transpose()
            .map_err(|e| format!("waf: rule '{}': {e}", rule.id))?;

        let rule_index = compiled_rules.len();
        let compiled = CompiledRule {
            id: rule.id.clone(),
            name: rule.name.clone(),
            category: rule.category.clone(),
            severity: rule.severity,
            target: rule.target.clone(),
            action: rule.action,
            conditions: compiled_conditions,
            fp_filters,
            cidr,
        };
        builders.add_rule(rule_index, &rule)?;
        compiled_rules.push(compiled);
    }

    let mut unknown_disabled: Vec<&str> = disabled_default_rules
        .iter()
        .filter(|id| !seen_default.contains(id.as_str()))
        .map(String::as_str)
        .collect();
    if !unknown_disabled.is_empty() {
        unknown_disabled.sort_unstable();
        return Err(format!(
            "waf: 'disabled_default_rules' references unknown default rule id(s): {}",
            unknown_disabled.join(", ")
        ));
    }

    // WAF is security-critical: a typo in an `enforce` override silently leaves
    // the rule monitor-only while construction still succeeds. Fail loudly so
    // unintended-monitor states cannot ship to production.
    let mut unknown: Vec<&str> = rule_modes
        .keys()
        .filter(|id| !seen.contains(id.as_str()))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        unknown.sort_unstable();
        return Err(format!(
            "waf: 'rule_modes' references unknown rule id(s): {}",
            unknown.join(", ")
        ));
    }

    builders.finish(compiled_rules)
}

fn validate_rule(rule: &WafRule) -> Result<(), String> {
    if rule.id.trim().is_empty() {
        return Err("waf: rule id must be non-empty".to_string());
    }
    if rule.category.trim().is_empty() {
        return Err(format!(
            "waf: rule '{}' category must be non-empty",
            rule.id
        ));
    }
    if !(1..=4).contains(&rule.paranoia_min) {
        return Err(format!(
            "waf: rule '{}' paranoia_min must be from 1 to 4",
            rule.id
        ));
    }
    if !matches!(rule.match_kind, MatchKind::Luhn) && rule.pattern.is_empty() {
        return Err(format!(
            "waf: rule '{}' pattern must be non-empty unless match_kind is luhn",
            rule.id
        ));
    }
    if rule.match_kind == MatchKind::Luhn
        && !rule.target.is_request_body()
        && !rule.target.is_response_body()
    {
        return Err(format!(
            "waf: rule '{}' match_kind luhn is only supported for body targets",
            rule.id
        ));
    }
    Ok(())
}

fn compile_fp_filters(rule: &WafRule) -> Result<Option<RegexSet>, String> {
    if rule.fp_filters.is_empty() {
        return Ok(None);
    }
    RegexSet::new(&rule.fp_filters).map(Some).map_err(|e| {
        format!(
            "waf: failed to compile fp_filters for rule '{}': {e}",
            rule.id
        )
    })
}

#[derive(Default)]
struct RuleSetBuilders {
    header_names: PatternBuilder,
    header_values: PatternBuilder,
    query_keys: PatternBuilder,
    query_values: PatternBuilder,
    cookies: PatternBuilder,
    url_path: PatternBuilder,
    full_url: PatternBuilder,
    method: PatternBuilder,
    body_bytes: PatternBuilder,
    body_json_paths: Vec<JsonPathRule>,
    response_headers: PatternBuilder,
    response_body_bytes: PatternBuilder,
    body_luhn_rules: Vec<usize>,
    response_luhn_rules: Vec<usize>,
    text_cidr_rules: Vec<usize>,
    body_cidr_rules: Vec<usize>,
    response_cidr_rules: Vec<usize>,
    request_body_rules_active: bool,
    request_cheap_rules_active: bool,
    response_header_rules_active: bool,
    response_body_rules_active: bool,
}

impl RuleSetBuilders {
    fn add_rule(&mut self, rule_index: usize, rule: &WafRule) -> Result<(), String> {
        self.request_body_rules_active |= rule.target.is_request_body();
        self.request_cheap_rules_active |= rule.target.is_request_cheap();
        self.response_header_rules_active |= rule.target.is_response_header();
        self.response_body_rules_active |= rule.target.is_response_body();

        if let RuleTarget::BodyJsonPath(path) = &rule.target {
            self.body_json_paths
                .push(compile_json_path_rule(rule_index, rule, path)?);
            return Ok(());
        }

        match rule.match_kind {
            MatchKind::Luhn => {
                if rule.target.is_response_body() {
                    self.response_luhn_rules.push(rule_index);
                } else if rule.target.is_request_body() {
                    self.body_luhn_rules.push(rule_index);
                } else {
                    unreachable!("validate_rule rejects luhn match_kind on non-body targets");
                }
                return Ok(());
            }
            MatchKind::Cidr => {
                if rule.target.is_response_body() {
                    self.response_cidr_rules.push(rule_index);
                } else if rule.target.is_request_body() {
                    self.body_cidr_rules.push(rule_index);
                } else {
                    self.text_cidr_rules.push(rule_index);
                }
                return Ok(());
            }
            MatchKind::Regex | MatchKind::Literal | MatchKind::Contains | MatchKind::Equals => {}
        }

        let pattern = rule_pattern(rule);
        let rule_ref = RuleRef {
            rule_index,
            target_name: rule.target.log_target(),
            header_names: match &rule.target {
                RuleTarget::HeaderValues(Some(names)) => {
                    Some(names.iter().map(|name| name.to_ascii_lowercase()).collect())
                }
                _ => None,
            },
        };
        match &rule.target {
            RuleTarget::HeaderNames => self.header_names.push(pattern, rule_ref),
            RuleTarget::HeaderValues(_) => self.header_values.push(pattern, rule_ref),
            RuleTarget::QueryKeys => self.query_keys.push(pattern, rule_ref),
            RuleTarget::QueryValues => self.query_values.push(pattern, rule_ref),
            RuleTarget::Cookies => self.cookies.push(pattern, rule_ref),
            RuleTarget::UrlPath => self.url_path.push(pattern, rule_ref),
            RuleTarget::FullUrl => self.full_url.push(pattern, rule_ref),
            RuleTarget::Method => self.method.push(pattern, rule_ref),
            RuleTarget::BodyText | RuleTarget::BodyJsonPath(_) => {
                self.body_bytes.push(pattern, rule_ref)
            }
            RuleTarget::ResponseHeaders => self.response_headers.push(pattern, rule_ref),
            RuleTarget::ResponseBody => self.response_body_bytes.push(pattern, rule_ref),
        }
        Ok(())
    }

    fn finish(self, rules: Vec<CompiledRule>) -> Result<CompiledRules, String> {
        Ok(CompiledRules {
            rules,
            header_names: self.header_names.finish_text("header_names")?,
            header_values: self.header_values.finish_text("header_values")?,
            query_keys: self.query_keys.finish_text("query_keys")?,
            query_values: self.query_values.finish_text("query_values")?,
            cookies: self.cookies.finish_text("cookies")?,
            url_path: self.url_path.finish_text("url_path")?,
            full_url: self.full_url.finish_text("full_url")?,
            method: self.method.finish_text("method")?,
            body_bytes: self.body_bytes.finish_bytes("body_bytes")?,
            body_json_paths: self.body_json_paths,
            response_headers: self.response_headers.finish_text("response_headers")?,
            response_body_bytes: self
                .response_body_bytes
                .finish_bytes("response_body_bytes")?,
            body_luhn_rules: self.body_luhn_rules,
            response_luhn_rules: self.response_luhn_rules,
            text_cidr_rules: self.text_cidr_rules,
            body_cidr_rules: self.body_cidr_rules,
            response_cidr_rules: self.response_cidr_rules,
            request_body_rules_active: self.request_body_rules_active,
            request_cheap_rules_active: self.request_cheap_rules_active,
            response_header_rules_active: self.response_header_rules_active,
            response_body_rules_active: self.response_body_rules_active,
        })
    }
}

#[derive(Default)]
struct PatternBuilder {
    patterns: Vec<String>,
    refs: Vec<RuleRef>,
}

impl PatternBuilder {
    fn push(&mut self, pattern: String, rule_ref: RuleRef) {
        self.patterns.push(pattern);
        self.refs.push(rule_ref);
    }

    fn finish_text(self, label: &str) -> Result<Option<TextRuleSet>, String> {
        if self.patterns.is_empty() {
            return Ok(None);
        }
        RegexSetBuilder::new(self.patterns)
            .build()
            .map(|set| {
                Some(TextRuleSet {
                    set,
                    refs: self.refs,
                })
            })
            .map_err(|e| format!("waf: failed to build {label} RegexSet: {e}"))
    }

    fn finish_bytes(self, label: &str) -> Result<Option<BytesRuleSet>, String> {
        if self.patterns.is_empty() {
            return Ok(None);
        }
        BytesRegexSet::new(self.patterns)
            .map(|set| {
                Some(BytesRuleSet {
                    set,
                    refs: self.refs,
                })
            })
            .map_err(|e| format!("waf: failed to build {label} bytes RegexSet: {e}"))
    }
}

fn rule_pattern(rule: &WafRule) -> String {
    match rule.match_kind {
        MatchKind::Regex => rule.pattern.clone(),
        MatchKind::Literal | MatchKind::Contains => format!("(?i){}", regex::escape(&rule.pattern)),
        MatchKind::Equals => format!("(?i)^{}$", regex::escape(&rule.pattern)),
        MatchKind::Luhn | MatchKind::Cidr => unreachable!("non-regex rule handled separately"),
    }
}

fn compile_json_path_rule(
    rule_index: usize,
    rule: &WafRule,
    path: &str,
) -> Result<JsonPathRule, String> {
    let path = compile_json_path(path, &rule.id)?;
    let matcher = match rule.match_kind {
        MatchKind::Regex | MatchKind::Literal | MatchKind::Contains | MatchKind::Equals => {
            let pattern = rule_pattern(rule);
            Regex::new(&pattern)
                .map(JsonPathMatcher::Regex)
                .map_err(|e| {
                    format!(
                        "waf: failed to compile body_json_path pattern for rule '{}': {e}",
                        rule.id
                    )
                })?
        }
        MatchKind::Luhn => JsonPathMatcher::Luhn,
        MatchKind::Cidr => JsonPathMatcher::Cidr,
    };
    Ok(JsonPathRule {
        rule_index,
        target_name: rule.target.log_target(),
        path,
        matcher,
    })
}

fn compile_json_path(path: &str, rule_id: &str) -> Result<Vec<JsonPathSegment>, String> {
    let mut segments = Vec::new();
    for segment in path.split('.') {
        if segment.is_empty() {
            return Err(format!(
                "waf: rule '{rule_id}' body_json_path contains an empty segment"
            ));
        }
        if let Ok(index) = segment.parse::<usize>() {
            segments.push(JsonPathSegment::Index(index));
        } else {
            segments.push(JsonPathSegment::Key(segment.to_string()));
        }
    }
    if segments.is_empty() {
        return Err(format!(
            "waf: rule '{rule_id}' body_json_path must not be empty"
        ));
    }
    Ok(segments)
}

pub(super) fn parse_rule_action(raw: &str, field: &str) -> Result<RuleAction, String> {
    match raw {
        "enforce" | "block" | "reject" => Ok(RuleAction::Enforce),
        "monitor" | "log" | "warn" => Ok(RuleAction::Monitor),
        "disabled" | "disable" | "off" => Ok(RuleAction::Disabled),
        other => Err(format!(
            "waf: '{field}' must be one of enforce, monitor, disabled; got {other:?}"
        )),
    }
}

pub(super) fn parse_custom_rule(
    value: &Value,
    default_action: RuleAction,
) -> Result<WafRule, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "waf: custom_rules entries must be objects".to_string())?;
    let id = required_string(object, "id")?;
    let name = optional_string(object, "name")?.unwrap_or_else(|| id.clone());
    let category = required_string(object, "category")?;
    let severity = parse_severity(
        optional_string(object, "severity")?
            .unwrap_or_else(|| "medium".to_string())
            .as_str(),
    )?;
    let target = parse_target(
        object
            .get("target")
            .ok_or_else(|| format!("waf: custom rule '{id}' requires 'target'"))?,
    )?;
    let match_kind = parse_match_kind(
        optional_string(object, "match_kind")?
            .unwrap_or_else(|| "regex".to_string())
            .as_str(),
    )?;
    let pattern = optional_string(object, "pattern")?.unwrap_or_default();
    let action = optional_string(object, "action")?
        .map(|raw| parse_rule_action(&raw, "custom_rules.action"))
        .transpose()?
        .unwrap_or(default_action);
    let fp_filters = optional_string_vec(object, "fp_filters")?.unwrap_or_default();
    let paranoia_min = optional_u8(object, "paranoia_min")?.unwrap_or(1);
    let conditions = object.get("conditions").map(parse_conditions).transpose()?;

    Ok(WafRule {
        id,
        name,
        category,
        severity,
        target,
        match_kind,
        pattern,
        conditions,
        action,
        fp_filters,
        paranoia_min,
    })
}

fn parse_severity(raw: &str) -> Result<Severity, String> {
    match raw {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(format!(
            "waf: severity must be one of info, low, medium, high, critical; got {other:?}"
        )),
    }
}

fn parse_match_kind(raw: &str) -> Result<MatchKind, String> {
    match raw {
        "regex" => Ok(MatchKind::Regex),
        "literal" => Ok(MatchKind::Literal),
        "contains" => Ok(MatchKind::Contains),
        "equals" => Ok(MatchKind::Equals),
        "luhn" => Ok(MatchKind::Luhn),
        "cidr" => Ok(MatchKind::Cidr),
        other => Err(format!(
            "waf: match_kind must be regex, literal, contains, equals, luhn, or cidr; got {other:?}"
        )),
    }
}

fn parse_target(value: &Value) -> Result<RuleTarget, String> {
    if let Some(raw) = value.as_str() {
        return parse_target_string(raw, None, None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| "waf: rule target must be a string or object".to_string())?;
    let raw = required_string(object, "type")?;
    let names = optional_string_vec(object, "names")?;
    let path = optional_string(object, "path")?;
    parse_target_string(&raw, names, path)
}

fn parse_target_string(
    raw: &str,
    names: Option<Vec<String>>,
    path: Option<String>,
) -> Result<RuleTarget, String> {
    if path.is_some() && raw != "body_json_path" {
        return Err(format!(
            "waf: target {raw:?} does not support 'path'; 'path' is only valid for body_json_path"
        ));
    }
    if names.is_some() && !matches!(raw, "header_values" | "request_headers") {
        return Err(format!(
            "waf: target {raw:?} does not support 'names'; 'names' is only valid for header_values/request_headers"
        ));
    }
    match raw {
        "header_names" => Ok(RuleTarget::HeaderNames),
        "header_values" | "request_headers" => {
            if names.as_ref().is_some_and(Vec::is_empty) {
                return Err(
                    "waf: header_values target 'names' must be non-empty when provided".to_string(),
                );
            }
            Ok(RuleTarget::HeaderValues(names))
        }
        "query_keys" => Ok(RuleTarget::QueryKeys),
        "query_values" | "request_query" => Ok(RuleTarget::QueryValues),
        "cookies" => Ok(RuleTarget::Cookies),
        "url_path" | "request_path" => Ok(RuleTarget::UrlPath),
        "full_url" | "request_url" => Ok(RuleTarget::FullUrl),
        "method" | "request_method" => Ok(RuleTarget::Method),
        "body_text" | "request_body" => Ok(RuleTarget::BodyText),
        "body_json_path" => Ok(RuleTarget::BodyJsonPath(path.ok_or_else(|| {
            "waf: body_json_path target requires string 'path'".to_string()
        })?)),
        "response_headers" => Ok(RuleTarget::ResponseHeaders),
        "response_body" => Ok(RuleTarget::ResponseBody),
        other => Err(format!("waf: unknown rule target {other:?}")),
    }
}

fn parse_conditions(value: &Value) -> Result<Conditions, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "waf: conditions must be an object".to_string())?;
    let headers = match object.get("headers") {
        None | Some(Value::Null) => HashMap::new(),
        Some(Value::Object(map)) => {
            let mut parsed = HashMap::new();
            for (key, value) in map {
                let expected = if value.is_null() {
                    None
                } else {
                    Some(value.as_str().ok_or_else(|| {
                        "waf: conditions.headers values must be strings or null".to_string()
                    })?)
                };
                parsed.insert(key.to_ascii_lowercase(), expected.map(str::to_string));
            }
            parsed
        }
        Some(_) => {
            return Err("waf: conditions.headers must be an object".to_string());
        }
    };
    Ok(Conditions {
        paths: optional_string_vec(object, "paths")?.unwrap_or_default(),
        methods: optional_string_vec(object, "methods")?
            .unwrap_or_default()
            .into_iter()
            .map(|method| method.to_ascii_uppercase())
            .collect(),
        headers,
        consumers: optional_string_vec(object, "consumers")?.unwrap_or_default(),
    })
}

fn required_string(object: &serde_json::Map<String, Value>, key: &str) -> Result<String, String> {
    optional_string(object, key)?.ok_or_else(|| format!("waf: missing required string '{key}'"))
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

fn optional_u8(object: &serde_json::Map<String, Value>, key: &str) -> Result<Option<u8>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|v| u8::try_from(v).ok())
            .map(Some)
            .ok_or_else(|| format!("waf: '{key}' must be an integer from 0 to 255")),
        Some(other) => Err(format!("waf: '{key}' must be an integer, got {other}")),
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

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RuleAction::Enforce => "enforce",
            RuleAction::Monitor => "monitor",
            RuleAction::Disabled => "disabled",
        })
    }
}

pub(super) fn extract_ip_tokens(value: &str) -> impl Iterator<Item = IpAddr> + '_ {
    value
        .split(|ch: char| !(ch.is_ascii_hexdigit() || matches!(ch, '.' | ':' | '[' | ']')))
        .filter_map(parse_ip_token)
}

fn parse_ip_token(token: &str) -> Option<IpAddr> {
    let bare_token = token.trim_matches(['[', ']']);
    bare_token
        .parse::<IpAddr>()
        .ok()
        .or_else(|| token.parse::<SocketAddr>().map(|socket| socket.ip()).ok())
        .or_else(|| bare_token.parse::<Ipv4Addr>().map(IpAddr::V4).ok())
        .or_else(|| bare_token.parse::<Ipv6Addr>().map(IpAddr::V6).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matches_ipv4_range() {
        let cidr = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(cidr.matches("10.2.3.4".parse().unwrap()));
        assert!(!cidr.matches("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn extract_ip_tokens_accepts_host_port_forms() {
        let ips: Vec<IpAddr> =
            extract_ip_tokens("10.2.3.4:8443 [2001:db8::1]:443 [2001:db8::2]").collect();

        assert!(ips.contains(&"10.2.3.4".parse().unwrap()));
        assert!(ips.contains(&"2001:db8::1".parse().unwrap()));
        assert!(ips.contains(&"2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn extract_ip_tokens_ignores_common_non_ip_tokens() {
        let ips: Vec<IpAddr> = extract_ip_tokens(
            "sha=0123456789abcdef0123456789abcdef01234567 uuid=550e8400-e29b-41d4-a716-446655440000",
        )
        .collect();

        assert!(ips.is_empty());
    }

    #[test]
    fn extract_ip_tokens_accepts_ipv6_shaped_hex_text() {
        let ips: Vec<IpAddr> =
            extract_ip_tokens("trace=dead:beef:cafe:1234:5678:90ab:cdef:0001").collect();

        assert_eq!(
            ips,
            vec![
                "dead:beef:cafe:1234:5678:90ab:cdef:1"
                    .parse::<IpAddr>()
                    .unwrap()
            ]
        );
    }

    #[test]
    fn equals_rule_is_anchored_and_case_insensitive() {
        let rule = WafRule {
            id: "R1".into(),
            name: "test".into(),
            category: "test".into(),
            severity: Severity::Low,
            target: RuleTarget::Method,
            match_kind: MatchKind::Equals,
            pattern: "propfind".into(),
            conditions: None,
            action: RuleAction::Monitor,
            fp_filters: vec![],
            paranoia_min: 1,
        };
        let compiled = compile_rules(vec![(rule, false)], &HashSet::new(), &HashMap::new(), 1)
            .expect("compile");
        assert!(compiled.method.as_ref().unwrap().set.is_match("PROPFIND"));
        assert!(!compiled.method.as_ref().unwrap().set.is_match("XPROPFIND"));
    }

    #[test]
    fn unknown_rule_modes_id_is_rejected() {
        let rule = WafRule {
            id: "R1".into(),
            name: "test".into(),
            category: "test".into(),
            severity: Severity::Low,
            target: RuleTarget::Method,
            match_kind: MatchKind::Equals,
            pattern: "propfind".into(),
            conditions: None,
            action: RuleAction::Monitor,
            fp_filters: vec![],
            paranoia_min: 1,
        };
        let mut modes = HashMap::new();
        modes.insert("R-TYPO".to_string(), RuleAction::Enforce);
        modes.insert("ALSO-WRONG".to_string(), RuleAction::Enforce);
        modes.insert("R1".to_string(), RuleAction::Enforce);
        let err = compile_rules(vec![(rule, false)], &HashSet::new(), &modes, 1).unwrap_err();
        assert!(err.contains("unknown rule id"));
        assert!(err.contains("R-TYPO"));
        assert!(err.contains("ALSO-WRONG"));
        // Known IDs should not appear in the error list.
        assert!(!err.contains("R1"));
    }

    #[test]
    fn known_rule_modes_id_filtered_by_paranoia_still_accepted() {
        let rule = WafRule {
            id: "R1".into(),
            name: "test".into(),
            category: "test".into(),
            severity: Severity::Low,
            target: RuleTarget::Method,
            match_kind: MatchKind::Equals,
            pattern: "propfind".into(),
            conditions: None,
            action: RuleAction::Monitor,
            fp_filters: vec![],
            paranoia_min: 4,
        };
        let mut modes = HashMap::new();
        modes.insert("R1".to_string(), RuleAction::Enforce);
        // R1 is filtered out by paranoia_level=1 but is still a known ID, so
        // the override is a no-op rather than an error.
        compile_rules(vec![(rule, false)], &HashSet::new(), &modes, 1).expect("compile");
    }
}
