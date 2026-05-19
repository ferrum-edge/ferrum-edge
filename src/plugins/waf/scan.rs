use std::collections::HashMap;
use std::net::IpAddr;

use super::decode;
use super::rules::{
    BytesRuleSet, JsonPathMatcher, JsonPathRule, JsonPathSegment, RuleHit, RuleRef, TextRuleSet,
    extract_ip_tokens,
};
use super::{WAF_INTERNAL_EXEMPT_KEY, Waf};
use crate::plugins::RequestContext;

#[derive(Debug, Default)]
pub(super) struct ScanOutcome {
    pub hits: Vec<RuleHit>,
    pub truncated: bool,
    pub timed_out: bool,
}

impl ScanOutcome {
    pub fn push(&mut self, hit: RuleHit) {
        if !self
            .hits
            .iter()
            .any(|existing| existing.rule_index == hit.rule_index)
        {
            self.hits.push(hit);
        }
    }
}

impl Waf {
    pub(super) fn run_cheap_scan(&self, ctx: &mut RequestContext) -> ScanOutcome {
        let mut outcome = ScanOutcome::default();
        let raw_query = ctx.raw_query_string().map(str::to_string);

        self.scan_text_set(
            &mut outcome,
            self.compiled.url_path.as_ref(),
            &ctx.path,
            ctx,
            None,
        );

        if let Some(raw_query) = raw_query.as_deref() {
            if !raw_query.is_empty() {
                let mut full_url = String::with_capacity(ctx.path.len() + raw_query.len() + 1);
                full_url.push_str(&ctx.path);
                full_url.push('?');
                full_url.push_str(raw_query);
                self.scan_text_set(
                    &mut outcome,
                    self.compiled.full_url.as_ref(),
                    &full_url,
                    ctx,
                    None,
                );
                self.scan_encoding_specials(&mut outcome, &full_url, ctx);
                self.scan_hpp_special(&mut outcome, raw_query, ctx);
            }
        } else {
            self.scan_text_set(
                &mut outcome,
                self.compiled.full_url.as_ref(),
                &ctx.path,
                ctx,
                None,
            );
            self.scan_encoding_specials(&mut outcome, &ctx.path, ctx);
        }

        ctx.materialize_query_params();
        for (key, value) in &ctx.query_params {
            self.scan_text_set(
                &mut outcome,
                self.compiled.query_keys.as_ref(),
                key,
                ctx,
                None,
            );
            self.scan_text_set(
                &mut outcome,
                self.compiled.query_values.as_ref(),
                value,
                ctx,
                None,
            );
            self.scan_cidr_rules(&mut outcome, value, &self.compiled.text_cidr_rules, ctx);
        }

        for (name, value) in &ctx.headers {
            self.scan_text_set(
                &mut outcome,
                self.compiled.header_names.as_ref(),
                name,
                ctx,
                Some(name.as_str()),
            );
            self.scan_text_set(
                &mut outcome,
                self.compiled.header_values.as_ref(),
                value,
                ctx,
                Some(name.as_str()),
            );
            if name == "cookie" {
                self.scan_cookies(&mut outcome, value, ctx);
            }
        }

        self.scan_text_set(
            &mut outcome,
            self.compiled.method.as_ref(),
            &ctx.method,
            ctx,
            None,
        );
        self.scan_method_special(&mut outcome, &ctx.method, ctx);
        self.scan_method_override_special(&mut outcome, &ctx.headers, ctx);

        outcome
    }

    pub(super) fn run_request_body_scan(
        &self,
        ctx: &mut RequestContext,
        _headers: &HashMap<String, String>,
        body: &[u8],
    ) -> ScanOutcome {
        let mut outcome = ScanOutcome::default();
        self.scan_bytes_set(&mut outcome, self.compiled.body_bytes.as_ref(), body, ctx);
        self.scan_json_path_rules(&mut outcome, body, ctx);
        if let Ok(text) = std::str::from_utf8(body) {
            self.scan_luhn_rules(&mut outcome, text, &self.compiled.body_luhn_rules, ctx);
            self.scan_cidr_rules(&mut outcome, text, &self.compiled.body_cidr_rules, ctx);
        }
        outcome
    }

    pub(super) fn run_response_header_scan(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
    ) -> ScanOutcome {
        let mut outcome = ScanOutcome::default();
        if let Some(set) = self.compiled.response_headers.as_ref() {
            for (name, value) in headers {
                let mut line = String::with_capacity(name.len() + value.len() + 2);
                line.push_str(name);
                line.push_str(": ");
                line.push_str(value);
                self.scan_text_set(&mut outcome, Some(set), &line, ctx, Some(name.as_str()));
            }
        }
        outcome
    }

    pub(super) fn run_response_body_scan(
        &self,
        ctx: &mut RequestContext,
        _headers: &HashMap<String, String>,
        body: &[u8],
    ) -> ScanOutcome {
        let mut outcome = ScanOutcome::default();
        self.scan_bytes_set(
            &mut outcome,
            self.compiled.response_body_bytes.as_ref(),
            body,
            ctx,
        );
        if let Ok(text) = std::str::from_utf8(body) {
            self.scan_luhn_rules(&mut outcome, text, &self.compiled.response_luhn_rules, ctx);
            self.scan_cidr_rules(&mut outcome, text, &self.compiled.response_cidr_rules, ctx);
        }
        outcome
    }

    fn scan_text_set(
        &self,
        outcome: &mut ScanOutcome,
        set: Option<&TextRuleSet>,
        value: &str,
        ctx: &RequestContext,
        header_name: Option<&str>,
    ) {
        let Some(set) = set else {
            return;
        };
        for index in set.set.matches(value) {
            self.push_if_allowed(outcome, &set.refs[index], value, ctx, header_name);
        }
    }

    fn scan_bytes_set(
        &self,
        outcome: &mut ScanOutcome,
        set: Option<&BytesRuleSet>,
        value: &[u8],
        ctx: &RequestContext,
    ) {
        let Some(set) = set else {
            return;
        };
        for index in set.set.matches(value) {
            let rule_ref = &set.refs[index];
            if let Ok(text) = std::str::from_utf8(value) {
                self.push_if_allowed(outcome, rule_ref, text, ctx, None);
            } else {
                self.push_if_allowed_bytes(outcome, rule_ref, ctx);
            }
        }
    }

    fn scan_json_path_rules(&self, outcome: &mut ScanOutcome, body: &[u8], ctx: &RequestContext) {
        if self.compiled.body_json_paths.is_empty() {
            return;
        }
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
            return;
        };
        for path_rule in &self.compiled.body_json_paths {
            let Some(value) = json_path_value(&json, &path_rule.path) else {
                continue;
            };
            let mut scratch = None;
            let Some(text) = json_scan_text(value, &mut scratch) else {
                continue;
            };
            if self.json_path_rule_matches(path_rule, text, ctx) {
                outcome.push(RuleHit {
                    rule_index: path_rule.rule_index,
                    target_name: path_rule.target_name,
                });
            }
        }
    }

    fn json_path_rule_matches(
        &self,
        path_rule: &JsonPathRule,
        value: &str,
        ctx: &RequestContext,
    ) -> bool {
        let rule = &self.compiled.rules[path_rule.rule_index];
        let matched = match &path_rule.matcher {
            JsonPathMatcher::Regex(regex) => regex.is_match(value),
            JsonPathMatcher::Luhn => contains_luhn_candidate(value),
            JsonPathMatcher::Cidr => rule
                .cidr
                .is_some_and(|cidr| extract_ip_tokens(value).any(|ip| cidr.matches(ip))),
        };
        matched
            && rule.matches_conditions(ctx)
            && !self.exemptions.suppresses_rule_for_request(ctx)
            && !self.exemptions.suppresses_value(value)
            && !rule.suppresses_text(value)
    }

    fn scan_cookies(&self, outcome: &mut ScanOutcome, header: &str, ctx: &RequestContext) {
        for cookie in header.split(';') {
            let cookie = cookie.trim();
            if !cookie.is_empty() {
                self.scan_text_set(outcome, self.compiled.cookies.as_ref(), cookie, ctx, None);
            }
        }
    }

    fn scan_luhn_rules(
        &self,
        outcome: &mut ScanOutcome,
        value: &str,
        rule_indices: &[usize],
        ctx: &RequestContext,
    ) {
        if rule_indices.is_empty() || !contains_luhn_candidate(value) {
            return;
        }
        for &rule_index in rule_indices {
            let rule = &self.compiled.rules[rule_index];
            if rule.matches_conditions(ctx)
                && !self.exemptions.suppresses_rule_for_request(ctx)
                && !self.exemptions.suppresses_value(value)
                && !rule.suppresses_text(value)
            {
                outcome.push(RuleHit {
                    rule_index,
                    target_name: rule.target.log_target(),
                });
            }
        }
    }

    fn scan_cidr_rules(
        &self,
        outcome: &mut ScanOutcome,
        value: &str,
        rule_indices: &[usize],
        ctx: &RequestContext,
    ) {
        if rule_indices.is_empty() {
            return;
        }
        let ips: Vec<IpAddr> = extract_ip_tokens(value).collect();
        if ips.is_empty() {
            return;
        }
        for &rule_index in rule_indices {
            let rule = &self.compiled.rules[rule_index];
            let Some(cidr) = rule.cidr else {
                continue;
            };
            if ips.iter().any(|ip| cidr.matches(*ip))
                && rule.matches_conditions(ctx)
                && !self.exemptions.suppresses_rule_for_request(ctx)
            {
                outcome.push(RuleHit {
                    rule_index,
                    target_name: rule.target.log_target(),
                });
            }
        }
    }

    fn scan_encoding_specials(&self, outcome: &mut ScanOutcome, value: &str, ctx: &RequestContext) {
        if (decode::has_double_encoded_marker(value)
            || decode::has_percent_null_byte(value)
            || decode::has_overlong_utf8_marker(value))
            && let Some(rule_index) = self.special_rule("FE-ENCODING-001")
        {
            self.push_special(outcome, rule_index, ctx);
        }
    }

    fn scan_hpp_special(&self, outcome: &mut ScanOutcome, raw_query: &str, ctx: &RequestContext) {
        if decode::has_conflicting_duplicate_query_key(raw_query)
            && let Some(rule_index) = self.special_rule("FE-HPP-001")
        {
            self.push_special(outcome, rule_index, ctx);
        }
    }

    fn scan_method_special(&self, outcome: &mut ScanOutcome, method: &str, ctx: &RequestContext) {
        if self
            .config
            .disallowed_methods
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(method))
            && let Some(rule_index) = self.special_rule("FE-METHOD-001")
        {
            self.push_special(outcome, rule_index, ctx);
        }
    }

    fn scan_method_override_special(
        &self,
        outcome: &mut ScanOutcome,
        headers: &HashMap<String, String>,
        ctx: &RequestContext,
    ) {
        if let Some((_, override_method)) = headers
            .iter()
            .find(|(name, _)| name.as_str() == "x-http-method-override")
            && !override_method.eq_ignore_ascii_case(&ctx.method)
            && let Some(rule_index) = self.special_rule("FE-HEADER-002")
        {
            self.push_special(outcome, rule_index, ctx);
        }
    }

    fn push_special(&self, outcome: &mut ScanOutcome, rule_index: usize, ctx: &RequestContext) {
        let rule = &self.compiled.rules[rule_index];
        if rule.matches_conditions(ctx) && !self.exemptions.suppresses_rule_for_request(ctx) {
            outcome.push(RuleHit {
                rule_index,
                target_name: rule.target.log_target(),
            });
        }
    }

    fn push_if_allowed(
        &self,
        outcome: &mut ScanOutcome,
        rule_ref: &RuleRef,
        value: &str,
        ctx: &RequestContext,
        header_name: Option<&str>,
    ) {
        if ctx.metadata.contains_key(WAF_INTERNAL_EXEMPT_KEY) {
            return;
        }
        let rule = &self.compiled.rules[rule_ref.rule_index];
        if rule_ref.matches_header(header_name)
            && rule.matches_conditions(ctx)
            && !self.exemptions.suppresses_rule_for_request(ctx)
            && !self.exemptions.suppresses_value(value)
            && !rule.suppresses_text(value)
        {
            outcome.push(RuleHit {
                rule_index: rule_ref.rule_index,
                target_name: rule_ref.target_name,
            });
        }
    }

    fn push_if_allowed_bytes(
        &self,
        outcome: &mut ScanOutcome,
        rule_ref: &RuleRef,
        ctx: &RequestContext,
    ) {
        if ctx.metadata.contains_key(WAF_INTERNAL_EXEMPT_KEY) {
            return;
        }
        let rule = &self.compiled.rules[rule_ref.rule_index];
        if rule.matches_conditions(ctx) && !self.exemptions.suppresses_rule_for_request(ctx) {
            outcome.push(RuleHit {
                rule_index: rule_ref.rule_index,
                target_name: rule_ref.target_name,
            });
        }
    }
}

fn json_path_value<'a>(
    value: &'a serde_json::Value,
    path: &[JsonPathSegment],
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path {
        match segment {
            JsonPathSegment::Key(key) => {
                current = current.get(key)?;
            }
            JsonPathSegment::Index(index) => {
                current = current.get(*index)?;
            }
        }
    }
    Some(current)
}

fn json_scan_text<'a>(
    value: &'a serde_json::Value,
    scratch: &'a mut Option<String>,
) -> Option<&'a str> {
    match value {
        serde_json::Value::String(value) => Some(value.as_str()),
        serde_json::Value::Number(value) => {
            *scratch = Some(value.to_string());
            scratch.as_deref()
        }
        serde_json::Value::Bool(value) => Some(if *value { "true" } else { "false" }),
        serde_json::Value::Null => Some("null"),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            *scratch = Some(value.to_string());
            scratch.as_deref()
        }
    }
}

fn contains_luhn_candidate(value: &str) -> bool {
    let mut digits = Vec::with_capacity(19);
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch as u8 - b'0');
            if digits.len() > 19 {
                digits.clear();
            }
        } else if matches!(ch, ' ' | '-' | '.') {
            continue;
        } else {
            if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
                return true;
            }
            digits.clear();
        }
    }
    (13..=19).contains(&digits.len()) && luhn_valid(&digits)
}

fn luhn_valid(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for digit in digits.iter().rev() {
        let mut value = u32::from(*digit);
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_detects_valid_card_candidate() {
        assert!(contains_luhn_candidate("card 4111 1111 1111 1111 leaked"));
        assert!(!contains_luhn_candidate("card 4111 1111 1111 1112 leaked"));
    }
}
