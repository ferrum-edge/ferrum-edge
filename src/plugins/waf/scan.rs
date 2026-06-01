use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;

use percent_encoding::percent_decode_str;

use super::Waf;
use super::decode;
use super::normalize;
use super::rules::{
    BytesRuleSet, JsonPathMatcher, JsonPathRule, JsonPathSegment, RuleHit, RuleRef, RuleTarget,
    TextRuleSet, extract_ip_tokens,
};
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
        let raw_query = ctx.raw_query_string();

        self.scan_text_set(
            &mut outcome,
            self.compiled.url_path.as_ref(),
            &ctx.path,
            ctx,
            None,
        );
        self.scan_cidr_rules_matching(
            &mut outcome,
            &ctx.path,
            &self.compiled.text_cidr_rules,
            ctx,
            |target| matches!(target, RuleTarget::UrlPath),
        );

        if let Some(raw_query) = raw_query {
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
                self.scan_cidr_rules_matching(
                    &mut outcome,
                    &full_url,
                    &self.compiled.text_cidr_rules,
                    ctx,
                    |target| matches!(target, RuleTarget::FullUrl),
                );
                self.scan_encoding_specials(&mut outcome, &full_url, ctx);
                self.scan_hpp_special(&mut outcome, raw_query, ctx);
            }
        } else if !ctx.query_params.is_empty() {
            let mut full_url = String::with_capacity(
                ctx.path.len()
                    + 1
                    + ctx
                        .query_params
                        .iter()
                        .map(|(key, value)| key.len() + value.len() + 2)
                        .sum::<usize>(),
            );
            full_url.push_str(&ctx.path);
            append_materialized_query(&mut full_url, &ctx.query_params);
            self.scan_text_set(
                &mut outcome,
                self.compiled.full_url.as_ref(),
                &full_url,
                ctx,
                None,
            );
            self.scan_cidr_rules_matching(
                &mut outcome,
                &full_url,
                &self.compiled.text_cidr_rules,
                ctx,
                |target| matches!(target, RuleTarget::FullUrl),
            );
            self.scan_encoding_specials(&mut outcome, &full_url, ctx);
        } else {
            self.scan_text_set(
                &mut outcome,
                self.compiled.full_url.as_ref(),
                &ctx.path,
                ctx,
                None,
            );
            self.scan_cidr_rules_matching(
                &mut outcome,
                &ctx.path,
                &self.compiled.text_cidr_rules,
                ctx,
                |target| matches!(target, RuleTarget::FullUrl),
            );
            self.scan_encoding_specials(&mut outcome, &ctx.path, ctx);
        }

        // Scan each raw query pair even after query-param materialization so
        // duplicate-key payloads (HTTP Parameter Pollution) cannot smuggle a
        // value past `query_keys`/`query_values` rules. The parsed HashMap
        // still collapses `?q=<script>&q=ok` to `q=ok`, so relying on the
        // monitor-only HPP rule alone would miss enforced query-value rules.
        if let Some(raw) = raw_query {
            for pair in raw.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (raw_k, raw_v) = pair.split_once('=').unwrap_or((pair, ""));
                let key = decode_query_component_for_waf(raw_k);
                let value = decode_query_component_for_waf(raw_v);
                self.scan_query_pair(&mut outcome, &key, &value, ctx);
            }
        } else {
            for (key, value) in &ctx.query_params {
                self.scan_query_pair(&mut outcome, key, value, ctx);
            }
        }

        for (name, value) in &ctx.headers {
            self.scan_text_set(
                &mut outcome,
                self.compiled.header_names.as_ref(),
                name,
                ctx,
                Some(name.as_str()),
            );
            self.scan_cidr_rules_matching(
                &mut outcome,
                name,
                &self.compiled.text_cidr_rules,
                ctx,
                |target| matches!(target, RuleTarget::HeaderNames),
            );
            self.scan_text_set(
                &mut outcome,
                self.compiled.header_values.as_ref(),
                value,
                ctx,
                Some(name.as_str()),
            );
            self.scan_cidr_rules_matching(
                &mut outcome,
                value,
                &self.compiled.text_cidr_rules,
                ctx,
                |target| header_value_target_matches(target, name),
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
        self.scan_cidr_rules_matching(
            &mut outcome,
            &ctx.method,
            &self.compiled.text_cidr_rules,
            ctx,
            |target| matches!(target, RuleTarget::Method),
        );
        self.scan_method_special(&mut outcome, &ctx.method, ctx);
        self.scan_method_override_special(&mut outcome, &ctx.headers, ctx);

        outcome
    }

    pub(super) fn run_request_body_scan(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
    ) -> ScanOutcome {
        let mut outcome = ScanOutcome::default();
        self.scan_bytes_set(&mut outcome, self.compiled.body_bytes.as_ref(), body, ctx);
        self.scan_json_path_rules(&mut outcome, body, ctx);
        let text = String::from_utf8_lossy(body);
        // Re-scan decoded forms so payloads hidden behind JSON `\uXXXX`,
        // HTML entities, or percent-encoding cannot evade the raw-byte set.
        // Lossy UTF-8 keeps one hostile byte from disabling text decoding for
        // the rest of an otherwise inspectable body. The same pass reports
        // whether an encoding stacked deeper than the decode cap remains.
        let (variants, residual_encoding) =
            normalize::decoded_variants_with_residual(text.as_ref());
        // Flag overlong-UTF8 / double-encoding / null-byte markers and the
        // beyond-cap residual in the body, mirroring the URL-side FE-ENCODING
        // check (markers `percent_decode_plus` cannot recover, and stacks the
        // layered decode cannot fully peel, are otherwise silent).
        self.scan_body_encoding_specials(&mut outcome, text.as_ref(), residual_encoding, ctx);
        for variant in variants {
            self.scan_json_path_rules(&mut outcome, variant.as_bytes(), ctx);
            self.scan_bytes_set(
                &mut outcome,
                self.compiled.body_bytes.as_ref(),
                variant.as_bytes(),
                ctx,
            );
            self.scan_luhn_rules(&mut outcome, &variant, &self.compiled.body_luhn_rules, ctx);
            self.scan_cidr_rules(&mut outcome, &variant, &self.compiled.body_cidr_rules, ctx);
        }
        self.scan_luhn_rules(
            &mut outcome,
            text.as_ref(),
            &self.compiled.body_luhn_rules,
            ctx,
        );
        self.scan_cidr_rules(
            &mut outcome,
            text.as_ref(),
            &self.compiled.body_cidr_rules,
            ctx,
        );
        outcome
    }

    pub(super) fn run_response_header_scan(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
    ) -> ScanOutcome {
        let mut outcome = ScanOutcome::default();
        for (name, value) in headers {
            let mut line = String::with_capacity(name.len() + value.len() + 2);
            line.push_str(name);
            line.push_str(": ");
            line.push_str(value);
            self.scan_text_set(
                &mut outcome,
                self.compiled.response_headers.as_ref(),
                &line,
                ctx,
                Some(name.as_str()),
            );
            self.scan_cidr_rules_matching(
                &mut outcome,
                &line,
                &self.compiled.text_cidr_rules,
                ctx,
                |target| matches!(target, RuleTarget::ResponseHeaders),
            );
        }
        outcome
    }

    pub(super) fn run_response_body_scan(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
    ) -> ScanOutcome {
        let mut outcome = ScanOutcome::default();
        self.scan_bytes_set(
            &mut outcome,
            self.compiled.response_body_bytes.as_ref(),
            body,
            ctx,
        );
        let text = String::from_utf8_lossy(body);
        let (variants, residual_encoding) =
            normalize::decoded_variants_with_residual(text.as_ref());
        self.scan_body_encoding_specials(&mut outcome, text.as_ref(), residual_encoding, ctx);
        for variant in variants {
            self.scan_bytes_set(
                &mut outcome,
                self.compiled.response_body_bytes.as_ref(),
                variant.as_bytes(),
                ctx,
            );
            self.scan_luhn_rules(
                &mut outcome,
                &variant,
                &self.compiled.response_luhn_rules,
                ctx,
            );
            self.scan_cidr_rules(
                &mut outcome,
                &variant,
                &self.compiled.response_cidr_rules,
                ctx,
            );
        }
        self.scan_luhn_rules(
            &mut outcome,
            text.as_ref(),
            &self.compiled.response_luhn_rules,
            ctx,
        );
        self.scan_cidr_rules(
            &mut outcome,
            text.as_ref(),
            &self.compiled.response_cidr_rules,
            ctx,
        );
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
                self.scan_cidr_rules_matching(
                    outcome,
                    cookie,
                    &self.compiled.text_cidr_rules,
                    ctx,
                    |target| matches!(target, RuleTarget::Cookies),
                );
            }
        }
    }

    fn scan_query_pair(
        &self,
        outcome: &mut ScanOutcome,
        key: &str,
        value: &str,
        ctx: &RequestContext,
    ) {
        self.scan_text_set(outcome, self.compiled.query_keys.as_ref(), key, ctx, None);
        self.scan_text_set(
            outcome,
            self.compiled.query_values.as_ref(),
            value,
            ctx,
            None,
        );
        self.scan_cidr_rules_matching(
            outcome,
            key,
            &self.compiled.text_cidr_rules,
            ctx,
            |target| matches!(target, RuleTarget::QueryKeys),
        );
        self.scan_cidr_rules_matching(
            outcome,
            value,
            &self.compiled.text_cidr_rules,
            ctx,
            |target| matches!(target, RuleTarget::QueryValues),
        );
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
        self.scan_cidr_rules_matching(outcome, value, rule_indices, ctx, |_| true);
    }

    fn scan_cidr_rules_matching<F>(
        &self,
        outcome: &mut ScanOutcome,
        value: &str,
        rule_indices: &[usize],
        ctx: &RequestContext,
        target_matches: F,
    ) where
        F: Fn(&RuleTarget) -> bool,
    {
        if rule_indices.is_empty() {
            return;
        }
        let mut ips: Option<Vec<IpAddr>> = None;
        for &rule_index in rule_indices {
            let rule = &self.compiled.rules[rule_index];
            let Some(cidr) = rule.cidr else {
                continue;
            };
            if !target_matches(&rule.target) {
                continue;
            }
            let ips = ips.get_or_insert_with(|| extract_ip_tokens(value).collect());
            if ips.is_empty() {
                return;
            }
            if ips.iter().any(|ip| cidr.matches(*ip))
                && rule.matches_conditions(ctx)
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

    fn scan_encoding_specials(&self, outcome: &mut ScanOutcome, value: &str, ctx: &RequestContext) {
        if let Some(rule_index) = self.specials.encoding
            && (decode::has_double_encoded_marker(value)
                || decode::has_percent_null_byte(value)
                || decode::has_overlong_utf8_marker(value))
        {
            self.push_special(outcome, rule_index, value, ctx);
        }
        if let Some(rule_index) = self.specials.overlong_utf8
            && decode::has_overlong_utf8_marker(value)
        {
            self.push_special(outcome, rule_index, value, ctx);
        }
    }

    /// Body-scoped counterpart to `scan_encoding_specials`. The FE-ENCODING
    /// special only inspects the URL/path, but the same evasions appear in
    /// bodies: overlong-UTF8 / double-encoding / null-byte markers that
    /// `percent_decode_plus` cannot losslessly recover (it collapses invalid
    /// UTF-8 to U+FFFD), and encodings stacked deeper than the layered-decode
    /// round cap so the decoded payload never reaches the body regex set. Flag
    /// both against the raw body text so they are surfaced through the same
    /// rules as URL-side checks rather than silently forwarded. FE-ENCODING-001
    /// remains the compatibility enforcement path for all encoding evasions;
    /// overlong UTF-8 also raises FE-ENCODING-002 so its dedicated per-rule modes
    /// and overrides remain effective.
    ///
    /// `residual_encoding` is the beyond-cap signal reported by
    /// `decoded_variants_with_residual`, threaded in so the layered decode runs
    /// once for both the variant set and this check.
    fn scan_body_encoding_specials(
        &self,
        outcome: &mut ScanOutcome,
        text: &str,
        residual_encoding: bool,
        ctx: &RequestContext,
    ) {
        let percent_markers_present = text.as_bytes().contains(&b'%');
        if let Some(rule_index) = self.specials.encoding {
            let flagged = residual_encoding
                || (percent_markers_present
                    && (decode::has_double_encoded_marker(text)
                        || decode::has_percent_null_byte(text)
                        || decode::has_overlong_utf8_marker(text)));
            if flagged {
                self.push_special(outcome, rule_index, text, ctx);
            }
        }
        // The marker helpers all look for `%`-prefixed sequences, so skip their
        // (up to MiB-sized) byte scans entirely when the body contains no `%`.
        if percent_markers_present
            && let Some(rule_index) = self.specials.overlong_utf8
            && decode::has_overlong_utf8_marker(text)
        {
            self.push_special(outcome, rule_index, text, ctx);
        }
    }

    fn scan_hpp_special(&self, outcome: &mut ScanOutcome, raw_query: &str, ctx: &RequestContext) {
        if let Some(rule_index) = self.specials.hpp
            && decode::has_conflicting_duplicate_query_key(raw_query)
        {
            self.push_special(outcome, rule_index, raw_query, ctx);
        }
    }

    fn scan_method_special(&self, outcome: &mut ScanOutcome, method: &str, ctx: &RequestContext) {
        if let Some(rule_index) = self.specials.method
            && self
                .config
                .disallowed_methods
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(method))
        {
            self.push_special(outcome, rule_index, method, ctx);
        }
    }

    fn scan_method_override_special(
        &self,
        outcome: &mut ScanOutcome,
        headers: &HashMap<String, String>,
        ctx: &RequestContext,
    ) {
        if let Some(rule_index) = self.specials.method_override
            && let Some(override_method) = headers.get("x-http-method-override")
            && !override_method.eq_ignore_ascii_case(&ctx.method)
        {
            self.push_special(outcome, rule_index, override_method, ctx);
        }
    }

    fn push_special(
        &self,
        outcome: &mut ScanOutcome,
        rule_index: usize,
        value: &str,
        ctx: &RequestContext,
    ) {
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

    fn push_if_allowed(
        &self,
        outcome: &mut ScanOutcome,
        rule_ref: &RuleRef,
        value: &str,
        ctx: &RequestContext,
        header_name: Option<&str>,
    ) {
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
        let rule = &self.compiled.rules[rule_ref.rule_index];
        if rule.matches_conditions(ctx) && !self.exemptions.suppresses_rule_for_request(ctx) {
            outcome.push(RuleHit {
                rule_index: rule_ref.rule_index,
                target_name: rule_ref.target_name,
            });
        }
    }
}

fn decode_query_component_for_waf(raw: &str) -> Cow<'_, str> {
    let decoded = percent_decode_str(raw).decode_utf8_lossy();
    if decoded.contains('+') {
        Cow::Owned(decoded.replace('+', " "))
    } else {
        decoded
    }
}

fn header_value_target_matches(target: &RuleTarget, header_name: &str) -> bool {
    match target {
        RuleTarget::HeaderValues(None) => true,
        RuleTarget::HeaderValues(Some(names)) => names
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(header_name)),
        _ => false,
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

const MAX_LUHN_DIGIT_RUN_SCAN: usize = 4096;

fn contains_luhn_candidate(value: &str) -> bool {
    // Maintain a sliding window of the most recent ≤19 digits. The previous
    // implementation cleared the buffer entirely on overflow, which lets an
    // attacker pad a real card number with extra digits and evade response-
    // body leak detection. The behavior below splits into two regimes:
    //
    // * Natural-length runs (the digit run is itself between 13 and 19
    //   digits and never overflows): check Luhn at the run's exact length.
    //   This preserves the original semantics — a 16-digit run with an
    //   invalid checksum still does not falsely match on some 13-digit
    //   substring that happens to checksum.
    // * Overflow runs (longer than 19 digits): the natural-length check
    //   alone cannot see card-length substrings, so before sliding the
    //   window and again at the run's terminating boundary we check every
    //   valid card length (13..=19) anchored at the window's start and
    //   end, catching cards padded on either side.
    let mut digits: Vec<u8> = Vec::with_capacity(19);
    let mut overflowed_run = false;
    let mut run_digits_seen = 0usize;
    let mut run_scan_suppressed = false;
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            run_digits_seen += 1;
            if run_digits_seen > MAX_LUHN_DIGIT_RUN_SCAN {
                if !run_scan_suppressed && check_run(&digits, overflowed_run) {
                    return true;
                }
                run_scan_suppressed = true;
                continue;
            }
            digits.push(ch as u8 - b'0');
            if digits.len() > 19 {
                if check_card_substrings(&digits[..19]) {
                    return true;
                }
                digits.remove(0);
                overflowed_run = true;
            }
        } else if matches!(ch, ' ' | '-' | '.') {
            continue;
        } else {
            if !run_scan_suppressed && check_run(&digits, overflowed_run) {
                return true;
            }
            digits.clear();
            overflowed_run = false;
            run_digits_seen = 0;
            run_scan_suppressed = false;
        }
    }
    !run_scan_suppressed && check_run(&digits, overflowed_run)
}

fn check_run(digits: &[u8], overflowed: bool) -> bool {
    if overflowed {
        check_card_substrings(digits)
    } else {
        (13..=19).contains(&digits.len()) && luhn_valid(digits)
    }
}

fn check_card_substrings(digits: &[u8]) -> bool {
    if digits.len() < 13 {
        return false;
    }
    let max_len = digits.len().min(19);
    // Check every valid card length anchored at the window's start and end.
    // Combined with the per-digit slide in `contains_luhn_candidate`, this
    // covers each 13..=19 length substring of any long digit run without
    // running luhn_valid over the full N×N substring space.
    for len in 13..=max_len {
        if luhn_valid(&digits[..len]) {
            return true;
        }
        if len < digits.len() && luhn_valid(&digits[digits.len() - len..]) {
            return true;
        }
    }
    false
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

fn append_materialized_query(
    full_url: &mut String,
    query_params: &std::collections::HashMap<String, String>,
) {
    // `query_params` is a `HashMap` with `RandomState`, so its iteration order
    // is non-deterministic across processes. Sort by (key, value) before
    // appending so `full_url`-target rules whose patterns depend on parameter
    // ordering/adjacency produce stable enforce/monitor verdicts regardless of
    // map layout. This is the synthetic-context fallback (raw query absent but
    // parsed params present); the live proxy path uses the verbatim raw query
    // and never reaches here, so the sort's allocation is off the common hot
    // path. HTTP Parameter Pollution is intentionally not detected here: the
    // collapsed map cannot represent duplicate keys, so there is nothing to
    // compare — the raw-query branch owns HPP detection.
    let mut pairs: Vec<(&String, &String)> = query_params.iter().collect();
    pairs.sort_unstable();
    let mut first = true;
    for (key, value) in pairs {
        if first {
            full_url.push('?');
            first = false;
        } else {
            full_url.push('&');
        }
        full_url.push_str(key);
        full_url.push('=');
        full_url.push_str(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_detects_valid_card_candidate() {
        assert!(contains_luhn_candidate("card 4111 1111 1111 1111 leaked"));
        assert!(!contains_luhn_candidate("card 4111 1111 1111 1112 leaked"));
    }

    #[test]
    fn luhn_detects_card_padded_in_long_digit_run() {
        // 4111111111111111 is a known-valid Luhn card. The previous
        // implementation cleared the digit buffer when a run exceeded 19,
        // losing this match entirely. The sliding-window version still
        // surfaces it whether the padding is at the start or end of the run.
        assert!(contains_luhn_candidate("00004111111111111111"));
        assert!(contains_luhn_candidate("41111111111111119999"));
        assert!(contains_luhn_candidate("000041111111111111119999"));
    }

    #[test]
    fn luhn_scan_caps_page_long_digit_runs() {
        let mut long_run = "1".repeat(MAX_LUHN_DIGIT_RUN_SCAN + 128);
        long_run.push_str("4111111111111111");

        // Accepted, documented limitation (see docs/waf.md "Detection limits"):
        // a card embedded after a >MAX_LUHN_DIGIT_RUN_SCAN contiguous-digit
        // prefix is not detected, bounding Luhn work on attacker-supplied
        // page-long digit runs.
        assert!(!contains_luhn_candidate(&long_run));
        assert!(contains_luhn_candidate("x4111111111111111"));
    }

    #[test]
    fn materialized_query_is_deterministic_regardless_of_map_order() {
        // `append_materialized_query` must sort by (key, value) so the
        // synthetic-context `full_url` is stable across HashMap layouts —
        // otherwise `full_url`-target rules that depend on parameter adjacency
        // produce non-deterministic enforce/monitor verdicts.
        let mut params = HashMap::new();
        params.insert("b".to_string(), "2".to_string());
        params.insert("a".to_string(), "1".to_string());
        params.insert("c".to_string(), "3".to_string());

        let mut full_url = String::from("/path");
        append_materialized_query(&mut full_url, &params);
        assert_eq!(full_url, "/path?a=1&b=2&c=3");

        // Duplicate insertion order / rebuild must not change the result.
        let mut other = HashMap::new();
        other.insert("c".to_string(), "3".to_string());
        other.insert("a".to_string(), "1".to_string());
        other.insert("b".to_string(), "2".to_string());
        let mut full_url2 = String::from("/path");
        append_materialized_query(&mut full_url2, &other);
        assert_eq!(full_url, full_url2);
    }
}
