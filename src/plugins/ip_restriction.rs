//! IP Restriction Plugin
//!
//! Standalone IP-based access control plugin, independent of consumer
//! authentication. Supports exact IPs, CIDR notation, and IPv6.
//!
//! The decision is fixed: a deny match always rejects, and a non-empty allow
//! list rejects every address outside it. The deprecated `mode` key
//! (`allow_first` / `deny_first`) never changes whether a request is admitted
//! (issue #6610). It only picks which rejection body and log reason an address
//! that is both outside the allow list and on the deny list receives.
//!
//! Rules are compiled on the cold path into sorted, merged numeric intervals.
//! Request matching is allocation-free, lock-free, and O(log n) in the number
//! of non-overlapping intervals. The authoritative client IP is parsed and
//! canonicalized once by the request/stream context and reused by every
//! `ip_restriction` instance.
//!
//! Rule spellings are canonical-only so the runtime and the published
//! `IpRestrictionRule` OpenAPI grammar admit exactly the same strings: IPv4
//! octets and CIDR prefixes are canonical unsigned decimal, and an IPv6 rule
//! zone must be non-empty and free of whitespace, `/`, and `]`. Client-IP
//! parsing (`crate::util::client_identity`) stays lenient about zones; this
//! grammar applies to configured rules only.
//!
//! Enforcement is admission-time. HTTP-family requests are checked per
//! request, but an established TCP/TLS, UDP/DTLS, or upgraded WebSocket
//! session is checked once when it is admitted and is not re-evaluated when a
//! reload changes the policy.
//!
//! Every rejection stamps the fixed-cardinality
//! [`REJECTION_REASON_METADATA_KEY`] metadata value so transaction logs can
//! tell the three rejection reasons apart per proxy.

use crate::plugins::utils::log_sampling::warn_sampled;

use async_trait::async_trait;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

const CONFIG_KEYS: &[&str] = &["allow", "deny", "mode"];

/// Metadata key stamped on every `ip_restriction` rejection, carrying one of
/// `unparseable_client_ip`, `not_in_allow_list`, or `ip_denied`.
///
/// The value set is fixed, so it is allowlisted for log sinks in
/// `crate::plugins::utils::metadata_redaction::BUILTIN_SAFE_METADATA_KEYS`.
pub const REJECTION_REASON_METADATA_KEY: &str = "ip_restriction.reason";

/// Why a client address failed the compiled policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rejection {
    UnparseableClientIp,
    NotInAllowList,
    IpDenied,
}

impl Rejection {
    fn reason(self) -> &'static str {
        match self {
            Self::UnparseableClientIp => "unparseable_client_ip",
            Self::NotInAllowList => "not_in_allow_list",
            Self::IpDenied => "ip_denied",
        }
    }

    /// Emit the sampled warning for this rejection and build its response.
    fn into_result(self, client_ip: &str) -> PluginResult {
        let body = match self {
            Self::UnparseableClientIp => {
                warn_sampled!(
                    client_ip = %client_ip,
                    plugin = "ip_restriction",
                    reason = "unparseable_client_ip",
                    "client IP could not be parsed; denying"
                );
                r#"{"error":"client IP could not be determined"}"#
            }
            Self::NotInAllowList => {
                warn_sampled!(
                    client_ip = %client_ip,
                    plugin = "ip_restriction",
                    reason = "not_in_allow_list",
                    "IP address not in allow list"
                );
                r#"{"error":"IP address not allowed"}"#
            }
            Self::IpDenied => {
                warn_sampled!(
                    client_ip = %client_ip,
                    plugin = "ip_restriction",
                    reason = "ip_denied",
                    "IP address denied"
                );
                r#"{"error":"IP address denied"}"#
            }
        };
        PluginResult::Reject {
            status_code: 403,
            body: body.to_string(),
            headers: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    AllowFirst,
    DenyFirst,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::AllowFirst => "allow_first",
            Self::DenyFirst => "deny_first",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

/// Inclusive numeric address interval, compiled from one exact-IP/CIDR rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedRule {
    family: IpFamily,
    start: u128,
    end: u128,
}

impl ParsedRule {
    fn matches(self, client_ip: IpAddr) -> bool {
        let (family, value) = ip_key(client_ip);
        self.family == family && self.start <= value && value <= self.end
    }
}

/// Immutable lookup index built at plugin construction/reload.
///
/// Overlapping, duplicate, and adjacent ranges are merged. A request performs
/// one binary search in its address family, so lookup does not scan configured
/// rules and requires no request-time allocation or synchronization.
#[derive(Debug, Default)]
struct IpRangeSet {
    v4: Box<[ParsedRule]>,
    v6: Box<[ParsedRule]>,
}

impl IpRangeSet {
    fn compile(rules: Vec<ParsedRule>) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for rule in rules {
            match rule.family {
                IpFamily::V4 => v4.push(rule),
                IpFamily::V6 => v6.push(rule),
            }
        }
        Self {
            v4: merge_ranges(v4).into_boxed_slice(),
            v6: merge_ranges(v6).into_boxed_slice(),
        }
    }

    fn contains(&self, client_ip: IpAddr) -> bool {
        let (family, value) = ip_key(client_ip);
        let ranges = match family {
            IpFamily::V4 => &self.v4,
            IpFamily::V6 => &self.v6,
        };
        range_binary_search(ranges, value)
    }

    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

pub struct IpRestriction {
    allow: IpRangeSet,
    deny: IpRangeSet,
    mode: Mode,
}

impl IpRestriction {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "ip_restriction: config must be an object".to_string())?;
        if let Some(unknown) = object
            .keys()
            .find(|key| !CONFIG_KEYS.contains(&key.as_str()))
        {
            return Err(format!(
                "ip_restriction: unknown configuration field {unknown:?}; allowed fields: `allow`, `deny`, `mode`"
            ));
        }

        let allow = IpRangeSet::compile(Self::parse_rule_list(object, "allow")?);
        let deny = IpRangeSet::compile(Self::parse_rule_list(object, "deny")?);
        if allow.is_empty() && deny.is_empty() {
            return Err(
                "ip_restriction: at least one `allow` or `deny` rule is required".to_string(),
            );
        }

        let mode = match object.get("mode") {
            None => Mode::AllowFirst,
            Some(Value::String(mode)) if mode == "allow_first" => Mode::AllowFirst,
            Some(Value::String(mode)) if mode == "deny_first" => Mode::DenyFirst,
            Some(other) => {
                return Err(format!(
                    "ip_restriction: `mode` must be `allow_first` or `deny_first`, got: {other:?}",
                    other = other.to_string()
                ));
            }
        };

        debug!(
            plugin = "ip_restriction",
            mode = mode.as_str(),
            allow_intervals = allow.v4.len() + allow.v6.len(),
            allow_ipv4_intervals = allow.v4.len(),
            allow_ipv6_intervals = allow.v6.len(),
            deny_intervals = deny.v4.len() + deny.v6.len(),
            deny_ipv4_intervals = deny.v4.len(),
            deny_ipv6_intervals = deny.v6.len(),
            "compiled IP restriction policy"
        );

        Ok(Self { allow, deny, mode })
    }

    /// Check a context-cached, canonical client IP against the compiled policy.
    fn check_ip(&self, client_ip: Option<IpAddr>) -> Option<Rejection> {
        let Some(client_ip) = client_ip else {
            return Some(Rejection::UnparseableClientIp);
        };

        // Both arms reject exactly the same addresses (deny wins, then the
        // allow list must match); `mode` only orders the two checks, which
        // decides the reported reason for an address that fails both.
        let not_allowed = || !self.allow.is_empty() && !self.allow.contains(client_ip);
        match self.mode {
            Mode::AllowFirst => {
                if not_allowed() {
                    return Some(Rejection::NotInAllowList);
                }
                if self.deny.contains(client_ip) {
                    return Some(Rejection::IpDenied);
                }
            }
            Mode::DenyFirst => {
                if self.deny.contains(client_ip) {
                    return Some(Rejection::IpDenied);
                }
                if not_allowed() {
                    return Some(Rejection::NotInAllowList);
                }
            }
        }
        None
    }

    /// Parse one rule array on the cold configuration path.
    fn parse_rule_list(config: &Map<String, Value>, key: &str) -> Result<Vec<ParsedRule>, String> {
        let Some(value) = config.get(key) else {
            return Ok(Vec::new());
        };
        let Value::Array(values) = value else {
            return Err(format!(
                "ip_restriction: `{key}` must be an array of IP/CIDR strings"
            ));
        };

        let mut rules = Vec::with_capacity(values.len());
        for value in values {
            let rule = value
                .as_str()
                .ok_or_else(|| format!("ip_restriction: `{key}` entries must be strings"))?
                .trim();
            if rule.is_empty() {
                return Err(format!(
                    "ip_restriction: `{key}` entries must be non-empty strings"
                ));
            }
            rules.push(parse_rule(rule).ok_or_else(|| {
                format!("ip_restriction: invalid `{key}` rule {rule:?} — expected exact IP or CIDR")
            })?);
        }
        Ok(rules)
    }
}

#[async_trait]
impl Plugin for IpRestriction {
    fn name(&self) -> &str {
        "ip_restriction"
    }

    fn priority(&self) -> u16 {
        super::priority::IP_RESTRICTION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_stream_connect(
        &self,
        ctx: &mut super::StreamConnectionContext,
    ) -> super::PluginResult {
        match self.check_ip(ctx.canonical_client_ip()) {
            None => PluginResult::Continue,
            Some(rejection) => {
                ctx.insert_metadata(
                    REJECTION_REASON_METADATA_KEY.to_string(),
                    rejection.reason().to_string(),
                );
                rejection.into_result(&ctx.client_ip)
            }
        }
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        match self.check_ip(ctx.canonical_client_ip()) {
            None => PluginResult::Continue,
            Some(rejection) => {
                ctx.metadata.insert(
                    REJECTION_REASON_METADATA_KEY.to_string(),
                    rejection.reason().to_string(),
                );
                rejection.into_result(&ctx.client_ip)
            }
        }
    }
}

fn merge_ranges(mut ranges: Vec<ParsedRule>) -> Vec<ParsedRule> {
    ranges.sort_unstable_by_key(|rule| (rule.start, rule.end));
    let mut merged: Vec<ParsedRule> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end.saturating_add(1)
        {
            previous.end = previous.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    merged
}

fn range_binary_search(ranges: &[ParsedRule], client: u128) -> bool {
    let mut low = 0;
    let mut high = ranges.len();
    while low < high {
        let middle = low + (high - low) / 2;
        if ranges[middle].start <= client {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    low > 0 && client <= ranges[low - 1].end
}

fn ip_key(client_ip: IpAddr) -> (IpFamily, u128) {
    match crate::util::client_identity::canonical_ip(client_ip) {
        IpAddr::V4(ip) => (IpFamily::V4, u128::from(u32::from(ip))),
        IpAddr::V6(ip) => (IpFamily::V6, u128::from(ip)),
    }
}

/// Parse one exact-IP/CIDR rule into an inclusive numeric interval.
fn parse_rule(rule: &str) -> Option<ParsedRule> {
    if let Some((network, prefix)) = rule.split_once('/') {
        return parse_cidr_rule(network, parse_canonical_prefix(prefix)?);
    }

    match parse_rule_ip(rule)? {
        IpAddr::V4(ip) => {
            let value = u128::from(u32::from(ip));
            Some(ParsedRule {
                family: IpFamily::V4,
                start: value,
                end: value,
            })
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                let value = u128::from(u32::from(mapped));
                return Some(ParsedRule {
                    family: IpFamily::V4,
                    start: value,
                    end: value,
                });
            }
            let value = u128::from(ip);
            Some(ParsedRule {
                family: IpFamily::V6,
                start: value,
                end: value,
            })
        }
    }
}

fn parse_cidr_rule(network: &str, prefix: u8) -> Option<ParsedRule> {
    match parse_rule_ip(network)? {
        IpAddr::V4(ip) => v4_range(u32::from(ip), prefix),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                let v4_prefix = prefix.checked_sub(96)?;
                return v4_range(u32::from(mapped), v4_prefix);
            }
            if prefix > 128 {
                return None;
            }
            let value = u128::from(ip);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let start = value & mask;
            Some(ParsedRule {
                family: IpFamily::V6,
                start,
                end: start | !mask,
            })
        }
    }
}

/// Parse a CIDR prefix length written in canonical unsigned decimal.
///
/// `str::parse::<u8>` also accepts a leading `+` and leading zeros (`/+8`,
/// `/08`, `/096`). Those denote the same numeric prefix, but the published
/// rule grammar does not admit them, so they are refused here too — the same
/// stance [`is_canonical_ipv4_literal`] takes for IPv4 octets.
fn parse_canonical_prefix(prefix: &str) -> Option<u8> {
    let canonical = !prefix.is_empty()
        && prefix.bytes().all(|byte| byte.is_ascii_digit())
        && (prefix.len() == 1 || !prefix.starts_with('0'));
    if !canonical {
        return None;
    }
    prefix.parse().ok()
}

fn v4_range(value: u32, prefix: u8) -> Option<ParsedRule> {
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let start = value & mask;
    Some(ParsedRule {
        family: IpFamily::V4,
        start: u128::from(start),
        end: u128::from(start | !mask),
    })
}

fn parse_rule_ip(ip: &str) -> Option<IpAddr> {
    match crate::util::client_identity::parse_client_ip_literal(ip)? {
        IpAddr::V4(ipv4) if is_canonical_ipv4_literal(ip, ipv4) => Some(IpAddr::V4(ipv4)),
        IpAddr::V4(_) => None,
        IpAddr::V6(ipv6) if has_valid_rule_zone(ip) => Some(IpAddr::V6(ipv6)),
        IpAddr::V6(_) => None,
    }
}

/// Whether an IPv6 rule literal's zone identifier, if any, is well formed.
///
/// The shared client-IP parser cuts everything after the first `%` without
/// inspecting it, so it also accepts `fe80::1%` and zones containing
/// whitespace or `]`. Configured rules are held to the published grammar
/// instead: a zone must be non-empty and contain no whitespace, `/`, or `]`.
/// The zone is still stripped before matching.
fn has_valid_rule_zone(literal: &str) -> bool {
    let unbracketed = literal
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(literal);
    match unbracketed.split_once('%') {
        None => true,
        Some((_, zone)) => {
            !zone.is_empty()
                && !zone
                    .chars()
                    .any(|ch| ch == '/' || ch == ']' || ch.is_whitespace())
        }
    }
}

fn is_canonical_ipv4_literal(literal: &str, ipv4: std::net::Ipv4Addr) -> bool {
    let mut parts = literal.split('.');
    for expected in ipv4.octets() {
        let Some(part) = parts.next() else {
            return false;
        };
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|byte| byte.is_ascii_digit())
            || part.parse::<u8>().ok() != Some(expected)
        {
            return false;
        }
    }
    parts.next().is_none()
}

/// Check if an IP address matches one exact-IP/CIDR rule.
///
/// This string-based API is preserved for external callers and tests. Runtime
/// plugin hooks use the context-cached typed client IP and compiled range set.
#[allow(dead_code)]
pub fn ip_matches(client_ip: &str, rule: &str) -> bool {
    let client_ip = crate::util::client_identity::parse_canonical_client_ip(client_ip);
    match (client_ip, parse_rule(rule)) {
        (Some(client_ip), Some(rule)) => rule.matches(client_ip),
        _ => false,
    }
}
