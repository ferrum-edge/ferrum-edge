//! IP Restriction Plugin
//!
//! Standalone IP-based access control plugin, independent of consumer
//! authentication. Supports exact IPs, CIDR notation, and IPv6.
//! Operates in either allow-first or deny-first mode.
//!
//! Rules are compiled on the cold path into sorted, merged numeric intervals.
//! Request matching is allocation-free, lock-free, and O(log n) in the number
//! of non-overlapping intervals. The authoritative client IP is parsed and
//! canonicalized once by the request/stream context and reused by every
//! `ip_restriction` instance.

use async_trait::async_trait;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::{debug, warn};

use super::{Plugin, PluginResult, RequestContext};

const CONFIG_KEYS: &[&str] = &["allow", "deny", "mode"];

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
                "ip_restriction: unknown configuration field '{unknown}'; allowed fields: allow, deny, mode"
            ));
        }

        let allow = IpRangeSet::compile(Self::parse_rule_list(object, "allow")?);
        let deny = IpRangeSet::compile(Self::parse_rule_list(object, "deny")?);
        if allow.is_empty() && deny.is_empty() {
            return Err(
                "ip_restriction: at least one 'allow' or 'deny' rule is required".to_string(),
            );
        }

        let mode = match object.get("mode") {
            None => Mode::AllowFirst,
            Some(Value::String(mode)) if mode == "allow_first" => Mode::AllowFirst,
            Some(Value::String(mode)) if mode == "deny_first" => Mode::DenyFirst,
            Some(other) => {
                return Err(format!(
                    "ip_restriction: 'mode' must be 'allow_first' or 'deny_first', got: {other}"
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
    fn check_ip(&self, client_ip: Option<IpAddr>, client_ip_label: &str) -> PluginResult {
        let Some(client_ip) = client_ip else {
            warn!(
                client_ip = %client_ip_label,
                plugin = "ip_restriction",
                reason = "unparseable_client_ip",
                "client IP could not be parsed; denying"
            );
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"client IP could not be determined"}"#.to_string(),
                headers: HashMap::new(),
            };
        };

        match self.mode {
            Mode::AllowFirst => {
                if !self.allow.is_empty() && !self.allow.contains(client_ip) {
                    return reject_not_allowed(client_ip_label);
                }
                if self.deny.contains(client_ip) {
                    return reject_denied(client_ip_label);
                }
            }
            Mode::DenyFirst => {
                if self.deny.contains(client_ip) {
                    return reject_denied(client_ip_label);
                }
                if !self.allow.is_empty() && !self.allow.contains(client_ip) {
                    return reject_not_allowed(client_ip_label);
                }
            }
        }
        PluginResult::Continue
    }

    /// Parse one rule array on the cold configuration path.
    fn parse_rule_list(config: &Map<String, Value>, key: &str) -> Result<Vec<ParsedRule>, String> {
        let Some(value) = config.get(key) else {
            return Ok(Vec::new());
        };
        let Value::Array(values) = value else {
            return Err(format!(
                "ip_restriction: '{key}' must be an array of IP/CIDR strings"
            ));
        };

        let mut rules = Vec::with_capacity(values.len());
        for value in values {
            let rule = value
                .as_str()
                .ok_or_else(|| format!("ip_restriction: '{key}' entries must be strings"))?
                .trim();
            if rule.is_empty() {
                return Err(format!(
                    "ip_restriction: '{key}' entries must be non-empty strings"
                ));
            }
            rules.push(parse_rule(rule).ok_or_else(|| {
                format!("ip_restriction: invalid {key} rule '{rule}' — expected exact IP or CIDR")
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
        self.check_ip(ctx.canonical_client_ip(), &ctx.client_ip)
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        self.check_ip(ctx.canonical_client_ip(), &ctx.client_ip)
    }
}

fn reject_not_allowed(client_ip: &str) -> PluginResult {
    warn!(client_ip = %client_ip, plugin = "ip_restriction", reason = "not_in_allow_list", "IP address not in allow list");
    PluginResult::Reject {
        status_code: 403,
        body: r#"{"error":"IP address not allowed"}"#.to_string(),
        headers: HashMap::new(),
    }
}

fn reject_denied(client_ip: &str) -> PluginResult {
    warn!(client_ip = %client_ip, plugin = "ip_restriction", reason = "ip_denied", "IP address denied");
    PluginResult::Reject {
        status_code: 403,
        body: r#"{"error":"IP address denied"}"#.to_string(),
        headers: HashMap::new(),
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
    match client_ip.to_canonical() {
        IpAddr::V4(ip) => (IpFamily::V4, u128::from(u32::from(ip))),
        IpAddr::V6(ip) => (IpFamily::V6, u128::from(ip)),
    }
}

/// Parse one exact-IP/CIDR rule into an inclusive numeric interval.
fn parse_rule(rule: &str) -> Option<ParsedRule> {
    if let Some((network, prefix)) = rule.split_once('/') {
        let prefix: u8 = prefix.parse().ok()?;
        return parse_cidr_rule(network, prefix);
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
    match super::parse_client_ip_literal(ip)? {
        IpAddr::V4(ipv4) if is_canonical_ipv4_literal(ip, ipv4) => Some(IpAddr::V4(ipv4)),
        IpAddr::V4(_) => None,
        IpAddr::V6(ipv6) => Some(IpAddr::V6(ipv6)),
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
    let client_ip = super::parse_client_ip_literal(client_ip).map(|ip| ip.to_canonical());
    match (client_ip, parse_rule(rule)) {
        (Some(client_ip), Some(rule)) => rule.matches(client_ip),
        _ => false,
    }
}
