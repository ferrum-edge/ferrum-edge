//! IP Restriction Plugin
//!
//! Standalone IP-based access control plugin, independent of consumer
//! authentication. Supports exact IPs, CIDR notation, and IPv6.
//! Operates in either allow-first or deny-first mode.
//!
//! All IP rules are pre-parsed at config load time into integer bitmasks,
//! so request-time matching is pure integer comparison with zero parsing.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use tracing::warn;

use super::{Plugin, PluginResult, RequestContext};

#[derive(Debug, Clone, PartialEq)]
enum Mode {
    AllowFirst,
    DenyFirst,
}

/// A pre-parsed IP rule — parsed once at config load, matched with integer ops at request time.
#[derive(Debug, Clone)]
pub(super) enum ParsedRule {
    /// Exact IPv4 address (stored as 32-bit integer).
    ExactV4(u32),
    /// IPv4 CIDR range (network & mask pre-computed).
    CidrV4 { network: u32, mask: u32 },
    /// Exact IPv6 address (stored as 128-bit integer).
    ExactV6(u128),
    /// IPv6 CIDR range (network & mask pre-computed).
    CidrV6 { network: u128, mask: u128 },
}

/// The client IP parsed once per request for matching against all rules.
#[derive(Debug)]
pub(super) enum ParsedClientIp {
    V4(u32),
    V6(u128),
    /// IPv4-mapped IPv6 address. Match both IPv4 rules and the original IPv6
    /// mapped CIDR/exact rules so operators can express either family.
    V4MappedV6 {
        v4: u32,
        v6: u128,
    },
    /// Unparseable client IP string — never matches validated rules.
    Unknown,
}

pub struct IpRestriction {
    allow: Vec<ParsedRule>,
    deny: Vec<ParsedRule>,
    mode: Mode,
}

impl IpRestriction {
    pub fn new(config: &Value) -> Result<Self, String> {
        let allow = Self::parse_rule_list(config, "allow")?;
        let deny = Self::parse_rule_list(config, "deny")?;

        if allow.is_empty() && deny.is_empty() {
            return Err(
                "ip_restriction: at least one 'allow' or 'deny' rule is required".to_string(),
            );
        }

        let mode = match config.get("mode") {
            None | Some(Value::Null) => Mode::AllowFirst,
            Some(Value::String(mode)) if mode == "allow_first" => Mode::AllowFirst,
            Some(Value::String(mode)) if mode == "deny_first" => Mode::DenyFirst,
            Some(other) => {
                return Err(format!(
                    "ip_restriction: 'mode' must be 'allow_first' or 'deny_first', got: {other}"
                ));
            }
        };

        Ok(Self { allow, deny, mode })
    }

    /// Check whether a client IP is allowed by the restriction rules.
    fn check_ip(&self, client_ip_str: &str) -> PluginResult {
        let client_ip = parse_client_ip(client_ip_str);

        match self.mode {
            Mode::AllowFirst => {
                if !self.allow.is_empty()
                    && !self.allow.iter().any(|rule| rule_matches(&client_ip, rule))
                {
                    warn!(client_ip = %client_ip_str, plugin = "ip_restriction", reason = "not_in_allow_list", "IP address not in allow list");
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"IP address not allowed"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
                if self.deny.iter().any(|rule| rule_matches(&client_ip, rule)) {
                    warn!(client_ip = %client_ip_str, plugin = "ip_restriction", reason = "ip_denied", "IP address denied");
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"IP address denied"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
            }
            Mode::DenyFirst => {
                if self.deny.iter().any(|rule| rule_matches(&client_ip, rule)) {
                    warn!(client_ip = %client_ip_str, plugin = "ip_restriction", reason = "ip_denied", "IP address denied");
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"IP address denied"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
                if !self.allow.is_empty()
                    && !self.allow.iter().any(|rule| rule_matches(&client_ip, rule))
                {
                    warn!(client_ip = %client_ip_str, plugin = "ip_restriction", reason = "not_in_allow_list", "IP address not in allow list");
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"IP address not allowed"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
            }
        }
        PluginResult::Continue
    }

    /// Parse a JSON array of IP/CIDR strings into pre-computed rules at config load time.
    fn parse_rule_list(config: &Value, key: &str) -> Result<Vec<ParsedRule>, String> {
        let Some(value) = config.get(key) else {
            return Ok(Vec::new());
        };
        if value.is_null() {
            return Ok(Vec::new());
        }
        let Value::Array(arr) = value else {
            return Err(format!(
                "ip_restriction: '{key}' must be an array of IP/CIDR strings"
            ));
        };

        let mut rules = Vec::with_capacity(arr.len());
        for value in arr {
            let rule = value
                .as_str()
                .ok_or_else(|| format!("ip_restriction: '{key}' entries must be strings"))?;
            let rule = rule.trim();
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
        self.check_ip(&ctx.client_ip)
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        self.check_ip(&ctx.client_ip)
    }
}

// ── Pre-parsing (config load time) ──────────────────────────────────

/// Parse a single rule string into a `ParsedRule` at config load time.
pub(super) fn parse_rule(rule: &str) -> Option<ParsedRule> {
    if let Some((network_str, prefix_str)) = rule.split_once('/') {
        // CIDR rule
        let prefix_len: u8 = match prefix_str.parse() {
            Ok(p) => p,
            Err(_) => return None,
        };

        // Try IPv4 CIDR
        if let Some(octets) = parse_ipv4(network_str) {
            if prefix_len > 32 {
                return None;
            }
            let network = u32::from_be_bytes(octets);
            let mask = if prefix_len == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix_len)
            };
            return Some(ParsedRule::CidrV4 {
                network: network & mask,
                mask,
            });
        }

        // Try IPv6 CIDR
        if let Some(parts) = parse_ipv6(network_str) {
            if prefix_len > 128 {
                return None;
            }
            let network = ipv6_to_u128(&parts);
            let mask = if prefix_len == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix_len)
            };
            return Some(ParsedRule::CidrV6 {
                network: network & mask,
                mask,
            });
        }

        None
    } else {
        // Exact IP rule
        if let Some(octets) = parse_ipv4(rule) {
            return Some(ParsedRule::ExactV4(u32::from_be_bytes(octets)));
        }
        if let Some(parts) = parse_ipv6(rule) {
            return Some(ParsedRule::ExactV6(ipv6_to_u128(&parts)));
        }
        None
    }
}

/// Parse a client IP string once per request.
pub(super) fn parse_client_ip(ip: &str) -> ParsedClientIp {
    if let Some(octets) = parse_ipv4(ip) {
        return ParsedClientIp::V4(u32::from_be_bytes(octets));
    }
    if let Some(parts) = parse_ipv6(ip) {
        let v6_bits = ipv6_to_u128(&parts);
        if let Some(v4) = Ipv6Addr::from(parts).to_ipv4_mapped() {
            return ParsedClientIp::V4MappedV6 {
                v4: u32::from(v4),
                v6: v6_bits,
            };
        }
        return ParsedClientIp::V6(v6_bits);
    }
    ParsedClientIp::Unknown
}

// ── Request-time matching (integer ops only) ────────────────────────

/// Match a pre-parsed client IP against a pre-parsed rule. Pure integer comparison.
pub(super) fn rule_matches(client: &ParsedClientIp, rule: &ParsedRule) -> bool {
    match (client, rule) {
        // IPv4 exact
        (ParsedClientIp::V4(client_bits), ParsedRule::ExactV4(rule_bits)) => {
            client_bits == rule_bits
        }
        // IPv4 CIDR
        (ParsedClientIp::V4(client_bits), ParsedRule::CidrV4 { network, mask }) => {
            (client_bits & mask) == *network
        }
        // IPv4-mapped IPv6 addresses should satisfy IPv4 rules.
        (ParsedClientIp::V4MappedV6 { v4, .. }, ParsedRule::ExactV4(rule_bits)) => v4 == rule_bits,
        (ParsedClientIp::V4MappedV6 { v4, .. }, ParsedRule::CidrV4 { network, mask }) => {
            (v4 & mask) == *network
        }
        // IPv6 exact
        (ParsedClientIp::V6(client_bits), ParsedRule::ExactV6(rule_bits)) => {
            client_bits == rule_bits
        }
        // IPv6 CIDR
        (ParsedClientIp::V6(client_bits), ParsedRule::CidrV6 { network, mask }) => {
            (client_bits & mask) == *network
        }
        // IPv4-mapped IPv6 addresses should also satisfy IPv6 mapped rules.
        (ParsedClientIp::V4MappedV6 { v6, .. }, ParsedRule::ExactV6(rule_bits)) => v6 == rule_bits,
        (ParsedClientIp::V4MappedV6 { v6, .. }, ParsedRule::CidrV6 { network, mask }) => {
            (v6 & mask) == *network
        }
        // Unknown or cross-family types never match validated rules.
        _ => false,
    }
}

// ── Backwards-compatible public API ─────────────────────────────────

/// Check if an IP address matches a rule (supports exact IPs, CIDR notation, and IPv6).
///
/// This is the string-based API preserved for external callers and tests.
/// Internally, the plugin uses pre-parsed rules for zero-parse request-time matching.
#[allow(dead_code)]
pub fn ip_matches(client_ip: &str, rule: &str) -> bool {
    let parsed_client = parse_client_ip(client_ip);
    parse_rule(rule)
        .map(|parsed_rule| rule_matches(&parsed_client, &parsed_rule))
        .unwrap_or(false)
}

// ── IP parsing helpers ──────────────────────────────────────────────

fn parse_ipv4(ip: &str) -> Option<[u8; 4]> {
    // Allocation-free — iterate without collecting the Vec.
    let mut parts = ip.split('.');
    let a: u8 = parts.next()?.parse().ok()?;
    let b: u8 = parts.next()?.parse().ok()?;
    let c: u8 = parts.next()?.parse().ok()?;
    let d: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        // Too many octets, e.g. "1.2.3.4.5".
        return None;
    }
    Some([a, b, c, d])
}

fn parse_ipv6(ip: &str) -> Option<[u16; 8]> {
    // Strip surrounding brackets if present (e.g. from URL-style "[::1]").
    let ip = ip
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(ip);

    // Strip a zone identifier suffix like "%eth0" — IPv6 zones are interface
    // scope hints and are not part of the address itself (RFC 6874). They never
    // exist on canonical `IpAddr::to_string()` output, but a malformed
    // X-Forwarded-For entry from upstream could contain one. Stripping prevents
    // unparseable client IPs from silently bypassing matching by being treated
    // as `Unknown`.
    let ip = match ip.find('%') {
        Some(idx) => &ip[..idx],
        None => ip,
    };

    ip.parse::<Ipv6Addr>().ok().map(|ip| ip.segments())
}

fn ipv6_to_u128(parts: &[u16; 8]) -> u128 {
    let mut result: u128 = 0;
    for &part in parts {
        result = (result << 16) | (part as u128);
    }
    result
}
