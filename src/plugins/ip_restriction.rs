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
    /// Unparseable rule — kept as a raw string for exact string comparison.
    /// This ensures backwards compatibility if someone passes a rule we can't parse.
    Raw(String),
}

/// The client IP parsed once per request for matching against all rules.
#[derive(Debug)]
pub(super) enum ParsedClientIp {
    V4(u32),
    V6(u128),
    /// Unparseable — can only match Raw rules via string comparison.
    Unknown(String),
}

pub struct IpRestriction {
    allow: Vec<ParsedRule>,
    deny: Vec<ParsedRule>,
    mode: Mode,
}

impl IpRestriction {
    pub fn new(config: &Value) -> Result<Self, String> {
        let allow = Self::parse_rule_list(config, "allow");
        let deny = Self::parse_rule_list(config, "deny");

        if allow.is_empty() && deny.is_empty() {
            return Err(
                "ip_restriction: at least one 'allow' or 'deny' rule is required".to_string(),
            );
        }

        let mode = match config["mode"].as_str() {
            Some("deny_first") => Mode::DenyFirst,
            _ => Mode::AllowFirst,
        };

        Ok(Self { allow, deny, mode })
    }

    /// Parse a JSON array of IP/CIDR strings into pre-computed rules at config load time.
    fn parse_rule_list(config: &Value, key: &str) -> Vec<ParsedRule> {
        config[key]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(parse_rule)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Plugin priority: early pre-processing, before auth.
pub const IP_RESTRICTION_PRIORITY: u16 = 150;

#[async_trait]
impl Plugin for IpRestriction {
    fn name(&self) -> &str {
        "ip_restriction"
    }

    fn priority(&self) -> u16 {
        IP_RESTRICTION_PRIORITY
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let client_ip = parse_client_ip(&ctx.client_ip);

        match self.mode {
            Mode::AllowFirst => {
                // If allow list is configured, IP must be in it
                if !self.allow.is_empty() {
                    if self.allow.iter().any(|rule| rule_matches(&client_ip, rule)) {
                        return PluginResult::Continue;
                    }
                    warn!(client_ip = %ctx.client_ip, plugin = "ip_restriction", reason = "not_in_allow_list", "IP address not in allow list");
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"IP address not allowed"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
                // Then check deny list
                if self.deny.iter().any(|rule| rule_matches(&client_ip, rule)) {
                    warn!(client_ip = %ctx.client_ip, plugin = "ip_restriction", reason = "ip_denied", "IP address denied");
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"IP address denied"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
            }
            Mode::DenyFirst => {
                // Check deny list first
                if self.deny.iter().any(|rule| rule_matches(&client_ip, rule)) {
                    warn!(client_ip = %ctx.client_ip, plugin = "ip_restriction", reason = "ip_denied", "IP address denied");
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"IP address denied"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
                // If allow list is configured and IP is not in it, deny
                if !self.allow.is_empty()
                    && !self.allow.iter().any(|rule| rule_matches(&client_ip, rule))
                {
                    warn!(client_ip = %ctx.client_ip, plugin = "ip_restriction", reason = "not_in_allow_list", "IP address not in allow list");
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
}

// ── Pre-parsing (config load time) ──────────────────────────────────

/// Parse a single rule string into a `ParsedRule` at config load time.
pub(super) fn parse_rule(rule: &str) -> ParsedRule {
    if let Some((network_str, prefix_str)) = rule.split_once('/') {
        // CIDR rule
        let prefix_len: u8 = match prefix_str.parse() {
            Ok(p) => p,
            Err(_) => return ParsedRule::Raw(rule.to_string()),
        };

        // Try IPv4 CIDR
        if let Some(octets) = parse_ipv4(network_str) {
            if prefix_len > 32 {
                return ParsedRule::Raw(rule.to_string());
            }
            let network = u32::from_be_bytes(octets);
            let mask = if prefix_len == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix_len)
            };
            return ParsedRule::CidrV4 {
                network: network & mask,
                mask,
            };
        }

        // Try IPv6 CIDR
        if let Some(parts) = parse_ipv6(network_str) {
            if prefix_len > 128 {
                return ParsedRule::Raw(rule.to_string());
            }
            let network = ipv6_to_u128(&parts);
            let mask = if prefix_len == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix_len)
            };
            return ParsedRule::CidrV6 {
                network: network & mask,
                mask,
            };
        }

        ParsedRule::Raw(rule.to_string())
    } else {
        // Exact IP rule
        if let Some(octets) = parse_ipv4(rule) {
            return ParsedRule::ExactV4(u32::from_be_bytes(octets));
        }
        if let Some(parts) = parse_ipv6(rule) {
            return ParsedRule::ExactV6(ipv6_to_u128(&parts));
        }
        // Unparseable — keep raw for string comparison
        ParsedRule::Raw(rule.to_string())
    }
}

/// Parse a client IP string once per request.
pub(super) fn parse_client_ip(ip: &str) -> ParsedClientIp {
    if let Some(octets) = parse_ipv4(ip) {
        return ParsedClientIp::V4(u32::from_be_bytes(octets));
    }
    if let Some(parts) = parse_ipv6(ip) {
        return ParsedClientIp::V6(ipv6_to_u128(&parts));
    }
    ParsedClientIp::Unknown(ip.to_string())
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
        // IPv6 exact
        (ParsedClientIp::V6(client_bits), ParsedRule::ExactV6(rule_bits)) => {
            client_bits == rule_bits
        }
        // IPv6 CIDR
        (ParsedClientIp::V6(client_bits), ParsedRule::CidrV6 { network, mask }) => {
            (client_bits & mask) == *network
        }
        // Raw fallback — string comparison
        (ParsedClientIp::Unknown(client_str), ParsedRule::Raw(rule_str)) => client_str == rule_str,
        // Cross-family or mismatched types never match
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
    let parsed_rule = parse_rule(rule);
    rule_matches(&parsed_client, &parsed_rule)
}

// ── IP parsing helpers ──────────────────────────────────────────────

fn parse_ipv4(ip: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a: u8 = parts[0].parse().ok()?;
    let b: u8 = parts[1].parse().ok()?;
    let c: u8 = parts[2].parse().ok()?;
    let d: u8 = parts[3].parse().ok()?;
    Some([a, b, c, d])
}

fn parse_ipv6(ip: &str) -> Option<[u16; 8]> {
    // Handle :: expansion
    let ip = ip.trim_matches('[').trim_matches(']');

    if ip.contains("::") {
        let parts: Vec<&str> = ip.split("::").collect();
        if parts.len() > 2 {
            return None;
        }

        let left: Vec<u16> = if parts[0].is_empty() {
            vec![]
        } else {
            parts[0]
                .split(':')
                .map(|p| u16::from_str_radix(p, 16))
                .collect::<Result<Vec<_>, _>>()
                .ok()?
        };

        let right: Vec<u16> = if parts.len() < 2 || parts[1].is_empty() {
            vec![]
        } else {
            parts[1]
                .split(':')
                .map(|p| u16::from_str_radix(p, 16))
                .collect::<Result<Vec<_>, _>>()
                .ok()?
        };

        if left.len() + right.len() > 8 {
            return None;
        }
        let zeros_needed = 8 - left.len() - right.len();
        let mut result = [0u16; 8];
        for (i, &v) in left.iter().enumerate() {
            result[i] = v;
        }
        for (i, &v) in right.iter().enumerate() {
            result[left.len() + zeros_needed + i] = v;
        }
        Some(result)
    } else {
        let parts: Vec<u16> = ip
            .split(':')
            .map(|p| u16::from_str_radix(p, 16))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        if parts.len() != 8 {
            return None;
        }
        let mut result = [0u16; 8];
        result.copy_from_slice(&parts);
        Some(result)
    }
}

fn ipv6_to_u128(parts: &[u16; 8]) -> u128 {
    let mut result: u128 = 0;
    for &part in parts {
        result = (result << 16) | (part as u128);
    }
    result
}
