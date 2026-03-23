use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::warn;

use super::{Plugin, PluginResult, RequestContext};

pub struct AccessControl {
    allowed_consumers: Vec<String>,
    disallowed_consumers: Vec<String>,
    allowed_ips: Vec<String>,
    blocked_ips: Vec<String>,
}

impl AccessControl {
    pub fn new(config: &Value) -> Self {
        let allowed = config["allowed_consumers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let disallowed = config["disallowed_consumers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let allowed_ips = config["allowed_ips"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let blocked_ips = config["blocked_ips"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            allowed_consumers: allowed,
            disallowed_consumers: disallowed,
            allowed_ips,
            blocked_ips,
        }
    }
}

#[async_trait]
impl Plugin for AccessControl {
    fn name(&self) -> &str {
        "access_control"
    }

    fn priority(&self) -> u16 {
        super::priority::ACCESS_CONTROL
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        // Check IP-based access control first
        let client_ip = &ctx.client_ip;

        // Check if IP is explicitly blocked
        if self
            .blocked_ips
            .iter()
            .any(|blocked_ip| ip_matches(client_ip, blocked_ip))
        {
            warn!(client_ip = %client_ip, plugin = "access_control", reason = "ip_blocked", "IP address blocked by access control");
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"IP address is blocked"}"#.into(),
                headers: HashMap::new(),
            };
        }

        // Check if allowed IPs are configured and IP is not in allowed list
        if !self.allowed_ips.is_empty()
            && !self
                .allowed_ips
                .iter()
                .any(|allowed_ip| ip_matches(client_ip, allowed_ip))
        {
            warn!(client_ip = %client_ip, plugin = "access_control", reason = "ip_not_allowed", "IP address not in allow list");
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"IP address not allowed"}"#.into(),
                headers: HashMap::new(),
            };
        }

        let consumer = match &ctx.identified_consumer {
            Some(c) => c,
            None => {
                warn!(client_ip = %ctx.client_ip, plugin = "access_control", reason = "no_consumer", "No consumer identified for access control");
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"No consumer identified"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        let username = &consumer.username;

        // Check disallowed first
        if self.disallowed_consumers.contains(username) {
            warn!(consumer = %username, client_ip = %ctx.client_ip, plugin = "access_control", reason = "consumer_disallowed", "Consumer rejected by access control");
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
                headers: HashMap::new(),
            };
        }

        // If allowed list is configured, consumer must be in it
        if !self.allowed_consumers.is_empty() && !self.allowed_consumers.contains(username) {
            warn!(consumer = %username, client_ip = %ctx.client_ip, plugin = "access_control", reason = "consumer_not_allowed", "Consumer not in allow list");
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
                headers: HashMap::new(),
            };
        }

        PluginResult::Continue
    }
}

/// Check if an IP address matches a rule (supports exact IPs, CIDR notation, and IPv6).
fn ip_matches(client_ip: &str, rule: &str) -> bool {
    // Simple exact match for individual IPs
    if client_ip == rule {
        return true;
    }

    // CIDR notation matching
    if rule.contains('/')
        && let Some((network_str, prefix_str)) = rule.split_once('/')
    {
        let prefix_len: u8 = match prefix_str.parse() {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Try IPv4
        if let (Some(client_octets), Some(network_octets)) =
            (parse_ipv4(client_ip), parse_ipv4(network_str))
        {
            if prefix_len > 32 {
                return false;
            }
            let client_bits = u32::from_be_bytes(client_octets);
            let network_bits = u32::from_be_bytes(network_octets);
            let mask = if prefix_len == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix_len)
            };
            return (client_bits & mask) == (network_bits & mask);
        }

        // Try IPv6
        if let (Some(client_parts), Some(network_parts)) =
            (parse_ipv6(client_ip), parse_ipv6(network_str))
        {
            if prefix_len > 128 {
                return false;
            }
            let client_bits = ipv6_to_u128(&client_parts);
            let network_bits = ipv6_to_u128(&network_parts);
            let mask = if prefix_len == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix_len)
            };
            return (client_bits & mask) == (network_bits & mask);
        }
    }

    false
}

/// Parse a dotted-quad IPv4 address into 4 octets.
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

/// Parse an IPv6 address into 8 groups of u16 values.
/// Supports `::` shorthand (e.g., `::1`, `2001:db8::1`, `fe80::`).
fn parse_ipv6(ip: &str) -> Option<[u16; 8]> {
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

/// Convert 8 IPv6 groups into a single u128 for bitwise CIDR comparison.
fn ipv6_to_u128(parts: &[u16; 8]) -> u128 {
    let mut result: u128 = 0;
    for &part in parts {
        result = (result << 16) | (part as u128);
    }
    result
}
