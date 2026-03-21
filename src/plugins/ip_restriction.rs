//! IP Restriction Plugin
//!
//! Standalone IP-based access control plugin, independent of consumer
//! authentication. Supports exact IPs, CIDR notation, and IPv6.
//! Operates in either allow-first or deny-first mode.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

#[derive(Debug, Clone, PartialEq)]
enum Mode {
    AllowFirst,
    DenyFirst,
}

pub struct IpRestriction {
    allow: Vec<String>,
    deny: Vec<String>,
    mode: Mode,
}

impl IpRestriction {
    pub fn new(config: &Value) -> Self {
        let allow = config["allow"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let deny = config["deny"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let mode = match config["mode"].as_str() {
            Some("deny_first") => Mode::DenyFirst,
            _ => Mode::AllowFirst,
        };

        Self { allow, deny, mode }
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
        let client_ip = &ctx.client_ip;

        match self.mode {
            Mode::AllowFirst => {
                // If allow list is configured, IP must be in it
                if !self.allow.is_empty() {
                    if self.allow.iter().any(|rule| ip_matches(client_ip, rule)) {
                        return PluginResult::Continue;
                    }
                    debug!("ip_restriction: IP '{}' not in allow list", client_ip);
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"IP address not allowed"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
                // Then check deny list
                if self.deny.iter().any(|rule| ip_matches(client_ip, rule)) {
                    debug!("ip_restriction: IP '{}' is denied", client_ip);
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"IP address denied"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
            }
            Mode::DenyFirst => {
                // Check deny list first
                if self.deny.iter().any(|rule| ip_matches(client_ip, rule)) {
                    debug!("ip_restriction: IP '{}' is denied", client_ip);
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"IP address denied"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
                // If allow list is configured and IP is not in it, deny
                if !self.allow.is_empty()
                    && !self.allow.iter().any(|rule| ip_matches(client_ip, rule))
                {
                    debug!("ip_restriction: IP '{}' not in allow list", client_ip);
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

/// Check if an IP address matches a rule (supports exact IPs, CIDR notation, and IPv6).
pub fn ip_matches(client_ip: &str, rule: &str) -> bool {
    // Exact match
    if client_ip == rule {
        return true;
    }

    // CIDR notation matching for IPv4
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
