use async_trait::async_trait;
use serde_json::Value;
use tracing::debug;

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

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        // Check IP-based access control first
        let client_ip = &ctx.client_ip;

        // Check if IP is explicitly blocked
        if self
            .blocked_ips
            .iter()
            .any(|blocked_ip| ip_matches(client_ip, blocked_ip))
        {
            debug!("access_control: IP '{}' is blocked", client_ip);
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"IP address is blocked"}"#.into(),
            };
        }

        // Check if allowed IPs are configured and IP is not in allowed list
        if !self.allowed_ips.is_empty()
            && !self
                .allowed_ips
                .iter()
                .any(|allowed_ip| ip_matches(client_ip, allowed_ip))
        {
            debug!("access_control: IP '{}' not in allowed list", client_ip);
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"IP address not allowed"}"#.into(),
            };
        }

        let consumer = match &ctx.identified_consumer {
            Some(c) => c,
            None => {
                debug!("access_control: no consumer identified, rejecting");
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"No consumer identified"}"#.into(),
                };
            }
        };

        let username = &consumer.username;

        // Check disallowed first
        if self.disallowed_consumers.contains(username) {
            debug!("access_control: consumer '{}' is disallowed", username);
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
            };
        }

        // If allowed list is configured, consumer must be in it
        if !self.allowed_consumers.is_empty() && !self.allowed_consumers.contains(username) {
            debug!(
                "access_control: consumer '{}' not in allowed list",
                username
            );
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
            };
        }

        PluginResult::Continue
    }
}

/// Check if an IP address matches a rule (supports exact IPs and CIDR notation).
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

        // Parse both IPs as IPv4
        let client_octets = match parse_ipv4(client_ip) {
            Some(o) => o,
            None => return false,
        };
        let network_octets = match parse_ipv4(network_str) {
            Some(o) => o,
            None => return false,
        };

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
