use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tracing::warn;

use super::ip_restriction::{ParsedRule, parse_client_ip, parse_rule, rule_matches};
use super::{Plugin, PluginResult, RequestContext};

pub struct AccessControl {
    /// O(1) consumer allow list (empty = no restriction).
    allowed_consumers: HashSet<String>,
    /// O(1) consumer deny list.
    disallowed_consumers: HashSet<String>,
    /// Pre-parsed IP allow rules (integer comparison at request time).
    allowed_ips: Vec<ParsedRule>,
    /// Pre-parsed IP block rules (integer comparison at request time).
    blocked_ips: Vec<ParsedRule>,
}

impl AccessControl {
    pub fn new(config: &Value) -> Result<Self, String> {
        let allowed: HashSet<String> = config["allowed_consumers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let disallowed: HashSet<String> = config["disallowed_consumers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let allowed_ips: Vec<ParsedRule> = config["allowed_ips"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(parse_rule)
                    .collect()
            })
            .unwrap_or_default();

        let blocked_ips: Vec<ParsedRule> = config["blocked_ips"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(parse_rule)
                    .collect()
            })
            .unwrap_or_default();

        if allowed.is_empty()
            && disallowed.is_empty()
            && allowed_ips.is_empty()
            && blocked_ips.is_empty()
        {
            return Err(
                "access_control: at least one of 'allowed_consumers', 'disallowed_consumers', 'allowed_ips', or 'blocked_ips' is required".to_string()
            );
        }

        Ok(Self {
            allowed_consumers: allowed,
            disallowed_consumers: disallowed,
            allowed_ips,
            blocked_ips,
        })
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
        // Parse client IP once for all rule checks (integer ops from here on)
        let client_ip = parse_client_ip(&ctx.client_ip);

        // Check if IP is explicitly blocked
        if self
            .blocked_ips
            .iter()
            .any(|rule| rule_matches(&client_ip, rule))
        {
            warn!(client_ip = %ctx.client_ip, plugin = "access_control", reason = "ip_blocked", "IP address blocked by access control");
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
                .any(|rule| rule_matches(&client_ip, rule))
        {
            warn!(client_ip = %ctx.client_ip, plugin = "access_control", reason = "ip_not_allowed", "IP address not in allow list");
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"IP address not allowed"}"#.into(),
                headers: HashMap::new(),
            };
        }

        let consumer = match &ctx.identified_consumer {
            Some(c) => c,
            None => {
                // If only IP rules are configured (no consumer rules), allow through
                if self.allowed_consumers.is_empty() && self.disallowed_consumers.is_empty() {
                    return PluginResult::Continue;
                }
                warn!(client_ip = %ctx.client_ip, plugin = "access_control", reason = "no_consumer", "No consumer identified for access control");
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"No consumer identified"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        let username = &consumer.username;

        // O(1) check: consumer deny list
        if self.disallowed_consumers.contains(username) {
            warn!(consumer = %username, client_ip = %ctx.client_ip, plugin = "access_control", reason = "consumer_disallowed", "Consumer rejected by access control");
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
                headers: HashMap::new(),
            };
        }

        // O(1) check: consumer allow list (if configured, consumer must be in it)
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
