//! Access Control List (ACL) plugin — post-authentication authorization.
//!
//! Runs in the `authorize` phase after authentication plugins have identified
//! the caller. On TCP and UDP stream proxies it applies the same checks in
//! `on_stream_connect` after a stream auth plugin has identified the caller.
//! By default this plugin is consumer-based only:
//! 1. **Consumer-based**: Allow/deny lists checked by consumer username (O(1) HashSet).
//! 2. **Group-based**: Allow/deny lists checked against the consumer's `acl_groups` (O(n·m)
//!    intersection, but both sets are small in practice).
//! 3. **Optional external-auth bypass**: `allow_authenticated_identity` permits
//!    requests that have `ctx.authenticated_identity` set but no mapped Consumer.
//!
//! IP-based access control lives in the `ip_restriction` plugin so all client-IP
//! enforcement is centralized in one place.
//!
//! Evaluation order: deny (consumer + group) → allow (consumer + group).
//! If no rules match, the request is allowed (open by default).

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tracing::warn;

use super::{Plugin, PluginResult, RequestContext, StreamConnectionContext};

pub struct AccessControl {
    /// O(1) consumer allow list (empty = no restriction).
    allowed_consumers: HashSet<String>,
    /// O(1) consumer deny list.
    disallowed_consumers: HashSet<String>,
    /// O(1) group allow list (empty = no restriction).
    allowed_groups: HashSet<String>,
    /// O(1) group deny list.
    disallowed_groups: HashSet<String>,
    /// When true, allow requests authenticated by an external auth plugin
    /// (for example `jwks_auth`) even if no gateway Consumer was mapped.
    allow_authenticated_identity: bool,
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

        let allowed_groups: HashSet<String> = config["allowed_groups"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let disallowed_groups: HashSet<String> = config["disallowed_groups"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let allow_authenticated_identity = config["allow_authenticated_identity"]
            .as_bool()
            .unwrap_or(false);

        if allowed.is_empty()
            && disallowed.is_empty()
            && allowed_groups.is_empty()
            && disallowed_groups.is_empty()
            && !allow_authenticated_identity
        {
            return Err(
                "access_control: at least one of 'allowed_consumers', 'disallowed_consumers', 'allowed_groups', 'disallowed_groups', or 'allow_authenticated_identity=true' is required".to_string()
            );
        }

        Ok(Self {
            allowed_consumers: allowed,
            disallowed_consumers: disallowed,
            allowed_groups,
            disallowed_groups,
            allow_authenticated_identity,
        })
    }

    fn authorize_identity(
        &self,
        client_ip: &str,
        identified_consumer: Option<&crate::config::types::Consumer>,
        authenticated_identity: Option<&str>,
    ) -> PluginResult {
        let consumer = match identified_consumer {
            Some(consumer) => consumer,
            None => {
                if self.allow_authenticated_identity && authenticated_identity.is_some() {
                    return PluginResult::Continue;
                }
                warn!(client_ip = %client_ip, plugin = "access_control", reason = "no_consumer", "No consumer identified for access control");
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"No consumer identified"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        let username = &consumer.username;

        // --- Deny checks (deny takes precedence) ---

        // Consumer username deny
        if self.disallowed_consumers.contains(username) {
            warn!(consumer = %username, client_ip = %client_ip, plugin = "access_control", reason = "consumer_disallowed", "Consumer rejected by access control");
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
                headers: HashMap::new(),
            };
        }

        // Group deny — if any of the consumer's groups are in the deny list
        if !self.disallowed_groups.is_empty() {
            for group in &consumer.acl_groups {
                if self.disallowed_groups.contains(group) {
                    warn!(consumer = %username, group = %group, client_ip = %client_ip, plugin = "access_control", reason = "group_disallowed", "Consumer rejected by access control (group)");
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"Consumer is not allowed"}"#.into(),
                        headers: HashMap::new(),
                    };
                }
            }
        }

        // --- Allow checks ---

        let has_allow_rules = !self.allowed_consumers.is_empty() || !self.allowed_groups.is_empty();

        if has_allow_rules {
            // Consumer username allow
            if self.allowed_consumers.contains(username) {
                return PluginResult::Continue;
            }

            // Group allow — if any of the consumer's groups are in the allow list
            if !self.allowed_groups.is_empty() {
                for group in &consumer.acl_groups {
                    if self.allowed_groups.contains(group) {
                        return PluginResult::Continue;
                    }
                }
            }

            // Neither username nor any group matched the allow lists
            warn!(consumer = %username, client_ip = %client_ip, plugin = "access_control", reason = "consumer_not_allowed", "Consumer not in allow list");
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
                headers: HashMap::new(),
            };
        }

        PluginResult::Continue
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

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_AND_STREAM_PROTOCOLS
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        self.authorize_identity(
            &ctx.client_ip,
            ctx.identified_consumer.as_deref(),
            ctx.authenticated_identity.as_deref(),
        )
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        self.authorize_identity(
            &ctx.client_ip,
            ctx.identified_consumer.as_deref(),
            ctx.authenticated_identity.as_deref(),
        )
    }
}
