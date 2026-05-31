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
//!    The `disallowed_consumers` list is still applied to the external identity
//!    string (e.g. JWKS `sub` claim), so operators can revoke a compromised
//!    externally-authenticated principal without a gateway Consumer mapping.
//!    Neither the consumer ALLOW-list nor the group allow/deny lists are applied
//!    to an unmapped external identity: there is no Consumer-mapped `acl_groups`,
//!    and `allowed_consumers` keys off gateway Consumer usernames rather than the
//!    external identity string. Because a blanket external-identity bypass and a
//!    strict consumer/group allow-list express contradictory intents, `new()`
//!    rejects `allow_authenticated_identity=true` combined with any allow-list
//!    (`allowed_consumers`/`allowed_groups`); the contradiction is caught at
//!    config validation instead of silently bypassing the allow-list for the
//!    whole class of externally-authenticated-but-unmapped callers.
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
    /// Precomputed allow-branch guard for the hot authorization path.
    has_allow_rules: bool,
}

impl AccessControl {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| format!("access_control: config must be an object, got: {config}"))?;

        reject_removed_ip_keys(object)?;
        reject_unknown_keys(object)?;

        let allowed = parse_string_set(object, "allowed_consumers")?;
        let disallowed = parse_string_set(object, "disallowed_consumers")?;
        let allowed_groups = parse_string_set(object, "allowed_groups")?;
        let disallowed_groups = parse_string_set(object, "disallowed_groups")?;
        let allow_authenticated_identity =
            parse_bool(object, "allow_authenticated_identity")?.unwrap_or(false);
        let has_allow_rules = !allowed.is_empty() || !allowed_groups.is_empty();

        if !has_allow_rules
            && disallowed.is_empty()
            && disallowed_groups.is_empty()
            && !allow_authenticated_identity
        {
            return Err(
                "access_control: at least one of 'allowed_consumers', 'disallowed_consumers', 'allowed_groups', 'disallowed_groups', or 'allow_authenticated_identity=true' is required".to_string()
            );
        }

        // A consumer/group allow-list and a blanket external-identity bypass are
        // contradictory intents. The allow-list keys off mapped-Consumer usernames
        // and `acl_groups`, which never apply to an unmapped external identity, so
        // enabling `allow_authenticated_identity` alongside an allow-list would
        // silently bypass that allow-list for every externally-authenticated-but-
        // unmapped caller. Reject the combination at construction so it fails
        // config validation instead of failing open at request time.
        if has_allow_rules && allow_authenticated_identity {
            return Err(
                "access_control: 'allow_authenticated_identity=true' cannot be combined with an allow-list ('allowed_consumers'/'allowed_groups'); the allow-list keys off mapped Consumers and is not applied to unmapped external identities, so the combination would bypass the allow-list".to_string()
            );
        }

        Ok(Self {
            allowed_consumers: allowed,
            disallowed_consumers: disallowed,
            allowed_groups,
            disallowed_groups,
            allow_authenticated_identity,
            has_allow_rules,
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
                if self.allow_authenticated_identity
                    && let Some(identity) = authenticated_identity
                {
                    // Apply the consumer deny list to the external identity string
                    // (e.g. JWKS `sub` claim). Group denylists are not applicable —
                    // external identities have no Consumer-mapped `acl_groups`. The
                    // allow-list (`allowed_consumers`/`allowed_groups`) is likewise
                    // not consulted here; `new()` rejects combining it with
                    // `allow_authenticated_identity`, so `has_allow_rules` is always
                    // false on this path.
                    if self.disallowed_consumers.contains(identity) {
                        warn!(
                            consumer = %identity,
                            client_ip = %client_ip,
                            plugin = "access_control",
                            reason = "external_identity_disallowed",
                            "External identity rejected by access control"
                        );
                        return PluginResult::Reject {
                            status_code: 403,
                            body: r#"{"error":"Identity is not allowed"}"#.into(),
                            headers: HashMap::new(),
                        };
                    }
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

        if self.has_allow_rules {
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

fn reject_removed_ip_keys(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    for key in ["allowed_ips", "blocked_ips"] {
        if object.contains_key(key) {
            return Err(format!(
                "access_control: '{key}' was removed; use the ip_restriction plugin for IP rules"
            ));
        }
    }
    Ok(())
}

/// Reject any unrecognized config key so a misspelled allow/deny key fails
/// config validation instead of being silently dropped (which would leave a
/// weaker-than-intended policy). Mirrors serde `deny_unknown_fields`. The
/// removed legacy IP keys are handled separately by `reject_removed_ip_keys`
/// with their own migration message.
fn reject_unknown_keys(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    const KNOWN_KEYS: [&str; 5] = [
        "allowed_consumers",
        "disallowed_consumers",
        "allowed_groups",
        "disallowed_groups",
        "allow_authenticated_identity",
    ];
    for key in object.keys() {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            return Err(format!("access_control: unknown config key '{key}'"));
        }
    }
    Ok(())
}

fn parse_string_set(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<HashSet<String>, String> {
    let Some(value) = object.get(field) else {
        return Ok(HashSet::new());
    };

    let values = value
        .as_array()
        .ok_or_else(|| format!("access_control: '{field}' must be an array of strings"))?;

    let mut parsed = HashSet::with_capacity(values.len());
    for entry in values {
        let Some(raw) = entry.as_str() else {
            return Err(format!("access_control: '{field}' entries must be strings"));
        };
        if raw.is_empty() {
            return Err(format!(
                "access_control: '{field}' entries must be non-empty strings"
            ));
        }
        parsed.insert(raw.to_string());
    }

    Ok(parsed)
}

fn parse_bool(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<bool>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("access_control: '{field}' must be a boolean"))
        })
        .transpose()
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

    fn is_authorize_plugin(&self) -> bool {
        true
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        self.authorize_identity(
            &ctx.client_ip,
            ctx.identified_consumer.as_deref(),
            ctx.authenticated_identity.as_deref(),
        )
    }
}
