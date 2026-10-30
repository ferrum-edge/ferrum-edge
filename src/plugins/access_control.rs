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
//! 4. **External-principal rules**: `allowed_external_identities` /
//!    `disallowed_external_identities` name exact unmapped external
//!    principals, optionally scoped to the authentication mechanism that
//!    verified them (`ExternalIdentityRealm::mechanism`). An external
//!    allow-list is a positive authorization for unmapped identities, so it is
//!    the narrow alternative to the blanket `allow_authenticated_identity`
//!    bypass (and, like the consumer allow-lists, cannot be combined with it).
//!
//! IP-based access control lives in the `ip_restriction` plugin so all client-IP
//! enforcement is centralized in one place.
//!
//! Evaluation order: deny (consumer + group) → allow (consumer + group).
//! If no allow-list is configured and no deny rule matches, the request is
//! allowed (open by default). Once ANY allow-list is configured (consumer,
//! group, or external identity), a principal that matches none of them is
//! denied — including a mapped Consumer on a policy whose only allow-list names
//! external identities.
//!
//! An omitted allow-list means "no allow restriction". An allow-list that is
//! present but empty is refused at construction (issue #6607): it would
//! otherwise read as "allow nobody" while behaving as "no restriction".

use crate::config::types::GatewayConfig;
use crate::plugins::utils::auth_flow::ExternalIdentityRealm;
use crate::plugins::utils::log_sampling::warn_sampled;

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use super::{Plugin, PluginResult, RequestContext, StreamConnectionContext};

// External principals (JWT/OIDC subjects, SPIFFE IDs, LDAP DNs, and similar)
// are not gateway Consumer usernames and can legitimately exceed the internal
// username ceiling. Keep an independent finite bound for exact deny rules and
// fail closed for larger external identities so no admitted principal is too
// large to revoke through this plugin.
const MAX_EXTERNAL_IDENTITY_LENGTH: usize = 4096;

/// Built-in authentication mechanisms that commit an unmapped external
/// principal together with its verified realm. An external-identity rule may
/// scope itself to one of these by name; any other value is refused at
/// construction so a misspelled mechanism cannot silently turn a scoped deny
/// rule into one that never matches.
const EXTERNAL_IDENTITY_MECHANISMS: [&str; 5] = [
    "jwks_auth",
    "ldap_auth",
    "oauth2_introspection",
    "oidc_relying_party",
    "soap_ws_security",
];

/// Every exact rule configured for one external identity string.
#[derive(Default)]
struct ExternalIdentityRule {
    /// An entry without `mechanism`: matches the identity from every realm.
    any_realm: bool,
    /// Mechanisms the identity's realm-scoped entries name.
    mechanisms: Vec<&'static str>,
}

impl ExternalIdentityRule {
    /// Whether this rule covers an identity committed under `realm`.
    ///
    /// `realm` is `None` when the identity did not come through the
    /// authentication commit boundary (stream contexts carry no realm, and a
    /// custom plugin may set the identity directly). A realm-scoped entry cannot
    /// tell whether such an identity is the one it names, so the caller decides
    /// the fail-closed direction: a deny rule matches it, an allow rule does not.
    fn matches(&self, realm: Option<ExternalIdentityRealm>, unknown_realm_matches: bool) -> bool {
        if self.any_realm {
            return true;
        }
        match realm {
            Some(realm) => self.mechanisms.contains(&realm.mechanism()),
            None => unknown_realm_matches,
        }
    }
}

pub struct AccessControl {
    /// O(1) consumer allow list (empty = no restriction).
    allowed_consumers: HashSet<String>,
    /// O(1) consumer deny list.
    disallowed_consumers: HashSet<String>,
    /// O(1) group allow list (empty = no restriction).
    allowed_groups: HashSet<String>,
    /// O(1) group deny list.
    disallowed_groups: HashSet<String>,
    /// Exact unmapped external principals that are allowed, optionally scoped
    /// to the verifying mechanism (empty = no external allow-list).
    allowed_external_identities: HashMap<String, ExternalIdentityRule>,
    /// Exact unmapped external principals that are denied, optionally scoped
    /// to the verifying mechanism.
    disallowed_external_identities: HashMap<String, ExternalIdentityRule>,
    /// When true, allow requests authenticated by an external auth plugin
    /// (for example `jwks_auth`) even if no gateway Consumer was mapped.
    allow_authenticated_identity: bool,
    /// Precomputed allow-branch guard for the hot authorization path: true
    /// when ANY allow-list (consumer, group, or external identity) is set.
    has_allow_rules: bool,
}

impl AccessControl {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config.as_object().ok_or_else(|| {
            format!(
                "access_control: config must be an object, got: {config:?}",
                config = config.to_string()
            )
        })?;

        reject_removed_ip_keys(object)?;
        reject_unknown_keys(object)?;
        reject_explicitly_empty_allow_lists(object)?;

        let allowed = parse_string_set(
            object,
            "allowed_consumers",
            crate::config::types::MAX_USERNAME_LENGTH,
        )?;
        let disallowed =
            parse_string_set(object, "disallowed_consumers", MAX_EXTERNAL_IDENTITY_LENGTH)?;
        let allowed_groups = parse_string_set(
            object,
            "allowed_groups",
            crate::config::types::MAX_ACL_GROUP_LENGTH,
        )?;
        let disallowed_groups = parse_string_set(
            object,
            "disallowed_groups",
            crate::config::types::MAX_ACL_GROUP_LENGTH,
        )?;
        let allowed_external_identities =
            parse_external_identity_rules(object, "allowed_external_identities")?;
        let disallowed_external_identities =
            parse_external_identity_rules(object, "disallowed_external_identities")?;
        let allow_authenticated_identity =
            parse_bool(object, "allow_authenticated_identity")?.unwrap_or(false);
        let has_allow_rules = !allowed.is_empty()
            || !allowed_groups.is_empty()
            || !allowed_external_identities.is_empty();

        if !has_allow_rules
            && disallowed.is_empty()
            && disallowed_groups.is_empty()
            && disallowed_external_identities.is_empty()
            && !allow_authenticated_identity
        {
            return Err(
                "access_control: at least one of `allowed_consumers`, `disallowed_consumers`, `allowed_groups`, `disallowed_groups`, `allowed_external_identities`, `disallowed_external_identities`, or `allow_authenticated_identity=true` is required".to_string()
            );
        }

        // A consumer/group allow-list and a blanket external-identity bypass are
        // contradictory intents. The allow-list keys off mapped-Consumer usernames
        // and `acl_groups`, which never apply to an unmapped external identity, so
        // enabling `allow_authenticated_identity` alongside an allow-list would
        // silently bypass that allow-list for every externally-authenticated-but-
        // unmapped caller. Reject the combination at construction so it fails
        // config validation instead of failing open at request time. An
        // external-identity allow-list contradicts the bypass the same way: the
        // bypass would admit every external identity the allow-list omits.
        if has_allow_rules && allow_authenticated_identity {
            return Err(
                "access_control: `allow_authenticated_identity=true` cannot be combined with an allow-list (`allowed_consumers`/`allowed_groups`/`allowed_external_identities`); the consumer allow-lists key off mapped Consumers and are not applied to unmapped external identities, and the bypass would admit every external identity an external allow-list omits, so the combination would bypass the allow-list".to_string()
            );
        }

        Ok(Self {
            allowed_consumers: allowed,
            disallowed_consumers: disallowed,
            allowed_groups,
            disallowed_groups,
            allowed_external_identities,
            disallowed_external_identities,
            allow_authenticated_identity,
            has_allow_rules,
        })
    }

    fn authorize_identity(
        &self,
        client_ip: &str,
        identified_consumer: Option<&crate::config::types::Consumer>,
        authenticated_identity: Option<&str>,
        authenticated_identity_realm: Option<ExternalIdentityRealm>,
    ) -> PluginResult {
        let authenticated_identity = super::meaningful_identity(authenticated_identity);
        let consumer = match identified_consumer {
            Some(consumer) => consumer,
            None => {
                if let Some(identity) = authenticated_identity {
                    return self.authorize_external_identity(
                        client_ip,
                        identity,
                        authenticated_identity_realm,
                    );
                }
                warn_sampled!(
                    client_ip = %client_ip,
                    plugin = "access_control",
                    reason = "no_consumer",
                    "No consumer identified for access control"
                );
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
            warn_sampled!(
                consumer = %username,
                client_ip = %client_ip,
                plugin = "access_control",
                reason = "consumer_disallowed",
                "Consumer rejected by access control"
            );
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
                    warn_sampled!(
                        consumer = %username,
                        group = %group,
                        client_ip = %client_ip,
                        plugin = "access_control",
                        reason = "group_disallowed",
                        "Consumer rejected by access control (group)"
                    );
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

            // Neither username nor any group matched the allow lists. This
            // also denies every mapped Consumer when the only allow-list
            // configured is `allowed_external_identities`: an allow-list means
            // "only these principals", never "these external principals plus
            // every Consumer".
            warn_sampled!(
                consumer = %username,
                client_ip = %client_ip,
                plugin = "access_control",
                reason = "consumer_not_allowed",
                "Consumer not in allow list"
            );
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
                headers: HashMap::new(),
            };
        }

        PluginResult::Continue
    }

    /// Authorize an unmapped external principal (no Consumer was identified).
    ///
    /// Admission needs either the blanket `allow_authenticated_identity` bypass
    /// or a matching `allowed_external_identities` entry; `new()` refuses the
    /// two together. Deny rules run first: `disallowed_consumers` is applied to
    /// the raw identity string from every realm, and a
    /// `disallowed_external_identities` entry applies to its scoped realm (or
    /// to every realm when it names no mechanism). The consumer and group
    /// allow-lists never apply here: an unmapped identity has no Consumer
    /// username or `acl_groups`.
    fn authorize_external_identity(
        &self,
        client_ip: &str,
        identity: &str,
        realm: Option<ExternalIdentityRealm>,
    ) -> PluginResult {
        if !self.allow_authenticated_identity && self.allowed_external_identities.is_empty() {
            warn_sampled!(
                client_ip = %client_ip,
                plugin = "access_control",
                reason = "external_identity_not_authorized",
                "Authenticated external identity rejected by access control"
            );
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Authenticated identity is not authorized"}"#.into(),
                headers: HashMap::new(),
            };
        }
        if identity.chars().count() > MAX_EXTERNAL_IDENTITY_LENGTH {
            warn_sampled!(
                client_ip = %client_ip,
                plugin = "access_control",
                reason = "external_identity_too_long",
                "External identity exceeded access-control admission bound"
            );
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Identity is not allowed"}"#.into(),
                headers: HashMap::new(),
            };
        }
        // A realm-scoped deny entry also matches an identity whose realm is
        // unknown: it cannot rule out that this is the principal it revokes.
        if self.disallowed_consumers.contains(identity)
            || self
                .disallowed_external_identities
                .get(identity)
                .is_some_and(|rule| rule.matches(realm, true))
        {
            warn_sampled!(
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
        if !self.allowed_external_identities.is_empty() {
            // A realm-scoped allow entry never matches an identity whose realm
            // is unknown: admission must be positively established.
            if self
                .allowed_external_identities
                .get(identity)
                .is_some_and(|rule| rule.matches(realm, false))
            {
                return PluginResult::Continue;
            }
            warn_sampled!(
                client_ip = %client_ip,
                plugin = "access_control",
                reason = "external_identity_not_allowed",
                "External identity not in allow list"
            );
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Identity is not allowed"}"#.into(),
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
                "access_control: `{key}` was removed; use the ip_restriction plugin for IP rules"
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
    const KNOWN_KEYS: [&str; 7] = [
        "allowed_consumers",
        "disallowed_consumers",
        "allowed_groups",
        "disallowed_groups",
        "allowed_external_identities",
        "disallowed_external_identities",
        "allow_authenticated_identity",
    ];
    for key in object.keys() {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            return Err(format!("access_control: unknown config key {key:?}"));
        }
    }
    Ok(())
}

/// Refuse an allow-list that is present but empty.
///
/// An omitted allow-list means "no allow restriction". An explicitly empty one
/// reads like "allow nobody", but with no entries there is nothing to match, so
/// treating it as "no restriction" would silently open a route an operator was
/// emptying to lock it down. Neither reading is safe to guess, so the
/// configuration is refused and the operator must omit the key or name at
/// least one principal.
fn reject_explicitly_empty_allow_lists(
    object: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    for key in [
        "allowed_consumers",
        "allowed_groups",
        "allowed_external_identities",
    ] {
        if object
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|entries| entries.is_empty())
        {
            return Err(format!(
                "access_control: `{key}` must not be an empty array; omit it for no allow \
                 restriction, or list at least one entry (an empty allow-list does not mean \
                 deny-all)"
            ));
        }
    }
    Ok(())
}

fn parse_string_set(
    object: &serde_json::Map<String, Value>,
    field: &str,
    max_length: usize,
) -> Result<HashSet<String>, String> {
    let Some(value) = object.get(field) else {
        return Ok(HashSet::new());
    };

    let values = value
        .as_array()
        .ok_or_else(|| format!("access_control: `{field}` must be an array of strings"))?;

    let mut parsed = HashSet::with_capacity(values.len());
    for entry in values {
        let Some(raw) = entry.as_str() else {
            return Err(format!("access_control: `{field}` entries must be strings"));
        };
        // Rules are stored byte-for-byte. Principals are never canonicalized:
        // Consumer usernames may legally carry padding and external identity
        // claims are preserved byte-for-byte (`meaningful_identity`), so
        // trimming a rule like " alice " would silently rewrite it to a value
        // that can never match the padded principal it targets — a fail-open
        // deny-list. Only whitespace-only entries are rejected.
        if raw.trim().is_empty() {
            return Err(format!(
                "access_control: `{field}` entries must contain non-whitespace characters"
            ));
        }
        let raw_length = raw.chars().count();
        if raw_length > max_length {
            return Err(format!(
                "access_control: `{field}` entries must not exceed {max_length} characters"
            ));
        }
        parsed.insert(raw.to_string());
    }

    Ok(parsed)
}

/// Parse `allowed_external_identities` / `disallowed_external_identities`.
///
/// Each entry is `{ "identity": <exact principal>, "mechanism": <optional> }`.
/// The identity follows the same admission rules as the string lists (stored
/// byte-for-byte, non-whitespace, at most [`MAX_EXTERNAL_IDENTITY_LENGTH`]
/// characters); `mechanism`, when present, must name one of
/// [`EXTERNAL_IDENTITY_MECHANISMS`]. Several entries for one identity merge:
/// an unscoped entry covers every realm. Error messages never echo the
/// supplied values.
fn parse_external_identity_rules(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<HashMap<String, ExternalIdentityRule>, String> {
    let Some(value) = object.get(field) else {
        return Ok(HashMap::new());
    };

    let entries = value
        .as_array()
        .ok_or_else(|| format!("access_control: `{field}` must be an array of objects"))?;

    let mut rules: HashMap<String, ExternalIdentityRule> = HashMap::with_capacity(entries.len());
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            return Err(format!(
                "access_control: `{field}` entries must be objects with an `identity` string"
            ));
        };
        if entry
            .keys()
            .any(|key| key != "identity" && key != "mechanism")
        {
            return Err(format!(
                "access_control: `{field}` entries accept only `identity` and `mechanism`"
            ));
        }
        let Some(identity) = entry.get("identity").and_then(Value::as_str) else {
            return Err(format!(
                "access_control: `{field}` entries must carry an `identity` string"
            ));
        };
        if identity.trim().is_empty() {
            return Err(format!(
                "access_control: `{field}` entry `identity` must contain non-whitespace characters"
            ));
        }
        if identity.chars().count() > MAX_EXTERNAL_IDENTITY_LENGTH {
            return Err(format!(
                "access_control: `{field}` entry `identity` must not exceed \
                 {MAX_EXTERNAL_IDENTITY_LENGTH} characters"
            ));
        }
        let mechanism = match entry.get("mechanism") {
            None => None,
            Some(value) => {
                let known = value.as_str().and_then(|raw| {
                    EXTERNAL_IDENTITY_MECHANISMS
                        .iter()
                        .copied()
                        .find(|mechanism| *mechanism == raw)
                });
                let Some(known) = known else {
                    return Err(format!(
                        "access_control: `{field}` entry `mechanism` must be one of {}",
                        EXTERNAL_IDENTITY_MECHANISMS.join(", ")
                    ));
                };
                Some(known)
            }
        };
        let rule = rules.entry(identity.to_string()).or_default();
        match mechanism {
            None => rule.any_realm = true,
            Some(mechanism) => {
                if !rule.mechanisms.contains(&mechanism) {
                    rule.mechanisms.push(mechanism);
                }
            }
        }
    }

    Ok(rules)
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
                .ok_or_else(|| format!("access_control: `{field}` must be a boolean"))
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

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::NONE
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_AND_STREAM_PROTOCOLS
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        self.authorize_identity(
            &ctx.client_ip,
            ctx.identified_consumer.as_deref(),
            ctx.authenticated_identity.as_deref(),
            ctx.authenticated_identity_realm,
        )
    }

    fn is_authorize_plugin(&self) -> bool {
        true
    }

    /// `authorize` is a pure function of the request's client IP, mapped
    /// Consumer, and authenticated identity (with its realm) against this
    /// instance's immutable allow/deny sets: no budget, no permit, no mutation
    /// of `ctx`, and no external call. Safe for the HBONE admission fence to
    /// re-run against a live tunnel. The fence re-reads the mapped Consumer
    /// record from the generation it judges before re-running this, so an ACL
    /// group or username change — or the Consumer's deletion — reaches live
    /// tunnels too, not only a changed plugin config.
    fn reevaluates_live_admission(&self) -> bool {
        true
    }

    /// Reusable (issue #5583), and for the SAME reason
    /// `reevaluates_live_admission` above is `true`: the verdict is a pure
    /// function of the request's identity inputs and this instance's immutable
    /// allow/deny sets, so the only things that can flip it for a live tunnel
    /// are a new generation carrying different sets or a different record for
    /// the mapped Consumer — and the sweep re-resolves that record from the
    /// judged generation's Consumer index. Every published generation
    /// requests a fence sweep
    /// (`ProxyState::publish_request_epoch_with_gateway_trust`), and the sweep
    /// re-runs exactly this `authorize` against the admitting request context
    /// under the new generation's view — so the decision reuse elides is
    /// re-issued, on the one event that could change it, for the tunnel's whole
    /// life. Both halves are load-bearing: dropping
    /// `reevaluates_live_admission` would strand this verdict at the admitting
    /// generation and must drop this with it.
    fn allows_hbone_inner_reuse(&self) -> bool {
        true
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        // Stream contexts carry no verified realm, so realm-scoped external
        // rules see an unknown realm: scoped denies match, scoped allows do not.
        self.authorize_identity(
            &ctx.client_ip,
            ctx.identified_consumer.as_deref(),
            ctx.authenticated_identity.as_deref(),
            None,
        )
    }
}

/// Whether an `access_control` plugin config names `username` in
/// `allowed_consumers` or `disallowed_consumers`, byte-for-byte.
///
/// A Consumer RENAME is refused while this holds for the OLD username (in the
/// SQL and MongoDB stores and on a file-mode reload): matching is exact, so the
/// rename would silently detach an allow entry (leaving it for a later Consumer
/// created under that username to inherit) or a deny entry (un-revoking the
/// renamed principal). Delete needs only the allow side, because a deleted
/// Consumer cannot be admitted under any name.
pub fn config_names_consumer_username(config: &Value, username: &str) -> bool {
    ["allowed_consumers", "disallowed_consumers"]
        .iter()
        .any(|key| {
            config
                .get(*key)
                .and_then(Value::as_array)
                .is_some_and(|entries| entries.iter().any(|entry| entry.as_str() == Some(username)))
        })
}

/// File-mode analogue of the store rename guard: every Consumer that
/// `candidate` renames (same namespace and id as in `previous`, different
/// username) while one of `candidate`'s `access_control` plugin configs in that
/// namespace still names the previous username. Each entry is a diagnostic
/// naming only resource ids, never usernames.
///
/// A reload that renames the Consumer AND rewrites the plugin config's entry in
/// the same file is accepted: it is the candidate's lists that are checked.
pub fn consumer_rename_conflicts(
    previous: &GatewayConfig,
    candidate: &GatewayConfig,
) -> Vec<String> {
    let previous_usernames: HashMap<(&str, &str), &str> = previous
        .consumers
        .iter()
        .map(|consumer| {
            (
                (consumer.namespace.as_str(), consumer.id.as_str()),
                consumer.username.as_str(),
            )
        })
        .collect();
    let mut conflicts = Vec::new();
    for consumer in &candidate.consumers {
        let Some(previous_username) =
            previous_usernames.get(&(consumer.namespace.as_str(), consumer.id.as_str()))
        else {
            continue;
        };
        if *previous_username == consumer.username.as_str() {
            continue;
        }
        if let Some(plugin) = candidate.plugin_configs.iter().find(|plugin| {
            plugin.plugin_name == "access_control"
                && plugin.namespace == consumer.namespace
                && config_names_consumer_username(&plugin.config, previous_username)
        }) {
            conflicts.push(format!(
                "consumer {:?} in namespace {:?} cannot be renamed while access_control \
                 plugin_config {:?} still names its previous username",
                consumer.id, consumer.namespace, plugin.id
            ));
        }
    }
    conflicts
}
