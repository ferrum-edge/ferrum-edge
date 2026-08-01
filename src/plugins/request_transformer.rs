//! Request transformer plugin — modifies headers, query params, and body
//! before proxying.
//!
//! Header/query rules execute in `before_proxy` before the backend request is
//! built. Body rules execute in `transform_request_body` which forces the
//! request body to be buffered.
//!
//! Rules are validated and partitioned at construction time:
//!
//! - Unknown top-level and per-rule properties are rejected (no silent typos).
//! - Unknown `operation` / `target` values are rejected (no silent no-ops).
//! - Header/query operation fields are exact: only `add`/`update` accept
//!   `value`; only `rename` accepts `new_key`; `remove` accepts neither.
//! - Every configured header `value` must parse as an HTTP `HeaderValue`
//!   (same complete syntax accepted at H1/H2/H3 emission). CR/LF keep a
//!   dedicated diagnostic; other forbidden control bytes fail the same gate.
//! - Query `value` / `new_key` / `key` strings must not contain CR or LF
//!   (injection into the request-target). Names and values are otherwise
//!   percent-encoded when authored onto the outbound query.
//! - Rules are split into `header_rules` and `query_rules` so the hot path
//!   does not dispatch on target strings per request, and so
//!   [`modifies_request_headers`] returns an accurate answer (which lets the
//!   handler skip cloning `ctx.headers` for query-only or body-only configs).
//!
//! ## Query mutation contract
//!
//! Query rules mutate an ordered, duplicate-aware representation derived from
//! the retained raw wire query (not the single-value `query_params` map).
//! Authentication-owned credential pairs marked under
//! `auth.strip_query_param.*` are removed from that representation **before**
//! any query rules run, so a rename/update/duplicate cannot relocate or
//! re-encode an authenticated secret onto a new outbound name. The serialized
//! result is published on [`RequestContext::publish_transformed_query`] so
//! every primary dispatch surface and `request_mirror` share the same
//! canonical outbound query; the proxy still applies a final strip pass as
//! defense in depth. Unmodified pairs keep their original encoding; the
//! ordinary no-query-rule path allocates nothing and leaves the raw query
//! untouched.
//!
//! Duplicate-name semantics (decoded names):
//! - `add`: append only when the name is absent; existing duplicates stay.
//! - `update`: rewrite every matching pair's value; append when absent.
//! - `remove`: drop every matching pair.
//! - `rename`: rename every matching pair, preserving value encoding and
//!   key-without-equals shape; existing destination names are left in place.
//!
//! ## Per-rule overrides from `mesh_route_dispatch`
//!
//! When `mesh_route_dispatch` matches a rule that carries
//! `request_transform`, it publishes a pre-compiled `Arc` onto
//! [`RequestContext::route_override_request_transform`]. Each enabled
//! instance of this plugin applies only its **static** header/query rules in
//! `before_proxy`. Proxy core then applies the matched route list **exactly
//! once** after the last eligible (enabled) `request_transformer` in the
//! ordered chain — i.e. **all static rules run first, then route-level
//! writes**. That ordering is structural under multiple same-type instances
//! and priority overrides: a later static add/update/remove/rename cannot
//! recreate or overwrite a header the matched route removed or set.
//!
//! ## `apply_route_overrides` opt-in
//!
//! Setting `apply_route_overrides: true` on the plugin config lets the
//! instance carry zero static `rules`. The K8s VirtualService translator
//! uses this to auto-emit a `request_transformer` on proxies that do not
//! already have one, so per-rule route-level transforms still find an
//! eligible consumer for the chain-level final phase. Direct operator
//! configs without static rules and without this flag continue to be
//! rejected.
//!
//! ## RTDS overlay
//!
//! When `runtime_overlay_scope: "<scope>"` is set, the effective value of
//! `ferrum.request_transformer.<scope>.enabled` is bound into this instance's
//! configuration by mesh preparation and resolved ONCE, immutably, at
//! construction. A `false` value short-circuits the plugin (static rules
//! become no-ops) and the instance is **not** eligible for route-header
//! finalization, so it cannot consume or suppress route overrides needed by
//! a later enabled consumer. A scope the accepted overlay does not name
//! falls back to `default_enabled` (defaults to `true` so the gate is
//! fail-open).
//!
//! The gate is deliberately NOT read at request time (GHSA-83rc-23c9-3g9x).
//! Because it is resolved from configuration, the gate and the rules it gates
//! are one indivisible generation: they are validated together, built into one
//! plugin cache, and published in one `RequestEpoch`. A request that pinned an
//! epoch therefore observes a single complete accepted generation for its whole
//! lifetime — it is wholly enabled or wholly disabled across `before_proxy`,
//! query rules, and body transformation, no matter how long it is in flight or
//! how many overlay updates land meanwhile. That holds identically on H1, H2,
//! and H3, across retries and synthetic responses, and for every instance in a
//! multi-instance chain.

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use tracing::debug;

use super::utils::body_transform::{self, BodyRule};
use super::utils::query::OrderedQuery;
use super::utils::transformer_gate;
use super::{Plugin, PluginResult, RequestContext};

pub mod runtime_overlay;

/// Top-level config keys accepted by [`RequestTransformer::new`].
const CONFIG_KEYS: &[&str] = &[
    "rules",
    "apply_route_overrides",
    "runtime_overlay_scope",
    "default_enabled",
    // Reserved: written by mesh preparation from the accepted RTDS overlay so
    // the gate rides the same generation as the rules. See
    // `crate::plugins::utils::transformer_gate::RESOLVED_ENABLED_KEY`.
    transformer_gate::RESOLVED_ENABLED_KEY,
];

/// Per-rule keys accepted for header, query, and body rules.
const RULE_KEYS: &[&str] = &["operation", "target", "key", "value", "new_key"];

#[derive(Debug, Clone, Copy, PartialEq)]
enum HeaderOp {
    Add,
    Update,
    Remove,
    Rename,
}

#[derive(Debug, Clone)]
struct HeaderRule {
    operation: HeaderOp,
    /// Pre-lowercased header key.
    key: String,
    /// Required for add/update.
    value: Option<String>,
    /// Pre-lowercased new key, required for rename.
    new_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum QueryOp {
    Add,
    Update,
    Remove,
    Rename,
}

#[derive(Debug, Clone)]
struct QueryRule {
    operation: QueryOp,
    key: String,
    /// Required for add/update.
    value: Option<String>,
    /// Required for rename.
    new_key: Option<String>,
}

pub struct RequestTransformer {
    header_rules: Vec<HeaderRule>,
    query_rules: Vec<QueryRule>,
    body_rules: Vec<BodyRule>,
    /// Set by config field `apply_route_overrides`. When `true` the plugin
    /// instance accepts a zero-rule config and declares
    /// `modifies_request_headers() == true` so the dispatcher clones request
    /// headers for it. The K8s VirtualService translator uses this opt-in
    /// when auto-emitting a `request_transformer` whose sole purpose is to
    /// apply per-rule `mesh_route_dispatch` route-level transforms.
    apply_route_overrides: bool,
    /// The one immutable effective gate decision for this instance, resolved at
    /// construction from `runtime_overlay_scope`, the mesh-materialized
    /// `runtime_overlay_resolved_enabled`, and `default_enabled`.
    ///
    /// `true` for every instance that did not opt into an RTDS scope. Every
    /// request phase reads this field, so a request can never see the gate
    /// change underneath it and paired header/query/body rules can never be
    /// applied under different gate states (GHSA-83rc-23c9-3g9x). A gate change
    /// arrives as a new plugin instance in a new `RequestEpoch`; in-flight
    /// requests keep the generation they pinned.
    rules_enabled: bool,
}

fn parse_op(op: &str) -> Option<(HeaderOp, QueryOp)> {
    match op {
        "add" => Some((HeaderOp::Add, QueryOp::Add)),
        "update" => Some((HeaderOp::Update, QueryOp::Update)),
        "remove" => Some((HeaderOp::Remove, QueryOp::Remove)),
        "rename" => Some((HeaderOp::Rename, QueryOp::Rename)),
        _ => None,
    }
}

fn contains_crlf(s: &str) -> bool {
    s.bytes().any(|b| b == b'\r' || b == b'\n')
}

fn reject_unknown_keys(
    object: &Map<String, Value>,
    path: &str,
    allowed: &[&str],
) -> Result<(), String> {
    let mut unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort_unstable();
    Err(format!(
        "request_transformer: unknown config key(s) under '{path}': {}; allowed keys: {}",
        unknown.join(", "),
        allowed.join(", ")
    ))
}

/// Validate a configured header value the same way outbound Hyper / H3 /
/// reqwest adapters do (`HeaderValue::from_str`), while keeping the
/// historical CR/LF-specific diagnostic for injection typos.
fn validate_configured_header_value(value: &str, idx: usize) -> Result<(), String> {
    if contains_crlf(value) {
        return Err(format!(
            "request_transformer: rule[{idx}]: header 'value' must not contain CR or LF"
        ));
    }
    HeaderValue::from_str(value).map_err(|_| {
        format!("request_transformer: rule[{idx}]: header 'value' must be a valid HTTP HeaderValue")
    })?;
    Ok(())
}

fn validate_configured_query_string_field(
    field: &str,
    value: &str,
    idx: usize,
) -> Result<(), String> {
    if contains_crlf(value) {
        return Err(format!(
            "request_transformer: rule[{idx}]: query '{field}' must not contain CR or LF"
        ));
    }
    Ok(())
}

impl RequestTransformer {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config_obj = config.as_object().ok_or_else(|| {
            format!(
                "request_transformer: config must be an object; allowed keys: {}",
                CONFIG_KEYS.join(", ")
            )
        })?;
        reject_unknown_keys(config_obj, "config", CONFIG_KEYS)?;

        let mut header_rules: Vec<HeaderRule> = Vec::new();
        let mut query_rules: Vec<QueryRule> = Vec::new();

        if let Some(rules) = config.get("rules") {
            let arr = rules
                .as_array()
                .ok_or("request_transformer: 'rules' must be an array")?;
            for (idx, r) in arr.iter().enumerate() {
                let rule_obj = r.as_object().ok_or_else(|| {
                    format!("request_transformer: rule[{idx}]: rule must be an object")
                })?;
                let rule_path = format!("config.rules[{idx}]");
                reject_unknown_keys(rule_obj, &rule_path, RULE_KEYS)?;

                let target = match r.get("target") {
                    Some(Value::String(s)) => s.as_str(),
                    None => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'target' is required (expected header/query/body)"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'target' must be a string (expected header/query/body)"
                        ));
                    }
                };

                // Body rules are validated and collected by `parse_body_rules`
                // (required / incompatible fields). Unknown keys are already
                // rejected above.
                if target == "body" {
                    continue;
                }

                if target != "header" && target != "query" {
                    return Err(format!(
                        "request_transformer: rule[{idx}]: unknown target '{target}' (expected header/query/body)"
                    ));
                }

                let op_str = match r.get("operation") {
                    Some(Value::String(s)) => s.as_str(),
                    None => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'operation' is required"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'operation' must be a string"
                        ));
                    }
                };
                let (hop, qop) = parse_op(op_str).ok_or_else(|| {
                    format!(
                        "request_transformer: rule[{idx}]: unknown operation '{op_str}' (expected add/update/remove/rename)"
                    )
                })?;

                let raw_key = match r.get("key") {
                    Some(Value::String(s)) => s.clone(),
                    None => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'key' is required"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'key' must be a string"
                        ));
                    }
                };
                let value_present = rule_obj.contains_key("value");
                let value = match r.get("value") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'value' must be a string for header/query rules"
                        ));
                    }
                };
                let new_key_present = rule_obj.contains_key("new_key");
                let raw_new_key = match r.get("new_key") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'new_key' must be a string"
                        ));
                    }
                };

                // Per-operation required- and forbidden-field validation.
                // Incompatible extras are rejected rather than silently ignored
                // so typos cannot produce a different transform than intended.
                // Matches body-rule constraints in `body_transform`.
                match op_str {
                    "add" | "update" => {
                        if value.is_none() {
                            return Err(format!(
                                "request_transformer: rule[{idx}]: '{op_str}' operation requires a 'value'"
                            ));
                        }
                        if new_key_present {
                            return Err(format!(
                                "request_transformer: rule[{idx}]: 'new_key' must not be set for {target} '{op_str}' operation"
                            ));
                        }
                    }
                    "rename" => {
                        if value_present {
                            return Err(format!(
                                "request_transformer: rule[{idx}]: 'value' must not be set for {target} 'rename' operation"
                            ));
                        }
                        if raw_new_key.is_none() {
                            return Err(format!(
                                "request_transformer: rule[{idx}]: 'rename' operation requires a 'new_key'"
                            ));
                        }
                    }
                    "remove" => {
                        if value_present {
                            return Err(format!(
                                "request_transformer: rule[{idx}]: 'value' must not be set for {target} 'remove' operation"
                            ));
                        }
                        if new_key_present {
                            return Err(format!(
                                "request_transformer: rule[{idx}]: 'new_key' must not be set for {target} 'remove' operation"
                            ));
                        }
                    }
                    _ => {}
                }

                if target == "header" {
                    let key = HeaderName::from_bytes(raw_key.as_bytes())
                        .map_err(|_| {
                            format!(
                                "request_transformer: rule[{idx}]: 'key' must be a valid HTTP header name"
                            )
                        })?
                        .to_string();
                    let new_key = raw_new_key
                        .as_deref()
                        .map(|key| {
                            HeaderName::from_bytes(key.as_bytes())
                                .map_err(|_| {
                                    format!(
                                        "request_transformer: rule[{idx}]: 'new_key' must be a valid HTTP header name"
                                    )
                                })
                                .map(|name| name.to_string())
                        })
                        .transpose()?;

                    if let Some(ref v) = value {
                        validate_configured_header_value(v, idx)?;
                    }
                    header_rules.push(HeaderRule {
                        operation: hop,
                        key,
                        value,
                        new_key,
                    });
                } else {
                    validate_configured_query_string_field("key", &raw_key, idx)?;
                    if let Some(ref v) = value {
                        validate_configured_query_string_field("value", v, idx)?;
                    }
                    if let Some(ref nk) = raw_new_key {
                        validate_configured_query_string_field("new_key", nk, idx)?;
                    }
                    query_rules.push(QueryRule {
                        operation: qop,
                        key: raw_key,
                        value,
                        new_key: raw_new_key,
                    });
                }
            }
        }

        let body_rules = body_transform::parse_body_rules(config)
            .map_err(|e| format!("request_transformer: {e}"))?;

        let apply_route_overrides = match config.get("apply_route_overrides") {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => false,
            Some(_) => {
                return Err(
                    "request_transformer: 'apply_route_overrides' must be a boolean".to_string(),
                );
            }
        };

        if header_rules.is_empty()
            && query_rules.is_empty()
            && body_rules.is_empty()
            && !apply_route_overrides
        {
            return Err(
                "request_transformer: no 'rules' configured — plugin will have no effect"
                    .to_string(),
            );
        }

        let runtime_overlay_scope = match config.get("runtime_overlay_scope") {
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(
                        "request_transformer: runtime_overlay_scope must be a non-empty string"
                            .to_string(),
                    );
                }
                Some(trimmed.to_string())
            }
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(
                    "request_transformer: runtime_overlay_scope must be a string".to_string(),
                );
            }
        };

        let default_enabled = match config.get("default_enabled") {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => true,
            Some(_) => {
                return Err("request_transformer: default_enabled must be a boolean".to_string());
            }
        };

        let resolved_enabled = match config.get(transformer_gate::RESOLVED_ENABLED_KEY) {
            Some(Value::Bool(b)) => Some(*b),
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(format!(
                    "request_transformer: {} must be a boolean",
                    transformer_gate::RESOLVED_ENABLED_KEY
                ));
            }
        };

        // Resolve the gate exactly once, here. An instance without a scope is
        // unconditionally enabled; otherwise the accepted overlay's value for
        // this generation wins, falling back to the operator's `default_enabled`
        // when the overlay named no gate for the scope.
        let rules_enabled = if runtime_overlay_scope.is_some() {
            resolved_enabled.unwrap_or(default_enabled)
        } else {
            true
        };

        Ok(Self {
            header_rules,
            query_rules,
            body_rules,
            apply_route_overrides,
            rules_enabled,
        })
    }
}

#[async_trait]
impl Plugin for RequestTransformer {
    fn name(&self) -> &str {
        "request_transformer"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_TRANSFORMER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        // Per-rule overrides (`apply_route_overrides=true`) can mutate
        // headers even when this instance has no static `header_rules`, so
        // the dispatcher must clone request headers for it. Returning
        // `false` here would let the dispatcher hand `ctx.headers` itself
        // to plugins via `mem::take`, which both breaks the gateway-wide
        // "ctx.headers is the original inbound headers" invariant and (on
        // some paths) silently drops route-level header writes.
        self.rules_enabled && (!self.header_rules.is_empty() || self.apply_route_overrides)
    }

    fn modifies_request_query(&self) -> bool {
        !self.query_rules.is_empty()
    }

    fn participates_in_route_request_header_finalization(&self) -> bool {
        self.rules_enabled
    }

    fn modifies_request_body(&self) -> bool {
        // The gate is immutable for this plugin generation, so a disabled
        // instance can safely drop the config-time buffering capability too.
        // Otherwise the kill-switch would still retain every request body even
        // though no phase can consume or transform it.
        self.rules_enabled && !self.body_rules.is_empty()
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.rules_enabled {
            return PluginResult::Continue;
        }
        for rule in &self.header_rules {
            match rule.operation {
                HeaderOp::Add => {
                    if let Some(ref val) = rule.value {
                        headers.entry(rule.key.clone()).or_insert_with(|| {
                            debug!("request_transformer: added header {}", rule.key);
                            val.clone()
                        });
                    }
                }
                HeaderOp::Update => {
                    if let Some(ref val) = rule.value {
                        headers.insert(rule.key.clone(), val.clone());
                        debug!("request_transformer: set header {}", rule.key);
                    }
                }
                HeaderOp::Remove => {
                    headers.remove(&rule.key);
                    debug!("request_transformer: removed header {}", rule.key);
                }
                HeaderOp::Rename => {
                    if let Some(ref new_key) = rule.new_key
                        && let Some(val) = headers.remove(&rule.key)
                    {
                        debug!(
                            "request_transformer: renamed header {} -> {}",
                            rule.key, new_key
                        );
                        headers.insert(new_key.clone(), val);
                    }
                }
            }
        }
        if !self.query_rules.is_empty() {
            apply_query_rules(self, ctx);
        }
        // Route-level header transforms are applied exactly once by proxy core
        // after the last eligible request_transformer in the chain — see
        // `finalize_route_override_request_headers`. Do not take or apply them
        // here: a later same-type instance must still be able to run static
        // rules before that authoritative final phase.
        PluginResult::Continue
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // The same immutable decision `before_proxy` used. A marker header and
        // its paired body removal therefore cannot straddle a gate flip.
        if !self.rules_enabled {
            return None;
        }
        // Only transform JSON bodies. When Content-Type is absent, attempt
        // JSON parse anyway — the body_transform helper short-circuits on
        // parse failure, so the cost is one failed parse per non-JSON request.
        if let Some(ct) = content_type
            && !body_transform::is_json_content_type(ct)
        {
            return None;
        }
        body_transform::apply_body_rules(body, &self.body_rules)
    }
}

fn apply_query_rules(plugin: &RequestTransformer, ctx: &mut RequestContext) {
    // Prefer an earlier transformer's published outbound query, then the
    // retained raw wire query, then the decoded map for synthetic contexts.
    // Starting from raw after a prior instance already mutated would undo
    // earlier ordered rules when multiple request_transformer instances run.
    let mut ordered = if let Some(outbound) = ctx.outbound_query_string() {
        OrderedQuery::parse(outbound)
    } else if let Some(raw) = ctx.raw_query_string() {
        OrderedQuery::parse(raw)
    } else if !ctx.query_params.is_empty() {
        OrderedQuery::from_map(&ctx.query_params)
    } else {
        OrderedQuery::new()
    };

    // Fail-closed: strip authentication-owned credentials from the transform
    // input before any query rules run. A rename/update of a marked name must
    // not relocate or re-encode the authenticated secret onto the outbound
    // query or the plugin-visible map. The proxy still applies a final strip
    // pass as defense in depth.
    let strip_names: HashSet<&str> = ctx
        .metadata
        .keys()
        .filter_map(|key| {
            key.strip_prefix(
                crate::plugins::utils::token_extract::STRIP_QUERY_PARAM_METADATA_PREFIX,
            )
        })
        .collect();
    let mut query_mutated = ordered.remove_matching_names(&strip_names);

    for rule in &plugin.query_rules {
        match rule.operation {
            QueryOp::Add => {
                if let Some(ref val) = rule.value {
                    let changed = ordered.add(&rule.key, val);
                    if changed {
                        // Log only the parameter name — never the value (may be secret).
                        debug!("request_transformer: added query param {}", rule.key);
                    }
                    query_mutated |= changed;
                }
            }
            QueryOp::Update => {
                if let Some(ref val) = rule.value {
                    query_mutated |= ordered.update(&rule.key, val);
                    debug!("request_transformer: updated query param {}", rule.key);
                }
            }
            QueryOp::Remove => {
                let changed = ordered.remove(&rule.key);
                if changed {
                    debug!("request_transformer: removed query param {}", rule.key);
                }
                query_mutated |= changed;
            }
            QueryOp::Rename => {
                if let Some(ref new_key) = rule.new_key {
                    let changed = ordered.rename(&rule.key, new_key);
                    if changed {
                        debug!(
                            "request_transformer: renamed query param {} -> {}",
                            rule.key, new_key
                        );
                    }
                    query_mutated |= changed;
                }
            }
        }
    }

    if !query_mutated {
        return;
    }

    // Keep the plugin-visible map coherent with the ordered outbound query
    // (last occurrence wins), without forcing later consumers to re-parse.
    ctx.publish_transformed_query(ordered.serialize(), ordered.to_single_value_map());
    ctx.metadata.insert(
        crate::proxy::QUERY_PARAMS_TRANSFORMED_METADATA_KEY.to_string(),
        "true".to_string(),
    );
}
