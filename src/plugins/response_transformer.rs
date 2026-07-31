//! Response transformer plugin — modifies response headers and body after
//! proxying.
//!
//! Header rules (add/remove/update/rename) execute in `after_proxy`. Body
//! rules require `requires_response_body_buffering()` = true so the response
//! body is collected before being forwarded to the client. The pre-header
//! decision is deliberately conservative: a client `Accept: text/event-stream`
//! value cannot release an ordinary JSON backend response. Once the backend
//! headers arrive, a genuine `text/event-stream` response is released through
//! `should_buffer_response_body_for_content_type()` so unbounded SSE remains
//! streaming.
//!
//! Rules are validated at construction time:
//!
//! - Unknown top-level and per-rule properties are rejected (no silent typos).
//! - Unknown `operation` / `target` values are rejected (no silent no-ops).
//! - Header operation fields are exact: only `add`/`update` accept `value`;
//!   only `rename` accepts `new_key`; `remove` accepts neither.
//! - Every configured header `value` must parse as an HTTP `HeaderValue`
//!   (same complete syntax accepted at H1/H2/H3 emission), including
//!   rejection of non-CR/LF forbidden control bytes.
//! - Header keys are pre-lowercased.
//! - Protocol-managed hop-by-hop and framing destinations (`Connection`,
//!   `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Connection`, `TE`, `Trailer`,
//!   `Transfer-Encoding`, `Upgrade`, `Content-Length`) are rejected for
//!   `add`/`update` and as rename destinations. `remove` of those names remains
//!   allowed. The gateway's final client-wire sanitizer derives `Content-Length`
//!   and strips connection/framing fields after every mutable response hook.
//!
//! ## Per-rule overrides from `mesh_route_dispatch`
//!
//! `mesh_route_dispatch` publishes per-rule
//! `route_override_response_transform` Arcs onto `RequestContext`. This
//! plugin applies them at the end of `after_proxy` — i.e. **static rules
//! run first, then per-rule overrides** — so route-level writes win on
//! conflict. The `apply_route_overrides: true` opt-in mirrors the
//! `request_transformer` counterpart: it lets the K8s VirtualService
//! translator auto-emit a `response_transformer` with zero static rules
//! whose only job is to act as a consumer for per-rule overrides.
//!
//! ## RTDS overlay
//!
//! When `runtime_overlay_scope: "<scope>"` is set, the effective value of
//! `ferrum.response_transformer.<scope>.enabled` is bound into this
//! instance's configuration by mesh preparation and resolved ONCE,
//! immutably, at construction. A `false` value short-circuits rule
//! application (static rules AND route-overlay overrides). A scope the
//! accepted overlay does not name falls back to `default_enabled`
//! (defaults to `true` — fail-open).
//!
//! The gate is deliberately NOT read at request time (GHSA-83rc-23c9-3g9x).
//! That matters most on this side, because the response pipeline consults the
//! gate at four points that are separated by real time — buffering preflight
//! (before backend headers), the header capability simulation, `after_proxy`
//! (after backend latency), and body transformation. A request-time gate let
//! those disagree: a `false` preflight selected streaming and a later `true`
//! header phase then applied header rules to a response whose body rules had no
//! buffered body left to run on, shipping a response marked as sanitized but
//! unredacted. Resolving from configuration makes buffer/stream selection and
//! every later hook read one immutable decision by construction, so the
//! preflight answer and the enforcement answer cannot diverge.
//!
//! A gate change is now a new plugin generation rather than a mutation of live
//! state, but that does not by itself protect a representation which OUTLIVES
//! the generation that produced it — a `response_caching` entry or a
//! Redis-persisted `request_deduplication` replay. This plugin does not try to
//! detect that from the replay path: a finalized replay
//! carries no evidence of which policy shaped it, and re-running rules on a
//! guess would double-apply non-idempotent `add` sequences. Instead the
//! plugins that retain a representation stamp it with the policy it was
//! produced under and retire it when that policy moves, so newly enabled
//! redaction applies exactly once and the unconditional
//! `finalized_response_replay` skip below stays intact:
//!
//! - `response_caching` stores the opaque identity paired atomically with the
//!   response-side gate map (pinned by
//!   `RequestContext::pin_response_policy_stamp`) and refetches from the origin
//!   when that identity no longer matches. Its entries never outlive the plugin
//!   instance, and a config reload builds a new instance with an empty cache,
//!   so static rules cannot change underneath them.
//! - `request_deduplication` persists to Redis, where an entry outlives the
//!   instance, the cache generation, and the process. A gate identity is
//!   meaningless there, so it stores content digests instead: the gate map's
//!   content *and* the per-proxy fold of every enrolled plugin's
//!   `response_presentation_policy()` — this plugin's being the digest of its
//!   whole accepted static config. A rule edit that leaves the gate map
//!   untouched therefore still retires every replay captured before it, as does
//!   a change to any other presentation plugin the replay path skips (`sse`) or
//!   to their configured order. A plugin whose rewrite is not a function of
//!   configuration at all (`mcp_gateway`, driven by live upstream discovery)
//!   cannot be folded in and is refused composition with deduplication
//!   entirely.
//!
//! ## Representation metadata after a body rewrite
//!
//! When a body rule actually changes the client-visible JSON bytes, the shared
//! body-transform lifecycle and this plugin's `on_response_body_transformed`
//! hook remove origin validators and integrity fields that no longer describe
//! those bytes (`ETag`, `Last-Modified`, `Content-Digest`, `Repr-Digest`,
//! legacy `Digest`, `Content-MD5`, and related content-bound checksum /
//! signature headers). `Last-Modified` is dropped rather than rewritten: it
//! names when the origin representation changed, not the gateway-authored
//! rewrite. Parse failures and semantic no-ops return `None` from
//! `transform_response_body` and leave origin metadata untouched.

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use tracing::debug;

use super::response_representation::effective_response_media_type;
use super::utils::body_transform::{self, BodyRule};
use super::utils::policy_digest;
use super::utils::route_header_transform::{
    RouteHeaderTransformOp, RouteHeaderTransformRule, apply_route_header_transforms,
    apply_route_header_transforms_tracked,
};
use super::utils::sse::is_text_event_stream_media_type;
use super::utils::transformer_gate;
use super::{Plugin, PluginResult, RequestContext};
use crate::util::http_headers::{cache_control_has_directive, etag_value_is_strong};

pub mod runtime_overlay;

/// Top-level config keys accepted by [`ResponseTransformer::new`].
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

/// Per-rule keys accepted for both header and body rules.
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

pub struct ResponseTransformer {
    header_rules: Vec<HeaderRule>,
    /// Pre-lowercased keys of static `update` rules. These are unconditional
    /// gateway overwrites, so a completed `after_proxy` owns them on a gRPC
    /// deadline rebuild even when the backend pre-populated the identical value
    /// (mutation tracking alone cannot see an exact-value write). Precomputed
    /// once so the deadline-provenance path allocates nothing per request.
    static_update_keys: Vec<String>,
    body_rules: Vec<BodyRule>,
    /// The one immutable effective gate decision for this instance, resolved at
    /// construction from `runtime_overlay_scope`, the mesh-materialized
    /// `runtime_overlay_resolved_enabled`, and `default_enabled`.
    ///
    /// `true` for every instance that did not opt into an RTDS scope. Every
    /// phase — buffering preflight, retry release, header simulation,
    /// `after_proxy`, and body transformation — reads this one field, so the
    /// buffer/stream selection and the later header/body hooks are guaranteed to
    /// agree (GHSA-83rc-23c9-3g9x).
    rules_enabled: bool,
    /// Content-derived digest of this instance's whole accepted static config.
    ///
    /// Computed once at construction from the canonical form of the validated
    /// configuration, so it covers every present and future static knob —
    /// header rules, body rules, `apply_route_overrides`,
    /// `runtime_overlay_scope`, `default_enabled` — without an enumeration that
    /// could silently fall behind a new field. Plugins that persist a finalized
    /// representation bind this value so a retained replay can never outlive
    /// the rules that produced it. Only the digest is ever exposed; the source
    /// config (which may carry operator-authored header values) is not retained.
    ///
    /// Since the accepted RTDS gate is now materialized INTO that configuration
    /// as `runtime_overlay_resolved_enabled`, this digest also covers the
    /// effective gate — per instance, which is strictly finer than the
    /// process-global gate-map fingerprint `request_deduplication` folds
    /// alongside it. Do not "simplify" that fingerprint away on the grounds that
    /// the gate is now in the config: the two are independent provenance inputs
    /// and the Redis-persisted replay contract binds both.
    static_policy_digest: [u8; 32],
}

/// Domain separator and schema version for [`ResponseTransformer`] provenance.
/// Bumping the version invalidates every previously persisted representation
/// rather than letting an old digest match new semantics.
const STATIC_POLICY_DIGEST_DOMAIN: &str = "ferrum.plugin.response_transformer.static.v1";

impl ResponseTransformer {
    fn static_rules_may_modify_content_type(&self) -> bool {
        self.header_rules.iter().any(|rule| match rule.operation {
            HeaderOp::Add | HeaderOp::Update | HeaderOp::Remove => rule.key == "content-type",
            HeaderOp::Rename => {
                rule.key == "content-type" || rule.new_key.as_deref() == Some("content-type")
            }
        })
    }

    fn route_rules_may_modify_content_type(ctx: &RequestContext) -> bool {
        ctx.route_override_response_transform
            .as_ref()
            .is_some_and(|rules| rules.iter().any(|rule| rule.key == "content-type"))
    }

    fn static_rules_may_add_cache_control_no_transform(&self) -> bool {
        self.header_rules.iter().any(|rule| match rule.operation {
            HeaderOp::Add | HeaderOp::Update => {
                rule.key == "cache-control"
                    && rule
                        .value
                        .as_deref()
                        .is_some_and(|value| cache_control_has_directive(value, "no-transform"))
            }
            HeaderOp::Remove => false,
            HeaderOp::Rename => rule.new_key.as_deref() == Some("cache-control"),
        })
    }

    fn route_rules_may_add_cache_control_no_transform(ctx: &RequestContext) -> bool {
        ctx.route_override_response_transform
            .as_ref()
            .is_some_and(|rules| {
                rules.iter().any(|rule| match rule.operation {
                    RouteHeaderTransformOp::Add | RouteHeaderTransformOp::Update => {
                        rule.key == "cache-control"
                            && rule.value.as_deref().is_some_and(|value| {
                                cache_control_has_directive(value, "no-transform")
                            })
                    }
                    RouteHeaderTransformOp::Remove => false,
                })
            })
    }

    fn static_rules_may_add_strong_etag(&self) -> bool {
        self.header_rules.iter().any(|rule| match rule.operation {
            HeaderOp::Add | HeaderOp::Update => {
                rule.key == "etag" && rule.value.as_deref().is_some_and(etag_value_is_strong)
            }
            HeaderOp::Remove => false,
            HeaderOp::Rename => rule.new_key.as_deref() == Some("etag"),
        })
    }

    fn route_rules_may_add_strong_etag(ctx: &RequestContext) -> bool {
        ctx.route_override_response_transform
            .as_ref()
            .is_some_and(|rules| {
                rules.iter().any(|rule| match rule.operation {
                    RouteHeaderTransformOp::Add | RouteHeaderTransformOp::Update => {
                        rule.key == "etag"
                            && rule.value.as_deref().is_some_and(etag_value_is_strong)
                    }
                    RouteHeaderTransformOp::Remove => false,
                })
            })
    }

    /// `fired_write_keys`, when `Some`, collects every key this rule set wrote
    /// WHOLE — that is, wrote a complete value that net-diff mutation tracking
    /// cannot be relied on to notice:
    ///
    /// * the destination key of every `rename` that actually fired. A rename can
    ///   land a value on the destination that is byte-identical to something a
    ///   backend could have sent (the backend may even have sent that exact
    ///   destination header itself), and mutation tracking sees only the source
    ///   removal.
    /// * the key of every `add` that actually INSERTED (a static `add` fires only
    ///   into an absent slot). An `add` following a `remove` of the same key can
    ///   leave the final map byte-identical to the backend's, so the net diff is
    ///   empty even though the gateway authored the surviving value.
    ///
    /// Callers that track gRPC-deadline provenance pass a sink and declare these
    /// keys owned; everyone else passes `None` and stays allocation-free.
    fn apply_static_header_rules(
        &self,
        response_headers: &mut HashMap<String, String>,
        emit_debug: bool,
        mut fired_write_keys: Option<&mut Vec<String>>,
    ) {
        for rule in &self.header_rules {
            match rule.operation {
                HeaderOp::Add => {
                    if let Some(value) = rule.value.as_ref()
                        && let Entry::Vacant(slot) = response_headers.entry(rule.key.clone())
                    {
                        // A static `add` only ever fires into an ABSENT slot, so
                        // the whole inserted value is gateway-authored. Record it
                        // for the same reason as a fired `rename` destination: an
                        // `add` that follows a `remove` of the same key can leave
                        // the map byte-identical to the backend's, and net-diff
                        // mutation tracking would then never credit the
                        // reintroduced header — silently dropping it from a
                        // synthesized DEADLINE_EXCEEDED response.
                        if emit_debug {
                            debug!("response_transformer: added header {}", rule.key);
                        }
                        slot.insert(value.clone());
                        if let Some(sink) = fired_write_keys.as_mut() {
                            sink.push(rule.key.clone());
                        }
                    }
                }
                HeaderOp::Update => {
                    if let Some(value) = rule.value.as_ref() {
                        response_headers.insert(rule.key.clone(), value.clone());
                        if emit_debug {
                            debug!("response_transformer: set header {}", rule.key);
                        }
                    }
                }
                HeaderOp::Remove => {
                    response_headers.remove(&rule.key);
                    if emit_debug {
                        debug!("response_transformer: removed header {}", rule.key);
                    }
                }
                HeaderOp::Rename => {
                    if let Some(new_key) = rule.new_key.as_ref()
                        && let Some(value) = response_headers.remove(&rule.key)
                    {
                        if emit_debug {
                            debug!(
                                "response_transformer: renamed header {} -> {}",
                                rule.key, new_key
                            );
                        }
                        response_headers.insert(new_key.clone(), value);
                        if let Some(sink) = fired_write_keys.as_mut() {
                            sink.push(new_key.clone());
                        }
                    }
                }
            }
        }
    }
}

fn parse_op(op: &str) -> Option<HeaderOp> {
    match op {
        "add" => Some(HeaderOp::Add),
        "update" => Some(HeaderOp::Update),
        "remove" => Some(HeaderOp::Remove),
        "rename" => Some(HeaderOp::Rename),
        _ => None,
    }
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
        "response_transformer: unknown config key(s) under '{path}': {}; allowed keys: {}",
        unknown.join(", "),
        allowed.join(", ")
    ))
}

impl ResponseTransformer {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config_obj = config.as_object().ok_or_else(|| {
            format!(
                "response_transformer: config must be an object; allowed keys: {}",
                CONFIG_KEYS.join(", ")
            )
        })?;
        reject_unknown_keys(config_obj, "config", CONFIG_KEYS)?;

        let mut header_rules: Vec<HeaderRule> = Vec::new();

        if let Some(rules) = config.get("rules") {
            let arr = rules
                .as_array()
                .ok_or("response_transformer: 'rules' must be an array")?;
            for (idx, r) in arr.iter().enumerate() {
                let rule_obj = r.as_object().ok_or_else(|| {
                    format!("response_transformer: rule[{idx}]: rule must be an object")
                })?;
                let rule_path = format!("config.rules[{idx}]");
                reject_unknown_keys(rule_obj, &rule_path, RULE_KEYS)?;

                let target = match r.get("target") {
                    Some(Value::String(s)) => s.as_str(),
                    None => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'target' is required (expected header/body)"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'target' must be a string (expected header/body)"
                        ));
                    }
                };

                if target == "body" {
                    // Body rules are validated by `parse_body_rules` (required /
                    // incompatible fields). Unknown keys are already rejected above.
                    continue;
                }

                if target != "header" {
                    return Err(format!(
                        "response_transformer: rule[{idx}]: unknown target '{target}' (expected header/body)"
                    ));
                }

                let op_str = match r.get("operation") {
                    Some(Value::String(s)) => s.as_str(),
                    None => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'operation' is required"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'operation' must be a string"
                        ));
                    }
                };
                let operation = parse_op(op_str).ok_or_else(|| {
                    format!(
                        "response_transformer: rule[{idx}]: unknown operation '{op_str}' (expected add/update/remove/rename)"
                    )
                })?;

                let raw_key = match r.get("key") {
                    Some(Value::String(s)) => s.clone(),
                    None => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'key' is required"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'key' must be a string"
                        ));
                    }
                };
                let key = HeaderName::from_bytes(raw_key.as_bytes())
                    .map_err(|_| {
                        format!(
                            "response_transformer: rule[{idx}]: 'key' must be a valid HTTP header name"
                        )
                    })?
                    .to_string();
                let value_present = rule_obj.contains_key("value");
                let value = match r.get("value") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'value' must be a string for header rules"
                        ));
                    }
                };
                let new_key_present = rule_obj.contains_key("new_key");
                let raw_new_key = match r.get("new_key") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'new_key' must be a string"
                        ));
                    }
                };
                let new_key = raw_new_key
                    .as_deref()
                    .map(|key| {
                        HeaderName::from_bytes(key.as_bytes())
                            .map_err(|_| {
                                format!(
                                    "response_transformer: rule[{idx}]: 'new_key' must be a valid HTTP header name"
                                )
                            })
                            .map(|name| name.to_string())
                    })
                    .transpose()?;

                // Per-operation required- and forbidden-field validation.
                // Incompatible extras are rejected rather than silently ignored
                // so typos cannot produce a different transform than intended.
                match operation {
                    HeaderOp::Add | HeaderOp::Update => {
                        if value.is_none() {
                            return Err(format!(
                                "response_transformer: rule[{idx}]: '{op_str}' operation requires a 'value'"
                            ));
                        }
                        if new_key_present {
                            return Err(format!(
                                "response_transformer: rule[{idx}]: 'new_key' must not be set for header '{op_str}' operation"
                            ));
                        }
                    }
                    HeaderOp::Rename => {
                        if value_present {
                            return Err(format!(
                                "response_transformer: rule[{idx}]: 'value' must not be set for header 'rename' operation"
                            ));
                        }
                        if raw_new_key.is_none() {
                            return Err(format!(
                                "response_transformer: rule[{idx}]: 'rename' operation requires a 'new_key'"
                            ));
                        }
                    }
                    HeaderOp::Remove => {
                        if value_present {
                            return Err(format!(
                                "response_transformer: rule[{idx}]: 'value' must not be set for header 'remove' operation"
                            ));
                        }
                        if new_key_present {
                            return Err(format!(
                                "response_transformer: rule[{idx}]: 'new_key' must not be set for header 'remove' operation"
                            ));
                        }
                    }
                }

                if let Some(ref v) = value {
                    HeaderValue::from_str(v).map_err(|_| {
                        format!(
                            "response_transformer: rule[{idx}]: header 'value' must be a valid HTTP HeaderValue"
                        )
                    })?;
                }

                // Protocol-managed framing / connection-control destinations are
                // owned by the final client-wire sanitizer. Reject add/update of
                // those keys and rename *to* those keys so a later instance or a
                // backend-controlled rename source cannot reintroduce them after
                // origin hop-by-hop strip. `remove` remains allowed.
                match operation {
                    HeaderOp::Add | HeaderOp::Update => {
                        if crate::proxy::headers::is_protocol_managed_plugin_response_destination(
                            &key,
                        ) {
                            return Err(format!(
                                "response_transformer: rule[{idx}]: header '{op_str}' destination \
                                 '{key}' is protocol-managed (hop-by-hop or framing) and cannot be \
                                 configured; the gateway derives Content-Length and strips \
                                 Connection/Transfer-Encoding/Trailer/Upgrade at the final \
                                 response boundary"
                            ));
                        }
                    }
                    HeaderOp::Rename => {
                        if let Some(ref dest) = new_key
                            && crate::proxy::headers::is_protocol_managed_plugin_response_destination(
                                dest,
                            )
                        {
                            return Err(format!(
                                "response_transformer: rule[{idx}]: rename destination '{dest}' is \
                                 protocol-managed (hop-by-hop or framing) and cannot be configured; \
                                 a backend-controlled source value must not become Connection, \
                                 Transfer-Encoding, Trailer, Upgrade, or Content-Length"
                            ));
                        }
                    }
                    HeaderOp::Remove => {}
                }

                header_rules.push(HeaderRule {
                    operation,
                    key,
                    value,
                    new_key,
                });
            }
        }

        let body_rules = body_transform::parse_body_rules(config)
            .map_err(|e| format!("response_transformer: {e}"))?;

        let apply_route_overrides = match config.get("apply_route_overrides") {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => false,
            Some(_) => {
                return Err(
                    "response_transformer: 'apply_route_overrides' must be a boolean".to_string(),
                );
            }
        };

        if header_rules.is_empty() && body_rules.is_empty() && !apply_route_overrides {
            return Err(
                "response_transformer: no 'rules' configured — plugin will have no effect"
                    .to_string(),
            );
        }

        // `apply_route_overrides` is parsed and validated above so the
        // K8s VirtualService translator can auto-emit a `response_transformer`
        // with zero static rules whose only purpose is to consume
        // `ctx.route_override_response_transform` Arcs in `after_proxy`.
        // The flag is config-time only — the runtime path consults `ctx`
        // unconditionally — so we drop it after construction.
        let _ = apply_route_overrides;

        let runtime_overlay_scope = match config.get("runtime_overlay_scope") {
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(
                        "response_transformer: runtime_overlay_scope must be a non-empty string"
                            .to_string(),
                    );
                }
                Some(trimmed.to_string())
            }
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(
                    "response_transformer: runtime_overlay_scope must be a string".to_string(),
                );
            }
        };

        let default_enabled = match config.get("default_enabled") {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => true,
            Some(_) => {
                return Err("response_transformer: default_enabled must be a boolean".to_string());
            }
        };

        let resolved_enabled = match config.get(transformer_gate::RESOLVED_ENABLED_KEY) {
            Some(Value::Bool(b)) => Some(*b),
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(format!(
                    "response_transformer: {} must be a boolean",
                    transformer_gate::RESOLVED_ENABLED_KEY
                ));
            }
        };

        // Resolve the gate exactly once, here — see the struct field docs.
        let rules_enabled = if runtime_overlay_scope.is_some() {
            resolved_enabled.unwrap_or(default_enabled)
        } else {
            true
        };

        let static_update_keys = header_rules
            .iter()
            .filter(|rule| rule.operation == HeaderOp::Update)
            .map(|rule| rule.key.clone())
            .collect::<Vec<_>>();

        // Digest the accepted configuration as a whole. Every rule that shapes
        // the client-visible representation is in here by construction, so a
        // redaction/header/body edit that leaves the RTDS gate map untouched
        // still changes the provenance a persisted replay is bound to.
        let static_policy_digest =
            policy_digest::static_config_digest(STATIC_POLICY_DIGEST_DOMAIN, config);

        Ok(Self {
            header_rules,
            static_update_keys,
            body_rules,
            rules_enabled,
            static_policy_digest,
        })
    }
}

/// Whether these bytes are framed gRPC that the LIVE response `Content-Type` no
/// longer admits to describing.
///
/// The representation gate reads `content-type` from the live header map, which
/// `after_proxy` has already had a chance to rewrite. A header rule that removes
/// or relabels a framed gRPC response's type would otherwise land it on the
/// untyped/JSON branch of the claim predicate: the gate would then hand
/// length-prefixed frames to a JSON field rule, fail to parse them as a bare
/// document, and answer `unparseable_document` — a `502` replacing a valid RPC
/// reply on a mixed HTTP/gRPC proxy.
///
/// Two independent pieces of pre-hook evidence answer it, and neither can be
/// relabelled mid-pipeline:
///
/// * The **pristine media type** stamped by
///   [`crate::proxy::stamp_original_response_metadata`] before any `after_proxy`
///   hook ran. If the backend's own `Content-Type` was framed gRPC, it stays
///   framed no matter what the live header says now. This is the same
///   snapshot-over-live-map discipline the gate already applies to content
///   coding and range/delta state.
/// * The **request's immutable flavor** — `is_native_grpc_request` (fixed before
///   any hook) and the separately retained gRPC-Web representation, the pair the
///   rejection shaper already trusts to pick the client's error flavor. This
///   covers the case where no media type was ever stamped, so the snapshot
///   cannot speak. The flavor only SELECTS the grammar there; the bytes then
///   have to satisfy it in full — see "the untyped case is decided on the
///   BYTES" below. A live type present without a pristine one does not settle
///   it either: `after_proxy` can add or relabel a type on a response the
///   backend sent untyped, so that label describes nothing the backend proved.
///
/// Deliberately NOT a decline: a gRPC-Web request whose backend genuinely
/// answered with a bare `application/json` document. The pristine type proves
/// that body is not framed, a field rule can act on it, and the transform does
/// rewrite it — so it stays claimed and the redaction still applies. Keying the
/// decline off the request flavor alone would have silently dropped that
/// redaction, which is the wrong direction for a fail-closed gate.
///
/// Likewise NOT a decline: an ordinary HTTP request with an absent or vendor
/// `+json` response `Content-Type`. That claim is the earlier absent-type fix and
/// is untouched here — this predicate only fires for gRPC/gRPC-Web traffic.
///
/// # The untyped case is decided on the BYTES, not the flavor
///
/// When neither the snapshot nor the live map names a type, the request flavor
/// alone cannot answer, and treating it as proof of framing was a fail-OPEN: a
/// mixed gRPC route whose backend returns a bare JSON error/envelope document
/// with no `Content-Type` would be declined by both this predicate and the
/// transform, so a configured redaction over that document never ran while the
/// operator believed it had. `response_transformer` otherwise treats an absent
/// type as JSON precisely so that class stays covered.
///
/// The bytes settle it, and they settle it by a TOTAL PARSE — never a sniff —
/// against the ONE grammar the client's representation actually admits.
/// [`super::grpc_web::client_grpc_framing_representation`] picks that grammar
/// from immutable request state, and
/// [`super::grpc_web::bytes_are_complete_grpc_frames`] then accepts only a byte
/// string that is exactly a sequence of complete frames legal in it: DATA frames
/// for native gRPC, DATA plus an optional FINAL trailer frame for gRPC-Web
/// binary, and the base64 of that for gRPC-Web text. Testing the union of all
/// three instead was the bypass — base64 text that decodes to frames on a native
/// or binary request, or a body trailer frame on a native one, is not a
/// representation those clients can receive, and excusing it as framing skipped
/// the fail-closed rejection the gate exists to make.
///
/// No grammar can collide with a JSON document: a frame's first octet is a
/// `Compressed-Flag`/trailer flag (`0x00`, `0x01`, `0x80`, `0x81`) and base64
/// excludes `{`, `[`, and `"`. So valid framing is never claimed and spuriously
/// rejected as an unparseable document, and a bare document is never waved
/// through unredacted — the two failure directions this predicate keeps apart.
///
/// Malformed, truncated, or mode-illegal framing is not "framed" and therefore
/// stays claimed; it then fails the gate's JSON parse and is rejected. That is
/// the documented fail-closed posture — the gateway cannot prove a redaction
/// applied to bytes it cannot parse, and a truncated frame sequence or a trailer
/// with data after it is not a servable complete representation either.
fn framed_grpc_request_without_proven_media_type(
    ctx: &RequestContext,
    response_body: &[u8],
) -> bool {
    let pristine_content_type = ctx
        .metadata
        .get(crate::proxy::ORIGINAL_RESPONSE_CONTENT_TYPE_METADATA_KEY)
        .map(String::as_str);

    if let Some(pristine) = pristine_content_type {
        // The backend's own type is authoritative over any later rewrite.
        return body_transform::is_framed_grpc_content_type(pristine);
    }

    // No stamped type to consult, so the BYTES decide — including when a live
    // `Content-Type` is present.
    //
    // The live map cannot stand in for the missing snapshot here: an
    // `after_proxy` hook is free to ADD or relabel a type on a response the
    // backend sent untyped, and `application/json` invented by such a hook is
    // not evidence about bytes the backend never described. Returning early on
    // any live type let that hook-authored label claim a complete gRPC/gRPC-Web
    // frame sequence as a JSON document, which the gate then failed to parse and
    // replaced with a `502 unparseable_document` — a valid RPC reply destroyed
    // by a header rule. A PRISTINE type still wins outright above; only the
    // unproven post-hook label yields to a total frame parse.
    //
    // Deciding it on a total parse is what keeps this from re-opening the
    // earlier fail-open: bytes that are not exactly complete frames stay
    // claimed, so a genuine JSON document under a hook-added (or hook-removed)
    // type is redacted exactly as before. The request's representation selects
    // the grammar and the bytes must satisfy exactly that one. Asking the union
    // of all three grammars was the other gap: base64 is a legal body only for a
    // text-mode gRPC-Web client, and a body trailer frame only for a gRPC-Web
    // one, so accepting either on a native gRPC request let a non-RPC byte
    // string pass as framing and skip the fail-closed rejection.
    let Some(representation) = super::grpc_web::client_grpc_framing_representation(ctx) else {
        return false;
    };
    super::grpc_web::bytes_are_complete_grpc_frames(response_body, representation)
}

/// Whether the response's media type admits this plugin's JSON body rules.
///
/// Mirrors the media-type half of [`Plugin::transform_response_body`] exactly,
/// but over the RESOLVED type rather than the raw live header: a framed gRPC
/// label that neither the pristine snapshot nor a total frame parse supports is
/// an `after_proxy`/translation artifact, not a description of these bytes, and
/// must not decline them. See
/// [`super::response_representation::effective_response_media_type`].
fn media_type_admits_body_rules(
    ctx: &RequestContext,
    response_content_type: Option<&str>,
    response_body: &[u8],
) -> bool {
    let media_type = effective_response_media_type(ctx, response_content_type, response_body);
    media_type.is_none_or(|ct| {
        body_transform::is_json_content_type(ct) && !body_transform::is_framed_grpc_content_type(ct)
    })
}

#[async_trait]
impl Plugin for ResponseTransformer {
    fn name(&self) -> &str {
        "response_transformer"
    }

    fn priority(&self) -> u16 {
        super::priority::RESPONSE_TRANSFORMER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    /// This plugin *is* the presentation policy a finalized replay skips, so it
    /// enrolls unconditionally — including when its rules are gated off for this
    /// generation. Enrolling only while enabled would hide the static rules of a
    /// disabled instance from a representation stored while it was disabled.
    ///
    /// `Static` is accurate, and since GHSA-83rc-23c9-3g9x it is accurate
    /// without qualification: every rule this plugin applies to a response body
    /// comes from its accepted configuration, the effective RTDS gate is now
    /// part of that configuration (`runtime_overlay_resolved_enabled`, folded
    /// into [`Self::static_policy_digest`]), and the instance holds no interior
    /// mutable state. So this digest — not the separately published gate map —
    /// is the complete witness of what this instance does to a representation.
    /// The one non-config input, `ctx.route_override_response_transform`, is
    /// header-only and is consumed without being applied on a finalized replay.
    fn response_presentation_policy(&self) -> Option<super::ResponsePresentationPolicy> {
        Some(super::ResponsePresentationPolicy::Static(
            self.static_policy_digest,
        ))
    }

    fn requires_buffered_grpc_web_trailer_policy(&self, ctx: &RequestContext) -> bool {
        self.rules_enabled
            && (!self.header_rules.is_empty() || ctx.route_override_response_transform.is_some())
    }

    fn requires_response_body_buffering(&self) -> bool {
        // `rules_enabled` is immutable for this generation, so a disabled
        // instance has no body hook to schedule and need not advertise the
        // cache-level buffering capability.
        self.rules_enabled && !self.body_rules.is_empty()
    }

    fn may_modify_response_content_type(
        &self,
        ctx: &RequestContext,
        _response_content_type: Option<&str>,
    ) -> bool {
        // Whether a rule fires is decided by config/route state, not the
        // backend response type, so the backend `Content-Type` is not consulted.
        self.rules_enabled
            && (self.static_rules_may_modify_content_type()
                || Self::route_rules_may_modify_content_type(ctx))
    }

    fn may_add_response_cache_control_no_transform(
        &self,
        ctx: &RequestContext,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.rules_enabled
            && (self.static_rules_may_add_cache_control_no_transform()
                || Self::route_rules_may_add_cache_control_no_transform(ctx))
    }

    fn may_add_response_strong_etag(
        &self,
        ctx: &RequestContext,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.rules_enabled
            && (self.static_rules_may_add_strong_etag()
                || Self::route_rules_may_add_strong_etag(ctx))
    }

    fn simulate_after_proxy_response_headers(
        &self,
        ctx: &mut RequestContext,
        response_headers: &mut HashMap<String, String>,
    ) {
        if !self.rules_enabled {
            return;
        }
        // Finalized cache/idempotent replays already carry post-transform
        // headers. Consume any route override without re-applying it.
        if ctx.finalized_response_replay {
            let _ = ctx.route_override_response_transform.take();
            return;
        }
        self.apply_static_header_rules(response_headers, false, None);
        if let Some(route_rules) = ctx.route_override_response_transform.take() {
            apply_route_header_transforms(route_rules.as_ref(), response_headers);
        }
    }

    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        // Honor the RTDS runtime kill-switch here, mirroring the early
        // `return None` in `transform_response_body`. When the overlay disables
        // this scope the transform is a no-op, so we must not pin the response
        // into the buffered path — otherwise a disabled transform still buffers
        // a large/streaming non-SSE response until the max-response-body limit
        // and then 502s, defeating the very buffering relief the kill-switch is
        // meant to provide. (Finding #64.) `self.rules_enabled` is the SAME
        // immutable decision `after_proxy` and `transform_response_body` read, so
        // this preflight answer and the later enforcement answer are identical by
        // construction: a gate that moves after this point cannot leave a
        // streaming-selected response to be header-marked as transformed while
        // its body rules have no buffered body to run on (GHSA-83rc-23c9-3g9x).
        //
        // Do NOT key this pre-header decision off the client-controlled Accept
        // header. A client can ask for SSE while the selected backend response
        // is ordinary JSON; releasing here would stream that JSON past every
        // configured body rule. Buffer conservatively until response headers
        // arrive, then let `should_buffer_response_body_for_content_type`
        // release a response that actually declares itself as event-stream.
        !self.body_rules.is_empty() && self.rules_enabled
    }

    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        // Retry-enabled dispatch buffers responses by default so a failed
        // attempt remains replayable. Opt into the header-first refinement only
        // while this plugin is the reason for buffering; the confirmation hook
        // below still releases solely a representation the body rules cannot
        // transform. The shared retry refinement separately refuses release if
        // any active plugin may rewrite Content-Type.
        self.should_buffer_response_body(ctx)
    }

    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && response_headers
                .get("content-type")
                .is_some_and(|content_type| is_text_event_stream_media_type(content_type))
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        // Body transforms operate on an assembled JSON document. A backend
        // response that actually declares `text/event-stream` is outside that
        // policy and must be released after headers rather than collected until
        // the response-body ceiling. Missing, JSON, and every ambiguous type
        // stay on the conservative buffered path. The shared refinement refuses
        // this downgrade when any later hook may rewrite Content-Type, so a
        // relabel cannot bypass the final client-visible policy decision.
        self.should_buffer_response_body(ctx)
            && !content_type.is_some_and(is_text_event_stream_media_type)
    }

    fn enforces_response_body_policy(
        &self,
        ctx: &RequestContext,
        response_content_type: Option<&str>,
        response_body: &[u8],
    ) -> bool {
        // Claim exactly the responses the transform phase would actually
        // rewrite, so the shared representation gate fails closed on those and
        // leaves every other response alone. The declines below are the
        // plugin's own documented no-ops, not inspection failures:
        //   * no configured `body_rules` — there is no body policy at all;
        //   * the RTDS kill-switch disabled this scope, mirroring the early
        //     `return None` in `transform_response_body`.
        //
        // Client SSE intent is NOT among them, and its absence is load-bearing.
        // The pre-header buffering vote cannot trust `Accept: text/event-stream`:
        // the backend may still return ordinary JSON. Header-time refinement
        // releases a response that genuinely declares `text/event-stream`, and
        // the media-type condition below declines that representation. If an
        // operator or another plugin nevertheless keeps the response buffered,
        // the lifecycle runs `transform_response_body_with_context` over it no
        // matter what this predicate said. Declining merely because the request
        // asked for SSE would make the gate answer `Unprotected`; an encoded,
        // `206`, or unparseable JSON response could then reach the transform,
        // return `None`, and cross with the configured redaction skipped.
        //
        // Claiming it is also the direction that keeps working traffic working.
        // An SSE-accepting request whose response is a complete JSON document is
        // fully inspectable and its redaction applies; the media-type condition
        // below declines a response that genuinely IS `text/event-stream`,
        // because that is not a JSON content type.
        //
        // The media-type condition mirrors `transform_response_body` EXACTLY,
        // and that symmetry is the whole point: this predicate must claim every
        // response the transform would actually rewrite, or the gate declines to
        // inspect bytes the enforcer then fails to parse — which is the very
        // `None`-conflation bypass the gate exists to close.
        //
        // So an ABSENT `Content-Type` is claimed, because the transform treats
        // it as JSON (`if let Some(ct) = content_type && !is_json => None`, i.e.
        // `None` falls through to `apply_body_rules`). Declining it here while
        // the enforcer accepts it would let an untyped `gzip`/`206`/malformed
        // response carry a protected field straight past a configured redaction.
        // A non-JSON type stays a documented decline, matching the same early
        // return in the transform.
        //
        // Consequence, accepted deliberately: an untyped response that is not
        // parseable JSON is now rejected rather than forwarded when a body
        // policy is configured. That is the fail-closed direction, and it only
        // affects proxies that configured a body redaction *and* have a backend
        // that omits `Content-Type` — an operator-visible backend defect, not
        // ordinary traffic.
        //
        // Framed gRPC is the one media-type family excluded on top of that,
        // because `application/grpc+json` (and the gRPC-Web `+json` variants)
        // end in `+json` and so satisfy `is_json_content_type` while carrying
        // length-prefixed FRAMES rather than a bare JSON document. This is not a
        // narrowing of the untyped-JSON claim above: `transform_response_body`
        // declines the same family, so the transform provably rewrites nothing
        // there and the claim stays exactly as wide as the enforcer. Claiming it
        // anyway would send every valid gRPC JSON response on a mixed HTTP/gRPC
        // proxy into the gate's `unparseable_document` rejection — turning
        // working traffic into 502s while protecting nothing, since a frame
        // (whose first byte is the 0x00/0x01 compressed flag) can never parse as
        // a JSON document for a field rule to act on in the first place.
        //
        // That media-type test alone is not enough, because it reads the LIVE
        // header, which `after_proxy` has already had a chance to rewrite.
        // `framed_grpc_request_without_proven_media_type` carries the same
        // decline over to the pre-hook evidence — the pristine stamped media
        // type, and the request's immutable gRPC/gRPC-Web flavor when none was
        // stamped — so stripping or relabelling the header cannot smuggle frames
        // onto the untyped branch. `transform_response_body_with_context` applies
        // the identical predicate, which is what keeps this decline symmetric
        // rather than reopening the gap the SSE decline had. When NOTHING named a
        // type, that helper decides on the response bytes rather than the request
        // flavor, so an untyped bare JSON error/envelope on a mixed gRPC route
        // stays claimed and redacted instead of being waved through as framing.
        //
        // The live media-type test must then not undo that answer, which is why
        // it runs over `effective_response_media_type` rather than the raw
        // header. The main gRPC path RELABELS the live map: `grpc_web`'s
        // `after_proxy` stamps `application/grpc-web*` on every translated
        // response before this gate runs. Applying the framed-media-type decline
        // to that label AFTER the byte parse had already answered "not framed"
        // put the fail-open straight back — an untyped backend's malformed frames
        // or bare JSON error came back unclaimed and were forwarded and
        // re-wrapped by the phase-9 re-encode with the redaction skipped. The
        // resolver drops only a framed label that neither the pristine snapshot
        // nor a total frame parse supports, so the byte parse OVERRIDES the
        // relabelling instead of being overridden by it, while a pristine framed
        // type and genuinely framed bytes both still decline.
        !self.body_rules.is_empty()
            && self.rules_enabled
            && !framed_grpc_request_without_proven_media_type(ctx, response_body)
            && media_type_admits_body_rules(ctx, response_content_type, response_body)
    }

    /// The pre-`after_proxy` capability probe, deliberately WIDER than the claim.
    ///
    /// The lifecycle asks this before any response hook has run, to decide
    /// whether to retain terminal-replacement provenance for a representation
    /// rejection. Neither of the two inputs the claim actually turns on is
    /// available yet: the live `Content-Type` has not been finalized and the body
    /// has not been read. The trait default therefore probes the claim with
    /// `(None, &[])`, i.e. it asks the *untyped, empty-body* question and hopes
    /// the answer generalizes.
    ///
    /// It did not. While the untyped branch of
    /// `framed_grpc_request_without_proven_media_type` keyed on the request
    /// flavor alone, that probe answered "framed" for every gRPC/gRPC-Web request
    /// and the claim came back `false`. On a mixed gRPC route whose backend then
    /// answered with a real bare `application/json` document, the claim predicate
    /// DID claim it, an encoded/partial/unparseable body WAS replaced, and the
    /// rejection path had no provenance to restore from: it dropped the
    /// decorators completed gateway hooks had already applied (CORS, security,
    /// correlation headers) while clearing backend fields. The same response on
    /// an HTTP route kept them, so the gRPC flavor silently got a weaker error.
    ///
    /// Deciding that branch on the bytes happens to make the default probe
    /// answer correctly today — an empty probe body is not a frame sequence — but
    /// relying on that is relying on a coincidence between a capability question
    /// and a claim evaluated over evidence this predicate does not have. The
    /// override consults only configuration and request-scoped overlay state,
    /// which is exactly the set of conditions that cannot change between the
    /// probe and the claim, so the two cannot diverge again as the claim's
    /// evidence grows. Answering `true` costs one provenance-mode selection and
    /// no request-path allocation; answering `false` too eagerly costs
    /// correctness, so this predicate errs wide by construction.
    fn may_enforce_response_body_policy(&self, _ctx: &RequestContext) -> bool {
        !self.body_rules.is_empty() && self.rules_enabled
    }

    /// Fail closed: the governed field set is not enumerable at config time.
    ///
    /// Static `rules` are enumerable, but `after_proxy` ALSO applies
    /// `ctx.route_override_response_transform` — per-rule header transforms
    /// published at request time by `mesh_route_dispatch` — and the runtime
    /// path consults that context slot unconditionally, independent of the
    /// config-time `apply_route_overrides` flag. A route-level `remove` whose
    /// field arrived only as a backend trailer is therefore both invisible to
    /// this declaration and invisible to observed-mutation reconciliation, so a
    /// buffered path that forwards backend trailers drops the whole trailer
    /// section instead of guessing which names are governed.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        if self.rules_enabled {
            super::ResponseTrailerPolicy::Unbounded
        } else {
            // A fully disabled generation runs no response-header rules,
            // including request-time route overrides. Publishing an unbounded
            // policy here would still drop every backend trailer even though
            // the transformer is supposed to be a complete no-op.
            super::ResponseTrailerPolicy::None
        }
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.rules_enabled {
            return PluginResult::Continue;
        }
        // `response_caching` HIT/REVALIDATED and idempotent replays store the
        // final post-transform header map. Re-running static or route-level
        // sequences (especially non-idempotent `add`) would mutate the cached
        // representation. Consume the route override so a later sibling cannot
        // apply it either; leave the replayed headers untouched.
        if ctx.finalized_response_replay {
            let _ = ctx.route_override_response_transform.take();
            return PluginResult::Continue;
        }
        // Collect fired whole-value writes only when a terminal replacement
        // rebuild could consult them, keeping the common path allocation-free.
        let track_owned = ctx.has_buffered_deadline_response_header_provenance();
        let mut fired_write_keys: Vec<String> = Vec::new();
        self.apply_static_header_rules(
            response_headers,
            true,
            track_owned.then_some(&mut fired_write_keys),
        );
        // Per-rule overrides published by `mesh_route_dispatch` run AFTER
        // static rules so route-level writes win on conflict — see module
        // docstring. Take the Arc out so a later response_transformer
        // instance in the chain does not re-apply the same list.
        let route_rules: Option<Arc<Vec<RouteHeaderTransformRule>>> =
            ctx.route_override_response_transform.take();
        if let Some(route_rules) = route_rules.as_ref() {
            apply_route_header_transforms_tracked(
                route_rules.as_ref(),
                response_headers,
                track_owned.then_some(&mut fired_write_keys),
            );
        }
        // Declare every WHOLE-VALUE gateway write (static and route-override) as
        // gateway-owned for a gRPC deadline rebuild, because net-diff mutation
        // tracking cannot see such a write when the backend already carried the
        // identical bytes:
        //
        // * `update` overwrites with the configured value, so a backend that
        //   pre-populated the identical key/value must not be able to suppress
        //   the decoration on a synthesized DEADLINE_EXCEEDED response.
        // * a fired `rename` destination: mutation tracking observes only the
        //   source removal, so a backend that also sent the destination key with
        //   the same value it is being renamed to would suppress the write.
        // * an `add` that actually INSERTED into an absent slot — including the
        //   `remove`-then-`add` sequence whose final map is byte-identical to the
        //   backend's, where the net diff is empty. `fired_write_keys` carries
        //   these from both rule sets.
        //
        // An `add` that APPENDED onto an existing value is deliberately absent:
        // it must stay on mutation tracking's append-partition branch so the
        // backend portion of the value never crosses onto the deadline response.
        //
        // The provenance state exists only for deadline-bound buffered responses,
        // so this is gated to avoid per-request allocation otherwise. Owned names
        // are borrowed, not cloned.
        if track_owned {
            let mut owned: Vec<&str> = Vec::new();
            owned.extend(self.static_update_keys.iter().map(String::as_str));
            owned.extend(fired_write_keys.iter().map(String::as_str));
            if let Some(route_rules) = route_rules.as_ref() {
                for rule in route_rules.iter() {
                    if rule.operation == RouteHeaderTransformOp::Update {
                        owned.push(rule.key.as_str());
                    }
                }
            }
            if !owned.is_empty() {
                ctx.record_deadline_owned_response_headers(&owned, response_headers);
            }
        }
        PluginResult::Continue
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    /// The context-aware entry point, and the one the buffered lifecycle always
    /// calls.
    ///
    /// It exists solely to carry the one decline that needs `ctx` — framed gRPC
    /// on pre-hook evidence — over from
    /// [`Plugin::enforces_response_body_policy`], because the shared
    /// representation gate's guarantee is a SYMMETRY between the two, not a
    /// property of either alone. The gate rejects an uninspectable
    /// representation only for responses the claim predicate claims; the
    /// lifecycle then runs this transform over *every* buffered response
    /// regardless of what the gate concluded. Any condition that appears in the
    /// claim and not here is therefore a hole: the response is admitted as
    /// `Unprotected`, and the transform still runs on encoded, partial, or
    /// unparseable bytes and returns `None` for them — the exact
    /// `None`-conflation the gate exists to close.
    ///
    /// The decline is reachable: a framed gRPC response whose live
    /// `Content-Type` an `after_proxy` header rule stripped or relabelled passes
    /// the media-type test in [`Plugin::transform_response_body`] on the
    /// untyped/JSON branch, so only the pre-hook evidence declines it.
    ///
    /// Declining here rather than widening the claim to match is the correct
    /// direction, and it costs no redaction: the pristine stamped media type (or,
    /// unstamped, a total parse of the bytes as complete length-prefixed frames)
    /// is proof that these bytes are FRAMES, which can never parse as the bare
    /// document a JSON field rule acts on. `apply_body_rules` would have returned
    /// `None` for them anyway — the explicit decline only makes that provable at
    /// the predicate instead of incidental to the parser. Claiming them instead
    /// would send every valid RPC reply on a mixed HTTP/gRPC proxy into the
    /// gate's `unparseable_document` rejection.
    ///
    /// `body` is passed through for exactly that untyped case. It is the same
    /// byte string the claim predicate was asked about — the gate re-asks the
    /// claim over the decoded bytes before enforcing, so both sides see one
    /// representation and the symmetry holds after a decode as well as before.
    ///
    /// SSE is deliberately NOT declined here. The opposite half of the fix
    /// removed the SSE-specific *decline* from the claim predicate — widening
    /// the claim for already-buffered ordinary JSON on an SSE-accepting request
    /// — because that response is fully inspectable and its redaction works
    /// today. A genuine `text/event-stream` response remains unclaimed via the
    /// media-type condition. See [`Plugin::enforces_response_body_policy`].
    async fn transform_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // Defense in depth: the shared synthetic path already skips ordinary
        // presentation transforms when `finalized_response_replay` is set.
        // Returning `None` here keeps direct callers from re-mutating a cached
        // final body if they forget that gate.
        if ctx.finalized_response_replay {
            return None;
        }
        if framed_grpc_request_without_proven_media_type(ctx, body) {
            return None;
        }
        // Same resolution the claim predicate applies, for the same reason and
        // over the same bytes: an unproven post-hook/translation-added framed
        // gRPC label must not make the enforcer decline what the claim just
        // claimed. Dropping it here restores the untyped branch, so
        // `apply_body_rules` actually runs — and a body that is not a parseable
        // document still returns `None` into the gate's fail-closed rejection
        // instead of being forwarded unredacted.
        let content_type = effective_response_media_type(ctx, content_type, body);
        self.transform_response_body(body, content_type, response_headers)
            .await
    }

    /// The context-free transform. Every buffered call site reaches this through
    /// [`Plugin::transform_response_body_with_context`] above, which applies the
    /// `ctx`-dependent half of the claim symmetry first; this method carries the
    /// half that needs only the media type.
    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.rules_enabled {
            return None;
        }
        // Framed gRPC is declined explicitly rather than left to fail inside
        // `apply_body_rules`. Both routes return `None`, but only the explicit
        // decline makes the media-type condition here symmetric with
        // `enforces_response_body_policy` by construction, so the claim
        // predicate and the enforcer cannot drift apart on the `+json` gRPC
        // types that satisfy `is_json_content_type`.
        if let Some(ct) = content_type
            && (!body_transform::is_json_content_type(ct)
                || body_transform::is_framed_grpc_content_type(ct))
        {
            return None;
        }
        body_transform::apply_body_rules(body, &self.body_rules)
    }

    fn on_response_body_transformed(
        &self,
        _ctx: &mut RequestContext,
        response_headers: &mut HashMap<String, String>,
    ) {
        // Lifecycle `finalize_response_body_transformation` already invalidates
        // content-bound validators before this hook. Re-run for defense in depth
        // and for direct unit-test callers that exercise the plugin hook alone:
        // an actual body rewrite must never leave ETag / Last-Modified /
        // Content-Digest / Repr-Digest / Digest / Content-MD5 describing the
        // pre-rewrite bytes. Last-Modified is dropped (not rewritten) because it
        // names when the origin representation changed, not the gateway-authored
        // JSON rewrite. The proxy calls this only after `transform_response_body`
        // returns `Some`, so parse failures and semantic no-ops keep origin
        // validators.
        super::invalidate_content_bound_response_headers(response_headers);
    }
}
