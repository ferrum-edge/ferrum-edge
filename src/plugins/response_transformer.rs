//! Response transformer plugin — modifies response headers and body after
//! proxying.
//!
//! Header rules (add/remove/update/rename) execute in `after_proxy`. Body
//! rules require `requires_response_body_buffering()` = true so the response
//! body is collected before being forwarded to the client.
//!
//! Rules are validated at construction time:
//!
//! - Unknown `operation` / `target` values are rejected (no silent no-ops).
//! - `add` / `update` require a `value`; `rename` requires a `new_key`.
//! - Header values with CR/LF characters are rejected (defence against
//!   header injection via config).
//! - Header keys are pre-lowercased.
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
//! When `runtime_overlay_scope: "<scope>"` is set, the plugin reads
//! `ferrum.response_transformer.<scope>.enabled` from the mesh runtime
//! overlay at request time. A `false` value short-circuits rule
//! application (static rules AND route-overlay overrides). A missing
//! entry falls back to `default_enabled` (defaults to `true` —
//! fail-open).

use async_trait::async_trait;
use http::header::HeaderName;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

use super::utils::body_transform::{self, BodyRule};
use super::utils::route_header_transform::{
    RouteHeaderTransformRule, apply_route_header_transforms,
};
use super::{Plugin, PluginResult, RequestContext};

pub mod runtime_overlay;

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
    body_rules: Vec<BodyRule>,
    /// When `Some`, the plugin reads
    /// `ferrum.response_transformer.<scope>.enabled` from the mesh
    /// runtime overlay on every request before applying rules.
    runtime_overlay_scope: Option<String>,
    /// Fallback when [`runtime_overlay_scope`] is set but the overlay
    /// does not carry the matching key. Defaults to `true` (fail-open).
    default_enabled: bool,
}

impl ResponseTransformer {
    fn rules_enabled(&self) -> bool {
        let Some(scope) = self.runtime_overlay_scope.as_deref() else {
            return true;
        };
        runtime_overlay::current_gates()
            .gate(scope)
            .unwrap_or(self.default_enabled)
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

fn contains_crlf(s: &str) -> bool {
    s.bytes().any(|b| b == b'\r' || b == b'\n')
}

impl ResponseTransformer {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("response_transformer: config must be an object".to_string());
        }

        let mut header_rules: Vec<HeaderRule> = Vec::new();

        if let Some(rules) = config.get("rules") {
            let arr = rules
                .as_array()
                .ok_or("response_transformer: 'rules' must be an array")?;
            for (idx, r) in arr.iter().enumerate() {
                if !r.is_object() {
                    return Err(format!(
                        "response_transformer: rule[{idx}]: rule must be an object"
                    ));
                }
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
                    // Body rules are validated by `parse_body_rules`.
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
                let value = match r.get("value") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'value' must be a string for header rules"
                        ));
                    }
                };
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

                // Per-operation required-field validation.
                match operation {
                    HeaderOp::Add | HeaderOp::Update => {
                        if value.is_none() {
                            return Err(format!(
                                "response_transformer: rule[{idx}]: '{op_str}' operation requires a 'value'"
                            ));
                        }
                    }
                    HeaderOp::Rename => {
                        if raw_new_key.is_none() {
                            return Err(format!(
                                "response_transformer: rule[{idx}]: 'rename' operation requires a 'new_key'"
                            ));
                        }
                    }
                    HeaderOp::Remove => {}
                }

                if let Some(ref v) = value
                    && contains_crlf(v)
                {
                    return Err(format!(
                        "response_transformer: rule[{idx}]: header 'value' must not contain CR or LF"
                    ));
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

        Ok(Self {
            header_rules,
            body_rules,
            runtime_overlay_scope,
            default_enabled,
        })
    }
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

    fn requires_response_body_buffering(&self) -> bool {
        !self.body_rules.is_empty()
    }

    fn may_rewrite_response_content_type(&self, ctx: &RequestContext) -> bool {
        self.rules_enabled()
            && (self.header_rules.iter().any(|rule| match rule.operation {
                HeaderOp::Add | HeaderOp::Update | HeaderOp::Remove => rule.key == "content-type",
                HeaderOp::Rename => {
                    rule.key == "content-type"
                        || rule
                            .new_key
                            .as_deref()
                            .is_some_and(|new_key| new_key == "content-type")
                }
            }) || ctx
                .route_override_response_transform
                .as_ref()
                .is_some_and(|rules| rules.iter().any(|rule| rule.key == "content-type")))
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        // Honor the RTDS runtime kill-switch here, mirroring the early
        // `return None` in `transform_response_body`. When the overlay disables
        // this scope the transform is a no-op, so we must not pin the response
        // into the buffered path — otherwise a disabled transform still buffers
        // a large/streaming non-SSE response until the max-response-body limit
        // and then 502s, defeating the very buffering relief the kill-switch is
        // meant to provide. `rules_enabled()` reads request-time overlay state,
        // so it belongs in this per-request gate (not the cache-level
        // `requires_response_body_buffering` upper bound). (Finding #64.)
        //
        // Skip body buffering for SSE requests (`Accept: text/event-stream`).
        // Body transforms operate on the assembled response body — applying
        // them to an unbounded event stream would buffer until the
        // max-response-body limit is hit and then 502. SSE transforms are
        // out of scope; operators should configure body transforms only for
        // non-SSE proxies, or layer a frame-level plugin on top.
        !self.body_rules.is_empty()
            && self.rules_enabled()
            && !super::utils::sse::is_sse_request(ctx)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.rules_enabled() {
            return PluginResult::Continue;
        }
        for rule in &self.header_rules {
            match rule.operation {
                HeaderOp::Add => {
                    if let Some(ref val) = rule.value {
                        response_headers.entry(rule.key.clone()).or_insert_with(|| {
                            debug!("response_transformer: added header {}={}", rule.key, val);
                            val.clone()
                        });
                    }
                }
                HeaderOp::Update => {
                    if let Some(ref val) = rule.value {
                        response_headers.insert(rule.key.clone(), val.clone());
                        debug!("response_transformer: set header {}={}", rule.key, val);
                    }
                }
                HeaderOp::Remove => {
                    response_headers.remove(&rule.key);
                    debug!("response_transformer: removed header {}", rule.key);
                }
                HeaderOp::Rename => {
                    if let Some(ref new_key) = rule.new_key
                        && let Some(val) = response_headers.remove(&rule.key)
                    {
                        debug!(
                            "response_transformer: renamed header {} -> {}",
                            rule.key, new_key
                        );
                        response_headers.insert(new_key.clone(), val);
                    }
                }
            }
        }
        // Per-rule overrides published by `mesh_route_dispatch` run AFTER
        // static rules so route-level writes win on conflict — see module
        // docstring. Take the Arc out so a later response_transformer
        // instance in the chain does not re-apply the same list.
        let route_rules: Option<Arc<Vec<RouteHeaderTransformRule>>> =
            ctx.route_override_response_transform.take();
        if let Some(route_rules) = route_rules {
            apply_route_header_transforms(route_rules.as_ref(), response_headers);
        }
        PluginResult::Continue
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.rules_enabled() {
            return None;
        }
        if let Some(ct) = content_type
            && !body_transform::is_json_content_type(ct)
        {
            return None;
        }
        body_transform::apply_body_rules(body, &self.body_rules)
    }
}
