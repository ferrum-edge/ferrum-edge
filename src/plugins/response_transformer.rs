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

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::utils::body_transform::{self, BodyRule};
use super::{Plugin, PluginResult, RequestContext};

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
        let mut header_rules: Vec<HeaderRule> = Vec::new();

        if let Some(arr) = config["rules"].as_array() {
            for (idx, r) in arr.iter().enumerate() {
                // `target` defaults to "header" when ABSENT (backward compat
                // for terse header-only configs). If present but not a string,
                // that is a configuration error — reject rather than silently
                // coerce. Note: `query` is NOT a valid target for
                // response_transformer; only `header` and `body` are accepted.
                let target = match r.get("target") {
                    Some(Value::String(s)) => s.as_str(),
                    Some(Value::Null) | None => "header",
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
                    key: raw_key.to_lowercase(),
                    value,
                    new_key: raw_new_key.map(|k| k.to_lowercase()),
                });
            }
        }

        let body_rules = body_transform::parse_body_rules(config)
            .map_err(|e| format!("response_transformer: {e}"))?;

        if header_rules.is_empty() && body_rules.is_empty() {
            return Err(
                "response_transformer: no 'rules' configured — plugin will have no effect"
                    .to_string(),
            );
        }

        Ok(Self {
            header_rules,
            body_rules,
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

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
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
        if let Some(ct) = content_type
            && !body_transform::is_json_content_type(ct)
        {
            return None;
        }
        body_transform::apply_body_rules(body, &self.body_rules)
    }
}
