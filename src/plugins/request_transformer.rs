//! Request transformer plugin — modifies headers, query params, and body
//! before proxying.
//!
//! Header/query rules execute in `before_proxy` before the backend request is
//! built. Body rules execute in `transform_request_body` which forces the
//! request body to be buffered.
//!
//! Rules are validated and partitioned at construction time:
//!
//! - Unknown `operation` / `target` values are rejected (no silent no-ops).
//! - `add` / `update` require a `value`; `rename` requires a `new_key`.
//! - Header values with CR/LF characters are rejected (defence against
//!   header injection via config).
//! - Rules are split into `header_rules` and `query_rules` so the hot path
//!   does not dispatch on target strings per request, and so
//!   [`modifies_request_headers`] returns an accurate answer (which lets the
//!   handler skip cloning `ctx.headers` for query-only or body-only configs).

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

impl RequestTransformer {
    pub fn new(config: &Value) -> Result<Self, String> {
        let mut header_rules: Vec<HeaderRule> = Vec::new();
        let mut query_rules: Vec<QueryRule> = Vec::new();

        if let Some(arr) = config["rules"].as_array() {
            for (idx, r) in arr.iter().enumerate() {
                // `target` defaults to "header" only when the field is
                // ABSENT (backward compat for terse header-only configs).
                // An explicit `"target": null` — or any non-string value —
                // is a configuration error. Silently defaulting an explicit
                // null would mask typos / misconfiguration.
                let target = match r.get("target") {
                    Some(Value::String(s)) => s.as_str(),
                    None => "header",
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'target' must be a string (expected header/query/body)"
                        ));
                    }
                };

                // Body rules are validated and collected by `parse_body_rules`.
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
                let value = match r.get("value") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'value' must be a string for header/query rules"
                        ));
                    }
                };
                let raw_new_key = match r.get("new_key") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'new_key' must be a string"
                        ));
                    }
                };

                // Per-operation required-field validation.
                match op_str {
                    "add" | "update" if value.is_none() => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: '{op_str}' operation requires a 'value'"
                        ));
                    }
                    "rename" if raw_new_key.is_none() => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'rename' operation requires a 'new_key'"
                        ));
                    }
                    _ => {}
                }

                if target == "header" {
                    // Defence-in-depth: reject CR/LF in header values at
                    // config time (hyper would reject later, but failing at
                    // load time gives clearer operator feedback).
                    if let Some(ref v) = value
                        && contains_crlf(v)
                    {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: header 'value' must not contain CR or LF"
                        ));
                    }
                    header_rules.push(HeaderRule {
                        operation: hop,
                        key: raw_key.to_lowercase(),
                        value,
                        new_key: raw_new_key.map(|k| k.to_lowercase()),
                    });
                } else {
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

        if header_rules.is_empty() && query_rules.is_empty() && body_rules.is_empty() {
            return Err(
                "request_transformer: no 'rules' configured — plugin will have no effect"
                    .to_string(),
            );
        }

        Ok(Self {
            header_rules,
            query_rules,
            body_rules,
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
        !self.header_rules.is_empty()
    }

    fn modifies_request_body(&self) -> bool {
        !self.body_rules.is_empty()
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        for rule in &self.header_rules {
            match rule.operation {
                HeaderOp::Add => {
                    if let Some(ref val) = rule.value {
                        headers.entry(rule.key.clone()).or_insert_with(|| {
                            debug!("request_transformer: added header {}={}", rule.key, val);
                            val.clone()
                        });
                    }
                }
                HeaderOp::Update => {
                    if let Some(ref val) = rule.value {
                        headers.insert(rule.key.clone(), val.clone());
                        debug!("request_transformer: set header {}={}", rule.key, val);
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
        for rule in &self.query_rules {
            match rule.operation {
                QueryOp::Add => {
                    if let Some(ref val) = rule.value {
                        ctx.query_params
                            .entry(rule.key.clone())
                            .or_insert_with(|| val.clone());
                    }
                }
                QueryOp::Update => {
                    if let Some(ref val) = rule.value {
                        ctx.query_params.insert(rule.key.clone(), val.clone());
                    }
                }
                QueryOp::Remove => {
                    ctx.query_params.remove(&rule.key);
                }
                QueryOp::Rename => {
                    if let Some(ref new_key) = rule.new_key
                        && let Some(val) = ctx.query_params.remove(&rule.key)
                    {
                        ctx.query_params.insert(new_key.clone(), val);
                    }
                }
            }
        }
        PluginResult::Continue
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
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
