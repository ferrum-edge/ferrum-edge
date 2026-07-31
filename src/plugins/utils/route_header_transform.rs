//! Shared header-transform shape used by `mesh_route_dispatch` (producer)
//! and the request/response transformer plugins (consumers).
//!
//! Istio `VirtualService.http[].headers.{request,response}.{set,add,remove}`
//! is per-http-route, not per-match: every dispatch rule emitted from a
//! single `http[]` entry carries the same transforms. The producer parses
//! and validates rules at config load time, stores them in an
//! `Arc<Vec<RouteHeaderTransformRule>>`, and clones that `Arc` onto
//! [`crate::plugins::RequestContext::route_override_request_transform`] /
//! [`crate::plugins::RequestContext::route_override_response_transform`]
//! when a `mesh_route_dispatch` rule matches.
//!
//! Enabled transformer instances apply only their **static** header rules.
//! Proxy core then applies each matched route list **exactly once** in a
//! chain-level final header phase after the last eligible (enabled)
//! `request_transformer` / `response_transformer` in the ordered plugin
//! chain. That keeps route-level policy authoritative under multiple
//! same-type instances: a later static add/update/remove/rename cannot
//! undo a route remove or set. A disabled RTDS instance is not eligible
//! and neither consumes nor suppresses the route list. When the chain has
//! no eligible consumer, the published `Arc` is left unused (the Virtual
//! Service translator auto-emits an `apply_route_overrides` consumer when
//! route header transforms are configured).
//!
//! Operations supported are the strict subset of header ops that the
//! transformer plugins also expose:
//! - `add` — append to an existing header value with a comma separator, or
//!   insert when absent. This mirrors Gateway API / Istio header-modifier
//!   semantics on Ferrum's single-value header map.
//! - `update` — insert or replace (`headers.request.set` semantics).
//! - `remove` — delete the header (all values for the key).
//!
//! Rename is intentionally not part of the route-level transform contract
//! because Istio has no rename verb.
//!
//! Ferrum's underlying `HashMap<String, String>` header storage does not
//! natively model repeated header fields, so append is represented in the
//! HTTP/1-compatible comma-joined form. Operators who need overwrite semantics
//! should use `set`, which translates to `update`.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

use http::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::plugins::RequestContext;

/// Apply the matched request route-header list exactly once and clear it from
/// `ctx`. Proxy core calls this after the last eligible `request_transformer`
/// static-rule pass so later same-type instances cannot undo route policy.
pub fn finalize_route_override_request_headers(
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
) {
    if let Some(route_rules) = ctx.route_override_request_transform.take() {
        apply_route_header_transforms(route_rules.as_ref(), headers);
    }
}

/// Apply (or consume without applying) the matched response route-header list
/// exactly once. Finalized cache/idempotent replays already carry the
/// post-transform map, so the Arc is taken without re-applying non-idempotent
/// `add` sequences. Ordinary paths apply the list and record whole-value
/// gateway ownership for deadline provenance when that state is active.
pub fn finalize_route_override_response_headers(
    ctx: &mut RequestContext,
    response_headers: &mut HashMap<String, String>,
) {
    if ctx.finalized_response_replay {
        let _ = ctx.route_override_response_transform.take();
        return;
    }
    let Some(route_rules) = ctx.route_override_response_transform.take() else {
        return;
    };
    finalize_route_override_response_headers_inner(ctx, response_headers, route_rules);
}

fn finalize_route_override_response_headers_inner(
    ctx: &mut RequestContext,
    response_headers: &mut HashMap<String, String>,
    route_rules: Arc<Vec<RouteHeaderTransformRule>>,
) {
    let track_owned = ctx.has_buffered_deadline_response_header_provenance();
    let mut fired_write_keys: Vec<String> = Vec::new();
    apply_route_header_transforms_tracked(
        route_rules.as_ref(),
        response_headers,
        track_owned.then_some(&mut fired_write_keys),
    );
    if track_owned {
        let mut owned: Vec<&str> = Vec::new();
        owned.extend(fired_write_keys.iter().map(String::as_str));
        for rule in route_rules.iter() {
            if rule.operation == RouteHeaderTransformOp::Update {
                owned.push(rule.key.as_str());
            }
        }
        if !owned.is_empty() {
            ctx.record_deadline_owned_response_headers(&owned, response_headers);
        }
    }
    // Whole-value ownership above covers writes whose final bytes can be
    // indistinguishable from the backend baseline. Record the completed route
    // phase as well so ordinary removals and appends are reconciled into
    // deadline provenance. This must live in the finalizer rather than its
    // callers: rejection/deadline early-return paths can finalize outside the
    // ordinary after-proxy loop.
    ctx.record_deadline_response_header_mutations(response_headers);
}

/// Operation in a route-level header transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteHeaderTransformOp {
    /// Append with comma separator when present; insert when absent.
    Add,
    /// Insert or replace.
    Update,
    /// Remove all values for the key.
    Remove,
}

/// A validated route-level header transform rule.
///
/// `key` is pre-lowercased so the hot path can compare against the
/// proxy-handler's normalized header map without per-request allocation.
#[derive(Debug, Clone)]
pub struct RouteHeaderTransformRule {
    pub operation: RouteHeaderTransformOp,
    pub key: String,
    /// `Some` for `Add` / `Update`; `None` for `Remove`.
    pub value: Option<String>,
}

/// JSON-facing rule shape. Matches the existing
/// `request_transformer` / `response_transformer` rule shape so a future
/// shared validator can be lifted out without re-spelling the wire format.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRouteHeaderTransformRule {
    pub operation: String,
    /// Always `"header"` for route-level transforms. Kept for shape parity
    /// with the transformer plugin config so operators reading the
    /// emitted dispatch JSON see a familiar key set.
    #[serde(default = "default_header_target")]
    pub target: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

fn default_header_target() -> String {
    "header".to_string()
}

/// Parse and validate a list of raw rules into runtime rules.
///
/// `context` is a short string used to prefix error messages
/// (e.g. `"rules[2].request_transform"`).
pub fn parse_route_header_transforms(
    raw: &[RawRouteHeaderTransformRule],
    context: &str,
) -> Result<Vec<RouteHeaderTransformRule>, String> {
    let mut out = Vec::with_capacity(raw.len());
    for (idx, rule) in raw.iter().enumerate() {
        if rule.target != "header" {
            return Err(format!(
                "{context}[{idx}].target must be \"header\" for route-level transforms (got \"{}\")",
                rule.target
            ));
        }
        let op = match rule.operation.as_str() {
            "add" => RouteHeaderTransformOp::Add,
            "update" => RouteHeaderTransformOp::Update,
            "remove" => RouteHeaderTransformOp::Remove,
            other => {
                return Err(format!(
                    "{context}[{idx}].operation must be one of add/update/remove (got \"{other}\")"
                ));
            }
        };
        if rule.key.is_empty() {
            return Err(format!("{context}[{idx}].key must not be empty"));
        }
        let key = HeaderName::from_bytes(rule.key.as_bytes())
            .map_err(|_| format!("{context}[{idx}].key must be a valid HTTP header name"))?
            .to_string();
        match op {
            RouteHeaderTransformOp::Add | RouteHeaderTransformOp::Update => {
                let Some(value) = rule.value.as_ref() else {
                    return Err(format!(
                        "{context}[{idx}].value is required for operation \"{}\"",
                        rule.operation
                    ));
                };
                if value.bytes().any(|b| b == b'\r' || b == b'\n') {
                    return Err(format!("{context}[{idx}].value must not contain CR or LF"));
                }
                // Same complete HeaderValue gate used by outbound Hyper / H3 /
                // reqwest adapters so invalid controls fail at config load.
                HeaderValue::from_str(value).map_err(|_| {
                    format!("{context}[{idx}].value must be a valid HTTP HeaderValue")
                })?;
                out.push(RouteHeaderTransformRule {
                    operation: op,
                    key,
                    value: Some(value.clone()),
                });
            }
            RouteHeaderTransformOp::Remove => {
                if rule.value.is_some() {
                    return Err(format!(
                        "{context}[{idx}].value must not be set for operation \"remove\""
                    ));
                }
                out.push(RouteHeaderTransformRule {
                    operation: op,
                    key,
                    value: None,
                });
            }
        }
    }
    Ok(out)
}

/// Apply a list of route header-transform rules to a header map.
///
/// Operations are applied in declaration order so operators get
/// predictable interleaving (e.g. an `add` after a `remove` reinstates the
/// header with the new value). `Add` appends with a comma separator when the
/// header already exists, except `Set-Cookie`, which uses the proxy's
/// newline-separated multi-value representation; `Update` is unconditional
/// replace; `Remove` deletes the entry.
pub fn apply_route_header_transforms(
    rules: &[RouteHeaderTransformRule],
    headers: &mut HashMap<String, String>,
) {
    apply_route_header_transforms_tracked(rules, headers, None);
}

/// [`apply_route_header_transforms`] with an optional sink recording the keys
/// whose `add` rule actually INSERTED into an absent slot (rather than
/// appending onto an existing value).
///
/// Such an insert writes the entire value, so it is a whole-value gateway
/// write. gRPC-deadline provenance needs that distinction: after an
/// `add`-following-`remove` sequence the final map can be byte-identical to
/// the backend's, and the net-diff mutation tracking in
/// `BufferedDeadlineResponseHeaderProvenance::record_gateway_mutations` would
/// see no change and never credit the reintroduced gateway header — dropping it
/// from a synthesized DEADLINE_EXCEEDED response. Appends are deliberately NOT
/// recorded: they must stay on the append-partition branch so the backend
/// portion of the value never crosses onto the deadline response.
///
/// Callers with no provenance to track pass `None` and stay allocation-free.
pub fn apply_route_header_transforms_tracked(
    rules: &[RouteHeaderTransformRule],
    headers: &mut HashMap<String, String>,
    mut inserted_keys: Option<&mut Vec<String>>,
) {
    for rule in rules {
        match rule.operation {
            RouteHeaderTransformOp::Add => {
                if let Some(value) = rule.value.as_ref() {
                    match headers.entry(rule.key.clone()) {
                        Entry::Occupied(mut existing) => {
                            let existing = existing.get_mut();
                            if existing.is_empty() {
                                existing.push_str(value);
                            } else {
                                if rule.key.eq_ignore_ascii_case("set-cookie") {
                                    existing.push('\n');
                                } else {
                                    existing.push(',');
                                }
                                existing.push_str(value);
                            }
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(value.clone());
                            if let Some(sink) = inserted_keys.as_mut() {
                                sink.push(rule.key.clone());
                            }
                        }
                    }
                }
            }
            RouteHeaderTransformOp::Update => {
                if let Some(value) = rule.value.as_ref() {
                    headers.insert(rule.key.clone(), value.clone());
                }
            }
            RouteHeaderTransformOp::Remove => {
                headers.remove(&rule.key);
            }
        }
    }
}

/// Convenience: build the emitted JSON shape that the `mesh_route_dispatch`
/// plugin accepts. Used by the K8s VirtualService translator to project
/// Istio `headers.request` / `headers.response` blocks onto each dispatch
/// rule.
pub fn route_header_transform_rules_to_json(
    set: Option<&serde_json::Map<String, Value>>,
    add: Option<&serde_json::Map<String, Value>>,
    remove: Option<&[String]>,
) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    if let Some(set_map) = set {
        for (key, value) in set_map {
            let Some(value_str) = value.as_str() else {
                continue;
            };
            out.push(serde_json::json!({
                "operation": "update",
                "target": "header",
                "key": key,
                "value": value_str,
            }));
        }
    }
    if let Some(add_map) = add {
        for (key, value) in add_map {
            let Some(value_str) = value.as_str() else {
                continue;
            };
            out.push(serde_json::json!({
                "operation": "add",
                "target": "header",
                "key": key,
                "value": value_str,
            }));
        }
    }
    if let Some(remove_list) = remove {
        for key in remove_list {
            out.push(serde_json::json!({
                "operation": "remove",
                "target": "header",
                "key": key,
            }));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_set_add_remove() {
        let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(serde_json::json!([
            {"operation": "update", "target": "header", "key": "X-Set", "value": "1"},
            {"operation": "add", "target": "header", "key": "X-Add", "value": "2"},
            {"operation": "remove", "target": "header", "key": "X-Del"},
        ]))
        .unwrap();
        let parsed = parse_route_header_transforms(&raw, "rules[0].request_transform").unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].operation, RouteHeaderTransformOp::Update);
        assert_eq!(parsed[0].key, "x-set");
        assert_eq!(parsed[1].operation, RouteHeaderTransformOp::Add);
        assert_eq!(parsed[2].operation, RouteHeaderTransformOp::Remove);
        assert!(parsed[2].value.is_none());
    }

    #[test]
    fn parse_rejects_unknown_operation() {
        let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(serde_json::json!([
            {"operation": "rename", "target": "header", "key": "X", "value": "Y"},
        ]))
        .unwrap();
        let err = parse_route_header_transforms(&raw, "ctx").unwrap_err();
        assert!(err.contains("add/update/remove"), "got: {err}");
    }

    #[test]
    fn parse_rejects_non_header_target() {
        let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(serde_json::json!([
            {"operation": "update", "target": "query", "key": "x", "value": "y"},
        ]))
        .unwrap();
        let err = parse_route_header_transforms(&raw, "ctx").unwrap_err();
        assert!(err.contains("must be \"header\""), "got: {err}");
    }

    #[test]
    fn parse_rejects_missing_value_for_add_update() {
        let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(serde_json::json!([
            {"operation": "update", "target": "header", "key": "X"},
        ]))
        .unwrap();
        let err = parse_route_header_transforms(&raw, "ctx").unwrap_err();
        assert!(err.contains("value is required"), "got: {err}");
    }

    #[test]
    fn parse_rejects_value_on_remove() {
        let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(serde_json::json!([
            {"operation": "remove", "target": "header", "key": "X", "value": "Y"},
        ]))
        .unwrap();
        let err = parse_route_header_transforms(&raw, "ctx").unwrap_err();
        assert!(err.contains("must not be set"), "got: {err}");
    }

    #[test]
    fn parse_rejects_crlf_in_value() {
        let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(serde_json::json!([
            {"operation": "update", "target": "header", "key": "X", "value": "a\r\nInjected: 1"},
        ]))
        .unwrap();
        let err = parse_route_header_transforms(&raw, "ctx").unwrap_err();
        assert!(err.contains("CR or LF"), "got: {err}");
    }

    #[test]
    fn parse_rejects_nul_and_other_forbidden_controls() {
        for (label, value) in [
            ("NUL", "ok\u{0000}bad"),
            ("SOH", "ok\u{0001}bad"),
            ("DEL", "ok\u{007f}bad"),
        ] {
            let raw: Vec<RawRouteHeaderTransformRule> =
                serde_json::from_value(serde_json::json!([{
                    "operation": "update",
                    "target": "header",
                    "key": "X",
                    "value": value,
                }]))
                .unwrap();
            let err = parse_route_header_transforms(&raw, "ctx").unwrap_err();
            assert!(err.contains("valid HTTP HeaderValue"), "{label}: got {err}");
        }
    }

    #[test]
    fn parse_accepts_header_value_edge_cases() {
        for value in ["", " ", "\t", "plain", "tab\there", "café"] {
            let raw: Vec<RawRouteHeaderTransformRule> =
                serde_json::from_value(serde_json::json!([{
                    "operation": "add",
                    "target": "header",
                    "key": "X-Edge",
                    "value": value,
                }]))
                .unwrap();
            parse_route_header_transforms(&raw, "ctx").unwrap_or_else(|e| {
                panic!("valid HeaderValue rejected for {value:?}: {e}");
            });
        }
    }

    #[test]
    fn parse_rejects_empty_key_and_invalid_chars() {
        let empty: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(serde_json::json!([
            {"operation": "remove", "target": "header", "key": ""},
        ]))
        .unwrap();
        assert!(
            parse_route_header_transforms(&empty, "ctx")
                .unwrap_err()
                .contains("key must not be empty")
        );
        let bad: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(serde_json::json!([
            {"operation": "remove", "target": "header", "key": "X Y"},
        ]))
        .unwrap();
        assert!(
            parse_route_header_transforms(&bad, "ctx")
                .unwrap_err()
                .contains("valid HTTP header name")
        );
        let separator: Vec<RawRouteHeaderTransformRule> =
            serde_json::from_value(serde_json::json!([
                {"operation": "remove", "target": "header", "key": "X/Bad"},
            ]))
            .unwrap();
        assert!(
            parse_route_header_transforms(&separator, "ctx")
                .unwrap_err()
                .contains("valid HTTP header name")
        );
    }

    #[test]
    fn apply_ordering_matches_declaration() {
        let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(serde_json::json!([
            {"operation": "remove", "target": "header", "key": "X-Trace"},
            {"operation": "add",    "target": "header", "key": "X-Trace", "value": "after-remove"},
            {"operation": "update", "target": "header", "key": "X-Trace", "value": "final"},
        ]))
        .unwrap();
        let parsed = parse_route_header_transforms(&raw, "ctx").unwrap();
        let mut headers = HashMap::new();
        headers.insert("x-trace".to_string(), "original".to_string());
        apply_route_header_transforms(&parsed, &mut headers);
        assert_eq!(headers.get("x-trace").map(String::as_str), Some("final"));
    }

    #[test]
    fn apply_add_appends_with_comma_when_header_exists() {
        let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(serde_json::json!([
            {"operation": "add", "target": "header", "key": "X-Trace", "value": "from-add"},
        ]))
        .unwrap();
        let parsed = parse_route_header_transforms(&raw, "ctx").unwrap();
        let mut headers = HashMap::new();
        headers.insert("x-trace".to_string(), "client".to_string());
        apply_route_header_transforms(&parsed, &mut headers);
        assert_eq!(
            headers.get("x-trace").map(String::as_str),
            Some("client,from-add")
        );
    }

    #[test]
    fn apply_add_preserves_set_cookie_as_separate_values() {
        let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(serde_json::json!([
            {"operation": "add", "target": "header", "key": "Set-Cookie", "value": "route=1; Path=/"},
        ]))
        .unwrap();
        let parsed = parse_route_header_transforms(&raw, "ctx").unwrap();
        let mut headers = HashMap::new();
        headers.insert("set-cookie".to_string(), "backend=1; Path=/".to_string());
        apply_route_header_transforms(&parsed, &mut headers);
        assert_eq!(
            headers.get("set-cookie").map(String::as_str),
            Some("backend=1; Path=/\nroute=1; Path=/")
        );
    }

    #[test]
    fn translator_helper_emits_set_add_remove() {
        let set = serde_json::json!({"X-Api-Version": "v1"});
        let add = serde_json::json!({"X-Trace": "y"});
        let remove = vec!["X-Debug".to_string()];
        let json =
            route_header_transform_rules_to_json(set.as_object(), add.as_object(), Some(&remove));
        assert_eq!(json.len(), 3);
        assert_eq!(json[0]["operation"], "update");
        assert_eq!(json[0]["key"], "X-Api-Version");
        assert_eq!(json[0]["value"], "v1");
        assert_eq!(json[1]["operation"], "add");
        assert_eq!(json[2]["operation"], "remove");
        // `remove` rules must not carry a value (the apply path treats absent
        // as the canonical no-op marker).
        assert!(json[2].get("value").is_none());
    }
}
