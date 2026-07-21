//! Response Mock Plugin
//!
//! Returns configurable mock responses without proxying to the backend.
//! Supports matching by HTTP method and path pattern (exact or regex),
//! with configurable status codes, headers, body, and optional latency
//! simulation. Useful for early API testing before backends are ready,
//! contract testing, and local development.
//!
//! ## Path Matching
//!
//! Mock rule paths are **relative to a prefix `listen_path`**. The plugin
//! strips that prefix from the incoming request path before matching rules.
//! For example, if the proxy has `listen_path: /api/v1` and a request arrives
//! at `/api/v1/users`, the mock rule path should be `/users`. A request to
//! exactly that strip-eligible prefix listen path (e.g., `/api/v1` with no
//! trailing component) is matched as `/`.
//!
//! Full request path matching (no stripping) applies for:
//! - exact listen paths (`=` prefix)
//! - regex listen paths (`~` prefix)
//! - root listen path (`/`)
//! - host-only proxies (`listen_path` omitted / `None`)
//!
//! ## WebSocket handshake
//!
//! `response_mock` participates in the HTTP-family protocol set, including
//! WebSocket upgrade handshakes. A matching rule short-circuits only the HTTP
//! handshake response (`PluginResult::Reject`). It does **not** establish or
//! mock an upgraded WebSocket frame stream — even when `status_code` is `101`.
//!
//! ## Config
//!
//! ```json
//! {
//!   "rules": [
//!     {
//!       "method": "GET",
//!       "path": "/users",
//!       "status_code": 200,
//!       "headers": { "content-type": "application/json" },
//!       "body": "{\"users\": []}",
//!       "delay_ms": 50
//!     },
//!     {
//!       "path": "~/users/[0-9]+",
//!       "status_code": 200,
//!       "headers": { "content-type": "application/json" },
//!       "body": "{\"id\": 1, \"name\": \"Mock User\"}"
//!     }
//!   ],
//!   "passthrough_on_no_match": true
//! }
//! ```
//!
//! - **rules**: Array of mock rules evaluated in order (first match wins)
//!   - **method**: HTTP method token to match (optional; omit to match all
//!     methods). When supplied it must be non-empty and parse as an HTTP
//!     method token.
//!   - **path**: Non-empty path relative to a prefix listen_path, full path
//!     for exact/regex/root/host-only scopes, or regex with `~` prefix
//!     (required)
//!   - **status_code**: HTTP status to return (default: 200). Must be a final
//!     status `200–599`, or `101` for a synthetic WebSocket handshake response.
//!     Other informational statuses (`100`, `102`–`199`) are rejected — a mock
//!     cannot emit a 1xx as a body-bearing final response.
//!   - **headers**: Response headers (default: `{"content-type": "application/json"}`)
//!   - **body**: Response body string (default: empty). On the wire, `HEAD`
//!     responses omit content bytes while keeping representation metadata
//!     (including `Content-Length`). Statuses `204`/`205`/`304` omit both the
//!     body and `Content-Length`, even when a non-empty `body` is configured.
//!   - **delay_ms**: Simulated latency in milliseconds (default: 0, max
//!     3,600,000 = 1 hour; larger values are rejected at construction)
//! - **passthrough_on_no_match**: If true, requests not matching any rule
//!   continue to the backend. If false (default), unmatched requests get 404.
//!
//! Unknown top-level and per-rule keys are rejected at construction. The
//! free-form `headers` map remains open for arbitrary string-valued headers.
//! HEAD / no-body wire shape is applied by the shared synthetic-response
//! finalizer so H1, H2, and H3 stay aligned.

use async_trait::async_trait;
use http::{
    Method,
    header::{HeaderName, HeaderValue},
};
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashMap;

use super::{Plugin, PluginResult, RequestContext};

/// Every accepted top-level configuration property.
pub const RESPONSE_MOCK_CONFIG_KEYS: &[&str] = &["rules", "passthrough_on_no_match"];

/// Every accepted per-rule configuration property.
pub const RESPONSE_MOCK_RULE_KEYS: &[&str] = &[
    "method",
    "path",
    "status_code",
    "headers",
    "body",
    "delay_ms",
];

/// Upper bound for a rule's `delay_ms` (1 hour). `delay_ms` feeds
/// `tokio::time::sleep` on the request hot path, so an unbounded value
/// (operator typo / wrong unit) would pin a request open and hold a draining
/// slot during graceful shutdown. Matches `fault_injection` and
/// `mesh_route_dispatch`. (Finding #63.)
const MAX_DELAY_MS: u64 = 3_600_000;

enum PathMatcher {
    Exact(String),
    Regex(Regex),
}

struct MockRule {
    method: Option<String>,
    path: PathMatcher,
    status_code: u16,
    headers: HashMap<String, String>,
    body: String,
    delay_ms: u64,
}

pub struct ResponseMock {
    rules: Vec<MockRule>,
    passthrough_on_no_match: bool,
}

impl ResponseMock {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config = config.as_object().ok_or_else(|| {
            format!(
                "response_mock: config must be an object; allowed keys: {}",
                RESPONSE_MOCK_CONFIG_KEYS.join(", ")
            )
        })?;
        reject_unknown_keys(config, "config", RESPONSE_MOCK_CONFIG_KEYS)?;

        let passthrough_on_no_match =
            optional_bool(config, "passthrough_on_no_match")?.unwrap_or(false);

        let rules_val = match config.get("rules") {
            Some(Value::Array(rules)) => rules,
            _ => return Err("response_mock: 'rules' must be a JSON array".to_string()),
        };

        if rules_val.is_empty() {
            return Err("response_mock: 'rules' array must not be empty".to_string());
        }

        let mut rules = Vec::with_capacity(rules_val.len());

        for (i, rule_val) in rules_val.iter().enumerate() {
            let rule_obj = rule_val
                .as_object()
                .ok_or_else(|| format!("response_mock: rule[{i}] must be an object"))?;
            let rule_path = format!("config.rules[{i}]");
            reject_unknown_keys(rule_obj, &rule_path, RESPONSE_MOCK_RULE_KEYS)?;

            let method = match rule_obj.get("method") {
                Some(Value::String(method)) if !method.is_empty() => {
                    Method::from_bytes(method.as_bytes()).map_err(|_| {
                        format!(
                            "response_mock: rule[{i}] 'method' must be a valid HTTP method token"
                        )
                    })?;
                    Some(method.to_ascii_uppercase())
                }
                Some(Value::String(_)) => {
                    return Err(format!(
                        "response_mock: rule[{i}] 'method' must not be empty"
                    ));
                }
                Some(Value::Null) | None => None,
                Some(_) => {
                    return Err(format!(
                        "response_mock: rule[{i}] 'method' must be a string"
                    ));
                }
            };

            let path_str = rule_obj
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("response_mock: rule[{i}] missing 'path'"))?;
            if path_str.is_empty() {
                return Err(format!("response_mock: rule[{i}] 'path' must not be empty"));
            }

            let path = if let Some(pattern) = path_str.strip_prefix('~') {
                if pattern.is_empty() {
                    return Err(format!(
                        "response_mock: rule[{i}] regex path must not be empty"
                    ));
                }
                let anchored = crate::config::types::anchor_regex_pattern(pattern);
                let re = Regex::new(&anchored).map_err(|e| {
                    format!("response_mock: rule[{i}] invalid regex '{pattern}': {e}")
                })?;
                PathMatcher::Regex(re)
            } else {
                PathMatcher::Exact(path_str.to_string())
            };

            let status_code = optional_status_code(rule_obj, i)?;

            let mut headers = HashMap::new();
            match rule_obj.get("headers") {
                Some(Value::Object(obj)) => {
                    for (k, v) in obj {
                        HeaderName::from_bytes(k.as_bytes()).map_err(|_| {
                            format!("response_mock: rule[{i}] header '{k}' is not a valid name")
                        })?;
                        let s = v.as_str().ok_or_else(|| {
                            format!("response_mock: rule[{i}] header '{k}' value must be a string")
                        })?;
                        HeaderValue::from_str(s).map_err(|_| {
                            format!("response_mock: rule[{i}] header '{k}' value is invalid")
                        })?;
                        headers.insert(k.to_ascii_lowercase(), s.to_string());
                    }
                }
                Some(Value::Null) | None => {}
                Some(_) => {
                    return Err(format!(
                        "response_mock: rule[{i}] 'headers' must be an object"
                    ));
                }
            }
            if !headers.contains_key("content-type") {
                headers.insert("content-type".to_string(), "application/json".to_string());
            }

            let body = match rule_obj.get("body") {
                Some(Value::String(body)) => body.clone(),
                Some(Value::Null) | None => String::new(),
                Some(_) => {
                    return Err(format!("response_mock: rule[{i}] 'body' must be a string"));
                }
            };

            let delay_ms = optional_u64(rule_obj, "delay_ms", i)?.unwrap_or(0);
            if delay_ms > MAX_DELAY_MS {
                return Err(format!(
                    "response_mock: rule[{i}] 'delay_ms' must be <= {MAX_DELAY_MS}, got {delay_ms}"
                ));
            }

            rules.push(MockRule {
                method,
                path,
                status_code,
                headers,
                body,
                delay_ms,
            });
        }

        Ok(Self {
            rules,
            passthrough_on_no_match,
        })
    }

    fn find_match(&self, method: &str, path: &str) -> Option<&MockRule> {
        self.rules.iter().find(|rule| {
            if rule.method.as_ref().is_some_and(|m| m != method) {
                return false;
            }

            match &rule.path {
                PathMatcher::Exact(p) => p == path,
                PathMatcher::Regex(re) => re.is_match(path),
            }
        })
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
        "response_mock: unknown config key(s) under '{path}': {}; allowed keys: {}",
        unknown.join(", "),
        allowed.join(", ")
    ))
}

fn optional_bool(config: &Map<String, Value>, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("response_mock: '{key}' must be a boolean")),
    }
}

fn optional_u64(
    config: &Map<String, Value>,
    key: &str,
    rule_idx: usize,
) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value.as_u64().map(Some).ok_or_else(|| {
            format!("response_mock: rule[{rule_idx}] '{key}' must be an unsigned integer")
        }),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!(
            "response_mock: rule[{rule_idx}] '{key}' must be an unsigned integer"
        )),
    }
}

fn optional_status_code(rule_val: &Map<String, Value>, rule_idx: usize) -> Result<u16, String> {
    let Some(raw) = optional_u64(rule_val, "status_code", rule_idx)? else {
        return Ok(200);
    };

    if !(100..=599).contains(&raw) {
        return Err(format!(
            "response_mock: rule[{rule_idx}] 'status_code' must be in range 100-599"
        ));
    }

    let status = raw as u16;
    // A mock short-circuit is a single final response. Unsupported
    // informational statuses cannot be followed by a non-1xx final response, so
    // reject them at construction. Status 101 remains allowed solely for a
    // synthetic WebSocket handshake response (still not an upgraded frame
    // stream).
    if (100..200).contains(&status) && status != 101 {
        return Err(format!(
            "response_mock: rule[{rule_idx}] 'status_code' {status} is an unsupported \
             informational status; use a final status (200–599), or 101 only for a \
             synthetic WebSocket handshake response"
        ));
    }

    Ok(status)
}

#[async_trait]
impl Plugin for ResponseMock {
    fn name(&self) -> &str {
        "response_mock"
    }

    fn priority(&self) -> u16 {
        super::priority::RESPONSE_MOCK
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_PROTOCOLS
    }

    fn defer_before_proxy_until_backend_path_resolved(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Strip the proxy's listen_path prefix so mock rules are relative to
        // the proxy scope. Several cases where no stripping applies:
        // - Host-only proxies (listen_path == None): no prefix to strip
        // - Regex listen_paths (`~` prefix): no literal prefix to strip
        // - Exact listen_paths (`=` prefix): match the full request path
        // - Root listen_path (`/`): avoid turning "/users" into "users"
        //
        // Uses `strip_prefix` which is char-boundary-safe — byte-indexed
        // slicing would panic if a listen_path byte-length landed mid-UTF-8
        // codepoint in a non-matching `ctx.path` (unlikely in practice since
        // the router already matched the prefix, but defence-in-depth).
        let match_path = match ctx
            .matched_proxy
            .as_ref()
            .and_then(|p| p.listen_path.as_deref())
        {
            Some(listen_path)
                if !listen_path.starts_with('~')
                    && !listen_path.starts_with('=')
                    && listen_path != "/" =>
            {
                match ctx.path.strip_prefix(listen_path) {
                    Some("") => "/",
                    Some(rest) => rest,
                    // Router gave us a mismatched path — fall back to the full
                    // path rather than panic.
                    None => ctx.path.as_str(),
                }
            }
            _ => ctx.path.as_str(),
        };

        if let Some(rule) = self.find_match(&ctx.method, match_path) {
            if rule.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(rule.delay_ms)).await;
            }

            return PluginResult::Reject {
                status_code: rule.status_code,
                body: rule.body.clone(),
                headers: rule.headers.clone(),
            };
        }

        if self.passthrough_on_no_match {
            PluginResult::Continue
        } else {
            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            PluginResult::Reject {
                status_code: 404,
                body: r#"{"error":"no mock rule matched"}"#.to_string(),
                headers,
            }
        }
    }
}
