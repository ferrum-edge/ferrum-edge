//! Response Mock Plugin
//!
//! Returns configurable mock responses without proxying to the backend.
//! Supports matching by HTTP method, path pattern (exact or regex), and
//! optional exact request header / query parameter conditions, with
//! configurable status codes, headers, body, and optional latency simulation.
//! Useful for early API testing before backends are ready, contract testing,
//! and local development.
//!
//! ## Path Matching
//!
//! Mock rule paths are **relative to a prefix `listen_path`**. Trailing
//! slashes on the prefix are trimmed before stripping. The plugin
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
//! Exact rule paths are indexed at construction, and every regex rule path is
//! prefiltered by one combined `RegexSet` pass, so a request does not walk
//! every rule. Ordered first-match-wins semantics are unchanged.
//!
//! ## WebSocket handshake
//!
//! `response_mock` supports HTTP and WebSocket upgrade handshakes. A matching
//! rule short-circuits only the HTTP handshake response. It does **not**
//! establish or mock an upgraded WebSocket frame stream, so it never claims a
//! successful handshake: a `2xx` rule that matches a WebSocket handshake fails
//! closed with `500` on every frontend (an HTTP/2 or HTTP/3 Extended CONNECT
//! `2xx` would otherwise be read as an established tunnel, and HTTP/2 resets a
//! `2xx` CONNECT response that carries a body). `101` is rejected at
//! construction: it is an HTTP/1.1-only informational status that HTTP/2 and
//! HTTP/3 cannot carry, and no mock can upgrade the connection.
//!
//! ## Native gRPC
//!
//! Native gRPC is **not** supported. Gateway reject normalization turns plugin
//! rejects into trailers-only gRPC errors and discards the configured body, so
//! advertising gRPC would make a default `status_code: 200` mock surface as
//! `grpc-status: 13` (`INTERNAL`) without a payload. Configure HTTP or
//! WebSocket mocks only; native gRPC traffic continues to the backend.
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
//!       "path": "/users",
//!       "match": { "headers": { "x-scenario": "empty" }, "query_params": { "page": "2" } },
//!       "body": "[]"
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
//! - **rules**: Array of 1–1024 mock rules evaluated in order (first match wins)
//!   - **method**: HTTP method token to match (optional; omit to match all
//!     methods). When supplied it must be non-empty and parse as an HTTP
//!     method token. Registered standard methods are matched case-insensitively
//!     (`get` matches `GET`); extension methods are case-sensitive and match
//!     the configured spelling exactly (`Foo` matches `Foo`, not `FOO`).
//!   - **path**: Non-empty path relative to a prefix listen_path, full path
//!     for exact/regex/root/host-only scopes, or regex with `~` prefix
//!     (required)
//!   - **match**: Optional extra request conditions; every one must hold.
//!     `headers` (1–16 names) compares each client-sent header field line
//!     byte-for-byte (names case-insensitive, values case-sensitive);
//!     gateway-asserted names are rejected. `query_params` (1–16 names)
//!     compares the percent-decoded query value exactly (last occurrence
//!     wins; a bare `?flag` has the value `""`). A rule whose conditions do
//!     not hold is skipped and evaluation continues with the next rule.
//!   - **status_code**: HTTP status to return (default: 200). Must be a final
//!     status `200–599`. Informational statuses (`100`–`199`, including `101`)
//!     are rejected — a mock cannot emit a 1xx as a final response or upgrade
//!     the connection.
//!   - **headers**: Response headers (default: `{"content-type": "application/json"}`),
//!     at most 64 entries with values of at most 8192 bytes.
//!     Protocol-managed hop-by-hop and framing names (`Connection`,
//!     `Transfer-Encoding`, `Trailer`, `Upgrade`, `Content-Length`, …) are
//!     rejected at construction; the gateway derives `Content-Length` from the
//!     mock body/status/method and strips connection/framing fields at the final
//!     response boundary.
//!   - **body**: Response body string (default: empty, at most 262144 bytes).
//!     On the wire, `HEAD` responses omit content bytes while keeping
//!     representation metadata (including `Content-Length`). Statuses
//!     `204`/`205`/`304` omit both the body and `Content-Length`, even when a
//!     non-empty `body` is configured.
//!   - **delay_ms**: Simulated latency in milliseconds (default: 0, max
//!     60,000 = 1 minute, the shared fault-delay ceiling; larger values are
//!     rejected at construction)
//! - **passthrough_on_no_match**: If true, requests not matching any rule
//!   continue to the backend. If false (default), unmatched requests get 404.
//!
//! Unknown top-level, per-rule, and `match` keys are rejected at construction.
//! The free-form `headers` map rejects protocol-managed hop-by-hop and framing
//! destinations. HEAD / no-body wire shape is applied by the shared
//! synthetic-response finalizer so H1, H2, and H3 stay aligned.
//!
//! ## Delay retention bounds
//!
//! `delay_ms` deliberately parks a live request, so it runs through the shared
//! fault-delay machinery ([`super::utils::fault_delay`]) instead of a bare
//! timer: the one-minute ceiling, the process-wide delayed-work budget
//! (`FERRUM_MAX_CONCURRENT_FAULT_DELAYS`, shared with `fault_injection`), and
//! cancellation on gateway shutdown drain and on HTTP/3 peer departure. A delay
//! skipped by an exhausted budget or cut short by shutdown serves the mock
//! immediately; a delay cut short because the client transport is gone answers
//! `499` with no body. Any non-completing delay records `fault_delay_outcome`
//! in request metadata.

use async_trait::async_trait;
use bytes::Bytes;
use http::{
    Method,
    header::{HeaderName, HeaderValue},
};
use regex::{Regex, RegexSet};
use serde_json::{Map, Value};
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;

use super::fault_injection::{CLIENT_GONE_STATUS, FAULT_DELAY_OUTCOME_METADATA_KEY};
use super::utils::fault_delay::{
    FAULT_DELAY_ADMISSION, FaultDelayAdmission, FaultDelayOutcome, fault_delay_shutdown,
    run_fault_delay_in,
};
use super::utils::fault_roll::MAX_FAULT_DELAY_MS;
use super::{Plugin, PluginResult, RequestContext};

/// Every accepted top-level configuration property.
pub const RESPONSE_MOCK_CONFIG_KEYS: &[&str] = &["rules", "passthrough_on_no_match"];

/// Every accepted per-rule configuration property.
pub const RESPONSE_MOCK_RULE_KEYS: &[&str] = &[
    "method",
    "path",
    "match",
    "status_code",
    "headers",
    "body",
    "delay_ms",
];

/// Every accepted property of a rule's `match` object.
pub const RESPONSE_MOCK_MATCH_KEYS: &[&str] = &["headers", "query_params"];

/// Upper bound for a rule's `delay_ms`: the shared fault-delay ceiling
/// (1 minute). The delay runs through `fault_delay::run_fault_delay_in`, which
/// clamps to the same value, so accepting more would silently shorten it.
pub const RESPONSE_MOCK_MAX_DELAY_MS: u64 = MAX_FAULT_DELAY_MS;

/// Most rules one instance accepts. Bounds construction work (every regex is
/// compiled) and the retained per-generation footprint.
pub const RESPONSE_MOCK_MAX_RULES: usize = 1024;

/// Largest configured `body`, in UTF-8 bytes.
pub const RESPONSE_MOCK_MAX_BODY_BYTES: usize = 262_144;

/// Most configured response headers per rule.
pub const RESPONSE_MOCK_MAX_HEADERS_PER_RULE: usize = 64;

/// Largest configured response header value, and largest `match` value.
pub const RESPONSE_MOCK_MAX_HEADER_VALUE_BYTES: usize = 8192;

/// Most conditions in each of `match.headers` and `match.query_params`.
pub const RESPONSE_MOCK_MAX_MATCH_CONDITIONS: usize = 16;

/// Largest `match.query_params` parameter name, in bytes.
pub const RESPONSE_MOCK_MAX_QUERY_PARAM_NAME_BYTES: usize = 256;

/// HTTP + WebSocket handshake only. Native gRPC is excluded because plugin
/// rejects are normalized to trailers-only gRPC errors that drop configured
/// bodies (issue #2442).
const RESPONSE_MOCK_PROTOCOLS: &[super::ProxyProtocol] =
    &[super::ProxyProtocol::Http, super::ProxyProtocol::WebSocket];

const NO_MATCH_BODY: &[u8] = br#"{"error":"no mock rule matched"}"#;
const WEBSOCKET_SUCCESS_REFUSAL_BODY: &[u8] = br#"{"error":"response_mock cannot mock a successful WebSocket handshake; configure a non-2xx status_code"}"#;

/// Optional per-rule request conditions. Every listed condition must hold.
struct RequestMatch {
    /// Lowercased header name and exact expected field-line value.
    headers: Vec<(String, String)>,
    /// Query parameter name and exact expected (percent-decoded) value.
    query_params: Vec<(String, String)>,
}

impl RequestMatch {
    /// Allocation-free: borrows the client's pristine field lines and the
    /// materialized query map in place.
    fn matches(&self, ctx: &RequestContext) -> bool {
        self.headers.iter().all(|(name, value)| {
            ctx.header_field_lines(name.as_str())
                .any(|line| line == value.as_bytes())
        }) && self.query_params.iter().all(|(name, value)| {
            ctx.query_params
                .get(name.as_str())
                .is_some_and(|actual| actual == value)
        })
    }
}

struct MockRule {
    method: Option<String>,
    /// `None` for an exact rule path (served from the exact-path index).
    path_regex: Option<Regex>,
    request_match: Option<RequestMatch>,
    status_code: u16,
    headers: HashMap<String, String>,
    /// Immutable across requests: each hit hands out a reference-counted
    /// clone instead of copying the configured bytes.
    body: Bytes,
    delay_ms: u64,
}

impl MockRule {
    /// Every condition other than the path.
    fn matches_request(&self, method: &str, ctx: &RequestContext) -> bool {
        if self.method.as_ref().is_some_and(|m| m != method) {
            return false;
        }
        self.request_match
            .as_ref()
            .is_none_or(|request_match| request_match.matches(ctx))
    }
}

pub struct ResponseMock {
    rules: Vec<MockRule>,
    /// Exact rule path → ascending indices of every exact rule with that path.
    exact_index: HashMap<String, Vec<usize>>,
    /// Ascending indices of every regex rule.
    regex_rule_indices: Vec<usize>,
    /// Combined prefilter over every regex rule path, in `regex_rule_indices`
    /// order. `None` with fewer than two regex rules, or when the combined set
    /// exceeds the regex compile limits (each pattern already compiled on its
    /// own, so only the prefilter is lost, never a rule).
    regex_set: Option<RegexSet>,
    passthrough_on_no_match: bool,
    delay_admission: &'static FaultDelayAdmission,
    delay_shutdown: &'static CancellationToken,
}

/// Returns `true` when `method` is one of the registered standard HTTP
/// methods. Only these tokens are case-folded to their canonical uppercase
/// spelling for matching; extension methods are case-sensitive per RFC 9110
/// §9.1 and keep their configured spelling, so a rule written as `Foo` matches
/// a request method `Foo` and never `FOO`.
fn is_registered_standard_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH"
    )
}

impl ResponseMock {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config = config.as_object().ok_or_else(|| {
            format!(
                "response_mock: config must be an object; allowed keys: `{}`",
                RESPONSE_MOCK_CONFIG_KEYS.join("`, `")
            )
        })?;
        reject_unknown_keys(config, "config", RESPONSE_MOCK_CONFIG_KEYS)?;

        let passthrough_on_no_match =
            optional_bool(config, "passthrough_on_no_match")?.unwrap_or(false);

        let rules_val = match config.get("rules") {
            Some(Value::Array(rules)) => rules,
            _ => return Err("response_mock: `rules` must be a JSON array".to_string()),
        };

        if rules_val.is_empty() {
            return Err("response_mock: `rules` array must not be empty".to_string());
        }
        if rules_val.len() > RESPONSE_MOCK_MAX_RULES {
            return Err(format!(
                "response_mock: `rules` must contain at most {RESPONSE_MOCK_MAX_RULES} rules"
            ));
        }

        let mut rules = Vec::with_capacity(rules_val.len());
        let mut exact_index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut regex_rule_indices = Vec::new();
        let mut regex_patterns: Vec<String> = Vec::new();

        for (i, rule_val) in rules_val.iter().enumerate() {
            let rule_obj = rule_val
                .as_object()
                .ok_or_else(|| format!("response_mock: `rule[{i}]` must be an object"))?;
            let rule_path = format!("config.rules[{i}]");
            reject_unknown_keys(rule_obj, &rule_path, RESPONSE_MOCK_RULE_KEYS)?;

            let method = match rule_obj.get("method") {
                Some(Value::String(method)) if !method.is_empty() => {
                    Method::from_bytes(method.as_bytes()).map_err(|_| {
                        format!(
                            "response_mock: `rule[{i}]` `method` must be a valid HTTP method token"
                        )
                    })?;
                    let uppercased = method.to_ascii_uppercase();
                    // Registered standard methods are case-folded for the
                    // convenience of lowercase configs (`get` matches `GET`).
                    // Extension methods are case-sensitive and must keep the
                    // configured spelling or a rule can never match.
                    let canonical = if is_registered_standard_method(&uppercased) {
                        uppercased
                    } else {
                        method.clone()
                    };
                    Some(canonical)
                }
                Some(Value::String(_)) => {
                    return Err(format!(
                        "response_mock: `rule[{i}]` `method` must not be empty"
                    ));
                }
                Some(Value::Null) | None => None,
                Some(_) => {
                    return Err(format!(
                        "response_mock: `rule[{i}]` `method` must be a string"
                    ));
                }
            };

            let path_str = rule_obj
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("response_mock: `rule[{i}]` missing `path`"))?;
            if path_str.is_empty() {
                return Err(format!(
                    "response_mock: `rule[{i}]` `path` must not be empty"
                ));
            }

            let path_regex = if let Some(pattern) = path_str.strip_prefix('~') {
                if pattern.is_empty() {
                    return Err(format!(
                        "response_mock: `rule[{i}]` regex path must not be empty"
                    ));
                }
                let anchored = crate::config::types::anchor_regex_pattern(pattern);
                let re = Regex::new(&anchored).map_err(|_| {
                    format!(
                        "response_mock: `rule[{i}].path`: invalid regex or complexity limit exceeded"
                    )
                })?;
                regex_patterns.push(anchored);
                Some(re)
            } else {
                None
            };

            let request_match = parse_request_match(rule_obj.get("match"), i)?;

            let status_code = optional_status_code(rule_obj, i)?;

            let mut headers = HashMap::new();
            match rule_obj.get("headers") {
                Some(Value::Object(obj)) => {
                    if obj.len() > RESPONSE_MOCK_MAX_HEADERS_PER_RULE {
                        return Err(format!(
                            "response_mock: `rule[{i}]` `headers` must contain at most \
                             {RESPONSE_MOCK_MAX_HEADERS_PER_RULE} entries"
                        ));
                    }
                    for (k, v) in obj {
                        HeaderName::from_bytes(k.as_bytes()).map_err(|_| {
                            format!("response_mock: `rule[{i}]` header {k:?} is not a valid name")
                        })?;
                        let s = v.as_str().ok_or_else(|| {
                            format!(
                                "response_mock: `rule[{i}]` header {k:?} value must be a string"
                            )
                        })?;
                        if s.len() > RESPONSE_MOCK_MAX_HEADER_VALUE_BYTES {
                            return Err(format!(
                                "response_mock: `rule[{i}]` header {k:?} value must be at most \
                                 {RESPONSE_MOCK_MAX_HEADER_VALUE_BYTES} bytes"
                            ));
                        }
                        HeaderValue::from_str(s).map_err(|_| {
                            format!("response_mock: `rule[{i}]` header {k:?} value is invalid")
                        })?;
                        let lower = k.to_ascii_lowercase();
                        if crate::proxy::headers::is_protocol_managed_plugin_response_destination(
                            &lower,
                        ) {
                            return Err(format!(
                                "response_mock: `rule[{i}]` header {k:?} is protocol-managed \
                                 (hop-by-hop or framing) and cannot be configured; the gateway \
                                 derives Content-Length from the mock body/status/method and \
                                 strips Connection/Transfer-Encoding/Trailer/Upgrade at the \
                                 final response boundary"
                            ));
                        }
                        headers.insert(lower, s.to_string());
                    }
                }
                Some(Value::Null) | None => {}
                Some(_) => {
                    return Err(format!(
                        "response_mock: `rule[{i}]` `headers` must be an object"
                    ));
                }
            }
            if !headers.contains_key("content-type") {
                headers.insert("content-type".to_string(), "application/json".to_string());
            }

            let body = match rule_obj.get("body") {
                Some(Value::String(body)) => {
                    if body.len() > RESPONSE_MOCK_MAX_BODY_BYTES {
                        return Err(format!(
                            "response_mock: `rule[{i}]` `body` must be at most \
                             {RESPONSE_MOCK_MAX_BODY_BYTES} bytes"
                        ));
                    }
                    Bytes::from(body.clone())
                }
                Some(Value::Null) | None => Bytes::new(),
                Some(_) => {
                    return Err(format!(
                        "response_mock: `rule[{i}]` `body` must be a string"
                    ));
                }
            };

            let delay_ms = optional_u64(rule_obj, "delay_ms", i)?.unwrap_or(0);
            if delay_ms > RESPONSE_MOCK_MAX_DELAY_MS {
                return Err(format!(
                    "response_mock: `rule[{i}]` `delay_ms` must be <= {RESPONSE_MOCK_MAX_DELAY_MS}, got \"{delay_ms}\""
                ));
            }

            if path_regex.is_some() {
                regex_rule_indices.push(i);
            } else {
                exact_index.entry(path_str.to_string()).or_default().push(i);
            }

            rules.push(MockRule {
                method,
                path_regex,
                request_match,
                status_code,
                headers,
                body,
                delay_ms,
            });
        }

        let regex_set = if regex_patterns.len() >= 2 {
            RegexSet::new(&regex_patterns).ok()
        } else {
            None
        };

        Ok(Self {
            rules,
            exact_index,
            regex_rule_indices,
            regex_set,
            passthrough_on_no_match,
            delay_admission: &FAULT_DELAY_ADMISSION,
            delay_shutdown: fault_delay_shutdown(),
        })
    }

    /// Replace the process-wide delayed-work budget and shutdown token with
    /// caller-owned ones. Test seam: production always uses the process-wide
    /// pair, and cancelling the process-global one-shot token from a test
    /// would disarm every other delay in the same test binary.
    #[doc(hidden)]
    pub fn with_delay_bounds(
        mut self,
        admission: &'static FaultDelayAdmission,
        shutdown: &'static CancellationToken,
    ) -> Self {
        self.delay_admission = admission;
        self.delay_shutdown = shutdown;
        self
    }

    /// Ordered first match over every rule, without walking them all.
    ///
    /// The earliest exact candidate comes from one hash lookup. Regex rules
    /// only win when they precede it, so only those are evaluated, in order,
    /// and only after the combined prefilter says some regex rule path can
    /// match at all. The result is identical to scanning `rules` in order.
    fn find_match(&self, ctx: &RequestContext, path: &str) -> Option<&MockRule> {
        let method = ctx.method.as_str();
        let exact = self.exact_index.get(path).and_then(|indices| {
            indices.iter().copied().find(|&index| {
                self.rules
                    .get(index)
                    .is_some_and(|rule| rule.matches_request(method, ctx))
            })
        });

        let regex_may_match = !self.regex_rule_indices.is_empty()
            && self.regex_set.as_ref().is_none_or(|set| set.is_match(path));
        let regex = if regex_may_match {
            self.regex_rule_indices
                .iter()
                .copied()
                .take_while(|&index| exact.is_none_or(|candidate| index < candidate))
                .find(|&index| {
                    self.rules.get(index).is_some_and(|rule| {
                        rule.path_regex.as_ref().is_some_and(|re| re.is_match(path))
                            && rule.matches_request(method, ctx)
                    })
                })
        } else {
            None
        };

        // `take_while` keeps any regex winner strictly before the exact one.
        regex.or(exact).and_then(|index| self.rules.get(index))
    }
}

fn parse_request_match(
    value: Option<&Value>,
    rule_idx: usize,
) -> Result<Option<RequestMatch>, String> {
    let match_obj = match value {
        Some(Value::Object(match_obj)) => match_obj,
        Some(Value::Null) | None => return Ok(None),
        Some(_) => {
            return Err(format!(
                "response_mock: `rule[{rule_idx}]` `match` must be an object"
            ));
        }
    };
    let match_path = format!("config.rules[{rule_idx}].match");
    reject_unknown_keys(match_obj, &match_path, RESPONSE_MOCK_MATCH_KEYS)?;
    if match_obj.is_empty() {
        return Err(format!(
            "response_mock: `rule[{rule_idx}]` `match` must contain `headers` or `query_params`"
        ));
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(raw) = match_obj.get("headers") {
        let Value::Object(headers_obj) = raw else {
            return Err(format!(
                "response_mock: `rule[{rule_idx}]` `match.headers` must be an object"
            ));
        };
        check_condition_count(headers_obj, rule_idx, "headers")?;
        for (raw_name, raw_value) in headers_obj {
            // Normalizes to lowercase, the form every stored field line uses.
            let name = HeaderName::from_bytes(raw_name.as_bytes()).map_err(|_| {
                format!(
                    "response_mock: `rule[{rule_idx}]` `match.headers` names must be valid HTTP \
                     header names"
                )
            })?;
            let name = name.as_str();
            if RequestContext::is_reserved_gateway_assertion_header(name) {
                return Err(format!(
                    "response_mock: `rule[{rule_idx}]` `match.headers` must not name \
                     gateway-asserted headers"
                ));
            }
            if headers.iter().any(|(existing, _)| existing == name) {
                return Err(format!(
                    "response_mock: `rule[{rule_idx}]` `match.headers` names must be unique \
                     ignoring case"
                ));
            }
            let value = condition_value(raw_value, rule_idx, "headers")?;
            if HeaderValue::from_str(value).is_err() {
                return Err(format!(
                    "response_mock: `rule[{rule_idx}]` `match.headers` values must be valid HTTP \
                     header values"
                ));
            }
            headers.push((name.to_string(), value.to_string()));
        }
    }

    let mut query_params: Vec<(String, String)> = Vec::new();
    if let Some(raw) = match_obj.get("query_params") {
        let Value::Object(query_obj) = raw else {
            return Err(format!(
                "response_mock: `rule[{rule_idx}]` `match.query_params` must be an object"
            ));
        };
        check_condition_count(query_obj, rule_idx, "query_params")?;
        for (name, raw_value) in query_obj {
            if name.is_empty() || name.len() > RESPONSE_MOCK_MAX_QUERY_PARAM_NAME_BYTES {
                return Err(format!(
                    "response_mock: `rule[{rule_idx}]` `match.query_params` names must be 1-\
                     {RESPONSE_MOCK_MAX_QUERY_PARAM_NAME_BYTES} bytes"
                ));
            }
            let value = condition_value(raw_value, rule_idx, "query_params")?;
            query_params.push((name.clone(), value.to_string()));
        }
    }

    Ok(Some(RequestMatch {
        headers,
        query_params,
    }))
}

fn check_condition_count(
    conditions: &Map<String, Value>,
    rule_idx: usize,
    field: &str,
) -> Result<(), String> {
    if conditions.is_empty() {
        return Err(format!(
            "response_mock: `rule[{rule_idx}]` `match.{field}` must name at least one entry"
        ));
    }
    if conditions.len() > RESPONSE_MOCK_MAX_MATCH_CONDITIONS {
        return Err(format!(
            "response_mock: `rule[{rule_idx}]` `match.{field}` must name at most \
             {RESPONSE_MOCK_MAX_MATCH_CONDITIONS} entries"
        ));
    }
    Ok(())
}

fn condition_value<'a>(value: &'a Value, rule_idx: usize, field: &str) -> Result<&'a str, String> {
    let Value::String(value) = value else {
        return Err(format!(
            "response_mock: `rule[{rule_idx}]` `match.{field}` values must be strings"
        ));
    };
    if value.len() > RESPONSE_MOCK_MAX_HEADER_VALUE_BYTES {
        return Err(format!(
            "response_mock: `rule[{rule_idx}]` `match.{field}` values must be at most \
             {RESPONSE_MOCK_MAX_HEADER_VALUE_BYTES} bytes"
        ));
    }
    Ok(value.as_str())
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
        "response_mock: unknown config key(s) under `{path}`: {:?}; allowed keys: `{}`",
        unknown.join(", "),
        allowed.join("`, `")
    ))
}

fn optional_bool(config: &Map<String, Value>, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("response_mock: `{key}` must be a boolean")),
    }
}

fn optional_u64(
    config: &Map<String, Value>,
    key: &str,
    rule_idx: usize,
) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value.as_u64().map(Some).ok_or_else(|| {
            format!("response_mock: `rule[{rule_idx}]` `{key}` must be an unsigned integer")
        }),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!(
            "response_mock: `rule[{rule_idx}]` `{key}` must be an unsigned integer"
        )),
    }
}

fn optional_status_code(rule_val: &Map<String, Value>, rule_idx: usize) -> Result<u16, String> {
    let Some(raw) = optional_u64(rule_val, "status_code", rule_idx)? else {
        return Ok(200);
    };

    if !(100..=599).contains(&raw) {
        return Err(format!(
            "response_mock: `rule[{rule_idx}]` `status_code` must be in range 100-599"
        ));
    }

    let status = raw as u16;
    // A mock short-circuit is a single final response. An informational status
    // cannot be followed by a final response here, and 101 would claim an
    // upgrade no mock performs (and that HTTP/2 / HTTP/3 cannot carry at all).
    if (100..200).contains(&status) {
        return Err(format!(
            "response_mock: `rule[{rule_idx}]` `status_code` \"{status}\" is an unsupported \
             informational status; use a final status (200–599)"
        ));
    }

    Ok(status)
}

fn json_reject(status_code: u16, body: &'static [u8]) -> PluginResult {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    PluginResult::RejectBinary {
        status_code,
        body: Bytes::from_static(body),
        headers,
    }
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
        RESPONSE_MOCK_PROTOCOLS
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
                let normalized_listen_path = listen_path.trim_end_matches('/');
                match ctx.path.strip_prefix(normalized_listen_path) {
                    Some("") => "/",
                    Some(rest) => rest,
                    // Router gave us a mismatched path — fall back to the full
                    // path rather than panic.
                    None => ctx.path.as_str(),
                }
            }
            _ => ctx.path.as_str(),
        };

        let Some(rule) = self.find_match(ctx, match_path) else {
            return if self.passthrough_on_no_match {
                PluginResult::Continue
            } else {
                json_reject(404, NO_MATCH_BODY)
            };
        };

        // A mock never establishes a WebSocket, so it must not claim a
        // successful handshake. On HTTP/2 / HTTP/3 Extended CONNECT a 2xx
        // means "tunnel established" (and HTTP/2 resets a 2xx CONNECT
        // response that carries a body); failing closed on every frontend
        // keeps one rule set behaving identically on H1, H2, and H3. The
        // request flavor is stamped before plugin hooks and cannot be forged
        // by mutable request headers.
        if ctx.has_websocket_response_boundary() && (200..300).contains(&rule.status_code) {
            return json_reject(500, WEBSOCKET_SUCCESS_REFUSAL_BODY);
        }

        if rule.delay_ms > 0 && !self.run_delay(ctx, rule.delay_ms).await {
            // The client transport is gone; nobody is left to read a mock.
            // The proxy path's normal rejection cleanup releases the request
            // guard and finalizes the stream.
            return PluginResult::Reject {
                status_code: CLIENT_GONE_STATUS,
                body: String::new(),
                headers: HashMap::new(),
            };
        }

        PluginResult::RejectBinary {
            status_code: rule.status_code,
            body: rule.body.clone(),
            headers: rule.headers.clone(),
        }
    }
}

impl ResponseMock {
    /// Run a rule's simulated latency under the shared fault-delay bounds and
    /// record a non-completing outcome. Returns `false` only when the client
    /// transport is gone and the mock must not be served.
    async fn run_delay(&self, ctx: &mut RequestContext, delay_ms: u64) -> bool {
        // Cheap non-blocking pre-check: an already-dead transport must not
        // even consume a slot from the process-wide delayed-work budget.
        if ctx
            .peer_connection
            .as_ref()
            .is_some_and(|signal| signal.is_closed())
        {
            record_delay_outcome(ctx, FaultDelayOutcome::CancelledByPeer);
            return false;
        }

        // Race the timer against the frontend's peer-gone watch (HTTP/3 only
        // today) and the gateway shutdown token. Clone the handle (one `Arc`
        // bump, delay path only) so the borrow of `ctx` ends before the
        // metadata write below.
        let signal = ctx.peer_connection.clone();
        let peer_gone = signal.as_ref().map(|signal| signal.closed());
        let outcome = run_fault_delay_in(
            self.delay_admission,
            self.delay_shutdown,
            delay_ms,
            peer_gone,
        )
        .await;
        if !outcome.completed() {
            record_delay_outcome(ctx, outcome);
        }
        // Shutdown and an exhausted budget serve the mock immediately: the
        // delay is a simulation, never enforcement.
        outcome != FaultDelayOutcome::CancelledByPeer
    }
}

/// Values are compiled-in labels from a closed enum, never request-, peer-, or
/// credential-derived.
fn record_delay_outcome(ctx: &mut RequestContext, outcome: FaultDelayOutcome) {
    ctx.metadata.insert(
        FAULT_DELAY_OUTCOME_METADATA_KEY.to_string(),
        outcome.metadata_label().to_string(),
    );
}
