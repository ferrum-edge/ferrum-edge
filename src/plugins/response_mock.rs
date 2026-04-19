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
//! Mock rule paths are **relative to the proxy's `listen_path`**. The plugin
//! strips the proxy's prefix listen_path from the incoming request path before
//! matching rules. For example, if the proxy has `listen_path: /api/v1` and
//! a request arrives at `/api/v1/users`, the mock rule path should be `/users`.
//!
//! For proxies with regex listen_paths (`~` prefix), the full request path is
//! used since there is no literal prefix to strip.
//!
//! A request to exactly the listen_path itself (e.g., `/api/v1` with no
//! trailing component) is matched as `/`.
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
//!   - **method**: HTTP method to match (optional; omit to match all methods)
//!   - **path**: Path relative to the proxy's listen_path, or regex with `~`
//!     prefix (required)
//!   - **status_code**: HTTP status to return (default: 200)
//!   - **headers**: Response headers (default: `{"content-type": "application/json"}`)
//!   - **body**: Response body string (default: empty)
//!   - **delay_ms**: Simulated latency in milliseconds (default: 0)
//! - **passthrough_on_no_match**: If true, requests not matching any rule
//!   continue to the backend. If false (default), unmatched requests get 404.

use async_trait::async_trait;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;

use super::{Plugin, PluginResult, RequestContext};

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
        let passthrough_on_no_match = config["passthrough_on_no_match"].as_bool().unwrap_or(false);

        let rules_val = config["rules"]
            .as_array()
            .ok_or("response_mock: 'rules' must be a JSON array")?;

        if rules_val.is_empty() {
            return Err("response_mock: 'rules' array must not be empty".to_string());
        }

        let mut rules = Vec::with_capacity(rules_val.len());

        for (i, rule_val) in rules_val.iter().enumerate() {
            let method = rule_val["method"].as_str().map(|m| m.to_uppercase());

            let path_str = rule_val["path"]
                .as_str()
                .ok_or_else(|| format!("response_mock: rule[{i}] missing 'path'"))?;

            let path = if let Some(pattern) = path_str.strip_prefix('~') {
                let anchored = crate::config::types::anchor_regex_pattern(pattern);
                let re = Regex::new(&anchored).map_err(|e| {
                    format!("response_mock: rule[{i}] invalid regex '{pattern}': {e}")
                })?;
                PathMatcher::Regex(re)
            } else {
                PathMatcher::Exact(path_str.to_string())
            };

            let status_code = rule_val["status_code"]
                .as_u64()
                .map(|c| c as u16)
                .filter(|&c| (100..=599).contains(&c))
                .unwrap_or(200);

            let mut headers = HashMap::new();
            if let Some(obj) = rule_val["headers"].as_object() {
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        headers.insert(k.to_lowercase(), s.to_string());
                    }
                }
            }
            if !headers.contains_key("content-type") {
                headers.insert("content-type".to_string(), "application/json".to_string());
            }

            let body = rule_val["body"].as_str().unwrap_or("").to_string();

            let delay_ms = rule_val["delay_ms"].as_u64().unwrap_or(0);

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

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Strip the proxy's listen_path prefix so mock rules are relative to
        // the proxy scope. Several cases where no stripping applies:
        // - Host-only proxies (listen_path == None): no prefix to strip
        // - Regex listen_paths (`~` prefix): no literal prefix to strip
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
            Some(listen_path) if !listen_path.starts_with('~') && listen_path != "/" => {
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
