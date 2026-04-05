//! GraphQL Plugin
//!
//! Adds GraphQL-aware proxying capabilities:
//! - Query parsing and operation extraction
//! - Query depth limiting (prevents deeply nested queries)
//! - Query complexity limiting (caps total field count)
//! - Alias count limiting (prevents alias-based DoS)
//! - Per-operation-type rate limiting (query vs mutation vs subscription)
//! - Per-named-operation rate limiting (e.g., "getUser" vs "createOrder")
//! - Introspection control (allow/deny __schema/__type queries)
//!
//! GraphQL requests are expected as POST with `application/json` body
//! containing `{"query": "...", "operationName": "..."}`.

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use super::{Plugin, PluginResult, RequestContext};

/// Maximum rate-limit state entries before triggering stale eviction.
const MAX_STATE_ENTRIES: usize = 100_000;

/// A rate window spec parsed from config.
#[derive(Debug, Clone)]
struct RateSpec {
    max_requests: u64,
    window: Duration,
}

/// Token bucket for per-operation rate limiting.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(limit: u64, window: Duration) -> Self {
        let capacity = limit as f64;
        let window_secs = window.as_secs_f64().max(0.001);
        Self {
            tokens: capacity,
            capacity,
            refill_rate: capacity / window_secs,
            last_refill: Instant::now(),
        }
    }

    fn check_and_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn remaining(&self) -> u64 {
        self.tokens.max(0.0) as u64
    }

    fn has_recent_activity(&self, now: Instant) -> bool {
        let window_secs = self.capacity / self.refill_rate;
        now.duration_since(self.last_refill).as_secs_f64() < window_secs
    }
}

/// Parsed GraphQL operation info.
#[derive(Debug, Clone)]
struct GraphqlOperation {
    /// "query", "mutation", or "subscription"
    op_type: String,
    /// Named operation (from operationName field or parsed from query)
    op_name: Option<String>,
    /// Maximum nesting depth of selection sets
    depth: u32,
    /// Total field count (complexity proxy)
    complexity: u32,
    /// Number of aliases used
    alias_count: u32,
    /// Whether this is an introspection query
    is_introspection: bool,
}

pub struct GraphqlPlugin {
    max_depth: Option<u32>,
    max_complexity: Option<u32>,
    max_aliases: Option<u32>,
    introspection_allowed: bool,
    limit_by: String,
    /// Rate limits by operation type: "query", "mutation", "subscription"
    type_rate_limits: HashMap<String, RateSpec>,
    /// Rate limits by named operation
    operation_rate_limits: HashMap<String, RateSpec>,
    /// Token bucket state: key -> bucket
    state: Arc<DashMap<String, TokenBucket>>,
    has_any_config: bool,
}

impl GraphqlPlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let max_depth = config["max_depth"].as_u64().map(|v| v as u32);
        let max_complexity = config["max_complexity"].as_u64().map(|v| v as u32);
        let max_aliases = config["max_aliases"].as_u64().map(|v| v as u32);
        let introspection_allowed = config["introspection_allowed"].as_bool().unwrap_or(true);
        let limit_by = config["limit_by"].as_str().unwrap_or("ip").to_string();

        let mut type_rate_limits = HashMap::new();
        if let Some(obj) = config["type_rate_limits"].as_object() {
            for (op_type, spec) in obj {
                if let (Some(max_requests), Some(window_seconds)) = (
                    spec["max_requests"].as_u64(),
                    spec["window_seconds"].as_u64(),
                ) {
                    type_rate_limits.insert(
                        op_type.to_lowercase(),
                        RateSpec {
                            max_requests,
                            window: Duration::from_secs(window_seconds.max(1)),
                        },
                    );
                }
            }
        }

        let mut operation_rate_limits = HashMap::new();
        if let Some(obj) = config["operation_rate_limits"].as_object() {
            for (op_name, spec) in obj {
                if let (Some(max_requests), Some(window_seconds)) = (
                    spec["max_requests"].as_u64(),
                    spec["window_seconds"].as_u64(),
                ) {
                    operation_rate_limits.insert(
                        op_name.clone(),
                        RateSpec {
                            max_requests,
                            window: Duration::from_secs(window_seconds.max(1)),
                        },
                    );
                }
            }
        }

        let has_any_config = max_depth.is_some()
            || max_complexity.is_some()
            || max_aliases.is_some()
            || !introspection_allowed
            || !type_rate_limits.is_empty()
            || !operation_rate_limits.is_empty();

        if !has_any_config {
            return Err(
                "graphql: no protection rules configured — set 'max_depth', 'max_complexity', \
                 'max_aliases', 'introspection_allowed', 'type_rate_limits', or 'operation_rate_limits'"
                    .to_string(),
            );
        }

        Ok(Self {
            max_depth,
            max_complexity,
            max_aliases,
            introspection_allowed,
            limit_by,
            type_rate_limits,
            operation_rate_limits,
            state: Arc::new(DashMap::new()),
            has_any_config,
        })
    }

    /// Evict entries with no recent activity to bound memory.
    fn evict_stale_entries(&self) {
        if self.state.len() <= MAX_STATE_ENTRIES {
            return;
        }
        let now = Instant::now();
        self.state
            .retain(|_, bucket| bucket.has_recent_activity(now));
    }

    /// Check a rate limit by key, creating a bucket if needed.
    fn check_rate(&self, key: &str, spec: &RateSpec) -> bool {
        self.evict_stale_entries();
        let mut entry = self
            .state
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(spec.max_requests, spec.window));
        entry.check_and_consume()
    }

    /// Get remaining count for a key (for metadata/headers).
    fn get_remaining(&self, key: &str) -> Option<u64> {
        self.state.get(key).map(|bucket| bucket.remaining())
    }

    /// Build the rate limit key based on `limit_by` config.
    fn rate_key(&self, ctx: &RequestContext, suffix: &str) -> String {
        let identity = if self.limit_by == "consumer" {
            ctx.effective_identity().unwrap_or(ctx.client_ip.as_str())
        } else {
            ctx.client_ip.as_str()
        };
        format!("gql:{}:{}", identity, suffix)
    }
}

/// Parse a GraphQL query string to extract operation info.
///
/// This is a lightweight parser that handles the subset of GraphQL syntax
/// needed for depth/complexity/alias analysis without a full AST.
fn parse_graphql_query(query: &str, operation_name: Option<&str>) -> GraphqlOperation {
    let trimmed = query.trim();

    // Determine operation type from query text
    let (op_type, rest) = if let Some(rest) = trimmed.strip_prefix("mutation") {
        ("mutation", rest)
    } else if let Some(rest) = trimmed.strip_prefix("subscription") {
        ("subscription", rest)
    } else if let Some(rest) = trimmed.strip_prefix("query") {
        ("query", rest)
    } else {
        // Shorthand query: `{ ... }`
        ("query", trimmed)
    };

    // Extract operation name from query if not provided
    let parsed_name = extract_operation_name(rest);
    let op_name = operation_name
        .filter(|n| !n.is_empty())
        .map(String::from)
        .or(parsed_name);

    // Calculate depth and complexity by scanning braces and fields
    let (depth, complexity, alias_count) = analyze_query(trimmed);

    // Check for introspection
    let is_introspection = trimmed.contains("__schema") || trimmed.contains("__type");

    GraphqlOperation {
        op_type: op_type.to_string(),
        op_name,
        depth,
        complexity,
        alias_count,
        is_introspection,
    }
}

/// Extract the operation name from the text after the operation keyword.
/// e.g., "GetUser($id: ID!) { ... }" -> Some("GetUser")
fn extract_operation_name(after_keyword: &str) -> Option<String> {
    let trimmed = after_keyword.trim_start();
    if trimmed.starts_with('{') || trimmed.is_empty() {
        return None;
    }

    // Take chars until we hit a non-identifier char
    let name: String = trimmed
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();

    if name.is_empty() { None } else { Some(name) }
}

/// Analyze a GraphQL query string for depth, complexity, and alias count.
///
/// - Depth: maximum nesting level of `{` `}` pairs
/// - Complexity: approximate field count (identifiers followed by selection sets or at field positions)
/// - Alias count: number of `identifier:` patterns (alias syntax)
fn analyze_query(query: &str) -> (u32, u32, u32) {
    let mut depth: u32 = 0;
    let mut max_depth: u32 = 0;
    let mut complexity: u32 = 0;
    let mut alias_count: u32 = 0;
    let mut paren_depth: u32 = 0; // Track parentheses for arguments
    let mut in_string = false;
    let mut in_comment = false;
    let chars: Vec<char> = query.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let c = chars[i];

        // Handle string literals
        if in_string {
            if c == '\\' {
                i += 2; // skip escaped char
                continue;
            }
            if c == '"' {
                // Check for block string """
                if i + 2 < len && chars[i + 1] == '"' && chars[i + 2] == '"' {
                    // End of block string — scan for closing """
                    i += 3;
                    while i + 2 < len {
                        if chars[i] == '"' && chars[i + 1] == '"' && chars[i + 2] == '"' {
                            i += 3;
                            break;
                        }
                        i += 1;
                    }
                }
                in_string = false;
            }
            i += 1;
            continue;
        }

        // Handle comments
        if in_comment {
            if c == '\n' {
                in_comment = false;
            }
            i += 1;
            continue;
        }

        if c == '#' {
            in_comment = true;
            i += 1;
            continue;
        }

        if c == '"' {
            in_string = true;
            // Check for block string """
            if i + 2 < len && chars[i + 1] == '"' && chars[i + 2] == '"' {
                i += 3;
                // Scan for closing """
                while i + 2 < len {
                    if chars[i] == '"' && chars[i + 1] == '"' && chars[i + 2] == '"' {
                        i += 3;
                        in_string = false;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            i += 1;
            continue;
        }

        if c == '(' {
            paren_depth += 1;
            i += 1;
            continue;
        }

        if c == ')' {
            paren_depth = paren_depth.saturating_sub(1);
            i += 1;
            continue;
        }

        // Skip everything inside argument lists
        if paren_depth > 0 {
            i += 1;
            continue;
        }

        if c == '{' {
            depth += 1;
            if depth > max_depth {
                max_depth = depth;
            }
            i += 1;
            continue;
        }

        if c == '}' {
            depth = depth.saturating_sub(1);
            i += 1;
            continue;
        }

        // Detect identifiers (potential fields or aliases)
        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < len && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let ident = &query[start..start + (i - start)];

            // Skip GraphQL keywords that aren't fields
            if matches!(
                ident,
                "query"
                    | "mutation"
                    | "subscription"
                    | "fragment"
                    | "on"
                    | "true"
                    | "false"
                    | "null"
            ) {
                continue;
            }

            // Skip whitespace after identifier
            let mut j = i;
            while j < len && chars[j].is_whitespace() {
                j += 1;
            }

            // Check if this is an alias (identifier followed by ':')
            if j < len && chars[j] == ':' {
                alias_count += 1;
                // The aliased field name follows — it will be counted as a field
                // on the next iteration
                i = j + 1;
                continue;
            }

            // If we're inside a selection set (depth > 0), count as a field
            if depth > 0 {
                // Skip directive names (prefixed by @)
                if start > 0 && chars[start - 1] == '@' {
                    continue;
                }
                complexity += 1;
            }
            continue;
        }

        i += 1;
    }

    (max_depth, complexity, alias_count)
}

#[async_trait]
impl Plugin for GraphqlPlugin {
    fn name(&self) -> &str {
        "graphql"
    }

    fn priority(&self) -> u16 {
        super::priority::GRAPHQL
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.has_any_config
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.has_any_config
            && ctx.method == "POST"
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|ct| ct.to_ascii_lowercase().contains("json"))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only process POST requests (standard GraphQL transport)
        if ctx.method != "POST" {
            return PluginResult::Continue;
        }

        // Check content type
        let content_type = headers
            .get("content-type")
            .or_else(|| ctx.headers.get("content-type"))
            .cloned()
            .unwrap_or_default()
            .to_lowercase();

        if !content_type.contains("json") {
            return PluginResult::Continue;
        }

        // Get request body
        let body = match ctx.metadata.get("request_body") {
            Some(b) if !b.is_empty() => b.clone(),
            _ => {
                debug!("graphql: no request body available");
                return PluginResult::Continue;
            }
        };

        // Parse the JSON body to extract the GraphQL query
        let parsed: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => {
                debug!("graphql: request body is not valid JSON");
                return PluginResult::Continue;
            }
        };

        let query = match parsed.get("query").and_then(|q| q.as_str()) {
            Some(q) if !q.is_empty() => q,
            _ => {
                // No query field — might be a persisted query or non-GraphQL request
                return PluginResult::Continue;
            }
        };

        let operation_name = parsed.get("operationName").and_then(|n| n.as_str());

        // Parse the GraphQL query
        let op = parse_graphql_query(query, operation_name);

        // Store operation info in metadata for logging/downstream plugins
        ctx.metadata
            .insert("graphql_operation_type".to_string(), op.op_type.clone());
        if let Some(ref name) = op.op_name {
            ctx.metadata
                .insert("graphql_operation_name".to_string(), name.clone());
        }
        ctx.metadata
            .insert("graphql_depth".to_string(), op.depth.to_string());
        ctx.metadata
            .insert("graphql_complexity".to_string(), op.complexity.to_string());

        // Check introspection
        if !self.introspection_allowed && op.is_introspection {
            debug!("graphql: introspection query blocked");
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"errors":[{"message":"Introspection queries are not allowed"}]}"#
                    .to_string(),
                headers: json_content_type_header(),
            };
        }

        // Check depth limit
        if let Some(max_depth) = self.max_depth
            && op.depth > max_depth
        {
            debug!(
                depth = op.depth,
                max_depth, "graphql: query depth exceeds limit"
            );
            return PluginResult::Reject {
                status_code: 400,
                body: format!(
                    r#"{{"errors":[{{"message":"Query depth {} exceeds maximum allowed depth of {}"}}]}}"#,
                    op.depth, max_depth
                ),
                headers: json_content_type_header(),
            };
        }

        // Check complexity limit
        if let Some(max_complexity) = self.max_complexity
            && op.complexity > max_complexity
        {
            debug!(
                complexity = op.complexity,
                max_complexity, "graphql: query complexity exceeds limit"
            );
            return PluginResult::Reject {
                status_code: 400,
                body: format!(
                    r#"{{"errors":[{{"message":"Query complexity {} exceeds maximum allowed complexity of {}"}}]}}"#,
                    op.complexity, max_complexity
                ),
                headers: json_content_type_header(),
            };
        }

        // Check alias count limit
        if let Some(max_aliases) = self.max_aliases
            && op.alias_count > max_aliases
        {
            debug!(
                alias_count = op.alias_count,
                max_aliases, "graphql: alias count exceeds limit"
            );
            return PluginResult::Reject {
                status_code: 400,
                body: format!(
                    r#"{{"errors":[{{"message":"Query uses {} aliases, maximum allowed is {}"}}]}}"#,
                    op.alias_count, max_aliases
                ),
                headers: json_content_type_header(),
            };
        }

        // Check operation type rate limit
        if let Some(spec) = self.type_rate_limits.get(&op.op_type) {
            let key = self.rate_key(ctx, &format!("type:{}", op.op_type));
            if !self.check_rate(&key, spec) {
                warn!(
                    op_type = %op.op_type,
                    plugin = "graphql",
                    "GraphQL operation type rate limit exceeded"
                );
                let remaining = self.get_remaining(&key).unwrap_or(0);
                let mut headers = json_content_type_header();
                headers.insert(
                    "x-graphql-ratelimit-limit".to_string(),
                    spec.max_requests.to_string(),
                );
                headers.insert(
                    "x-graphql-ratelimit-remaining".to_string(),
                    remaining.to_string(),
                );
                return PluginResult::Reject {
                    status_code: 429,
                    body: format!(
                        r#"{{"errors":[{{"message":"Rate limit exceeded for {} operations"}}]}}"#,
                        op.op_type
                    ),
                    headers,
                };
            }
        }

        // Check named operation rate limit
        if let Some(ref op_name) = op.op_name
            && let Some(spec) = self.operation_rate_limits.get(op_name)
        {
            let key = self.rate_key(ctx, &format!("op:{}", op_name));
            if !self.check_rate(&key, spec) {
                warn!(
                    operation = %op_name,
                    plugin = "graphql",
                    "GraphQL named operation rate limit exceeded"
                );
                let remaining = self.get_remaining(&key).unwrap_or(0);
                let mut headers = json_content_type_header();
                headers.insert(
                    "x-graphql-ratelimit-limit".to_string(),
                    spec.max_requests.to_string(),
                );
                headers.insert(
                    "x-graphql-ratelimit-remaining".to_string(),
                    remaining.to_string(),
                );
                return PluginResult::Reject {
                    status_code: 429,
                    body: format!(
                        r#"{{"errors":[{{"message":"Rate limit exceeded for operation '{}'"}}]}}"#,
                        escape_json_string(op_name)
                    ),
                    headers,
                };
            }
        }

        PluginResult::Continue
    }
}

/// Returns a header map with `content-type: application/json`.
fn json_content_type_header() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}

/// Escape special characters for safe JSON string interpolation.
fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
