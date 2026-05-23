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
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use super::utils::body_transform::is_json_content_type;
use super::utils::rate_limit::{
    DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitBackend, RateLimitOutcome,
    RateLimitWindowSpec,
};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

/// Maximum rate-limit state entries before triggering stale eviction.
const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_CHECK_INTERVAL_REQUESTS: u64 = 1024;

/// A rate window spec parsed from config.
#[derive(Debug, Clone)]
struct RateSpec {
    max_requests: u64,
    op: DynamicRateLimitOp,
}

/// Parsed GraphQL operation info.
#[derive(Debug, Clone)]
struct GraphqlOperation {
    /// "query", "mutation", or "subscription"
    op_type: &'static str,
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
    limiter: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm>,
    request_counter: AtomicU64,
    has_any_config: bool,
}

impl GraphqlPlugin {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("graphql: config must be an object".to_string());
        }

        let max_depth = optional_u32(config, "max_depth")?;
        let max_complexity = optional_u32(config, "max_complexity")?;
        let max_aliases = optional_u32(config, "max_aliases")?;
        let introspection_allowed = optional_bool(config, "introspection_allowed")?.unwrap_or(true);
        // limit_by must be a recognized policy — silently treating "user" as "ip"
        // would be a security misconfiguration footgun.
        let limit_by = match config.get("limit_by") {
            None | Some(Value::Null) => "ip".to_string(),
            Some(Value::String(s)) => {
                let lc = s.to_lowercase();
                if !matches!(lc.as_str(), "ip" | "consumer") {
                    return Err(format!(
                        "graphql: 'limit_by' must be one of 'ip' or 'consumer', got: {s:?}"
                    ));
                }
                lc
            }
            Some(other) => {
                return Err(format!(
                    "graphql: 'limit_by' must be a string, got: {other}"
                ));
            }
        };

        let type_rate_limits = parse_type_rate_limits(config)?;
        let operation_rate_limits = parse_operation_rate_limits(config)?;

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
            limiter: RateLimitBackend::from_plugin_config(
                "graphql",
                config,
                &http_client,
                DynamicHttpRateLimitAlgorithm::new(),
            )?,
            request_counter: AtomicU64::new(0),
            has_any_config,
        })
    }

    /// Evict entries with no recent activity to bound memory.
    fn evict_stale_entries(&self) {
        let request = self.request_counter.fetch_add(1, Ordering::Relaxed);
        if !request.is_multiple_of(EVICTION_CHECK_INTERVAL_REQUESTS) {
            return;
        }
        if self.limiter.tracked_keys_count() > MAX_STATE_ENTRIES {
            self.limiter
                .enforce_capacity(MAX_STATE_ENTRIES, Instant::now());
        }
    }

    /// Check a rate limit by key, creating a bucket if needed.
    async fn check_rate(&self, key: &str, spec: &RateSpec) -> RateLimitOutcome {
        self.evict_stale_entries();
        self.limiter.check(key.to_string(), key, &spec.op).await
    }

    /// Build the rate limit key based on `limit_by` config.
    fn rate_key(&self, ctx: &RequestContext, kind: &str, value: &str) -> String {
        let identity = if self.limit_by == "consumer" {
            ctx.effective_identity().unwrap_or(ctx.client_ip.as_str())
        } else {
            ctx.client_ip.as_str()
        };
        let mut key = String::with_capacity(4 + identity.len() + kind.len() + value.len() + 2);
        key.push_str("gql:");
        key.push_str(identity);
        key.push(':');
        key.push_str(kind);
        key.push(':');
        key.push_str(value);
        key
    }
}

fn optional_u32(config: &Value, field: &'static str) -> Result<Option<u32>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!("graphql: '{field}' must be an integer"));
    };
    u32::try_from(value)
        .map(Some)
        .map_err(|_| format!("graphql: '{field}' must fit in a 32-bit unsigned integer"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("graphql: '{field}' must be a boolean"))
}

fn parse_type_rate_limits(config: &Value) -> Result<HashMap<String, RateSpec>, String> {
    let Some(value) = config.get("type_rate_limits") else {
        return Ok(HashMap::new());
    };
    let Some(obj) = value.as_object() else {
        return Err("graphql: 'type_rate_limits' must be an object".to_string());
    };

    let mut limits = HashMap::new();
    for (op_type, spec) in obj {
        let op_type_lc = op_type.to_ascii_lowercase();
        if !matches!(op_type_lc.as_str(), "query" | "mutation" | "subscription") {
            return Err(format!(
                "graphql: type_rate_limits key must be one of 'query', 'mutation', or 'subscription', got: {op_type:?}"
            ));
        }
        limits.insert(
            op_type_lc,
            parse_rate_spec("type_rate_limits", op_type, spec)?,
        );
    }

    Ok(limits)
}

fn parse_operation_rate_limits(config: &Value) -> Result<HashMap<String, RateSpec>, String> {
    let Some(value) = config.get("operation_rate_limits") else {
        return Ok(HashMap::new());
    };
    let Some(obj) = value.as_object() else {
        return Err("graphql: 'operation_rate_limits' must be an object".to_string());
    };

    let mut limits = HashMap::new();
    for (op_name, spec) in obj {
        if !is_graphql_name(op_name) {
            return Err(format!(
                "graphql: operation_rate_limits key must be a valid GraphQL operation name, got: {op_name:?}"
            ));
        }
        limits.insert(
            op_name.clone(),
            parse_rate_spec("operation_rate_limits", op_name, spec)?,
        );
    }

    Ok(limits)
}

fn parse_rate_spec(field: &str, key: &str, spec: &Value) -> Result<RateSpec, String> {
    if !spec.is_object() {
        return Err(format!("graphql: {field}['{key}'] must be an object"));
    }
    let max_requests = required_positive_u64(spec, field, key, "max_requests")?;
    let window_seconds = required_positive_u64(spec, field, key, "window_seconds")?;
    let window = Duration::from_secs(window_seconds);
    Ok(RateSpec {
        max_requests,
        op: DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
            limit: max_requests,
            duration: window,
        }]),
    })
}

fn required_positive_u64(
    spec: &Value,
    parent: &str,
    key: &str,
    field: &str,
) -> Result<u64, String> {
    let value = spec[field].as_u64().ok_or_else(|| {
        format!("graphql: {parent}['{key}']: '{field}' is required and must be a positive integer")
    })?;
    if value == 0 {
        return Err(format!(
            "graphql: {parent}['{key}']: '{field}' must be greater than zero"
        ));
    }
    Ok(value)
}

/// Parse a GraphQL query string to extract operation info.
///
/// This is a lightweight parser that handles the subset of GraphQL syntax
/// needed for depth/complexity/alias analysis without a full AST.
fn parse_graphql_query(query: &str, operation_name: Option<&str>) -> GraphqlOperation {
    let trimmed = trim_leading_ignored(query);

    // Determine operation type from query text
    let (op_type, rest) = if let Some(rest) = strip_operation_keyword(trimmed, "mutation") {
        ("mutation", rest)
    } else if let Some(rest) = strip_operation_keyword(trimmed, "subscription") {
        ("subscription", rest)
    } else if let Some(rest) = strip_operation_keyword(trimmed, "query") {
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
    let (depth, complexity, alias_count, is_introspection) = analyze_query(trimmed);

    GraphqlOperation {
        op_type,
        op_name,
        depth,
        complexity,
        alias_count,
        is_introspection,
    }
}

fn trim_leading_ignored(mut query: &str) -> &str {
    loop {
        query = query.trim_start();
        if !query.starts_with('#') {
            return query;
        }
        match query.find(['\n', '\r']) {
            Some(pos) => query = &query[pos + 1..],
            None => return "",
        }
    }
}

fn strip_operation_keyword<'a>(query: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = query.strip_prefix(keyword)?;
    if rest
        .as_bytes()
        .first()
        .is_some_and(|b| is_graphql_name_continue(*b))
    {
        return None;
    }
    Some(rest)
}

/// Extract the operation name from the text after the operation keyword.
/// e.g., "GetUser($id: ID!) { ... }" -> Some("GetUser")
fn extract_operation_name(after_keyword: &str) -> Option<String> {
    let trimmed = after_keyword.trim_start();
    if trimmed.starts_with('{') || trimmed.is_empty() {
        return None;
    }

    let bytes = trimmed.as_bytes();
    if !bytes.first().is_some_and(|b| is_graphql_name_start(*b)) {
        return None;
    }

    let mut end = 1;
    while end < bytes.len() && is_graphql_name_continue(bytes[end]) {
        end += 1;
    }
    Some(trimmed[..end].to_string())
}

/// Analyze a GraphQL query string for depth, complexity, and alias count.
///
/// - Depth: maximum nesting level of `{` `}` pairs
/// - Complexity: approximate field count (identifiers followed by selection sets or at field positions)
/// - Alias count: number of `identifier:` patterns (alias syntax)
fn analyze_query(query: &str) -> (u32, u32, u32, bool) {
    let mut depth: u32 = 0;
    let mut max_depth: u32 = 0;
    let mut complexity: u32 = 0;
    let mut alias_count: u32 = 0;
    let mut paren_depth: u32 = 0; // Track parentheses for arguments
    let mut in_string = false;
    let mut in_block_string = false;
    let mut in_comment = false;
    let mut is_introspection = false;
    let bytes = query.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        let c = bytes[i];

        if in_block_string {
            if i + 2 < len && bytes[i..i + 3] == *b"\"\"\"" {
                in_block_string = false;
                i += 3;
            } else {
                i += 1;
            }
            continue;
        }

        // Handle string literals
        if in_string {
            if c == b'\\' {
                i = (i + 2).min(len); // skip escaped char
                continue;
            }
            if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        // Handle comments
        if in_comment {
            if c == b'\n' || c == b'\r' {
                in_comment = false;
            }
            i += 1;
            continue;
        }

        if c == b'#' {
            in_comment = true;
            i += 1;
            continue;
        }

        if c == b'"' {
            if i + 2 < len && bytes[i..i + 3] == *b"\"\"\"" {
                in_block_string = true;
                i += 3;
            } else {
                in_string = true;
                i += 1;
            }
            continue;
        }

        if c == b'(' {
            paren_depth += 1;
            i += 1;
            continue;
        }

        if c == b')' {
            paren_depth = paren_depth.saturating_sub(1);
            i += 1;
            continue;
        }

        // Skip everything inside argument lists
        if paren_depth > 0 {
            i += 1;
            continue;
        }

        if c == b'{' {
            depth += 1;
            if depth > max_depth {
                max_depth = depth;
            }
            i += 1;
            continue;
        }

        if c == b'}' {
            depth = depth.saturating_sub(1);
            i += 1;
            continue;
        }

        // Detect identifiers (potential fields or aliases)
        if is_graphql_name_start(c) {
            let start = i;
            while i < len && is_graphql_name_continue(bytes[i]) {
                i += 1;
            }
            let ident = &query[start..i];

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
            while j < len && bytes[j].is_ascii_whitespace() {
                j += 1;
            }

            // Check if this is an alias (identifier followed by ':')
            if j < len && bytes[j] == b':' {
                alias_count += 1;
                // The aliased field name follows — it will be counted as a field
                // on the next iteration
                i = j + 1;
                continue;
            }

            // If we're inside a selection set (depth > 0), count as a field
            if depth > 0 {
                // Skip directive names (prefixed by @)
                if start > 0 && bytes[start - 1] == b'@' {
                    continue;
                }
                if ident == "__schema" || ident == "__type" {
                    is_introspection = true;
                }
                complexity += 1;
            }
            continue;
        }

        i += 1;
    }

    (max_depth, complexity, alias_count, is_introspection)
}

fn is_graphql_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.first().is_some_and(|b| is_graphql_name_start(*b))
        && bytes.iter().skip(1).all(|b| is_graphql_name_continue(*b))
}

fn is_graphql_name_start(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphabetic()
}

fn is_graphql_name_continue(b: u8) -> bool {
    is_graphql_name_start(b) || b.is_ascii_digit()
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

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
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
                .is_some_and(|ct| is_json_content_type(ct))
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
        if !headers
            .get("content-type")
            .is_some_and(|ct| is_json_content_type(ct))
        {
            return PluginResult::Continue;
        }

        // Get request body
        let body = match ctx.metadata.get("request_body") {
            Some(b) if !b.is_empty() => b.as_str(),
            _ => {
                debug!("graphql: no request body available");
                return PluginResult::Continue;
            }
        };

        // Parse the JSON body to extract the GraphQL query
        let parsed: Value = match serde_json::from_str(body) {
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
            .insert("graphql_operation_type".to_string(), op.op_type.to_string());
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
                body: graphql_error_body("Introspection queries are not allowed"),
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
                body: depth_error_body(op.depth, max_depth),
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
                body: complexity_error_body(op.complexity, max_complexity),
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
                body: alias_error_body(op.alias_count, max_aliases),
                headers: json_content_type_header(),
            };
        }

        // Check operation type rate limit
        if let Some(spec) = self.type_rate_limits.get(op.op_type) {
            let key = self.rate_key(ctx, "type", op.op_type);
            let outcome = self.check_rate(&key, spec).await;
            if !outcome.allowed {
                warn!(
                    op_type = %op.op_type,
                    plugin = "graphql",
                    "GraphQL operation type rate limit exceeded"
                );
                let remaining = outcome.remaining.unwrap_or(0);
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
                    body: type_rate_limit_error_body(op.op_type),
                    headers,
                };
            }
        }

        // Check named operation rate limit
        if let Some(ref op_name) = op.op_name
            && let Some(spec) = self.operation_rate_limits.get(op_name)
        {
            let key = self.rate_key(ctx, "op", op_name);
            let outcome = self.check_rate(&key, spec).await;
            if !outcome.allowed {
                warn!(
                    operation = %op_name,
                    plugin = "graphql",
                    "GraphQL named operation rate limit exceeded"
                );
                let remaining = outcome.remaining.unwrap_or(0);
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
                    body: operation_rate_limit_error_body(op_name),
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

fn graphql_error_body(message: &str) -> String {
    serde_json::json!({ "errors": [{ "message": message }] }).to_string()
}

fn depth_error_body(depth: u32, max_depth: u32) -> String {
    let mut message = String::with_capacity(72);
    let _ = write!(
        &mut message,
        "Query depth {depth} exceeds maximum allowed depth of {max_depth}"
    );
    graphql_error_body(&message)
}

fn complexity_error_body(complexity: u32, max_complexity: u32) -> String {
    let mut message = String::with_capacity(88);
    let _ = write!(
        &mut message,
        "Query complexity {complexity} exceeds maximum allowed complexity of {max_complexity}"
    );
    graphql_error_body(&message)
}

fn alias_error_body(alias_count: u32, max_aliases: u32) -> String {
    let mut message = String::with_capacity(64);
    let _ = write!(
        &mut message,
        "Query uses {alias_count} aliases, maximum allowed is {max_aliases}"
    );
    graphql_error_body(&message)
}

fn type_rate_limit_error_body(op_type: &str) -> String {
    let mut message = String::with_capacity(45 + op_type.len());
    message.push_str("Rate limit exceeded for ");
    message.push_str(op_type);
    message.push_str(" operations");
    graphql_error_body(&message)
}

fn operation_rate_limit_error_body(op_name: &str) -> String {
    let mut message = String::with_capacity(37 + op_name.len());
    message.push_str("Rate limit exceeded for operation '");
    message.push_str(op_name);
    message.push('\'');
    graphql_error_body(&message)
}
