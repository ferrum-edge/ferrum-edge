//! GraphQL Plugin
//!
//! Adds GraphQL-aware proxying capabilities:
//! - Query parsing and operation extraction
//! - Query depth limiting (bounds selection-set nesting)
//! - Query complexity limiting (bounds approximate field count)
//! - Alias count limiting (mitigates alias-based DoS)
//! - Per-operation-type rate limiting (query vs mutation vs subscription)
//! - Per-named-operation rate limiting (e.g., "getUser" vs "createOrder")
//! - Introspection control (allow/deny __schema/__type queries)
//!
//! GraphQL requests are expected as POST with `application/json` body
//! containing `{"query": "...", "operationName": "..."}`. By default
//! (`require_inspectable_transport: true`) the plugin fails closed for other
//! HTTP representations it cannot inspect (GraphQL GET, `application/graphql`,
//! JSON batch arrays, APQ hash-only envelopes, multipart `operations`, missing
//! or unparseable bodies). Set `require_inspectable_transport: false` to
//! restore fail-open for those representations. WebSocket/SSE GraphQL are out
//! of scope: this plugin is HTTP-only (`HTTP_ONLY_PROTOCOLS`).
//!
//! The analyzer is a lightweight, allocation-light parser rather than a full
//! GraphQL AST. It selects the operation to analyze using `operationName` (per
//! the GraphQL spec, `operationName` is required for multi-operation documents)
//! so per-type rate limits and depth/complexity caps apply to the operation the
//! backend will actually execute. Fragment spreads (`...Frag`) are expanded at
//! their use sites when computing depth/complexity — with cycle detection and a
//! byte budget so expansion cannot itself become a DoS — so those limits cannot
//! be bypassed by hiding nesting or fields behind fragments. It is still a
//! heuristic (e.g. it does not type-check or validate against a schema) and is
//! intended as an edge filter layered in front of the backend GraphQL server.

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
use super::utils::redis_rate_limiter::REDIS_PLUGIN_CONFIG_KEYS;
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use crate::util::unknown_keys::reject_unknown_keys;

/// Maximum rate-limit state entries before triggering stale eviction.
const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_CHECK_INTERVAL_REQUESTS: u64 = 1024;

/// GraphQL-specific top-level config keys (excludes shared Redis sync fields).
const GRAPHQL_POLICY_CONFIG_KEYS: &[&str] = &[
    "max_depth",
    "max_complexity",
    "max_aliases",
    "introspection_allowed",
    "require_inspectable_transport",
    "limit_by",
    "type_rate_limits",
    "operation_rate_limits",
];

/// Closed top-level key set for `graphql` plugin config.
///
/// Must stay aligned with OpenAPI `GraphqlConfig`, `REDIS_PLUGIN_CONFIG_KEYS`,
/// and `docs/plugins.md`. Unknown root keys fail closed so typos cannot silently
/// replace introspection, identity, rate-map, or Redis synchronization policy.
pub const GRAPHQL_CONFIG_KEYS: &[&str] = &[
    "max_depth",
    "max_complexity",
    "max_aliases",
    "introspection_allowed",
    "require_inspectable_transport",
    "limit_by",
    "type_rate_limits",
    "operation_rate_limits",
    // Shared Redis sync (see REDIS_PLUGIN_CONFIG_KEYS)
    "sync_mode",
    "redis_url",
    "redis_tls",
    "redis_key_prefix",
    "redis_pool_size",
    "redis_connect_timeout_seconds",
    "redis_health_check_interval_seconds",
    "redis_username",
    "redis_password",
];

const RATE_SPEC_KEYS: &[&str] = &["max_requests", "window_seconds"];

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
    /// When true (default), refuse HTTP GraphQL representations that cannot
    /// be inspected. When false, preserve fail-open for those transports.
    require_inspectable_transport: bool,
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
        let object = config
            .as_object()
            .ok_or_else(|| "graphql: config must be an object".to_string())?;
        // Debug assertion keeps the documented key groups aligned with the
        // closed root allowlist used for admission and OpenAPI parity.
        debug_assert!(
            GRAPHQL_POLICY_CONFIG_KEYS
                .iter()
                .chain(REDIS_PLUGIN_CONFIG_KEYS.iter())
                .all(|key| GRAPHQL_CONFIG_KEYS.contains(key))
                && GRAPHQL_CONFIG_KEYS.len()
                    == GRAPHQL_POLICY_CONFIG_KEYS.len() + REDIS_PLUGIN_CONFIG_KEYS.len()
        );
        reject_unknown_keys(object, "config", GRAPHQL_CONFIG_KEYS, "graphql: ")?;

        match config.get("sync_mode") {
            None => {}
            Some(Value::String(sync_mode)) if matches!(sync_mode.as_str(), "local" | "redis") => {}
            Some(Value::String(sync_mode)) => {
                return Err(format!(
                    "graphql: 'sync_mode' must be exactly 'local' or 'redis', got: {sync_mode:?}"
                ));
            }
            Some(_) => {
                return Err("graphql: 'sync_mode' must be a string".to_string());
            }
        }

        let max_depth = optional_u32(config, "max_depth")?;
        let max_complexity = optional_u32(config, "max_complexity")?;
        let max_aliases = optional_u32(config, "max_aliases")?;
        let introspection_allowed = optional_bool(config, "introspection_allowed")?.unwrap_or(true);
        let require_inspectable_transport =
            optional_bool(config, "require_inspectable_transport")?.unwrap_or(true);
        // limit_by must be a recognized policy — silently treating "user" as "ip"
        // would be a security misconfiguration footgun.
        let limit_by = match config.get("limit_by") {
            None => "ip".to_string(),
            Some(Value::String(s)) => {
                if !matches!(s.as_str(), "ip" | "consumer") {
                    return Err(format!(
                        "graphql: 'limit_by' must be exactly 'ip' or 'consumer', got: {s:?}"
                    ));
                }
                s.clone()
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
                 'max_aliases', 'introspection_allowed: false', 'type_rate_limits', or \
                 'operation_rate_limits'"
                    .to_string(),
            );
        }

        Ok(Self {
            max_depth,
            max_complexity,
            max_aliases,
            introspection_allowed,
            require_inspectable_transport,
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
        if !matches!(op_type.as_str(), "query" | "mutation" | "subscription") {
            return Err(format!(
                "graphql: type_rate_limits key must be exactly 'query', 'mutation', or 'subscription', got: {op_type:?}"
            ));
        }
        limits.insert(
            op_type.clone(),
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
    let object = spec
        .as_object()
        .ok_or_else(|| format!("graphql: {field}['{key}'] must be an object"))?;
    let path = format!("config.{field}[{key}]");
    reject_unknown_keys(object, &path, RATE_SPEC_KEYS, "graphql: ")?;
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

/// Bound on the total bytes scanned while expanding fragment spreads for a
/// single request. Fragment expansion can multiply work (a wide fragment
/// spread at many sites, or chained fragments), so the resolver itself must be
/// bounded or it becomes a DoS vector. The request body is already size-limited
/// upstream (buffering + size_limiting), so this budget only ever trips for
/// pathological documents; exceeding it is treated as a depth/complexity
/// violation (400) rather than analyzed further.
const MAX_FRAGMENT_EXPANSION_BYTES: usize = 4 * 1024 * 1024;

/// Bound on the analyzer's recursion depth. Each nested selection set, fragment
/// spread, and inline fragment recurses one frame; without a cap a pathological
/// document (e.g. a long non-cyclic chain of single-spread fragments) could
/// recurse deeply enough to overflow the stack — turning the limiter into its
/// own DoS. This bound is far above any legitimate query's resolved nesting and
/// comfortably below stack-exhaustion territory on a default worker stack.
/// Exceeding it yields a 400.
const MAX_ANALYSIS_RECURSION: u32 = 512;

/// Outcome of parsing a GraphQL document into the operation to analyze.
enum ParsedQuery {
    /// The selected operation, ready for limit checks.
    Operation(GraphqlOperation),
    /// The document is invalid per the GraphQL spec or exceeds the expansion
    /// budget and must be rejected before reaching the backend.
    Reject { status_code: u16, message: String },
}

/// A top-level operation definition located in the document.
struct OperationDef<'a> {
    op_type: &'static str,
    /// Operation name as written in the document, if any.
    name: Option<&'a str>,
    /// The operation's top-level selection set body (the bytes between the
    /// outermost `{` and its matching `}`), borrowed from the document.
    selection_set: &'a str,
}

/// Parse a GraphQL query string and select the operation to analyze.
///
/// This is a lightweight parser that handles the subset of GraphQL syntax
/// needed for depth/complexity/alias analysis without a full AST. Unlike a raw
/// text scan it (1) splits the document into individual operation and fragment
/// definitions, (2) selects which operation is analyzed using `operation_name`
/// (per the GraphQL spec: `operationName` is required when a document defines
/// more than one operation), and (3) expands fragment spreads (`...Frag`) at
/// their use sites when computing depth/complexity so those limits cannot be
/// bypassed by hiding nesting/fields behind fragments. Fragment expansion is
/// cycle-safe and byte-budgeted so the expansion itself cannot be turned into a
/// DoS.
fn parse_graphql_query(query: &str, operation_name: Option<&str>) -> ParsedQuery {
    let operation_name = operation_name.filter(|n| !n.is_empty());
    let (operations, fragments) = parse_document(query);

    // Select the operation to analyze.
    let selected: Option<&OperationDef> = match operation_name {
        Some(name) => {
            // Explicit operationName: it must match exactly one operation.
            match operations.iter().find(|op| op.name == Some(name)) {
                Some(op) => Some(op),
                None if operations.is_empty() => None, // fall back to whole-document scan
                None => {
                    return ParsedQuery::Reject {
                        status_code: 400,
                        message: format!("Unknown operation named \"{name}\""),
                    };
                }
            }
        }
        None => {
            // No operationName: the GraphQL spec requires it for multi-operation
            // documents. Reject those rather than silently analyzing the wrong
            // operation (which would let per-type limits be bypassed).
            if operations.len() > 1 {
                return ParsedQuery::Reject {
                    status_code: 400,
                    message:
                        "operationName is required when the document contains multiple operations"
                            .to_string(),
                };
            }
            operations.first()
        }
    };

    match selected {
        Some(op) => {
            let op_name = operation_name
                .map(String::from)
                .or_else(|| op.name.map(String::from));

            match analyze_operation(op.selection_set, &fragments) {
                Some((depth, complexity, alias_count, is_introspection)) => {
                    ParsedQuery::Operation(GraphqlOperation {
                        op_type: op.op_type,
                        op_name,
                        depth,
                        complexity,
                        alias_count,
                        is_introspection,
                    })
                }
                None => ParsedQuery::Reject {
                    status_code: 400,
                    message: "Query is too large to analyze (fragment expansion budget exceeded)"
                        .to_string(),
                },
            }
        }
        None => {
            // The structured parser found no operation (e.g. a non-standard or
            // unparseable body). The legacy whole-document scan is
            // fragment-blind, so fail closed when fragment syntax is present
            // rather than enforcing weaker depth/complexity limits.
            let trimmed = trim_leading_ignored(query);
            if !fragments.is_empty() || contains_fragment_syntax(trimmed) {
                return ParsedQuery::Reject {
                    status_code: 400,
                    message: "Query contains fragments but could not be structurally analyzed"
                        .to_string(),
                };
            }
            // Otherwise fall back to the legacy whole-document scan so we do
            // not introduce false rejections for fragment-free non-standard
            // bodies; op_type comes from the leading keyword as before.
            let op_type = if strip_operation_keyword(trimmed, "mutation").is_some() {
                "mutation"
            } else if strip_operation_keyword(trimmed, "subscription").is_some() {
                "subscription"
            } else {
                "query"
            };
            let op_name = operation_name.map(String::from);
            let (depth, complexity, alias_count, is_introspection) = analyze_query(trimmed);
            ParsedQuery::Operation(GraphqlOperation {
                op_type,
                op_name,
                depth,
                complexity,
                alias_count,
                is_introspection,
            })
        }
    }
}

/// Split a GraphQL document into its top-level operation definitions and a
/// `name -> selection-set body` map of its fragment definitions.
///
/// String literals, block strings, comments, and argument lists are respected
/// so keywords/braces inside them are never mistaken for structure.
fn parse_document(query: &str) -> (Vec<OperationDef<'_>>, HashMap<&str, &str>) {
    let bytes = query.as_bytes();
    let len = bytes.len();
    let mut operations: Vec<OperationDef<'_>> = Vec::new();
    let mut fragments: HashMap<&str, &str> = HashMap::new();
    let mut i = 0;

    while i < len {
        let c = bytes[i];

        // Skip ignored tokens (whitespace, commas, comments).
        if c.is_ascii_whitespace() || c == b',' {
            i += 1;
            continue;
        }
        if c == b'#' {
            i = skip_line_comment(bytes, i);
            continue;
        }

        // A bare selection set is an anonymous (shorthand) query operation.
        if c == b'{' {
            if let Some(end) = find_matching_brace(bytes, i) {
                operations.push(OperationDef {
                    op_type: "query",
                    name: None,
                    selection_set: &query[i + 1..end],
                });
                i = end + 1;
            } else {
                // Unbalanced braces: stop structured parsing.
                break;
            }
            continue;
        }

        // Identifier at the top level: an operation or fragment keyword.
        if is_graphql_name_start(c) {
            let (ident, after_ident) = read_name(bytes, i);
            let op_type = match ident {
                "query" => Some("query"),
                "mutation" => Some("mutation"),
                "subscription" => Some("subscription"),
                _ => None,
            };

            if let Some(op_type) = op_type {
                // Optional name, optional variable defs `(...)` and directives,
                // then the selection-set `{ ... }`.
                let (name, after_name) = read_optional_name(bytes, after_ident, query);
                match find_next_top_level_brace(bytes, after_name) {
                    Some(brace) => match find_matching_brace(bytes, brace) {
                        Some(end) => {
                            operations.push(OperationDef {
                                op_type,
                                name,
                                selection_set: &query[brace + 1..end],
                            });
                            i = end + 1;
                        }
                        None => break,
                    },
                    None => break,
                }
                continue;
            }

            if ident == "fragment" {
                // `fragment Name on Type { ... }`
                let (name, after_name) = read_optional_name(bytes, after_ident, query);
                match find_next_top_level_brace(bytes, after_name) {
                    Some(brace) => match find_matching_brace(bytes, brace) {
                        Some(end) => {
                            if let Some(name) = name {
                                // First definition wins on duplicate names.
                                fragments.entry(name).or_insert(&query[brace + 1..end]);
                            }
                            i = end + 1;
                        }
                        None => break,
                    },
                    None => break,
                }
                continue;
            }

            // Unknown leading identifier: not something we model; advance past
            // it to avoid an infinite loop and keep scanning.
            i = after_ident;
            continue;
        }

        i += 1;
    }

    (operations, fragments)
}

/// Read a GraphQL name starting at `start` (must be a name-start byte).
/// Returns the name slice and the index just past it.
fn read_name(bytes: &[u8], start: usize) -> (&str, usize) {
    let mut end = start + 1;
    while end < bytes.len() && is_graphql_name_continue(bytes[end]) {
        end += 1;
    }
    // SAFETY of from_utf8: names are ASCII (name-start/continue are ASCII), so
    // this slice is valid UTF-8; use the checked conversion regardless.
    let name = std::str::from_utf8(&bytes[start..end]).unwrap_or("");
    (name, end)
}

/// After an operation/fragment keyword, skip ignored tokens and read an
/// optional name. Returns the name (if present) and the index to continue from.
///
/// The name borrows from `query` (not the temporary `bytes` slice) so it shares
/// the document's lifetime. The first name after `query`/`mutation`/
/// `subscription` is the operation name; the first name after `fragment` is the
/// fragment name (the `on Type` condition comes after and is skipped by the
/// brace search).
fn read_optional_name<'a>(bytes: &[u8], i: usize, query: &'a str) -> (Option<&'a str>, usize) {
    let i = skip_ignored(bytes, i);
    if i < bytes.len() && is_graphql_name_start(bytes[i]) {
        let (_, after) = read_name(bytes, i);
        return (Some(&query[i..after]), after);
    }
    (None, i)
}

/// Find the next top-level `{` starting at `i`, skipping balanced parentheses
/// (variable definitions / arguments), strings, and comments. Returns `None`
/// if a `}` or end-of-input is reached first (which would be malformed).
fn find_next_top_level_brace(bytes: &[u8], mut i: usize) -> Option<usize> {
    let len = bytes.len();
    while i < len {
        let c = bytes[i];
        match c {
            b'{' => return Some(i),
            b'}' => return None,
            b'#' => i = skip_line_comment(bytes, i),
            b'"' => i = skip_string(bytes, i),
            b'(' => i = skip_parens(bytes, i),
            _ => i += 1,
        }
    }
    None
}

/// Given `bytes[open] == b'{'`, return the index of the matching `}`,
/// respecting nested braces, strings, comments, and argument parens. Returns
/// `None` if the document ends before the brace is closed.
fn find_matching_brace(bytes: &[u8], open: usize) -> Option<usize> {
    let len = bytes.len();
    let mut depth = 0u32;
    let mut i = open;
    while i < len {
        match bytes[i] {
            b'#' => {
                i = skip_line_comment(bytes, i);
                continue;
            }
            b'"' => {
                i = skip_string(bytes, i);
                continue;
            }
            b'(' => {
                i = skip_parens(bytes, i);
                continue;
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Skip a balanced parenthesized group starting at `bytes[i] == b'('`.
/// Returns the index just past the matching `)`. Respects strings and comments
/// inside the group; braces inside arguments are ignored by the caller.
fn skip_parens(bytes: &[u8], i: usize) -> usize {
    let len = bytes.len();
    let mut depth = 0u32;
    let mut j = i;
    while j < len {
        match bytes[j] {
            b'#' => {
                j = skip_line_comment(bytes, j);
                continue;
            }
            b'"' => {
                j = skip_string(bytes, j);
                continue;
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    len
}

/// Skip a string literal (regular or block) starting at `bytes[i] == b'"'`.
/// Returns the index just past the closing quote(s).
fn skip_string(bytes: &[u8], i: usize) -> usize {
    let len = bytes.len();
    // Block string """ ... """
    if i + 2 < len && bytes[i..i + 3] == *b"\"\"\"" {
        let mut j = i + 3;
        while j < len {
            if j + 2 < len && bytes[j..j + 3] == *b"\"\"\"" {
                return j + 3;
            }
            // Block strings allow escaped triple-quote via backslash; treat any
            // backslash as escaping the next byte to stay conservative.
            if bytes[j] == b'\\' {
                j = (j + 2).min(len);
                continue;
            }
            j += 1;
        }
        return len;
    }
    // Regular string
    let mut j = i + 1;
    while j < len {
        match bytes[j] {
            b'\\' => {
                j = (j + 2).min(len);
                continue;
            }
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    len
}

/// Skip a `#` line comment starting at `bytes[i] == b'#'`. Returns the index of
/// the line terminator (or end-of-input).
fn skip_line_comment(bytes: &[u8], i: usize) -> usize {
    let len = bytes.len();
    let mut j = i + 1;
    while j < len && bytes[j] != b'\n' && bytes[j] != b'\r' {
        j += 1;
    }
    j
}

/// Skip ignored tokens (whitespace, commas, comments) starting at `i`.
fn skip_ignored(bytes: &[u8], mut i: usize) -> usize {
    let len = bytes.len();
    while i < len {
        let c = bytes[i];
        if c.is_ascii_whitespace() || c == b',' {
            i += 1;
        } else if c == b'#' {
            i = skip_line_comment(bytes, i);
        } else {
            break;
        }
    }
    i
}

/// Analyze a selected operation's selection set, expanding fragment spreads.
///
/// Returns `(max_depth, complexity, alias_count, is_introspection)` measured
/// over the operation with all reachable fragments expanded in place, or `None`
/// if the byte-expansion budget was exceeded (which the caller turns into a
/// 400). Cyclic fragment spreads are detected via a per-path visited set so the
/// expansion always terminates.
fn analyze_operation(
    selection_set: &str,
    fragments: &HashMap<&str, &str>,
) -> Option<(u32, u32, u32, bool)> {
    let mut acc = AnalysisAcc::default();
    let mut visited: Vec<&str> = Vec::new();
    let mut budget = MAX_FRAGMENT_EXPANSION_BYTES;
    // The operation selection set sits one level inside the operation's
    // outermost braces, so its fields are at depth 1.
    analyze_selection_set(
        selection_set,
        1,
        0,
        fragments,
        &mut visited,
        &mut acc,
        &mut budget,
    )?;
    Some((
        acc.max_depth,
        acc.complexity,
        acc.alias_count,
        acc.is_introspection,
    ))
}

/// Mutable accumulator for an analysis pass.
#[derive(Default)]
struct AnalysisAcc {
    max_depth: u32,
    complexity: u32,
    alias_count: u32,
    is_introspection: bool,
}

/// Scan one selection-set body (the bytes between a matched `{` `}`), with the
/// enclosing brace already accounted for as `base_depth`. Fields are counted
/// into `acc.complexity`; nested selection sets recurse; `...Frag` spreads
/// expand the named fragment's selection set at the current depth (guarded
/// against cycles via `visited` and bounded by `budget`).
///
/// `call_depth` is the analyzer's recursion depth (independent of `base_depth`,
/// since fragment spreads recurse without adding GraphQL nesting); it caps stack
/// usage. Returns `None` if either the byte budget or the recursion bound is
/// exceeded.
fn analyze_selection_set<'a>(
    body: &'a str,
    base_depth: u32,
    call_depth: u32,
    fragments: &HashMap<&'a str, &'a str>,
    visited: &mut Vec<&'a str>,
    acc: &mut AnalysisAcc,
    budget: &mut usize,
) -> Option<()> {
    if call_depth >= MAX_ANALYSIS_RECURSION {
        return None;
    }
    *budget = budget.checked_sub(body.len())?;
    if base_depth > acc.max_depth {
        acc.max_depth = base_depth;
    }

    let bytes = body.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        let c = bytes[i];

        match c {
            b'#' => {
                i = skip_line_comment(bytes, i);
                continue;
            }
            b'"' => {
                i = skip_string(bytes, i);
                continue;
            }
            b'(' => {
                // Argument list: skip entirely (matches the original scanner,
                // which ignored everything inside arguments).
                i = skip_parens(bytes, i);
                continue;
            }
            b'{' => {
                // Nested selection set: recurse one level deeper.
                let end = find_matching_brace(bytes, i)?;
                analyze_selection_set(
                    &body[i + 1..end],
                    base_depth + 1,
                    call_depth + 1,
                    fragments,
                    visited,
                    acc,
                    budget,
                )?;
                i = end + 1;
                continue;
            }
            b'}' => {
                // Should not appear at this level (bodies are pre-balanced), but
                // tolerate it.
                i += 1;
                continue;
            }
            b'.' => {
                // Fragment spread `...Name` or inline fragment
                // (`... on Type { ... }`, `... { ... }`, `... @dir { ... }`).
                if i + 2 < len && bytes[i + 1] == b'.' && bytes[i + 2] == b'.' {
                    let after_dots = skip_ignored(bytes, i + 3);
                    // A named fragment spread is `...` followed by a name that is
                    // not the `on` keyword. Anything else is an inline fragment.
                    if after_dots < len && is_graphql_name_start(bytes[after_dots]) {
                        let (name, after_name) = read_name(bytes, after_dots);
                        if name != "on" {
                            // Named fragment spread: expand the fragment body at
                            // the current depth. A spread whose name is already on
                            // the current path is a cycle (invalid GraphQL); we
                            // simply do not recurse into it, which guarantees the
                            // expansion terminates.
                            if let Some(frag_body) = fragments.get(name)
                                && !visited.contains(&name)
                            {
                                visited.push(name);
                                let frag_body = *frag_body;
                                let result = analyze_selection_set(
                                    frag_body,
                                    base_depth,
                                    call_depth + 1,
                                    fragments,
                                    visited,
                                    acc,
                                    budget,
                                );
                                visited.pop();
                                result?;
                            }
                            i = after_name;
                            continue;
                        }
                    }
                    // Inline fragment: its selection set is spliced in at the
                    // SAME depth (an inline fragment adds no nesting level). Skip
                    // any `on Type` / directives, then analyze the `{ ... }` body
                    // at the current base_depth.
                    match find_next_top_level_brace(bytes, i + 3) {
                        Some(brace) => {
                            let end = find_matching_brace(bytes, brace)?;
                            analyze_selection_set(
                                &body[brace + 1..end],
                                base_depth,
                                call_depth + 1,
                                fragments,
                                visited,
                                acc,
                                budget,
                            )?;
                            i = end + 1;
                        }
                        None => {
                            // No selection set found (malformed); skip the dots.
                            i += 3;
                        }
                    }
                    continue;
                }
                i += 1;
                continue;
            }
            _ => {}
        }

        if is_graphql_name_start(c) {
            let (ident, after_ident) = read_name(bytes, i);

            // Skip keywords/literals that are not fields.
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
                i = after_ident;
                continue;
            }

            // Look past whitespace for an alias `:`.
            let j = skip_ws_only(bytes, after_ident);
            if j < len && bytes[j] == b':' {
                acc.alias_count += 1;
                // The aliased field name follows and is counted on a later
                // iteration.
                i = j + 1;
                continue;
            }

            // A field. Skip directive names (prefixed by `@`).
            if i > 0 && bytes[i - 1] == b'@' {
                i = after_ident;
                continue;
            }
            if ident == "__schema" || ident == "__type" {
                acc.is_introspection = true;
            }
            acc.complexity += 1;
            i = after_ident;
            continue;
        }

        i += 1;
    }

    Some(())
}

/// Skip only ASCII whitespace (not commas/comments) starting at `i`.
fn skip_ws_only(bytes: &[u8], mut i: usize) -> usize {
    let len = bytes.len();
    while i < len && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
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

fn contains_fragment_syntax(query: &str) -> bool {
    let bytes = query.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        match bytes[i] {
            b'#' => {
                i = skip_line_comment(bytes, i);
            }
            b'"' => {
                i = skip_string(bytes, i);
            }
            b'.' if i + 2 < len && bytes[i + 1] == b'.' && bytes[i + 2] == b'.' => {
                return true;
            }
            c if is_graphql_name_start(c) => {
                let (ident, after_ident) = read_name(bytes, i);
                if ident == "fragment" {
                    return true;
                }
                i = after_ident;
            }
            _ => {
                i += 1;
            }
        }
    }

    false
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

fn is_graphql_json_content_type(content_type: &str) -> bool {
    is_json_content_type(content_type) || ascii_contains_ignore_case(content_type, "json")
}

fn ascii_contains_ignore_case(haystack: &str, needle: &str) -> bool {
    let hb = haystack.as_bytes();
    let nb = needle.as_bytes();
    if nb.is_empty() {
        return true;
    }
    if nb.len() > hb.len() {
        return false;
    }

    hb.windows(nb.len()).any(|window| {
        window
            .iter()
            .zip(nb.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
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
                .is_some_and(|ct| is_graphql_json_content_type(ct))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only inspect POST + JSON + object with string `query`. Other HTTP
        // representations are refuse-by-default (fail closed) unless the
        // operator sets require_inspectable_transport: false.
        if ctx.method != "POST" {
            if self.require_inspectable_transport {
                return reject_uninspectable_transport(
                    "GraphQL request uses an unsupported HTTP method; \
                     only POST with an inspectable JSON body is accepted",
                );
            }
            return PluginResult::Continue;
        }

        if !headers
            .get("content-type")
            .is_some_and(|ct| is_graphql_json_content_type(ct))
        {
            if self.require_inspectable_transport {
                return reject_uninspectable_transport(
                    "GraphQL request uses an unsupported content type; \
                     only JSON content types are inspectable",
                );
            }
            return PluginResult::Continue;
        }

        let body = match ctx.metadata.get("request_body") {
            Some(b) if !b.is_empty() => b.as_str(),
            _ => {
                debug!("graphql: no request body available");
                if self.require_inspectable_transport {
                    return reject_uninspectable_transport(
                        "GraphQL request body is missing or empty \
                         and cannot be inspected",
                    );
                }
                return PluginResult::Continue;
            }
        };

        let parsed: Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => {
                debug!("graphql: request body is not valid JSON");
                if self.require_inspectable_transport {
                    return reject_uninspectable_transport(
                        "GraphQL request body is not valid JSON \
                         and cannot be inspected",
                    );
                }
                return PluginResult::Continue;
            }
        };

        let query = match parsed.get("query").and_then(|q| q.as_str()) {
            Some(q) if !q.is_empty() => q,
            _ => {
                // Batch arrays, APQ hash-only envelopes, empty/missing query.
                if self.require_inspectable_transport {
                    return reject_uninspectable_transport(
                        "GraphQL request must include an inspectable string \
                         query field; batch arrays and persisted-query \
                         envelopes without a query document are refused",
                    );
                }
                return PluginResult::Continue;
            }
        };

        let operation_name = parsed.get("operationName").and_then(|n| n.as_str());

        // Parse the GraphQL query and select the operation to analyze. The
        // parser rejects spec-invalid documents (e.g. multiple operations
        // without operationName) and over-budget fragment expansion.
        let op = match parse_graphql_query(query, operation_name) {
            ParsedQuery::Operation(op) => op,
            ParsedQuery::Reject {
                status_code,
                message,
            } => {
                debug!(status_code, %message, "graphql: query rejected during parsing");
                return PluginResult::Reject {
                    status_code,
                    body: graphql_error_body(&message),
                    headers: json_content_type_header(),
                };
            }
        };

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

/// Reject an HTTP GraphQL representation that cannot be inspected.
fn reject_uninspectable_transport(message: &str) -> PluginResult {
    PluginResult::Reject {
        status_code: 400,
        body: graphql_error_body(message),
        headers: json_content_type_header(),
    }
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
