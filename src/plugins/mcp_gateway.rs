//! MCP Gateway plugin.
//!
//! Makes HTTP-based Model Context Protocol JSON-RPC traffic visible to Ferrum:
//! it extracts `mcp.*` metadata, preserves MCP session headers, aggregates
//! discovery catalogs in aggregate-router mode, and routes namespaced MCP tool,
//! resource, and prompt calls to configured upstream MCP servers.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures_util::StreamExt;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use regex::Regex;
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::warn;
use url::Url;

use crate::config::types::{BackendScheme, BackendTlsConfig};

use super::{HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext};

const DEFAULT_PROTOCOL_VERSION: &str = "2025-11-25";
const DEFAULT_SESSION_TTL_SECONDS: u64 = 3600;
const DEFAULT_MAX_SESSIONS: usize = 16_384;
const METADATA_REWRITE_KEY: &str = "mcp.needs_request_rewrite";
const METADATA_REWRITE_METHOD_KEY: &str = "mcp.rewrite.method";
const METADATA_REWRITE_PARAM_KEY: &str = "mcp.rewrite.param";
const METADATA_REWRITE_PUBLIC_VALUE_KEY: &str = "mcp.rewrite.public_value";
const METADATA_REWRITE_UPSTREAM_VALUE_KEY: &str = "mcp.rewrite.upstream_value";
const METADATA_RESPONSE_REWRITE_KEY: &str = "mcp.needs_response_rewrite";
const METADATA_RESPONSE_REWRITE_METHOD_KEY: &str = "mcp.response_rewrite.method";
const METADATA_RESPONSE_REWRITE_SERVER_KEY: &str = "mcp.response_rewrite.server_id";
const METADATA_RESPONSE_REWRITE_SESSION_KEY: &str = "mcp.response_rewrite.session";
const METADATA_RESPONSE_REWRITE_CATALOG_VERSION_KEY: &str = "mcp.response_rewrite.catalog_version";
const MAX_MCP_PAGINATION_PAGES: usize = 100;
const DEFAULT_MAX_MCP_CATALOG_ITEMS_PER_LIST: usize = 10_000;
const DEFAULT_MAX_MCP_CATALOG_BYTES_PER_LIST: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_UPSTREAM_JSON_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_JSONRPC_BATCH_ITEMS: usize = 32;
const DEFAULT_MAX_JSONRPC_BATCH_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_JSONRPC_BATCH_ITEM_BYTES: usize = 256 * 1024;
/// Default aggregate serialized JSON-RPC batch *response* budget (array framing
/// included). Kept aligned with the request-body default so operators size one
/// knob pair coherently.
const DEFAULT_MAX_JSONRPC_BATCH_RESPONSE_BYTES: usize = 1024 * 1024;
/// JSON-RPC application error: aggregate batch member would require upstream
/// routing that cannot preserve later plugin phases inside one HTTP exchange.
const MCP_BATCH_UPSTREAM_ROUTING_UNSUPPORTED: i64 = -32009;
/// JSON-RPC application error: an MCP session-lifecycle operation was attempted
/// inside a JSON-RPC batch. Session minting/eviction is not transactional across
/// batch members and one HTTP response header cannot advertise more than one new
/// session, so lifecycle members are rejected before any session-store mutation.
const MCP_BATCH_SESSION_LIFECYCLE_AMBIGUOUS: i64 = -32010;
/// JSON-RPC application error: a batch notification member could not be
/// processed. Notifications carry no per-item response element, so the failure
/// is surfaced once at batch level instead of silently claiming success.
const MCP_BATCH_NOTIFICATION_FAILED: i64 = -32011;
const MAX_UPSTREAM_SSE_EVENT_BYTES: usize = 1024 * 1024;
const MCP_STREAMABLE_HTTP_ACCEPT: &str = "application/json, text/event-stream";
const MCP_TEMPLATE_RESOURCE_URI_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
const MCP_RESERVED_TEMPLATE_RESOURCE_URI_ENCODE_SET: &AsciiSet =
    &MCP_TEMPLATE_RESOURCE_URI_ENCODE_SET
        .remove(b':')
        .remove(b'/')
        .remove(b'?')
        .remove(b'#')
        .remove(b'[')
        .remove(b']')
        .remove(b'@')
        .remove(b'!')
        .remove(b'$')
        .remove(b'&')
        .remove(b'\'')
        .remove(b'(')
        .remove(b')')
        .remove(b'*')
        .remove(b'+')
        .remove(b',')
        .remove(b';')
        .remove(b'=');
const MCP_REWRITTEN_RESPONSE_VALIDATORS: &[&str] = &[
    "etag",
    "last-modified",
    "content-digest",
    "digest",
    "content-md5",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpGatewayMode {
    TransparentProxy,
    AggregateRouter,
}

impl McpGatewayMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "transparent_proxy" => Ok(Self::TransparentProxy),
            "aggregate_router" => Ok(Self::AggregateRouter),
            other => Err(format!(
                "mcp_gateway: 'mode' must be transparent_proxy or aggregate_router, got {other:?}"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::TransparentProxy => "transparent_proxy",
            Self::AggregateRouter => "aggregate_router",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitializeStrategy {
    Lazy,
    Startup,
    Passthrough,
}

impl InitializeStrategy {
    fn parse(value: &str, field: &str) -> Result<Self, String> {
        match value {
            "lazy" => Ok(Self::Lazy),
            "startup" => Ok(Self::Startup),
            "passthrough" => Ok(Self::Passthrough),
            other => Err(format!(
                "mcp_gateway: '{field}' must be lazy, startup, or passthrough, got {other:?}"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyAction {
    Allow,
    Deny,
    HideFromDiscovery,
}

impl PolicyAction {
    fn parse(value: &str, field: &str) -> Result<Self, String> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "hide_from_discovery" => Ok(Self::HideFromDiscovery),
            other => Err(format!(
                "mcp_gateway: '{field}' must be allow, deny, or hide_from_discovery, got {other:?}"
            )),
        }
    }

    fn as_policy_decision(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::HideFromDiscovery => "hide",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryBehavior {
    Allow,
    HideUntilConfigured,
}

impl DiscoveryBehavior {
    fn parse(value: &str, field: &str) -> Result<Self, String> {
        match value {
            "allow" | "allow_immediately" | "expose" => Ok(Self::Allow),
            "hide_until_configured" => Ok(Self::HideUntilConfigured),
            other => Err(format!(
                "mcp_gateway: '{field}' must be allow or hide_until_configured, got {other:?}"
            )),
        }
    }
}

#[derive(Debug, Clone)]
struct McpDiscoveryConfig {
    aggregate_tools: bool,
    aggregate_resources: bool,
    aggregate_prompts: bool,
    namespace_separator: String,
    cache_ttl: Duration,
    hide_denied_items: bool,
    on_new_tool: DiscoveryBehavior,
    on_schema_change: DiscoveryBehavior,
}

#[derive(Debug, Clone)]
struct McpSessionConfig {
    downstream_session_header: String,
    upstream_session_header: String,
    initialize_upstreams: InitializeStrategy,
    session_ttl: Duration,
    max_sessions: usize,
}

#[derive(Debug, Clone)]
struct McpCapabilitiesConfig {
    advertise_tools: bool,
    advertise_resources: bool,
    advertise_prompts: bool,
    advertise_logging: bool,
    advertise_completions: bool,
    advertise_tasks: bool,
    passthrough_unknown_methods: bool,
}

#[derive(Debug, Clone)]
struct McpPolicy {
    default_action: PolicyAction,
    hide_denied_tools: bool,
    tools: HashMap<String, PolicyAction>,
}

impl McpPolicy {
    fn action_for_tool(&self, public_name: &str) -> PolicyAction {
        self.tools
            .get(public_name)
            .copied()
            .unwrap_or(self.default_action)
    }
}

#[derive(Debug, Clone)]
struct McpValidationConfig {
    validate_tool_arguments: bool,
    /// Max bytes read from a single non-SSE upstream `application/json`
    /// response before the read is aborted (DoS backstop).
    max_upstream_response_bytes: usize,
    /// Max items accumulated across paginated catalog list pages.
    max_catalog_items_per_list: usize,
    /// Max total serialized bytes accumulated across paginated catalog pages.
    max_catalog_bytes_per_list: usize,
    /// Max JSON-RPC batch array members admitted before expensive dispatch.
    max_batch_items: usize,
    /// Max aggregate request-body bytes admitted for a JSON-RPC batch.
    max_batch_bytes: usize,
    /// Max serialized bytes admitted for one JSON-RPC batch member.
    max_batch_item_bytes: usize,
    /// Max serialized bytes admitted for the assembled JSON-RPC batch response
    /// array (including array framing). Oversized aggregates fail closed.
    max_batch_response_bytes: usize,
}

#[derive(Debug, Clone)]
struct McpObservabilityConfig {
    emit_metadata: bool,
    log_raw_arguments: bool,
    log_argument_hash: bool,
    #[allow(dead_code)] // Parsed for V1 config compatibility; result logging is not emitted in V1.
    log_raw_results: bool,
    #[allow(dead_code)] // Parsed for V1 config compatibility; result hashing is not emitted in V1.
    log_result_hash: bool,
}

#[derive(Debug, Clone)]
struct McpUpstreamTarget {
    scheme: BackendScheme,
    host: String,
    port: u16,
    path: String,
    authority: String,
}

#[derive(Debug, Clone)]
struct McpServerConfig {
    server_id: String,
    namespace: String,
    upstream_url: String,
    target: McpUpstreamTarget,
    enabled: bool,
    expose_tools: bool,
    expose_resources: bool,
    expose_prompts: bool,
    initialize_strategy: InitializeStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpMessageKind {
    Request,
    Notification,
    Response,
    ErrorResponse,
}

impl McpMessageKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Notification => "notification",
            Self::Response => "response",
            Self::ErrorResponse => "error_response",
        }
    }
}

#[derive(Debug, Clone)]
struct McpEnvelope {
    jsonrpc: String,
    id: Option<Value>,
    method: Option<String>,
    params: Option<Value>,
    #[allow(dead_code)] // Kept in the parsed envelope shape for response classification.
    result: Option<Value>,
    #[allow(dead_code)] // Kept in the parsed envelope shape for error-response classification.
    error: Option<Value>,
    message_kind: McpMessageKind,
}

/// One JSON-RPC batch array member after raw-wire admission.
///
/// `validation.max_batch_item_bytes` is a *wire*-byte cap: it is enforced on
/// the member's exact raw JSON slice (internal whitespace and escape sequences
/// included) before that member is deserialized into a `Value`. A member that
/// fails admission is never materialized and its id is never read, so an
/// oversized attacker-controlled id can be neither cloned nor reflected.
enum BatchMember {
    /// The raw slice was within the per-member cap and materialized cleanly.
    Admitted(Value),
    /// The raw slice exceeded the per-member cap (or could not be
    /// materialized). Yields a bounded `id: null` Invalid Request at this
    /// member's input position.
    Rejected,
}

#[derive(Clone)]
struct ToolCatalogEntry {
    public_name: String,
    upstream_name: String,
    server_id: String,
    namespace: String,
    input_schema: Value,
    output_schema: Option<Value>,
    title: Option<String>,
    description: Option<String>,
    annotations: Option<Value>,
    enabled: bool,
    hidden_by_discovery: bool,
    hidden_from_discovery: bool,
    // Sticky: once a tool is hidden because its inputSchema drifted under
    // on_schema_change=hide_until_configured, it stays hidden across refreshes
    // (the new hash becomes the baseline, so schema_changed is only true once)
    // until an operator reconfigures/reloads — including explicitly-configured
    // tools, which the per-refresh schema check would otherwise re-enable.
    hidden_by_schema_change: bool,
    input_validator: Arc<jsonschema::Validator>,
    #[allow(dead_code)] // Stored for drift/operational metadata extensions.
    discovered_at: DateTime<Utc>,
    schema_hash: String,
    #[allow(dead_code)] // Stored for description-only drift detection extensions.
    description_hash: String,
}

#[derive(Debug, Clone)]
struct PromptCatalogEntry {
    public_name: String,
    upstream_name: String,
    server_id: String,
    namespace: String,
    description: Option<String>,
    arguments_schema: Option<Value>,
    enabled: bool,
    #[allow(dead_code)] // Stored for drift/operational metadata extensions.
    discovered_at: DateTime<Utc>,
    #[allow(dead_code)] // Stored for prompt schema drift metadata extensions.
    schema_hash: String,
}

#[derive(Debug, Clone)]
struct ResourceCatalogEntry {
    public_uri: String,
    upstream_uri: String,
    server_id: String,
    namespace: String,
    name: Option<String>,
    description: Option<String>,
    mime_type: Option<String>,
    enabled: bool,
    #[allow(dead_code)] // Stored for drift/operational metadata extensions.
    discovered_at: DateTime<Utc>,
    #[allow(dead_code)] // Stored for resource drift metadata extensions.
    uri_hash: String,
}

#[derive(Clone)]
struct ResourceTemplateCatalogEntry {
    public_uri_template: String,
    server_id: String,
    namespace: String,
    name: Option<String>,
    title: Option<String>,
    description: Option<String>,
    mime_type: Option<String>,
    annotations: Option<Value>,
    icons: Option<Value>,
    enabled: bool,
    #[allow(dead_code)] // Stored for drift/operational metadata extensions.
    discovered_at: DateTime<Utc>,
    uri_template_regex: Arc<Regex>,
}

struct RequestRewrite<'a> {
    method: &'a str,
    param: &'a str,
    public_value: &'a str,
    upstream_value: &'a str,
    server_id: &'a str,
    downstream_session_id: &'a str,
    catalog_version: u64,
    response_resource_rewrite_possible: bool,
}

#[derive(Clone, Default)]
struct CatalogCollisionTombstones {
    tools: HashSet<String>,
    prompts: HashSet<String>,
    resources: HashSet<String>,
}

#[derive(Clone)]
struct McpCatalog {
    tools: HashMap<String, ToolCatalogEntry>,
    prompts: HashMap<String, PromptCatalogEntry>,
    resources: HashMap<String, ResourceCatalogEntry>,
    resource_templates: HashMap<String, ResourceTemplateCatalogEntry>,
    version: u64,
    last_refreshed_at: Option<Instant>,
    resource_templates_refreshed_at: Option<Instant>,
    resource_templates_last_attempted_at: HashMap<String, Instant>,
    last_refreshed_wall: DateTime<Utc>,
    // `(server_id, catalog family)` pairs whose most recent list refresh
    // failed and whose entries (if any) are being served stale from the last
    // good refresh. Bounded by configured servers x catalog families; exposed
    // through `mcp.catalog_degraded` metadata.
    degraded: BTreeSet<(String, &'static str)>,
    // `(server_id, catalog family)` pairs with at least one successful list in
    // this catalog's lifetime (a successful *empty* list counts). Carried
    // forward across failed refreshes so "last-good empty" stays
    // distinguishable from "never successfully listed"; availability is never
    // inferred from entry counts. Bounded like `degraded`.
    last_good: BTreeSet<(String, &'static str)>,
    // Catalog families whose most recent refresh failed on every attempted
    // upstream with no last-good state anywhere in the family. Requests for
    // these families surface -32006 instead of a cached empty catalog until a
    // refresh succeeds; other families stay usable.
    unavailable: BTreeSet<&'static str>,
    // Public keys suppressed by collision handling are absent from the maps
    // above, so retain explicit tombstones across degraded refreshes. Otherwise
    // a healthy upstream could become the temporary winner of a prior
    // collision merely because another participant failed its list request.
    collision_tombstones: CatalogCollisionTombstones,
    // Families whose collision history exceeded the aggregate number of items
    // one refresh can return. A single bit replaces unbounded historical keys;
    // the affected family stays unavailable until a fully authoritative
    // refresh can rebuild its collision state from current upstream results.
    collision_tombstone_overflow: BTreeSet<&'static str>,
}

impl Default for McpCatalog {
    fn default() -> Self {
        Self {
            tools: HashMap::new(),
            prompts: HashMap::new(),
            resources: HashMap::new(),
            resource_templates: HashMap::new(),
            version: 0,
            last_refreshed_at: None,
            resource_templates_refreshed_at: None,
            resource_templates_last_attempted_at: HashMap::new(),
            last_refreshed_wall: Utc::now(),
            degraded: BTreeSet::new(),
            last_good: BTreeSet::new(),
            unavailable: BTreeSet::new(),
            collision_tombstones: CatalogCollisionTombstones::default(),
            collision_tombstone_overflow: BTreeSet::new(),
        }
    }
}

impl McpCatalog {
    fn is_stale(&self, ttl: Duration) -> bool {
        match self.last_refreshed_at {
            Some(refreshed) => refreshed.elapsed() >= ttl,
            None => true,
        }
    }

    fn resource_templates_are_stale(&self, ttl: Duration) -> bool {
        match self.resource_templates_refreshed_at {
            Some(refreshed) => refreshed.elapsed() >= ttl,
            None => true,
        }
    }
}

/// Per-family success/failure accounting for one catalog refresh pass. A
/// family is fully unavailable when every attempted upstream list failed and
/// no attempted upstream has last-good state (a previous successful list,
/// possibly empty) to serve stale — availability is deliberately not inferred
/// from entry counts.
#[derive(Default)]
struct FamilyRefreshStats {
    attempted: usize,
    failed: usize,
    has_last_good: bool,
}

impl FamilyRefreshStats {
    fn record_success(&mut self) {
        self.attempted += 1;
        self.has_last_good = true;
    }

    fn record_failure(&mut self, had_last_good: bool) {
        self.attempted += 1;
        self.failed += 1;
        self.has_last_good |= had_last_good;
    }

    fn fully_unavailable(&self) -> bool {
        self.attempted > 0 && self.failed == self.attempted && !self.has_last_good
    }

    fn fully_authoritative(&self) -> bool {
        self.attempted > 0 && self.failed == 0
    }
}

#[derive(Debug)]
enum McpCatalogError {
    SessionNotFound,
    Refresh(String),
}

#[derive(Clone)]
struct DownstreamMcpSession {
    #[allow(dead_code)] // Useful in snapshots/debug views; map key is used for lookup.
    downstream_session_id: String,
    protocol_version: String,
    client_info: Option<Value>,
    client_capabilities: Option<Value>,
    upstream_sessions: HashMap<String, UpstreamMcpSession>,
    catalog: Arc<RwLock<McpCatalog>>,
    // Per-session catalog refresh lock: serializes discovery for *this* session's
    // catalog only, so a slow upstream refreshing one session does not block
    // discovery for unrelated sessions (the catalog is per-session by design).
    catalog_refresh_lock: Arc<Mutex<()>>,
    last_seen: Instant,
}

#[derive(Debug, Clone)]
struct UpstreamMcpSession {
    #[allow(dead_code)] // Useful in snapshots/debug views; map key is used for lookup.
    server_id: String,
    upstream_session_id: Option<String>,
    protocol_version: Option<String>,
    initialized: bool,
    // Per-(session, server) initialize lock: serializes the upstream initialize +
    // notifications/initialized round trip for this one upstream session, so a slow
    // upstream does not stall initialization for other sessions or other servers.
    init_lock: Arc<Mutex<()>>,
}

/// MCP-aware gateway/router plugin.
pub struct McpGateway {
    enabled: bool,
    mode: McpGatewayMode,
    endpoint_path: String,
    supported_protocol_versions: Vec<String>,
    discovery: McpDiscoveryConfig,
    sessions: McpSessionConfig,
    capabilities: McpCapabilitiesConfig,
    servers: HashMap<String, McpServerConfig>,
    primary_server_id: String,
    // Catalog-refresh and upstream-initialize locks are scoped per-session and
    // per-(session, server) respectively (see DownstreamMcpSession /
    // UpstreamMcpSession), not globally, so one slow upstream cannot serialize
    // discovery or initialization across unrelated client sessions.
    session_admission_lock: Arc<Mutex<()>>,
    session_store: Arc<DashMap<String, DownstreamMcpSession>>,
    // Response transforms only retain the already-observable hash of the
    // downstream session in request metadata. This secondary index gives them
    // O(1) access to the same per-session catalog used for request routing
    // without retaining or logging the raw downstream session id.
    session_catalogs_by_hash: Arc<DashMap<String, Arc<RwLock<McpCatalog>>>>,
    policy: McpPolicy,
    validation: McpValidationConfig,
    observability: McpObservabilityConfig,
    http_client: PluginHttpClient,
}

impl McpGateway {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "mcp_gateway: config must be an object".to_string())?;

        let enabled = optional_bool(object, "enabled")?.unwrap_or(true);
        let mode = McpGatewayMode::parse(
            optional_string(object, "mode")?
                .ok_or_else(|| "mcp_gateway: 'mode' is required".to_string())?,
        )?;

        let endpoint = optional_object(object, "endpoint")?;
        let endpoint_path = optional_string_from_object(endpoint, "path")?
            .ok_or_else(|| "mcp_gateway: 'endpoint.path' is required".to_string())?;
        validate_path(&endpoint_path, "endpoint.path")?;

        let supported_protocol_versions =
            optional_string_vec_from_object(endpoint, "protocol_versions")?
                .unwrap_or_else(|| vec![DEFAULT_PROTOCOL_VERSION.to_string()]);
        if supported_protocol_versions.is_empty() {
            return Err("mcp_gateway: 'endpoint.protocol_versions' must not be empty".to_string());
        }
        if supported_protocol_versions
            .iter()
            .any(|version| version.trim().is_empty())
        {
            return Err(
                "mcp_gateway: 'endpoint.protocol_versions' entries must not be empty".to_string(),
            );
        }
        // `2025-03-26` is admitted: JSON-RPC batches are handled by the gateway
        // with explicit item/byte/nesting limits (see validation.max_batch_*).

        let discovery = parse_discovery(object)?;
        let sessions = parse_sessions(object)?;
        let capabilities = parse_capabilities(object)?;
        let policy = parse_policy(object)?;
        let validation = parse_validation(object)?;
        let observability = parse_observability(object)?;
        let servers = parse_servers(object, sessions.initialize_upstreams)?;
        if servers.is_empty() {
            return Err("mcp_gateway: 'servers' must not be empty".to_string());
        }
        // Screen each upstream's literal-IP URL against the egress policy at
        // config-load: these are dialed through the shared client, but reqwest
        // skips the DnsCacheResolver for IP literals, so an operator/file/CP
        // write naming e.g. `http://169.254.169.254/...` must be rejected here.
        for server in servers.values() {
            if let Ok(parsed) = url::Url::parse(&server.upstream_url) {
                crate::plugins::utils::log_helpers::screen_url_host_egress(
                    "mcp_gateway",
                    "upstream_url",
                    &parsed,
                    http_client.backend_allow_ips(),
                )?;
            }
        }
        if sessions.initialize_upstreams == InitializeStrategy::Startup
            || servers
                .values()
                .any(|server| server.initialize_strategy == InitializeStrategy::Startup)
        {
            warn!(
                "mcp_gateway startup upstream initialization is treated as lazy in V1 because MCP initialize requires a downstream session"
            );
        }
        let mut enabled_server_ids: Vec<String> = servers
            .values()
            .filter(|server| server.enabled)
            .map(|server| server.server_id.clone())
            .collect();
        enabled_server_ids.sort();
        if enabled_server_ids.is_empty() {
            return Err("mcp_gateway: at least one server must be enabled".to_string());
        }
        if mode == McpGatewayMode::TransparentProxy && enabled_server_ids.len() != 1 {
            return Err(
                "mcp_gateway: transparent_proxy mode requires exactly one enabled server"
                    .to_string(),
            );
        }
        if mode == McpGatewayMode::AggregateRouter
            && !servers.values().any(|server| {
                server.enabled
                    && (server.expose_tools || server.expose_resources || server.expose_prompts)
            })
        {
            return Err(
                "mcp_gateway: aggregate_router mode requires at least one enabled exposed item"
                    .to_string(),
            );
        }
        if mode == McpGatewayMode::AggregateRouter && !capabilities.passthrough_unknown_methods {
            // These capabilities have no dedicated dispatch in V1. Advertising them
            // in the synthetic initialize response would make compliant clients call
            // methods (completion/complete, logging/setLevel, tasks/*) that the
            // dispatcher answers with -32601. Require passthrough so they are at
            // least routed to the primary upstream until they are implemented.
            for (advertised, capability) in [
                (capabilities.advertise_completions, "advertise_completions"),
                (capabilities.advertise_logging, "advertise_logging"),
                (capabilities.advertise_tasks, "advertise_tasks"),
            ] {
                if advertised {
                    return Err(format!(
                        "mcp_gateway: capabilities.{capability} requires capabilities.passthrough_unknown_methods=true in aggregate_router mode until that method is routed or implemented"
                    ));
                }
            }
        }

        let primary_server_id = enabled_server_ids
            .first()
            .ok_or_else(|| "mcp_gateway: at least one server must be enabled".to_string())?
            .clone();

        // session_store is read/touched on every aggregate request and written on
        // initialize/eviction, so size its shards per the hot-path DashMap invariant
        // (honors FERRUM_POOL_SHARD_AMOUNT via the shared http client).
        let session_shard_amount = http_client.pool_shard_amount();

        // No static replay-provenance digest is computed here on purpose. The
        // public-URI mapping this plugin writes into response bodies comes from
        // the live per-session `McpCatalog`, not from `config`; see
        // `response_presentation_policy`.
        Ok(Self {
            enabled,
            mode,
            endpoint_path,
            supported_protocol_versions,
            discovery,
            sessions,
            capabilities,
            servers,
            primary_server_id,
            session_admission_lock: Arc::new(Mutex::new(())),
            session_store: Arc::new(DashMap::with_shard_amount(session_shard_amount)),
            session_catalogs_by_hash: Arc::new(DashMap::with_shard_amount(session_shard_amount)),
            policy,
            validation,
            observability,
            http_client,
        })
    }

    fn matches_endpoint(&self, ctx: &RequestContext) -> bool {
        ctx.path == self.endpoint_path
    }

    fn content_type_is_json(headers: &HashMap<String, String>) -> bool {
        header_value(headers, "content-type").is_none_or(|value| {
            let media_type = value.split(';').next().unwrap_or(value).trim();
            media_type.eq_ignore_ascii_case("application/json")
                || media_type.eq_ignore_ascii_case("application/json-rpc")
                || media_type.ends_with("+json")
        })
    }

    /// Whether the raw request body is shaped like a JSON-RPC batch, decided
    /// from the first non-whitespace byte only. Used to apply
    /// `validation.max_batch_bytes` before any JSON parsing, so an oversized
    /// batch never funds a full `serde_json::Value` allocation. JSON permits
    /// only these four whitespace bytes before a value.
    fn body_is_jsonrpc_batch_shaped(body: &[u8]) -> bool {
        body.iter()
            .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
            .is_some_and(|byte| *byte == b'[')
    }

    fn request_body<'a>(&self, ctx: &'a RequestContext) -> Option<&'a [u8]> {
        ctx.request_body_bytes
            .as_ref()
            .map(|body| body.as_ref())
            .or_else(|| ctx.metadata.get("request_body").map(|body| body.as_bytes()))
    }

    fn emit_base_metadata(&self, ctx: &mut RequestContext) {
        if !self.observability.emit_metadata {
            return;
        }
        ctx.metadata
            .insert("mcp.enabled".to_string(), "true".to_string());
        ctx.metadata
            .insert("mcp.mode".to_string(), self.mode.as_str().to_string());
        ctx.metadata
            .entry("mcp.route_decision".to_string())
            .or_insert_with(|| "not_applicable".to_string());
        ctx.metadata
            .entry("mcp.policy_decision".to_string())
            .or_insert_with(|| "not_applicable".to_string());
        ctx.metadata
            .entry("mcp.schema_validation".to_string())
            .or_insert_with(|| "skipped".to_string());
    }

    /// Emit the degraded (server, family) pairs a catalog is serving stale as
    /// bounded `mcp.catalog_degraded` metadata (sorted `server:family` pairs).
    /// Server ids are operator config, never upstream URLs or credentials.
    fn emit_catalog_degraded_metadata(&self, ctx: &mut RequestContext, catalog: &McpCatalog) {
        if !self.observability.emit_metadata || catalog.degraded.is_empty() {
            return;
        }
        let mut degraded = String::new();
        for (server_id, family) in &catalog.degraded {
            if !degraded.is_empty() {
                degraded.push(',');
            }
            degraded.push_str(server_id);
            degraded.push(':');
            degraded.push_str(family);
        }
        ctx.metadata
            .insert("mcp.catalog_degraded".to_string(), degraded);
    }

    fn emit_envelope_metadata(&self, ctx: &mut RequestContext, envelope: &McpEnvelope) {
        if !self.observability.emit_metadata {
            return;
        }
        ctx.metadata.insert(
            "mcp.message.kind".to_string(),
            envelope.message_kind.as_str().to_string(),
        );
        ctx.metadata
            .insert("mcp.jsonrpc".to_string(), envelope.jsonrpc.clone());
        if let Some(method) = envelope.method.as_deref() {
            ctx.metadata
                .insert("mcp.method".to_string(), method.to_string());
        }
    }

    fn mark_protocol_version(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        envelope: Option<&McpEnvelope>,
    ) -> Option<String> {
        let version = header_value(headers, "mcp-protocol-version")
            .map(ToOwned::to_owned)
            .or_else(|| {
                envelope.and_then(|env| {
                    env.params
                        .as_ref()
                        .and_then(|params| params.get("protocolVersion"))
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
            });
        if let Some(version) = version.as_deref() {
            ctx.metadata
                .insert("mcp.protocol_version".to_string(), version.to_string());
        }
        version
    }

    /// Post-initialize `MCP-Protocol-Version` gate.
    ///
    /// Shared by singleton dispatch and both batch paths so a JSON-RPC batch
    /// can never forward (or execute) a protocol version that the equivalent
    /// singleton request rejects. `initialize` is exempt because it negotiates
    /// the version rather than asserting one.
    fn unsupported_protocol_version_response(
        &self,
        ctx: &mut RequestContext,
        envelope: &McpEnvelope,
        protocol_version: Option<&str>,
    ) -> Option<PluginResult> {
        if envelope.method.as_deref() == Some("initialize") {
            return None;
        }
        let version = protocol_version?;
        if self
            .supported_protocol_versions
            .iter()
            .any(|supported| supported.as_str() == version)
        {
            return None;
        }
        ctx.metadata
            .insert("mcp.route_decision".to_string(), "deny".to_string());
        Some(json_response(
            400,
            json!({
                "jsonrpc": "2.0",
                "id": envelope.id.clone().unwrap_or(Value::Null),
                "error": {
                    "code": -32600,
                    "message": "Unsupported MCP protocol version"
                }
            }),
            None,
        ))
    }

    fn downstream_session_id_from_headers(
        &self,
        headers: &HashMap<String, String>,
    ) -> Option<String> {
        header_value(headers, &self.sessions.downstream_session_header).map(ToOwned::to_owned)
    }

    fn upstream_session_id(&self, downstream_id: &str, server_id: &str) -> Option<String> {
        self.downstream_session_clone(downstream_id)
            .and_then(|session| {
                session
                    .upstream_sessions
                    .get(server_id)
                    .and_then(|upstream| upstream.upstream_session_id.clone())
            })
    }

    fn set_route_to_server(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        server: &McpServerConfig,
        downstream_session_id: Option<&str>,
    ) {
        ctx.route_override_backend_scheme = Some(server.target.scheme);
        ctx.route_override_backend_host = Some(server.target.host.clone());
        ctx.route_override_backend_port = Some(server.target.port);
        ctx.route_override_resolved_tls = Some(BackendTlsConfig::default_verify());
        ctx.route_override_path = Some(server.target.path.clone());
        ctx.route_override_path_is_absolute = true;
        ctx.route_override_authority = Some(server.target.authority.clone());
        headers.insert("host".to_string(), server.target.authority.clone());
        if self.mode == McpGatewayMode::AggregateRouter {
            // Session headers and the protocol version are gateway-owned in aggregate
            // mode. Strip any client-supplied session value — the synthetic downstream
            // id and any forged upstream id (including a differently-cased header
            // key) — before re-adding only the gateway's mediated upstream session id.
            // This stops passthrough / stateless upstreams (no mediated upstream
            // session id) from binding to or rejecting a client-injected session.
            // Transparent mode passes the client's session header straight through to
            // its single upstream.
            remove_header(headers, &self.sessions.downstream_session_header);
            remove_header(headers, &self.sessions.upstream_session_header);
            if let Some(downstream_id) = downstream_session_id {
                // Forward the version the upstream session negotiated, which can
                // differ from the downstream-negotiated version when both are
                // supported. Sending the client's version could be rejected by an
                // upstream that initialized to a different one.
                remove_header(headers, "mcp-protocol-version");
                headers.insert(
                    "mcp-protocol-version".to_string(),
                    self.protocol_version_for_upstream(downstream_id, &server.server_id),
                );
                if let Some(upstream_id) =
                    self.upstream_session_id(downstream_id, &server.server_id)
                {
                    headers.insert(
                        self.sessions.upstream_session_header.to_ascii_lowercase(),
                        upstream_id,
                    );
                }
            }
        }
        if self.observability.emit_metadata {
            ctx.metadata
                .insert("mcp.server_id".to_string(), server.server_id.clone());
            ctx.metadata
                .insert("mcp.route_decision".to_string(), "forward".to_string());
        }
    }

    fn mark_request_rewrite(
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        rewrite: RequestRewrite<'_>,
    ) {
        ctx.metadata
            .insert(METADATA_REWRITE_KEY.to_string(), "true".to_string());
        ctx.metadata.insert(
            METADATA_REWRITE_METHOD_KEY.to_string(),
            rewrite.method.to_string(),
        );
        ctx.metadata.insert(
            METADATA_REWRITE_PARAM_KEY.to_string(),
            rewrite.param.to_string(),
        );
        ctx.metadata.insert(
            METADATA_REWRITE_PUBLIC_VALUE_KEY.to_string(),
            rewrite.public_value.to_string(),
        );
        ctx.metadata.insert(
            METADATA_REWRITE_UPSTREAM_VALUE_KEY.to_string(),
            rewrite.upstream_value.to_string(),
        );
        // Stage a non-serialized, gateway-authenticated public→upstream tool
        // identity for `ai_tool_governor`'s final-body recheck. Public metadata
        // alone is forgeable by sibling plugins; only this private field may
        // remap policy identity after aggregate routing rewrites `params.name`.
        if rewrite.method == "tools/call" && rewrite.param == "name" {
            ctx.mcp_trusted_tool_name_rewrite = Some((
                rewrite.public_value.to_string(),
                rewrite.upstream_value.to_string(),
            ));
        }
        if !rewrite.response_resource_rewrite_possible {
            return;
        }

        // Routed JSON results must remain identity-encoded so the response
        // transform can inspect them. A non-compliant upstream that still sends
        // Content-Encoding is handled defensively on the response path.
        remove_header(headers, "accept-encoding");
        ctx.metadata.insert(
            METADATA_RESPONSE_REWRITE_KEY.to_string(),
            "true".to_string(),
        );
        ctx.metadata.insert(
            METADATA_RESPONSE_REWRITE_METHOD_KEY.to_string(),
            rewrite.method.to_string(),
        );
        ctx.metadata.insert(
            METADATA_RESPONSE_REWRITE_SERVER_KEY.to_string(),
            rewrite.server_id.to_string(),
        );
        ctx.metadata.insert(
            METADATA_RESPONSE_REWRITE_SESSION_KEY.to_string(),
            hash_str(rewrite.downstream_session_id),
        );
        ctx.metadata.insert(
            METADATA_RESPONSE_REWRITE_CATALOG_VERSION_KEY.to_string(),
            rewrite.catalog_version.to_string(),
        );
        if rewrite.method == "resources/read" {
            ctx.mcp_response_resource_binding = Some((
                rewrite.upstream_value.to_string(),
                rewrite.public_value.to_string(),
            ));
        }
    }

    fn resource_response_rewrite_possible(&self, server_id: &str) -> bool {
        self.discovery.aggregate_resources
            && self
                .servers
                .get(server_id)
                .is_some_and(|server| server.enabled && server.expose_resources)
    }

    fn response_length_allows_rewrite(&self, response_headers: &HashMap<String, String>) -> bool {
        header_value(response_headers, "content-length")
            .and_then(|value| value.trim().parse::<usize>().ok())
            .is_some_and(|length| length <= self.validation.max_upstream_response_bytes)
    }

    fn response_encoding_allows_rewrite(response_headers: &HashMap<String, String>) -> bool {
        header_value(response_headers, "content-encoding")
            .is_none_or(|encoding| encoding.eq_ignore_ascii_case("identity"))
    }

    fn primary_server(&self) -> Option<&McpServerConfig> {
        self.servers.get(&self.primary_server_id)
    }

    fn session_is_expired(&self, session: &DownstreamMcpSession) -> bool {
        session.last_seen.elapsed() >= self.sessions.session_ttl
    }

    async fn touch_downstream_session(
        &self,
        downstream_session_id: &str,
        ctx: &RequestContext,
    ) -> bool {
        let expired = self
            .session_store
            .get(downstream_session_id)
            .is_some_and(|session| self.session_is_expired(&session));
        if expired {
            self.remove_downstream_session(downstream_session_id, ctx)
                .await;
            return false;
        }
        if let Some(mut session) = self.session_store.get_mut(downstream_session_id) {
            session.last_seen = Instant::now();
            true
        } else {
            false
        }
    }

    fn downstream_session_clone(
        &self,
        downstream_session_id: &str,
    ) -> Option<DownstreamMcpSession> {
        self.session_store
            .get(downstream_session_id)
            .map(|session| session.clone())
    }

    fn catalog_for_session(&self, downstream_session_id: &str) -> Option<Arc<RwLock<McpCatalog>>> {
        self.downstream_session_clone(downstream_session_id)
            .map(|session| session.catalog)
    }

    async fn require_live_downstream_session(
        &self,
        headers: &HashMap<String, String>,
        id: Option<Value>,
        ctx: &RequestContext,
    ) -> Result<String, PluginResult> {
        let Some(session_id) = self.downstream_session_id_from_headers(headers) else {
            // No session header at all: the client never initialized (or dropped
            // the header). Per MCP Streamable HTTP this is HTTP 400, distinct from
            // the 404 that signals a terminated/unknown session and prompts re-init.
            return Err(missing_session_response(id));
        };
        if !self.touch_downstream_session(&session_id, ctx).await {
            return Err(session_not_found_response());
        }
        Ok(session_id)
    }

    async fn create_downstream_session(
        &self,
        ctx: &RequestContext,
        protocol_version: String,
        client_info: Option<Value>,
        client_capabilities: Option<Value>,
    ) -> String {
        let downstream_session_id = uuid::Uuid::new_v4().to_string();

        // Enforce the cap and reclaim sessions atomically, but keep upstream
        // DELETE I/O *out* of the critical section. Under the admission lock we do
        // only the in-memory work — a single scan that partitions sessions into
        // expired (always reclaimed) and live (cap-eviction candidates), the
        // store removals, and the insert — so concurrent `initialize` calls can't
        // exceed `max_sessions` yet don't serialize behind each other's network
        // cleanup. The evicted sessions' upstream DELETEs are issued concurrently
        // after the lock is released.
        let evicted = {
            let _admission_guard = self.session_admission_lock.lock().await;

            let mut expired_keys: Vec<String> = Vec::new();
            let mut live: Vec<(Instant, String)> = Vec::new();
            for entry in self.session_store.iter() {
                if self.session_is_expired(entry.value()) {
                    expired_keys.push(entry.key().clone());
                } else {
                    live.push((entry.value().last_seen, entry.key().clone()));
                }
            }

            let mut evicted: Vec<DownstreamMcpSession> = Vec::new();
            for key in expired_keys {
                if let Some(session) = self.take_downstream_session(&key) {
                    evicted.push(session);
                }
            }

            // After reclaiming expired sessions, evict the oldest live sessions if
            // still at the cap so there is room for exactly one new session.
            let target = self.sessions.max_sessions.saturating_sub(1);
            if live.len() > target {
                let to_remove = live.len() - target;
                live.sort_unstable_by_key(|(last_seen, _)| *last_seen);
                for (_, key) in live.into_iter().take(to_remove) {
                    if let Some(session) = self.take_downstream_session(&key) {
                        evicted.push(session);
                    }
                }
            }

            let upstream_sessions = self
                .servers
                .values()
                .filter(|server| server.enabled)
                .map(|server| {
                    (
                        server.server_id.clone(),
                        UpstreamMcpSession {
                            server_id: server.server_id.clone(),
                            upstream_session_id: None,
                            protocol_version: None,
                            initialized: false,
                            init_lock: Arc::new(Mutex::new(())),
                        },
                    )
                })
                .collect();
            let catalog = Arc::new(RwLock::new(McpCatalog::default()));
            self.session_store.insert(
                downstream_session_id.clone(),
                DownstreamMcpSession {
                    downstream_session_id: downstream_session_id.clone(),
                    protocol_version,
                    client_info,
                    client_capabilities,
                    upstream_sessions,
                    catalog: Arc::clone(&catalog),
                    catalog_refresh_lock: Arc::new(Mutex::new(())),
                    last_seen: Instant::now(),
                },
            );
            self.session_catalogs_by_hash
                .insert(hash_str(&downstream_session_id), catalog);
            evicted
        };

        // Tear down evicted sessions' upstreams concurrently, outside the lock, so
        // eviction never serializes new sessions behind upstream DELETE round trips.
        if !evicted.is_empty() {
            futures_util::future::join_all(
                evicted
                    .into_iter()
                    .map(|session| self.delete_upstream_sessions(session, ctx)),
            )
            .await;
        }

        downstream_session_id
    }

    async fn ensure_upstream_initialized(
        &self,
        downstream_session_id: &str,
        server_id: &str,
        ctx: &RequestContext,
    ) -> Result<Option<String>, String> {
        let server = self
            .servers
            .get(server_id)
            .ok_or_else(|| format!("unknown MCP upstream server {server_id:?}"))?;
        if server.initialize_strategy == InitializeStrategy::Passthrough {
            return Ok(None);
        }
        // Per-(session, server) lock: only the same upstream session serializes
        // here, so concurrent first-touch of different sessions/servers proceeds
        // in parallel and a slow upstream does not block unrelated initializes.
        let init_lock = self
            .downstream_session_clone(downstream_session_id)
            .and_then(|session| {
                session
                    .upstream_sessions
                    .get(server_id)
                    .map(|upstream| Arc::clone(&upstream.init_lock))
            })
            .ok_or_else(|| "downstream MCP session is not initialized".to_string())?;
        let _guard = init_lock.lock().await;
        if let Some(upstream_session_id) = self
            .downstream_session_clone(downstream_session_id)
            .and_then(|session| {
                session
                    .upstream_sessions
                    .get(server_id)
                    .filter(|upstream| upstream.initialized)
                    .map(|upstream| upstream.upstream_session_id.clone())
            })
        {
            return Ok(upstream_session_id);
        }

        let session = self
            .downstream_session_clone(downstream_session_id)
            .ok_or_else(|| "downstream MCP session is not initialized".to_string())?;
        let body = json!({
            "jsonrpc": "2.0",
            "id": uuid::Uuid::new_v4().to_string(),
            "method": "initialize",
            "params": {
                "protocolVersion": session.protocol_version,
                "capabilities": session.client_capabilities.unwrap_or_else(|| json!({})),
                "clientInfo": session.client_info.unwrap_or_else(|| json!({
                    "name": "ferrum-mcp-gateway",
                    "version": env!("CARGO_PKG_VERSION")
                })),
            }
        });
        let request = self
            .http_client
            .get()
            .post(&server.upstream_url)
            .header("content-type", "application/json")
            .header("accept", MCP_STREAMABLE_HTTP_ACCEPT)
            .header(
                "mcp-protocol-version",
                self.protocol_version_for_session(downstream_session_id),
            )
            .json(&body);
        let response = self
            .http_client
            .execute_tracked(request, "mcp_gateway.initialize", &ctx.plugin_http_call_ns)
            .await
            .map_err(|error| {
                warn!(
                    server_id = %server.server_id,
                    method = "initialize",
                    error = %error,
                    "MCP upstream initialize request failed"
                );
                format!("failed to initialize upstream MCP server: {error}")
            })?;
        if !response.status().is_success() {
            warn!(
                server_id = %server.server_id,
                method = "initialize",
                status = %response.status(),
                "MCP upstream initialize returned non-success status"
            );
            return Err(format!(
                "upstream MCP initialize returned HTTP {}",
                response.status()
            ));
        }
        let upstream_session_id = response
            .headers()
            .get(&self.sessions.upstream_session_header)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let response_body = upstream_response_json(
            response,
            &server.server_id,
            "initialize",
            self.validation.max_upstream_response_bytes,
        )
        .await?;
        if let Some(error) = response_body.get("error") {
            let error_code = error.get("code").and_then(Value::as_i64);
            let error_message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown MCP JSON-RPC error");
            warn!(
                server_id = %server.server_id,
                method = "initialize",
                error_code,
                error_message = %error_message,
                "MCP upstream initialize returned JSON-RPC error"
            );
            return Err("upstream MCP initialize returned JSON-RPC error".to_string());
        }
        if response_body.get("result").is_none() {
            warn!(
                server_id = %server.server_id,
                method = "initialize",
                "MCP upstream initialize response missing result"
            );
            return Err("upstream MCP initialize response missing result".to_string());
        }
        let negotiated_protocol_version = response_body
            .get("result")
            .and_then(|result| result.get("protocolVersion"))
            .and_then(Value::as_str)
            .unwrap_or(session.protocol_version.as_str())
            .to_string();
        if !self
            .supported_protocol_versions
            .iter()
            .any(|supported| supported == &negotiated_protocol_version)
        {
            warn!(
                server_id = %server.server_id,
                method = "initialize",
                protocol_version = %negotiated_protocol_version,
                "MCP upstream initialize negotiated unsupported protocol version"
            );
            return Err(format!(
                "upstream MCP initialize negotiated unsupported protocol version {negotiated_protocol_version}"
            ));
        }

        self.send_upstream_initialized_notification(
            ctx,
            server,
            &negotiated_protocol_version,
            upstream_session_id.as_deref(),
        )
        .await?;

        if let Some(mut session) = self.session_store.get_mut(downstream_session_id) {
            session.last_seen = Instant::now();
            if let Some(upstream) = session.upstream_sessions.get_mut(server_id) {
                upstream.initialized = true;
                upstream.upstream_session_id = upstream_session_id.clone();
                upstream.protocol_version = Some(negotiated_protocol_version);
            }
        }
        Ok(upstream_session_id)
    }

    async fn send_upstream_initialized_notification(
        &self,
        ctx: &RequestContext,
        server: &McpServerConfig,
        protocol_version: &str,
        upstream_session_id: Option<&str>,
    ) -> Result<(), String> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        });
        let mut request = self
            .http_client
            .get()
            .post(&server.upstream_url)
            .header("content-type", "application/json")
            .header("accept", MCP_STREAMABLE_HTTP_ACCEPT)
            .header("mcp-protocol-version", protocol_version);
        if let Some(session_id) = upstream_session_id {
            request = request.header(&self.sessions.upstream_session_header, session_id);
        }
        let response = self
            .http_client
            .execute_tracked(
                request.json(&body),
                "mcp_gateway.initialized_notification",
                &ctx.plugin_http_call_ns,
            )
            .await
            .map_err(|error| {
                warn!(
                    server_id = %server.server_id,
                    method = "notifications/initialized",
                    error = %error,
                    "MCP upstream initialized notification failed"
                );
                format!("failed to send upstream MCP initialized notification: {error}")
            })?;
        if !response.status().is_success() {
            warn!(
                server_id = %server.server_id,
                method = "notifications/initialized",
                status = %response.status(),
                "MCP upstream initialized notification returned non-success status"
            );
            return Err(format!(
                "upstream MCP initialized notification returned HTTP {}",
                response.status()
            ));
        }
        Ok(())
    }

    /// The gateway's preferred protocol version: the first configured entry in
    /// `endpoint.protocol_versions`. This is the version negotiated on
    /// `initialize` when the client requests an unsupported version and the
    /// default whenever no session version is known. Indexing is safe: config
    /// validation rejects an empty `protocol_versions` list.
    fn preferred_protocol_version(&self) -> &str {
        &self.supported_protocol_versions[0]
    }

    fn protocol_version_for_session(&self, downstream_session_id: &str) -> String {
        self.downstream_session_clone(downstream_session_id)
            .map(|session| session.protocol_version.clone())
            .unwrap_or_else(|| self.preferred_protocol_version().to_string())
    }

    fn protocol_version_for_upstream(
        &self,
        downstream_session_id: &str,
        server_id: &str,
    ) -> String {
        self.downstream_session_clone(downstream_session_id)
            .and_then(|session| {
                session
                    .upstream_sessions
                    .get(server_id)
                    .and_then(|upstream| upstream.protocol_version.clone())
                    .or(Some(session.protocol_version))
            })
            .unwrap_or_else(|| self.preferred_protocol_version().to_string())
    }

    /// Remove a session from the store without any upstream I/O. Splitting the
    /// store removal from the upstream `DELETE` lets eviction take sessions under
    /// the admission lock and issue the network cleanup after releasing it.
    fn take_downstream_session(&self, downstream_session_id: &str) -> Option<DownstreamMcpSession> {
        let session = self
            .session_store
            .remove(downstream_session_id)
            .map(|(_, session)| session);
        if session.is_some() {
            self.session_catalogs_by_hash
                .remove(&hash_str(downstream_session_id));
        }
        session
    }

    /// Issue the upstream `DELETE` for each initialized upstream session of an
    /// already-removed downstream session. Failures are logged, not fatal.
    async fn delete_upstream_sessions(&self, session: DownstreamMcpSession, ctx: &RequestContext) {
        for (server_id, upstream) in session.upstream_sessions {
            let Some(upstream_session_id) = upstream.upstream_session_id.clone() else {
                continue;
            };
            if !upstream.initialized {
                continue;
            }
            let Some(server) = self.servers.get(&server_id) else {
                continue;
            };
            let request = self
                .http_client
                .get()
                .delete(&server.upstream_url)
                .header(&self.sessions.upstream_session_header, upstream_session_id)
                .header(
                    "mcp-protocol-version",
                    upstream
                        .protocol_version
                        .as_deref()
                        .unwrap_or(session.protocol_version.as_str()),
                );
            match self
                .http_client
                .execute_tracked(
                    request,
                    "mcp_gateway.session_delete",
                    &ctx.plugin_http_call_ns,
                )
                .await
            {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => {
                    warn!(
                        server_id = %server.server_id,
                        status = %response.status(),
                        "MCP upstream session delete returned non-success status"
                    );
                }
                Err(error) => {
                    warn!(
                        server_id = %server.server_id,
                        error = %error,
                        "MCP upstream session delete failed"
                    );
                }
            }
        }
    }

    async fn remove_downstream_session(
        &self,
        downstream_session_id: &str,
        ctx: &RequestContext,
    ) -> bool {
        let Some(session) = self.take_downstream_session(downstream_session_id) else {
            return false;
        };
        self.delete_upstream_sessions(session, ctx).await;
        true
    }

    async fn request_upstream_json(
        &self,
        ctx: &RequestContext,
        downstream_session_id: &str,
        server: &McpServerConfig,
        method: &str,
        params: Value,
    ) -> Result<Value, String> {
        let upstream_session_id = self
            .ensure_upstream_initialized(downstream_session_id, &server.server_id, ctx)
            .await?;
        let body = json!({
            "jsonrpc": "2.0",
            "id": uuid::Uuid::new_v4().to_string(),
            "method": method,
            "params": params,
        });
        let mut request = self
            .http_client
            .get()
            .post(&server.upstream_url)
            .header("content-type", "application/json")
            .header("accept", MCP_STREAMABLE_HTTP_ACCEPT)
            .header(
                "mcp-protocol-version",
                self.protocol_version_for_upstream(downstream_session_id, &server.server_id),
            );
        if let Some(session_id) = upstream_session_id {
            request = request.header(&self.sessions.upstream_session_header, session_id);
        }
        let response = self
            .http_client
            .execute_tracked(
                request.json(&body),
                "mcp_gateway.discovery",
                &ctx.plugin_http_call_ns,
            )
            .await
            .map_err(|error| {
                warn!(
                    server_id = %server.server_id,
                    method,
                    error = %error,
                    "MCP upstream request failed"
                );
                format!("upstream MCP request failed: {error}")
            })?;
        if !response.status().is_success() {
            warn!(
                server_id = %server.server_id,
                method,
                status = %response.status(),
                "MCP upstream request returned non-success status"
            );
            return Err(format!(
                "upstream MCP request returned HTTP {}",
                response.status()
            ));
        }
        let response_body = upstream_response_json(
            response,
            &server.server_id,
            method,
            self.validation.max_upstream_response_bytes,
        )
        .await?;
        if let Some(error) = response_body.get("error") {
            let error_code = error.get("code").and_then(Value::as_i64);
            let error_message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown MCP JSON-RPC error");
            warn!(
                server_id = %server.server_id,
                method,
                error_code,
                error_message = %error_message,
                "MCP upstream returned JSON-RPC error"
            );
            return Err(format!("upstream MCP {method} returned JSON-RPC error"));
        }
        Ok(response_body)
    }

    async fn request_upstream_list_pages(
        &self,
        ctx: &RequestContext,
        downstream_session_id: &str,
        server: &McpServerConfig,
        method: &str,
        result_key: &str,
    ) -> Result<Vec<Value>, String> {
        let mut items = Vec::new();
        let mut total_item_bytes = 0usize;
        let max_items = self.validation.max_catalog_items_per_list;
        let max_bytes = self.validation.max_catalog_bytes_per_list;
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_MCP_PAGINATION_PAGES {
            let params = match cursor.as_deref() {
                Some(cursor) => json!({ "cursor": cursor }),
                None => json!({}),
            };
            let response = self
                .request_upstream_json(ctx, downstream_session_id, server, method, params)
                .await?;
            let result = response
                .get("result")
                .and_then(Value::as_object)
                .ok_or_else(|| format!("upstream MCP {method} response missing result"))?;
            let page_items = result
                .get(result_key)
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    format!("upstream MCP {method} response missing result.{result_key}")
                })?;
            for item in page_items {
                if items.len() >= max_items {
                    warn!(
                        server_id = %server.server_id,
                        method,
                        max_items,
                        "MCP upstream catalog item count exceeded limit"
                    );
                    return Err(format!(
                        "upstream MCP {method} catalog exceeded {max_items} items"
                    ));
                }
                let item_bytes = serde_json::to_vec(item).map_err(|error| {
                    warn!(
                        server_id = %server.server_id,
                        method,
                        error = %error,
                        "MCP upstream catalog item could not be measured"
                    );
                    format!("upstream MCP {method} catalog item could not be measured: {error}")
                })?;
                if total_item_bytes.saturating_add(item_bytes.len()) > max_bytes {
                    warn!(
                        server_id = %server.server_id,
                        method,
                        max_bytes,
                        "MCP upstream catalog item bytes exceeded limit"
                    );
                    return Err(format!(
                        "upstream MCP {method} catalog exceeded {max_bytes} bytes"
                    ));
                }
                total_item_bytes += item_bytes.len();
                items.push(item.clone());
            }
            cursor = result
                .get("nextCursor")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            if cursor.is_none() {
                return Ok(items);
            }
        }
        warn!(
            server_id = %server.server_id,
            method,
            max_pages = MAX_MCP_PAGINATION_PAGES,
            "MCP upstream pagination exceeded maximum page count"
        );
        Err(format!(
            "upstream MCP {method} pagination exceeded {MAX_MCP_PAGINATION_PAGES} pages"
        ))
    }

    async fn ensure_catalog(
        &self,
        ctx: &RequestContext,
        downstream_session_id: &str,
    ) -> Result<(), McpCatalogError> {
        let session = self
            .downstream_session_clone(downstream_session_id)
            .ok_or(McpCatalogError::SessionNotFound)?;
        let catalog_lock = &session.catalog;
        {
            let catalog = catalog_lock.read().await;
            if !catalog.is_stale(self.discovery.cache_ttl) {
                return Ok(());
            }
        }
        let _guard = session.catalog_refresh_lock.lock().await;
        {
            let catalog = catalog_lock.read().await;
            if !catalog.is_stale(self.discovery.cache_ttl) {
                return Ok(());
            }
        }
        self.refresh_catalog(ctx, downstream_session_id, catalog_lock)
            .await
            .map_err(McpCatalogError::Refresh)
    }

    async fn ensure_resource_templates(
        &self,
        ctx: &RequestContext,
        downstream_session_id: &str,
    ) -> Result<(), McpCatalogError> {
        let session = self
            .downstream_session_clone(downstream_session_id)
            .ok_or(McpCatalogError::SessionNotFound)?;
        let catalog_lock = &session.catalog;
        {
            let catalog = catalog_lock.read().await;
            if !catalog.resource_templates_are_stale(self.discovery.cache_ttl) {
                return Ok(());
            }
        }
        let _guard = session.catalog_refresh_lock.lock().await;
        {
            let catalog = catalog_lock.read().await;
            if !catalog.resource_templates_are_stale(self.discovery.cache_ttl) {
                return Ok(());
            }
        }
        self.refresh_resource_templates(ctx, downstream_session_id, catalog_lock)
            .await
            .map_err(McpCatalogError::Refresh)
    }

    async fn prepare_response_resource_bindings(
        &self,
        ctx: &RequestContext,
        downstream_session_id: &str,
        server_id: &str,
    ) {
        if !self.resource_response_rewrite_possible(server_id) {
            return;
        }
        let Some(session) = self.downstream_session_clone(downstream_session_id) else {
            return;
        };
        {
            let catalog = session.catalog.read().await;
            if catalog
                .resource_templates_last_attempted_at
                .get(server_id)
                .is_some_and(|attempted| attempted.elapsed() < self.discovery.cache_ttl)
            {
                return;
            }
        }
        let _guard = session.catalog_refresh_lock.lock().await;
        {
            let mut catalog = session.catalog.write().await;
            if catalog
                .resource_templates_last_attempted_at
                .get(server_id)
                .is_some_and(|attempted| attempted.elapsed() < self.discovery.cache_ttl)
            {
                return;
            }
            // Record the attempt before network I/O so concurrent tool/prompt
            // calls do not stampede an upstream that does not implement
            // resources/templates/list. Explicit template-list requests still
            // use ensure_resource_templates and surface refresh failures.
            catalog
                .resource_templates_last_attempted_at
                .insert(server_id.to_string(), Instant::now());
        }
        if let Err(error) = self
            .refresh_resource_templates_for_server(
                ctx,
                downstream_session_id,
                server_id,
                &session.catalog,
            )
            .await
        {
            warn!(
                error = %error,
                "MCP resource templates unavailable for response reverse mapping"
            );
        }
    }

    async fn refresh_catalog(
        &self,
        ctx: &RequestContext,
        downstream_session_id: &str,
        catalog_lock: &Arc<RwLock<McpCatalog>>,
    ) -> Result<(), String> {
        let old_catalog = catalog_lock.read().await.clone();
        let mut tools = HashMap::new();
        let mut prompts = HashMap::new();
        let mut resources = HashMap::new();
        let mut collision_tombstones = CatalogCollisionTombstones::default();
        // A single unavailable upstream must not abort the whole refresh: each
        // failed `*/list` keeps that (server, family)'s last-good entries stale
        // and is recorded as degraded, while other upstreams and families
        // refresh normally. Only iterated (enabled + exposed) servers can carry
        // entries forward, so disabled/removed/unexposed servers still drop out.
        // Availability is accounted per catalog family so a healthy family can
        // never mask another family's total outage.
        let mut degraded: Vec<(String, &'static str)> = Vec::new();
        let mut last_good: BTreeSet<(String, &'static str)> = BTreeSet::new();
        let mut families: BTreeMap<&'static str, FamilyRefreshStats> = BTreeMap::new();
        let discovered_at = Utc::now();

        for server in self.servers.values().filter(|server| server.enabled) {
            if self.discovery.aggregate_tools && server.expose_tools {
                match self
                    .request_upstream_list_pages(
                        ctx,
                        downstream_session_id,
                        server,
                        "tools/list",
                        "tools",
                    )
                    .await
                {
                    Ok(items) => {
                        families.entry("tools").or_default().record_success();
                        last_good.insert((server.server_id.clone(), "tools"));
                        for item in items {
                            if let Some(entry) = self.tool_entry_from_value(
                                server,
                                item,
                                discovered_at,
                                &old_catalog,
                            ) {
                                let public_name = entry.public_name.clone();
                                insert_catalog_entry(
                                    &mut tools,
                                    &mut collision_tombstones.tools,
                                    public_name,
                                    entry,
                                    &server.server_id,
                                    "tool",
                                );
                            }
                        }
                    }
                    Err(_) => {
                        let had_last_good = old_catalog
                            .last_good
                            .contains(&(server.server_id.clone(), "tools"));
                        if had_last_good {
                            last_good.insert((server.server_id.clone(), "tools"));
                        }
                        families
                            .entry("tools")
                            .or_default()
                            .record_failure(had_last_good);
                        carry_stale_entries(
                            &old_catalog.tools,
                            &mut tools,
                            &mut collision_tombstones.tools,
                            |entry| entry.server_id == server.server_id,
                            &server.server_id,
                            "tool",
                        );
                        degraded.push((server.server_id.clone(), "tools"));
                    }
                }
            }
            if self.discovery.aggregate_prompts && server.expose_prompts {
                match self
                    .request_upstream_list_pages(
                        ctx,
                        downstream_session_id,
                        server,
                        "prompts/list",
                        "prompts",
                    )
                    .await
                {
                    Ok(items) => {
                        families.entry("prompts").or_default().record_success();
                        last_good.insert((server.server_id.clone(), "prompts"));
                        for item in items {
                            if let Some(entry) =
                                self.prompt_entry_from_value(server, item, discovered_at)
                            {
                                let public_name = entry.public_name.clone();
                                insert_catalog_entry(
                                    &mut prompts,
                                    &mut collision_tombstones.prompts,
                                    public_name,
                                    entry,
                                    &server.server_id,
                                    "prompt",
                                );
                            }
                        }
                    }
                    Err(_) => {
                        let had_last_good = old_catalog
                            .last_good
                            .contains(&(server.server_id.clone(), "prompts"));
                        if had_last_good {
                            last_good.insert((server.server_id.clone(), "prompts"));
                        }
                        families
                            .entry("prompts")
                            .or_default()
                            .record_failure(had_last_good);
                        carry_stale_entries(
                            &old_catalog.prompts,
                            &mut prompts,
                            &mut collision_tombstones.prompts,
                            |entry| entry.server_id == server.server_id,
                            &server.server_id,
                            "prompt",
                        );
                        degraded.push((server.server_id.clone(), "prompts"));
                    }
                }
            }
            if self.discovery.aggregate_resources && server.expose_resources {
                match self
                    .request_upstream_list_pages(
                        ctx,
                        downstream_session_id,
                        server,
                        "resources/list",
                        "resources",
                    )
                    .await
                {
                    Ok(items) => {
                        families.entry("resources").or_default().record_success();
                        last_good.insert((server.server_id.clone(), "resources"));
                        for item in items {
                            if let Some(entry) =
                                self.resource_entry_from_value(server, item, discovered_at)
                            {
                                let public_uri = entry.public_uri.clone();
                                insert_catalog_entry(
                                    &mut resources,
                                    &mut collision_tombstones.resources,
                                    public_uri,
                                    entry,
                                    &server.server_id,
                                    "resource",
                                );
                            }
                        }
                    }
                    Err(_) => {
                        let had_last_good = old_catalog
                            .last_good
                            .contains(&(server.server_id.clone(), "resources"));
                        if had_last_good {
                            last_good.insert((server.server_id.clone(), "resources"));
                        }
                        families
                            .entry("resources")
                            .or_default()
                            .record_failure(had_last_good);
                        carry_stale_entries(
                            &old_catalog.resources,
                            &mut resources,
                            &mut collision_tombstones.resources,
                            |entry| entry.server_id == server.server_id,
                            &server.server_id,
                            "resource",
                        );
                        degraded.push((server.server_id.clone(), "resources"));
                    }
                }
            }
        }

        // A degraded family is not authoritative evidence that a prior
        // collision disappeared: the failed upstream may still expose the
        // colliding key. Reapply old tombstones after merging fresh and stale
        // entries, and clear them only when every attempted upstream for that
        // family listed successfully. Resource keys use a server-id-qualified
        // URI and cannot collide across servers, but retaining their defensive
        // duplicate-key tombstones here keeps all collision-checked maps on the
        // same fail-closed lifecycle.
        let mut collision_tombstone_overflow = BTreeSet::new();
        let tools_tombstone_limit = family_collision_tombstone_limit(
            families.get("tools"),
            self.validation.max_catalog_items_per_list,
        );
        if reconcile_collision_tombstones(
            &old_catalog.collision_tombstones.tools,
            &mut collision_tombstones.tools,
            &mut tools,
            families.get("tools"),
            tools_tombstone_limit,
            old_catalog.collision_tombstone_overflow.contains("tools"),
        ) {
            warn!(
                family = "tools",
                max_tombstones = tools_tombstone_limit,
                "MCP catalog collision history exceeded bounded retention; failing family closed until an authoritative refresh"
            );
            collision_tombstone_overflow.insert("tools");
        }
        let prompts_tombstone_limit = family_collision_tombstone_limit(
            families.get("prompts"),
            self.validation.max_catalog_items_per_list,
        );
        if reconcile_collision_tombstones(
            &old_catalog.collision_tombstones.prompts,
            &mut collision_tombstones.prompts,
            &mut prompts,
            families.get("prompts"),
            prompts_tombstone_limit,
            old_catalog.collision_tombstone_overflow.contains("prompts"),
        ) {
            warn!(
                family = "prompts",
                max_tombstones = prompts_tombstone_limit,
                "MCP catalog collision history exceeded bounded retention; failing family closed until an authoritative refresh"
            );
            collision_tombstone_overflow.insert("prompts");
        }
        let resources_tombstone_limit = family_collision_tombstone_limit(
            families.get("resources"),
            self.validation.max_catalog_items_per_list,
        );
        if reconcile_collision_tombstones(
            &old_catalog.collision_tombstones.resources,
            &mut collision_tombstones.resources,
            &mut resources,
            families.get("resources"),
            resources_tombstone_limit,
            old_catalog
                .collision_tombstone_overflow
                .contains("resources"),
        ) {
            warn!(
                family = "resources",
                max_tombstones = resources_tombstone_limit,
                "MCP catalog collision history exceeded bounded retention; failing family closed until an authoritative refresh"
            );
            collision_tombstone_overflow.insert("resources");
        }

        // A fully unavailable family (every attempted list failed, no last-good
        // state anywhere in the family) must not be published as an empty
        // catalog: that would misreport a total family outage as
        // healthy-and-empty for the whole cache TTL. It is marked on the
        // catalog instead, and requests for that family surface -32006 while
        // healthy families keep serving.
        let unavailable: BTreeSet<&'static str> = families
            .iter()
            .filter(|(_, stats)| stats.fully_unavailable())
            .map(|(family, _)| *family)
            .collect();
        // Total outage with nothing to serve in any attempted family: keep the
        // catalog stale (the next request retries) and surface the refresh
        // error instead of publishing a misleading empty catalog. The
        // per-request warnings above already carry the failure detail.
        if !families.is_empty() && unavailable.len() == families.len() {
            let attempted_lists: usize = families.values().map(|stats| stats.attempted).sum();
            return Err(format!(
                "all {attempted_lists} MCP upstream catalog list requests failed"
            ));
        }
        for (server_id, family) in &degraded {
            warn!(
                server_id = %server_id,
                family,
                "MCP upstream catalog list failed; retaining last-good family state when available"
            );
        }

        let mut catalog = catalog_lock.write().await;
        let changed = catalog.tools.keys().collect::<HashSet<_>>() != tools.keys().collect()
            || catalog.prompts.keys().collect::<HashSet<_>>() != prompts.keys().collect()
            || catalog.resources.keys().collect::<HashSet<_>>() != resources.keys().collect()
            || catalog.tools.iter().any(|(name, old)| {
                tools
                    .get(name)
                    .is_some_and(|new| new.schema_hash != old.schema_hash)
            });
        catalog.tools = tools;
        catalog.prompts = prompts;
        catalog.resources = resources;
        catalog
            .degraded
            .retain(|(_, family)| *family == "resource_templates");
        catalog.degraded.extend(degraded);
        catalog
            .last_good
            .retain(|(_, family)| *family == "resource_templates");
        catalog.last_good.extend(last_good);
        catalog
            .unavailable
            .retain(|family| *family == "resource_templates");
        catalog.unavailable.extend(unavailable);
        catalog.collision_tombstones = collision_tombstones;
        catalog.collision_tombstone_overflow = collision_tombstone_overflow;
        if changed || catalog.version == 0 {
            catalog.version = catalog.version.saturating_add(1);
        }
        catalog.last_refreshed_at = Some(Instant::now());
        catalog.last_refreshed_wall = discovered_at;
        Ok(())
    }

    async fn refresh_resource_templates(
        &self,
        ctx: &RequestContext,
        downstream_session_id: &str,
        catalog_lock: &Arc<RwLock<McpCatalog>>,
    ) -> Result<(), String> {
        let old_catalog = catalog_lock.read().await.clone();
        let mut resource_templates = HashMap::new();
        // Same per-upstream degradation policy as refresh_catalog: a failing
        // upstream keeps its last-good templates stale instead of aborting the
        // refresh for every other upstream. Public template URIs are prefixed
        // with the server id, so carried entries cannot collide across servers.
        let mut degraded: Vec<String> = Vec::new();
        let mut last_good: BTreeSet<(String, &'static str)> = BTreeSet::new();
        let mut stats = FamilyRefreshStats::default();
        let discovered_at = Utc::now();

        if self.discovery.aggregate_resources {
            for server in self
                .servers
                .values()
                .filter(|server| server.enabled && server.expose_resources)
            {
                match self
                    .request_upstream_list_pages(
                        ctx,
                        downstream_session_id,
                        server,
                        "resources/templates/list",
                        "resourceTemplates",
                    )
                    .await
                {
                    Ok(items) => {
                        stats.record_success();
                        last_good.insert((server.server_id.clone(), "resource_templates"));
                        for item in items {
                            if let Some(entry) =
                                self.resource_template_entry_from_value(server, item, discovered_at)
                            {
                                resource_templates.insert(entry.public_uri_template.clone(), entry);
                            }
                        }
                    }
                    Err(_) => {
                        let had_last_good = old_catalog
                            .last_good
                            .contains(&(server.server_id.clone(), "resource_templates"));
                        if had_last_good {
                            last_good.insert((server.server_id.clone(), "resource_templates"));
                        }
                        stats.record_failure(had_last_good);
                        for (public_uri_template, entry) in &old_catalog.resource_templates {
                            if entry.server_id != server.server_id {
                                continue;
                            }
                            resource_templates.insert(public_uri_template.clone(), entry.clone());
                        }
                        warn!(
                            server_id = %server.server_id,
                            family = "resource_templates",
                            "MCP upstream catalog list failed; retaining last-good family state when available"
                        );
                        degraded.push(server.server_id.clone());
                    }
                }
            }
        }

        // Total template outage with no last-good state (a prior successful —
        // possibly empty — list): keep the template catalog stale so the next
        // request retries, and surface -32006 instead of publishing an empty
        // template catalog.
        if stats.fully_unavailable() {
            return Err(format!(
                "all {attempted} MCP upstream resource template list requests failed",
                attempted = stats.attempted
            ));
        }

        let mut catalog = catalog_lock.write().await;
        let changed = catalog.resource_templates.keys().collect::<HashSet<_>>()
            != resource_templates.keys().collect();
        catalog.resource_templates = resource_templates;
        catalog
            .degraded
            .retain(|(_, family)| *family != "resource_templates");
        catalog.degraded.extend(
            degraded
                .into_iter()
                .map(|server_id| (server_id, "resource_templates")),
        );
        catalog
            .last_good
            .retain(|(_, family)| *family != "resource_templates");
        catalog.last_good.extend(last_good);
        if changed || catalog.version == 0 {
            catalog.version = catalog.version.saturating_add(1);
        }
        catalog.resource_templates_refreshed_at = Some(Instant::now());
        let attempted_at = catalog.resource_templates_refreshed_at;
        for server in self
            .servers
            .values()
            .filter(|server| server.enabled && server.expose_resources)
        {
            if let Some(attempted_at) = attempted_at {
                catalog
                    .resource_templates_last_attempted_at
                    .insert(server.server_id.clone(), attempted_at);
            }
        }
        catalog.last_refreshed_wall = discovered_at;
        Ok(())
    }

    async fn refresh_resource_templates_for_server(
        &self,
        ctx: &RequestContext,
        downstream_session_id: &str,
        server_id: &str,
        catalog_lock: &Arc<RwLock<McpCatalog>>,
    ) -> Result<(), String> {
        let server = self
            .servers
            .get(server_id)
            .filter(|server| server.enabled && server.expose_resources)
            .ok_or_else(|| format!("unknown or disabled MCP resource server {server_id:?}"))?;
        let items = match self
            .request_upstream_list_pages(
                ctx,
                downstream_session_id,
                server,
                "resources/templates/list",
                "resourceTemplates",
            )
            .await
        {
            Ok(items) => items,
            Err(error) => {
                let mut catalog = catalog_lock.write().await;
                catalog
                    .degraded
                    .insert((server_id.to_string(), "resource_templates"));
                return Err(error);
            }
        };
        let discovered_at = Utc::now();
        let mut resource_templates = HashMap::new();
        for item in items {
            if let Some(entry) =
                self.resource_template_entry_from_value(server, item, discovered_at)
            {
                resource_templates.insert(entry.public_uri_template.clone(), entry);
            }
        }

        let mut catalog = catalog_lock.write().await;
        let old_keys = catalog
            .resource_templates
            .iter()
            .filter(|(_, entry)| entry.server_id == server_id)
            .map(|(public_uri, _)| public_uri)
            .collect::<HashSet<_>>();
        let changed = old_keys != resource_templates.keys().collect::<HashSet<_>>();
        catalog
            .resource_templates
            .retain(|_, entry| entry.server_id != server_id);
        catalog.resource_templates.extend(resource_templates);
        catalog
            .degraded
            .remove(&(server_id.to_string(), "resource_templates"));
        catalog
            .last_good
            .insert((server_id.to_string(), "resource_templates"));
        if changed || catalog.version == 0 {
            catalog.version = catalog.version.saturating_add(1);
        }
        catalog.last_refreshed_wall = discovered_at;
        Ok(())
    }

    fn tool_entry_from_value(
        &self,
        server: &McpServerConfig,
        item: Value,
        discovered_at: DateTime<Utc>,
        old_catalog: &McpCatalog,
    ) -> Option<ToolCatalogEntry> {
        let name = item.get("name")?.as_str()?.to_string();
        let public_name = namespaced(
            &server.namespace,
            &self.discovery.namespace_separator,
            &name,
        );
        let input_schema = item
            .get("inputSchema")
            .cloned()
            .unwrap_or_else(|| json!({"type": "object"}));
        let schema_hash = hash_value(&input_schema);
        let input_validator = match jsonschema::validator_for(&input_schema) {
            Ok(validator) => Arc::new(validator),
            Err(error) => {
                warn!(
                    server_id = %server.server_id,
                    tool = %name,
                    error = %error,
                    "Skipping MCP tool with invalid inputSchema"
                );
                return None;
            }
        };
        let description = item
            .get("description")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let description_hash = hash_value(&Value::String(description.clone().unwrap_or_default()));
        let policy_action = self.policy.action_for_tool(&public_name);
        let explicitly_configured = self.policy.tools.contains_key(&public_name);
        let schema_changed = old_catalog
            .tools
            .get(&public_name)
            .is_some_and(|old| old.schema_hash != schema_hash);
        let previously_hidden_by_discovery = old_catalog
            .tools
            .get(&public_name)
            .is_some_and(|old| old.hidden_by_discovery);
        let new_tool = !old_catalog.tools.contains_key(&public_name);
        // Schema-change hiding must persist across refreshes (the changed schema
        // becomes the new baseline, so `schema_changed` is only true on the first
        // refresh after the drift). Carry it forward stickily so the gate is not
        // lifted on the next refresh. This is what keeps explicitly-configured
        // tools hidden too: they can only become hidden via schema change (the
        // new-tool gate below exempts configured tools), so retaining their hidden
        // state here never traps a freshly-configured tool.
        let previously_hidden_by_schema_change = old_catalog
            .tools
            .get(&public_name)
            .is_some_and(|old| old.hidden_by_schema_change);
        let hidden_by_schema_change = previously_hidden_by_schema_change
            || (schema_changed
                && self.discovery.on_schema_change == DiscoveryBehavior::HideUntilConfigured);
        let hidden_by_discovery = (previously_hidden_by_discovery && !explicitly_configured)
            || (new_tool
                && self.discovery.on_new_tool == DiscoveryBehavior::HideUntilConfigured
                && !explicitly_configured)
            || hidden_by_schema_change;
        let hidden_from_discovery =
            hidden_by_discovery || policy_action == PolicyAction::HideFromDiscovery;
        let enabled = policy_action == PolicyAction::Allow && !hidden_by_discovery;
        Some(ToolCatalogEntry {
            public_name,
            upstream_name: name,
            server_id: server.server_id.clone(),
            namespace: server.namespace.clone(),
            input_schema,
            output_schema: item.get("outputSchema").cloned(),
            title: item
                .get("title")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            description,
            annotations: item.get("annotations").cloned(),
            enabled,
            hidden_by_discovery,
            hidden_from_discovery,
            hidden_by_schema_change,
            input_validator,
            discovered_at,
            schema_hash,
            description_hash,
        })
    }

    fn prompt_entry_from_value(
        &self,
        server: &McpServerConfig,
        item: Value,
        discovered_at: DateTime<Utc>,
    ) -> Option<PromptCatalogEntry> {
        let name = item.get("name")?.as_str()?.to_string();
        let public_name = namespaced(
            &server.namespace,
            &self.discovery.namespace_separator,
            &name,
        );
        let arguments_schema = item.get("argumentsSchema").cloned();
        let schema_hash = hash_value(arguments_schema.as_ref().unwrap_or(&Value::Null));
        Some(PromptCatalogEntry {
            public_name,
            upstream_name: name,
            server_id: server.server_id.clone(),
            namespace: server.namespace.clone(),
            description: item
                .get("description")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            arguments_schema,
            enabled: true,
            discovered_at,
            schema_hash,
        })
    }

    fn resource_entry_from_value(
        &self,
        server: &McpServerConfig,
        item: Value,
        discovered_at: DateTime<Utc>,
    ) -> Option<ResourceCatalogEntry> {
        let upstream_uri = item.get("uri")?.as_str()?.to_string();
        let public_uri = public_resource_uri(&server.server_id, &upstream_uri);
        Some(ResourceCatalogEntry {
            uri_hash: hash_str(&upstream_uri),
            public_uri,
            upstream_uri,
            server_id: server.server_id.clone(),
            namespace: server.namespace.clone(),
            name: item
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            description: item
                .get("description")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            mime_type: item
                .get("mimeType")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            enabled: true,
            discovered_at,
        })
    }

    fn resource_template_entry_from_value(
        &self,
        server: &McpServerConfig,
        item: Value,
        discovered_at: DateTime<Utc>,
    ) -> Option<ResourceTemplateCatalogEntry> {
        let upstream_uri_template = item.get("uriTemplate")?.as_str()?.to_string();
        let uri_template_regex = match uri_template_regex(&upstream_uri_template) {
            Ok(regex) => Arc::new(regex),
            Err(error) => {
                warn!(
                    server_id = %server.server_id,
                    uri_template_hash = %hash_str(&upstream_uri_template),
                    error = %error,
                    "Skipping MCP resource template with invalid URI template"
                );
                return None;
            }
        };
        Some(ResourceTemplateCatalogEntry {
            public_uri_template: public_resource_template_uri(
                &server.server_id,
                &upstream_uri_template,
            ),
            server_id: server.server_id.clone(),
            namespace: server.namespace.clone(),
            name: item
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            title: item
                .get("title")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            description: item
                .get("description")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            mime_type: item
                .get("mimeType")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            annotations: item.get("annotations").cloned(),
            icons: item.get("icons").cloned(),
            enabled: true,
            discovered_at,
            uri_template_regex,
        })
    }

    fn synthetic_initialize_response(
        &self,
        envelope: &McpEnvelope,
        protocol_version: &str,
        downstream_session_id: &str,
    ) -> PluginResult {
        let mut capabilities = Map::new();
        if self.capabilities.advertise_tools {
            capabilities.insert("tools".to_string(), json!({"listChanged": true}));
        }
        if self.capabilities.advertise_resources {
            capabilities.insert("resources".to_string(), json!({"listChanged": true}));
        }
        if self.capabilities.advertise_prompts {
            capabilities.insert("prompts".to_string(), json!({"listChanged": true}));
        }
        if self.capabilities.advertise_logging {
            capabilities.insert("logging".to_string(), json!({}));
        }
        if self.capabilities.advertise_completions {
            capabilities.insert("completions".to_string(), json!({}));
        }
        if self.capabilities.advertise_tasks {
            capabilities.insert("tasks".to_string(), json!({}));
        }

        json_response(
            200,
            json!({
                "jsonrpc": "2.0",
                "id": envelope.id.clone().unwrap_or(Value::Null),
                "result": {
                    "protocolVersion": protocol_version,
                    "capabilities": Value::Object(capabilities),
                    "serverInfo": {
                        "name": "ferrum-mcp-gateway",
                        "title": "Ferrum MCP Gateway",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }
            }),
            Some((
                &self.sessions.downstream_session_header,
                downstream_session_id,
            )),
        )
    }

    async fn aggregate_tools_list(
        &self,
        ctx: &mut RequestContext,
        envelope: &McpEnvelope,
        downstream_session_id: &str,
    ) -> PluginResult {
        if let Err(error) = self.ensure_catalog(ctx, downstream_session_id).await {
            return catalog_error_response(envelope.id.clone(), "MCP catalog unavailable", error);
        }
        let Some(catalog_lock) = self.catalog_for_session(downstream_session_id) else {
            return session_not_found_response();
        };
        let catalog = catalog_lock.read().await;
        if self.observability.emit_metadata {
            ctx.metadata.insert(
                "mcp.route_decision".to_string(),
                "synthetic_response".to_string(),
            );
            ctx.metadata.insert(
                "mcp.catalog_version".to_string(),
                catalog.version.to_string(),
            );
        }
        self.emit_catalog_degraded_metadata(ctx, &catalog);
        if let Some(response) = family_unavailable_error(&catalog, "tools", envelope.id.clone()) {
            return response;
        }
        let tools: Vec<Value> = catalog
            .tools
            .values()
            .filter(|entry| {
                !entry.hidden_from_discovery
                    && (entry.enabled
                        || !(self.discovery.hide_denied_items || self.policy.hide_denied_tools))
            })
            .map(tool_entry_to_public_value)
            .collect();
        json_response(
            200,
            json!({
                "jsonrpc": "2.0",
                "id": envelope.id.clone().unwrap_or(Value::Null),
                "result": { "tools": tools }
            }),
            None,
        )
    }

    async fn aggregate_prompts_list(
        &self,
        ctx: &mut RequestContext,
        envelope: &McpEnvelope,
        downstream_session_id: &str,
    ) -> PluginResult {
        if let Err(error) = self.ensure_catalog(ctx, downstream_session_id).await {
            return catalog_error_response(envelope.id.clone(), "MCP catalog unavailable", error);
        }
        let Some(catalog_lock) = self.catalog_for_session(downstream_session_id) else {
            return session_not_found_response();
        };
        let catalog = catalog_lock.read().await;
        if self.observability.emit_metadata {
            ctx.metadata.insert(
                "mcp.route_decision".to_string(),
                "synthetic_response".to_string(),
            );
            ctx.metadata.insert(
                "mcp.catalog_version".to_string(),
                catalog.version.to_string(),
            );
        }
        self.emit_catalog_degraded_metadata(ctx, &catalog);
        if let Some(response) = family_unavailable_error(&catalog, "prompts", envelope.id.clone()) {
            return response;
        }
        let prompts: Vec<Value> = catalog
            .prompts
            .values()
            .filter(|entry| entry.enabled)
            .map(prompt_entry_to_public_value)
            .collect();
        json_response(
            200,
            json!({
                "jsonrpc": "2.0",
                "id": envelope.id.clone().unwrap_or(Value::Null),
                "result": { "prompts": prompts }
            }),
            None,
        )
    }

    async fn aggregate_resources_list(
        &self,
        ctx: &mut RequestContext,
        envelope: &McpEnvelope,
        downstream_session_id: &str,
    ) -> PluginResult {
        if let Err(error) = self.ensure_catalog(ctx, downstream_session_id).await {
            return catalog_error_response(envelope.id.clone(), "MCP catalog unavailable", error);
        }
        let Some(catalog_lock) = self.catalog_for_session(downstream_session_id) else {
            return session_not_found_response();
        };
        let catalog = catalog_lock.read().await;
        if self.observability.emit_metadata {
            ctx.metadata.insert(
                "mcp.route_decision".to_string(),
                "synthetic_response".to_string(),
            );
            ctx.metadata.insert(
                "mcp.catalog_version".to_string(),
                catalog.version.to_string(),
            );
        }
        self.emit_catalog_degraded_metadata(ctx, &catalog);
        if let Some(response) = family_unavailable_error(&catalog, "resources", envelope.id.clone())
        {
            return response;
        }
        let resources: Vec<Value> = catalog
            .resources
            .values()
            .filter(|entry| entry.enabled)
            .map(resource_entry_to_public_value)
            .collect();
        json_response(
            200,
            json!({
                "jsonrpc": "2.0",
                "id": envelope.id.clone().unwrap_or(Value::Null),
                "result": { "resources": resources }
            }),
            None,
        )
    }

    async fn aggregate_resource_templates_list(
        &self,
        ctx: &mut RequestContext,
        envelope: &McpEnvelope,
        downstream_session_id: &str,
    ) -> PluginResult {
        if let Err(error) = self
            .ensure_resource_templates(ctx, downstream_session_id)
            .await
        {
            return catalog_error_response(
                envelope.id.clone(),
                "MCP resource template catalog unavailable",
                error,
            );
        }
        let Some(catalog_lock) = self.catalog_for_session(downstream_session_id) else {
            return session_not_found_response();
        };
        let catalog = catalog_lock.read().await;
        let resource_templates: Vec<Value> = catalog
            .resource_templates
            .values()
            .filter(|entry| entry.enabled)
            .map(resource_template_entry_to_public_value)
            .collect();
        if self.observability.emit_metadata {
            ctx.metadata.insert(
                "mcp.route_decision".to_string(),
                "synthetic_response".to_string(),
            );
            ctx.metadata.insert(
                "mcp.catalog_version".to_string(),
                catalog.version.to_string(),
            );
        }
        self.emit_catalog_degraded_metadata(ctx, &catalog);
        json_response(
            200,
            json!({
                "jsonrpc": "2.0",
                "id": envelope.id.clone().unwrap_or(Value::Null),
                "result": { "resourceTemplates": resource_templates }
            }),
            None,
        )
    }

    async fn route_tool_call(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        envelope: &McpEnvelope,
        downstream_session_id: &str,
    ) -> PluginResult {
        // Defense-in-depth: aggregate batches classify `tools/call` before
        // dispatch, but keep this private guard ahead of catalog I/O so a
        // late path can never dial or refresh upstream discovery.
        if self.batch_forbids_upstream(ctx) {
            return PluginResult::Continue;
        }
        if let Err(error) = self.ensure_catalog(ctx, downstream_session_id).await {
            return catalog_error_response(envelope.id.clone(), "MCP catalog unavailable", error);
        }
        let public_name = match envelope
            .params
            .as_ref()
            .and_then(|params| params.get("name"))
            .and_then(Value::as_str)
        {
            Some(name) => name.to_string(),
            None => {
                return json_rpc_error(
                    envelope.id.clone(),
                    -32602,
                    "Invalid MCP tool call params",
                    None,
                );
            }
        };
        if self.observability.emit_metadata {
            ctx.metadata
                .insert("mcp.public_tool_name".to_string(), public_name.clone());
            ctx.metadata
                .insert("mcp.item_type".to_string(), "tool".to_string());
            ctx.metadata
                .insert("mcp.item_name".to_string(), public_name.clone());
        }
        let Some(catalog_lock) = self.catalog_for_session(downstream_session_id) else {
            return session_not_found_response();
        };
        let catalog = catalog_lock.read().await;
        self.emit_catalog_degraded_metadata(ctx, &catalog);
        if let Some(response) = family_unavailable_error(&catalog, "tools", envelope.id.clone()) {
            return response;
        }
        let Some(entry) = catalog.tools.get(&public_name).cloned() else {
            if self.observability.emit_metadata {
                ctx.metadata
                    .insert("mcp.catalog_hit".to_string(), "false".to_string());
                ctx.metadata
                    .insert("mcp.policy_decision".to_string(), "deny".to_string());
            }
            return json_rpc_error(envelope.id.clone(), -32003, "Unknown MCP tool", None);
        };
        drop(catalog);
        if self.observability.emit_metadata {
            ctx.metadata
                .insert("mcp.catalog_hit".to_string(), "true".to_string());
            ctx.metadata
                .insert("mcp.server_id".to_string(), entry.server_id.clone());
            ctx.metadata.insert(
                "mcp.upstream_tool_name".to_string(),
                entry.upstream_name.clone(),
            );
            ctx.metadata.insert(
                "mcp.input_schema_hash".to_string(),
                entry.schema_hash.clone(),
            );
        }
        let policy_action = self.policy.action_for_tool(&public_name);
        if policy_action != PolicyAction::Allow || !entry.enabled {
            if self.observability.emit_metadata {
                ctx.metadata.insert(
                    "mcp.policy_decision".to_string(),
                    policy_action.as_policy_decision().to_string(),
                );
                ctx.metadata
                    .insert("mcp.route_decision".to_string(), "deny".to_string());
            }
            return json_rpc_error(
                envelope.id.clone(),
                -32001,
                "MCP tool call denied by gateway policy",
                None,
            );
        }
        if self.observability.emit_metadata {
            ctx.metadata
                .insert("mcp.policy_decision".to_string(), "allow".to_string());
        }

        if self.validation.validate_tool_arguments {
            let empty_arguments;
            let arguments = match envelope
                .params
                .as_ref()
                .and_then(|params| params.get("arguments"))
            {
                Some(arguments) => arguments,
                None => {
                    empty_arguments = json!({});
                    &empty_arguments
                }
            };
            if self.observability.log_argument_hash {
                ctx.metadata
                    .insert("mcp.arguments_hash".to_string(), hash_value(arguments));
            }
            if self.observability.log_raw_arguments {
                ctx.metadata
                    .insert("mcp.arguments".to_string(), arguments.to_string());
            }
            match validate_json_schema(&entry.input_validator, arguments) {
                Ok(()) => {
                    if self.observability.emit_metadata {
                        ctx.metadata
                            .insert("mcp.schema_validation".to_string(), "pass".to_string());
                    }
                }
                Err(_) => {
                    if self.observability.emit_metadata {
                        ctx.metadata
                            .insert("mcp.schema_validation".to_string(), "fail".to_string());
                        ctx.metadata
                            .insert("mcp.route_decision".to_string(), "deny".to_string());
                    }
                    return json_rpc_error(
                        envelope.id.clone(),
                        -32602,
                        "Invalid MCP tool arguments",
                        None,
                    );
                }
            }
        }

        let Some(server) = self.servers.get(&entry.server_id) else {
            return json_rpc_error(
                envelope.id.clone(),
                -32002,
                "Unknown upstream MCP server",
                None,
            );
        };
        let response_resource_rewrite_possible =
            self.resource_response_rewrite_possible(&server.server_id);
        if response_resource_rewrite_possible {
            self.prepare_response_resource_bindings(ctx, downstream_session_id, &server.server_id)
                .await;
        }
        let Some(catalog_lock) = self.catalog_for_session(downstream_session_id) else {
            return session_not_found_response();
        };
        let catalog_version = catalog_lock.read().await.version;
        if let Err(error) = self
            .ensure_upstream_initialized(downstream_session_id, &server.server_id, ctx)
            .await
        {
            return json_rpc_error(
                envelope.id.clone(),
                -32005,
                "Upstream MCP session unavailable",
                Some(error),
            );
        }
        self.set_route_to_server(ctx, headers, server, Some(downstream_session_id));
        Self::mark_request_rewrite(
            ctx,
            headers,
            RequestRewrite {
                method: "tools/call",
                param: "name",
                public_value: &public_name,
                upstream_value: &entry.upstream_name,
                server_id: &entry.server_id,
                downstream_session_id,
                catalog_version,
                response_resource_rewrite_possible,
            },
        );
        PluginResult::Continue
    }

    async fn route_prompt_get(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        envelope: &McpEnvelope,
        downstream_session_id: &str,
    ) -> PluginResult {
        // Defense-in-depth: see `route_tool_call`. Keep ahead of catalog I/O.
        if self.batch_forbids_upstream(ctx) {
            return PluginResult::Continue;
        }
        if let Err(error) = self.ensure_catalog(ctx, downstream_session_id).await {
            return catalog_error_response(envelope.id.clone(), "MCP catalog unavailable", error);
        }
        let public_name = match envelope
            .params
            .as_ref()
            .and_then(|params| params.get("name"))
            .and_then(Value::as_str)
        {
            Some(name) => name.to_string(),
            None => {
                return json_rpc_error(
                    envelope.id.clone(),
                    -32602,
                    "Invalid MCP prompt params",
                    None,
                );
            }
        };
        let Some(catalog_lock) = self.catalog_for_session(downstream_session_id) else {
            return session_not_found_response();
        };
        let catalog = catalog_lock.read().await;
        self.emit_catalog_degraded_metadata(ctx, &catalog);
        if let Some(response) = family_unavailable_error(&catalog, "prompts", envelope.id.clone()) {
            return response;
        }
        let Some(entry) = catalog.prompts.get(&public_name).cloned() else {
            return json_rpc_error(envelope.id.clone(), -32008, "Unknown MCP prompt", None);
        };
        drop(catalog);
        let Some(server) = self.servers.get(&entry.server_id) else {
            return json_rpc_error(
                envelope.id.clone(),
                -32002,
                "Unknown upstream MCP server",
                None,
            );
        };
        let response_resource_rewrite_possible =
            self.resource_response_rewrite_possible(&server.server_id);
        if response_resource_rewrite_possible {
            self.prepare_response_resource_bindings(ctx, downstream_session_id, &server.server_id)
                .await;
        }
        let Some(catalog_lock) = self.catalog_for_session(downstream_session_id) else {
            return session_not_found_response();
        };
        let catalog_version = catalog_lock.read().await.version;
        if let Err(error) = self
            .ensure_upstream_initialized(downstream_session_id, &server.server_id, ctx)
            .await
        {
            return json_rpc_error(
                envelope.id.clone(),
                -32005,
                "Upstream MCP session unavailable",
                Some(error),
            );
        }
        if self.observability.emit_metadata {
            ctx.metadata
                .insert("mcp.item_type".to_string(), "prompt".to_string());
            ctx.metadata
                .insert("mcp.prompt_name".to_string(), public_name.clone());
            ctx.metadata
                .insert("mcp.server_id".to_string(), entry.server_id.clone());
            ctx.metadata.insert(
                "mcp.upstream_prompt_name".to_string(),
                entry.upstream_name.clone(),
            );
        }
        self.set_route_to_server(ctx, headers, server, Some(downstream_session_id));
        Self::mark_request_rewrite(
            ctx,
            headers,
            RequestRewrite {
                method: "prompts/get",
                param: "name",
                public_value: &public_name,
                upstream_value: &entry.upstream_name,
                server_id: &entry.server_id,
                downstream_session_id,
                catalog_version,
                response_resource_rewrite_possible,
            },
        );
        PluginResult::Continue
    }

    async fn route_resource_read(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        envelope: &McpEnvelope,
        downstream_session_id: &str,
    ) -> PluginResult {
        // Defense-in-depth: see `route_tool_call`. Keep ahead of catalog I/O.
        if self.batch_forbids_upstream(ctx) {
            return PluginResult::Continue;
        }
        let catalog_error = match self.ensure_catalog(ctx, downstream_session_id).await {
            Ok(()) => None,
            Err(McpCatalogError::SessionNotFound) => return session_not_found_response(),
            Err(error) => Some(error),
        };
        let public_uri = match envelope
            .params
            .as_ref()
            .and_then(|params| params.get("uri"))
            .and_then(Value::as_str)
        {
            Some(uri) => uri.to_string(),
            None => {
                return json_rpc_error(
                    envelope.id.clone(),
                    -32602,
                    "Invalid MCP resource params",
                    None,
                );
            }
        };
        let route = if catalog_error.is_none() {
            let Some(catalog_lock) = self.catalog_for_session(downstream_session_id) else {
                return session_not_found_response();
            };
            let catalog = catalog_lock.read().await;
            self.emit_catalog_degraded_metadata(ctx, &catalog);
            catalog.resources.get(&public_uri).map(|entry| {
                (
                    entry.server_id.clone(),
                    entry.upstream_uri.clone(),
                    catalog.version,
                )
            })
        } else {
            None
        };
        // Tool/prompt response preparation may have populated templates for
        // just the selected server. Honor a fresh URI returned from that cache
        // before attempting an all-server refresh: an unrelated resource server
        // that does not implement template discovery must not make the freshly
        // returned URI unreadable. When the template catalog TTL has expired,
        // refresh the selected server before accepting the cached template so
        // removed templates do not remain routable.
        let cached_template_route = if route.is_none() {
            let Some(catalog_lock) = self.catalog_for_session(downstream_session_id) else {
                return session_not_found_response();
            };
            let cached_route = {
                let catalog = catalog_lock.read().await;
                resource_template_route(&catalog, &public_uri).map(|(server_id, upstream_uri)| {
                    (
                        server_id,
                        upstream_uri,
                        catalog.version,
                        catalog.resource_templates_are_stale(self.discovery.cache_ttl),
                    )
                })
            };
            match cached_route {
                Some((server_id, upstream_uri, catalog_version, false)) => {
                    Some((server_id, upstream_uri, catalog_version))
                }
                Some((server_id, _, _, true)) => {
                    // The response-binding refresh path records a per-server
                    // attempt before I/O, preventing repeated requests to an
                    // unsupported or temporarily unavailable upstream. It is
                    // deliberately fail-open here: this route was previously
                    // discovered and remains safer than making a transient
                    // discovery outage break a long-lived session. A successful
                    // refresh still removes routes the upstream withdrew.
                    self.prepare_response_resource_bindings(ctx, downstream_session_id, &server_id)
                        .await;
                    let catalog = catalog_lock.read().await;
                    match resource_template_route(&catalog, &public_uri) {
                        Some((server_id, upstream_uri)) => {
                            Some((server_id, upstream_uri, catalog.version))
                        }
                        None => {
                            return json_rpc_error(
                                envelope.id.clone(),
                                -32007,
                                "Unknown MCP resource",
                                None,
                            );
                        }
                    }
                }
                None => None,
            }
        } else {
            None
        };
        let (server_id, upstream_uri, catalog_version) = match route.or(cached_template_route) {
            Some(route) => route,
            None => {
                if let Err(error) = self
                    .ensure_resource_templates(ctx, downstream_session_id)
                    .await
                {
                    return catalog_error_response(
                        envelope.id.clone(),
                        "MCP resource template catalog unavailable",
                        error,
                    );
                }
                let Some(catalog_lock) = self.catalog_for_session(downstream_session_id) else {
                    return session_not_found_response();
                };
                let catalog = catalog_lock.read().await;
                let Some((server_id, upstream_uri)) =
                    resource_template_route(&catalog, &public_uri)
                else {
                    if let Some(response) =
                        family_unavailable_error(&catalog, "resources", envelope.id.clone())
                    {
                        return response;
                    }
                    if let Some(error) = catalog_error {
                        return catalog_error_response(
                            envelope.id.clone(),
                            "MCP catalog unavailable",
                            error,
                        );
                    }
                    return json_rpc_error(
                        envelope.id.clone(),
                        -32007,
                        "Unknown MCP resource",
                        None,
                    );
                };
                (server_id, upstream_uri, catalog.version)
            }
        };
        let Some(server) = self.servers.get(&server_id) else {
            return json_rpc_error(
                envelope.id.clone(),
                -32002,
                "Unknown upstream MCP server",
                None,
            );
        };
        if let Err(error) = self
            .ensure_upstream_initialized(downstream_session_id, &server.server_id, ctx)
            .await
        {
            return json_rpc_error(
                envelope.id.clone(),
                -32005,
                "Upstream MCP session unavailable",
                Some(error),
            );
        }
        if self.observability.emit_metadata {
            ctx.metadata
                .insert("mcp.item_type".to_string(), "resource".to_string());
            ctx.metadata
                .insert("mcp.resource_uri".to_string(), public_uri.clone());
            ctx.metadata
                .insert("mcp.server_id".to_string(), server_id.clone());
            ctx.metadata.insert(
                "mcp.upstream_resource_uri".to_string(),
                upstream_uri.clone(),
            );
        }
        self.set_route_to_server(ctx, headers, server, Some(downstream_session_id));
        Self::mark_request_rewrite(
            ctx,
            headers,
            RequestRewrite {
                method: "resources/read",
                param: "uri",
                public_value: &public_uri,
                upstream_value: &upstream_uri,
                server_id: &server_id,
                downstream_session_id,
                catalog_version,
                response_resource_rewrite_possible: self
                    .resource_response_rewrite_possible(&server_id),
            },
        );
        PluginResult::Continue
    }

    fn handle_transparent_post(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        envelope: &McpEnvelope,
    ) -> PluginResult {
        let Some(server) = self.primary_server() else {
            return json_rpc_error(
                envelope.id.clone(),
                -32002,
                "Unknown upstream MCP server",
                None,
            );
        };
        if self.observability.emit_metadata {
            ctx.metadata
                .insert("mcp.server_id".to_string(), server.server_id.clone());
        }
        let downstream_session_id = self.downstream_session_id_from_headers(headers);
        self.set_route_to_server(ctx, headers, server, downstream_session_id.as_deref());
        PluginResult::Continue
    }

    async fn handle_jsonrpc_batch(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        batch: &[BatchMember],
    ) -> PluginResult {
        // Whole-body byte, empty-array, and member-count admission already ran
        // on the raw wire bytes in `admit_raw_jsonrpc_batch`; per-member
        // shape/size defects are per-item errors from here on.
        if self.observability.emit_metadata {
            ctx.metadata
                .insert("mcp.batch".to_string(), "true".to_string());
            ctx.metadata
                .insert("mcp.batch_size".to_string(), batch.len().to_string());
        }

        if self.mode == McpGatewayMode::TransparentProxy {
            return self.handle_transparent_jsonrpc_batch(ctx, headers, batch);
        }

        self.handle_aggregate_jsonrpc_batch(ctx, headers, batch)
            .await
    }

    /// Transparent batches keep one upstream and therefore Continue through the
    /// normal proxy/plugin chain after every member passes the same envelope
    /// rules as a singleton. Partial rewrite/forward is impossible for an HTTP
    /// batch body, so any invalid member fails closed into a synthetic per-item
    /// error array (valid siblings are not forwarded either) rather than
    /// dialing upstream under weaker policy.
    fn handle_transparent_jsonrpc_batch(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        batch: &[BatchMember],
    ) -> PluginResult {
        let mut envelopes = Vec::with_capacity(batch.len());
        let mut invalid = false;
        let mut responses = Vec::with_capacity(batch.len());

        for item in batch {
            match self.validate_batch_member(item) {
                Ok(envelope) => {
                    if matches!(
                        envelope.message_kind,
                        McpMessageKind::Response | McpMessageKind::ErrorResponse
                    ) {
                        invalid = true;
                        responses.push(json_rpc_error_value(
                            envelope.id.clone(),
                            -32600,
                            "Invalid MCP JSON-RPC request",
                        ));
                        envelopes.push(None);
                    } else {
                        self.emit_envelope_metadata(ctx, &envelope);
                        let protocol_version =
                            self.mark_protocol_version(ctx, headers, Some(&envelope));
                        // Exact singleton parity: a post-initialize member on an
                        // unsupported MCP-Protocol-Version is rejected here too,
                        // so a batch cannot smuggle an unsupported version past
                        // the gate the equivalent singleton enforces. Rejecting
                        // the whole HTTP request is the only fail-closed option
                        // — an HTTP batch body cannot be partially forwarded.
                        if let Some(response) = self.unsupported_protocol_version_response(
                            ctx,
                            &envelope,
                            protocol_version.as_deref(),
                        ) {
                            // Drop any staged per-item state, then restate the
                            // deny decision so the rejection stays observable.
                            self.clear_batch_item_routing_state(ctx);
                            self.restore_batch_request_metadata(ctx, headers, &BTreeSet::new());
                            ctx.metadata
                                .insert("mcp.route_decision".to_string(), "deny".to_string());
                            return response;
                        }
                        responses.push(Value::Null);
                        envelopes.push(Some(envelope));
                    }
                }
                Err(error) => {
                    invalid = true;
                    responses.push(error);
                    envelopes.push(None);
                }
            }
        }

        if invalid {
            let response_values =
                responses
                    .into_iter()
                    .zip(envelopes.iter())
                    .filter_map(|(slot, envelope)| match envelope {
                        // A valid notification never receives a JSON-RPC response,
                        // even when an invalid sibling prevents the whole HTTP
                        // batch from being forwarded.
                        Some(envelope)
                            if matches!(envelope.message_kind, McpMessageKind::Notification) =>
                        {
                            None
                        }
                        Some(envelope) => Some(json_rpc_error_value(
                            envelope.id.clone(),
                            -32600,
                            "JSON-RPC batch was not forwarded because a sibling member was invalid",
                        )),
                        None => Some(slot),
                    });
            // Apply the response budget while the synthetic array is assembled,
            // not after serializing the entire result. Admitted member ids are
            // bounded by the request/item caps, but their combined reflected
            // size may still be much larger than max_batch_response_bytes.
            // Serializing the whole array before checking that cap would let an
            // invalid transparent batch allocate beyond the configured response
            // budget even though the client ultimately receives only a bounded
            // error.
            let mut bounded_responses = Vec::new();
            let mut response_bytes = 2usize;
            for value in response_values {
                if let Err(response) = self.push_bounded_batch_response(
                    &mut bounded_responses,
                    &mut response_bytes,
                    value,
                ) {
                    self.clear_batch_item_routing_state(ctx);
                    self.restore_batch_request_metadata(ctx, headers, &BTreeSet::new());
                    ctx.metadata.insert(
                        "mcp.route_decision".to_string(),
                        "synthetic_response".to_string(),
                    );
                    return response;
                }
            }
            self.clear_batch_item_routing_state(ctx);
            self.restore_batch_request_metadata(ctx, headers, &BTreeSet::new());
            ctx.metadata.insert(
                "mcp.route_decision".to_string(),
                "synthetic_response".to_string(),
            );
            return self.bounded_batch_json_response(bounded_responses);
        }

        // Every member is independently valid. Route once to the single
        // upstream so later before_proxy / request-body / after_proxy plugins
        // still observe the same Continue path as a singleton MCP POST.
        let route_envelope = envelopes
            .into_iter()
            .flatten()
            .next()
            .unwrap_or(McpEnvelope {
                jsonrpc: "2.0".to_string(),
                id: None,
                method: None,
                params: None,
                result: None,
                error: None,
                message_kind: McpMessageKind::Notification,
            });
        // The forwarded body is the whole batch, not `route_envelope`, so no
        // single member may describe the request: drop every member-scoped key
        // the loop stamped (otherwise `mcp.method` and friends would report the
        // *last* member while the route was chosen from the *first*) and keep
        // only the request-level summary before Continuing.
        self.clear_batch_item_routing_state(ctx);
        self.restore_batch_request_metadata(ctx, headers, &BTreeSet::new());
        self.handle_transparent_post(ctx, headers, &route_envelope)
    }

    /// Aggregate batches assemble gateway-handled (synthetic) member results.
    /// Known upstream-routed methods (`tools/call`, `prompts/get`,
    /// `resources/read`) are rejected *before* dispatch — ahead of session
    /// touch, catalog refresh, policy/schema work, and any network I/O — so a
    /// cold versus warm catalog cannot change the fail-closed `-32009`
    /// outcome. Unknown/passthrough members that still resolve to upstream
    /// routing remain covered by the private `mcp_batch_forbids_upstream`
    /// guard: executing a `Continue` inside `before_proxy` would bypass later
    /// plugin phases (`a2a_gateway`, `mesh_route_dispatch`, `ai_semantic_cache`,
    /// request transformers, final request-body hooks, and normal proxy
    /// response phases). Multi-upstream or mixed synthetic+upstream shapes
    /// cannot be represented by one HTTP exchange under full policy, so those
    /// members must be issued as singleton requests.
    ///
    /// Session-lifecycle members (`initialize`) are rejected *before* dispatch.
    /// Session minting and the eviction it can trigger are not transactional
    /// across batch members: a later ambiguity or a `max_batch_response_bytes`
    /// failure would leave a hidden session behind, and removing a
    /// newly minted session cannot restore one that its admission evicted. The
    /// supported contract is therefore that `initialize` is a singleton HTTP
    /// request, and no batch may mint or evict a downstream session or stamp a
    /// session response header. Ordinary gateway-handled batch members may
    /// still refresh an existing session's idle lifetime, just like equivalent
    /// singletons.
    async fn handle_aggregate_jsonrpc_batch(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        batch: &[BatchMember],
    ) -> PluginResult {
        let mut responses = Vec::new();
        // Exact serialized size of the response array accumulated so far:
        // opening + closing brackets plus each serialized item and comma.
        // Tracking this incrementally avoids cloning and reserializing every
        // prior response for each new batch member.
        let mut response_bytes = 2usize;
        let mut saw_response_bearing = false;
        let mut blocked_upstream_notification = false;
        let mut blocked_lifecycle_notification = false;
        let mut failed_notification = false;
        // Bounded union of every member's catalog-degradation state. The key is
        // request-level observability, but it is *produced* per member and the
        // per-item reset clears it, so it is accumulated here instead of being
        // left at whichever member happened to run last. Cardinality is fixed:
        // at most (configured servers x catalog families) `server:family` pairs.
        let mut catalog_degraded: BTreeSet<String> = BTreeSet::new();
        let inbound_headers = headers.clone();

        for item in batch {
            // Each member starts from the inbound request headers and a cleared
            // per-item routing/rewrite state so no sibling's route override,
            // trusted tool rewrite, response binding, or injected header can
            // influence this member's dispatch decision.
            *headers = inbound_headers.clone();
            self.clear_batch_item_routing_state(ctx);
            ctx.mcp_batch_forbids_upstream = true;

            let envelope = match self.validate_batch_member(item) {
                Ok(envelope) => envelope,
                Err(error) => {
                    saw_response_bearing = true;
                    if let Err(response) =
                        self.push_bounded_batch_response(&mut responses, &mut response_bytes, error)
                    {
                        return self.fail_batch_closed(ctx, headers, &inbound_headers, response);
                    }
                    continue;
                }
            };
            if matches!(
                envelope.message_kind,
                McpMessageKind::Response | McpMessageKind::ErrorResponse
            ) {
                saw_response_bearing = true;
                if let Err(response) = self.push_bounded_batch_response(
                    &mut responses,
                    &mut response_bytes,
                    json_rpc_error_value(
                        envelope.id.clone(),
                        -32600,
                        "Invalid MCP JSON-RPC request",
                    ),
                ) {
                    return self.fail_batch_closed(ctx, headers, &inbound_headers, response);
                }
                continue;
            }

            let is_notification = matches!(envelope.message_kind, McpMessageKind::Notification);
            let method = envelope.method.as_deref().unwrap_or_default();

            // Reject session lifecycle before any dispatch so a batch initialize
            // can never mint a session (or evict an existing live one) before a
            // later member or response-admission failure.
            if method == "initialize" {
                if is_notification {
                    blocked_lifecycle_notification = true;
                    continue;
                }
                saw_response_bearing = true;
                if let Err(response) = self.push_bounded_batch_response(
                    &mut responses,
                    &mut response_bytes,
                    json_rpc_error_value(
                        envelope.id.clone(),
                        MCP_BATCH_SESSION_LIFECYCLE_AMBIGUOUS,
                        "MCP initialize must be a singleton request, not a JSON-RPC batch member",
                    ),
                ) {
                    return self.fail_batch_closed(ctx, headers, &inbound_headers, response);
                }
                continue;
            }

            // Reject known upstream-routed methods before any dispatch so a
            // cold/stale catalog cannot dial discovery, touch the session, run
            // policy/schema work, or return a cache-dependent error ahead of the
            // deterministic -32009 singleton-routing boundary. Notification forms
            // omit a response element; request forms append -32009 per item.
            if aggregate_method_requires_upstream_routing(method) {
                if is_notification {
                    blocked_upstream_notification = true;
                    continue;
                }
                saw_response_bearing = true;
                if let Err(response) = self.push_bounded_batch_response(
                    &mut responses,
                    &mut response_bytes,
                    json_rpc_error_value(
                        envelope.id.clone(),
                        MCP_BATCH_UPSTREAM_ROUTING_UNSUPPORTED,
                        "Aggregate JSON-RPC batch member requires singleton upstream routing",
                    ),
                ) {
                    return self.fail_batch_closed(ctx, headers, &inbound_headers, response);
                }
                continue;
            }

            self.emit_envelope_metadata(ctx, &envelope);
            let result = self.dispatch_post_envelope(ctx, headers, &envelope).await;
            // Take this member's degraded set before the next iteration's reset
            // drops it, so the request-level summary is the union across members
            // rather than the last member's view.
            if let Some(item_degraded) = ctx.metadata.remove("mcp.catalog_degraded") {
                for pair in item_degraded.split(',').filter(|pair| !pair.is_empty()) {
                    catalog_degraded.insert(pair.to_string());
                }
            }
            match classify_batch_item_result(
                result,
                envelope.id.clone(),
                is_notification,
                &self.sessions.downstream_session_header,
            ) {
                BatchItemOutcome::Notification => {}
                BatchItemOutcome::FailedNotification => {
                    failed_notification = true;
                }
                BatchItemOutcome::Response {
                    value,
                    session_header: item_session,
                } => {
                    saw_response_bearing = true;
                    if item_session.is_some() {
                        // Lifecycle members are rejected above, so no member can
                        // legitimately advertise a downstream session. Fail this
                        // member closed rather than stamping a session header the
                        // batch does not own — the response must never name a
                        // session the store may not hold.
                        if let Err(response) = self.push_bounded_batch_response(
                            &mut responses,
                            &mut response_bytes,
                            json_rpc_error_value(
                                envelope.id.clone(),
                                MCP_BATCH_SESSION_LIFECYCLE_AMBIGUOUS,
                                "MCP session lifecycle is not supported inside a JSON-RPC batch",
                            ),
                        ) {
                            return self.fail_batch_closed(
                                ctx,
                                headers,
                                &inbound_headers,
                                response,
                            );
                        }
                        continue;
                    }
                    if let Err(response) =
                        self.push_bounded_batch_response(&mut responses, &mut response_bytes, value)
                    {
                        return self.fail_batch_closed(ctx, headers, &inbound_headers, response);
                    }
                }
                BatchItemOutcome::UpstreamBound {
                    id,
                    is_notification,
                } => {
                    // Never dial upstream from before_proxy: that would skip
                    // every later configured plugin phase for this member.
                    self.clear_batch_item_routing_state(ctx);
                    if is_notification {
                        blocked_upstream_notification = true;
                    } else {
                        saw_response_bearing = true;
                        if let Err(response) = self.push_bounded_batch_response(
                            &mut responses,
                            &mut response_bytes,
                            json_rpc_error_value(
                                id,
                                MCP_BATCH_UPSTREAM_ROUTING_UNSUPPORTED,
                                "Aggregate JSON-RPC batch member requires singleton upstream routing",
                            ),
                        ) {
                            return self.fail_batch_closed(ctx, headers, &inbound_headers, response);
                        }
                    }
                }
            }
        }

        self.clear_batch_item_routing_state(ctx);
        *headers = inbound_headers;
        self.restore_batch_request_metadata(ctx, headers, &catalog_degraded);
        ctx.metadata.insert(
            "mcp.route_decision".to_string(),
            "synthetic_response".to_string(),
        );

        if !saw_response_bearing {
            // Notification-only batches carry no per-item response element, so
            // any blocked or failed notification is reported once at batch
            // level. Ordering is most-specific-first: a lifecycle restriction
            // explains an upstream one, which explains a dispatch failure.
            if blocked_lifecycle_notification {
                return json_rpc_error(
                    None,
                    MCP_BATCH_SESSION_LIFECYCLE_AMBIGUOUS,
                    "MCP initialize must be a singleton request, not a JSON-RPC batch member",
                    Some(
                        "session lifecycle members are not dispatched inside JSON-RPC batches"
                            .to_string(),
                    ),
                );
            }
            if blocked_upstream_notification {
                // Do not return empty 202: upstream-bound notifications were
                // not executed, so claiming success would hide a fail-closed
                // policy restriction.
                return json_rpc_error(
                    None,
                    MCP_BATCH_UPSTREAM_ROUTING_UNSUPPORTED,
                    "Aggregate JSON-RPC batch requires singleton upstream routing",
                    Some(
                        "upstream-bound notification members are not dispatched inside aggregate batches"
                            .to_string(),
                    ),
                );
            }
            if failed_notification {
                return json_rpc_error(
                    None,
                    MCP_BATCH_NOTIFICATION_FAILED,
                    "JSON-RPC batch notification member could not be processed",
                    None,
                );
            }
            return empty_response(202);
        }

        // No batch may stamp a downstream session header: session lifecycle is
        // singleton-only, so there is never a batch-owned live session to name.
        self.bounded_batch_json_response(responses)
    }

    /// Restore request state before returning a batch-level fail-closed
    /// response. Every early return from the aggregate loop must leave the
    /// context with no per-item routing, rewrite, or dispatch-guard state, and
    /// the headers back at their inbound values.
    fn fail_batch_closed(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        inbound_headers: &HashMap<String, String>,
        response: PluginResult,
    ) -> PluginResult {
        self.clear_batch_item_routing_state(ctx);
        // A fail-closed batch publishes no catalog-degradation summary: the
        // members that would have contributed one never completed.
        self.restore_batch_request_metadata(ctx, inbound_headers, &BTreeSet::new());
        ctx.metadata.insert(
            "mcp.route_decision".to_string(),
            "synthetic_response".to_string(),
        );
        *headers = inbound_headers.clone();
        response
    }

    /// Re-establish the request-level MCP metadata the per-item reset clears.
    ///
    /// `mcp.protocol_version` is a property of the *request* — the inbound
    /// `MCP-Protocol-Version` header — not of any member. `mark_protocol_version`
    /// also falls back to a member's `params.protocolVersion` when the header is
    /// absent, which is right for the per-member version gate but would
    /// otherwise leave the last member that declared one describing the whole
    /// request. Passing `None` here re-derives it from the inbound headers only,
    /// so a member's params can gate that member without ever labelling the
    /// batch. `mcp.catalog_degraded` is likewise republished as the bounded
    /// union accumulated across members, never one member's view.
    fn restore_batch_request_metadata(
        &self,
        ctx: &mut RequestContext,
        inbound_headers: &HashMap<String, String>,
        catalog_degraded: &BTreeSet<String>,
    ) {
        // Stamps `mcp.protocol_version` from the header when present; the
        // returned value is only needed by the per-member gate, not here.
        let _ = self.mark_protocol_version(ctx, inbound_headers, None);
        if !self.observability.emit_metadata || catalog_degraded.is_empty() {
            return;
        }
        let pairs: Vec<&str> = catalog_degraded.iter().map(String::as_str).collect();
        ctx.metadata
            .insert("mcp.catalog_degraded".to_string(), pairs.join(","));
    }

    /// Raw admission for an array-shaped request body.
    ///
    /// The whole-body cap runs on the raw bytes first, then only the array
    /// framing is parsed: every member is retained as a borrowed
    /// `&RawValue` — its exact JSON wire slice — so the member-count gate and
    /// `validation.max_batch_item_bytes` both run before any member funds a
    /// `Value` tree. `RawValue::get()` excludes the array separators and the
    /// inter-member whitespace surrounding the member, and includes the
    /// member's internal whitespace and escape sequences verbatim, so a member
    /// that is large on the wire cannot shrink under the cap by normalizing.
    ///
    /// Malformed array-shaped bodies and malformed members both fail closed.
    fn admit_raw_jsonrpc_batch(&self, body: &[u8]) -> Result<Vec<BatchMember>, PluginResult> {
        if body.len() > self.validation.max_batch_bytes {
            return Err(json_rpc_error(
                None,
                -32600,
                "Invalid Request",
                Some("JSON-RPC batch exceeded max_batch_bytes".to_string()),
            ));
        }
        let raw_members: Vec<&RawValue> = match serde_json::from_slice(body) {
            Ok(members) => members,
            Err(_) => {
                return Err(json_rpc_error(
                    None,
                    -32600,
                    "Invalid MCP JSON-RPC request",
                    None,
                ));
            }
        };
        self.admit_jsonrpc_batch(raw_members.len())?;
        Ok(raw_members
            .into_iter()
            .map(|member| {
                let raw = member.get();
                if raw.len() > self.validation.max_batch_item_bytes {
                    // Deliberately do not parse or read this member's id.
                    return BatchMember::Rejected;
                }
                match serde_json::from_str::<Value>(raw) {
                    Ok(value) => BatchMember::Admitted(value),
                    Err(_) => BatchMember::Rejected,
                }
            })
            .collect())
    }

    fn admit_jsonrpc_batch(&self, batch_len: usize) -> Result<(), PluginResult> {
        if batch_len == 0 {
            return Err(json_rpc_error(None, -32600, "Invalid Request", None));
        }
        if batch_len > self.validation.max_batch_items {
            return Err(json_rpc_error(
                None,
                -32600,
                "Invalid Request",
                Some("JSON-RPC batch exceeded max_batch_items".to_string()),
            ));
        }
        Ok(())
    }

    /// Per-member validation used by both transparent and aggregate batch
    /// paths, after raw-wire admission. Members refused by the raw per-member
    /// wire cap, and non-object / nested-array members, become bounded
    /// `id: null` Invalid Request values; other malformed members reflect only
    /// their already-materialized id.
    fn validate_batch_member(&self, member: &BatchMember) -> Result<McpEnvelope, Value> {
        let BatchMember::Admitted(item) = member else {
            // The raw slice was never materialized, so there is no id to echo.
            return Err(json_rpc_error_value(
                None,
                -32600,
                "Invalid MCP JSON-RPC request",
            ));
        };
        if !item.is_object() {
            return Err(json_rpc_error_value(
                None,
                -32600,
                "Invalid MCP JSON-RPC request",
            ));
        }
        let member_id = item.get("id").cloned();
        parse_mcp_envelope_value(item)
            .map_err(|_| json_rpc_error_value(member_id, -32600, "Invalid MCP JSON-RPC request"))
    }

    fn push_bounded_batch_response(
        &self,
        responses: &mut Vec<Value>,
        response_bytes: &mut usize,
        value: Value,
    ) -> Result<(), PluginResult> {
        let encoded_item = match serde_json::to_vec(&value) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(json_rpc_error(
                    None,
                    -32600,
                    "Invalid Request",
                    Some("JSON-RPC batch response could not be measured".to_string()),
                ));
            }
        };
        let separator_bytes = usize::from(!responses.is_empty());
        let Some(next_response_bytes) = response_bytes
            .checked_add(separator_bytes)
            .and_then(|bytes| bytes.checked_add(encoded_item.len()))
        else {
            return Err(json_rpc_error(
                None,
                -32600,
                "Invalid Request",
                Some("JSON-RPC batch exceeded max_batch_response_bytes".to_string()),
            ));
        };
        if next_response_bytes > self.validation.max_batch_response_bytes {
            return Err(json_rpc_error(
                None,
                -32600,
                "Invalid Request",
                Some("JSON-RPC batch exceeded max_batch_response_bytes".to_string()),
            ));
        }
        responses.push(value);
        *response_bytes = next_response_bytes;
        Ok(())
    }

    /// Serialize a bounded batch response array. Batches never carry a session
    /// response header: session lifecycle is singleton-only, so there is no
    /// batch-owned session to advertise (and therefore no way to name a session
    /// the store does not hold).
    fn bounded_batch_json_response(&self, responses: Vec<Value>) -> PluginResult {
        let body = Value::Array(responses);
        match serde_json::to_vec(&body) {
            Ok(bytes) if bytes.len() > self.validation.max_batch_response_bytes => json_rpc_error(
                None,
                -32600,
                "Invalid Request",
                Some("JSON-RPC batch exceeded max_batch_response_bytes".to_string()),
            ),
            Ok(_) => json_response(200, body, None),
            Err(_) => json_rpc_error(
                None,
                -32600,
                "Invalid Request",
                Some("JSON-RPC batch response could not be measured".to_string()),
            ),
        }
    }

    /// Drop every piece of per-item state a batch member can stage, so a
    /// sibling's routing decision, private rewrite trust, response binding, or
    /// item-scoped observability can never authorize or reroute another member.
    /// Only request-level metadata survives a batch: `mcp.enabled`, `mcp.mode`,
    /// `mcp.batch`, `mcp.batch_size`, and the terminal `mcp.route_decision`. The
    /// request-start baselines for `mcp.policy_decision` /
    /// `mcp.schema_validation` are re-established afterwards so log schemas keep
    /// seeing those fields with their neutral values rather than a sibling
    /// member's verdict.
    ///
    /// `mcp.protocol_version` and `mcp.catalog_degraded` are cleared here too
    /// even though their final values are request-level: both can be *written*
    /// by a single member (`params.protocolVersion`, one member's catalog
    /// refresh), so every batch terminal point republishes them from
    /// request-level inputs via [`Self::restore_batch_request_metadata`] rather
    /// than letting whichever member ran last describe the request.
    fn clear_batch_item_routing_state(&self, ctx: &mut RequestContext) {
        ctx.route_override_backend_scheme = None;
        ctx.route_override_backend_host = None;
        ctx.route_override_backend_port = None;
        ctx.route_override_resolved_tls = None;
        ctx.route_override_path = None;
        ctx.route_override_path_is_absolute = false;
        ctx.route_override_authority = None;
        ctx.mcp_trusted_tool_name_rewrite = None;
        ctx.mcp_response_resource_binding = None;
        ctx.mcp_batch_forbids_upstream = false;
        ctx.metadata.remove("mcp.server_id");
        ctx.metadata.remove("mcp.item_type");
        ctx.metadata.remove("mcp.item_name");
        ctx.metadata.remove("mcp.tool_name");
        ctx.metadata.remove("mcp.public_tool_name");
        ctx.metadata.remove("mcp.upstream_tool_name");
        ctx.metadata.remove("mcp.prompt_name");
        ctx.metadata.remove("mcp.upstream_prompt_name");
        ctx.metadata.remove("mcp.resource_uri");
        ctx.metadata.remove("mcp.upstream_resource_uri");
        ctx.metadata.remove("mcp.arguments");
        ctx.metadata.remove("mcp.arguments_hash");
        ctx.metadata.remove("mcp.input_schema_hash");
        ctx.metadata.remove("mcp.schema_validation");
        ctx.metadata.remove("mcp.policy_decision");
        ctx.metadata.remove("mcp.catalog_hit");
        ctx.metadata.remove("mcp.catalog_version");
        ctx.metadata.remove("mcp.catalog_degraded");
        ctx.metadata.remove("mcp.protocol_version");
        ctx.metadata.remove("mcp.session.downstream");
        ctx.metadata.remove("mcp.protocol_version_negotiated");
        ctx.metadata.remove("mcp.message.kind");
        ctx.metadata.remove("mcp.jsonrpc");
        ctx.metadata.remove("mcp.method");
        ctx.metadata.remove(METADATA_REWRITE_KEY);
        ctx.metadata.remove(METADATA_REWRITE_METHOD_KEY);
        ctx.metadata.remove(METADATA_REWRITE_PARAM_KEY);
        ctx.metadata.remove(METADATA_REWRITE_PUBLIC_VALUE_KEY);
        ctx.metadata.remove(METADATA_REWRITE_UPSTREAM_VALUE_KEY);
        ctx.metadata.remove(METADATA_RESPONSE_REWRITE_KEY);
        ctx.metadata.remove(METADATA_RESPONSE_REWRITE_METHOD_KEY);
        ctx.metadata.remove(METADATA_RESPONSE_REWRITE_SERVER_KEY);
        ctx.metadata.remove(METADATA_RESPONSE_REWRITE_SESSION_KEY);
        ctx.metadata
            .remove(METADATA_RESPONSE_REWRITE_CATALOG_VERSION_KEY);
        // Restore the neutral request-start baselines the cleared keys had
        // before any member ran. `entry().or_insert` leaves the terminal
        // `mcp.route_decision` alone.
        self.emit_base_metadata(ctx);
    }

    /// Whether this dispatch is an aggregate JSON-RPC batch member and must not
    /// reach the network. Reads the private `RequestContext` flag only: public
    /// `metadata` is plugin scratch space that inbound request data and sibling
    /// plugins can write, and a network-dispatch boundary must not be forgeable.
    fn batch_forbids_upstream(&self, ctx: &RequestContext) -> bool {
        ctx.mcp_batch_forbids_upstream
    }

    async fn dispatch_post_envelope(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        envelope: &McpEnvelope,
    ) -> PluginResult {
        self.emit_envelope_metadata(ctx, envelope);
        let protocol_version = self.mark_protocol_version(ctx, headers, Some(envelope));
        let method = envelope.method.as_deref().unwrap_or_default();
        // Methods the aggregate router handles itself are all JSON-RPC requests.
        // A notification-form one (no id) is accepted with 202/no body and must run
        // none of the request-side side effects, so this guard precedes protocol
        // validation and the session touch/validation below: a stale session header
        // must not turn it into a 404, a live one must not bump last_seen, and no
        // catalog refresh or routing may occur. Genuine notifications/*,
        // notification-form ping, and passthrough/unknown methods keep their handling
        // in the match below. Transparent mode forwards notifications to its single
        // upstream, so this only applies in aggregate mode.
        if self.mode == McpGatewayMode::AggregateRouter
            && envelope.message_kind == McpMessageKind::Notification
            && matches!(
                method,
                "initialize"
                    | "tools/list"
                    | "tools/call"
                    | "prompts/list"
                    | "prompts/get"
                    | "resources/list"
                    | "resources/templates/list"
                    | "resources/read"
            )
        {
            ctx.metadata.insert(
                "mcp.route_decision".to_string(),
                "synthetic_response".to_string(),
            );
            return empty_response(202);
        }
        if let Some(response) =
            self.unsupported_protocol_version_response(ctx, envelope, protocol_version.as_deref())
        {
            return response;
        }
        if let Some(session_id) = self.downstream_session_id_from_headers(headers) {
            if self.mode == McpGatewayMode::AggregateRouter
                && method != "initialize"
                && !self.touch_downstream_session(&session_id, ctx).await
            {
                return session_not_found_response();
            }
            ctx.metadata
                .insert("mcp.session.downstream".to_string(), hash_str(&session_id));
        }

        if self.mode == McpGatewayMode::TransparentProxy {
            return self.handle_transparent_post(ctx, headers, envelope);
        }

        match method {
            "initialize" => {
                // MCP initialize is a negotiation, not a gate: echo a supported
                // requested version; otherwise answer with the gateway's
                // preferred supported version and let the client decide whether
                // to continue on it. Post-initialize requests still fail closed
                // above when the MCP-Protocol-Version header is unsupported.
                let version = match protocol_version {
                    Some(requested)
                        if self
                            .supported_protocol_versions
                            .iter()
                            .any(|supported| supported == &requested) =>
                    {
                        requested
                    }
                    Some(_) => {
                        let negotiated = self.preferred_protocol_version().to_string();
                        ctx.metadata.insert(
                            "mcp.protocol_version_negotiated".to_string(),
                            negotiated.clone(),
                        );
                        negotiated
                    }
                    None => self.preferred_protocol_version().to_string(),
                };
                let client_info = envelope
                    .params
                    .as_ref()
                    .and_then(|params| params.get("clientInfo"))
                    .cloned();
                let client_capabilities = envelope
                    .params
                    .as_ref()
                    .and_then(|params| params.get("capabilities"))
                    .cloned();
                let downstream_session_id = self
                    .create_downstream_session(
                        ctx,
                        version.clone(),
                        client_info,
                        client_capabilities,
                    )
                    .await;
                ctx.metadata.insert(
                    "mcp.session.downstream".to_string(),
                    hash_str(&downstream_session_id),
                );
                ctx.metadata.insert(
                    "mcp.route_decision".to_string(),
                    "synthetic_response".to_string(),
                );
                self.synthetic_initialize_response(envelope, &version, &downstream_session_id)
            }
            "notifications/initialized" | "ping" => {
                ctx.metadata.insert(
                    "mcp.route_decision".to_string(),
                    "synthetic_response".to_string(),
                );
                if envelope.message_kind == McpMessageKind::Notification {
                    return empty_response(202);
                }
                json_response(
                    200,
                    json!({
                        "jsonrpc": "2.0",
                        "id": envelope.id.clone().unwrap_or(Value::Null),
                        "result": {}
                    }),
                    None,
                )
            }
            "tools/list" => {
                let session_id = match self
                    .require_live_downstream_session(headers, envelope.id.clone(), ctx)
                    .await
                {
                    Ok(session_id) => session_id,
                    Err(result) => return result,
                };
                self.aggregate_tools_list(ctx, envelope, &session_id).await
            }
            "tools/call" => {
                let session_id = match self
                    .require_live_downstream_session(headers, envelope.id.clone(), ctx)
                    .await
                {
                    Ok(session_id) => session_id,
                    Err(result) => return result,
                };
                self.route_tool_call(ctx, headers, envelope, &session_id)
                    .await
            }
            "prompts/list" => {
                let session_id = match self
                    .require_live_downstream_session(headers, envelope.id.clone(), ctx)
                    .await
                {
                    Ok(session_id) => session_id,
                    Err(result) => return result,
                };
                self.aggregate_prompts_list(ctx, envelope, &session_id)
                    .await
            }
            "prompts/get" => {
                let session_id = match self
                    .require_live_downstream_session(headers, envelope.id.clone(), ctx)
                    .await
                {
                    Ok(session_id) => session_id,
                    Err(result) => return result,
                };
                self.route_prompt_get(ctx, headers, envelope, &session_id)
                    .await
            }
            "resources/list" => {
                let session_id = match self
                    .require_live_downstream_session(headers, envelope.id.clone(), ctx)
                    .await
                {
                    Ok(session_id) => session_id,
                    Err(result) => return result,
                };
                self.aggregate_resources_list(ctx, envelope, &session_id)
                    .await
            }
            "resources/templates/list" => {
                let session_id = match self
                    .require_live_downstream_session(headers, envelope.id.clone(), ctx)
                    .await
                {
                    Ok(session_id) => session_id,
                    Err(result) => return result,
                };
                self.aggregate_resource_templates_list(ctx, envelope, &session_id)
                    .await
            }
            "resources/read" => {
                let session_id = match self
                    .require_live_downstream_session(headers, envelope.id.clone(), ctx)
                    .await
                {
                    Ok(session_id) => session_id,
                    Err(result) => return result,
                };
                self.route_resource_read(ctx, headers, envelope, &session_id)
                    .await
            }
            _ if self.capabilities.passthrough_unknown_methods => {
                if let Some(server) = self.primary_server() {
                    let session_id = match self
                        .require_live_downstream_session(headers, envelope.id.clone(), ctx)
                        .await
                    {
                        Ok(session_id) => session_id,
                        Err(result) => return result,
                    };
                    if self.batch_forbids_upstream(ctx) {
                        return PluginResult::Continue;
                    }
                    if let Err(error) = self
                        .ensure_upstream_initialized(&session_id, &server.server_id, ctx)
                        .await
                    {
                        return json_rpc_error(
                            envelope.id.clone(),
                            -32005,
                            "Upstream MCP session unavailable",
                            Some(error),
                        );
                    }
                    self.set_route_to_server(ctx, headers, server, Some(&session_id));
                    PluginResult::Continue
                } else {
                    json_rpc_error(
                        envelope.id.clone(),
                        -32002,
                        "Unknown upstream MCP server",
                        None,
                    )
                }
            }
            _ if envelope.message_kind == McpMessageKind::Notification => {
                ctx.metadata.insert(
                    "mcp.route_decision".to_string(),
                    "synthetic_response".to_string(),
                );
                empty_response(202)
            }
            _ => json_rpc_error(envelope.id.clone(), -32601, "MCP method not found", None),
        }
    }
}

#[async_trait]
impl Plugin for McpGateway {
    fn name(&self) -> &str {
        "mcp_gateway"
    }

    fn priority(&self) -> u16 {
        super::priority::MCP_GATEWAY
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        HTTP_ONLY_PROTOCOLS
    }

    /// The public-URI/name rewrite this plugin applies to `resources/read`,
    /// `tools/call`, and `prompts/get` results is **not** a function of static
    /// configuration, so it cannot be reduced to a construction-time digest.
    ///
    /// `transform_response_body_with_context` resolves the rewrite against
    /// [`McpCatalog`] — the per-downstream-session resources, resource
    /// templates, tools, and prompts this gateway discovers from upstream and
    /// re-lists whenever `discovery.cache_ttl` expires. Which public URI maps
    /// to which upstream URI, which entries are hidden, and which are ambiguous
    /// all change with no config edit, no plugin-cache rebuild, and no new
    /// plugin instance. The catalog is also per session and per process: its
    /// `version` counter is a local monotonic value, so it is meaningless to a
    /// representation replayed in another session or by another gateway.
    /// Digesting the static config would therefore assert a compatibility claim
    /// the catalog can invalidate at any moment while the digest still matches.
    ///
    /// The ordering makes this unrecoverable rather than merely awkward:
    /// `request_deduplication` (priority
    /// `priorities::REQUEST_DEDUPLICATION`) short-circuits in `before_proxy`
    /// ahead of this plugin (`priorities::MCP_GATEWAY`), so a replay never runs
    /// the MCP validation/routing that would observe the current catalog or
    /// stamp `mcp.response_rewrite.*` metadata. There is no request-scoped
    /// dynamic provenance to pin before the dedup lookup, and establishing one
    /// would require an upstream discovery refresh — a network round trip under
    /// a per-session lock — on the dedup hot path.
    ///
    /// Reporting `Dynamic` collapses the proxy's presentation digest to `None`,
    /// which makes every replay consumer fail closed. Config admission rejects
    /// the composition outright
    /// (`request_deduplication::validate_composition`); this is the runtime
    /// backstop for admission paths that only warn.
    fn response_presentation_policy(&self) -> Option<super::ResponsePresentationPolicy> {
        self.enabled
            .then_some(super::ResponsePresentationPolicy::Dynamic)
    }

    fn modifies_request_headers(&self) -> bool {
        self.enabled
    }

    fn modifies_request_body(&self) -> bool {
        self.enabled && self.mode == McpGatewayMode::AggregateRouter
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.enabled
    }

    fn needs_request_body_bytes(&self) -> bool {
        self.enabled
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.enabled && self.matches_endpoint(ctx) && ctx.method.eq_ignore_ascii_case("POST")
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.enabled && self.mode == McpGatewayMode::AggregateRouter
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.requires_response_body_buffering()
            && ctx
                .metadata
                .get(METADATA_RESPONSE_REWRITE_KEY)
                .is_some_and(|value| value == "true")
    }

    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        self.should_buffer_response_body(ctx)
    }

    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && !(header_value(response_headers, "content-type")
                .is_none_or(mcp_content_type_is_json)
                && Self::response_encoding_allows_rewrite(response_headers)
                && self.response_length_allows_rewrite(response_headers))
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && content_type.is_none_or(mcp_content_type_is_json)
            && Self::response_encoding_allows_rewrite(response_headers)
            && self.response_length_allows_rewrite(response_headers)
    }

    fn needs_final_request_body_context(&self) -> bool {
        self.enabled && self.mode == McpGatewayMode::AggregateRouter
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx
            .metadata
            .get("ai_stream_router_claimed")
            .is_some_and(|value| value == "true")
        {
            return PluginResult::Continue;
        }
        if !self.enabled || !self.matches_endpoint(ctx) {
            return PluginResult::Continue;
        }
        self.emit_base_metadata(ctx);

        if ctx.method.eq_ignore_ascii_case("GET") {
            if self.mode == McpGatewayMode::TransparentProxy {
                if let Some(server) = self.primary_server() {
                    let downstream_session_id = self.downstream_session_id_from_headers(headers);
                    self.set_route_to_server(
                        ctx,
                        headers,
                        server,
                        downstream_session_id.as_deref(),
                    );
                }
                return PluginResult::Continue;
            }
            ctx.metadata
                .insert("mcp.route_decision".to_string(), "deny".to_string());
            return PluginResult::Reject {
                status_code: 405,
                body: json!({"error": "aggregate MCP SSE multiplexing is not supported in V1"})
                    .to_string(),
                headers: HashMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
            };
        }

        if ctx.method.eq_ignore_ascii_case("DELETE") {
            if self.mode == McpGatewayMode::TransparentProxy {
                if let Some(server) = self.primary_server() {
                    let downstream_session_id = self.downstream_session_id_from_headers(headers);
                    self.set_route_to_server(
                        ctx,
                        headers,
                        server,
                        downstream_session_id.as_deref(),
                    );
                }
                return PluginResult::Continue;
            }
            if let Some(session_id) = self.downstream_session_id_from_headers(headers) {
                if !self.touch_downstream_session(&session_id, ctx).await {
                    return session_not_found_response();
                }
                self.remove_downstream_session(&session_id, ctx).await;
                ctx.metadata
                    .insert("mcp.session.downstream".to_string(), hash_str(&session_id));
            }
            ctx.metadata.insert(
                "mcp.route_decision".to_string(),
                "synthetic_response".to_string(),
            );
            return PluginResult::Reject {
                status_code: 200,
                body: "{}".to_string(),
                headers: HashMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
            };
        }

        if !ctx.method.eq_ignore_ascii_case("POST") {
            if self.mode == McpGatewayMode::AggregateRouter {
                ctx.metadata
                    .insert("mcp.route_decision".to_string(), "deny".to_string());
                return PluginResult::Reject {
                    status_code: 405,
                    body: json!({"error": "unsupported MCP aggregate HTTP method"}).to_string(),
                    headers: HashMap::from([(
                        "content-type".to_string(),
                        "application/json".to_string(),
                    )]),
                };
            }
            return PluginResult::Continue;
        }
        if !Self::content_type_is_json(headers) {
            return json_rpc_error(None, -32600, "Invalid MCP JSON-RPC request", None);
        }
        let Some(body) = self.request_body(ctx) else {
            return json_rpc_error(None, -32600, "Invalid MCP JSON-RPC request", None);
        };
        // Enforce the advertised aggregate batch byte cap on the raw body,
        // before serde_json allocates a `Value` tree for it. A body whose first
        // non-whitespace byte is `[` is array-shaped, so an oversized batch is
        // refused without paying parse cost, and the per-member cap is then
        // enforced on each member's raw wire slice before that member is
        // materialized. Array-shaped bodies that are malformed still fail
        // closed, and singleton bodies are untouched by these caps.
        if Self::body_is_jsonrpc_batch_shaped(body) {
            let batch = match self.admit_raw_jsonrpc_batch(body) {
                Ok(batch) => batch,
                Err(response) => return response,
            };
            return self.handle_jsonrpc_batch(ctx, headers, &batch).await;
        }
        let parsed: Value = match serde_json::from_slice(body) {
            Ok(value) => value,
            Err(_) => return json_rpc_error(None, -32600, "Invalid MCP JSON-RPC request", None),
        };
        let envelope = match parse_mcp_envelope_value(&parsed) {
            Ok(envelope) => envelope,
            Err(_) => return json_rpc_error(None, -32600, "Invalid MCP JSON-RPC request", None),
        };
        self.dispatch_post_envelope(ctx, headers, &envelope).await
    }

    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.enabled || self.mode != McpGatewayMode::AggregateRouter {
            return None;
        }
        if ctx.metadata.remove(METADATA_REWRITE_KEY).as_deref() != Some("true") {
            // Routing stages rewrite metadata and the private tool-name mapping
            // together. If a later before_proxy hook stripped the marker before
            // this transform ran, drop pending trust so an incomplete rewrite
            // cannot remap governor policy identity. This hook runs once per
            // request, so a successful rewrite (which consumes the marker) is
            // not cleared here.
            ctx.mcp_trusted_tool_name_rewrite = None;
            return None;
        }
        let Some(method) = ctx.metadata.remove(METADATA_REWRITE_METHOD_KEY) else {
            ctx.mcp_trusted_tool_name_rewrite = None;
            return None;
        };
        let Some(param) = ctx.metadata.remove(METADATA_REWRITE_PARAM_KEY) else {
            ctx.mcp_trusted_tool_name_rewrite = None;
            return None;
        };
        let Some(public_value) = ctx.metadata.remove(METADATA_REWRITE_PUBLIC_VALUE_KEY) else {
            ctx.mcp_trusted_tool_name_rewrite = None;
            return None;
        };
        let Some(upstream_value) = ctx.metadata.remove(METADATA_REWRITE_UPSTREAM_VALUE_KEY) else {
            ctx.mcp_trusted_tool_name_rewrite = None;
            return None;
        };
        let trusted_tool_rewrite = method == "tools/call" && param == "name";
        // Forgeable rewrite metadata cannot mint governor trust on its own: a
        // tools/call name rewrite must match the private mapping staged by
        // `mark_request_rewrite`. Any mismatch or failed rewrite clears it so
        // the final governor recheck fails closed on untrusted aliases.
        if trusted_tool_rewrite {
            match &ctx.mcp_trusted_tool_name_rewrite {
                Some((trusted_public, trusted_upstream))
                    if trusted_public == &public_value && trusted_upstream == &upstream_value => {}
                _ => {
                    ctx.mcp_trusted_tool_name_rewrite = None;
                    return None;
                }
            }
        }

        let mut value: Value = match serde_json::from_slice(body) {
            Ok(value) => value,
            Err(_) => {
                if trusted_tool_rewrite {
                    ctx.mcp_trusted_tool_name_rewrite = None;
                }
                return None;
            }
        };
        let request_method = match value.get("method").and_then(Value::as_str) {
            Some(request_method) => request_method,
            None => {
                if trusted_tool_rewrite {
                    ctx.mcp_trusted_tool_name_rewrite = None;
                }
                return None;
            }
        };
        if request_method != method {
            warn!(
                expected_method = %method,
                actual_method = %request_method,
                "Skipping MCP request rewrite because routed method does not match buffered body"
            );
            if trusted_tool_rewrite {
                ctx.mcp_trusted_tool_name_rewrite = None;
            }
            return None;
        }
        let Some(params) = value.get_mut("params").and_then(Value::as_object_mut) else {
            if trusted_tool_rewrite {
                ctx.mcp_trusted_tool_name_rewrite = None;
            }
            return None;
        };
        let Some(current_value) = params.get(&param).and_then(Value::as_str) else {
            if trusted_tool_rewrite {
                ctx.mcp_trusted_tool_name_rewrite = None;
            }
            return None;
        };
        if current_value != public_value {
            warn!(
                method = %method,
                param = %param,
                expected_value_hash = %hash_str(&public_value),
                actual_value_hash = %hash_str(current_value),
                "Skipping MCP request rewrite because routed value does not match buffered body"
            );
            if trusted_tool_rewrite {
                ctx.mcp_trusted_tool_name_rewrite = None;
            }
            return None;
        }
        params.insert(param, Value::String(upstream_value));
        match serde_json::to_vec(&value) {
            Ok(rewritten) => Some(rewritten),
            Err(_) => {
                if trusted_tool_rewrite {
                    ctx.mcp_trusted_tool_name_rewrite = None;
                }
                None
            }
        }
    }

    async fn transform_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        let original_metadata_stamped = ctx
            .metadata
            .contains_key(crate::proxy::ORIGINAL_RESPONSE_METADATA_STAMPED_KEY);
        let origin_encoded = if original_metadata_stamped {
            ctx.metadata
                .contains_key(crate::proxy::ORIGIN_ENCODED_RESPONSE_METADATA_KEY)
        } else {
            header_value(response_headers, "content-encoding")
                .is_some_and(|encoding| !encoding.eq_ignore_ascii_case("identity"))
        };
        let original_content_length = if original_metadata_stamped {
            ctx.metadata
                .get(crate::proxy::ORIGINAL_RESPONSE_CONTENT_LENGTH_METADATA_KEY)
                .and_then(|value| value.parse::<usize>().ok())
        } else {
            header_value(response_headers, "content-length")
                .and_then(|value| value.parse::<usize>().ok())
        };
        if !self.should_buffer_response_body(ctx)
            || content_type.is_some_and(|value| {
                super::utils::body_transform::is_event_stream_content_type(value)
            })
            || content_type.is_some_and(|value| !mcp_content_type_is_json(value))
            || origin_encoded
            || original_content_length
                .is_none_or(|length| length > self.validation.max_upstream_response_bytes)
        {
            return None;
        }
        if body.len() > self.validation.max_upstream_response_bytes {
            warn!(
                method = ctx
                    .metadata
                    .get(METADATA_RESPONSE_REWRITE_METHOD_KEY)
                    .map(String::as_str)
                    .unwrap_or("unknown"),
                max_bytes = self.validation.max_upstream_response_bytes,
                actual_bytes = body.len(),
                "Skipping MCP response rewrite because upstream JSON response exceeded size limit"
            );
            return None;
        }

        let method = ctx.metadata.get(METADATA_RESPONSE_REWRITE_METHOD_KEY)?;
        if !matches!(
            method.as_str(),
            "resources/read" | "tools/call" | "prompts/get"
        ) {
            return None;
        }
        let server_id = ctx.metadata.get(METADATA_RESPONSE_REWRITE_SERVER_KEY)?;
        let session_hash = ctx.metadata.get(METADATA_RESPONSE_REWRITE_SESSION_KEY)?;
        let expected_catalog_version = ctx
            .metadata
            .get(METADATA_RESPONSE_REWRITE_CATALOG_VERSION_KEY)?
            .parse::<u64>()
            .ok()?;
        let catalog_lock = self
            .session_catalogs_by_hash
            .get(session_hash)
            .map(|catalog| Arc::clone(catalog.value()));
        let catalog = match &catalog_lock {
            Some(catalog) => Some(catalog.read().await),
            None => None,
        };
        let catalog_version_matches = catalog
            .as_ref()
            .is_some_and(|catalog| catalog.version == expected_catalog_version);
        if !catalog_version_matches
            && (method != "resources/read" || ctx.mcp_response_resource_binding.is_none())
        {
            return None;
        }
        let mut value: Value = serde_json::from_slice(body).ok()?;
        let result = value.get_mut("result")?;

        let outcome = match method.as_str() {
            "resources/read" => rewrite_resource_read_result(
                result,
                catalog.as_deref(),
                server_id,
                ctx.mcp_response_resource_binding
                    .as_ref()
                    .map(|(upstream, public)| (upstream.as_str(), public.as_str())),
                catalog_version_matches,
            ),
            "tools/call" => rewrite_tool_call_result(result, catalog.as_deref()?, server_id),
            "prompts/get" => rewrite_prompt_get_result(result, catalog.as_deref()?, server_id),
            _ => ResponseRewriteOutcome::Unchanged,
        };
        if outcome != ResponseRewriteOutcome::Changed {
            return None;
        }
        serde_json::to_vec(&value).ok()
    }

    fn on_response_body_transformed(
        &self,
        _ctx: &mut RequestContext,
        response_headers: &mut HashMap<String, String>,
    ) {
        // The selected representation changed. Origin validators and integrity
        // hashes describe the upstream-native bytes, not the public-URI body.
        for header in MCP_REWRITTEN_RESPONSE_VALIDATORS {
            remove_header(response_headers, header);
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.servers
            .values()
            .filter(|server| server.enabled)
            .map(|server| server.target.host.clone())
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseRewriteOutcome {
    Unchanged,
    Changed,
    Ambiguous,
}

fn mcp_content_type_is_json(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or(value).trim();
    media_type.eq_ignore_ascii_case("application/json")
        || media_type.eq_ignore_ascii_case("application/json-rpc")
        || media_type
            .rsplit_once('+')
            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
}

pub(crate) fn redact_internal_log_metadata(metadata: &mut HashMap<String, String>) {
    metadata.remove(METADATA_RESPONSE_REWRITE_KEY);
    metadata.remove(METADATA_RESPONSE_REWRITE_METHOD_KEY);
    metadata.remove(METADATA_RESPONSE_REWRITE_SERVER_KEY);
    metadata.remove(METADATA_RESPONSE_REWRITE_SESSION_KEY);
    metadata.remove(METADATA_RESPONSE_REWRITE_CATALOG_VERSION_KEY);
}

impl ResponseRewriteOutcome {
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Ambiguous, _) | (_, Self::Ambiguous) => Self::Ambiguous,
            (Self::Changed, _) | (_, Self::Changed) => Self::Changed,
            _ => Self::Unchanged,
        }
    }
}

fn rewrite_resource_read_result(
    result: &mut Value,
    catalog: Option<&McpCatalog>,
    server_id: &str,
    routed_binding: Option<(&str, &str)>,
    allow_catalog_fallback: bool,
) -> ResponseRewriteOutcome {
    let Some(contents) = result.get_mut("contents").and_then(Value::as_array_mut) else {
        return ResponseRewriteOutcome::Unchanged;
    };
    contents
        .iter_mut()
        .fold(ResponseRewriteOutcome::Unchanged, |outcome, content| {
            let rewritten = match routed_binding {
                Some((upstream_uri, public_uri))
                    if content.get("uri").and_then(Value::as_str) == Some(upstream_uri) =>
                {
                    rewrite_uri_field_to(content, "uri", public_uri)
                }
                _ if allow_catalog_fallback => catalog
                    .map(|catalog| rewrite_uri_field(content, "uri", catalog, server_id))
                    .unwrap_or(ResponseRewriteOutcome::Unchanged),
                _ => ResponseRewriteOutcome::Unchanged,
            };
            outcome.merge(rewritten)
        })
}

fn rewrite_tool_call_result(
    result: &mut Value,
    catalog: &McpCatalog,
    server_id: &str,
) -> ResponseRewriteOutcome {
    let mut outcome = ResponseRewriteOutcome::Unchanged;
    if let Some(content) = result.get_mut("content") {
        outcome = outcome.merge(rewrite_content_blocks(content, catalog, server_id));
    }
    // Some upstreams use the resources/read-style plural shape for embedded
    // resources in tool results. Keep this narrow to direct `contents[].uri`
    // fields rather than walking arbitrary structured tool output.
    if let Some(contents) = result.get_mut("contents").and_then(Value::as_array_mut) {
        for content in contents {
            outcome = outcome.merge(rewrite_uri_field(content, "uri", catalog, server_id));
        }
    }
    outcome
}

fn rewrite_prompt_get_result(
    result: &mut Value,
    catalog: &McpCatalog,
    server_id: &str,
) -> ResponseRewriteOutcome {
    let Some(messages) = result.get_mut("messages").and_then(Value::as_array_mut) else {
        return ResponseRewriteOutcome::Unchanged;
    };
    messages
        .iter_mut()
        .fold(ResponseRewriteOutcome::Unchanged, |outcome, message| {
            let rewritten = message
                .get_mut("content")
                .map(|content| rewrite_content_blocks(content, catalog, server_id))
                .unwrap_or(ResponseRewriteOutcome::Unchanged);
            outcome.merge(rewritten)
        })
}

fn rewrite_content_blocks(
    content: &mut Value,
    catalog: &McpCatalog,
    server_id: &str,
) -> ResponseRewriteOutcome {
    match content {
        Value::Array(items) => items
            .iter_mut()
            .fold(ResponseRewriteOutcome::Unchanged, |outcome, item| {
                outcome.merge(rewrite_content_block(item, catalog, server_id))
            }),
        Value::Object(_) => rewrite_content_block(content, catalog, server_id),
        _ => ResponseRewriteOutcome::Unchanged,
    }
}

fn rewrite_content_block(
    content: &mut Value,
    catalog: &McpCatalog,
    server_id: &str,
) -> ResponseRewriteOutcome {
    let content_kind = match content.get("type").and_then(Value::as_str) {
        Some("resource_link") => 1,
        Some("resource") => 2,
        _ => 0,
    };
    match content_kind {
        1 => rewrite_uri_field(content, "uri", catalog, server_id),
        2 => content
            .get_mut("resource")
            .map(|resource| rewrite_uri_field(resource, "uri", catalog, server_id))
            .unwrap_or(ResponseRewriteOutcome::Unchanged),
        _ => ResponseRewriteOutcome::Unchanged,
    }
}

fn rewrite_uri_field(
    value: &mut Value,
    field: &str,
    catalog: &McpCatalog,
    server_id: &str,
) -> ResponseRewriteOutcome {
    let Some(uri) = value.get(field).and_then(Value::as_str) else {
        return ResponseRewriteOutcome::Unchanged;
    };
    let public_uri = match reverse_resource_uri(catalog, server_id, uri) {
        ReverseResourceUri::Mapped(public_uri) => Some(public_uri),
        ReverseResourceUri::Unchanged => None,
        ReverseResourceUri::Ambiguous => return ResponseRewriteOutcome::Ambiguous,
    };
    let Some(public_uri) = public_uri else {
        return ResponseRewriteOutcome::Unchanged;
    };
    if public_uri == uri {
        return ResponseRewriteOutcome::Unchanged;
    }
    rewrite_uri_field_to(value, field, &public_uri)
}

fn rewrite_uri_field_to(
    value: &mut Value,
    field: &str,
    public_uri: &str,
) -> ResponseRewriteOutcome {
    if let Some(object) = value.as_object_mut() {
        object.insert(field.to_string(), Value::String(public_uri.to_string()));
        ResponseRewriteOutcome::Changed
    } else {
        ResponseRewriteOutcome::Unchanged
    }
}

enum ReverseResourceUri {
    Unchanged,
    Mapped(String),
    Ambiguous,
}

fn reverse_resource_uri(
    catalog: &McpCatalog,
    server_id: &str,
    upstream_uri: &str,
) -> ReverseResourceUri {
    let mut matched_public_uri: Option<&str> = None;
    for entry in catalog.resources.values().filter(|entry| {
        entry.enabled && entry.server_id == server_id && entry.upstream_uri == upstream_uri
    }) {
        if matched_public_uri.is_some_and(|public_uri| public_uri != entry.public_uri.as_str()) {
            return ReverseResourceUri::Ambiguous;
        }
        matched_public_uri = Some(&entry.public_uri);
    }
    if let Some(public_uri) = matched_public_uri {
        return ReverseResourceUri::Mapped(public_uri.to_string());
    }

    let mut matched_template_uri: Option<String> = None;
    for entry in catalog
        .resource_templates
        .values()
        .filter(|entry| entry.enabled && entry.server_id == server_id)
    {
        let Some(public_uri) = expand_public_resource_template(entry, upstream_uri) else {
            continue;
        };
        if matched_template_uri
            .as_ref()
            .is_some_and(|matched| matched != &public_uri)
        {
            return ReverseResourceUri::Ambiguous;
        }
        matched_template_uri = Some(public_uri);
    }
    if let Some(public_uri) = matched_template_uri {
        return ReverseResourceUri::Mapped(public_uri);
    }

    // No exact resource or template binding matched. This includes native
    // `mcp://` URIs whose authority happens to equal this gateway's server id:
    // exact/template matching runs first (so a configured template still
    // namespaces them), and anything left over has no upstream binding to
    // reverse-map, so it must pass through unchanged.
    ReverseResourceUri::Unchanged
}

fn expand_public_resource_template(
    entry: &ResourceTemplateCatalogEntry,
    upstream_uri: &str,
) -> Option<String> {
    let captures = entry.uri_template_regex.captures(upstream_uri)?;
    let mut public_uri = String::with_capacity(entry.public_uri_template.len());
    let mut index = 0;
    let mut capture_index = 1;
    while let Some(open_offset) = entry.public_uri_template[index..].find('{') {
        let open = index + open_offset;
        let close_offset = entry.public_uri_template[open + 1..].find('}')?;
        let close = open + 1 + close_offset;
        public_uri.push_str(&entry.public_uri_template[index..open]);
        let expansion = captures.get(capture_index)?.as_str();
        let expression = &entry.public_uri_template[open + 1..close];
        if expression
            .as_bytes()
            .first()
            .is_some_and(|operator| b"+#./;?&".contains(operator))
        {
            // The public URI suffix is percent-decoded once by
            // `public_resource_uri_parts`. Keep RFC 3986 reserved/unreserved
            // bytes literal, encode invalid URI bytes, and encode `%` as `%25`
            // so existing upstream escapes survive that single decode.
            public_uri.push_str(
                &utf8_percent_encode(expansion, MCP_RESERVED_TEMPLATE_RESOURCE_URI_ENCODE_SET)
                    .to_string(),
            );
        } else {
            public_uri.push_str(
                &utf8_percent_encode(expansion, MCP_TEMPLATE_RESOURCE_URI_ENCODE_SET).to_string(),
            );
        }
        capture_index += 1;
        index = close + 1;
    }
    public_uri.push_str(&entry.public_uri_template[index..]);
    (capture_index == captures.len()).then_some(public_uri)
}

fn parse_mcp_envelope_value(value: &Value) -> Result<McpEnvelope, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "JSON-RPC envelope must be an object".to_string())?;
    let jsonrpc = object
        .get("jsonrpc")
        .and_then(Value::as_str)
        .ok_or_else(|| "JSON-RPC envelope missing jsonrpc".to_string())?
        .to_string();
    if jsonrpc != "2.0" {
        return Err("JSON-RPC version must be 2.0".to_string());
    }
    let id = object.get("id").cloned();
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let params = object.get("params").cloned();
    let result = object.get("result").cloned();
    let error = object.get("error").cloned();
    let message_kind = if error.is_some() {
        McpMessageKind::ErrorResponse
    } else if result.is_some() {
        McpMessageKind::Response
    } else if method.is_some() && id.is_none() {
        McpMessageKind::Notification
    } else if method.is_some() {
        McpMessageKind::Request
    } else {
        return Err("JSON-RPC envelope must contain method, result, or error".to_string());
    };
    Ok(McpEnvelope {
        jsonrpc,
        id,
        method,
        params,
        result,
        error,
        message_kind,
    })
}

async fn upstream_response_json(
    response: reqwest::Response,
    server_id: &str,
    method: &str,
    max_response_bytes: usize,
) -> Result<Value, String> {
    let is_sse = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|content_type| {
            content_type
                .trim()
                .eq_ignore_ascii_case("text/event-stream")
        });
    if is_sse {
        return upstream_sse_json_rpc_response(response, server_id, method).await;
    }

    let body =
        bounded_upstream_response_text(response, server_id, method, max_response_bytes).await?;

    serde_json::from_str::<Value>(&body)
        .or_else(|error| parse_sse_json_rpc_response(&body).ok_or(error))
        .map_err(|error| {
            warn!(
                server_id,
                method,
                error = %error,
                "MCP upstream response was neither JSON nor SSE JSON-RPC"
            );
            format!("upstream MCP response was neither JSON nor SSE JSON-RPC: {error}")
        })
}

async fn bounded_upstream_response_text(
    response: reqwest::Response,
    server_id: &str,
    method: &str,
    max_response_bytes: usize,
) -> Result<String, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        warn!(
            server_id,
            method,
            max_bytes = max_response_bytes,
            "MCP upstream JSON response exceeded size limit"
        );
        return Err(format!(
            "upstream MCP response exceeded {max_response_bytes} bytes"
        ));
    }

    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            warn!(
                server_id,
                method,
                error = %error,
                "MCP upstream response body could not be read"
            );
            format!("upstream MCP response body could not be read: {error}")
        })?;
        if body.len().saturating_add(chunk.len()) > max_response_bytes {
            warn!(
                server_id,
                method,
                max_bytes = max_response_bytes,
                "MCP upstream JSON response exceeded size limit"
            );
            return Err(format!(
                "upstream MCP response exceeded {max_response_bytes} bytes"
            ));
        }
        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).map_err(|error| {
        warn!(
            server_id,
            method,
            error = %error,
            "MCP upstream response body was not UTF-8"
        );
        format!("upstream MCP response body was not UTF-8: {error}")
    })
}

async fn upstream_sse_json_rpc_response(
    response: reqwest::Response,
    server_id: &str,
    method: &str,
) -> Result<Value, String> {
    let mut stream = response.bytes_stream();
    let mut buffer = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            warn!(
                server_id,
                method,
                error = %error,
                "MCP upstream SSE response body could not be read"
            );
            format!("upstream MCP SSE response body could not be read: {error}")
        })?;
        buffer.extend_from_slice(&chunk);
        if buffer.len() > MAX_UPSTREAM_SSE_EVENT_BYTES {
            warn!(
                server_id,
                method,
                max_bytes = MAX_UPSTREAM_SSE_EVENT_BYTES,
                "MCP upstream SSE event exceeded size limit"
            );
            return Err(format!(
                "upstream MCP SSE event exceeded {MAX_UPSTREAM_SSE_EVENT_BYTES} bytes"
            ));
        }
        while let Some((event_end, delimiter_len)) = find_sse_event_delimiter(&buffer) {
            let event = buffer[..event_end].to_vec();
            buffer.drain(..event_end + delimiter_len);
            let event = std::str::from_utf8(&event).map_err(|error| {
                warn!(
                    server_id,
                    method,
                    error = %error,
                    "MCP upstream SSE event was not UTF-8"
                );
                format!("upstream MCP SSE event was not UTF-8: {error}")
            })?;
            if let Some(value) = parse_sse_json_rpc_response(event) {
                return Ok(value);
            }
        }
    }

    if !buffer.is_empty() {
        let event = std::str::from_utf8(&buffer).map_err(|error| {
            warn!(
                server_id,
                method,
                error = %error,
                "MCP upstream SSE event was not UTF-8"
            );
            format!("upstream MCP SSE event was not UTF-8: {error}")
        })?;
        if let Some(value) = parse_sse_json_rpc_response(event) {
            return Ok(value);
        }
    }

    warn!(
        server_id,
        method, "MCP upstream SSE response did not contain a JSON-RPC response"
    );
    Err("upstream MCP SSE response did not contain a JSON-RPC response".to_string())
}

fn find_sse_event_delimiter(buffer: &[u8]) -> Option<(usize, usize)> {
    [
        b"\n\n".as_slice(),
        b"\r\n\r\n".as_slice(),
        b"\r\r".as_slice(),
    ]
    .into_iter()
    .filter_map(|delimiter| {
        buffer
            .windows(delimiter.len())
            .position(|window| window == delimiter)
            .map(|position| (position, delimiter.len()))
    })
    .min_by_key(|(position, _)| *position)
}

fn parse_sse_json_rpc_response(body: &str) -> Option<Value> {
    let normalized = body.replace("\r\n", "\n");
    for event in normalized.split("\n\n") {
        let data = event
            .lines()
            .filter_map(|line| {
                line.trim_start()
                    .strip_prefix("data:")
                    .map(|data| data.strip_prefix(' ').unwrap_or(data))
            })
            .collect::<Vec<_>>()
            .join("\n");
        if data.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        if value.get("id").is_some()
            && (value.get("result").is_some() || value.get("error").is_some())
        {
            return Some(value);
        }
    }
    None
}

fn validate_json_schema(validator: &jsonschema::Validator, instance: &Value) -> Result<(), String> {
    validator
        .validate(instance)
        .map_err(|error| format!("schema validation failed: {error}"))
}

fn json_rpc_error(
    id: Option<Value>,
    code: i64,
    message: &str,
    internal_detail: Option<String>,
) -> PluginResult {
    let mut metadata = Map::new();
    if let Some(detail) = internal_detail.as_deref() {
        warn!(
            code,
            message,
            internal_detail = %detail,
            "MCP gateway returning JSON-RPC error"
        );
        metadata.insert(
            "gateway".to_string(),
            Value::String("mcp_gateway".to_string()),
        );
    }
    let error = if metadata.is_empty() {
        json!({ "code": code, "message": message })
    } else {
        json!({ "code": code, "message": message, "data": metadata })
    };
    json_response(
        200,
        json!({
            "jsonrpc": "2.0",
            "id": id.unwrap_or(Value::Null),
            "error": error,
        }),
        None,
    )
}

fn json_rpc_error_value(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message,
        }
    })
}

/// Methods whose aggregate handling routes to an upstream MCP server. Inside an
/// aggregate batch both their request and notification forms are rejected before
/// dispatch (session touch, catalog refresh, policy/schema work, or network I/O)
/// under the singleton-routing restriction.
fn aggregate_method_requires_upstream_routing(method: &str) -> bool {
    matches!(method, "tools/call" | "prompts/get" | "resources/read")
}

enum BatchItemOutcome {
    Notification,
    /// A notification member whose dispatch did not succeed. A notification
    /// never carries a per-item response element, so the batch reports the
    /// failure once at batch level instead of silently claiming success or
    /// answering a message that must not be answered.
    FailedNotification,
    Response {
        value: Value,
        session_header: Option<(String, String)>,
    },
    /// Member prepared a backend route (`PluginResult::Continue`). Aggregate
    /// batches must not dial that route from `before_proxy`; notifications omit
    /// a response element entirely.
    UpstreamBound {
        id: Option<Value>,
        is_notification: bool,
    },
}

fn classify_batch_item_result(
    result: PluginResult,
    id: Option<Value>,
    is_notification: bool,
    downstream_session_header: &str,
) -> BatchItemOutcome {
    match result {
        PluginResult::Continue => BatchItemOutcome::UpstreamBound {
            id,
            is_notification,
        },
        PluginResult::Reject {
            status_code: 202,
            body,
            ..
        } if body.is_empty() => BatchItemOutcome::Notification,
        // An empty 202 is the only success shape for a notification. Any other
        // terminal result is a failure that must not become a response element.
        _ if is_notification => BatchItemOutcome::FailedNotification,
        PluginResult::Reject {
            status_code: 404,
            body,
            ..
        } if body.is_empty() => BatchItemOutcome::Response {
            value: json_rpc_error_value(id, -32004, "MCP session not found"),
            session_header: None,
        },
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            // Only the configured downstream session header is eligible for
            // batch propagation / final response stamping (case-insensitive).
            let session_header = headers.iter().find_map(|(name, value)| {
                if name.eq_ignore_ascii_case(downstream_session_header) {
                    Some((
                        downstream_session_header.to_ascii_lowercase(),
                        value.clone(),
                    ))
                } else {
                    None
                }
            });
            if let Ok(value) = serde_json::from_str::<Value>(&body)
                && value.is_object()
            {
                return BatchItemOutcome::Response {
                    value,
                    session_header,
                };
            }
            // Non-JSON terminal responses (and empty bodies) become bounded
            // per-item errors so sibling batch members still validate.
            let message = match status_code {
                400 => "Invalid MCP JSON-RPC request",
                404 => "MCP session not found",
                405 => "Unsupported MCP aggregate HTTP method",
                _ => "MCP gateway request failed",
            };
            BatchItemOutcome::Response {
                value: json_rpc_error_value(id, -32600, message),
                session_header: None,
            }
        }
        // Other plugin results are not produced by MCP dispatch today; fail closed.
        _ => BatchItemOutcome::Response {
            value: json_rpc_error_value(id, -32603, "Internal MCP gateway error"),
            session_header: None,
        },
    }
}

fn catalog_error_response(
    id: Option<Value>,
    message: &str,
    error: McpCatalogError,
) -> PluginResult {
    match error {
        McpCatalogError::SessionNotFound => session_not_found_response(),
        McpCatalogError::Refresh(error) => json_rpc_error(id, -32006, message, Some(error)),
    }
}

/// `-32006` when a request targets a catalog family whose most recent refresh
/// failed on every attempted upstream with no last-good state to serve, or
/// whose bounded collision history overflowed during degraded refreshes.
/// Returns `None` when the family is available.
fn family_unavailable_error(
    catalog: &McpCatalog,
    family: &'static str,
    id: Option<Value>,
) -> Option<PluginResult> {
    if catalog.collision_tombstone_overflow.contains(family) {
        return Some(json_rpc_error(
            id,
            -32006,
            "MCP catalog unavailable",
            Some(format!(
                "{family} collision history exceeded bounded retention; a fully authoritative refresh is required"
            )),
        ));
    }
    if !catalog.unavailable.contains(family) {
        return None;
    }
    Some(json_rpc_error(
        id,
        -32006,
        "MCP catalog unavailable",
        Some(format!(
            "every upstream {family} list failed and no last-good {family} catalog exists"
        )),
    ))
}

fn json_response(
    status_code: u16,
    body: Value,
    session_header: Option<(&str, &str)>,
) -> PluginResult {
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    if let Some((name, value)) = session_header {
        headers.insert(name.to_ascii_lowercase(), value.to_string());
    }
    PluginResult::Reject {
        status_code,
        body: body.to_string(),
        headers,
    }
}

fn empty_response(status_code: u16) -> PluginResult {
    PluginResult::Reject {
        status_code,
        body: String::new(),
        headers: HashMap::new(),
    }
}

fn session_not_found_response() -> PluginResult {
    empty_response(404)
}

/// Insert a discovered catalog entry under `key`, skipping (and warning on) any
/// public-name collision across upstreams. A colliding name is exposed by
/// *neither* upstream: that prevents silent routing to the wrong upstream (the
/// original collision concern) while keeping the rest of the catalog usable
/// rather than failing discovery wholesale. Applied uniformly to tools, prompts,
/// and resources so collision behavior is consistent across item types.
fn insert_catalog_entry<T>(
    map: &mut HashMap<String, T>,
    collided: &mut HashSet<String>,
    key: String,
    entry: T,
    server_id: &str,
    item_kind: &str,
) {
    if collided.contains(&key) {
        warn!(
            public_name = %key,
            server_id,
            item_kind,
            "skipping MCP catalog entry: public name already collided across upstreams"
        );
        return;
    }
    if map.remove(&key).is_some() {
        collided.insert(key.clone());
        warn!(
            public_name = %key,
            server_id,
            item_kind,
            "skipping colliding MCP catalog entries: duplicate public name across upstreams"
        );
        return;
    }
    map.insert(key, entry);
}

/// Carry one failed upstream's last-good entries for a single catalog family
/// into the rebuilt catalog so a per-upstream refresh failure degrades only
/// that upstream. Carried entries still pass through `insert_catalog_entry`,
/// so a stale name colliding with another upstream's fresh name is dropped for
/// both and can never route ambiguously.
fn carry_stale_entries<T: Clone>(
    old_entries: &HashMap<String, T>,
    entries: &mut HashMap<String, T>,
    collided: &mut HashSet<String>,
    belongs_to_server: impl Fn(&T) -> bool,
    server_id: &str,
    item_kind: &str,
) {
    for (key, entry) in old_entries {
        if !belongs_to_server(entry) {
            continue;
        }
        insert_catalog_entry(
            entries,
            collided,
            key.clone(),
            entry.clone(),
            server_id,
            item_kind,
        );
    }
}

/// Bound collision history by the aggregate number of items all attempted
/// upstream lists can return in one family refresh. A single per-list limit is
/// insufficient because several servers can contribute distinct collisions.
fn family_collision_tombstone_limit(
    refresh_stats: Option<&FamilyRefreshStats>,
    max_items_per_list: usize,
) -> usize {
    refresh_stats.map_or(0, |stats| {
        stats.attempted.saturating_mul(max_items_per_list)
    })
}

/// Keep every previously ambiguous public key suppressed unless the current
/// family refresh is authoritative. If the union of current and historical
/// collisions exceeds the aggregate refresh bound, retain no attacker-chosen
/// subset: clear the family map and replace the keys with one sticky overflow
/// bit. This prevents lexicographic/hash ordering or repeated degraded
/// refreshes from resurrecting a suppressed route. A fully authoritative
/// refresh discards historical uncertainty and rebuilds from current results.
fn reconcile_collision_tombstones<T>(
    old_collisions: &HashSet<String>,
    collisions: &mut HashSet<String>,
    entries: &mut HashMap<String, T>,
    refresh_stats: Option<&FamilyRefreshStats>,
    max_tombstones: usize,
    previously_overflowed: bool,
) -> bool {
    let fully_authoritative = refresh_stats.is_some_and(FamilyRefreshStats::fully_authoritative);
    let mut overflowed = collisions.len() > max_tombstones;

    if !fully_authoritative {
        overflowed |= previously_overflowed;
        if !overflowed {
            for key in old_collisions {
                entries.remove(key);
                if collisions.contains(key) {
                    continue;
                }
                if collisions.len() == max_tombstones {
                    overflowed = true;
                    break;
                }
                collisions.insert(key.clone());
            }
        }
    }

    if overflowed {
        entries.clear();
        collisions.clear();
    }
    overflowed
}

/// HTTP 400 for a request that requires an MCP session but carried no session
/// header. Distinct from `session_not_found_response` (404 = terminated/unknown
/// session): the message reflects the real cause (the client never sent
/// `Mcp-Session-Id`) rather than attributing it to the upstream.
fn missing_session_response(id: Option<Value>) -> PluginResult {
    json_response(
        400,
        json!({
            "jsonrpc": "2.0",
            "id": id.unwrap_or(Value::Null),
            "error": {
                "code": -32600,
                "message": "Missing Mcp-Session-Id header; call initialize to obtain a session"
            }
        }),
        None,
    )
}

fn tool_entry_to_public_value(entry: &ToolCatalogEntry) -> Value {
    let mut object = Map::new();
    object.insert("name".to_string(), Value::String(entry.public_name.clone()));
    if let Some(title) = &entry.title {
        object.insert("title".to_string(), Value::String(title.clone()));
    }
    if let Some(description) = &entry.description {
        object.insert(
            "description".to_string(),
            Value::String(format!("[{}] {}", entry.namespace, description)),
        );
    }
    object.insert("inputSchema".to_string(), entry.input_schema.clone());
    if let Some(output_schema) = &entry.output_schema {
        object.insert("outputSchema".to_string(), output_schema.clone());
    }
    if let Some(annotations) = &entry.annotations {
        object.insert("annotations".to_string(), annotations.clone());
    }
    Value::Object(object)
}

fn prompt_entry_to_public_value(entry: &PromptCatalogEntry) -> Value {
    let mut object = Map::new();
    object.insert("name".to_string(), Value::String(entry.public_name.clone()));
    if let Some(description) = &entry.description {
        object.insert(
            "description".to_string(),
            Value::String(format!("[{}] {}", entry.namespace, description)),
        );
    }
    if let Some(arguments_schema) = &entry.arguments_schema {
        object.insert("argumentsSchema".to_string(), arguments_schema.clone());
    }
    Value::Object(object)
}

fn resource_entry_to_public_value(entry: &ResourceCatalogEntry) -> Value {
    let mut object = Map::new();
    object.insert("uri".to_string(), Value::String(entry.public_uri.clone()));
    if let Some(name) = &entry.name {
        object.insert("name".to_string(), Value::String(name.clone()));
    }
    if let Some(description) = &entry.description {
        object.insert(
            "description".to_string(),
            Value::String(format!("[{}] {}", entry.namespace, description)),
        );
    }
    if let Some(mime_type) = &entry.mime_type {
        object.insert("mimeType".to_string(), Value::String(mime_type.clone()));
    }
    Value::Object(object)
}

fn resource_template_entry_to_public_value(entry: &ResourceTemplateCatalogEntry) -> Value {
    let mut object = Map::new();
    object.insert(
        "uriTemplate".to_string(),
        Value::String(entry.public_uri_template.clone()),
    );
    if let Some(name) = &entry.name {
        object.insert("name".to_string(), Value::String(name.clone()));
    }
    if let Some(title) = &entry.title {
        object.insert("title".to_string(), Value::String(title.clone()));
    }
    if let Some(description) = &entry.description {
        object.insert(
            "description".to_string(),
            Value::String(format!("[{}] {}", entry.namespace, description)),
        );
    }
    if let Some(mime_type) = &entry.mime_type {
        object.insert("mimeType".to_string(), Value::String(mime_type.clone()));
    }
    if let Some(annotations) = &entry.annotations {
        object.insert("annotations".to_string(), annotations.clone());
    }
    if let Some(icons) = &entry.icons {
        object.insert("icons".to_string(), icons.clone());
    }
    Value::Object(object)
}

fn namespaced(namespace: &str, separator: &str, upstream_name: &str) -> String {
    let mut value = String::with_capacity(namespace.len() + separator.len() + upstream_name.len());
    value.push_str(namespace);
    value.push_str(separator);
    value.push_str(upstream_name);
    value
}

fn public_resource_uri(server_id: &str, upstream_uri: &str) -> String {
    format!(
        "mcp://{}/{}",
        server_id,
        utf8_percent_encode(upstream_uri, NON_ALPHANUMERIC)
    )
}

fn public_resource_template_uri(server_id: &str, upstream_uri_template: &str) -> String {
    let mut encoded = String::new();
    let mut index = 0;
    while let Some(open_offset) = upstream_uri_template[index..].find('{') {
        let open = index + open_offset;
        encoded.push_str(
            &utf8_percent_encode(&upstream_uri_template[index..open], NON_ALPHANUMERIC).to_string(),
        );
        let Some(close_offset) = upstream_uri_template[open + 1..].find('}') else {
            encoded.push_str(
                &utf8_percent_encode(&upstream_uri_template[open..], NON_ALPHANUMERIC).to_string(),
            );
            return format!("mcp://{server_id}/{encoded}");
        };
        let close = open + 1 + close_offset;
        encoded.push_str(&upstream_uri_template[open..=close]);
        index = close + 1;
    }
    encoded.push_str(
        &utf8_percent_encode(&upstream_uri_template[index..], NON_ALPHANUMERIC).to_string(),
    );
    format!("mcp://{server_id}/{encoded}")
}

fn public_resource_uri_parts(public_uri: &str) -> Option<(&str, String)> {
    let rest = public_uri.strip_prefix("mcp://")?;
    let (server_id, encoded_upstream_uri) = rest.split_once('/')?;
    let upstream_uri = percent_decode_str(encoded_upstream_uri)
        .decode_utf8()
        .ok()?
        .into_owned();
    Some((server_id, upstream_uri))
}

fn uri_template_regex(uri_template: &str) -> Result<Regex, String> {
    let mut pattern = String::from("^");
    let mut index = 0;
    while let Some(open_offset) = uri_template[index..].find('{') {
        let open = index + open_offset;
        pattern.push_str(&regex::escape(&uri_template[index..open]));
        let close_offset = uri_template[open + 1..]
            .find('}')
            .ok_or_else(|| "unclosed URI template expression".to_string())?;
        let close = open + 1 + close_offset;
        let expression = &uri_template[open + 1..close];
        if expression.trim().is_empty() || expression.contains('{') {
            return Err("invalid URI template expression".to_string());
        }
        pattern.push_str("(.*)");
        index = close + 1;
    }
    if uri_template[index..].contains('}') {
        return Err("unmatched URI template close brace".to_string());
    }
    pattern.push_str(&regex::escape(&uri_template[index..]));
    pattern.push('$');
    Regex::new(&pattern).map_err(|error| error.to_string())
}

fn resource_template_route(catalog: &McpCatalog, public_uri: &str) -> Option<(String, String)> {
    let (server_id, upstream_uri) = public_resource_uri_parts(public_uri)?;
    catalog
        .resource_templates
        .values()
        .find(|entry| {
            entry.enabled
                && entry.server_id == server_id
                && entry.uri_template_regex.is_match(&upstream_uri)
        })
        .map(|entry| (entry.server_id.clone(), upstream_uri))
}

fn hash_value(value: &Value) -> String {
    match serde_json::to_vec(value) {
        Ok(bytes) => hex::encode(Sha256::digest(bytes)),
        Err(_) => hash_str(&value.to_string()),
    }
}

fn hash_str(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .get(&name.to_ascii_lowercase())
        .or_else(|| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
        })
        .map(String::as_str)
}

/// Remove every header entry whose name matches `name` case-insensitively.
/// Header map keys are not guaranteed to be lowercased (see `header_value`'s
/// fallback), so match by `eq_ignore_ascii_case` rather than a single lookup.
fn remove_header(headers: &mut HashMap<String, String>, name: &str) {
    headers.retain(|key, _| !key.eq_ignore_ascii_case(name));
}

fn optional_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a Map<String, Value>>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value)),
        Some(other) => Err(format!(
            "mcp_gateway: '{key}' must be an object, got {other}"
        )),
    }
}

fn optional_bool(object: &Map<String, Value>, key: &str) -> Result<Option<bool>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(other) => Err(format!(
            "mcp_gateway: '{key}' must be a boolean, got {other}"
        )),
    }
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(other) => Err(format!(
            "mcp_gateway: '{key}' must be a string, got {other}"
        )),
    }
}

fn optional_string_from_object(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<String>, String> {
    match object.and_then(|object| object.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(format!(
            "mcp_gateway: '{key}' must be a string, got {other}"
        )),
    }
}

fn optional_bool_from_object(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<bool>, String> {
    match object.and_then(|object| object.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(other) => Err(format!(
            "mcp_gateway: '{key}' must be a boolean, got {other}"
        )),
    }
}

fn optional_u64_from_object(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<u64>, String> {
    match object.and_then(|object| object.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("mcp_gateway: '{key}' must be a positive integer"))
            .map(Some),
        Some(other) => Err(format!(
            "mcp_gateway: '{key}' must be a positive integer, got {other}"
        )),
    }
}

fn optional_string_vec_from_object(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<Vec<String>>, String> {
    let Some(value) = object.and_then(|object| object.get(key)) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let array = value
        .as_array()
        .ok_or_else(|| format!("mcp_gateway: '{key}' must be an array"))?;
    let mut values = Vec::with_capacity(array.len());
    for (idx, item) in array.iter().enumerate() {
        values.push(
            item.as_str()
                .ok_or_else(|| format!("mcp_gateway: '{key}[{idx}]' must be a string"))?
                .to_string(),
        );
    }
    Ok(Some(values))
}

fn parse_discovery(object: &Map<String, Value>) -> Result<McpDiscoveryConfig, String> {
    let discovery = optional_object(object, "discovery")?;
    let namespace_separator = optional_string_from_object(discovery, "namespace_separator")?
        .unwrap_or_else(|| ".".to_string());
    if namespace_separator.is_empty() {
        return Err("mcp_gateway: 'discovery.namespace_separator' must not be empty".to_string());
    }
    let cache_ttl_seconds =
        optional_u64_from_object(discovery, "cache_ttl_seconds")?.unwrap_or(300);
    if cache_ttl_seconds == 0 {
        return Err(
            "mcp_gateway: 'discovery.cache_ttl_seconds' must be greater than zero".to_string(),
        );
    }
    let on_new_tool = DiscoveryBehavior::parse(
        optional_string_from_object(discovery, "on_new_tool")?
            .as_deref()
            .unwrap_or("hide_until_configured"),
        "discovery.on_new_tool",
    )?;
    let on_schema_change = DiscoveryBehavior::parse(
        optional_string_from_object(discovery, "on_schema_change")?
            .as_deref()
            .unwrap_or("hide_until_configured"),
        "discovery.on_schema_change",
    )?;
    Ok(McpDiscoveryConfig {
        aggregate_tools: optional_bool_from_object(discovery, "aggregate_tools")?.unwrap_or(true),
        aggregate_resources: optional_bool_from_object(discovery, "aggregate_resources")?
            .unwrap_or(true),
        aggregate_prompts: optional_bool_from_object(discovery, "aggregate_prompts")?
            .unwrap_or(true),
        namespace_separator,
        cache_ttl: Duration::from_secs(cache_ttl_seconds),
        hide_denied_items: optional_bool_from_object(discovery, "hide_denied_items")?
            .unwrap_or(true),
        on_new_tool,
        on_schema_change,
    })
}

fn parse_sessions(object: &Map<String, Value>) -> Result<McpSessionConfig, String> {
    let sessions = optional_object(object, "sessions")?;
    let initialize_upstreams = InitializeStrategy::parse(
        optional_string_from_object(sessions, "initialize_upstreams")?
            .as_deref()
            .unwrap_or("lazy"),
        "sessions.initialize_upstreams",
    )?;
    let session_ttl_seconds = optional_u64_from_object(sessions, "session_ttl_seconds")?
        .unwrap_or(DEFAULT_SESSION_TTL_SECONDS);
    if session_ttl_seconds == 0 {
        return Err(
            "mcp_gateway: 'sessions.session_ttl_seconds' must be greater than zero".to_string(),
        );
    }
    let max_sessions =
        optional_u64_from_object(sessions, "max_sessions")?.unwrap_or(DEFAULT_MAX_SESSIONS as u64);
    if max_sessions == 0 {
        return Err("mcp_gateway: 'sessions.max_sessions' must be greater than zero".to_string());
    }
    let max_sessions = usize::try_from(max_sessions)
        .map_err(|_| "mcp_gateway: 'sessions.max_sessions' is too large".to_string())?;
    let downstream_session_header =
        optional_string_from_object(sessions, "downstream_session_header")?
            .unwrap_or_else(|| "mcp-session-id".to_string());
    validate_session_header_name(
        &downstream_session_header,
        "sessions.downstream_session_header",
    )?;
    let upstream_session_header = optional_string_from_object(sessions, "upstream_session_header")?
        .unwrap_or_else(|| "mcp-session-id".to_string());
    validate_session_header_name(&upstream_session_header, "sessions.upstream_session_header")?;
    Ok(McpSessionConfig {
        downstream_session_header,
        upstream_session_header,
        initialize_upstreams,
        session_ttl: Duration::from_secs(session_ttl_seconds),
        max_sessions,
    })
}

fn parse_capabilities(object: &Map<String, Value>) -> Result<McpCapabilitiesConfig, String> {
    let capabilities = optional_object(object, "capabilities")?;
    Ok(McpCapabilitiesConfig {
        advertise_tools: optional_bool_from_object(capabilities, "advertise_tools")?
            .unwrap_or(true),
        advertise_resources: optional_bool_from_object(capabilities, "advertise_resources")?
            .unwrap_or(true),
        advertise_prompts: optional_bool_from_object(capabilities, "advertise_prompts")?
            .unwrap_or(true),
        advertise_logging: optional_bool_from_object(capabilities, "advertise_logging")?
            .unwrap_or(false),
        advertise_completions: optional_bool_from_object(capabilities, "advertise_completions")?
            .unwrap_or(false),
        advertise_tasks: optional_bool_from_object(capabilities, "advertise_tasks")?
            .unwrap_or(false),
        passthrough_unknown_methods: optional_bool_from_object(
            capabilities,
            "passthrough_unknown_methods",
        )?
        .unwrap_or(false),
    })
}

fn parse_policy(object: &Map<String, Value>) -> Result<McpPolicy, String> {
    let policy = optional_object(object, "policy")?;
    let default_action = match optional_string_from_object(policy, "default_action")?
        .as_deref()
        .unwrap_or("deny")
    {
        "allow" => PolicyAction::Allow,
        "deny" => PolicyAction::Deny,
        other => {
            return Err(format!(
                "mcp_gateway: 'policy.default_action' must be allow or deny, got {other:?}"
            ));
        }
    };
    let hide_denied_tools = optional_bool_from_object(policy, "hide_denied_tools")?.unwrap_or(true);
    let mut tools = HashMap::new();
    if let Some(tools_object) = policy
        .and_then(|policy| policy.get("tools"))
        .and_then(Value::as_object)
    {
        for (tool_name, tool_policy) in tools_object {
            let object = tool_policy.as_object().ok_or_else(|| {
                format!("mcp_gateway: policy.tools[{tool_name:?}] must be an object")
            })?;
            let action = PolicyAction::parse(
                optional_string(object, "action")?.ok_or_else(|| {
                    format!("mcp_gateway: policy.tools[{tool_name:?}].action is required")
                })?,
                &format!("policy.tools[{tool_name:?}].action"),
            )?;
            tools.insert(tool_name.clone(), action);
        }
    } else if policy
        .and_then(|policy| policy.get("tools"))
        .is_some_and(|value| !value.is_null())
    {
        return Err("mcp_gateway: 'policy.tools' must be an object".to_string());
    }
    Ok(McpPolicy {
        default_action,
        hide_denied_tools,
        tools,
    })
}

fn parse_validation(object: &Map<String, Value>) -> Result<McpValidationConfig, String> {
    let validation = optional_object(object, "validation")?;
    // Tool result validation is not implemented in V1. Reject it rather than
    // silently accepting a config that advertises enforcement that never runs.
    if optional_bool_from_object(validation, "validate_tool_results")?.unwrap_or(false) {
        return Err(
            "mcp_gateway: 'validation.validate_tool_results' is not supported yet; tool result validation is not implemented"
                .to_string(),
        );
    }
    let max_upstream_response_bytes =
        optional_u64_from_object(validation, "max_upstream_response_bytes")?
            .map(|value| value as usize)
            .unwrap_or(DEFAULT_MAX_UPSTREAM_JSON_RESPONSE_BYTES);
    if max_upstream_response_bytes == 0 {
        return Err(
            "mcp_gateway: 'validation.max_upstream_response_bytes' must be greater than 0"
                .to_string(),
        );
    }
    let max_catalog_items_per_list =
        optional_u64_from_object(validation, "max_catalog_items_per_list")?
            .map(|value| value as usize)
            .unwrap_or(DEFAULT_MAX_MCP_CATALOG_ITEMS_PER_LIST);
    if max_catalog_items_per_list == 0 {
        return Err(
            "mcp_gateway: 'validation.max_catalog_items_per_list' must be greater than 0"
                .to_string(),
        );
    }
    let max_catalog_bytes_per_list =
        optional_u64_from_object(validation, "max_catalog_bytes_per_list")?
            .map(|value| value as usize)
            .unwrap_or(DEFAULT_MAX_MCP_CATALOG_BYTES_PER_LIST);
    if max_catalog_bytes_per_list == 0 {
        return Err(
            "mcp_gateway: 'validation.max_catalog_bytes_per_list' must be greater than 0"
                .to_string(),
        );
    }
    let max_batch_items = optional_u64_from_object(validation, "max_batch_items")?
        .map(|value| value as usize)
        .unwrap_or(DEFAULT_MAX_JSONRPC_BATCH_ITEMS);
    if max_batch_items == 0 {
        return Err("mcp_gateway: 'validation.max_batch_items' must be greater than 0".to_string());
    }
    let max_batch_bytes = optional_u64_from_object(validation, "max_batch_bytes")?
        .map(|value| value as usize)
        .unwrap_or(DEFAULT_MAX_JSONRPC_BATCH_BYTES);
    if max_batch_bytes == 0 {
        return Err("mcp_gateway: 'validation.max_batch_bytes' must be greater than 0".to_string());
    }
    let max_batch_item_bytes = optional_u64_from_object(validation, "max_batch_item_bytes")?
        .map(|value| value as usize)
        .unwrap_or(DEFAULT_MAX_JSONRPC_BATCH_ITEM_BYTES);
    if max_batch_item_bytes == 0 {
        return Err(
            "mcp_gateway: 'validation.max_batch_item_bytes' must be greater than 0".to_string(),
        );
    }
    if max_batch_item_bytes > max_batch_bytes {
        return Err(
            "mcp_gateway: 'validation.max_batch_item_bytes' must not exceed 'validation.max_batch_bytes'"
                .to_string(),
        );
    }
    let max_batch_response_bytes =
        optional_u64_from_object(validation, "max_batch_response_bytes")?
            .map(|value| value as usize)
            .unwrap_or(DEFAULT_MAX_JSONRPC_BATCH_RESPONSE_BYTES);
    if max_batch_response_bytes == 0 {
        return Err(
            "mcp_gateway: 'validation.max_batch_response_bytes' must be greater than 0".to_string(),
        );
    }
    Ok(McpValidationConfig {
        validate_tool_arguments: optional_bool_from_object(validation, "validate_tool_arguments")?
            .unwrap_or(true),
        max_upstream_response_bytes,
        max_catalog_items_per_list,
        max_catalog_bytes_per_list,
        max_batch_items,
        max_batch_bytes,
        max_batch_item_bytes,
        max_batch_response_bytes,
    })
}

fn parse_observability(object: &Map<String, Value>) -> Result<McpObservabilityConfig, String> {
    let observability = optional_object(object, "observability")?;
    Ok(McpObservabilityConfig {
        emit_metadata: optional_bool_from_object(observability, "emit_metadata")?.unwrap_or(true),
        log_raw_arguments: optional_bool_from_object(observability, "log_raw_arguments")?
            .unwrap_or(false),
        log_argument_hash: optional_bool_from_object(observability, "log_argument_hash")?
            .unwrap_or(true),
        log_raw_results: optional_bool_from_object(observability, "log_raw_results")?
            .unwrap_or(false),
        log_result_hash: optional_bool_from_object(observability, "log_result_hash")?
            .unwrap_or(false),
    })
}

fn parse_servers(
    object: &Map<String, Value>,
    default_initialize_strategy: InitializeStrategy,
) -> Result<HashMap<String, McpServerConfig>, String> {
    let servers_value = object
        .get("servers")
        .ok_or_else(|| "mcp_gateway: 'servers' is required".to_string())?;
    let servers_object = servers_value
        .as_object()
        .ok_or_else(|| "mcp_gateway: 'servers' must be an object".to_string())?;
    if servers_object.is_empty() {
        return Err("mcp_gateway: 'servers' must not be empty".to_string());
    }
    let mut namespaces = HashSet::new();
    let mut servers = HashMap::with_capacity(servers_object.len());
    for (server_id, value) in servers_object {
        if server_id.trim().is_empty() {
            return Err("mcp_gateway: server IDs must not be empty".to_string());
        }
        validate_server_id(server_id)?;
        let object = value
            .as_object()
            .ok_or_else(|| format!("mcp_gateway: server {server_id:?} must be an object"))?;
        let upstream_url = optional_string(object, "upstream_url")?
            .ok_or_else(|| format!("mcp_gateway: server {server_id:?} requires 'upstream_url'"))?
            .to_string();
        let namespace = optional_string(object, "namespace")?
            .ok_or_else(|| format!("mcp_gateway: server {server_id:?} requires 'namespace'"))?
            .to_string();
        if namespace.trim().is_empty() {
            return Err(format!(
                "mcp_gateway: server {server_id:?} namespace must not be empty"
            ));
        }
        if !namespaces.insert(namespace.clone()) {
            return Err(format!(
                "mcp_gateway: duplicate server namespace {namespace:?}"
            ));
        }
        let initialize_strategy = optional_string(object, "initialize_strategy")?
            .map(|value| InitializeStrategy::parse(value, "servers.*.initialize_strategy"))
            .transpose()?
            .unwrap_or(default_initialize_strategy);
        servers.insert(
            server_id.clone(),
            McpServerConfig {
                server_id: server_id.clone(),
                namespace,
                target: parse_upstream_target(&upstream_url, server_id)?,
                upstream_url,
                enabled: optional_bool(object, "enabled")?.unwrap_or(true),
                expose_tools: optional_bool(object, "expose_tools")?.unwrap_or(true),
                expose_resources: optional_bool(object, "expose_resources")?.unwrap_or(false),
                expose_prompts: optional_bool(object, "expose_prompts")?.unwrap_or(false),
                initialize_strategy,
            },
        );
    }
    Ok(servers)
}

fn parse_upstream_target(url: &str, server_id: &str) -> Result<McpUpstreamTarget, String> {
    let parsed = Url::parse(url).map_err(|error| {
        format!("mcp_gateway: server {server_id:?} upstream_url invalid: {error}")
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "mcp_gateway: server {server_id:?} upstream_url must not contain credentials"
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "mcp_gateway: server {server_id:?} upstream_url must not contain query or fragment"
        ));
    }
    let scheme = match parsed.scheme() {
        "http" => BackendScheme::Http,
        "https" => BackendScheme::Https,
        other => {
            return Err(format!(
                "mcp_gateway: server {server_id:?} upstream_url scheme must be http or https, got {other:?}"
            ));
        }
    };
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("mcp_gateway: server {server_id:?} upstream_url missing host"))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| format!("mcp_gateway: server {server_id:?} upstream_url missing port"))?;
    let path = if parsed.path().is_empty() {
        "/".to_string()
    } else {
        parsed.path().to_string()
    };
    let authority = authority_for_host_port(&host, parsed.port(), scheme);
    Ok(McpUpstreamTarget {
        scheme,
        host,
        port,
        path,
        authority,
    })
}

fn authority_for_host_port(
    host: &str,
    explicit_port: Option<u16>,
    scheme: BackendScheme,
) -> String {
    let rendered_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let default_port = match scheme {
        BackendScheme::Http => 80,
        BackendScheme::Https => 443,
        _ => 0,
    };
    match explicit_port {
        Some(port) if port != default_port => format!("{rendered_host}:{port}"),
        _ => rendered_host,
    }
}

fn validate_path(path: &str, field: &str) -> Result<(), String> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(format!("mcp_gateway: '{field}' must be a non-empty path"));
    }
    Ok(())
}

/// Server ids are embedded verbatim into public `mcp://{server_id}/...` resource
/// and resource-template URIs that `public_resource_uri_parts` later parses back
/// by splitting at the first `/`. Restrict them to a URI-safe identifier subset
/// so a `/` (or other reserved delimiter) cannot make an advertised resource URI
/// parse back to the wrong server id and become unroutable.
fn validate_server_id(server_id: &str) -> Result<(), String> {
    if !server_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!(
            "mcp_gateway: server id {server_id:?} must contain only ASCII alphanumerics, '.', '_', or '-'"
        ));
    }
    Ok(())
}

/// Validate a configured MCP session header name as a syntactically valid HTTP
/// header name, so invalid characters (spaces, control bytes) are rejected at
/// config time instead of failing every routed upstream request at runtime.
fn validate_session_header_name(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("mcp_gateway: '{field}' must not be empty"));
    }
    http::header::HeaderName::from_bytes(value.as_bytes())
        .map(|_| ())
        .map_err(|_| {
            format!("mcp_gateway: '{field}' must be a valid HTTP header name, got {value:?}")
        })
}
